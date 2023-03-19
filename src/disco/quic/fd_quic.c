#include "fd_quic.h"
#include "fd_tpu_defrag.h"

struct fd_tpu_tile_state {
  fd_frag_meta_t *   mcache;
  fd_tpu_defrag_t *  defrag;

  ulong   depth;
  ulong * sync;
  ulong   seq;

  void *  base;
  ulong   chunk0;
  ulong   wmark;
  ulong   chunk;
};
typedef struct fd_tpu_tile_state fd_tpu_tile_state_t;

/* Tile-local sequence number for conns */
static FD_TLS ulong conn_seq = 0UL;

/* fd_tpu_now implements fd_quic_now_t */
static ulong
fd_tpu_now( void * ctx ) {
  (void)ctx;
  return (ulong)fd_log_wallclock();
}

/* fd_tpu_conn_create implements fd_quic_cb_conn_new_t */
static void
fd_tpu_conn_create( fd_quic_conn_t * conn,
                    void *           quic_ctx ) {
  (void)conn;
  (void)quic_ctx;

  conn->local_conn_id = ++conn_seq;
}

/* fd_tpu_stream_create implements fd_quic_cb_stream_new_t */
static void
fd_tpu_stream_create( fd_quic_stream_t * stream,
                      void *             quic_ctx,
                      int                type ) {

  (void)type; /* TODO reject bidi streams? */

  ulong conn_id   = stream->conn->local_conn_id;
  ulong stream_id = stream->stream_id;

  fd_tpu_defrag_t * defragger = (fd_tpu_defrag_t *)quic_ctx;

  fd_tpu_defrag_entry_t * entry = fd_tpu_defrag_entry_start( defragger, conn_id, stream_id );
  if( FD_UNLIKELY( !entry ) ) {
    fd_quic_stream_close( stream, 0x03 ); /* FIXME fd_quic_stream_close not implemented */
    return;
  }

  stream->context = entry;
}

/* fd_tpu_stream_receive implements fd_quic_cb_stream_receive_t */
static void
fd_tpu_stream_receive( fd_quic_stream_t * stream,
                       void *             stream_ctx,
                       uchar const *      data,
                       ulong              data_sz,
                       ulong              offset,
                       int                fin ) {

  (void)offset; /* TODO offset required? */
  (void)fin; /* TODO instantly publish if offset==0UL && fin */

  ulong conn_id   = stream->conn->local_conn_id;
  ulong stream_id = stream->stream_id;

  fd_tpu_defrag_entry_t * entry     = (fd_tpu_defrag_entry_t *)stream_ctx;
  fd_tpu_defrag_t *       defragger = entry->defrag;

  if( FD_UNLIKELY( !fd_tpu_defrag_entry_exists( entry, conn_id, stream_id ) ) )
    return;

  if( FD_UNLIKELY( !fd_tpu_defrag_entry_append( defragger, entry, data, data_sz ) ) ) {
    fd_quic_stream_close( stream, 0x03 ); /* FIXME fd_quic_stream_close not implemented */
    return;
  }
}

/* fd_tpu_stream_notify implements fd_quic_cb_stream_notify_t */
static void
fd_tpu_stream_notify( fd_quic_stream_t * stream,
                      void *             stream_ctx,
                      int                type ) {

  /* FIXME: This is not the right place to publish messages, move
     publishing back to main loop and populate light "publish stack"
     from here instead. */

  /* Stream context */

  fd_tpu_defrag_entry_t * entry     = (fd_tpu_defrag_entry_t *)stream_ctx;
  fd_tpu_defrag_t *       defragger = entry->defrag;
  fd_tpu_tile_state_t *   tile      = fd_tpu_defrag_containing( defragger );
  ulong                   conn_id   = stream->conn->local_conn_id;
  ulong                   stream_id = stream->stream_id;

  if( FD_UNLIKELY( !fd_tpu_defrag_entry_exists( entry, conn_id, stream_id ) ) )
    return;

  if( FD_UNLIKELY( type!=FD_QUIC_NOTIFY_END ) ) {
    fd_tpu_defrag_entry_fini( defragger, entry );
    return;
  }

  /* At this point, we have a message to publish */

  /* Load tile constants */

  fd_frag_meta_t * const mcache = tile->mcache;
  ulong            const depth  = tile->depth;
  ulong *          const sync   = tile->sync;
  void *           const base   = tile->base;
  ulong            const chunk0 = tile->chunk0;
  ulong            const wmark  = tile->wmark;

  /* Load tile variables */

  ulong seq   = tile->seq;
  ulong chunk = tile->chunk;

  /* Load message */

  uchar * payload = entry->chunk;
  ulong   sz      = entry->sz;

  /* Copy message into dcache chunk */

  uchar * chunk_laddr = (uchar *)fd_chunk_to_laddr( base, chunk );
  fd_memcpy( chunk_laddr, payload, sz );

  /* Publish meta */

  ulong orig = 0UL; /* TODO origin? */

  ulong ctl = fd_frag_meta_ctl( orig, 1 /*som*/, 1 /*eom*/, 0 /*err*/ );
    /* TODO support fragmentation */

  long now = fd_tickcount();
  ulong tsorig = fd_frag_meta_ts_comp( now ); /* TODO orig time */
  ulong tspub  = tsorig;

  ulong sig = (ulong)now; /* TODO message sig */

  fd_mcache_publish( mcache, depth, seq, sig, chunk, sz, ctl, tsorig, tspub );

  /* Windup for the next publish and accumulate diagnostics */

  chunk = fd_dcache_compact_next( chunk, sz, chunk0, wmark );
  seq   = fd_seq_inc( seq, 1UL );

  /* Free frame from demux heap */

  fd_tpu_defrag_entry_fini( defragger, entry );

  /* Save tile variables */

  tile->seq   = seq;
  tile->chunk = chunk;
}

int
fd_quic_tile( fd_cnc_t *         cnc,
              ulong              shard,
              fd_quic_t *        quic,
              fd_quic_config_t * quic_cfg,
              fd_frag_meta_t *   mcache,
              uchar *            dcache,
              ulong              stream_par_cnt,
              fd_rng_t *         rng,
              void *             scratch ) {

  /* cnc state */
  ulong * cnc_diag;
  ulong   cnc_diag_tpu_pub_cnt;
  ulong   cnc_diag_tpu_pub_sz;
  ulong   cnc_diag_tpu_conn_live_cnt;

  /* out frag stream state */
  ulong   depth;  /* ==fd_mcache_depth( mcache ), depth of the mcache / positive integer power of 2 */
  ulong * sync;   /* ==fd_mcache_seq_laddr( mcache ), local addr where replay mcache sync info is published */
  ulong   seq;    /* seq replay frag sequence number to publish */

  void *  base;   /* ==fd_wksp_containing( dcache ), chunk reference address in the tile's local address space */
  ulong   chunk0; /* ==fd_dcache_compact_chunk0( base, dcache, pkt_max ) */
  ulong   wmark;  /* ==fd_dcache_compact_wmark ( base, dcache, _pkt_max ), packets chunks start in [chunk0,wmark] */
  ulong   chunk;  /* Chunk where next packet will be written, in [chunk0,wmark] */

  /* housekeeping state */
  ulong async_min; /* minimum number of ticks between processing a housekeeping event, positive integer power of 2 */

  ulong mtu = FD_TPU_MTU;

  do {

    FD_LOG_INFO(( "Booting quic" ));

    if( FD_UNLIKELY( !scratch ) ) {
      FD_LOG_WARNING(( "NULL scratch" ));
      return 1;
    }

    if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)scratch, fd_quic_tile_scratch_align() ) ) ) {
      FD_LOG_WARNING(( "misaligned scratch" ));
      return 1;
    }

    /* cnc state init */

    if( FD_UNLIKELY( !cnc ) ) { FD_LOG_WARNING(( "NULL cnc" )); return 1; }
    if( FD_UNLIKELY( fd_cnc_app_sz( cnc )<64UL ) ) { FD_LOG_WARNING(( "cnc app sz must be at least 64" )); return 1; }
    if( FD_UNLIKELY( fd_cnc_signal_query( cnc )!=FD_CNC_SIGNAL_BOOT ) ) { FD_LOG_WARNING(( "already booted" )); return 1; }

    cnc_diag = (ulong *)fd_cnc_app_laddr( cnc );

    cnc_diag_tpu_pub_cnt       = 0UL;
    cnc_diag_tpu_pub_sz        = 0UL;
    cnc_diag_tpu_conn_live_cnt = 0UL;

    /* quic config init */

    if( FD_UNLIKELY( !quic_cfg ) ) { FD_LOG_WARNING(( "NULL quic cfg" )); return 1; }

    quic_cfg->cb_conn_new           = fd_tpu_conn_create;
    quic_cfg->cb_handshake_complete = NULL;
    quic_cfg->cb_conn_final         = NULL;
    quic_cfg->cb_stream_new         = fd_tpu_stream_create;
    quic_cfg->cb_stream_notify      = fd_tpu_stream_notify;
    quic_cfg->cb_stream_receive     = fd_tpu_stream_receive;

    quic_cfg->alpns    = (uchar const *)"solana-tpu";
    quic_cfg->alpns_sz = 10UL;

    quic_cfg->now_fn  = fd_tpu_now;
    quic_cfg->now_ctx = NULL;

    /* quic server init */

    if( FD_UNLIKELY( !quic ) ) { FD_LOG_WARNING(( "NULL quic" )); return 1; }

    /* out frag stream init */

    if( FD_UNLIKELY( !mcache ) ) { FD_LOG_WARNING(( "NULL mcache" )); return 1; }
    depth = fd_mcache_depth    ( mcache );
    sync  = fd_mcache_seq_laddr( mcache );

    seq = fd_mcache_seq_query( sync );

    if( FD_UNLIKELY( !dcache ) ) { FD_LOG_WARNING(( "NULL dcache" )); return 1; }

    base = fd_wksp_containing( dcache );
    if( FD_UNLIKELY( !base ) ) { FD_LOG_WARNING(( "fd_wksp_containing failed" )); return 1; }

    if( FD_UNLIKELY( !fd_dcache_compact_is_safe( base, dcache, mtu, depth ) ) ) {
      FD_LOG_WARNING(( "--dcache not compatible with wksp base and --mcache depth" ));
      return 1;
    }

    chunk0 = fd_dcache_compact_chunk0( base, dcache );
    wmark  = fd_dcache_compact_wmark ( base, dcache, mtu );
    chunk  = FD_VOLATILE_CONST( cnc_diag[ FD_QUIC_CNC_DIAG_CHUNK_IDX ] );
    if( FD_UNLIKELY( !((chunk0<=chunk) & (chunk<=wmark)) ) ) chunk = chunk0;
      FD_LOG_INFO(( "out of bounds cnc chunk index; overriding initial chunk to chunk0" ));
    FD_LOG_INFO(( "chunk %lu", chunk ));

  } while(0);

  FD_LOG_INFO(( "Running QUIC (shard %lu)", shard ));
  fd_cnc_signal( cnc, FD_CNC_SIGNAL_RUN );
  long then = fd_tickcount();
  long now  = then;
  for(;;) {

    /* Do housekeeping at a low rate in the background */
    if( FD_UNLIKELY( (now-then)>=0L ) ) {

      /* Send synchronization info */
      fd_mcache_seq_update( sync, seq );

      fd_cnc_heartbeat( cnc, now );

      /* Receive command-and-control signals */
      ulong s = fd_cnc_signal_query( cnc );
      if( FD_UNLIKELY( s!=FD_CNC_SIGNAL_RUN ) ) {
        if( FD_LIKELY( s==FD_CNC_SIGNAL_HALT ) ) break;
        fd_cnc_signal( cnc, FD_CNC_SIGNAL_RUN );
      }

      /* Reload housekeeping timer */
      then = now + (long)fd_tempo_async_reload( rng, async_min );
    }

    fd_quic_service( quic );

  }

  do {

    FD_LOG_INFO(( "Halting quic" ));

    /* TODO close all open QUIC conns */

    FD_LOG_INFO(( "Halted replay" ));
    fd_cnc_signal( cnc, FD_CNC_SIGNAL_BOOT );

  } while(0);

  return 0;
}
