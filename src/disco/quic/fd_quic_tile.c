#include "fd_quic.h"

#if !FD_HAS_HOSTED
#error "fd_quic tile requires FD_HAS_HOSTED"
#endif

#define SCRATCH_ALLOC( a, s ) (__extension__({                    \
    ulong _scratch_alloc = fd_ulong_align_up( scratch_top, (a) ); \
    scratch_top = _scratch_alloc + (s);                           \
    (void *)_scratch_alloc;                                       \
  }))

/* dcache app region related ******************************************/

FD_FN_CONST static inline ulong
fd_quic_chunk_idx( ulong chunk0,
                   ulong chunk ) {
  return ((chunk-chunk0)*FD_CHUNK_FOOTPRINT) / fd_ulong_align_up( FD_TPU_DCACHE_MTU, FD_CHUNK_FOOTPRINT );
}

/* fd_quic_dcache_msg_ctx returns a pointer to the TPU/QUIC message
   context struct for the given dcache app laddr and chunk.  app_laddr
   points to the first byte of the dcache's app region in the tile's
   local address space and has FD_DCACHE_ALIGN alignment (see
   fd_dcache_app_laddr()).  chunk must be within the valid bounds for
   this dcache. */

FD_FN_CONST static inline fd_quic_tpu_msg_ctx_t *
fd_quic_dcache_msg_ctx( uchar * app_laddr,
                        ulong   chunk0,
                        ulong   chunk ) {
  fd_quic_tpu_msg_ctx_t * msg_arr = (fd_quic_tpu_msg_ctx_t *)app_laddr;
  return &msg_arr[ fd_quic_chunk_idx( chunk0, chunk ) ];
}

/* QUIC context related ***********************************************/

/* Local publish queue populated by QUIC service callbacks */
#define QUEUE_NAME pubq
#define QUEUE_T    fd_quic_tpu_msg_ctx_t *
#include "../../util/tmpl/fd_queue_dynamic.c"

/* fd_quic_tpu_ctx_t is the tile context object provided to callbacks
   from fd_quic. */

struct fd_quic_tpu_ctx {
  /* dcache */

  uchar * base;        /* dcache chunk region */
  uchar * dcache_app;  /* dcache app region */
  ulong   chunk0;
  ulong   wmark;

  ulong   chunk;       /* current dcache chunk idx */

  /* mcache */
  ulong            inflight_streams;
  fd_frag_meta_t * mcache;
  ulong          * seq;
  ulong            depth;

  /* publish stack */

  fd_quic_tpu_msg_ctx_t ** pubq;

  /* meta */

  ulong   cnc_diag_tpu_conn_live_cnt;
  ulong   cnc_diag_tpu_conn_seq;
};
typedef struct fd_quic_tpu_ctx fd_quic_tpu_ctx_t;

/* QUIC callbacks *****************************************************/

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
                    void *           _ctx ) {

  conn->local_conn_id = ++conn_seq;

  fd_quic_tpu_ctx_t * ctx = (fd_quic_tpu_ctx_t *)_ctx;
  ctx->cnc_diag_tpu_conn_seq = conn_seq;
  ctx->cnc_diag_tpu_conn_live_cnt++;
}

/* fd_tpu_conn_destroy implements fd_quic_cb_conn_final_t */
static void
fd_tpu_conn_destroy( fd_quic_conn_t * conn,
                     void *           _ctx ) {
  (void)conn;

  fd_quic_tpu_ctx_t * ctx = (fd_quic_tpu_ctx_t *)_ctx;
  ctx->cnc_diag_tpu_conn_live_cnt--;
}

/* fd_tpu_stream_create implements fd_quic_cb_stream_new_t */
static void
fd_tpu_stream_create( fd_quic_stream_t * stream,
                      void *             _ctx,
                      int                type ) {

  /* At this point, the QUIC client and server have agreed to open a
     stream.  In case the client has opened this stream, it is assumed
     that the QUIC implementation has verified that the client has the
     necessary stream quota to do so. */

  (void)type; /* TODO reject bidi streams? */

  /* Load QUIC state */

  fd_quic_tpu_ctx_t * ctx = (fd_quic_tpu_ctx_t *)_ctx;

  ulong conn_id   = stream->conn->local_conn_id;
  ulong stream_id = stream->stream_id;

  /* Load dcache info */

  uchar * const base       = ctx->base;
  uchar * const dcache_app = ctx->dcache_app;
  ulong   const chunk0     = ctx->chunk0;
  ulong   const wmark      = ctx->wmark;
  ulong         chunk      = ctx->chunk;
  
  /* Allocate new dcache entry */

  chunk = fd_dcache_compact_next( chunk, FD_TPU_DCACHE_MTU, chunk0, wmark );

  fd_quic_tpu_msg_ctx_t * msg_ctx = fd_quic_dcache_msg_ctx( dcache_app, chunk0, chunk );
  msg_ctx->conn_id   = conn_id;
  msg_ctx->stream_id = stream_id;
  msg_ctx->data      = fd_chunk_to_laddr( base, chunk );
  msg_ctx->sz        = 0U;
  msg_ctx->tsorig    = (uint)fd_frag_meta_ts_comp( fd_tickcount() );

  /* By default the dcache only has headroom for one in-flight fragment, but
     QUIC might have many. If we exceed the headroom, we publish a dummy
     mcache entry to evict the reader from this fragment we want to use so we
     can start using it.
     
     This is not ideal because if the reader is already done with the fragment
     we are writing a useless mcache entry, so we try and do it only when
     needed.
     
     The QUIC receive path might typically execute stream_create,
     stream_receive, and stream_notice serially, so it is often the case that
     even if we are handling multiple new connections in one receive batch,
     the in-flight count remains zero or one. */
  if( ctx->inflight_streams > 0 ) {
    ulong ctl   = fd_frag_meta_ctl( 0, 1 /* som */, 1 /* eom */, 0 /* err */ );
    ulong tsnow = fd_frag_meta_ts_comp( fd_tickcount() );
    fd_mcache_publish( ctx->mcache, ctx->depth, *ctx->seq, 1, 0, 0, ctl, tsnow, tsnow );
    *ctx->seq = fd_seq_inc( *ctx->seq, 1UL );
  }

  ctx->inflight_streams += 1;

  /* Wind up for next callback */

  ctx->chunk      = chunk;    /* Update dcache chunk index */
  stream->context = msg_ctx;  /* Update stream dcache entry */
}

/* fd_tpu_stream_receive implements fd_quic_cb_stream_receive_t */
static void
fd_tpu_stream_receive( fd_quic_stream_t * stream,
                       void *             stream_ctx,
                       uchar const *      data,
                       ulong              data_sz,
                       ulong              offset,
                       int                fin ) {

  (void)fin; /* TODO instantly publish if offset==0UL && fin */

  /* Bounds check */
  /* TODO this bounds check is not complete and assumes that the QUIC
     implementation rejects obviously invalid offset values, e.g. those
     that would overflow the data pointer. */

  ulong total_sz = offset+data_sz;
  if( FD_UNLIKELY( total_sz>FD_TPU_MTU || total_sz<offset ) ) {
    //fd_quic_stream_close( stream, 0x03 ); /* FIXME fd_quic_stream_close not implemented */
    return;  /* oversz stream */
  }

  /* Load QUIC state */

  ulong conn_id   = stream->conn->local_conn_id;
  ulong stream_id = stream->stream_id;

  /* Load existing dcache chunk ctx */

  fd_quic_tpu_msg_ctx_t * msg_ctx = (fd_quic_tpu_msg_ctx_t *)stream_ctx;
  if( FD_UNLIKELY( msg_ctx->conn_id != conn_id || msg_ctx->stream_id != stream_id ) ) {
    //fd_quic_stream_close( stream, 0x03 ); /* FIXME fd_quic_stream_close not implemented */
    FD_LOG_WARNING(( "dcache overflow while demuxing %lu!=%lu %lu!=%lu", conn_id, msg_ctx->conn_id, stream_id, msg_ctx->stream_id ));
    return;  /* overrun */
  }

  /* Append data into chunk */

  fd_memcpy( msg_ctx->data + offset, data, data_sz );
  msg_ctx->sz = (uint)total_sz;
}

/* fd_tpu_stream_notify implements fd_quic_cb_stream_notify_t */
static void
fd_tpu_stream_notify( fd_quic_stream_t * stream,
                      void *             stream_ctx,
                      int                type ) {
  /* Load QUIC state */

  fd_quic_tpu_msg_ctx_t * msg_ctx = (fd_quic_tpu_msg_ctx_t *)stream_ctx;
  fd_quic_conn_t *        conn    = stream->conn;
  fd_quic_t *             quic    = conn->quic;
  fd_quic_tpu_ctx_t *     ctx = quic->cb.quic_ctx; /* TODO ugly */

  if( FD_UNLIKELY( type!=FD_QUIC_NOTIFY_END ) ) {
    ctx->inflight_streams -= 1;
    return;  /* not a successful stream close */
  }

  ulong conn_id   = stream->conn->local_conn_id;
  ulong stream_id = stream->stream_id;
  if( FD_UNLIKELY( msg_ctx->conn_id != conn_id || msg_ctx->stream_id != stream_id ) )
    return;  /* overrun */

  /* Mark message as completed */

  msg_ctx->stream_id = ULONG_MAX;

  /* Add to local publish queue */

  if( FD_UNLIKELY( pubq_full( ctx->pubq ) ) ) {
    FD_LOG_WARNING(( "pubq full, dropping" ));
    return;
  }
  pubq_push( ctx->pubq, msg_ctx );
}

/* Tile ***************************************************************/

ulong
fd_quic_tile_scratch_footprint( ulong depth ) {
  return pubq_footprint( depth );
}

int
fd_quic_tile( fd_cnc_t *         cnc,
              fd_quic_t *        quic,
              fd_xsk_aio_t *     xsk_aio,
              fd_frag_meta_t *   mcache,
              uchar *            dcache,
              long               lazy,
              fd_rng_t *         rng,
              void *             scratch,
              double             tick_per_ns ) {

  /* cnc state */
  ulong * cnc_diag;
  ulong   cnc_diag_tpu_pub_cnt;
  ulong   cnc_diag_tpu_pub_sz;

  /* out frag stream state */
  ulong   depth;  /* ==fd_mcache_depth( mcache ), depth of the mcache / positive integer power of 2 */
  ulong * sync;   /* ==fd_mcache_seq_laddr( mcache ), local addr where QUIC mcache sync info is published */
  ulong   seq;    /* seq QUIC frag sequence number to publish */

  void *  base;   /* ==fd_wksp_containing( dcache ), chunk reference address in the tile's local address space */
  ulong   chunk0; /* ==fd_dcache_compact_chunk0( base, dcache ) */
  ulong   chunk1; /* ==fd_dcache_compact_chunk1( base, dcache ) */
  ulong   wmark;  /* ==fd_dcache_compact_wmark ( base, dcache, _pkt_max ), packets chunks start in [chunk0,wmark] */
  ulong   chunk;  /* Chunk where next packet will be written, in [chunk0,wmark] */

  /* quic context */
  fd_quic_tpu_ctx_t quic_ctx = {0};

  /* local publish queue */
  fd_quic_tpu_msg_ctx_t ** msg_pubq;

  /* housekeeping state */
  ulong async_min; /* minimum number of ticks between processing a housekeeping event, positive integer power of 2 */

  ulong mtu = FD_TPU_DCACHE_MTU;

  /* txn parser */
  fd_txn_parse_counters_t txn_parse_counters = {0};

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

    ulong scratch_top = (ulong)scratch;

    /* cnc state init */

    if( FD_UNLIKELY( !cnc ) ) { FD_LOG_WARNING(( "NULL cnc" )); return 1; }
    if( FD_UNLIKELY( fd_cnc_app_sz( cnc )<64UL ) ) { FD_LOG_WARNING(( "cnc app sz must be at least 64" )); return 1; }
    if( FD_UNLIKELY( fd_cnc_signal_query( cnc )!=FD_CNC_SIGNAL_BOOT ) ) { FD_LOG_WARNING(( "already booted" )); return 1; }

    cnc_diag = (ulong *)fd_cnc_app_laddr( cnc );

    cnc_diag_tpu_pub_cnt = 0UL;
    cnc_diag_tpu_pub_sz  = 0UL;

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

    if( FD_UNLIKELY( fd_dcache_app_sz( dcache ) < fd_quic_dcache_app_footprint( depth ) ) ) {
      FD_LOG_WARNING(( "--dcache app sz too small (min=%lu have=%lu)",
                       fd_quic_dcache_app_footprint( depth ),
                       fd_dcache_app_sz( dcache ) ));
      return 1;
    }

    chunk0 = fd_dcache_compact_chunk0( base, dcache );
    chunk1 = fd_dcache_compact_chunk1( base, dcache );
    wmark  = fd_dcache_compact_wmark ( base, dcache, mtu );
    chunk  = FD_VOLATILE_CONST( cnc_diag[ FD_QUIC_CNC_DIAG_CHUNK_IDX ] );
    if( FD_UNLIKELY( !((chunk0<=chunk) & (chunk<=wmark)) ) ) {
      chunk = chunk0;
      FD_LOG_INFO(( "out of bounds cnc chunk index; overriding initial chunk to chunk0" ));
    }

    FD_LOG_INFO(( "dcache chunk  %lu", chunk  ));
    FD_LOG_INFO(( "dcache chunk0 %lu", chunk0 ));
    FD_LOG_INFO(( "dcache wmark  %lu", wmark  ));
    FD_LOG_INFO(( "dcache chunk1 %lu", chunk1 ));
    FD_LOG_INFO(( "dcache max chunk_idx %lu", fd_quic_chunk_idx( chunk0, chunk1 ) ));

    /* local pubq init */

    msg_pubq = pubq_join( pubq_new( SCRATCH_ALLOC( pubq_align(), pubq_footprint( depth ) ), depth ) );
    if( FD_UNLIKELY( !msg_pubq ) ) { FD_LOG_WARNING(( "pubq join failed" )); return 1; }

    /* quic server init */

    if( FD_UNLIKELY( !quic    ) ) { FD_LOG_WARNING(( "NULL quic"          ) ); return 1; }
    fd_quic_callbacks_t * quic_cb = &quic->cb;
    if( FD_UNLIKELY( !quic_cb ) ) { FD_LOG_WARNING(( "NULL quic callbacks") ); return 1; }

    quic_cb->conn_new         = fd_tpu_conn_create;
    quic_cb->conn_hs_complete = NULL;
    quic_cb->conn_final       = fd_tpu_conn_destroy;
    quic_cb->stream_new       = fd_tpu_stream_create;
    quic_cb->stream_notify    = fd_tpu_stream_notify;
    quic_cb->stream_receive   = fd_tpu_stream_receive;

    quic_cb->now     = fd_tpu_now;
    quic_cb->now_ctx = NULL;

    quic_ctx.base       = base;
    quic_ctx.dcache_app = fd_dcache_app_laddr( dcache );
    quic_ctx.chunk0     = chunk0;
    quic_ctx.wmark      = wmark;
    quic_ctx.chunk      = chunk;
    quic_ctx.pubq       = msg_pubq;
    quic_ctx.cnc_diag_tpu_conn_live_cnt = 0UL;
    quic_ctx.seq        = &seq;
    quic_ctx.mcache     = mcache;
    quic_ctx.depth      = depth;
    quic_ctx.inflight_streams = 0UL;

    quic_cb->quic_ctx = &quic_ctx;

    if( FD_UNLIKELY( !fd_quic_init( quic ) ) ) { FD_LOG_WARNING(( "fd_quic_init failed" )); return 1; }

    /* housekeeping init */

    if( lazy<=0L ) lazy = fd_tempo_lazy_default( depth );
    FD_LOG_INFO(( "Configuring housekeeping (lazy %li ns)", lazy ));

    async_min = fd_tempo_async_min( lazy, 1UL /*event_cnt*/, (float)tick_per_ns );
    if( FD_UNLIKELY( !async_min ) ) { FD_LOG_WARNING(( "bad lazy" )); return 1; }

  } while(0);

  ulong tx_idx  = fd_tile_idx();

  FD_LOG_INFO(( "running QUIC server" ));
  fd_cnc_signal( cnc, FD_CNC_SIGNAL_RUN );
  long then = fd_tickcount();
  long now  = then;
  for(;;) {

    /* Do housekeeping at a low rate in the background */
    if( FD_UNLIKELY( (now-then)>=0L ) ) {

      /* Send synchronization info */
      fd_mcache_seq_update( sync, seq );

      fd_cnc_heartbeat( cnc, now );
      FD_COMPILER_MFENCE();
      cnc_diag[ FD_QUIC_CNC_DIAG_CHUNK_IDX         ]  = chunk;
      cnc_diag[ FD_QUIC_CNC_DIAG_TPU_PUB_CNT       ] += cnc_diag_tpu_pub_cnt;
      cnc_diag[ FD_QUIC_CNC_DIAG_TPU_PUB_SZ        ] += cnc_diag_tpu_pub_sz;
      cnc_diag[ FD_QUIC_CNC_DIAG_TPU_CONN_LIVE_CNT ]  = quic_ctx.cnc_diag_tpu_conn_live_cnt;
      cnc_diag[ FD_QUIC_CNC_DIAG_TPU_CONN_SEQ      ]  = quic_ctx.cnc_diag_tpu_conn_seq;
      FD_COMPILER_MFENCE();
      cnc_diag_tpu_pub_cnt = 0UL;
      cnc_diag_tpu_pub_sz  = 0UL;

      /* Receive command-and-control signals */
      ulong s = fd_cnc_signal_query( cnc );
      if( FD_UNLIKELY( s!=FD_CNC_SIGNAL_RUN ) ) {
        if( FD_LIKELY( s==FD_CNC_SIGNAL_HALT ) ) break;
        fd_cnc_signal( cnc, FD_CNC_SIGNAL_RUN );
      }

      /* Reload housekeeping timer */
      then = now + (long)fd_tempo_async_reload( rng, async_min );
    }

    /* Poll network backend */
    fd_xsk_aio_service( xsk_aio );

    /* Service QUIC clients */
    fd_quic_service( quic );

    /* Update locals */
    chunk = quic_ctx.chunk;

    /* Publish completed messages */
    ulong pub_cnt = pubq_cnt( msg_pubq );
    for( ulong i=0; i<pub_cnt; i++ ) {

      fd_quic_tpu_msg_ctx_t * msg = msg_pubq[ i ];

      if( FD_UNLIKELY( msg->stream_id != ULONG_MAX ) )
        continue;  /* overrun */

      /* Get byte slice backing serialized txn data */

      uchar * txn    = msg->data;
      ulong   txn_sz = msg->sz;

      FD_TEST( txn_sz<=1232UL );

      /* At this point dcache only contains raw payload of txn.
         Beyond end of txn, but within bounds of msg layout, add a trailer
         describing the txn layout.

         [ payload      ] (txn_sz bytes)
         [ pad-align 2B ] (? bytes)
         [ fd_txn_t     ] (? bytes)
         [ payload_sz   ] (2B) */

      /* Ensure sufficient space to store trailer */

      void * txn_t = (void *)( fd_ulong_align_up( (ulong)msg->data + txn_sz, 2UL ) );
      if( FD_UNLIKELY( (mtu - ((ulong)txn_t - (ulong)msg->data)) < (FD_TXN_MAX_SZ+2UL) ) ) {
        FD_LOG_WARNING(( "dcache entry too small" ));
        continue;
      }

      /* Parse transaction */

      ulong txn_t_sz = fd_txn_parse( txn, txn_sz, txn_t, &txn_parse_counters );
      if( txn_t_sz==0 ) {
        FD_LOG_DEBUG(( "fd_txn_parse(sz=%lu) failed", txn_sz ));
        continue; /* invalid txn (terminate conn?) */
      }

      /* Write payload_sz */

      ushort * payload_sz = (ushort *)( (ulong)txn_t + txn_t_sz );
      *payload_sz = (ushort)txn_sz;

      /* End of message */

      void * msg_end = (void *)( (ulong)payload_sz + 2UL );

      /* Create mcache entry */

      ulong chunk  = fd_laddr_to_chunk( base, msg->data );
      ulong sz     = (ulong)msg_end - (ulong)msg->data;
      ulong sig    = 0; /* A non-dummy entry representing a finished transaction */
      ulong ctl    = fd_frag_meta_ctl( tx_idx, 1 /* som */, 1 /* eom */, 0 /* err */ );
      ulong tsorig = msg->tsorig;
      ulong tspub  = fd_frag_meta_ts_comp( fd_tickcount() );

      fd_mcache_publish( mcache, depth, seq, sig, chunk, sz, ctl, tsorig, tspub );
      quic_ctx.inflight_streams -= 1;

      /* Windup for the next iteration and accumulate diagnostics */

      seq = fd_seq_inc( seq, 1UL );
      cnc_diag_tpu_pub_cnt++;
      cnc_diag_tpu_pub_sz += sz;
    }
    pubq_remove_all( msg_pubq );

    now = fd_tickcount();
  }

  do {

    FD_LOG_INFO(( "Halting quic" ));
    fd_quic_leave( quic );

    /* TODO close all open QUIC conns */

    FD_LOG_INFO(( "Halted quic" ));
    fd_cnc_signal( cnc, FD_CNC_SIGNAL_BOOT );

  } while(0);

  return 0;
}

#undef SCRATCH_ALLOC
