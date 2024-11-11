#include "../../../../disco/tiles.h"

#include "generated/quic_seccomp.h"

#include "../../../../disco/metrics/fd_metrics.h"
#include "../../../../waltz/quic/fd_quic.h"
#include "../../../../waltz/xdp/fd_xsk_aio.h"
#include "../../../../waltz/xdp/fd_xsk.h"
#include "../../../../waltz/ip/fd_netlink.h"
#include "../../../../disco/quic/fd_tpu.h"

#include <linux/unistd.h>
#include <sys/random.h>

/* fd_quic provides a TPU server tile.

   This tile handles incoming transactions that clients request to be
   included in blocks.  Supported protocols currently include TPU/UDP
   and TPU/QUIC.

   The fd_quic tile acts as a plain old Tango producer writing to a cnc
   and an mcache.  The tile will defragment multi-packet TPU streams
   coming in from QUIC, such that each mcache/dcache pair forms a
   complete txn.  This requires the dcache mtu to be at least that of
   the largest allowed serialized txn size.

   QUIC tiles don't service network devices directly, but rely on
   packets being received by net tiles and forwarded on via. a mux
   (multiplexer).  An arbitrary number of QUIC tiles can be run.  Each
   UDP flow must stick to one QUIC tile. */

typedef struct {
  fd_tpu_reasm_t * reasm;

  fd_stem_context_t * stem;

  fd_quic_t *      quic;
  const fd_aio_t * quic_rx_aio;
  fd_aio_t         quic_tx_aio[1];

# define ED25519_PRIV_KEY_SZ (32)
# define ED25519_PUB_KEY_SZ  (32)
  uchar            tls_priv_key[ ED25519_PRIV_KEY_SZ ];
  uchar            tls_pub_key [ ED25519_PUB_KEY_SZ  ];
  fd_sha512_t      sha512[1]; /* used for signing */

  uchar buffer[ FD_NET_MTU ];

  ulong conn_seq; /* current quic connection sequence number */

  ulong round_robin_cnt;
  ulong round_robin_id;

  fd_wksp_t * in_mem;
  ulong       in_chunk0;
  ulong       in_wmark;

  fd_frag_meta_t * net_out_mcache;
  ulong *          net_out_sync;
  ulong            net_out_depth;
  ulong            net_out_seq;

  fd_wksp_t * net_out_mem;
  ulong       net_out_chunk0;
  ulong       net_out_wmark;
  ulong       net_out_chunk;

  fd_wksp_t * verify_out_mem;

  struct {
    ulong legacy_reasm_append [ FD_METRICS_COUNTER_QUIC_TILE_NON_QUIC_REASSEMBLY_APPEND_CNT ];
    ulong legacy_reasm_publish[ FD_METRICS_COUNTER_QUIC_TILE_NON_QUIC_REASSEMBLY_PUBLISH_CNT ];

    ulong reasm_append [ FD_METRICS_COUNTER_QUIC_TILE_REASSEMBLY_APPEND_CNT ];
    ulong reasm_publish[ FD_METRICS_COUNTER_QUIC_TILE_REASSEMBLY_PUBLISH_CNT ];
  } metrics;
} fd_quic_ctx_t;

FD_FN_CONST static inline fd_quic_limits_t
quic_limits( fd_topo_tile_t const * tile ) {
  fd_quic_limits_t limits = {
    .conn_cnt      = tile->quic.max_concurrent_connections,
    .handshake_cnt = tile->quic.max_concurrent_handshakes,

    /* fd_quic will not issue nor use any new connection IDs after
       completing a handshake.  Connection migration is not supported
       either. */
    .conn_id_cnt      = FD_QUIC_MIN_CONN_ID_CNT,
    .inflight_pkt_cnt = tile->quic.max_inflight_quic_packets,
    .tx_buf_sz        = 0,
    .rx_stream_cnt    = tile->quic.max_concurrent_streams_per_connection,
    .stream_pool_cnt  = tile->quic.max_concurrent_streams_per_connection * tile->quic.max_concurrent_connections,
  };
  return limits;
}

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 4096UL;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  fd_quic_limits_t limits = quic_limits( tile );
  ulong            l      = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof( fd_quic_ctx_t ), sizeof( fd_quic_ctx_t )      );
  l = FD_LAYOUT_APPEND( l, fd_aio_align(),           fd_aio_footprint()           );
  l = FD_LAYOUT_APPEND( l, fd_quic_align(),          fd_quic_footprint( &limits ) );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

/* legacy_stream_notify is called for transactions sent via TPU/UDP. For
   now both QUIC and non-QUIC transactions are accepted, with traffic
   type determined by port.

   UDP transactions must fit in one packet and cannot be fragmented, and
   notify here means the entire packet was received. */

static void
legacy_stream_notify( fd_quic_ctx_t * ctx,
                      uchar *         packet,
                      ulong           packet_sz ) {

  fd_stem_context_t * stem = ctx->stem;

  uint                  tsorig = (uint)fd_frag_meta_ts_comp( fd_tickcount() );
  fd_tpu_reasm_slot_t * slot   = fd_tpu_reasm_prepare( ctx->reasm, tsorig );

  int add_err = fd_tpu_reasm_append( ctx->reasm, slot, packet, packet_sz, 0UL );
  ctx->metrics.legacy_reasm_append[ add_err ]++;
  if( FD_UNLIKELY( add_err!=FD_TPU_REASM_SUCCESS ) ) return;

  uint   tspub = (uint)fd_frag_meta_ts_comp( fd_tickcount() );
  void * base  = ctx->verify_out_mem;
  ulong  seq   = stem->seqs[0];

  int pub_err = fd_tpu_reasm_publish( ctx->reasm, slot, stem->mcaches[0], base, seq, tspub );
  ctx->metrics.legacy_reasm_publish[ pub_err ]++;
  if( FD_UNLIKELY( pub_err!=FD_TPU_REASM_SUCCESS ) ) return;

  fd_stem_advance( stem, 0UL );
}

/* Because of the separate mcache for publishing network fragments
   back to networking tiles, which is not managed by the mux, we
   need to periodically update the sync. */
static void
during_housekeeping( fd_quic_ctx_t * ctx ) {
  fd_mcache_seq_update( ctx->net_out_sync, ctx->net_out_seq );
}

/* This tile always publishes messages downstream, even if there are
   no credits available.  It ignores the flow control of the downstream
   verify tile.  This is OK as the verify tile is written to expect
   this behavior, and enables the QUIC tile to publish as fast as it
   can.  It would currently be difficult trying to backpressure further
   up the stack to the network itself. */
static inline void
before_credit( fd_quic_ctx_t *     ctx,
               fd_stem_context_t * stem,
               int *               charge_busy ) {
  ctx->stem = stem;

  /* Publishes to mcache via callbacks */
  *charge_busy = fd_quic_service( ctx->quic );
}

static inline void
metrics_write( fd_quic_ctx_t * ctx ) {
  FD_MCNT_ENUM_COPY( QUIC_TILE, NON_QUIC_REASSEMBLY_APPEND,  ctx->metrics.legacy_reasm_append );
  FD_MCNT_ENUM_COPY( QUIC_TILE, NON_QUIC_REASSEMBLY_PUBLISH, ctx->metrics.legacy_reasm_publish );
  FD_MCNT_ENUM_COPY( QUIC_TILE, REASSEMBLY_APPEND,           ctx->metrics.reasm_append );
  FD_MCNT_ENUM_COPY( QUIC_TILE, REASSEMBLY_PUBLISH,          ctx->metrics.reasm_publish );

  FD_MCNT_SET(   QUIC, RECEIVED_PACKETS, ctx->quic->metrics.net_rx_pkt_cnt );
  FD_MCNT_SET(   QUIC, RECEIVED_BYTES,   ctx->quic->metrics.net_rx_byte_cnt );
  FD_MCNT_SET(   QUIC, SENT_PACKETS,     ctx->quic->metrics.net_tx_pkt_cnt );
  FD_MCNT_SET(   QUIC, SENT_BYTES,       ctx->quic->metrics.net_tx_byte_cnt );

  FD_MGAUGE_SET( QUIC, CONNECTIONS_ACTIVE,  ctx->quic->metrics.conn_active_cnt );
  FD_MCNT_SET(   QUIC, CONNECTIONS_CREATED, ctx->quic->metrics.conn_created_cnt );
  FD_MCNT_SET(   QUIC, CONNECTIONS_CLOSED,  ctx->quic->metrics.conn_closed_cnt );
  FD_MCNT_SET(   QUIC, CONNECTIONS_ABORTED, ctx->quic->metrics.conn_aborted_cnt );
  FD_MCNT_SET(   QUIC, CONNECTIONS_TIMED_OUT, ctx->quic->metrics.conn_timeout_cnt );
  FD_MCNT_SET(   QUIC, CONNECTIONS_RETRIED, ctx->quic->metrics.conn_retry_cnt );

  FD_MCNT_SET(   QUIC, CONNECTION_ERROR_NO_SLOTS,   ctx->quic->metrics.conn_err_no_slots_cnt );
  FD_MCNT_SET(   QUIC, CONNECTION_ERROR_TLS_FAIL,   ctx->quic->metrics.conn_err_tls_fail_cnt );
  FD_MCNT_SET(   QUIC, CONNECTION_ERROR_RETRY_FAIL, ctx->quic->metrics.conn_err_retry_fail_cnt );

  FD_MCNT_SET(   QUIC, HANDSHAKES_CREATED,         ctx->quic->metrics.hs_created_cnt );
  FD_MCNT_SET(   QUIC, HANDSHAKE_ERROR_ALLOC_FAIL, ctx->quic->metrics.hs_err_alloc_fail_cnt );

  FD_MCNT_SET(   QUIC, STREAM_OPENED, ctx->quic->metrics.stream_opened_cnt );
  FD_MCNT_ENUM_COPY( QUIC, STREAM_CLOSED, ctx->quic->metrics.stream_closed_cnt );
  FD_MGAUGE_SET( QUIC, STREAM_ACTIVE, ctx->quic->metrics.stream_active_cnt );

  FD_MCNT_SET(  QUIC, STREAM_RECEIVED_EVENTS, ctx->quic->metrics.stream_rx_event_cnt );
  FD_MCNT_SET(  QUIC, STREAM_RECEIVED_BYTES,  ctx->quic->metrics.stream_rx_byte_cnt );

  FD_MCNT_ENUM_COPY( QUIC, RECEIVED_FRAMES, ctx->quic->metrics.frame_rx_cnt );
}

static int
before_frag( fd_quic_ctx_t * ctx,
             ulong           in_idx,
             ulong           seq,
             ulong           sig ) {
  (void)in_idx;
  (void)seq;

  ulong proto = fd_disco_netmux_sig_proto( sig );
  if( FD_UNLIKELY( proto!=DST_PROTO_TPU_UDP && proto!=DST_PROTO_TPU_QUIC ) ) return 1;

  ulong hash = fd_disco_netmux_sig_hash( sig );
  if( FD_UNLIKELY( (hash % ctx->round_robin_cnt) != ctx->round_robin_id ) ) return 1;

  return 0;
}

static void
during_frag( fd_quic_ctx_t * ctx,
             ulong           in_idx,
             ulong           seq,
             ulong           sig,
             ulong           chunk,
             ulong           sz ) {
  (void)in_idx;
  (void)seq;
  (void)sig;

  if( FD_UNLIKELY( chunk<ctx->in_chunk0 || chunk>ctx->in_wmark || sz > FD_NET_MTU ) )
    FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->in_chunk0, ctx->in_wmark ));

  uchar * src = (uchar *)fd_chunk_to_laddr( ctx->in_mem, chunk );
  fd_memcpy( ctx->buffer, src, sz ); /* TODO: Eliminate copy... fd_aio needs refactoring */
}

static void
after_frag( fd_quic_ctx_t *     ctx,
            ulong               in_idx,
            ulong               seq,
            ulong               sig,
            ulong               chunk,
            ulong               sz,
            ulong               tsorig,
            fd_stem_context_t * stem ) {
  (void)in_idx;
  (void)seq;
  (void)chunk;
  (void)tsorig;
  (void)stem;

  ulong proto = fd_disco_netmux_sig_proto( sig );

  if( FD_LIKELY( proto==DST_PROTO_TPU_QUIC ) ) {
    fd_aio_pkt_info_t pkt = { .buf = ctx->buffer, .buf_sz = (ushort)sz };
    fd_aio_send( ctx->quic_rx_aio, &pkt, 1, NULL, 1 );
  } else if( FD_LIKELY( proto==DST_PROTO_TPU_UDP ) ) {
    ulong network_hdr_sz = fd_disco_netmux_sig_hdr_sz( sig );
    if( FD_UNLIKELY( sz<=network_hdr_sz ) ) {
      /* Transaction not valid if the packet isn't large enough for the network
         headers. */
      FD_MCNT_INC( QUIC_TILE, NON_QUIC_PACKET_TOO_SMALL, 1UL );
      return;
    }

    ulong data_sz = sz - network_hdr_sz;
    if( FD_UNLIKELY( data_sz<FD_TXN_MIN_SERIALIZED_SZ ) ) {
      /* Smaller than the smallest possible transaction */
      FD_MCNT_INC( QUIC_TILE, NON_QUIC_PACKET_TOO_SMALL, 1UL );
      return;
    }

    if( FD_UNLIKELY( data_sz>FD_TPU_MTU ) ) {
      /* Transaction couldn't possibly be valid if it's longer than transaction
         MTU so drop it. This is not required, as the txn will fail to parse,
         but it's a nice short circuit. */
      FD_MCNT_INC( QUIC_TILE, NON_QUIC_PACKET_TOO_LARGE, 1UL );
      return;
    }

    legacy_stream_notify( ctx, ctx->buffer+network_hdr_sz, data_sz );
  }
}

/* quic_now is called by the QUIC engine to get the current timestamp in
   UNIX time.  */

static ulong
quic_now( void * ctx ) {
  (void)ctx;
  return (ulong)fd_log_wallclock();
}

/* quic_conn_new is invoked by the QUIC engine whenever a new connection
   is being established. */
static void
quic_conn_new( fd_quic_conn_t * conn,
               void *           _ctx ) {
  fd_quic_ctx_t * ctx = (fd_quic_ctx_t *)_ctx;

  conn->local_conn_id = ++ctx->conn_seq;
}

/* quic_stream_new is called back by the QUIC engine whenever an open
   connection creates a new stream, at the time this is called, both the
   client and server must have agreed to open the stream.  In case the
   client has opened this stream, it is assumed that the QUIC
   implementation has verified that the client has the necessary stream
   quota to do so. */

static void
quic_stream_new( fd_quic_stream_t * stream,
                 void *             _ctx ) {

  /* Load QUIC state */

  fd_quic_ctx_t * ctx = (fd_quic_ctx_t *)_ctx;

  ulong conn_id   = stream->conn->local_conn_id;
  ulong stream_id = stream->stream_id;

  /* Acquire reassembly slot */

  uint                  tsorig = (uint)fd_frag_meta_ts_comp( fd_tickcount() );
  fd_tpu_reasm_slot_t * slot   = fd_tpu_reasm_prepare( ctx->reasm, tsorig );

  slot->conn_id   = conn_id;
  slot->stream_id = stream_id;

  /* Wire up with QUIC stream */

  stream->context = slot;

  /* Wind up for next iteration */

}

/* quic_stream_receive is called back by the QUIC engine when any stream
   in any connection being serviced receives new data.  Currently we
   simply copy received data out of the xsk (network device memory) into
   a local dcache. */

static void
quic_stream_receive( fd_quic_stream_t * stream,
                     void *             stream_ctx,
                     uchar const *      data,
                     ulong              data_sz,
                     ulong              offset,
                     int                fin ) {

  (void)fin; /* TODO instantly publish if offset==0UL && fin */

  /* Load TPU state */

  fd_quic_t *           quic     = stream->conn->quic;
  fd_quic_ctx_t *       quic_ctx = quic->cb.quic_ctx;
  fd_tpu_reasm_t *      reasm    = quic_ctx->reasm;
  fd_tpu_reasm_slot_t * slot     = stream_ctx;
  fd_quic_ctx_t *       ctx    = quic->cb.quic_ctx;

  /* Check if reassembly slot is still valid */

  ulong conn_id   = stream->conn->local_conn_id;
  ulong stream_id = stream->stream_id;

  if( FD_UNLIKELY( ( slot->conn_id   != conn_id   ) |
                   ( slot->stream_id != stream_id ) ) ) {
    return;  /* clobbered */
  }

  /* Append data into chunk, we know this is valid */

  int add_err = fd_tpu_reasm_append( reasm, slot, data, data_sz, offset );
  ctx->metrics.reasm_append[ add_err ]++;
}

/* quic_stream_notify is called back by the QUIC implementation when a
   stream is finished.  This could either be because it completed
   successfully after reading valid data, or it was closed prematurely
   for some other reason.  All streams must eventually notify.

   If we see a successful QUIC stream notify, it means we have received
   a full transaction and should publish it downstream to be verified
   and executed. */

static void
quic_stream_notify( fd_quic_stream_t * stream,
                    void *             stream_ctx,
                    int                type ) {

  /* Load TPU state */

  fd_quic_t *           quic   = stream->conn->quic;
  fd_quic_ctx_t *       ctx    = quic->cb.quic_ctx;
  fd_tpu_reasm_t *      reasm  = ctx->reasm;
  fd_tpu_reasm_slot_t * slot   = stream_ctx;
  fd_stem_context_t *   stem   = ctx->stem;
  fd_frag_meta_t *      mcache = stem->mcaches[0];
  void *                base   = ctx->verify_out_mem;

  /* Check if reassembly slot is still valid */

  ulong conn_id   = stream->conn->local_conn_id;
  ulong stream_id = stream->stream_id;

  if( FD_UNLIKELY( ( slot->conn_id   != conn_id   ) |
                   ( slot->stream_id != stream_id ) ) ) {
    FD_MCNT_INC( QUIC_TILE, REASSEMBLY_NOTIFY_CLOBBERED, 1UL );
    return;  /* clobbered */
  }

  /* Abort reassembly slot if QUIC stream closes non-gracefully */

  if( FD_UNLIKELY( type!=FD_QUIC_STREAM_NOTIFY_END ) ) {
    FD_MCNT_INC( QUIC_TILE, REASSEMBLY_NOTIFY_ABORTED, 1UL );
    fd_tpu_reasm_cancel( reasm, slot );
    return;  /* not a successful stream close */
  }

  /* Publish message */

  ulong  seq   = stem->seqs[0];
  uint   tspub = (uint)fd_frag_meta_ts_comp( fd_tickcount() );
  int pub_err = fd_tpu_reasm_publish( reasm, slot, mcache, base, seq, tspub );
  ctx->metrics.reasm_publish[ pub_err ]++;
  if( FD_UNLIKELY( pub_err!=FD_TPU_REASM_SUCCESS ) ) return;

  fd_stem_advance( stem, 0UL );
}

static int
quic_tx_aio_send( void *                    _ctx,
                  fd_aio_pkt_info_t const * batch,
                  ulong                     batch_cnt,
                  ulong *                   opt_batch_idx,
                  int                       flush ) {
  (void)flush;

  fd_quic_ctx_t * ctx = (fd_quic_ctx_t *)_ctx;

  for( ulong i=0; i<batch_cnt; i++ ) {
    void * dst = fd_chunk_to_laddr( ctx->net_out_mem, ctx->net_out_chunk );
    fd_memcpy( dst, batch[ i ].buf, batch[ i ].buf_sz );

    uchar const * packet = dst;
    uchar const * packet_end = packet + batch[i].buf_sz;
    uchar const * iphdr = packet + 14U;

    uint test_ethip = ( (uint)packet[12] << 16u ) | ( (uint)packet[13] << 8u ) | (uint)packet[23];
    uint   ip_dstaddr  = 0;
    if( FD_LIKELY( test_ethip==0x080011 ) ) {
      /* IPv4 is variable-length, so lookup IHL to find start of UDP */
      uint iplen = ( ( (uint)iphdr[0] ) & 0x0FU ) * 4U;
      uchar const * udp = iphdr + iplen;

      /* Ignore if UDP header is too short */
      if( FD_UNLIKELY( udp+8U>packet_end ) ) {
        FD_MCNT_INC( QUIC_TILE, QUIC_PACKET_TOO_SMALL, 1UL );
        continue;
      }

      /* Extract IP dest addr and UDP dest port */
      ip_dstaddr  =                  *(uint   *)( iphdr+16UL );
    }

    /* send packets are just round-robined by sequence number, so for now
       just indicate where they came from so they don't bounce back */
    ulong sig = fd_disco_netmux_sig( 0U, 0U, ip_dstaddr, DST_PROTO_OUTGOING, FD_NETMUX_SIG_MIN_HDR_SZ );

    ulong tspub  = (ulong)fd_frag_meta_ts_comp( fd_tickcount() );
    fd_mcache_publish( ctx->net_out_mcache,
                       ctx->net_out_depth,
                       ctx->net_out_seq,
                       sig,
                       ctx->net_out_chunk,
                       batch[ i ].buf_sz,
                       0,
                       0,
                       tspub );

    ctx->net_out_seq   = fd_seq_inc( ctx->net_out_seq, 1UL );
    ctx->net_out_chunk = fd_dcache_compact_next( ctx->net_out_chunk, FD_NET_MTU, ctx->net_out_chunk0, ctx->net_out_wmark );
  }

  if( FD_LIKELY( opt_batch_idx ) ) {
    *opt_batch_idx = batch_cnt;
  }

  return FD_AIO_SUCCESS;
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  (void)topo; (void)tile;

  /* The fd_quic implementation calls fd_log_wallclock() internally
     which itself calls clock_gettime() which on most kernels is not a
     real syscall but a virtual one in the process via. the vDSO.

     The first time this virtual call is made to the vDSO it does an
     mmap(2) of some shared memory into userspace, which cannot
     happen while sandboxed so we need to ensure that initialization
     happens here. */

  fd_log_wallclock();
}

static void
quic_tls_cv_sign( void *      signer_ctx,
                  uchar       signature[ static 64 ],
                  uchar const payload[ static 130 ] ) {
  fd_quic_ctx_t * ctx = signer_ctx;
  fd_sha512_t * sha512 = fd_sha512_join( ctx->sha512 );
  fd_ed25519_sign( signature, payload, 130UL, ctx->tls_pub_key, ctx->tls_priv_key, sha512 );
  fd_sha512_leave( sha512 );
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  if( FD_UNLIKELY( tile->in_cnt<1UL ||
                   strcmp( topo->links[ tile->in_link_id[ 0UL ] ].name, "net_quic" ) ) )
    FD_LOG_ERR(( "quic tile has none or unexpected input links %lu %s %s",
                 tile->in_cnt, topo->links[ tile->in_link_id[ 0 ] ].name, topo->links[ tile->in_link_id[ 1 ] ].name ));

  if( FD_UNLIKELY( tile->out_cnt!=2UL ||
                   strcmp( topo->links[ tile->out_link_id[ 0UL ] ].name, "quic_verify" ) ||
                   strcmp( topo->links[ tile->out_link_id[ 1UL ] ].name, "quic_net" ) ) )
    FD_LOG_ERR(( "quic tile has none or unexpected output links %lu %s %s",
                 tile->out_cnt, topo->links[ tile->out_link_id[ 0 ] ].name, topo->links[ tile->out_link_id[ 1 ] ].name ));

  if( FD_UNLIKELY( !tile->in_cnt ) ) FD_LOG_ERR(( "quic tile in cnt is zero" ));

  ulong depth = tile->quic.depth;
  if( topo->links[ tile->out_link_id[ 0 ] ].depth != depth )
    FD_LOG_ERR(( "quic tile in depths are not equal" ));

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_quic_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_quic_ctx_t ), sizeof( fd_quic_ctx_t ) );

  /* End privileged allocs */

  FD_TEST( getrandom( ctx->tls_priv_key, ED25519_PRIV_KEY_SZ, 0 )==ED25519_PRIV_KEY_SZ );
  fd_sha512_t * sha512 = fd_sha512_join( fd_sha512_new( ctx->sha512 ) );
  fd_ed25519_public_from_private( ctx->tls_pub_key, ctx->tls_priv_key, sha512 );
  fd_sha512_leave( sha512 );

  fd_aio_t * quic_tx_aio = fd_aio_join( fd_aio_new( ctx->quic_tx_aio, ctx, quic_tx_aio_send ) );
  if( FD_UNLIKELY( !quic_tx_aio ) ) FD_LOG_ERR(( "fd_aio_join failed" ));

  fd_quic_limits_t limits = quic_limits( tile );
  fd_quic_t * quic = fd_quic_join( fd_quic_new( FD_SCRATCH_ALLOC_APPEND( l, fd_quic_align(), fd_quic_footprint( &limits ) ), &limits ) );
  if( FD_UNLIKELY( !quic ) ) FD_LOG_ERR(( "fd_quic_join failed" ));

  if( FD_UNLIKELY( tile->quic.ack_delay_millis == 0 ) ) {
    FD_LOG_ERR(( "Invalid `ack_delay_millis`: must be greater than zero" ));
  }
  if( FD_UNLIKELY( tile->quic.ack_delay_millis >= tile->quic.idle_timeout_millis ) ) {
    FD_LOG_ERR(( "Invalid `ack_delay_millis`: must be lower than `idle_timeout_millis`" ));
  }

  quic->config.role                       = FD_QUIC_ROLE_SERVER;
  quic->config.net.ip_addr                = tile->quic.ip_addr;
  quic->config.net.listen_udp_port        = tile->quic.quic_transaction_listen_port;
  quic->config.idle_timeout               = tile->quic.idle_timeout_millis * 1000000UL;
  quic->config.ack_delay                  = tile->quic.ack_delay_millis * 1000000UL;
  quic->config.initial_rx_max_stream_data = FD_TXN_MTU;
  quic->config.retry                      = tile->quic.retry;
  fd_memcpy( quic->config.link.src_mac_addr, tile->quic.src_mac_addr, 6 );
  fd_memcpy( quic->config.identity_public_key, ctx->tls_pub_key, ED25519_PUB_KEY_SZ );

  quic->config.sign         = quic_tls_cv_sign;
  quic->config.sign_ctx     = ctx;

  quic->cb.conn_new         = quic_conn_new;
  quic->cb.conn_hs_complete = NULL;
  quic->cb.conn_final       = NULL;
  quic->cb.stream_new       = quic_stream_new;
  quic->cb.stream_receive   = quic_stream_receive;
  quic->cb.stream_notify    = quic_stream_notify;
  quic->cb.now              = quic_now;
  quic->cb.now_ctx          = NULL;
  quic->cb.quic_ctx         = ctx;

  fd_quic_set_aio_net_tx( quic, quic_tx_aio );
  if( FD_UNLIKELY( !fd_quic_init( quic ) ) ) FD_LOG_ERR(( "fd_quic_init failed" ));

  /* Put a bound on chunks we read from the input, to make sure they
      are within in the data region of the workspace. */
  fd_topo_link_t * link0 = &topo->links[ tile->in_link_id[ 0 ] ];

  for( ulong i=1UL; i<tile->in_cnt; i++ ) {
    fd_topo_link_t * link = &topo->links[ tile->in_link_id[ i ] ];

    if( FD_UNLIKELY( !tile->in_link_poll[ i ] ) ) continue;

    if( FD_UNLIKELY( topo->objs[ link0->dcache_obj_id ].wksp_id!=topo->objs[ link->dcache_obj_id ].wksp_id ) ) FD_LOG_ERR(( "quic tile reads input from multiple workspaces" ));
    if( FD_UNLIKELY( link0->mtu!=link->mtu         ) ) FD_LOG_ERR(( "quic tile reads input from multiple links with different MTUs" ));
  }

  ctx->in_mem    = topo->workspaces[ topo->objs[ link0->dcache_obj_id ].wksp_id ].wksp;
  ctx->in_chunk0 = fd_disco_compact_chunk0( ctx->in_mem );
  ctx->in_wmark  = fd_disco_compact_wmark ( ctx->in_mem, link0->mtu );

  fd_topo_link_t * net_out = &topo->links[ tile->out_link_id[ 1 ] ];

  ctx->net_out_mcache = net_out->mcache;
  ctx->net_out_sync   = fd_mcache_seq_laddr( ctx->net_out_mcache );
  ctx->net_out_depth  = fd_mcache_depth( ctx->net_out_mcache );
  ctx->net_out_seq    = fd_mcache_seq_query( ctx->net_out_sync );
  ctx->net_out_chunk0 = fd_dcache_compact_chunk0( fd_wksp_containing( net_out->dcache ), net_out->dcache );
  ctx->net_out_mem    = topo->workspaces[ topo->objs[ net_out->dcache_obj_id ].wksp_id ].wksp;
  ctx->net_out_wmark  = fd_dcache_compact_wmark ( ctx->net_out_mem, net_out->dcache, net_out->mtu );
  ctx->net_out_chunk  = ctx->net_out_chunk0;

  fd_topo_link_t * verify_out = &topo->links[ tile->out_link_id[ 0 ] ];

  ctx->verify_out_mem = topo->workspaces[ topo->objs[ verify_out->reasm_obj_id ].wksp_id ].wksp;

  ctx->reasm = verify_out->reasm;
  if( FD_UNLIKELY( !ctx->reasm ) )
    FD_LOG_ERR(( "invalid tpu_reasm parameters" ));

  ctx->conn_seq    = 0UL;

  ctx->quic        = quic;
  ctx->quic_rx_aio = fd_quic_get_aio_net_rx( quic );

  ctx->round_robin_cnt = fd_topo_tile_name_cnt( topo, tile->name );
  ctx->round_robin_id  = tile->kind_id;

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, 1UL );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  (void)topo;
  (void)tile;

  populate_sock_filter_policy_quic( out_cnt, out, (uint)fd_log_private_logfile_fd() );
  return sock_filter_policy_quic_instr_cnt;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  (void)topo;
  (void)tile;

  if( FD_UNLIKELY( out_fds_cnt<2UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  return out_cnt;
}

#define STEM_BURST (1UL)

#define STEM_CALLBACK_CONTEXT_TYPE  fd_quic_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_quic_ctx_t)

#define STEM_CALLBACK_DURING_HOUSEKEEPING during_housekeeping
#define STEM_CALLBACK_METRICS_WRITE       metrics_write
#define STEM_CALLBACK_BEFORE_CREDIT       before_credit
#define STEM_CALLBACK_BEFORE_FRAG         before_frag
#define STEM_CALLBACK_DURING_FRAG         during_frag
#define STEM_CALLBACK_AFTER_FRAG          after_frag

#include "../../../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_quic = {
  .name                     = "quic",
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};
