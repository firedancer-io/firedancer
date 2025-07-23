
/* fd_qblast_tile creates and maintains multiple QUIC connections.
   This tile establishes a configurable number of QUIC connections to
   stress test QUIC connection handling and identify scaling bottlenecks.

   It maintains an array of active connections and continuously services them. */

#include "../../../../disco/topo/fd_topo.h"
#include "../../../../disco/stem/fd_stem.h"
#include "../../../../waltz/quic/fd_quic.h"
#include "../../../../disco/net/fd_net_tile.h"
#include "../../../../disco/metrics/fd_metrics.h"
#include "../../../../ballet/ed25519/fd_ed25519.h"
#include "../../../../flamenco/types/fd_types_custom.h"

#define QBLAST_MAX_CONNECTIONS 10000UL
#define QUIC_IDLE_TIMEOUT_NS       (2e9 )   /*  2 s */
#define QUIC_ACK_DELAY_NS          (25e6)  /* 25 ms */
#define CONN_ATTEMPT_INTERVAL_NS   (1e6L) /* 1 ms */
#define SEND_STREAM_INTERVAL_NS    (1e3L) /* 1 us */

static fd_quic_limits_t quic_limits = {
  .conn_cnt                    = QBLAST_MAX_CONNECTIONS,
  .handshake_cnt               = QBLAST_MAX_CONNECTIONS,
  .conn_id_cnt                 = FD_QUIC_MIN_CONN_ID_CNT,
  .inflight_frame_cnt          = 16UL * QBLAST_MAX_CONNECTIONS,
  .min_inflight_frame_cnt_conn = 4UL,
  .stream_id_cnt               = 256UL,
  .tx_buf_sz                   = FD_TXN_MTU,
  .stream_pool_cnt             = (1UL<<16),
};

struct fd_qblast_tile_ctx {
  void * out_base;
  ulong  chunk0;
  ulong  wmark;
  ulong  chunk;

  uint   dst_ip;
  ushort dst_port;
  uint   src_ip;
  ushort src_port;

  ulong conn_target;

# define ED25519_PRIV_KEY_SZ (32)
# define ED25519_PUB_KEY_SZ  (32)
  uchar            tls_priv_key[ ED25519_PRIV_KEY_SZ ];
  uchar            tls_pub_key [ ED25519_PUB_KEY_SZ  ];
  fd_pubkey_t identity_key[1];

  fd_quic_t * quic;
  fd_aio_t    quic_tx_aio[1];

  /* Array of QUIC connections */
  fd_quic_conn_t * connections[QBLAST_MAX_CONNECTIONS];
  ulong            connection_count;
  ulong            next_connect_attempt;

  uchar quic_buf[FD_NET_MTU];
  fd_net_rx_bounds_t net_in_bounds;

  fd_stem_context_t * stem;
  long                now;

  struct {
    ulong handshakes_completed;     /* qblast handshake completion tracking */
    ulong no_conn;                  /* qblast no connection tracking */
    ulong no_stream;                /* qblast no stream tracking */
    ulong stream_failed;            /* qblast stream failure tracking */
  } metrics;
};

typedef struct fd_qblast_tile_ctx fd_qblast_tile_ctx_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return fd_ulong_max( alignof(fd_qblast_tile_ctx_t), fd_quic_align() );
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile FD_PARAM_UNUSED ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_qblast_tile_ctx_t), sizeof(fd_qblast_tile_ctx_t) );
  l = FD_LAYOUT_APPEND( l, fd_quic_align(), fd_quic_footprint( &quic_limits ) );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

/* QUIC callbacks */

static ulong
quic_now( void * _ctx ) {
  fd_qblast_tile_ctx_t const * ctx = fd_type_pun_const( _ctx );
  return (ulong)ctx->now;
}

static inline void
metrics_write( fd_qblast_tile_ctx_t * ctx ) {
  /* qblast-specific metrics (not duplicated from QUIC) */
  FD_MCNT_SET( QBLAST, HANDSHAKES_COMPLETED,    ctx->metrics.handshakes_completed );
  FD_MCNT_SET( QBLAST, NO_CONN,                 ctx->metrics.no_conn );
  FD_MCNT_SET( QBLAST, NO_STREAM,               ctx->metrics.no_stream );
  FD_MCNT_SET( QBLAST, STREAM_FAILED,           ctx->metrics.stream_failed );

  /* Extract all QUIC internal metrics */
  FD_MCNT_SET(   QBLAST, QUIC_RECEIVED_PACKETS,     ctx->quic->metrics.net_rx_pkt_cnt );
  FD_MCNT_SET(   QBLAST, QUIC_RECEIVED_BYTES,       ctx->quic->metrics.net_rx_byte_cnt );
  FD_MCNT_SET(   QBLAST, QUIC_SENT_PACKETS,         ctx->quic->metrics.net_tx_pkt_cnt );
  FD_MCNT_SET(   QBLAST, QUIC_SENT_BYTES,           ctx->quic->metrics.net_tx_byte_cnt );
  FD_MCNT_SET(   QBLAST, QUIC_RETRY_SENT,           ctx->quic->metrics.retry_tx_cnt );

  FD_MGAUGE_SET( QBLAST, QUIC_CONNECTIONS_ACTIVE,   ctx->quic->metrics.conn_active_cnt );
  FD_MCNT_SET(   QBLAST, QUIC_CONNECTIONS_CREATED,  ctx->quic->metrics.conn_created_cnt );
  FD_MCNT_SET(   QBLAST, QUIC_CONNECTIONS_CLOSED,   ctx->quic->metrics.conn_closed_cnt );
  FD_MCNT_SET(   QBLAST, QUIC_CONNECTIONS_ABORTED,  ctx->quic->metrics.conn_aborted_cnt );
  FD_MCNT_SET(   QBLAST, QUIC_CONNECTIONS_TIMED_OUT,ctx->quic->metrics.conn_timeout_cnt );
  FD_MCNT_SET(   QBLAST, QUIC_CONNECTIONS_RETRIED,  ctx->quic->metrics.conn_retry_cnt );

  FD_MCNT_SET(   QBLAST, QUIC_CONNECTION_ERROR_NO_SLOTS,   ctx->quic->metrics.conn_err_no_slots_cnt );
  FD_MCNT_SET(   QBLAST, QUIC_CONNECTION_ERROR_RETRY_FAIL, ctx->quic->metrics.conn_err_retry_fail_cnt );

  FD_MCNT_ENUM_COPY( QBLAST, QUIC_PKT_CRYPTO_FAILED,   ctx->quic->metrics.pkt_decrypt_fail_cnt );
  FD_MCNT_ENUM_COPY( QBLAST, QUIC_PKT_NO_KEY,          ctx->quic->metrics.pkt_no_key_cnt );
  FD_MCNT_SET(       QBLAST, QUIC_PKT_NO_CONN,         ctx->quic->metrics.pkt_no_conn_cnt );
  FD_MCNT_ENUM_COPY( QBLAST, QUIC_FRAME_TX_ALLOC,      ctx->quic->metrics.frame_tx_alloc_cnt );
  FD_MCNT_SET(       QBLAST, QUIC_PKT_NET_HEADER_INVALID,  ctx->quic->metrics.pkt_net_hdr_err_cnt );
  FD_MCNT_SET(       QBLAST, QUIC_PKT_QUIC_HEADER_INVALID, ctx->quic->metrics.pkt_quic_hdr_err_cnt );
  FD_MCNT_SET(       QBLAST, QUIC_PKT_UNDERSZ,         ctx->quic->metrics.pkt_undersz_cnt );
  FD_MCNT_SET(       QBLAST, QUIC_PKT_OVERSZ,          ctx->quic->metrics.pkt_oversz_cnt );
  FD_MCNT_SET(       QBLAST, QUIC_PKT_VERNEG,          ctx->quic->metrics.pkt_verneg_cnt );
  FD_MCNT_SET(       QBLAST, QUIC_PKT_RETRANSMISSIONS, ctx->quic->metrics.pkt_retransmissions_cnt );

  FD_MCNT_SET(   QBLAST, QUIC_HANDSHAKES_CREATED,         ctx->quic->metrics.hs_created_cnt );
  FD_MCNT_SET(   QBLAST, QUIC_HANDSHAKE_ERROR_ALLOC_FAIL, ctx->quic->metrics.hs_err_alloc_fail_cnt );
  FD_MCNT_SET(   QBLAST, QUIC_HANDSHAKE_EVICTED,          ctx->quic->metrics.hs_evicted_cnt );

  FD_MCNT_SET(  QBLAST, QUIC_STREAM_RECEIVED_EVENTS, ctx->quic->metrics.stream_rx_event_cnt );
  FD_MCNT_SET(  QBLAST, QUIC_STREAM_RECEIVED_BYTES,  ctx->quic->metrics.stream_rx_byte_cnt );

  FD_MCNT_ENUM_COPY( QBLAST, QUIC_RECEIVED_FRAMES,  ctx->quic->metrics.frame_rx_cnt );
  FD_MCNT_SET      ( QBLAST, QUIC_FRAME_FAIL_PARSE, ctx->quic->metrics.frame_rx_err_cnt );

  FD_MCNT_ENUM_COPY( QBLAST, QUIC_ACK_TX, ctx->quic->metrics.ack_tx );

  FD_MHIST_COPY( QBLAST, QUIC_SERVICE_DURATION_SECONDS, ctx->quic->metrics.service_duration );
  FD_MHIST_COPY( QBLAST, QUIC_RECEIVE_DURATION_SECONDS, ctx->quic->metrics.receive_duration );
}

static void
quic_hs_complete( fd_quic_conn_t * conn,
                  void *           quic_ctx FD_PARAM_UNUSED ) {
  fd_qblast_tile_ctx_t * ctx = fd_type_pun( quic_ctx );
  ctx->metrics.handshakes_completed++;
  FD_LOG_NOTICE(( "QUIC handshake complete for connection %p", (void*)conn ));
}

static void
quic_tls_cv_sign( void *      signer_ctx,
                  uchar       signature[ static 64 ],
                  uchar const payload[ static 130 ] ) {
  fd_qblast_tile_ctx_t * ctx = signer_ctx;
  fd_ed25519_sign( signature, payload, 130UL, ctx->tls_pub_key, ctx->tls_priv_key, NULL );
}

/* quic_connect establishes a new QUIC connection for the given connection
   slot index. Returns the connection handle on success. */

static fd_quic_conn_t *
quic_connect( fd_qblast_tile_ctx_t * ctx,
              ulong                      idx ) {
  FD_TEST( !ctx->connections[idx] );
  fd_quic_conn_t * conn = fd_quic_connect( ctx->quic, ctx->dst_ip, ctx->dst_port, ctx->src_ip, ctx->src_port );
  FD_TEST( conn );
  FD_LOG_NOTICE(( "Initiated QUIC connection %lu/%lu to %u.%u.%u.%u:%u (dst_ip=0x%08x)",
    ctx->connection_count, ctx->conn_target,
    ctx->dst_ip&0xFF, (ctx->dst_ip>>8)&0xFF, (ctx->dst_ip>>16)&0xFF, (ctx->dst_ip>>24)&0xFF, ctx->dst_port, ctx->dst_ip ));
  fd_quic_conn_set_context( conn, (void*)idx );
  ctx->connection_count++;
  return ctx->connections[ idx ] = conn;
}

/* quic_conn_final is called when a QUIC connection is finalized/closed.
   It decrements the connection count and establishes a new connection
   to maintain the target connection count. */

static void
quic_conn_final( fd_quic_conn_t * conn,
                 void *           quic_ctx ) {
  fd_qblast_tile_ctx_t * ctx = quic_ctx;
  ctx->connection_count--;
  ulong conn_idx = (ulong)fd_quic_conn_get_context( conn );
  FD_LOG_NOTICE(( "QUIC connection %lu closed, %lu connections remaining, restarting", conn_idx, ctx->connection_count ));
  ctx->connections[ conn_idx ] = NULL;
  quic_connect( ctx, conn_idx );
}

/* quic_tx_aio_send handles outgoing QUIC packets by wrapping them in
   Ethernet headers and publishing them to the network output link.
   Returns FD_AIO_SUCCESS on success. */

static int
quic_tx_aio_send( void *                    _ctx,
                  fd_aio_pkt_info_t const * batch,
                  ulong                     batch_cnt,
                  ulong *                   opt_batch_idx,
                  int                       flush ) {
  (void)flush;
  fd_qblast_tile_ctx_t * ctx = _ctx;

  for( ulong i=0UL; i<batch_cnt; i++ ) {
    if( FD_UNLIKELY( batch[ i ].buf_sz<FD_NETMUX_SIG_MIN_HDR_SZ ) ) continue;

    uint const ip_dst = FD_LOAD( uint, batch[ i ].buf+offsetof( fd_ip4_hdr_t, daddr_c ) );
    uchar * packet_l2 = fd_chunk_to_laddr( ctx->out_base, ctx->chunk );
    uchar * packet_l3 = packet_l2 + sizeof(fd_eth_hdr_t);
    memset( packet_l2, 0, 12 );
    FD_STORE( ushort, packet_l2+offsetof( fd_eth_hdr_t, net_type ), fd_ushort_bswap( FD_ETH_HDR_TYPE_IP ) );
    fd_memcpy( packet_l3, batch[ i ].buf, batch[ i ].buf_sz );
    ulong sz_l2 = sizeof(fd_eth_hdr_t) + batch[ i ].buf_sz;

    ulong sig = fd_disco_netmux_sig( ip_dst, 0U, ip_dst, DST_PROTO_OUTGOING, FD_NETMUX_SIG_MIN_HDR_SZ );
    ulong tspub = (ulong)ctx->now;

    fd_stem_publish( ctx->stem, 0UL, sig, ctx->chunk, sz_l2, 0UL, 0, tspub );
    ctx->chunk = fd_dcache_compact_next( ctx->chunk, sz_l2, ctx->chunk0, ctx->wmark );
  }

  if( FD_LIKELY( opt_batch_idx ) ) {
    *opt_batch_idx = batch_cnt;
  }

  return FD_AIO_SUCCESS;
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  if( FD_UNLIKELY( !tile->out_cnt ) ) FD_LOG_ERR(( "qblast has no primary output link" ));

  /* Scratch mem setup */
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_qblast_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_qblast_tile_ctx_t), sizeof(fd_qblast_tile_ctx_t) );

  void * out_base   = topo->workspaces[ topo->objs[ topo->links[ tile->out_link_id[ 0 ] ].dcache_obj_id ].wksp_id ].wksp;
  void * out_dcache = topo->links[ tile->out_link_id[ 0 ] ].dcache;
  ctx->out_base = out_base;
  ctx->chunk0   = fd_dcache_compact_chunk0( out_base, out_dcache );
  ctx->wmark    = fd_dcache_compact_wmark( out_base, out_dcache, FD_NET_MTU );
  ctx->chunk    = ctx->chunk0;

  /* Set up network parameters */
  ctx->dst_ip   = tile->qblast.dst_ip;
  ctx->dst_port = tile->qblast.dst_port;
  ctx->src_ip   = tile->qblast.src_ip;
  ctx->src_port = tile->qblast.src_port;
  FD_TEST( ctx->src_ip);


  /* Initialize connection tracking */
  ctx->conn_target          = tile->qblast.conn_target;
  ctx->connection_count     = 0UL;
  ctx->next_connect_attempt = 0UL;
  for( ulong i=0UL; i<QBLAST_MAX_CONNECTIONS; i++ ) {
    ctx->connections[i] = NULL;
  }

  /* Initialize qblast-specific metrics */
  fd_memset( &ctx->metrics, 0, sizeof(ctx->metrics) );

  /* Set up input link for network RX */
  FD_TEST( tile->in_cnt==1UL );
  void * in_dcache = topo->links[ tile->in_link_id[ 0 ] ].dcache;
  fd_net_rx_bounds_init( &ctx->net_in_bounds, in_dcache );

  /* Generate a dummy identity key for QUIC TLS */
  fd_memset( ctx->identity_key, 0x42, sizeof(ctx->identity_key) );

  /* Set up AIO for network TX */
  fd_aio_t * quic_tx_aio = fd_aio_join( fd_aio_new( ctx->quic_tx_aio, ctx, quic_tx_aio_send ) );
  if( FD_UNLIKELY( !quic_tx_aio ) ) FD_LOG_ERR(( "fd_aio_join failed" ));

  /* Allocate QUIC instance using scratch allocator */
  fd_quic_t * quic = fd_quic_join( fd_quic_new( FD_SCRATCH_ALLOC_APPEND( l, fd_quic_align(), fd_quic_footprint( &quic_limits ) ), &quic_limits ) );
  if( FD_UNLIKELY( !quic ) ) FD_LOG_ERR(( "fd_quic_new failed" ));

  /* Set up QUIC configuration */
  quic->config.sign          = quic_tls_cv_sign;
  quic->config.sign_ctx      = ctx;
  quic->config.role          = FD_QUIC_ROLE_CLIENT;
  quic->config.idle_timeout  = QUIC_IDLE_TIMEOUT_NS;
  quic->config.ack_delay     = QUIC_ACK_DELAY_NS;
  quic->config.keep_alive    = 1;
  fd_memcpy( quic->config.identity_public_key, ctx->identity_key, sizeof(ctx->identity_key) );

  /* Set up QUIC callbacks */
  quic->cb.conn_hs_complete  = quic_hs_complete;
  quic->cb.conn_final        = quic_conn_final;
  quic->cb.now               = quic_now;
  quic->cb.now_ctx           = ctx;
  quic->cb.quic_ctx          = ctx;

  fd_quic_set_aio_net_tx( quic, quic_tx_aio );
  FD_TEST( fd_quic_init( quic ) );

  ctx->quic = quic;

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, scratch_align() );
  if( FD_UNLIKELY( scratch_top != (ulong)scratch + scratch_footprint( tile ) ) ) {
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));
  }
}

static void
before_credit( fd_qblast_tile_ctx_t * ctx,
               fd_stem_context_t *         stem,
               int *                       charge_busy ) {
  ctx->stem = stem;
  ctx->now = fd_tickcount();

  *charge_busy = fd_quic_service( ctx->quic );

  /* Try to establish new connections up to target */
  if( ctx->connection_count < ctx->conn_target ) {
    static long last_conn_time = 0;
    if( ctx->now - last_conn_time > CONN_ATTEMPT_INTERVAL_NS ) {
      quic_connect( ctx, ctx->connection_count );
      last_conn_time = ctx->now;
    }
  }

  static long last_sent = 0;
  if ( ctx->now-last_sent > SEND_STREAM_INTERVAL_NS ) {
    for( ulong i=0UL; i<ctx->connection_count; i++ ) {
      fd_quic_conn_t * conn = ctx->connections[ i ];
      if( !conn ) {
        ctx->metrics.no_conn++;
        continue;
      }
      fd_quic_stream_t * stream = fd_quic_conn_new_stream( conn );
      if( !stream ) {
        ctx->metrics.no_stream++;
        continue;
      }
      char const msg[] = "Hello, QUIC!";
      int result = fd_quic_stream_send( stream, msg, sizeof(msg), 1 );
      if( FD_UNLIKELY( result!=FD_QUIC_SUCCESS ) ) {
        ctx->metrics.stream_failed++;
      }
    }
    last_sent = ctx->now;
  }
}

static void
during_frag( fd_qblast_tile_ctx_t * ctx,
             ulong                       in_idx,
             ulong                       seq FD_PARAM_UNUSED,
             ulong                       sig FD_PARAM_UNUSED,
             ulong                       chunk,
             ulong                       sz,
             ulong                       ctl ) {

  /* Handle incoming network packets for QUIC */
  if( FD_UNLIKELY( in_idx != 0UL ) ) return; /* We only expect one input */

  void const * src = fd_net_rx_translate_frag( &ctx->net_in_bounds, chunk, ctl, sz );
  if( FD_LIKELY( sz >= sizeof(fd_eth_hdr_t) ) ) {
    uchar * ip_pkt = (uchar *)src + sizeof(fd_eth_hdr_t);
    ulong   ip_sz  = sz - sizeof(fd_eth_hdr_t);
    fd_quic_process_packet( ctx->quic, ip_pkt, ip_sz );
  }
}

#define STEM_BURST (1UL)

#define STEM_CALLBACK_CONTEXT_TYPE fd_qblast_tile_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_qblast_tile_ctx_t)

#define STEM_CALLBACK_METRICS_WRITE metrics_write
#define STEM_CALLBACK_BEFORE_CREDIT before_credit
#define STEM_CALLBACK_DURING_FRAG during_frag

#include "../../../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_qblast = {
  .name              = "qblast",
  .scratch_align     = scratch_align,
  .scratch_footprint = scratch_footprint,
  .unprivileged_init = unprivileged_init,
  .run               = stem_run
};
