#if !FD_HAS_HOSTED
#error "retransmit tile requires FD_HAS_HOSTED"
#endif

#include "../../tango/xdp/fd_xdp.h"
#include "../../tango/fd_tango.h"
#include "../../util/fd_util.h"
#include "../../util/net/fd_eth.h"
#include "../../util/net/fd_ip4.h"
#include "../../util/net/fd_udp.h"
#include "../../ballet/shred/fd_shred.h"
#include "../../ballet/shred/fd_fec_set.h"

/* FD_IMPORT_BINARY( test_private_key, "src/ballet/shred/fixtures/demo-shreds.key"  ); */

struct __attribute__((packed)) fd_shred_pkt {
  fd_eth_hdr_t eth[1];
  fd_ip4_hdr_t ip4[1];
  fd_udp_hdr_t udp[1];

  uchar payload[FD_SHRED_MAX_SZ];
};
typedef struct fd_shred_pkt fd_shred_pkt_t;


// footprint of fd_fec_resolver
// backing storage for packets. depth*(67+67)*(sizeof(fd_shred_pkt_t))


static inline int
send_loop_helper( fd_aio_t const * tx_aio,
                  fd_aio_pkt_info_t const * data,
                  ulong cnt ) {
  ulong total_sent = 0UL;
  while( total_sent<cnt ) {
    ulong okay_cnt = 0UL;
    int send_rc = fd_aio_send( tx_aio, data+total_sent, cnt-total_sent, &okay_cnt );
    if( FD_LIKELY( send_rc>=0 ) ) return send_rc;
    if( FD_UNLIKELY( send_rc!=FD_AIO_ERR_AGAIN ) ) return send_rc;
    total_sent += okay_cnt;
  }
  return 0;

}

struct fd_net_endpoint {
  uchar  mac[6];
  /* Both of these are stored in network byte order */
  ushort port;
  uint   ip4;
};
typedef struct fd_net_endpoint fd_net_endpoint_t;

static inline fd_net_endpoint_t *
fd_net_endpoint_load( uchar const * pod, fd_net_endpoint_t * out ) {
  char const * _mac  = fd_pod_query_cstr(   pod, "mac",       NULL );
  char const * _ip   = fd_pod_query_cstr(   pod, "ip",        NULL );
  ushort        _port = fd_pod_query_ushort( pod, "port", (ushort)0 );

  if( FD_UNLIKELY( !_mac  ) ) { FD_LOG_WARNING(( "mac not found"  )); return NULL; }
  if( FD_UNLIKELY( !_ip   ) ) { FD_LOG_WARNING(( "ip not found"   )); return NULL; }
  if( FD_UNLIKELY( !_port ) ) { FD_LOG_WARNING(( "port not found" )); return NULL; }

  if( FD_UNLIKELY( !fd_cstr_to_mac_addr( _mac, out->mac ) ) ) {
    FD_LOG_WARNING(( "Parsing %s as mac failed", _mac ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_cstr_to_ip4_addr( _ip, &out->ip4 ) ) ) {
    FD_LOG_WARNING(( "Parsing %s as ip4 failed", _ip ));
    return NULL;
  }

  out->ip4  = fd_uint_bswap(   out->ip4 );
  out->port = fd_ushort_bswap( _port    );
  return out;
}

struct forwarding_ctx {
  fd_aio_t const * tx_aio;
  fd_net_endpoint_t src;
  fd_net_endpoint_t dst;

  fd_aio_pkt_info_t * * data_batches;
  fd_aio_pkt_info_t * * parity_batches;
  fd_fec_resolver_t * resolver;

  fd_fec_set_t * set;
};
typedef struct forwarding_ctx forwarding_ctx_t;



void
handle_rx_shred( void *                    _ctx,
                 fd_shred_t const * shred,
                 ulong              shred_sz ) {
  forwarding_ctx_t * ctx = (forwarding_ctx_t *)_ctx;

  fd_fec_set_t * to_send = fd_fec_resolver_add_shred( ctx->resolver, shred, shred_sz );
  if( FD_UNLIKELY( to_send ) ) {
    long idx = to_send - ctx->set;
    /* TODO: Do I want to bother changing the identification field? */
    int send_rc = send_loop_helper( ctx->tx_aio, ctx->data_batches[ idx ], to_send->data_shred_cnt );
    if( FD_UNLIKELY( send_rc<0 ) )  FD_LOG_WARNING(( "AIO send err for data shreds. Error: %s", fd_aio_strerror( send_rc ) ));
    send_rc = send_loop_helper( ctx->tx_aio, ctx->parity_batches[ idx ], to_send->parity_shred_cnt );
    if( FD_UNLIKELY( send_rc<0 ) )  FD_LOG_WARNING(( "AIO send err for data shreds. Error: %s", fd_aio_strerror( send_rc ) ));
  }

  /*
    fd_memcpy( pkt->eth->dst, ctx->dst.mac, 6UL );
    fd_memcpy( pkt->eth->src, ctx->src.mac , 6UL );
    pkt->ip4->saddr     = ctx->src.ip4;
    pkt->ip4->daddr     = ctx->dst.ip4;
    pkt->ip4->check  = 0U;
    pkt->ip4->check  = fd_ip4_hdr_check( pkt->ip4 );
    pkt->udp->net_sport = ctx->src.port;
    pkt->udp->net_dport = ctx->dst.port;
    */
}

int
handle_rx( void *                    ctx,
           fd_aio_pkt_info_t const * batch,
           ulong                     batch_cnt,
           ulong *                   opt_batch_idx ) {
  (void)opt_batch_idx;
  for( ulong i=0UL; i<batch_cnt; i++ ) {
    fd_shred_t const * shred = fd_shred_parse( batch[i].buf, batch[i].buf_sz );
    if( FD_LIKELY( shred ) ) handle_rx_shred( ctx, shred, batch[i].buf_sz );
    else {  /* Increment a counter */ }
  }
  return FD_AIO_SUCCESS;
}

int
fd_frank_retransmit_task( int     argc,
                          char ** argv ) {
  (void)argc;
  fd_log_thread_set( argv[0] );
  char const * retransmit_name = argv[0];
  FD_LOG_INFO(( "retransmit.%s init", retransmit_name ));

  /* Parse "command line" arguments */

  char const * pod_gaddr = argv[1];
  char const * cfg_path  = argv[2];

  /* Load up the configuration for this frank instance */

  FD_LOG_INFO(( "using configuration in pod %s at path %s", pod_gaddr, cfg_path ));
  uchar const * pod     = fd_wksp_pod_attach( pod_gaddr );
  uchar const * cfg_pod = fd_pod_query_subpod( pod, cfg_path );
  if( FD_UNLIKELY( !cfg_pod ) ) FD_LOG_ERR(( "path not found" ));

  uchar const * retransmit_pods = fd_pod_query_subpod( cfg_pod, "retransmit" );
  if( FD_UNLIKELY( !retransmit_pods ) ) FD_LOG_ERR(( "%s.retransmit path not found", cfg_path ));

  uchar const * retransmit_pod = fd_pod_query_subpod( retransmit_pods, retransmit_name );
  if( FD_UNLIKELY( !retransmit_pod ) ) FD_LOG_ERR(( "%s.retransmit.%s path not found", cfg_path, retransmit_name ));

  FD_LOG_INFO(( "joining %s.retransmit.%s.cnc", cfg_path, retransmit_name ));
  fd_cnc_t * cnc = fd_cnc_join( fd_wksp_pod_map( retransmit_pod, "cnc" ) );
  if( FD_UNLIKELY( !cnc ) ) FD_LOG_ERR(( "fd_cnc_join failed" ));
  if( FD_UNLIKELY( fd_cnc_signal_query( cnc )!=FD_CNC_SIGNAL_BOOT ) ) FD_LOG_ERR(( "cnc not in boot state" ));

  FD_LOG_INFO(( "loading %s.retransmit.%s.xsk", cfg_path, retransmit_name ));
  fd_xsk_t * xsk = fd_xsk_join( fd_wksp_pod_map( retransmit_pod, "xsk") );
  if( FD_UNLIKELY( !xsk ) ) FD_LOG_ERR(( "fd_xsk_join failed" ));

  FD_LOG_INFO(( "loading %s.retransmit.%s.xsk_aio", cfg_path, retransmit_name ));
  fd_xsk_aio_t * xsk_aio = fd_xsk_aio_join( fd_wksp_pod_map( retransmit_pod, "xsk_aio" ), xsk );
  if( FD_UNLIKELY( !xsk_aio ) ) FD_LOG_ERR(( "fd_xsk_aio_join failed" ));

  forwarding_ctx_t ctx[1];

  uchar const * src_endpt_pod = fd_pod_query_subpod( retransmit_pod, "src_net_endpoint" );
  if( FD_UNLIKELY( !src_endpt_pod ) ) FD_LOG_ERR(( "%s.retransmit.%s.src_net_endpoint path not found", cfg_path, retransmit_name ));

  if( FD_UNLIKELY( !fd_net_endpoint_load( src_endpt_pod, &(ctx->src) ) ) )
    FD_LOG_ERR(( "parsing network endpoint from %s.retransmit.%s.src_net_endpoint failed", cfg_path, retransmit_name ));

  uchar const * dst_endpt_pod = fd_pod_query_subpod( retransmit_pod, "dst_net_endpoint" );
  if( FD_UNLIKELY( !dst_endpt_pod ) ) FD_LOG_ERR(( "%s.retransmit.%s.dst_net_endpoint path not found", cfg_path, retransmit_name ));

  if( FD_UNLIKELY( !fd_net_endpoint_load( dst_endpt_pod, &(ctx->src) ) ) )
    FD_LOG_ERR(( "parsing network endpoint from %s.retransmit.%s.dst_net_endpoint failed", cfg_path, retransmit_name ));

  long  lazy      = fd_pod_query_long ( retransmit_pod, "lazy",      0L  );
  if( lazy<=0L ) lazy = fd_tempo_lazy_default( 1024UL );
  FD_LOG_INFO(( "using lazy %li ns", lazy ));
  ulong async_min = fd_tempo_async_min( lazy, 1UL /*event_cnt*/, (float)fd_tempo_tick_per_ns( NULL ) );
  if( FD_UNLIKELY( !async_min ) ) FD_LOG_ERR(( "bad lazy" ));

  uint seed = fd_pod_query_uint( retransmit_pod, "seed", (uint)fd_tile_id() ); /* use app tile_id as default */
  FD_LOG_INFO(( "creating rng (%s.retransmit.%s.seed %u)", cfg_path, retransmit_name, seed ));
  fd_rng_t _rng[ 1 ];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, seed, 0UL ) );
  if( FD_UNLIKELY( !rng ) ) FD_LOG_ERR(( "fd_rng_join failed" ));


  fd_aio_t _aio[1];
  fd_aio_t * aio = fd_aio_join( fd_aio_new( _aio, ctx, handle_rx ) );
  if( FD_UNLIKELY( !aio ) ) FD_LOG_ERR(( "join aio failed" ));

  fd_xsk_aio_set_rx( xsk_aio, aio );

  fd_aio_t const * tx_aio = fd_xsk_aio_get_tx( xsk_aio );
  ctx->tx_aio = tx_aio;

  FD_LOG_NOTICE(( "Listening on interface %s queue %d", fd_xsk_ifname( xsk ), fd_xsk_ifqueue( xsk ) ));



  long now  = fd_tickcount();
  long then = now;


  fd_cnc_signal( cnc, FD_CNC_SIGNAL_RUN );
  for(;;) {

    /* Do housekeep at a low rate in the background */

    if( FD_UNLIKELY( (now-then)>=0L ) ) {

      /* Send diagnostic info */
      fd_cnc_heartbeat( cnc, now );

      /* Receive command-and-control signals */
      ulong s = fd_cnc_signal_query( cnc );
      if( FD_UNLIKELY( s!=FD_CNC_SIGNAL_RUN ) ) {
        if( FD_LIKELY( s==FD_CNC_SIGNAL_HALT ) ) break;
        char buf[ FD_CNC_SIGNAL_CSTR_BUF_MAX ];
        FD_LOG_WARNING(( "Unexpected signal %s (%lu) received; trying to resume", fd_cnc_signal_cstr( s, buf ), s ));
        fd_cnc_signal( cnc, FD_CNC_SIGNAL_RUN );
      }

      /* Reload housekeeping timer */
      then = now + (long)fd_tempo_async_reload( rng, async_min );
    }

    now = fd_tickcount();

    fd_xsk_aio_service( xsk_aio );

  }

  FD_LOG_NOTICE(( "Cleaning up" ));

  fd_cnc_signal( cnc, FD_CNC_SIGNAL_BOOT );

  fd_aio_delete    ( fd_aio_leave( aio ) );
  fd_rng_delete    ( fd_rng_leave   ( rng    ) );
  fd_wksp_pod_unmap( fd_xsk_aio_leave( xsk_aio ) );
  fd_wksp_pod_unmap( fd_xsk_leave( xsk ) );
  fd_wksp_pod_unmap( fd_cnc_leave( cnc ) );
  fd_wksp_pod_detach( pod );

  return 0;
}
