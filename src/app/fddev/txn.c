#include "fddev.h"

#include "../fdctl/configure/configure.h"
#include "../../ballet/base64/fd_base64.h"
#include "../../tango/quic/fd_quic.h"
#include "../../tango/quic/tests/fd_quic_test_helpers.h"

#include <linux/capability.h>

FD_IMPORT_BINARY(sample_transaction, "src/tango/quic/tests/quic_txn.bin");

static int g_conn_hs_complete = 0;
static int g_conn_final = 0;
static int g_stream_notify = 0;

#define MAX_TXN_COUNT 128

void
txn_cmd_perm( args_t *         args,
              security_t *     security,
              config_t * const config ) {
  (void)args;

  if( FD_UNLIKELY( config->development.netns.enabled ) )
    check_cap( security, "txn", CAP_SYS_ADMIN, "enter a network namespace by calling `setns(2)`" );
}

void
txn_cmd_args( int *    pargc,
              char *** pargv,
              args_t * args ) {
  args->txn.payload_base64 = fd_env_strip_cmdline_cstr( pargc, pargv, "--payload-base64-encoded", NULL, NULL );
  args->txn.count = fd_env_strip_cmdline_ulong( pargc, pargv, "--count", NULL, 1 );
  if( FD_UNLIKELY( !args->txn.count || args->txn.count > MAX_TXN_COUNT ) )
    FD_LOG_ERR(( "count must be between 1 and %d", MAX_TXN_COUNT ));

  args->txn.dst_ip = fd_env_strip_cmdline_cstr( pargc, pargv, "--dst-ip", NULL, 0 );
  args->txn.dst_port = fd_env_strip_cmdline_ushort( pargc, pargv, "--dst-port", NULL, 0 );
}

static ulong
cb_now( void * context ) {
  (void)context;
  return (ulong)fd_log_wallclock();
}

static void
cb_conn_hs_complete( fd_quic_conn_t * conn,
                     void *           quic_ctx ) {
  (void)conn;
  (void)quic_ctx;
  g_conn_hs_complete = 1;
}

static void
cb_conn_final( fd_quic_conn_t * conn,
               void *           quic_ctx ) {
  (void)conn;
  (void)quic_ctx;
  g_conn_final = 1;
}

static void
cb_stream_notify( fd_quic_stream_t * stream,
                  void *             stream_ctx,
                  int                notify_type ) {
  (void)stream;
  (void)stream_ctx;
  (void)notify_type;
  g_stream_notify = 1;
}

static void
send_quic_transactions( fd_quic_t *         quic,
                        fd_quic_udpsock_t * udpsock,
                        ulong               count,
                        uint                dst_ip,
                        ushort              dst_port,
                        fd_aio_pkt_info_t * pkt ) {
  fd_quic_set_aio_net_tx( quic, udpsock->aio );
  FD_TEST( fd_quic_init( quic ) );

  quic->cb.now = cb_now;
  quic->cb.conn_final = cb_conn_final;
  quic->cb.conn_hs_complete = cb_conn_hs_complete;
  quic->cb.stream_notify = cb_stream_notify;

  fd_quic_conn_t * conn = fd_quic_connect( quic, dst_ip, dst_port, NULL );
  while ( FD_LIKELY( !( g_conn_hs_complete || g_conn_final ) ) ) {
    fd_quic_service( quic );
    fd_quic_udpsock_service( udpsock );
  }
  FD_TEST( conn );
  if( FD_UNLIKELY( conn->state != FD_QUIC_CONN_STATE_ACTIVE ) )
    FD_LOG_ERR(( "unable to connect to QUIC endpoint at "FD_IP4_ADDR_FMT":%hu, is it running? state is %d", FD_IP4_ADDR_FMT_ARGS(dst_ip), dst_port, conn->state ));

  fd_quic_stream_t * stream = fd_quic_conn_new_stream( conn, FD_QUIC_TYPE_UNIDIR );
  FD_TEST( stream );

  ulong sent = 0;
  while( sent < count ) {
    int res = fd_quic_stream_send( stream, pkt + sent, count - sent, 1 );
    if( FD_UNLIKELY( res < 0 ) ) FD_LOG_ERR(( "fd_quic_stream_send failed (%d)", res ));
    sent += (ulong)res;

    fd_quic_service( quic );
    fd_quic_udpsock_service( udpsock );
  }

  while ( FD_UNLIKELY( !( g_stream_notify || g_conn_final ) ) ) {
    fd_quic_service( quic );
    fd_quic_udpsock_service( udpsock );
  }

  fd_quic_conn_close( conn, 0 );
  fd_quic_fini( quic );
}

void
txn_cmd_fn( args_t *         args,
            config_t * const config ) {
  if( FD_UNLIKELY( config->development.netns.enabled ) )
    enter_network_namespace( config->development.netns.interface1 );

  /* wait until validator is ready to receive txns before sending */
  ready_cmd_fn( args, config );

  fd_quic_limits_t quic_limits = {
    .conn_cnt         = 1UL,
    .handshake_cnt    = 1UL,
    .conn_id_cnt      = 4UL,
    .conn_id_sparsity = 4.0,
    .stream_cnt = { 0UL,   // FD_QUIC_STREAM_TYPE_BIDI_CLIENT
                    0UL,   // FD_QUIC_STREAM_TYPE_BIDI_SERVER
                    1UL,   // FD_QUIC_STREAM_TYPE_UNI_CLIENT
                    0UL }, // FD_QUIC_STREAM_TYPE_UNI_SERVER
    .stream_sparsity  = 4.0,
    .inflight_pkt_cnt = 64UL,
    .tx_buf_sz        = 1UL<<15UL
  };
  ulong quic_footprint = fd_quic_footprint( &quic_limits );
  FD_TEST( quic_footprint );

  fd_wksp_t * wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz("normal"),
                                            1UL << 10,
                                            fd_shmem_cpu_idx( 0 ),
                                            "wksp",
                                            0UL );
  FD_TEST( wksp );
  void * mem = fd_wksp_alloc_laddr( wksp, fd_quic_align(), quic_footprint, 1UL );
  fd_quic_t * quic = fd_quic_new( mem, &quic_limits );
  FD_TEST( quic );

  fd_quic_udpsock_t _udpsock;
  fd_quic_udpsock_t * udpsock = fd_quic_client_create_udpsock( &_udpsock, wksp, fd_quic_get_aio_net_rx( quic ), 0 );
  FD_TEST( udpsock == &_udpsock );

  fd_quic_config_t * client_cfg = &quic->config;
  client_cfg->role = FD_QUIC_ROLE_CLIENT;
  memcpy( client_cfg->alpns, "\xasolana-tpu", 11UL );
  client_cfg->alpns_sz = 11U;
  memcpy( client_cfg->link.dst_mac_addr, config->net.mac_addr, 6UL );
  client_cfg->net.ip_addr           = udpsock->listen_ip;
  client_cfg->net.ephem_udp_port.lo = (ushort)udpsock->listen_port;
  client_cfg->net.ephem_udp_port.hi = (ushort)(udpsock->listen_port + 1);
  client_cfg->initial_rx_max_stream_data = 1<<15;
  client_cfg->idle_timeout = 100UL * 1000UL * 1000UL; /* 100 millis */
  client_cfg->initial_rx_max_stream_data = FD_QUIC_DEFAULT_INITIAL_RX_MAX_STREAM_DATA;

  fd_aio_pkt_info_t pkt[ MAX_TXN_COUNT ];

  if( FD_LIKELY( !args->txn.payload_base64 ) ) {
    for( ulong i=0; i<args->txn.count; i++ ) {
      pkt[ i ].buf    = (void * )sample_transaction;
      pkt[ i ].buf_sz = (ushort )sample_transaction_sz;
    }
  } else {
    uchar buf[1300];
    int buf_sz = fd_base64_decode( args->txn.payload_base64, buf );
    if( FD_UNLIKELY( buf_sz == -1 ) ) FD_LOG_ERR(( "bad payload input `%s`", args->txn.payload_base64 ));
    for( ulong i=0; i<args->txn.count; i++ ) {
      pkt[ i ].buf    = (void * )buf;
      pkt[ i ].buf_sz = (ushort )buf_sz;
    }
  }

  uint dst_ip = config->net.ip_addr;
  if( FD_UNLIKELY( args->txn.dst_ip ) )
    if( FD_UNLIKELY( !fd_cstr_to_ip4_addr( args->txn.dst_ip, &dst_ip  ) ) ) FD_LOG_ERR(( "invalid --dst-ip" ));

  ushort dst_port = config->tiles.serve.quic.transaction_listen_port;
  if( FD_UNLIKELY( args->txn.dst_port ) ) dst_port = args->txn.dst_port;

  FD_LOG_NOTICE(( "sending %lu transactions to "FD_IP4_ADDR_FMT":%hu", args->txn.count, FD_IP4_ADDR_FMT_ARGS(dst_ip), dst_port ));

  send_quic_transactions( quic, udpsock, args->txn.count, dst_ip, dst_port, pkt );
  exit_group( 0 );
}
