#include "../../shared/fd_config.h"
#include "../../shared/fd_action.h"

#include "../../platform/fd_sys_util.h"
#include "../../platform/fd_net_util.h"
#include "../../shared/commands/ready.h"
#include "../../../ballet/base64/fd_base64.h"
#include "../../../waltz/quic/fd_quic.h"
#include "../../../waltz/quic/tests/fd_quic_test_helpers.h"
#include "../../../waltz/tls/test_tls_helper.h"
#include "../../../util/net/fd_ip4.h"

#include <errno.h>
#include <sys/random.h>
#include <linux/capability.h>

FD_IMPORT_BINARY(sample_transaction, "src/waltz/quic/tests/quic_txn.bin");

static int g_conn_hs_complete = 0;
static int g_conn_final = 0;

#define MAX_TXN_COUNT 128

/* Packet numbers of the stream packets awaiting an ack */
static ulong g_pkt_num[ MAX_TXN_COUNT ];
static ulong g_pkt_cnt   = 0UL;
static ulong g_pkt_acked = 0UL;

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
cb_ack_range( fd_quic_conn_t * conn,
              ulong            pkt_num_lo,
              ulong            pkt_num_hi,
              void *           quic_ctx ) {
  (void)conn;
  (void)quic_ctx;
  for( ulong i=0UL; i<g_pkt_cnt; i++ ) {
    if( g_pkt_num[ i ]<pkt_num_lo || g_pkt_num[ i ]>pkt_num_hi ) continue;
    g_pkt_num[ i ] = ULONG_MAX;
    g_pkt_acked++;
  }
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

  quic->cb.conn_final       = cb_conn_final;
  quic->cb.conn_hs_complete = cb_conn_hs_complete;
  quic->cb.ack_range        = cb_ack_range;

  fd_quic_conn_t * conn = fd_quic_connect( quic, dst_ip, dst_port, 0U, (ushort)udpsock->listen_port, fd_log_wallclock() );
  while( FD_LIKELY( !( g_conn_hs_complete || g_conn_final ) ) ) {
    fd_quic_service( quic, fd_log_wallclock() );
    fd_quic_udpsock_service( udpsock );
  }
  FD_TEST( conn );
  if( FD_UNLIKELY( conn->state != FD_QUIC_CONN_STATE_ACTIVE ) )
    FD_LOG_ERR(( "unable to connect to QUIC endpoint at "FD_IP4_ADDR_FMT":%hu, is it running? state is %u", FD_IP4_ADDR_FMT_ARGS(dst_ip), dst_port, conn->state ));

  /* One stream per transaction */
  for( ulong sent=0UL; sent<count && !g_conn_final; sent++ ) {
    fd_aio_pkt_info_t * chunk     = pkt + sent;
    ulong               stream_id = FD_QUIC_STREAM_TYPE_UNI_CLIENT + 4UL*sent;

    /* wait for the peer to grant the stream (MAX_STREAMS) */
    while( !g_conn_final && stream_id>=conn->tx_sup_stream_id ) {
      fd_quic_service( quic, fd_log_wallclock() );
      fd_quic_udpsock_service( udpsock );
    }
    if( FD_UNLIKELY( g_conn_final ) ) break;

    if( FD_UNLIKELY( !fd_quic_test_stream_send( conn, stream_id, chunk->buf, chunk->buf_sz, &g_pkt_num[ g_pkt_cnt ] ) ) )
      FD_LOG_ERR(( "failed to send transaction (%u bytes)", (uint)chunk->buf_sz ));
    g_pkt_cnt++;

    fd_quic_service( quic, fd_log_wallclock() );
    fd_quic_udpsock_service( udpsock );
  }

  /* An unacked packet ends this wait at the conn's idle timeout */
  while( FD_LIKELY( g_pkt_acked!=g_pkt_cnt && !g_conn_final ) ) {
    fd_quic_service( quic, fd_log_wallclock() );
    fd_quic_udpsock_service( udpsock );
  }
  if( FD_UNLIKELY( g_pkt_acked!=g_pkt_cnt ) ) FD_LOG_WARNING(( "%lu of %lu packets were not acknowledged", g_pkt_cnt-g_pkt_acked, g_pkt_cnt ));

  /* close and wait for connection to complete */
  if( !g_conn_final ) {
    fd_quic_conn_close( conn, 0 );
    while( !g_conn_final ) {
      fd_quic_service( quic, fd_log_wallclock() );
      fd_quic_udpsock_service( udpsock );
    }
  }

  fd_quic_fini( quic );
}

void
txn_cmd_fn( args_t *   args,
            config_t * config ) {
  /* wait until validator is ready to receive txns before sending */
  args_t ready_args = {0};
  ready_cmd_fn( &ready_args, config );

  fd_quic_limits_t quic_limits = {
    .conn_cnt           =  1UL,
    .handshake_cnt      =  1UL,
    .conn_id_cnt        =  4UL,
    .inflight_frame_cnt =  2UL*MAX_TXN_COUNT,
  };
  ulong quic_footprint = fd_quic_footprint( &quic_limits );
  FD_TEST( quic_footprint );

  fd_wksp_t * wksp = fd_wksp_new_anonymous( FD_SHMEM_NORMAL_PAGE_SZ,
                                            1UL << 10,
                                            fd_shmem_cpu_idx( 0 ),
                                            "wksp",
                                            0UL );
  FD_TEST( wksp );
  void * mem = fd_wksp_alloc_laddr( wksp, fd_quic_align(), quic_footprint, 1UL );
  fd_quic_t * quic = fd_quic_join( fd_quic_new( mem, &quic_limits ) );
  FD_TEST( quic );

  /* Signer */
  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );
  fd_tls_test_sign_ctx_t * sign_ctx = fd_wksp_alloc_laddr( wksp, alignof(fd_tls_test_sign_ctx_t), sizeof(fd_tls_test_sign_ctx_t), 1UL );
  fd_tls_test_sign_ctx( sign_ctx, rng );

  fd_memcpy( quic->config.identity_public_key, sign_ctx->public_key, 32UL );
  quic->config.sign_ctx = sign_ctx;
  quic->config.sign     = fd_tls_test_sign_sign;

  fd_quic_udpsock_t _udpsock;
  fd_quic_udpsock_t * udpsock = fd_quic_client_create_udpsock( &_udpsock, wksp, fd_quic_get_aio_net_rx( quic ), 0 );
  FD_TEST( udpsock == &_udpsock );

  fd_quic_config_t * client_cfg = &quic->config;
  client_cfg->role = FD_QUIC_ROLE_CLIENT;
  client_cfg->idle_timeout = 200UL * 1000UL * 1000UL; /* 5000 millis */
  client_cfg->initial_rx_max_stream_data = 0; /* doesn't receive */

  fd_aio_pkt_info_t pkt[ MAX_TXN_COUNT ];

  if( FD_LIKELY( !args->txn.payload_base64 ) ) {
    FD_LOG_INFO(( "Transaction payload not specified, using hardcoded sample payload" ));
    for( ulong i=0; i<args->txn.count; i++ ) {
      pkt[ i ].buf    = (void * )sample_transaction;
      pkt[ i ].buf_sz = (ushort )sample_transaction_sz;
    }
  } else {
    ulong payload_b64_sz = strlen( args->txn.payload_base64 );

    static uchar buf[ 1UL << 15UL ];
    if( FD_UNLIKELY( FD_BASE64_DEC_SZ( payload_b64_sz ) > sizeof(buf) ) )
      FD_LOG_ERR(( "Input payload is too large (max %lu bytes)", sizeof(buf) ));

    long buf_sz = fd_base64_decode( buf, args->txn.payload_base64, payload_b64_sz );
    if( FD_UNLIKELY( buf_sz<0L ) ) FD_LOG_ERR(( "bad payload input `%s`", args->txn.payload_base64 ));
    if( FD_UNLIKELY( (ulong)buf_sz>FD_QUIC_STREAM_TX_MAX ) )
      FD_LOG_ERR(( "Transaction is too large to send in one QUIC packet (%ld bytes, max %lu)", buf_sz, FD_QUIC_STREAM_TX_MAX ));

    for( ulong i=0; i<args->txn.count; i++ ) {
      pkt[ i ].buf    = (void * )buf;
      pkt[ i ].buf_sz = (ushort )buf_sz;
    }
  }

  uint dst_ip = config->net.ip_addr;
  if( FD_UNLIKELY( args->txn.dst_ip ) )
    if( FD_UNLIKELY( !fd_cstr_to_ip4_addr( args->txn.dst_ip, &dst_ip  ) ) ) FD_LOG_ERR(( "invalid --dst-ip" ));

  ushort dst_port = config->tiles.quic.quic_transaction_listen_port;
  if( FD_UNLIKELY( args->txn.dst_port ) ) dst_port = args->txn.dst_port;

  FD_LOG_NOTICE(( "sending %lu transactions to "FD_IP4_ADDR_FMT":%hu", args->txn.count, FD_IP4_ADDR_FMT_ARGS(dst_ip), dst_port ));

  send_quic_transactions( quic, udpsock, args->txn.count, dst_ip, dst_port, pkt );
  fd_sys_util_exit_group( 0 );
}

action_t fd_action_txn = {
  .name = "txn",
  .args = txn_cmd_args,
  .fn   = txn_cmd_fn,
  .description = "Send a transaction to a running development validator (see the `dev` command)",
  .usage = "txn [OPTIONS]"
};
