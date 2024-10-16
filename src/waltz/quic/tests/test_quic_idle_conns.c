#include "../fd_quic.h"
#include "fd_quic_test_helpers.h"
#include "../../../ballet/base64/fd_base64.h"
#include "../../../util/net/fd_ip4.h"

#include <stdio.h>
#include <errno.h>
#include <string.h>


struct conn_meta {
  fd_quic_conn_t * conn;
  uint             conn_idx;
  uint             state;
};
typedef struct conn_meta conn_meta_t;

#define CONN_STATE_DEAD      0U
#define CONN_STATE_INIT      1U
#define CONN_STATE_ACTIVE    2U

#define MAX_CONNS 65536

conn_meta_t g_conn_meta[MAX_CONNS];

int g_dead   = MAX_CONNS;
int g_init   = 0;
int g_active = 0;

void
cb_conn_new( fd_quic_conn_t  * conn,
             void *            quic_ctx ) {
  (void)conn;
  (void)quic_ctx;
}

void
cb_conn_handshake_complete( fd_quic_conn_t * conn,
                            void *           quic_ctx ) {
  (void)conn;
  (void)quic_ctx;

  conn_meta_t * conn_meta = &g_conn_meta[conn->conn_idx];

  conn_meta->state = CONN_STATE_ACTIVE;

  g_init--;
  g_active++;
}

void
cb_conn_final( fd_quic_conn_t * conn,
               void *           quic_ctx ) {
  (void)conn;
  (void)quic_ctx;

  conn_meta_t * conn_meta = &g_conn_meta[conn->conn_idx];

  conn_meta->conn = NULL;

  switch( conn_meta->state ) {
    case CONN_STATE_DEAD:                         break;
    case CONN_STATE_INIT:   g_init--;   g_dead++; break;
    case CONN_STATE_ACTIVE: g_active--; g_dead++; break;
  }

  conn_meta->state = CONN_STATE_DEAD;
}

void
cb_stream_new( fd_quic_stream_t * stream,
               void *             quic_ctx ) {
  (void)stream;
  (void)quic_ctx;
}

void
cb_stream_notify( fd_quic_stream_t * stream,
                  void *             stream_ctx,
                  int                notify_type ) {
  (void)stream;
  (void)stream_ctx;
  (void)notify_type;
}

void
cb_stream_receive( fd_quic_stream_t * stream,
                   void *             stream_ctx,
                   uchar const *      data,
                   ulong              data_sz,
                   ulong              offset,
                   int                fin ) {
  (void)stream;
  (void)stream_ctx;
  (void)data;
  (void)data_sz;
  (void)offset;
  (void)fin;
}

ulong
cb_now( void * context ) {
  (void)context;
  return (ulong)fd_log_wallclock();
}


void
run_quic_client( fd_quic_t *         quic,
                 fd_quic_udpsock_t * udpsock,
                 uint                dst_ip,
                 ushort              dst_port ) {

  quic->cb.conn_new         = cb_conn_new;
  quic->cb.conn_hs_complete = cb_conn_handshake_complete;
  quic->cb.conn_final       = cb_conn_final;
  quic->cb.stream_new       = cb_stream_new;
  quic->cb.stream_notify    = cb_stream_notify;
  quic->cb.stream_receive   = cb_stream_receive;
  quic->cb.now              = cb_now;
  quic->cb.now_ctx          = NULL;

  fd_quic_set_aio_net_tx( quic, udpsock->aio );
  FD_TEST( fd_quic_init( quic ) );

  ulong out_time = (ulong)fd_log_wallclock() + (ulong)1e9;

  while( 1 ) {
    fd_quic_service( quic );
    fd_quic_udpsock_service( udpsock );

    if( g_dead > 0 ) {
      /* start a new connection */
      fd_quic_conn_t * conn = fd_quic_connect( quic, dst_ip, dst_port, NULL );

      if( conn ) {
        g_conn_meta[conn->conn_idx].conn     = conn;
        g_conn_meta[conn->conn_idx].conn_idx = (uint)conn->conn_idx;
        g_conn_meta[conn->conn_idx].state    = CONN_STATE_INIT;

        g_dead--;
        g_init++;
      }
    }

    /* TODO send pings */

    /* output stats */
    ulong now = (ulong)fd_log_wallclock();
    if( now > out_time ) {
      FD_LOG_NOTICE(( "connections: active: %lu  initializing: %lu", (ulong)g_active, (ulong)g_init ));
      out_time = now + (ulong)1e9;
    }
  }

  /* finalize quic */
  fd_quic_fini( quic );
}


int
main( int argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  char const * _src_ip = fd_env_strip_cmdline_cstr( &argc,
                                                    &argv,
                                                    "--src-ip",
                                                    NULL,
                                                    "127.0.0.1" );

  char const * _dst_ip = fd_env_strip_cmdline_cstr( &argc,
                                                    &argv,
                                                    "--dst-ip",
                                                    NULL,
                                                    "127.0.0.1" );

  ushort dst_port = fd_env_strip_cmdline_ushort( &argc,
                                                 &argv,
                                                 "--dst-port",
                                                 NULL,
                                                 9007 );

  /* number of connections to maintain */
  ulong num_conns = fd_env_strip_cmdline_ulong( &argc,
                                                &argv,
                                                "--num-conns",
                                                NULL,
                                                256 );

  ulong num_pages = fd_env_strip_cmdline_ulong( &argc,
                                                &argv,
                                                "--num-pages",
                                                NULL,
                                                1 << 15 );

  char const * _page_sz = fd_env_strip_cmdline_cstr( &argc,
                                                     &argv,
                                                     "--page-sz",
                                                     NULL,
                                                     "normal" );

  ulong cpu_idx = fd_tile_cpu_id( fd_tile_idx() );
  if( cpu_idx>=fd_shmem_cpu_cnt() ) cpu_idx = 0UL;
  ulong numa_idx = fd_env_strip_cmdline_ulong( &argc,
                                               &argv,
                                               "--numa-idx",
                                               NULL,
                                               fd_shmem_numa_idx(cpu_idx) );

  ulong page_sz = fd_cstr_to_shmem_page_sz( _page_sz );
  if( FD_UNLIKELY( !page_sz ) ) FD_LOG_ERR(( "unsupported --page-sz" ));

  if( num_conns > MAX_CONNS ) {
    FD_LOG_ERR(( "Argument --num-conns larger than maximum of %lu", (ulong)MAX_CONNS ));
  }

  fd_wksp_t * wksp = fd_wksp_new_anonymous( page_sz,
                                            num_pages,
                                            numa_idx,
                                            "wksp",
                                            0UL );
  FD_TEST( wksp );

  fd_quic_limits_t quic_limits = {
     .conn_cnt           = num_conns,
     .handshake_cnt      = num_conns,
     .conn_id_cnt        = 16UL,
     .rx_stream_cnt      = 2UL,
     .stream_pool_cnt    = num_conns * 2,
     .inflight_pkt_cnt   = 64UL,
     .tx_buf_sz          = 0
  };
  ulong quic_footprint = fd_quic_footprint( &quic_limits );
  FD_TEST( quic_footprint );

  void * mem = fd_wksp_alloc_laddr( wksp, fd_quic_align(), quic_footprint, 1UL );
  fd_quic_t * quic = fd_quic_new( mem, &quic_limits );
  FD_TEST( quic );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );
  fd_tls_test_sign_ctx_t * sign_ctx = fd_wksp_alloc_laddr( wksp, alignof(fd_tls_test_sign_ctx_t), sizeof(fd_tls_test_sign_ctx_t), 1UL );
  *sign_ctx = fd_tls_test_sign_ctx( rng );
  fd_quic_config_test_signer( quic, sign_ctx );

  fd_quic_udpsock_t _udpsock;
  uint listen_ip;
  if( FD_UNLIKELY( !fd_cstr_to_ip4_addr( _src_ip, &listen_ip ) ) ) {
    FD_LOG_NOTICE(( "invalid --src-ip" ));
    return 1;
  }
  fd_quic_udpsock_t * udpsock = fd_quic_client_create_udpsock( &_udpsock, wksp, fd_quic_get_aio_net_rx( quic ), listen_ip );
  FD_TEST( udpsock == &_udpsock );

  fd_quic_config_t * client_cfg = &quic->config;
  client_cfg->role = FD_QUIC_ROLE_CLIENT;
  FD_TEST( fd_quic_config_from_env( &argc, &argv, client_cfg ) );
  memcpy(client_cfg->link.dst_mac_addr, "\x52\xF1\x7E\xDA\x2C\xE0", 6UL);
  client_cfg->net.ip_addr         = udpsock->listen_ip;
  client_cfg->net.ephem_udp_port.lo = (ushort)udpsock->listen_port;
  client_cfg->net.ephem_udp_port.hi = (ushort)(udpsock->listen_port + 1);
  client_cfg->initial_rx_max_stream_data = 1<<15;
  client_cfg->idle_timeout = (ulong)10000e6;

  uint dst_ip = 0;
  if( FD_UNLIKELY( !fd_cstr_to_ip4_addr( _dst_ip, &dst_ip ) ) ) {
    FD_LOG_NOTICE(( "invalid --dst-ip" ));
    return 1;
  }
  run_quic_client( quic, udpsock, dst_ip, dst_port );

  fd_wksp_free_laddr( fd_quic_delete( fd_quic_leave( quic ) ) );
  fd_quic_udpsock_destroy( udpsock );
  fd_wksp_delete_anonymous( wksp );

  fd_halt();

  return 0;
}
