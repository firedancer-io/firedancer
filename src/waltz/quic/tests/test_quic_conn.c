#include "../fd_quic.h"
#include "fd_quic_test_helpers.h"

/* test_quic_conn repeatedly opens and closes QUIC connections. */

#include <stdlib.h>

int state           = 0;
int server_complete = 0;
int client_complete = 0;

/* server connection received in callback */
fd_quic_conn_t * server_conn = NULL;
fd_quic_conn_t * client_conn = NULL;

extern uchar pkt_full[];
extern ulong pkt_full_sz;

static ulong _recv = 0;
void
my_stream_receive_cb(
    void *             cb_ctx,
    fd_quic_conn_t *   conn,
    ulong              stream_id,
    uchar const *      data,
    ulong              data_sz,
    ulong              offset,
    int                fin
) {
  (void)cb_ctx; (void)conn; (void)stream_id; (void)fin;

  ulong expected_data_sz = 512ul;

  FD_LOG_INFO(( "received data from peer. size: %lu offset: %lu",
                data_sz, offset ));
  //FD_LOG_HEXDUMP_DEBUG(( "received data", data, data_sz ));

  if( FD_UNLIKELY( data_sz!=512UL ) ) {
    FD_LOG_ERR(( "data wrong size. Is: %lu, expected: %lu",
                 data_sz, expected_data_sz ));
    return;
  }

  if( FD_UNLIKELY( 0!=memcmp( data, "Hello world", 11u ) ) ) {
    FD_LOG_HEXDUMP_WARNING(( "incorrect data", data, 11UL ));
    FD_LOG_ERR(( "value received incorrect" ));
    return;
  }

  FD_LOG_DEBUG(( "recv ok" ));

  _recv++;
}


struct my_context {
  int server;
};
typedef struct my_context my_context_t;

void
my_cb_conn_final( fd_quic_conn_t * conn,
                  void *           context ) {
  (void)context;

  fd_quic_conn_t ** ppconn = conn->context;
  if( ppconn ) {
    FD_LOG_INFO(( "my_cb_conn_final %p SUCCESS", (void*)*ppconn ));
    *ppconn = NULL;
  } else {
    FD_LOG_WARNING(( "my_cb_conn_final FAIL" ));
  }
}

void
my_connection_new( fd_quic_conn_t * conn,
                   void *           vp_context ) {
  (void)vp_context;

  FD_LOG_INFO(( "server handshake complete" ));

  server_complete = 1;
  server_conn = conn;

  conn->context = &server_conn;
}

void
my_handshake_complete( fd_quic_conn_t * conn,
                       void *           vp_context ) {
  (void)vp_context;

  FD_LOG_INFO(( "client handshake complete" ));

  client_complete = 1;

  conn->context = &client_conn;
}

/* global "clock" */
ulong now = (ulong)1e18;

ulong test_clock( void * ctx ) {
  (void)ctx;
  return now;
}

int
main( int argc, char ** argv ) {

  fd_boot          ( &argc, &argv );
  fd_quic_test_boot( &argc, &argv );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  ulong cpu_idx = fd_tile_cpu_id( fd_tile_idx() );
  if( cpu_idx>fd_shmem_cpu_cnt() ) cpu_idx = 0UL;

  char const * _page_sz  = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",   NULL, "gigantic"                   );
  ulong        page_cnt  = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt",  NULL, 2UL                          );
  ulong        numa_idx  = fd_env_strip_cmdline_ulong( &argc, &argv, "--numa-idx",  NULL, fd_shmem_numa_idx( cpu_idx ) );

  ulong page_sz = fd_cstr_to_shmem_page_sz( _page_sz );
  if( FD_UNLIKELY( !page_sz ) ) FD_LOG_ERR(( "unsupported --page-sz" ));

  FD_LOG_NOTICE(( "Creating workspace (--page-cnt %lu, --page-sz %s, --numa-idx %lu)", page_cnt, _page_sz, numa_idx ));
  fd_wksp_t * wksp = fd_wksp_new_anonymous( page_sz, page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  fd_quic_limits_t const quic_limits = {
    .conn_cnt         =   10,
    .conn_id_cnt      =   10,
    .handshake_cnt    =   10,
    .tx_stream_cnt    =  400,
    .inflight_pkt_cnt = 1024,
  };

  ulong quic_footprint = fd_quic_footprint( &quic_limits );
  FD_TEST( quic_footprint );
  FD_LOG_NOTICE(( "QUIC footprint: %lu bytes", quic_footprint ));

  FD_LOG_NOTICE(( "Creating server QUIC" ));
  fd_quic_t * server_quic = fd_quic_new_anonymous( wksp, &quic_limits, FD_QUIC_ROLE_SERVER, rng );
  FD_TEST( server_quic );

  FD_LOG_NOTICE(( "Creating client QUIC" ));
  fd_quic_t * client_quic = fd_quic_new_anonymous( wksp, &quic_limits, FD_QUIC_ROLE_CLIENT, rng );
  FD_TEST( client_quic );

  fd_quic_config_t * client_config = &client_quic->config;
  client_config->idle_timeout = 5e6;

  client_quic->cb.conn_hs_complete = my_handshake_complete;
  client_quic->cb.conn_final       = my_cb_conn_final;

  client_quic->cb.now     = test_clock;
  client_quic->cb.now_ctx = NULL;

  fd_quic_config_t * server_config = &server_quic->config;
  server_config->idle_timeout = 5e6;

  server_quic->cb.conn_new       = my_connection_new;
  server_quic->cb.stream_receive = my_stream_receive_cb;
  server_quic->cb.conn_final     = my_cb_conn_final;

  server_quic->cb.now     = test_clock;
  server_quic->cb.now_ctx = NULL;

  FD_LOG_NOTICE(( "Creating virtual pair" ));
  fd_quic_virtual_pair_t vp;
  fd_quic_virtual_pair_init( &vp, server_quic, client_quic );

  FD_LOG_NOTICE(( "Initializing QUICs" ));
  FD_TEST( fd_quic_init( client_quic ) );
  FD_TEST( fd_quic_init( server_quic ) );

  uint k = 1;

  char buf[512] = "Hello world!\x00-   ";

  int done  = 0;

  state = 1;

  while( k < 4000 && !done ) {
    now += 50000;

    ulong client_wakeup = fd_quic_get_next_wakeup( client_quic );
    ulong server_wakeup = fd_quic_get_next_wakeup( server_quic );
    ulong earliest_wakeup = fd_ulong_min( client_wakeup, server_wakeup );
    if( earliest_wakeup > now && earliest_wakeup != (ulong)(-1) ) now = earliest_wakeup;

    fd_quic_service( client_quic );
    fd_quic_service( server_quic );

    buf[12] = ' ';
    buf[15] = (char)( ( k / 10 ) + '0' );
    buf[16] = (char)( ( k % 10 ) + '0' );

    /* connection torn down? */
    if( !client_conn ) {
      state = 1; /* start a new one */
    }

    switch( state ) {
      case 0:
        FD_LOG_DEBUG(( "sending: %d", (int)k ));

        int rc = fd_quic_stream_uni_send( client_conn, buf, sizeof(buf) );
        if( rc == FD_QUIC_SUCCESS ) {
          /* successful - stream will begin closing */
          /* stream and meta will be recycled when quic notifies the stream
              is closed via my_stream_notify_cb */
          k++;
          if( (k%2) == 0 ) {
            // close client
            state = 1;

            fd_quic_conn_close( client_conn, 0 /* app defined reason code */ );
          }
        } else {
          FD_LOG_WARNING(( "unable to send - no streams available" ));
        }
        break;

      case 1:
        // wait for connection to close
        if( !client_conn ) {
          FD_LOG_INFO(( "client closed. opening new" ));

          /* new handshake starting */
          client_complete = 0;

          /* start new connection */
          client_conn = fd_quic_connect(
              client_quic,
              server_quic->config.net.ip_addr,
              server_quic->config.net.listen_udp_port,
              server_quic->config.sni );

          if( !client_quic ) {
            FD_LOG_ERR(( "fd_quic_connect failed" ));
          }

          client_conn->context = &client_conn;

          state = 2;
        }

        break;

      case 2:
        if( client_complete ) {
          FD_LOG_INFO(( "new connection completed handshake" ));

          state = 0;
        }

        break;

      default:
        done = 1;
    }

  }

  FD_LOG_NOTICE(( "Done sending. Received: %lu", _recv ));

  if( client_conn ) fd_quic_conn_close( client_conn, 0 );
  if( server_conn ) fd_quic_conn_close( server_conn, 0 );

  /* give server connection a chance to close */
  for( int j = 0; j < 1000; ++j ) {
    ulong next_wakeup = fd_quic_get_next_wakeup( server_quic );

    if( next_wakeup == ~(ulong)0 ) {
      FD_LOG_INFO(( "server has no schedule "));
      break;
    }

    now = next_wakeup;

    fd_quic_service( server_quic );
  }

  FD_LOG_NOTICE(( "Cleaning up" ));
  fd_quic_virtual_pair_fini( &vp );
  fd_wksp_free_laddr( fd_quic_delete( fd_quic_leave( fd_quic_fini( server_quic ) ) ) );
  fd_wksp_free_laddr( fd_quic_delete( fd_quic_leave( fd_quic_fini( client_quic ) ) ) );
  fd_wksp_delete_anonymous( wksp );
  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_quic_test_halt();
  fd_halt();
  return 0;
}
