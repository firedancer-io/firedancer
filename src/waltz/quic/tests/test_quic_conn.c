#include "../fd_quic.h"
#include "fd_quic_test_helpers.h"

/* test_quic_conn repeatedly opens and closes QUIC connections. */

int state           = 0;
int server_complete = 0;
int client_complete = 0;

/* server connection received in callback */
fd_quic_conn_t * server_conn = NULL;
fd_quic_conn_t * client_conn = NULL;

extern uchar pkt_full[];
extern ulong pkt_full_sz;

uchar fail = 0;

static ulong _recv = 0;
int
my_stream_rx_cb( fd_quic_conn_t * conn,
                 ulong            stream_id,
                 ulong            offset,
                 uchar const *    data,
                 ulong            data_sz,
                 int              fin ) {
  (void)conn; (void)stream_id; (void)fin;

  ulong expected_data_sz = 512ul;

  FD_LOG_INFO(( "received data from peer. size: %lu offset: %lu",
                data_sz, offset ));
  FD_LOG_HEXDUMP_DEBUG(( "received data", data, data_sz ));

  if( FD_UNLIKELY( data_sz!=512UL ) ) {
    FD_LOG_WARNING(( "data wrong size. Is: %lu, expected: %lu",
                     data_sz, expected_data_sz ));
    fail = 1;
    return FD_QUIC_SUCCESS;
  }

  if( FD_UNLIKELY( 0!=memcmp( data, "Hello world", 11u ) ) ) {
    FD_LOG_WARNING(( "value received incorrect" ));
    fail = 1;
    return FD_QUIC_SUCCESS;
  }

  FD_LOG_DEBUG(( "recv ok" ));

  _recv++;
  return FD_QUIC_SUCCESS;
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

  fd_quic_conn_set_context( conn, &server_conn );
}

void
my_handshake_complete( fd_quic_conn_t * conn,
                       void *           vp_context ) {
  (void)vp_context;

  FD_LOG_INFO(( "client handshake complete" ));

  client_complete = 1;

  fd_quic_conn_set_context( conn, &client_conn );
}

/* global "clock" */
long now = (long)1e18;

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
    .conn_cnt           = 10,
    .conn_id_cnt        = 10,
    .handshake_cnt      = 10,
    .stream_id_cnt      = 10,
    .stream_pool_cnt    = 400,
    .inflight_frame_cnt = 1024 * 10,
    .tx_buf_sz          = 1<<14
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

  client_quic->cb.conn_hs_complete = my_handshake_complete;
  client_quic->cb.stream_rx        = my_stream_rx_cb;
  client_quic->cb.conn_final       = my_cb_conn_final;

  server_quic->cb.conn_new       = my_connection_new;
  server_quic->cb.stream_rx      = my_stream_rx_cb;
  server_quic->cb.conn_final     = my_cb_conn_final;

  server_quic->config.initial_rx_max_stream_data = 1<<14;
  client_quic->config.initial_rx_max_stream_data = 1<<14;

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

    fd_quic_service( client_quic, now );
    fd_quic_service( server_quic, now );

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

        fd_quic_stream_t * stream = fd_quic_conn_new_stream( client_conn );
        if( FD_UNLIKELY( !stream ) ) {
          FD_LOG_WARNING(( "unable to send - no streams available" ));
          break;
        }

        int rc = fd_quic_stream_send( stream, buf, sizeof(buf), 1 /* fin */ );
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
          client_conn = fd_quic_connect( client_quic, 0U, 0, 0U, 0, now );

          if( !client_conn ) {
            FD_LOG_ERR(( "fd_quic_connect failed" ));
          }

          fd_quic_conn_set_context( client_conn, &client_conn );

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

  FD_LOG_INFO(( "client_conn: %p", (void*)client_conn ));
  FD_LOG_INFO(( "server_conn: %p", (void*)server_conn ));

  /* give server connection a chance to close */
  for( int j = 0; j < 1000; ++j ) {
    fd_quic_service( server_quic, now );
  }

  FD_LOG_INFO(( "client_conn: %p", (void*)client_conn ));
  FD_LOG_INFO(( "server_conn: %p", (void*)server_conn ));

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
