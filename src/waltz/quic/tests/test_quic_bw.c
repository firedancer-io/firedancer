#include "../fd_quic.h"
#include "fd_quic_test_helpers.h"

uchar conn_final_cnt = 0;

ulong rx_tot_sz = 0;

static void
my_conn_final( fd_quic_conn_t * conn,
               void *           quic_ctx ) {
  (void)conn;
  (void)quic_ctx;
  conn_final_cnt++;
}

static void
my_stream_receive_cb( fd_quic_stream_t * stream,
                      void *             ctx,
                      uchar const *      data,
                      ulong              data_sz,
                      ulong              offset,
                      int                fin ) {
  (void)ctx;
  (void)stream;
  (void)data;
  (void)data_sz;
  (void)offset;
  (void)fin;

  rx_tot_sz += data_sz;
}

int server_complete = 0;
int client_complete = 0;

/* server connection received in callback */
fd_quic_conn_t * server_conn = NULL;

void my_connection_new( fd_quic_conn_t * conn,
                        void *           vp_context ) {
  (void)vp_context;

  FD_LOG_INFO(( "server handshake complete" ));

  server_complete = 1;
  server_conn = conn;
}

void my_handshake_complete( fd_quic_conn_t * conn,
                            void *           vp_context ) {
  (void)conn;
  (void)vp_context;

  FD_LOG_INFO(( "client handshake complete" ));

  client_complete = 1;
}

int
main( int     argc,
      char ** argv ) {

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
    .conn_id_sparsity   = 4.0,
    .handshake_cnt      = 10,
    .stream_cnt         = { 0, 0, 10, 0 },
    .initial_stream_cnt = { 0, 0, 10, 0 },
    .stream_pool_cnt    = 200,
    .inflight_pkt_cnt   = 100,
    .tx_buf_sz          = 1<<20
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

  server_quic->config.role = FD_QUIC_ROLE_SERVER;
  client_quic->config.role = FD_QUIC_ROLE_CLIENT;

  server_quic->cb.conn_new         = my_connection_new;
  server_quic->cb.conn_final       = my_conn_final;
  server_quic->cb.stream_receive   = my_stream_receive_cb;

  client_quic->cb.conn_hs_complete = my_handshake_complete;

  server_quic->config.initial_rx_max_stream_data = 1<<20;
  client_quic->config.initial_rx_max_stream_data = 1<<20;

  FD_LOG_NOTICE(( "Creating virtual pair" ));
  fd_quic_virtual_pair_t vp;
  fd_quic_virtual_pair_init( &vp, server_quic, client_quic );

  FD_LOG_NOTICE(( "Initializing QUICs" ));
  FD_TEST( fd_quic_init( server_quic ) );
  FD_TEST( fd_quic_init( client_quic ) );

  /* make a connection from client to server */
  fd_quic_conn_t * client_conn = fd_quic_connect(
      client_quic,
      server_quic->config.net.ip_addr,
      server_quic->config.net.listen_udp_port,
      server_quic->config.sni );

  FD_TEST( conn_final_cnt==0 );

  /* do general processing */
  for( ulong j = 0; j < 20; j++ ) {
    ulong ct = fd_quic_get_next_wakeup( client_quic );
    ulong st = fd_quic_get_next_wakeup( server_quic );
    ulong next_wakeup = fd_ulong_min( ct, st );

    if( next_wakeup == ~(ulong)0 ) {
      FD_LOG_INFO(( "client and server have no schedule" ));
      break;
    }

    FD_LOG_INFO(( "running services at %lu", next_wakeup ));
    fd_quic_service( client_quic );
    fd_quic_service( server_quic );

    if( server_complete && client_complete ) {
      FD_LOG_INFO(( "***** both handshakes complete *****" ));
      break;
    }
  }

  FD_LOG_DEBUG(( "client_conn->state: %d", client_conn->state ));

  for( ulong j = 0; j < 20; j++ ) {
    ulong ct = fd_quic_get_next_wakeup( client_quic );
    ulong st = fd_quic_get_next_wakeup( server_quic );
    ulong next_wakeup = fd_ulong_min( ct, st );

    if( next_wakeup == ~(ulong)0 ) {
      FD_LOG_INFO(( "client and server have no schedule" ));
      break;
    }

    fd_quic_service( client_quic );
    fd_quic_service( server_quic );
  }

  FD_LOG_DEBUG(( "client_conn->state: %d", client_conn->state ));

  FD_TEST( client_conn->state == FD_QUIC_CONN_STATE_ACTIVE );
  FD_TEST( conn_final_cnt==0 );

  /* try sending */
  fd_quic_stream_t * client_stream = fd_quic_conn_new_stream( client_conn, FD_QUIC_TYPE_BIDIR );
  FD_TEST( client_stream );

  char buf[ 256UL ] = "Hello world!\x00-   ";
  ulong buf_sz = sizeof(buf);
  fd_aio_pkt_info_t batch[1] = {{ buf, (ushort)buf_sz }};
  int rc = fd_quic_stream_send( client_stream, batch, 1, 0 );

  FD_LOG_INFO(( "fd_quic_stream_send returned %d", rc ));

  ulong tot     = 0;
  long last_ts = fd_log_wallclock();
  long rprt_ts = fd_log_wallclock() + (long)1e9;

  long start_ts = fd_log_wallclock();
  long end_ts   = start_ts + (long)10e9; /* ten seconds */
  while(1) {
    fd_quic_service( client_quic );
    fd_quic_service( server_quic );

    rc = fd_quic_stream_send( client_stream, batch, 1, 0 );
    if( rc == 1 ) {
      tot += buf_sz;
    }

    long t = fd_log_wallclock();
    if( t >= rprt_ts ) {
      long dt = t - last_ts;
      float bps = (float)tot / (float)dt;
      FD_LOG_NOTICE(( "bw: %f  dt: %f  bytes: %f", (double)bps, (double)dt, (double)tot ));

      tot     = 0;
      last_ts = t;
      rprt_ts = t + (long)1e9;

      if( t > end_ts ) break;
    }
  }

  /* close the connections */
  fd_quic_conn_close( client_conn, 0 );
  fd_quic_conn_close( server_conn, 0 );

  /* allow acks to go */
  for( unsigned j = 0; j < 10; ++j ) {
    ulong ct = fd_quic_get_next_wakeup( client_quic );
    ulong st = fd_quic_get_next_wakeup( server_quic );
    ulong next_wakeup = fd_ulong_min( ct, st );

    if( next_wakeup == ~(ulong)0 ) {
      /* indicates no schedule, which is correct after connection
         instances have been reclaimed */
      FD_LOG_INFO(( "Finished cleaning up connections" ));
      break;
    }

    FD_LOG_INFO(( "running services at %lu", next_wakeup ));
    fd_quic_service( client_quic );
    fd_quic_service( server_quic );
  }

  FD_TEST( conn_final_cnt==2 );

  FD_LOG_NOTICE(( "Cleaning up" ));
  fd_quic_virtual_pair_fini( &vp );
  fd_wksp_free_laddr( fd_quic_delete( fd_quic_leave( fd_quic_fini( server_quic ) ) ) );
  fd_wksp_free_laddr( fd_quic_delete( fd_quic_leave( fd_quic_fini( client_quic ) ) ) );
  fd_wksp_delete_anonymous( wksp );
  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
