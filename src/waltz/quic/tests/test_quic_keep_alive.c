#include "../fd_quic.h"
#include "fd_quic_test_helpers.h"

int server_complete = 0;
int client_complete = 0;

void
my_connection_new( fd_quic_conn_t * conn FD_PARAM_UNUSED,
                   void *           vp_context FD_PARAM_UNUSED ) {
  server_complete = 1;
}

void
my_handshake_complete( fd_quic_conn_t * conn FD_PARAM_UNUSED,
                       void *           vp_context FD_PARAM_UNUSED ) {
  client_complete = 1;
}


/* global "clock" */
ulong now = 145;

ulong test_clock( void * ctx ) {
  (void)ctx;
  return now;
}

static void
test_quic_keep_alive( fd_quic_t * client_quic, fd_quic_t * server_quic, int keep_alive ) {

  server_complete = 0;
  client_complete = 0;

  client_quic->config.keep_alive = keep_alive;

  FD_TEST( fd_quic_init( server_quic ) );
  FD_TEST( fd_quic_init( client_quic ) );
  fd_quic_svc_validate( server_quic );
  fd_quic_svc_validate( client_quic );

  fd_quic_conn_t * client_conn = fd_quic_connect( client_quic, 0U, 0, 0U, 0 );
  FD_TEST( client_conn );

  /* do general processing */
  for( ulong j = 0; j < 20; j++ ) {
    FD_LOG_INFO(( "running services" ));
    fd_quic_service( client_quic );
    fd_quic_service( server_quic );

    if( server_complete && client_complete ) {
      FD_LOG_INFO(( "***** both handshakes complete *****" ));
      break;
    }
  }

  /* FIXME: when svc_queue fixed, make sure these are different
     and use idle_timeout = their min */
  FD_TEST( client_quic->config.idle_timeout == server_quic->config.idle_timeout );
  ulong const idle_timeout = client_quic->config.idle_timeout;
  ulong const timestep     = idle_timeout>>3;

  for( int i=0; i<10; ++i ) {
    now+=timestep;
    fd_quic_service( client_quic );
    fd_quic_service( server_quic );
  }
  if( keep_alive ) {
    FD_TEST( client_conn->state == FD_QUIC_CONN_STATE_ACTIVE );
  } else {
    FD_TEST( client_conn->state == FD_QUIC_CONN_STATE_DEAD ||
            client_conn->state == FD_QUIC_CONN_STATE_INVALID );
  }
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

  fd_quic_t * server_quic = fd_quic_new_anonymous( wksp, &quic_limits, FD_QUIC_ROLE_SERVER, rng );
  FD_TEST( server_quic );

  fd_quic_t * client_quic = fd_quic_new_anonymous( wksp, &quic_limits, FD_QUIC_ROLE_CLIENT, rng );
  FD_TEST( client_quic );

  server_quic->cb.now              = test_clock;
  client_quic->cb.now              = test_clock;

  server_quic->cb.conn_new         = my_connection_new;
  client_quic->cb.conn_hs_complete = my_handshake_complete;

  server_quic->config.initial_rx_max_stream_data = 1<<16;
  client_quic->config.initial_rx_max_stream_data = 1<<16;

  fd_quic_virtual_pair_t vp;
  fd_quic_virtual_pair_init( &vp, server_quic, client_quic );

  test_quic_keep_alive( client_quic, server_quic, 0 );
  test_quic_keep_alive( client_quic, server_quic, 1 );

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


