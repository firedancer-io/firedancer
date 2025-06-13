#include "../fd_quic.h"
#include "fd_quic_test_helpers.h"

int server_complete = 0;
int client_complete = 0;
fd_quic_conn_t * server_conn = NULL;

int called_final = 0;

void
my_connection_new( fd_quic_conn_t * conn FD_PARAM_UNUSED,
                   void *           vp_context FD_PARAM_UNUSED ) {
  server_complete = 1;
  server_conn = conn;
}

void
my_handshake_complete( fd_quic_conn_t * conn FD_PARAM_UNUSED,
                       void *           vp_context FD_PARAM_UNUSED ) {
  client_complete = 1;
}

void
my_connection_final( fd_quic_conn_t * conn       FD_PARAM_UNUSED,
                     void           * vp_context FD_PARAM_UNUSED ) {
  called_final = 1;
}

/* global "clock" */
long now = 145;

/* returns the client conn, setting server_conn in the global */
static fd_quic_conn_t *
test_init( fd_quic_t * client_quic, fd_quic_t * server_quic ) {
  server_complete = 0;
  client_complete = 0;
  server_conn = NULL;

  fd_memset( &server_quic->metrics, 0, sizeof(fd_quic_metrics_t) );
  fd_memset( &client_quic->metrics, 0, sizeof(fd_quic_metrics_t) );

  FD_TEST( fd_quic_init( server_quic ) );
  FD_TEST( fd_quic_init( client_quic ) );
  fd_quic_get_state( server_quic )->now = fd_quic_get_state( client_quic )->now = now;
  fd_quic_state_validate( server_quic );
  fd_quic_state_validate( client_quic );

  fd_quic_conn_t * client_conn = fd_quic_connect( client_quic, 0U, 0, 0U, 0, now );
  FD_TEST( client_conn );

  /* do general processing */
  for( ulong j=0; j<20; ++j ) {
    FD_LOG_INFO(( "running services" ));
    fd_quic_service( client_quic, now );
    fd_quic_service( server_quic, now );

    if( server_complete && client_complete ) {
      FD_LOG_INFO(( "***** both handshakes complete *****" ));
    }
  }

  FD_TEST( server_complete && client_complete );
  FD_TEST( server_conn );
  return client_conn;
}

/* walks a timeout period by stepping 1/8 timeout, 'eighths' times */
static long
walk_timeout_period( fd_quic_conn_t * client_conn, fd_quic_t * server_quic, int eighths ) {

  fd_quic_t * client_quic = client_conn->quic;

  long const server_timeout = server_quic->config.idle_timeout;
  long const client_timeout = client_quic->config.idle_timeout;
  long const idle_timeout   = fd_long_min( server_timeout, client_timeout );

  FD_TEST( server_conn->idle_timeout_ns == idle_timeout );
  FD_TEST( client_conn->idle_timeout_ns == idle_timeout );

  long const timestep = idle_timeout>>3;
  for( int i=0; i<eighths; ++i ) {
    now+=timestep;
    fd_quic_service( client_quic, now );
    fd_quic_service( server_quic, now );
  }

  return timestep;
}

static void
test_quic_keep_alive( fd_quic_t * client_quic, fd_quic_t * server_quic, int keep_alive ) {

  called_final = 0;
  client_quic->config.keep_alive = keep_alive;
  fd_quic_conn_t * client_conn = test_init( client_quic, server_quic );

  walk_timeout_period( client_conn, server_quic, 8 );
  if( keep_alive ) {
    FD_TEST( server_conn->state == FD_QUIC_CONN_STATE_ACTIVE );
  } else {
    FD_TEST( server_conn->state == FD_QUIC_CONN_STATE_INVALID ||
             server_conn->state == FD_QUIC_CONN_STATE_DEAD );
    FD_TEST( called_final );
  }
}

static void
test_quic_let_die( fd_quic_t * client_quic, fd_quic_t * server_quic ) {
  called_final = 0;
  fd_quic_conn_t * client_conn = test_init( client_quic, server_quic );

  long const timestep = client_conn->idle_timeout_ns>>3;
  fd_quic_conn_let_die( client_conn, timestep );
  walk_timeout_period( client_conn, server_quic, 8 );
  FD_TEST( server_conn->state == FD_QUIC_CONN_STATE_INVALID ||
           server_conn->state == FD_QUIC_CONN_STATE_DEAD );
  FD_TEST( called_final );
}

static void
test_quic_free_timed_out( fd_quic_t * client_quic, fd_quic_t * server_quic ) {
  fd_quic_conn_t * orig_client_conn = test_init( client_quic, server_quic );
  fd_quic_conn_t * orig_server_conn = server_conn;
  ulong const conn_cnt = server_quic->limits.conn_cnt;

  ulong const orig_timeouts = server_quic->metrics.conn_timeout_cnt;

  now += orig_client_conn->idle_timeout_ns>>3;

  /* try creating 10 conns - the last one should fail */
  for( ulong i=0; i<conn_cnt; ++i ) {
    fd_quic_conn_t * conn = fd_quic_connect( client_quic, 0, 0, 0, 0, now );
    for( ulong j=0; j<10; ++j ) {
      fd_quic_service( client_quic, now );
      fd_quic_service( server_quic, now );
    }
    if( i!=conn_cnt-1 ) {
      FD_TEST( conn->state == FD_QUIC_CONN_STATE_ACTIVE );
    } else {
      FD_TEST( !conn );
    }
  }
  FD_TEST( orig_timeouts == server_quic->metrics.conn_timeout_cnt );

  walk_timeout_period( orig_client_conn, server_quic, 7 );

  /* server should have timed out the first one now */
  FD_TEST( orig_server_conn->state == FD_QUIC_CONN_STATE_INVALID ||
           orig_server_conn->state == FD_QUIC_CONN_STATE_DEAD );
  FD_TEST( orig_client_conn->state == FD_QUIC_CONN_STATE_INVALID ||
           orig_client_conn->state == FD_QUIC_CONN_STATE_DEAD );
  FD_TEST( orig_timeouts + 1 == server_quic->metrics.conn_timeout_cnt );

  /* try again, should have space by freeing old one */
  fd_quic_conn_t * conn = fd_quic_connect( client_quic, 0, 0, 0, 0, now );
  FD_TEST( conn );
  for( ulong j=0; j<10; ++j ) {
    fd_quic_service( client_quic, now );
    fd_quic_service( server_quic, now );
  }
  FD_TEST( conn->state == FD_QUIC_CONN_STATE_ACTIVE );
  FD_TEST( server_conn == orig_server_conn );
  FD_TEST( orig_timeouts + 1 == server_quic->metrics.conn_timeout_cnt );
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

  server_quic->cb.conn_new         = my_connection_new;
  client_quic->cb.conn_hs_complete = my_handshake_complete;
  server_quic->cb.conn_final       = my_connection_final;

  server_quic->config.idle_timeout = 1e7;
  client_quic->config.idle_timeout = 1e9;

  server_quic->config.ack_delay    = 1e6;
  client_quic->config.ack_delay    = 1e6;

  server_quic->config.initial_rx_max_stream_data = 1<<16;
  client_quic->config.initial_rx_max_stream_data = 1<<16;

  fd_quic_virtual_pair_t vp;
  fd_quic_virtual_pair_init( &vp, server_quic, client_quic );

  test_quic_keep_alive    ( client_quic, server_quic, 1 );
  test_quic_keep_alive    ( client_quic, server_quic, 0 );
  test_quic_let_die       ( client_quic, server_quic );
  test_quic_free_timed_out( client_quic, server_quic );

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
