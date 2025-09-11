#include "../fd_quic.h"
#include "../fd_quic_private.h"
#include "fd_quic_test_helpers.h"

#include <stdio.h>
#include <stdlib.h>

int
my_stream_rx_cb( fd_quic_conn_t * conn,
                 ulong            stream_id,
                 ulong            offset,
                 uchar const *    data,
                 ulong            data_sz,
                 int              fin ) {
  (void)conn;
  FD_LOG_DEBUG(( "server rx stream data stream=%lu size=%lu offset=%lu",
                 stream_id, data_sz, offset ));
  FD_TEST( fd_ulong_is_aligned( offset, 512UL ) );
  FD_LOG_HEXDUMP_DEBUG(( "received data", data, data_sz ));

  FD_TEST( data_sz==512UL );
  FD_TEST( !fin );
  FD_TEST( 0==memcmp( data, "Hello world", 11u ) );
  return FD_QUIC_SUCCESS;
}

int server_complete = 0;
int client_complete = 0;

/* server connection received in callback */
fd_quic_conn_t * server_conn = NULL;

void
my_connection_new( fd_quic_conn_t * conn,
                   void *           vp_context ) {
  (void)vp_context;

  FD_LOG_NOTICE(( "server handshake complete" ));

  server_complete = 1;
  server_conn = conn;
}

void
my_handshake_complete( fd_quic_conn_t * conn,
                       void *           vp_context ) {
  (void)conn;
  (void)vp_context;

  FD_LOG_NOTICE(( "client handshake complete" ));

  client_complete = 1;
}

static void
validate_quic_hs_tls_cache( fd_quic_t * quic ) {
  fd_quic_state_t        * state     =  fd_quic_get_state( quic );
  fd_quic_tls_hs_cache_t * hs_cache  =  &state->hs_cache;
  fd_quic_tls_hs_t       * pool      =  state->hs_pool;

  ulong cache_cnt  = 0UL;
  long  prev_birth = 0L;
  for( fd_quic_tls_hs_cache_iter_t iter = fd_quic_tls_hs_cache_iter_fwd_init( hs_cache, pool );
      !fd_quic_tls_hs_cache_iter_done( iter, hs_cache, pool );
      iter = fd_quic_tls_hs_cache_iter_fwd_next( iter, hs_cache, pool )
  ) {
    fd_quic_tls_hs_t * hs = fd_quic_tls_hs_cache_iter_ele( iter, hs_cache, pool );
    FD_TEST( hs->birthtime >= prev_birth );
    prev_birth = hs->birthtime;
    cache_cnt++;
  }

  FD_TEST( cache_cnt == fd_quic_tls_hs_pool_used( pool ) );
}


/* global "clock" */
long now = 123;

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

  server_quic->cb.conn_new         = my_connection_new;
  server_quic->cb.stream_rx        = my_stream_rx_cb;

  client_quic->cb.conn_hs_complete = my_handshake_complete;

  server_quic->config.initial_rx_max_stream_data = 1<<16;
  client_quic->config.initial_rx_max_stream_data = 1<<16;

  FD_LOG_NOTICE(( "Creating virtual pair" ));
  fd_quic_virtual_pair_t vp;
  fd_quic_virtual_pair_init( &vp, server_quic, client_quic );

  FD_LOG_NOTICE(( "Initializing QUICs" ));
  FD_TEST( fd_quic_init( server_quic ) );
  FD_TEST( fd_quic_init( client_quic ) );
  fd_quic_state_validate( server_quic );
  fd_quic_state_validate( client_quic );

  FD_LOG_NOTICE(( "Creating connection" ));
  fd_quic_conn_t * client_conn = fd_quic_connect( client_quic, 0U, 0, 0U, 0, now );
  FD_TEST( client_conn );

  /* do general processing */
  for( ulong j = 0; j < 20; j++ ) {
    FD_LOG_INFO(( "running services" ));
    fd_quic_service( client_quic, now );
    fd_quic_service( server_quic, now );
    validate_quic_hs_tls_cache( client_quic );
    validate_quic_hs_tls_cache( server_quic );

    if( server_complete && client_complete ) {
      FD_LOG_INFO(( "***** both handshakes complete *****" ));
      break;
    }
  }

  fflush( fd_quic_test_pcap );
  FD_TEST( server_complete && client_complete );

  /* TODO detect missing QUIC transport params */

  /* TODO we get callback before the call to fd_quic_conn_new_stream can complete
     must delay until the conn->state is ACTIVE */

  FD_LOG_NOTICE(( "Creating streams" ));

  fd_quic_stream_t * client_stream   = fd_quic_conn_new_stream( client_conn );
  FD_TEST( client_stream );

  fd_quic_stream_t * client_stream_0 = fd_quic_conn_new_stream( client_conn );
  FD_TEST( client_stream_0 );

  FD_LOG_NOTICE(( "Sending data over streams" ));

  char buf[512] = "Hello world!\x00-   ";

  for( unsigned j = 0; j < 16; ++j ) {
    FD_LOG_INFO(( "running services" ));

    fd_quic_service( client_quic, now );
    fd_quic_service( server_quic, now );

    buf[12] = ' ';
    //buf[15] = (char)( ( j / 10 ) + '0' );
    buf[16] = (char)( ( j % 10 ) + '0' );
    int rc = 0;
    if( j&1 ) {
      rc = fd_quic_stream_send( client_stream,   buf, sizeof(buf), 0 );
    } else {
      rc = fd_quic_stream_send( client_stream_0, buf, sizeof(buf), 0 );
    }

    FD_LOG_INFO(( "fd_quic_stream_send returned %d", rc ));
  }

  /* testing keep_alive */
  ulong const idle_timeout = fd_ulong_min(
                                  (ulong)client_quic->config.idle_timeout,
                                  (ulong)server_quic->config.idle_timeout
                                 );
  ulong const timestep     = idle_timeout>>3;

  for( int keep_alive=1; keep_alive>=0; --keep_alive ) {
    client_quic->config.keep_alive = keep_alive;
    for( int i=0; i<10; ++i ) {
      now+=(long)timestep;
      fd_quic_service( client_quic, now );
      fd_quic_service( server_quic, now );
    }
    if( keep_alive ) {
      FD_TEST( client_conn->state == FD_QUIC_CONN_STATE_ACTIVE );
    } else {
      FD_TEST( client_conn->state == FD_QUIC_CONN_STATE_DEAD ||
              client_conn->state == FD_QUIC_CONN_STATE_INVALID );
    }
  }

  FD_LOG_NOTICE(( "Validated idle_timeout and keep_alive" ));


  FD_LOG_NOTICE(( "Closing connections" ));

  fd_quic_state_validate( server_quic );
  fd_quic_state_validate( client_quic );
  fd_quic_conn_close( client_conn, 0 );
  fd_quic_conn_close( server_conn, 0 );

  FD_LOG_NOTICE(( "Waiting for ACKs" ));

  for( uint j=0; j<10U; ++j ) {
    FD_LOG_INFO(( "running services" ));
    fd_quic_service( client_quic, now );
    fd_quic_service( server_quic, now );
  }

  fd_quic_state_validate( server_quic );
  fd_quic_state_validate( client_quic );
  validate_quic_hs_tls_cache( client_quic );
  validate_quic_hs_tls_cache( server_quic );

  FD_TEST_CUSTOM( sizeof(fd_quic_tls_hs_cache_t) == fd_quic_tls_hs_cache_footprint( ),
                    "tls hs cache relies on footprint==sizeof, modify that impl" );

  FD_LOG_NOTICE(( "Testing TLS cache - within ttl prevents eviction " ));
  client_quic->config.tls_hs_ttl = 5UL;

  ulong             prev_evicted = client_quic->metrics.hs_evicted_cnt;
  fd_quic_state_t * client_state = fd_quic_get_state( client_quic );
  FD_TEST( prev_evicted == 0 );

  /* fill buffer, no eviction or failure */
  for( int i=0; i<10; ++i ) {
    FD_TEST( fd_quic_connect( client_quic, 0U, 0, 0U, 0, now ) );
    FD_TEST( client_quic->metrics.hs_evicted_cnt == prev_evicted );
  }
  FD_TEST( !fd_quic_tls_hs_pool_free( client_state->hs_pool ) );
  validate_quic_hs_tls_cache( client_quic );

  now++;
  /* new connection should fail because within TTL of 5 */
  ulong prev_fail = client_quic->metrics.hs_err_alloc_fail_cnt;
  FD_TEST( !fd_quic_connect( client_quic, 0U, 0, 0U, 0, now ) );
  FD_TEST( client_quic->metrics.hs_err_alloc_fail_cnt == prev_fail+1 );
  validate_quic_hs_tls_cache( client_quic );

  FD_LOG_NOTICE(( "Testing TLS cache - evicts if over ttl " ));
  now+=10;
  FD_TEST( !fd_quic_tls_hs_pool_free( client_state->hs_pool ) );
  FD_TEST( fd_quic_connect( client_quic, 0U, 0, 0U, 0, now ) );
  validate_quic_hs_tls_cache( client_quic );
  FD_TEST( client_quic->metrics.hs_evicted_cnt == prev_evicted+1 );


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
