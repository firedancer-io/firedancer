#include "../fd_quic.h"
#include "../fd_quic_private.h"
#include "fd_quic_test_helpers.h"
#include "../../../disco/metrics/generated/fd_metrics_enums.h"

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

static void
test_quic_hs( fd_quic_t * server_quic,
              fd_quic_t * client_quic ) {
  FD_LOG_NOTICE(( "Testing QUIC handshake" ));

  FD_TEST( fd_quic_init( server_quic ) );
  FD_TEST( fd_quic_init( client_quic ) );
  fd_quic_get_state( server_quic )->now = fd_quic_get_state( client_quic )->now = now;
  fd_quic_state_validate( server_quic );
  fd_quic_state_validate( client_quic );

  FD_LOG_NOTICE(( "Creating connection" ));
  fd_quic_conn_t * client_conn = fd_quic_connect( client_quic, FD_QUIC_TEST_SERVER_IP4, 0, FD_QUIC_TEST_CLIENT_IP4, 0, now );
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

  fd_quic_state_validate( server_quic );
  fd_quic_state_validate( client_quic );
  fd_quic_conn_close( client_conn, 0 );
  fd_quic_conn_close( server_conn, 0 );

  for( uint j=0; j<10U; ++j ) {
    FD_LOG_INFO(( "running services" ));
    fd_quic_service( client_quic, now );
    fd_quic_service( server_quic, now );
  }

  fd_quic_state_validate( server_quic );
  fd_quic_state_validate( client_quic );
  validate_quic_hs_tls_cache( client_quic );
  validate_quic_hs_tls_cache( server_quic );

  FD_CHECK_ERR( sizeof(fd_quic_tls_hs_cache_t) == fd_quic_tls_hs_cache_footprint(),
                "tls hs cache relies on footprint==sizeof, modify that impl" );

  FD_LOG_NOTICE(( "Testing TLS cache - within ttl prevents eviction " ));
  client_quic->config.tls_hs_ttl = 5UL;

  ulong             prev_evicted = client_quic->metrics.hs_evicted_cnt;
  fd_quic_state_t * client_state = fd_quic_get_state( client_quic );
  FD_TEST( prev_evicted == 0 );

  /* fill buffer, no eviction or failure */
  for( int i=0; i<10; ++i ) {
    FD_TEST( fd_quic_connect( client_quic, FD_QUIC_TEST_SERVER_IP4, 0, FD_QUIC_TEST_CLIENT_IP4, 0, now ) );
    FD_TEST( client_quic->metrics.hs_evicted_cnt == prev_evicted );
  }
  FD_TEST( !fd_quic_tls_hs_pool_free( client_state->hs_pool ) );
  validate_quic_hs_tls_cache( client_quic );

  now++;
  /* new connection should fail because within TTL of 5 */
  ulong prev_fail = client_quic->metrics.hs_err_alloc_fail_cnt;
  FD_TEST( !fd_quic_connect( client_quic, FD_QUIC_TEST_SERVER_IP4, 0, FD_QUIC_TEST_CLIENT_IP4, 0, now ) );
  FD_TEST( client_quic->metrics.hs_err_alloc_fail_cnt == prev_fail+1 );
  validate_quic_hs_tls_cache( client_quic );

  FD_LOG_NOTICE(( "Testing TLS cache - evicts if over ttl " ));
  now+=10;
  FD_TEST( !fd_quic_tls_hs_pool_free( client_state->hs_pool ) );
  FD_TEST( fd_quic_connect( client_quic, FD_QUIC_TEST_SERVER_IP4, 0, FD_QUIC_TEST_CLIENT_IP4, 0, now ) );
  validate_quic_hs_tls_cache( client_quic );
  FD_TEST( client_quic->metrics.hs_evicted_cnt == prev_evicted+1 );

  fd_quic_fini( client_quic );
  fd_quic_fini( server_quic );
}

/* Test function to verify server can send application data during handshake */
static void
test_quic_hs_with_server_appdata( fd_quic_t * server_quic,
                                  fd_quic_t * client_quic ) {
  FD_LOG_NOTICE(( "Testing server application data during handshake" ));

  /* Initialize QUICs */
  FD_TEST( fd_quic_init( server_quic ) );
  FD_TEST( fd_quic_init( client_quic ) );

  long test_now = 1000;
  fd_quic_get_state( server_quic )->now = fd_quic_get_state( client_quic )->now = test_now;

  /* Store initial retransmission counts */
  ulong server_retx_before[4] = { server_quic->metrics.pkt_retransmissions_cnt[0],
                                  server_quic->metrics.pkt_retransmissions_cnt[1],
                                  server_quic->metrics.pkt_retransmissions_cnt[2],
                                  server_quic->metrics.pkt_retransmissions_cnt[3] };
  ulong client_retx_before[4] = { client_quic->metrics.pkt_retransmissions_cnt[0],
                                  client_quic->metrics.pkt_retransmissions_cnt[1],
                                  client_quic->metrics.pkt_retransmissions_cnt[2],
                                  client_quic->metrics.pkt_retransmissions_cnt[3] };

  /* Client initiates connection */
  fd_quic_conn_t * client_conn = fd_quic_connect( client_quic, FD_QUIC_TEST_SERVER_IP4, 0, FD_QUIC_TEST_CLIENT_IP4, 0, test_now );
  FD_TEST( client_conn );
  fd_quic_service( client_quic, test_now );

  /* Artificially set the ping flag on server */
  FD_TEST( server_quic->metrics.conn_alloc_cnt == 1 );
  fd_quic_conn_t * srv_conn = (fd_quic_conn_t *)fd_quic_get_state( server_quic )->conn_base;
  FD_TEST( srv_conn->state != FD_QUIC_CONN_STATE_INVALID );
  srv_conn->flags |= FD_QUIC_CONN_FLAGS_PING;

  /* Service the server, asserting client successfully processed a 1-RTT packet */
  ulong exp_1rtt_prev = client_conn->exp_pkt_number[2];
  fd_quic_service( server_quic, test_now );
  FD_TEST( client_conn->exp_pkt_number[2] == exp_1rtt_prev+1 );

  /* Complete the handshake */
  for( ulong j = 0; j < 20; j++ ) {
    fd_quic_service( client_quic, test_now );
    fd_quic_service( server_quic, test_now );

    if( server_complete && client_complete ) {
      FD_LOG_INFO(( "Handshake complete" ));
      break;
    }
  }

  /* Verify handshake completed */
  FD_TEST( server_complete && client_complete );
  FD_TEST( client_conn->handshake_complete );
  FD_TEST( server_conn->handshake_complete );

  /* Verify no retransmissions occurred */
  ulong server_retx_after[4] = { server_quic->metrics.pkt_retransmissions_cnt[0],
                                  server_quic->metrics.pkt_retransmissions_cnt[1],
                                  server_quic->metrics.pkt_retransmissions_cnt[2],
                                  server_quic->metrics.pkt_retransmissions_cnt[3] };
  ulong client_retx_after[4] = { client_quic->metrics.pkt_retransmissions_cnt[0],
                                  client_quic->metrics.pkt_retransmissions_cnt[1],
                                  client_quic->metrics.pkt_retransmissions_cnt[2],
                                  client_quic->metrics.pkt_retransmissions_cnt[3] };

  for( uint j=0; j<4; ++j ) {
    FD_TEST( server_retx_after[j] == server_retx_before[j] );
    FD_TEST( client_retx_after[j] == client_retx_before[j] );
  }

  /* Clean up */
  fd_quic_fini( server_quic );
  fd_quic_fini( client_quic );

  FD_LOG_NOTICE(( "test_quic_hs_with_server_appdata: pass" ));
}

/* Test function to verify server can send application data during handshake */
static void
test_quic_hs_with_client_appdata( fd_quic_t * server_quic,
                                  fd_quic_t * client_quic ) {
  FD_LOG_NOTICE(( "Testing client application data during handshake" ));

  /* Initialize QUICs */
  FD_TEST( fd_quic_init( server_quic ) );
  FD_TEST( fd_quic_init( client_quic ) );

  long test_now = 1000;
  fd_quic_get_state( server_quic )->now = fd_quic_get_state( client_quic )->now = test_now;

  /* Store initial retransmission counts */
  ulong server_retx_before[4] = { server_quic->metrics.pkt_retransmissions_cnt[0],
                                  server_quic->metrics.pkt_retransmissions_cnt[1],
                                  server_quic->metrics.pkt_retransmissions_cnt[2],
                                  server_quic->metrics.pkt_retransmissions_cnt[3] };
  ulong client_retx_before[4] = { client_quic->metrics.pkt_retransmissions_cnt[0],
                                  client_quic->metrics.pkt_retransmissions_cnt[1],
                                  client_quic->metrics.pkt_retransmissions_cnt[2],
                                  client_quic->metrics.pkt_retransmissions_cnt[3] };

  /* Client initiates connection */
  fd_quic_conn_t * client_conn = fd_quic_connect( client_quic, FD_QUIC_TEST_SERVER_IP4, 0, FD_QUIC_TEST_CLIENT_IP4, 0, test_now );
  FD_TEST( client_conn );
  fd_quic_service( client_quic, test_now );

  /* Service the server */
  fd_quic_service( server_quic, test_now );

  /* Grab server connection */
  FD_TEST( server_quic->metrics.conn_alloc_cnt == 1 );
  fd_quic_conn_t * srv_conn = (fd_quic_conn_t *)fd_quic_get_state( server_quic )->conn_base;
  FD_TEST( srv_conn->state != FD_QUIC_CONN_STATE_INVALID );

  /* Force ping 1rtt during client's turn. Assert server received it */
  ulong exp_1rtt_prev = srv_conn->exp_pkt_number[2];
  client_conn->flags |= FD_QUIC_CONN_FLAGS_PING;
  fd_quic_service( client_quic, test_now );
  FD_TEST( srv_conn->exp_pkt_number[2] == exp_1rtt_prev+1 );

  /* Complete the handshake */
  for( ulong j = 0; j < 20; j++ ) {
    fd_quic_service( client_quic, test_now );
    fd_quic_service( server_quic, test_now );

    if( server_complete && client_complete ) {
      FD_LOG_INFO(( "Handshake complete" ));
      break;
    }
  }

  /* Verify handshake completed */
  FD_TEST( server_complete && client_complete );
  FD_TEST( client_conn->handshake_complete );
  FD_TEST( server_conn->handshake_complete );

  /* Verify no retransmissions occurred */
  ulong server_retx_after[4] = { server_quic->metrics.pkt_retransmissions_cnt[0],
                                  server_quic->metrics.pkt_retransmissions_cnt[1],
                                  server_quic->metrics.pkt_retransmissions_cnt[2],
                                  server_quic->metrics.pkt_retransmissions_cnt[3] };
  ulong client_retx_after[4] = { client_quic->metrics.pkt_retransmissions_cnt[0],
                                  client_quic->metrics.pkt_retransmissions_cnt[1],
                                  client_quic->metrics.pkt_retransmissions_cnt[2],
                                  client_quic->metrics.pkt_retransmissions_cnt[3] };

  for( uint j=0; j<4; ++j ) {
    FD_TEST( server_retx_after[j] == server_retx_before[j] );
    FD_TEST( client_retx_after[j] == client_retx_before[j] );
  }

  /* Clean up */
  fd_quic_fini( server_quic );
  fd_quic_fini( client_quic );

  FD_LOG_NOTICE(( "test_quic_hs_with_server_appdata: pass" ));
}

static int
test_drop_send( void *                    ctx,
                fd_aio_pkt_info_t const * batch,
                ulong                     batch_cnt,
                ulong *                   opt_batch_idx,
                int                       flush ) {
  (void)ctx; (void)batch; (void)batch_cnt; (void)opt_batch_idx; (void)flush;
  return FD_AIO_SUCCESS;
}

static ulong
server_pkt_meta_max( fd_quic_t * quic ) {
  fd_quic_state_t * state = fd_quic_get_state( quic );
  ulong max = 0UL;
  for( ulong j=0UL; j<quic->limits.conn_cnt; j++ ) {
    fd_quic_conn_t * conn = fd_quic_conn_at_idx( state, j );
    if( conn->state!=FD_QUIC_CONN_STATE_INVALID ) max = fd_ulong_max( max, conn->used_pkt_meta );
  }
  return max;
}

/* Handshake storm at the TPU tile's pkt_meta sizing (16/conn, reserve
   8, conn_cnt = 4*handshake_cnt).  Server flights are dropped for
   several PTOs so HS_DATA retransmits pile up; every handshake must still
   complete without a pkt_meta alloc failure. */

static void
test_quic_hs_storm( fd_wksp_t * wksp,
                    fd_rng_t *  rng ) {
  FD_LOG_NOTICE(( "Testing handshake storm at TPU pkt_meta sizing" ));

  ulong const hs_cnt   = 64UL;
  ulong const conn_cnt = 4UL*hs_cnt;
  fd_quic_limits_t const server_limits = {
    .conn_cnt                    = conn_cnt,
    .conn_id_cnt                 = FD_QUIC_MIN_CONN_ID_CNT,
    .handshake_cnt               = hs_cnt,
    .inflight_frame_cnt          = 16UL*conn_cnt,
    .min_inflight_frame_cnt_conn = 8UL
  };
  fd_quic_limits_t const client_limits = {
    .conn_cnt           = conn_cnt,
    .conn_id_cnt        = FD_QUIC_MIN_CONN_ID_CNT,
    .handshake_cnt      = hs_cnt,
    .inflight_frame_cnt = 64UL*conn_cnt
  };
  fd_quic_t * server = fd_quic_new_anonymous( wksp, &server_limits, FD_QUIC_ROLE_SERVER, rng );
  fd_quic_t * client = fd_quic_new_anonymous( wksp, &client_limits, FD_QUIC_ROLE_CLIENT, rng );
  server->config.idle_timeout = client->config.idle_timeout = (long)30e9;

  fd_quic_virtual_pair_t vp;
  fd_quic_virtual_pair_init( &vp, server, client );
  FD_TEST( fd_quic_init( server ) );
  FD_TEST( fd_quic_init( client ) );

  fd_aio_t drop_aio[1];
  FD_TEST( fd_aio_join( fd_aio_new( drop_aio, NULL, test_drop_send ) ) );
  fd_aio_t server_tx = server->aio_tx;

  long  t   = 1000L;
  ulong max = 0UL;
  fd_quic_sync_clocks( server, client, t );
  for( ulong wave=0UL; wave<conn_cnt/hs_cnt; wave++ ) {
    fd_quic_set_aio_net_tx( server, drop_aio );
    for( ulong j=0UL; j<hs_cnt; j++ ) {
      FD_TEST( fd_quic_connect( client, FD_QUIC_TEST_SERVER_IP4, 0, FD_QUIC_TEST_CLIENT_IP4, 0, t ) );
    }
    for( ulong j=0UL; j<4UL*conn_cnt; j++ ) fd_quic_service( client, t );
    for( ulong r=0UL; r<3UL; r++ ) {
      for( ulong j=0UL; j<4UL*conn_cnt; j++ ) fd_quic_service( server, t );
      max = fd_ulong_max( max, server_pkt_meta_max( server ) );
      t += (long)600e6; /* > server PTO */
    }
    FD_TEST( server->metrics.conn_state_cnt[ FD_QUIC_CONN_STATE_HANDSHAKE ]==hs_cnt );

    /* server retransmits first so clients learn its conn ID */
    fd_quic_set_aio_net_tx( server, &server_tx );
    for( ulong j=0UL; j<4UL*conn_cnt; j++ ) fd_quic_service( server, t );
    ulong want = (wave+1UL)*hs_cnt;
    for( ulong j=0UL; j<20000UL; j++ ) {
      fd_quic_service( client, t );
      fd_quic_service( server, t );
      t += (long)1e6;
      max = fd_ulong_max( max, server_pkt_meta_max( server ) );
      if( server->metrics.conn_state_cnt[ FD_QUIC_CONN_STATE_ACTIVE ]==want &&
          client->metrics.conn_state_cnt[ FD_QUIC_CONN_STATE_ACTIVE ]==want ) break;
    }
    FD_TEST( server->metrics.conn_state_cnt[ FD_QUIC_CONN_STATE_ACTIVE ]==want );
    FD_TEST( client->metrics.conn_state_cnt[ FD_QUIC_CONN_STATE_ACTIVE ]==want );
  }

  FD_LOG_NOTICE(( "server pkt_meta max/conn %lu, retx %lu", max, server->metrics.pkt_retransmissions_cnt[ fd_quic_enc_level_handshake_id ] ));
  FD_TEST( server->metrics.pkt_retransmissions_cnt[ fd_quic_enc_level_handshake_id ] );
  FD_TEST( max<=8UL );
  FD_TEST( !server->metrics.frame_tx_alloc_cnt[ FD_METRICS_ENUM_PKT_META_ACQUIRE_RESULT_V_POOL_EMPTY_IDX ] );
  FD_TEST( !server->metrics.frame_tx_alloc_cnt[ FD_METRICS_ENUM_PKT_META_ACQUIRE_RESULT_V_CONN_LIMIT_IDX ] );
  fd_quic_state_validate( server );

  fd_quic_virtual_pair_fini( &vp );
  fd_quic_fini( server );
  fd_quic_fini( client );
  fd_wksp_free_laddr( fd_quic_delete( fd_quic_leave( server ) ) );
  fd_wksp_free_laddr( fd_quic_delete( fd_quic_leave( client ) ) );
}

int
main( int argc, char ** argv ) {
  fd_boot          ( &argc, &argv );
  fd_quic_test_boot( &argc, &argv );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  ulong cpu_idx = fd_tile_cpu_id( fd_tile_idx() );
  if( cpu_idx>fd_shmem_cpu_cnt() ) cpu_idx = 0UL;

  char const * _page_sz  = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",   NULL, "gigantic"                   );
  ulong        page_cnt  = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt",  NULL, 1UL                          );
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

  fd_quic_t * server_quic = fd_quic_new_anonymous( wksp, &quic_limits, FD_QUIC_ROLE_SERVER, rng );
  FD_TEST( server_quic );

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

  test_quic_hs( server_quic, client_quic );

  test_quic_hs_with_server_appdata( server_quic, client_quic );

  test_quic_hs_with_client_appdata( server_quic, client_quic );

  FD_LOG_NOTICE(( "Cleaning up" ));
  fd_quic_virtual_pair_fini( &vp );
  test_quic_hs_storm( wksp, rng );
  fd_wksp_free_laddr( fd_quic_delete( fd_quic_leave( server_quic ) ) );
  fd_wksp_free_laddr( fd_quic_delete( fd_quic_leave( client_quic ) ) );
  fd_wksp_delete_anonymous( wksp );
  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_quic_test_halt();
  fd_halt();
  return 0;
}
