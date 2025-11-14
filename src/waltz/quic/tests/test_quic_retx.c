#include "../fd_quic.h"
#include "fd_quic_test_helpers.h"

int server_complete = 0;
int client_complete = 0;

long now = 1L;

#define TEST_DEFAULT_ONE_WAY_LATENCY 150L

#define EPS 0.0001f

char msg[] = "Hello world!\x00-   ";

/* server connection received in callback */
fd_quic_conn_t * server_conn = NULL;

fd_quic_netem_t _netem[2];
fd_quic_netem_t * client_netem;
fd_quic_netem_t * server_netem;

/* Global buffers and flag for stream retx test */
uchar exp_stream [4000];
uchar rcvd_stream[4000];
int fin_complete = 0;
ulong rcvd_stream_sz = 0;

static void
set_1_way_latency( long latency ) {
  fd_quic_netem_set_one_way_latency( client_netem, latency );
  fd_quic_netem_set_one_way_latency( server_netem, latency );
}

static void
send_packet( fd_quic_conn_t * client_conn ) {
  fd_quic_t * client_quic = client_conn->quic;
  fd_quic_stream_t * client_stream = fd_quic_conn_new_stream( client_conn );
  FD_TEST( client_stream );
  FD_TEST( !fd_quic_stream_send( client_stream, msg, sizeof(msg), 1 ) );
  fd_quic_service( client_quic, now );
}

static void
force_rtt_measurement( fd_quic_conn_t * client_conn, fd_quic_t * server_quic, long one_way_latency ) {
  set_1_way_latency( one_way_latency );
  send_packet( client_conn );
  now += server_quic->config.ack_delay;
  fd_quic_service( server_quic, now );
}

void
conn_final( fd_quic_conn_t * conn, void * context FD_PARAM_UNUSED ) {
  FD_LOG_NOTICE(( "%s conn died!!!!" , conn->server ? "server" : "client" ));
}

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

int server_stream_rx_cb( fd_quic_conn_t * conn,
                         ulong            stream_id,
                         ulong            offset,
                         uchar const *    data,
                         ulong            data_sz,
                         int              fin ) {
  (void)conn;
  (void)stream_id;

  /* if first four bytes are all 0, consider this new data */
  if( FD_LOAD( uint, rcvd_stream+offset ) == 0 )
    rcvd_stream_sz += data_sz;

  /* Copy received data to buffer at offset */
  fd_memcpy( rcvd_stream + offset, data, data_sz );

  /* If fin is set and we have all the data, compare and set completion flag */
  if( fin && rcvd_stream_sz == sizeof(exp_stream) ) {
    if( 0 == memcmp( exp_stream, rcvd_stream, sizeof(exp_stream) ) ) {
      fin_complete = 1;
      FD_LOG_INFO(( "Stream completed successfully - all data matches" ));
    } else {
      FD_LOG_ERR(( "Stream data mismatch!" ));
    }
  }

  return FD_QUIC_SUCCESS;
}

static void
ack_inflight( fd_quic_conn_t * client_conn, fd_quic_t * server_quic ) {
  now += server_quic->config.ack_delay;
  fd_quic_service( server_quic, now );
  for( uint j=0; j<4; j++ ) {
    FD_TEST( !fd_quic_pkt_meta_ds_ele_cnt( &client_conn->pkt_meta_tracker.sent_pkt_metas[j] ) );
  }
  fd_quic_state_t * state = fd_quic_get_state( client_conn->quic );
  FD_TEST( state->stream_pool->cur_cnt == 5UL );
}

static void
test_rtt_update( fd_quic_conn_t * client_conn, fd_quic_t * server_quic ) {
  /* grab initial RTT */
  FD_TEST( client_conn->rtt->is_rtt_valid );
  float orig_smoothed_rtt = client_conn->rtt->smoothed_rtt;
  float orig_min_rtt      = client_conn->rtt->min_rtt;
  float orig_var_rtt      = client_conn->rtt->var_rtt;

  /* double RTT and confirm it updates */
  force_rtt_measurement( client_conn, server_quic, 300L );


  float new_smoothed_rtt = client_conn->rtt->smoothed_rtt;
  float new_min_rtt      = client_conn->rtt->min_rtt;
  float new_var_rtt      = client_conn->rtt->var_rtt;

  float exp_smoothed_rtt = 7.0f/8.0f * orig_smoothed_rtt + 1.0f/8.0f * 600.0f;
  float exp_var_rtt = 3.0f/4.0f * orig_var_rtt + 1.0f/4.0f * fd_abs( exp_smoothed_rtt - 600.0f );

  FD_TEST( fd_abs( new_smoothed_rtt -  exp_smoothed_rtt ) < EPS );
  FD_TEST( fd_abs( new_var_rtt      -  exp_var_rtt      ) < EPS );
  FD_TEST(         new_min_rtt      == orig_min_rtt             );

  /* cleanup */
  ack_inflight( client_conn, server_quic );
  set_1_way_latency( TEST_DEFAULT_ONE_WAY_LATENCY );
  client_conn->rtt[0] = (fd_rtt_estimate_t){
    .is_rtt_valid = 1,
    .smoothed_rtt = TEST_DEFAULT_ONE_WAY_LATENCY,
    .latest_rtt   = TEST_DEFAULT_ONE_WAY_LATENCY,
    .var_rtt      = 0.0f,
    .min_rtt      = TEST_DEFAULT_ONE_WAY_LATENCY,
  };
  FD_LOG_NOTICE(( "test_rtt_update: pass" ));
}

static void
test_retx_pto( fd_quic_conn_t * client_conn, fd_quic_t * server_quic FD_PARAM_UNUSED ) {

  fd_quic_t * client_quic = client_conn->quic;

  { /* retx at pto timeout when no other packets */
    /* send a packet, but drop it */
    fd_quic_netem_set_drop( client_netem, 1UL );
    long send_time = now;
    send_packet( client_conn );

    /* fwd time until right before we should expire, assert no retx */
    float smoothed_rtt  = client_conn->rtt->smoothed_rtt;
    float rtt_var       = client_conn->rtt->var_rtt;
    ulong orig_retx_cnt = client_quic->metrics.pkt_retransmissions_cnt[3];

    long pto_duration = (long)( smoothed_rtt + (4.0f * rtt_var) + client_conn->peer_max_ack_delay_ns );
    long expiry_time  = send_time + pto_duration;
         now          = expiry_time-1;
    fd_quic_service( client_quic, now );
    FD_TEST( client_quic->metrics.pkt_retransmissions_cnt[3] == orig_retx_cnt );

    /* fwd time one more step until expiry, assert retx */
    now+=1;
    fd_quic_service( client_quic, now );
    FD_TEST( client_quic->metrics.pkt_retransmissions_cnt[3] == orig_retx_cnt+1 );

    /* cleanup */
    ack_inflight( client_conn, server_quic );
    FD_LOG_NOTICE(( "test_retx_pto: pass solo packet" ));
  }


  { /* retx at pto timeout when future unacked packet exists */

    /* send two packets, dropping the second */
    fd_quic_netem_set_drop( client_netem, 2UL ); /* 0b10 */
    send_packet( client_conn ); /* A */
    send_packet( client_conn ); /* B */

    /* grab original expiries */
    fd_quic_pkt_meta_tracker_t     * tracker = &client_conn->pkt_meta_tracker;
    fd_quic_pkt_meta_ds_fwd_iter_t   A_iter  = fd_quic_pkt_meta_ds_fwd_iter_init( &tracker->sent_pkt_metas[3], tracker->pool );
    fd_quic_pkt_meta_t             * A_meta  = fd_quic_pkt_meta_ds_fwd_iter_ele( A_iter, tracker->pool );
    fd_quic_pkt_meta_t             * B_meta  = fd_quic_pkt_meta_ds_fwd_iter_ele(
                                                    fd_quic_pkt_meta_ds_fwd_iter_next( A_iter, tracker->pool ),
                                                    tracker->pool ); /* B */
    long  const orig_expiry_A = A_meta->expiry;
    long  const orig_expiry_B = B_meta->expiry;
    ulong const orig_retx_cnt = client_quic->metrics.pkt_retransmissions_cnt[3];

    FD_TEST( fd_quic_get_next_wakeup( client_quic ) == orig_expiry_A );

    /* ack the first one after loss duration, should not retx B */
    long loss_duration = fd_quic_calc_expiry_duration( client_conn, 1, 0 );
    now += fd_long_max( loss_duration, server_quic->config.ack_delay );
    fd_quic_service( server_quic, now );
    FD_TEST( client_quic->metrics.pkt_retransmissions_cnt[3] == orig_retx_cnt );

    /* acks don't cancel the timer, so we should need to run that 'empty' service */
    if( fd_quic_get_next_wakeup( client_quic ) == orig_expiry_A ) {
      now = orig_expiry_A;
      fd_quic_service( client_quic, now );
      FD_TEST( client_quic->metrics.pkt_retransmissions_cnt[3] == orig_retx_cnt );
    }

    /* B's expiry should remain unchanged and we're scheduled for it */
    long const new_expiry  = B_meta->expiry;
    FD_TEST( new_expiry == orig_expiry_B );
    FD_TEST( new_expiry == fd_quic_get_next_wakeup( client_quic ) );

    /* finish retx for future tests */
    now = new_expiry;
    fd_quic_service( client_quic, now );

    /* cleanup */
    ack_inflight( client_conn, server_quic );
    FD_LOG_NOTICE(( "test_retx_pto: pass future unacked packet" ));
  }
}

static void
test_loss_time_threshold( fd_quic_conn_t * client_conn, fd_quic_t * server_quic ) {
  fd_quic_t * client_quic = client_conn->quic;

  { /* uses loss shorter time threshold when we have acked a higher packet */

    /* send two packets, drop 1st */
    fd_quic_netem_set_drop( client_netem, 1UL );
    long first_send_time = now;
    send_packet( client_conn );
    send_packet( client_conn );

    /* get original expiry time */
    fd_quic_pkt_meta_tracker_t * tracker     = &client_conn->pkt_meta_tracker;
    fd_quic_pkt_meta_t         * pkt_meta    = fd_quic_pkt_meta_min( &tracker->sent_pkt_metas[3], tracker->pool );
    long                         orig_expiry = pkt_meta->expiry;
    FD_TEST( pkt_meta->tx_time == first_send_time );

    now += server_quic->config.ack_delay;
    fd_quic_service( server_quic, now );

    /* assert retx fires when time \in (time_threshold_expiry, pkt_meta->expiry) */
    long loss_duration = (long)( 1.125f * fmaxf( client_conn->rtt->smoothed_rtt, client_conn->rtt->latest_rtt ) );
    long time_threshold_expiry = first_send_time + loss_duration;

    FD_TEST( now < time_threshold_expiry );
    FD_TEST( time_threshold_expiry < orig_expiry );

    ulong orig_retx_cnt = client_quic->metrics.pkt_retransmissions_cnt[3];
    now = time_threshold_expiry - 1;
    fd_quic_service( client_quic, now ); /* should not retx, right before */
    FD_TEST( client_quic->metrics.pkt_retransmissions_cnt[3] == orig_retx_cnt );

    now+=1;
    fd_quic_service( client_quic, now ); /* trigger the retx */
    FD_TEST( client_quic->metrics.pkt_retransmissions_cnt[3] == orig_retx_cnt+1 );

    /* cleanup */
    ack_inflight( client_conn, server_quic );
    FD_LOG_NOTICE(( "test_loss_time_threshold: pass" ));
  }
}

static void
test_loss_skip_threshold( fd_quic_conn_t * client_conn, fd_quic_t * server_quic ) {

  fd_quic_t * client_quic = client_conn->quic;

  { /* retx when 3 skipped packets */
    /* send 5 packets, drop 1st */
    fd_quic_netem_set_drop( client_netem, 1UL );
    for( uint j=0; j<5; j++ ) send_packet( client_conn );

    ulong orig_retx_cnt = client_quic->metrics.pkt_retransmissions_cnt[3];
    now += server_quic->config.ack_delay;
    fd_quic_service( server_quic, now );
    FD_TEST( client_quic->metrics.pkt_retransmissions_cnt[3] == orig_retx_cnt+1 ); /* confirm retx prepped */
    fd_quic_service( client_quic, now ); /* actually perform the retx */

    /* cleanup */
    ack_inflight( client_conn, server_quic );
    FD_LOG_NOTICE(( "test_loss_skip_threshold: pass enough skipped" ));
  }

  { /* not enough skipped to retx */
    /* send 4 packets, drop 1st */
    fd_quic_netem_set_drop( client_netem, 1UL );
    for( uint j=0; j<4; j++ ) send_packet( client_conn );

    ulong orig_retx_cnt = client_quic->metrics.pkt_retransmissions_cnt[3];
    now += server_quic->config.ack_delay;
    fd_quic_service( server_quic, now );
    FD_TEST( client_quic->metrics.pkt_retransmissions_cnt[3] == orig_retx_cnt ); /* confirm no retx */

    /* fwd to expiry for retx */
    now = fd_quic_get_next_wakeup( client_quic );
    fd_quic_service( client_quic, now );
    FD_TEST( client_quic->metrics.pkt_retransmissions_cnt[3] == orig_retx_cnt+1 );

    /* cleanup */
    ack_inflight( client_conn, server_quic );
    FD_LOG_NOTICE(( "test_loss_skip_threshold: pass not enough skipped" ));
  }
}

/* tests stream retx logic when some middle stream frag drops */
static void
test_stream_retx_multi_packet( fd_quic_conn_t * client_conn, fd_quic_t * server_quic ) {

  server_quic->cb.stream_rx  = server_stream_rx_cb; /* just for this test */

  fd_quic_t * client_quic = client_conn->quic;

  /* 1. Fill buffer with random bytes */
  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );
  for( ulong i=0; i<sizeof(exp_stream); i++ ) {
    exp_stream[i] = fd_rng_uchar( rng );
  }
  fd_memset( rcvd_stream, 0, sizeof(rcvd_stream) );
  rcvd_stream_sz = 0;
  fin_complete = 0;

  /* 2. Drop second client packet */
  fd_quic_netem_set_drop( client_netem, 2UL ); /* 0b10 */

  /* 3. Send whole buffer with fin bit */
  fd_quic_stream_t * stream = fd_quic_conn_new_stream( client_conn );
  FD_TEST( stream );
  FD_TEST( !fd_quic_stream_send( stream, exp_stream, sizeof(exp_stream), 1 ) );
  fd_quic_service( client_quic, now );

  /* 4. Service server and verify fin not complete yet (second packet was dropped) */
  now += server_quic->config.ack_delay;
  fd_quic_service( server_quic, now );
  FD_TEST( !fin_complete );

  /* 5. Jump to retx time and retx */
  now = fd_quic_get_next_wakeup( client_quic );
  fd_quic_service( client_quic, now );
  FD_TEST( fin_complete );

  /* cleanup */
  FD_LOG_NOTICE(( "test_stream_retx_multi_packet: pass" ));
}

int
main( int     argc,
      char ** argv ) {

  fd_boot          ( &argc, &argv );
  fd_quic_test_boot( &argc, &argv );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  ulong cpu_idx = fd_tile_cpu_id( fd_tile_idx() );
  if( cpu_idx>fd_shmem_cpu_cnt() ) cpu_idx = 0UL;

  char const * _page_sz = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--page-sz",   NULL, "gigantic"                   );
  ulong        numa_idx = fd_env_strip_cmdline_ulong ( &argc, &argv, "--numa-idx",  NULL, fd_shmem_numa_idx( cpu_idx ) );
  ulong        page_cnt = fd_env_strip_cmdline_ulong ( &argc, &argv, "--page-cnt",  NULL, 2UL                          );

  ulong page_sz = fd_cstr_to_shmem_page_sz( _page_sz );
  if( FD_UNLIKELY( !page_sz ) ) FD_LOG_ERR(( "unsupported --page-sz" ));

  FD_LOG_NOTICE(( "Creating workspace (--page-cnt %lu, --page-sz %s, --numa-idx %lu)", page_cnt, _page_sz, numa_idx ));
  fd_wksp_t * wksp = fd_wksp_new_anonymous( page_sz, page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  fd_quic_limits_t const server_limits = {
    .conn_cnt           = 1,
    .conn_id_cnt        = 4,
    .handshake_cnt      = 1,
    .stream_pool_cnt    = 1,
    .inflight_frame_cnt = 128,
  };
  FD_LOG_NOTICE(( "Creating server QUIC (%lu bytes)", fd_quic_footprint( &server_limits ) ));
  fd_quic_t * server_quic = fd_quic_new_anonymous( wksp, &server_limits, FD_QUIC_ROLE_SERVER, rng );
  FD_TEST( server_quic );

  fd_quic_limits_t const client_limits = {
    .conn_cnt           = 1,
    .conn_id_cnt        = 4,
    .handshake_cnt      = 1,
    .stream_id_cnt      = 5,
    .stream_pool_cnt    = 5,
    .inflight_frame_cnt = 5*16,
    .tx_buf_sz          = 4000
  };

  FD_LOG_NOTICE(( "Creating client QUIC (%lu bytes)", fd_quic_footprint( &client_limits ) ));
  fd_quic_t * client_quic = fd_quic_new_anonymous( wksp, &client_limits, FD_QUIC_ROLE_CLIENT, rng );
  FD_TEST( client_quic );

  server_quic->config.role = FD_QUIC_ROLE_SERVER;
  server_quic->cb.conn_new         = my_connection_new;

  client_quic->config.role = FD_QUIC_ROLE_CLIENT;
  client_quic->cb.conn_hs_complete = my_handshake_complete;

  server_quic->cb.conn_final = conn_final;
  client_quic->cb.conn_final = conn_final;

  server_quic->config.initial_rx_max_stream_data = 1<<15;
  client_quic->config.initial_rx_max_stream_data = 1<<15;

  FD_LOG_NOTICE(( "Creating virtual pair" ));
  fd_quic_virtual_pair_t vp;
  fd_quic_virtual_pair_init( &vp, /*a*/ client_quic, /*b*/ server_quic );

  client_netem = fd_quic_netem_init( _netem, 0.0, 0.0, &now );
  fd_quic_set_aio_net_tx( client_quic, &client_netem->local );
  client_netem->dst = vp.aio_a2b;

  server_netem = fd_quic_netem_init( _netem+1, 0.0, 0.0, &now );
  fd_quic_set_aio_net_tx( server_quic, &server_netem->local );
  server_netem->dst = vp.aio_b2a;

  set_1_way_latency( TEST_DEFAULT_ONE_WAY_LATENCY );

  FD_LOG_NOTICE(( "Initializing QUICs" ));
  FD_TEST( fd_quic_init( server_quic ) );
  FD_TEST( fd_quic_init( client_quic ) );
  fd_quic_sync_clocks( server_quic, client_quic, now );

  fd_quic_conn_t * client_conn = fd_quic_connect( client_quic, 0U, 0, 0U, 0, now );

  /* do general processing */
  for( ulong j = 0; j < 20; j++ ) {
    FD_LOG_INFO(( "running services" ));
    fd_quic_service( client_quic, now );
    fd_quic_service( server_quic, now );

    if( server_complete && client_complete ) {
      FD_LOG_INFO(( "***** both handshakes complete *****" ));
      break;
    }
  }

  FD_TEST( client_conn->state == FD_QUIC_CONN_STATE_ACTIVE );

  test_rtt_update(          client_conn, server_quic );
  test_retx_pto(            client_conn, server_quic );
  test_loss_time_threshold( client_conn, server_quic );
  test_loss_skip_threshold( client_conn, server_quic );
  test_stream_retx_multi_packet( client_conn, server_quic );
}

