#include "../fd_quic.h"
#include "fd_quic_test_helpers.h"

int server_complete = 0;
int client_complete = 0;

ulong now = 0UL;

#define TEST_DEFAULT_ONE_WAY_LATENCY 150

#define EPS 0.0001f

char msg[] = "Hello world!\x00-   ";

/* server connection received in callback */
fd_quic_conn_t * server_conn = NULL;

fd_quic_netem_t _netem[2];
fd_quic_netem_t * client_netem;
fd_quic_netem_t * server_netem;

static void
set_1_way_latency( ulong latency ) {
  fd_quic_netem_set_one_way_latency( client_netem, latency );
  fd_quic_netem_set_one_way_latency( server_netem, latency );
}

static void
send_packet( fd_quic_conn_t * client_conn ) {
  fd_quic_t * client_quic = client_conn->quic;
  fd_quic_stream_t * client_stream = fd_quic_conn_new_stream( client_conn );
  FD_TEST( client_stream );
  FD_TEST( !fd_quic_stream_send( client_stream, msg, sizeof(msg), 1 ) );
  fd_quic_service( client_quic );
}

static void
force_rtt_measurement( fd_quic_conn_t * client_conn, fd_quic_t * server_quic, ulong one_way_latency ) {
  set_1_way_latency( one_way_latency );
  send_packet( client_conn );
  now += server_quic->config.ack_delay;
  fd_quic_service( server_quic );
}

ulong
fd_quic_now( void * context FD_PARAM_UNUSED ) {
  return now;
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

static void
test_rtt_update( fd_quic_conn_t * client_conn, fd_quic_t * server_quic ) {

  fd_quic_stream_t * client_stream = fd_quic_conn_new_stream( client_conn );
  FD_TEST( client_stream );

  /* grab initial RTT */
  FD_TEST( client_conn->rtt->is_rtt_valid );
  float orig_smoothed_rtt = client_conn->rtt->smoothed_rtt;
  float orig_min_rtt      = client_conn->rtt->min_rtt;
  float orig_var_rtt      = client_conn->rtt->var_rtt;

  /* double RTT and confirm it updates */
  force_rtt_measurement( client_conn, server_quic, 300 );

  float new_smoothed_rtt = client_conn->rtt->smoothed_rtt;
  float new_min_rtt      = client_conn->rtt->min_rtt;
  float new_var_rtt      = client_conn->rtt->var_rtt;

  float exp_smoothed_rtt = 7.0f/8.0f * orig_smoothed_rtt + 1.0f/8.0f * 600.0f;
  float exp_var_rtt = 3.0f/4.0f * orig_var_rtt + 1.0f/4.0f * fd_abs( exp_smoothed_rtt - 600.0f );

  FD_TEST( fd_abs( new_smoothed_rtt - exp_smoothed_rtt ) < EPS );
  FD_TEST( fd_abs( new_var_rtt      - exp_var_rtt      ) < EPS );
  FD_TEST( new_min_rtt      == orig_min_rtt      );
}

static void
test_retx_expiry( fd_quic_conn_t * client_conn, fd_quic_t * server_quic ) {

  fd_quic_t * client_quic = client_conn->quic;

  /* Make rtt measurement huge */
  force_rtt_measurement( client_conn, server_quic, 30000 );

  /* reset latency to default */
  set_1_way_latency( TEST_DEFAULT_ONE_WAY_LATENCY );

  /* send a packet, but drop it */
  fd_quic_netem_set_drop( client_netem, 1UL );
  send_packet( client_conn );

  /* fwd time until right before we should expire, assert no retx */
  float smoothed_rtt  = client_conn->rtt->smoothed_rtt;
  float rtt_var       = client_conn->rtt->var_rtt;
  ulong orig_retx_cnt = client_quic->metrics.pkt_retx_cnt[3];

  ulong pto_duration = (ulong)( smoothed_rtt + (4.0f * rtt_var) + client_conn->peer_max_ack_delay_ticks );
  ulong expiry_time  = now + pto_duration - TEST_DEFAULT_ONE_WAY_LATENCY;
        now          = expiry_time-1;
  fd_quic_service( client_quic );
  FD_TEST( client_quic->metrics.pkt_retx_cnt[3] == orig_retx_cnt );

  /* fwd time one more step until expiry, assert retx */
  now+=1;
  fd_quic_service( client_quic );
  FD_TEST( client_quic->metrics.pkt_retx_cnt[3] == orig_retx_cnt+1 );

  /* let server ack, to clear pkt_meta */
  now += server_quic->config.ack_delay;
  fd_quic_service( server_quic );
}

static void
test_time_threshold( fd_quic_conn_t * client_conn, fd_quic_t * server_quic ) {
  fd_quic_t * client_quic = client_conn->quic;

  /* send two packets, drop 1st */
  fd_quic_netem_set_drop( client_netem, 1UL );
  set_1_way_latency( TEST_DEFAULT_ONE_WAY_LATENCY );
  ulong first_send_time = now;
  send_packet( client_conn );
  send_packet( client_conn );

  /* get original expiry time */
  fd_quic_pkt_meta_tracker_t * tracker = &client_conn->pkt_meta_tracker;
  fd_quic_pkt_meta_t * pkt_meta = fd_quic_pkt_meta_min( &tracker->sent_pkt_metas[3], tracker->pool );
  ulong orig_expiry_time = pkt_meta->expiry;
  FD_TEST( pkt_meta->tx_time == first_send_time );

  now += server_quic->config.ack_delay;
  fd_quic_service( server_quic );

  /* assert retx fires when time \in (time_threshold_expiry, pkt_meta->expiry) */
  ulong loss_duration = (ulong)( 1.125f * fmaxf( client_conn->rtt->smoothed_rtt, client_conn->rtt->latest_rtt ) );
  ulong time_threshold_expiry = first_send_time + loss_duration;

  FD_TEST( now < time_threshold_expiry );
  FD_TEST( time_threshold_expiry < orig_expiry_time );

  ulong orig_retx_cnt = client_quic->metrics.pkt_retx_cnt[3];
  now = time_threshold_expiry - 1;
  fd_quic_service( client_quic );

  FD_TEST( client_quic->metrics.pkt_retx_cnt[3] == orig_retx_cnt );

  now+=1;
  fd_quic_service( client_quic );
  FD_TEST( client_quic->metrics.pkt_retx_cnt[3] == orig_retx_cnt+1 );
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
    .tx_buf_sz          = 1024
  };

  FD_LOG_NOTICE(( "Creating client QUIC (%lu bytes)", fd_quic_footprint( &client_limits ) ));
  fd_quic_t * client_quic = fd_quic_new_anonymous( wksp, &client_limits, FD_QUIC_ROLE_CLIENT, rng );
  FD_TEST( client_quic );

  server_quic->config.role = FD_QUIC_ROLE_SERVER;
  server_quic->cb.conn_new         = my_connection_new;

  client_quic->config.role = FD_QUIC_ROLE_CLIENT;
  client_quic->cb.conn_hs_complete = my_handshake_complete;

  server_quic->cb.now = fd_quic_now;
  client_quic->cb.now = fd_quic_now;

  server_quic->cb.conn_final = conn_final;
  client_quic->cb.conn_final = conn_final;

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
  fd_quic_set_clock( server_quic, fd_quic_now, NULL, 1.0 );
  fd_quic_set_clock( client_quic, fd_quic_now, NULL, 1.0 );
  FD_TEST( fd_quic_init( server_quic ) );
  FD_TEST( fd_quic_init( client_quic ) );

  fd_quic_conn_t * client_conn = fd_quic_connect( client_quic, 0U, 0, 0U, 0 );

  /* do general processing */
  for( ulong j = 0; j < 20; j++ ) {
    FD_LOG_INFO(( "running services" ));
    fd_quic_service( client_quic );;
    fd_quic_service( server_quic );;

    if( server_complete && client_complete ) {
      FD_LOG_INFO(( "***** both handshakes complete *****" ));
      break;
    }
  }

  FD_TEST( client_conn->state == FD_QUIC_CONN_STATE_ACTIVE );

  test_rtt_update(     client_conn, server_quic );
  test_retx_expiry(    client_conn, server_quic );
  test_time_threshold( client_conn, server_quic );
}

