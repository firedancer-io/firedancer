/* test_quic_pkt_meta_lifecycle exercises ACK processing and pkt_meta
   expiry for packets built with fd_quic_conn_tx_stream. */

#include "fd_quic_sandbox.h"
#include "../fd_quic_private.h"
#include "../fd_quic_proto.h"
#include "../fd_quic_proto.c"

#define APP_ENC_LEVEL fd_quic_enc_level_appdata_id              /* 3 */

static uint
app_pn_space( void ) {
  static uchar const el2pn_map[] = { 0, 2, 1, 2 };
  return el2pn_map[ APP_ENC_LEVEL ];
}
#define APP_PN_SPACE app_pn_space()

/* Helpers *************************************************************/

static ulong
count_pkt_metas( fd_quic_conn_t * conn,
                 uint             enc_level ) {
  fd_quic_pkt_meta_tracker_t * tracker = &conn->pkt_meta_tracker;
  return fd_quic_pkt_meta_ds_ele_cnt( &tracker->sent_pkt_metas[ enc_level ] );
}

static ulong
service_conn( fd_quic_sandbox_t * sandbox,
              fd_quic_conn_t *    conn,
              long                step_ns ) {
  fd_quic_t *       quic  = sandbox->quic;
  fd_quic_state_t * state = fd_quic_get_state( quic );
  sandbox->wallclock += step_ns;
  state->now = sandbox->wallclock;

  fd_quic_conn_service( quic, conn, sandbox->wallclock );

  ulong pkt_cnt = 0;
  while( fd_quic_sandbox_next_packet( sandbox ) ) pkt_cnt++;
  return pkt_cnt;
}

static void
inject_ack( fd_quic_sandbox_t * sandbox,
            fd_quic_conn_t *    conn,
            ulong               lo,
            ulong               hi ) {
  FD_TEST( hi>=lo );
  fd_quic_ack_frame_t ack_frame = {
    .type            = 0x02,
    .largest_ack     = hi,
    .ack_delay       = 0UL,
    .ack_range_count = 0UL,
    .first_ack_range = hi - lo,
  };
  uchar buf[64];
  ulong sz = fd_quic_encode_ack_frame( buf, sizeof(buf), &ack_frame );
  FD_TEST( sz!=FD_QUIC_ENCODE_FAIL );
  fd_quic_sandbox_send_lone_frame( sandbox, conn, buf, sz );
}

static fd_quic_conn_t *
setup_conn( fd_quic_sandbox_t * sandbox,
            fd_rng_t *          rng ) {
  fd_quic_sandbox_init( sandbox, FD_QUIC_ROLE_CLIENT );
  sandbox->quic->config.initial_rx_max_stream_data = 1UL<<15;
  sandbox->quic->config.idle_timeout               = (long)60e9;
  fd_quic_conn_t * conn = fd_quic_sandbox_new_conn_established( sandbox, rng );
  FD_TEST( conn );
  conn->tx_sup_stream_id                = 256;
  conn->tx_max_data                     = 1UL<<20;
  conn->tx_initial_max_stream_data_uni  = 1UL<<15;
  conn->idle_timeout_ns                 = (long)60e9;
  return conn;
}

static ulong
send_pings( fd_quic_sandbox_t * sandbox,
            fd_quic_conn_t *    conn,
            uint                n ) {
  fd_quic_t *       quic  = sandbox->quic;
  fd_quic_state_t * state = fd_quic_get_state( quic );
  ulong last_pkt = conn->pkt_number[ APP_PN_SPACE ];
  for( uint j=0; j<n; j++ ) {
    conn->flags          = ( conn->flags & ~FD_QUIC_CONN_FLAGS_PING_SENT ) | FD_QUIC_CONN_FLAGS_PING;
    conn->upd_pkt_number = FD_QUIC_PKT_NUM_PENDING;
    sandbox->wallclock  += (long)1e6;
    conn->svc_meta.next_timeout = sandbox->wallclock;
    fd_quic_svc_timers_schedule( state->svc_timers, conn, sandbox->wallclock );
    fd_quic_service( quic, sandbox->wallclock );
    while( fd_quic_sandbox_next_packet( sandbox ) ) {}
    last_pkt = conn->pkt_number[ APP_PN_SPACE ] - 1UL;
  }
  return last_pkt;
}

/* Advance wallclock and run pkt_meta_retry to expire outstanding
   pkt_metas.  This calls fd_quic_pkt_meta_retry directly. */
static void
expire_pkt_metas( fd_quic_sandbox_t * sandbox,
                  fd_quic_conn_t *    conn,
                  long                step_ns ) {
  fd_quic_state_t * state = fd_quic_get_state( sandbox->quic );
  sandbox->wallclock += step_ns;
  state->now = sandbox->wallclock;
  fd_quic_pkt_meta_retry( sandbox->quic, conn, 0, ~0u );
}

static ulong
stream_tx( fd_quic_conn_t * conn ) {
  uchar pkt[ 1500 ];
  uchar data[ 100 ];
  memset( data, 0xAB, sizeof(data) );
  ulong pkt_num = ULONG_MAX;
  ulong used = 0UL;
  FD_TEST( !fd_quic_conn_tx_stream( conn, pkt, sizeof(pkt), &used, FD_QUIC_STREAM_TYPE_UNI_CLIENT, data, sizeof(data), NULL ) );
  FD_TEST( fd_quic_conn_tx_stream( conn, pkt, sizeof(pkt), &used, ULONG_MAX, NULL, 0UL, &pkt_num )-1UL < ULONG_MAX-1UL );
  FD_TEST( pkt_num==conn->pkt_number[ APP_PN_SPACE ]-1UL );
  return pkt_num;
}

static __attribute__((noinline)) void
test_stream_tx_ack( fd_quic_sandbox_t * sandbox,
                    fd_rng_t *          rng ) {
  fd_quic_conn_t * conn = setup_conn( sandbox, rng );

  ulong pkt = stream_tx( conn );
  FD_TEST( count_pkt_metas( conn, APP_ENC_LEVEL )==1UL );

  inject_ack( sandbox, conn, pkt, pkt );
  service_conn( sandbox, conn, (long)1e6 );
  FD_TEST( count_pkt_metas( conn, APP_ENC_LEVEL )==0UL );

  fd_quic_state_validate( sandbox->quic );
  FD_LOG_NOTICE(( "PASS: test_stream_tx_ack" ));
}

static __attribute__((noinline)) void
test_stream_tx_lost( fd_quic_sandbox_t * sandbox,
                     fd_rng_t *          rng ) {
  fd_quic_conn_t * conn = setup_conn( sandbox, rng );

  stream_tx( conn );
  ulong pkt_next = conn->pkt_number[ APP_PN_SPACE ];
  ulong retx_cnt = sandbox->quic->metrics.pkt_retransmissions_cnt[ APP_ENC_LEVEL ];

  expire_pkt_metas( sandbox, conn, (long)5e9 );
  service_conn( sandbox, conn, (long)1e6 );
  FD_TEST( count_pkt_metas( conn, APP_ENC_LEVEL )==0UL );
  FD_TEST( conn->pkt_number[ APP_PN_SPACE ]==pkt_next );
  FD_TEST( sandbox->quic->metrics.pkt_retransmissions_cnt[ APP_ENC_LEVEL ]==retx_cnt );

  fd_quic_state_validate( sandbox->quic );
  FD_LOG_NOTICE(( "PASS: test_stream_tx_lost" ));
}

static __attribute__((noinline)) void
test_ack_with_gap( fd_quic_sandbox_t * sandbox,
                   fd_rng_t *          rng ) {
  fd_quic_conn_t * conn = setup_conn( sandbox, rng );

  ulong base_pkt = conn->pkt_number[ APP_PN_SPACE ];
  send_pings( sandbox, conn, 6 );
  ulong metas_before = count_pkt_metas( conn, APP_ENC_LEVEL );
  FD_TEST( metas_before >= 6UL );

  inject_ack( sandbox, conn, base_pkt, base_pkt+1 );
  service_conn( sandbox, conn, (long)1e6 );

  inject_ack( sandbox, conn, base_pkt+4, base_pkt+5 );
  service_conn( sandbox, conn, (long)1e6 );

  ulong metas_after = count_pkt_metas( conn, APP_ENC_LEVEL );
  FD_TEST( metas_after >= 2UL );

  fd_quic_state_validate( sandbox->quic );
  FD_LOG_NOTICE(( "PASS: test_ack_with_gap" ));
}

/* main ****************************************************************/

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_rng_t _rng[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  ulong cpu_idx = fd_tile_cpu_id( fd_tile_idx() );
  if( cpu_idx>=fd_shmem_cpu_cnt() ) cpu_idx = 0UL;

  char const * _page_sz = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",  NULL, "gigantic"                 );
  ulong        page_cnt = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt", NULL, 1UL                        );
  ulong        numa_idx = fd_env_strip_cmdline_ulong( &argc, &argv, "--numa-idx", NULL, fd_shmem_numa_idx(cpu_idx) );

  ulong page_sz = fd_cstr_to_shmem_page_sz( _page_sz );
  if( FD_UNLIKELY( !page_sz ) ) FD_LOG_ERR(( "unsupported --page-sz" ));

  fd_quic_limits_t quic_limits = {
    .conn_cnt                    =   4UL,
    .handshake_cnt               =   1UL,
    .conn_id_cnt                 =   4UL,
    .inflight_frame_cnt          = 128UL,
  };

  ulong const pkt_cnt = 128UL;
  ulong const pkt_mtu = 1500UL;

  FD_LOG_NOTICE(( "Creating workspace" ));
  fd_wksp_t * wksp = fd_wksp_new_anonymous( page_sz, page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  void * sandbox_mem = fd_wksp_alloc_laddr( wksp, fd_quic_sandbox_align(),
      fd_quic_sandbox_footprint( &quic_limits, pkt_cnt, pkt_mtu ), 1UL );

  fd_quic_sandbox_t * sandbox = fd_quic_sandbox_new( sandbox_mem, &quic_limits, pkt_cnt, pkt_mtu );
  FD_TEST( sandbox );

  test_stream_tx_ack  ( sandbox, rng );
  test_stream_tx_lost ( sandbox, rng );
  test_ack_with_gap   ( sandbox, rng );

  fd_wksp_free_laddr( fd_quic_sandbox_delete( sandbox ) );
  fd_wksp_delete_anonymous( wksp );
  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
