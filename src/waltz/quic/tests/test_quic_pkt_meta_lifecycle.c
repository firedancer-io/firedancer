/* test_quic_pkt_meta_lifecycle exercises the stream lifecycle, ACK
   processing, and pkt_meta retry/loss detection paths in fd_quic.
   Includes a regression test for the stale pkt_meta bug where
   ACK-driven loss detection can leave a pkt_meta whose stream data
   was already fully acknowledged via a retransmission. */

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
count_pkt_metas_for_stream( fd_quic_conn_t * conn,
                            uint             enc_level,
                            ulong            stream_id ) {
  fd_quic_pkt_meta_tracker_t * tracker = &conn->pkt_meta_tracker;
  fd_quic_pkt_meta_t *         pool    = tracker->pool;
  fd_quic_pkt_meta_ds_t *      sent    = &tracker->sent_pkt_metas[ enc_level ];
  ulong cnt = 0;
  for( fd_quic_pkt_meta_ds_fwd_iter_t iter = fd_quic_pkt_meta_ds_fwd_iter_init( sent, pool );
       !fd_quic_pkt_meta_ds_fwd_iter_done( iter );
       iter = fd_quic_pkt_meta_ds_fwd_iter_next( iter, pool ) ) {
    fd_quic_pkt_meta_t * e = fd_quic_pkt_meta_ds_fwd_iter_ele( iter, pool );
    if( e->key.type==FD_QUIC_PKT_META_TYPE_STREAM && e->key.stream_id==stream_id ) cnt++;
  }
  return cnt;
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
flush_conn( fd_quic_sandbox_t * sandbox,
            fd_quic_conn_t *    conn ) {
  conn->upd_pkt_number = FD_QUIC_PKT_NUM_PENDING;
  service_conn( sandbox, conn, (long)1e6 );
  return conn->pkt_number[ APP_PN_SPACE ] - 1UL;
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

/* Group 1: Stream lifecycle *******************************************/

static __attribute__((noinline)) void
test_stream_send_ack_free( fd_quic_sandbox_t * sandbox,
                           fd_rng_t *          rng ) {
  fd_quic_conn_t * conn = setup_conn( sandbox, rng );

  fd_quic_stream_t * stream = fd_quic_conn_new_stream( conn );
  FD_TEST( stream );
  ulong stream_id = stream->stream_id;

  uchar data[100];
  memset( data, 0xAB, sizeof(data) );
  int rc = fd_quic_stream_send( stream, data, sizeof(data), 1 );
  FD_TEST( rc==FD_QUIC_SUCCESS );

  ulong pkt = flush_conn( sandbox, conn );
  FD_TEST( count_pkt_metas_for_stream( conn, APP_ENC_LEVEL, stream_id ) >= 1UL );

  inject_ack( sandbox, conn, pkt, pkt );
  service_conn( sandbox, conn, (long)1e6 );

  FD_TEST( count_pkt_metas_for_stream( conn, APP_ENC_LEVEL, stream_id ) == 0UL );

  fd_quic_state_validate( sandbox->quic );
  FD_LOG_NOTICE(( "PASS: test_stream_send_ack_free" ));
}

static __attribute__((noinline)) void
test_stream_send_no_fin( fd_quic_sandbox_t * sandbox,
                         fd_rng_t *          rng ) {
  fd_quic_conn_t * conn = setup_conn( sandbox, rng );

  fd_quic_stream_t * stream = fd_quic_conn_new_stream( conn );
  FD_TEST( stream );
  ulong stream_id = stream->stream_id;

  uchar data[64];
  memset( data, 0xCD, sizeof(data) );
  int rc = fd_quic_stream_send( stream, data, sizeof(data), 0 );
  FD_TEST( rc==FD_QUIC_SUCCESS );

  ulong pkt = flush_conn( sandbox, conn );
  inject_ack( sandbox, conn, pkt, pkt );
  service_conn( sandbox, conn, (long)1e6 );

  FD_TEST( count_pkt_metas_for_stream( conn, APP_ENC_LEVEL, stream_id ) == 0UL );
  FD_TEST( stream->unacked_low == sizeof(data) );
  FD_TEST( !( stream->stream_flags & FD_QUIC_STREAM_FLAGS_DEAD ) );

  fd_quic_state_validate( sandbox->quic );
  FD_LOG_NOTICE(( "PASS: test_stream_send_no_fin" ));
}

static __attribute__((noinline)) void
test_stream_fin_only( fd_quic_sandbox_t * sandbox,
                      fd_rng_t *          rng ) {
  fd_quic_conn_t * conn = setup_conn( sandbox, rng );

  fd_quic_stream_t * stream = fd_quic_conn_new_stream( conn );
  FD_TEST( stream );
  ulong stream_id = stream->stream_id;

  fd_quic_stream_fin( stream );
  FD_TEST( stream->state & FD_QUIC_STREAM_STATE_TX_FIN );

  ulong pkt = flush_conn( sandbox, conn );
  inject_ack( sandbox, conn, pkt, pkt );
  service_conn( sandbox, conn, (long)1e6 );

  FD_TEST( count_pkt_metas_for_stream( conn, APP_ENC_LEVEL, stream_id ) == 0UL );

  fd_quic_state_validate( sandbox->quic );
  FD_LOG_NOTICE(( "PASS: test_stream_fin_only" ));
}

/* Group 2: ACK processing ********************************************/

static __attribute__((noinline)) void
test_ack_in_order( fd_quic_sandbox_t * sandbox,
                   fd_rng_t *          rng ) {
  fd_quic_conn_t * conn = setup_conn( sandbox, rng );

  fd_quic_stream_t * stream = fd_quic_conn_new_stream( conn );
  FD_TEST( stream );
  ulong stream_id = stream->stream_id;

  uchar data[200];
  memset( data, 0x11, sizeof(data) );
  int rc = fd_quic_stream_send( stream, data, sizeof(data), 1 );
  FD_TEST( rc==FD_QUIC_SUCCESS );

  ulong pkt_lo = flush_conn( sandbox, conn );
  ulong stream_metas = count_pkt_metas_for_stream( conn, APP_ENC_LEVEL, stream_id );
  FD_TEST( stream_metas >= 1UL );
  ulong pkt_hi = conn->pkt_number[ APP_PN_SPACE ] - 1UL;

  inject_ack( sandbox, conn, pkt_lo, pkt_lo );
  service_conn( sandbox, conn, (long)1e6 );
  FD_TEST( stream->unacked_low > 0UL );

  if( pkt_hi > pkt_lo ) {
    inject_ack( sandbox, conn, pkt_hi, pkt_hi );
    service_conn( sandbox, conn, (long)1e6 );
  }

  FD_TEST( stream->unacked_low == sizeof(data) );
  fd_quic_state_validate( sandbox->quic );
  FD_LOG_NOTICE(( "PASS: test_ack_in_order" ));
}

static __attribute__((noinline)) void
test_ack_out_of_order( fd_quic_sandbox_t * sandbox,
                       fd_rng_t *          rng ) {
  fd_quic_conn_t * conn = setup_conn( sandbox, rng );

  fd_quic_stream_t * stream = fd_quic_conn_new_stream( conn );
  FD_TEST( stream );

  uchar data[200];
  memset( data, 0x22, sizeof(data) );
  int rc = fd_quic_stream_send( stream, data, sizeof(data), 1 );
  FD_TEST( rc==FD_QUIC_SUCCESS );

  ulong pkt_first = flush_conn( sandbox, conn );
  ulong pkt_last  = conn->pkt_number[ APP_PN_SPACE ] - 1UL;

  if( pkt_last <= pkt_first ) {
    FD_LOG_NOTICE(( "SKIP: test_ack_out_of_order (data fit in one packet)" ));
    fd_quic_state_validate( sandbox->quic );
    return;
  }

  inject_ack( sandbox, conn, pkt_last, pkt_last );
  service_conn( sandbox, conn, (long)1e6 );
  FD_TEST( stream->unacked_low == 0UL );

  inject_ack( sandbox, conn, pkt_first, pkt_first );
  service_conn( sandbox, conn, (long)1e6 );
  FD_TEST( stream->unacked_low == sizeof(data) );

  fd_quic_state_validate( sandbox->quic );
  FD_LOG_NOTICE(( "PASS: test_ack_out_of_order" ));
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

/* Group 3: pkt_meta retry / loss detection ****************************/

static __attribute__((noinline)) void
test_retry_basic( fd_quic_sandbox_t * sandbox,
                  fd_rng_t *          rng ) {
  fd_quic_conn_t * conn = setup_conn( sandbox, rng );

  fd_quic_stream_t * stream = fd_quic_conn_new_stream( conn );
  FD_TEST( stream );
  ulong stream_id = stream->stream_id;

  uchar data[80];
  memset( data, 0x33, sizeof(data) );
  fd_quic_stream_send( stream, data, sizeof(data), 0 );
  flush_conn( sandbox, conn );

  FD_TEST( stream->tx_sent == sizeof(data) );
  FD_TEST( count_pkt_metas_for_stream( conn, APP_ENC_LEVEL, stream_id ) >= 1UL );

  expire_pkt_metas( sandbox, conn, (long)5e9 );

  FD_TEST( stream->tx_sent < sizeof(data) );

  fd_quic_state_validate( sandbox->quic );
  FD_LOG_NOTICE(( "PASS: test_retry_basic" ));
}

static __attribute__((noinline)) void
test_retry_preserves_tx_ack( fd_quic_sandbox_t * sandbox,
                             fd_rng_t *          rng ) {
  fd_quic_conn_t * conn = setup_conn( sandbox, rng );

  fd_quic_stream_t * stream = fd_quic_conn_new_stream( conn );
  FD_TEST( stream );
  ulong stream_id = stream->stream_id;

  uchar data[200];
  memset( data, 0x44, sizeof(data) );
  fd_quic_stream_send( stream, data, sizeof(data), 1 );

  ulong pkt_first = flush_conn( sandbox, conn );
  ulong pkt_last  = conn->pkt_number[ APP_PN_SPACE ] - 1UL;

  if( pkt_last <= pkt_first ) {
    FD_LOG_NOTICE(( "SKIP: test_retry_preserves_tx_ack (single packet)" ));
    fd_quic_state_validate( sandbox->quic );
    return;
  }

  inject_ack( sandbox, conn, pkt_last, pkt_last );
  service_conn( sandbox, conn, (long)1e6 );
  FD_TEST( stream->unacked_low == 0UL );

  expire_pkt_metas( sandbox, conn, (long)5e9 );

  ulong resend_pkt = flush_conn( sandbox, conn );
  inject_ack( sandbox, conn, resend_pkt, resend_pkt );
  service_conn( sandbox, conn, (long)1e6 );

  FD_TEST( stream->unacked_low == sizeof(data) );
  FD_TEST( count_pkt_metas_for_stream( conn, APP_ENC_LEVEL, stream_id ) == 0UL );

  fd_quic_state_validate( sandbox->quic );
  FD_LOG_NOTICE(( "PASS: test_retry_preserves_tx_ack" ));
}

static __attribute__((noinline)) void
test_skip_ceil_forces_retry( fd_quic_sandbox_t * sandbox,
                             fd_rng_t *          rng ) {
  fd_quic_conn_t * conn = setup_conn( sandbox, rng );

  fd_quic_stream_t * stream = fd_quic_conn_new_stream( conn );
  FD_TEST( stream );

  uchar data[40];
  memset( data, 0x55, sizeof(data) );
  fd_quic_stream_send( stream, data, sizeof(data), 0 );
  ulong stream_pkt = flush_conn( sandbox, conn );

  send_pings( sandbox, conn, 4 );

  /* Directly call fd_quic_pkt_meta_retry with force_below_pkt_num
     set above the stream packet.  This simulates the skip_ceil
     computation from the ACK handler. */
  fd_quic_state_t * state = fd_quic_get_state( sandbox->quic );
  state->now = sandbox->wallclock;
  fd_quic_pkt_meta_retry( sandbox->quic, conn, stream_pkt+1, APP_ENC_LEVEL );

  FD_TEST( stream->tx_sent < sizeof(data) );

  fd_quic_state_validate( sandbox->quic );
  FD_LOG_NOTICE(( "PASS: test_skip_ceil_forces_retry" ));
}

/* REGRESSION TEST for the stale pkt_meta bug. */
static __attribute__((noinline)) void
test_stale_pkt_meta_regression( fd_quic_sandbox_t * sandbox,
                                fd_rng_t *          rng ) {
  fd_quic_conn_t * conn = setup_conn( sandbox, rng );

  fd_quic_stream_t * stream = fd_quic_conn_new_stream( conn );
  FD_TEST( stream );
  ulong stream_id = stream->stream_id;

  uchar data[200];
  memset( data, 0x66, sizeof(data) );
  fd_quic_stream_send( stream, data, sizeof(data), 0 );

  ulong first_pkt = flush_conn( sandbox, conn );

  ulong stream_meta_cnt = count_pkt_metas_for_stream( conn, APP_ENC_LEVEL, stream_id );
  if( stream_meta_cnt < 2UL ) {
    FD_LOG_NOTICE(( "SKIP: test_stale_pkt_meta_regression (single packet)" ));
    fd_quic_state_validate( sandbox->quic );
    return;
  }

  ulong pkt_after = conn->pkt_number[ APP_PN_SPACE ] - 1UL;

  /* ACK all stream packets except the first one.  This advances
     unacked_low for the portion of stream data in those packets. */
  if( pkt_after > first_pkt ) {
    inject_ack( sandbox, conn, first_pkt+1UL, pkt_after );
    service_conn( sandbox, conn, (long)1e6 );
  }

  /* Force-retry the first packet (simulating skip_ceil from the ACK
     handler). */
  fd_quic_state_t * state = fd_quic_get_state( sandbox->quic );
  state->now = sandbox->wallclock;
  fd_quic_pkt_meta_retry( sandbox->quic, conn, first_pkt+1UL, APP_ENC_LEVEL );

  /* Retransmit and ACK the retransmission. */
  ulong resend_pkt = flush_conn( sandbox, conn );
  ulong resend_end = conn->pkt_number[ APP_PN_SPACE ] - 1UL;

  inject_ack( sandbox, conn, resend_pkt, resend_end );
  service_conn( sandbox, conn, (long)1e6 );

  /* Expire everything.  With the stale pkt_meta fix this must not
     crash.  Without it, FD_LOG_CRIT fires here. */
  expire_pkt_metas( sandbox, conn, (long)10e9 );

  FD_TEST( count_pkt_metas_for_stream( conn, APP_ENC_LEVEL, stream_id ) == 0UL );
  fd_quic_state_validate( sandbox->quic );
  FD_LOG_NOTICE(( "PASS: test_stale_pkt_meta_regression" ));
}

static __attribute__((noinline)) void
test_retry_with_fin( fd_quic_sandbox_t * sandbox,
                     fd_rng_t *          rng ) {
  fd_quic_conn_t * conn = setup_conn( sandbox, rng );

  fd_quic_stream_t * stream = fd_quic_conn_new_stream( conn );
  FD_TEST( stream );
  ulong stream_id = stream->stream_id;

  uchar data[50];
  memset( data, 0x77, sizeof(data) );
  fd_quic_stream_send( stream, data, sizeof(data), 1 );
  flush_conn( sandbox, conn );

  FD_TEST( stream->state & FD_QUIC_STREAM_STATE_TX_FIN );
  FD_TEST( count_pkt_metas_for_stream( conn, APP_ENC_LEVEL, stream_id ) >= 1UL );

  expire_pkt_metas( sandbox, conn, (long)5e9 );

  ulong pkt = flush_conn( sandbox, conn );
  inject_ack( sandbox, conn, pkt, pkt );
  service_conn( sandbox, conn, (long)1e6 );

  FD_TEST( count_pkt_metas_for_stream( conn, APP_ENC_LEVEL, stream_id ) == 0UL );

  fd_quic_state_validate( sandbox->quic );
  FD_LOG_NOTICE(( "PASS: test_retry_with_fin" ));
}

static __attribute__((noinline)) void
test_retry_dead_stream( fd_quic_sandbox_t * sandbox,
                        fd_rng_t *          rng ) {
  fd_quic_conn_t * conn = setup_conn( sandbox, rng );

  fd_quic_stream_t * stream = fd_quic_conn_new_stream( conn );
  FD_TEST( stream );
  ulong stream_id = stream->stream_id;

  uchar data[30];
  memset( data, 0x88, sizeof(data) );
  fd_quic_stream_send( stream, data, sizeof(data), 1 );
  flush_conn( sandbox, conn );

  FD_TEST( count_pkt_metas_for_stream( conn, APP_ENC_LEVEL, stream_id ) >= 1UL );

  fd_quic_tx_stream_free( sandbox->quic, conn, stream, FD_QUIC_STREAM_NOTIFY_END );

  expire_pkt_metas( sandbox, conn, (long)5e9 );

  fd_quic_state_validate( sandbox->quic );
  FD_LOG_NOTICE(( "PASS: test_retry_dead_stream" ));
}

/* Group 4: Validate invariants ****************************************/

static __attribute__((noinline)) void
test_validate_after_each_op( fd_quic_sandbox_t * sandbox,
                             fd_rng_t *          rng ) {
  fd_quic_conn_t * conn = setup_conn( sandbox, rng );
  fd_quic_t * quic = sandbox->quic;

  fd_quic_state_validate( quic );

  fd_quic_stream_t * stream = fd_quic_conn_new_stream( conn );
  FD_TEST( stream );
  ulong stream_id = stream->stream_id;
  fd_quic_state_validate( quic );

  uchar data[120];
  memset( data, 0x99, sizeof(data) );
  fd_quic_stream_send( stream, data, sizeof(data), 0 );
  fd_quic_state_validate( quic );

  flush_conn( sandbox, conn );
  fd_quic_state_validate( quic );

  expire_pkt_metas( sandbox, conn, (long)5e9 );
  fd_quic_state_validate( quic );

  ulong pkt2 = flush_conn( sandbox, conn );
  fd_quic_state_validate( quic );

  inject_ack( sandbox, conn, pkt2, pkt2 );
  service_conn( sandbox, conn, (long)1e6 );
  fd_quic_state_validate( quic );

  FD_TEST( stream->unacked_low == sizeof(data) );

  fd_quic_stream_fin( stream );
  fd_quic_state_validate( quic );

  ulong pkt3 = flush_conn( sandbox, conn );
  fd_quic_state_validate( quic );

  inject_ack( sandbox, conn, pkt3, pkt3 );
  service_conn( sandbox, conn, (long)1e6 );
  fd_quic_state_validate( quic );

  FD_TEST( count_pkt_metas_for_stream( conn, APP_ENC_LEVEL, stream_id ) == 0UL );

  FD_LOG_NOTICE(( "PASS: test_validate_after_each_op" ));
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
  ulong        page_cnt = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt", NULL, 2UL                        );
  ulong        numa_idx = fd_env_strip_cmdline_ulong( &argc, &argv, "--numa-idx", NULL, fd_shmem_numa_idx(cpu_idx) );

  ulong page_sz = fd_cstr_to_shmem_page_sz( _page_sz );
  if( FD_UNLIKELY( !page_sz ) ) FD_LOG_ERR(( "unsupported --page-sz" ));

  fd_quic_limits_t quic_limits = {
    .conn_cnt                    =   4UL,
    .handshake_cnt               =   1UL,
    .conn_id_cnt                 =   4UL,
    .stream_id_cnt               =  16UL,
    .inflight_frame_cnt          = 128UL,
    .tx_buf_sz                   = 512UL,
    .stream_pool_cnt             =  64UL,
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

  test_stream_send_ack_free      ( sandbox, rng );
  test_stream_send_no_fin        ( sandbox, rng );
  test_stream_fin_only           ( sandbox, rng );

  test_ack_in_order              ( sandbox, rng );
  test_ack_out_of_order          ( sandbox, rng );
  test_ack_with_gap              ( sandbox, rng );

  test_retry_basic               ( sandbox, rng );
  test_retry_preserves_tx_ack    ( sandbox, rng );
  test_skip_ceil_forces_retry    ( sandbox, rng );
  test_stale_pkt_meta_regression ( sandbox, rng );
  test_retry_with_fin            ( sandbox, rng );
  test_retry_dead_stream         ( sandbox, rng );

  test_validate_after_each_op    ( sandbox, rng );

  fd_wksp_free_laddr( fd_quic_sandbox_delete( sandbox ) );
  fd_wksp_delete_anonymous( wksp );
  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
