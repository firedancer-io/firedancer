/* test_quic_conformance verifies that fd_quic adheres to various
   assertions made in the QUIC specification (RFC 9000). */

#include "fd_quic_sandbox.h"
#include "../fd_quic_proto.h"
#include "../fd_quic_private.h"

/* RFC 9000 Section 4.1. Data Flow Control

   > A receiver MUST close the connection with an error of type
   > FLOW_CONTROL_ERROR if the sender violates the advertised connection
   > or stream data limits */

static __attribute__ ((noinline)) void
test_quic_stream_data_limit_enforcement( fd_quic_sandbox_t * sandbox,
                                         fd_rng_t *          rng ) {

  fd_quic_sandbox_init( sandbox, FD_QUIC_ROLE_SERVER );
  sandbox->quic->config.initial_rx_max_stream_data = 1UL;
  fd_quic_conn_t * conn = fd_quic_sandbox_new_conn_established( sandbox, rng );
  conn->rx_sup_stream_id = (2UL<<2) + FD_QUIC_STREAM_TYPE_UNI_CLIENT;

  uchar buf[ 1024 ];
  fd_quic_stream_frame_t stream_frame =
    { .stream_id  = FD_QUIC_STREAM_TYPE_UNI_CLIENT,
      .fin_opt    = 1,
      .length_opt = 2,
      .length     = 2UL };
  ulong sz = fd_quic_encode_stream_frame( buf, sizeof(buf), &stream_frame );
  FD_TEST( sz!=FD_QUIC_ENCODE_FAIL );
  memset( buf+sz, '0', 2 );
  sz += 2;

  fd_quic_sandbox_send_lone_frame( sandbox, conn, buf, sz );
  FD_TEST( conn->state  == FD_QUIC_CONN_STATE_ABORT );
  FD_TEST( conn->reason == FD_QUIC_CONN_REASON_FLOW_CONTROL_ERROR );
}

/* RFC 9000 Section 4.6. Controlling Concurrency

   > Endpoints MUST NOT exceed the limit set by their peer. An endpoint
   > that receives a frame with a stream ID exceeding the limit it has
   > sent MUST treat this as a connection error of type
   > STREAM_LIMIT_ERROR */

static __attribute__ ((noinline)) void
test_quic_stream_limit_enforcement( fd_quic_sandbox_t * sandbox,
                                    fd_rng_t *          rng ) {

  fd_quic_sandbox_init( sandbox, FD_QUIC_ROLE_SERVER );
  fd_quic_conn_t * conn = fd_quic_sandbox_new_conn_established( sandbox, rng );
  conn->rx_sup_stream_id = 0UL + FD_QUIC_STREAM_TYPE_UNI_CLIENT;

  uchar buf[ 1024 ];
  fd_quic_stream_frame_t stream_frame =
    { .stream_id = FD_QUIC_STREAM_TYPE_UNI_CLIENT,
      .fin_opt   = 1 };
  ulong sz = fd_quic_encode_stream_frame( buf, sizeof(buf), &stream_frame );
  FD_TEST( sz!=FD_QUIC_ENCODE_FAIL );

  fd_quic_sandbox_send_lone_frame( sandbox, conn, buf, sz );
  FD_TEST( conn->state  == FD_QUIC_CONN_STATE_ABORT );
  FD_TEST( conn->reason == FD_QUIC_CONN_REASON_STREAM_LIMIT_ERROR );
}

/* Ensure that worst-case stream pool allocations are bounded.

   This is a custom protocol restriction that goes beyond QUIC's limits. */

static __attribute__ ((noinline)) void
test_quic_stream_concurrency( fd_quic_sandbox_t * sandbox,
                              fd_rng_t *          rng ) {

  fd_quic_sandbox_init( sandbox, FD_QUIC_ROLE_SERVER );
  fd_quic_conn_t * conn = fd_quic_sandbox_new_conn_established( sandbox, rng );
  conn->rx_sup_stream_id = (1024UL<<2) + FD_QUIC_STREAM_TYPE_UNI_CLIENT;

  // ulong const max_streams = 32UL;

  /* Each frame initiates a new stream without closing it */
  for( ulong j=0UL; j<512UL; j++ ) {
    uchar buf[ 1024 ];
    fd_quic_stream_frame_t stream_frame =
      { .stream_id  = FD_QUIC_STREAM_TYPE_UNI_CLIENT,
        .length_opt = 1,
        .length     = 1UL };
    ulong sz = fd_quic_encode_stream_frame( buf, sizeof(buf), &stream_frame );
    FD_TEST( sz!=FD_QUIC_ENCODE_FAIL );
    buf[ sz++ ] = '0';
    fd_quic_sandbox_send_lone_frame( sandbox, conn, buf, sz );
    FD_TEST( conn->state == FD_QUIC_CONN_STATE_ACTIVE );
  }

}

/* - Ensure that a high stream ID prunes low stream IDs
   - Ensure that pruned low stream IDs are not received multiple times */

static __attribute__((noinline)) void
test_quic_stream_skip( fd_quic_sandbox_t * sandbox,
                       fd_rng_t *          rng ) {

  fd_quic_sandbox_init( sandbox, FD_QUIC_ROLE_SERVER );
  fd_quic_conn_t * conn = fd_quic_sandbox_new_conn_established( sandbox, rng );
  conn->rx_sup_stream_id = (1024UL<<2) + FD_QUIC_STREAM_TYPE_UNI_CLIENT;

  /* Fill the current stream window with unfinished streams */
  ulong window_cnt = sandbox->quic->limits.rx_stream_cnt;
  for( ulong j=0UL; j<window_cnt; j++ ) {
    uchar buf[ 64 ];
    fd_quic_stream_frame_t stream_frame =
      { .stream_id  = (j<<2) + FD_QUIC_STREAM_TYPE_UNI_CLIENT,
        .length_opt = 1,
        .length     = 1UL };
    ulong sz = fd_quic_encode_stream_frame( buf, sizeof(buf), &stream_frame );
    FD_TEST( sz!=FD_QUIC_ENCODE_FAIL );
    buf[ sz++ ] = '0';
    fd_quic_sandbox_send_lone_frame( sandbox, conn, buf, sz );
    FD_TEST( conn->state == FD_QUIC_CONN_STATE_ACTIVE );
  }
  FD_TEST( sandbox->quic->metrics.stream_opened_cnt   == window_cnt );
  FD_TEST( sandbox->quic->metrics.stream_closed_cnt   == 0UL        );
  FD_TEST( sandbox->quic->metrics.stream_rx_event_cnt == window_cnt );
  FD_TEST( sandbox->quic->metrics.stream_active_cnt   == window_cnt );

  /* Send one more stream frame without a gap.  This moves the stream
     receive window one up.  The oldest stream thereby drops below the
     window and gets aborted. */
  do {
    uchar buf[ 64 ];
    fd_quic_stream_frame_t stream_frame =
      { .stream_id  = (window_cnt<<2) + FD_QUIC_STREAM_TYPE_UNI_CLIENT,
        .length_opt = 1,
        .length     = 1UL };
    ulong sz = fd_quic_encode_stream_frame( buf, sizeof(buf), &stream_frame );
    FD_TEST( sz!=FD_QUIC_ENCODE_FAIL );
    buf[ sz++ ] = '0';
    fd_quic_sandbox_send_lone_frame( sandbox, conn, buf, sz );
    FD_TEST( conn->state == FD_QUIC_CONN_STATE_ACTIVE );
  } while(0);
  FD_TEST( sandbox->quic->metrics.stream_opened_cnt   == window_cnt+1UL );
  FD_TEST( sandbox->quic->metrics.stream_closed_cnt   ==            1UL );
  FD_TEST( sandbox->quic->metrics.stream_rx_event_cnt == window_cnt+1UL );
  FD_TEST( sandbox->quic->metrics.stream_active_cnt   == window_cnt     );

  /* Send data on a closed stream.  Frame should be ignored */
  do {
    uchar buf[ 64 ];
    fd_quic_stream_frame_t stream_frame =
      { .stream_id  = FD_QUIC_STREAM_TYPE_UNI_CLIENT,
        .length_opt = 1,
        .length     = 1UL,
        .offset_opt = 1,
        .offset     = 1UL,
        .fin_opt    = 1 };
    ulong sz = fd_quic_encode_stream_frame( buf, sizeof(buf), &stream_frame );
    FD_TEST( sz!=FD_QUIC_ENCODE_FAIL );
    buf[ sz++ ] = '0';
    fd_quic_sandbox_send_lone_frame( sandbox, conn, buf, sz );
    FD_TEST( conn->state == FD_QUIC_CONN_STATE_ACTIVE );
  } while(0);
  FD_TEST( sandbox->quic->metrics.stream_opened_cnt   == window_cnt+1UL );
  FD_TEST( sandbox->quic->metrics.stream_closed_cnt   ==            1UL );
  FD_TEST( sandbox->quic->metrics.stream_rx_event_cnt == window_cnt+1UL );
  FD_TEST( sandbox->quic->metrics.stream_active_cnt   == window_cnt     );

  /* Send a stream, skipping one stream ID.  This moves up the window
     by two, dropping two streams. */
  do {
    uchar buf[ 64 ];
    fd_quic_stream_frame_t stream_frame =
      { .stream_id  = ((window_cnt+2)<<2) + FD_QUIC_STREAM_TYPE_UNI_CLIENT,
        .length_opt = 1,
        .length     = 1UL };
    ulong sz = fd_quic_encode_stream_frame( buf, sizeof(buf), &stream_frame );
    FD_TEST( sz!=FD_QUIC_ENCODE_FAIL );
    buf[ sz++ ] = '0';
    fd_quic_sandbox_send_lone_frame( sandbox, conn, buf, sz );
    FD_TEST( conn->state == FD_QUIC_CONN_STATE_ACTIVE );
  } while(0);
  FD_TEST( sandbox->quic->metrics.stream_opened_cnt   == window_cnt+2UL );
  FD_TEST( sandbox->quic->metrics.stream_closed_cnt   ==            3UL );
  FD_TEST( sandbox->quic->metrics.stream_rx_event_cnt == window_cnt+2UL );
  FD_TEST( sandbox->quic->metrics.stream_active_cnt   == window_cnt-1UL );

  /* All streams should close when the connection winds down */
  do {
    uchar buf[ 64 ];
    fd_quic_conn_close_1_frame_t close_frame = {0};
    ulong sz = fd_quic_encode_conn_close_1_frame( buf, sizeof(buf), &close_frame );
    FD_TEST( sz!=FD_QUIC_ENCODE_FAIL );
    fd_quic_sandbox_send_lone_frame( sandbox, conn, buf, sz );
  } while(0);

  /* Mark conn as free */
  FD_TEST( conn->state == FD_QUIC_CONN_STATE_PEER_CLOSE );
  fd_quic_conn_service( sandbox->quic, conn, fd_quic_now( sandbox->quic ) );
  FD_TEST( conn->state == FD_QUIC_CONN_STATE_DEAD );
  FD_TEST( sandbox->quic->metrics.conn_closed_cnt == 1UL );

  /* Actually free conn */
  fd_quic_conn_free( sandbox->quic, conn );
  FD_TEST( sandbox->quic->metrics.stream_closed_cnt == window_cnt+2UL );
  FD_TEST( sandbox->quic->metrics.stream_active_cnt == 0UL            );
}

static __attribute__((noinline)) void
test_quic_stream_retransmit( fd_quic_sandbox_t * sandbox,
                             fd_rng_t *          rng ) {

  fd_quic_sandbox_init( sandbox, FD_QUIC_ROLE_SERVER );
  fd_quic_conn_t * conn = fd_quic_sandbox_new_conn_established( sandbox, rng );
  conn->rx_sup_stream_id = (1024UL<<2) + FD_QUIC_STREAM_TYPE_UNI_CLIENT;

  /* Send same stream multiple times */
  uchar buf[ 64 ];
  fd_quic_stream_frame_t stream_frame =
    { .stream_id  = FD_QUIC_STREAM_TYPE_UNI_CLIENT,
      .length_opt = 1,
      .length     = 1UL,
      .fin_opt    = 1 };

  for( ulong j=0; j<32; j++ ) {
    ulong sz = fd_quic_encode_stream_frame( buf, sizeof(buf), &stream_frame );
    FD_TEST( sz!=FD_QUIC_ENCODE_FAIL );
    buf[ sz++ ] = '0';
    fd_quic_sandbox_send_lone_frame( sandbox, conn, buf, sz );
    FD_TEST( conn->state == FD_QUIC_CONN_STATE_ACTIVE );
  }
  FD_TEST( sandbox->quic->metrics.stream_rx_event_cnt == 1UL );
  FD_TEST( sandbox->quic->metrics.stream_active_cnt == 0UL );
}

/* reorder: ensure that reordered fragments arrive without corruption */

/* Ensure that the server-side spends less than O(n) time handling
   skipped stream IDs.  (Otherwise, this test would run for a very long
   time) */

static __attribute__((noinline)) void
test_quic_stream_skip_long( fd_quic_sandbox_t * sandbox,
                            fd_rng_t *          rng ) {

  fd_quic_sandbox_init( sandbox, FD_QUIC_ROLE_SERVER );
  fd_quic_conn_t * conn = fd_quic_sandbox_new_conn_established( sandbox, rng );
  conn->rx_sup_stream_id = (1UL<<62)-1;

  for( ulong j=0UL; j<1024UL; j++ ) {
    uchar buf[ 256 ] = {0};
    ulong stream_id = (j<<32) + FD_QUIC_STREAM_TYPE_UNI_CLIENT;
    fd_quic_stream_frame_t stream_frame =
      { .stream_id  = stream_id,
        .length_opt = 1,
        .length     = 1UL };
    ulong sz = fd_quic_encode_stream_frame( buf, sizeof(buf), &stream_frame );
    FD_TEST( sz!=FD_QUIC_ENCODE_FAIL );
    buf[ sz++ ] = '0';
    fd_quic_sandbox_send_lone_frame( sandbox, conn, buf, sz );
    FD_TEST( conn->state == FD_QUIC_CONN_STATE_ACTIVE );
    FD_TEST( sandbox->quic->metrics.stream_rx_event_cnt == j+1UL );
    FD_TEST( sandbox->quic->metrics.stream_active_cnt == 1 );
  }
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  ulong cpu_idx = fd_tile_cpu_id( fd_tile_idx() );
  if( cpu_idx>=fd_shmem_cpu_cnt() ) cpu_idx = 0UL;

  char const * _page_sz = fd_env_strip_cmdline_cstr  ( &argc, &argv, "--page-sz",  NULL, "gigantic"                 );
  ulong        page_cnt = fd_env_strip_cmdline_ulong ( &argc, &argv, "--page-cnt", NULL, 2UL                        );
  ulong        numa_idx = fd_env_strip_cmdline_ulong ( &argc, &argv, "--numa-idx", NULL, fd_shmem_numa_idx(cpu_idx) );

  ulong page_sz = fd_cstr_to_shmem_page_sz( _page_sz );
  if( FD_UNLIKELY( !page_sz ) ) FD_LOG_ERR(( "unsupported --page-sz" ));

  fd_quic_limits_t quic_limits = {
    .conn_cnt         =   4UL,
    .handshake_cnt    =   1UL,
    .conn_id_cnt      =   4UL,
    .stream_id_cnt    =   8UL,
    .rx_stream_cnt    =   8UL,
    .inflight_pkt_cnt =   8UL,
    .tx_buf_sz        = 512UL,
    .stream_pool_cnt  =  32UL,
  };

  ulong const pkt_cnt = 128UL;
  ulong const pkt_mtu = 1232UL;  /* consider reducing? */

  FD_LOG_NOTICE(( "Creating anonymous workspace with --page-cnt %lu --page-sz %s pages on --numa-idx %lu", page_cnt, _page_sz, numa_idx ));
  fd_wksp_t * wksp = fd_wksp_new_anonymous( page_sz, page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  /* Allocate a sandbox object */

  void * sandbox_mem = fd_wksp_alloc_laddr(
      /* wksp  */ wksp,
      /* align */ fd_quic_sandbox_align(),
      /* size  */ fd_quic_sandbox_footprint( &quic_limits, pkt_cnt, pkt_mtu ),
      /* tag   */ 1UL );

  fd_quic_sandbox_t * sandbox = fd_quic_sandbox_join( fd_quic_sandbox_new(
      sandbox_mem, &quic_limits, pkt_cnt, pkt_mtu ) );
  FD_TEST( sandbox );

  /* Run tests */
  test_quic_stream_data_limit_enforcement( sandbox, rng );
  test_quic_stream_limit_enforcement     ( sandbox, rng );
  test_quic_stream_concurrency           ( sandbox, rng );
  test_quic_stream_retransmit            ( sandbox, rng );
  test_quic_stream_skip                  ( sandbox, rng );
  test_quic_stream_skip_long             ( sandbox, rng );

  /* Wind down */

  fd_wksp_free_laddr( fd_quic_sandbox_delete( fd_quic_sandbox_leave( sandbox ) ) );
  fd_wksp_delete_anonymous( wksp );
  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
