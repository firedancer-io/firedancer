/* test_quic_concurrency tests fd_quic server when handling a large
   number of connections sending small streams.  This is meant to
   approximate TPU/QUIC on mainnet.

   Traffic is injected at the QUIC frame level (skipping decryption).
   The QUIC server still undergoes fd_quic_service and sends out
   encrypted packets. */

#include "fd_quic_sandbox.h"
#include "../fd_quic_proto.h"
#include "../fd_quic_proto.c"
#include "../fd_quic_private.h"
#include "../../../tango/fd_tango.h"

static ulong
quic_now( void * ctx ) {
  (void)ctx;
  return (ulong)fd_log_wallclock();
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  ulong cpu_idx = fd_tile_cpu_id( fd_tile_idx() );
  if( cpu_idx>fd_shmem_cpu_cnt() ) cpu_idx = 0UL;

  char const * _page_sz   = fd_env_strip_cmdline_cstr ( &argc, &argv, "--page-sz",  NULL, "gigantic"                   );
  ulong        page_cnt   = fd_env_strip_cmdline_ulong( &argc, &argv, "--page-cnt", NULL, 2UL                          );
  ulong        numa_idx   = fd_env_strip_cmdline_ulong( &argc, &argv, "--numa-idx", NULL, fd_shmem_numa_idx( cpu_idx ) );
  ulong        conn_cnt   = fd_env_strip_cmdline_ulong( &argc, &argv, "--conn-cnt", NULL, 100000UL                     );
  float        duration   = fd_env_strip_cmdline_float( &argc, &argv, "--duration", NULL, 3.0f                         );
  ulong        conn_burst = fd_env_strip_cmdline_ulong( &argc, &argv, "--burst",    NULL, 16UL                         );
  if( !conn_burst ) conn_burst = 1UL;

  ulong page_sz = fd_cstr_to_shmem_page_sz( _page_sz );
  if( FD_UNLIKELY( !page_sz ) ) FD_LOG_ERR(( "unsupported --page-sz" ));

  /* Join a large page backed workspace for predictable performance */

  FD_LOG_NOTICE(( "Creating workspace (--page-cnt %lu, --page-sz %s, --numa-idx %lu)", page_cnt, _page_sz, numa_idx ));
  fd_wksp_t * wksp = fd_wksp_new_anonymous( page_sz, page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );
  ulong const wksp_tag = 1UL;

  /* Create a QUIC instance with support for lots of connections.
     For better test performance, we use fd_quic_sandbox to inject mock
     traffic instead of running real QUIC clients. */

  fd_quic_limits_t quic_limits = {
    .conn_cnt         = conn_cnt,
    .handshake_cnt    =        1,
    .conn_id_cnt      =        4,
    .rx_stream_cnt    =        2,
    .inflight_pkt_cnt =        4,
    .tx_buf_sz        =        0
  };
  quic_limits.stream_pool_cnt = quic_limits.conn_cnt * quic_limits.rx_stream_cnt;
  FD_LOG_INFO(( "fd_quic limits: conn_cnt=%lu conn_id_cnt=%lu stream_pool_cnt=%lu",
                quic_limits.conn_cnt, quic_limits.conn_id_cnt, quic_limits.stream_pool_cnt ));
  FD_LOG_INFO(( "fd_quic footprint is %.1f MB", (double)fd_quic_footprint( &quic_limits ) / 1e6 ));

  ulong const pkt_max = 1024UL;
  ulong const mtu     = 1500UL;
  void * sandbox_mem = fd_wksp_alloc_laddr(
      wksp,
      fd_quic_sandbox_align(),
      fd_quic_sandbox_footprint( &quic_limits, pkt_max, mtu ),
      wksp_tag
  );
  fd_quic_sandbox_t * const sandbox = fd_quic_sandbox_join( fd_quic_sandbox_new( sandbox_mem, &quic_limits, pkt_max, mtu ) );
  FD_TEST( sandbox );
  FD_TEST( fd_quic_sandbox_init( sandbox, FD_QUIC_ROLE_SERVER ) );
  fd_quic_t * const quic = sandbox->quic;
  quic->cb.now = quic_now;
  quic->config.idle_timeout = (ulong)100000e9;
  fd_quic_state_t * state = fd_quic_get_state( quic );
  state->now = fd_quic_now( quic );

  /* Create table of server-side conn objects to inject traffic into. */

  fd_quic_conn_t ** const conn_list = fd_wksp_alloc_laddr( wksp, alignof(void *), conn_cnt * sizeof(void *), wksp_tag );
  FD_TEST( conn_list );

  for( ulong j=0UL; j<conn_cnt; j++ ) {
    fd_quic_conn_t * conn = fd_quic_sandbox_new_conn_established( sandbox, rng );
    conn->rx_sup_stream_id = (1UL<<62)-1;
    conn->last_activity    = state->now;
    conn->idle_timeout     = (ulong)100000e9;
    conn_list[ j ] = conn;
  }

  /* Test loop */

  FD_LOG_NOTICE(( "Test start (--conn-cnt %lu --duration %g s --conn-burst %lu)", conn_cnt, (double)duration, conn_burst ));

  long test_finish = fd_log_wallclock() + (long)( (double)duration * 1e9 );

  long  lazy        = 1e6; /* 1 ms */
  float tick_per_ns = (float)fd_tempo_tick_per_ns( NULL );
  ulong async_min   = fd_tempo_async_min( lazy, 1UL /*event_cnt*/, tick_per_ns );

  long now  = fd_tickcount();
  long then = now;

  uchar frame_buf[ 1024 ];
  long  last_stat = fd_log_wallclock();

  ulong frame_cnt = 0UL;
  ulong burst_idx = 0UL;
  ulong conn_idx  = LONG_MAX;
  for(;;) {

    if( FD_UNLIKELY( (now-then)>=0L ) ) {
      long ts = fd_log_wallclock();
      if( fd_log_wallclock() > test_finish ) break;

      if( ts-last_stat >= (long)1e9 ) {
        ulong frame_cnt = quic->metrics.stream_rx_event_cnt;
        FD_LOG_NOTICE(( "  Stat:  %.3g frame/s", (double)frame_cnt / ( (double)( ts-last_stat )/1e9 ) ));
        last_stat += (long)1e9;
        quic->metrics.stream_rx_event_cnt = 0UL;
      }

      then = now + (long)fd_tempo_async_reload( rng, async_min );
    }

    fd_quic_service( quic );

    if( burst_idx==0UL ) {
      conn_idx  = fd_rng_ulong_roll( rng, conn_cnt );
      burst_idx = conn_burst;
    }
    burst_idx--;
    fd_quic_conn_t * conn = conn_list[ conn_idx ];

    fd_quic_stream_frame_t stream_frame =
      { .stream_id  = conn->rx_hi_stream_id,
        .fin_opt    = 1 };
    ulong sz = fd_quic_encode_stream_frame( frame_buf, sizeof(frame_buf), &stream_frame );
    FD_TEST( sz!=FD_QUIC_ENCODE_FAIL );
    sz += 64;

    fd_quic_sandbox_send_lone_frame( sandbox, conn, frame_buf, sz );
    FD_TEST( conn->state==FD_QUIC_CONN_STATE_ACTIVE );

    now = fd_tickcount();
    frame_cnt++;

  }

  FD_LOG_NOTICE(( "Test finish" ));

  FD_LOG_NOTICE(( "Injected %lu stream frames", frame_cnt ));
  FD_LOG_NOTICE(( "Sent %lu packets", quic->metrics.net_tx_pkt_cnt ));

  if( frame_cnt > 10000UL ) {
    /* Fail test if the server sent back an excessive amount of ACKs */
    FD_TEST( quic->metrics.net_tx_pkt_cnt <= frame_cnt );
  }

  fd_quic_svc_validate( quic );

  fd_wksp_free_laddr( conn_list );
  fd_wksp_free_laddr( fd_quic_sandbox_delete( fd_quic_sandbox_leave( sandbox ) ) );
  fd_rng_delete( fd_rng_leave( rng ) );
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
