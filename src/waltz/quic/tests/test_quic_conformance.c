/* test_quic_conformance verifies that fd_quic adheres to various
   assertions made in the QUIC specification (RFC 9000). */

#include "fd_quic_sandbox.h"
#include "../fd_quic_proto.h"

/* RFC 9000 Section 4.1. Data Flow Control

   > A receiver MUST close the connection with an error of type
   > FLOW_CONTROL_ERROR if the sender violates the advertised connection
   > or stream data limits */

static __attribute__ ((noinline)) void
test_quic_stream_data_limit_enforcement( fd_quic_sandbox_t * sandbox,
                                         fd_rng_t *          rng ) {

  fd_quic_sandbox_init( sandbox, FD_QUIC_ROLE_SERVER );
  fd_quic_conn_t * conn = fd_quic_sandbox_new_conn_established( sandbox, rng );
  fd_quic_conn_set_max_streams( conn, FD_QUIC_TYPE_UNIDIR, 1UL );

  uchar buf[ 1024 ];
  fd_quic_stream_frame_t stream_frame =
    { .stream_id = FD_QUIC_STREAM_TYPE_UNI_CLIENT,
      .fin_opt   = 1,
      .length    = 1UL };
  ulong sz = fd_quic_encode_stream_frame( buf, sizeof(buf), &stream_frame );
  FD_TEST( sz!=FD_QUIC_PARSE_FAIL );
  buf[ sz++ ] = 0;

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
  fd_quic_conn_set_max_streams( conn, FD_QUIC_TYPE_BIDIR, 1UL );

  uchar buf[ 1024 ];
  fd_quic_stream_frame_t stream_frame =
    { .stream_id = FD_QUIC_STREAM_TYPE_UNI_CLIENT,
      .fin_opt   = 1 };
  ulong sz = fd_quic_encode_stream_frame( buf, sizeof(buf), &stream_frame );
  FD_TEST( sz!=FD_QUIC_PARSE_FAIL );

  fd_quic_sandbox_send_lone_frame( sandbox, conn, buf, sz );
  FD_TEST( conn->state  == FD_QUIC_CONN_STATE_ABORT );
  FD_TEST( conn->reason == FD_QUIC_CONN_REASON_STREAM_LIMIT_ERROR );
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

  fd_quic_limits_t quic_limits[1] = {{0}};
  fd_quic_limits_from_env( &argc, &argv, quic_limits );

  ulong const pkt_cnt = 128UL;
  ulong const pkt_mtu = 1232UL;  /* consider reducing? */

  FD_LOG_NOTICE(( "Creating anonymous workspace with --page-cnt %lu --page-sz %s pages on --numa-idx %lu", page_cnt, _page_sz, numa_idx ));
  fd_wksp_t * wksp = fd_wksp_new_anonymous( page_sz, page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  /* Allocate a sandbox object */

  void * sandbox_mem = fd_wksp_alloc_laddr(
      /* wksp  */ wksp,
      /* align */ fd_quic_sandbox_align(),
      /* size  */ fd_quic_sandbox_footprint( quic_limits, pkt_cnt, pkt_mtu ),
      /* tag   */ 1UL );

  fd_quic_sandbox_t * sandbox = fd_quic_sandbox_join( fd_quic_sandbox_new(
      sandbox_mem, quic_limits, pkt_cnt, pkt_mtu ) );
  FD_TEST( sandbox );

  /* Run tests */

  test_quic_stream_data_limit_enforcement( sandbox, rng );
  test_quic_stream_limit_enforcement     ( sandbox, rng );

  /* Wind down */

  fd_wksp_free_laddr( fd_quic_sandbox_delete( fd_quic_sandbox_leave( sandbox ) ) );
  fd_wksp_delete_anonymous( wksp );
  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
