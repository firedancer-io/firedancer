/* fuzz_bundle_client injects HTTP/2 frames into a bundle tile state. */

#include "test_bundle_common.c"
#include "fd_bundle_tile_private.h"
#include <errno.h>
#include <stdlib.h>

/* Override the clock source weak symbol.
   For now, this fuzzer does not support timeouts. */

long
fd_bundle_now( void ) {
  return 2UL;
}

static fd_wksp_t * g_wksp;

int
LLVMFuzzerInitialize( int *    pargc,
                      char *** pargv ) {
  putenv( "FD_LOG_BACKTRACE=0" );

  fd_boot( pargc, pargv );

  ulong cpu_idx = fd_tile_cpu_id( fd_tile_idx() );
  if( cpu_idx>fd_shmem_cpu_cnt() ) cpu_idx = 0UL;
  char const * _page_sz = fd_env_strip_cmdline_cstr ( pargc, pargv, "--page-sz",  NULL, "normal"                     );
  ulong        page_cnt = fd_env_strip_cmdline_ulong( pargc, pargv, "--page-cnt", NULL, 256UL                        );
  ulong        numa_idx = fd_env_strip_cmdline_ulong( pargc, pargv, "--numa-idx", NULL, fd_shmem_numa_idx( cpu_idx ) );
  fd_wksp_t * wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 16UL );
  FD_TEST( wksp );
  g_wksp = wksp;

  atexit( fd_halt );

  fd_log_level_core_set( 4 );
  fd_log_level_stderr_set( 4 );
  fd_log_level_logfile_set( 4 );

  return 0;
}

int
LLVMFuzzerTestOneInput( uchar const * data,
                        ulong         size ) {
  fd_wksp_t * const wksp = g_wksp;
  if( size<8UL ) return -1;

  test_bundle_env_t env[1];
  test_bundle_env_create( env, wksp );
  test_bundle_env_mock_conn_empty( env );

  fd_bundle_tile_t * const ctx      = env->state;
  fd_h2_rbuf_t *     const frame_rx = ctx->grpc_client->frame_rx;
  fd_h2_rbuf_t *     const frame_tx = ctx->grpc_client->frame_tx;

  ctx->grpc_client->conn->ping_tx = 2; /* allow PING ACKs */

  ulong const seed = fd_ulong_hash( FD_LOAD( ulong, data+size-8 ) );
  if( seed &  1 ) test_bundle_env_mock_h2_hs( env->state );
  if( seed &  2 ) test_bundle_env_mock_builder_info( env->state );
  if( seed &  4 ) test_bundle_env_mock_bundle_stream( env->state );
  if( seed &  8 ) test_bundle_env_mock_packet_stream( env->state );
  if( seed & 16 ) test_bundle_env_mock_builder_info_req( env->state );

  while( size ) {
    // ulong chunk_sz = 1UL;
    ulong const chunk_sz = fd_ulong_min( size, fd_h2_rbuf_free_sz( frame_rx ) );
    fd_h2_rbuf_push( frame_rx, data, chunk_sz );
    data += chunk_sz;
    size -= chunk_sz;
    int charge_busy = 0;
    fd_bundle_client_step( ctx, &charge_busy );
    fd_h2_rbuf_skip( frame_tx, fd_h2_rbuf_used_sz( frame_tx ) );
    if( ctx->defer_reset ) break;
  }

  test_bundle_env_destroy( env );

  /* Check for memory leaks */
  fd_wksp_usage_t wksp_usage;
  FD_TEST( fd_wksp_usage( wksp, NULL, 0UL, &wksp_usage ) );
  FD_TEST( wksp_usage.free_cnt==wksp_usage.total_cnt );

  return 0;
}
