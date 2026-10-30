#include "fd_sched_test_store.h"

/* Solfuzz runs shred fixtures on multiple tiles.  The test helper must
   give each tile its own store so both can pin a FEC simultaneously. */
static atomic_uint  worker_pinned;
static atomic_uint  worker_release;
static fd_store_t * worker_store;

static int
store_worker( int     argc FD_PARAM_UNUSED,
              char ** argv FD_PARAM_UNUSED ) {
  fd_sched_test_fec_t fec = {0};
  fd_sched_fec_read_t read = fd_sched_test_fec_pin( &fec, NULL );
  worker_store = read.store;
  atomic_store_explicit( &worker_pinned, 1U, memory_order_release );
  while( !atomic_load_explicit( &worker_release, memory_order_acquire ) ) FD_SPIN_PAUSE();
  fd_sched_test_fec_unpin( &read );
  return 0;
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  int require_multitile = fd_env_strip_cmdline_contains( &argc, &argv, "--require-multitile" );
  if( FD_UNLIKELY( require_multitile && fd_tile_cnt()<2UL ) )
    FD_LOG_ERR(( "--require-multitile needs at least two tile CPUs" ));

  fd_sched_test_fec_t fec = {0};
  fd_sched_fec_read_t read = fd_sched_test_fec_pin( &fec, NULL );
  FD_TEST( fd_store_query_data_sz( read.store, read.view )==0UL );

  if( FD_LIKELY( fd_tile_cnt()>1UL ) ) {
    FD_TEST( fd_tile_exec_new( 1UL, store_worker, 0, NULL ) );
    while( !atomic_load_explicit( &worker_pinned, memory_order_acquire ) ) FD_SPIN_PAUSE();
    FD_TEST( read.store!=worker_store );
    fd_sched_test_fec_unpin( &read );
    atomic_store_explicit( &worker_release, 1U, memory_order_release );
    fd_tile_exec_delete( fd_tile_exec( 1UL ), NULL );
  } else {
    FD_LOG_WARNING(( "skip concurrent test: needs at least 2 tiles" ));
    fd_sched_test_fec_unpin( &read );
  }

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
