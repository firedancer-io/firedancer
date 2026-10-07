#define _GNU_SOURCE
#include "fd_cost_tracker_store.h"

#include <stdlib.h> /* aligned_alloc */
#include <sys/mman.h> /* memfd_create */
#include <sys/stat.h>
#include <unistd.h>

static ulong
spill_sz( int fd ) {
  struct stat st;
  FD_TEST( !fstat( fd, &st ) );
  return (ulong)st.st_size;
}

static fd_cost_tracker_store_t *
store_create( void ** mem_out,
             int     fd,
             ulong   max_live_slots,
             ulong   cache_cnt ) {
  ulong footprint = fd_cost_tracker_store_footprint( max_live_slots, cache_cnt );
  FD_TEST( footprint );
  void * mem = aligned_alloc( fd_cost_tracker_store_align(), footprint );
  FD_TEST( mem );
  FD_TEST( !ftruncate( fd, 0L ) );
  fd_cost_tracker_store_t * store = fd_cost_tracker_store_join( fd_cost_tracker_store_new( mem, fd, max_live_slots, cache_cnt, 123UL, 456UL ), fd );
  FD_TEST( store );
  *mem_out = mem;
  return store;
}

static void
test_new_join( int fd ) {
  FD_TEST( !fd_cost_tracker_store_footprint( 0UL, 1UL ) );
  FD_TEST( !fd_cost_tracker_store_footprint( 2UL, 0UL ) );
  FD_TEST( !fd_cost_tracker_store_footprint( USHORT_MAX, 1UL ) );
  FD_TEST( fd_cost_tracker_store_footprint( 2UL, 3UL )==fd_cost_tracker_store_footprint( 2UL, 2UL ) );

  ulong  footprint = fd_cost_tracker_store_footprint( 2UL, 1UL );
  void * mem       = aligned_alloc( fd_cost_tracker_store_align(), footprint );
  FD_TEST( mem );
  FD_TEST( !fd_cost_tracker_store_new( NULL,             fd, 2UL, 1UL, 0UL, 0UL ) );
  FD_TEST( !fd_cost_tracker_store_new( (uchar *)mem+1UL, fd, 2UL, 1UL, 0UL, 0UL ) );
  FD_TEST( !fd_cost_tracker_store_new( mem,              -1, 2UL, 1UL, 0UL, 0UL ) );
  FD_TEST( fd_cost_tracker_store_new( mem, fd, 2UL, 1UL, 0UL, 0UL ) );
  FD_TEST( !fd_cost_tracker_store_join( NULL,             fd   ) );
  FD_TEST( !fd_cost_tracker_store_join( (uchar *)mem+1UL, fd   ) );
  FD_TEST( !fd_cost_tracker_store_join( mem,              fd+1 ) );
  FD_TEST(  fd_cost_tracker_store_join( mem,              fd   ) );
  free( mem );
}

/* More cost trackers than cache entries spill to disk and reload with
   their contents intact, and a pinned cost tracker is never evicted. */

static void
test_spill_reload( int fd ) {
  ulong const live_cnt  = 4UL;
  ulong const cache_cnt = 2UL;
  void * mem;
  fd_cost_tracker_store_t * store = store_create( &mem, fd, live_cnt, cache_cnt );

  ushort idx[ 4 ];
  for( ulong i=0UL; i<live_cnt; i++ ) {
    idx[ i ] = fd_cost_tracker_store_new_fork( store, USHORT_MAX );
    fd_cost_tracker_t * ct = fd_cost_tracker_store_pin( store, idx[ i ] );
    FD_TEST( ct->bench_max_cost_per_block==123UL );
    ct->block_cost = 1000UL+i;
    fd_cost_tracker_store_unpin( store, idx[ i ] );
  }
  FD_TEST( spill_sz( fd ) );

  fd_cost_tracker_t * pinned = fd_cost_tracker_store_pin( store, idx[ 0 ] );
  FD_TEST( pinned->block_cost==1000UL );
  for( ulong round=0UL; round<2UL; round++ ) {
    for( ulong i=1UL; i<live_cnt; i++ ) {
      fd_cost_tracker_t * ct = fd_cost_tracker_store_pin( store, idx[ i ] );
      FD_TEST( ct->block_cost==1000UL+i );
      FD_TEST( fd_cost_tracker_store_peek( store, idx[ i ] )==ct );
      fd_cost_tracker_store_unpin( store, idx[ i ] );
    }
  }
  FD_TEST( fd_cost_tracker_store_peek( store, idx[ 0 ] )==pinned );
  FD_TEST( pinned->block_cost==1000UL );
  fd_cost_tracker_store_unpin( store, idx[ 0 ] );

  free( mem );
}

/* A released fork id can be reused, even if its old contents
   were spilled. */

static void
test_release_fresh( int fd ) {
  void * mem;
  fd_cost_tracker_store_t * store = store_create( &mem, fd, 2UL, 1UL );

  ushort a = fd_cost_tracker_store_new_fork( store, USHORT_MAX );
  fd_cost_tracker_store_pin( store, a )->block_cost = 77UL;
  fd_cost_tracker_store_unpin( store, a );
  ushort b = fd_cost_tracker_store_new_fork( store, USHORT_MAX ); /* evicts a */
  FD_TEST( b!=a );

  ushort c = fd_cost_tracker_store_new_fork( store, a );
  FD_TEST( c==a );
  FD_TEST( fd_cost_tracker_store_pin( store, c )->bench_max_cost_per_block==123UL );
  fd_cost_tracker_store_unpin( store, c );

  fd_cost_tracker_store_reset( store );
  FD_TEST( fd_cost_tracker_store_new_fork( store, USHORT_MAX )<2 );

  free( mem );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  int fd = memfd_create( "test_cost_tracker_store", 0 );
  FD_TEST( fd>=0 );

  test_new_join( fd );
  test_spill_reload( fd );
  test_release_fresh( fd );

  FD_TEST( !close( fd ) );
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
