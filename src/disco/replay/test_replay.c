#include "fd_replay.h"
#include <sys/resource.h>

int
fd_replay_verify_init_map( fd_replay_t const * replay ) {
  fd_replay_slice_t * slice_map      = replay->slice_map;
  ulong               prev_deque_loc = 0;
  for( ulong i = 0; i < replay->block_max; i++ ) {
    fd_replay_slice_t * slice_map_entry = slice_map + i;
    FD_TEST( fd_replay_slice_deque_cnt( slice_map_entry->deque ) == 0 );
    FD_TEST( fd_replay_slice_deque_max( slice_map_entry->deque ) == replay->slice_max );
    if( i == 0 ) {
      prev_deque_loc = (ulong)fd_replay_slice_deque_private_const_hdr_from_deque( slice_map_entry->deque );
      continue;
    }
    FD_TEST( (ulong)fd_replay_slice_deque_private_const_hdr_from_deque( slice_map_entry->deque ) ==
            fd_ulong_align_up( prev_deque_loc + fd_replay_slice_deque_footprint( replay->slice_max ),
                               fd_replay_slice_deque_align() ) );
    prev_deque_loc = (ulong)fd_replay_slice_deque_private_const_hdr_from_deque( slice_map_entry->deque );
  }
  return 1;
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  ulong  page_cnt  = 1;
  char * page_sz   = "gigantic";
  ulong  numa_idx  = fd_shmem_numa_idx( 0 );
  fd_wksp_t * wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( page_sz ), page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  ulong  fec_max       = 16;
  ulong  slice_max     = 16;
  ulong  block_max     = 16;
  void * replay_mem    = fd_wksp_alloc_laddr( wksp, fd_replay_align(), fd_replay_footprint( fec_max, slice_max ), 1UL );
  fd_replay_t * replay = fd_replay_join( fd_replay_new( replay_mem, fec_max, slice_max, block_max ) );
  FD_TEST( replay );

  FD_TEST( fd_replay_slice_map_key_cnt( replay->slice_map ) == 0 );
  FD_TEST( fd_replay_verify_init_map( replay ) );

  /* try inserting into a deque */
  fd_replay_slice_t * slot_entry = fd_replay_slice_map_insert( replay->slice_map, 1 );
  FD_TEST( fd_replay_slice_map_key_cnt( replay->slice_map ) == 1 );
  FD_TEST( fd_replay_slice_deque_cnt( slot_entry->deque ) == 0 );
  fd_replay_slice_deque_push_tail( slot_entry->deque, 42 );
  FD_TEST( fd_replay_slice_deque_cnt( slot_entry->deque ) == 1 );
  FD_TEST( fd_replay_slice_deque_max( slot_entry->deque ) == replay->slice_max );
  ulong slice = fd_replay_slice_deque_pop_head( slot_entry->deque );
  FD_TEST( slice == 42 );
  fd_replay_slice_map_remove( replay->slice_map, slot_entry );
  FD_TEST( fd_replay_slice_map_key_cnt( replay->slice_map ) == 0 );
  FD_TEST( fd_replay_verify_init_map( replay ) );
  /* no collisions so the map should be in init state*/

  FD_TEST( !fd_replay_fec_query( replay, 42, 84 ) );
  fd_replay_fec_insert( replay, 42, 84 );
  FD_TEST( fd_replay_fec_query( replay, 42, 84 ) );

  fd_halt();
  return 0;
}
