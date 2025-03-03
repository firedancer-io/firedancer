#include "fd_replay.h"

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  ulong  page_cnt  = 1;
  char * page_sz   = "gigantic";
  ulong  numa_idx  = fd_shmem_numa_idx( 0 );
  fd_wksp_t * wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( page_sz ), page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  ulong slice_max      = 16;
  void * replay_mem    = fd_wksp_alloc_laddr( wksp, fd_replay_align(), fd_replay_footprint( 16 ), 1UL );
  fd_replay_t * replay = fd_replay_join( fd_replay_new( replay_mem, 0UL, slice_max ) );
  FD_TEST( replay );

  fd_halt();
  return 0;
}
