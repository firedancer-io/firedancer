#include "vote_pool.h"

void
test_insert_votes( fd_wksp_t * wksp ) {
  //int lg_slot_cnt = 8;

  void * mem = fd_wksp_alloc_laddr( wksp, fd_alpen_slot_votes_map_align(), fd_alpen_slot_votes_map_footprint(), 1UL );
  FD_TEST( mem );
  fd_alpen_slot_votes_t * slot_votes = fd_alpen_slot_votes_map_join( fd_alpen_slot_votes_map_new( mem ) );
  FD_TEST( slot_votes );

  ulong slot = 1;
  ulong validator_id = 0;
  fd_hash_t blockid = {0};
  fd_hash_t bank_hash = {0};

  notar_insert( slot_votes, &blockid, slot, validator_id, &bank_hash );
  skip_insert( slot_votes, slot, validator_id );
  notar_fallback_insert( slot_votes, &blockid, slot, validator_id, &bank_hash );
  skip_fallback_insert( slot_votes, slot, validator_id );
  finalize_insert( slot_votes, slot, validator_id );

} // test_insert_votes

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  ulong  page_cnt  = 10;
  char * _page_sz  = "gigantic";
  ulong  numa_idx  = fd_shmem_numa_idx( 0 );
  fd_wksp_t * wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  test_insert_votes( wksp );

  fd_halt();
  return 0;
}
