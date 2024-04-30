#include "fd_ghost.h"

#define INSERT( c, p )                                                           \
  slot_hashes[i] = ( fd_slot_hash_t ){ .slot = c, .hash = pubkey_null };          \
  if( p < ULONG_MAX ) {                                                          \
    parent_slot_hashes[i] = ( fd_slot_hash_t ){ .slot = p, .hash = pubkey_null }; \
    fd_ghost_leaf_insert( ghost, &slot_hashes[i], &parent_slot_hashes[i] );        \
  } else {                                                                       \
    parent_slot_hashes[i] = ( fd_slot_hash_t ){ .slot = p, .hash = pubkey_null }; \
    fd_ghost_leaf_insert( ghost, &slot_hashes[i], NULL );                         \
  }                                                                              \
  i++;

/*
         slot 0
           |
         slot 1
         /    \
    slot 2    |
       |    slot 3
    slot 4    |
            slot 5
              |
            slot 6
*/
void
test_ghost_simple( fd_ghost_t * ghost ) {
  fd_slot_hash_t slot_hashes[fd_ghost_node_pool_max( ghost->node_pool )];
  fd_slot_hash_t parent_slot_hashes[fd_ghost_node_pool_max( ghost->node_pool )];
  ulong          i = 0;

  INSERT( 0, ULONG_MAX );
  INSERT( 1, 0 );
  INSERT( 2, 1 );
  INSERT( 3, 1 );
  INSERT( 4, 2 );
  INSERT( 5, 3 );
  INSERT( 6, 5 );

  fd_ghost_print( ghost );

  fd_pubkey_t    pk1 = { .key = { 1 } };
  fd_slot_hash_t sh2 = { .slot = 2, .hash = pubkey_null };
  fd_ghost_replay_vote_upsert( ghost, &sh2, &pk1, 1 );

  fd_ghost_print( ghost );

  fd_slot_hash_t sh3 = { .slot = 3, .hash = pubkey_null };
  fd_ghost_replay_vote_upsert( ghost, &sh3, &pk1, 1 );

  fd_ghost_print( ghost );
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  ulong  page_cnt = 1;
  char * _page_sz = "gigantic";
  ulong  numa_idx = fd_shmem_numa_idx( 0 );
  FD_LOG_NOTICE( ( "Creating workspace (--page-cnt %lu, --page-sz %s, --numa-idx %lu)",
                   page_cnt,
                   _page_sz,
                   numa_idx ) );
  fd_wksp_t * wksp = fd_wksp_new_anonymous(
      fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  ulong  node_max = 16;
  ulong  vote_max = 16;
  void * mem =
      fd_wksp_alloc_laddr( wksp, fd_ghost_align(), fd_ghost_footprint( node_max, vote_max ), 1UL );
  FD_TEST( mem );
  fd_ghost_t * ghost = fd_ghost_join( fd_ghost_new( mem, node_max, vote_max, 0UL ) );
  FD_TEST( ghost );
  FD_TEST( FD_SLOT_HASH_EQ( &ghost->root, &FD_SLOT_HASH_NULL ) );
  FD_TEST( ghost->node_pool );
  FD_TEST( ghost->node_map );
  FD_TEST( ghost->vote_pool );
  FD_TEST( ghost->vote_map );

  test_ghost_simple( ghost );

  fd_halt();
  return 0;
}
