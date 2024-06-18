#include "fd_ghost.h"
#include <stdlib.h>

#define INSERT( c, p )                                                                                                                     \
  slots[i]        = c;                                                                                                                     \
  parent_slots[i] = p;                                                                                                                     \
  if( p < ULONG_MAX ) {                                                                                                                    \
    fd_ghost_node_insert( ghost, slots[i], parent_slots[i] );                                                                              \
  } else {                                                                                                                                 \
    fd_ghost_init( ghost, slots[i] );                                                                                                      \
  }

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
test_ghost_simple( fd_wksp_t * wksp ) {
  ulong  node_max = 8;
  ulong  vote_max = 8;
  void * mem      = fd_wksp_alloc_laddr( wksp, fd_ghost_align(), fd_ghost_footprint( node_max, vote_max ), 1UL );
  FD_TEST( mem );
  fd_ghost_t * ghost = fd_ghost_join( fd_ghost_new( mem, node_max, vote_max, 0UL ) );

  ulong slots[fd_ghost_node_pool_max( ghost->node_pool )];
  ulong parent_slots[fd_ghost_node_pool_max( ghost->node_pool )];
  ulong i = 0;

  INSERT( 0, ULONG_MAX );
  INSERT( 1, 0 );
  INSERT( 2, 1 );
  INSERT( 3, 1 );
  INSERT( 4, 2 );
  INSERT( 5, 3 );
  INSERT( 6, 5 );

  fd_ghost_print( ghost, FD_SLOT_NULL, 0, 0 );

  fd_pubkey_t pk1  = { .key = { 1 } };
  ulong       key2 = 2;
  fd_ghost_replay_vote_upsert( ghost, key2, &pk1, 1 );

  fd_ghost_print( ghost, FD_SLOT_NULL, 0, 0 );

  ulong key3 = 3;
  fd_ghost_replay_vote_upsert( ghost, key3, &pk1, 1 );

  fd_ghost_print( ghost, FD_SLOT_NULL, 0, 0 );

  fd_wksp_free_laddr( mem );
}

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

          ...

         slot 2
           |
         slot 4
*/
void
test_ghost_publish_left( fd_wksp_t * wksp ) {
  ulong  node_max = 8;
  ulong  vote_max = 8;
  void * mem      = fd_wksp_alloc_laddr( wksp, fd_ghost_align(), fd_ghost_footprint( node_max, vote_max ), 1UL );
  FD_TEST( mem );
  fd_ghost_t * ghost = fd_ghost_join( fd_ghost_new( mem, node_max, vote_max, 0UL ) );

  ulong slots[node_max];
  ulong parent_slots[node_max];
  ulong i = 0;

  INSERT( 0, ULONG_MAX );
  INSERT( 1, 0 );
  INSERT( 2, 1 );
  INSERT( 3, 1 );
  INSERT( 4, 2 );
  INSERT( 5, 3 );
  INSERT( 6, 5 );

  fd_pubkey_t pk1  = { .key = { 1 } };
  ulong       key2 = 2;
  fd_ghost_replay_vote_upsert( ghost, key2, &pk1, 1 );

  ulong key3 = 3;
  fd_ghost_replay_vote_upsert( ghost, key3, &pk1, 1 );
  fd_ghost_node_t * node2 = fd_ghost_node_query( ghost, key2 );
  FD_TEST( node2 );

  fd_ghost_print( ghost, FD_SLOT_NULL, 0, 0 );
  fd_ghost_publish( ghost, node2 );
  FD_TEST( ghost->root->slot == 2 );
  FD_TEST( ghost->root->child->slot == 4 );
  FD_TEST( fd_ghost_node_pool_free( ghost->node_pool ) == node_max - 2 );
  fd_ghost_print( ghost, FD_SLOT_NULL, 0, 0 );

  fd_wksp_free_laddr( mem );
}

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

          ...

         slot 3
           |
         slot 5
           |
         slot 6
*/
void
test_ghost_publish_right( fd_wksp_t * wksp ) {
  ulong  node_max = 8;
  ulong  vote_max = 8;
  void * mem      = fd_wksp_alloc_laddr( wksp, fd_ghost_align(), fd_ghost_footprint( node_max, vote_max ), 1UL );
  FD_TEST( mem );
  fd_ghost_t * ghost = fd_ghost_join( fd_ghost_new( mem, node_max, vote_max, 0UL ) );

  ulong slots[node_max];
  ulong parent_slots[node_max];
  ulong i = 0;

  INSERT( 0, ULONG_MAX );
  INSERT( 1, 0 );
  INSERT( 2, 1 );
  INSERT( 3, 1 );
  INSERT( 4, 2 );
  INSERT( 5, 3 );
  INSERT( 6, 5 );

  fd_pubkey_t pk1  = { .key = { 1 } };
  ulong       key2 = 2;
  fd_ghost_replay_vote_upsert( ghost, key2, &pk1, 1 );

  ulong key3 = 3;
  fd_ghost_replay_vote_upsert( ghost, key3, &pk1, 1 );
  fd_ghost_node_t * node3 = fd_ghost_node_query( ghost, key3 );
  FD_TEST( node3 );

  fd_ghost_print( ghost, FD_SLOT_NULL, 0, 0 );
  fd_ghost_publish( ghost, node3 );
  FD_TEST( ghost->root->slot == 3 );
  FD_TEST( ghost->root->child->slot == 5 );
  FD_TEST( ghost->root->child->child->slot == 6 );
  FD_TEST( fd_ghost_node_pool_free( ghost->node_pool ) == node_max - 3 );
  fd_ghost_print( ghost, FD_SLOT_NULL, 0, 0 );

  fd_wksp_free_laddr( mem );
}

void
test_ghost_print( fd_wksp_t * wksp ) {
  ulong  node_max = 16;
  ulong  vote_max = 16;
  void * mem      = fd_wksp_alloc_laddr( wksp, fd_ghost_align(), fd_ghost_footprint( node_max, vote_max ), 1UL );
  FD_TEST( mem );
  fd_ghost_t * ghost = fd_ghost_join( fd_ghost_new( mem, node_max, vote_max, 0UL ) );

  ulong slots[node_max];
  ulong parent_slots[node_max];
  ulong i = 0;

  INSERT( 268538758, ULONG_MAX );
  INSERT( 268538759, 268538758 );
  INSERT( 268538760, 268538759 );
  INSERT( 268538761, 268538758 );

  ulong             query = 268538758;
  fd_ghost_node_t * node  = fd_ghost_node_query( ghost, query );
  node->weight            = 32;

  query        = 268538759;
  node         = fd_ghost_node_query( ghost, query );
  node->weight = 8;

  query        = 268538760;
  node         = fd_ghost_node_query( ghost, query );
  node->weight = 9;

  query        = 268538761;
  node         = fd_ghost_node_query( ghost, query );
  node->weight = 10;

  fd_ghost_print( ghost, query, FD_GHOST_PRINT_DEPTH_DEFAULT, 100 );

  fd_wksp_free_laddr( mem );
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  ulong  page_cnt = 1;
  char * _page_sz = "gigantic";
  ulong  numa_idx = fd_shmem_numa_idx( 0 );
  FD_LOG_NOTICE( ( "Creating workspace (--page-cnt %lu, --page-sz %s, --numa-idx %lu)", page_cnt, _page_sz, numa_idx ) );
  fd_wksp_t * wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  test_ghost_print( wksp );
  test_ghost_simple( wksp );
  test_ghost_publish_left( wksp );
  test_ghost_publish_right( wksp );

  fd_halt();
  return 0;
}
