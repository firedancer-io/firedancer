#include "fd_ghost.h"
#include <math.h>
#include <stdlib.h>

#define INSERT( c, p )                                                                             \
  slots[i]        = c;                                                                             \
  parent_slots[i] = p;                                                                             \
  fd_ghost_insert( ghost, slots[i], parent_slots[i] );                                             \
  i++;

fd_ghost_node_t *
query_mut( fd_ghost_t * ghost, ulong slot ) {
  fd_wksp_t * wksp = fd_wksp_containing( ghost );
  fd_ghost_node_map_t * node_map = fd_wksp_laddr_fast( wksp, ghost->node_map_gaddr );
  fd_ghost_node_t * node_pool = fd_wksp_laddr_fast( wksp, ghost->node_pool_gaddr );
  return fd_ghost_node_map_ele_query( node_map, &slot, NULL, node_pool );
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
  void * mem      = fd_wksp_alloc_laddr( wksp,
                                    fd_ghost_align(),
                                    fd_ghost_footprint( node_max, vote_max ),
                                    1UL );
  FD_TEST( mem );
  fd_ghost_t * ghost = fd_ghost_join( fd_ghost_new( mem, node_max, vote_max, 0UL ) );
  fd_ghost_node_t * node_pool = fd_wksp_laddr_fast( wksp, ghost->node_pool_gaddr );


  ulong slots[fd_ghost_node_pool_max( node_pool )];
  ulong parent_slots[fd_ghost_node_pool_max( node_pool )];
  ulong i = 0;

  fd_ghost_init( ghost, 0, 10 );
  INSERT( 1, 0 );
  INSERT( 2, 1 );
  INSERT( 3, 1 );
  INSERT( 4, 2 );
  INSERT( 5, 3 );
  INSERT( 6, 5 );

  fd_ghost_print( ghost );

  fd_pubkey_t pk1  = { .key = { 1 } };
  ulong       key2 = 2;
  fd_ghost_replay_vote( ghost, key2, &pk1, 1 );

  fd_ghost_print( ghost );

  ulong key3 = 3;
  fd_ghost_replay_vote( ghost, key3, &pk1, 1 );

  fd_ghost_print( ghost );

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
  void * mem      = fd_wksp_alloc_laddr( wksp,
                                    fd_ghost_align(),
                                    fd_ghost_footprint( node_max, vote_max ),
                                    1UL );
  FD_TEST( mem );
  fd_ghost_t * ghost = fd_ghost_join( fd_ghost_new( mem, node_max, vote_max, 0UL ) );
  fd_ghost_node_t * node_pool = fd_wksp_laddr_fast( wksp, ghost->node_pool_gaddr );

  ulong slots[node_max];
  ulong parent_slots[node_max];
  ulong i = 0;

  fd_ghost_init( ghost, 0, 2 );
  INSERT( 1, 0 );
  INSERT( 2, 1 );
  INSERT( 3, 1 );
  INSERT( 4, 2 );
  INSERT( 5, 3 );
  INSERT( 6, 5 );

  FD_TEST( fd_ghost_verify( ghost ) );

  fd_pubkey_t pk1  = { .key = { 1 } };
  ulong       key2 = 2;
  fd_ghost_replay_vote( ghost, key2, &pk1, 1 );

  fd_ghost_print( ghost );

  FD_TEST( fd_ghost_verify( ghost ) );

  ulong key3 = 3;
  fd_ghost_replay_vote( ghost, key3, &pk1, 1 );
  fd_ghost_node_t const * node2 = fd_ghost_query( ghost, key2 );
  FD_TEST( node2 );
  FD_TEST( fd_ghost_verify( ghost ) );

  fd_ghost_print( ghost );
  fd_ghost_publish( ghost, key2 );
  fd_ghost_node_t * root = fd_ghost_node_pool_ele( node_pool, ghost->root_idx );
  FD_TEST( root->slot == 2 );
  FD_TEST( fd_ghost_verify( ghost ) );

  FD_TEST( fd_ghost_node_pool_ele( node_pool, root->child_idx )->slot == 4 );
  FD_TEST( fd_ghost_node_pool_free( node_pool ) == node_max - 2 );
  fd_ghost_print( ghost );

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
  void * mem      = fd_wksp_alloc_laddr( wksp,
                                    fd_ghost_align(),
                                    fd_ghost_footprint( node_max, vote_max ),
                                    1UL );
  FD_TEST( mem );
  fd_ghost_t * ghost = fd_ghost_join( fd_ghost_new( mem, node_max, vote_max, 0UL ) );
  fd_ghost_node_t * node_pool = fd_wksp_laddr_fast( wksp, ghost->node_pool_gaddr );

  ulong slots[node_max];
  ulong parent_slots[node_max];
  ulong i = 0;

  fd_ghost_init( ghost, 0, 2 );
  INSERT( 1, 0 );
  INSERT( 2, 1 );
  INSERT( 3, 1 );
  INSERT( 4, 2 );
  INSERT( 5, 3 );
  INSERT( 6, 5 );
  FD_TEST( fd_ghost_verify( ghost ) );

  fd_pubkey_t pk1  = { .key = { 1 } };
  ulong       key2 = 2;
  fd_ghost_replay_vote( ghost, key2, &pk1, 1 );
  FD_TEST( fd_ghost_verify( ghost ) );

  ulong key3 = 3;
  fd_ghost_replay_vote( ghost, key3, &pk1, 1 );
  FD_TEST( fd_ghost_verify( ghost ) );
  fd_ghost_node_t const * node3 = fd_ghost_query( ghost, key3 );
  FD_TEST( node3 );

  fd_ghost_print( ghost );
  fd_ghost_publish( ghost, key3 );
  FD_TEST( fd_ghost_verify( ghost ) );

  fd_ghost_node_t * root = fd_ghost_node_pool_ele( node_pool, ghost->root_idx );
  FD_TEST( root->slot == 3 );
  FD_TEST( fd_ghost_node_pool_ele( node_pool, root->child_idx )->slot == 5 );
  FD_TEST( fd_ghost_child_node( ghost, fd_ghost_child_node( ghost, root ) )->slot == 6 );
  FD_TEST( fd_ghost_node_pool_free( node_pool ) == node_max - 3 );
  fd_ghost_print( ghost );

  fd_wksp_free_laddr( mem );
}

void
test_ghost_gca( fd_wksp_t * wksp ) {
  ulong  node_max = 8;
  ulong  vote_max = 8;
  void * mem      = fd_wksp_alloc_laddr( wksp,
                                    fd_ghost_align(),
                                    fd_ghost_footprint( node_max, vote_max ),
                                    1UL );
  FD_TEST( mem );
  fd_ghost_t * ghost = fd_ghost_join( fd_ghost_new( mem, node_max, vote_max, 0UL ) );
  fd_ghost_node_t * node_pool = fd_wksp_laddr_fast( wksp, ghost->node_pool_gaddr );

  ulong slots[fd_ghost_node_pool_max( node_pool )];
  ulong parent_slots[fd_ghost_node_pool_max( node_pool )];
  ulong i = 0;

  fd_ghost_init( ghost, 0, 0 );
  INSERT( 1, 0 );
  INSERT( 2, 1 );
  INSERT( 3, 1 );
  INSERT( 4, 2 );
  INSERT( 5, 3 );
  INSERT( 6, 5 );
  FD_TEST( fd_ghost_verify( ghost ) );

  fd_ghost_print( ghost );

  FD_TEST( fd_ghost_gca( ghost, 0, 0 )->slot == 0 );

  FD_TEST( fd_ghost_gca( ghost, 0, 1 )->slot == 0 );
  FD_TEST( fd_ghost_gca( ghost, 1, 1 )->slot == 1 );

  FD_TEST( fd_ghost_gca( ghost, 0, 2 )->slot == 0 );
  FD_TEST( fd_ghost_gca( ghost, 1, 2 )->slot == 1 );
  FD_TEST( fd_ghost_gca( ghost, 2, 2 )->slot == 2 );

  FD_TEST( fd_ghost_gca( ghost, 0, 3 )->slot == 0 );
  FD_TEST( fd_ghost_gca( ghost, 1, 3 )->slot == 1 );
  FD_TEST( fd_ghost_gca( ghost, 2, 3 )->slot == 1 );
  FD_TEST( fd_ghost_gca( ghost, 3, 3 )->slot == 3 );

  FD_TEST( fd_ghost_gca( ghost, 0, 4 )->slot == 0 );
  FD_TEST( fd_ghost_gca( ghost, 1, 4 )->slot == 1 );
  FD_TEST( fd_ghost_gca( ghost, 2, 4 )->slot == 2 );
  FD_TEST( fd_ghost_gca( ghost, 3, 4 )->slot == 1 );
  FD_TEST( fd_ghost_gca( ghost, 4, 4 )->slot == 4 );

  FD_TEST( fd_ghost_gca( ghost, 0, 5 )->slot == 0 );
  FD_TEST( fd_ghost_gca( ghost, 1, 5 )->slot == 1 );
  FD_TEST( fd_ghost_gca( ghost, 2, 5 )->slot == 1 );
  FD_TEST( fd_ghost_gca( ghost, 3, 5 )->slot == 3 );
  FD_TEST( fd_ghost_gca( ghost, 4, 5 )->slot == 1 );
  FD_TEST( fd_ghost_gca( ghost, 6, 5 )->slot == 5 );

  FD_TEST( fd_ghost_gca( ghost, 0, 6 )->slot == 0 );
  FD_TEST( fd_ghost_gca( ghost, 1, 6 )->slot == 1 );
  FD_TEST( fd_ghost_gca( ghost, 2, 6 )->slot == 1 );
  FD_TEST( fd_ghost_gca( ghost, 3, 6 )->slot == 3 );
  FD_TEST( fd_ghost_gca( ghost, 4, 6 )->slot == 1 );
  FD_TEST( fd_ghost_gca( ghost, 5, 6 )->slot == 5 );
  FD_TEST( fd_ghost_gca( ghost, 6, 6 )->slot == 6 );
}

void
test_ghost_print( fd_wksp_t * wksp ) {
  ulong  node_max = 16;
  ulong  vote_max = 16;
  void * mem      = fd_wksp_alloc_laddr( wksp,
                                    fd_ghost_align(),
                                    fd_ghost_footprint( node_max, vote_max ),
                                    1UL );
  FD_TEST( mem );
  fd_ghost_t * ghost = fd_ghost_join( fd_ghost_new( mem, node_max, vote_max, 0UL ) );

  ulong slots[node_max];
  ulong parent_slots[node_max];
  ulong i = 0;

  fd_ghost_init( ghost, 268538758, 100 );
  INSERT( 268538759, 268538758 );
  INSERT( 268538760, 268538759 );
  INSERT( 268538761, 268538758 );

  fd_ghost_node_t * node;
  ulong             query;

  query        = 268538758;
  node         = query_mut( ghost, query );
  node->weight = 32;

  query        = 268538759;
  node         = query_mut( ghost, query );
  node->weight = 8;

  query        = 268538760;
  node         = query_mut( ghost, query );
  node->weight = 9;

  query        = 268538761;
  node         = query_mut( ghost, query );
  node->weight = 10;
  FD_TEST( fd_ghost_verify( ghost ) );

  fd_ghost_slot_print( ghost, query, 8 );
  fd_ghost_print( ghost );

  fd_wksp_free_laddr( mem );
}


/*
         slot 10
         /    \
    slot 11    |
       |    slot 12
    slot 13    
*/

void
test_ghost_head( fd_wksp_t * wksp ){
  ulong  node_max = 16;
  ulong  vote_max = 16;
  void * mem      = fd_wksp_alloc_laddr( wksp,
                                    fd_ghost_align(),
                                    fd_ghost_footprint( node_max, vote_max ),
                                    1UL );
  FD_TEST( mem );
  fd_ghost_t * ghost = fd_ghost_join( fd_ghost_new( mem, node_max, vote_max, 0UL ) );

  ulong slots[node_max];
  ulong parent_slots[node_max];
  ulong i = 0;

  fd_ghost_init( ghost, 10, 150 );
  INSERT( 11, 10 );
  INSERT( 12, 10 );
  INSERT( 13, 11 );

  fd_pubkey_t pk1  = { .key = { 1 } };
  ulong       key11 = 11;
  fd_ghost_replay_vote( ghost, key11, &pk1, 50 );
  FD_TEST( fd_ghost_verify( ghost ) );

  fd_pubkey_t pk2  = { .key = { 2 } };
  ulong       key12 = 12;
  fd_ghost_replay_vote( ghost, key12, &pk2, 100);
  FD_TEST( fd_ghost_verify( ghost ) );

  fd_ghost_node_t const * head = fd_ghost_head( ghost );
  FD_TEST( head->slot == 12 );

  ulong key13 = 13;
  fd_ghost_replay_vote( ghost, key13, &pk1, 75); // different stake than it was inserted with...
  FD_TEST( fd_ghost_verify( ghost ) );

  fd_ghost_node_t const * head2 = fd_ghost_head( ghost );
  FD_TEST( head2->slot == 12 );

  fd_ghost_print( ghost );

  fd_wksp_free_laddr( mem );
}

void test_ghost_vote_leaves( fd_wksp_t * wksp ){
  ulong node_max = 8;
  ulong vote_max = 8;
  int depth = 3;

  void * mem = fd_wksp_alloc_laddr( wksp,
                                    fd_ghost_align(),
                                    fd_ghost_footprint( node_max, vote_max ),
                                    1UL );
  FD_TEST( mem ); 
  fd_ghost_t * ghost = fd_ghost_join( fd_ghost_new( mem, node_max, vote_max, 0UL ) );

  fd_ghost_init( ghost, 0, 40 );
  fd_pubkey_t pk = { .key = { 0 } };

  /* make a full binary tree */
  for( ulong i = 1; i < node_max - 1; i++){
    fd_ghost_insert( ghost, i, (i - 1) / 2 );
  }

  /* one validator changes votes along leaves */
  ulong first_leaf = (ulong) (pow(2, (depth - 1)) - 1);
  for( ulong i = first_leaf; i < node_max - 1; i++){
    fd_ghost_replay_vote( ghost, i, &pk, 10);
  }

  fd_ghost_print( ghost );

  ulong path[depth];
  ulong leaf = node_max - 2;
  for( int i = depth - 1; i >= 0; i--){
    path[i] = leaf;
    leaf = (leaf - 1) / 2;
  }

  /* check weights and stakes */
  int j = 0;
  for( ulong i = 0; i < node_max - 1; i++){
    fd_ghost_node_t const * node = fd_ghost_query( ghost, i );
    if ( i == node_max - 2) FD_TEST( node->stake == 10 );
    else  FD_TEST( node->stake == 0 );

    if ( i == path[j] ){ // if on fork
      FD_TEST( node->weight == 10 );
      j++;
    } else {
      FD_TEST( node->weight == 0 );
    }
  }

  /* have other validators vote for rest of leaves */
  for ( ulong i = first_leaf; i < node_max - 2; i++){
    fd_pubkey_t pk = { .key = { (uchar)i } };
    fd_ghost_replay_vote( ghost, i, &pk, 10);
  }

  /* check weights and stakes */
  for( ulong i = 0; i < node_max - 1; i++){
    fd_ghost_node_t const * node = fd_ghost_query( ghost, i );
    if ( i >= first_leaf){
      FD_TEST( node->stake == 10 );
      FD_TEST( node->weight == 10 );
    } else {
      FD_TEST( node->stake == 0 );
      FD_TEST( node->weight > 10);
    }
  }

  FD_TEST( fd_ghost_verify( ghost ) );
  fd_ghost_print( ghost );
}

void
test_ghost_head_full_tree( fd_wksp_t * wksp ){
  ulong  node_max = 16;
  ulong  vote_max = 16;
  void * mem      = fd_wksp_alloc_laddr( wksp,
                                    fd_ghost_align(),
                                    fd_ghost_footprint( node_max, vote_max ),
                                    1UL );
  FD_TEST( mem );
  fd_ghost_t * ghost = fd_ghost_join( fd_ghost_new( mem, node_max, vote_max, 0UL ) );

  fd_ghost_init( ghost, 0, 120 );
  FD_LOG_NOTICE(( "ghost node max: %lu", fd_ghost_node_pool_max( fd_ghost_node_pool( ghost ) ) ));

  for ( ulong i = 1; i < node_max - 1; i++ ) {
    fd_ghost_insert( ghost, i,  (i - 1)/2);
    fd_pubkey_t pk = { .key = { ( uchar )i } };
    fd_ghost_replay_vote( ghost, i, &pk, i);
  }

  for ( ulong i = 0; i < node_max - 1; i++ ) {
    fd_ghost_node_t const * node = fd_ghost_query( ghost, i );
    FD_TEST( node->stake == i );
  }

  FD_TEST( fd_ghost_verify( ghost ) );

  fd_ghost_print( ghost );
  fd_ghost_node_t const * head = fd_ghost_head( ghost );

  FD_LOG_NOTICE(( "head slot %lu", head->slot ));

  // head will always be rightmost node in this complete binary tree

  FD_TEST( head->slot == 14 );

  // add one more node

  fd_ghost_insert( ghost, node_max - 1, (node_max - 2)/2 );
  fd_pubkey_t pk = { .key = { (uchar)(node_max - 1) } };
  fd_ghost_replay_vote( ghost, node_max - 1, &pk, node_max - 1);

  FD_TEST( fd_ghost_verify( ghost ) );
  head = fd_ghost_head( ghost );
  FD_TEST( head->slot == 14 );

  // adding one more node would fail.
}

void 
test_rooted_vote( fd_wksp_t * wksp ){
  ulong node_max = 16; 
  ulong vote_max = 16;
  void * mem = fd_wksp_alloc_laddr( wksp,
                                    fd_ghost_align(),
                                    fd_ghost_footprint( node_max, vote_max ),
                                    1UL );
  FD_TEST( mem );
  fd_ghost_t * ghost = fd_ghost_join( fd_ghost_new( mem, node_max, vote_max, 0UL ) );

  fd_ghost_init( ghost, 0, 120 );

  fd_ghost_insert( ghost, 1, 0);
  fd_pubkey_t pk = { .key = { 1 } };
  fd_ghost_replay_vote( ghost, 1, &pk, 20);

  fd_pubkey_t pk2 = { .key = { 2 } }; 
  fd_ghost_rooted_vote( ghost, 1, &pk2, 10 );

  fd_ghost_node_t const * node = fd_ghost_query( ghost, 1 );
  FD_TEST( node->stake == 20 );
  FD_TEST( node->weight == 20 );
  FD_TEST( node->rooted_stake == 10 );

  fd_ghost_verify( ghost );
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
  fd_wksp_t * wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ),
                                            page_cnt,
                                            fd_shmem_cpu_idx( numa_idx ),
                                            "wksp",
                                            0UL );
  FD_TEST( wksp );

  test_ghost_print( wksp );
  test_ghost_simple( wksp );
  test_ghost_publish_left( wksp );
  test_ghost_publish_right( wksp );
  test_ghost_gca( wksp );
  test_ghost_vote_leaves( wksp );
  test_ghost_head_full_tree( wksp );
  test_ghost_head( wksp );
  test_rooted_vote( wksp );

  fd_halt();
  return 0;
}
