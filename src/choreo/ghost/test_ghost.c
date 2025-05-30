#include "fd_ghost.h"
#include "../epoch/fd_epoch.h"

#include <stdarg.h>

#define INSERT( c, p )                                                                             \
  slots[i]        = c;                                                                             \
  parent_slots[i] = p;                                                                             \
  fd_ghost_insert( ghost, parent_slots[i], slots[i] );                                             \
  i++;

fd_ghost_node_t *
query_mut( fd_ghost_t * ghost, ulong slot ) {
  fd_wksp_t * wksp = fd_wksp_containing( ghost );
  fd_ghost_node_map_t * node_map = fd_wksp_laddr_fast( wksp, ghost->node_map_gaddr );
  fd_ghost_node_t * node_pool = fd_wksp_laddr_fast( wksp, ghost->node_pool_gaddr );
  return fd_ghost_node_map_ele_query( node_map, &slot, NULL, node_pool );
}

fd_epoch_t *
mock_epoch( fd_wksp_t * wksp, ulong total_stake, ulong voter_cnt, ... ) {
  void * epoch_mem = fd_wksp_alloc_laddr( wksp, fd_epoch_align(), fd_epoch_footprint( voter_cnt ), 1UL );
  FD_TEST( epoch_mem );
  fd_epoch_t * epoch = fd_epoch_join( fd_epoch_new( epoch_mem, voter_cnt ) );
  FD_TEST( epoch );

  va_list ap;
  va_start( ap, voter_cnt );
  for( ulong i = 0; i < voter_cnt; i++ ) {
    fd_pubkey_t key = va_arg( ap, fd_pubkey_t );
    fd_voter_t * voter = fd_epoch_voters_insert( fd_epoch_voters( epoch ), key );
    voter->stake       = va_arg( ap, ulong );
    voter->replay_vote = FD_SLOT_NULL;
  }
  va_end( ap );

  epoch->total_stake = total_stake;
  return epoch;
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

  void * mem = fd_wksp_alloc_laddr( wksp, fd_ghost_align(), fd_ghost_footprint( node_max ), 1UL );
  FD_TEST( mem );
  fd_ghost_t * ghost = fd_ghost_join( fd_ghost_new( mem, 0UL, node_max ) );
  fd_ghost_node_t * node_pool = fd_wksp_laddr_fast( wksp, ghost->node_pool_gaddr );

  ulong slots[fd_ghost_node_pool_max( node_pool )];
  ulong parent_slots[fd_ghost_node_pool_max( node_pool )];
  ulong i = 0;

  fd_ghost_init( ghost, 0 );
  INSERT( 1, 0 );
  INSERT( 2, 1 );
  INSERT( 3, 1 );
  INSERT( 4, 2 );
  INSERT( 5, 3 );
  INSERT( 6, 5 );
  FD_TEST( !fd_ghost_verify( ghost ) );

  fd_pubkey_t  key   = { .key = { 1 } };
  fd_epoch_t * epoch = mock_epoch( wksp, 10, 1, key, 1 );
  fd_voter_t * voter = fd_epoch_voters_query( fd_epoch_voters( epoch ), key, NULL );

  fd_ghost_print( ghost, epoch, fd_ghost_root( ghost ) );
  fd_ghost_replay_vote( ghost, voter, 2 );
  fd_ghost_print( ghost, epoch, fd_ghost_root( ghost ) );
  fd_ghost_replay_vote( ghost, voter, 3 );
  fd_ghost_print( ghost, epoch, fd_ghost_root( ghost ) );

  fd_wksp_free_laddr( fd_epoch_delete( fd_epoch_leave( epoch ) ) );
  fd_wksp_free_laddr( fd_ghost_delete( fd_ghost_leave( ghost ) ) );
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
  void * mem      = fd_wksp_alloc_laddr( wksp,
                                    fd_ghost_align(),
                                    fd_ghost_footprint( node_max ),
                                    1UL );
  FD_TEST( mem );
  fd_ghost_t * ghost = fd_ghost_join( fd_ghost_new( mem, 0UL, node_max ) );
  fd_ghost_node_t * node_pool = fd_wksp_laddr_fast( wksp, ghost->node_pool_gaddr );

  ulong slots[node_max];
  ulong parent_slots[node_max];
  ulong i = 0;

  fd_ghost_init( ghost, 0 );
  INSERT( 1, 0 );
  INSERT( 2, 1 );
  INSERT( 3, 1 );
  INSERT( 4, 2 );
  INSERT( 5, 3 );
  INSERT( 6, 5 );
  FD_TEST( !fd_ghost_verify( ghost ) );

  fd_pubkey_t  pk1   = { { 1 } };
  fd_epoch_t * epoch = mock_epoch( wksp, 2, 1, pk1, 1 );
  fd_voter_t * v1    = fd_epoch_voters_query( fd_epoch_voters( epoch ), pk1, NULL );

  fd_ghost_replay_vote( ghost, v1, 2 );
  fd_ghost_print( ghost, epoch, fd_ghost_root( ghost ) );
  FD_TEST( !fd_ghost_verify( ghost ) );

  fd_ghost_replay_vote( ghost, v1, 3 );
  fd_ghost_node_t const * node2 = fd_ghost_query( ghost, 2 );
  FD_TEST( node2 );
  FD_TEST( !fd_ghost_verify( ghost ) );

  fd_ghost_print( ghost, epoch, fd_ghost_root( ghost ) );
  fd_ghost_publish( ghost, 2 );
  fd_ghost_node_t const * root = fd_ghost_root( ghost );
  FD_TEST( root->slot == 2 );

  fd_ghost_node_map_t * node_map = fd_ghost_node_map( ghost );
  for( fd_ghost_node_map_iter_t iter = fd_ghost_node_map_iter_init( node_map, node_pool );
       !fd_ghost_node_map_iter_done( iter, node_map, node_pool );
       iter = fd_ghost_node_map_iter_next( iter, node_map, node_pool ) ) {
    fd_ghost_node_t const * node = fd_ghost_node_map_iter_ele( iter, node_map, node_pool );
    FD_LOG_NOTICE(("slot: %lu", node->slot));
  }

  FD_TEST( !fd_ghost_verify( ghost ) );

  FD_TEST( fd_ghost_node_pool_ele( node_pool, root->child_idx )->slot == 4 );
  FD_TEST( fd_ghost_node_pool_free( node_pool ) == node_max - 2 );
  fd_ghost_print( ghost, epoch, fd_ghost_root( ghost ) );

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
  void * mem      = fd_wksp_alloc_laddr( wksp,
                                    fd_ghost_align(),
                                    fd_ghost_footprint( node_max ),
                                    1UL );
  FD_TEST( mem );
  fd_ghost_t * ghost = fd_ghost_join( fd_ghost_new( mem, 0UL, node_max ) );
  fd_ghost_node_t * node_pool = fd_wksp_laddr_fast( wksp, ghost->node_pool_gaddr );

  ulong slots[node_max];
  ulong parent_slots[node_max];
  ulong i = 0;

  fd_ghost_init( ghost, 0 );
  INSERT( 1, 0 );
  INSERT( 2, 1 );
  INSERT( 3, 1 );
  INSERT( 4, 2 );
  INSERT( 5, 3 );
  INSERT( 6, 5 );
  FD_TEST( !fd_ghost_verify( ghost ) );

  fd_pubkey_t  pk1   = { { 1 } };
  fd_epoch_t * epoch = mock_epoch( wksp, 2, 1, pk1, 1 );
  fd_voter_t * v1    = fd_epoch_voters_query( fd_epoch_voters( epoch ), pk1, NULL );

  fd_ghost_replay_vote( ghost, v1, 2 );
  FD_TEST( !fd_ghost_verify( ghost ) );

  fd_ghost_replay_vote( ghost, v1, 3 );
  FD_TEST( !fd_ghost_verify( ghost ) );
  fd_ghost_node_t const * node3 = fd_ghost_query( ghost, 3 );
  FD_TEST( node3 );

  fd_ghost_print( ghost, epoch, fd_ghost_root( ghost ) );
  fd_ghost_publish( ghost, 3 );
  FD_TEST( !fd_ghost_verify( ghost ) );

  fd_ghost_node_t * root = fd_ghost_node_pool_ele( node_pool, ghost->root_idx );
  FD_TEST( root->slot == 3 );
  FD_TEST( fd_ghost_node_pool_ele( node_pool, root->child_idx )->slot == 5 );
  FD_TEST( fd_ghost_child( ghost, fd_ghost_child( ghost, root ) )->slot == 6 );
  FD_TEST( fd_ghost_node_pool_free( node_pool ) == node_max - 3 );
  fd_ghost_print( ghost, epoch, fd_ghost_root( ghost ) );

  fd_wksp_free_laddr( mem );
}

void
test_ghost_gca( fd_wksp_t * wksp ) {
  ulong  node_max = 8;
  void * mem      = fd_wksp_alloc_laddr( wksp,
                                    fd_ghost_align(),
                                    fd_ghost_footprint( node_max ),
                                    1UL );
  FD_TEST( mem );
  fd_ghost_t * ghost = fd_ghost_join( fd_ghost_new( mem, 0UL, node_max ) );
  fd_ghost_node_t * node_pool = fd_wksp_laddr_fast( wksp, ghost->node_pool_gaddr );

  ulong slots[fd_ghost_node_pool_max( node_pool )];
  ulong parent_slots[fd_ghost_node_pool_max( node_pool )];
  ulong i = 0;

  fd_ghost_init( ghost, 0 );
  INSERT( 1, 0 );
  INSERT( 2, 1 );
  INSERT( 3, 1 );
  INSERT( 4, 2 );
  INSERT( 5, 3 );
  INSERT( 6, 5 );
  FD_TEST( !fd_ghost_verify( ghost ) );

  fd_epoch_t * epoch = mock_epoch( wksp, 0, 0 );
  fd_ghost_print( ghost, epoch, fd_ghost_root( ghost ) );

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
  void * mem      = fd_wksp_alloc_laddr( wksp,
                                    fd_ghost_align(),
                                    fd_ghost_footprint( node_max ),
                                    1UL );
  FD_TEST( mem );
  fd_ghost_t * ghost = fd_ghost_join( fd_ghost_new( mem, 0UL, node_max ) );

  ulong slots[node_max];
  ulong parent_slots[node_max];
  ulong i = 0;

  fd_epoch_t * epoch = mock_epoch( wksp, 300, 0 );

  fd_ghost_init( ghost, 268538758 );
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
  FD_TEST( !fd_ghost_verify( ghost ) );

  fd_ghost_node_t const * grandparent = fd_ghost_parent( ghost, fd_ghost_parent( ghost, fd_ghost_query( ghost, 268538760 ) ) );
  fd_ghost_print( ghost, epoch, grandparent );

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
  void * mem      = fd_wksp_alloc_laddr( wksp, fd_ghost_align(), fd_ghost_footprint( node_max ), 1UL );
  FD_TEST( mem );
  fd_ghost_t * ghost = fd_ghost_join( fd_ghost_new( mem, 0UL, node_max ) );

  ulong slots[node_max];
  ulong parent_slots[node_max];
  ulong i = 0;

  fd_pubkey_t  pk1   = { { 1 } };
  fd_pubkey_t  pk2   = { { 2 } };
  fd_epoch_t * epoch = mock_epoch( wksp, 150, 2, pk1, 50, pk2, 100 );
  fd_voter_t * v1    = fd_epoch_voters_query( fd_epoch_voters( epoch ), pk1, NULL );
  fd_voter_t * v2    = fd_epoch_voters_query( fd_epoch_voters( epoch ), pk2, NULL );

  fd_ghost_init( ghost, 10 );
  INSERT( 11, 10 );
  INSERT( 12, 10 );
  INSERT( 13, 11 );

  fd_ghost_replay_vote( ghost, v1, 11 );
  FD_TEST( !fd_ghost_verify( ghost ) );

  fd_ghost_replay_vote( ghost, v2, 12 );
  FD_TEST( !fd_ghost_verify( ghost ) );

  fd_ghost_node_t const * head = fd_ghost_head( ghost, fd_ghost_root( ghost ) );
  FD_TEST( head->slot == 12 );

  fd_ghost_replay_vote( ghost, v1, 13 );
  FD_TEST( !fd_ghost_verify( ghost ) );

  fd_ghost_node_t const * head2 = fd_ghost_head( ghost, fd_ghost_root( ghost ) );
  FD_TEST( head2->slot == 12 );

  fd_ghost_print( ghost, epoch, fd_ghost_root( ghost ) );

  fd_wksp_free_laddr( mem );
}

void
test_ghost_vote_leaves( fd_wksp_t * wksp ) {
  ulong node_max = 8;
  int d = 3;

  void * mem = fd_wksp_alloc_laddr( wksp,
                                    fd_ghost_align(),
                                    fd_ghost_footprint( node_max ),
                                    1UL );
  FD_TEST( mem );
  fd_ghost_t * ghost = fd_ghost_join( fd_ghost_new( mem, 0UL, node_max ) );

  fd_ghost_init( ghost, 0 );
  fd_epoch_t * epoch = mock_epoch( wksp, 40, 0 );

  /* make a full binary tree */
  for( ulong i = 1; i < node_max - 1; i++){
    fd_ghost_insert( ghost, (i-1)/2, i );
  }

  /* one validator changes votes along leaves */
  ulong first_leaf = fd_ulong_pow2(d-1) - 1;
  fd_voter_t v = { .key = { { 0 } }, .stake = 10, .replay_vote = FD_SLOT_NULL };
  for( ulong i = first_leaf; i < node_max - 1; i++){
    fd_ghost_replay_vote( ghost, &v, i );
    v.replay_vote = i;
  }

  fd_ghost_print( ghost, epoch, fd_ghost_root( ghost ) );

  ulong path[d];
  ulong leaf = node_max - 2;
  for( int i = d - 1; i >= 0; i--){
    path[i] = leaf;
    leaf = (leaf - 1) / 2;
  }

  /* check weights and stakes */
  int j = 0;
  for( ulong i = 0; i < node_max - 1; i++){
    fd_ghost_node_t const * node = fd_ghost_query( ghost, i );
    if ( i == node_max - 2) FD_TEST( node->replay_stake == 10 );
    else  FD_TEST( node->replay_stake == 0 );

    if ( i == path[j] ){ // if on fork
      FD_TEST( node->weight == 10 );
      j++;
    } else {
      FD_TEST( node->weight == 0 );
    }
  }

  /* have other validators vote for rest of leaves */
  for ( ulong i = first_leaf; i < node_max - 2; i++){
    fd_voter_t v = { .key = { { (uchar)i } }, .stake = 10, .replay_vote = FD_SLOT_NULL };
    fd_ghost_replay_vote( ghost, &v, i );
  }

  /* check weights and stakes */
  for( ulong i = 0; i < node_max - 1; i++){
    fd_ghost_node_t const * node = fd_ghost_query( ghost, i );
    if ( i >= first_leaf){
      FD_TEST( node->replay_stake == 10 );
      FD_TEST( node->weight == 10 );
    } else {
      FD_TEST( node->replay_stake == 0 );
      FD_TEST( node->weight > 10);
    }
  }

  FD_TEST( !fd_ghost_verify( ghost ) );
  fd_ghost_print( ghost, epoch, fd_ghost_root( ghost ) );
}

void
test_ghost_old_vote_pruned( fd_wksp_t * wksp ){
  ulong node_max = 16;
  void * mem      = fd_wksp_alloc_laddr( wksp,
    fd_ghost_align(),
    fd_ghost_footprint( node_max ),
    1UL );
  FD_TEST( mem );
  fd_ghost_t * ghost = fd_ghost_join( fd_ghost_new( mem, 0UL, node_max ) );
  fd_epoch_t * epoch = mock_epoch( wksp, 0, 0 );

  fd_ghost_init( ghost, 0 );
  for ( ulong i = 1; i < node_max - 1; i++ ) {
    fd_ghost_insert( ghost, (i-1)/2, i );
    fd_voter_t v = { .key = { { (uchar)i } }, .stake = i, .replay_vote = FD_SLOT_NULL };
    fd_ghost_replay_vote( ghost, &v, i );
  }

  fd_ghost_publish( ghost, 1);
  fd_ghost_print( ghost, epoch, fd_ghost_root( ghost ) );

  fd_voter_t switch_voter = { .key = { { 5 } }, .stake = 5, .replay_vote = 5 };
  fd_ghost_replay_vote( ghost, &switch_voter, 9 );
  /* switching to vote 9, from voting 5, that is > than the root */
  fd_ghost_print( ghost, epoch, fd_ghost_root( ghost ) );

  FD_TEST( fd_ghost_query( ghost, 9 )->weight == 14 );
  FD_TEST( fd_ghost_query( ghost, 3 )->weight == 18 );
  FD_TEST( fd_ghost_query( ghost, 4 )->weight == 28 );
  FD_TEST( fd_ghost_query( ghost, 1 )->weight == 47 ); /* full tree */

  FD_TEST( !fd_ghost_verify( ghost ) );

  fd_ghost_publish( ghost, 3 ); /* cut down to nodes 3,7,8 */
  /* now previously voted 2 ( < the root ) votes for 7 */
  fd_voter_t switch_voter2 = { .key = { { 2 } }, .stake = 2, .replay_vote = 2 };
  fd_ghost_replay_vote( ghost, &switch_voter2, 7 );

  fd_ghost_print( ghost, epoch, fd_ghost_root( ghost ) );
  FD_TEST( fd_ghost_query( ghost, 7 )->weight == 9 );
  FD_TEST( fd_ghost_query( ghost, 8 )->weight == 8 );
  FD_TEST( fd_ghost_query( ghost, 3 )->weight == 20 );

  FD_TEST( !fd_ghost_verify( ghost ) );
}

void
test_ghost_head_full_tree( fd_wksp_t * wksp ){
  ulong  node_max = 16;
  void * mem      = fd_wksp_alloc_laddr( wksp,
                                    fd_ghost_align(),
                                    fd_ghost_footprint( node_max ),
                                    1UL );
  FD_TEST( mem );
  fd_ghost_t * ghost = fd_ghost_join( fd_ghost_new( mem, 0UL, node_max ) );

  fd_epoch_t * epoch = mock_epoch( wksp, 120, 0 );

  fd_ghost_init( ghost, 0 );
  FD_LOG_NOTICE(( "ghost node max: %lu", fd_ghost_node_pool_max( fd_ghost_node_pool( ghost ) ) ));

  for ( ulong i = 1; i < node_max - 1; i++ ) {
    fd_ghost_insert( ghost, (i-1)/2, i );
    fd_voter_t v = { .key = { { (uchar)i } }, .stake = i, .replay_vote = FD_SLOT_NULL };
    fd_ghost_replay_vote( ghost, &v, i );
  }

  for ( ulong i = 0; i < node_max - 1; i++ ) {
    fd_ghost_node_t const * node = fd_ghost_query( ghost, i );
    FD_TEST( node->replay_stake == i );
  }

  FD_TEST( !fd_ghost_verify( ghost ) );

  fd_ghost_print( ghost, epoch, fd_ghost_root( ghost ) );
  fd_ghost_node_t const * head = fd_ghost_head( ghost, fd_ghost_root( ghost ) );

  FD_LOG_NOTICE(( "head slot %lu", head->slot ));

  // head will always be rightmost node in this complete binary tree

  FD_TEST( head->slot == 14 );

  // add one more node

  fd_ghost_insert( ghost, (node_max-2)/2, node_max - 1 );
  fd_voter_t v = { .key = { { (uchar)( node_max - 1 ) } }, .stake = node_max - 1, .replay_vote = FD_SLOT_NULL };
  fd_ghost_replay_vote( ghost, &v, node_max - 1);

  FD_TEST( !fd_ghost_verify( ghost ) );
  head = fd_ghost_head( ghost, fd_ghost_root( ghost ) );
  FD_TEST( head->slot == 14 );

  // adding one more node would fail.
}

void
test_rooted_vote( fd_wksp_t * wksp ){
  ulong node_max = 16;
  void * mem = fd_wksp_alloc_laddr( wksp,
                                    fd_ghost_align(),
                                    fd_ghost_footprint( node_max ),
                                    1UL );
  FD_TEST( mem );
  fd_ghost_t * ghost = fd_ghost_join( fd_ghost_new( mem, 0UL, node_max ) );

  fd_pubkey_t  pk1   = { .key = { 1 } };
  fd_pubkey_t  pk2   = { .key = { 2 } };
  fd_epoch_t * epoch = mock_epoch( wksp, 120, 2, pk1, 20, pk2, 10 );
  fd_voter_t * v1    = fd_epoch_voters_query( fd_epoch_voters( epoch ), pk1, NULL );
  fd_voter_t * v2    = fd_epoch_voters_query( fd_epoch_voters( epoch ), pk2, NULL );

  fd_ghost_init( ghost, 0 );

  fd_ghost_insert( ghost, 0, 1);
  fd_ghost_replay_vote( ghost, v1, 1 );

  fd_ghost_rooted_vote( ghost, v2, 1 );

  fd_ghost_node_t const * node = fd_ghost_query( ghost, 1 );
  FD_TEST( node->replay_stake == 20 );
  FD_TEST( node->weight == 20 );
  FD_TEST( node->rooted_stake == 10 );

  FD_TEST( !fd_ghost_verify( ghost ) );
}

/*
         slot 10
         /    \
    slot 11    |
       |    slot 12
    slot 13
*/

void
test_ghost_head_valid( fd_wksp_t * wksp ) {
  ulong  node_max = 16;
  void * mem      = fd_wksp_alloc_laddr( wksp, fd_ghost_align(), fd_ghost_footprint( node_max ), 1UL );
  FD_TEST( mem );
  fd_ghost_t * ghost = fd_ghost_join( fd_ghost_new( mem, 0UL, node_max ) );

  ulong slots[node_max];
  ulong parent_slots[node_max];
  ulong i = 0;

  fd_pubkey_t  pk1   = { { 1 } };
  fd_pubkey_t  pk2   = { { 2 } };
  fd_epoch_t * epoch = mock_epoch( wksp, 150, 2, pk1, 50, pk2, 100 );
  fd_voter_t * v1    = fd_epoch_voters_query( fd_epoch_voters( epoch ), pk1, NULL );
  fd_voter_t * v2    = fd_epoch_voters_query( fd_epoch_voters( epoch ), pk2, NULL );

  fd_ghost_init( ghost, 10 );
  INSERT( 11, 10 );
  INSERT( 12, 10 );
  INSERT( 13, 11 );

  fd_ghost_replay_vote( ghost, v1, 11 );
  FD_TEST( !fd_ghost_verify( ghost ) );

  fd_ghost_replay_vote( ghost, v2, 12 );
  FD_TEST( !fd_ghost_verify( ghost ) );

  // fd_ghost_node_t const * head = fd_ghost_head( ghost, fd_ghost_root( ghost ) );
  // FD_TEST( head->slot == 12 );

  fd_ghost_replay_vote( ghost, v1, 13 );
  FD_TEST( !fd_ghost_verify( ghost ) );

  // fd_ghost_node_t const * head2 = fd_ghost_head( ghost, fd_ghost_root( ghost ) );
  // FD_TEST( head2->slot == 12 );

  query_mut( ghost, 12 )->valid = 0; // mark 12 as invalid
  // fd_ghost_node_t const * head3 = fd_ghost_head( ghost, fd_ghost_root( ghost ) );
  // FD_TEST( head3->slot == 13 );

  fd_ghost_replay_vote( ghost, v2, 13 );
  query_mut( ghost, 11 )->valid = 0; // mark 11 as invalid
  // fd_ghost_node_t const * head4 = fd_ghost_head( ghost, fd_ghost_root( ghost ) );
  // FD_TEST( head4->slot == 10 );

  query_mut( ghost, 12 )->valid = 1; // mark 12 as valid
  fd_ghost_node_t const * head5 = fd_ghost_head( ghost, fd_ghost_root( ghost ) );
  FD_LOG_NOTICE(( "head5 slot %lu", head5->slot ));
  FD_TEST( head5->slot == 12 );

  fd_ghost_print( ghost, epoch, fd_ghost_root( ghost ) );

  fd_wksp_free_laddr( mem );
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

  // test_ghost_print( wksp );
  // test_ghost_simple( wksp );
  // test_ghost_publish_left( wksp );
  // test_ghost_publish_right( wksp );
  // test_ghost_gca( wksp );
  // test_ghost_vote_leaves( wksp );
  // test_ghost_head_full_tree( wksp );
  // test_ghost_head( wksp );
  // test_rooted_vote( wksp );
  // test_ghost_old_vote_pruned( wksp );
  test_ghost_head_valid( wksp );

  fd_halt();
  return 0;
}
