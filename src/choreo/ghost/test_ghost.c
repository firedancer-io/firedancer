#include "fd_ghost.h"
#include "../epoch/fd_epoch.h"

#include <stdarg.h>

#define PRINT 1

#define INSERT( c, p )                                                                             \
  fd_ghost_insert( ghost, &hash_##p, c, &hash_##c, 20 );

fd_ghost_ele_t *
query_mut( fd_ghost_t * ghost, ulong slot ) {
  fd_wksp_t *          wksp = fd_wksp_containing( ghost );
  fd_ghost_slot_map_t * map = fd_wksp_laddr_fast( wksp, ghost->slot_map_gaddr );
  fd_ghost_ele_t *     pool = fd_wksp_laddr_fast( wksp, ghost->pool_gaddr );
  return fd_ghost_slot_map_ele_query( map, &slot, NULL, pool );
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
    voter->stake            = va_arg( ap, ulong );
    voter->replay_vote.slot = FD_SLOT_NULL;
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
  fd_ghost_t *      ghost = fd_ghost_join( fd_ghost_new( mem, node_max, 0UL ) );
  //fd_ghost_ele_t * pool  = fd_wksp_laddr_fast( wksp, ghost->pool_gaddr );

  // define hash_0, hash_1, hash_2, hash_3, hash_4, hash_5, hash_6
  fd_hash_t hash_0 = { .ul = { ULONG_MAX } };
  fd_hash_t hash_1 = { .key = { 1 } };
  fd_hash_t hash_2 = { .key = { 2 } };
  fd_hash_t hash_3 = { .key = { 3 } };
  fd_hash_t hash_4 = { .key = { 4 } };
  fd_hash_t hash_5 = { .key = { 5 } };
  fd_hash_t hash_6 = { .key = { 6 } };

  fd_ghost_init( ghost, 0, &hash_0 );
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

# if PRINT
  fd_ghost_print( ghost, 10, fd_ghost_root( ghost ) );
# endif
  fd_ghost_replay_vote( ghost, voter, &hash_2 );
# if PRINT
  fd_ghost_print( ghost, 10, fd_ghost_root( ghost ) );
# endif
  fd_ghost_replay_vote( ghost, voter, &hash_3 );
# if PRINT
  fd_ghost_print( ghost, 10, fd_ghost_root( ghost ) );
# endif

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
  fd_ghost_t * ghost = fd_ghost_join( fd_ghost_new( mem, node_max, 0UL ) );
  fd_ghost_ele_t * pool = fd_wksp_laddr_fast( wksp, ghost->pool_gaddr );


  // define hash_0, hash_1, hash_2, hash_3, hash_4, hash_5, hash_6
  fd_hash_t hash_0 = { .ul = { ULONG_MAX } };
  fd_hash_t hash_1 = { .key = { 1 } };
  fd_hash_t hash_2 = { .key = { 2 } };
  fd_hash_t hash_3 = { .key = { 3 } };
  fd_hash_t hash_4 = { .key = { 4 } };
  fd_hash_t hash_5 = { .key = { 5 } };
  fd_hash_t hash_6 = { .key = { 6 } };

  fd_ghost_init( ghost, 0, &hash_0 );
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

  fd_ghost_replay_vote( ghost, v1, &hash_2 );
# if PRINT
  fd_ghost_print( ghost, 2, fd_ghost_root( ghost ) );
# endif
  FD_TEST( !fd_ghost_verify( ghost ) );

  fd_ghost_replay_vote( ghost, v1, &hash_3 );
  fd_ghost_ele_t const * node2 = fd_ghost_query( ghost, &hash_2 );
  FD_TEST( node2 );
  FD_TEST( !fd_ghost_verify( ghost ) );

# if PRINT
  fd_ghost_print( ghost, 2, fd_ghost_root( ghost ) );
# endif
  fd_ghost_publish( ghost, &hash_2 );
  fd_ghost_ele_t const * root = fd_ghost_root( ghost );
  FD_TEST( root->slot == 2 );
  FD_TEST( !fd_ghost_verify( ghost ) );

  FD_TEST( fd_ghost_pool_ele( pool, root->child )->slot == 4 );
  FD_TEST( fd_ghost_pool_free( pool ) == node_max - 2 );
# if PRINT
  fd_ghost_print( ghost, 2, fd_ghost_root( ghost ) );
# endif

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
  fd_ghost_t * ghost = fd_ghost_join( fd_ghost_new( mem, node_max, 0UL ) );
  fd_ghost_ele_t * pool = fd_wksp_laddr_fast( wksp, ghost->pool_gaddr );

  fd_hash_t hash_0 = { .ul = { ULONG_MAX } };
  fd_hash_t hash_1 = { .key = { 1 } };
  fd_hash_t hash_2 = { .key = { 2 } };
  fd_hash_t hash_3 = { .key = { 3 } };
  fd_hash_t hash_4 = { .key = { 4 } };
  fd_hash_t hash_5 = { .key = { 5 } };
  fd_hash_t hash_6 = { .key = { 6 } };

  fd_ghost_init( ghost, 0, &hash_0 );
  INSERT( 1, 0 );
  INSERT( 2, 1 );
  INSERT( 3, 1 );
  INSERT( 4, 2 );
  INSERT( 5, 3 );
  INSERT( 6, 5 );
  FD_TEST( !fd_ghost_verify( ghost ) );

  fd_pubkey_t  pk1   = { { 1 } };
  ulong        total = 2;
  fd_epoch_t * epoch = mock_epoch( wksp, total, 1, pk1, 1 );
  fd_voter_t * v1    = fd_epoch_voters_query( fd_epoch_voters( epoch ), pk1, NULL );

  fd_ghost_replay_vote( ghost, v1, &hash_2 );
  FD_TEST( !fd_ghost_verify( ghost ) );

  fd_ghost_replay_vote( ghost, v1, &hash_3 );
  FD_TEST( !fd_ghost_verify( ghost ) );
  fd_ghost_ele_t const * node3 = fd_ghost_query( ghost, &hash_3 );
  FD_TEST( node3 );

# if PRINT
  fd_ghost_print( ghost, total, fd_ghost_root( ghost ) );
# endif
  fd_ghost_publish( ghost, &hash_3 );
  FD_TEST( !fd_ghost_verify( ghost ) );

  fd_ghost_ele_t * root = fd_ghost_pool_ele( pool, ghost->root );
  FD_TEST( root->slot == 3 );
  FD_TEST( fd_ghost_pool_ele( pool, root->child )->slot == 5 );
  FD_TEST( fd_ghost_child( ghost, fd_ghost_child( ghost, root ) )->slot == 6 );
  FD_TEST( fd_ghost_pool_free( pool ) == node_max - 3 );
# if PRINT
  fd_ghost_print( ghost, total, fd_ghost_root( ghost ) );
# endif

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
  fd_ghost_t * ghost = fd_ghost_join( fd_ghost_new( mem, node_max, 0UL ) );
  //fd_ghost_ele_t * pool = fd_wksp_laddr_fast( wksp, ghost->pool_gaddr );

  fd_hash_t hash_0 = { .ul = { ULONG_MAX } };
  fd_hash_t hash_1 = { .key = { 1 } };
  fd_hash_t hash_2 = { .key = { 2 } };
  fd_hash_t hash_3 = { .key = { 3 } };
  fd_hash_t hash_4 = { .key = { 4 } };
  fd_hash_t hash_5 = { .key = { 5 } };
  fd_hash_t hash_6 = { .key = { 6 } };

  fd_ghost_init( ghost, 0, &hash_0 );
  INSERT( 1, 0 );
  INSERT( 2, 1 );
  INSERT( 3, 1 );
  INSERT( 4, 2 );
  INSERT( 5, 3 );
  INSERT( 6, 5 );
  FD_TEST( !fd_ghost_verify( ghost ) );

# if PRINT
  fd_ghost_print( ghost, 0, fd_ghost_root( ghost ) );
# endif

  FD_TEST( fd_ghost_gca( ghost, &hash_0, &hash_0 )->slot == 0 );

  FD_TEST( fd_ghost_gca( ghost, &hash_0, &hash_1 )->slot == 0 );
  FD_TEST( fd_ghost_gca( ghost, &hash_1, &hash_1 )->slot == 1 );

  FD_TEST( fd_ghost_gca( ghost, &hash_0, &hash_2 )->slot == 0 );
  FD_TEST( fd_ghost_gca( ghost, &hash_1, &hash_2 )->slot == 1 );
  FD_TEST( fd_ghost_gca( ghost, &hash_2, &hash_2 )->slot == 2 );

  FD_TEST( fd_ghost_gca( ghost, &hash_0, &hash_3 )->slot == 0 );
  FD_TEST( fd_ghost_gca( ghost, &hash_1, &hash_3 )->slot == 1 );
  FD_TEST( fd_ghost_gca( ghost, &hash_2, &hash_3 )->slot == 1 );
  FD_TEST( fd_ghost_gca( ghost, &hash_3, &hash_3 )->slot == 3 );

  FD_TEST( fd_ghost_gca( ghost, &hash_0, &hash_4 )->slot == 0 );
  FD_TEST( fd_ghost_gca( ghost, &hash_1, &hash_4 )->slot == 1 );
  FD_TEST( fd_ghost_gca( ghost, &hash_2, &hash_4 )->slot == 2 );
  FD_TEST( fd_ghost_gca( ghost, &hash_3, &hash_4 )->slot == 1 );
  FD_TEST( fd_ghost_gca( ghost, &hash_4, &hash_4 )->slot == 4 );

  FD_TEST( fd_ghost_gca( ghost, &hash_0, &hash_5 )->slot == 0 );
  FD_TEST( fd_ghost_gca( ghost, &hash_1, &hash_5 )->slot == 1 );
  FD_TEST( fd_ghost_gca( ghost, &hash_2, &hash_5 )->slot == 1 );
  FD_TEST( fd_ghost_gca( ghost, &hash_3, &hash_5 )->slot == 3 );
  FD_TEST( fd_ghost_gca( ghost, &hash_4, &hash_5 )->slot == 1 );
  FD_TEST( fd_ghost_gca( ghost, &hash_5, &hash_5 )->slot == 5 );

  FD_TEST( fd_ghost_gca( ghost, &hash_0, &hash_6 )->slot == 0 );
  FD_TEST( fd_ghost_gca( ghost, &hash_1, &hash_6 )->slot == 1 );
  FD_TEST( fd_ghost_gca( ghost, &hash_2, &hash_6 )->slot == 1 );
  FD_TEST( fd_ghost_gca( ghost, &hash_3, &hash_6 )->slot == 3 );
  FD_TEST( fd_ghost_gca( ghost, &hash_4, &hash_6 )->slot == 1 );
  FD_TEST( fd_ghost_gca( ghost, &hash_5, &hash_6 )->slot == 5 );
  FD_TEST( fd_ghost_gca( ghost, &hash_6, &hash_6 )->slot == 6 );
}

/*void
test_ghost_print( fd_wksp_t * wksp ) {
  ulong  node_max = 16;
  void * mem      = fd_wksp_alloc_laddr( wksp,
                                    fd_ghost_align(),
                                    fd_ghost_footprint( node_max ),
                                    1UL );
  FD_TEST( mem );
  fd_ghost_t * ghost = fd_ghost_join( fd_ghost_new( mem, node_max, 0UL ) );

  ulong slots[node_max];
  ulong parent_slots[node_max];
  ulong i = 0;

  ulong        total = 300;

  fd_ghost_init( ghost, 268538758 );
  INSERT( 268538759, 268538758 );
  INSERT( 268538760, 268538759 );
  INSERT( 268538761, 268538758 );

  fd_ghost_ele_t * node;
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

  fd_ghost_ele_t const * grandparent = fd_ghost_parent( ghost, fd_ghost_parent( ghost, fd_ghost_query( ghost, 268538760 ) ) );
# if PRINT
  fd_ghost_print( ghost, total, grandparent );
# else
  (void)grandparent;
  (void)total;
# endif

  fd_wksp_free_laddr( mem );
}*/


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
  fd_ghost_t * ghost = fd_ghost_join( fd_ghost_new( mem, node_max, 0UL ) );

  fd_pubkey_t  pk1   = { { 1 } };
  fd_pubkey_t  pk2   = { { 2 } };
  ulong        total = 150;
  fd_epoch_t * epoch = mock_epoch( wksp, 150, 2, pk1, 50, pk2, 100 );
  fd_voter_t * v1    = fd_epoch_voters_query( fd_epoch_voters( epoch ), pk1, NULL );
  fd_voter_t * v2    = fd_epoch_voters_query( fd_epoch_voters( epoch ), pk2, NULL );

  fd_hash_t hash_10 = { .key = { 10 } };
  fd_hash_t hash_11 = { .key = { 11 } };
  fd_hash_t hash_12 = { .key = { 12 } };
  fd_hash_t hash_13 = { .key = { 13 } };

  fd_ghost_init( ghost, 10, &hash_10 );
  INSERT( 11, 10 );
  INSERT( 12, 10 );
  INSERT( 13, 11 );

  fd_ghost_replay_vote( ghost, v1, &hash_11 );
  FD_TEST( !fd_ghost_verify( ghost ) );

  fd_ghost_replay_vote( ghost, v2, &hash_12 );
  FD_TEST( !fd_ghost_verify( ghost ) );

  fd_ghost_ele_t const * head = fd_ghost_head( ghost, fd_ghost_root( ghost ) );
  FD_TEST( head->slot == 12 );

  fd_ghost_replay_vote( ghost, v1, &hash_13 );
  FD_TEST( !fd_ghost_verify( ghost ) );

  fd_ghost_ele_t const * head2 = fd_ghost_head( ghost, fd_ghost_root( ghost ) );
  FD_TEST( head2->slot == 12 );

# if PRINT
  fd_ghost_print( ghost, total, fd_ghost_root( ghost ) );
# else
  (void)total;
# endif

  fd_wksp_free_laddr( mem );
}

void
test_ghost_vote_leaves( fd_wksp_t * wksp ) {
  ulong node_max = 8;
  ulong total_stake = 40;
  int d = 3;

  void * mem = fd_wksp_alloc_laddr( wksp,
                                    fd_ghost_align(),
                                    fd_ghost_footprint( node_max ),
                                    1UL );
  FD_TEST( mem );
  fd_ghost_t * ghost = fd_ghost_join( fd_ghost_new( mem, node_max, 0UL ) );

  fd_hash_t hash_arr[node_max];
  hash_arr[0] = (fd_hash_t) { .ul = { ULONG_MAX } };
  for( ulong i = 1; i < node_max; i++){
    hash_arr[i] = (fd_hash_t) { .key = { (uchar)i } };
  }

  fd_ghost_init( ghost, 0, &hash_arr[0] );

  /* make a full binary tree */
  for( ulong i = 1; i < node_max - 1; i++){
    FD_LOG_NOTICE(("inserting %lu with parent %lu", i, (i-1)/2));
    fd_ghost_insert( ghost, &hash_arr[(i-1)/2], i, &hash_arr[i], total_stake );
    FD_TEST( !fd_ghost_verify( ghost ) );
  }
  FD_TEST( !fd_ghost_verify( ghost ) );


  fd_ghost_print( ghost, total_stake, fd_ghost_root( ghost ) );

  /* one validator changes votes along leaves */
  ulong first_leaf = fd_ulong_pow2(d-1) - 1;
  fd_voter_t v = { .key = { { 0 } }, .stake = 10, .replay_vote = { .slot = FD_SLOT_NULL } };
  for( ulong i = first_leaf; i < node_max - 1; i++){
    fd_ghost_replay_vote( ghost, &v, &hash_arr[i] );
  }
  FD_TEST( !fd_ghost_verify( ghost ) );


# if PRINT
  fd_ghost_print( ghost, total_stake, fd_ghost_root( ghost ) );
# else
  (void)total_stake;
# endif

  ulong path[d];
  ulong leaf = node_max - 2;
  for( int i = d - 1; i >= 0; i--){
    path[i] = leaf;
    leaf = (leaf - 1) / 2;
  }

  /* check weights and stakes */
  int j = 0;
  for( ulong i = 0; i < node_max - 1; i++){
    fd_ghost_ele_t const * node = fd_ghost_query( ghost, &hash_arr[i] );
    if ( i == node_max - 2) FD_TEST( node->replay_stake == 10 );
    else  FD_TEST( node->replay_stake == 0 );

    if( i == path[j] ) { /* if on fork */
      FD_TEST( node->weight == 10 );
      j++;
    } else {
      FD_TEST( node->weight == 0 );
    }
  }

  /* have other validators vote for rest of leaves */
  for ( ulong i = first_leaf; i < node_max - 2; i++){
    fd_voter_t v = { .key = { .key = { (uchar)i }  }, .stake = 10, .replay_vote = { .slot = FD_SLOT_NULL } };
    fd_ghost_replay_vote( ghost, &v, &hash_arr[i] );
    FD_TEST( !fd_ghost_verify( ghost ) );
  }

  /* check weights and stakes */
  for( ulong i = 0; i < node_max - 1; i++){
    fd_ghost_ele_t const * node = fd_ghost_query( ghost, &hash_arr[i] );
    if ( i >= first_leaf){
      FD_TEST( node->replay_stake == 10 );
      FD_TEST( node->weight == 10 );
    } else {
      FD_TEST( node->replay_stake == 0 );
      FD_TEST( node->weight > 10);
    }
  }

  FD_TEST( !fd_ghost_verify( ghost ) );
# if PRINT
  fd_ghost_print( ghost, total_stake, fd_ghost_root( ghost ) );
# endif
}

void
test_ghost_old_vote_pruned( fd_wksp_t * wksp ){
  ulong  node_max   = 16;
  ulong total_stake = 50;
  void * mem      = fd_wksp_alloc_laddr( wksp,
    fd_ghost_align(),
    fd_ghost_footprint( node_max ),
    1UL );
  FD_TEST( mem );
  fd_ghost_t * ghost = fd_ghost_join( fd_ghost_new( mem, node_max, 0UL ) );

  fd_hash_t hash_arr[node_max];
  hash_arr[0] = (fd_hash_t) { .ul = { ULONG_MAX } };
  for( ulong i = 1; i < node_max; i++){
    hash_arr[i] = (fd_hash_t) { .key = { (uchar)i } };
  }

  fd_ghost_init( ghost, 0, &hash_arr[0] );
  for ( ulong i = 1; i < node_max - 1; i++ ) {
    fd_ghost_insert( ghost, &hash_arr[(i-1)/2], i, &hash_arr[i], total_stake );
    fd_voter_t v = { .key = { { (uchar)i } }, .stake = i, .replay_vote = { .slot = FD_SLOT_NULL } };
    fd_ghost_replay_vote( ghost, &v, &hash_arr[i] );
  }

  fd_ghost_publish( ghost, &hash_arr[1]);
# if PRINT
  fd_ghost_print( ghost, total_stake, fd_ghost_root( ghost ) );
# else
  (void)total_stake;
# endif

  fd_voter_t switch_voter = { .key = { { 5 } }, .stake = 5, .replay_vote = { .slot = 5 } };
  fd_ghost_replay_vote( ghost, &switch_voter, &hash_arr[9] );
  /* switching to vote 9, from voting 5, that is > than the root */
# if PRINT
  fd_ghost_print( ghost, total_stake, fd_ghost_root( ghost ) );
# endif

  FD_TEST( fd_ghost_query( ghost, &hash_arr[9] )->weight == 14 );
  FD_TEST( fd_ghost_query( ghost, &hash_arr[3] )->weight == 18 );
  FD_TEST( fd_ghost_query( ghost, &hash_arr[4] )->weight == 28 );
  FD_TEST( fd_ghost_query( ghost, &hash_arr[1] )->weight == 47 ); /* full tree */

  FD_TEST( !fd_ghost_verify( ghost ) );

  fd_ghost_publish( ghost, &hash_arr[3] ); /* cut down to nodes 3,7,8 */
  /* now previously voted 2 ( < the root ) votes for 7 */
  fd_voter_t switch_voter2 = { .key = { { 2 } }, .stake = 2, .replay_vote = { .slot = 2 } };
  fd_ghost_replay_vote( ghost, &switch_voter2, &hash_arr[7] );

# if PRINT
  fd_ghost_print( ghost, total_stake, fd_ghost_root( ghost ) );
# endif
  FD_TEST( fd_ghost_query( ghost, &hash_arr[7] )->weight == 9 );
  FD_TEST( fd_ghost_query( ghost, &hash_arr[8] )->weight == 8 );
  FD_TEST( fd_ghost_query( ghost, &hash_arr[3] )->weight == 20 );

  FD_TEST( !fd_ghost_verify( ghost ) );
}

void
test_ghost_head_full_tree( fd_wksp_t * wksp ){
  ulong  node_max    = 16;
  ulong  total_stake = 120;
  void * mem         = fd_wksp_alloc_laddr( wksp,
                                       fd_ghost_align(),
                                       fd_ghost_footprint( node_max ),
                                       1UL );
  FD_TEST( mem );
  fd_ghost_t * ghost = fd_ghost_join( fd_ghost_new( mem, node_max, 0UL ) );

  fd_hash_t hash_arr[node_max];
  hash_arr[0] = (fd_hash_t) { .ul = { ULONG_MAX } };
  for( ulong i = 1; i < node_max; i++){
    hash_arr[i] = (fd_hash_t) { .key = { (uchar)i } };
  }

  fd_ghost_init( ghost, 0, &hash_arr[0] );

  for ( ulong i = 1; i < node_max - 1; i++ ) {
    fd_ghost_insert( ghost, &hash_arr[(i-1)/2], i, &hash_arr[i], total_stake );
    fd_voter_t v = { .key = { { (uchar)i } }, .stake = i, .replay_vote = { .slot = FD_SLOT_NULL } };
    fd_ghost_replay_vote( ghost, &v, &hash_arr[i] );
  }

  for ( ulong i = 0; i < node_max - 1; i++ ) {
    fd_ghost_ele_t const * node = fd_ghost_query( ghost, &hash_arr[i] );
    FD_TEST( node->replay_stake == i );
  }

  FD_TEST( !fd_ghost_verify( ghost ) );

# if PRINT
  fd_ghost_print( ghost, total_stake, fd_ghost_root( ghost ) );
# endif
  fd_ghost_ele_t const * head = fd_ghost_head( ghost, fd_ghost_root( ghost ) );

  /* head will always be rightmost node in this complete binary tree */

  FD_TEST( head->slot == 14 );

  /* add one more node */

  fd_ghost_insert( ghost, &hash_arr[(node_max-2)/2], node_max - 1, &hash_arr[node_max - 1], total_stake );
  fd_voter_t v = { .key = { { (uchar)( node_max - 1 ) } }, .stake = node_max - 1, .replay_vote = { .slot = FD_SLOT_NULL } };
  fd_ghost_replay_vote( ghost, &v, &hash_arr[node_max - 1]);

  FD_TEST( !fd_ghost_verify( ghost ) );
  head = fd_ghost_head( ghost, fd_ghost_root( ghost ) );
  FD_TEST( head->slot == 14 );

  /* adding one more node would fail. */
}

void
test_rooted_vote( fd_wksp_t * wksp ){
  ulong  node_max    = 16;
  ulong  total_stake = 50;
  void * mem         = fd_wksp_alloc_laddr( wksp,
                                            fd_ghost_align(),
                                            fd_ghost_footprint( node_max ),
                                            1UL );
  FD_TEST( mem );
  fd_ghost_t * ghost = fd_ghost_join( fd_ghost_new( mem, node_max, 0UL ) );

  fd_pubkey_t  pk1   = { .key = { 1 } };
  fd_pubkey_t  pk2   = { .key = { 2 } };
  fd_epoch_t * epoch = mock_epoch( wksp, 120, 2, pk1, 20, pk2, 10 );
  fd_voter_t * v1    = fd_epoch_voters_query( fd_epoch_voters( epoch ), pk1, NULL );
  fd_voter_t * v2    = fd_epoch_voters_query( fd_epoch_voters( epoch ), pk2, NULL );

  fd_hash_t hash_0 = { .ul = { ULONG_MAX} };
  fd_hash_t hash_1 = { .key = { 1 } };

  fd_ghost_init( ghost, 0, &hash_0 );

  fd_ghost_insert( ghost, &hash_0, 1, &hash_1, total_stake );
  fd_ghost_replay_vote( ghost, v1, &hash_1 );

  fd_ghost_rooted_vote( ghost, v2, 1 );

  fd_ghost_ele_t const * node = fd_ghost_query( ghost, &hash_1 );
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
  fd_ghost_t * ghost = fd_ghost_join( fd_ghost_new( mem, node_max, 0UL ) );

  fd_pubkey_t  pk1   = { { 1 } };
  fd_pubkey_t  pk2   = { { 2 } };
  ulong        total = 150;
  fd_epoch_t * epoch = mock_epoch( wksp, 150, 2, pk1, 50, pk2, 100 );
  fd_voter_t * v1    = fd_epoch_voters_query( fd_epoch_voters( epoch ), pk1, NULL );
  fd_voter_t * v2    = fd_epoch_voters_query( fd_epoch_voters( epoch ), pk2, NULL );

  fd_hash_t hash_10 = { .key = { 10 } };
  fd_hash_t hash_11 = { .key = { 11 } };
  fd_hash_t hash_12 = { .key = { 12 } };
  fd_hash_t hash_13 = { .key = { 13 } };

  fd_ghost_init( ghost, 10, &hash_10 );
  INSERT( 11, 10 );
  INSERT( 12, 10 );
  INSERT( 13, 11 );

  fd_ghost_replay_vote( ghost, v1, &hash_11 );
  FD_TEST( !fd_ghost_verify( ghost ) );

  fd_ghost_replay_vote( ghost, v2, &hash_12 );
  FD_TEST( !fd_ghost_verify( ghost ) );

  // fd_ghost_node_t const * head = fd_ghost_head( ghost, fd_ghost_root( ghost ) );
  // FD_TEST( head->slot == 12 );

  fd_ghost_replay_vote( ghost, v1, &hash_13 );
  FD_TEST( !fd_ghost_verify( ghost ) );

  // fd_ghost_node_t const * head2 = fd_ghost_head( ghost, fd_ghost_root( ghost ) );
  // FD_TEST( head2->slot == 12 );

  query_mut( ghost, 12 )->valid = 0; // mark 12 as invalid
  // fd_ghost_node_t const * head3 = fd_ghost_head( ghost, fd_ghost_root( ghost ) );
  // FD_TEST( head3->slot == 13 );

  fd_ghost_replay_vote( ghost, v2, &hash_13 );
  query_mut( ghost, 11 )->valid = 0; // mark 11 as invalid
  // fd_ghost_node_t const * head4 = fd_ghost_head( ghost, fd_ghost_root( ghost ) );
  // FD_TEST( head4->slot == 10 );

  query_mut( ghost, 12 )->valid = 1; // mark 12 as valid
  fd_ghost_ele_t const * head5 = fd_ghost_head( ghost, fd_ghost_root( ghost ) );
  FD_TEST( head5->slot == 12 );

# if PRINT
  fd_ghost_print( ghost, total, fd_ghost_root( ghost ) );
# else
  (void)total;
# endif

  fd_wksp_free_laddr( mem );
}

void
test_duplicate_simple( fd_wksp_t * wksp ){
  ulong node_max = 16;
  ulong total_stake = 10;
  void * mem = fd_wksp_alloc_laddr( wksp,
                                    fd_ghost_align(),
                                    fd_ghost_footprint( node_max ),
                                    1UL );
  FD_TEST( mem );

  /* 1
    / \
   2   2'
   |   |
   3   4 */

  fd_ghost_t * ghost = fd_ghost_join( fd_ghost_new( mem, node_max, 0UL ) );
  fd_ghost_ele_t * pool = fd_ghost_pool( ghost );

  fd_hash_t hash_1 = { .key = { 1 } };
  fd_hash_t hash_2 = { .key = { 2 } };
  fd_hash_t hash_2_prime = { .key = { 2, 1 } };
  fd_hash_t hash_3 = { .key = { 3 } };
  fd_hash_t hash_4 = { .key = { 4 } };

  fd_ghost_init( ghost, 1, &hash_1 );

  /* We see 2 and 3 first, so we replay down the left branch first */
  fd_ghost_insert( ghost, &hash_1, 2, &hash_2, total_stake );
  fd_ghost_insert( ghost, &hash_2, 3, &hash_3, total_stake );

  /* We see evidence of 2' and 4. Add them to the tree */
  fd_ghost_insert( ghost, &hash_1, 2, &hash_2_prime, total_stake );
  fd_ghost_insert( ghost, &hash_2_prime, 4, &hash_4, total_stake );

  /* Only 1 - 2 - 3 should be visible in the slot map */
  FD_TEST( memcmp( fd_ghost_hash( ghost, 1 ), &hash_1, sizeof(fd_hash_t) ) == 0 );
  FD_TEST( memcmp( fd_ghost_hash( ghost, 2 ), &hash_2, sizeof(fd_hash_t) ) == 0 );
  FD_TEST( memcmp( fd_ghost_hash( ghost, 3 ), &hash_3, sizeof(fd_hash_t) ) == 0 );
  FD_TEST( memcmp( fd_ghost_hash( ghost, 4 ), &hash_4, sizeof(fd_hash_t) ) == 0 );

  fd_ghost_ele_t const * dup_child = fd_ghost_query( ghost, &hash_4 );
  fd_ghost_ele_t const * dup_parent = fd_ghost_pool_ele( pool, dup_child->parent );
  FD_TEST( dup_parent->slot == 2 );
  FD_TEST( memcmp( &dup_parent->key, &hash_2_prime, sizeof(fd_hash_t) ) == 0 );

  fd_ghost_print( ghost, total_stake, fd_ghost_root( ghost ) );

  FD_TEST( !fd_ghost_verify( ghost ) );
}

void
test_many_duplicates( fd_wksp_t * wksp ){
  ulong node_max = 16;
  ulong total_stake = 10;
  void * mem = fd_wksp_alloc_laddr( wksp,
                                    fd_ghost_align(),
                                    fd_ghost_footprint( node_max ),
                                    1UL );
  FD_TEST( mem );

  fd_ghost_t * ghost = fd_ghost_join( fd_ghost_new( mem, node_max, 0UL ) );
  fd_ghost_slot_map_t * map_slot = fd_ghost_slot_map( ghost );
  fd_ghost_ele_t * pool = fd_ghost_pool( ghost );

  fd_hash_t hash_1 = { .key = { 1 } };
  fd_hash_t hash_2 = { .key = { 2 } };
  fd_hash_t hash_2_prime = { .key = { 2, 1 } };
  fd_hash_t hash_3 = { .key = { 3 } };
  fd_hash_t hash_3_prime = { .key = { 3, 1 } };
  fd_hash_t hash_4 = { .key = { 4 } };
  fd_hash_t hash_4_prime = { .key = { 4, 1 } };
  fd_hash_t hash_4_prime_prime = { .key = { 4, 1, 1 } };

    /* 1
      / \
    2   2'
    |   |
    3   3'
    / \  |
  4  4' 4'' */

  fd_ghost_init( ghost, 1, &hash_1 );

  /* Slots I see initially*/

  fd_ghost_insert( ghost, &hash_1, 2, &hash_2, total_stake );
  fd_ghost_insert( ghost, &hash_2, 3, &hash_3, total_stake );
  fd_ghost_insert( ghost, &hash_3, 4, &hash_4, total_stake );

  /* Evidence of duplicates */

  fd_ghost_insert( ghost, &hash_1, 2, &hash_2_prime, total_stake );
  fd_ghost_insert( ghost, &hash_2_prime, 3, &hash_3_prime, total_stake );
  fd_ghost_insert( ghost, &hash_3_prime, 4, &hash_4_prime_prime, total_stake );
  fd_ghost_insert( ghost, &hash_3, 4, &hash_4_prime, total_stake );

  ulong visible_slots[4] = { 3, 1, 2, 4 };
  fd_hash_t visible_hashes[4] = { hash_3, hash_1, hash_2, hash_4 };
  int cnt = 0;
  for( fd_ghost_slot_map_iter_t iter = fd_ghost_slot_map_iter_init( map_slot, pool );
       !fd_ghost_slot_map_iter_done( iter, map_slot, pool );
       iter = fd_ghost_slot_map_iter_next( iter, map_slot, pool ) ) {
    fd_ghost_ele_t const * ele = fd_ghost_slot_map_iter_ele( iter, map_slot, pool );
    FD_LOG_NOTICE(( "ele->slot: %lu, visible_slots[cnt]: %lu", ele->slot, visible_slots[cnt] ));
    FD_TEST( ele->slot == visible_slots[cnt] );
    FD_TEST( memcmp( &ele->key, &visible_hashes[cnt], sizeof(fd_hash_t) ) == 0 );
    cnt++;
  }
  FD_TEST( cnt == 4 );

  fd_ghost_print( ghost, total_stake, fd_ghost_root( ghost ) );

  /* Vote down the left branch */
  fd_voter_t v1 = { .key = { { 1 } }, .stake = 10, .replay_vote = { .slot = FD_SLOT_NULL } };
  fd_ghost_replay_vote( ghost, &v1, &hash_4 );
}

/* Key differences between Agave and Firedancer:  Agave inserts to their
   fork tracking structure before the bank is frozen.  Thus they can
   build forks and mark things duplicate/duplicate confirmed, but it has
   no effect bevause the bank is not yet frozen.  However, Firedancer
   only adds to ghost once the bank is frozen, and the slot has been
   fully replayed. */

void
run_test_state_duplicate_then_bank_frozen( fd_wksp_t * wksp ) {
  /* covers both mid-replay and haven't started replay test cases */
  ulong node_max = 16;
  ulong total_stake = 10;
  void * mem = fd_wksp_alloc_laddr( wksp,
                                    fd_ghost_align(),
                                    fd_ghost_footprint( node_max ),
                                    1UL );
  FD_TEST( mem );

  fd_ghost_t     * ghost = fd_ghost_join( fd_ghost_new( mem, node_max, 0UL ) );

  fd_hash_t hash_0 = { .ul = { ULONG_MAX } };
  fd_hash_t hash_1 = { .key = { 1 } };
  fd_hash_t hash_2 = { .key = { 2 } };

  fd_ghost_init( ghost, 0, &hash_0 );
  fd_ghost_insert( ghost, &hash_0, 1, &hash_1, total_stake );

  /* Get a duplicate message shred/gossip/repair. Nothing happens because
     the slot 2 has not yet been replayed  */
  process_duplicate( ghost, 2, total_stake );
  FD_TEST( fd_ghost_hash( ghost, 2 ) == NULL );
  FD_TEST( fd_ghost_head( ghost, fd_ghost_root( ghost ) )->slot == 1 );

  /* Finish replaying slot 2, hash 2 */
  fd_ghost_insert( ghost, &hash_1, 2, &hash_2, total_stake );
  FD_TEST( !fd_ghost_query( ghost, &hash_2 )->valid );
  /* Parent of 2 is 1, so head should be 1 */
  FD_TEST( fd_ghost_head( ghost, fd_ghost_root( ghost ) )->slot == 1 );
}

void
test_state_ancestor_confirmed_descendant_duplicate( fd_wksp_t * wksp ){
  ulong node_max = 16;
  ulong total_stake = 10;
  void * mem = fd_wksp_alloc_laddr( wksp,
                                    fd_ghost_align(),
                                    fd_ghost_footprint( node_max ),
                                    1UL );
  FD_TEST( mem );

  /* 0 - 1 - 2 - 3 */
  fd_ghost_t * ghost = fd_ghost_join( fd_ghost_new( mem, node_max, 0UL ) );
  fd_dup_seen_t * dup_map = fd_ghost_dup_map( ghost );

  fd_hash_t hash_0 = { .ul = { ULONG_MAX } };
  fd_hash_t hash_1 = { .key = { 1 } };
  fd_hash_t hash_2 = { .key = { 2 } };
  fd_hash_t hash_3 = { .key = { 3 } };

  fd_ghost_init( ghost, 0, &hash_0 );
  fd_ghost_insert( ghost, &hash_0, 1, &hash_1, total_stake );
  fd_ghost_insert( ghost, &hash_1, 2, &hash_2, total_stake );
  fd_ghost_insert( ghost, &hash_2, 3, &hash_3, total_stake );

  FD_TEST( fd_ghost_head( ghost, fd_ghost_root( ghost ) )->slot == 3 );
  process_duplicate_confirmed( ghost, &hash_2, 2 );
  FD_TEST( fd_ghost_head( ghost, fd_ghost_root( ghost ) )->slot == 3 );

  /* mark 3 as duplicate */
  process_duplicate( ghost, 3, total_stake );
  FD_TEST( fd_dup_seen_map_query( dup_map, 3, NULL ) );

  FD_TEST( fd_ghost_head( ghost, fd_ghost_root( ghost ) )->slot == 2 );
}

void
test_state_ancestor_duplicate_descendant_confirmed( fd_wksp_t * wksp ){
  ulong node_max = 16;
  ulong total_stake = 18;
  void * mem = fd_wksp_alloc_laddr( wksp,
                                    fd_ghost_align(),
                                    fd_ghost_footprint( node_max ),
                                    1UL );
  FD_TEST( mem );

  fd_ghost_t * ghost = fd_ghost_join( fd_ghost_new( mem, node_max, 0UL ) );
  fd_dup_seen_t * dup_map = fd_ghost_dup_map( ghost );

  fd_hash_t hash_0 = { .ul = { ULONG_MAX } };
  fd_hash_t hash_1 = { .key = { 1 } };
  fd_hash_t hash_2 = { .key = { 2 } };
  fd_hash_t hash_3 = { .key = { 3 } };

  fd_ghost_init( ghost, 0, &hash_0 );
  fd_ghost_insert( ghost, &hash_0, 1, &hash_1, total_stake );
  fd_ghost_insert( ghost, &hash_1, 2, &hash_2, total_stake );
  fd_ghost_insert( ghost, &hash_2, 3, &hash_3, total_stake );

  FD_TEST( fd_ghost_head( ghost, fd_ghost_root( ghost ) )->slot == 3 );

  process_duplicate( ghost, 2, total_stake );
  FD_TEST( fd_dup_seen_map_query( dup_map, 2, NULL ) );
  FD_TEST( fd_ghost_head( ghost, fd_ghost_root( ghost ) )->slot == 1 );

  fd_voter_t v1 = { .key = { { 1 } }, .stake = 10, .replay_vote = { .slot = FD_SLOT_NULL } };
  fd_ghost_replay_vote( ghost, &v1, &hash_3 );

  FD_TEST( is_duplicate_confirmed( ghost, &hash_3, total_stake ) );

  /* 3 becomes duplicate confirmed */
  if( is_duplicate_confirmed( ghost, &hash_3, total_stake ) ) {
    process_duplicate_confirmed( ghost, &hash_3, 3 );
  }
  FD_TEST( fd_ghost_query( ghost, &hash_3 )->valid );
  FD_TEST( fd_ghost_head( ghost, fd_ghost_root( ghost ) )->slot == 3 );
}

void
test_state_descendant_confirmed_ancestor_duplicate( fd_wksp_t * wksp ){
  ulong node_max = 16;
  ulong total_stake = 18;
  void * mem = fd_wksp_alloc_laddr( wksp,
                                    fd_ghost_align(),
                                    fd_ghost_footprint( node_max ),
                                    1UL );
  FD_TEST( mem );

  /* 0 - 1 - 2 - 3 */
  fd_ghost_t * ghost = fd_ghost_join( fd_ghost_new( mem, node_max, 0UL ) );
  fd_dup_seen_t * dup_map = fd_ghost_dup_map( ghost );

  fd_hash_t hash_0 = { .ul = { ULONG_MAX } };
  fd_hash_t hash_1 = { .key = { 1 } };
  fd_hash_t hash_2 = { .key = { 2 } };
  fd_hash_t hash_3 = { .key = { 3 } };

  fd_ghost_init( ghost, 0, &hash_0 );
  fd_ghost_insert( ghost, &hash_0, 1, &hash_1, total_stake );
  fd_ghost_insert( ghost, &hash_1, 2, &hash_2, total_stake );
  fd_ghost_insert( ghost, &hash_2, 3, &hash_3, total_stake );

  FD_TEST( fd_ghost_head( ghost, fd_ghost_root( ghost ) )->slot == 3 );
  fd_voter_t v1 = { .key = { { 1 } }, .stake = 10, .replay_vote = { .slot = FD_SLOT_NULL } };
  fd_ghost_replay_vote( ghost, &v1, &hash_3 );

  FD_TEST( is_duplicate_confirmed( ghost, &hash_3, total_stake ) );

  /* 3 becomes duplicate confirmed */
  if( is_duplicate_confirmed( ghost, &hash_3, total_stake ) ) {
    process_duplicate_confirmed( ghost, &hash_3, 3 );
  }
  fd_ghost_print( ghost, total_stake, fd_ghost_root( ghost ) );
  for( ulong slot = 0; slot < 4; slot++ ) {
    fd_ghost_ele_t const * ele = fd_ghost_query( ghost, fd_ghost_hash( ghost, slot ) );
    FD_TEST( ele->valid );
    FD_LOG_NOTICE(("slot %lu, ele->key: %s", slot, FD_BASE58_ENC_32_ALLOCA(&ele->key) ));
    FD_TEST( is_duplicate_confirmed( ghost, &ele->key, total_stake ) );
  }

  process_duplicate( ghost, 1, total_stake );
  FD_TEST( fd_dup_seen_map_query( dup_map, 1, NULL ) );
  FD_TEST( fd_ghost_head( ghost, fd_ghost_root( ghost ) )->slot == 3 );

}


void
test_duplicate_after_frozen( fd_wksp_t * wksp ){
  ulong node_max    = 16;
  ulong total_stake = 10;
  void * mem = fd_wksp_alloc_laddr( wksp,
                                    fd_ghost_align(),
                                    fd_ghost_footprint( node_max ),
                                    1UL );
  FD_TEST( mem );

  fd_ghost_t * ghost = fd_ghost_join( fd_ghost_new( mem, node_max, 0UL ) );

  fd_hash_t hash_0 = { .ul = { ULONG_MAX } };
  fd_hash_t hash_1 = { .key = { 1 } };
  fd_ghost_init( ghost, 0, &hash_0 );
  fd_ghost_insert( ghost, &hash_0, 1, &hash_1, total_stake );
  process_duplicate( ghost, 1, total_stake );

  FD_TEST( fd_ghost_head( ghost, fd_ghost_root( ghost ) )->slot == 0 );
}

void
test_duplicate_node_inserted( fd_wksp_t * wksp ) {
  ulong node_max = 16;
  ulong total_stake = 10;
  void * mem = fd_wksp_alloc_laddr( wksp,
                                    fd_ghost_align(),
                                    fd_ghost_footprint( node_max ),
                                    1UL );
  FD_TEST( mem );

  fd_ghost_t * ghost = fd_ghost_join( fd_ghost_new( mem, node_max, 0UL ) );
  fd_hash_t    hash0 = { .ul = { ULONG_MAX } };
  fd_hash_t    hash1 = { .key = { 1 } };

  fd_ghost_init( ghost, 0, &hash0 );

  ulong duplicate_slot = 1;

  FD_TEST( fd_ghost_hash( ghost, duplicate_slot ) == NULL );

  // Simulate finish replaying a bank by inserting the slot - equivalent to:
  fd_ghost_insert( ghost, &hash0, 1, &hash1, total_stake );

  // Test equivalent to: assert_eq!(blockstore.get_bank_hash(duplicate_slot).unwrap(), duplicate_slot_hash);
  fd_hash_t const * stored_hash = fd_ghost_hash( ghost, duplicate_slot );
  FD_TEST( stored_hash != NULL );
  FD_TEST( memcmp( stored_hash, &hash1, sizeof(fd_hash_t) ) == 0 );

  // Now test freezing another version of the same bank - this creates a duplicate scenario
  fd_hash_t new_bank_hash = { .key = { 2 } };

  // In Ghost, inserting the same slot with a different hash creates a duplicate
  fd_ghost_insert( ghost, &hash0, duplicate_slot, &new_bank_hash, total_stake );

  // The slot map should still point to the original version (the "happy tree")
  // but the new hash should be tracked in the hash map
  fd_hash_t const * slot_map_hash = fd_ghost_hash( ghost, duplicate_slot );
  FD_TEST( slot_map_hash != NULL );
  FD_TEST( memcmp( slot_map_hash, &hash1, sizeof(fd_hash_t) ) == 0 ); // Still original hash

  // The new hash should be queryable directly
  fd_ghost_ele_t const * new_hash_ele = fd_ghost_query( ghost, &new_bank_hash );
  FD_TEST( new_hash_ele != NULL );
  FD_TEST( new_hash_ele->slot == duplicate_slot );

  // Clean up
  fd_wksp_free_laddr( fd_ghost_delete( fd_ghost_leave( ghost ) ) );
}


int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  ulong  page_cnt  = 1;
  char * _page_sz  = "gigantic";
  ulong  numa_idx  = fd_shmem_numa_idx( 0 );
  fd_wksp_t * wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  test_duplicate_simple( wksp );
  test_many_duplicates( wksp );
  // test_ghost_print( wksp );
  test_ghost_simple( wksp );
  test_ghost_publish_left( wksp );
  test_ghost_publish_right( wksp );
  test_ghost_gca( wksp );
  test_ghost_vote_leaves( wksp );
  test_ghost_head_full_tree( wksp );
  test_ghost_head( wksp );
  test_rooted_vote( wksp );
  test_ghost_old_vote_pruned( wksp );
  test_ghost_head_valid( wksp );

  test_duplicate_after_frozen( wksp );
  test_duplicate_node_inserted( wksp );

  /* agave cluster_slot_state_verifier tests*/
  test_state_ancestor_confirmed_descendant_duplicate( wksp );
  run_test_state_duplicate_then_bank_frozen( wksp );
  test_state_ancestor_duplicate_descendant_confirmed( wksp );
  test_state_ancestor_duplicate_descendant_confirmed( wksp );
  test_state_descendant_confirmed_ancestor_duplicate( wksp );

  fd_halt();
  return 0;
}
