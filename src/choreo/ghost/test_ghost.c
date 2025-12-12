#include "fd_ghost.h"
#include "fd_ghost_private.h"
#include "../voter/fd_voter.h"
#include <stdarg.h>

// void setup_block_ids( fd_hash_t * block_ids, ulong cnt ) {
//   for( ulong i = 0; i < cnt; i++ ) block_ids[i] = (fd_hash_t){ .ul = { i } };
// }

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

// fd_ghost_t *
// setup_ghost( fd_wksp_t * wksp, ulong blk_max, ulong vtr_max ) {
//   void       * mem   = fd_wksp_alloc_laddr( wksp, fd_ghost_align(), fd_ghost_footprint( blk_max, vtr_max ), 42UL );
//   fd_ghost_t * ghost = fd_ghost_join( fd_ghost_new( mem, blk_max, vtr_max, 42UL ) );
//   FD_TEST( ghost );
//   fd_hash_t block_ids[7]; setup_block_ids( block_ids, 7 );
//   fd_ghost_insert( ghost, &block_ids[0], NULL         , 0 );
//   fd_ghost_insert( ghost, &block_ids[1], &block_ids[0], 1 );
//   fd_ghost_insert( ghost, &block_ids[2], &block_ids[1], 2 );
//   fd_ghost_insert( ghost, &block_ids[3], &block_ids[1], 3 );
//   fd_ghost_insert( ghost, &block_ids[4], &block_ids[2], 4 );
//   fd_ghost_insert( ghost, &block_ids[5], &block_ids[3], 5 );
//   fd_ghost_insert( ghost, &block_ids[6], &block_ids[5], 6 );
//   return ghost;
// }

// void
// teardown_ghost( fd_ghost_t * ghost ) {
//   fd_wksp_free_laddr( fd_ghost_delete( fd_ghost_leave( ghost ) ) );
// }

// fd_tower_accts_t *
// setup_tower_accts( fd_wksp_t * wksp, ulong max, ... ) {
//   void * mem = fd_wksp_alloc_laddr( wksp, fd_tower_accts_align(), fd_tower_accts_footprint( max ), 1UL );
//   fd_tower_accts_t * tower_accts = fd_tower_accts_join( fd_tower_accts_new( mem, max ) );
//   FD_TEST( tower_accts );

//   va_list ap;
//   va_start( ap, max );
//   for( ulong i = 0; i < max; i++ ) {
//     ulong addr  = va_arg( ap, ulong );
//     ulong stake = va_arg( ap, ulong );
//     ulong vote  = va_arg( ap, ulong );

//     uchar data[3762];
//     memset( data, 0, sizeof(data) );
//     fd_voter_state_t * state = (fd_voter_state_t *)fd_type_pun( data );
//     state->kind = FD_VOTER_STATE_CURRENT;
//     state->cnt  = 1;
//     state->votes[0] = (fd_voter_vote_t){ .slot = vote };

//     fd_tower_accts_push_tail( tower_accts, (fd_tower_accts_t){ .addr = (fd_pubkey_t){ .ul = { addr } }, .stake = stake, .data = data } );
//   }
//   va_end( ap );
//   return tower_accts;
// }

// void
// teardown_tower_accts( fd_tower_accts_t * accts ) {
//   fd_wksp_free_laddr( fd_tower_accts_delete( fd_tower_accts_leave( accts ) ) );
// }

// void
// test_simple( fd_wksp_t * wksp ) {
//   fd_ghost_t * ghost = setup_ghost( wksp, 8, 8 );
//   fd_hash_t    block_ids[7]; setup_block_ids( block_ids, 7 );

//   fd_ghost_blk_t const * root = fd_ghost_root_const( ghost );
//   FD_TEST( root );
//   FD_TEST( 0==memcmp( &root->key, &block_ids[0], sizeof(fd_hash_t) ) );
//   FD_TEST( fd_ghost_best   ( ghost, root )==fd_ghost_query( ghost, &block_ids[6] ) );
//   FD_TEST( fd_ghost_deepest( ghost, root )==fd_ghost_query( ghost, &block_ids[6] ) );
//   FD_TEST( !fd_ghost_verify( ghost ) );

//   teardown_ghost( ghost );
// }

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

// void
// test_publish_left( fd_wksp_t * wksp ) {
//   fd_ghost_t * ghost = setup_ghost( wksp, 8, 8 );
//   fd_hash_t    block_ids[7]; setup_block_ids( block_ids, 7 );

//   fd_ghost_blk_t * blk2 = fd_ghost_query( ghost, &block_ids[2] );
//   FD_TEST( blk2 );
//   fd_ghost_publish( ghost, blk2 );

//   FD_TEST( !fd_ghost_query( ghost, &block_ids[0] ) );
//   FD_TEST( !fd_ghost_query( ghost, &block_ids[1] ) );
//   FD_TEST( !fd_ghost_query( ghost, &block_ids[3] ) );
//   FD_TEST( !fd_ghost_query( ghost, &block_ids[5] ) );
//   FD_TEST( !fd_ghost_query( ghost, &block_ids[6] ) );
//   FD_TEST(  fd_ghost_query( ghost, &block_ids[2] ) );
//   FD_TEST(  fd_ghost_query( ghost, &block_ids[4] ) );

//   fd_ghost_blk_t * root = fd_ghost_root( ghost );
//   FD_TEST( root==fd_ghost_query( ghost, &block_ids[2] ) );
//   FD_TEST( fd_ghost_child( ghost, root )->slot == 4 );
//   FD_TEST( fd_ghost_best   ( ghost, root )==fd_ghost_query( ghost, &block_ids[4] ) );
//   FD_TEST( fd_ghost_deepest( ghost, root )==fd_ghost_query( ghost, &block_ids[4] ) );
//   FD_TEST( !fd_ghost_verify( ghost ) );
//   FD_TEST( pool_free( ghost->pool )==pool_max( ghost->pool ) - 2 );

//   teardown_ghost( ghost );
// }

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

// void
// test_publish_right( fd_wksp_t * wksp ) {
//   fd_ghost_t * ghost = setup_ghost( wksp, 8, 8 );
//   fd_hash_t block_ids[7]; setup_block_ids( block_ids, 7 );

//   fd_ghost_blk_t * blk3 = fd_ghost_query( ghost, &block_ids[3] );
//   FD_TEST( blk3 );
//   fd_ghost_publish( ghost, blk3 );

//   FD_TEST( !fd_ghost_query( ghost, &block_ids[0] ) );
//   FD_TEST( !fd_ghost_query( ghost, &block_ids[1] ) );
//   FD_TEST( !fd_ghost_query( ghost, &block_ids[2] ) );
//   FD_TEST( !fd_ghost_query( ghost, &block_ids[4] ) );
//   FD_TEST( !fd_ghost_query( ghost, &block_ids[3] ) );
//   FD_TEST(  fd_ghost_query( ghost, &block_ids[5] ) );
//   FD_TEST(  fd_ghost_query( ghost, &block_ids[6] ) );

//   fd_ghost_blk_t * root = fd_ghost_root( ghost );
//   FD_TEST( root==fd_ghost_query( ghost, &block_ids[3] ) );
//   FD_TEST( fd_ghost_child( ghost, root )->slot == 5 );
//   FD_TEST( fd_ghost_child( ghost, fd_ghost_child( ghost, root ) )->slot == 6 );
//   FD_TEST( fd_ghost_best   ( ghost, root )==fd_ghost_query( ghost, &block_ids[4] ) );
//   FD_TEST( fd_ghost_deepest( ghost, root )==fd_ghost_query( ghost, &block_ids[4] ) );
//   FD_TEST( !fd_ghost_verify( ghost ) );
//   FD_TEST( pool_free( ghost->pool )==pool_max( ghost->pool ) - 3 );

//   teardown_ghost( ghost );
// }

// void
// test_best( fd_wksp_t * wksp ){
//   fd_ghost_t *       ghost  = setup_ghost( wksp, 8, 8 );
//   fd_tower_accts_t * accts2 = setup_tower_accts( wksp, 'a', 50, 2 );
//   fd_tower_accts_t * accts3 = setup_tower_accts( wksp, 'b', 100, 3 );
//   fd_hash_t block_ids[7]; setup_block_ids( block_ids, 7 );

//   fd_ghost_count_votes( ghost, fd_ghost_query( ghost, &block_ids[4] ), accts2 );
//   fd_ghost_count_votes( ghost, fd_ghost_query( ghost, &block_ids[5] ), accts3 );

//   FD_TEST( fd_ghost_query( ghost, &block_ids[2] )->stake==50 );
//   FD_TEST( fd_ghost_query( ghost, &block_ids[3] )->stake==100 );

//   FD_TEST( fd_ghost_best( ghost, fd_ghost_root( ghost ) )->slot==6 );
//   FD_TEST( fd_ghost_deepest( ghost, fd_ghost_root( ghost ) )->slot==6 );
//   FD_TEST( !fd_ghost_verify( ghost ) );

//   teardown_tower_accts( accts2 );
//   teardown_tower_accts( accts3 );

//   accts2 = setup_tower_accts( wksp, 'a', 50, 3 ); /* both switched */
//   accts3 = setup_tower_accts( wksp, 'b', 100, 2 );

//   fd_ghost_count_votes( ghost, fd_ghost_query( ghost, &block_ids[4] ), accts2 );
//   fd_ghost_count_votes( ghost, fd_ghost_query( ghost, &block_ids[5] ), accts3 );

//   FD_TEST( fd_ghost_best( ghost, fd_ghost_root( ghost ) )->slot==4 );
//   FD_TEST( fd_ghost_deepest( ghost, fd_ghost_root( ghost ) )->slot==6 );
//   FD_TEST( !fd_ghost_verify( ghost ) );

//   teardown_ghost( ghost );
// }

// void
// test_vote_leaves( fd_wksp_t * wksp ) {
//   ulong blk_max     = 8;
//   ulong total_stake = 40;

//   void       * mem   = fd_wksp_alloc_laddr( wksp, fd_ghost_align(), fd_ghost_footprint( 8, 8 ), 42UL );
//   fd_ghost_t * ghost = fd_ghost_join( fd_ghost_new( mem, 8, 8, 42UL ) );
//   FD_TEST( ghost );

//   fd_hash_t block_ids[blk_max]; setup_block_ids( block_ids, blk_max );
//   block_ids[0] = (fd_hash_t) { .ul = { ULONG_MAX } };
//   for( ulong i = 1; i < blk_max; i++ ) {
//     block_ids[i] = (fd_hash_t) { .key = { (uchar)i } };
//   }

//   /* make a full binary tree */
//   fd_ghost_insert( ghost, &block_ids[0], NULL, 0 );
//   for( ulong i = 1; i < blk_max - 1; i++){
//     FD_LOG_NOTICE(( "inserting %lu with parent %lu", i, (i-1)/2 ));
//     fd_ghost_insert( ghost, &block_ids[i], &block_ids[(i-1)/2], i );
//     FD_TEST( !fd_ghost_verify( ghost ) );
//   }
//   FD_TEST( !fd_ghost_verify( ghost ) );

//   /* one validator changes votes along leaves */
//   int d = 3;
//   ulong first_leaf = fd_ulong_pow2(d-1) - 1;
//   fd_voter_t v = { .key = { { 0 } }, .stake = 10, .replay_vote = { .slot = FD_SLOT_NULL } };
//   for( ulong i = first_leaf; i < blk_max - 1; i++){
//     fd_ghost_count_vote( ghost, &v, &block_ids[i] );
//   }
//   FD_TEST( !fd_ghost_verify( ghost ) );


// # if PRINT
//   fd_ghost_print( ghost, total_stake, fd_ghost_root( ghost ) );
// # else
//   (void)total_stake;
// # endif

//   ulong path[d];
//   ulong leaf = blk_max - 2;
//   for( int i = d - 1; i >= 0; i--){
//     path[i] = leaf;
//     leaf = (leaf - 1) / 2;
//   }

//   /* check weights and stakes */
//   int j = 0;
//   for( ulong i = 0; i < blk_max - 1; i++){
//     fd_ghost_blk_t const * blk = fd_ghost_query( ghost, &hash_arr[i] );
//     if ( i == blk_max - 2) FD_TEST( blk->replay_stake == 10 );
//     else  FD_TEST( blk->replay_stake == 0 );

//     if( i == path[j] ) { /* if on fork */
//       FD_TEST( blk->stake == 10 );
//       j++;
//     } else {
//       FD_TEST( blk->stake == 0 );
//     }
//   }

//   /* have other validators vote for rest of leaves */
//   for ( ulong i = first_leaf; i < blk_max - 2; i++){
//     fd_voter_t v = { .key = { .key = { (uchar)i }  }, .stake = 10, .replay_vote = { .slot = FD_SLOT_NULL } };
//     fd_ghost_count_vote( ghost, &v, &hash_arr[i] );
//     FD_TEST( !fd_ghost_verify( ghost ) );
//   }

//   /* check weights and stakes */
//   for( ulong i = 0; i < blk_max - 1; i++){
//     fd_ghost_blk_t const * blk = fd_ghost_query( ghost, &hash_arr[i] );
//     if ( i >= first_leaf){
//       FD_TEST( blk->replay_stake == 10 );
//       FD_TEST( blk->stake == 10 );
//     } else {
//       FD_TEST( blk->replay_stake == 0 );
//       FD_TEST( blk->stake > 10);
//     }
//   }

//   FD_TEST( !fd_ghost_verify( ghost ) );
// # if PRINT
//   fd_ghost_print( ghost, total_stake, fd_ghost_root( ghost ) );
// # endif
// }

// void
// test_old_vote_pruned( fd_wksp_t * wksp ){
//   ulong  blk_max   = 16;
//   ulong total_stake = 50;
//   void * mem      = fd_wksp_alloc_laddr( wksp,
//     fd_ghost_align(),
//     fd_ghost_footprint( blk_max ),
//     1UL );
//   FD_TEST( mem );
//   fd_ghost_t * ghost = fd_ghost_join( fd_ghost_new( mem, blk_max, 0UL ) );

//   fd_hash_t hash_arr[blk_max];
//   hash_arr[0] = (fd_hash_t) { .ul = { ULONG_MAX } };
//   for( ulong i = 1; i < blk_max; i++){
//     hash_arr[i] = (fd_hash_t) { .key = { (uchar)i } };
//   }

//   fd_ghost_init( ghost, 0, &hash_arr[0] );
//   for ( ulong i = 1; i < blk_max - 1; i++ ) {
//     fd_ghost_update( ghost, &hash_arr[(i-1)/2], i, &hash_arr[i], total_stake );
//     fd_voter_t v = { .key = { { (uchar)i } }, .stake = i, .replay_vote = { .slot = FD_SLOT_NULL } };
//     fd_ghost_count_vote( ghost, &v, &hash_arr[i] );
//   }

//   fd_ghost_publish( ghost, &hash_arr[1]);
// # if PRINT
//   fd_ghost_print( ghost, total_stake, fd_ghost_root( ghost ) );
// # else
//   (void)total_stake;
// # endif

//   fd_voter_t switch_voter = { .key = { { 5 } }, .stake = 5, .replay_vote = { .slot = 5 } };
//   fd_ghost_count_vote( ghost, &switch_voter, &hash_arr[9] );
//   /* switching to vote 9, from voting 5, that is > than the root */
// # if PRINT
//   fd_ghost_print( ghost, total_stake, fd_ghost_root( ghost ) );
// # endif

//   FD_TEST( fd_ghost_query( ghost, &hash_arr[9] )->stake == 14 );
//   FD_TEST( fd_ghost_query( ghost, &hash_arr[3] )->stake == 18 );
//   FD_TEST( fd_ghost_query( ghost, &hash_arr[4] )->stake == 28 );
//   FD_TEST( fd_ghost_query( ghost, &hash_arr[1] )->stake == 47 ); /* full tree */

//   FD_TEST( !fd_ghost_verify( ghost ) );

//   fd_ghost_publish( ghost, &hash_arr[3] ); /* cut down to blks 3,7,8 */
//   /* now previously voted 2 ( < the root ) votes for 7 */
//   fd_voter_t switch_voter2 = { .key = { { 2 } }, .stake = 2, .replay_vote = { .slot = 2 } };
//   fd_ghost_count_vote( ghost, &switch_voter2, &hash_arr[7] );

// # if PRINT
//   fd_ghost_print( ghost, total_stake, fd_ghost_root( ghost ) );
// # endif
//   FD_TEST( fd_ghost_query( ghost, &hash_arr[7] )->stake == 9 );
//   FD_TEST( fd_ghost_query( ghost, &hash_arr[8] )->stake == 8 );
//   FD_TEST( fd_ghost_query( ghost, &hash_arr[3] )->stake == 20 );

//   FD_TEST( !fd_ghost_verify( ghost ) );
// }

// void
// test_best_full_tree( fd_wksp_t * wksp ){
//   ulong  blk_max    = 16;
//   ulong  total_stake = 120;
//   void * mem         = fd_wksp_alloc_laddr( wksp,
//                                        fd_ghost_align(),
//                                        fd_ghost_footprint( blk_max ),
//                                        1UL );
//   FD_TEST( mem );
//   fd_ghost_t * ghost = fd_ghost_join( fd_ghost_new( mem, blk_max, 0UL ) );

//   fd_hash_t hash_arr[blk_max];
//   hash_arr[0] = (fd_hash_t) { .ul = { ULONG_MAX } };
//   for( ulong i = 1; i < blk_max; i++){
//     hash_arr[i] = (fd_hash_t) { .key = { (uchar)i } };
//   }

//   fd_ghost_init( ghost, 0, &hash_arr[0] );

//   for ( ulong i = 1; i < blk_max - 1; i++ ) {
//     fd_ghost_update( ghost, &hash_arr[(i-1)/2], i, &hash_arr[i], total_stake );
//     fd_voter_t v = { .key = { { (uchar)i } }, .stake = i, .replay_vote = { .slot = FD_SLOT_NULL } };
//     fd_ghost_count_vote( ghost, &v, &hash_arr[i] );
//   }

//   for ( ulong i = 0; i < blk_max - 1; i++ ) {
//     fd_ghost_blk_t const * blk = fd_ghost_query( ghost, &hash_arr[i] );
//     FD_TEST( blk->replay_stake == i );
//   }

//   FD_TEST( !fd_ghost_verify( ghost ) );

// # if PRINT
//   fd_ghost_print( ghost, total_stake, fd_ghost_root( ghost ) );
// # endif
//   fd_ghost_blk_t const * head = fd_ghost_best( ghost, fd_ghost_root( ghost ) );

//   /* head will always be rightmost blk in this complete binary tree */

//   FD_TEST( head->slot == 14 );

//   /* add one more blk */

//   fd_ghost_update( ghost, &hash_arr[(blk_max-2)/2], blk_max - 1, &hash_arr[blk_max - 1], total_stake );
//   fd_voter_t v = { .key = { { (uchar)( blk_max - 1 ) } }, .stake = blk_max - 1, .replay_vote = { .slot = FD_SLOT_NULL } };
//   fd_ghost_count_vote( ghost, &v, &hash_arr[blk_max - 1]);

//   FD_TEST( !fd_ghost_verify( ghost ) );
//   head = fd_ghost_best( ghost, fd_ghost_root( ghost ) );
//   FD_TEST( head->slot == 14 );

//   /* adding one more blk would fail. */
// }

/*
         slot 10
         /    \
    slot 11    |
       |    slot 12
    slot 13
*/

// void
// test_best_valid( fd_wksp_t * wksp ) {
//   ulong  blk_max = 16;
//   void * mem      = fd_wksp_alloc_laddr( wksp, fd_ghost_align(), fd_ghost_footprint( blk_max ), 1UL );
//   FD_TEST( mem );
//   fd_ghost_t * ghost = fd_ghost_join( fd_ghost_new( mem, blk_max, 0UL ) );

//   fd_pubkey_t  pk1   = { { 1 } };
//   fd_pubkey_t  pk2   = { { 2 } };
//   ulong        total = 150;
//   fd_epoch_t * epoch = mock_epoch( wksp, 150, 2, pk1, 50, pk2, 100 );
//   fd_voter_t * v1    = fd_epoch_voters_query( fd_epoch_voters( epoch ), pk1, NULL );
//   fd_voter_t * v2    = fd_epoch_voters_query( fd_epoch_voters( epoch ), pk2, NULL );

//   fd_hash_t hash_10 = { .key = { 10 } };
//   fd_hash_t hash_11 = { .key = { 11 } };
//   fd_hash_t hash_12 = { .key = { 12 } };
//   fd_hash_t hash_13 = { .key = { 13 } };

//   fd_ghost_init( ghost, 10, &hash_10 );
//   INSERT( 11, 10 );
//   INSERT( 12, 10 );
//   INSERT( 13, 11 );

//   fd_ghost_count_vote( ghost, v1, &hash_11 );
//   FD_TEST( !fd_ghost_verify( ghost ) );

//   fd_ghost_count_vote( ghost, v2, &hash_12 );
//   FD_TEST( !fd_ghost_verify( ghost ) );

//   // fd_ghost_blk_t const * head = fd_ghost_best( ghost, fd_ghost_root( ghost ) );
//   // FD_TEST( head->slot == 12 );

//   fd_ghost_count_vote( ghost, v1, &hash_13 );
//   FD_TEST( !fd_ghost_verify( ghost ) );

//   // fd_ghost_blk_t const * head2 = fd_ghost_best( ghost, fd_ghost_root( ghost ) );
//   // FD_TEST( head2->slot == 12 );

//   query_mut( ghost, 12 )->valid = 0; // mark 12 as invalid
//   // fd_ghost_blk_t const * head3 = fd_ghost_best( ghost, fd_ghost_root( ghost ) );
//   // FD_TEST( head3->slot == 13 );

//   fd_ghost_count_vote( ghost, v2, &hash_13 );
//   query_mut( ghost, 11 )->valid = 0; // mark 11 as invalid
//   // fd_ghost_blk_t const * head4 = fd_ghost_best( ghost, fd_ghost_root( ghost ) );
//   // FD_TEST( head4->slot == 10 );

//   query_mut( ghost, 12 )->valid = 1; // mark 12 as valid
//   fd_ghost_blk_t const * head5 = fd_ghost_best( ghost, fd_ghost_root( ghost ) );
//   FD_TEST( head5->slot == 12 );

// # if PRINT
//   fd_ghost_print( ghost, total, fd_ghost_root( ghost ) );
// # else
//   (void)total;
// # endif

//   fd_wksp_free_laddr( mem );
// }

// void
// test_duplicate_simple( fd_wksp_t * wksp ) {
//   ulong  blk_max     = 16;
//   ulong  total_stake = 10;
//   void * mem = fd_wksp_alloc_laddr( wksp, fd_ghost_align(), fd_ghost_footprint( blk_max ), 1UL );
//   FD_TEST( mem );

  /* 1
    / \
   2   2'
   |   |
   3   4 */

//   fd_ghost_t *     ghost = fd_ghost_join( fd_ghost_new( mem, blk_max, 0UL ) );
//   fd_ghost_blk_t * pool  = pool( ghost );

//   fd_hash_t hash_1 = { .key = { 1 } };
//   fd_hash_t hash_2 = { .key = { 2 } };
//   fd_hash_t hash_2_prime = { .key = { 2, 1 } };
//   fd_hash_t hash_3 = { .key = { 3 } };
//   fd_hash_t hash_4 = { .key = { 4 } };

//   fd_ghost_init( ghost, 1, &hash_1 );

//   /* We see 2 and 3 first, so we replay down the left branch first */
//   fd_ghost_update( ghost, &hash_1, 2, &hash_2, total_stake );
//   fd_ghost_update( ghost, &hash_2, 3, &hash_3, total_stake );

//   /* We see evidence of 2' and 4. Add them to the tree */
//   fd_ghost_update( ghost, &hash_1, 2, &hash_2_prime, total_stake );
//   fd_ghost_update( ghost, &hash_2_prime, 4, &hash_4, total_stake );

//   /* Only 1 - 2 - 3 should be visible in the slot map */
//   FD_TEST( memcmp( fd_ghost_hash( ghost, 1 ), &hash_1, sizeof(fd_hash_t) ) == 0 );
//   FD_TEST( memcmp( fd_ghost_hash( ghost, 2 ), &hash_2, sizeof(fd_hash_t) ) == 0 );
//   FD_TEST( memcmp( fd_ghost_hash( ghost, 3 ), &hash_3, sizeof(fd_hash_t) ) == 0 );
//   FD_TEST( memcmp( fd_ghost_hash( ghost, 4 ), &hash_4, sizeof(fd_hash_t) ) == 0 );

//   fd_ghost_blk_t const * dup_child = fd_ghost_query( ghost, &hash_4 );
//   fd_ghost_blk_t const * dup_parent = pool_ele( pool, dup_child->parent );
//   FD_TEST( dup_parent->slot == 2 );
//   FD_TEST( memcmp( &dup_parent->key, &hash_2_prime, sizeof(fd_hash_t) ) == 0 );

//   fd_ghost_print( ghost, total_stake, fd_ghost_root( ghost ) );

//   FD_TEST( !fd_ghost_verify( ghost ) );
// }

// void
// test_many_duplicates( fd_wksp_t * wksp ){
//   ulong blk_max = 16;
//   ulong total_stake = 10;
//   void * mem = fd_wksp_alloc_laddr( wksp,
//                                     fd_ghost_align(),
//                                     fd_ghost_footprint( blk_max ),
//                                     1UL );
//   FD_TEST( mem );

//   fd_ghost_t * ghost = fd_ghost_join( fd_ghost_new( mem, blk_max, 0UL ) );
//   fd_ghost_slot_map_t * map_slot = fd_ghost_slot_map( ghost );
//   fd_ghost_blk_t * pool = pool( ghost );

//   fd_hash_t hash_1 = { .key = { 1 } };
//   fd_hash_t hash_2 = { .key = { 2 } };
//   fd_hash_t hash_2_prime = { .key = { 2, 1 } };
//   fd_hash_t hash_3 = { .key = { 3 } };
//   fd_hash_t hash_3_prime = { .key = { 3, 1 } };
//   fd_hash_t hash_4 = { .key = { 4 } };
//   fd_hash_t hash_4_prime = { .key = { 4, 1 } };
//   fd_hash_t hash_4_prime_prime = { .key = { 4, 1, 1 } };

    /* 1
      / \
    2   2'
    |   |
    3   3'
    / \  |
  4  4' 4'' */

//   fd_ghost_init( ghost, 1, &hash_1 );

//   /* Slots I see initially*/

//   fd_ghost_update( ghost, &hash_1, 2, &hash_2, total_stake );
//   fd_ghost_update( ghost, &hash_2, 3, &hash_3, total_stake );
//   fd_ghost_update( ghost, &hash_3, 4, &hash_4, total_stake );

//   /* Evidence of duplicates */

//   fd_ghost_update( ghost, &hash_1, 2, &hash_2_prime, total_stake );
//   fd_ghost_update( ghost, &hash_2_prime, 3, &hash_3_prime, total_stake );
//   fd_ghost_update( ghost, &hash_3_prime, 4, &hash_4_prime_prime, total_stake );
//   fd_ghost_update( ghost, &hash_3, 4, &hash_4_prime, total_stake );

//   ulong visible_slots[4] = { 3, 1, 2, 4 };
//   fd_hash_t visible_hashes[4] = { hash_3, hash_1, hash_2, hash_4 };
//   int cnt = 0;
//   for( fd_ghost_slot_map_iter_t iter = fd_ghost_slot_map_iter_init( map_slot, pool );
//        !fd_ghost_slot_map_iter_done( iter, map_slot, pool );
//        iter = fd_ghost_slot_map_iter_next( iter, map_slot, pool ) ) {
//     fd_ghost_blk_t const * ele = fd_ghost_slot_map_iter_ele( iter, map_slot, pool );
//     FD_LOG_NOTICE(( "ele->slot: %lu, visible_slots[cnt]: %lu", ele->slot, visible_slots[cnt] ));
//     FD_TEST( ele->slot == visible_slots[cnt] );
//     FD_TEST( memcmp( &ele->key, &visible_hashes[cnt], sizeof(fd_hash_t) ) == 0 );
//     cnt++;
//   }
//   FD_TEST( cnt == 4 );

//   fd_ghost_print( ghost, total_stake, fd_ghost_root( ghost ) );

//   /* Vote down the left branch */
//   fd_voter_t v1 = { .key = { { 1 } }, .stake = 10, .replay_vote = { .slot = FD_SLOT_NULL } };
//   fd_ghost_count_vote( ghost, &v1, &hash_4 );
// }

// /* Key differences between Agave and Firedancer:  Agave inserts to their
//    fork tracking structure before the bank is frozen.  Thus they can
//    build forks and mark things duplicate/duplicate confirmed, but it has
//    no effect bevause the bank is not yet frozen.  However, Firedancer
//    only adds to ghost once the bank is frozen, and the slot has been
//    fully replayed. */

// void
// run_test_state_duplicate_then_bank_frozen( fd_wksp_t * wksp ) {
//   /* covers both mid-replay and haven't started replay test cases */
//   ulong blk_max = 16;
//   ulong total_stake = 10;
//   void * mem = fd_wksp_alloc_laddr( wksp,
//                                     fd_ghost_align(),
//                                     fd_ghost_footprint( blk_max ),
//                                     1UL );
//   FD_TEST( mem );

//   fd_ghost_t     * ghost = fd_ghost_join( fd_ghost_new( mem, blk_max, 0UL ) );

//   fd_hash_t hash_0 = { .ul = { ULONG_MAX } };
//   fd_hash_t hash_1 = { .key = { 1 } };
//   fd_hash_t hash_2 = { .key = { 2 } };

//   fd_ghost_init( ghost, 0, &hash_0 );
//   fd_ghost_update( ghost, &hash_0, 1, &hash_1, total_stake );

//   /* Get a duplicate message shred/gossip/repair. Nothing happens because
//      the slot 2 has not yet been replayed  */
//   process_duplicate( ghost, 2, total_stake );
//   FD_TEST( fd_ghost_hash( ghost, 2 ) == NULL );
//   FD_TEST( fd_ghost_best( ghost, fd_ghost_root( ghost ) )->slot == 1 );

//   /* Finish replaying slot 2, hash 2 */
//   fd_ghost_update( ghost, &hash_1, 2, &hash_2, total_stake );
//   FD_TEST( !fd_ghost_query( ghost, &hash_2 )->valid );
//   /* Parent of 2 is 1, so head should be 1 */
//   FD_TEST( fd_ghost_best( ghost, fd_ghost_root( ghost ) )->slot == 1 );
// }

// void
// test_state_ancestor_confirmed_descendant_duplicate( fd_wksp_t * wksp ){
//   ulong blk_max = 16;
//   ulong total_stake = 10;
//   void * mem = fd_wksp_alloc_laddr( wksp,
//                                     fd_ghost_align(),
//                                     fd_ghost_footprint( blk_max ),
//                                     1UL );
//   FD_TEST( mem );

//   /* 0 - 1 - 2 - 3 */
//   fd_ghost_t * ghost = fd_ghost_join( fd_ghost_new( mem, blk_max, 0UL ) );
//   fd_dup_seen_t * dup_map = fd_ghost_dup_map( ghost );

//   fd_hash_t hash_0 = { .ul = { ULONG_MAX } };
//   fd_hash_t hash_1 = { .key = { 1 } };
//   fd_hash_t hash_2 = { .key = { 2 } };
//   fd_hash_t hash_3 = { .key = { 3 } };

//   fd_ghost_init( ghost, 0, &hash_0 );
//   fd_ghost_update( ghost, &hash_0, 1, &hash_1, total_stake );
//   fd_ghost_update( ghost, &hash_1, 2, &hash_2, total_stake );
//   fd_ghost_update( ghost, &hash_2, 3, &hash_3, total_stake );

//   FD_TEST( fd_ghost_best( ghost, fd_ghost_root( ghost ) )->slot == 3 );
//   process_duplicate_confirmed( ghost, &hash_2, 2 );
//   FD_TEST( fd_ghost_best( ghost, fd_ghost_root( ghost ) )->slot == 3 );

//   /* mark 3 as duplicate */
//   process_duplicate( ghost, 3, total_stake );
//   FD_TEST( fd_dup_seen_map_query( dup_map, 3, NULL ) );

//   FD_TEST( fd_ghost_best( ghost, fd_ghost_root( ghost ) )->slot == 2 );
// }

// void
// test_state_ancestor_duplicate_descendant_confirmed( fd_wksp_t * wksp ){
//   ulong blk_max = 16;
//   ulong total_stake = 18;
//   void * mem = fd_wksp_alloc_laddr( wksp,
//                                     fd_ghost_align(),
//                                     fd_ghost_footprint( blk_max ),
//                                     1UL );
//   FD_TEST( mem );

//   fd_ghost_t * ghost = fd_ghost_join( fd_ghost_new( mem, blk_max, 0UL ) );
//   fd_dup_seen_t * dup_map = fd_ghost_dup_map( ghost );

//   fd_hash_t hash_0 = { .ul = { ULONG_MAX } };
//   fd_hash_t hash_1 = { .key = { 1 } };
//   fd_hash_t hash_2 = { .key = { 2 } };
//   fd_hash_t hash_3 = { .key = { 3 } };

//   fd_ghost_init( ghost, 0, &hash_0 );
//   fd_ghost_update( ghost, &hash_0, 1, &hash_1, total_stake );
//   fd_ghost_update( ghost, &hash_1, 2, &hash_2, total_stake );
//   fd_ghost_update( ghost, &hash_2, 3, &hash_3, total_stake );

//   FD_TEST( fd_ghost_best( ghost, fd_ghost_root( ghost ) )->slot == 3 );

//   process_duplicate( ghost, 2, total_stake );
//   FD_TEST( fd_dup_seen_map_query( dup_map, 2, NULL ) );
//   FD_TEST( fd_ghost_best( ghost, fd_ghost_root( ghost ) )->slot == 1 );

//   fd_voter_t v1 = { .key = { { 1 } }, .stake = 10, .replay_vote = { .slot = FD_SLOT_NULL } };
//   fd_ghost_count_vote( ghost, &v1, &hash_3 );

//   FD_TEST( is_duplicate_confirmed( ghost, &hash_3, total_stake ) );

//   /* 3 becomes duplicate confirmed */
//   if( is_duplicate_confirmed( ghost, &hash_3, total_stake ) ) {
//     process_duplicate_confirmed( ghost, &hash_3, 3 );
//   }
//   FD_TEST( fd_ghost_query( ghost, &hash_3 )->valid );
//   FD_TEST( fd_ghost_best( ghost, fd_ghost_root( ghost ) )->slot == 3 );
// }

// void
// test_state_descendant_confirmed_ancestor_duplicate( fd_wksp_t * wksp ){
//   ulong blk_max = 16;
//   ulong total_stake = 18;
//   void * mem = fd_wksp_alloc_laddr( wksp,
//                                     fd_ghost_align(),
//                                     fd_ghost_footprint( blk_max ),
//                                     1UL );
//   FD_TEST( mem );

//   /* 0 - 1 - 2 - 3 */
//   fd_ghost_t * ghost = fd_ghost_join( fd_ghost_new( mem, blk_max, 0UL ) );
//   fd_dup_seen_t * dup_map = fd_ghost_dup_map( ghost );

//   fd_hash_t hash_0 = { .ul = { ULONG_MAX } };
//   fd_hash_t hash_1 = { .key = { 1 } };
//   fd_hash_t hash_2 = { .key = { 2 } };
//   fd_hash_t hash_3 = { .key = { 3 } };

//   fd_ghost_init( ghost, 0, &hash_0 );
//   fd_ghost_update( ghost, &hash_0, 1, &hash_1, total_stake );
//   fd_ghost_update( ghost, &hash_1, 2, &hash_2, total_stake );
//   fd_ghost_update( ghost, &hash_2, 3, &hash_3, total_stake );

//   FD_TEST( fd_ghost_best( ghost, fd_ghost_root( ghost ) )->slot == 3 );
//   fd_voter_t v1 = { .key = { { 1 } }, .stake = 10, .replay_vote = { .slot = FD_SLOT_NULL } };
//   fd_ghost_count_vote( ghost, &v1, &hash_3 );

//   FD_TEST( is_duplicate_confirmed( ghost, &hash_3, total_stake ) );

//   /* 3 becomes duplicate confirmed */
//   if( is_duplicate_confirmed( ghost, &hash_3, total_stake ) ) {
//     process_duplicate_confirmed( ghost, &hash_3, 3 );
//   }
//   fd_ghost_print( ghost, total_stake, fd_ghost_root( ghost ) );
//   for( ulong slot = 0; slot < 4; slot++ ) {
//     fd_ghost_blk_t const * ele = fd_ghost_query( ghost, fd_ghost_hash( ghost, slot ) );
//     FD_TEST( ele->valid );
//     FD_LOG_NOTICE(("slot %lu, ele->key: %s", slot, FD_BASE58_ENC_32_ALLOCA(&ele->key) ));
//     FD_TEST( is_duplicate_confirmed( ghost, &ele->key, total_stake ) );
//   }

//   process_duplicate( ghost, 1, total_stake );
//   FD_TEST( fd_dup_seen_map_query( dup_map, 1, NULL ) );
//   FD_TEST( fd_ghost_best( ghost, fd_ghost_root( ghost ) )->slot == 3 );

// }

// void
// test_duplicate_after_frozen( fd_wksp_t * wksp ){
//   ulong blk_max    = 16;
//   ulong total_stake = 10;
//   void * mem = fd_wksp_alloc_laddr( wksp,
//                                     fd_ghost_align(),
//                                     fd_ghost_footprint( blk_max ),
//                                     1UL );
//   FD_TEST( mem );

//   fd_ghost_t * ghost = fd_ghost_join( fd_ghost_new( mem, blk_max, 0UL ) );

//   fd_hash_t hash_0 = { .ul = { ULONG_MAX } };
//   fd_hash_t hash_1 = { .key = { 1 } };
//   fd_ghost_init( ghost, 0, &hash_0 );
//   fd_ghost_update( ghost, &hash_0, 1, &hash_1, total_stake );
//   process_duplicate( ghost, 1, total_stake );

//   FD_TEST( fd_ghost_best( ghost, fd_ghost_root( ghost ) )->slot == 0 );
// }

// void
// test_duplicate_blk_inserted( fd_wksp_t * wksp ) {
//   ulong blk_max = 16;
//   ulong total_stake = 10;
//   void * mem = fd_wksp_alloc_laddr( wksp,
//                                     fd_ghost_align(),
//                                     fd_ghost_footprint( blk_max ),
//                                     1UL );
//   FD_TEST( mem );

//   fd_ghost_t * ghost = fd_ghost_join( fd_ghost_new( mem, blk_max, 0UL ) );
//   fd_hash_t    hash0 = { .ul = { ULONG_MAX } };
//   fd_hash_t    hash1 = { .key = { 1 } };

//   fd_ghost_init( ghost, 0, &hash0 );

//   ulong duplicate_slot = 1;

//   FD_TEST( fd_ghost_hash( ghost, duplicate_slot ) == NULL );

//   // Simulate finish replaying a bank by inserting the slot - equivalent to:
//   fd_ghost_update( ghost, &hash0, 1, &hash1, total_stake );

//   // Test equivalent to: assert_eq!(blockstore.get_bank_hash(duplicate_slot).unwrap(), duplicate_slot_hash);
//   fd_hash_t const * stored_hash = fd_ghost_hash( ghost, duplicate_slot );
//   FD_TEST( stored_hash != NULL );
//   FD_TEST( memcmp( stored_hash, &hash1, sizeof(fd_hash_t) ) == 0 );

//   // Now test freezing another version of the same bank - this creates a duplicate scenario
//   fd_hash_t new_bank_hash = { .key = { 2 } };

//   // In Ghost, inserting the same slot with a different hash creates a duplicate
//   fd_ghost_update( ghost, &hash0, duplicate_slot, &new_bank_hash, total_stake );

//   // The slot map should still point to the original version (the "happy tree")
//   // but the new hash should be tracked in the hash map
//   fd_hash_t const * slot_map_hash = fd_ghost_hash( ghost, duplicate_slot );
//   FD_TEST( slot_map_hash != NULL );
//   FD_TEST( memcmp( slot_map_hash, &hash1, sizeof(fd_hash_t) ) == 0 ); // Still original hash

//   // The new hash should be queryable directly
//   fd_ghost_blk_t const * new_hash_ele = fd_ghost_query( ghost, &new_bank_hash );
//   FD_TEST( new_hash_ele != NULL );
//   FD_TEST( new_hash_ele->slot == duplicate_slot );

//   // Clean up
//   fd_wksp_free_laddr( fd_ghost_delete( fd_ghost_leave( ghost ) ) );
// }


int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  ulong  page_cnt  = 1;
  char * _page_sz  = "gigantic";
  ulong  numa_idx  = fd_shmem_numa_idx( 0 );
  fd_wksp_t * wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  // test_duplicate_simple( wksp );
  // test_many_duplicates( wksp );
  // // test_print( wksp );
  // test_simple( wksp );
  // test_publish_left( wksp );
  // test_publish_right( wksp );
  // test_gca( wksp );
  // test_vote_leaves( wksp );
  // test_best_full_tree( wksp );
  // test_best( wksp );
  // test_rooted_vote( wksp );
  // test_old_vote_pruned( wksp );
  // test_best_valid( wksp );

  // test_duplicate_after_frozen( wksp );
  // test_duplicate_blk_inserted( wksp );

  // /* agave cluster_slot_state_verifier tests*/
  // test_state_ancestor_confirmed_descendant_duplicate( wksp );
  // run_test_state_duplicate_then_bank_frozen( wksp );
  // test_state_ancestor_duplicate_descendant_confirmed( wksp );
  // test_state_ancestor_duplicate_descendant_confirmed( wksp );
  // test_state_descendant_confirmed_ancestor_duplicate( wksp );

  fd_halt();
  return 0;
}
