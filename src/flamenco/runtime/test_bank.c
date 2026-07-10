#include "fd_bank.h"
#include "../rewards/fd_stake_rewards.h"
#include "sysvar/fd_sysvar_epoch_schedule.h"

#include <stdlib.h> // ARM64: aligned_alloc(3)

static fd_stake_delegation_t const *
test_bank_frontier_delegation_query( fd_banks_t *                   banks FD_PARAM_UNUSED,
                                     fd_stake_delegations_t const * stake_delegations,
                                     fd_pubkey_t const *            stake_account ) {
  fd_stake_delegations_iter_t iter_[1];
  for( fd_stake_delegations_iter_t * iter = fd_stake_delegations_iter_init( iter_, stake_delegations );
       !fd_stake_delegations_iter_done( iter );
       fd_stake_delegations_iter_next( iter ) ) {
    fd_stake_delegation_t const * stake_delegation = fd_stake_delegations_iter_ele( iter );
    if( FD_UNLIKELY( stake_delegation->is_tombstone ) ) continue;
    if( FD_LIKELY( !memcmp( &stake_delegation->stake_account, stake_account, sizeof(fd_pubkey_t) ) ) ) {
      return stake_delegation;
    }
  }

  return NULL;
}

static void
test_bank_advancing( void * mem ) {
  fd_banks_t * banks = fd_banks_join( fd_banks_new( mem, 16UL, 4UL, 2048UL, 2048UL, 0, 8888UL ) );
  /* Create the following fork tree with refcnts:

         P(0)
       /    \\
     Q(1)    A(0)
           / ||  \
       X(0) B(0)  C(0)
      /      || \
     Y(0)   M(0) R(0)
           / ||   /  \
       D(2) T(0) J(0) L(0)
             ||
             ..
             ..
             ||
     blocks we might be actively replaying

     Where || marks the rooted fork and numbers in parentheses are
     refcnts.

     When Q's refcnt drops to 0, we should be able to advance the
     published root to block M, because blocks P, A, and B, as well as
     all subtrees branching off of them, have refcnt 0. */

  /* Start with P as root. */
  fd_bank_t * bank_P = fd_banks_init_bank( banks );
  FD_TEST( bank_P ); /* P slot = 100 */
  FD_TEST( bank_P->bank_seq==1UL );
  bank_P->f.slot = 100UL;
  FD_TEST( bank_P->f.slot == 100UL );
  bank_P->refcnt = 0UL; /* P(0) */
  ulong bank_idx_P = bank_P->idx;

  /* Create Q branch from P. */
  fd_bank_t * bank_Q = fd_banks_new_bank( banks, bank_idx_P, 0L, 0 );
  ulong bank_idx_Q = bank_Q->idx;
  bank_Q = fd_banks_clone_from_parent( banks, bank_idx_Q );
  FD_TEST( bank_Q );  /* Q slot = 101 */
  FD_TEST( bank_Q->bank_seq==2UL );
  bank_Q->f.slot = 101UL;
  bank_Q->refcnt = 1UL; /* Q(1) */
  fd_banks_mark_bank_frozen( bank_Q );
  FD_TEST( fd_banks_bank_query( banks, bank_idx_Q ) == bank_Q );

  /* Create A branch from P - this is on the rooted fork. */
  fd_bank_t * bank_A = fd_banks_new_bank( banks, bank_idx_P, 0L, 0 );
  ulong bank_idx_A = bank_A->idx;
  bank_A = fd_banks_clone_from_parent( banks, bank_idx_A );
  FD_TEST( bank_A );  /* A slot = 102 */
  FD_TEST( bank_A->bank_seq==3UL );
  bank_A->f.slot = 102UL;
  bank_A->refcnt = 0UL; /* A(0) */
  fd_banks_mark_bank_frozen( bank_A );

  /* Create X branch from A. */
  fd_bank_t * bank_X = fd_banks_new_bank( banks, bank_idx_A, 0L, 0 );
  ulong bank_idx_X = bank_X->idx;
  bank_X = fd_banks_clone_from_parent( banks, bank_idx_X );
  FD_TEST( bank_X );  /* X slot = 103 */
  FD_TEST( bank_X->bank_seq==4UL );
  bank_X->f.slot = 103UL;
  bank_X->refcnt = 0UL; /* X(0) */
  fd_banks_mark_bank_frozen( bank_X );

  /* Create Y branch from X. */
  fd_bank_t * bank_Y = fd_banks_new_bank( banks, bank_idx_X, 0L, 0 );
  ulong bank_idx_Y = bank_Y->idx;
  bank_Y = fd_banks_clone_from_parent( banks, bank_idx_Y );
  FD_TEST( bank_Y );  /* Y slot = 104 */
  FD_TEST( bank_Y->bank_seq==5UL );
  bank_Y->f.slot = 104UL;
  bank_Y->refcnt = 0UL; /* Y(0) */
  fd_banks_mark_bank_frozen( bank_Y );

  /* Create B branch from A - this is on the rooted fork. */
  fd_bank_t * bank_B = fd_banks_new_bank( banks, bank_idx_A, 0L, 0 );
  ulong bank_idx_B = bank_B->idx;
  bank_B = fd_banks_clone_from_parent( banks, bank_idx_B );
  FD_TEST( bank_B );  /* B slot = 105 */
  FD_TEST( bank_B->bank_seq==6UL );
  bank_B->f.slot = 105UL;
  bank_B->refcnt = 0UL; /* B(0) */
  fd_banks_mark_bank_frozen( bank_B );

  /* Create C branch from A. */
  fd_bank_t * bank_C = fd_banks_new_bank( banks, bank_idx_A, 0L, 0 );
  ulong bank_idx_C = bank_C->idx;
  bank_C = fd_banks_clone_from_parent( banks, bank_idx_C );
  FD_TEST( bank_C );  /* C slot = 106 */
  FD_TEST( bank_C->bank_seq==7UL );
  bank_C->f.slot = 106UL;
  bank_C->refcnt = 0UL; /* C(0) */
  fd_banks_mark_bank_frozen( bank_C );

  /* Create M branch from B - this is on the rooted fork. */
  fd_bank_t * bank_M = fd_banks_new_bank( banks, bank_idx_B, 0L, 0 );
  ulong bank_idx_M = bank_M->idx;
  bank_M = fd_banks_clone_from_parent( banks, bank_idx_M );
  FD_TEST( bank_M );  /* M slot = 107 */
  FD_TEST( bank_M->bank_seq==8UL );
  bank_M->f.slot = 107UL;
  bank_M->refcnt = 0UL; /* M(0) */
  fd_banks_mark_bank_frozen( bank_M );

  /* Create R branch from B. */
  fd_bank_t * bank_R = fd_banks_new_bank( banks, bank_idx_B, 0L, 0 );
  ulong bank_idx_R = bank_R->idx;
  bank_R = fd_banks_clone_from_parent( banks, bank_idx_R );
  FD_TEST( bank_R );  /* R slot = 108 */
  FD_TEST( bank_R->bank_seq==9UL );
  bank_R->f.slot = 108UL;
  bank_R->refcnt = 0UL; /* R(0) */
  fd_banks_mark_bank_frozen( bank_R );

  /* Create D branch from M. */
  fd_bank_t * bank_D = fd_banks_new_bank( banks, bank_idx_M, 0L, 0 );
  ulong bank_idx_D = bank_D->idx;
  bank_D = fd_banks_clone_from_parent( banks, bank_idx_D );
  FD_TEST( bank_D );  /* D slot = 109 */
  FD_TEST( bank_D->bank_seq==10UL );
  bank_D->f.slot = 109UL;
  bank_D->refcnt = 2UL; /* D(2) */
  fd_banks_mark_bank_frozen( bank_D );

  /* Create T branch from M - this is on the rooted fork. */
  fd_bank_t * bank_T = fd_banks_new_bank( banks, bank_idx_M, 0L, 0 );
  ulong bank_idx_T = bank_T->idx;
  bank_T = fd_banks_clone_from_parent( banks, bank_idx_T );
  FD_TEST( bank_T );  /* T slot = 110 */
  FD_TEST( bank_T->bank_seq==11UL );
  bank_T->f.slot = 110UL;
  bank_T->refcnt = 0UL; /* T(0) */
  fd_banks_mark_bank_frozen( bank_T );

  /* Create J branch from R. */
  fd_bank_t * bank_J = fd_banks_new_bank( banks, bank_idx_R, 0L, 0 );
  ulong bank_idx_J = bank_J->idx;
  bank_J = fd_banks_clone_from_parent( banks, bank_idx_J );
  FD_TEST( bank_J );  /* J slot = 111 */
  FD_TEST( bank_J->bank_seq==12UL );
  bank_J->f.slot = 111UL;
  bank_J->refcnt = 0UL; /* J(0) */
  fd_banks_mark_bank_frozen( bank_J );

  /* Create L branch from R. */
  fd_bank_t * bank_L = fd_banks_new_bank( banks, bank_idx_R, 0L, 0 );
  ulong bank_idx_L = bank_L->idx;
  bank_L = fd_banks_clone_from_parent( banks, bank_idx_L );
  FD_TEST( bank_L );  /* L slot = 112 */
  FD_TEST( bank_L->bank_seq==13UL );
  bank_L->f.slot = 112UL;
  bank_L->refcnt = 0UL; /* L(0) */
  fd_banks_mark_bank_frozen( bank_L );

  /* Verify all banks exist. */
  FD_TEST( fd_banks_bank_query( banks, bank_idx_P ) == bank_P );
  FD_TEST( fd_banks_bank_query( banks, bank_idx_Q ) == bank_Q );
  FD_TEST( fd_banks_bank_query( banks, bank_idx_A ) == bank_A );
  FD_TEST( fd_banks_bank_query( banks, bank_idx_X ) == bank_X );
  FD_TEST( fd_banks_bank_query( banks, bank_idx_Y ) == bank_Y );
  FD_TEST( fd_banks_bank_query( banks, bank_idx_B ) == bank_B );
  FD_TEST( fd_banks_bank_query( banks, bank_idx_C ) == bank_C );
  FD_TEST( fd_banks_bank_query( banks, bank_idx_M ) == bank_M );
  FD_TEST( fd_banks_bank_query( banks, bank_idx_R ) == bank_R );
  FD_TEST( fd_banks_bank_query( banks, bank_idx_D ) == bank_D );
  FD_TEST( fd_banks_bank_query( banks, bank_idx_T ) == bank_T );
  FD_TEST( fd_banks_bank_query( banks, bank_idx_J ) == bank_J );
  FD_TEST( fd_banks_bank_query( banks, bank_idx_L ) == bank_L );

  /* Verify initial refcnts. */
  FD_TEST( bank_P->refcnt == 0UL );
  FD_TEST( bank_Q->refcnt == 1UL );
  FD_TEST( bank_A->refcnt == 0UL );
  FD_TEST( bank_X->refcnt == 0UL );
  FD_TEST( bank_Y->refcnt == 0UL );
  FD_TEST( bank_B->refcnt == 0UL );
  FD_TEST( bank_C->refcnt == 0UL );
  FD_TEST( bank_M->refcnt == 0UL );
  FD_TEST( bank_R->refcnt == 0UL );
  FD_TEST( bank_D->refcnt == 2UL );
  FD_TEST( bank_T->refcnt == 0UL );
  FD_TEST( bank_J->refcnt == 0UL );
  FD_TEST( bank_L->refcnt == 0UL );

  /* Try to publish with Q having refcnt 1 - should not be able to advance past P. */
  ulong advanceable_bank_idx = ULONG_MAX;
  int result = fd_banks_advance_root_prepare( banks, bank_idx_T, &advanceable_bank_idx ); /* Try to publish up to T */
  FD_TEST( result == 0 ); /* Should not be able to advance past P */

  /* Now decrement Q's refcnt to 0. */
  bank_Q->refcnt--;
  FD_TEST( bank_Q->refcnt == 0UL );

  /* Try to publish again - should now be able to advance to A. */
  result = fd_banks_advance_root_prepare( banks, bank_idx_T, &advanceable_bank_idx );
  FD_TEST( result == 1 );
  FD_TEST( advanceable_bank_idx == bank_idx_A ); /* Should be able to publish up to A */

  fd_banks_advance_root( banks, bank_idx_A );
  fd_bank_t * new_root = fd_banks_root( banks );
  FD_TEST( new_root );
  FD_TEST( new_root == bank_A );
  FD_TEST( new_root->idx == bank_idx_A );

  result = fd_banks_advance_root_prepare( banks, bank_idx_T, &advanceable_bank_idx );
  FD_TEST( result == 1 );
  FD_TEST( advanceable_bank_idx == bank_idx_B ); /* Should be able to publish up to B */

  fd_banks_advance_root( banks, bank_idx_B );
  new_root = fd_banks_root( banks );
  FD_TEST( new_root );
  FD_TEST( new_root == bank_B );
  FD_TEST( new_root->idx == bank_idx_B );

  result = fd_banks_advance_root_prepare( banks, bank_idx_T, &advanceable_bank_idx );
  FD_TEST( result == 1 );
  FD_TEST( advanceable_bank_idx == bank_idx_M ); /* Should be able to publish up to M */

  /* Actually publish up to M. */
  fd_banks_advance_root( banks, bank_idx_M );
  new_root = fd_banks_root( banks );
  FD_TEST( new_root );
  FD_TEST( new_root == bank_M );
  FD_TEST( new_root->idx == bank_idx_M );

  /* Verify that banks P, Q, A, X, Y, B, C and their subtrees have been pruned. */
  FD_TEST( !fd_banks_bank_query( banks, bank_idx_P ) ); /* P should be gone */
  FD_TEST( !fd_banks_bank_query( banks, bank_idx_Q ) ); /* Q should be gone */
  FD_TEST( !fd_banks_bank_query( banks, bank_idx_A ) ); /* A should be gone */
  FD_TEST( !fd_banks_bank_query( banks, bank_idx_X ) ); /* X should be gone */
  FD_TEST( !fd_banks_bank_query( banks, bank_idx_Y ) ); /* Y should be gone */
  FD_TEST( !fd_banks_bank_query( banks, bank_idx_B ) ); /* B should be gone */
  FD_TEST( !fd_banks_bank_query( banks, bank_idx_C ) ); /* C should be gone */
  FD_TEST( !fd_banks_bank_query( banks, bank_idx_R ) ); /* R should be gone */
  FD_TEST( !fd_banks_bank_query( banks, bank_idx_J ) ); /* J should be gone */
  FD_TEST( !fd_banks_bank_query( banks, bank_idx_L ) ); /* L should be gone */

  /* Verify that the remaining banks are still there. */
  FD_TEST( fd_banks_bank_query( banks, bank_idx_M ) == bank_M ); /* M should be the new root */
  FD_TEST( fd_banks_bank_query( banks, bank_idx_D ) == bank_D ); /* D should remain */
  FD_TEST( fd_banks_bank_query( banks, bank_idx_T ) == bank_T ); /* T should remain */

  /* Verify that the new structure matches the expected result:
         M(0)
        / ||
     D(2) T(0)
          ||
          .. */

  FD_TEST( fd_banks_root( banks ) == bank_M );
  FD_TEST( fd_banks_root( banks )->idx == bank_idx_M );

  /* Verify refcnts after publishing. */
  FD_TEST( bank_M->refcnt == 0UL );
  FD_TEST( bank_D->refcnt == 2UL ); /* D still has refcnt 2 */
  FD_TEST( bank_T->refcnt == 0UL );

  /* Now decrement D's refcnt and try to publish further. */
  bank_D->refcnt--;
  bank_D->refcnt--;
  FD_TEST( bank_D->refcnt == 0UL );

  /* Should now be able to publish up to T. */
  result = fd_banks_advance_root_prepare( banks, bank_idx_T, &advanceable_bank_idx );
  FD_TEST( result == 1 );
  FD_TEST( advanceable_bank_idx == bank_idx_T ); /* Should be able to publish up to T */

  /* Actually publish up to T. */
  fd_banks_advance_root( banks, bank_idx_T );
  new_root = fd_banks_root( banks );
  FD_TEST( new_root );
  FD_TEST( new_root == bank_T );
  FD_TEST( new_root->idx == bank_idx_T );

  /* Verify that M and D have been pruned. */
  FD_TEST( !fd_banks_bank_query( banks, bank_idx_M ) ); /* M should be gone */
  FD_TEST( !fd_banks_bank_query( banks, bank_idx_D ) ); /* D should be gone */
  FD_TEST( fd_banks_bank_query( banks, bank_idx_T ) == bank_T ); /* T should be the new root */

}

static void
test_bank_dead_eviction( void * mem ) {
  fd_banks_t * banks = fd_banks_join( fd_banks_new( mem, 16UL, 4UL, 2048UL, 2048UL, 0, 8888UL ) );
  fd_bank_t * bank_data_pool = fd_type_pun( (uchar *)banks + banks->pool_offset );

  fd_bank_t * bank_P = fd_banks_init_bank( banks );
  FD_TEST( bank_P ); /* P slot = 100 */
  FD_TEST( bank_P->bank_seq==1UL );
  bank_P->f.slot = 100UL;
  FD_TEST( bank_P->f.slot == 100UL );
  bank_P->refcnt = 0UL; /* P(0) */
  FD_TEST( fd_banks_pool_used( bank_data_pool )==1UL );

  fd_banks_prune_cancel_info_t cancel[ 1 ];

  FD_TEST( !fd_banks_prune_one_bank( banks, cancel ) );
  FD_TEST( fd_banks_pool_used( bank_data_pool )==1UL );

  /* Case: isolated dead bank that gets pruned. */
  fd_bank_t * bank_D = fd_banks_new_bank( banks, bank_P->idx, 0L, 0 );
  FD_TEST( fd_banks_pool_used( bank_data_pool )==2UL );
  bank_D = fd_banks_clone_from_parent( banks, bank_D->idx );
  FD_TEST( bank_D );
  FD_TEST( fd_banks_pool_used( bank_data_pool )==2UL );

  FD_TEST( !fd_banks_prune_one_bank( banks, cancel ) );
  FD_TEST( fd_banks_pool_used( bank_data_pool )==2UL );
  fd_banks_mark_bank_frozen( bank_D );

  ulong marked_cnt = ULONG_MAX;
  fd_banks_mark_bank_dead( banks, bank_D->idx, NULL, &marked_cnt );
  FD_TEST( fd_banks_pool_used( bank_data_pool )==2UL );
  FD_TEST( bank_D->state==FD_BANK_STATE_DEAD );
  FD_TEST( marked_cnt==1UL );

  ulong bank_D_slot = bank_D->f.slot;
  ulong bank_D_seq  = bank_D->bank_seq;
  ulong bank_D_idx  = bank_D->idx;
  FD_TEST( fd_banks_prune_one_bank( banks, cancel )==2 );
  FD_TEST( cancel->slot    ==bank_D_slot );
  FD_TEST( cancel->bank_seq==bank_D_seq  );
  FD_TEST( cancel->bank_idx==bank_D_idx  );
  FD_TEST( fd_banks_pool_used( bank_data_pool )==1UL );

  /* Case: started-replaying dead bank can be pruned without requesting cancellation info. */
  fd_bank_t * bank_N = fd_banks_new_bank( banks, bank_P->idx, 0L, 0 );
  FD_TEST( fd_banks_pool_used( bank_data_pool )==2UL );
  bank_N = fd_banks_clone_from_parent( banks, bank_N->idx );
  FD_TEST( bank_N );
  FD_TEST( fd_banks_pool_used( bank_data_pool )==2UL );
  fd_banks_mark_bank_frozen( bank_N );
  fd_banks_mark_bank_dead( banks, bank_N->idx, NULL, NULL );
  FD_TEST( fd_banks_prune_one_bank( banks, NULL )==2 );
  FD_TEST( fd_banks_pool_used( bank_data_pool )==1UL );

  /* Case: multiple isolated dead banks get pruned at once. */
  fd_bank_t * bank_C = fd_banks_new_bank( banks, bank_P->idx, 0L, 0 );
  FD_TEST( fd_banks_pool_used( bank_data_pool )==2UL );
  bank_C = fd_banks_clone_from_parent( banks, bank_C->idx );
  FD_TEST( bank_C );
  FD_TEST( fd_banks_pool_used( bank_data_pool )==2UL );
  FD_TEST( !fd_banks_prune_one_bank( banks, cancel ) );
  FD_TEST( fd_banks_pool_used( bank_data_pool )==2UL );
  fd_banks_mark_bank_frozen( bank_C );

  fd_bank_t * bank_R = fd_banks_new_bank( banks, bank_P->idx, 0L, 0 );
  FD_TEST( fd_banks_pool_used( bank_data_pool )==3UL );
  bank_R = fd_banks_clone_from_parent( banks, bank_R->idx );
  FD_TEST( bank_R );
  FD_TEST( fd_banks_pool_used( bank_data_pool )==3UL );
  FD_TEST( !fd_banks_prune_one_bank( banks, cancel ) );
  FD_TEST( fd_banks_pool_used( bank_data_pool )==3UL );

  fd_bank_t * bank_Y = fd_banks_new_bank( banks, bank_P->idx, 0L, 0 );
  FD_TEST( fd_banks_pool_used( bank_data_pool )==4UL );
  bank_Y = fd_banks_clone_from_parent( banks, bank_Y->idx );
  FD_TEST( bank_Y );
  FD_TEST( fd_banks_pool_used( bank_data_pool )==4UL );
  FD_TEST( !fd_banks_prune_one_bank( banks, cancel ) );
  FD_TEST( fd_banks_pool_used( bank_data_pool )==4UL );

  fd_bank_t * bank_Z = fd_banks_new_bank( banks, bank_C->idx, 0L, 0 );
  FD_TEST( fd_banks_pool_used( bank_data_pool )==5UL );
  bank_Z = fd_banks_clone_from_parent( banks, bank_Z->idx );
  FD_TEST( bank_Z );
  FD_TEST( fd_banks_pool_used( bank_data_pool )==5UL );
  FD_TEST( !fd_banks_prune_one_bank( banks, cancel ) );
  FD_TEST( fd_banks_pool_used( bank_data_pool )==5UL );

  fd_banks_mark_bank_dead( banks, bank_Y->idx, NULL, NULL );
  fd_banks_mark_bank_dead( banks, bank_Z->idx, NULL, NULL );
  FD_TEST( fd_banks_prune_one_bank( banks, cancel ) );
  FD_TEST( fd_banks_pool_used( bank_data_pool )==4UL );
  FD_TEST( fd_banks_prune_one_bank( banks, cancel ) );
  FD_TEST( fd_banks_pool_used( bank_data_pool )==3UL );

  /* Case: dead banks that are siblings of non pruned banks. Make sure
     that sibling links are updated correctly. */
  fd_bank_t * bank_G = fd_banks_new_bank( banks, bank_C->idx, 0L, 0 );
  FD_TEST( fd_banks_pool_used( bank_data_pool )==4UL );
  bank_G = fd_banks_clone_from_parent( banks, bank_G->idx );
  FD_TEST( bank_G );
  FD_TEST( fd_banks_pool_used( bank_data_pool )==4UL );

  fd_bank_t * bank_W = fd_banks_new_bank( banks, bank_C->idx, 0L, 0 );
  FD_TEST( fd_banks_pool_used( bank_data_pool )==5UL );
  bank_W = fd_banks_clone_from_parent( banks, bank_W->idx );
  FD_TEST( bank_W );

  fd_bank_t * bank_I = fd_banks_new_bank( banks, bank_W->idx, 0L, 0 );
  FD_TEST( fd_banks_pool_used( bank_data_pool )==6UL );

  fd_bank_t * bank_J = fd_banks_new_bank( banks, bank_W->idx, 0L, 0 );
  FD_TEST( fd_banks_pool_used( bank_data_pool )==7UL );

  ulong dead_bank_idxs[3];
  ulong dead_bank_idxs_cnt = ULONG_MAX;
  fd_banks_mark_bank_dead( banks, bank_W->idx, dead_bank_idxs, &dead_bank_idxs_cnt );
  FD_TEST( dead_bank_idxs_cnt==3UL );
  FD_TEST( dead_bank_idxs[0]==bank_W->idx );
  FD_TEST( dead_bank_idxs[1]==bank_I->idx );
  FD_TEST( dead_bank_idxs[2]==bank_J->idx );
  FD_TEST( bank_G->sibling_idx==bank_W->idx );
  FD_TEST( fd_banks_prune_one_bank( banks, cancel ) );
  FD_TEST( fd_banks_pool_used( bank_data_pool )==6UL );
  FD_TEST( fd_banks_prune_one_bank( banks, cancel ) );
  FD_TEST( fd_banks_pool_used( bank_data_pool )==5UL );
  FD_TEST( fd_banks_prune_one_bank( banks, cancel ) );
  FD_TEST( fd_banks_pool_used( bank_data_pool )==4UL );
  FD_TEST( bank_G->sibling_idx==ULONG_MAX );

  bank_W = fd_banks_new_bank( banks, bank_C->idx, 0L, 0 );
  FD_TEST( fd_banks_pool_used( bank_data_pool )==5UL );
  bank_W = fd_banks_clone_from_parent( banks, bank_W->idx );
  FD_TEST( bank_W );

  bank_I = fd_banks_new_bank( banks, bank_C->idx, 0L, 0 );
  FD_TEST( fd_banks_pool_used( bank_data_pool )==6UL );
  bank_I = fd_banks_clone_from_parent( banks, bank_I->idx );
  FD_TEST( bank_I );
  FD_TEST( fd_banks_bank_query( banks, bank_I->idx ) );

  fd_banks_mark_bank_dead( banks, bank_W->idx, NULL, NULL );
  FD_TEST( bank_G->sibling_idx==bank_W->idx );
  FD_TEST( fd_banks_prune_one_bank( banks, cancel ) );
  FD_TEST( fd_banks_pool_used( bank_data_pool )==5UL );
  FD_TEST( bank_G->sibling_idx!=ULONG_MAX );
  FD_TEST( bank_G->sibling_idx==bank_I->idx );
  FD_TEST( fd_banks_bank_query( banks, bank_I->idx ) );

  /* Case: dead banks get pruned when advancing the root.  Make sure
     that double frees don't happen. */
  bank_W = fd_banks_new_bank( banks, bank_P->idx, 0L, 0 );
  FD_TEST( fd_banks_pool_used( bank_data_pool )==6UL );
  bank_W = fd_banks_clone_from_parent( banks, bank_W->idx );
  FD_TEST( bank_W );

  bank_Z = fd_banks_new_bank( banks, bank_W->idx, 0L, 0 );
  FD_TEST( fd_banks_pool_used( bank_data_pool )==7UL );
  fd_banks_mark_bank_dead( banks, bank_Z->idx, NULL, NULL );

  fd_banks_advance_root( banks, bank_C->idx );
  FD_TEST( fd_banks_pool_used( bank_data_pool )==3UL );
  FD_TEST( fd_banks_bank_query( banks, bank_C->idx ) );
  FD_TEST( fd_banks_bank_query( banks, bank_G->idx ) );
  FD_TEST( fd_banks_bank_query( banks, bank_I->idx ) );
  FD_TEST( !fd_banks_bank_query( banks, bank_Z->idx ) );

  FD_TEST( !fd_banks_prune_one_bank( banks, cancel ) );

  /* Case: don't prune dead banks if there is an outstanding reference
     to them. */
  bank_D = fd_banks_new_bank( banks, bank_C->idx, 0L, 0 );
  bank_D = fd_banks_clone_from_parent( banks, bank_D->idx );
  FD_TEST( bank_D );
  FD_TEST( fd_banks_pool_used( bank_data_pool )==4UL );

  bank_W = fd_banks_new_bank( banks, bank_D->idx, 0L, 0 );
  FD_TEST( fd_banks_pool_used( bank_data_pool )==5UL );

  bank_D->refcnt = 1UL;
  fd_banks_mark_bank_dead( banks, bank_D->idx, NULL, NULL );
  FD_TEST( fd_banks_prune_one_bank( banks, cancel ) );  /* W pruned */
  FD_TEST( fd_banks_pool_used( bank_data_pool )==4UL );
  FD_TEST( !fd_banks_prune_one_bank( banks, cancel ) ); /* D blocked by refcnt */

  bank_D->refcnt = 0UL;
  FD_TEST( fd_banks_prune_one_bank( banks, cancel ) );
  FD_TEST( fd_banks_pool_used( bank_data_pool )==3UL );

  /* Case: dead bank is the left-most child of the parent. */
  bank_D = fd_banks_new_bank( banks, bank_C->idx, 0L, 0 );

  fd_banks_advance_root( banks, bank_G->idx );

  bank_W = fd_banks_new_bank( banks, bank_G->idx, 0L, 0 );
  bank_I = fd_banks_new_bank( banks, bank_G->idx, 0L, 0 );
  bank_C = fd_banks_new_bank( banks, bank_G->idx, 0L, 0 );
  FD_TEST( fd_banks_pool_used( bank_data_pool )==4UL );
}


static void
test_bank_evictable( void * mem ) {
  fd_banks_t * banks = fd_banks_join( fd_banks_new( mem, 16UL, 8UL, 2048UL, 2048UL, 0, 8888UL ) );
  banks->evict_rr_idx = 0UL; /* This test verifies a specific RR order. */

  /*     A
        / \
       B   C
      /|\
     D E F
     |\  |
     I J G
     ^  / \
 leader H L(leader)
   */

  fd_bank_t * bank_A = fd_banks_init_bank( banks );
  FD_TEST( bank_A );
  bank_A->f.epoch_schedule = (fd_epoch_schedule_t) {
    .slots_per_epoch             = 32UL,
    .leader_schedule_slot_offset = 32UL,
    .warmup                      = 0,
    .first_normal_epoch          = 0UL,
    .first_normal_slot           = 0UL
  };

  fd_bank_t * bank_B = fd_banks_new_bank( banks, bank_A->idx, 0L, 0 );
  bank_B = fd_banks_clone_from_parent( banks, bank_B->idx );
  FD_TEST( bank_B );
  fd_banks_mark_bank_frozen( bank_B );

  fd_bank_t * bank_C = fd_banks_new_bank( banks, bank_A->idx, 0L, 0 );
  bank_C = fd_banks_clone_from_parent( banks, bank_C->idx );
  FD_TEST( bank_C );

  fd_bank_t * bank_D = fd_banks_new_bank( banks, bank_B->idx, 0L, 0 );
  bank_D = fd_banks_clone_from_parent( banks, bank_D->idx );
  FD_TEST( bank_D );
  fd_banks_mark_bank_frozen( bank_D );

  fd_bank_t * bank_E = fd_banks_new_bank( banks, bank_B->idx, 0L, 0 );
  bank_E = fd_banks_clone_from_parent( banks, bank_E->idx );
  FD_TEST( bank_E );

  fd_bank_t * bank_F = fd_banks_new_bank( banks, bank_B->idx, 0L, 0 );
  bank_F = fd_banks_clone_from_parent( banks, bank_F->idx );
  FD_TEST( bank_F );
  fd_banks_mark_bank_frozen( bank_F );

  fd_bank_t * bank_G = fd_banks_new_bank( banks, bank_F->idx, 0L, 0 );
  bank_G = fd_banks_clone_from_parent( banks, bank_G->idx );
  FD_TEST( bank_G );
  fd_banks_mark_bank_frozen( bank_G );

  fd_bank_t * bank_H = fd_banks_new_bank( banks, bank_G->idx, 0L, 0 );
  bank_H = fd_banks_clone_from_parent( banks, bank_H->idx );
  FD_TEST( bank_H );

  fd_bank_t * bank_L = fd_banks_new_bank( banks, bank_G->idx, 0L, 1 );
  bank_L = fd_banks_clone_from_parent( banks, bank_L->idx );
  FD_TEST( bank_L );
  fd_banks_mark_bank_frozen( bank_L );

  fd_bank_t * bank_I = fd_banks_new_bank( banks, bank_D->idx, 0L, 1 );
  bank_I = fd_banks_clone_from_parent( banks, bank_I->idx );
  FD_TEST( bank_I );
  fd_banks_mark_bank_frozen( bank_I );

  fd_bank_t * bank_J = fd_banks_new_bank( banks, bank_D->idx, 0L, 0 );
  bank_J = fd_banks_clone_from_parent( banks, bank_J->idx );
  FD_TEST( bank_J );
  fd_banks_mark_bank_frozen( bank_J );

  ulong evictable_bank_idx = fd_banks_get_evictable_bank( banks, NULL );
  FD_TEST( evictable_bank_idx==bank_J->idx );
  FD_TEST( banks->prunable_idx==bank_J->idx );

  FD_TEST( bank_J->state==FD_BANK_STATE_PRUNABLE );
  FD_TEST( bank_A->state!=FD_BANK_STATE_PRUNABLE );
  FD_TEST( bank_B->state!=FD_BANK_STATE_PRUNABLE );
  FD_TEST( bank_C->state!=FD_BANK_STATE_PRUNABLE );
  FD_TEST( bank_D->state!=FD_BANK_STATE_PRUNABLE );
  FD_TEST( bank_E->state!=FD_BANK_STATE_PRUNABLE );
  FD_TEST( bank_F->state!=FD_BANK_STATE_PRUNABLE );
  FD_TEST( bank_G->state!=FD_BANK_STATE_PRUNABLE );
  FD_TEST( bank_H->state!=FD_BANK_STATE_PRUNABLE );
  FD_TEST( bank_I->state!=FD_BANK_STATE_PRUNABLE );
  FD_TEST( bank_L->state!=FD_BANK_STATE_PRUNABLE );

  FD_TEST( fd_banks_get_evictable_bank( banks, NULL )==ULONG_MAX );
  FD_TEST( fd_banks_prune_one_bank( banks, NULL ) );
  FD_TEST( banks->prunable_idx==ULONG_MAX );

  evictable_bank_idx = fd_banks_get_evictable_bank( banks, NULL );
  FD_TEST( evictable_bank_idx==bank_H->idx );
  FD_TEST( banks->prunable_idx==bank_H->idx );
  FD_TEST( bank_H->state==FD_BANK_STATE_PRUNABLE );
  FD_TEST( bank_C->state!=FD_BANK_STATE_PRUNABLE );
  FD_TEST( bank_D->state!=FD_BANK_STATE_PRUNABLE );
  FD_TEST( bank_E->state!=FD_BANK_STATE_PRUNABLE );

  FD_TEST( fd_banks_get_evictable_bank( banks, NULL )==ULONG_MAX );
  FD_TEST( fd_banks_prune_one_bank( banks, NULL ) );
  FD_TEST( banks->prunable_idx==ULONG_MAX );

  evictable_bank_idx = fd_banks_get_evictable_bank( banks, NULL );
  FD_TEST( evictable_bank_idx==bank_E->idx );
  FD_TEST( banks->prunable_idx==bank_E->idx );
  FD_TEST( bank_E->state==FD_BANK_STATE_PRUNABLE );

  FD_TEST( fd_banks_get_evictable_bank( banks, NULL )==ULONG_MAX );
  FD_TEST( fd_banks_prune_one_bank( banks, NULL ) );
  FD_TEST( banks->prunable_idx==ULONG_MAX );

  evictable_bank_idx = fd_banks_get_evictable_bank( banks, NULL );
  FD_TEST( evictable_bank_idx==bank_C->idx );
  FD_TEST( banks->prunable_idx==bank_C->idx );
  FD_TEST( bank_C->state==FD_BANK_STATE_PRUNABLE );

  FD_TEST( fd_banks_get_evictable_bank( banks, NULL )==ULONG_MAX );
  FD_TEST( fd_banks_prune_one_bank( banks, NULL ) );
  FD_TEST( banks->prunable_idx==ULONG_MAX );
}

static void
test_bank_evictable_protected( void * mem ) {
  fd_banks_t * banks = fd_banks_join( fd_banks_new( mem, 4UL, 4UL, 8UL, 8UL, 0, 8889UL ) );
  FD_TEST( banks );

  fd_bank_t * root = fd_banks_init_bank( banks );
  FD_TEST( root );
  root->f.epoch_schedule = (fd_epoch_schedule_t) {
    .slots_per_epoch             = 32UL,
    .leader_schedule_slot_offset = 32UL,
    .warmup                      = 0,
    .first_normal_epoch          = 0UL,
    .first_normal_slot           = 0UL
  };

  fd_bank_t * protected = fd_banks_new_bank( banks, root->idx, 0L, 0 );
  protected = fd_banks_clone_from_parent( banks, protected->idx );
  FD_TEST( protected );
  protected->f.slot = 1UL;
  fd_banks_mark_bank_frozen( protected );

  fd_bank_t * sibling = fd_banks_new_bank( banks, root->idx, 0L, 0 );
  ulong sibling_idx = sibling->idx;
  sibling = fd_banks_clone_from_parent( banks, sibling_idx );
  FD_TEST( sibling );
  sibling->f.slot = 2UL;
  fd_banks_mark_bank_frozen( sibling );

  FD_TEST( fd_banks_get_evictable_bank( banks, protected )==sibling_idx );
  FD_TEST( protected->state!=FD_BANK_STATE_PRUNABLE );
  FD_TEST( fd_banks_prune_one_bank( banks, NULL ) );

  FD_TEST( fd_banks_get_evictable_bank( banks, protected )==ULONG_MAX );

  FD_TEST( fd_banks_get_evictable_bank( banks, NULL )==protected->idx );
  FD_TEST( fd_banks_prune_one_bank( banks, NULL ) );
  fd_banks_clear( banks );
}

static void
test_bank_stake_delegations_dynamic_sizing( void * mem ) {
  ulong const max_total_banks       = 16UL;
  ulong const max_fork_width        = 4UL;
  ulong const max_vote_accounts     = 2048UL;
  ulong const max_stake_small       = 32UL;
  ulong const max_stake_large       = 2048UL;
  ulong const stake_footprint_small = fd_stake_delegations_footprint( max_stake_small, max_stake_small, max_total_banks );
  ulong const stake_footprint_large = fd_stake_delegations_footprint( max_stake_large, max_stake_large, max_total_banks );

  fd_banks_t * banks_small = fd_banks_join( fd_banks_new( mem, max_total_banks, max_fork_width, max_stake_small, max_vote_accounts, 0, 9991UL ) );
  FD_TEST( banks_small );

  uchar * root_mem_small      = fd_type_pun( (uchar *)banks_small + banks_small->stake_delegations_offset );
  uchar * epoch_leaders_small = fd_type_pun( (uchar *)banks_small + banks_small->epoch_leaders_offset );
  FD_TEST( root_mem_small );
  FD_TEST( epoch_leaders_small );
  FD_TEST( fd_ulong_is_aligned( (ulong)root_mem_small,     fd_stake_delegations_align() ) );
  ulong const root_to_epoch_small = (ulong)epoch_leaders_small - (ulong)root_mem_small;
  FD_TEST( root_to_epoch_small>=stake_footprint_small );
  FD_TEST( root_to_epoch_small<(stake_footprint_small+FD_EPOCH_LEADERS_ALIGN) );

  /* If frontier memcpy uses the wrong footprint, this region gets
     clobbered because it sits directly after the frontier stake set. */
  uchar epoch_leaders_snapshot[128];
  fd_memcpy( epoch_leaders_snapshot, (uchar *)banks_small + banks_small->epoch_leaders_offset, sizeof(epoch_leaders_snapshot) );

  fd_bank_t * root_bank = fd_banks_init_bank( banks_small );
  FD_TEST( root_bank );

  fd_pubkey_t stake_0 = { .ul[0] = 0x1001UL };
  fd_pubkey_t vote_0  = { .ul[0] = 0x2001UL };
  fd_pubkey_t stake_1 = { .ul[0] = 0x1002UL };
  fd_pubkey_t vote_1  = { .ul[0] = 0x2002UL };

  fd_stake_delegations_t * root_stake_delegations = fd_banks_stake_delegations_root_query( banks_small );
  fd_stake_delegations_root_update( root_stake_delegations, &stake_0, &vote_0, 11UL, 1UL, 2UL, 3UL, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 );

  fd_stake_delegations_t * frontier_stake_delegations = fd_bank_stake_delegations_frontier_query( banks_small, root_bank );
  FD_TEST( fd_stake_delegations_cnt( frontier_stake_delegations )==1UL );
  fd_stake_delegation_t const * stake_delegation = test_bank_frontier_delegation_query( banks_small, frontier_stake_delegations, &stake_0 );
  FD_TEST( stake_delegation );
  FD_TEST( stake_delegation->stake==11UL );
  FD_TEST( !memcmp( epoch_leaders_snapshot, (uchar *)banks_small + banks_small->epoch_leaders_offset, sizeof(epoch_leaders_snapshot) ) );
  fd_bank_stake_delegations_end_frontier_query( banks_small, root_bank );

  /* Frontier overlays root with deltas during query; base root state is unchanged once query ends. */
  FD_TEST( test_bank_frontier_delegation_query( banks_small, root_stake_delegations, &stake_0 ) );

  fd_bank_t * child_bank = fd_banks_new_bank( banks_small, root_bank->idx, 0L, 0 );
  ulong child_bank_idx = child_bank->idx;
  child_bank = fd_banks_clone_from_parent( banks_small, child_bank_idx );
  FD_TEST( child_bank );

  fd_stake_delegations_t * sd = fd_bank_stake_delegations_modify( child_bank );
  fd_stake_delegations_fork_update( sd, child_bank->stake_delegations_fork_id, &stake_0, &vote_0, 33UL, 4UL, 5UL, 6UL, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 );
  fd_stake_delegations_fork_update( sd, child_bank->stake_delegations_fork_id, &stake_1, &vote_1, 22UL, 4UL, 5UL, 6UL, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 );
  frontier_stake_delegations = fd_bank_stake_delegations_frontier_query( banks_small, child_bank );
  FD_TEST( fd_stake_delegations_cnt( frontier_stake_delegations )==2UL );
  stake_delegation = test_bank_frontier_delegation_query( banks_small, frontier_stake_delegations, &stake_0 );
  FD_TEST( stake_delegation );
  FD_TEST( stake_delegation->stake==33UL );
  stake_delegation = test_bank_frontier_delegation_query( banks_small, frontier_stake_delegations, &stake_1 );
  FD_TEST( stake_delegation );
  FD_TEST( stake_delegation->stake==22UL );
  FD_TEST( !memcmp( epoch_leaders_snapshot, (uchar *)banks_small + banks_small->epoch_leaders_offset, sizeof(epoch_leaders_snapshot) ) );
  fd_bank_stake_delegations_end_frontier_query( banks_small, child_bank );

  /* Root state should still reflect only rooted delegations pre-publish. */
  stake_delegation = test_bank_frontier_delegation_query( banks_small, root_stake_delegations, &stake_0 );
  FD_TEST( stake_delegation );
  FD_TEST( stake_delegation->stake==11UL );
  FD_TEST( !test_bank_frontier_delegation_query( banks_small, root_stake_delegations, &stake_1 ) );

  fd_banks_mark_bank_frozen( child_bank );
  fd_banks_advance_root( banks_small, child_bank_idx );
  root_stake_delegations = fd_banks_stake_delegations_root_query( banks_small );
  stake_delegation = test_bank_frontier_delegation_query( banks_small, root_stake_delegations, &stake_0 );
  FD_TEST( stake_delegation );
  FD_TEST( stake_delegation->stake==33UL );
  stake_delegation = test_bank_frontier_delegation_query( banks_small, root_stake_delegations, &stake_1 );
  FD_TEST( stake_delegation );
  FD_TEST( stake_delegation->stake==22UL );

  fd_banks_t * banks_large = fd_banks_join( fd_banks_new( mem, max_total_banks, max_fork_width, max_stake_large, max_vote_accounts, 0, 9992UL ) );
  FD_TEST( banks_large );

  uchar * root_mem_large      = fd_type_pun( (uchar *)banks_large + banks_large->stake_delegations_offset );
  uchar * epoch_leaders_large = fd_type_pun( (uchar *)banks_large + banks_large->epoch_leaders_offset );
  FD_TEST( root_mem_large );
  FD_TEST( epoch_leaders_large );
  FD_TEST( fd_ulong_is_aligned( (ulong)root_mem_large,     fd_stake_delegations_align() ) );
  ulong const root_to_epoch_large = (ulong)epoch_leaders_large - (ulong)root_mem_large;
  FD_TEST( root_to_epoch_large>=stake_footprint_large );
  FD_TEST( root_to_epoch_large<(stake_footprint_large+FD_EPOCH_LEADERS_ALIGN) );
  FD_TEST( stake_footprint_large > stake_footprint_small );
  FD_TEST( root_to_epoch_large > root_to_epoch_small );
}

static void
test_bank_new_votes_lifecycle( void * mem ) {
  fd_banks_t * banks = fd_banks_join( fd_banks_new( mem, 16UL, 4UL, 2048UL, 2048UL, 0, 6666UL ) );
  FD_TEST( banks );

  fd_bank_t * root = fd_banks_init_bank( banks );
  FD_TEST( root );
  FD_TEST( root->new_votes_fork_id==USHORT_MAX );

  fd_new_votes_t * new_votes = fd_bank_new_votes( root );
  FD_TEST( new_votes );
  FD_TEST( fd_new_votes_cnt( new_votes )==0UL );

  fd_bank_t * keep_child = fd_banks_new_bank( banks, root->idx, 0L, 0 );
  ulong keep_child_idx = keep_child->idx;
  keep_child = fd_banks_clone_from_parent( banks, keep_child_idx );
  FD_TEST( keep_child );
  FD_TEST( fd_bank_new_votes( keep_child )==new_votes );
  FD_TEST( keep_child->new_votes_fork_id!=USHORT_MAX );

  fd_bank_t * drop_child = fd_banks_new_bank( banks, root->idx, 0L, 0 );
  ulong drop_child_idx = drop_child->idx;
  drop_child = fd_banks_clone_from_parent( banks, drop_child_idx );
  FD_TEST( drop_child );
  FD_TEST( drop_child->new_votes_fork_id!=USHORT_MAX );
  FD_TEST( keep_child->new_votes_fork_id!=drop_child->new_votes_fork_id );

  fd_pubkey_t keep_vote = { .ul[0] = 0xAAUL };
  fd_pubkey_t drop_vote = { .ul[0] = 0xBBUL };
  fd_new_votes_insert( new_votes, keep_child->new_votes_fork_id, &keep_vote );
  fd_new_votes_insert( new_votes, drop_child->new_votes_fork_id, &drop_vote );
  FD_TEST( fd_new_votes_cnt( new_votes )==2UL );

  fd_banks_mark_bank_frozen( keep_child );
  fd_banks_mark_bank_frozen( drop_child );
  fd_banks_advance_root( banks, keep_child_idx );

  FD_TEST( banks->root_idx==keep_child_idx );
  FD_TEST( keep_child->new_votes_fork_id==USHORT_MAX );
  FD_TEST( !fd_banks_bank_query( banks, drop_child_idx ) );
  FD_TEST( fd_new_votes_cnt( new_votes )==1UL );

  fd_banks_clear( banks );
  FD_TEST( fd_new_votes_cnt( new_votes )==0UL );
}

static void
test_bank_new_votes_fork_indices( void * mem ) {
  fd_banks_t * banks = fd_banks_join( fd_banks_new( mem, 16UL, 4UL, 2048UL, 2048UL, 0, 5555UL ) );
  FD_TEST( banks );

  /* Root bank (no fork id). */
  fd_bank_t * root = fd_banks_init_bank( banks );
  FD_TEST( root );

  ushort out[16];
  ulong cnt = fd_banks_new_votes_fork_indices( root, out );
  FD_TEST( cnt==0UL );

  /* A -> B -> C chain, each cloned from parent. */
  fd_bank_t * A = fd_banks_new_bank( banks, root->idx, 0L, 0 );
  ulong A_idx = A->idx;
  A = fd_banks_clone_from_parent( banks, A_idx );
  FD_TEST( A->new_votes_fork_id!=USHORT_MAX );
  fd_banks_mark_bank_frozen( A );

  fd_bank_t * B = fd_banks_new_bank( banks, A_idx, 0L, 0 );
  ulong B_idx = B->idx;
  B = fd_banks_clone_from_parent( banks, B_idx );
  FD_TEST( B->new_votes_fork_id!=USHORT_MAX );
  fd_banks_mark_bank_frozen( B );

  fd_bank_t * C = fd_banks_new_bank( banks, B_idx, 0L, 0 );
  ulong C_idx = C->idx;
  C = fd_banks_clone_from_parent( banks, C_idx );
  FD_TEST( C->new_votes_fork_id!=USHORT_MAX );

  cnt = fd_banks_new_votes_fork_indices( C, out );
  FD_TEST( cnt==3UL );
  FD_TEST( out[0]==C->new_votes_fork_id );
  FD_TEST( out[1]==B->new_votes_fork_id );
  FD_TEST( out[2]==A->new_votes_fork_id );

  cnt = fd_banks_new_votes_fork_indices( B, out );
  FD_TEST( cnt==2UL );
  FD_TEST( out[0]==B->new_votes_fork_id );
  FD_TEST( out[1]==A->new_votes_fork_id );

  cnt = fd_banks_new_votes_fork_indices( A, out );
  FD_TEST( cnt==1UL );
  FD_TEST( out[0]==A->new_votes_fork_id );

  (void)C_idx;
  fd_banks_clear( banks );
}

static void
test_bank_advance_root_preserves_inherited_stake_rewards( void * mem ) {
  fd_banks_t * banks = fd_banks_join( fd_banks_new( mem, 16UL, 4UL, 2048UL, 2048UL, 0, 6666UL ) );
  FD_TEST( banks );

  fd_bank_t * bank_A = fd_banks_init_bank( banks );
  FD_TEST( bank_A );
  bank_A->f.epoch_schedule = (fd_epoch_schedule_t) {
    .slots_per_epoch             = 32UL,
    .leader_schedule_slot_offset = 32UL,
    .warmup                      = 0,
    .first_normal_epoch          = 0UL,
    .first_normal_slot           = 0UL
  };
  bank_A->f.parent_slot = 0UL;
  bank_A->f.slot        = 32UL;
  bank_A->refcnt        = 0UL;

  ulong const starting_block_height = 12345UL;
  uint  const partition_cnt         = 3U;
  fd_hash_t parent_blockhash = { 0 };

  fd_stake_rewards_t * stake_rewards = fd_bank_stake_rewards_modify( bank_A );
  uchar fork_idx = fd_stake_rewards_init( stake_rewards,
                                          fd_slot_to_epoch( &bank_A->f.epoch_schedule, bank_A->f.slot, NULL ),
                                          &parent_blockhash,
                                          starting_block_height,
                                          partition_cnt );
  bank_A->stake_rewards_fork_id = fork_idx;

  fd_bank_t * bank_B = fd_banks_new_bank( banks, bank_A->idx, 0L, 0 );
  bank_B = fd_banks_clone_from_parent( banks, bank_B->idx );
  FD_TEST( bank_B );
  bank_B->f.slot = 33UL;
  FD_TEST( bank_B->stake_rewards_fork_id==fork_idx );
  fd_banks_mark_bank_frozen( bank_B );

  fd_banks_advance_root( banks, bank_B->idx );

  fd_bank_t * new_root = fd_banks_root( banks );
  FD_TEST( new_root==bank_B );
  FD_TEST( new_root->stake_rewards_fork_id==fork_idx );
  FD_TEST( fd_stake_rewards_starting_block_height( stake_rewards, fork_idx )==starting_block_height );
  FD_TEST( fd_stake_rewards_num_partitions( stake_rewards, fork_idx )==partition_cnt );

  fd_banks_clear( banks );
}

static void
test_bank_advance_root_purges_losing_vote_stakes_fork( void * mem ) {
  fd_banks_t * banks = fd_banks_join( fd_banks_new( mem, 16UL, 4UL, 2048UL, 2048UL, 0, 6667UL ) );
  FD_TEST( banks );

  fd_bank_t * root = fd_banks_init_bank( banks );
  FD_TEST( root );
  root->f.epoch_schedule = (fd_epoch_schedule_t) {
    .slots_per_epoch             = 32UL,
    .leader_schedule_slot_offset = 32UL,
    .warmup                      = 0,
    .first_normal_epoch          = 0UL,
    .first_normal_slot           = 0UL
  };
  root->f.parent_slot = 29UL;
  root->f.slot        = 30UL;

  fd_vote_stakes_t * vote_stakes = fd_bank_vote_stakes( root );
  ushort root_fork_idx = fd_vote_stakes_get_root_idx( vote_stakes );

  fd_bank_t * winner = fd_banks_new_bank( banks, root->idx, 0L, 0 );
  winner = fd_banks_clone_from_parent( banks, winner->idx );
  FD_TEST( winner );
  winner->f.slot = 31UL; /* Does not cross the epoch boundary. */
  FD_TEST( winner->vote_stakes_fork_id==root_fork_idx );
  fd_banks_mark_bank_frozen( winner );

  fd_bank_t * loser = fd_banks_new_bank( banks, root->idx, 0L, 0 );
  ulong loser_idx = loser->idx;
  loser = fd_banks_clone_from_parent( banks, loser_idx );
  FD_TEST( loser );
  loser->f.slot = 32UL; /* Crosses the epoch boundary. */
  ushort loser_fork_idx = fd_vote_stakes_new_child( vote_stakes );
  loser->vote_stakes_fork_id = loser_fork_idx;
  fd_banks_mark_bank_frozen( loser );

  fd_banks_advance_root( banks, winner->idx );

  FD_TEST( !fd_banks_bank_query( banks, loser_idx ) );
  FD_TEST( fd_vote_stakes_new_child( vote_stakes )==loser_fork_idx );

  fd_banks_clear( banks );
}

static void
test_bank_clear( void * mem ) {
  fd_banks_t * banks = fd_banks_join( fd_banks_new( mem, 16UL, 4UL, 2048UL, 2048UL, 0, 7777UL ) );
  FD_TEST( banks );

  fd_bank_t * root = fd_banks_init_bank( banks );
  FD_TEST( root );
  root->f.slot           = 100UL;
  root->f.capitalization = 5000UL;

  fd_bank_t * child_A = fd_banks_new_bank( banks, root->idx, 0L, 0 );
  ulong child_A_idx = child_A->idx;
  child_A = fd_banks_clone_from_parent( banks, child_A_idx );
  child_A->f.slot = 101UL;
  fd_banks_mark_bank_frozen( child_A );

  fd_bank_t * child_B = fd_banks_new_bank( banks, root->idx, 0L, 0 );
  ulong child_B_idx = child_B->idx;
  child_B = fd_banks_clone_from_parent( banks, child_B_idx );
  child_B->f.slot = 102UL;
  fd_banks_mark_bank_frozen( child_B );

  FD_TEST( fd_banks_pool_used_cnt( banks ) == 3UL );

  fd_banks_clear( banks );

  FD_TEST( banks->root_idx == ULONG_MAX );
  FD_TEST( banks->bank_seq == 1UL );
  FD_TEST( fd_banks_pool_used_cnt( banks ) == 0UL );

  fd_bank_t * new_root = fd_banks_init_bank( banks );
  FD_TEST( new_root );
  FD_TEST( new_root->f.slot == 0UL );
  FD_TEST( new_root->f.capitalization == 0UL );
  FD_TEST( new_root->bank_seq == 1UL );
  new_root->f.slot = 200UL;
  FD_TEST( new_root->f.slot == 200UL );

  fd_bank_t * new_child = fd_banks_new_bank( banks, new_root->idx, 0L, 0 );
  ulong new_child_idx = new_child->idx;
  new_child = fd_banks_clone_from_parent( banks, new_child_idx );
  FD_TEST( new_child );
  new_child->f.slot = 201UL;
  FD_TEST( new_child->f.slot == 201UL );
  fd_banks_mark_bank_frozen( new_child );

  fd_banks_advance_root( banks, new_child_idx );
  FD_TEST( banks->root_idx == new_child_idx );

  fd_banks_clear( banks );
  FD_TEST( banks->root_idx == ULONG_MAX );
  FD_TEST( fd_banks_pool_used_cnt( banks ) == 0UL );
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  fd_pubkey_t key_0 = { .ul[0] = 1 };
  fd_pubkey_t key_1 = { .ul[0] = 2 };
  fd_pubkey_t key_2 = { .ul[0] = 3 };
  fd_pubkey_t key_3 = { .ul[0] = 4 };
  fd_pubkey_t key_4 = { .ul[0] = 5 };
  fd_pubkey_t key_5 = { .ul[0] = 6 };
  fd_pubkey_t key_6 = { .ul[0] = 7 };
  fd_pubkey_t key_7 = { .ul[0] = 8 };
  fd_pubkey_t key_8 = { .ul[0] = 9 };
  fd_pubkey_t key_9 = { .ul[0] = 10 };

  ulong const mem_req       = 4UL<<30;
  ulong       wksp_part_max = fd_wksp_part_max_est( mem_req, 1UL<<20 );
  ulong       wksp_data_max = fd_wksp_data_max_est( mem_req, wksp_part_max );
  void *      wksp_mem      = aligned_alloc( FD_SHMEM_NORMAL_PAGE_SZ, mem_req ); FD_TEST( wksp_mem );
  fd_wksp_t * wksp          = fd_wksp_new( wksp_mem, "snapin", 1U, wksp_part_max, wksp_data_max ); FD_TEST( wksp );
  fd_shmem_join_anonymous( "snapin", FD_SHMEM_JOIN_MODE_READ_WRITE, wksp, wksp_mem, FD_SHMEM_NORMAL_PAGE_SZ, mem_req>>FD_SHMEM_NORMAL_LG_PAGE_SZ );

  ulong const fp = fd_banks_footprint( 16UL, 8UL, 2048UL, 2048UL );
  uchar * mem = fd_wksp_alloc_laddr( wksp, fd_banks_align(), fp, 1UL );
  FD_TEST( mem );
# if !FD_HAS_MSAN
  for( ulong i=0UL; i<fp; i+=8 ) FD_STORE( ulong, mem+i, fd_ulong_hash( i ) );
# endif

  mem = fd_banks_new( mem, 16UL, 4UL, 2048UL, 2048UL, 0, 8888UL );
  FD_TEST( mem );

  /* Init banks */

  fd_banks_t * banks = fd_banks_join( mem );
  FD_TEST( banks );

  fd_bank_t * bank = fd_banks_init_bank( banks );
  FD_TEST( bank );
  bank->f.slot = 1UL;
  ulong bank_idx = bank->idx;
  FD_TEST( bank->bank_seq==1UL );

  /* Set some fields */

  bank->f.capitalization = 1000UL;
  FD_TEST( bank->f.capitalization == 1000UL );

  /* Set a delta-based field. Query it from the local delta, then from
     the larger combined frontier state. */

  fd_stake_delegations_t * sd_test = fd_bank_stake_delegations_modify( bank );
  fd_new_votes_t *         nv_test = fd_bank_new_votes( bank );
  bank->stake_delegations_fork_id  = fd_stake_delegations_new_fork( sd_test );
  bank->new_votes_fork_id          = fd_new_votes_new_fork( nv_test );

  fd_stake_delegations_fork_update( sd_test, bank->stake_delegations_fork_id, &key_0, &key_9, 100UL, 100UL, 100UL, 100UL, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 );

  fd_stake_delegations_t * stake_delegations = fd_bank_stake_delegations_frontier_query( banks, bank );
  FD_TEST( fd_stake_delegations_cnt( stake_delegations ) == 1UL );
  fd_stake_delegation_t const * stake_delegation = test_bank_frontier_delegation_query( banks, stake_delegations, &key_0 );
  FD_TEST( stake_delegation );
  FD_TEST( stake_delegation->stake == 100UL );
  FD_TEST( !memcmp( &stake_delegation->vote_account, &key_9, sizeof(fd_pubkey_t) ) );
  FD_TEST( !memcmp( &stake_delegation->stake_account, &key_0, sizeof(fd_pubkey_t) ) );
  FD_TEST( stake_delegation->activation_epoch == 100UL );
  FD_TEST( stake_delegation->deactivation_epoch == 100UL );
  FD_TEST( stake_delegation->credits_observed == 100UL );
  fd_bank_stake_delegations_end_frontier_query( banks, bank );

  /* Create some additional ancestry */

  fd_bank_t * bank2 = fd_banks_new_bank( banks, bank_idx, 0L, 0 );
  ulong bank_idx2 = bank2->idx;
  bank2 = fd_banks_clone_from_parent( banks, bank_idx2 );
  FD_TEST( bank2 );
  bank2->f.slot = 2UL;
  FD_TEST( bank2->bank_seq==2UL );
  FD_TEST( bank2->f.capitalization == 1000UL );
  /* At this point, the first epoch leaders has been allocated from the
     pool that is limited to 2 instances. */
  fd_epoch_leaders_t * epoch_leaders = fd_bank_epoch_leaders_modify( bank2, bank2->f.epoch );
  FD_TEST( epoch_leaders );

  /* Make sure that the contents of the stake delegations is the same
     after a new bank has been created. */

  stake_delegations = fd_bank_stake_delegations_frontier_query( banks, bank );
  FD_TEST( fd_stake_delegations_cnt( stake_delegations ) == 1UL );
  stake_delegation = test_bank_frontier_delegation_query( banks, stake_delegations, &key_0 );
  FD_TEST( stake_delegation );
  FD_TEST( stake_delegation->stake == 100UL );
  fd_bank_stake_delegations_end_frontier_query( banks, bank );

  /* Make updates to delta */

  sd_test = fd_bank_stake_delegations_modify( bank2 );
  fd_stake_delegations_fork_update( sd_test, bank2->stake_delegations_fork_id, &key_0, &key_0, 200UL, 100UL, 100UL, 100UL, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 );
  fd_stake_delegations_fork_update( sd_test, bank2->stake_delegations_fork_id, &key_1, &key_8, 100UL, 100UL, 100UL, 100UL, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 );
  stake_delegations = fd_bank_stake_delegations_frontier_query( banks, bank2 );
  FD_TEST( fd_stake_delegations_cnt( stake_delegations ) == 2UL );
  stake_delegation = test_bank_frontier_delegation_query( banks, stake_delegations, &key_0 );
  FD_TEST( stake_delegation );
  FD_TEST( stake_delegation->stake == 200UL );
  stake_delegation = test_bank_frontier_delegation_query( banks, stake_delegations, &key_1 );
  FD_TEST( stake_delegation );
  FD_TEST( stake_delegation->stake == 100UL );
  fd_bank_stake_delegations_end_frontier_query( banks, bank2 );

  fd_banks_mark_bank_frozen( bank2 );

  fd_bank_t * bank3 = fd_banks_new_bank( banks, bank_idx, 0L, 0 );
  ulong bank_idx3 = bank3->idx;
  bank3 = fd_banks_clone_from_parent( banks, bank_idx3 );
  FD_TEST( bank3 );
  FD_TEST( bank3->bank_seq==3UL );
  FD_TEST( bank3->f.capitalization == 1000UL );
  bank3->f.capitalization = 2000UL;
  FD_TEST( bank3->f.capitalization == 2000UL );

  /* Because bank 3 is on a different fork than bank 2, make sure that
     the updates don't get incorrectly applied. */

  sd_test = fd_bank_stake_delegations_modify( bank3 );
  fd_stake_delegations_fork_update( sd_test, bank3->stake_delegations_fork_id, &key_2, &key_7, 10UL, 100UL, 100UL, 100UL, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 );
  stake_delegations = fd_bank_stake_delegations_frontier_query( banks, bank3 );
  FD_TEST( fd_stake_delegations_cnt( stake_delegations ) == 2UL );
  stake_delegation = test_bank_frontier_delegation_query( banks, stake_delegations, &key_2 );
  FD_TEST( stake_delegation );
  FD_TEST( stake_delegation->stake == 10UL );
  stake_delegation = test_bank_frontier_delegation_query( banks, stake_delegations, &key_0 );
  FD_TEST( stake_delegation->stake == 100UL );
  fd_bank_stake_delegations_end_frontier_query( banks, bank3 );

  /* At this point, the second epoch leaders has been allocated from the
     pool that is limited to 2 instances. */

  fd_epoch_leaders_t * epoch_leaders2 = fd_bank_epoch_leaders_modify( bank3, bank3->f.epoch );
  FD_TEST( epoch_leaders2 );

  fd_banks_mark_bank_frozen( bank3 );

  fd_bank_t * bank4 = fd_banks_new_bank( banks, bank_idx3, 0L, 0 );
  ulong bank_idx4 = bank4->idx;
  bank4 = fd_banks_clone_from_parent( banks, bank_idx4 );
  FD_TEST( bank4 );
  FD_TEST( bank4->bank_seq==4UL );
  FD_TEST( bank4->f.capitalization == 2000UL );

  fd_banks_mark_bank_frozen( bank4 );

  fd_bank_t * bank5 = fd_banks_new_bank( banks, bank_idx4, 0L, 0 );
  ulong bank_idx5 = bank5->idx;
  bank5 = fd_banks_clone_from_parent( banks, bank_idx5 );
  FD_TEST( bank5 );
  FD_TEST( bank5->bank_seq==5UL );
  FD_TEST( bank5->f.capitalization == 2000UL );
  bank5->f.capitalization = 3000UL;
  FD_TEST( bank5->f.capitalization == 3000UL );

  fd_banks_mark_bank_frozen( bank5 );

  fd_bank_t * bank6 = fd_banks_new_bank( banks, bank_idx2, 0L, 0 );
  ulong bank_idx6 = bank6->idx;
  bank6 = fd_banks_clone_from_parent( banks, bank_idx6 );
  FD_TEST( bank6 );
  FD_TEST( bank6->bank_seq==6UL );
  FD_TEST( bank6->f.capitalization == 1000UL );
  bank6->f.capitalization = 2100UL;
  bank6->f.slot = 6UL;
  FD_TEST( bank6->f.capitalization == 2100UL );

  fd_banks_mark_bank_frozen( bank6 );

  fd_bank_t * bank7 = fd_banks_new_bank( banks, bank_idx6, 0L, 0 );
  ulong bank_idx7 = bank7->idx;
  bank7 = fd_banks_clone_from_parent( banks, bank_idx7 );
  FD_TEST( bank7 );
  FD_TEST( bank7->bank_seq==7UL );
  bank7->f.slot = 7UL;
  FD_TEST( bank7->f.capitalization == 2100UL );

  sd_test = fd_bank_stake_delegations_modify( bank7 );
  fd_stake_delegations_fork_update( sd_test, bank7->stake_delegations_fork_id, &key_3, &key_6, 7UL, 100UL, 100UL, 100UL, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 );
  stake_delegations = fd_bank_stake_delegations_frontier_query( banks, bank7 );

  FD_TEST( fd_stake_delegations_cnt( stake_delegations ) == 3UL );
  FD_TEST( test_bank_frontier_delegation_query( banks, stake_delegations, &key_0 ) ); // bank2
  FD_TEST( test_bank_frontier_delegation_query( banks, stake_delegations, &key_1 ) ); // bank2
  FD_TEST( test_bank_frontier_delegation_query( banks, stake_delegations, &key_3 ) ); // bank7
  stake_delegation = test_bank_frontier_delegation_query( banks, stake_delegations, &key_3 );
  FD_TEST( stake_delegation );
  FD_TEST( stake_delegation->stake == 7UL );
  stake_delegation = test_bank_frontier_delegation_query( banks, stake_delegations, &key_1 );
  FD_TEST( stake_delegation );
  FD_TEST( stake_delegation->stake == 100UL );
  fd_bank_stake_delegations_end_frontier_query( banks, bank7 );

  fd_banks_mark_bank_frozen( bank7 );

  /* At this point there are these forks:
     1. 1 -> 2 -> 6 -> 7
     2. 1 -> 3 -> 4
     3. 1 -> 3 -> 5 */

  fd_bank_t * bank8 = fd_banks_new_bank( banks, bank_idx7, 0L, 0 );
  ulong bank_idx8 = bank8->idx;
  bank8 = fd_banks_clone_from_parent( banks, bank_idx8 );
  FD_TEST( bank8 );
  FD_TEST( bank8->bank_seq==8UL );
  FD_TEST( bank8->f.capitalization == 2100UL );

  sd_test = fd_bank_stake_delegations_modify( bank8 );
  fd_stake_delegations_fork_update( sd_test, bank8->stake_delegations_fork_id, &key_4, &key_5, 4UL, 100UL, 100UL, 100UL, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_009 );
  stake_delegations = fd_bank_stake_delegations_frontier_query( banks, bank8 );
  FD_TEST( fd_stake_delegations_cnt( stake_delegations ) == 4UL );
  stake_delegation = test_bank_frontier_delegation_query( banks, stake_delegations, &key_4 );
  FD_TEST( stake_delegation );
  FD_TEST( stake_delegation->stake == 4UL );
  fd_bank_stake_delegations_end_frontier_query( banks, bank8 );

  fd_banks_mark_bank_frozen( bank8 );

  fd_bank_t * bank9 = fd_banks_new_bank( banks, bank_idx7, 0L, 0 );
  ulong bank_idx9 = bank9->idx;
  bank9 = fd_banks_clone_from_parent( banks, bank_idx9 );
  FD_TEST( bank9 );
  FD_TEST( bank9->bank_seq==9UL );
  FD_TEST( bank9->f.capitalization == 2100UL );

  /* Ensure that the child-most bank is able to correctly query the
     total stake delegations even when some ancestors have not
     published any delegations. */

  stake_delegations = fd_bank_stake_delegations_frontier_query( banks, bank9 );
  FD_TEST( fd_stake_delegations_cnt( stake_delegations ) == 3UL );
  stake_delegation = test_bank_frontier_delegation_query( banks, stake_delegations, &key_3 );
  FD_TEST( stake_delegation );
  FD_TEST( stake_delegation->stake == 7UL );
  stake_delegation = test_bank_frontier_delegation_query( banks, stake_delegations, &key_1 );
  FD_TEST( stake_delegation );
  FD_TEST( stake_delegation->stake == 100UL );
  fd_bank_stake_delegations_end_frontier_query( banks, bank9 );

  /* Check that there are 3 free pool elements. */

  fd_banks_mark_bank_frozen( bank9 );

  /* Verify that the bank is published and that it is indeed bank7.
     Also, verify that the stake delegations have been correctly
     applied to the new root. */

  fd_banks_advance_root( banks, bank2->idx );
  fd_bank_t * new_root = fd_banks_root( banks );
  FD_TEST( new_root );
  FD_TEST( new_root->f.slot == 2UL );
  FD_TEST( new_root == bank2 );

  fd_banks_advance_root( banks, bank6->idx );
  new_root = fd_banks_root( banks );
  FD_TEST( new_root );
  FD_TEST( new_root->f.slot == 6UL );
  FD_TEST( new_root == bank6 );

  fd_banks_advance_root( banks, bank7->idx );
  new_root = fd_banks_root( banks );
  FD_TEST( new_root );
  FD_TEST( new_root->f.slot == 7UL );
  FD_TEST( new_root == bank7 );

  /* Verify that direct and competing forks are pruned off */
  FD_TEST( !fd_banks_bank_query( banks, bank_idx6 ) );
  FD_TEST( !fd_banks_bank_query( banks, bank_idx3 ) );

  stake_delegations = fd_bank_stake_delegations_frontier_query( banks, new_root );
  FD_TEST( fd_stake_delegations_cnt( stake_delegations ) == 3UL );
  stake_delegation = test_bank_frontier_delegation_query( banks, stake_delegations, &key_3 );
  FD_TEST( stake_delegation );
  FD_TEST( stake_delegation->stake == 7UL );
  stake_delegation = test_bank_frontier_delegation_query( banks, stake_delegations, &key_1 );
  FD_TEST( stake_delegation );
  FD_TEST( stake_delegation->stake == 100UL );
  fd_bank_stake_delegations_end_frontier_query( banks, new_root );

  stake_delegations = fd_banks_stake_delegations_root_query( banks );
  FD_TEST( fd_stake_delegations_cnt( stake_delegations ) == 3UL );
  stake_delegation = test_bank_frontier_delegation_query( banks, stake_delegations, &key_3 );
  FD_TEST( stake_delegation );
  FD_TEST( stake_delegation->stake == 7UL );
  stake_delegation = test_bank_frontier_delegation_query( banks, stake_delegations, &key_1 );
  FD_TEST( stake_delegation );
  FD_TEST( stake_delegation->stake == 100UL );

  /* Create some new children */

  fd_bank_t * bank10 = fd_banks_new_bank( banks, bank_idx7, 0L, 0 );
  ulong bank_idx10 = bank10->idx;
  bank10 = fd_banks_clone_from_parent( banks, bank_idx10 );
  FD_TEST( bank10 );
  FD_TEST( bank10->bank_seq==10UL );
  FD_TEST( bank10->f.capitalization == 2100UL );

  fd_banks_mark_bank_frozen( bank10 );

  fd_bank_t * bank11 = fd_banks_new_bank( banks, bank_idx9, 0L, 0 );
  ulong bank_idx11 = bank11->idx;
  bank11 = fd_banks_clone_from_parent( banks, bank_idx11 );
  FD_TEST( bank11 );
  FD_TEST( bank11->bank_seq==11UL );
  FD_TEST( bank11->f.capitalization == 2100UL );
  bank11->f.slot = 11UL;

  /* Now there should be 3 forks:
     1. 7 (1234) -> 8
     2. 7 (1234) -> 9 -> 11
     3  7 (1234) -> 10 */

  /* At this point, bank7 is the root and it has 3 children: bank8, bank9, and bank10 */

  /* Verify that children slots are not pruned off */

  FD_TEST( !!fd_banks_bank_query( banks, bank8->idx ) );
  FD_TEST( !!fd_banks_bank_query( banks, bank9->idx ) );
  FD_TEST( !!fd_banks_bank_query( banks, bank10->idx ) );

  /* Verify that the CoW fields are properly set for bank11 */

  /* Clear bank11, we need to make sure that the pool indices are
     cleared and properly released.

     We test the cases where:
     1. Pool was not made dirty and had a non-null parent pool idx.
     2. Pool was not made dirty and had a null parent pool idx.
     3. Pool was made dirty and had a non-null parent pool idx.
     4. Pool was made dirty and had a null parent pool idx. */


  /* Set the cost tracker to some non-zero values. */

  fd_banks_clear_bank( banks, bank11, 2048UL );
  FD_TEST( bank11->f.slot == 0UL );
  FD_TEST( bank11->f.capitalization == 0UL );

  test_bank_advancing( mem );

  test_bank_dead_eviction( mem );

  test_bank_evictable( mem );

  test_bank_evictable_protected( mem );

  test_bank_stake_delegations_dynamic_sizing( mem );

  test_bank_new_votes_lifecycle( mem );

  test_bank_new_votes_fork_indices( mem );

  test_bank_advance_root_preserves_inherited_stake_rewards( mem );

  test_bank_advance_root_purges_losing_vote_stakes_fork( mem );

  test_bank_clear( mem );

  FD_LOG_NOTICE(( "pass" ));

  fd_halt();
  return 0;
}
