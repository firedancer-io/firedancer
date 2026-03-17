#include "fd_bank.h"

#include <stdlib.h> // ARM64: aligned_alloc(3)

static inline uchar *
fd_banks_get_epoch_leaders( fd_banks_data_t * banks_data ) {
  return fd_type_pun( (uchar *)banks_data + banks_data->epoch_leaders_offset );
}

static inline uchar *
fd_banks_get_stake_delegations_root_mem( fd_banks_data_t * banks_data ) {
  return fd_type_pun( (uchar *)banks_data + banks_data->stake_delegations_root_offset );
}

static inline uchar *
fd_banks_get_stake_delegations_frontier_mem( fd_banks_data_t * banks_data ) {
  return fd_type_pun( (uchar *)banks_data + banks_data->stake_delegations_frontier_offset );
}

static inline fd_stake_delegations_delta_t *
fd_banks_get_stake_delegations_delta( fd_banks_data_t * banks_data ) {
  return fd_type_pun( (uchar *)banks_data + banks_data->stake_delegations_delta_offset );
}

static void
test_bank_advancing( void * mem ) {
  fd_banks_locks_t locks[1];
  fd_banks_locks_init( locks );
  fd_banks_t banksl_join[1];
  fd_banks_t * banks = fd_banks_join( banksl_join, fd_banks_new( mem, 16UL, 4UL, 2048UL, 2048UL, 0, 8888UL ), locks );
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
  fd_bank_t bank_P[1];
  FD_TEST( fd_banks_init_bank( bank_P, banks ) ); /* P slot = 100 */
  FD_TEST( bank_P->data->bank_seq==0UL );
  bank_P->data->fields.slot = 100UL;
  bank_P->data->refcnt = 0UL; /* P(0) */
  ulong bank_idx_P = bank_P->data->idx;

  /* Create Q branch from P. */
  fd_bank_t bank_Q[1];
  ulong bank_idx_Q = fd_banks_new_bank( bank_Q, banks, bank_idx_P, 0L )->data->idx;
  FD_TEST( fd_banks_clone_from_parent( bank_Q, banks, bank_idx_Q ) );  /* Q slot = 101 */
  FD_TEST( bank_Q->data->bank_seq==1UL );
  bank_Q->data->fields.slot = 101UL;
  bank_Q->data->refcnt = 1UL; /* Q(1) */
  fd_banks_mark_bank_frozen( bank_Q );
  fd_bank_t bank_query[1];
  FD_TEST( fd_banks_bank_query( bank_query, banks, bank_idx_Q )->data == bank_Q->data );

  /* Create A branch from P - this is on the rooted fork. */
  fd_bank_t bank_A[1];
  ulong bank_idx_A = fd_banks_new_bank( bank_A, banks, bank_idx_P, 0L )->data->idx;
  FD_TEST( fd_banks_clone_from_parent( bank_A, banks, bank_idx_A ) );  /* A slot = 102 */
  FD_TEST( bank_A->data->bank_seq==2UL );
  bank_A->data->fields.slot = 102UL;
  bank_A->data->refcnt = 0UL; /* A(0) */
  fd_banks_mark_bank_frozen( bank_A );

  /* Create X branch from A. */
  fd_bank_t bank_X[1];
  ulong bank_idx_X = fd_banks_new_bank( bank_X, banks, bank_idx_A, 0L )->data->idx;
  FD_TEST( fd_banks_clone_from_parent( bank_X, banks, bank_idx_X ) );  /* X slot = 103 */
  FD_TEST( bank_X->data->bank_seq==3UL );
  bank_X->data->fields.slot = 103UL;
  bank_X->data->refcnt = 0UL; /* X(0) */
  fd_banks_mark_bank_frozen( bank_X );

  /* Create Y branch from X. */
  fd_bank_t bank_Y[1];
  ulong bank_idx_Y = fd_banks_new_bank( bank_Y, banks, bank_idx_X, 0L )->data->idx;
  FD_TEST( fd_banks_clone_from_parent( bank_Y, banks, bank_idx_Y ) );  /* Y slot = 104 */
  FD_TEST( bank_Y->data->bank_seq==4UL );
  bank_Y->data->fields.slot = 104UL;
  bank_Y->data->refcnt = 0UL; /* Y(0) */
  fd_banks_mark_bank_frozen( bank_Y );

  /* Create B branch from A - this is on the rooted fork. */
  fd_bank_t bank_B[1];
  ulong bank_idx_B = fd_banks_new_bank( bank_B, banks, bank_idx_A, 0L )->data->idx;
  FD_TEST( fd_banks_clone_from_parent( bank_B, banks, bank_idx_B ) );  /* B slot = 105 */
  FD_TEST( bank_B->data->bank_seq==5UL );
  bank_B->data->fields.slot = 105UL;
  bank_B->data->refcnt = 0UL; /* B(0) */
  fd_banks_mark_bank_frozen( bank_B );

  /* Create C branch from A. */
  fd_bank_t bank_C[1];
  ulong bank_idx_C = fd_banks_new_bank( bank_C, banks, bank_idx_A, 0L )->data->idx;
  FD_TEST( fd_banks_clone_from_parent( bank_C, banks, bank_idx_C ) );  /* C slot = 106 */
  FD_TEST( bank_C->data->bank_seq==6UL );
  bank_C->data->fields.slot = 106UL;
  bank_C->data->refcnt = 0UL; /* C(0) */
  fd_banks_mark_bank_frozen( bank_C );

  /* Create M branch from B - this is on the rooted fork. */
  fd_bank_t bank_M[1];
  ulong bank_idx_M = fd_banks_new_bank( bank_M, banks, bank_idx_B, 0L )->data->idx;
  FD_TEST( fd_banks_clone_from_parent( bank_M, banks, bank_idx_M ) );  /* M slot = 107 */
  FD_TEST( bank_M->data->bank_seq==7UL );
  bank_M->data->fields.slot = 107UL;
  bank_M->data->refcnt = 0UL; /* M(0) */
  fd_banks_mark_bank_frozen( bank_M );

  /* Create R branch from B. */
  fd_bank_t bank_R[1];
  ulong bank_idx_R = fd_banks_new_bank( bank_R, banks, bank_idx_B, 0L )->data->idx;
  FD_TEST( fd_banks_clone_from_parent( bank_R, banks, bank_idx_R ) );  /* R slot = 108 */
  FD_TEST( bank_R->data->bank_seq==8UL );
  bank_R->data->fields.slot = 108UL;
  bank_R->data->refcnt = 0UL; /* R(0) */
  fd_banks_mark_bank_frozen( bank_R );

  /* Create D branch from M. */
  fd_bank_t bank_D[1];
  ulong bank_idx_D = fd_banks_new_bank( bank_D, banks, bank_idx_M, 0L )->data->idx;
  FD_TEST( fd_banks_clone_from_parent( bank_D, banks, bank_idx_D ) );  /* D slot = 109 */
  FD_TEST( bank_D->data->bank_seq==9UL );
  bank_D->data->fields.slot = 109UL;
  bank_D->data->refcnt = 2UL; /* D(2) */
  fd_banks_mark_bank_frozen( bank_D );

  /* Create T branch from M - this is on the rooted fork. */
  fd_bank_t bank_T[1];
  ulong bank_idx_T = fd_banks_new_bank( bank_T, banks, bank_idx_M, 0L )->data->idx;
  FD_TEST( fd_banks_clone_from_parent( bank_T, banks, bank_idx_T ) );  /* T slot = 110 */
  FD_TEST( bank_T->data->bank_seq==10UL );
  bank_T->data->fields.slot = 110UL;
  bank_T->data->refcnt = 0UL; /* T(0) */
  fd_banks_mark_bank_frozen( bank_T );

  /* Create J branch from R. */
  fd_bank_t bank_J[1];
  ulong bank_idx_J = fd_banks_new_bank( bank_J, banks, bank_idx_R, 0L )->data->idx;
  FD_TEST( fd_banks_clone_from_parent( bank_J, banks, bank_idx_J ) );  /* J slot = 111 */
  FD_TEST( bank_J->data->bank_seq==11UL );
  bank_J->data->fields.slot = 111UL;
  bank_J->data->refcnt = 0UL; /* J(0) */
  fd_banks_mark_bank_frozen( bank_J );

  /* Create L branch from R. */
  fd_bank_t bank_L[1];
  ulong bank_idx_L = fd_banks_new_bank( bank_L, banks, bank_idx_R, 0L )->data->idx;
  FD_TEST( fd_banks_clone_from_parent( bank_L,banks, bank_idx_L ) );  /* L slot = 112 */
  FD_TEST( bank_L->data->bank_seq==12UL );
  bank_L->data->fields.slot = 112UL;
  bank_L->data->refcnt = 0UL; /* L(0) */
  fd_banks_mark_bank_frozen( bank_L );

  /* Verify all banks exist. */
  FD_TEST( fd_banks_bank_query( bank_query, banks, bank_idx_P )->data == bank_P->data );
  FD_TEST( fd_banks_bank_query( bank_query, banks, bank_idx_Q )->data == bank_Q->data );
  FD_TEST( fd_banks_bank_query( bank_query, banks, bank_idx_A )->data == bank_A->data );
  FD_TEST( fd_banks_bank_query( bank_query, banks, bank_idx_X )->data == bank_X->data );
  FD_TEST( fd_banks_bank_query( bank_query, banks, bank_idx_Y )->data == bank_Y->data );
  FD_TEST( fd_banks_bank_query( bank_query, banks, bank_idx_B )->data == bank_B->data );
  FD_TEST( fd_banks_bank_query( bank_query, banks, bank_idx_C )->data == bank_C->data );
  FD_TEST( fd_banks_bank_query( bank_query, banks, bank_idx_M )->data == bank_M->data );
  FD_TEST( fd_banks_bank_query( bank_query, banks, bank_idx_R )->data == bank_R->data );
  FD_TEST( fd_banks_bank_query( bank_query, banks, bank_idx_D )->data == bank_D->data );
  FD_TEST( fd_banks_bank_query( bank_query, banks, bank_idx_T )->data == bank_T->data );
  FD_TEST( fd_banks_bank_query( bank_query, banks, bank_idx_J )->data == bank_J->data );
  FD_TEST( fd_banks_bank_query( bank_query, banks, bank_idx_L )->data == bank_L->data );

  /* Verify initial refcnts. */
  FD_TEST( bank_P->data->refcnt == 0UL );
  FD_TEST( bank_Q->data->refcnt == 1UL );
  FD_TEST( bank_A->data->refcnt == 0UL );
  FD_TEST( bank_X->data->refcnt == 0UL );
  FD_TEST( bank_Y->data->refcnt == 0UL );
  FD_TEST( bank_B->data->refcnt == 0UL );
  FD_TEST( bank_C->data->refcnt == 0UL );
  FD_TEST( bank_M->data->refcnt == 0UL );
  FD_TEST( bank_R->data->refcnt == 0UL );
  FD_TEST( bank_D->data->refcnt == 2UL );
  FD_TEST( bank_T->data->refcnt == 0UL );
  FD_TEST( bank_J->data->refcnt == 0UL );
  FD_TEST( bank_L->data->refcnt == 0UL );

  /* Try to publish with Q having refcnt 1 - should not be able to advance past P. */
  ulong advanceable_bank_idx = ULONG_MAX;
  int result = fd_banks_advance_root_prepare( banks, bank_idx_T, &advanceable_bank_idx ); /* Try to publish up to T */
  FD_TEST( result == 0 ); /* Should not be able to advance past P */

  /* Now decrement Q's refcnt to 0. */
  bank_Q->data->refcnt--;
  FD_TEST( bank_Q->data->refcnt == 0UL );

  /* Try to publish again - should now be able to advance to A. */
  result = fd_banks_advance_root_prepare( banks, bank_idx_T, &advanceable_bank_idx );
  FD_TEST( result == 1 );
  FD_TEST( advanceable_bank_idx == bank_idx_A ); /* Should be able to publish up to A */

  fd_banks_advance_root( banks, bank_idx_A );
  fd_bank_t new_root[1];
  FD_TEST( fd_banks_root( new_root, banks ) );
  FD_TEST( new_root->data == bank_A->data );
  FD_TEST( new_root->data->idx == bank_idx_A );

  result = fd_banks_advance_root_prepare( banks, bank_idx_T, &advanceable_bank_idx );
  FD_TEST( result == 1 );
  FD_TEST( advanceable_bank_idx == bank_idx_B ); /* Should be able to publish up to B */

  fd_banks_advance_root( banks, bank_idx_B );
  FD_TEST( fd_banks_root( new_root, banks ) );
  FD_TEST( new_root->data == bank_B->data );
  FD_TEST( new_root->data->idx == bank_idx_B );

  result = fd_banks_advance_root_prepare( banks, bank_idx_T, &advanceable_bank_idx );
  FD_TEST( result == 1 );
  FD_TEST( advanceable_bank_idx == bank_idx_M ); /* Should be able to publish up to M */

  /* Actually publish up to M. */
  fd_banks_advance_root( banks, bank_idx_M );
  FD_TEST( fd_banks_root( new_root, banks ) );
  FD_TEST( new_root->data == bank_M->data );
  FD_TEST( new_root->data->idx == bank_idx_M );

  /* Verify that banks P, Q, A, X, Y, B, C and their subtrees have been pruned. */
  FD_TEST( !fd_banks_bank_query( bank_query, banks, bank_idx_P ) ); /* P should be gone */
  FD_TEST( !fd_banks_bank_query( bank_query, banks, bank_idx_Q ) ); /* Q should be gone */
  FD_TEST( !fd_banks_bank_query( bank_query, banks, bank_idx_A ) ); /* A should be gone */
  FD_TEST( !fd_banks_bank_query( bank_query, banks, bank_idx_X ) ); /* X should be gone */
  FD_TEST( !fd_banks_bank_query( bank_query, banks, bank_idx_Y ) ); /* Y should be gone */
  FD_TEST( !fd_banks_bank_query( bank_query, banks, bank_idx_B ) ); /* B should be gone */
  FD_TEST( !fd_banks_bank_query( bank_query, banks, bank_idx_C ) ); /* C should be gone */
  FD_TEST( !fd_banks_bank_query( bank_query, banks, bank_idx_R ) ); /* R should be gone */
  FD_TEST( !fd_banks_bank_query( bank_query, banks, bank_idx_J ) ); /* J should be gone */
  FD_TEST( !fd_banks_bank_query( bank_query, banks, bank_idx_L ) ); /* L should be gone */

  /* Verify that the remaining banks are still there. */
  FD_TEST( fd_banks_bank_query( bank_query, banks, bank_idx_M )->data == bank_M->data ); /* M should be the new root */
  FD_TEST( fd_banks_bank_query( bank_query, banks, bank_idx_D )->data == bank_D->data ); /* D should remain */
  FD_TEST( fd_banks_bank_query( bank_query, banks, bank_idx_T )->data == bank_T->data ); /* T should remain */

  /* Verify that the new structure matches the expected result:
         M(0)
        / ||
     D(2) T(0)
          ||
          .. */

  FD_TEST( fd_banks_root( bank_query, banks )->data      == bank_M->data );
  FD_TEST( fd_banks_root( bank_query, banks )->data->idx == bank_idx_M );

  /* Verify refcnts after publishing. */
  FD_TEST( bank_M->data->refcnt == 0UL );
  FD_TEST( bank_D->data->refcnt == 2UL ); /* D still has refcnt 2 */
  FD_TEST( bank_T->data->refcnt == 0UL );

  /* Now decrement D's refcnt and try to publish further. */
  bank_D->data->refcnt--;
  bank_D->data->refcnt--;
  FD_TEST( bank_D->data->refcnt == 0UL );

  /* Should now be able to publish up to T. */
  result = fd_banks_advance_root_prepare( banks, bank_idx_T, &advanceable_bank_idx );
  FD_TEST( result == 1 );
  FD_TEST( advanceable_bank_idx == bank_idx_T ); /* Should be able to publish up to T */

  /* Actually publish up to T. */
  fd_banks_advance_root( banks, bank_idx_T );
  fd_banks_root( new_root, banks );
  FD_TEST( new_root->data == bank_T->data );
  FD_TEST( new_root->data->idx == bank_idx_T );

  /* Verify that M and D have been pruned. */
  FD_TEST( !fd_banks_bank_query( bank_query, banks, bank_idx_M ) ); /* M should be gone */
  FD_TEST( !fd_banks_bank_query( bank_query, banks, bank_idx_D ) ); /* D should be gone */
  FD_TEST( fd_banks_bank_query( bank_query, banks, bank_idx_T )->data == bank_T->data ); /* T should be the new root */

}

static void
test_bank_dead_eviction( void * mem ) {
  fd_banks_locks_t locks[1];
  fd_banks_locks_init( locks );
  fd_banks_t banksl_join[1];
  fd_banks_t * banks = fd_banks_join( banksl_join, fd_banks_new( mem, 16UL, 4UL, 2048UL, 2048UL, 0, 8888UL ), locks );

  fd_bank_t bank_P[1];
  FD_TEST( fd_banks_init_bank( bank_P, banks ) ); /* P slot = 100 */
  FD_TEST( bank_P->data->bank_seq==0UL );
  bank_P->data->fields.slot = 100UL;
  bank_P->data->refcnt = 0UL; /* P(0) */
  FD_TEST( fd_banks_get_used_cnt( banks )==1UL );

  fd_banks_prune_cancel_info_t cancel[ 1 ];

  FD_TEST( !fd_banks_prune_one_dead_bank( banks, cancel ) );
  FD_TEST( fd_banks_get_used_cnt( banks )==1UL );

  /* Case: isolated dead bank that gets pruned. */
  fd_bank_t bank_D[1];
  fd_banks_new_bank( bank_D, banks, bank_P->data->idx, 0L );
  FD_TEST( fd_banks_get_used_cnt( banks )==2UL );
  FD_TEST( fd_banks_clone_from_parent( bank_D, banks, bank_D->data->idx ) );
  FD_TEST( fd_banks_get_used_cnt( banks )==2UL );

  FD_TEST( !fd_banks_prune_one_dead_bank( banks, cancel ) );
  FD_TEST( fd_banks_get_used_cnt( banks )==2UL );
  fd_banks_mark_bank_frozen( bank_D );

  fd_banks_mark_bank_dead( banks, bank_D->data->idx );
  FD_TEST( fd_banks_get_used_cnt( banks )==2UL );
  FD_TEST( bank_D->data->flags&FD_BANK_FLAGS_DEAD );

  FD_TEST( fd_banks_prune_one_dead_bank( banks, cancel ) );
  FD_TEST( fd_banks_get_used_cnt( banks )==1UL );

  /* Case: multiple isolated dead banks get pruned at once. */
  fd_bank_t bank_C[1];
  fd_banks_new_bank( bank_C, banks, bank_P->data->idx, 0L );
  FD_TEST( fd_banks_get_used_cnt( banks )==2UL );
  FD_TEST( fd_banks_clone_from_parent( bank_C, banks, bank_C->data->idx ) );
  FD_TEST( fd_banks_get_used_cnt( banks )==2UL );
  FD_TEST( !fd_banks_prune_one_dead_bank( banks, cancel ) );
  FD_TEST( fd_banks_get_used_cnt( banks )==2UL );
  fd_banks_mark_bank_frozen( bank_C );

  fd_bank_t bank_R[1];
  fd_banks_new_bank( bank_R, banks, bank_P->data->idx, 0L );
  FD_TEST( fd_banks_get_used_cnt( banks )==3UL );
  FD_TEST( fd_banks_clone_from_parent( bank_R, banks, bank_R->data->idx ) );
  FD_TEST( fd_banks_get_used_cnt( banks )==3UL );
  FD_TEST( !fd_banks_prune_one_dead_bank( banks, cancel ) );
  FD_TEST( fd_banks_get_used_cnt( banks )==3UL );

  fd_bank_t bank_Y[1];
  fd_banks_new_bank( bank_Y, banks, bank_P->data->idx, 0L );
  FD_TEST( fd_banks_get_used_cnt( banks )==4UL );
  FD_TEST( fd_banks_clone_from_parent( bank_Y, banks, bank_Y->data->idx ) );
  FD_TEST( fd_banks_get_used_cnt( banks )==4UL );
  FD_TEST( !fd_banks_prune_one_dead_bank( banks, cancel ) );
  FD_TEST( fd_banks_get_used_cnt( banks )==4UL );

  fd_bank_t bank_Z[1];
  fd_banks_new_bank( bank_Z, banks, bank_C->data->idx, 0L );
  FD_TEST( fd_banks_get_used_cnt( banks )==5UL );
  FD_TEST( fd_banks_clone_from_parent( bank_Z, banks, bank_Z->data->idx ) );
  FD_TEST( fd_banks_get_used_cnt( banks )==5UL );
  FD_TEST( !fd_banks_prune_one_dead_bank( banks, cancel ) );
  FD_TEST( fd_banks_get_used_cnt( banks )==5UL );

  fd_banks_mark_bank_dead( banks, bank_Y->data->idx );
  fd_banks_mark_bank_dead( banks, bank_Z->data->idx );
  FD_TEST( fd_banks_prune_one_dead_bank( banks, cancel ) );
  FD_TEST( fd_banks_get_used_cnt( banks )==4UL );
  FD_TEST( fd_banks_prune_one_dead_bank( banks, cancel ) );
  FD_TEST( fd_banks_get_used_cnt( banks )==3UL );

  /* Case: dead banks that are siblings of non pruned banks. Make sure
     that sibling links are updated correctly. */
  fd_bank_t bank_G[1];
  fd_banks_new_bank( bank_G, banks, bank_C->data->idx, 0L );
  FD_TEST( fd_banks_get_used_cnt( banks )==4UL );
  FD_TEST( fd_banks_clone_from_parent( bank_G, banks, bank_G->data->idx ) );
  FD_TEST( fd_banks_get_used_cnt( banks )==4UL );

  fd_bank_t bank_W[1];
  fd_banks_new_bank( bank_W, banks, bank_C->data->idx, 0L );
  FD_TEST( fd_banks_get_used_cnt( banks )==5UL );
  FD_TEST( fd_banks_clone_from_parent( bank_W, banks, bank_W->data->idx ) );

  fd_bank_t bank_I[1];
  fd_banks_new_bank( bank_I, banks, bank_W->data->idx, 0L );
  FD_TEST( fd_banks_get_used_cnt( banks )==6UL );

  fd_banks_mark_bank_dead( banks, bank_W->data->idx );
  FD_TEST( bank_G->data->sibling_idx==bank_W->data->idx );
  FD_TEST( fd_banks_prune_one_dead_bank( banks, cancel ) );
  FD_TEST( fd_banks_get_used_cnt( banks )==5UL );
  FD_TEST( fd_banks_prune_one_dead_bank( banks, cancel ) );
  FD_TEST( fd_banks_get_used_cnt( banks )==4UL );
  FD_TEST( bank_G->data->sibling_idx==ULONG_MAX );

  fd_banks_new_bank( bank_W, banks, bank_C->data->idx, 0L );
  FD_TEST( fd_banks_get_used_cnt( banks )==5UL );
  FD_TEST( fd_banks_clone_from_parent( bank_W, banks, bank_W->data->idx ) );

  fd_banks_new_bank( bank_I, banks, bank_C->data->idx, 0L );
  FD_TEST( fd_banks_get_used_cnt( banks )==6UL );
  FD_TEST( fd_banks_clone_from_parent( bank_I, banks, bank_I->data->idx ) );
  fd_bank_t bank_query[1];
  FD_TEST( fd_banks_bank_query( bank_query, banks, bank_I->data->idx ) );

  fd_banks_mark_bank_dead( banks, bank_W->data->idx );
  FD_TEST( bank_G->data->sibling_idx==bank_W->data->idx );
  FD_TEST( fd_banks_prune_one_dead_bank( banks, cancel ) );
  FD_TEST( fd_banks_get_used_cnt( banks )==5UL );
  FD_TEST( bank_G->data->sibling_idx!=ULONG_MAX );
  FD_TEST( bank_G->data->sibling_idx==bank_I->data->idx );
  FD_TEST( fd_banks_bank_query( bank_query, banks, bank_I->data->idx ) );

  /* Case: dead banks get pruned when advancing the root.  Make sure
     that double frees don't happen. */
  fd_banks_new_bank( bank_W, banks, bank_P->data->idx, 0L );
  FD_TEST( fd_banks_get_used_cnt( banks )==6UL );
  FD_TEST( fd_banks_clone_from_parent( bank_W, banks, bank_W->data->idx ) );

  fd_banks_new_bank( bank_Z, banks, bank_W->data->idx, 0L );
  FD_TEST( fd_banks_get_used_cnt( banks )==7UL );
  fd_banks_mark_bank_dead( banks, bank_Z->data->idx );

  fd_banks_advance_root( banks, bank_C->data->idx );
  FD_TEST( fd_banks_get_used_cnt( banks )==3UL );
  FD_TEST( fd_banks_bank_query( bank_query, banks, bank_C->data->idx ) );
  FD_TEST( fd_banks_bank_query( bank_query, banks, bank_G->data->idx ) );
  FD_TEST( fd_banks_bank_query( bank_query, banks, bank_I->data->idx ) );
  FD_TEST( !fd_banks_bank_query( bank_query, banks, bank_Z->data->idx ) );

  FD_TEST( !fd_banks_prune_one_dead_bank( banks, cancel ) );

  /* Case: don't prune dead banks if there is an outstanding reference
     to them. */
  fd_banks_new_bank( bank_D, banks, bank_C->data->idx, 0L );
  FD_TEST( fd_banks_clone_from_parent( bank_D, banks, bank_D->data->idx ) );
  FD_TEST( fd_banks_get_used_cnt( banks )==4UL );

  fd_banks_new_bank( bank_W, banks, bank_D->data->idx, 0L );
  FD_TEST( fd_banks_get_used_cnt( banks )==5UL );

  bank_D->data->refcnt = 1UL;
  fd_banks_mark_bank_dead( banks, bank_D->data->idx );
  FD_TEST( fd_banks_prune_one_dead_bank( banks, cancel ) );  /* W pruned */
  FD_TEST( fd_banks_get_used_cnt( banks )==4UL );
  FD_TEST( !fd_banks_prune_one_dead_bank( banks, cancel ) ); /* D blocked by refcnt */

  bank_D->data->refcnt = 0UL;
  FD_TEST( fd_banks_prune_one_dead_bank( banks, cancel ) );
  FD_TEST( fd_banks_get_used_cnt( banks )==3UL );

  /* Case: dead bank is the left-most child of the parent. */
  fd_banks_new_bank( bank_D, banks, bank_C->data->idx, 0L );

  fd_banks_advance_root( banks, bank_G->data->idx );

  fd_banks_new_bank( bank_W, banks, bank_G->data->idx, 0L );
  fd_banks_new_bank( bank_I, banks, bank_G->data->idx, 0L );
  fd_banks_new_bank( bank_C, banks, bank_G->data->idx, 0L );
  FD_TEST( fd_banks_get_used_cnt( banks )==4UL );
}


static void
test_bank_frontier( void * mem ) {
  fd_banks_locks_t locks[1];
  fd_banks_locks_init( locks );
  fd_banks_t banksl_join[1];
  fd_banks_t * banks = fd_banks_join( banksl_join, fd_banks_new( mem, 16UL, 8UL, 2048UL, 2048UL, 0, 8888UL ), locks );

  /*     A
        / \
       B   C
      /|\
     D E F
     |\  |
     I J G
         |
         H */

  fd_bank_t bank_A[1];
  FD_TEST( fd_banks_init_bank( bank_A, banks ) );

  fd_bank_t bank_B[1];
  fd_banks_new_bank( bank_B, banks, bank_A->data->idx, 0L );
  FD_TEST( fd_banks_clone_from_parent( bank_B, banks, bank_B->data->idx ) );
  fd_banks_mark_bank_frozen( bank_B );

  fd_bank_t bank_C[1];
  fd_banks_new_bank( bank_C, banks, bank_A->data->idx, 0L );
  FD_TEST( fd_banks_clone_from_parent( bank_C, banks, bank_C->data->idx ) );

  fd_bank_t bank_D[1];
  fd_banks_new_bank( bank_D, banks, bank_B->data->idx, 0L );
  FD_TEST( fd_banks_clone_from_parent( bank_D, banks, bank_D->data->idx ) );
  fd_banks_mark_bank_frozen( bank_D );

  fd_bank_t bank_E[1];
  fd_banks_new_bank( bank_E, banks, bank_B->data->idx, 0L );
  FD_TEST( fd_banks_clone_from_parent( bank_E, banks, bank_E->data->idx ) );

  fd_bank_t bank_F[1];
  fd_banks_new_bank( bank_F, banks, bank_B->data->idx, 0L );
  FD_TEST( fd_banks_clone_from_parent( bank_F, banks, bank_F->data->idx ) );
  fd_banks_mark_bank_frozen( bank_F );

  fd_bank_t bank_G[1];
  fd_banks_new_bank( bank_G, banks, bank_F->data->idx, 0L );
  FD_TEST( fd_banks_clone_from_parent( bank_G, banks, bank_G->data->idx ) );
  fd_banks_mark_bank_frozen( bank_G );

  fd_bank_t bank_H[1];
  fd_banks_new_bank( bank_H, banks, bank_G->data->idx, 0L );
  FD_TEST( fd_banks_clone_from_parent( bank_H, banks, bank_H->data->idx ) );

  fd_bank_t bank_I[1];
  fd_banks_new_bank( bank_I, banks, bank_D->data->idx, 0L );
  FD_TEST( fd_banks_clone_from_parent( bank_I, banks, bank_I->data->idx ) );

  fd_bank_t bank_J[1];
  fd_banks_new_bank( bank_J, banks, bank_D->data->idx, 0L );
  FD_TEST( fd_banks_clone_from_parent( bank_J, banks, bank_J->data->idx ) );

  ulong frontier_indices[32];
  ulong frontier_cnt = 0UL;

  fd_banks_get_frontier( banks, frontier_indices, &frontier_cnt );
  FD_TEST( frontier_cnt==5UL );

  fd_banks_mark_bank_dead( banks, bank_I->data->idx );

  fd_banks_get_frontier( banks, frontier_indices, &frontier_cnt );
  FD_TEST( frontier_cnt==4UL );

  fd_banks_mark_bank_frozen( bank_J );

  fd_banks_get_frontier( banks, frontier_indices, &frontier_cnt );
  FD_TEST( frontier_cnt==3UL );
}

static void
test_bank_stake_delegations_dynamic_sizing( void * mem ) {
  ulong const max_total_banks       = 16UL;
  ulong const max_fork_width        = 4UL;
  ulong const max_vote_accounts     = 2048UL;
  ulong const max_stake_small       = 32UL;
  ulong const max_stake_large       = 2048UL;
  ulong const stake_footprint_small = fd_stake_delegations_footprint( max_stake_small );
  ulong const stake_footprint_large = fd_stake_delegations_footprint( max_stake_large );

  fd_banks_locks_t locks_small[1];
  fd_banks_locks_init( locks_small );
  fd_banks_t banks_small_ljoin[1];
  fd_banks_t * banks_small = fd_banks_join(
      banks_small_ljoin,
      fd_banks_new( mem, max_total_banks, max_fork_width, max_stake_small, max_vote_accounts, 0, 9991UL ),
      locks_small );
  FD_TEST( banks_small );

  uchar * root_mem_small     = fd_banks_get_stake_delegations_root_mem( banks_small->data );
  uchar * frontier_mem_small = fd_banks_get_stake_delegations_frontier_mem( banks_small->data );
  FD_TEST( root_mem_small );
  FD_TEST( frontier_mem_small );
  FD_TEST( root_mem_small!=frontier_mem_small );
  FD_TEST( fd_ulong_is_aligned( (ulong)root_mem_small,     fd_stake_delegations_align() ) );
  FD_TEST( fd_ulong_is_aligned( (ulong)frontier_mem_small, fd_stake_delegations_align() ) );
  FD_TEST( ((ulong)frontier_mem_small - (ulong)root_mem_small)==stake_footprint_small );

  /* If frontier memcpy uses the wrong footprint, this region gets
     clobbered because it sits directly after the frontier stake set. */
  uchar epoch_leaders_snapshot[128];
  fd_memcpy( epoch_leaders_snapshot, fd_banks_get_epoch_leaders( banks_small->data ), sizeof(epoch_leaders_snapshot) );

  fd_bank_t root_bank[1];
  FD_TEST( fd_banks_init_bank( root_bank, banks_small ) );

  fd_pubkey_t stake_0 = { .ul[0] = 0x1001UL };
  fd_pubkey_t vote_0  = { .ul[0] = 0x2001UL };
  fd_pubkey_t stake_1 = { .ul[0] = 0x1002UL };
  fd_pubkey_t vote_1  = { .ul[0] = 0x2002UL };

  fd_stake_delegations_t * root_stake_delegations = fd_banks_stake_delegations_root_query( banks_small );
  fd_stake_delegations_update( root_stake_delegations, &stake_0, &vote_0, 11UL, 1UL, 2UL, 3UL, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_009 );

  fd_stake_delegations_t * frontier_stake_delegations = fd_bank_stake_delegations_frontier_query( banks_small, root_bank );
  FD_TEST( fd_stake_delegations_cnt( frontier_stake_delegations )==1UL );
  fd_stake_delegation_t const * stake_delegation = fd_stake_delegations_query( frontier_stake_delegations, &stake_0 );
  FD_TEST( stake_delegation );
  FD_TEST( stake_delegation->stake==11UL );
  FD_TEST( !memcmp( epoch_leaders_snapshot, fd_banks_get_epoch_leaders( banks_small->data ), sizeof(epoch_leaders_snapshot) ) );

  /* Root and frontier are distinct buffers. */
  fd_stake_delegations_remove( frontier_stake_delegations, &stake_0 );
  FD_TEST( !fd_stake_delegations_query( frontier_stake_delegations, &stake_0 ) );
  FD_TEST( fd_stake_delegations_query( root_stake_delegations, &stake_0 ) );

  fd_bank_t child_bank[1];
  ulong child_bank_idx = fd_banks_new_bank( child_bank, banks_small, root_bank->data->idx, 0L )->data->idx;
  FD_TEST( fd_banks_clone_from_parent( child_bank, banks_small, child_bank_idx ) );

  fd_stake_delegations_delta_t * delta = fd_bank_stake_delegations_delta_locking_modify( child_bank );
  fd_stake_delegations_delta_update( delta, child_bank->data->stake_delegations_fork_id, &stake_0, &vote_0, 33UL, 4UL, 5UL, 6UL, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_009 );
  fd_stake_delegations_delta_update( delta, child_bank->data->stake_delegations_fork_id, &stake_1, &vote_1, 22UL, 4UL, 5UL, 6UL, FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_009 );
  fd_bank_stake_delegations_delta_end_locking_modify( child_bank );

  frontier_stake_delegations = fd_bank_stake_delegations_frontier_query( banks_small, child_bank );
  FD_TEST( fd_stake_delegations_cnt( frontier_stake_delegations )==2UL );
  stake_delegation = fd_stake_delegations_query( frontier_stake_delegations, &stake_0 );
  FD_TEST( stake_delegation );
  FD_TEST( stake_delegation->stake==33UL );
  stake_delegation = fd_stake_delegations_query( frontier_stake_delegations, &stake_1 );
  FD_TEST( stake_delegation );
  FD_TEST( stake_delegation->stake==22UL );
  FD_TEST( !memcmp( epoch_leaders_snapshot, fd_banks_get_epoch_leaders( banks_small->data ), sizeof(epoch_leaders_snapshot) ) );

  /* Frontier is rebuilt from root + deltas each query. */
  fd_stake_delegations_remove( frontier_stake_delegations, &stake_1 );
  FD_TEST( !fd_stake_delegations_query( frontier_stake_delegations, &stake_1 ) );
  frontier_stake_delegations = fd_bank_stake_delegations_frontier_query( banks_small, child_bank );
  FD_TEST( fd_stake_delegations_query( frontier_stake_delegations, &stake_1 ) );

  stake_delegation = fd_stake_delegations_query( root_stake_delegations, &stake_0 );
  FD_TEST( stake_delegation );
  FD_TEST( stake_delegation->stake==11UL );
  FD_TEST( !fd_stake_delegations_query( root_stake_delegations, &stake_1 ) );

  fd_banks_mark_bank_frozen( child_bank );
  fd_banks_advance_root( banks_small, child_bank_idx );
  root_stake_delegations = fd_banks_stake_delegations_root_query( banks_small );
  stake_delegation = fd_stake_delegations_query( root_stake_delegations, &stake_0 );
  FD_TEST( stake_delegation );
  FD_TEST( stake_delegation->stake==33UL );
  stake_delegation = fd_stake_delegations_query( root_stake_delegations, &stake_1 );
  FD_TEST( stake_delegation );
  FD_TEST( stake_delegation->stake==22UL );

  fd_banks_locks_t locks_large[1];
  fd_banks_locks_init( locks_large );
  fd_banks_t banks_large_ljoin[1];
  fd_banks_t * banks_large = fd_banks_join(
      banks_large_ljoin,
      fd_banks_new( mem, max_total_banks, max_fork_width, max_stake_large, max_vote_accounts, 0, 9992UL ),
      locks_large );
  FD_TEST( banks_large );

  uchar * root_mem_large     = fd_banks_get_stake_delegations_root_mem( banks_large->data );
  uchar * frontier_mem_large = fd_banks_get_stake_delegations_frontier_mem( banks_large->data );
  FD_TEST( root_mem_large );
  FD_TEST( frontier_mem_large );
  FD_TEST( root_mem_large!=frontier_mem_large );
  FD_TEST( fd_ulong_is_aligned( (ulong)root_mem_large,     fd_stake_delegations_align() ) );
  FD_TEST( fd_ulong_is_aligned( (ulong)frontier_mem_large, fd_stake_delegations_align() ) );
  FD_TEST( ((ulong)frontier_mem_large - (ulong)root_mem_large)==stake_footprint_large );
  FD_TEST( stake_footprint_large > stake_footprint_small );
}

static void
test_bank_shared_offset_accessors( void * mem ) {
  fd_banks_locks_t locks[1];
  fd_banks_locks_init( locks );
  fd_banks_t banks_ljoin[1];
  fd_banks_t * banks = fd_banks_join( banks_ljoin, fd_banks_new( mem, 16UL, 4UL, 2048UL, 2048UL, 0, 9911UL ), locks );
  FD_TEST( banks );

  fd_banks_data_t * banks_data = banks->data;
  fd_bank_t root_bank[1];
  FD_TEST( fd_banks_init_bank( root_bank, banks ) );
  FD_TEST( fd_type_pun( (uchar *)root_bank->data + root_bank->data->banks_data_offset )==banks_data );

  fd_vote_stakes_t * expected_vote_stakes = fd_type_pun( (uchar *)banks_data + banks_data->vote_stakes_pool_offset );
  FD_TEST( fd_bank_vote_stakes_locking_modify( root_bank )==expected_vote_stakes );
  fd_bank_vote_stakes_end_locking_modify( root_bank );

  fd_stake_rewards_t * expected_stake_rewards = fd_type_pun( (uchar *)banks_data + banks_data->stake_rewards_offset );
  FD_TEST( fd_bank_stake_rewards_query( root_bank )==expected_stake_rewards );
  FD_TEST( fd_bank_stake_rewards_modify( root_bank )==expected_stake_rewards );

  fd_bank_t child_bank[1];
  ulong child_bank_idx = fd_banks_new_bank( child_bank, banks, root_bank->data->idx, 0L )->data->idx;
  FD_TEST( fd_banks_clone_from_parent( child_bank, banks, child_bank_idx ) );
  FD_TEST( fd_type_pun( (uchar *)child_bank->data + child_bank->data->banks_data_offset )==banks_data );

  fd_stake_delegations_delta_t * expected_stake_delegations_delta = fd_type_pun( (uchar *)banks_data + banks_data->stake_delegations_delta_offset );
  FD_TEST( fd_bank_stake_delegations_delta_locking_modify( child_bank )==expected_stake_delegations_delta );
  fd_bank_stake_delegations_delta_end_locking_modify( child_bank );

  child_bank->data->fields.epoch = 5UL;
  fd_epoch_leaders_t * expected_epoch_leaders = fd_type_pun( (uchar *)banks_data + banks_data->epoch_leaders_offset + banks_data->epoch_leaders_footprint );
  FD_TEST( fd_bank_epoch_leaders_modify( child_bank )==expected_epoch_leaders );
  FD_TEST( fd_bank_epoch_leaders_query( child_bank )==expected_epoch_leaders );

  fd_bank_cost_tracker_t * cost_tracker_pool = fd_type_pun( (uchar *)banks_data + banks_data->cost_tracker_pool_offset );
  FD_TEST( child_bank->data->cost_tracker_pool_idx!=fd_bank_cost_tracker_pool_idx_null( cost_tracker_pool ) );
  fd_cost_tracker_t const * expected_cost_tracker = fd_type_pun_const( fd_bank_cost_tracker_pool_ele( cost_tracker_pool, child_bank->data->cost_tracker_pool_idx )->data );
  FD_TEST( fd_bank_cost_tracker_query( child_bank )==expected_cost_tracker );
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

  uchar * mem = fd_wksp_alloc_laddr( wksp, fd_banks_align(), fd_banks_footprint( 16UL, 4UL, 2048UL, 2048UL ), 1UL );
  FD_TEST( mem );
# if !FD_HAS_MSAN
  ulong fp = fd_banks_footprint( 16UL, 4UL, 2048UL, 2048UL );
  for( ulong i=0UL; i<fp; i+=8 ) FD_STORE( ulong, mem+i, fd_ulong_hash( i ) );
# endif

  mem = fd_banks_new( mem, 16UL, 4UL, 2048UL, 2048UL, 0, 8888UL );
  FD_TEST( mem );

  /* Init banks */

  fd_banks_t banksl_join[1];

  fd_banks_locks_t locks[1];
  fd_banks_locks_init( locks );

  fd_banks_t * banks = fd_banks_join( banksl_join, mem, locks );
  FD_TEST( banks );

  fd_bank_t bank[1];
  FD_TEST( fd_banks_init_bank( bank, banks ) );
  bank->data->fields.slot = 1UL;
  ulong bank_idx = bank->data->idx;
  FD_TEST( bank->data->bank_seq==0UL );

  /* Set some fields */

  bank->data->fields.capitalization = 1000UL;

  /* Set a delta-based field. Query it from the local delta, then from
     the larger combined frontier state. */

  fd_stake_delegations_delta_t * stake_delegations_delta = fd_banks_get_stake_delegations_delta( banks->data );
  bank->data->stake_delegations_fork_id = fd_stake_delegations_delta_new_fork( stake_delegations_delta );

  stake_delegations_delta = fd_bank_stake_delegations_delta_locking_modify( bank );
  fd_stake_delegations_delta_update( stake_delegations_delta, bank->data->stake_delegations_fork_id, &key_0, &key_9, 100UL, 100UL, 100UL, 100UL, 0.09 );

  fd_bank_stake_delegations_delta_end_locking_modify( bank );

  fd_stake_delegations_t * stake_delegations = fd_bank_stake_delegations_frontier_query( banks, bank );
  FD_TEST( fd_stake_delegations_cnt( stake_delegations ) == 1UL );
  fd_stake_delegation_t const * stake_delegation = fd_stake_delegations_query( stake_delegations, &key_0 );
  FD_TEST( stake_delegation );
  FD_TEST( stake_delegation->stake == 100UL );
  FD_TEST( !memcmp( &stake_delegation->vote_account, &key_9, sizeof(fd_pubkey_t) ) );
  FD_TEST( !memcmp( &stake_delegation->stake_account, &key_0, sizeof(fd_pubkey_t) ) );
  FD_TEST( stake_delegation->activation_epoch == 100UL );
  FD_TEST( stake_delegation->deactivation_epoch == 100UL );
  FD_TEST( stake_delegation->credits_observed == 100UL );

  /* Create some additional ancestry */

  fd_bank_t bank2[1];
  ulong bank_idx2 = fd_banks_new_bank( bank2, banks, bank_idx, 0L )->data->idx;
  FD_TEST( fd_banks_clone_from_parent( bank2, banks, bank_idx2 ) );
  bank2->data->fields.slot = 2UL;
  FD_TEST( bank2->data->bank_seq==1UL );
  FD_TEST( bank2->data->fields.capitalization == 1000UL );
  /* At this point, the first epoch leaders has been allocated from the
     pool that is limited to 2 instances. */
  fd_epoch_leaders_t * epoch_leaders = fd_bank_epoch_leaders_modify( bank2 );
  FD_TEST( epoch_leaders );

  /* Make sure that the contents of the stake delegations is the same
     after a new bank has been created. */

  stake_delegations = fd_bank_stake_delegations_frontier_query( banks, bank );
  FD_TEST( fd_stake_delegations_cnt( stake_delegations ) == 1UL );
  stake_delegation = fd_stake_delegations_query( stake_delegations, &key_0 );
  FD_TEST( stake_delegation );
  FD_TEST( stake_delegation->stake == 100UL );

  /* Make updates to delta */

  stake_delegations_delta = fd_bank_stake_delegations_delta_locking_modify( bank2 );
  fd_stake_delegations_delta_update( stake_delegations_delta, bank2->data->stake_delegations_fork_id, &key_0, &key_0, 200UL, 100UL, 100UL, 100UL, 0.09 );
  fd_stake_delegations_delta_update( stake_delegations_delta, bank2->data->stake_delegations_fork_id, &key_1, &key_8, 100UL, 100UL, 100UL, 100UL, 0.09 );
  fd_bank_stake_delegations_delta_end_locking_modify( bank2 );

  stake_delegations = fd_bank_stake_delegations_frontier_query( banks, bank2 );
  FD_TEST( fd_stake_delegations_cnt( stake_delegations ) == 2UL );
  stake_delegation = fd_stake_delegations_query( stake_delegations, &key_0 );
  FD_TEST( stake_delegation );
  FD_TEST( stake_delegation->stake == 200UL );
  stake_delegation = fd_stake_delegations_query( stake_delegations, &key_1 );
  FD_TEST( stake_delegation );
  FD_TEST( stake_delegation->stake == 100UL );

  fd_banks_mark_bank_frozen( bank2 );

  fd_bank_t bank3[1];
  ulong bank_idx3 = fd_banks_new_bank( bank3, banks, bank_idx, 0L )->data->idx;
  FD_TEST( fd_banks_clone_from_parent( bank3, banks, bank_idx3 ) );
  FD_TEST( bank3->data->bank_seq==2UL );
  FD_TEST( bank3->data->fields.capitalization == 1000UL );
  bank3->data->fields.capitalization = 2000UL;

  /* Because bank 3 is on a different fork than bank 2, make sure that
     the updates don't get incorrectly applied. */

  stake_delegations_delta = fd_bank_stake_delegations_delta_locking_modify( bank3 );
  fd_stake_delegations_delta_update( stake_delegations_delta, bank3->data->stake_delegations_fork_id, &key_2, &key_7, 10UL, 100UL, 100UL, 100UL, 0.09 );
  fd_bank_stake_delegations_delta_end_locking_modify( bank3 );

  stake_delegations = fd_bank_stake_delegations_frontier_query( banks, bank3 );
  FD_TEST( fd_stake_delegations_cnt( stake_delegations ) == 2UL );
  stake_delegation = fd_stake_delegations_query( stake_delegations, &key_2 );
  FD_TEST( stake_delegation );
  FD_TEST( stake_delegation->stake == 10UL );
  stake_delegation = fd_stake_delegations_query( stake_delegations, &key_0 );
  FD_TEST( stake_delegation->stake == 100UL );

  /* At this point, the second epoch leaders has been allocated from the
     pool that is limited to 2 instances. */

  fd_epoch_leaders_t * epoch_leaders2 = fd_bank_epoch_leaders_modify( bank3 );
  FD_TEST( epoch_leaders2 );

  fd_banks_mark_bank_frozen( bank3 );

  fd_bank_t bank4[1];
  ulong bank_idx4 = fd_banks_new_bank( bank4, banks, bank_idx3, 0L )->data->idx;
  FD_TEST( fd_banks_clone_from_parent( bank4, banks, bank_idx4 ) );
  FD_TEST( bank4->data->bank_seq==3UL );
  FD_TEST( bank4->data->fields.capitalization == 2000UL );

  fd_banks_mark_bank_frozen( bank4 );

  fd_bank_t bank5[1];
  ulong bank_idx5 = fd_banks_new_bank( bank5, banks, bank_idx4, 0L )->data->idx;
  FD_TEST( fd_banks_clone_from_parent( bank5, banks, bank_idx5 ) );
  FD_TEST( bank5->data->bank_seq==4UL );
  FD_TEST( bank5->data->fields.capitalization == 2000UL );
  bank5->data->fields.capitalization = 3000UL;
  FD_TEST( bank5->data->fields.capitalization == 3000UL );

  fd_banks_mark_bank_frozen( bank5 );

  fd_bank_t bank6[1];
  ulong bank_idx6 = fd_banks_new_bank( bank6, banks, bank_idx2, 0L )->data->idx;
  FD_TEST( fd_banks_clone_from_parent( bank6, banks, bank_idx6 ) );
  FD_TEST( bank6->data->bank_seq==5UL );
  FD_TEST( bank6->data->fields.capitalization == 1000UL );
  bank6->data->fields.capitalization = 2100UL;
  bank6->data->fields.slot = 6UL;
  FD_TEST( bank6->data->fields.capitalization == 2100UL );

  fd_banks_mark_bank_frozen( bank6 );

  fd_bank_t bank7[1];
  ulong bank_idx7 = fd_banks_new_bank( bank7, banks, bank_idx6, 0L )->data->idx;
  FD_TEST( fd_banks_clone_from_parent( bank7, banks, bank_idx7 ) );
  FD_TEST( bank7->data->bank_seq==6UL );
  bank7->data->fields.slot = 7UL;
  FD_TEST( bank7->data->fields.capitalization == 2100UL );

  stake_delegations_delta = fd_bank_stake_delegations_delta_locking_modify( bank7 );
  fd_stake_delegations_delta_update( stake_delegations_delta, bank7->data->stake_delegations_fork_id, &key_3, &key_6, 7UL, 100UL, 100UL, 100UL, 0.09 );
  fd_bank_stake_delegations_delta_end_locking_modify( bank7 );

  stake_delegations = fd_bank_stake_delegations_frontier_query( banks, bank7 );

  FD_TEST( fd_stake_delegations_cnt( stake_delegations ) == 3UL );
  FD_TEST( fd_stake_delegations_query( stake_delegations, &key_0 ) ); // bank2
  FD_TEST( fd_stake_delegations_query( stake_delegations, &key_1 ) ); // bank2
  FD_TEST( fd_stake_delegations_query( stake_delegations, &key_3 ) ); // bank7
  stake_delegation = fd_stake_delegations_query( stake_delegations, &key_3 );
  FD_TEST( stake_delegation );
  FD_TEST( stake_delegation->stake == 7UL );
  stake_delegation = fd_stake_delegations_query( stake_delegations, &key_1 );
  FD_TEST( stake_delegation );
  FD_TEST( stake_delegation->stake == 100UL );

  fd_banks_mark_bank_frozen( bank7 );

  /* At this point there are these forks:
     1. 1 -> 2 -> 6 -> 7
     2. 1 -> 3 -> 4
     3. 1 -> 3 -> 5 */

  fd_bank_t bank8[1];
  ulong bank_idx8 = fd_banks_new_bank( bank8, banks, bank_idx7, 0L )->data->idx;
  FD_TEST( fd_banks_clone_from_parent( bank8, banks, bank_idx8 ) );
  FD_TEST( bank8->data->bank_seq==7UL );
  FD_TEST( bank8->data->fields.capitalization == 2100UL );

  stake_delegations_delta = fd_bank_stake_delegations_delta_locking_modify( bank8 );
  fd_stake_delegations_delta_update( stake_delegations_delta, bank8->data->stake_delegations_fork_id, &key_4, &key_5, 4UL, 100UL, 100UL, 100UL, 0.09 );
  fd_bank_stake_delegations_delta_end_locking_modify( bank8 );

  stake_delegations = fd_bank_stake_delegations_frontier_query( banks, bank8 );
  FD_TEST( fd_stake_delegations_cnt( stake_delegations ) == 4UL );
  stake_delegation = fd_stake_delegations_query( stake_delegations, &key_4 );
  FD_TEST( stake_delegation );
  FD_TEST( stake_delegation->stake == 4UL );

  fd_banks_mark_bank_frozen( bank8 );

  fd_bank_t bank9[1];
  ulong bank_idx9 = fd_banks_new_bank( bank9, banks, bank_idx7, 0L )->data->idx;
  FD_TEST( fd_banks_clone_from_parent( bank9, banks, bank_idx9 ) );
  FD_TEST( bank9->data->bank_seq==8UL );
  FD_TEST( bank9->data->fields.capitalization == 2100UL );

  /* Ensure that the child-most bank is able to correctly query the
     total stake delegations even when some ancestors have not
     published any delegations. */

  stake_delegations = fd_bank_stake_delegations_frontier_query( banks, bank9 );
  FD_TEST( fd_stake_delegations_cnt( stake_delegations ) == 3UL );
  stake_delegation = fd_stake_delegations_query( stake_delegations, &key_3 );
  FD_TEST( stake_delegation );
  FD_TEST( stake_delegation->stake == 7UL );
  stake_delegation = fd_stake_delegations_query( stake_delegations, &key_1 );
  FD_TEST( stake_delegation );
  FD_TEST( stake_delegation->stake == 100UL );

  /* Check that there are 3 free pool elements. */

  fd_banks_mark_bank_frozen( bank9 );

  /* Verify that the bank is published and that it is indeed bank7.
     Also, verify that the stake delegations have been correctly
     applied to the new root. */

  fd_banks_advance_root( banks, bank2->data->idx );
  fd_bank_t new_root[1];
  FD_TEST( fd_banks_root( new_root, banks ) );
  FD_TEST( new_root->data->fields.slot == 2UL );
  FD_TEST( new_root->data == bank2->data );

  fd_banks_advance_root( banks, bank6->data->idx );
  FD_TEST( fd_banks_root( new_root, banks ) );
  FD_TEST( new_root->data->fields.slot == 6UL );
  FD_TEST( new_root->data == bank6->data );

  fd_banks_advance_root( banks, bank7->data->idx );
  FD_TEST( fd_banks_root( new_root, banks ) );
  FD_TEST( new_root->data->fields.slot == 7UL );
  FD_TEST( new_root->data == bank7->data );

  /* Verify that direct and competing forks are pruned off */
  fd_bank_t bank_prune[1];
  FD_TEST( !fd_banks_bank_query( bank_prune, banks, bank_idx6 ) );
  FD_TEST( !fd_banks_bank_query( bank_prune, banks, bank_idx3 ) );

  stake_delegations = fd_bank_stake_delegations_frontier_query( banks, (fd_bank_t *)new_root );
  FD_TEST( fd_stake_delegations_cnt( stake_delegations ) == 3UL );
  stake_delegation = fd_stake_delegations_query( stake_delegations, &key_3 );
  FD_TEST( stake_delegation );
  FD_TEST( stake_delegation->stake == 7UL );
  stake_delegation = fd_stake_delegations_query( stake_delegations, &key_1 );
  FD_TEST( stake_delegation );
  FD_TEST( stake_delegation->stake == 100UL );

  stake_delegations = fd_banks_stake_delegations_root_query( banks );
  FD_TEST( fd_stake_delegations_cnt( stake_delegations ) == 3UL );
  stake_delegation = fd_stake_delegations_query( stake_delegations, &key_3 );
  FD_TEST( stake_delegation );
  FD_TEST( stake_delegation->stake == 7UL );
  stake_delegation = fd_stake_delegations_query( stake_delegations, &key_1 );
  FD_TEST( stake_delegation );
  FD_TEST( stake_delegation->stake == 100UL );

  /* Create some new children */

  fd_bank_t bank10[1];
  ulong bank_idx10 = fd_banks_new_bank( bank10, banks, bank_idx7, 0L )->data->idx;
  FD_TEST( fd_banks_clone_from_parent( bank10, banks, bank_idx10 ) );
  FD_TEST( bank10->data->bank_seq==9UL );
  FD_TEST( bank10->data->fields.capitalization == 2100UL );

  fd_banks_mark_bank_frozen( bank10 );

  fd_bank_t bank11[1];
  ulong bank_idx11 = fd_banks_new_bank( bank11, banks, bank_idx9, 0L )->data->idx;
  FD_TEST( fd_banks_clone_from_parent( bank11, banks, bank_idx11 ) );
  FD_TEST( bank11->data->bank_seq==10UL );
  FD_TEST( bank11->data->fields.capitalization == 2100UL );
  bank11->data->fields.slot = 11UL;

  /* Now there should be 3 forks:
     1. 7 (1234) -> 8
     2. 7 (1234) -> 9 -> 11
     3  7 (1234) -> 10 */

  /* At this point, bank7 is the root and it has 3 children: bank8, bank9, and bank10 */

  /* Verify that children slots are not pruned off */

  fd_bank_t bank_query[1];
  FD_TEST( !!fd_banks_bank_query( bank_query, banks, bank8->data->idx ) );
  FD_TEST( !!fd_banks_bank_query( bank_query, banks, bank9->data->idx ) );
  FD_TEST( !!fd_banks_bank_query( bank_query, banks, bank10->data->idx ) );

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
  FD_TEST( bank11->data->fields.slot == 0UL );
  FD_TEST( bank11->data->fields.capitalization == 0UL );

  FD_TEST( !fd_banks_join( banksl_join, banks->data, NULL ) );

  test_bank_advancing( mem );

  test_bank_dead_eviction( mem );

  test_bank_frontier( mem );

  test_bank_stake_delegations_dynamic_sizing( mem );

  test_bank_shared_offset_accessors( mem );

  FD_LOG_NOTICE(( "pass" ));

  fd_halt();
  return 0;
}
