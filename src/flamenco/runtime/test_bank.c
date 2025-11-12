#include "fd_bank.h"
#include "fd_exec_stack.h"

/* Regression guard for bundle execution: verifies that a transaction
   context marked as being part of a bundle exposes writable accounts
   updated by preceding bundle contexts to the executor. This prevents
   the executor from falling back to AccountsDB reads and miss
   in-flight mutations.*/
static void
test_bundle_prev_ctx_is_visible_to_executor( void ) {
  fd_exec_txn_ctx_t prev_ctx[1] = {0};
  fd_exec_txn_ctx_t curr_ctx[1] = {0};
  fd_exec_accounts_t exec_accounts[1] = {0};
  fd_txn_p_t prev_txn_p[1] = {0};
  fd_txn_p_t curr_txn_p[1] = {0};
  fd_txn_t * prev_txn = TXN( prev_txn_p );
  fd_txn_t * curr_txn = TXN( curr_txn_p );
  prev_txn->transaction_version = FD_TXN_VLEGACY;
  curr_txn->transaction_version = FD_TXN_VLEGACY;
  prev_txn->signature_cnt        = 1U;
  curr_txn->signature_cnt        = 1U;
  prev_txn->acct_addr_cnt        = 1U;
  curr_txn->acct_addr_cnt        = 1U;

  prev_ctx->txn = *prev_txn_p;
  curr_ctx->txn = *curr_txn_p;

  fd_pubkey_t fee_payer_key = {0};
  fee_payer_key.uc[ 0 ] = 42;
  prev_ctx->account_keys[ FD_FEE_PAYER_TXN_IDX ] = fee_payer_key;
  curr_ctx->account_keys[ FD_FEE_PAYER_TXN_IDX ] = fee_payer_key;
  prev_ctx->accounts_cnt = 1UL;
  curr_ctx->accounts_cnt = 1UL;
  prev_ctx->nonce_account_idx_in_txn = ULONG_MAX;
  curr_ctx->nonce_account_idx_in_txn = ULONG_MAX;

   struct {
      fd_account_meta_t meta;
      uchar             data[ 1 ];
   } prev_account_storage = {0};
   prev_account_storage.meta.lamports = 500UL;

   FD_TEST( fd_txn_account_join( fd_txn_account_new( &prev_ctx->accounts[ FD_FEE_PAYER_TXN_IDX ],
                                                     &fee_payer_key,
                                                     &prev_account_storage.meta,
                                                     1 ) ) );

  curr_ctx->exec_accounts = exec_accounts;
  curr_ctx->bundle.is_bundle          = 1;
  curr_ctx->bundle.prev_txn_ctxs_cnt  = 1UL;
  curr_ctx->bundle.prev_txn_ctxs[ 0 ] = prev_ctx;

  /* Edge case: fee payer lamports were mutated by the previous bundle
     transaction and have not been committed to AccountsDB yet. */
  fd_txn_account_t * acct = fd_executor_setup_txn_account( curr_ctx, FD_FEE_PAYER_TXN_IDX );
  FD_TEST( acct );
  /* If the executor fails to consult prev_txn_ctxs, meta points to a
     zeroed staging buffer (or NULL) and this assertion trips. */
  FD_TEST( acct->meta->lamports==prev_account_storage.meta.lamports );
}

static void
test_bank_advancing( void * mem ) {
  fd_banks_t * banks = fd_banks_join( fd_banks_new( mem, 16UL, 2UL, 0, 8888UL ) );
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
  fd_bank_t * bank_P = fd_banks_init_bank( banks ); /* P slot = 100 */
  FD_TEST( bank_P );
  fd_bank_slot_set( bank_P, 100UL );
  FD_TEST( fd_bank_slot_get( bank_P ) == 100UL );
  bank_P->refcnt = 0UL; /* P(0) */
  ulong bank_idx_P = bank_P->idx;

  /* Create Q branch from P. */
  ulong bank_idx_Q = fd_banks_new_bank( banks, bank_idx_P, 0L )->idx;
  fd_bank_t * bank_Q = fd_banks_clone_from_parent( banks, bank_idx_Q, bank_idx_P );  /* Q slot = 101 */
  FD_TEST( bank_Q );
  fd_bank_slot_set( bank_Q, 101UL );
  bank_Q->refcnt = 1UL; /* Q(1) */
  fd_banks_mark_bank_frozen( banks, bank_Q );
  FD_TEST( fd_banks_bank_query( banks, bank_idx_Q ) == bank_Q );

  /* Create A branch from P - this is on the rooted fork. */
  ulong bank_idx_A = fd_banks_new_bank( banks, bank_idx_P, 0L )->idx;
  fd_bank_t * bank_A = fd_banks_clone_from_parent( banks, bank_idx_A, bank_idx_P );  /* A slot = 102 */
  FD_TEST( bank_A );
  fd_bank_slot_set( bank_A, 102UL );
  bank_A->refcnt = 0UL; /* A(0) */
  fd_banks_mark_bank_frozen( banks, bank_A );

  /* Create X branch from A. */
  ulong bank_idx_X = fd_banks_new_bank( banks, bank_idx_A, 0L )->idx;
  fd_bank_t * bank_X = fd_banks_clone_from_parent( banks, bank_idx_X, bank_idx_A );  /* X slot = 103 */
  FD_TEST( bank_X );
  fd_bank_slot_set( bank_X, 103UL );
  bank_X->refcnt = 0UL; /* X(0) */
  fd_banks_mark_bank_frozen( banks, bank_X );

  /* Create Y branch from X. */
  ulong bank_idx_Y = fd_banks_new_bank( banks, bank_idx_X, 0L )->idx;
  fd_bank_t * bank_Y = fd_banks_clone_from_parent( banks, bank_idx_Y, bank_idx_X );  /* Y slot = 104 */
  FD_TEST( bank_Y );
  fd_bank_slot_set( bank_Y, 104UL );
  bank_Y->refcnt = 0UL; /* Y(0) */
  fd_banks_mark_bank_frozen( banks, bank_Y );

  /* Create B branch from A - this is on the rooted fork. */
  ulong bank_idx_B = fd_banks_new_bank( banks, bank_idx_A, 0L )->idx;
  fd_bank_t * bank_B = fd_banks_clone_from_parent( banks, bank_idx_B, bank_idx_A );  /* B slot = 105 */
  FD_TEST( bank_B );
  fd_bank_slot_set( bank_B, 105UL );
  bank_B->refcnt = 0UL; /* B(0) */
  fd_banks_mark_bank_frozen( banks, bank_B );

  /* Create C branch from A. */
  ulong bank_idx_C = fd_banks_new_bank( banks, bank_idx_A, 0L )->idx;
  fd_bank_t * bank_C = fd_banks_clone_from_parent( banks, bank_idx_C, bank_idx_A );  /* C slot = 106 */
  FD_TEST( bank_C );
  fd_bank_slot_set( bank_C, 106UL );
  bank_C->refcnt = 0UL; /* C(0) */
  fd_banks_mark_bank_frozen( banks, bank_C );

  /* Create M branch from B - this is on the rooted fork. */
  ulong bank_idx_M = fd_banks_new_bank( banks, bank_idx_B, 0L )->idx;
  fd_bank_t * bank_M = fd_banks_clone_from_parent( banks, bank_idx_M, bank_idx_B );  /* M slot = 107 */
  FD_TEST( bank_M );
  fd_bank_slot_set( bank_M, 107UL );
  bank_M->refcnt = 0UL; /* M(0) */
  fd_banks_mark_bank_frozen( banks, bank_M );

  /* Create R branch from B. */
  ulong bank_idx_R = fd_banks_new_bank( banks, bank_idx_B, 0L )->idx;
  fd_bank_t * bank_R = fd_banks_clone_from_parent( banks, bank_idx_R, bank_idx_B );  /* R slot = 108 */
  FD_TEST( bank_R );
  fd_bank_slot_set( bank_R, 108UL );
  bank_R->refcnt = 0UL; /* R(0) */
  fd_banks_mark_bank_frozen( banks, bank_R );

  /* Create D branch from M. */
  ulong bank_idx_D = fd_banks_new_bank( banks, bank_idx_M, 0L )->idx;
  fd_bank_t * bank_D = fd_banks_clone_from_parent( banks, bank_idx_D, bank_idx_M );  /* D slot = 109 */
  FD_TEST( bank_D );
  fd_bank_slot_set( bank_D, 109UL );
  bank_D->refcnt = 2UL; /* D(2) */
  fd_banks_mark_bank_frozen( banks, bank_D );

  /* Create T branch from M - this is on the rooted fork. */
  ulong bank_idx_T = fd_banks_new_bank( banks, bank_idx_M, 0L )->idx;
  fd_bank_t * bank_T = fd_banks_clone_from_parent( banks, bank_idx_T, bank_idx_M );  /* T slot = 110 */
  FD_TEST( bank_T );
  fd_bank_slot_set( bank_T, 110UL );
  bank_T->refcnt = 0UL; /* T(0) */
  fd_banks_mark_bank_frozen( banks, bank_T );

  /* Create J branch from R. */
  ulong bank_idx_J = fd_banks_new_bank( banks, bank_idx_R, 0L )->idx;
  fd_bank_t * bank_J = fd_banks_clone_from_parent( banks, bank_idx_J, bank_idx_R );  /* J slot = 111 */
  FD_TEST( bank_J );
  fd_bank_slot_set( bank_J, 111UL );
  bank_J->refcnt = 0UL; /* J(0) */
  fd_banks_mark_bank_frozen( banks, bank_J );

  /* Create L branch from R. */
  ulong bank_idx_L = fd_banks_new_bank( banks, bank_idx_R, 0L )->idx;
  fd_bank_t * bank_L = fd_banks_clone_from_parent( banks, bank_idx_L, bank_idx_R );  /* L slot = 112 */
  FD_TEST( bank_L );
  fd_bank_slot_set( bank_L, 112UL );
  bank_L->refcnt = 0UL; /* L(0) */
  fd_banks_mark_bank_frozen( banks, bank_L );

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

  fd_bank_t const * new_root = fd_banks_advance_root( banks, bank_idx_A );
  FD_TEST( new_root == bank_A );
  FD_TEST( new_root->idx == bank_idx_A );

  result = fd_banks_advance_root_prepare( banks, bank_idx_T, &advanceable_bank_idx );
  FD_TEST( result == 1 );
  FD_TEST( advanceable_bank_idx == bank_idx_B ); /* Should be able to publish up to B */

  new_root = fd_banks_advance_root( banks, bank_idx_B );
  FD_TEST( new_root == bank_B );
  FD_TEST( new_root->idx == bank_idx_B );

  result = fd_banks_advance_root_prepare( banks, bank_idx_T, &advanceable_bank_idx );
  FD_TEST( result == 1 );
  FD_TEST( advanceable_bank_idx == bank_idx_M ); /* Should be able to publish up to M */

  /* Actually publish up to M. */
  new_root = fd_banks_advance_root( banks, bank_idx_M );
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
  new_root = fd_banks_advance_root( banks, bank_idx_T );
  FD_TEST( new_root == bank_T );
  FD_TEST( new_root->idx == bank_idx_T );

  /* Verify that M and D have been pruned. */
  FD_TEST( !fd_banks_bank_query( banks, bank_idx_M ) ); /* M should be gone */
  FD_TEST( !fd_banks_bank_query( banks, bank_idx_D ) ); /* D should be gone */
  FD_TEST( fd_banks_bank_query( banks, bank_idx_T ) == bank_T ); /* T should be the new root */

}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );
  test_bundle_prev_ctx_is_visible_to_executor();

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

  char *      _page_sz = "gigantic";
  ulong       numa_idx = fd_shmem_numa_idx( 0 );
  fd_wksp_t * wksp     = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ),
                                                25UL,
                                                fd_shmem_cpu_idx( numa_idx ),
                                                "wksp",
                                                0UL );
  FD_TEST( wksp );

  uchar * mem = fd_wksp_alloc_laddr( wksp, fd_banks_align(), fd_banks_footprint( 16UL, 2UL ), 1UL );
  FD_TEST( mem );

  mem = fd_banks_new( mem, 16UL, 2UL, 0, 8888UL );
  FD_TEST( mem );

  /* Init banks */

  fd_banks_t * banks = fd_banks_join( mem );
  FD_TEST( banks );

  fd_bank_t * bank = fd_banks_init_bank( banks );
  fd_bank_slot_set( bank, 1UL );
  ulong bank_idx = bank->idx;
  FD_TEST( bank );

  /* Set some fields */

  fd_bank_capitalization_set( bank, 1000UL );
  FD_TEST( fd_bank_capitalization_get( bank ) == 1000UL );

  /* Set a delta-based field. Query it from the local delta, then from
     the larger combined frontier state. */

  fd_stake_delegations_t * stake_delegations = fd_bank_stake_delegations_delta_locking_modify( bank );
  fd_stake_delegations_update( stake_delegations, &key_0, &key_9, 100UL, 100UL, 100UL, 100UL, 100UL );

  fd_stake_delegation_t const * stake_delegation = fd_stake_delegations_query( stake_delegations, &key_0 );
  FD_TEST( fd_stake_delegations_cnt( stake_delegations ) == 1UL );
  FD_TEST( stake_delegation );
  FD_TEST( stake_delegation->stake == 100UL );
  FD_TEST( !memcmp( &stake_delegation->vote_account, &key_9, sizeof(fd_pubkey_t) ) );
  FD_TEST( !memcmp( &stake_delegation->stake_account, &key_0, sizeof(fd_pubkey_t) ) );
  FD_TEST( stake_delegation->activation_epoch == 100UL );
  FD_TEST( stake_delegation->deactivation_epoch == 100UL );
  FD_TEST( stake_delegation->credits_observed == 100UL );

  fd_bank_stake_delegations_delta_end_locking_modify( bank );

  stake_delegations = fd_bank_stake_delegations_frontier_query( banks, bank );
  FD_TEST( fd_stake_delegations_cnt( stake_delegations ) == 1UL );
  stake_delegation = fd_stake_delegations_query( stake_delegations, &key_0 );
  FD_TEST( stake_delegation );
  FD_TEST( stake_delegation->stake == 100UL );
  FD_TEST( !memcmp( &stake_delegation->vote_account, &key_9, sizeof(fd_pubkey_t) ) );
  FD_TEST( !memcmp( &stake_delegation->stake_account, &key_0, sizeof(fd_pubkey_t) ) );
  FD_TEST( stake_delegation->activation_epoch == 100UL );
  FD_TEST( stake_delegation->deactivation_epoch == 100UL );
  FD_TEST( stake_delegation->credits_observed == 100UL );

  /* Create some additional ancestry */

  ulong bank_idx2 = fd_banks_new_bank( banks, bank_idx, 0L )->idx;
  fd_bank_t * bank2 = fd_banks_clone_from_parent( banks, bank_idx2, bank_idx );
  fd_bank_slot_set( bank2, 2UL );
  FD_TEST( bank2 );
  FD_TEST( fd_bank_capitalization_get( bank2 ) == 1000UL );
  /* At this point, the first epoch leaders has been allocated from the
     pool that is limited to 2 instances. */
  fd_epoch_leaders_t * epoch_leaders = fd_bank_epoch_leaders_locking_modify( bank2 );
  FD_TEST( epoch_leaders );
  fd_bank_epoch_leaders_end_locking_modify( bank2 );

  /* Make sure that the contents of the stake delegations is the same
     after a new bank has been created. */

  stake_delegations = fd_bank_stake_delegations_frontier_query( banks, bank );
  FD_TEST( fd_stake_delegations_cnt( stake_delegations ) == 1UL );
  stake_delegation = fd_stake_delegations_query( stake_delegations, &key_0 );
  FD_TEST( stake_delegation );
  FD_TEST( stake_delegation->stake == 100UL );

  /* Make updates to delta */

  stake_delegations = fd_bank_stake_delegations_delta_locking_modify( bank2 );
  fd_stake_delegations_update( stake_delegations, &key_0, &key_0, 200UL, 100UL, 100UL, 100UL, 100UL );
  fd_stake_delegations_update( stake_delegations, &key_1, &key_8, 100UL, 100UL, 100UL, 100UL, 100UL );
  FD_TEST( fd_stake_delegations_cnt( stake_delegations ) == 2UL );
  stake_delegation = fd_stake_delegations_query( stake_delegations, &key_0 );
  FD_TEST( stake_delegation );
  FD_TEST( stake_delegation->stake == 200UL );
  FD_TEST( !memcmp( &stake_delegation->stake_account, &key_0, sizeof(fd_pubkey_t) ) );
  stake_delegation = fd_stake_delegations_query( stake_delegations, &key_1 );
  FD_TEST( stake_delegation );
  FD_TEST( stake_delegation->stake == 100UL );
  fd_bank_stake_delegations_delta_end_locking_modify( bank2 );

  stake_delegations = fd_bank_stake_delegations_frontier_query( banks, bank2 );
  FD_TEST( fd_stake_delegations_cnt( stake_delegations ) == 2UL );
  stake_delegation = fd_stake_delegations_query( stake_delegations, &key_0 );
  FD_TEST( stake_delegation );
  FD_TEST( stake_delegation->stake == 200UL );
  stake_delegation = fd_stake_delegations_query( stake_delegations, &key_1 );
  FD_TEST( stake_delegation );
  FD_TEST( stake_delegation->stake == 100UL );

  fd_banks_mark_bank_frozen( banks, bank2 );

  ulong bank_idx3 = fd_banks_new_bank( banks, bank_idx, 0L )->idx;
  fd_bank_t * bank3 = fd_banks_clone_from_parent( banks, bank_idx3, bank_idx );
  FD_TEST( bank3 );
  FD_TEST( fd_bank_capitalization_get( bank3 ) == 1000UL );
  fd_bank_capitalization_set( bank3, 2000UL );
  FD_TEST( fd_bank_capitalization_get( bank3 ) == 2000UL );

  /* Because bank 3 is on a different fork than bank 2, make sure that
     the updates don't get incorrectly applied. */

  stake_delegations = fd_bank_stake_delegations_delta_locking_modify( bank3 );
  fd_stake_delegations_update( stake_delegations, &key_2, &key_7, 10UL, 100UL, 100UL, 100UL, 100UL );
  FD_TEST( fd_stake_delegations_cnt( stake_delegations ) == 1UL );
  stake_delegation = fd_stake_delegations_query( stake_delegations, &key_2 );
  FD_TEST( stake_delegation );
  FD_TEST( stake_delegation->stake == 10UL );
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

  fd_epoch_leaders_t * epoch_leaders2 = fd_bank_epoch_leaders_locking_modify( bank3 );
  FD_TEST( epoch_leaders2 );
  fd_bank_epoch_leaders_end_locking_modify( bank3 );

  fd_banks_mark_bank_frozen( banks, bank3 );

  ulong bank_idx4 = fd_banks_new_bank( banks, bank_idx3, 0L )->idx;
  fd_bank_t * bank4 = fd_banks_clone_from_parent( banks, bank_idx4, bank_idx3 );
  FD_TEST( bank4 );
  FD_TEST( fd_bank_capitalization_get( bank4 ) == 2000UL );

  /* Trying to allocate a new epoch leaders should fail because the pool
     now has no free elements. */

  FD_TEST( !fd_bank_epoch_leaders_pool_free( fd_bank_get_epoch_leaders_pool( bank4 ) ) );

  fd_banks_mark_bank_frozen( banks, bank4 );

  ulong bank_idx5 = fd_banks_new_bank( banks, bank_idx4, 0L )->idx;
  fd_bank_t * bank5 = fd_banks_clone_from_parent( banks, bank_idx5, bank_idx4 );
  FD_TEST( bank5 );
  FD_TEST( fd_bank_capitalization_get( bank5 ) == 2000UL );
  fd_bank_capitalization_set( bank5, 3000UL );
  FD_TEST( fd_bank_capitalization_get( bank5 ) == 3000UL );

  fd_banks_mark_bank_frozen( banks, bank5 );

  ulong bank_idx6 = fd_banks_new_bank( banks, bank_idx2, 0L )->idx;
  fd_bank_t * bank6 = fd_banks_clone_from_parent( banks, bank_idx6, bank_idx2 );
  FD_TEST( bank6 );
  FD_TEST( fd_bank_capitalization_get( bank6 ) == 1000UL );
  fd_bank_capitalization_set( bank6, 2100UL );
  fd_bank_slot_set( bank6, 6UL );
  FD_TEST( fd_bank_capitalization_get( bank6 ) == 2100UL );

  fd_banks_mark_bank_frozen( banks, bank6 );

  ulong bank_idx7 = fd_banks_new_bank( banks, bank_idx6, 0L )->idx;
  fd_bank_t * bank7 = fd_banks_clone_from_parent( banks, bank_idx7, bank_idx6 );
  FD_TEST( bank7 );
  fd_bank_slot_set( bank7, 7UL );
  FD_TEST( fd_bank_capitalization_get( bank7 ) == 2100UL );

  stake_delegations = fd_bank_stake_delegations_delta_locking_modify( bank7 );
  fd_stake_delegations_update( stake_delegations, &key_3, &key_6, 7UL, 100UL, 100UL, 100UL, 100UL );
  stake_delegation = fd_stake_delegations_query( stake_delegations, &key_3 );
  FD_TEST( stake_delegation );
  FD_TEST( stake_delegation->stake == 7UL );
  fd_stake_delegations_remove( stake_delegations, &key_0 );
  stake_delegation = fd_stake_delegations_query( stake_delegations, &key_0 );
  FD_TEST( stake_delegation );
  FD_TEST( stake_delegation->is_tombstone==1 );
  fd_bank_stake_delegations_delta_end_locking_modify( bank7 );

  stake_delegations = fd_bank_stake_delegations_frontier_query( banks, bank7 );
  FD_TEST( fd_stake_delegations_cnt( stake_delegations ) == 2UL );
  stake_delegation = fd_stake_delegations_query( stake_delegations, &key_3 );
  FD_TEST( stake_delegation );
  FD_TEST( stake_delegation->stake == 7UL );
  stake_delegation = fd_stake_delegations_query( stake_delegations, &key_1 );
  FD_TEST( stake_delegation );
  FD_TEST( stake_delegation->stake == 100UL );

  fd_banks_mark_bank_frozen( banks, bank7 );

  /* At this point there are these forks:
     1. 1 -> 2 -> 6 -> 7
     2. 1 -> 3 -> 4
     3. 1 -> 3 -> 5 */

  ulong bank_idx8 = fd_banks_new_bank( banks, bank_idx7, 0L )->idx;
  fd_bank_t * bank8 = fd_banks_clone_from_parent( banks, bank_idx8, bank_idx7 );
  FD_TEST( bank8 );
  FD_TEST( fd_bank_capitalization_get( bank8 ) == 2100UL );

  stake_delegations = fd_bank_stake_delegations_delta_locking_modify( bank8 );
  fd_stake_delegations_update( stake_delegations, &key_4, &key_5, 4UL, 100UL, 100UL, 100UL, 100UL );
  fd_bank_stake_delegations_delta_end_locking_modify( bank8 );

  stake_delegations = fd_bank_stake_delegations_frontier_query( banks, bank8 );
  FD_TEST( fd_stake_delegations_cnt( stake_delegations ) == 3UL );
  stake_delegation = fd_stake_delegations_query( stake_delegations, &key_4 );
  FD_TEST( stake_delegation );
  FD_TEST( stake_delegation->stake == 4UL );

  fd_banks_mark_bank_frozen( banks, bank8 );

  ulong bank_idx9 = fd_banks_new_bank( banks, bank_idx7, 0L )->idx;
  fd_bank_t * bank9 = fd_banks_clone_from_parent( banks, bank_idx9, bank_idx7 );
  FD_TEST( bank9 );
  FD_TEST( fd_bank_capitalization_get( bank9 ) == 2100UL );

  /* Ensure that the child-most bank is able to correctly query the
     total stake delegations even when some ancestors have not
     published any delegations. */

  stake_delegations = fd_bank_stake_delegations_frontier_query( banks, bank9 );
  FD_TEST( fd_stake_delegations_cnt( stake_delegations ) == 2UL );
  stake_delegation = fd_stake_delegations_query( stake_delegations, &key_3 );
  FD_TEST( stake_delegation );
  FD_TEST( stake_delegation->stake == 7UL );
  stake_delegation = fd_stake_delegations_query( stake_delegations, &key_1 );
  FD_TEST( stake_delegation );
  FD_TEST( stake_delegation->stake == 100UL );

  /* Set some CoW fields. */

  fd_vote_states_t * keys = fd_bank_vote_states_prev_locking_modify( bank9 );
  keys->magic = 101UL;
  fd_bank_vote_states_prev_end_locking_modify( bank9 );

  /* Check that is now 1 free pool elements. */

  FD_TEST( fd_bank_vote_states_prev_pool_free( fd_bank_get_vote_states_prev_pool( bank9 ) ) == 1UL );

  fd_vote_states_t * keys2 = fd_bank_vote_states_prev_locking_modify( bank9 );
  keys2->magic = 101UL;
  fd_bank_vote_states_prev_end_locking_modify( bank9 );

  fd_banks_mark_bank_frozen( banks, bank9 );

  /* Verify that the bank is published and that it is indeed bank7.
     Also, verify that the stake delegations have been correctly
     applied to the new root. */

  fd_bank_t const * new_root = fd_banks_advance_root( banks, bank2->idx );
  FD_TEST( new_root );
  FD_TEST( fd_bank_slot_get( new_root ) == 2UL );
  FD_TEST( new_root == bank2 );

  new_root = fd_banks_advance_root( banks, bank6->idx );
  FD_TEST( new_root );
  FD_TEST( fd_bank_slot_get( new_root ) == 6UL );
  FD_TEST( new_root == bank6 );

  new_root = fd_banks_advance_root( banks, bank7->idx );
  FD_TEST( new_root );
  FD_TEST( fd_bank_slot_get( new_root ) == 7UL );
  FD_TEST( new_root == bank7 );

  /* Verify that direct and competing forks are pruned off */
  FD_TEST( !fd_banks_bank_query( banks, bank_idx6 ) );
  FD_TEST( !fd_banks_bank_query( banks, bank_idx3 ) );

  stake_delegations = fd_bank_stake_delegations_frontier_query( banks, (fd_bank_t *)new_root );
  FD_TEST( fd_stake_delegations_cnt( stake_delegations ) == 2UL );
  stake_delegation = fd_stake_delegations_query( stake_delegations, &key_3 );
  FD_TEST( stake_delegation );
  FD_TEST( stake_delegation->stake == 7UL );
  stake_delegation = fd_stake_delegations_query( stake_delegations, &key_1 );
  FD_TEST( stake_delegation );
  FD_TEST( stake_delegation->stake == 100UL );

  stake_delegations = fd_banks_stake_delegations_root_query( banks );
  FD_TEST( fd_stake_delegations_cnt( stake_delegations ) == 2UL );
  stake_delegation = fd_stake_delegations_query( stake_delegations, &key_3 );
  FD_TEST( stake_delegation );
  FD_TEST( stake_delegation->stake == 7UL );
  stake_delegation = fd_stake_delegations_query( stake_delegations, &key_1 );
  FD_TEST( stake_delegation );
  FD_TEST( stake_delegation->stake == 100UL );

  /* Create some new children */

  ulong bank_idx10 = fd_banks_new_bank( banks, bank_idx7, 0L )->idx;
  fd_bank_t * bank10 = fd_banks_clone_from_parent( banks, bank_idx10, bank_idx7 );
  FD_TEST( bank10 );
  FD_TEST( fd_bank_capitalization_get( bank10 ) == 2100UL );

  /* At this point, there should be an epoch leader pool element that is
     freed up. */
  FD_TEST( fd_bank_epoch_leaders_pool_free( fd_bank_get_epoch_leaders_pool( bank10 ) ) == 1UL );
  fd_epoch_leaders_t * epoch_leaders3 = fd_bank_epoch_leaders_locking_modify( bank10 );
  FD_TEST( epoch_leaders3 );
  fd_bank_epoch_leaders_end_locking_modify( bank10 );

  fd_banks_mark_bank_frozen( banks, bank10 );

  ulong bank_idx11 = fd_banks_new_bank( banks, bank_idx9, 0L )->idx;
  fd_bank_t * bank11 = fd_banks_clone_from_parent( banks, bank_idx11, bank_idx9 );
  FD_TEST( bank11 );
  FD_TEST( fd_bank_capitalization_get( bank11 ) == 2100UL );
  fd_bank_slot_set( bank11, 11UL );

  /* Again, there are no free epoch leader pool elements. */
  FD_TEST( !fd_bank_epoch_leaders_pool_free( fd_bank_get_epoch_leaders_pool( bank11 ) ) );

  fd_vote_states_t const * keys3 = fd_bank_vote_states_prev_locking_query( bank11 );
  FD_TEST( keys3->magic == 101UL );
  fd_bank_vote_states_prev_end_locking_query( bank11 );

  fd_vote_states_t const * keys4 = fd_bank_vote_states_prev_locking_query( bank11 );
  FD_TEST( keys4->magic == 101UL );
  fd_bank_vote_states_prev_end_locking_query( bank11 );

  keys = fd_bank_vote_states_prev_locking_modify( bank11 );
  keys->magic = 101UL;
  fd_bank_vote_states_prev_end_locking_modify( bank11 );

  fd_vote_states_t const * votes_const = fd_bank_vote_states_locking_query( bank11 );
  FD_TEST( !votes_const );
  fd_bank_vote_states_end_locking_query( bank11 );

  fd_vote_states_t * votes = fd_bank_vote_states_locking_modify( bank11 );
  votes->magic = 102UL;
  fd_bank_vote_states_end_locking_modify( bank11 );

  FD_TEST( fd_bank_vote_states_pool_free( fd_bank_get_vote_states_pool( bank11 ) ) == 15UL );

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

  keys3 = fd_bank_vote_states_prev_locking_query( bank11 );
  FD_TEST( keys3->magic == 101UL );
  fd_bank_vote_states_prev_end_locking_query( bank11 );

  keys4 = fd_bank_vote_states_prev_locking_query( bank11 );
  FD_TEST( keys4->magic == 101UL );
  fd_bank_vote_states_prev_end_locking_query( bank11 );

  votes_const = fd_bank_vote_states_locking_query( bank11 );
  FD_TEST( votes->magic == 102UL );
  fd_bank_vote_states_end_locking_query( bank11 );

  /* Clear bank11, we need to make sure that the pool indices are
     cleared and properly released.

     We test the cases where:
     1. Pool was not made dirty and had a non-null parent pool idx.
     2. Pool was not made dirty and had a null parent pool idx.
     3. Pool was made dirty and had a non-null parent pool idx.
     4. Pool was made dirty and had a null parent pool idx. */


  /* Set the cost tracker to some non-zero values. */

  fd_banks_clear_bank( banks, bank11 );
  FD_TEST( fd_bank_slot_get( bank11 ) == 0UL );
  FD_TEST( fd_bank_capitalization_get( bank11 ) == 0UL );

  keys3 = fd_bank_vote_states_prev_locking_query( bank11 );
  FD_TEST( keys3->magic == 101UL );
  fd_bank_vote_states_prev_end_locking_query( bank11 );

  keys4 = fd_bank_vote_states_prev_locking_query( bank11 );
  FD_TEST( keys4->magic == 101UL );
  fd_bank_vote_states_prev_end_locking_query( bank11 );

  votes_const = fd_bank_vote_states_locking_query( bank11 );
  FD_TEST( !votes_const );
  fd_bank_vote_states_end_locking_query( bank11 );

  FD_TEST( fd_banks_leave( banks ) );
  FD_TEST( fd_banks_join( fd_banks_leave( banks ) ) == banks );
  uchar * deleted_banks_mem = fd_banks_delete( fd_banks_leave( banks ) );
  FD_TEST( deleted_banks_mem == mem );
  FD_TEST( fd_banks_join( deleted_banks_mem ) == NULL );

  test_bank_advancing( mem );

  FD_LOG_NOTICE(( "pass" ));

  fd_halt();
  return 0;
}
