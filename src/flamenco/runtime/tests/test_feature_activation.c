/* Unit test for feature account activation (gh issue #7791).

   Exercises feature activation at epoch boundaries via
   fd_svm_mini, including:
   - Normal activation of a pending feature at an epoch boundary
   - Feature account too small (1 byte) is skipped gracefully
   - Already-active feature account is not re-activated */

#include "fd_svm_mini.h"
#include "../fd_system_ids.h"
#include "../../features/fd_features.h"

#define TEST_SLOTS_PER_EPOCH (3UL)

/* Pick a non-cleaned-up feature to use as a test subject.
   We'll find one dynamically in the test. */

static fd_feature_id_t const *
find_non_cleaned_up_feature( void ) {
  for( fd_feature_id_t const * id = fd_feature_iter_init();
       !fd_feature_iter_done( id );
       id = fd_feature_iter_next( id ) ) {
    if( !id->cleaned_up && !id->reverted ) return id;
  }
  return NULL;
}

/* Create a feature account in rooted state. */

static void
create_feature_account( fd_svm_mini_t *     mini,
                        fd_pubkey_t const * pubkey,
                        void const *        data,
                        uint                dlen ) {
  fd_account_meta_t meta = { .lamports = 1UL, .dlen = dlen };
  fd_memcpy( meta.owner, fd_solana_feature_program_id.uc, 32UL );
  fd_accdb_ro_t ro[1];
  fd_accdb_ro_init_nodb_oob( ro, pubkey, &meta, data );
  fd_svm_mini_put_account_rooted( mini, ro );
}

/* Create a feature account with wrong owner in rooted state. */

static void
create_feature_account_wrong_owner( fd_svm_mini_t *     mini,
                                    fd_pubkey_t const * pubkey,
                                    void const *        data,
                                    uint                dlen ) {
  fd_account_meta_t meta = { .lamports = 1UL, .dlen = dlen };
  fd_memcpy( meta.owner, fd_solana_system_program_id.uc, 32UL );
  fd_accdb_ro_t ro[1];
  fd_accdb_ro_init_nodb_oob( ro, pubkey, &meta, data );
  fd_svm_mini_put_account_rooted( mini, ro );
}

/* Read feature activation slot from the bank's features set. */

static ulong
get_feature_slot( fd_bank_t *             bank,
                  fd_feature_id_t const * id ) {
  return fd_features_get( &bank->f.features, id );
}

/* Advance the svm_mini environment from root through an epoch boundary.

   With slots_per_epoch=3 and root_slot=1 (epoch 0):
   - Slot 2 (epoch 0): attach, freeze, advance
   - Slot 3 (epoch 1): epoch boundary triggers feature activation

   Returns the bank index of the epoch-boundary slot. */

static ulong
advance_to_epoch_boundary( fd_svm_mini_t * mini, ulong root_idx ) {
  /* Slot 2: still epoch 0 */
  ulong idx2 = fd_svm_mini_attach_child( mini, root_idx, 2UL );
  fd_svm_mini_freeze( mini, idx2 );
  fd_svm_mini_advance_root( mini, idx2 );

  /* Slot 3: epoch boundary (epoch 0 -> epoch 1).
     fd_runtime_block_execute_prepare (called by attach_child) calls
     fd_compute_and_apply_new_feature_activations which calls
     fd_features_activate -> fd_feature_activate for each feature. */
  ulong idx3 = fd_svm_mini_attach_child( mini, idx2, 3UL );
  return idx3;
}

/* Test: pending feature with proper 9-byte account gets activated
   at epoch boundary. */

static void
test_normal_activation( fd_svm_mini_t * mini ) {
  fd_feature_id_t const * feat = find_non_cleaned_up_feature();
  FD_TEST( feat );

  fd_svm_mini_params_t params[1];
  fd_svm_mini_params_default( params );
  params->slots_per_epoch        = TEST_SLOTS_PER_EPOCH;
  params->init_feature_accounts  = 0;
  ulong root_idx = fd_svm_mini_reset( mini, params );

  fd_bank_t * root_bank = fd_svm_mini_bank( mini, root_idx );

  /* Disable ALL features, then mark our test feature as disabled
     (pending activation).  This ensures it's not already active. */
  fd_features_disable_all( &root_bank->f.features );

  /* Create a proper 9-byte pending feature account (is_active=0). */
  fd_feature_t pending = { .is_active = 0, .activation_slot = 0UL };
  create_feature_account( mini, &feat->id, &pending, sizeof(fd_feature_t) );

  ulong boundary_idx = advance_to_epoch_boundary( mini, root_idx );
  fd_bank_t * bank = fd_svm_mini_bank( mini, boundary_idx );

  /* The feature should now be activated at the epoch boundary slot. */
  ulong activation_slot = get_feature_slot( bank, feat );
  FD_TEST( activation_slot != FD_FEATURE_DISABLED );
  FD_TEST( activation_slot == 3UL );

  FD_LOG_NOTICE(( "test_normal_activation: PASSED (activated at slot %lu)", activation_slot ));
}

/* Test: feature account that is too small (1 byte) should be skipped
   gracefully.  fd_feature_decode requires >= 9 bytes, so a 1-byte
   account should not trigger activation or crash. */

static void
test_too_small_account_skipped( fd_svm_mini_t * mini ) {
  fd_feature_id_t const * feat = find_non_cleaned_up_feature();
  FD_TEST( feat );

  fd_svm_mini_params_t params[1];
  fd_svm_mini_params_default( params );
  params->slots_per_epoch        = TEST_SLOTS_PER_EPOCH;
  params->init_feature_accounts  = 0;
  ulong root_idx = fd_svm_mini_reset( mini, params );

  fd_bank_t * root_bank = fd_svm_mini_bank( mini, root_idx );
  fd_features_disable_all( &root_bank->f.features );

  /* Create a 1-byte feature account — too small for fd_feature_t (9 bytes).
     This simulates the edge case from gh#7791. */
  uchar one_byte = 0; /* is_active = 0 */
  create_feature_account( mini, &feat->id, &one_byte, 1U );

  ulong boundary_idx = advance_to_epoch_boundary( mini, root_idx );
  fd_bank_t * bank = fd_svm_mini_bank( mini, boundary_idx );

  /* The feature should remain disabled — the 1-byte account is too
     small to decode, so fd_feature_activate skips it. */
  ulong activation_slot = get_feature_slot( bank, feat );
  FD_TEST( activation_slot == FD_FEATURE_DISABLED );

  FD_LOG_NOTICE(( "test_too_small_account_skipped: PASSED" ));
}

/* Test: already-active feature account is recognized (not re-activated
   at a different slot). */

static void
test_already_active_recognized( fd_svm_mini_t * mini ) {
  fd_feature_id_t const * feat = find_non_cleaned_up_feature();
  FD_TEST( feat );

  fd_svm_mini_params_t params[1];
  fd_svm_mini_params_default( params );
  params->slots_per_epoch        = TEST_SLOTS_PER_EPOCH;
  params->init_feature_accounts  = 0;
  ulong root_idx = fd_svm_mini_reset( mini, params );

  fd_bank_t * root_bank = fd_svm_mini_bank( mini, root_idx );
  fd_features_disable_all( &root_bank->f.features );

  /* Create a feature account that is already active (activated at slot 1). */
  fd_feature_t active = { .is_active = 1, .activation_slot = 1UL };
  create_feature_account( mini, &feat->id, &active, sizeof(fd_feature_t) );

  ulong boundary_idx = advance_to_epoch_boundary( mini, root_idx );
  fd_bank_t * bank = fd_svm_mini_bank( mini, boundary_idx );

  /* The feature should be recognized as activated at slot 1 (its
     original activation slot), not re-activated at slot 3. */
  ulong activation_slot = get_feature_slot( bank, feat );
  FD_TEST( activation_slot == 1UL );

  FD_LOG_NOTICE(( "test_already_active_recognized: PASSED (slot=%lu)", activation_slot ));
}

/* Test: feature account with no owner (not owned by feature program)
   should be skipped. */

static void
test_wrong_owner_skipped( fd_svm_mini_t * mini ) {
  fd_feature_id_t const * feat = find_non_cleaned_up_feature();
  FD_TEST( feat );

  fd_svm_mini_params_t params[1];
  fd_svm_mini_params_default( params );
  params->slots_per_epoch        = TEST_SLOTS_PER_EPOCH;
  params->init_feature_accounts  = 0;
  ulong root_idx = fd_svm_mini_reset( mini, params );

  fd_bank_t * root_bank = fd_svm_mini_bank( mini, root_idx );
  fd_features_disable_all( &root_bank->f.features );

  /* Create a 9-byte pending feature account but with wrong owner. */
  fd_feature_t pending = { .is_active = 0, .activation_slot = 0UL };
  create_feature_account_wrong_owner( mini, &feat->id, &pending, sizeof(fd_feature_t) );

  ulong boundary_idx = advance_to_epoch_boundary( mini, root_idx );
  fd_bank_t * bank = fd_svm_mini_bank( mini, boundary_idx );

  /* Feature should remain disabled — wrong owner. */
  ulong activation_slot = get_feature_slot( bank, feat );
  FD_TEST( activation_slot == FD_FEATURE_DISABLED );

  FD_LOG_NOTICE(( "test_wrong_owner_skipped: PASSED" ));
}

int
main( int argc, char ** argv ) {
  fd_svm_mini_limits_t limits[1];
  fd_svm_mini_limits_default( limits );
  fd_svm_mini_t * mini = fd_svm_test_boot( &argc, &argv, limits );

  test_normal_activation( mini );
  test_too_small_account_skipped( mini );
  test_already_active_recognized( mini );
  test_wrong_owner_skipped( mini );

  FD_LOG_NOTICE(( "pass" ));
  fd_svm_test_halt( mini );
  return 0;
}
