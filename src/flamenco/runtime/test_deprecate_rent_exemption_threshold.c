/* Test for SIMD-0194: deprecate_rent_exemption_threshold

   This test simulates passing through several epoch boundaries, checking that
   the value of rent in the accounts db, the bank and the sysvar cache is
   updated correctly at the slot where deprecate_rent_exemption_threshold
   is activated. */

#include "../mini/fd_svm_mini.h"
#include "fd_runtime.h"
#include "fd_bank.h"
#include "fd_system_ids.h"
#include "sysvar/fd_sysvar_rent.h"
#include "sysvar/fd_sysvar_epoch_schedule.h"
#include "../accdb/fd_accdb_impl_v1.h"
#include "../../funk/fd_funk_rec.h"

/* Values before deprecate_rent_exemption_threshold is activated */
#define TEST_DEFAULT_LAMPORTS_PER_UINT8_YEAR (3480UL)
#define TEST_DEFAULT_EXEMPTION_THRESHOLD     (2.0)

/* Values after deprecate_rent_exemption_threshold is activated */
#define TEST_NEW_LAMPORTS_PER_UINT8_YEAR (6960UL)
#define TEST_NEW_EXEMPTION_THRESHOLD     (1.0)

#define TEST_SLOTS_PER_EPOCH         (3UL)
#define TEST_FEATURE_ACTIVATION_SLOT (TEST_SLOTS_PER_EPOCH * 2)

static void
verify_rent_values( fd_svm_mini_t * svm,
                    ulong           expected_lamports,
                    double          expected_threshold ) {
  fd_svm_view_t * view = fd_svm_mini_join_root( svm );

  fd_funk_t * funk = fd_accdb_user_v1_funk( view->accdb );

  fd_rent_t funk_rent[1];
  FD_TEST( fd_sysvar_rent_read( funk, &view->xid, funk_rent ) );
  FD_TEST( funk_rent->lamports_per_uint8_year == expected_lamports );
  FD_TEST( funk_rent->exemption_threshold     == expected_threshold );

  fd_rent_t const * bank_rent = fd_bank_rent_query( view->bank );
  FD_TEST( bank_rent );
  FD_TEST( bank_rent->lamports_per_uint8_year == expected_lamports );
  FD_TEST( bank_rent->exemption_threshold     == expected_threshold );

  fd_sysvar_cache_t const * sysvar_cache = fd_bank_sysvar_cache_query( view->bank );
  fd_rent_t cache_rent[1];
  FD_TEST( fd_sysvar_cache_rent_read( sysvar_cache, cache_rent ) );
  FD_TEST( cache_rent->lamports_per_uint8_year == expected_lamports );
  FD_TEST( cache_rent->exemption_threshold     == expected_threshold );

  fd_svm_view_leave( view );
}

static int
rent_was_modified_in_txn( fd_svm_view_t * view ) {
  /* FIXME use accdb_ro API */
  fd_funk_t * funk = fd_accdb_user_v1_funk( view->accdb );
  fd_funk_rec_key_t key;
  fd_memcpy( key.uc, fd_sysvar_rent_id.key, FD_PUBKEY_FOOTPRINT );
  fd_funk_txn_xid_t xid_out;
  fd_funk_rec_query_t query[1];

  fd_funk_rec_query_try_global( funk, &view->xid, &key, &xid_out, query );
  return fd_funk_txn_xid_eq( &xid_out, &view->xid );
}

static int
process_slot( fd_svm_mini_t * svm,
              ulong           slot ) {
  fd_svm_view_t * parent = fd_svm_mini_join_root( svm );
  fd_svm_view_t * view   = fd_svm_view_fork( parent, slot );
  fd_svm_view_leave( parent );

  int is_epoch_boundary = 0;

  /* FIXME add capture_ctx */
  fd_runtime_block_execute_prepare( svm->banks, view->bank, view->accdb, view->runtime_stack, NULL, &is_epoch_boundary );

  int rent_modified = rent_was_modified_in_txn( view );

  fd_svm_view_freeze( view );
  fd_svm_view_root  ( view );

  return rent_modified;
}

/* Advance to target slot and return whether rent was modified in that slot. */
static int
advance_to_slot( fd_svm_mini_t * svm,
                 ulong           target_slot ) {
  ulong current_slot;
  {
    fd_svm_view_t * root = fd_svm_mini_join_root( svm );
    current_slot = fd_bank_slot_get( root->bank );
    fd_svm_view_leave( root );
  }

  int rent_modified = 0;
  for( ulong slot = current_slot + 1UL; slot <= target_slot; slot++ ) {
    rent_modified = process_slot( svm, slot );
  }
  return rent_modified;
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_svm_mini_limits_t svm_limits = {
    .max_vote_accounts = 4,
    .max_live_slots    = 2,
    .max_fork_width    = 2
  };
  fd_svm_mini_t * svm = fd_svm_mini_create( &svm_limits, "test", 0UL );

  {
    fd_svm_view_t * root = fd_svm_mini_join_root( svm );

    fd_epoch_schedule_t epoch_schedule = {
      .slots_per_epoch             = TEST_SLOTS_PER_EPOCH,
      .leader_schedule_slot_offset = TEST_SLOTS_PER_EPOCH
    };
    fd_bank_epoch_schedule_set( root->bank, epoch_schedule );
    fd_sysvar_epoch_schedule_write( root->bank, root->accdb, &root->xid, NULL, &epoch_schedule );

    fd_features_t * features = fd_bank_features_modify( root->bank );
    features->deprecate_rent_exemption_threshold = TEST_FEATURE_ACTIVATION_SLOT;

    fd_svm_view_freeze( root );
    fd_svm_view_leave ( root );
  }

  /* - Epoch 1: deprecate_rent_exemption_threshold not activated
     - Epoch 2: deprecate_rent_exemption_threshold activation epoch
     - Epoch 3: after deprecate_rent_exemption_threshold activation epoch */

  /* Advance to last slot of epoch 1. Rent should not change. */
  int rent_modified = advance_to_slot( svm, (2UL * TEST_SLOTS_PER_EPOCH) - 1UL );
  verify_rent_values( svm, TEST_DEFAULT_LAMPORTS_PER_UINT8_YEAR, TEST_DEFAULT_EXEMPTION_THRESHOLD );
  FD_TEST( !rent_modified );

  /* Advance to first slot of epoch 2. Rent should change. */
  rent_modified = advance_to_slot( svm, 2UL * TEST_SLOTS_PER_EPOCH );
  verify_rent_values( svm, TEST_NEW_LAMPORTS_PER_UINT8_YEAR, TEST_NEW_EXEMPTION_THRESHOLD );
  FD_TEST( rent_modified );

  /* Advance to first slot of epoch 3. Rent should not change. */
  rent_modified = advance_to_slot( svm, 3UL * TEST_SLOTS_PER_EPOCH );
  verify_rent_values( svm, TEST_NEW_LAMPORTS_PER_UINT8_YEAR, TEST_NEW_EXEMPTION_THRESHOLD );
  FD_TEST( !rent_modified );

  fd_svm_mini_destroy( svm );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
