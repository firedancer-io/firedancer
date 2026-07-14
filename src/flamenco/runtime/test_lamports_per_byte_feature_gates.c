#include "tests/fd_svm_mini.h"
#include "fd_system_ids.h"
#include "sysvar/fd_sysvar_cache.h"
#include "sysvar/fd_sysvar_epoch_schedule.h"
#include "sysvar/fd_sysvar_rent.h"
#include "../features/fd_features.h"

#define TEST_SLOTS_PER_EPOCH                (3UL)
#define TEST_INITIAL_LAMPORTS_PER_UINT8_YEAR (1UL)
#define TEST_EXEMPTION_THRESHOLD            (1.0)
#define TEST_BURN_PERCENT                   (50)
#define TEST_ACCOUNT_STORAGE_OVERHEAD       (128UL)

struct test_rent_feature_gate {
  ulong        feature_offset;
  ulong        lamports_per_byte;
  char const * name;
};
typedef struct test_rent_feature_gate test_rent_feature_gate_t;

#define TEST_RENT_FEATURE_GATE(name, lamports) \
  { offsetof( fd_features_t, name ), (lamports), #name }

static test_rent_feature_gate_t const test_rent_feature_gates[] = {
  TEST_RENT_FEATURE_GATE( set_lamports_per_byte_to_6333, 6333UL ),
  TEST_RENT_FEATURE_GATE( set_lamports_per_byte_to_5080, 5080UL ),
  TEST_RENT_FEATURE_GATE( set_lamports_per_byte_to_2575, 2575UL ),
  TEST_RENT_FEATURE_GATE( set_lamports_per_byte_to_1322, 1322UL ),
  TEST_RENT_FEATURE_GATE( set_lamports_per_byte_to_696,   696UL  ),
  TEST_RENT_FEATURE_GATE( set_lamports_per_byte_to_6960, 6960UL )
};

#undef TEST_RENT_FEATURE_GATE

static fd_feature_id_t const *
find_feature_id( ulong feature_offset ) {
  for( fd_feature_id_t const * id = fd_feature_iter_init();
       !fd_feature_iter_done( id );
       id = fd_feature_iter_next( id ) ) {
    if( id->index==(feature_offset>>3) ) return id;
  }
  return NULL;
}

static ulong
expected_minimum_balance( ulong lamports_per_byte,
                          ulong data_len ) {
  return (data_len + TEST_ACCOUNT_STORAGE_OVERHEAD) * lamports_per_byte;
}

static void
verify_minimum_balance( fd_rent_t const * rent,
                        ulong             expected_lamports_per_byte ) {
  static ulong const data_lens[] = { 0UL, 200UL, 4096UL };

  for( ulong i=0UL; i<sizeof(data_lens)/sizeof(data_lens[0]); i++ ) {
    ulong data_len = data_lens[i];
    FD_TEST( fd_rent_exempt_minimum_balance( rent, data_len )==
             expected_minimum_balance( expected_lamports_per_byte, data_len ) );
  }
}

static void
verify_rent( fd_svm_mini_t * mini,
             ulong           bank_idx,
             ulong           expected_lamports_per_byte ) {
  fd_bank_t * bank = fd_svm_mini_bank( mini, bank_idx );
  FD_TEST( bank );

  fd_rent_t const * bank_rent = &bank->f.rent;
  FD_TEST( bank_rent->lamports_per_uint8_year==expected_lamports_per_byte );
  FD_TEST( bank_rent->exemption_threshold==TEST_EXEMPTION_THRESHOLD );
  FD_TEST( bank_rent->burn_percent==TEST_BURN_PERCENT );
  verify_minimum_balance( bank_rent, expected_lamports_per_byte );

  fd_rent_t sysvar_rent[1];
  FD_TEST( fd_sysvar_rent_read( mini->runtime->accdb,
                                fd_svm_mini_fork_id( mini, bank_idx ),
                                sysvar_rent ) );
  FD_TEST( sysvar_rent->lamports_per_uint8_year==expected_lamports_per_byte );
  FD_TEST( sysvar_rent->exemption_threshold==TEST_EXEMPTION_THRESHOLD );
  FD_TEST( sysvar_rent->burn_percent==TEST_BURN_PERCENT );
  verify_minimum_balance( sysvar_rent, expected_lamports_per_byte );

  fd_rent_t cache_rent[1];
  FD_TEST( fd_sysvar_cache_rent_read( &bank->f.sysvar_cache, cache_rent ) );
  FD_TEST( cache_rent->lamports_per_uint8_year==expected_lamports_per_byte );
  FD_TEST( cache_rent->exemption_threshold==TEST_EXEMPTION_THRESHOLD );
  FD_TEST( cache_rent->burn_percent==TEST_BURN_PERCENT );
  verify_minimum_balance( cache_rent, expected_lamports_per_byte );
}

static void
add_pending_feature( fd_svm_mini_t *                 mini,
                     test_rent_feature_gate_t const * gate ) {
  fd_feature_id_t const * id = find_feature_id( gate->feature_offset );
  FD_TEST( id );

  fd_feature_t pending = { .is_active = 0, .activation_slot = 0UL };
  fd_acc_t acc = {0};
  fd_memcpy( acc.pubkey, id->id.uc, 32UL );
  fd_memcpy( acc.owner, fd_solana_feature_program_id.uc, 32UL );
  acc.lamports = 1UL;
  acc.data_len = sizeof(fd_feature_t);
  acc.data     = (uchar *)&pending;
  fd_svm_mini_put_account_rooted( mini, &acc );
}

static void
verify_feature_activated( fd_svm_mini_t *                 mini,
                          ulong                           bank_idx,
                          test_rent_feature_gate_t const * gate,
                          ulong                           expected_slot ) {
  fd_feature_id_t const * id = find_feature_id( gate->feature_offset );
  FD_TEST( id );

  fd_bank_t * bank = fd_svm_mini_bank( mini, bank_idx );
  FD_TEST( bank );
  FD_TEST( fd_features_get( &bank->f.features, id )==expected_slot );
}

static ulong
reset_test_env( fd_svm_mini_t * mini ) {
  fd_rent_t rent = {
    .lamports_per_uint8_year = TEST_INITIAL_LAMPORTS_PER_UINT8_YEAR,
    .exemption_threshold     = TEST_EXEMPTION_THRESHOLD,
    .burn_percent            = TEST_BURN_PERCENT
  };

  fd_svm_mini_params_t params[1];
  fd_svm_mini_params_default( params );
  params->slots_per_epoch       = TEST_SLOTS_PER_EPOCH;
  params->init_feature_accounts = 0;
  params->rent                  = &rent;
  return fd_svm_mini_reset( mini, params );
}

static ulong
advance_to_next_epoch_boundary( fd_svm_mini_t * mini,
                                ulong           root_idx ) {
  fd_bank_t * root_bank = fd_svm_mini_bank( mini, root_idx );
  FD_TEST( root_bank );

  fd_epoch_schedule_t const * epoch_schedule = &root_bank->f.epoch_schedule;
  ulong current_slot  = root_bank->f.slot;
  ulong current_epoch = fd_slot_to_epoch( epoch_schedule, current_slot, NULL );
  ulong target_slot   = fd_epoch_slot0( epoch_schedule, current_epoch+1UL );
  ulong bank_idx      = root_idx;

  for( ulong slot=current_slot+1UL; slot<=target_slot; slot++ ) {
    bank_idx = fd_svm_mini_attach_child( mini, bank_idx, slot );
    fd_svm_mini_freeze( mini, bank_idx );
    fd_svm_mini_advance_root( mini, bank_idx );
  }

  return bank_idx;
}

static void
test_single_feature_activations( fd_svm_mini_t * mini ) {
  for( ulong i=0UL; i<sizeof(test_rent_feature_gates)/sizeof(test_rent_feature_gates[0]); i++ ) {
    test_rent_feature_gate_t const * gate = &test_rent_feature_gates[i];
    ulong root_idx = reset_test_env( mini );
    add_pending_feature( mini, gate );

    ulong bank_idx = advance_to_next_epoch_boundary( mini, root_idx );
    fd_bank_t * bank = fd_svm_mini_bank( mini, bank_idx );
    FD_TEST( bank );

    verify_feature_activated( mini, bank_idx, gate, bank->f.slot );
    verify_rent( mini, bank_idx, gate->lamports_per_byte );

    FD_LOG_NOTICE(( "single activation passed: %s", gate->name ));
  }
}

static void
test_same_epoch_reduction_ordering( fd_svm_mini_t * mini ) {
  ulong root_idx = reset_test_env( mini );
  add_pending_feature( mini, &test_rent_feature_gates[0] ); /* 6333 */
  add_pending_feature( mini, &test_rent_feature_gates[2] ); /* 2575 */

  ulong bank_idx = advance_to_next_epoch_boundary( mini, root_idx );
  fd_bank_t * bank = fd_svm_mini_bank( mini, bank_idx );
  FD_TEST( bank );

  verify_feature_activated( mini, bank_idx, &test_rent_feature_gates[0], bank->f.slot );
  verify_feature_activated( mini, bank_idx, &test_rent_feature_gates[2], bank->f.slot );
  verify_rent( mini, bank_idx, test_rent_feature_gates[2].lamports_per_byte );
}

static void
test_out_of_order_activation( fd_svm_mini_t * mini ) {
  ulong root_idx = reset_test_env( mini );
  add_pending_feature( mini, &test_rent_feature_gates[3] ); /* 1322 */

  ulong bank_idx = advance_to_next_epoch_boundary( mini, root_idx );
  fd_bank_t * bank = fd_svm_mini_bank( mini, bank_idx );
  FD_TEST( bank );
  verify_feature_activated( mini, bank_idx, &test_rent_feature_gates[3], bank->f.slot );
  verify_rent( mini, bank_idx, test_rent_feature_gates[3].lamports_per_byte );

  add_pending_feature( mini, &test_rent_feature_gates[1] ); /* 5080 */
  root_idx = bank_idx;
  bank_idx = advance_to_next_epoch_boundary( mini, root_idx );
  bank = fd_svm_mini_bank( mini, bank_idx );
  FD_TEST( bank );

  verify_feature_activated( mini, bank_idx, &test_rent_feature_gates[1], bank->f.slot );
  verify_rent( mini, bank_idx, test_rent_feature_gates[1].lamports_per_byte );
}

static void
test_safeguard_override( fd_svm_mini_t * mini ) {
  ulong root_idx = reset_test_env( mini );
  add_pending_feature( mini, &test_rent_feature_gates[4] ); /* 696 */
  add_pending_feature( mini, &test_rent_feature_gates[5] ); /* 6960 */

  ulong bank_idx = advance_to_next_epoch_boundary( mini, root_idx );
  fd_bank_t * bank = fd_svm_mini_bank( mini, bank_idx );
  FD_TEST( bank );

  verify_feature_activated( mini, bank_idx, &test_rent_feature_gates[4], bank->f.slot );
  verify_feature_activated( mini, bank_idx, &test_rent_feature_gates[5], bank->f.slot );
  verify_rent( mini, bank_idx, test_rent_feature_gates[5].lamports_per_byte );
}

int
main( int     argc,
      char ** argv ) {
  fd_svm_mini_limits_t limits[1];
  fd_svm_mini_limits_default( limits );
  fd_svm_mini_t * mini = fd_svm_test_boot( &argc, &argv, limits );

  test_single_feature_activations( mini );
  test_same_epoch_reduction_ordering( mini );
  test_out_of_order_activation( mini );
  test_safeguard_override( mini );

  FD_LOG_NOTICE(( "pass" ));
  fd_svm_test_halt( mini );
  return 0;
}
