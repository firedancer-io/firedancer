/* Test priority fee settlement edge cases (gh issue #7793).

   Exercises the following scenarios in fd_runtime_settle_fees:
   - Block had no transactions (no fees)
   - Fee collector / leader does not exist
   - PF payout is too low to pass rent exemption threshold
   - Fee collector not owned by system program */

#include "fd_svm_mini.h"
#include "../fd_system_ids.h"
#include "../../leaders/fd_leaders.h"
#include "../sysvar/fd_sysvar_rent.h"
#include "../sysvar/fd_sysvar_epoch_schedule.h"
#include "../../stakes/fd_collector_overrides.h"
#include "../program/fd_vote_program.h"

/* Read the lamport balance of an account at a given fork.
   Returns 0 if the account does not exist. */

static ulong
read_lamports( fd_svm_mini_t *        mini,
               fd_accdb_fork_id_t     fork_id,
               fd_pubkey_t const *    pubkey ) {
  ulong l = fd_accdb_lamports( mini->runtime->accdb, fork_id, pubkey->key );
  return l==ULONG_MAX ? 0UL : l;
}

/* Helper: look up the leader pubkey for a given bank. */

static fd_pubkey_t const *
get_leader( fd_bank_t * bank ) {
  fd_epoch_leaders_t const * leaders = fd_bank_epoch_leaders_query( bank, bank->f.epoch );
  FD_TEST( leaders );
  fd_pubkey_t const * leader = fd_epoch_leaders_get( leaders, bank->f.slot );
  FD_TEST( leader );
  return leader;
}

/* Test: block with no transactions (no fees collected).
   After freeze, the leader balance should not change. */

static void
test_no_fees( fd_svm_mini_t * mini ) {
  fd_svm_mini_params_t params[1];
  fd_svm_mini_params_default( params );
  ulong root_idx = fd_svm_mini_reset( mini, params );

  ulong child_slot = 2UL;
  ulong child_idx  = fd_svm_mini_attach_child( mini, root_idx, child_slot );
  fd_bank_t *        bank    = fd_svm_mini_bank   ( mini, child_idx );
  fd_accdb_fork_id_t fork_id = fd_svm_mini_fork_id( mini, child_idx );

  /* Verify no fees accumulated */
  FD_TEST( bank->f.execution_fees == 0UL );
  FD_TEST( bank->f.priority_fees  == 0UL );

  /* Record pre-freeze state */
  fd_pubkey_t const * leader = get_leader( bank );
  ulong cap_before = bank->f.capitalization;
  ulong bal_before = read_lamports( mini, fork_id, leader );

  fd_svm_mini_freeze( mini, child_idx );

  /* Leader balance unchanged, capitalization unchanged */
  ulong bal_after = read_lamports( mini, fork_id, leader );
  FD_TEST( bal_after == bal_before );
  FD_TEST( bank->f.capitalization == cap_before );

  FD_LOG_NOTICE(( "test_no_fees: PASSED" ));
}

/* Test: fees credited to leader when leader account exists and is
   owned by system program (the happy path). */

static void
test_fees_credited_to_leader( fd_svm_mini_t * mini ) {
  fd_svm_mini_params_t params[1];
  fd_svm_mini_params_default( params );
  ulong root_idx = fd_svm_mini_reset( mini, params );

  ulong child_slot = 2UL;
  ulong child_idx  = fd_svm_mini_attach_child( mini, root_idx, child_slot );
  fd_bank_t *        bank    = fd_svm_mini_bank   ( mini, child_idx );
  fd_accdb_fork_id_t fork_id = fd_svm_mini_fork_id( mini, child_idx );

  fd_pubkey_t const * leader = get_leader( bank );

  /* Ensure leader has enough lamports to be rent-exempt after payout */
  fd_svm_mini_add_lamports( mini, fork_id, leader, 1000000000UL /* 1 SOL */ );

  /* Set fees */
  ulong exec_fees = 10000UL;
  ulong prio_fees = 5000UL;
  bank->f.execution_fees = exec_fees;
  bank->f.priority_fees  = prio_fees;

  ulong bal_before = read_lamports( mini, fork_id, leader );
  ulong cap_before = bank->f.capitalization;

  fd_svm_mini_freeze( mini, child_idx );

  ulong burn     = exec_fees / 2;
  ulong credited = prio_fees + (exec_fees - burn);

  ulong bal_after = read_lamports( mini, fork_id, leader );
  FD_TEST( bal_after == bal_before + credited );
  FD_TEST( bank->f.capitalization == cap_before - burn );

  FD_LOG_NOTICE(( "test_fees_credited_to_leader: PASSED" ));
}

/* Test: leader account does not exist prior to freeze.
   fd_runtime_settle_fees creates the account with FD_ACCDB_FLAG_CREATE.
   If the payout is sufficient for rent exemption, the leader should
   receive the fees. */

static void
test_leader_does_not_exist( fd_svm_mini_t * mini ) {
  fd_svm_mini_params_t params[1];
  fd_svm_mini_params_default( params );
  /* Use 0 mock validators so the leader account is NOT pre-funded */
  params->mock_validator_cnt = 0UL;
  ulong root_idx = fd_svm_mini_reset( mini, params );

  ulong child_slot = 2UL;
  ulong child_idx  = fd_svm_mini_attach_child( mini, root_idx, child_slot );
  fd_bank_t *        bank    = fd_svm_mini_bank   ( mini, child_idx );
  fd_accdb_fork_id_t fork_id = fd_svm_mini_fork_id( mini, child_idx );

  /* We need a leader schedule even with 0 mock validators.
     Create one manually. */
  fd_pubkey_t leader_key = { .ul[0] = 0xDEADUL };

  fd_vote_stake_weight_t stake = {
    .vote_key = leader_key,
    .id_key   = leader_key,
    .stake    = 1000000000UL,
  };
  ulong epoch    = bank->f.epoch;
  ulong slot0    = fd_epoch_slot0( &bank->f.epoch_schedule, epoch );
  ulong slot_cnt = bank->f.epoch_schedule.slots_per_epoch;
  void * leaders_mem = fd_bank_epoch_leaders_modify( bank, epoch );
  FD_TEST( fd_epoch_leaders_join( fd_epoch_leaders_new(
      leaders_mem, epoch, slot0, slot_cnt, 1UL, &stake ) ) );

  /* Verify the leader account does NOT exist */
  FD_TEST( read_lamports( mini, fork_id, &leader_key ) == 0UL );

  /* Set fees high enough to pass rent exemption for a 0-data account */
  ulong minbal = fd_rent_exempt_minimum_balance( &bank->f.rent, 0UL );
  /* total credited = priority_fees + (execution_fees - execution_fees/2)
     We want credited >= minbal.  Set priority_fees = minbal. */
  bank->f.execution_fees = 0UL;
  bank->f.priority_fees  = minbal;

  ulong cap_before = bank->f.capitalization;

  fd_svm_mini_freeze( mini, child_idx );

  /* Leader should now exist with minbal lamports */
  ulong bal_after = read_lamports( mini, fork_id, &leader_key );
  FD_TEST( bal_after == minbal );
  /* No burn (execution_fees == 0) */
  FD_TEST( bank->f.capitalization == cap_before );

  FD_LOG_NOTICE(( "test_leader_does_not_exist: PASSED" ));
}

/* Test: PF payout too low to make the leader rent-exempt.
   When the leader starts with 0 lamports and the fee is less than
   the rent-exempt minimum, the fee should be burned instead. */

static void
test_payout_below_rent_exempt( fd_svm_mini_t * mini ) {
  fd_svm_mini_params_t params[1];
  fd_svm_mini_params_default( params );
  params->mock_validator_cnt = 0UL;
  ulong root_idx = fd_svm_mini_reset( mini, params );

  ulong child_slot = 2UL;
  ulong child_idx  = fd_svm_mini_attach_child( mini, root_idx, child_slot );
  fd_bank_t *        bank    = fd_svm_mini_bank   ( mini, child_idx );
  fd_accdb_fork_id_t fork_id = fd_svm_mini_fork_id( mini, child_idx );

  /* Set up leader schedule */
  fd_pubkey_t leader_key = { .ul[0] = 0xBEEFUL };

  fd_vote_stake_weight_t stake = {
    .vote_key = leader_key,
    .id_key   = leader_key,
    .stake    = 1000000000UL,
  };
  ulong  epoch       = bank->f.epoch;
  ulong  slot0       = fd_epoch_slot0( &bank->f.epoch_schedule, epoch );
  ulong  slot_cnt    = bank->f.epoch_schedule.slots_per_epoch;
  void * leaders_mem = fd_bank_epoch_leaders_modify( bank, epoch );
  FD_TEST( fd_epoch_leaders_join( fd_epoch_leaders_new(
      leaders_mem, epoch, slot0, slot_cnt, 1UL, &stake ) ) );

  /* Leader does not exist => starts with 0 lamports.
     Set fees to 1 lamport, well below rent-exempt threshold. */
  bank->f.execution_fees = 0UL;
  bank->f.priority_fees  = 1UL;

  ulong cap_before = bank->f.capitalization;

  fd_svm_mini_freeze( mini, child_idx );

  /* Leader should NOT receive the fee (validation fails => burn) */
  ulong bal_after = read_lamports( mini, fork_id, &leader_key );
  FD_TEST( bal_after == 0UL );
  /* All fees burned */
  FD_TEST( bank->f.capitalization == cap_before - 1UL );

  FD_LOG_NOTICE(( "test_payout_below_rent_exempt: PASSED" ));
}

/* Test: fee collector owned by a non-system program.
   When the leader account is owned by e.g. the vote program instead
   of the system program, fee settlement should burn the fees. */

static void
test_leader_not_system_owned( fd_svm_mini_t * mini ) {
  fd_svm_mini_params_t params[1];
  fd_svm_mini_params_default( params );
  params->mock_validator_cnt = 0UL;
  ulong root_idx = fd_svm_mini_reset( mini, params );

  ulong child_slot = 2UL;
  ulong child_idx  = fd_svm_mini_attach_child( mini, root_idx, child_slot );
  fd_bank_t *        bank    = fd_svm_mini_bank   ( mini, child_idx );
  fd_accdb_fork_id_t fork_id = fd_svm_mini_fork_id( mini, child_idx );

  /* Set up leader schedule */
  fd_pubkey_t leader_key = { .ul[0] = 0xCAFEUL };

  fd_vote_stake_weight_t stake = {
    .vote_key = leader_key,
    .id_key   = leader_key,
    .stake    = 1000000000UL,
  };
  ulong epoch    = bank->f.epoch;
  ulong slot0    = fd_epoch_slot0( &bank->f.epoch_schedule, epoch );
  ulong slot_cnt = bank->f.epoch_schedule.slots_per_epoch;
  void * leaders_mem = fd_bank_epoch_leaders_modify( bank, epoch );
  FD_TEST( fd_epoch_leaders_join( fd_epoch_leaders_new(
      leaders_mem, epoch, slot0, slot_cnt, 1UL, &stake ) ) );

  /* Create the leader account owned by the vote program (not system) */
  {
    fd_accdb_t * accdb = mini->runtime->accdb;
    fd_acc_t acc = fd_accdb_write_one( accdb, fork_id, leader_key.uc );
    acc.lamports = 1000000000UL;  /* plenty for rent exemption */
    fd_memcpy( acc.owner, fd_solana_vote_program_id.uc, 32UL );
    acc.commit = 1;
    fd_accdb_unwrite_one( accdb, &acc );
  }

  /* Set fees */
  ulong prio_fees = 50000UL;
  bank->f.execution_fees = 0UL;
  bank->f.priority_fees  = prio_fees;

  ulong bal_before = read_lamports( mini, fork_id, &leader_key );
  ulong cap_before = bank->f.capitalization;

  fd_svm_mini_freeze( mini, child_idx );

  /* Leader balance should NOT increase (fees burned) */
  ulong bal_after = read_lamports( mini, fork_id, &leader_key );
  FD_TEST( bal_after == bal_before );
  /* All fees burned */
  FD_TEST( bank->f.capitalization == cap_before - prio_fees );

  FD_LOG_NOTICE(( "test_leader_not_system_owned: PASSED" ));
}

/**********************************************************************/
/* SIMD-0232: block revenue collectors                                */
/**********************************************************************/

/* Common setup: one mock validator, feature active, a child bank
   with fees accrued, and optionally a block revenue collector
   override for the leader's vote account (tag epoch-1). */

static ulong
setup_simd0232_fee_block( fd_svm_mini_t *     mini,
                          fd_pubkey_t const * block_collector_opt,
                          ulong               execution_fees,
                          ulong               priority_fees,
                          ulong *             root_idx_out ) {
  fd_svm_mini_params_t params[1];
  fd_svm_mini_params_default( params );
  ulong root_idx = fd_svm_mini_reset( mini, params );
  *root_idx_out  = root_idx;

  fd_bank_t * root_bank = fd_svm_mini_bank( mini, root_idx );
  FD_FEATURE_SET_ACTIVE( &root_bank->f.features, custom_commission_collector, 0UL );

  ulong child_idx = fd_svm_mini_attach_child( mini, root_idx, 2UL );
  fd_bank_t * bank = fd_svm_mini_bank( mini, child_idx );

  if( block_collector_opt ) {
    fd_epoch_leaders_t const * leaders     = fd_bank_epoch_leaders_query( bank, bank->f.epoch );
    fd_pubkey_t const *        leader_vote = fd_epoch_leaders_get_vote( leaders, bank->f.slot );
    FD_TEST( leader_vote );
    fd_collector_overrides_upsert( fd_bank_collector_overrides( bank ),
                                   bank->collector_overrides_fork_id,
                                   fd_ulong_sat_sub( bank->f.epoch, 1UL ),
                                   leader_vote,
                                   0, NULL,
                                   1, block_collector_opt );
  }

  bank->f.execution_fees = execution_fees;
  bank->f.priority_fees  = priority_fees;
  return child_idx;
}

/* fee_reward = priority + (execution - execution/2) */
#define SIMD0232_FEE_EXECUTION (2000000UL)
#define SIMD0232_FEE_PRIORITY  ( 500000UL)
#define SIMD0232_FEE_REWARD    (1500000UL)

/* Feature on, no override: fees go to the leader identity (the
   default block revenue collector). */
static void
test_simd0232_fee_default_collector( fd_svm_mini_t * mini ) {
  ulong root_idx;
  ulong child_idx = setup_simd0232_fee_block( mini, NULL, SIMD0232_FEE_EXECUTION, SIMD0232_FEE_PRIORITY, &root_idx );
  fd_bank_t *        bank    = fd_svm_mini_bank   ( mini, child_idx );
  fd_accdb_fork_id_t fork_id = fd_svm_mini_fork_id( mini, child_idx );

  fd_pubkey_t const * leader = get_leader( bank );
  fd_svm_mini_add_lamports( mini, fork_id, leader, 1000000000UL );
  ulong bal_before = read_lamports( mini, fork_id, leader );

  fd_svm_mini_freeze( mini, child_idx );
  FD_TEST( read_lamports( mini, fork_id, leader )==bal_before+SIMD0232_FEE_REWARD );

  FD_LOG_NOTICE(( "test_simd0232_fee_default_collector: PASSED" ));
}

/* Override to a rent-exempt system account: fees are routed there and
   the leader identity gets nothing. */
static void
test_simd0232_fee_custom_collector( fd_svm_mini_t * mini ) {
  fd_pubkey_t collector; memset( collector.uc, 0xF1, 32UL );

  ulong root_idx;
  ulong child_idx = setup_simd0232_fee_block( mini, &collector, SIMD0232_FEE_EXECUTION, SIMD0232_FEE_PRIORITY, &root_idx );
  fd_bank_t *        bank    = fd_svm_mini_bank   ( mini, child_idx );
  fd_accdb_fork_id_t fork_id = fd_svm_mini_fork_id( mini, child_idx );

  ulong min_bal = fd_rent_exempt_minimum_balance( &bank->f.rent, 0UL );
  fd_svm_mini_add_lamports( mini, fork_id, &collector, min_bal );

  fd_pubkey_t const * leader = get_leader( bank );
  fd_svm_mini_add_lamports( mini, fork_id, leader, 1000000000UL );
  ulong leader_before = read_lamports( mini, fork_id, leader );

  fd_svm_mini_freeze( mini, child_idx );

  FD_TEST( read_lamports( mini, fork_id, &collector )==min_bal+SIMD0232_FEE_REWARD );
  FD_TEST( read_lamports( mini, fork_id, leader )==leader_before );

  FD_LOG_NOTICE(( "test_simd0232_fee_custom_collector: PASSED" ));
}

/* Override to a missing account: created when the fee covers rent
   exemption, burned when it falls short. */
static void
test_simd0232_fee_collector_rent_exemption( fd_svm_mini_t * mini ) {
  fd_bank_t * probe = fd_banks_root( mini->banks );
  ulong min_bal = fd_rent_exempt_minimum_balance( &probe->f.rent, 0UL );
  FD_TEST( SIMD0232_FEE_REWARD>=min_bal ); /* setup assumption */

  {
    fd_pubkey_t collector; memset( collector.uc, 0xF2, 32UL );
    ulong root_idx;
    ulong child_idx = setup_simd0232_fee_block( mini, &collector, SIMD0232_FEE_EXECUTION, SIMD0232_FEE_PRIORITY, &root_idx );
    fd_accdb_fork_id_t fork_id = fd_svm_mini_fork_id( mini, child_idx );
    fd_svm_mini_freeze( mini, child_idx );
    FD_TEST( read_lamports( mini, fork_id, &collector )==SIMD0232_FEE_REWARD );
  }

  {
    fd_pubkey_t collector; memset( collector.uc, 0xF3, 32UL );
    ulong root_idx;
    ulong child_idx = setup_simd0232_fee_block( mini, &collector, 100UL, 100UL, &root_idx );
    fd_bank_t *        bank    = fd_svm_mini_bank   ( mini, child_idx );
    fd_accdb_fork_id_t fork_id = fd_svm_mini_fork_id( mini, child_idx );
    fd_pubkey_t const * leader = get_leader( bank );
    ulong leader_before = read_lamports( mini, fork_id, leader );
    fd_svm_mini_freeze( mini, child_idx );
    FD_TEST( read_lamports( mini, fork_id, &collector )==0UL );
    FD_TEST( read_lamports( mini, fork_id, leader )==leader_before );
  }

  FD_LOG_NOTICE(( "test_simd0232_fee_collector_rent_exemption: PASSED" ));
}

/* Override to the leader's own vote account: valid collector even
   though it is vote-program-owned (bypasses the external collector
   checks). */
static void
test_simd0232_fee_vote_account_collector( fd_svm_mini_t * mini ) {
  fd_svm_mini_params_t params[1];
  fd_svm_mini_params_default( params );
  ulong root_idx = fd_svm_mini_reset( mini, params );
  fd_bank_t * root_bank = fd_svm_mini_bank( mini, root_idx );
  FD_FEATURE_SET_ACTIVE( &root_bank->f.features, custom_commission_collector, 0UL );

  ulong child_idx = fd_svm_mini_attach_child( mini, root_idx, 2UL );
  fd_bank_t *        bank    = fd_svm_mini_bank   ( mini, child_idx );
  fd_accdb_fork_id_t fork_id = fd_svm_mini_fork_id( mini, child_idx );

  fd_epoch_leaders_t const * leaders     = fd_bank_epoch_leaders_query( bank, bank->f.epoch );
  fd_pubkey_t const *        leader_vote = fd_epoch_leaders_get_vote( leaders, bank->f.slot );
  FD_TEST( leader_vote );
  fd_pubkey_t vote_key = *leader_vote;

  fd_collector_overrides_upsert( fd_bank_collector_overrides( bank ),
                                 bank->collector_overrides_fork_id,
                                 fd_ulong_sat_sub( bank->f.epoch, 1UL ),
                                 &vote_key,
                                 0, NULL,
                                 1, &vote_key );

  bank->f.execution_fees = SIMD0232_FEE_EXECUTION;
  bank->f.priority_fees  = SIMD0232_FEE_PRIORITY;

  fd_pubkey_t const * leader = get_leader( bank );
  ulong vote_before   = read_lamports( mini, fork_id, &vote_key );
  ulong leader_before = read_lamports( mini, fork_id, leader );
  FD_TEST( vote_before>0UL ); /* mock vote account exists (vote program owned) */

  fd_svm_mini_freeze( mini, child_idx );

  FD_TEST( read_lamports( mini, fork_id, &vote_key )==vote_before+SIMD0232_FEE_REWARD );
  FD_TEST( read_lamports( mini, fork_id, leader )==leader_before );

  FD_LOG_NOTICE(( "test_simd0232_fee_vote_account_collector: PASSED" ));
}

/* Override to a non-system-owned account: burned. */
static void
test_simd0232_fee_invalid_owner_burns( fd_svm_mini_t * mini ) {
  fd_pubkey_t collector; memset( collector.uc, 0xF4, 32UL );

  ulong root_idx;
  ulong child_idx = setup_simd0232_fee_block( mini, &collector, SIMD0232_FEE_EXECUTION, SIMD0232_FEE_PRIORITY, &root_idx );
  fd_bank_t *        bank    = fd_svm_mini_bank   ( mini, child_idx );
  fd_accdb_fork_id_t fork_id = fd_svm_mini_fork_id( mini, child_idx );

  fd_pubkey_t bad_owner; memset( bad_owner.uc, 0x99, 32UL );
  uchar no_data[1] = {0};
  fd_acc_t bad = {0};
  memcpy( bad.pubkey, collector.uc, 32 );
  memcpy( bad.owner, bad_owner.uc, 32 );
  bad.lamports = 1000000000UL;
  bad.data_len = 0UL;
  bad.data     = no_data;
  fd_svm_mini_put_account_rooted( mini, &bad );

  fd_pubkey_t const * leader = get_leader( bank );
  ulong leader_before = read_lamports( mini, fork_id, leader );

  fd_svm_mini_freeze( mini, child_idx );

  FD_TEST( read_lamports( mini, fork_id, &collector )==1000000000UL );
  FD_TEST( read_lamports( mini, fork_id, leader )==leader_before );

  FD_LOG_NOTICE(( "test_simd0232_fee_invalid_owner_burns: PASSED" ));
}

/* Override to a reserved account: burned. */
static void
test_simd0232_fee_reserved_collector_burns( fd_svm_mini_t * mini ) {
  fd_pubkey_t collector = fd_sysvar_clock_id;
  FD_TEST( fd_pubkey_is_active_reserved_key( &collector ) ||
           fd_pubkey_is_pending_reserved_key( &collector ) );

  ulong root_idx;
  ulong child_idx = setup_simd0232_fee_block( mini, &collector, SIMD0232_FEE_EXECUTION, SIMD0232_FEE_PRIORITY, &root_idx );
  fd_bank_t *        bank    = fd_svm_mini_bank   ( mini, child_idx );
  fd_accdb_fork_id_t fork_id = fd_svm_mini_fork_id( mini, child_idx );

  fd_pubkey_t const * leader = get_leader( bank );
  ulong coll_before   = read_lamports( mini, fork_id, &collector );
  ulong leader_before = read_lamports( mini, fork_id, leader );

  fd_svm_mini_freeze( mini, child_idx );

  FD_TEST( read_lamports( mini, fork_id, &collector )==coll_before );
  FD_TEST( read_lamports( mini, fork_id, leader )==leader_before );

  FD_LOG_NOTICE(( "test_simd0232_fee_reserved_collector_burns: PASSED" ));
}

/* Override to the incinerator: the deposit always succeeds (no rent
   check) and the incinerator is cleared at the end of the block. */
static void
test_simd0232_fee_incinerator_collector( fd_svm_mini_t * mini ) {
  fd_pubkey_t collector = fd_sysvar_incinerator_id;

  ulong root_idx;
  ulong child_idx = setup_simd0232_fee_block( mini, &collector, SIMD0232_FEE_EXECUTION, SIMD0232_FEE_PRIORITY, &root_idx );
  fd_bank_t *        bank    = fd_svm_mini_bank   ( mini, child_idx );
  fd_accdb_fork_id_t fork_id = fd_svm_mini_fork_id( mini, child_idx );

  fd_pubkey_t const * leader = get_leader( bank );
  ulong leader_before = read_lamports( mini, fork_id, leader );
  ulong cap_before    = bank->f.capitalization;

  fd_svm_mini_freeze( mini, child_idx );

  FD_TEST( read_lamports( mini, fork_id, &collector )==0UL );
  FD_TEST( read_lamports( mini, fork_id, leader )==leader_before );
  /* burn portion + incinerated reward both leave capitalization */
  FD_TEST( bank->f.capitalization==cap_before - SIMD0232_FEE_EXECUTION - SIMD0232_FEE_PRIORITY );

  FD_LOG_NOTICE(( "test_simd0232_fee_incinerator_collector: PASSED" ));
}

/* End-to-end: the collector override is captured from the vote
   account state at an epoch boundary, carried through leader schedule
   derivation, and consumed by fee settlement two epochs later.  No
   override is inserted manually. */
static void
test_simd0232_fee_capture_chain( fd_svm_mini_t * mini ) {
  fd_svm_mini_params_t params[1];
  fd_svm_mini_params_default( params );
  params->slots_per_epoch    = FD_EPOCH_LEN_MIN;
  params->root_slot          = 1UL;
  params->mock_validator_cnt = 1UL;
  ulong root_idx = fd_svm_mini_reset( mini, params );

  fd_bank_t * root_bank = fd_svm_mini_bank( mini, root_idx );
  FD_FEATURE_SET_ACTIVE( &root_bank->f.features, custom_commission_collector, 0UL );

  /* Feature account so the activation survives fd_features_restore at
     the boundaries. */
  {
    fd_pubkey_t feature_id[1];
    FD_TEST( fd_base58_decode_32( "3HcSrCTGXTUnrTueHi4DAwNuMxZSsm5xui2Ax3mgxHqf", feature_id->uc ) );
    uchar data[9] = {0};
    data[0] = 1;
    fd_acc_t acc = {0};
    memcpy( acc.pubkey, feature_id->uc, 32 );
    memcpy( acc.owner, fd_solana_feature_program_id.uc, 32 );
    acc.lamports = 1000000UL;
    acc.data_len = sizeof(data);
    acc.data     = data;
    fd_svm_mini_put_account_rooted( mini, &acc );
  }

  /* Rewrite the mock validator's vote account as a V4 state with a
     custom block revenue collector. */
  fd_pubkey_t identity_key, vote_key, stake_key;
  {
    fd_rng_t rng[1];
    fd_rng_join( fd_rng_new( rng, (uint)params->hash_seed, 0UL ) );
    for( ulong j=0UL; j<4UL; j++ ) identity_key.ul[j] = fd_rng_ulong( rng );
    for( ulong j=0UL; j<4UL; j++ ) vote_key.ul[j]     = fd_rng_ulong( rng );
    for( ulong j=0UL; j<4UL; j++ ) stake_key.ul[j]    = fd_rng_ulong( rng );
    (void)stake_key;
    fd_rng_delete( fd_rng_leave( rng ) );
  }
  fd_pubkey_t collector; memset( collector.uc, 0xF5, 32UL );

  {
    uchar data[ FD_VOTE_STATE_V4_SZ ] = {0};
    ulong o = 0UL;
    FD_STORE( uint, data+o, 3U ); o += 4UL;
    memcpy( data+o, identity_key.uc, 32UL ); o += 32UL; /* node_pubkey */
    memcpy( data+o, identity_key.uc, 32UL ); o += 32UL; /* authorized_withdrawer */
    memcpy( data+o, vote_key.uc, 32UL ); o += 32UL;     /* inflation collector (default) */
    memcpy( data+o, collector.uc, 32UL ); o += 32UL;    /* block revenue collector */
    FD_STORE( ushort, data+o, (ushort)0 ); o += 2UL;
    FD_STORE( ushort, data+o, (ushort)0 ); o += 2UL;
    FD_STORE( ulong, data+o, 0UL ); o += 8UL;
    data[ o++ ] = 1;
    memset( data+o, 0xBB, FD_BLS_PUBKEY_COMPRESSED_SZ );
    o += FD_BLS_PUBKEY_COMPRESSED_SZ;
    FD_STORE( ulong, data+o, 0UL ); o += 8UL;
    data[ o++ ] = 0;
    FD_STORE( ulong, data+o, 0UL ); o += 8UL;
    FD_STORE( ulong, data+o, 1UL ); o += 8UL;           /* 1 epoch credits entry */
    FD_STORE( ulong, data+o, 0UL ); o += 8UL;
    FD_STORE( ulong, data+o, 2UL ); o += 8UL;
    FD_STORE( ulong, data+o, 0UL ); o += 8UL;

    fd_accdb_fork_id_t root_fk = fd_svm_mini_fork_id( mini, root_idx );
    fd_acc_t old = fd_accdb_read_one( mini->runtime->accdb, root_fk, vote_key.key );
    FD_TEST( old.lamports>0UL );
    ulong lamports = old.lamports;
    uchar owner[32]; memcpy( owner, old.owner, 32 );
    fd_accdb_unread_one( mini->runtime->accdb, &old );

    fd_acc_t acc = {0};
    memcpy( acc.pubkey, vote_key.key, 32 );
    memcpy( acc.owner, owner, 32 );
    acc.lamports = lamports;
    acc.data_len = FD_VOTE_STATE_V4_SZ;
    acc.data     = data;
    fd_svm_mini_put_account_rooted( mini, &acc );
  }

  /* Pre-fund the collector so the deposit is rent-exempt. */
  fd_bank_t * probe = fd_banks_root( mini->banks );
  ulong min_bal = fd_rent_exempt_minimum_balance( &probe->f.rent, 0UL );
  fd_svm_mini_add_lamports_rooted( mini, &collector, min_bal );

  /* Cross into epoch 1 (capture) and epoch 2 (schedule derived from
     the captured state). */
  ulong e1_idx = fd_svm_mini_attach_child( mini, root_idx, FD_EPOCH_LEN_MIN );
  fd_svm_mini_freeze( mini, e1_idx );
  ulong e2_idx = fd_svm_mini_attach_child( mini, e1_idx, 2UL*FD_EPOCH_LEN_MIN );
  fd_svm_mini_freeze( mini, e2_idx );

  /* Settle fees in epoch 2. */
  ulong fee_idx = fd_svm_mini_attach_child( mini, e2_idx, 2UL*FD_EPOCH_LEN_MIN+1UL );
  fd_bank_t *        bank    = fd_svm_mini_bank   ( mini, fee_idx );
  fd_accdb_fork_id_t fork_id = fd_svm_mini_fork_id( mini, fee_idx );
  FD_TEST( bank->f.epoch==2UL );

  bank->f.execution_fees = SIMD0232_FEE_EXECUTION;
  bank->f.priority_fees  = SIMD0232_FEE_PRIORITY;

  ulong coll_before = read_lamports( mini, fork_id, &collector );
  ulong id_before   = read_lamports( mini, fork_id, &identity_key );

  fd_svm_mini_freeze( mini, fee_idx );

  FD_TEST( read_lamports( mini, fork_id, &collector )==coll_before+SIMD0232_FEE_REWARD );
  FD_TEST( read_lamports( mini, fork_id, &identity_key )==id_before );

  FD_LOG_NOTICE(( "test_simd0232_fee_capture_chain: PASSED" ));
}

/* Sets up a single-key leader schedule for the bank's epoch. */
static void
make_leader_schedule( fd_bank_t * bank, fd_pubkey_t const * leader_key ) {
  fd_vote_stake_weight_t stake = {
    .vote_key = *leader_key,
    .id_key   = *leader_key,
    .stake    = 1000000000UL,
  };
  ulong  epoch       = bank->f.epoch;
  ulong  slot0       = fd_epoch_slot0( &bank->f.epoch_schedule, epoch );
  ulong  slot_cnt    = bank->f.epoch_schedule.slots_per_epoch;
  void * leaders_mem = fd_bank_epoch_leaders_modify( bank, epoch );
  FD_TEST( fd_epoch_leaders_join( fd_epoch_leaders_new(
      leaders_mem, epoch, slot0, slot_cnt, 1UL, &stake ) ) );
}

/* relax_post_exec_min_balance_check matrix on the pre-feature fee
   path: a rent-paying deposit is credited only when the collector
   pre-exists and the feature is active. */
static void
test_fee_relax_matrix( fd_svm_mini_t * mini ) {
  ulong fee = 100UL; /* well below the rent-exempt minimum */

  for( int relax=0; relax<2; relax++ ) {
    for( int prefunded=0; prefunded<2; prefunded++ ) {
      fd_svm_mini_params_t params[1];
      fd_svm_mini_params_default( params );
      params->mock_validator_cnt = 0UL;
      ulong root_idx = fd_svm_mini_reset( mini, params );

      fd_bank_t * root_bank = fd_svm_mini_bank( mini, root_idx );
      if( relax ) FD_FEATURE_SET_ACTIVE( &root_bank->f.features, relax_post_exec_min_balance_check, 0UL );

      ulong child_idx = fd_svm_mini_attach_child( mini, root_idx, 2UL );
      fd_bank_t *        bank    = fd_svm_mini_bank   ( mini, child_idx );
      fd_accdb_fork_id_t fork_id = fd_svm_mini_fork_id( mini, child_idx );

      fd_pubkey_t leader_key = { .ul[0] = 0xAB00UL + (ulong)(relax*2+prefunded) };
      make_leader_schedule( bank, &leader_key );
      if( prefunded ) fd_svm_mini_add_lamports( mini, fork_id, &leader_key, 1UL );

      bank->f.execution_fees = 0UL;
      bank->f.priority_fees  = fee;
      ulong bal_before = read_lamports( mini, fork_id, &leader_key );
      ulong cap_before = bank->f.capitalization;

      fd_svm_mini_freeze( mini, child_idx );

      int credited = relax && prefunded;
      FD_TEST( read_lamports( mini, fork_id, &leader_key )==bal_before+( credited ? fee : 0UL ) );
      FD_TEST( bank->f.capitalization==cap_before-( credited ? 0UL : fee ) );
    }
  }

  FD_LOG_NOTICE(( "test_fee_relax_matrix: PASSED" ));
}

/* A deposit that would overflow the collector's balance burns on the
   pre-feature fee path. */
static void
test_fee_overflow_burns( fd_svm_mini_t * mini ) {
  fd_svm_mini_params_t params[1];
  fd_svm_mini_params_default( params );
  params->mock_validator_cnt = 0UL;
  ulong root_idx = fd_svm_mini_reset( mini, params );

  ulong child_idx = fd_svm_mini_attach_child( mini, root_idx, 2UL );
  fd_bank_t *        bank    = fd_svm_mini_bank   ( mini, child_idx );
  fd_accdb_fork_id_t fork_id = fd_svm_mini_fork_id( mini, child_idx );

  fd_pubkey_t leader_key = { .ul[0] = 0xFEEDUL };
  make_leader_schedule( bank, &leader_key );

  /* System-owned leader whose balance is one lamport shy of the
     maximum. */
  {
    fd_accdb_t * accdb = mini->runtime->accdb;
    fd_acc_t acc = fd_accdb_write_one( accdb, fork_id, leader_key.uc );
    acc.lamports = ULONG_MAX-1UL;
    acc.commit   = 1;
    fd_accdb_unwrite_one( accdb, &acc );
  }

  ulong prio_fees = 50000UL;
  bank->f.execution_fees = 0UL;
  bank->f.priority_fees  = prio_fees;
  ulong cap_before = bank->f.capitalization;

  fd_svm_mini_freeze( mini, child_idx );

  FD_TEST( read_lamports( mini, fork_id, &leader_key )==ULONG_MAX-1UL );
  FD_TEST( bank->f.capitalization==cap_before-prio_fees );

  FD_LOG_NOTICE(( "test_fee_overflow_burns: PASSED" ));
}

/* Same overflow burn with the feature active and a custom collector. */
static void
test_simd0232_fee_overflow_burns( fd_svm_mini_t * mini ) {
  fd_pubkey_t collector; memset( collector.uc, 0xF6, 32UL );

  ulong root_idx;
  ulong child_idx = setup_simd0232_fee_block( mini, &collector, SIMD0232_FEE_EXECUTION, SIMD0232_FEE_PRIORITY, &root_idx );
  fd_bank_t *        bank    = fd_svm_mini_bank   ( mini, child_idx );
  fd_accdb_fork_id_t fork_id = fd_svm_mini_fork_id( mini, child_idx );

  {
    fd_accdb_t * accdb = mini->runtime->accdb;
    fd_acc_t acc = fd_accdb_write_one( accdb, fork_id, collector.uc );
    acc.lamports = ULONG_MAX-1UL;
    acc.commit   = 1;
    fd_accdb_unwrite_one( accdb, &acc );
  }

  fd_pubkey_t const * leader = get_leader( bank );
  ulong leader_before = read_lamports( mini, fork_id, leader );
  ulong cap_before    = bank->f.capitalization;

  fd_svm_mini_freeze( mini, child_idx );

  FD_TEST( read_lamports( mini, fork_id, &collector )==ULONG_MAX-1UL );
  FD_TEST( read_lamports( mini, fork_id, leader )==leader_before );
  FD_TEST( bank->f.capitalization==cap_before-SIMD0232_FEE_EXECUTION-SIMD0232_FEE_PRIORITY );

  FD_LOG_NOTICE(( "test_simd0232_fee_overflow_burns: PASSED" ));
}

/* With relax_post_exec_min_balance_check active, a pre-existing
   rent-paying custom collector still receives the fee reward. */
static void
test_simd0232_fee_relax_deposit( fd_svm_mini_t * mini ) {
  ulong fee = 100UL; /* below the rent-exempt minimum */

  for( int relax=0; relax<2; relax++ ) {
    fd_svm_mini_params_t params[1];
    fd_svm_mini_params_default( params );
    ulong root_idx = fd_svm_mini_reset( mini, params );

    fd_bank_t * root_bank = fd_svm_mini_bank( mini, root_idx );
    FD_FEATURE_SET_ACTIVE( &root_bank->f.features, custom_commission_collector, 0UL );
    if( relax ) FD_FEATURE_SET_ACTIVE( &root_bank->f.features, relax_post_exec_min_balance_check, 0UL );

    ulong child_idx = fd_svm_mini_attach_child( mini, root_idx, 2UL );
    fd_bank_t *        bank    = fd_svm_mini_bank   ( mini, child_idx );
    fd_accdb_fork_id_t fork_id = fd_svm_mini_fork_id( mini, child_idx );

    fd_pubkey_t collector = { .ul[0] = 0xAC00UL + (ulong)relax };
    fd_epoch_leaders_t const * leaders     = fd_bank_epoch_leaders_query( bank, bank->f.epoch );
    fd_pubkey_t const *        leader_vote = fd_epoch_leaders_get_vote( leaders, bank->f.slot );
    FD_TEST( leader_vote );
    fd_collector_overrides_upsert( fd_bank_collector_overrides( bank ),
                                   bank->collector_overrides_fork_id,
                                   fd_ulong_sat_sub( bank->f.epoch, 1UL ),
                                   leader_vote,
                                   0, NULL,
                                   1, &collector );
    fd_svm_mini_add_lamports( mini, fork_id, &collector, 1UL );

    bank->f.execution_fees = 0UL;
    bank->f.priority_fees  = fee;

    fd_svm_mini_freeze( mini, child_idx );

    FD_TEST( read_lamports( mini, fork_id, &collector )==( relax ? 1UL+fee : 1UL ) );
  }

  FD_LOG_NOTICE(( "test_simd0232_fee_relax_deposit: PASSED" ));
}

/* Every reserved key burns the fee reward when set as the custom
   collector. */
static void
test_simd0232_fee_reserved_sweep( fd_svm_mini_t * mini ) {
  fd_pubkey_t const * reserved[] = {
    /* active */
    &fd_solana_bpf_loader_program_id,
    &fd_solana_bpf_loader_deprecated_program_id,
    &fd_solana_bpf_loader_upgradeable_program_id,
    &fd_solana_config_program_id,
    &fd_solana_feature_program_id,
    &fd_solana_stake_program_config_id,
    &fd_solana_stake_program_id,
    &fd_solana_system_program_id,
    &fd_solana_vote_program_id,
    &fd_sysvar_clock_id,
    &fd_sysvar_epoch_schedule_id,
    &fd_sysvar_fees_id,
    &fd_sysvar_instructions_id,
    &fd_sysvar_recent_block_hashes_id,
    &fd_sysvar_rent_id,
    &fd_sysvar_rewards_id,
    &fd_sysvar_slot_hashes_id,
    &fd_sysvar_slot_history_id,
    &fd_sysvar_stake_history_id,
    &fd_solana_native_loader_id,
    &fd_solana_secp256r1_program_id,
    /* pending */
    &fd_solana_address_lookup_table_program_id,
    &fd_solana_compute_budget_program_id,
    &fd_solana_ed25519_sig_verify_program_id,
    &fd_solana_bpf_loader_v4_program_id,
    &fd_solana_keccak_secp_256k_program_id,
    &fd_solana_zk_elgamal_proof_program_id,
    &fd_solana_zk_token_proof_program_id,
    &fd_sysvar_epoch_rewards_id,
    &fd_sysvar_last_restart_slot_id,
    &fd_sysvar_owner_id,
  };
  ulong reserved_cnt = sizeof(reserved)/sizeof(reserved[0]);
  FD_TEST( reserved_cnt==31UL );

  for( ulong i=0UL; i<reserved_cnt; i++ ) {
    FD_TEST( fd_pubkey_is_active_reserved_key( reserved[i] ) ||
             fd_pubkey_is_pending_reserved_key( reserved[i] ) );

    ulong root_idx;
    ulong child_idx = setup_simd0232_fee_block( mini, reserved[i], SIMD0232_FEE_EXECUTION, SIMD0232_FEE_PRIORITY, &root_idx );
    fd_bank_t *        bank    = fd_svm_mini_bank   ( mini, child_idx );
    fd_accdb_fork_id_t fork_id = fd_svm_mini_fork_id( mini, child_idx );

    fd_pubkey_t const * leader = get_leader( bank );
    ulong coll_before   = read_lamports( mini, fork_id, reserved[i] );
    ulong leader_before = read_lamports( mini, fork_id, leader );
    ulong cap_before    = bank->f.capitalization;

    fd_svm_mini_freeze( mini, child_idx );

    FD_TEST( read_lamports( mini, fork_id, reserved[i] )==coll_before );
    FD_TEST( read_lamports( mini, fork_id, leader )==leader_before );
    FD_TEST( bank->f.capitalization==cap_before-SIMD0232_FEE_EXECUTION-SIMD0232_FEE_PRIORITY );
  }

  FD_LOG_NOTICE(( "test_simd0232_fee_reserved_sweep: PASSED (%lu keys)", reserved_cnt ));
}

int
main( int     argc,
      char ** argv ) {
  fd_svm_mini_limits_t limits[1];
  fd_svm_mini_limits_default( limits );
  fd_svm_mini_t * mini = fd_svm_test_boot( &argc, &argv, limits );

  test_no_fees( mini );
  test_fees_credited_to_leader( mini );
  test_leader_does_not_exist( mini );
  test_payout_below_rent_exempt( mini );
  test_leader_not_system_owned( mini );
  test_fee_relax_matrix( mini );
  test_fee_overflow_burns( mini );

  test_simd0232_fee_default_collector( mini );
  test_simd0232_fee_custom_collector( mini );
  test_simd0232_fee_collector_rent_exemption( mini );
  test_simd0232_fee_vote_account_collector( mini );
  test_simd0232_fee_invalid_owner_burns( mini );
  test_simd0232_fee_reserved_collector_burns( mini );
  test_simd0232_fee_incinerator_collector( mini );
  test_simd0232_fee_overflow_burns( mini );
  test_simd0232_fee_relax_deposit( mini );
  test_simd0232_fee_reserved_sweep( mini );
  test_simd0232_fee_capture_chain( mini );

  FD_LOG_NOTICE(( "pass" ));
  fd_svm_test_halt( mini );
  return 0;
}
