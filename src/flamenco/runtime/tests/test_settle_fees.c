/* Test priority fee settlement edge cases (gh issue #7793).

   Exercises the following scenarios in fd_runtime_settle_fees:
   - Block had no transactions (no fees)
   - Fee collector / leader does not exist
   - PF payout is too low to pass rent exemption threshold
   - Fee collector not owned by system program */

#include "fd_svm_mini.h"
#include "../../accdb/fd_accdb_sync.h"
#include "../fd_system_ids.h"
#include "../../leaders/fd_leaders.h"
#include "../sysvar/fd_sysvar_rent.h"
#include "../sysvar/fd_sysvar_epoch_schedule.h"

/* Read the lamport balance of an account at a given xid.
   Returns 0 if the account does not exist. */

static ulong
read_lamports( fd_svm_mini_t *     mini,
               fd_xid_t const *    xid,
               fd_pubkey_t const * pubkey ) {
  fd_accdb_ro_t ro[1];
  if( !fd_accdb_open_ro( mini->accdb, ro, xid, pubkey ) ) return 0UL;
  ulong lamports = fd_accdb_ref_lamports( ro );
  fd_accdb_close_ro( mini->accdb, ro );
  return lamports;
}

/* Helper: look up the leader pubkey for a given bank. */

static fd_pubkey_t const *
get_leader( fd_bank_t * bank ) {
  fd_epoch_leaders_t const * leaders = fd_bank_epoch_leaders_query( bank );
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
  fd_bank_t * bank = fd_svm_mini_bank( mini, child_idx );
  fd_xid_t    xid  = fd_svm_mini_xid( mini, child_idx );

  /* Verify no fees accumulated */
  FD_TEST( bank->f.execution_fees == 0UL );
  FD_TEST( bank->f.priority_fees  == 0UL );

  /* Record pre-freeze state */
  fd_pubkey_t const * leader = get_leader( bank );
  ulong cap_before = bank->f.capitalization;
  ulong bal_before = read_lamports( mini, &xid, leader );

  fd_svm_mini_freeze( mini, child_idx );

  /* Leader balance unchanged, capitalization unchanged */
  ulong bal_after = read_lamports( mini, &xid, leader );
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
  fd_bank_t * bank = fd_svm_mini_bank( mini, child_idx );
  fd_xid_t    xid  = fd_svm_mini_xid( mini, child_idx );

  fd_pubkey_t const * leader = get_leader( bank );

  /* Ensure leader has enough lamports to be rent-exempt after payout */
  fd_svm_mini_add_lamports( mini, &xid, leader, 1000000000UL /* 1 SOL */ );

  /* Set fees */
  ulong exec_fees = 10000UL;
  ulong prio_fees = 5000UL;
  bank->f.execution_fees = exec_fees;
  bank->f.priority_fees  = prio_fees;

  ulong bal_before = read_lamports( mini, &xid, leader );
  ulong cap_before = bank->f.capitalization;

  fd_svm_mini_freeze( mini, child_idx );

  ulong burn     = exec_fees / 2;
  ulong credited = prio_fees + (exec_fees - burn);

  ulong bal_after = read_lamports( mini, &xid, leader );
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
  fd_bank_t * bank = fd_svm_mini_bank( mini, child_idx );
  fd_xid_t    xid  = fd_svm_mini_xid( mini, child_idx );

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
  void * leaders_mem = fd_bank_epoch_leaders_modify( bank );
  FD_TEST( fd_epoch_leaders_join( fd_epoch_leaders_new(
      leaders_mem, epoch, slot0, slot_cnt, 1UL, &stake, 0UL ) ) );

  /* Verify the leader account does NOT exist */
  FD_TEST( read_lamports( mini, &xid, &leader_key ) == 0UL );

  /* Set fees high enough to pass rent exemption for a 0-data account */
  ulong minbal = fd_rent_exempt_minimum_balance( &bank->f.rent, 0UL );
  /* total credited = priority_fees + (execution_fees - execution_fees/2)
     We want credited >= minbal.  Set priority_fees = minbal. */
  bank->f.execution_fees = 0UL;
  bank->f.priority_fees  = minbal;

  ulong cap_before = bank->f.capitalization;

  fd_svm_mini_freeze( mini, child_idx );

  /* Leader should now exist with minbal lamports */
  ulong bal_after = read_lamports( mini, &xid, &leader_key );
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
  fd_bank_t * bank = fd_svm_mini_bank( mini, child_idx );
  fd_xid_t    xid  = fd_svm_mini_xid( mini, child_idx );

  /* Set up leader schedule */
  fd_pubkey_t leader_key = { .ul[0] = 0xBEEFUL };

  fd_vote_stake_weight_t stake = {
    .vote_key = leader_key,
    .id_key   = leader_key,
    .stake    = 1000000000UL,
  };
  ulong epoch    = bank->f.epoch;
  ulong slot0    = fd_epoch_slot0( &bank->f.epoch_schedule, epoch );
  ulong slot_cnt = bank->f.epoch_schedule.slots_per_epoch;
  void * leaders_mem = fd_bank_epoch_leaders_modify( bank );
  FD_TEST( fd_epoch_leaders_join( fd_epoch_leaders_new(
      leaders_mem, epoch, slot0, slot_cnt, 1UL, &stake, 0UL ) ) );

  /* Leader does not exist => starts with 0 lamports.
     Set fees to 1 lamport, well below rent-exempt threshold. */
  bank->f.execution_fees = 0UL;
  bank->f.priority_fees  = 1UL;

  ulong cap_before = bank->f.capitalization;

  fd_svm_mini_freeze( mini, child_idx );

  /* Leader should NOT receive the fee (validation fails => burn) */
  ulong bal_after = read_lamports( mini, &xid, &leader_key );
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
  fd_bank_t * bank = fd_svm_mini_bank( mini, child_idx );
  fd_xid_t    xid  = fd_svm_mini_xid( mini, child_idx );

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
  void * leaders_mem = fd_bank_epoch_leaders_modify( bank );
  FD_TEST( fd_epoch_leaders_join( fd_epoch_leaders_new(
      leaders_mem, epoch, slot0, slot_cnt, 1UL, &stake, 0UL ) ) );

  /* Create the leader account owned by the vote program (not system) */
  {
    fd_accdb_rw_t rw[1];
    FD_TEST( fd_accdb_open_rw( mini->accdb, rw, &xid, &leader_key, 0UL, FD_ACCDB_FLAG_CREATE ) );
    rw->meta->lamports = 1000000000UL;  /* plenty for rent exemption */
    rw->meta->slot     = 1UL;
    memcpy( rw->meta->owner, fd_solana_vote_program_id.uc, 32UL );
    fd_accdb_close_rw( mini->accdb, rw );
  }

  /* Set fees */
  ulong prio_fees = 50000UL;
  bank->f.execution_fees = 0UL;
  bank->f.priority_fees  = prio_fees;

  ulong bal_before = read_lamports( mini, &xid, &leader_key );
  ulong cap_before = bank->f.capitalization;

  fd_svm_mini_freeze( mini, child_idx );

  /* Leader balance should NOT increase (fees burned) */
  ulong bal_after = read_lamports( mini, &xid, &leader_key );
  FD_TEST( bal_after == bal_before );
  /* All fees burned */
  FD_TEST( bank->f.capitalization == cap_before - prio_fees );

  FD_LOG_NOTICE(( "test_leader_not_system_owned: PASSED" ));
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

  FD_LOG_NOTICE(( "pass" ));
  fd_svm_test_halt( mini );
  return 0;
}
