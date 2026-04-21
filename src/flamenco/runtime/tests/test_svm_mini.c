#include "fd_svm_mini.h"
#include "../../accdb/fd_accdb.h"
#include "../../runtime/fd_bank.h"
#include "../../leaders/fd_leaders.h"
#include "../../stakes/fd_vote_stakes.h"

static const fd_pubkey_t test_pubkey  = {{ 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,
                                           17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32 }};
static const fd_pubkey_t test_pubkey2 = {{ 99,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,
                                           17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32 }};

int
main( int     argc,
      char ** argv ) {
  fd_svm_mini_limits_t limits[1];
  fd_svm_mini_limits_default( limits );
  fd_svm_mini_t * mini = fd_svm_test_boot( &argc, &argv, limits );

  FD_TEST( fd_svm_mini_wksp_data_max( limits )>0UL );
  FD_TEST( mini );
  FD_TEST( mini->wksp );
  FD_TEST( mini->banks );
  FD_TEST( mini->runtime );
  FD_TEST( mini->runtime_stack );
  FD_TEST( mini->vm );

  /* fd_svm_mini_destroy( NULL ) is a no-op */
  fd_svm_mini_destroy( NULL );

  /* fd_svm_mini_bank invalid */
  FD_TEST( fd_svm_mini_bank( mini, 9999UL )==NULL );

  /* fd_svm_mini_reset: default params */
  fd_svm_mini_params_t params[1];
  fd_svm_mini_params_default( params );
  ulong root_idx = fd_svm_mini_reset( mini, params );
  fd_bank_t * bank = fd_svm_mini_bank( mini, root_idx );
  FD_TEST( bank );
  FD_TEST( bank->f.slot==1UL );
  FD_TEST( bank->f.epoch_schedule.slots_per_epoch==16UL );
  FD_TEST( bank->f.rent.lamports_per_uint8_year==3480UL );
  FD_TEST( bank->f.rent.burn_percent==50 );

  /* fd_svm_mini_reset: custom epoch_schedule */
  fd_epoch_schedule_t sched = {
    .slots_per_epoch             = 100UL,
    .leader_schedule_slot_offset = 100UL,
    .warmup                      = 0,
    .first_normal_epoch          = 0UL,
    .first_normal_slot           = 0UL,
  };
  params->epoch_schedule = &sched;
  root_idx = fd_svm_mini_reset( mini, params );
  FD_TEST( fd_svm_mini_bank( mini, root_idx )->f.epoch_schedule.slots_per_epoch==100UL );

  /* fd_svm_mini_reset: custom rent */
  params->epoch_schedule = NULL;
  fd_rent_t rent = { .lamports_per_uint8_year = 9999UL, .exemption_threshold = 1.0, .burn_percent = 25 };
  params->rent = &rent;
  root_idx = fd_svm_mini_reset( mini, params );
  FD_TEST( fd_svm_mini_bank( mini, root_idx )->f.rent.lamports_per_uint8_year==9999UL );
  FD_TEST( fd_svm_mini_bank( mini, root_idx )->f.rent.burn_percent==25 );

  /* fd_svm_mini_reset: custom slots_per_epoch (no epoch_schedule ptr) */
  params->rent = NULL;
  params->slots_per_epoch = 200UL;
  root_idx = fd_svm_mini_reset( mini, params );
  FD_TEST( fd_svm_mini_bank( mini, root_idx )->f.epoch_schedule.slots_per_epoch==200UL );
  FD_TEST( fd_svm_mini_bank( mini, root_idx )->f.epoch_schedule.leader_schedule_slot_offset==200UL );

  /* Fork lifecycle: attach_child, cancel_fork, advance_root */
  params->slots_per_epoch = 100UL;
  params->root_slot = 10UL;
  root_idx = fd_svm_mini_reset( mini, params );

  fd_accdb_fork_id_t root_fk = fd_svm_mini_fork_id( mini, root_idx );
  (void)root_fk;

  ulong child_a = fd_svm_mini_attach_child( mini, root_idx, 11UL );
  FD_TEST( fd_svm_mini_bank( mini, child_a )->f.slot==11UL );
  fd_banks_mark_bank_frozen( fd_svm_mini_bank( mini, child_a ) );

  ulong child_b = fd_svm_mini_attach_child( mini, child_a, 12UL );
  FD_TEST( fd_svm_mini_bank( mini, child_b )->f.slot==12UL );

  ulong child_c = fd_svm_mini_attach_child( mini, child_a, 13UL );
  FD_TEST( fd_svm_mini_bank( mini, child_c )->f.slot==13UL );

  fd_banks_mark_bank_frozen( fd_svm_mini_bank( mini, child_c ) );
  fd_svm_mini_cancel_fork( mini, child_c );

  fd_banks_mark_bank_frozen( fd_svm_mini_bank( mini, child_b ) );
  fd_svm_mini_advance_root( mini, child_a );

  /* put_account_rooted + add_lamports_rooted */
  params->root_slot = 0UL;
  root_idx = fd_svm_mini_reset( mini, params );
  root_fk = fd_svm_mini_fork_id( mini, root_idx );
  bank = fd_svm_mini_bank( mini, root_idx );

  ulong cap0 = bank->f.capitalization;

  /* add_lamports_rooted: new account */
  fd_svm_mini_add_lamports_rooted( mini, &test_pubkey, 1000UL );
  FD_TEST( fd_accdb_lamports( mini->runtime->accdb, root_fk, test_pubkey.uc )==1000UL );
  FD_TEST( bank->f.capitalization==cap0+1000UL );

  /* put_account_rooted: overwrite (remove + re-insert) */
  fd_accdb_entry_t tmp_entry = {0};
  memcpy( tmp_entry.pubkey, test_pubkey.uc, 32UL );
  tmp_entry.lamports = 500UL;
  fd_svm_mini_put_account_rooted( mini, &tmp_entry );
  FD_TEST( fd_accdb_lamports( mini->runtime->accdb, root_fk, test_pubkey.uc )==500UL );
  FD_TEST( bank->f.capitalization==cap0+500UL );

  /* put_account_rooted: decrease lamports (capitalization must decrease) */
  tmp_entry.lamports = 200UL;
  fd_svm_mini_put_account_rooted( mini, &tmp_entry );
  FD_TEST( fd_accdb_lamports( mini->runtime->accdb, root_fk, test_pubkey.uc )==200UL );
  FD_TEST( bank->f.capitalization==cap0+200UL );

  /* put_account_rooted: increase lamports back */
  tmp_entry.lamports = 500UL;
  fd_svm_mini_put_account_rooted( mini, &tmp_entry );
  FD_TEST( bank->f.capitalization==cap0+500UL );

  /* add_lamports_rooted: existing account */
  fd_svm_mini_add_lamports_rooted( mini, &test_pubkey, 500UL );
  FD_TEST( fd_accdb_lamports( mini->runtime->accdb, root_fk, test_pubkey.uc )==1000UL );
  FD_TEST( bank->f.capitalization==cap0+1000UL );

  /* add_lamports (non-rooted fork) */
  ulong fork_idx = fd_svm_mini_attach_child( mini, root_idx, 1UL );
  fd_accdb_fork_id_t fork_fk = fd_svm_mini_fork_id( mini, fork_idx );
  fd_bank_t * fork_bank = fd_svm_mini_bank( mini, fork_idx );
  ulong fork_cap0 = fork_bank->f.capitalization;

  fd_svm_mini_add_lamports( mini, fork_fk, &test_pubkey2, 777UL );
  FD_TEST( fd_accdb_lamports( mini->runtime->accdb, fork_fk, test_pubkey2.uc )==777UL );
  FD_TEST( fork_bank->f.capitalization==fork_cap0+777UL );

  fd_svm_mini_add_lamports( mini, fork_fk, &test_pubkey2, 223UL );
  FD_TEST( fd_accdb_lamports( mini->runtime->accdb, fork_fk, test_pubkey2.uc )==1000UL );
  FD_TEST( fork_bank->f.capitalization==fork_cap0+1000UL );

  /* add_lamports on fork must not affect root capitalization */
  FD_TEST( bank->f.capitalization==cap0+1000UL );

  /* mock_validator_cnt=0: no validators, no leader schedule */
  params->mock_validator_cnt = 0UL;
  params->root_slot          = 0UL;
  params->slots_per_epoch    = 16UL;
  root_idx = fd_svm_mini_reset( mini, params );
  bank = fd_svm_mini_bank( mini, root_idx );
  FD_TEST( bank );

  fd_epoch_leaders_t const * leaders = fd_bank_epoch_leaders_query( bank );
  FD_TEST( leaders==NULL );

  fd_vote_stakes_t * vs0 = fd_bank_vote_stakes( bank );
  ushort vs0_root_idx = fd_vote_stakes_get_root_idx( vs0 );
  FD_TEST( fd_vote_stakes_ele_cnt( vs0, vs0_root_idx )==0U );

  /* mock_validator_cnt=1: single validator */
  params->mock_validator_cnt = 1UL;
  root_idx = fd_svm_mini_reset( mini, params );
  bank = fd_svm_mini_bank( mini, root_idx );
  FD_TEST( bank );

  leaders = fd_bank_epoch_leaders_query( bank );
  FD_TEST( leaders );
  FD_TEST( leaders->pub_cnt==1UL );
  FD_TEST( leaders->slot_cnt==bank->f.epoch_schedule.slots_per_epoch );
  FD_TEST( fd_epoch_leaders_get( leaders, leaders->slot0 ) );

  fd_vote_stakes_t * vs1 = fd_bank_vote_stakes( bank );
  ushort vs1_root_idx = fd_vote_stakes_get_root_idx( vs1 );
  FD_TEST( fd_vote_stakes_ele_cnt( vs1, vs1_root_idx )==1U );

  /* mock_validator_cnt=4: multiple validators */
  params->mock_validator_cnt = 4UL;
  root_idx = fd_svm_mini_reset( mini, params );
  bank = fd_svm_mini_bank( mini, root_idx );
  FD_TEST( bank );

  leaders = fd_bank_epoch_leaders_query( bank );
  FD_TEST( leaders );
  FD_TEST( leaders->pub_cnt==4UL );
  FD_TEST( leaders->slot_cnt==bank->f.epoch_schedule.slots_per_epoch );
  for( ulong s=leaders->slot0; s<leaders->slot0+leaders->slot_cnt; s++ ) {
    FD_TEST( fd_epoch_leaders_get( leaders, s ) );
  }

  fd_vote_stakes_t * vs4 = fd_bank_vote_stakes( bank );
  ushort vs4_root_idx = fd_vote_stakes_get_root_idx( vs4 );
  FD_TEST( fd_vote_stakes_ele_cnt( vs4, vs4_root_idx )==4U );

  FD_LOG_NOTICE(( "pass" ));
  fd_svm_test_halt( mini );
  return 0;
}
