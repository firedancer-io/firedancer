#include "fd_snapmin.h"
#include "../../flamenco/runtime/fd_system_ids.h"
#include "../../flamenco/runtime/tests/fd_svm_mini.h"
#include "../../flamenco/alpenglow/fd_alpenglow.h"
#include "../../flamenco/features/fd_features.h"

#define VALIDATOR_CNT 3UL
#define ROOT_SLOT     1770UL /* epoch 4 with 432 slots/epoch */
#define ELE_MAX       1024UL

#define TEST_WKSP_TAG           43UL
#define TEST_WKSP_ADDL_SZ       (256UL<<20)
#define TEST_WKSP_ADDL_PART_CNT (64UL)

static void
new_set( fd_wksp_t *    wksp,
         fd_snapmin_t * set ) {
  void * mem = fd_wksp_alloc_laddr( wksp, fd_snapmin_align(), fd_snapmin_footprint( ELE_MAX ), TEST_WKSP_TAG );
  FD_TEST( mem );
  FD_TEST( fd_snapmin_new( mem, ELE_MAX, 42UL ) );
  FD_TEST( fd_snapmin_join( set, mem )==set );
}

/* Read the whole set into keys in small batches.  Returns the count. */

static ulong
read_all( fd_snapmin_t * set,
          fd_pubkey_t *  keys ) {
  ulong cursor = 0UL;
  ulong cnt    = 0UL;
  for(;;) {
    ulong n = fd_snapmin_next( set, &cursor, keys+cnt, fd_ulong_min( 7UL, ELE_MAX-cnt ) );
    if( !n ) break;
    cnt += n;
  }
  return cnt;
}

static int
has( fd_pubkey_t const * keys,
     ulong               cnt,
     fd_pubkey_t const * key ) {
  for( ulong i=0UL; i<cnt; i++ ) {
    if( fd_pubkey_eq( &keys[ i ], key ) ) return 1;
  }
  return 0;
}

/* Returns how many of the root stake accounts are in keys. */

static ulong
stake_accounts_kept( fd_svm_mini_t *     mini,
                     fd_pubkey_t const * keys,
                     ulong               cnt ) {
  fd_stake_delegations_t * delegations = fd_banks_stake_delegations_root_query( mini->banks );
  ulong kept = 0UL;
  ulong seen = 0UL;
  fd_stake_delegations_iter_t iter_[1];
  for( fd_stake_delegations_iter_t * iter = fd_stake_delegations_iter_init( iter_, delegations );
       !fd_stake_delegations_iter_done( iter );
       fd_stake_delegations_iter_next( iter ) ) {
    kept += (ulong)has( keys, cnt, &fd_stake_delegations_iter_ele( iter )->stake_account );
    seen++;
  }
  FD_TEST( seen==VALIDATOR_CNT );
  return kept;
}

static void
test_set( fd_wksp_t * wksp ) {
  fd_snapmin_t set[1];
  new_set( wksp, set );

  fd_rng_t rng[1];
  fd_rng_join( fd_rng_new( rng, 7U, 0UL ) );

  /* The system program id is all zero bytes and must count as a key. */
  fd_pubkey_t keys[ 4 ];
  keys[ 0 ] = fd_solana_system_program_id;
  for( ulong i=1UL; i<4UL; i++ ) {
    for( ulong j=0UL; j<4UL; j++ ) keys[ i ].ul[ j ] = fd_rng_ulong( rng );
  }
  for( ulong r=0UL; r<2UL; r++ ) {
    for( ulong i=0UL; i<4UL; i++ ) fd_snapmin_insert( set, keys[ i ].uc );
  }

  fd_pubkey_t out[ ELE_MAX ];
  FD_TEST( read_all( set, out )==4UL );
  for( ulong i=0UL; i<4UL; i++ ) FD_TEST( has( out, 4UL, &keys[ i ] ) );

  fd_rng_delete( fd_rng_leave( rng ) );
}

static void
test_boot_accounts_same_epoch( fd_svm_mini_t * mini,
                               fd_bank_t *     bank ) {
  fd_snapmin_t set[1];
  new_set( mini->wksp, set );
  fd_snapmin_keep_boot_accounts( set, bank, mini->banks, ROOT_SLOT+10UL );

  fd_pubkey_t keys[ ELE_MAX ];
  ulong cnt = read_all( set, keys );

  for( fd_feature_id_t const * id = fd_feature_iter_init();
       !fd_feature_iter_done( id );
       id = fd_feature_iter_next( id ) ) {
    FD_TEST( has( keys, cnt, &id->id ) );
  }

  fd_pubkey_t const * expect[] = {
    &fd_sysvar_clock_id,
    &fd_sysvar_epoch_rewards_id,
    &fd_sysvar_epoch_schedule_id,
    &fd_sysvar_last_restart_slot_id,
    &fd_sysvar_recent_block_hashes_id,
    &fd_sysvar_rent_id,
    &fd_sysvar_slot_hashes_id,
    &fd_sysvar_slot_history_id,
    &fd_sysvar_stake_history_id,
    &fd_sysvar_fees_id,
    &fd_sysvar_instructions_id,
    &fd_sysvar_rewards_id,
    &fd_sysvar_owner_id,
    &fd_sysvar_incinerator_id,
    &fd_solana_system_program_id,
    &fd_solana_bpf_loader_upgradeable_program_id,
    &fd_solana_stake_program_id,
    &fd_solana_address_lookup_table_program_id,
    &fd_solana_feature_program_id,
    &fd_solana_spl_token_id,
  };
  for( ulong i=0UL; i<sizeof(expect)/sizeof(expect[0]); i++ ) FD_TEST( has( keys, cnt, expect[ i ] ) );

  char const * seeds[] = { "carlgration", "alpenclock", "vote_reward_account", "reward_epoch_delegated_stakes" };
  for( ulong i=0UL; i<4UL; i++ ) {
    fd_pubkey_t pda;
    fd_alpenglow_pda( seeds[ i ], &pda );
    FD_TEST( has( keys, cnt, &pda ) );
  }

  fd_vote_stakes_t * vote_stakes = fd_bank_vote_stakes( bank );
  ulong              fork_id     = bank->vote_stakes_fork_id;
  for( int kind=FD_VOTE_STAKES_ITER_T_1; kind<=FD_VOTE_STAKES_ITER_T_2; kind++ ) {
    ulong seen = 0UL;
    uchar iter_mem[ FD_VOTE_STAKES_ITER_FOOTPRINT ] __attribute__((aligned(FD_VOTE_STAKES_ITER_ALIGN)));
    for( fd_vote_stakes_iter_t * iter = fd_vote_stakes_iter_init( vote_stakes, fork_id, kind, iter_mem );
         !fd_vote_stakes_iter_done( vote_stakes, fork_id, kind, iter );
         fd_vote_stakes_iter_next( vote_stakes, fork_id, kind, iter ) ) {
      fd_vote_stakes_ele_t ele[1];
      fd_vote_stakes_iter_ele( vote_stakes, fork_id, kind, iter, ele );
      FD_TEST( has( keys, cnt, &ele->pubkey ) );
      FD_TEST( has( keys, cnt, &ele->node_account ) );
      seen++;
    }
    FD_TEST( seen==VALIDATOR_CNT );
  }

  FD_TEST( stake_accounts_kept( mini, keys, cnt )==0UL );
  FD_TEST( !has( keys, cnt, &fd_solana_stake_program_v5_buffer_address ) );
}

static void
test_boot_accounts_new_epoch( fd_svm_mini_t * mini,
                              fd_bank_t *     bank ) {
  fd_snapmin_t set[1];
  new_set( mini->wksp, set );
  fd_snapmin_keep_boot_accounts( set, bank, mini->banks, ROOT_SLOT+432UL );

  fd_pubkey_t keys[ ELE_MAX ];
  ulong cnt = read_all( set, keys );
  FD_TEST( stake_accounts_kept( mini, keys, cnt )==VALIDATOR_CNT );
  FD_TEST( has( keys, cnt, &fd_solana_stake_program_v5_buffer_address ) );
}

int
main( int     argc,
      char ** argv ) {
  fd_svm_mini_limits_t limits[1];
  fd_svm_mini_limits_default( limits );
  /* The feature accounts alone are over 200. */
  limits->max_accounts       = 1024UL;
  limits->wksp_addl_sz       = TEST_WKSP_ADDL_SZ;
  limits->wksp_addl_part_cnt = TEST_WKSP_ADDL_PART_CNT;
  fd_svm_mini_t * mini = fd_svm_test_boot( &argc, &argv, limits );
  FD_TEST( mini );

  fd_svm_mini_params_t params[1];
  fd_svm_mini_params_default( params );
  params->mock_validator_cnt    = VALIDATOR_CNT;
  params->root_slot             = ROOT_SLOT;
  params->slots_per_epoch       = 432UL;
  params->init_feature_accounts = 1;
  /* Place the bank in epoch 4 so it carries every vote set E-3..E+1. */
  fd_sol_sysvar_clock_t clock = { .slot = ROOT_SLOT, .epoch = 4UL, .leader_schedule_epoch = 5UL };
  params->clock                 = &clock;
  ulong bank_idx = fd_svm_mini_reset( mini, params );
  fd_bank_t * bank = fd_svm_mini_bank( mini, bank_idx );
  FD_TEST( bank );

  test_set( mini->wksp );
  test_boot_accounts_same_epoch( mini, bank );
  test_boot_accounts_new_epoch( mini, bank );
  FD_TEST( !fd_accdb_exists( mini->runtime->accdb, bank->accdb_fork_id, fd_snapmin_balance_key.uc ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_svm_test_halt( mini );
  return 0;
}
