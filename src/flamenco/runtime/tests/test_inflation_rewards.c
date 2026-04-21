#include "fd_svm_mini.h"
#include "../../rewards/fd_rewards.h"
#include "../../rewards/fd_rewards_base.h"
#include "../../rewards/fd_stake_rewards.h"
#include "../../stakes/fd_stake_types.h"
#include "../program/fd_vote_program.h"
#include "../program/vote/fd_vote_codec.h"
#include "../sysvar/fd_sysvar_epoch_rewards.h"
#include "../sysvar/fd_sysvar_epoch_schedule.h"
#include <stdlib.h>

static ulong
read_lamports( fd_svm_mini_t *     mini,
               fd_accdb_fork_id_t  fork_id,
               fd_pubkey_t const * pubkey ) {
  return fd_accdb_lamports( mini->runtime->accdb, fork_id, pubkey->key );
}

static fd_stake_t
read_stake( fd_svm_mini_t *     mini,
            fd_accdb_fork_id_t  fork_id,
            fd_pubkey_t const * pubkey ) {
  fd_accdb_entry_t entry = fd_accdb_read_one( mini->runtime->accdb, fork_id, pubkey->key );
  FD_TEST( entry.lamports > 0UL );
  fd_stake_state_t const * ss = fd_stake_state_view( entry.data, entry.data_len );
  FD_TEST( ss && ss->stake_type==FD_STAKE_STATE_STAKE );
  fd_stake_t s = ss->stake.stake;
  fd_accdb_unread_one( mini->runtime->accdb, &entry );
  return s;
}

static void
mock_validator_keys( ulong         hash_seed,
                     fd_pubkey_t * identity_out,
                     fd_pubkey_t * vote_out,
                     fd_pubkey_t * stake_out ) {
  fd_rng_t rng[1];
  fd_rng_join( fd_rng_new( rng, (uint)hash_seed, 0UL ) );
  for( ulong j=0UL; j<4UL; j++ ) identity_out->ul[j] = fd_rng_ulong( rng );
  for( ulong j=0UL; j<4UL; j++ ) vote_out->ul[j]     = fd_rng_ulong( rng );
  for( ulong j=0UL; j<4UL; j++ ) stake_out->ul[j]    = fd_rng_ulong( rng );
  fd_rng_delete( fd_rng_leave( rng ) );
}

static void
patch_vote_account( fd_svm_mini_t *     mini,
                    ulong               root_idx,
                    fd_pubkey_t const * vote_key,
                    uchar               new_commission,
                    ulong               epoch,
                    ulong               credits,
                    ulong               prev_credits ) {
  fd_accdb_fork_id_t root_fk = fd_svm_mini_fork_id( mini, root_idx );

  fd_accdb_entry_t entry = fd_accdb_read_one( mini->runtime->accdb, root_fk, vote_key->key );
  FD_TEST( entry.lamports > 0UL );
  ulong data_sz = entry.data_len;
  FD_TEST( data_sz<=FD_VOTE_STATE_V3_SZ );
  uchar data_copy[ FD_VOTE_STATE_V3_SZ ];
  memcpy( data_copy, entry.data, data_sz );
  uchar owner_copy[32]; memcpy( owner_copy, entry.owner, 32 );
  ulong lamports_copy = entry.lamports;
  int   exec_copy     = entry.executable;
  fd_accdb_unread_one( mini->runtime->accdb, &entry );

  fd_vote_state_versioned_t versioned[1];
  FD_TEST( fd_vote_state_versioned_deserialize( versioned, data_copy, data_sz ) );
  FD_TEST( versioned->kind==fd_vote_state_versioned_enum_v3 );
  fd_vote_state_v3_t * vs = &versioned->v3;
  vs->commission = new_commission;
  fd_vote_epoch_credits_t * ec = deq_fd_vote_epoch_credits_t_push_tail_nocopy( vs->epoch_credits );
  *ec = (fd_vote_epoch_credits_t){ .epoch=epoch, .credits=credits, .prev_credits=prev_credits };

  uchar new_data[ FD_VOTE_STATE_V3_SZ ] = {0};
  FD_TEST( !fd_vote_state_versioned_serialize( versioned, new_data, sizeof(new_data) ) );

  fd_accdb_entry_t new_entry = {0};
  memcpy( new_entry.pubkey, vote_key->key, 32 );
  memcpy( new_entry.owner, owner_copy, 32 );
  new_entry.lamports   = lamports_copy;
  new_entry.executable = exec_copy;
  new_entry.data_len   = sizeof(new_data);
  new_entry.data       = new_data;
  fd_svm_mini_put_account_rooted( mini, &new_entry );
}

static void
clone_stake_account( fd_svm_mini_t *     mini,
                     ulong               root_idx,
                     fd_pubkey_t const * src_key,
                     fd_pubkey_t const * dst_key ) {
  fd_accdb_fork_id_t root_fk = fd_svm_mini_fork_id( mini, root_idx );

  fd_accdb_entry_t entry = fd_accdb_read_one( mini->runtime->accdb, root_fk, src_key->key );
  FD_TEST( entry.lamports > 0UL );
  ulong data_sz = entry.data_len;
  FD_TEST( data_sz<=FD_STAKE_STATE_SZ );
  uchar data_copy[ FD_STAKE_STATE_SZ ];
  memcpy( data_copy, entry.data, data_sz );
  uchar owner_copy[32]; memcpy( owner_copy, entry.owner, 32 );
  ulong lamports_copy = entry.lamports;
  int   exec_copy     = entry.executable;
  fd_accdb_unread_one( mini->runtime->accdb, &entry );

  fd_accdb_entry_t new_entry = {0};
  memcpy( new_entry.pubkey, dst_key->key, 32 );
  memcpy( new_entry.owner, owner_copy, 32 );
  new_entry.lamports   = lamports_copy;
  new_entry.executable = exec_copy;
  new_entry.data_len   = data_sz;
  new_entry.data       = data_copy;
  fd_svm_mini_put_account_rooted( mini, &new_entry );
}

static uchar
init_stake_rewards( fd_bank_t * bank,
                    fd_hash_t const * blockhash,
                    ulong starting_block_height,
                    uint num_partitions ) {
  fd_stake_rewards_t * stake_rewards = fd_bank_stake_rewards_modify( bank );
  uchar fork_idx = fd_stake_rewards_init( stake_rewards,
                                          bank->f.epoch,
                                          blockhash,
                                          starting_block_height,
                                          num_partitions );
  bank->stake_rewards_fork_id = fork_idx;
  return fork_idx;
}

static void
init_epoch_rewards_sysvar( fd_bank_t *      bank,
                           fd_svm_mini_t *  mini,
                           ulong            starting_block_height,
                           uint             num_partitions,
                           ulong            total_rewards ) {
  fd_hash_t parent_blockhash = {{ 0 }};
  memset( parent_blockhash.hash, 0xEF, sizeof(parent_blockhash.hash) );
  fd_sysvar_epoch_rewards_init( bank,
                                mini->runtime->accdb,
                                NULL,
                                0UL,
                                starting_block_height,
                                num_partitions,
                                total_rewards,
                                0U,
                                &parent_blockhash );
}

static uint
find_reward_partition( fd_stake_rewards_t *      stake_rewards,
                        uchar                     fork_idx,
                        fd_pubkey_t const *       pubkey,
                        uint                      num_partitions ) {
  for( uint p=0U; p<num_partitions; p++ ) {
    for( fd_stake_rewards_iter_init( stake_rewards, fork_idx, p );
         !fd_stake_rewards_iter_done( stake_rewards );
         fd_stake_rewards_iter_next( stake_rewards, fork_idx ) ) {
      fd_pubkey_t cur;
      ulong       lamports;
      ulong       credits;
      fd_stake_rewards_iter_ele( stake_rewards, fork_idx, &cur, &lamports, &credits );
      if( !memcmp( cur.key, pubkey->key, 32 ) ) return p;
    }
  }
  return UINT_MAX;
}

static void
test_commission_split( void ) {
  fd_commission_split_t r[1];

  fd_vote_commission_split( 0, 1000UL, r );
  FD_TEST( r->voter_portion  ==    0UL );
  FD_TEST( r->staker_portion == 1000UL );
  FD_TEST( r->is_split       ==    0U  );

  fd_vote_commission_split( 100, 1000UL, r );
  FD_TEST( r->voter_portion  == 1000UL );
  FD_TEST( r->staker_portion ==    0UL );
  FD_TEST( r->is_split       ==    0U  );

  fd_vote_commission_split( 200, 1000UL, r );
  FD_TEST( r->voter_portion  == 1000UL );
  FD_TEST( r->staker_portion ==    0UL );
  FD_TEST( r->is_split       ==    0U  );

  fd_vote_commission_split( 50, 1000UL, r );
  FD_TEST( r->voter_portion  ==  500UL );
  FD_TEST( r->staker_portion ==  500UL );
  FD_TEST( r->is_split       ==    1U  );

  fd_vote_commission_split( 10, 1000UL, r );
  FD_TEST( r->voter_portion  ==  100UL );
  FD_TEST( r->staker_portion ==  900UL );
  FD_TEST( r->is_split       ==    1U  );

  fd_vote_commission_split( 1, 10UL, r );
  FD_TEST( r->voter_portion  ==  0UL );
  FD_TEST( r->staker_portion ==  9UL );
  FD_TEST( r->is_split       ==  1U  );

  fd_vote_commission_split( 33, 100UL, r );
  FD_TEST( r->voter_portion  == 33UL );
  FD_TEST( r->staker_portion == 67UL );
  FD_TEST( r->is_split       ==  1U  );

  fd_vote_commission_split( 50, 0UL, r );
  FD_TEST( r->voter_portion  == 0UL );
  FD_TEST( r->staker_portion == 0UL );

  FD_LOG_NOTICE(( "test_commission_split: PASSED" ));
}

#define TEST_SLOTS_PER_EPOCH 16UL
#define TEST_ROOT_SLOT        1UL
#define TEST_EPOCH_BOUNDARY  16UL
#define TEST_DISTRIB_SLOT    17UL

static ulong
advance_to_distribution( fd_svm_mini_t * mini, ulong root_idx ) {
  ulong epoch_idx  = fd_svm_mini_attach_child( mini, root_idx,    TEST_EPOCH_BOUNDARY );
  fd_svm_mini_freeze( mini, epoch_idx );
  ulong distrib_idx = fd_svm_mini_attach_child( mini, epoch_idx, TEST_DISTRIB_SLOT );
  return distrib_idx;
}

static void
test_no_credits_no_reward( fd_svm_mini_t * mini ) {
  fd_svm_mini_params_t params[1];
  fd_svm_mini_params_default( params );
  params->slots_per_epoch    = TEST_SLOTS_PER_EPOCH;
  params->root_slot          = TEST_ROOT_SLOT;
  params->mock_validator_cnt = 1UL;
  ulong root_idx = fd_svm_mini_reset( mini, params );

  fd_bank_t * root_bank = fd_svm_mini_bank( mini, root_idx );
  root_bank->f.inflation = (fd_inflation_t){
    .initial         = 0.08,
    .terminal        = 0.015,
    .taper           = 0.15,
    .foundation      = 0.05,
    .foundation_term = 7.0,
  };

  fd_pubkey_t identity_key, vote_key, stake_key;
  mock_validator_keys( params->hash_seed, &identity_key, &vote_key, &stake_key );

  fd_accdb_fork_id_t root_fk = fd_svm_mini_fork_id( mini, root_idx );
  ulong stake_lam_before = read_lamports( mini, root_fk, &stake_key );
  FD_TEST( stake_lam_before > 0UL );

  ulong distrib_idx = advance_to_distribution( mini, root_idx );
  fd_accdb_fork_id_t distrib_fk = fd_svm_mini_fork_id( mini, distrib_idx );

  ulong stake_lam_after = read_lamports( mini, distrib_fk, &stake_key );
  FD_TEST( stake_lam_after == stake_lam_before );

  fd_stake_t s = read_stake( mini, distrib_fk, &stake_key );
  FD_TEST( s.delegation.stake == 1000000000UL );
  FD_TEST( s.credits_observed == 0UL );

  FD_LOG_NOTICE(( "test_no_credits_no_reward: PASSED" ));
}

static void
test_credits_staker_reward( fd_svm_mini_t * mini ) {
  fd_svm_mini_params_t params[1];
  fd_svm_mini_params_default( params );
  params->slots_per_epoch    = TEST_SLOTS_PER_EPOCH;
  params->root_slot          = TEST_ROOT_SLOT;
  params->mock_validator_cnt = 1UL;
  ulong root_idx = fd_svm_mini_reset( mini, params );

  fd_bank_t * root_bank = fd_svm_mini_bank( mini, root_idx );
  root_bank->f.inflation = (fd_inflation_t){
    .initial         = 0.08,
    .terminal        = 0.015,
    .taper           = 0.15,
    .foundation      = 0.05,
    .foundation_term = 7.0,
  };

  fd_pubkey_t identity_key, vote_key, stake_key;
  mock_validator_keys( params->hash_seed, &identity_key, &vote_key, &stake_key );

  patch_vote_account( mini, root_idx, &vote_key, 0, 0UL, 2UL, 0UL );

  fd_accdb_fork_id_t root_fk = fd_svm_mini_fork_id( mini, root_idx );
  ulong stake_lam_before = read_lamports( mini, root_fk, &stake_key );
  FD_TEST( stake_lam_before > 0UL );
  fd_stake_t s_before = read_stake( mini, root_fk, &stake_key );
  FD_TEST( s_before.credits_observed == 0UL );

  ulong distrib_idx = advance_to_distribution( mini, root_idx );
  fd_accdb_fork_id_t distrib_fk = fd_svm_mini_fork_id( mini, distrib_idx );

  ulong stake_lam_after = read_lamports( mini, distrib_fk, &stake_key );
  fd_stake_t s_after = read_stake( mini, distrib_fk, &stake_key );

  FD_TEST( stake_lam_after > stake_lam_before );
  ulong reward = stake_lam_after - stake_lam_before;

  FD_TEST( s_after.delegation.stake == s_before.delegation.stake + reward );
  FD_TEST( s_after.credits_observed == 2UL );
  FD_TEST( s_after.delegation.voter_pubkey.ul[0] == vote_key.ul[0] );

  FD_LOG_NOTICE(( "test_credits_staker_reward: PASSED (staker reward = %lu lamports)", reward ));
}

static void
patch_stake_activation_epoch( fd_svm_mini_t *     mini,
                               ulong               root_idx,
                               fd_pubkey_t const * stake_key,
                               fd_pubkey_t const * vote_key,
                               ulong               new_activation_epoch ) {
  fd_accdb_fork_id_t root_fk = fd_svm_mini_fork_id( mini, root_idx );

  fd_accdb_entry_t entry = fd_accdb_read_one( mini->runtime->accdb, root_fk, stake_key->key );
  FD_TEST( entry.lamports > 0UL );
  fd_stake_state_t const * ss_orig = fd_stake_state_view( entry.data, entry.data_len );
  FD_TEST( ss_orig && ss_orig->stake_type==FD_STAKE_STATE_STAKE );
  fd_stake_state_t ss_new = *ss_orig;
  ss_new.stake.stake.delegation.activation_epoch = new_activation_epoch;
  uchar owner_copy[32]; memcpy( owner_copy, entry.owner, 32 );
  ulong lamports_copy = entry.lamports;
  int   exec_copy     = entry.executable;
  fd_accdb_unread_one( mini->runtime->accdb, &entry );

  uchar new_data[ FD_STAKE_STATE_SZ ] = {0};
  FD_STORE( fd_stake_state_t, new_data, ss_new );
  fd_accdb_entry_t new_entry = {0};
  memcpy( new_entry.pubkey, stake_key->key, 32 );
  memcpy( new_entry.owner, owner_copy, 32 );
  new_entry.lamports   = lamports_copy;
  new_entry.executable = exec_copy;
  new_entry.data_len   = sizeof(new_data);
  new_entry.data       = new_data;
  fd_svm_mini_put_account_rooted( mini, &new_entry );

  fd_stake_delegations_t * sd = fd_banks_stake_delegations_root_query( mini->banks );
  fd_stake_delegations_root_update( sd, stake_key, vote_key,
      ss_new.stake.stake.delegation.stake,
      new_activation_epoch,
      ss_new.stake.stake.delegation.deactivation_epoch,
      ss_new.stake.stake.credits_observed,
      FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
}

static void
test_activation_epoch_skips_reward( fd_svm_mini_t * mini ) {
  fd_svm_mini_params_t params[1];
  fd_svm_mini_params_default( params );
  params->slots_per_epoch    = TEST_SLOTS_PER_EPOCH;
  params->root_slot          = TEST_ROOT_SLOT;
  params->mock_validator_cnt = 2UL;
  ulong root_idx = fd_svm_mini_reset( mini, params );

  fd_bank_t * root_bank = fd_svm_mini_bank( mini, root_idx );
  root_bank->f.inflation = (fd_inflation_t){
    .initial         = 0.08,
    .terminal        = 0.015,
    .taper           = 0.15,
    .foundation      = 0.05,
    .foundation_term = 7.0,
  };

  fd_pubkey_t identity_key, vote_key, stake_key;
  mock_validator_keys( params->hash_seed, &identity_key, &vote_key, &stake_key );

  patch_vote_account( mini, root_idx, &vote_key, 0, 0UL, 2UL, 0UL );

  patch_stake_activation_epoch( mini, root_idx, &stake_key, &vote_key, 0UL );

  fd_accdb_fork_id_t root_fk = fd_svm_mini_fork_id( mini, root_idx );
  ulong stake_lam_before = read_lamports( mini, root_fk, &stake_key );
  fd_stake_t s_before    = read_stake  ( mini, root_fk, &stake_key );
  FD_TEST( s_before.credits_observed == 0UL );

  ulong distrib_idx = advance_to_distribution( mini, root_idx );
  fd_accdb_fork_id_t distrib_fk = fd_svm_mini_fork_id( mini, distrib_idx );

  ulong stake_lam_after = read_lamports( mini, distrib_fk, &stake_key );
  FD_TEST( stake_lam_after == stake_lam_before );

  fd_stake_t s_after = read_stake( mini, distrib_fk, &stake_key );
  FD_TEST( s_after.delegation.stake == s_before.delegation.stake );
  FD_TEST( s_after.credits_observed == 2UL );

  FD_LOG_NOTICE(( "test_activation_epoch_skips_reward: PASSED" ));
}

static void
test_zero_inflation_credits_advance( fd_svm_mini_t * mini ) {
  fd_svm_mini_params_t params[1];
  fd_svm_mini_params_default( params );
  params->slots_per_epoch    = TEST_SLOTS_PER_EPOCH;
  params->root_slot          = TEST_ROOT_SLOT;
  params->mock_validator_cnt = 1UL;
  ulong root_idx = fd_svm_mini_reset( mini, params );

  fd_pubkey_t identity_key, vote_key, stake_key;
  mock_validator_keys( params->hash_seed, &identity_key, &vote_key, &stake_key );

  patch_vote_account( mini, root_idx, &vote_key, 0, 0UL, 2UL, 0UL );

  fd_accdb_fork_id_t root_fk = fd_svm_mini_fork_id( mini, root_idx );
  ulong stake_lam_before = read_lamports( mini, root_fk, &stake_key );
  fd_stake_t s_before    = read_stake  ( mini, root_fk, &stake_key );
  FD_TEST( s_before.credits_observed == 0UL );

  ulong distrib_idx = advance_to_distribution( mini, root_idx );
  fd_accdb_fork_id_t distrib_fk = fd_svm_mini_fork_id( mini, distrib_idx );

  ulong stake_lam_after = read_lamports( mini, distrib_fk, &stake_key );
  FD_TEST( stake_lam_after == stake_lam_before );

  fd_stake_t s_after = read_stake( mini, distrib_fk, &stake_key );
  FD_TEST( s_after.delegation.stake == s_before.delegation.stake );
  FD_TEST( s_after.credits_observed == 2UL );

  FD_LOG_NOTICE(( "test_zero_inflation_credits_advance: PASSED" ));
}

static void
test_full_commission_voter_reward( fd_svm_mini_t * mini ) {
  fd_svm_mini_params_t params[1];
  fd_svm_mini_params_default( params );
  params->slots_per_epoch    = TEST_SLOTS_PER_EPOCH;
  params->root_slot          = TEST_ROOT_SLOT;
  params->mock_validator_cnt = 1UL;
  ulong root_idx = fd_svm_mini_reset( mini, params );

  fd_bank_t * root_bank = fd_svm_mini_bank( mini, root_idx );
  root_bank->f.inflation = (fd_inflation_t){
    .initial         = 0.08,
    .terminal        = 0.015,
    .taper           = 0.15,
    .foundation      = 0.05,
    .foundation_term = 7.0,
  };

  fd_pubkey_t identity_key, vote_key, stake_key;
  mock_validator_keys( params->hash_seed, &identity_key, &vote_key, &stake_key );

  patch_vote_account( mini, root_idx, &vote_key, 100, 0UL, 2UL, 0UL );

  fd_accdb_fork_id_t root_fk = fd_svm_mini_fork_id( mini, root_idx );
  ulong stake_lam_before = read_lamports( mini, root_fk, &stake_key );
  ulong vote_lam_before  = read_lamports( mini, root_fk, &vote_key );
  FD_TEST( stake_lam_before > 0UL );
  FD_TEST( vote_lam_before  > 0UL );

  ulong distrib_idx = advance_to_distribution( mini, root_idx );
  fd_accdb_fork_id_t distrib_fk = fd_svm_mini_fork_id( mini, distrib_idx );

  ulong stake_lam_after = read_lamports( mini, distrib_fk, &stake_key );
  ulong vote_lam_after  = read_lamports( mini, distrib_fk, &vote_key );

  FD_TEST( stake_lam_after == stake_lam_before );

  FD_TEST( vote_lam_after > vote_lam_before );

  fd_stake_t s_after = read_stake( mini, distrib_fk, &stake_key );
  FD_TEST( s_after.credits_observed == 2UL );

  FD_LOG_NOTICE(( "test_full_commission_voter_reward: PASSED (voter reward = %lu lamports)",
                   vote_lam_after - vote_lam_before ));
}

static void
test_split_commission_reward( fd_svm_mini_t * mini ) {
  fd_svm_mini_params_t params[1];
  fd_svm_mini_params_default( params );
  params->slots_per_epoch    = TEST_SLOTS_PER_EPOCH;
  params->root_slot          = TEST_ROOT_SLOT;
  params->mock_validator_cnt = 1UL;
  ulong root_idx = fd_svm_mini_reset( mini, params );

  fd_bank_t * root_bank = fd_svm_mini_bank( mini, root_idx );
  root_bank->f.inflation = (fd_inflation_t){
    .initial         = 0.08,
    .terminal        = 0.015,
    .taper           = 0.15,
    .foundation      = 0.05,
    .foundation_term = 7.0,
  };

  fd_pubkey_t identity_key, vote_key, stake_key;
  mock_validator_keys( params->hash_seed, &identity_key, &vote_key, &stake_key );

  patch_vote_account( mini, root_idx, &vote_key, 50, 0UL, 2UL, 0UL );

  fd_accdb_fork_id_t root_fk = fd_svm_mini_fork_id( mini, root_idx );
  ulong stake_lam_before = read_lamports( mini, root_fk, &stake_key );
  ulong vote_lam_before  = read_lamports( mini, root_fk, &vote_key );

  ulong distrib_idx = advance_to_distribution( mini, root_idx );
  fd_accdb_fork_id_t distrib_fk = fd_svm_mini_fork_id( mini, distrib_idx );

  ulong stake_lam_after = read_lamports( mini, distrib_fk, &stake_key );
  ulong vote_lam_after  = read_lamports( mini, distrib_fk, &vote_key );

  ulong staker_reward = stake_lam_after - stake_lam_before;
  ulong voter_reward  = vote_lam_after  - vote_lam_before;

  FD_TEST( staker_reward > 0UL );
  FD_TEST( voter_reward  > 0UL );

  ulong diff = staker_reward > voter_reward ?
               staker_reward - voter_reward :
               voter_reward  - staker_reward;
  FD_TEST( diff <= 1UL );

  fd_stake_t s_after = read_stake( mini, distrib_fk, &stake_key );
  FD_TEST( s_after.delegation.stake == 1000000000UL + staker_reward );
  FD_TEST( s_after.credits_observed == 2UL );

  FD_LOG_NOTICE(( "test_split_commission_reward: PASSED (staker=%lu, voter=%lu)",
                   staker_reward, voter_reward ));
}

static void
test_commission_split_suppresses_reward( fd_svm_mini_t * mini ) {
  fd_svm_mini_params_t params[1];
  fd_svm_mini_params_default( params );
  params->slots_per_epoch    = TEST_SLOTS_PER_EPOCH;
  params->root_slot          = TEST_ROOT_SLOT;
  params->mock_validator_cnt = 1UL;
  ulong root_idx = fd_svm_mini_reset( mini, params );

  fd_bank_t * root_bank = fd_svm_mini_bank( mini, root_idx );
  root_bank->f.inflation = (fd_inflation_t){
    .initial         = 0.0001,
    .terminal        = 0.0001,
    .taper           = 0.15,
    .foundation      = 0.0,
    .foundation_term = 0.0,
  };

  fd_pubkey_t identity_key, vote_key, stake_key;
  mock_validator_keys( params->hash_seed, &identity_key, &vote_key, &stake_key );

  patch_vote_account( mini, root_idx, &vote_key, 1, 0UL, 2UL, 0UL );

  fd_accdb_fork_id_t root_fk = fd_svm_mini_fork_id( mini, root_idx );
  ulong stake_lam_before = read_lamports( mini, root_fk, &stake_key );
  ulong vote_lam_before  = read_lamports( mini, root_fk, &vote_key );

  ulong distrib_idx = advance_to_distribution( mini, root_idx );
  fd_accdb_fork_id_t distrib_fk = fd_svm_mini_fork_id( mini, distrib_idx );

  ulong stake_lam_after = read_lamports( mini, distrib_fk, &stake_key );
  ulong vote_lam_after  = read_lamports( mini, distrib_fk, &vote_key );

  ulong staker_reward = stake_lam_after - stake_lam_before;
  ulong voter_reward  = vote_lam_after  - vote_lam_before;

  FD_TEST( staker_reward == 0UL );
  FD_TEST( voter_reward  == 0UL );

  fd_stake_t s_after = read_stake( mini, distrib_fk, &stake_key );
  FD_TEST( s_after.credits_observed == 0UL );

  FD_LOG_NOTICE(( "test_commission_split_suppresses_reward: PASSED" ));
}

static void
test_credit_rewind_force_update( fd_svm_mini_t * mini ) {
  fd_svm_mini_params_t params[1];
  fd_svm_mini_params_default( params );
  params->slots_per_epoch    = TEST_SLOTS_PER_EPOCH;
  params->root_slot          = TEST_ROOT_SLOT;
  params->mock_validator_cnt = 1UL;
  ulong root_idx = fd_svm_mini_reset( mini, params );

  fd_bank_t * root_bank = fd_svm_mini_bank( mini, root_idx );
  root_bank->f.inflation = (fd_inflation_t){
    .initial         = 0.08,
    .terminal        = 0.015,
    .taper           = 0.15,
    .foundation      = 0.05,
    .foundation_term = 7.0,
  };

  fd_pubkey_t identity_key, vote_key, stake_key;
  mock_validator_keys( params->hash_seed, &identity_key, &vote_key, &stake_key );

  patch_vote_account( mini, root_idx, &vote_key, 0, 0UL, 5UL, 0UL );

  {
    fd_accdb_fork_id_t root_fk = fd_svm_mini_fork_id( mini, root_idx );
    fd_accdb_entry_t entry = fd_accdb_read_one( mini->runtime->accdb, root_fk, stake_key.key );
    FD_TEST( entry.lamports > 0UL );
    fd_stake_state_t const * ss_orig = fd_stake_state_view( entry.data, entry.data_len );
    FD_TEST( ss_orig && ss_orig->stake_type==FD_STAKE_STATE_STAKE );
    fd_stake_state_t ss_new = *ss_orig;
    ss_new.stake.stake.credits_observed = 10UL;
    uchar owner_copy[32]; memcpy( owner_copy, entry.owner, 32 );
    ulong lamports_copy = entry.lamports;
    int   exec_copy     = entry.executable;
    fd_accdb_unread_one( mini->runtime->accdb, &entry );

    uchar new_data[ FD_STAKE_STATE_SZ ] = {0};
    FD_STORE( fd_stake_state_t, new_data, ss_new );
    fd_accdb_entry_t new_entry = {0};
    memcpy( new_entry.pubkey, stake_key.key, 32 );
    memcpy( new_entry.owner, owner_copy, 32 );
    new_entry.lamports   = lamports_copy;
    new_entry.executable = exec_copy;
    new_entry.data_len   = sizeof(new_data);
    new_entry.data       = new_data;
    fd_svm_mini_put_account_rooted( mini, &new_entry );

    fd_stake_delegations_t * sd = fd_banks_stake_delegations_root_query( mini->banks );
    fd_stake_delegations_root_update( sd, &stake_key, &vote_key,
        ss_new.stake.stake.delegation.stake,
        ss_new.stake.stake.delegation.activation_epoch,
        ss_new.stake.stake.delegation.deactivation_epoch,
        10UL,
        FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
  }

  fd_accdb_fork_id_t root_fk = fd_svm_mini_fork_id( mini, root_idx );
  ulong stake_lam_before = read_lamports( mini, root_fk, &stake_key );

  ulong distrib_idx = advance_to_distribution( mini, root_idx );
  fd_accdb_fork_id_t distrib_fk = fd_svm_mini_fork_id( mini, distrib_idx );

  ulong stake_lam_after = read_lamports( mini, distrib_fk, &stake_key );
  FD_TEST( stake_lam_after == stake_lam_before );

  fd_stake_t s_after = read_stake( mini, distrib_fk, &stake_key );
  FD_TEST( s_after.credits_observed == 5UL );
  FD_TEST( s_after.delegation.stake == 1000000000UL );

  FD_LOG_NOTICE(( "test_credit_rewind_force_update: PASSED" ));
}

static void
test_multi_validator_proportional( fd_svm_mini_t * mini ) {
  fd_svm_mini_params_t params[1];
  fd_svm_mini_params_default( params );
  params->slots_per_epoch    = TEST_SLOTS_PER_EPOCH;
  params->root_slot          = TEST_ROOT_SLOT;
  params->mock_validator_cnt = 2UL;
  params->hash_seed          = 42UL;
  ulong root_idx = fd_svm_mini_reset( mini, params );

  fd_bank_t * root_bank = fd_svm_mini_bank( mini, root_idx );
  root_bank->f.inflation = (fd_inflation_t){
    .initial         = 0.08,
    .terminal        = 0.015,
    .taper           = 0.15,
    .foundation      = 0.05,
    .foundation_term = 7.0,
  };

  fd_pubkey_t vote_a, stake_a;
  fd_pubkey_t vote_b, stake_b;
  {
    fd_rng_t rng[1];
    fd_rng_join( fd_rng_new( rng, (uint)params->hash_seed, 0UL ) );
    for( ulong j=0UL; j<4UL; j++ ) (void)fd_rng_ulong( rng );
    for( ulong j=0UL; j<4UL; j++ ) vote_a.ul[j]   = fd_rng_ulong( rng );
    for( ulong j=0UL; j<4UL; j++ ) stake_a.ul[j]  = fd_rng_ulong( rng );
    for( ulong j=0UL; j<4UL; j++ ) (void)fd_rng_ulong( rng );
    for( ulong j=0UL; j<4UL; j++ ) vote_b.ul[j]   = fd_rng_ulong( rng );
    for( ulong j=0UL; j<4UL; j++ ) stake_b.ul[j]  = fd_rng_ulong( rng );
    fd_rng_delete( fd_rng_leave( rng ) );
  }

  patch_vote_account( mini, root_idx, &vote_a, 0, 0UL, 4UL, 0UL );
  patch_vote_account( mini, root_idx, &vote_b, 0, 0UL, 2UL, 0UL );

  fd_accdb_fork_id_t root_fk = fd_svm_mini_fork_id( mini, root_idx );
  ulong stake_a_before = read_lamports( mini, root_fk, &stake_a );
  ulong stake_b_before = read_lamports( mini, root_fk, &stake_b );

  ulong distrib_idx = advance_to_distribution( mini, root_idx );
  fd_accdb_fork_id_t distrib_fk = fd_svm_mini_fork_id( mini, distrib_idx );

  ulong stake_a_after = read_lamports( mini, distrib_fk, &stake_a );
  ulong stake_b_after = read_lamports( mini, distrib_fk, &stake_b );

  ulong reward_a = stake_a_after - stake_a_before;
  ulong reward_b = stake_b_after - stake_b_before;

  FD_TEST( reward_a > 0UL );
  FD_TEST( reward_b > 0UL );

  FD_TEST( reward_a >= 2UL * reward_b - 1UL );
  FD_TEST( reward_a <= 2UL * reward_b + 1UL );

  fd_stake_t sa = read_stake( mini, distrib_fk, &stake_a );
  fd_stake_t sb = read_stake( mini, distrib_fk, &stake_b );
  FD_TEST( sa.credits_observed == 4UL );
  FD_TEST( sb.credits_observed == 2UL );

  FD_LOG_NOTICE(( "test_multi_validator_proportional: PASSED (A=%lu, B=%lu, ratio=%.2f)",
                   reward_a, reward_b, (double)reward_a / (double)reward_b ));
}

static void
test_calculate_points_typical_values( fd_svm_mini_t * mini ) {
  fd_svm_mini_params_t params[1];
  fd_svm_mini_params_default( params );
  params->slots_per_epoch    = TEST_SLOTS_PER_EPOCH;
  params->root_slot          = TEST_ROOT_SLOT;
  params->mock_validator_cnt = 1UL;
  ulong root_idx = fd_svm_mini_reset( mini, params );

  fd_bank_t * root_bank = fd_svm_mini_bank( mini, root_idx );
  root_bank->f.inflation = (fd_inflation_t){
    .initial         = 0.08,
    .terminal        = 0.015,
    .taper           = 0.15,
    .foundation      = 0.05,
    .foundation_term = 7.0,
  };

  fd_pubkey_t identity_key, vote_key, stake_key;
  mock_validator_keys( params->hash_seed, &identity_key, &vote_key, &stake_key );

  patch_vote_account( mini, root_idx, &vote_key, 0, 0UL, 193000000UL, 0UL );

  fd_accdb_fork_id_t root_fk = fd_svm_mini_fork_id( mini, root_idx );
  ulong stake_lam_before = read_lamports( mini, root_fk, &stake_key );
  FD_TEST( stake_lam_before > 0UL );

  ulong distrib_idx = advance_to_distribution( mini, root_idx );
  fd_accdb_fork_id_t distrib_fk = fd_svm_mini_fork_id( mini, distrib_idx );

  ulong stake_lam_after = read_lamports( mini, distrib_fk, &stake_key );
  FD_TEST( stake_lam_after > stake_lam_before );

  fd_stake_t s_after = read_stake( mini, distrib_fk, &stake_key );
  FD_TEST( s_after.credits_observed == 193000000UL );

  FD_LOG_NOTICE(( "test_calculate_points_typical_values: PASSED (reward = %lu lamports)",
                   stake_lam_after - stake_lam_before ));
}

static void
test_epoch_rewards_sysvar_lifecycle( fd_svm_mini_t * mini ) {
  fd_svm_mini_params_t params[1];
  fd_svm_mini_params_default( params );
  params->slots_per_epoch    = TEST_SLOTS_PER_EPOCH;
  params->root_slot          = TEST_ROOT_SLOT;
  params->mock_validator_cnt = 1UL;
  ulong root_idx = fd_svm_mini_reset( mini, params );
  ulong child_idx = fd_svm_mini_attach_child( mini, root_idx, params->root_slot + 1UL );

  fd_bank_t *          bank     = fd_svm_mini_bank( mini, child_idx );
  fd_accdb_fork_id_t   child_fk = fd_svm_mini_fork_id( mini, child_idx );

  fd_hash_t parent_blockhash = {{ 0 }};
  memset( parent_blockhash.hash, 0xAB, sizeof(parent_blockhash.hash) );

  ulong   total_rewards   = 1000UL;
  ulong   starting_height = 42UL;
  ulong   num_partitions  = 5UL;
  uint128 total_points    = (uint128)123456789UL;

  fd_sysvar_epoch_rewards_init( bank, mini->runtime->accdb, NULL,
                                0UL, starting_height, num_partitions,
                                total_rewards, total_points, &parent_blockhash );

  fd_sysvar_epoch_rewards_t er[1];
  FD_TEST( fd_sysvar_epoch_rewards_read( mini->runtime->accdb, child_fk, er ) );
  FD_TEST( er->active                             == 1              );
  FD_TEST( er->total_rewards                      == total_rewards  );
  FD_TEST( er->distributed_rewards                == 0UL            );
  FD_TEST( er->num_partitions                     == num_partitions );
  FD_TEST( er->distribution_starting_block_height == starting_height );
  FD_TEST( er->total_points.ud                    == total_points   );
  FD_TEST( !memcmp( er->parent_blockhash.hash, parent_blockhash.hash, 32 ) );

  fd_sysvar_epoch_rewards_distribute( bank, mini->runtime->accdb, NULL, 10UL );
  FD_TEST( fd_sysvar_epoch_rewards_read( mini->runtime->accdb, child_fk, er ) );
  FD_TEST( er->distributed_rewards == 10UL );
  FD_TEST( er->active              == 1    );

  fd_sysvar_epoch_rewards_distribute( bank, mini->runtime->accdb, NULL, 10UL );
  FD_TEST( fd_sysvar_epoch_rewards_read( mini->runtime->accdb, child_fk, er ) );
  FD_TEST( er->distributed_rewards == 20UL );

  fd_sysvar_epoch_rewards_set_inactive( bank, mini->runtime->accdb, NULL );
  FD_TEST( fd_sysvar_epoch_rewards_read( mini->runtime->accdb, child_fk, er ) );
  FD_TEST( er->active              == 0             );
  FD_TEST( er->total_rewards       == total_rewards  );
  FD_TEST( er->distributed_rewards == 20UL           );
  FD_TEST( er->num_partitions      == num_partitions );

  FD_LOG_NOTICE(( "test_epoch_rewards_sysvar_lifecycle: PASSED" ));
}

static void
test_hash_rewards_into_partitions( void ) {
  ulong max_accs  = 16384UL;
  ulong exp_accs  = 12345UL;
  ulong max_forks = 4UL;

  ulong footprint = fd_stake_rewards_footprint( max_accs, exp_accs, max_forks );
  FD_TEST( footprint > 0UL );
  void * mem = aligned_alloc( fd_stake_rewards_align(), footprint );
  FD_TEST( mem );

  fd_stake_rewards_t * sr = fd_stake_rewards_join(
      fd_stake_rewards_new( mem, max_accs, exp_accs, max_forks, 42UL ) );
  FD_TEST( sr );

  fd_hash_t blockhash = {{ 0 }};
  memset( blockhash.hash, 0xCD, sizeof(blockhash.hash) );

  uint  num_partitions = 5U;
  uchar fork_idx = fd_stake_rewards_init( sr, 1UL, &blockhash, 100UL, num_partitions );

  for( ulong i=0UL; i<12345UL; i++ ) {
    fd_pubkey_t pubkey = {{ 0 }};
    FD_STORE( ulong, pubkey.key, i );
    fd_stake_rewards_insert( sr, fork_idx, &pubkey, i+1UL, i );
  }

  ulong total_count = 0UL, total_lamports = 0UL;
  for( uint p=0U; p<num_partitions; p++ ) {
    for( fd_stake_rewards_iter_init( sr, fork_idx, p );
         !fd_stake_rewards_iter_done( sr );
         fd_stake_rewards_iter_next( sr, fork_idx ) ) {
      fd_pubkey_t pubkey; ulong lamports, credits_observed;
      fd_stake_rewards_iter_ele( sr, fork_idx, &pubkey, &lamports, &credits_observed );
      total_count++;
      total_lamports += lamports;
    }
  }

  FD_TEST( total_count    == 12345UL );
  FD_TEST( total_lamports == 12345UL * 12346UL / 2UL );
  FD_TEST( fd_stake_rewards_total_rewards( sr, fork_idx )   == total_lamports  );
  FD_TEST( fd_stake_rewards_num_partitions( sr, fork_idx )  == num_partitions  );

  free( mem );

  FD_LOG_NOTICE(( "test_hash_rewards_into_partitions: PASSED (total=%lu)", total_count ));
}

static void
test_hash_rewards_into_partitions_empty( void ) {
  ulong footprint = fd_stake_rewards_footprint( 1024UL, 256UL, 4UL );
  void * mem = aligned_alloc( fd_stake_rewards_align(), footprint );
  FD_TEST( mem );

  fd_stake_rewards_t * sr = fd_stake_rewards_join(
      fd_stake_rewards_new( mem, 1024UL, 256UL, 4UL, 42UL ) );
  FD_TEST( sr );

  fd_hash_t blockhash = {{ 0 }};
  uint  num_partitions = 5U;
  uchar fork_idx = fd_stake_rewards_init( sr, 1UL, &blockhash, 100UL, num_partitions );

  for( uint p=0U; p<num_partitions; p++ ) {
    fd_stake_rewards_iter_init( sr, fork_idx, p );
    FD_TEST( fd_stake_rewards_iter_done( sr ) );
  }
  FD_TEST( fd_stake_rewards_total_rewards( sr, fork_idx ) == 0UL );

  free( mem );

  FD_LOG_NOTICE(( "test_hash_rewards_into_partitions_empty: PASSED" ));
}

static void
test_epoch_credit_rewards_and_history_update( fd_svm_mini_t * mini ) {
  fd_svm_mini_params_t params[1];
  fd_svm_mini_params_default( params );
  params->slots_per_epoch    = TEST_SLOTS_PER_EPOCH;
  params->root_slot          = TEST_ROOT_SLOT;
  params->mock_validator_cnt = 1UL;
  ulong root_idx = fd_svm_mini_reset( mini, params );

  fd_pubkey_t identity_key, vote_key, stake_key;
  mock_validator_keys( params->hash_seed, &identity_key, &vote_key, &stake_key );

  ulong reward_lamports = 500UL;
  ulong credits_observed = 7UL;

  fd_hash_t blockhash = {{ 0 }};
  memset( blockhash.hash, 0x22, sizeof(blockhash.hash) );

  ulong child_idx = fd_svm_mini_attach_child( mini, root_idx, params->root_slot + 1UL );
  fd_bank_t * child_bank = fd_svm_mini_bank( mini, child_idx );
  fd_accdb_fork_id_t child_fk = fd_svm_mini_fork_id( mini, child_idx );

  ulong starting_block_height = child_bank->f.block_height;
  uchar fork_idx = init_stake_rewards( child_bank, &blockhash, starting_block_height, 1U );
  fd_stake_rewards_t * stake_rewards = fd_bank_stake_rewards_modify( child_bank );
  fd_stake_rewards_insert( stake_rewards, fork_idx, &stake_key, reward_lamports, credits_observed );
  init_epoch_rewards_sysvar( child_bank, mini, starting_block_height, 1U, reward_lamports );

  ulong stake_lam_before = read_lamports( mini, child_fk, &stake_key );
  ulong cap_before = child_bank->f.capitalization;

  fd_distribute_partitioned_epoch_rewards( child_bank, mini->runtime->accdb, NULL );

  ulong stake_lam_after = read_lamports( mini, child_fk, &stake_key );
  fd_stake_t s_after = read_stake( mini, child_fk, &stake_key );
  FD_TEST( stake_lam_after == stake_lam_before + reward_lamports );
  FD_TEST( s_after.credits_observed == credits_observed );
  FD_TEST( child_bank->f.capitalization == cap_before + reward_lamports );

  fd_sysvar_epoch_rewards_t er[1];
  FD_TEST( fd_sysvar_epoch_rewards_read( mini->runtime->accdb, child_fk, er ) );
  FD_TEST( er->distributed_rewards == reward_lamports );
  FD_TEST( er->active == 0 );
  FD_TEST( child_bank->stake_rewards_fork_id == UCHAR_MAX );

  FD_LOG_NOTICE(( "test_epoch_credit_rewards_and_history_update: PASSED" ));
}

static void
test_update_reward_history_in_partition( fd_svm_mini_t * mini ) {
  fd_svm_mini_params_t params[1];
  fd_svm_mini_params_default( params );
  params->slots_per_epoch    = TEST_SLOTS_PER_EPOCH;
  params->root_slot          = TEST_ROOT_SLOT;
  params->mock_validator_cnt = 1UL;
  ulong root_idx = fd_svm_mini_reset( mini, params );

  fd_pubkey_t identity_key, vote_key, stake_key;
  mock_validator_keys( params->hash_seed, &identity_key, &vote_key, &stake_key );

  fd_pubkey_t stake_key_b = {{ 0 }};
  stake_key_b.ul[0] = stake_key.ul[0] + 1UL;
  stake_key_b.ul[1] = stake_key.ul[1];
  stake_key_b.ul[2] = stake_key.ul[2];
  stake_key_b.ul[3] = stake_key.ul[3];

  clone_stake_account( mini, root_idx, &stake_key, &stake_key_b );

  ulong reward_a = 111UL;
  ulong reward_b = 222UL;
  ulong total_rewards = reward_a + reward_b;

  fd_hash_t blockhash = {{ 0 }};
  memset( blockhash.hash, 0x33, sizeof(blockhash.hash) );

  ulong child_idx = fd_svm_mini_attach_child( mini, root_idx, params->root_slot + 1UL );
  fd_bank_t * child_bank = fd_svm_mini_bank( mini, child_idx );
  fd_accdb_fork_id_t child_fk = fd_svm_mini_fork_id( mini, child_idx );

  ulong starting_block_height = child_bank->f.block_height;
  uchar fork_idx = init_stake_rewards( child_bank, &blockhash, starting_block_height, 1U );
  fd_stake_rewards_t * stake_rewards = fd_bank_stake_rewards_modify( child_bank );
  fd_stake_rewards_insert( stake_rewards, fork_idx, &stake_key, reward_a, 5UL );
  fd_stake_rewards_insert( stake_rewards, fork_idx, &stake_key_b, reward_b, 6UL );
  init_epoch_rewards_sysvar( child_bank, mini, starting_block_height, 1U, total_rewards );

  ulong cap_before = child_bank->f.capitalization;
  fd_distribute_partitioned_epoch_rewards( child_bank, mini->runtime->accdb, NULL );

  fd_sysvar_epoch_rewards_t er[1];
  FD_TEST( fd_sysvar_epoch_rewards_read( mini->runtime->accdb, child_fk, er ) );
  FD_TEST( er->distributed_rewards == total_rewards );
  FD_TEST( child_bank->f.capitalization == cap_before + total_rewards );

  FD_LOG_NOTICE(( "test_update_reward_history_in_partition: PASSED" ));
}

static void
test_build_updated_stake_reward( fd_svm_mini_t * mini ) {
  fd_svm_mini_params_t params[1];
  fd_svm_mini_params_default( params );
  params->slots_per_epoch    = TEST_SLOTS_PER_EPOCH;
  params->root_slot          = TEST_ROOT_SLOT;
  params->mock_validator_cnt = 1UL;
  ulong root_idx = fd_svm_mini_reset( mini, params );

  fd_pubkey_t identity_key, vote_key, stake_key;
  mock_validator_keys( params->hash_seed, &identity_key, &vote_key, &stake_key );

  ulong reward_lamports = 1234UL;
  ulong credits_observed = 12UL;

  fd_hash_t blockhash = {{ 0 }};
  memset( blockhash.hash, 0x44, sizeof(blockhash.hash) );

  ulong child_idx = fd_svm_mini_attach_child( mini, root_idx, params->root_slot + 1UL );
  fd_accdb_fork_id_t child_fk = fd_svm_mini_fork_id( mini, child_idx );
  fd_bank_t * child_bank = fd_svm_mini_bank( mini, child_idx );

  ulong starting_block_height = child_bank->f.block_height;
  uchar fork_idx = init_stake_rewards( child_bank, &blockhash, starting_block_height, 1U );
  fd_stake_rewards_t * stake_rewards = fd_bank_stake_rewards_modify( child_bank );
  fd_stake_rewards_insert( stake_rewards, fork_idx, &stake_key, reward_lamports, credits_observed );
  init_epoch_rewards_sysvar( child_bank, mini, starting_block_height, 1U, reward_lamports );

  ulong stake_lam_before = read_lamports( mini, child_fk, &stake_key );
  fd_stake_t s_before = read_stake( mini, child_fk, &stake_key );

  fd_distribute_partitioned_epoch_rewards( child_bank, mini->runtime->accdb, NULL );

  ulong stake_lam_after = read_lamports( mini, child_fk, &stake_key );
  fd_stake_t s_after = read_stake( mini, child_fk, &stake_key );

  FD_TEST( stake_lam_after == stake_lam_before + reward_lamports );
  FD_TEST( s_after.delegation.stake == s_before.delegation.stake + reward_lamports );
  FD_TEST( s_after.credits_observed == credits_observed );

  FD_LOG_NOTICE(( "test_build_updated_stake_reward: PASSED" ));
}

static void
test_update_reward_history_in_partition_empty( fd_svm_mini_t * mini ) {
  fd_svm_mini_params_t params[1];
  fd_svm_mini_params_default( params );
  params->slots_per_epoch    = TEST_SLOTS_PER_EPOCH;
  params->root_slot          = TEST_ROOT_SLOT;
  params->mock_validator_cnt = 1UL;
  ulong root_idx = fd_svm_mini_reset( mini, params );

  fd_hash_t blockhash = {{ 0 }};
  memset( blockhash.hash, 0x55, sizeof(blockhash.hash) );

  ulong child_idx = fd_svm_mini_attach_child( mini, root_idx, params->root_slot + 1UL );
  fd_bank_t * child_bank = fd_svm_mini_bank( mini, child_idx );
  fd_accdb_fork_id_t child_fk = fd_svm_mini_fork_id( mini, child_idx );

  ulong starting_block_height = child_bank->f.block_height;
  init_stake_rewards( child_bank, &blockhash, starting_block_height, 1U );
  init_epoch_rewards_sysvar( child_bank, mini, starting_block_height, 1U, 0UL );

  ulong cap_before = child_bank->f.capitalization;
  fd_distribute_partitioned_epoch_rewards( child_bank, mini->runtime->accdb, NULL );

  fd_sysvar_epoch_rewards_t er[1];
  FD_TEST( fd_sysvar_epoch_rewards_read( mini->runtime->accdb, child_fk, er ) );
  FD_TEST( er->distributed_rewards == 0UL );
  FD_TEST( child_bank->f.capitalization == cap_before );

  FD_LOG_NOTICE(( "test_update_reward_history_in_partition_empty: PASSED" ));
}

static void
test_store_stake_accounts_in_partition( fd_svm_mini_t * mini ) {
  fd_svm_mini_params_t params[1];
  fd_svm_mini_params_default( params );
  params->slots_per_epoch    = TEST_SLOTS_PER_EPOCH;
  params->root_slot          = TEST_ROOT_SLOT;
  params->mock_validator_cnt = 1UL;
  ulong root_idx = fd_svm_mini_reset( mini, params );

  fd_pubkey_t identity_key, vote_key, stake_key;
  mock_validator_keys( params->hash_seed, &identity_key, &vote_key, &stake_key );

  fd_hash_t blockhash = {{ 0 }};
  memset( blockhash.hash, 0x66, sizeof(blockhash.hash) );

  uint num_partitions = 2U;

  ulong child_idx0 = fd_svm_mini_attach_child( mini, root_idx, params->root_slot + 1UL );
  fd_bank_t * bank0 = fd_svm_mini_bank( mini, child_idx0 );
  fd_accdb_fork_id_t fk0 = fd_svm_mini_fork_id( mini, child_idx0 );

  ulong starting_block_height = bank0->f.block_height;
  fd_stake_rewards_t * stake_rewards = fd_bank_stake_rewards_modify( bank0 );
  fd_rng_t rng[1];
  fd_rng_join( fd_rng_new( rng, (uint)params->hash_seed, 0UL ) );

  fd_pubkey_t pubkeys[4];
  ulong rewards[4];
  ulong credits[4];
  uint attempts = 0U;
  uchar fork_idx = UCHAR_MAX;

  while( attempts++ < 64U ) {
    fd_stake_rewards_clear( stake_rewards );
    fork_idx = init_stake_rewards( bank0, &blockhash, starting_block_height, num_partitions );

    for( uint i=0U; i<4U; i++ ) {
      for( ulong j=0UL; j<4UL; j++ ) pubkeys[i].ul[j] = fd_rng_ulong( rng );
      rewards[i] = 100UL + (ulong)i;
      credits[i] = 10UL + (ulong)i;
      fd_stake_rewards_insert( stake_rewards, fork_idx, &pubkeys[i], rewards[i], credits[i] );
    }

    ulong counts[2] = {0UL, 0UL};
    for( uint i=0U; i<4U; i++ ) {
      uint part = find_reward_partition( stake_rewards, fork_idx, &pubkeys[i], num_partitions );
      if( part<num_partitions ) counts[part]++;
    }
    if( counts[0] && counts[1] ) break;
  }

  FD_TEST( fork_idx!=UCHAR_MAX );

  for( uint i=0U; i<4U; i++ ) clone_stake_account( mini, root_idx, &stake_key, &pubkeys[i] );

  ulong total_rewards = 0UL;
  for( uint i=0U; i<4U; i++ ) total_rewards += rewards[i];

  init_epoch_rewards_sysvar( bank0, mini, starting_block_height, num_partitions, total_rewards );

  ulong lam_before[4];
  for( uint i=0U; i<4U; i++ ) lam_before[i] = read_lamports( mini, fk0, &pubkeys[i] );

  fd_distribute_partitioned_epoch_rewards( bank0, mini->runtime->accdb, NULL );

  for( uint i=0U; i<4U; i++ ) {
    uint part = find_reward_partition( stake_rewards, fork_idx, &pubkeys[i], num_partitions );
    ulong lam_after = read_lamports( mini, fk0, &pubkeys[i] );
    fd_stake_t s_after = read_stake( mini, fk0, &pubkeys[i] );
    if( part==0U ) {
      FD_TEST( lam_after == lam_before[i] + rewards[i] );
      FD_TEST( s_after.credits_observed == credits[i] );
    } else {
      FD_TEST( lam_after == lam_before[i] );
    }
  }

  ulong child_idx1 = fd_svm_mini_attach_child( mini, child_idx0, params->root_slot + 2UL );
  fd_bank_t * bank1 = fd_svm_mini_bank( mini, child_idx1 );
  fd_accdb_fork_id_t fk1 = fd_svm_mini_fork_id( mini, child_idx1 );

  fd_distribute_partitioned_epoch_rewards( bank1, mini->runtime->accdb, NULL );

  for( uint i=0U; i<4U; i++ ) {
    ulong lam_after = read_lamports( mini, fk1, &pubkeys[i] );
    FD_TEST( lam_after == lam_before[i] + rewards[i] );
  }

  fd_sysvar_epoch_rewards_t er[1];
  FD_TEST( fd_sysvar_epoch_rewards_read( mini->runtime->accdb, fk1, er ) );
  FD_TEST( er->distributed_rewards == total_rewards );
  FD_TEST( er->active == 0 );

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "test_store_stake_accounts_in_partition: PASSED" ));
}

static void
test_store_stake_accounts_in_partition_empty( fd_svm_mini_t * mini ) {
  fd_svm_mini_params_t params[1];
  fd_svm_mini_params_default( params );
  params->slots_per_epoch    = TEST_SLOTS_PER_EPOCH;
  params->root_slot          = TEST_ROOT_SLOT;
  params->mock_validator_cnt = 1UL;
  ulong root_idx = fd_svm_mini_reset( mini, params );

  fd_pubkey_t identity_key, vote_key, stake_key;
  mock_validator_keys( params->hash_seed, &identity_key, &vote_key, &stake_key );

  fd_hash_t blockhash = {{ 0 }};
  memset( blockhash.hash, 0x77, sizeof(blockhash.hash) );

  uint num_partitions = 2U;

  fd_pubkey_t reward_key = {{ 0 }};
  uchar fork_idx = UCHAR_MAX;
  uint attempts = 0U;
  ulong child_idx0 = fd_svm_mini_attach_child( mini, root_idx, params->root_slot + 1UL );
  fd_bank_t * bank0 = fd_svm_mini_bank( mini, child_idx0 );
  fd_accdb_fork_id_t fk0 = fd_svm_mini_fork_id( mini, child_idx0 );
  ulong starting_block_height = bank0->f.block_height;
  fd_stake_rewards_t * stake_rewards = fd_bank_stake_rewards_modify( bank0 );

  while( attempts++ < 64U ) {
    fd_stake_rewards_clear( stake_rewards );
    fork_idx = init_stake_rewards( bank0, &blockhash, starting_block_height, num_partitions );
    for( ulong j=0UL; j<4UL; j++ ) reward_key.ul[j] = (ulong)(attempts * 101U + j);
    fd_stake_rewards_insert( stake_rewards, fork_idx, &reward_key, 333UL, 9UL );
    uint part = find_reward_partition( stake_rewards, fork_idx, &reward_key, num_partitions );
    if( part==1U ) break;
  }

  FD_TEST( fork_idx!=UCHAR_MAX );
  clone_stake_account( mini, root_idx, &stake_key, &reward_key );

  init_epoch_rewards_sysvar( bank0, mini, starting_block_height, num_partitions, 333UL );

  ulong lam_before = read_lamports( mini, fk0, &reward_key );
  ulong cap_before = bank0->f.capitalization;
  fd_distribute_partitioned_epoch_rewards( bank0, mini->runtime->accdb, NULL );

  ulong lam_after = read_lamports( mini, fk0, &reward_key );
  FD_TEST( lam_after == lam_before );
  FD_TEST( bank0->f.capitalization == cap_before );
  FD_TEST( bank0->stake_rewards_fork_id == fork_idx );

  fd_sysvar_epoch_rewards_t er[1];
  FD_TEST( fd_sysvar_epoch_rewards_read( mini->runtime->accdb, fk0, er ) );
  FD_TEST( er->distributed_rewards == 0UL );

  FD_LOG_NOTICE(( "test_store_stake_accounts_in_partition_empty: PASSED" ));
}

static void
test_distribute_rewards_capitalization( fd_svm_mini_t * mini ) {
  fd_svm_mini_params_t params[1];
  fd_svm_mini_params_default( params );
  params->slots_per_epoch    = TEST_SLOTS_PER_EPOCH;
  params->root_slot          = TEST_ROOT_SLOT;
  params->mock_validator_cnt = 1UL;
  ulong root_idx = fd_svm_mini_reset( mini, params );

  fd_bank_t * root_bank = fd_svm_mini_bank( mini, root_idx );
  root_bank->f.inflation = (fd_inflation_t){
    .initial         = 0.08,
    .terminal        = 0.015,
    .taper           = 0.15,
    .foundation      = 0.05,
    .foundation_term = 7.0,
  };

  fd_pubkey_t identity_key, vote_key, stake_key;
  mock_validator_keys( params->hash_seed, &identity_key, &vote_key, &stake_key );
  patch_vote_account( mini, root_idx, &vote_key, 0, 0UL, 2UL, 0UL );

  fd_accdb_fork_id_t root_fk = fd_svm_mini_fork_id( mini, root_idx );
  ulong stake_lam_before = read_lamports( mini, root_fk, &stake_key );

  ulong epoch_idx = fd_svm_mini_attach_child( mini, root_idx, TEST_EPOCH_BOUNDARY );
  fd_svm_mini_freeze( mini, epoch_idx );
  ulong cap_at_epoch = fd_svm_mini_bank( mini, epoch_idx )->f.capitalization;

  ulong distrib_idx = fd_svm_mini_attach_child( mini, epoch_idx, TEST_DISTRIB_SLOT );
  fd_bank_t * distrib_bank = fd_svm_mini_bank( mini, distrib_idx );
  fd_accdb_fork_id_t distrib_fk = fd_svm_mini_fork_id( mini, distrib_idx );

  ulong staker_reward = read_lamports( mini, distrib_fk, &stake_key ) - stake_lam_before;
  FD_TEST( staker_reward > 0UL );
  FD_TEST( distrib_bank->f.capitalization == cap_at_epoch + staker_reward );

  fd_sysvar_epoch_rewards_t er[1];
  if( fd_sysvar_epoch_rewards_read( mini->runtime->accdb, distrib_fk, er ) )
    FD_TEST( er->distributed_rewards >= staker_reward );

  FD_LOG_NOTICE(( "test_distribute_rewards_capitalization: PASSED (reward=%lu, cap_delta=%lu)",
                   staker_reward, distrib_bank->f.capitalization - cap_at_epoch ));
}

static void
test_distribute_empty_rewards( fd_svm_mini_t * mini ) {
  fd_svm_mini_params_t params[1];
  fd_svm_mini_params_default( params );
  params->slots_per_epoch    = TEST_SLOTS_PER_EPOCH;
  params->root_slot          = TEST_ROOT_SLOT;
  params->mock_validator_cnt = 1UL;
  ulong root_idx = fd_svm_mini_reset( mini, params );

  fd_pubkey_t identity_key, vote_key, stake_key;
  mock_validator_keys( params->hash_seed, &identity_key, &vote_key, &stake_key );

  fd_accdb_fork_id_t root_fk = fd_svm_mini_fork_id( mini, root_idx );
  ulong stake_lam_before = read_lamports( mini, root_fk, &stake_key );

  ulong epoch_idx = fd_svm_mini_attach_child( mini, root_idx, TEST_EPOCH_BOUNDARY );
  fd_svm_mini_freeze( mini, epoch_idx );
  ulong cap_at_epoch = fd_svm_mini_bank( mini, epoch_idx )->f.capitalization;

  ulong distrib_idx = fd_svm_mini_attach_child( mini, epoch_idx, TEST_DISTRIB_SLOT );
  fd_bank_t * distrib_bank = fd_svm_mini_bank( mini, distrib_idx );
  fd_accdb_fork_id_t distrib_fk = fd_svm_mini_fork_id( mini, distrib_idx );

  FD_TEST( read_lamports( mini, distrib_fk, &stake_key ) == stake_lam_before );
  FD_TEST( distrib_bank->f.capitalization == cap_at_epoch );

  FD_LOG_NOTICE(( "test_distribute_empty_rewards: PASSED" ));
}

static void
test_get_reward_distribution_num_blocks_cap( void ) {
  fd_epoch_schedule_t schedule = {
    .slots_per_epoch    = 1000UL,
    .warmup             = 0,
    .first_normal_epoch = 0UL,
    .first_normal_slot  = 0UL,
  };

  ulong total_stake_accounts = STAKE_ACCOUNT_STORES_PER_BLOCK * 200UL;
  uint  num_blocks = fd_rewards_get_reward_distribution_num_blocks( &schedule, 0UL, total_stake_accounts );
  uint  cap = (uint)( schedule.slots_per_epoch / MAX_FACTOR_OF_REWARD_BLOCKS_IN_EPOCH );

  FD_TEST( num_blocks == cap );

  FD_LOG_NOTICE(( "test_get_reward_distribution_num_blocks_cap: PASSED" ));
}

static void
test_get_reward_distribution_num_blocks_normal( void ) {
  fd_epoch_schedule_t schedule = {
    .slots_per_epoch    = 1000UL,
    .warmup             = 0,
    .first_normal_epoch = 0UL,
    .first_normal_slot  = 0UL,
  };

  ulong total_stake_accounts = STAKE_ACCOUNT_STORES_PER_BLOCK * 2UL + 1UL;
  uint  num_blocks = fd_rewards_get_reward_distribution_num_blocks( &schedule, 0UL, total_stake_accounts );

  FD_TEST( num_blocks == 3U );

  FD_LOG_NOTICE(( "test_get_reward_distribution_num_blocks_normal: PASSED" ));
}

static void
test_get_reward_distribution_num_blocks_warmup( void ) {
  fd_epoch_schedule_t schedule = {
    .slots_per_epoch             = 64UL,
    .leader_schedule_slot_offset = 64UL,
    .warmup                      = 1,
    .first_normal_epoch          = 1UL,
    .first_normal_slot           = 32UL,
  };

  uint num_blocks = fd_rewards_get_reward_distribution_num_blocks( &schedule, 0UL, 123456UL );

  FD_TEST( num_blocks == 1U );

  FD_LOG_NOTICE(( "test_get_reward_distribution_num_blocks_warmup: PASSED" ));
}

static void
test_get_reward_distribution_num_blocks_none( void ) {
  fd_epoch_schedule_t schedule = {
    .slots_per_epoch    = 1000UL,
    .warmup             = 0,
    .first_normal_epoch = 0UL,
    .first_normal_slot  = 0UL,
  };

  uint num_blocks = fd_rewards_get_reward_distribution_num_blocks( &schedule, 0UL, 0UL );

  FD_TEST( num_blocks == 1U );

  FD_LOG_NOTICE(( "test_get_reward_distribution_num_blocks_none: PASSED" ));
}

int
main( int     argc,
      char ** argv ) {
  fd_svm_mini_limits_t limits[1];
  fd_svm_mini_limits_default( limits );
  fd_svm_mini_t * mini = fd_svm_test_boot( &argc, &argv, limits );

  test_commission_split();
  test_no_credits_no_reward( mini );
  test_credits_staker_reward( mini );
  test_activation_epoch_skips_reward( mini );
  test_zero_inflation_credits_advance( mini );
  test_full_commission_voter_reward( mini );
  test_split_commission_reward( mini );
  test_commission_split_suppresses_reward( mini );
  test_credit_rewind_force_update( mini );
  test_multi_validator_proportional( mini );
  test_calculate_points_typical_values( mini );
  test_epoch_rewards_sysvar_lifecycle( mini );
  test_hash_rewards_into_partitions();
  test_hash_rewards_into_partitions_empty();
  test_distribute_rewards_capitalization( mini );
  test_distribute_empty_rewards( mini );
  test_epoch_credit_rewards_and_history_update( mini );
  test_update_reward_history_in_partition( mini );
  test_build_updated_stake_reward( mini );
  test_update_reward_history_in_partition_empty( mini );
  test_store_stake_accounts_in_partition( mini );
  test_store_stake_accounts_in_partition_empty( mini );
  test_get_reward_distribution_num_blocks_cap();
  test_get_reward_distribution_num_blocks_normal();
  test_get_reward_distribution_num_blocks_warmup();
  test_get_reward_distribution_num_blocks_none();

  FD_LOG_NOTICE(( "pass" ));
  fd_svm_test_halt( mini );
  return 0;
}
