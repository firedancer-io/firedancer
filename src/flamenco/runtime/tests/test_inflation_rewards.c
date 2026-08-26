#include "fd_svm_mini.h"
#include "../../rewards/fd_alpen_rewards.h"
#include "../../rewards/fd_rewards.h"
#include "../../rewards/fd_rewards_base.h"
#include "../../rewards/fd_stake_rewards.h"
#include "../../stakes/fd_stake_types.h"
#include "../program/fd_vote_program.h"
#include "../program/vote/fd_vote_codec.h"
#include "../program/vote/fd_vote_state_versioned.h"
#include "../sysvar/fd_sysvar_epoch_rewards.h"
#include "../fd_system_ids.h"
#include "../fd_pubkey_utils.h"
#include "../sysvar/fd_sysvar_rent.h"
#include "../../../ballet/hex/fd_hex.h"
#include <stdlib.h>

#define TEST_STAKE_ACCOUNT_STORES_PER_BLOCK (4096UL)
#define TEST_SLOTS_PER_EPOCH                (16UL)
#define TEST_ROOT_SLOT                      (1UL)
#define TEST_EPOCH_BOUNDARY                 (16UL)
#define TEST_DISTRIB_SLOT                   (17UL)

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
  fd_acc_t acc = fd_accdb_read_one( mini->runtime->accdb, fork_id, pubkey->key );
  FD_TEST( acc.lamports > 0UL );
  fd_stake_state_t const * ss = fd_stake_state_view( acc.data, acc.data_len );
  FD_TEST( ss && ss->stake_type==FD_STAKE_STATE_STAKE );
  fd_stake_t s = ss->stake.stake;
  fd_accdb_unread_one( mini->runtime->accdb, &acc );
  return s;
}

static void
mock_validator_keys_idx( ulong         hash_seed,
                         ulong         validator_idx,
                         fd_pubkey_t * identity_out,
                         fd_pubkey_t * vote_out,
                         fd_pubkey_t * stake_out ) {
  /* Mirrors the single RNG stream fd_svm_mini_init_mock_validators
     draws from, so validator i's keys are the i'th triple. */
  fd_rng_t rng[1];
  fd_rng_join( fd_rng_new( rng, (uint)hash_seed, 0UL ) );
  for( ulong i=0UL; i<=validator_idx; i++ ) {
    for( ulong j=0UL; j<4UL; j++ ) identity_out->ul[j] = fd_rng_ulong( rng );
    for( ulong j=0UL; j<4UL; j++ ) vote_out->ul[j]     = fd_rng_ulong( rng );
    for( ulong j=0UL; j<4UL; j++ ) stake_out->ul[j]    = fd_rng_ulong( rng );
  }
  fd_rng_delete( fd_rng_leave( rng ) );
}

static void
mock_validator_keys( ulong         hash_seed,
                     fd_pubkey_t * identity_out,
                     fd_pubkey_t * vote_out,
                     fd_pubkey_t * stake_out ) {
  mock_validator_keys_idx( hash_seed, 0UL, identity_out, vote_out, stake_out );
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

  fd_acc_t acc = fd_accdb_read_one( mini->runtime->accdb, root_fk, vote_key->key );
  FD_TEST( acc.lamports > 0UL );
  ulong data_sz = acc.data_len;
  FD_TEST( data_sz<=FD_VOTE_STATE_V4_SZ );
  uchar data_copy[ FD_VOTE_STATE_V4_SZ ];
  memcpy( data_copy, acc.data, data_sz );
  uchar owner_copy[32]; memcpy( owner_copy, acc.owner, 32 );
  ulong lamports_copy = acc.lamports;
  int   exec_copy     = acc.executable;
  fd_accdb_unread_one( mini->runtime->accdb, &acc );

  fd_vote_state_versioned_t versioned[1];
  FD_TEST( fd_vote_state_versioned_deserialize( versioned, data_copy, data_sz ) );
  fd_vsv_set_commission( versioned, new_commission );
  fd_vote_epoch_credits_t * epoch_credits = fd_vsv_get_epoch_credits_mutable( versioned );
  fd_vote_epoch_credits_t * ec = deq_fd_vote_epoch_credits_t_push_tail_nocopy( epoch_credits );
  *ec = (fd_vote_epoch_credits_t){ .epoch=epoch, .credits=credits, .prev_credits=prev_credits };

  uchar new_data[ FD_VOTE_STATE_V4_SZ ] = {0};
  ulong new_data_sz = versioned->kind==fd_vote_state_versioned_enum_v4 ? FD_VOTE_STATE_V4_SZ : FD_VOTE_STATE_V3_SZ;
  FD_TEST( !fd_vote_state_versioned_serialize( versioned, new_data, new_data_sz ) );

  fd_acc_t new_acc = {0};
  memcpy( new_acc.pubkey, vote_key->key, 32 );
  memcpy( new_acc.owner, owner_copy, 32 );
  new_acc.lamports   = lamports_copy;
  new_acc.executable = exec_copy;
  new_acc.data_len   = new_data_sz;
  new_acc.data       = new_data;
  fd_svm_mini_put_account_rooted( mini, &new_acc );
}

static void
set_account_lamports( fd_svm_mini_t *     mini,
                      ulong               root_idx,
                      fd_pubkey_t const * pubkey,
                      ulong               lamports ) {
  fd_accdb_fork_id_t root_fk = fd_svm_mini_fork_id( mini, root_idx );
  fd_acc_t           acc     = fd_accdb_read_one( mini->runtime->accdb, root_fk, pubkey->uc );
  FD_TEST( acc.lamports>0UL );
  FD_TEST( acc.data_len<=FD_VOTE_STATE_V4_SZ );

  uchar data[ FD_VOTE_STATE_V4_SZ ];
  fd_memcpy( data, acc.data, acc.data_len );
  ulong data_len   = acc.data_len;
  uchar owner[32]; fd_memcpy( owner, acc.owner, 32UL );
  int   executable = acc.executable;
  fd_accdb_unread_one( mini->runtime->accdb, &acc );

  fd_acc_t replacement = {0};
  fd_memcpy( replacement.pubkey, pubkey->uc, 32UL );
  fd_memcpy( replacement.owner, owner, 32UL );
  replacement.lamports   = lamports;
  replacement.executable = executable;
  replacement.data_len   = data_len;
  replacement.data       = data;
  fd_svm_mini_put_account_rooted( mini, &replacement );
}

static void
clone_stake_account( fd_svm_mini_t *     mini,
                     ulong               root_idx,
                     fd_pubkey_t const * src_key,
                     fd_pubkey_t const * dst_key ) {
  fd_accdb_fork_id_t root_fk = fd_svm_mini_fork_id( mini, root_idx );

  fd_acc_t acc = fd_accdb_read_one( mini->runtime->accdb, root_fk, src_key->key );
  FD_TEST( acc.lamports > 0UL );
  ulong data_sz = acc.data_len;
  FD_TEST( data_sz<=FD_STAKE_STATE_SZ );
  uchar data_copy[ FD_STAKE_STATE_SZ ];
  memcpy( data_copy, acc.data, data_sz );
  uchar owner_copy[32]; memcpy( owner_copy, acc.owner, 32 );
  ulong lamports_copy = acc.lamports;
  int   exec_copy     = acc.executable;
  fd_accdb_unread_one( mini->runtime->accdb, &acc );

  fd_acc_t new_acc = {0};
  memcpy( new_acc.pubkey, dst_key->key, 32 );
  memcpy( new_acc.owner, owner_copy, 32 );
  new_acc.lamports   = lamports_copy;
  new_acc.executable = exec_copy;
  new_acc.data_len   = data_sz;
  new_acc.data       = data_copy;
  fd_svm_mini_put_account_rooted( mini, &new_acc );
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
                                          num_partitions,
                                          0UL );
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

  fd_vote_commission_split( 10000, 1000UL, r );
  FD_TEST( r->voter_portion  == 1000UL );
  FD_TEST( r->staker_portion ==    0UL );
  FD_TEST( r->is_split       ==    0U  );

  fd_vote_commission_split( 20000, 1000UL, r );
  FD_TEST( r->voter_portion  == 1000UL );
  FD_TEST( r->staker_portion ==    0UL );
  FD_TEST( r->is_split       ==    0U  );

  fd_vote_commission_split( 5000, 1000UL, r );
  FD_TEST( r->voter_portion  ==  500UL );
  FD_TEST( r->staker_portion ==  500UL );
  FD_TEST( r->is_split       ==    1U  );

  fd_vote_commission_split( 1000, 1000UL, r );
  FD_TEST( r->voter_portion  ==  100UL );
  FD_TEST( r->staker_portion ==  900UL );
  FD_TEST( r->is_split       ==    1U  );

  fd_vote_commission_split( 100, 10UL, r );
  FD_TEST( r->voter_portion  ==  0UL );
  FD_TEST( r->staker_portion ==  9UL );
  FD_TEST( r->is_split       ==  1U  );

  fd_vote_commission_split( 3300, 100UL, r );
  FD_TEST( r->voter_portion  == 33UL );
  FD_TEST( r->staker_portion == 67UL );
  FD_TEST( r->is_split       ==  1U  );

  fd_vote_commission_split( 5000, 0UL, r );
  FD_TEST( r->voter_portion  == 0UL );
  FD_TEST( r->staker_portion == 0UL );

  fd_vote_commission_split( 1, 10000UL, r );
  FD_TEST( r->voter_portion  ==    1UL );
  FD_TEST( r->staker_portion == 9999UL );
  FD_TEST( r->is_split       ==    1U  );

  fd_vote_commission_split( 99, 10000UL, r );
  FD_TEST( r->voter_portion  ==   99UL );
  FD_TEST( r->staker_portion == 9901UL );
  FD_TEST( r->is_split       ==    1U  );

  fd_vote_commission_split( 150, 10000UL, r );
  FD_TEST( r->voter_portion  ==  150UL );
  FD_TEST( r->staker_portion == 9850UL );
  FD_TEST( r->is_split       ==    1U  );

  fd_vote_commission_split( 3333, 10000UL, r );
  FD_TEST( r->voter_portion  == 3333UL );
  FD_TEST( r->staker_portion == 6667UL );
  FD_TEST( r->is_split       ==    1U  );

  fd_vote_commission_split( 7777, 1000UL, r );
  FD_TEST( r->voter_portion  == 777UL );
  FD_TEST( r->staker_portion == 222UL );
  FD_TEST( r->is_split       ==   1U  );

  fd_vote_commission_split( 9999, 10000UL, r );
  FD_TEST( r->voter_portion  == 9999UL );
  FD_TEST( r->staker_portion ==    1UL );
  FD_TEST( r->is_split       ==    1U  );

  FD_LOG_NOTICE(( "test_commission_split: PASSED" ));
}

static fd_pubkey_t
alpenglow_feature_id( void ) {
  fd_pubkey_t id[1];
  FD_TEST( fd_base58_decode_32( "A1PeNGc3D8SQmKwdYf4qj1XG7XgWVSuFQaiJSCQj775h", id->uc ) );
  return *id;
}

static void
activate_alpenglow( fd_svm_mini_t * mini ) {
  fd_pubkey_t id      = alpenglow_feature_id();
  uchar       data[9] = {1};

  fd_acc_t acc = {0};
  fd_memcpy( acc.pubkey, id.uc, 32UL );
  fd_memcpy( acc.owner, fd_solana_feature_program_id.uc, 32UL );
  acc.lamports = 1000000UL;
  acc.data_len = sizeof(data);
  acc.data     = data;
  fd_svm_mini_put_account_rooted( mini, &acc );
}

static fd_pubkey_t
epoch_inflation_account_id( void ) {
  fd_pubkey_t   program_id  = alpenglow_feature_id();
  uchar const   seed[]      = "vote_reward_account";
  uchar const * seeds[1]    = { seed };
  ulong         seed_szs[1] = { sizeof(seed)-1UL };
  fd_pubkey_t   address[1];
  uchar         bump_seed;
  uint          custom_err  = 0U;
  FD_TEST( !fd_pubkey_find_program_address( &program_id, 1UL, seeds, seed_szs,
                                            address, &bump_seed, &custom_err ) );
  return *address;
}

static fd_pubkey_t
reward_epoch_stakes_account_id( void ) {
  fd_pubkey_t   program_id  = alpenglow_feature_id();
  uchar const   seed[]      = "reward_epoch_delegated_stakes";
  uchar const * seeds[1]    = { seed };
  ulong         seed_szs[1] = { sizeof(seed)-1UL };
  fd_pubkey_t   address[1];
  uchar         bump_seed;
  uint          custom_err  = 0U;
  FD_TEST( !fd_pubkey_find_program_address( &program_id, 1UL, seeds, seed_szs,
                                            address, &bump_seed, &custom_err ) );
  return *address;
}

/* Writes the "carlgration" genesis certificate account, marking the
   chain as migrated to alpenglow at migration_slot.  The reward gates
   key on this (rewarded_epoch_is_alpenglow), not on the feature bit. */
static void
set_alpenglow_migration( fd_svm_mini_t * mini,
                         ulong           migration_slot ) {
  fd_pubkey_t   program_id  = alpenglow_feature_id();
  uchar const   seed[]      = "carlgration";
  uchar const * seeds[1]    = { seed };
  ulong         seed_szs[1] = { sizeof(seed)-1UL };
  fd_pubkey_t   address[1];
  uchar         bump_seed;
  uint          custom_err  = 0U;
  FD_TEST( !fd_pubkey_find_program_address( &program_id, 1UL, seeds, seed_szs,
                                            address, &bump_seed, &custom_err ) );

  uchar data[8];
  FD_STORE( ulong, data, migration_slot );

  fd_acc_t acc = {0};
  fd_memcpy( acc.pubkey, address->uc, 32UL );
  fd_memcpy( acc.owner, fd_solana_system_program_id.uc, 32UL );
  acc.lamports = 1000000UL;
  acc.data_len = sizeof(data);
  acc.data     = data;
  fd_svm_mini_put_account_rooted( mini, &acc );
}

static void
init_epoch_inflation_account( fd_svm_mini_t * mini ) {
  fd_pubkey_t address  = epoch_inflation_account_id();
  uchar       data[25] = {0};
  FD_STORE( ulong, data,      1000000UL            ); /* max_possible_validator_reward */
  FD_STORE( ulong, data+8UL,  TEST_SLOTS_PER_EPOCH ); /* slots_per_epoch */
  FD_STORE( ulong, data+16UL, 0UL                  ); /* epoch */
  data[24] = 0U;                                      /* prev = None */

  fd_acc_t acc = {0};
  fd_memcpy( acc.pubkey, address.uc, 32UL );
  fd_memcpy( acc.owner, fd_solana_system_program_id.uc, 32UL );
  acc.lamports = 1000000UL;
  acc.data_len = sizeof(data);
  acc.data     = data;
  fd_svm_mini_put_account_rooted( mini, &acc );
}

static ag_epoch_info_t const *
fixed_epoch_info( void * ctx,
                  ulong  epoch ) {
  (void)epoch;
  return (ag_epoch_info_t const *)ctx;
}

static ulong
vote_last_voted_slot( fd_svm_mini_t *     mini,
                      fd_accdb_fork_id_t  fork_id,
                      fd_pubkey_t const * vote_key ) {
  fd_acc_t acc = fd_accdb_read_one( mini->runtime->accdb, fork_id, vote_key->uc );
  FD_TEST( acc.lamports );
  fd_vote_state_versioned_t vote_state[1];
  FD_TEST( !fd_vsv_deserialize( &acc, vote_state ) );
  ulong const * last_voted_slot = fd_vsv_get_last_voted_slot( vote_state );
  ulong         result          = last_voted_slot ? *last_voted_slot : ULONG_MAX;
  fd_accdb_unread_one( mini->runtime->accdb, &acc );
  return result;
}

static void
test_footer_uses_vote_stakes_rank( fd_svm_mini_t * mini,
                                   int             use_t_3 ) {
  fd_svm_mini_params_t params[1];
  fd_svm_mini_params_default( params );
  params->slots_per_epoch    = TEST_SLOTS_PER_EPOCH;
  params->root_slot          = TEST_ROOT_SLOT;
  params->mock_validator_cnt = 2UL;
  ulong root_idx = fd_svm_mini_reset( mini, params );

  activate_alpenglow( mini );
  set_alpenglow_migration( mini, TEST_ROOT_SLOT );
  init_epoch_inflation_account( mini );

  fd_pubkey_t identity_a, vote_a, stake_a;
  fd_pubkey_t identity_b, vote_b, stake_b;
  mock_validator_keys_idx( params->hash_seed, 0UL, &identity_a, &vote_a, &stake_a );
  mock_validator_keys_idx( params->hash_seed, 1UL, &identity_b, &vote_b, &stake_b );

  ulong reward_slot = use_t_3 ? 10UL : 2UL;
  ulong bank_idx    = fd_svm_mini_attach_child( mini, root_idx, reward_slot+8UL );
  fd_bank_t * bank  = fd_svm_mini_bank( mini, bank_idx );
  FD_FEATURE_SET_ACTIVE( &bank->f.features, alpenglow, 0UL );

  uchar valid_bls[2][ FD_BLS_PUBKEY_COMPRESSED_SZ ];
  fd_hex_decode( valid_bls[0], "97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb", sizeof(valid_bls[0]) );
  fd_hex_decode( valid_bls[1], "af9ff5448e60bc9a718f463ac102bd6f8772e6460c19076a6c89d5806e5a8ef44b6f3b8af09e37a4e564987a26b9deda", sizeof(valid_bls[1]) );

  fd_vote_stakes_t * vote_stakes = fd_bank_vote_stakes( bank );
  fd_vote_stakes_reset( vote_stakes );
  bank->vote_stakes_fork_id = fd_vote_stakes_init( vote_stakes, bank->f.epoch );

  if( use_t_3 ) {
    fd_vote_stakes_snap_insert_t_2( vote_stakes, bank->vote_stakes_fork_id, &vote_b, &identity_b, 200UL, 0U, valid_bls[1] );
    fd_vote_stakes_snap_insert_t_2( vote_stakes, bank->vote_stakes_fork_id, &vote_a, &identity_a, 100UL, 0U, valid_bls[0] );
    fd_vote_stakes_finalize( vote_stakes, bank->f.epoch );

    fd_vote_stakes_snap_insert_t_3( vote_stakes, bank->vote_stakes_fork_id, &vote_a, &identity_a, 200UL, 0U, valid_bls[0] );
    fd_vote_stakes_snap_insert_t_3( vote_stakes, bank->vote_stakes_fork_id, &vote_b, &identity_b, 100UL, 0U, valid_bls[1] );
    fd_vote_stakes_finalize( vote_stakes, bank->f.epoch-1UL );
  } else {
    fd_vote_stakes_snap_insert_t_2( vote_stakes, bank->vote_stakes_fork_id, &vote_a, &identity_a, 200UL, 0U, valid_bls[0] );
    fd_vote_stakes_snap_insert_t_2( vote_stakes, bank->vote_stakes_fork_id, &vote_b, &identity_b, 100UL, 0U, valid_bls[1] );
    fd_vote_stakes_finalize( vote_stakes, bank->f.epoch );
  }

  ag_epoch_info_t wrong_info = { .validator_cnt=1UL, .total_stake=200UL };
  wrong_info.validators[0].id    = 0UL;
  wrong_info.validators[0].stake = 200UL;
  fd_memcpy( wrong_info.validators[0].vote_key, vote_b.uc, sizeof(fd_pubkey_t) );

  fd_reward_cert_t reward_cert = { .slot=reward_slot, .nbits=1U };
  reward_cert.signer_set[0] = 1UL;
  fd_footer_certs_t certs = { .skip_reward_cert=&reward_cert };

  fd_accdb_fork_id_t fork_id = fd_svm_mini_fork_id( mini, bank_idx );
  FD_TEST( vote_last_voted_slot( mini, fork_id, &vote_a )!=reward_slot );
  FD_TEST( !fd_alpen_rewards_apply( bank, mini->runtime->accdb, NULL, &certs, 1000000000UL,
                                    fixed_epoch_info, &wrong_info ) );
  FD_TEST( vote_last_voted_slot( mini, fork_id, &vote_a )==reward_slot );
  FD_TEST( vote_last_voted_slot( mini, fork_id, &vote_b )!=reward_slot );

  ulong final_slot = reward_slot+1UL;
  ag_fast_final_cert_t final_cert = { .slot=final_slot };
  final_cert.agg_sig.bitmask[0] = 1UL;
  certs = (fd_footer_certs_t){ .fast_final_cert=&final_cert };
  FD_TEST( !fd_alpen_rewards_apply( bank, mini->runtime->accdb, NULL, &certs, 1000000000UL,
                                    fixed_epoch_info, &wrong_info ) );
  FD_TEST( vote_last_voted_slot( mini, fork_id, &vote_a )==final_slot );
  FD_TEST( vote_last_voted_slot( mini, fork_id, &vote_b )!=final_slot );
}

/* Writes a VoteStateV4-serialized vote account with the given
   commission (percent), epoch credits, and SIMD-0232 collectors. */
static void
patch_vote_account_v4( fd_svm_mini_t *     mini,
                       fd_pubkey_t const * vote_key,
                       fd_pubkey_t const * node_key,
                       fd_pubkey_t const * inflation_collector,
                       fd_pubkey_t const * block_collector,
                       uchar               commission,
                       ulong               epoch,
                       ulong               credits,
                       ulong               prev_credits ) {
  uchar data[ FD_VOTE_STATE_V4_SZ ] = {0};
  ulong o = 0UL;
  FD_STORE( uint, data+o, 3U ); o += 4UL;                            /* variant = V4 */
  memcpy( data+o, node_key->uc, 32UL ); o += 32UL;                   /* node_pubkey */
  memcpy( data+o, node_key->uc, 32UL ); o += 32UL;                   /* authorized_withdrawer */
  memcpy( data+o, inflation_collector->uc, 32UL ); o += 32UL;        /* inflation_rewards_collector */
  memcpy( data+o, block_collector->uc, 32UL ); o += 32UL;            /* block_revenue_collector */
  FD_STORE( ushort, data+o, (ushort)( (uint)commission*100U ) ); o += 2UL; /* inflation bps */
  FD_STORE( ushort, data+o, (ushort)0 ); o += 2UL;                   /* block revenue bps */
  FD_STORE( ulong, data+o, 0UL ); o += 8UL;                          /* pending_delegator_rewards */
  data[ o++ ] = 1;                                                   /* bls pubkey = Some */
  memset( data+o, 0xBB, FD_BLS_PUBKEY_COMPRESSED_SZ );
  o += FD_BLS_PUBKEY_COMPRESSED_SZ;
  FD_STORE( ulong, data+o, 0UL ); o += 8UL;                          /* votes len */
  data[ o++ ] = 0;                                                   /* root slot = None */
  FD_STORE( ulong, data+o, 0UL ); o += 8UL;                          /* authorized voters len */
  FD_STORE( ulong, data+o, 1UL ); o += 8UL;                          /* epoch credits len */
  FD_STORE( ulong, data+o, epoch ); o += 8UL;
  FD_STORE( ulong, data+o, credits ); o += 8UL;
  FD_STORE( ulong, data+o, prev_credits ); o += 8UL;
  /* last_timestamp (slot, ts) stays zero */

  fd_accdb_fork_id_t root_fk = fd_banks_root( mini->banks )->accdb_fork_id;
  fd_acc_t acc = fd_accdb_read_one( mini->runtime->accdb, root_fk, vote_key->key );
  FD_TEST( acc.lamports>0UL );
  ulong lamports_copy = acc.lamports;
  uchar owner_copy[32]; memcpy( owner_copy, acc.owner, 32 );
  fd_accdb_unread_one( mini->runtime->accdb, &acc );

  fd_acc_t new_acc = {0};
  memcpy( new_acc.pubkey, vote_key->key, 32 );
  memcpy( new_acc.owner, owner_copy, 32 );
  new_acc.lamports = lamports_copy;
  new_acc.data_len = FD_VOTE_STATE_V4_SZ;
  new_acc.data     = data;
  fd_svm_mini_put_account_rooted( mini, &new_acc );
}

static ulong
advance_to_distribution( fd_svm_mini_t * mini, ulong root_idx ) {
  ulong epoch_idx  = fd_svm_mini_attach_child( mini, root_idx,    TEST_EPOCH_BOUNDARY );
  fd_svm_mini_freeze( mini, epoch_idx );
  ulong distrib_idx = fd_svm_mini_attach_child( mini, epoch_idx, TEST_DISTRIB_SLOT );
  return distrib_idx;
}

static void
test_alpenglow_reward_uses_vote_credits( fd_svm_mini_t * mini ) {
  fd_svm_mini_params_t params[1];
  fd_svm_mini_params_default( params );
  params->slots_per_epoch    = TEST_SLOTS_PER_EPOCH;
  params->root_slot          = TEST_ROOT_SLOT;
  params->mock_validator_cnt = 1UL;
  ulong root_idx = fd_svm_mini_reset( mini, params );

  activate_alpenglow( mini );
  set_alpenglow_migration( mini, TEST_ROOT_SLOT );
  init_epoch_inflation_account( mini );

  fd_pubkey_t identity_key, vote_key, stake_key;
  mock_validator_keys( params->hash_seed, &identity_key, &vote_key, &stake_key );
  patch_vote_account( mini, root_idx, &vote_key, 0U, 0UL, 1000UL, 0UL );

  fd_bank_t *        root_bank = fd_svm_mini_bank( mini, root_idx );
  ulong              vat       = fd_slot_params_at_slot( root_bank, TEST_EPOCH_BOUNDARY ).vat_to_burn_per_epoch;
  fd_accdb_fork_id_t root_fk   = fd_svm_mini_fork_id( mini, root_idx );
  set_account_lamports( mini, root_idx, &vote_key, read_lamports( mini, root_fk, &vote_key )+vat );
  ulong vote_before  = read_lamports( mini, root_fk, &vote_key );
  ulong stake_before = read_lamports( mini, root_fk, &stake_key );

  ulong              epoch_idx = fd_svm_mini_attach_child( mini, root_idx, TEST_EPOCH_BOUNDARY );
  fd_accdb_fork_id_t epoch_fk  = fd_svm_mini_fork_id( mini, epoch_idx );

  FD_TEST( read_lamports( mini, epoch_fk, &vote_key )==vote_before-vat );
  FD_TEST( read_lamports( mini, epoch_fk, &fd_sysvar_incinerator_id )==vat );

  fd_pubkey_t inflation_id  = epoch_inflation_account_id();
  fd_acc_t    inflation_acc = fd_accdb_read_one( mini->runtime->accdb, epoch_fk, inflation_id.uc );
  FD_TEST( inflation_acc.lamports>0UL );
  FD_TEST( inflation_acc.data_len==49UL );
  FD_TEST( FD_LOAD( ulong, inflation_acc.data+16UL )==1UL );
  FD_TEST( inflation_acc.data[24UL]==1U );
  FD_TEST( FD_LOAD( ulong, inflation_acc.data+25UL+16UL )==0UL );
  fd_accdb_unread_one( mini->runtime->accdb, &inflation_acc );

  fd_pubkey_t reward_stakes_id  = reward_epoch_stakes_account_id();
  fd_acc_t    reward_stakes_acc = fd_accdb_read_one( mini->runtime->accdb, epoch_fk, reward_stakes_id.uc );
  FD_TEST( reward_stakes_acc.lamports>0UL );
  FD_TEST( reward_stakes_acc.data_len==56UL );
  FD_TEST( FD_LOAD( ulong, reward_stakes_acc.data )==0UL );
  FD_TEST( FD_LOAD( ulong, reward_stakes_acc.data+8UL )==1UL );
  FD_TEST( !memcmp( reward_stakes_acc.data+16UL, vote_key.uc, sizeof(fd_pubkey_t) ) );
  FD_TEST( FD_LOAD( ulong, reward_stakes_acc.data+48UL )==1000000000UL );
  fd_accdb_unread_one( mini->runtime->accdb, &reward_stakes_acc );

  /* Snapshot recalculation must use the persisted denominator, not the
     current epoch's admitted stake. */
  fd_bank_t * epoch_bank = fd_svm_mini_bank( mini, epoch_idx );
  fd_vote_stakes_t * vote_stakes = fd_bank_vote_stakes( epoch_bank );
  fd_vote_stakes_reset( vote_stakes );
  epoch_bank->vote_stakes_fork_id = fd_vote_stakes_init( vote_stakes, epoch_bank->f.epoch );
  uchar no_bls[ FD_BLS_PUBKEY_COMPRESSED_SZ ] = {0};
  fd_vote_stakes_snap_insert_t_1( vote_stakes, epoch_bank->vote_stakes_fork_id, &vote_key, &identity_key, 1000000000UL,    0U, no_bls );
  fd_vote_stakes_snap_insert_t_2( vote_stakes, epoch_bank->vote_stakes_fork_id, &vote_key, &identity_key, 1000000000UL,    0U, no_bls );
  fd_vote_stakes_snap_insert_t_3( vote_stakes, epoch_bank->vote_stakes_fork_id, &vote_key, &identity_key, 1000000000UL, 1234U, no_bls );

  FD_FEATURE_SET_ACTIVE( &epoch_bank->f.features, delay_commission_updates, 0UL );
  fd_stake_rewards_clear( fd_bank_stake_rewards_modify( epoch_bank ) );
  epoch_bank->stake_rewards_fork_id = UCHAR_MAX;
  fd_rewards_recalculate_partitioned_rewards( mini->banks,
                                              epoch_bank,
                                              mini->runtime->accdb,
                                              mini->runtime_stack,
                                              NULL );
  FD_TEST( fd_stake_rewards_total_rewards( fd_bank_stake_rewards_modify( epoch_bank ),
                                           epoch_bank->stake_rewards_fork_id )==876UL );

  epoch_bank->f.features.delay_commission_updates = FD_FEATURE_DISABLED;
  fd_stake_rewards_clear( fd_bank_stake_rewards_modify( epoch_bank ) );
  epoch_bank->stake_rewards_fork_id = UCHAR_MAX;
  fd_rewards_recalculate_partitioned_rewards( mini->banks,
                                              epoch_bank,
                                              mini->runtime->accdb,
                                              mini->runtime_stack,
                                              NULL );
  FD_TEST( fd_stake_rewards_total_rewards( fd_bank_stake_rewards_modify( epoch_bank ),
                                           epoch_bank->stake_rewards_fork_id )==1000UL );

  fd_svm_mini_freeze( mini, epoch_idx );
  ulong              distrib_idx = fd_svm_mini_attach_child( mini, epoch_idx, TEST_DISTRIB_SLOT );
  fd_accdb_fork_id_t distrib_fk  = fd_svm_mini_fork_id( mini, distrib_idx );

  FD_TEST( read_lamports( mini, distrib_fk, &stake_key )==stake_before+1000UL );
  FD_TEST( read_stake( mini, distrib_fk, &stake_key ).credits_observed==1000UL );

  FD_LOG_NOTICE(( "test_alpenglow_reward_uses_vote_credits: PASSED" ));
}

static void
test_alpenglow_preserves_commission_remainder( fd_svm_mini_t * mini ) {
  fd_svm_mini_params_t params[1];
  fd_svm_mini_params_default( params );
  params->slots_per_epoch    = TEST_SLOTS_PER_EPOCH;
  params->root_slot          = TEST_ROOT_SLOT;
  params->mock_validator_cnt = 1UL;
  ulong root_idx = fd_svm_mini_reset( mini, params );

  activate_alpenglow( mini );
  set_alpenglow_migration( mini, TEST_ROOT_SLOT );
  init_epoch_inflation_account( mini );

  fd_pubkey_t identity_key, vote_key, stake_key;
  mock_validator_keys( params->hash_seed, &identity_key, &vote_key, &stake_key );
  patch_vote_account( mini, root_idx, &vote_key, 50U, 0UL, 1UL, 0UL );

  fd_bank_t *        root_bank = fd_svm_mini_bank( mini, root_idx );
  ulong              vat       = fd_slot_params_at_slot( root_bank, TEST_EPOCH_BOUNDARY ).vat_to_burn_per_epoch;
  fd_accdb_fork_id_t root_fk   = fd_svm_mini_fork_id( mini, root_idx );
  set_account_lamports( mini, root_idx, &vote_key, read_lamports( mini, root_fk, &vote_key )+vat );
  ulong vote_before  = read_lamports( mini, root_fk, &vote_key );
  ulong stake_before = read_lamports( mini, root_fk, &stake_key );

  ulong              epoch_idx = fd_svm_mini_attach_child( mini, root_idx, TEST_EPOCH_BOUNDARY );
  fd_accdb_fork_id_t epoch_fk  = fd_svm_mini_fork_id( mini, epoch_idx );
  FD_TEST( read_lamports( mini, epoch_fk, &vote_key )==vote_before-vat+1UL );

  fd_svm_mini_freeze( mini, epoch_idx );
  ulong              distrib_idx = fd_svm_mini_attach_child( mini, epoch_idx, TEST_DISTRIB_SLOT );
  fd_accdb_fork_id_t distrib_fk  = fd_svm_mini_fork_id( mini, distrib_idx );

  FD_TEST( read_lamports( mini, distrib_fk, &stake_key )==stake_before );
  FD_TEST( read_stake( mini, distrib_fk, &stake_key ).credits_observed==1UL );

  FD_LOG_NOTICE(( "test_alpenglow_preserves_commission_remainder: PASSED" ));
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

  fd_acc_t acc = fd_accdb_read_one( mini->runtime->accdb, root_fk, stake_key->key );
  FD_TEST( acc.lamports > 0UL );
  fd_stake_state_t const * ss_orig = fd_stake_state_view( acc.data, acc.data_len );
  FD_TEST( ss_orig && ss_orig->stake_type==FD_STAKE_STATE_STAKE );
  fd_stake_state_t ss_new = *ss_orig;
  ss_new.stake.stake.delegation.activation_epoch = new_activation_epoch;
  uchar owner_copy[32]; memcpy( owner_copy, acc.owner, 32 );
  ulong lamports_copy = acc.lamports;
  int   exec_copy     = acc.executable;
  fd_accdb_unread_one( mini->runtime->accdb, &acc );

  uchar new_data[ FD_STAKE_STATE_SZ ] = {0};
  FD_STORE( fd_stake_state_t, new_data, ss_new );
  fd_acc_t new_acc = {0};
  memcpy( new_acc.pubkey, stake_key->key, 32 );
  memcpy( new_acc.owner, owner_copy, 32 );
  new_acc.lamports   = lamports_copy;
  new_acc.executable = exec_copy;
  new_acc.data_len   = sizeof(new_data);
  new_acc.data       = new_data;
  fd_svm_mini_put_account_rooted( mini, &new_acc );

  fd_stake_delegations_t * sd = fd_banks_stake_delegations_root_query( mini->banks );
  fd_stake_delegations_root_update( sd, stake_key, vote_key,
      ss_new.stake.stake.delegation.stake,
      new_activation_epoch,
      ss_new.stake.stake.delegation.deactivation_epoch,
      ss_new.stake.stake.credits_observed,
      new_acc.lamports,
      (uint)new_acc.data_len,
      FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
}

/* Re-points an existing stake account at a different vote account,
   preserving its activation epoch and stake so it stays fully
   effective. */
static void
redelegate_stake( fd_svm_mini_t *     mini,
                  ulong               root_idx,
                  fd_pubkey_t const * stake_key,
                  fd_pubkey_t const * new_vote_key ) {
  fd_accdb_fork_id_t root_fk = fd_svm_mini_fork_id( mini, root_idx );

  fd_acc_t acc = fd_accdb_read_one( mini->runtime->accdb, root_fk, stake_key->key );
  FD_TEST( acc.lamports > 0UL );
  fd_stake_state_t const * ss_orig = fd_stake_state_view( acc.data, acc.data_len );
  FD_TEST( ss_orig && ss_orig->stake_type==FD_STAKE_STATE_STAKE );
  fd_stake_state_t ss_new = *ss_orig;
  ss_new.stake.stake.delegation.voter_pubkey = *new_vote_key;
  uchar owner_copy[32]; memcpy( owner_copy, acc.owner, 32 );
  ulong lamports_copy = acc.lamports;
  int   exec_copy     = acc.executable;
  fd_accdb_unread_one( mini->runtime->accdb, &acc );

  uchar new_data[ FD_STAKE_STATE_SZ ] = {0};
  FD_STORE( fd_stake_state_t, new_data, ss_new );
  fd_acc_t new_acc = {0};
  memcpy( new_acc.pubkey, stake_key->key, 32 );
  memcpy( new_acc.owner, owner_copy, 32 );
  new_acc.lamports   = lamports_copy;
  new_acc.executable = exec_copy;
  new_acc.data_len   = sizeof(new_data);
  new_acc.data       = new_data;
  fd_svm_mini_put_account_rooted( mini, &new_acc );

  fd_stake_delegations_t * sd = fd_banks_stake_delegations_root_query( mini->banks );
  fd_stake_delegations_root_update( sd, stake_key, new_vote_key,
      ss_new.stake.stake.delegation.stake,
      ss_new.stake.stake.delegation.activation_epoch,
      ss_new.stake.stake.delegation.deactivation_epoch,
      ss_new.stake.stake.credits_observed,
      new_acc.lamports,
      (uint)new_acc.data_len,
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

  /* Under VAT only vote accounts with non-zero effective stake are
     admitted, and an unadmitted voter's delegations are skipped by the
     reward path entirely.  The stake patched above is warming up in the
     rewarded epoch, so give the vote account a second, fully effective
     delegation to keep it admitted.  Otherwise
     force_credits_update_with_skipped_reward is never reached. */
  fd_pubkey_t identity_key_1, vote_key_1, stake_key_1;
  mock_validator_keys_idx( params->hash_seed, 1UL, &identity_key_1, &vote_key_1, &stake_key_1 );
  redelegate_stake( mini, root_idx, &stake_key_1, &vote_key );

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
    fd_acc_t acc = fd_accdb_read_one( mini->runtime->accdb, root_fk, stake_key.key );
    FD_TEST( acc.lamports > 0UL );
    fd_stake_state_t const * ss_orig = fd_stake_state_view( acc.data, acc.data_len );
    FD_TEST( ss_orig && ss_orig->stake_type==FD_STAKE_STATE_STAKE );
    fd_stake_state_t ss_new = *ss_orig;
    ss_new.stake.stake.credits_observed = 10UL;
    uchar owner_copy[32]; memcpy( owner_copy, acc.owner, 32 );
    ulong lamports_copy = acc.lamports;
    int   exec_copy     = acc.executable;
    fd_accdb_unread_one( mini->runtime->accdb, &acc );

    uchar new_data[ FD_STAKE_STATE_SZ ] = {0};
    FD_STORE( fd_stake_state_t, new_data, ss_new );
    fd_acc_t new_acc = {0};
    memcpy( new_acc.pubkey, stake_key.key, 32 );
    memcpy( new_acc.owner, owner_copy, 32 );
    new_acc.lamports   = lamports_copy;
    new_acc.executable = exec_copy;
    new_acc.data_len   = sizeof(new_data);
    new_acc.data       = new_data;
    fd_svm_mini_put_account_rooted( mini, &new_acc );

    fd_stake_delegations_t * sd = fd_banks_stake_delegations_root_query( mini->banks );
    fd_stake_delegations_root_update( sd, &stake_key, &vote_key,
        ss_new.stake.stake.delegation.stake,
        ss_new.stake.stake.delegation.activation_epoch,
        ss_new.stake.stake.delegation.deactivation_epoch,
        10UL,
        new_acc.lamports,
        (uint)new_acc.data_len,
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
  ulong max_forks = 4UL;

  ulong footprint = fd_stake_rewards_footprint( max_accs, max_forks );
  FD_TEST( footprint > 0UL );
  void * mem = aligned_alloc( fd_stake_rewards_align(), footprint );
  FD_TEST( mem );

  fd_stake_rewards_t * sr = fd_stake_rewards_join(
      fd_stake_rewards_new( mem, max_accs, max_forks ) );
  FD_TEST( sr );

  fd_hash_t blockhash = {{ 0 }};
  memset( blockhash.hash, 0xCD, sizeof(blockhash.hash) );

  uint  num_partitions = 5U;
  uchar fork_idx = fd_stake_rewards_init( sr, 1UL, &blockhash, 100UL, num_partitions, 0UL );

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

/* When the rewards of an epoch do not all fit, only a window of the
   partitions is materialized at a time.  Walking the window across the
   epoch, replaying the same inserts each time, must yield every reward
   exactly once and in the same partition it would have landed in had
   everything been resident. */

static void
test_hash_rewards_windowed( void ) {
  ulong const capacity   = 64UL;
  ulong const reward_cnt = 1024UL;
  uint  const num_partitions = 32U;

  ulong footprint = fd_stake_rewards_footprint( capacity, 1UL );
  void * mem = aligned_alloc( fd_stake_rewards_align(), footprint );
  FD_TEST( mem );

  fd_stake_rewards_t * sr = fd_stake_rewards_join(
      fd_stake_rewards_new( mem, capacity, 1UL ) );
  FD_TEST( sr );

  fd_hash_t blockhash = {{ 0 }};
  memset( blockhash.hash, 0xAB, sizeof(blockhash.hash) );

  uchar fork_idx = fd_stake_rewards_init( sr, 1UL, &blockhash, 100UL, num_partitions, reward_cnt );

  /* The window must be a strict subset, otherwise the test is vacuous. */
  FD_TEST( fd_stake_rewards_window_lo( sr, fork_idx )==0U );
  FD_TEST( fd_stake_rewards_window_hi( sr, fork_idx )<num_partitions-1U );

  uchar seen[ 1024 ] = { 0 };
  ulong total_count = 0UL;

  uint  win_lo        = 0U;
  ulong remaining_cnt = reward_cnt;
  ulong remaining_sum = reward_cnt*(reward_cnt+1UL)/2UL;
  while( win_lo<num_partitions ) {
    if( win_lo ) fd_stake_rewards_window_advance( sr, fork_idx, &blockhash, win_lo, remaining_cnt );

    for( ulong i=0UL; i<reward_cnt; i++ ) {
      if( seen[ i ] ) continue;
      fd_pubkey_t pubkey = {{ 0 }};
      FD_STORE( ulong, pubkey.key, i );
      fd_stake_rewards_insert( sr, fork_idx, &pubkey, i+1UL, i );
    }

    /* The total covers everything inserted, not just the window. */
    FD_TEST( fd_stake_rewards_total_rewards( sr, fork_idx )==remaining_sum );

    uint win_hi = fd_stake_rewards_window_hi( sr, fork_idx );
    FD_TEST( win_hi>=win_lo );

    ulong window_count = 0UL;
    ulong window_sum   = 0UL;
    for( uint p=win_lo; p<=win_hi; p++ ) {
      for( fd_stake_rewards_iter_init( sr, fork_idx, p );
           !fd_stake_rewards_iter_done( sr );
           fd_stake_rewards_iter_next( sr, fork_idx ) ) {
        fd_pubkey_t pubkey; ulong lamports, credits_observed;
        fd_stake_rewards_iter_ele( sr, fork_idx, &pubkey, &lamports, &credits_observed );

        ulong i = FD_LOAD( ulong, pubkey.key );
        FD_TEST( i<reward_cnt );
        FD_TEST( !seen[ i ] );
        FD_TEST( lamports==i+1UL );
        FD_TEST( credits_observed==i );
        seen[ i ] = 1;
        window_count++;
        window_sum += lamports;
      }
    }

    total_count   += window_count;
    remaining_cnt -= window_count;
    remaining_sum -= window_sum;
    win_lo         = win_hi+1U;
  }

  FD_TEST( total_count==reward_cnt );
  FD_TEST( !remaining_cnt );
  FD_TEST( !remaining_sum );

  free( mem );

  FD_LOG_NOTICE(( "test_hash_rewards_windowed: PASSED" ));
}

static void
test_hash_rewards_window_sizing( void ) {
  ulong const capacity       = 1024UL;
  uint  const num_partitions = 256U;
  ulong const reward_cnt     = 2048UL; /* eight per partition */

  ulong footprint = fd_stake_rewards_footprint( capacity, 1UL );
  void * mem = aligned_alloc( fd_stake_rewards_align(), footprint );
  FD_TEST( mem );

  fd_stake_rewards_t * sr = fd_stake_rewards_join(
      fd_stake_rewards_new( mem, capacity, 1UL ) );
  FD_TEST( sr );

  fd_hash_t blockhash = {{ 0 }};
  memset( blockhash.hash, 0x5C, sizeof(blockhash.hash) );

  /* 1014 of the 1024 entries are usable, so 126 partitions fit. */
  uchar fork_idx = fd_stake_rewards_init( sr, 1UL, &blockhash, 100UL, num_partitions, reward_cnt );
  FD_TEST( fd_stake_rewards_window_lo( sr, fork_idx )==0U   );
  FD_TEST( fd_stake_rewards_window_hi( sr, fork_idx )==125U );

  /* Paying [0,125] leaves 130 partitions holding 1040 rewards, which is
     still eight per partition, so the next window is just as wide.
     Dividing 1040 by all 256 partitions instead asks for 249, which
     covers the whole remainder and holds all 1040 of them. */
  fd_stake_rewards_window_advance( sr, fork_idx, &blockhash, 126U, 1040UL );
  FD_TEST( fd_stake_rewards_window_lo( sr, fork_idx )==126U );
  FD_TEST( fd_stake_rewards_window_hi( sr, fork_idx )==251U );

  /* Once the remainder fits, the window covers all of it. */
  fd_stake_rewards_window_advance( sr, fork_idx, &blockhash, 252U, 32UL );
  FD_TEST( fd_stake_rewards_window_lo( sr, fork_idx )==252U );
  FD_TEST( fd_stake_rewards_window_hi( sr, fork_idx )==255U );

  free( mem );

  FD_LOG_NOTICE(( "test_hash_rewards_window_sizing: PASSED" ));
}

static void
test_hash_rewards_into_partitions_empty( void ) {
  ulong footprint = fd_stake_rewards_footprint( 1024UL, 4UL );
  void * mem = aligned_alloc( fd_stake_rewards_align(), footprint );
  FD_TEST( mem );

  fd_stake_rewards_t * sr = fd_stake_rewards_join(
      fd_stake_rewards_new( mem, 1024UL, 4UL ) );
  FD_TEST( sr );

  fd_hash_t blockhash = {{ 0 }};
  uint  num_partitions = 5U;
  uchar fork_idx = fd_stake_rewards_init( sr, 1UL, &blockhash, 100UL, num_partitions, 0UL );

  for( uint p=0U; p<num_partitions; p++ ) {
    fd_stake_rewards_iter_init( sr, fork_idx, p );
    FD_TEST( fd_stake_rewards_iter_done( sr ) );
  }
  FD_TEST( fd_stake_rewards_total_rewards( sr, fork_idx ) == 0UL );

  free( mem );

  FD_LOG_NOTICE(( "test_hash_rewards_into_partitions_empty: PASSED" ));
}

static void
test_hash_rewards_pubkeys_across_forks( void ) {
  ulong max_accs  = 4UL;
  ulong max_forks = 3UL;

  FD_TEST( fd_stake_rewards_footprint( 2150000UL, 32UL ) < (4UL<<30) );

  ulong footprint = fd_stake_rewards_footprint( max_accs, max_forks );
  void * mem = aligned_alloc( fd_stake_rewards_align(), footprint );
  FD_TEST( mem );

  fd_stake_rewards_t * sr = fd_stake_rewards_join(
      fd_stake_rewards_new( mem, max_accs, max_forks ) );
  FD_TEST( sr );

  uchar fork_idx[3];
  for( ulong fork=0UL; fork<max_forks; fork++ ) {
    fd_hash_t blockhash = {{ 0 }};
    memset( blockhash.hash, (int)(0xA0UL + fork), sizeof(blockhash.hash) );
    fork_idx[fork] = fd_stake_rewards_init( sr, 1UL, &blockhash, 100UL + fork, 2U, 0UL );

    for( ulong i=0UL; i<max_accs; i++ ) {
      fd_pubkey_t pubkey = {{ 0 }};
      pubkey.ul[0] = (fork & 1UL) * max_accs + i;
      pubkey.ul[1] = 0xF00DUL;
      fd_stake_rewards_insert( sr, fork_idx[fork], &pubkey, (fork + 1UL)*100UL + i, i );
    }
  }

  for( ulong fork=0UL; fork<max_forks; fork++ ) {
    ulong total_count    = 0UL;
    ulong total_lamports = 0UL;
    ulong seen           = 0UL;
    for( uint p=0U; p<2U; p++ ) {
      for( fd_stake_rewards_iter_init( sr, fork_idx[fork], p );
           !fd_stake_rewards_iter_done( sr );
           fd_stake_rewards_iter_next( sr, fork_idx[fork] ) ) {
        fd_pubkey_t pubkey; ulong lamports, credits_observed;
        fd_stake_rewards_iter_ele( sr, fork_idx[fork], &pubkey, &lamports, &credits_observed );
        ulong account_idx = pubkey.ul[0] - (fork & 1UL) * max_accs;
        FD_TEST( account_idx<max_accs );
        FD_TEST( pubkey.ul[1]==0xF00DUL );
        FD_TEST( !(seen & (1UL<<account_idx)) );
        FD_TEST( credits_observed==account_idx );
        FD_TEST( lamports==(fork + 1UL)*100UL + account_idx );
        seen |= 1UL<<account_idx;
        total_count++;
        total_lamports += lamports;
      }
    }

    FD_TEST( total_count    == max_accs );
    FD_TEST( total_lamports == max_accs * (fork + 1UL)*100UL + max_accs * (max_accs - 1UL) / 2UL );
    FD_TEST( fd_stake_rewards_total_rewards( sr, fork_idx[fork] ) == total_lamports );
    FD_TEST( seen == (1UL<<max_accs)-1UL );
  }

  for( ulong fork=0UL; fork<max_forks; fork++ ) fd_stake_rewards_purge( sr, fork_idx[fork] );

  fd_hash_t blockhash = {{ 0 }};
  uchar next_epoch_fork_idx = fd_stake_rewards_init( sr, 2UL, &blockhash, 200UL, 1U, 0UL );
  for( ulong i=0UL; i<max_accs; i++ ) {
    fd_pubkey_t pubkey = {{ 0 }};
    pubkey.ul[0] = max_accs + i;
    fd_stake_rewards_insert( sr, next_epoch_fork_idx, &pubkey, i, i );
  }
  ulong next_epoch_cnt = 0UL;
  for( fd_stake_rewards_iter_init( sr, next_epoch_fork_idx, 0U );
       !fd_stake_rewards_iter_done( sr );
       fd_stake_rewards_iter_next( sr, next_epoch_fork_idx ) ) {
    fd_pubkey_t pubkey; ulong lamports, credits_observed;
    fd_stake_rewards_iter_ele( sr, next_epoch_fork_idx, &pubkey, &lamports, &credits_observed );
    next_epoch_cnt++;
  }
  FD_TEST( next_epoch_cnt==max_accs );

  blockhash.ul[0] = 1UL;
  uchar next_epoch_second_fork_idx = fd_stake_rewards_init( sr, 2UL, &blockhash, 201UL, 1U, 0UL );
  for( ulong i=0UL; i<max_accs; i++ ) {
    fd_pubkey_t pubkey = {{ 0 }};
    pubkey.ul[0] = 2UL*max_accs + i;
    fd_stake_rewards_insert( sr, next_epoch_second_fork_idx, &pubkey, i, i );
  }
  ulong next_epoch_second_cnt  = 0UL;
  ulong next_epoch_second_seen = 0UL;
  for( fd_stake_rewards_iter_init( sr, next_epoch_second_fork_idx, 0U );
       !fd_stake_rewards_iter_done( sr );
       fd_stake_rewards_iter_next( sr, next_epoch_second_fork_idx ) ) {
    fd_pubkey_t pubkey; ulong lamports, credits_observed;
    fd_stake_rewards_iter_ele( sr, next_epoch_second_fork_idx, &pubkey, &lamports, &credits_observed );
    ulong account_idx = pubkey.ul[0] - 2UL*max_accs;
    FD_TEST( account_idx<max_accs );
    FD_TEST( !(next_epoch_second_seen & (1UL<<account_idx)) );
    FD_TEST( lamports==account_idx );
    FD_TEST( credits_observed==account_idx );
    next_epoch_second_seen |= 1UL<<account_idx;
    next_epoch_second_cnt++;
  }
  FD_TEST( next_epoch_second_cnt==max_accs );
  FD_TEST( next_epoch_second_seen==(1UL<<max_accs)-1UL );

  free( mem );

  FD_LOG_NOTICE(( "test_hash_rewards_pubkeys_across_forks: PASSED" ));
}

static void
test_hash_rewards_purge_first_fork( void ) {
  ulong max_accs  = 4UL;
  ulong max_forks = 2UL;

  ulong footprint = fd_stake_rewards_footprint( max_accs, max_forks );
  void * mem = aligned_alloc( fd_stake_rewards_align(), footprint );
  FD_TEST( mem );

  fd_stake_rewards_t * sr = fd_stake_rewards_join(
      fd_stake_rewards_new( mem, max_accs, max_forks ) );
  FD_TEST( sr );

  fd_hash_t blockhash = {{ 0 }};
  fd_pubkey_t pubkey = {{ 0 }};

  uchar first_fork_idx = fd_stake_rewards_init( sr, 1UL, &blockhash, 100UL, 1U, 0UL );
  fd_stake_rewards_insert( sr, first_fork_idx, &pubkey, 1UL, 1UL );
  pubkey.ul[0] = 1UL;
  fd_stake_rewards_insert( sr, first_fork_idx, &pubkey, 2UL, 2UL );
  fd_stake_rewards_purge( sr, first_fork_idx );

  blockhash.ul[0] = 1UL;
  uchar second_fork_idx = fd_stake_rewards_init( sr, 1UL, &blockhash, 101UL, 1U, 0UL );
  pubkey.ul[0] = 2UL;
  fd_stake_rewards_insert( sr, second_fork_idx, &pubkey, 3UL, 3UL );

  fd_stake_rewards_iter_init( sr, second_fork_idx, 0U );
  FD_TEST( !fd_stake_rewards_iter_done( sr ) );
  fd_pubkey_t actual_pubkey; ulong lamports, credits_observed;
  fd_stake_rewards_iter_ele( sr, second_fork_idx, &actual_pubkey, &lamports, &credits_observed );
  FD_TEST( !memcmp( &actual_pubkey, &pubkey, sizeof(fd_pubkey_t) ) );
  FD_TEST( lamports==3UL );
  FD_TEST( credits_observed==3UL );
  fd_stake_rewards_iter_next( sr, second_fork_idx );
  FD_TEST( fd_stake_rewards_iter_done( sr ) );

  free( mem );

  FD_LOG_NOTICE(( "test_hash_rewards_purge_first_fork: PASSED" ));
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

  fd_distribute_partitioned_epoch_rewards( mini->banks, child_bank, mini->runtime->accdb, mini->runtime_stack, NULL );

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
  fd_distribute_partitioned_epoch_rewards( mini->banks, child_bank, mini->runtime->accdb, mini->runtime_stack, NULL );

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

  fd_distribute_partitioned_epoch_rewards( mini->banks, child_bank, mini->runtime->accdb, mini->runtime_stack, NULL );

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
  fd_distribute_partitioned_epoch_rewards( mini->banks, child_bank, mini->runtime->accdb, mini->runtime_stack, NULL );

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

  fd_distribute_partitioned_epoch_rewards( mini->banks, bank0, mini->runtime->accdb, mini->runtime_stack, NULL );

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

  fd_svm_mini_freeze( mini, child_idx0 );
  ulong child_idx1 = fd_svm_mini_attach_child( mini, child_idx0, params->root_slot + 2UL );
  fd_bank_t * bank1 = fd_svm_mini_bank( mini, child_idx1 );
  fd_accdb_fork_id_t fk1 = fd_svm_mini_fork_id( mini, child_idx1 );

  fd_distribute_partitioned_epoch_rewards( mini->banks, bank1, mini->runtime->accdb, mini->runtime_stack, NULL );

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
  fd_distribute_partitioned_epoch_rewards( mini->banks, bank0, mini->runtime->accdb, mini->runtime_stack, NULL );

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

  ulong total_stake_accounts = TEST_STAKE_ACCOUNT_STORES_PER_BLOCK * 200UL;
  uint  num_blocks = fd_rewards_get_reward_distribution_num_blocks( &schedule, 0UL, total_stake_accounts, TEST_STAKE_ACCOUNT_STORES_PER_BLOCK );
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

  ulong total_stake_accounts = TEST_STAKE_ACCOUNT_STORES_PER_BLOCK * 2UL + 1UL;
  uint  num_blocks = fd_rewards_get_reward_distribution_num_blocks( &schedule, 0UL, total_stake_accounts, TEST_STAKE_ACCOUNT_STORES_PER_BLOCK );

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

  uint num_blocks = fd_rewards_get_reward_distribution_num_blocks( &schedule, 0UL, 123456UL, TEST_STAKE_ACCOUNT_STORES_PER_BLOCK );

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

  uint num_blocks = fd_rewards_get_reward_distribution_num_blocks( &schedule, 0UL, 0UL, TEST_STAKE_ACCOUNT_STORES_PER_BLOCK );

  FD_TEST( num_blocks == 1U );

  FD_LOG_NOTICE(( "test_get_reward_distribution_num_blocks_none: PASSED" ));
}

/**********************************************************************/
/* SIMD-0232: inflation rewards commission collectors                 */
/**********************************************************************/

/* Creates the feature account so the activation survives
   fd_features_restore at the epoch boundary. */
static void
activate_feature_account_( fd_svm_mini_t *     mini,
                           fd_pubkey_t const * feature_id ) {
  uchar data[9] = {0};
  data[0] = 1; /* is_active */
  /* activation_slot = 0 */
  fd_acc_t acc = {0};
  memcpy( acc.pubkey, feature_id->uc, 32 );
  memcpy( acc.owner, fd_solana_feature_program_id.uc, 32 );
  acc.lamports = 1000000UL;
  acc.data_len = sizeof(data);
  acc.data     = data;
  fd_svm_mini_put_account_rooted( mini, &acc );
}

static void
activate_custom_commission_collector( fd_svm_mini_t * mini ) {
  fd_pubkey_t feature_id[1];
  FD_TEST( fd_base58_decode_32( "3HcSrCTGXTUnrTueHi4DAwNuMxZSsm5xui2Ax3mgxHqf", feature_id->uc ) );
  activate_feature_account_( mini, feature_id );
}

/* Shared setup: one 100%-commission V4 validator with the given
   inflation collector, feature active.  Returns the distribution fork
   after crossing the boundary. */
static ulong
setup_simd0232_single( fd_svm_mini_t * mini,
                       fd_pubkey_t *   vote_key_out,
                       fd_pubkey_t *   collector,
                       ulong *         root_idx_out ) {
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
  FD_FEATURE_SET_ACTIVE( &root_bank->f.features, custom_commission_collector, 0UL );
  activate_custom_commission_collector( mini );

  fd_pubkey_t identity_key, vote_key, stake_key;
  mock_validator_keys( params->hash_seed, &identity_key, &vote_key, &stake_key );
  patch_vote_account_v4( mini, &vote_key, &identity_key, collector, &identity_key, 100, 0UL, 2UL, 0UL );

  *vote_key_out = vote_key;
  *root_idx_out = root_idx;
  return root_idx;
}

/* Rewards are routed to the override collector; the vote account gets
   nothing. */
static ulong
test_simd0232_collector_reward( fd_svm_mini_t * mini ) {
  fd_pubkey_t collector; memset( collector.uc, 0xC1, 32UL );

  fd_pubkey_t vote_key; ulong root_idx;
  setup_simd0232_single( mini, &vote_key, &collector, &root_idx );

  /* Rent-exempt system account. */
  fd_bank_t * root_bank = fd_svm_mini_bank( mini, root_idx );
  ulong min_bal = fd_rent_exempt_minimum_balance( &root_bank->f.rent, 0UL );
  fd_svm_mini_add_lamports_rooted( mini, &collector, min_bal );

  fd_accdb_fork_id_t root_fk = fd_svm_mini_fork_id( mini, root_idx );
  ulong vote_lam_before      = read_lamports( mini, root_fk, &vote_key );

  ulong distrib_idx = advance_to_distribution( mini, root_idx );
  fd_accdb_fork_id_t distrib_fk = fd_svm_mini_fork_id( mini, distrib_idx );

  ulong collector_lam = read_lamports( mini, distrib_fk, &collector );
  FD_TEST( collector_lam > min_bal );
  ulong reward = collector_lam - min_bal;
  FD_TEST( read_lamports( mini, distrib_fk, &vote_key )==vote_lam_before );

  FD_LOG_NOTICE(( "test_simd0232_collector_reward: PASSED (reward = %lu lamports)", reward ));
  return reward;
}

/* A non-system-owned collector burns the commission; both the
   collector and the vote account are unchanged. */
static void
test_simd0232_invalid_collector_burns( fd_svm_mini_t * mini ) {
  fd_pubkey_t collector; memset( collector.uc, 0xC2, 32UL );

  fd_pubkey_t vote_key; ulong root_idx;
  setup_simd0232_single( mini, &vote_key, &collector, &root_idx );

  /* Collector owned by a non-system program. */
  fd_pubkey_t bad_owner; memset( bad_owner.uc, 0x99, 32UL );
  uchar no_data[1] = {0};
  fd_acc_t bad = {0};
  memcpy( bad.pubkey, collector.uc, 32 );
  memcpy( bad.owner, bad_owner.uc, 32 );
  bad.lamports = 1000000000UL;
  bad.data_len = 0UL;
  bad.data     = no_data;
  fd_svm_mini_put_account_rooted( mini, &bad );

  fd_accdb_fork_id_t root_fk = fd_svm_mini_fork_id( mini, root_idx );
  ulong vote_lam_before      = read_lamports( mini, root_fk, &vote_key );

  ulong distrib_idx = advance_to_distribution( mini, root_idx );
  fd_accdb_fork_id_t distrib_fk = fd_svm_mini_fork_id( mini, distrib_idx );

  FD_TEST( read_lamports( mini, distrib_fk, &collector )==1000000000UL );
  FD_TEST( read_lamports( mini, distrib_fk, &vote_key )==vote_lam_before );

  FD_LOG_NOTICE(( "test_simd0232_invalid_collector_burns: PASSED" ));
}

/* A missing collector account is created when the rewards reach rent
   exemption, and burned when they fall short. */
static void
test_simd0232_collector_rent_exemption( fd_svm_mini_t * mini,
                                        ulong           reward ) {
  fd_bank_t * probe_bank = fd_banks_root( mini->banks );
  ulong min_bal = fd_rent_exempt_minimum_balance( &probe_bank->f.rent, 0UL );
  FD_TEST( reward < min_bal ); /* test setup assumption */

  /* Pre-fund so that (balance + reward) is exactly rent exempt:
     deposit succeeds. */
  {
    fd_pubkey_t collector; memset( collector.uc, 0xC3, 32UL );
    fd_pubkey_t vote_key; ulong root_idx;
    setup_simd0232_single( mini, &vote_key, &collector, &root_idx );
    fd_svm_mini_add_lamports_rooted( mini, &collector, min_bal - reward );

    ulong distrib_idx = advance_to_distribution( mini, root_idx );
    fd_accdb_fork_id_t distrib_fk = fd_svm_mini_fork_id( mini, distrib_idx );
    FD_TEST( read_lamports( mini, distrib_fk, &collector )==min_bal );
  }

  /* One lamport short of rent exemption after the deposit: burned. */
  {
    fd_pubkey_t collector; memset( collector.uc, 0xC4, 32UL );
    fd_pubkey_t vote_key; ulong root_idx;
    setup_simd0232_single( mini, &vote_key, &collector, &root_idx );
    fd_svm_mini_add_lamports_rooted( mini, &collector, min_bal - reward - 1UL );

    ulong distrib_idx = advance_to_distribution( mini, root_idx );
    fd_accdb_fork_id_t distrib_fk = fd_svm_mini_fork_id( mini, distrib_idx );
    FD_TEST( read_lamports( mini, distrib_fk, &collector )==min_bal - reward - 1UL );
  }

  FD_LOG_NOTICE(( "test_simd0232_collector_rent_exemption: PASSED" ));
}

/* Two validators routing to the same collector aggregate their
   rewards. */
static void
test_simd0232_repeated_collector( fd_svm_mini_t * mini ) {
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
  FD_FEATURE_SET_ACTIVE( &root_bank->f.features, custom_commission_collector, 0UL );
  activate_custom_commission_collector( mini );

  fd_pubkey_t collector; memset( collector.uc, 0xC5, 32UL );
  ulong min_bal = fd_rent_exempt_minimum_balance( &root_bank->f.rent, 0UL );
  fd_svm_mini_add_lamports_rooted( mini, &collector, min_bal );

  /* Mock validator keys are drawn sequentially from one rng seeded
     with hash_seed. */
  fd_rng_t rng[1];
  fd_rng_join( fd_rng_new( rng, (uint)params->hash_seed, 0UL ) );
  fd_pubkey_t votes[2];
  for( ulong i=0UL; i<2UL; i++ ) {
    fd_pubkey_t identity_key, vote_key, stake_key;
    for( ulong j=0UL; j<4UL; j++ ) identity_key.ul[j] = fd_rng_ulong( rng );
    for( ulong j=0UL; j<4UL; j++ ) vote_key.ul[j]     = fd_rng_ulong( rng );
    for( ulong j=0UL; j<4UL; j++ ) stake_key.ul[j]    = fd_rng_ulong( rng );
    (void)stake_key;
    patch_vote_account_v4( mini, &vote_key, &identity_key, &collector, &identity_key, 100, 0UL, 2UL, 0UL );
    votes[i] = vote_key;
  }
  fd_rng_delete( fd_rng_leave( rng ) );

  fd_accdb_fork_id_t root_fk = fd_svm_mini_fork_id( mini, root_idx );
  ulong vote0_before = read_lamports( mini, root_fk, &votes[0] );
  ulong vote1_before = read_lamports( mini, root_fk, &votes[1] );

  ulong distrib_idx = advance_to_distribution( mini, root_idx );
  fd_accdb_fork_id_t distrib_fk = fd_svm_mini_fork_id( mini, distrib_idx );

  ulong collector_lam = read_lamports( mini, distrib_fk, &collector );
  FD_TEST( collector_lam > min_bal );
  FD_TEST( read_lamports( mini, distrib_fk, &votes[0] )==vote0_before );
  FD_TEST( read_lamports( mini, distrib_fk, &votes[1] )==vote1_before );

  FD_LOG_NOTICE(( "test_simd0232_repeated_collector: PASSED (aggregated = %lu lamports)", collector_lam - min_bal ));
}

/* Commission routed to another vote account is burned; that vote
   account keeps only its own self-collected reward. */
static void
test_simd0232_vote_account_collector_burns_external( fd_svm_mini_t * mini ) {
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
  FD_FEATURE_SET_ACTIVE( &root_bank->f.features, custom_commission_collector, 0UL );
  activate_custom_commission_collector( mini );

  fd_rng_t rng[1];
  fd_rng_join( fd_rng_new( rng, (uint)params->hash_seed, 0UL ) );
  fd_pubkey_t identities[2], votes[2];
  for( ulong i=0UL; i<2UL; i++ ) {
    fd_pubkey_t identity_key, vote_key, stake_key;
    for( ulong j=0UL; j<4UL; j++ ) identity_key.ul[j] = fd_rng_ulong( rng );
    for( ulong j=0UL; j<4UL; j++ ) vote_key.ul[j]     = fd_rng_ulong( rng );
    for( ulong j=0UL; j<4UL; j++ ) stake_key.ul[j]    = fd_rng_ulong( rng );
    (void)stake_key;
    identities[i] = identity_key;
    votes[i]      = vote_key;
  }
  fd_rng_delete( fd_rng_leave( rng ) );

  /* Validator 0 routes to validator 1's vote account; validator 1
     collects for itself (default). */
  patch_vote_account_v4( mini, &votes[0], &identities[0], &votes[1], &identities[0], 100, 0UL, 2UL, 0UL );
  patch_vote_account_v4( mini, &votes[1], &identities[1], &votes[1], &identities[1], 100, 0UL, 2UL, 0UL );

  fd_accdb_fork_id_t root_fk = fd_svm_mini_fork_id( mini, root_idx );
  ulong vote0_before = read_lamports( mini, root_fk, &votes[0] );
  ulong vote1_before = read_lamports( mini, root_fk, &votes[1] );

  ulong distrib_idx = advance_to_distribution( mini, root_idx );
  fd_accdb_fork_id_t distrib_fk = fd_svm_mini_fork_id( mini, distrib_idx );

  /* Equal stake and credits: both earned the same reward R.  B must
     gain exactly its own R, with A's R burned. */
  ulong vote1_after = read_lamports( mini, distrib_fk, &votes[1] );
  FD_TEST( read_lamports( mini, distrib_fk, &votes[0] )==vote0_before );
  FD_TEST( vote1_after > vote1_before );
  ulong vote1_gain = vote1_after - vote1_before;

  FD_LOG_NOTICE(( "test_simd0232_vote_account_collector_burns_external: PASSED (self reward = %lu)", vote1_gain ));
}

/* Commission routed to a vote account that earns no commission of its
   own is still burned: the collector is not system-owned. */
static void
test_simd0232_zero_commission_vote_collector_burns( fd_svm_mini_t * mini ) {
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
  FD_FEATURE_SET_ACTIVE( &root_bank->f.features, custom_commission_collector, 0UL );
  activate_custom_commission_collector( mini );

  fd_rng_t rng[1];
  fd_rng_join( fd_rng_new( rng, (uint)params->hash_seed, 0UL ) );
  fd_pubkey_t identities[2], votes[2];
  for( ulong i=0UL; i<2UL; i++ ) {
    fd_pubkey_t identity_key, vote_key, stake_key;
    for( ulong j=0UL; j<4UL; j++ ) identity_key.ul[j] = fd_rng_ulong( rng );
    for( ulong j=0UL; j<4UL; j++ ) vote_key.ul[j]     = fd_rng_ulong( rng );
    for( ulong j=0UL; j<4UL; j++ ) stake_key.ul[j]    = fd_rng_ulong( rng );
    (void)stake_key;
    identities[i] = identity_key;
    votes[i]      = vote_key;
  }
  fd_rng_delete( fd_rng_leave( rng ) );

  /* Validator 0: 100% commission routed to validator 1's vote account.
     Validator 1: 0% commission (earns no commission of its own). */
  patch_vote_account_v4( mini, &votes[0], &identities[0], &votes[1], &identities[0], 100, 0UL, 2UL, 0UL );
  patch_vote_account_v4( mini, &votes[1], &identities[1], &votes[1], &identities[1], 0, 0UL, 2UL, 0UL );

  fd_accdb_fork_id_t root_fk = fd_svm_mini_fork_id( mini, root_idx );
  ulong vote0_before = read_lamports( mini, root_fk, &votes[0] );
  ulong vote1_before = read_lamports( mini, root_fk, &votes[1] );

  ulong distrib_idx = advance_to_distribution( mini, root_idx );
  fd_accdb_fork_id_t distrib_fk = fd_svm_mini_fork_id( mini, distrib_idx );

  FD_TEST( read_lamports( mini, distrib_fk, &votes[0] )==vote0_before );
  FD_TEST( read_lamports( mini, distrib_fk, &votes[1] )==vote1_before );

  FD_LOG_NOTICE(( "test_simd0232_zero_commission_vote_collector_burns: PASSED" ));
}

/* Rewards routed to the incinerator are deposited without a rent
   check and burned at the end of the block. */
static void
test_simd0232_incinerator_collector( fd_svm_mini_t * mini ) {
  fd_pubkey_t vote_key; ulong root_idx;
  fd_pubkey_t incinerator = fd_sysvar_incinerator_id;
  setup_simd0232_single( mini, &vote_key, &incinerator, &root_idx );

  fd_accdb_fork_id_t root_fk = fd_svm_mini_fork_id( mini, root_idx );
  ulong vote_lam_before      = read_lamports( mini, root_fk, &vote_key );

  ulong distrib_idx = advance_to_distribution( mini, root_idx );
  fd_accdb_fork_id_t distrib_fk = fd_svm_mini_fork_id( mini, distrib_idx );

  /* The incinerator is cleared at the end of the boundary block. */
  FD_TEST( read_lamports( mini, distrib_fk, &incinerator )==0UL );
  FD_TEST( read_lamports( mini, distrib_fk, &vote_key )==vote_lam_before );

  FD_LOG_NOTICE(( "test_simd0232_incinerator_collector: PASSED" ));
}

/* Burned commission still counts into the EpochRewards sysvar's
   distributed_rewards: with a single 100%-commission validator whose
   collector is invalid, everything burns yet distributed equals the
   epoch total. */
static void
test_simd0232_burn_counts_in_sysvar( fd_svm_mini_t * mini,
                                     ulong           reward ) {
  fd_pubkey_t collector; memset( collector.uc, 0xC6, 32UL );

  fd_pubkey_t vote_key; ulong root_idx;
  setup_simd0232_single( mini, &vote_key, &collector, &root_idx );

  /* Non-system owner: the commission burns. */
  fd_pubkey_t bad_owner; memset( bad_owner.uc, 0x98, 32UL );
  uchar no_data[1] = {0};
  fd_acc_t bad = {0};
  memcpy( bad.pubkey, collector.uc, 32 );
  memcpy( bad.owner, bad_owner.uc, 32 );
  bad.lamports = 1000000000UL;
  bad.data_len = 0UL;
  bad.data     = no_data;
  fd_svm_mini_put_account_rooted( mini, &bad );

  fd_accdb_fork_id_t root_fk = fd_svm_mini_fork_id( mini, root_idx );
  ulong vote_lam_before      = read_lamports( mini, root_fk, &vote_key );

  ulong epoch_idx = fd_svm_mini_attach_child( mini, root_idx, TEST_EPOCH_BOUNDARY );
  fd_accdb_fork_id_t epoch_fk = fd_svm_mini_fork_id( mini, epoch_idx );

  FD_TEST( read_lamports( mini, epoch_fk, &collector )==1000000000UL );
  FD_TEST( read_lamports( mini, epoch_fk, &vote_key )==vote_lam_before );

  /* The commission (the full epoch total at 100% commission) burned,
     but distributed_rewards still accounts for it.  The absolute value
     is near the reference reward, scaled slightly by the extra
     capitalization the collector account added. */
  fd_sysvar_epoch_rewards_t er[1];
  FD_TEST( fd_sysvar_epoch_rewards_read( mini->runtime->accdb, epoch_fk, er ) );
  FD_TEST( er->distributed_rewards>0UL );
  FD_TEST( er->distributed_rewards==er->total_rewards );
  FD_TEST( er->distributed_rewards>=reward );

  FD_LOG_NOTICE(( "test_simd0232_burn_counts_in_sysvar: PASSED (burned = %lu)", er->distributed_rewards ));
}

/* An absent collector is not created when the commission falls short
   of rent exemption, and is created system-owned when it reaches it. */
static void
test_simd0232_absent_collector( fd_svm_mini_t * mini,
                                ulong           reward ) {
  /* Below rent exemption: burned, account never created. */
  {
    fd_pubkey_t collector; memset( collector.uc, 0xC7, 32UL );
    fd_pubkey_t vote_key; ulong root_idx;
    setup_simd0232_single( mini, &vote_key, &collector, &root_idx );

    ulong distrib_idx = advance_to_distribution( mini, root_idx );
    fd_accdb_fork_id_t distrib_fk = fd_svm_mini_fork_id( mini, distrib_idx );
    FD_TEST( read_lamports( mini, distrib_fk, &collector )==0UL );
  }

  /* Boosted inflation so the commission alone reaches rent exemption:
     the account is created, owned by the system program. */
  {
    fd_pubkey_t collector; memset( collector.uc, 0xC8, 32UL );
    fd_pubkey_t vote_key; ulong root_idx;
    setup_simd0232_single( mini, &vote_key, &collector, &root_idx );

    fd_bank_t * root_bank = fd_svm_mini_bank( mini, root_idx );
    ulong  min_bal = fd_rent_exempt_minimum_balance( &root_bank->f.rent, 0UL );
    double boost   = (double)( 4UL*min_bal )/(double)reward + 1.0;
    root_bank->f.inflation.initial  *= boost;
    root_bank->f.inflation.terminal *= boost;

    ulong distrib_idx = advance_to_distribution( mini, root_idx );
    fd_accdb_fork_id_t distrib_fk = fd_svm_mini_fork_id( mini, distrib_idx );

    fd_acc_t acc = fd_accdb_read_one( mini->runtime->accdb, distrib_fk, collector.key );
    FD_TEST( acc.lamports>=min_bal );
    FD_TEST( !memcmp( acc.owner, fd_solana_system_program_id.uc, 32UL ) );
    FD_TEST( acc.data_len==0UL );
    fd_accdb_unread_one( mini->runtime->accdb, &acc );
  }

  FD_LOG_NOTICE(( "test_simd0232_absent_collector: PASSED" ));
}

/* With relax_post_exec_min_balance_check active, a pre-existing
   rent-paying collector still receives the deposit. */
static void
test_simd0232_relax_deposit( fd_svm_mini_t * mini,
                             ulong           reward ) {
  fd_pubkey_t collector; memset( collector.uc, 0xC9, 32UL );

  fd_pubkey_t vote_key; ulong root_idx;
  setup_simd0232_single( mini, &vote_key, &collector, &root_idx );

  fd_bank_t * root_bank = fd_svm_mini_bank( mini, root_idx );
  FD_FEATURE_SET_ACTIVE( &root_bank->f.features, relax_post_exec_min_balance_check, 0UL );
  fd_pubkey_t relax_id[1];
  FD_TEST( fd_base58_decode_32( "BY4JhHLahVzS9ynfDz4exzGPbVXhFmJvEyMWsXbDBqME", relax_id->uc ) );
  activate_feature_account_( mini, relax_id );

  /* One lamport: rent-paying before and after the deposit. */
  fd_svm_mini_add_lamports_rooted( mini, &collector, 1UL );

  ulong distrib_idx = advance_to_distribution( mini, root_idx );
  fd_accdb_fork_id_t distrib_fk = fd_svm_mini_fork_id( mini, distrib_idx );

  FD_TEST( read_lamports( mini, distrib_fk, &collector )==1UL+reward );

  FD_LOG_NOTICE(( "test_simd0232_relax_deposit: PASSED" ));
}

/* A reserved key never receives the commission, even when the account
   is system-owned and rent-exempt. */
static void
test_simd0232_reserved_collector_burns( fd_svm_mini_t * mini ) {
  fd_pubkey_t collector = fd_sysvar_rewards_id;

  fd_pubkey_t vote_key; ulong root_idx;
  setup_simd0232_single( mini, &vote_key, &collector, &root_idx );

  uchar no_data[1] = {0};
  fd_acc_t acc = {0};
  memcpy( acc.pubkey, collector.uc, 32 );
  memcpy( acc.owner, fd_solana_system_program_id.uc, 32 );
  acc.lamports = 1000000000UL;
  acc.data_len = 0UL;
  acc.data     = no_data;
  fd_svm_mini_put_account_rooted( mini, &acc );

  ulong distrib_idx = advance_to_distribution( mini, root_idx );
  fd_accdb_fork_id_t distrib_fk = fd_svm_mini_fork_id( mini, distrib_idx );

  FD_TEST( read_lamports( mini, distrib_fk, &collector )==1000000000UL );

  FD_LOG_NOTICE(( "test_simd0232_reserved_collector_burns: PASSED" ));
}

/* A deposit that would overflow the collector's balance burns. */
static void
test_simd0232_overflow_burns( fd_svm_mini_t * mini ) {
  fd_pubkey_t collector; memset( collector.uc, 0xCA, 32UL );

  fd_pubkey_t vote_key; ulong root_idx;
  setup_simd0232_single( mini, &vote_key, &collector, &root_idx );

  uchar no_data[1] = {0};
  fd_acc_t acc = {0};
  memcpy( acc.pubkey, collector.uc, 32 );
  memcpy( acc.owner, fd_solana_system_program_id.uc, 32 );
  acc.lamports = ULONG_MAX-1UL;
  acc.data_len = 0UL;
  acc.data     = no_data;
  fd_svm_mini_put_account_rooted( mini, &acc );

  ulong distrib_idx = advance_to_distribution( mini, root_idx );
  fd_accdb_fork_id_t distrib_fk = fd_svm_mini_fork_id( mini, distrib_idx );

  FD_TEST( read_lamports( mini, distrib_fk, &collector )==ULONG_MAX-1UL );

  FD_LOG_NOTICE(( "test_simd0232_overflow_burns: PASSED" ));
}

/* An explicit self collector (the vote account's own pubkey) receives
   the commission without any of the external-collector checks. */
static void
test_simd0232_self_collector( fd_svm_mini_t * mini ) {
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
  FD_FEATURE_SET_ACTIVE( &root_bank->f.features, custom_commission_collector, 0UL );
  activate_custom_commission_collector( mini );

  fd_pubkey_t identity_key, vote_key, stake_key;
  mock_validator_keys( params->hash_seed, &identity_key, &vote_key, &stake_key );
  patch_vote_account_v4( mini, &vote_key, &identity_key, &vote_key, &identity_key, 100, 0UL, 2UL, 0UL );

  fd_accdb_fork_id_t root_fk = fd_svm_mini_fork_id( mini, root_idx );
  ulong vote_lam_before      = read_lamports( mini, root_fk, &vote_key );

  ulong distrib_idx = advance_to_distribution( mini, root_idx );
  fd_accdb_fork_id_t distrib_fk = fd_svm_mini_fork_id( mini, distrib_idx );

  FD_TEST( read_lamports( mini, distrib_fk, &vote_key )>vote_lam_before );

  FD_LOG_NOTICE(( "test_simd0232_self_collector: PASSED" ));
}

/* Rewards recalculation (snapshot restore) rebuilds the stake
   partitions without touching commission collectors or the sysvar. */
static void
test_simd0232_recalc_ignores_commission( fd_svm_mini_t * mini ) {
  fd_pubkey_t collector; memset( collector.uc, 0xCB, 32UL );

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
  FD_FEATURE_SET_ACTIVE( &root_bank->f.features, custom_commission_collector, 0UL );
  activate_custom_commission_collector( mini );

  ulong min_bal = fd_rent_exempt_minimum_balance( &root_bank->f.rent, 0UL );
  fd_svm_mini_add_lamports_rooted( mini, &collector, min_bal );

  /* 50% commission so both a commission and a staker portion exist. */
  fd_pubkey_t identity_key, vote_key, stake_key;
  mock_validator_keys( params->hash_seed, &identity_key, &vote_key, &stake_key );
  patch_vote_account_v4( mini, &vote_key, &identity_key, &collector, &identity_key, 50, 0UL, 2UL, 0UL );

  ulong epoch_idx = fd_svm_mini_attach_child( mini, root_idx, TEST_EPOCH_BOUNDARY );
  fd_svm_mini_freeze( mini, epoch_idx );
  fd_bank_t * epoch_bank = fd_svm_mini_bank( mini, epoch_idx );
  fd_accdb_fork_id_t epoch_fk = fd_svm_mini_fork_id( mini, epoch_idx );

  ulong collector_after_boundary = read_lamports( mini, epoch_fk, &collector );
  FD_TEST( collector_after_boundary>min_bal );

  fd_sysvar_epoch_rewards_t er_before[1];
  FD_TEST( fd_sysvar_epoch_rewards_read( mini->runtime->accdb, epoch_fk, er_before ) );

  fd_stake_rewards_t * stake_rewards = fd_bank_stake_rewards_modify( epoch_bank );
  ulong staker_total = fd_stake_rewards_total_rewards( stake_rewards, epoch_bank->stake_rewards_fork_id );
  FD_TEST( staker_total>0UL );

  /* Simulate a restart: drop the partitions and recalculate. */
  fd_stake_rewards_clear( stake_rewards );
  epoch_bank->stake_rewards_fork_id = UCHAR_MAX;
  fd_rewards_recalculate_partitioned_rewards( mini->banks, epoch_bank, mini->runtime->accdb, mini->runtime_stack, NULL );

  FD_TEST( epoch_bank->stake_rewards_fork_id!=UCHAR_MAX );
  FD_TEST( fd_stake_rewards_total_rewards( fd_bank_stake_rewards_modify( epoch_bank ), epoch_bank->stake_rewards_fork_id )==staker_total );

  /* The collector and the sysvar are untouched by recalculation. */
  FD_TEST( read_lamports( mini, epoch_fk, &collector )==collector_after_boundary );
  fd_sysvar_epoch_rewards_t er_after[1];
  FD_TEST( fd_sysvar_epoch_rewards_read( mini->runtime->accdb, epoch_fk, er_after ) );
  FD_TEST( er_after->distributed_rewards==er_before->distributed_rewards );
  FD_TEST( er_after->total_rewards==er_before->total_rewards );

  /* Distribution still pays the staker exactly once. */
  fd_pubkey_t stake_only = stake_key;
  ulong stake_lam_before = read_lamports( mini, epoch_fk, &stake_only );
  ulong distrib_idx = fd_svm_mini_attach_child( mini, epoch_idx, TEST_DISTRIB_SLOT );
  fd_accdb_fork_id_t distrib_fk = fd_svm_mini_fork_id( mini, distrib_idx );
  FD_TEST( read_lamports( mini, distrib_fk, &stake_only )==stake_lam_before+staker_total );
  FD_TEST( read_lamports( mini, distrib_fk, &collector )==collector_after_boundary );

  FD_LOG_NOTICE(( "test_simd0232_recalc_ignores_commission: PASSED (commission=%lu staker=%lu)",
                  collector_after_boundary-min_bal, staker_total ));
}

int
main( int     argc,
      char ** argv ) {
  fd_svm_mini_limits_t limits[1];
  fd_svm_mini_limits_default( limits );
  fd_svm_mini_t * mini = fd_svm_test_boot( &argc, &argv, limits );

  test_commission_split();
  test_footer_uses_vote_stakes_rank( mini, 0 );
  test_footer_uses_vote_stakes_rank( mini, 1 );
  test_alpenglow_reward_uses_vote_credits( mini );
  test_alpenglow_preserves_commission_remainder( mini );
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
  test_hash_rewards_windowed();
  test_hash_rewards_window_sizing();
  test_hash_rewards_into_partitions_empty();
  test_hash_rewards_pubkeys_across_forks();
  test_hash_rewards_purge_first_fork();
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

  ulong simd0232_reward = test_simd0232_collector_reward( mini );
  test_simd0232_invalid_collector_burns( mini );
  test_simd0232_collector_rent_exemption( mini, simd0232_reward );
  test_simd0232_repeated_collector( mini );
  test_simd0232_vote_account_collector_burns_external( mini );
  test_simd0232_zero_commission_vote_collector_burns( mini );
  test_simd0232_incinerator_collector( mini );
  test_simd0232_burn_counts_in_sysvar( mini, simd0232_reward );
  test_simd0232_absent_collector( mini, simd0232_reward );
  test_simd0232_relax_deposit( mini, simd0232_reward );
  test_simd0232_reserved_collector_burns( mini );
  test_simd0232_overflow_burns( mini );
  test_simd0232_self_collector( mini );
  test_simd0232_recalc_ignores_commission( mini );

  FD_LOG_NOTICE(( "pass" ));
  fd_svm_test_halt( mini );
  return 0;
}
