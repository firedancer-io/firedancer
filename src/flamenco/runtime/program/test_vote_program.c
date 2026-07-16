#include "../tests/fd_svm_mini.h"
#include "../../accdb/fd_accdb.h"
#include "../fd_runtime.h"
#include "../fd_bank.h"
#include "../fd_system_ids.h"
#include "../../features/fd_features.h"
#include "../../../ballet/hex/fd_hex.h"
#include "vote/fd_vote_codec.h"
#include "vote/fd_vote_state_versioned.h"
#include "../../../disco/fd_txn_p.h"

#define TEST_SLOTS_PER_EPOCH (32UL)
#define TEST_PARENT_SLOT     (9UL)
#define TEST_CHILD_SLOT      (10UL)
#define TEST_GRANDCHILD_SLOT (11UL)

struct test_env {
  fd_svm_mini_t * mini;
  fd_bank_t *     bank;
  fd_txn_p_t      txn_p[1];
  fd_txn_in_t     txn_in[1];
  fd_txn_out_t    txn_out[1];
};
typedef struct test_env test_env_t;

static void
create_account_raw( fd_accdb_t *        accdb,
                    fd_accdb_fork_id_t  fork_id,
                    fd_pubkey_t const * pubkey,
                    ulong               lamports,
                    uint                dlen,
                    uchar *             data,
                    fd_pubkey_t const * owner ) {
  fd_acc_t acc = fd_accdb_write_one( accdb, fork_id, pubkey->key );
  if( data && dlen ) memcpy( acc.data, data, dlen );
  acc.data_len   = dlen;
  acc.lamports   = lamports;
  acc.executable = 0;
  if( owner ) memcpy( acc.owner, owner->key, 32UL );
  else        memset( acc.owner, 0,          32UL );
  acc.commit = 1;
  fd_accdb_unwrite_one( accdb, &acc );
}

static void
create_simple_account( test_env_t * env, fd_pubkey_t const * pubkey, ulong lamports ) {
  create_account_raw( env->mini->runtime->accdb, env->bank->accdb_fork_id, pubkey, lamports, 0UL, NULL, NULL );
}

static int
txn_succeeded( test_env_t * env ) {
  return env->txn_out[0].err.is_committable &&
         env->txn_out[0].err.txn_err == FD_RUNTIME_EXECUTE_SUCCESS;
}

static void
setup_test( test_env_t * env, fd_svm_mini_t * mini ) {
  fd_memset( env, 0, sizeof(test_env_t) );
  env->mini = mini;

  fd_svm_mini_params_t params[1];
  fd_svm_mini_params_default( params );
  params->slots_per_epoch = TEST_SLOTS_PER_EPOCH;
  params->root_slot       = TEST_PARENT_SLOT;
  ulong root_idx  = fd_svm_mini_reset( mini, params );
  fd_bank_t * root_bank = fd_svm_mini_bank( mini, root_idx );
  root_bank->f.epoch = 4UL;

  /* Two fork levels below the (frozen) root: an intermediate fork that
     carries the test blockhash, and the grandchild we actually execute
     on.  fd_svm_mini_register_blockhash registers the blockhash on the
     executing bank's PARENT (the intermediate), which the grandchild
     descends from, so the status-cache query resolves.

     The intermediate bank must be marked frozen before the grandchild
     can be cloned from it (fd_banks_clone_from_parent requires a frozen
     parent).  We mark only the BANK state frozen here, not the full
     fd_svm_mini_freeze: the intermediate's txncache fork is finalized
     later by register_blockhash with the test blockhash, and that
     finalize requires the fork to not already be frozen. */
  ulong inter_idx = fd_svm_mini_attach_child( mini, root_idx,  TEST_CHILD_SLOT      );
  fd_banks_mark_bank_frozen( fd_svm_mini_bank( mini, inter_idx ) );
  ulong child_idx = fd_svm_mini_attach_child( mini, inter_idx, TEST_GRANDCHILD_SLOT );
  env->bank = fd_svm_mini_bank( mini, child_idx );

  fd_features_enable_cleaned_up( &env->bank->f.features );

  /* The block_hash_queue is empty after reset; push a dummy. */
  fd_blockhashes_t * bhq = fd_blockhashes_init( &env->bank->f.block_hash_queue, 12345UL );
  fd_hash_t dummy_hash = {0};
  fd_memset( dummy_hash.uc, 0xAB, FD_HASH_FOOTPRINT );
  fd_blockhash_info_t * info = fd_blockhashes_push_new( bhq, &dummy_hash );
  info->lamports_per_signature = 0UL;
}

static void
setup_account_initialize_txn( test_env_t * env ) {
  /* https://explorer.solana.com/tx/5jvysdwH5a3HCug5AfcJEKgbVGjfKUBiEFtKwrU88QmwUUgVMLqejjAmB3R4xpY7XQGf8VKBXyrNMnu58EFc8L3S */
  static char * hex =
    "03"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "03010407"
    "0880dc185717ce96239eb7bb7260938b79c9e8e00a79f8891f5ed1227f24cd2b" /* signer */
    "ad2277e4f7c1fc98173bfe282470eccbf78c50451f9d9a9aecc0fbe67915af7a" /* vote account */
    "0aa9bcc27d093d38fa5d85cedb7136a5f3ba615782b8c036a7a778563c3796a8"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "06a7d51718c774c928566398691d5eb68b5eb8a39b4b6d5c73555b2100000000"
    "06a7d517192c5c51218cc94c3d4af17f58daee089ba1fd44e3dbd98a00000000"
    "0761481d357474bb7c4d7624ebd3bdb3d8355e73d11043fc0da3538000000000"
    "f6166aa252c9331dc67ac8629abd45483ff31b6a53a8f89704cfd391ee02ba17" /* blockhash */
    "01"
    "06040105040265"
    /* vote.initialize_account */
    "000000000aa9bcc27d093d38fa5d85cedb7136a5f3ba615782b8c036a7a778563c3796a80aa9bcc27d093d38fa5d85cedb7136a5f3ba615782b8c036a7a778563c3796a80880dc185717ce96239eb7bb7260938b79c9e8e00a79f8891f5ed1227f24cd2b64"
  ;

  /* decode and parse txn */
  ulong txn_sz = strlen(hex) / 2;
  env->txn_p->payload_sz = txn_sz;
  fd_hex_decode( env->txn_p->payload, hex, txn_sz );
  FD_TEST( fd_txn_parse( env->txn_p->payload, txn_sz, TXN(env->txn_p), NULL )>0 );

  /* add the blockhash (and register it with the txncache fork so the
     status-cache query/insert during execution can find it) */
  fd_hash_t blockhash[1];
  fd_hex_decode( blockhash, "f6166aa252c9331dc67ac8629abd45483ff31b6a53a8f89704cfd391ee02ba17", 32 );
  fd_blockhashes_push_new( &env->bank->f.block_hash_queue, blockhash );
  fd_svm_mini_register_blockhash( env->mini, env->bank->idx, blockhash );

  /* add the signer to the accdb with 1 SOL */
  fd_pubkey_t pubkey[1];
  fd_hex_decode( pubkey, "0880dc185717ce96239eb7bb7260938b79c9e8e00a79f8891f5ed1227f24cd2b", 32 );
  create_simple_account( env, pubkey, 1000000000UL );

  /* manually create the vote account */
  fd_hex_decode( pubkey, "ad2277e4f7c1fc98173bfe282470eccbf78c50451f9d9a9aecc0fbe67915af7a", 32 );
  uchar data[3762UL] = { 0 };
  create_account_raw( env->mini->runtime->accdb, env->bank->accdb_fork_id, pubkey, 1000000000UL, 3762UL, data, &fd_solana_vote_program_id );

  /* connect txn_in to the input tx */
  env->txn_in->txn              = env->txn_p;
  env->txn_in->bundle.is_bundle = 0;
}

static void
setup_account_initialize_v2_txn( test_env_t * env ) {
  static char * hex =
    "03"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "03010508"
    "0880dc185717ce96239eb7bb7260938b79c9e8e00a79f8891f5ed1227f24cd2b" /* signer */
    "ad2277e4f7c1fc98173bfe282470eccbf78c50451f9d9a9aecc0fbe67915af7a" /* vote account */
    "0aa9bcc27d093d38fa5d85cedb7136a5f3ba615782b8c036a7a778563c3796a8"
    "0000000000000000000000000000000000000000000000000000000000000000"
    "06a7d51718c774c928566398691d5eb68b5eb8a39b4b6d5c73555b2100000000"
    "06a7d517192c5c51218cc94c3d4af17f58daee089ba1fd44e3dbd98a00000000"
    "0761481d357474bb7c4d7624ebd3bdb3d8355e73d11043fc0da3538000000000"
    "0306466fe5211732ffecadba72c39be7bc8ce5bbc5f7126b2c439b3a40000000"
    "f6166aa252c9331dc67ac8629abd45483ff31b6a53a8f89704cfd391ee02ba17" /* blockhash */
    "02"
    /* compute budget */
    "070005"
    "02e5860100"
    /* ix header for vote.initialize_account_v2 */
    "060401050402"
    "B802"
    /* vote.initialize_account_v2 */
    "10000000"
    "0aa9bcc27d093d38fa5d85cedb7136a5f3ba615782b8c036a7a778563c3796a8"
    "0aa9bcc27d093d38fa5d85cedb7136a5f3ba615782b8c036a7a778563c3796a8"
    /* bls pubkey */ "8160635a65d58a24c1b50ea84d957f16f54f4ff7deab3cc8b1858cd18f6ad72c479886092b9d53ebc47deb2660aea3d6"
    /* bls proof  */ "89905944ac6a5e7bf605e1fe69a9602f9bb4c67aa0b41f759497edbed0047a51bd6f9301430433ecbf1eed7b1a3b91351152875251560f859c77444ce342dc322d704a4192c721f5c456a2936dc9eee947750bf18b2b925fd556bff732866231"
    "0880dc185717ce96239eb7bb7260938b79c9e8e00a79f8891f5ed1227f24cd2b"
    "0000"
    "ad2277e4f7c1fc98173bfe282470eccbf78c50451f9d9a9aecc0fbe67915af7a"
    "0000"
    "0aa9bcc27d093d38fa5d85cedb7136a5f3ba615782b8c036a7a778563c3796a8"
  ;

  /* decode and parse txn */
  ulong txn_sz = strlen(hex) / 2;
  env->txn_p->payload_sz = txn_sz;
  fd_hex_decode( env->txn_p->payload, hex, txn_sz );
  FD_TEST( fd_txn_parse( env->txn_p->payload, txn_sz, TXN(env->txn_p), NULL )>0 );

  /* add the blockhash (and register it with the txncache fork so the
     status-cache query/insert during execution can find it) */
  fd_hash_t blockhash[1];
  fd_hex_decode( blockhash, "f6166aa252c9331dc67ac8629abd45483ff31b6a53a8f89704cfd391ee02ba17", 32 );
  fd_blockhashes_push_new( &env->bank->f.block_hash_queue, blockhash );
  fd_svm_mini_register_blockhash( env->mini, env->bank->idx, blockhash );

  /* add the signer to the accdb with 1 SOL */
  fd_pubkey_t pubkey[1];
  fd_hex_decode( pubkey, "0880dc185717ce96239eb7bb7260938b79c9e8e00a79f8891f5ed1227f24cd2b", 32 );
  create_simple_account( env, pubkey, 1000000000UL );

  /* manually create the vote account */
  fd_hex_decode( pubkey, "ad2277e4f7c1fc98173bfe282470eccbf78c50451f9d9a9aecc0fbe67915af7a", 32 );
  uchar data[3762UL] = { 0 };
  create_account_raw( env->mini->runtime->accdb, env->bank->accdb_fork_id, pubkey, 1000000000UL, 3762UL, data, &fd_solana_vote_program_id );

  /* connect txn_in to the input tx */
  env->txn_in->txn              = env->txn_p;
  env->txn_in->bundle.is_bundle = 0;
}

static void
setup_update_commission_collector_txn( test_env_t *        env,
                                       fd_pubkey_t *       collector_pubkey,
                                       uint                kind,
                                       int                 alias_vote_account,
                                       int                 collector_writable,
                                       fd_pubkey_t const * collector_owner,
                                       ulong               collector_lamports ) {
  static char * hex =
    "01"
    "01000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    "010001"
    "04"
    "0880dc185717ce96239eb7bb7260938b79c9e8e00a79f8891f5ed1227f24cd2b" /* signer */
    "ad2277e4f7c1fc98173bfe282470eccbf78c50451f9d9a9aecc0fbe67915af7a" /* vote account */
    "2222222222222222222222222222222222222222222222222222222222222222" /* collector */
    "0761481d357474bb7c4d7624ebd3bdb3d8355e73d11043fc0da3538000000000" /* vote program */
    "f6166aa252c9331dc67ac8629abd45483ff31b6a53a8f89704cfd391ee02ba17" /* blockhash */
    "01"
    "030301020008"
    "1100000000000000" /* UpdateCommissionCollector(InflationRewards) */
  ;

  ulong txn_sz = strlen( hex ) / 2UL;
  env->txn_p->payload_sz = txn_sz;
  fd_hex_decode( env->txn_p->payload, hex, txn_sz );
  FD_TEST( fd_txn_parse( env->txn_p->payload, txn_sz, TXN(env->txn_p), NULL )>0 );

  fd_txn_t * txn = TXN( env->txn_p );
  FD_TEST( txn->instr_cnt==1UL );
  FD_TEST( txn->instr[ 0 ].acct_cnt==3UL );
  FD_TEST( txn->instr[ 0 ].data_sz==8UL );

  if( FD_UNLIKELY( !collector_writable ) ) {
    env->txn_p->payload[ txn->message_off+2UL ] = 2U;
  }
  if( FD_UNLIKELY( alias_vote_account ) ) {
    env->txn_p->payload[ txn->instr[ 0 ].acct_off+1UL ] = 1U;
  }
  fd_memset( env->txn_p->payload+txn->instr[ 0 ].data_off+4UL, 0, sizeof(uint) );
  env->txn_p->payload[ txn->instr[ 0 ].data_off+4UL ] = (uchar)kind;

  FD_TEST( fd_txn_parse( env->txn_p->payload, txn_sz, TXN(env->txn_p), NULL )>0 );

  fd_hex_decode( collector_pubkey, "2222222222222222222222222222222222222222222222222222222222222222", 32UL );
  if( FD_LIKELY( !alias_vote_account ) ) {
    create_account_raw( env->mini->runtime->accdb,
                        env->bank->accdb_fork_id,
                        collector_pubkey,
                        collector_lamports,
                        0UL,
                        NULL,
                        collector_owner );
  }

  fd_memset( env->txn_out, 0, sizeof(env->txn_out) );
  env->txn_in->txn              = env->txn_p;
  env->txn_in->bundle.is_bundle = 0;
}

static void
read_vote_collectors( fd_acc_t const * vote_acc,
                      fd_pubkey_t *    inflation_rewards_collector,
                      fd_pubkey_t *    block_revenue_collector ) {
  fd_vote_state_versioned_t vote_state[1];
  FD_TEST( !fd_vsv_deserialize( vote_acc, vote_state ) );
  FD_TEST( vote_state->kind==fd_vote_state_versioned_enum_v4 );
  *inflation_rewards_collector = vote_state->v4.inflation_rewards_collector;
  *block_revenue_collector     = vote_state->v4.block_revenue_collector;
}

static void
read_persisted_vote_collectors( test_env_t *  env,
                                fd_pubkey_t * inflation_rewards_collector,
                                fd_pubkey_t * block_revenue_collector ) {
  fd_pubkey_t vote_pubkey[1];
  fd_hex_decode( vote_pubkey, "ad2277e4f7c1fc98173bfe282470eccbf78c50451f9d9a9aecc0fbe67915af7a", 32UL );

  fd_acc_t vote_acc = fd_accdb_read_one( env->mini->runtime->accdb, env->bank->accdb_fork_id, vote_pubkey->uc );
  read_vote_collectors( &vote_acc, inflation_rewards_collector, block_revenue_collector );
  fd_accdb_unread_one( env->mini->runtime->accdb, &vote_acc );
}

static void
test_account_initialize( fd_svm_mini_t * mini ) {
  static test_env_t env[1];
  setup_test( env, mini );
  setup_account_initialize_txn( env );

  /* Run the vote program */
  fd_runtime_prepare_and_execute_txn( env->mini->runtime, env->bank, env->txn_in, env->txn_out );
  FD_TEST( txn_succeeded( env ) );

  /* Assert that the vote account is now populated */
  fd_acc_t const * vote_acc = env->txn_out->accounts.account[1];
  FD_TEST( vote_acc->data_len>0 );
  FD_TEST( !fd_mem_iszero( vote_acc->data, vote_acc->data_len ) );
  FD_TEST( env->txn_out->accounts.new_vote[1] );
  FD_TEST( !env->txn_out->accounts.rm_vote[1] );

  FD_LOG_NOTICE(( "test_account_initialize... ok" ));
}

static void
test_account_initialize_simd_0387( fd_svm_mini_t * mini ) {
  static test_env_t env[1];
  setup_test( env, mini );
  setup_account_initialize_txn( env );

  FD_FEATURE_SET_ACTIVE( &env->bank->f.features, vote_state_v4, 0UL );
  FD_FEATURE_SET_ACTIVE( &env->bank->f.features, bls_pubkey_management_in_vote_account, 0UL );

  fd_runtime_prepare_and_execute_txn( env->mini->runtime, env->bank, env->txn_in, env->txn_out );
  FD_TEST( txn_succeeded( env ) );
  FD_TEST( env->txn_out->accounts.new_vote[1] );
  FD_TEST( !env->txn_out->accounts.rm_vote[1] );

  FD_LOG_NOTICE(( "test_account_initialize_simd_0387... ok" ));
}

static void
test_account_initialize_v2_invalid_proof( fd_svm_mini_t * mini ) {
  static test_env_t env[1];
  setup_test( env, mini );
  setup_account_initialize_v2_txn( env );

  /* Invalidate proof */
  ulong proof_off = env->txn_p->payload_sz - 32-2 - 32-2 - 32 - 96;
  env->txn_p->payload[ proof_off ] = 0xFF;

  FD_FEATURE_SET_ACTIVE( &env->bank->f.features, vote_state_v4, 0UL );
  FD_FEATURE_SET_ACTIVE( &env->bank->f.features, bls_pubkey_management_in_vote_account, 0UL );

  fd_runtime_prepare_and_execute_txn( env->mini->runtime, env->bank, env->txn_in, env->txn_out );
  FD_TEST( !txn_succeeded( env ) );

  FD_LOG_NOTICE(( "test_account_initialize_v2_invalid_proof... ok" ));
}

static void
test_account_initialize_v2_no_simd_0387( fd_svm_mini_t * mini ) {
  static test_env_t env[1];
  setup_test( env, mini );
  setup_account_initialize_v2_txn( env );

  fd_runtime_prepare_and_execute_txn( env->mini->runtime, env->bank, env->txn_in, env->txn_out );
  FD_TEST( !txn_succeeded( env ) );

  FD_LOG_NOTICE(( "test_account_initialize_v2_no_simd_0387... ok" ));
}

struct update_commission_collector_test_case {
  char const *        name;
  uint                kind;
  int                 feature_active;
  int                 alias_vote_account;
  int                 collector_writable;
  int                 collector_rent_exempt;
  fd_pubkey_t const * collector_owner;
  int                 expected_err;
};
typedef struct update_commission_collector_test_case update_commission_collector_test_case_t;

static void
run_update_commission_collector_test( fd_svm_mini_t *                                mini,
                                      update_commission_collector_test_case_t const * test_case ) {
  static test_env_t env[1];
  setup_test( env, mini );
  setup_account_initialize_txn( env );

  fd_runtime_prepare_and_execute_txn( env->mini->runtime, env->bank, env->txn_in, env->txn_out );
  FD_TEST( txn_succeeded( env ) );
  fd_runtime_commit_txn( env->mini->runtime, env->bank, NULL, env->txn_out, 0 );

  fd_pubkey_t initial_inflation_rewards_collector[1];
  fd_pubkey_t initial_block_revenue_collector[1];
  read_persisted_vote_collectors( env, initial_inflation_rewards_collector, initial_block_revenue_collector );

  if( test_case->feature_active ) {
    FD_FEATURE_SET_ACTIVE( &env->bank->f.features, custom_commission_collector, 0UL );
  } else {
    FD_TEST( !FD_FEATURE_ACTIVE_BANK( env->bank, custom_commission_collector ) );
  }

  fd_pubkey_t collector_pubkey[1];
  ulong collector_min_balance = fd_rent_exempt_minimum_balance( &env->bank->f.rent, 0UL );
  ulong collector_lamports    = test_case->collector_rent_exempt ? collector_min_balance : collector_min_balance-1UL;
  setup_update_commission_collector_txn( env,
                                         collector_pubkey,
                                         test_case->kind,
                                         test_case->alias_vote_account,
                                         test_case->collector_writable,
                                         test_case->collector_owner,
                                         collector_lamports );

  fd_runtime_prepare_and_execute_txn( env->mini->runtime, env->bank, env->txn_in, env->txn_out );

  fd_pubkey_t actual_inflation_rewards_collector[1];
  fd_pubkey_t actual_block_revenue_collector[1];
  read_vote_collectors( env->txn_out->accounts.account[ 1 ],
                        actual_inflation_rewards_collector,
                        actual_block_revenue_collector );

  if( test_case->expected_err==FD_EXECUTOR_INSTR_SUCCESS ) {
    FD_TEST( txn_succeeded( env ) );

    fd_pubkey_t vote_pubkey[1];
    fd_hex_decode( vote_pubkey, "ad2277e4f7c1fc98173bfe282470eccbf78c50451f9d9a9aecc0fbe67915af7a", 32UL );
    fd_pubkey_t const * expected_collector = test_case->alias_vote_account ? vote_pubkey : collector_pubkey;

    if( test_case->kind==fd_commission_kind_enum_inflation_rewards ) {
      FD_TEST( fd_pubkey_eq( actual_inflation_rewards_collector, expected_collector ) );
      FD_TEST( fd_pubkey_eq( actual_block_revenue_collector, initial_block_revenue_collector ) );
    } else {
      FD_TEST( test_case->kind==fd_commission_kind_enum_block_revenue );
      FD_TEST( fd_pubkey_eq( actual_inflation_rewards_collector, initial_inflation_rewards_collector ) );
      FD_TEST( fd_pubkey_eq( actual_block_revenue_collector, expected_collector ) );
    }
  } else {
    FD_TEST( !txn_succeeded( env ) );
    FD_TEST( env->txn_out->err.is_committable );
    FD_TEST( env->txn_out->err.txn_err==FD_RUNTIME_TXN_ERR_INSTRUCTION_ERROR );
    FD_TEST( env->txn_out->err.exec_err==test_case->expected_err );
    FD_TEST( fd_pubkey_eq( actual_inflation_rewards_collector, initial_inflation_rewards_collector ) );
    FD_TEST( fd_pubkey_eq( actual_block_revenue_collector, initial_block_revenue_collector ) );
  }

  FD_TEST( env->txn_out->err.is_committable );
  fd_runtime_commit_txn( env->mini->runtime, env->bank, NULL, env->txn_out, 0 );

  fd_pubkey_t persisted_inflation_rewards_collector[1];
  fd_pubkey_t persisted_block_revenue_collector[1];
  read_persisted_vote_collectors( env, persisted_inflation_rewards_collector, persisted_block_revenue_collector );
  FD_TEST( fd_pubkey_eq( persisted_inflation_rewards_collector, actual_inflation_rewards_collector ) );
  FD_TEST( fd_pubkey_eq( persisted_block_revenue_collector, actual_block_revenue_collector ) );

  FD_LOG_NOTICE(( "%s... ok", test_case->name ));
}

static void
test_update_commission_collector( fd_svm_mini_t * mini ) {
  update_commission_collector_test_case_t const test_cases[] = {
    { "test_update_commission_collector_inflation_rewards",
      fd_commission_kind_enum_inflation_rewards, 1, 0, 1, 1, &fd_solana_system_program_id, FD_EXECUTOR_INSTR_SUCCESS },
    { "test_update_commission_collector_block_revenue",
      fd_commission_kind_enum_block_revenue,     1, 0, 1, 1, &fd_solana_system_program_id, FD_EXECUTOR_INSTR_SUCCESS },
    { "test_update_commission_collector_vote_account_alias",
      fd_commission_kind_enum_block_revenue,     1, 1, 1, 1, &fd_solana_system_program_id, FD_EXECUTOR_INSTR_SUCCESS },
    { "test_update_commission_collector_feature_disabled",
      fd_commission_kind_enum_inflation_rewards, 0, 0, 1, 1, &fd_solana_system_program_id, FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA },
    { "test_update_commission_collector_invalid_owner",
      fd_commission_kind_enum_inflation_rewards, 1, 0, 1, 1, &fd_solana_vote_program_id,   FD_EXECUTOR_INSTR_ERR_INVALID_ACC_OWNER },
    { "test_update_commission_collector_not_rent_exempt",
      fd_commission_kind_enum_inflation_rewards, 1, 0, 1, 0, &fd_solana_system_program_id, FD_EXECUTOR_INSTR_ERR_INSUFFICIENT_FUNDS },
    { "test_update_commission_collector_read_only",
      fd_commission_kind_enum_inflation_rewards, 1, 0, 0, 1, &fd_solana_system_program_id, FD_EXECUTOR_INSTR_ERR_INVALID_ARG },
  };

  for( ulong i=0UL; i<sizeof(test_cases)/sizeof(test_cases[0]); i++ ) {
    run_update_commission_collector_test( mini, &test_cases[ i ] );
  }
}

static void
test_authorized_voters_footprint( void ) {
  FD_TEST( FD_AUTHORIZED_VOTERS_POOL_ALIGN  == fd_vote_authorized_voters_pool_align() );
  FD_TEST( FD_AUTHORIZED_VOTERS_TREAP_ALIGN == fd_vote_authorized_voters_treap_align() );

  ulong pool_required  = fd_vote_authorized_voters_pool_footprint( MAX_AUTHORIZED_VOTERS_CAPACITY );
  ulong treap_required = fd_vote_authorized_voters_treap_footprint( MAX_AUTHORIZED_VOTERS_CAPACITY );

  FD_LOG_NOTICE(( "authorized voters pool required: %lu, FD_AUTHORIZED_VOTERS_POOL_FOOTPRINT: %lu",
                   pool_required, (ulong)FD_AUTHORIZED_VOTERS_POOL_FOOTPRINT ));
  FD_TEST( pool_required == FD_AUTHORIZED_VOTERS_POOL_FOOTPRINT );

  FD_LOG_NOTICE(( "authorized voters treap required: %lu, FD_AUTHORIZED_VOTERS_TREAP_FOOTPRINT: %lu",
                   treap_required, (ulong)FD_AUTHORIZED_VOTERS_TREAP_FOOTPRINT ));
  FD_TEST( treap_required == FD_AUTHORIZED_VOTERS_TREAP_FOOTPRINT );

  FD_LOG_NOTICE(( "test_authorized_voters_footprint... ok" ));
}

static void
test_vote_lockouts_footprint( void ) {
  FD_TEST( FD_VOTE_INSTR_LOCKOUTS_ALIGN == deq_fd_vote_lockout_t_align() );

  ulong required = deq_fd_vote_lockout_t_footprint( FD_VOTE_INSTR_MAX_LOCKOUT_OFFSETS_LEN );

  FD_LOG_NOTICE(( "vote lockouts required: %lu, FD_VOTE_INSTR_LOCKOUTS_FOOTPRINT: %lu",
                   required, (ulong)FD_VOTE_INSTR_LOCKOUTS_FOOTPRINT ));
  FD_TEST( required == FD_VOTE_INSTR_LOCKOUTS_FOOTPRINT );

  FD_LOG_NOTICE(( "test_vote_lockouts_footprint... ok" ));
}

static void
test_landed_votes_footprint( void ) {
  FD_TEST( FD_LANDED_VOTES_ALIGN == deq_fd_landed_vote_t_align() );

  ulong required = deq_fd_landed_vote_t_footprint( MAX_LOCKOUT_HISTORY_CAPACITY );

  FD_LOG_NOTICE(( "landed votes required: %lu, MAX_LOCKOUT_HISTORY_CAPACITY: %lu",
                   required, (ulong)FD_LANDED_VOTES_FOOTPRINT ));
  FD_TEST( required == FD_LANDED_VOTES_FOOTPRINT );

  FD_LOG_NOTICE(( "test_landed_votes_footprint... ok" ));
}

static void
test_epoch_credits_footprint( void ) {
  FD_TEST( FD_EPOCH_CREDITS_ALIGN == deq_fd_vote_epoch_credits_t_align() );

  ulong required = deq_fd_vote_epoch_credits_t_footprint();

  FD_LOG_NOTICE(( "epoch credits required: %lu, FD_EPOCH_CREDITS_FOOTPRINT: %lu",
                   required, (ulong)FD_EPOCH_CREDITS_FOOTPRINT ));
  FD_TEST( required == FD_EPOCH_CREDITS_FOOTPRINT );

  FD_LOG_NOTICE(( "test_epoch_credits_footprint... ok" ));
}

static void
test_vote_instruction_footprints( void ) {
  FD_TEST( FD_VOTE_INSTR_SLOTS_ALIGN == deq_ulong_align() );
  FD_TEST( FD_VOTE_INSTR_SLOTS_FOOTPRINT == deq_ulong_footprint( FD_VOTE_INSTR_MAX_SLOT_NUMS_LEN ) );

  FD_TEST( FD_VOTE_INSTR_UPDATE_LOCKOUTS_ALIGN == deq_fd_vote_lockout_t_align() );
  FD_TEST( FD_VOTE_INSTR_UPDATE_LOCKOUTS_FOOTPRINT == deq_fd_vote_lockout_t_footprint( FD_VOTE_INSTR_MAX_LOCKOUTS_LEN ) );

  FD_TEST( FD_VOTE_INSTR_LOCKOUT_OFFSET_ALIGN == alignof(fd_lockout_offset_t) );
  FD_TEST( FD_VOTE_INSTR_LOCKOUT_OFFSET_FOOTPRINT == sizeof(fd_lockout_offset_t) * FD_VOTE_INSTR_MAX_LOCKOUT_OFFSETS_LEN );

  FD_TEST( FD_VOTE_INSTR_SEED_MAX == FD_TXN_MTU );

  FD_TEST( FD_VOTE_INSTR_LANDED_VOTES_ALIGN == deq_fd_landed_vote_t_align() );
  FD_TEST( FD_VOTE_INSTR_LANDED_VOTES_FOOTPRINT == deq_fd_landed_vote_t_footprint( FD_VOTE_INSTR_MAX_LOCKOUT_OFFSETS_LEN ) );

  FD_LOG_NOTICE(( "test_vote_instruction_footprints... ok" ));
}

int
main( int     argc,
      char ** argv ) {
  fd_svm_mini_limits_t limits[1];
  fd_svm_mini_limits_default( limits );
  fd_svm_mini_t * mini = fd_svm_test_boot( &argc, &argv, limits );

  test_account_initialize( mini );
  test_account_initialize_simd_0387( mini );
  test_account_initialize_v2_invalid_proof( mini );
  test_account_initialize_v2_no_simd_0387( mini );
  test_update_commission_collector( mini );

  test_authorized_voters_footprint();
  test_vote_lockouts_footprint();
  test_landed_votes_footprint();
  test_epoch_credits_footprint();
  test_vote_instruction_footprints();

  FD_LOG_NOTICE(( "pass" ));
  fd_svm_test_halt( mini );
  return 0;
}
