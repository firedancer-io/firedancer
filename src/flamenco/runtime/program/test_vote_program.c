#include "../tests/fd_svm_mini.h"
#include "../../accdb/fd_accdb.h"
#include "../fd_runtime.h"
#include "../fd_bank.h"
#include "../fd_system_ids.h"
#include "../../features/fd_features.h"
#include "../../../ballet/hex/fd_hex.h"
#include "fd_vote_program.h"
#include "vote/fd_vote_codec.h"
#include "vote/fd_authorized_voters.h"
#include "../../../disco/fd_txn_p.h"

#define TEST_SLOTS_PER_EPOCH (32UL)
#define TEST_PARENT_SLOT     (9UL)
#define TEST_CHILD_SLOT      (10UL)

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
  fd_accdb_entry_t entry = fd_accdb_write_one( accdb, fork_id, pubkey->key );
  if( data && dlen ) memcpy( entry.data, data, dlen );
  entry.data_len   = dlen;
  entry.lamports   = lamports;
  entry.executable = 0;
  if( owner ) memcpy( entry.owner, owner->key, 32UL );
  else        memset( entry.owner, 0,          32UL );
  entry.commit = 1;
  fd_accdb_unwrite_one( accdb, &entry );
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

  ulong child_idx = fd_svm_mini_attach_child( mini, root_idx, TEST_CHILD_SLOT );
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

  /* add the blockhash */
  fd_hash_t blockhash[1];
  fd_hex_decode( blockhash, "f6166aa252c9331dc67ac8629abd45483ff31b6a53a8f89704cfd391ee02ba17", 32 );
  fd_blockhashes_push_new( &env->bank->f.block_hash_queue, blockhash );

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

  /* add the blockhash */
  fd_hash_t blockhash[1];
  fd_hex_decode( blockhash, "f6166aa252c9331dc67ac8629abd45483ff31b6a53a8f89704cfd391ee02ba17", 32 );
  fd_blockhashes_push_new( &env->bank->f.block_hash_queue, blockhash );

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
test_account_initialize( fd_svm_mini_t * mini ) {
  static test_env_t env[1];
  setup_test( env, mini );
  setup_account_initialize_txn( env );

  /* Run the vote program */
  fd_runtime_prepare_and_execute_txn( env->mini->runtime, env->bank, env->txn_in, env->txn_out );
  FD_TEST( txn_succeeded( env ) );

  /* Assert that the vote account is now populated */
  fd_accdb_entry_t const * vote_acc = &env->txn_out->accounts.account[1];
  FD_TEST( vote_acc->data_len>0 );
  FD_TEST( !fd_mem_iszero( vote_acc->data, vote_acc->data_len ) );

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

  test_authorized_voters_footprint();
  test_vote_lockouts_footprint();
  test_landed_votes_footprint();
  test_epoch_credits_footprint();
  test_vote_instruction_footprints();

  FD_LOG_NOTICE(( "pass" ));
  fd_svm_test_halt( mini );
  return 0;
}
