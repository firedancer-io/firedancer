#include "../tests/fd_svm_mini.h"
#include "../../accdb/fd_accdb.h"
#include "../fd_runtime.h"
#include "../fd_bank.h"
#include "../fd_system_ids.h"
#include "fd_vote_program.h"
#include "../../features/fd_features.h"
#include "../../../ballet/hex/fd_hex.h"
#include "vote/fd_vote_codec_tmpl.h"
#include "vote/fd_vote_state_versioned.h"
#include "../sysvar/fd_sysvar_clock.h"
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

/* Features active on mainnet that are not yet in the cleaned-up set.
   The SIMD-0232 tests run with these on so the exercised feature
   combination matches the one the feature will activate under. */
static void
enable_mainnet_features( test_env_t * env ) {
  FD_FEATURE_SET_ACTIVE( &env->bank->f.features, bls_pubkey_management_in_vote_account, 0UL );
  FD_FEATURE_SET_ACTIVE( &env->bank->f.features, commission_rate_in_basis_points,       0UL );
  FD_FEATURE_SET_ACTIVE( &env->bank->f.features, delay_commission_updates,              0UL );
}

/* Decodes, parses, executes and commits a hex-encoded transaction.
   expect_err is the expected exec_err when expect_ok is 0. */
static void
exec_txn_hex( test_env_t * env, char const * hex, int expect_ok, int expect_err ) {
  ulong txn_sz = strlen( hex ) / 2;
  env->txn_p->payload_sz = (ushort)txn_sz;
  fd_hex_decode( env->txn_p->payload, hex, txn_sz );
  FD_TEST( fd_txn_parse( env->txn_p->payload, txn_sz, TXN(env->txn_p), NULL )>0 );
  env->txn_in->txn              = env->txn_p;
  env->txn_in->bundle.is_bundle = 0;
  fd_runtime_prepare_and_execute_txn( env->mini->runtime, env->bank, env->txn_in, env->txn_out );
  if( expect_ok ) {
    if( FD_UNLIKELY( !txn_succeeded( env ) ) ) {
      FD_LOG_WARNING(( "txn failed: sig_byte=%02x txn_err=%d exec_err=%d custom_err=%u",
                       env->txn_p->payload[1], env->txn_out->err.txn_err,
                       env->txn_out->err.exec_err, env->txn_out->err.custom_err ));
    }
    FD_TEST( txn_succeeded( env ) );
  } else {
    FD_TEST( !txn_succeeded( env ) );
    FD_TEST( env->txn_out->err.exec_err==expect_err );
  }
  fd_runtime_commit_txn( env->mini->runtime, env->bank, NULL, env->txn_out );
}

/* Account keys shared by the hand-crafted transactions below. */
#define HEX_PAYER     "0880dc185717ce96239eb7bb7260938b79c9e8e00a79f8891f5ed1227f24cd2b" /* payer / initial withdrawer */
#define HEX_VOTE      "ad2277e4f7c1fc98173bfe282470eccbf78c50451f9d9a9aecc0fbe67915af7a" /* vote account */
#define HEX_NODE      "0aa9bcc27d093d38fa5d85cedb7136a5f3ba615782b8c036a7a778563c3796a8" /* node identity / voter */
#define HEX_PROGRAM   "0761481d357474bb7c4d7624ebd3bdb3d8355e73d11043fc0da3538000000000" /* vote program */
#define HEX_BLOCKHASH "f6166aa252c9331dc67ac8629abd45483ff31b6a53a8f89704cfd391ee02ba17"
#define HEX_CLOCK     "06a7d51718c774c928566398691d5eb68b5eb8a39b4b6d5c73555b2100000000" /* clock sysvar */
#define HEX_RENT      "06a7d517192c5c51218cc94c3d4af17f58daee089ba1fd44e3dbd98a00000000" /* rent sysvar */
#define HEX_COLLECTOR "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" /* system-owned collector */

static fd_validator_location_t const LOC_FRA = { 4051542, 618526, 4870645 };

/* Builds a single-payer UpdateCommissionCollector transaction over the
   fixed key list [payer, vote, collector, vote program]. */
static void
build_update_collector_hex( char *       hex,          /* out, at least 4096 */
                            char         sig_byte,     /* unique per txn within a test env */
                            char const * header,       /* e.g. "010001" */
                            char const * vote_hex,
                            char const * collector_hex,
                            char const * instr_accts,  /* 3 account indices */
                            char const * data_hex ) {  /* 8-byte instruction data */
  char sig[ 129 ]; for( ulong i=0UL; i<128UL; i++ ) sig[i] = sig_byte; sig[128]='\0';
  hex[0] = '\0';
  strcat( hex, "01" ); strcat( hex, sig ); strcat( hex, header ); strcat( hex, "04" );
  strcat( hex, HEX_PAYER ); strcat( hex, vote_hex ); strcat( hex, collector_hex ); strcat( hex, HEX_PROGRAM );
  strcat( hex, HEX_BLOCKHASH );
  strcat( hex, "01" ); strcat( hex, "03" ); strcat( hex, "03" );
  strcat( hex, instr_accts ); strcat( hex, "08" ); strcat( hex, data_hex );
}

/* Raw bincode writers for fabricating on-chain vote account data. */

static ulong
put_bytes( uchar * data, ulong off, void const * src, ulong sz ) {
  fd_memcpy( data+off, src, sz );
  return off+sz;
}

/* Serializes a minimal v3 vote state (wire discriminant 2): no votes,
   no root, voter_cnt authorized voters at epoch 0, empty prior_voters
   and epoch_credits.  data must be zeroed and large enough (3762). */
static void
build_v3_vote_state( uchar *             data,
                     fd_pubkey_t const * node,
                     fd_pubkey_t const * withdrawer,
                     fd_pubkey_t const * voter,
                     ulong               voter_cnt,
                     uchar               commission ) {
  ulong off  = 0UL;
  uint  disc = 2U;
  ulong zero = 0UL;
  uchar none = 0;
  off = put_bytes( data, off, &disc, 4UL );
  off = put_bytes( data, off, node, 32UL );
  off = put_bytes( data, off, withdrawer, 32UL );
  off = put_bytes( data, off, &commission, 1UL );
  off = put_bytes( data, off, &zero, 8UL );      /* votes: empty */
  off = put_bytes( data, off, &none, 1UL );      /* root_slot: None */
  off = put_bytes( data, off, &voter_cnt, 8UL ); /* authorized_voters */
  if( voter_cnt ) {
    off = put_bytes( data, off, &zero, 8UL );    /* epoch 0 */
    off = put_bytes( data, off, voter, 32UL );
  }
  off += 32UL*48UL;                              /* prior_voters.buf: zeros */
  ulong idx = 31UL;
  uchar one = 1;
  off = put_bytes( data, off, &idx, 8UL );       /* prior_voters.idx */
  off = put_bytes( data, off, &one, 1UL );       /* prior_voters.is_empty */
  off = put_bytes( data, off, &zero, 8UL );      /* epoch_credits: empty */
  off += 16UL;                                   /* last_timestamp: zeros */
}

/* Serializes a minimal v4 vote state (wire discriminant 3) with the
   given collectors, 100% commissions and an optional BLS pubkey. */
static void
build_v4_vote_state( uchar *             data,
                     fd_pubkey_t const * node,
                     fd_pubkey_t const * withdrawer,
                     fd_pubkey_t const * inflation_collector,
                     fd_pubkey_t const * block_collector,
                     uchar const *       bls_pubkey ) {    /* 48 bytes, NULL for None */
  ulong  off  = 0UL;
  uint   disc = 3U;
  ulong  zero = 0UL;
  uchar  none = 0;
  uchar  one  = 1;
  ushort bps  = 10000;
  off = put_bytes( data, off, &disc, 4UL );
  off = put_bytes( data, off, node, 32UL );
  off = put_bytes( data, off, withdrawer, 32UL );
  off = put_bytes( data, off, inflation_collector, 32UL );
  off = put_bytes( data, off, block_collector, 32UL );
  off = put_bytes( data, off, &bps, 2UL );       /* inflation_rewards_commission_bps */
  off = put_bytes( data, off, &bps, 2UL );       /* block_revenue_commission_bps */
  off = put_bytes( data, off, &zero, 8UL );      /* pending_delegator_rewards */
  if( bls_pubkey ) {                             /* Option<[u8; 48]> */
    off = put_bytes( data, off, &one, 1UL );
    off = put_bytes( data, off, bls_pubkey, 48UL );
  } else {
    off = put_bytes( data, off, &none, 1UL );
  }
  off = put_bytes( data, off, &zero, 8UL );      /* votes: empty */
  off = put_bytes( data, off, &none, 1UL );      /* root_slot: None */
  ulong voter_cnt = 1UL;
  off = put_bytes( data, off, &voter_cnt, 8UL ); /* authorized_voters */
  off = put_bytes( data, off, &zero, 8UL );      /* epoch 0 */
  off = put_bytes( data, off, node, 32UL );
  off = put_bytes( data, off, &zero, 8UL );      /* epoch_credits: empty */
  off += 16UL;                                   /* last_timestamp: zeros */
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
  env->txn_p->payload_sz = (ushort)txn_sz;
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
  env->txn_p->payload_sz = (ushort)txn_sz;
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
setup_update_commission_collector_txn( test_env_t * env ) {
  /* Hand-crafted transaction invoking
     vote.update_commission_collector (discriminant 17) with
     kind=inflation_rewards (0) on the vote account created by
     setup_account_initialize_txn.  Accounts: vote account, new
     collector, withdrawer (signer).  The first signature is non-zero
     so the status cache does not consider it a duplicate of the
     initialize transaction. */
  static char * hex =
    "01"
    "11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"
    "010001"
    "04"
    "0880dc185717ce96239eb7bb7260938b79c9e8e00a79f8891f5ed1227f24cd2b" /* withdrawer (signer, payer) */
    "ad2277e4f7c1fc98173bfe282470eccbf78c50451f9d9a9aecc0fbe67915af7a" /* vote account */
    "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" /* new collector */
    "0761481d357474bb7c4d7624ebd3bdb3d8355e73d11043fc0da3538000000000" /* vote program */
    "f6166aa252c9331dc67ac8629abd45483ff31b6a53a8f89704cfd391ee02ba17" /* blockhash */
    "01"
    "03"     /* program id index */
    "03"     /* 3 instruction accounts */
    "010200" /* vote account, collector, withdrawer */
    "08"
    /* vote.update_commission_collector, kind=inflation_rewards */
    "1100000000000000"
  ;

  /* decode and parse txn */
  ulong txn_sz = strlen(hex) / 2;
  env->txn_p->payload_sz = (ushort)txn_sz;
  fd_hex_decode( env->txn_p->payload, hex, txn_sz );
  FD_TEST( fd_txn_parse( env->txn_p->payload, txn_sz, TXN(env->txn_p), NULL )>0 );

  /* create the new collector account (system-owned, rent-exempt) */
  fd_pubkey_t pubkey[1];
  fd_hex_decode( pubkey, "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", 32 );
  create_simple_account( env, pubkey, 1000000000UL );

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

static void
test_update_commission_collector_feature_gate( fd_svm_mini_t * mini ) {
  static test_env_t env[1];
  setup_test( env, mini );
  enable_mainnet_features( env );
  setup_account_initialize_txn( env );

  /* Initialize the vote account and commit, so the follow-up
     transaction observes it. */
  fd_runtime_prepare_and_execute_txn( env->mini->runtime, env->bank, env->txn_in, env->txn_out );
  FD_TEST( txn_succeeded( env ) );
  fd_runtime_commit_txn( env->mini->runtime, env->bank, NULL, env->txn_out );

  setup_update_commission_collector_txn( env );

  /* custom_commission_collector (SIMD-0232) is not active: the
     instruction must fail with InvalidInstructionData. */
  fd_runtime_prepare_and_execute_txn( env->mini->runtime, env->bank, env->txn_in, env->txn_out );
  FD_TEST( !txn_succeeded( env ) );
  FD_TEST( env->txn_out->err.exec_err==FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA );

  FD_LOG_NOTICE(( "test_update_commission_collector_feature_gate... ok" ));
}

/* UpdateValidatorIdentity syncs block_revenue_collector with the new
   identity before SIMD-0232 and leaves it untouched after. */
static void
test_update_validator_identity_collector_sync( fd_svm_mini_t * mini, int feature_active ) {
  static test_env_t env[1];
  setup_test( env, mini );
  enable_mainnet_features( env );
  setup_account_initialize_txn( env );
  if( feature_active ) FD_FEATURE_SET_ACTIVE( &env->bank->f.features, custom_commission_collector, 0UL );

  fd_runtime_prepare_and_execute_txn( env->mini->runtime, env->bank, env->txn_in, env->txn_out );
  FD_TEST( txn_succeeded( env ) );
  fd_runtime_commit_txn( env->mini->runtime, env->bank, NULL, env->txn_out );

  /* With the feature active, first set a custom block revenue
     collector so the sync check below distinguishes "left untouched"
     from "synced to the old identity" (whose value equals the
     default). */
  fd_pubkey_t custom_collector[1];
  fd_hex_decode( custom_collector, HEX_COLLECTOR, 32 );
  if( feature_active ) {
    fd_pubkey_t pubkey[1];
    fd_hex_decode( pubkey, HEX_COLLECTOR, 32 );
    create_simple_account( env, pubkey, 1000000000UL );
    char hex[ 4096 ];
    build_update_collector_hex( hex, 'c', "010001", HEX_VOTE, HEX_COLLECTOR,
                                "010200", "1100000001000000" );
    exec_txn_hex( env, hex, 1, 0 );
  }

  /* UpdateValidatorIdentity: the new identity is the withdrawer key,
     which already signs. */
  {
    char hex[ 4096 ]; hex[0]='\0';
    char sig[ 129 ]; for( ulong i=0UL; i<128UL; i++ ) sig[i] = feature_active ? 'a' : 'b'; sig[128]='\0';
    strcat( hex, "01" ); strcat( hex, sig ); strcat( hex, "010001" ); strcat( hex, "03" );
    strcat( hex, "0880dc185717ce96239eb7bb7260938b79c9e8e00a79f8891f5ed1227f24cd2b" ); /* withdrawer = new identity */
    strcat( hex, "ad2277e4f7c1fc98173bfe282470eccbf78c50451f9d9a9aecc0fbe67915af7a" ); /* vote account */
    strcat( hex, "0761481d357474bb7c4d7624ebd3bdb3d8355e73d11043fc0da3538000000000" ); /* vote program */
    strcat( hex, "f6166aa252c9331dc67ac8629abd45483ff31b6a53a8f89704cfd391ee02ba17" );
    strcat( hex, "01" ); strcat( hex, "02" ); strcat( hex, "02" );
    strcat( hex, "0100" ); strcat( hex, "04" ); strcat( hex, "04000000" );
    ulong txn_sz = strlen(hex) / 2;
    env->txn_p->payload_sz = (ushort)txn_sz;
    fd_hex_decode( env->txn_p->payload, hex, txn_sz );
    FD_TEST( fd_txn_parse( env->txn_p->payload, txn_sz, TXN(env->txn_p), NULL )>0 );
    env->txn_in->txn = env->txn_p;
    fd_runtime_prepare_and_execute_txn( env->mini->runtime, env->bank, env->txn_in, env->txn_out );
    FD_TEST( txn_succeeded( env ) );
  }

  static fd_vote_state_versioned_t vsv[1];
  FD_TEST( !fd_vsv_deserialize( env->txn_out->accounts.account[1], vsv ) );
  FD_TEST( vsv->kind==fd_vote_state_versioned_enum_v4 );

  fd_pubkey_t new_identity[1];
  fd_hex_decode( new_identity, "0880dc185717ce96239eb7bb7260938b79c9e8e00a79f8891f5ed1227f24cd2b", 32 );

  FD_TEST( fd_pubkey_eq( &vsv->v4.node_pubkey, new_identity ) );
  if( feature_active ) {
    /* SIMD-0232: block revenue collector no longer syncs; the custom
       collector set above survives the identity change. */
    FD_TEST( fd_pubkey_eq( &vsv->v4.block_revenue_collector, custom_collector ) );
  } else {
    FD_TEST( fd_pubkey_eq( &vsv->v4.block_revenue_collector, new_identity ) );
  }

  FD_LOG_NOTICE(( "test_update_validator_identity_collector_sync(%d)... ok", feature_active ));
}

/* UpdateCommissionCollector coverage with the SIMD-0232 feature
   active. */
static void
test_update_commission_collector( fd_svm_mini_t * mini ) {
  static test_env_t env[1];
  setup_test( env, mini );
  enable_mainnet_features( env );
  setup_account_initialize_txn( env );

  FD_FEATURE_SET_ACTIVE( &env->bank->f.features, custom_commission_collector, 0UL );

  fd_runtime_prepare_and_execute_txn( env->mini->runtime, env->bank, env->txn_in, env->txn_out );
  FD_TEST( txn_succeeded( env ) );
  fd_runtime_commit_txn( env->mini->runtime, env->bank, NULL, env->txn_out );

  setup_update_commission_collector_txn( env );

  /* Positive path: inflation rewards collector set to cc..., block
     revenue collector unchanged. */
  fd_runtime_prepare_and_execute_txn( env->mini->runtime, env->bank, env->txn_in, env->txn_out );
  FD_TEST( txn_succeeded( env ) );

  static fd_vote_state_versioned_t vsv[1];
  FD_TEST( !fd_vsv_deserialize( env->txn_out->accounts.account[1], vsv ) );
  FD_TEST( vsv->kind==fd_vote_state_versioned_enum_v4 );

  fd_pubkey_t expected_collector[1];
  fd_hex_decode( expected_collector, "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", 32 );
  FD_TEST( fd_pubkey_eq( &vsv->v4.inflation_rewards_collector, expected_collector ) );

  fd_pubkey_t node_pubkey[1];
  fd_hex_decode( node_pubkey, "0aa9bcc27d093d38fa5d85cedb7136a5f3ba615782b8c036a7a778563c3796a8", 32 );
  FD_TEST( fd_pubkey_eq( &vsv->v4.block_revenue_collector, node_pubkey ) );
  fd_runtime_commit_txn( env->mini->runtime, env->bank, NULL, env->txn_out );

  /* Variant harness: rebuilds the txn with the given sig byte, header,
     collector key, instruction accounts, and data. */
  #define RUN_VARIANT( sig_byte, header, collector_hex, instr_accts, data_hex, expect_ok, expect_err ) do {   \
    char hex[ 4096 ]; hex[0]='\0';                                                                            \
    char sig[ 129 ]; for( ulong i=0UL; i<128UL; i++ ) sig[i] = (sig_byte); sig[128]='\0';                     \
    strcat( hex, "01" ); strcat( hex, sig ); strcat( hex, (header) ); strcat( hex, "04" );                    \
    strcat( hex, "0880dc185717ce96239eb7bb7260938b79c9e8e00a79f8891f5ed1227f24cd2b" );                        \
    strcat( hex, "ad2277e4f7c1fc98173bfe282470eccbf78c50451f9d9a9aecc0fbe67915af7a" );                        \
    strcat( hex, (collector_hex) );                                                                           \
    strcat( hex, "0761481d357474bb7c4d7624ebd3bdb3d8355e73d11043fc0da3538000000000" );                        \
    strcat( hex, "f6166aa252c9331dc67ac8629abd45483ff31b6a53a8f89704cfd391ee02ba17" );                        \
    strcat( hex, "01" ); strcat( hex, "03" ); strcat( hex, "03" );                                            \
    strcat( hex, (instr_accts) ); strcat( hex, "08" ); strcat( hex, (data_hex) );                             \
    ulong txn_sz = strlen(hex) / 2;                                                                           \
    env->txn_p->payload_sz = (ushort)txn_sz;                                                                  \
    fd_hex_decode( env->txn_p->payload, hex, txn_sz );                                                        \
    FD_TEST( fd_txn_parse( env->txn_p->payload, txn_sz, TXN(env->txn_p), NULL )>0 );                          \
    env->txn_in->txn = env->txn_p;                                                                            \
    fd_runtime_prepare_and_execute_txn( env->mini->runtime, env->bank, env->txn_in, env->txn_out );           \
    if( expect_ok ) { FD_TEST( txn_succeeded( env ) ); }                                                      \
    else            { FD_TEST( !txn_succeeded( env ) ); FD_TEST( env->txn_out->err.exec_err==(expect_err) ); }\
    fd_runtime_commit_txn( env->mini->runtime, env->bank, NULL, env->txn_out );                            \
  } while(0)

  /* BlockRevenue kind: block revenue collector updated. */
  RUN_VARIANT( '2', "010001",
               "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
               "010200", "1100000001000000", 1, 0 );
  FD_TEST( !fd_vsv_deserialize( env->txn_out->accounts.account[1], vsv ) );
  FD_TEST( fd_pubkey_eq( &vsv->v4.block_revenue_collector, expected_collector ) );

  /* Collector == vote account: allowed even though the owner is the
     vote program (instr accounts: vote, vote, withdrawer). */
  RUN_VARIANT( '3', "010001",
               "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
               "010100", "1100000000000000", 1, 0 );
  FD_TEST( !fd_vsv_deserialize( env->txn_out->accounts.account[1], vsv ) );
  fd_pubkey_t vote_pubkey[1];
  fd_hex_decode( vote_pubkey, "ad2277e4f7c1fc98173bfe282470eccbf78c50451f9d9a9aecc0fbe67915af7a", 32 );
  FD_TEST( fd_pubkey_eq( &vsv->v4.inflation_rewards_collector, vote_pubkey ) );

  /* Non-system-owned collector -> InvalidAccountOwner. */
  {
    fd_pubkey_t dd_key[1]; fd_hex_decode( dd_key, "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", 32 );
    fd_pubkey_t owner[1];  fd_hex_decode( owner,  "0aa9bcc27d093d38fa5d85cedb7136a5f3ba615782b8c036a7a778563c3796a8", 32 );
    create_account_raw( env->mini->runtime->accdb, env->bank->accdb_fork_id, dd_key, 1000000000UL, 0UL, NULL, owner );
  }
  RUN_VARIANT( '4', "010001",
               "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
               "010200", "1100000000000000", 0, FD_EXECUTOR_INSTR_ERR_INVALID_ACC_OWNER );

  /* Rent-paying collector -> InsufficientFunds. */
  {
    fd_pubkey_t ee_key[1]; fd_hex_decode( ee_key, "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", 32 );
    create_simple_account( env, ee_key, 100UL );
  }
  RUN_VARIANT( '5', "010001",
               "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
               "010200", "1100000000000000", 0, FD_EXECUTOR_INSTR_ERR_INSUFFICIENT_FUNDS );

  /* Non-writable collector (header marks last 2 keys readonly)
     -> InvalidArgument (reserved-account proxy check). */
  RUN_VARIANT( '6', "010002",
               "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
               "010200", "1100000000000000", 0, FD_EXECUTOR_INSTR_ERR_INVALID_ARG );

  /* Withdrawer not an instruction account signer
     -> MissingRequiredSignature (instr accounts: vote, collector,
     collector). */
  RUN_VARIANT( '7', "010001",
               "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
               "010202", "1100000000000000", 0, FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE );

  /* Fewer than 3 instruction accounts -> MissingAccount. */
  {
    char hex[ 4096 ]; hex[0]='\0';
    char sig[ 129 ]; for( ulong i=0UL; i<128UL; i++ ) sig[i] = '8'; sig[128]='\0';
    strcat( hex, "01" ); strcat( hex, sig ); strcat( hex, "010001" ); strcat( hex, "04" );
    strcat( hex, "0880dc185717ce96239eb7bb7260938b79c9e8e00a79f8891f5ed1227f24cd2b" );
    strcat( hex, "ad2277e4f7c1fc98173bfe282470eccbf78c50451f9d9a9aecc0fbe67915af7a" );
    strcat( hex, "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" );
    strcat( hex, "0761481d357474bb7c4d7624ebd3bdb3d8355e73d11043fc0da3538000000000" );
    strcat( hex, "f6166aa252c9331dc67ac8629abd45483ff31b6a53a8f89704cfd391ee02ba17" );
    strcat( hex, "01" ); strcat( hex, "03" ); strcat( hex, "02" );
    strcat( hex, "0102" ); strcat( hex, "08" ); strcat( hex, "1100000000000000" );
    ulong txn_sz = strlen(hex) / 2;
    env->txn_p->payload_sz = (ushort)txn_sz;
    fd_hex_decode( env->txn_p->payload, hex, txn_sz );
    FD_TEST( fd_txn_parse( env->txn_p->payload, txn_sz, TXN(env->txn_p), NULL )>0 );
    env->txn_in->txn = env->txn_p;
    fd_runtime_prepare_and_execute_txn( env->mini->runtime, env->bank, env->txn_in, env->txn_out );
    FD_TEST( !txn_succeeded( env ) );
    FD_TEST( env->txn_out->err.exec_err==FD_EXECUTOR_INSTR_ERR_MISSING_ACC );
    fd_runtime_commit_txn( env->mini->runtime, env->bank, NULL, env->txn_out );
  }

  /* Full aliasing of all three accounts is allowed; this only fails
     because the withdrawer signature is missing. */
  RUN_VARIANT( '9', "010001",
               "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
               "010101", "1100000000000000", 0, FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE );

  /* Collector == vote account for the BlockRevenue kind. */
  RUN_VARIANT( 'a', "010001",
               "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
               "010100", "1100000001000000", 1, 0 );
  FD_TEST( !fd_vsv_deserialize( env->txn_out->accounts.account[1], vsv ) );
  FD_TEST( fd_pubkey_eq( &vsv->v4.block_revenue_collector, vote_pubkey ) );

  /* The incinerator is an acceptable collector: it is system-owned,
     not reserved, and (here) funded above the rent-exempt minimum. */
  {
    fd_pubkey_t incinerator[1];
    fd_hex_decode( incinerator, "003390728d34116079bdc911bfff00dbd44d2ecdccf79ca6e10038e100000000", 32 );
    create_simple_account( env, incinerator, 1000000000UL );
    RUN_VARIANT( 'b', "010001",
                 "003390728d34116079bdc911bfff00dbd44d2ecdccf79ca6e10038e100000000",
                 "010200", "1100000000000000", 1, 0 );
    FD_TEST( !fd_vsv_deserialize( env->txn_out->accounts.account[1], vsv ) );
    FD_TEST( fd_pubkey_eq( &vsv->v4.inflation_rewards_collector, incinerator ) );
  }

  #undef RUN_VARIANT

  FD_LOG_NOTICE(( "test_update_commission_collector... ok" ));
}

/* A vote account that is its own authorized withdrawer can update both
   collectors with all three instruction accounts aliased to itself, as
   long as the vote account signs. */
static void
test_update_commission_collector_self_withdrawer( fd_svm_mini_t * mini ) {
  static test_env_t env[1];
  setup_test( env, mini );
  enable_mainnet_features( env );
  FD_FEATURE_SET_ACTIVE( &env->bank->f.features, custom_commission_collector, 0UL );
  setup_account_initialize_txn( env );

  #define HEX_VOTE2 "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

  /* Create and initialize a vote account whose withdrawer is the vote
     account itself.  Signers: payer, vote account, node. */
  fd_pubkey_t vote2[1];
  fd_hex_decode( vote2, HEX_VOTE2, 32 );
  uchar data[3762UL] = { 0 };
  create_account_raw( env->mini->runtime->accdb, env->bank->accdb_fork_id, vote2, 1000000000UL, 3762UL, data, &fd_solana_vote_program_id );

  {
    char hex[ 4096 ]; hex[0]='\0';
    char sig[ 129 ]; for( ulong i=0UL; i<128UL; i++ ) sig[i] = '1'; sig[128]='\0';
    strcat( hex, "03" ); strcat( hex, sig ); strcat( hex, sig ); strcat( hex, sig );
    strcat( hex, "03010407" );
    strcat( hex, HEX_PAYER ); strcat( hex, HEX_VOTE2 ); strcat( hex, HEX_NODE );
    strcat( hex, "0000000000000000000000000000000000000000000000000000000000000000" );
    strcat( hex, HEX_CLOCK ); strcat( hex, HEX_RENT ); strcat( hex, HEX_PROGRAM );
    strcat( hex, HEX_BLOCKHASH );
    strcat( hex, "01" ); strcat( hex, "06040105040265" );
    /* vote.initialize_account: node, voter, withdrawer=vote2, commission */
    strcat( hex, "00000000" ); strcat( hex, HEX_NODE ); strcat( hex, HEX_NODE );
    strcat( hex, HEX_VOTE2 ); strcat( hex, "64" );
    exec_txn_hex( env, hex, 1, 0 );
  }

  /* Both kinds succeed with instruction accounts [vote2, vote2, vote2]
     and vote2 signing; the collector resolves to vote2. */
  #define RUN_ALIAS( sig_byte, data_hex ) do {                                                     \
    char hex[ 4096 ]; hex[0]='\0';                                                                 \
    char sig[ 129 ]; for( ulong i=0UL; i<128UL; i++ ) sig[i] = (sig_byte); sig[128]='\0';          \
    strcat( hex, "02" ); strcat( hex, sig ); strcat( hex, sig );                                   \
    strcat( hex, "020001" ); strcat( hex, "03" );                                                  \
    strcat( hex, HEX_PAYER ); strcat( hex, HEX_VOTE2 ); strcat( hex, HEX_PROGRAM );                \
    strcat( hex, HEX_BLOCKHASH );                                                                  \
    strcat( hex, "01" ); strcat( hex, "02" ); strcat( hex, "03" ); strcat( hex, "010101" );        \
    strcat( hex, "08" ); strcat( hex, (data_hex) );                                                \
    exec_txn_hex( env, hex, 1, 0 );                                                                \
  } while(0)

  static fd_vote_state_versioned_t vsv[1];

  RUN_ALIAS( '2', "1100000000000000" );
  FD_TEST( !fd_vsv_deserialize( env->txn_out->accounts.account[1], vsv ) );
  FD_TEST( fd_pubkey_eq( &vsv->v4.inflation_rewards_collector, vote2 ) );

  RUN_ALIAS( '3', "1100000001000000" );
  FD_TEST( !fd_vsv_deserialize( env->txn_out->accounts.account[1], vsv ) );
  FD_TEST( fd_pubkey_eq( &vsv->v4.block_revenue_collector, vote2 ) );

  #undef RUN_ALIAS
  #undef HEX_VOTE2

  FD_LOG_NOTICE(( "test_update_commission_collector_self_withdrawer... ok" ));
}

/* Updating one collector on a v3-serialized account converts the state
   to v4 in place: the other collector and the commission bps take the
   conversion defaults (identity for block revenue, commission*100 for
   inflation bps). */
static void
test_update_commission_collector_v3_state( fd_svm_mini_t * mini ) {
  static test_env_t env[1];
  setup_test( env, mini );
  enable_mainnet_features( env );
  FD_FEATURE_SET_ACTIVE( &env->bank->f.features, custom_commission_collector, 0UL );
  setup_account_initialize_txn( env ); /* registers blockhash, creates payer */

  #define HEX_VOTE3 "3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a"

  fd_pubkey_t node[1];       fd_hex_decode( node,       HEX_NODE,      32 );
  fd_pubkey_t withdrawer[1]; fd_hex_decode( withdrawer, HEX_PAYER,     32 );
  fd_pubkey_t vote3[1];      fd_hex_decode( vote3,      HEX_VOTE3,     32 );
  fd_pubkey_t collector[1];  fd_hex_decode( collector,  HEX_COLLECTOR, 32 );
  create_simple_account( env, collector, 1000000000UL );

  uchar data[3762UL] = { 0 };
  build_v3_vote_state( data, node, withdrawer, node, 1UL, (uchar)42 );
  create_account_raw( env->mini->runtime->accdb, env->bank->accdb_fork_id, vote3, 1000000000UL, 3762UL, data, &fd_solana_vote_program_id );

  char hex[ 4096 ];
  build_update_collector_hex( hex, '1', "010001", HEX_VOTE3, HEX_COLLECTOR,
                              "010200", "1100000000000000" );
  exec_txn_hex( env, hex, 1, 0 );

  static fd_vote_state_versioned_t vsv[1];
  FD_TEST( !fd_vsv_deserialize( env->txn_out->accounts.account[1], vsv ) );
  FD_TEST( vsv->kind==fd_vote_state_versioned_enum_v4 );
  FD_TEST( fd_pubkey_eq( &vsv->v4.inflation_rewards_collector, collector ) );
  FD_TEST( fd_pubkey_eq( &vsv->v4.block_revenue_collector, node ) );
  FD_TEST( vsv->v4.inflation_rewards_commission_bps==4200 );
  FD_TEST( vsv->v4.block_revenue_commission_bps==10000 );

  #undef HEX_VOTE3

  FD_LOG_NOTICE(( "test_update_commission_collector_v3_state... ok" ));
}

/* A v4 state carrying a BLS pubkey round-trips through the update: the
   BLS pubkey and the untouched collector are preserved. */
static void
test_update_commission_collector_bls_state( fd_svm_mini_t * mini ) {
  static test_env_t env[1];
  setup_test( env, mini );
  enable_mainnet_features( env );
  FD_FEATURE_SET_ACTIVE( &env->bank->f.features, custom_commission_collector, 0UL );
  setup_account_initialize_txn( env );

  #define HEX_VOTE4 "4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b4b"

  fd_pubkey_t node[1];       fd_hex_decode( node,       HEX_NODE,      32 );
  fd_pubkey_t withdrawer[1]; fd_hex_decode( withdrawer, HEX_PAYER,     32 );
  fd_pubkey_t vote4[1];      fd_hex_decode( vote4,      HEX_VOTE4,     32 );
  fd_pubkey_t collector[1];  fd_hex_decode( collector,  HEX_COLLECTOR, 32 );
  create_simple_account( env, collector, 1000000000UL );

  uchar bls_pubkey[48];
  fd_memset( bls_pubkey, 0x5c, 48UL );
  uchar data[3762UL] = { 0 };
  build_v4_vote_state( data, node, withdrawer, vote4, node, bls_pubkey );
  create_account_raw( env->mini->runtime->accdb, env->bank->accdb_fork_id, vote4, 1000000000UL, 3762UL, data, &fd_solana_vote_program_id );

  char hex[ 4096 ];
  build_update_collector_hex( hex, '1', "010001", HEX_VOTE4, HEX_COLLECTOR,
                              "010200", "1100000000000000" );
  exec_txn_hex( env, hex, 1, 0 );

  static fd_vote_state_versioned_t vsv[1];
  FD_TEST( !fd_vsv_deserialize( env->txn_out->accounts.account[1], vsv ) );
  FD_TEST( vsv->kind==fd_vote_state_versioned_enum_v4 );
  FD_TEST( fd_pubkey_eq( &vsv->v4.inflation_rewards_collector, collector ) );
  FD_TEST( fd_pubkey_eq( &vsv->v4.block_revenue_collector, node ) );
  FD_TEST( vsv->v4.has_bls_pubkey_compressed );
  FD_TEST( !memcmp( vsv->v4.bls_pubkey_compressed, bls_pubkey, 48UL ) );
  FD_TEST( vsv->v4.inflation_rewards_commission_bps==10000 );
  FD_TEST( vsv->v4.block_revenue_commission_bps==10000 );

  #undef HEX_VOTE4

  FD_LOG_NOTICE(( "test_update_commission_collector_bls_state... ok" ));
}

static void
test_update_commission_collector_v5_state( fd_svm_mini_t * mini ) {
  static test_env_t env[1];
  setup_test( env, mini );
  enable_mainnet_features( env );
  FD_FEATURE_SET_ACTIVE( &env->bank->f.features, custom_commission_collector, 0UL );
  setup_account_initialize_txn( env );

  #define HEX_VOTE5 "5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c"

  fd_pubkey_t node[1];       fd_hex_decode( node,       HEX_NODE,      32 );
  fd_pubkey_t withdrawer[1]; fd_hex_decode( withdrawer, HEX_PAYER,     32 );
  fd_pubkey_t vote5[1];      fd_hex_decode( vote5,      HEX_VOTE5,     32 );
  fd_pubkey_t collector[1];  fd_hex_decode( collector,  HEX_COLLECTOR, 32 );
  create_simple_account( env, collector, 1000000000UL );

  uchar bls_pubkey[ FD_BLS_PUBKEY_COMPRESSED_SZ ];
  fd_memset( bls_pubkey, 0x5c, FD_BLS_PUBKEY_COMPRESSED_SZ );
  uchar data[ 3762UL ] = { 0 };
  build_v4_vote_state( data, node, withdrawer, vote5, node, bls_pubkey );
  static fd_vote_state_versioned_t vsv[1];
  FD_TEST( fd_vote_state_versioned_deserialize( vsv, data, sizeof(data) ) );
  FD_TEST( !fd_vsv_try_convert_to_v5( vsv, &LOC_FRA, 0UL ) );
  vsv->v5.location    = (fd_validator_location_t){ 1, -2, 3 };
  vsv->v5.latest_vote = 1234UL;
  FD_TEST( !fd_vote_state_versioned_serialize( vsv, data, sizeof(data) ) );
  create_account_raw( env->mini->runtime->accdb, env->bank->accdb_fork_id, vote5, 1000000000UL, 3762UL, data, &fd_solana_vote_program_id );

  char hex[ 4096 ];
  build_update_collector_hex( hex, '1', "010001", HEX_VOTE5, HEX_COLLECTOR,
                              "010200", "1100000000000000" );
  exec_txn_hex( env, hex, 1, 0 );

  fd_acc_t const * acc = env->txn_out->accounts.account[ 1 ];
  FD_TEST( acc->data_len==FD_VOTE_STATE_V5_SZ );
  FD_TEST( fd_mem_iszero( acc->data+FD_VOTE_STATE_V5_PAD_OFF, FD_VOTE_STATE_V5_PAD_SZ ) );
  FD_TEST( !fd_vsv_deserialize( acc, vsv ) );
  FD_TEST( vsv->kind==fd_vote_state_versioned_enum_v5 );
  FD_TEST( fd_pubkey_eq( &vsv->v5.inflation_rewards_collector, collector ) );
  FD_TEST( vsv->v5.location.y==-2 && vsv->v5.latest_vote==1234UL );
  FD_TEST( !memcmp( vsv->v5.bls_pubkey_compressed, bls_pubkey, FD_BLS_PUBKEY_COMPRESSED_SZ ) );

  #undef HEX_VOTE5

  FD_LOG_NOTICE(( "test_update_commission_collector_v5_state... ok" ));
}

static void
hex_append_bytes( char *       hex,
                  void const * src,
                  ulong        sz ) {
  static char const digits[] = "0123456789abcdef";
  hex += strlen( hex );
  for( ulong i=0UL; i<sz; i++ ) {
    uchar b = ((uchar const *)src)[ i ];
    *hex++ = digits[ b>>4 ];
    *hex++ = digits[ b&15 ];
  }
  *hex = '\0';
}

static void
build_vote_ix_hex( char *              hex,
                   char                sig_byte,
                   fd_pubkey_t const * payer,
                   fd_pubkey_t const * vote,
                   uchar const *       instr_accts,
                   uchar               instr_accts_cnt,
                   uchar const *       data,
                   uchar               data_sz ) {
  char sig[ 129 ]; for( ulong i=0UL; i<128UL; i++ ) sig[ i ] = sig_byte; sig[ 128 ]='\0';
  hex[ 0 ] = '\0';
  strcat( hex, "01" ); strcat( hex, sig ); strcat( hex, "010003" ); strcat( hex, "05" );
  hex_append_bytes( hex, payer->key, 32UL );
  hex_append_bytes( hex, vote->key, 32UL );
  hex_append_bytes( hex, fd_sysvar_slot_hashes_id.key, 32UL );
  hex_append_bytes( hex, fd_sysvar_clock_id.key, 32UL );
  hex_append_bytes( hex, fd_solana_vote_program_id.key, 32UL );
  strcat( hex, HEX_BLOCKHASH );
  strcat( hex, "01" ); strcat( hex, "04" );
  hex_append_bytes( hex, &instr_accts_cnt, 1UL );
  hex_append_bytes( hex, instr_accts, instr_accts_cnt );
  hex_append_bytes( hex, &data_sz, 1UL );
  hex_append_bytes( hex, data, data_sz );
}

static void
test_update_commission_bps_v5_state( fd_svm_mini_t * mini ) {
  static test_env_t env[1];
  setup_test( env, mini );
  enable_mainnet_features( env );
  setup_account_initialize_txn( env );

  #define HEX_VOTE5 "5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d5d"

  fd_pubkey_t node[1];       fd_hex_decode( node,       HEX_NODE,  32 );
  fd_pubkey_t withdrawer[1]; fd_hex_decode( withdrawer, HEX_PAYER, 32 );
  fd_pubkey_t vote5[1];      fd_hex_decode( vote5,      HEX_VOTE5, 32 );

  uchar bls_pubkey[ FD_BLS_PUBKEY_COMPRESSED_SZ ];
  fd_memset( bls_pubkey, 0x5d, FD_BLS_PUBKEY_COMPRESSED_SZ );
  uchar data[ 3762UL ] = { 0 };
  build_v4_vote_state( data, node, withdrawer, vote5, node, bls_pubkey );
  static fd_vote_state_versioned_t vsv[1];
  FD_TEST( fd_vote_state_versioned_deserialize( vsv, data, sizeof(data) ) );
  FD_TEST( !fd_vsv_try_convert_to_v5( vsv, &LOC_FRA, 0UL ) );
  fd_vote_state_v5_commission_t block_before;
  fd_vote_state_v5_commission_get( &vsv->v5, fd_commission_kind_enum_block_revenue, &block_before );
  FD_TEST( !fd_vote_state_versioned_serialize( vsv, data, sizeof(data) ) );
  create_account_raw( env->mini->runtime->accdb, env->bank->accdb_fork_id, vote5, 1000000000UL, 3762UL, data, &fd_solana_vote_program_id );

  fd_sol_sysvar_clock_t clock[1];
  FD_TEST( fd_sysvar_clock_read( env->mini->runtime->accdb, env->bank->accdb_fork_id, clock ) );

  uchar const instr_accts[ 2 ] = { 1, 0 };
  char        hex[ 4096 ];
  ushort const bps[ 2 ] = { 100, 200 };
  for( ulong i=0UL; i<2UL; i++ ) {
    uchar ix[ 10 ] = { 0x12, 0, 0, 0, (uchar)bps[ i ], (uchar)( bps[ i ]>>8 ), 0, 0, 0, 0 };
    build_vote_ix_hex( hex, (char)( '6'+i ), withdrawer, vote5, instr_accts, 2, ix, 10 );
    exec_txn_hex( env, hex, 1, 0 );

    FD_TEST( !fd_vsv_deserialize( env->txn_out->accounts.account[ 1 ], vsv ) );
    FD_TEST( vsv->kind==fd_vote_state_versioned_enum_v5 );
    fd_vote_state_v5_commission_t c;
    fd_vote_state_v5_commission_get( &vsv->v5, fd_commission_kind_enum_inflation_rewards, &c );
    FD_TEST( c.len==( clock->epoch==0UL ? 1UL : 2UL ) );
    FD_TEST( c.epoch[ c.len-1UL ]==clock->epoch+2UL && c.bps[ c.len-1UL ]==bps[ i ] );
    fd_vote_state_v5_commission_get( &vsv->v5, fd_commission_kind_enum_block_revenue, &c );
    FD_TEST( fd_memeq( &c, &block_before, sizeof(c) ) );
  }

  #undef HEX_VOTE5

  FD_LOG_NOTICE(( "test_update_commission_bps_v5_state... ok" ));
}

static void
check_v5_tower_vote_rejected( test_env_t *        env,
                              char                sig_byte,
                              fd_pubkey_t const * payer,
                              fd_pubkey_t const * vote5,
                              fd_pubkey_t const * vote4,
                              uchar const *       instr_accts,
                              uchar               instr_accts_cnt,
                              uchar const *       data,
                              uchar               data_sz,
                              uchar const *       v5_data ) {
  char hex[ 4096 ];

  build_vote_ix_hex( hex, sig_byte, payer, vote5, instr_accts, instr_accts_cnt, data, data_sz );
  exec_txn_hex( env, hex, 0, FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA );
  fd_acc_t acc = fd_accdb_read_one( env->mini->runtime->accdb, env->bank->accdb_fork_id, vote5->key );
  FD_TEST( acc.data_len==FD_VOTE_STATE_V5_SZ );
  FD_TEST( !memcmp( acc.data, v5_data, FD_VOTE_STATE_V5_SZ ) );
  fd_accdb_unread_one( env->mini->runtime->accdb, &acc );

  build_vote_ix_hex( hex, (char)(sig_byte+1), payer, vote4, instr_accts, instr_accts_cnt, data, data_sz );
  ulong txn_sz = strlen( hex ) / 2;
  env->txn_p->payload_sz = (ushort)txn_sz;
  fd_hex_decode( env->txn_p->payload, hex, txn_sz );
  FD_TEST( fd_txn_parse( env->txn_p->payload, txn_sz, TXN(env->txn_p), NULL )>0 );
  env->txn_in->txn              = env->txn_p;
  env->txn_in->bundle.is_bundle = 0;
  fd_runtime_prepare_and_execute_txn( env->mini->runtime, env->bank, env->txn_in, env->txn_out );
  FD_TEST( txn_succeeded( env ) || env->txn_out->err.exec_err!=FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA );
  fd_runtime_commit_txn( env->mini->runtime, env->bank, NULL, env->txn_out );
}

static void
test_tower_votes_rejected_on_v5_state( fd_svm_mini_t * mini ) {
  static test_env_t env[1];
  setup_test( env, mini );
  enable_mainnet_features( env );
  setup_account_initialize_txn( env );

  fd_pubkey_t payer[1];  fd_hex_decode( payer, HEX_PAYER, 32 );
  fd_pubkey_t vote5[1];  fd_memset( vote5, 0x5d, 32UL );
  fd_pubkey_t vote4[1];  fd_memset( vote4, 0x4d, 32UL );
  fd_pubkey_t other[1];  fd_hex_decode( other, HEX_COLLECTOR, 32 );

  uchar bls_pubkey[ FD_BLS_PUBKEY_COMPRESSED_SZ ];
  fd_memset( bls_pubkey, 0x5c, FD_BLS_PUBKEY_COMPRESSED_SZ );
  uchar v4_data[ 3762UL ] = { 0 };
  build_v4_vote_state( v4_data, payer, payer, other, other, bls_pubkey );
  static fd_vote_state_versioned_t vsv[1];
  FD_TEST( fd_vote_state_versioned_deserialize( vsv, v4_data, sizeof(v4_data) ) );
  create_account_raw( env->mini->runtime->accdb, env->bank->accdb_fork_id, vote4, 1000000000UL, 3762UL, v4_data, &fd_solana_vote_program_id );
  FD_TEST( !fd_vsv_try_convert_to_v5( vsv, &LOC_FRA, 0UL ) );
  uchar v5_data[ 3762UL ] = { 0 };
  FD_TEST( !fd_vote_state_versioned_serialize( vsv, v5_data, sizeof(v5_data) ) );
  create_account_raw( env->mini->runtime->accdb, env->bank->accdb_fork_id, vote5, 1000000000UL, 3762UL, v5_data, &fd_solana_vote_program_id );

  uchar tower_sync[ 4+8+1+32+1+32 ] = { 0 };
  tower_sync[ 0 ] = 14;
  fd_memset( tower_sync+4, 0xff, 8UL );
  uchar tower_sync_accts[ 2 ] = { 1, 0 };
  check_v5_tower_vote_rejected( env, '1', payer, vote5, vote4, tower_sync_accts, 2, tower_sync, (uchar)sizeof(tower_sync), v5_data );

  uchar vote_ix[ 4+8+8+32+1 ] = { 0 };
  vote_ix[ 0 ] = 2;
  vote_ix[ 4 ] = 1;
  uchar vote_accts[ 4 ] = { 1, 2, 3, 0 };
  check_v5_tower_vote_rejected( env, '3', payer, vote5, vote4, vote_accts, 4, vote_ix, (uchar)sizeof(vote_ix), v5_data );

  uchar vsu_ix[ 4+8+1+32+1 ] = { 0 };
  vsu_ix[ 0 ] = 8;
  uchar vsu_accts[ 2 ] = { 1, 0 };
  check_v5_tower_vote_rejected( env, '5', payer, vote5, vote4, vsu_accts, 2, vsu_ix, (uchar)sizeof(vsu_ix), v5_data );

  FD_LOG_NOTICE(( "test_tower_votes_rejected_on_v5_state... ok" ));
}

static void
test_authorize_voter_v5_state( fd_svm_mini_t * mini ) {
  static test_env_t env[1];
  setup_test( env, mini );
  setup_account_initialize_txn( env );

  fd_pubkey_t payer[1];     fd_hex_decode( payer,     HEX_PAYER,     32 );
  fd_pubkey_t collector[1]; fd_hex_decode( collector, HEX_COLLECTOR, 32 );
  fd_pubkey_t vote5[1];     fd_memset( vote5, 0x5e, 32UL );
  fd_pubkey_t full5[1];     fd_memset( full5, 0x5f, 32UL );

  uchar bls_pubkey[ FD_BLS_PUBKEY_COMPRESSED_SZ ];
  fd_memset( bls_pubkey, 0x5c, FD_BLS_PUBKEY_COMPRESSED_SZ );
  uchar data[ FD_VOTE_STATE_V5_SZ ] = { 0 };
  build_v4_vote_state( data, payer, payer, collector, collector, bls_pubkey );
  static fd_vote_state_versioned_t vsv[1];
  FD_TEST( fd_vote_state_versioned_deserialize( vsv, data, sizeof(data) ) );
  FD_TEST( !fd_vsv_try_convert_to_v5( vsv, &LOC_FRA, 0UL ) );
  FD_TEST( !fd_vote_state_versioned_serialize( vsv, data, sizeof(data) ) );
  create_account_raw( env->mini->runtime->accdb, env->bank->accdb_fork_id, vote5, 1000000000UL, FD_VOTE_STATE_V5_SZ, data, &fd_solana_vote_program_id );

  for( ulong i=1UL; i<MAX_AUTHORIZED_VOTERS; i++ ) {
    vsv->v5.authorized_voters[ i ] = (fd_vote_state_v5_authorized_voter_t){ .epoch=999UL+i, .pubkey=*payer };
  }
  vsv->v5.authorized_voters_len = MAX_AUTHORIZED_VOTERS;
  uchar full_data[ FD_VOTE_STATE_V5_SZ ] = { 0 };
  FD_TEST( !fd_vote_state_versioned_serialize( vsv, full_data, sizeof(full_data) ) );
  create_account_raw( env->mini->runtime->accdb, env->bank->accdb_fork_id, full5, 1000000000UL, FD_VOTE_STATE_V5_SZ, full_data, &fd_solana_vote_program_id );

  uchar authorize_ix[ 4+32+4 ] = { 0 };
  authorize_ix[ 0 ] = 1;
  memcpy( authorize_ix+4, collector->key, 32UL );
  uchar authorize_accts[ 3 ] = { 1, 3, 0 };
  char  hex[ 4096 ];

  build_vote_ix_hex( hex, '7', payer, vote5, authorize_accts, 3, authorize_ix, (uchar)sizeof(authorize_ix) );
  exec_txn_hex( env, hex, 1, 0 );
  FD_TEST( !fd_vsv_deserialize( env->txn_out->accounts.account[ 1 ], vsv ) );
  FD_TEST( vsv->kind==fd_vote_state_versioned_enum_v5 );
  FD_TEST( fd_pubkey_eq( &vsv->v5.authorized_voters[ vsv->v5.authorized_voters_len-1UL ].pubkey, collector ) );

  build_vote_ix_hex( hex, '8', payer, full5, authorize_accts, 3, authorize_ix, (uchar)sizeof(authorize_ix) );
  exec_txn_hex( env, hex, 0, FD_EXECUTOR_INSTR_ERR_ACC_DATA_TOO_SMALL );
  fd_acc_t acc = fd_accdb_read_one( env->mini->runtime->accdb, env->bank->accdb_fork_id, full5->key );
  FD_TEST( acc.data_len==FD_VOTE_STATE_V5_SZ && !memcmp( acc.data, full_data, FD_VOTE_STATE_V5_SZ ) );
  fd_accdb_unread_one( env->mini->runtime->accdb, &acc );

  FD_LOG_NOTICE(( "test_authorize_voter_v5_state... ok" ));
}

static ulong
update_location_ix( uchar *                         data,
                    fd_validator_location_t const * loc ) {
  FD_STORE( uint, data,      20U    );
  FD_STORE( int,  data+4UL,  loc->x );
  FD_STORE( int,  data+8UL,  loc->y );
  FD_STORE( int,  data+12UL, loc->z );
  return 16UL;
}

static void
read_account( test_env_t *        env,
              fd_pubkey_t const * key,
              uchar *             out,
              ulong *             out_sz ) {
  fd_acc_t acc = fd_accdb_read_one( env->mini->runtime->accdb, env->bank->accdb_fork_id, key->key );
  FD_TEST( acc.lamports && acc.data_len<=8192UL );
  fd_memcpy( out, acc.data, acc.data_len );
  *out_sz = acc.data_len;
  fd_accdb_unread_one( env->mini->runtime->accdb, &acc );
}

static void
build_update_location_hex( char *              hex,
                           uchar               sig_id,
                           fd_pubkey_t const * payer,
                           fd_pubkey_t const * vote,
                           uchar const *       data,
                           uchar               data_sz ) {
  static char const digits[] = "0123456789abcdef";
  uchar accts[ 2 ] = { 1, 0 };
  build_vote_ix_hex( hex, '1', payer, vote, accts, 2, data, data_sz );
  hex[ 2 ] = digits[ sig_id>>4 ];
  hex[ 3 ] = digits[ sig_id&15 ];
}

static void
send_update_location( test_env_t *                    env,
                      uchar                           sig_id,
                      fd_pubkey_t const *             payer,
                      fd_pubkey_t const *             vote,
                      fd_validator_location_t const * loc,
                      ulong                           extra_bytes,
                      int                             expect_ok,
                      int                             expect_err ) {
  uchar data[ 32 ] = { 0 };
  ulong data_sz = update_location_ix( data, loc ) + extra_bytes;
  char  hex[ 4096 ];
  build_update_location_hex( hex, sig_id, payer, vote, data, (uchar)data_sz );
  exec_txn_hex( env, hex, expect_ok, expect_err );
}

static fd_validator_location_t const LOC_NYC = { 1333729, -4654333, 4138065 };

static void
test_update_location_success( fd_svm_mini_t * mini ) {
  static test_env_t env[1];
  setup_test( env, mini );
  setup_account_initialize_txn( env );
  FD_FEATURE_SET_ACTIVE( &env->bank->f.features, validator_location_registration, 0UL );

  fd_pubkey_t payer[1];     fd_hex_decode( payer,     HEX_PAYER,     32 );
  fd_pubkey_t collector[1]; fd_hex_decode( collector, HEX_COLLECTOR, 32 );
  fd_pubkey_t vote[1];      fd_memset( vote, 0x71, 32UL );

  uchar bls[ FD_BLS_PUBKEY_COMPRESSED_SZ ];
  fd_memset( bls, 0x5c, FD_BLS_PUBKEY_COMPRESSED_SZ );
  uchar data[ FD_VOTE_STATE_V4_SZ ] = { 0 };
  build_v4_vote_state( data, payer, payer, collector, collector, bls );
  create_account_raw( env->mini->runtime->accdb, env->bank->accdb_fork_id, vote, 1000000000UL, FD_VOTE_STATE_V4_SZ, data, &fd_solana_vote_program_id );

  send_update_location( env, 0x01, payer, vote, &LOC_FRA, 0UL, 1, 0 );
  uchar after1[ 8192 ]; ulong sz1;
  read_account( env, vote, after1, &sz1 );
  FD_TEST( sz1==FD_VOTE_STATE_V5_SZ && FD_LOAD( uint, after1 )==fd_vote_state_versioned_enum_v5 );
  FD_TEST( fd_vote_account_is_valid_v5( after1, sz1 ) );
  FD_TEST( FD_LOAD( int, after1+144 )==LOC_FRA.x && FD_LOAD( int, after1+148 )==LOC_FRA.y && FD_LOAD( int, after1+152 )==LOC_FRA.z );
  FD_TEST( fd_memeq( after1+4,   payer->key, 32UL ) );
  FD_TEST( fd_memeq( after1+36,  payer->key, 32UL ) );
  FD_TEST( fd_memeq( after1+236, bls,        FD_BLS_PUBKEY_COMPRESSED_SZ ) );
  fd_sol_sysvar_clock_t clock[1];
  FD_TEST( fd_sysvar_clock_read( env->mini->runtime->accdb, env->bank->accdb_fork_id, clock ) );
  FD_TEST( FD_LOAD( ushort, after1+132 )==1 && FD_LOAD( ulong, after1+156 )==clock->epoch+2UL && FD_LOAD( ushort, after1+188 )==10000 );
  FD_TEST( FD_LOAD( ushort, after1+134 )==1 && FD_LOAD( ulong, after1+196 )==clock->epoch+2UL && FD_LOAD( ushort, after1+228 )==10000 );
  fd_pubkey_t voter;
  FD_TEST( !fd_vote_account_authorized_voter( after1, sz1, ULONG_MAX, &voter ) && fd_pubkey_eq( &voter, payer ) );

  send_update_location( env, 0x02, payer, vote, &LOC_NYC, 0UL, 1, 0 );
  uchar after2[ 8192 ]; ulong sz2;
  read_account( env, vote, after2, &sz2 );
  FD_TEST( sz2==sz1 );
  FD_TEST( FD_LOAD( int, after2+144 )==LOC_NYC.x && FD_LOAD( int, after2+148 )==LOC_NYC.y && FD_LOAD( int, after2+152 )==LOC_NYC.z );
  FD_TEST( fd_memeq( after1, after2, 144UL ) && fd_memeq( after1+156, after2+156, sz1-156UL ) );

  send_update_location( env, 0x03, payer, vote, &LOC_NYC, 1UL, 1, 0 );
  uchar after3[ 8192 ]; ulong sz3;
  read_account( env, vote, after3, &sz3 );
  FD_TEST( sz3==sz2 && fd_memeq( after2, after3, sz2 ) );

  FD_LOG_NOTICE(( "test_update_location_success... ok" ));
}

static void
test_update_location_errors( fd_svm_mini_t * mini ) {
  static test_env_t env[1];
  setup_test( env, mini );
  setup_account_initialize_txn( env );

  fd_pubkey_t payer[1];     fd_hex_decode( payer,     HEX_PAYER,     32 );
  fd_pubkey_t collector[1]; fd_hex_decode( collector, HEX_COLLECTOR, 32 );
  uchar bls[ FD_BLS_PUBKEY_COMPRESSED_SZ ];
  fd_memset( bls, 0x5c, FD_BLS_PUBKEY_COMPRESSED_SZ );

  fd_pubkey_t v4_bls[1];   fd_memset( v4_bls,   0x81, 32UL );
  fd_pubkey_t v4_nobls[1]; fd_memset( v4_nobls, 0x82, 32UL );
  fd_pubkey_t v3[1];       fd_memset( v3,       0x83, 32UL );
  fd_pubkey_t v4_big[1];   fd_memset( v4_big,   0x84, 32UL );
  fd_pubkey_t sys[1];      fd_memset( sys,      0x85, 32UL );
  fd_pubkey_t other[1];    fd_memset( other,    0x86, 32UL );
  fd_pubkey_t uninit[1];   fd_memset( uninit,   0x87, 32UL );

  uchar data[ 4000 ];
  fd_memset( data, 0, sizeof(data) ); build_v4_vote_state( data, payer, payer, collector, collector, bls );
  create_account_raw( env->mini->runtime->accdb, env->bank->accdb_fork_id, v4_bls,   1000000000UL, FD_VOTE_STATE_V4_SZ, data, &fd_solana_vote_program_id );
  create_account_raw( env->mini->runtime->accdb, env->bank->accdb_fork_id, sys,      1000000000UL, FD_VOTE_STATE_V4_SZ, data, &fd_solana_system_program_id );
  create_account_raw( env->mini->runtime->accdb, env->bank->accdb_fork_id, v4_big,   1000000000UL, 4000UL,              data, &fd_solana_vote_program_id );
  fd_memset( data, 0, sizeof(data) ); build_v4_vote_state( data, payer, payer, collector, collector, NULL );
  create_account_raw( env->mini->runtime->accdb, env->bank->accdb_fork_id, v4_nobls, 1000000000UL, FD_VOTE_STATE_V4_SZ, data, &fd_solana_vote_program_id );
  fd_memset( data, 0, sizeof(data) ); build_v3_vote_state( data, payer, payer, payer, 1UL, 10 );
  create_account_raw( env->mini->runtime->accdb, env->bank->accdb_fork_id, v3,       1000000000UL, FD_VOTE_STATE_V3_SZ, data, &fd_solana_vote_program_id );
  fd_memset( data, 0, sizeof(data) ); build_v4_vote_state( data, other, payer, collector, collector, bls );
  create_account_raw( env->mini->runtime->accdb, env->bank->accdb_fork_id, other,    1000000000UL, FD_VOTE_STATE_V4_SZ, data, &fd_solana_vote_program_id );
  fd_memset( data, 0, sizeof(data) );
  create_account_raw( env->mini->runtime->accdb, env->bank->accdb_fork_id, uninit,   1000000000UL, FD_VOTE_STATE_V4_SZ, data, &fd_solana_vote_program_id );

  uchar before[ 8192 ], after[ 8192 ]; ulong before_sz, after_sz;

  read_account( env, v4_bls, before, &before_sz );
  send_update_location( env, 0x10, payer, v4_bls, &LOC_FRA, 0UL, 0, FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA );
  read_account( env, v4_bls, after, &after_sz );
  FD_TEST( after_sz==before_sz && fd_memeq( before, after, before_sz ) );

  FD_FEATURE_SET_ACTIVE( &env->bank->f.features, validator_location_registration, 0UL );

  fd_validator_location_t const bad[] = {
    { 0, 0, 0 }, { 0, 0, 6378138 }, { 6378139, 0, 0 },
    { INT_MIN, 0, 0 }, { 0, INT_MAX, 0 }, { 0, 0, INT_MIN }
  };
  for( ulong i=0UL; i<sizeof(bad)/sizeof(bad[ 0 ]); i++ ) {
    send_update_location( env, (uchar)( 0x20+i ), payer, v4_bls, &bad[ i ], 0UL, 0, FD_EXECUTOR_INSTR_ERR_INVALID_ARG );
  }
  read_account( env, v4_bls, after, &after_sz );
  FD_TEST( after_sz==before_sz && fd_memeq( before, after, before_sz ) );

  send_update_location( env, 0x30, payer, other,    &LOC_FRA,  0UL, 0, FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE );
  send_update_location( env, 0x31, payer, other,    &bad[ 0 ], 0UL, 0, FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE );
  send_update_location( env, 0x32, payer, v4_nobls, &LOC_FRA,  0UL, 0, FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA );
  send_update_location( env, 0x33, payer, v4_nobls, &bad[ 0 ], 0UL, 0, FD_EXECUTOR_INSTR_ERR_INVALID_ARG );
  send_update_location( env, 0x34, payer, v3,       &LOC_FRA,  0UL, 0, FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA );
  send_update_location( env, 0x35, payer, v4_big,   &LOC_FRA,  0UL, 0, FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA );
  send_update_location( env, 0x36, payer, sys,      &LOC_FRA,  0UL, 0, FD_EXECUTOR_INSTR_ERR_INVALID_ACC_OWNER );
  send_update_location( env, 0x37, payer, uninit,   &LOC_FRA,  0UL, 0, FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA );

  uchar ix[ 16 ];
  update_location_ix( ix, &LOC_FRA );
  char  hex[ 4096 ];
  build_update_location_hex( hex, 0x40, payer, v4_bls, ix, 15 );
  exec_txn_hex( env, hex, 0, FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA );

  build_update_location_hex( hex, 0x41, payer, v4_bls, ix, 16 );
  memcpy( hex+2UL+128UL, "010004", 6UL );
  exec_txn_hex( env, hex, 0, FD_EXECUTOR_INSTR_ERR_READONLY_DATA_MODIFIED );

  read_account( env, v4_bls, after, &after_sz );
  FD_TEST( after_sz==before_sz && fd_memeq( before, after, before_sz ) );

  FD_LOG_NOTICE(( "test_update_location_errors... ok" ));
}

static void
set_clock_epoch( test_env_t * env,
                 ulong        epoch ) {
  fd_sol_sysvar_clock_t clock[1];
  FD_TEST( fd_sysvar_cache_clock_read( &env->bank->f.sysvar_cache, clock ) );
  clock->epoch = epoch;
  fd_sysvar_cache_restore_one( &env->bank->f.sysvar_cache, &fd_sysvar_clock_id, 1UL, (uchar const *)clock, sizeof(fd_sol_sysvar_clock_t) );
}

static void
add_second_voter( uchar *             data,
                  ulong               epoch,
                  fd_pubkey_t const * voter ) {
  FD_STORE( ulong, data+202UL, 2UL   );
  FD_STORE( ulong, data+250UL, epoch );
  fd_memcpy( data+258UL, voter->key, 32UL );
}

static void
test_update_location_authority( fd_svm_mini_t * mini ) {
  static test_env_t env[1];
  setup_test( env, mini );
  setup_account_initialize_txn( env );
  FD_FEATURE_SET_ACTIVE( &env->bank->f.features, validator_location_registration, 0UL );
  set_clock_epoch( env, 5UL );

  fd_pubkey_t payer[1];     fd_hex_decode( payer,     HEX_PAYER,     32 );
  fd_pubkey_t collector[1]; fd_hex_decode( collector, HEX_COLLECTOR, 32 );
  fd_pubkey_t node[1];      fd_memset( node,  0x91, 32UL );
  fd_pubkey_t other[1];     fd_memset( other, 0x92, 32UL );
  fd_pubkey_t va[1];        fd_memset( va,    0xa1, 32UL );
  fd_pubkey_t vb[1];        fd_memset( vb,    0xa2, 32UL );
  fd_pubkey_t vc[1];        fd_memset( vc,    0xa3, 32UL );
  fd_pubkey_t vd[1];        fd_memset( vd,    0xa4, 32UL );
  uchar bls[ FD_BLS_PUBKEY_COMPRESSED_SZ ];
  fd_memset( bls, 0x5c, FD_BLS_PUBKEY_COMPRESSED_SZ );

  uchar data[ FD_VOTE_STATE_V4_SZ ];
  fd_memset( data, 0, sizeof(data) ); build_v4_vote_state( data, payer, payer, collector, collector, bls );
  create_account_raw( env->mini->runtime->accdb, env->bank->accdb_fork_id, va, 1000000000UL, FD_VOTE_STATE_V4_SZ, data, &fd_solana_vote_program_id );
  fd_memset( data, 0, sizeof(data) ); build_v4_vote_state( data, payer, payer, collector, collector, bls );
  fd_memcpy( data+4UL, node->key, 32UL );
  create_account_raw( env->mini->runtime->accdb, env->bank->accdb_fork_id, vb, 1000000000UL, FD_VOTE_STATE_V4_SZ, data, &fd_solana_vote_program_id );
  fd_memset( data, 0, sizeof(data) ); build_v4_vote_state( data, payer, payer, collector, collector, bls );
  add_second_voter( data, 6UL, other );
  create_account_raw( env->mini->runtime->accdb, env->bank->accdb_fork_id, vc, 1000000000UL, FD_VOTE_STATE_V4_SZ, data, &fd_solana_vote_program_id );
  fd_memset( data, 0, sizeof(data) ); build_v4_vote_state( data, payer, payer, collector, collector, bls );
  add_second_voter( data, 4UL, other );
  create_account_raw( env->mini->runtime->accdb, env->bank->accdb_fork_id, vd, 1000000000UL, FD_VOTE_STATE_V4_SZ, data, &fd_solana_vote_program_id );

  uchar out[ 8192 ]; ulong out_sz;

  send_update_location( env, 0x50, payer, va, &LOC_FRA, 0UL, 1, 0 );
  read_account( env, va, out, &out_sz );
  FD_TEST( FD_LOAD( uint, out+300 )==1U && FD_LOAD( ulong, out+304 )==5UL && fd_memeq( out+312, payer->key, 32UL ) );

  send_update_location( env, 0x51, payer, vb, &LOC_FRA, 0UL, 1, 0 );
  read_account( env, vb, out, &out_sz );
  FD_TEST( fd_memeq( out+4, node->key, 32UL ) );
  FD_TEST( FD_LOAD( uint, out+300 )==1U && FD_LOAD( ulong, out+304 )==5UL && fd_memeq( out+312, payer->key, 32UL ) );

  send_update_location( env, 0x52, payer, vc, &LOC_FRA, 0UL, 1, 0 );
  read_account( env, vc, out, &out_sz );
  FD_TEST( FD_LOAD( uint, out+300 )==2U );
  FD_TEST( FD_LOAD( ulong, out+304 )==5UL && fd_memeq( out+312, payer->key, 32UL ) );
  FD_TEST( FD_LOAD( ulong, out+344 )==6UL && fd_memeq( out+352, other->key, 32UL ) );

  uchar before[ 8192 ]; ulong before_sz;
  read_account( env, vd, before, &before_sz );
  send_update_location( env, 0x53, payer, vd, &LOC_FRA, 0UL, 0, FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE );
  read_account( env, vd, out, &out_sz );
  FD_TEST( out_sz==before_sz && fd_memeq( before, out, before_sz ) );

  FD_LOG_NOTICE(( "test_update_location_authority... ok" ));
}

/* Malformed vote account states: wire discriminant 0, truncated
   payloads for every version, and a v3 state with no authorized
   voters. */
static void
test_update_commission_collector_bad_state( fd_svm_mini_t * mini ) {
  static test_env_t env[1];
  setup_test( env, mini );
  enable_mainnet_features( env );
  FD_FEATURE_SET_ACTIVE( &env->bank->f.features, custom_commission_collector, 0UL );
  setup_account_initialize_txn( env );

  fd_pubkey_t collector[1]; fd_hex_decode( collector, HEX_COLLECTOR, 32 );
  create_simple_account( env, collector, 1000000000UL );

  /* One vote account per malformed shape, keyed e1..e5. */
  #define RUN_BAD_STATE( sig_byte, vote_hex, dlen, dat, expect_err ) do {                          \
    fd_pubkey_t vote_key[1];                                                                       \
    fd_hex_decode( vote_key, (vote_hex), 32 );                                                     \
    create_account_raw( env->mini->runtime->accdb, env->bank->accdb_fork_id, vote_key,             \
                        1000000000UL, (dlen), (dat), &fd_solana_vote_program_id );                 \
    char hex[ 4096 ];                                                                              \
    build_update_collector_hex( hex, (sig_byte), "010001", (vote_hex), HEX_COLLECTOR,              \
                                "010200", "1100000000000000" );                                    \
    exec_txn_hex( env, hex, 0, (expect_err) );                                                     \
  } while(0)

  /* Wire discriminant 0 (uninitialized). */
  {
    uchar data[3762UL] = { 0 };
    RUN_BAD_STATE( '1', "e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1",
                   3762UL, data, FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA );
  }

  /* Truncated payloads: discriminant present, body cut short. */
  {
    uchar data[10UL] = { 1 };
    RUN_BAD_STATE( '2', "e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2",
                   10UL, data, FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA );
  }
  {
    uchar data[10UL] = { 2 };
    RUN_BAD_STATE( '3', "e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3e3",
                   10UL, data, FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA );
  }
  {
    uchar data[10UL] = { 3 };
    RUN_BAD_STATE( '4', "e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4e4",
                   10UL, data, FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA );
  }

  /* Well-formed v3 with no authorized voters is uninitialized. */
  {
    fd_pubkey_t node[1];       fd_hex_decode( node,       HEX_NODE,  32 );
    fd_pubkey_t withdrawer[1]; fd_hex_decode( withdrawer, HEX_PAYER, 32 );
    uchar data[3762UL] = { 0 };
    build_v3_vote_state( data, node, withdrawer, NULL, 0UL, (uchar)42 );
    RUN_BAD_STATE( '5', "e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5",
                   3762UL, data, FD_EXECUTOR_INSTR_ERR_UNINITIALIZED_ACCOUNT );
  }

  #undef RUN_BAD_STATE

  FD_LOG_NOTICE(( "test_update_commission_collector_bad_state... ok" ));
}

/* Instructions that do not target the collectors (Authorize,
   UpdateCommissionBps) leave both collector fields untouched. */
static void
test_collectors_immutable( fd_svm_mini_t * mini ) {
  static test_env_t env[1];
  setup_test( env, mini );
  enable_mainnet_features( env );
  FD_FEATURE_SET_ACTIVE( &env->bank->f.features, custom_commission_collector, 0UL );
  setup_account_initialize_txn( env );

  fd_runtime_prepare_and_execute_txn( env->mini->runtime, env->bank, env->txn_in, env->txn_out );
  FD_TEST( txn_succeeded( env ) );
  fd_runtime_commit_txn( env->mini->runtime, env->bank, NULL, env->txn_out );

  fd_pubkey_t collector[1]; fd_hex_decode( collector, HEX_COLLECTOR, 32 );
  create_simple_account( env, collector, 1000000000UL );

  /* Set both collectors to the custom key. */
  char hex[ 4096 ];
  build_update_collector_hex( hex, '1', "010001", HEX_VOTE, HEX_COLLECTOR,
                              "010200", "1100000000000000" );
  exec_txn_hex( env, hex, 1, 0 );
  build_update_collector_hex( hex, '2', "010001", HEX_VOTE, HEX_COLLECTOR,
                              "010200", "1100000001000000" );
  exec_txn_hex( env, hex, 1, 0 );

  static fd_vote_state_versioned_t vsv[1];

  /* Authorize(Withdrawer -> node): keys [payer, vote, clock, program],
     instruction accounts [vote, clock, current withdrawer]. */
  {
    char sig[ 129 ]; for( ulong i=0UL; i<128UL; i++ ) sig[i] = '3'; sig[128]='\0';
    hex[0]='\0';
    strcat( hex, "01" ); strcat( hex, sig ); strcat( hex, "010002" ); strcat( hex, "04" );
    strcat( hex, HEX_PAYER ); strcat( hex, HEX_VOTE ); strcat( hex, HEX_CLOCK ); strcat( hex, HEX_PROGRAM );
    strcat( hex, HEX_BLOCKHASH );
    strcat( hex, "01" ); strcat( hex, "03" ); strcat( hex, "03" ); strcat( hex, "010200" );
    strcat( hex, "28" );
    /* vote.authorize: new authority, VoteAuthorize::Withdrawer */
    strcat( hex, "01000000" ); strcat( hex, HEX_NODE ); strcat( hex, "01000000" );
    exec_txn_hex( env, hex, 1, 0 );

    FD_TEST( !fd_vsv_deserialize( env->txn_out->accounts.account[1], vsv ) );
    FD_TEST( fd_pubkey_eq( &vsv->v4.inflation_rewards_collector, collector ) );
    FD_TEST( fd_pubkey_eq( &vsv->v4.block_revenue_collector, collector ) );
  }

  /* UpdateCommissionBps(InflationRewards, 100): the new withdrawer
     (node) signs.  Keys [payer, node, vote, program], instruction
     accounts [vote, withdrawer]. */
  {
    char sig[ 129 ]; for( ulong i=0UL; i<128UL; i++ ) sig[i] = '4'; sig[128]='\0';
    hex[0]='\0';
    strcat( hex, "02" ); strcat( hex, sig ); strcat( hex, sig );
    strcat( hex, "020101" ); strcat( hex, "04" );
    strcat( hex, HEX_PAYER ); strcat( hex, HEX_NODE ); strcat( hex, HEX_VOTE ); strcat( hex, HEX_PROGRAM );
    strcat( hex, HEX_BLOCKHASH );
    strcat( hex, "01" ); strcat( hex, "03" ); strcat( hex, "02" ); strcat( hex, "0201" );
    strcat( hex, "0a" );
    /* vote.update_commission_bps: bps=100, kind=inflation_rewards */
    strcat( hex, "12000000" ); strcat( hex, "6400" ); strcat( hex, "00000000" );
    exec_txn_hex( env, hex, 1, 0 );

    FD_TEST( !fd_vsv_deserialize( env->txn_out->accounts.account[2], vsv ) );
    FD_TEST( fd_pubkey_eq( &vsv->v4.inflation_rewards_collector, collector ) );
    FD_TEST( fd_pubkey_eq( &vsv->v4.block_revenue_collector, collector ) );
    FD_TEST( vsv->v4.inflation_rewards_commission_bps==100 );
  }

  FD_LOG_NOTICE(( "test_collectors_immutable... ok" ));
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

  FD_TEST( FD_VOTE_INSTR_SEED_MAX == FD_TXN_MTU_V0 );

  FD_TEST( FD_VOTE_INSTR_LANDED_VOTES_ALIGN == deq_fd_landed_vote_t_align() );
  FD_TEST( FD_VOTE_INSTR_LANDED_VOTES_FOOTPRINT == deq_fd_landed_vote_t_footprint( FD_VOTE_INSTR_MAX_LOCKOUT_OFFSETS_LEN ) );

  FD_LOG_NOTICE(( "test_vote_instruction_footprints... ok" ));
}

static void
test_vote_state_alignment( void ) {
  uchar storage[ FD_VOTE_STATE_V4_SZ+3UL ] __attribute__((aligned(4)));

  for( ulong off=0UL; off<4UL; off++ ) {
    uchar * data = storage+off;

    fd_memset( data, 0, FD_VOTE_STATE_V4_SZ );
    FD_STORE( uint, data, fd_vote_state_versioned_enum_v4 );
    FD_TEST( fd_vsv_is_correct_size_and_initialized( data, FD_VOTE_STATE_V4_SZ ) );
    FD_TEST( !fd_vsv_is_correct_size_and_initialized( data, FD_VOTE_STATE_V4_SZ-1UL ) );

    fd_memset( data, 0, FD_VOTE_STATE_V3_SZ );
    data[ 4 ] = 1U;
    FD_TEST( fd_vsv_is_correct_size_and_initialized( data, FD_VOTE_STATE_V3_SZ ) );
  }
}

/* fd_vote_account_authorized_voter returns the last entry at or before
   the requested epoch, matching agave's get_authorized_voter. */

static void
test_authorized_voter_accessor( void ) {
  static fd_pubkey_t const voters[3] = { { .ul = { 1UL } }, { .ul = { 2UL } }, { .ul = { 3UL } } };
  static ulong const       epochs[3] = { 2UL, 4UL, 6UL };
  uint const kinds[2] = { fd_vote_state_versioned_enum_v3, fd_vote_state_versioned_enum_v4 };
  for( ulong k=0UL; k<2UL; k++ ) {
    fd_vote_state_versioned_t versioned[1];
    FD_TEST( fd_vote_state_versioned_new( versioned, kinds[k] ) );
    fd_vote_authorized_voters_t * av = kinds[k]==fd_vote_state_versioned_enum_v4 ? &versioned->v4.authorized_voters
                                                                                 : &versioned->v3.authorized_voters;
    for( ulong i=0UL; i<3UL; i++ ) {
      fd_vote_authorized_voter_t * ele = fd_vote_authorized_voters_pool_ele_acquire( av->pool );
      *ele = (fd_vote_authorized_voter_t){ .epoch = epochs[i], .pubkey = voters[i], .prio = (uchar)epochs[i] };
      fd_vote_authorized_voters_treap_ele_insert( av->treap, ele, av->pool );
    }
    uchar data[ FD_VOTE_STATE_V4_SZ ] = {0};
    FD_TEST( !fd_vote_state_versioned_serialize( versioned, data, sizeof(data) ) );

    fd_pubkey_t out;
    FD_TEST(  fd_vote_account_authorized_voter( data, sizeof(data), 1UL, &out ) ); /* before the first entry */
    FD_TEST( !fd_vote_account_authorized_voter( data, sizeof(data), 2UL, &out ) && fd_memeq( &out, &voters[0], sizeof(fd_pubkey_t) ) );
    FD_TEST( !fd_vote_account_authorized_voter( data, sizeof(data), 3UL, &out ) && fd_memeq( &out, &voters[0], sizeof(fd_pubkey_t) ) );
    FD_TEST( !fd_vote_account_authorized_voter( data, sizeof(data), 4UL, &out ) && fd_memeq( &out, &voters[1], sizeof(fd_pubkey_t) ) );
    FD_TEST( !fd_vote_account_authorized_voter( data, sizeof(data), 9UL, &out ) && fd_memeq( &out, &voters[2], sizeof(fd_pubkey_t) ) );
    FD_TEST(  fd_vote_account_authorized_voter( data, 64UL,         9UL, &out ) ); /* truncated */
  }
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
  test_update_commission_collector_feature_gate( mini );
  test_update_commission_collector( mini );
  test_update_commission_collector_self_withdrawer( mini );
  test_update_commission_collector_v3_state( mini );
  test_update_commission_collector_bls_state( mini );
  test_update_commission_collector_v5_state( mini );
  test_update_commission_bps_v5_state( mini );
  test_tower_votes_rejected_on_v5_state( mini );
  test_authorize_voter_v5_state( mini );
  test_update_location_success( mini );
  test_update_location_errors( mini );
  test_update_location_authority( mini );
  test_update_commission_collector_bad_state( mini );
  test_collectors_immutable( mini );
  test_update_validator_identity_collector_sync( mini, 0 );
  test_update_validator_identity_collector_sync( mini, 1 );
  test_authorized_voters_footprint();
  test_vote_lockouts_footprint();
  test_landed_votes_footprint();
  test_epoch_credits_footprint();
  test_vote_instruction_footprints();
  test_vote_state_alignment();
  test_authorized_voter_accessor();

  FD_LOG_NOTICE(( "pass" ));
  fd_svm_test_halt( mini );
  return 0;
}
