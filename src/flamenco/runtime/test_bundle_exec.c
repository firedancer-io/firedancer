#include "tests/fd_svm_mini.h"
#include "fd_runtime.h"
#include "fd_bank.h"
#include "fd_system_ids.h"
#include "fd_alut.h"
#include "../stakes/fd_stake_delegations.h"
#include "../stakes/fd_stake_types.h"
#include "program/fd_system_program.h"
#include "program/fd_bpf_loader_program.h"
#include "sysvar/fd_sysvar.h"
#include "sysvar/fd_sysvar_base.h"
#include "sysvar/fd_sysvar_cache.h"
#include "../accdb/fd_accdb.h"
#include "../features/fd_features.h"
#include "../../disco/fd_txn_p.h"
#include "../log_collector/fd_log_collector.h"
#include "../../ballet/txn/fd_compact_u16.h"

#define TEST_SLOTS_PER_EPOCH         (32UL)
#define TEST_PARENT_SLOT             (9UL)
#define TEST_CHILD_SLOT              (10UL)

struct test_env {
  fd_svm_mini_t *    mini;
  fd_bank_t *        bank;
  fd_accdb_fork_id_t fork_id;
  fd_runtime_t *     runtime;
  fd_txn_in_t        txn_in;
  fd_txn_out_t       txn_out[ 5UL ];
};
typedef struct test_env test_env_t;

static void
create_test_account( fd_accdb_t *        accdb,
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

static fd_stake_delegation_t const *
find_visible_stake_delegation( fd_stake_delegations_t const * stake_delegations,
                               fd_pubkey_t const *            stake_account ) {
  fd_stake_delegations_iter_t iter_[1];
  for( fd_stake_delegations_iter_t * iter = fd_stake_delegations_iter_init( iter_, stake_delegations );
       !fd_stake_delegations_iter_done( iter );
       fd_stake_delegations_iter_next( iter ) ) {
    fd_stake_delegation_t const * d = fd_stake_delegations_iter_ele( iter );
    if( FD_UNLIKELY( d->is_tombstone ) ) continue;
    if( FD_LIKELY( fd_pubkey_eq( &d->stake_account, stake_account ) ) ) return d;
  }
  return NULL;
}

static void
setup_env( test_env_t * env, fd_svm_mini_t * mini ) {
  fd_memset( env, 0, sizeof(test_env_t) );
  env->mini    = mini;
  env->runtime = mini->runtime;

  fd_svm_mini_params_t params[1];
  fd_svm_mini_params_default( params );
  params->slots_per_epoch = TEST_SLOTS_PER_EPOCH;
  params->root_slot       = TEST_PARENT_SLOT;
  ulong root_idx = fd_svm_mini_reset( mini, params );
  fd_bank_t * root_bank = fd_svm_mini_bank( mini, root_idx );
  root_bank->f.epoch = 4UL;

  ulong child_idx = fd_svm_mini_attach_child( mini, root_idx, TEST_CHILD_SLOT );
  env->bank    = fd_svm_mini_bank( mini, child_idx );
  env->fork_id = fd_svm_mini_fork_id( mini, child_idx );

  fd_features_enable_cleaned_up( &env->bank->f.features );

  /* The block_hash_queue is empty after reset; push a dummy. */
  fd_blockhashes_t * bhq = fd_blockhashes_init( &env->bank->f.block_hash_queue, 12345UL );
  fd_hash_t dummy_hash = {0};
  fd_memset( dummy_hash.uc, 0xAB, FD_HASH_FOOTPRINT );
  fd_blockhash_info_t * info = fd_blockhashes_push_new( bhq, &dummy_hash );
  info->lamports_per_signature = 0UL;
}

#define FD_CHECKED_ADD_TO_TXN_DATA( _begin, _cur_data, _to_add, _sz ) __extension__({ \
  if( FD_UNLIKELY( (*_cur_data)+_sz>_begin+FD_TXN_MTU ) ) return ULONG_MAX;          \
  fd_memcpy( *_cur_data, _to_add, _sz );                                             \
  *_cur_data += _sz;                                                                 \
})

#define FD_CHECKED_ADD_CU16_TO_TXN_DATA( _begin, _cur_data, _to_add ) __extension__({ \
  do {                                                                                \
     uchar _buf[3];                                                                   \
     ulong _sz = (ulong)fd_cu16_enc( (ushort)_to_add, _buf );                         \
     FD_CHECKED_ADD_TO_TXN_DATA( _begin, _cur_data, _buf, _sz );                      \
  } while(0);                                                                         \
})

struct txn_instr {
  uchar         program_id_idx;
  uchar const * account_idxs;
  ushort        account_idxs_cnt;
  uchar const * data;
  ushort        data_sz;
};
typedef struct txn_instr txn_instr_t;

static ulong
txn_serialize( uchar *          txn_raw_begin,
               ulong            signatures_cnt,
               fd_signature_t * signatures,
               ulong            num_required_signatures,
               ulong            num_readonly_signed_accounts,
               ulong            num_readonly_unsigned_accounts,
               ulong            account_keys_cnt,
               fd_pubkey_t *    account_keys,
               fd_hash_t *      recent_blockhash ) {
  uchar * txn_raw_cur_ptr = txn_raw_begin;

  uchar signature_cnt = fd_uchar_max( 1, (uchar)signatures_cnt );
  FD_CHECKED_ADD_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, &signature_cnt, sizeof(uchar) );
  for( uchar i = 0; i < signature_cnt; ++i ) {
    FD_CHECKED_ADD_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, &signatures[i], FD_TXN_SIGNATURE_SZ );
  }

  uchar header_b0 = (uchar) 0x80UL;
  FD_CHECKED_ADD_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, &header_b0, sizeof(uchar) );

  FD_CHECKED_ADD_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, &num_required_signatures,        sizeof(uchar) );
  FD_CHECKED_ADD_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, &num_readonly_signed_accounts,   sizeof(uchar) );
  FD_CHECKED_ADD_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, &num_readonly_unsigned_accounts, sizeof(uchar) );

  ushort num_acct_keys = (ushort)account_keys_cnt;
  FD_CHECKED_ADD_CU16_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, num_acct_keys );
  for( ushort i = 0; i < num_acct_keys; ++i ) {
    FD_CHECKED_ADD_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, &account_keys[i], sizeof(fd_pubkey_t) );
  }

  FD_CHECKED_ADD_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, recent_blockhash, sizeof(fd_hash_t) );

  ushort instr_count = 0;
  FD_CHECKED_ADD_CU16_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, instr_count );

  ushort addr_table_cnt = 0;
  FD_CHECKED_ADD_CU16_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, addr_table_cnt );

  return (ulong)(txn_raw_cur_ptr - txn_raw_begin);
}

static ulong
txn_serialize_with_instrs( uchar *             txn_raw_begin,
                           ulong               signatures_cnt,
                           fd_signature_t *    signatures,
                           ulong               num_required_signatures,
                           ulong               num_readonly_signed_accounts,
                           ulong               num_readonly_unsigned_accounts,
                           ulong               account_keys_cnt,
                           fd_pubkey_t *       account_keys,
                           fd_hash_t *         recent_blockhash,
                           txn_instr_t const * instrs,
                           ushort              instr_cnt ) {
  uchar * txn_raw_cur_ptr = txn_raw_begin;

  uchar signature_cnt = fd_uchar_max( 1, (uchar)signatures_cnt );
  FD_CHECKED_ADD_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, &signature_cnt, sizeof(uchar) );
  for( uchar i = 0; i < signature_cnt; ++i ) {
    FD_CHECKED_ADD_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, &signatures[i], FD_TXN_SIGNATURE_SZ );
  }

  uchar header_b0 = (uchar) 0x80UL;
  FD_CHECKED_ADD_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, &header_b0, sizeof(uchar) );

  FD_CHECKED_ADD_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, &num_required_signatures,        sizeof(uchar) );
  FD_CHECKED_ADD_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, &num_readonly_signed_accounts,   sizeof(uchar) );
  FD_CHECKED_ADD_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, &num_readonly_unsigned_accounts, sizeof(uchar) );

  ushort num_acct_keys = (ushort)account_keys_cnt;
  FD_CHECKED_ADD_CU16_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, num_acct_keys );
  for( ushort i = 0; i < num_acct_keys; ++i ) {
    FD_CHECKED_ADD_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, &account_keys[i], sizeof(fd_pubkey_t) );
  }

  FD_CHECKED_ADD_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, recent_blockhash, sizeof(fd_hash_t) );

  FD_CHECKED_ADD_CU16_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, instr_cnt );
  for( ushort i=0; i<instr_cnt; i++ ) {
    FD_CHECKED_ADD_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, &instrs[i].program_id_idx, sizeof(uchar) );
    FD_CHECKED_ADD_CU16_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, instrs[i].account_idxs_cnt );
    FD_CHECKED_ADD_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, instrs[i].account_idxs, instrs[i].account_idxs_cnt );
    FD_CHECKED_ADD_CU16_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, instrs[i].data_sz );
    FD_CHECKED_ADD_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, instrs[i].data, instrs[i].data_sz );
  }

  ushort addr_table_cnt = 0;
  FD_CHECKED_ADD_CU16_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, addr_table_cnt );

  return (ulong)(txn_raw_cur_ptr - txn_raw_begin);
}

static void
durable_nonce_from_blockhash( fd_hash_t *       out,
                              fd_hash_t const * blockhash ) {
  uchar buf[45];
  memcpy( buf,    "DURABLE_NONCE", 13UL );
  memcpy( buf+13, blockhash,       sizeof(fd_hash_t) );
  fd_sha256_hash( buf, sizeof(buf), out );
}

static void
write_nonce_state_into( uchar *             data,
                        ulong               dlen,
                        fd_pubkey_t const * authority,
                        fd_hash_t const *   durable_nonce ) {
  fd_nonce_state_versions_t state = {
    .version                = FD_NONCE_VERSION_CURRENT,
    .kind                   = FD_NONCE_STATE_INITIALIZED,
    .authority              = *authority,
    .durable_nonce          = *durable_nonce,
    .lamports_per_signature = 0UL
  };

  ulong written = 0UL;
  FD_TEST( !fd_nonce_state_versions_encode( &state, data, dlen, &written ) );
}

static void
create_nonce_account_initialized( test_env_t *          env,
                                  fd_pubkey_t const *   nonce_pubkey,
                                  fd_pubkey_t const *   authority,
                                  fd_hash_t const *     durable_nonce ) {
  uchar nonce_data[ FD_SYSTEM_PROGRAM_NONCE_DLEN ] = {0};
  write_nonce_state_into( nonce_data, FD_SYSTEM_PROGRAM_NONCE_DLEN, authority, durable_nonce );
  create_test_account( env->mini->runtime->accdb, env->fork_id, nonce_pubkey, 10000000UL,
                       FD_SYSTEM_PROGRAM_NONCE_DLEN, nonce_data, &fd_solana_system_program_id );
}

/* bundle_acquire mirrors the production execle path: it acquires a whole
   bundle's accounts in a single acquire_a/acquire_b pair before any txn
   executes.  Bundle txns never acquire per-txn; each one binds to this
   pre-acquired pool, so every account a bundle txn references must be in
   the set prepared here.

   The number of txn_outs prepared here must cover the number of bundle
   txns that can execute against this pool.  These tests use a
   representative txn whose accounts cover the bundle union, but still
   prepare one txn_out per possible bundle txn so prepare-time per-txn
   state (notably executable accounts) exists for each executed txn.
   Must be paired with fd_runtime_fini_bundle after the
   bundle's txns are committed or cancelled. */

static void
bundle_acquire( test_env_t * env, fd_txn_p_t * representative_txn, ulong txn_cnt ) {
  fd_txn_in_t prep_in[ FD_PACK_MAX_TXN_PER_BUNDLE ] = {0};
  FD_TEST( txn_cnt<=FD_PACK_MAX_TXN_PER_BUNDLE );
  for( ulong i=0UL; i<txn_cnt; i++ ) {
    prep_in[ i ].txn              = representative_txn;
    prep_in[ i ].bundle.is_bundle = 1;
  }
  fd_runtime_prepare_bundle_accounts( env->runtime, env->bank, prep_in, env->txn_out, txn_cnt );
}

/* test_execute_bundles is a single mega-function spanning the original
   tests, but updated for accdb v4.  Invariants on accdb refcounts
   (`ro_active`/`rw_active`) and `acc_pool` free-counts have been
   dropped — those primitives no longer exist in v4.  We keep the
   functional bundle behavior under test (rw->rw, rw->ro->rw->ro,
   bundle failure modes, account reclaim divergence, program-cache
   coherency, and ALT extension stale-read regression). */

static void
test_execute_bundles( fd_svm_mini_t * mini ) {
  /* env contains fd_txn_out_t which has a 10MB nonce_rollback_data
     buffer — must not be on the stack. */
  static test_env_t env_storage[1];
  test_env_t * env = env_storage;
  setup_env( env, mini );

  fd_pubkey_t system  = {0};
  fd_pubkey_t pubkey1 = { .ul[0] = 1UL };
  create_test_account( env->mini->runtime->accdb, env->fork_id, &pubkey1, 1000000UL, 0UL, NULL, &system );
  fd_pubkey_t pubkey2 = { .ul[0] = 2UL };
  uchar data2[5] = {6, 7, 8, 9, 10};
  create_test_account( env->mini->runtime->accdb, env->fork_id, &pubkey2, 1000000UL, 5UL, data2, &system );
  fd_pubkey_t pubkey3 = { .ul[0] = 3UL };
  uchar data3[5] = {11, 12, 13, 14, 15};
  create_test_account( env->mini->runtime->accdb, env->fork_id, &pubkey3, 1000000UL, 5UL, data3, &system );

  fd_signature_t signature = {0};
  fd_hash_t dummy_hash = {0};
  fd_memset( dummy_hash.uc, 0xAB, FD_HASH_FOOTPRINT );
  fd_pubkey_t account_keys[3] = { pubkey1, pubkey2, pubkey3 };

  #define TEST_FILLER_MAX (8UL)
  fd_pubkey_t filler[ TEST_FILLER_MAX ];
  for( ulong i=0UL; i<TEST_FILLER_MAX; i++ ) filler[i] = (fd_pubkey_t){ .ul[0] = 0xF000UL + i };
  ulong filler_idx = 0UL; (void)filler_idx;
  #define reset_world() do {                                                                                       \
    setup_env( env, mini );                                                                                        \
    create_test_account( env->mini->runtime->accdb, env->fork_id, &pubkey1, 1000000UL, 0UL, NULL,  &system );      \
    create_test_account( env->mini->runtime->accdb, env->fork_id, &pubkey2, 1000000UL, 5UL, data2, &system );      \
    create_test_account( env->mini->runtime->accdb, env->fork_id, &pubkey3, 1000000UL, 5UL, data3, &system );      \
    for( ulong _i=0UL; _i<TEST_FILLER_MAX; _i++ )                                                                  \
      create_test_account( env->mini->runtime->accdb, env->fork_id, &filler[_i], 1000000UL, 0UL, NULL, &system );  \
    filler_idx = 0UL;                                                                                              \
  } while(0)

  #define serialize_bundle_txn( out_p, base_keys, base_cnt, base_ro_unsigned ) (__extension__({  \
    fd_pubkey_t _ks[ FD_TXN_ACCT_ADDR_MAX ];                                                      \
    ulong _n = (base_cnt);                                                                        \
    for( ulong _i=0UL; _i<_n; _i++ ) _ks[_i] = (base_keys)[_i];                                   \
    _ks[_n] = filler[ filler_idx++ ];                                                             \
    ulong _sz = txn_serialize( (out_p)->payload, 1, &signature, 1UL, 0UL,                         \
                               (base_ro_unsigned)+1UL, _n+1UL, _ks, &dummy_hash );                \
    (out_p)->payload_sz = (ushort)_sz;                                                            \
    FD_TEST( fd_txn_parse( (out_p)->payload, _sz, TXN( (out_p) ), NULL ) );                       \
    _sz; }))

  #define bundle_acquire_repr( base_keys, base_cnt, txn_cnt ) do {                                \
    fd_txn_p_t _repr = {0};                                                                       \
    fd_pubkey_t _rk[ FD_TXN_ACCT_ADDR_MAX ];                                                      \
    ulong _n = (base_cnt);                                                                        \
    for( ulong _i=0UL; _i<_n; _i++ ) _rk[_i] = (base_keys)[_i];                                   \
    for( ulong _i=0UL; _i<TEST_FILLER_MAX; _i++ ) _rk[_n+_i] = filler[_i];                        \
    ulong _sz = txn_serialize( _repr.payload, 1, &signature, 1UL, 0UL,                            \
                               TEST_FILLER_MAX, _n+TEST_FILLER_MAX, _rk, &dummy_hash );           \
    _repr.payload_sz = (ushort)_sz;                                                               \
    FD_TEST( fd_txn_parse( _repr.payload, _sz, TXN( &_repr ), NULL ) );                           \
    bundle_acquire( env, &_repr, (txn_cnt) );                                                     \
  } while(0)

  /* ==========================================================================
     Test 1: rw -> rw — bundle reuses a writable account as writable
     ========================================================================== */

  fd_txn_p_t txn_p = {0};
  fd_txn_p_t bundle_txns[5]; memset( bundle_txns, 0, sizeof(bundle_txns) );
  ulong sz; (void)sz;
  serialize_bundle_txn( &bundle_txns[0], account_keys, 2UL, 0UL );
  serialize_bundle_txn( &bundle_txns[1], account_keys, 2UL, 0UL );

  bundle_acquire_repr( account_keys, 2UL, 2UL );

  env->txn_in.txn                     = &bundle_txns[0];
  env->txn_in.bundle.is_bundle        = 1;
  env->txn_in.bundle.prev_txn_cnt     = 0;
  fd_runtime_prepare_and_execute_txn( env->runtime, env->bank, &env->txn_in, &env->txn_out[0] );
  FD_TEST( env->txn_out[0].err.is_committable );
  FD_TEST( env->txn_out[0].err.txn_err==FD_RUNTIME_EXECUTE_SUCCESS );
  FD_TEST( !memcmp( &env->txn_out[0].accounts.keys[0], &pubkey1, sizeof(fd_pubkey_t) ) );
  FD_TEST( !memcmp( &env->txn_out[0].accounts.keys[1], &pubkey2, sizeof(fd_pubkey_t) ) );
  FD_TEST( env->txn_out[0].accounts.is_writable[0] == 1 );
  FD_TEST( env->txn_out[0].accounts.is_writable[1] == 1 );
  FD_TEST( env->txn_out[0].accounts.account[1]->lamports == 1000000UL );
  env->txn_out[0].accounts.account[1]->lamports = 2000000UL;

  env->txn_in.txn                     = &bundle_txns[1];
  env->txn_in.bundle.is_bundle        = 1;
  env->txn_in.bundle.prev_txn_cnt     = 1;
  env->txn_in.bundle.prev_txn_outs[0] = &env->txn_out[0];
  fd_runtime_prepare_and_execute_txn( env->runtime, env->bank, &env->txn_in, &env->txn_out[1] );
  FD_TEST( env->txn_out[1].err.is_committable );
  FD_TEST( env->txn_out[1].err.txn_err==FD_RUNTIME_EXECUTE_SUCCESS );
  FD_TEST( env->txn_out[1].accounts.account[1] == env->txn_out[0].accounts.account[1] );
  FD_TEST( env->txn_out[1].accounts.account[1]->lamports == 2000000UL );

  fd_runtime_commit_txn( env->runtime, env->bank, NULL, &env->txn_out[0], 0 );
  fd_runtime_commit_txn( env->runtime, env->bank, NULL, &env->txn_out[1], 0 );
  fd_runtime_fini_bundle( env->runtime );

  /* After commit, a fresh non-bundle txn sees 2000000. */
  serialize_bundle_txn( &txn_p, account_keys, 2UL, 0UL );
  env->txn_in.txn              = &txn_p;
  env->txn_in.bundle.is_bundle = 0;
  fd_runtime_prepare_and_execute_txn( env->runtime, env->bank, &env->txn_in, &env->txn_out[2] );
  FD_TEST( env->txn_out[2].err.is_committable );
  FD_TEST( env->txn_out[2].accounts.account[1]->lamports == 2000000UL );
  env->txn_out[2].err.is_committable = 0;
  fd_runtime_cancel_txn( env->runtime, NULL, NULL, &env->txn_out[2], 0 );

  FD_LOG_NOTICE(( "test rw -> rw... ok" ));

  /* ==========================================================================
     Test 2: rw -> ro -> rw -> ro
     ========================================================================== */

  reset_world();
  bundle_acquire_repr( account_keys, 2UL, 4UL );

  serialize_bundle_txn( &txn_p, account_keys, 2UL, 0UL );
  env->txn_in.txn                     = &txn_p;
  env->txn_in.bundle.is_bundle        = 1;
  env->txn_in.bundle.prev_txn_cnt     = 0;
  fd_runtime_prepare_and_execute_txn( env->runtime, env->bank, &env->txn_in, &env->txn_out[0] );
  FD_TEST( env->txn_out[0].err.is_committable );
  FD_TEST( env->txn_out[0].accounts.is_writable[1] == 1 );
  env->txn_out[0].accounts.account[1]->lamports = 2000001UL;

  /* tx1: account becomes readonly */
  serialize_bundle_txn( &txn_p, account_keys, 2UL, 1UL );
  env->txn_in.txn                     = &txn_p;
  env->txn_in.bundle.prev_txn_cnt     = 1;
  env->txn_in.bundle.prev_txn_outs[0] = &env->txn_out[0];
  fd_runtime_prepare_and_execute_txn( env->runtime, env->bank, &env->txn_in, &env->txn_out[1] );
  FD_TEST( env->txn_out[1].err.is_committable );
  FD_TEST( env->txn_out[1].accounts.is_writable[1] == 0 );
  FD_TEST( env->txn_out[1].accounts.account[1]->lamports == 2000001UL );

  /* tx2: account becomes writable again */
  serialize_bundle_txn( &txn_p, account_keys, 2UL, 0UL );
  env->txn_in.txn                     = &txn_p;
  env->txn_in.bundle.prev_txn_cnt     = 2;
  env->txn_in.bundle.prev_txn_outs[0] = &env->txn_out[0];
  env->txn_in.bundle.prev_txn_outs[1] = &env->txn_out[1];
  fd_runtime_prepare_and_execute_txn( env->runtime, env->bank, &env->txn_in, &env->txn_out[2] );
  FD_TEST( env->txn_out[2].err.is_committable );
  FD_TEST( env->txn_out[2].accounts.is_writable[1] == 1 );
  FD_TEST( env->txn_out[2].accounts.account[1]->lamports == 2000001UL );
  env->txn_out[2].accounts.account[1]->lamports = 2000011UL;

  /* tx3: readonly again */
  serialize_bundle_txn( &txn_p, account_keys, 2UL, 1UL );
  env->txn_in.txn                     = &txn_p;
  env->txn_in.bundle.prev_txn_cnt     = 3;
  env->txn_in.bundle.prev_txn_outs[0] = &env->txn_out[0];
  env->txn_in.bundle.prev_txn_outs[1] = &env->txn_out[1];
  env->txn_in.bundle.prev_txn_outs[2] = &env->txn_out[2];
  fd_runtime_prepare_and_execute_txn( env->runtime, env->bank, &env->txn_in, &env->txn_out[3] );
  FD_TEST( env->txn_out[3].err.is_committable );
  FD_TEST( env->txn_out[3].accounts.is_writable[1] == 0 );
  FD_TEST( env->txn_out[3].accounts.account[1]->lamports == 2000011UL );

  fd_runtime_commit_txn( env->runtime, env->bank, NULL, &env->txn_out[0], 0 );
  fd_runtime_commit_txn( env->runtime, env->bank, NULL, &env->txn_out[1], 0 );
  fd_runtime_commit_txn( env->runtime, env->bank, NULL, &env->txn_out[2], 0 );
  fd_runtime_commit_txn( env->runtime, env->bank, NULL, &env->txn_out[3], 0 );
  fd_runtime_fini_bundle( env->runtime );

  FD_LOG_NOTICE(( "test rw -> ro -> rw -> ro... ok" ));

  /* ==========================================================================
     Test 3: Bundle fails after first transaction — single cancel
     ========================================================================== */

  reset_world();
  bundle_acquire_repr( account_keys, 2UL, 1UL );

  serialize_bundle_txn( &txn_p, account_keys, 2UL, 0UL );
  env->txn_in.txn                     = &txn_p;
  env->txn_in.bundle.is_bundle        = 1;
  env->txn_in.bundle.prev_txn_cnt     = 0;
  fd_runtime_prepare_and_execute_txn( env->runtime, env->bank, &env->txn_in, &env->txn_out[0] );
  FD_TEST( env->txn_out[0].err.is_committable );
  FD_TEST( env->txn_out[0].accounts.account[1]->lamports == 1000000UL );
  env->txn_out[0].accounts.account[1]->lamports = 2000021UL;
  /* Single acquire for the bundle; release once via fini_bundle. */
  env->txn_out[0].err.is_committable = 0;
  fd_runtime_fini_bundle( env->runtime );

  FD_LOG_NOTICE(( "test bundle cancel after tx0... ok" ));

  /* ==========================================================================
     Test 4: 5-tx bundle, all cancelled
     ========================================================================== */

  reset_world();
  bundle_acquire_repr( account_keys, 2UL, 5UL );

  serialize_bundle_txn( &txn_p, account_keys, 2UL, 0UL );
  env->txn_in.txn                     = &txn_p;
  env->txn_in.bundle.is_bundle        = 1;
  env->txn_in.bundle.prev_txn_cnt     = 0;
  fd_runtime_prepare_and_execute_txn( env->runtime, env->bank, &env->txn_in, &env->txn_out[0] );
  FD_TEST( env->txn_out[0].err.is_committable );
  FD_TEST( env->txn_out[0].accounts.account[1]->lamports == 1000000UL );
  env->txn_out[0].accounts.account[1]->lamports = 2000021UL;

  serialize_bundle_txn( &txn_p, account_keys, 2UL, 0UL );
  env->txn_in.txn                     = &txn_p;
  env->txn_in.bundle.prev_txn_cnt     = 1;
  env->txn_in.bundle.prev_txn_outs[0] = &env->txn_out[0];
  fd_runtime_prepare_and_execute_txn( env->runtime, env->bank, &env->txn_in, &env->txn_out[1] );
  FD_TEST( env->txn_out[1].err.is_committable );
  FD_TEST( env->txn_out[1].accounts.account[1]->lamports == 2000021UL );
  env->txn_out[1].accounts.account[1]->lamports = 2000031UL;

  serialize_bundle_txn( &txn_p, account_keys, 2UL, 0UL );
  env->txn_in.txn                     = &txn_p;
  env->txn_in.bundle.prev_txn_cnt     = 2;
  env->txn_in.bundle.prev_txn_outs[1] = &env->txn_out[1];
  fd_runtime_prepare_and_execute_txn( env->runtime, env->bank, &env->txn_in, &env->txn_out[2] );
  FD_TEST( env->txn_out[2].err.is_committable );
  FD_TEST( env->txn_out[2].accounts.account[1]->lamports == 2000031UL );
  env->txn_out[2].accounts.account[1]->lamports = 2000041UL;

  /* tx3: readonly */
  serialize_bundle_txn( &txn_p, account_keys, 2UL, 1UL );
  env->txn_in.txn                     = &txn_p;
  env->txn_in.bundle.prev_txn_cnt     = 3;
  env->txn_in.bundle.prev_txn_outs[2] = &env->txn_out[2];
  fd_runtime_prepare_and_execute_txn( env->runtime, env->bank, &env->txn_in, &env->txn_out[3] );
  FD_TEST( env->txn_out[3].err.is_committable );
  FD_TEST( env->txn_out[3].accounts.is_writable[1] == 0 );
  FD_TEST( env->txn_out[3].accounts.account[1]->lamports == 2000041UL );

  /* tx4: writable, simulated failure */
  serialize_bundle_txn( &txn_p, account_keys, 2UL, 0UL );
  env->txn_in.txn                     = &txn_p;
  env->txn_in.bundle.prev_txn_cnt     = 4;
  env->txn_in.bundle.prev_txn_outs[3] = &env->txn_out[3];
  fd_runtime_prepare_and_execute_txn( env->runtime, env->bank, &env->txn_in, &env->txn_out[4] );
  FD_TEST( env->txn_out[4].err.is_committable );
  FD_TEST( env->txn_out[4].accounts.account[1]->lamports == 2000041UL );
  env->txn_out[4].err.txn_err = FD_RUNTIME_TXN_ERR_INSTRUCTION_ERROR;

  /* The bundle was acquired once; release once via fini_bundle (do not
     cancel per-txn, which would double-release the single acquire). */
  for( int i=0; i<5; i++ ) env->txn_out[i].err.is_committable = 0;
  fd_runtime_fini_bundle( env->runtime );

  FD_LOG_NOTICE(( "test 5-tx bundle cancel... ok" ));

  /* ==========================================================================
     Test 4b: owner-readonly + later-writer must still be committed.

     The accdb reference for an account is owned by the FIRST bundle txn
     to acquire it.  Only that owner lthashes the (final, shared) account
     state at commit, and only if its is_writable slot is set.  If the
     owner acquired the account read-only but a LATER txn in the bundle
     reuses it writable and modifies it, the modification must still be
     committed to the lthash exactly once.  Regression: previously the
     write was dropped (owner: not writable -> skipped; writer: not the
     owner -> skipped) producing a bank hash mismatch.
     ========================================================================== */

  {
    reset_world();
    fd_pubkey_t rw_after_ro = { .ul[0] = 0x52574146544552UL };
    create_test_account( env->mini->runtime->accdb, env->fork_id, &rw_after_ro,
                         3000000UL, 0UL, NULL, &system );
    fd_pubkey_t ro_keys[2] = { pubkey1, rw_after_ro };
    bundle_acquire_repr( ro_keys, 2UL, 2UL );

    /* tx0: target is read-only -> owner acquires the accdb ref RO. */
    serialize_bundle_txn( &txn_p, ro_keys, 2UL, 1UL );
    env->txn_in.txn                     = &txn_p;
    env->txn_in.bundle.is_bundle        = 1;
    env->txn_in.bundle.prev_txn_cnt     = 0;
    fd_runtime_prepare_and_execute_txn( env->runtime, env->bank, &env->txn_in, &env->txn_out[0] );
    FD_TEST( env->txn_out[0].err.is_committable );
    FD_TEST( env->txn_out[0].accounts.is_writable[1] == 0 );
    FD_TEST( env->txn_out[0].accounts.account_acquired[1] == 1 ); /* owner of the ref */
    FD_TEST( env->txn_out[0].accounts.account[1]->lamports == 3000000UL );

    /* tx1: target becomes writable, reuses the owner's account, writes it. */
    serialize_bundle_txn( &txn_p, ro_keys, 2UL, 0UL );
    env->txn_in.txn                     = &txn_p;
    env->txn_in.bundle.prev_txn_cnt     = 1;
    env->txn_in.bundle.prev_txn_outs[0] = &env->txn_out[0];
    fd_runtime_prepare_and_execute_txn( env->runtime, env->bank, &env->txn_in, &env->txn_out[1] );
    FD_TEST( env->txn_out[1].err.is_committable );
    FD_TEST( env->txn_out[1].accounts.is_writable[1] == 1 );
    FD_TEST( env->txn_out[1].accounts.account[1] == env->txn_out[0].accounts.account[1] ); /* reused */
    env->txn_out[1].accounts.account[1]->lamports = 4000000UL;

    /* Ownership of the accdb ref must transfer to the writable reuser:
       the writer now owns+commits the final state, while is_writable on
       the read-only owner is left untouched (so per-account cost stays
       correct). */
    FD_TEST( env->txn_out[1].accounts.account_acquired[1] == 1 ); /* writer is now the owner */
    FD_TEST( env->txn_out[0].accounts.account_acquired[1] == 0 ); /* prior owner released ownership */
    FD_TEST( env->txn_out[0].accounts.is_writable[1] == 0 );      /* still read-only for tx0 */

    fd_runtime_commit_txn( env->runtime, env->bank, NULL, &env->txn_out[0], 0 );
    fd_runtime_commit_txn( env->runtime, env->bank, NULL, &env->txn_out[1], 0 );
    fd_runtime_fini_bundle( env->runtime );

    /* Post-commit non-bundle read must observe the write (would be the
       stale 3000000 if the modification was dropped from the lthash).
       Fresh message so it is not deduped against the committed tx1. */
    serialize_bundle_txn( &txn_p, ro_keys, 2UL, 0UL );
    env->txn_in.txn              = &txn_p;
    env->txn_in.bundle.is_bundle = 0;
    fd_runtime_prepare_and_execute_txn( env->runtime, env->bank, &env->txn_in, &env->txn_out[2] );
    FD_TEST( env->txn_out[2].err.is_committable );
    FD_TEST( env->txn_out[2].accounts.account[1]->lamports == 4000000UL );
    env->txn_out[2].err.is_committable = 0;
    fd_runtime_cancel_txn( env->runtime, NULL, NULL, &env->txn_out[2], 0 );

    env->txn_in.bundle.is_bundle = 1; /* restore for subsequent tests */
  }

  FD_LOG_NOTICE(( "test owner-readonly + later-writer commit... ok" ));

  /* ==========================================================================
     Test 5: Account reclaim divergence between bundle and replay
     ========================================================================== */

  reset_world();
  fd_pubkey_t some_program = { .ul[0] = 0xDEADBEEFUL };
  fd_pubkey_t victim       = { .ul[0] = 0xCAFEUL };
  uchar victim_data[64];
  memset( victim_data, 0xAA, 64UL );
  create_test_account( env->mini->runtime->accdb, env->fork_id, &victim, 500000UL, 64UL, victim_data, &some_program );

  fd_pubkey_t reclaim_keys[2] = { pubkey1, victim };
  bundle_acquire_repr( reclaim_keys, 2UL, 2UL );
  serialize_bundle_txn( &txn_p, reclaim_keys, 2UL, 0UL );

  env->txn_in.txn              = &txn_p;
  env->txn_in.bundle.is_bundle = 1;
  env->txn_in.bundle.prev_txn_cnt = 0;
  fd_runtime_prepare_and_execute_txn( env->runtime, env->bank, &env->txn_in, &env->txn_out[0] );
  FD_TEST( env->txn_out[0].err.is_committable );
  FD_TEST( env->txn_out[0].accounts.account[1]->lamports == 500000UL );
  FD_TEST( env->txn_out[0].accounts.account[1]->data_len == 64UL );
  FD_TEST( !memcmp( env->txn_out[0].accounts.account[1]->owner, &some_program, 32UL ) );

  /* Simulate SBF program draining lamports to 0. */
  env->txn_out[0].accounts.account[1]->lamports = 0UL;

  serialize_bundle_txn( &txn_p, reclaim_keys, 2UL, 0UL );
  env->txn_in.txn                     = &txn_p;
  env->txn_in.bundle.prev_txn_cnt     = 1;
  env->txn_in.bundle.prev_txn_outs[0] = &env->txn_out[0];
  fd_runtime_prepare_and_execute_txn( env->runtime, env->bank, &env->txn_in, &env->txn_out[1] );
  FD_TEST( env->txn_out[1].err.is_committable );

  /* In bundle mode, tx1 must not see un-reclaimed state from tx0. */
  FD_TEST( env->txn_out[1].accounts.account[1]->lamports == 0UL );
  FD_TEST( env->txn_out[1].accounts.account[1]->data_len != 64UL );
  FD_TEST( memcmp( env->txn_out[1].accounts.account[1]->owner, &some_program, 32UL ) );

  fd_runtime_commit_txn( env->runtime, env->bank, NULL, &env->txn_out[0], 0 );
  fd_runtime_commit_txn( env->runtime, env->bank, NULL, &env->txn_out[1], 0 );
  fd_runtime_fini_bundle( env->runtime );

  /* Post-commit non-bundle read (fresh message). */
  serialize_bundle_txn( &txn_p, reclaim_keys, 2UL, 0UL );
  env->txn_in.txn              = &txn_p;
  env->txn_in.bundle.is_bundle = 0;
  fd_runtime_prepare_and_execute_txn( env->runtime, env->bank, &env->txn_in, &env->txn_out[2] );
  FD_TEST( env->txn_out[2].err.is_committable );
  FD_TEST( env->txn_out[2].accounts.account[1]->lamports == 0UL );
  FD_TEST( env->txn_out[2].accounts.account[1]->data_len == 0UL );
  fd_pubkey_t zero_owner = {0};
  FD_TEST( !memcmp( env->txn_out[2].accounts.account[1]->owner, &zero_owner, 32UL ) );
  env->txn_out[2].err.is_committable = 0;
  fd_runtime_cancel_txn( env->runtime, NULL, NULL, &env->txn_out[2], 0 );

  FD_LOG_NOTICE(( "test reclaim divergence... ok" ));

  /* ==========================================================================
     Test 5b: Bundle carry-forward must preserve stake cache update for a
     closed stake account.  The bank starts with a visible delegation in
     the parent/root view.  tx0 simulates closing the stake account after
     execution, and tx1 reuses the same pubkey as writable inside the
     bundle.  Correct behavior is that committing the bundle removes the
     stake delegation from the frontier view.
     ========================================================================== */

  {
    reset_world();
    fd_pubkey_t stake_account = { .ul[0] = 0x5154414b45UL };
    fd_pubkey_t vote_account  = { .ul[0] = 0x564f5445UL };
    uchar stake_data[ FD_STAKE_STATE_SZ ] = {0};
    FD_STORE( fd_stake_state_t, stake_data, ((fd_stake_state_t) {
      .stake_type = FD_STAKE_STATE_STAKE,
      .stake = {
        .meta = {
          .staker     = stake_account,
          .withdrawer = stake_account
        },
        .stake = {
          .delegation = {
            .voter_pubkey         = vote_account,
            .stake                = 1000000000UL,
            .activation_epoch     = 0UL,
            .deactivation_epoch   = ULONG_MAX,
            .warmup_cooldown_rate = 0.25
          }
        }
      }
    }) );
    create_test_account( env->mini->runtime->accdb, env->fork_id, &stake_account, 2000000000UL,
                         (uint)FD_STAKE_STATE_SZ, stake_data,
                         &fd_solana_stake_program_id );

    fd_stake_delegations_t * root_stake_delegations = fd_banks_stake_delegations_root_query( env->mini->banks );
    fd_stake_delegations_root_update( root_stake_delegations,
                                      &stake_account,
                                      &vote_account,
                                      1000000000UL,
                                      0UL,
                                      ULONG_MAX,
                                      0UL,
                                      FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );

    {
      fd_stake_delegations_t * frontier = fd_bank_stake_delegations_frontier_query( env->mini->banks, env->bank );
      FD_TEST( find_visible_stake_delegation( frontier, &stake_account ) );
      fd_bank_stake_delegations_end_frontier_query( env->mini->banks, env->bank );
    }

    fd_pubkey_t stake_keys[2] = { pubkey1, stake_account };
    txn_p = (fd_txn_p_t){0};
    bundle_acquire_repr( stake_keys, 2UL, 2UL );
    serialize_bundle_txn( &txn_p, stake_keys, 2UL, 0UL );

    env->txn_in.txn                 = &txn_p;
    env->txn_in.bundle.is_bundle    = 1;
    env->txn_in.bundle.prev_txn_cnt = 0;
    fd_runtime_prepare_and_execute_txn( env->runtime, env->bank, &env->txn_in, &env->txn_out[0] );
    FD_TEST( env->txn_out[0].err.is_committable );
    FD_TEST( env->txn_out[0].err.txn_err==FD_RUNTIME_EXECUTE_SUCCESS );
    FD_TEST( env->txn_out[0].accounts.is_writable[1] );
    FD_TEST( env->txn_out[0].accounts.stake_update[1] );

    /* Simulate the post-close reclaimed state after txn_check had already
       queued stake_update for tx0.  This is the state tx1 carries
       forward in the vulnerable bundle path. */
    env->txn_out[0].accounts.account[1]->lamports   = 0UL;
    env->txn_out[0].accounts.account[1]->data_len   = 0UL;
    env->txn_out[0].accounts.account[1]->executable = 0;
    fd_memset( env->txn_out[0].accounts.account[1]->owner, 0, 32UL );

    serialize_bundle_txn( &txn_p, stake_keys, 2UL, 0UL );
    env->txn_in.txn                     = &txn_p;
    env->txn_in.bundle.is_bundle        = 1;
    env->txn_in.bundle.prev_txn_cnt     = 1;
    env->txn_in.bundle.prev_txn_outs[0] = &env->txn_out[0];
    fd_runtime_prepare_and_execute_txn( env->runtime, env->bank, &env->txn_in, &env->txn_out[1] );
    FD_TEST( env->txn_out[1].err.is_committable );
    FD_TEST( env->txn_out[1].err.txn_err==FD_RUNTIME_EXECUTE_SUCCESS );
    FD_TEST( env->txn_out[1].accounts.is_writable[1] );
    FD_TEST( env->txn_out[1].accounts.account[1]->lamports==0UL );

    fd_runtime_commit_txn( env->runtime, env->bank, NULL, &env->txn_out[0], 0 );
    fd_runtime_commit_txn( env->runtime, env->bank, NULL, &env->txn_out[1], 0 );
    fd_runtime_fini_bundle( env->runtime );

    {
      fd_stake_delegations_t * frontier = fd_bank_stake_delegations_frontier_query( env->mini->banks, env->bank );
      FD_TEST( !find_visible_stake_delegation( frontier, &stake_account ) );
      fd_bank_stake_delegations_end_frontier_query( env->mini->banks, env->bank );
    }

    FD_LOG_NOTICE(( "test bundle stake-cache carry-forward... ok" ));
  }

  /* ==========================================================================
     Test 6: Bundle program-cache coherency regression
     ========================================================================== */

  reset_world();
  fd_pubkey_t system_prog     = {0};
  fd_pubkey_t payer           = { .ul[0] = 0xC0DE01UL };
  fd_pubkey_t program_key     = { .ul[0] = 0xC0DE02UL };
  fd_pubkey_t programdata_key = { .ul[0] = 0xC0DE03UL };
  fd_pubkey_t authority_key   = { .ul[0] = 0xC0DE04UL };

  create_test_account( env->mini->runtime->accdb, env->fork_id, &payer, 10000000UL, 0UL, NULL, &system_prog );

  /* program account */
  uchar program_data_buf[ SIZE_OF_PROGRAM ];
  {
    fd_bpf_state_t state;
    fd_memset( &state, 0, sizeof(state) );
    state.discriminant                      = FD_BPF_STATE_PROGRAM;
    state.inner.program.programdata_address = programdata_key;
    ulong out_sz = 0UL;
    FD_TEST( !fd_bpf_state_encode( &state, program_data_buf, SIZE_OF_PROGRAM, &out_sz ) );
  }
  create_test_account( env->mini->runtime->accdb, env->fork_id, &program_key, 1000000UL,
                       SIZE_OF_PROGRAM, program_data_buf,
                       &fd_solana_bpf_loader_upgradeable_program_id );

  /* programdata: starts pre-upgrade with slot=5 */
  uchar programdata_data_buf[ PROGRAMDATA_METADATA_SIZE ];
  {
    fd_bpf_state_t state;
    fd_memset( &state, 0, sizeof(state) );
    state.discriminant                                     = FD_BPF_STATE_PROGRAM_DATA;
    state.inner.program_data.slot                          = 5UL;
    state.inner.program_data.upgrade_authority_address     = authority_key;
    state.inner.program_data.has_upgrade_authority_address = 1;
    ulong out_sz = 0UL;
    FD_TEST( !fd_bpf_state_encode( &state, programdata_data_buf, PROGRAMDATA_METADATA_SIZE, &out_sz ) );
  }
  create_test_account( env->mini->runtime->accdb, env->fork_id, &programdata_key, 1000000UL,
                       PROGRAMDATA_METADATA_SIZE, programdata_data_buf,
                       &fd_solana_bpf_loader_upgradeable_program_id );

  /* Build the whole 2-txn bundle up front so it can be prepared in a
     single pass (prepared txn count must equal executed txn count).
     tx0: simulated upgrade — empty txn including programdata, then we
     manually update its data to slot=10 in txn_out.
     tx1: invoke program WITHOUT programdata in its account list. */
  fd_txn_p_t   coherency_txn[2]; memset( coherency_txn, 0, sizeof(coherency_txn) );
  fd_txn_in_t  coherency_in [2]; memset( coherency_in,  0, sizeof(coherency_in)  );
  fd_pubkey_t txn1_keys[3] = { payer, program_key, programdata_key };
  sz = txn_serialize( coherency_txn[0].payload, 1, &signature, 1UL, 0UL, 0UL, 3UL, txn1_keys, &dummy_hash );
  coherency_txn[0].payload_sz = (ushort)sz;
  FD_TEST( fd_txn_parse( coherency_txn[0].payload, sz, TXN( &coherency_txn[0] ), NULL ) );

  fd_pubkey_t txn2_keys[2] = { payer, program_key };
  sz = txn_serialize( coherency_txn[1].payload, 1, &signature, 1UL, 0UL, 0UL, 2UL, txn2_keys, &dummy_hash );
  coherency_txn[1].payload_sz = (ushort)sz;
  FD_TEST( fd_txn_parse( coherency_txn[1].payload, sz, TXN( &coherency_txn[1] ), NULL ) );

  coherency_in[0].txn              = &coherency_txn[0];
  coherency_in[0].bundle.is_bundle = 1;
  coherency_in[1].txn              = &coherency_txn[1];
  coherency_in[1].bundle.is_bundle = 1;
  fd_runtime_prepare_bundle_accounts( env->runtime, env->bank, coherency_in, env->txn_out, 2UL );

  env->txn_in.txn                 = &coherency_txn[0];
  env->txn_in.bundle.is_bundle    = 1;
  env->txn_in.bundle.prev_txn_cnt = 0;
  fd_runtime_prepare_and_execute_txn( env->runtime, env->bank, &env->txn_in, &env->txn_out[0] );
  FD_TEST( env->txn_out[0].err.is_committable );

  int pd_idx = -1;
  for( ushort i = 0; i < env->txn_out[0].accounts.cnt; i++ ) {
    if( fd_pubkey_eq( &env->txn_out[0].accounts.keys[i], &programdata_key ) ) {
      pd_idx = i;
      break;
    }
  }
  FD_TEST( pd_idx >= 0 );
  FD_TEST( env->txn_out[0].accounts.is_writable[ pd_idx ] );

  uchar * pd_out_data = env->txn_out[0].accounts.account[ pd_idx ]->data;
  {
    fd_bpf_state_t upgraded;
    fd_memset( &upgraded, 0, sizeof(upgraded) );
    upgraded.discriminant                                     = FD_BPF_STATE_PROGRAM_DATA;
    upgraded.inner.program_data.slot                          = 10UL;
    upgraded.inner.program_data.upgrade_authority_address     = authority_key;
    upgraded.inner.program_data.has_upgrade_authority_address = 1;
    ulong out_sz = 0UL;
    FD_TEST( !fd_bpf_state_encode( &upgraded, pd_out_data, PROGRAMDATA_METADATA_SIZE, &out_sz ) );
  }

  env->txn_in.txn                     = &coherency_txn[1];
  env->txn_in.bundle.prev_txn_cnt     = 1;
  env->txn_in.bundle.prev_txn_outs[0] = &env->txn_out[0];
  fd_runtime_prepare_and_execute_txn( env->runtime, env->bank, &env->txn_in, &env->txn_out[1] );
  FD_TEST( env->txn_out[1].err.is_committable );

  /* Locate the loaded programdata in txn_out->accounts.executable[]
     (an array of pointers into runtime-owned storage). */
  int found_programdata = 0;
  for( ulong i = 0; i < env->txn_out[1].accounts.executable_cnt; i++ ) {
    fd_acc_t const * acc = env->txn_out[1].accounts.executable[i];
    if( memcmp( acc->pubkey, programdata_key.uc, 32UL ) ) continue;

    fd_bpf_state_t pd_state[1];
    FD_TEST( fd_bpf_loader_program_get_state( acc, pd_state ) == FD_EXECUTOR_INSTR_SUCCESS );
    FD_TEST( pd_state->discriminant == FD_BPF_STATE_PROGRAM_DATA );
    FD_TEST( pd_state->inner.program_data.slot == 10UL );
    found_programdata = 1;
    break;
  }
  FD_TEST( found_programdata );

  /* Single bundle acquire -> single release via fini_bundle. */
  env->txn_out[0].err.is_committable = 0;
  env->txn_out[1].err.is_committable = 0;
  fd_runtime_fini_bundle( env->runtime );

  FD_LOG_NOTICE(( "test bundle program-cache coherency... ok" ));

  /* ==========================================================================
     Test 7: Bundle ALT stale-read regression
     ========================================================================== */

  {
    reset_world();
    /* Initialize slot hashes sysvar so the sysvar cache can serve them
       to fd_executor_setup_txn_alut_account_keys. */

    uchar slot_hashes_data[ FD_SYSVAR_SLOT_HASHES_BINCODE_SZ ];
    ulong sh_cnt = 10UL;
    FD_STORE( ulong, slot_hashes_data, sh_cnt );
    fd_slot_hash_t * sh_entries = (fd_slot_hash_t *)( slot_hashes_data + sizeof(ulong) );
    for( ulong i = 0UL; i < sh_cnt; i++ ) {
      sh_entries[i].slot = 10UL - i;
      fd_memset( sh_entries[i].hash.hash, 0, 32UL );
    }
    ulong sh_sz = sizeof(ulong) + sh_cnt * sizeof(fd_slot_hash_t);
    fd_sysvar_account_update( env->bank, env->runtime->accdb, NULL, &fd_sysvar_slot_hashes_id, slot_hashes_data, sh_sz );

    fd_sysvar_cache_restore( env->bank, env->mini->runtime->accdb );

    fd_pubkey_t alut_key = { .ul[0] = 0xA107UL };
    ulong num_alut_addrs = 4UL;
    ulong alut_data_sz   = FD_LOOKUP_TABLE_META_SIZE + num_alut_addrs * 32UL;
    uchar alut_data[ FD_LOOKUP_TABLE_META_SIZE + 4 * 32 ];

    fd_alut_meta_t alut_meta = {
      .discriminant                   = FD_ALUT_STATE_DISC_LOOKUP_TABLE,
      .deactivation_slot              = ULONG_MAX,
      .last_extended_slot             = 10UL,
      .last_extended_slot_start_index = 2,
      .has_authority                  = 0,
    };
    FD_TEST( fd_alut_state_encode( &alut_meta, alut_data, FD_LOOKUP_TABLE_META_SIZE ) == 0 );

    fd_acct_addr_t * alut_addrs = (fd_acct_addr_t *)( alut_data + FD_LOOKUP_TABLE_META_SIZE );
    for( ulong i = 0UL; i < num_alut_addrs; i++ ) {
      fd_memset( alut_addrs[i].b, 0, 32UL );
      alut_addrs[i].b[0] = (uchar)( 0xE0 + i );
      alut_addrs[i].b[1] = (uchar)( 0xF0 + i );
    }

    create_test_account( env->mini->runtime->accdb, env->fork_id, &alut_key, 1000000UL,
                         (uint)alut_data_sz, alut_data,
                         &fd_solana_address_lookup_table_program_id );

    /* tx0: include the ALT as writable and simulate an in-bundle
       extension by updating its data in txn_out.  tx1 below references
       the same lookup table but does not include the ALT account in its
       own account list, so it must not see tx0's in-memory mutation via
       the bundle-wide account pool. */
    fd_pubkey_t alt_resolved_addr = {0};
    alt_resolved_addr.uc[0] = 0xE3;
    alt_resolved_addr.uc[1] = 0xF3;
    fd_pubkey_t txn0_keys[3] = { pubkey1, alut_key, alt_resolved_addr };
    txn_p = (fd_txn_p_t){0};
    sz = txn_serialize( txn_p.payload, 1, &signature, 1UL, 0UL, 1UL,
                        3UL, txn0_keys, &dummy_hash );
    txn_p.payload_sz = (ushort)sz;
    FD_TEST( fd_txn_parse( txn_p.payload, sz, TXN( &txn_p ), NULL ) );

    /* tx1: V0 transaction using the ALT to resolve index 3. */
    fd_txn_p_t txn1_p = {0};
    uchar * pl  = txn1_p.payload;
    ulong   off = 0UL;

    pl[off++] = 1;
    fd_memset( pl + off, 0, 64UL );
    off += 64UL;

    pl[off++] = 0x80;
    pl[off++] = 1;
    pl[off++] = 0;
    pl[off++] = 0;

    pl[off++] = 1;
    fd_memcpy( pl + off, &pubkey1, 32UL );
    ulong acct_addr_off = off;
    off += 32UL;

    ulong rbh_off = off;
    fd_memcpy( pl + off, &dummy_hash, 32UL );
    off += 32UL;

    pl[off++] = 0;

    pl[off++] = 1;
    ulong alut_addr_payload_off = off;
    fd_memcpy( pl + off, &alut_key, 32UL );
    off += 32UL;
    pl[off++] = 1;
    pl[off++] = 3;
    ulong writable_off = off - 1UL;
    pl[off++] = 0;

    txn1_p.payload_sz = (ushort)off;

    uchar txn1_mem[ sizeof(fd_txn_t) + sizeof(fd_txn_acct_addr_lut_t) ] __attribute__((aligned(16UL)));
    fd_txn_t * txn1 = (fd_txn_t *)txn1_mem;
    fd_memset( txn1, 0, sizeof(txn1_mem) );

    txn1->transaction_version          = FD_TXN_V0;
    txn1->signature_cnt                = 1;
    txn1->signature_off                = 1;
    txn1->message_off                  = 65;
    txn1->readonly_signed_cnt          = 0;
    txn1->readonly_unsigned_cnt        = 0;
    txn1->acct_addr_cnt                = 1;
    txn1->acct_addr_off                = (ushort)acct_addr_off;
    txn1->recent_blockhash_off         = (ushort)rbh_off;
    txn1->instr_cnt                    = 0;
    txn1->addr_table_lookup_cnt        = 1;
    txn1->addr_table_adtl_writable_cnt = 1;
    txn1->addr_table_adtl_cnt          = 1;

    fd_txn_acct_addr_lut_t * lut = fd_txn_get_address_tables( txn1 );
    lut->addr_off     = (ushort)alut_addr_payload_off;
    lut->writable_cnt = 1;
    lut->writable_off = (ushort)writable_off;
    lut->readonly_cnt = 0;
    lut->readonly_off = (ushort)off;

    FD_TEST( sizeof(txn1_mem) <= sizeof(txn1_p._) );
    fd_memcpy( txn1_p._, txn1_mem, sizeof(txn1_mem) );

    fd_txn_in_t alut_bundle_in[2] = {0};
    alut_bundle_in[0].txn              = &txn_p;
    alut_bundle_in[0].bundle.is_bundle = 1;
    alut_bundle_in[1].txn              = &txn1_p;
    alut_bundle_in[1].bundle.is_bundle = 1;

    int prep_err = fd_runtime_prepare_bundle_accounts( env->runtime, env->bank, alut_bundle_in, env->txn_out, 2UL );
    FD_TEST( prep_err == FD_RUNTIME_TXN_ERR_INVALID_ADDRESS_LOOKUP_TABLE_INDEX );

    FD_LOG_NOTICE(( "test bundle ALT peer isolation... ok" ));
  }

  /* ==========================================================================
     Test 8: Bundle-forwarded nonce account during transaction age check
     ========================================================================== */

  {
    reset_world();
    fd_pubkey_t nonce_fee_payer = { .ul[0] = 0xFEEFUL };
    fd_pubkey_t nonce_key       = { .ul[0] = 0xFACEUL };

    fd_hash_t stale_blockhash = {0};
    fd_memset( stale_blockhash.uc, 0x11, FD_HASH_FOOTPRINT );
    fd_hash_t stale_nonce;
    durable_nonce_from_blockhash( &stale_nonce, &stale_blockhash );

    fd_hash_t bundle_blockhash = {0};
    fd_memset( bundle_blockhash.uc, 0x22, FD_HASH_FOOTPRINT );
    fd_hash_t bundle_nonce;
    durable_nonce_from_blockhash( &bundle_nonce, &bundle_blockhash );

    create_test_account( env->mini->runtime->accdb, env->fork_id, &nonce_fee_payer, 10000000UL,
                         0UL, NULL, &fd_solana_system_program_id );
    create_test_account( env->mini->runtime->accdb, env->fork_id, &fd_solana_system_program_id, 1UL,
                         0UL, NULL, &fd_solana_native_loader_id );
    create_nonce_account_initialized( env, &nonce_key, &nonce_fee_payer, &stale_nonce );

    /* tx0: load nonce account writable, then write the staged bundle
       nonce.  tx0 also references (read-only) the two extra accounts tx1
       pulls in (the recent block hashes sysvar and the system program)
       so the whole bundle's account set is acquired once, up front. */
    fd_pubkey_t txn0_nonce_keys[4] = {
      nonce_fee_payer, nonce_key,
      fd_sysvar_recent_block_hashes_id, fd_solana_system_program_id
    };
    txn_p = (fd_txn_p_t){0};
    sz = txn_serialize( txn_p.payload, 1, &signature, 1UL, 0UL, 2UL,
                        4UL, txn0_nonce_keys, &dummy_hash );
    txn_p.payload_sz = (ushort)sz;
    FD_TEST( fd_txn_parse( txn_p.payload, sz, TXN( &txn_p ), NULL ) );

    env->txn_in.txn                 = &txn_p;
    env->txn_in.bundle.is_bundle    = 1;
    env->txn_in.bundle.prev_txn_cnt = 0;
    bundle_acquire( env, &txn_p, 2UL );
    fd_runtime_prepare_and_execute_txn( env->runtime, env->bank, &env->txn_in, &env->txn_out[0] );
    FD_TEST( env->txn_out[0].err.is_committable );
    FD_TEST( env->txn_out[0].err.txn_err == FD_RUNTIME_EXECUTE_SUCCESS );
    FD_TEST( fd_pubkey_eq( &env->txn_out[0].accounts.keys[1], &nonce_key ) );
    FD_TEST( env->txn_out[0].accounts.is_writable[1] );
    write_nonce_state_into( env->txn_out[0].accounts.account[1]->data,
                            env->txn_out[0].accounts.account[1]->data_len,
                            &nonce_fee_payer,
                            &bundle_nonce );

    /* tx1: durable nonce txn whose recent blockhash matches only the
       staged bundle nonce. */
    fd_pubkey_t txn1_nonce_keys[4] = {
      nonce_fee_payer, nonce_key,
      fd_sysvar_recent_block_hashes_id, fd_solana_system_program_id
    };
    uchar ix_accts[3] = { 1, 2, 0 };
    uchar ix_data[4];
    FD_STORE( uint, ix_data, (uint)FD_SYSTEM_PROGRAM_INSTR_ADVANCE_NONCE_ACCOUNT );
    txn_instr_t nonce_instr = {
      .program_id_idx   = 3,
      .account_idxs     = ix_accts,
      .account_idxs_cnt = 3,
      .data             = ix_data,
      .data_sz          = sizeof(ix_data)
    };

    fd_txn_p_t nonce_txn = {0};
    sz = txn_serialize_with_instrs( nonce_txn.payload, 1, &signature,
                                    1UL, 0UL, 2UL, 4UL, txn1_nonce_keys,
                                    &bundle_nonce, &nonce_instr, 1U );
    nonce_txn.payload_sz = (ushort)sz;
    FD_TEST( fd_txn_parse( nonce_txn.payload, sz, TXN( &nonce_txn ), NULL ) );

    env->txn_in.txn                     = &nonce_txn;
    env->txn_in.bundle.is_bundle        = 1;
    env->txn_in.bundle.prev_txn_cnt     = 1;
    env->txn_in.bundle.prev_txn_outs[0] = &env->txn_out[0];
    fd_runtime_prepare_and_execute_txn( env->runtime, env->bank, &env->txn_in, &env->txn_out[1] );

    FD_TEST( env->txn_out[1].err.is_committable );
    FD_TEST( env->txn_out[1].err.txn_err == FD_RUNTIME_EXECUTE_SUCCESS );

    fd_runtime_commit_txn( env->runtime, env->bank, NULL, &env->txn_out[0], 0 );
    fd_runtime_commit_txn( env->runtime, env->bank, NULL, &env->txn_out[1], 0 );
    fd_runtime_fini_bundle( env->runtime );

    FD_LOG_NOTICE(( "test bundle-forwarded nonce... ok" ));
  }

  /* Test: bundle vote account lifecycle deltas remain ordered across
     separate txn_out commits.  This simulates tx0 open, tx1 close,
     tx2 open for the same vote account. */

  reset_world();
  fd_txn_p_t lifecycle_txn_p[3] = {0};
  fd_pubkey_t vote_lifecycle_keys[2] = { pubkey1, pubkey2 };
  bundle_acquire_repr( vote_lifecycle_keys, 2UL, 3UL );
  for( ulong i=0UL; i<3UL; i++ ) {
    serialize_bundle_txn( &lifecycle_txn_p[i], vote_lifecycle_keys, 2UL, 0UL );

    env->txn_in.txn                 = &lifecycle_txn_p[i];
    env->txn_in.bundle.is_bundle    = 1;
    env->txn_in.bundle.prev_txn_cnt = i;
    for( ulong j=0UL; j<i; j++ ) env->txn_in.bundle.prev_txn_outs[j] = &env->txn_out[j];

    fd_runtime_prepare_and_execute_txn( env->runtime, env->bank, &env->txn_in, &env->txn_out[i] );
    FD_TEST( env->txn_out[i].err.is_committable );
    FD_TEST( env->txn_out[i].err.txn_err==FD_RUNTIME_EXECUTE_SUCCESS );
    FD_TEST( fd_pubkey_eq( &env->txn_out[i].accounts.keys[1], &pubkey2 ) );
    FD_TEST( fd_runtime_account_is_writable_idx( &env->txn_in, &env->txn_out[i], 1 ) );
  }

  env->txn_out[0].accounts.new_vote[1] = 1;
  env->txn_out[1].accounts.rm_vote [1] = 1;
  env->txn_out[2].accounts.new_vote[1] = 1;

  fd_runtime_commit_txn( env->runtime, env->bank, NULL, &env->txn_out[0], 0 );
  fd_runtime_commit_txn( env->runtime, env->bank, NULL, &env->txn_out[1], 0 );
  fd_runtime_commit_txn( env->runtime, env->bank, NULL, &env->txn_out[2], 0 );
  fd_runtime_fini_bundle( env->runtime );

  fd_new_votes_t * new_votes = fd_bank_new_votes( env->bank );
  ushort fork_idx = env->bank->new_votes_fork_id;
  fd_new_votes_apply_delta( new_votes, fork_idx );

  uchar __attribute__((aligned(FD_NEW_VOTES_ITER_ALIGN))) iter_mem[ FD_NEW_VOTES_ITER_FOOTPRINT ];
  fd_new_votes_iter_t * iter = fd_new_votes_iter_init( new_votes, NULL, 0UL, iter_mem );
  FD_TEST( !fd_new_votes_iter_done( iter ) );
  int is_tombstone = 1;
  fd_pubkey_t const * pubkey = fd_new_votes_iter_ele( iter, &is_tombstone );
  FD_TEST( !is_tombstone );
  FD_TEST( fd_pubkey_eq( pubkey, &pubkey2 ) );
  fd_new_votes_iter_next( iter );
  FD_TEST( fd_new_votes_iter_done( iter ) );
  fd_new_votes_iter_fini( iter );

  fd_new_votes_evict_fork( new_votes, fork_idx );
  env->bank->new_votes_fork_id = USHORT_MAX;

  /* Test: a bundle rm_vote queued by a NON-owner txn must still be
     recorded in order.  new_vote/rm_vote feed an ordered op-log, so they
     fire per writable txn, independent of which txn owns the accdb ref.

     Regression this guards: if rm_vote were gated on account_acquired
     (like the lthash commit), then a close queued by tx0 whose ref
     ownership later moved to tx1 (a writable reuse that does not touch
     vote state) would be dropped.  With the account pre-existing in the
     root map, dropping the remove leaves a stale entry (present) instead
     of correctly tombstoning it (absent). */
  {
    reset_world();
    env->bank->new_votes_fork_id = fd_new_votes_new_fork( fd_bank_new_votes( env->bank ) );
    fd_new_votes_t * nv  = fd_bank_new_votes( env->bank );
    ushort           fidx = env->bank->new_votes_fork_id;

    /* Pre-populate the root map with pubkey2 so a dropped remove is
       observable as a stale survivor. */
    fd_new_votes_insert( nv, fidx, &pubkey2 );
    fd_new_votes_apply_delta( nv, fidx );

    fd_txn_p_t nonowner_txn_p[2] = {0};
    fd_pubkey_t nonowner_keys[2] = { pubkey1, pubkey2 };
    bundle_acquire_repr( nonowner_keys, 2UL, 2UL );
    for( ulong i=0UL; i<2UL; i++ ) {
      serialize_bundle_txn( &nonowner_txn_p[i], nonowner_keys, 2UL, 0UL );
      env->txn_in.txn                 = &nonowner_txn_p[i];
      env->txn_in.bundle.is_bundle    = 1;
      env->txn_in.bundle.prev_txn_cnt = i;
      for( ulong j=0UL; j<i; j++ ) env->txn_in.bundle.prev_txn_outs[j] = &env->txn_out[j];
      fd_runtime_prepare_and_execute_txn( env->runtime, env->bank, &env->txn_in, &env->txn_out[i] );
      FD_TEST( env->txn_out[i].err.is_committable );
      FD_TEST( env->txn_out[i].accounts.is_writable[1] );
    }

    /* tx0 closes the vote account; tx1 reuses it writable (taking
       ownership of the accdb ref) but does not touch vote state. */
    env->txn_out[0].accounts.rm_vote[1] = 1;

    /* Ownership must have moved to tx1, leaving tx0 a non-owner. */
    FD_TEST( env->txn_out[0].accounts.account_acquired[1] == 0 );
    FD_TEST( env->txn_out[1].accounts.account_acquired[1] == 1 );

    fd_runtime_commit_txn( env->runtime, env->bank, NULL, &env->txn_out[0], 0 );
    fd_runtime_commit_txn( env->runtime, env->bank, NULL, &env->txn_out[1], 0 );
    fd_runtime_fini_bundle( env->runtime );

    fd_new_votes_apply_delta( nv, fidx );

    /* The non-owner's remove must have tombstoned the pre-existing entry. */
    uchar __attribute__((aligned(FD_NEW_VOTES_ITER_ALIGN))) it_mem[ FD_NEW_VOTES_ITER_FOOTPRINT ];
    fd_new_votes_iter_t * it = fd_new_votes_iter_init( nv, NULL, 0UL, it_mem );
    FD_TEST( fd_new_votes_iter_done( it ) ); /* pubkey2 removed -> empty */
    fd_new_votes_iter_fini( it );

    fd_new_votes_evict_fork( nv, fidx );
    env->bank->new_votes_fork_id = USHORT_MAX;
  }

  FD_LOG_NOTICE(( "test bundle non-owner vote op ordering... ok" ));

  /* Test: stake_update queued by a non-owner txn must still fire once,
     on the txn that ends up owning the accdb ref.  tx0 marks the stake
     account; tx1 reuses it writable (ownership moves to tx1).  The
     delegation must be removed exactly once (drained to zero in tx1). */
  {
    reset_world();
    fd_pubkey_t stake_acct = { .ul[0] = 0x53544B4544474531UL };
    fd_pubkey_t vote_acct  = { .ul[0] = 0x564F544543414331UL };
    uchar sdata[ FD_STAKE_STATE_SZ ] = {0};
    FD_STORE( fd_stake_state_t, sdata, ((fd_stake_state_t){
      .stake_type = FD_STAKE_STATE_STAKE,
      .stake = { .meta = { .staker = stake_acct, .withdrawer = stake_acct },
                 .stake = { .delegation = { .voter_pubkey = vote_acct, .stake = 5UL,
                                            .activation_epoch = 0UL, .deactivation_epoch = ULONG_MAX,
                                            .warmup_cooldown_rate = 0.25 } } } }) );
    create_test_account( env->mini->runtime->accdb, env->fork_id, &stake_acct, 2000000000UL,
                         (uint)FD_STAKE_STATE_SZ, sdata, &fd_solana_stake_program_id );
    fd_stake_delegations_root_update( fd_banks_stake_delegations_root_query( env->mini->banks ),
                                      &stake_acct, &vote_acct, 5UL, 0UL, ULONG_MAX, 0UL,
                                      FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );

    fd_txn_p_t sp[2] = {0};
    fd_pubkey_t skeys[2] = { pubkey1, stake_acct };
    bundle_acquire_repr( skeys, 2UL, 2UL );
    for( ulong i=0UL; i<2UL; i++ ) {
      serialize_bundle_txn( &sp[i], skeys, 2UL, 0UL );
      env->txn_in.txn                 = &sp[i];
      env->txn_in.bundle.is_bundle    = 1;
      env->txn_in.bundle.prev_txn_cnt = i;
      for( ulong j=0UL; j<i; j++ ) env->txn_in.bundle.prev_txn_outs[j] = &env->txn_out[j];
      fd_runtime_prepare_and_execute_txn( env->runtime, env->bank, &env->txn_in, &env->txn_out[i] );
      FD_TEST( env->txn_out[i].err.is_committable );
      FD_TEST( env->txn_out[i].accounts.is_writable[1] );
    }

    /* tx0 saw the stake account and queued stake_update; ownership and
       the stake_update flag both moved to tx1 (cleared on tx0), so the
       delegation update fires exactly once on the new owner.  tx1 then
       drains the account to zero (closed). */
    FD_TEST( env->txn_out[0].accounts.account_acquired[1] == 0 );
    FD_TEST( env->txn_out[0].accounts.stake_update[1] == 0 ); /* moved away */
    FD_TEST( env->txn_out[1].accounts.account_acquired[1] == 1 );
    FD_TEST( env->txn_out[1].accounts.stake_update[1] );      /* carried onto new owner */
    env->txn_out[1].accounts.account[1]->lamports   = 0UL;
    env->txn_out[1].accounts.account[1]->data_len   = 0UL;
    fd_memset( env->txn_out[1].accounts.account[1]->owner, 0, 32UL );

    fd_runtime_commit_txn( env->runtime, env->bank, NULL, &env->txn_out[0], 0 );
    fd_runtime_commit_txn( env->runtime, env->bank, NULL, &env->txn_out[1], 0 );
    fd_runtime_fini_bundle( env->runtime );

    fd_stake_delegations_t * frontier = fd_bank_stake_delegations_frontier_query( env->mini->banks, env->bank );
    FD_TEST( !find_visible_stake_delegation( frontier, &stake_acct ) ); /* removed exactly once */
    fd_bank_stake_delegations_end_frontier_query( env->mini->banks, env->bank );
  }

  FD_LOG_NOTICE(( "test bundle non-owner stake_update carry... ok" ));

  /* Test: a fully-cancelled bundle must not apply any vote op.  tx0
     queues rm_vote then the bundle is cancelled (not committed); the
     pre-existing root entry must survive untouched. */
  {
    reset_world();
    fd_pubkey_t cancel_fp  = { .ul[0] = 0x43414E43454C4650UL };
    fd_pubkey_t cancel_acc = { .ul[0] = 0x43414E43454C4143UL };
    create_test_account( env->mini->runtime->accdb, env->fork_id, &cancel_fp,  1000000000UL, 0UL, NULL, &system );
    create_test_account( env->mini->runtime->accdb, env->fork_id, &cancel_acc, 1000000UL,    0UL, NULL, &system );

    env->bank->new_votes_fork_id = fd_new_votes_new_fork( fd_bank_new_votes( env->bank ) );
    fd_new_votes_t * nv   = fd_bank_new_votes( env->bank );
    ushort           fidx = env->bank->new_votes_fork_id;
    fd_new_votes_insert( nv, fidx, &cancel_acc );
    fd_new_votes_apply_delta( nv, fidx );

    fd_txn_p_t cp = {0};
    fd_pubkey_t ckeys[2] = { cancel_fp, cancel_acc };
    bundle_acquire_repr( ckeys, 2UL, 1UL );
    serialize_bundle_txn( &cp, ckeys, 2UL, 0UL );
    env->txn_in.txn                 = &cp;
    env->txn_in.bundle.is_bundle    = 1;
    env->txn_in.bundle.prev_txn_cnt = 0;
    fd_runtime_prepare_and_execute_txn( env->runtime, env->bank, &env->txn_in, &env->txn_out[0] );
    FD_TEST( env->txn_out[0].err.is_committable );
    env->txn_out[0].accounts.rm_vote[1] = 1;

    /* Cancel instead of commit: no vote op should be applied.  Single
       bundle acquire -> single release via fini_bundle. */
    env->txn_out[0].err.is_committable = 0;
    fd_runtime_fini_bundle( env->runtime );

    fd_new_votes_apply_delta( nv, fidx );
    uchar __attribute__((aligned(FD_NEW_VOTES_ITER_ALIGN))) it_mem[ FD_NEW_VOTES_ITER_FOOTPRINT ];
    fd_new_votes_iter_t * it = fd_new_votes_iter_init( nv, NULL, 0UL, it_mem );
    FD_TEST( !fd_new_votes_iter_done( it ) ); /* cancel_acc still present */
    int ts = 1;
    FD_TEST( fd_pubkey_eq( fd_new_votes_iter_ele( it, &ts ), &cancel_acc ) && !ts );
    fd_new_votes_iter_fini( it );

    fd_new_votes_evict_fork( nv, fidx );
    env->bank->new_votes_fork_id = USHORT_MAX;
  }

  FD_LOG_NOTICE(( "test bundle cancelled vote op not applied... ok" ));
}

int
main( int     argc,
      char ** argv ) {
  fd_svm_mini_limits_t limits[1];
  fd_svm_mini_limits_default( limits );
  fd_svm_mini_t * mini = fd_svm_test_boot( &argc, &argv, limits );

  test_execute_bundles( mini );

  FD_LOG_NOTICE(( "pass" ));
  fd_svm_test_halt( mini );
  return 0;
}
