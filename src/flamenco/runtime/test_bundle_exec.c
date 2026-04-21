#include "tests/fd_svm_mini.h"
#include "fd_runtime.h"
#include "fd_bank.h"
#include "fd_system_ids.h"
#include "fd_alut.h"
#include "program/fd_system_program.h"
#include "program/fd_bpf_loader_program.h"
#include "sysvar/fd_sysvar.h"
#include "sysvar/fd_sysvar_base.h"
#include "sysvar/fd_sysvar_cache.h"
#include "../accdb/fd_accdb.h"
#include "../features/fd_features.h"
#include "../../disco/fd_txn_p.h"

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
  do {                                                                               \
     uchar _buf[3];                                                                  \
     fd_bincode_encode_ctx_t _encode_ctx = { .data = _buf, .dataend = _buf+3 };      \
     fd_bincode_compact_u16_encode( &_to_add, &_encode_ctx );                        \
     ulong _sz = (ulong) ((uchar *)_encode_ctx.data - _buf );                        \
     FD_CHECKED_ADD_TO_TXN_DATA( _begin, _cur_data, _buf, _sz );                     \
  } while(0);                                                                        \
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

  /* ==========================================================================
     Test 1: rw -> rw — bundle reuses a writable account as writable
     ========================================================================== */

  fd_txn_p_t txn_p = {0};
  ulong sz = txn_serialize( txn_p.payload, 1, &signature, 1UL, 0UL, 0UL, 2UL, account_keys, &dummy_hash );
  txn_p.payload_sz = (ushort)sz;
  FD_TEST( fd_txn_parse( txn_p.payload, sz, TXN( &txn_p ), NULL ) );

  env->txn_in.txn                     = &txn_p;
  env->txn_in.bundle.is_bundle        = 1;
  env->txn_in.bundle.prev_txn_cnt     = 0;
  fd_runtime_prepare_and_execute_txn( env->runtime, env->bank, &env->txn_in, &env->txn_out[0] );
  FD_TEST( env->txn_out[0].err.is_committable );
  FD_TEST( env->txn_out[0].err.txn_err==FD_RUNTIME_EXECUTE_SUCCESS );
  FD_TEST( !memcmp( &env->txn_out[0].accounts.keys[0], &pubkey1, sizeof(fd_pubkey_t) ) );
  FD_TEST( !memcmp( &env->txn_out[0].accounts.keys[1], &pubkey2, sizeof(fd_pubkey_t) ) );
  FD_TEST( env->txn_out[0].accounts.account[0]._writable == 1 );
  FD_TEST( env->txn_out[0].accounts.account[1]._writable == 1 );
  FD_TEST( env->txn_out[0].accounts.account[1].lamports == 1000000UL );
  env->txn_out[0].accounts.account[1].lamports = 2000000UL;

  env->txn_in.txn                     = &txn_p;
  env->txn_in.bundle.is_bundle        = 1;
  env->txn_in.bundle.prev_txn_cnt     = 1;
  env->txn_in.bundle.prev_txn_outs[0] = &env->txn_out[0];
  fd_runtime_prepare_and_execute_txn( env->runtime, env->bank, &env->txn_in, &env->txn_out[1] );
  FD_TEST( env->txn_out[1].err.is_committable );
  FD_TEST( env->txn_out[1].err.txn_err==FD_RUNTIME_EXECUTE_SUCCESS );
  FD_LOG_NOTICE(( "tx1 acct1 lamports = %lu", env->txn_out[1].accounts.account[1].lamports ));
  FD_TEST( env->txn_out[1].accounts.account[1].lamports == 2000000UL );

  /* Same txn but outside of a bundle should see the original 1000000. */
  env->txn_in.txn              = &txn_p;
  env->txn_in.bundle.is_bundle = 0;
  fd_runtime_prepare_and_execute_txn( env->runtime, env->bank, &env->txn_in, &env->txn_out[2] );
  FD_TEST( env->txn_out[2].err.is_committable );
  FD_TEST( env->txn_out[2].err.txn_err==FD_RUNTIME_EXECUTE_SUCCESS );
  FD_TEST( env->txn_out[2].accounts.account[1].lamports == 1000000UL );
  env->txn_out[2].err.is_committable = 0;
  fd_runtime_cancel_txn( env->runtime, &env->txn_out[2] );

  fd_runtime_commit_txn( env->runtime, env->bank, &env->txn_out[0] );
  fd_runtime_commit_txn( env->runtime, env->bank, &env->txn_out[1] );

  /* After commit, non-bundle txn sees 2000000. */
  env->txn_in.txn              = &txn_p;
  env->txn_in.bundle.is_bundle = 0;
  fd_runtime_prepare_and_execute_txn( env->runtime, env->bank, &env->txn_in, &env->txn_out[2] );
  FD_TEST( env->txn_out[2].err.is_committable );
  FD_TEST( env->txn_out[2].accounts.account[1].lamports == 2000000UL );
  env->txn_out[2].err.is_committable = 0;
  fd_runtime_cancel_txn( env->runtime, &env->txn_out[2] );

  FD_LOG_NOTICE(( "test rw -> rw... ok" ));

  /* ==========================================================================
     Test 2: rw -> ro -> rw -> ro
     ========================================================================== */

  sz = txn_serialize( txn_p.payload, 1, &signature, 1UL, 0UL, 0UL, 2UL, account_keys, &dummy_hash );
  txn_p.payload_sz = (ushort)sz;
  FD_TEST( fd_txn_parse( txn_p.payload, sz, TXN( &txn_p ), NULL ) );

  env->txn_in.txn                     = &txn_p;
  env->txn_in.bundle.is_bundle        = 1;
  env->txn_in.bundle.prev_txn_cnt     = 0;
  fd_runtime_prepare_and_execute_txn( env->runtime, env->bank, &env->txn_in, &env->txn_out[0] );
  FD_TEST( env->txn_out[0].err.is_committable );
  FD_TEST( env->txn_out[0].accounts.account[1]._writable == 1 );
  env->txn_out[0].accounts.account[1].lamports = 2000001UL;

  /* tx1: account becomes readonly */
  sz = txn_serialize( txn_p.payload, 1, &signature, 1UL, 0UL, 1UL, 2UL, account_keys, &dummy_hash );
  txn_p.payload_sz = (ushort)sz;
  FD_TEST( fd_txn_parse( txn_p.payload, sz, TXN( &txn_p ), NULL ) );
  env->txn_in.txn                     = &txn_p;
  env->txn_in.bundle.prev_txn_cnt     = 1;
  env->txn_in.bundle.prev_txn_outs[0] = &env->txn_out[0];
  fd_runtime_prepare_and_execute_txn( env->runtime, env->bank, &env->txn_in, &env->txn_out[1] );
  FD_TEST( env->txn_out[1].err.is_committable );
  FD_TEST( env->txn_out[1].accounts.account[1]._writable == 0 );
  FD_TEST( env->txn_out[1].accounts.account[1].lamports == 2000001UL );

  /* tx2: account becomes writable again */
  sz = txn_serialize( txn_p.payload, 1, &signature, 1UL, 0UL, 0UL, 2UL, account_keys, &dummy_hash );
  txn_p.payload_sz = (ushort)sz;
  FD_TEST( fd_txn_parse( txn_p.payload, sz, TXN( &txn_p ), NULL ) );
  env->txn_in.txn                     = &txn_p;
  env->txn_in.bundle.prev_txn_cnt     = 2;
  env->txn_in.bundle.prev_txn_outs[0] = &env->txn_out[0];
  env->txn_in.bundle.prev_txn_outs[1] = &env->txn_out[1];
  fd_runtime_prepare_and_execute_txn( env->runtime, env->bank, &env->txn_in, &env->txn_out[2] );
  FD_TEST( env->txn_out[2].err.is_committable );
  FD_TEST( env->txn_out[2].accounts.account[1]._writable == 1 );
  FD_TEST( env->txn_out[2].accounts.account[1].lamports == 2000001UL );
  env->txn_out[2].accounts.account[1].lamports = 2000011UL;

  /* tx3: readonly again */
  sz = txn_serialize( txn_p.payload, 1, &signature, 1UL, 0UL, 1UL, 2UL, account_keys, &dummy_hash );
  txn_p.payload_sz = (ushort)sz;
  FD_TEST( fd_txn_parse( txn_p.payload, sz, TXN( &txn_p ), NULL ) );
  env->txn_in.txn                     = &txn_p;
  env->txn_in.bundle.prev_txn_cnt     = 3;
  env->txn_in.bundle.prev_txn_outs[0] = &env->txn_out[0];
  env->txn_in.bundle.prev_txn_outs[1] = &env->txn_out[1];
  env->txn_in.bundle.prev_txn_outs[2] = &env->txn_out[2];
  fd_runtime_prepare_and_execute_txn( env->runtime, env->bank, &env->txn_in, &env->txn_out[3] );
  FD_TEST( env->txn_out[3].err.is_committable );
  FD_TEST( env->txn_out[3].accounts.account[1]._writable == 0 );
  FD_TEST( env->txn_out[3].accounts.account[1].lamports == 2000011UL );

  fd_runtime_commit_txn( env->runtime, env->bank, &env->txn_out[0] );
  fd_runtime_commit_txn( env->runtime, env->bank, &env->txn_out[1] );
  fd_runtime_commit_txn( env->runtime, env->bank, &env->txn_out[2] );
  fd_runtime_commit_txn( env->runtime, env->bank, &env->txn_out[3] );

  FD_LOG_NOTICE(( "test rw -> ro -> rw -> ro... ok" ));

  /* ==========================================================================
     Test 3: Bundle fails after first transaction — single cancel
     ========================================================================== */

  sz = txn_serialize( txn_p.payload, 1, &signature, 1UL, 0UL, 0UL, 2UL, account_keys, &dummy_hash );
  txn_p.payload_sz = (ushort)sz;
  FD_TEST( fd_txn_parse( txn_p.payload, sz, TXN( &txn_p ), NULL ) );

  env->txn_in.txn                     = &txn_p;
  env->txn_in.bundle.is_bundle        = 1;
  env->txn_in.bundle.prev_txn_cnt     = 0;
  fd_runtime_prepare_and_execute_txn( env->runtime, env->bank, &env->txn_in, &env->txn_out[0] );
  FD_TEST( env->txn_out[0].err.is_committable );
  FD_TEST( env->txn_out[0].accounts.account[1].lamports == 2000011UL );
  env->txn_out[0].accounts.account[1].lamports = 2000021UL;
  env->txn_out[0].err.is_committable = 0;
  fd_runtime_cancel_txn( env->runtime, &env->txn_out[0] );

  FD_LOG_NOTICE(( "test bundle cancel after tx0... ok" ));

  /* ==========================================================================
     Test 4: 5-tx bundle, all cancelled
     ========================================================================== */

  sz = txn_serialize( txn_p.payload, 1, &signature, 1UL, 0UL, 0UL, 2UL, account_keys, &dummy_hash );
  txn_p.payload_sz = (ushort)sz;
  FD_TEST( fd_txn_parse( txn_p.payload, sz, TXN( &txn_p ), NULL ) );

  env->txn_in.txn                     = &txn_p;
  env->txn_in.bundle.is_bundle        = 1;
  env->txn_in.bundle.prev_txn_cnt     = 0;
  fd_runtime_prepare_and_execute_txn( env->runtime, env->bank, &env->txn_in, &env->txn_out[0] );
  FD_TEST( env->txn_out[0].err.is_committable );
  FD_TEST( env->txn_out[0].accounts.account[1].lamports == 2000011UL );
  env->txn_out[0].accounts.account[1].lamports = 2000021UL;

  env->txn_in.bundle.prev_txn_cnt     = 1;
  env->txn_in.bundle.prev_txn_outs[0] = &env->txn_out[0];
  fd_runtime_prepare_and_execute_txn( env->runtime, env->bank, &env->txn_in, &env->txn_out[1] );
  FD_TEST( env->txn_out[1].err.is_committable );
  FD_TEST( env->txn_out[1].accounts.account[1].lamports == 2000021UL );
  env->txn_out[1].accounts.account[1].lamports = 2000031UL;

  env->txn_in.bundle.prev_txn_cnt     = 2;
  env->txn_in.bundle.prev_txn_outs[1] = &env->txn_out[1];
  fd_runtime_prepare_and_execute_txn( env->runtime, env->bank, &env->txn_in, &env->txn_out[2] );
  FD_TEST( env->txn_out[2].err.is_committable );
  FD_TEST( env->txn_out[2].accounts.account[1].lamports == 2000031UL );
  env->txn_out[2].accounts.account[1].lamports = 2000041UL;

  /* tx3: readonly */
  sz = txn_serialize( txn_p.payload, 1, &signature, 1UL, 0UL, 1UL, 2UL, account_keys, &dummy_hash );
  txn_p.payload_sz = (ushort)sz;
  FD_TEST( fd_txn_parse( txn_p.payload, sz, TXN( &txn_p ), NULL ) );
  env->txn_in.txn                     = &txn_p;
  env->txn_in.bundle.prev_txn_cnt     = 3;
  env->txn_in.bundle.prev_txn_outs[2] = &env->txn_out[2];
  fd_runtime_prepare_and_execute_txn( env->runtime, env->bank, &env->txn_in, &env->txn_out[3] );
  FD_TEST( env->txn_out[3].err.is_committable );
  FD_TEST( env->txn_out[3].accounts.account[1]._writable == 0 );
  FD_TEST( env->txn_out[3].accounts.account[1].lamports == 2000041UL );

  /* tx4: writable, simulated failure */
  sz = txn_serialize( txn_p.payload, 1, &signature, 1UL, 0UL, 0UL, 2UL, account_keys, &dummy_hash );
  txn_p.payload_sz = (ushort)sz;
  FD_TEST( fd_txn_parse( txn_p.payload, sz, TXN( &txn_p ), NULL ) );
  env->txn_in.txn                     = &txn_p;
  env->txn_in.bundle.prev_txn_cnt     = 4;
  env->txn_in.bundle.prev_txn_outs[3] = &env->txn_out[3];
  fd_runtime_prepare_and_execute_txn( env->runtime, env->bank, &env->txn_in, &env->txn_out[4] );
  FD_TEST( env->txn_out[4].err.is_committable );
  FD_TEST( env->txn_out[4].accounts.account[1].lamports == 2000041UL );
  env->txn_out[4].err.txn_err = FD_RUNTIME_TXN_ERR_INSTRUCTION_ERROR;

  for( int i=0; i<5; i++ ) env->txn_out[i].err.is_committable = 0;
  for( int i=0; i<5; i++ ) fd_runtime_cancel_txn( env->runtime, &env->txn_out[i] );

  FD_LOG_NOTICE(( "test 5-tx bundle cancel... ok" ));

  /* ==========================================================================
     Test 5: Account reclaim divergence between bundle and replay
     ========================================================================== */

  fd_pubkey_t some_program = { .ul[0] = 0xDEADBEEFUL };
  fd_pubkey_t victim       = { .ul[0] = 0xCAFEUL };
  uchar victim_data[64];
  memset( victim_data, 0xAA, 64UL );
  create_test_account( env->mini->runtime->accdb, env->fork_id, &victim, 500000UL, 64UL, victim_data, &some_program );

  fd_pubkey_t reclaim_keys[2] = { pubkey1, victim };
  sz = txn_serialize( txn_p.payload, 1, &signature, 1UL, 0UL, 0UL, 2UL, reclaim_keys, &dummy_hash );
  txn_p.payload_sz = (ushort)sz;
  FD_TEST( fd_txn_parse( txn_p.payload, sz, TXN( &txn_p ), NULL ) );

  env->txn_in.txn              = &txn_p;
  env->txn_in.bundle.is_bundle = 1;
  env->txn_in.bundle.prev_txn_cnt = 0;
  fd_runtime_prepare_and_execute_txn( env->runtime, env->bank, &env->txn_in, &env->txn_out[0] );
  FD_TEST( env->txn_out[0].err.is_committable );
  FD_TEST( env->txn_out[0].accounts.account[1].lamports == 500000UL );
  FD_TEST( env->txn_out[0].accounts.account[1].data_len == 64UL );
  FD_TEST( !memcmp( env->txn_out[0].accounts.account[1].owner, &some_program, 32UL ) );

  /* Simulate SBF program draining lamports to 0. */
  env->txn_out[0].accounts.account[1].lamports = 0UL;

  env->txn_in.bundle.prev_txn_cnt     = 1;
  env->txn_in.bundle.prev_txn_outs[0] = &env->txn_out[0];
  fd_runtime_prepare_and_execute_txn( env->runtime, env->bank, &env->txn_in, &env->txn_out[1] );
  FD_TEST( env->txn_out[1].err.is_committable );

  /* In bundle mode, tx1 must not see un-reclaimed state from tx0. */
  FD_TEST( env->txn_out[1].accounts.account[1].lamports == 0UL );
  FD_TEST( env->txn_out[1].accounts.account[1].data_len != 64UL );
  FD_TEST( memcmp( env->txn_out[1].accounts.account[1].owner, &some_program, 32UL ) );

  fd_runtime_commit_txn( env->runtime, env->bank, &env->txn_out[0] );
  fd_runtime_commit_txn( env->runtime, env->bank, &env->txn_out[1] );

  /* Post-commit non-bundle read */
  env->txn_in.txn              = &txn_p;
  env->txn_in.bundle.is_bundle = 0;
  fd_runtime_prepare_and_execute_txn( env->runtime, env->bank, &env->txn_in, &env->txn_out[2] );
  FD_TEST( env->txn_out[2].err.is_committable );
  FD_TEST( env->txn_out[2].accounts.account[1].lamports == 0UL );
  FD_TEST( env->txn_out[2].accounts.account[1].data_len == 0UL );
  fd_pubkey_t zero_owner = {0};
  FD_TEST( !memcmp( env->txn_out[2].accounts.account[1].owner, &zero_owner, 32UL ) );
  env->txn_out[2].err.is_committable = 0;
  fd_runtime_cancel_txn( env->runtime, &env->txn_out[2] );

  FD_LOG_NOTICE(( "test reclaim divergence... ok" ));

  /* ==========================================================================
     Test 6: Bundle program-cache coherency regression
     ========================================================================== */

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

  /* tx0: simulated upgrade — empty txn including programdata, then we
     manually update its data to slot=10 in txn_out. */
  txn_p = (fd_txn_p_t){0};
  fd_pubkey_t txn1_keys[3] = { payer, program_key, programdata_key };
  sz = txn_serialize( txn_p.payload, 1, &signature, 1UL, 0UL, 0UL, 3UL, txn1_keys, &dummy_hash );
  txn_p.payload_sz = (ushort)sz;
  FD_TEST( fd_txn_parse( txn_p.payload, sz, TXN( &txn_p ), NULL ) );

  env->txn_in.txn                 = &txn_p;
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
  FD_TEST( env->txn_out[0].accounts.account[ pd_idx ]._writable );

  uchar * pd_out_data = env->txn_out[0].accounts.account[ pd_idx ].data;
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

  /* tx1: invoke program WITHOUT programdata in account list. */
  fd_pubkey_t txn2_keys[2] = { payer, program_key };
  sz = txn_serialize( txn_p.payload, 1, &signature, 1UL, 0UL, 0UL, 2UL, txn2_keys, &dummy_hash );
  txn_p.payload_sz = (ushort)sz;
  FD_TEST( fd_txn_parse( txn_p.payload, sz, TXN( &txn_p ), NULL ) );

  env->txn_in.txn                     = &txn_p;
  env->txn_in.bundle.prev_txn_cnt     = 1;
  env->txn_in.bundle.prev_txn_outs[0] = &env->txn_out[0];
  fd_runtime_prepare_and_execute_txn( env->runtime, env->bank, &env->txn_in, &env->txn_out[1] );
  FD_TEST( env->txn_out[1].err.is_committable );

  /* Locate the loaded programdata in runtime->accounts.executable[]
     (now an array of fd_accdb_entry_t, no fd_accdb_ro_t indirection). */
  int found_programdata = 0;
  for( ulong i = 0; i < env->runtime->accounts.executable_cnt; i++ ) {
    fd_accdb_entry_t const * ent = &env->runtime->accounts.executable[i];
    if( memcmp( ent->pubkey, programdata_key.uc, 32UL ) ) continue;

    fd_bpf_state_t pd_state[1];
    FD_TEST( fd_bpf_loader_program_get_state( ent, pd_state ) == FD_EXECUTOR_INSTR_SUCCESS );
    FD_TEST( pd_state->discriminant == FD_BPF_STATE_PROGRAM_DATA );
    FD_TEST( pd_state->inner.program_data.slot == 10UL );
    found_programdata = 1;
    break;
  }
  FD_TEST( found_programdata );

  env->txn_out[0].err.is_committable = 0;
  env->txn_out[1].err.is_committable = 0;
  fd_runtime_cancel_txn( env->runtime, &env->txn_out[0] );
  fd_runtime_cancel_txn( env->runtime, &env->txn_out[1] );

  FD_LOG_NOTICE(( "test bundle program-cache coherency... ok" ));

  /* ==========================================================================
     Test 7: Bundle ALT stale-read regression
     ========================================================================== */

  {
    /* Initialize slot hashes sysvar for ALT activation logic.  Build a
       fd_slot_hashes_global_t in scratch memory with 10 entries for
       slots 1..10, encode it, and persist via fd_sysvar_account_update. */
    uchar __attribute__((aligned(FD_SYSVAR_SLOT_HASHES_ALIGN)))
        slot_hashes_mem[ FD_SYSVAR_SLOT_HASHES_FOOTPRINT ];
    fd_memset( slot_hashes_mem, 0, sizeof(slot_hashes_mem) );

    fd_slot_hashes_global_t * sh_global = (fd_slot_hashes_global_t *)slot_hashes_mem;
    uchar * sh_deque_mem = (uchar *)fd_ulong_align_up(
        (ulong)( slot_hashes_mem + sizeof(fd_slot_hashes_global_t) ),
        deq_fd_slot_hash_t_align() );
    deq_fd_slot_hash_t_new( sh_deque_mem, 512UL );
    sh_global->hashes_offset = (ulong)sh_deque_mem - (ulong)sh_global;

    fd_slot_hash_t * sh_deq = deq_fd_slot_hash_t_join( sh_deque_mem );
    for( ulong i = 0UL; i < 10UL; i++ ) {
      fd_slot_hash_t entry = { .slot = 10UL - i };
      fd_memset( entry.hash.hash, 0, 32UL );
      deq_fd_slot_hash_t_push_tail( sh_deq, entry );
    }

    uchar __attribute__((aligned(FD_SYSVAR_SLOT_HASHES_ALIGN)))
        sh_enc[ FD_SYSVAR_SLOT_HASHES_BINCODE_SZ ] = {0};
    fd_bincode_encode_ctx_t enc_ctx = {
      .data    = sh_enc,
      .dataend = sh_enc + FD_SYSVAR_SLOT_HASHES_BINCODE_SZ,
    };
    FD_TEST( !fd_slot_hashes_encode_global( sh_global, &enc_ctx ) );
    fd_sysvar_account_update( env->bank, env->mini->runtime->accdb, NULL,
                              &fd_sysvar_slot_hashes_id, sh_enc,
                              FD_SYSVAR_SLOT_HASHES_BINCODE_SZ );

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

    /* tx0: include the ALT as writable; simulate the extension by
       updating its data in txn_out. */
    fd_pubkey_t txn0_keys[2] = { pubkey1, alut_key };
    txn_p = (fd_txn_p_t){0};
    sz = txn_serialize( txn_p.payload, 1, &signature, 1UL, 0UL, 0UL,
                        2UL, txn0_keys, &dummy_hash );
    txn_p.payload_sz = (ushort)sz;
    FD_TEST( fd_txn_parse( txn_p.payload, sz, TXN( &txn_p ), NULL ) );

    env->txn_in.txn                 = &txn_p;
    env->txn_in.bundle.is_bundle    = 1;
    env->txn_in.bundle.prev_txn_cnt = 0;
    fd_runtime_prepare_and_execute_txn( env->runtime, env->bank, &env->txn_in, &env->txn_out[0] );
    FD_TEST( env->txn_out[0].err.is_committable );

    int alut_idx = -1;
    for( ushort i = 0; i < env->txn_out[0].accounts.cnt; i++ ) {
      if( fd_pubkey_eq( &env->txn_out[0].accounts.keys[i], &alut_key ) ) {
        alut_idx = i;
        break;
      }
    }
    FD_TEST( alut_idx >= 0 );
    FD_TEST( env->txn_out[0].accounts.account[ alut_idx ]._writable );

    uchar * alut_out_data = env->txn_out[0].accounts.account[ alut_idx ].data;
    fd_alut_meta_t extended_meta = alut_meta;
    extended_meta.last_extended_slot_start_index = 4;
    FD_TEST( fd_alut_state_encode( &extended_meta, alut_out_data, FD_LOOKUP_TABLE_META_SIZE ) == 0 );

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

    env->txn_in.txn                     = &txn1_p;
    env->txn_in.bundle.is_bundle        = 1;
    env->txn_in.bundle.prev_txn_cnt     = 1;
    env->txn_in.bundle.prev_txn_outs[0] = &env->txn_out[0];
    fd_runtime_prepare_and_execute_txn( env->runtime, env->bank, &env->txn_in, &env->txn_out[1] );

    FD_TEST( env->txn_out[1].err.is_committable );
    FD_TEST( env->txn_out[1].err.txn_err == FD_RUNTIME_EXECUTE_SUCCESS );

    fd_pubkey_t expected_addr = {{0}};
    expected_addr.uc[0] = 0xE3;
    expected_addr.uc[1] = 0xF3;
    FD_TEST( fd_pubkey_eq( &env->txn_out[1].accounts.keys[1], &expected_addr ) );

    if( env->txn_out[1].err.is_committable ) {
      fd_runtime_commit_txn( env->runtime, env->bank, &env->txn_out[1] );
    } else {
      fd_runtime_cancel_txn( env->runtime, &env->txn_out[1] );
    }
    fd_runtime_commit_txn( env->runtime, env->bank, &env->txn_out[0] );

    FD_LOG_NOTICE(( "test bundle ALT stale read... ok" ));
  }

  /* ==========================================================================
     Test 8: Bundle-forwarded nonce account during transaction age check
     ========================================================================== */

  {
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

    /* tx0: load nonce account writable, then write the staged bundle nonce. */
    fd_pubkey_t txn0_nonce_keys[2] = { nonce_fee_payer, nonce_key };
    txn_p = (fd_txn_p_t){0};
    sz = txn_serialize( txn_p.payload, 1, &signature, 1UL, 0UL, 0UL,
                        2UL, txn0_nonce_keys, &dummy_hash );
    txn_p.payload_sz = (ushort)sz;
    FD_TEST( fd_txn_parse( txn_p.payload, sz, TXN( &txn_p ), NULL ) );

    env->txn_in.txn                 = &txn_p;
    env->txn_in.bundle.is_bundle    = 1;
    env->txn_in.bundle.prev_txn_cnt = 0;
    fd_runtime_prepare_and_execute_txn( env->runtime, env->bank, &env->txn_in, &env->txn_out[0] );
    FD_TEST( env->txn_out[0].err.is_committable );
    FD_TEST( env->txn_out[0].err.txn_err == FD_RUNTIME_EXECUTE_SUCCESS );
    FD_TEST( fd_pubkey_eq( &env->txn_out[0].accounts.keys[1], &nonce_key ) );
    FD_TEST( env->txn_out[0].accounts.account[1]._writable );
    write_nonce_state_into( env->txn_out[0].accounts.account[1].data,
                            env->txn_out[0].accounts.account[1].data_len,
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

    fd_runtime_commit_txn( env->runtime, env->bank, &env->txn_out[0] );
    fd_runtime_commit_txn( env->runtime, env->bank, &env->txn_out[1] );

    FD_LOG_NOTICE(( "test bundle-forwarded nonce... ok" ));
  }
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
