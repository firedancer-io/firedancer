/* Test accounts_resize_delta tracking with signed arithmetic. */

#include "fd_svm_mini.h"
#include "../program/fd_bpf_loader_program.h"
#include "../fd_system_ids.h"
#include "../../../disco/fd_txn_p.h"
#include <stdlib.h>

#define MiB (1L << 20)

#define TEST_SLOTS_PER_EPOCH       (3UL)
#define TEST_LAMPORTS              (100000000000UL)

#define SYSTEM_PROGRAM_IX_ALLOCATE (8U)

struct test_env {
  fd_svm_mini_t * mini;
  fd_bank_t *     bank;
  fd_accdb_fork_id_t fork_id;
  fd_txn_in_t     txn_in;
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
  if( data && dlen ) fd_memcpy( entry.data, data, dlen );
  entry.data_len   = dlen;
  entry.lamports   = lamports;
  entry.executable = 0;
  if( owner ) {
    memcpy( entry.owner, owner->key, 32UL );
  } else {
    memset( entry.owner, 0UL, 32UL );
  }
  entry.commit = 1;
  fd_accdb_unwrite_one( accdb, &entry );
}

static void
setup_test( test_env_t * env, fd_svm_mini_t * mini ) {
  fd_memset( env, 0, sizeof(test_env_t) );
  env->mini = mini;

  fd_svm_mini_params_t params[1];
  fd_svm_mini_params_default( params );
  params->slots_per_epoch = TEST_SLOTS_PER_EPOCH;
  ulong root_idx = fd_svm_mini_reset( mini, params );

  ulong child_idx = fd_svm_mini_attach_child( mini, root_idx, 10UL );
  env->bank    = fd_svm_mini_bank( mini, child_idx );
  env->fork_id = fd_svm_mini_fork_id( mini, child_idx );
}

static void
create_allocatable_account( test_env_t * env, fd_pubkey_t const * pubkey ) {
  fd_pubkey_t system_program = fd_solana_system_program_id;
  create_account_raw( env->mini->runtime->accdb, env->fork_id, pubkey, TEST_LAMPORTS, 0UL, NULL, &system_program );
}

static void
create_loader_v3_buffer( test_env_t *        env,
                         fd_pubkey_t const * pubkey,
                         fd_pubkey_t const * authority,
                         ulong               buffer_size ) {
  ulong dlen = BUFFER_METADATA_SIZE + buffer_size;
  uchar * data = aligned_alloc( 8UL, fd_ulong_align_up( dlen, 8UL ) );
  FD_TEST( data );
  fd_memset( data, 0, dlen );

  fd_bpf_state_t state = {0};
  state.discriminant                        = FD_BPF_STATE_BUFFER;
  state.inner.buffer.has_authority_address = 1;
  state.inner.buffer.authority_address     = *authority;

  ulong out_sz = 0UL;
  FD_TEST( !fd_bpf_state_encode( &state, data, BUFFER_METADATA_SIZE, &out_sz ) );
  FD_TEST( out_sz == BUFFER_METADATA_SIZE );

  fd_accdb_entry_t rw = fd_accdb_write_one( env->mini->runtime->accdb, env->fork_id, pubkey->key );
  fd_memset( rw.data, 0, dlen );
  FD_STORE( ulong, rw.data, 0UL );
  fd_memcpy( rw.data + 8, authority->uc, 32 );
  FD_STORE( ulong, rw.data + 40, 0UL );
  rw.data_len   = dlen;
  rw.lamports   = TEST_LAMPORTS;
  rw.executable = 1;
  fd_memcpy( rw.owner, fd_solana_bpf_loader_upgradeable_program_id.uc, 32 );
  rw.commit = 1;
  fd_accdb_unwrite_one( env->mini->runtime->accdb, &rw );
  free( data );
}

static void
create_simple_account( test_env_t * env, fd_pubkey_t const * pubkey, ulong lamports ) {
  create_account_raw( env->mini->runtime->accdb, env->fork_id, pubkey, lamports, 0UL, NULL, NULL );
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
  uchar   program_id_idx;
  uchar * account_idxs;
  ushort  account_idxs_cnt;
  uchar * data;
  ushort  data_sz;
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
               fd_hash_t *      recent_blockhash,
               txn_instr_t *    instrs,
               ushort           instr_cnt ) {
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
  for( ushort i = 0; i < instr_cnt; ++i ) {
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
build_allocate_instr( uchar * data, ulong space ) {
  data[0] = SYSTEM_PROGRAM_IX_ALLOCATE;
  data[1] = 0; data[2] = 0; data[3] = 0;
  for( int i = 0; i < 8; i++ ) {
    data[4+i] = (uchar)((space >> (i*8)) & 0xFF);
  }
}

static void
build_close_instr( uchar * data ) {
  fd_bpf_instruction_t instr = {0};
  instr.discriminant = FD_BPF_INSTR_CLOSE;

  ulong out_sz = 0UL;
  FD_TEST( !fd_bpf_instruction_encode( &instr, data, 4UL, &out_sz ) );
  FD_TEST( out_sz == 4UL );
}

static void
execute_txn( test_env_t *     env,
             fd_pubkey_t *    account_keys,
             ulong            account_keys_cnt,
             ulong            num_signers,
             ulong            num_readonly_unsigned,
             txn_instr_t *    instrs,
             ushort           instr_cnt ) {
  fd_signature_t signatures[8] = {0};
  fd_hash_t blockhash = {0};
  fd_memset( blockhash.uc, 0xAB, FD_HASH_FOOTPRINT );

  fd_txn_p_t txn_p = {0};
  ulong sz = txn_serialize( txn_p.payload, num_signers, signatures, num_signers,
                            0UL, num_readonly_unsigned, account_keys_cnt, account_keys,
                            &blockhash, instrs, instr_cnt );
  FD_TEST( fd_txn_parse( txn_p.payload, sz, TXN( &txn_p ), NULL ) );

  env->txn_in.txn              = &txn_p;
  env->txn_in.bundle.is_bundle = 0;

  fd_runtime_prepare_and_execute_txn( env->mini->runtime, env->bank, &env->txn_in, &env->txn_out[0] );
}

static int
txn_succeeded( test_env_t * env ) {
  return env->txn_out[0].err.is_committable &&
         env->txn_out[0].err.txn_err == FD_RUNTIME_EXECUTE_SUCCESS;
}

static long
get_resize_delta( test_env_t * env ) {
  return env->txn_out[0].details.accounts_resize_delta;
}

/* Empty txn has delta=0 */
static void
test_empty_txn_delta_is_zero( fd_svm_mini_t * mini ) {
  static test_env_t env[1];
  setup_test( env, mini );

  fd_pubkey_t acct1 = { .ul[0] = 1UL };
  fd_pubkey_t acct2 = { .ul[0] = 2UL };
  create_simple_account( env, &acct1, 1000000UL );
  create_simple_account( env, &acct2, 1000000UL );

  fd_pubkey_t keys[2] = { acct1, acct2 };
  execute_txn( env, keys, 2, 1, 0, NULL, 0 );

  FD_TEST( txn_succeeded( env ) );
  FD_TEST( get_resize_delta( env ) == 0L );

  FD_LOG_NOTICE(( "test_empty_txn_delta_is_zero: PASSED" ));
}

/* 10+9=19 MiB under limit */
static void
test_allocate_19mib_succeeds( fd_svm_mini_t * mini ) {
  static test_env_t env[1];
  setup_test( env, mini );

  fd_pubkey_t acct_a = { .ul[0] = 0xA0UL };
  fd_pubkey_t acct_b = { .ul[0] = 0xB0UL };
  create_allocatable_account( env, &acct_a );
  create_allocatable_account( env, &acct_b );

  fd_pubkey_t system = fd_solana_system_program_id;
  fd_pubkey_t keys[3] = { acct_a, acct_b, system };

  uchar data_a[12], data_b[12];
  build_allocate_instr( data_a, 10UL * (ulong)MiB );
  build_allocate_instr( data_b,  9UL * (ulong)MiB );

  uchar idx_a[1] = {0}, idx_b[1] = {1};
  txn_instr_t instrs[2] = {
    { .program_id_idx = 2, .account_idxs = idx_a, .account_idxs_cnt = 1, .data = data_a, .data_sz = 12 },
    { .program_id_idx = 2, .account_idxs = idx_b, .account_idxs_cnt = 1, .data = data_b, .data_sz = 12 },
  };
  execute_txn( env, keys, 3, 2, 1, instrs, 2 );

  FD_TEST( txn_succeeded( env ) );
  FD_TEST( get_resize_delta( env ) == 19L * MiB );
  FD_LOG_NOTICE(( "test_allocate_19mib_succeeds: PASSED (delta = %ld MiB)", get_resize_delta( env ) / MiB ));
}

/* 10+10=20 MiB at limit */
static void
test_allocate_20mib_succeeds( fd_svm_mini_t * mini ) {
  static test_env_t env[1];
  setup_test( env, mini );

  fd_pubkey_t acct_a = { .ul[0] = 0xA2UL };
  fd_pubkey_t acct_b = { .ul[0] = 0xB2UL };
  create_allocatable_account( env, &acct_a );
  create_allocatable_account( env, &acct_b );

  fd_pubkey_t system = fd_solana_system_program_id;
  fd_pubkey_t keys[3] = { acct_a, acct_b, system };

  uchar data_a[12], data_b[12];
  build_allocate_instr( data_a, 10UL * (ulong)MiB );
  build_allocate_instr( data_b, 10UL * (ulong)MiB );

  uchar idx_a[1] = {0}, idx_b[1] = {1};
  txn_instr_t instrs[2] = {
    { .program_id_idx = 2, .account_idxs = idx_a, .account_idxs_cnt = 1, .data = data_a, .data_sz = 12 },
    { .program_id_idx = 2, .account_idxs = idx_b, .account_idxs_cnt = 1, .data = data_b, .data_sz = 12 },
  };
  execute_txn( env, keys, 3, 2, 1, instrs, 2 );

  FD_TEST( txn_succeeded( env ) );
  FD_TEST( get_resize_delta( env ) == 20L * MiB );
  FD_LOG_NOTICE(( "test_allocate_20mib_succeeds: PASSED (delta = %ld MiB)", get_resize_delta( env ) / MiB ));
}

/* 7+7+7=21 MiB exceeds per-txn limit (20 MiB).
   Each allocation is under the 10 MiB per-account limit, so this
   exercises the MAX_PERMITTED_ACCOUNT_DATA_ALLOCS_PER_TXN branch. */
static void
test_allocate_21mib_fails( fd_svm_mini_t * mini ) {
  static test_env_t env[1];
  setup_test( env, mini );

  fd_pubkey_t acct_a = { .ul[0] = 0xA1UL };
  fd_pubkey_t acct_b = { .ul[0] = 0xB1UL };
  fd_pubkey_t acct_c = { .ul[0] = 0xC1UL };
  create_allocatable_account( env, &acct_a );
  create_allocatable_account( env, &acct_b );
  create_allocatable_account( env, &acct_c );

  fd_pubkey_t system = fd_solana_system_program_id;
  fd_pubkey_t keys[4] = { acct_a, acct_b, acct_c, system };

  uchar data_a[12], data_b[12], data_c[12];
  build_allocate_instr( data_a, 7UL * (ulong)MiB );
  build_allocate_instr( data_b, 7UL * (ulong)MiB );
  build_allocate_instr( data_c, 7UL * (ulong)MiB );

  uchar idx_a[1] = {0}, idx_b[1] = {1}, idx_c[1] = {2};
  txn_instr_t instrs[3] = {
    { .program_id_idx = 3, .account_idxs = idx_a, .account_idxs_cnt = 1, .data = data_a, .data_sz = 12 },
    { .program_id_idx = 3, .account_idxs = idx_b, .account_idxs_cnt = 1, .data = data_b, .data_sz = 12 },
    { .program_id_idx = 3, .account_idxs = idx_c, .account_idxs_cnt = 1, .data = data_c, .data_sz = 12 },
  };
  execute_txn( env, keys, 4, 3, 1, instrs, 3 );

  FD_TEST( !txn_succeeded( env ) );

  FD_LOG_NOTICE(( "test_allocate_21mib_fails: PASSED" ));
}

/* Closing a loader-v3 buffer gives negative delta. */
static void
test_close_gives_negative_delta( fd_svm_mini_t * mini ) {
  static test_env_t env[1];
  setup_test( env, mini );

  fd_pubkey_t authority  = { .ul[0] = 0xA3UL };
  fd_pubkey_t buffer     = { .ul[0] = 0xC3UL };
  fd_pubkey_t recipient  = { .ul[0] = 0xD3UL };
  ulong buffer_size = 5UL * (ulong)MiB;

  create_simple_account( env, &authority, TEST_LAMPORTS );
  create_loader_v3_buffer( env, &buffer, &authority, buffer_size );
  create_simple_account( env, &recipient, 1000000UL );

  fd_pubkey_t loader_v3 = fd_solana_bpf_loader_upgradeable_program_id;
  fd_pubkey_t keys[4] = { authority, buffer, recipient, loader_v3 };

  uchar close_data[4];
  build_close_instr( close_data );

  uchar idx[3] = { 1, 2, 0 };
  txn_instr_t instrs[1] = {
    { .program_id_idx = 3, .account_idxs = idx, .account_idxs_cnt = 3, .data = close_data, .data_sz = 4 },
  };
  execute_txn( env, keys, 4, 1, 1, instrs, 1 );

  FD_TEST( txn_succeeded( env ) );
  long expected_delta = -(long)buffer_size - ((long)BUFFER_METADATA_SIZE - (long)SIZE_OF_UNINITIALIZED);
  FD_TEST( get_resize_delta( env ) == expected_delta );
  FD_LOG_NOTICE(( "test_close_gives_negative_delta: PASSED (delta = %ld bytes)", get_resize_delta( env ) ));
}

/* Closing a loader-v3 buffer enables allocation that would otherwise exceed limit.
   10 MiB + 10 MiB - (5 MiB + 33 bytes) + 5 MiB = 20 MiB - 33 bytes.
   With unsigned arithmetic this would fail. */
static void
test_close_enables_more_allocation( fd_svm_mini_t * mini ) {
  static test_env_t env[1];
  setup_test( env, mini );

  fd_pubkey_t authority  = { .ul[0] = 0xA4UL };
  fd_pubkey_t buffer     = { .ul[0] = 0xC4UL };
  fd_pubkey_t recipient  = { .ul[0] = 0xD4UL };
  fd_pubkey_t acct_a     = { .ul[0] = 0xE4UL };
  fd_pubkey_t acct_b     = { .ul[0] = 0xF4UL };
  fd_pubkey_t acct_c     = { .ul[0] = 0x14UL };
  ulong buffer_size = 5UL * (ulong)MiB;

  create_simple_account( env, &authority, TEST_LAMPORTS );
  create_loader_v3_buffer( env, &buffer, &authority, buffer_size );
  create_simple_account( env, &recipient, 1000000UL );
  create_allocatable_account( env, &acct_a );
  create_allocatable_account( env, &acct_b );
  create_allocatable_account( env, &acct_c );

  fd_pubkey_t system = fd_solana_system_program_id;
  fd_pubkey_t loader_v3 = fd_solana_bpf_loader_upgradeable_program_id;
  fd_pubkey_t keys[8] = { authority, acct_a, acct_b, acct_c, buffer, recipient, system, loader_v3 };

  uchar alloc_a[12], alloc_b[12], alloc_c[12], close_data[4];
  build_allocate_instr( alloc_a, 10UL * (ulong)MiB );
  build_allocate_instr( alloc_b, 10UL * (ulong)MiB );
  build_allocate_instr( alloc_c,  5UL * (ulong)MiB );
  build_close_instr( close_data );

  uchar idx_a[1] = {1}, idx_b[1] = {2}, idx_c[1] = {3};
  uchar idx_close[3] = { 4, 5, 0 };

  txn_instr_t instrs[4] = {
    { .program_id_idx = 6, .account_idxs = idx_a,      .account_idxs_cnt = 1, .data = alloc_a, .data_sz = 12 },
    { .program_id_idx = 6, .account_idxs = idx_b,      .account_idxs_cnt = 1, .data = alloc_b, .data_sz = 12 },
    { .program_id_idx = 7, .account_idxs = idx_close,  .account_idxs_cnt = 3, .data = close_data, .data_sz = 4 },
    { .program_id_idx = 6, .account_idxs = idx_c,      .account_idxs_cnt = 1, .data = alloc_c, .data_sz = 12 },
  };
  execute_txn( env, keys, 8, 4, 2, instrs, 4 );

  FD_TEST( txn_succeeded( env ) );
  long delta = get_resize_delta( env );
  /* Expected: 10 MiB + 10 MiB - (5 MiB + 33 bytes close delta) + 5 MiB = 20 MiB - 33 bytes */
  FD_TEST( delta == 20L * MiB - ((long)BUFFER_METADATA_SIZE - (long)SIZE_OF_UNINITIALIZED) );
  FD_LOG_NOTICE(( "test_close_enables_more_allocation: PASSED (delta = %ld bytes)", delta ));
}

int
main( int argc, char ** argv ) {
  fd_svm_mini_limits_t limits[1];
  fd_svm_mini_limits_default( limits );
  fd_svm_mini_t * mini = fd_svm_test_boot( &argc, &argv, limits );

  test_empty_txn_delta_is_zero( mini );
  test_allocate_19mib_succeeds( mini );
  test_allocate_20mib_succeeds( mini );
  test_allocate_21mib_fails( mini );
  test_close_gives_negative_delta( mini );
  test_close_enables_more_allocation( mini );

  FD_LOG_NOTICE(( "pass" ));
  fd_svm_test_halt( mini );
  return 0;
}
