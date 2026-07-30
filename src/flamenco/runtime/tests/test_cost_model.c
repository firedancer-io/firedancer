/* Ported from agave cost-model calculate_allocated_accounts_data_size tests. */

#include "../fd_cost_tracker.h"
#include "../fd_bank.h"
#include "../fd_runtime_const.h"
#include "../fd_runtime.h"
#include "../fd_system_ids.h"
#include "../fd_executor.h"
#include "../sysvar/fd_sysvar_instructions.h"
#include "../program/fd_compute_budget_program.h"
#include "../program/fd_system_program.h"
#include "../../features/fd_features.h"
#include "../../../ballet/txn/fd_compact_u16.h"
#include "../../../ballet/txn/fd_txn.h"
#include "../../../disco/fd_txn_p.h"
#include "../../../util/fd_util.h"

#define SYSTEM_PROGRAM_IDX (1U)

#define FD_CHECKED_ADD_TO_TXN_DATA( _begin, _cur_data, _to_add, _sz ) __extension__({ \
  FD_TEST( (*_cur_data)+_sz<=_begin+FD_TXN_MTU );                                    \
  fd_memcpy( *_cur_data, _to_add, _sz );                                             \
  *_cur_data += _sz;                                                                 \
})

#define FD_CHECKED_ADD_CU16_TO_TXN_DATA( _begin, _cur_data, _to_add ) __extension__({ \
  do {                                                                               \
     uchar _buf[3];                                                                  \
     ulong _sz = (ulong)fd_cu16_enc( (ushort)_to_add, _buf );                        \
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

typedef struct {
  uchar * data;
  ushort  data_sz;
} test_ix_t;

static ushort
encode_system_instruction( fd_system_program_instruction_t const * instr,
                           uchar *                                 buf,
                           ushort                                  buf_sz ) {
  ulong out_sz;
  int err = fd_system_program_instruction_encode( instr, buf, (ulong)buf_sz, &out_sz );
  FD_TEST( !err );
  return (ushort)out_sz;
}

static void
txn_serialize( fd_txn_p_t *     out,
               ulong            num_signers,
               ulong            num_readonly_unsigned,
               ulong            account_keys_cnt,
               fd_pubkey_t *    account_keys,
               fd_hash_t *      recent_blockhash,
               txn_instr_t *    instrs,
               ushort           instr_cnt ) {
  uchar * txn_raw_begin   = out->payload;
  uchar * txn_raw_cur_ptr = txn_raw_begin;

  uchar signature_cnt = (uchar)fd_ulong_max( 1UL, num_signers );
  FD_CHECKED_ADD_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, &signature_cnt, sizeof(uchar) );
  for( uchar i=0; i<signature_cnt; i++ ) {
    fd_signature_t sig = {0};
    FD_CHECKED_ADD_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, &sig, FD_TXN_SIGNATURE_SZ );
  }

  uchar header_b0 = (uchar)0x80UL;
  FD_CHECKED_ADD_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, &header_b0, sizeof(uchar) );

  uchar num_req_sigs    = (uchar)num_signers;
  uchar num_ro_signed   = 0;
  uchar num_ro_unsigned = (uchar)num_readonly_unsigned;
  FD_CHECKED_ADD_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, &num_req_sigs,    1 );
  FD_CHECKED_ADD_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, &num_ro_signed,   1 );
  FD_CHECKED_ADD_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, &num_ro_unsigned, 1 );

  ushort num_acct_keys = (ushort)account_keys_cnt;
  FD_CHECKED_ADD_CU16_TO_TXN_DATA( txn_raw_begin, &txn_raw_cur_ptr, num_acct_keys );
  for( ushort i=0; i<num_acct_keys; i++ ) {
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

  out->payload_sz = (ulong)(txn_raw_cur_ptr - txn_raw_begin);
}


static ulong
fd_calculate_allocated_accounts_data_size( fd_bank_t * bank,
                                           fd_txn_in_t const * txn_in ) {
  static fd_txn_out_t txn_out;
  fd_memset( &txn_out, 0, sizeof(txn_out) );
  fd_compute_budget_details_new( &txn_out.details.compute_budget );
  fd_cost_tracker_calculate_cost( bank, txn_in, &txn_out );
  return txn_out.details.txn_cost.transaction.allocated_accounts_data_size;
}

static ulong
run_allocated_data_size( fd_bank_t * bank, test_ix_t * ixs, ushort ix_cnt ) {
  fd_pubkey_t keys[2] = {
    { .ul = { 1UL, 0UL, 0UL, 0UL } },
    fd_solana_system_program_id,
  };
  fd_hash_t blockhash = {0};
  uchar empty_accounts[1] = {0};

  txn_instr_t instrs[8] = {0};
  FD_TEST( ix_cnt<=8 );
  for( ushort i=0; i<ix_cnt; i++ ) {
    instrs[i].program_id_idx = (uchar)SYSTEM_PROGRAM_IDX;
    instrs[i].account_idxs = empty_accounts;
    instrs[i].account_idxs_cnt = 0;
    instrs[i].data = ixs[i].data;
    instrs[i].data_sz = ixs[i].data_sz;
  }

  fd_txn_p_t txn_p = {0};
  txn_serialize( &txn_p, 1UL, 1UL, 2UL, keys, &blockhash, instrs, ix_cnt );
  FD_TEST( fd_txn_parse( txn_p.payload, txn_p.payload_sz, TXN( &txn_p ), NULL ) );

  fd_txn_in_t txn_in = {0};
  txn_in.txn = &txn_p;

  return fd_calculate_allocated_accounts_data_size( bank, &txn_in );
}

static void
test_calculate_allocated_accounts_data_size_no_allocation( fd_bank_t * bank ) {
  fd_system_program_instruction_t instr = {0};
  instr.discriminant = FD_SYSTEM_PROGRAM_INSTR_TRANSFER;
  instr.inner.transfer = 1UL;

  uchar data[64];
  ushort data_sz = encode_system_instruction( &instr, data, sizeof(data) );
  test_ix_t ixs[1] = { { .data = data, .data_sz = data_sz } };

  FD_TEST( run_allocated_data_size( bank, ixs, 1 )==0UL );
  FD_LOG_NOTICE(( "test_calculate_allocated_accounts_data_size_no_allocation: PASSED" ));
}

static void
test_calculate_allocated_accounts_data_size_multiple_allocations( fd_bank_t * bank ) {
  fd_system_program_instruction_t create_instr = {0};
  create_instr.discriminant = FD_SYSTEM_PROGRAM_INSTR_CREATE_ACCOUNT;
  create_instr.inner.create_account.space = 100UL;

  fd_system_program_instruction_t alloc_instr = {0};
  alloc_instr.discriminant = FD_SYSTEM_PROGRAM_INSTR_ALLOCATE;
  alloc_instr.inner.allocate = 200UL;

  uchar data1[64];
  uchar data2[64];
  ushort data1_sz = encode_system_instruction( &create_instr, data1, sizeof(data1) );
  ushort data2_sz = encode_system_instruction( &alloc_instr, data2, sizeof(data2) );

  test_ix_t ixs[2] = {
    { .data = data1, .data_sz = data1_sz },
    { .data = data2, .data_sz = data2_sz },
  };

  FD_TEST( run_allocated_data_size( bank, ixs, 2 )==(100UL+200UL) );
  FD_LOG_NOTICE(( "test_calculate_allocated_accounts_data_size_multiple_allocations: PASSED" ));
}

static void
test_calculate_allocated_accounts_data_size_max_limit( fd_bank_t * bank ) {
  ulong spaces[3] = { FD_RUNTIME_ACC_SZ_MAX, FD_RUNTIME_ACC_SZ_MAX, 100UL };
  FD_TEST( spaces[0]+spaces[1]+spaces[2] > 2UL*FD_RUNTIME_ACC_SZ_MAX );

  fd_system_program_instruction_t instrs[3] = {0};
  for( int i=0; i<3; i++ ) {
    instrs[i].discriminant = FD_SYSTEM_PROGRAM_INSTR_CREATE_ACCOUNT;
    instrs[i].inner.create_account.space = spaces[i];
  }

  uchar data0[64];
  uchar data1[64];
  uchar data2[64];
  ushort data0_sz = encode_system_instruction( &instrs[0], data0, sizeof(data0) );
  ushort data1_sz = encode_system_instruction( &instrs[1], data1, sizeof(data1) );
  ushort data2_sz = encode_system_instruction( &instrs[2], data2, sizeof(data2) );

  test_ix_t ixs[3] = {
    { .data = data0, .data_sz = data0_sz },
    { .data = data1, .data_sz = data1_sz },
    { .data = data2, .data_sz = data2_sz },
  };

  FD_TEST( run_allocated_data_size( bank, ixs, 3 )==(2UL*FD_RUNTIME_ACC_SZ_MAX) );
  FD_LOG_NOTICE(( "test_calculate_allocated_accounts_data_size_max_limit: PASSED" ));
}

static void
test_calculate_allocated_accounts_data_size_overflow( fd_bank_t * bank ) {
  fd_system_program_instruction_t create_instr = {0};
  create_instr.discriminant = FD_SYSTEM_PROGRAM_INSTR_CREATE_ACCOUNT;
  create_instr.inner.create_account.space = 100UL;

  fd_system_program_instruction_t alloc_instr = {0};
  alloc_instr.discriminant = FD_SYSTEM_PROGRAM_INSTR_ALLOCATE;
  alloc_instr.inner.allocate = ULONG_MAX;

  uchar data1[64];
  uchar data2[64];
  ushort data1_sz = encode_system_instruction( &create_instr, data1, sizeof(data1) );
  ushort data2_sz = encode_system_instruction( &alloc_instr, data2, sizeof(data2) );

  test_ix_t ixs[2] = {
    { .data = data1, .data_sz = data1_sz },
    { .data = data2, .data_sz = data2_sz },
  };

  FD_TEST( run_allocated_data_size( bank, ixs, 2 )==0UL );
  FD_LOG_NOTICE(( "test_calculate_allocated_accounts_data_size_overflow: PASSED" ));
}

static void
test_calculate_allocated_accounts_data_size_invalid_ix( fd_bank_t * bank ) {
  fd_system_program_instruction_t alloc_instr = {0};
  alloc_instr.discriminant = FD_SYSTEM_PROGRAM_INSTR_ALLOCATE;
  alloc_instr.inner.allocate = 100UL;

  uchar data1[64];
  ushort data1_sz = encode_system_instruction( &alloc_instr, data1, sizeof(data1) );

  uchar invalid_data[1] = { 0xFF };
  test_ix_t ixs[2] = {
    { .data = data1, .data_sz = data1_sz },
    { .data = invalid_data, .data_sz = (ushort)sizeof(invalid_data) },
  };

  FD_TEST( run_allocated_data_size( bank, ixs, 2 )==0UL );
  FD_LOG_NOTICE(( "test_calculate_allocated_accounts_data_size_invalid_ix: PASSED" ));
}


static void
test_sanitize_compute_unit_limits_heap_size( void ) {
  static fd_txn_out_t txn_out;
  fd_memset( &txn_out, 0, sizeof(txn_out) );
  fd_compute_budget_details_new( &txn_out.details.compute_budget );

  txn_out.details.compute_budget.has_requested_heap_size = 1;

  txn_out.details.compute_budget.heap_size = FD_MIN_HEAP_FRAME_BYTES;
  FD_TEST( fd_sanitize_compute_unit_limits( &txn_out )==FD_RUNTIME_EXECUTE_SUCCESS );

  fd_compute_budget_details_new( &txn_out.details.compute_budget );
  txn_out.details.compute_budget.has_requested_heap_size = 1;
  txn_out.details.compute_budget.heap_size = FD_MIN_HEAP_FRAME_BYTES + 1UL;
  FD_TEST( fd_sanitize_compute_unit_limits( &txn_out )==FD_RUNTIME_TXN_ERR_INSTRUCTION_ERROR );

  FD_LOG_NOTICE(( "test_sanitize_compute_unit_limits_heap_size: PASSED" ));
}

/* 5-config-a: tx-v1 (SIMD-0385) heap-size sanitization. Runs a fabricated
   v1 transaction through fd_executor_verify_transaction (which routes v1
   to fd_executor_sanitize_txn_v1_config) and asserts the heap-size accept/
   reject decision matches agave's try_into_config V1 rule (must be a
   multiple of 1 KiB in [32 KiB, 256 KiB]; bit-4-unset defaults to 32 KiB).
   https://github.com/anza-xyz/agave/blob/v4.2.0-beta.1/runtime-transaction/src/transaction_meta.rs#L157-L163 */
static int
run_v1_heap_case( fd_bank_t * bank, uint config_mask, uint heap_val ) {
  /* static: fd_txn_out_t is multi-MB (per-bundle account arrays + the
     instructions-sysvar scratch buffer), so it must not go on the stack. */
  static fd_txn_p_t txnp;
  fd_memset( &txnp, 0, sizeof(txnp) );
  fd_txn_t * txn = TXN( &txnp );
  txn->transaction_version      = FD_TXN_V1;
  txn->instr_cnt                = 0;
  txn->signature_cnt            = 0;
  txn->v1_txn_config_values_off = 64;
  fd_memcpy( txnp.payload + 4UL, &config_mask, sizeof(uint) );
  /* With only bit 4 (heap) set, the heap word is the first ConfigValues
     word, i.e. at values_off + 0. */
  fd_memcpy( txnp.payload + 64UL, &heap_val, sizeof(uint) );
  txnp.payload_sz = 128UL;

  fd_txn_in_t txn_in = {0};
  txn_in.txn = &txnp;

  static fd_txn_out_t txn_out;
  fd_memset( &txn_out, 0, sizeof(txn_out) );
  fd_compute_budget_details_new( &txn_out.details.compute_budget );

  return fd_executor_verify_transaction( bank, &txn_in, &txn_out );
}

static void
test_sanitize_txn_v1_config_heap_size( fd_bank_t * bank ) {
  /* bit 4 unset -> default 32 KiB -> accepted */
  FD_TEST( run_v1_heap_case( bank, 0x00, 0U            )==FD_RUNTIME_EXECUTE_SUCCESS );
  /* explicit valid: min, mid, max (all multiples of 1 KiB) */
  FD_TEST( run_v1_heap_case( bank, 0x10,  32U*1024U    )==FD_RUNTIME_EXECUTE_SUCCESS );
  FD_TEST( run_v1_heap_case( bank, 0x10,  64U*1024U    )==FD_RUNTIME_EXECUTE_SUCCESS );
  FD_TEST( run_v1_heap_case( bank, 0x10, 256U*1024U    )==FD_RUNTIME_EXECUTE_SUCCESS );
  /* below min, above max, and non-multiple-of-1KiB -> SanitizeFailure */
  FD_TEST( run_v1_heap_case( bank, 0x10,  16U*1024U    )==FD_RUNTIME_TXN_ERR_SANITIZE_FAILURE );
  FD_TEST( run_v1_heap_case( bank, 0x10, 512U*1024U    )==FD_RUNTIME_TXN_ERR_SANITIZE_FAILURE );
  FD_TEST( run_v1_heap_case( bank, 0x10,  32U*1024U+1U )==FD_RUNTIME_TXN_ERR_SANITIZE_FAILURE );
  FD_LOG_NOTICE(( "test_sanitize_txn_v1_config_heap_size: PASSED" ));
}

/* Phase 7b (SIMD-0385): a v1 transaction must be rejected with
   UnsupportedVersion while enable_tx_v1 is inactive. The gate precedes the
   compute-budget/heap decode, so even an otherwise-valid v1 txn (and an
   otherwise-SanitizeFailure heap value) is UnsupportedVersion when off.
   https://github.com/anza-xyz/agave/blob/v4.2.0-beta.1/runtime/src/bank.rs#L5467-L5477 */
static void
test_v1_feature_gate( void ) {
  static fd_bank_t bank_off;
  fd_memset( &bank_off, 0, sizeof(bank_off) );
  bank_off.f.slot = 1UL;
  fd_features_enable_all( &bank_off.f.features );
  bank_off.f.features.enable_tx_v1 = FD_FEATURE_DISABLED;

  FD_TEST( run_v1_heap_case( &bank_off, 0x10, 64U*1024U )==FD_RUNTIME_TXN_ERR_UNSUPPORTED_VERSION );
  FD_TEST( run_v1_heap_case( &bank_off, 0x10, 16U*1024U )==FD_RUNTIME_TXN_ERR_UNSUPPORTED_VERSION );
  FD_LOG_NOTICE(( "test_v1_feature_gate: PASSED" ));
}

static void
test_sysvar_instructions_overflow( void ) {
  static fd_txn_p_t txnp;
  fd_memset( &txnp, 0, sizeof(txnp) );
  fd_txn_t * txn = TXN( &txnp );
  txn->transaction_version = FD_TXN_V1;
  txn->instr_cnt           = 2;

  txn->instr[0].acct_cnt = 1984; txn->instr[0].data_sz = 21;
  txn->instr[1].acct_cnt = 0;    txn->instr[1].data_sz = 0;
  FD_TEST( fd_sysvar_instructions_offsets_overflow( txn )==0 );   /* start[1]==65535 -> accepted */

  txn->instr[0].data_sz = 22;
  FD_TEST( fd_sysvar_instructions_offsets_overflow( txn )==1 );   /* start[1]==65536 -> rejected */

  fd_txn_in_t txn_in = {0};
  txn_in.txn = &txnp;
  static fd_txn_out_t txn_out;
  fd_memset( &txn_out, 0, sizeof(txn_out) );
  FD_TEST( fd_sysvar_instructions_serialize_account( &txn_in, &txn_out, 0UL )
           ==FD_RUNTIME_TXN_ERR_MAX_LOADED_ACCOUNTS_DATA_SIZE_EXCEEDED );

  FD_LOG_NOTICE(( "test_sysvar_instructions_overflow: PASSED" ));
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  static fd_bank_t bank = {0};
  bank.f.slot = 1UL;
  fd_features_enable_all( &bank.f.features );

  test_calculate_allocated_accounts_data_size_no_allocation( &bank );
  test_calculate_allocated_accounts_data_size_multiple_allocations( &bank );
  test_calculate_allocated_accounts_data_size_max_limit( &bank );
  test_calculate_allocated_accounts_data_size_overflow( &bank );
  test_calculate_allocated_accounts_data_size_invalid_ix( &bank );

  test_sanitize_compute_unit_limits_heap_size();
  test_sanitize_txn_v1_config_heap_size( &bank );
  test_v1_feature_gate();
  test_sysvar_instructions_overflow();

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
