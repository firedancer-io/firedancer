/* Test for the bounds on the number of accounts referenced by a single
   instruction. The worst case is FD_INSTR_ACCT_MAX: 1094. Transactions with
   >FD_INSTR_ACCT_MAX instruction accounts are not possible due to the MTU.

   limit_instruction_accounts disabled:
   - Transactions with >256 instruction and <=FD_INSTR_ACCT_MAX accounts
     are accepted.
   - Instructions with >FD_INSTR_ACCT_MAX accounts are rejected.

   limit_instruction_accounts enabled:
   - Transactions with >255 instruction accounts are rejected */

#include "tests/fd_svm_mini.h"
#include "info/fd_instr_info.h"
#include "fd_runtime.h"
#include "fd_runtime_err.h"
#include "fd_system_ids.h"
#include "../../disco/fd_txn_p.h"

static void
setup_txn( fd_svm_mini_t * mini, fd_bank_t * bank, fd_xid_t const * xid,
           fd_pubkey_t const * fee_payer,
           fd_txn_p_t * txn_p, fd_txn_out_t * txn_out, fd_txn_in_t * txn_in,
           ushort instr_acct_cnt ) {
  fd_memset( txn_p, 0, sizeof(fd_txn_p_t) );
  fd_memset( txn_out, 0, sizeof(fd_txn_out_t) );

  fd_txn_t * txn = TXN( txn_p );
  txn->transaction_version  = FD_TXN_VLEGACY;
  txn->signature_cnt        = 1;
  txn->acct_addr_cnt        = 2;
  txn->instr_cnt            = 1;
  txn->recent_blockhash_off = 0;
  txn->acct_addr_off        = 32;

  fd_memcpy( txn_p->payload, fd_blockhashes_peek_last_hash( &bank->f.block_hash_queue ), sizeof(fd_hash_t) );

  fd_memcpy( txn_p->payload + 32, fee_payer, sizeof(fd_pubkey_t) );
  fd_memcpy( txn_p->payload + 64, &fd_solana_compute_budget_program_id, sizeof(fd_pubkey_t) );

  txn->instr[0].program_id = 1;
  txn->instr[0].acct_cnt   = instr_acct_cnt;
  txn->instr[0].acct_off   = 96;

  for( ushort i=0; i<instr_acct_cnt; i++ ) {
    txn_p->payload[96+i] = 0;
  }

  ushort data_off = (ushort)(96 + instr_acct_cnt);
  txn->instr[0].data_off = data_off;
  txn->instr[0].data_sz  = 5;

  /* SetComputeUnitLimit(200000) */
  txn_p->payload[data_off+0] = 2;
  txn_p->payload[data_off+1] = 0x40;
  txn_p->payload[data_off+2] = 0x0D;
  txn_p->payload[data_off+3] = 0x03;
  txn_p->payload[data_off+4] = 0x00;

  txn_in->txn              = txn_p;
  txn_in->bundle.is_bundle = 0;

  (void)mini; (void)xid;
}

static void
verify_trace_accts( fd_svm_mini_t * mini, ushort expected_cnt ) {
  FD_TEST( mini->runtime->instr.trace_length == 1 );
  fd_instr_info_t const * trace = &mini->runtime->instr.trace[0];
  FD_TEST( trace->acct_cnt == expected_cnt );
  for( ushort i=0; i<expected_cnt; i++ ) {
    fd_instruction_account_t expected = {
      .index_in_transaction = 0,
      .index_in_caller      = 0,
      .index_in_callee      = i,
      .is_writable          = 1,
      .is_signer            = 1,
    };
    FD_TEST( !memcmp( &trace->accounts[i], &expected, sizeof(fd_instruction_account_t) ) );
  }
}

static void
init_test_env( fd_svm_mini_t * mini,
               fd_bank_t **    out_bank,
               fd_xid_t *      out_xid,
               fd_pubkey_t *   out_fee_payer ) {
  fd_svm_mini_params_t params[1];
  fd_svm_mini_params_default( params );
  ulong root_idx = fd_svm_mini_reset( mini, params );

  ulong bank_idx = fd_svm_mini_attach_child( mini, root_idx, 10UL );
  fd_bank_t * bank = fd_svm_mini_bank( mini, bank_idx );
  fd_xid_t xid = fd_svm_mini_xid( mini, bank_idx );

  fd_pubkey_t fee_payer;
  fd_memset( &fee_payer, 0x01, sizeof(fd_pubkey_t) );
  fd_svm_mini_add_lamports( mini, &xid, &fee_payer, 1000000000UL );

  *out_bank      = bank;
  *out_xid       = xid;
  *out_fee_payer = fee_payer;
}

/* More than 256, the previous (incorrect) limit */
static void
test_500_instr_accts( fd_svm_mini_t * mini ) {
  fd_bank_t * bank;
  fd_xid_t    xid;
  fd_pubkey_t fee_payer;
  init_test_env( mini, &bank, &xid, &fee_payer );

  fd_txn_p_t   txn_p[1];
  fd_txn_out_t txn_out[1];
  fd_txn_in_t  txn_in[1];

  bank->f.features.limit_instruction_accounts = FD_FEATURE_DISABLED;
  setup_txn( mini, bank, &xid, &fee_payer, txn_p, txn_out, txn_in, 500 );
  fd_runtime_prepare_and_execute_txn( mini->runtime, bank, txn_in, txn_out );
  FD_TEST( txn_out->err.txn_err == FD_RUNTIME_EXECUTE_SUCCESS );
  verify_trace_accts( mini, 500 );
}

/* Worst-case allowed number of instruction accounts */
static void
test_1094_instr_accts( fd_svm_mini_t * mini ) {
  fd_bank_t * bank;
  fd_xid_t    xid;
  fd_pubkey_t fee_payer;
  init_test_env( mini, &bank, &xid, &fee_payer );

  fd_txn_p_t   txn_p[1];
  fd_txn_out_t txn_out[1];
  fd_txn_in_t  txn_in[1];

  bank->f.features.limit_instruction_accounts = FD_FEATURE_DISABLED;
  setup_txn( mini, bank, &xid, &fee_payer, txn_p, txn_out, txn_in, FD_INSTR_ACCT_MAX );
  fd_runtime_prepare_and_execute_txn( mini->runtime, bank, txn_in, txn_out );
  FD_TEST( txn_out->err.txn_err == FD_RUNTIME_EXECUTE_SUCCESS );
  verify_trace_accts( mini, FD_INSTR_ACCT_MAX );
}

/* SIMD-0406: limit_instruction_accounts feature tests.
   When activated, instructions with >255 accounts should be rejected. */
static void
test_limit_instr_accts_at_limit( fd_svm_mini_t * mini ) {
  fd_bank_t * bank;
  fd_xid_t    xid;
  fd_pubkey_t fee_payer;
  init_test_env( mini, &bank, &xid, &fee_payer );

  fd_txn_p_t   txn_p[1];
  fd_txn_out_t txn_out[1];
  fd_txn_in_t  txn_in[1];

  bank->f.features.limit_instruction_accounts = 0UL;
  setup_txn( mini, bank, &xid, &fee_payer, txn_p, txn_out, txn_in, 255 );
  fd_runtime_prepare_and_execute_txn( mini->runtime, bank, txn_in, txn_out );
  FD_TEST( txn_out->err.txn_err == FD_RUNTIME_EXECUTE_SUCCESS );
  verify_trace_accts( mini, 255 );
}

static void
test_limit_instr_accts_exceeded( fd_svm_mini_t * mini ) {
  fd_bank_t * bank;
  fd_xid_t    xid;
  fd_pubkey_t fee_payer;
  init_test_env( mini, &bank, &xid, &fee_payer );

  fd_txn_p_t   txn_p[1];
  fd_txn_out_t txn_out[1];
  fd_txn_in_t  txn_in[1];

  bank->f.features.limit_instruction_accounts = 0UL;
  setup_txn( mini, bank, &xid, &fee_payer, txn_p, txn_out, txn_in, 256 );
  fd_runtime_prepare_and_execute_txn( mini->runtime, bank, txn_in, txn_out );
  FD_TEST( txn_out->err.txn_err == FD_RUNTIME_TXN_ERR_SANITIZE_FAILURE );
}

int
main( int argc, char ** argv ) {
  fd_svm_mini_limits_t limits[1];
  fd_svm_mini_limits_default( limits );
  fd_svm_mini_t * mini = fd_svm_test_boot( &argc, &argv, limits );

  /* Tests with limit_instruction_accounts disabled */
  test_500_instr_accts( mini );
  test_1094_instr_accts( mini );

  /* Tests with limit_instruction_accounts enabled */
  test_limit_instr_accts_at_limit( mini );
  test_limit_instr_accts_exceeded( mini );

  FD_LOG_NOTICE(( "pass" ));
  fd_svm_test_halt( mini );
  return 0;
}
