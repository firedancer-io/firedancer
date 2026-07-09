/* Unit test for define_ltds_fee_only_semantics */

#include "tests/fd_svm_mini.h"
#include "fd_runtime.h"
#include "fd_runtime_err.h"
#include "fd_executor.h"
#include "fd_system_ids.h"
#include "../features/fd_features.h"
#include "../../disco/fd_txn_p.h"
#include "../../ballet/sha256/fd_sha256.h"
#include "program/fd_compute_budget_program.h"
#include "program/fd_system_program.h"

static void
set_gate( fd_bank_t * bank, int on ) {
  bank->f.features.define_ltds_fee_only_semantics = on ? 0UL : FD_FEATURE_DISABLED;
}

static void
setup_env( fd_svm_mini_t *      mini,
           int                  feature_on,
           fd_bank_t **         out_bank,
           fd_accdb_fork_id_t * out_fork_id,
           fd_pubkey_t *        out_fee_payer ) {
  fd_svm_mini_params_t params[1];
  fd_svm_mini_params_default( params );
  ulong root_idx = fd_svm_mini_reset( mini, params );
  ulong bank_idx = fd_svm_mini_attach_child( mini, root_idx, 10UL );
  fd_bank_t *        bank    = fd_svm_mini_bank( mini, bank_idx );
  fd_accdb_fork_id_t fork_id = fd_svm_mini_fork_id( mini, bank_idx );

  set_gate( bank, feature_on );

  fd_pubkey_t fee_payer; fd_memset( &fee_payer, 0x11, sizeof(fd_pubkey_t) );
  fd_svm_mini_add_lamports( mini, fork_id, &fee_payer, 1000000000UL );

  *out_bank      = bank;
  *out_fork_id   = fork_id;
  *out_fee_payer = fee_payer;
}

static void
durable_nonce_from_blockhash( fd_hash_t *       out,
                              fd_hash_t const * blockhash ) {
  uchar buf[ 13UL + sizeof(fd_hash_t) ];
  memcpy( buf,    "DURABLE_NONCE", 13UL );
  memcpy( buf+13, blockhash,       sizeof(fd_hash_t) );
  fd_sha256_hash( buf, sizeof(buf), out );
}

/* Returns a durable_nonce derived from a hash unrelated to the bank's
   blockhash queue.  Using durable_nonce_from_blockhash(current_last_hash)
   would trip the BLOCKHASH_NONCE_ALREADY_ADVANCED guard. */
static fd_hash_t
make_stale_durable_nonce( void ) {
  fd_hash_t stale; fd_memset( stale.uc, 0x42, sizeof(fd_hash_t) );
  fd_hash_t out;
  durable_nonce_from_blockhash( &out, &stale );
  return out;
}

static void
put_account( fd_svm_mini_t *     mini,
             fd_pubkey_t const * pubkey,
             ulong               lamports,
             uint                dlen,
             uchar const *       data,
             fd_pubkey_t const * owner,
             uchar               executable ) {
  fd_acc_t acc = {0};
  fd_memcpy( acc.pubkey, pubkey->uc, 32UL );
  fd_memcpy( acc.owner,  owner->uc,  32UL );
  acc.lamports   = lamports;
  acc.executable = executable;
  acc.data_len   = dlen;
  acc.data       = (uchar *)data;
  fd_svm_mini_put_account_rooted( mini, &acc );
}

static void
put_nonce_account( fd_svm_mini_t *     mini,
                   fd_pubkey_t const * pubkey,
                   fd_pubkey_t const * authority,
                   fd_hash_t const *   durable_nonce ) {
  fd_nonce_state_versions_t state = {
    .version       = FD_NONCE_VERSION_CURRENT,
    .kind          = FD_NONCE_STATE_INITIALIZED,
    .authority     = *authority,
    .durable_nonce = *durable_nonce,
  };
  uchar data[ FD_SYSTEM_PROGRAM_NONCE_DLEN ] = {0};
  ulong written = 0UL;
  FD_TEST( !fd_nonce_state_versions_encode( &state, data, FD_SYSTEM_PROGRAM_NONCE_DLEN, &written ) );

  put_account( mini, pubkey, 1000000000UL,
               (uint)FD_SYSTEM_PROGRAM_NONCE_DLEN, data,
               &fd_solana_system_program_id, 0 );
}

static void
put_system_program_account( fd_svm_mini_t * mini ) {
  put_account( mini, &fd_solana_system_program_id, 1UL,
               0U, NULL, &fd_solana_native_loader_id, 1 );
}

/* Encode SetLoadedAccountsDataSizeLimit(limit) into 5 bytes at `out`. */
static void
encode_set_loaded_data_size_limit( uchar * out, uint limit ) {
  out[0] = (uchar)FD_COMPUTE_BUDGET_INSTR_DISC_SET_LOADED_ACCOUNTS_DATA_SIZE_LIMIT;
  out[1] = (uchar)( limit        & 0xFFU);
  out[2] = (uchar)((limit >>  8) & 0xFFU);
  out[3] = (uchar)((limit >> 16) & 0xFFU);
  out[4] = (uchar)((limit >> 24) & 0xFFU);
}

/* Two accounts (fee_payer, bad_program), one instruction whose program_id
   does not exist in the accdb.  Load fails with PROGRAM_ACCOUNT_NOT_FOUND. */
static void
build_minimal_fees_only_txn( fd_bank_t const *   bank,
                             fd_pubkey_t const * fee_payer,
                             fd_pubkey_t const * bad_program,
                             fd_txn_p_t *        txn_p,
                             fd_txn_in_t *       txn_in,
                             fd_txn_out_t *      txn_out ) {
  fd_memset( txn_p,   0, sizeof(fd_txn_p_t)   );
  fd_memset( txn_in,  0, sizeof(fd_txn_in_t)  );
  fd_memset( txn_out, 0, sizeof(fd_txn_out_t) );

  fd_txn_t * txn = TXN( txn_p );
  txn->transaction_version  = FD_TXN_VLEGACY;
  txn->signature_cnt        = 1;
  txn->acct_addr_cnt        = 2;
  txn->instr_cnt            = 1;
  txn->recent_blockhash_off = 0;
  txn->acct_addr_off        = 32;

  fd_memcpy( txn_p->payload,      fd_blockhashes_peek_last_hash( &bank->f.block_hash_queue ), sizeof(fd_hash_t)   );
  fd_memcpy( txn_p->payload + 32, fee_payer,   sizeof(fd_pubkey_t) );
  fd_memcpy( txn_p->payload + 64, bad_program, sizeof(fd_pubkey_t) );

  txn->instr[0].program_id = 1;
  txn->instr[0].acct_off   = 96;
  txn->instr[0].data_off   = 96;

  txn_in->txn              = txn_p;
}

/* Three accounts (fee_payer, oversized, compute_budget_program), one
   SetLoadedAccountsDataSizeLimit instruction.  Load fails with
   MAX_LOADED_ACCOUNTS_DATA_SIZE_EXCEEDED while loading the oversized account. */
static void
build_limit_exceeded_txn( fd_bank_t const *   bank,
                          fd_pubkey_t const * fee_payer,
                          fd_pubkey_t const * large_acct,
                          uint                limit,
                          fd_txn_p_t *        txn_p,
                          fd_txn_in_t *       txn_in,
                          fd_txn_out_t *      txn_out ) {
  fd_memset( txn_p,   0, sizeof(fd_txn_p_t)   );
  fd_memset( txn_in,  0, sizeof(fd_txn_in_t)  );
  fd_memset( txn_out, 0, sizeof(fd_txn_out_t) );

  fd_txn_t * txn = TXN( txn_p );
  txn->transaction_version  = FD_TXN_VLEGACY;
  txn->signature_cnt        = 1;
  txn->acct_addr_cnt        = 3;
  txn->instr_cnt            = 1;
  txn->recent_blockhash_off = 0;
  txn->acct_addr_off        = 32;

  fd_memcpy( txn_p->payload,       fd_blockhashes_peek_last_hash( &bank->f.block_hash_queue ), sizeof(fd_hash_t)   );
  fd_memcpy( txn_p->payload +  32, fee_payer,                            sizeof(fd_pubkey_t) );
  fd_memcpy( txn_p->payload +  64, large_acct,                           sizeof(fd_pubkey_t) );
  fd_memcpy( txn_p->payload +  96, &fd_solana_compute_budget_program_id, sizeof(fd_pubkey_t) );

  ushort const data_off = 128;
  encode_set_loaded_data_size_limit( txn_p->payload + data_off, limit );

  txn->instr[0].program_id = 2;
  txn->instr[0].acct_off   = data_off;
  txn->instr[0].data_off   = data_off;
  txn->instr[0].data_sz    = 5;

  txn_in->txn              = txn_p;
}

/* Durable-nonce txn, separate nonce account.  Accounts:
   [0]=fee_payer  [1]=nonce_key  [2]=recent_block_hashes
   [3]=system_program  [4]=bad_program.  Instructions:
   [0]=advance_nonce_account(nonce, recent_hashes, fee_payer)
   [1]=bad_program. */
static void
build_separate_nonce_txn( fd_pubkey_t const * fee_payer,
                          fd_pubkey_t const * nonce_key,
                          fd_pubkey_t const * bad_program,
                          fd_hash_t const *   durable_nonce,
                          fd_txn_p_t *        txn_p,
                          fd_txn_in_t *       txn_in,
                          fd_txn_out_t *      txn_out ) {
  fd_memset( txn_p,   0, sizeof(fd_txn_p_t)   );
  fd_memset( txn_in,  0, sizeof(fd_txn_in_t)  );
  fd_memset( txn_out, 0, sizeof(fd_txn_out_t) );

  fd_txn_t * txn = TXN( txn_p );
  txn->transaction_version   = FD_TXN_VLEGACY;
  txn->signature_cnt         = 1;
  txn->readonly_unsigned_cnt = 3;
  txn->acct_addr_cnt         = 5;
  txn->instr_cnt             = 2;
  txn->recent_blockhash_off  = 0;
  txn->acct_addr_off         = 32;

  fd_memcpy( txn_p->payload,        durable_nonce,                     sizeof(fd_hash_t)   );
  fd_memcpy( txn_p->payload +  32,  fee_payer,                         sizeof(fd_pubkey_t) );
  fd_memcpy( txn_p->payload +  64,  nonce_key,                         sizeof(fd_pubkey_t) );
  fd_memcpy( txn_p->payload +  96,  &fd_sysvar_recent_block_hashes_id, sizeof(fd_pubkey_t) );
  fd_memcpy( txn_p->payload + 128,  &fd_solana_system_program_id,      sizeof(fd_pubkey_t) );
  fd_memcpy( txn_p->payload + 160,  bad_program,                       sizeof(fd_pubkey_t) );

  txn_p->payload[ 192 ] = 1;
  txn_p->payload[ 193 ] = 2;
  txn_p->payload[ 194 ] = 0;
  FD_STORE( uint, txn_p->payload + 195, (uint)FD_SYSTEM_PROGRAM_INSTR_ADVANCE_NONCE_ACCOUNT );

  txn->instr[0].program_id = 3;
  txn->instr[0].acct_cnt   = 3;
  txn->instr[0].acct_off   = 192;
  txn->instr[0].data_off   = 195;
  txn->instr[0].data_sz    = 4;

  txn->instr[1].program_id = 4;
  txn->instr[1].acct_off   = 199;
  txn->instr[1].data_off   = 199;

  txn_in->txn              = txn_p;
}

/* Durable-nonce txn, fee_payer IS the nonce account.  Accounts:
   [0]=fee_payer (holds nonce state)  [1]=recent_block_hashes
   [2]=system_program  [3]=bad_program. */
static void
build_same_nonce_txn( fd_pubkey_t const * fee_payer,
                      fd_pubkey_t const * bad_program,
                      fd_hash_t const *   durable_nonce,
                      fd_txn_p_t *        txn_p,
                      fd_txn_in_t *       txn_in,
                      fd_txn_out_t *      txn_out ) {
  fd_memset( txn_p,   0, sizeof(fd_txn_p_t)   );
  fd_memset( txn_in,  0, sizeof(fd_txn_in_t)  );
  fd_memset( txn_out, 0, sizeof(fd_txn_out_t) );

  fd_txn_t * txn = TXN( txn_p );
  txn->transaction_version   = FD_TXN_VLEGACY;
  txn->signature_cnt         = 1;
  txn->readonly_unsigned_cnt = 3;
  txn->acct_addr_cnt         = 4;
  txn->instr_cnt             = 2;
  txn->recent_blockhash_off  = 0;
  txn->acct_addr_off         = 32;

  fd_memcpy( txn_p->payload,        durable_nonce,                     sizeof(fd_hash_t)   );
  fd_memcpy( txn_p->payload +  32,  fee_payer,                         sizeof(fd_pubkey_t) );
  fd_memcpy( txn_p->payload +  64,  &fd_sysvar_recent_block_hashes_id, sizeof(fd_pubkey_t) );
  fd_memcpy( txn_p->payload +  96,  &fd_solana_system_program_id,      sizeof(fd_pubkey_t) );
  fd_memcpy( txn_p->payload + 128,  bad_program,                       sizeof(fd_pubkey_t) );

  txn_p->payload[ 160 ] = 0;
  txn_p->payload[ 161 ] = 1;
  txn_p->payload[ 162 ] = 0;
  FD_STORE( uint, txn_p->payload + 163, (uint)FD_SYSTEM_PROGRAM_INSTR_ADVANCE_NONCE_ACCOUNT );

  txn->instr[0].program_id = 2;
  txn->instr[0].acct_cnt   = 3;
  txn->instr[0].acct_off   = 160;
  txn->instr[0].data_off   = 163;
  txn->instr[0].data_sz    = 4;

  txn->instr[1].program_id = 3;
  txn->instr[1].acct_off   = 167;
  txn->instr[1].data_off   = 167;

  txn_in->txn              = txn_p;
}

/* Separate-nonce txn with an extra SetLoadedAccountsDataSizeLimit
   instruction.  Accounts:
   [0]=fee_payer  [1]=nonce_key  [2]=recent_block_hashes
   [3]=system_program  [4]=bad_program  [5]=compute_budget_program.
   Instructions: [0]=advance_nonce [1]=SetLimit(limit) [2]=bad_program. */
static void
build_separate_nonce_with_limit_txn( fd_pubkey_t const * fee_payer,
                                     fd_pubkey_t const * nonce_key,
                                     fd_pubkey_t const * bad_program,
                                     fd_hash_t const *   durable_nonce,
                                     uint                limit,
                                     fd_txn_p_t *        txn_p,
                                     fd_txn_in_t *       txn_in,
                                     fd_txn_out_t *      txn_out ) {
  fd_memset( txn_p,   0, sizeof(fd_txn_p_t)   );
  fd_memset( txn_in,  0, sizeof(fd_txn_in_t)  );
  fd_memset( txn_out, 0, sizeof(fd_txn_out_t) );

  fd_txn_t * txn = TXN( txn_p );
  txn->transaction_version   = FD_TXN_VLEGACY;
  txn->signature_cnt         = 1;
  txn->readonly_unsigned_cnt = 4;
  txn->acct_addr_cnt         = 6;
  txn->instr_cnt             = 3;
  txn->recent_blockhash_off  = 0;
  txn->acct_addr_off         = 32;

  fd_memcpy( txn_p->payload,        durable_nonce,                        sizeof(fd_hash_t)   );
  fd_memcpy( txn_p->payload +  32,  fee_payer,                            sizeof(fd_pubkey_t) );
  fd_memcpy( txn_p->payload +  64,  nonce_key,                            sizeof(fd_pubkey_t) );
  fd_memcpy( txn_p->payload +  96,  &fd_sysvar_recent_block_hashes_id,    sizeof(fd_pubkey_t) );
  fd_memcpy( txn_p->payload + 128,  &fd_solana_system_program_id,         sizeof(fd_pubkey_t) );
  fd_memcpy( txn_p->payload + 160,  bad_program,                          sizeof(fd_pubkey_t) );
  fd_memcpy( txn_p->payload + 192,  &fd_solana_compute_budget_program_id, sizeof(fd_pubkey_t) );

  txn_p->payload[ 224 ] = 1;
  txn_p->payload[ 225 ] = 2;
  txn_p->payload[ 226 ] = 0;
  FD_STORE( uint, txn_p->payload + 227, (uint)FD_SYSTEM_PROGRAM_INSTR_ADVANCE_NONCE_ACCOUNT );

  txn->instr[0].program_id = 3;
  txn->instr[0].acct_cnt   = 3;
  txn->instr[0].acct_off   = 224;
  txn->instr[0].data_off   = 227;
  txn->instr[0].data_sz    = 4;

  ushort const cb_off = 231;
  encode_set_loaded_data_size_limit( txn_p->payload + cb_off, limit );

  txn->instr[1].program_id = 5;
  txn->instr[1].acct_off   = cb_off;
  txn->instr[1].data_off   = cb_off;
  txn->instr[1].data_sz    = 5;

  txn->instr[2].program_id = 4;
  txn->instr[2].acct_off   = (ushort)(cb_off + 5);
  txn->instr[2].data_off   = (ushort)(cb_off + 5);

  txn_in->txn              = txn_p;
}

/* CASE 1 — feature OFF, no nonce: expects fee_payer.dlen (= 0). */
static void
test_off_no_nonce_bad_program( fd_svm_mini_t * mini ) {
  fd_bank_t * bank; fd_accdb_fork_id_t fork_id; fd_pubkey_t fee_payer;
  setup_env( mini, /*feature_on=*/0, &bank, &fork_id, &fee_payer );

  fd_pubkey_t bad_program; fd_memset( &bad_program, 0x22, sizeof(fd_pubkey_t) );

  fd_txn_p_t   txn_p[1];
  fd_txn_in_t  txn_in[1];
  static fd_txn_out_t txn_out[1];
  build_minimal_fees_only_txn( bank, &fee_payer, &bad_program, txn_p, txn_in, txn_out );

  fd_runtime_prepare_and_execute_txn( mini->runtime, bank, txn_in, txn_out );

  FD_TEST( txn_out->err.is_fees_only );
  FD_TEST( txn_out->err.txn_err==FD_RUNTIME_TXN_ERR_PROGRAM_ACCOUNT_NOT_FOUND );
  FD_TEST( txn_out->details.loaded_accounts_data_size==0UL );
}

/* CASE 2 — feature ON, no nonce: expects accumulated BASE + fee_payer.dlen
   (= 64 + 0) since the bad program contributes 0 to the accumulator. */
static void
test_on_no_nonce_bad_program( fd_svm_mini_t * mini ) {
  fd_bank_t * bank; fd_accdb_fork_id_t fork_id; fd_pubkey_t fee_payer;
  setup_env( mini, /*feature_on=*/1, &bank, &fork_id, &fee_payer );

  fd_pubkey_t bad_program; fd_memset( &bad_program, 0x22, sizeof(fd_pubkey_t) );

  fd_txn_p_t   txn_p[1];
  fd_txn_in_t  txn_in[1];
  static fd_txn_out_t txn_out[1];
  build_minimal_fees_only_txn( bank, &fee_payer, &bad_program, txn_p, txn_in, txn_out );

  fd_runtime_prepare_and_execute_txn( mini->runtime, bank, txn_in, txn_out );

  FD_TEST( txn_out->err.is_fees_only );
  FD_TEST( txn_out->err.txn_err==FD_RUNTIME_TXN_ERR_PROGRAM_ACCOUNT_NOT_FOUND );
  FD_TEST( txn_out->details.loaded_accounts_data_size==FD_TRANSACTION_ACCOUNT_BASE_SIZE );
}

/* CASE 3 — feature OFF, no nonce, load fails at size limit: expects
   fee_payer.dlen (= 0).  The amendment is not active so the accumulator
   is overwritten regardless of the requested limit. */
static void
test_off_no_nonce_limit_exceeded( fd_svm_mini_t * mini ) {
  fd_bank_t * bank; fd_accdb_fork_id_t fork_id; fd_pubkey_t fee_payer;
  setup_env( mini, /*feature_on=*/0, &bank, &fork_id, &fee_payer );

  fd_pubkey_t large_acct; fd_memset( &large_acct, 0x33, sizeof(fd_pubkey_t) );
  uchar large_data[ 5000 ] = {0};
  put_account( mini, &large_acct, 1000000UL, 5000U, large_data,
               &fd_solana_system_program_id, 0 );

  fd_txn_p_t   txn_p[1];
  fd_txn_in_t  txn_in[1];
  static fd_txn_out_t txn_out[1];
  build_limit_exceeded_txn( bank, &fee_payer, &large_acct, 200U, txn_p, txn_in, txn_out );

  fd_runtime_prepare_and_execute_txn( mini->runtime, bank, txn_in, txn_out );

  FD_TEST( txn_out->err.is_fees_only );
  FD_TEST( txn_out->err.txn_err==FD_RUNTIME_TXN_ERR_MAX_LOADED_ACCOUNTS_DATA_SIZE_EXCEEDED );
  FD_TEST( txn_out->details.loaded_accounts_data_size==0UL );
}

/* CASE 4 — feature ON, no nonce, load fails at size limit: expects the
   accumulator clamped to the requested limit. */
static void
test_on_no_nonce_limit_exceeded( fd_svm_mini_t * mini ) {
  fd_bank_t * bank; fd_accdb_fork_id_t fork_id; fd_pubkey_t fee_payer;
  setup_env( mini, /*feature_on=*/1, &bank, &fork_id, &fee_payer );

  fd_pubkey_t large_acct; fd_memset( &large_acct, 0x33, sizeof(fd_pubkey_t) );
  uchar large_data[ 5000 ] = {0};
  put_account( mini, &large_acct, 1000000UL, 5000U, large_data,
               &fd_solana_system_program_id, 0 );

  fd_txn_p_t   txn_p[1];
  fd_txn_in_t  txn_in[1];
  static fd_txn_out_t txn_out[1];
  uint const limit = 200U;
  build_limit_exceeded_txn( bank, &fee_payer, &large_acct, limit, txn_p, txn_in, txn_out );

  fd_runtime_prepare_and_execute_txn( mini->runtime, bank, txn_in, txn_out );

  FD_TEST( txn_out->err.is_fees_only );
  FD_TEST( txn_out->err.txn_err==FD_RUNTIME_TXN_ERR_MAX_LOADED_ACCOUNTS_DATA_SIZE_EXCEEDED );
  FD_TEST( txn_out->details.loaded_accounts_data_size==(ulong)limit );
}

/* CASE 5 — feature OFF, separate nonce account: expects
   fee_payer.dlen + nonce.dlen (= 0 + 80). */
static void
test_off_separate_nonce_bad_program( fd_svm_mini_t * mini ) {
  fd_bank_t * bank; fd_accdb_fork_id_t fork_id; fd_pubkey_t fee_payer;
  setup_env( mini, /*feature_on=*/0, &bank, &fork_id, &fee_payer );

  fd_pubkey_t nonce_key;   fd_memset( &nonce_key,   0x77, sizeof(fd_pubkey_t) );
  fd_pubkey_t bad_program; fd_memset( &bad_program, 0x22, sizeof(fd_pubkey_t) );

  fd_hash_t durable_nonce = make_stale_durable_nonce();
  put_nonce_account( mini, &nonce_key, &fee_payer, &durable_nonce );
  put_system_program_account( mini );

  fd_txn_p_t   txn_p[1];
  fd_txn_in_t  txn_in[1];
  static fd_txn_out_t txn_out[1];
  build_separate_nonce_txn( &fee_payer, &nonce_key, &bad_program, &durable_nonce,
                            txn_p, txn_in, txn_out );

  fd_runtime_prepare_and_execute_txn( mini->runtime, bank, txn_in, txn_out );

  FD_TEST( txn_out->err.is_fees_only );
  FD_TEST( txn_out->err.txn_err==FD_RUNTIME_TXN_ERR_PROGRAM_ACCOUNT_NOT_FOUND );
  FD_TEST( txn_out->accounts.nonce_idx_in_txn==1UL );
  FD_TEST( txn_out->details.loaded_accounts_data_size==FD_SYSTEM_PROGRAM_NONCE_DLEN );
}

/* CASE 6 — feature OFF, fee_payer IS the nonce account: expects 80 (the
   fee_payer slot already carries the nonce data; the inner-if guard
   prevents double-counting via rollback_nonce->dlen). */
static void
test_off_same_nonce_bad_program( fd_svm_mini_t * mini ) {
  fd_bank_t * bank; fd_accdb_fork_id_t fork_id; fd_pubkey_t fee_payer;
  setup_env( mini, /*feature_on=*/0, &bank, &fork_id, &fee_payer );

  fd_pubkey_t bad_program; fd_memset( &bad_program, 0x22, sizeof(fd_pubkey_t) );

  fd_hash_t durable_nonce = make_stale_durable_nonce();
  put_nonce_account( mini, &fee_payer, &fee_payer, &durable_nonce );
  put_system_program_account( mini );

  fd_txn_p_t   txn_p[1];
  fd_txn_in_t  txn_in[1];
  static fd_txn_out_t txn_out[1];
  build_same_nonce_txn( &fee_payer, &bad_program, &durable_nonce, txn_p, txn_in, txn_out );

  fd_runtime_prepare_and_execute_txn( mini->runtime, bank, txn_in, txn_out );

  FD_TEST( txn_out->err.is_fees_only );
  FD_TEST( txn_out->err.txn_err==FD_RUNTIME_TXN_ERR_PROGRAM_ACCOUNT_NOT_FOUND );
  FD_TEST( txn_out->accounts.nonce_idx_in_txn==0UL );
  FD_TEST( txn_out->details.loaded_accounts_data_size==FD_SYSTEM_PROGRAM_NONCE_DLEN );
}

/* CASE 7 — feature ON, separate nonce, load fails at size limit: expects
   the requested limit (clamp).  Sanity check that the feature-ON path
   ignores the nonce/fee-payer split; otherwise the OFF-arm arithmetic
   would produce fee_payer.dlen + nonce.dlen instead. */
static void
test_on_separate_nonce_limit_exceeded( fd_svm_mini_t * mini ) {
  fd_bank_t * bank; fd_accdb_fork_id_t fork_id; fd_pubkey_t fee_payer;
  setup_env( mini, /*feature_on=*/1, &bank, &fork_id, &fee_payer );

  fd_pubkey_t nonce_key;   fd_memset( &nonce_key,   0x77, sizeof(fd_pubkey_t) );
  fd_pubkey_t bad_program; fd_memset( &bad_program, 0x22, sizeof(fd_pubkey_t) );

  fd_hash_t durable_nonce = make_stale_durable_nonce();
  put_nonce_account( mini, &nonce_key, &fee_payer, &durable_nonce );
  put_system_program_account( mini );

  fd_txn_p_t   txn_p[1];
  fd_txn_in_t  txn_in[1];
  static fd_txn_out_t txn_out[1];
  uint const limit = 100U;
  build_separate_nonce_with_limit_txn( &fee_payer, &nonce_key, &bad_program, &durable_nonce,
                                       limit, txn_p, txn_in, txn_out );

  fd_runtime_prepare_and_execute_txn( mini->runtime, bank, txn_in, txn_out );

  FD_TEST( txn_out->err.is_fees_only );
  FD_TEST( txn_out->err.txn_err==FD_RUNTIME_TXN_ERR_MAX_LOADED_ACCOUNTS_DATA_SIZE_EXCEEDED );
  FD_TEST( txn_out->accounts.nonce_idx_in_txn==1UL );
  FD_TEST( txn_out->details.loaded_accounts_data_size==(ulong)limit );
}

int
main( int argc, char ** argv ) {
  fd_svm_mini_limits_t limits[1];
  fd_svm_mini_limits_default( limits );
  fd_svm_mini_t * mini = fd_svm_test_boot( &argc, &argv, limits );

  test_off_no_nonce_bad_program        ( mini );
  test_on_no_nonce_bad_program         ( mini );
  test_off_no_nonce_limit_exceeded     ( mini );
  test_on_no_nonce_limit_exceeded      ( mini );
  test_off_separate_nonce_bad_program  ( mini );
  test_off_same_nonce_bad_program      ( mini );
  test_on_separate_nonce_limit_exceeded( mini );

  FD_LOG_NOTICE(( "pass" ));
  fd_svm_test_halt( mini );
  return 0;
}
