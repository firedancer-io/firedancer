#include "fd_zk_token_proof_program.h"
#include "zk_token/fd_zktpp.h"
#include "../fd_executor.h"
#include "../context/fd_exec_txn_ctx.h"
#include "../fd_acc_mgr.h"
#include <string.h>

struct __attribute__((packed)) fd_zktpp_proof_ctx_state_meta {
  uchar ctx_state_authority[32];
  uchar proof_type;
};
typedef struct fd_zktpp_proof_ctx_state_meta fd_zktpp_proof_ctx_state_meta_t;

static int
process_close_proof_context( fd_exec_instr_ctx_t ctx ) {
  fd_pubkey_t const * txn_accs       = ctx.txn_ctx->accounts;
  uchar const *       instr_acc_idxs = ctx.instr->acct_txn_idxs;
  ulong               instr_acc_cnt  = ctx.instr->acct_cnt;

  /* https://github.com/solana-labs/solana/blob/d6aba9dc483a79ab569b47b7f3df19e6535f6722/programs/zk-token-proof/src/lib.rs#L94 */
  if( FD_UNLIKELY( instr_acc_cnt<3UL ) )
    return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
  fd_pubkey_t const *     owner_addr = &txn_accs[instr_acc_idxs[2]];
  fd_borrowed_account_t * owner_acc  = NULL;
  int rc = fd_instr_borrowed_account_view_idx( &ctx, 2, &owner_acc );
  switch ( rc ) {
  case FD_ACC_MGR_SUCCESS:
    break;
  case FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT:
    // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/src/transaction_context.rs#L637
    return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
  default:
    // https://github.com/firedancer-io/solana/blob/da470eef4652b3b22598a1f379cacfe82bd5928d/sdk/src/transaction_context.rs#L639
    return FD_EXECUTOR_INSTR_ERR_ACC_BORROW_FAILED;
  }

  /* https://github.com/solana-labs/solana/blob/d6aba9dc483a79ab569b47b7f3df19e6535f6722/programs/zk-token-proof/src/lib.rs#L97 */
  if( FD_UNLIKELY( !fd_instr_acc_is_signer_idx( ctx.instr, 2 ) ) )
    return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;

  /* https://github.com/solana-labs/solana/blob/d6aba9dc483a79ab569b47b7f3df19e6535f6722/programs/zk-token-proof/src/lib.rs#L103 */
  fd_pubkey_t const * proof_ctx_addr    = &txn_accs[instr_acc_idxs[0]];
  fd_borrowed_account_t * proof_ctx_acc = NULL;
  rc = fd_instr_borrowed_account_view_idx( &ctx, 0, &proof_ctx_acc );
  switch ( rc ) {
  case FD_ACC_MGR_SUCCESS:
    break;
  case FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT:
    return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
  default:
    return FD_EXECUTOR_INSTR_ERR_ACC_BORROW_FAILED;
  }

  /* https://github.com/solana-labs/solana/blob/d6aba9dc483a79ab569b47b7f3df19e6535f6722/programs/zk-token-proof/src/lib.rs#L106 */
  fd_pubkey_t const * dest_acc_addr = &txn_accs[instr_acc_idxs[1]];
  fd_borrowed_account_t * dest_acc  = NULL;
  rc = fd_instr_borrowed_account_view_idx( &ctx, 1, &dest_acc );
  switch ( rc ) {
  case FD_ACC_MGR_SUCCESS:
    break;
  case FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT:
    return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
  default:
    return FD_EXECUTOR_INSTR_ERR_ACC_BORROW_FAILED;
  }

  /* https://github.com/solana-labs/solana/blob/d6aba9dc483a79ab569b47b7f3df19e6535f6722/programs/zk-token-proof/src/lib.rs#L109 */
  if( FD_UNLIKELY( 0==memcmp( proof_ctx_addr->uc, dest_acc_addr->uc, sizeof(fd_pubkey_t) ) ) )
    return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;

  /* https://github.com/solana-labs/solana/blob/d6aba9dc483a79ab569b47b7f3df19e6535f6722/programs/zk-token-proof/src/lib.rs#L115 */
  if( FD_UNLIKELY( proof_ctx_acc->const_meta->dlen != sizeof(fd_zktpp_proof_ctx_state_meta_t) ) )
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  fd_zktpp_proof_ctx_state_meta_t const * proof_ctx_state_meta = fd_type_pun_const( proof_ctx_acc->const_data );
  /* https://github.com/solana-labs/solana/blob/d6aba9dc483a79ab569b47b7f3df19e6535f6722/programs/zk-token-proof/src/lib.rs#L117 */
  uchar const * expected_owner_addr = proof_ctx_state_meta->ctx_state_authority;

  /* https://github.com/solana-labs/solana/blob/d6aba9dc483a79ab569b47b7f3df19e6535f6722/programs/zk-token-proof/src/lib.rs#L119 */
  if( FD_UNLIKELY( 0!=memcmp( owner_addr, expected_owner_addr, sizeof(fd_pubkey_t) ) ) )
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_OWNER;

  /* https://github.com/solana-labs/solana/blob/d6aba9dc483a79ab569b47b7f3df19e6535f6722/programs/zk-token-proof/src/lib.rs#L125 */
  /* TODO dubious borrowing rules here ... */
  rc = fd_instr_borrowed_account_modify( &ctx, dest_acc_addr, 0, &dest_acc );
  if( FD_UNLIKELY( rc!=FD_ACC_MGR_SUCCESS ) )
    return FD_EXECUTOR_INSTR_ERR_ACC_BORROW_FAILED;
  dest_acc->meta->info.lamports += proof_ctx_acc->meta->info.lamports;
  /* TODO delete other account */
  return FD_EXECUTOR_INSTR_SUCCESS;
}

int
fd_executor_zk_token_proof_program_execute_instruction( fd_exec_instr_ctx_t ctx ) {

  uchar const * instr_data    = ctx.instr->data;
  ulong         instr_data_sz = ctx.instr->data_sz;

  if( FD_UNLIKELY( instr_data_sz<1UL ) )
    return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;

  /* TODO pre-checks:
     - check feature_set.is_active
     - check invoke context stack height
     https://github.com/solana-labs/solana/blob/v1.17.10/programs/zk-token-proof/src/lib.rs#L134-L154 */

  switch( instr_data[0] ) {
  case FD_ZKTPP_INSTR_CLOSE_CONTEXT_STATE:
    /* TODO:
       - consume CU
       - Log "CloseContextState"
       https://github.com/solana-labs/solana/blob/v1.17.10/programs/zk-token-proof/src/lib.rs#L158-L163 */
    return fd_zktpp_process_close_proof_context( ctx );
  case FD_ZKTPP_INSTR_VERIFY_ZERO_BALANCE:
  case FD_ZKTPP_INSTR_VERIFY_WITHDRAW:
  case FD_ZKTPP_INSTR_VERIFY_CIPHERTEXT_CIPHERTEXT_EQUALITY:
  case FD_ZKTPP_INSTR_VERIFY_TRANSFER:
  case FD_ZKTPP_INSTR_VERIFY_TRANSFER_WITH_FEE:
  case FD_ZKTPP_INSTR_VERIFY_PUBKEY_VALIDITY:
  case FD_ZKTPP_INSTR_VERIFY_RANGE_PROOF_U64:
  case FD_ZKTPP_INSTR_VERIFY_BATCHED_RANGE_PROOF_U64:
  case FD_ZKTPP_INSTR_VERIFY_BATCHED_RANGE_PROOF_U128:
  case FD_ZKTPP_INSTR_VERIFY_BATCHED_RANGE_PROOF_U256:
  case FD_ZKTPP_INSTR_VERIFY_CIPHERTEXT_COMMITMENT_EQUALITY:
  case FD_ZKTPP_INSTR_VERFIY_GROUPED_CIPHERTEXT_2_HANDLES_VALIDITY:
  case FD_ZKTPP_INSTR_VERIFY_BATCHED_GROUPED_CIPHERTEXT_2_HANDLES_VALIDITY:
  case FD_ZKTPP_INSTR_VERIFY_FEE_SIGMA:
    // TODO: consume CU + Log
    return fd_zktpp_process_verify_proof( ctx, instr_data[0] );
  default:
    return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
  }
}
