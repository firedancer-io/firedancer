#include <string.h>

#include "fd_zktpp_private.h"
#include "../fd_zk_token_proof_program.h"
#include "../../context/fd_exec_txn_ctx.h"
#include "../../fd_acc_mgr.h"

struct __attribute__((packed)) fd_zktpp_proof_ctx_state_meta {
  uchar ctx_state_authority[32];
  uchar proof_type;
};
typedef struct fd_zktpp_proof_ctx_state_meta fd_zktpp_proof_ctx_state_meta_t;

int
fd_zktpp_process_close_proof_context( fd_exec_instr_ctx_t ctx ) {
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
  rc = fd_instr_borrowed_account_modify( &ctx, dest_acc_addr, 0, 0, &dest_acc );
  if( FD_UNLIKELY( rc!=FD_ACC_MGR_SUCCESS ) )
    return FD_EXECUTOR_INSTR_ERR_ACC_BORROW_FAILED;
  dest_acc->meta->info.lamports += proof_ctx_acc->meta->info.lamports;
  /* TODO delete other account */
  return FD_EXECUTOR_INSTR_SUCCESS;
}

/* fd_zktpp_process_verify_proof is equivalent to process_verify_proof
   and calls specific functions inside instructions/ to verify each
   individual ZKP.
   https://github.com/solana-labs/solana/blob/v1.17.10/programs/zk-token-proof/src/lib.rs#L35 */
int
fd_zktpp_process_verify_proof( FD_FN_UNUSED fd_exec_instr_ctx_t ctx,
                               FD_FN_UNUSED uchar               instr_id ) {
  int zkp_res = 0;
  /* parse context and proof data 
     https://github.com/solana-labs/solana/blob/v1.17.10/programs/zk-token-proof/src/lib.rs#L40C29-L46 */

  // TODO
  void * context = ctx.instr->data + 1;
  void * proof = ctx.instr->data + 1;

  /* verify individual ZKP */
  switch( instr_id ) {
  case FD_ZKTPP_INSTR_VERIFY_ZERO_BALANCE:
    zkp_res = fd_zktpp_verify_proof_zero_balance( context, proof );
    break;
  case FD_ZKTPP_INSTR_VERIFY_WITHDRAW:
    zkp_res = fd_zktpp_verify_proof_withdraw( context, proof );
    break;
  case FD_ZKTPP_INSTR_VERIFY_CIPHERTEXT_CIPHERTEXT_EQUALITY:
    zkp_res = fd_zktpp_verify_proof_ciphertext_ciphertext_equality( context, proof );
    break;
  case FD_ZKTPP_INSTR_VERIFY_TRANSFER:
    zkp_res = fd_zktpp_verify_proof_transfer( context, proof );
    break;
  case FD_ZKTPP_INSTR_VERIFY_TRANSFER_WITH_FEE:
    zkp_res = fd_zktpp_verify_proof_transfer_with_fee( context, proof );
    break;
  case FD_ZKTPP_INSTR_VERIFY_PUBKEY_VALIDITY:
    zkp_res = fd_zktpp_verify_proof_pubkey_validity( context, proof );
    break;
  case FD_ZKTPP_INSTR_VERIFY_RANGE_PROOF_U64:
    zkp_res = fd_zktpp_verify_proof_range_proof_u64( context, proof );
    break;
  case FD_ZKTPP_INSTR_VERIFY_BATCHED_RANGE_PROOF_U64:
    zkp_res = fd_zktpp_verify_proof_batched_range_proof_u64( context, proof );
    break;
  case FD_ZKTPP_INSTR_VERIFY_BATCHED_RANGE_PROOF_U128:
    zkp_res = fd_zktpp_verify_proof_batched_range_proof_u128( context, proof );
    break;
  case FD_ZKTPP_INSTR_VERIFY_BATCHED_RANGE_PROOF_U256:
    zkp_res = fd_zktpp_verify_proof_batched_range_proof_u256( context, proof );
    break;
  case FD_ZKTPP_INSTR_VERIFY_CIPHERTEXT_COMMITMENT_EQUALITY:
    zkp_res = fd_zktpp_verify_proof_ciphertext_commitment_equality( context, proof );
    break;
  case FD_ZKTPP_INSTR_VERFIY_GROUPED_CIPHERTEXT_2_HANDLES_VALIDITY:
    zkp_res = fd_zktpp_verify_proof_grouped_ciphertext_validity( context, proof );
    break;
  case FD_ZKTPP_INSTR_VERIFY_BATCHED_GROUPED_CIPHERTEXT_2_HANDLES_VALIDITY:
    zkp_res = fd_zktpp_verify_proof_batched_grouped_ciphertext_validity( context, proof );
    break;
  case FD_ZKTPP_INSTR_VERIFY_FEE_SIGMA:
    zkp_res = fd_zktpp_verify_proof_fee_sigma( context, proof );
    break;
  default:
    return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
  }

  if( FD_UNLIKELY( zkp_res!=FD_EXECUTOR_INSTR_SUCCESS ) ) {
    return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
  }

  /* create context state if accounts are provided with the instruction
     https://github.com/solana-labs/solana/blob/v1.17.10/programs/zk-token-proof/src/lib.rs#L54-L84 */

  //TODO

  return FD_EXECUTOR_INSTR_SUCCESS;
}
