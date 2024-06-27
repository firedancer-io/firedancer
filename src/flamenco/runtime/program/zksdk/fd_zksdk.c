#include <string.h>
#include "fd_zksdk_private.h"
#include "../../fd_acc_mgr.h"
#include "../../fd_system_ids.h"

struct __attribute__((packed)) fd_zksdk_proof_ctx_state_meta {
  uchar ctx_state_authority[32];
  uchar proof_type;
};
typedef struct fd_zksdk_proof_ctx_state_meta fd_zksdk_proof_ctx_state_meta_t;

static inline int
fd_try_borrow_instruction_account( fd_exec_instr_ctx_t *    ctx,
                                   uchar                    idx,
                                   fd_borrowed_account_t ** acc ) {
  int rc = fd_instr_borrowed_account_view_idx( ctx, idx, acc );
  switch ( rc ) {
  case FD_ACC_MGR_SUCCESS:
    return FD_EXECUTOR_INSTR_SUCCESS;
  case FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT:
    return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
  }
  return FD_EXECUTOR_INSTR_ERR_ACC_BORROW_FAILED;
}

static inline int
fd_try_borrow_instruction_account_modify( fd_exec_instr_ctx_t *    ctx,
                                          uchar                    idx,
                                          ulong                    min_data_sz,
                                          fd_borrowed_account_t ** acc ) {
  int rc = fd_instr_borrowed_account_modify_idx( ctx, idx, min_data_sz, acc );
  if( FD_LIKELY( rc == FD_ACC_MGR_SUCCESS ) ) {
    return FD_EXECUTOR_INSTR_SUCCESS;
  }
  return FD_EXECUTOR_INSTR_ERR_ACC_BORROW_FAILED;
}

/* fd_zksdk_process_close_context_state is equivalent to process_close_proof_context()
   https://github.com/anza-xyz/agave/blob/v2.0.1/programs/zk-elgamal-proof/src/lib.rs#L127 */
int
fd_zksdk_process_close_context_state( fd_exec_instr_ctx_t ctx ) {
  ulong instr_acc_cnt  = ctx.instr->acct_cnt;
  int rc = 0;

  uchar owner_idx = 2;
  uchar proof_idx = 0;
  uchar dest_idx  = 1;
  if( FD_UNLIKELY( instr_acc_cnt != 3UL ) ) {
    return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
  }

  fd_borrowed_account_t * owner_acc = NULL;
  rc = fd_try_borrow_instruction_account( &ctx, owner_idx, &owner_acc );
  if( FD_UNLIKELY( rc != FD_EXECUTOR_INSTR_SUCCESS ) ) {
    return rc;
  }

  /* https://github.com/solana-labs/solana/blob/v1.17.13/programs/zk-token-proof/src/lib.rs#L97 */
  if( FD_UNLIKELY( !fd_instr_acc_is_signer_idx( ctx.instr, owner_idx ) ) ) {
    return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
  }

  fd_borrowed_account_t * proof_acc = NULL;
  rc = fd_try_borrow_instruction_account( &ctx, proof_idx, &proof_acc );
  if( FD_UNLIKELY( rc != FD_EXECUTOR_INSTR_SUCCESS ) ) {
    return rc;
  }

  fd_borrowed_account_t * dest_acc = NULL;
  rc = fd_try_borrow_instruction_account( &ctx, dest_idx, &dest_acc );
  if( FD_UNLIKELY( rc != FD_EXECUTOR_INSTR_SUCCESS ) ) {
    return rc;
  }

  /* https://github.com/solana-labs/solana/blob/v1.17.13/programs/zk-token-proof/src/lib.rs#L109 */
  if( FD_UNLIKELY( fd_memeq( proof_acc->pubkey->uc, dest_acc->pubkey->uc, sizeof(fd_pubkey_t) ) ) ) {
    return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
  }

  rc = fd_try_borrow_instruction_account_modify( &ctx, proof_idx, 0, &proof_acc );
  if( FD_UNLIKELY( rc != FD_EXECUTOR_INSTR_SUCCESS ) ) {
    return rc;
  }

  /* https://github.com/solana-labs/solana/blob/v1.17.13/programs/zk-token-proof/src/lib.rs#L115
     note that data contains also context data, but we only need the initial 33 bytes. */
  if( FD_UNLIKELY( proof_acc->const_meta->dlen < sizeof(fd_zksdk_proof_ctx_state_meta_t) ) ) {
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  }
  fd_zksdk_proof_ctx_state_meta_t const * proof_ctx_state_meta = fd_type_pun_const( proof_acc->const_data );

  /* https://github.com/solana-labs/solana/blob/v1.17.13/programs/zk-token-proof/src/lib.rs#L117-L119 */
  uchar const * expected_owner_addr = proof_ctx_state_meta->ctx_state_authority;
  if( !FD_UNLIKELY( fd_memeq( owner_acc->pubkey->uc, expected_owner_addr, sizeof(fd_pubkey_t) ) ) ) {
    FD_LOG_HEXDUMP_DEBUG(( "owner", owner_acc->pubkey->uc, sizeof(fd_pubkey_t) ));
    FD_LOG_HEXDUMP_DEBUG(( "ctx_state_authority", proof_ctx_state_meta->ctx_state_authority, sizeof(fd_pubkey_t) ));
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_OWNER;
  }

  /* https://github.com/solana-labs/solana/blob/v1.17.13/programs/zk-token-proof/src/lib.rs#L123-L125 */
  rc = fd_try_borrow_instruction_account_modify( &ctx, dest_idx, 0, &dest_acc );
  if( FD_UNLIKELY( rc != FD_EXECUTOR_INSTR_SUCCESS ) ) {
    return rc;
  }
  dest_acc->meta->info.lamports += proof_acc->meta->info.lamports;

  /* delete proof context account */
  proof_acc->meta->info.lamports = 0;
  proof_acc->meta->dlen = 0;
  fd_memcpy( proof_acc->meta->info.owner, fd_solana_system_program_id.uc, sizeof(fd_pubkey_t) );

  return FD_EXECUTOR_INSTR_SUCCESS;
}

/* fd_zksdk_process_verify_proof is equivalent to process_verify_proof()
   and calls specific functions inside instructions/ to verify each
   individual ZKP.
   https://github.com/anza-xyz/agave/blob/v2.0.1/programs/zk-elgamal-proof/src/lib.rs#L32 */
int
fd_zksdk_process_verify_proof( fd_exec_instr_ctx_t ctx ) {
  uchar const * instr_data = ctx.instr->data;
  ulong instr_acc_cnt      = ctx.instr->acct_cnt;
  uchar instr_id = instr_data[0];
  int (*fd_zksdk_instr_verify_proof)( void const *, void const * ) = NULL;

  /* Specific instruction function */
  switch( instr_id ) {
  case FD_ZKSDK_INSTR_VERIFY_ZERO_CIPHERTEXT:
    fd_zksdk_instr_verify_proof = &fd_zksdk_instr_verify_proof_zero_ciphertext;
    break;
  case FD_ZKSDK_INSTR_VERIFY_CIPHERTEXT_CIPHERTEXT_EQUALITY:
    fd_zksdk_instr_verify_proof = &fd_zksdk_instr_verify_proof_ciphertext_ciphertext_equality;
    break;
  case FD_ZKSDK_INSTR_VERIFY_CIPHERTEXT_COMMITMENT_EQUALITY:
    fd_zksdk_instr_verify_proof = &fd_zksdk_instr_verify_proof_ciphertext_commitment_equality;
    break;
  case FD_ZKSDK_INSTR_VERIFY_PUBKEY_VALIDITY:
    fd_zksdk_instr_verify_proof = &fd_zksdk_instr_verify_proof_pubkey_validity;
    break;
  case FD_ZKSDK_INSTR_VERIFY_PERCENTAGE_WITH_CAP:
    fd_zksdk_instr_verify_proof = &fd_zksdk_instr_verify_proof_percentage_with_cap;
    break;
  case FD_ZKSDK_INSTR_VERIFY_BATCHED_RANGE_PROOF_U64:
    fd_zksdk_instr_verify_proof = &fd_zksdk_instr_verify_proof_batched_range_proof_u64;
    break;
  case FD_ZKSDK_INSTR_VERIFY_BATCHED_RANGE_PROOF_U128:
    fd_zksdk_instr_verify_proof = &fd_zksdk_instr_verify_proof_batched_range_proof_u128;
    break;
  case FD_ZKSDK_INSTR_VERIFY_BATCHED_RANGE_PROOF_U256:
    fd_zksdk_instr_verify_proof = &fd_zksdk_instr_verify_proof_batched_range_proof_u256;
    break;
  default:
    return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
  }

  /* parse context and proof data
     important: instr_id is guaranteed to be valid, to access values in the arrays */
  if (ctx.instr->data_sz != 1 + fd_zksdk_context_sz[instr_id] + fd_zksdk_proof_sz[instr_id]) {
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  }
  void const * context = instr_data + 1;
  void const * proof   = instr_data + 1 + fd_zksdk_context_sz[instr_id];

  /* verify individual ZKP */
  int zkp_res = (*fd_zksdk_instr_verify_proof)( context, proof );

  if( FD_UNLIKELY( zkp_res!=FD_EXECUTOR_INSTR_SUCCESS ) ) {
    // return zkp_res;
    return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
  }

  /* create context state if accounts are provided with the instruction
     https://github.com/anza-xyz/agave/blob/v2.0.1/programs/zk-elgamal-proof/src/lib.rs#L92 */

  if( instr_acc_cnt == 0 ) {
    return FD_EXECUTOR_INSTR_SUCCESS;
  }

  FD_LOG_DEBUG(( "create zk proof context account" ));

  int rc = 0;
  uchar auth_idx  = 1;
  uchar proof_idx = 0;
  ulong data_sz = 32UL + 1UL + fd_zksdk_context_sz[instr_id];

  fd_borrowed_account_t * auth_acc = NULL;
  rc = fd_try_borrow_instruction_account( &ctx, auth_idx, &auth_acc );
  if( FD_UNLIKELY( rc != FD_EXECUTOR_INSTR_SUCCESS ) ) {
    return rc;
  }

  fd_borrowed_account_t * proof_acc = NULL;
  rc = fd_try_borrow_instruction_account( &ctx, proof_idx, &proof_acc );
  if( FD_UNLIKELY( rc != FD_EXECUTOR_INSTR_SUCCESS ) ) {
    return rc;
  }

  /* https://github.com/solana-labs/solana/blob/v1.17.13/programs/zk-token-proof/src/lib.rs#L62 */
  if( FD_UNLIKELY( !fd_memeq( proof_acc->const_meta->info.owner, fd_solana_zk_elgamal_proof_program_id.uc, sizeof(fd_pubkey_t) ) ) ) {
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_OWNER;
  }

  /* proof_acc->data contains:
     - 32-byte context state authority
     - 1-byte proof type (0 == uninitialized)
     - the actual proof context state data

     Rust parses the data structure:
     - Parsing invalid context state authority + proof type returns "invalid account data"
     - Parsing a valid context state authority + proof type that's not unintialized returs "account already initialized"
     - Parsing an (empty? garbage?) authority and uninitialized proof type should work. */
  /* https://github.com/solana-labs/solana/blob/v1.17.13/programs/zk-token-proof/src/lib.rs#L69 */
  if( FD_UNLIKELY( proof_acc->const_meta->dlen < 33UL ) ) {
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  }
  if( FD_UNLIKELY( proof_acc->const_meta->dlen >= 33UL && proof_acc->const_data[32] != 0 ) ) {
    return FD_EXECUTOR_INSTR_ERR_ACC_ALREADY_INITIALIZED;
  }

  rc = fd_try_borrow_instruction_account_modify( &ctx, proof_idx, data_sz, &proof_acc );
  if( FD_UNLIKELY( rc != FD_EXECUTOR_INSTR_SUCCESS ) ) {
    return rc;
  }

  fd_memcpy( &proof_acc->data[  0 ], auth_acc->pubkey->uc, sizeof(fd_pubkey_t) );
  /* instr_data first byte is instr_id == proof type, followed by the context */
  fd_memcpy( &proof_acc->data[ 32 ], instr_data, 1UL + fd_zksdk_context_sz[instr_id] );

  return FD_EXECUTOR_INSTR_SUCCESS;
}
