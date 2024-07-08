#include "fd_zksdk_private.h"
#include "../../fd_account.h"
#include "../../fd_system_ids.h"

/* fd_zksdk_process_close_context_state is equivalent to process_close_proof_context()
   https://github.com/anza-xyz/agave/blob/v2.0.1/programs/zk-elgamal-proof/src/lib.rs#L127 */
int
fd_zksdk_process_close_context_state( fd_exec_instr_ctx_t ctx ) {
#define ACC_IDX_PROOF (0UL)
#define ACC_IDX_DEST  (1UL)
#define ACC_IDX_OWNER (2UL)

  fd_pubkey_t owner_pubkey[1];
  fd_pubkey_t proof_pubkey[1];
  fd_pubkey_t dest_pubkey[1];

  /* https://github.com/anza-xyz/agave/blob/v2.0.1/programs/zk-elgamal-proof/src/lib.rs#L131-L139 */
  FD_BORROWED_ACCOUNT_DECL( owner_acc );
  FD_BORROWED_ACCOUNT_TRY_BORROW_IDX( &ctx, ACC_IDX_OWNER, owner_acc ) {
    if( FD_UNLIKELY( !fd_instr_acc_is_signer_idx( ctx.instr, ACC_IDX_OWNER ) ) ) {
      return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
    }
    fd_memcpy( owner_pubkey, owner_acc->pubkey, sizeof(fd_pubkey_t) );
  } FD_BORROWED_ACCOUNT_DROP( owner_acc );

  /* https://github.com/anza-xyz/agave/blob/v2.0.1/programs/zk-elgamal-proof/src/lib.rs#L141-L149
     Note: following exactly Agave's behavior, we can certainly simplify the borrowings. */
  FD_BORROWED_ACCOUNT_DECL( proof_acc );
  FD_BORROWED_ACCOUNT_TRY_BORROW_IDX( &ctx, ACC_IDX_PROOF, proof_acc ) {
    fd_memcpy( proof_pubkey, proof_acc->pubkey, sizeof(fd_pubkey_t) );
  } FD_BORROWED_ACCOUNT_DROP( proof_acc );

  FD_BORROWED_ACCOUNT_DECL( dest_acc );
  FD_BORROWED_ACCOUNT_TRY_BORROW_IDX( &ctx, ACC_IDX_DEST, dest_acc ) {
    fd_memcpy( dest_pubkey, dest_acc->pubkey, sizeof(fd_pubkey_t) );
  } FD_BORROWED_ACCOUNT_DROP( dest_acc );

  if( FD_UNLIKELY( fd_memeq( proof_pubkey, dest_pubkey, sizeof(fd_pubkey_t) ) ) ) {
    return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.0.1/programs/zk-elgamal-proof/src/lib.rs#L151-L152 */
  FD_BORROWED_ACCOUNT_TRY_BORROW_IDX( &ctx, ACC_IDX_PROOF, proof_acc ) {

    /* https://github.com/anza-xyz/agave/blob/v2.0.1/programs/zk-elgamal-proof/src/lib.rs#L161-L162
       Note: data also contains context data, but we only need the initial 33 bytes. */
    if( FD_UNLIKELY( proof_acc->const_meta->dlen < sizeof(fd_zksdk_proof_ctx_state_meta_t) ) ) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
    }
    fd_zksdk_proof_ctx_state_meta_t const * proof_ctx_state_meta = fd_type_pun_const( proof_acc->const_data );

    /* https://github.com/anza-xyz/agave/blob/v2.0.1/programs/zk-elgamal-proof/src/lib.rs#L155 */
    fd_pubkey_t const * expected_owner_addr = &proof_ctx_state_meta->ctx_state_authority;

    /* https://github.com/anza-xyz/agave/blob/v2.0.1/programs/zk-elgamal-proof/src/lib.rs#L157-L159 */
    if( FD_UNLIKELY( !fd_memeq( owner_pubkey, expected_owner_addr, sizeof(fd_pubkey_t) ) ) ) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_OWNER;
    }

  /* https://github.com/anza-xyz/agave/blob/v2.0.1/programs/zk-elgamal-proof/src/lib.rs#L161-L162 */
  FD_BORROWED_ACCOUNT_TRY_BORROW_IDX( &ctx, ACC_IDX_DEST, dest_acc ) {

    /* https://github.com/anza-xyz/agave/blob/v2.0.1/programs/zk-elgamal-proof/src/lib.rs#L163-L166 */
    int err = 0;
    err = fd_account_checked_add_lamports( &ctx, ACC_IDX_DEST, proof_acc->meta->info.lamports );
    if( FD_UNLIKELY( err ) ) {
      return err;
    }
    err = fd_account_set_lamports( &ctx, ACC_IDX_PROOF, 0UL );
    if( FD_UNLIKELY( err ) ) {
      return err;
    }
    err = fd_account_set_data_length( &ctx, ACC_IDX_PROOF, 0UL );
    if( FD_UNLIKELY( err ) ) {
      return err;
    }
    err = fd_account_set_owner( &ctx, ACC_IDX_PROOF, &fd_solana_system_program_id );
    if( FD_UNLIKELY( err ) ) {
      return err;
    }

  } FD_BORROWED_ACCOUNT_DROP( dest_acc );
  } FD_BORROWED_ACCOUNT_DROP( proof_acc );

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
  case FD_ZKSDK_INSTR_VERIFY_GROUPED_CIPHERTEXT_2_HANDLES_VALIDITY:
    fd_zksdk_instr_verify_proof = &fd_zksdk_instr_verify_proof_grouped_ciphertext_2_handles_validity;
    break;
  case FD_ZKSDK_INSTR_VERIFY_BATCHED_GROUPED_CIPHERTEXT_2_HANDLES_VALIDITY:
    fd_zksdk_instr_verify_proof = &fd_zksdk_instr_verify_proof_batched_grouped_ciphertext_2_handles_validity;
    break;
  case FD_ZKSDK_INSTR_VERIFY_GROUPED_CIPHERTEXT_3_HANDLES_VALIDITY:
    fd_zksdk_instr_verify_proof = &fd_zksdk_instr_verify_proof_grouped_ciphertext_3_handles_validity;
    break;
  case FD_ZKSDK_INSTR_VERIFY_BATCHED_GROUPED_CIPHERTEXT_3_HANDLES_VALIDITY:
    fd_zksdk_instr_verify_proof = &fd_zksdk_instr_verify_proof_batched_grouped_ciphertext_3_handles_validity;
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
    return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
  }

  /* create context state if accounts are provided with the instruction
     https://github.com/anza-xyz/agave/blob/v2.0.1/programs/zk-elgamal-proof/src/lib.rs#L92 */

  if( instr_acc_cnt == 0 ) {
    return FD_EXECUTOR_INSTR_SUCCESS;
  }

  FD_LOG_DEBUG(( "create zk proof context account" ));
#if 0
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
#endif
  return FD_EXECUTOR_INSTR_SUCCESS;
}
