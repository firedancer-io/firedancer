#include "fd_zksdk_private.h"
#include "../../fd_account.h"
#include "../../fd_system_ids.h"

/* fd_zksdk_process_close_context_state is equivalent to process_close_proof_context()
   https://github.com/anza-xyz/agave/blob/v2.0.1/programs/zk-elgamal-proof/src/lib.rs#L127 */
int
fd_zksdk_process_close_context_state( fd_exec_instr_ctx_t * ctx ) {
#define ACC_IDX_PROOF (0UL)
#define ACC_IDX_DEST  (1UL)
#define ACC_IDX_OWNER (2UL)

  fd_pubkey_t owner_pubkey[1];
  fd_pubkey_t proof_pubkey[1];
  fd_pubkey_t dest_pubkey[1];

  /* https://github.com/anza-xyz/agave/blob/v2.0.1/programs/zk-elgamal-proof/src/lib.rs#L131-L139 */
  FD_BORROWED_ACCOUNT_DECL( owner_acc );
  FD_BORROWED_ACCOUNT_TRY_BORROW_IDX( ctx, ACC_IDX_OWNER, owner_acc ) {
    if( FD_UNLIKELY( !fd_instr_acc_is_signer_idx( ctx->instr, ACC_IDX_OWNER ) ) ) {
      return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
    }
    fd_memcpy( owner_pubkey, owner_acc->pubkey, sizeof(fd_pubkey_t) );
  } FD_BORROWED_ACCOUNT_DROP( owner_acc );

  /* https://github.com/anza-xyz/agave/blob/v2.0.1/programs/zk-elgamal-proof/src/lib.rs#L141-L149
     Note: following exactly Agave's behavior, we can certainly simplify the borrowings. */
  FD_BORROWED_ACCOUNT_DECL( proof_acc );
  FD_BORROWED_ACCOUNT_TRY_BORROW_IDX( ctx, ACC_IDX_PROOF, proof_acc ) {
    fd_memcpy( proof_pubkey, proof_acc->pubkey, sizeof(fd_pubkey_t) );
  } FD_BORROWED_ACCOUNT_DROP( proof_acc );

  FD_BORROWED_ACCOUNT_DECL( dest_acc );
  FD_BORROWED_ACCOUNT_TRY_BORROW_IDX( ctx, ACC_IDX_DEST, dest_acc ) {
    fd_memcpy( dest_pubkey, dest_acc->pubkey, sizeof(fd_pubkey_t) );
  } FD_BORROWED_ACCOUNT_DROP( dest_acc );

  if( FD_UNLIKELY( fd_memeq( proof_pubkey, dest_pubkey, sizeof(fd_pubkey_t) ) ) ) {
    return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.0.1/programs/zk-elgamal-proof/src/lib.rs#L151-L152 */
  FD_BORROWED_ACCOUNT_TRY_BORROW_IDX( ctx, ACC_IDX_PROOF, proof_acc ) {

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
  FD_BORROWED_ACCOUNT_TRY_BORROW_IDX( ctx, ACC_IDX_DEST, dest_acc ) {

    /* https://github.com/anza-xyz/agave/blob/v2.0.1/programs/zk-elgamal-proof/src/lib.rs#L163-L166 */
    int err = 0;
    err = fd_account_checked_add_lamports( ctx, ACC_IDX_DEST, proof_acc->const_meta->info.lamports );
    if( FD_UNLIKELY( err ) ) {
      return err;
    }
    err = fd_account_set_lamports( ctx, ACC_IDX_PROOF, 0UL );
    if( FD_UNLIKELY( err ) ) {
      return err;
    }
    err = fd_account_set_data_length( ctx, ACC_IDX_PROOF, 0UL );
    if( FD_UNLIKELY( err ) ) {
      return err;
    }
    err = fd_account_set_owner( ctx, ACC_IDX_PROOF, &fd_solana_system_program_id );
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
fd_zksdk_process_verify_proof( fd_exec_instr_ctx_t * ctx ) {
  uchar const * instr_data = ctx->instr->data;
  ulong instr_acc_cnt      = ctx->instr->acct_cnt;
  uchar instr_id = instr_data[0]; /* instr_data_sz already checked by the caller */

  /* ProofContextState "header" size, ie. 1 authority pubkey + 1 proof_type byte */
#define CTX_HEAD_SZ 33UL

  /* Aux memory buffer.
     When proof data is taken from ix data we can access it directly,
     but when it's taken from account data we need to copy it to release
     the borrow. The largest ZKP is for range_proof_u256.
     Moreover, when storing context to an account, we need to serialize
     the ProofContextState struct that has 33 bytes of header -- we include
     them here so we can do a single memcpy. */
#define MAX_SZ (sizeof(fd_zksdk_range_proof_u256_proof_t)+sizeof(fd_zksdk_batched_range_proof_context_t))
  uchar buffer[ CTX_HEAD_SZ+MAX_SZ ];

  /* Specific instruction function */
  int (*fd_zksdk_instr_verify_proof)( void const *, void const * ) = NULL;
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

  /* https://github.com/anza-xyz/agave/blob/v2.0.1/programs/zk-elgamal-proof/src/lib.rs#L42 */
  uint accessed_accounts = 0U;
  uchar const * context = NULL;
  /* Note: instr_id is guaranteed to be valid, to access values in the arrays. */
  ulong context_sz = fd_zksdk_context_sz[instr_id];
  ulong proof_data_sz = context_sz + fd_zksdk_proof_sz[instr_id];

  if( ctx->instr->data_sz == 5UL ) {
    /* Case 1. Proof data from account data. */

    /* https://github.com/anza-xyz/agave/blob/v2.0.1/programs/zk-elgamal-proof/src/lib.rs#L46-L47 */
    FD_BORROWED_ACCOUNT_DECL( proof_data_acc );
    FD_BORROWED_ACCOUNT_TRY_BORROW_IDX( ctx, 0UL, proof_data_acc ) {

      /* https://github.com/anza-xyz/agave/blob/v2.0.1/programs/zk-elgamal-proof/src/lib.rs#L48 */
      accessed_accounts = 1U;

      /* https://github.com/anza-xyz/agave/blob/v2.0.1/programs/zk-elgamal-proof/src/lib.rs#L50-L61
         Note: it doesn't look like the ref code can throw any error. */
      uint proof_data_offset = fd_uint_load_4_fast(&instr_data[1]);

      /* https://github.com/anza-xyz/agave/blob/v2.0.1/programs/zk-elgamal-proof/src/lib.rs#L62-L65 */
      if( proof_data_offset+proof_data_sz > proof_data_acc->const_meta->dlen ) {
        return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
      }
      context = fd_memcpy( buffer+CTX_HEAD_SZ, &proof_data_acc->const_data[proof_data_offset], proof_data_sz );

    } FD_BORROWED_ACCOUNT_DROP( proof_data_acc );
  } else {
    /* Case 2. Proof data from ix data. */

    /* https://github.com/anza-xyz/agave/blob/v2.0.1/programs/zk-elgamal-proof/src/lib.rs#L78-L82
       Note: instr_id is guaranteed to be valid, to access values in the arrays. */
    if (ctx->instr->data_sz != 1 + proof_data_sz) {
      fd_log_collector_msg_literal( ctx, "invalid proof data" );
      return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
    }
    context = instr_data + 1;
  }

  /* Verify individual ZKP
     https://github.com/anza-xyz/agave/blob/v2.0.1/programs/zk-elgamal-proof/src/lib.rs#L83-L86 */
  void const * proof = context + fd_zksdk_context_sz[instr_id];
  int err = (*fd_zksdk_instr_verify_proof)( context, proof );
  if( FD_UNLIKELY( err ) ) {
    //TODO: full log, including err
    fd_log_collector_msg_literal( ctx, "proof_verification failed" );
    return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
  }

  /* Create context state if accounts are provided with the instruction
     https://github.com/anza-xyz/agave/blob/v2.0.1/programs/zk-elgamal-proof/src/lib.rs#L92 */
  if( instr_acc_cnt > accessed_accounts ) {

    /* https://github.com/anza-xyz/agave/blob/v2.0.1/programs/zk-elgamal-proof/src/lib.rs#L93-L98 */
    fd_pubkey_t context_state_authority[1];
    FD_BORROWED_ACCOUNT_DECL( _acc );
    FD_BORROWED_ACCOUNT_TRY_BORROW_IDX( ctx, accessed_accounts+1, _acc ) {
      fd_memcpy( context_state_authority, _acc->pubkey, sizeof(fd_pubkey_t) );
    } FD_BORROWED_ACCOUNT_DROP( _acc );

    /* https://github.com/anza-xyz/agave/blob/v2.0.1/programs/zk-elgamal-proof/src/lib.rs#L100-L101 */
    FD_BORROWED_ACCOUNT_DECL( proof_context_acc );
    FD_BORROWED_ACCOUNT_TRY_BORROW_IDX( ctx, accessed_accounts, proof_context_acc ) {

      /* https://github.com/anza-xyz/agave/blob/v2.0.1/programs/zk-elgamal-proof/src/lib.rs#L103-L105 */
      if( FD_UNLIKELY( !fd_memeq( proof_context_acc->const_meta->info.owner, &fd_solana_zk_elgamal_proof_program_id, sizeof(fd_pubkey_t) ) ) ) {
        return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_OWNER;
      }

      /* https://github.com/anza-xyz/agave/blob/v2.0.1/programs/zk-elgamal-proof/src/lib.rs#L107-L112 */
      if( FD_UNLIKELY( proof_context_acc->const_meta->dlen >= CTX_HEAD_SZ && proof_context_acc->const_data[32] != 0 ) ) {
        return FD_EXECUTOR_INSTR_ERR_ACC_ALREADY_INITIALIZED;
      }

      /* https://github.com/anza-xyz/agave/blob/v2.0.1/programs/zk-elgamal-proof/src/lib.rs#L114-L115
         Note: nothing to do. */

      /* https://github.com/anza-xyz/agave/blob/v2.0.1/programs/zk-elgamal-proof/src/lib.rs#L117-L119 */
      ulong context_data_sx = CTX_HEAD_SZ + context_sz;
      if( FD_UNLIKELY( proof_context_acc->const_meta->dlen != context_data_sx ) ) {
        return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
      }

      /* https://github.com/anza-xyz/agave/blob/v2.0.1/programs/zk-elgamal-proof/src/lib.rs#L121 */
      fd_memcpy( buffer, context_state_authority, sizeof(fd_pubkey_t) ); // buffer[0..31]
      buffer[ 32 ] = instr_id;                                           // buffer[32]
      if( ctx->instr->data_sz != 5UL ) {                                  // buffer[33..]
        fd_memcpy( buffer+CTX_HEAD_SZ, context, context_sz );
      }
      err = fd_account_set_data_from_slice( ctx, accessed_accounts, buffer, context_data_sx );
      if( FD_UNLIKELY( err ) ) {
        return err;
      }

    } FD_BORROWED_ACCOUNT_DROP( proof_context_acc );
  }

  return FD_EXECUTOR_INSTR_SUCCESS;
}
