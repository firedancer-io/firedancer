#include "fd_zk_elgamal_proof_program.h"
#include "../fd_executor.h"
#include "../fd_borrowed_account.h"
#include "../fd_system_ids.h"
#include "../../log_collector/fd_log_collector.h"
#include "../../../ballet/zksdk/fd_zksdk.h"

/* fd_zksdk_process_verify_proof is equivalent to process_verify_proof()
   and calls specific functions inside zksdk/instructions/ to verify each
   individual ZKP.
   https://github.com/firedancer-io/agave/blob/v4.0.0-prerelease/programs/zk-elgamal-proof/src/lib.rs#L35 */
int
fd_zksdk_process_verify_proof( fd_exec_instr_ctx_t * ctx ) {
  /* This initial code is Firedancer-only, we just need to initialize variables.
     Agave code is referenced via comments. */
  int err;
  uchar const * instr_data    = ctx->instr->data;
  ushort        instr_acc_cnt = ctx->instr->acct_cnt;
  uchar         instr_id      = instr_data[0]; /* instr_data_sz already checked by the caller */

  /* Buffer to store ProofContextStateMeta (header) followed by a proof context
     (the largest context is for batched_grouped_ciphertext_3_handles_validity). */
  const ulong CTX_META_SZ = sizeof(fd_zksdk_proof_ctx_state_meta_t);
  const ulong MAX_CTX_SZ  = sizeof(fd_zksdk_batched_grp_ciph_3h_val_context_t);
  uchar context_state_data[ CTX_META_SZ+MAX_CTX_SZ ];

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

  /* Note: this check is redundant and can't error out
     https://github.com/firedancer-io/agave/blob/v4.0.0-prerelease/programs/zk-elgamal-proof/src/lib.rs#L41
     the caller already does the same:
     https://github.com/firedancer-io/agave/blob/v4.0.0-prerelease/programs/zk-elgamal-proof/src/lib.rs#L190 */

  /* https://github.com/firedancer-io/agave/blob/v4.0.0-prerelease/programs/zk-elgamal-proof/src/lib.rs#L45 */
  ushort accessed_accounts = 0U;

  /* Note: instr_id is guaranteed to be valid, to access values in the arrays. */
  ulong context_sz = fd_zksdk_context_sz[instr_id];
  ulong proof_data_sz = context_sz + fd_zksdk_proof_sz[instr_id];
  uchar const * context = NULL;

  /* if instruction data is exactly 5 bytes, then read proof from an account
     https://github.com/firedancer-io/agave/blob/v4.0.0-prerelease/programs/zk-elgamal-proof/src/lib.rs#L48 */
  if( ctx->instr->data_sz == FD_ZKSDK_INSTR_DATA_LENGTH_WITH_PROOF_ACCOUNT ) {
    /* Case 1. Proof data from account data. */

    /* Borrow the proof data account.
       https://github.com/firedancer-io/agave/blob/v4.0.0-prerelease/programs/zk-elgamal-proof/src/lib.rs#L49-L50 */
    fd_guarded_borrowed_account_t proof_data_acc = {0};
    FD_TRY_BORROW_INSTR_ACCOUNT_DEFAULT_ERR_CHECK( ctx, 0UL, &proof_data_acc );

    /* https://github.com/firedancer-io/agave/blob/v4.0.0-prerelease/programs/zk-elgamal-proof/src/lib.rs#L51 */
    accessed_accounts = 1U;

    /* https://github.com/firedancer-io/agave/blob/v4.0.0-prerelease/programs/zk-elgamal-proof/src/lib.rs#L53-L64
       Note: it doesn't look like Agave code can throw any error. */
    uint proof_data_offset = fd_uint_load_4( &instr_data[1] );

    /* https://github.com/firedancer-io/agave/blob/v4.0.0-prerelease/programs/zk-elgamal-proof/src/lib.rs#L65-L68
       Note: explcit cast to ulong just to call out that there can't be overflow */
    if( (ulong)proof_data_offset+proof_data_sz > fd_borrowed_account_get_data_len( &proof_data_acc ) ) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
    }

    /* https://github.com/firedancer-io/agave/blob/v4.0.0-prerelease/programs/zk-elgamal-proof/src/lib.rs#L69-L72
       Note: this should never fail, the proofs are just bytes, and we tested that the size is valid */
    uchar const * proof_acc_data = fd_borrowed_account_get_data( &proof_data_acc );
    context = &proof_acc_data[proof_data_offset];

  } else {
    /* Case 2. Proof data from ix data. */

    /* https://github.com/firedancer-io/agave/blob/v4.0.0-prerelease/programs/zk-elgamal-proof/src/lib.rs#L81-L85
       Note: instr_id is guaranteed to be valid, to access values in the arrays. */
    if( ctx->instr->data_sz != 1 + proof_data_sz ) {
      fd_log_collector_msg_literal( ctx, "invalid proof data" );
      return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
    }
    context = instr_data + 1;
  }

  /* Verify individual ZKP
     https://github.com/firedancer-io/agave/blob/v4.0.0-prerelease/programs/zk-elgamal-proof/src/lib.rs#L74-L77
     https://github.com/firedancer-io/agave/blob/v4.0.0-prerelease/programs/zk-elgamal-proof/src/lib.rs#L86-L89 */

  /* TODO: we probably need an extra check to validate the length of sigma proofs,
     see: https://github.com/solana-program/zk-elgamal-proof/pull/244
     However this check seems to be redundant for the case of ix data, and
     seems to be missing only for accounts. It's also unclear what the result should be,
     need to have explicit tests. */
  void const * proof = context + fd_zksdk_context_sz[instr_id];
  err = (*fd_zksdk_instr_verify_proof)( context, proof );
  if( FD_UNLIKELY( err ) ) {
    //TODO: full log, including err
    fd_log_collector_msg_literal( ctx, "proof verification failed" );
    return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
  }

  /* Create context state if we have both proof_context and authority accounts.
     https://github.com/firedancer-io/agave/blob/v4.0.0-prerelease/programs/zk-elgamal-proof/src/lib.rs#L95-L98 */
  if( instr_acc_cnt >= accessed_accounts + 2U ) {
    /* Obtain the context_state_authority by borrowing the account temporarily in a local scope.
       https://github.com/firedancer-io/agave/blob/v4.0.0-prerelease/programs/zk-elgamal-proof/src/lib.rs#L100-L102 */
    fd_pubkey_t context_state_authority[1];
    do {
      fd_guarded_borrowed_account_t _acc = {0};
      FD_TRY_BORROW_INSTR_ACCOUNT_DEFAULT_ERR_CHECK( ctx, (ushort)(accessed_accounts+1), &_acc );
      *context_state_authority = *_acc.pubkey;
    } while(0);

    /* Borrow the proof context account
       https://github.com/firedancer-io/agave/blob/v4.0.0-prerelease/programs/zk-elgamal-proof/src/lib.rs#L104-L105 */
    fd_guarded_borrowed_account_t proof_context_acc = {0};
    FD_TRY_BORROW_INSTR_ACCOUNT_DEFAULT_ERR_CHECK( ctx, accessed_accounts, &proof_context_acc );

    /* https://github.com/firedancer-io/agave/blob/v4.0.0-prerelease/programs/zk-elgamal-proof/src/lib.rs#L107-L109 */
    if( FD_UNLIKELY( !fd_memeq( fd_borrowed_account_get_owner( &proof_context_acc ), &fd_solana_zk_elgamal_proof_program_id, sizeof(fd_pubkey_t) ) ) ) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_OWNER;
    }

    /* https://github.com/firedancer-io/agave/blob/v4.0.0-prerelease/programs/zk-elgamal-proof/src/lib.rs#L111-L112 */
    if( FD_UNLIKELY( fd_borrowed_account_get_data_len( &proof_context_acc ) < CTX_META_SZ ) ) {
      /* https://github.com/solana-program/zk-elgamal-proof/blob/zk-sdk%40v5.0.1/zk-sdk/src/zk_elgamal_proof_program/state.rs#L83 */
      return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
    }

    /* https://github.com/firedancer-io/agave/blob/v4.0.0-prerelease/programs/zk-elgamal-proof/src/lib.rs#L114-L116 */
    if( FD_UNLIKELY( fd_borrowed_account_get_data( &proof_context_acc )[32] != 0 ) ) {
      return FD_EXECUTOR_INSTR_ERR_ACC_ALREADY_INITIALIZED;
    }

    /* https://github.com/firedancer-io/agave/blob/v4.0.0-prerelease/programs/zk-elgamal-proof/src/lib.rs#L118-L119 */
    fd_memcpy( context_state_data, context_state_authority, sizeof(fd_pubkey_t) ); /* context_state_data[0..31] */
    context_state_data[ 32 ] = instr_id;                                           /* context_state_data[32] */
    fd_memcpy( context_state_data+CTX_META_SZ, context, context_sz );              /* context_state_data[33..] */

    /* https://github.com/firedancer-io/agave/blob/v4.0.0-prerelease/programs/zk-elgamal-proof/src/lib.rs#L121-L123 */
    ulong context_state_data_sx = CTX_META_SZ + context_sz;
    if( FD_UNLIKELY( fd_borrowed_account_get_data_len( &proof_context_acc ) != context_state_data_sx ) ) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
    }

    /* https://github.com/firedancer-io/agave/blob/v4.0.0-prerelease/programs/zk-elgamal-proof/src/lib.rs#L125 */
    err = fd_borrowed_account_set_data_from_slice( &proof_context_acc, context_state_data, context_state_data_sx );
    if( FD_UNLIKELY( err ) ) {
      return err;
    }
  }

  /* https://github.com/firedancer-io/agave/blob/v4.0.0-prerelease/programs/zk-elgamal-proof/src/lib.rs#L126 */
  return FD_EXECUTOR_INSTR_SUCCESS;
}

/* fd_zksdk_process_close_proof_context is equivalent to process_close_proof_context()
   https://github.com/firedancer-io/agave/blob/v4.0.0-prerelease/programs/zk-elgamal-proof/src/lib.rs#L131 */
int
fd_zksdk_process_close_proof_context( fd_exec_instr_ctx_t * ctx ) {
#define ACC_IDX_PROOF (0UL)
#define ACC_IDX_DEST  (1UL)
#define ACC_IDX_OWNER (2UL)
  fd_pubkey_t owner_pubkey[1];
  fd_pubkey_t proof_pubkey[1];
  fd_pubkey_t dest_pubkey[1];

  /* Note: this check is redundant and can't error out
     https://github.com/firedancer-io/agave/blob/v4.0.0-prerelease/programs/zk-elgamal-proof/src/lib.rs#L133
     the caller already does the same:
     https://github.com/firedancer-io/agave/blob/v4.0.0-prerelease/programs/zk-elgamal-proof/src/lib.rs#L190 */

  /* Obtain the owner pubkey by borrowing the owner account in local scope.
     https://github.com/firedancer-io/agave/blob/v4.0.0-prerelease/programs/zk-elgamal-proof/src/lib.rs#L135-L141 */
  do {
    fd_guarded_borrowed_account_t owner_acc = {0};
    int instr_err_code = 0;
    if( FD_UNLIKELY( !fd_instr_acc_is_signer_idx( ctx->instr, ACC_IDX_OWNER, &instr_err_code ) ) ) {
      if( FD_UNLIKELY( !!instr_err_code ) ) return instr_err_code;
      return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
    }

    FD_TRY_BORROW_INSTR_ACCOUNT_DEFAULT_ERR_CHECK( ctx, ACC_IDX_OWNER, &owner_acc );
    *owner_pubkey = *owner_acc.pubkey;
    /* implicit drop of borrowed owner_acc */
  } while (0);

  /* Allocate space for borrowed accounts */
  fd_guarded_borrowed_account_t proof_acc = {0};
  fd_guarded_borrowed_account_t dest_acc  = {0};

  /* Obtain the proof account pubkey by borrowing the proof account.
     https://github.com/firedancer-io/agave/blob/v4.0.0-prerelease/programs/zk-elgamal-proof/src/lib.rs#L143 */
  FD_TRY_BORROW_INSTR_ACCOUNT_DEFAULT_ERR_CHECK(ctx, ACC_IDX_PROOF, &proof_acc );
  *proof_pubkey = *proof_acc.pubkey;
  fd_borrowed_account_drop( &proof_acc );

  /* Obtain the dest account pubkey by borrowing the dest account.
     https://github.com/firedancer-io/agave/blob/v4.0.0-prerelease/programs/zk-elgamal-proof/src/lib.rs#L144 */
  FD_TRY_BORROW_INSTR_ACCOUNT_DEFAULT_ERR_CHECK( ctx, ACC_IDX_DEST, &dest_acc );
  *dest_pubkey = *dest_acc.pubkey;
  fd_borrowed_account_drop( &dest_acc );

  /* https://github.com/firedancer-io/agave/blob/v4.0.0-prerelease/programs/zk-elgamal-proof/src/lib.rs#L145-L147 */
  if( FD_UNLIKELY( fd_memeq( proof_pubkey, dest_pubkey, sizeof(fd_pubkey_t) ) ) ) {
    return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
  }

  /* Re-borrow the proof account.
     https://github.com/firedancer-io/agave/blob/v4.0.0-prerelease/programs/zk-elgamal-proof/src/lib.rs#L149 */
  FD_TRY_BORROW_INSTR_ACCOUNT_DEFAULT_ERR_CHECK(ctx, ACC_IDX_PROOF, &proof_acc );

  /* Check that the proof context account is owned by the zk-elgamal-proof program.
     https://github.com/firedancer-io/agave/blob/v4.0.0-prerelease/programs/zk-elgamal-proof/src/lib.rs#L150-L152 */
  if( FD_UNLIKELY( !fd_memeq( fd_borrowed_account_get_owner( &proof_acc ), &fd_solana_zk_elgamal_proof_program_id, sizeof(fd_pubkey_t) ) ) ) {
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_OWNER;
  }

  /* https://github.com/firedancer-io/agave/blob/v4.0.0-prerelease/programs/zk-elgamal-proof/src/lib.rs#L153-L154
     Note: data also contains context data, but we only need the initial 33 bytes. */
  if( FD_UNLIKELY( fd_borrowed_account_get_data_len( &proof_acc ) < sizeof(fd_zksdk_proof_ctx_state_meta_t) ) ) {
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  }
  fd_zksdk_proof_ctx_state_meta_t const * proof_ctx_state_meta = fd_type_pun_const( fd_borrowed_account_get_data( &proof_acc ) );

  /* Check that the proof context account is initialized (proof_type != 0).
     ProofType::Uninitialized = 0
     https://github.com/firedancer-io/agave/blob/v4.0.0-prerelease/programs/zk-elgamal-proof/src/lib.rs#L155-L157 */
  if( FD_UNLIKELY( proof_ctx_state_meta->proof_type == 0 ) ) {
    return FD_EXECUTOR_INSTR_ERR_UNINITIALIZED_ACCOUNT;
  }

  /* https://github.com/firedancer-io/agave/blob/v4.0.0-prerelease/programs/zk-elgamal-proof/src/lib.rs#L159 */
  fd_pubkey_t const * expected_owner_addr = (fd_pubkey_t const *)proof_ctx_state_meta->ctx_state_authority;

  /* https://github.com/firedancer-io/agave/blob/v4.0.0-prerelease/programs/zk-elgamal-proof/src/lib.rs#L161-L163 */
  if( FD_UNLIKELY( !fd_memeq( owner_pubkey, expected_owner_addr, sizeof(fd_pubkey_t) ) ) ) {
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_OWNER;
  }

  /* Re-borrow the dest account.
     https://github.com/firedancer-io/agave/blob/v4.0.0-prerelease/programs/zk-elgamal-proof/src/lib.rs#L165 */
  FD_TRY_BORROW_INSTR_ACCOUNT_DEFAULT_ERR_CHECK( ctx, ACC_IDX_DEST, &dest_acc );

  /* https://github.com/firedancer-io/agave/blob/v4.0.0-prerelease/programs/zk-elgamal-proof/src/lib.rs#L166-L169 */
  int err = 0;
  err = fd_borrowed_account_checked_add_lamports( &dest_acc, fd_borrowed_account_get_lamports( &proof_acc ) );
  if( FD_UNLIKELY( err ) ) {
    return err;
  }
  err = fd_borrowed_account_set_lamports( &proof_acc, 0UL );
  if( FD_UNLIKELY( err ) ) {
    return err;
  }
  err = fd_borrowed_account_set_data_length( &proof_acc, 0UL );
  if( FD_UNLIKELY( err ) ) {
    return err;
  }
  err = fd_borrowed_account_set_owner( &proof_acc, &fd_solana_system_program_id );
  if( FD_UNLIKELY( err ) ) {
    return err;
  }

  /* https://github.com/firedancer-io/agave/blob/v4.0.0-prerelease/programs/zk-elgamal-proof/src/lib.rs#L171 */
  return FD_EXECUTOR_INSTR_SUCCESS;
}

/*
 * ZK ElGamal Proof Program
 */

/* https://github.com/firedancer-io/agave/blob/v4.0.0-prerelease/programs/zk-elgamal-proof/src/lib.rs#L174 */
int
fd_executor_zk_elgamal_proof_program_execute( fd_exec_instr_ctx_t * ctx ) {
  /* https://github.com/firedancer-io/agave/blob/v4.0.0-prerelease/programs/zk-elgamal-proof/src/lib.rs#L175-L187 */
  if( FD_LIKELY(  FD_FEATURE_ACTIVE_BANK( ctx->bank, disable_zk_elgamal_proof_program )
              && !FD_FEATURE_ACTIVE_BANK( ctx->bank, reenable_zk_elgamal_proof_program ) ) ) {
    fd_log_collector_msg_literal( ctx, "zk-elgamal-proof program is temporarily disabled" );
    return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
  }

  uchar const * instr_data    = ctx->instr->data;
  ulong         instr_data_sz = ctx->instr->data_sz;

  /* https://github.com/firedancer-io/agave/blob/v4.0.0-prerelease/programs/zk-elgamal-proof/src/lib.rs#L189-L193 */
  if( FD_UNLIKELY( instr_data_sz==0UL ) ) {
    return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
  }

  switch( instr_data[0] ) {
  case FD_ZKSDK_INSTR_CLOSE_CONTEXT_STATE:
    /* https://github.com/firedancer-io/agave/blob/v4.0.0-prerelease/programs/zk-elgamal-proof/src/lib.rs#L196-L202 */
    FD_EXEC_CU_UPDATE( ctx, FD_ZKSDK_INSTR_CLOSE_CONTEXT_STATE_COMPUTE_UNITS );
    fd_log_collector_msg_literal( ctx, "CloseContextState" );
    return fd_zksdk_process_close_proof_context( ctx );

  case FD_ZKSDK_INSTR_VERIFY_ZERO_CIPHERTEXT:
    /* https://github.com/firedancer-io/agave/blob/v4.0.0-prerelease/programs/zk-elgamal-proof/src/lib.rs#L203-L207 */
    FD_EXEC_CU_UPDATE( ctx, FD_ZKSDK_INSTR_VERIFY_ZERO_CIPHERTEXT_COMPUTE_UNITS );
    fd_log_collector_msg_literal( ctx, "VerifyZeroCiphertext" );
    break;

  case FD_ZKSDK_INSTR_VERIFY_CIPHERTEXT_CIPHERTEXT_EQUALITY:
    FD_EXEC_CU_UPDATE( ctx, FD_ZKSDK_INSTR_VERIFY_CIPHERTEXT_CIPHERTEXT_EQUALITY_COMPUTE_UNITS );
    fd_log_collector_msg_literal( ctx, "VerifyCiphertextCiphertextEquality" );
    break;

  case FD_ZKSDK_INSTR_VERIFY_CIPHERTEXT_COMMITMENT_EQUALITY:
    FD_EXEC_CU_UPDATE( ctx, FD_ZKSDK_INSTR_VERIFY_CIPHERTEXT_COMMITMENT_EQUALITY_COMPUTE_UNITS );
    fd_log_collector_msg_literal( ctx, "VerifyCiphertextCommitmentEquality" );
    break;

  case FD_ZKSDK_INSTR_VERIFY_PUBKEY_VALIDITY:
    FD_EXEC_CU_UPDATE( ctx, FD_ZKSDK_INSTR_VERIFY_PUBKEY_VALIDITY_COMPUTE_UNITS );
    fd_log_collector_msg_literal( ctx, "VerifyPubkeyValidity" );
    break;

  case FD_ZKSDK_INSTR_VERIFY_PERCENTAGE_WITH_CAP:
    FD_EXEC_CU_UPDATE( ctx, FD_ZKSDK_INSTR_VERIFY_PERCENTAGE_WITH_CAP_COMPUTE_UNITS );
    fd_log_collector_msg_literal( ctx, "VerifyPercentageWithCap" );
    break;

  case FD_ZKSDK_INSTR_VERIFY_BATCHED_RANGE_PROOF_U64:
    FD_EXEC_CU_UPDATE( ctx, FD_ZKSDK_INSTR_VERIFY_BATCHED_RANGE_PROOF_U64_COMPUTE_UNITS );
    fd_log_collector_msg_literal( ctx, "VerifyBatchedRangeProofU64" );
    break;

  case FD_ZKSDK_INSTR_VERIFY_BATCHED_RANGE_PROOF_U128:
    FD_EXEC_CU_UPDATE( ctx, FD_ZKSDK_INSTR_VERIFY_BATCHED_RANGE_PROOF_U128_COMPUTE_UNITS );
    fd_log_collector_msg_literal( ctx, "VerifyBatchedRangeProofU128" );
    break;

  case FD_ZKSDK_INSTR_VERIFY_BATCHED_RANGE_PROOF_U256:
    FD_EXEC_CU_UPDATE( ctx, FD_ZKSDK_INSTR_VERIFY_BATCHED_RANGE_PROOF_U256_COMPUTE_UNITS );
    fd_log_collector_msg_literal( ctx, "VerifyBatchedRangeProofU256" );
    break;

  case FD_ZKSDK_INSTR_VERIFY_GROUPED_CIPHERTEXT_2_HANDLES_VALIDITY:
    FD_EXEC_CU_UPDATE( ctx, FD_ZKSDK_INSTR_VERIFY_GROUPED_CIPHERTEXT_2_HANDLES_VALIDITY_COMPUTE_UNITS );
    fd_log_collector_msg_literal( ctx, "VerifyGroupedCiphertext2HandlesValidity" );
    break;

  case FD_ZKSDK_INSTR_VERIFY_BATCHED_GROUPED_CIPHERTEXT_2_HANDLES_VALIDITY:
    FD_EXEC_CU_UPDATE( ctx, FD_ZKSDK_INSTR_VERIFY_BATCHED_GROUPED_CIPHERTEXT_2_HANDLES_VALIDITY_COMPUTE_UNITS );
    fd_log_collector_msg_literal( ctx, "VerifyBatchedGroupedCiphertext2HandlesValidity" );
    break;

  case FD_ZKSDK_INSTR_VERIFY_GROUPED_CIPHERTEXT_3_HANDLES_VALIDITY:
    FD_EXEC_CU_UPDATE( ctx, FD_ZKSDK_INSTR_VERIFY_GROUPED_CIPHERTEXT_3_HANDLES_VALIDITY_COMPUTE_UNITS );
    fd_log_collector_msg_literal( ctx, "VerifyGroupedCiphertext3HandlesValidity" );
    break;

  case FD_ZKSDK_INSTR_VERIFY_BATCHED_GROUPED_CIPHERTEXT_3_HANDLES_VALIDITY:
    FD_EXEC_CU_UPDATE( ctx, FD_ZKSDK_INSTR_VERIFY_BATCHED_GROUPED_CIPHERTEXT_3_HANDLES_VALIDITY_COMPUTE_UNITS );
    fd_log_collector_msg_literal( ctx, "VerifyBatchedGroupedCiphertext3HandlesValidity" );
    break;

  default:
    /* Invalid instruction discriminator.
       https://github.com/firedancer-io/agave/blob/v4.0.0-prerelease/programs/zk-elgamal-proof/src/lib.rs#L192-L193 */
    return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
  }

  /* All verify instructions call process_verify_proof.
     https://github.com/firedancer-io/agave/blob/v4.0.0-prerelease/programs/zk-elgamal-proof/src/lib.rs#L208-L210 (and similar for each instruction) */
  return fd_zksdk_process_verify_proof( ctx );
}
