#include "fd_zksdk_private.h"
#include "../../fd_borrowed_account.h"
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

  /* Obtain the owner pubkey by borrowing the owner account in local scope
  https://github.com/anza-xyz/agave/blob/master/programs/zk-elgamal-proof/src/lib.rs#L133-L141 */
  do {
    fd_guarded_borrowed_account_t owner_acc = {0};
    int instr_err_code = 0;
    if( FD_UNLIKELY( !fd_instr_acc_is_signer_idx( ctx->instr, ACC_IDX_OWNER, &instr_err_code ) ) ) {
      if( FD_UNLIKELY( !!instr_err_code ) ) return instr_err_code;
      return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
    }

    FD_TRY_BORROW_INSTR_ACCOUNT_DEFAULT_ERR_CHECK( ctx, ACC_IDX_OWNER, &owner_acc );
    *owner_pubkey = *owner_acc.acct->pubkey;
    /* implicit drop of borrowed owner_acc */
  } while (0);

  /* Allocate space for borrowed accounts */
  fd_guarded_borrowed_account_t proof_acc = {0};
  fd_guarded_borrowed_account_t dest_acc  = {0};

  /* Obtain the proof account pubkey by borrowing the proof account.
     https://github.com/anza-xyz/agave/blob/master/programs/zk-elgamal-proof/src/lib.rs#L143-L145 */
  FD_TRY_BORROW_INSTR_ACCOUNT_DEFAULT_ERR_CHECK(ctx, ACC_IDX_PROOF, &proof_acc );
  *proof_pubkey = *proof_acc.acct->pubkey;
  fd_borrowed_account_drop( &proof_acc );

  /* Obtain the dest account pubkey by borrowing the dest account.
     https://github.com/anza-xyz/agave/blob/master/programs/zk-elgamal-proof/src/lib.rs#L146-L148*/
  FD_TRY_BORROW_INSTR_ACCOUNT_DEFAULT_ERR_CHECK( ctx, ACC_IDX_DEST, &dest_acc );
  *dest_pubkey = *dest_acc.acct->pubkey;
  fd_borrowed_account_drop( &dest_acc );

  if( FD_UNLIKELY( fd_memeq( proof_pubkey, dest_pubkey, sizeof(fd_pubkey_t) ) ) ) {
    return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
  }

  /* Re-borrow the proof account
     https://github.com/anza-xyz/agave/blob/master/programs/zk-elgamal-proof/src/lib.rs#L153-L154 */
  FD_TRY_BORROW_INSTR_ACCOUNT_DEFAULT_ERR_CHECK(ctx, ACC_IDX_PROOF, &proof_acc );

  /* Check that the proof context account is owned by the zk-elgamal-proof program
     https://github.com/anza-xyz/agave/blob/v3.1.0-beta.0/programs/zk-elgamal-proof/src/lib.rs#167-L171 */
  if( FD_UNLIKELY( !fd_memeq( fd_borrowed_account_get_owner( &proof_acc ), &fd_solana_zk_elgamal_proof_program_id, sizeof(fd_pubkey_t) ) ) ) {
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_OWNER;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.0.1/programs/zk-elgamal-proof/src/lib.rs#L161-L162
      Note: data also contains context data, but we only need the initial 33 bytes. */
  if( FD_UNLIKELY( fd_borrowed_account_get_data_len( &proof_acc ) < sizeof(fd_zksdk_proof_ctx_state_meta_t) ) ) {
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  }
  fd_zksdk_proof_ctx_state_meta_t const * proof_ctx_state_meta = fd_type_pun_const( fd_borrowed_account_get_data( &proof_acc ) );

  /* Check that the proof context account is initialized (proof_type != 0)
     ProofType::Uninitialized = 0
     https://github.com/anza-xyz/agave/blob/v3.1.0-beta.0/programs/zk-elgamal-proof/src/lib.rs#L161-L165 */
  if( FD_UNLIKELY( proof_ctx_state_meta->proof_type == 0 ) ) {
    return FD_EXECUTOR_INSTR_ERR_UNINITIALIZED_ACCOUNT;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.0.1/programs/zk-elgamal-proof/src/lib.rs#L155 */
  fd_pubkey_t const * expected_owner_addr = &proof_ctx_state_meta->ctx_state_authority;

  /* https://github.com/anza-xyz/agave/blob/v2.0.1/programs/zk-elgamal-proof/src/lib.rs#L157-L159 */
  if( FD_UNLIKELY( !fd_memeq( owner_pubkey, expected_owner_addr, sizeof(fd_pubkey_t) ) ) ) {
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_OWNER;
  }

  /* Re-borrow the dest account
     https://github.com/anza-xyz/agave/blob/v2.1.14/programs/zk-elgamal-proof/src/lib.rs#L162-L163 */
  FD_TRY_BORROW_INSTR_ACCOUNT_DEFAULT_ERR_CHECK( ctx, ACC_IDX_DEST, &dest_acc );

  /* https://github.com/anza-xyz/agave/blob/v2.0.1/programs/zk-elgamal-proof/src/lib.rs#L163-L166 */
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

  return FD_EXECUTOR_INSTR_SUCCESS;
}

/* fd_zksdk_process_verify_proof is equivalent to process_verify_proof()
   and calls specific functions inside instructions/ to verify each
   individual ZKP.
   https://github.com/anza-xyz/agave/blob/v2.0.1/programs/zk-elgamal-proof/src/lib.rs#L32 */
int
fd_zksdk_process_verify_proof( fd_exec_instr_ctx_t * ctx ) {
  int err;
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
  ushort        accessed_accounts = 0U;
  uchar const * context           = NULL;
  /* Note: instr_id is guaranteed to be valid, to access values in the arrays. */
  ulong context_sz = fd_zksdk_context_sz[instr_id];
  ulong proof_data_sz = context_sz + fd_zksdk_proof_sz[instr_id];

  /* if instruction data is exactly 5 bytes, then read proof from an account
     https://github.com/anza-xyz/agave/blob/v2.1.14/programs/zk-elgamal-proof/src/lib.rs#L46 */
  if( ctx->instr->data_sz == 5UL ) {
    /* Case 1. Proof data from account data. */

    /* Borrow the proof data account.
      https://github.com/anza-xyz/agave/blob/v2.1.14/programs/zk-elgamal-proof/src/lib.rs#L47-L48 */
    fd_guarded_borrowed_account_t proof_data_acc = {0};
    FD_TRY_BORROW_INSTR_ACCOUNT_DEFAULT_ERR_CHECK( ctx, 0UL, &proof_data_acc );

    /* https://github.com/anza-xyz/agave/blob/v2.0.1/programs/zk-elgamal-proof/src/lib.rs#L48 */
    accessed_accounts = 1U;

    /* https://github.com/anza-xyz/agave/blob/v2.0.1/programs/zk-elgamal-proof/src/lib.rs#L50-L61
        Note: it doesn't look like the ref code can throw any error. */
    uint proof_data_offset = fd_uint_load_4_fast(&instr_data[1]);

    /* https://github.com/anza-xyz/agave/blob/v2.0.1/programs/zk-elgamal-proof/src/lib.rs#L62-L65 */
    if( proof_data_offset+proof_data_sz > fd_borrowed_account_get_data_len( &proof_data_acc ) ) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
    }
    uchar const * proof_acc_data = fd_borrowed_account_get_data( &proof_data_acc );
    context = fd_memcpy( buffer+CTX_HEAD_SZ, &proof_acc_data[proof_data_offset], proof_data_sz );
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
  err = (*fd_zksdk_instr_verify_proof)( context, proof );
  if( FD_UNLIKELY( err ) ) {
    //TODO: full log, including err
    fd_log_collector_msg_literal( ctx, "proof_verification failed" );
    return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
  }

  /* Create context state if we have both proof_context and authority accounts.
     https://github.com/anza-xyz/agave/blob/v3.1.0-beta.0/programs/zk-elgamal-proof/src/lib.rs#L102-L106 */
  if( instr_acc_cnt >= accessed_accounts + 2UL ) {
    /* Obtain the context_state_authority by borrowing the account temporarily in a local scope.
       https://github.com/anza-xyz/agave/blob/v2.1.14/programs/zk-elgamal-proof/src/lib.rs#L94-L99
       https://github.com/anza-xyz/agave/blob/v3.1.0-beta.0/programs/zk-elgamal-proof/src/lib.rs#L107-L110 */
    fd_pubkey_t context_state_authority[1];
    do {
      fd_guarded_borrowed_account_t _acc = {0};
      FD_TRY_BORROW_INSTR_ACCOUNT_DEFAULT_ERR_CHECK( ctx, (ushort)(accessed_accounts+1), &_acc );
      *context_state_authority = *_acc.acct->pubkey;
    } while(0);

    /* Borrow the proof context account
       https://github.com/anza-xyz/agave/blob/v2.1.14/programs/zk-elgamal-proof/src/lib.rs#L101-L102 */
    fd_guarded_borrowed_account_t proof_context_acc = {0};
    FD_TRY_BORROW_INSTR_ACCOUNT_DEFAULT_ERR_CHECK( ctx, accessed_accounts, &proof_context_acc );

    /* https://github.com/anza-xyz/agave/blob/v2.0.1/programs/zk-elgamal-proof/src/lib.rs#L103-L105 */
    if( FD_UNLIKELY( !fd_memeq( fd_borrowed_account_get_owner( &proof_context_acc ), &fd_solana_zk_elgamal_proof_program_id, sizeof(fd_pubkey_t) ) ) ) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_OWNER;
    }

    /* https://github.com/anza-xyz/agave/blob/v2.0.1/programs/zk-elgamal-proof/src/lib.rs#L107-L112 */
    if( FD_UNLIKELY( fd_borrowed_account_get_data_len( &proof_context_acc ) >= CTX_HEAD_SZ && fd_borrowed_account_get_data( &proof_context_acc )[32] != 0 ) ) {
      return FD_EXECUTOR_INSTR_ERR_ACC_ALREADY_INITIALIZED;
    }

    /* https://github.com/anza-xyz/agave/blob/v2.0.1/programs/zk-elgamal-proof/src/lib.rs#L114-L115
        Note: nothing to do. */

    /* https://github.com/anza-xyz/agave/blob/v2.0.1/programs/zk-elgamal-proof/src/lib.rs#L117-L119 */
    ulong context_data_sx = CTX_HEAD_SZ + context_sz;
    if( FD_UNLIKELY( fd_borrowed_account_get_data_len( &proof_context_acc ) != context_data_sx ) ) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
    }

    /* Check writability for any account that passes validation.
       Even with just 1 account, if it passes owner and data checks, it must be writable.
       https://github.com/anza-xyz/agave/blob/v3.1.0-beta.0/programs/zk-elgamal-proof/src/lib.rs#L112-L113 */
    if( FD_UNLIKELY( !fd_instr_acc_is_writable_idx( ctx->instr, accessed_accounts ) ) ) {
      return FD_EXECUTOR_INSTR_ERR_READONLY_DATA_MODIFIED;
    }

    /* https://github.com/anza-xyz/agave/blob/v2.0.1/programs/zk-elgamal-proof/src/lib.rs#L121 */
    fd_memcpy( buffer, context_state_authority, sizeof(fd_pubkey_t) ); // buffer[0..31]
    buffer[ 32 ] = instr_id;                                           // buffer[32]
    if( ctx->instr->data_sz != 5UL ) {                                  // buffer[33..]
      fd_memcpy( buffer+CTX_HEAD_SZ, context, context_sz );
    }
    err = fd_borrowed_account_set_data_from_slice( &proof_context_acc, buffer, context_data_sx );
    if( FD_UNLIKELY( err ) ) {
      return err;
    }
  }

  return FD_EXECUTOR_INSTR_SUCCESS;
}
