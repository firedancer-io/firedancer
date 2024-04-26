#include "fd_system_program.h"
#include "../fd_account.h"
#include "../fd_acc_mgr.h"
#include "../fd_system_ids.h"
#include "../context/fd_exec_slot_ctx.h"
#include "../context/fd_exec_txn_ctx.h"
#include "../sysvar/fd_sysvar_rent.h"

static int
require_acct( fd_exec_instr_ctx_t * ctx,
              ulong                 idx,
              fd_pubkey_t const *   pubkey ) {

  /* https://github.com/solana-labs/solana/blob/v1.17.23/program-runtime/src/sysvar_cache.rs#L228-L229 */

  if( FD_UNLIKELY( ctx->instr->acct_cnt <= idx ) )
    return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;

  /* https://github.com/solana-labs/solana/blob/v1.17.23/program-runtime/src/sysvar_cache.rs#L230-L232 */

  if( FD_UNLIKELY( 0!=memcmp( ctx->instr->acct_pubkeys[idx].uc, pubkey->uc, sizeof(fd_pubkey_t) ) ) )
    return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;

  return FD_EXECUTOR_INSTR_SUCCESS;
}

static int
require_acct_rent( fd_exec_instr_ctx_t * ctx,
                   ulong                 idx,
                   fd_rent_t const **    out_rent ) {

  do {
    int err = require_acct( ctx, idx, &fd_sysvar_rent_id );
    if( FD_UNLIKELY( err ) ) return err;
  } while(0);

  fd_rent_t const * rent = fd_sysvar_cache_rent( ctx->slot_ctx->sysvar_cache );
  if( FD_UNLIKELY( !rent ) )
    return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR;

  *out_rent = rent;
  return FD_EXECUTOR_INSTR_SUCCESS;
}

static int
require_acct_recent_blockhashes(
  fd_exec_instr_ctx_t *             ctx,
  ulong                             idx,
  fd_recent_block_hashes_t const ** out ) {

  do {
    int err = require_acct( ctx, idx, &fd_sysvar_recent_block_hashes_id );
    if( FD_UNLIKELY( err ) ) return err;
  } while(0);

  fd_recent_block_hashes_t const * rbh = fd_sysvar_cache_recent_block_hashes( ctx->slot_ctx->sysvar_cache );
  if( FD_UNLIKELY( !rbh ) )
    return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR;

  *out = rbh;
  return FD_EXECUTOR_INSTR_SUCCESS;
}

/* most_recent_block_hash mirrors
   solana_runtime::bank::Bank::last_blockhash_and_lamports_per_signature

   https://github.com/solana-labs/solana/blob/v1.17.23/runtime/src/bank.rs#L4033-L4040 */

static int
most_recent_block_hash( fd_exec_instr_ctx_t * ctx,
                        fd_hash_t *           out ) {

  fd_block_block_hash_entry_t * hashes = ctx->slot_ctx->slot_bank.recent_block_hashes.hashes;
  if( deq_fd_block_block_hash_entry_t_empty( hashes ) ) {
    ctx->txn_ctx->custom_err = 6;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  *out = deq_fd_block_block_hash_entry_t_peek_head_const( hashes )->blockhash;
  return FD_EXECUTOR_INSTR_SUCCESS;
}

static void
fd_durable_nonce_from_blockhash( fd_hash_t *       out,
                                 fd_hash_t const * blockhash ) {
  uchar buf[45];
  memcpy( buf,    "DURABLE_NONCE", 13UL );
  memcpy( buf+13, blockhash,       32UL );
  fd_sha256_hash( buf, sizeof(buf), out );
}

/* fd_system_program_set_nonce_state is a helper for updating the
   contents of a nonce account.

   Matches solana_sdk::transaction_context::BorrowedAccount::set_state
   https://github.com/solana-labs/solana/blob/v1.17.23/sdk/src/transaction_context.rs#L1020-L1029 */

static int
fd_system_program_set_nonce_state( fd_exec_instr_ctx_t *             ctx,
                                   ulong                             acct_idx,
                                   fd_nonce_state_versions_t const * new_state ) {

  /* https://github.com/solana-labs/solana/blob/v1.17.23/sdk/src/transaction_context.rs#L1021
     => https://github.com/solana-labs/solana/blob/v1.17.23/sdk/src/transaction_context.rs#L868 */

  do {
    int err = 99999;
    if( FD_UNLIKELY( !fd_account_can_data_be_changed( ctx->instr, acct_idx, &err ) ) )
      return err;
  } while(0);

  /* https://github.com/solana-labs/solana/blob/v1.17.23/sdk/src/transaction_context.rs#L1024-L1026 */

  fd_borrowed_account_t * account = NULL;
  do {
    int err = fd_instr_borrowed_account_modify_idx( ctx, acct_idx, 0UL, &account );
    if( FD_UNLIKELY( err ) ) FD_LOG_ERR(( "fd_instr_borrowed_account_modify_idx failed (%d-%s)", err, fd_acc_mgr_strerror( err ) ));
  } while(0);

  if( FD_UNLIKELY( fd_nonce_state_versions_size( new_state ) > account->meta->dlen ) )
    return FD_EXECUTOR_INSTR_ERR_ACC_DATA_TOO_SMALL;

  /* https://github.com/solana-labs/solana/blob/v1.17.23/sdk/src/transaction_context.rs#L1027 */

  do {
    fd_bincode_encode_ctx_t encode =
      { .data    = account->data,
        .dataend = account->data + account->meta->hlen };
    int err = fd_nonce_state_versions_encode( new_state, &encode );
    if( FD_UNLIKELY( err ) ) return FD_EXECUTOR_INSTR_ERR_GENERIC_ERR;
  } while(0);

  return FD_EXECUTOR_INSTR_SUCCESS;
}

/* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_instruction.rs#L20-L70

   Matches Solana Labs system_instruction::advance_nonce_account */

static int
fd_system_program_advance_nonce_account( fd_exec_instr_ctx_t *   ctx,
                                         fd_borrowed_account_t * account,
                                         ulong                   instr_acc_idx ) {

  /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_instruction.rs#L25-L32 */

  if( FD_UNLIKELY( !fd_instr_acc_is_writable_idx( ctx->instr, instr_acc_idx ) ) ) {
    /* TODO Log: "Authorize nonce account: Account {} must be writable" */
    return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
  }

  /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_instruction.rs#L34 */

  fd_nonce_state_versions_t versions[1] = {{0}};
  fd_bincode_decode_ctx_t decode =
    { .data    = account->const_data,
      .dataend = account->const_data + account->const_meta->dlen,
      .valloc  = fd_scratch_virtual() };
  if( FD_UNLIKELY( fd_nonce_state_versions_decode( versions, &decode )!=FD_BINCODE_SUCCESS ) )
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;

  /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_instruction.rs#L35 */

  fd_nonce_state_t * state = NULL;
  switch( versions->discriminant ) {
  case fd_nonce_state_versions_enum_legacy:
    state = &versions->inner.legacy;
    break;
  case fd_nonce_state_versions_enum_current:
    state = &versions->inner.current;
    break;
  default:
    __builtin_unreachable();
  }

  switch( state->discriminant ) {

  case fd_nonce_state_enum_initialized: {
    fd_nonce_data_t * data = &state->inner.initialized;

    /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_instruction.rs#L37-L44 */

    if( FD_UNLIKELY( !fd_instr_any_signed( ctx->instr, &data->authority ) ) ) {
      /* TODO Log: "Advance nonce account: Account {} must be a signer" */
      return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
    }

    /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_instruction.rs#L45 */

    fd_hash_t blockhash;
    do {
      int err = most_recent_block_hash( ctx, &blockhash );
      if( FD_UNLIKELY( err ) ) return err;
    } while(0);

    fd_hash_t next_durable_nonce;
    fd_durable_nonce_from_blockhash( &next_durable_nonce, &blockhash );

    /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_instruction.rs#L46-L52 */

    if( FD_UNLIKELY( 0==memcmp( data->durable_nonce.hash, next_durable_nonce.hash, sizeof(fd_hash_t) ) ) ) {
      /* TODO Log: "Advance nonce account: nonce can only advance once per slot" */
      ctx->txn_ctx->custom_err = FD_SYSTEM_PROGRAM_ERR_NONCE_BLOCKHASH_NOT_EXPIRED;
      return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
    }

    /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_instruction.rs#L54-L58 */

    fd_nonce_state_versions_t new_state = {
      .discriminant = fd_nonce_state_versions_enum_current,
      .inner = { .current = {
        .discriminant = fd_nonce_state_enum_initialized,
        .inner = { .initialized = {
          .authority      = data->authority,
          .durable_nonce  = next_durable_nonce,
          .fee_calculator = {
            .lamports_per_signature = ctx->slot_ctx->slot_bank.lamports_per_signature
          }
        } }
      } }
    };

    /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_instruction.rs#L59 */

    do {
      int err = fd_system_program_set_nonce_state( ctx, instr_acc_idx, &new_state );
      if( FD_UNLIKELY( err ) ) return err;
    } while(0);

    /* Mark this as a nonce account usage.  This prevents the account
       state from reverting in case the transaction fails. */

    ctx->txn_ctx->nonce_accounts[ ctx->instr->acct_txn_idxs[ instr_acc_idx ] ] = 1;

    break;
  }

  case fd_nonce_state_enum_uninitialized: {
    /* TODO Log: "Advance nonce account: Account {} state is invalid" */
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  }

  } /* switch */

  return FD_EXECUTOR_INSTR_SUCCESS;
}

/* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_processor.rs#L423-L441

   Matches Solana Labs system_processor SystemInstruction::AdvanceNonceAccount => { ... } */

int
fd_system_program_exec_advance_nonce_account( fd_exec_instr_ctx_t * ctx ) {

  /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_processor.rs#L423-L441 */

  if( FD_UNLIKELY( ctx->instr->acct_cnt < 1 ) )
    return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;

  /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_processor.rs#L425-L426 */

  uchar const             instr_acc_idx = 0;
  fd_borrowed_account_t * account = NULL;
  do {
    int err = fd_instr_borrowed_account_view_idx( ctx, instr_acc_idx, &account );
    if( FD_UNLIKELY( err ) ) FD_LOG_ERR(( "fd_instr_borrowed_account_view_idx failed (%d-%s)", err, fd_acc_mgr_strerror( err ) ));
  } while(0);

  if( FD_UNLIKELY( !fd_borrowed_account_acquire_write( account ) ) )
    return FD_EXECUTOR_INSTR_ERR_ACC_BORROW_FAILED;

  /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_processor.rs#L427-L432 */

  fd_recent_block_hashes_t const * recent_blockhashes = NULL;
  do {
    int err = require_acct_recent_blockhashes( ctx, 1UL, &recent_blockhashes );
    if( FD_UNLIKELY( err ) ) return err;
  } while(0);

  fd_block_block_hash_entry_t const * hashes = recent_blockhashes->hashes;

  /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_processor.rs#L433-L439 */

  if( FD_UNLIKELY( deq_fd_block_block_hash_entry_t_empty( hashes ) ) ) {
    /* TODO Log: "Advance nonce account: recent blockhash list is empty" */
    ctx->txn_ctx->custom_err = FD_SYSTEM_PROGRAM_ERR_NONCE_NO_RECENT_BLOCKHASHES;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  int err = fd_system_program_advance_nonce_account( ctx, account, instr_acc_idx );

  /* Implicit drop */
  fd_borrowed_account_release_write( account );

  return err;
}

/* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_instruction.rs#L72-L151

   Matches Solana Labs system_instruction::withdraw_nonce_account */

static int
fd_system_program_withdraw_nonce_account( fd_exec_instr_ctx_t * ctx,
                                          ulong                 requested_lamports,
                                          fd_rent_t const *     rent ) {

  ulong const from_acct_idx = 0UL;
  ulong const to_acct_idx   = 1UL;

  /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_instruction.rs#L82-L83 */

  fd_borrowed_account_t * from = NULL;
  do {
    int err = fd_instr_borrowed_account_view_idx( ctx, from_acct_idx, &from );
    if( FD_UNLIKELY( err ) ) FD_LOG_ERR(( "fd_instr_borrowed_account_view_idx failed (%d-%s)", err, fd_acc_mgr_strerror( err ) ));
  } while(0);

  if( FD_UNLIKELY( !fd_borrowed_account_acquire_write( from ) ) )
    return FD_EXECUTOR_INSTR_ERR_ACC_BORROW_FAILED;

  /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_instruction.rs#L84-L91 */

  if( FD_UNLIKELY( !fd_instr_acc_is_writable_idx( ctx->instr, 0 ) ) ) {
    /* TODO Log: "Withdraw nonce account: Account {} must be writeable" */
    return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
  }

  /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_instruction.rs#L93 */

  fd_nonce_state_versions_t versions[1] = {{0}};
  fd_bincode_decode_ctx_t decode =
    { .data    = from->const_data,
      .dataend = from->const_data + from->const_meta->dlen,
      .valloc  = fd_scratch_virtual() };
  if( FD_UNLIKELY( fd_nonce_state_versions_decode( versions, &decode )!=FD_BINCODE_SUCCESS ) )
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;

  /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_instruction.rs#L94 */

  fd_nonce_state_t * state = NULL;
  switch( versions->discriminant ) {
  case fd_nonce_state_versions_enum_legacy:
    state = &versions->inner.legacy;
    break;
  case fd_nonce_state_versions_enum_current:
    state = &versions->inner.current;
    break;
  default:
    __builtin_unreachable();
  }

  fd_pubkey_t signer[1] = {0};
  switch( state->discriminant ) {

  case fd_nonce_state_enum_uninitialized: {
    /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_instruction.rs#L95-L106 */

    if( FD_UNLIKELY( requested_lamports > from->const_meta->info.lamports ) ) {
      /* TODO Log: "Withdraw nonce account: insufficient lamports {}, need {}" */
      return FD_EXECUTOR_INSTR_ERR_INSUFFICIENT_FUNDS;
    }

    /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_instruction.rs#L105 */

    *signer = *from->pubkey;

    break;
  }

  case fd_nonce_state_enum_initialized: {
    /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_instruction.rs#L107-L132 */
    fd_nonce_data_t * data = &state->inner.initialized;

    if( requested_lamports == from->const_meta->info.lamports ) {
        /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_instruction.rs#L108-L117 */

      /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_instruction.rs#L109 */

      fd_hash_t blockhash;
      do {
        int err = most_recent_block_hash( ctx, &blockhash );
        if( FD_UNLIKELY( err ) ) return err;
      } while(0);

      fd_hash_t next_durable_nonce;
      fd_durable_nonce_from_blockhash( &next_durable_nonce, &blockhash );

      /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_instruction.rs#L110-L116 */

      if( FD_UNLIKELY( 0==memcmp( data->durable_nonce.hash, next_durable_nonce.hash, sizeof(fd_hash_t) ) ) ) {
        /* TODO Log: "Advance nonce account: nonce can only advance once per slot" */
        ctx->txn_ctx->custom_err = FD_SYSTEM_PROGRAM_ERR_NONCE_BLOCKHASH_NOT_EXPIRED;
        return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
      }

      /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_instruction.rs#L117 */

      fd_nonce_state_versions_t new_state[1] = {{
        .discriminant = fd_nonce_state_versions_enum_current,
        .inner = { .current = {
          .discriminant = fd_nonce_state_enum_uninitialized
        } }
      }};

      do {
        int err = fd_system_program_set_nonce_state( ctx, from_acct_idx, new_state );
        if( FD_UNLIKELY( err ) ) return err;
      } while(0);

    } else {
        /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_instruction.rs#L118-L130 */

      /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_instruction.rs#L120 */

      ulong min_balance = fd_rent_exempt_minimum_balance2( rent, from->const_meta->dlen );

      ulong amount;
      if( FD_UNLIKELY( __builtin_uaddl_overflow( requested_lamports, min_balance, &amount ) ) )
        return FD_EXECUTOR_INSTR_ERR_INSUFFICIENT_FUNDS;

      /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_instruction.rs#L121-L129 */

      if( FD_UNLIKELY( amount > from->const_meta->info.lamports ) ) {
        /* TODO Log: "Withdraw nonce account: insufficient lamports {}, need {}" */
        return FD_EXECUTOR_INSTR_ERR_INSUFFICIENT_FUNDS;
      }

    }

    /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_instruction.rs#L131 */

    *signer = data->authority;

    break;
  }

  } /* switch */

  /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_instruction.rs#L135-L142 */

  if( FD_UNLIKELY( !fd_instr_any_signed( ctx->instr, signer ) ) ) {
    /* TODO Log: "Withdraw nonce account: Account {} must sign" */
    return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
  }

  /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_instruction.rs#L144 */

  do {
    /* TODO verify that account is writable before calling this API */
    int err = fd_account_checked_sub_lamports( ctx, from_acct_idx, requested_lamports );
    if( FD_UNLIKELY( err ) ) return err;
  } while(0);

  /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_instruction.rs#L145 */

  fd_borrowed_account_release_write( from );

  /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_instruction.rs#L146-L147 */

  fd_borrowed_account_t * to = NULL;
  do {
    int err = fd_instr_borrowed_account_modify_idx( ctx, to_acct_idx, 0UL, &to );
    if( FD_UNLIKELY( err ) ) FD_LOG_ERR(( "fd_instr_borrowed_account_modify_idx failed (%d-%s)", err, fd_acc_mgr_strerror( err ) ));
  } while(0);

  if( FD_UNLIKELY( !fd_borrowed_account_acquire_write( to ) ) )
    return FD_EXECUTOR_INSTR_ERR_ACC_BORROW_FAILED;

  /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_instruction.rs#L148 */

  do {
    int err = fd_account_checked_add_lamports( ctx, to_acct_idx, requested_lamports );
    if( FD_UNLIKELY( err ) ) return err;
  } while(0);

  /* Implicit drop */
  fd_borrowed_account_release_write( to );

  return FD_EXECUTOR_INSTR_SUCCESS;
}

/* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_processor.rs#L442-L461

   Matches Solana Labs system_processor SystemInstruction::WithdrawNonceAccount { ... } => { ... } */

int
fd_system_program_exec_withdraw_nonce_account( fd_exec_instr_ctx_t * ctx,
                                               ulong                 requested_lamports ) {

  /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_processor.rs#L443 */

  if( FD_UNLIKELY( ctx->instr->acct_cnt < 2 ) )
    return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;

  /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_processor.rs#L445-L449 */

  fd_recent_block_hashes_t const * recent_blockhashes = NULL;
  do {
    int err = require_acct_recent_blockhashes( ctx, 2UL, &recent_blockhashes );
    if( FD_UNLIKELY( err ) ) return err;
  } while(0);

  /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_processor.rs#L450 */

  fd_rent_t const * rent = NULL;
  do {
    int err = require_acct_rent( ctx, 3UL, &rent );
    if( FD_UNLIKELY( err ) ) return err;
  } while(0);

  /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_processor.rs#L451-L460 */

  return fd_system_program_withdraw_nonce_account( ctx, requested_lamports, rent );
}

/* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_instruction.rs#L153-L198

   Matches Solana Labs system_instruction::initialize_nonce_account */

static int
fd_system_program_initialize_nonce_account( fd_exec_instr_ctx_t *   ctx,
                                            fd_borrowed_account_t * account,
                                            ulong                   instr_acc_idx,
                                            fd_pubkey_t const *     authorized,
                                            fd_rent_t const *       rent ) {

  /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_instruction.rs#L159-L166 */

  if( FD_UNLIKELY( !fd_instr_acc_is_writable_idx( ctx->instr, instr_acc_idx ) ) ) {
    /* TODO Log: "Initialize nonce account: Account {} must be writeable" */
    return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
  }

  /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_instruction.rs#L168 */

  fd_nonce_state_versions_t versions[1] = {{0}};
  fd_bincode_decode_ctx_t decode =
    { .data    = account->const_data,
      .dataend = account->const_data + account->const_meta->dlen,
      .valloc  = fd_scratch_virtual() };
  if( FD_UNLIKELY( fd_nonce_state_versions_decode( versions, &decode )!=FD_BINCODE_SUCCESS ) )
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;

  fd_nonce_state_t * state = NULL;
  switch( versions->discriminant ) {
  case fd_nonce_state_versions_enum_legacy:
    state = &versions->inner.legacy;
    break;
  case fd_nonce_state_versions_enum_current:
    state = &versions->inner.current;
    break;
  default:
    __builtin_unreachable();
  }

  switch( state->discriminant ) {

  case fd_nonce_state_enum_uninitialized: {
    /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_instruction.rs#L169-L188 */

    /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_instruction.rs#L170 */

    ulong min_balance = fd_rent_exempt_minimum_balance2( rent, account->const_meta->dlen );

    /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_instruction.rs#L171-L179 */

    if( FD_UNLIKELY( account->const_meta->info.lamports < min_balance ) ) {
      /* TODO Log: "Initialize nonce account: insufficient lamports {}, need {}" */
      return FD_EXECUTOR_INSTR_ERR_INSUFFICIENT_FUNDS;
    }

    /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_instruction.rs#L180 */

    fd_hash_t blockhash;
    do {
      int err = most_recent_block_hash( ctx, &blockhash );
      if( FD_UNLIKELY( err ) ) return err;
    } while(0);

    fd_hash_t durable_nonce;
    fd_durable_nonce_from_blockhash( &durable_nonce, &blockhash );

    /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_instruction.rs#L181-L186 */

    fd_nonce_state_versions_t new_state = {
      .discriminant = fd_nonce_state_versions_enum_current,
      .inner = { .current = {
        .discriminant = fd_nonce_state_enum_initialized,
        .inner = { .initialized = {
          .authority      = *authorized,
          .durable_nonce  = durable_nonce,
          .fee_calculator = {
            .lamports_per_signature = ctx->slot_ctx->slot_bank.lamports_per_signature
          }
        } }
      } }
    };

    /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_instruction.rs#L187 */

    do {
      int err = fd_system_program_set_nonce_state( ctx, instr_acc_idx, &new_state );
      if( FD_UNLIKELY( err ) ) return err;
    } while(0);

    break;
  }

  case fd_nonce_state_enum_initialized: {
    /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_instruction.rs#L189-L196 */

    /* TODO Log: "Initialize nonce account: Account {} state is invalid" */
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  }

  } /* switch */

  return FD_EXECUTOR_INSTR_SUCCESS;
}

/* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_processor.rs#L462-L481

   Matches Solana Labs system_processor SystemInstruction::InitializeNonceAccount { ... } => { ... } */

int
fd_system_program_exec_initialize_nonce_account( fd_exec_instr_ctx_t * ctx,
                                                 fd_pubkey_t const *   authorized ) {

  /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_processor.rs#L463 */

  if( FD_UNLIKELY( ctx->instr->acct_cnt < 1 ) )
    return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;

  /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_processor.rs#L464-L465 */

  uchar const             instr_acc_idx = 0;
  fd_borrowed_account_t * account       = NULL;
  do {
    int err = fd_instr_borrowed_account_view_idx( ctx, instr_acc_idx, &account );
    if( FD_UNLIKELY( err ) ) FD_LOG_ERR(( "fd_instr_borrowed_account_view_idx failed (%d-%s)", err, fd_acc_mgr_strerror( err ) ));
  } while(0);

  if( FD_UNLIKELY( !fd_borrowed_account_acquire_write( account ) ) )
    return FD_EXECUTOR_INSTR_ERR_ACC_BORROW_FAILED;

  /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_processor.rs#L466-L471 */

  fd_recent_block_hashes_t const * recent_blockhashes = NULL;
  do {
    int err = require_acct_recent_blockhashes( ctx, 1UL, &recent_blockhashes );
    if( FD_UNLIKELY( err ) ) return err;
  } while(0);

  fd_block_block_hash_entry_t const * hashes = recent_blockhashes->hashes;

  /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_processor.rs#L472-L478 */

  if( FD_UNLIKELY( deq_fd_block_block_hash_entry_t_empty( hashes ) ) ) {
    /* TODO Log: "Initialize nonce account: recent blockhash list is empty" */
    ctx->txn_ctx->custom_err = FD_SYSTEM_PROGRAM_ERR_NONCE_NO_RECENT_BLOCKHASHES;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_processor.rs#L479 */

  fd_rent_t const * rent = NULL;
  do {
    int err = require_acct_rent( ctx, 2UL, &rent );
    if( FD_UNLIKELY( err ) ) return err;
  } while(0);

  /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_processor.rs#L480 */

  int err = fd_system_program_initialize_nonce_account( ctx, account, instr_acc_idx, authorized, rent );

  /* Implicit drop */
  fd_borrowed_account_release_write( account );

  return err;
}

/* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_instruction.rs#L200-L236

   Matches Solana Labs system_instruction::authorize_nonce_account */

static int
fd_system_program_authorize_nonce_account( fd_exec_instr_ctx_t *   ctx,
                                           fd_borrowed_account_t * account,
                                           ulong                   instr_acc_idx,
                                           fd_pubkey_t const *     nonce_authority ) {

  /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_instruction.rs#L206-L213 */

  if( FD_UNLIKELY( !fd_instr_acc_is_writable_idx( ctx->instr, instr_acc_idx ) ) ) {
    /* TODO Log: "Authorize nonce account: Account {} must be writable" */
    return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
  }

  /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_instruction.rs#L214-L215 */

  fd_nonce_state_versions_t versions[1] = {{0}};
  fd_bincode_decode_ctx_t decode =
    { .data    = account->const_data,
      .dataend = account->const_data + account->const_meta->dlen,
      .valloc  = fd_scratch_virtual() };
  if( FD_UNLIKELY( fd_nonce_state_versions_decode( versions, &decode )!=FD_BINCODE_SUCCESS ) )
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;

  /* Inlining solana_program::nonce::state::Versions::authorize
     https://github.com/solana-labs/solana/blob/v1.17.23/sdk/program/src/nonce/state/mod.rs#L76-L102 */

  /* https://github.com/solana-labs/solana/blob/v1.17.23/sdk/program/src/nonce/state/mod.rs#L81 */

  fd_nonce_state_t * state = NULL;
  switch( versions->discriminant ) {
  case fd_nonce_state_versions_enum_legacy:
    state = &versions->inner.legacy;
    break;
  case fd_nonce_state_versions_enum_current:
    state = &versions->inner.current;
    break;
  default:
    __builtin_unreachable();
  }

  /* https://github.com/solana-labs/solana/blob/v1.17.23/sdk/program/src/nonce/state/mod.rs#L81-L84 */

  if( FD_UNLIKELY( state->discriminant != fd_nonce_state_enum_initialized ) ) {
    /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_instruction.rs#L219-L226 */

    /* TODO Log: "Authorize nonce account: Account {} state is invalid" */
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  }

  fd_nonce_data_t * data = &state->inner.initialized;

  /* https://github.com/solana-labs/solana/blob/v1.17.23/sdk/program/src/nonce/state/mod.rs#L85-L89 */

  if( FD_UNLIKELY( !fd_instr_any_signed( ctx->instr, &data->authority ) ) ) {
    /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_instruction.rs#L227-L234 */

    /* TODO Log: "Authorize nonce account: Account {} must sign" */
    return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
  }

  /* https://github.com/solana-labs/solana/blob/v1.17.23/sdk/program/src/nonce/state/mod.rs#L90-L95 */

  fd_nonce_state_t new_state[1] = {{
    .discriminant = fd_nonce_state_enum_initialized,
    .inner = { .initialized = {
      .authority      = *nonce_authority,
      .durable_nonce  = data->durable_nonce,
      .fee_calculator = data->fee_calculator
    } }
  }};

  /* https://github.com/solana-labs/solana/blob/v1.17.23/sdk/program/src/nonce/state/mod.rs#L96-L101 */

  fd_nonce_state_versions_t new_versioned[1] = {{0}};
  new_versioned->discriminant = versions->discriminant;
  switch( versions->discriminant ) {
  case fd_nonce_state_versions_enum_legacy:
    new_versioned->inner.legacy = *new_state;
    break;
  case fd_nonce_state_versions_enum_current:
    new_versioned->inner.current = *new_state;
    break;
  default:
    __builtin_unreachable();
  }

  /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_instruction.rs#L218 */

  do {
    int err = fd_system_program_set_nonce_state( ctx, instr_acc_idx, new_versioned );
    if( FD_UNLIKELY( err ) ) return err;
  } while(0);

  return FD_EXECUTOR_INSTR_SUCCESS;
}

/* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_processor.rs#L482-L487

   Matches Solana Labs system_processor SystemInstruction::AuthorizeNonceAccount { ... } => { ... } */

int
fd_system_program_exec_authorize_nonce_account( fd_exec_instr_ctx_t * ctx,
                                                fd_pubkey_t const *   nonce_authority ) {

  /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_processor.rs#L483 */

  if( FD_UNLIKELY( ctx->instr->acct_cnt < 1 ) )
    return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;

  /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_processor.rs#L484-L485 */

  fd_borrowed_account_t * account = NULL;
  do {
    int err = fd_instr_borrowed_account_view_idx( ctx, 0, &account );
    if( FD_UNLIKELY( err ) ) FD_LOG_ERR(( "fd_instr_borrowed_account_view_idx failed (%d-%s)", err, fd_acc_mgr_strerror( err ) ));
  } while(0);

  if( FD_UNLIKELY( !fd_borrowed_account_acquire_write( account ) ) )
    return FD_EXECUTOR_INSTR_ERR_ACC_BORROW_FAILED;

  /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_processor.rs#L486 */

  int err = fd_system_program_authorize_nonce_account( ctx, account, 0UL, nonce_authority );

  /* Implicit drop */
  fd_borrowed_account_release_write( account );

  return err;
}

/* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_processor.rs#L488-L503

   Matches Solana Labs system_processor SystemInstruction::UpgradeNonceAccount { ... } => { ... } */

int
fd_system_program_exec_upgrade_nonce_account( fd_exec_instr_ctx_t * ctx ) {

  ulong const nonce_acct_idx = 0UL;

  /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_processor.rs#L489 */

  if( FD_UNLIKELY( ctx->instr->acct_cnt < 1 ) )
    return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;

  /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_processor.rs#L490-L491 */

  fd_borrowed_account_t * account = NULL;
  do {
    int err = fd_instr_borrowed_account_view_idx( ctx, nonce_acct_idx, &account );
    if( FD_UNLIKELY( err ) ) FD_LOG_ERR(( "fd_instr_borrowed_account_view_idx failed (%d-%s)", err, fd_acc_mgr_strerror( err ) ));
  } while(0);

  if( FD_UNLIKELY( !fd_borrowed_account_acquire_write( account ) ) )
    return FD_EXECUTOR_INSTR_ERR_ACC_BORROW_FAILED;

  /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_processor.rs#L492-L494 */

  if( FD_UNLIKELY( 0!=memcmp( account->const_meta->info.owner, fd_solana_system_program_id.key, sizeof(fd_pubkey_t) ) ) )
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_OWNER;

  /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_processor.rs#L495-L497 */

  if( FD_UNLIKELY( !fd_instr_acc_is_writable_idx( ctx->instr, 0 ) ) )
    return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;

  /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_processor.rs#L498 */

  fd_nonce_state_versions_t versions[1] = {{0}};
  fd_bincode_decode_ctx_t decode =
    { .data    = account->const_data,
      .dataend = account->const_data + account->const_meta->dlen,
      .valloc  = fd_scratch_virtual() };
  if( FD_UNLIKELY( fd_nonce_state_versions_decode( versions, &decode )!=FD_BINCODE_SUCCESS ) )
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;

  /* Inlining solana_program::nonce::state::Versions::upgrade
     https://github.com/solana-labs/solana/blob/v1.17.23/sdk/program/src/nonce/state/mod.rs#L55-L73 */

  if( FD_UNLIKELY( versions->discriminant != fd_nonce_state_versions_enum_legacy ) )
    return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;

  fd_nonce_state_t * state = &versions->inner.legacy;
  if( FD_UNLIKELY( state->discriminant != fd_nonce_state_enum_initialized ) )
    return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;

  fd_durable_nonce_from_blockhash( &state->inner.initialized.durable_nonce, &state->inner.initialized.durable_nonce );

  /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_processor.rs#L501 */

  fd_nonce_state_versions_t new_state[1] = {{
    .discriminant = fd_nonce_state_versions_enum_current,
    .inner = { .current = *state }
  }};

  do {
    int err = fd_system_program_set_nonce_state( ctx, nonce_acct_idx, new_state );
    if( FD_UNLIKELY( err ) ) return err;
  } while(0);

  /* Implicit drop */
  fd_borrowed_account_release_write( account );

  return FD_EXECUTOR_INSTR_SUCCESS;
}

int
fd_load_nonce_account( fd_exec_txn_ctx_t const *   txn_ctx,
                       fd_nonce_state_versions_t * state,
                       fd_valloc_t                 valloc,
                       int *                       perr ) {

  *perr = 0;

  fd_txn_t const *      txn_descriptor = txn_ctx->txn_descriptor;
  fd_rawtxn_b_t const * txn_raw        = txn_ctx->_txn_raw;

  if( txn_descriptor->instr_cnt == 0 ) {
    *perr = FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
    return 0;
  }

  fd_txn_instr_t const * txn_instr = &txn_descriptor->instr[0];

  if( FD_UNLIKELY( txn_instr->program_id >= txn_descriptor->acct_addr_cnt ) )
    return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;

  fd_acct_addr_t const * tx_accs = fd_txn_get_acct_addrs( txn_descriptor, txn_raw->raw );
  fd_acct_addr_t const * prog_id = tx_accs + txn_instr->program_id;

  if( memcmp( prog_id->b, fd_solana_system_program_id.key, sizeof( fd_pubkey_t ) ) ) {
    return 0;
  }

  uchar const * instr_data = fd_txn_get_instr_data( txn_instr, txn_raw->raw );
  uchar const * instr_acct_idxs = fd_txn_get_instr_accts( txn_instr, txn_raw->raw );

  if( FD_UNLIKELY(
      txn_instr->data_sz != 4UL ||
      FD_LOAD( uint, instr_data ) != (uint)fd_system_program_instruction_enum_advance_nonce_account ) ) {
    *perr = FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
    return 0;
  }

  if( FD_UNLIKELY( ( txn_descriptor->acct_addr_cnt < 1 ) |
                   ( txn_instr->acct_cnt < 1           ) ) ) {
    return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
  }  
  if( FD_UNLIKELY( instr_acct_idxs[0] >= txn_descriptor->acct_addr_cnt ) ) {
    *perr = FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
    return 0;
  }

  fd_acct_addr_t const * me = &tx_accs[ instr_acct_idxs[0] ];

  // https://github.com/firedancer-io/solana/blob/ffd63324f988e1b2151dab34983c71d6ff4087f6/runtime/src/nonce_keyed_account.rs#L66

  FD_BORROWED_ACCOUNT_DECL(me_rec);
  int err = fd_acc_mgr_view( txn_ctx->acc_mgr, txn_ctx->funk_txn, (fd_pubkey_t const *)me, me_rec );
  if( FD_UNLIKELY( err != FD_ACC_MGR_SUCCESS ) ) {

    *perr = FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
    return 0;
  }

  fd_bincode_decode_ctx_t decode = {
    .data    = me_rec->const_data,
    .dataend = me_rec->const_data + me_rec->const_meta->dlen,
    .valloc  = valloc
  };

  if( fd_nonce_state_versions_decode( state, &decode ) ) {
    *perr = FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
    return 0;
  }

  return 1;
}


int
fd_has_nonce_account( fd_exec_txn_ctx_t const *   txn_ctx,
                       int *                      perr ) {

  *perr = 0;

  fd_txn_t const *      txn_descriptor = txn_ctx->txn_descriptor;
  fd_rawtxn_b_t const * txn_raw        = txn_ctx->_txn_raw;

  if( txn_descriptor->instr_cnt == 0 ) {
    *perr = FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
    return 0;
  }

  fd_txn_instr_t const * txn_instr = &txn_descriptor->instr[0];

  if( FD_UNLIKELY( txn_instr->program_id >= txn_descriptor->acct_addr_cnt ) )
    return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;

  fd_acct_addr_t const * tx_accs = fd_txn_get_acct_addrs( txn_descriptor, txn_raw->raw );
  fd_acct_addr_t const * prog_id = tx_accs + txn_instr->program_id;

  if( memcmp( prog_id->b, fd_solana_system_program_id.key, sizeof( fd_pubkey_t ) ) ) {
    return 0;
  }

  uchar const * instr_data = fd_txn_get_instr_data( txn_instr, txn_raw->raw );
  uchar const * instr_acct_idxs = fd_txn_get_instr_accts( txn_instr, txn_raw->raw );

  if( FD_UNLIKELY(
      txn_instr->data_sz != 4UL ||
      FD_LOAD( uint, instr_data ) != (uint)fd_system_program_instruction_enum_advance_nonce_account ) ) {
    *perr = FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
    return 0;
  }

  if( FD_UNLIKELY( ( txn_descriptor->acct_addr_cnt < 1 ) |
                   ( txn_instr->acct_cnt < 1           ) ) ) {
    return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
  }  
  if( FD_UNLIKELY( instr_acct_idxs[0] >= txn_descriptor->acct_addr_cnt ) ) {
    *perr = FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
    return 0;
  }

  return 1;
}
