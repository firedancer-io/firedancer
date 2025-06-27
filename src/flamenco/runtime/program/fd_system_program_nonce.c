#include "fd_system_program.h"
#include "../fd_borrowed_account.h"
#include "../fd_acc_mgr.h"
#include "../fd_system_ids.h"
#include "../context/fd_exec_slot_ctx.h"
#include "../context/fd_exec_txn_ctx.h"
#include "../sysvar/fd_sysvar_rent.h"
#include "../sysvar/fd_sysvar_recent_hashes.h"
#include "../fd_executor.h"

static int
require_acct( fd_exec_instr_ctx_t * ctx,
              ushort                idx,
              fd_pubkey_t const *   pubkey ) {

  /* https://github.com/anza-xyz/agave/blob/v2.1.14/program-runtime/src/sysvar_cache.rs#L290-L294 */
  fd_pubkey_t const * acc_key = NULL;
  int err = fd_exec_instr_ctx_get_key_of_account_at_index( ctx, idx, &acc_key );
  if( FD_UNLIKELY( err ) ) return err;

  if( FD_UNLIKELY( 0!=memcmp( acc_key, pubkey->uc, sizeof(fd_pubkey_t) ) ) )
    return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;

  return FD_EXECUTOR_INSTR_SUCCESS;
}

static int
require_acct_rent( fd_exec_instr_ctx_t * ctx,
                   ushort                idx,
                   fd_rent_t const **    out_rent ) {

  do {
    int err = require_acct( ctx, idx, &fd_sysvar_rent_id );
    if( FD_UNLIKELY( err ) ) return err;
  } while(0);

  fd_rent_t const * rent = fd_sysvar_rent_read( ctx->txn_ctx->funk, ctx->txn_ctx->funk_txn, ctx->txn_ctx->spad );
  if( FD_UNLIKELY( !rent ) )
    return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR;

  *out_rent = rent;
  return FD_EXECUTOR_INSTR_SUCCESS;
}

static int
require_acct_recent_blockhashes( fd_exec_instr_ctx_t *        ctx,
                                 ushort                       idx,
                                 fd_recent_block_hashes_t * * out ) {

  do {
    int err = require_acct( ctx, idx, &fd_sysvar_recent_block_hashes_id );
    if( FD_UNLIKELY( err ) ) return err;
  } while(0);

  fd_recent_block_hashes_global_t const * rbh_global = fd_sysvar_recent_hashes_read( ctx->txn_ctx->funk, ctx->txn_ctx->funk_txn, ctx->txn_ctx->spad );
  if( FD_UNLIKELY( !rbh_global ) ) {
    return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR;
  }

  (*out)->hashes = deq_fd_block_block_hash_entry_t_join( (uchar*)rbh_global + rbh_global->hashes_offset );

  return FD_EXECUTOR_INSTR_SUCCESS;
}

/* most_recent_block_hash mirrors
   solana_runtime::bank::Bank::last_blockhash_and_lamports_per_signature

   https://github.com/solana-labs/solana/blob/v1.17.23/runtime/src/bank.rs#L4033-L4040 */

static int
most_recent_block_hash( fd_exec_instr_ctx_t * ctx,
                        fd_hash_t *           out ) {
  /* The environment config blockhash comes from `bank.last_blockhash_and_lamports_per_signature()`,
     which takes the top element from the blockhash queue.
     https://github.com/anza-xyz/agave/blob/v2.1.6/programs/system/src/system_instruction.rs#L47 */
  fd_block_hash_queue_global_t const * block_hash_queue = fd_bank_block_hash_queue_query( ctx->txn_ctx->bank );
  fd_hash_t const *                    last_hash        = fd_block_hash_queue_last_hash_join( block_hash_queue );
  if( FD_UNLIKELY( last_hash==NULL ) ) {
    // Agave panics if this blockhash was never set at the start of the txn batch
    ctx->txn_ctx->custom_err = FD_SYSTEM_PROGRAM_ERR_NONCE_NO_RECENT_BLOCKHASHES;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  *out = *last_hash;
  return FD_EXECUTOR_INSTR_SUCCESS;
}

static void
fd_durable_nonce_from_blockhash( fd_hash_t *       out,
                                 fd_hash_t const * blockhash ) {
  uchar buf[45];
  memcpy( buf,    "DURABLE_NONCE", 13UL );
  memcpy( buf+13, blockhash,       sizeof(fd_hash_t) );
  fd_sha256_hash( buf, sizeof(buf), out );
}

/* fd_system_program_set_nonce_state is a helper for updating the
   contents of a nonce account.

   Matches solana_sdk::transaction_context::BorrowedAccount::set_state
   https://github.com/solana-labs/solana/blob/v1.17.23/sdk/src/transaction_context.rs#L1020-L1029 */

static int
fd_system_program_set_nonce_state( fd_borrowed_account_t *           account,
                                   fd_nonce_state_versions_t const * new_state ) {

  /* https://github.com/solana-labs/solana/blob/v1.17.23/sdk/src/transaction_context.rs#L1021
     => https://github.com/solana-labs/solana/blob/v1.17.23/sdk/src/transaction_context.rs#L868 */

  uchar * data = NULL;
  ulong   dlen = 0UL;
  int err = fd_borrowed_account_get_data_mut( account, &data, &dlen );
  if( FD_UNLIKELY( err ) ) return err;

  /* https://github.com/solana-labs/solana/blob/v1.17.23/sdk/src/transaction_context.rs#L1024-L1026 */

  if( FD_UNLIKELY( fd_nonce_state_versions_size( new_state ) > fd_borrowed_account_get_data_len( account ) ) )
    return FD_EXECUTOR_INSTR_ERR_ACC_DATA_TOO_SMALL;

  /* https://github.com/solana-labs/solana/blob/v1.17.23/sdk/src/transaction_context.rs#L1027 */

  do {
    fd_bincode_encode_ctx_t encode =
      { .data    = data,
        .dataend = data + dlen };
    int err = fd_nonce_state_versions_encode( new_state, &encode );
    if( FD_UNLIKELY( err ) ) {
      return FD_EXECUTOR_INSTR_ERR_GENERIC_ERR;
    }
  } while(0);

  return FD_EXECUTOR_INSTR_SUCCESS;
}

/* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_instruction.rs#L20-L70

   Matches Solana Labs system_instruction::advance_nonce_account */

static int
fd_system_program_advance_nonce_account( fd_exec_instr_ctx_t *   ctx,
                                         fd_borrowed_account_t * account,
                                         ushort                  instr_acc_idx ) {

  /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_instruction.rs#L25-L32 */

  if( FD_UNLIKELY( !fd_instr_acc_is_writable_idx( ctx->instr, instr_acc_idx ) ) ) {
    /* Max msg_sz: 50 - 2 + 45 = 93 < 127 => we can use printf */
    fd_log_collector_printf_dangerous_max_127( ctx,
      "Advance nonce account: Account %s must be writeable", FD_BASE58_ENC_32_ALLOCA( account->acct->pubkey) );
    return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
  }

  /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_instruction.rs#L34 */

  int err;
  fd_nonce_state_versions_t * versions = fd_bincode_decode_spad(
      nonce_state_versions, ctx->txn_ctx->spad,
      fd_borrowed_account_get_data( account ),
      fd_borrowed_account_get_data_len( account ),
      &err );
  if( FD_UNLIKELY( err ) ) return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;

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

    if( FD_UNLIKELY( !fd_exec_instr_ctx_any_signed( ctx, &data->authority ) ) ) {
      /* Max msg_sz: 50 - 2 + 45 = 93 < 127 => we can use printf */
      fd_log_collector_printf_dangerous_max_127( ctx,
        "Advance nonce account: Account %s must be a signer", FD_BASE58_ENC_32_ALLOCA( &data->authority ) );
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
      fd_log_collector_msg_literal( ctx, "Advance nonce account: nonce can only advance once per slot" );
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
            .lamports_per_signature = fd_bank_prev_lamports_per_signature_get( ctx->txn_ctx->bank )
          }
        } }
      } }
    };

    /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_instruction.rs#L59 */

    do {
      int err = fd_system_program_set_nonce_state( account, &new_state );
      if( FD_UNLIKELY( err ) ) return err;
    } while(0);

    break;
  }

  case fd_nonce_state_enum_uninitialized: {
    /* Max msg_sz: 50 - 2 + 45 = 93 < 127 => we can use printf */
    fd_log_collector_printf_dangerous_max_127( ctx,
      "Advance nonce account: Account %s state is invalid", FD_BASE58_ENC_32_ALLOCA( account->acct->pubkey ) );
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  }

  } /* switch */

  return FD_EXECUTOR_INSTR_SUCCESS;
}

/* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_processor.rs#L423-L441

   Matches Solana Labs system_processor SystemInstruction::AdvanceNonceAccount => { ... } */

int
fd_system_program_exec_advance_nonce_account( fd_exec_instr_ctx_t * ctx ) {
  int err;
  /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_processor.rs#L423-L441 */

  if( FD_UNLIKELY( ctx->instr->acct_cnt < 1 ) )
    return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;

  /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_processor.rs#L425-L426 */

  uchar const             instr_acc_idx = 0;

  /* https://github.com/anza-xyz/agave/blob/v2.1.14/programs/system/src/system_processor.rs#L409-L410 */

  fd_guarded_borrowed_account_t account;
  FD_TRY_BORROW_INSTR_ACCOUNT_DEFAULT_ERR_CHECK( ctx, instr_acc_idx, &account );

  /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_processor.rs#L427-L432 */

  fd_recent_block_hashes_t   recent_blockhashes_obj;
  fd_recent_block_hashes_t * recent_blockhashes = &recent_blockhashes_obj;
  do {
    err = require_acct_recent_blockhashes( ctx, 1UL, &recent_blockhashes );
    if( FD_UNLIKELY( err ) ) return err;
  } while(0);

  fd_block_block_hash_entry_t const * hashes = recent_blockhashes->hashes;

  /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_processor.rs#L433-L439 */

  if( FD_UNLIKELY( deq_fd_block_block_hash_entry_t_empty( hashes ) ) ) {
    fd_log_collector_msg_literal( ctx, "Advance nonce account: recent blockhash list is empty" );
    ctx->txn_ctx->custom_err = FD_SYSTEM_PROGRAM_ERR_NONCE_NO_RECENT_BLOCKHASHES;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  err = fd_system_program_advance_nonce_account( ctx, &account, instr_acc_idx );

  /* Implicit drop */

  return err;
}

/* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_instruction.rs#L72-L151

   Matches Solana Labs system_instruction::withdraw_nonce_account */

static int
fd_system_program_withdraw_nonce_account( fd_exec_instr_ctx_t * ctx,
                                          ulong                 requested_lamports,
                                          fd_rent_t const *     rent ) {
  int err;
  ushort const from_acct_idx = 0UL;
  ushort const to_acct_idx   = 1UL;

  /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_instruction.rs#L82-L83 */

  fd_guarded_borrowed_account_t from;
  FD_TRY_BORROW_INSTR_ACCOUNT_DEFAULT_ERR_CHECK( ctx, from_acct_idx, &from );

  /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_instruction.rs#L84-L91 */

  if( FD_UNLIKELY( !fd_instr_acc_is_writable_idx( ctx->instr, from_acct_idx ) ) ) {
    /* Max msg_sz: 51 - 2 + 45 = 94 < 127 => we can use printf */
    fd_log_collector_printf_dangerous_max_127( ctx,
      "Withdraw nonce account: Account %s must be writeable", FD_BASE58_ENC_32_ALLOCA( from.acct->pubkey ) );
    return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
  }

  /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_instruction.rs#L93 */

  fd_nonce_state_versions_t * versions = fd_bincode_decode_spad(
      nonce_state_versions, ctx->txn_ctx->spad,
      fd_borrowed_account_get_data( &from ),
      fd_borrowed_account_get_data_len( &from ),
      &err );
  if( FD_UNLIKELY( err ) ) return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;

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

    if( FD_UNLIKELY( requested_lamports > fd_borrowed_account_get_lamports( &from ) ) ) {
      /* Max msg_sz: 59 - 6 + 20 + 20 = 93 < 127 => we can use printf */
      fd_log_collector_printf_dangerous_max_127( ctx,
        "Withdraw nonce account: insufficient lamports %lu, need %lu", fd_borrowed_account_get_lamports( &from ), requested_lamports );
      return FD_EXECUTOR_INSTR_ERR_INSUFFICIENT_FUNDS;
    }

    /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_instruction.rs#L105 */

    *signer = *from.acct->pubkey;

    break;
  }

  case fd_nonce_state_enum_initialized: {
    /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_instruction.rs#L107-L132 */
    fd_nonce_data_t * data = &state->inner.initialized;

    if( requested_lamports == fd_borrowed_account_get_lamports( &from ) ) {
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
        fd_log_collector_msg_literal( ctx, "Withdraw nonce account: nonce can only advance once per slot" );
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
        int err = fd_system_program_set_nonce_state( &from, new_state );
        if( FD_UNLIKELY( err ) ) return err;
      } while(0);

    } else {
        /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_instruction.rs#L118-L130 */

      /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_instruction.rs#L120 */

      ulong min_balance = fd_rent_exempt_minimum_balance( rent, fd_borrowed_account_get_data_len( &from ) );

      ulong amount;
      if( FD_UNLIKELY( __builtin_uaddl_overflow( requested_lamports, min_balance, &amount ) ) )
        return FD_EXECUTOR_INSTR_ERR_INSUFFICIENT_FUNDS;

      /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_instruction.rs#L121-L129 */

      if( FD_UNLIKELY( amount > fd_borrowed_account_get_lamports( &from ) ) ) {
        /* Max msg_sz: 59 - 6 + 20 + 20 = 93 < 127 => we can use printf */
        fd_log_collector_printf_dangerous_max_127( ctx,
          "Withdraw nonce account: insufficient lamports %lu, need %lu", fd_borrowed_account_get_lamports( &from ), amount );
        return FD_EXECUTOR_INSTR_ERR_INSUFFICIENT_FUNDS;
      }

    }

    /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_instruction.rs#L131 */

    *signer = data->authority;

    break;
  }

  } /* switch */

  /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_instruction.rs#L135-L142 */

  if( FD_UNLIKELY( !fd_exec_instr_ctx_any_signed( ctx, signer ) ) ) {
    /* Max msg_sz: 44 - 2 + 45 = 87 < 127 => we can use printf */
    fd_log_collector_printf_dangerous_max_127( ctx,
      "Withdraw nonce account: Account %s must sign", FD_BASE58_ENC_32_ALLOCA( signer ) );
    return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
  }

  /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_instruction.rs#L144 */

  err = fd_borrowed_account_checked_sub_lamports( &from, requested_lamports );
  if( FD_UNLIKELY( err ) ) return err;

  /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_instruction.rs#L145 */

    fd_borrowed_account_drop( &from );

  /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_instruction.rs#L146-L147 */

  fd_guarded_borrowed_account_t to;
  FD_TRY_BORROW_INSTR_ACCOUNT_DEFAULT_ERR_CHECK( ctx, to_acct_idx, &to );

  /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_instruction.rs#L148 */

  err = fd_borrowed_account_checked_add_lamports( &to, requested_lamports );
  if( FD_UNLIKELY( err ) ) return err;

  /* Implicit drop */

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

  fd_recent_block_hashes_t   recent_blockhashes_obj;
  fd_recent_block_hashes_t * recent_blockhashes = &recent_blockhashes_obj;
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
                                            fd_pubkey_t const *     authorized,
                                            fd_rent_t const *       rent ) {

  /* https://github.com/anza-xyz/agave/blob/v2.2.0/programs/system/src/system_instruction.rs#L167-L174 */

  if( FD_UNLIKELY( !fd_borrowed_account_is_writable( account ) ) ) {
    /* Max msg_sz: 53 - 2 + 45 = 96 < 127 => we can use printf */
    fd_log_collector_printf_dangerous_max_127( ctx,
      "Initialize nonce account: Account %s must be writeable", FD_BASE58_ENC_32_ALLOCA( account->acct->pubkey ) );
    return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
  }

  /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_instruction.rs#L168 */

  int err;
  fd_nonce_state_versions_t * versions = fd_bincode_decode_spad(
      nonce_state_versions, ctx->txn_ctx->spad,
      fd_borrowed_account_get_data( account ),
      fd_borrowed_account_get_data_len( account ),
      &err );
  if( FD_UNLIKELY( err ) ) return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;

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

    ulong min_balance = fd_rent_exempt_minimum_balance( rent, fd_borrowed_account_get_data_len( account ) );

    /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_instruction.rs#L171-L179 */

    if( FD_UNLIKELY( fd_borrowed_account_get_lamports( account ) < min_balance ) ) {
      /* Max msg_sz: 61 - 6 + 20 + 20 = 95 < 127 => we can use printf */
      fd_log_collector_printf_dangerous_max_127( ctx,
        "Initialize nonce account: insufficient lamports %lu, need %lu", fd_borrowed_account_get_lamports( account ), min_balance );
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
            .lamports_per_signature = fd_bank_prev_lamports_per_signature_get( ctx->txn_ctx->bank )
          }
        } }
      } }
    };

    /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_instruction.rs#L187 */

    do {
      int err = fd_system_program_set_nonce_state( account, &new_state );
      if( FD_UNLIKELY( err ) ) return err;
    } while(0);

    break;
  }

  case fd_nonce_state_enum_initialized: {
    /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_instruction.rs#L189-L196 */

    /* Max msg_sz: 53 - 2 + 45 = 96 < 127 => we can use printf */
    fd_log_collector_printf_dangerous_max_127( ctx,
      "Initialize nonce account: Account %s state is invalid", FD_BASE58_ENC_32_ALLOCA( account->acct->pubkey ) );

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
  int err;
  /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_processor.rs#L463 */

  if( FD_UNLIKELY( ctx->instr->acct_cnt < 1 ) )
    return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;

  /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_processor.rs#L464-L465 */

  uchar const instr_acc_idx = 0;
  /* https://github.com/anza-xyz/agave/blob/v2.1.14/programs/system/src/system_processor.rs#L448-L449 */
  fd_guarded_borrowed_account_t account;
  FD_TRY_BORROW_INSTR_ACCOUNT_DEFAULT_ERR_CHECK( ctx, instr_acc_idx, &account );

  /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_processor.rs#L466-L471 */

  fd_recent_block_hashes_t   recent_blockhashes_obj;
  fd_recent_block_hashes_t * recent_blockhashes = &recent_blockhashes_obj;
  do {
    err = require_acct_recent_blockhashes( ctx, 1UL, &recent_blockhashes );
    if( FD_UNLIKELY( err ) ) return err;
  } while(0);

  fd_block_block_hash_entry_t const * hashes = recent_blockhashes->hashes;

  /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_processor.rs#L472-L478 */

  if( FD_UNLIKELY( deq_fd_block_block_hash_entry_t_empty( hashes ) ) ) {
    fd_log_collector_msg_literal( ctx, "Initialize nonce account: recent blockhash list is empty" );
    ctx->txn_ctx->custom_err = FD_SYSTEM_PROGRAM_ERR_NONCE_NO_RECENT_BLOCKHASHES;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_processor.rs#L479 */

  fd_rent_t const * rent = NULL;
  do {
    err = require_acct_rent( ctx, 2UL, &rent );
    if( FD_UNLIKELY( err ) ) return err;
  } while(0);

  /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_processor.rs#L480 */

  err = fd_system_program_initialize_nonce_account( ctx, &account, authorized, rent );

  /* Implicit drop */

  return err;
}

/* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_instruction.rs#L200-L236

   Matches Solana Labs system_instruction::authorize_nonce_account */

static int
fd_system_program_authorize_nonce_account( fd_exec_instr_ctx_t *   ctx,
                                           fd_borrowed_account_t * account,
                                           ushort                  instr_acc_idx,
                                           fd_pubkey_t const *     nonce_authority ) {

  /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_instruction.rs#L206-L213 */

  if( FD_UNLIKELY( !fd_instr_acc_is_writable_idx( ctx->instr, instr_acc_idx ) ) ) {
    /* Max msg_sz: 52 - 2 + 45 = 95 < 127 => we can use printf */
    fd_log_collector_printf_dangerous_max_127( ctx,
      "Authorize nonce account: Account %s must be writeable", FD_BASE58_ENC_32_ALLOCA( account->acct->pubkey ) );
    return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
  }

  /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_instruction.rs#L214-L215 */

  int err;
  fd_nonce_state_versions_t * versions = fd_bincode_decode_spad(
      nonce_state_versions, ctx->txn_ctx->spad,
      fd_borrowed_account_get_data( account ),
      fd_borrowed_account_get_data_len( account ),
      &err );
  if( FD_UNLIKELY( err ) ) return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;

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

    /* Max msg_sz: 52 - 2 + 45 = 95 < 127 => we can use printf */
    fd_log_collector_printf_dangerous_max_127( ctx,
      "Authorize nonce account: Account %s state is invalid", FD_BASE58_ENC_32_ALLOCA( account->acct->pubkey ) );

    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  }

  fd_nonce_data_t * data = &state->inner.initialized;

  /* https://github.com/solana-labs/solana/blob/v1.17.23/sdk/program/src/nonce/state/mod.rs#L85-L89 */

  if( FD_UNLIKELY( !fd_exec_instr_ctx_any_signed( ctx, &data->authority ) ) ) {
    /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_instruction.rs#L227-L234 */
    /* Max msg_sz: 45 - 2 + 45 = 88 < 127 => we can use printf */
    fd_log_collector_printf_dangerous_max_127( ctx,
      "Authorize nonce account: Account %s must sign", FD_BASE58_ENC_32_ALLOCA( &data->authority ) );
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
    int err = fd_system_program_set_nonce_state( account, new_versioned );
    if( FD_UNLIKELY( err ) ) return err;
  } while(0);

  return FD_EXECUTOR_INSTR_SUCCESS;
}

/* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_processor.rs#L482-L487

   Matches Solana Labs system_processor SystemInstruction::AuthorizeNonceAccount { ... } => { ... } */

int
fd_system_program_exec_authorize_nonce_account( fd_exec_instr_ctx_t * ctx,
                                                fd_pubkey_t const *   nonce_authority ) {
  int err;
  /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_processor.rs#L483 */

  if( FD_UNLIKELY( ctx->instr->acct_cnt < 1 ) )
    return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;

  /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_processor.rs#L484-L485 */

  fd_guarded_borrowed_account_t account;
  err = fd_exec_instr_ctx_try_borrow_instr_account( ctx, 0, &account );
  if( FD_UNLIKELY( err ) ) {
    return err;
  }

  /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_processor.rs#L486 */

  err = fd_system_program_authorize_nonce_account( ctx, &account, 0UL, nonce_authority );

  /* Implicit drop */

  return err;
}

/* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_processor.rs#L488-L503

   Matches Solana Labs system_processor SystemInstruction::UpgradeNonceAccount { ... } => { ... } */

int
fd_system_program_exec_upgrade_nonce_account( fd_exec_instr_ctx_t * ctx ) {
  int err;
  ushort const nonce_acct_idx = 0UL;

  /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_processor.rs#L489 */

  if( FD_UNLIKELY( ctx->instr->acct_cnt < 1 ) )
    return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;

  /* https://github.com/anza-xyz/agave/blob/v2.1.14/programs/system/src/system_processor.rs#L474-475 */

  fd_guarded_borrowed_account_t account;
  FD_TRY_BORROW_INSTR_ACCOUNT_DEFAULT_ERR_CHECK( ctx, nonce_acct_idx, &account );

  /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_processor.rs#L492-L494 */

  if( FD_UNLIKELY( 0!=memcmp( fd_borrowed_account_get_owner( &account ), fd_solana_system_program_id.key, sizeof(fd_pubkey_t) ) ) )
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_OWNER;

  /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_processor.rs#L495-L497 */

  if( FD_UNLIKELY( !fd_instr_acc_is_writable_idx( ctx->instr, 0 ) ) )
    return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;

  /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_processor.rs#L498 */

  fd_nonce_state_versions_t * versions = fd_bincode_decode_spad(
      nonce_state_versions, ctx->txn_ctx->spad,
      fd_borrowed_account_get_data( &account ),
      fd_borrowed_account_get_data_len( &account ),
      &err );
  if( FD_UNLIKELY( err ) ) return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;

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

  err = fd_system_program_set_nonce_state( &account, new_state );
  if( FD_UNLIKELY( err ) ) return err;

  /* Implicit drop */

  return FD_EXECUTOR_INSTR_SUCCESS;
}

/* https://github.com/anza-xyz/agave/blob/16de8b75ebcd57022409b422de557dd37b1de8db/runtime/src/bank.rs#L3529-L3554 */
/* The age of a transaction is valid under two conditions. The first is that
   the transactions blockhash is a recent blockhash (within 151) in the block
   hash queue. The other condition is that the transaction contains a valid
   nonce account. This is the case under several conditions. If neither
   condition is met then the transaction is invalid.
   Note: We check 151 and not 150 due to a known bug in agave. */
int
fd_check_transaction_age( fd_exec_txn_ctx_t * txn_ctx ) {
  fd_block_hash_queue_global_t const * block_hash_queue = fd_bank_block_hash_queue_query( txn_ctx->bank );
  fd_hash_t *                          last_blockhash   = fd_block_hash_queue_last_hash_join( block_hash_queue );

  /* check_transaction_age */
  fd_hash_t   next_durable_nonce   = {0};
  fd_durable_nonce_from_blockhash( &next_durable_nonce, last_blockhash );
  ushort      recent_blockhash_off = txn_ctx->txn_descriptor->recent_blockhash_off;
  fd_hash_t * recent_blockhash     = (fd_hash_t *)((uchar *)txn_ctx->_txn_raw->raw + recent_blockhash_off);

  /* https://github.com/anza-xyz/agave/blob/16de8b75ebcd57022409b422de557dd37b1de8db/runtime/src/bank.rs#L3538-L3542 */
  /* get_hash_info_if_valid. Check 151 hashes from the block hash queue and its
     age to see if it is valid. */

  if( fd_executor_is_blockhash_valid_for_age( block_hash_queue, recent_blockhash, FD_RECENT_BLOCKHASHES_MAX_ENTRIES ) ) {
    return FD_RUNTIME_EXECUTE_SUCCESS;
  }

  /* https://github.com/anza-xyz/agave/blob/16de8b75ebcd57022409b422de557dd37b1de8db/runtime/src/bank.rs#L3622-L3633 */
  /* check_and_load_message_nonce_account */
  if( FD_UNLIKELY( !memcmp( &next_durable_nonce, recent_blockhash, sizeof(fd_hash_t) ) ) ) { /* nonce_is_advanceable == false  */
    return FD_RUNTIME_TXN_ERR_BLOCKHASH_NOT_FOUND;
  }

  /* https://github.com/anza-xyz/agave/blob/16de8b75ebcd57022409b422de557dd37b1de8db/runtime/src/bank.rs#L3603-L3620*/
  /* load_message_nonce_account */

  /* https://github.com/anza-xyz/agave/blob/16de8b75ebcd57022409b422de557dd37b1de8db/sdk/program/src/message/sanitized.rs#L345-L371 */
  /* get_durable_nonce */
  if( FD_UNLIKELY( !txn_ctx->txn_descriptor->instr_cnt ) ) {
    return FD_RUNTIME_TXN_ERR_BLOCKHASH_NOT_FOUND;
  }
  /* Check the first instruction (nonce instruction) to see if the program id
     is the system program. Also make sure that it is an advance nonce account
     instruction. Finally make sure that the first insutrction account is
     writeable; if it is, then that account is a durable nonce account. */
  fd_txn_instr_t const * txn_instr = &txn_ctx->txn_descriptor->instr[0];
  fd_acct_addr_t const * tx_accs = fd_txn_get_acct_addrs( txn_ctx->txn_descriptor, txn_ctx->_txn_raw->raw );
  fd_acct_addr_t const * prog_id = tx_accs + txn_instr->program_id;
  if( FD_UNLIKELY( memcmp( prog_id->b, fd_solana_system_program_id.key, sizeof( fd_pubkey_t ) ) ) ) {
    return FD_RUNTIME_TXN_ERR_BLOCKHASH_NOT_FOUND;
  }
  uchar const * instr_data  = fd_txn_get_instr_data( txn_instr, txn_ctx->_txn_raw->raw );
  uchar const * instr_accts = fd_txn_get_instr_accts( txn_instr, txn_ctx->_txn_raw->raw );

  /* https://github.com/anza-xyz/agave/blob/16de8b75ebcd57022409b422de557dd37b1de8db/sdk/program/src/message/sanitized.rs#L356-L358 */
  if( FD_UNLIKELY( txn_instr->data_sz<4UL || FD_LOAD( uint, instr_data ) !=
                   (uint)fd_system_program_instruction_enum_advance_nonce_account ) ) {
    return FD_RUNTIME_TXN_ERR_BLOCKHASH_NOT_FOUND;
  }
  if( FD_UNLIKELY( !fd_exec_txn_ctx_account_is_writable_idx( txn_ctx, instr_accts[0] ) ) ) {
    return FD_RUNTIME_TXN_ERR_BLOCKHASH_NOT_FOUND;
  }

  FD_TXN_ACCOUNT_DECL( durable_nonce_rec );
  int err = fd_txn_account_init_from_funk_readonly( durable_nonce_rec,
                                                    &txn_ctx->account_keys[ instr_accts[0] ],
                                                    txn_ctx->funk,
                                                    txn_ctx->funk_txn );
  if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS ) ) {
    return FD_RUNTIME_TXN_ERR_BLOCKHASH_NOT_FOUND;
  }

  /* https://github.com/anza-xyz/agave/blob/16de8b75ebcd57022409b422de557dd37b1de8db/sdk/src/nonce_account.rs#L28-L42 */
  /* verify_nonce_account */
  fd_pubkey_t const * owner_pubkey = durable_nonce_rec->vt->get_owner( durable_nonce_rec );
  if( FD_UNLIKELY( memcmp( owner_pubkey, fd_solana_system_program_id.key, sizeof( fd_pubkey_t ) ) ) ) {
    return FD_RUNTIME_TXN_ERR_BLOCKHASH_NOT_FOUND;
  }

  fd_nonce_state_versions_t * state = fd_bincode_decode_spad(
      nonce_state_versions, txn_ctx->spad,
      durable_nonce_rec->vt->get_data( durable_nonce_rec ),
      durable_nonce_rec->vt->get_data_len( durable_nonce_rec ),
      &err );
  if( FD_UNLIKELY( err ) ) return FD_RUNTIME_TXN_ERR_BLOCKHASH_NOT_FOUND;

  /* https://github.com/anza-xyz/agave/blob/16de8b75ebcd57022409b422de557dd37b1de8db/sdk/program/src/nonce/state/mod.rs#L36-L53 */
  /* verify_recent_blockhash. Thjis checks that the decoded nonce record is
     not a legacy nonce nor uninitialized. If this is the case, then we can
     verify by comparing the decoded durable nonce to the recent blockhash */
  if( FD_UNLIKELY( fd_nonce_state_versions_is_legacy( state ) ) ) {
    return FD_RUNTIME_TXN_ERR_BLOCKHASH_NOT_FOUND;
  }

  fd_nonce_state_t nonce_state = state->inner.current;
  if( FD_UNLIKELY( fd_nonce_state_is_uninitialized( &nonce_state ) ) ) {
    return FD_RUNTIME_TXN_ERR_BLOCKHASH_NOT_FOUND;
  }

  if( FD_UNLIKELY( memcmp( &nonce_state.inner.initialized.durable_nonce, recent_blockhash, sizeof(fd_hash_t) ) ) ) {
    return FD_RUNTIME_TXN_ERR_BLOCKHASH_NOT_FOUND;
  }

  /* Finally check that the nonce is authorized by seeing if any accounts in
     the nonce instruction are signers. This is a successful exit case. */
  for( ushort i=0; i<txn_instr->acct_cnt; ++i ) {
    if( fd_txn_is_signer( txn_ctx->txn_descriptor, (int)instr_accts[i] ) ) {
      if( !memcmp( &txn_ctx->account_keys[ instr_accts[i] ], &state->inner.current.inner.initialized.authority, sizeof( fd_pubkey_t ) ) ) {
        /*
           Mark nonce account to make sure that we modify and hash the
           account even if the transaction failed to execute
           successfully.
         */
        txn_ctx->nonce_account_idx_in_txn = instr_accts[ 0 ];
        /*
           Now figure out the state that the nonce account should
           advance to.
         */
        fd_txn_account_t * rollback_nonce_rec = fd_txn_account_init( &txn_ctx->rollback_nonce_account[ 0 ] );
        int                err                = fd_txn_account_init_from_funk_readonly( rollback_nonce_rec,
                                                                                        &txn_ctx->account_keys[ instr_accts[ 0 ] ],
                                                                                        txn_ctx->funk,
                                                                                        txn_ctx->funk_txn );
        if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS ) ) {
          return FD_RUNTIME_TXN_ERR_BLOCKHASH_NOT_FOUND;
        }
        fd_nonce_state_versions_t new_state = {
          .discriminant = fd_nonce_state_versions_enum_current,
          .inner = { .current = {
            .discriminant = fd_nonce_state_enum_initialized,
            .inner = { .initialized = {
              .authority      = state->inner.current.inner.initialized.authority,
              .durable_nonce  = next_durable_nonce,
              .fee_calculator = {
                .lamports_per_signature = fd_bank_prev_lamports_per_signature_get( txn_ctx->bank )
              }
            } }
          } }
        };
        if( FD_UNLIKELY( fd_nonce_state_versions_size( &new_state ) > FD_ACC_NONCE_SZ_MAX ) ) {
          FD_LOG_ERR(( "fd_nonce_state_versions_size( &new_state ) %lu > FD_ACC_NONCE_SZ_MAX %lu", fd_nonce_state_versions_size( &new_state ), FD_ACC_NONCE_SZ_MAX ));
        }
        /* make_modifiable uses the old length for the data copy */
        ulong old_tot_len = sizeof(fd_account_meta_t)+rollback_nonce_rec->vt->get_data_len( rollback_nonce_rec );
        void * borrowed_account_data = fd_spad_alloc( txn_ctx->spad, FD_ACCOUNT_REC_ALIGN, fd_ulong_max( FD_ACC_NONCE_TOT_SZ_MAX, old_tot_len ) );
        fd_txn_account_make_mutable( rollback_nonce_rec,
                                     borrowed_account_data,
                                     txn_ctx->spad_wksp );
        if( FD_UNLIKELY( fd_nonce_state_versions_size( &new_state ) > rollback_nonce_rec->vt->get_data_len( rollback_nonce_rec ) ) ) {
          return FD_RUNTIME_TXN_ERR_BLOCKHASH_NOT_FOUND;
        }
        do {
          fd_bincode_encode_ctx_t encode_ctx =
            { .data    = rollback_nonce_rec->vt->get_data_mut( rollback_nonce_rec ),
              .dataend = rollback_nonce_rec->vt->get_data_mut( rollback_nonce_rec ) + rollback_nonce_rec->vt->get_data_len( rollback_nonce_rec ) };
          int err = fd_nonce_state_versions_encode( &new_state, &encode_ctx );
          if( FD_UNLIKELY( err ) ) {
            return FD_RUNTIME_TXN_ERR_BLOCKHASH_NOT_FOUND;
          }
        } while(0);
        return FD_RUNTIME_EXECUTE_SUCCESS;
      }
    }
  }
  /* This means that the blockhash was not found */
  return FD_RUNTIME_TXN_ERR_BLOCKHASH_NOT_FOUND;

}
