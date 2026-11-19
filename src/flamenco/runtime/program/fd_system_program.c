#include "fd_system_program.h"
#include "../fd_executor.h"
#include "../fd_borrowed_account.h"
#include "../fd_system_ids.h"
#include "../fd_pubkey_utils.h"
#include "../../log_collector/fd_log_collector.h"


#define FD_FMT_ADDRESS(account_b58, base, out_fmt)                                                 \
  char out_fmt[ 128UL ];                                                                           \
  if( base ) {                                                                                     \
    FD_BASE58_ENCODE_32_BYTES( base->key, base_b58 );                                              \
    snprintf( out_fmt, 128UL, "Address { address: %s, base: Some(%s) }", account_b58, base_b58 );  \
  } else {                                                                                         \
    snprintf( out_fmt, 128UL, "Address { address: %s, base: None }", account_b58 );                \
  }

/* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/system/src/system_processor.rs#L43-L72

   Partial port of system_processor::Address::create, only covering the
   case of the "seed" input actually existing.  Note that this doesn't
   "create" an address, but rather re-derives from PDA inputs and checks
   that the result matches some expected value. */

static int
verify_seed_address( fd_exec_instr_ctx_t * ctx,
                     fd_pubkey_t const *   expected,
                     fd_pubkey_t const *   base,
                     char const *          seed,
                     ulong                 seed_sz,
                     fd_pubkey_t const *   owner ) {

  fd_pubkey_t actual[1];
  do {
    int err = fd_pubkey_create_with_seed(
        ctx,
        base->uc,
        seed,
        seed_sz,
        owner->uc,
        actual->uc );
    if( FD_UNLIKELY( err ) ) return err;
  } while(0);

  if( FD_UNLIKELY( 0!=memcmp( actual->uc, expected->uc, sizeof(fd_pubkey_t) ) ) ) {
    /* Log msg_sz can be more or less than 127 bytes */
    FD_BASE58_ENCODE_32_BYTES( expected->key, expected_b58 );
    FD_BASE58_ENCODE_32_BYTES( actual->key,   actual_b58   );
    fd_log_collector_printf_inefficient_max_512( ctx,
      "Create: address %s does not match derived address %s",
      expected_b58, actual_b58 );
    ctx->txn_out->err.custom_err = FD_SYSTEM_PROGRAM_ERR_ADDR_WITH_SEED_MISMATCH;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  return 0;
}

/* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/system/src/system_processor.rs#L216
   https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/system/src/system_processor.rs#L216

   Matches Solana Labs system_processor::transfer_verified */

static int
fd_system_program_transfer_verified( fd_exec_instr_ctx_t * ctx,
                                     ulong                 transfer_amount,
                                     ushort                from_acct_idx,
                                     ushort                to_acct_idx ) {
  int err;

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/system/src/system_processor.rs#L223 */

  fd_guarded_borrowed_account_t from = {0};
  FD_TRY_BORROW_INSTR_ACCOUNT_DEFAULT_ERR_CHECK( ctx, from_acct_idx, &from );

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/system/src/system_processor.rs#L224-L227 */

  if( fd_borrowed_account_get_data_len( &from ) != 0UL ) {
    fd_log_collector_msg_literal( ctx, "Transfer: `from` must not carry data" );
    return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
  }

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/system/src/system_processor.rs#L228-L236 */

  if( transfer_amount > fd_borrowed_account_get_lamports( &from ) ) {
    /* Max msg_sz: 45 - 6 + 20 + 20 = 79 < 127 => we can use printf */
    fd_log_collector_printf_dangerous_max_127( ctx, "Transfer: insufficient lamports %lu, need %lu", fd_borrowed_account_get_lamports( &from ), transfer_amount );
    ctx->txn_out->err.custom_err = FD_SYSTEM_PROGRAM_ERR_RESULT_WITH_NEGATIVE_LAMPORTS;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/system/src/system_processor.rs#L238 */

  err = fd_borrowed_account_checked_sub_lamports( &from, transfer_amount );
  /* Note: this err can never happen because of the check above */
  if( FD_UNLIKELY( err ) ) return err;

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/system/src/system_processor.rs#L239 */

  fd_borrowed_account_drop( &from );

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/system/src/system_processor.rs#L240 */

  fd_guarded_borrowed_account_t to = {0};
  FD_TRY_BORROW_INSTR_ACCOUNT_DEFAULT_ERR_CHECK( ctx, to_acct_idx, &to );

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/system/src/system_processor.rs#L241 */

  err = fd_borrowed_account_checked_add_lamports( &to, transfer_amount );
  if( FD_UNLIKELY( err ) ) return err;

  return 0;
}

/* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/system/src/system_processor.rs#L245

   Matches system_processor::transfer */

static int
fd_system_program_transfer( fd_exec_instr_ctx_t * ctx,
                            ulong                 transfer_amount,
                            ushort                from_acct_idx,
                            ushort                to_acct_idx ) {

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/system/src/system_processor.rs#L252-L259 */

  int instr_err_code = 0;
  if( FD_UNLIKELY( !fd_instr_acc_is_signer_idx( ctx->instr, from_acct_idx, &instr_err_code ) ) ) {
    /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/transaction-context/src/instruction.rs#L236 */
    if( FD_UNLIKELY( !!instr_err_code ) ) return instr_err_code;
    /* Max msg_sz: 37 - 2 + 45 = 80 < 127 => we can use printf */
    ushort idx_in_txn = ctx->instr->accounts[ from_acct_idx ].index_in_transaction;
    FD_BASE58_ENCODE_32_BYTES( ctx->txn_out->accounts.keys[ idx_in_txn ].uc, key_b58 );
    fd_log_collector_printf_dangerous_max_127( ctx,
      "Transfer: `from` account %s must sign", key_b58 );
    return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
  }

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/system/src/system_processor.rs#L261-L267 */

  return fd_system_program_transfer_verified( ctx, transfer_amount, from_acct_idx, to_acct_idx );
}

/* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/system/src/system_processor.rs#L75-L115
   https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/system/src/system_processor.rs#L75

   Based on Solana Labs system_processor::allocate() */

static int
fd_system_program_allocate( fd_exec_instr_ctx_t *   ctx,
                            fd_borrowed_account_t * account,
                            ulong                   space,
                            fd_pubkey_t const *     authority,
                            fd_pubkey_t const *     base ) {
  int err;

  /* Assumes that acct_idx was bounds checked */

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/system/src/system_processor.rs#L82-L89 */

  if( FD_UNLIKELY( !fd_exec_instr_ctx_any_signed( ctx, authority ) ) ) {
    /* Max msg_sz: 35 - 2 + 125 = 158 */
    FD_BASE58_ENCODE_32_BYTES( account->acc->pubkey, account_b58 );
    FD_FMT_ADDRESS( account_b58, base, address_fmt );
    fd_log_collector_printf_inefficient_max_512( ctx,
      "Allocate: 'to' account %s must sign",
      address_fmt );
    return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
  }

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/system/src/system_processor.rs#L91-L100 */

  if( FD_UNLIKELY( ( fd_borrowed_account_get_data_len( account ) != 0UL ) ||
                   ( 0!=memcmp( fd_borrowed_account_get_owner( account ), fd_solana_system_program_id.uc, 32UL ) ) ) ) {
    /* Max msg_sz: 35 - 2 + 125 = 158 */
    FD_BASE58_ENCODE_32_BYTES( account->acc->pubkey, account_b58 );
    FD_FMT_ADDRESS( account_b58, base, address_fmt );
    fd_log_collector_printf_inefficient_max_512( ctx,
      "Allocate: account %s already in use",
      address_fmt );
    ctx->txn_out->err.custom_err = FD_SYSTEM_PROGRAM_ERR_ACCT_ALREADY_IN_USE;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/system/src/system_processor.rs#L102-L110 */

  if( FD_UNLIKELY( space > FD_RUNTIME_ACC_SZ_MAX ) ) {
    /* Max msg_sz: 48 - 6 + 2*20 = 82 < 127 => we can use printf */
    fd_log_collector_printf_dangerous_max_127( ctx,
      "Allocate: requested %lu, max allowed %lu", space, FD_RUNTIME_ACC_SZ_MAX );
    ctx->txn_out->err.custom_err = FD_SYSTEM_PROGRAM_ERR_INVALID_ACCT_DATA_LEN;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/system/src/system_processor.rs#L112 */

  err = fd_borrowed_account_set_data_length( account, space );
  if( FD_UNLIKELY( err ) ) {
    return err;
  }

  return FD_EXECUTOR_INSTR_SUCCESS;
}

/* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/system/src/system_processor.rs#L117-L135
   https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/system/src/system_processor.rs#L117

   Based on Solana Labs system_processor::assign() */

static int
fd_system_program_assign( fd_exec_instr_ctx_t *   ctx,
                          fd_borrowed_account_t * account,
                          fd_pubkey_t const *     owner,
                          fd_pubkey_t const *     authority,
                          fd_pubkey_t const *     base ) {
  /* Assumes addr_idx was bounds checked */

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/system/src/system_processor.rs#L125-L127 */

  if( 0==memcmp( fd_borrowed_account_get_owner( account ), owner->uc, sizeof(fd_pubkey_t) ) )
    return 0;

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/system/src/system_processor.rs#L129-L132 */

  if( FD_UNLIKELY( !fd_exec_instr_ctx_any_signed( ctx, authority ) ) ) {
    /* Max msg_sz: 28 - 2 + 125 = 151 */
    FD_BASE58_ENCODE_32_BYTES( account->acc->pubkey, account_b58 );
    FD_FMT_ADDRESS( account_b58, base, address_fmt );
    fd_log_collector_printf_inefficient_max_512( ctx,
      "Assign: account %s must sign",
      address_fmt );
    return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
  }

  return fd_borrowed_account_set_owner( account, owner );
}

/* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/system/src/system_processor.rs#L137-L147

   Based on Solana Labs system_processor::allocate_and_assign() */

static int
fd_system_program_allocate_and_assign( fd_exec_instr_ctx_t *   ctx,
                                       fd_borrowed_account_t * account,
                                       ulong                   space,
                                       fd_pubkey_t const *     owner,
                                       fd_pubkey_t const *     authority,
                                       fd_pubkey_t const *     base ) {

  do {
    int err = fd_system_program_allocate( ctx, account, space, authority, base );
    if( FD_UNLIKELY( err ) ) return err;
  } while(0);
  return fd_system_program_assign( ctx, account, owner, authority, base );

}

/* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/system/src/system_processor.rs#L150-L182
   https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/system/src/system_processor.rs#L150

   Matches Solana Labs system_processor::create_account() */

static int
fd_system_program_create_account( fd_exec_instr_ctx_t * ctx,
                                  ushort                from_acct_idx,
                                  ushort                to_acct_idx,
                                  ulong                 lamports,
                                  ulong                 space,
                                  fd_pubkey_t const *   owner,
                                  fd_pubkey_t const *   authority,
                                  fd_pubkey_t const *   base ) {
  int err;

  /* if it looks like the to account is already in use, bail
     https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/system/src/system_processor.rs#L162-L174 */

  do {
    /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/system/src/system_processor.rs#L163 */

    fd_guarded_borrowed_account_t to = {0};
    FD_TRY_BORROW_INSTR_ACCOUNT_DEFAULT_ERR_CHECK( ctx, to_acct_idx, &to );

    /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/system/src/system_processor.rs#L164-L171 */

    if( FD_UNLIKELY( fd_borrowed_account_get_lamports( &to ) ) ) {
      /* Max msg_sz: 41 - 2 + 125 = 164 */
      FD_BASE58_ENCODE_32_BYTES( to.acc->pubkey, to_b58 );
      FD_FMT_ADDRESS( to_b58, base, address_fmt );
      fd_log_collector_printf_inefficient_max_512( ctx,
        "Create Account: account %s already in use",
        address_fmt );
      ctx->txn_out->err.custom_err = FD_SYSTEM_PROGRAM_ERR_ACCT_ALREADY_IN_USE;
      return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
    }

    /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/system/src/system_processor.rs#L173 */

    err = fd_system_program_allocate_and_assign( ctx, &to, space, owner, authority, base );
    if( FD_UNLIKELY( err ) ) return err;

    /* Implicit drop
       https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/system/src/system_processor.rs#L174 */
  } while (0);

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/system/src/system_processor.rs#L175-L181 */

  return fd_system_program_transfer( ctx, lamports, from_acct_idx, to_acct_idx );
}

/* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/system/src/system_processor.rs#L184-L214 */

static int
fd_system_program_create_account_allow_prefund( fd_exec_instr_ctx_t * ctx,
                                                ushort               to_acct_idx,
                                                ulong                lamports,
                                                ulong                space,
                                                fd_pubkey_t const *  owner,
                                                fd_pubkey_t const *  to_address,
                                                ushort               from_acct_idx ) {
  int err;

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/system/src/system_processor.rs#L198-L201 */
  do {
    fd_guarded_borrowed_account_t to = {0};
    FD_TRY_BORROW_INSTR_ACCOUNT_DEFAULT_ERR_CHECK( ctx, to_acct_idx, &to );
    err = fd_system_program_allocate_and_assign( ctx, &to, space, owner, to_address, NULL );
    if( FD_UNLIKELY( err ) ) return err;
  } while(0);

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/system/src/system_processor.rs#L202-L212 */
  if( FD_LIKELY( lamports > 0 ) ) {
    return fd_system_program_transfer( ctx, lamports, from_acct_idx, to_acct_idx );
  }

  return FD_EXECUTOR_INSTR_SUCCESS;
}

/* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/system/src/system_processor.rs#L331-L353

   Matches Solana Labs system_processor SystemInstruction::CreateAccount { ... } => { ... } */

int
fd_system_program_exec_create_account( fd_exec_instr_ctx_t *    ctx,
                                       create_account_t const * create_acc ) {

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/system/src/system_processor.rs#L336 */

  if( FD_UNLIKELY( ctx->instr->acct_cnt < 2 ) )
    return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/system/src/system_processor.rs#L337-L341
     Authorization check is lifted out from 'allocate' to here. */

  ushort const from_acct_idx = 0UL;
  ushort const to_acct_idx   = 1UL;

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/system/src/system_processor.rs#L337-L338 */
  fd_pubkey_t const * authority = NULL;
  int err = fd_exec_instr_ctx_get_key_of_account_at_index( ctx, to_acct_idx, &authority );
  if( FD_UNLIKELY( err ) ) return err;

  return fd_system_program_create_account(
      ctx,
      from_acct_idx,
      to_acct_idx,
      create_acc->lamports,
      create_acc->space,
      &create_acc->owner,
      authority,
      NULL );
}

/* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/system/src/system_processor.rs#L531-L564 */

int
fd_system_program_exec_create_account_allow_prefund( fd_exec_instr_ctx_t *    ctx,
                                                     create_account_t const * args ) {

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/system/src/system_processor.rs#L536-L541 */
  if( FD_UNLIKELY( !FD_FEATURE_ACTIVE_BANK( ctx->bank, create_account_allow_prefund ) ) ) {
    return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
  }

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/system/src/system_processor.rs#L542-L548 */
  ushort from_acct_idx = 0;
  if( args->lamports > 0 ) {
    if( FD_UNLIKELY( fd_exec_instr_ctx_check_num_insn_accounts( ctx, 2U ) ) ) {
      return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
    }
    from_acct_idx = 1;
  } else {
    if( FD_UNLIKELY( fd_exec_instr_ctx_check_num_insn_accounts( ctx, 1U ) ) ) {
      return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;
    }
  }

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/system/src/system_processor.rs#L549-L553 */
  ushort const to_acct_idx       = 0;
  fd_pubkey_t const * to_address = NULL;
  int err = fd_exec_instr_ctx_get_key_of_account_at_index( ctx, to_acct_idx, &to_address );
  if( FD_UNLIKELY( err ) ) return err;

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/system/src/system_processor.rs#L554-L563 */
  return fd_system_program_create_account_allow_prefund(
      ctx, to_acct_idx, args->lamports, args->space, &args->owner, to_address, from_acct_idx );
}

/* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/system/src/system_processor.rs#L380-L389

   Matches Solana Labs system_processor SystemInstruction::Assign { ... } => { ... } */

int
fd_system_program_exec_assign( fd_exec_instr_ctx_t * ctx,
                               fd_pubkey_t const *   owner ) {
  int err;

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/system/src/system_processor.rs#L381 */

  if( FD_UNLIKELY( ctx->instr->acct_cnt < 1 ) )
    return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/system/src/system_processor.rs#L382 */

  fd_guarded_borrowed_account_t account = {0};
  FD_TRY_BORROW_INSTR_ACCOUNT_DEFAULT_ERR_CHECK( ctx, 0, &account );

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/system/src/system_processor.rs#L383-L387
     system_processor::Address::create eliminated (dead code) */

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/system/src/system_processor.rs#L388 */

  err = fd_system_program_assign( ctx, &account, owner, (fd_pubkey_t*)account.acc->pubkey, NULL );
  if( FD_UNLIKELY( err ) ) return err;

  /* Implicit drop */

  return 0;
}

/* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/system/src/system_processor.rs#L390-L393

   Matches Solana Labs system_processor SystemInstruction::Transfer { ... } => { ... } */

int
fd_system_program_exec_transfer( fd_exec_instr_ctx_t * ctx,
                                 ulong                 transfer_amount ) {

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/system/src/system_processor.rs#L391 */

  if( FD_UNLIKELY( ctx->instr->acct_cnt < 2 ) )
    return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/system/src/system_processor.rs#L392 */

  return fd_system_program_transfer( ctx, transfer_amount, 0UL, 1UL );
}

/* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/system/src/system_processor.rs#L355

   Matches Solana Labs system_processor SystemInstruction::CreateAccountWithSeed { ... } => { ... } */

int
fd_system_program_exec_create_account_with_seed( fd_exec_instr_ctx_t *              ctx,
                                                 create_account_with_seed_t const * args ) {

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/system/src/system_processor.rs#L362 */

  if( FD_UNLIKELY( fd_exec_instr_ctx_check_num_insn_accounts( ctx, 2UL) ) )
    return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/system/src/system_processor.rs#L363-L367 */

  fd_pubkey_t const * to_address = NULL;
  int err = fd_exec_instr_ctx_get_key_of_account_at_index( ctx, 1UL, &to_address );
  if( FD_UNLIKELY( err ) ) return err;

  do {
    int err = verify_seed_address(
        ctx,
        to_address,
        &args->base,
        (char const *)args->seed,
        args->seed_len,
        &args->owner );
    if( FD_UNLIKELY( err ) ) return err;
  } while(0);

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/system/src/system_processor.rs#L368-L378 */

  ushort const from_acct_idx = 0UL;
  ushort const to_acct_idx   = 1UL;
  return fd_system_program_create_account(
      ctx,
      from_acct_idx,
      to_acct_idx,
      args->lamports,
      args->space,
      &args->owner,
      &args->base,
      &args->base );
}

/* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/system/src/system_processor.rs#L489-L498

   Matches Solana Labs system_processor SystemInstruction::Allocate { ... } => { ... } */

int
fd_system_program_exec_allocate( fd_exec_instr_ctx_t * ctx,
                                 ulong                 space ) {
  int err;

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/system/src/system_processor.rs#L490 */

  if( FD_UNLIKELY( ctx->instr->acct_cnt < 1 ) )
    return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/system/src/system_processor.rs#L491 */
  fd_guarded_borrowed_account_t account = {0};
  FD_TRY_BORROW_INSTR_ACCOUNT_DEFAULT_ERR_CHECK( ctx, 0, &account );

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/system/src/system_processor.rs#L492-L496
     system_processor::Address::create eliminated (dead code) */

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/system/src/system_processor.rs#L497
     Authorization check is lifted out from 'allocate' to here. */

  err = fd_system_program_allocate( ctx, &account, space, (fd_pubkey_t*)account.acc->pubkey, NULL );
  if( FD_UNLIKELY( err ) ) return err;

  /* Implicit drop */

  return 0;
}

/* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/system/src/system_processor.rs#L499-L520

   Matches Solana Labs system_processor SystemInstruction::AllocateWithSeed { ... } => { ... } */

int
fd_system_program_exec_allocate_with_seed( fd_exec_instr_ctx_t *        ctx,
                                           allocate_with_seed_t const * args ) {
  int err;

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/system/src/system_processor.rs#L505 */

  if( FD_UNLIKELY( ctx->instr->acct_cnt < 1 ) )
    return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/system/src/system_processor.rs#L506 */

  fd_guarded_borrowed_account_t account = {0};
  FD_TRY_BORROW_INSTR_ACCOUNT_DEFAULT_ERR_CHECK( ctx, 0, &account );

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/system/src/system_processor.rs#L507-L511 */

  err = verify_seed_address(
    ctx,
    (fd_pubkey_t*)account.acc->pubkey,
    &args->base,
    (char const *)args->seed,
    args->seed_len,
    &args->owner );
  if( FD_UNLIKELY( err ) ) return err;

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/system/src/system_processor.rs#L512-L519
     Authorization check is lifted out from 'allocate' to here. */

  err = fd_system_program_allocate_and_assign(
    ctx,
    &account,
    args->space,
    &args->owner,
    &args->base,
    &args->base );
  if( FD_UNLIKELY( err ) ) return err;

  /* Implicit drop */

  return 0;
}

/* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/system/src/system_processor.rs#L521-L530

   Matches Solana Labs system_processor SystemInstruction::AssignWithSeed { ... } => { ... } */

int
fd_system_program_exec_assign_with_seed( fd_exec_instr_ctx_t *      ctx,
                                         assign_with_seed_t const * args ) {
  int err;

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/system/src/system_processor.rs#L522 */

  if( FD_UNLIKELY( ctx->instr->acct_cnt < 1 ) )
    return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/system/src/system_processor.rs#L523 */

  fd_guarded_borrowed_account_t account = {0};
  FD_TRY_BORROW_INSTR_ACCOUNT_DEFAULT_ERR_CHECK( ctx, 0, &account );

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/system/src/system_processor.rs#L524-L528 */

  err = verify_seed_address(
    ctx,
    (fd_pubkey_t*)account.acc->pubkey,
    &args->base,
    (char const *)args->seed,
    args->seed_len,
    &args->owner );
  if( FD_UNLIKELY( err ) ) return err;

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/system/src/system_processor.rs#L529
     Authorization check is lifted out from 'assign' to here. */

  err = fd_system_program_assign( ctx, &account, &args->owner, &args->base, &args->base );
  if( FD_UNLIKELY( err ) ) return err;

  /* Implicit drop */

  return 0;
}

/* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/system/src/system_processor.rs#L394-L410

   Matches Solana Labs system_processor SystemInstruction::TransferWithSeed { ... } => { ... } */

int
fd_system_program_exec_transfer_with_seed( fd_exec_instr_ctx_t *        ctx,
                                           transfer_with_seed_t const * args ) {

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/system/src/system_processor.rs#L399 */

  if( FD_UNLIKELY( fd_exec_instr_ctx_check_num_insn_accounts( ctx, 3UL ) ) )
    return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/system/src/system_processor.rs#L400-L409
     Inlined call to system_processor::transfer_with_seed */

  ushort const from_idx      = 0UL;
  ushort const from_base_idx = 1UL;
  ushort const to_idx        = 2UL;

  int instr_err_code = 0;
  if( FD_UNLIKELY( !fd_instr_acc_is_signer_idx( ctx->instr, from_base_idx, &instr_err_code ) ) ) {
    /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/transaction-context/src/instruction.rs#L236 */
    if( FD_UNLIKELY( !!instr_err_code ) ) return instr_err_code;
    /* Max msg_sz: 37 - 2 + 45 = 80 < 127 => we can use printf */
    ushort idx_in_txn = ctx->instr->accounts[ from_base_idx ].index_in_transaction;
    FD_BASE58_ENCODE_32_BYTES( ctx->txn_out->accounts.keys[ idx_in_txn ].uc, key_b58 );
    fd_log_collector_printf_dangerous_max_127( ctx,
      "Transfer: 'from' account %s must sign", key_b58 );
    return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
  }

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/system/src/system_processor.rs#L290-L295 */

  fd_pubkey_t const * base = NULL;
  int err = fd_exec_instr_ctx_get_key_of_account_at_index( ctx, from_base_idx, &base );
  if( FD_UNLIKELY( err ) ) return err;

  fd_pubkey_t address_from_seed[1];
  do {
    int err = fd_pubkey_create_with_seed(
        ctx,
        base->uc,
        (char const *)args->from_seed,
        args->from_seed_len,
        args->from_owner.uc,
        address_from_seed->uc );
    if( FD_UNLIKELY( err ) ) return err;
  } while(0);

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/system/src/system_processor.rs#L297-L306 */
  fd_pubkey_t const * from_key = NULL;
  err = fd_exec_instr_ctx_get_key_of_account_at_index( ctx, from_idx, &from_key );
  if( FD_UNLIKELY( err ) ) return err;

  if( FD_UNLIKELY( 0!=memcmp( address_from_seed->uc,
                              from_key->uc,
                              sizeof(fd_pubkey_t) ) ) ) {
    /* Log msg_sz can be more or less than 127 bytes */
    FD_BASE58_ENCODE_32_BYTES( from_key->key,          from_key_b58          );
    FD_BASE58_ENCODE_32_BYTES( address_from_seed->key, address_from_seed_b58 );
    fd_log_collector_printf_inefficient_max_512( ctx,
      "Transfer: 'from' address %s does not match derived address %s",
      from_key_b58,
      address_from_seed_b58 );
    ctx->txn_out->err.custom_err = FD_SYSTEM_PROGRAM_ERR_ADDR_WITH_SEED_MISMATCH;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  /* https://github.com/anza-xyz/agave/blob/v4.5.0-beta.0/programs/system/src/system_processor.rs#L308-L314 */
  return fd_system_program_transfer_verified( ctx, args->lamports, from_idx, to_idx );
}

int
fd_system_program_execute( fd_exec_instr_ctx_t * ctx ) {
  FD_EXEC_CU_UPDATE( ctx, 150UL );

  fd_system_program_instruction_t instruction;
  if( FD_UNLIKELY( fd_system_program_instruction_decode( &instruction,
                                                         ctx->instr->data,
                                                         ctx->instr->data_sz ) ) ) {
    return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
  }

  switch( instruction.discriminant ) {
  case FD_SYSTEM_PROGRAM_INSTR_CREATE_ACCOUNT:
    return fd_system_program_exec_create_account( ctx, &instruction.inner.create_account );
  case FD_SYSTEM_PROGRAM_INSTR_ASSIGN:
    return fd_system_program_exec_assign( ctx, &instruction.inner.assign );
  case FD_SYSTEM_PROGRAM_INSTR_TRANSFER:
    return fd_system_program_exec_transfer( ctx, instruction.inner.transfer );
  case FD_SYSTEM_PROGRAM_INSTR_CREATE_ACCOUNT_WITH_SEED:
    return fd_system_program_exec_create_account_with_seed( ctx, &instruction.inner.create_account_with_seed );
  case FD_SYSTEM_PROGRAM_INSTR_ADVANCE_NONCE_ACCOUNT:
    return fd_system_program_exec_advance_nonce_account( ctx );
  case FD_SYSTEM_PROGRAM_INSTR_WITHDRAW_NONCE_ACCOUNT:
    return fd_system_program_exec_withdraw_nonce_account( ctx, instruction.inner.withdraw_nonce_account );
  case FD_SYSTEM_PROGRAM_INSTR_INITIALIZE_NONCE_ACCOUNT:
    return fd_system_program_exec_initialize_nonce_account( ctx, &instruction.inner.initialize_nonce_account );
  case FD_SYSTEM_PROGRAM_INSTR_AUTHORIZE_NONCE_ACCOUNT:
    return fd_system_program_exec_authorize_nonce_account( ctx, &instruction.inner.authorize_nonce_account );
  case FD_SYSTEM_PROGRAM_INSTR_ALLOCATE:
    return fd_system_program_exec_allocate( ctx, instruction.inner.allocate );
  case FD_SYSTEM_PROGRAM_INSTR_ALLOCATE_WITH_SEED:
    return fd_system_program_exec_allocate_with_seed( ctx, &instruction.inner.allocate_with_seed );
  case FD_SYSTEM_PROGRAM_INSTR_ASSIGN_WITH_SEED:
    return fd_system_program_exec_assign_with_seed( ctx, &instruction.inner.assign_with_seed );
  case FD_SYSTEM_PROGRAM_INSTR_TRANSFER_WITH_SEED:
    return fd_system_program_exec_transfer_with_seed( ctx, &instruction.inner.transfer_with_seed );
  case FD_SYSTEM_PROGRAM_INSTR_UPGRADE_NONCE_ACCOUNT:
    return fd_system_program_exec_upgrade_nonce_account( ctx );
  case FD_SYSTEM_PROGRAM_INSTR_CREATE_ACCOUNT_ALLOW_PREFUND:
    return fd_system_program_exec_create_account_allow_prefund( ctx, &instruction.inner.create_account_allow_prefund );
  default:
    return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
  }
}

/**********************************************************************/
/* Public API                                                         */
/**********************************************************************/

int
fd_get_system_account_kind( fd_acc_t const * acc ) {
  /* https://github.com/anza-xyz/solana-sdk/blob/nonce-account%40v5.0.0/nonce-account/src/lib.rs#L68-L70 */
  if( FD_UNLIKELY( memcmp( acc->owner, fd_solana_system_program_id.uc, sizeof(fd_pubkey_t) ) ) ) {
    return FD_SYSTEM_PROGRAM_NONCE_ACCOUNT_KIND_UNKNOWN;
  }

  /* https://github.com/anza-xyz/solana-sdk/blob/nonce-account%40v5.0.0/nonce-account/src/lib.rs#L74-L75 */
  if( FD_LIKELY( !acc->data_len ) ) {
    return FD_SYSTEM_PROGRAM_NONCE_ACCOUNT_KIND_SYSTEM;
  }

  /* https://github.com/anza-xyz/solana-sdk/blob/nonce-account%40v5.0.0/nonce-account/src/lib.rs#L76 */
  if( FD_UNLIKELY( acc->data_len!=FD_SYSTEM_PROGRAM_NONCE_DLEN ) ) {
    return FD_SYSTEM_PROGRAM_NONCE_ACCOUNT_KIND_UNKNOWN;
  }

  /* https://github.com/anza-xyz/solana-sdk/blob/nonce-account%40v5.0.0/nonce-account/src/lib.rs#L77-L88 */
  fd_nonce_state_versions_t state[1];
  if( FD_UNLIKELY( fd_nonce_state_versions_decode( state, acc->data, acc->data_len ) ) ) {
    return FD_SYSTEM_PROGRAM_NONCE_ACCOUNT_KIND_UNKNOWN;
  }

  if( FD_LIKELY( state->kind==FD_NONCE_STATE_INITIALIZED ) ) {
    return FD_SYSTEM_PROGRAM_NONCE_ACCOUNT_KIND_NONCE;
  }

  return FD_SYSTEM_PROGRAM_NONCE_ACCOUNT_KIND_UNKNOWN;
}
