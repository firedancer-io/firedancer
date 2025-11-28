#include "fd_system_program.h"
#include "../fd_executor.h"
#include "../fd_borrowed_account.h"
#include "../fd_system_ids.h"
#include "../fd_pubkey_utils.h"
#include "../../log_collector/fd_log_collector.h"

/* The dynamically sized portion of the system program instruction only
   comes from the seed.  This means in the worst case assuming that the
   seed takes up the entire transaction MTU, the worst case footprint
   is the sum of the size of the instruction and the transaction MTU.
   This is not the tightest bound, but it's a reasonable bound. */

#define FD_SYSTEM_PROGRAM_INSTR_FOOTPRINT (FD_TXN_MTU + sizeof(fd_system_program_instruction_t))

/* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L42-L68

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
    fd_log_collector_printf_inefficient_max_512( ctx,
      "Create: address %s does not match derived address %s",
      FD_BASE58_ENC_32_ALLOCA( expected ),
      FD_BASE58_ENC_32_ALLOCA( actual ) );
    ctx->txn_out->err.custom_err = FD_SYSTEM_PROGRAM_ERR_ADDR_WITH_SEED_MISMATCH;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  return 0;
}

/* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L183
   https://github.com/anza-xyz/agave/blob/v2.0.9/programs/system/src/system_processor.rs#L182

   Matches Solana Labs system_processor::transfer_verified */

static int
fd_system_program_transfer_verified( fd_exec_instr_ctx_t * ctx,
                                     ulong                 transfer_amount,
                                     ushort                from_acct_idx,
                                     ushort                to_acct_idx ) {
  int err;

  /* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L191-L192 */

  fd_guarded_borrowed_account_t from = {0};
  FD_TRY_BORROW_INSTR_ACCOUNT_DEFAULT_ERR_CHECK( ctx, from_acct_idx, &from );

  /* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L193-L196 */

  if( fd_borrowed_account_get_data_len( &from ) != 0UL ) {
    fd_log_collector_msg_literal( ctx, "Transfer: `from` must not carry data" );
    return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
  }

  /* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L197-L205 */

  if( transfer_amount > fd_borrowed_account_get_lamports( &from ) ) {
    /* Max msg_sz: 45 - 6 + 20 + 20 = 79 < 127 => we can use printf */
    fd_log_collector_printf_dangerous_max_127( ctx, "Transfer: insufficient lamports %lu, need %lu", fd_borrowed_account_get_lamports( &from ), transfer_amount );
    ctx->txn_out->err.custom_err = FD_SYSTEM_PROGRAM_ERR_RESULT_WITH_NEGATIVE_LAMPORTS;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  /* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L207 */

  err = fd_borrowed_account_checked_sub_lamports( &from, transfer_amount );
  /* Note: this err can never happen because of the check above */
  if( FD_UNLIKELY( err ) ) return err;

  /* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L208 */

  fd_borrowed_account_drop( &from );

  /* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L209-L210 */

  fd_guarded_borrowed_account_t to = {0};
  FD_TRY_BORROW_INSTR_ACCOUNT_DEFAULT_ERR_CHECK( ctx, to_acct_idx, &to );

  /* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L211 */

  err = fd_borrowed_account_checked_add_lamports( &to, transfer_amount );
  if( FD_UNLIKELY( err ) ) return err;

  return 0;
}

/* https://github.com/anza-xyz/agave/blob/v2.0.9/programs/system/src/system_processor.rs#L214

   Matches system_processor::transfer */

static int
fd_system_program_transfer( fd_exec_instr_ctx_t * ctx,
                            ulong                 transfer_amount,
                            ushort                from_acct_idx,
                            ushort                to_acct_idx ) {

  /* https://github.com/anza-xyz/agave/blob/v2.0.9/programs/system/src/system_processor.rs#L222-L232 */

  int instr_err_code = 0;
  if( FD_UNLIKELY( !fd_instr_acc_is_signer_idx( ctx->instr, from_acct_idx, &instr_err_code ) ) ) {
    /* https://github.com/anza-xyz/agave/blob/v3.0.3/transaction-context/src/lib.rs#L789 */
    if( FD_UNLIKELY( !!instr_err_code ) ) return instr_err_code;
    /* Max msg_sz: 37 - 2 + 45 = 80 < 127 => we can use printf */
    ushort idx_in_txn = ctx->instr->accounts[ from_acct_idx ].index_in_transaction;
    fd_log_collector_printf_dangerous_max_127( ctx,
      "Transfer: `from` account %s must sign", FD_BASE58_ENC_32_ALLOCA( &ctx->txn_out->accounts.account_keys[ idx_in_txn ] ) );
    return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.0.9/programs/system/src/system_processor.rs#L234-L241 */

  return fd_system_program_transfer_verified( ctx, transfer_amount, from_acct_idx, to_acct_idx );
}

/* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L71-L111
   https://github.com/anza-xyz/agave/blob/v2.0.9/programs/system/src/system_processor.rs#L70

   Based on Solana Labs system_processor::allocate() */

static int
fd_system_program_allocate( fd_exec_instr_ctx_t *   ctx,
                            fd_borrowed_account_t * account,
                            ulong                   space,
                            fd_pubkey_t const *     authority,
                            fd_pubkey_t const *     base ) {
  int err;

  /* Assumes that acct_idx was bounds checked */

  /* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L78-L85 */

  if( FD_UNLIKELY( !fd_exec_instr_ctx_any_signed( ctx, authority ) ) ) {
    /* Max msg_sz: 35 - 2 + 125 = 158 */
    fd_log_collector_printf_inefficient_max_512( ctx,
      "Allocate: 'to' (account %s, base %s) must sign",
      FD_BASE58_ENC_32_ALLOCA( &account->acct->pubkey ),
      base ? FD_BASE58_ENC_32_ALLOCA( base ) : "None" );
    return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
  }

  /* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L87-L96 */

  if( FD_UNLIKELY( ( fd_borrowed_account_get_data_len( account ) != 0UL ) ||
                   ( 0!=memcmp( fd_borrowed_account_get_owner( account ), fd_solana_system_program_id.uc, 32UL ) ) ) ) {
    /* Max msg_sz: 35 - 2 + 125 = 158 */
    fd_log_collector_printf_inefficient_max_512( ctx,
      "Allocate: account (account %s, base %s) already in use",
      FD_BASE58_ENC_32_ALLOCA( &account->acct->pubkey ),
      base ? FD_BASE58_ENC_32_ALLOCA( base ) : "None" );
    ctx->txn_out->err.custom_err = FD_SYSTEM_PROGRAM_ERR_ACCT_ALREADY_IN_USE;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  /* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L98-L106 */

  if( FD_UNLIKELY( space > FD_RUNTIME_ACC_SZ_MAX ) ) {
    /* Max msg_sz: 48 - 6 + 2*20 = 82 < 127 => we can use printf */
    fd_log_collector_printf_dangerous_max_127( ctx,
      "Allocate: requested %lu, max allowed %lu", space, FD_RUNTIME_ACC_SZ_MAX );
    ctx->txn_out->err.custom_err = FD_SYSTEM_PROGRAM_ERR_INVALID_ACCT_DATA_LEN;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  /* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L108 */

  err = fd_borrowed_account_set_data_length( account, space );
  if( FD_UNLIKELY( err ) ) {
    return err;
  }

  return FD_EXECUTOR_INSTR_SUCCESS;
}

/* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L113-L131
   https://github.com/anza-xyz/agave/blob/v2.0.9/programs/system/src/system_processor.rs#L112

   Based on Solana Labs system_processor::assign() */

static int
fd_system_program_assign( fd_exec_instr_ctx_t *   ctx,
                          fd_borrowed_account_t * account,
                          fd_pubkey_t const *     owner,
                          fd_pubkey_t const *     authority,
                          fd_pubkey_t const *     base ) {
  /* Assumes addr_idx was bounds checked */

  /* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L121-L123 */

  if( 0==memcmp( fd_borrowed_account_get_owner( account ), owner->uc, sizeof(fd_pubkey_t) ) )
    return 0;

  /* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L125-L128 */

  if( FD_UNLIKELY( !fd_exec_instr_ctx_any_signed( ctx, authority ) ) ) {
    /* Max msg_sz: 28 - 2 + 125 = 151 */
    fd_log_collector_printf_inefficient_max_512( ctx,
      "Allocate: 'to' (account %s, base %s) must sign",
      FD_BASE58_ENC_32_ALLOCA( &account->acct->pubkey ),
      base ? FD_BASE58_ENC_32_ALLOCA( base ) : "None" );
    return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
  }

  return fd_borrowed_account_set_owner( account, owner );
}

/* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L133-L143

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

/* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L146-L181
   https://github.com/anza-xyz/agave/blob/v2.0.9/programs/system/src/system_processor.rs#L145

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
     https://github.com/anza-xyz/agave/blob/v2.1.14/programs/system/src/system_processor.rs#L159-L172 */

  do {
    /* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L160-L161 */

    fd_guarded_borrowed_account_t to = {0};
    FD_TRY_BORROW_INSTR_ACCOUNT_DEFAULT_ERR_CHECK( ctx, to_acct_idx, &to );

    /* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L162-L169 */

    if( FD_UNLIKELY( fd_borrowed_account_get_lamports( &to ) ) ) {
      /* Max msg_sz: 41 - 2 + 125 = 164 */
      fd_log_collector_printf_inefficient_max_512( ctx,
        "Allocate: 'to' (account %s, base %s) already in use",
        FD_BASE58_ENC_32_ALLOCA( &to.acct->pubkey ),
        base ? FD_BASE58_ENC_32_ALLOCA( base ) : "None" );
      ctx->txn_out->err.custom_err = FD_SYSTEM_PROGRAM_ERR_ACCT_ALREADY_IN_USE;
      return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
    }

    /* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L171 */

    err = fd_system_program_allocate_and_assign( ctx, &to, space, owner, authority, base );
    if( FD_UNLIKELY( err ) ) return err;

    /* Implicit drop
       https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L172 */
  } while (0);

  /* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L173-L180 */

  return fd_system_program_transfer( ctx, lamports, from_acct_idx, to_acct_idx );
}

/* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L327-L352

   Matches Solana Labs system_processor SystemInstruction::CreateAccount { ... } => { ... } */

int
fd_system_program_exec_create_account( fd_exec_instr_ctx_t *                                  ctx,
                                       fd_system_program_instruction_create_account_t const * create_acc ) {

  /* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L332 */

  if( FD_UNLIKELY( ctx->instr->acct_cnt < 2 ) )
    return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;

  /* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L333-L339
     Authorization check is lifted out from 'allocate' to here. */

  ushort const from_acct_idx = 0UL;
  ushort const to_acct_idx   = 1UL;

  /* https://github.com/anza-xyz/agave/blob/v2.1.14/programs/system/src/system_processor.rs#L317-L320 */
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

/* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L381-L393

   Matches Solana Labs system_processor SystemInstruction::Assign { ... } => { ... } */

int
fd_system_program_exec_assign( fd_exec_instr_ctx_t * ctx,
                               fd_pubkey_t const *   owner ) {
  int err;

  /* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L382 */

  if( FD_UNLIKELY( ctx->instr->acct_cnt < 1 ) )
    return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;

  /* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L383-L384 */

  fd_guarded_borrowed_account_t account = {0};
  FD_TRY_BORROW_INSTR_ACCOUNT_DEFAULT_ERR_CHECK( ctx, 0, &account );

  /* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L385-L391
     system_processor::Address::create eliminated (dead code) */

  /* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L392 */

  err = fd_system_program_assign( ctx, &account, owner, account.acct->pubkey, NULL );
  if( FD_UNLIKELY( err ) ) return err;

  /* Implicit drop */

  return 0;
}

/* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L394-L404

   Matches Solana Labs system_processor SystemInstruction::Transfer { ... } => { ... } */

int
fd_system_program_exec_transfer( fd_exec_instr_ctx_t * ctx,
                                 ulong                 transfer_amount ) {

  /* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L395 */

  if( FD_UNLIKELY( ctx->instr->acct_cnt < 2 ) )
    return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;

  /* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L396-L402 */

  return fd_system_program_transfer( ctx, transfer_amount, 0UL, 1UL );
}

/* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L353

   Matches Solana Labs system_processor SystemInstruction::CreateAccountWithSeed { ... } => { ... } */

int
fd_system_program_exec_create_account_with_seed( fd_exec_instr_ctx_t *                                            ctx,
                                                 fd_system_program_instruction_create_account_with_seed_t const * args ) {

  /* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L360 */

  if( FD_UNLIKELY( fd_exec_instr_ctx_check_num_insn_accounts( ctx, 2UL) ) )
    return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;

  /* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L361-L367 */

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

  /* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L368-L379 */

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

/* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L504-L516

   Matches Solana Labs system_processor SystemInstruction::Allocate { ... } => { ... } */

int
fd_system_program_exec_allocate( fd_exec_instr_ctx_t * ctx,
                                 ulong                 space ) {
  int err;

  /* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L505 */

  if( FD_UNLIKELY( ctx->instr->acct_cnt < 1 ) )
    return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;

  /* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L506-L507 */
  fd_guarded_borrowed_account_t account = {0};
  FD_TRY_BORROW_INSTR_ACCOUNT_DEFAULT_ERR_CHECK( ctx, 0, &account );

  /* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L508-L514
     system_processor::Address::create eliminated (dead code) */

  /* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L515
     Authorization check is lifted out from 'allocate' to here. */

  err = fd_system_program_allocate( ctx, &account, space, account.acct->pubkey, NULL );
  if( FD_UNLIKELY( err ) ) return err;

  /* Implicit drop */

  return 0;
}

/* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L517-L541

   Matches Solana Labs system_processor SystemInstruction::AllocateWithSeed { ... } => { ... } */

int
fd_system_program_exec_allocate_with_seed( fd_exec_instr_ctx_t *                                      ctx,
                                           fd_system_program_instruction_allocate_with_seed_t const * args ) {
  int err;

  /* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L523 */

  if( FD_UNLIKELY( ctx->instr->acct_cnt < 1 ) )
    return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;

  /* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#524-525 */

  fd_guarded_borrowed_account_t account = {0};
  FD_TRY_BORROW_INSTR_ACCOUNT_DEFAULT_ERR_CHECK( ctx, 0, &account );

  /* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L526-L532 */

  err = verify_seed_address(
    ctx,
    account.acct->pubkey,
    &args->base,
    (char const *)args->seed,
    args->seed_len,
    &args->owner );
  if( FD_UNLIKELY( err ) ) return err;

  /* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L533-L540
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

/* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L542-L554

   Matches Solana Labs system_processor SystemInstruction::AssignWithSeed { ... } => { ... } */

int
fd_system_program_exec_assign_with_seed( fd_exec_instr_ctx_t *                                    ctx,
                                         fd_system_program_instruction_assign_with_seed_t const * args ) {
  int err;

  /* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#543 */

  if( FD_UNLIKELY( ctx->instr->acct_cnt < 1 ) )
    return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;

  /* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L544-L545 */

  fd_guarded_borrowed_account_t account = {0};
  FD_TRY_BORROW_INSTR_ACCOUNT_DEFAULT_ERR_CHECK( ctx, 0, &account );

  /* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L546-L552 */

  err = verify_seed_address(
    ctx,
    account.acct->pubkey,
    &args->base,
    (char const *)args->seed,
    args->seed_len,
    &args->owner );
  if( FD_UNLIKELY( err ) ) return err;

  /* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L553
     Authorization check is lifted out from 'assign' to here. */

  err = fd_system_program_assign( ctx, &account, &args->owner, &args->base, &args->base );
  if( FD_UNLIKELY( err ) ) return err;

  /* Implicit drop */

  return 0;
}

/* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L405-L422

   Matches Solana Labs system_processor SystemInstruction::TransferWithSeed { ... } => { ... } */

int
fd_system_program_exec_transfer_with_seed( fd_exec_instr_ctx_t *                                      ctx,
                                           fd_system_program_instruction_transfer_with_seed_t const * args ) {

  /* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L410 */

  if( FD_UNLIKELY( fd_exec_instr_ctx_check_num_insn_accounts( ctx, 3UL ) ) )
    return FD_EXECUTOR_INSTR_ERR_MISSING_ACC;

  /* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L411-L421
     Inlined call to system_processor::transfer_with_seed */

  ushort const from_idx      = 0UL;
  ushort const from_base_idx = 1UL;
  ushort const to_idx        = 2UL;

  int instr_err_code = 0;
  if( FD_UNLIKELY( !fd_instr_acc_is_signer_idx( ctx->instr, from_base_idx, &instr_err_code ) ) ) {
    /* https://github.com/anza-xyz/agave/blob/v3.0.3/transaction-context/src/lib.rs#L789 */
    if( FD_UNLIKELY( !!instr_err_code ) ) return instr_err_code;
    /* Max msg_sz: 37 - 2 + 45 = 80 < 127 => we can use printf */
    ushort idx_in_txn = ctx->instr->accounts[ from_base_idx ].index_in_transaction;
    fd_log_collector_printf_dangerous_max_127( ctx,
      "Transfer: 'from' account %s must sign", FD_BASE58_ENC_32_ALLOCA( &ctx->txn_out->accounts.account_keys[ idx_in_txn ] ) );
    return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.2.0/programs/system/src/system_processor.rs#L267-L274 */

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

  /* https://github.com/anza-xyz/agave/blob/v2.2.0/programs/system/src/system_processor.rs#L276-L287 */
  fd_pubkey_t const * from_key = NULL;
  err = fd_exec_instr_ctx_get_key_of_account_at_index( ctx, from_idx, &from_key );
  if( FD_UNLIKELY( err ) ) return err;

  if( FD_UNLIKELY( 0!=memcmp( address_from_seed->uc,
                              from_key->uc,
                              sizeof(fd_pubkey_t) ) ) ) {
    /* Log msg_sz can be more or less than 127 bytes */
    fd_log_collector_printf_inefficient_max_512( ctx,
      "Transfer: 'from' address %s does not match derived address %s",
      FD_BASE58_ENC_32_ALLOCA( from_key ),
      FD_BASE58_ENC_32_ALLOCA( address_from_seed ) );
    ctx->txn_out->err.custom_err = FD_SYSTEM_PROGRAM_ERR_ADDR_WITH_SEED_MISMATCH;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  /* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L305-L312 */
  return fd_system_program_transfer_verified( ctx, args->lamports, from_idx, to_idx );
}

int
fd_system_program_execute( fd_exec_instr_ctx_t * ctx ) {
  FD_EXEC_CU_UPDATE( ctx, 150UL );

  /* Deserialize the SystemInstruction enum */
  uchar * data = ctx->instr->data;
  if( FD_UNLIKELY( data==NULL ) ) {
    return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
  }

  if( FD_UNLIKELY( ctx->instr->data_sz>FD_SYSTEM_PROGRAM_INSTR_FOOTPRINT ) ) {
    return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
  }

  uchar instr_mem[ FD_SYSTEM_PROGRAM_INSTR_FOOTPRINT ] __attribute__((aligned(alignof(fd_system_program_instruction_t))));

  int decode_err;
  fd_system_program_instruction_t * instruction = fd_bincode_decode_static_limited_deserialize(
      system_program_instruction, instr_mem,
      data, ctx->instr->data_sz,
      FD_TXN_MTU,
      &decode_err );
  if( FD_UNLIKELY( decode_err ) ) {
    return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
  }

  int result = FD_EXECUTOR_INSTR_ERR_INVALID_ARG;

  switch( instruction->discriminant ) {
  case fd_system_program_instruction_enum_create_account: {
    result = fd_system_program_exec_create_account(
        ctx, &instruction->inner.create_account );
    break;
  }
  case fd_system_program_instruction_enum_assign: {
    result = fd_system_program_exec_assign(
        ctx, &instruction->inner.assign );
    break;
  }
  case fd_system_program_instruction_enum_transfer: {
    result = fd_system_program_exec_transfer(
        ctx, instruction->inner.transfer );
    break;
  }
  case fd_system_program_instruction_enum_create_account_with_seed: {
    result = fd_system_program_exec_create_account_with_seed(
        ctx, &instruction->inner.create_account_with_seed );
    break;
  }
  case fd_system_program_instruction_enum_advance_nonce_account: {
    result = fd_system_program_exec_advance_nonce_account( ctx );
    break;
  }
  case fd_system_program_instruction_enum_withdraw_nonce_account: {
    result = fd_system_program_exec_withdraw_nonce_account(
        ctx, instruction->inner.withdraw_nonce_account );
    break;
  }
  case fd_system_program_instruction_enum_initialize_nonce_account: {
    result = fd_system_program_exec_initialize_nonce_account(
        ctx, &instruction->inner.initialize_nonce_account );
    break;
  }
  case fd_system_program_instruction_enum_authorize_nonce_account: {
    result = fd_system_program_exec_authorize_nonce_account(
        ctx, &instruction->inner.authorize_nonce_account );
    break;
  }
  case fd_system_program_instruction_enum_allocate: {
    result = fd_system_program_exec_allocate( ctx, instruction->inner.allocate );
    break;
  }
  case fd_system_program_instruction_enum_allocate_with_seed: {
    // https://github.com/solana-labs/solana/blob/b00d18cec4011bb452e3fe87a3412a3f0146942e/runtime/src/system_instruction_processor.rs#L525
    result = fd_system_program_exec_allocate_with_seed(
        ctx, &instruction->inner.allocate_with_seed );
    break;
  }
  case fd_system_program_instruction_enum_assign_with_seed: {
    // https://github.com/solana-labs/solana/blob/b00d18cec4011bb452e3fe87a3412a3f0146942e/runtime/src/system_instruction_processor.rs#L545
    result = fd_system_program_exec_assign_with_seed(
        ctx, &instruction->inner.assign_with_seed );
    break;
  }
  case fd_system_program_instruction_enum_transfer_with_seed: {
    // https://github.com/solana-labs/solana/blob/b00d18cec4011bb452e3fe87a3412a3f0146942e/runtime/src/system_instruction_processor.rs#L412
    result = fd_system_program_exec_transfer_with_seed(
        ctx, &instruction->inner.transfer_with_seed );
    break;
  }
  case fd_system_program_instruction_enum_upgrade_nonce_account: {
    // https://github.com/solana-labs/solana/blob/b00d18cec4011bb452e3fe87a3412a3f0146942e/runtime/src/system_instruction_processor.rs#L491
    result = fd_system_program_exec_upgrade_nonce_account( ctx );
    break;
  }
  }

  return result;
}

/**********************************************************************/
/* Public API                                                         */
/**********************************************************************/

int
fd_get_system_account_kind( fd_txn_account_t * account ) {
  /* https://github.com/anza-xyz/solana-sdk/blob/nonce-account%40v2.2.1/nonce-account/src/lib.rs#L56 */
  if( FD_UNLIKELY( memcmp( fd_txn_account_get_owner( account ), fd_solana_system_program_id.uc, sizeof(fd_pubkey_t) ) ) ) {
    return FD_SYSTEM_PROGRAM_NONCE_ACCOUNT_KIND_UNKNOWN;
  }

  /* https://github.com/anza-xyz/solana-sdk/blob/nonce-account%40v2.2.1/nonce-account/src/lib.rs#L57-L58 */
  if( FD_LIKELY( !fd_txn_account_get_data_len( account ) ) ) {
    return FD_SYSTEM_PROGRAM_NONCE_ACCOUNT_KIND_SYSTEM;
  }

  /* https://github.com/anza-xyz/solana-sdk/blob/nonce-account%40v2.2.1/nonce-account/src/lib.rs#L59 */
  if( FD_UNLIKELY( fd_txn_account_get_data_len( account )!=FD_SYSTEM_PROGRAM_NONCE_DLEN ) ) {
    return FD_SYSTEM_PROGRAM_NONCE_ACCOUNT_KIND_UNKNOWN;
  }

  /* https://github.com/anza-xyz/solana-sdk/blob/nonce-account%40v2.2.1/nonce-account/src/lib.rs#L60-L64 */
  fd_nonce_state_versions_t versions[1];
  if( FD_UNLIKELY( !fd_bincode_decode_static(
      nonce_state_versions, versions,
      fd_txn_account_get_data( account ),
      fd_txn_account_get_data_len( account ),
      NULL ) ) ) {
    return FD_SYSTEM_PROGRAM_NONCE_ACCOUNT_KIND_UNKNOWN;
  }

  fd_nonce_state_t * state = NULL;
  if( fd_nonce_state_versions_is_current( versions ) ) {
    state = &versions->inner.current;
  } else {
    state = &versions->inner.legacy;
  }

  if( FD_LIKELY( fd_nonce_state_is_initialized( state ) ) ) {
    return FD_SYSTEM_PROGRAM_NONCE_ACCOUNT_KIND_NONCE;
  }

  return FD_SYSTEM_PROGRAM_NONCE_ACCOUNT_KIND_UNKNOWN;
}
