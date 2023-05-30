#include "../fd_executor.h"
#include "fd_system_program.h"
#include "../fd_acc_mgr.h"
#include "../fd_runtime.h"
#include "../sysvar/fd_sysvar_rent.h"
#include "../sysvar/fd_sysvar.h"
#include "../../base58/fd_base58.h"

#ifdef _DISABLE_OPTIMIZATION
#pragma GCC optimize ("O0")
#endif

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/system_instruction.rs#L139 */
#define MAX_PERMITTED_DATA_LENGTH ( 10 * 1024 * 1024 )

static int transfer(
  instruction_ctx_t ctx,
  ulong             requested_lamports
  ) {
  /* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/runtime/src/system_instruction_processor.rs#L327 */

  /* Pull out sender (acc idx 0) and recipient (acc idx 1) */
  uchar *       instr_acc_idxs = ((uchar *)ctx.txn_raw->raw + ctx.instr->acct_off);
  fd_pubkey_t * txn_accs = (fd_pubkey_t *)((uchar *)ctx.txn_raw->raw + ctx.txn_descriptor->acct_addr_off);
  fd_pubkey_t * sender   = &txn_accs[instr_acc_idxs[0]];
  fd_pubkey_t * receiver = &txn_accs[instr_acc_idxs[1]];


  char encoded_sender[50];
  fd_base58_encode_32((uchar *) sender, 0, encoded_sender);

  char encoded_receiver[50];
  fd_base58_encode_32((uchar *) receiver, 0, encoded_receiver);

  FD_LOG_NOTICE(( "transferring slot=%lu amount=%lu from %s to %s", ctx.global->bank.solana_bank.slot, requested_lamports, encoded_sender, encoded_receiver ));

  /* Check sender has signed the transaction */
  uchar sender_is_signer = 0;
  for ( ulong i = 0; i < ctx.instr->acct_cnt; i++ ) {
    if ( instr_acc_idxs[i] < ctx.txn_descriptor->signature_cnt ) {
      fd_pubkey_t * signer = &txn_accs[instr_acc_idxs[i]];
      if ( memcmp( signer, sender, sizeof(fd_pubkey_t) ) == 0 ) {
        sender_is_signer = 1;
        break;
      }
    }
  }
  if ( !sender_is_signer ) {
    FD_LOG_WARNING( ( " sender has not authorized transfer " ) );
    return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
  }

  // TODO: check sender has empty data https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/runtime/src/system_instruction_processor.rs#LL177C20-L177C20

  /* Check sender account has enough balance to execute this transaction */
  fd_acc_lamports_t sender_lamports = 0;
  int               read_result = fd_acc_mgr_get_lamports( ctx.global->acc_mgr, ctx.global->funk_txn, sender, &sender_lamports );
  if ( FD_UNLIKELY( read_result != FD_ACC_MGR_SUCCESS ) ) {
    FD_LOG_WARNING(( "failed to get lamports" ));
    /* TODO: correct error messages */
    return FD_EXECUTOR_INSTR_ERR_GENERIC_ERR;
  }
  if ( FD_UNLIKELY( sender_lamports < requested_lamports ) ) {
    FD_LOG_WARNING(( "sender only has %lu lamports, needs %lu", sender_lamports, requested_lamports ));
    return FD_EXECUTOR_INSTR_ERR_INSUFFICIENT_FUNDS;
  }

  /* Determine the receiver's current balance, creating the account if it does not exist */
  fd_acc_lamports_t receiver_lamports = 0;
  read_result = fd_acc_mgr_get_lamports( ctx.global->acc_mgr, ctx.global->funk_txn, receiver, &receiver_lamports );
  if ( FD_UNLIKELY( read_result == FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT ) ) {

    /* Create new account if it doesn't exist */
    FD_LOG_DEBUG(( "transfer to unknown account: creating new account" ));
    fd_account_meta_t metadata;
    fd_account_meta_init(&metadata);
    int write_result = fd_acc_mgr_write_account_data( ctx.global->acc_mgr, ctx.global->funk_txn, receiver, &metadata, sizeof(metadata), NULL, 0, 0 );
    if ( FD_UNLIKELY( write_result != FD_ACC_MGR_SUCCESS ) ) {
      FD_LOG_WARNING(( "failed to create new account" ));
      return FD_EXECUTOR_INSTR_ERR_GENERIC_ERR;
    }

  }
  else if ( FD_UNLIKELY( read_result != FD_ACC_MGR_SUCCESS ) ) {
    FD_LOG_WARNING(( "failed to get lamports" ));
    return FD_EXECUTOR_INSTR_ERR_GENERIC_ERR;
  }
  FD_LOG_DEBUG(("transfer: sender balance before transfer: %lu", sender_lamports));
  FD_LOG_DEBUG(("transfer: receiver balance before transfer: %lu", receiver_lamports));

  /* TODO: check for underflow https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/runtime/src/system_instruction_processor.rs#L191 */

  /* Execute the transfer */
  int write_result = fd_acc_mgr_set_lamports( ctx.global->acc_mgr, ctx.global->funk_txn, ctx.global->bank.solana_bank.slot , sender, sender_lamports - requested_lamports );
  if ( FD_UNLIKELY( write_result != FD_ACC_MGR_SUCCESS ) ) {
    FD_LOG_WARNING(( "failed to set sender lamports" ));
    return FD_EXECUTOR_INSTR_ERR_GENERIC_ERR;
  }
  write_result = fd_acc_mgr_set_lamports( ctx.global->acc_mgr, ctx.global->funk_txn, ctx.global->bank.solana_bank.slot, receiver, receiver_lamports + requested_lamports );
  if ( FD_UNLIKELY( write_result != FD_ACC_MGR_SUCCESS ) ) {
    FD_LOG_WARNING(( "failed to set receiver lamports" ));
    return FD_EXECUTOR_INSTR_ERR_GENERIC_ERR;
  }

  FD_LOG_INFO(( "successfully executed transfer of %lu lamports", requested_lamports ));

  return FD_EXECUTOR_INSTR_SUCCESS;
}

static int create_account(
  instruction_ctx_t ctx,
    fd_system_program_instruction_t *instruction
) {
  if (ctx.instr->acct_cnt < 2) 
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;

  /* Account 0: funding account
     Account 1: new account
   */
  uchar *       instr_acc_idxs = ((uchar *)ctx.txn_raw->raw + ctx.instr->acct_off);
  fd_pubkey_t * txn_accs = (fd_pubkey_t *)((uchar *)ctx.txn_raw->raw + ctx.txn_descriptor->acct_addr_off);

  fd_pubkey_t * from     = &txn_accs[instr_acc_idxs[0]];
  fd_pubkey_t * to       = &txn_accs[instr_acc_idxs[1]];

  ulong             lamports = 0;
  ulong             space = 0;
  fd_pubkey_t*      owner = NULL;
  fd_pubkey_t*      base = NULL;
  char*             seed = NULL;


  if (instruction->discriminant == fd_system_program_instruction_enum_create_account) {
    // https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/runtime/src/system_instruction_processor.rs#L277
    fd_system_program_instruction_create_account_t* params = &instruction->inner.create_account;
    lamports = params->lamports;
    space = params->space;
    owner = &params->owner;
    base = to;
  } else {
    // https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/runtime/src/system_instruction_processor.rs#L296
    fd_system_program_instruction_create_account_with_seed_t* params = &instruction->inner.create_account_with_seed;
    lamports = params->lamports;
    space = params->space;
    owner = &params->owner;
    base = &params->base;
    seed = params->seed;

    fd_pubkey_t      address_with_seed;

    fd_pubkey_create_with_seed(base, seed, owner, &address_with_seed);
    if (memcmp(address_with_seed.hash, to->hash, sizeof(to->hash))) 
      return fd_system_error_enum_address_with_seed_mismatch;
  }

  // https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/runtime/src/system_instruction_processor.rs#L33

  /* Check from/to has signed the transaction */
  uchar from_is_signer = 0;
  uchar to_signed = 0;

  for ( ulong i = 0; i < ctx.instr->acct_cnt; i++ ) {
    if ( instr_acc_idxs[i] < ctx.txn_descriptor->signature_cnt ) {
      fd_pubkey_t * signer = &txn_accs[instr_acc_idxs[i]];
      if ( memcmp( signer, from, sizeof(fd_pubkey_t) ) == 0 )
        from_is_signer = 1;
      if ( !memcmp( signer, base, sizeof(fd_pubkey_t) ) )
        to_signed = 1;
    }
  }
  if ( !from_is_signer | !to_signed )
    return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;

  fd_account_meta_t metadata;
  int read_result = fd_acc_mgr_get_metadata( ctx.global->acc_mgr, ctx.global->funk_txn, from, &metadata );
  if ( read_result == FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT ) {
    FD_LOG_WARNING(( "account does not exist" ));
    /* TODO: propagate SystemError::AccountAlreadyInUse enum variant */
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  fd_acc_lamports_t sender_lamports = metadata.info.lamports;

  if ( FD_UNLIKELY( sender_lamports < lamports ) ) {
    FD_LOG_WARNING(( "sender only has %lu lamports, needs %lu", sender_lamports, lamports ));
    return FD_EXECUTOR_INSTR_ERR_INSUFFICIENT_FUNDS;
  }

  /* Execute the transfer */
  int write_result = fd_acc_mgr_set_lamports( ctx.global->acc_mgr, ctx.global->funk_txn, ctx.global->bank.solana_bank.slot , from, sender_lamports - lamports );
  if ( FD_UNLIKELY( write_result != FD_ACC_MGR_SUCCESS ) ) {
    FD_LOG_WARNING(( "failed to set sender lamports" ));
    return FD_EXECUTOR_INSTR_ERR_GENERIC_ERR;
  }

  /* Check to see if the account is already in use */
  read_result = fd_acc_mgr_get_metadata( ctx.global->acc_mgr, ctx.global->funk_txn, to, &metadata );
  if ( read_result != FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT ) {
    FD_LOG_WARNING(( "account already exists" ));
    /* TODO: propagate SystemError::AccountAlreadyInUse enum variant */
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  /* Check that we are not exceeding the MAX_PERMITTED_DATA_LENGTH account size */
  if ( space > MAX_PERMITTED_DATA_LENGTH ) {
    FD_LOG_WARNING(( "MAX_PERMITTED_DATA_LENGTH exceeded" ));
    /* TODO: propagate SystemError::InvalidAccountDataLength enum variant */
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  /* Initialize the account with all zeroed data and the correct owner */

  unsigned char *data =  (unsigned char *) (*ctx.global->allocf)(ctx.global->allocf_arg, 1, space);
  memset( data, 0, space );
  fd_solana_account_t account = {
    .lamports = lamports,
    .data_len = space,
    .data = data,
    .owner = *owner,
    .executable = 0,
    .rent_epoch = 0,   /* TODO */
  };
  write_result = fd_acc_mgr_write_structured_account(ctx.global->acc_mgr, ctx.global->funk_txn, 0, to, &account);
  ctx.global->freef(ctx.global->allocf_arg, data);
  if ( write_result != FD_ACC_MGR_SUCCESS ) {
    FD_LOG_NOTICE(( "failed to create account: %d", write_result ));
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  return FD_EXECUTOR_INSTR_SUCCESS;
}

// https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/runtime/src/system_instruction_processor.rs#L321-L326
// https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/runtime/src/system_instruction_processor.rs#L111
static int assign(
  instruction_ctx_t ctx,
  fd_pubkey_t owner
) {
  /* Pull out the account to be assigned an owner (acc idx 0) */
  uchar *       instr_acc_idxs = ((uchar *)ctx.txn_raw->raw + ctx.instr->acct_off);
  fd_pubkey_t * txn_accs = (fd_pubkey_t *)((uchar *)ctx.txn_raw->raw + ctx.txn_descriptor->acct_addr_off);
  fd_pubkey_t * keyed_account   = &txn_accs[instr_acc_idxs[0]];

  // get owner
  fd_pubkey_t current_owner;
  int read_result = fd_acc_mgr_get_owner( ctx.global->acc_mgr, ctx.global->funk_txn, keyed_account, &current_owner );

  if ( FD_UNLIKELY( read_result != FD_ACC_MGR_SUCCESS ) ) {
    return FD_EXECUTOR_INSTR_ERR_GENERIC_ERR;
  }

  // no work to do when owner is the same
  // #ifdef current_owner
  if ( memcmp( &current_owner, &owner, sizeof(fd_pubkey_t)) == 0 ) {
    return FD_EXECUTOR_INSTR_SUCCESS;
  }
  // #endif

  /* Check sender has signed the transaction */
  uchar sender_is_signer = 0;
  for ( ulong i = 0; i < ctx.instr->acct_cnt; i++ ) {
    if ( instr_acc_idxs[i] < ctx.txn_descriptor->signature_cnt ) {
      fd_pubkey_t * signer = &txn_accs[instr_acc_idxs[i]];
      if ( memcmp( signer, keyed_account, sizeof(fd_pubkey_t) ) == 0 ) {
        sender_is_signer = 1;
        break;
      }
    }
  }
  if ( !sender_is_signer ) {
    return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
  }

  // Set the owner of the account
  int execute_result = fd_acc_mgr_set_owner( ctx.global->acc_mgr, ctx.global->funk_txn, ctx.global->bank.solana_bank.slot , keyed_account, owner );
  if ( FD_UNLIKELY( execute_result != FD_ACC_MGR_SUCCESS ) ) {
    return FD_EXECUTOR_INSTR_ERR_GENERIC_ERR;
  }

  return FD_EXECUTOR_INSTR_SUCCESS;
}

int fd_executor_system_program_execute_instruction(
  instruction_ctx_t ctx
  ) {
  /* Deserialize the SystemInstruction enum */
  uchar *      data            = (uchar *)ctx.txn_raw->raw + ctx.instr->data_off;
  void*        input            = (void *)data;
  const void** input_ptr = (const void **)&input;
  void*        dataend          = (void*)&data[ctx.instr->data_sz];

  fd_system_program_instruction_t instruction;
  fd_system_program_instruction_decode( &instruction, input_ptr, dataend, ctx.global->allocf, ctx.global->allocf_arg );

  int   result = FD_EXECUTOR_INSTR_ERR_INVALID_ARG;

  switch (instruction.discriminant) {
  case fd_system_program_instruction_enum_transfer: {
    result = transfer( ctx, instruction.inner.transfer );
    break;
  }
  case fd_system_program_instruction_enum_create_account: {
    result = create_account( ctx, &instruction );
    break;
  }
  case fd_system_program_instruction_enum_create_account_with_seed: {
    result = create_account( ctx, &instruction );
    break;
  }
  case fd_system_program_instruction_enum_assign: {
    result = assign( ctx, instruction.inner.assign );
    break;
  }
  case fd_system_program_instruction_enum_advance_nonce_account: {
    result = fd_advance_nonce_account( ctx );
    break;
  }
  case fd_system_program_instruction_enum_withdraw_nonce_account: {
    result = fd_withdraw_nonce_account( ctx, instruction.inner.withdraw_nonce_account );
    break;
  }
  case fd_system_program_instruction_enum_initialize_nonce_account: {
    result = fd_initialize_nonce_account( ctx, &instruction.inner.initialize_nonce_account );
    break;
  }
  case fd_system_program_instruction_enum_authorize_nonce_account: {
    result = fd_authorize_nonce_account( ctx, &instruction.inner.authorize_nonce_account );
    break;
  }
  default: {
    /* TODO: support other instruction types */
    FD_LOG_WARNING(( "unsupported system program instruction: discriminant: %d", instruction.discriminant ));
  }
  }

  fd_system_program_instruction_destroy( &instruction, ctx.global->freef, ctx.global->allocf_arg );
  return result;
}

