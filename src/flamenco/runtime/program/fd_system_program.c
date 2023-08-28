#include "../fd_executor.h"
#include "fd_system_program.h"
#include "../fd_acc_mgr.h"
#include "../fd_runtime.h"
#include "../fd_account.h"
#include "../sysvar/fd_sysvar_rent.h"
#include "../sysvar/fd_sysvar.h"
#include "../../../ballet/base58/fd_base58.h"

static int transfer(
  instruction_ctx_t                ctx,
  fd_system_program_instruction_t *instruction
  ) {
  /* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/runtime/src/system_instruction_processor.rs#L327 */

  /* Pull out sender (acc idx 0) and recipient (acc idx 1) */
  uchar *       instr_acc_idxs = ctx.instr->acct_txn_idxs;
  fd_pubkey_t * txn_accs = ctx.txn_ctx->accounts;
  fd_pubkey_t * sender = NULL;
  fd_pubkey_t * receiver = NULL;

  ulong requested_lamports;
  if (instruction->discriminant == fd_system_program_instruction_enum_transfer) {
    int err = fd_account_sanity_check(&ctx, 2);
    if (FD_UNLIKELY(FD_EXECUTOR_INSTR_SUCCESS != err))
      return err;

    sender   = &txn_accs[instr_acc_idxs[0]];
    receiver = &txn_accs[instr_acc_idxs[1]];
    requested_lamports = instruction->inner.transfer;
  } else if (instruction->discriminant == fd_system_program_instruction_enum_transfer_with_seed) {
    int err = fd_account_sanity_check(&ctx, 3);
    if (FD_UNLIKELY(FD_EXECUTOR_INSTR_SUCCESS != err))
      return err;

    sender      = &txn_accs[instr_acc_idxs[0]];
    fd_pubkey_t * sender_base = &txn_accs[instr_acc_idxs[1]];
    receiver    = &txn_accs[instr_acc_idxs[2]];
    requested_lamports = instruction->inner.transfer_with_seed.lamports;

    fd_pubkey_t      address_with_seed;
    fd_pubkey_create_with_seed(
      sender_base->uc,
      instruction->inner.transfer_with_seed.from_seed,
      strlen( instruction->inner.transfer_with_seed.from_seed ),
      instruction->inner.transfer_with_seed.from_owner.uc,
      address_with_seed.uc );
    if (memcmp(address_with_seed.hash, sender->hash, sizeof(sender->hash))) {
      ctx.txn_ctx->custom_err = 5;
      return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
    }
  } else {
    /* Should never get here */
    return FD_EXECUTOR_INSTR_ERR_GENERIC_ERR;
  }

  if (!fd_instr_acc_is_signer(ctx.instr, sender))
    return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;

  int    err = 0;

  fd_funk_rec_t const *sender_con_rec = NULL;
  char * raw_acc_data = (char*) fd_acc_mgr_view_raw(ctx.global->acc_mgr, ctx.global->funk_txn, (fd_pubkey_t *) sender, &sender_con_rec, &err);
  if (NULL == raw_acc_data)
    return FD_EXECUTOR_INSTR_ERR_GENERIC_ERR;
  fd_account_meta_t *m = (fd_account_meta_t *) raw_acc_data;
  if (m->dlen > 0)
    return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;

  if (m->info.lamports < requested_lamports) {
    ctx.txn_ctx->custom_err = 1;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  fd_funk_rec_t const * receiver_con_rec = NULL;
  raw_acc_data = (char*) fd_acc_mgr_view_raw(ctx.global->acc_mgr, ctx.global->funk_txn, (fd_pubkey_t *) receiver, &receiver_con_rec, NULL);
  ulong              res = requested_lamports;
  if (NULL != raw_acc_data) {
    fd_account_meta_t *m2 = (fd_account_meta_t *) raw_acc_data;
    res = fd_ulong_sat_add(res, m2->info.lamports);
    if (ULONG_MAX == res)
      return FD_EXECUTOR_INSTR_ERR_ARITHMETIC_OVERFLOW;
  }

  // Ok, time to do some damage...
  fd_funk_rec_t * sender_rec = NULL;
  void *          sender_data = fd_acc_mgr_modify_raw(ctx.global->acc_mgr, ctx.global->funk_txn, sender, 0, 0UL, sender_con_rec, &sender_rec, &err);
  if (FD_EXECUTOR_INSTR_SUCCESS != err)
    return err;

  fd_funk_rec_t * receiver_rec = NULL;
  void *          receiver_data = fd_acc_mgr_modify_raw(ctx.global->acc_mgr, ctx.global->funk_txn, receiver, 1, 0UL, receiver_con_rec, &receiver_rec, &err);
  if (FD_EXECUTOR_INSTR_SUCCESS != err)
    return err;

  ((fd_account_meta_t *) sender_data)->info.lamports = ((fd_account_meta_t *) sender_data)->info.lamports - requested_lamports;
  ((fd_account_meta_t *) receiver_data)->info.lamports = res;

  err = fd_acc_mgr_commit_raw(ctx.global->acc_mgr, sender_rec, sender, sender_data, ctx.global->bank.slot, 0);
  if (FD_EXECUTOR_INSTR_SUCCESS != err)
    return err;
  return fd_acc_mgr_commit_raw(ctx.global->acc_mgr, receiver_rec, receiver, receiver_data, ctx.global->bank.slot, 0);
}

// https://github.com/solana-labs/solana/blob/b00d18cec4011bb452e3fe87a3412a3f0146942e/runtime/src/system_instruction_processor.rs#L507
// https://github.com/solana-labs/solana/blob/b00d18cec4011bb452e3fe87a3412a3f0146942e/runtime/src/system_instruction_processor.rs#L525

static int fd_system_allocate(
  instruction_ctx_t                ctx,
  fd_system_program_instruction_t *instruction
  ) {
    int err = fd_account_sanity_check(&ctx, 1);
    if (FD_UNLIKELY(FD_EXECUTOR_INSTR_SUCCESS != err))
      return err;
  uchar *       instr_acc_idxs = ctx.instr->acct_txn_idxs;
  fd_pubkey_t * txn_accs = ctx.txn_ctx->accounts;
  fd_pubkey_t * account     = &txn_accs[instr_acc_idxs[0]];
  fd_pubkey_t*  owner = NULL;

  unsigned long allocate = 0;
  if (instruction->discriminant == fd_system_program_instruction_enum_allocate) {
    if (!fd_instr_acc_is_signer(ctx.instr, account))
      return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;

    allocate = instruction->inner.allocate;
  } else {
    fd_system_program_instruction_allocate_with_seed_t *t = &instruction->inner.allocate_with_seed;

    if (!fd_instr_acc_is_signer(ctx.instr, &t->base))
      return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;

    fd_pubkey_t      address_with_seed;
    fd_pubkey_create_with_seed( t->base.uc, t->seed, strlen( t->seed ), t->owner.uc, address_with_seed.uc );
    if (memcmp(address_with_seed.hash, account->hash, sizeof(account->hash))) {
      ctx.txn_ctx->custom_err = 5;
      return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
    }
    allocate = t->space;
    owner = &t->owner;
  }

  fd_funk_rec_t const *crec = NULL;
  char * raw_acc_data = (char*) fd_acc_mgr_view_raw(ctx.global->acc_mgr, ctx.global->funk_txn, (fd_pubkey_t *) account, &crec, NULL);
  if (NULL != raw_acc_data) {
    fd_account_meta_t *m = (fd_account_meta_t *) raw_acc_data;

    if (instruction->discriminant == fd_system_program_instruction_enum_allocate) {
      if (memcmp(m->info.owner, ctx.global->solana_system_program, sizeof(m->info.owner)) != 0)
        return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
    }

    // This will get handled later in the set_data_length so.. maybe we don't need this here?
    if (m->dlen > 0)
      return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  if (allocate > MAX_PERMITTED_DATA_LENGTH)
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;

  fd_funk_rec_t *rec = NULL;
  err = 0;
  void *data = fd_acc_mgr_modify_raw(ctx.global->acc_mgr, ctx.global->funk_txn, account, 1, allocate, crec, &rec, &err);
  if (NULL == rec)
    return err;

  fd_account_meta_t *m = (fd_account_meta_t *) data;

  if (!fd_account_set_data_length(&ctx, m, account, allocate, 0, &err))
    return err;

  if (instruction->discriminant == fd_system_program_instruction_enum_allocate_with_seed) {
    err = fd_account_set_owner(&ctx, m, account, owner);
    if (FD_ACC_MGR_SUCCESS != err)
      return err;
  }

  err = fd_acc_mgr_commit_raw(ctx.global->acc_mgr, rec, account, data, ctx.global->bank.slot, 0);
  if (FD_ACC_MGR_SUCCESS != err)
    return err;

  return FD_ACC_MGR_SUCCESS;
}

// https://github.com/solana-labs/solana/blob/b00d18cec4011bb452e3fe87a3412a3f0146942e/runtime/src/system_instruction_processor.rs#L545
static int fd_system_assign_with_seed(
  instruction_ctx_t                                ctx,
  fd_system_program_instruction_assign_with_seed_t*t
  ) {
  int err = fd_account_sanity_check(&ctx, 1);
  if (FD_UNLIKELY(FD_EXECUTOR_INSTR_SUCCESS != err))
    return err;

  uchar const * instr_acc_idxs = ctx.instr->acct_txn_idxs;
  fd_pubkey_t * txn_accs = ctx.txn_ctx->accounts;
  fd_pubkey_t * account     = &txn_accs[instr_acc_idxs[0]];

  fd_pubkey_t      address_with_seed;
  fd_pubkey_create_with_seed( t->base.uc, t->seed, strlen( t->seed ), t->owner.uc, address_with_seed.uc );
  if (memcmp(address_with_seed.hash, account->hash, sizeof(account->hash))) {
    ctx.txn_ctx->custom_err = 5;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  fd_funk_rec_t const *crec = NULL;
  char * raw_acc_data = (char*) fd_acc_mgr_view_raw(ctx.global->acc_mgr, ctx.global->funk_txn, (fd_pubkey_t *) account, &crec, NULL);
  if (NULL != raw_acc_data) {
    fd_account_meta_t *m = (fd_account_meta_t *) raw_acc_data;

    if (memcmp(&t->owner, m->info.owner, sizeof(fd_pubkey_t)) == 0)
      return FD_ACC_MGR_SUCCESS;
  }

  if (!fd_instr_acc_is_signer(ctx.instr, &t->base))
    return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;

  fd_funk_rec_t *rec = NULL;
  err = 0;
  void *data = fd_acc_mgr_modify_raw(ctx.global->acc_mgr, ctx.global->funk_txn, account, 1, 0UL, crec, &rec, &err);
  if (NULL == rec)
    return err;

  fd_account_meta_t *m = (fd_account_meta_t *) data;

  if (memcmp(m->info.owner, ctx.global->solana_system_program, sizeof(m->info.owner)) != 0)
    return FD_EXECUTOR_INSTR_ERR_MODIFIED_PROGRAM_ID;

  err = fd_account_set_owner(&ctx, m, account, &t->owner);
  if (FD_ACC_MGR_SUCCESS != err)
    return err;

  err = fd_acc_mgr_commit_raw(ctx.global->acc_mgr, rec, account, data, ctx.global->bank.slot, 0);
  if (FD_ACC_MGR_SUCCESS != err)
    return err;

  return FD_ACC_MGR_SUCCESS;
}

static int create_account(
  instruction_ctx_t                ctx,
  fd_system_program_instruction_t *instruction
  ) {
  if (ctx.txn_ctx->txn_descriptor->acct_addr_cnt < 2) {
    return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
  }

  /* Account 0: funding account
     Account 1: new account
   */

  uchar const * instr_acc_idxs = ctx.instr->acct_txn_idxs;
  fd_pubkey_t * txn_accs = ctx.txn_ctx->accounts;
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

    fd_pubkey_create_with_seed( base->uc, seed, strlen( seed ), owner->uc, address_with_seed.uc );
    if (memcmp(address_with_seed.hash, to->hash, sizeof(to->hash)))
      return fd_system_error_enum_address_with_seed_mismatch;
  }

  // https://github.com/solana-labs/solana/blob/b9a2030537ba440c0378cc1ed02af7cff3f35141/programs/system/src/system_processor.rs#L146-L181

  if (!fd_instr_acc_is_signer(ctx.instr, from))
    return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
  if (!fd_instr_acc_is_signer(ctx.instr, base))
    return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;

  fd_funk_rec_t const * from_rec_ro = NULL;
  int err;
  char * raw_acc_data_from = (char*) fd_acc_mgr_view_raw(ctx.global->acc_mgr, ctx.global->funk_txn, (fd_pubkey_t *) from, &from_rec_ro, &err);
  if (err == FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT ) {
    ctx.txn_ctx->custom_err = 0; /* SystemError::AccountAlreadyInUse */
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  fd_account_meta_t *metadata = (fd_account_meta_t *) raw_acc_data_from;
  if (metadata->dlen > 0) {
    return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
  }

  fd_acc_lamports_t sender_lamports = metadata->info.lamports;

  if ( FD_UNLIKELY( sender_lamports < lamports ) ) {
    ctx.txn_ctx->custom_err = 1; /* SystemError::ResultWithNegativeLamports */
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  fd_funk_rec_t * from_rec_rw = NULL;
  raw_acc_data_from = fd_acc_mgr_modify_raw(ctx.global->acc_mgr, ctx.global->funk_txn, (fd_pubkey_t *) from, 0, 0UL, from_rec_ro, &from_rec_rw, &err);
  FD_TEST( raw_acc_data_from );
  ((fd_account_meta_t *) raw_acc_data_from)->info.lamports = sender_lamports - lamports;
  /* Execute the transfer */
  int write_result = fd_acc_mgr_commit_raw( ctx.global->acc_mgr, from_rec_rw, from, raw_acc_data_from, ctx.global->bank.slot, 0);
  if ( FD_UNLIKELY( write_result != FD_ACC_MGR_SUCCESS ) ) {
    return FD_EXECUTOR_INSTR_ERR_GENERIC_ERR;
  }

  /* Check to see if the account is already in use */
  err = FD_ACC_MGR_SUCCESS;
  fd_funk_rec_t const * to_rec_ro = NULL;
  char * raw_acc_data_to = (char *) fd_acc_mgr_view_raw(ctx.global->acc_mgr, ctx.global->funk_txn, to, &to_rec_ro, &err);
  if (err == FD_ACC_MGR_SUCCESS) {
    /* Check if account was deleted */
    metadata = (fd_account_meta_t *) raw_acc_data_to;
    if( metadata->info.lamports != 0 ) {
      ctx.txn_ctx->custom_err = 0;     /* SystemError::AccountAlreadyInUse */
      return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
    }
  } else if (err != FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT ) {
    ctx.txn_ctx->custom_err = 0;     /* SystemError::AccountAlreadyInUse */
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  if (!fd_instr_acc_is_signer(ctx.instr, to)) {
    return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
  }

  if (metadata->dlen != 0 || memcmp(metadata->info.owner, ctx.global->solana_system_program, sizeof(fd_pubkey_t)) != 0) {
    ctx.txn_ctx->custom_err = 0;     /* SystemError::AccountAlreadyInUse */
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }
  ulong sz2 = space + sizeof(fd_account_meta_t);
  fd_funk_rec_t * to_rec_rw = NULL;
  raw_acc_data_to = (char*) fd_acc_mgr_modify_raw(ctx.global->acc_mgr, ctx.global->funk_txn, (fd_pubkey_t *) to, 1, sz2, to_rec_ro, &to_rec_rw, &err);
  FD_TEST( raw_acc_data_to );
  /* Check that we are not exceeding the MAX_PERMITTED_DATA_LENGTH account size */
  if ( space > MAX_PERMITTED_DATA_LENGTH ) {
    ctx.txn_ctx->custom_err = 3;     /* SystemError::InvalidAccountDataLength */
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  if( !FD_FEATURE_ACTIVE( ctx.global, system_transfer_zero_check ) && lamports == 0) {
    return FD_EXECUTOR_INSTR_SUCCESS;
  }

  metadata = (fd_account_meta_t *) raw_acc_data_to;
  metadata->info.lamports = lamports;
  metadata->dlen = space;
  metadata->info.executable = 0;
  metadata->info.rent_epoch = 0;
  /* Initialize the account with all zeroed data and the correct owner */
  fd_memcpy( &metadata->info.owner, owner, sizeof(fd_pubkey_t) );
  memset( raw_acc_data_to + metadata->hlen, 0, space );

  write_result = fd_acc_mgr_commit_raw( ctx.global->acc_mgr, to_rec_rw, to, raw_acc_data_to, ctx.global->bank.slot, 0);
  if ( FD_UNLIKELY( write_result != FD_ACC_MGR_SUCCESS ) ) {
    FD_LOG_NOTICE(( "failed to create account: %d", write_result ));
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  return FD_EXECUTOR_INSTR_SUCCESS;
}

// https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/runtime/src/system_instruction_processor.rs#L321-L326
// https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/runtime/src/system_instruction_processor.rs#L111
static int assign(
  instruction_ctx_t ctx,
  fd_pubkey_t       owner
  ) {
  int err = fd_account_sanity_check(&ctx, 1);
  if (FD_UNLIKELY(FD_EXECUTOR_INSTR_SUCCESS != err))
    return err;

  /* Pull out the account to be assigned an owner (acc idx 0) */
  uchar *       instr_acc_idxs = ctx.instr->acct_txn_idxs;
  fd_pubkey_t * txn_accs = ctx.txn_ctx->accounts;
  fd_pubkey_t * keyed_account   = &txn_accs[instr_acc_idxs[0]];

  fd_account_meta_t * meta = NULL;
  int read_result = fd_acc_mgr_modify( ctx.global->acc_mgr, ctx.global->funk_txn, keyed_account, /* do_create */ 0, 0UL, NULL, NULL, &meta, NULL );
  if( FD_UNLIKELY( read_result!=FD_ACC_MGR_SUCCESS ) )
    return FD_EXECUTOR_INSTR_ERR_GENERIC_ERR;

  // no work to do when owner is the same
  // #ifdef current_owner
  if( 0==memcmp( meta->info.owner, owner.key, sizeof(fd_pubkey_t)) )
    return FD_EXECUTOR_INSTR_SUCCESS;
  // #endif

  if (!fd_instr_acc_is_signer(ctx.instr, keyed_account))
    return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;

  memcpy( meta->info.owner, owner.key, sizeof(fd_pubkey_t) );
  return FD_EXECUTOR_INSTR_SUCCESS;
}

int fd_executor_system_program_execute_instruction(
  instruction_ctx_t ctx
  ) {
  /* Deserialize the SystemInstruction enum */
  uchar *      data            = ctx.instr->data;

  fd_system_program_instruction_t instruction;
  fd_system_program_instruction_new( &instruction );
  fd_bincode_decode_ctx_t ctx2;
  ctx2.data = data;
  ctx2.dataend = &data[ctx.instr->data_sz];
  ctx2.valloc  = ctx.global->valloc;
  if ( fd_system_program_instruction_decode( &instruction, &ctx2 ) ) {
    FD_LOG_WARNING(("fd_system_program_instruction_decode failed"));
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  }

  int   result = FD_EXECUTOR_INSTR_ERR_INVALID_ARG;

  switch (instruction.discriminant) {
  case fd_system_program_instruction_enum_transfer: {
    result = transfer( ctx, &instruction );
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
  case fd_system_program_instruction_enum_allocate: {
    result = fd_system_allocate( ctx, &instruction );
    break;
  }
  case fd_system_program_instruction_enum_allocate_with_seed: {
    // https://github.com/solana-labs/solana/blob/b00d18cec4011bb452e3fe87a3412a3f0146942e/runtime/src/system_instruction_processor.rs#L525
    result = fd_system_allocate( ctx, &instruction );
    break;
  }
  case fd_system_program_instruction_enum_assign_with_seed: {
    // https://github.com/solana-labs/solana/blob/b00d18cec4011bb452e3fe87a3412a3f0146942e/runtime/src/system_instruction_processor.rs#L545
    result = fd_system_assign_with_seed( ctx, &instruction.inner.assign_with_seed );
    break;
  }
  case fd_system_program_instruction_enum_transfer_with_seed: {
    // https://github.com/solana-labs/solana/blob/b00d18cec4011bb452e3fe87a3412a3f0146942e/runtime/src/system_instruction_processor.rs#L412
    result = transfer( ctx, &instruction );
    break;
  }
  case fd_system_program_instruction_enum_upgrade_nonce_account: {
    // https://github.com/solana-labs/solana/blob/b00d18cec4011bb452e3fe87a3412a3f0146942e/runtime/src/system_instruction_processor.rs#L491
    result = fd_upgrade_nonce_account( ctx );
    break;
  }
  default: {
    /* TODO: support other instruction types */
    FD_LOG_WARNING(( "unsupported system program instruction: discriminant: %d", instruction.discriminant ));
  }
  }

  fd_bincode_destroy_ctx_t ctx3 = { .valloc = ctx.global->valloc };
  fd_system_program_instruction_destroy( &instruction, &ctx3 );
  return result;
}
