#include "../fd_executor.h"
#include "fd_system_program.h"
#include "../fd_acc_mgr.h"
#include "../fd_account.h"
#include "../fd_runtime.h"
#include "../sysvar/fd_sysvar_rent.h"
#include "../sysvar/fd_sysvar.h"
#include "../../../ballet/base58/fd_base58.h"

// ~/repos/solana/web3.js/src/system-program.ts

// NonceError::NoRecentBlockhashes => FD_EXECUTOR_SYSTEM_ERR_NONCE_NO_RECENT_BLOCKHASHES,
// NonceError::NotExpired          => FD_EXECUTOR_SYSTEM_ERR_NONCE_BLOCKHASH_NOT_EXPIRED,
// NonceError::UnexpectedValue     => FD_EXECUTOR_SYSTEM_ERR_NONCE_UNEXPECTED_BLOCKHASH_VALUE,
// NonceError::BadAccountState     => FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA

static char DURABLE_NONCE_HASH_PREFIX[] = "DURABLE_NONCE";

void fd_durable_nonce_from_blockhash(fd_hash_t *hash, fd_hash_t *out) {
// https://github.com/firedancer-io/solana/blob/ffd63324f988e1b2151dab34983c71d6ff4087f6/runtime/src/nonce_keyed_account.rs#L55
  fd_sha256_t sha;
  fd_sha256_init( &sha );
  fd_sha256_append( &sha, (uchar const *) DURABLE_NONCE_HASH_PREFIX, sizeof(DURABLE_NONCE_HASH_PREFIX) - 1);
  fd_sha256_append( &sha, hash->hash, 32);
  fd_sha256_fini( &sha, out->hash );
}

int fd_load_nonce_account( fd_exec_txn_ctx_t * txn_ctx, 
                           fd_txn_t * txn_descriptor, 
                           fd_rawtxn_b_t const * txn_raw, 
                           fd_nonce_state_versions_t * state,
                           int * opt_err ) {
  if (txn_descriptor->instr_cnt == 0) {
    *opt_err = FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
    return 0;
  }

  fd_txn_instr_t * txn_instr = &txn_descriptor->instr[0];
  fd_instr_info_t instr;
  fd_convert_txn_instr_to_instr(txn_descriptor, txn_raw, txn_instr, txn_ctx->accounts, txn_ctx->borrowed_accounts, &instr);

  // A little defense in depth?
  int err = fd_account_sanity_check_raw(&instr, txn_descriptor->acct_addr_cnt, instr.program_id + 1);
  if (FD_EXECUTOR_INSTR_SUCCESS != err) {
    *opt_err = err;
    return 0;
  }

  fd_pubkey_t * tx_accs   = (fd_pubkey_t *)((uchar *)txn_raw->raw + txn_descriptor->acct_addr_off);
  fd_pubkey_t * pubkey = &tx_accs[instr.program_id];

  if ( memcmp( pubkey, fd_solana_system_program_id.key, sizeof( fd_pubkey_t ) ) )
    return 0;

  /* Deserialize the SystemInstruction enum */
  uchar *      data            = instr.data;

  fd_system_program_instruction_t instruction;
  fd_bincode_decode_ctx_t ctx2 = {
    .data = data,
    .dataend = &data[instr.data_sz],
    .valloc  = txn_ctx->valloc
  };
  if ( fd_system_program_instruction_decode( &instruction, &ctx2 ) ) {
    FD_LOG_WARNING(("fd_system_program_instruction_decode failed"));
    *opt_err = FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
    return 0;
  }

  if (fd_system_program_instruction_enum_advance_nonce_account != instruction.discriminant)
    return 0;

  err = fd_account_sanity_check_raw(&instr, txn_descriptor->acct_addr_cnt, 3);
  if (FD_UNLIKELY(FD_EXECUTOR_INSTR_SUCCESS != err)) {
    *opt_err = err;
    return 0;
  }

  uchar *       instr_acc_idxs = instr.acct_txn_idxs;
  fd_pubkey_t * me   = &tx_accs[instr_acc_idxs[0]];

  // https://github.com/firedancer-io/solana/blob/ffd63324f988e1b2151dab34983c71d6ff4087f6/runtime/src/nonce_keyed_account.rs#L66


  FD_BORROWED_ACCOUNT_DECL(me_rec);
  err = fd_acc_mgr_view(txn_ctx->acc_mgr, txn_ctx->funk_txn, (fd_pubkey_t *) me, me_rec);
  if( FD_UNLIKELY( err != FD_ACC_MGR_SUCCESS ) ) {
    *opt_err = FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
    return 0;
  }

  fd_bincode_decode_ctx_t ctx = {
    .data = me_rec->const_data,
    .dataend = me_rec->const_data + me_rec->const_meta->dlen,
    .valloc  = txn_ctx->valloc
  };

  if ( fd_nonce_state_versions_decode( state, &ctx ) ) {
    FD_LOG_WARNING(("fd_nonce_state_versions_decode failed"));
    *opt_err = FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
    return 0;
  }

  return 1;
}

// https://github.com/firedancer-io/solana/blob/8fb537409eb901444e064f50ea8dd7dcafb12a00/runtime/src/system_instruction_processor.rs#L351
int fd_advance_nonce_account( fd_exec_instr_ctx_t ctx ) {
//        {pubkey: params.noncePubkey, isSigner: false, isWritable: true},
//        {pubkey: SYSVAR_RECENT_BLOCKHASHES_PUBKEY, isSigner: false, isWritable: false,},
//        {pubkey: params.authorizedPubkey, isSigner: true, isWritable: false},
  if (ctx.txn_ctx->txn_descriptor->acct_addr_cnt < 2) {
    return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
  }

  uchar const * instr_acc_idxs = ctx.instr->acct_txn_idxs;

  if (!fd_instr_acc_is_writable_idx(ctx.instr, 0))
    return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;

  fd_pubkey_t const * txn_accs = ctx.txn_ctx->accounts;
  fd_pubkey_t const * me = &txn_accs[instr_acc_idxs[0]];

  if (0 != memcmp(&txn_accs[instr_acc_idxs[1]], fd_sysvar_recent_block_hashes_id.key, sizeof(fd_pubkey_t))) {
    return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
  }

  // https://github.com/firedancer-io/solana/blob/ffd63324f988e1b2151dab34983c71d6ff4087f6/runtime/src/nonce_keyed_account.rs#L66


  FD_BORROWED_ACCOUNT_DECL(me_rec);
  int err = fd_acc_mgr_view(ctx.acc_mgr, ctx.funk_txn, (fd_pubkey_t *) me, me_rec);
   if (FD_UNLIKELY( err != FD_ACC_MGR_SUCCESS))
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;

  fd_nonce_state_versions_t state;
  fd_bincode_decode_ctx_t ctx2 = {
    .data = me_rec->const_data,
    .dataend = me_rec->const_data + me_rec->const_meta->dlen,
    .valloc  = ctx.valloc
  };
  if ( fd_nonce_state_versions_decode( &state, &ctx2 ) )
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;

  if (state.inner.current.discriminant != fd_nonce_state_enum_initialized)
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;

//                if !signers.contains(&data.authority) {
//                    ic_msg!(
//                        invoke_context,
//                        "Advance nonce account: Account {} must be a signer",
//                        data.authority
//                    );
//                    return Err(InstructionError::MissingRequiredSignature);
//                }

  if (!fd_instr_acc_is_signer(ctx.instr, &state.inner.current.inner.initialized.authority))
    return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;

  //if ( memcmp( authorized, state.inner.current.inner.initialized.authority.hash, sizeof(fd_pubkey_t) ) )
  //return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;

//                let (next_durable_nonce, separate_domains) = get_durable_nonce(invoke_context);

  fd_block_block_hash_entry_t * hashes = ctx.slot_ctx->bank.recent_block_hashes.hashes;
  if ( deq_fd_block_block_hash_entry_t_cnt( hashes ) == 0) {
    ctx.txn_ctx->custom_err = 6;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  fd_block_block_hash_entry_t *re = deq_fd_block_block_hash_entry_t_peek_head( hashes );

  fd_hash_t durable_nonce;
  fd_durable_nonce_from_blockhash(&re->blockhash, &durable_nonce);

//                if data.durable_nonce == next_durable_nonce {
//                    ic_msg!(
//                        invoke_context,
//                        "Advance nonce account: nonce can only advance once per slot"
//                    );
//                    return Err(nonce_to_instruction_error(
//                        NonceError::NotExpired,
//                        merge_nonce_error_into_system_error,
//                    ));
//                }

  if (!memcmp(state.inner.current.inner.initialized.durable_nonce.hash, durable_nonce.hash, sizeof(state.inner.current.inner.initialized.durable_nonce.hash)))
    return FD_EXECUTOR_SYSTEM_ERR_NONCE_BLOCKHASH_NOT_EXPIRED;


//                let new_data = nonce::state::Data::new(
//                    data.authority,
//                    next_durable_nonce,
//                    invoke_context.lamports_per_signature,
//                );

  state.discriminant = fd_nonce_state_versions_enum_current;
  fd_memcpy(state.inner.current.inner.initialized.durable_nonce.hash, durable_nonce.hash, sizeof(state.inner.current.inner.initialized.durable_nonce.hash));
  state.inner.current.inner.initialized.fee_calculator.lamports_per_signature = fd_runtime_lamports_per_signature(&ctx.slot_ctx->bank);

//                self.set_state(&Versions::new(
//                    State::Initialized(new_data),
//                    separate_domains,
//                ))

  ulong          sz = fd_nonce_state_versions_size(&state);
  unsigned char *enc = fd_alloca_check(1, sz);
  memset(enc, 0, sz);
  fd_bincode_encode_ctx_t ctx3 = {
    .data = enc,
    .dataend = enc + sz
  };
  if ( fd_nonce_state_versions_encode(&state, &ctx3) )
    FD_LOG_ERR(("fd_nonce_state_versions_encode failed"));

  err = 0;
  if (!fd_account_check_set_data_length(&ctx, me_rec->const_meta, me, sz, &err))
    return err;

  err = fd_acc_mgr_modify(ctx.acc_mgr, ctx.funk_txn, me, 1, sz, me_rec);
  if (FD_UNLIKELY( err != FD_ACC_MGR_SUCCESS))
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;

  me_rec->meta->dlen = sz;
  fd_memcpy(me_rec->data, enc, sz);

  return fd_acc_mgr_commit(ctx.acc_mgr, me_rec, ctx.slot_ctx);
}

// https://github.com/firedancer-io/solana/blob/8fb537409eb901444e064f50ea8dd7dcafb12a00/runtime/src/system_instruction_processor.rs#L366
int fd_withdraw_nonce_account(
  fd_exec_instr_ctx_t               ctx,
  unsigned long                   requested_lamports
  )
{

  if (ctx.txn_ctx->txn_descriptor->acct_addr_cnt < 2) {
    return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
  }

  uchar const * instr_acc_idxs = ctx.instr->acct_txn_idxs;

  if (!fd_instr_acc_is_writable_idx(ctx.instr, 0) || !fd_instr_acc_is_writable_idx(ctx.instr, 1))
    return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;

  fd_pubkey_t * txn_accs = ctx.txn_ctx->accounts;
  fd_pubkey_t * from   = &txn_accs[instr_acc_idxs[0]];
  fd_pubkey_t * to  = &txn_accs[instr_acc_idxs[1]];

  fd_borrowed_account_t * from_rec = NULL;
  int err = fd_instr_borrowed_account_view(&ctx,  (fd_pubkey_t *) from, & from_rec);
  if( FD_UNLIKELY( err != FD_ACC_MGR_SUCCESS ) )
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;

  fd_nonce_state_versions_t state;
  fd_bincode_decode_ctx_t ctx2 = {
    .data = from_rec->const_data,
    .dataend = from_rec->const_data + from_rec->const_meta->dlen,
    .valloc  = ctx.valloc
  };
  if ( fd_nonce_state_versions_decode( &state, &ctx2 ) )
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;

  switch (state.inner.current.discriminant) {
  case fd_nonce_state_enum_uninitialized: {
    // Why are we not also checking rent here?
    if ( FD_UNLIKELY( from_rec->const_meta->info.lamports < requested_lamports ) )
      return FD_EXECUTOR_INSTR_ERR_INSUFFICIENT_FUNDS;
    break;
  }
  case fd_nonce_state_enum_initialized: {
    if (  from_rec->const_meta->info.lamports == requested_lamports ) {
      if (deq_fd_block_block_hash_entry_t_cnt(ctx.slot_ctx->bank.recent_block_hashes.hashes) == 0)
        return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;

      fd_block_block_hash_entry_t *re = deq_fd_block_block_hash_entry_t_peek_head(ctx.slot_ctx->bank.recent_block_hashes.hashes);
      fd_hash_t                    durable_nonce;
      fd_durable_nonce_from_blockhash(&re->blockhash, &durable_nonce);
      if (!memcmp(state.inner.current.inner.initialized.durable_nonce.hash, durable_nonce.hash, sizeof(state.inner.current.inner.initialized.durable_nonce.hash)))
        return FD_EXECUTOR_SYSTEM_ERR_NONCE_BLOCKHASH_NOT_EXPIRED;

      state.inner.current.discriminant = fd_nonce_state_enum_uninitialized;

    } else {
      ulong minimum_rent_exempt_balance = fd_rent_exempt_minimum_balance( ctx.slot_ctx, from_rec->const_meta->dlen );
      ulong amount = fd_ulong_sat_add(from_rec->const_meta->info.lamports, minimum_rent_exempt_balance);
      if ( FD_UNLIKELY (amount > from_rec->const_meta->info.lamports) )
        return FD_EXECUTOR_INSTR_ERR_INSUFFICIENT_FUNDS;
    }
    break;
  }
  default: {
    FD_LOG_NOTICE(( "garbage nonce state" ));
    // TODO: What is the correct error?!
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }
  }

  if (!fd_instr_acc_is_signer(ctx.instr, from))
    return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;

  fd_borrowed_account_t * to_rec = NULL;
  ulong              res = requested_lamports;

  err = fd_instr_borrowed_account_view(&ctx,  (fd_pubkey_t *) to, & to_rec);

  if( FD_UNLIKELY( err == FD_ACC_MGR_SUCCESS ) ) {
    res = fd_ulong_sat_add(res, to_rec->const_meta->info.lamports);
    if (ULONG_MAX == res)
      return FD_EXECUTOR_INSTR_ERR_ARITHMETIC_OVERFLOW;
  }

  FD_TEST (requested_lamports <= from_rec->const_meta->info.lamports);

  // Ok, time to do some damage...
  err = fd_instr_borrowed_account_modify(&ctx,  from,  0,  0UL, & from_rec);
  err = fd_instr_borrowed_account_modify(&ctx,  to,  1,  0UL, & to_rec);

  from_rec->meta->info.lamports -= requested_lamports;
  to_rec->meta->info.lamports = res;

  err = fd_acc_mgr_commit(ctx.acc_mgr, from_rec, ctx.slot_ctx);
  if (FD_EXECUTOR_INSTR_SUCCESS != err)
    return err;
  return fd_acc_mgr_commit(ctx.acc_mgr, to_rec, ctx.slot_ctx);
}

// https://github.com/firedancer-io/solana/blob/8fb537409eb901444e064f50ea8dd7dcafb12a00/runtime/src/system_instruction_processor.rs#L380

// let tx = new Transaction();
//  tx.add(
//    // create nonce account
//    SystemProgram.createAccount({
//      fromPubkey: FEE_PAYER.publicKey,
//      newAccountPubkey: nonceAccount.publicKey,
//      lamports: await CONNECTION.getMinimumBalanceForRentExemption(NONCE_ACCOUNT_LENGTH),
//      space: NONCE_ACCOUNT_LENGTH,
//      programId: SystemProgram.programId,
//    }),
//    // init nonce account
//    SystemProgram.nonceInitialize({
//      noncePubkey: nonceAccount.publicKey, // nonce account pubkey
//      authorizedPubkey: FEE_PAYER.publicKey, // nonce account auth
//    })
//  );

// https://github.com/firedancer-io/solana/blob/8fb537409eb901444e064f50ea8dd7dcafb12a00/runtime/src/system_instruction_processor.rs#L380
int fd_initialize_nonce_account(
  fd_exec_instr_ctx_t   ctx,
  fd_pubkey_t        *initialize_nonce_account
  ) {
  if (ctx.txn_ctx->txn_descriptor->acct_addr_cnt < 2) {
    return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
  }

  if (!fd_instr_acc_is_writable_idx(ctx.instr, 0))
    return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;

  fd_pubkey_t * txn_accs = ctx.txn_ctx->accounts;
  uchar const * instr_acc_idxs = ctx.instr->acct_txn_idxs;

  fd_pubkey_t * me   = &txn_accs[instr_acc_idxs[0]];

  if (0 != memcmp(&txn_accs[instr_acc_idxs[1]], fd_sysvar_recent_block_hashes_id.key, sizeof(fd_pubkey_t))) {
    return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
  }
  if (!fd_instr_acc_is_signer_idx(ctx.instr, 0))
    return FD_EXECUTOR_INSTR_ERR_INVALID_ARG; // Really? This was the error?!

  fd_borrowed_account_t * me_rec = NULL;
  int err = fd_instr_borrowed_account_view(&ctx,  (fd_pubkey_t *) me, & me_rec);
  if( FD_UNLIKELY( err != FD_ACC_MGR_SUCCESS ) )
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;

  fd_nonce_state_versions_t state;
  fd_bincode_decode_ctx_t ctx2 = {
    .data = me_rec->const_data,
    .dataend = me_rec->const_data + me_rec->const_meta->dlen,
    .valloc  = ctx.valloc
  };

  if ( fd_nonce_state_versions_decode( &state, &ctx2 ) ) {
    FD_LOG_WARNING(("fd_nonce_state_versions_decode failed"));
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  }

  switch (state.inner.current.discriminant) {
  case fd_nonce_state_enum_uninitialized: {
    ulong minimum_rent_exempt_balance = fd_rent_exempt_minimum_balance( ctx.slot_ctx, me_rec->const_meta->dlen );
    if ( me_rec->const_meta->info.lamports < minimum_rent_exempt_balance )
      return FD_EXECUTOR_INSTR_ERR_INSUFFICIENT_FUNDS;

    fd_block_block_hash_entry_t * hashes = ctx.slot_ctx->bank.recent_block_hashes.hashes;
    if ( deq_fd_block_block_hash_entry_t_cnt( hashes ) == 0) {
      ctx.txn_ctx->custom_err = 6;
      return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
    }

    fd_block_block_hash_entry_t *re = deq_fd_block_block_hash_entry_t_peek_head( hashes );

    fd_hash_t durable_nonce;
    fd_durable_nonce_from_blockhash(&re->blockhash, &durable_nonce);

    state.inner.current.discriminant = fd_nonce_state_enum_initialized;
    state.discriminant = fd_nonce_state_versions_enum_current;

    state.inner.current.inner.initialized.authority = *initialize_nonce_account;
    fd_memcpy(state.inner.current.inner.initialized.durable_nonce.hash, durable_nonce.hash, sizeof(state.inner.current.inner.initialized.durable_nonce.hash));
    state.inner.current.inner.initialized.fee_calculator.lamports_per_signature = fd_runtime_lamports_per_signature_for_blockhash(ctx.slot_ctx, &re->blockhash);

    ulong          sz = fd_nonce_state_versions_size(&state);

    int err = 0;
    if (!fd_account_check_set_data_length(&ctx, me_rec->const_meta, me, sz, &err))
      return err;

    err = fd_instr_borrowed_account_modify(&ctx,  me,  1,  sz, & me_rec );
    if( FD_UNLIKELY( err != FD_ACC_MGR_SUCCESS ) )
      return err;

    fd_bincode_encode_ctx_t ctx4 = {
      .data = me_rec->data,
      .dataend = me_rec->data + sz
    };
    if ( fd_nonce_state_versions_encode(&state, &ctx4) )
      FD_LOG_ERR(("fd_nonce_state_versions_encode failed"));

    me_rec->meta->dlen = sz;
    return fd_acc_mgr_commit(ctx.acc_mgr, me_rec, ctx.slot_ctx);
  }

  case fd_nonce_state_enum_initialized: {
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  }
  default: {
    FD_LOG_NOTICE(( "garbage nonce state" ));
    // TODO: What is the correct error?!
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }
  }

  return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
}

// https://github.com/firedancer-io/solana/blob/8fb537409eb901444e064f50ea8dd7dcafb12a00/runtime/src/system_instruction_processor.rs#L400
int fd_authorize_nonce_account(
  fd_exec_instr_ctx_t   ctx,
  fd_pubkey_t        *authorize_nonce_account
  ) {
//        {pubkey: params.noncePubkey, isSigner: false, isWritable: true},
//        {pubkey: params.authorizedPubkey, isSigner: true, isWritable: false},

  if (ctx.txn_ctx->txn_descriptor->acct_addr_cnt < 1) {
    return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
  }

  uchar const * instr_acc_idxs = ctx.instr->acct_txn_idxs;
  fd_pubkey_t * txn_accs = ctx.txn_ctx->accounts;

  if (!fd_instr_acc_is_writable_idx(ctx.instr, 0))
    return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;

  fd_pubkey_t const *       me           = &txn_accs[instr_acc_idxs[0]];
  fd_borrowed_account_t  * rec = fd_borrowed_account_init(fd_alloca(FD_BORROWED_ACCOUNT_ALIGN, FD_BORROWED_ACCOUNT_FOOTPRINT));

  int err = fd_instr_borrowed_account_view(&ctx,  me, & rec );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_WARNING(( "fd_acc_mgr_view failed: %d", err ));
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  int ret = -1;

  fd_nonce_state_versions_t state;
  fd_bincode_decode_ctx_t ctx2;
  ctx2.data    = rec->const_data;
  ctx2.dataend = rec->const_data + rec->const_meta->dlen;
  ctx2.valloc  = ctx.valloc;
  if ( fd_nonce_state_versions_decode( &state, &ctx2 ) )
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;

  do {
    if (state.inner.current.discriminant != fd_nonce_state_enum_initialized) {
      ret = FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
      break;
    }

    if (!fd_instr_acc_is_signer(ctx.instr, &state.inner.current.inner.initialized.authority)) {
      ret = FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
      break;
    }

    state.discriminant = fd_nonce_state_versions_enum_current;
    state.inner.current.inner.initialized.authority = *authorize_nonce_account;

    ulong          sz = fd_nonce_state_versions_size(&state);
    err = fd_instr_borrowed_account_modify(&ctx,  me,  1,  sz, & rec );
    if( FD_UNLIKELY( err ) ) {
      FD_LOG_WARNING(( "fd_acc_mgr_modify failed: %d", err ));
      ret = FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
      break;
    }

    fd_bincode_encode_ctx_t ctx3;
    ctx3.data = rec->data;
    ctx3.dataend = rec->data + sz;
    if ( fd_nonce_state_versions_encode(&state, &ctx3) ) {
      ret = FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
      break;
    }

    rec->meta->dlen = sz;

    ret = FD_EXECUTOR_INSTR_SUCCESS;
  } while (0);

  fd_bincode_destroy_ctx_t ctx3;
  ctx3.valloc = ctx.valloc;
  fd_nonce_state_versions_destroy( &state, &ctx3 );

  return ret;
}

int fd_upgrade_nonce_account(
  fd_exec_instr_ctx_t   ctx
  ) {
//            instruction_context.check_number_of_instruction_accounts(1)?;
//            let mut nonce_account =
//                instruction_context.try_borrow_instruction_account(transaction_context, 0)?;
//            if !system_program::check_id(nonce_account.get_owner()) {
//                return Err(InstructionError::InvalidAccountOwner);
//            }
//            if !nonce_account.is_writable() {
//                return Err(InstructionError::InvalidArgument);
//            }
//            let nonce_versions: nonce::state::Versions = nonce_account.get_state()?;
//            match nonce_versions.upgrade() {
//                None => Err(InstructionError::InvalidArgument),
//                Some(nonce_versions) => nonce_account.set_state(&nonce_versions),
//            }

// https://github.com/solana-labs/solana/blob/b00d18cec4011bb452e3fe87a3412a3f0146942e/runtime/src/system_instruction_processor.rs#L491

  if (ctx.txn_ctx->txn_descriptor->acct_addr_cnt < 1) {
    return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
  }

  fd_pubkey_t * txn_accs = ctx.txn_ctx->accounts;
  uchar const * instr_acc_idxs = ctx.instr->acct_txn_idxs;
  fd_pubkey_t *             me             = &txn_accs[instr_acc_idxs[0]];
  fd_borrowed_account_t * acc = NULL;

  int err = fd_instr_borrowed_account_view(&ctx,  me, & acc );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_WARNING(( "fd_acc_mgr_view failed: %d", err ));
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  if (memcmp(acc->const_meta->info.owner, fd_solana_system_program_id.key, sizeof(acc->const_meta->info.owner)) != 0)
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_OWNER;

  if (!fd_instr_acc_is_writable_idx(ctx.instr, 0))
    return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;

  fd_nonce_state_versions_t state;
  fd_bincode_decode_ctx_t ctx2;
  ctx2.data    = acc->const_data;
  ctx2.dataend = acc->const_data + acc->const_meta->dlen;
  ctx2.valloc  = ctx.valloc;

  if ( fd_nonce_state_versions_decode( &state, &ctx2 ) ) {
    FD_LOG_WARNING(("fd_nonce_state_versions_decode failed"));
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  }

  int ret = 0;
  do {
    if (state.discriminant != fd_nonce_state_versions_enum_legacy) {
      ret = FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
      break;
    }

    if (state.inner.legacy.discriminant != fd_nonce_state_enum_initialized) {
      ret = FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
      break;
    }

    fd_hash_t durable_nonce;
    fd_durable_nonce_from_blockhash(&state.inner.legacy.inner.initialized.durable_nonce, &durable_nonce);

    state.discriminant = fd_nonce_state_versions_enum_current;
    memcpy(&state.inner.current.inner.initialized.durable_nonce, &durable_nonce, sizeof(durable_nonce));

    ulong          sz = fd_nonce_state_versions_size(&state);
    err = fd_instr_borrowed_account_modify(&ctx,  me,  1,  sz, & acc );
    if( FD_UNLIKELY( err ) ) {
      FD_LOG_WARNING(( "fd_acc_mgr_modify failed: %d", err ));
      ret = FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
      break;
    }

    fd_bincode_encode_ctx_t ctx3;
    ctx3.data = acc->data;
    ctx3.dataend = acc->data + sz;
    if ( fd_nonce_state_versions_encode(&state, &ctx3) ) {
      FD_LOG_WARNING(("fd_nonce_state_versions_encode failed"));
      ret = -1;
      break;
    }

    acc->meta->dlen = sz;

    ret = FD_EXECUTOR_INSTR_SUCCESS;
  } while (false);

  fd_bincode_destroy_ctx_t ctx3 = { .valloc = ctx.valloc };
  fd_nonce_state_versions_destroy( &state, &ctx3 );

  return ret;
}
