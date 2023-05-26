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

int fd_load_nonce_account(
  fd_global_ctx_t *global, fd_txn_t * txn_descriptor, fd_rawtxn_b_t* txn_raw, fd_nonce_state_versions_t *state
) {
  fd_txn_instr_t * instr = &txn_descriptor->instr[0];
  fd_pubkey_t *tx_accs   = (fd_pubkey_t *)((uchar *)txn_raw->raw + txn_descriptor->acct_addr_off);
  fd_pubkey_t *pubkey = &tx_accs[instr->program_id];

  if ( memcmp( pubkey, global->solana_system_program, sizeof( fd_pubkey_t ) ) ) 
    return 0;

  /* Deserialize the SystemInstruction enum */
  uchar *      data            = (uchar *)txn_raw->raw + instr->data_off;
  void*        input            = (void *)data;
  const void** input_ptr = (const void **)&input;
  void*        dataend          = (void*)&data[instr->data_sz];

  fd_system_program_instruction_t instruction;
  fd_system_program_instruction_decode( &instruction, input_ptr, dataend, global->allocf, global->allocf_arg );

  if (fd_system_program_instruction_enum_advance_nonce_account != instruction.discriminant)
    return 0;

  if (instr->acct_cnt != 3)
    return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;

  uchar *       instr_acc_idxs = ((uchar *)txn_raw->raw + instr->acct_off);

  ulong acct_addr_cnt = txn_descriptor->acct_addr_cnt;
  if ((instr_acc_idxs[0] >= acct_addr_cnt) | (instr_acc_idxs[1] >= acct_addr_cnt))
    return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;

  fd_pubkey_t * me   = &tx_accs[instr_acc_idxs[0]];

  // https://github.com/firedancer-io/solana/blob/ffd63324f988e1b2151dab34983c71d6ff4087f6/runtime/src/nonce_keyed_account.rs#L66

  fd_account_meta_t metadata;
  long              read_result = fd_acc_mgr_get_metadata( global->acc_mgr, global->funk_txn, me, &metadata );
  if ( read_result == FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT ) 
    return 0;

  unsigned char *raw_acc_data = fd_alloca( 1, metadata.dlen );
  read_result = fd_acc_mgr_get_account_data( global->acc_mgr, global->funk_txn, (fd_pubkey_t *) me, raw_acc_data, metadata.hlen, metadata.dlen );
  if ( read_result != FD_ACC_MGR_SUCCESS ) 
    return 0;

  input = (void *)raw_acc_data;
  fd_nonce_state_versions_decode( state, (const void **) &input, raw_acc_data + metadata.dlen, global->allocf, global->allocf_arg );

  return 1;
}

// https://github.com/firedancer-io/solana/blob/8fb537409eb901444e064f50ea8dd7dcafb12a00/runtime/src/system_instruction_processor.rs#L351
int fd_advance_nonce_account(
  instruction_ctx_t ctx
  ) {
//        {pubkey: params.noncePubkey, isSigner: false, isWritable: true},
//        {pubkey: SYSVAR_RECENT_BLOCKHASHES_PUBKEY, isSigner: false, isWritable: false,},
//        {pubkey: params.authorizedPubkey, isSigner: true, isWritable: false},

  if (ctx.instr->acct_cnt != 3)
    return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;

  uchar *       instr_acc_idxs = ((uchar *)ctx.txn_raw->raw + ctx.instr->acct_off);
  fd_pubkey_t * txn_accs = (fd_pubkey_t *)((uchar *)ctx.txn_raw->raw + ctx.txn_descriptor->acct_addr_off);

  ulong acct_addr_cnt = ctx.txn_descriptor->acct_addr_cnt;
  if ((instr_acc_idxs[0] >= acct_addr_cnt) | (instr_acc_idxs[1] >= acct_addr_cnt))
    // TODO: confirm what this would look like in solana
    return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;

  fd_pubkey_t * me   = &txn_accs[instr_acc_idxs[0]];
  //fd_pubkey_t * blockhash   = &txn_accs[instr_acc_idxs[1]];
  //fd_pubkey_t * authorized   = &txn_accs[instr_acc_idxs[2]];

  // https://github.com/firedancer-io/solana/blob/ffd63324f988e1b2151dab34983c71d6ff4087f6/runtime/src/nonce_keyed_account.rs#L66

  fd_account_meta_t metadata;
  long              read_result = fd_acc_mgr_get_metadata( ctx.global->acc_mgr, ctx.global->funk_txn, me, &metadata );
  if ( read_result == FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT ) {
    // TODO: What is the correct error?!
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  unsigned char *raw_acc_data = fd_alloca( 1, metadata.dlen );
  read_result = fd_acc_mgr_get_account_data( ctx.global->acc_mgr, ctx.global->funk_txn, (fd_pubkey_t *) me, raw_acc_data, metadata.hlen, metadata.dlen );
  if ( read_result != FD_ACC_MGR_SUCCESS ) {
    FD_LOG_NOTICE(( "failed to read account data: %ld", read_result ));
    // TODO: What is the correct error?!
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  void* input = (void *)raw_acc_data;
  fd_nonce_state_versions_t state;
  fd_nonce_state_versions_decode( &state, (const void **) &input, raw_acc_data + metadata.dlen, ctx.global->allocf, ctx.global->allocf_arg );

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

  uchar authorized = 0;
  for ( ulong i = 0; i < ctx.txn_descriptor->signature_cnt; i++ ) {
    if ( !memcmp( &txn_accs[i], state.inner.current.inner.initialized.authority.hash, sizeof(fd_pubkey_t) ) ) {
      authorized = 1;
      break;
    }
  }

  if (!authorized)
      return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;

  //if ( memcmp( authorized, state.inner.current.inner.initialized.authority.hash, sizeof(fd_pubkey_t) ) )
  //return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;

//                let (next_durable_nonce, separate_domains) = get_durable_nonce(invoke_context);

  fd_block_block_hash_entry_t *re = &ctx.global->bank.recent_block_hashes.hashes.elems[0];

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
  state.inner.current.inner.initialized.fee_calculator.lamports_per_signature = fd_runtime_lamports_per_signature(ctx.global);

//                self.set_state(&Versions::new(
//                    State::Initialized(new_data),
//                    separate_domains,
//                ))

  ulong sz = fd_nonce_state_versions_size(&state);
  unsigned char *enc = fd_alloca(1, sz);
  memset(enc, 0, sz);
  void const *ptr = (void const *) enc;
  fd_nonce_state_versions_encode(&state, &ptr);

  fd_acc_mgr_update_data ( ctx.global->acc_mgr, ctx.global->funk_txn, ctx.global->bank.solana_bank.slot, me, enc, sz);


  return FD_EXECUTOR_INSTR_SUCCESS;
}

// https://github.com/firedancer-io/solana/blob/8fb537409eb901444e064f50ea8dd7dcafb12a00/runtime/src/system_instruction_processor.rs#L366
int fd_withdraw_nonce_account(
  instruction_ctx_t  ctx,
    FD_FN_UNUSED unsigned long      withdraw_nonce_account
  ) 
{
  FD_LOG_ERR(( "unsupported discriminant: withdraw_none_account" ));

//        {pubkey: params.noncePubkey, isSigner: false, isWritable: true},
//        {pubkey: params.toPubkey, isSigner: false, isWritable: true},
//        {pubkey: SYSVAR_RECENT_BLOCKHASHES_PUBKEY, isSigner: false, isWritable: false,},
//        {pubkey: SYSVAR_RENT_PUBKEY, isSigner: false, isWritable: false,},
//        {pubkey: params.authorizedPubkey, isSigner: true, isWritable: false},

  // https://github.com/firedancer-io/solana/blob/ffd63324f988e1b2151dab34983c71d6ff4087f6/runtime/src/nonce_keyed_account.rs#L138

//        if invoke_context
//            .feature_set
//            .is_active(&nonce_must_be_writable::id())
//            && !self.is_writable()
//        {
//            ic_msg!(
//                invoke_context,
//                "Withdraw nonce account: Account {} must be writeable",
//                self.unsigned_key()
//            );
//            return Err(InstructionError::InvalidArgument);
//        }


  if (ctx.instr->acct_cnt != 5)
    return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;

  uchar *       instr_acc_idxs = ((uchar *)ctx.txn_raw->raw + ctx.instr->acct_off);
  fd_pubkey_t * txn_accs = (fd_pubkey_t *)((uchar *)ctx.txn_raw->raw + ctx.txn_descriptor->acct_addr_off);

  ulong acct_addr_cnt = ctx.txn_descriptor->acct_addr_cnt;


  if ((instr_acc_idxs[0] >= acct_addr_cnt) 
    | (instr_acc_idxs[1] >= acct_addr_cnt)
    | (instr_acc_idxs[2] >= acct_addr_cnt)
    | (instr_acc_idxs[3] >= acct_addr_cnt)
    | (instr_acc_idxs[4] >= acct_addr_cnt))
    return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;

  fd_pubkey_t * me   = &txn_accs[instr_acc_idxs[0]];

  uchar new_signed = 0;
  for ( ulong i = 0; i < ctx.instr->acct_cnt; i++ ) {
    if ( instr_acc_idxs[i] < ctx.txn_descriptor->signature_cnt ) {
      if ( !memcmp( &txn_accs[instr_acc_idxs[i]], me, sizeof(fd_pubkey_t) ) ) {
        new_signed = 1;
        break;
      }
    }
  }
  if ( !new_signed )  {
    FD_LOG_WARNING(( "account not signed" ));
    return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
  }

  fd_account_meta_t metadata;
  long              read_result = fd_acc_mgr_get_metadata( ctx.global->acc_mgr, ctx.global->funk_txn, me, &metadata );
  if ( read_result == FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT ) 
    return 0;

  unsigned char *raw_acc_data = fd_alloca( 1, metadata.dlen );
  read_result = fd_acc_mgr_get_account_data( ctx.global->acc_mgr, ctx.global->funk_txn, (fd_pubkey_t *) me, raw_acc_data, metadata.hlen, metadata.dlen );
  if ( read_result != FD_ACC_MGR_SUCCESS ) {
    FD_LOG_NOTICE(( "failed to read account data: %ld", read_result ));
    // TODO: What is the correct error?!
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  void* input = (void *)raw_acc_data;
  fd_nonce_state_versions_t state;
  fd_nonce_state_versions_decode( &state, (const void **) &input, raw_acc_data + metadata.dlen, ctx.global->allocf, ctx.global->allocf_arg );

  switch (state.inner.current.discriminant) {
  case fd_nonce_state_enum_uninitialized: {
//                if lamports > self.lamports()? {
//                    ic_msg!(
//                        invoke_context,
//                        "Withdraw nonce account: insufficient lamports {}, need {}",
//                        self.lamports()?,
//                        lamports,
//                    );
//                    return Err(InstructionError::InsufficientFunds);
//                }
//                *self.unsigned_key()

  }
  case fd_nonce_state_enum_initialized: {
//                if lamports == self.lamports()? {
//                    let (durable_nonce, separate_domains) = get_durable_nonce(invoke_context);
//                    if data.durable_nonce == durable_nonce {
//                        ic_msg!(
//                            invoke_context,
//                            "Withdraw nonce account: nonce can only advance once per slot"
//                        );
//                        return Err(nonce_to_instruction_error(
//                            NonceError::NotExpired,
//                            merge_nonce_error_into_system_error,
//                        ));
//                    }
//                    self.set_state(&Versions::new(State::Uninitialized, separate_domains))?;
//                } else {
//                    let min_balance = rent.minimum_balance(self.data_len()?);
//                    let amount = checked_add(lamports, min_balance)?;
//                    if amount > self.lamports()? {
//                        ic_msg!(
//                            invoke_context,
//                            "Withdraw nonce account: insufficient lamports {}, need {}",
//                            self.lamports()?,
//                            amount,
//                        );
//                        return Err(InstructionError::InsufficientFunds);
//                    }
//                }
//                data.authority
//            }

  }
  default: {
    FD_LOG_NOTICE(( "garbage nonce state" ));
    // TODO: What is the correct error?!
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }
  }


//        let nonce_balance = self.try_account_ref_mut()?.lamports();
//        self.try_account_ref_mut()?.set_lamports(
//            nonce_balance
//                .checked_sub(lamports)
//                .ok_or(InstructionError::ArithmeticOverflow)?,
//        );
//        let to_balance = to.try_account_ref_mut()?.lamports();
//        to.try_account_ref_mut()?.set_lamports(
//            to_balance
//                .checked_add(lamports)
//                .ok_or(InstructionError::ArithmeticOverflow)?,
//        );

  return FD_EXECUTOR_INSTR_SUCCESS;
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
  FD_FN_UNUSED instruction_ctx_t   ctx,
  FD_FN_UNUSED fd_pubkey_t        *initialize_nonce_account
  ) {
//        {pubkey: params.noncePubkey, isSigner: false, isWritable: true},
//        {pubkey: SYSVAR_RECENT_BLOCKHASHES_PUBKEY, isSigner: false, isWritable: false,},
//        {pubkey: SYSVAR_RENT_PUBKEY, isSigner: false, isWritable: false},

  if (ctx.instr->acct_cnt != 3)
    return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;

  uchar *       instr_acc_idxs = ((uchar *)ctx.txn_raw->raw + ctx.instr->acct_off);

  ulong acct_addr_cnt = ctx.txn_descriptor->acct_addr_cnt;

  // TODO: Is this implicately elsewhere in solana?  confirm the error code
  if ((instr_acc_idxs[0] >= acct_addr_cnt) | (instr_acc_idxs[1] >= acct_addr_cnt) | (instr_acc_idxs[2] >= acct_addr_cnt))
    return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;

  fd_pubkey_t * txn_accs = (fd_pubkey_t *)((uchar *)ctx.txn_raw->raw + ctx.txn_descriptor->acct_addr_off);

  fd_pubkey_t * me   = &txn_accs[instr_acc_idxs[0]];

  // WHY are these specified?  because it causes the scheduler to
  // order the execution of this txn against the updating of these
  // system vars...  Now, maybe I am wrong but I find that rather
  // questionable since we know these will be updated either entirely
  // at the end of the block or at the beginning of the block...
  //
  // I suspect I will learn more as time goes on on why anybody would
  // do this..
  fd_pubkey_t * blockhashes = &txn_accs[instr_acc_idxs[1]];
  fd_pubkey_t * rent = &txn_accs[instr_acc_idxs[2]];

  if ((NULL == me) | (NULL == blockhashes) | (NULL == rent)) 
    return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;

  /* Check to see if the account is already in use */
  fd_account_meta_t metadata;
  long              read_result = fd_acc_mgr_get_metadata( ctx.global->acc_mgr, ctx.global->funk_txn, me, &metadata );
  if ( read_result == FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT ) {
    FD_LOG_WARNING(( "account does not exists" ));
    // TODO: What is the correct error?!
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  // TODO: Do the signatures have to be in the same order as the pubkeys?
  // Do we really need aloop here?  Could an account be "signed" and
  // not be writable?


#if 0
  // I think... this check isn't valid during an init?

  // Are we authorized to be messing with this account?
  uchar authorized = 0;
  for ( ulong i = 0; i < ctx.txn_descriptor->signature_cnt; i++ ) {
    if ( !memcmp( &txn_accs[i], metadata.info.owner, sizeof(fd_pubkey_t) ) ) {
      authorized = 1;
      break;
    }
  }

  // TODO: what is the correct error
  if ( !authorized )  {
    FD_LOG_WARNING(( "account not authorized" ));
    return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
  }
#endif

  // Do I really have to sign for the specific account?  Can't I just be authorized to mess with 
  // this account?   find this check in the code and at it into the comments...
  uchar new_signed = 0;
  for ( ulong i = 0; i < ctx.instr->acct_cnt; i++ ) {
    if ( instr_acc_idxs[i] < ctx.txn_descriptor->signature_cnt ) {
      if ( !memcmp( &txn_accs[instr_acc_idxs[i]], me, sizeof(fd_pubkey_t) ) ) {
        new_signed = 1;
        break;
      }
    }
  }
  if ( !new_signed )  {
    FD_LOG_WARNING(( "account not signed" ));
    return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
  }

  unsigned char *raw_acc_data = fd_alloca( 1, metadata.dlen );
  read_result = fd_acc_mgr_get_account_data( ctx.global->acc_mgr, ctx.global->funk_txn, (fd_pubkey_t *) me, raw_acc_data, metadata.hlen, metadata.dlen );
  if ( read_result != FD_ACC_MGR_SUCCESS ) {
    FD_LOG_NOTICE(( "failed to read account data: %ld", read_result ));
    // TODO: What is the correct error?!
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  void* input = (void *)raw_acc_data;
  fd_nonce_state_versions_t state;
  fd_nonce_state_versions_decode( &state, (const void **) &input, raw_acc_data + metadata.dlen, ctx.global->allocf, ctx.global->allocf_arg );

  switch (state.inner.current.discriminant) {
  case fd_nonce_state_enum_uninitialized: {
    ulong minimum_rent_exempt_balance = fd_rent_exempt_minimum_balance( ctx.global, metadata.dlen );
    if ( metadata.info.lamports < minimum_rent_exempt_balance ) 
      return FD_EXECUTOR_INSTR_ERR_INSUFFICIENT_FUNDS;

    fd_block_block_hash_entry_t *re = &ctx.global->bank.recent_block_hashes.hashes.elems[0];

    fd_hash_t durable_nonce;
    fd_durable_nonce_from_blockhash(&re->blockhash, &durable_nonce);

    state.inner.current.discriminant = fd_nonce_state_enum_initialized;
    state.discriminant = fd_nonce_state_versions_enum_current;

    state.inner.current.inner.initialized.authority = *initialize_nonce_account;
    fd_memcpy(state.inner.current.inner.initialized.durable_nonce.hash, durable_nonce.hash, sizeof(state.inner.current.inner.initialized.durable_nonce.hash));
    state.inner.current.inner.initialized.fee_calculator.lamports_per_signature = fd_runtime_lamports_per_signature_for_blockhash(ctx.global, &re->blockhash);

    ulong sz = fd_nonce_state_versions_size(&state);
    unsigned char *enc = fd_alloca(1, sz);
    memset(enc, 0, sz);
    void const *ptr = (void const *) enc;
    fd_nonce_state_versions_encode(&state, &ptr);

//    char buf2[50];
//    fd_base58_encode_32((uchar *) state.inner.current.inner.initialized.authority.hash, NULL, buf2);
//    FD_LOG_NOTICE(("authority: %s", buf2));
//    fd_base58_encode_32((uchar *) state.inner.current.inner.initialized.durable_nonce.hash, NULL, buf2);
//    FD_LOG_NOTICE(("durable_nonce: %s %ld", buf2, state.inner.current.inner.initialized.fee_calculator.lamports_per_signature));

    // TODO: why!? Why do I have to cast here?    should we be using fd_sysvar_set here...

    fd_acc_mgr_update_data ( ctx.global->acc_mgr, ctx.global->funk_txn, ctx.global->bank.solana_bank.slot, me, enc, sz);

    return FD_EXECUTOR_INSTR_SUCCESS;
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
  FD_FN_UNUSED instruction_ctx_t   ctx,
  FD_FN_UNUSED fd_pubkey_t        *authorize_nonce_account
  ) {
//        {pubkey: params.noncePubkey, isSigner: false, isWritable: true},
//        {pubkey: params.authorizedPubkey, isSigner: true, isWritable: false},

  if (ctx.instr->acct_cnt != 2)
    return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;

  uchar *       instr_acc_idxs = ((uchar *)ctx.txn_raw->raw + ctx.instr->acct_off);
  fd_pubkey_t * txn_accs = (fd_pubkey_t *)((uchar *)ctx.txn_raw->raw + ctx.txn_descriptor->acct_addr_off);

  ulong acct_addr_cnt = ctx.txn_descriptor->acct_addr_cnt;
  if ((instr_acc_idxs[0] >= acct_addr_cnt) | (instr_acc_idxs[1] >= acct_addr_cnt))
    // TODO: confirm what this would look like in solana
    return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;

  fd_pubkey_t * me   = &txn_accs[instr_acc_idxs[0]];

  fd_account_meta_t metadata;
  long              read_result = fd_acc_mgr_get_metadata( ctx.global->acc_mgr, ctx.global->funk_txn, me, &metadata );
  if ( read_result == FD_ACC_MGR_ERR_UNKNOWN_ACCOUNT ) {
    // TODO: What is the correct error?!
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  unsigned char *raw_acc_data = fd_alloca( 1, metadata.dlen );
  read_result = fd_acc_mgr_get_account_data( ctx.global->acc_mgr, ctx.global->funk_txn, (fd_pubkey_t *) me, raw_acc_data, metadata.hlen, metadata.dlen );
  if ( read_result != FD_ACC_MGR_SUCCESS ) {
    FD_LOG_NOTICE(( "failed to read account data: %ld", read_result ));
    // TODO: What is the correct error?!
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  void* input = (void *)raw_acc_data;
  fd_nonce_state_versions_t state;
  fd_nonce_state_versions_decode( &state, (const void **) &input, raw_acc_data + metadata.dlen, ctx.global->allocf, ctx.global->allocf_arg );

  if (state.inner.current.discriminant != fd_nonce_state_enum_initialized)
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;

  uchar authorized = 0;
  for ( ulong i = 0; i < ctx.txn_descriptor->signature_cnt; i++ ) {
    if ( !memcmp( &txn_accs[i], state.inner.current.inner.initialized.authority.hash, sizeof(fd_pubkey_t) ) ) {
      authorized = 1;
      break;
    }
  }

  if (!authorized)
      return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;

  state.discriminant = fd_nonce_state_versions_enum_current;
  state.inner.current.inner.initialized.authority = *authorize_nonce_account;

  ulong sz = fd_nonce_state_versions_size(&state);
  unsigned char *enc = fd_alloca(1, sz);
  memset(enc, 0, sz);
  void const *ptr = (void const *) enc;
  fd_nonce_state_versions_encode(&state, &ptr);

  fd_acc_mgr_update_data ( ctx.global->acc_mgr, ctx.global->funk_txn, ctx.global->bank.solana_bank.slot, me, enc, sz);

  return FD_EXECUTOR_INSTR_SUCCESS;
}
