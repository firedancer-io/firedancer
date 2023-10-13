#include "fd_bpf_loader_v4_program.h"
#include "../fd_runtime.h"
#include "../../types/fd_types.h"
#include "../../../util/bits/fd_sat.h"
#include "../fd_system_ids.h"

#define DEPLOYMENT_COOLDOWN_IN_SLOTS (750)

/* Methods for processing specific BPF Loader v4 instructions */

static int _process_write             ( fd_exec_instr_ctx_t, fd_bpf_loader_v4_program_instruction_write_t const * );
static int _process_truncate          ( fd_exec_instr_ctx_t, uint );
static int _process_deploy            ( fd_exec_instr_ctx_t );
static int _process_retract           ( fd_exec_instr_ctx_t );
static int _process_transfer_authority( fd_exec_instr_ctx_t );

/* check_program_account runs a sequence of checks on an account owned
   by the BPF Loader v4 program.  Used by most instruction handlers.

   List of checks:
   - Account owner is BPF Loader v4
   - Account data is not zero-length
   - State header at start of account data within bounds
   - Program is writable
   - First instruction account (presumed authority) has signed operation
   - Program is not finalized (i.e. authority in state header is not NULL)
   - First instruction account matches the authority in the state header

   Returns an executor instruction error or 0 on success.
   On success, ensures that a pointer to the account's first byte can
   be safely casted to a pointer to fd_bpf_loader_v4_state_t.

   Linearly matches Solana Labs:
   https://github.com/solana-labs/solana/blob/d90e1582869d8ef8d386a1c156eda987404c43be/programs/loader-v4/src/lib.rs#L203 */

static int
check_program_account( fd_exec_instr_ctx_t         ctx,
                       fd_account_meta_t const * program_meta ) {

  /* Unpack arguments */

  uchar const * instr_acc_idxs = ctx.instr->acct_txn_idxs;
  fd_pubkey_t * txn_accs =  ctx.txn_ctx->accounts;
  ulong                   instr_acc_cnt  = ctx.instr->acct_cnt;
  uchar const *           program_data   = (uchar const *)program_meta + program_meta->hlen;

  /* Assume instruction account index 1 to be authority */

  FD_TEST( instr_acc_cnt >= 2 );
  fd_pubkey_t const * authority = &txn_accs[ instr_acc_idxs[1] ];

  /* https://github.com/solana-labs/solana/blob/d90e1582869d8ef8d386a1c156eda987404c43be/programs/loader-v4/src/lib.rs#L209 */
  if( FD_UNLIKELY( 0!=memcmp( program_meta->info.owner, fd_solana_bpf_loader_v4_program_id.key, sizeof(fd_pubkey_t) ) ) ) {
    // TODO Log: "Program not owner by loader"
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_OWNER;
  }

  /* https://github.com/solana-labs/solana/blob/d90e1582869d8ef8d386a1c156eda987404c43be/programs/loader-v4/src/lib.rs#L213 */
  if( FD_UNLIKELY( program_meta->dlen == 0UL ) ) {
    // TODO Log: "Program is uninitialized"
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  }

  /* https://github.com/solana-labs/solana/blob/d90e1582869d8ef8d386a1c156eda987404c43be/programs/loader-v4/src/lib.rs#L217 */
  fd_bpf_loader_v4_state_t const * state =
    fd_bpf_loader_v4_get_state_const( program_meta, program_data );
  if( FD_UNLIKELY( state==NULL ) )
    return FD_EXECUTOR_INSTR_ERR_ACC_DATA_TOO_SMALL;

  /* https://github.com/solana-labs/solana/blob/d90e1582869d8ef8d386a1c156eda987404c43be/programs/loader-v4/src/lib.rs#L218 */
  if( FD_UNLIKELY( !fd_txn_is_writable( ctx.txn_ctx->txn_descriptor, instr_acc_idxs[0] ) ) ) {
    // TODO Log: "Program account is not writeable"
    return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
  }

  /* https://github.com/solana-labs/solana/blob/d90e1582869d8ef8d386a1c156eda987404c43be/programs/loader-v4/src/lib.rs#L222 */
  if( FD_UNLIKELY( !fd_txn_is_signer( ctx.txn_ctx->txn_descriptor, instr_acc_idxs[1] ) ) ) {
    // TODO Log: "Authority did not sign"
    return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
  }

  /* https://github.com/solana-labs/solana/blob/d90e1582869d8ef8d386a1c156eda987404c43be/programs/loader-v4/src/lib.rs#L226 */
  if( FD_UNLIKELY( state->has_authority==0 ) ) {
    // TODO Log: "Program is finalized"
    return FD_EXECUTOR_INSTR_ERR_ACC_IMMUTABLE;
  }

  /* https://github.com/solana-labs/solana/blob/d90e1582869d8ef8d386a1c156eda987404c43be/programs/loader-v4/src/lib.rs#L230 */
  if( FD_UNLIKELY( 0!=memcmp( state->authority_addr, authority->key, sizeof(fd_pubkey_t) ) ) ) {
    // TODO Log: "Incorrect authority provided"
    return FD_EXECUTOR_INSTR_ERR_INCORRECT_AUTHORITY;
  }

  return 0;
}

/* _process_meta_instruction handles a direct invocation of the
   BPF Loader v4 program (i.e. instruction's program ID matches) */

static int
_process_meta_instruction( fd_exec_instr_ctx_t ctx ) {

  /* TODO: Consume DEFAULT_COMPUTE_UNITS upfront if feature_set::native_programs_consume_cu is active
     https://github.com/solana-labs/solana/blob/d90e1582869d8ef8d386a1c156eda987404c43be/programs/loader-v4/src/lib.rs#L577 */

  /* Scratch frame -- Deallocated when instruction processor exits */

  FD_SCRATCH_SCOPED_FRAME;

  /* Deserialize instruction */

  uchar const * instr_data = ctx.instr->data;
  fd_bincode_decode_ctx_t instr_decode = {
    .data    = instr_data,
    .dataend = instr_data + ctx.instr->data_sz,
    .valloc  = fd_scratch_virtual()
  };

  fd_bpf_loader_v4_program_instruction_t instr[1];
  int err = fd_bpf_loader_v4_program_instruction_decode( instr, &instr_decode );
  if( FD_UNLIKELY( err!=FD_BINCODE_SUCCESS ) ) return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;

  /* Handle instruction */

  switch( instr->discriminant ) {
  case fd_bpf_loader_v4_program_instruction_enum_write:
    return _process_write( ctx, &instr->inner.write );
  case fd_bpf_loader_v4_program_instruction_enum_truncate:
    return _process_truncate( ctx, instr->inner.truncate );
  case fd_bpf_loader_v4_program_instruction_enum_deploy:
    return _process_deploy( ctx );
  case fd_bpf_loader_v4_program_instruction_enum_retract:
    return _process_retract( ctx );
  case fd_bpf_loader_v4_program_instruction_enum_transfer_authority:
    return _process_transfer_authority( ctx );
  default:
    __builtin_unreachable();
    FD_LOG_CRIT(( "entered unreachable code" ));
  }
}

int
fd_executor_bpf_loader_v4_program_execute_instruction( fd_exec_instr_ctx_t ctx ) {

  /* Query program ID */
  fd_pubkey_t const * txn_accs =  ctx.txn_ctx->accounts;
  fd_pubkey_t const * program_id = &txn_accs[ ctx.instr->program_id ];

  if( FD_FEATURE_ACTIVE( ctx.slot_ctx, enable_program_runtime_v2_and_loader_v4 ) && 0==memcmp( program_id, fd_solana_bpf_loader_v4_program_id.key, sizeof(fd_pubkey_t) ) ) {
    return _process_meta_instruction( ctx );
  } else {
    FD_LOG_WARNING(( "BPF loader v4 program execution not yet supported" ));
    return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_PROGRAM_ID;
  }
}

static int
_process_write( fd_exec_instr_ctx_t                                    ctx,
                fd_bpf_loader_v4_program_instruction_write_t const * write ) {

  /* Context */

  uchar const * instr_acc_idxs = ctx.instr->acct_txn_idxs;
  fd_pubkey_t * txn_accs =  ctx.txn_ctx->accounts;
  ulong               instr_acc_cnt  = ctx.instr->acct_cnt;
  fd_acc_mgr_t *      acc_mgr        = ctx.acc_mgr;
  fd_funk_txn_t *     funk_txn       = ctx.funk_txn;

  /* Unpack accounts

     https://github.com/solana-labs/solana/blob/d90e1582869d8ef8d386a1c156eda987404c43be/programs/loader-v4/src/lib.rs#L245-L251 */

  if( FD_UNLIKELY( instr_acc_cnt < 2 ) )
    return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;

  ulong program_id_idx = instr_acc_idxs[0];
  ulong authority_idx  = instr_acc_idxs[1];

  fd_pubkey_t const * program_id = &txn_accs[ program_id_idx ];
  fd_pubkey_t const * authority  = &txn_accs[ authority_idx  ];
  fd_pubkey_t const * payer      = NULL;

  /* May only be accessed if !!payer */
  FD_BORROWED_ACCOUNT_DECL(payer_rec);

  if( instr_acc_cnt >= 3 ) {
    payer = &txn_accs[ instr_acc_idxs[2] ];

    int err = fd_acc_mgr_view( acc_mgr, funk_txn, payer, payer_rec );
    if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS ) ) payer = NULL;
  }

  (void)authority;

  /* Read program data
     https://github.com/solana-labs/solana/blob/d90e1582869d8ef8d386a1c156eda987404c43be/sdk/src/transaction_context.rs#L861 */
  FD_BORROWED_ACCOUNT_DECL(program_rec);
  /* TODO: If account does not exist, should we pretend there is a
           zero-length data region instead of erroring out? */
  int err = fd_acc_mgr_view( acc_mgr, funk_txn, program_id, program_rec);
  if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS ) ) return err;

  /* https://github.com/solana-labs/solana/blob/d90e1582869d8ef8d386a1c156eda987404c43be/programs/loader-v4/src/lib.rs#L252 */
  int is_initialization = (write->offset==0U) & (program_rec->const_meta->dlen==0UL);
  if( is_initialization ) {
    if( FD_UNLIKELY( 0!=memcmp( program_rec->const_meta->info.owner, fd_solana_bpf_loader_v4_program_id.key, sizeof(fd_pubkey_t) ) ) )
      return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_OWNER;
    if( FD_UNLIKELY( !fd_txn_is_writable( ctx.txn_ctx->txn_descriptor, instr_acc_idxs[0] ) ) )
      return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
    if( FD_UNLIKELY( !fd_txn_is_signer( ctx.txn_ctx->txn_descriptor, instr_acc_idxs[1] ) ) )
      return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
  } else {
    int err = check_program_account( ctx, program_rec->const_meta );
    if( FD_UNLIKELY( err!=0 ) ) return err;

    fd_bpf_loader_v4_state_t const * state = (fd_bpf_loader_v4_state_t const *)
      fd_type_pun_const( program_rec->const_data );
    if( FD_UNLIKELY( state->is_deployed ) ) {
      // TODO Log: "Program is not retracted"
      return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
    }
  }

  /* https://github.com/solana-labs/solana/blob/d90e1582869d8ef8d386a1c156eda987404c43be/programs/loader-v4/src/lib.rs#L278 */
  if( payer )
    if( FD_UNLIKELY( !fd_txn_is_signer( ctx.txn_ctx->txn_descriptor, instr_acc_idxs[2] ) ) )
      return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
  /* https://github.com/solana-labs/solana/blob/d90e1582869d8ef8d386a1c156eda987404c43be/programs/loader-v4/src/lib.rs#L282 */
  if( payer )
    if( FD_UNLIKELY( !fd_txn_is_writable( ctx.txn_ctx->txn_descriptor, instr_acc_idxs[2] ) ) )
      return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;

  /* https://github.com/solana-labs/solana/blob/d90e1582869d8ef8d386a1c156eda987404c43be/programs/loader-v4/src/lib.rs#L285-L286 */
  ulong program_size = program_rec->const_meta->dlen;
        program_size = fd_ulong_sat_sub( program_size, sizeof(fd_bpf_loader_v4_state_t) );

  /* https://github.com/solana-labs/solana/blob/d90e1582869d8ef8d386a1c156eda987404c43be/programs/loader-v4/src/lib.rs#L290-L291 */
  if( FD_UNLIKELY( write->offset > program_size ) ) {
    /* TODO log to program log: "Write out of bounds" */
    return FD_EXECUTOR_INSTR_ERR_ACC_DATA_TOO_SMALL;
  }

  /* Unpack instruction arguments */
  uchar const * bytes      = write->bytes;
  ulong const   bytes_len  = write->bytes_len;
  ulong const   offset     = write->offset;
  ulong const   end_offset = offset + write->bytes_len;

  ulong const program_acc_new_sz =
    fd_ulong_max( program_rec->const_meta->dlen, end_offset + sizeof(fd_bpf_loader_v4_state_t) );

  fd_rent_t const * rent = &ctx.slot_ctx->bank.rent;
  ulong required_lamports = fd_rent_exempt_minimum_balance2( rent, program_acc_new_sz );
  ulong transfer_lamports = fd_ulong_sat_sub( required_lamports, program_rec->const_meta->info.lamports );

  /* Does not linearly match Solana Labs */

  int sufficient_lamports =
       ( transfer_lamports==0UL )
    || ( (!!payer) && (payer_rec->const_meta->info.lamports >= transfer_lamports) );
  if( FD_UNLIKELY( !sufficient_lamports ) ) {
    /* TODO log to program log: "Insufficient lamports, %lu are required" */
    return FD_EXECUTOR_INSTR_ERR_INSUFFICIENT_FUNDS;
  }

  /* https://github.com/solana-labs/solana/blob/d90e1582869d8ef8d386a1c156eda987404c43be/programs/loader-v4/src/lib.rs#L310-L311 */

  /* Upgrade program to writable handle */
  err = fd_acc_mgr_modify( acc_mgr, funk_txn, program_id, 0, program_acc_new_sz, program_rec);
  if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS ) ) return err;
  program_rec->meta->dlen = program_acc_new_sz;

  /* https://github.com/solana-labs/solana/blob/d90e1582869d8ef8d386a1c156eda987404c43be/programs/loader-v4/src/lib.rs#L313 */
  if( payer ) {
    /* Upgrade payer to writable handle */
    err = fd_acc_mgr_modify( acc_mgr, funk_txn, payer, 0, 0UL, payer_rec);
    if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS ) ) return err;

    /* Transfer lamports
       https://github.com/solana-labs/solana/blob/d90e1582869d8ef8d386a1c156eda987404c43be/programs/loader-v4/src/lib.rs#L314 */
    payer_rec->meta  ->info.lamports -= transfer_lamports;
    program_rec->meta->info.lamports += transfer_lamports;
  }

  /* https://github.com/solana-labs/solana/blob/d90e1582869d8ef8d386a1c156eda987404c43be/programs/loader-v4/src/lib.rs#L317 */
  if( is_initialization ) {
    FD_TEST( program_rec->meta->dlen >= sizeof(fd_bpf_loader_v4_state_t) );
    fd_bpf_loader_v4_state_t * state = (fd_bpf_loader_v4_state_t *)fd_type_pun( program_rec->data );
    state->slot          = ctx.slot_ctx->bank.slot;  /* Solana Labs reads from the clock sysvar here */
    state->is_deployed   = 0;
    state->has_authority = 1;
    memcpy( state->authority_addr, authority->key, sizeof(fd_pubkey_t) );
  }

  /* https://github.com/solana-labs/solana/blob/d90e1582869d8ef8d386a1c156eda987404c43be/programs/loader-v4/src/lib.rs#L323
     Note: We have already verified end_offset at this point. */
  FD_TEST( write->offset <= end_offset );  /* This should be a debug assertion */

  ulong const write_off     = sizeof(fd_bpf_loader_v4_state_t) + offset;
  ulong const write_off_end = write_off + bytes_len;
  FD_TEST( write_off_end <= program_rec->const_meta->dlen );

  uchar * write_ptr = program_rec->data + write_off;
  fd_memcpy( write_ptr, bytes, bytes_len );

  return 0;
}

static int
_process_truncate( fd_exec_instr_ctx_t ctx,
                   uint              offset ) {

  /* Accounts */

  uchar const * instr_acc_idxs = ctx.instr->acct_txn_idxs;
  fd_pubkey_t const * txn_accs =  ctx.txn_ctx->accounts;
  fd_acc_mgr_t *      acc_mgr        = ctx.acc_mgr;
  fd_funk_txn_t *     funk_txn       = ctx.funk_txn;

  if( FD_UNLIKELY( ctx.instr->acct_cnt < 3 ) )
    return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;

  ulong program_id_idx = instr_acc_idxs[0];
  //ulong authority_idx  = instr_acc_idxs[1];
  ulong recipient_idx  = instr_acc_idxs[2];

  fd_pubkey_t const * program_id = &txn_accs[ program_id_idx ];
  //fd_pubkey_t const * authority  = &txn_accs[ authority_idx  ];
  fd_pubkey_t const * recipient  = &txn_accs[ recipient_idx  ];

  /* Read program account */
  FD_BORROWED_ACCOUNT_DECL(program_rec);
  int err = fd_acc_mgr_view( acc_mgr, funk_txn, program_id, program_rec);
  if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS ) ) return err;

  /* Check program account
     https://github.com/solana-labs/solana/blob/d90e1582869d8ef8d386a1c156eda987404c43be/programs/loader-v4/src/lib.rs#L347 */
  err = check_program_account( ctx, program_rec->const_meta);
  if( FD_UNLIKELY( err!=0 ) ) return err;
  fd_bpf_loader_v4_state_t const * state = (fd_bpf_loader_v4_state_t const *)
    fd_type_pun_const( program_rec->const_data );

  /* https://github.com/solana-labs/solana/blob/d90e1582869d8ef8d386a1c156eda987404c43be/programs/loader-v4/src/lib.rs#L353 */
  if( FD_UNLIKELY( state->is_deployed ) ) {
    // TODO Log: "Program is not retracted"
    return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
  }

  /* https://github.com/solana-labs/solana/blob/d90e1582869d8ef8d386a1c156eda987404c43be/programs/loader-v4/src/lib.rs#L357 */
  ulong program_size = program_rec->const_meta->dlen;
        program_size = fd_ulong_sat_sub( program_size, sizeof(fd_bpf_loader_v4_state_t) );

  /* https://github.com/solana-labs/solana/blob/d90e1582869d8ef8d386a1c156eda987404c43be/programs/loader-v4/src/lib.rs#L361 */
  if( FD_UNLIKELY( offset > program_size ) ) {
    /* TODO log to program log: "Write out of bounds" */
    return FD_EXECUTOR_INSTR_ERR_ACC_DATA_TOO_SMALL;
  }

  /* Determine target lamport count and account size.
     Does not exactly match Solana Labs control flow.
     https://github.com/solana-labs/solana/blob/d90e1582869d8ef8d386a1c156eda987404c43be/programs/loader-v4/src/lib.rs#L365 */
  ulong target_program_acc_sz;
  ulong required_lamports;
  if( offset==0U ) {
    target_program_acc_sz = 0UL;
    required_lamports     = 0UL;
  } else {
    target_program_acc_sz = sizeof(fd_bpf_loader_v4_state_t) + offset;
    required_lamports     = fd_rent_exempt_minimum_balance2( &ctx.slot_ctx->bank.rent, target_program_acc_sz );
  }

  /* Upgrade to writable handle and shrink account.
     TODO fd_funk does currently not support shrinking records. */
  if( FD_UNLIKELY( !fd_txn_is_writable( ctx.txn_ctx->txn_descriptor, (int)program_id_idx ) ) )
    return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
  err = fd_acc_mgr_modify( acc_mgr, funk_txn, program_id, /* do_create */ 0, target_program_acc_sz, program_rec);
  if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS ) ) return err;
  program_rec->meta->dlen = target_program_acc_sz;

  /* Obtain writable handle to recipient account. */
  if( FD_UNLIKELY( !fd_txn_is_writable( ctx.txn_ctx->txn_descriptor, (int)recipient_idx ) ) )
    return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
  FD_BORROWED_ACCOUNT_DECL(recipient_rec);
  // TODO, shouldn't this potentially create the account?
  err = fd_acc_mgr_modify( acc_mgr, funk_txn, recipient, /* flags */ 0UL, /* min_data_sz */ 0UL, recipient_rec);
  if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS ) ) return err;

  /* https://github.com/solana-labs/solana/blob/d90e1582869d8ef8d386a1c156eda987404c43be/programs/loader-v4/src/lib.rs#L375 */
  ulong transfer_lamports = program_rec->const_meta->info.lamports - required_lamports;
  FD_TEST( transfer_lamports <= program_rec->const_meta->info.lamports );  /* debug assert */
  program_rec->meta  ->info.lamports -= transfer_lamports;
  recipient_rec->meta->info.lamports += transfer_lamports;

  return 0;
}

static int
_process_deploy( fd_exec_instr_ctx_t ctx ) {

  /* Accounts */
  uchar const * instr_acc_idxs = ctx.instr->acct_txn_idxs;
  fd_pubkey_t const * txn_accs =  ctx.txn_ctx->accounts;
  if (ctx.instr->acct_cnt < 2) {
    return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
  }
  const fd_pubkey_t * program_acc = &txn_accs[instr_acc_idxs[0]];
  const fd_pubkey_t * authority_address = &txn_accs[instr_acc_idxs[1]];
  const fd_pubkey_t * source_program = NULL;

  if (ctx.instr->acct_cnt >= 3) {
    source_program = &txn_accs[instr_acc_idxs[2]];
  }
  // Load program account
  FD_BORROWED_ACCOUNT_DECL(program_acc_rec);
  int err = fd_acc_mgr_modify(ctx.acc_mgr, ctx.funk_txn, program_acc, 1, 0, program_acc_rec);
  if( FD_UNLIKELY( err ) ) return err;
  err = check_program_account(ctx, program_acc_rec->meta);
  if( FD_UNLIKELY( err ) ) return err;

  // Get bpf v4 state
  fd_bpf_loader_v4_state_t const * state = (fd_bpf_loader_v4_state_t const *)
      fd_type_pun_const( program_acc_rec->const_data );

  fd_sol_sysvar_clock_t clock;
  fd_sysvar_clock_read(ctx.slot_ctx, &clock);
  ulong current_slot = clock.slot;

  if (fd_ulong_sat_add(state->slot, DEPLOYMENT_COOLDOWN_IN_SLOTS) > current_slot) {
    return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
  }

  if (state->is_deployed) {
    return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
  }

  fd_account_meta_t * buffer_metadata = NULL;
  uchar * buffer_data = NULL;

  fd_borrowed_account_t *source_program_rec = NULL;
  if (source_program) {
    source_program_rec = fd_borrowed_account_init(fd_alloca(FD_BORROWED_ACCOUNT_ALIGN, FD_BORROWED_ACCOUNT_FOOTPRINT));
    err = fd_acc_mgr_modify(ctx.acc_mgr, ctx.funk_txn, source_program, 1, 0, source_program_rec);
    if (FD_UNLIKELY(err != FD_EXECUTOR_INSTR_SUCCESS)) {
      return err;
    }

    err = check_program_account(ctx, source_program_rec->const_meta);
    if (FD_UNLIKELY(err != FD_EXECUTOR_INSTR_SUCCESS)) {
      return err;
    }

    fd_bpf_loader_v4_state_t const * source_state = (fd_bpf_loader_v4_state_t const *)
      fd_type_pun_const( source_program_rec->const_data);

    if (source_state->is_deployed) {
      return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
    }
    buffer_metadata = source_program_rec->meta;
    buffer_data = source_program_rec->data;
  } else {
    buffer_metadata = program_acc_rec->meta;
    buffer_data = program_acc_rec->data;
  }

  // TODO: load_program
  FD_LOG_WARNING(("TODO: load program"));
  // let (_executor, load_program_metrics) = load_program_from_account(
  //     &invoke_context.feature_set,
  //     invoke_context.get_compute_budget(),
  //     invoke_context.get_log_collector(),
  //     buffer,
  //     false, /* debugging_features */
  // )?;

  if (source_program) {
    ulong required_lamports = fd_rent_exempt_minimum_balance(ctx.slot_ctx, program_acc_rec->meta->dlen);
    ulong transfer_lamports = fd_ulong_sat_sub(program_acc_rec->meta->info.lamports, required_lamports);

    program_acc_rec->meta->dlen = source_program_rec->meta->dlen;
    fd_memcpy(program_acc_rec->data, source_program_rec->data, source_program_rec->meta->dlen);
    source_program_rec->meta->dlen = 0;
    source_program_rec->meta->info.lamports -= transfer_lamports;
    program_acc_rec->meta->info.lamports += transfer_lamports;
  }

  fd_bpf_loader_v4_state_t * mut_state = (fd_bpf_loader_v4_state_t *) program_acc_rec->data;
  mut_state->slot = current_slot;
  mut_state->is_deployed = true;

  (void) buffer_data;
  (void) buffer_metadata;
  (void) authority_address;
  return FD_EXECUTOR_INSTR_SUCCESS;
}

static int
_process_retract( fd_exec_instr_ctx_t ctx ) {

  /* Context */
  uchar const * instr_acc_idxs = ctx.instr->acct_txn_idxs;
  fd_pubkey_t const * txn_accs =  ctx.txn_ctx->accounts;
  fd_acc_mgr_t *      acc_mgr        = ctx.acc_mgr;
  fd_funk_txn_t *     funk_txn       = ctx.funk_txn;

  /* Unpack accounts

     https://github.com/solana-labs/solana/blob/d90e1582869d8ef8d386a1c156eda987404c43be/programs/loader-v4/src/lib.rs#L494 */

  if( FD_UNLIKELY( ctx.instr->acct_cnt < 2 ) )
    return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;

  ulong program_id_idx = instr_acc_idxs[0];
  //ulong authority_idx  = instr_acc_idxs[1];

  fd_pubkey_t const * program_id = &txn_accs[ program_id_idx ];
  //fd_pubkey_t const * authority  = &txn_accs[ authority_idx  ];

  /* Read program account */
  FD_BORROWED_ACCOUNT_DECL(program_rec);

  int err = fd_acc_mgr_view( acc_mgr, funk_txn, program_id, program_rec);
  if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS ) ) return err;

  /* Check program account
     https://github.com/solana-labs/solana/blob/d90e1582869d8ef8d386a1c156eda987404c43be/programs/loader-v4/src/lib.rs#L498 */
  err = check_program_account( ctx, program_rec->const_meta );
  if( FD_UNLIKELY( err!=0 ) ) return err;
  fd_bpf_loader_v4_state_t const * state = (fd_bpf_loader_v4_state_t const *)
    fd_type_pun_const( program_rec->const_data );

  /* Solana Labs reads from the clock sysvar here
     https://github.com/solana-labs/solana/blob/d90e1582869d8ef8d386a1c156eda987404c43be/programs/loader-v4/src/lib.rs#L504 */
  ulong current_slot = ctx.slot_ctx->bank.slot;
  if( state->slot + DEPLOYMENT_COOLDOWN_IN_SLOTS > current_slot ) {
    // TODO Log: "Program was deployed recently, cooldown stil in effect"
    return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
  }

  /* https://github.com/solana-labs/solana/blob/d90e1582869d8ef8d386a1c156eda987404c43be/programs/loader-v4/src/lib.rs#L512 */
  if( !state->is_deployed ) {
    // TODO Log: "Program is not deployed"
    return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
  }

  /* Upgrade to writable handle
     https://github.com/solana-labs/solana/blob/d90e1582869d8ef8d386a1c156eda987404c43be/programs/loader-v4/src/lib.rs#L516 */
  if( FD_UNLIKELY( !fd_txn_is_writable( ctx.txn_ctx->txn_descriptor, (int)program_id_idx ) ) )
    return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
  err = fd_acc_mgr_modify( acc_mgr, funk_txn, program_id, /* do_create */ 0, 0UL, program_rec);
  if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS ) ) return err;
  fd_bpf_loader_v4_state_t * state_rw = (fd_bpf_loader_v4_state_t *)fd_type_pun( program_rec->data );

  /* https://github.com/solana-labs/solana/blob/d90e1582869d8ef8d386a1c156eda987404c43be/programs/loader-v4/src/lib.rs#L517 */
  state_rw->is_deployed = 0;

  return 0;
}

static int
_process_transfer_authority( fd_exec_instr_ctx_t ctx ) {

  /* Context */
  uchar const * instr_acc_idxs = ctx.instr->acct_txn_idxs;
  fd_pubkey_t const * txn_accs =  ctx.txn_ctx->accounts;
  fd_acc_mgr_t *      acc_mgr        = ctx.acc_mgr;
  fd_funk_txn_t *     funk_txn       = ctx.funk_txn;

  /* Unpack accounts

     https://github.com/solana-labs/solana/blob/d90e1582869d8ef8d386a1c156eda987404c43be/programs/loader-v4/src/lib.rs#L527 */

  if( FD_UNLIKELY( ctx.instr->acct_cnt < 2 ) )
    return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;

  ulong program_id_idx    = instr_acc_idxs[0];
  //ulong authority_idx     = instr_acc_idxs[1];
  ulong new_authority_idx = ULONG_MAX;

  fd_pubkey_t const * program_id    = &txn_accs[ program_id_idx    ];
  //fd_pubkey_t const * authority     = &txn_accs[ authority_idx     ];
  fd_pubkey_t const * new_authority = NULL;

  if( FD_UNLIKELY( ctx.instr->acct_cnt >= 3 ) ) {
    new_authority_idx = instr_acc_idxs[2];
    new_authority     = &txn_accs[ new_authority_idx ];
  }

  /* Read program account */
  FD_BORROWED_ACCOUNT_DECL(program_rec);
  int err = fd_acc_mgr_view( acc_mgr, funk_txn, program_id, program_rec );
  if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS ) ) return err;

  /* Check program account
     https://github.com/solana-labs/solana/blob/d90e1582869d8ef8d386a1c156eda987404c43be/programs/loader-v4/src/lib.rs#L536 */
  err = check_program_account( ctx, program_rec->const_meta );
  if( FD_UNLIKELY( err!=0 ) ) return err;

  /* For some reason, third instruction account is checked later */
  if( new_authority ) {
    if( FD_UNLIKELY( !fd_txn_is_signer( ctx.txn_ctx->txn_descriptor, (int)new_authority_idx ) ) ) {
      // TODO Log: "New authority did not sign"
      return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
    }
  }

  /* Upgrade to writable handle
     https://github.com/solana-labs/solana/blob/d90e1582869d8ef8d386a1c156eda987404c43be/programs/loader-v4/src/lib.rs#L542 */
  if( FD_UNLIKELY( !fd_txn_is_writable( ctx.txn_ctx->txn_descriptor, (int)program_id_idx ) ) )
    return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
  err = fd_acc_mgr_modify( acc_mgr, funk_txn, program_id, /* do_create */ 0, 0UL, program_rec );
  if( FD_UNLIKELY( err!=FD_ACC_MGR_SUCCESS ) ) return err;
  fd_bpf_loader_v4_state_t * state_rw = (fd_bpf_loader_v4_state_t *)fd_type_pun( program_rec->data );

  /* https://github.com/solana-labs/solana/blob/d90e1582869d8ef8d386a1c156eda987404c43be/programs/loader-v4/src/lib.rs#L547 */
  if( !new_authority ) {
    state_rw->has_authority = 0;
    fd_memset( state_rw, 0, sizeof(fd_pubkey_t) );
  } else {
    state_rw->has_authority = 1;
    fd_memcpy( state_rw->authority_addr, new_authority->key, sizeof(fd_pubkey_t) );
  }
  return 0;
}
