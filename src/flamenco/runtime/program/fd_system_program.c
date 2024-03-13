#include "../fd_executor.h"
#include "fd_system_program.h"
#include "../fd_acc_mgr.h"
#include "../fd_runtime.h"
#include "../fd_account.h"
#include "../fd_system_ids.h"
#include "../sysvar/fd_sysvar_rent.h"
#include "../context/fd_exec_epoch_ctx.h"
#include "../context/fd_exec_slot_ctx.h"
#include "../context/fd_exec_txn_ctx.h"

/* TODO Move this out */

static int
fd_pubkey_create_with_seed( uchar const  base [ static 32 ],
                            char const * seed,
                            ulong        seed_sz,
                            uchar const  owner[ static 32 ],
                            uchar        out  [ static 32 ] ) {

  static char const pda_marker[] = {"ProgramDerivedAddress"};

  if( seed_sz > 32UL )
    return FD_EXECUTOR_SYSTEM_ERR_MAX_SEED_LENGTH_EXCEEDED;

  if( memcmp( &owner[32UL - sizeof(pda_marker)-1], pda_marker, sizeof(pda_marker)-1 ) == 0 )
    return FD_EXECUTOR_INSTR_ERR_ILLEGAL_OWNER;

  fd_sha256_t sha;
  fd_sha256_init( &sha );

  fd_sha256_append( &sha, base,  32UL    );
  fd_sha256_append( &sha, seed,  seed_sz );
  fd_sha256_append( &sha, owner, 32UL    );

  fd_sha256_fini( &sha, out );

  return FD_EXECUTOR_INSTR_SUCCESS;
}

/* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L42-L68

   Partial port of system_processor::Address::create, only covering the
   case of the "seed" input actually existing.  Note that this doesn't
   "create" an address, but rather re-derives from PDA inputs and checks
   that the result matches some expected value. */

static int
fd_system_program_pda_verify( fd_exec_instr_ctx_t * ctx,
                              fd_pubkey_t const *   expected,
                              fd_pubkey_t const *   base,
                              char const *          seed,
                              ulong                 seed_sz,
                              fd_pubkey_t const *   owner ) {

  fd_pubkey_t actual[1];
  do {
    int err = fd_pubkey_create_with_seed(
        base->uc,
        seed,
        seed_sz,
        owner->uc,
        actual->uc );
    if( FD_UNLIKELY( err ) ) return err;
  } while(0);

  if( FD_UNLIKELY( 0!=memcmp( actual->uc, expected->uc, sizeof(fd_pubkey_t) ) ) ) {
    /* TODO Log: "Create: address {} does not match derived address {}" */
    ctx->txn_ctx->custom_err = FD_SYSTEM_PROGRAM_ERR_ADDR_WITH_SEED_MISMATCH;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  return 0;
}

/* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L183

   Matches Solana Labs system_processor::transfer_verified */

static int
fd_system_program_transfer_verified( fd_exec_instr_ctx_t * ctx,
                                     ulong                 transfer_amount,
                                     ulong                 from_acct_idx,
                                     ulong                 to_acct_idx ) {

  /* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L191-L192 */

  fd_borrowed_account_t * from = NULL;
  do {
    int err = fd_instr_borrowed_account_view_idx( ctx, (uchar)from_acct_idx, &from );
    if( FD_UNLIKELY( err ) ) return FD_EXECUTOR_INSTR_ERR_FATAL;
  } while(0);

  if( FD_UNLIKELY( !fd_borrowed_account_acquire_write( from ) ) )
    return FD_EXECUTOR_INSTR_ERR_ACC_BORROW_FAILED;

  /* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L193-L196 */

  if( from->const_meta->dlen != 0UL ) {
    /* TODO Log: "Transfer: `from` must not carry data" */
    return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
  }

  /* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L197-L205 */

  if( transfer_amount > from->starting_lamports ) {
    /* TODO Log: "Transfer: insufficient lamports {}, need {} */
    ctx->txn_ctx->custom_err = FD_SYSTEM_PROGRAM_ERR_RESULT_WITH_NEGATIVE_LAMPORTS;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  /* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L207 */

  if( FD_UNLIKELY( !fd_instr_acc_is_writable_idx( ctx->instr, 0UL ) ) )
    return FD_EXECUTOR_INSTR_ERR_READONLY_LAMPORT_CHANGE;

  do {
    int err = fd_instr_borrowed_account_modify_idx( ctx, (uchar)from_acct_idx, 0UL, &from );
    if( FD_UNLIKELY( err ) ) return FD_EXECUTOR_INSTR_ERR_FATAL;
  } while(0);

  do {
    int err = fd_account_checked_sub_lamports( ctx, from->meta, from->pubkey, transfer_amount );
    if( FD_UNLIKELY( err ) ) return err;
  } while(0);

  /* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L208 */

  fd_borrowed_account_release_write( from );

  /* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L209-L210 */

  fd_borrowed_account_t * to = NULL;

  do {
    int err = fd_instr_borrowed_account_modify_idx( ctx, (uchar)to_acct_idx, 0UL, &to );
    if( FD_UNLIKELY( err ) ) return FD_EXECUTOR_INSTR_ERR_FATAL;
  } while(0);

  if( FD_UNLIKELY( !fd_borrowed_account_acquire_write( to ) ) )
    return FD_EXECUTOR_INSTR_ERR_ACC_BORROW_FAILED;

  /* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L211 */

  do {
    int err = fd_account_checked_add_lamports( ctx, to->meta, to->pubkey, transfer_amount );
    if( FD_UNLIKELY( err ) ) return err;
  } while(0);

  fd_borrowed_account_release_write( to );  /* implicit drop */

  return 0;
}

/* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L215

   Matches system_processor::transfer */

static int
fd_system_program_transfer( fd_exec_instr_ctx_t * ctx,
                            ulong                 transfer_amount,
                            ulong                 from_acct_idx,
                            ulong                 to_acct_idx ) {

  /* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L223-L229 */

  if( !FD_FEATURE_ACTIVE( ctx->slot_ctx, system_transfer_zero_check )
      && transfer_amount == 0UL )
    return 0;

  /* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L231-L241 */

  if( FD_UNLIKELY( !fd_instr_acc_is_signer_idx( ctx->instr, (uchar)from_acct_idx ) ) ) {
    /* TODO Log: "Transfer: `from` account {} must sign" */
    return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
  }

  /* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L243-L250 */

  return fd_system_program_transfer_verified( ctx, transfer_amount, from_acct_idx, to_acct_idx );
}

/* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L71-L111

   Matches Solana Labs system_processor::allocate() */

static int
fd_system_program_allocate( fd_exec_instr_ctx_t * ctx,
                            ulong                 acct_idx,
                            int                   is_authorized,
                            ulong                 space ) {

  /* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L78-L85 */

  if( FD_UNLIKELY( !is_authorized ) ) {
    /* TODO Log: "Allocate 'to' account {:?} must sign" */
    return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
  }

  /* Assumes that acct_idx was bounds checked */

  fd_borrowed_account_t * account = ctx->instr->borrowed_accounts[ acct_idx ];

  /* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L87-L96 */

  if( FD_UNLIKELY( ( account->const_meta->dlen != 0UL ) |
                   ( 0!=memcmp( account->const_meta->info.owner, fd_solana_system_program_id.uc, 32UL ) ) ) ) {
    /* TODO Log: "Allocate: account {:?} already in use" */
    ctx->txn_ctx->custom_err = FD_SYSTEM_PROGRAM_ERR_ACCT_ALREADY_IN_USE;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  /* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L98-L106 */

  if( FD_UNLIKELY( space > FD_ACC_SZ_MAX ) ) {
    /* TODO Log: "Allocate: requested {}, max allowed {}" */
    ctx->txn_ctx->custom_err = FD_SYSTEM_PROGRAM_ERR_INVALID_ACCT_DATA_LEN;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  /* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L108 */

  do {
    /* Implicit upgrade to writable */
    int err = fd_instr_borrowed_account_modify_idx( ctx, (uchar)acct_idx, space, &account );
    if( FD_UNLIKELY( err ) ) return FD_EXECUTOR_INSTR_ERR_FATAL;
  } while(0);

  do {
    int err = FD_EXECUTOR_INSTR_ERR_FATAL;  /* 'FATAL', in case set_data_length doesn't initialize this value */
    int ok = fd_account_set_data_length( ctx, account->meta, account->pubkey, space, &err );
    if( FD_UNLIKELY( !ok ) ) return err;
  } while(0);

  return 0;
}

/* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L113-L131

   Matches Solana Labs system_processor::assign() */

static int
fd_system_program_assign( fd_exec_instr_ctx_t * ctx,
                          ulong                 acct_idx,
                          int                   is_authorized,
                          fd_pubkey_t const *   owner ) {

  /* Assumes addr_idx was bounds checked */

  fd_borrowed_account_t * account = ctx->instr->borrowed_accounts[ acct_idx ];

  /* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L121-L123 */

  if( 0==memcmp( account->const_meta->info.owner, owner->uc, sizeof(fd_pubkey_t) ) )
    return 0;

  /* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L125-L128 */

  if( FD_UNLIKELY( !is_authorized ) ) {
    /* TODO Log: "Assign: account {:?} must sign" */
    return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
  }

  /* Implicit writable acquire */
  do {
    int err = fd_instr_borrowed_account_modify_idx( ctx, (uchar)acct_idx, 0UL, &account );
    if( FD_UNLIKELY( err ) ) return FD_EXECUTOR_INSTR_ERR_FATAL;
  } while(0);

  return fd_account_set_owner( ctx, account->meta, account->pubkey, owner );
}

/* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L133-L143

   Matches Solana Labs system_processor::allocate_and_assign() */

static int
fd_system_program_allocate_and_assign( fd_exec_instr_ctx_t * ctx,
                                       ulong                 acct_idx,
                                       int                   is_authorized,
                                       ulong                 space,
                                       fd_pubkey_t const *   owner ) {

  do {
    int err = fd_system_program_allocate( ctx, acct_idx, is_authorized, space );
    if( FD_UNLIKELY( err ) ) return err;
  } while(0);

  return fd_system_program_assign( ctx, acct_idx, is_authorized, owner );
}

/* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L146-L181

   Matches Solana Labs system_processor::create_account() */

static int
fd_system_program_create_account( fd_exec_instr_ctx_t * ctx,
                                  ulong                 from_acct_idx,
                                  ulong                 to_acct_idx,
                                  int                   to_is_authorized,
                                  ulong                 lamports,
                                  ulong                 space,
                                  fd_pubkey_t const *   owner ) {

  /* Assumes to_acct_idx has no write handle */

  /* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L160-L161 */

  fd_borrowed_account_t * to = NULL;
  do {
    int err = fd_instr_borrowed_account_view_idx( ctx, (uchar)to_acct_idx, &to );
    if( FD_UNLIKELY( err ) ) return FD_EXECUTOR_INSTR_ERR_FATAL;
  } while(0);

  if( FD_UNLIKELY( !fd_borrowed_account_acquire_write( to ) ) )
    return FD_EXECUTOR_INSTR_ERR_ACC_BORROW_FAILED;

  /* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L162-L169 */

  if( FD_UNLIKELY( to->const_meta->info.lamports ) ) {
    /* TODO Log: "Create Account: account {:?} already in use" */
    ctx->txn_ctx->custom_err = FD_SYSTEM_PROGRAM_ERR_ACCT_ALREADY_IN_USE;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  /* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L171 */

  do {
    int err = fd_system_program_allocate_and_assign( ctx, to_acct_idx, to_is_authorized, space, owner );
    if( FD_UNLIKELY( err ) ) return err;
  } while(0);

  /* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L172
     Implicit drop */

  fd_borrowed_account_release_write( to );

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
    return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;

  /* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L333-L339 */

  ulong const from_acct_idx    = 0UL;
  ulong const to_acct_idx      = 1UL;
  int   const to_is_authorized = !!fd_instr_acc_is_signer_idx( ctx->instr, (uchar)to_acct_idx );
  return fd_system_program_create_account(
      ctx,
      (uchar)from_acct_idx,
      (uchar)to_acct_idx,
      to_is_authorized,
      create_acc->lamports,
      create_acc->space,
      &create_acc->owner );
}

/* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L381-L393

   Matches Solana Labs system_processor SystemInstruction::Assign { ... } => { ... } */

int
fd_system_program_exec_assign( fd_exec_instr_ctx_t * ctx,
                               fd_pubkey_t const *   owner ) {

  /* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L382 */

  if( FD_UNLIKELY( ctx->instr->acct_cnt < 1 ) )
    return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;

  /* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L383-L384 */

  fd_borrowed_account_t * account;
  do {
    int err = fd_instr_borrowed_account_view_idx( ctx, 0, &account );
    if( FD_UNLIKELY( err ) ) return FD_EXECUTOR_INSTR_ERR_FATAL;
  } while(0);

  if( FD_UNLIKELY( !fd_borrowed_account_acquire_write( account ) ) )
    return FD_EXECUTOR_INSTR_ERR_ACC_BORROW_FAILED;

  /* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L385-L391
     system_processor::Address::create eliminated (dead code) */

  /* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L392 */

  ulong const acct_idx      = 0UL;
  int   const is_authorized = !!fd_instr_acc_is_signer_idx( ctx->instr, (uchar)acct_idx );
  do {
    int err = fd_system_program_assign( ctx, (uchar)acct_idx, is_authorized, owner );
    if( FD_UNLIKELY( err ) ) return err;
  } while(0);

  /* Implicit drop */
  fd_borrowed_account_release_write( account );

  return 0;
}

/* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L394-L404

   Matches Solana Labs system_processor SystemInstruction::Transfer { ... } => { ... } */

int
fd_system_program_exec_transfer( fd_exec_instr_ctx_t * ctx,
                                 ulong                 transfer_amount ) {

  /* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L395 */

  if( FD_UNLIKELY( ctx->instr->acct_cnt < 2 ) )
    return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;

  /* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L396-L402 */

  return fd_system_program_transfer( ctx, transfer_amount, 0UL, 1UL );
}

/* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L353

   Matches Solana Labs system_processor SystemInstruction::CreateAccountWithSeed { ... } => { ... } */

int
fd_system_program_exec_create_account_with_seed( fd_exec_instr_ctx_t *                                            ctx,
                                                 fd_system_program_instruction_create_account_with_seed_t const * args ) {

  fd_instr_info_t const * instr = ctx->instr;

  /* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L360 */

  if( FD_UNLIKELY( instr->acct_cnt < 2 ) )
    return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;

  /* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L361-L367 */

  do {
    int err = fd_system_program_pda_verify(
        ctx,
        &instr->acct_pubkeys[1],
        &args->base,
        (char const *)args->seed,
        args->seed_len,
        &args->owner );
    if( FD_UNLIKELY( err ) ) return err;
  } while(0);

  /* https://github.com/solana-labs/solana/blob/v1.17.23/programs/system/src/system_processor.rs#L35-L41

     Authorization check is lifted out from 'allocate' to here.
     Scan instruction accounts for matching signer. */

  int to_is_authorized = 0;
  for( ulong j=0UL; j < instr->acct_cnt; j++ ) {
    to_is_authorized |=
      ( ( !!fd_instr_acc_is_signer_idx( instr, (uchar)j ) ) &
        ( 0==memcmp( instr->acct_pubkeys[j].uc, args->base.uc, sizeof(fd_pubkey_t) ) ) );
  }

  /* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L368-L379 */

  ulong const from_acct_idx    = 0UL;
  ulong const to_acct_idx      = 1UL;
  return fd_system_program_create_account(
      ctx,
      (uchar)from_acct_idx,
      (uchar)to_acct_idx,
      to_is_authorized,
      args->lamports,
      args->space,
      &args->owner );
}

/* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L504-L516

   Matches Solana Labs system_processor SystemInstruction::Allocate { ... } => { ... } */

int
fd_system_program_exec_allocate( fd_exec_instr_ctx_t * ctx,
                                 ulong                 space ) {

  /* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L505 */

  if( FD_UNLIKELY( ctx->instr->acct_cnt < 1 ) )
    return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;

  /* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L506-L507 */

  fd_borrowed_account_t * account;
  do {
    int err = fd_instr_borrowed_account_view_idx( ctx, 0, &account );
    if( FD_UNLIKELY( err ) ) return FD_EXECUTOR_INSTR_ERR_FATAL;
  } while(0);

  if( FD_UNLIKELY( !fd_borrowed_account_acquire_write( account ) ) )
    return FD_EXECUTOR_INSTR_ERR_ACC_BORROW_FAILED;

  /* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L508-L514
     system_processor::Address::create eliminated (dead code) */

  /* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L515 */

  ulong const acct_idx      = 0UL;
  int   const is_authorized = !!fd_instr_acc_is_signer_idx( ctx->instr, (uchar)acct_idx );
  do {
    int err = fd_system_program_allocate( ctx, (uchar)acct_idx, is_authorized, space );
    if( FD_UNLIKELY( err ) ) return err;
  } while(0);

  /* Implicit drop */
  fd_borrowed_account_release_write( account );

  return 0;
}

/* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L517-L541

   Matches Solana Labs system_processor SystemInstruction::AllocateWithSeed { ... } => { ... } */

int
fd_system_program_exec_allocate_with_seed( fd_exec_instr_ctx_t *                                      ctx,
                                           fd_system_program_instruction_allocate_with_seed_t const * args ) {

  /* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L523 */

  if( FD_UNLIKELY( ctx->instr->acct_cnt < 1 ) )
    return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;

  /* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#524-525 */

  fd_borrowed_account_t * account;
  do {
    int err = fd_instr_borrowed_account_view_idx( ctx, 0, &account );
    if( FD_UNLIKELY( err ) ) return FD_EXECUTOR_INSTR_ERR_FATAL;
  } while(0);

  if( FD_UNLIKELY( !fd_borrowed_account_acquire_write( account ) ) )
    return FD_EXECUTOR_INSTR_ERR_ACC_BORROW_FAILED;

  /* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L526-L532 */

  do {
    int err = fd_system_program_pda_verify(
        ctx,
        account->pubkey,
        &args->base,
        (char const *)args->seed,
        args->seed_len,
        &args->owner );
    if( FD_UNLIKELY( err ) ) return err;
  } while(0);

  /* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L533-L540 */

  ulong const acct_idx      = 0UL;
  int   const is_authorized = !!fd_instr_acc_is_signer_idx( ctx->instr, (uchar)acct_idx );
  do {
    int err = fd_system_program_allocate_and_assign(
        ctx,
        (uchar)acct_idx,
        is_authorized,
        args->space,
        &args->owner );
    if( FD_UNLIKELY( err ) ) return err;
  } while(0);

  /* Implicit drop */
  fd_borrowed_account_release_write( account );

  return 0;
}

/* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L542-L554

   Matches Solana Labs system_processor SystemInstruction::AssignWithSeed { ... } => { ... } */

int
fd_system_program_exec_assign_with_seed( fd_exec_instr_ctx_t *                                    ctx,
                                         fd_system_program_instruction_assign_with_seed_t const * args ) {

  /* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#543 */

  if( FD_UNLIKELY( ctx->instr->acct_cnt < 1 ) )
    return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;

  /* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L544-L545 */

  fd_borrowed_account_t * account;
  do {
    int err = fd_instr_borrowed_account_view_idx( ctx, 0, &account );
    if( FD_UNLIKELY( err ) ) return FD_EXECUTOR_INSTR_ERR_FATAL;
  } while(0);

  if( FD_UNLIKELY( !fd_borrowed_account_acquire_write( account ) ) )
    return FD_EXECUTOR_INSTR_ERR_ACC_BORROW_FAILED;

  /* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L546-L552 */

  do {
    int err = fd_system_program_pda_verify(
        ctx,
        account->pubkey,
        &args->base,
        (char const *)args->seed,
        args->seed_len,
        &args->owner );
    if( FD_UNLIKELY( err ) ) return err;
  } while(0);

  /* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L553 */

  ulong const acct_idx      = 0UL;
  int   const is_authorized = !!fd_instr_acc_is_signer_idx( ctx->instr, (uchar)acct_idx );
  do {
    int err = fd_system_program_assign( ctx, (uchar)acct_idx, is_authorized, &args->owner );
    if( FD_UNLIKELY( err ) ) return err;
  } while(0);

  /* Implicit drop */
  fd_borrowed_account_release_write( account );

  return 0;
}

/* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L405-L422

   Matches Solana Labs system_processor SystemInstruction::TransferWithSeed { ... } => { ... } */

int
fd_system_program_exec_transfer_with_seed( fd_exec_instr_ctx_t *                                      ctx,
                                           fd_system_program_instruction_transfer_with_seed_t const * args ) {

  /* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L410 */

  if( FD_UNLIKELY( ctx->instr->acct_cnt < 3 ) )
    return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;

  /* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L411-L421
     Inlined call to system_processor::transfer_with_seed */

  ulong const from_idx      = 0UL;
  ulong const from_base_idx = 1UL;
  ulong const to_idx        = 2UL;

  /* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L264-L270 */

  if( FD_UNLIKELY( ( !FD_FEATURE_ACTIVE( ctx->slot_ctx, system_transfer_zero_check ) ) ) &
                   ( args->lamports == 0UL ) )
    return 0;

  /* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L272-L282 */

  if( FD_UNLIKELY( !fd_instr_acc_is_signer_idx( ctx->instr, from_base_idx ) ) ) {
    /* TODO Log: "Transfer 'from' account {:?} must sign" */
    return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
  }

  /* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L283-L290 */

  fd_pubkey_t address_from_seed[1];
  do {
    int err = fd_pubkey_create_with_seed(
        ctx->instr->acct_pubkeys[ from_base_idx ].uc,
        (char const *)args->from_seed,
        args->from_seed_len,
        args->from_owner.uc,
        address_from_seed->uc );
    if( FD_UNLIKELY( err ) ) return err;
  } while(0);

  /* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L292-L303 */

  if( FD_UNLIKELY( 0!=memcmp( address_from_seed->uc,
                              ctx->instr->acct_pubkeys[ from_idx ].uc,
                              sizeof(fd_pubkey_t) ) ) ) {
    /* TODO Log: "Transfer 'from' address {} does not match derived address {}" */
    ctx->txn_ctx->custom_err = FD_SYSTEM_PROGRAM_ERR_ADDR_WITH_SEED_MISMATCH;
    return FD_EXECUTOR_INSTR_ERR_CUSTOM_ERR;
  }

  /* https://github.com/solana-labs/solana/blob/v1.17.22/programs/system/src/system_processor.rs#L305-L312 */
  return fd_system_program_transfer_verified( ctx, args->lamports, from_idx, to_idx );
}

int
fd_system_program_execute( fd_exec_instr_ctx_t ctx ) {
  do {
    int err = fd_exec_consume_cus( ctx.txn_ctx, 150UL );
    if( FD_UNLIKELY( err ) ) return err;
  } while(0);

  /* Deserialize the SystemInstruction enum */
  uchar * data = ctx.instr->data;

  fd_system_program_instruction_t instruction;
  fd_bincode_decode_ctx_t decode =
    { .data    = data,
      .dataend = &data[ctx.instr->data_sz],
      .valloc  = fd_scratch_virtual() };
  if( fd_system_program_instruction_decode( &instruction, &decode ) )
    return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;

  int result = FD_EXECUTOR_INSTR_ERR_INVALID_ARG;

  switch( instruction.discriminant ) {
  case fd_system_program_instruction_enum_create_account: {
    result = fd_system_program_exec_create_account(
        &ctx, &instruction.inner.create_account );
    break;
  }
  case fd_system_program_instruction_enum_assign: {
    result = fd_system_program_exec_assign(
        &ctx, &instruction.inner.assign );
    break;
  }
  case fd_system_program_instruction_enum_transfer: {
    result = fd_system_program_exec_transfer(
        &ctx, instruction.inner.transfer );
    break;
  }
  case fd_system_program_instruction_enum_create_account_with_seed: {
    result = fd_system_program_exec_create_account_with_seed(
        &ctx, &instruction.inner.create_account_with_seed );
    break;
  }
  case fd_system_program_instruction_enum_advance_nonce_account: {
    result = fd_system_program_exec_advance_nonce_account( &ctx );
    break;
  }
  case fd_system_program_instruction_enum_withdraw_nonce_account: {
    result = fd_system_program_exec_withdraw_nonce_account(
        &ctx, instruction.inner.withdraw_nonce_account );
    break;
  }
  case fd_system_program_instruction_enum_initialize_nonce_account: {
    result = fd_system_program_exec_initialize_nonce_account(
        &ctx, &instruction.inner.initialize_nonce_account );
    break;
  }
  case fd_system_program_instruction_enum_authorize_nonce_account: {
    result = fd_system_program_exec_authorize_nonce_account(
        &ctx, &instruction.inner.authorize_nonce_account );
    break;
  }
  case fd_system_program_instruction_enum_allocate: {
    result = fd_system_program_exec_allocate( &ctx, instruction.inner.allocate );
    break;
  }
  case fd_system_program_instruction_enum_allocate_with_seed: {
    // https://github.com/solana-labs/solana/blob/b00d18cec4011bb452e3fe87a3412a3f0146942e/runtime/src/system_instruction_processor.rs#L525
    result = fd_system_program_exec_allocate_with_seed(
        &ctx, &instruction.inner.allocate_with_seed );
    break;
  }
  case fd_system_program_instruction_enum_assign_with_seed: {
    // https://github.com/solana-labs/solana/blob/b00d18cec4011bb452e3fe87a3412a3f0146942e/runtime/src/system_instruction_processor.rs#L545
    result = fd_system_program_exec_assign_with_seed(
        &ctx, &instruction.inner.assign_with_seed );
    break;
  }
  case fd_system_program_instruction_enum_transfer_with_seed: {
    // https://github.com/solana-labs/solana/blob/b00d18cec4011bb452e3fe87a3412a3f0146942e/runtime/src/system_instruction_processor.rs#L412
    result = fd_system_program_exec_transfer_with_seed(
        &ctx, &instruction.inner.transfer_with_seed );
    break;
  }
  case fd_system_program_instruction_enum_upgrade_nonce_account: {
    // https://github.com/solana-labs/solana/blob/b00d18cec4011bb452e3fe87a3412a3f0146942e/runtime/src/system_instruction_processor.rs#L491
    result = fd_system_program_exec_upgrade_nonce_account( &ctx );
    break;
  }
  }

  fd_bincode_destroy_ctx_t destroy = { .valloc = ctx.valloc };
  fd_system_program_instruction_destroy( &instruction, &destroy );
  return result;
}
