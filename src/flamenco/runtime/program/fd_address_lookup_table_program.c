#include "fd_program_util.h"
#include "fd_zk_token_proof_program.h"
#include "../fd_executor.h"
#include "../context/fd_exec_txn_ctx.h"
#include "../fd_acc_mgr.h"
#include "../fd_pubkey_utils.h"
#include <string.h>

static int
create_lookup_table( fd_exec_instr_ctx_t *       ctx,
                     fd_addrlut_create_t const * create ) {

  /* https://github.com/solana-labs/solana/blob/56ccffdaa5394f179dce6c0383918e571aca8bff/programs/address-lookup-table/src/processor.rs#L58-L62 */
  fd_borrowed_account_t * lut_acct;
  int acct_err = fd_instr_ctx_try_borrow_instruction_account( ctx, ctx->txn_ctx, 0, &lut_acct );
  if( FD_UNLIKELY( acct_err ) ) {
    /* TODO return code */
    return FD_EXECUTOR_INSTR_ERR_ACC_BORROW_FAILED;
  }
  ulong               lut_lamports = lut_acct->const_meta->info.lamports;
  fd_pubkey_t const * lut_key      = lut_acct->pubkey;
  uchar const *       lut_owner    = lut_acct->const_meta->info.owner;

  /* https://github.com/solana-labs/solana/blob/56ccffdaa5394f179dce6c0383918e571aca8bff/programs/address-lookup-table/src/processor.rs#L63-L70 */
  if( !FD_FEATURE_ACTIVE( ctx->slot_ctx, relax_authority_signer_check_for_lookup_table_creation )
      && lut_acct->const_meta->dlen != 0UL ) {
    /* TODO Log: "Table account must not be allocated" */
    return FD_EXECUTOR_INSTR_ERR_ACC_ALREADY_INITIALIZED;
  }
  /* TODO release lut_acct borrow
     https://github.com/solana-labs/solana/blob/56ccffdaa5394f179dce6c0383918e571aca8bff/programs/address-lookup-table/src/processor.rs#L71 */

  /* https://github.com/solana-labs/solana/blob/56ccffdaa5394f179dce6c0383918e571aca8bff/programs/address-lookup-table/src/processor.rs#L73-L75 */
  fd_borrowed_account_t * authority_acct;
  acct_err = fd_instr_ctx_try_borrow_instruction_account( ctx, ctx->txn_ctx, 1, &authority_acct );
  fd_pubkey_t const * authority_key = authority_acct->pubkey;

  /* https://github.com/solana-labs/solana/blob/56ccffdaa5394f179dce6c0383918e571aca8bff/programs/address-lookup-table/src/processor.rs#L76-L83 */
  if( !FD_FEATURE_ACTIVE( ctx->slot_ctx, relax_authority_signer_check_for_lookup_table_creation )
      && !fd_instr_acc_is_signer_idx( ctx->instr, 1 ) ) {
    /* TODO Log: "Authority account must be a signer" */
    return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
  }
  /* TODO release authority_acct borrow
     https://github.com/solana-labs/solana/blob/56ccffdaa5394f179dce6c0383918e571aca8bff/programs/address-lookup-table/src/processor.rs#L84 */

  /* https://github.com/solana-labs/solana/blob/56ccffdaa5394f179dce6c0383918e571aca8bff/programs/address-lookup-table/src/processor.rs#L86-L88 */
  fd_borrowed_account_t * payer_acct;
  acct_err = fd_instr_ctx_try_borrow_instruction_account( ctx, ctx->txn_ctx, 2, &payer_acct );
  if( FD_UNLIKELY( acct_err ) ) {
    /* TODO return code */
    return FD_EXECUTOR_INSTR_ERR_ACC_BORROW_FAILED;
  }
  fd_pubkey_t const * payer_key = payer_acct->pubkey; (void)payer_key;

  /* https://github.com/solana-labs/solana/blob/56ccffdaa5394f179dce6c0383918e571aca8bff/programs/address-lookup-table/src/processor.rs#L89-L92 */
  if( !fd_instr_acc_is_signer_idx( ctx->instr, 2 ) ) {
    /* TODO Log: "Payer account must be a signer" */
    return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
  }

  /* TODO release payer_acct borrow
     https://github.com/solana-labs/solana/blob/56ccffdaa5394f179dce6c0383918e571aca8bff/programs/address-lookup-table/src/processor.rs#L93 */

  fd_slot_hashes_t slot_hashes = {0};
  int slot_hashes_err = fd_sysvar_slot_hashes_read( ctx->slot_ctx, &slot_hashes );
  if( FD_UNLIKELY( slot_hashes_err ) ) {
    /* TODO what error to return if sysvar read fails? */
    return FD_EXECUTOR_INSTR_ERR_GENERIC_ERR;
  }

  /* TODO Binary search derivation slot in slot hashes sysvar */
  ulong derivation_slot = 1UL;
  if( 1 ) {
    /* TODO Log: {} is not a recent slot */
    return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
  }

  /* https://github.com/solana-labs/solana/blob/56ccffdaa5394f179dce6c0383918e571aca8bff/programs/address-lookup-table/src/processor.rs#L109-L118 */
  fd_pubkey_t derived_tbl_key[1];
  do {
    fd_sha256_t sha[1]; fd_sha256_init( sha );
    fd_sha256_append( sha, authority_key->key, 32UL );
    fd_sha256_append( sha, &derivation_slot,    8UL );
    fd_sha256_append( sha, &create->bump_seed,  1UL );
    fd_sha256_append( sha, fd_solana_address_lookup_table_program_id.key, 32UL );
    fd_sha256_append( sha, "ProgramDerivedAddress", 21UL );
    fd_sha256_fini( sha, derived_tbl_key->key );
  } while(0);
  if( FD_UNLIKELY( !fd_ed25519_validate_public_key( derived_tbl_key->key ) ) )
    return FD_EXECUTOR_INSTR_ERR_INVALID_SEEDS;

  /* https://github.com/solana-labs/solana/blob/56ccffdaa5394f179dce6c0383918e571aca8bff/programs/address-lookup-table/src/processor.rs#L120-L127 */
  if( FD_UNLIKELY( 0!=memcmp( lut_key->key, derived_tbl_key->key, 32UL ) ) ) {
    /* TODO Log: "Table address must match derived address: {}" */
    return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
  }

  /* https://github.com/solana-labs/solana/blob/56ccffdaa5394f179dce6c0383918e571aca8bff/programs/address-lookup-table/src/processor.rs#L129-L135 */
  if( FD_FEATURE_ACTIVE( ctx->slot_ctx, relax_authority_signer_check_for_lookup_table_creation )
      && 0==memcmp( lut_owner, fd_solana_address_lookup_table_program_id.key, 32UL ) ) {
    return FD_EXECUTOR_INSTR_SUCCESS;
  }

  /* https://github.com/solana-labs/solana/blob/56ccffdaa5394f179dce6c0383918e571aca8bff/programs/address-lookup-table/src/processor.rs#L137-L142 */
  ulong tbl_acct_data_len = 0x38UL;
  ulong required_lamports = fd_rent_exempt_minimum_balance( ctx->slot_ctx, tbl_acct_data_len );
        required_lamports = fd_ulong_max( required_lamports, 1UL );
        required_lamports = fd_ulong_sat_sub( required_lamports, lut_lamports );

  /* https://github.com/solana-labs/solana/blob/56ccffdaa5394f179dce6c0383918e571aca8bff/programs/address-lookup-table/src/processor.rs#L144-L149 */
  if( required_lamports > 0UL ) {
    FD_LOG_WARNING(( "TODO: CPI to system program" ));
    return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_PROGRAM_ID;  /* transfer */
  }

  FD_LOG_WARNING(( "TODO: CPI to system program" ));  /* allocate */
  FD_LOG_WARNING(( "TODO: CPI to system program" ));  /* assign */

  /* TODO Native cross program invocations ... */

  /* TODO: Acquire writable handle */
  fd_address_lookup_table_state_t state[1];
  fd_address_lookup_table_state_new( state );
  state->discriminant = fd_address_lookup_table_state_enum_lookup_table;
  fd_address_lookup_table_new( &state->inner.lookup_table );
  fd_memcpy( state->inner.lookup_table.meta.authority->key, authority_key->key, 32UL );
  /* TODO set state */

  FD_LOG_WARNING(( "TODO" ));
  (void)ctx; (void)create;
  return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_PROGRAM_ID;
}

static int
freeze_lookup_table( fd_exec_instr_ctx_t * ctx ) {

  /* https://github.com/solana-labs/solana/blob/abf3b3e527c8b24b122ab2cccb34d9aff05f8c15/programs/address-lookup-table/src/processor.rs#L176-L178 */
  fd_borrowed_account_t * lut_acct;
  int acct_err = fd_instr_ctx_try_borrow_instruction_account( ctx, ctx->txn_ctx, 0, &lut_acct );
  if( FD_UNLIKELY( acct_err ) ) {
    /* TODO return code */
    return FD_EXECUTOR_INSTR_ERR_ACC_BORROW_FAILED;
  }

  /* https://github.com/solana-labs/solana/blob/abf3b3e527c8b24b122ab2cccb34d9aff05f8c15/programs/address-lookup-table/src/processor.rs#L178-L181 */
  if( FD_UNLIKELY( 0!=memcmp( lut_acct->const_meta->info.owner, fd_solana_address_lookup_table_program_id.key, sizeof(fd_pubkey_t) ) ) ) {
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_OWNER;
  }
  /* TODO release lut_acct borrow
     https://github.com/solana-labs/solana/blob/56ccffdaa5394f179dce6c0383918e571aca8bff/programs/address-lookup-table/src/processor.rs#L71 */

  /* https://github.com/solana-labs/solana/blob/abf3b3e527c8b24b122ab2cccb34d9aff05f8c15/programs/address-lookup-table/src/processor.rs#L183-L186 */
  fd_borrowed_account_t * authority_acct;
  acct_err = fd_instr_ctx_try_borrow_instruction_account( ctx, ctx->txn_ctx, 1, &authority_acct );
  if( FD_UNLIKELY( acct_err ) ) {
    /* TODO return code */
    return FD_EXECUTOR_INSTR_ERR_ACC_BORROW_FAILED;
  }
  fd_pubkey_t const * authority_key = authority_acct->pubkey;

  /* https://github.com/solana-labs/solana/blob/abf3b3e527c8b24b122ab2cccb34d9aff05f8c15/programs/address-lookup-table/src/processor.rs#L186-L189 */
  if( FD_UNLIKELY( !fd_instr_acc_is_signer_idx( ctx->instr, 1UL ) ) ) {
    /* TODO Log: "Authority account must be a signer" */
    return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
  }
  /* TODO release authority_acct borrow
     https://github.com/solana-labs/solana/blob/abf3b3e527c8b24b122ab2cccb34d9aff05f8c15/programs/address-lookup-table/src/processor.rs#L190 */

  /* TODO Re-borrow LUT account
     https://github.com/solana-labs/solana/blob/abf3b3e527c8b24b122ab2cccb34d9aff05f8c15/programs/address-lookup-table/src/processor.rs#L192-L193 */

  uchar const * lut_data    = lut_acct->const_data;
  ulong         lut_data_sz = lut_acct->const_meta->dlen;

  /* TODO Implement AddressLookupTable::deserialize */
  (void)lut_data; (void)lut_data_sz;
  (void)authority_key;

  FD_LOG_WARNING(( "TODO" ));
  (void)ctx;
  return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_PROGRAM_ID;
}

static int
extend_lookup_table( fd_exec_instr_ctx_t *       ctx,
                     fd_addrlut_extend_t const * extend ) {

  /* https://github.com/solana-labs/solana/blob/abf3b3e527c8b24b122ab2cccb34d9aff05f8c15/programs/address-lookup-table/src/processor.rs#L230-L232 */
  fd_borrowed_account_t * lut_acct;
  int acct_err = fd_instr_ctx_try_borrow_instruction_account( ctx, ctx->txn_ctx, 0, &lut_acct );
  if( FD_UNLIKELY( acct_err ) ) {
    /* TODO return code */
    return FD_EXECUTOR_INSTR_ERR_ACC_BORROW_FAILED;
  }
  fd_pubkey_t const * lut_key = lut_acct->pubkey;

  /* https://github.com/solana-labs/solana/blob/abf3b3e527c8b24b122ab2cccb34d9aff05f8c15/programs/address-lookup-table/src/processor.rs#L233-L235 */
  if( FD_UNLIKELY( 0!=memcmp( lut_acct->const_meta->info.owner, fd_solana_address_lookup_table_program_id.key, sizeof(fd_pubkey_t) ) ) ) {
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_OWNER;
  }
  /* TODO release lut_acct borrow
     https://github.com/solana-labs/solana/blob/56ccffdaa5394f179dce6c0383918e571aca8bff/programs/address-lookup-table/src/processor.rs#L236 */

  /* https://github.com/solana-labs/solana/blob/abf3b3e527c8b24b122ab2cccb34d9aff05f8c15/programs/address-lookup-table/src/processor.rs#L238-240 */
  fd_borrowed_account_t * authority_acct;
  acct_err = fd_instr_ctx_try_borrow_instruction_account( ctx, ctx->txn_ctx, 1, &authority_acct );
  if( FD_UNLIKELY( acct_err ) ) {
    /* TODO return code */
    return FD_EXECUTOR_INSTR_ERR_ACC_BORROW_FAILED;
  }
  fd_pubkey_t const * authority_key = authority_acct->pubkey;

  /* https://github.com/solana-labs/solana/blob/abf3b3e527c8b24b122ab2cccb34d9aff05f8c15/programs/address-lookup-table/src/processor.rs#L241-244 */
  if( FD_UNLIKELY( !fd_instr_acc_is_signer_idx( ctx->instr, 1UL ) ) ) {
    /* TODO Log: "Authority account must be a signer" */
    return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
  }
  /* TODO release authority_acct borrow
     https://github.com/solana-labs/solana/blob/abf3b3e527c8b24b122ab2cccb34d9aff05f8c15/programs/address-lookup-table/src/processor.rs#L245 */

  /* TODO Re-borrow LUT account
     https://github.com/solana-labs/solana/blob/abf3b3e527c8b24b122ab2cccb34d9aff05f8c15/programs/address-lookup-table/src/processor.rs#L247-248 */

  uchar const * lut_data     = lut_acct->const_data;
  ulong         lut_data_sz  = lut_acct->const_meta->dlen;
  ulong         lut_lamports = lut_acct->const_meta->info.lamports;

  /* TODO Implement AddressLookupTable::deserialize */
  (void)lut_key; (void)authority_key;
  (void)lut_data; (void)lut_data_sz; (void)lut_lamports;

  FD_LOG_WARNING(( "TODO" ));
  (void)ctx; (void)extend;
  return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_PROGRAM_ID;
}

static int
deactivate_lookup_table( fd_exec_instr_ctx_t * ctx ) {

  /* https://github.com/solana-labs/solana/blob/abf3b3e527c8b24b122ab2cccb34d9aff05f8c15/programs/address-lookup-table/src/processor.rs#L346-347 */
  fd_borrowed_account_t * lut_acct;
  int acct_err = fd_instr_ctx_try_borrow_instruction_account( ctx, ctx->txn_ctx, 0, &lut_acct );
  if( FD_UNLIKELY( acct_err ) ) {
    /* TODO return code */
    return FD_EXECUTOR_INSTR_ERR_ACC_BORROW_FAILED;
  }

  /* https://github.com/solana-labs/solana/blob/abf3b3e527c8b24b122ab2cccb34d9aff05f8c15/programs/address-lookup-table/src/processor.rs#L348-L350 */
  if( FD_UNLIKELY( 0!=memcmp( lut_acct->const_meta->info.owner, fd_solana_address_lookup_table_program_id.key, sizeof(fd_pubkey_t) ) ) ) {
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_OWNER;
  }
  /* TODO release lut_acct borrow
     https://github.com/solana-labs/solana/blob/56ccffdaa5394f179dce6c0383918e571aca8bff/programs/address-lookup-table/src/processor.rs#L351 */

  /* https://github.com/solana-labs/solana/blob/abf3b3e527c8b24b122ab2cccb34d9aff05f8c15/programs/address-lookup-table/src/processor.rs#L353-355 */
  fd_borrowed_account_t * authority_acct;
  acct_err = fd_instr_ctx_try_borrow_instruction_account( ctx, ctx->txn_ctx, 1, &authority_acct );
  if( FD_UNLIKELY( acct_err ) ) {
    /* TODO return code */
    return FD_EXECUTOR_INSTR_ERR_ACC_BORROW_FAILED;
  }
  fd_pubkey_t const * authority_key = authority_acct->pubkey;

  /* https://github.com/solana-labs/solana/blob/abf3b3e527c8b24b122ab2cccb34d9aff05f8c15/programs/address-lookup-table/src/processor.rs#L356-L359 */
  if( FD_UNLIKELY( !fd_instr_acc_is_signer_idx( ctx->instr, 1UL ) ) ) {
    /* TODO Log: "Authority account must be a signer" */
    return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
  }
  /* TODO release authority_acct borrow
     https://github.com/solana-labs/solana/blob/abf3b3e527c8b24b122ab2cccb34d9aff05f8c15/programs/address-lookup-table/src/processor.rs#L360 */

  /* TODO Re-borrow LUT account
     https://github.com/solana-labs/solana/blob/abf3b3e527c8b24b122ab2cccb34d9aff05f8c15/programs/address-lookup-table/src/processor.rs#L362-L363 */

  uchar const * lut_data    = lut_acct->const_data;
  ulong         lut_data_sz = lut_acct->const_meta->dlen;

  /* TODO Implement AddressLookupTable::deserialize */
  (void)lut_data; (void)lut_data_sz;
  (void)authority_key;

  FD_LOG_WARNING(( "TODO" ));
  (void)ctx;
  return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_PROGRAM_ID;
}

static int
close_lookup_table( fd_exec_instr_ctx_t * ctx ) {
  FD_LOG_WARNING(( "TODO" ));
  (void)ctx;
  return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_PROGRAM_ID;
}

int
fd_executor_address_lookup_table_program_execute_instruction( fd_exec_instr_ctx_t * ctx ) {

  uchar const * instr_data    = ctx->instr->data;
  ulong         instr_data_sz = ctx->instr->data_sz;

  FD_SCRATCH_SCOPED_FRAME;

  fd_bincode_decode_ctx_t decode = {
    .valloc  = fd_scratch_virtual(),
    .data    = instr_data,
    .dataend = instr_data + instr_data_sz
  };
  fd_addrlut_instruction_t instr[1];
  /* https://github.com/solana-labs/solana/blob/fb80288f885a62bcd923f4c9579fd0edeafaff9b/programs/address-lookup-table/src/processor.rs#L31 */
  if( FD_UNLIKELY( fd_addrlut_instruction_decode( instr, &decode ) != FD_BINCODE_SUCCESS ) )
    return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;

  switch( instr->discriminant ) {
  case fd_addrlut_instruction_enum_create_lut:
    return create_lookup_table( ctx, &instr->inner.create_lut );
  case fd_addrlut_instruction_enum_freeze_lut:
    return freeze_lookup_table( ctx );
  case fd_addrlut_instruction_enum_extend_lut:
    return extend_lookup_table( ctx, &instr->inner.extend_lut );
  case fd_addrlut_instruction_enum_deactivate_lut:
    return deactivate_lookup_table( ctx );
  case fd_addrlut_instruction_enum_close_lut:
    return close_lookup_table( ctx );
  default:
    break;
  }

  return FD_EXECUTOR_INSTR_SUCCESS;
}
