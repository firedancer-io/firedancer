#include "fd_address_lookup_table_program.h"
#include "fd_program_util.h"
#include "../fd_executor.h"
#include "../context/fd_exec_txn_ctx.h"
#include "../fd_acc_mgr.h"
#include "../fd_pubkey_utils.h"
#include "../fd_account.h"
#include "../sysvar/fd_sysvar_clock.h"
#include "../sysvar/fd_sysvar_slot_hashes.h"
#include "../../../ballet/ed25519/fd_curve25519.h"
#include "../../vm/syscall/fd_vm_syscall.h"
#include "fd_native_cpi.h"

#include <string.h>

struct fd_addrlut {
  fd_address_lookup_table_state_t state;

  fd_pubkey_t const * addr;  /* points into account data */
  ulong               addr_cnt;
};

typedef struct fd_addrlut fd_addrlut_t;

#define FD_ADDRLUT_META_SZ       (56UL)
#define FD_ADDRLUT_MAX_ADDR_CNT (256UL)
#define DEFAULT_COMPUTE_UNITS   (750UL)

static fd_addrlut_t *
fd_addrlut_new( void * mem ) {

  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, alignof(fd_addrlut_t) ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  return fd_type_pun( mem );
}

static int
fd_addrlut_deserialize( fd_addrlut_t * lut,
                        uchar const *  data,
                        ulong          data_sz ) {

  lut = fd_addrlut_new( lut ); FD_TEST( lut );

  fd_bincode_decode_ctx_t decode =
    { .data    = data,
      .dataend = data+data_sz };
  if( FD_UNLIKELY( fd_address_lookup_table_state_decode( &lut->state, &decode )!=FD_BINCODE_SUCCESS ) )
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;

  if( lut->state.discriminant==fd_address_lookup_table_state_enum_uninitialized )
    return FD_EXECUTOR_INSTR_ERR_UNINITIALIZED_ACCOUNT;
  FD_TEST( lut->state.discriminant == fd_address_lookup_table_state_enum_lookup_table );

  if( data_sz < FD_ADDRLUT_META_SZ )
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;

  uchar const * raw_addr_data    = data   +FD_ADDRLUT_META_SZ;
  ulong         raw_addr_data_sz = data_sz-FD_ADDRLUT_META_SZ;

  if( !fd_ulong_is_aligned( raw_addr_data_sz, 32UL ) )
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;

  lut->addr     = fd_type_pun_const( raw_addr_data );
  lut->addr_cnt = raw_addr_data_sz / 32UL;

  return FD_EXECUTOR_INSTR_SUCCESS;
}

static int
fd_addrlut_serialize_meta( fd_address_lookup_table_state_t const * state,
                           uchar * data,
                           ulong   data_sz ) {

  /* TODO can this ever get hit?  All code paths to this function seem
     to check account data size during deserialization. */
  if( FD_UNLIKELY( data_sz<FD_ADDRLUT_META_SZ ) )
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;

  fd_bincode_encode_ctx_t encode =
    { .data    = data,
      .dataend = data+FD_ADDRLUT_META_SZ };
  fd_memset( data, 0, (ulong)encode.dataend - (ulong)encode.data );

  int bin_err = fd_address_lookup_table_state_encode( state, &encode );
  FD_TEST( !bin_err );

  return FD_EXECUTOR_INSTR_SUCCESS;
}

/* https://github.com/solana-labs/solana/blob/v1.17.4/sdk/program/src/address_lookup_table/state.rs#L79-L103 */

static int
fd_addrlut_status( fd_lookup_table_meta_t const * state,
                   ulong                          current_slot,
                   fd_slot_hashes_t const *       slot_hashes,
                   ulong *                        remaining_blocks ) {
  if( state->deactivation_slot == ULONG_MAX )
    return FD_ADDRLUT_STATUS_ACTIVATED;
  if( state->deactivation_slot == current_slot ) {
    *remaining_blocks = 513UL;
    return FD_ADDRLUT_STATUS_DEACTIVATING;
  }

  /* TODO consider making this a binary search */
  for( deq_fd_slot_hash_t_iter_t iter = deq_fd_slot_hash_t_iter_init( slot_hashes->hashes );
       !deq_fd_slot_hash_t_iter_done( slot_hashes->hashes, iter );
       iter = deq_fd_slot_hash_t_iter_next( slot_hashes->hashes, iter ) ) {
    fd_slot_hash_t const * ele = deq_fd_slot_hash_t_iter_ele_const( slot_hashes->hashes, iter );
    if( ele->slot == state->deactivation_slot ) {
      *remaining_blocks = 512UL - (current_slot - ele->slot);
      return FD_ADDRLUT_STATUS_DEACTIVATING;
    }
  }

  return FD_ADDRLUT_STATUS_DEACTIVATED;
}

// static ulong
// find_slot_hash( fd_slot_hash_t const * hashes, ulong slot ) {

//   ulong start = 0;
//   ulong end = deq_fd_slot_hash_t_cnt( hashes );

//   while (start < end) {
//     ulong mid = start + (end - start) / 2;
//     fd_slot_hash_t const * ele = deq_fd_slot_hash_t_peek_index_const( hashes, mid );

//     if ( ele->slot == slot ) {
//       return slot;
//     } else if ( ele->slot < slot ) {
//       start = mid + 1;
//     } else {
//       end = mid - 1;
//     }
//   }

//   return ULONG_MAX;
// }

/* Note on uses of fd_borrowed_account_acquire_write_is_safe:

   In some places of this program, the Agave implementation acquires a
   "mutable borrow" on the account that is immediately dropped before
   any borrow can occur.  In other words, this borrow attempt only
   introduces a "borrow failed" error case into the protocol but
   otherwise introduces no side effects.  i.e.

     if not fd_borrowed_account_acquire_write():
       return FD_EXECUTOR_INSTR_ERR_ACC_BORROW_FAILED
     ... read only operations ...
     fd_borrowed_account_release_write()
     ... arbitrary logic ...

   Is equivalent to

     if not fd_borrowed_account_acquire_write_is_safe():
       return FD_EXECUTOR_INSTR_ERR_ACC_BORROW_FAILED
     ... read only operations ...
     ... arbitrary logic ... */

static int
create_lookup_table( fd_exec_instr_ctx_t *       ctx,
                     fd_addrlut_create_t const * create ) {

# define ACC_IDX_LUT       (0UL)
# define ACC_IDX_AUTHORITY (1UL)
# define ACC_IDX_PAYER     (2UL)

  /* Prepare LUT account **********************************************/
  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L58-L59 */

  /* try_borrow_instruction_account => get_index_of_instruction_account_in_transaction */
  ulong               lut_lamports = 0UL;
  fd_pubkey_t const * lut_key      = NULL;
  uchar const *       lut_owner    = NULL;
  FD_BORROWED_ACCOUNT_TRY_BORROW_IDX( ctx, ACC_IDX_LUT, lut_acct ) {

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L60-L62 */
  lut_lamports = lut_acct->const_meta->info.lamports;
  lut_key      = lut_acct->pubkey;
  lut_owner    = lut_acct->const_meta->info.owner;

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L63-L70 */
  if( !FD_FEATURE_ACTIVE( ctx->slot_ctx, relax_authority_signer_check_for_lookup_table_creation )
      && lut_acct->const_meta->dlen != 0UL ) {
    FD_LOG_WARNING(( "Table account must not be allocated" ));
    return FD_EXECUTOR_INSTR_ERR_ACC_ALREADY_INITIALIZED;
  }

  } FD_BORROWED_ACCOUNT_DROP( lut_acct );

  /* Prepare authority account ****************************************/
  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L73-L74 */

  fd_pubkey_t const * authority_key = NULL;
  /* try_borrow_instruction_account => get_index_of_instruction_account_in_transaction */
  FD_BORROWED_ACCOUNT_TRY_BORROW_IDX( ctx, ACC_IDX_AUTHORITY, authority_acct ) {

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L75 */
  authority_key = authority_acct->pubkey;

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L76-L83 */
  if( !FD_FEATURE_ACTIVE( ctx->slot_ctx, relax_authority_signer_check_for_lookup_table_creation )
      && !fd_instr_acc_is_signer_idx( ctx->instr, ACC_IDX_AUTHORITY ) ) {
    FD_LOG_WARNING(( "Authority account must be a signer" ));
    return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
  }

  } FD_BORROWED_ACCOUNT_DROP( authority_acct );

  /* Prepare payer account ********************************************/
  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L86-L87 */

  /* try_borrow_account => get_index_of_instruction_account_in_transaction */
  fd_pubkey_t const * payer_key = NULL; 
  FD_BORROWED_ACCOUNT_TRY_BORROW_IDX( ctx, ACC_IDX_PAYER, payer_acct ) {

  payer_key = payer_acct->pubkey;

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L89-L92 */
  if( !fd_instr_acc_is_signer_idx( ctx->instr, ACC_IDX_PAYER ) ) {
    /* TODO Log: "Payer account must be a signer" */
    return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
  }

  } FD_BORROWED_ACCOUNT_DROP( payer_acct );

  ulong derivation_slot = 1UL;

  do {
    fd_slot_hashes_t slot_hashes[1];
    if( FD_UNLIKELY( !fd_sysvar_slot_hashes_read( slot_hashes, ctx->slot_ctx ) ) )
      return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR;

    /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L97 */
    int is_recent_slot = 0;
    /* TODO: loop is naive */
    for( deq_fd_slot_hash_t_iter_t iter = deq_fd_slot_hash_t_iter_init( slot_hashes->hashes );
         !deq_fd_slot_hash_t_iter_done( slot_hashes->hashes, iter );
         iter = deq_fd_slot_hash_t_iter_next( slot_hashes->hashes, iter ) ) {
      fd_slot_hash_t const * ele = deq_fd_slot_hash_t_iter_ele_const( slot_hashes->hashes, iter );
      if( ele->slot == create->recent_slot ) {
        is_recent_slot = 1;
        break;
      }
    }

    fd_bincode_destroy_ctx_t destroy = { .valloc = ctx->slot_ctx->valloc };
    fd_slot_hashes_destroy( slot_hashes, &destroy );

    if( FD_UNLIKELY( !is_recent_slot ) ) {
      /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L100-L105 */
      FD_LOG_WARNING(("%lu is not a recent slot", create->recent_slot));
      return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
    } else {
      derivation_slot = create->recent_slot;
    }
  } while(0);

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L109-L118 */
  fd_pubkey_t derived_tbl_key[1];
  uchar *     seeds[2];
  ulong       seed_szs[2] = { sizeof(fd_pubkey_t), sizeof(ulong) };
  seeds[0] = (uchar *)authority_key;
  seeds[1] = (uchar *)&derivation_slot;
  int err = fd_pubkey_derive_pda( &fd_solana_address_lookup_table_program_id, 
                                  2UL, seeds, seed_szs, (uchar*)&create->bump_seed, derived_tbl_key );
  if( FD_UNLIKELY( err ) ) {
    return err;
  }

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L120-L127 */
  if( FD_UNLIKELY( 0!=memcmp( lut_key->key, derived_tbl_key->key, sizeof(fd_pubkey_t) ) ) ) {
    FD_LOG_WARNING(( "Table address must match derived address" ));
    return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
  }

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L129-L135 */
  if( FD_FEATURE_ACTIVE( ctx->slot_ctx, relax_authority_signer_check_for_lookup_table_creation )
      && 0==memcmp( lut_owner, fd_solana_address_lookup_table_program_id.key, sizeof(fd_pubkey_t) ) ) {
    return FD_EXECUTOR_INSTR_SUCCESS;
  }

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L137-L142 */
  ulong tbl_acct_data_len = 0x38UL;
  ulong required_lamports = fd_rent_exempt_minimum_balance( ctx->slot_ctx, tbl_acct_data_len );
        required_lamports = fd_ulong_max( required_lamports, 1UL );
        required_lamports = fd_ulong_sat_sub( required_lamports, lut_lamports );

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L144-L149 */
  if( required_lamports>0UL ) {
    // Create account metas
    FD_SCRATCH_SCOPE_BEGIN {
      fd_vm_rust_account_meta_t * acct_metas = (fd_vm_rust_account_meta_t *)
                                                fd_scratch_alloc( FD_VM_RUST_ACCOUNT_META_ALIGN, 2 * sizeof(fd_vm_rust_account_meta_t) );
      fd_native_cpi_create_account_meta( payer_key, 1, 1, &acct_metas[0] );
      fd_native_cpi_create_account_meta( lut_key,   0, 1, &acct_metas[1] );

      // Create signers list
      fd_pubkey_t signers[16];
      ulong signers_cnt = 1;
      signers[0] = *payer_key;

      // Create system program instruction
      fd_system_program_instruction_t instr = {0};
      instr.discriminant = fd_system_program_instruction_enum_transfer;
      instr.inner.transfer = required_lamports;

      int err = fd_native_cpi_execute_system_program_instruction(
        ctx,
        &instr,
        acct_metas,
        2,
        signers,
        signers_cnt
      );
      if( FD_UNLIKELY( err ) ) {
        return err;
      }
    } FD_SCRATCH_SCOPE_END;
  }

  FD_SCRATCH_SCOPE_BEGIN {
    fd_vm_rust_account_meta_t * acct_metas = ( fd_vm_rust_account_meta_t * )
                                              fd_scratch_alloc( FD_VM_RUST_ACCOUNT_META_ALIGN, sizeof(fd_vm_rust_account_meta_t) );
    fd_native_cpi_create_account_meta( lut_key, 1, 1, &acct_metas[0] );

    // Create signers list
    fd_pubkey_t signers[16];
    ulong signers_cnt = 1;
    signers[0] = *lut_key;

    // Create system program instruction
    fd_system_program_instruction_t instr = {0};
    instr.discriminant = fd_system_program_instruction_enum_allocate;
    instr.inner.allocate = 56;

    // Execute allocate instruction
    int err = fd_native_cpi_execute_system_program_instruction(
      ctx,
      &instr,
      acct_metas,
      1,
      signers,
      signers_cnt
    );
    if( FD_UNLIKELY( err ) ) {
      return err;
    }

    instr.discriminant = fd_system_program_instruction_enum_assign;
    instr.inner.assign = fd_solana_address_lookup_table_program_id;

    // Execute assign instruction
    err = fd_native_cpi_execute_system_program_instruction(
      ctx,
      &instr,
      acct_metas,
      1,
      signers,
      signers_cnt
    );
    if( FD_UNLIKELY( err ) ) {
      return err;
    }
  } FD_SCRATCH_SCOPE_END;


  FD_BORROWED_ACCOUNT_TRY_BORROW_IDX( ctx, ACC_IDX_LUT, lut_acct ) {
  fd_address_lookup_table_state_t state[1];
  fd_address_lookup_table_state_new( state );
  state->discriminant = fd_address_lookup_table_state_enum_lookup_table;
  fd_address_lookup_table_new( &state->inner.lookup_table );
  fd_memcpy( state->inner.lookup_table.meta.authority.key, authority_key->key, 32UL );
  state->inner.lookup_table.meta.has_authority = 1;
  state->inner.lookup_table.meta.deactivation_slot = ULONG_MAX;

  uchar * data = NULL;
  ulong   dlen = 0UL;
  int err = fd_account_get_data_mut( ctx, ACC_IDX_LUT, &data, &dlen );
  if( FD_UNLIKELY( err ) ) { 
    return err;
  }

  int state_err = fd_addrlut_serialize_meta( state, data, sizeof(fd_address_lookup_table_state_t) );
  if( FD_UNLIKELY( state_err ) ) { return state_err; }

  } FD_BORROWED_ACCOUNT_DROP( lut_acct );

  return FD_EXECUTOR_INSTR_SUCCESS;

# undef ACC_IDX_LUT
# undef ACC_IDX_AUTHORITY
# undef ACC_IDX_PAYER
}

static int
freeze_lookup_table( fd_exec_instr_ctx_t * ctx ) {

# define ACC_IDX_LUT       (0UL)
# define ACC_IDX_AUTHORITY (1UL)

  /* Prepare LUT account **********************************************/
  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L176-177 */

  /* try_borrow_account => get_index_of_instruction_account_in_transaction */
  FD_BORROWED_ACCOUNT_TRY_BORROW_IDX( ctx, ACC_IDX_LUT, lut_acct ) {

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L178-L181 */
  if( FD_UNLIKELY( 0!=memcmp( lut_acct->const_meta->info.owner, fd_solana_address_lookup_table_program_id.key, sizeof(fd_pubkey_t) ) ) ) {
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_OWNER;
  }

  } FD_BORROWED_ACCOUNT_DROP( lut_acct );

  /* Prepare authority account ****************************************/
  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L183-L184 */

  /* try_borrow_account => get_index_of_instruction_account_in_transaction */
  fd_pubkey_t const * authority_key = NULL;
  FD_BORROWED_ACCOUNT_TRY_BORROW_IDX( ctx, ACC_IDX_AUTHORITY, authority_acct ) {

  authority_key = authority_acct->pubkey;

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L186-L189 */
  if( FD_UNLIKELY( !fd_instr_acc_is_signer_idx( ctx->instr, ACC_IDX_AUTHORITY ) ) ) {
    FD_LOG_WARNING(( "Authority account must be a signer" ));
    return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
  }

  } FD_BORROWED_ACCOUNT_DROP( authority_acct );

  /* Update lookup table account **************************************/

  FD_BORROWED_ACCOUNT_TRY_BORROW_IDX( ctx, ACC_IDX_LUT, lut_acct ) {

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L194 */
  uchar const * lut_data    = lut_acct->const_data;
  ulong         lut_data_sz = lut_acct->const_meta->dlen;

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L195 */
  fd_addrlut_t lut[1];
  int err = fd_addrlut_deserialize( lut, lut_data, lut_data_sz );
  if( FD_UNLIKELY( err ) ) { 
    return err;
  }

  fd_address_lookup_table_t * state = &lut->state.inner.lookup_table;

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L197-L200 */
  if( FD_UNLIKELY( !state->meta.has_authority ) ) {
    FD_LOG_WARNING(("Lookup table is already frozen"));
    return FD_EXECUTOR_INSTR_ERR_ACC_IMMUTABLE;
  }

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L201-L203 */
  if( FD_UNLIKELY( 0!=memcmp( state->meta.authority.key, authority_key->key, sizeof(fd_pubkey_t) ) ) ) {
    FD_LOG_WARNING(("Incorrect Authority"));
    return FD_EXECUTOR_INSTR_ERR_INCORRECT_AUTHORITY;
  }

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L204-L207 */
  if( FD_UNLIKELY( state->meta.deactivation_slot!=ULONG_MAX ) ) {
    FD_LOG_WARNING(("Deactivated tables can't be frozen"));
    return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
  }

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L208-L211 */
  if( FD_UNLIKELY( !lut->addr_cnt ) ) {
    FD_LOG_WARNING(("Empty lookup tables can't be frozen"));
    return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
  }

  uchar *data = NULL;
  ulong dlen  = 0UL;
  err = fd_account_get_data_mut( ctx, ACC_IDX_LUT, &data, &dlen );
  if( FD_UNLIKELY( err ) ) {
    return err;
  }

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L213-L218 */
  state->meta.has_authority = 0;

  err = fd_addrlut_serialize_meta( &lut->state, data, dlen );
  if( FD_UNLIKELY( err ) ) { 
    return err;
  }

  } FD_BORROWED_ACCOUNT_DROP( lut_acct );

  return FD_EXECUTOR_INSTR_SUCCESS;
# undef ACC_IDX_LUT
# undef ACC_IDX_AUTHORITY
}

static int
extend_lookup_table( fd_exec_instr_ctx_t *       ctx,
                     fd_addrlut_extend_t const * extend ) {

# define ACC_IDX_LUT       (0UL)
# define ACC_IDX_AUTHORITY (1UL)
# define ACC_IDX_PAYER     (2UL)

  /* Prepare LUT account **********************************************/
  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L230-L236 */

  fd_pubkey_t const * lut_key = NULL;

  /* try_borrow_account => get_index_of_instruction_account_in_transaction */
  FD_BORROWED_ACCOUNT_TRY_BORROW_IDX( ctx, ACC_IDX_LUT, lut_acct ) {

  lut_key = lut_acct->pubkey;

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L233-235 */
  if( FD_UNLIKELY( 0!=memcmp( lut_acct->const_meta->info.owner, fd_solana_address_lookup_table_program_id.key, sizeof(fd_pubkey_t) ) ) )
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_OWNER;

  } FD_BORROWED_ACCOUNT_DROP( lut_acct );

  /* Prepare authority account ****************************************/
  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L238-L245 */

  fd_pubkey_t const * authority_key = NULL;

  /* try_borrow_account => get_index_of_instruction_account_in_transaction */
  FD_BORROWED_ACCOUNT_TRY_BORROW_IDX( ctx, ACC_IDX_AUTHORITY, authority_acct ) {

  authority_key = authority_acct->pubkey;

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L241-L244 */
  if( FD_UNLIKELY( !fd_instr_acc_is_signer_idx( ctx->instr, ACC_IDX_AUTHORITY ) ) ) {
    FD_LOG_WARNING(( "Authority account must be a signer" ));
    return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
  }

  } FD_BORROWED_ACCOUNT_DROP( authority_acct );

  /* Update lookup table account **************************************/

  uchar const * lut_data          = NULL;
  ulong         lut_data_sz       = 0UL;
  ulong         lut_lamports      = 0UL;
  ulong         new_table_data_sz = 0UL;


  FD_BORROWED_ACCOUNT_TRY_BORROW_IDX( ctx, ACC_IDX_LUT, lut_acct ) {

  lut_data     = lut_acct->const_data;
  lut_data_sz  = lut_acct->const_meta->dlen;
  lut_lamports = lut_acct->const_meta->info.lamports;

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L251 */
  fd_addrlut_t lut[1];
  int err = fd_addrlut_deserialize( lut, (uchar *)lut_data, lut_data_sz );
  if( FD_UNLIKELY( err ) ) { 
    return err; 
  }

  fd_address_lookup_table_t * state = &lut->state.inner.lookup_table;

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L253-L255 */
  if( FD_UNLIKELY( !state->meta.has_authority ) ) {
    return FD_EXECUTOR_INSTR_ERR_ACC_IMMUTABLE;
  }

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L256-L258 */
  if( FD_UNLIKELY( 0!=memcmp( state->meta.authority.key, authority_key->key, sizeof(fd_pubkey_t) ) ) ) {
    return FD_EXECUTOR_INSTR_ERR_INCORRECT_AUTHORITY;
  }

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L259-L262 */
  if( FD_UNLIKELY( state->meta.deactivation_slot != ULONG_MAX ) ) {
    FD_LOG_WARNING(( "Deactivated tables cannot be extended" ));
    return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
  }

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L263-L269 */
  if( FD_UNLIKELY( lut->addr_cnt >= FD_ADDRLUT_MAX_ADDR_CNT ) ) {
    FD_LOG_WARNING(( "Lookup table is full and cannot contain more addresses" ));
    return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
  }

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L271-L274 */
  if( FD_UNLIKELY( !extend->new_addrs_len ) ) {
    FD_LOG_WARNING(( "Must extend with at least one address" ));
    return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
  }

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L276-L279 */
  ulong old_addr_cnt = lut->addr_cnt;
  ulong new_addr_cnt = lut->addr_cnt + extend->new_addrs_len;
  if( FD_UNLIKELY( new_addr_cnt > FD_ADDRLUT_MAX_ADDR_CNT ) ) {
    FD_LOG_WARNING(( "Extended lookup table length %lu would exceed max capacity of %lu", new_addr_cnt, FD_ADDRLUT_MAX_ADDR_CNT ));
    return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
  }

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L290 */
  fd_sol_sysvar_clock_t clock[1];
  if( FD_UNLIKELY( !fd_sysvar_clock_read( clock, ctx->slot_ctx ) ) )
    return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR;

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L291-L299 */
  if( clock->slot!=state->meta.last_extended_slot ) {
    state->meta.last_extended_slot             = clock->slot;
    state->meta.last_extended_slot_start_index = (uchar)lut->addr_cnt;
  }

  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/address-lookup-table/src/processor.rs#L302
  new_table_data_sz = FD_ADDRLUT_META_SZ + new_addr_cnt * sizeof(fd_pubkey_t);

  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/address-lookup-table/src/processor.rs#L308
  if( FD_UNLIKELY( !fd_account_can_data_be_changed( ctx->instr, ACC_IDX_LUT, &err ) ) ) {
    return err;
  }

  int modify_err = fd_instr_borrowed_account_modify( ctx, lut_acct->pubkey, new_table_data_sz, &lut_acct );
  if( FD_UNLIKELY( modify_err ) ) {
    return FD_EXECUTOR_INSTR_ERR_FATAL;
  }

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L307-L310 */
  err = fd_addrlut_serialize_meta( &lut->state, lut_acct->data, lut_acct->meta->dlen );
  if( FD_UNLIKELY( err ) ) { 
    return err;
  }

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L311-L313 */
  do {
    uchar * new_keys = lut_acct->data + FD_ADDRLUT_META_SZ + old_addr_cnt * sizeof(fd_pubkey_t);
    fd_memcpy( new_keys, extend->new_addrs, extend->new_addrs_len * sizeof(fd_pubkey_t) );
  } while(0);
  lut_acct->meta->dlen = new_table_data_sz;
  lut->addr            = (fd_pubkey_t *)(lut_acct->data + FD_ADDRLUT_META_SZ);
  lut->addr_cnt        = new_addr_cnt;

  } FD_BORROWED_ACCOUNT_DROP( lut_acct );


  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L317-L321 */
  ulong required_lamports = fd_rent_exempt_minimum_balance( ctx->slot_ctx, new_table_data_sz );
        required_lamports = fd_ulong_max    ( required_lamports, 1UL );
        required_lamports = fd_ulong_sat_sub( required_lamports, lut_lamports );

  if( required_lamports ) {
    fd_pubkey_t const * payer_key = NULL;

    /* try_borrow_account => get_index_of_instruction_account_in_transaction */
    FD_BORROWED_ACCOUNT_TRY_BORROW_IDX( ctx, ACC_IDX_PAYER, payer_acct ) {

    payer_key = payer_acct->pubkey;
    /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L327-L330 */
    if( FD_UNLIKELY( !fd_instr_acc_is_signer_idx( ctx->instr, ACC_IDX_PAYER ) ) ) {
      FD_LOG_WARNING(( "Payer account must be a signer" ));
      return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
    }

    } FD_BORROWED_ACCOUNT_DROP( payer_acct );


    FD_SCRATCH_SCOPE_BEGIN {
      // Create account metas
      fd_vm_rust_account_meta_t * acct_metas = (fd_vm_rust_account_meta_t *)
                                                fd_scratch_alloc( FD_VM_RUST_ACCOUNT_META_ALIGN, 2 * sizeof(fd_vm_rust_account_meta_t) );
      fd_native_cpi_create_account_meta( payer_key, 1, 1, &acct_metas[0] );
      fd_native_cpi_create_account_meta( lut_key,   0, 1, &acct_metas[1] );

      // Create signers list
      fd_pubkey_t signers[16];
      ulong signers_cnt = 1UL;
      signers[0]        = *payer_key;

      // Create system program instruction
      fd_system_program_instruction_t instr = {0};
      instr.discriminant                    = fd_system_program_instruction_enum_transfer;
      instr.inner.transfer                  = required_lamports;

      int err = fd_native_cpi_execute_system_program_instruction( ctx,
                                                                  &instr,
                                                                  acct_metas,
                                                                  2UL,
                                                                  signers,
                                                                  signers_cnt );
      if( FD_UNLIKELY( err ) ) {
        return err;
      }
    } FD_SCRATCH_SCOPE_END;
  }

  return FD_EXECUTOR_INSTR_SUCCESS;

# undef ACC_IDX_LUT
# undef ACC_IDX_AUTHORITY
# undef ACC_IDX_PAYER
}

static int
deactivate_lookup_table( fd_exec_instr_ctx_t * ctx ) {

# define ACC_IDX_LUT       (0UL)
# define ACC_IDX_AUTHORITY (1UL)

  /* Prepare LUT account **********************************************/
  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L346-L351 */

  /* try_borrow_instruction_account => get_index_of_instruction_account_in_transaction */
  FD_BORROWED_ACCOUNT_TRY_BORROW_IDX( ctx, ACC_IDX_LUT, lut_acct ) {

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L348-L350 */
  if( FD_UNLIKELY( 0!=memcmp( lut_acct->const_meta->info.owner, fd_solana_address_lookup_table_program_id.key, sizeof(fd_pubkey_t) ) ) )
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_OWNER;

  } FD_BORROWED_ACCOUNT_DROP( lut_acct );

  /* Prepare authority account ****************************************/
  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L353-L360 */

  /* try_borrow_account => get_index_of_instruction_account_in_transaction */
  fd_pubkey_t const * authority_key = NULL;
  FD_BORROWED_ACCOUNT_TRY_BORROW_IDX( ctx, ACC_IDX_AUTHORITY, authority_acct ) {

  authority_key = authority_acct->pubkey;

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L356-L359 */
  if( FD_UNLIKELY( !fd_instr_acc_is_signer_idx( ctx->instr, ACC_IDX_AUTHORITY ) ) ) {
    FD_LOG_WARNING(( "Authority account must be a signer" ));
    return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
  }

  } FD_BORROWED_ACCOUNT_DROP( authority_acct );

  /* Update lookup table account **************************************/

  FD_BORROWED_ACCOUNT_TRY_BORROW_IDX( ctx, ACC_IDX_LUT, lut_acct ) {

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L364 */
  uchar const * lut_data    = lut_acct->const_data;
  ulong         lut_data_sz = lut_acct->const_meta->dlen;

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L365 */
  fd_addrlut_t lut[1];
  int err = fd_addrlut_deserialize( lut, (uchar *)lut_data, lut_data_sz );
  if( FD_UNLIKELY( err ) ) { 
    return err;
  }

  fd_address_lookup_table_t * state = &lut->state.inner.lookup_table;

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L367-L370 */
  if( FD_UNLIKELY( !state->meta.has_authority ) ) {
    FD_LOG_WARNING(( "Lookup table is already frozen" ));
    return FD_EXECUTOR_INSTR_ERR_ACC_IMMUTABLE;
  }

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L371-L373 */
  if( FD_UNLIKELY( 0!=memcmp( state->meta.authority.key, authority_key->key, sizeof(fd_pubkey_t) ) ) ) {
    return FD_EXECUTOR_INSTR_ERR_INCORRECT_AUTHORITY;
  }

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L374-L377 */
  if( FD_UNLIKELY( state->meta.deactivation_slot != ULONG_MAX ) ) {
    FD_LOG_WARNING(( "Lookup table is already deactivated" ));
    return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
  }

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L380 */
  fd_sol_sysvar_clock_t clock[1];
  if( FD_UNLIKELY( !fd_sysvar_clock_read( clock, ctx->slot_ctx ) ) ) {
    return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR;
  }

  uchar * data = NULL;
  ulong   dlen = 0UL;
  err = fd_account_get_data_mut ( ctx, ACC_IDX_LUT, &data, &dlen );
  if( FD_UNLIKELY( err ) ) {
    return err;
  }

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L381 */
  state->meta.deactivation_slot = clock->slot;

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L383-L386 */
  err = fd_addrlut_serialize_meta( &lut->state, data, dlen );
  if( FD_UNLIKELY( err ) ) { 
    return err;
  }

  } FD_BORROWED_ACCOUNT_DROP( lut_acct );

  return FD_EXECUTOR_INSTR_SUCCESS;

# undef ACC_IDX_LUT
# undef ACC_IDX_AUTHORITY
}

static int
close_lookup_table( fd_exec_instr_ctx_t * ctx ) {

# define ACC_IDX_LUT       (0UL)
# define ACC_IDX_AUTHORITY (1UL)
# define ACC_IDX_RECIPIENT (2UL)

  /* Prepare LUT account **********************************************/
  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L395-L400 */

  /* try_borrow_instruction_account => get_index_of_instruction_account_in_transaction */
  FD_BORROWED_ACCOUNT_TRY_BORROW_IDX( ctx, ACC_IDX_LUT, lut_acct ) {

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L397-L399 */
  if( FD_UNLIKELY( 0!=memcmp( lut_acct->const_meta->info.owner, fd_solana_address_lookup_table_program_id.key, sizeof(fd_pubkey_t) ) ) )
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_OWNER;

  } FD_BORROWED_ACCOUNT_DROP( lut_acct );

  /* Prepare authority account ****************************************/
  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L402-L409 */

  /* try_borrow_account => get_index_of_instruction_account_in_transaction */
  fd_pubkey_t const * authority_key = NULL;
  FD_BORROWED_ACCOUNT_TRY_BORROW_IDX( ctx, ACC_IDX_AUTHORITY, authority_acct ) {

  authority_key = authority_acct->pubkey;

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L405-L408 */
  if( FD_UNLIKELY( !fd_instr_acc_is_signer_idx( ctx->instr, ACC_IDX_AUTHORITY ) ) ) {
    FD_LOG_WARNING(( "Authority account must be a signer" ));
    return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
  }

  } FD_BORROWED_ACCOUNT_DROP( authority_acct );

  /* Update lookup table account **************************************/

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L411 */
  if( FD_UNLIKELY( ctx->instr->acct_cnt<3 ) ) {
    return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
  }

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L412-L420 */
  if( FD_UNLIKELY( ctx->instr->borrowed_accounts[0]==ctx->instr->borrowed_accounts[2] ) ) {
    FD_LOG_WARNING(( "Lookup table cannot be recipient of reclaimed lamports" ));
    return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
  }

  ulong         withdrawn_lamports = 0UL;
  uchar const * lut_data           = NULL;
  ulong         lut_data_sz        = 0UL;

  FD_BORROWED_ACCOUNT_TRY_BORROW_IDX( ctx, ACC_IDX_LUT, lut_acct ) {

  withdrawn_lamports = lut_acct->const_meta->info.lamports;
  lut_data           = lut_acct->const_data;
  lut_data_sz        = lut_acct->const_meta->dlen;

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L426 */
  fd_addrlut_t lut[1];
  int err = fd_addrlut_deserialize( lut, (uchar *)lut_data, lut_data_sz );
  if( FD_UNLIKELY( err ) ) { 
    return err;
  }

  fd_address_lookup_table_t * state = &lut->state.inner.lookup_table;

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L428-L431 */
  if( FD_UNLIKELY( !state->meta.has_authority ) ) {
    FD_LOG_WARNING(( "Lookup table is frozen" ));
    return FD_EXECUTOR_INSTR_ERR_ACC_IMMUTABLE;
  }

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L432-L434 */
  if( FD_UNLIKELY( 0!=memcmp( state->meta.authority.key, authority_key->key, sizeof(fd_pubkey_t) ) ) ) {
    return FD_EXECUTOR_INSTR_ERR_INCORRECT_AUTHORITY;
  }

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L437 */
  fd_sol_sysvar_clock_t clock[1];
  if( FD_UNLIKELY( !fd_sysvar_clock_read( clock, ctx->slot_ctx ) ) ) {
    return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR;
  }

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L438 */
  fd_slot_hashes_t slot_hashes[1];
  if( FD_UNLIKELY( !fd_sysvar_slot_hashes_read( slot_hashes, ctx->slot_ctx ) ) ) { 
    return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR;
  }

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L440 */
  ulong remaining_blocks = 0UL;
  int status = fd_addrlut_status( &state->meta, clock->slot, slot_hashes, &remaining_blocks );

  fd_bincode_destroy_ctx_t destroy = { .valloc = ctx->slot_ctx->valloc };
  fd_slot_hashes_destroy( slot_hashes, &destroy );

  switch( status ) {
    case FD_ADDRLUT_STATUS_ACTIVATED:
      FD_LOG_WARNING(( "Lookup table is not deactivated" ));
      return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
    case FD_ADDRLUT_STATUS_DEACTIVATING:
      FD_LOG_WARNING(( "Table cannot be closed until it's fully deactivated" ));
      return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
    case FD_ADDRLUT_STATUS_DEACTIVATED:
      break;
    default:
      __builtin_unreachable();
  }
  
  } FD_BORROWED_ACCOUNT_DROP( lut_acct );

  /* Add lamports to recipient ****************************************/

  /* try_borrow_instruction_account => get_index_of_instruction_account_in_transaction */
  FD_BORROWED_ACCOUNT_TRY_BORROW_IDX( ctx, ACC_IDX_RECIPIENT, recipient_acct ) {

  int err = fd_account_checked_add_lamports( ctx, ACC_IDX_RECIPIENT, withdrawn_lamports );
  if( FD_UNLIKELY( err ) ) {
    return err;
  }

  } FD_BORROWED_ACCOUNT_DROP( recipient_acct );

  /* Delete LUT account ***********************************************/

  FD_BORROWED_ACCOUNT_TRY_BORROW_IDX( ctx, ACC_IDX_LUT, lut_acct ) {

  int err;
  if( FD_UNLIKELY( !fd_account_can_data_be_changed( ctx->instr, ACC_IDX_LUT, &err ) ) ) {
    return err;
  }

  err = fd_account_set_lamports( ctx, ACC_IDX_LUT, 0UL );
  if( FD_UNLIKELY( err ) ) {
    return err;
  }
  err = fd_account_set_data_length( ctx, ACC_IDX_LUT, 0UL );
  if( FD_UNLIKELY( err ) ) {
    return err;
  }

  } FD_BORROWED_ACCOUNT_DROP( lut_acct );

  return FD_EXECUTOR_INSTR_SUCCESS;

# undef ACC_IDX_LUT
# undef ACC_IDX_AUTHORITY
# undef ACC_IDX_RECIPIENT
}

int
fd_address_lookup_table_program_execute( fd_exec_instr_ctx_t _ctx ) {
  do {
    int err = fd_exec_consume_cus( _ctx.txn_ctx, DEFAULT_COMPUTE_UNITS );
    if( FD_UNLIKELY( err ) ) return err;
  } while(0);

  fd_exec_instr_ctx_t * ctx = &_ctx;
  uchar const * instr_data    = ctx->instr->data;
  ulong         instr_data_sz = ctx->instr->data_sz;
  if( FD_UNLIKELY( instr_data==NULL ) ) {
    return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
  }

  FD_SCRATCH_SCOPE_BEGIN {

    fd_bincode_decode_ctx_t decode = {
      .valloc  = fd_scratch_virtual(),
      .data    = instr_data,
      .dataend = instr_data + instr_data_sz
    };
    fd_addrlut_instruction_t instr[1];
    /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L28 */
    if( FD_UNLIKELY( fd_addrlut_instruction_decode( instr, &decode ) != FD_BINCODE_SUCCESS ) ) {
      FD_LOG_WARNING(("Failed to decode instruction"));
      return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
    }


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
  } FD_SCRATCH_SCOPE_END;

  return FD_EXECUTOR_INSTR_SUCCESS;
}
