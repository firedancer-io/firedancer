#include "fd_address_lookup_table_program.h"
#include "../fd_executor.h"
#include "../fd_pubkey_utils.h"
#include "../fd_borrowed_account.h"
#include "../sysvar/fd_sysvar_slot_hashes.h"
#include "../../vm/syscall/fd_vm_syscall.h"
#include "fd_native_cpi.h"
#include "../fd_runtime_err.h"
#include "../fd_system_ids.h"

#include <string.h>

/* The worst case address lookup table footprint is for the extend
   instruction which is dynamically sized based on the number of new
   entries.  Assuming that the instruction takes up the full transaction
   MTU (1232 bytes), we can have 1232/32 entries = 38 entries.  This is
   not the tightest bound possible, but it is reasonable.
   The total footprint is then sizeof(fd_addrlut_instruction_t) + 38
   entries * sizeof(fd_pubkey_t) = 1240 bytes. */

#define FD_ADDRLUT_INSTR_FOOTPRINT (1240UL)

struct fd_addrlut {
  fd_address_lookup_table_state_t state;

  fd_pubkey_t const * addr;  /* points into account data */
  ulong               addr_cnt;
};

typedef struct fd_addrlut fd_addrlut_t;

#define FD_ADDRLUT_META_SZ       (56UL)
#define FD_ADDRLUT_MAX_ADDR_CNT (256UL)
#define DEFAULT_COMPUTE_UNITS   (750UL)
#define MAX_ENTRIES             FD_SYSVAR_SLOT_HASHES_CAP

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

  /* We anticipate that we require no allocations to decode the address lookup
     table state size and that the data is already preallocated. */
  fd_bincode_decode_ctx_t decode = {
    .data    = data,
    .dataend = data+data_sz
  };

  ulong total_sz = 0UL;
  if( FD_UNLIKELY( fd_address_lookup_table_state_decode_footprint( &decode, &total_sz )!=FD_BINCODE_SUCCESS ) ) {
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_DATA;
  }

  /* NOTE: We technically don't need this check if we assume that the caller
     is correctly handling the memory that is passed into this function. */
  if( FD_UNLIKELY( total_sz!=sizeof(fd_address_lookup_table_state_t) ) ) {
    FD_LOG_ERR(( "Unexpected total size of address lookup table state" ));
  }

  fd_address_lookup_table_state_decode( &lut->state, &decode );

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

static ulong
slot_hashes_position( fd_slot_hash_t const * hashes, /* deque */
                      ulong                  slot ) {
  /* Logic is copied from slice::binary_search_by() in Rust. While not fully optimized,
     it aims to achieve fuzzing conformance for both sorted and unsorted inputs.
     Returns the slot hash position of the input slot. */
  ulong size = deq_fd_slot_hash_t_cnt( hashes );
  if( FD_UNLIKELY( size==0UL ) ) return ULONG_MAX;

  ulong base = 0UL;
  while( size>1UL ) {
    ulong half = size / 2UL;
    ulong mid = base + half;
    ulong mid_slot = deq_fd_slot_hash_t_peek_index_const( hashes, mid )->slot;
    base = (slot>mid_slot) ? base : mid;
    size -= half;
  }

  return deq_fd_slot_hash_t_peek_index_const( hashes, base )->slot==slot ? base : ULONG_MAX;
}

/* https://github.com/anza-xyz/agave/blob/368ea563c423b0a85cc317891187e15c9a321521/sdk/program/src/address_lookup_table/state.rs#L81-L104 */
static uchar
fd_addrlut_status( fd_lookup_table_meta_t const * state,
                   ulong                          current_slot,
                   fd_slot_hash_t const *         slot_hashes, /* deque */
                   ulong *                        remaining_blocks ) {
  /* https://github.com/anza-xyz/agave/blob/368ea563c423b0a85cc317891187e15c9a321521/sdk/program/src/address_lookup_table/state.rs#L82-L83 */
  if( state->deactivation_slot==ULONG_MAX ) {
    return FD_ADDRLUT_STATUS_ACTIVATED;
  }

  /* https://github.com/anza-xyz/agave/blob/368ea563c423b0a85cc317891187e15c9a321521/sdk/program/src/address_lookup_table/state.rs#L84-L87 */
  if( state->deactivation_slot==current_slot ) {
    *remaining_blocks = MAX_ENTRIES + 1UL;
    return FD_ADDRLUT_STATUS_DEACTIVATING;
  }

  /* https://github.com/anza-xyz/agave/blob/368ea563c423b0a85cc317891187e15c9a321521/sdk/program/src/address_lookup_table/state.rs#L88-L100 */
  ulong slot_hash_position = slot_hashes_position( slot_hashes, state->deactivation_slot );
  if( slot_hash_position!=ULONG_MAX ) {
    *remaining_blocks = MAX_ENTRIES - slot_hash_position;
    return FD_ADDRLUT_STATUS_DEACTIVATING;
  }

  /* https://github.com/anza-xyz/agave/blob/368ea563c423b0a85cc317891187e15c9a321521/sdk/program/src/address_lookup_table/state.rs#L102 */
  return FD_ADDRLUT_STATUS_DEACTIVATED;
}

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

  int err;

  ulong               lut_lamports  = 0UL;
  fd_pubkey_t const * lut_key       = NULL;
  fd_pubkey_t const * lut_owner     = NULL;
  fd_pubkey_t const * authority_key = NULL;
  fd_pubkey_t const * payer_key     = NULL;

  /* Prepare LUT account **********************************************/
  /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/address-lookup-table/src/processor.rs#L59-L60 */
  /* try_borrow_instruction_account => get_index_of_instruction_account_in_transaction */
  fd_guarded_borrowed_account_t lut_acct = {0};
  FD_TRY_BORROW_INSTR_ACCOUNT_DEFAULT_ERR_CHECK( ctx, ACC_IDX_LUT, &lut_acct );

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L60-L62 */
  lut_lamports = fd_borrowed_account_get_lamports( &lut_acct );
  lut_key      = lut_acct.acct->pubkey;
  lut_owner    = fd_borrowed_account_get_owner( &lut_acct );

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L63-L70 */
  if( !FD_FEATURE_ACTIVE_BANK( ctx->txn_ctx->bank, relax_authority_signer_check_for_lookup_table_creation )
      && fd_borrowed_account_get_data_len( &lut_acct ) != 0UL ) {
    fd_log_collector_msg_literal( ctx, "Table account must not be allocated" );
    return FD_EXECUTOR_INSTR_ERR_ACC_ALREADY_INITIALIZED;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/address-lookup-table/src/processor.rs#L72 */
  fd_borrowed_account_drop( &lut_acct );

  /* Prepare authority account ****************************************/
  /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/address-lookup-table/src/processor.rs#L74-L75 */
  /* try_borrow_instruction_account => get_index_of_instruction_account_in_transaction */
  fd_guarded_borrowed_account_t authority_acct = {0};
  FD_TRY_BORROW_INSTR_ACCOUNT_DEFAULT_ERR_CHECK( ctx, ACC_IDX_AUTHORITY, &authority_acct );


  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L75 */
  authority_key = authority_acct.acct->pubkey;

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L76-L83 */
  if( !FD_FEATURE_ACTIVE_BANK( ctx->txn_ctx->bank, relax_authority_signer_check_for_lookup_table_creation )
      && !fd_instr_acc_is_signer_idx( ctx->instr, ACC_IDX_AUTHORITY, NULL ) ) {
    fd_log_collector_msg_literal( ctx, "Authority account must be a signer" );
    return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/address-lookup-table/src/processor.rs#L85 */
  fd_borrowed_account_drop( &authority_acct );

  /* Prepare payer account ********************************************/
  /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/address-lookup-table/src/processor.rs#L87-L88 */
    /* try_borrow_account => get_index_of_instruction_account_in_transaction */
  fd_guarded_borrowed_account_t payer_acct = {0};
  FD_TRY_BORROW_INSTR_ACCOUNT_DEFAULT_ERR_CHECK( ctx, ACC_IDX_PAYER, &payer_acct );

  payer_key = payer_acct.acct->pubkey;

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L89-L92 */
  if( !fd_instr_acc_is_signer_idx( ctx->instr, ACC_IDX_PAYER, NULL ) ) {
    fd_log_collector_msg_literal( ctx, "Payer account must be a signer" );
    return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/address-lookup-table/src/processor.rs#L94 */
  fd_borrowed_account_drop( &payer_acct );

  ulong derivation_slot = 1UL;

  do {
    fd_slot_hash_t const * slot_hash = fd_sysvar_cache_slot_hashes_join_const( ctx->sysvar_cache );
    if( FD_UNLIKELY( !slot_hash ) ) {
      return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR;
    }

    /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L97 */
    ulong is_recent_slot = slot_hashes_position( slot_hash, create->recent_slot )!=ULONG_MAX;
    fd_sysvar_cache_slot_hashes_leave_const( ctx->sysvar_cache, slot_hash );
    if( FD_UNLIKELY( !is_recent_slot ) ) {
      /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L100-L105 */
      /* Max msg_sz: 24 - 3 + 20 = 41 < 127 => we can use printf */
      fd_log_collector_printf_dangerous_max_127( ctx, "%lu is not a recent slot", create->recent_slot );
      return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
    } else {
      derivation_slot = create->recent_slot;
    }
  } while(0);

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L109-L118 */
  fd_pubkey_t derived_tbl_key[1];
  uchar const * seeds[2];
  ulong         seed_szs[2] = { sizeof(fd_pubkey_t), sizeof(ulong) };
  seeds[0] = (uchar const *)authority_key;
  seeds[1] = (uchar const *)&derivation_slot;
  err = fd_pubkey_derive_pda( &fd_solana_address_lookup_table_program_id, 2UL, seeds,
                                  seed_szs, (uchar*)&create->bump_seed, derived_tbl_key, &ctx->txn_ctx->err.custom_err );
  if( FD_UNLIKELY( err ) ) {
    return err;
  }

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L120-L127 */
  if( FD_UNLIKELY( 0!=memcmp( lut_key->key, derived_tbl_key->key, sizeof(fd_pubkey_t) ) ) ) {
    /* Max msg_sz: 44 - 2 + 45 = 87 < 127 => we can use printf */
    FD_BASE58_ENCODE_32_BYTES( derived_tbl_key->uc, derived_tbl_key_b58 );
    fd_log_collector_printf_dangerous_max_127( ctx,
      "Table address must match derived address: %s", derived_tbl_key_b58 );
    return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
  }

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L129-L135 */
  if( FD_FEATURE_ACTIVE_BANK( ctx->txn_ctx->bank, relax_authority_signer_check_for_lookup_table_creation )
      && 0==memcmp( lut_owner, fd_solana_address_lookup_table_program_id.key, sizeof(fd_pubkey_t) ) ) {
    return FD_EXECUTOR_INSTR_SUCCESS;
  }

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L137-L142 */

  fd_rent_t const rent = fd_sysvar_cache_rent_read_nofail( ctx->sysvar_cache );
  ulong tbl_acct_data_len = 0x38UL;
  ulong required_lamports = fd_rent_exempt_minimum_balance( &rent, tbl_acct_data_len );
  /* */ required_lamports = fd_ulong_max( required_lamports, 1UL );
  /* */ required_lamports = fd_ulong_sat_sub( required_lamports, lut_lamports );

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L144-L149 */
  if( required_lamports>0UL ) {
    // Create account metas
    fd_vm_rust_account_meta_t acct_metas[ 2UL ];
    fd_native_cpi_create_account_meta( payer_key, 1, 1, &acct_metas[0] );
    fd_native_cpi_create_account_meta( lut_key,   0, 1, &acct_metas[1] );

    // Create signers list
    fd_pubkey_t signers[16];
    ulong signers_cnt = 1;
    signers[0] = *payer_key;

    // Create system program instruction
    uchar instr_data[FD_TXN_MTU];
    fd_system_program_instruction_t instr = {
      .discriminant = fd_system_program_instruction_enum_transfer,
      .inner = {
        .transfer = required_lamports,
      }
    };

    fd_bincode_encode_ctx_t encode_ctx = {
      .data    = instr_data,
      .dataend = instr_data + FD_TXN_MTU
    };

    // This should never fail.
    int err = fd_system_program_instruction_encode( &instr, &encode_ctx );
    if( FD_UNLIKELY( err ) ) {
      return FD_EXECUTOR_INSTR_ERR_FATAL;
    }

    err = fd_native_cpi_native_invoke( ctx,
                                       &fd_solana_system_program_id,
                                       instr_data,
                                       FD_TXN_MTU,
                                       acct_metas,
                                       2UL,
                                       signers,
                                       signers_cnt );
    if( FD_UNLIKELY( err ) ) {
      return err;
    }
  }

  fd_vm_rust_account_meta_t acct_metas[ 1UL ];
  fd_native_cpi_create_account_meta( lut_key, 1, 1, acct_metas );

  // Create signers list
  fd_pubkey_t signers[16];
  ulong signers_cnt = 1;
  signers[0] = *lut_key;

  // Create system program allocate instruction
  uchar instr_data[FD_TXN_MTU];
  fd_system_program_instruction_t instr = {
    .discriminant = fd_system_program_instruction_enum_allocate,
    .inner = {
      .allocate = FD_LOOKUP_TABLE_META_SIZE,
    }
  };

  fd_bincode_encode_ctx_t encode_ctx = {
    .data    = instr_data,
    .dataend = instr_data + FD_TXN_MTU
  };

  // This should never fail.
  err = fd_system_program_instruction_encode( &instr, &encode_ctx );
  if( FD_UNLIKELY( err ) ) {
    return FD_EXECUTOR_INSTR_ERR_FATAL;
  }

  // Execute allocate instruction
  err = fd_native_cpi_native_invoke( ctx,
                                     &fd_solana_system_program_id,
                                     instr_data,
                                     FD_TXN_MTU,
                                     acct_metas,
                                     1UL,
                                     signers,
                                     signers_cnt );
  if( FD_UNLIKELY( err ) ) {
    return err;
  }

  // Prepare system program assign instruction
  instr = (fd_system_program_instruction_t) {
    .discriminant = fd_system_program_instruction_enum_assign,
    .inner = {
      .assign = fd_solana_address_lookup_table_program_id,
    }
  };

  encode_ctx = (fd_bincode_encode_ctx_t) {
    .data    = instr_data,
    .dataend = instr_data + FD_TXN_MTU
  };

  // This should never fail.
  err = fd_system_program_instruction_encode( &instr, &encode_ctx );
  if( FD_UNLIKELY( err ) ) {
    return FD_EXECUTOR_INSTR_ERR_FATAL;
  }

  // Execute assign instruction
  err = fd_native_cpi_native_invoke( ctx,
                                     &fd_solana_system_program_id,
                                     instr_data,
                                     FD_TXN_MTU,
                                     acct_metas,
                                     1UL,
                                     signers,
                                     signers_cnt );
  if( FD_UNLIKELY( err ) ) {
    return err;
  }


  /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/address-lookup-table/src/processor.rs#L164-L165 */
  FD_TRY_BORROW_INSTR_ACCOUNT_DEFAULT_ERR_CHECK( ctx, ACC_IDX_LUT, &lut_acct );

  fd_address_lookup_table_state_t state[1];
  fd_address_lookup_table_state_new( state );
  state->discriminant = fd_address_lookup_table_state_enum_lookup_table;
  fd_address_lookup_table_new( &state->inner.lookup_table );
  fd_memcpy( state->inner.lookup_table.meta.authority.key, authority_key->key, 32UL );
  state->inner.lookup_table.meta.has_authority = 1;
  state->inner.lookup_table.meta.deactivation_slot = ULONG_MAX;

  uchar * data = NULL;
  ulong   dlen = 0UL;
  err = fd_borrowed_account_get_data_mut( &lut_acct, &data, &dlen );
  if( FD_UNLIKELY( err ) ) {
    return err;
  }

  int state_err = fd_addrlut_serialize_meta( state, data, sizeof(fd_address_lookup_table_state_t) );
  if( FD_UNLIKELY( state_err ) ) { return state_err; }

  /* implicit drop of lut_acct */

  return FD_EXECUTOR_INSTR_SUCCESS;

# undef ACC_IDX_LUT
# undef ACC_IDX_AUTHORITY
# undef ACC_IDX_PAYER
}

static int
freeze_lookup_table( fd_exec_instr_ctx_t * ctx ) {

# define ACC_IDX_LUT       (0UL)
# define ACC_IDX_AUTHORITY (1UL)
  int err;

  /* Prepare LUT account **********************************************/
  /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/address-lookup-table/src/processor.rs#L177-L178 */
  /* try_borrow_account => get_index_of_instruction_account_in_transaction */
  fd_guarded_borrowed_account_t lut_acct = {0};
  FD_TRY_BORROW_INSTR_ACCOUNT_DEFAULT_ERR_CHECK( ctx, ACC_IDX_LUT, &lut_acct );

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L178-L181 */
  if( FD_UNLIKELY( 0!=memcmp( fd_borrowed_account_get_owner( &lut_acct ), fd_solana_address_lookup_table_program_id.key, sizeof(fd_pubkey_t) ) ) ) {
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_OWNER;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/address-lookup-table/src/processor.rs#L182 */
  fd_borrowed_account_drop( &lut_acct );

  /* Prepare authority account ****************************************/
  /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/address-lookup-table/src/processor.rs#L184-L185 */
  fd_pubkey_t const * authority_key = NULL;
  /* try_borrow_account => get_index_of_instruction_account_in_transaction */
  fd_guarded_borrowed_account_t authority_acct = {0};
  FD_TRY_BORROW_INSTR_ACCOUNT_DEFAULT_ERR_CHECK( ctx, ACC_IDX_AUTHORITY, &authority_acct );

  authority_key = authority_acct.acct->pubkey;

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L186-L189 */
  if( FD_UNLIKELY( !fd_instr_acc_is_signer_idx( ctx->instr, ACC_IDX_AUTHORITY, NULL ) ) ) {
    fd_log_collector_msg_literal( ctx, "Authority account must be a signer" );
    return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/address-lookup-table/src/processor.rs#L191 */
  fd_borrowed_account_drop( &authority_acct );

  /* Update lookup table account **************************************/
  /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/address-lookup-table/src/processor.rs#L193-L194 */
  FD_TRY_BORROW_INSTR_ACCOUNT_DEFAULT_ERR_CHECK( ctx, ACC_IDX_LUT, &lut_acct );

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L194 */
  uchar const * lut_data    = fd_borrowed_account_get_data( &lut_acct );
  ulong         lut_data_sz = fd_borrowed_account_get_data_len( &lut_acct );

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L195 */
  fd_addrlut_t lut[1];
  err = fd_addrlut_deserialize( lut, lut_data, lut_data_sz );
  if( FD_UNLIKELY( err ) ) {
    return err;
  }

  fd_address_lookup_table_t * state = &lut->state.inner.lookup_table;

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L197-L200 */
  if( FD_UNLIKELY( !state->meta.has_authority ) ) {
    fd_log_collector_msg_literal( ctx, "Lookup table is already frozen");
    return FD_EXECUTOR_INSTR_ERR_ACC_IMMUTABLE;
  }

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L201-L203 */
  if( FD_UNLIKELY( 0!=memcmp( state->meta.authority.key, authority_key->key, sizeof(fd_pubkey_t) ) ) ) {
    return FD_EXECUTOR_INSTR_ERR_INCORRECT_AUTHORITY;
  }

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L204-L207 */
  if( FD_UNLIKELY( state->meta.deactivation_slot!=ULONG_MAX ) ) {
    fd_log_collector_msg_literal( ctx, "Deactivated tables cannot be frozen" );
    return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
  }

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L208-L211 */
  if( FD_UNLIKELY( !lut->addr_cnt ) ) {
    fd_log_collector_msg_literal( ctx, "Empty lookup tables cannot be frozen" );
    return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
  }

  uchar *data = NULL;
  ulong dlen  = 0UL;
  err = fd_borrowed_account_get_data_mut( &lut_acct, &data, &dlen );
  if( FD_UNLIKELY( err ) ) {
    return err;
  }

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L213-L218 */
  state->meta.has_authority = 0;

  err = fd_addrlut_serialize_meta( &lut->state, data, dlen );
  if( FD_UNLIKELY( err ) ) {
    return err;
  }

  /* implicit drop of lut_acct */

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
  int err;

  /* Prepare LUT account **********************************************/
  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L230-L236 */
  fd_pubkey_t const * lut_key = NULL;
  /* try_borrow_account => get_index_of_instruction_account_in_transaction */

  /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/address-lookup-table/src/processor.rs#L231-L232 */
  fd_guarded_borrowed_account_t lut_acct = {0};
  FD_TRY_BORROW_INSTR_ACCOUNT_DEFAULT_ERR_CHECK( ctx, ACC_IDX_LUT, &lut_acct );

  lut_key = lut_acct.acct->pubkey;

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L233-235 */
  if( FD_UNLIKELY( 0!=memcmp( fd_borrowed_account_get_owner( &lut_acct ), fd_solana_address_lookup_table_program_id.key, sizeof(fd_pubkey_t) ) ) )
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_OWNER;

    /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/address-lookup-table/src/processor.rs#L237 */
  fd_borrowed_account_drop( &lut_acct );

  /* Prepare authority account ****************************************/
  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L238-L245 */
  fd_pubkey_t const * authority_key = NULL;
  /* try_borrow_account => get_index_of_instruction_account_in_transaction */
  /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/address-lookup-table/src/processor.rs#L239-L240 */
  fd_guarded_borrowed_account_t authority_acct = {0};
  FD_TRY_BORROW_INSTR_ACCOUNT_DEFAULT_ERR_CHECK( ctx, ACC_IDX_AUTHORITY, &authority_acct );

  authority_key = authority_acct.acct->pubkey;

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L241-L244 */
  if( FD_UNLIKELY( !fd_instr_acc_is_signer_idx( ctx->instr, ACC_IDX_AUTHORITY, NULL ) ) ) {
    fd_log_collector_msg_literal( ctx, "Authority account must be a signer" );
    return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/address-lookup-table/src/processor.rs#L246 */
  fd_borrowed_account_drop( &authority_acct );

  uchar const * lut_data          = NULL;
  ulong         lut_data_sz       = 0UL;
  ulong         lut_lamports      = 0UL;
  ulong         new_table_data_sz = 0UL;

  /* Update lookup table account **************************************/

  /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/address-lookup-table/src/processor.rs#L248-L249 */
  FD_TRY_BORROW_INSTR_ACCOUNT_DEFAULT_ERR_CHECK( ctx, ACC_IDX_LUT, &lut_acct );

  lut_data     = fd_borrowed_account_get_data( &lut_acct );
  lut_data_sz  = fd_borrowed_account_get_data_len( &lut_acct );
  lut_lamports = fd_borrowed_account_get_lamports( &lut_acct );

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L251 */
  fd_addrlut_t lut[1];
  err = fd_addrlut_deserialize( lut, (uchar *)lut_data, lut_data_sz );
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
    fd_log_collector_msg_literal( ctx, "Deactivated tables cannot be extended" );
    return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
  }

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L263-L269 */
  if( FD_UNLIKELY( lut->addr_cnt >= FD_ADDRLUT_MAX_ADDR_CNT ) ) {
    fd_log_collector_msg_literal( ctx, "Lookup table is full and cannot contain more addresses" );
    return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
  }

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L271-L274 */
  if( FD_UNLIKELY( !extend->new_addrs_len ) ) {
    fd_log_collector_msg_literal( ctx, "Must extend with at least one address" );
    return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
  }

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L276-L279 */
  ulong old_addr_cnt = lut->addr_cnt;
  ulong new_addr_cnt = lut->addr_cnt + extend->new_addrs_len;
  if( FD_UNLIKELY( new_addr_cnt > FD_ADDRLUT_MAX_ADDR_CNT ) ) {
    /* Max msg_sz: 65 - 6 + 20*2 = 99 < 127 => we can use printf */
    fd_log_collector_printf_dangerous_max_127( ctx,
      "Extended lookup table length %lu would exceed max capacity of %lu", new_addr_cnt, FD_ADDRLUT_MAX_ADDR_CNT );
    return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
  }

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L290 */
  fd_sol_sysvar_clock_t clock_;
  fd_sol_sysvar_clock_t const * clock = fd_sysvar_cache_clock_read( ctx->sysvar_cache, &clock_ );
  if( FD_UNLIKELY( !clock ) ) {
    return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR;
  }

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L291-L299 */
  if( clock->slot!=state->meta.last_extended_slot ) {
    state->meta.last_extended_slot             = clock->slot;
    state->meta.last_extended_slot_start_index = (uchar)lut->addr_cnt;
  }

  // https://github.com/anza-xyz/agave/blob/v2.0.1/programs/address-lookup-table/src/processor.rs#L302
  new_table_data_sz = FD_ADDRLUT_META_SZ + new_addr_cnt * sizeof(fd_pubkey_t);

  /* https://github.com/anza-xyz/agave/blob/v2.2.0/programs/address-lookup-table/src/processor.rs#L286 */
  uchar * lut_data_mut = NULL;
  ulong   lut_data_mut_len = 0;
  err = fd_borrowed_account_get_data_mut( &lut_acct, &lut_data_mut, &lut_data_mut_len );
  if( FD_UNLIKELY( err ) ) {
    return err;
  }
  fd_txn_account_resize( lut_acct.acct, new_table_data_sz );

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L307-L310 */
  err = fd_addrlut_serialize_meta( &lut->state, lut_data_mut, lut_data_mut_len );
  if( FD_UNLIKELY( err ) ) {
    return err;
  }

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L311-L313 */
  do {
    uchar * new_keys = lut_data_mut + FD_ADDRLUT_META_SZ + old_addr_cnt * sizeof(fd_pubkey_t);
    fd_memcpy( new_keys, extend->new_addrs, extend->new_addrs_len * sizeof(fd_pubkey_t) );
  } while(0);
  fd_borrowed_account_set_data_length( &lut_acct, new_table_data_sz );
  lut->addr            = (fd_pubkey_t *)(lut_data_mut + FD_ADDRLUT_META_SZ);
  lut->addr_cnt        = new_addr_cnt;

  /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/address-lookup-table/src/processor.rs#L316 */
  fd_borrowed_account_drop( &lut_acct );


  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L317-L321 */
  fd_rent_t rent[1] = { fd_sysvar_cache_rent_read_nofail( ctx->sysvar_cache ) };
  ulong required_lamports = fd_rent_exempt_minimum_balance( rent, new_table_data_sz );
  /* */ required_lamports = fd_ulong_max    ( required_lamports, 1UL );
  /* */ required_lamports = fd_ulong_sat_sub( required_lamports, lut_lamports );

  if( required_lamports ) {
    fd_pubkey_t const * payer_key = NULL;

    /* try_borrow_account => get_index_of_instruction_account_in_transaction */
    /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/address-lookup-table/src/processor.rs#L325-L326 */
    fd_guarded_borrowed_account_t payer_acct = {0};
    FD_TRY_BORROW_INSTR_ACCOUNT_DEFAULT_ERR_CHECK( ctx, ACC_IDX_PAYER, &payer_acct );

    payer_key = payer_acct.acct->pubkey;
    /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L327-L330 */
    if( FD_UNLIKELY( !fd_instr_acc_is_signer_idx( ctx->instr, ACC_IDX_PAYER, NULL ) ) ) {
      fd_log_collector_msg_literal( ctx, "Payer account must be a signer" );
      return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
    }

    /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/address-lookup-table/src/processor.rs#L332 */
    fd_borrowed_account_drop( &payer_acct );

    // Create account metas
    fd_vm_rust_account_meta_t acct_metas[ 2UL ];
    fd_native_cpi_create_account_meta( payer_key, 1, 1, &acct_metas[0] );
    fd_native_cpi_create_account_meta( lut_key,   0, 1, &acct_metas[1] );

    // Create signers list
    fd_pubkey_t signers[16];
    ulong signers_cnt = 1UL;
    signers[0]        = *payer_key;

    // Create system program instruction
    uchar instr_data[FD_TXN_MTU];
    fd_system_program_instruction_t instr = {
      .discriminant = fd_system_program_instruction_enum_transfer,
      .inner = {
        .transfer = required_lamports,
      }
    };

    fd_bincode_encode_ctx_t encode_ctx = {
      .data    = instr_data,
      .dataend = instr_data + FD_TXN_MTU
    };

    // This should never fail.
    int err = fd_system_program_instruction_encode( &instr, &encode_ctx );
    if( FD_UNLIKELY( err ) ) {
      return FD_EXECUTOR_INSTR_ERR_FATAL;
    }

    err = fd_native_cpi_native_invoke( ctx,
                                       &fd_solana_system_program_id,
                                       instr_data,
                                       FD_TXN_MTU,
                                       acct_metas,
                                       2UL,
                                       signers,
                                       signers_cnt );
    if( FD_UNLIKELY( err ) ) {
      return err;
    }
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
  int err;

  /* Prepare LUT account **********************************************/
  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L346-L351 */
  /* try_borrow_instruction_account => get_index_of_instruction_account_in_transaction */

  /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/address-lookup-table/src/processor.rs#L347-L348 */
  fd_guarded_borrowed_account_t lut_acct = {0};
  FD_TRY_BORROW_INSTR_ACCOUNT_DEFAULT_ERR_CHECK( ctx, ACC_IDX_LUT, &lut_acct );

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L348-L350 */
  if( FD_UNLIKELY( 0!=memcmp( fd_borrowed_account_get_owner( &lut_acct ), fd_solana_address_lookup_table_program_id.key, sizeof(fd_pubkey_t) ) ) )
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_OWNER;

    /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/address-lookup-table/src/processor.rs#L352 */
  fd_borrowed_account_drop( &lut_acct );

  /* Prepare authority account ****************************************/
  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L353-L360 */
  fd_pubkey_t const * authority_key = NULL;
  /* try_borrow_account => get_index_of_instruction_account_in_transaction */
  /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/address-lookup-table/src/processor.rs#L354-L355 */
  fd_guarded_borrowed_account_t authority_acct = {0};
  FD_TRY_BORROW_INSTR_ACCOUNT_DEFAULT_ERR_CHECK( ctx, ACC_IDX_AUTHORITY, &authority_acct );

  authority_key = authority_acct.acct->pubkey;

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L356-L359 */
  if( FD_UNLIKELY( !fd_instr_acc_is_signer_idx( ctx->instr, ACC_IDX_AUTHORITY, NULL ) ) ) {
    fd_log_collector_msg_literal( ctx, "Authority account must be a signer" );
    return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/address-lookup-table/src/processor.rs#L361 */
  fd_borrowed_account_drop( &authority_acct );

  /* Update lookup table account **************************************/

  /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/address-lookup-table/src/processor.rs#L363-L364 */
  FD_TRY_BORROW_INSTR_ACCOUNT_DEFAULT_ERR_CHECK( ctx, ACC_IDX_LUT, &lut_acct );

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L364 */
  uchar const * lut_data    = fd_borrowed_account_get_data( &lut_acct );
  ulong         lut_data_sz = fd_borrowed_account_get_data_len( &lut_acct );

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L365 */
  fd_addrlut_t lut[1];
  err = fd_addrlut_deserialize( lut, (uchar *)lut_data, lut_data_sz );
  if( FD_UNLIKELY( err ) ) {
    return err;
  }

  fd_address_lookup_table_t * state = &lut->state.inner.lookup_table;

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L367-L370 */
  if( FD_UNLIKELY( !state->meta.has_authority ) ) {
    fd_log_collector_msg_literal( ctx, "Lookup table is frozen" );
    return FD_EXECUTOR_INSTR_ERR_ACC_IMMUTABLE;
  }

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L371-L373 */
  if( FD_UNLIKELY( 0!=memcmp( state->meta.authority.key, authority_key->key, sizeof(fd_pubkey_t) ) ) ) {
    return FD_EXECUTOR_INSTR_ERR_INCORRECT_AUTHORITY;
  }

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L374-L377 */
  if( FD_UNLIKELY( state->meta.deactivation_slot != ULONG_MAX ) ) {
    fd_log_collector_msg_literal( ctx, "Lookup table is already deactivated" );
    return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
  }

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L380 */
  fd_sol_sysvar_clock_t clock_;
  fd_sol_sysvar_clock_t const * clock = fd_sysvar_cache_clock_read( ctx->sysvar_cache, &clock_ );
  if( FD_UNLIKELY( !clock ) ) {
    return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR;
  }

  uchar * data = NULL;
  ulong   dlen = 0UL;
  err = fd_borrowed_account_get_data_mut ( &lut_acct, &data, &dlen );
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

  /* implicit drop of lut_acct */

  return FD_EXECUTOR_INSTR_SUCCESS;

# undef ACC_IDX_LUT
# undef ACC_IDX_AUTHORITY
}

static int
close_lookup_table( fd_exec_instr_ctx_t * ctx ) {

# define ACC_IDX_LUT       (0UL)
# define ACC_IDX_AUTHORITY (1UL)
# define ACC_IDX_RECIPIENT (2UL)
  int err;

  /* Prepare LUT account **********************************************/
  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L395-L400 */
  /* try_borrow_instruction_account => get_index_of_instruction_account_in_transaction */

  /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/address-lookup-table/src/processor.rs#L396-L397 */
  fd_guarded_borrowed_account_t lut_acct = {0};
  FD_TRY_BORROW_INSTR_ACCOUNT_DEFAULT_ERR_CHECK( ctx, ACC_IDX_LUT, &lut_acct );

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L397-L399 */
  if( FD_UNLIKELY( 0!=memcmp( fd_borrowed_account_get_owner( &lut_acct ), fd_solana_address_lookup_table_program_id.key, sizeof(fd_pubkey_t) ) ) )
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_OWNER;

    /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/address-lookup-table/src/processor.rs#L401 */
  fd_borrowed_account_drop( &lut_acct );

  /* Prepare authority account ****************************************/
  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L402-L409 */
  fd_pubkey_t const * authority_key = NULL;
  /* try_borrow_account => get_index_of_instruction_account_in_transaction */
  /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/address-lookup-table/src/processor.rs#L403-L404 */
  fd_guarded_borrowed_account_t authority_acct = {0};
  FD_TRY_BORROW_INSTR_ACCOUNT_DEFAULT_ERR_CHECK( ctx, ACC_IDX_AUTHORITY, &authority_acct );

  authority_key = authority_acct.acct->pubkey;

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L405-L408 */
  if( FD_UNLIKELY( !fd_instr_acc_is_signer_idx( ctx->instr, ACC_IDX_AUTHORITY, NULL ) ) ) {
    fd_log_collector_msg_literal( ctx, "Authority account must be a signer" );
    return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/address-lookup-table/src/processor.rs#L410 */
  fd_borrowed_account_drop( &authority_acct );

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L411 */
  err = fd_exec_instr_ctx_check_num_insn_accounts( ctx, 3 );
  if( FD_UNLIKELY( err ) ) {
    return err;
  }

  /* It's ok to directly access the instruction accounts because we already verified 3 expected instruction accounts.
     https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L412-L420 */
  if( FD_UNLIKELY( ctx->instr->accounts[0].index_in_transaction ==
                   ctx->instr->accounts[2].index_in_transaction ) ) {
    fd_log_collector_msg_literal( ctx, "Lookup table cannot be the recipient of reclaimed lamports" );
    return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
  }

  ulong         withdrawn_lamports = 0UL;
  uchar const * lut_data           = NULL;
  ulong         lut_data_sz        = 0UL;

  /* Update lookup table account **************************************/

  /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/address-lookup-table/src/processor.rs#L423-L424 */
  FD_TRY_BORROW_INSTR_ACCOUNT_DEFAULT_ERR_CHECK( ctx, ACC_IDX_LUT, &lut_acct );

  withdrawn_lamports = fd_borrowed_account_get_lamports( &lut_acct );
  lut_data           = fd_borrowed_account_get_data( &lut_acct );
  lut_data_sz        = fd_borrowed_account_get_data_len( &lut_acct );

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L426 */
  fd_addrlut_t lut[1];
  err = fd_addrlut_deserialize( lut, (uchar *)lut_data, lut_data_sz );
  if( FD_UNLIKELY( err ) ) {
    return err;
  }

  fd_address_lookup_table_t * state = &lut->state.inner.lookup_table;

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L428-L431 */
  if( FD_UNLIKELY( !state->meta.has_authority ) ) {
    fd_log_collector_msg_literal( ctx,  "Lookup table is frozen" );
    return FD_EXECUTOR_INSTR_ERR_ACC_IMMUTABLE;
  }

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L432-L434 */
  if( FD_UNLIKELY( 0!=memcmp( state->meta.authority.key, authority_key->key, sizeof(fd_pubkey_t) ) ) ) {
    return FD_EXECUTOR_INSTR_ERR_INCORRECT_AUTHORITY;
  }

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L437 */
  fd_sol_sysvar_clock_t clock_;
  fd_sol_sysvar_clock_t * clock = fd_sysvar_cache_clock_read( ctx->sysvar_cache, &clock_ );
  if( FD_UNLIKELY( !clock ) ) {
    return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR;
  }

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L438 */
  fd_slot_hash_t const * slot_hash = fd_sysvar_cache_slot_hashes_join_const( ctx->sysvar_cache );
  if( FD_UNLIKELY( !slot_hash ) ) {
    return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR;
  }

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L440 */
  ulong remaining_blocks = 0UL;
  int status = fd_addrlut_status( &state->meta, clock->slot, slot_hash, &remaining_blocks );
  fd_sysvar_cache_slot_hashes_leave_const( ctx->sysvar_cache, slot_hash );

  switch( status ) {
    case FD_ADDRLUT_STATUS_ACTIVATED:
      fd_log_collector_msg_literal( ctx, "Lookup table is not deactivated" );
      return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
    case FD_ADDRLUT_STATUS_DEACTIVATING:
      /* Max msg_sz: 65 - 3 + 20 = 82 < 127 => we can use printf */
      fd_log_collector_printf_dangerous_max_127( ctx,
        "Table cannot be closed until it's fully deactivated in %lu blocks", remaining_blocks );
      return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
    case FD_ADDRLUT_STATUS_DEACTIVATED:
      break;
    default:
      __builtin_unreachable();
  }

  /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/address-lookup-table/src/processor.rs#L456 */
  fd_borrowed_account_drop( &lut_acct );

  /* Add lamports to recipient ****************************************/
  /* try_borrow_instruction_account => get_index_of_instruction_account_in_transaction */

  /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/address-lookup-table/src/processor.rs#L458-L459 */
  fd_guarded_borrowed_account_t recipient_acct = {0};
  FD_TRY_BORROW_INSTR_ACCOUNT_DEFAULT_ERR_CHECK( ctx, ACC_IDX_RECIPIENT, &recipient_acct );

  err = fd_borrowed_account_checked_add_lamports( &recipient_acct, withdrawn_lamports );
  if( FD_UNLIKELY( err ) ) {
    return err;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/address-lookup-table/src/processor.rs#L461 */
  fd_borrowed_account_drop( &recipient_acct );

  /* Delete LUT account ***********************************************/

  /* https://github.com/anza-xyz/agave/blob/v2.1.4/programs/address-lookup-table/src/processor.rs#L463-L464 */
  FD_TRY_BORROW_INSTR_ACCOUNT_DEFAULT_ERR_CHECK( ctx, ACC_IDX_LUT, &lut_acct );

  err = fd_borrowed_account_set_data_length( &lut_acct, 0UL );
  if( FD_UNLIKELY( err ) ) {
    return err;
  }

  err = fd_borrowed_account_set_lamports( &lut_acct, 0UL );
  if( FD_UNLIKELY( err ) ) {
    return err;
  }

  return FD_EXECUTOR_INSTR_SUCCESS;

# undef ACC_IDX_LUT
# undef ACC_IDX_AUTHORITY
# undef ACC_IDX_RECIPIENT
}

int
fd_address_lookup_table_program_execute( fd_exec_instr_ctx_t * ctx ) {
  /* Prevent execution of migrated native programs */
  if( FD_UNLIKELY( FD_FEATURE_ACTIVE_BANK( ctx->txn_ctx->bank, migrate_address_lookup_table_program_to_core_bpf ) ) ) {
    return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_PROGRAM_ID;
  }

  FD_EXEC_CU_UPDATE( ctx, DEFAULT_COMPUTE_UNITS );

  uchar const * instr_data    = ctx->instr->data;
  ulong         instr_data_sz = ctx->instr->data_sz;
  if( FD_UNLIKELY( instr_data==NULL ) ) {
    return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
  }
  if( FD_UNLIKELY( instr_data_sz>FD_TXN_MTU ) ) {
    return FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA;
  }

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L28 */
  uchar instr_mem[ FD_ADDRLUT_INSTR_FOOTPRINT ] __attribute__((aligned(alignof(fd_addrlut_instruction_t))));
  fd_addrlut_instruction_t * instr = fd_bincode_decode_static(
      addrlut_instruction,
      instr_mem,
      instr_data,
      instr_data_sz,
      NULL );
  if( FD_UNLIKELY( !instr ) ) {
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

  return FD_EXECUTOR_INSTR_SUCCESS;
}

/**********************************************************************/
/* Public API                                                         */
/**********************************************************************/

/* https://github.com/anza-xyz/agave/blob/368ea563c423b0a85cc317891187e15c9a321521/sdk/program/src/address_lookup_table/state.rs#L72-L78 */
static uchar
is_active( fd_address_lookup_table_t const * self,
           ulong                             current_slot,
           fd_slot_hash_t const *            slot_hashes ) { /* deque */
  /* https://github.com/anza-xyz/agave/blob/368ea563c423b0a85cc317891187e15c9a321521/sdk/program/src/address_lookup_table/state.rs#L73-L77 */
  ulong _dummy[1];
  switch( fd_addrlut_status( &self->meta, current_slot, slot_hashes, _dummy ) ) {
    case FD_ADDRLUT_STATUS_ACTIVATED:
    case FD_ADDRLUT_STATUS_DEACTIVATING:
      return 1;
    case FD_ADDRLUT_STATUS_DEACTIVATED:
      return 0;
    default:
      __builtin_unreachable();
  }
}

/* Sets active_addresses_len on success
   https://github.com/anza-xyz/agave/blob/368ea563c423b0a85cc317891187e15c9a321521/sdk/program/src/address_lookup_table/state.rs#L142-L164 */
int
fd_get_active_addresses_len( fd_address_lookup_table_t * self,
                             ulong                       current_slot,
                             fd_slot_hash_t const *      slot_hashes, /* deque */
                             ulong                       addresses_len,
                             ulong *                     active_addresses_len ) {
  /* https://github.com/anza-xyz/agave/blob/368ea563c423b0a85cc317891187e15c9a321521/sdk/program/src/address_lookup_table/state.rs#L147-L152 */
  if( FD_UNLIKELY( !is_active( self, current_slot, slot_hashes ) ) ) {
    return FD_RUNTIME_TXN_ERR_ADDRESS_LOOKUP_TABLE_NOT_FOUND;
  }

  /* https://github.com/anza-xyz/agave/blob/368ea563c423b0a85cc317891187e15c9a321521/sdk/program/src/address_lookup_table/state.rs#L157-L161 */
  *active_addresses_len = ( current_slot > self->meta.last_extended_slot )
      ? addresses_len
      : self->meta.last_extended_slot_start_index;

  return FD_RUNTIME_EXECUTE_SUCCESS;
}
