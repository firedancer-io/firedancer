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
#include "../../vm/syscall/fd_vm_syscall.h" /* FIXME: GROSS (for prepare_instruction) */

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

  int bin_err = fd_address_lookup_table_state_encode( state, &encode );
  FD_TEST( !bin_err );

  fd_memset( data, 0, (ulong)encode.dataend - (ulong)encode.data );
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

static inline void create_account_meta(fd_pubkey_t const * key, uchar is_signer, uchar is_writable, fd_vm_rust_account_meta_t * meta) {
  meta->is_signer = is_signer;
  meta->is_writable = is_writable;
  fd_memcpy(meta->pubkey, key->key, sizeof(fd_pubkey_t));
}

static int execute_system_program_instruction(fd_exec_instr_ctx_t * ctx,
                                              fd_system_program_instruction_t const * instr,
                                              fd_vm_rust_account_meta_t const * acct_metas,
                                              ulong acct_metas_len,
                                              fd_pubkey_t const * signers,
                                              ulong signers_cnt) {
  fd_instr_info_t instr_info[1];
  fd_instruction_account_t instruction_accounts[256];
  ulong instruction_accounts_cnt;

  for (ulong i = 0; i < ctx->txn_ctx->accounts_cnt; i++) {
    if (memcmp(fd_solana_system_program_id.key, ctx->txn_ctx->accounts[i].key, sizeof(fd_pubkey_t)) == 0) {
      instr_info->program_id = (uchar)i;
      break;
    }
  }

  ulong starting_lamports = 0;
  uchar acc_idx_seen[256];
  memset(acc_idx_seen, 0, 256);

  instr_info->program_id_pubkey = fd_solana_system_program_id;
  instr_info->acct_cnt = (ushort)acct_metas_len;
  for (ulong j = 0; j < acct_metas_len; j++) {
    fd_vm_rust_account_meta_t const * acct_meta = &acct_metas[j];

    for (ulong k = 0; k < ctx->txn_ctx->accounts_cnt; k++) {
      if (memcmp(acct_meta->pubkey, ctx->txn_ctx->accounts[k].uc, sizeof(fd_pubkey_t)) == 0) {
        instr_info->acct_pubkeys[j] = ctx->txn_ctx->accounts[k];
        instr_info->acct_txn_idxs[j] = (uchar)k;
        instr_info->acct_flags[j] = 0;
        instr_info->borrowed_accounts[j] = &ctx->txn_ctx->borrowed_accounts[k];

        instr_info->is_duplicate[j] = acc_idx_seen[k];
        if( FD_LIKELY( !acc_idx_seen[k] ) ) {
          /* This is the first time seeing this account */
          acc_idx_seen[k] = 1;
          if( instr_info->borrowed_accounts[j]->const_meta != NULL ) {
            starting_lamports += instr_info->borrowed_accounts[j]->const_meta->info.lamports;
          }
        }

        if( acct_meta->is_writable ) {
          instr_info->acct_flags[j] |= FD_INSTR_ACCT_FLAGS_IS_WRITABLE;
        }
        // TODO: should check the parent has signer flag set
        if( acct_meta->is_signer ) {
          instr_info->acct_flags[j] |= FD_INSTR_ACCT_FLAGS_IS_SIGNER;
        } else {
          for( ulong k = 0; k < signers_cnt; k++ ) {
            if( memcmp( &signers[k], &acct_meta->pubkey, sizeof( fd_pubkey_t ) ) == 0 ) {
              instr_info->acct_flags[j] |= FD_INSTR_ACCT_FLAGS_IS_SIGNER;
              break;
            }
          }
        }
        break;
      }
    }

    instr_info->starting_lamports = starting_lamports;
  }

  fd_bincode_encode_ctx_t ctx2;
  void * buf = fd_valloc_malloc(ctx->valloc, FD_SYSTEM_PROGRAM_INSTRUCTION_ALIGN, sizeof(fd_system_program_instruction_t));
  ctx2.data = buf;
  ctx2.dataend = (uchar*)ctx2.data + sizeof(fd_system_program_instruction_t);
  int err = fd_system_program_instruction_encode(instr, &ctx2);
  if (err != FD_EXECUTOR_INSTR_SUCCESS) {
    FD_LOG_WARNING(("Encode failed"));
    return err;
  }

  instr_info->data = buf;
  instr_info->data_sz = (ushort) sizeof(fd_system_program_instruction_t);
  int exec_err = fd_vm_prepare_instruction(ctx->instr, instr_info, ctx, instruction_accounts, &instruction_accounts_cnt, signers, signers_cnt);
  if( exec_err != FD_EXECUTOR_INSTR_SUCCESS ) {
    FD_LOG_WARNING(("PREPARE FAILED"));
    return exec_err;
  }
  return fd_execute_instr( ctx->txn_ctx, instr_info );
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

   In some places of this program, the Labs implementation acquires a
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
  if( FD_UNLIKELY( ctx->instr->acct_cnt < ACC_IDX_LUT+1UL ) )
    return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
  fd_borrowed_account_t * lut_acct = NULL;
  fd_instr_borrowed_account_view_idx( ctx, ACC_IDX_LUT, &lut_acct );  /* check error? */
  FD_TEST( lut_acct );

  /* try_borrow_instruction_account => RefCell::try_borrow_mut (see above note)
     (See https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L71) */
  if( FD_UNLIKELY( !fd_borrowed_account_acquire_write_is_safe( lut_acct ) ) )
    return FD_EXECUTOR_INSTR_ERR_ACC_BORROW_FAILED;

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L60-L62 */
  ulong               lut_lamports = lut_acct->const_meta->info.lamports;
  fd_pubkey_t const * lut_key      = lut_acct->pubkey;
  uchar const *       lut_owner    = lut_acct->const_meta->info.owner;

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L63-L70 */
  if( !FD_FEATURE_ACTIVE( ctx->slot_ctx, relax_authority_signer_check_for_lookup_table_creation )
      && lut_acct->const_meta->dlen != 0UL ) {
    /* TODO Log: "Table account must not be allocated" */
    return FD_EXECUTOR_INSTR_ERR_ACC_ALREADY_INITIALIZED;
  }

  /* Prepare authority account ****************************************/
  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L73-L74 */

  /* try_borrow_instruction_account => get_index_of_instruction_account_in_transaction */
  if( FD_UNLIKELY( ctx->instr->acct_cnt < ACC_IDX_AUTHORITY+1UL ) )
    return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
  fd_borrowed_account_t * authority_acct = NULL;
  fd_instr_borrowed_account_view_idx( ctx, ACC_IDX_AUTHORITY, &authority_acct );  /* check error? */
  FD_TEST( lut_acct );

  /* try_borrow_instruction_account => RefCell::try_borrow_mut (see above note)
     (See https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L84) */
  if( FD_UNLIKELY( !fd_borrowed_account_acquire_write_is_safe( authority_acct ) ) )
    return FD_EXECUTOR_INSTR_ERR_ACC_BORROW_FAILED;

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L75 */
  fd_pubkey_t const * authority_key = authority_acct->pubkey;

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L76-L83 */
  if( !FD_FEATURE_ACTIVE( ctx->slot_ctx, relax_authority_signer_check_for_lookup_table_creation )
      && !fd_instr_acc_is_signer_idx( ctx->instr, ACC_IDX_AUTHORITY ) ) {
    /* TODO Log: "Authority account must be a signer" */
    return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
  }

  /* Prepare payer account ********************************************/
  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L86-L87 */

  /* try_borrow_account => get_index_of_instruction_account_in_transaction */
  if( FD_UNLIKELY( ctx->instr->acct_cnt < ACC_IDX_PAYER+1UL ) )
    return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
  fd_borrowed_account_t * payer_acct = NULL;
  fd_instr_borrowed_account_view_idx( ctx, ACC_IDX_PAYER, &payer_acct );  /* check error? */
  FD_TEST( lut_acct );
  fd_pubkey_t const * payer_key = payer_acct->pubkey;

  /* try_borrow_account => RefCell::try_borrow_mut (see above note)
     (See https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L93) */
  if( FD_UNLIKELY( !fd_borrowed_account_acquire_write_is_safe( payer_acct ) ) )
    return FD_EXECUTOR_INSTR_ERR_ACC_BORROW_FAILED;

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L89-L92 */
  if( !fd_instr_acc_is_signer_idx( ctx->instr, ACC_IDX_PAYER ) ) {
    /* TODO Log: "Payer account must be a signer" */
    return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
  }

  ulong derivation_slot = 1UL;

  do {
    fd_slot_hashes_t slot_hashes[1];
    if( FD_UNLIKELY( !fd_sysvar_slot_hashes_read( slot_hashes, ctx->slot_ctx ) ) )
      return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR;

    /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L97 */
    int is_recent_slot = 0;
    /* TODO loop is naive */
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
  do {
    fd_sha256_t sha[1]; fd_sha256_init( sha );
    fd_sha256_append( sha, authority_key->key, 32UL );
    fd_sha256_append( sha, &derivation_slot,    8UL );
    fd_sha256_append( sha, &create->bump_seed,  1UL );
    fd_sha256_append( sha, fd_solana_address_lookup_table_program_id.key, 32UL );
    fd_sha256_append( sha, "ProgramDerivedAddress", 21UL );
    fd_sha256_fini( sha, derived_tbl_key->key );
  } while(0);
  if( FD_UNLIKELY( fd_ed25519_point_validate( derived_tbl_key->key ) ) ) {
    return FD_EXECUTOR_INSTR_ERR_INVALID_SEEDS;
  }

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L120-L127 */
  if( FD_UNLIKELY( 0!=memcmp( lut_key->key, derived_tbl_key->key, 32UL ) ) ) {
    /* TODO Log: "Table address must match derived address: {}" */
    return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
  }

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L129-L135 */
  if( FD_FEATURE_ACTIVE( ctx->slot_ctx, relax_authority_signer_check_for_lookup_table_creation )
      && 0==memcmp( lut_owner, fd_solana_address_lookup_table_program_id.key, 32UL ) ) {
    return FD_EXECUTOR_INSTR_SUCCESS;
  }

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L137-L142 */
  ulong tbl_acct_data_len = 0x38UL;
  ulong required_lamports = fd_rent_exempt_minimum_balance( ctx->slot_ctx, tbl_acct_data_len );
        required_lamports = fd_ulong_max( required_lamports, 1UL );
        required_lamports = fd_ulong_sat_sub( required_lamports, lut_lamports );

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L144-L149 */
  if( required_lamports > 0UL ) {
    // Create account metas
    fd_vm_rust_account_meta_t * acct_metas = (fd_vm_rust_account_meta_t*) fd_valloc_malloc(ctx->valloc, FD_VM_RUST_ACCOUNT_META_ALIGN, 2 * sizeof(fd_vm_rust_account_meta_t));
    create_account_meta(payer_key, 1, 1, &acct_metas[0]);
    create_account_meta(lut_key, 0, 1, &acct_metas[1]);

    // Create signers list
    fd_pubkey_t signers[16];
    ulong signers_cnt = 1;
    signers[0] = *payer_key;

    // Create system program instruction
    fd_system_program_instruction_t instr;
    instr.discriminant = fd_system_program_instruction_enum_transfer;
    instr.inner.transfer = required_lamports;

    int err = execute_system_program_instruction(
      ctx,
      &instr,
      acct_metas,
      2,
      signers,
      signers_cnt
    );
    fd_valloc_free(ctx->valloc, acct_metas);
    if ( err != 0 ) {
      return FD_EXECUTOR_INSTR_ERR_GENERIC_ERR;
    }
  }

  fd_vm_rust_account_meta_t * acct_metas = (fd_vm_rust_account_meta_t*) fd_valloc_malloc(ctx->valloc, FD_VM_RUST_ACCOUNT_META_ALIGN, sizeof(fd_vm_rust_account_meta_t));
  create_account_meta(lut_key, 1, 1, &acct_metas[0]);

  // Create signers list
  fd_pubkey_t signers[16];
  ulong signers_cnt = 1;
  signers[0] = *lut_key;

  // Create system program instruction
  fd_system_program_instruction_t instr;
  instr.discriminant = fd_system_program_instruction_enum_allocate;
  instr.inner.allocate = 56;

  // Execute allocate instruction
  int err = execute_system_program_instruction(
    ctx,
    &instr,
    acct_metas,
    1,
    signers,
    signers_cnt
  );
  if ( err != 0 ) {
    return FD_EXECUTOR_INSTR_ERR_GENERIC_ERR;
  }

  instr.discriminant = fd_system_program_instruction_enum_assign;
  instr.inner.assign = fd_solana_address_lookup_table_program_id;

  // Execute assign instruction
  err = execute_system_program_instruction(
    ctx,
    &instr,
    acct_metas,
    1,
    signers,
    signers_cnt
  );
  if ( err != 0 ) {
    return FD_EXECUTOR_INSTR_ERR_GENERIC_ERR;
  }

  fd_valloc_free(ctx->valloc, acct_metas);

  if( FD_UNLIKELY( !fd_borrowed_account_acquire_write( lut_acct ) ) )
    return FD_EXECUTOR_INSTR_ERR_ACC_BORROW_FAILED;
  fd_address_lookup_table_state_t state[1];
  fd_address_lookup_table_state_new( state );
  state->discriminant = fd_address_lookup_table_state_enum_lookup_table;
  fd_address_lookup_table_new( &state->inner.lookup_table );
  fd_memcpy( state->inner.lookup_table.meta.authority.key, authority_key->key, 32UL );
  state->inner.lookup_table.meta.has_authority = 1;
  state->inner.lookup_table.meta.deactivation_slot = ULONG_MAX;

  fd_instr_borrowed_account_modify_idx( ctx, ACC_IDX_LUT, 0, &lut_acct );
  FD_TEST( lut_acct->meta );

  int state_err = fd_addrlut_serialize_meta( state, lut_acct->data, sizeof(fd_address_lookup_table_state_t) );
  if( FD_UNLIKELY( state_err ) ) { return state_err; }
  /* Implicit drop */
  fd_borrowed_account_release_write( lut_acct );
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
  if( FD_UNLIKELY( ctx->instr->acct_cnt < ACC_IDX_LUT+1UL ) )
    return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
  fd_borrowed_account_t * lut_acct = NULL;
  fd_instr_borrowed_account_view_idx( ctx, ACC_IDX_LUT, &lut_acct );  /* check error? */
  FD_TEST( lut_acct );

  /* try_borrow_account => RefCell::try_borrow_mut (see above note)
     (See https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L181) */
  if( FD_UNLIKELY( !fd_borrowed_account_acquire_write_is_safe( lut_acct ) ) )
    return FD_EXECUTOR_INSTR_ERR_ACC_BORROW_FAILED;

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L178-L181 */
  if( FD_UNLIKELY( 0!=memcmp( lut_acct->const_meta->info.owner, fd_solana_address_lookup_table_program_id.key, sizeof(fd_pubkey_t) ) ) ) {
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_OWNER;
  }

  /* Prepare authority account ****************************************/
  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L183-L184 */

  /* try_borrow_account => get_index_of_instruction_account_in_transaction */
  if( FD_UNLIKELY( ctx->instr->acct_cnt < ACC_IDX_AUTHORITY+1UL ) )
    return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
  fd_borrowed_account_t * authority_acct = NULL;
  fd_instr_borrowed_account_view_idx( ctx, ACC_IDX_AUTHORITY, &authority_acct );  /* check error? */
  FD_TEST( authority_acct );

  /* try_borrow_instruction_account => RefCell::try_borrow_mut (see above note)
     (See https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L190) */
  if( FD_UNLIKELY( !fd_borrowed_account_acquire_write_is_safe( authority_acct ) ) )
    return FD_EXECUTOR_INSTR_ERR_ACC_BORROW_FAILED;

  fd_pubkey_t const * authority_key = authority_acct->pubkey;

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L186-L189 */
  if( FD_UNLIKELY( !fd_instr_acc_is_signer_idx( ctx->instr, ACC_IDX_AUTHORITY ) ) ) {
    /* TODO Log: "Authority account must be a signer" */
    return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
  }

  /* Update lookup table account **************************************/

  int lock_ok = fd_borrowed_account_acquire_write( lut_acct );
                /* must be paired with release */
  FD_TEST( !!lock_ok );  /* Lock would always succeed at this point */

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L194 */
  uchar const * lut_data    = lut_acct->const_data;
  ulong         lut_data_sz = lut_acct->const_meta->dlen;

  int err = FD_EXECUTOR_INSTR_SUCCESS;
  do {  /* with locked account */
    /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L195 */
    fd_addrlut_t lut[1];
    int state_err = fd_addrlut_deserialize( lut, lut_data, lut_data_sz );
    if( FD_UNLIKELY( state_err ) ) { err = state_err; break; }

    fd_address_lookup_table_t * state = &lut->state.inner.lookup_table;

    /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L197-L200 */
    if( FD_UNLIKELY( !state->meta.has_authority ) ) {
      /* TODO Log: "Lookup table is already frozen" */
      err = FD_EXECUTOR_INSTR_ERR_ACC_IMMUTABLE; break;
    }

    /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L201-L203 */
    if( FD_UNLIKELY( 0!=memcmp( state->meta.authority.key, authority_key->key, sizeof(fd_pubkey_t) ) ) ) {
      /* TODO Log: "Incorrect Authority" */
      err = FD_EXECUTOR_INSTR_ERR_INCORRECT_AUTHORITY; break;
    }

    /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L204-L207 */
    if( FD_UNLIKELY( state->meta.deactivation_slot != ULONG_MAX ) ) {
      /* TODO Log: "Deactivated tables cannot be frozen" */
      err = FD_EXECUTOR_INSTR_ERR_INVALID_ARG; break;
    }

    /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L208-L211 */
    if( FD_UNLIKELY( !lut->addr_cnt ) ) {
      /* TODO Log: "Empty lookup tables cannot be frozen" */
      err = FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA; break;
    }

    /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L216 */
    int modify_err = fd_instr_borrowed_account_modify_idx( ctx, ACC_IDX_LUT, /* min_data_sz */ 0UL, &lut_acct );
    if( FD_UNLIKELY( modify_err!=FD_ACC_MGR_SUCCESS ) ) {
      err = FD_EXECUTOR_INSTR_ERR_FATAL; break;
    }

    /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L213-L218 */
    state->meta.has_authority = 0;
    state_err = fd_addrlut_serialize_meta( &lut->state, lut_acct->data, lut_acct->meta->dlen );
    if( FD_UNLIKELY( state_err ) ) { err = state_err; break; }

    err = FD_EXECUTOR_INSTR_SUCCESS;
  } while(0);
  fd_borrowed_account_release_write( lut_acct );

  return err;

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

  /* try_borrow_account => get_index_of_instruction_account_in_transaction */
  if( FD_UNLIKELY( ctx->instr->acct_cnt < ACC_IDX_LUT+1UL ) )
    return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
  fd_borrowed_account_t * lut_acct = NULL;
  fd_instr_borrowed_account_view_idx( ctx, ACC_IDX_LUT, &lut_acct );  /* check error? */
  FD_TEST( lut_acct );

  /* try_borrow_account => RefCell::try_borrow_mut (see above note)
     (See https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L236) */
  if( FD_UNLIKELY( !fd_borrowed_account_acquire_write_is_safe( lut_acct ) ) )
    return FD_EXECUTOR_INSTR_ERR_ACC_BORROW_FAILED;

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L233-235 */
  if( FD_UNLIKELY( 0!=memcmp( lut_acct->const_meta->info.owner, fd_solana_address_lookup_table_program_id.key, sizeof(fd_pubkey_t) ) ) )
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_OWNER;

  /* Prepare authority account ****************************************/
  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L238-L245 */

  /* try_borrow_account => get_index_of_instruction_account_in_transaction */
  if( FD_UNLIKELY( ctx->instr->acct_cnt < ACC_IDX_AUTHORITY+1UL ) )
    return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
  fd_borrowed_account_t * authority_acct = NULL;
  fd_instr_borrowed_account_view_idx( ctx, ACC_IDX_AUTHORITY, &authority_acct );  /* check error? */
  FD_TEST( authority_acct );

  /* try_borrow_instruction_account => RefCell::try_borrow_mut (see above note)
     (See https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L245) */
  if( FD_UNLIKELY( !fd_borrowed_account_acquire_write_is_safe( authority_acct ) ) )
    return FD_EXECUTOR_INSTR_ERR_ACC_BORROW_FAILED;

  fd_pubkey_t const * authority_key = authority_acct->pubkey;

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L241-L244 */
  if( FD_UNLIKELY( !fd_instr_acc_is_signer_idx( ctx->instr, ACC_IDX_AUTHORITY ) ) ) {
    /* TODO Log: "Authority account must be a signer" */
    return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
  }

  /* Update lookup table account **************************************/

  int lock_ok = fd_borrowed_account_acquire_write( lut_acct );
                /* must be paired with release */
  FD_TEST( !!lock_ok );  /* Lock would always succeed at this point */

  uchar const * lut_data     = lut_acct->const_data;
  ulong         lut_data_sz  = lut_acct->const_meta->dlen;
  ulong         lut_lamports = lut_acct->const_meta->info.lamports;

  int   err               = FD_EXECUTOR_INSTR_SUCCESS;
  ulong new_table_data_sz = 0UL;
  do {  /* with locked account */
    /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L251 */
    fd_addrlut_t lut[1];
    int state_err = fd_addrlut_deserialize( lut, (uchar *)lut_data, lut_data_sz );
    if( FD_UNLIKELY( state_err ) ) { err = state_err; break; }

    fd_address_lookup_table_t * state = &lut->state.inner.lookup_table;

    /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L253-L255 */
    if( FD_UNLIKELY( !state->meta.has_authority ) ) {
      err = FD_EXECUTOR_INSTR_ERR_ACC_IMMUTABLE;
      break;
    }

    /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L256-L258 */
    if( FD_UNLIKELY( 0!=memcmp( state->meta.authority.key, authority_key->key, sizeof(fd_pubkey_t) ) ) ) {
      err = FD_EXECUTOR_INSTR_ERR_INCORRECT_AUTHORITY; break;
    }

    /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L259-L262 */
    if( FD_UNLIKELY( state->meta.deactivation_slot != ULONG_MAX ) ) {
      /* TODO Log: "Deactivated tables cannot be extended" */
      err = FD_EXECUTOR_INSTR_ERR_INVALID_ARG; break;
    }

    /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L263-L269 */
    if( FD_UNLIKELY( lut->addr_cnt >= FD_ADDRLUT_MAX_ADDR_CNT ) ) {
      /* TODO Log: "Lookup table is full and cannot contain more addresses" */
      err = FD_EXECUTOR_INSTR_ERR_INVALID_ARG; break;
    }

    /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L271-L274 */
    if( FD_UNLIKELY( !extend->new_addrs_len ) ) {
      /* TODO Log: "Must extend with at least one address" */
      err = FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA; break;
    }

    /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L276-L279 */
    ulong old_addr_cnt = lut->addr_cnt;
    ulong new_addr_cnt = lut->addr_cnt + extend->new_addrs_len;
    if( FD_UNLIKELY( new_addr_cnt > FD_ADDRLUT_MAX_ADDR_CNT ) ) {
      /* TODO Log: "Extended lookup table length {} would exceed max capacity of {}" */
      err = FD_EXECUTOR_INSTR_ERR_INVALID_INSTR_DATA; break;
    }

    /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L290 */
    fd_sol_sysvar_clock_t clock[1];
    if( FD_UNLIKELY( !fd_sysvar_clock_read( clock, ctx->slot_ctx ) ) )
      return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR;

    /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L291-L299 */
    if( clock->slot != state->meta.last_extended_slot ) {
      state->meta.last_extended_slot             = clock->slot;
      state->meta.last_extended_slot_start_index = (uchar)lut->addr_cnt;
    }

    /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L308 */
    new_table_data_sz = FD_ADDRLUT_META_SZ + new_addr_cnt * sizeof(fd_pubkey_t);
    int modify_err = fd_instr_borrowed_account_modify( ctx, lut_acct->pubkey, new_table_data_sz, &lut_acct );
    if( FD_UNLIKELY( modify_err ) ) {
      err = FD_EXECUTOR_INSTR_ERR_FATAL; break;
    }

    /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L307-L310 */
    state_err = fd_addrlut_serialize_meta( &lut->state, lut_acct->data, lut_acct->meta->dlen );
    if( FD_UNLIKELY( state_err ) ) { err = state_err; break; }

    /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L311-L313 */
    do {
      uchar * new_keys = lut_acct->data + FD_ADDRLUT_META_SZ + old_addr_cnt * sizeof(fd_pubkey_t);
      fd_memcpy( new_keys, extend->new_addrs, extend->new_addrs_len * sizeof(fd_pubkey_t) );
    } while(0);
    lut_acct->meta->dlen = new_table_data_sz;
    lut->addr     = (fd_pubkey_t *)(lut_acct->data + FD_ADDRLUT_META_SZ);
    lut->addr_cnt = new_addr_cnt;

    err = FD_EXECUTOR_INSTR_SUCCESS;
  } while(0);
  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L315 */
  fd_borrowed_account_release_write( lut_acct );

  if( FD_UNLIKELY( err!=FD_EXECUTOR_INSTR_SUCCESS ) )
    return err;

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L317-L321 */
  ulong required_lamports =
    fd_rent_exempt_minimum_balance( ctx->slot_ctx, new_table_data_sz );
  required_lamports = fd_ulong_max    ( required_lamports, 1UL );
  required_lamports = fd_ulong_sat_sub( required_lamports, lut_lamports );

  if( required_lamports ) {
    /* try_borrow_account => get_index_of_instruction_account_in_transaction */
    if( FD_UNLIKELY( ctx->instr->acct_cnt < ACC_IDX_PAYER+1UL ) )
      return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
    fd_borrowed_account_t * payer_acct = NULL;
    fd_instr_borrowed_account_view_idx( ctx, ACC_IDX_PAYER, &payer_acct );  /* check error? */
    FD_TEST( payer_acct );

    /* try_borrow_instruction_account => RefCell::try_borrow_mut (see above note)
      (See https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L331) */
    if( FD_UNLIKELY( !fd_borrowed_account_acquire_write_is_safe( payer_acct ) ) )
      return FD_EXECUTOR_INSTR_ERR_ACC_BORROW_FAILED;

    fd_pubkey_t const * payer_key = payer_acct->pubkey;
    fd_pubkey_t const * lut_key   = lut_acct->pubkey;
    /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L327-L330 */
    if( FD_UNLIKELY( !fd_instr_acc_is_signer_idx( ctx->instr, ACC_IDX_PAYER ) ) ) {
      /* TODO Log: "Payer account must be a signer" */
      return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
    }

    // Create account metas
    fd_vm_rust_account_meta_t * acct_metas = (fd_vm_rust_account_meta_t*) fd_valloc_malloc(ctx->valloc, FD_VM_RUST_ACCOUNT_META_ALIGN, 2 * sizeof(fd_vm_rust_account_meta_t));
    create_account_meta(payer_key, 1, 1, &acct_metas[0]);
    create_account_meta(lut_key, 0, 1, &acct_metas[1]);

    // Create signers list
    fd_pubkey_t signers[16];
    ulong signers_cnt = 1;
    signers[0] = *payer_key;

    // Create system program instruction
    fd_system_program_instruction_t instr;
    instr.discriminant = fd_system_program_instruction_enum_transfer;
    instr.inner.transfer = required_lamports;

    int err = execute_system_program_instruction(
      ctx,
      &instr,
      acct_metas,
      2,
      signers,
      signers_cnt
    );
    fd_valloc_free(ctx->valloc, acct_metas);
    if ( err != 0 ) {
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

  /* Prepare LUT account **********************************************/
  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L346-L351 */

  /* try_borrow_instruction_account => get_index_of_instruction_account_in_transaction */
  if( FD_UNLIKELY( ctx->instr->acct_cnt < ACC_IDX_LUT+1UL ) )
    return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
  fd_borrowed_account_t * lut_acct = NULL;
  fd_instr_borrowed_account_view_idx( ctx, ACC_IDX_LUT, &lut_acct );  /* check error? */
  FD_TEST( lut_acct );

  /* try_borrow_instruction_account => RefCell::try_borrow_mut (see above note)
     (See https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L346-L347) */
  if( FD_UNLIKELY( !fd_borrowed_account_acquire_write_is_safe( lut_acct ) ) )
    return FD_EXECUTOR_INSTR_ERR_ACC_BORROW_FAILED;

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L348-L350 */
  if( FD_UNLIKELY( 0!=memcmp( lut_acct->const_meta->info.owner, fd_solana_address_lookup_table_program_id.key, sizeof(fd_pubkey_t) ) ) )
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_OWNER;

  /* Prepare authority account ****************************************/
  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L353-L360 */

  /* try_borrow_account => get_index_of_instruction_account_in_transaction */
  if( FD_UNLIKELY( ctx->instr->acct_cnt < ACC_IDX_AUTHORITY+1UL ) )
    return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
  fd_borrowed_account_t * authority_acct = NULL;
  fd_instr_borrowed_account_view_idx( ctx, ACC_IDX_AUTHORITY, &authority_acct );  /* check error? */
  FD_TEST( authority_acct );

  /* try_borrow_instruction_account => RefCell::try_borrow_mut (see above note)
     (See https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L353-L354) */
  if( FD_UNLIKELY( !fd_borrowed_account_acquire_write_is_safe( authority_acct ) ) )
    return FD_EXECUTOR_INSTR_ERR_ACC_BORROW_FAILED;

  fd_pubkey_t const * authority_key = authority_acct->pubkey;

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L356-L359 */
  if( FD_UNLIKELY( !fd_instr_acc_is_signer_idx( ctx->instr, ACC_IDX_AUTHORITY ) ) ) {
    /* TODO Log: "Authority account must be a signer" */
    return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
  }

  /* Update lookup table account **************************************/

  int lock_ok = fd_borrowed_account_acquire_write( lut_acct );
                /* must be paired with release */
  FD_TEST( !!lock_ok );  /* Lock would always succeed at this point */

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L364 */
  uchar const * lut_data    = lut_acct->const_data;
  ulong         lut_data_sz = lut_acct->const_meta->dlen;

  int err = FD_EXECUTOR_INSTR_SUCCESS;
  do {  /* with locked account */
    /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L365 */
    fd_addrlut_t lut[1];
    int state_err = fd_addrlut_deserialize( lut, (uchar *)lut_data, lut_data_sz );
    if( FD_UNLIKELY( state_err ) ) { err = state_err; break; }

    fd_address_lookup_table_t * state = &lut->state.inner.lookup_table;

    /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L367-L370 */
    if( FD_UNLIKELY( !state->meta.has_authority ) ) {
      /* TODO Log: "Lookup table is already frozen" */
      err = FD_EXECUTOR_INSTR_ERR_ACC_IMMUTABLE; break;
    }

    /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L371-L373 */
    if( FD_UNLIKELY( 0!=memcmp( state->meta.authority.key, authority_key->key, sizeof(fd_pubkey_t) ) ) ) {
      err = FD_EXECUTOR_INSTR_ERR_INCORRECT_AUTHORITY; break;
    }

    /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L374-L377 */
    if( FD_UNLIKELY( state->meta.deactivation_slot != ULONG_MAX ) ) {
      /* TODO Log: "Lookup table is already deactivated" */
      err = FD_EXECUTOR_INSTR_ERR_INVALID_ARG; break;
    }

    /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L380 */
    fd_sol_sysvar_clock_t clock[1];
      if( FD_UNLIKELY( !fd_sysvar_clock_read( clock, ctx->slot_ctx ) ) )
        return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR;

    /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L384 */
    int modify_err = fd_instr_borrowed_account_modify_idx( ctx, ACC_IDX_LUT, /* min_data_sz */ 0UL, &lut_acct );
    if( FD_UNLIKELY( modify_err!=FD_ACC_MGR_SUCCESS ) ) {
      err = FD_EXECUTOR_INSTR_ERR_FATAL; break;
    }

    /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L381 */
    state->meta.deactivation_slot = clock->slot;

    /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L383-L386 */
    state_err = fd_addrlut_serialize_meta( &lut->state, lut_acct->data, lut_acct->meta->dlen );
    if( FD_UNLIKELY( state_err ) ) { err = state_err; break; }

    err = FD_EXECUTOR_INSTR_SUCCESS;
  } while(0);
  fd_borrowed_account_release_write( lut_acct );

  return err;

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
  if( FD_UNLIKELY( ctx->instr->acct_cnt < ACC_IDX_LUT+1UL ) )
    return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
  fd_borrowed_account_t * lut_acct = NULL;
  fd_instr_borrowed_account_view_idx( ctx, ACC_IDX_LUT, &lut_acct );  /* check error? */
  FD_TEST( lut_acct );

  /* try_borrow_instruction_account => RefCell::try_borrow_mut (see above note)
     (See https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L400) */
  if( FD_UNLIKELY( !fd_borrowed_account_acquire_write_is_safe( lut_acct ) ) )
    return FD_EXECUTOR_INSTR_ERR_ACC_BORROW_FAILED;

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L397-L399 */
  if( FD_UNLIKELY( 0!=memcmp( lut_acct->const_meta->info.owner, fd_solana_address_lookup_table_program_id.key, sizeof(fd_pubkey_t) ) ) )
    return FD_EXECUTOR_INSTR_ERR_INVALID_ACC_OWNER;

  /* Prepare authority account ****************************************/
  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L402-L409 */

  /* try_borrow_account => get_index_of_instruction_account_in_transaction */
  if( FD_UNLIKELY( ctx->instr->acct_cnt < ACC_IDX_AUTHORITY+1UL ) )
    return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
  fd_borrowed_account_t * authority_acct = NULL;
  fd_instr_borrowed_account_view_idx( ctx, ACC_IDX_AUTHORITY, &authority_acct );  /* check error? */
  FD_TEST( authority_acct );

  /* try_borrow_instruction_account => RefCell::try_borrow_mut (see above note)
     (See https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L409) */
  if( FD_UNLIKELY( !fd_borrowed_account_acquire_write_is_safe( authority_acct ) ) )
    return FD_EXECUTOR_INSTR_ERR_ACC_BORROW_FAILED;

  fd_pubkey_t const * authority_key = authority_acct->pubkey;

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L405-L408 */
  if( FD_UNLIKELY( !fd_instr_acc_is_signer_idx( ctx->instr, ACC_IDX_AUTHORITY ) ) ) {
    /* TODO Log: "Authority account must be a signer" */
    return FD_EXECUTOR_INSTR_ERR_MISSING_REQUIRED_SIGNATURE;
  }

  /* Update lookup table account **************************************/

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L411 */
  if( FD_UNLIKELY( ctx->instr->acct_cnt < 3 ) ) {
    return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
  }

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L412-L420 */
  /* TODO is this pointer comparison safe? */
  if( FD_UNLIKELY( ctx->instr->borrowed_accounts[0]
                == ctx->instr->borrowed_accounts[2] ) ) {
    /* TODO Log: "Lookup table cannot be recipient of reclaimed lamports" */
    return FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
  }

  int lock_ok = fd_borrowed_account_acquire_write( lut_acct );
                /* must be paired with release */
  FD_TEST( !!lock_ok );  /* Lock would always succeed at this point */

  ulong         withdrawn_lamports = lut_acct->const_meta->info.lamports;
  uchar const * lut_data           = lut_acct->const_data;
  ulong         lut_data_sz        = lut_acct->const_meta->dlen;

  int err = FD_EXECUTOR_INSTR_SUCCESS;
  do {
    /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L426 */
    fd_addrlut_t lut[1];
    int state_err = fd_addrlut_deserialize( lut, (uchar *)lut_data, lut_data_sz );
    if( FD_UNLIKELY( state_err ) ) { err = state_err; break; }

    fd_address_lookup_table_t * state = &lut->state.inner.lookup_table;

    /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L428-L431 */
    if( FD_UNLIKELY( !state->meta.has_authority ) ) {
      /* TODO Log: "Lookup table is frozen" */
      err = FD_EXECUTOR_INSTR_ERR_ACC_IMMUTABLE; break;
    }

    /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L432-L434 */
    if( FD_UNLIKELY( 0!=memcmp( state->meta.authority.key, authority_key->key, sizeof(fd_pubkey_t) ) ) ) {
      err = FD_EXECUTOR_INSTR_ERR_INCORRECT_AUTHORITY; break;
    }

    /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L437 */
    fd_sol_sysvar_clock_t clock[1];
    if( FD_UNLIKELY( !fd_sysvar_clock_read( clock, ctx->slot_ctx ) ) )
      return FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR;

    int status;
    do {
      /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L438
         TODO THIS SHOULD BE A SCRATCH ALLOC */
      fd_slot_hashes_t slot_hashes[1];
      if( FD_UNLIKELY( !fd_sysvar_slot_hashes_read( slot_hashes, ctx->slot_ctx ) ) )
        { err = FD_EXECUTOR_INSTR_ERR_UNSUPPORTED_SYSVAR; break; }

      /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L440 */
      ulong remaining_blocks = 0UL;
      status = fd_addrlut_status( &state->meta, clock->slot, slot_hashes, &remaining_blocks );

      fd_bincode_destroy_ctx_t destroy = { .valloc = ctx->slot_ctx->valloc };
      fd_slot_hashes_destroy( slot_hashes, &destroy );
    } while(0);
    if( FD_UNLIKELY( err!=FD_EXECUTOR_INSTR_SUCCESS ) ) break;

    switch( status ) {
    case FD_ADDRLUT_STATUS_ACTIVATED:
      /* TODO Log: "Lookup table is not deactivated" */
      err = FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
      break;
    case FD_ADDRLUT_STATUS_DEACTIVATING:
      /* TODO Log: Table cannot be closed until it's fully deactivated in {} blocks" */
      err = FD_EXECUTOR_INSTR_ERR_INVALID_ARG;
      break;
    case FD_ADDRLUT_STATUS_DEACTIVATED:
      err = FD_EXECUTOR_INSTR_SUCCESS;
      break;
    default:
      __builtin_unreachable();
    }
  } while(0);
  fd_borrowed_account_release_write( lut_acct );
  if( FD_UNLIKELY( err!=FD_EXECUTOR_INSTR_SUCCESS ) ) return err;

  /* Add lamports to recipient ****************************************/

  /* try_borrow_instruction_account => get_index_of_instruction_account_in_transaction */
  if( FD_UNLIKELY( ctx->instr->acct_cnt < ACC_IDX_RECIPIENT+1UL ) )
    return FD_EXECUTOR_INSTR_ERR_NOT_ENOUGH_ACC_KEYS;
  fd_borrowed_account_t * recipient_acct = NULL;
  fd_instr_borrowed_account_view_idx( ctx, ACC_IDX_RECIPIENT, &recipient_acct );  /* check error? */
  FD_TEST( recipient_acct );

  /* try_borrow_instruction_account => RefCell::try_borrow_mut (see above note)
     (See https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L457-L458) */
  if( FD_UNLIKELY( !fd_borrowed_account_acquire_write_is_safe( recipient_acct ) ) )
    return FD_EXECUTOR_INSTR_ERR_ACC_BORROW_FAILED;

  /* https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L459 */
  int modify_err = fd_instr_borrowed_account_modify_idx( ctx, ACC_IDX_RECIPIENT, /* min_data_sz */ 0UL, &recipient_acct );
  if( FD_UNLIKELY( modify_err!=FD_ACC_MGR_SUCCESS ) ) {
    return FD_EXECUTOR_INSTR_ERR_FATAL;
  }
  /* TODO handle is_early_verification_of_account_modifications_enabled */
  int op_err = fd_borrowed_account_checked_add_lamports( recipient_acct, withdrawn_lamports );
  if( FD_UNLIKELY( op_err ) ) return op_err;

  /* Delete LUT account ***********************************************/

  /* try_borrow_instruction_account => RefCell::try_borrow_mut (see above note)
     (See https://github.com/solana-labs/solana/blob/v1.17.4/programs/address-lookup-table/src/processor.rs#L462-L465) */
  if( FD_UNLIKELY( !fd_borrowed_account_acquire_write_is_safe( lut_acct ) ) )
    return FD_EXECUTOR_INSTR_ERR_ACC_BORROW_FAILED;  /* Should be impossible */
  /* todo is_early_verification_of_account_modifications_enabled */
  modify_err = fd_instr_borrowed_account_modify_idx( ctx, ACC_IDX_LUT, /* min_data_sz */ 0UL, &lut_acct );
  if( FD_UNLIKELY( modify_err!=FD_ACC_MGR_SUCCESS ) ) {
    return FD_EXECUTOR_INSTR_ERR_FATAL;
  }
  lut_acct->meta->dlen          = 0UL;
  lut_acct->meta->info.lamports = 0UL;
  return FD_EXECUTOR_INSTR_SUCCESS;

# undef ACC_IDX_LUT
# undef ACC_IDX_AUTHORITY
# undef ACC_IDX_RECIPIENT
}

int
fd_address_lookup_table_program_execute( fd_exec_instr_ctx_t _ctx ) {

  fd_exec_instr_ctx_t * ctx = &_ctx;
  uchar const * instr_data    = ctx->instr->data;
  ulong         instr_data_sz = ctx->instr->data_sz;

  ctx->txn_ctx->compute_meter = fd_ulong_sat_sub( ctx->txn_ctx->compute_meter, DEFAULT_COMPUTE_UNITS );

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
