#include "context/fd_exec_slot_ctx.h"
#include "sysvar/fd_sysvar_rent.h"
#include "program/fd_bpf_loader_program.h"
#include "program/fd_builtin_programs.h"
#include "fd_pubkey_utils.h"

/* Mimics bank.new_target_program_account(). Assumes out_rec is a
   modifiable record.

   From the calling context, out_rec points to a native program record
   (e.g. Config, ALUT native programs). There should be enough space in
   out_rec->data to hold at least 36 bytes (the size of a BPF
   upgradeable program account) when calling this function. The native
   program account's owner is set to the BPF loader upgradeable program
   ID, and lamports are increased / deducted to contain the rent exempt
   minimum balance.

   https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L79-L95 */
static int
fd_new_target_program_account( fd_exec_slot_ctx_t * slot_ctx,
                               fd_pubkey_t const *  target_program_data_address,
                               fd_txn_account_t *   out_rec ) {
  /* https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L86-L88 */
  fd_bpf_upgradeable_loader_state_t state = {
    .discriminant = fd_bpf_upgradeable_loader_state_enum_program,
    .inner = {
      .program = {
        .programdata_address = *target_program_data_address,
      }
    }
  };

  /* https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L89-L90 */
  fd_rent_t const * rent = fd_bank_rent_query( slot_ctx->bank );
  if( FD_UNLIKELY( rent==NULL ) ) {
    return -1;
  }

  fd_txn_account_set_lamports( out_rec, fd_rent_exempt_minimum_balance( rent, SIZE_OF_PROGRAM ) );
  fd_bincode_encode_ctx_t ctx = {
    .data    = fd_txn_account_get_data_mut( out_rec ),
    .dataend = fd_txn_account_get_data_mut( out_rec ) + SIZE_OF_PROGRAM,
  };

  /* https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L91-L9 */
  int err = fd_bpf_upgradeable_loader_state_encode( &state, &ctx );
  if( FD_UNLIKELY( err ) ) {
    return err;
  }
  fd_txn_account_set_owner( out_rec, &fd_solana_bpf_loader_upgradeable_program_id );

  /* https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L93-L94 */
  fd_txn_account_set_executable( out_rec, 1 );
  return FD_RUNTIME_EXECUTE_SUCCESS;
}

/* Mimics bank.new_target_program_data_account(). Assumes
   new_target_program_data_account is a modifiable record.
   config_upgrade_authority_address may be NULL.

   This function uses an existing buffer account buffer_acc_rec to set
   the program data account data for a core program BPF migration. Sets
   the lamports and data fields of new_target_program_data_account
   based on the ELF data length, and sets the owner to the BPF loader
   upgradeable program ID.

   https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L97-L153 */
static int
fd_new_target_program_data_account( fd_exec_slot_ctx_t * slot_ctx,
                                    fd_pubkey_t *        config_upgrade_authority_address,
                                    fd_txn_account_t *   buffer_acc_rec,
                                    fd_txn_account_t *   new_target_program_data_account,
                                    fd_spad_t *          runtime_spad ) {

  FD_SPAD_FRAME_BEGIN( runtime_spad ) {

  /* https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L113-L116 */
  int err;
  fd_bpf_upgradeable_loader_state_t * state = fd_bincode_decode_spad(
      bpf_upgradeable_loader_state, runtime_spad,
      fd_txn_account_get_data( buffer_acc_rec ),
      fd_txn_account_get_data_len( buffer_acc_rec ),
      &err );
  if( FD_UNLIKELY( err ) ) return err;

  if( FD_UNLIKELY( !fd_bpf_upgradeable_loader_state_is_buffer( state ) ) ) {
    return -1;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L118-L125 */
  if( config_upgrade_authority_address!=NULL ) {
    if( FD_UNLIKELY( !state->inner.buffer.has_authority_address ||
                     !fd_pubkey_eq( config_upgrade_authority_address, &state->inner.buffer.authority_address ) ) ) {
      return -1;
    }
  }

  /* https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L127-L132 */
  fd_rent_t const * rent = fd_bank_rent_query( slot_ctx->bank );
  if( FD_UNLIKELY( rent==NULL ) ) {
    return -1;
  }

  const uchar * elf = fd_txn_account_get_data( buffer_acc_rec ) + BUFFER_METADATA_SIZE;
  ulong space = PROGRAMDATA_METADATA_SIZE - BUFFER_METADATA_SIZE + fd_txn_account_get_data_len( buffer_acc_rec );
  ulong lamports = fd_rent_exempt_minimum_balance( rent, space );

  /* https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L134-L137 */
  fd_bpf_upgradeable_loader_state_t programdata_metadata = {
    .discriminant = fd_bpf_upgradeable_loader_state_enum_program_data,
    .inner = {
      .program_data = {
        .slot = fd_bank_slot_get( slot_ctx->bank ),
        .has_upgrade_authority_address = !!config_upgrade_authority_address,
        .upgrade_authority_address     = config_upgrade_authority_address ? *config_upgrade_authority_address : (fd_pubkey_t){{0}}
      }
    }
  };

  /* https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L139-L144 */
  fd_txn_account_set_lamports( new_target_program_data_account, lamports );
  fd_bincode_encode_ctx_t encode_ctx = {
    .data    = fd_txn_account_get_data_mut( new_target_program_data_account ),
    .dataend = fd_txn_account_get_data_mut( new_target_program_data_account ) + PROGRAMDATA_METADATA_SIZE,
  };
  err = fd_bpf_upgradeable_loader_state_encode( &programdata_metadata, &encode_ctx );
  if( FD_UNLIKELY( err ) ) {
    return err;
  }
  fd_txn_account_set_owner( new_target_program_data_account, &fd_solana_bpf_loader_upgradeable_program_id );

  /* Copy the ELF data over
     https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L145 */
  fd_memcpy( fd_txn_account_get_data_mut( new_target_program_data_account ) + PROGRAMDATA_METADATA_SIZE, elf, fd_txn_account_get_data_len( buffer_acc_rec ) - BUFFER_METADATA_SIZE );

  return FD_RUNTIME_EXECUTE_SUCCESS;

  } FD_SPAD_FRAME_END;
}

/* Initializes a source buffer account from funk. Returns 1 if the
   buffer account does not exist or is not owned by the upgradeable
   loader. Returns 0 on success.

   https://github.com/anza-xyz/agave/blob/v2.3.0/runtime/src/bank/builtins/core_bpf_migration/source_buffer.rs#L22-L49 */
static int
fd_source_buffer_account_new( fd_exec_slot_ctx_t * slot_ctx,
                              fd_txn_account_t *   buffer_account,
                              fd_pubkey_t const *  buffer_address,
                              fd_funk_rec_prepare_t * prepare ) {
  /* The buffer account should exist.
     https://github.com/anza-xyz/agave/blob/v2.3.0/runtime/src/bank/builtins/core_bpf_migration/source_buffer.rs#L27-L29 */
  if( FD_UNLIKELY( fd_txn_account_init_from_funk_mutable( buffer_account, buffer_address, slot_ctx->funk, slot_ctx->xid, 0, 0UL, prepare )!=FD_ACC_MGR_SUCCESS ) ) {
    FD_LOG_DEBUG(( "Buffer account %s does not exist, skipping migration...", FD_BASE58_ENC_32_ALLOCA( buffer_address ) ));
    return 1;
  }

  /* The buffer account should be owned by the upgradeable loader.
     https://github.com/anza-xyz/agave/blob/v2.3.0/runtime/src/bank/builtins/core_bpf_migration/source_buffer.rs#L31-L34 */
  if( FD_UNLIKELY( memcmp( fd_txn_account_get_owner( buffer_account ), fd_solana_bpf_loader_upgradeable_program_id.uc, sizeof(fd_pubkey_t) ) ) ) {
    FD_LOG_DEBUG(( "Buffer account %s is not owned by the upgradeable loader, skipping migration...", FD_BASE58_ENC_32_ALLOCA( buffer_address ) ));
    return 1;
  }

  /* The buffer account should have the correct state. We already check
     the buffer account state in fd_new_target_program_data_account(),
     so we can skip the checks here.
     https://github.com/anza-xyz/agave/blob/v2.3.0/runtime/src/bank/builtins/core_bpf_migration/source_buffer.rs#L37-L47 */

  return 0;
}

/* Similar to fd_source_buffer_account_new() but also checks the build
   hash of the buffer account for verification. verified_build_hash must
   be valid and non-NULL. Returns 1 if fd_source_buffer_account_new()
   fails, the buffer dlen is too small, or if the build hash mismatches.
   Returns 0 on success.

   https://github.com/anza-xyz/agave/blob/v2.3.0/runtime/src/bank/builtins/core_bpf_migration/source_buffer.rs#L51-L75 */
static int
fd_source_buffer_account_new_with_hash( fd_exec_slot_ctx_t *    slot_ctx,
                                        fd_txn_account_t *      buffer_account,
                                        fd_pubkey_t const *     buffer_address,
                                        fd_hash_t const *       verified_build_hash,
                                        fd_funk_rec_prepare_t * prepare ) {
  /* https://github.com/anza-xyz/agave/blob/v2.3.0/runtime/src/bank/builtins/core_bpf_migration/source_buffer.rs#L58 */
  int err = fd_source_buffer_account_new( slot_ctx, buffer_account, buffer_address, prepare );
  if( FD_UNLIKELY( err ) ) {
    return err;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.3.0/runtime/src/bank/builtins/core_bpf_migration/source_buffer.rs#L59 */
  uchar const * data = fd_txn_account_get_data( buffer_account );
  ulong         data_len = fd_txn_account_get_data_len( buffer_account );

  /* https://github.com/anza-xyz/agave/blob/v2.3.0/runtime/src/bank/builtins/core_bpf_migration/source_buffer.rs#L61 */
  ulong offset = BUFFER_METADATA_SIZE;
  if( FD_UNLIKELY( data_len<offset ) ) {
    return 1;
  }

  /* Search for the first nonzero byte in the buffer account data starting
     from the right.
     https://github.com/anza-xyz/agave/blob/v2.3.0/runtime/src/bank/builtins/core_bpf_migration/source_buffer.rs#L62 */
  ulong end_offset = offset;
  for( ulong i=data_len-1UL; i>=offset; i-- ) {
    if( data[i]!=0 ) {
      end_offset = i+1UL;
      break;
    }
  }

  /* Compute and verify the hash.
     https://github.com/anza-xyz/agave/blob/v2.3.0/runtime/src/bank/builtins/core_bpf_migration/source_buffer.rs#L64-L71 */
  fd_hash_t hash[1];
  fd_sha256_hash( data+offset, end_offset-offset, hash );
  if( FD_UNLIKELY( memcmp( verified_build_hash, hash, sizeof(fd_hash_t) ) ) ) {
    FD_LOG_WARNING(( "Mismatching build hash for Buffer account %s (expected=%s, actual=%s). Skipping migration...", FD_BASE58_ENC_32_ALLOCA( buffer_address ), FD_BASE58_ENC_32_ALLOCA( verified_build_hash ), FD_BASE58_ENC_32_ALLOCA( hash ) ));
    return 1;
  }

  return 0;
}

/* Mimics migrate_builtin_to_core_bpf().
   https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L235-L318 */
void
fd_migrate_builtin_to_core_bpf( fd_exec_slot_ctx_t *                   slot_ctx,
                                fd_core_bpf_migration_config_t const * config,
                                fd_spad_t *                            runtime_spad ) {
  int err;

  /* Initialize local variables from the config */
  fd_pubkey_t const * source_buffer_address     = config->source_buffer_address;
  fd_pubkey_t *       upgrade_authority_address = config->upgrade_authority_address;
  uchar               stateless                 = !!( config->migration_target==FD_CORE_BPF_MIGRATION_TARGET_STATELESS );
  fd_pubkey_t const * builtin_program_id        = config->builtin_program_id;
  fd_hash_t const *   verified_build_hash       = config->verified_build_hash;

  /* https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L242-L243

     The below logic is used to obtain a TargetBuiltin account. There
     are three fields of TargetBuiltin returned:
      - target.program_address: builtin_program_id
      - target.program_account:
          - if stateless: an AccountSharedData::default() (i.e. system
            program id, 0 lamports, 0 data, non-executable, system
            program owner)
          - if NOT stateless: the existing account (for us its called
            target_program_account)
      - target.program_data_address: target_program_data_address for
        us, derived below. */

  /* These checks will fail if the core program has already been migrated to BPF, since the account will exist + the program owner
     will no longer be the native loader.
     https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/target_builtin.rs#L23-L50 */
  FD_TXN_ACCOUNT_DECL( target_program_account );
  uchar program_exists = ( fd_txn_account_init_from_funk_readonly( target_program_account, builtin_program_id, slot_ctx->funk, slot_ctx->xid )==FD_ACC_MGR_SUCCESS );
  if( !stateless ) {
    /* The program account should exist.
       https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/target_builtin.rs#L30-L33 */
    if( FD_UNLIKELY( !program_exists ) ) {
      FD_LOG_DEBUG(( "Builtin program %s does not exist, skipping migration...", FD_BASE58_ENC_32_ALLOCA( builtin_program_id ) ));
      return;
    }

    /* The program account should be owned by the native loader.
       https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/target_builtin.rs#L35-L38 */
    if( FD_UNLIKELY( memcmp( fd_txn_account_get_owner( target_program_account ), fd_solana_native_loader_id.uc, sizeof(fd_pubkey_t) ) ) ) {
      FD_LOG_DEBUG(( "Builtin program %s is not owned by the native loader, skipping migration...", FD_BASE58_ENC_32_ALLOCA( builtin_program_id ) ));
      return;
    }
  } else {
    /* The program account should _not_ exist.
       https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/target_builtin.rs#L42-L46 */
    if( FD_UNLIKELY( program_exists ) ) {
      FD_LOG_DEBUG(( "Stateless program %s already exists, skipping migration...", FD_BASE58_ENC_32_ALLOCA( builtin_program_id ) ));
      return;
    }
  }

  /* The program data account should not exist.
     https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/target_builtin.rs#L52-L62 */
  uint custom_err = UINT_MAX;
  fd_pubkey_t target_program_data_address[ 1UL ];
  uchar const * seeds[ 1UL ];
  seeds[ 0UL ]    = (uchar const *)builtin_program_id;
  ulong seed_sz   = sizeof(fd_pubkey_t);
  uchar bump_seed = 0;
  err = fd_pubkey_find_program_address( &fd_solana_bpf_loader_upgradeable_program_id, 1UL, seeds, &seed_sz, target_program_data_address, &bump_seed, &custom_err );
  if( FD_UNLIKELY( err ) ) {
    /* TODO: We should handle these errors more gracefully instead of just killing the client. */
    FD_LOG_ERR(( "Unable to find a viable program address bump seed" )); // Solana panics, error code is undefined
    return;
  }
  FD_TXN_ACCOUNT_DECL( program_data_account );
  if( FD_UNLIKELY( fd_txn_account_init_from_funk_readonly( program_data_account, target_program_data_address, slot_ctx->funk, slot_ctx->xid )==FD_ACC_MGR_SUCCESS ) ) {
    FD_LOG_WARNING(( "Program data account %s already exists, skipping migration...", FD_BASE58_ENC_32_ALLOCA( target_program_data_address ) ));
    return;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.3.0/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L221-L229

     Obtains a SourceBuffer account. There are two fields returned:
      - source.buffer_address: source_buffer_address
      - source.buffer_account: the existing buffer account
     Depending on if the verified build hash is provided,  */
  FD_TXN_ACCOUNT_DECL( source_buffer_account );
  fd_funk_rec_prepare_t source_buffer_prepare = {0};
  if( verified_build_hash!=NULL ) {
    if( FD_UNLIKELY( fd_source_buffer_account_new_with_hash( slot_ctx, source_buffer_account, source_buffer_address, verified_build_hash, &source_buffer_prepare ) ) ) {
      return;
    }
  } else {
    if( FD_UNLIKELY( fd_source_buffer_account_new( slot_ctx, source_buffer_account, source_buffer_address, &source_buffer_prepare ) ) ) {
      return;
    }
  }

  fd_lthash_value_t prev_source_buffer_hash[1];
  fd_hashes_account_lthash(
    source_buffer_address,
    fd_txn_account_get_meta( source_buffer_account ),
    fd_txn_account_get_data( source_buffer_account ),
    prev_source_buffer_hash );

  /* This check is done a bit prematurely because we calculate the
     previous account state's lamports. We use 0 for starting lamports
     for stateless accounts because they don't yet exist.

     https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L277-L280 */
  ulong lamports_to_burn = ( stateless ? 0UL : fd_txn_account_get_lamports( target_program_account ) ) + fd_txn_account_get_lamports( source_buffer_account );

  /* Start a funk write txn */
  fd_funk_txn_xid_t parent_xid = slot_ctx->xid[0];
  fd_funk_txn_xid_t migration_xid = fd_funk_generate_xid();
  fd_funk_txn_prepare( slot_ctx->funk, slot_ctx->xid, &migration_xid );
  slot_ctx->xid[0] = migration_xid;

  /* Attempt serialization of program account. If the program is
     stateless, we want to create the account. Otherwise, we want a
     writable handle to modify the existing account.
     https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L246-L249 */
  FD_TXN_ACCOUNT_DECL( new_target_program_account );
  fd_funk_rec_prepare_t new_target_program_prepare = {0};
  err = fd_txn_account_init_from_funk_mutable(
      new_target_program_account,
      builtin_program_id,
      slot_ctx->funk,
      slot_ctx->xid,
      stateless,
      SIZE_OF_PROGRAM,
      &new_target_program_prepare );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_WARNING(( "Builtin program ID %s does not exist", FD_BASE58_ENC_32_ALLOCA( builtin_program_id ) ));
    goto fail;
  }
  fd_lthash_value_t prev_new_target_program_account_hash[1];
  fd_hashes_account_lthash(
    builtin_program_id,
    fd_txn_account_get_meta( new_target_program_account ),
    fd_txn_account_get_data( new_target_program_account ),
    prev_new_target_program_account_hash );
  fd_txn_account_set_data_len( new_target_program_account, SIZE_OF_PROGRAM );
  fd_txn_account_set_slot( new_target_program_account, fd_bank_slot_get( slot_ctx->bank ) );

  /* Create a new target program account. This modifies the existing record. */
  err = fd_new_target_program_account( slot_ctx, target_program_data_address, new_target_program_account );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_WARNING(( "Failed to write new program state to %s", FD_BASE58_ENC_32_ALLOCA( builtin_program_id ) ));
    goto fail;
  }

  fd_hashes_update_lthash(
    new_target_program_account,
    prev_new_target_program_account_hash,
    slot_ctx->bank,
    slot_ctx->capture_ctx );
  fd_txn_account_mutable_fini( new_target_program_account, slot_ctx->funk, &new_target_program_prepare );

  /* Create a new target program data account. */
  ulong new_target_program_data_account_sz = PROGRAMDATA_METADATA_SIZE - BUFFER_METADATA_SIZE + fd_txn_account_get_data_len( source_buffer_account );
  FD_TXN_ACCOUNT_DECL( new_target_program_data_account );
  fd_funk_rec_prepare_t new_target_program_data_prepare = {0};
  err = fd_txn_account_init_from_funk_mutable(
      new_target_program_data_account,
      target_program_data_address,
      slot_ctx->funk,
      slot_ctx->xid,
      1,
      new_target_program_data_account_sz,
      &new_target_program_data_prepare );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_WARNING(( "Failed to create new program data account to %s", FD_BASE58_ENC_32_ALLOCA( target_program_data_address ) ));
    goto fail;
  }
  fd_lthash_value_t prev_new_target_program_data_account_hash[1];
  fd_hashes_account_lthash(
    target_program_data_address,
    fd_txn_account_get_meta( new_target_program_data_account ),
    fd_txn_account_get_data( new_target_program_data_account ),
    prev_new_target_program_data_account_hash );
  fd_txn_account_set_data_len( new_target_program_data_account, new_target_program_data_account_sz );
  fd_txn_account_set_slot( new_target_program_data_account, fd_bank_slot_get( slot_ctx->bank ) );

  err = fd_new_target_program_data_account( slot_ctx,
                                            upgrade_authority_address,
                                            source_buffer_account,
                                            new_target_program_data_account,
                                            runtime_spad );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_WARNING(( "Failed to write new program data state to %s", FD_BASE58_ENC_32_ALLOCA( target_program_data_address ) ));
    goto fail;
  }

  fd_hashes_update_lthash(
    new_target_program_data_account,
    prev_new_target_program_data_account_hash,
    slot_ctx->bank,
    slot_ctx->capture_ctx );
  fd_txn_account_mutable_fini( new_target_program_data_account, slot_ctx->funk, &new_target_program_data_prepare );

  /* Deploy the new target Core BPF program.
     https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L268-L271 */
  err = fd_directly_invoke_loader_v3_deploy( slot_ctx,
                                             builtin_program_id,
                                             fd_txn_account_get_data( new_target_program_data_account ) + PROGRAMDATA_METADATA_SIZE,
                                             fd_txn_account_get_data_len( new_target_program_data_account ) - PROGRAMDATA_METADATA_SIZE,
                                             runtime_spad );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_WARNING(( "Failed to deploy program %s", FD_BASE58_ENC_32_ALLOCA( builtin_program_id ) ));
    goto fail;
  }

  /* https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L281-L284 */
  ulong lamports_to_fund = fd_txn_account_get_lamports( new_target_program_account ) + fd_txn_account_get_lamports( new_target_program_data_account );

  /* Update capitalization.
     https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L286-L297 */
  if( lamports_to_burn>lamports_to_fund ) {
    fd_bank_capitalization_set( slot_ctx->bank, fd_bank_capitalization_get( slot_ctx->bank ) - ( lamports_to_burn - lamports_to_fund ) );
  } else {
    fd_bank_capitalization_set( slot_ctx->bank, fd_bank_capitalization_get( slot_ctx->bank ) + ( lamports_to_fund - lamports_to_burn ) );
  }

  /* Reclaim the source buffer account
     https://github.com/anza-xyz/agave/blob/v2.1.0/runtime/src/bank/builtins/core_bpf_migration/mod.rs#L305 */
  fd_txn_account_set_lamports( source_buffer_account, 0 );
  fd_txn_account_set_data_len( source_buffer_account, 0 );
  fd_txn_account_clear_owner( source_buffer_account );

  fd_hashes_update_lthash(
    source_buffer_account,
    prev_source_buffer_hash,
    slot_ctx->bank,
    slot_ctx->capture_ctx );
  fd_txn_account_mutable_fini( source_buffer_account, slot_ctx->funk, &source_buffer_prepare );

  /* Publish the in-preparation transaction into the parent. We should not have to create
     a BPF cache entry here because the program is technically "delayed visibility", so the program
     should not be invokable until the next slot. The cache entry will be created at the end of the
     block as a part of the finalize routine. */
  fd_funk_txn_publish_into_parent( slot_ctx->funk, slot_ctx->xid );
  slot_ctx->xid[0] = parent_xid;
  return;

fail:
  /* Cancel the in-preparation transaction and discard any in-progress changes. */
  fd_funk_txn_cancel( slot_ctx->funk, slot_ctx->xid );
  slot_ctx->xid[0] = parent_xid;
}
