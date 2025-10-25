#include "fd_prog_load.h"
#include "../runtime/program/fd_bpf_loader_program.h"
#include "../runtime/program/fd_loader_v4_program.h"
#include "../runtime/sysvar/fd_sysvar_epoch_schedule.h"

/* Similar to the below function, but gets the executable program content for the v4 loader.
   Unlike the v3 loader, the programdata is stored in a single program account. The program must
   NOT be retracted to be added to the cache. Returns a pointer to the programdata on success,
   and NULL on failure.

   Reasons for failure include:
   - The program state cannot be read from the account data or is in the `retracted` state. */
static uchar const *
fd_get_executable_program_content_for_v4_loader( fd_txn_account_t const * program_acc,
                                                 ulong *                  program_data_len ) {
  int err;

  /* Get the current loader v4 state. This implicitly also checks the dlen. */
  fd_loader_v4_state_t const * state = fd_loader_v4_get_state( program_acc, &err );
  if( FD_UNLIKELY( err ) ) {
    return NULL;
  }

  /* The program must be deployed or finalized. */
  if( FD_UNLIKELY( fd_loader_v4_status_is_retracted( state ) ) ) {
    return NULL;
  }

  /* This subtraction is safe because get_state() implicitly checks the
     dlen. */
  *program_data_len = fd_txn_account_get_data_len( program_acc )-LOADER_V4_PROGRAM_DATA_OFFSET;
  return fd_txn_account_get_data( program_acc )+LOADER_V4_PROGRAM_DATA_OFFSET;
}

/* Gets the programdata for a v3 loader-owned account by decoding the account data
   as well as the programdata account. Returns a pointer to the programdata on success,
   and NULL on failure.

   Reasons for failure include:
   - The program account data cannot be decoded or is not in the `program` state.
   - The programdata account is not large enough to hold at least `PROGRAMDATA_METADATA_SIZE` bytes. */
static uchar const *
fd_get_executable_program_content_for_upgradeable_loader( fd_funk_t const *         funk,
                                                          fd_funk_txn_xid_t const * xid,
                                                          fd_txn_account_t const *  program_acc,
                                                          ulong *                   program_data_len,
                                                          fd_funk_txn_xid_t *       out_xid ) {
  fd_bpf_upgradeable_loader_state_t program_account_state[1];
  if( FD_UNLIKELY( !fd_bincode_decode_static(
      bpf_upgradeable_loader_state,
      program_account_state,
      fd_txn_account_get_data( program_acc ),
      fd_txn_account_get_data_len( program_acc ),
      NULL ) ) ) {
    return NULL;
  }
  if( !fd_bpf_upgradeable_loader_state_is_program( program_account_state ) ) {
    return NULL;
  }

  fd_pubkey_t * programdata_address = &program_account_state->inner.program.programdata_address;

  fd_account_meta_t const * meta = fd_funk_get_acc_meta_readonly(
      funk, xid, programdata_address, NULL, NULL, out_xid );
  if( FD_UNLIKELY( !meta ) ) return NULL;
  fd_txn_account_t _rec[1];
  fd_txn_account_t * programdata_acc = fd_txn_account_join( fd_txn_account_new( _rec, programdata_address, (void *)meta, 0 ), funk->wksp );
  if( FD_UNLIKELY( !programdata_acc ) ) FD_LOG_CRIT(( "fd_txn_account_new failed" ));

  /* We don't actually need to decode here, just make sure that the account
     can be decoded successfully. */
  fd_bincode_decode_ctx_t ctx_programdata = {
    .data    = fd_txn_account_get_data( programdata_acc ),
    .dataend = fd_txn_account_get_data( programdata_acc ) + fd_txn_account_get_data_len( programdata_acc ),
  };

  ulong total_sz = 0UL;
  if( FD_UNLIKELY( fd_bpf_upgradeable_loader_state_decode_footprint( &ctx_programdata, &total_sz ) ) ) {
    return NULL;
  }

  if( FD_UNLIKELY( fd_txn_account_get_data_len( programdata_acc )<PROGRAMDATA_METADATA_SIZE ) ) {
    return NULL;
  }

  *program_data_len = fd_txn_account_get_data_len( programdata_acc ) - PROGRAMDATA_METADATA_SIZE;
  return fd_txn_account_get_data( programdata_acc ) + PROGRAMDATA_METADATA_SIZE;
}

/* Gets the programdata for a v1/v2 loader-owned account by returning a
   pointer to the account data. Returns a pointer to the programdata on
   success. Given the txn account API always returns a handle to the
   account data, this function should NEVER return NULL (since the
   programdata of v1 and v2 loader) accounts start at the beginning of
   the data. */
static uchar const *
fd_get_executable_program_content_for_v1_v2_loaders( fd_txn_account_t const * program_acc,
                                                     ulong *                  program_data_len ) {
  *program_data_len = fd_txn_account_get_data_len( program_acc );
  return fd_txn_account_get_data( program_acc );
}

uchar const *
fd_prog_load_elf( fd_funk_t const *         accdb,
                  fd_funk_txn_xid_t const * xid,
                  void const *              _prog_addr,
                  ulong *                   out_sz,
                  fd_funk_txn_xid_t *       out_xid ) {
  fd_pubkey_t prog_addr = FD_LOAD( fd_pubkey_t, _prog_addr );

  fd_funk_txn_xid_t _out_xid;
  if( !out_xid ) out_xid = &_out_xid;
  fd_account_meta_t const * meta = fd_funk_get_acc_meta_readonly(
      accdb, xid, &prog_addr, NULL, NULL, out_xid );
  if( FD_UNLIKELY( !meta ) ) return NULL;
  fd_txn_account_t _rec[1];
  fd_txn_account_t * rec = fd_txn_account_join( fd_txn_account_new( _rec, &prog_addr, (void *)meta, 0 ), accdb->wksp );
  if( FD_UNLIKELY( !rec ) ) FD_LOG_CRIT(( "fd_txn_account_new failed" ));

  /* v1/v2 loaders: Programdata is just the account data.
     v3 loader: Programdata lives in a separate account. Deserialize the
                program account and lookup the programdata account.
                 Deserialize the programdata account.
     v4 loader: Programdata lives in the program account, offset by
                LOADER_V4_PROGRAM_DATA_OFFSET. */
  fd_pubkey_t const * owner = fd_txn_account_get_owner( rec );
  uchar const * elf = NULL;
  if( !memcmp( owner, fd_solana_bpf_loader_upgradeable_program_id.key, sizeof(fd_pubkey_t) ) ) {
    /* When a loader v3 program is redeployed, the programdata account
       is always updated.  Therefore, use the programdata account's
       'last update XID' instead of the program account's. */
    elf = fd_get_executable_program_content_for_upgradeable_loader( accdb, xid, rec, out_sz, out_xid );
  } else if( !memcmp( owner, fd_solana_bpf_loader_v4_program_id.key, sizeof(fd_pubkey_t) ) ) {
    elf = fd_get_executable_program_content_for_v4_loader( rec, out_sz );
  } else if( !memcmp( owner, fd_solana_bpf_loader_program_id.key, sizeof(fd_pubkey_t) ) ||
             !memcmp( owner, fd_solana_bpf_loader_deprecated_program_id.key, sizeof(fd_pubkey_t) ) ) {
    elf = fd_get_executable_program_content_for_v1_v2_loaders( rec, out_sz );
  }

  if( FD_LIKELY( !elf ) ) {
    fd_funk_txn_xid_set_root( out_xid );
  }

  return elf;
}

FD_FN_PURE fd_prog_versions_t
fd_prog_versions( fd_features_t const * features,
                  ulong                 slot ) {
  int disable_v0  = FD_FEATURE_ACTIVE( slot, features, disable_sbpf_v0_execution );
  int reenable_v0 = FD_FEATURE_ACTIVE( slot, features, reenable_sbpf_v0_execution );
  int enable_v0   = !disable_v0 || reenable_v0;
  int enable_v1   = FD_FEATURE_ACTIVE( slot, features, enable_sbpf_v1_deployment_and_execution );
  int enable_v2   = FD_FEATURE_ACTIVE( slot, features, enable_sbpf_v2_deployment_and_execution );
  int enable_v3   = FD_FEATURE_ACTIVE( slot, features, enable_sbpf_v3_deployment_and_execution );

  fd_prog_versions_t v = {0};
  v.min_sbpf_version = enable_v0 ? FD_SBPF_V0 : FD_SBPF_V3;
  if( enable_v3 ) {
    v.max_sbpf_version = FD_SBPF_V3;
  } else if( enable_v2 ) {
    v.max_sbpf_version = FD_SBPF_V2;
  } else if( enable_v1 ) {
    v.max_sbpf_version = FD_SBPF_V1;
  } else {
    v.max_sbpf_version = FD_SBPF_V0;
  }
  return v;
}


fd_prog_load_env_t *
fd_prog_load_env_from_bank( fd_prog_load_env_t * env,
                            fd_bank_t const *    bank ) {
  *env = (fd_prog_load_env_t) {
    .features      = fd_bank_features_query( bank ),
    .slot          = fd_bank_slot_get      ( bank ),
    .epoch         = fd_bank_epoch_get     ( bank ),
    .epoch_slot0   = fd_epoch_slot0( fd_bank_epoch_schedule_query( bank ), fd_bank_epoch_get( bank ) )
  };
  return env;
}
