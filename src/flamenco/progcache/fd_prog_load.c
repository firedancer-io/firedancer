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
fd_get_executable_program_content_for_v4_loader( fd_accdb_ro_t const * ro ) {
  int err;

  /* Get the current loader v4 state. This implicitly also checks the dlen. */
  void const * data    = fd_accdb_ref_data_const( ro );
  ulong        data_sz = fd_accdb_ref_data_sz( ro );
  fd_loader_v4_state_t const * state = fd_loader_v4_get_state( data, data_sz, &err );
  if( FD_UNLIKELY( err ) ) {
    return NULL;
  }

  /* The program must be deployed or finalized. */
  if( FD_UNLIKELY( fd_loader_v4_status_is_retracted( state ) ) ) {
    return NULL;
  }

  /* This subtraction is safe because get_state() implicitly checks the
     dlen. */
  return (uchar const *)data+LOADER_V4_PROGRAM_DATA_OFFSET;
}

/* Gets the programdata for a v3 loader-owned account by decoding the account data
   as well as the programdata account. Returns a pointer to the programdata on success,
   and NULL on failure.

   Reasons for failure include:
   - The program account data cannot be decoded or is not in the `program` state.
   - The programdata account is not large enough to hold at least `PROGRAMDATA_METADATA_SIZE` bytes. */
static fd_accdb_ro_t *
fd_prog_load_v3( fd_accdb_user_t *         accdb,
                 fd_funk_txn_xid_t const * xid,
                 fd_accdb_ro_t *           progdata,
                 fd_accdb_ro_t const *     prog,
                 ulong *                   out_offset ) {
  fd_bpf_upgradeable_loader_state_t program_account_state[1];
  if( FD_UNLIKELY( !fd_bincode_decode_static(
      bpf_upgradeable_loader_state,
      program_account_state,
      fd_accdb_ref_data_const( prog ),
      fd_accdb_ref_data_sz   ( prog ),
      NULL ) ) ) {
    return NULL;
  }
  if( !fd_bpf_upgradeable_loader_state_is_program( program_account_state ) ) {
    return NULL;
  }

  fd_pubkey_t * programdata_address = &program_account_state->inner.program.programdata_address;

  if( FD_UNLIKELY( !fd_accdb_open_ro( accdb, progdata, xid, programdata_address ) ) ) {
    return NULL;
  }

  /* We don't actually need to decode here, just make sure that the account
     can be decoded successfully. */
  fd_bincode_decode_ctx_t ctx_programdata = {
    .data    = fd_accdb_ref_data_const( progdata ),
    .dataend = (uchar const *)fd_accdb_ref_data_const( progdata ) + fd_accdb_ref_data_sz( progdata ),
  };

  ulong total_sz = 0UL;
  if( FD_UNLIKELY( fd_bpf_upgradeable_loader_state_decode_footprint( &ctx_programdata, &total_sz ) ) ) {
    fd_accdb_close_ro( accdb, progdata );
    return NULL;
  }

  if( FD_UNLIKELY( fd_accdb_ref_data_sz( progdata )<PROGRAMDATA_METADATA_SIZE ) ) {
    fd_accdb_close_ro( accdb, progdata );
    return NULL;
  }

  *out_offset = PROGRAMDATA_METADATA_SIZE;
  return progdata;
}

fd_accdb_ro_t *
fd_prog_load_elf( fd_accdb_user_t *         accdb,
                  fd_funk_txn_xid_t const * xid,
                  fd_accdb_ro_t *           out,
                  void const *              prog_addr,
                  ulong *                   out_offset ) {
  fd_accdb_ro_t prog[1];
  if( FD_UNLIKELY( !fd_accdb_open_ro( accdb, prog, xid, &prog_addr ) ) ) {
    return NULL;
  }

  /* v1/v2 loaders: Programdata is just the account data.
     v3 loader: Programdata lives in a separate account. Deserialize the
                program account and lookup the programdata account.
                 Deserialize the programdata account.
     v4 loader: Programdata lives in the program account, offset by
                LOADER_V4_PROGRAM_DATA_OFFSET. */
  void const * owner = fd_accdb_ref_owner( prog );
  if( !memcmp( owner, fd_solana_bpf_loader_upgradeable_program_id.key, sizeof(fd_pubkey_t) ) ) {

    /* When a loader v3 program is redeployed, the programdata account
       is always updated.  Therefore, use the programdata account's
       'last update XID' instead of the program account's. */
    fd_accdb_ro_t progdata_[1];
    fd_accdb_ro_t * progdata = fd_prog_load_v3( accdb, xid, progdata_, prog, out_offset );
    fd_accdb_close_ro( accdb, prog );
    if( !progdata ) return NULL;
    *out = *progdata;

  } else if( !memcmp( owner, fd_solana_bpf_loader_v4_program_id.key, sizeof(fd_pubkey_t) ) ) {

    if( !fd_get_executable_program_content_for_v4_loader( prog ) ) {
      fd_accdb_close_ro( accdb, prog );
      return NULL;
    }
    *out        = *prog;
    *out_offset = LOADER_V4_PROGRAM_DATA_OFFSET;

  } else if( !memcmp( owner, fd_solana_bpf_loader_program_id.key, sizeof(fd_pubkey_t) ) ||
             !memcmp( owner, fd_solana_bpf_loader_deprecated_program_id.key, sizeof(fd_pubkey_t) ) ) {

    *out        = *prog;
    *out_offset = 0UL;

  } else {
    return NULL;
  }

  return out;
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
