#include "fd_prog_load.h"
#include "../runtime/program/fd_bpf_loader_program.h"
#include "../runtime/program/fd_loader_v4_program.h"
#include "../runtime/sysvar/fd_sysvar_epoch_schedule.h"
#include "../runtime/fd_system_ids.h"

static fd_prog_info_t *
fd_prog_info_v4( fd_prog_info_t *      out,
                 fd_accdb_ro_t const * ro ) {

  ulong data_sz = fd_accdb_ref_data_sz( ro );
  if( FD_UNLIKELY( data_sz<LOADER_V4_PROGRAM_DATA_OFFSET ) ) {
    FD_LOG_WARNING(( "program data account is invalid" ));
    return NULL;
  }

  fd_loader_v4_state_t state = FD_LOAD( fd_loader_v4_state_t, fd_accdb_ref_data_const( ro ) );
  if( FD_UNLIKELY( state.status==FD_LOADER_V4_STATUS_ENUM_RETRACTED ) ) {
    FD_LOG_WARNING(( "program data account is not executable" ));
    return NULL;
  }

  *out = (fd_prog_info_t) {
    .elf_off = LOADER_V4_PROGRAM_DATA_OFFSET,
    .elf_sz  = data_sz - LOADER_V4_PROGRAM_DATA_OFFSET,
    .deploy_slot = state.slot
  };
  return out;
}

static fd_prog_info_t *
fd_prog_info_v3( fd_prog_info_t *      out,
                 fd_accdb_ro_t const * ro ) {

  ulong data_sz = fd_accdb_ref_data_sz( ro );
  if( FD_UNLIKELY( data_sz<PROGRAMDATA_METADATA_SIZE ) ) {
    FD_LOG_WARNING(( "program data account is too small" ));
    return NULL;
  }
  fd_bpf_upgradeable_loader_state_t state;
  if( FD_UNLIKELY( fd_bpf_upgradeable_loader_state_decode( &state, fd_accdb_ref_data_const( ro ), data_sz ) ) ) {
    FD_LOG_WARNING(( "program data account is invalid" ));
    return NULL;
  }
  if( FD_UNLIKELY( state.discriminant!=fd_bpf_upgradeable_loader_state_enum_program_data ) ) {
    FD_LOG_WARNING(( "loader v3 account is not a program data account" ));
    return NULL;
  }

  *out = (fd_prog_info_t) {
    .elf_off = PROGRAMDATA_METADATA_SIZE,
    .elf_sz  = data_sz - PROGRAMDATA_METADATA_SIZE,
    .deploy_slot = state.inner.program_data.slot
  };
  return out;
}

static fd_prog_info_t *
fd_prog_info_v1( fd_prog_info_t *      out,
                 fd_accdb_ro_t const * ro ) {
  *out = (fd_prog_info_t) {
    .elf_off = 0UL,
    .elf_sz  = fd_accdb_ref_data_sz( ro ),
    .deploy_slot = 0UL
  };
  return out;
}

/* We determine the BPF loader type based off of the program acount owner,
   instead of the programdata owner.
   https://github.com/anza-xyz/agave/blob/v4.0.0-beta.5/svm/src/program_loader.rs#L29 */
fd_prog_info_t *
fd_prog_info( fd_prog_info_t     * out,
              fd_accdb_ro_t      * ro,
              fd_pubkey_t const  * program_owner ){
  if( fd_pubkey_eq( program_owner, &fd_solana_bpf_loader_upgradeable_program_id ) ) {
    return fd_prog_info_v3( out, ro );
  } else if( fd_pubkey_eq( program_owner, &fd_solana_bpf_loader_v4_program_id ) ) {
    return fd_prog_info_v4( out, ro );
  } else if( fd_pubkey_eq( program_owner, &fd_solana_bpf_loader_program_id ) ||
             fd_pubkey_eq( program_owner, &fd_solana_bpf_loader_deprecated_program_id ) ) {
    return fd_prog_info_v1( out, ro );
  } else {
    FD_BASE58_ENCODE_32_BYTES( fd_accdb_ref_address( ro ),  addr_b58  );
    FD_BASE58_ENCODE_32_BYTES( program_owner->key,          owner_b58 );
    FD_LOG_WARNING(( "unsupported program data account (address=%s program_owner=%s)", addr_b58, owner_b58 ));
    return NULL;
  }
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
  /* https://github.com/anza-xyz/agave/blob/v4.0.0-beta.4/syscalls/src/lib.rs#L314-L319 */
  v.min_sbpf_version = enable_v0 ? FD_SBPF_V0 : FD_SBPF_V3;
  /* https://github.com/anza-xyz/agave/blob/v4.0.0-beta.4/syscalls/src/lib.rs#L320-L328 */
  if( enable_v3 )      { v.max_sbpf_version = FD_SBPF_V3; }
  else if( enable_v2 ) { v.max_sbpf_version = FD_SBPF_V2; }
  else if( enable_v1 ) { v.max_sbpf_version = FD_SBPF_V1; }
  else                 { v.max_sbpf_version = FD_SBPF_V0; }
  return v;
}

fd_prog_load_env_t *
fd_prog_load_env_from_bank( fd_prog_load_env_t * env,
                            fd_bank_t const *    bank ) {
  *env = (fd_prog_load_env_t) {
    .features    = &bank->f.features,
    .epoch       = bank->f.epoch,
    .epoch_slot0 = fd_epoch_slot0( &bank->f.epoch_schedule, bank->f.epoch )
  };
  return env;
}
