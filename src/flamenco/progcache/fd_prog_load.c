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
  fd_bincode_decode_ctx_t decode = fd_bincode_decode_ctx( fd_accdb_ref_data_const( ro ), data_sz );
  ulong total_sz = 0UL;
  if( FD_UNLIKELY( fd_bpf_upgradeable_loader_state_decode_footprint( &decode, &total_sz )!=FD_BINCODE_SUCCESS ) ) {
    FD_LOG_WARNING(( "program data account is invalid" ));
    return NULL;
  }
  if( FD_UNLIKELY( fd_accdb_ref_data_sz( ro )<PROGRAMDATA_METADATA_SIZE ) ) {
    FD_LOG_WARNING(( "program data account is too small" ));
    return NULL;
  }
  fd_bpf_upgradeable_loader_state_t state;
  fd_bpf_upgradeable_loader_state_decode( &state, &decode );
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

fd_prog_info_t *
fd_prog_info( fd_prog_info_t * out,
              fd_accdb_ro_t *  ro ){
  void const * owner = fd_accdb_ref_owner( ro );
  if( !memcmp( owner, fd_solana_bpf_loader_upgradeable_program_id.key, sizeof(fd_pubkey_t) ) ) {
    return fd_prog_info_v3( out, ro );
  } else if( !memcmp( owner, fd_solana_bpf_loader_v4_program_id.key, sizeof(fd_pubkey_t) ) ) {
    return fd_prog_info_v4( out, ro );
  } else if( !memcmp( owner, fd_solana_bpf_loader_program_id.key, sizeof(fd_pubkey_t) ) ||
             !memcmp( owner, fd_solana_bpf_loader_deprecated_program_id.key, sizeof(fd_pubkey_t) ) ) {
    return fd_prog_info_v1( out, ro );
  } else {
    FD_BASE58_ENCODE_32_BYTES( fd_accdb_ref_address( ro ), addr_b58  );
    FD_BASE58_ENCODE_32_BYTES( fd_accdb_ref_owner  ( ro ), owner_b58 );
    FD_LOG_WARNING(( "unsupported program data account (address=%s owner=%s)", addr_b58, owner_b58 ));
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

  fd_prog_versions_t v = {0};
  if( enable_v2 ) {
    v.max_sbpf_version = FD_SBPF_V2;
  } else if( enable_v1 ) {
    v.max_sbpf_version = FD_SBPF_V1;
  } else {
    v.max_sbpf_version = FD_SBPF_V0;
  }
  v.min_sbpf_version = enable_v0 ? FD_SBPF_V0 : fd_uint_min( FD_SBPF_V2, v.max_sbpf_version );
  return v;
}

fd_prog_load_env_t *
fd_prog_load_env_from_bank( fd_prog_load_env_t * env,
                            fd_bank_t const *    bank ) {
  *env = (fd_prog_load_env_t) {
    .features    = &bank->data->f.features,
    .epoch       = bank->data->f.epoch,
    .epoch_slot0 = fd_epoch_slot0( &bank->data->f.epoch_schedule, bank->data->f.epoch )
  };
  return env;
}
