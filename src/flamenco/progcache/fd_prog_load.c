#include "fd_prog_load.h"
#include "../runtime/program/fd_bpf_loader_program.h"
#include "../runtime/sysvar/fd_sysvar_epoch_schedule.h"
#include "../runtime/fd_system_ids.h"
#include "../../ballet/sbpf/fd_sbpf_loader.h"

static fd_prog_info_t *
fd_prog_info_v3( fd_prog_info_t *         out,
                 fd_acc_t const * ro ) {
  if( FD_UNLIKELY( ro->data_len<PROGRAMDATA_METADATA_SIZE ) ) {
    FD_LOG_WARNING(( "program data account is too small" ));
    return NULL;
  }
  fd_bpf_state_t state;
  if( FD_UNLIKELY( fd_bpf_state_decode( &state, ro->data, ro->data_len ) ) ) {
    FD_LOG_WARNING(( "program data account is invalid" ));
    return NULL;
  }
  if( FD_UNLIKELY( state.discriminant!=FD_BPF_STATE_PROGRAM_DATA ) ) {
    FD_LOG_WARNING(( "loader v3 account is not a program data account" ));
    return NULL;
  }

  *out = (fd_prog_info_t) {
    .elf_off = PROGRAMDATA_METADATA_SIZE,
    .elf_sz  = ro->data_len - PROGRAMDATA_METADATA_SIZE,
    .deploy_slot = state.inner.program_data.slot
  };
  return out;
}

static fd_prog_info_t *
fd_prog_info_v1( fd_prog_info_t * out,
                 fd_acc_t const * acc ) {
  *out = (fd_prog_info_t) {
    .elf_off = 0UL,
    .elf_sz  = acc->data_len,
    .deploy_slot = 0UL
  };
  return out;
}

/* https://github.com/anza-xyz/agave/blob/v4.0.0-beta.5/svm/src/program_loader.rs#L29 */
fd_prog_info_t *
fd_prog_info( fd_prog_info_t * out,
              fd_acc_t const * acc ){
  fd_pubkey_t const * program_owner = (fd_pubkey_t const*)acc->owner;
  if( fd_pubkey_eq( program_owner, &fd_solana_bpf_loader_upgradeable_program_id ) ) {
    return fd_prog_info_v3( out, acc );
  } else if( fd_pubkey_eq( program_owner, &fd_solana_bpf_loader_program_id ) ||
             fd_pubkey_eq( program_owner, &fd_solana_bpf_loader_deprecated_program_id ) ) {
    return fd_prog_info_v1( out, acc );
  } else {
    FD_BASE58_ENCODE_32_BYTES( acc->pubkey, addr_b58  );
    FD_BASE58_ENCODE_32_BYTES( program_owner->key, owner_b58 );
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
  fd_prog_versions_t v = {0};
  /* https://github.com/anza-xyz/agave/blob/v4.3.0-beta.0/syscalls/src/lib.rs#L333-L340 */
  v.min_sbpf_version = enable_v0 ? FD_SBPF_V0 : FD_SBPF_V3;
  v.max_sbpf_version = FD_SBPF_V3;
  return v;
}

fd_prog_load_env_t *
fd_prog_load_env_from_bank( fd_prog_load_env_t * env,
                            fd_bank_t const *    bank ) {
  fd_features_t const * features     = &bank->f.features;
  ulong                 feature_slot = 0UL;

#if FD_PROGCACHE_EB_ALWAYS_INVALIDATE

  /* Valid for FD_FEATURE_ACTIVE only because activations land on epoch starts. */
  feature_slot = fd_epoch_slot0( &bank->f.epoch_schedule, bank->f.epoch );

#else

  /* Max activation slot <= bank_slot.  Signed so DISABLED (ULONG_MAX) reads as
     -1 and loses the max, and so this vectorizes: vpmaxsq has no unsigned form. */
  long const * f     = (long const *)features->f;
  long         limit = (long)bank->f.slot;
  long         acc   = 0L;
  for( ulong i=0UL; i<FD_FEATURE_ID_CNT; i++ ) {
    long s = f[ i ];
    long v = (s<=limit) ? s : 0L; /* a not-yet-active feature must not win */
    acc = v>acc ? v : acc;
  }
  feature_slot = (ulong)acc;

#endif

  *env = (fd_prog_load_env_t) {
    .features     = features,
    .feature_slot = feature_slot
  };
  return env;
}
