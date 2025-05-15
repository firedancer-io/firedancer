#include "fd_bank_abi.h"
#include "../../flamenco/runtime/fd_runtime.h"
#include "../../flamenco/runtime/sysvar/fd_sysvar_slot_hashes.h"

int
fd_bank_abi_resolve_address_lookup_tables( fd_bank_shim_ctx_t const *     ctx,
                                           int                            fixed_root  FD_PARAM_UNUSED,
                                           ulong                          slot,
                                           fd_txn_t const *               txn,
                                           uchar const *                  payload,
                                           fd_acct_addr_t *               out_lut_accts ) {
  /* minimal slot_ctx for sysvar read (from funk root) */
  fd_exec_slot_ctx_t slot_ctx = {
    .funk = ctx->funk,
    .funk_txn = NULL, /* query funk root */
  };

  /* Lookup sysvar_slot_hashes */
  fd_slot_hashes_global_t const * slot_hashes_global = fd_sysvar_slot_hashes_read( &slot_ctx,
                                                                                   ctx->spad );
  if( FD_UNLIKELY( !slot_hashes_global ) ) {
    FD_LOG_ERR(( "failed to get slot hashes global" ));
  }

  fd_slot_hash_t * slot_hash = NULL;
  fd_sysvar_slot_hashes_join( (void *)slot_hashes_global, &slot_hash );

  int err = fd_runtime_load_txn_address_lookup_tables( txn,
                                                       payload,
                                                       ctx->funk,
                                                       NULL, /* query funk root */
                                                       slot,
                                                       slot_hash,
                                                       out_lut_accts );
  if( FD_UNLIKELY( err != FD_RUNTIME_EXECUTE_SUCCESS ) ) {  
    FD_LOG_WARNING(( "failed to load txn address lookup tables" ));
    return err;
  }

  return 0;
}

void fd_ext_bank_release( void const * bank  FD_PARAM_UNUSED) {
  FD_LOG_ERR(("nope"));
}

int
fd_ext_admin_rpc_set_identity( uchar const * identity_keypair FD_PARAM_UNUSED,
                               int           require_tower FD_PARAM_UNUSED) {
  FD_LOG_ERR(("nope"));
  return 0;
}

void
fd_ext_bank_acquire( void const * bank FD_PARAM_UNUSED) {
  FD_LOG_ERR(("nope"));
}

int
fd_ext_bank_load_account( void const *  bank FD_PARAM_UNUSED,
                          int           fixed_root FD_PARAM_UNUSED,
                          uchar const * addr FD_PARAM_UNUSED,
                          uchar *       owner FD_PARAM_UNUSED,
                          uchar *       data FD_PARAM_UNUSED,
                          ulong *       data_sz FD_PARAM_UNUSED) {
  FD_LOG_ERR(("nope"));
  return 0;
}

void
fd_ext_poh_register_tick( void const * bank FD_PARAM_UNUSED, uchar const * hash FD_PARAM_UNUSED) {
  FD_LOG_ERR(("nope"));
}

void
fd_ext_poh_signal_leader_change( void * sender FD_PARAM_UNUSED) {
  FD_LOG_ERR(("nope"));
}
