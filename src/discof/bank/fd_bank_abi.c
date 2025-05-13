#include "fd_bank_abi.h"

int
fd_bank_abi_resolve_address_lookup_tables( void const *     bank FD_PARAM_UNUSED,
                                           int              fixed_root  FD_PARAM_UNUSED,
                                           ulong            slot  FD_PARAM_UNUSED,
                                           fd_txn_t const * txn  FD_PARAM_UNUSED,
                                           uchar const *    payload  FD_PARAM_UNUSED,
                                           fd_acct_addr_t * out_lut_accts  FD_PARAM_UNUSED) {


#if 0

  // reference code to start with

  /* Only resolve for V0 transaction versions */
  if( txn_descriptor->transaction_version == FD_TXN_V0 ) {
    fd_txn_acct_addr_lut_t const * addr_luts = fd_txn_get_address_tables_const( txn_descriptor );
    for( ulong i = 0UL; i < txn_descriptor->addr_table_lookup_cnt; i++ ) {
      fd_txn_acct_addr_lut_t const * addr_lut  = &addr_luts[i];

      fd_pubkey_t * addr_lut_acc = (fd_pubkey_t *)((uchar *)txn_raw.raw + addr_lut->addr_off);
      /* TODO: WRITE OUT RESOLVED PUBKEY */
    }

    /* Look up the pubkeys from the ALTs */
    fd_slot_hashes_global_t const * slot_hashes_global = fd_sysvar_cache_slot_hashes(
      ctx->slot_ctx->sysvar_cache, ctx->runtime_public_wksp );
    if( FD_UNLIKELY( !slot_hashes_global ) ) {
      FD_LOG_ERR(( "failed to get slot hashes global" ));
    }
    fd_slot_hash_t * slot_hash = deq_fd_slot_hash_t_join( (uchar *)slot_hashes_global + slot_hashes_global->hashes_offset );
    fd_acct_addr_t * accts_alt = fd_spad_alloc(
      ctx->runtime_spad, alignof(fd_acct_addr_t), sizeof(fd_acct_addr_t) * txn_descriptor->addr_table_adtl_cnt );
    int err = fd_runtime_load_txn_address_lookup_tables( txn_descriptor,
      txn_raw.raw,
      ctx->funk,
      ctx->slot_ctx->funk_txn,
      ctx->curr_slot,
      slot_hash,
      accts_alt);
    if( FD_UNLIKELY( err != FD_RUNTIME_EXECUTE_SUCCESS ) ) {
      FD_LOG_WARNING(( "failed to load txn address lookup tables" ));
    }

    for( ulong i = 0UL; i < txn_descriptor->addr_table_lookup_cnt; i++ ) {
      fd_pubkey_t * pubkey = fd_type_pun( &accts_alt[i] );
      /* TODO: WRITE OUT RESOLVED PUBKEY */
    }
  }
} FD_SPAD_FRAME_END;

#endif

  FD_LOG_ERR(("nope"));
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
