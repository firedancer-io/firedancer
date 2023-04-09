#include "fd_sysvar_fees.h"
#include "../fd_types.h"
#include "fd_sysvar.h"

void write_fees( fd_global_ctx_t* global, fd_sysvar_fees_t* fees ) {
  ulong          sz = fd_sysvar_fees_size( fees );
  unsigned char *enc = fd_alloca( 1, sz );
  memset( enc, 0, sz );
  void const *ptr = (void const *) enc;
  fd_sysvar_fees_encode( fees, &ptr );

  fd_sysvar_set( global, global->sysvar_owner, global->sysvar_fees, enc, sz, global->current_slot );
}

void fd_sysvar_fees_read( fd_global_ctx_t* global, fd_sysvar_fees_t* result ) {
  fd_account_meta_t metadata;
  int               read_result = fd_acc_mgr_get_metadata( global->acc_mgr, global->funk_txn, (fd_pubkey_t *) global->sysvar_fees, &metadata );
  if ( read_result != FD_ACC_MGR_SUCCESS ) {
    FD_LOG_NOTICE(( "failed to read account metadata: %d", read_result ));
    return;
  }

  unsigned char *raw_acc_data = fd_alloca( 1, metadata.dlen );
  read_result = fd_acc_mgr_get_account_data( global->acc_mgr, global->funk_txn, (fd_pubkey_t *) global->sysvar_fees, raw_acc_data, metadata.hlen, metadata.dlen );
  if ( read_result != FD_ACC_MGR_SUCCESS ) {
    FD_LOG_NOTICE(( "failed to read account data: %d", read_result ));
    return;
  }

  void* input = (void *)raw_acc_data;
  fd_sysvar_fees_decode( result, (const void **)&input, raw_acc_data + metadata.dlen, global->allocf, global->allocf_arg );
}

void fd_sysvar_fees_init( fd_global_ctx_t* global ) {
  /* Default taken from https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/fee_calculator.rs#L110 */
  /* TODO: handle non-default case */
  fd_sysvar_fees_t fees = {
    {
      .lamports_per_signature = 0,
    }
  };
  write_fees( global, &fees );
}
