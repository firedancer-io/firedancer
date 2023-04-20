#include "fd_sysvar_stake_history.h"
#include "../fd_types.h"
#include "fd_sysvar.h"

void write_stake_history( fd_global_ctx_t* global, fd_stake_history_t* stake_history ) {
  /* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/sysvar/stake_history.rs#L12 */
  ulong min_size = 16392;
  
  ulong          sz = fd_ulong_max( min_size, fd_stake_history_size( stake_history ) );
  unsigned char *enc = fd_alloca( 1, sz );
  memset( enc, 0, sz );
  void const *ptr = (void const *) enc;
  fd_stake_history_encode( stake_history, &ptr );

  fd_sysvar_set( global, global->sysvar_owner, global->sysvar_stake_history, enc, sz, global->bank.solana_bank.slot );
}

void fd_sysvar_stake_history_read( fd_global_ctx_t* global, fd_stake_history_t* result ) {
  fd_account_meta_t metadata;
  int               read_result = fd_acc_mgr_get_metadata( global->acc_mgr, global->funk_txn, (fd_pubkey_t *) global->sysvar_stake_history, &metadata );
  if ( read_result != FD_ACC_MGR_SUCCESS ) {
    FD_LOG_NOTICE(( "failed to read account metadata: %d", read_result ));
    return;
  }

  unsigned char *raw_acc_data = fd_alloca( 1, metadata.dlen );
  read_result = fd_acc_mgr_get_account_data( global->acc_mgr, global->funk_txn, (fd_pubkey_t *) global->sysvar_stake_history, raw_acc_data, metadata.hlen, metadata.dlen );
  if ( read_result != FD_ACC_MGR_SUCCESS ) {
    FD_LOG_NOTICE(( "failed to read account data: %d", read_result ));
    return;
  }

  void* input = (void *)raw_acc_data;
  fd_stake_history_decode( result, (const void **)&input, raw_acc_data + metadata.dlen, global->allocf, global->allocf_arg );
}

void fd_sysvar_stake_history_init( fd_global_ctx_t* global ) {
  fd_stake_history_t stake_history;
  memset( &stake_history, 0, sizeof(fd_stake_history_t) );
  write_stake_history( global, &stake_history );
}
