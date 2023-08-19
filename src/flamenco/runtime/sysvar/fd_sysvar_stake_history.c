#include "fd_sysvar_stake_history.h"
#include "../../../flamenco/types/fd_types.h"
#include "fd_sysvar.h"

void write_stake_history( fd_global_ctx_t* global, fd_stake_history_t* stake_history ) {
  /* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/sysvar/stake_history.rs#L12 */
  ulong min_size = 16392;

  ulong          sz = fd_ulong_max( min_size, fd_stake_history_size( stake_history ) );
  unsigned char *enc = fd_alloca( 1, sz );
  memset( enc, 0, sz );
  fd_bincode_encode_ctx_t ctx;
  ctx.data = enc;
  ctx.dataend = enc + sz;
  if ( fd_stake_history_encode( stake_history, &ctx ) )
    FD_LOG_ERR(("fd_stake_history_encode failed"));

  fd_sysvar_set( global, global->sysvar_owner, (fd_pubkey_t *) global->sysvar_stake_history, enc, sz, global->bank.slot );
}

int fd_sysvar_stake_history_read( fd_global_ctx_t* global, fd_stake_history_t* result ) {
  int          acc_view_err = 0;
  char const * raw_acc_data = fd_acc_mgr_view_raw( global->acc_mgr, global->funk_txn, (fd_pubkey_t *) global->sysvar_stake_history, NULL, &acc_view_err );
  fd_account_meta_t const * metadata = (fd_account_meta_t const *)raw_acc_data;

  fd_bincode_decode_ctx_t ctx;
  ctx.data = raw_acc_data + metadata->hlen;
  ctx.dataend = (char *) ctx.data + metadata->dlen;
  ctx.valloc  = global->valloc;
  if ( fd_stake_history_decode( result, &ctx ) )
    FD_LOG_ERR(("fd_stake_history_decode failed"));
  return 0;
}

void fd_sysvar_stake_history_init( fd_global_ctx_t* global ) {
  fd_stake_history_t stake_history;
  memset( &stake_history, 0, sizeof(fd_stake_history_t) );
  write_stake_history( global, &stake_history );
}
