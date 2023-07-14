#include "fd_sysvar_rent.h"
#include "../../../flamenco/types/fd_types.h"
#include "fd_sysvar.h"

/* https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/rent.rs#L36 */
#define ACCOUNT_STORAGE_OVERHEAD ( 128 )

void write_rent( fd_global_ctx_t* global, fd_rent_t* rent ) {
  ulong          sz = fd_rent_size( rent );
  unsigned char *enc = fd_alloca( 1, sz );
  memset( enc, 0, sz );
  fd_bincode_encode_ctx_t ctx;
  ctx.data = enc;
  ctx.dataend = enc + sz;
  if ( fd_rent_encode( rent, &ctx ) )
    FD_LOG_ERR(("fd_rent_encode failed"));

  fd_sysvar_set( global, global->sysvar_owner, (fd_pubkey_t *) global->sysvar_rent, enc, sz, global->bank.slot );
}

void fd_sysvar_rent_read( fd_global_ctx_t* global, fd_rent_t* result ) {
  fd_account_meta_t metadata;
  int               read_result = fd_acc_mgr_get_metadata( global->acc_mgr, global->funk_txn, (fd_pubkey_t *) global->sysvar_rent, &metadata );
  if ( read_result != FD_ACC_MGR_SUCCESS ) {
    FD_LOG_NOTICE(( "failed to read account metadata: %d", read_result ));
    return;
  }

  unsigned char *raw_acc_data = fd_alloca( 1, metadata.dlen );
  read_result = fd_acc_mgr_get_account_data( global->acc_mgr, global->funk_txn, (fd_pubkey_t *) global->sysvar_rent, raw_acc_data, metadata.hlen, metadata.dlen );
  if ( read_result != FD_ACC_MGR_SUCCESS ) {
    FD_LOG_NOTICE(( "failed to read account data: %d", read_result ));
    return;
  }

  fd_bincode_decode_ctx_t decoder = {
    .data    = raw_acc_data,
    .dataend = raw_acc_data + metadata.dlen,
    .valloc  = global->valloc
  };
  if ( fd_rent_decode( result, &decoder ) )
    FD_LOG_ERR(("fd_rent_decode failed"));
}

void fd_sysvar_rent_init( fd_global_ctx_t* global ) {
  /* Defaults taken from https://github.com/solana-labs/solana/blob/8f2c8b8388a495d2728909e30460aa40dcc5d733/sdk/program/src/rent.rs#L22-L36 */
  /* TODO: handle non-default case */
  fd_rent_t rent;
  fd_rent_new(&rent);
  
  rent.lamports_per_uint8_year = 3480,
  rent.exemption_threshold = 2,
  rent.burn_percent = 50,

  write_rent( global, &rent );
}

/* TODO: handle update */

ulong fd_rent_exempt_minimum_balance( fd_global_ctx_t* global, ulong data_len ) {
  fd_rent_t rent;
  fd_sysvar_rent_read( global, &rent );

  /* https://github.com/solana-labs/solana/blob/792fafe0c25ac06868e3ac80a2b13f1a5b4a1ef8/sdk/program/src/rent.rs#L72 */
  return (data_len + ACCOUNT_STORAGE_OVERHEAD) * ((ulong) ((double)rent.lamports_per_uint8_year * rent.exemption_threshold));
}
