#include "fd_sysvar_rent.h"
#include "fd_sysvar.h"
#include "../fd_acc_mgr.h"
#include "../fd_system_ids.h"

#include <assert.h>

void
fd_sysvar_rent_write( fd_bank_t *               bank,
                      fd_funk_t *               funk,
                      fd_funk_txn_xid_t const * xid,
                      fd_capture_ctx_t *        capture_ctx,
                      fd_rent_t const *         rent ) {

  uchar enc[ 32 ];

  ulong sz = fd_rent_size( rent );
  FD_TEST( sz<=sizeof(enc) );
  memset( enc, 0, sz );

  fd_bincode_encode_ctx_t ctx;
  ctx.data    = enc;
  ctx.dataend = enc + sz;
  if( fd_rent_encode( rent, &ctx ) )
    FD_LOG_ERR(("fd_rent_encode failed"));

  fd_sysvar_account_update( bank, funk, xid, capture_ctx, &fd_sysvar_rent_id, enc, sz );
}

void
fd_sysvar_rent_init( fd_bank_t *               bank,
                     fd_funk_t *               funk,
                     fd_funk_txn_xid_t const * xid,
                     fd_capture_ctx_t *        capture_ctx ) {
  fd_rent_t const * rent = fd_bank_rent_query( bank );
  fd_sysvar_rent_write( bank, funk, xid, capture_ctx, rent );
}

fd_rent_t const *
fd_sysvar_rent_read( fd_funk_t *               funk,
                     fd_funk_txn_xid_t const * xid,
                     fd_spad_t *               spad ) {
  fd_txn_account_t acc[1];
  int rc = fd_txn_account_init_from_funk_readonly( acc, &fd_sysvar_rent_id, funk, xid );
  if( FD_UNLIKELY( rc!=FD_ACC_MGR_SUCCESS ) ) {
    return NULL;
  }

  /* This check is needed as a quirk of the fuzzer. If a sysvar account
     exists in the accounts database, but doesn't have any lamports,
     this means that the account does not exist. This wouldn't happen
     in a real execution environment. */
  if( FD_UNLIKELY( fd_txn_account_get_lamports( acc )==0UL ) ) {
    return NULL;
  }

  int err;
  return fd_bincode_decode_spad(
      rent, spad,
      fd_txn_account_get_data( acc ),
      fd_txn_account_get_data_len( acc ),
      &err );
}
