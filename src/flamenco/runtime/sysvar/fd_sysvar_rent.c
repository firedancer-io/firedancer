#include "fd_sysvar_rent.h"
#include "fd_sysvar.h"
#include "../fd_acc_mgr.h"
#include "../fd_system_ids.h"
#include "fd_sysvar_base.h"

#include <assert.h>

void
fd_sysvar_rent_write( fd_bank_t *               bank,
                      fd_accdb_user_t *         accdb,
                      fd_funk_txn_xid_t const * xid,
                      fd_capture_ctx_t *        capture_ctx,
                      fd_rent_t const *         rent ) {

  uchar enc[ FD_SYSVAR_RENT_BINCODE_SZ ] = {0};

  fd_bincode_encode_ctx_t ctx = {
    .data    = enc,
    .dataend = enc + FD_SYSVAR_RENT_BINCODE_SZ,
  };
  if( FD_UNLIKELY( fd_rent_encode( rent, &ctx ) ) ) {
    FD_LOG_ERR(( "fd_rent_encode failed" ));
  }

  fd_sysvar_account_update( bank, accdb, xid, capture_ctx, &fd_sysvar_rent_id, enc, FD_SYSVAR_RENT_BINCODE_SZ );
}

void
fd_sysvar_rent_init( fd_bank_t *               bank,
                     fd_accdb_user_t *         accdb,
                     fd_funk_txn_xid_t const * xid,
                     fd_capture_ctx_t *        capture_ctx ) {
  fd_rent_t const * rent = fd_bank_rent_query( bank );
  fd_sysvar_rent_write( bank, accdb, xid, capture_ctx, rent );
}

fd_rent_t const *
fd_sysvar_rent_read( fd_funk_t *               funk,
                     fd_funk_txn_xid_t const * xid,
                     fd_rent_t *               rent ) {
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

  return fd_bincode_decode_static(
      rent, rent,
      fd_txn_account_get_data( acc ),
      fd_txn_account_get_data_len( acc ),
      NULL );
}
