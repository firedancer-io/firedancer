#include "fd_sysvar_rent.h"
#include "fd_sysvar.h"
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
fd_sysvar_rent_read( fd_accdb_user_t *         accdb,
                     fd_funk_txn_xid_t const * xid,
                     fd_rent_t *               rent ) {
  fd_accdb_ro_t ro[1];
  if( FD_UNLIKELY( !fd_accdb_open_ro( accdb, ro, xid, &fd_sysvar_rent_id ) ) ) {
    return NULL;
  }

  /* This check is needed as a quirk of the fuzzer. If a sysvar account
     exists in the accounts database, but doesn't have any lamports,
     this means that the account does not exist. This wouldn't happen
     in a real execution environment. */
  if( FD_UNLIKELY( fd_accdb_ref_lamports( ro )==0UL ) ) {
    fd_accdb_close_ro( accdb, ro );
    return NULL;
  }

  rent = fd_bincode_decode_static(
      rent, rent,
      fd_accdb_ref_data_const( ro ),
      fd_accdb_ref_data_sz   ( ro ),
      NULL );
  fd_accdb_close_ro( accdb, ro );
  return rent;
}
