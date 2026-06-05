#include "fd_sysvar_rent.h"
#include "fd_sysvar.h"
#include "../fd_system_ids.h"

void
fd_sysvar_rent_write( fd_bank_t *        bank,
                      fd_accdb_t *       accdb,
                      fd_capture_ctx_t * capture_ctx,
                      fd_rent_t const *  rent ) {
  fd_sysvar_account_update( bank, accdb, capture_ctx, &fd_sysvar_rent_id, rent, FD_SYSVAR_RENT_BINCODE_SZ );
}

void
fd_sysvar_rent_init( fd_bank_t *        bank,
                     fd_accdb_t *       accdb,
                     fd_capture_ctx_t * capture_ctx ) {
  fd_sysvar_rent_write( bank, accdb, capture_ctx, &bank->f.rent );
}

fd_rent_t const *
fd_sysvar_rent_read( fd_accdb_t *       accdb,
                     fd_accdb_fork_id_t fork_id,
                     fd_rent_t *        rent ) {
  fd_acc_t acc = fd_accdb_read_one( accdb, fork_id, fd_sysvar_rent_id.uc );
  if( FD_UNLIKELY( !acc.lamports || acc.data_len<FD_SYSVAR_RENT_BINCODE_SZ ) ) {
    fd_accdb_unread_one( accdb, &acc );
    return NULL;
  }

  fd_memcpy( rent, acc.data, FD_SYSVAR_RENT_BINCODE_SZ );
  fd_accdb_unread_one( accdb, &acc );
  return rent;
}
