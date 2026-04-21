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
