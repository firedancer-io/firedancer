#ifndef HEADER_fd_src_flamenco_runtime_sysvar_fd_sysvar_slot_hashes_h
#define HEADER_fd_src_flamenco_runtime_sysvar_fd_sysvar_slot_hashes_h

#include "fd_sysvar_base.h"
#include "../fd_bank.h"

FD_PROTOTYPES_BEGIN

void
fd_sysvar_slot_hashes_init( fd_bank_t *               bank,
                            fd_accdb_user_t *         accdb,
                            fd_funk_txn_xid_t const * xid,
                            fd_capture_ctx_t *        capture_ctx );

void
fd_sysvar_slot_hashes_update( fd_bank_t *               bank,
                              fd_accdb_user_t *         accdb,
                              fd_funk_txn_xid_t const * xid,
                              fd_capture_ctx_t *        capture_ctx );

int
fd_sysvar_slot_hashes_validate( uchar const * data,
                                ulong         sz );

fd_slot_hashes_t *
fd_sysvar_slot_hashes_view( fd_slot_hashes_t * view,
                            uchar const *      data,
                            ulong              sz );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_sysvar_fd_sysvar_slot_hashes_h */
