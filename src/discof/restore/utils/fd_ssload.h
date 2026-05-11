#ifndef HEADER_fd_src_discof_restore_utils_fd_ssload_h
#define HEADER_fd_src_discof_restore_utils_fd_ssload_h

#include "fd_ssmsg.h"
#include "../../../flamenco//runtime/fd_blockhashes.h"

FD_PROTOTYPES_BEGIN

/* Returns 0 on success, -1 on corrupt manifest.  On failure, bank and
   associated structures are left partially mutated.  Caller must treat
   failure as unrecoverable (e.g. abort or discard the bank). */
int
fd_ssload_recover( fd_snapshot_manifest_t * manifest,
                   fd_banks_t *             banks,
                   fd_bank_t *              bank,
                   int                      is_incremental );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_restore_utils_fd_ssload_h */
