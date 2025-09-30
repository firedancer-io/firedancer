#ifndef HEADER_fd_src_discof_restore_utils_fd_ssload_h
#define HEADER_fd_src_discof_restore_utils_fd_ssload_h

#include "fd_ssmsg.h"
#include "../../../flamenco//runtime/fd_blockhashes.h"

FD_PROTOTYPES_BEGIN

void
blockhashes_recover( fd_blockhashes_t *                       blockhashes,
                     fd_snapshot_manifest_blockhash_t const * ages,
                     ulong                                    age_cnt,
                     ulong                                    seed );

void
fd_ssload_recover( fd_snapshot_manifest_t * manifest,
                   fd_banks_t *             banks,
                   fd_bank_t *              bank );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_restore_utils_fd_ssload_h */
