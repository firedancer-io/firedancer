#ifndef HEADER_fd_src_flamenco_runtime_sysvar_fd_sysvar_recent_hashes_h
#define HEADER_fd_src_flamenco_runtime_sysvar_fd_sysvar_recent_hashes_h

/* fd_sysvar_recent_hashes.h manages the "recent block hashes" sysvar
   account (address SysvarRecentB1ockHashes11111111111111111111).  */

#include "../fd_bank.h"

/* FD_SYSVAR_RECENT_HASHES_CAP is the max number of block hash entries
   the recent blockhashes sysvar will include.

   https://github.com/anza-xyz/agave/blob/6398ddf6ab8a8f81017bf675ab315a70067f0bf0/sdk/program/src/sysvar/recent_blockhashes.rs#L32
*/

#define FD_SYSVAR_RECENT_HASHES_CAP (150UL)

FD_PROTOTYPES_BEGIN

/* Initialize the recent hashes sysvar account. */

void
fd_sysvar_recent_hashes_init( fd_bank_t *        bank,
                              fd_accdb_t *       accdb,
                              fd_capture_ctx_t * capture_ctx );

/* Update the recent hashes sysvar account. This should be called at the
   start of every slot, before execution commences. */

void
fd_sysvar_recent_hashes_update( fd_bank_t *        bank,
                                fd_accdb_t *       accdb,
                                fd_capture_ctx_t * capture_ctx );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_sysvar_fd_sysvar_recent_hashes_h */
