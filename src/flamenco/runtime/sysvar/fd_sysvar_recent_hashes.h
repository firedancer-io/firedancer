#ifndef HEADER_fd_src_flamenco_runtime_sysvar_fd_sysvar_recent_hashes_h
#define HEADER_fd_src_flamenco_runtime_sysvar_fd_sysvar_recent_hashes_h

/* fd_sysvar_recent_hashes.h manages the "recent block hashes" sysvar
   account (address SysvarRecentB1ockHashes11111111111111111111).  */

#include "fd_sysvar_base.h"
#include "../fd_blockhashes.h"

/* FD_SYSVAR_RECENT_HASHES_CAP is the max number of block hash entries
   the recent blockhashes sysvar will include.

   https://github.com/anza-xyz/solana-sdk/blob/slot-history%40v2.2.1/sysvar/src/recent_blockhashes.rs#L37 */

#define FD_SYSVAR_RECENT_HASHES_CAP (150UL)

FD_PROTOTYPES_BEGIN

/* fd_sysvar_recent_hashes_init sets the "recent block hashes" sysvar
   account to an empty vector.  This is used to initialize the runtime
   from genesis (FIXME Agave reference). */

void
fd_sysvar_recent_hashes_init( fd_exec_slot_ctx_t * slot_ctx );

/* fd_sysvar_recent_hashes_update appends an entry to the bank's block
   hash queue, and the "recent block hashes" sysvar account.  Called
   during the slot boundary (at the start of a slot). */

void
fd_sysvar_recent_hashes_update( fd_exec_slot_ctx_t * slot_ctx );

void
fd_sysvar_recent_hashes_encode( fd_blockhashes_t const * bhq,
                                uchar                    out_mem[ FD_SYSVAR_RECENT_HASHES_BINCODE_SZ ] );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_sysvar_fd_sysvar_recent_hashes_h */
