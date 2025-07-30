#ifndef HEADER_fd_src_flamenco_runtime_sysvar_fd_sysvar_slot_hashes_h
#define HEADER_fd_src_flamenco_runtime_sysvar_fd_sysvar_slot_hashes_h

/* fd_sysvar_slot_hashes.h manages the "slot hashes" sysvar account
   (address SysvarS1otHashes111111111111111111111111111).

   This sysvar contains bank hashes of previous slots. */

#include "fd_sysvar_base.h"

/* FD_SYSVAR_SLOT_HASHES_CAP is the max number of entries that the
   "slot hashes" sysvar will include.

   https://docs.rs/solana-slot-hashes/2.2.1/src/solana_slot_hashes/lib.rs.html#21 */

#define FD_SYSVAR_SLOT_HASHES_CAP (512UL)

FD_PROTOTYPES_BEGIN

/* fd_sysvar_slot_hashes_init creates a "slot hashes" sysvar account
   (overwrites an existing one). */

void
fd_sysvar_slot_hashes_init( fd_exec_slot_ctx_t * slot_ctx );

/* fd_sysvar_slot_hashes_update updates the "slot hashes" sysvar account
   at the start of a block. */

void
fd_sysvar_slot_hashes_update( fd_exec_slot_ctx_t * slot_ctx );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_sysvar_fd_sysvar_slot_hashes_h */
