#ifndef HEADER_fd_src_flamenco_runtime_sysvar_fd_sysvar_recent_hashes_h
#define HEADER_fd_src_flamenco_runtime_sysvar_fd_sysvar_recent_hashes_h

/* fd_sysvar_recent_hashes.h manages the "recent block hashes" sysvar
   account (address SysvarRecentB1ockHashes11111111111111111111).  */

#include "../../fd_flamenco_base.h"

/* FD_SYSVAR_RECENT_HASHES_CAP is the max number of block hash entries
   the recent blockhashes sysvar will include.

   https://github.com/anza-xyz/solana-sdk/blob/slot-history%40v2.2.1/sysvar/src/recent_blockhashes.rs#L37 */

#define FD_SYSVAR_RECENT_HASHES_CAP (150UL)

/* FD_SYSVAR_RECENT_HASHES_BINCODE_SZ is the serialized size of the
   recent block hashes sysvar account.  (static/hardcoded)

   Agave v2.2.1: https://github.com/anza-xyz/solana-sdk/blob/slot-history%40v2.2.1/sysvar/src/recent_blockhashes.rs#L157 */

#define FD_SYSVAR_RECENT_HASHES_BINCODE_SZ (6008UL)

#define FD_SYSVAR_RECENT_HASHES_OBJ_SZ \
  FD_LAYOUT_FINI( FD_LAYOUT_APPEND( FD_LAYOUT_APPEND( FD_LAYOUT_APPEND( FD_LAYOUT_APPEND( \
  FD_LAYOUT_APPEND( FD_LAYOUT_INIT, \
      alignof(fd_block_hash_queue_global_t), sizeof(fd_block_hash_queue_global_t) ) \
      alignof(ulong),                        sizeof(ulong) ) \
      FD_HASH_ALIGN,                         sizeof(fd_hash_t) ) \
      fd_hash_hash_age_pair_t_map_align(),   fd_hash_hash_age_pair_t_map_footprint( 400 ) ) \
      alignof(ulong),                        sizeof(ulong) ), \
      128UL )

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

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_sysvar_fd_sysvar_recent_hashes_h */
