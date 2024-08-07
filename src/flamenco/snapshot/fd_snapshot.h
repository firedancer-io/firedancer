#ifndef HEADER_fd_src_flamenco_snapshot_fd_snapshot_h
#define HEADER_fd_src_flamenco_snapshot_fd_snapshot_h

#if FD_HAS_ZSTD

/* fd_snapshot.h provides high-level blocking APIs for Solana snapshots. */

#include "fd_snapshot_base.h"

FD_PROTOTYPES_BEGIN

/* fd_snapshot_load does a blocking load of a snapshot.

   source_cstr is either a local file system path (absolute or relative)
   or a HTTP URL (must start with 'http://', HTTPS not yet supported).

   slot_ctx is a valid initialized slot context (a funk, acc_mgr, heap
   valloc, zero-initialized slot bank).

   slot_ctx->valloc should have enough space to buffer the snapshot's
   manifest.

   If verify_hash!=0 calculates the snapshot hash.

   If check_hash!=0 checks that the snapshot hash matches the file name.

   snapshot_type is one of FD_SNAPSHOT_TYPE_{...}. */

void
fd_snapshot_load( const char *             source_cstr,
                  fd_exec_slot_ctx_t     * slot_ctx,
                  fd_tpool_runtime_ctx_t * tpool,
                  uint                     verify_hash,
                  uint                     check_hash,
                  int                      snapshot_type );

FD_PROTOTYPES_END

#endif /* FD_HAS_ZSTD */

#endif /* HEADER_fd_src_flamenco_snapshot_fd_snapshot_h */
