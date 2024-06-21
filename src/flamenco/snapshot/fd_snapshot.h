#ifndef HEADER_fd_src_flamenco_snapshot_fd_snapshot_h
#define HEADER_fd_src_flamenco_snapshot_fd_snapshot_h

/* fd_snapshot.h provides high-level blocking APIs for Solana snapshots. */

#include "../fd_flamenco_base.h"

#define FD_SNAPSHOT_TYPE_UNSPECIFIED 0
#define FD_SNAPSHOT_TYPE_FULL        1
#define FD_SNAPSHOT_TYPE_INCREMENTAL 2

struct fd_snapshot_name {
  int       type;
  ulong     slot;
  ulong     incremental_slot;
  fd_hash_t fhash;
  char      file_ext[ 16 ];
};

typedef struct fd_snapshot_name fd_snapshot_name_t;

FD_PROTOTYPES_BEGIN

fd_snapshot_name_t *
fd_snapshot_name_from_cstr( fd_snapshot_name_t * id,
                            char const *         cstr,
                            ulong                base_slot );

fd_snapshot_name_t *
fd_snapshot_name_from_buf( fd_snapshot_name_t * id,
                           char const *         str,
                           ulong                str_len,
                           ulong                base_slot );

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
fd_snapshot_load( const char *         source_cstr,
                  fd_exec_slot_ctx_t * slot_ctx,
                  uint                 verify_hash,
                  uint                 check_hash,
                  int                  snapshot_type );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_snapshot_fd_snapshot_h */
