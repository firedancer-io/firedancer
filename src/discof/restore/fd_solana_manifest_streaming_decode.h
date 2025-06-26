#ifndef HEADER_fd_src_discof_restore_fd_solana_manifest_streaming_decode_h
#define HEADER_fd_src_discof_restore_fd_solana_manifest_streaming_decode_h
#include "../../flamenco/types/fd_types.h"
#include "fd_snapshot_messages.h"

/* fd_solana_manifest_streaming_decode.h provides APIs for stream
   decoding the Solana manifest data structure.  It is used by the
   snapshot tiles to quickly decode the manifest and obtain needed
   information. */

struct fd_snapshot_append_vec {
  ulong id;
  ulong file_sz;
};

typedef struct fd_snapshot_append_vec fd_snapshot_append_vec_t;

struct fd_snapshot_slot_entry {
  ulong                    slot;
  ulong                    append_vecs_len;
  fd_snapshot_append_vec_t append_vecs[ 8UL ]; /* TODO: Bound correctly */
};

typedef struct fd_snapshot_slot_entry fd_snapshot_slot_entry_t;

struct fd_snapshot_storages {
  ulong                    len;
  fd_snapshot_slot_entry_t entries[ 1048576 ]; /* TODO: Bound correctly */

};

typedef struct fd_snapshot_storages fd_snapshot_storages_t;

int
fd_solana_manifest_streaming_decode( uchar * buf,
                                     ulong   bufsz,
                                     fd_snapshot_storages_t * storages,
                                     fd_snapshot_manifest_t * manifest );

#endif /* HEADER_fd_src_discof_restore_fd_solana_manifest_streaming_decode_h */
