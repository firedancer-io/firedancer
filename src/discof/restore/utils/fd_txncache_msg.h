#ifndef HEADER_fd_src_discof_restore_utils_fd_txncache_msg_h
#define HEADER_fd_src_discof_restore_utils_fd_txncache_msg_h

#include "../../../flamenco/types/fd_types_custom.h"

struct fd_snapshot_txncache_entry {
  ulong slot;
  uchar blockhash[ FD_HASH_FOOTPRINT ];
  uchar txnhash[ 20UL ];
};
typedef struct fd_snapshot_txncache_entry fd_snapshot_txncache_entry_t;

#endif /* HEADER_fd_src_discof_restore_utils_fd_txncache_msg_h */
