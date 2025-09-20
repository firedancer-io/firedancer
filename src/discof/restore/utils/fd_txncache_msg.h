#ifndef HEADER_fd_src_discof_restore_utils_fd_txncache_msg_h
#define HEADER_fd_src_discof_restore_utils_fd_txncache_msg_h

#include "../../../flamenco/types/fd_types_custom.h"

struct fd_sstxncache_entry {
  ulong slot;
  uchar blockhash[ FD_HASH_FOOTPRINT ];
  uchar txnhash[ 20UL ];
  uchar result;
};
typedef struct fd_sstxncache_entry fd_sstxncache_entry_t;

struct fd_sstxncache {
  ulong                 len;
  fd_sstxncache_entry_t entries[ 1024UL*1024UL*4UL ]; /* TODO: bound */

};
typedef struct fd_sstxncache fd_sstxncache_t;

#endif /* HEADER_fd_src_discof_restore_utils_fd_txncache_msg_h */
