#ifndef HEADER_fd_src_discof_genesis_fd_genesi_tile_h
#define HEADER_fd_src_discof_genesis_fd_genesi_tile_h

/* The genesis tile publishes a single message type:

   A 'fd_genesis_meta_t' struct, followed by a Bincode-encoded genesis
   blob. */

#include "../../ballet/lthash/fd_lthash.h"
#include "../../flamenco/fd_flamenco_base.h"

/* Worst case bound for a genesis TAR and bzip2's output size in MiB can
   fit in a uint (in bytes). */
#define FD_GENESIS_MAX_FILE_SIZE_MIB (4055UL)

struct fd_genesis_meta {
  ulong bootstrap  : 1;
  ulong has_lthash : 1;

  fd_hash_t         genesis_hash;
  ulong             creation_time_seconds;
  fd_lthash_value_t lthash;

  ulong blob_sz;
  /* uchar[ blob_sz ] follows immediately after this struct */
};

typedef struct fd_genesis_meta fd_genesis_meta_t;

FD_FN_CONST static inline ulong
fd_genesi_tile_mtu( ulong max_message_size ) {
  return sizeof(fd_genesis_meta_t) + max_message_size;
}

#endif /* HEADER_fd_src_discof_genesis_fd_genesi_tile_h */
