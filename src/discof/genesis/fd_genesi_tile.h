#ifndef HEADER_fd_src_discof_genesis_fd_genesi_tile_h
#define HEADER_fd_src_discof_genesis_fd_genesi_tile_h

/* The genesis tile publishes a single message type:

   A 'fd_genesis_meta_t' struct, followed by a Bincode-encoded genesis
   blob. */

#include "../../ballet/lthash/fd_lthash.h"
#include "../../flamenco/runtime/fd_genesis_parse.h"

#define FD_GENESIS_TILE_MTU (sizeof(fd_genesis_meta_t) + FD_GENESIS_MAX_MESSAGE_SIZE)

struct fd_genesis_meta {
  ulong bootstrap  : 1;
  ulong has_lthash : 1;

  fd_hash_t         genesis_hash;
  fd_lthash_value_t lthash;

  ulong blob_sz;
  /* uchar[ blob_sz ] follows immediately after this struct */
};

typedef struct fd_genesis_meta fd_genesis_meta_t;

#endif /* HEADER_fd_src_discof_genesis_fd_genesi_tile_h */
