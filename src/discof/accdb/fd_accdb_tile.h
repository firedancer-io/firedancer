/* The accdb tile is a thread dedicated to servicing read and write
   requests for the accounts database LSM storage engine.

   The tile receives requests over a message bus (mcache) and
   dispatches them to the underlying fd_accdb_lsm layer, which
   manages a fork-aware, append-only, partitioned key-value store
   backed by a single file on NVMe.

   Only two operations are supported by the tile:

     FD_ACCDB_OP_READ  — look up an account as-of a given fork
     FD_ACCDB_OP_WRITE — persist account data on a given fork

   Fork management (attach_child, advance_root, purge) is handled
   directly on the shared shmem by the cache layer and does not
   go through this tile. */

#ifndef HEADER_fd_src_discof_accdb_fd_accdb_tile_h
#define HEADER_fd_src_discof_accdb_fd_accdb_tile_h

#include "../../util/fd_util_base.h"

#define FD_ACCDB_OP_READ  (0UL)
#define FD_ACCDB_OP_WRITE (1UL)

struct fd_accdb_read_request {
  ulong entries_cnt;
  struct {
    ulong offset;
    ulong len;

    ulong cache_size_class;
    ulong cache_idx;
  } entries[ 650UL ];
};

typedef struct fd_accdb_read_request fd_accdb_read_request_t;

struct fd_accdb_write_request {
  ulong entries_cnt;
  struct {
    ulong cache_size_class;
    ulong cache_idx;
  } entries[ 650UL ];
};

typedef struct fd_accdb_write_request fd_accdb_write_request_t;

#endif /* HEADER_fd_src_discof_accdb_fd_accdb_tile_h */
