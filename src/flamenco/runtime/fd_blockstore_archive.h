#ifndef HEADER_fd_src_flamenco_runtime_fd_blockstore_archive_h
#define HEADER_fd_src_flamenco_runtime_fd_blockstore_archive_h

#include "fd_blockstore.h"
#include "fd_rocksdb.h"

/* fd_blockstore_ser is a serialization context for archiving a block to
   disk. We can remove the rocksdb include once we change the fd_block_t
   serialization member. */
struct fd_blockstore_ser {
  fd_block_info_t * block_map;
  fd_block_t      * block;
  uchar           * data;
};
typedef struct fd_blockstore_ser fd_blockstore_ser_t;

/* Archives a block and block map entry to fd at blockstore->off, and does
   any necessary bookkeeping.
   If fd is -1, no write is attempted. Returns written size */
ulong
fd_blockstore_block_checkpt( fd_blockstore_t * blockstore,
                             fd_blockstore_ser_t * ser,
                             int fd,
                             ulong slot );

/* Restores a block and block map entry from fd at given offset. As this used by
   rpcserver, it must return an error code instead of throwing an error on failure. */
int
fd_blockstore_block_info_restore( fd_blockstore_archiver_t * archvr,
                                  int fd,
                                  fd_block_idx_t * block_idx_entry,
                                  fd_block_info_t * block_map_entry_out,
                                  fd_block_t * block_out );

/* Reads block data from fd into a given buf. Modifies data_off similarly to
   meta_restore */
int
fd_blockstore_block_data_restore( fd_blockstore_archiver_t * archvr,
                                  int fd,
                                  fd_block_idx_t * block_idx_entry,
                                  uchar * buf_out,
                                  ulong buf_max,
                                  ulong data_sz );

/* Returns 0 if the archive metadata is valid */
bool
fd_blockstore_archiver_verify( fd_blockstore_t * blockstore, fd_blockstore_archiver_t * archiver );

/* Reads from fd a block meta object, and returns the slot number */
ulong
fd_blockstore_archiver_lrw_slot( fd_blockstore_t * blockstore, int fd, fd_block_info_t * lrw_block_info, fd_block_t * lrw_block );

#endif /* HEADER_fd_src_flamenco_runtime_fd_blockstore_archive_h */
