#ifndef HEADER_fd_src_discof_backup_fd_txncache_writer_h
#define HEADER_fd_src_discof_backup_fd_txncache_writer_h

#include "../../flamenco/runtime/fd_txncache.h"

struct fd_txnhash_20 { uchar b[20]; };
typedef struct fd_txnhash_20 fd_txnhash_20_t;

struct fd_txncache_writer {
  uint              state;
  fd_txncache_t *   tc;
  ulong             slot;
  ulong             snapshot_root_idx;

  ulong             root_iter;
  ulong             page_idx;
  ulong             txn_idx;
  ulong             txns_in_page;
};

typedef struct fd_txncache_writer fd_txncache_writer_t;

FD_PROTOTYPES_BEGIN

fd_txncache_writer_t *
fd_txncache_writer_init( fd_txncache_writer_t * writer,
                         fd_txncache_t *        tc,
                         ulong                  slot );

#define FD_TXNCACHE_WRITER_BUF_MIN (32UL<<20)

ulong
fd_txncache_writer_serialize( fd_txncache_writer_t * enc,
                              uchar                  out_buf[ FD_TXNCACHE_WRITER_BUF_MIN ],
                              ulong                  buf_sz );

ulong
fd_txncache_writer_serialized_sz( fd_txncache_t * tc,
                                  ulong           slot );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_backup_fd_txncache_writer_h */
