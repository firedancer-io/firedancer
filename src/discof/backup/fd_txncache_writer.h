#ifndef HEADER_fd_src_discof_backup_fd_txncache_writer_h
#define HEADER_fd_src_discof_backup_fd_txncache_writer_h

#include "../../flamenco/runtime/fd_txncache.h"
#include "../../flamenco/runtime/sysvar/fd_sysvar_slot_history.h"

#define FD_TXNCACHE_WRITER_MAX_GROUPS      (256UL)
#define FD_TXNCACHE_WRITER_MAX_SLOT_DELTAS (300UL)

struct fd_txncache_writer_group {
  fd_txncache_fork_id_t blockhash_fork_id;
  uchar                 blockhash[ 32UL ];
  ulong                 txnhash_offset;
  ulong                 txn_cnt;
};
typedef struct fd_txncache_writer_group fd_txncache_writer_group_t;

struct fd_txncache_writer {
  uint            state;
  fd_txncache_t * tc;
  ulong           slot;
  ulong           slot_cnt;
  ulong           slot_idx;
  ulong           group_cnt;
  ulong           group_idx;
  ulong           txn_idx;
  int             txn_iter_active;

  ulong slot_delta[ FD_TXNCACHE_WRITER_MAX_SLOT_DELTAS ];
  fd_txncache_writer_group_t group[ FD_TXNCACHE_WRITER_MAX_GROUPS ];
  fd_txncache_iter_t txn_iter[1];
};

typedef struct fd_txncache_writer fd_txncache_writer_t;

FD_PROTOTYPES_BEGIN

/* fd_txncache_writer_init creates a new txncache (SlotDeltas) writer.
   Assumes the following:
   - slot is a rooted slot
   - the txncache contents for all slots <= given slot won't change
   - txncache root does not advance while writer is active */

fd_txncache_writer_t *
fd_txncache_writer_init( fd_txncache_writer_t *         writer,
                         fd_txncache_t *                tc,
                         ulong                          slot,
                         fd_slot_history_view_t const * slot_history );

#define FD_TXNCACHE_WRITER_BUF_MIN (32UL<<20)

ulong
fd_txncache_writer_serialize( fd_txncache_writer_t * enc,
                              uchar                  out_buf[ FD_TXNCACHE_WRITER_BUF_MIN ],
                              ulong                  buf_sz );

ulong
fd_txncache_writer_serialized_sz( fd_txncache_writer_t const * writer );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_backup_fd_txncache_writer_h */
