#ifndef HEADER_fd_src_discof_backup_fd_txncache_writer_h
#define HEADER_fd_src_discof_backup_fd_txncache_writer_h

/* fd_txncache_writer serializes the rooted part of a txncache into the
   snapshots/status_cache file of a Solana snapshot (bincode
   Vec<SlotDelta>).  Holds txncache read locks while operating. */

#include "../../flamenco/runtime/fd_txncache.h"
#include "../../flamenco/runtime/fd_txncache_shmem.h"

/* FD_TXNCACHE_WRITER_MAX_SLOT_DELTAS is the number of slot deltas a
   status cache holds, mirroring Agave's
   status_cache::MAX_CACHE_ENTRIES.  Snapshot load walks the SlotHistory
   sysvar back from the snapshot slot and requires a slot delta for each
   of the newest MAX_CACHE_ENTRIES slots that has a block.
   https://github.com/anza-xyz/agave/blob/v3.1.8/runtime/src/snapshot_bank_utils.rs#L609 */

#define FD_TXNCACHE_WRITER_MAX_SLOT_DELTAS (300UL)

/* FD_TXNCACHE_WRITER_MAX_GROUPS is the most rooted blockcaches a
   txncache holds, and thus the most blockhash groups a writer emits. */

#define FD_TXNCACHE_WRITER_MAX_GROUPS FD_TXNCACHE_MAX_SLOT_DELTAS

/* FD_TXNCACHE_WRITER_BUF_MIN is the smallest output buffer
   fd_txncache_writer_serialize accepts (fits any single record).
   Transactions are emitted one hash bucket at a time; a bucket that
   does not fit the remaining buffer is retried on the next call, and a
   bucket that does not fit an empty buffer is fatal.  The caller should
   therefore offer as much room as it has (snapmk offers up to 32 MiB,
   or 1.4M transactions in one bucket of one blockcache). */

#define FD_TXNCACHE_WRITER_BUF_MIN (4096UL)

/* FD_TXNCACHE_WRITER_HOLD_MAX bounds the output produced under one
   txncache read lock hold, so replay's write lock operations are never
   blocked for long. */

#define FD_TXNCACHE_WRITER_HOLD_MAX (1UL<<20)

/* Chunk kinds returned by fd_txncache_writer_serialize.  The writer
   streams in a single pass, so bincode length prefixes that precede the
   bytes they describe are emitted as PLACEHOLDER chunks, which the
   caller must store at a position it can later overwrite in place, and
   fixed up by a PATCH chunk once the bytes have been streamed.  At most
   one placeholder is outstanding at a time. */

#define FD_TXNCACHE_WRITER_CHUNK_DATA        (1) /* append to the stream */
#define FD_TXNCACHE_WRITER_CHUNK_PLACEHOLDER (2) /* append to the stream, keep the position */
#define FD_TXNCACHE_WRITER_CHUNK_PATCH       (3) /* overwrite the last placeholder */

struct fd_txnhash_20 { uchar b[20]; };
typedef struct fd_txnhash_20 fd_txnhash_20_t;

struct fd_txncache_writer_group {
  ulong bc_idx;     /* blockcache pool index */
  uint  generation; /* blockcache generation at init, detects reuse */
};

typedef struct fd_txncache_writer_group fd_txncache_writer_group_t;

struct fd_txncache_writer {
  uint              state;
  fd_txncache_t *   tc;
  ulong             slot;
  ulong             snapshot_root_idx;
  uint              snapshot_root_generation;

  /* SlotDeltas (ascending) */
  ulong             slots[ FD_TXNCACHE_WRITER_MAX_SLOT_DELTAS ];
  ulong             slot_cnt;
  ulong             slot_idx;

  /* Blockhash groups of the snapshot slot's delta, oldest root first */
  fd_txncache_writer_group_t groups[ FD_TXNCACHE_WRITER_MAX_GROUPS ];
  ulong             group_cnt;
  ulong             group_idx;

  /* Position within the group being streamed.  Bucket granular, since
     compaction of the txncache moves transactions between pages and
     rebuilds chains but never changes which bucket a transaction hashes
     to. */
  ulong             bucket_idx;    /* next bucket to emit */
  ulong             group_emitted; /* transactions emitted so far in the group */
};

typedef struct fd_txncache_writer fd_txncache_writer_t;

FD_PROTOTYPES_BEGIN

/* fd_txncache_writer_init prepares writer to serialize the status
   cache of tc as of the rooted fork fork_id, which must be the most
   recent root.  slot is the fork's slot.  slot_history points to the
   slot_history_sz byte bincode encoding of the SlotHistory sysvar in
   the bank's sysvar cache, which decides which slots get a slot delta.

   Returns writer on success and NULL if fork_id is not the most recent
   root, in which case the txncache root moved under the snapshot and
   the snapshot cannot be produced. */

fd_txncache_writer_t *
fd_txncache_writer_init( fd_txncache_writer_t * writer,
                         fd_txncache_t *        tc,
                         fd_txncache_fork_id_t  fork_id,
                         ulong                  slot,
                         uchar const *          slot_history,
                         ulong                  slot_history_sz );

/* fd_txncache_writer_serialize writes the next chunk of the status
   cache to out_buf (buf_sz>=FD_TXNCACHE_WRITER_BUF_MIN) and sets
   *out_kind to its FD_TXNCACHE_WRITER_CHUNK_* kind.  Returns the chunk
   size, or zero once the whole status cache was written. */

ulong
fd_txncache_writer_serialize( fd_txncache_writer_t * writer,
                              uchar *                out_buf,
                              ulong                  buf_sz,
                              int *                  out_kind );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_backup_fd_txncache_writer_h */
