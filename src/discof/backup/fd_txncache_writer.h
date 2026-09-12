#ifndef HEADER_fd_src_discof_backup_fd_txncache_writer_h
#define HEADER_fd_src_discof_backup_fd_txncache_writer_h

/* fd_txncache_writer serializes the rooted part of a txncache into the
   snapshots/status_cache file of a Solana snapshot (bincode
   Vec<SlotDelta>), shaped the way Agave writes it: one slot delta per
   recent rooted slot with a block, holding the transactions that
   executed in that slot, grouped by the blockhash they referenced.
   Holds txncache read locks while walking the txncache. */

#include "../../flamenco/runtime/fd_txncache.h"
#include "../../flamenco/runtime/fd_txncache_shmem.h"

/* FD_TXNCACHE_WRITER_MAX_SLOT_DELTAS is the number of slot deltas a
   status cache holds, mirroring Agave's StatusCache::max_root_entries
   (default MAX_ROOT_ENTRIES = MAX_RECENT_BLOCKHASHES = 300; the
   constant status_cache::MAX_CACHE_ENTRIES up to v3.x).  Snapshot load
   walks the SlotHistory sysvar back from the snapshot slot and requires
   a slot delta for each of the newest max_root_entries slots that has
   a block.  No shipped Agave changes it from 300; if it ever becomes
   configurable, this and FD_SLOT_DELTA_MAX_ENTRIES must follow.
   https://github.com/anza-xyz/agave/blob/v3.1.8/runtime/src/snapshot_bank_utils.rs#L609 */

#define FD_TXNCACHE_WRITER_MAX_SLOT_DELTAS (300UL)

#define FD_TXNCACHE_WRITER_MAX_BLOCKHASHES (FD_TXNCACHE_MAX_SLOT_DELTAS+1UL)

#define FD_TXNCACHE_WRITER_MAX_GROUPS (FD_TXNCACHE_WRITER_MAX_SLOT_DELTAS*FD_TXNCACHE_WRITER_MAX_BLOCKHASHES)

/* FD_TXNCACHE_WRITER_BUF_MIN is the smallest output buffer
   fd_txncache_writer_serialize accepts (fits any single record).
   Serialization emits whole records only and stops when the next one
   does not fit; the caller comes back with more room. */

#define FD_TXNCACHE_WRITER_BUF_MIN (4096UL)

#define FD_TXNCACHE_WRITER_RELOCK_THRESH (1UL<<16)

struct fd_txncache_writer_blockhash_desc {
  ulong blockcache_idx; /* blockcache pool index */
  uint  generation;     /* blockcache generation at init, detects reuse */
  uchar blockhash[ 32UL ];
  ulong txnhash_offset;
};

typedef struct fd_txncache_writer_blockhash_desc fd_txncache_writer_blockhash_desc_t;

/* A group is one non-empty (execution slot, referenced blockhash) pair
   and serializes as one wire group in one slot delta.  The dense group
   key is a position in slots[] paired with a position in
   blockhash_descs[]. */
struct fd_txncache_writer_group {
  ushort slot_i;
  ushort blockhash_i;
  uint   entry_cnt;        /* transactions in the group */
  uint   arena_entry_off;
  uint   filled_entry_cnt; /* entries copied so far in the current fill */
};

typedef struct fd_txncache_writer_group fd_txncache_writer_group_t;

typedef uchar fd_txnhash_t[ 20UL ];

struct fd_txncache_writer {
  uint              state;
  fd_txncache_t *   tc;
  ulong             snapshot_slot;
  ulong             snapshot_root_idx;
  uint              snapshot_root_generation;

  /* SlotDeltas (ascending). */
  ulong             slots[ FD_TXNCACHE_WRITER_MAX_SLOT_DELTAS ];
  ulong             slot_cnt;
  ulong             group_cnt_by_slot_i[ FD_TXNCACHE_WRITER_MAX_SLOT_DELTAS ];

  /* Referenced blockhash descriptors, oldest rooted blockcache first. */
  fd_txncache_writer_blockhash_desc_t blockhash_descs[ FD_TXNCACHE_WRITER_MAX_BLOCKHASHES ];
  ulong                               blockhash_cnt;
  ushort                              fork_id_to_slot_i[ USHORT_MAX+1UL ];

  /* Groups in wire order (slot ascending, then blockhash descriptor ascending). */
  uint                       entry_cnt_by_key[ FD_TXNCACHE_WRITER_MAX_GROUPS ];
  uint                       group_i_by_key[ FD_TXNCACHE_WRITER_MAX_GROUPS ];
  fd_txncache_writer_group_t groups[ FD_TXNCACHE_WRITER_MAX_GROUPS ];
  ulong                      group_cnt;
  ulong                      entry_cnt; /* Transactions across all groups. */

  /* Scratchpad for collecting transaction hashes in serialization
     order. */
  fd_txnhash_t * arena;
  ulong          arena_entry_cnt_max;
  ulong          batch_hi;

  /* Serialization cursor. */
  ulong             slot_i;  /* Next slot delta. */
  ulong             group_i; /* Next group. */
  ulong             entry_i; /* Next entry of the current group. */
};

typedef struct fd_txncache_writer fd_txncache_writer_t;

FD_PROTOTYPES_BEGIN

/* Returns the arena size the writer recommends for a txncache whose
   blocks hold at most max_txn_per_slot transactions.

   The writer stages transaction hashes in an arena the caller provides.
   The txncache stores transactions by referenced blockhash while the
   wire format wants them by execution slot, so the writer counts every
   group in one walk of the txncache, then fills the arena with as many
   consecutive groups as fit per further walk.  A single group that does
   not fit the arena is fatal.  Caller should use this function to size
   the arena.

   The arena must be aligned to fd_txncache_writer_arena_align(). */

FD_FN_CONST ulong
fd_txncache_writer_arena_sz( ulong max_txn_per_slot );

FD_FN_CONST ulong
fd_txncache_writer_arena_align( void );

/* fd_txncache_writer_init prepares writer to serialize the status
   cache of tc as of the rooted fork fork_id, which must be the most
   recent root.  snapshot_slot is the fork's slot.  slot_history points
   to the slot_history_sz byte bincode encoding of the SlotHistory
   sysvar in the bank's sysvar cache, which decides which slots get a
   slot delta and names each execution slot.  arena is the arena_sz byte
   staging area.

   Walks the whole txncache once to count the transactions of every
   (slot, blockhash) group, so the serialized size is known on return.

   Returns writer on success.  Returns NULL if fork_id is not the most
   recent root or if more than one rooted blockhash descriptor lacks a
   named execution slot.  Replay should not be advancing the root while
   a snapshot is in progress, so snapmk treats NULL as fatal. */

fd_txncache_writer_t *
fd_txncache_writer_init( fd_txncache_writer_t * writer,
                         fd_txncache_t *        tc,
                         fd_txncache_fork_id_t  fork_id,
                         ulong                  snapshot_slot,
                         uchar const *          slot_history,
                         ulong                  slot_history_sz,
                         void *                 arena,
                         ulong                  arena_sz );

/* fd_txncache_writer_serialized_sz returns the exact size in bytes of
   the status cache an initialized writer will produce. */

FD_FN_PURE ulong
fd_txncache_writer_serialized_sz( fd_txncache_writer_t const * writer );

/* fd_txncache_writer_serialize writes the next chunk of the status
   cache to out_buf (buf_sz>=FD_TXNCACHE_WRITER_BUF_MIN).  Returns the
   chunk size, or zero once the whole status cache was written.  May
   walk the txncache to fill the arena with the next batch of groups. */

ulong
fd_txncache_writer_serialize( fd_txncache_writer_t * writer,
                              uchar *                out_buf,
                              ulong                  buf_sz );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_backup_fd_txncache_writer_h */
