#ifndef HEADER_fd_src_discof_backup_fd_txncache_writer_h
#define HEADER_fd_src_discof_backup_fd_txncache_writer_h

#include "../../flamenco/runtime/fd_txncache.h"
#include "../../flamenco/runtime/fd_txncache_shmem.h"
#include "../../flamenco/runtime/sysvar/fd_sysvar_slot_history.h"

struct fd_txnhash_20 { uchar b[20]; };
typedef struct fd_txnhash_20 fd_txnhash_20_t;

/* A rooted blockcache is retained for at most
   FD_TXNCACHE_MAX_BLOCKHASH_DISTANCE root advances, so that is the most
   slot deltas the txncache can ever hold. */

#define FD_TXNCACHE_WRITER_MAX_ROOTS FD_TXNCACHE_MAX_SLOT_DELTAS

/* Agave keeps a status cache entry for each of the MAX_RECENT_BLOCKHASHES
   most recent rooted slots, and refuses to load a snapshot that does not
   have a slot delta for every one of them.  We only retain half that
   many, so the older ones are written out as empty slot deltas.
   https://github.com/anza-xyz/agave/blob/v3.1.8/runtime/src/snapshot_bank_utils.rs#L609 */

#define FD_TXNCACHE_WRITER_MAX_SLOT_DELTAS (300UL)

struct fd_txncache_writer {
  uint            state;
  fd_txncache_t * tc;
  ulong           snapshot_root_idx;
  ulong           serialized_sz;

  /* The rooted blockcaches, oldest first.  Each is both a slot delta
     (transactions that executed in that slot) and a blockhash group
     within every slot delta (transactions that referenced the
     blockhash that slot produced), so root[] indexes both axes of
     txn_cnt below. */

  ulong  root_cnt;
  ushort root_bc  [ FD_TXNCACHE_WRITER_MAX_ROOTS ]; /* position -> blockcache index */
  ushort root_ord [ FD_TXNCACHE_WRITER_MAX_ROOTS ]; /* positions ordered by blockcache index */
  ulong  root_slot[ FD_TXNCACHE_WRITER_MAX_ROOTS ]; /* position -> slot, ULONG_MAX if unknown */
  ulong  delta_cnt;                                 /* roots with a known slot */

  /* Rooted slots older than everything the txncache still holds, written
     out as empty slot deltas.  Ascending, and all older than the oldest
     slot in root_slot. */

  ulong empty_cnt;
  ulong empty_slot[ FD_TXNCACHE_WRITER_MAX_SLOT_DELTAS ];

  uint  txn_cnt  [ FD_TXNCACHE_WRITER_MAX_ROOTS ][ FD_TXNCACHE_WRITER_MAX_ROOTS ]; /* [executed in][referenced] */
  ulong group_cnt[ FD_TXNCACHE_WRITER_MAX_ROOTS ]; /* non-empty groups per slot delta */

  /* Encode cursor. */
  ulong empty_pos;
  ulong exec_pos;
  ulong hash_pos;
};

typedef struct fd_txncache_writer fd_txncache_writer_t;

FD_PROTOTYPES_BEGIN

/* fd_txncache_writer_init prepares writer to serialize the rooted
   contents of tc as a Solana status cache (a Vec<SlotDelta>).  It walks
   the whole cache once to tally entries per (executed in, referenced)
   pair, so fd_txncache_writer_serialized_sz is exact from here on.  The
   caller must not mutate the rooted portion of tc between this call and
   the end of serialization, or the serialized size will not match the
   bytes produced.

   slot_history is the SlotHistory sysvar of the bank being snapshotted,
   used to pad the output with empty slot deltas back to
   FD_TXNCACHE_WRITER_MAX_SLOT_DELTAS rooted slots.  It may be NULL, in
   which case only the slots the txncache still holds are written and
   Agave will refuse to load the snapshot. */

fd_txncache_writer_t *
fd_txncache_writer_init( fd_txncache_writer_t *         writer,
                         fd_txncache_t *                tc,
                         fd_slot_history_view_t const * slot_history );

/* fd_txncache_writer_serialized_sz returns the exact number of bytes
   fd_txncache_writer_serialize will produce in total. */

FD_FN_PURE ulong
fd_txncache_writer_serialized_sz( fd_txncache_writer_t const * writer );

#define FD_TXNCACHE_WRITER_BUF_MIN (32UL<<20)

/* fd_txncache_writer_serialize writes up to buf_sz bytes of the status
   cache into out_buf, returning the number of bytes written, or 0 once
   serialization is complete.  buf_sz must be at least
   FD_TXNCACHE_WRITER_BUF_MIN. */

ulong
fd_txncache_writer_serialize( fd_txncache_writer_t * writer,
                              uchar                  out_buf[ FD_TXNCACHE_WRITER_BUF_MIN ],
                              ulong                  buf_sz );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_backup_fd_txncache_writer_h */
