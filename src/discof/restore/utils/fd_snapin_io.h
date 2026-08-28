#ifndef HEADER_fd_src_discof_restore_utils_fd_snapin_io_h
#define HEADER_fd_src_discof_restore_utils_fd_snapin_io_h

/* fd_snapin_io defines the shared-memory coordination state between
   the N symmetric fused parse+insert+write snapin tiles of the
   tar-boundary-sharded snapshot-load topology.  There is no
   coordinator and no message-passing protocol between the tiles: every
   tile independently reassembles the decompressed stream from all
   snapdc lanes, walks the tar entry headers, and parses+inserts only
   the appendvecs it claims from the shared `next_appendvec` counter.
   All controls (INIT/FINI/...) ride the data lanes as barriers, exactly
   as in the sequential loader, and every tile acks them to snapct on
   its own snapin_ct link.

   The "snapio_snoop" topology object holds:

     - the striped spin locks serializing accdb hash-chain access
       across the parallel writers;

     - the attempt slot, published by tile 0 at its INIT barrier (after
       its attempt-scoped accdb work: reset+attach for a full load,
       attach_child+doomed-partition release for an incremental one).
       Every tile gates its first insert of the attempt on it, because
       nothing else orders tile 0's INIT-time accdb work against another
       tile's first insert: snapct does not gate DATA on INIT acks.  The
       gate is non-blocking -- a tile holds its data lanes until the slot
       carries its generation, so an attempt whose INIT barrier was
       aborted on tile 0 still drains and retries.  The accdb fork id for
       the attempt rides the slot;

     - `next_appendvec`, the eager-claim counter every tile
       fetch-and-adds to pick the appendvecs it owns (no static
       ownership rule, no load-balancing pass);

     - `totals`, the cross-tile account/byte accumulator each tile
       folds its FINI counters into directly (no per-tile staging left
       to gather: tile 0 reads `totals` straight at the NEXT/DONE
       barrier, once all FINI acks -- and therefore all folds -- have
       completed);

     - winner-gated snoop targets (the SlotHistory sysvar capture and
       the feature-gate snoop block) that every tile updates in place
       as it streams past the relevant accounts, replacing the old
       per-tile staging + end-of-load k-way merge: whichever tile last
       wins the account's stripe lock in the accdb writer also wins the
       snoop target, so there is exactly one copy to read at DONE, not
       N to merge;

     - the fail_partitions list each tile stamps before its FAIL ack,
       which tile 0 gathers during its deferred rollback at the retry's
       INIT barrier (snapct gates the retry INIT on all FAIL acks, so
       every tile has provably quiesced by then). */

#include "fd_ssctrl.h"
#include "../../../flamenco/features/fd_feature_snoop.h"
#include "../../../flamenco/runtime/sysvar/fd_sysvar_base.h"

/* Maximum number of snapdc lanes a snapin tile tracks. */

#define FD_SNAPIN_IO_LANE_MAX    (16UL)

/* Shared staging object ("snapio_snoop" topo obj) ******************/

/* Striped spin locks serializing accdb hash-chain access across the
   parallel writers (stripe = chain_idx & FD_SNAPIO_STRIPE_MSK).  The
   stripe count was swept on mainnet at 8 workers (1.16B lock
   acquisitions per load): 2^12 stripes measured 0.4% spins/lock, and
   wall time stays flat all the way down to 2^10 stripes, so 2^12
   leaves a wide margin at negligible cost.  2^12 stripes = 16 KiB. */

#define FD_SNAPIO_STRIPE_CNT (1UL<<12)
#define FD_SNAPIO_STRIPE_MSK (FD_SNAPIO_STRIPE_CNT-1UL)

/* Maximum accdb partitions one tile can acquire across one attempt.
   Sized to the accdb partition pool (8192 in both validator
   topologies), so it cannot overflow; the write head tracker crashes
   with a clear message if it ever would. */

#define FD_SNAPIO_FAIL_PARTITION_MAX (8192UL)

/* fd_snapio_totals_t is the cross-tile end-of-attempt accumulator.
   Every tile FD_ATOMIC_FETCH_AND_ADDs its FINI-time local counters
   directly into these fields (holding no per-tile copy afterwards),
   so by the time snapct has gated NEXT/DONE on all FINI acks, `totals`
   already holds the fold -- tile 0 just reads it, it does not compute
   it. */

struct __attribute__((aligned(64))) fd_snapio_totals {
  ulong accounts_loaded;
  ulong accounts_replaced;
  ulong accounts_ignored;
  ulong input_lamports;
  ulong replaced_lamports;
  ulong ignored_lamports;
  ulong bytes_written;
  ulong eq_slot_dups;
  ulong eq_slot_lamports_diff;
  ulong appendvecs_processed;
};

typedef struct fd_snapio_totals fd_snapio_totals_t;

/* fd_snapio_worker_t is a tile's end-of-attempt fail-partition
   staging: the accdb partitions it acquired during the current
   attempt, published (cnt stamped, fence, FAIL ack) when the attempt
   fails.  Tile 0 gathers the lists during its deferred rollback at the
   retry's INIT barrier and releases them back to the partition pool
   once the index purge has completed (a failed FULL attempt instead
   releases everything via fd_accdb_reset at the retry's INIT_FULL).
   Only the owning tile stamps and only tile 0 clears (at gather time):
   a tile zeroing its own list at INIT would race tile 0's gather,
   since INIT barriers complete in arbitrary tile order. */

struct __attribute__((aligned(64))) fd_snapio_worker {
  ulong fail_partition_cnt;
  uint  fail_partitions[ FD_SNAPIO_FAIL_PARTITION_MAX ];
};

typedef struct fd_snapio_worker fd_snapio_worker_t;

/* The attempt slot: {generation, fork_id}, published (with a fence) by
   tile 0 in its INIT barrier handler once its attempt-scoped accdb
   work is complete.  Every tile (including tile 0) requires
   attempt.generation==own generation before its writer_begin, caching
   the fork id: USHORT_MAX during a full load, the incremental fork id
   during an incremental one.  The wait is a non-blocking hold on the
   tile's data lanes, not a spin inside a frag handler, so control frags
   stay deliverable while it holds.  Deadlock-free: a gating tile has, by
   per-lane in-order consumption, already consumed INIT on all its lanes,
   so every snapdc already published its INIT copy and tile 0 needs
   nothing from the gating tile to complete its own INIT barrier and
   publish the slot.  The generation (rather than a flag) is what is
   compared, so a slot left behind by an earlier attempt -- including one
   whose INIT barrier tile 0 never completed -- cannot release the gate
   early. */

struct fd_snapio_snoop_hdr {
  ulong magic;
  ulong worker_cnt;

  struct __attribute__((aligned(64))) {
    ulong generation;
    ulong fork_id;
  } attempt;

  /* next_appendvec: the eager-claim counter.  Every tile
     FD_ATOMIC_FETCH_AND_ADDs it once when its attempt-slot gate opens
     (before parsing anything, so its walk position is still 0)
     to pick up its first appendvec, and again every time it starts
     parsing the appendvec it currently holds a claim for, so it always
     holds exactly one unmatched claim while an attempt is in flight.
     The tar stream places appendvecs in one global increasing order
     that every tile walks identically (skipping the body bytes of
     appendvecs it does not own), and the counter hands out claims in
     that same order one at a time, so a freshly fetched claim can
     never land behind the fetching tile's walk position: the value at
     walk position P can only be dispensed once, and it is dispensed
     (and immediately consumed by the tile that drew it) no later than
     the first tile's walk reaches P.  Tile 0 re-zeroes it (along with
     `totals` and the snoop targets below) at INIT before publishing
     the attempt slot, so every attempt starts the claim sequence at 0.
     Isolated to its own 128-byte-aligned pair of cache lines: it is
     the hottest atomically-updated field here (fetch-and-added by
     every tile at every appendvec boundary), and sharing a line with
     the read-mostly attempt slot or the FINI-time-only `totals` would
     ping-pong those for no reason. */
  ulong next_appendvec __attribute__((aligned(128)));

  fd_snapio_totals_t totals;

  /* Winner-gated SlotHistory sysvar capture.  Whichever tile last
     writes (or replaces) the SlotHistory account -- i.e. whichever
     tile last wins that account's accdb stripe lock -- also owns this
     capture, so there is exactly one copy to read at DONE instead of N
     per-tile copies to merge.  Reproduces the sequential loader's
     "last write wins" semantics without the old (slot, appendvec_idx,
     record_idx) stream-position tiebreak: the accdb stripe lock is
     already the single serialization point for "which write is last",
     so no secondary positional arbitration is needed. */
  struct __attribute__((aligned(64))) {
    int   captured;
    int   executable;
    ulong slot;
    ulong lamports;
    ulong data_len;
    uchar owner[ 32UL ];
    uchar buf[ FD_SYSVAR_SLOT_HISTORY_BINCODE_SZ ];
  } slot_history;

  /* Winner-gated feature-gate snoop.  Same principle as slot_history
     above, per feature id: the tile that wins the account's stripe
     lock records that feature's activation state directly here, so the
     old per-id (appendvec_idx, record_idx) positional arrays
     (feature_av[]/feature_rec[]) used only to arbitrate between
     per-tile copies are gone -- there is only ever one copy. */
  fd_feature_snoop_t feature_snoop;
};

typedef struct fd_snapio_snoop_hdr fd_snapio_snoop_hdr_t;

#define FD_SNAPIO_SNOOP_MAGIC (0xF17EDA2C0501A910UL)

static inline ulong
fd_snapio_snoop_align( void ) {
  return 4096UL;
}

static inline ulong
fd_snapio_snoop_footprint( ulong worker_cnt ) {
  return fd_ulong_align_up( sizeof(fd_snapio_snoop_hdr_t), 4096UL )
       + fd_ulong_align_up( FD_SNAPIO_STRIPE_CNT*sizeof(int), 4096UL )
       + worker_cnt*sizeof(fd_snapio_worker_t);
}

static inline void *
fd_snapio_snoop_new( void * mem,
                     ulong  worker_cnt ) {
  fd_snapio_snoop_hdr_t * hdr = (fd_snapio_snoop_hdr_t *)mem;
  hdr->worker_cnt = worker_cnt;
  /* Workspace files can outlive a crashed or killed load, so nothing
     here may assume fresh (zeroed) shmem: a lock left held by a dead
     process would spin the next boot forever, a stale attempt
     generation could release a tile's INIT spin gate early, a stale
     next_appendvec/totals/slot_history/feature_snoop could be observed
     before this attempt's INIT re-zeroes them, and a stale
     fail_partitions list could release live partitions at a deferred
     rollback.  _new therefore explicitly zeroes every shared field
     below; tiles additionally re-zero the attempt-scoped ones
     (next_appendvec, totals, slot_history, feature_snoop) at every
     INIT, since those must start each attempt fresh, not just each
     boot. */
  hdr->attempt.generation = 0UL;
  hdr->attempt.fork_id    = 0UL;
  hdr->next_appendvec     = 0UL;
  fd_memset( &hdr->totals,       0, sizeof(fd_snapio_totals_t) );
  fd_memset( &hdr->slot_history, 0, sizeof(hdr->slot_history)  );
  fd_memset( &hdr->feature_snoop, 0, sizeof(fd_feature_snoop_t) );
  uchar * stripes = (uchar *)hdr + fd_ulong_align_up( sizeof(fd_snapio_snoop_hdr_t), 4096UL );
  fd_memset( stripes, 0, FD_SNAPIO_STRIPE_CNT*sizeof(int) );
  uchar * workers = stripes + fd_ulong_align_up( FD_SNAPIO_STRIPE_CNT*sizeof(int), 4096UL );
  for( ulong w=0UL; w<worker_cnt; w++ ) {
    fd_memset( workers + w*sizeof(fd_snapio_worker_t), 0, sizeof(fd_snapio_worker_t) );
  }
  FD_COMPILER_MFENCE();
  hdr->magic = FD_SNAPIO_SNOOP_MAGIC;
  return mem;
}

static inline fd_snapio_snoop_hdr_t *
fd_snapio_snoop_join( void * mem ) {
  fd_snapio_snoop_hdr_t * hdr = (fd_snapio_snoop_hdr_t *)mem;
  if( FD_UNLIKELY( hdr->magic!=FD_SNAPIO_SNOOP_MAGIC ) ) return NULL;
  return hdr;
}

static inline int *
fd_snapio_snoop_stripes( fd_snapio_snoop_hdr_t * hdr ) {
  return (int *)( (uchar *)hdr + fd_ulong_align_up( sizeof(fd_snapio_snoop_hdr_t), 4096UL ) );
}

static inline fd_snapio_worker_t *
fd_snapio_snoop_worker( fd_snapio_snoop_hdr_t * hdr,
                        ulong                   worker_idx ) {
  uchar * base = (uchar *)fd_snapio_snoop_stripes( hdr ) + fd_ulong_align_up( FD_SNAPIO_STRIPE_CNT*sizeof(int), 4096UL );
  return (fd_snapio_worker_t *)( base + worker_idx*sizeof(fd_snapio_worker_t) );
}

#endif /* HEADER_fd_src_discof_restore_utils_fd_snapin_io_h */
