#define _GNU_SOURCE /* sync_file_range */
#include "utils/fd_ssctrl.h"
#include "utils/fd_ssload.h"
#include "utils/fd_ssmsg.h"
#include "utils/fd_ssparse.h"
#include "utils/fd_ssmanifest_parser.h"
#include "utils/fd_slot_delta_parser.h"
#include "utils/fd_snapin_io.h"
#include "../../util/fd_hash32.h"

#include "../../disco/topo/fd_topo.h"
#include "../../disco/metrics/fd_metrics.h"
#include "../../disco/gui/fd_gui_config_parse.h"
#include "../../flamenco/runtime/fd_txncache.h"
#include "../../flamenco/runtime/fd_system_ids.h"
#include "../../flamenco/runtime/fd_hashes.h"
#include "../../flamenco/runtime/sysvar/fd_sysvar_epoch_schedule.h"
#include "../../flamenco/runtime/sysvar/fd_sysvar_slot_history.h"

#include "../../flamenco/runtime/fd_txncache.h"
#include "../../flamenco/runtime/fd_bank.h"
#include "../../flamenco/features/fd_feature_snoop.h"
#include "../../flamenco/stakes/fd_stake_types.h"
#include "../../disco/stem/fd_stem.h"
#include "../../flamenco/accdb/fd_accdb.h"
#include "../../disco/events/generated/fd_event_gen.h"

#include "generated/fd_snapin_tile_seccomp.h"

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#define NAME "snapin"

/* The snapshot loader runs as N identical fused parse+insert+write
   snapin tiles (kind_id 0..N-1).  Every tile independently reassembles
   the decompressed snapshot stream from all snapdc lanes (full reliable
   consumer, expected-frame rotation), walks the tar entry headers via
   the ssparse appendvec passthrough, and parses+inserts only the
   appendvecs it claimed from the shared `next_appendvec` counter: one
   eager claim when its attempt-slot gate opens, and the next claim taken
   as it starts parsing the appendvec it holds, so ownership follows the
   tiles' actual progress instead of a static rule.

   Non-owned appendvec bodies are skipped by pure arithmetic inside the
   passthrough parser, so a tile's frag release rate is its own scan
   position -- there is no coordinator, no job/coverage protocol and no
   returnable-frag hold.  Owned accounts are inserted through the
   striped-lock accdb writer and their packed disk records pwrite()n at
   the tile's own explicit offsets through a staging buffer.

   All controls (INIT/FINI/...) ride the data lanes as barriers exactly
   as in the sequential loader, and every tile acks them to snapct on
   its own snapin_ct link (snapct counts ack links by name).  Tile 0
   additionally parses the manifest and status cache (the stream places
   them before all appendvecs; the other tiles discard those byte
   ranges), owns the manif/gui out links, publishes the attempt slot,
   and at end of load reads the shared totals and winner-gated snoop
   targets and runs the readback gate.  Cross-tile coordination happens
   exclusively through the snapio_snoop shared object; see
   utils/fd_snapin_io.h for the happens-before chains.

   Every write a tile makes to that shared object is one of exactly
   three kinds: an atomic read-modify-write (`next_appendvec`,
   `totals`), a write from inside the accdb snoop callback with the
   account's stripe lock held (`slot_history`, `feature_snoop`), or a
   write from tile 0's INIT critical sequence, which completes before
   the attempt slot that releases every other tile is published. */

/* Per-tile staging buffer coalescing the packed disk records of
   consecutive accounts into one pwrite. */

#define FD_SNAPIN_WRITE_BUF_SZ (2UL<<20)

/* Write-behind: tiles kick async writeback of their flushed records in
   large contiguous runs and bound their in-flight (kicked but not yet
   completed) dirty bytes.  Without this, N tiles writing ~9 GB/s
   aggregate into the page cache outrun the array's sustained
   multi-stream writeback rate; once the accumulated dirty pages cross
   the kernel's balance_dirty_pages engagement point, every pwrite gets
   throttled with coarse (up to ~100 ms) sleeps -- and a sleeping tile
   freezes its lane fseqs (tile fseq == scan position), which convoys
   the ENTIRE pipe (measured at eight writers: raw intake collapsed from
   9.3 GB/s to an oscillating 1.4-7 GB/s once ~100 GB of dirty pages had
   accumulated).  The write-behind backstop replaces those coarse kernel
   sleeps with smooth kick-granular self-throttling to the device, and
   starting writeback immediately maximizes the bytes drained during the
   load.  The aggregate window must stay below the throttle engagement
   point ((dirty_background_ratio+dirty_ratio)/2, ~6.5% of RAM by
   default) to preserve the page-cache elasticity that low tile counts
   rely on -- so it is a fraction of the host's RAM, not a fixed byte
   count: window = min( WB_WINDOW_MAX, WB_MEM_PCT% of MemTotal ), read
   at privileged_init (before the sandbox closes /proc) and divided
   evenly across the tiles.  WB_WINDOW_MAX is what was swept on the
   ~1.2 TB reference host, where the percentage term is not the binding
   one. */

#define FD_SNAPIN_WB_KICK_SZ      (64UL<<20) /* kick writeback per this many contiguous flushed bytes */
#define FD_SNAPIN_WB_WINDOW_MAX   (80UL<<30) /* aggregate kicked-not-waited budget across all tiles */
#define FD_SNAPIN_WB_MEM_PCT      (5UL)      /* ... capped at this percentage of MemTotal */
#define FD_SNAPIN_WB_RING_CNT     (4096UL)   /* max outstanding kicked ranges (pow2) */

/* Tile count at and above which write-behind is engaged.  Below it,
   aggregate pwrite intake cannot outrun the array's writeback and
   riding the page cache is measurably faster. */

#define FD_SNAPIN_WB_MIN_WORKERS  (8UL)

/* Rate limit for the attempt-slot gate diagnostic.  The gate holds the
   tile's data lanes (it does not spin inside a frag handler), so an
   unpublished slot is a stall to report, not a crash: it is also the
   normal state while tile 0 is still doing slow INIT work (a large
   failed-incremental purge wait, the acc_map memset), and it is the
   expected state when an ERROR aborted tile 0's own INIT barrier -- in
   which case the tile must stay live to consume the ERROR and ack the
   FAIL that follows. */

#define FD_SNAPIN_GATE_WARN_NS (10L*1000L*1000L*1000L)

/* 300 root slots in the slot deltas array, and each one references all
   151 prior blockhashes that it's able to. */
#define FD_SNAPIN_MAX_SLOT_DELTA_GROUPS (300UL*151UL)

struct fd_blockhash_entry {
  fd_hash_t blockhash;

  struct {
    ulong prev;
    ulong next;
  } map;
};

typedef struct fd_blockhash_entry fd_blockhash_entry_t;

#define MAP_NAME                           blockhash_map
#define MAP_KEY                            blockhash
#define MAP_KEY_T                          fd_hash_t
#define MAP_ELE_T                          fd_blockhash_entry_t
#define MAP_KEY_EQ(k0,k1)                  (!memcmp((k0),(k1), sizeof(fd_hash_t)))
#define MAP_KEY_HASH(key,seed)             (fd_hash32( (key)->uc, (seed) ))
#define MAP_PREV                           map.prev
#define MAP_NEXT                           map.next
#define MAP_OPTIMIZE_RANDOM_ACCESS_REMOVAL 1
#include "../../util/tmpl/fd_map_chain.c"

/* For a transaction to be valid to be inserted into the txncache, it
   must reference a blockhash that is in the set of recent blockhashes.
   This means that only transactions executed in the latest 151 slots
   can be in the txncache: the remaining entries can be ignored. */
#define FD_SNAPIN_TXNCACHE_MAX_ENTRIES (FD_TXNCACHE_MAX_SLOT_DELTAS*FD_PACK_MAX_TXNCACHE_TXN_PER_SLOT)

FD_STATIC_ASSERT( FD_TXNCACHE_MAX_SLOT_DELTAS<=FD_SLOT_DELTA_MAX_ENTRIES, txncache_staging_slot_cnt );

struct blockhash_group {
  uchar blockhash[ 32UL ];
  ulong slot;
  ulong txnhash_offset;
  ulong txncache_entry_idx;
  ulong txncache_entry_cnt;
};

typedef struct blockhash_group blockhash_group_t;

struct txncache_staging_slot {
  ulong slot;
  ulong entry_cnt;
};

typedef struct txncache_staging_slot txncache_staging_slot_t;

struct fd_snapin_out_link {
  ulong       idx;
  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
  ulong       chunk;
  ulong       mtu;
};
typedef struct fd_snapin_out_link fd_snapin_out_link_t;

struct fd_snapin_tile {
  int  state;
  uint full           : 1;  /* loading a full snapshot? */
  uint init_completed : 1;  /* tile 0: did INIT complete for this attempt? */
  uint gate_pending   : 1;  /* waiting for this attempt's slot before admitting data? */

  ulong tile_idx;           /* == tile->kind_id */
  ulong tile_cnt;
  ulong lane_cnt;
  ulong generation;         /* attempt counter, bumped at the first INIT frag (all tiles, in lockstep via their lane barriers) */
  ulong expected_frame;
  ulong pending_control;    /* control message expected from snapdc tiles */
  uchar control_seen[ FD_TOPO_MAX_TILE_IN_LINKS ];

  ulong seed;
  long boot_timestamp;

  fd_accdb_t *    accdb;
  fd_txncache_t * txncache; /* tile 0 only */

  fd_banks_t * banks;
  fd_bank_t *  bank;        /* tile 0 only */

  /* Every tile updates the bank's root stake delegations directly from
     the snoop callback (the struct serializes mutators on its own write
     lock), so every tile joins banks even though only tile 0 owns the
     bank itself. */
  fd_stake_delegations_t * stake_delegations;

  /* Tile 0: the feature snoop the bank is finalized from, accumulated
     across the full and incremental loads.  Each attempt's shared
     winner-gated copy is merged in at the NEXT/DONE barrier. */
  fd_feature_snoop_t feature_snoop[1];

  fd_ssparse_t             ssparse[1];
  fd_ssmanifest_parser_t * manifest_parser;   /* tile 0 only */
  fd_slot_delta_parser_t * slot_delta_parser; /* tile 0 only */

  struct {
    int manifest_done;
    int status_cache_done;
    int manifest_processed;
  } flags;

  ulong advertised_slot;
  ulong bank_slot;
  ulong epoch;

  fd_epoch_schedule_t epoch_schedule;

  ulong full_genesis_creation_time_seconds;
  uchar advertised_hash[ FD_HASH_FOOTPRINT ];

  ulong capitalization;          /* tile 0: capitalization of all loaded accounts, from the shared totals */
  ulong dup_capitalization;      /* tile 0: capitalization of duplicate accounts, from the shared totals */
  ulong manifest_capitalization; /* capitalization according to the current snapshot manifest */

  struct {
    ulong              capitalization;
    fd_feature_snoop_t feature_snoop;
  } recovery; /* tile 0: stores state from the last full snapshot for incremental revert */

  ulong               blockhash_groups_len;
  blockhash_group_t * blockhash_groups;

  int alpenglow;

  fd_sstxncache_hash_t *  txncache_entries;
  txncache_staging_slot_t txncache_slots[ FD_TXNCACHE_MAX_SLOT_DELTAS ];
  ulong                   txncache_slots_len;
  ulong                   txncache_current_slot_idx;
  ulong                   txncache_current_slot_entry_cnt;

  fd_accdb_fork_id_t accdb_root_fork_id;
  fd_accdb_fork_id_t accdb_incr_fork_id; /* tile 0: child fork for incremental writes (purge on failure) */
  fd_txncache_fork_id_t txncache_root_fork_id;

  struct {
    ulong full_bytes_read;
    ulong incremental_bytes_read;

    /* Account gauges.  Strictly this tile's OWN share, cumulative over
       the load session (full then incremental), and live from the first
       insert through FINI and past the NEXT/DONE barrier: the GUI and
       the snapshot-load watch both SUM these over all snapin tiles and
       take deltas, so anything that dips them mid-load (a per-tile zero
       at FINI, or tile 0 overwriting its own with the cross-tile fold)
       either collapses the sum to zero or double counts it.  They are
       rebased only at an INIT barrier: to 0 for a full attempt, to this
       tile's latched full-snapshot share for an incremental one (which
       also discards a failed incremental attempt's partial counts).
       Tile 0's cross-tile totals live in ctx->totals_fold instead. */
    ulong accounts_loaded;
    ulong accounts_replaced;
    ulong accounts_ignored;

    /* This tile's own share of the full snapshot, latched at NEXT. */
    ulong full_accounts_loaded;
    ulong full_accounts_replaced;
    ulong full_accounts_ignored;

    /* Persistent counters */
    ulong total_accounts_processed;
    ulong total_account_batches_processed;
  } metrics;

  struct {
    fd_wksp_t * wksp;
    ulong       chunk0;
    ulong       wmark;
    ulong       mtu;
    ulong       pos;
  } in[ FD_TOPO_MAX_TILE_IN_LINKS ];

  fd_snapin_out_link_t ct_out;
  fd_snapin_out_link_t manifest_out; /* tile 0 only */
  fd_snapin_out_link_t gui_out;      /* tile 0 only */

  /* Shared snapio_snoop object. */
  fd_snapio_snoop_hdr_t * snoop_hdr;
  int *                   stripe_locks;
  fd_snapio_worker_t *    my_snoop;                      /* this tile's fail-partition staging */
  fd_snapio_worker_t *    snoops[ FD_SNAPIN_TILE_MAX ];   /* tile 0: all tiles' fail-partition staging */

  /* Sharded parse state (per attempt). */
  ulong appendvec_seq;      /* stream sequence number of the next appendvec header */
  ulong claimed_appendvec;  /* the one outstanding claim off hdr->next_appendvec */
  ulong owned_appendvecs;   /* claims consumed this attempt */
  ulong owned_bytes;
  ulong incr_fork;          /* accdb fork for this attempt's inserts, from the attempt slot (USHORT_MAX = full) */
  long  gate_warn_ts;       /* next wallclock at which a held-data diagnostic may be logged */

  /* Per-attempt insert counters, folded into the shared totals at FINI.
     Kept separate from metrics.accounts_* because tile 0's gauges also
     hold cross-attempt fold results. */
  struct {
    ulong accounts_loaded;
    ulong accounts_replaced;
    ulong accounts_ignored;
    ulong input_lamports;
    ulong replaced_lamports;
    ulong ignored_lamports;
  } worker;

  /* Write engine: private explicit-offset write head + staging buffer. */
  fd_accdb_snapshot_whead_t whead;
  uchar * write_buf;
  ulong   write_buf_used;
  ulong   flush_off;        /* file offset of write_buf[0] */
  ulong   bytes_written;
  fd_accdb_snapshot_worker_metrics_t worker_metrics[1];
  struct {
    int   accepted;    /* 0 = ignored duplicate: drop the data bytes */
    ulong received;
    ulong file_off;    /* allocated meta offset; data at +sizeof(disk_meta) */
  } open_acc;

  /* Snoop view of the batch currently inside
     fd_accdb_snapshot_write_batch_worker.  The callback only receives
     the batch index, so the account inputs it needs are published here
     first; the fields are live only for the duration of that one call
     and are only read for indices flagged in snoop_candidates[]. */
  struct {
    ulong                 slot;
    uchar const * const * pubkeys;
    uchar const * const * owners;
    uchar const * const * datas;
    ulong const *         lamports;
    ulong const *         data_lens;
    ulong const *         data_szs;    /* bytes readable at datas[i] */
    int   const *         executables;
  } snoop_view;

  /* Streaming-path snoop deferral.  A fragmented account body is not
     available at ACCOUNT_HEADER time, but the shared snoop targets may
     only be written from inside the callback, with the account's stripe
     lock held.  So for the rare accounts a snoop cares about, the accdb
     insert (and therefore the record staging) is held back until the
     body prefix the snoop needs has been buffered here, and only then
     issued as a one-entry batch.  `need` is always <= data_len, so the
     buffer always fills before the body ends. */
  struct {
    int   active;
    int   executable;
    ulong slot;
    ulong lamports;
    ulong data_len;
    ulong need;
    ulong write_pos;
    uchar pubkey[ 32UL ];
    uchar owner [ 32UL ];
    uchar buf   [ FD_SYSVAR_SLOT_HISTORY_BINCODE_SZ ];
  } pending;

  /* Write-behind (bounded in-flight dirty bytes). */
  ulong wb_total_window;    /* aggregate cap, sized from MemTotal at privileged_init */
  ulong wb_kick_sz;         /* kick granularity (lowered by tests) */
  ulong wb_window;          /* per-tile in-flight cap; 0 disables */
  ulong wb_run_off;         /* current un-kicked contiguous flushed run */
  ulong wb_run_sz;
  ulong wb_pending;         /* kicked but not yet waited-on bytes */
  ulong wb_head;            /* ring of kicked ranges */
  ulong wb_tail;
  ulong wb_kick_cnt;        /* instrumentation */
  ulong wb_wait_cnt;
  struct { ulong off; ulong sz; } wb_ring[ FD_SNAPIN_WB_RING_CNT ];

  /* Tile 0: end-of-attempt fold state. */
  int   attempt_folded;     /* shared totals and snoop targets read out for this attempt? */
  struct {
    ulong eq_slot_dups;
    ulong eq_slot_lamports_diff;
    ulong bytes_written;
  } worker_fold;

  /* Tile 0: cross-tile account totals, accumulated out of the shared
     `totals` at each successful attempt's NEXT/DONE barrier (so
     cumulative over the load session; reset at INIT_FULL).  Diagnostic
     only -- deliberately NOT written back into the per-tile gauges,
     which dashboards sum across all snapin tiles. */
  struct {
    ulong accounts_loaded;
    ulong accounts_replaced;
    ulong accounts_ignored;
  } totals_fold;

  /* Tile 0: rollback of a failed attempt, deferred from the FAIL
     barrier to the NEXT INIT barrier.  fd_accdb_reset and the
     incremental purge path require that no other joiner is still
     mutating shared state, but a tile that is behind on the stream
     keeps inserting until it consumes its own FAIL barrier copies.
     By the retry's INIT barrier every tile has provably quiesced:
     snapct publishes the retry INIT only after ALL FAIL acks, and each
     tile acks FAIL only after its worker-side teardown (including
     writer_end).  If snapct aborts without retrying, the rollback
     never runs and the database is left dirty at shutdown; benign,
     the process exits and the next boot's INIT_FULL resets it. */
  struct {
    int                pending;
    int                full;  /* kind of the failed attempt */
    fd_accdb_fork_id_t fork;  /* incr fork of the failed attempt */
  } rollback;

  /* Tile 0: partitions abandoned by failed attempts (gathered from the
     tiles' fail-partition staging at the FAIL quiesce), released back to the
     partition pool once the failed attempt's index purge completed --
     at the next INIT_INCR (whose attach_child waits for the purge); a
     failed FULL attempt instead releases everything via fd_accdb_reset
     at the retry's INIT_FULL.  Bounded by the partition pool size. */
  uint  doomed_partitions[ FD_SNAPIO_FAIL_PARTITION_MAX ];
  ulong doomed_partition_cnt;
  struct {       /* appendvec size distribution, logged at FINI */
    ulong cnt;
    ulong bytes;
    ulong max_sz;
    ulong over_64m_cnt;
    ulong over_256m_bytes;
    ulong log2_hist[ 48 ];
  } av_stats;

  ulong gui_config_acct_sz;   /* total expected account data length (0 when not accumulating) */
  ulong gui_config_acct_off;  /* bytes accumulated so far into the current gui_out link chunk */

  /* Tile 0: in-memory copy of the SlotHistory sysvar account, read out
     of the shared winner-gated capture at the NEXT/DONE barrier.  The
     accdb read-back path is unsafe at the end of load because the
     write-behind may not have flushed the bytes yet; the snoop path
     observes the bytes directly.  The captured copy is then used by
     verify_slot_deltas_with_slot_history. */
  struct {
    int   captured;
    int   executable;
    ulong slot;
    ulong lamports;
    ulong data_len;
    uchar owner[ 32UL ];
    uchar buf[ FD_SYSVAR_SLOT_HISTORY_BINCODE_SZ ];
  } slot_history;
};

typedef struct fd_snapin_tile fd_snapin_tile_t;

/* The snapin tiles are symmetric workers, except that tile 0 is the
   lead: it parses the manifest and status cache, owns the tile-0-only
   accdb attempt work, folds the cross-tile totals and does the
   end-of-load logging and verification. */

static inline int
is_lead( fd_snapin_tile_t const * ctx ) {
  return !ctx->tile_idx;
}

static void
format_count( char * out, ulong out_sz, ulong n ) {
  if(      n>=1000000UL ) FD_TEST( fd_cstr_printf_check( out, out_sz, NULL, "%.1fM", (double)n/1e6 ) );
  else if( n>=1000UL    ) FD_TEST( fd_cstr_printf_check( out, out_sz, NULL, "%.1fK", (double)n/1e3 ) );
  else                    FD_TEST( fd_cstr_printf_check( out, out_sz, NULL, "%lu",   n             ) );
}

static inline int
should_shutdown( fd_snapin_tile_t * ctx ) {
  if( FD_UNLIKELY( ctx->state==FD_SNAPSHOT_STATE_SHUTDOWN && is_lead( ctx ) ) ) {
    ulong accounts_dup = ctx->totals_fold.accounts_ignored + ctx->totals_fold.accounts_replaced;
    long  elapsed_ns   = fd_log_wallclock() - ctx->boot_timestamp;
    char  loaded_buf[ 32 ];
    char  dup_buf   [ 32 ];
    format_count( loaded_buf, sizeof(loaded_buf), ctx->totals_fold.accounts_loaded );
    format_count( dup_buf,    sizeof(dup_buf),    accounts_dup                 );
    FD_LOG_NOTICE(( "loaded %s accounts %s(%s dups)%s from snapshot in %.3f seconds",
                    loaded_buf, fd_log_style_dim(), dup_buf, fd_log_style_normal(), (double)elapsed_ns/1e9 ));
  }
  return ctx->state==FD_SNAPSHOT_STATE_SHUTDOWN;
}

static ulong
scratch_align( void ) {
  /* Must cover the largest FD_LAYOUT_APPEND alignment in
     scratch_footprint (the 4096-aligned write buffer).  The footprint
     is computed from a zero base, so if the topology placed the tile
     object at a smaller alignment the runtime layout could consume up
     to align-scratch_align more bytes than the footprint and overflow
     into the next workspace object (with >=2 tiles that is the next
     tile's ctx). */
  return 4096UL;
}

static ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_snapin_tile_t),       sizeof(fd_snapin_tile_t)                                    );
  l = FD_LAYOUT_APPEND( l, fd_accdb_align(),                fd_accdb_footprint( tile->snapin.max_live_slots )           );
  if( FD_LIKELY( !tile->kind_id ) ) {
    l = FD_LAYOUT_APPEND( l, fd_txncache_align(),           fd_txncache_footprint( tile->snapin.max_live_slots )        );
    l = FD_LAYOUT_APPEND( l, fd_ssmanifest_parser_align(),  fd_ssmanifest_parser_footprint()                            );
    l = FD_LAYOUT_APPEND( l, fd_slot_delta_parser_align(),  fd_slot_delta_parser_footprint()                            );
    l = FD_LAYOUT_APPEND( l, alignof(blockhash_group_t),    sizeof(blockhash_group_t)*FD_SNAPIN_MAX_SLOT_DELTA_GROUPS   );
    l = FD_LAYOUT_APPEND( l, alignof(fd_sstxncache_hash_t), sizeof(fd_sstxncache_hash_t)*FD_SNAPIN_TXNCACHE_MAX_ENTRIES );
  }
  l = FD_LAYOUT_APPEND( l, 4096UL,                          FD_SNAPIN_WRITE_BUF_SZ                                      );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static void
metrics_write( fd_snapin_tile_t * ctx ) {
  fd_accdb_flush_metrics( ctx->accdb );

  FD_MGAUGE_SET( SNAPIN, STATE,                  (ulong)ctx->state );
  FD_MGAUGE_SET( SNAPIN, FULL_BYTES_READ,        ctx->metrics.full_bytes_read );
  FD_MGAUGE_SET( SNAPIN, INCREMENTAL_BYTES_READ, ctx->metrics.incremental_bytes_read );
  FD_MGAUGE_SET( SNAPIN, ACCOUNT_LOADED,         ctx->metrics.accounts_loaded );
  FD_MGAUGE_SET( SNAPIN, ACCOUNT_REPLACED,       ctx->metrics.accounts_replaced );
  FD_MGAUGE_SET( SNAPIN, ACCOUNT_IGNORED,        ctx->metrics.accounts_ignored );
  FD_MCNT_SET  ( SNAPIN, ACCOUNT_PROCESSED,       ctx->metrics.total_accounts_processed );
  FD_MCNT_SET  ( SNAPIN, ACCOUNT_BATCH_PROCESSED, ctx->metrics.total_account_batches_processed );
}

/* verify_slot_deltas_with_slot_history verifies the 'SlotHistory'
   sysvar account after loading a snapshot.  Uses the in-memory copy
   read out of the shared winner-gated capture.  We cannot read from
   accdb at this point because the write-behind may not have completed
   yet for the SlotHistory bytes.

   Returns 0 if verification passed, -1 if not. */

static int
verify_slot_deltas_with_slot_history( fd_snapin_tile_t * ctx ) {
  if( FD_UNLIKELY( !ctx->slot_history.captured ) ) {
    FD_LOG_WARNING(( "SlotHistory sysvar account was not present in the snapshot stream" ));
    return -1;
  }
  if( FD_UNLIKELY( !ctx->slot_history.lamports || !ctx->slot_history.data_len ) ) {
    FD_LOG_WARNING(( "SlotHistory sysvar account missing or empty" ));
    return -1;
  }
  if( FD_UNLIKELY( !fd_memeq( ctx->slot_history.owner, fd_sysvar_owner_id.uc, sizeof(fd_pubkey_t) ) ) ) {
    FD_BASE58_ENCODE_32_BYTES( ctx->slot_history.owner, owner_b58 );
    FD_LOG_WARNING(( "SlotHistory sysvar owner is invalid: %s != sysvar_owner_id", owner_b58 ));
    return -1;
  }

  fd_slot_history_view_t view[1];
  if( FD_UNLIKELY( !fd_sysvar_slot_history_view( view, ctx->slot_history.buf, ctx->slot_history.data_len ) ) ) {
    FD_LOG_WARNING(( "SlotHistory sysvar account data is corrupt" ));
    return -1;
  }

  /* Sanity checks for slot history:
     https://github.com/anza-xyz/agave/blob/v3.1.8/runtime/src/snapshot_bank_utils.rs#L586 */

  ulong newest_slot = view->next_slot - 1UL;
  if( FD_UNLIKELY( newest_slot!=ctx->bank_slot ) ) {
    /* VerifySlotHistoryError::InvalidNewestSlot
       https://github.com/anza-xyz/agave/blob/v3.1.8/runtime/src/snapshot_bank_utils.rs#L621 */
    FD_LOG_WARNING(( "SlotHistory sysvar has an invalid newest slot: %lu != bank slot: %lu", newest_slot, ctx->bank_slot ));
    return -1;
  }

  if( FD_UNLIKELY( view->bits_len!=FD_SLOT_HISTORY_MAX_ENTRIES ) ) {
    /* VerifySlotHistoryError::InvalidNumEntries
       https://github.com/anza-xyz/agave/blob/v3.1.8/runtime/src/snapshot_bank_utils.rs#L625 */
    FD_LOG_WARNING(( "SlotHistory sysvar has invalid number of entries: %lu != expected: %lu", view->bits_len, FD_SLOT_HISTORY_MAX_ENTRIES ));
    return -1;
  }

  /* All slots in slot deltas should be present in the slot history */
  fd_slot_delta_slot_set_t slot_set = fd_slot_delta_parser_slot_set( ctx->slot_delta_parser );
  for( ulong i=0UL; i<slot_set.ele_cnt; i++ ) {
    ulong slot = slot_set.pool[ i ].slot;
    if( FD_UNLIKELY( fd_sysvar_slot_history_find_slot( view, slot )!=FD_SLOT_HISTORY_SLOT_FOUND ) ) {
      /* VerifySlotDeltasError::SlotNotFoundInHistory
         https://github.com/anza-xyz/agave/blob/v3.1.8/snapshots/src/error.rs#L144
         https://github.com/anza-xyz/agave/blob/v3.1.8/runtime/src/snapshot_bank_utils.rs#L593 */
      FD_LOG_WARNING(( "slot %lu missing from SlotHistory sysvar account", slot ));
      return -1;
    }
  }

  /* The most recent slots (up to the number of slots in the txncache)
     in the SlotHistory should be present in the txncache. */
  if( FD_LIKELY( slot_set.ele_cnt ) ) {
    ulong oldest = newest_slot - slot_set.ele_cnt;
    for( ulong i=newest_slot; i>oldest; i-- ) {
      if( FD_LIKELY( fd_sysvar_slot_history_find_slot( view, i )==FD_SLOT_HISTORY_SLOT_FOUND ) ) {
        if( FD_UNLIKELY( slot_set_ele_query( slot_set.map, &i, NULL, slot_set.pool )==NULL ) ) {
          /* VerifySlotDeltasError::SlotNotFoundInDeltas
             https://github.com/anza-xyz/agave/blob/v3.1.8/snapshots/src/error.rs#L147
             https://github.com/anza-xyz/agave/blob/v3.1.8/runtime/src/snapshot_bank_utils.rs#L609 */
          FD_LOG_WARNING(( "slot %lu missing from slot deltas but present in SlotHistory", i ));
          return -1;
        }
      }
    }
  }

  return 0;
}

/* verification of epoch stakes from manifest
   https://github.com/anza-xyz/agave/blob/v3.1.8/runtime/src/snapshot_bank_utils.rs#L632 */
static int
verify_epoch_stakes( fd_snapshot_manifest_t const * manifest ) {
  fd_epoch_schedule_t epoch_schedule = (fd_epoch_schedule_t){
    .slots_per_epoch             = manifest->epoch_schedule_params.slots_per_epoch,
    .leader_schedule_slot_offset = manifest->epoch_schedule_params.leader_schedule_slot_offset,
    .warmup                      = manifest->epoch_schedule_params.warmup,
    .first_normal_epoch          = manifest->epoch_schedule_params.first_normal_epoch,
    .first_normal_slot           = manifest->epoch_schedule_params.first_normal_slot,
  };

  ulong min_required_epoch = fd_slot_to_epoch( &epoch_schedule, manifest->slot, NULL );
  ulong max_required_epoch = fd_slot_to_leader_schedule_epoch( &epoch_schedule, manifest->slot );

  /* ensure all required epochs are present in epoch stakes */
  for( ulong i=min_required_epoch; i<=max_required_epoch; i++ ) {
    int found = 0;
    for( ulong j=0UL; j<FD_RUNTIME_MANIFEST_EPOCH_STAKES_LEN; j++ ) {
      if( manifest->epoch_stakes[j].epoch==i ) {
        found = 1;
        break;
      }
    }

    if( FD_UNLIKELY( !found ) ) {
      /* VerifyEpochStakesError::StakesNotFound
         https://github.com/anza-xyz/agave/blob/v3.1.8/runtime/src/snapshot_bank_utils.rs#L667 */
      FD_LOG_WARNING(( "stakes not found for epoch %lu in manifest", i ));
      return -1;
    }
  }

  return 0;
}

static int
verify_slot_deltas_with_bank_slot( fd_snapin_tile_t * ctx,
                                   ulong              bank_slot ) {
  fd_slot_delta_slot_set_t slot_set = fd_slot_delta_parser_slot_set( ctx->slot_delta_parser );
  for( ulong i=0UL; i<slot_set.ele_cnt; i++ ) {
    ulong slot = slot_set.pool[ i ].slot;
    /* VerifySlotDeltasError::SlotGreaterThanMaxRoot
       https://github.com/anza-xyz/agave/blob/v3.1.8/snapshots/src/error.rs#L138
       https://github.com/anza-xyz/agave/blob/v3.1.8/runtime/src/snapshot_bank_utils.rs#L550 */
    if( FD_UNLIKELY( slot>bank_slot ) ) {
      FD_LOG_WARNING(( "entry slot %lu is greater than bank slot %lu", slot, bank_slot ));
      return -1;
    }
  }
  return 0;
}

static int
verify_bank_hash( fd_snapin_tile_t const *       ctx,
                  fd_snapshot_manifest_t const * manifest ) {
  if( FD_UNLIKELY( manifest->blockhashes_len==0UL ) ) {
    FD_LOG_WARNING(( "%s manifest for epoch %lu and slot %lu has no blockhashes",
                     ctx->full?"full":"incr", ctx->epoch, manifest->slot ));
    return -1;
  }

  if( FD_UNLIKELY( !manifest->has_accounts_lthash ) ) {
    FD_LOG_WARNING(( "%s manifest for epoch %lu and slot %lu is missing accounts lthash",
                     ctx->full?"full":"incr", ctx->epoch, manifest->slot ));
    return -1;
  }

  /* find the last blockhash */
  ulong max_hash_idx = 0UL;
  ulong last_bh_idx  = 0UL;
  for( ulong i=0UL; i<manifest->blockhashes_len; i++ ) {
    if( FD_LIKELY( manifest->blockhashes[ i ].hash_index > max_hash_idx ) ) {
      max_hash_idx = manifest->blockhashes[ i ].hash_index;
      last_bh_idx  = i;
    }
  }

  /* fd_lthash_value_t is aligned to 64B but the accounts_lthash in the
     manifest may not be because its simply a uchar array.  Copy is
     needed to avoid undefined behavior. */
  fd_lthash_value_t accounts_lthash[ 1UL ];
  fd_memcpy( accounts_lthash, manifest->accounts_lthash, sizeof(fd_lthash_value_t) );

  fd_hash_t const * parent_bank_hash = (fd_hash_t const *)fd_type_pun_const( manifest->parent_bank_hash );
  fd_hash_t const * last_blockhash   = (fd_hash_t const *)fd_type_pun_const( manifest->blockhashes[ last_bh_idx ].hash );
  fd_hash_t         computed_bank_hash[ 1UL ];
  fd_hashes_hash_bank( accounts_lthash, parent_bank_hash, last_blockhash, manifest->signature_count, computed_bank_hash );
  fd_hashes_apply_hard_forks(
      computed_bank_hash,
      manifest->slot,
      manifest->parent_slot,
      manifest->hard_forks,
      manifest->hard_fork_cnt );

  if( FD_UNLIKELY( memcmp( computed_bank_hash, manifest->bank_hash, FD_HASH_FOOTPRINT ) ) ) {
    FD_BASE58_ENCODE_32_BYTES( computed_bank_hash->hash, computed_bank_hash_enc );
    FD_BASE58_ENCODE_32_BYTES( manifest->bank_hash, manifest_bank_hash_enc );
    FD_LOG_WARNING(( "%s manifest for epoch %lu and slot %lu bank hash verification failed: computed %s does not match manifest %s",
                     ctx->full?"full":"incr", ctx->epoch, manifest->slot,
                     computed_bank_hash_enc, manifest_bank_hash_enc ));
    return -1;
  }

  return 0;
}

static inline void
clear_control_barrier( fd_snapin_tile_t * ctx ) {
  ctx->pending_control = ULONG_MAX;
  fd_memset( ctx->control_seen, 0, sizeof(ctx->control_seen) );
}

static void
transition_malformed( fd_snapin_tile_t *  ctx,
                      fd_stem_context_t * stem ) {
  if( FD_UNLIKELY( ctx->state==FD_SNAPSHOT_STATE_ERROR ) ) return;
  ctx->state = FD_SNAPSHOT_STATE_ERROR;
  fd_stem_publish( stem, ctx->ct_out.idx, FD_SNAPSHOT_MSG_CTRL_ERROR, 0UL, 0UL, 0UL, 0UL, 0UL );
}

static int
populate_txncache( fd_snapin_tile_t *                     ctx,
                   fd_snapshot_manifest_blockhash_t const blockhashes[ static FD_BLOCKHASHES_MAX ],
                   ulong                                  blockhashes_len ) {
  /* Our txncache internally contains the fork structure for the chain,
     which we need to recreate here.  Because snapshots are only served
     for rooted slots, there is actually no forking, and the bank forks
     are just a single bank, the root, like

       _root

     But the txncache also must contain the 150 more recent banks prior
     to the root (151 rooted banks total), looking like,


       _root_150 -> _root_149 -> ... -> _root_2 -> _root_1 -> _root

     Our txncache is "slot agnostic" meaning there is no concept of a
     slot number in it.  It just has a fork tree structure.  So long as
     the fork tree is isomorphic to the actual bank forks, and each bank
     has the correct blockhash, it works.

     So the challenge is simply to create this chain of 151 forks in the
     txncache, with correct blockhashes, and then insert all the
     transactions into it.

     Constructing the chain of blockhashes is easy.  It is just the
     BLOCKHASH_QUEUE array in the manifest.  This array is unfortunately
     not sorted and appears in random order, but it has a hash_index
     field which is a gapless index, starting at some arbitrary offset,
     so we can back out the 151 blockhashes we need from this, by first
     finding the max hash_index as _max and then collecting hash entries
     via,

       _root_150 -> _root_149 -> ... -> _root_2 -> _root_1 -> _root
       _max-150  -> _max-149  -> ... -> _max-2  -> _max-1  -> _max

     Now the remaining problem is inserting transactions into this
     chain.  Remember each transaction needs to be inserted with:

      (a) The fork ID (position of the bank in the chain) it was executed in.
      (b) The blockhash of the bank it referenced.

    (b) is trivial to retrieve, as it's in the actual slot_deltas entry
    in the manifest served by Agave.  But (a) is mildly annoying.  Agave
    serves slot_deltas based on slot, so we need an additional mapping
    from slot to position in our banks chain.  It turns out we have to
    go to yet another structure in the manifest to retrieve this, the
    ancestors array.  This is just an array of slot values,  so we need
    to sort it, and line it up against our banks chain like so,

       _root_150  -> _root_149  -> ... -> _root_2  -> _root_1  -> _root
       _max-150   -> _max-149   -> ... -> _max-2   -> _max-1   -> _max
       _slots_150 -> _slots_149 -> ... -> _slots_2 -> _slots_1 -> _slots

    From there we are done.

    Well almost ... if you were paying attention you might have noticed
    this is a lot of work and we are lazy.  Why don't we just ignore the
    slot mapping and assume everything executed at the root slot
    exactly?  The only invariant we should maintain from a memory
    perspective is that at most, across all active banks,
    FD_MAX_TXN_PER_SLOT transactions are stored per slot, but we
    have preserved that.  It is not true "per slot" technically, but
    it's true across all slots, and the memory is aggregated.  It will
    also always be true, even as slots are garbage collected, because
    entries are collected by reference blockhash, not executed slot.

    ... actually we can't do this.  There's more broken things here.
    The Agave status decided to only store 20 bytes for 32 byte
    transaction hashes to save on memory.  That's OK, but they didn't
    just take the first 20 bytes.  They instead, for each blockhash,
    take a random offset between 0 and 12, and store bytes
    [ offset, offset+20 ) of the transaction hash.  We need to know this
    offset to be able to query the txncache later, so we need to
    retrieve it from the slot_deltas entry in the manifest, and key it
    into our txncache.  Unfortunately this offset is stored per slot in
    the slot_deltas entry.  So we need to first go and retrieve the
    ancestors array, sort it, and line it up against our banks chain as
    described above, and then go through slot deltas, to retrieve the
    offset for each slot, and stick it into the appropriate bank in
    our chain. */

  if( FD_UNLIKELY( blockhashes_len>FD_BLOCKHASHES_MAX ) ) {
    FD_LOG_WARNING(( "corrupt snapshot: blockhash queue length %lu exceeds maximum %lu", blockhashes_len, FD_BLOCKHASHES_MAX ));
    return 1;
  }
  if( FD_UNLIKELY( !blockhashes_len ) ) {
    FD_LOG_WARNING(( "corrupt snapshot: blockhash queue is empty" ));
    return 1;
  }

  ulong seq_min = ULONG_MAX;
  for( ulong i=0UL; i<blockhashes_len; i++ ) seq_min = fd_ulong_min( seq_min, blockhashes[ i ].hash_index );

  ulong seq_max;
  if( FD_UNLIKELY( __builtin_uaddl_overflow( seq_min, blockhashes_len, &seq_max ) ) ) {
    FD_LOG_WARNING(( "corrupt snapshot: blockhash queue sequence number wraparound (seq_min=%lu age_cnt=%lu)", seq_min, blockhashes_len ));
    return 1;
  }

  /* First let's construct the chain array as described above.  But
     index 0 will be the root, index 1 the root's parent, etc. */

  struct {
    int exists;
    uchar blockhash[ 32UL ];
    fd_txncache_fork_id_t fork_id;
    ulong txnhash_offset;
  } banks[ FD_BLOCKHASHES_MAX ] = {0};

  for( ulong i=0UL; i<blockhashes_len; i++ ) {
    fd_snapshot_manifest_blockhash_t const * elem = &blockhashes[ i ];
    ulong idx;
    if( FD_UNLIKELY( __builtin_usubl_overflow( elem->hash_index, seq_min, &idx ) ) ) {
      FD_LOG_WARNING(( "corrupt snapshot: gap in blockhash queue (seq=[%lu,%lu) idx=%lu)", seq_min, seq_max, blockhashes[ i ].hash_index ));
      return 1;
    }

    if( FD_UNLIKELY( idx>=blockhashes_len ) ) {
      FD_LOG_WARNING(( "corrupt snapshot: blockhash queue index out of range (seq_min=%lu age_cnt=%lu idx=%lu)", seq_min, blockhashes_len, idx ));
      return 1;
    }

    if( FD_UNLIKELY( banks[ blockhashes_len-1UL-idx ].exists ) ) {
      FD_LOG_WARNING(( "corrupt snapshot: duplicate blockhash hash_index %lu", elem->hash_index ));
      return 1;
    }

    banks[ blockhashes_len-1UL-idx ].fork_id.val = USHORT_MAX;
    banks[ blockhashes_len-1UL-idx ].txnhash_offset = ULONG_MAX;
    memcpy( banks[ blockhashes_len-1UL-idx ].blockhash, elem->hash, 32UL );
    banks[ blockhashes_len-1UL-idx ].exists = 1;
  }

  ulong chain_len = fd_ulong_min( blockhashes_len, 151UL );

  /* Now we need a hashset of just the 151 most recent blockhashes,
     anything else is a nonce transaction which we do not insert, or an
     already expired transaction which can also be discarded. */

  uchar __attribute__((aligned(alignof(blockhash_map_t)))) _map[ blockhash_map_footprint( 1024UL ) ];
  blockhash_map_t * blockhash_map = blockhash_map_join( blockhash_map_new( _map, 1024UL, ctx->seed ) );
  if( FD_UNLIKELY( !blockhash_map ) ) FD_LOG_ERR(( "failed to create blockhash map" ));

  fd_blockhash_entry_t blockhash_pool[ 151UL ];
  for( ulong i=0UL; i<chain_len; i++ ) {
    fd_memcpy( blockhash_pool[ i ].blockhash.uc, banks[ i ].blockhash, 32UL );

    if( FD_UNLIKELY( blockhash_map_ele_query_const( blockhash_map, &blockhash_pool[ i ].blockhash, NULL, blockhash_pool ) ) ) {
      FD_BASE58_ENCODE_32_BYTES( banks[ i ].blockhash, blockhash_b58 );
      FD_LOG_WARNING(( "corrupt snapshot: duplicate blockhash %s in 151 most recent blockhashes", blockhash_b58 ));
      return 1;
    }

    blockhash_map_ele_insert( blockhash_map, &blockhash_pool[ i ], blockhash_pool );
  }

  /* Now load the blockhash offsets for these blockhashes ... */
  if( FD_UNLIKELY( !ctx->blockhash_groups_len ) ) {
    fd_slot_delta_slot_set_t ss = fd_slot_delta_parser_slot_set( ctx->slot_delta_parser );
    /* No offsets AND no rooted slots is corruption in either mode.  No
       offsets WITH rooted slots only happens under Alpenglow. */
    if( FD_UNLIKELY( !ctx->alpenglow || !ss.ele_cnt ) ) {
      FD_LOG_WARNING(( "corrupt snapshot: no blockhash offsets found (rooted_slots=%lu)", ss.ele_cnt ));
      return 1;
    }
    FD_LOG_WARNING(( "status cache has no blockhash offsets (rooted_slots=%lu); proceeding with empty txncache offsets",
                     ss.ele_cnt ));
  }
  for( ulong i=0UL; i<ctx->blockhash_groups_len; i++ ) {
    blockhash_group_t const * group = &ctx->blockhash_groups[ i ];
    fd_hash_t key;
    fd_memcpy( key.uc, group->blockhash, 32UL );
    fd_blockhash_entry_t * entry = blockhash_map_ele_query( blockhash_map, &key, NULL, blockhash_pool );
    if( FD_UNLIKELY( !entry ) ) continue; /* Not in the most recent 151 blockhashes */

    ulong chain_idx = (ulong)(entry - blockhash_pool);

    if( FD_UNLIKELY( banks[ chain_idx ].txnhash_offset!=ULONG_MAX && banks[ chain_idx ].txnhash_offset!=group->txnhash_offset ) ) {
      FD_BASE58_ENCODE_32_BYTES( entry->blockhash.uc, blockhash_b58 );
      FD_LOG_WARNING(( "corrupt snapshot: conflicting txnhash offsets for blockhash %s", blockhash_b58 ));
      return 1;
    }

    banks[ chain_idx ].txnhash_offset = group->txnhash_offset;
  }

  /* Construct the linear fork chain in the txncache. */

  fd_txncache_fork_id_t parent = { .val = USHORT_MAX };
  for( ulong i=0UL; i<chain_len; i++ ) banks[ chain_len-1UL-i ].fork_id = parent = fd_txncache_attach_child( ctx->txncache, parent );
  for( ulong i=0UL; i<chain_len; i++ ) fd_txncache_attach_blockhash( ctx->txncache, banks[ i ].fork_id, banks[ i ].blockhash );

  /* Now insert all transactions as if they executed at the current
     root, per above. */

  for( ulong i=0UL; i<ctx->blockhash_groups_len; i++ ) {
    blockhash_group_t const * group = &ctx->blockhash_groups[ i ];
    /* Skip if there are no transaction in this group or if the slot is
       too old. */
    if( FD_UNLIKELY( group->txncache_entry_idx==ULONG_MAX || !group->txncache_entry_cnt ) ) continue;

    ulong slot_idx = group->txncache_entry_idx/FD_PACK_MAX_TXNCACHE_TXN_PER_SLOT;
    FD_TEST( slot_idx<ctx->txncache_slots_len );
    /* Skip groups whose entries correspond to a different slot.  This
       happens when an older slot is evicted and its storage is reused. */
    if( FD_UNLIKELY( ctx->txncache_slots[ slot_idx ].slot!=group->slot ) ) continue;
    ulong slot_entry_idx = group->txncache_entry_idx-slot_idx*FD_PACK_MAX_TXNCACHE_TXN_PER_SLOT;
    FD_TEST( slot_entry_idx<=ctx->txncache_slots[ slot_idx ].entry_cnt );
    FD_TEST( group->txncache_entry_cnt<=ctx->txncache_slots[ slot_idx ].entry_cnt-slot_entry_idx );
    fd_sstxncache_hash_t const * entries = &ctx->txncache_entries[ group->txncache_entry_idx ];

    fd_hash_t key;
    fd_memcpy( key.uc, group->blockhash, 32UL );
    if( FD_UNLIKELY( !blockhash_map_ele_query_const( blockhash_map, &key, NULL, blockhash_pool ) ) ) continue;

    for( ulong j=0UL; j<group->txncache_entry_cnt; j++ ) {
      fd_sstxncache_hash_t const * entry = &entries[ j ];
      fd_txncache_insert( ctx->txncache, banks[ 0UL ].fork_id, group->blockhash, entry->txnhash );
    }
  }

  /* Then finalize all the banks (freezing them) and setting the txnhash
     offset so future queries use the correct offset.  If the offset is
     ULONG_MAX this is valid, it means the blockhash had no transactions
     in it, so there's nothing in the status cache under that blockhash.

     Just set the offset to 0 in this case, it doesn't matter, but
     should be valid between 0 and 12 inclusive. */
  for( ulong i=0UL; i<chain_len; i++ ) {
    ulong txnhash_offset = banks[ chain_len-1UL-i ].txnhash_offset==ULONG_MAX ? 0UL : banks[ chain_len-1UL-i ].txnhash_offset;
    fd_txncache_finalize_fork( ctx->txncache, banks[ chain_len-1UL-i ].fork_id, txnhash_offset, banks[ chain_len-1UL-i ].blockhash );
  }

  for( ulong i=1UL; i<chain_len; i++ ) fd_txncache_advance_root( ctx->txncache, banks[ chain_len-1UL-i ].fork_id );

  ctx->txncache_root_fork_id = parent;

  return 0;
}

static void
process_manifest( fd_snapin_tile_t *  ctx,
                  fd_stem_context_t * stem ) {
  fd_snapshot_manifest_t * manifest = fd_chunk_to_laddr( ctx->manifest_out.mem, ctx->manifest_out.chunk );

  if( FD_UNLIKELY( ctx->advertised_slot!=manifest->slot ) ) {
    /* SnapshotError::MismatchedSlot
       https://github.com/anza-xyz/agave/blob/v3.1.8/runtime/src/snapshot_bank_utils.rs#L472 */
    FD_LOG_WARNING(( "snapshot manifest bank slot %lu does not match advertised slot %lu from snapshot peer",
                     manifest->slot, ctx->advertised_slot ));
    transition_malformed( ctx, stem );
    return;
  }

  if( FD_UNLIKELY( !manifest->has_accounts_lthash ) ) {
    /* The manifest must contain accounts lthash, irrespective of
       whether lthash verification is disabled or not.
       https://github.com/anza-xyz/agave/blob/v3.1.9/runtime/src/serde_snapshot.rs#L482 */
    FD_LOG_WARNING(( "snapshot manifest missing accounts lthash" ));
    transition_malformed( ctx, stem );
    return;
  }

  uchar const * sum = manifest->accounts_lthash;
  uchar hash32[32]; fd_blake3_hash( sum, FD_LTHASH_LEN_BYTES, hash32 );
  FD_BASE58_ENCODE_32_BYTES( sum,    sum_enc    );
  FD_BASE58_ENCODE_32_BYTES( hash32, hash32_enc );
  FD_LOG_INFO(( "snapshot manifest slot=%lu indicates lthash[..32]=%s blake3(lthash)=%s",
                manifest->slot, sum_enc, hash32_enc ));

  if( FD_UNLIKELY( memcmp( ctx->advertised_hash, hash32, FD_HASH_FOOTPRINT ) ) ) {
    /* SnapshotError::MismatchedHash
        https://github.com/anza-xyz/agave/blob/v3.1.8/runtime/src/snapshot_bank_utils.rs#L479 */
    FD_BASE58_ENCODE_32_BYTES( ctx->advertised_hash, advertised_hash_enc );
    FD_LOG_WARNING(( "snapshot manifest accounts lthash %s does not match advertised hash from snapshot peer %s",
                     hash32_enc, advertised_hash_enc ));
    transition_malformed( ctx, stem );
    return;
  }

  ctx->bank_slot = manifest->slot;
  ctx->manifest_capitalization = manifest->capitalization;
  if( FD_UNLIKELY( ctx->manifest_capitalization>LONG_MAX ) ) {
    /* Calculations downstream require capitalization to be treated
       as long (to handle addition and subtraction). */
    FD_LOG_WARNING(( "snapshot manifest capitalization %lu exceeds LONG_MAX", ctx->manifest_capitalization ));
    transition_malformed( ctx, stem );
    return;
  }

  if( FD_UNLIKELY( fd_ssload_manifest_validate( manifest, FD_RUNTIME_MAX_VAT_VOTE_ACCOUNTS, FD_RUNTIME_MAX_STAKE_ACCOUNTS ) ) ) {
    FD_LOG_WARNING(( "snapshot manifest validation failed" ));
    transition_malformed( ctx, stem );
    return;
  }

  fd_epoch_schedule_t epoch_schedule = (fd_epoch_schedule_t){
    .slots_per_epoch             = manifest->epoch_schedule_params.slots_per_epoch,
    .leader_schedule_slot_offset = manifest->epoch_schedule_params.leader_schedule_slot_offset,
    .warmup                      = manifest->epoch_schedule_params.warmup,
    .first_normal_epoch          = manifest->epoch_schedule_params.first_normal_epoch,
    .first_normal_slot           = manifest->epoch_schedule_params.first_normal_slot,
  };
  ctx->epoch          = fd_slot_to_epoch( &epoch_schedule, manifest->slot, NULL );
  ctx->epoch_schedule = epoch_schedule;

  if( FD_UNLIKELY( verify_bank_hash( ctx, manifest ) ) ) {
    /* https://github.com/anza-xyz/agave/blob/v3.1.9/runtime/src/bank.rs#L4682 */
    transition_malformed( ctx, stem );
    return;
  }

  if( FD_UNLIKELY( verify_slot_deltas_with_bank_slot( ctx, manifest->slot ) ) ) {
    FD_LOG_WARNING(( "slot deltas verification failed" ));
    transition_malformed( ctx, stem );
    return;
  }

  if( FD_UNLIKELY( verify_epoch_stakes( manifest ) ) ) {
    FD_LOG_WARNING(( "epoch stakes verification failed" ));
    transition_malformed( ctx, stem );
    return;
  }

  if( FD_UNLIKELY( populate_txncache( ctx, manifest->blockhashes, manifest->blockhashes_len ) ) ) {
    FD_LOG_WARNING(( "populating txncache failed" ));
    transition_malformed( ctx, stem );
    return;
  }

  if( ctx->full ) {
    ctx->full_genesis_creation_time_seconds = manifest->creation_time_seconds;
  } else {
    if( FD_UNLIKELY( manifest->creation_time_seconds!=ctx->full_genesis_creation_time_seconds ) ) {
      FD_LOG_WARNING(( "snapshot manifest genesis creation time seconds %lu does not match full snapshot genesis creation time seconds %lu",
                       manifest->creation_time_seconds, ctx->full_genesis_creation_time_seconds ));
      transition_malformed( ctx, stem );
      return;
    }
  }

  manifest->accdb_fork_id    = fd_ushort_if( ctx->full, ctx->accdb_root_fork_id.val, ctx->accdb_incr_fork_id.val );
  manifest->txncache_fork_id = ctx->txncache_root_fork_id.val;

  ulong sig = ctx->full ? fd_ssmsg_sig( FD_SSMSG_MANIFEST_FULL ) :
                          fd_ssmsg_sig( FD_SSMSG_MANIFEST_INCREMENTAL );
  fd_stem_publish( stem, ctx->manifest_out.idx, sig, ctx->manifest_out.chunk, sizeof(fd_snapshot_manifest_t), 0UL, 0UL, 0UL );
  ctx->manifest_out.chunk = fd_dcache_compact_next( ctx->manifest_out.chunk, sizeof(fd_snapshot_manifest_t), ctx->manifest_out.chunk0, ctx->manifest_out.wmark );
}

static int
validate_capitalization( fd_snapin_tile_t * ctx ) {
  if( FD_UNLIKELY( ctx->capitalization!=ctx->manifest_capitalization ) ) {
    /* SnapshotError::MismatchedCapitalization
        https://github.com/anza-xyz/agave/blob/v4.0.0-beta.2/runtime/src/snapshot_bank_utils.rs#L217 */
    FD_LOG_WARNING(( "%s snapshot manifest capitalization %lu does not match computed capitalization %lu",
                     ctx->full?"full":"incr", ctx->manifest_capitalization, ctx->capitalization ));
    return -1;
  }
  return 0;
}

/* Write engine ********************************************************/

static void
worker_reset_write_engine( fd_snapin_tile_t * ctx ) {
  ctx->write_buf_used      = 0UL;
  ctx->flush_off           = 0UL;
  ctx->bytes_written       = 0UL;
  ctx->whead.val           = 0UL;
  ctx->whead.has_partition = 0;
  ctx->whead.attempt_partition_cnt = 0UL; /* tracker buffer/capacity are set once at init */
  fd_memset( &ctx->open_acc, 0, sizeof(ctx->open_acc) );
  ctx->wb_run_sz  = 0UL;
  ctx->wb_pending = 0UL;
  ctx->wb_head    = 0UL;
  ctx->wb_tail    = 0UL;
  ctx->wb_kick_cnt = 0UL;
  ctx->wb_wait_cnt = 0UL;
}

/* Write-behind machinery.  worker_wb_disable turns it off for the rest
   of the run (unsupported filesystem); worker_wb_kick starts async
   writeback of the accumulated contiguous run; worker_wb_track records
   a flushed range and applies the smooth self-throttle backstop. */

static void
worker_wb_disable( fd_snapin_tile_t * ctx ) {
  FD_LOG_WARNING(( "sync_file_range failed (%d-%s); disabling write-behind", errno, fd_io_strerror( errno ) ));
  ctx->wb_window  = 0UL;
  ctx->wb_run_sz  = 0UL;
  ctx->wb_pending = 0UL;
  ctx->wb_head    = ctx->wb_tail;
}

static void
worker_wb_kick( fd_snapin_tile_t * ctx ) {
  if( FD_LIKELY( !ctx->wb_run_sz ) ) return;

  /* Ring full: retire the oldest range first. */
  if( FD_UNLIKELY( ctx->wb_tail-ctx->wb_head>=FD_SNAPIN_WB_RING_CNT ) ) {
    ulong idx = ctx->wb_head & (FD_SNAPIN_WB_RING_CNT-1UL);
    while( FD_UNLIKELY( -1==sync_file_range( FD_ACCDB_FD_RW, (long)ctx->wb_ring[ idx ].off, (long)ctx->wb_ring[ idx ].sz,
                                             SYNC_FILE_RANGE_WAIT_BEFORE|SYNC_FILE_RANGE_WRITE|SYNC_FILE_RANGE_WAIT_AFTER ) ) ) {
      if( FD_LIKELY( errno==EINTR ) ) continue;
      worker_wb_disable( ctx );
      return;
    }
    ctx->wb_pending -= ctx->wb_ring[ idx ].sz;
    ctx->wb_head++;
    ctx->wb_wait_cnt++;
  }

  while( FD_UNLIKELY( -1==sync_file_range( FD_ACCDB_FD_RW, (long)ctx->wb_run_off, (long)ctx->wb_run_sz, SYNC_FILE_RANGE_WRITE ) ) ) {
    if( FD_LIKELY( errno==EINTR ) ) continue;
    worker_wb_disable( ctx );
    return;
  }
  ctx->wb_ring[ ctx->wb_tail & (FD_SNAPIN_WB_RING_CNT-1UL) ] = (__typeof__(ctx->wb_ring[0])){ .off = ctx->wb_run_off, .sz = ctx->wb_run_sz };
  ctx->wb_tail++;
  ctx->wb_pending += ctx->wb_run_sz;
  ctx->wb_run_sz   = 0UL;
  ctx->wb_kick_cnt++;
}

static void
worker_wb_track( fd_snapin_tile_t * ctx,
                 ulong              off,
                 ulong              sz ) {
  if( FD_LIKELY( !ctx->wb_window ) ) return;

  if( FD_UNLIKELY( ctx->wb_run_sz && off!=ctx->wb_run_off+ctx->wb_run_sz ) ) worker_wb_kick( ctx ); /* partition rotation */
  if( FD_UNLIKELY( !ctx->wb_run_sz ) ) ctx->wb_run_off = off;
  ctx->wb_run_sz += sz;
  if( FD_UNLIKELY( ctx->wb_run_sz>=ctx->wb_kick_sz ) ) worker_wb_kick( ctx );

  /* Backstop: wait on the oldest kicked range whenever the in-flight
     window is exceeded.  That range was kicked tens of kicks ago
     (window/kick_sz), so the wait is short and kick granular: the lane
     runway rides through it where the kernel's coarse dirty-throttle
     sleeps would stall the pipe. */
  while( FD_UNLIKELY( ctx->wb_window && ctx->wb_pending>ctx->wb_window && ctx->wb_head!=ctx->wb_tail ) ) {
    ulong idx = ctx->wb_head & (FD_SNAPIN_WB_RING_CNT-1UL);
    while( FD_UNLIKELY( -1==sync_file_range( FD_ACCDB_FD_RW, (long)ctx->wb_ring[ idx ].off, (long)ctx->wb_ring[ idx ].sz,
                                             SYNC_FILE_RANGE_WAIT_BEFORE|SYNC_FILE_RANGE_WRITE|SYNC_FILE_RANGE_WAIT_AFTER ) ) ) {
      if( FD_LIKELY( errno==EINTR ) ) continue;
      worker_wb_disable( ctx );
      return;
    }
    ctx->wb_pending -= ctx->wb_ring[ idx ].sz;
    ctx->wb_head++;
    ctx->wb_wait_cnt++;
  }
}

/* Staging buffer: buffered pwrites into the tile's own accdb
   partitions.  flush_off is explicit because per-tile offsets are only
   sequential within a partition; worker_buffer_write flushes whenever
   the allocator rotates. */

static void
worker_buffer_flush( fd_snapin_tile_t * ctx ) {
  if( FD_UNLIKELY( !ctx->write_buf_used ) ) return;

  ulong sz  = ctx->write_buf_used;
  ulong off = ctx->flush_off;
  ulong bytes_written = 0UL;
  while( bytes_written<sz ) {
    long res = pwrite( FD_ACCDB_FD_RW, ctx->write_buf+bytes_written, sz-bytes_written, (long)(off+bytes_written) );
    if( FD_UNLIKELY( -1L==res ) ) {
      if( FD_LIKELY( errno==EINTR ) ) continue;
      FD_LOG_ERR(( "error writing to disk (%d-%s)", errno, fd_io_strerror( errno ) ));
    }
    bytes_written      += (ulong)res;
    ctx->bytes_written += (ulong)res;
  }
  ctx->flush_off      += sz;
  ctx->write_buf_used  = 0UL;

  worker_wb_track( ctx, off, sz );
}

static void
worker_buffer_write( fd_snapin_tile_t * ctx,
                     ulong              file_off,
                     uchar const *      data,
                     ulong              sz ) {
  /* Force a flush whenever the next offset is not the natural append
     point (first write, or the allocator rotated to a new partition). */
  if( FD_UNLIKELY( file_off!=ctx->flush_off+ctx->write_buf_used ) ) {
    worker_buffer_flush( ctx );
    ctx->flush_off = file_off;
  }
  while( sz ) {
    ulong avail = FD_SNAPIN_WRITE_BUF_SZ - ctx->write_buf_used;
    ulong n     = fd_ulong_min( sz, avail );
    fd_memcpy( ctx->write_buf + ctx->write_buf_used, data, n );
    ctx->write_buf_used += n;
    data += n;
    sz   -= n;
    if( FD_UNLIKELY( ctx->write_buf_used==FD_SNAPIN_WRITE_BUF_SZ ) ) worker_buffer_flush( ctx );
  }
}

static void
worker_stage_meta( fd_snapin_tile_t * ctx,
                   ulong              file_off,
                   uchar const *      pubkey,
                   uchar const *      owner,
                   ulong              data_len ) {
  fd_accdb_disk_meta_t meta;
  fd_memcpy( meta.pubkey, pubkey, 32UL );
  meta.size       = (uint)data_len;
  meta.generation = 0U;
  fd_memcpy( meta.owner, owner, 32UL );
  worker_buffer_write( ctx, file_off, meta.b, sizeof(fd_accdb_disk_meta_t) );
}

/* Winner-gated snoops ***********************************************/

/* A tile snoops three kinds of account: the SlotHistory sysvar (by
   pubkey) and the feature-gate and stake programs (by owner).  Only
   these are flagged as snoop candidates, so the callback never touches
   the hot insert path. */

static inline int
worker_snoop_candidate( uchar const * pubkey,
                        uchar const * owner ) {
  return !memcmp( owner,  fd_solana_feature_program_id.uc, 32UL )
      || !memcmp( owner,  fd_solana_stake_program_id.uc,   32UL )
      || !memcmp( pubkey, fd_sysvar_slot_history_id.uc,    32UL );
}

/* worker_snoop_need returns how many leading body bytes the snoops need
   from a candidate account, applying the same gates as the sequential
   loader (a gate that rejects the account outright yields 0).  It is
   always <= data_len, so the streaming path's buffer fills before the
   body ends. */

static inline ulong
worker_snoop_need( uchar const * pubkey,
                   uchar const * owner,
                   ulong         lamports,
                   ulong         data_len ) {
  if( FD_UNLIKELY( !memcmp( pubkey, fd_sysvar_slot_history_id.uc, 32UL ) ) ) {
    return data_len<=FD_SYSVAR_SLOT_HISTORY_BINCODE_SZ ? data_len : 0UL;
  }
  if( FD_UNLIKELY( !lamports ) ) return 0UL;
  if( FD_UNLIKELY( !memcmp( owner, fd_solana_feature_program_id.uc, 32UL ) ) ) {
    return fd_ulong_min( data_len, sizeof(fd_feature_t) );
  }
  if( FD_UNLIKELY( !memcmp( owner, fd_solana_stake_program_id.uc, 32UL ) ) ) {
    return data_len>=sizeof(fd_stake_state_t) ? sizeof(fd_stake_state_t) : 0UL;
  }
  return 0UL;
}

FD_STATIC_ASSERT( sizeof(fd_feature_t)    <=FD_SYSVAR_SLOT_HISTORY_BINCODE_SZ, snoop_prefix_buf );
FD_STATIC_ASSERT( sizeof(fd_stake_state_t)<=FD_SYSVAR_SLOT_HISTORY_BINCODE_SZ, snoop_prefix_buf );

/* worker_snoop_winner is the accdb snoop callback: the striped writer
   invokes it for every insert-or-replace winner the tile flagged as a
   candidate, with that account's stripe lock STILL HELD.  Because one
   pubkey always hashes to one stripe, and because equal-slot
   cross-appendvec duplicates hard-fail the load, the winners for a
   given pubkey fire serialized and in strictly increasing slot order:
   the last callback to fire is the highest-slot version, which is the
   version the sequential loader would have kept.  Writing the shared
   snoop targets only from here is therefore both race-free and
   stream-order equivalent, with no positional tiebreak needed.

   Distinct pubkeys may run here concurrently, but they only ever touch
   disjoint targets: distinct elements of the feature snoop's per-id
   arrays, or the stake-delegations struct, which serializes mutators on
   its own write lock.  That nests the stake lock inside a stripe lock;
   the order is one-way (no accdb path takes a stripe lock while holding
   the stake lock), so it cannot deadlock. */

static void
worker_snoop_winner( void * cb_ctx,
                     ulong  batch_idx ) {
  fd_snapin_tile_t * ctx = (fd_snapin_tile_t *)cb_ctx;

  uchar const * pubkey   = ctx->snoop_view.pubkeys  [ batch_idx ];
  uchar const * owner    = ctx->snoop_view.owners   [ batch_idx ];
  uchar const * data     = ctx->snoop_view.datas    [ batch_idx ];
  ulong         lamports = ctx->snoop_view.lamports [ batch_idx ];
  ulong         data_len = ctx->snoop_view.data_lens[ batch_idx ];
  ulong         data_sz  = ctx->snoop_view.data_szs [ batch_idx ];

  if( FD_UNLIKELY( !memcmp( pubkey, fd_sysvar_slot_history_id.uc, 32UL ) ) ) {
    if( FD_UNLIKELY( data_len>FD_SYSVAR_SLOT_HISTORY_BINCODE_SZ ) ) return;
    fd_snapio_snoop_hdr_t * hdr = ctx->snoop_hdr;
    hdr->slot_history.slot       = ctx->snoop_view.slot;
    hdr->slot_history.lamports   = lamports;
    hdr->slot_history.data_len   = data_len;
    hdr->slot_history.executable = ctx->snoop_view.executables[ batch_idx ];
    fd_memcpy( hdr->slot_history.owner, owner, 32UL );
    fd_memcpy( hdr->slot_history.buf, data, fd_ulong_min( data_len, data_sz ) );
    hdr->slot_history.captured   = 1;
    return;
  }

  if( FD_UNLIKELY( !memcmp( owner, fd_solana_feature_program_id.uc, 32UL ) ) ) {
    fd_feature_snoop_account( &ctx->snoop_hdr->feature_snoop, (fd_pubkey_t const *)pubkey,
                              lamports, owner, data, data_sz );
    return;
  }

  if( FD_UNLIKELY( !lamports ) ) return;

  /* Stake delegation.  Same per-account update the sequential loader
     applies, so a parallel load leaves the identical delegation set. */
  fd_stake_state_t const * stake_state = fd_stake_state_view( data, data_sz );
  if( FD_UNLIKELY( !stake_state || stake_state->stake_type!=FD_STAKE_STATE_STAKE ) ) return;

  fd_delegation_t const * delegation = &stake_state->stake.stake.delegation;
  if( FD_UNLIKELY( ( delegation->activation_epoch!=ULONG_MAX &&
                     delegation->activation_epoch>=(ulong)USHORT_MAX ) ||
                   ( delegation->deactivation_epoch!=ULONG_MAX &&
                     delegation->deactivation_epoch>=(ulong)USHORT_MAX ) ) ) return;

  fd_stake_delegations_root_update(
      ctx->stake_delegations,
      (fd_pubkey_t const *)pubkey,
      &delegation->voter_pubkey,
      delegation->stake,
      delegation->activation_epoch,
      delegation->deactivation_epoch,
      stake_state->stake.stake.credits_observed,
      lamports,
      (uint)data_len,
      /* fd_stake_delegations_refresh recomputes this after load. */
      FD_STAKE_DELEGATIONS_WARMUP_COOLDOWN_RATE_ENUM_025 );
}

static void
worker_reset_attempt( fd_snapin_tile_t * ctx ) {
  ctx->expected_frame = 0UL;
  for( ulong lane=0UL; lane<ctx->lane_cnt; lane++ ) ctx->in[ lane ].pos = 0UL;
  ctx->appendvec_seq    = 0UL;
  ctx->owned_appendvecs = 0UL;
  ctx->owned_bytes      = 0UL;
  ctx->incr_fork        = ULONG_MAX;
  ctx->gate_pending     = 0;
  worker_reset_write_engine( ctx );
  fd_memset( &ctx->worker, 0, sizeof(ctx->worker) );
  fd_memset( ctx->worker_metrics, 0, sizeof(ctx->worker_metrics) );
  ctx->pending.active            = 0;
  fd_ssparse_init( ctx->ssparse );
  fd_ssparse_batch_enable( ctx->ssparse, 1 );
  fd_ssparse_appendvec_passthrough_enable( ctx->ssparse, 1 );
  /* claimed_appendvec is deliberately NOT reset here: a fresh claim is
     drawn for every attempt when the attempt-slot gate opens, so there
     is no unclaimed sentinel to restore.

     The metrics.accounts_* gauges are likewise NOT reset here: they are
     load-session cumulative, not attempt scoped, so that the cross-tile
     sum the dashboards take never dips.  The INIT handler rebases them
     (see the struct comment).

     my_snoop's fail_partition_cnt is likewise NOT touched -- only the
     owning tile's FAIL handler stamps it and only tile 0 clears it (at
     the deferred-rollback gather), because INIT barriers complete in
     arbitrary tile order and a tile zeroing its own list at INIT would
     race tile 0's gather.  The shared next_appendvec, totals and
     winner-gated snoop targets are re-zeroed once by tile 0 in its INIT
     critical sequence, not per-tile here. */
}

/* worker_record_insert_metrics folds the outcome of one accepted
   accdb insert call (cnt accounts) into this tile's gauges and into
   its share of the cross-tile fold.  Call it only once the insert
   succeeded: a malformed batch leaves every counter untouched. */

static inline void
worker_record_insert_metrics( fd_snapin_tile_t * ctx,
                              ulong              cnt,
                              ulong              accounts_ignored,
                              ulong              accounts_replaced,
                              ulong              accounts_loaded,
                              ulong              input_lamports,
                              ulong              replaced_lamports,
                              ulong              ignored_lamports ) {
  ctx->metrics.accounts_ignored  += accounts_ignored;
  ctx->metrics.accounts_replaced += accounts_replaced;
  ctx->metrics.accounts_loaded   += accounts_loaded;
  ctx->metrics.total_accounts_processed += cnt;
  ctx->metrics.total_account_batches_processed++;
  ctx->worker.accounts_ignored  += accounts_ignored;
  ctx->worker.accounts_replaced += accounts_replaced;
  ctx->worker.accounts_loaded   += accounts_loaded;
  ctx->worker.input_lamports    = fd_ulong_sat_add( ctx->worker.input_lamports,    input_lamports    );
  ctx->worker.replaced_lamports = fd_ulong_sat_add( ctx->worker.replaced_lamports, replaced_lamports );
  ctx->worker.ignored_lamports  = fd_ulong_sat_add( ctx->worker.ignored_lamports,  ignored_lamports  );
}

static int
worker_process_account_batch( fd_snapin_tile_t *            ctx,
                              fd_ssparse_advance_result_t * result ) {
  uchar const * const * entries    = result->account_batch.batch;
  ulong                 cnt        = result->account_batch.batch_cnt;
  ulong                 batch_slot = result->account_batch.slot;

  uchar const * pubkeys     [ FD_SSPARSE_ACC_BATCH_MAX ] = {0};
  uchar const * owners      [ FD_SSPARSE_ACC_BATCH_MAX ] = {0};
  uchar const * datas       [ FD_SSPARSE_ACC_BATCH_MAX ] = {0};
  ulong         lamports    [ FD_SSPARSE_ACC_BATCH_MAX ] = {0};
  ulong         data_lens   [ FD_SSPARSE_ACC_BATCH_MAX ] = {0};
  int           executables [ FD_SSPARSE_ACC_BATCH_MAX ] = {0};
  int           candidates  [ FD_SSPARSE_ACC_BATCH_MAX ] = {0};
  ulong         file_offsets[ FD_SSPARSE_ACC_BATCH_MAX ] = {0};

  ulong batch_lamports = 0UL;
  for( ulong i=0UL; i<cnt; i++ ) {
    uchar const * e = entries[ i ];
    pubkeys[ i ]     = e + 16UL;
    owners[ i ]      = e + 64UL;
    datas[ i ]       = e + 136UL; /* batch bodies are contiguous */
    lamports[ i ]    = fd_ulong_load_8_fast( e+48UL );
    data_lens[ i ]   = fd_ulong_load_8_fast( e+8UL );
    executables[ i ] = e[ 96UL ];
    candidates[ i ]  = worker_snoop_candidate( pubkeys[ i ], owners[ i ] );
    batch_lamports   = fd_ulong_sat_add( batch_lamports, lamports[ i ] );
  }

  ctx->snoop_view.slot        = batch_slot;
  ctx->snoop_view.pubkeys     = pubkeys;
  ctx->snoop_view.owners      = owners;
  ctx->snoop_view.datas       = datas;
  ctx->snoop_view.lamports    = lamports;
  ctx->snoop_view.data_lens   = data_lens;
  ctx->snoop_view.data_szs    = data_lens;
  ctx->snoop_view.executables = executables;

  ulong accounts_ignored, accounts_replaced, accounts_loaded, replaced_lamports, ignored_lamports;
  fd_accdb_fork_id_t fork_id = { .val = ctx->full ? USHORT_MAX : (ushort)ctx->incr_fork };
  if( FD_UNLIKELY( 0!=fd_accdb_snapshot_write_batch_worker( ctx->accdb, fork_id, cnt, pubkeys, batch_slot, lamports,
                                                            data_lens, executables, candidates, &ctx->whead,
                                                            ctx->stripe_locks, FD_SNAPIO_STRIPE_MSK, ctx->worker_metrics,
                                                            file_offsets, &accounts_ignored, &accounts_replaced,
                                                            &accounts_loaded, &replaced_lamports, &ignored_lamports,
                                                            worker_snoop_winner, ctx ) ) ) {
    return -1;
  }

  /* Stage the accepted disk records (72 byte header + data, packed at
     the allocated explicit offsets; ignored dups burn no space). */
  for( ulong i=0UL; i<cnt; i++ ) {
    if( FD_UNLIKELY( file_offsets[ i ]==ULONG_MAX ) ) continue;
    worker_stage_meta( ctx, file_offsets[ i ], pubkeys[ i ], owners[ i ], data_lens[ i ] );
    if( FD_LIKELY( data_lens[ i ] ) ) {
      worker_buffer_write( ctx, file_offsets[ i ]+sizeof(fd_accdb_disk_meta_t), datas[ i ], data_lens[ i ] );
    }
  }

  worker_record_insert_metrics( ctx, cnt, accounts_ignored, accounts_replaced, accounts_loaded,
                                batch_lamports, replaced_lamports, ignored_lamports );

  return 0;
}

/* worker_insert_one inserts a single streamed account, stages its meta
   record and opens the tile's body-write window.  candidate flags the
   account for the snoop callback, in which case data[0,data_sz) is the
   body prefix the snoops read (see ctx->pending). */

static int
worker_insert_one( fd_snapin_tile_t * ctx,
                   uchar const *      pubkey,
                   uchar const *      owner,
                   ulong              slot,
                   ulong              lamports,
                   ulong              data_len,
                   int                executable,
                   int                candidate,
                   uchar const *      data,
                   ulong              data_sz ) {
  uchar const * pubkeys     [ 1 ] = { pubkey };
  uchar const * owners      [ 1 ] = { owner };
  uchar const * datas       [ 1 ] = { data };
  ulong         lamports_a  [ 1 ] = { lamports };
  ulong         data_lens   [ 1 ] = { data_len };
  ulong         data_szs    [ 1 ] = { data_sz };
  int           executables [ 1 ] = { executable };
  int           candidates  [ 1 ] = { candidate };
  ulong         file_offsets[ 1 ];

  ctx->snoop_view.slot        = slot;
  ctx->snoop_view.pubkeys     = pubkeys;
  ctx->snoop_view.owners      = owners;
  ctx->snoop_view.datas       = datas;
  ctx->snoop_view.lamports    = lamports_a;
  ctx->snoop_view.data_lens   = data_lens;
  ctx->snoop_view.data_szs    = data_szs;
  ctx->snoop_view.executables = executables;

  ulong accounts_ignored, accounts_replaced, accounts_loaded, replaced_lamports, ignored_lamports;
  fd_accdb_fork_id_t fork_id = { .val = ctx->full ? USHORT_MAX : (ushort)ctx->incr_fork };
  if( FD_UNLIKELY( 0!=fd_accdb_snapshot_write_batch_worker( ctx->accdb, fork_id, 1UL, pubkeys, slot, lamports_a,
                                                            data_lens, executables, candidates, &ctx->whead,
                                                            ctx->stripe_locks, FD_SNAPIO_STRIPE_MSK, ctx->worker_metrics,
                                                            file_offsets, &accounts_ignored, &accounts_replaced,
                                                            &accounts_loaded, &replaced_lamports, &ignored_lamports,
                                                            worker_snoop_winner, ctx ) ) ) {
    return -1;
  }
  int ignored = file_offsets[ 0 ]==ULONG_MAX;

  ctx->open_acc.accepted = !ignored;
  ctx->open_acc.received = 0UL;
  ctx->open_acc.file_off = file_offsets[ 0 ];
  if( FD_LIKELY( !ignored ) ) worker_stage_meta( ctx, file_offsets[ 0 ], pubkey, owner, data_len );

  worker_record_insert_metrics( ctx, 1UL, accounts_ignored, accounts_replaced, accounts_loaded,
                                lamports, replaced_lamports, ignored_lamports );

  return 0;
}

/* worker_pending_flush issues the held-back insert of a snoop candidate
   now that its body prefix is buffered, then stages that prefix; the
   rest of the body streams normally from here. */

static int
worker_pending_flush( fd_snapin_tile_t * ctx ) {
  ctx->pending.active = 0;
  if( FD_UNLIKELY( 0!=worker_insert_one( ctx, ctx->pending.pubkey, ctx->pending.owner, ctx->pending.slot,
                                         ctx->pending.lamports, ctx->pending.data_len, ctx->pending.executable,
                                         1, ctx->pending.buf, ctx->pending.write_pos ) ) ) return -1;
  if( FD_LIKELY( ctx->open_acc.accepted && ctx->pending.write_pos ) ) {
    worker_buffer_write( ctx, ctx->open_acc.file_off+sizeof(fd_accdb_disk_meta_t),
                         ctx->pending.buf, ctx->pending.write_pos );
  }
  ctx->open_acc.received = ctx->pending.write_pos;
  return 0;
}

static int
worker_process_account_header( fd_snapin_tile_t *            ctx,
                               fd_ssparse_advance_result_t * result ) {
  uchar const * pubkey   = result->account_header.pubkey;
  uchar const * owner    = result->account_header.owner;
  ulong         lamports = result->account_header.lamports;
  ulong         data_len = result->account_header.data_len;

  if( FD_LIKELY( !worker_snoop_candidate( pubkey, owner ) ) ) {
    return worker_insert_one( ctx, pubkey, owner, result->account_header.slot, lamports, data_len,
                              result->account_header.executable, 0, NULL, 0UL );
  }

  /* Snoop candidate: hold the insert back until the prefix the snoops
     need has been buffered, so the callback can write the shared
     targets with the stripe lock held. */
  ctx->pending.active     = 1;
  ctx->pending.executable = result->account_header.executable;
  ctx->pending.slot       = result->account_header.slot;
  ctx->pending.lamports   = lamports;
  ctx->pending.data_len   = data_len;
  ctx->pending.need       = worker_snoop_need( pubkey, owner, lamports, data_len );
  ctx->pending.write_pos  = 0UL;
  fd_memcpy( ctx->pending.pubkey, pubkey, 32UL );
  fd_memcpy( ctx->pending.owner,  owner,  32UL );
  if( FD_UNLIKELY( !ctx->pending.need ) ) return worker_pending_flush( ctx );
  return 0;
}

/* Returns 0 on success, -1 on a failure that must fail the attempt. */

static int
worker_process_account_data( fd_snapin_tile_t *            ctx,
                             fd_ssparse_advance_result_t * result ) {
  uchar const * data    = result->account_data.data;
  ulong         data_sz = result->account_data.data_sz;

  if( FD_UNLIKELY( ctx->pending.active ) ) {
    ulong copy_sz = fd_ulong_min( data_sz, ctx->pending.need-ctx->pending.write_pos );
    fd_memcpy( ctx->pending.buf+ctx->pending.write_pos, data, copy_sz );
    ctx->pending.write_pos += copy_sz;
    if( FD_UNLIKELY( ctx->pending.write_pos<ctx->pending.need ) ) return 0;
    if( FD_UNLIKELY( 0!=worker_pending_flush( ctx ) ) ) return -1;
    data    += copy_sz;
    data_sz -= copy_sz;
    if( FD_LIKELY( !data_sz ) ) return 0;
  }

  if( FD_LIKELY( ctx->open_acc.accepted ) ) {
    worker_buffer_write( ctx, ctx->open_acc.file_off+sizeof(fd_accdb_disk_meta_t)+ctx->open_acc.received,
                         data, data_sz );
  }
  ctx->open_acc.received += data_sz;
  return 0;
}

static int
handle_data_frag( fd_snapin_tile_t *  ctx,
                  ulong               in_idx,
                  ulong               chunk,
                  ulong               sz,
                  fd_stem_context_t * stem ) {
  if( FD_UNLIKELY( ctx->state==FD_SNAPSHOT_STATE_FINISHING ) ) {
    FD_LOG_WARNING(( "received unexpected data frag while in state %s (%lu)",
                     fd_ssctrl_state_str( (ulong)ctx->state ), (ulong)ctx->state  ));
    transition_malformed( ctx, stem );
    return 0;
  }
  if( FD_UNLIKELY( ctx->state==FD_SNAPSHOT_STATE_ERROR ) ) {
    /* Ignore all data frags after observing an error in the stream until
       we receive fail & init control messages to restart processing. */
    return 0;
  }
  if( FD_UNLIKELY( ctx->state!=FD_SNAPSHOT_STATE_PROCESSING ) ) {
    FD_LOG_ERR(( "received data frag during invalid state %s (%lu)",
                 fd_ssctrl_state_str( (ulong)ctx->state ), (ulong)ctx->state ));
  }

  if( FD_UNLIKELY( chunk<ctx->in[ in_idx ].chunk0 || chunk>ctx->in[ in_idx ].wmark || sz>ctx->in[ in_idx ].mtu ) ) {
    FD_LOG_ERR(( "invalid data frag bounds (chunk=%lu chunk0=%lu wmark=%lu sz=%lu mtu=%lu)", chunk, ctx->in[ in_idx ].chunk0, ctx->in[ in_idx ].wmark, sz, ctx->in[ in_idx ].mtu ));
  }

  for(;;) {
    if( FD_UNLIKELY( sz-ctx->in[ in_idx ].pos==0UL ) ) break;

    uchar const * data = (uchar const *)fd_chunk_to_laddr_const( ctx->in[ in_idx ].wksp, chunk ) + ctx->in[ in_idx ].pos;

    int early_exit = 0;
    fd_ssparse_advance_result_t result[1];
    int res = fd_ssparse_advance( ctx->ssparse, data, sz-ctx->in[ in_idx ].pos, result );
    switch( res ) {
      case FD_SSPARSE_ADVANCE_ERROR:
        FD_LOG_WARNING(( "error while parsing snapshot stream" ));
        transition_malformed( ctx, stem );
        return 0;
      case FD_SSPARSE_ADVANCE_AGAIN:
        break;
      case FD_SSPARSE_ADVANCE_APPENDVEC: {
        /* Tar-boundary sharding: each appendvec is owned by exactly one
           tile.  Owned: flip the passthrough parser into parsing this
           one appendvec's accounts in-stream.  Not owned: the garbage
           skipper consumes the body arithmetically. */
        ulong av_idx = ctx->appendvec_seq++;
        if( FD_UNLIKELY( is_lead( ctx ) ) ) {
          ulong body_sz = result->appendvec.data_sz;
          ctx->av_stats.cnt++;
          ctx->av_stats.bytes += body_sz;
          ctx->av_stats.max_sz = fd_ulong_max( ctx->av_stats.max_sz, body_sz );
          if( FD_UNLIKELY( body_sz>(64UL<<20) ) )  ctx->av_stats.over_64m_cnt++;
          if( FD_UNLIKELY( body_sz>(256UL<<20) ) ) ctx->av_stats.over_256m_bytes += body_sz;
          ctx->av_stats.log2_hist[ fd_ulong_min( (ulong)fd_ulong_find_msb( fd_ulong_max( body_sz, 1UL ) ), 47UL ) ]++;
        }
        if( FD_UNLIKELY( av_idx==ctx->claimed_appendvec ) ) {
          /* Claim the next appendvec before parsing this one: the counter is
             already past av_idx (it handed av_idx to us), so a fresh claim can
             never land behind our walk position.  The tar format streams the
             whole manifest before any appendvec, so tile 0 reaches this point
             only after its manifest parse -- other tiles absorb the early
             appendvecs without any special case. */
          ctx->claimed_appendvec = FD_ATOMIC_FETCH_AND_ADD( &ctx->snoop_hdr->next_appendvec, 1UL );
          ctx->owned_appendvecs++;
          fd_ssparse_appendvec_parse( ctx->ssparse );
          ctx->owned_bytes += result->appendvec.data_sz;
        }
        break;
      }
      case FD_SSPARSE_ADVANCE_REGION:
        /* Non-appendvec tar entry (version/manifest/status cache);
           nothing to do at header time. */
        break;
      case FD_SSPARSE_ADVANCE_MANIFEST:
      case FD_SSPARSE_ADVANCE_MANIFEST_DONE: {
        if( FD_LIKELY( !is_lead( ctx ) ) ) break; /* only tile 0 parses the manifest */
        if( FD_UNLIKELY( ctx->flags.manifest_done ) ) {
          FD_LOG_WARNING(( "excess data after manifest" ));
          transition_malformed( ctx, stem );
          return 0;
        }
        int parser_res = fd_ssmanifest_parser_consume( ctx->manifest_parser,
                                                       result->manifest.data,
                                                       result->manifest.data_sz );
        if( FD_UNLIKELY( parser_res==FD_SSMANIFEST_PARSER_ADVANCE_ERROR ) ) {
          FD_LOG_WARNING(( "error while parsing snapshot manifest" ));
          transition_malformed( ctx, stem );
          return 0;
        }
        if( res==FD_SSPARSE_ADVANCE_MANIFEST_DONE ) {
          if( FD_UNLIKELY( fd_ssmanifest_parser_fini( ctx->manifest_parser )!=FD_SSMANIFEST_PARSER_ADVANCE_DONE ) ) {
            FD_LOG_WARNING(( "manifest stream ended before parser was done" ));
            transition_malformed( ctx, stem );
            return 0;
          }
          ctx->flags.manifest_done = 1;
        }
        break;
      }
      case FD_SSPARSE_ADVANCE_STATUS_CACHE: {
        if( FD_LIKELY( !is_lead( ctx ) ) ) break; /* only tile 0 parses the status cache */
        fd_slot_delta_parser_advance_result_t sd_result[1];
        ulong bytes_remaining = result->status_cache.data_sz;

        while( bytes_remaining ) {
          int res = fd_slot_delta_parser_consume( ctx->slot_delta_parser,
                                                  result->status_cache.data,
                                                  bytes_remaining,
                                                  sd_result );
          if( FD_UNLIKELY( res<0 ) ) {
            FD_LOG_WARNING(( "error while parsing slot deltas in status cache" ));
            transition_malformed( ctx, stem );
            return 0;
          } else if( FD_LIKELY( res==FD_SLOT_DELTA_PARSER_ADVANCE_SLOT ) ) {
            /* If we're parsing a new slot, add th new slot if we
               haven't parsed 151 slots yet.  Otherwise ignore or evict
               slots that are too old.  */
            ulong candidate_idx;
            if( FD_LIKELY( ctx->txncache_slots_len<FD_TXNCACHE_MAX_SLOT_DELTAS ) ) {
              candidate_idx = ctx->txncache_slots_len++;
            } else {
              candidate_idx = 0UL;
              for( ulong i=1UL; i<FD_TXNCACHE_MAX_SLOT_DELTAS; i++ ) {
                if( ctx->txncache_slots[ i ].slot<ctx->txncache_slots[ candidate_idx ].slot ) candidate_idx = i;
              }
              if( FD_UNLIKELY( sd_result->slot<ctx->txncache_slots[ candidate_idx ].slot ) ) candidate_idx = ULONG_MAX;
            }

            if( FD_LIKELY( candidate_idx!=ULONG_MAX ) ) {
              ctx->txncache_slots[ candidate_idx ].slot      = sd_result->slot;
              ctx->txncache_slots[ candidate_idx ].entry_cnt = 0UL;
            }
            ctx->txncache_current_slot_idx       = candidate_idx;
            ctx->txncache_current_slot_entry_cnt = 0UL;
          } else if( FD_LIKELY( res==FD_SLOT_DELTA_PARSER_ADVANCE_GROUP ) ) {
            if( FD_UNLIKELY( ctx->blockhash_groups_len>=FD_SNAPIN_MAX_SLOT_DELTA_GROUPS ) ) {
              FD_LOG_WARNING(( "blockhash groups overflow, max is %lu", FD_SNAPIN_MAX_SLOT_DELTA_GROUPS ));
              transition_malformed( ctx, stem );
              return 0;
            }

            blockhash_group_t * group = &ctx->blockhash_groups[ ctx->blockhash_groups_len++ ];
            memcpy( group->blockhash, sd_result->group.blockhash, 32UL );
            group->slot               = sd_result->group.slot;
            group->txnhash_offset     = sd_result->group.txnhash_offset;
            group->txncache_entry_cnt = 0UL;

            /* Ignore the group if its corresponding slot is too old.
               Otherwise record which entry to start looking at. */
            ulong slot_idx = ctx->txncache_current_slot_idx;
            if( FD_UNLIKELY( slot_idx==ULONG_MAX ) ) {
              group->txncache_entry_idx = ULONG_MAX;
            } else {
              FD_TEST( slot_idx<ctx->txncache_slots_len );
              FD_TEST( ctx->txncache_slots[ slot_idx ].slot==group->slot );
              group->txncache_entry_idx = slot_idx*FD_PACK_MAX_TXNCACHE_TXN_PER_SLOT+ctx->txncache_slots[ slot_idx ].entry_cnt;
            }
          } else if( FD_LIKELY( res==FD_SLOT_DELTA_PARSER_ADVANCE_ENTRY ) ) {
            FD_TEST( ctx->blockhash_groups_len );
            blockhash_group_t * group = &ctx->blockhash_groups[ ctx->blockhash_groups_len-1UL ];
            FD_TEST( group->slot==sd_result->entry->slot );

            if( FD_UNLIKELY( ctx->txncache_current_slot_entry_cnt>=FD_PACK_MAX_TXNCACHE_TXN_PER_SLOT ) ) {
              FD_LOG_WARNING(( "txncache entries overflow for slot %lu, max is %lu",
                               group->slot, FD_PACK_MAX_TXNCACHE_TXN_PER_SLOT ));
              transition_malformed( ctx, stem );
              return 0;
            }
            ctx->txncache_current_slot_entry_cnt++;

            /* Record the entry iff it corresponds to a valid slot. */
            ulong slot_idx = ctx->txncache_current_slot_idx;
            if( FD_LIKELY( slot_idx!=ULONG_MAX ) ) {
              FD_TEST( slot_idx<ctx->txncache_slots_len );
              txncache_staging_slot_t * staging_slot = &ctx->txncache_slots[ slot_idx ];
              FD_TEST( staging_slot->slot==group->slot );
              FD_TEST( staging_slot->entry_cnt<FD_PACK_MAX_TXNCACHE_TXN_PER_SLOT );
              ulong entry_idx = slot_idx*FD_PACK_MAX_TXNCACHE_TXN_PER_SLOT+staging_slot->entry_cnt;
              FD_TEST( entry_idx==group->txncache_entry_idx+group->txncache_entry_cnt );
              memcpy( ctx->txncache_entries[ entry_idx ].txnhash, sd_result->entry->txnhash, sizeof(fd_sstxncache_hash_t) );
              staging_slot->entry_cnt++;
              group->txncache_entry_cnt++;
            }
          }

          bytes_remaining           -= sd_result->bytes_consumed;
          result->status_cache.data += sd_result->bytes_consumed;
        }

        if( FD_UNLIKELY( result->status_cache.done ) ) {
          int fini_res = fd_slot_delta_parser_consume( ctx->slot_delta_parser, result->status_cache.data, 0UL, sd_result );
          if( FD_UNLIKELY( fini_res<0 ) ) {
            FD_LOG_WARNING(( "error while finalizing slot deltas in status cache" ));
            transition_malformed( ctx, stem );
            return 0;
          }
          ctx->flags.status_cache_done = fini_res==FD_SLOT_DELTA_PARSER_ADVANCE_DONE;
        }
        break;
      }
      case FD_SSPARSE_ADVANCE_ACCOUNT_HEADER:
        early_exit = worker_process_account_header( ctx, result );
        if( FD_UNLIKELY( early_exit<0 ) ) {
          transition_malformed( ctx, stem );
          return 0;
        }

        /* TODO(parallel snapshot load): with tar-boundary sharding each
           tile only sees account bytes for its owned appendvecs, so
           this ConfigProgram capture (validator name/icon for the GUI)
           only fires for tile-0-owned appendvecs and snapin_gui is
           effectively silent until gossip/replay refresh the info.
           Unlike the other snoops it cannot ride the accdb callback:
           the payload has to reach snapin_gui as a link publish, which
           may not happen with a stripe lock held. */
        if( FD_UNLIKELY( ctx->gui_out.idx!=ULONG_MAX
                      && !memcmp( result->account_header.owner, fd_solana_config_program_id.key, sizeof(fd_hash_t) )
                      && result->account_header.data_len
                      && result->account_header.data_len<=FD_GUI_CONFIG_PARSE_MAX_VALID_ACCT_SZ ) ) {
          ctx->gui_config_acct_sz  = result->account_header.data_len;
          ctx->gui_config_acct_off = 0UL;
        } else {
          ctx->gui_config_acct_sz  = 0UL;
        }
        break;
      case FD_SSPARSE_ADVANCE_ACCOUNT_DATA:
        early_exit = worker_process_account_data( ctx, result );
        if( FD_UNLIKELY( early_exit<0 ) ) {
          transition_malformed( ctx, stem );
          return 0;
        }

        /* Account data may span multiple input chunks (when an account
           straddles a decompressed chunk boundary), so we copy each
           piece into the gui_out dcache and only publish once the full
           account has been received.

           We expect ConfigKeys Vec to be length 2 (checked via the
           first byte of the accumulated data).  We expect the size of
           ConfigProgram-owned accounts to be at most
           FD_GUI_CONFIG_PARSE_MAX_VALID_ACCT_SZ, since this is the
           size that the Solana CLI allocates for them. Although the
           ConfigProgram itself does not enforce these invariants, the
           vast majority of accounts (with a tiny number of exceptions
           on devnet) are maintained with the Solana CLI. */
        if( FD_UNLIKELY( ctx->gui_config_acct_sz ) ) {
          uchar * acct = fd_chunk_to_laddr( ctx->gui_out.mem, ctx->gui_out.chunk );
          fd_memcpy( acct + ctx->gui_config_acct_off, result->account_data.data, result->account_data.data_sz );
          ctx->gui_config_acct_off += result->account_data.data_sz;

          if( FD_LIKELY( ctx->gui_config_acct_off>=ctx->gui_config_acct_sz ) ) {
            ctx->gui_config_acct_sz = 0UL;
            if( FD_LIKELY( acct[ 0 ]==2UL ) ) {
              fd_stem_publish( stem, ctx->gui_out.idx, 0UL, ctx->gui_out.chunk, ctx->gui_config_acct_off, 0UL, 0UL, 0UL );
              ctx->gui_out.chunk = fd_dcache_compact_next( ctx->gui_out.chunk, ctx->gui_config_acct_off, ctx->gui_out.chunk0, ctx->gui_out.wmark );
              early_exit = 1;
            }
          }
        }
        break;
      case FD_SSPARSE_ADVANCE_ACCOUNT_BATCH:
        early_exit = worker_process_account_batch( ctx, result );
        if( FD_UNLIKELY( early_exit<0 ) ) {
          transition_malformed( ctx, stem );
          return 0;
        }
        break;
      case FD_SSPARSE_ADVANCE_DONE:
        ctx->state = FD_SNAPSHOT_STATE_FINISHING;
        break;
      default:
        FD_LOG_ERR(( "unexpected fd_ssparse_advance result %d", res ));
        break;
    }

    if( FD_UNLIKELY( !ctx->flags.manifest_processed && ctx->flags.manifest_done && ctx->flags.status_cache_done ) ) {
      process_manifest( ctx, stem );
      if( FD_UNLIKELY( ctx->state==FD_SNAPSHOT_STATE_ERROR ) ) break;
      ctx->flags.manifest_processed = 1;
    }

    ctx->in[ in_idx ].pos += result->bytes_consumed;
    if( FD_LIKELY( ctx->full ) ) ctx->metrics.full_bytes_read        += result->bytes_consumed;
    else                         ctx->metrics.incremental_bytes_read += result->bytes_consumed;

    if( FD_UNLIKELY( early_exit ) ) break;
  }

  int reprocess_frag = ctx->in[ in_idx ].pos<sz;
  if( FD_LIKELY( !reprocess_frag ) ) ctx->in[ in_idx ].pos = 0UL;
  return reprocess_frag;
}

/* Tile-0 end-of-load work ********************************************/

/* Read out the shared totals and the winner-gated snoop targets.  They
   are valid only after all FINI acks: snapct publishes NEXT/DONE only
   once every tile acked FINI, and each tile folds its counters into
   `totals` (and last wins the snoop targets) before that ack.  There is
   nothing per-tile left to gather -- hdr->totals is already the
   cross-tile sum and hdr->slot_history/hdr->feature_snoop are already
   the single winner-gated copy. */

static void
tile0_fold_attempt( fd_snapin_tile_t * ctx ) {
  if( FD_UNLIKELY( ctx->attempt_folded ) ) return;
  ctx->attempt_folded = 1;

  fd_snapio_totals_t const * totals = &ctx->snoop_hdr->totals;

  /* Eager claim: every appendvec in the stream was claimed by exactly
     one tile, and every tile ends the attempt holding exactly one
     unmatched claim. */
  FD_TEST( totals->appendvecs_processed==ctx->appendvec_seq );
  FD_TEST( ctx->snoop_hdr->next_appendvec==ctx->appendvec_seq+ctx->snoop_hdr->worker_cnt );

  /* Cross-tile account totals, for the end-of-load log and nothing
     else.  totals is re-zeroed at every INIT and this runs only on a
     successful attempt, so accumulating gives the load-session sum.
     Deliberately not written into ctx->metrics: the gauges are summed
     across all snapin tiles by the dashboards, and folding the total
     into tile 0's gauge would double count every other tile. */
  ctx->totals_fold.accounts_loaded   += totals->accounts_loaded;
  ctx->totals_fold.accounts_replaced += totals->accounts_replaced;
  ctx->totals_fold.accounts_ignored  += totals->accounts_ignored;

  ctx->capitalization = fd_ulong_if( ctx->full, 0UL, ctx->recovery.capitalization );
  ctx->capitalization = fd_ulong_sat_add( ctx->capitalization, totals->input_lamports   );
  ctx->capitalization = fd_ulong_sat_sub( ctx->capitalization, totals->ignored_lamports );
  ctx->dup_capitalization = totals->replaced_lamports;
  ctx->worker_fold.eq_slot_dups          += totals->eq_slot_dups;
  ctx->worker_fold.eq_slot_lamports_diff += totals->eq_slot_lamports_diff;
  ctx->worker_fold.bytes_written         += totals->bytes_written;

  /* Slot history: hdr already holds the single winner-gated copy. */
  fd_snapio_snoop_hdr_t const * hdr = ctx->snoop_hdr;
  if( FD_LIKELY( hdr->slot_history.captured ) ) {
    ctx->slot_history.captured   = 1;
    ctx->slot_history.slot       = hdr->slot_history.slot;
    ctx->slot_history.lamports   = hdr->slot_history.lamports;
    ctx->slot_history.data_len   = hdr->slot_history.data_len;
    ctx->slot_history.executable = hdr->slot_history.executable;
    fd_memcpy( ctx->slot_history.owner, hdr->slot_history.owner, 32UL );
    fd_memcpy( ctx->slot_history.buf, hdr->slot_history.buf, hdr->slot_history.data_len );
  }

  /* Features: merge this attempt's winner-gated copy over the carried
     state, per id.  hdr->feature_snoop is zeroed at every INIT, so an
     incremental attempt only overrides the ids whose accounts it
     actually streamed -- the sequential loader likewise accumulates
     into one snoop across the full and incremental loads. */
  for( ulong i=0UL; i<FD_FEATURE_SNOOP_CNT; i++ ) {
    if( FD_LIKELY( !hdr->feature_snoop.present[ i ] ) ) continue;
    ctx->feature_snoop->present        [ i ] = 1;
    ctx->feature_snoop->is_active      [ i ] = hdr->feature_snoop.is_active      [ i ];
    ctx->feature_snoop->activation_slot[ i ] = hdr->feature_snoop.activation_slot[ i ];
  }
}

/* Order-independent checksums of the snooped state.  The parallel
   loader must reproduce them exactly against a single-tile run of the
   same snapshot. */

static void
log_snoop_checksums( fd_snapin_tile_t * ctx ) {
  fd_stake_delegations_t * sd = ctx->stake_delegations;
  fd_stake_delegation_t const * root_pool  = fd_type_pun_const( (uchar const *)sd + sd->pool_offset_ );
  fd_stake_delegation_t const * delta_pool = fd_type_pun_const( (uchar const *)sd + sd->delta_pool_offset_ );
  ulong stake_cs  = 0UL;
  ulong stake_cnt = 0UL;
  for( ulong i=0UL; i<sd->pool_idx_wmk_; i++ ) {
    fd_stake_delegation_t const * d = &root_pool[ i ];
    if( !d->in_use ) continue;
    if( d->delta_idx!=UINT_MAX ) d = &delta_pool[ d->delta_idx ];
    if( d->is_tombstone ) continue;
    ulong h = fd_hash( 0x57A4EUL, d->stake_account.uc, 32UL );
    h = fd_hash( h, d->vote_account.uc, 32UL );
    ulong nums[ 6 ] = { d->stake, d->lamports, d->credits_observed,
                        (ulong)d->activation_epoch, (ulong)d->deactivation_epoch, (ulong)d->acc_dlen };
    h = fd_hash( h, nums, sizeof(nums) );
    stake_cs += h; /* commutative: iteration order independent */
    stake_cnt++;
  }
  ulong feature_cs = fd_hash( 0xFEA7UL, ctx->feature_snoop, sizeof(fd_feature_snoop_t) );
  ulong sh_cs      = ctx->slot_history.captured ? fd_hash( 0x5107UL, ctx->slot_history.buf, ctx->slot_history.data_len ) : 0UL;
  FD_LOG_NOTICE(( "snoop A/B: stake_cnt=%lu stake_cs=%016lx feature_cs=%016lx slot_history_slot=%lu slot_history_cs=%016lx",
                  stake_cnt, stake_cs, feature_cs, ctx->slot_history.captured ? ctx->slot_history.slot : 0UL, sh_cs ));
}

/* Appendvec count and size distribution.  An appendvec is parseable
   only sequentially by its owning tile, so any appendvec larger than
   the in-flight lane window forces the whole pipe down to one tile's
   fused rate for its duration; these numbers bound that tax. */

static void
log_appendvec_stats( fd_snapin_tile_t * ctx ) {
  if( FD_UNLIKELY( !ctx->av_stats.cnt ) ) return;

  /* Approximate percentiles from the log2 histogram (upper bucket
     bound). */
  ulong p50 = 0UL, p90 = 0UL;
  ulong seen = 0UL;
  for( ulong b=0UL; b<48UL; b++ ) {
    seen += ctx->av_stats.log2_hist[ b ];
    if( !p50 && seen*2UL >=      ctx->av_stats.cnt ) p50 = 2UL<<b;
    if( !p90 && seen*10UL>= 9UL*ctx->av_stats.cnt  ) p90 = 2UL<<b;
  }
  FD_LOG_NOTICE(( "appendvecs: cnt=%lu total=%.1f GiB avg=%.1f MiB p50<=%lu p90<=%lu max=%lu, >64MiB cnt=%lu, >256MiB bytes=%.1f GiB",
                  ctx->av_stats.cnt,
                  (double)ctx->av_stats.bytes/(double)(1UL<<30),
                  (double)ctx->av_stats.bytes/(double)ctx->av_stats.cnt/(double)(1UL<<20),
                  p50, p90, ctx->av_stats.max_sz,
                  ctx->av_stats.over_64m_cnt,
                  (double)ctx->av_stats.over_256m_bytes/(double)(1UL<<30) ));
}

/* Tile 0's deferred rollback of a failed attempt, run at the retry's
   INIT barrier before the attempt's normal accdb work.  Every tile has
   provably quiesced: snapct published this INIT only after ALL FAIL
   acks, and each tile acked FAIL only after its worker-side teardown
   (including writer_end).  No tile can start the NEW attempt's
   allocations or inserts concurrently either: its first insert is
   gated on the attempt slot, which tile 0 publishes only after this
   rollback and its INIT work completed. */

static void
tile0_rollback_failed_attempt( fd_snapin_tile_t * ctx,
                               int                retry_full ) {
  ctx->rollback.pending = 0;

  /* Gather the tiles' per-attempt partition lists.  They are released
     once the purge below has completed: attach_child at this INIT_INCR
     waits for it; a failed FULL attempt instead releases everything
     via fd_accdb_reset at this INIT_FULL. */
  for( ulong w=0UL; w<ctx->tile_cnt; w++ ) {
    fd_snapio_worker_t * ws = ctx->snoops[ w ];
    for( ulong i=0UL; i<ws->fail_partition_cnt; i++ ) {
      FD_TEST( ctx->doomed_partition_cnt<FD_SNAPIO_FAIL_PARTITION_MAX );
      ctx->doomed_partitions[ ctx->doomed_partition_cnt++ ] = ws->fail_partitions[ i ];
    }
    ws->fail_partition_cnt = 0UL;
  }

  if( !ctx->rollback.full ) {
    /* Purge the failed incremental fork (and subsequent children); the
       attach_child at this INIT_INCR waits for it before the doomed
       partitions are released.  When the retry is a full load instead,
       skip the purge: fd_accdb_reset wipes the fork (and reclaims every
       partition) wholesale, and must not run concurrently with an
       in-flight background purge. */
    if( FD_LIKELY( !retry_full ) ) fd_accdb_purge( ctx->accdb, ctx->rollback.fork );
    *ctx->feature_snoop = ctx->recovery.feature_snoop;
  } else {
    /* A failed FULL attempt can only be retried by another full load:
       there is no valid root to hang an incremental off. */
    FD_TEST( retry_full );
  }
}

/* Tile 0 arms the deferred rollback of a failed attempt (the rollback
   itself runs at the retry's INIT barrier, see above).  Everything that
   discards attempt-scoped accdb state must stay under the
   init_completed guard: when an ERROR aborted this tile's own INIT
   barrier the INIT handler never ran, so `full` still describes the
   PREVIOUS attempt.  Wiping accdb_root_fork_id on that stale flag would
   strand the root of a full load that actually succeeded, and the
   retry's attach_child would hang a second ROOT off USHORT_MAX instead
   of the loaded accounts. */

static void
tile0_defer_rollback( fd_snapin_tile_t * ctx ) {
  if( FD_LIKELY( ctx->init_completed ) ) {
    ctx->rollback.pending = 1;
    ctx->rollback.full    = ctx->full;
    ctx->rollback.fork    = ctx->accdb_incr_fork_id;
    if( ctx->full ) ctx->accdb_root_fork_id = (fd_accdb_fork_id_t){ .val = USHORT_MAX };
    ctx->accdb_incr_fork_id = (fd_accdb_fork_id_t){ .val = USHORT_MAX };
  }
  ctx->init_completed = 0;
}

/* Tile 0's per-attempt INIT work, run inside the INIT barrier.  It
   rolls back any failed previous attempt, resets the tile-0-only
   parsers and fold state, does this attempt's accdb work (reset +
   attach for a full load, attach_child + doomed-partition release
   for an incremental one), re-zeroes the attempt-scoped shared
   state and finally publishes the attempt slot that releases every
   tile's first insert. */

static void
tile0_init_attempt( fd_snapin_tile_t * ctx,
                    ulong              in_idx,
                    ulong              chunk ) {
  /* Deferred rollback of a failed previous attempt, before this
     attempt's accdb work (and before the attempt slot publish
     that releases the other tiles' first inserts). */
  if( FD_UNLIKELY( ctx->rollback.pending ) ) tile0_rollback_failed_attempt( ctx, ctx->full );

  ctx->blockhash_groups_len    = 0UL;
  ctx->manifest_capitalization = 0UL;
  ctx->txncache_slots_len      = 0UL;
  ctx->attempt_folded          = 0;
  fd_memset( &ctx->worker_fold, 0, sizeof(ctx->worker_fold) );
  fd_memset( &ctx->av_stats,    0, sizeof(ctx->av_stats)    );

  fd_txncache_reset( ctx->txncache );
  fd_ssmanifest_parser_init( ctx->manifest_parser, fd_chunk_to_laddr( ctx->manifest_out.mem, ctx->manifest_out.chunk ) );
  fd_slot_delta_parser_init( ctx->slot_delta_parser );

  /* Rewind metric counters (no-op unless recovering from a fail) */
  if( ctx->full ) {
    fd_memset( &ctx->totals_fold, 0, sizeof(ctx->totals_fold) );
    ctx->full_genesis_creation_time_seconds = 0UL;
    ctx->capitalization          = 0UL;
    ctx->dup_capitalization      = 0UL;
    ctx->recovery.capitalization = 0UL;

    fd_stake_delegations_reset( ctx->stake_delegations );
    fd_accdb_reset( ctx->accdb );
    /* The reset released every partition, including any doomed
       ones from previously failed attempts. */
    ctx->doomed_partition_cnt = 0UL;
    fd_accdb_fork_id_t null_fork_id = (fd_accdb_fork_id_t){ .val = USHORT_MAX };
    ctx->accdb_root_fork_id = fd_accdb_attach_child( ctx->accdb, null_fork_id );

    fd_accdb_snapshot_load_begin_with_writers( ctx->accdb, ctx->tile_cnt );

    ctx->slot_history.captured = 0;

    fd_memset( ctx->feature_snoop, 0, sizeof(ctx->feature_snoop) );
  } else {
    ctx->capitalization     = ctx->recovery.capitalization;
    ctx->dup_capitalization = 0UL;

    /* Discard stale capture so the retry's sysvar is snooped fresh */
    ctx->slot_history.captured = 0;

    /* Create a child fork for incremental writes.  On failure,
       fd_accdb_purge(child) reverts just the incremental changes.
       On success, fd_accdb_advance_root(child) promotes them. */
    ctx->accdb_incr_fork_id = fd_accdb_attach_child( ctx->accdb, ctx->accdb_root_fork_id );

    /* attach_child waited for any pending background command, so
       a previously failed incremental attempt's purge has
       completed and no index entry references its tiles'
       partitions anymore: release them back to the partition pool
       before this attempt starts allocating. */
    if( FD_UNLIKELY( ctx->doomed_partition_cnt ) ) {
      fd_accdb_snapshot_worker_release_partitions( ctx->accdb, ctx->doomed_partitions, ctx->doomed_partition_cnt );
      ctx->doomed_partition_cnt = 0UL;
    }
  }

  /* Save the slot advertised by the snapshot peer and verify it
     against the slot in the snapshot manifest.  For redirect-based
     HTTP downloads, these are initial estimates from gossip and
     will be updated by the META message below once the redirect
     resolves to a concrete snapshot filename. */
  fd_ssctrl_init_t const * msg = fd_chunk_to_laddr_const( ctx->in[ in_idx ].wksp, chunk );
  ctx->advertised_slot = msg->slot;
  fd_memcpy( ctx->advertised_hash, msg->snapshot_hash, FD_HASH_FOOTPRINT );
  ctx->init_completed = 1;

  /* Re-zero the attempt-scoped shared state.  Only this tile
     writes it here, and no tile reads or writes it before its
     attempt-slot gate opens, which the publish below releases
     -- so this is the one place a snoop target or
     counter may be written outside an atomic or a stripe lock.
     Every attempt must start from zero: workspaces outlive
     crashed loads, and a retry follows a partially completed
     attempt. */
  fd_snapio_snoop_hdr_t * hdr = ctx->snoop_hdr;
  fd_memset( &hdr->totals,        0, sizeof(hdr->totals)        );
  fd_memset( &hdr->slot_history,  0, sizeof(hdr->slot_history)  );
  fd_memset( &hdr->feature_snoop, 0, sizeof(hdr->feature_snoop) );
  FD_VOLATILE( hdr->next_appendvec ) = 0UL;
  FD_COMPILER_MFENCE();

  /* Publish the attempt slot LAST, once this tile's attempt-scoped
     accdb work is complete: every tile (including this one) gates
     its first insert on it. */
  FD_VOLATILE( hdr->attempt.fork_id ) = ctx->full ? (ulong)USHORT_MAX : (ulong)ctx->accdb_incr_fork_id.val;
  FD_COMPILER_MFENCE();
  FD_VOLATILE( hdr->attempt.generation ) = ctx->generation;
}

/* Attempt-slot gate ***************************************************/

/* Nothing barrier-orders tile 0's INIT-time accdb work (reset + attach +
   load_begin for a full load, attach_child + doomed-partition release
   for an incremental one) against another tile's first insert: snapct
   does not gate DATA on INIT acks.  So every tile gates its first
   insert of an attempt on the attempt slot, which tile 0 publishes last
   in its INIT critical sequence.

   The gate is armed (not waited on) at the INIT barrier and polled from
   the DATA admission path in before_frag, which holds the lane until
   the slot carries this attempt's generation.  It deliberately does NOT
   spin inside the INIT handler: an ERROR can abort tile 0's own INIT
   barrier mid-way (see handle_control_barrier), leaving the slot
   unpublished for this generation forever, and a tile parked inside a
   frag handler would never consume the ERROR that is sitting at one of
   its lane heads, never ack the FAIL that follows, and so wedge the
   whole retry.  Holding the lane instead keeps ERROR and FAIL
   deliverable (before_frag admits ERROR unconditionally and admits FAIL
   once in ERROR state), so an aborted attempt drains and retries; the
   retry's INIT re-arms the gate on the new generation.

   Deadlock-free: a tile only ever holds DATA behind an unpublished
   slot, and tile 0's progress to its own INIT barrier depends only on
   already-published frags -- by per-lane in-order consumption a gating
   tile has already consumed INIT on every lane, so every snapdc has
   published its INIT copy and tile 0 needs nothing from the gating tile
   to publish. */

static void
attempt_gate_open( fd_snapin_tile_t * ctx ) {
  FD_COMPILER_MFENCE();
  FD_TEST( FD_VOLATILE_CONST( ctx->snoop_hdr->attempt.generation )==ctx->generation );
  ctx->incr_fork = FD_VOLATILE_CONST( ctx->snoop_hdr->attempt.fork_id );
  if( FD_UNLIKELY( ctx->full ? ctx->incr_fork!=(ulong)USHORT_MAX : ctx->incr_fork>=(ulong)USHORT_MAX ) ) {
    FD_LOG_ERR(( "invalid attempt fork %lu (full=%d); this is a bug", ctx->incr_fork, (int)ctx->full ));
  }
  fd_accdb_snapshot_writer_begin( ctx->accdb );

  /* Eager claim.  The counter was re-zeroed by tile 0 before it
     published the slot, so the claim sequence starts at 0 every
     attempt.  From here the tile always holds exactly one outstanding
     claim, which the appendvec walk consumes and immediately replaces.
     Drawing it here (rather than at the INIT barrier) cannot orphan an
     ordinal: the claim is taken before the first data frag is admitted,
     so the tile's walk position is still 0 and every claim it can ever
     draw is at or ahead of that position. */
  ctx->claimed_appendvec = FD_ATOMIC_FETCH_AND_ADD( &ctx->snoop_hdr->next_appendvec, 1UL );
  ctx->gate_pending      = 0;
}

/* Returns 1 if this attempt's write path is armed, 0 if the caller must
   hold the frag. */

static inline int
attempt_gate_ready( fd_snapin_tile_t * ctx ) {
  if( FD_LIKELY( !ctx->gate_pending ) ) return 1;
  if( FD_UNLIKELY( FD_VOLATILE_CONST( ctx->snoop_hdr->attempt.generation )!=ctx->generation ) ) {
    long now = fd_log_wallclock();
    if( FD_UNLIKELY( now>=ctx->gate_warn_ts ) ) {
      ctx->gate_warn_ts = now + FD_SNAPIN_GATE_WARN_NS;
      FD_LOG_WARNING(( "tile %lu holding snapshot data: attempt slot for generation %lu not published yet (slot holds %lu)",
                       ctx->tile_idx, ctx->generation, FD_VOLATILE_CONST( ctx->snoop_hdr->attempt.generation ) ));
    }
    return 0;
  }
  attempt_gate_open( ctx );
  return 1;
}

static void
handle_control_frag( fd_snapin_tile_t *  ctx,
                     fd_stem_context_t * stem,
                     ulong               in_idx,
                     ulong               sig,
                     ulong               chunk,
                     ulong               sz ) {
  if( ctx->state==FD_SNAPSHOT_STATE_ERROR && sig!=FD_SNAPSHOT_MSG_CTRL_FAIL ) {
    /* Control messages move along the snapshot load pipeline.  Since
       error conditions can be triggered by any tile in the pipeline,
       it is possible to be in error state and still receive otherwise
       valid messages.  Only a fail message can revert this. */
    return;
  };

  int forward_msg = 1;

  switch( sig ) {
    case FD_SNAPSHOT_MSG_CTRL_INIT_FULL:
    case FD_SNAPSHOT_MSG_CTRL_INIT_INCR: {
      FD_TEST( ctx->state==FD_SNAPSHOT_STATE_IDLE );
      /* generation was already bumped at the first INIT frag (see
         handle_control_barrier) */
      ctx->state = FD_SNAPSHOT_STATE_PROCESSING;
      ctx->full = sig==FD_SNAPSHOT_MSG_CTRL_INIT_FULL;

      worker_reset_attempt( ctx );
      fd_memset( &ctx->flags, 0, sizeof(ctx->flags) );
      if( ctx->full ) ctx->metrics.full_bytes_read = 0UL;
      ctx->metrics.incremental_bytes_read = 0UL;

      /* Rebase this tile's account gauges -- the only point at which
         they may move backwards (see the struct comment).  A full
         attempt starts the session at zero; an incremental attempt, and
         any retry of one, resumes from this tile's latched
         full-snapshot share, discarding whatever a failed attempt had
         accumulated. */
      if( ctx->full ) {
        ctx->metrics.accounts_loaded        = 0UL;
        ctx->metrics.accounts_replaced      = 0UL;
        ctx->metrics.accounts_ignored       = 0UL;
        ctx->metrics.full_accounts_loaded   = 0UL;
        ctx->metrics.full_accounts_replaced = 0UL;
        ctx->metrics.full_accounts_ignored  = 0UL;
      } else {
        ctx->metrics.accounts_loaded   = ctx->metrics.full_accounts_loaded;
        ctx->metrics.accounts_replaced = ctx->metrics.full_accounts_replaced;
        ctx->metrics.accounts_ignored  = ctx->metrics.full_accounts_ignored;
      }

      if( FD_UNLIKELY( is_lead( ctx ) ) ) tile0_init_attempt( ctx, in_idx, chunk );

      /* Arm the attempt-slot gate (see attempt_gate_open above).  Tile 0
         published the slot itself in tile0_init_attempt, so it opens the
         gate right here and never holds data; every other tile opens it
         from the data admission path in before_frag. */
      ctx->gate_pending = 1;
      ctx->gate_warn_ts = fd_log_wallclock() + FD_SNAPIN_GATE_WARN_NS;
      if( FD_UNLIKELY( is_lead( ctx ) ) ) attempt_gate_open( ctx );
      break;
    }

    case FD_SNAPSHOT_MSG_META: {
      /* For redirect-based HTTP downloads, the META message carries
         the resolved slot and hash from the actual snapshot filename
         the server redirected to.  Update the advertised values so
         that process_manifest can verify the manifest against them. */
      FD_TEST( sz==sizeof(fd_ssctrl_meta_t) );
      fd_ssctrl_meta_t const * meta = fd_chunk_to_laddr_const( ctx->in[ in_idx ].wksp, chunk );
      if( meta->resolved_slot!=ULONG_MAX ) {
        ctx->advertised_slot = meta->resolved_slot;
        fd_memcpy( ctx->advertised_hash, meta->resolved_hash, FD_HASH_FOOTPRINT );
      }
      forward_msg = 0; /* snapct already receives META directly from snapld */
      break;
    }

    case FD_SNAPSHOT_MSG_CTRL_FINI: {
      /* This is a special case: handle_data_frag must have already
         processed FD_SSPARSE_ADVANCE_DONE and moved the state into
         FD_SNAPSHOT_STATE_FINISHING (every tile walks the whole tar
         itself, so its parser reaches EOF before the FINI barrier
         completes).  Otherwise, treat this as a malformed snapshot so
         that the pipeline can retry. */
      if( FD_UNLIKELY( ctx->state!=FD_SNAPSHOT_STATE_FINISHING ) ) {
        FD_LOG_WARNING(( "received FINI while in state %s (%lu), expected FINISHING (possibly truncated tar stream)",
                         fd_ssctrl_state_str( (ulong)ctx->state ), (ulong)ctx->state ));
        transition_malformed( ctx, stem );
        forward_msg = 0;
        break;
      }

      /* Make every staged byte durable and hand off the final partition
         before acking: tile 0's readback gate and load_end at the DONE
         barrier run only after all FINI acks. */
      worker_buffer_flush( ctx );
      fd_accdb_snapshot_worker_close( ctx->accdb, &ctx->whead );
      fd_accdb_snapshot_writer_end( ctx->accdb );
      fd_accdb_snapshot_flush_worker_metrics( ctx->accdb, ctx->worker_metrics );

      FD_LOG_NOTICE(( "snapin %lu: owned appendvecs=%lu owned_bytes=%lu bytes_written=%lu, wb kicks=%lu waits=%lu",
                      ctx->tile_idx, ctx->owned_appendvecs, ctx->owned_bytes, ctx->bytes_written,
                      ctx->wb_kick_cnt, ctx->wb_wait_cnt ));
      if( FD_UNLIKELY( is_lead( ctx ) ) ) log_appendvec_stats( ctx );

      /* Equal-slot cross-appendvec duplicates are accepted, not
         fatal: Agave tolerates them too (see the eq-slot branch in
         fd_accdb_snapshot_write_batch_worker), and the counters below
         still flow into the shared totals so DONE can report them. */

      /* Fold this tile's counters into the shared totals (the
         snapin_ct link is mcache-only, so the counters cannot ride the
         ack; tile 0 reads the fold at the NEXT/DONE barrier, which
         snapct gates on all FINI acks).  One atomic add per field, so
         there is no per-tile staging slot for tile 0 to gather. */
      fd_snapio_totals_t * totals = &ctx->snoop_hdr->totals;
      FD_ATOMIC_FETCH_AND_ADD( &totals->accounts_loaded,       ctx->worker.accounts_loaded                );
      FD_ATOMIC_FETCH_AND_ADD( &totals->accounts_replaced,     ctx->worker.accounts_replaced              );
      FD_ATOMIC_FETCH_AND_ADD( &totals->accounts_ignored,      ctx->worker.accounts_ignored               );
      FD_ATOMIC_FETCH_AND_ADD( &totals->input_lamports,        ctx->worker.input_lamports                 );
      FD_ATOMIC_FETCH_AND_ADD( &totals->replaced_lamports,     ctx->worker.replaced_lamports              );
      FD_ATOMIC_FETCH_AND_ADD( &totals->ignored_lamports,      ctx->worker.ignored_lamports               );
      FD_ATOMIC_FETCH_AND_ADD( &totals->bytes_written,         ctx->bytes_written                         );
      FD_ATOMIC_FETCH_AND_ADD( &totals->eq_slot_dups,          ctx->worker_metrics->eq_slot_dups          );
      FD_ATOMIC_FETCH_AND_ADD( &totals->eq_slot_lamports_diff, ctx->worker_metrics->eq_slot_lamports_diff );
      FD_ATOMIC_FETCH_AND_ADD( &totals->appendvecs_processed,  ctx->owned_appendvecs                      );
      FD_COMPILER_MFENCE(); /* totals + snoop targets visible before the ack */

      /* This tile's account gauges are deliberately left alone: they
         hold its own share, tile 0 does not fold the shared totals back
         into a gauge, and dashboards sum them across all snapin tiles
         (see the metrics struct comment). */
      break;
    }

    case FD_SNAPSHOT_MSG_CTRL_NEXT: {
      FD_TEST( ctx->state==FD_SNAPSHOT_STATE_FINISHING );
      ctx->state = FD_SNAPSHOT_STATE_IDLE;

      /* Every tile latches its OWN full-snapshot share: the incremental
         attempt (and any retry of it) rebases its gauge on this, which
         is what keeps the cross-tile sum continuous across the phase
         boundary. */
      ctx->metrics.full_accounts_loaded   = ctx->metrics.accounts_loaded;
      ctx->metrics.full_accounts_replaced = ctx->metrics.accounts_replaced;
      ctx->metrics.full_accounts_ignored  = ctx->metrics.accounts_ignored;

      if( FD_LIKELY( !is_lead( ctx ) ) ) break;

      /* Every tile has acked FINI by the time NEXT arrives (snapct
         gates on the acks), so the shared totals and snoop targets are
         complete and quiescent. */
      tile0_fold_attempt( ctx );

      if( FD_UNLIKELY( verify_slot_deltas_with_slot_history( ctx ) ) ) {
        FD_LOG_WARNING(( "slot deltas verification failed for full snapshot" ));
        transition_malformed( ctx, stem );
        forward_msg = 0;
        break;
      }

      ctx->capitalization = fd_ulong_sat_sub( ctx->capitalization, ctx->dup_capitalization );
      if( FD_UNLIKELY( validate_capitalization( ctx )!=0 ) ) {
        transition_malformed( ctx, stem );
        forward_msg = 0;
        break;
      }

      ctx->recovery.capitalization = ctx->capitalization;
      ctx->recovery.feature_snoop = *ctx->feature_snoop;
      ctx->init_completed = 0;
      break;
    }

    case FD_SNAPSHOT_MSG_CTRL_DONE: {
      FD_TEST( ctx->state==FD_SNAPSHOT_STATE_FINISHING );
      ctx->state = FD_SNAPSHOT_STATE_IDLE;
      if( FD_LIKELY( !is_lead( ctx ) ) ) break;

      tile0_fold_attempt( ctx );

      if( FD_UNLIKELY( verify_slot_deltas_with_slot_history( ctx ) ) ) {
        if( ctx->full ) FD_LOG_WARNING(( "slot deltas verification failed for full snapshot" ));
        else            FD_LOG_WARNING(( "slot deltas verification failed for incremental snapshot" ));
        transition_malformed( ctx, stem );
        forward_msg = 0;
        break;
      }

      ctx->capitalization = fd_ulong_sat_sub( ctx->capitalization, ctx->dup_capitalization );
      if( FD_UNLIKELY( validate_capitalization( ctx )!=0 ) ) {
        transition_malformed( ctx, stem );
        forward_msg = 0;
        break;
      }

      /* Multi-writer layout is not stream-ordered: gate on a sampled
         index->file readback (tiles flushed + closed their partitions
         before acking FINI, so the bytes are visible here).  Must run
         BEFORE advance_root below: the promotion is asynchronous and
         background_advance_root concurrently unlinks + defer-frees
         shadowed full entries, which can be recycled under our chain
         walk (this joiner publishes no epoch).  Pre-promotion, both the
         old and new versions are chain-linked with valid on-disk
         records, so the readback covers both phases. */
      fd_accdb_snapshot_verify_readback( ctx->accdb, 100000UL );

      if( !ctx->full ) {
        fd_accdb_snapshot_recover_delta( ctx->accdb, ctx->accdb_incr_fork_id );
        /* ensure that snapin tile sees all delta changes before rooting */
        __atomic_thread_fence( __ATOMIC_SEQ_CST );
        fd_accdb_advance_root( ctx->accdb, ctx->accdb_incr_fork_id );
        ctx->accdb_root_fork_id = ctx->accdb_incr_fork_id;
        ctx->accdb_incr_fork_id = (fd_accdb_fork_id_t){ .val = USHORT_MAX };
      }

      fd_accdb_snapshot_load_end( ctx->accdb );

      fd_feature_snoop_finalize( &ctx->bank->f.features, ctx->bank_slot, &ctx->epoch_schedule, ctx->feature_snoop );

      FD_LOG_NOTICE(( "parallel loader: equal-slot cross-appendvec dups=%lu (lamports-diff=%lu), worker bytes written=%lu",
                      ctx->worker_fold.eq_slot_dups, ctx->worker_fold.eq_slot_lamports_diff,
                      ctx->worker_fold.bytes_written ));
      if( FD_UNLIKELY( ctx->worker_fold.eq_slot_dups ) ) {
        FD_LOG_WARNING(( "parallel loader: accepted %lu equal-slot cross-appendvec duplicates (lamports-diff=%lu); "
                         "stripe-lock arrival order picked the winner",
                         ctx->worker_fold.eq_slot_dups, ctx->worker_fold.eq_slot_lamports_diff ));
      }
      log_snoop_checksums( ctx );

      /* Notify replay when snapshot is fully loaded and verified. */
      fd_stem_publish( stem, ctx->manifest_out.idx, fd_ssmsg_sig( FD_SSMSG_DONE ), 0UL, 0UL, 0UL, 0UL, 0UL );
      ctx->init_completed = 0;
      break;
    }

    case FD_SNAPSHOT_MSG_CTRL_ERROR: {
      FD_TEST( ctx->state!=FD_SNAPSHOT_STATE_SHUTDOWN );
      ctx->state = FD_SNAPSHOT_STATE_ERROR;
      break;
    }

    case FD_SNAPSHOT_MSG_CTRL_FAIL: {
      FD_TEST( ctx->state!=FD_SNAPSHOT_STATE_SHUTDOWN );
      /* Worker-side teardown.  Close the final open partition (stamps
         its write_offset and books the tail slack, exactly like a
         rotation would) and publish this attempt's partition list
         before dropping the tracker: tile 0 gathers the lists at its
         deferred rollback and releases the partitions once the index
         purge completed.  Fold the attempt's buffered shared-counter
         deltas (disk_used_bytes, accounts_total) BEFORE they are
         discarded: the purge subtracts per unlinked entry, so
         discarding the additions would leave the shared counters
         net-negative by the attempt's contribution.  The staging
         buffer and private write head are then simply forgotten.  The
         FAIL ack below is this tile's quiesce certificate: after it,
         the tile touches no shared accdb state until the next attempt's
         slot gate opens. */
      fd_accdb_snapshot_worker_close( ctx->accdb, &ctx->whead );
      fd_accdb_snapshot_flush_worker_metrics( ctx->accdb, ctx->worker_metrics );
      ctx->my_snoop->fail_partition_cnt = ctx->whead.attempt_partition_cnt;
      FD_COMPILER_MFENCE(); /* partition list visible before the ack */
      worker_reset_attempt( ctx );
      fd_accdb_snapshot_writer_end( ctx->accdb );

      /* Tile 0: defer the database rollback to the NEXT INIT barrier,
         by which point snapct has collected every tile's FAIL ack (so
         all in-flight inserts have provably drained).  If the load is
         aborted without a retry the rollback never runs; benign, the
         process exits and the next boot's INIT_FULL resets. */
      if( FD_UNLIKELY( is_lead( ctx ) ) ) tile0_defer_rollback( ctx );

      ctx->state = FD_SNAPSHOT_STATE_IDLE;
      break;
    }

    case FD_SNAPSHOT_MSG_CTRL_SHUTDOWN: {
      FD_TEST( ctx->state==FD_SNAPSHOT_STATE_IDLE );
      ctx->state = FD_SNAPSHOT_STATE_SHUTDOWN;
      break;
    }

    default: {
      FD_LOG_ERR(( "unexpected control frag %s (%lu) in state %s (%lu)",
                   fd_ssctrl_msg_ctrl_str( sig ), sig,
                   fd_ssctrl_state_str( (ulong)ctx->state ), (ulong)ctx->state ));
      break;
    }
  }

  /* Forward the control message down the pipeline (this is the tile's
     ack: snapct counts one snapin_ct link per snapin tile). */
  if( FD_LIKELY( forward_msg ) ) {
    fd_stem_publish( stem, ctx->ct_out.idx, sig, 0UL, 0UL, 0UL, 0UL, 0UL );
  }
}

static inline int
all_controls_seen( fd_snapin_tile_t const * ctx ) {
  int all_seen = 1;
  for( ulong i=0UL; i<ctx->lane_cnt; i++ ) {
    all_seen &= !!ctx->control_seen[ i ];
  }
  return all_seen;
}

static inline int
before_frag( fd_snapin_tile_t * ctx,
             ulong              in_idx,
             ulong              seq    FD_PARAM_UNUSED,
             ulong              sig ) {
  /* If we're currently in ERROR state we should only process FAIL
     control frags */
  if( FD_UNLIKELY( ctx->state==FD_SNAPSHOT_STATE_ERROR ) ) {
    return sig!=FD_SNAPSHOT_MSG_CTRL_FAIL;
  }

  if( FD_UNLIKELY( sig==FD_SNAPSHOT_MSG_CTRL_ERROR ) ) {
    return 0;
  }

  /* Once this lane sends the pending control, hold its later frags
     until all snapdc lanes send the same control. */
  if( FD_UNLIKELY( ctx->pending_control!=ULONG_MAX && ctx->control_seen[ in_idx ] ) ) {
    FD_TEST( sig!=ctx->pending_control );
    return -1;
  }

  if( FD_UNLIKELY( sig==FD_SNAPSHOT_MSG_DATA ) ) {
    /* Only accept DATA frags from the expected lane */
    if( FD_UNLIKELY( in_idx!=ctx->expected_frame%ctx->lane_cnt ) ) return -1;

    /* ... and only once this attempt's slot is published, so no insert
       can race tile 0's INIT-time accdb work.  Controls stay
       admissible while data is held: that is what lets a tile whose
       INIT barrier completed for an attempt tile 0 never published
       consume the aborting ERROR and ack the FAIL. */
    if( FD_UNLIKELY( !attempt_gate_ready( ctx ) ) ) return -1;
  }

  return 0;
}

static inline int
handle_lane_data_frag( fd_snapin_tile_t *  ctx,
                       fd_stem_context_t * stem,
                       ulong               in_idx,
                       ulong               chunk,
                       ulong               sz,
                       ulong               ctl ) {
  /* EOM marks the end of a frame */
  int eom = !!fd_frag_meta_ctl_eom( ctl );

  /* The tar parser can reach EOF before snapdc reports the end of the
     zstd frame.  Only the empty EOM is valid (any payload after EOF is
     malformed). */
  int trailing_eom = ctx->state==FD_SNAPSHOT_STATE_FINISHING && eom && !sz;
  if( FD_UNLIKELY( !trailing_eom && handle_data_frag( ctx, in_idx, chunk, sz, stem ) ) ) {
    return 1;
  }

  if( FD_UNLIKELY( eom ) ) {
    ctx->expected_frame++;
  }

  return 0;
}

static inline void
handle_control_barrier( fd_snapin_tile_t *  ctx,
                        fd_stem_context_t * stem,
                        ulong               in_idx,
                        ulong               sig,
                        ulong               chunk,
                        ulong               sz ) {
  /* Error control frags must be immediately handled. */
  if( FD_UNLIKELY( sig==FD_SNAPSHOT_MSG_CTRL_ERROR ) ) {
    handle_control_frag( ctx, stem, in_idx, sig, chunk, sz );
    return;
  }

  if( FD_UNLIKELY( sig!=ctx->pending_control ) ) {
    FD_TEST( ctx->pending_control==ULONG_MAX || sig==FD_SNAPSHOT_MSG_CTRL_FAIL );
    clear_control_barrier( ctx );
    ctx->pending_control = sig;

    /* Bump the attempt generation at the FIRST INIT frag (barrier
       start), not at barrier completion: an ERROR processed while the
       INIT barrier is partially complete aborts the barrier (the
       remaining INIT frags are drained by the ERROR-state filter), but
       every tile is guaranteed to observe at least one INIT frag per
       attempt (INIT is only ever sent after the previous FAIL fully
       flushed, and the aborting ERROR is itself queued behind INIT on
       its own lane).  Bumping here keeps all tiles' generations in
       lockstep even across aborted barriers. */
    if( FD_UNLIKELY( sig==FD_SNAPSHOT_MSG_CTRL_INIT_FULL || sig==FD_SNAPSHOT_MSG_CTRL_INIT_INCR ) ) {
      ctx->generation++;
    }
  }

  /* Only process the control frag when all upstream tiles have sent
     the same control message. */
  FD_TEST( !ctx->control_seen[ in_idx ] );
  ctx->control_seen[ in_idx ] = 1U;
  if( FD_LIKELY( !all_controls_seen( ctx ) ) ) {
    return;
  }

  /* All controls received, process the control frag. */
  clear_control_barrier( ctx );
  handle_control_frag( ctx, stem, in_idx, sig, chunk, sz );
}

static inline int
returnable_frag( fd_snapin_tile_t *  ctx,
                 ulong               in_idx,
                 ulong               seq    FD_PARAM_UNUSED,
                 ulong               sig,
                 ulong               chunk,
                 ulong               sz,
                 ulong               ctl,
                 ulong               tsorig FD_PARAM_UNUSED,
                 ulong               tspub  FD_PARAM_UNUSED,
                 fd_stem_context_t * stem ) {
  FD_TEST( ctx->state!=FD_SNAPSHOT_STATE_SHUTDOWN );

  if( FD_UNLIKELY( sig==FD_SNAPSHOT_MSG_DATA ) ) return handle_lane_data_frag( ctx, stem, in_idx, chunk, sz, ctl );
  else                                           handle_control_barrier( ctx, stem, in_idx, sig, chunk, sz );

  return 0;
}

static ulong
populate_allowed_fds( fd_topo_t      const * topo FD_PARAM_UNUSED,
                      fd_topo_tile_t const * tile FD_PARAM_UNUSED,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  if( FD_UNLIKELY( out_fds_cnt<3UL ) ) FD_LOG_ERR(( "invalid out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0;
  out_fds[ out_cnt++ ] = 2UL; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) ) {
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  }
  out_fds[ out_cnt++ ] = FD_ACCDB_FD_RW; /* accounts db */

  return out_cnt;
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  (void)topo; (void)tile;
  populate_sock_filter_policy_fd_snapin_tile( out_cnt, out, (uint)fd_log_private_logfile_fd(), FD_ACCDB_FD_RW );
  return sock_filter_policy_fd_snapin_tile_instr_cnt;
}

/* Returns MemTotal in bytes, or 0 if it cannot be determined. */

static ulong
read_mem_total_bytes( void ) {
  int fd = open( "/proc/meminfo", O_RDONLY );
  if( FD_UNLIKELY( -1==fd ) ) return 0UL;
  char  buf[ 4096 ];
  long  n = read( fd, buf, sizeof(buf)-1UL );
  if( FD_UNLIKELY( -1==close( fd ) ) ) FD_LOG_ERR(( "close(/proc/meminfo) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( n<=0L ) ) return 0UL;
  buf[ n ] = '\0';

  char const * p = strstr( buf, "MemTotal:" );
  if( FD_UNLIKELY( !p ) ) return 0UL;
  p += strlen( "MemTotal:" );
  while( *p==' ' || *p=='\t' ) p++;
  if( FD_UNLIKELY( *p<'0' || *p>'9' ) ) return 0UL;
  ulong kib = 0UL;
  for( ; *p>='0' && *p<='9'; p++ ) {
    if( FD_UNLIKELY( kib>(ULONG_MAX-9UL)/10UL ) ) return 0UL; /* implausible, but do not wrap */
    kib = kib*10UL + (ulong)(*p-'0');
  }
  if( FD_UNLIKELY( kib>(ULONG_MAX>>10) ) ) return 0UL;
  return kib<<10;
}

static void
privileged_init( fd_topo_t const *      topo,
                 fd_topo_tile_t const * tile ) {
  fd_snapin_tile_t * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  memset( ctx, 0, sizeof(fd_snapin_tile_t) );
  FD_TEST( fd_rng_secure( &ctx->seed, 8UL ) );

  /* Size the aggregate write-behind window here, while /proc is still
     reachable: the budget must stay below the host's dirty-throttle
     engagement point, which is a fraction of RAM, so a fixed byte count
     is only valid on the host it was swept on.  With MemTotal unknown
     there is no safe budget, so write-behind is disabled -- that is the
     behaviour every topology below FD_SNAPIN_WB_MIN_WORKERS tiles runs
     with anyway. */
  ulong mem_total = read_mem_total_bytes();
  if( FD_UNLIKELY( !mem_total ) ) {
    FD_LOG_WARNING(( "could not read MemTotal from /proc/meminfo; disabling snapshot write-behind" ));
    ctx->wb_total_window = 0UL;
  } else {
    ctx->wb_total_window = fd_ulong_min( FD_SNAPIN_WB_WINDOW_MAX, (mem_total/100UL)*FD_SNAPIN_WB_MEM_PCT );
  }
}

static inline fd_snapin_out_link_t
out1( fd_topo_t const *      topo,
      fd_topo_tile_t const * tile,
      char const *           name,
      ulong                  kind_id ) {
  ulong idx = fd_topo_find_tile_out_link( topo, tile, name, kind_id );

  if( FD_UNLIKELY( idx==ULONG_MAX ) ) return (fd_snapin_out_link_t){ .idx = ULONG_MAX, .mem = NULL, .chunk0 = 0, .wmark = 0, .chunk = 0, .mtu = 0 };

  ulong mtu = topo->links[ tile->out_link_id[ idx ] ].mtu;
  if( FD_UNLIKELY( mtu==0UL ) ) return (fd_snapin_out_link_t){ .idx = idx, .mem = NULL, .chunk0 = ULONG_MAX, .wmark = ULONG_MAX, .chunk = ULONG_MAX, .mtu = mtu };

  void * mem   = topo->workspaces[ topo->objs[ topo->links[ tile->out_link_id[ idx ] ].dcache_obj_id ].wksp_id ].wksp;
  ulong chunk0 = fd_dcache_compact_chunk0( mem, topo->links[ tile->out_link_id[ idx ] ].dcache );
  ulong wmark  = fd_dcache_compact_wmark ( mem, topo->links[ tile->out_link_id[ idx ] ].dcache, mtu );
  return (fd_snapin_out_link_t){ .idx = idx, .mem = mem, .chunk0 = chunk0, .wmark = wmark, .chunk = chunk0, .mtu = mtu };
}

static void
unprivileged_init( fd_topo_t const *      topo,
                   fd_topo_tile_t const * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_snapin_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_snapin_tile_t), sizeof(fd_snapin_tile_t) );
  void * _accdb          = FD_SCRATCH_ALLOC_APPEND( l, fd_accdb_align(),          fd_accdb_footprint( tile->snapin.max_live_slots ) );

  ctx->tile_idx = tile->kind_id;
  if( FD_UNLIKELY( ctx->tile_idx>=FD_SNAPIN_TILE_MAX ) ) {
    FD_LOG_ERR(( "tile `" NAME "` has unsupported kind id %lu", tile->kind_id ));
  }
  ctx->full            = 1;
  ctx->init_completed  = 0;
  ctx->state           = FD_SNAPSHOT_STATE_IDLE;
  ctx->lane_cnt        = tile->in_cnt;
  ctx->generation      = 0UL;
  ctx->expected_frame  = 0UL;
  clear_control_barrier( ctx );
  fd_memset( &ctx->metrics, 0, sizeof(ctx->metrics) );

  void * _accdb_shmem = fd_topo_obj_laddr( topo, tile->snapin.accdb_obj_id );
  fd_accdb_shmem_t * accdb_shmem = fd_accdb_shmem_join( _accdb_shmem );
  FD_TEST( accdb_shmem );
  ctx->accdb = fd_accdb_join( fd_accdb_new( _accdb, accdb_shmem, FD_ACCDB_FD_RW, 0UL, NULL ) );
  FD_TEST( ctx->accdb );

  fd_snapio_snoop_hdr_t * snoop_hdr = fd_snapio_snoop_join( fd_topo_obj_laddr( topo, tile->snapin.snoop_obj_id ) );
  FD_TEST( snoop_hdr );
  FD_TEST( ctx->tile_idx<snoop_hdr->worker_cnt );
  ctx->snoop_hdr     = snoop_hdr;
  ctx->tile_cnt      = snoop_hdr->worker_cnt;
  ctx->stripe_locks  = fd_snapio_snoop_stripes( snoop_hdr );
  ctx->my_snoop      = fd_snapio_snoop_worker( snoop_hdr, ctx->tile_idx );
  if( FD_UNLIKELY( is_lead( ctx ) ) ) {
    for( ulong w=0UL; w<ctx->tile_cnt; w++ ) ctx->snoops[ w ] = fd_snapio_snoop_worker( snoop_hdr, w );
  }

  /* Track this attempt's partitions straight into the shared staging,
     so a failed attempt's list only needs its count stamped before the
     FAIL ack. */
  ctx->whead.attempt_partitions    = ctx->my_snoop->fail_partitions;
  ctx->whead.attempt_partition_cnt = 0UL;
  ctx->whead.attempt_partition_max = FD_SNAPIO_FAIL_PARTITION_MAX;

  /* wb_total_window was sized from MemTotal in privileged_init. */
  ctx->wb_kick_sz = FD_SNAPIN_WB_KICK_SZ;
  ctx->wb_window  = ctx->tile_cnt>=FD_SNAPIN_WB_MIN_WORKERS
                  ? ctx->wb_total_window/ctx->tile_cnt : 0UL;
  if( FD_UNLIKELY( is_lead( ctx ) ) ) {
    FD_LOG_NOTICE(( "snapin: write-behind window %lu MiB aggregate, %lu MiB per tile (%lu tiles)",
                    ctx->wb_total_window>>20, ctx->wb_window>>20, ctx->tile_cnt ));
  }

  /* Every tile updates the root stake delegations from its snoop
     callback, so every tile joins banks; only tile 0 initializes and
     owns the bank itself. */
  ctx->banks = fd_banks_join( fd_topo_obj_laddr( topo, tile->snapin.banks_obj_id ) );
  FD_TEST( ctx->banks );
  ctx->stake_delegations = fd_banks_stake_delegations_root_query( ctx->banks );
  FD_TEST( ctx->stake_delegations );

  if( FD_UNLIKELY( is_lead( ctx ) ) ) {
    void * _txncache        = FD_SCRATCH_ALLOC_APPEND( l, fd_txncache_align(),           fd_txncache_footprint( tile->snapin.max_live_slots )        );
    void * _manifest_parser = FD_SCRATCH_ALLOC_APPEND( l, fd_ssmanifest_parser_align(),  fd_ssmanifest_parser_footprint()                            );
    void * _sd_parser       = FD_SCRATCH_ALLOC_APPEND( l, fd_slot_delta_parser_align(),  fd_slot_delta_parser_footprint()                            );
    ctx->blockhash_groups   = FD_SCRATCH_ALLOC_APPEND( l, alignof(blockhash_group_t),    sizeof(blockhash_group_t)*FD_SNAPIN_MAX_SLOT_DELTA_GROUPS   );
    ctx->txncache_entries   = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_sstxncache_hash_t), sizeof(fd_sstxncache_hash_t)*FD_SNAPIN_TXNCACHE_MAX_ENTRIES );

    void * _txncache_shmem = fd_topo_obj_laddr( topo, tile->snapin.txncache_obj_id );
    fd_txncache_shmem_t * txncache_shmem = fd_txncache_shmem_join( _txncache_shmem );
    FD_TEST( txncache_shmem );
    ctx->txncache = fd_txncache_join( fd_txncache_new( _txncache, txncache_shmem ) );
    FD_TEST( ctx->txncache );

    ctx->bank = fd_banks_init_bank( ctx->banks );
    FD_TEST( ctx->bank );
    FD_TEST( ctx->bank->idx==0UL );

    ctx->manifest_parser = fd_ssmanifest_parser_join( fd_ssmanifest_parser_new( _manifest_parser ) );
    FD_TEST( ctx->manifest_parser );

    ctx->slot_delta_parser = fd_slot_delta_parser_join( fd_slot_delta_parser_new( _sd_parser ) );
    FD_TEST( ctx->slot_delta_parser );
  }

  ctx->write_buf = FD_SCRATCH_ALLOC_APPEND( l, 4096UL, FD_SNAPIN_WRITE_BUF_SZ );

  ctx->alpenglow = tile->snapin.alpenglow;
  ctx->blockhash_groups_len = 0UL;

  ctx->ct_out       = out1( topo, tile, "snapin_ct",    ctx->tile_idx );
  ctx->manifest_out = out1( topo, tile, "snapin_manif", 0UL           );
  ctx->gui_out      = out1( topo, tile, "snapin_gui",   0UL           );

  if( FD_UNLIKELY( ctx->ct_out.idx==ULONG_MAX ) ) FD_LOG_ERR(( "tile `" NAME ":%lu` missing required out link `snapin_ct`", ctx->tile_idx ));
  if( FD_UNLIKELY( is_lead( ctx ) && ctx->manifest_out.idx==ULONG_MAX ) ) FD_LOG_ERR(( "tile `" NAME "` missing required out link `snapin_manif`" ));

  if( FD_UNLIKELY( is_lead( ctx ) ) ) {
    fd_ssmanifest_parser_init( ctx->manifest_parser, fd_chunk_to_laddr( ctx->manifest_out.mem, ctx->manifest_out.chunk ) );
    fd_slot_delta_parser_init( ctx->slot_delta_parser );
  }

  for( ulong i=0UL; i<ctx->lane_cnt; i++ ) {
    fd_topo_link_t const * in_link = &topo->links[ tile->in_link_id[ i ] ];
    FD_TEST( 0==strcmp( in_link->name, "snapdc_in" ) );
    FD_TEST( in_link->kind_id==i );
    fd_topo_wksp_t const * in_wksp = &topo->workspaces[ topo->objs[ in_link->dcache_obj_id ].wksp_id ];
    ctx->in[ i ].wksp   = in_wksp->wksp;
    ctx->in[ i ].chunk0 = fd_dcache_compact_chunk0( ctx->in[ i ].wksp, in_link->dcache );
    ctx->in[ i ].wmark  = fd_dcache_compact_wmark( ctx->in[ i ].wksp, in_link->dcache, in_link->mtu );
    ctx->in[ i ].mtu    = in_link->mtu;
    ctx->in[ i ].pos    = 0UL;
  }
  if( FD_UNLIKELY( !ctx->lane_cnt || ctx->lane_cnt>FD_SNAPIN_IO_LANE_MAX ) ) {
    FD_LOG_ERR(( "tile `" NAME ":%lu` has %lu snapshot data lanes, expected 1..%lu", ctx->tile_idx, ctx->lane_cnt, FD_SNAPIN_IO_LANE_MAX ));
  }

  worker_reset_attempt( ctx );

  ctx->gui_config_acct_sz  = 0UL;
  ctx->gui_config_acct_off = 0UL;

  ctx->advertised_slot = 0UL;
  ctx->bank_slot       = 0UL;
  ctx->epoch           = 0UL;

  ctx->full_genesis_creation_time_seconds = 0UL;
  ctx->manifest_capitalization            = 0UL;
  ctx->capitalization                     = 0UL;
  ctx->dup_capitalization                 = 0UL;
  ctx->recovery.capitalization            = 0UL;

  ctx->attempt_folded = 0;
  fd_memset( &ctx->worker_fold, 0, sizeof(ctx->worker_fold) );
  fd_memset( &ctx->av_stats,    0, sizeof(ctx->av_stats)    );
  ctx->doomed_partition_cnt = 0UL;

  ctx->accdb_root_fork_id = (fd_accdb_fork_id_t){ .val = USHORT_MAX };
  ctx->accdb_incr_fork_id = (fd_accdb_fork_id_t){ .val = USHORT_MAX };

  fd_memset( &ctx->flags, 0, sizeof(ctx->flags) );
  ctx->boot_timestamp = fd_log_wallclock();
}

/* There are 3 output links that affect the calculation of STEM_BURST:
    1. snapin_ct    - worst case: 1 message (ack or unsolicited ERROR)
    2. snapin_manif - worst case: 1 message (tile 0 only)
    3. snapin_gui   - worst case: 1 message (config program account,
       tile 0 only)
   The STEM_BURST is the max value across these 3 links (not the sum).
   Note that snapin_txn is excluded from this calculation, since it is
   an unreliable link, working as a dcache place holder. */
#define STEM_BURST 1UL

/* Account batches arrive at roughly two million messages per second and
   every tile's fseq is its scan position.  Refresh flow-control credits
   well before a lane's runway drains so the producers never see a stale
   fseq snapshot. */
#define STEM_LAZY  (128L*250L)

#define STEM_CALLBACK_CONTEXT_TYPE  fd_snapin_tile_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_snapin_tile_t)

#define STEM_CALLBACK_SHOULD_SHUTDOWN should_shutdown
#define STEM_CALLBACK_METRICS_WRITE   metrics_write
#define STEM_CALLBACK_BEFORE_FRAG     before_frag
#define STEM_CALLBACK_RETURNABLE_FRAG returnable_frag

#include "../../disco/stem/fd_stem.c"

static ulong
max_event_sz( fd_topo_tile_t const * tile FD_PARAM_UNUSED ) {
  return sizeof(fd_event_accdb_partition_added_t);
}

fd_topo_run_tile_t fd_tile_snapin = {
  .name                     = NAME,
  .populate_allowed_fds     = populate_allowed_fds,
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .max_event_sz             = max_event_sz,
  .run                      = stem_run,
};

#undef NAME
