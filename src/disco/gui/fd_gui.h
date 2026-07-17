#ifndef HEADER_fd_src_disco_gui_fd_gui_h
#define HEADER_fd_src_disco_gui_fd_gui_h

#include "fd_gui_peers.h"
#include "fd_gui_hist.h"

#include "../topo/fd_topo.h"

#include "../../ballet/txn/fd_txn.h"
#include "../../disco/tiles.h"
#include "../../disco/fd_txn_p.h"
#include "../../disco/bundle/fd_bundle_tile.h"
#include "../../discof/restore/fd_snapct_tile.h"
#include "../../discof/restore/utils/fd_ssmsg.h"
#include "../../discof/tower/fd_tower_tile.h"
#include "../../discof/replay/fd_replay_tile.h"
#include "../../flamenco/leaders/fd_leaders.h"
#include "../../flamenco/runtime/sysvar/fd_sysvar_epoch_schedule.h" /* fd_slot_to_epoch */
#include "../../util/fd_util_base.h"
#include "../../util/hist/fd_histf.h"
#include "../../waltz/http/fd_http_server.h"
#include "../../flamenco/accdb/fd_accdb_cache.h"
#include "../../flamenco/accdb/fd_accdb_shmem.h"

/* ---- Network Bandwidth Monitoring ----------------------------------- */

#define FD_GUI_NETWORK_EMA_HALF_LIFE_NS (1000000000L) /* 1 second in nanoseconds */
#define FD_GUI_NET_PROTO_CNT            (6UL)         /* turbine, gossip, tpu, repair, rserve, metric */
#define FD_GUI_NET_RATE_MAX_WINDOW_NS   (300L*1000L*1000L*1000L) /* 5 minutes in nanoseconds */

/* Monotonic deque element for sliding-window max tracking of
   EMA-smoothed network throughput. */
struct fd_gui_rate_entry {
  long   ts_nanos;
  double value;
};
typedef struct fd_gui_rate_entry fd_gui_rate_entry_t;

/* At 100 ms sampling, 5 minutes = 3000 samples. */
#define DEQUE_NAME fd_gui_rate_deque
#define DEQUE_T    fd_gui_rate_entry_t
#define DEQUE_MAX  4096UL
#include "../../util/tmpl/fd_deque.c"

/* ---- History Buffers ------------------------------------------------ */

#define FD_GUI_TPS_HISTORY_WINDOW_DURATION_SECONDS (10L)
#define FD_GUI_TPS_HISTORY_SAMPLE_CNT              (150UL)

#define FD_GUI_PROGCACHE_HISTORY_CNT               (600UL) /* 60s / 100ms */

#define FD_GUI_TURBINE_RECV_TIMESTAMPS (750UL)

/* One use case for tracking ingress shred slot is to estimate when we
   have caught up to the tip of the blockchain.  A naive approach would
   be to track the maximum seen slot.

   maximum_seen_slot = fd_ulong_max( maximum_seen_slot, new_slot_from_shred_tile );

   Unfortunately, this doesn't always work because a validator can send
   a slot number that is arbitrarily large on a false fork. Also, these
   shreds can be for a repair response, which can be arbitrarily small.

   The prospects here seem bleak, but not all hope is lost!  We know
   that for a sufficiently large historical time window there is a high
   probability that at least some of the slots we observe will be valid
   recent turbine slots. For a sufficiently small window there is a high
   probability that all the observed shred slots are non-malicious (i.e.
   not arbitrarily large).

   In practice shred slots are almost always non-malicious. We can keep
   a history of the 12 largest slots we've seen in the past 4.8 seconds.
   We'll consider the "tip" of the blockchain to be the maximum slot in
   our history. This way, if we receive maliciously large slot number,
   it will be evicted after 4.8 seconds. If we receive a small slot from
   a repair response it will be ignored because we've seen other larger
   slots, meaning that our estimate is eventually consistent. For
   monitoring purposes this is sufficient.

   The worst case scenario is that this validator receives an incorrect
   shred slot slot more than once every 3 leader rotations. Before the
   previous incorrect slot is evicted from the history, a new one takes
   it's place and we wouldn't never get a correct estimate of the tip of
   the chain.  We also would indefinitely think that that we haven't
   caught up. This would require the chain having perpetually malicious
   leaders with adjacent rotations.  If this happens, Solana has bigger
   problems. */
#define FD_GUI_TURBINE_SLOT_HISTORY_SZ (  12UL )

/* Like the turbine slot, the latest repair slot can also swing to
   arbitrarily large values due to a malicious fork switch.  The gui
   provides the same guarantees for freshness and accuracy.  This
   history is somewhat larger to handle the increased repair bandwidth
   during catch up. */
#define FD_GUI_REPAIR_SLOT_HISTORY_SZ  ( 512UL )

/* FD_GUI_*_CATCH_UP_HISTORY_SZ is the capacity of the record of slots
   seen from repair or turbine during the catch up stage at startup.
   These buffers are run-length encoded, so they will typically be very
   small.  The worst-case scenario is unbounded, so bounds here are
   determined heuristically. */
#define FD_GUI_REPAIR_CATCH_UP_HISTORY_SZ  (4096UL)
#define FD_GUI_TURBINE_CATCH_UP_HISTORY_SZ (4096UL)

/* FD_GUI_SHREDS_HISTORY_SZ the number of shred events in our historical
   shred store.  Shred events here belong to finalized slots which means
   we won't record any additional shred updates for these slots.

   All shred events for a given slot will be places in a contiguous
   chunk in the array, and the bounding indicies are stored in the
   slot history.  Within a slot chunk, shred events are ordered in the
   ordered they were recorded by the gui tile.

   Ideally, we have enough space to store an epoch's worth of events,
   but we are limited by realistic memory consumption.  Instead, we pick
   bound heuristically. */
#define FD_GUI_SHREDS_HISTORY_SZ     (432000UL*2000UL*4UL / 12UL)

#define FD_GUI_SLOT_RANKINGS_SZ (100UL)
#define FD_GUI_SLOT_RANKING_TYPE_ASC  (0)
#define FD_GUI_SLOT_RANKING_TYPE_DESC (1)

/* ---- Boot ----------------------------------------------------------- */

#define FD_GUI_BOOT_PROGRESS_TYPE_JOINING_GOSSIP               (1)
#define FD_GUI_BOOT_PROGRESS_TYPE_LOADING_FULL_SNAPSHOT        (2)
#define FD_GUI_BOOT_PROGRESS_TYPE_LOADING_INCREMENTAL_SNAPSHOT (3)
#define FD_GUI_BOOT_PROGRESS_TYPE_WAITING_FOR_SUPERMAJORITY    (4)
#define FD_GUI_BOOT_PROGRESS_TYPE_CATCHING_UP                  (5)
#define FD_GUI_BOOT_PROGRESS_TYPE_RUNNING                      (6)

#define FD_GUI_BOOT_PROGRESS_FULL_SNAPSHOT_IDX        (0UL)
#define FD_GUI_BOOT_PROGRESS_INCREMENTAL_SNAPSHOT_IDX (1UL)
#define FD_GUI_BOOT_PROGRESS_SNAPSHOT_CNT             (2UL)

#define FD_GUI_SLOT_LEVEL_INCOMPLETE               (0)
#define FD_GUI_SLOT_LEVEL_COMPLETED                (1)
#define FD_GUI_SLOT_LEVEL_OPTIMISTICALLY_CONFIRMED (2)
#define FD_GUI_SLOT_LEVEL_ROOTED                   (3)
#define FD_GUI_SLOT_LEVEL_FINALIZED                (4)

/* "Skipped" means not present on the canonical fork (i.e. tower_slot's
   fork). Since tower_slot may fall behind replay, we need a third state
   to assign slots which are ahead of it. */
#define FD_GUI_SKIP_STATUS_UNKNOWN     ((uchar)0)
#define FD_GUI_SKIP_STATUS_NOT_SKIPPED ((uchar)1)
#define FD_GUI_SKIP_STATUS_SKIPPED     ((uchar)2)

#define FD_GUI_TXN_FLAGS_STARTED         ( 1U)
#define FD_GUI_TXN_FLAGS_ENDED           ( 2U)
#define FD_GUI_TXN_FLAGS_IS_SIMPLE_VOTE  ( 4U)
#define FD_GUI_TXN_FLAGS_FROM_BUNDLE     ( 8U)
#define FD_GUI_TXN_FLAGS_LANDED_IN_BLOCK (16U)

#define FD_GUI_VOTE_STATE_NON_VOTING (0)
#define FD_GUI_VOTE_STATE_VOTING     (1)
#define FD_GUI_VOTE_STATE_DELINQUENT (2)

#define FD_GUI_MAX_VOTE_DISTANCE     (512UL)

#define FD_GUI_LANDED_VOTE_MAX      (4096UL)

#define FD_GUI_SLOT_SHRED_REPAIR_REQUEST          (0UL)
#define FD_GUI_SLOT_SHRED_SHRED_RECEIVED_TURBINE  (1UL)
#define FD_GUI_SLOT_SHRED_SHRED_RECEIVED_REPAIR   (2UL)
#define FD_GUI_SLOT_SHRED_SHRED_REPLAY_EXEC_DONE  (3UL)
#define FD_GUI_SLOT_SHRED_SHRED_SLOT_COMPLETE     (4UL)
/* #define FD_GUI_SLOT_SHRED_SHRED_REPLAY_EXEC_START (5UL) // UNUSED */
#define FD_GUI_SLOT_SHRED_SHRED_PUBLISHED         (6UL)

struct fd_gui_tile_timers {
  long   sample_time_nanos; /* wallclock ns this sample was taken; identical across the per-tile records. */
  ulong  tile_idx;          /* global tile index into topo->tiles. */
  ulong timers[ FD_METRICS_ENUM_TILE_REGIME_CNT ];
  ulong sched_timers[ FD_METRICS_ENUM_CPU_REGIME_CNT ];

  int    in_backp;
  ushort last_cpu;
  uchar  status;
  ulong  heartbeat;
  ulong  backp_cnt;
  ulong  nvcsw;
  ulong  nivcsw;
  ulong  minflt;
  ulong  majflt;
  ulong  interrupts;
  ulong  tlb_shootdowns;
  ulong  timer_ticks;
};

typedef struct fd_gui_tile_timers fd_gui_tile_timers_t;

struct fd_gui_tile_timers_hist {
  long   sample_time_nanos;
  ushort tile_idx;
  uchar  alive;
  uchar  in_backp;
  ushort timers[ FD_METRICS_ENUM_TILE_REGIME_CNT ];
  ushort sched_timers[ FD_METRICS_ENUM_CPU_REGIME_CNT ];
  ushort idle_ratio;
  ushort last_cpu;
  ulong  backp_msgs;
  ulong  nvcsw;
  ulong  nivcsw;
  ulong  minflt;
  ulong  majflt;
  ulong  interrupts;
  ulong  tlb_shootdowns;
  ulong  timer_ticks;
};

typedef struct fd_gui_tile_timers_hist fd_gui_tile_timers_hist_t;

struct fd_gui_scheduler_counts {
  long  sample_time_ns;
  ulong regular;
  ulong votes;
  ulong conflicting;
  ulong bundles;
};

typedef struct fd_gui_scheduler_counts fd_gui_scheduler_counts_t;

struct fd_gui_network_stats {
  /* total bytes accumulated */
  struct {
    ulong turbine;
    ulong gossip;
    ulong tpu;
    ulong repair;
    ulong rserve;
    ulong metric;
  } in, out;
};

typedef struct fd_gui_network_stats fd_gui_network_stats_t;

struct fd_gui_accounts_stats {
  /* Raw counters/gauges read from tile metric pages.  Stored so we can
     compute deltas (and per-second rates) against a previous snapshot. */
  long  sample_time_nanos;

  /* Disk (gauges from accdb tile). */
  ulong accounts_total;
  ulong accounts_capacity;
  ulong disk_allocated_bytes;
  ulong disk_current_bytes;
  ulong disk_used_bytes;

  /* Compaction (gauges + counters from accdb tile). */
  ulong in_compaction;
  ulong compactions_requested;
  ulong compactions_completed;
  ulong accounts_relocated_bytes;

  /* Cache occupancy (gauges from accdb tile, per class). */
  ulong cache_class_used           [ FD_ACCDB_CACHE_CLASS_CNT ];
  ulong cache_class_max            [ FD_ACCDB_CACHE_CLASS_CNT ];
  ulong cache_class_reserved       [ FD_ACCDB_CACHE_CLASS_CNT ];
  /* Preeviction thresholds, expressed as used-slot counts directly
     comparable to cache_class_used / cache_class_max. */
  ulong cache_class_target_used    [ FD_ACCDB_CACHE_CLASS_CNT ];
  ulong cache_class_low_water_used [ FD_ACCDB_CACHE_CLASS_CNT ];

  /* Aggregate counters summed across all accdb consumer tiles. */
  ulong acquired;                   /* total acquires */
  ulong acquired_writable;          /* writable subset of acquires (RW tiles only) */
  ulong acquired_per_class           [ FD_ACCDB_CACHE_CLASS_CNT ]; /* acquires attributed to a class (RW tiles only) */
  ulong acquired_writable_per_class  [ FD_ACCDB_CACHE_CLASS_CNT ]; /* writable acquires attributed to a class (RW tiles only) */
  ulong not_found_per_class          [ FD_ACCDB_CACHE_CLASS_CNT ]; /* misses, per class */
  ulong evicted_per_class            [ FD_ACCDB_CACHE_CLASS_CNT ];
  ulong preevicted_per_class         [ FD_ACCDB_CACHE_CLASS_CNT ];
  ulong committed_new_per_class      [ FD_ACCDB_CACHE_CLASS_CNT ];
  ulong committed_overwrite_per_class[ FD_ACCDB_CACHE_CLASS_CNT ];

  /* IO counters.  bytes_written/read_ops/write_ops are summed across
     all consumer tiles; bytes_written_accdb is the bytes written by
     the accdb tile itself (background preevict + compaction), used to
     compute the prewrite ratio. */
  ulong bytes_read;
  ulong bytes_copied;
  ulong bytes_written;
  ulong bytes_written_accdb;
  ulong read_ops;
  ulong write_ops;
};

typedef struct fd_gui_accounts_stats fd_gui_accounts_stats_t;

struct fd_gui_turbine_slot {
 ulong slot;
 long timestamp;
};

typedef struct fd_gui_turbine_slot fd_gui_turbine_slot_t;

struct __attribute__((packed)) fd_gui_slot_history_shred_event {
  long   timestamp;
  uint   slot;
  ushort shred_idx;
  uchar  event;
};

typedef struct fd_gui_slot_history_shred_event fd_gui_slot_history_shred_event_t;

struct __attribute__((packed)) fd_gui_slot {
  ulong     slot;             /* this record's slot number. */
  ulong     bank_seq;         /* this block's fork discriminator (the record's own key bank_seq).*/
  ulong     parent_bank_seq;  /* parent block's fork discriminator (ULONG_MAX if unknown) */
  long      completed_time;   /* slot completion wallclock ns (LONG_MAX if unknown) */
  uint      shred_cnt;        /* slot->shred_cnt at completion */
  fd_hash_t block_hash;       /* block hash of the slot */
  uchar     mine:1;           /* 1 if this was our leader slot */
  uchar     is_voter:1;       /* 1 if we were structurally a voter when this slot was replayed */
  uint      vote_success;     /* successful vote txn count     (UINT_MAX if unknown) */
  uint      vote_failed;      /* failed vote txn count         (UINT_MAX if unknown) */
  uint      nonvote_success;  /* successful nonvote txn count  (UINT_MAX if unknown) */
  uint      nonvote_failed;   /* failed nonvote txn count      (UINT_MAX if unknown) */
  uchar     vote_latency;     /* our raw vote latency for the slot (UCHAR_MAX if did not vote) */
  uchar     vote_latency_exact;/* our vote latency minus skipped slots on the landed fork, or FD_GUI_VOTE_LATENCY_NOT_VOTED if no vote landed. */
  uint      max_compute_units;/* block compute unit limit      (UINT_MAX if unknown) */
  uint      compute_units;    /* block compute units consumed  (UINT_MAX if unknown) */
  ulong     transaction_fee;  /* total transaction fee         (ULONG_MAX if unknown) */
  ulong     priority_fee;     /* total priority fee            (ULONG_MAX if unknown) */
  ulong     tips;             /* total tips                    (ULONG_MAX if unknown) */
  ulong     parent_slot;      /* parent (on-fork) slot number  (ULONG_MAX if unknown) */
  long      parent_completed_time; /* parent block completion wallclock ns (LONG_MAX if unknown) */
  ulong     vote_slot;        /* most recent slot we had landed a vote for as of this slot's replay (ULONG_MAX if unknown) */
  uchar     skip;             /* one of FD_GUI_SKIP_STATUS_* */
  uchar     level;            /* one of FD_GUI_SLOT_LEVEL_* */
};

typedef struct fd_gui_slot fd_gui_slot_t;

struct __attribute__((packed)) fd_gui_leader_slot {
  ulong     slot;                         /* this record's slot number (the record's own key). */
  ulong     bank_seq;                     /* this block's fork discriminator (the record's own key bank_seq). */
  long      leader_start_time;            /* wallclock ns we became leader */
  long      leader_end_time;              /* wallclock ns we stopped being leader */
  fd_hash_t block_hash;                   /* block hash of the produced block */
  ulong     max_microblocks;              /* initial max microblocks packable into the slot */
  uint      microblocks_upper_bound;      /* final/exact microblock upper bound */
  uint      begin_microblocks;            /* microblocks started (pack -> bank) */
  uint      end_microblocks;              /* microblocks ended (bank -> poh) */
  fd_done_packing_t scheduler_stats[ 1 ]; /* pack "done packing" record (limits, usage, results) */
  uchar     unbecame_leader;              /* 1 if we relinquished leadership for this slot */
};

typedef struct fd_gui_leader_slot fd_gui_leader_slot_t;

struct fd_gui_slot_ranking {
  ulong slot;
  ulong value;
  int   type;
};
typedef struct fd_gui_slot_ranking fd_gui_slot_ranking_t;

struct fd_gui_slot_rankings {
  fd_gui_slot_ranking_t largest_tips           [ FD_GUI_SLOT_RANKINGS_SZ+1UL ];
  fd_gui_slot_ranking_t largest_fees           [ FD_GUI_SLOT_RANKINGS_SZ+1UL ];
  fd_gui_slot_ranking_t largest_rewards        [ FD_GUI_SLOT_RANKINGS_SZ+1UL ];
  fd_gui_slot_ranking_t largest_duration       [ FD_GUI_SLOT_RANKINGS_SZ+1UL ];
  fd_gui_slot_ranking_t largest_compute_units  [ FD_GUI_SLOT_RANKINGS_SZ+1UL ];
  fd_gui_slot_ranking_t largest_skipped        [ FD_GUI_SLOT_RANKINGS_SZ+1UL ];
  fd_gui_slot_ranking_t largest_rewards_per_cu [ FD_GUI_SLOT_RANKINGS_SZ+1UL ];
  fd_gui_slot_ranking_t smallest_tips          [ FD_GUI_SLOT_RANKINGS_SZ+1UL ];
  fd_gui_slot_ranking_t smallest_fees          [ FD_GUI_SLOT_RANKINGS_SZ+1UL ];
  fd_gui_slot_ranking_t smallest_rewards       [ FD_GUI_SLOT_RANKINGS_SZ+1UL ];
  fd_gui_slot_ranking_t smallest_rewards_per_cu[ FD_GUI_SLOT_RANKINGS_SZ+1UL ];
  fd_gui_slot_ranking_t smallest_duration      [ FD_GUI_SLOT_RANKINGS_SZ+1UL ];
  fd_gui_slot_ranking_t smallest_compute_units [ FD_GUI_SLOT_RANKINGS_SZ+1UL ];
  fd_gui_slot_ranking_t smallest_skipped       [ FD_GUI_SLOT_RANKINGS_SZ+1UL ];
};

typedef struct fd_gui_slot_rankings fd_gui_slot_rankings_t;

#define FD_GUI_EPOCH_SCHED_CNT ((MAX_SLOTS_PER_EPOCH+FD_EPOCH_SLOTS_PER_ROTATION-1UL)/FD_EPOCH_SLOTS_PER_ROTATION)
#define FD_GUI_EPOCH_PUB_CNT   (MAX_COMPRESSED_STAKE_WEIGHTS+1UL) /* +1 for indeterminate leader */

#define FD_GUI_VOTE_LATENCY_NOT_VOTED ((uchar)(UCHAR_MAX))     /* vote missing */
#define FD_GUI_VOTE_LATENCY_MAX       ((uchar)(UCHAR_MAX-1UL)) /* largest observable vote latency */

struct fd_gui_epoch {
  ulong epoch;
  ulong start_slot;
  ulong slot_cnt;                        /* end_slot = start_slot + slot_cnt - 1 */
  long  start_time;                      /* epoch start wallclock ns (LONG_MAX if unknown) */
  long  end_time;                        /* epoch end wallclock ns   (LONG_MAX if unknown) */
  long  target_slot_duration_ns;         /* protocol target slot duration */
  ulong my_total_slots;                  /* our leader slots seen this epoch */
  ulong my_skipped_slots;                /* our skipped leader slots this epoch */
  ulong rankings_slot;                   /* one more than the largest slot processed into rankings */
  fd_gui_slot_rankings_t rankings   [ 1 ]; /* global slot rankings */
  fd_gui_slot_rankings_t my_rankings[ 1 ]; /* my slots only */

  /* Arrays of FD_GUI_VOTE_LATENCY_* */
  uchar latency      [ MAX_SLOTS_PER_EPOCH ];
  uchar latency_exact[ MAX_SLOTS_PER_EPOCH ];
  uchar is_voter     [ MAX_SLOTS_PER_EPOCH ]; /* 1 if we were structurally a voter when this slot was replayed */

  fd_epoch_schedule_t epoch_schedule;    /* slot<->epoch conversion (fd_slot_to_epoch) */
  ulong               pub_cnt;           /* number of deduped leader pubkeys in pub[] */
  ulong               stakes_cnt;        /* number of entries in stakes[] */
  uint                sched[ FD_GUI_EPOCH_SCHED_CNT ]; /* rotation -> index into pub[] */
  fd_pubkey_t         pub[ FD_GUI_EPOCH_PUB_CNT ];     /* deduped leaders (+ indeterminate) */
  fd_vote_stake_weight_t stakes[ MAX_COMPRESSED_STAKE_WEIGHTS ];
};

typedef struct fd_gui_epoch fd_gui_epoch_t;

struct fd_gui_ephemeral_slot {
  ulong slot; /* ULONG_MAX indicates invalid/evicted */
  long timestamp_arrival_nanos;
};
typedef struct fd_gui_ephemeral_slot fd_gui_ephemeral_slot_t;

struct __attribute__((packed)) fd_gui_store_txn_start {
  ulong slot;
  ulong bank_seq;               /* per-fork bank sequence */
  ulong txn_idx;                /* per-(bank_seq) transaction index */
  uchar signature[ FD_TXN_SIGNATURE_SZ ];
  ulong transaction_fee;
  ulong priority_fee;
  long  timestamp_arrival_nanos;
  long  microblock_start_ns;    /* absolute ns (begin tspub) */
  uint  compute_units_requested;
  uint  microblock_idx;
  uint  source_ipv4;
  uchar source_tpu;
  uchar flags;                  /* STARTED | IS_SIMPLE_VOTE | FROM_BUNDLE */
};
typedef struct fd_gui_store_txn_start fd_gui_store_txn_start_t;

struct __attribute__((packed)) fd_gui_store_txn_end {
  ulong slot;
  ulong bank_seq;               /* per-fork bank sequence */
  ulong txn_idx;
  long  timestamp_arrival_nanos;
  long  microblock_end_ns;      /* absolute ns (end tspub) */
  fd_txn_ns_dt_t txn_ns_dt;     /* relative to microblock_start */
  ulong tips;
  uint  compute_units_consumed;
  uint  bank_idx;
  uint  error_code;
  uchar flags;                  /* ENDED | LANDED_IN_BLOCK */
};
typedef struct fd_gui_store_txn_end fd_gui_store_txn_end_t;

struct fd_gui_slot_txn_join {
  fd_gui_store_txn_start_t const * start;
  fd_gui_store_txn_end_t   const * end;
};

typedef struct fd_gui_slot_txn_join fd_gui_slot_txn_join_t;

struct fd_gui_txn_waterfall {
  long sample_time_nanos; /* wallclock ns this sample was taken. */
  struct {
    ulong quic;
    ulong udp;
    ulong gossip;
    ulong block_engine;
    ulong pack_cranked;
  } in;

  struct {
    ulong net_overrun;
    ulong quic_overrun;
    ulong quic_frag_drop;
    ulong quic_abandoned;
    ulong tpu_quic_invalid;
    ulong tpu_udp_invalid;
    ulong verify_overrun;
    ulong verify_parse;
    ulong verify_failed;
    ulong verify_duplicate;
    ulong dedup_duplicate;
    ulong resolv_lut_failed;
    ulong resolv_expired;
    ulong resolv_ancient;
    ulong resolv_no_ledger;
    ulong resolv_retained;
    ulong pack_invalid;
    ulong pack_invalid_bundle;
    ulong pack_expired;
    ulong pack_already_executed;
    ulong pack_retained;
    ulong pack_wait_full;
    ulong pack_leader_slow;
    ulong bank_invalid;
    ulong bank_nonce_already_advanced;
    ulong bank_nonce_advance_failed;
    ulong bank_nonce_wrong_blockhash;
    ulong block_success;
    ulong block_fail;
  } out;
};

typedef struct fd_gui_txn_waterfall fd_gui_txn_waterfall_t;

struct fd_gui_tile_stats {
  long  sample_time_nanos;

  ulong net_in_rx_bytes;           /* Number of bytes received by the net or sock tile*/
  ulong quic_conn_cnt;             /* Number of active QUIC connections */
  fd_histf_t bundle_rx_delay_hist; /* Histogram of bundle rx delay */
  ulong bundle_rtt_smoothed_nanos; /* RTT (nanoseconds) moving average */
  ulong verify_drop_cnt;           /* Number of transactions dropped by verify tiles */
  ulong verify_total_cnt;          /* Number of transactions received by verify tiles */
  ulong dedup_drop_cnt;            /* Number of transactions dropped by dedup tile */
  ulong dedup_total_cnt;           /* Number of transactions received by dedup tile */
  ulong pack_buffer_cnt;           /* Number of buffered transactions in the pack tile */
  ulong pack_buffer_capacity;      /* Total size of the pack transaction buffer */
  ulong bank_txn_exec_cnt;         /* Number of transactions processed by the bank tile */
  ulong net_out_tx_bytes;          /* Number of bytes sent by the net or sock tile */
};

typedef struct fd_gui_tile_stats fd_gui_tile_stats_t;


struct fd_gui_boot_progress {
  uchar phase;
  long joining_gossip_time_nanos;
  struct {
    ulong  slot;
    uint   peer_addr;
    ushort peer_port;
    ulong  total_bytes_compressed;
    long   reset_time_nanos;          /* UNIX nanosecond timestamp */
    long   sample_time_nanos;
    ulong  reset_cnt;

    ulong read_bytes_compressed;
    char  read_path[ PATH_MAX+30UL ]; /* URL or filesystem path.  30 is fd_cstr_nlen( "https://255.255.255.255:12345/", ULONG_MAX ) */

    ulong decompress_bytes_decompressed;
    ulong decompress_bytes_compressed;

    ulong insert_bytes_decompressed;
    char  insert_path[ PATH_MAX ];
    ulong insert_accounts_current;

    ulong snapwr_in_bytes_decompressed;
    ulong snapwr_out_bytes_decompressed;
    ulong snapwr_accounts_current;
  } loading_snapshot[ FD_GUI_BOOT_PROGRESS_SNAPSHOT_CNT ];

  ulong wfs_total_stake;
  ulong wfs_connected_stake;
  ulong wfs_total_peers;
  ulong wfs_connected_peers;
  ulong wfs_attempt;

  long  catching_up_time_nanos;
  ulong catching_up_first_replay_slot;
};

typedef struct fd_gui_boot_progress fd_gui_boot_progress_t;

/* Triangular-weighted moving window over per-snap deltas.  Snap
   cadence is ~100ms, window is FD_GUI_ACCDB_WIN_SAMPLES samples
   (~5s).  The output rate for any metric is:

     rate = sum( w[i] * delta[i] ) / sum( w[i] * dt[i] )

   where w[i] is the triangular weight (newest sample heaviest,
   oldest weight=1).  This is fully caught up to a new rate after
   the window length but smoother than a boxcar (no cliff edge as
   samples age out). */
#define FD_GUI_ACCDB_WIN_SAMPLES 50UL

/* Per-partition triangular-weighted windows for read/write rates.
   Sized to match the accdb partition pool ceiling (8192).  Rates
   are derived in fd_gui_printf via fd_gui_accdb_weighted_rate. */
#define FD_GUI_MAX_PARTITIONS 8192UL

/* Per-tile accdb stats.  At init we walk the topology and assign a
   slot to each tile that uses the account database (execle, execrp,
   replay, tower, rpc, resolv, snapwr).  Each slot keeps cumulative
   previous values for delta computation and a triangular-weighted
   delta ring (same cadence / weighting as the aggregate rings). */
#define FD_GUI_MAX_ACCDB_TILES 64UL

/* Tile kinds.  Determines which subset of metrics to read. */
#define FD_GUI_ACCDB_TILE_KIND_RW     0  /* execle, execrp, replay, tower */
#define FD_GUI_ACCDB_TILE_KIND_RO     1  /* rpc, resolv */
#define FD_GUI_ACCDB_TILE_KIND_SNAPWR 2  /* snapwr (direct disk writer during snapshot load) */
#define FD_GUI_ACCDB_TILE_KIND_ACCDB  3  /* accdb tile itself (prewrite + compaction writes) */

/* 60s-history rings for the per-tile sparkline.  Each bucket is the
   sum of per-snap deltas that fell into that bucket window.
   index 0 = current bucket (in-flight), older buckets follow.  When
   a bucket interval elapses we shift right (older buckets drop off
   the end) and start a new index-0 bucket.  240 buckets x 250ms =
   60 second window. */
#define FD_GUI_ACCDB_SPARKLINE_SAMPLES   240UL
#define FD_GUI_ACCDB_SPARKLINE_BUCKET_NS 250000000L

struct fd_gui_accdb_stats {
  ulong accdb_win_idx;        /* next write index */
  ulong accdb_win_count;      /* samples filled, capped at FD_GUI_ACCDB_WIN_SAMPLES */
  long  accdb_win_dt_nanos [ FD_GUI_ACCDB_WIN_SAMPLES ];

  /* Aggregate delta rings (units per snap). */
  ulong agg_acquired_win          [ FD_GUI_ACCDB_WIN_SAMPLES ];
  ulong agg_acquired_writable_win [ FD_GUI_ACCDB_WIN_SAMPLES ];
  ulong agg_bytes_read_win        [ FD_GUI_ACCDB_WIN_SAMPLES ];
  ulong agg_bytes_copied_win      [ FD_GUI_ACCDB_WIN_SAMPLES ];
  ulong agg_bytes_written_win     [ FD_GUI_ACCDB_WIN_SAMPLES ];
  ulong agg_bytes_written_accdb_win[FD_GUI_ACCDB_WIN_SAMPLES ];
  ulong agg_read_ops_win          [ FD_GUI_ACCDB_WIN_SAMPLES ];
  ulong agg_write_ops_win         [ FD_GUI_ACCDB_WIN_SAMPLES ];
  ulong agg_relocated_bytes_win   [ FD_GUI_ACCDB_WIN_SAMPLES ];
  ulong agg_misses_win            [ FD_GUI_ACCDB_WIN_SAMPLES ];

  /* Per-class delta rings (units per snap). */
  ulong class_acq_win         [ FD_ACCDB_CACHE_CLASS_CNT ][ FD_GUI_ACCDB_WIN_SAMPLES ];
  ulong class_acq_wr_win      [ FD_ACCDB_CACHE_CLASS_CNT ][ FD_GUI_ACCDB_WIN_SAMPLES ];
  ulong class_not_found_win   [ FD_ACCDB_CACHE_CLASS_CNT ][ FD_GUI_ACCDB_WIN_SAMPLES ];
  ulong class_evicted_win     [ FD_ACCDB_CACHE_CLASS_CNT ][ FD_GUI_ACCDB_WIN_SAMPLES ];
  ulong class_preevicted_win  [ FD_ACCDB_CACHE_CLASS_CNT ][ FD_GUI_ACCDB_WIN_SAMPLES ];
  ulong class_commit_new_win  [ FD_ACCDB_CACHE_CLASS_CNT ][ FD_GUI_ACCDB_WIN_SAMPLES ];
  ulong class_commit_over_win [ FD_ACCDB_CACHE_CLASS_CNT ][ FD_GUI_ACCDB_WIN_SAMPLES ];

  ulong partition_cnt;            /* live count from accdb_shmem; <= FD_GUI_MAX_PARTITIONS */
  ulong partition_read_ops_win    [ FD_GUI_MAX_PARTITIONS ][ FD_GUI_ACCDB_WIN_SAMPLES ];
  ulong partition_bytes_read_win  [ FD_GUI_MAX_PARTITIONS ][ FD_GUI_ACCDB_WIN_SAMPLES ];
  ulong partition_write_ops_win   [ FD_GUI_MAX_PARTITIONS ][ FD_GUI_ACCDB_WIN_SAMPLES ];
  ulong partition_bytes_written_win[FD_GUI_MAX_PARTITIONS ][ FD_GUI_ACCDB_WIN_SAMPLES ];

  /* Per-partition snapshots (most recent values, for non-rate fields:
     offset, layer, write_offset, bytes_freed, ticks, compaction state). */
  fd_accdb_shmem_partition_info_t partitions[ FD_GUI_MAX_PARTITIONS ];

  /* Cumulative counters from the previous snap for delta computation. */
  ulong partition_prev_read_ops    [ FD_GUI_MAX_PARTITIONS ];
  ulong partition_prev_bytes_read  [ FD_GUI_MAX_PARTITIONS ];
  ulong partition_prev_write_ops   [ FD_GUI_MAX_PARTITIONS ];
  ulong partition_prev_bytes_written[FD_GUI_MAX_PARTITIONS ];

  ulong  accdb_tile_cnt;
  ushort accdb_tile_topo_idx [ FD_GUI_MAX_ACCDB_TILES ]; /* index into topo->tiles */
  uchar  accdb_tile_kind     [ FD_GUI_MAX_ACCDB_TILES ];

  /* Most-recent cumulative values per tile, plus the snapshot from
     the previous snap for delta computation. */
  ulong tile_cur_acquired          [ FD_GUI_MAX_ACCDB_TILES ];
  ulong tile_cur_acquired_writable [ FD_GUI_MAX_ACCDB_TILES ];
  ulong tile_cur_bytes_read        [ FD_GUI_MAX_ACCDB_TILES ];
  ulong tile_cur_bytes_copied      [ FD_GUI_MAX_ACCDB_TILES ];
  ulong tile_cur_bytes_written     [ FD_GUI_MAX_ACCDB_TILES ];
  ulong tile_cur_read_ops          [ FD_GUI_MAX_ACCDB_TILES ];
  ulong tile_cur_write_ops         [ FD_GUI_MAX_ACCDB_TILES ];
  ulong tile_cur_misses            [ FD_GUI_MAX_ACCDB_TILES ];
  ulong tile_cur_evicted           [ FD_GUI_MAX_ACCDB_TILES ];
  ulong tile_cur_committed         [ FD_GUI_MAX_ACCDB_TILES ];
  ulong tile_cur_acquire_calls     [ FD_GUI_MAX_ACCDB_TILES ];
  uchar tile_cur_status            [ FD_GUI_MAX_ACCDB_TILES ]; /* 1=running, 2=shutdown */

  ulong tile_prev_acquired         [ FD_GUI_MAX_ACCDB_TILES ];
  ulong tile_prev_acquired_writable[ FD_GUI_MAX_ACCDB_TILES ];
  ulong tile_prev_bytes_read       [ FD_GUI_MAX_ACCDB_TILES ];
  ulong tile_prev_bytes_copied     [ FD_GUI_MAX_ACCDB_TILES ];
  ulong tile_prev_bytes_written    [ FD_GUI_MAX_ACCDB_TILES ];
  ulong tile_prev_read_ops         [ FD_GUI_MAX_ACCDB_TILES ];
  ulong tile_prev_write_ops        [ FD_GUI_MAX_ACCDB_TILES ];
  ulong tile_prev_misses           [ FD_GUI_MAX_ACCDB_TILES ];
  ulong tile_prev_evicted          [ FD_GUI_MAX_ACCDB_TILES ];
  ulong tile_prev_committed        [ FD_GUI_MAX_ACCDB_TILES ];
  ulong tile_prev_acquire_calls    [ FD_GUI_MAX_ACCDB_TILES ];

  /* Per-tile delta rings. */
  ulong tile_acquired_win         [ FD_GUI_MAX_ACCDB_TILES ][ FD_GUI_ACCDB_WIN_SAMPLES ];
  ulong tile_acquired_writable_win[ FD_GUI_MAX_ACCDB_TILES ][ FD_GUI_ACCDB_WIN_SAMPLES ];
  ulong tile_bytes_read_win       [ FD_GUI_MAX_ACCDB_TILES ][ FD_GUI_ACCDB_WIN_SAMPLES ];
  ulong tile_bytes_copied_win     [ FD_GUI_MAX_ACCDB_TILES ][ FD_GUI_ACCDB_WIN_SAMPLES ];
  ulong tile_bytes_written_win    [ FD_GUI_MAX_ACCDB_TILES ][ FD_GUI_ACCDB_WIN_SAMPLES ];
  ulong tile_read_ops_win         [ FD_GUI_MAX_ACCDB_TILES ][ FD_GUI_ACCDB_WIN_SAMPLES ];
  ulong tile_write_ops_win        [ FD_GUI_MAX_ACCDB_TILES ][ FD_GUI_ACCDB_WIN_SAMPLES ];
  ulong tile_misses_win           [ FD_GUI_MAX_ACCDB_TILES ][ FD_GUI_ACCDB_WIN_SAMPLES ];
  ulong tile_evicted_win          [ FD_GUI_MAX_ACCDB_TILES ][ FD_GUI_ACCDB_WIN_SAMPLES ];
  ulong tile_committed_win        [ FD_GUI_MAX_ACCDB_TILES ][ FD_GUI_ACCDB_WIN_SAMPLES ];
  ulong tile_acquire_calls_win    [ FD_GUI_MAX_ACCDB_TILES ][ FD_GUI_ACCDB_WIN_SAMPLES ];

  long  tile_sparkline_bucket_start_nanos [ FD_GUI_MAX_ACCDB_TILES ];
  ulong tile_sparkline_acq_bucket         [ FD_GUI_MAX_ACCDB_TILES ];
  ulong tile_sparkline_acq_wr_bucket      [ FD_GUI_MAX_ACCDB_TILES ];
  /* Per-second rates (units/second) for the last N completed buckets.
     Newest at index 0, oldest at the end.  Filled lazily as snaps
     complete each bucket interval. */
  double tile_sparkline_acq_history    [ FD_GUI_MAX_ACCDB_TILES ][ FD_GUI_ACCDB_SPARKLINE_SAMPLES ];
  double tile_sparkline_acq_wr_history [ FD_GUI_MAX_ACCDB_TILES ][ FD_GUI_ACCDB_SPARKLINE_SAMPLES ];
  ulong  tile_sparkline_count          [ FD_GUI_MAX_ACCDB_TILES ];  /* completed buckets, capped at FD_GUI_ACCDB_SPARKLINE_SAMPLES */
};

typedef struct fd_gui_accdb_stats fd_gui_accdb_stats_t;

/* fd_gui_summary_t holds the aggregate node-level state rendered by the
   "summary" websocket topic and the terminal dashboard. */

struct fd_gui_summary {
  fd_pubkey_t identity_key[ 1 ];
  int         has_vote_key;
  fd_pubkey_t vote_key[ 1 ];
  char vote_key_base58[ FD_BASE58_ENCODED_32_SZ ];
  char identity_key_base58[ FD_BASE58_ENCODED_32_SZ ];

  int          is_full_client;
  char const * version;
  char const * cluster;
  char         accounts_database_path[ PATH_MAX ];
  char         gui_database_path     [ PATH_MAX ];

  char   wfs_bank_hash[ FD_BASE58_ENCODED_32_SZ ];
  ushort expected_shred_version;
  int    wfs_enabled;

  ulong vote_distance;
  int   vote_state;

  long  startup_time_nanos;

  fd_gui_boot_progress_t boot_progress;
  fd_gui_boot_progress_t prev_boot_progress;

  int schedule_strategy;

  ulong identity_account_balance;
  ulong vote_account_balance;
  ulong estimated_slot_duration_nanos;

  ulong sock_tile_cnt;
  ulong net_tile_cnt;
  ulong quic_tile_cnt;
  ulong verify_tile_cnt;
  ulong resolh_tile_cnt;
  ulong resolv_tile_cnt;
  ulong bank_tile_cnt;
  ulong execle_tile_cnt;
  ulong execrp_tile_cnt;
  ulong shred_tile_cnt;

  ulong slot_rooted;
  ulong slot_optimistically_confirmed;
  ulong slot_estimated;
  ulong slot_caught_up;
  ulong slot_repair;
  ulong slot_turbine;
  ulong slot_reset;
  ulong slot_storage;
  ulong slot_tower;
  ulong slot_tower_bank_seq; /* tracks canonical fork frontier */
  ulong active_fork_cnt;

  struct {
    ulong epoch;
    ulong skipped;
    ulong total;
  } skip_rate[ 2 ];

  fd_gui_ephemeral_slot_t slots_max_turbine[ FD_GUI_TURBINE_SLOT_HISTORY_SZ+1UL ];
  fd_gui_ephemeral_slot_t slots_max_repair [ FD_GUI_REPAIR_SLOT_HISTORY_SZ +1UL ];

  /* catchup_* is run-length encoded. i.e. adjacent pairs represent
     contiguous runs */
  ulong catch_up_turbine[ FD_GUI_TURBINE_CATCH_UP_HISTORY_SZ ];
  ulong catch_up_turbine_sz;

  ulong catch_up_repair[ FD_GUI_REPAIR_CATCH_UP_HISTORY_SZ ];
  ulong catch_up_repair_sz;

  ulong estimated_tps_history_idx;
  struct {
   ulong vote_failed;
   ulong vote_success;
   ulong nonvote_success;
   ulong nonvote_failed;
  } estimated_tps_history[ FD_GUI_TPS_HISTORY_SAMPLE_CNT ];

  fd_gui_network_stats_t network_stats_current[ 1 ];
  fd_gui_network_stats_t network_stats_prev   [ 1 ];
  int                    network_stats_has_prev;

  /* EMA-smoothed network throughput (bytes/sec) with a 1-second
     half-life. */
  double                   ingress_ema[ FD_GUI_NET_PROTO_CNT ];
  double                   egress_ema[ FD_GUI_NET_PROTO_CNT ];
  long                     net_rate_prev_ts;
  int                      net_rate_ema_ready;
  fd_gui_rate_entry_t *    ingress_maxq;
  fd_gui_rate_entry_t *    egress_maxq;

  fd_gui_accdb_stats_t    accdb[ 1 ];

  fd_gui_accounts_stats_t accounts_stats_reference[ 1 ];
  fd_gui_accounts_stats_t accounts_stats_current  [ 1 ];
  int                     accounts_stats_have_reference;

  fd_gui_txn_waterfall_t txn_waterfall_reference[ 1 ];
  fd_gui_txn_waterfall_t txn_waterfall_current  [ 1 ];

  fd_gui_tile_stats_t tile_stats_reference[ 1 ];
  fd_gui_tile_stats_t tile_stats_current  [ 1 ];

  ulong progcache_history_idx;
  ulong progcache_hits_history   [ FD_GUI_PROGCACHE_HISTORY_CNT ];
  ulong progcache_lookups_history[ FD_GUI_PROGCACHE_HISTORY_CNT ];
  ulong progcache_hits_1min;
  ulong progcache_lookups_1min;

  fd_gui_tile_timers_t      tile_timers_reference[ FD_TOPO_MAX_TILES ];
  fd_gui_tile_timers_t      tile_timers_current  [ FD_TOPO_MAX_TILES ];
  fd_gui_tile_timers_hist_t tile_timers_packed   [ FD_TOPO_MAX_TILES ];

  /* Topo tile indices in display order, built once on init. */
  ulong tile[ FD_TOPO_MAX_TILES ];
  ulong tile_cnt;
};

typedef struct fd_gui_summary fd_gui_summary_t;

struct fd_gui {
  fd_http_server_t * http;
  fd_topo_t const * topo;
  fd_accdb_shmem_t const * accdb_shmem;

  void * db; /* GUI database */
  void * hist;

  double tick_per_ns;
  ulong  tile_cnt;

  long next_sample_1sec;
  long next_sample_200millis;
  long next_sample_100millis;
  long next_sample_50millis;
  long next_sample_40millis;
  long next_sample_25millis;
  long next_sample_10millis;

  int leader_active;

  fd_gui_summary_t summary;

  /* Scratch record for the synthesized skipped slots returned by
     fd_gui_slot_get_canon_safe. */
  fd_gui_slot_t skipped_scratch[ 1 ];

  /* used for estimating slot duration */
  fd_gui_turbine_slot_t turbine_slots[ FD_GUI_TURBINE_RECV_TIMESTAMPS ];

  /* Reusable scratch for reassembling a single slot's transactions at
     query time (fd_gui_printf_slot_transactions_request). */
  struct {
    fd_gui_store_txn_start_t  starts[ FD_MAX_TXN_PER_SLOT ];
    fd_gui_store_txn_end_t    ends  [ FD_MAX_TXN_PER_SLOT ];
    fd_gui_slot_txn_join_t    joined[ FD_MAX_TXN_PER_SLOT ];
  } slot_txn_scratch;

  struct {
    ulong landed_slot;
    ulong landed_bank_seq;
    ulong voted_slot;
  } landed_votes[ FD_GUI_LANDED_VOTE_MAX ];
  ulong landed_vote_cnt;

  struct {
    int has_block_engine;
    char name[ 16 ];
    char url[ 256 ];
    char ip_cstr[ 40 ]; /* IPv4 or IPv6 cstr */
    int status;
  } block_engine;

  struct {
    /* The epoch we are currently in, advanced at epoch_info ingest. */
    ulong current_epoch;
     ulong stored_epoch_cnt;

    int                 has_epoch_schedule;
    fd_epoch_schedule_t epoch_schedule;

    uchar __attribute__((aligned(FD_EPOCH_LEADERS_ALIGN))) lsched_scratch[ FD_EPOCH_LEADERS_FOOTPRINT(MAX_COMPRESSED_STAKE_WEIGHTS, MAX_SLOTS_PER_EPOCH) ];
    fd_vote_stake_weight_t stakes_scratch[ MAX_COMPRESSED_STAKE_WEIGHTS ];
  } epoch;

  fd_gui_peers_ctx_t * peers; /* full-client */

  struct {
    ulong leader_shred_cnt;      /* A gauge counting the number of leader shreds seen on the SHRED_OUT link.  Resets at
                                    the end of a leader slot.  This works because leader fecs are published in order. */

    /* The wallclock-ns timestamp up to which shred events have already
       been pushed to clients. */
    long broadcast_watermark_ns;
  } shreds;
};

typedef struct fd_gui fd_gui_t;

FD_PROTOTYPES_BEGIN

/* fd_gui_tile_timers_diff computes the compact, display-ready diff of a
   single tile's timers between two raw cumulative samples `prev` and
   `cur`, writing it into `out`. */

void
fd_gui_tile_timers_diff( fd_gui_tile_timers_hist_t *  out,
                         fd_gui_tile_timers_t const * prev,
                         fd_gui_tile_timers_t const * cur,
                         ulong                        tile_idx,
                         long                         sample_time_nanos );

FD_FN_CONST ulong
fd_gui_align( void );

ulong
fd_gui_footprint( ulong tile_cnt );

void *
fd_gui_new( void *                   shmem,
            fd_http_server_t *       http,
            char const *             version,
            char const *             cluster,
            uchar const *            identity_key,
            int                      has_vote_key,
            uchar const *            vote_key,
            int                      is_full_client,
            int                      snapshots_enabled,
            int                      is_voting,
            int                      schedule_strategy,
            char const *             wfs_expected_bank_hash_cstr,
            ushort                   expected_shred_version,
            char const *             accounts_database_path,
            char const *             gui_database_path,
            void *                   db,
            fd_topo_t const *        topo,
            fd_accdb_shmem_t const * accdb_shmem,
            long                     now );

fd_gui_t *
fd_gui_join( void * shmem );

void
fd_gui_set_identity( fd_gui_t *    gui,
                     uchar const * identity_pubkey );

void
fd_gui_ws_open( fd_gui_t *  gui,
                ulong       conn_id,
                long now );

int
fd_gui_ws_message( fd_gui_t *    gui,
                   ulong         ws_conn_id,
                   uchar const * data,
                   ulong         data_len );

void
fd_gui_became_leader( fd_gui_t * gui,
                      ulong      slot,
                      long       start_time_nanos,
                      long       end_time_nanos,
                      ulong      max_compute_units,
                      ulong      max_microblocks,
                      ulong      bank_seq );

void
fd_gui_unbecame_leader( fd_gui_t *                gui,
                        ulong                     _slot,
                        fd_done_packing_t const * done_packing,
                        long                      now );

void
fd_gui_microblock_execution_begin( fd_gui_t *   gui,
                                   long         tspub_ns,
                                   ulong        _slot,
                                   fd_txn_e_t * txns,
                                   ulong        txn_cnt,
                                   uint         microblock_idx,
                                   ulong        pack_txn_idx,
                                   ulong        bank_seq,
                                   long         now );

void
fd_gui_microblock_execution_end( fd_gui_t *     gui,
                                 long           tspub_ns,
                                 ulong          bank_idx,
                                 ulong          _slot,
                                 ulong          txn_cnt,
                                 fd_txn_p_t *   txns,
                                 ulong          pack_txn_idx,
                                 fd_txn_ns_dt_t txn_ns_dt,
                                 ulong          tips,
                                 ulong          bank_seq,
                                 long           now );

int
fd_gui_poll( fd_gui_t * gui, long now );

void
fd_gui_handle_block_engine_update( fd_gui_t *                              gui,
                                   fd_bundle_block_engine_update_t const * update );

void
fd_gui_handle_shred( fd_gui_t * gui,
                     ulong      slot,
                     ulong      shred_idx,
                     int        is_turbine,
                     long       tsorig,
                     long       now );

void
fd_gui_handle_leader_fec( fd_gui_t * gui,
                          ulong      slot,
                          ulong      fec_shred_cnt,
                          int        is_end_of_slot,
                          long       tsorig,
                          long       now );

void
fd_gui_handle_exec_txn_done( fd_gui_t * gui,
                             ulong      slot,
                             ulong      start_shred_idx,
                             ulong      end_shred_idx,
                             long       tsorig_ns,
                             long       tspub_ns,
                             long       now );

void
fd_gui_handle_repair_slot( fd_gui_t * gui, ulong slot, long now );

void
fd_gui_handle_repair_request( fd_gui_t * gui, ulong slot, ulong shred_idx, long now );

void
fd_gui_handle_snapshot_update( fd_gui_t *                 gui,
                               fd_snapct_update_t const * msg );

void
fd_gui_stage_snapshot_manifest( fd_gui_t *                       gui,
                                fd_snapshot_manifest_t const *   manifest );

void
fd_gui_handle_epoch_info( fd_gui_t *                  gui,
                          fd_epoch_info_msg_t const * epoch_info,
                          long                        now );

void
fd_gui_handle_tower_update( fd_gui_t *                   gui,
                            fd_tower_slot_done_t const * msg,
                            long                         now );

void
fd_gui_handle_replay_update( fd_gui_t *                         gui,
                             fd_replay_slot_completed_t const * slot_completed,
                             ulong                              vote_slot,
                             long                               now );

void
fd_gui_stage_landed_vote( fd_gui_t * gui,
                          ulong      landed_slot,
                          ulong      landed_bank_seq,
                          ulong      voted_slot );

void
fd_gui_handle_genesis_hash( fd_gui_t *        gui,
                            fd_hash_t const * msg );

/* fd_gui_handle_root_advanced is invoked on REPLAY_SIG_ROOT_ADVANCED.
   It roots the (slot, bank_seq) fork and updates the dependent state. */
void
fd_gui_handle_root_advanced( fd_gui_t * gui,
                             ulong      slot,
                             ulong      bank_seq,
                             long       now );

/* fd_gui_handle_oc_advanced is invoked on REPLAY_SIG_OC_ADVANCED.  It
   marks the (slot, bank_seq) fork optimistically confirmed. */
void
fd_gui_handle_oc_advanced( fd_gui_t * gui,
                           ulong      slot,
                           ulong      bank_seq,
                           long       now );

/* fd_gui_slot_get_canon_safe resolves slot number `_slot` on the
   canonical fork and returns a renderable record. */
fd_gui_slot_t *
fd_gui_slot_get_canon_safe( fd_gui_t * gui, ulong _slot );


/* fd_gui_epoch returns the DB EPOCH record for `epoch`, or NULL if no
   record for that epoch is durable in the store.  The returned pointer
   may be written in place. */
static inline fd_gui_epoch_t *
fd_gui_epoch( fd_gui_t * gui, ulong epoch ) {
  fd_gui_hist_epoch_key_t key[ 1 ]; key->epoch = epoch;
  return (fd_gui_epoch_t *)fd_gui_hist_kv_get( gui, FD_GUI_HIST_EPOCH, key );
}

/* fd_gui_current_epoch returns the record for the current epoch,
   or NULL if no epoch has been ingested yet. */
static inline fd_gui_epoch_t *
fd_gui_current_epoch( fd_gui_t * gui ) {
  if( FD_UNLIKELY( gui->epoch.current_epoch==ULONG_MAX ) ) return NULL;
  return fd_gui_epoch( gui, gui->epoch.current_epoch );
}

/* fd_gui_epoch_get_or_create returns the mutable DB EPOCH record
   for `epoch`, creating it if none exists yet. */
static inline fd_gui_epoch_t *
fd_gui_epoch_get_or_create( fd_gui_t * gui,
                            ulong      epoch,
                            int *      created_out ) {
  fd_gui_epoch_t * rec = fd_gui_epoch( gui, epoch );
  if( FD_LIKELY( rec ) ) { if( created_out ) *created_out = 0; return rec; }

  fd_gui_hist_epoch_key_t key[ 1 ]; key->epoch = epoch;
  rec = fd_gui_hist_kv_get_or_create( gui, FD_GUI_HIST_EPOCH, key );
  if( FD_UNLIKELY( !rec ) ) return NULL;
  gui->epoch.stored_epoch_cnt++; /* account the new epoch on successful creation only */
  if( created_out ) *created_out = 1;
  return rec;
}

/* fd_gui_first_replay_slot returns the lowest slot number the validator
   has authoritative knowledge of during this run. */
static inline ulong
fd_gui_first_replay_slot( fd_gui_t const * gui ) {
  ulong slot_incremental = gui->summary.boot_progress.loading_snapshot[ FD_GUI_BOOT_PROGRESS_INCREMENTAL_SNAPSHOT_IDX ].slot;
  ulong slot_full        = gui->summary.boot_progress.loading_snapshot[ FD_GUI_BOOT_PROGRESS_FULL_SNAPSHOT_IDX ].slot;
  return fd_ulong_if( slot_incremental!=ULONG_MAX, slot_incremental+1UL,
                      fd_ulong_if( slot_full!=ULONG_MAX, slot_full+1UL, ULONG_MAX ) );
}

/* fd_gui_slot_leader_get_or_create returns the mutable returns the
   DB LEADER_SLOT record for (slot, bank_seq), creating it if none
   exists yet. */

static inline fd_gui_leader_slot_t *
fd_gui_slot_leader_get_or_create( fd_gui_t * gui,
                                  ulong      slot,
                                  ulong      bank_seq ) {
  if( FD_UNLIKELY( !gui->db || slot==ULONG_MAX ) ) return NULL;

  fd_gui_hist_leader_slot_key_t key = { .slot = slot, .bank_seq = bank_seq };

  fd_gui_leader_slot_t * rec = fd_gui_hist_kv_get( gui, FD_GUI_HIST_LEADER_SLOT, &key );
  if( FD_LIKELY( rec ) ) return rec;

  fd_gui_leader_slot_t * seed = fd_gui_hist_kv_get_or_create( gui, FD_GUI_HIST_LEADER_SLOT, &key );
  if( FD_UNLIKELY( !seed ) ) return NULL;

  *seed = (fd_gui_leader_slot_t){
    .slot                    = slot,
    .bank_seq                = bank_seq,
    .leader_start_time       = LONG_MAX,
    .leader_end_time         = LONG_MAX,
    .max_microblocks         = ULONG_MAX,
    .microblocks_upper_bound = UINT_MAX,
    .begin_microblocks       = 0U,
    .end_microblocks         = 0U,
    .unbecame_leader         = 0
  };
  return seed;
}

/* fd_gui_slot_leader_get_any returns the DB record for key matching
   (lslot, *), regardless of fork, or NULL if no record exists for lslot. */

static inline fd_gui_leader_slot_t *
fd_gui_slot_leader_get_any( fd_gui_t * gui, ulong _lslot ) {
  if( FD_UNLIKELY( !gui->db || _lslot==ULONG_MAX ) ) return NULL;
  return fd_gui_hist_kv_get_slot_any( gui, FD_GUI_HIST_LEADER_SLOT, _lslot );
}

/* fd_gui_slot_get returns the DB record for the exact key
   (slot, bank_seq), or NULL if none exists. */

static inline fd_gui_slot_t *
fd_gui_slot_get( fd_gui_t * gui, ulong slot, ulong bank_seq ) {
  if( FD_UNLIKELY( slot==ULONG_MAX || bank_seq==ULONG_MAX ) ) return NULL;
  fd_gui_hist_slot_key_t key;
  key.slot = slot; key.bank_seq = bank_seq;
  return (fd_gui_slot_t *)fd_gui_hist_kv_get( gui, FD_GUI_HIST_SLOT, &key );
}

/* fd_gui_slot_parent_get returns the DB record for the parent of `c` on
   c's own fork or NULL if the parent is unknown or has no record. */

static inline fd_gui_slot_t *
fd_gui_slot_parent_get( fd_gui_t * gui, fd_gui_slot_t const * c ) {
  if( FD_UNLIKELY( !c ) ) return NULL;
  return fd_gui_slot_get( gui, c->parent_slot, c->parent_bank_seq );
}

/* fd_gui_slot_get_canon returns the DB record for slot number `_slot`
   on the canonical fork, or NULL if `_slot` is skipped, above the
   canonical tip, or the tip is not yet resolved.  The canonical fork is
   the consensus fork chosen by tower fork choice. */

static inline fd_gui_slot_t *
fd_gui_slot_get_canon( fd_gui_t * gui, ulong _slot ) {
  if( FD_UNLIKELY( _slot==ULONG_MAX ) ) return NULL;

  /* At or below the root the canonical fork has settled, meaning there
     should be exactly one NOT_SKIPPED entry per slot. */
  if( FD_LIKELY( gui->summary.slot_rooted!=ULONG_MAX && _slot<=gui->summary.slot_rooted ) ) {
    fd_gui_hist_kv_slot_iter_t it[ 1 ];
    for( fd_gui_hist_kv_iter_begin( gui, it, FD_GUI_HIST_SLOT, _slot ); it->rec; fd_gui_hist_kv_iter_next( it ) ) {
      fd_gui_slot_t const * rec = (fd_gui_slot_t const *)it->rec;
      if( FD_LIKELY( rec->skip==FD_GUI_SKIP_STATUS_NOT_SKIPPED ) ) return fd_gui_slot_get( gui, _slot, it->bank_seq );
    }
    return NULL; /* skipped on the canonical fork, or no record */
  }

  /* Otherwise do a fork-walk from the canonical frontier. */
  ulong slot     = gui->summary.slot_tower;
  ulong bank_seq = gui->summary.slot_tower_bank_seq;
  for(;;) {
    if( FD_UNLIKELY( slot==ULONG_MAX || bank_seq==ULONG_MAX ) ) return NULL;
    if( FD_UNLIKELY( slot<_slot ) ) return NULL; /* walked past _slot: skipped or above-tip */
    fd_gui_slot_t * n = fd_gui_slot_get( gui, slot, bank_seq );
    if( FD_UNLIKELY( !n ) ) return NULL; /* evicted / no record */
    if( FD_LIKELY( slot==_slot ) ) return n;
    slot     = n->parent_slot;
    bank_seq = n->parent_bank_seq;
  }
}

/* fd_gui_slot_get_any returns the DB record for slot number `_slot`
   without any fork awareness: it is a simple store lookup that returns
   the first record that exists for `_slot`. */

static inline fd_gui_slot_t *
fd_gui_slot_get_any( fd_gui_t * gui, ulong _slot ) {
  if( FD_UNLIKELY( _slot==ULONG_MAX ) ) return NULL;

  fd_gui_hist_kv_slot_iter_t it[ 1 ];
  fd_gui_hist_kv_iter_begin( gui, it, FD_GUI_HIST_SLOT, _slot );
  if( FD_UNLIKELY( !it->rec ) ) return NULL;
  return fd_gui_slot_get( gui, _slot, it->bank_seq );
}

/* fd_gui_slot_is_ancestor returns 1 if anc is known to be an ancestor
   of slot and neither slot is skipped, 0 otherwise. */

static inline int
fd_gui_slot_is_ancestor( fd_gui_t * gui, ulong anc, ulong slot ) {
  /* Walk the canonical fork from `slot` down to the root by slot number,
     hopping the (parent_slot, parent_bank_seq) edge. */
  fd_gui_slot_t * c = fd_gui_slot_get_canon( gui, slot );
  ulong cslot = slot;
  while( c ) {
    if( FD_UNLIKELY( cslot==anc ) ) return 1;
    if( FD_UNLIKELY( cslot<anc ) ) return 0; /* walked past anc on this fork */
    ulong pslot = c->parent_slot;
    c = fd_gui_slot_parent_get( gui, c );
    cslot = pslot;
  }
  return 0;
}

/* fd_gui_slot_skipped_get_parent returns the largest slot number
   smaller than slot that is not skipped. */

static inline ulong
fd_gui_slot_skipped_get_parent( fd_gui_t * gui, ulong slot ) {
  fd_gui_slot_t * c = fd_gui_slot_get_canon( gui, gui->summary.slot_tower );
  while( c ) {
    ulong pslot = c->parent_slot;
    fd_gui_slot_t * p = fd_gui_slot_parent_get( gui, c );
    if( FD_UNLIKELY( p && pslot<slot ) ) return pslot;
    c = p;
  }
  return ULONG_MAX;
}

/* fd_gui_slot_is_skipped returns 1 if `slot` is skipped on the fork
   whose tip is (des, des_bank_seq) and whose root is `root`, 0
   otherwise. */

static inline int
fd_gui_slot_is_skipped( fd_gui_t * gui, ulong root, ulong des, ulong des_bank_seq, ulong slot ) {
  fd_gui_slot_t * c = fd_gui_slot_get( gui, des, des_bank_seq );
  ulong cslot = des;
  while( c ) {
    if( FD_UNLIKELY( root==cslot ) ) return 0; /* on the fork, not skipped */
    ulong pslot = c->parent_slot;
    fd_gui_slot_t * p = fd_gui_slot_parent_get( gui, c );
    if( FD_UNLIKELY( p && pslot<slot && cslot>slot ) ) return 1; /* in-between two on-fork records, skipped */
    c     = p;
    cslot = pslot;
  }
  return 0; /* slot not between root and des, or is unknown */
}

/* fd_gui_get_epoch_by_slot returns the mutable DB EPOCH record covering
   `_slot` (resolved via the epoch schedule), or NULL if no epoch
   schedule is known yet or no record for that epoch is present. */

static inline fd_gui_epoch_t *
fd_gui_get_epoch_by_slot( fd_gui_t * gui, ulong _slot ) {
  if( FD_UNLIKELY( !gui->epoch.has_epoch_schedule ) ) return NULL;
  ulong epoch = fd_slot_to_epoch( &gui->epoch.epoch_schedule, _slot, NULL );
  return fd_gui_epoch( gui, epoch );
}

/* fd_gui_get_slot_leader returns the leader pubkey scheduled for
   `_slot`, or NULL if `epoch` is NULL, `_slot` is outside the epoch,
   or the schedule index is indeterminate. */

static inline fd_pubkey_t const *
fd_gui_get_slot_leader( fd_gui_epoch_t const * epoch, ulong _slot ) {
  if( FD_UNLIKELY( !epoch ) ) return NULL;
  if( FD_UNLIKELY( _slot<epoch->start_slot || _slot>=epoch->start_slot+epoch->slot_cnt ) ) return NULL;
  ulong rot = (_slot - epoch->start_slot)/FD_EPOCH_SLOTS_PER_ROTATION;
  uint  idx = epoch->sched[ rot ];
  if( FD_UNLIKELY( idx>=epoch->pub_cnt ) ) return NULL; /* indeterminate */
  return &epoch->pub[ idx ];
}

/* fd_gui_slot_get_or_create returns the mutable returns the mutable DB
   SLOT record for (_slot, bank_seq), creating it if none exists yet. */

static inline fd_gui_slot_t *
fd_gui_slot_get_or_create( fd_gui_t * gui,
                           ulong      _slot,
                           ulong      _parent_slot,
                           ulong      bank_seq,
                           ulong      parent_bank_seq ) {
  fd_gui_slot_t * rec = fd_gui_slot_get( gui, _slot, bank_seq );
  if( FD_LIKELY( rec ) ) return rec;

  fd_gui_epoch_t * epoch = fd_gui_get_epoch_by_slot( gui, _slot );
  fd_pubkey_t const * slot_leader = fd_gui_get_slot_leader( epoch, _slot );
  int mine = fd_int_if( !!slot_leader, !memcmp( slot_leader->uc, gui->summary.identity_key->uc, 32UL ), 0 );

  fd_gui_hist_slot_key_t key;
  key.slot = _slot; key.bank_seq = bank_seq;
  fd_gui_slot_t * meta = fd_gui_hist_kv_get_or_create( gui, FD_GUI_HIST_SLOT, &key );
  if( FD_UNLIKELY( !meta ) ) return NULL;

  meta->slot              = _slot;
  meta->bank_seq          = bank_seq;
  meta->parent_bank_seq   = parent_bank_seq;
  meta->parent_slot       = _parent_slot;
  meta->vote_slot          = ULONG_MAX;
  meta->vote_latency       = UCHAR_MAX;
  meta->vote_latency_exact = FD_GUI_VOTE_LATENCY_NOT_VOTED;
  meta->max_compute_units = UINT_MAX;
  meta->completed_time    = LONG_MAX;
  meta->parent_completed_time = LONG_MAX;
  meta->mine              = (uchar)(mine & 1);
  meta->is_voter          = 0;
  meta->skip              = FD_GUI_SKIP_STATUS_UNKNOWN;
  meta->level             = (uchar)( _slot ? FD_GUI_SLOT_LEVEL_INCOMPLETE : FD_GUI_SLOT_LEVEL_ROOTED ); /* slot 0 always rooted */
  meta->vote_failed       = UINT_MAX;
  meta->vote_success      = UINT_MAX;
  meta->nonvote_success   = UINT_MAX;
  meta->nonvote_failed    = UINT_MAX;
  meta->compute_units     = UINT_MAX;
  meta->transaction_fee   = ULONG_MAX;
  meta->priority_fee      = ULONG_MAX;
  meta->tips              = ULONG_MAX;
  meta->shred_cnt         = UINT_MAX;
  memset( meta->block_hash.uc, 0, sizeof(fd_hash_t) );

  if( FD_UNLIKELY( mine && epoch ) ) epoch->my_total_slots++;

  return meta;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_gui_fd_gui_h */
