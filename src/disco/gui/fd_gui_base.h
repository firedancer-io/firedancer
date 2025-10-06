#ifndef HEADER_fd_src_disco_gui_fd_gui_base_h
#define HEADER_fd_src_disco_gui_fd_gui_base_h

#include "../../util/fd_util_base.h"
#include "../../util/hist/fd_histf.h"
#include "../../ballet/txn/fd_txn.h"

#define FD_GUI_SLOTS_CNT                           (864000UL) /* 2x 432000 */
#define FD_GUI_LEADER_CNT                          (21600UL) /* 5% of 432000 */

#define FD_GUI_TPS_HISTORY_WINDOW_DURATION_SECONDS (10L)
#define FD_GUI_TPS_HISTORY_SAMPLE_CNT              (150UL)

#define FD_GUI_TILE_TIMER_SNAP_CNT                 (512UL)
#define FD_GUI_TILE_TIMER_LEADER_DOWNSAMPLE_CNT    (50UL)    /* 500ms / 10ms */
#define FD_GUI_TILE_TIMER_TILE_CNT                 (128UL)

#define FD_GUI_VOTE_STATE_NON_VOTING (0)
#define FD_GUI_VOTE_STATE_VOTING     (1)
#define FD_GUI_VOTE_STATE_DELINQUENT (2)

#define FD_GUI_BOOT_PROGRESS_TYPE_JOINING_GOSSIP               (1)
#define FD_GUI_BOOT_PROGRESS_TYPE_LOADING_FULL_SNAPSHOT        (2)
#define FD_GUI_BOOT_PROGRESS_TYPE_LOADING_INCREMENTAL_SNAPSHOT (3)
#define FD_GUI_BOOT_PROGRESS_TYPE_CATCHING_UP                  (4)
#define FD_GUI_BOOT_PROGRESS_TYPE_RUNNING                      (5)

#define FD_GUI_BOOT_PROGRESS_FULL_SNAPSHOT_IDX        (0UL)
#define FD_GUI_BOOT_PROGRESS_INCREMENTAL_SNAPSHOT_IDX (1UL)
#define FD_GUI_BOOT_PROGRESS_SNAPSHOT_CNT             (2UL)

#define FD_GUI_SLOT_LEVEL_INCOMPLETE               (0)
#define FD_GUI_SLOT_LEVEL_COMPLETED                (1)
#define FD_GUI_SLOT_LEVEL_OPTIMISTICALLY_CONFIRMED (2)
#define FD_GUI_SLOT_LEVEL_ROOTED                   (3)
#define FD_GUI_SLOT_LEVEL_FINALIZED                (4)

/* Ideally, we would store an entire epoch's worth of transactions.  If
   we assume any given validator will have at most 5% stake, and average
   transactions per slot is around 10_000, then an epoch will have about
   432_000*10_000*0.05 transactions (~2^28).

   Unfortunately, the transaction struct is 100+ bytes.  If we sized the
   array to 2^28 entries then the memory required would be ~26GB.  In
   order to keep memory usage to a more reasonable level, we'll
   arbitrarily use a fourth of that size. */
#define FD_GUI_TXN_HISTORY_SZ (1UL<<26UL)

#define FD_GUI_TXN_FLAGS_STARTED         ( 1U)
#define FD_GUI_TXN_FLAGS_ENDED           ( 2U)
#define FD_GUI_TXN_FLAGS_IS_SIMPLE_VOTE  ( 4U)
#define FD_GUI_TXN_FLAGS_FROM_BUNDLE     ( 8U)
#define FD_GUI_TXN_FLAGS_LANDED_IN_BLOCK (16U)

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
#define FD_GUI_TURBINE_SLOT_HISTORY_SZ ( 12UL )
#define FD_GUI_REPAIR_SLOT_HISTORY_SZ  ( 12UL )

/* FD_GUI_SHREDS_STAGING_SZ is number of shred events we'll retain in
   in a small staging area.  The lifecycle of a shred looks something
   like the following

   states] turbine -> repairing (optional) ->  processing                   -> waiting_for_siblings -> slot_complete
   events]         ^-repair_requested      ^-shred_received/shred_repaired  ^-shred_replayed        ^-max(shred_replayed)

   We're interested in recording timestamps for state transitions (which
   these docs call "shred events").  Unfortunately, due to forking,
   duplicate packets, etc we can't make any guarantees about ordering or
   uniqueness for these event timestamps.  Instead the GUI just records
   timestamps for all events as they occur and put them into an array.
   Newly recorded event timestamps are also broadcast live to WebSocket
   consumers.

   The amount of shred events for non-finalized blocks can't really be
   bounded, so we use generous estimates here to set a memory bound. */
#define FD_GUI_MAX_SHREDS_PER_BLOCK  (32UL*1024UL)
#define FD_GUI_MAX_EVENTS_PER_SHRED  (       32UL)
#define FD_GUI_SHREDS_STAGING_SZ     (32UL * FD_GUI_MAX_SHREDS_PER_BLOCK * FD_GUI_MAX_EVENTS_PER_SHRED)

/* FD_GUI_SHREDS_HISTORY_SZ the number of shred events in our historical
   shred store.  Shred events here belong to finalized slots which means
   we won't record any additional shred updates for these slots.

   All shred events for a given slot will be places in a contiguous
   chunk in the array, and the bounding indicies are stored in the
   fd_gui_slot_t slot history.  Within a slot chunk, shred events are
   ordered in the ordered they were recorded by the gui tile.

   Ideally, we have enough space to store an epoch's worth of events,
   but we are limited by realistic memory consumption.  Instead, we pick
   bound heuristically. */
#define FD_GUI_SHREDS_HISTORY_SZ     (432000UL*2000UL*4UL / 6UL)

#define FD_GUI_SLOT_SHRED_REPAIR_REQUEST         (0UL)
#define FD_GUI_SLOT_SHRED_SHRED_RECEIVED_TURBINE (1UL)
#define FD_GUI_SLOT_SHRED_SHRED_RECEIVED_REPAIR  (2UL)
#define FD_GUI_SLOT_SHRED_SHRED_REPLAYED         (3UL)
#define FD_GUI_SLOT_SHRED_SHRED_SLOT_COMPLETE    (4UL)

#define FD_GUI_SLOT_RANKINGS_SZ (100UL)
#define FD_GUI_SLOT_RANKING_TYPE_ASC  (0)
#define FD_GUI_SLOT_RANKING_TYPE_DESC (1)

struct fd_gui_txn_waterfall {
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
    ulong pack_retained;
    ulong pack_wait_full;
    ulong pack_leader_slow;
    ulong bank_invalid;
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

struct fd_gui_tile_timers {
  ulong caughtup_housekeeping_ticks;
  ulong processing_housekeeping_ticks;
  ulong backpressure_housekeeping_ticks;

  ulong caughtup_prefrag_ticks;
  ulong processing_prefrag_ticks;
  ulong backpressure_prefrag_ticks;

  ulong caughtup_postfrag_ticks;
  ulong processing_postfrag_ticks;
};

typedef struct fd_gui_tile_timers fd_gui_tile_timers_t;

struct fd_gui_slot {
  ulong slot;
  ulong parent_slot;
  uint  max_compute_units;
  long  completed_time;
  long  replay_time_nanos;
  int   mine;
  int   skipped;
  int   must_republish;
  int   level;
  uint  total_txn_cnt;
  uint  vote_txn_cnt;
  uint  failed_txn_cnt;
  uint  nonvote_failed_txn_cnt;
  uint  compute_units;
  uint  shred_cnt;
  ulong transaction_fee;
  ulong priority_fee;
  ulong tips;

  ulong leader_history_idx;

  struct {
    ulong start_offset; /* gui->shreds.history[ start_offset % FD_GUI_SHREDS_HISTORY_SZ ] is the first shred event in
                           contiguous chunk of events in the shred history corresponding to this slot. */
    ulong end_offset;   /* gui->shreds.history[ end_offset % FD_GUI_SHREDS_HISTORY_SZ ] is the last shred event in
                           contiguous chunk of events in the shred history corresponding to this slot. */
  } shreds;
};

typedef struct fd_gui_slot fd_gui_slot_t;

struct fd_gui_slot_staged_shred_event {
  long   timestamp;
  ulong  slot;
  ushort shred_idx;
  ushort fec_idx;
  uchar  event;
};

typedef struct fd_gui_slot_staged_shred_event fd_gui_slot_staged_shred_event_t;

#define SORT_NAME fd_gui_slot_staged_shred_event_sort
#define SORT_KEY_T fd_gui_slot_staged_shred_event_t
#define SORT_BEFORE(a,b) (__extension__({ (void)(b); (a).slot==ULONG_MAX; }))
#include "../../util/tmpl/fd_sort.c"

struct __attribute__((packed)) fd_gui_slot_history_shred_event {
  long   timestamp;
  ushort shred_idx;
  uchar  event;
};

typedef struct fd_gui_slot_history_shred_event fd_gui_slot_history_shred_event_t;

struct fd_gui_slot_ranking {
  ulong slot;
  ulong value;
  int   type;
};
typedef struct fd_gui_slot_ranking fd_gui_slot_ranking_t;

/* All rankings are initialized / reset to ULONG_MAX.  These sentinels
   sort AFTER non-sentinel ranking entries.  Equal slots are sorted by
   oldest slot AFTER.  Otherwise sort by value according to ranking
   type. */
#define SORT_NAME fd_gui_slot_ranking_sort
#define SORT_KEY_T fd_gui_slot_ranking_t
#define SORT_BEFORE(a,b) fd_int_if( (a).slot==ULONG_MAX, 0, fd_int_if( (b).slot==ULONG_MAX, 1, fd_int_if( (a).value==(b).value, (a).slot>(b).slot, fd_int_if( (a).type==FD_GUI_SLOT_RANKING_TYPE_DESC, (a).value>(b).value, (a).value<(b).value ) ) ) )
#include "../../util/tmpl/fd_sort.c"

struct fd_gui_slot_rankings {
  fd_gui_slot_ranking_t largest_tips          [ FD_GUI_SLOT_RANKINGS_SZ+1UL ];
  fd_gui_slot_ranking_t largest_fees          [ FD_GUI_SLOT_RANKINGS_SZ+1UL ];
  fd_gui_slot_ranking_t largest_rewards       [ FD_GUI_SLOT_RANKINGS_SZ+1UL ];
  fd_gui_slot_ranking_t largest_duration      [ FD_GUI_SLOT_RANKINGS_SZ+1UL ];
  fd_gui_slot_ranking_t largest_compute_units [ FD_GUI_SLOT_RANKINGS_SZ+1UL ];
  fd_gui_slot_ranking_t largest_skipped       [ FD_GUI_SLOT_RANKINGS_SZ+1UL ];
  fd_gui_slot_ranking_t smallest_tips         [ FD_GUI_SLOT_RANKINGS_SZ+1UL ];
  fd_gui_slot_ranking_t smallest_fees         [ FD_GUI_SLOT_RANKINGS_SZ+1UL ];
  fd_gui_slot_ranking_t smallest_rewards      [ FD_GUI_SLOT_RANKINGS_SZ+1UL ];
  fd_gui_slot_ranking_t smallest_duration     [ FD_GUI_SLOT_RANKINGS_SZ+1UL ];
  fd_gui_slot_ranking_t smallest_compute_units[ FD_GUI_SLOT_RANKINGS_SZ+1UL ];
  fd_gui_slot_ranking_t smallest_skipped      [ FD_GUI_SLOT_RANKINGS_SZ+1UL ];
};

typedef struct fd_gui_slot_rankings fd_gui_slot_rankings_t;

struct fd_gui_ephemeral_slot {
      ulong slot; /* ULONG_MAX indicates invalid/evicted */
      long timestamp_arrival_nanos;
};
typedef struct fd_gui_ephemeral_slot fd_gui_ephemeral_slot_t;

#define SORT_NAME fd_gui_ephemeral_slot_sort
#define SORT_KEY_T fd_gui_ephemeral_slot_t
#define SORT_BEFORE(a,b) fd_int_if( (a).slot==ULONG_MAX, 0, fd_int_if( (b).slot==ULONG_MAX, 1, fd_int_if( (a).slot==(b).slot, (a).timestamp_arrival_nanos>(b).timestamp_arrival_nanos, (a).slot>(b).slot ) ) )
#include "../../util/tmpl/fd_sort.c"

struct __attribute__((packed)) fd_gui_txn {
  uchar signature[ FD_TXN_SIGNATURE_SZ ];
  ulong transaction_fee;
  ulong priority_fee;
  ulong tips;
  long timestamp_arrival_nanos;

  /* compute_units_requested has both execution and non-execution cus */
  uint compute_units_requested : 21; /* <= 1.4M */
  uint compute_units_consumed  : 21; /* <= 1.4M */
  uint bank_idx                :  6; /* in [0, 64) */
  uint error_code              :  6; /* in [0, 64) */
  int timestamp_delta_start_nanos;
  int timestamp_delta_end_nanos;

  /* txn_{}_pct is used as a fraction of the total microblock
     duration. For example, txn_load_end_pct can be used to find the
     time when this transaction started executing:

     timestamp_delta_start_exec_nanos = (
       (timestamp_delta_end_nanos-timestamp_delta_start_nanos) *
       ((double)txn_{}_pct/USHORT_MAX)
     ) */
  uchar txn_start_pct;
  uchar txn_load_end_pct;
  uchar txn_end_pct;
  uchar txn_preload_end_pct;
  uchar flags; /* assigned with the FD_GUI_TXN_FLAGS_* macros */
  uchar source_tpu; /* FD_TXN_M_TPU_SOURCE_* */
  uint  source_ipv4;
  uint  microblock_idx;
};


typedef struct fd_gui_txn fd_gui_txn_t;

#endif /* HEADER_fd_src_disco_gui_fd_gui_base_h */