#ifndef HEADER_fd_src_disco_gui_fd_gui_h
#define HEADER_fd_src_disco_gui_fd_gui_h

#include "fd_gui_peers.h"

#include "../topo/fd_topo.h"

#include "../../ballet/txn/fd_txn.h"
#include "../../disco/fd_txn_p.h"
#include "../../discof/restore/fd_snapct_tile.h"
#include "../../discof/tower/fd_tower_tile.h"
#include "../../flamenco/leaders/fd_leaders.h"
#include "../../flamenco/types/fd_types_custom.h"
#include "../../util/fd_util_base.h"
#include "../../util/hist/fd_histf.h"
#include "../../waltz/http/fd_http_server.h"

/* frankendancer only */
#define FD_GUI_MAX_PEER_CNT ( 40200UL)

/* frankendancer only */
#define FD_GUI_START_PROGRESS_TYPE_INITIALIZING                       ( 0)
#define FD_GUI_START_PROGRESS_TYPE_SEARCHING_FOR_FULL_SNAPSHOT        ( 1)
#define FD_GUI_START_PROGRESS_TYPE_DOWNLOADING_FULL_SNAPSHOT          ( 2)
#define FD_GUI_START_PROGRESS_TYPE_SEARCHING_FOR_INCREMENTAL_SNAPSHOT ( 3)
#define FD_GUI_START_PROGRESS_TYPE_DOWNLOADING_INCREMENTAL_SNAPSHOT   ( 4)
#define FD_GUI_START_PROGRESS_TYPE_CLEANING_BLOCK_STORE               ( 5)
#define FD_GUI_START_PROGRESS_TYPE_CLEANING_ACCOUNTS                  ( 6)
#define FD_GUI_START_PROGRESS_TYPE_LOADING_LEDGER                     ( 7)
#define FD_GUI_START_PROGRESS_TYPE_PROCESSING_LEDGER                  ( 8)
#define FD_GUI_START_PROGRESS_TYPE_STARTING_SERVICES                  ( 9)
#define FD_GUI_START_PROGRESS_TYPE_HALTED                             (10)
#define FD_GUI_START_PROGRESS_TYPE_WAITING_FOR_SUPERMAJORITY          (11)
#define FD_GUI_START_PROGRESS_TYPE_RUNNING                            (12)

/* frankendancer only */
#define FD_GUI_SLOT_LEADER_UNSTARTED (0UL)
#define FD_GUI_SLOT_LEADER_STARTED   (1UL)
#define FD_GUI_SLOT_LEADER_ENDED     (2UL)

/* frankendancer only */
struct fd_gui_gossip_peer {
  fd_pubkey_t pubkey[ 1 ];
  ulong       wallclock;
  ushort      shred_version;

  int has_version;
  struct {
    ushort major;
    ushort minor;
    ushort patch;

    int    has_commit;
    uint   commit;

    uint   feature_set;
  } version;

  struct {
    uint   ipv4;
    ushort port;
  } sockets[ 12 ];
};

/* frankendancer only */
struct fd_gui_vote_account {
  fd_pubkey_t pubkey[ 1 ];
  fd_pubkey_t vote_account[ 1 ];

  ulong       activated_stake;
  ulong       last_vote;
  ulong       root_slot;
  ulong       epoch_credits;
  uchar       commission;
  int         delinquent;
};

/* frankendancer only */
struct fd_gui_validator_info {
  fd_pubkey_t pubkey[ 1 ];

  char name[ 64 ];
  char website[ 128 ];
  char details[ 256 ];
  char icon_uri[ 128 ];
};

/* frankendancer only */
#define FD_GUI_SLOT_LEADER_UNSTARTED (0UL)
#define FD_GUI_SLOT_LEADER_STARTED   (1UL)
#define FD_GUI_SLOT_LEADER_ENDED     (2UL)

#define FD_GUI_SLOTS_CNT                           (864000UL) /* 2x 432000 */
#define FD_GUI_LEADER_CNT                          (4096UL)

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

struct fd_gui_leader_slot {
  ulong slot;
  long  leader_start_time; /* UNIX timestamp of when we first became leader in this slot */
  long  leader_end_time;   /* UNIX timestamp of when we stopped being leader in this slot */

  /* Stem tiles can exist in one of 8 distinct activity regimes at any
     given moment.  One of these regimes, caughtup_postfrag, is the
     only regime where a tile is in a spin loop without doing any
     useful work.  This info is useful from a monitoring perspective
     because it lets us estimate CPU utilization on a pinned core.

     Every 10ms, the gui tile samples the amount of time tiles spent
     in each regime in the past 10ms.  This sample is used to infer
     the CPU utilization in the past 10ms.  This utilization is
     streamed live to WebSocket clients.

     In additional to live utilization, we are interested in recording
     utilization during one of this validator's leader slots.  The gui
     tile is continuously recording samples to storage with capacity
     FD_GUI_TILE_TIMER_SNAP_CNT. The sample index is recorded at the
     start and end of a leader slot, and the number of samples is
     downsampled to be at most FD_GUI_TILE_TIMER_LEADER_DOWNSAMPLE_CNT
     samples (e.g. if there was an unusually long leader slot) and
     inserted into historical storage with capacity FD_GUI_LEADER_CNT.
     FD_GUI_TILE_TIMER_TILE_CNT is the maximum number of tiles supported. */
  fd_gui_tile_timers_t tile_timers[ FD_GUI_TILE_TIMER_LEADER_DOWNSAMPLE_CNT ][ FD_GUI_TILE_TIMER_TILE_CNT ];
  ulong                tile_timers_sample_cnt;

  struct {
    uint microblocks_upper_bound; /* An upper bound on the number of microblocks in the slot.  If the number of
                                     microblocks observed is equal to this, the slot can be considered over.
                                     Generally, the bound is set to a "final" state by a done packing message,
                                     which sets it to the exact number of microblocks, but sometimes this message
                                     is not sent, if the max upper bound published by poh was already correct. */
    uint begin_microblocks; /* The number of microblocks we have seen be started (sent) from pack to banks. */
    uint end_microblocks;   /* The number of microblocks we have seen be ended (sent) from banks to poh.  The
                               slot is only considered over if the begin and end microblocks seen are both equal
                               to the microblock upper bound. */

    ulong   start_offset; /* The smallest pack transaction index for this slot. The first transaction for this slot will
                             be written to gui->txs[ start_offset%FD_GUI_TXN_HISTORY_SZ ]. */
    ulong   end_offset;   /* The largest pack transaction index for this slot, plus 1. The last transaction for this
                             slot will be written to gui->txs[ (start_offset-1)%FD_GUI_TXN_HISTORY_SZ ]. */
  } txs;
};

typedef struct fd_gui_leader_slot fd_gui_leader_slot_t;

struct fd_gui_slot_completed {
  ulong slot;
  long  completed_time;
  ulong parent_slot;
  uint  max_compute_units;
  uint  total_txn_cnt;
  uint  vote_txn_cnt;
  uint  failed_txn_cnt;
  uint  nonvote_failed_txn_cnt;
  ulong transaction_fee;
  ulong priority_fee;
  ulong tips;
  uint  compute_units;
  uint  shred_cnt;
};

typedef struct fd_gui_slot_completed fd_gui_slot_completed_t;

struct fd_gui_slot_staged_shred_event {
  long   timestamp;
  ulong  slot;
  ushort shred_idx;
  ushort fec_idx;
  uchar  event;
};

typedef struct fd_gui_slot_staged_shred_event fd_gui_slot_staged_shred_event_t;

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

struct fd_gui_ephemeral_slot {
      ulong slot; /* ULONG_MAX indicates invalid/evicted */
      long timestamp_arrival_nanos;
};
typedef struct fd_gui_ephemeral_slot fd_gui_ephemeral_slot_t;

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

struct fd_gui_slot {
  ulong slot;
  ulong parent_slot;
  uint  max_compute_units;
  long  completed_time;
  int   mine;
  int   skipped;
  int   must_republish;
  int   level;
  uint  total_txn_cnt;
  uint  vote_txn_cnt;
  uint  failed_txn_cnt;
  uint  nonvote_failed_txn_cnt;
  uint  compute_units;
  ulong transaction_fee;
  ulong priority_fee;
  ulong tips;
  uint  shred_cnt;

  /* Some slot info is only tracked for our own leader slots. These
     slots are kept in a separate buffer. */
  ulong leader_history_idx;

  fd_gui_txn_waterfall_t waterfall_begin[ 1 ];
  fd_gui_txn_waterfall_t waterfall_end[ 1 ];

  fd_gui_tile_stats_t tile_stats_begin[ 1 ];
  fd_gui_tile_stats_t tile_stats_end[ 1 ];

  struct {
    ulong start_offset; /* gui->shreds.history[ start_offset % FD_GUI_SHREDS_HISTORY_SZ ] is the first shred event in
                           contiguous chunk of events in the shred history corresponding to this slot. */
    ulong end_offset;   /* gui->shreds.history[ end_offset % FD_GUI_SHREDS_HISTORY_SZ ] is the last shred event in
                           contiguous chunk of events in the shred history corresponding to this slot. */
  } shreds;
};

typedef struct fd_gui_slot fd_gui_slot_t;

struct fd_gui {
  fd_http_server_t * http;
  fd_topo_t * topo;

  long next_sample_400millis;
  long next_sample_100millis;
  long next_sample_10millis;

  ulong debug_in_leader_slot;

  struct {
    fd_pubkey_t identity_key[ 1 ];
    int         has_vote_key;
    fd_pubkey_t vote_key[ 1 ];
    char vote_key_base58[ FD_BASE58_ENCODED_32_SZ ];
    char identity_key_base58[ FD_BASE58_ENCODED_32_SZ ];

    int          is_full_client;
    char const * version;
    char const * cluster;

    ulong vote_distance;
    int vote_state;

    long  startup_time_nanos;

    union {
      struct { /* frankendancer only */
      uchar phase;
      int   startup_got_full_snapshot;

      ulong  startup_incremental_snapshot_slot;
      uint   startup_incremental_snapshot_peer_ip_addr;
        ushort startup_incremental_snapshot_peer_port;
        double startup_incremental_snapshot_elapsed_secs;
        double startup_incremental_snapshot_remaining_secs;
        double startup_incremental_snapshot_throughput;
        ulong  startup_incremental_snapshot_total_bytes;
        ulong  startup_incremental_snapshot_current_bytes;

        ulong  startup_full_snapshot_slot;
        uint   startup_full_snapshot_peer_ip_addr;
        ushort startup_full_snapshot_peer_port;
        double startup_full_snapshot_elapsed_secs;
        double startup_full_snapshot_remaining_secs;
        double startup_full_snapshot_throughput;
        ulong  startup_full_snapshot_total_bytes;
        ulong  startup_full_snapshot_current_bytes;

        ulong startup_ledger_slot;
        ulong startup_ledger_max_slot;

        ulong startup_waiting_for_supermajority_slot;
        ulong startup_waiting_for_supermajority_stake_pct;
      } startup_progress;
      struct { /* used in the full client */
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
        } loading_snapshot[ FD_GUI_BOOT_PROGRESS_SNAPSHOT_CNT ];

        long  catching_up_time_nanos;
        ulong catching_up_first_replay_slot;
      } boot_progress;
    };

    int schedule_strategy;

    ulong identity_account_balance;
    ulong vote_account_balance;
    ulong estimated_slot_duration_nanos;

    ulong sock_tile_cnt;
    ulong net_tile_cnt;
    ulong quic_tile_cnt;
    ulong verify_tile_cnt;
    ulong resolv_tile_cnt;
    ulong bank_tile_cnt;
    ulong shred_tile_cnt;

    ulong slot_rooted;
    ulong slot_optimistically_confirmed;
    ulong slot_completed;
    ulong slot_estimated;
    ulong slot_caught_up;
    ulong slot_repair;
    ulong slot_turbine;

    fd_gui_ephemeral_slot_t slots_max_turbine[ FD_GUI_TURBINE_SLOT_HISTORY_SZ+1UL ];
    fd_gui_ephemeral_slot_t slots_max_repair [ FD_GUI_REPAIR_SLOT_HISTORY_SZ +1UL ];

    /* catchup_* is run-length encoded. i.e. adjacent pairs represent
      contiguous runs */
    ulong catch_up_turbine[ FD_GUI_TURBINE_CATCH_UP_HISTORY_SZ ];
    ulong catch_up_turbine_sz;

    ulong catch_up_repair[ FD_GUI_REPAIR_CATCH_UP_HISTORY_SZ ];
    ulong catch_up_repair_sz;

    ulong estimated_tps_history_idx;
    ulong estimated_tps_history[ FD_GUI_TPS_HISTORY_SAMPLE_CNT ][ 3UL ];

    fd_gui_txn_waterfall_t txn_waterfall_reference[ 1 ];
    fd_gui_txn_waterfall_t txn_waterfall_current[ 1 ];

    fd_gui_tile_stats_t tile_stats_reference[ 1 ];
    fd_gui_tile_stats_t tile_stats_current[ 1 ];

    ulong                tile_timers_snap_idx;
    ulong                tile_timers_snap_idx_slot_start;
    /* Temporary storage for samples. Will be downsampled into leader history on slot end. */
    fd_gui_tile_timers_t tile_timers_snap[ FD_GUI_TILE_TIMER_SNAP_CNT ][ FD_GUI_TILE_TIMER_TILE_CNT ];
  } summary;

  fd_gui_slot_t slots[ FD_GUI_SLOTS_CNT ][ 1 ];

  fd_gui_leader_slot_t leader_slots[ FD_GUI_LEADER_CNT ][ 1 ];
  ulong leader_slots_cnt;

  fd_gui_txn_t txs[ FD_GUI_TXN_HISTORY_SZ ][ 1 ];
  ulong pack_txn_idx; /* The pack index of the most recently received transaction */

  struct {
    int has_block_engine;
    char name[ 16 ];
    char url[ 256 ];
    char ip_cstr[ 40 ]; /* IPv4 or IPv6 cstr */
    int status;
  } block_engine;

  struct {
    int has_epoch[ 2 ];

    struct {
      ulong epoch;
      long start_time;
      long end_time;

      ulong my_total_slots;
      ulong my_skipped_slots;

      ulong start_slot;
      ulong end_slot;
      ulong excluded_stake;
      fd_epoch_leaders_t * lsched;
      uchar __attribute__((aligned(FD_EPOCH_LEADERS_ALIGN))) _lsched[ FD_EPOCH_LEADERS_FOOTPRINT(MAX_STAKED_LEADERS, MAX_SLOTS_PER_EPOCH) ];
      fd_vote_stake_weight_t stakes[ MAX_STAKED_LEADERS ];

      ulong rankings_slot; /* One more than the largest slot we've processed into our rankings */
      fd_gui_slot_rankings_t rankings[ 1 ]; /* global slot rankings */
      fd_gui_slot_rankings_t my_rankings[ 1 ]; /* my slots only */
    } epochs[ 2 ];
  } epoch;

  struct {  /* frankendancer only */
    ulong                     peer_cnt;
    struct fd_gui_gossip_peer peers[ FD_GUI_MAX_PEER_CNT ];
  } gossip;

  struct {  /* frankendancer only */
    ulong                      vote_account_cnt;
    struct fd_gui_vote_account vote_accounts[ FD_GUI_MAX_PEER_CNT ];
  } vote_account;

  struct {  /* frankendancer only */
    ulong                        info_cnt;
    struct fd_gui_validator_info info[ FD_GUI_MAX_PEER_CNT ];
  } validator_info;

  fd_gui_peers_ctx_t * peers; /* full-client */

  struct {
    ulong staged_next_broadcast; /* staged[ staged_next_broadcast % FD_GUI_SHREDS_STAGING_SZ ] is the first shred event
                                    that hasn't yet been broadcast to WebSocket clients */
    ulong staged_head;            /* staged_head % FD_GUI_SHREDS_STAGING_SZ is the valid event in staged */
    ulong staged_tail;            /* staged_head % FD_GUI_SHREDS_STAGING_SZ is the last valid event in staged */
    fd_gui_slot_staged_shred_event_t  staged [ FD_GUI_SHREDS_STAGING_SZ ];

    ulong history_slot;          /* the largest slot store in history */
    ulong history_tail;          /* history_tail % FD_GUI_SHREDS_STAGING_SZ is the last valid event in history +1 */
    fd_gui_slot_history_shred_event_t history[ FD_GUI_SHREDS_HISTORY_SZ ];

    /* scratch space for stable sorts */
    fd_gui_slot_staged_shred_event_t _staged_scratch [ FD_GUI_SHREDS_STAGING_SZ ];
    fd_gui_slot_staged_shred_event_t _staged_scratch2[ FD_GUI_SHREDS_STAGING_SZ ];
  } shreds; /* full client */
};

typedef struct fd_gui fd_gui_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong
fd_gui_align( void );

FD_FN_CONST ulong
fd_gui_footprint( void );

void *
fd_gui_new( void *                shmem,
            fd_http_server_t *    http,
            char const *          version,
            char const *          cluster,
            uchar const *         identity_key,
            int                   has_vote_key,
            uchar const *         vote_key,
            int                   is_full_client,
            int                   snapshots_enabled,
            int                   is_voting,
            int                   schedule_strategy,
            fd_topo_t *           topo,
            long                  now );

fd_gui_t *
fd_gui_join( void * shmem );

void
fd_gui_set_identity( fd_gui_t *    gui,
                     uchar const * identity_pubkey );

void
fd_gui_ws_open( fd_gui_t *  gui,
                ulong       conn_id );

int
fd_gui_ws_message( fd_gui_t *    gui,
                   ulong         ws_conn_id,
                   uchar const * data,
                   ulong         data_len );

void
fd_gui_plugin_message( fd_gui_t *    gui,
                       ulong         plugin_msg,
                       uchar const * msg,
                       long          now );

void
fd_gui_became_leader( fd_gui_t * gui,
                      ulong      slot,
                      long       start_time_nanos,
                      long       end_time_nanos,
                      ulong      max_compute_units,
                      ulong      max_microblocks );

void
fd_gui_unbecame_leader( fd_gui_t * gui,
                        ulong      slot,
                        ulong      microblocks_in_slot );

void
fd_gui_microblock_execution_begin( fd_gui_t *   gui,
                                   long         now,
                                   ulong        _slot,
                                   fd_txn_p_t * txns,
                                   ulong        txn_cnt,
                                   uint         microblock_idx,
                                   ulong        pack_txn_idx );

void
fd_gui_microblock_execution_end( fd_gui_t *   gui,
                                 long         now,
                                 ulong        bank_idx,
                                 ulong        _slot,
                                 ulong        txn_cnt,
                                 fd_txn_p_t * txns,
                                 ulong        pack_txn_idx,
                                 uchar        txn_start_pct,
                                 uchar        txn_load_end_pct,
                                 uchar        txn_end_pct,
                                 uchar        txn_preload_end_pct,
                                 ulong        tips );

int
fd_gui_poll( fd_gui_t * gui, long now );

void
fd_gui_handle_shred( fd_gui_t * gui,
                     ulong      slot,
                     ulong      shred_idx,
                     ulong      fec_idx,
                     int        is_turbine,
                     long       tsorig );

void
fd_gui_handle_repair_slot( fd_gui_t * gui, ulong slot, long now );

void
fd_gui_handle_snapshot_update( fd_gui_t *                 gui,
                               fd_snapct_update_t const * msg );

void
fd_gui_handle_leader_schedule( fd_gui_t *                    gui,
                               fd_stake_weight_msg_t const * leader_schedule,
                               long                          now );

void
fd_gui_handle_tower_update( fd_gui_t *                   gui,
                            fd_tower_slot_done_t const * msg,
                            long                         now );

void
fd_gui_handle_replay_update( fd_gui_t *                gui,
                             fd_gui_slot_completed_t * slot_completed,
                             long                      now );

static inline fd_gui_slot_t *
fd_gui_get_slot( fd_gui_t const * gui, ulong _slot ) {
  fd_gui_slot_t const * slot = gui->slots[ _slot % FD_GUI_SLOTS_CNT ];
  if( FD_UNLIKELY( slot->slot==ULONG_MAX || _slot==ULONG_MAX || slot->slot!=_slot ) ) return NULL;
  return (fd_gui_slot_t *)slot;
}

static inline fd_gui_slot_t const *
fd_gui_get_slot_const( fd_gui_t const * gui, ulong _slot ) {
  return fd_gui_get_slot( gui, _slot );
}

static inline fd_gui_leader_slot_t *
fd_gui_get_leader_slot( fd_gui_t const * gui, ulong _slot ) {
  fd_gui_slot_t const * slot = fd_gui_get_slot( gui, _slot );
  if( FD_UNLIKELY( !slot
                || !slot->mine
                || slot->leader_history_idx==ULONG_MAX
                || slot->leader_history_idx + FD_GUI_LEADER_CNT < gui->leader_slots_cnt
                || gui->leader_slots[ slot->leader_history_idx % FD_GUI_LEADER_CNT ]->slot!=_slot ) ) return NULL;
  return (fd_gui_leader_slot_t *)gui->leader_slots[ slot->leader_history_idx % FD_GUI_LEADER_CNT ];
}

static inline fd_gui_leader_slot_t const *
fd_gui_get_leader_slot_const( fd_gui_t const * gui, ulong _slot ) {
  return fd_gui_get_leader_slot( gui, _slot );
}

/* fd_gui_get_root_slot returns a handle to the closest ancestor of slot
   that is a root, if available, otherwise NULL. */
static inline fd_gui_slot_t *
fd_gui_get_root_slot( fd_gui_t const * gui,
                      ulong            slot ) {
  fd_gui_slot_t * c = fd_gui_get_slot( gui, slot );
  while( c ) {
    if( FD_UNLIKELY( c->level>=FD_GUI_SLOT_LEVEL_ROOTED ) ) return c;
    c = fd_gui_get_slot( gui, c->parent_slot );
  }
  return NULL;
}

/* fd_gui_slot_is_ancestor returns 1 if anc is known to be an ancestor
   of slot (on the same fork), 0 otherwise. */
static inline int
fd_gui_slot_is_ancestor( fd_gui_t const * gui,
                         ulong            anc,
                         ulong            slot ) {
  fd_gui_slot_t * c = fd_gui_get_slot( gui, slot );
  while( c ) {
    if( FD_UNLIKELY( c->slot==anc ) ) return 1;
    c = fd_gui_get_slot( gui, c->parent_slot );
  }
  return 0;
}

/* fd_gui_get_parent_slot_on_fork returns a handle to the parent of slot
   on the fork ending on frontier_slot.  If slot is unknown or skipped,
   the closest (by slot number) valid parent on the fork is returned.

   NULL if slot is not an ancestor of frontier slot or if the parent is
   unknown. */
static inline fd_gui_slot_t *
fd_gui_get_parent_slot_on_fork( fd_gui_t const * gui,
                                ulong            frontier_slot,
                                ulong            slot ) {
  fd_gui_slot_t * c = fd_gui_get_slot( gui, frontier_slot );
  while( c ) {
    if( FD_UNLIKELY( c->slot<=slot ) ) return NULL;
    fd_gui_slot_t * p = fd_gui_get_slot( gui, c->parent_slot );
    if( FD_UNLIKELY( p && p->slot<=slot-1UL ) ) return p;
    c = p;
  }
  return NULL;
}

/* fd_gui_is_skipped_on_fork returns 1 if slot is skipped on the fork
   starting at anc and ending at des, 0 otherwise. */
static inline int
fd_gui_is_skipped_on_fork( fd_gui_t const * gui,
                           ulong            anc,
                           ulong            des,
                           ulong            slot ) {
  fd_gui_slot_t const * c = fd_gui_get_slot( gui, des );
  while( c ) {
    if( FD_UNLIKELY( anc==c->slot ) ) return 0; /* on the fork, not skipped */
    fd_gui_slot_t const * p = fd_gui_get_slot( gui, c->parent_slot );
    if( FD_UNLIKELY( p && p->slot<slot && c->slot>slot ) ) return 1; /* in-between two nodes, skipped */
    c = p;
  }

  return 0; /* slot not between anc and des, or is unknown */
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_gui_fd_gui_h */
