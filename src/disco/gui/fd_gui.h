#ifndef HEADER_fd_src_disco_gui_fd_gui_h
#define HEADER_fd_src_disco_gui_fd_gui_h

#include "../fd_disco_base.h"

#include "../pack/fd_microblock.h"
#include "../../waltz/http/fd_http_server.h"
#include "../../flamenco/leaders/fd_leaders.h"
#include "../../util/hist/fd_histf.h"

#include "../topo/fd_topo.h"

#define FD_GUI_SLOTS_CNT (864000UL)
#define FD_GUI_TPS_HISTORY_WINDOW_DURATION_SECONDS (10L) /* 10 second moving average */
#define FD_GUI_TPS_HISTORY_SAMPLE_CNT              (150UL)
#define FD_GUI_TILE_TIMER_SNAP_CNT                 (512UL)
#define FD_GUI_TILE_TIMER_LEADER_CNT               (4096UL)
#define FD_GUI_TILE_TIMER_LEADER_DOWNSAMPLE_CNT    (50UL)
#define FD_GUI_TILE_TIMER_TILE_CNT                 (128UL)
#define FD_GUI_MAX_PEER_CNT                        (40200UL)

#define FD_GUI_SLOT_LEVEL_INCOMPLETE               (0)
#define FD_GUI_SLOT_LEVEL_COMPLETED                (1)
#define FD_GUI_SLOT_LEVEL_OPTIMISTICALLY_CONFIRMED (2)
#define FD_GUI_SLOT_LEVEL_ROOTED                   (3)
#define FD_GUI_SLOT_LEVEL_FINALIZED                (4)

#define FD_GUI_VOTE_STATE_NON_VOTING (0)
#define FD_GUI_VOTE_STATE_VOTING     (1)
#define FD_GUI_VOTE_STATE_DELINQUENT (2)

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

struct fd_gui_validator_info {
  fd_pubkey_t pubkey[ 1 ];

  char name[ 64 ];
  char website[ 128 ];
  char details[ 256 ];
  char icon_uri[ 128 ];
};

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

#define FD_GUI_SLOT_LEADER_UNSTARTED (0UL)
#define FD_GUI_SLOT_LEADER_STARTED   (1UL)
#define FD_GUI_SLOT_LEADER_ENDED     (2UL)

struct fd_gui_slot {
  ulong slot;
  ulong parent_slot;
  uint max_compute_units;
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

  uchar leader_state;

  struct {
    long leader_start_time; /* UNIX timestamp of when we first became leader in this slot */
    long leader_end_time;   /* UNIX timestamp of when we stopped being leader in this slot */

    long reference_ticks;   /* A somewhat arbitrary reference tickcount, that we use for compressing the tickcounts
                               of transaction start and end times in this slot.  It is, roughly (not exactly), the
                               minimum of the first transaction start or end tickcount, and the time of the message
                               from poh to pack telling it to become leader. */
    long reference_nanos;   /* The UNIX timestamp in nanoseconds of the reference tick value above. */

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

  fd_gui_txn_waterfall_t waterfall_begin[ 1 ];
  fd_gui_txn_waterfall_t waterfall_end[ 1 ];

  fd_gui_tile_stats_t tile_stats_begin[ 1 ];
  fd_gui_tile_stats_t tile_stats_end[ 1 ];

  ulong tile_timers_history_idx;
};

typedef struct fd_gui_slot fd_gui_slot_t;

struct __attribute__((packed)) fd_gui_txn {
  uchar signature[ FD_SHA512_HASH_SZ ];
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

    char const * version;
    char const * cluster;

    ulong vote_distance;
    int vote_state;

    long  startup_time_nanos;

    uchar startup_progress;
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
    ulong                tile_timers_history_idx;
    fd_gui_tile_timers_t tile_timers_leader_history[ FD_GUI_TILE_TIMER_LEADER_CNT ][ FD_GUI_TILE_TIMER_LEADER_DOWNSAMPLE_CNT ][ FD_GUI_TILE_TIMER_TILE_CNT ];
    ulong                tile_timers_leader_history_slot_sample_cnt[ FD_GUI_TILE_TIMER_LEADER_CNT ];
    ulong                tile_timers_leader_history_slot[ FD_GUI_TILE_TIMER_LEADER_CNT ];
  } summary;

  fd_gui_slot_t slots[ FD_GUI_SLOTS_CNT ][ 1 ];

  ulong pack_txn_idx; /* The pack index of the most recently received transaction */
  fd_gui_txn_t txs[ FD_GUI_TXN_HISTORY_SZ ][ 1 ];
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
    } epochs[ 2 ];
  } epoch;

  struct {
    ulong                     peer_cnt;
    struct fd_gui_gossip_peer peers[ FD_GUI_MAX_PEER_CNT ];
  } gossip;

  struct {
    ulong                      vote_account_cnt;
    struct fd_gui_vote_account vote_accounts[ FD_GUI_MAX_PEER_CNT ];
  } vote_account;

  struct {
    ulong                        info_cnt;
    struct fd_gui_validator_info info[ FD_GUI_MAX_PEER_CNT ];
  } validator_info;
};

typedef struct fd_gui fd_gui_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong
fd_gui_align( void );

FD_FN_CONST ulong
fd_gui_footprint( void );

void *
fd_gui_new( void *             shmem,
            fd_http_server_t * http,
            char const *       version,
            char const *       cluster,
            uchar const *      identity_key,
            int                has_vote_key,
            uchar const *      vote_key,
            int                is_voting,
            int                schedule_strategy,
            fd_topo_t *        topo );

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
                       uchar const * msg );

void
fd_gui_became_leader( fd_gui_t * gui,
                      long       tickcount,
                      ulong      slot,
                      long       start_time_nanos,
                      long       end_time_nanos,
                      ulong      max_compute_units,
                      ulong      max_microblocks );

void
fd_gui_unbecame_leader( fd_gui_t * gui,
                        long       tickcount,
                        ulong      slot,
                        ulong      microblocks_in_slot );

void
fd_gui_microblock_execution_begin( fd_gui_t *   gui,
                                   long         tickcount,
                                   ulong        _slot,
                                   fd_txn_p_t * txns,
                                   ulong        txn_cnt,
                                   uint         microblock_idx,
                                   ulong        pack_txn_idx );

void
fd_gui_microblock_execution_end( fd_gui_t *   gui,
                                 long         tickcount,
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
fd_gui_poll( fd_gui_t * gui );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_gui_fd_gui_h */
