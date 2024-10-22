#ifndef HEADER_fd_src_disco_gui_fd_gui_h
#define HEADER_fd_src_disco_gui_fd_gui_h

#include "../fd_disco_base.h"

#include "../../ballet/http/fd_http_server.h"
#include "../../flamenco/types/fd_types.h"
#include "../../flamenco/leaders/fd_leaders.h"

#include "../topo/fd_topo.h"

#define FD_GUI_SLOTS_CNT (864000UL)
#define FD_GUI_TPS_HISTORY_WINDOW_DURATION_SECONDS (10L) /* 10 second moving average */
#define FD_GUI_TPS_HISTORY_SAMPLE_CNT              (150UL)
#define FD_GUI_TILE_TIMER_SNAP_CNT                 (512UL)
#define FD_GUI_TILE_TIMER_LEADER_CNT               (4096UL)
#define FD_GUI_TILE_TIMER_LEADER_DOWNSAMPLE_CNT    (50UL)
#define FD_GUI_TILE_TIMER_TILE_CNT                 (128UL)

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
  } in;

  struct {
    ulong net_overrun;
    ulong quic_overrun;
    ulong quic_quic_invalid;
    ulong quic_udp_invalid;
    ulong verify_overrun;
    ulong verify_parse;
    ulong verify_failed;
    ulong verify_duplicate;
    ulong dedup_duplicate;
    ulong resolv_failed;
    ulong pack_invalid;
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

struct fd_gui_tile_prime_metric {
  ulong net_in_bytes;
  ulong quic_conns;
  ulong verify_drop_numerator;
  ulong verify_drop_denominator;
  ulong dedup_drop_numerator;
  ulong dedup_drop_denominator;
  ulong pack_fill_numerator;
  ulong pack_fill_denominator;
  ulong bank_txn;
  ulong net_out_bytes;
  long  ts_nanos;
};

typedef struct fd_gui_tile_prime_metric fd_gui_tile_prime_metric_t;

#define FD_GUI_SLOT_LEADER_UNSTARTED (0UL)
#define FD_GUI_SLOT_LEADER_STARTED   (1UL)
#define FD_GUI_SLOT_LEADER_ENDED     (2UL)

struct fd_gui_slot {
  ulong slot;
  ulong parent_slot;
  long  completed_time;
  int   mine;
  int   skipped;
  int   must_republish;
  int   level;
  ulong total_txn_cnt;
  ulong vote_txn_cnt;
  ulong failed_txn_cnt;
  ulong nonvote_failed_txn_cnt;
  ulong compute_units;
  ulong transaction_fee;
  ulong priority_fee;

  int leader_state;

  fd_gui_txn_waterfall_t waterfall_begin[ 1 ];
  fd_gui_txn_waterfall_t waterfall_end[ 1 ];

  fd_gui_tile_prime_metric_t tile_prime_metric_begin[ 1 ];
  fd_gui_tile_prime_metric_t tile_prime_metric_end[ 1 ];

  ulong tile_timers_history_idx;
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
    char identity_key_base58[ FD_BASE58_ENCODED_32_SZ+1 ];

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

    ulong balance;
    ulong estimated_slot_duration_nanos;

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

    fd_gui_tile_prime_metric_t tile_prime_metric_ref[ 1 ];
    fd_gui_tile_prime_metric_t tile_prime_metric_cur[ 1 ];

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
      uchar __attribute__((aligned(FD_EPOCH_LEADERS_ALIGN))) _lsched[ FD_EPOCH_LEADERS_FOOTPRINT(50000UL, 432000UL) ];
      fd_stake_weight_t stakes[ 50000UL ];
    } epochs[ 2 ];
  } epoch;

  struct {
    ulong                     peer_cnt;
    struct fd_gui_gossip_peer peers[ 40200 ];
  } gossip;

  struct {
    ulong                      vote_account_cnt;
    struct fd_gui_vote_account vote_accounts[ 40200 ];
  } vote_account;

  struct {
    ulong                        info_cnt;
    struct fd_gui_validator_info info[ 40200 ];
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
            int                is_voting,
            fd_topo_t *        topo );

fd_gui_t *
fd_gui_join( void * shmem );

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

int
fd_gui_poll( fd_gui_t * gui );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_gui_fd_gui_h */
