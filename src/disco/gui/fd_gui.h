#ifndef HEADER_fd_src_disco_gui_fd_gui_h
#define HEADER_fd_src_disco_gui_fd_gui_h

#include "fd_gui_base.h"
#include "fd_gui_peers.h"

#include "../topo/fd_topo.h"

#include "../../util/fd_util_base.h"
#include "../../waltz/http/fd_http_server.h"
#include "../../flamenco/leaders/fd_leaders.h"
#include "../../discof/restore/fd_snaprd_tile.h"

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
      struct { /* used in frankendancer */
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
          long   reset_time_nanos;                /* UNIX nanosecond timestamp */
          long   sample_time_nanos;
          ulong  reset_cnt;

          ulong read_bytes_compressed;
          char  read_path[ PATH_MAX+30UL ];       /* URL or filesystem path.  30 is fd_cstr_nlen( "https://255.255.255.255:12345/", ULONG_MAX ) */

          ulong decompress_bytes_decompressed;
          ulong decompress_bytes_compressed;

          ulong insert_bytes_decompressed;
          char  insert_path[ PATH_MAX ];
          ulong insert_accounts_current;
        } loading_snapshot[ FD_GUI_BOOT_PROGRESS_SNAPSHOT_CNT ];

        long  catching_up_time_nanos;
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

    fd_gui_ephemeral_slot_t slots_max_turbine[ FD_GUI_TURBINE_SLOT_HISTORY_SZ+1UL ];
    fd_gui_ephemeral_slot_t slots_max_repair [ FD_GUI_REPAIR_SLOT_HISTORY_SZ +1UL ];

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

  struct {
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

    fd_gui_txn_waterfall_t waterfall_begin[ 1 ];
    fd_gui_txn_waterfall_t waterfall_end[ 1 ];

    fd_gui_tile_stats_t tile_stats_begin[ 1 ];
    fd_gui_tile_stats_t tile_stats_end[ 1 ];

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
  } leader_history[ FD_GUI_LEADER_CNT ];
  ulong leader_history_idx;

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

      ulong rankings_slot; /* One more than the largest slot we've processed into our rankings */
      fd_gui_slot_rankings_t rankings[ 1 ]; /* global slot rankings */
      fd_gui_slot_rankings_t my_rankings[ 1 ]; /* my slots only */
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

  fd_gui_peers_ctx_t * peers; /* full-client */
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
                      long       now,
                      ulong      slot,
                      long       start_time_nanos,
                      long       end_time_nanos,
                      ulong      max_compute_units,
                      ulong      max_microblocks );

void
fd_gui_unbecame_leader( fd_gui_t * gui,
                        long       now,
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
                               fd_snaprd_update_t * msg );


FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_gui_fd_gui_h */
