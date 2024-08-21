#ifndef HEADER_fd_src_disco_gui_fd_gui_h
#define HEADER_fd_src_disco_gui_fd_gui_h

#include "../fd_disco_base.h"

#include "../../ballet/http/fd_http_server.h"
#include "../../ballet/http/fd_hcache.h"
#include "../../flamenco/types/fd_types.h"
#include "../../flamenco/leaders/fd_leaders.h"

#include "../topo/fd_topo.h"

#define FD_GUI_MAX_SLOTS_CNT_PER_EPOCH (432000UL)
#define FD_GUI_MAX_PUB_CNT             (50000UL)
#define FD_GUI_PER_SLOT_NANOS          (400L*1000L*1000L)
#define FD_GUI_COUNTER_SAMPLE_NANOS    (100L*1000L*1000L)
#define FD_GUI_TILE_SAMPLE_NANOS       (10L*1000L*1000L)
#define FD_GUI_TILE_SAMPLE_PER_SLOT    (FD_GUI_PER_SLOT_NANOS/FD_GUI_TILE_SAMPLE_NANOS)

#define FD_GUI_SLOT_LEVEL_INCOMPLETE               (0)
#define FD_GUI_SLOT_LEVEL_COMPLETED                (1)
#define FD_GUI_SLOT_LEVEL_OPTIMISTICALLY_CONFIRMED (2)
#define FD_GUI_SLOT_LEVEL_ROOTED                   (3)
#define FD_GUI_SLOT_LEVEL_FINALIZED                (4)

struct fd_gui_slot {
  ulong slot;
  long  completed_time;
  int   mine;
  int   skipped;
  int   level;
  ulong total_txn_cnt;
  ulong vote_txn_cnt;
  ulong failed_txn_cnt;
  ulong compute_units;
  ulong fees;
};

typedef struct fd_gui_slot fd_gui_slot_t;

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

/* acquired_txns_leftover is a snapshot value at the beginning of a
   leader slot.
   buffered_txns is a point-in-time gauge value.
   Everything else comes from cumulative counters and we should take
   delats.
   acquired_txns has a base value of acquired_txns_leftover plus the
   deltas of everything else. */
struct fd_gui_txn_info {
  ulong acquired_txns;
  ulong acquired_txns_leftover;
  ulong acquired_txns_quic;
  ulong acquired_txns_nonquic;
  ulong acquired_txns_gossip;
  ulong dropped_txns;
  ulong dropped_txns_net_overrun;
  ulong dropped_txns_net_invalid;
  ulong dropped_txns_quic_overrun;
  ulong dropped_txns_quic_reasm;
  ulong dropped_txns_verify_overrun;
  ulong dropped_txns_verify_drop;
  ulong dropped_txns_dedup_drop;
  ulong dropped_txns_pack_nonleader;
  ulong dropped_txns_pack_invalid;
  ulong dropped_txns_pack_priority;
  ulong dropped_txns_bank_invalid;
  ulong executed_txns_failure;
  ulong executed_txns_success;
  ulong buffered_txns;
};

typedef struct fd_gui_txn_info fd_gui_txn_info_t;

struct fd_gui_full_tile_info {
  ulong housekeeping_ticks;
  ulong backpressure_ticks;
  ulong caught_up_ticks;
  ulong overrun_polling_ticks;
  ulong overrun_reading_ticks;
  ulong filter_before_frag_ticks;
  ulong filter_after_frag_ticks;
  ulong finish_ticks;
};

typedef struct fd_gui_full_tile_info fd_gui_full_tile_info_t;

FD_FN_UNUSED static ulong
tile_total_ticks( fd_gui_full_tile_info_t * tile_info ) {
  return tile_info->housekeeping_ticks +
         tile_info->backpressure_ticks +
         tile_info->caught_up_ticks +
         tile_info->overrun_polling_ticks +
         tile_info->overrun_reading_ticks +
         tile_info->filter_before_frag_ticks +
         tile_info->filter_after_frag_ticks +
         tile_info->finish_ticks;
}

struct fd_gui_tile_info {
  ulong caught_up_ticks;
  ulong total_ticks;
  long ts;
};

typedef struct fd_gui_tile_info fd_gui_tile_info_t;

struct fd_gui {
  fd_hcache_t * hcache;

  fd_topo_t * topo;

  long next_sample_100millis;
  long next_sample_10millis;

  struct {
    fd_pubkey_t identity_key[ 1 ];

#define FD_GUI_NUM_EPOCHS 2UL
    char const * version;        
    char const * cluster;

    char identity_key_base58[ FD_BASE58_ENCODED_32_SZ+1 ];

    long  startup_time_nanos;

    ulong balance;
    ulong estimated_slot_duration_nanos;

    ulong slot_rooted;
    ulong slot_optimistically_confirmed;
    ulong slot_completed;
    ulong slot_estimated;

    ulong estimated_tps;
    ulong estimated_vote_tps;
    ulong estimated_failed_tps;

    fd_gui_txn_info_t txn_info_prev[ 1 ]; /* Cumulative/Sampled */
    fd_gui_txn_info_t txn_info_this[ 1 ]; /* Cumulative/Sampled */
    fd_gui_txn_info_t txn_info_json[ 1 ]; /* Delta/Computed */
    fd_gui_txn_info_t txn_info_hist[ FD_GUI_NUM_EPOCHS ][ FD_GUI_MAX_SLOTS_CNT_PER_EPOCH ]; /* Historical data */
    ulong             txn_info_slot[ FD_GUI_NUM_EPOCHS ][ FD_GUI_MAX_SLOTS_CNT_PER_EPOCH ]; /* Which slot is the historical data for? */
    ulong             slot_start_high_watermark;
    ulong             slot_end_high_watermark;

    ulong net_tile_count;
    ulong quic_tile_count;
    ulong verify_tile_count;
    ulong bank_tile_count;
    ulong shred_tile_count;

    /* In a perfect world we'd have exactly x number of samples per
       slot, but due to clock drift and whatnot, let's just allocate
       more space for now. TODO implement proper garbage collected ring
       buffer. */
#define FD_GUI_MAX_TILES 64
#define FD_GUI_TILE_SAMPLE_CNT_PER_TILE (FD_GUI_TILE_SAMPLE_PER_SLOT * FD_GUI_MAX_SLOTS_CNT_PER_EPOCH * FD_GUI_NUM_EPOCHS * 2)
    fd_gui_tile_info_t tile_info[ FD_GUI_MAX_TILES ][ FD_GUI_TILE_SAMPLE_CNT_PER_TILE ];
    fd_gui_tile_info_t tile_info_slot_start_end[ FD_GUI_NUM_EPOCHS ][ FD_GUI_MAX_TILES ][ FD_GUI_MAX_SLOTS_CNT_PER_EPOCH * 2 ];
    ulong              tile_info_slot_start_end_sample_cnt[ FD_GUI_NUM_EPOCHS ][ FD_GUI_MAX_SLOTS_CNT_PER_EPOCH * 2 ];
    ulong tile_info_sample_cnt;
    long  last_tile_info_ts;
  } summary;

  struct {
    struct {
      ulong epoch;
      ulong start_slot;
      ulong end_slot;
      ulong excluded_stake;
      fd_epoch_leaders_t * lsched;
      uchar __attribute__((aligned(FD_EPOCH_LEADERS_ALIGN))) _lsched[ FD_EPOCH_LEADERS_FOOTPRINT(FD_GUI_MAX_PUB_CNT, FD_GUI_MAX_SLOTS_CNT_PER_EPOCH) ];
      fd_stake_weight_t stakes[ FD_GUI_MAX_PUB_CNT ];
    } epochs[ FD_GUI_NUM_EPOCHS ];
    ulong max_known_epoch;
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
    ulong info_cnt;
    struct fd_gui_validator_info info[ 40200 ];
  } validator_info;

  struct {
    fd_gui_slot_t data[ 864000UL ][ 1 ];
  } slots;

  char tmp_buf[ 8192 ];
};

typedef struct fd_gui fd_gui_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong
fd_gui_align( void );

FD_FN_CONST ulong
fd_gui_footprint( void );

void *
fd_gui_new( void *        shmem,
            fd_hcache_t * hcache,
            char const *  version,
            char const *  cluster,
            uchar const * identity_key,
            fd_topo_t *   topo );

fd_gui_t *
fd_gui_join( void * shmem );

void
fd_gui_ws_open( fd_gui_t *  gui,
                ulong       conn_id );

void
fd_gui_ws_message( fd_gui_t *    gui,
                   ulong         ws_conn_id,
                   uchar const * data,
                   ulong         data_len );

void
fd_gui_plugin_message( fd_gui_t *    gui,
                       ulong         plugin_msg,
                       uchar const * msg,
                       ulong         msg_len );

void
fd_gui_poll( fd_gui_t * gui );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_gui_fd_gui_h */
