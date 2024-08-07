#ifndef HEADER_fd_src_disco_gui_fd_gui_h
#define HEADER_fd_src_disco_gui_fd_gui_h

#include "../fd_disco_base.h"

#include "../../ballet/http/fd_http_server.h"
#include "../../ballet/http/fd_hcache.h"
#include "../../flamenco/types/fd_types.h"
#include "../../flamenco/leaders/fd_leaders.h"

#include "../topo/fd_topo.h"

#define MAX_SLOTS_CNT         432000UL
#define MAX_PUB_CNT           50000UL

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

struct fd_gui_tile_info {
  ulong housekeeping_ticks;
  ulong backpressure_ticks;
  ulong caught_up_ticks;
  ulong overrun_polling_ticks;
  ulong overrun_reading_ticks;
  ulong filter_before_frag_ticks;
  ulong filter_after_frag_ticks;
  ulong finish_ticks;
};

typedef struct fd_gui_tile_info fd_gui_tile_info_t;

struct fd_gui {
  fd_hcache_t * hcache;

  fd_topo_t * topo;

  long next_sample_100millis;

  struct {
    char const * version;        
    char const * cluster;
    char const * identity_key_base58;

    ulong slot_rooted;
    ulong slot_optimistically_confirmed;
    ulong slot_completed;
    ulong slot_estimated;

    fd_gui_txn_info_t txn_info_prev[ 1 ]; /* Cumulative/Sampled */
    fd_gui_txn_info_t txn_info_this[ 1 ]; /* Cumulative/Sampled */
    fd_gui_txn_info_t txn_info_json[ 1 ]; /* Delta/Computed */

    ulong net_tile_count;
    ulong quic_tile_count;
    ulong verify_tile_count;
    ulong bank_tile_count;
    ulong shred_tile_count;

    fd_gui_tile_info_t tile_info[ FD_TOPO_MAX_TILES * 2 ];
    ulong tile_info_sample_cnt;
    long  last_tile_info_ts;
  } summary;

  struct {
#define FD_GUI_NUM_EPOCHS 2UL
    struct {
      ulong epoch;
      ulong start_slot;
      ulong end_slot;
      ulong excluded_stake;
      fd_epoch_leaders_t * lsched;
      uchar __attribute__((aligned(FD_EPOCH_LEADERS_ALIGN))) _lsched[ FD_EPOCH_LEADERS_FOOTPRINT(MAX_PUB_CNT, MAX_SLOTS_CNT) ];
      fd_stake_weight_t stakes[ MAX_PUB_CNT ];
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
            char const *  identity_key_base58,
            fd_topo_t *   topo );

fd_gui_t *
fd_gui_join( void * shmem );

void
fd_gui_ws_open( fd_gui_t *  gui,
                ulong       conn_id );

void
fd_gui_plugin_message( fd_gui_t *    gui,
                       ulong         plugin_msg,
                       uchar const * msg,
                       ulong         msg_len );

void
fd_gui_poll( fd_gui_t * gui );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_gui_fd_gui_h */
