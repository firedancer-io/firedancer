#ifndef HEADER_fd_src_discof_tower_fd_tower_tile_private_h
#define HEADER_fd_src_discof_tower_fd_tower_tile_private_h

/* Internal types of the tower tile.  Included by the tile and by
   firedancer-dev's tower command, which reads the tile's ctx out of
   shared memory. */

#include "fd_tower_tile.h"
#include "../../choreo/eqvoc/fd_eqvoc.h"
#include "../../choreo/ghost/fd_ghost.h"
#include "../../choreo/hfork/fd_hfork.h"
#include "../../choreo/votes/fd_votes.h"
#include "../../choreo/tower/fd_tower.h"
#include "../../choreo/tower/fd_tower_file.h"
#include "../../choreo/tower/fd_tower_recover.h"
#include "../../choreo/tower/fd_tower_serdes.h"
#include "../../choreo/tower/fd_tower_stakes.h"
#include "../../disco/keyguard/fd_keyguard_client.h"
#include "../../disco/keyguard/fd_keyswitch.h"
#include "../../disco/metrics/fd_metrics.h"
#include "../../disco/fd_txn_m.h"
#include "../../discof/replay/fd_replay_tile.h"
#include "../../flamenco/leaders/fd_multi_epoch_leaders.h"
#include "../../flamenco/runtime/fd_bank.h"
#include "../../flamenco/runtime/program/vote/fd_vote_state_versioned.h"
#include "../../flamenco/stakes/fd_vote_stakes.h"
#include "../../util/fd_hash32.h"

#define AUTH_VTR_LG_MAX (5) /* The Solana Vote Interface supports up to 32 authorized voters. */
FD_STATIC_ASSERT( 1<<AUTH_VTR_LG_MAX==32, AUTH_VTR_LG_MAX );

/* Tower processes at most 2 equivocating blocks for a given slot: the
   first block is the first one we observe for a slot, and the second
   block is the one that gets duplicate confirmed.  Most of the time,
   they are the same (ie. the block we first saw is the block that gets
   duplicate confirmed), but we size for the worst case which is every
   block in slot_max equivocates and we always see 2 blocks for every
   slot. */

#define EQVOC_MAX (2)

/* The Alpenglow VAT caps the voting set of validators to 2000.  Only
   the top 2000 voters by stake will be counted towards consensus rules.
   Firedancer uses the same bound for TowerBFT.

   Note module implementations may round the max capacity of various
   structures to pow2 for performance, but the consensus logic will only
   retain at most 2000 voters.

   https://github.com/solana-foundation/solana-improvement-documents/blob/main/proposals/0357-alpenglow_validator_admission_ticket.md */

#define VTR_MAX (2000) /* the maximum # of unique voters ie. node pubkeys. */

/* PER_VTR_MAX controls how many "entries" a validator is allowed to
   occupy in various vote-tracking structures.  This is set somewhat
   arbitrarily based on expected worst-case usage by an honest validator
   and is set to guard against a malicious spamming validator attempting
   to oom Firedancer structures. */

#define PER_VTR_MAX (512) /* the maximum amount of slot history the sysvar retains */

struct publish {
  ulong          sig;
  fd_tower_msg_t msg;
};
typedef struct publish publish_t;

#define DEQUE_NAME publishes
#define DEQUE_T    publish_t
#include "../../util/tmpl/fd_deque_dynamic.c"

struct auth_vtr {
  fd_pubkey_t addr;      /* map key, vote account address */
  uint        hash;      /* reserved for use by fd_map */
  ulong       paths_idx; /* index in authorized voter paths */
};
typedef struct auth_vtr auth_vtr_t;

#define MAP_NAME               auth_vtr
#define MAP_T                  auth_vtr_t
#define MAP_LG_SLOT_CNT        AUTH_VTR_LG_MAX
#define MAP_KEY                addr
#define MAP_KEY_T              fd_pubkey_t
#define MAP_KEY_NULL           (fd_pubkey_t){0}
#define MAP_KEY_EQUAL(k0,k1)   (!(memcmp((k0).key,(k1).key,sizeof(fd_pubkey_t))))
#define MAP_KEY_INVAL(k)       (MAP_KEY_EQUAL((k),MAP_KEY_NULL))
#define MAP_KEY_EQUAL_IS_SLOW  1
#define MAP_KEY_HASH(k)        ((uint)fd_ulong_hash( fd_ulong_load_8( (k).uc ) ))
#include "../../util/tmpl/fd_map.c"

struct epoch_vtr {
  fd_pubkey_t vote_acc;
  ulong       stake;
  fd_pubkey_t auth_vtr; /* authorized voter for vote_acc at this map's target epoch; all-zero if unavailable */
  ulong       next; /* reserved for fd_pool and fd_map_chain */
};
typedef struct epoch_vtr epoch_vtr_t;

#define POOL_NAME epoch_vtr_pool
#define POOL_T    epoch_vtr_t
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME               epoch_vtr_map
#define MAP_ELE_T              epoch_vtr_t
#define MAP_KEY                vote_acc
#define MAP_KEY_T              fd_pubkey_t
#define MAP_KEY_EQ(k0,k1)      (!memcmp((k0),(k1),sizeof(fd_pubkey_t)))
#define MAP_KEY_HASH(key,seed) (fd_hash32( (key)->uc, (seed) ))
#define MAP_NEXT               next
#include "../../util/tmpl/fd_map_chain.c"

#define AUTH_VOTERS_MAX (16UL)

struct in_ctx {
  int         mcache_only;
  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
  ulong       mtu;
};
typedef struct in_ctx in_ctx_t;

struct fd_tower_tile {
  ulong            seed; /* map seed */
  int              tower_file_enabled;
  int              tower_file_sandboxed; /* reserved descriptor number is fixed by seccomp */
  int              tower_dir_fd;
  int              tower_file_fd;
  ulong            tower_file_sz;
  fd_pubkey_t      tower_file_identity;
  fd_keyguard_client_t keyguard_client[ 1 ];
  uchar            tower_file_buf[ FD_TOWER_FILE_MAX ];
  fd_tower_recover_t recovery;
  int              recovery_pending;
  int              tower_file_loaded;      /* the signed file for the staked identity was verified at boot */
  fd_tower_file_t  signed_tower;           /* newest checkpoint signed during this process */
  int              signed_tower_valid;
  int              epoch_refresh_pending;  /* an adoption advanced the root, refresh the epoch voter caches on the next completed slot */
  int              recovery_initialized;
  int              recovery_from_adopt;    /* the failover tile asked for this recovery, a stale file follows the vote account */
  int              local_adopt_pending;    /* answer the zero length adoption once the recovery has run */
  int              local_adopt_answer;     /* the answer is ready to publish */
  ulong            local_adopt_sig;
  fd_tower_adopt_result_t local_adopt_result;
  ulong            recovery_onchain_root;  /* our root in the vote account at the last replayed slot */
  int              first_use_pending;
  int              first_use_authorized;  /* one launch, consumed when the staked key is installed */
  int              failover_tower_adopted; /* a confirmed tower was adopted before this switch */
  int              no_vote_authority;     /* shadow votes never authorize the staked identity */
  int              failover_enabled;
  fd_pubkey_t      failover_staked_identity; /* the one identity of the pool */
  int              failover_standby;
  fd_pubkey_t      identity_key[1];
  fd_pubkey_t      vote_account[1];
  ulong            auth_vtr_path_cnt;  /* number of authorized voter paths passed to tile */
  uchar            our_vote_acct[FD_VOTE_STATE_DATA_MAX]; /* buffer for reading back our own vote acct data */
  ulong            our_vote_acct_sz;

  /* owned joins */

  fd_wksp_t *      wksp; /* workspace */
  fd_keyswitch_t * identity_keyswitch;
  auth_vtr_t *     auth_vtr;
  fd_keyswitch_t * auth_vtr_keyswitch; /* authorized voter keyswitch */

  fd_eqvoc_t * eqvoc;
  fd_ghost_t * ghost;
  fd_hfork_t * hfork;
  fd_votes_t * votes;
  fd_tower_t * tower;

  fd_vote_instruction_t scratch_ix;
  fd_tower_vote_t *     scratch_tower; /* spare deque used during vote txn processing */

  publish_t *                publishes; /* deque of slot_confirmed msgs queued for publishing */
  fd_multi_epoch_leaders_t * mleaders; /* multi-epoch leaders */

  /* borrowed joins */

  fd_banks_t * banks;
  fd_accdb_t * accdb;

  /* static structures */

  fd_pubkey_t                   id_keys  [VTR_MAX]; /* identity keys */
  fd_pubkey_t                   vote_accs[VTR_MAX]; /* vote account addresses */
  ulong                         vtr_cnt;            /* actual cnt of elements in above arrays */
  fd_gossip_duplicate_shred_t   duplicate_chunks[FD_EQVOC_CHUNK_CNT];
  fd_compact_tower_sync_serde_t compact_tower_sync_serde;
  uchar                         vote_txn[FD_TPU_PARSED_MTU];

  uchar __attribute__((aligned(FD_MULTI_EPOCH_LEADERS_ALIGN))) mleaders_mem[ FD_MULTI_EPOCH_LEADERS_FOOTPRINT ];
  uchar __attribute__((aligned(FD_VOTE_STAKES_ITER_ALIGN))) iter_mem[ FD_VOTE_STAKES_ITER_FOOTPRINT ];

  ulong             root_epoch;
  ulong             root_epoch_total_stake;
  ulong             next_epoch_total_stake;
  epoch_vtr_t     * root_epoch_vtr_pool;
  epoch_vtr_map_t * root_epoch_vtr_map;
  epoch_vtr_t     * next_epoch_vtr_pool;
  epoch_vtr_map_t * next_epoch_vtr_map;

  /* metadata */

  int    halt_signing;
  int    hard_fork_fatal;
  int    wfs;           /* 1 if booted with wait_for_supermajority */
  ushort shred_version;
  int    init; /* 1 after ghost_init has been called */

  /* in/out link setup */

  int      in_kind[ 64UL ];
  in_ctx_t in     [ 64UL ];

  fd_wksp_t * out_mem;
  ulong       out_chunk0;
  ulong       out_wmark;
  ulong       out_idx;
  ulong       out_chunk;
  ulong       out_seq;

  /* Adoption results go back to the failover tile on their own link. */
  ulong       failov_out_idx;
  fd_wksp_t * failov_out_mem;
  ulong       failov_out_chunk0;
  ulong       failov_out_wmark;
  ulong       failov_out_chunk;

  /* metrics */

  struct {
    ulong not_ready;

    ulong ignored_cnt;
    ulong ignored_slot;
    ulong eqvoc_cnt;
    ulong eqvoc_slot;

    ulong replay_slot;
    ulong last_vote_slot;
    ulong reset_slot;
    ulong root_slot;
    ulong init_slot;

    ulong fork[ FD_METRICS_ENUM_TOWER_FORK_DECISION_CNT ];
    ulong gate[ FD_METRICS_ENUM_TOWER_VOTE_GATE_CNT ];

    ulong votes     [ FD_METRICS_ENUM_VOTE_TXN_RESULT_CNT         ];
    ulong vote_slots[ FD_METRICS_ENUM_VOTE_SLOT_RESULT_CNT        ];
    ulong gate_int  [ FD_METRICS_ENUM_VOTE_INTERMEDIATE_GATE_CNT  ];

    ulong eqvoc_success;
    ulong eqvoc_err;

    ulong ghost[ FD_METRICS_ENUM_GHOST_VOTE_RESULT_CNT ];

    ulong hfork[ FD_METRICS_ENUM_HARD_FORK_VOTE_RESULT_CNT ];

    ulong hfork_matched_slot;
    ulong hfork_mismatched_slot;
  } metrics;
};
typedef struct fd_tower_tile fd_tower_tile_t;

#endif /* HEADER_fd_src_discof_tower_fd_tower_tile_private_h */
