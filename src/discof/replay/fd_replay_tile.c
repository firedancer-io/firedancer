#include "fd_replay_tile.h"
#include "fd_sched.h"
#include "fd_exec.h"
#include "fd_vote_tracker.h"
#include "../../flamenco/accdb/fd_accdb_sync.h"
#include "generated/fd_replay_tile_seccomp.h"

#include "../genesis/fd_genesi_tile.h"
#include "../poh/fd_poh.h"
#include "../poh/fd_poh_tile.h"
#include "../tower/fd_tower_tile.h"
#include "../resolv/fd_resolv_tile.h"
#include "../restore/utils/fd_ssload.h"

#include "../../disco/tiles.h"
#include "../../disco/fd_txn_m.h"
#include "../../disco/store/fd_store.h"
#include "../../discof/reasm/fd_reasm.h"
#include "../../disco/keyguard/fd_keyload.h"
#include "../../util/pod/fd_pod.h"
#include "../../flamenco/accdb/fd_accdb_admin.h"
#include "../../flamenco/accdb/fd_accdb_user.h"
#include "../../flamenco/rewards/fd_rewards.h"
#include "../../flamenco/leaders/fd_multi_epoch_leaders.h"
#include "../../flamenco/progcache/fd_progcache_admin.h"
#include "../../disco/metrics/fd_metrics.h"

#include "../../flamenco/runtime/fd_runtime.h"
#include "../../flamenco/runtime/fd_runtime_stack.h"
#include "../../flamenco/fd_flamenco_base.h"
#include "../../flamenco/runtime/sysvar/fd_sysvar_epoch_schedule.h"

#include "../../flamenco/runtime/tests/fd_dump_pb.h"

#include <errno.h>

/* Replay concepts:

   - Blocks are aggregations of entries aka. microblocks which are
     groupings of txns and are constructed by the block producer (see
     fd_pack).

   - Entries are grouped into entry batches by the block producer (see
     fd_pack / fd_shredder).

   - Entry batches are divided into chunks known as shreds by the block
     producer (see fd_shredder).

   - Shreds are grouped into forward-error-correction sets (FEC sets) by
     the block producer (see fd_shredder).

   - Shreds are transmitted to the rest of the cluster via the Turbine
     protocol (see fd_shredder / fd_shred).

   - Once enough shreds within a FEC set are received to recover the
     entirety of the shred data encoded by that FEC set, the receiver
     can "complete" the FEC set (see fd_fec_resolver).

   - If shreds in the FEC set are missing such that it can't complete,
     the receiver can use the Repair protocol to request missing shreds
     in FEC set (see fd_repair).

  -  The current Repair protocol does not support requesting coding
     shreds.  As a result, some FEC sets might be actually complete
     (contain all data shreds).  Repair currently hacks around this by
     forcing completion but the long-term solution is to add support for
     fec_repairing coding shreds via Repair.

  - FEC sets are delivered in partial-order to the Replay tile by the
    Repair tile.  Currently Replay only supports replaying entry batches
    so FEC sets need to reassembled into an entry batch before they can
    be replayed.  The new Dispatcher will change this by taking a FEC
    set as input instead. */

#define IN_KIND_SNAP    (0)
#define IN_KIND_GENESIS (1)
#define IN_KIND_IPECHO  (2)
#define IN_KIND_TOWER   (3)
#define IN_KIND_RESOLV  (4)
#define IN_KIND_POH     (5)
#define IN_KIND_EXEC    (6)
#define IN_KIND_SHRED   (7)
#define IN_KIND_VTXN    (8)
#define IN_KIND_GUI     (9)

#define DEBUG_LOGGING 0

/* The first bank that that the replay tile produces either for genesis
   or the snapshot boot will always be at bank index 0. */
#define FD_REPLAY_BOOT_BANK_IDX (0UL)

struct fd_replay_in_link {
  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
  ulong       mtu;
};

typedef struct fd_replay_in_link fd_replay_in_link_t;

struct fd_replay_out_link {
  ulong       idx;
  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
  ulong       chunk;
};

typedef struct fd_replay_out_link fd_replay_out_link_t;

/* fd_block_id_map is a simple map of block-ids to bank indices.  The
   map sits on top of an array of fd_block_id_ele_t.  This serves as a
   translation layer between block ids to bank indices. */

struct fd_block_id_ele {
  fd_hash_t block_id;
  ulong     slot; /* = FD_SLOT_NULL if not initialized */
  ulong     next_;
};
typedef struct fd_block_id_ele fd_block_id_ele_t;

#define MAP_NAME               fd_block_id_map
#define MAP_ELE_T              fd_block_id_ele_t
#define MAP_KEY_T              fd_hash_t
#define MAP_KEY                block_id
#define MAP_NEXT               next_
#define MAP_KEY_EQ(k0,k1)      (!memcmp((k0),(k1), sizeof(fd_hash_t)))
#define MAP_KEY_HASH(key,seed) (fd_hash((seed),(key),sizeof(fd_hash_t)))
#include "../../util/tmpl/fd_map_chain.c"

static inline ulong
fd_block_id_ele_get_idx( fd_block_id_ele_t * ele_arr, fd_block_id_ele_t * ele ) {
  return (ulong)(ele - ele_arr);
}

struct fd_replay_tile {
  fd_wksp_t * wksp;

  fd_accdb_admin_t     accdb_admin[1];
  fd_accdb_user_t      accdb[1];
  fd_progcache_admin_t progcache_admin[1];

  fd_txncache_t * txncache;
  fd_store_t *    store;
  fd_banks_t *    banks;

  /* This flag is 1 If we have seen a vote signature that our node has
     sent out get rooted at least one time.  The value is 0 otherwise.
     We can't become leader and pack blocks until this flag has been
     set.  This parallels the Agave 'has_new_vote_been_rooted'.

     TODO: Add a flag to the toml to make this optional. */
  int has_identity_vote_rooted;

  fd_reasm_t * reasm;

  /* Replay state machine. */
  fd_sched_t *         sched;
  uint                 enable_bank_hash_cmp:1;
  fd_bank_hash_cmp_t * bank_hash_cmp;
  ulong                exec_cnt;
  fd_replay_out_link_t exec_out[ 1 ]; /* Sending work down to exec tiles */

  fd_vote_tracker_t *  vote_tracker;

  int has_genesis_hash;
  uchar genesis_hash[ 32UL ];

#define FD_REPLAY_HARD_FORKS_MAX (64UL)
  ulong hard_forks_cnt;
  ulong hard_forks[ FD_REPLAY_HARD_FORKS_MAX ];

  ushort expected_shred_version;
  ushort ipecho_shred_version;

  /* A note on publishing ...

     The watermarks are used to publish our fork-aware structures.  For
     example, store, banks, and txncache need to be published to release
     resources occupied by rooted or dead blocks.  In general,
     publishing has the effect of pruning forks in those structures,
     indicating that it is ok to release the memory being occupied by
     the blocks on said forks.  Tower is responsible for informing us of
     the latest block on the consensus rooted fork.  As soon as we can,
     we should move the published root as close as possible to the
     latest consensus root, publishing/pruning everything on the fork
     tree along the way.  That is, all the blocks that directly descend
     from the current published root (inclusive) to the new published
     root (exclusive) on the rooted fork, as well as all the minority
     forks that branch from said blocks.

     Ideally, we'd move the published root to the consensus root
     immediately upon receiving a new consensus root.  However, that's
     not always safe to do.  One thing we need to be careful about is
     making sure that there are no more users/consumers of
     soon-to-be-pruned blocks, lest a use-after-free occurs.  This can
     be done by using a reference counter for each block.  Any
     concurrent activity, such as transaction execution in the exec
     tiles, should retain a refcnt on the block for as
     long as it needs access to the shared fork-aware structures related
     to that block.  Eventually, refcnt on a given block will drop down
     to 0 as the block either finishes replaying or gets marked as dead,
     and any other tile that has retained a refcnt on the block releases
     it.  At that point, it becomes a candidate for pruning.  The key to
     safe publishing then becomes figuring out how far we could advance
     the published root, such that every minority fork branching off of
     blocks in between the current published root (inclusive) and the
     new published root (exclusive) is safe to be pruned.  This is a
     straightforward tree traversal, where if a block B on the rooted
     fork has refcnt 0, and all minority forks branching off of B also
     have refcnt 0, then B is safe to be pruned.  We advance the
     published root to the farthest consecutively prunable block on the
     rooted fork.  Note that reasm presents the replay tile with a clean
     view of the world where every block is chained off of a parent
     block.  So there are no orpahned/dangling tree nodes to worry
     about.  The world is a nice single tree as far as replay is
     concerned.

     In the following fork tree, every node is a block and the number in
     parentheses is the refcnt on the block.  The chain marked with
     double slashes is the rooted fork.  Suppose the published root is
     at block P, and consensus root is at block T.  We can't publish
     past block P because Q has refcnt 1.


          P(0)
        /    \\
      Q(1)    A(0)
            / ||  \
        X(0) B(0)  C(0)
       /      || \
      Y(0)   M(0) R(0)
            / ||   /  \
        D(2) T(0) J(0) L(0)
              ||
              ..
              ..
              ..
              ||
      blocks we might be actively replaying


     When refcnt on Q drops to 0, we would be able to advance the
     published root to block M, because blocks P, A, and B, as well as
     all subtrees branching off of them, have refcnt 0, and therefore
     can be pruned.  Block M itself cannot be pruned yet because its
     child block D has refcnt 2.  After publishing/pruning, the fork
     tree would be:


             M(0)
            / ||
        D(2) T(0)
              ||
              ..
              ..
              ..
              ||
      blocks we might be actively replaying


     As a result, the shared fork-aware structures can free resources
     for blocks P, A, B, and all subtrees branching off of them.

     For the reference counting part, the replay tile is the sole entity
     that can update the refcnt.  This ensures that all refcnt increment
     and decrement attempts are serialized at the replay tile, and that
     there are no racy resurrection of a soon-to-be-pruned block.  If a
     refcnt increment request arrives after a block has been pruned,
     replay simply rejects the request.

     A note on the implementation of the above ...

     Upon receiving a new consensus root, we descend down the rooted
     fork from the current published root to the new consensus root.  On
     each node/block of the rooted fork, we do a summation of the refcnt
     on the block and all the minority fork blocks branching from the
     block.  If the summation is 0, the block is safe for pruning.  We
     advance the published root to the far end of the consecutive run of
     0 refcnt sums originating from the current published root.  On our
     descent down the minority forks, we also mark any block that hasn't
     finished replaying as dead, so we don't waste time executing them.
     No more transactions shall be dispatched for execution from dead
     blocks.

     Blocks start out with a refcnt of 0.  Other tiles may send a
     request to the replay tile for a reference on a block.  The
     transaction dispatcher is another source of refcnt updates.  On
     every dispatch of a transaction for block B, we increment the
     refcnt for B.  And on every transaction finalization, we decrement
     the refcnt for B.  This means that whenever the refcnt on a block
     is 0, there is no more reference on that block from the execution
     pipeline.  While it might be tempting to simply increment the
     refcnt once when we start replaying a block, and decrement the
     refcnt once when we finish a block, this more fine-grained refcnt
     update strategy allows for aborting and potentially immediate
     pruning of blocks under interleaved block replay.  Upon receiving a
     new consensus root, we can simply look at the refcnt on minority
     fork blocks, and a refcnt of 0 would imply that the block is safe
     for pruning, even if we haven't finished replaying it.  Without the
     fine-grained refcnt, we would need to first stop dispatching from
     the aborted block, and then wait for a full drain of the execution
     pipeline to know for sure that there are no more in-flight
     transactions executing on the aborted block.  Note that this will
     allow the refcnt on any block to transiently drop down to 0.  We
     will not mistakenly prune an actively replaying block, aka a leaf
     node, that is chaining off of the rooted fork, because the
     consensus root is always an ancestor of the actively replaying tip.
     */
  fd_hash_t consensus_root;          /* The most recent block to have reached max lockout in the tower. */
  ulong     consensus_root_slot;     /* slot number of the above. */
  ulong     consensus_root_bank_idx; /* bank index of the above. */
  ulong     published_root_slot;     /* slot number of the published root. */
  ulong     published_root_bank_idx; /* bank index of the published root. */

  /* We need to maintain a tile-local mapping of block-ids to bank index
     and vice versa.  This translation layer is needed for conversion
     since tower operates on block-ids and downstream consumers of FEC
     sets operate on bank indices.  This mapping must happen both ways:
     1. tower sends us block ids and we must map them to bank indices.
     2. when a block is completed, we must map the bank index to a block
        id to send a slot complete message to tower. */
  ulong               block_id_len;
  fd_block_id_ele_t * block_id_arr;
  fd_block_id_map_t * block_id_map;

  /* Capture-related configs */
  fd_capture_ctx_t * capture_ctx;
  FILE *             capture_file;

  /* Whether the runtime has been booted either from snapshot loading
     or from genesis. */
  int is_booted;

  /* Buffer to store vote towers that need to be published to the Tower
     tile. */
  ulong             vote_tower_out_idx; /* index of vote tower to publish next */
  ulong             vote_tower_out_len; /* number of vote towers in the buffer */
  fd_replay_tower_t vote_tower_out[FD_REPLAY_TOWER_VOTE_ACC_MAX];

  fd_multi_epoch_leaders_t * mleaders;

  fd_pubkey_t identity_pubkey[1]; /* TODO: Keyswitch */

  /* When we transition to becoming leader, we can only unbecome the
     leader if we have received a block id from the FEC reassembler, and
     a message from PoH that the leader slot has ended.  After both of
     these conditions are met, then we are free to unbecome the leader.
  */
  int         is_leader;
  int         recv_poh;
  int         recv_block_id;
  ulong       next_leader_slot;
  long        next_leader_tickcount;
  ulong       highwater_leader_slot;
  ulong       reset_slot;
  fd_bank_t * reset_bank;
  fd_hash_t   reset_block_id;
  long        reset_timestamp_nanos;
  double      slot_duration_nanos;
  double      slot_duration_ticks;
  fd_bank_t * leader_bank; /* ==NULL if not currently the leader */

  ulong  resolv_tile_cnt;

  int in_kind[ 64 ];
  fd_replay_in_link_t in[ 64 ];

  fd_replay_out_link_t replay_out[1];

  fd_replay_out_link_t stake_out[1];

  /* The gui tile needs to reliably own a reference to the most recent
     completed active bank.  Replay needs to know if the gui as a
     consumer is enabled so it can increment the bank's refcnt before
     publishing the bank_idx to the gui. */
  int gui_enabled;

  /* For dumping blocks to protobuf. For backtest only. */
  fd_block_dump_ctx_t * block_dump_ctx;

  struct {
    fd_histf_t store_read_wait[ 1 ];
    fd_histf_t store_read_work[ 1 ];
    fd_histf_t store_publish_wait[ 1 ];
    fd_histf_t store_publish_work[ 1 ];
    fd_histf_t store_link_wait[ 1 ];
    fd_histf_t store_link_work[ 1 ];

    ulong slots_total;
    ulong transactions_total;
  } metrics;

  uchar __attribute__((aligned(FD_MULTI_EPOCH_LEADERS_ALIGN))) mleaders_mem[ FD_MULTI_EPOCH_LEADERS_FOOTPRINT ];

  fd_runtime_stack_t runtime_stack;
};

typedef struct fd_replay_tile fd_replay_tile_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 128UL;
}
FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  ulong chain_cnt = fd_block_id_map_chain_cnt_est( tile->replay.max_live_slots );

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_replay_tile_t),  sizeof(fd_replay_tile_t) );
  l = FD_LAYOUT_APPEND( l, alignof(fd_block_id_ele_t), sizeof(fd_block_id_ele_t) * tile->replay.max_live_slots );
  l = FD_LAYOUT_APPEND( l, fd_block_id_map_align(),    fd_block_id_map_footprint( chain_cnt ) );
  l = FD_LAYOUT_APPEND( l, fd_txncache_align(),        fd_txncache_footprint( tile->replay.max_live_slots ) );
  l = FD_LAYOUT_APPEND( l, fd_reasm_align(),           fd_reasm_footprint( 1 << 20 ) );
  l = FD_LAYOUT_APPEND( l, fd_sched_align(),           fd_sched_footprint( tile->replay.max_live_slots ) );
  l = FD_LAYOUT_APPEND( l, fd_vote_tracker_align(),    fd_vote_tracker_footprint() );
  l = FD_LAYOUT_APPEND( l, fd_capture_ctx_align(),     fd_capture_ctx_footprint() );

  if( FD_UNLIKELY( tile->replay.dump_block_to_pb ) ) {
    l = FD_LAYOUT_APPEND( l, fd_block_dump_context_align(), fd_block_dump_context_footprint() );
  }

  l = FD_LAYOUT_FINI( l, scratch_align() );

  return l;
}

static inline void
metrics_write( fd_replay_tile_t * ctx ) {
  FD_MHIST_COPY( REPLAY, STORE_LINK_WAIT,    ctx->metrics.store_link_wait );
  FD_MHIST_COPY( REPLAY, STORE_LINK_WORK,    ctx->metrics.store_link_work );
  FD_MHIST_COPY( REPLAY, STORE_READ_WAIT,    ctx->metrics.store_read_wait );
  FD_MHIST_COPY( REPLAY, STORE_READ_WORK,    ctx->metrics.store_read_work );
  FD_MHIST_COPY( REPLAY, STORE_PUBLISH_WAIT, ctx->metrics.store_publish_wait );
  FD_MHIST_COPY( REPLAY, STORE_PUBLISH_WORK, ctx->metrics.store_publish_work );

  FD_MGAUGE_SET( REPLAY, ROOT_SLOT, ctx->consensus_root_slot==ULONG_MAX ? 0UL : ctx->consensus_root_slot );
  ulong leader_slot = ctx->leader_bank ? fd_bank_slot_get( ctx->leader_bank ) : 0UL;
  FD_MGAUGE_SET( REPLAY, LEADER_SLOT, leader_slot );

  if( FD_LIKELY( ctx->leader_bank ) ) {
    FD_MGAUGE_SET( REPLAY, NEXT_LEADER_SLOT, leader_slot );
    FD_MGAUGE_SET( REPLAY, LEADER_SLOT, leader_slot );
  } else {
    FD_MGAUGE_SET( REPLAY, NEXT_LEADER_SLOT, ctx->next_leader_slot==ULONG_MAX ? 0UL : ctx->next_leader_slot );
    FD_MGAUGE_SET( REPLAY, LEADER_SLOT, 0UL );
  }
  FD_MGAUGE_SET( REPLAY, RESET_SLOT, ctx->reset_slot==ULONG_MAX ? 0UL : ctx->reset_slot );

  fd_bank_t * bank_pool = fd_banks_get_bank_pool( ctx->banks );
  ulong live_banks = fd_banks_pool_max( bank_pool ) - fd_banks_pool_free( bank_pool );
  FD_MGAUGE_SET( REPLAY, LIVE_BANKS, live_banks );

  FD_MCNT_SET( REPLAY, SLOTS_TOTAL, ctx->metrics.slots_total );
  FD_MCNT_SET( REPLAY, TRANSACTIONS_TOTAL, ctx->metrics.transactions_total );
}

static inline ulong
generate_stake_weight_msg( ulong                       epoch,
                           fd_epoch_schedule_t const * epoch_schedule,
                           fd_vote_states_t const *    epoch_stakes,
                           ulong *                     stake_weight_msg_out ) {
  fd_stake_weight_msg_t *  stake_weight_msg = (fd_stake_weight_msg_t *)fd_type_pun( stake_weight_msg_out );
  fd_vote_stake_weight_t * stake_weights    = stake_weight_msg->weights;

  stake_weight_msg->epoch             = epoch;
  stake_weight_msg->start_slot        = fd_epoch_slot0( epoch_schedule, epoch );
  stake_weight_msg->slot_cnt          = epoch_schedule->slots_per_epoch;
  stake_weight_msg->excluded_stake    = 0UL;
  stake_weight_msg->vote_keyed_lsched = 1UL;

  /* FIXME: SIMD-0180 - hack to (de)activate in testnet vs mainnet.
     This code can be removed once the feature is active. */
  if( (1==epoch_schedule->warmup && epoch<FD_SIMD0180_ACTIVE_EPOCH_TESTNET) ||
      (0==epoch_schedule->warmup && epoch<FD_SIMD0180_ACTIVE_EPOCH_MAINNET) ) {
    stake_weight_msg->vote_keyed_lsched = 0UL;
  }

  /* epoch_stakes from manifest are already filtered (stake>0), but not sorted */
  fd_vote_states_iter_t iter_[1];
  ulong idx = 0UL;
  for( fd_vote_states_iter_t * iter = fd_vote_states_iter_init( iter_, epoch_stakes ); !fd_vote_states_iter_done( iter ); fd_vote_states_iter_next( iter ) ) {
    fd_vote_state_ele_t * vote_state = fd_vote_states_iter_ele( iter );
    if( FD_UNLIKELY( !vote_state->stake ) ) continue;

    stake_weights[ idx ].stake = vote_state->stake;
    memcpy( stake_weights[ idx ].id_key.uc, &vote_state->node_account, sizeof(fd_pubkey_t) );
    memcpy( stake_weights[ idx ].vote_key.uc, &vote_state->vote_account, sizeof(fd_pubkey_t) );
    idx++;
  }
  stake_weight_msg->staked_cnt = idx;
  sort_vote_weights_by_stake_vote_inplace( stake_weights, idx );

  return fd_stake_weight_msg_sz( idx );
}

static void
publish_stake_weights( fd_replay_tile_t *   ctx,
                       fd_stem_context_t *  stem,
                       fd_bank_t *          bank,
                       int                  current_epoch ) {
  fd_epoch_schedule_t const * schedule = fd_bank_epoch_schedule_query( bank );
  ulong epoch = fd_slot_to_epoch( schedule, fd_bank_slot_get( bank ), NULL );

  fd_vote_states_t const * vote_states_prev;
  if( FD_LIKELY( current_epoch ) ) vote_states_prev = fd_bank_vote_states_prev_locking_query( bank );
  else                             vote_states_prev = fd_bank_vote_states_prev_prev_locking_query( bank );

  ulong * stake_weights_msg = fd_chunk_to_laddr( ctx->stake_out->mem, ctx->stake_out->chunk );
  ulong stake_weights_sz = generate_stake_weight_msg( epoch+fd_ulong_if( current_epoch, 1UL, 0UL), schedule, vote_states_prev, stake_weights_msg );
  ulong stake_weights_sig = 4UL;
  fd_stem_publish( stem, ctx->stake_out->idx, stake_weights_sig, ctx->stake_out->chunk, stake_weights_sz, 0UL, 0UL, fd_frag_meta_ts_comp( fd_tickcount() ) );
  ctx->stake_out->chunk = fd_dcache_compact_next( ctx->stake_out->chunk, stake_weights_sz, ctx->stake_out->chunk0, ctx->stake_out->wmark );

  if( FD_LIKELY( current_epoch ) ) fd_bank_vote_states_prev_end_locking_query( bank );
  else                             fd_bank_vote_states_prev_prev_end_locking_query( bank );

  fd_multi_epoch_leaders_stake_msg_init( ctx->mleaders, fd_type_pun_const( stake_weights_msg ) );
  fd_multi_epoch_leaders_stake_msg_fini( ctx->mleaders );
}

/**********************************************************************/
/* Vote tower publishing helpers                                      */
/**********************************************************************/

/* fd_replay_out_vote_tower_from_funk queries Funk for the state of the vote
   account with the given pubkey, and copies the state into the given
   fd_replay_tower_t structure. The account data is simply copied as-is.

   Parameters:
   - funk:           The funk database instance to query vote account data from
   - funk_txn:       The funk transaction context for consistent reads
   - pubkey:         The public key of the vote account to retrieve
   - stake:          The stake amount associated with this vote account
   - vote_tower_out: Output structure to populate with vote state information

   Failure modes:
   - Vote account data is too large (returns -1)
   - Vote account is not found in Funk (returns -1) */
static int
fd_replay_out_vote_tower_from_funk(
    fd_accdb_user_t *         accdb,
    fd_funk_txn_xid_t const * xid,
    fd_pubkey_t const *       pubkey,
    ulong                     stake,
    fd_replay_tower_t *       vote_tower_out
) {

  fd_memset( vote_tower_out, 0, sizeof(fd_replay_tower_t) );
  vote_tower_out->key   = *pubkey;
  vote_tower_out->stake = stake;

  /* Speculatively copy out the raw vote account state from Funk */
  for(;;) {
    fd_memset( vote_tower_out->acc, 0, sizeof(vote_tower_out->acc) );

    fd_accdb_peek_t peek[1];
    if( FD_UNLIKELY( !fd_accdb_peek( accdb, peek, xid, pubkey->uc ) ) ) {
      /* FIXME crash here? */
      FD_LOG_WARNING(( "vote account not found. address: %s", FD_BASE58_ENC_32_ALLOCA( pubkey->uc ) ));
      return -1;
    }

    ulong data_sz = fd_accdb_ref_data_sz( peek->acc );
    if( FD_UNLIKELY( data_sz > sizeof(vote_tower_out->acc) ) ) {
      FD_LOG_WARNING(( "vote account %s has too large data. dlen %lu > %lu",
        FD_BASE58_ENC_32_ALLOCA( pubkey->uc ),
        data_sz,
        sizeof(vote_tower_out->acc) ));
      return -1;
    }

    fd_memcpy( vote_tower_out->acc, fd_accdb_ref_data_const( peek->acc ), data_sz );
    vote_tower_out->acc_sz = data_sz;

    if( FD_LIKELY( fd_accdb_peek_test( peek ) ) ) break;
    FD_SPIN_PAUSE();
  }

  return 0;
}

/* This function buffers all the vote account towers that Tower needs at
   the end of this slot into the ctx->vote_tower_out buffer.  These will
   then be published in after_credit.

   This function should be called at the end of a slot, before any epoch
   boundary processing. */
static void
buffer_vote_towers( fd_replay_tile_t *        ctx,
                    fd_funk_txn_xid_t const * xid,
                    fd_bank_t *               bank ) {
  ctx->vote_tower_out_idx = 0UL;
  ctx->vote_tower_out_len = 0UL;

  fd_vote_states_t const * vote_states = fd_bank_vote_states_prev_locking_query( bank );
  fd_vote_states_iter_t iter_[1];
  for( fd_vote_states_iter_t * iter = fd_vote_states_iter_init( iter_, vote_states );
       !fd_vote_states_iter_done( iter );
       fd_vote_states_iter_next( iter ) ) {
    fd_vote_state_ele_t const * vote_state = fd_vote_states_iter_ele( iter );
    if( FD_UNLIKELY( vote_state->stake == 0 ) ) continue; /* skip unstaked vote accounts */
    fd_pubkey_t const * vote_account_pubkey = &vote_state->vote_account;
    if( FD_UNLIKELY( ctx->vote_tower_out_len >= (FD_REPLAY_TOWER_VOTE_ACC_MAX-1UL) ) ) FD_LOG_ERR(( "vote_tower_out_len too large" ));
    if( FD_UNLIKELY( fd_replay_out_vote_tower_from_funk( ctx->accdb,
                                                         xid,
                                                         vote_account_pubkey,
                                                         vote_state->stake,
                                                         &ctx->vote_tower_out[ctx->vote_tower_out_len++] ) ) ) {
      FD_LOG_DEBUG(( "failed to get vote state for vote account %s", FD_BASE58_ENC_32_ALLOCA( vote_account_pubkey->uc ) ));
    }
  }
  fd_bank_vote_states_prev_end_locking_query( bank );
}

/* This function publishes the next vote tower in the
   ctx->vote_tower_out buffer to the tower tile.

   This function should be called in after_credit, after all the vote
   towers for the end of a slot have been buffered in
   ctx->vote_tower_out. */

static void
publish_next_vote_tower( fd_replay_tile_t *  ctx,
                         fd_stem_context_t * stem ) {
  int som = ctx->vote_tower_out_idx==0;
  int eom = ctx->vote_tower_out_idx==( ctx->vote_tower_out_len - 1 );

  fd_replay_tower_t * vote_state = fd_chunk_to_laddr( ctx->replay_out->mem, ctx->replay_out->chunk );
  *vote_state = ctx->vote_tower_out[ ctx->vote_tower_out_idx ];
  fd_stem_publish( stem, ctx->replay_out->idx, REPLAY_SIG_VOTE_STATE, ctx->replay_out->chunk, sizeof(fd_replay_tower_t), fd_frag_meta_ctl( 0UL, som, eom, 0 ), 0UL, fd_frag_meta_ts_comp( fd_tickcount() ) );
  ctx->replay_out->chunk = fd_dcache_compact_next( ctx->replay_out->chunk, sizeof(fd_replay_tower_t), ctx->replay_out->chunk0, ctx->replay_out->wmark );

  ctx->vote_tower_out_idx++;
}

/**********************************************************************/
/* Transaction execution state machine helpers                        */
/**********************************************************************/

static fd_bank_t *
replay_block_start( fd_replay_tile_t *  ctx,
                    fd_stem_context_t * stem,
                    ulong               bank_idx,
                    ulong               parent_bank_idx,
                    ulong               slot ) {
  long before = fd_log_wallclock();

  /* Switch to a new block that we don't have a bank for. */

  fd_bank_t * bank = fd_banks_bank_query( ctx->banks, bank_idx );
  if( FD_UNLIKELY( !bank ) ) {
    FD_LOG_CRIT(( "invariant violation: bank is NULL for bank index %lu", bank_idx ));
  }
  if( FD_UNLIKELY( bank->flags!=FD_BANK_FLAGS_INIT ) ) {
    FD_LOG_CRIT(( "invariant violation: bank is not in correct state for bank index %lu", bank_idx ));
  }

  bank->preparation_begin_nanos = before;

  fd_bank_t * parent_bank = fd_banks_bank_query( ctx->banks, parent_bank_idx );
  if( FD_UNLIKELY( !parent_bank ) ) {
    FD_LOG_CRIT(( "invariant violation: parent bank is NULL for bank index %lu", parent_bank_idx ));
  }
  if( FD_UNLIKELY( !(parent_bank->flags&FD_BANK_FLAGS_FROZEN) ) ) {
    FD_LOG_CRIT(( "invariant violation: parent bank is not frozen for bank index %lu", parent_bank_idx ));
  }
  ulong parent_slot = fd_bank_slot_get( parent_bank );

  /* Clone the bank from the parent.  We must special case the first
     slot that is executed as the snapshot does not provide a parent
     block id. */

  bank = fd_banks_clone_from_parent( ctx->banks, bank_idx, parent_bank_idx );
  if( FD_UNLIKELY( !bank ) ) {
    FD_LOG_CRIT(( "invariant violation: bank is NULL for bank index %lu", bank_idx ));
  }
  fd_bank_slot_set( bank, slot );
  fd_bank_parent_slot_set( bank, parent_slot );
  bank->txncache_fork_id = fd_txncache_attach_child( ctx->txncache, parent_bank->txncache_fork_id );

  /* Create a new funk txn for the block. */

  fd_funk_txn_xid_t xid        = { .ul = { slot, bank_idx } };
  fd_funk_txn_xid_t parent_xid = { .ul = { parent_slot, parent_bank_idx } };
  fd_accdb_attach_child( ctx->accdb_admin, &parent_xid, &xid );
  fd_progcache_txn_attach_child( ctx->progcache_admin, &parent_xid, &xid );

  /* Update any required runtime state and handle any potential epoch
     boundary change. */

  if( ctx->capture_ctx ) {
    fd_solcap_writer_set_slot( ctx->capture_ctx->capture, slot );
  }

  fd_bank_shred_cnt_set( bank, 0UL );
  fd_bank_execution_fees_set( bank, 0UL );
  fd_bank_priority_fees_set( bank, 0UL );

  fd_bank_has_identity_vote_set( bank, 0 );

  /* Set the tick height. */
  fd_bank_tick_height_set( bank, fd_bank_max_tick_height_get( bank ) );

  /* Update block height. */
  fd_bank_block_height_set( bank, fd_bank_block_height_get( bank ) + 1UL );

  ulong * max_tick_height = fd_bank_max_tick_height_modify( bank );
  ulong   ticks_per_slot  = fd_bank_ticks_per_slot_get( bank );
  if( FD_UNLIKELY( FD_RUNTIME_EXECUTE_SUCCESS != fd_runtime_compute_max_tick_height( ticks_per_slot, slot, max_tick_height ) ) ) {
    FD_LOG_CRIT(( "couldn't compute tick height/max tick height slot %lu ticks_per_slot %lu", slot, ticks_per_slot ));
  }

  int is_epoch_boundary = 0;
  fd_runtime_block_pre_execute_process_new_epoch(
      ctx->banks,
      bank,
      ctx->accdb,
      &xid,
      ctx->capture_ctx,
      &ctx->runtime_stack,
      &is_epoch_boundary );
  if( FD_UNLIKELY( is_epoch_boundary ) ) publish_stake_weights( ctx, stem, bank, 1 );

  FD_TEST( !fd_runtime_block_execute_prepare( bank, ctx->accdb, &xid, &ctx->runtime_stack, ctx->capture_ctx ) );
  return bank;
}

static void
publish_slot_completed( fd_replay_tile_t *  ctx,
                        fd_stem_context_t * stem,
                        fd_bank_t *         bank,
                        int                 is_initial ) {

  ulong slot = fd_bank_slot_get( bank );

  fd_block_id_ele_t * block_id_ele = &ctx->block_id_arr[ bank->idx ];

  /* HACKY: hacky way of checking if we should send a null parent block
     id */
  fd_hash_t parent_block_id = {0};
  if( FD_UNLIKELY( !is_initial ) ) {
    parent_block_id = ctx->block_id_arr[ bank->parent_idx ].block_id;
  }

  fd_hash_t const * bank_hash  = fd_bank_bank_hash_query( bank );
  fd_hash_t const * block_hash = fd_blockhashes_peek_last( fd_bank_block_hash_queue_query( bank ) );
  FD_TEST( bank_hash  );
  FD_TEST( block_hash );

  if( FD_LIKELY( !is_initial ) ) fd_txncache_finalize_fork( ctx->txncache, bank->txncache_fork_id, 0UL, block_hash->uc );

  fd_epoch_schedule_t const * epoch_schedule = fd_bank_epoch_schedule_query( bank );
  ulong slot_idx;
  ulong epoch = fd_slot_to_epoch( epoch_schedule, slot, &slot_idx );

  ctx->metrics.slots_total++;
  ctx->metrics.transactions_total = fd_bank_txn_count_get( bank );

  fd_replay_slot_completed_t * slot_info = fd_chunk_to_laddr( ctx->replay_out->mem, ctx->replay_out->chunk );
  slot_info->slot                  = slot;
  slot_info->root_slot             = ctx->consensus_root_slot;
  slot_info->epoch                 = epoch;
  slot_info->slot_in_epoch         = slot_idx;
  slot_info->block_height          = fd_bank_block_height_get( bank );
  slot_info->parent_slot           = fd_bank_parent_slot_get( bank );
  slot_info->block_id              = block_id_ele->block_id;
  slot_info->parent_block_id       = parent_block_id;
  slot_info->bank_hash             = *bank_hash;
  slot_info->block_hash            = *block_hash;
  slot_info->transaction_count     = fd_bank_txn_count_get( bank );

  slot_info->first_fec_set_received_nanos      = bank->first_fec_set_received_nanos;
  slot_info->preparation_begin_nanos           = bank->preparation_begin_nanos;
  slot_info->first_transaction_scheduled_nanos = bank->first_transaction_scheduled_nanos;
  slot_info->last_transaction_finished_nanos   = bank->last_transaction_finished_nanos;
  slot_info->completion_time_nanos             = fd_log_wallclock();

  /* refcnt should be incremented by 1 for each consumer that uses
     `bank_idx`.  Each consumer should decrement the bank's refcnt once
     they are done usin the bank. */
  if( FD_LIKELY( ctx->gui_enabled ) ) bank->refcnt++; /* gui tile */
  slot_info->bank_idx = bank->idx;

  slot_info->parent_bank_idx = ULONG_MAX;
  fd_bank_t * parent_bank = fd_banks_get_parent( ctx->banks, bank );
  if( FD_LIKELY( parent_bank && ctx->gui_enabled ) ) {
    parent_bank->refcnt++;
    slot_info->parent_bank_idx = parent_bank->idx;
  }

  fd_stem_publish( stem, ctx->replay_out->idx, REPLAY_SIG_SLOT_COMPLETED, ctx->replay_out->chunk, sizeof(fd_replay_slot_completed_t), 0UL, 0UL, fd_frag_meta_ts_comp( fd_tickcount() ) );
  ctx->replay_out->chunk = fd_dcache_compact_next( ctx->replay_out->chunk, sizeof(fd_replay_slot_completed_t), ctx->replay_out->chunk0, ctx->replay_out->wmark );
}

static void
replay_block_finalize( fd_replay_tile_t *  ctx,
                       fd_stem_context_t * stem,
                       fd_bank_t *         bank ) {

  bank->last_transaction_finished_nanos = fd_log_wallclock();

  if( FD_UNLIKELY( ctx->capture_ctx ) ) fd_solcap_writer_flush( ctx->capture_ctx->capture );

  FD_TEST( !(bank->flags&FD_BANK_FLAGS_FROZEN) );

  ulong             slot = fd_bank_slot_get( bank );
  fd_funk_txn_xid_t xid  = { .ul = { slot, bank->idx } };

  /* Set poh hash in bank. */
  fd_hash_t * poh = fd_sched_get_poh( ctx->sched, bank->idx );
  fd_bank_poh_set( bank, *poh );

  /* Set shred count in bank. */
  fd_bank_shred_cnt_set( bank, fd_sched_get_shred_cnt( ctx->sched, bank->idx ) );

  /* Do hashing and other end-of-block processing. */
  fd_runtime_block_execute_finalize( bank, ctx->accdb, &xid, ctx->capture_ctx, 1 );

  /* Mark the bank as frozen. */
  fd_banks_mark_bank_frozen( ctx->banks, bank );

  /* Copy the vote tower of all the vote accounts into the buffer,
     which will be published in after_credit. */
  buffer_vote_towers( ctx, &xid, bank );

  /**********************************************************************/
  /* Bank hash comparison, and halt if there's a mismatch after replay  */
  /**********************************************************************/

  fd_hash_t const * bank_hash = fd_bank_bank_hash_query( bank );
  FD_TEST( bank_hash );

  fd_bank_hash_cmp_t * bank_hash_cmp = ctx->bank_hash_cmp;
  fd_bank_hash_cmp_lock( bank_hash_cmp );
  fd_bank_hash_cmp_insert( bank_hash_cmp, fd_bank_slot_get( bank ), bank_hash, 1, 0 );

  /* Try to move the bank hash comparison watermark forward */
  for( ulong cmp_slot = bank_hash_cmp->watermark + 1; cmp_slot < fd_bank_slot_get( bank ); cmp_slot++ ) {
    if( FD_UNLIKELY( !ctx->enable_bank_hash_cmp ) ) {
      bank_hash_cmp->watermark = cmp_slot;
      break;
    }
    int rc = fd_bank_hash_cmp_check( bank_hash_cmp, cmp_slot );
    switch ( rc ) {
      case -1:
        /* Mismatch */
        FD_LOG_CRIT(( "Bank hash mismatch on slot: %lu. Halting.", cmp_slot ));
        break;
      case 0:
        /* Not ready */
        break;
      case 1:
        /* Match*/
        bank_hash_cmp->watermark = cmp_slot;
        break;
      default:;
    }
  }

  fd_bank_hash_cmp_unlock( bank_hash_cmp );

  /* Must be last so we can measure completion time correctly, even
     though we could technically do this before the hash cmp and vote
     tower stuff. */
  publish_slot_completed( ctx, stem, bank, 0 );

  /* If enabled, dump the block to a file and reset the dumping
     context state */
  if( FD_UNLIKELY( ctx->capture_ctx && ctx->capture_ctx->dump_block_to_pb ) ) {
    fd_dump_block_to_protobuf( ctx->block_dump_ctx, ctx->banks, bank, ctx->accdb->funk, ctx->capture_ctx );
    fd_block_dump_context_reset( ctx->block_dump_ctx );
  }
}

/**********************************************************************/
/* Leader bank management                                             */
/**********************************************************************/

static fd_bank_t *
prepare_leader_bank( fd_replay_tile_t *  ctx,
                     ulong               slot,
                     long                now,
                     fd_hash_t const *   parent_block_id,
                     fd_stem_context_t * stem ) {
  long before = fd_log_wallclock();

  /* Make sure that we are not already leader. */
  FD_TEST( ctx->leader_bank==NULL );

  fd_block_id_ele_t * parent_ele = fd_block_id_map_ele_query( ctx->block_id_map, parent_block_id, NULL, ctx->block_id_arr );
  if( FD_UNLIKELY( !parent_ele ) ) {
    FD_LOG_CRIT(( "invariant violation: parent bank index not found for merkle root %s", FD_BASE58_ENC_32_ALLOCA( parent_block_id->uc ) ));
  }
  ulong parent_bank_idx = fd_block_id_ele_get_idx( ctx->block_id_arr, parent_ele );

  fd_bank_t * parent_bank = fd_banks_bank_query( ctx->banks, parent_bank_idx );
  if( FD_UNLIKELY( !parent_bank ) ) {
    FD_LOG_CRIT(( "invariant violation: parent bank not found for bank index %lu", parent_bank_idx ));
  }
  ulong parent_slot = fd_bank_slot_get( parent_bank );

  ctx->leader_bank = fd_banks_new_bank( ctx->banks, parent_bank_idx, now );
  if( FD_UNLIKELY( !ctx->leader_bank ) ) {
    FD_LOG_CRIT(( "invariant violation: leader bank is NULL for slot %lu", slot ));
  }

  if( FD_UNLIKELY( !fd_banks_clone_from_parent( ctx->banks, ctx->leader_bank->idx, parent_bank_idx ) ) ) {
    FD_LOG_CRIT(( "invariant violation: bank is NULL for slot %lu", slot ));
  }

  ctx->leader_bank->preparation_begin_nanos = before;

  fd_bank_slot_set( ctx->leader_bank, slot );
  fd_bank_parent_slot_set( ctx->leader_bank, parent_slot );
  ctx->leader_bank->txncache_fork_id = fd_txncache_attach_child( ctx->txncache, parent_bank->txncache_fork_id );
  /* prepare the funk transaction for the leader bank */
  fd_funk_txn_xid_t xid        = { .ul = { slot, ctx->leader_bank->idx } };
  fd_funk_txn_xid_t parent_xid = { .ul = { parent_slot, parent_bank_idx } };
  fd_accdb_attach_child( ctx->accdb_admin, &parent_xid, &xid );
  fd_progcache_txn_attach_child( ctx->progcache_admin, &parent_xid, &xid );

  fd_bank_execution_fees_set( ctx->leader_bank, 0UL );
  fd_bank_priority_fees_set( ctx->leader_bank, 0UL );
  fd_bank_shred_cnt_set( ctx->leader_bank, 0UL );

  /* Set the tick height. */
  fd_bank_tick_height_set( ctx->leader_bank, fd_bank_max_tick_height_get( ctx->leader_bank ) );

  /* Update block height. */
  fd_bank_block_height_set( ctx->leader_bank, fd_bank_block_height_get( ctx->leader_bank ) + 1UL );

  ulong * max_tick_height = fd_bank_max_tick_height_modify( ctx->leader_bank );
  ulong   ticks_per_slot  = fd_bank_ticks_per_slot_get( ctx->leader_bank );
  if( FD_UNLIKELY( FD_RUNTIME_EXECUTE_SUCCESS != fd_runtime_compute_max_tick_height( ticks_per_slot, slot, max_tick_height ) ) ) {
    FD_LOG_CRIT(( "couldn't compute tick height/max tick height slot %lu ticks_per_slot %lu", slot, ticks_per_slot ));
  }

  int is_epoch_boundary = 0;
  fd_runtime_block_pre_execute_process_new_epoch(
      ctx->banks,
      ctx->leader_bank,
      ctx->accdb,
      &xid,
      ctx->capture_ctx,
      &ctx->runtime_stack,
      &is_epoch_boundary );
  if( FD_UNLIKELY( is_epoch_boundary ) ) publish_stake_weights( ctx, stem, ctx->leader_bank, 1 );

  FD_TEST( !fd_runtime_block_execute_prepare( ctx->leader_bank, ctx->accdb, &xid, &ctx->runtime_stack, ctx->capture_ctx ) );

  /* Now that a bank has been created for the leader slot, increment the
     reference count until we are done with the leader slot. */
  ctx->leader_bank->refcnt++;

  return ctx->leader_bank;
}

static void
fini_leader_bank( fd_replay_tile_t *  ctx,
                  fd_stem_context_t * stem ) {

  FD_TEST( ctx->leader_bank!=NULL );
  FD_TEST( ctx->is_leader );
  FD_TEST( ctx->recv_block_id );
  FD_TEST( ctx->recv_poh );

  ctx->leader_bank->last_transaction_finished_nanos = fd_log_wallclock();

  fd_banks_mark_bank_frozen( ctx->banks, ctx->leader_bank );

  ulong curr_slot = fd_bank_slot_get( ctx->leader_bank );

  fd_sched_block_add_done( ctx->sched, ctx->leader_bank->idx, ctx->leader_bank->parent_idx, curr_slot );

  /* Do hashing and other end-of-block processing */
  fd_funk_txn_map_t * txn_map = fd_funk_txn_map( ctx->accdb->funk );
  if( FD_UNLIKELY( !txn_map->map ) ) {
    FD_LOG_ERR(( "Could not find valid funk transaction map" ));
  }
  fd_funk_txn_xid_t xid = { .ul = { curr_slot, ctx->leader_bank->idx } };

  fd_runtime_block_execute_finalize( ctx->leader_bank, ctx->accdb, &xid, ctx->capture_ctx, 0 );

  fd_hash_t const * bank_hash  = fd_bank_bank_hash_query( ctx->leader_bank );
  FD_TEST( bank_hash );

  fd_bank_hash_cmp_t * bank_hash_cmp = ctx->bank_hash_cmp;
  fd_bank_hash_cmp_lock( bank_hash_cmp );
  fd_bank_hash_cmp_insert( bank_hash_cmp, curr_slot, bank_hash, 1, 0 );

  /* Try to move the bank hash comparison watermark forward */
  for( ulong cmp_slot = bank_hash_cmp->watermark + 1; cmp_slot < curr_slot; cmp_slot++ ) {
    if( FD_UNLIKELY( !ctx->enable_bank_hash_cmp ) ) {
      bank_hash_cmp->watermark = cmp_slot;
      break;
    }
    int rc = fd_bank_hash_cmp_check( bank_hash_cmp, cmp_slot );
    switch ( rc ) {
      case -1:
        /* Mismatch */
        FD_LOG_WARNING(( "Bank hash mismatch on slot: %lu. Halting.", cmp_slot ));
        break;
      case 0:
        /* Not ready */
        break;
      case 1:
        /* Match*/
        bank_hash_cmp->watermark = cmp_slot;
        break;
      default:;
    }
  }

  fd_bank_hash_cmp_unlock( bank_hash_cmp );

  publish_slot_completed( ctx, stem, ctx->leader_bank, 0 );

  /* Copy the vote tower of all the vote accounts into the buffer,
      which will be published in after_credit. */
  buffer_vote_towers( ctx, &xid, ctx->leader_bank );

  /* The reference on the bank is finally no longer needed. */
  ctx->leader_bank->refcnt--;

  /* We are no longer leader so we can clear the bank index we use for
     being the leader. */
  ctx->leader_bank   = NULL;
  ctx->recv_block_id = 0;
  ctx->recv_poh      = 0;
  ctx->is_leader     = 0;
}

static void
publish_root_advanced( fd_replay_tile_t *  ctx,
                       fd_stem_context_t * stem ) {

  /* FIXME: for now we want to send the child of the consensus root to
     avoid data races with funk root advancing.  This is a temporary
     hack because currently it is not safe to query against the xid for
     the root that is being advanced in funk.  This doesn't eliminate
     the data race that exists in funk, but reduces how often it occurs.

     Case that causes a data race:
     replay: we are advancing the root from slot A->B
     resolv: we are resolving ALUTs against slot B */

  fd_bank_t * consensus_root_bank = fd_banks_bank_query( ctx->banks, ctx->consensus_root_bank_idx );
  if( FD_UNLIKELY( !consensus_root_bank ) ) {
    FD_LOG_CRIT(( "invariant violation: consensus root bank is NULL at bank index %lu", ctx->consensus_root_bank_idx ));
  }

  if( FD_UNLIKELY( consensus_root_bank->child_idx==ULONG_MAX ) ) {
    return;
  }

  fd_bank_t * bank = fd_banks_bank_query( ctx->banks, consensus_root_bank->child_idx );
  if( FD_UNLIKELY( !bank ) ) {
    FD_LOG_CRIT(( "invariant violation: consensus root bank child is NULL at bank index %lu", consensus_root_bank->child_idx ));
  }

  /* Increment the reference count on the consensus root bank to account
     for the number of exec tiles that are waiting on it. */
  bank->refcnt += ctx->resolv_tile_cnt;

  fd_replay_root_advanced_t * msg = fd_chunk_to_laddr( ctx->replay_out->mem, ctx->replay_out->chunk );
  msg->bank_idx = bank->idx;
  msg->block_height = fd_bank_block_height_get( bank );

  fd_stem_publish( stem, ctx->replay_out->idx, REPLAY_SIG_ROOT_ADVANCED, ctx->replay_out->chunk, sizeof(fd_replay_root_advanced_t), 0UL, 0UL, fd_frag_meta_ts_comp( fd_tickcount() ) );
  ctx->replay_out->chunk = fd_dcache_compact_next( ctx->replay_out->chunk, sizeof(fd_replay_root_advanced_t), ctx->replay_out->chunk0, ctx->replay_out->wmark );
}

/* init_funk performs pre-flight checks for the account database and
   program cache.  Ensures that the account database was set up
   correctly by bootstrap components (e.g. genesis or snapshot loader).
   Mirrors the account database's fork tree down to the program cache. */

static void
init_funk( fd_replay_tile_t * ctx,
           ulong              bank_slot ) {
  /* Ensure that the loaded bank root corresponds to the account
     database's root. */
  fd_funk_t * funk = ctx->accdb_admin->funk;
  if( FD_UNLIKELY( !funk->shmem ) ) {
    FD_LOG_CRIT(( "failed to initialize account database: replay tile is not joined to database shared memory objects" ));
  }
  fd_funk_txn_xid_t const * accdb_pub = fd_funk_last_publish( funk );
  if( FD_UNLIKELY( accdb_pub->ul[0]!=bank_slot ) ) {
    FD_LOG_CRIT(( "failed to initialize account database: accdb is at slot %lu, but chain state is at slot %lu\n"
                  "This is a bug in startup components.",
                  accdb_pub->ul[0], bank_slot ));
  }
  if( FD_UNLIKELY( fd_funk_last_publish_is_frozen( funk ) ) ) {
    FD_LOG_CRIT(( "failed to initialize account database: accdb fork graph is not clean.\n"
                  "The account database should only contain state for the root slot at this point,\n"
                  "but there are incomplete database transactions leftover.\n"
                  "This is a bug in startup components."  ));
  }

  /* The program cache tracks the account database's fork graph at all
     times.  Perform initial synchronization: pivot from funk 'root' (a
     sentinel XID) to 'last publish' (the bootstrap root slot). */
  if( FD_UNLIKELY( !ctx->progcache_admin->funk->shmem ) ) {
    FD_LOG_CRIT(( "failed to initialize account database: replay tile is not joined to program cache" ));
  }
  fd_progcache_clear( ctx->progcache_admin );
  fd_progcache_txn_attach_child( ctx->progcache_admin, fd_funk_root( ctx->progcache_admin->funk ), fd_funk_last_publish( ctx->accdb->funk ) );
  fd_progcache_txn_advance_root( ctx->progcache_admin,                                             fd_funk_last_publish( ctx->accdb->funk ) );
}

static void
init_after_snapshot( fd_replay_tile_t * ctx ) {
  /* Now that the snapshot has been loaded in, we have to refresh the
     stake delegations since the manifest does not contain the full set
     of data required for the stake delegations. See
     fd_stake_delegations.h for why this is required. */

  fd_bank_t * bank = fd_banks_bank_query( ctx->banks, FD_REPLAY_BOOT_BANK_IDX );
  if( FD_UNLIKELY( !bank ) ) {
    FD_LOG_CRIT(( "invariant violation: replay bank is NULL at bank index %lu", FD_REPLAY_BOOT_BANK_IDX ));
  }

  fd_funk_txn_xid_t xid = { .ul = { fd_bank_slot_get( bank ), bank->idx } };
  init_funk( ctx, fd_bank_slot_get( bank ) );

  fd_stake_delegations_t * root_delegations = fd_banks_stake_delegations_root_query( ctx->banks );

  fd_stake_delegations_refresh( root_delegations, ctx->accdb->funk, &xid );

  /* After both snapshots have been loaded in, we can determine if we should
     start distributing rewards. */

  fd_rewards_recalculate_partitioned_rewards( ctx->banks, bank, ctx->accdb->funk, &xid, &ctx->runtime_stack, ctx->capture_ctx );

  ulong snapshot_slot = fd_bank_slot_get( bank );
  if( FD_UNLIKELY( !snapshot_slot ) ) {
    /* Genesis-specific setup. */
    /* FIXME: This branch does not set up a new block exec ctx
       properly. Needs to do whatever prepare_new_block_execution
       does, but just hacking that in breaks stuff. */
    fd_runtime_update_leaders( bank, &ctx->runtime_stack );

    ulong hashcnt_per_slot = fd_bank_hashes_per_tick_get( bank ) * fd_bank_ticks_per_slot_get( bank );
    fd_hash_t * poh = fd_bank_poh_modify( bank );
    while( hashcnt_per_slot-- ) {
      fd_sha256_hash( poh->hash, 32UL, poh->hash );
    }

    FD_TEST( !fd_runtime_block_execute_prepare( bank, ctx->accdb, &xid, &ctx->runtime_stack, ctx->capture_ctx ) );
    fd_runtime_block_execute_finalize( bank, ctx->accdb, &xid, ctx->capture_ctx, 1 );

    snapshot_slot = 0UL;
  }

  /* Initialize consensus structures post-snapshot */

  fd_vote_states_t const * vote_states = fd_bank_vote_states_locking_query( bank );

  fd_bank_hash_cmp_t * bank_hash_cmp = ctx->bank_hash_cmp;

  fd_vote_states_iter_t iter_[1];
  for( fd_vote_states_iter_t * iter = fd_vote_states_iter_init( iter_, vote_states ); !fd_vote_states_iter_done( iter ); fd_vote_states_iter_next( iter ) ) {
    fd_vote_state_ele_t const * vote_state = fd_vote_states_iter_ele( iter );
    bank_hash_cmp->total_stake += vote_state->stake;
  }
  bank_hash_cmp->watermark = snapshot_slot;

  fd_bank_vote_states_end_locking_query( bank );

  if( FD_UNLIKELY( ctx->capture_ctx ) ) fd_solcap_writer_flush( ctx->capture_ctx->capture );
}

static inline int
maybe_become_leader( fd_replay_tile_t *  ctx,
                     fd_stem_context_t * stem ) {
  FD_TEST( ctx->is_booted );
  if( FD_LIKELY( ctx->next_leader_slot==ULONG_MAX || ctx->is_leader || !ctx->has_identity_vote_rooted || ctx->replay_out->idx==ULONG_MAX ) ) return 0;

  FD_TEST( ctx->next_leader_slot>ctx->reset_slot );
  long now = fd_tickcount();
  if( FD_LIKELY( now<ctx->next_leader_tickcount ) ) return 0;

  /* TODO:
  if( FD_UNLIKELY( ctx->halted_switching_key ) ) return 0; */

  /* If a prior leader is still in the process of publishing their slot,
     delay ours to let them finish ... unless they are so delayed that
     we risk getting skipped by the leader following us.  1.2 seconds
     is a reasonable default here, although any value between 0 and 1.6
     seconds could be considered reasonable.  This is arbitrary and
     chosen due to intuition. */
  if( FD_UNLIKELY( now<ctx->next_leader_tickcount+(long)(3.0*ctx->slot_duration_ticks) ) ) {
    FD_TEST( ctx->reset_bank );

    /* TODO: Make the max_active_descendant calculation more efficient
       by caching it in the bank structure and updating it as banks are
       created and completed. */
    ulong max_active_descendant = 0UL;
    ulong child_idx = ctx->reset_bank->child_idx;
    while( child_idx!=ULONG_MAX ) {
      fd_bank_t const * child_bank = fd_banks_bank_query( ctx->banks, child_idx );
      max_active_descendant = fd_ulong_max( max_active_descendant, fd_bank_slot_get( child_bank ) );
      child_idx = child_bank->sibling_idx;
    }

    /* If the max_active_descendant is >= next_leader_slot, we waited
       too long and a leader after us started publishing to try and skip
       us.  Just start our leader slot immediately, we might win ... */
    if( FD_LIKELY( max_active_descendant>=ctx->reset_slot && max_active_descendant<ctx->next_leader_slot ) ) {
      /* If one of the leaders between the reset slot and our leader
         slot is in the process of publishing (they have a descendant
         bank that is in progress of being replayed), then keep waiting.
         We probably wouldn't get a leader slot out before they
         finished.

         Unless... we are past the deadline to start our slot by more
         than 1.2 seconds, in which case we should probably start it to
         avoid getting skipped by the leader behind us. */
      return 0;
    }
  }

  long now_nanos = fd_log_wallclock();

  ctx->is_leader     = 1;
  ctx->recv_poh      = 0;
  ctx->recv_block_id = 0;

  FD_TEST( ctx->highwater_leader_slot==ULONG_MAX || ctx->highwater_leader_slot<ctx->next_leader_slot );
  ctx->highwater_leader_slot = ctx->next_leader_slot;

  FD_LOG_INFO(( "becoming leader for slot %lu, parent slot is %lu", ctx->next_leader_slot, ctx->reset_slot ));

  /* Acquires bank, sets up initial state, and refcnts it. */
  fd_bank_t * bank = prepare_leader_bank( ctx, ctx->next_leader_slot, now_nanos, &ctx->reset_block_id, stem );

  fd_became_leader_t * msg = fd_chunk_to_laddr( ctx->replay_out->mem, ctx->replay_out->chunk );
  msg->slot = ctx->next_leader_slot;
  msg->slot_start_ns = now_nanos;
  msg->slot_end_ns   = now_nanos+(long)ctx->slot_duration_nanos;
  msg->bank = NULL;
  msg->bank_idx = bank->idx;
  msg->ticks_per_slot = fd_bank_ticks_per_slot_get( bank );
  msg->hashcnt_per_tick = fd_bank_hashes_per_tick_get( bank );
  msg->tick_duration_ns = (ulong)(ctx->slot_duration_nanos/(double)msg->ticks_per_slot);

  if( FD_UNLIKELY( msg->hashcnt_per_tick==1UL ) ) {
    /* Low power producer, maximum of one microblock per tick in the slot */
    msg->max_microblocks_in_slot = msg->ticks_per_slot;
  } else {
    /* See the long comment in after_credit for this limit */
    msg->max_microblocks_in_slot = fd_ulong_min( MAX_MICROBLOCKS_PER_SLOT, msg->ticks_per_slot*(msg->hashcnt_per_tick-1UL) );
  }

  msg->total_skipped_ticks = msg->ticks_per_slot*(ctx->next_leader_slot-ctx->reset_slot);
  msg->epoch = fd_slot_to_epoch( fd_bank_epoch_schedule_query( bank ), ctx->next_leader_slot, NULL );
  fd_memset( msg->bundle, 0, sizeof(msg->bundle) );

  fd_cost_tracker_t const * cost_tracker = fd_bank_cost_tracker_locking_query( bank );

  msg->limits.slot_max_cost = cost_tracker->block_cost_limit;
  msg->limits.slot_max_vote_cost = cost_tracker->vote_cost_limit;
  msg->limits.slot_max_write_cost_per_acct = cost_tracker->account_cost_limit;

  fd_bank_cost_tracker_end_locking_query( bank );

  if( FD_UNLIKELY( msg->ticks_per_slot+msg->total_skipped_ticks>USHORT_MAX ) ) {
    /* There can be at most USHORT_MAX skipped ticks, because the
       parent_offset field in the shred data is only 2 bytes wide. */
    FD_LOG_ERR(( "too many skipped ticks %lu for slot %lu, chain must halt", msg->ticks_per_slot+msg->total_skipped_ticks, ctx->next_leader_slot ));
  }

  fd_stem_publish( stem, ctx->replay_out->idx, REPLAY_SIG_BECAME_LEADER, ctx->replay_out->chunk, sizeof(fd_became_leader_t), 0UL, 0UL, fd_frag_meta_ts_comp( fd_tickcount() ) );
  ctx->replay_out->chunk = fd_dcache_compact_next( ctx->replay_out->chunk, sizeof(fd_became_leader_t), ctx->replay_out->chunk0, ctx->replay_out->wmark );

  ctx->next_leader_slot = ULONG_MAX;
  ctx->next_leader_tickcount = LONG_MAX;

  return 1;
}

static void
process_poh_message( fd_replay_tile_t *                 ctx,
                     fd_poh_leader_slot_ended_t const * slot_ended ) {

  FD_TEST( ctx->is_booted );
  FD_TEST( ctx->is_leader );
  FD_TEST( ctx->leader_bank!=NULL );

  FD_TEST( ctx->highwater_leader_slot>=slot_ended->slot );
  FD_TEST( ctx->next_leader_slot>ctx->highwater_leader_slot );

  /* Update the poh hash in the bank.  We will want to maintain a refcnt
     on the bank until we have recieved the block id for the block after
     it has been shredded. */

  memcpy( fd_bank_poh_modify( ctx->leader_bank ), slot_ended->blockhash, sizeof(fd_hash_t) );

  ctx->recv_poh = 1;
}

static void
publish_reset( fd_replay_tile_t *  ctx,
               fd_stem_context_t * stem,
               fd_bank_t const *   bank ) {
  if( FD_UNLIKELY( ctx->replay_out->idx==ULONG_MAX ) ) return;

  fd_hash_t const * block_hash = fd_blockhashes_peek_last( fd_bank_block_hash_queue_query( bank ) );
  FD_TEST( block_hash );

  fd_poh_reset_t * reset = fd_chunk_to_laddr( ctx->replay_out->mem, ctx->replay_out->chunk );

  reset->timestamp        = fd_log_wallclock();
  reset->completed_slot   = fd_bank_slot_get( bank );
  reset->hashcnt_per_tick = fd_bank_hashes_per_tick_get( bank );
  reset->ticks_per_slot   = fd_bank_ticks_per_slot_get( bank );
  reset->tick_duration_ns = (ulong)(ctx->slot_duration_nanos/(double)reset->ticks_per_slot);
  fd_memcpy( reset->completed_blockhash, block_hash->uc, sizeof(fd_hash_t) );

  ulong ticks_per_slot = fd_bank_ticks_per_slot_get( bank );
  if( FD_UNLIKELY( reset->hashcnt_per_tick==1UL ) ) {
    /* Low power producer, maximum of one microblock per tick in the slot */
    reset->max_microblocks_in_slot = ticks_per_slot;
  } else {
    /* See the long comment in after_credit for this limit */
    reset->max_microblocks_in_slot = fd_ulong_min( MAX_MICROBLOCKS_PER_SLOT, ticks_per_slot*(reset->hashcnt_per_tick-1UL) );
  }
  reset->next_leader_slot = ctx->next_leader_slot;

  fd_stem_publish( stem, ctx->replay_out->idx, REPLAY_SIG_RESET, ctx->replay_out->chunk, sizeof(fd_poh_reset_t), 0UL, 0UL, fd_frag_meta_ts_comp( fd_tickcount() ) );
  ctx->replay_out->chunk = fd_dcache_compact_next( ctx->replay_out->chunk, sizeof(fd_poh_reset_t), ctx->replay_out->chunk0, ctx->replay_out->wmark );
}

static void
boot_genesis( fd_replay_tile_t *  ctx,
              fd_stem_context_t * stem,
              ulong               in_idx,
              ulong               chunk ) {
  /* If we are bootstrapping, we can't wait to wait for our identity
     vote to be rooted as this creates a circular dependency. */
  ctx->has_identity_vote_rooted = 1;

  uchar const * lthash       = (uchar*)fd_chunk_to_laddr( ctx->in[ in_idx ].mem, chunk );
  uchar const * genesis_hash = (uchar*)fd_chunk_to_laddr( ctx->in[ in_idx ].mem, chunk )+sizeof(fd_lthash_value_t);

  // TODO: Do not pass the fd_types type between tiles, it have offsets
  // that are unsafe and can't be validated as being in-bounds.  Need to
  // pass an actual owned genesis type.
  fd_genesis_solana_global_t const * genesis = fd_type_pun( (uchar*)fd_chunk_to_laddr( ctx->in[ in_idx ].mem, chunk )+sizeof(fd_hash_t)+sizeof(fd_lthash_value_t) );

  fd_bank_t * bank = fd_banks_bank_query( ctx->banks, FD_REPLAY_BOOT_BANK_IDX );
  FD_TEST( bank );
  fd_funk_txn_xid_t xid = { .ul = { 0UL, FD_REPLAY_BOOT_BANK_IDX } };

  /* Do genesis-related processing in a non-rooted transaction */
  fd_funk_txn_xid_t root_xid; fd_funk_txn_xid_set_root( &root_xid );
  fd_funk_txn_xid_t target_xid = { .ul = { 0UL, 0UL } };
  fd_accdb_attach_child( ctx->accdb_admin, &root_xid, &target_xid );
  fd_runtime_read_genesis( ctx->banks, bank, ctx->accdb, &xid, NULL, fd_type_pun_const( genesis_hash ), fd_type_pun_const( lthash ), genesis, &ctx->runtime_stack );
  fd_accdb_advance_root( ctx->accdb_admin, &target_xid );

  static const fd_txncache_fork_id_t txncache_root = { .val = USHORT_MAX };
  bank->txncache_fork_id = fd_txncache_attach_child( ctx->txncache, txncache_root );

  fd_hash_t const * block_hash = fd_blockhashes_peek_last( fd_bank_block_hash_queue_query( bank ) );
  fd_txncache_finalize_fork( ctx->txncache, bank->txncache_fork_id, 0UL, block_hash->uc );

  publish_stake_weights( ctx, stem, bank, 0 );
  publish_stake_weights( ctx, stem, bank, 1 );

  /* We call this after fd_runtime_read_genesis, which sets up the
     slot_bank needed in blockstore_init. */
  init_after_snapshot( ctx );

  /* Initialize store for genesis case, similar to snapshot case */
  fd_hash_t genesis_block_id = { .ul[0] = FD_RUNTIME_INITIAL_BLOCK_ID };
  fd_store_exacq( ctx->store );
  if( FD_UNLIKELY( fd_store_root( ctx->store ) ) ) {
    FD_LOG_CRIT(( "invariant violation: store root is not 0 for genesis" ));
  }
  fd_store_insert( ctx->store, 0, &genesis_block_id );
  ctx->store->slot0 = 0UL; /* Genesis slot */
  fd_store_exrel( ctx->store );

  ctx->published_root_slot = 0UL;
  fd_sched_block_add_done( ctx->sched, bank->idx, ULONG_MAX, 0UL );

  fd_bank_block_height_set( bank, 1UL );

  ctx->consensus_root          = (fd_hash_t){ .ul[0] = FD_RUNTIME_INITIAL_BLOCK_ID };
  ctx->consensus_root_slot     = 0UL;
  ctx->consensus_root_bank_idx = 0UL;
  ctx->published_root_slot     = 0UL;
  ctx->published_root_bank_idx = 0UL;

  ctx->reset_slot            = 0UL;
  ctx->reset_bank            = bank;
  ctx->reset_timestamp_nanos = fd_log_wallclock();
  ctx->next_leader_slot      = fd_multi_epoch_leaders_get_next_slot( ctx->mleaders, 1UL, ctx->identity_pubkey );
  if( FD_LIKELY( ctx->next_leader_slot ) ) {
    ctx->next_leader_tickcount = (long)((double)(ctx->next_leader_slot-ctx->reset_slot-1UL)*ctx->slot_duration_ticks) + fd_tickcount();
  } else {
    ctx->next_leader_tickcount = LONG_MAX;
  }

  ctx->is_booted = 1;
  maybe_become_leader( ctx, stem );

  fd_hash_t initial_block_id = { .ul = { FD_RUNTIME_INITIAL_BLOCK_ID } };
  fd_reasm_fec_t * fec       = fd_reasm_insert( ctx->reasm, &initial_block_id, NULL, 0 /* genesis slot */, 0, 0, 0, 0, 1, 0 ); /* FIXME manifest block_id */
  fec->bank_idx              = 0UL;


  fd_block_id_ele_t * block_id_ele = &ctx->block_id_arr[ 0 ];
  FD_TEST( block_id_ele );
  block_id_ele->block_id = initial_block_id;
  block_id_ele->slot     = 0UL;

  FD_TEST( fd_block_id_map_ele_insert( ctx->block_id_map, block_id_ele, ctx->block_id_arr ) );

  publish_slot_completed( ctx, stem, bank, 1 );
  publish_root_advanced( ctx, stem );
  publish_reset( ctx, stem, bank );
}

static void
on_snapshot_message( fd_replay_tile_t *  ctx,
                     fd_stem_context_t * stem,
                     ulong               in_idx,
                     ulong               chunk,
                     ulong               sig ) {
  ulong msg = fd_ssmsg_sig_message( sig );
  if( FD_LIKELY( msg==FD_SSMSG_DONE ) ) {
    /* An end of message notification indicates the snapshot is loaded.
       Replay is able to start executing from this point onwards. */
    /* TODO: replay should finish booting. Could make replay a
       state machine and set the state here accordingly. */
    ctx->is_booted = 1;

    fd_bank_t * bank = fd_banks_bank_query( ctx->banks, FD_REPLAY_BOOT_BANK_IDX );
    if( FD_UNLIKELY( !bank ) ) {
      FD_LOG_CRIT(( "invariant violation: bank is NULL for bank index %lu", FD_REPLAY_BOOT_BANK_IDX ));
    }

    ulong snapshot_slot = fd_bank_slot_get( bank );
    /* FIXME: This is a hack because the block id of the snapshot slot
       is not provided in the snapshot.  A possible solution is to get
       the block id of the snapshot slot from repair. */
    fd_hash_t manifest_block_id = { .ul = { FD_RUNTIME_INITIAL_BLOCK_ID } };

    fd_store_exacq( ctx->store );
    FD_TEST( !fd_store_root( ctx->store ) );
    fd_store_insert( ctx->store, 0, &manifest_block_id );
    ctx->store->slot0 = snapshot_slot; /* FIXME manifest_block_id */
    fd_store_exrel( ctx->store );

    /* Typically, when we cross an epoch boundary during normal
       operation, we publish the stake weights for the new epoch.  But
       since we are starting from a snapshot, we need to publish two
       epochs worth of stake weights: the previous epoch (which is
       needed for voting on the current epoch), and the current epoch
       (which is needed for voting on the next epoch). */
    publish_stake_weights( ctx, stem, bank, 0 );
    publish_stake_weights( ctx, stem, bank, 1 );

    ctx->consensus_root          = manifest_block_id;
    ctx->consensus_root_slot     = snapshot_slot;
    ctx->consensus_root_bank_idx = 0UL;
    ctx->published_root_slot     = ctx->consensus_root_slot;
    ctx->published_root_bank_idx = 0UL;

    ctx->reset_slot            = snapshot_slot;
    ctx->reset_bank            = bank;
    ctx->reset_timestamp_nanos = fd_log_wallclock();
    ctx->next_leader_slot      = fd_multi_epoch_leaders_get_next_slot( ctx->mleaders, 1UL, ctx->identity_pubkey );
    if( FD_LIKELY( ctx->next_leader_slot ) ) {
      ctx->next_leader_tickcount = (long)((double)(ctx->next_leader_slot-ctx->reset_slot-1UL)*ctx->slot_duration_ticks) + fd_tickcount();
    } else {
      ctx->next_leader_tickcount = LONG_MAX;
    }

    fd_sched_block_add_done( ctx->sched, bank->idx, ULONG_MAX, snapshot_slot );
    FD_TEST( bank->idx==0UL );

    fd_funk_txn_xid_t xid = { .ul = { snapshot_slot, FD_REPLAY_BOOT_BANK_IDX } };

    fd_features_restore( bank, ctx->accdb->funk, &xid );

    fd_runtime_update_leaders( bank, &ctx->runtime_stack );

    fd_block_id_ele_t * block_id_ele = &ctx->block_id_arr[ 0 ];
    FD_TEST( block_id_ele );
    block_id_ele->block_id = manifest_block_id;
    block_id_ele->slot     = snapshot_slot;
    FD_TEST( fd_block_id_map_ele_insert( ctx->block_id_map, block_id_ele, ctx->block_id_arr ) );

    /* We call this after fd_runtime_read_genesis, which sets up the
       slot_bank needed in blockstore_init. */
    init_after_snapshot( ctx );

    publish_slot_completed( ctx, stem, bank, 1 );
    publish_root_advanced( ctx, stem );

    fd_reasm_fec_t * fec = fd_reasm_insert( ctx->reasm, &manifest_block_id, NULL, snapshot_slot, 0, 0, 0, 0, 1, 0 ); /* FIXME manifest block_id */
    fec->bank_idx        = 0UL;
    return;
  }

  switch( msg ) {
    case FD_SSMSG_MANIFEST_FULL:
    case FD_SSMSG_MANIFEST_INCREMENTAL: {
      /* We may either receive a full snapshot manifest or an
         incremental snapshot manifest.  Note that this external message
         id is only used temporarily because replay cannot yet receive
         the firedancer-internal snapshot manifest message. */
      if( FD_UNLIKELY( chunk<ctx->in[ in_idx ].chunk0 || chunk>ctx->in[ in_idx ].wmark ) )
        FD_LOG_ERR(( "chunk %lu from in %d corrupt, not in range [%lu,%lu]", chunk, ctx->in_kind[ in_idx ], ctx->in[ in_idx ].chunk0, ctx->in[ in_idx ].wmark ));

      fd_ssload_recover( fd_chunk_to_laddr( ctx->in[ in_idx ].mem, chunk ),
                         ctx->banks,
                         fd_banks_bank_query( ctx->banks, FD_REPLAY_BOOT_BANK_IDX ),
                         ctx->runtime_stack.stakes.vote_credits );

      fd_snapshot_manifest_t const * manifest = fd_chunk_to_laddr( ctx->in[ in_idx ].mem, chunk );
      ctx->hard_forks_cnt = manifest->hard_forks_len;
      for( ulong i=0UL; i<manifest->hard_forks_len; i++ ) ctx->hard_forks[ i ] = manifest->hard_forks[ i ];
      break;
    }
    default: {
      FD_LOG_ERR(( "Received unknown snapshot message with msg %lu", msg ));
      return;
    }
  }

  return;
}

static void
dispatch_task( fd_replay_tile_t *  ctx,
               fd_stem_context_t * stem,
               fd_sched_task_t *   task ) {

  switch( task->task_type ) {
    case FD_SCHED_TT_TXN_EXEC: {
      fd_txn_p_t * txn_p = fd_sched_get_txn( ctx->sched, task->txn_exec->txn_idx );

      /* FIXME: this should be done during txn parsing so that we don't
         have to loop over all accounts a second time. */
      /* Insert or reverify invoked programs for this epoch, if needed. */
      fd_bank_t * bank = fd_banks_bank_query( ctx->banks, task->txn_exec->bank_idx );

      /* Add the transaction to the block dumper if necessary. This
         logic doesn't need to be fork-aware since it's only meant to
         be used in backtest. */
      if( FD_UNLIKELY( ctx->capture_ctx && ctx->capture_ctx->dump_block_to_pb ) ) {
        fd_dump_block_to_protobuf_collect_tx( ctx->block_dump_ctx, txn_p );
      }

      bank->refcnt++;

      if( FD_UNLIKELY( !bank->first_transaction_scheduled_nanos ) ) bank->first_transaction_scheduled_nanos = fd_log_wallclock();

      fd_replay_out_link_t *   exec_out = ctx->exec_out;
      fd_exec_txn_exec_msg_t * exec_msg = fd_chunk_to_laddr( exec_out->mem, exec_out->chunk );
      memcpy( &exec_msg->txn, txn_p, sizeof(fd_txn_p_t) );
      exec_msg->bank_idx = task->txn_exec->bank_idx;
      exec_msg->txn_idx  = task->txn_exec->txn_idx;
      fd_stem_publish( stem, exec_out->idx, (FD_EXEC_TT_TXN_EXEC<<32) | task->txn_exec->exec_idx, exec_out->chunk, sizeof(*exec_msg), 0UL, 0UL, 0UL );
      exec_out->chunk = fd_dcache_compact_next( exec_out->chunk, sizeof(*exec_msg), exec_out->chunk0, exec_out->wmark );
      break;
    }
    case FD_SCHED_TT_TXN_SIGVERIFY: {
      fd_txn_p_t * txn_p = fd_sched_get_txn( ctx->sched, task->txn_sigverify->txn_idx );

      fd_bank_t * bank = fd_banks_bank_query( ctx->banks, task->txn_sigverify->bank_idx );
      bank->refcnt++;

      fd_replay_out_link_t *        exec_out = ctx->exec_out;
      fd_exec_txn_sigverify_msg_t * exec_msg = fd_chunk_to_laddr( exec_out->mem, exec_out->chunk );
      memcpy( &exec_msg->txn, txn_p, sizeof(fd_txn_p_t) );
      exec_msg->bank_idx = task->txn_sigverify->bank_idx;
      exec_msg->txn_idx  = task->txn_sigverify->txn_idx;
      fd_stem_publish( stem, exec_out->idx, (FD_EXEC_TT_TXN_SIGVERIFY<<32) | task->txn_sigverify->exec_idx, exec_out->chunk, sizeof(*exec_msg), 0UL, 0UL, 0UL );
      exec_out->chunk = fd_dcache_compact_next( exec_out->chunk, sizeof(*exec_msg), exec_out->chunk0, exec_out->wmark );
      break;
    };
    default: {
      FD_LOG_CRIT(( "unexpected task type %lu", task->task_type ));
    }
  }
}

/* Returns 1 if charge_busy. */
static int
replay( fd_replay_tile_t *  ctx,
        fd_stem_context_t * stem ) {

  if( FD_UNLIKELY( !ctx->is_booted ) ) return 0;

  int charge_busy = 0;
  fd_sched_task_t task[ 1 ];
  if( FD_UNLIKELY( !fd_sched_task_next_ready( ctx->sched, task ) ) ) {
    return charge_busy; /* Nothing to execute or do. */
  }

  charge_busy = 1;

  switch( task->task_type ) {
    case FD_SCHED_TT_BLOCK_START: {
      replay_block_start( ctx, stem, task->block_start->bank_idx, task->block_start->parent_bank_idx, task->block_start->slot );
      fd_sched_task_done( ctx->sched, FD_SCHED_TT_BLOCK_START, ULONG_MAX, ULONG_MAX );
      break;
    }
    case FD_SCHED_TT_BLOCK_END: {
      fd_bank_t * bank = fd_banks_bank_query( ctx->banks, task->block_end->bank_idx );
      if( FD_LIKELY( !(bank->flags&FD_BANK_FLAGS_DEAD) ) ) replay_block_finalize( ctx, stem, bank );
      fd_sched_task_done( ctx->sched, FD_SCHED_TT_BLOCK_END, ULONG_MAX, ULONG_MAX );
      break;
    }
    case FD_SCHED_TT_TXN_EXEC:
    case FD_SCHED_TT_TXN_SIGVERIFY: {
      /* Likely/common case: we have a transaction we actually need to
         execute. */
      dispatch_task( ctx, stem, task );
      break;
    }
    default: {
      FD_LOG_CRIT(( "unexpected task type %lu", task->task_type ));
    }
  }

  return charge_busy;
}

static void
process_fec_set( fd_replay_tile_t * ctx,
                 fd_reasm_fec_t *   reasm_fec ) {
  long now = fd_log_wallclock();

  /* Linking only requires a shared lock because the fields that are
     modified are only read on publish which uses exclusive lock. */

  long shacq_start, shacq_end, shrel_end;

  FD_STORE_SHARED_LOCK( ctx->store, shacq_start, shacq_end, shrel_end ) {
    if( FD_UNLIKELY( !fd_store_link( ctx->store, &reasm_fec->key, &reasm_fec->cmr ) ) ) FD_LOG_WARNING(( "failed to link %s %s. slot %lu fec_set_idx %u", FD_BASE58_ENC_32_ALLOCA( &reasm_fec->key ), FD_BASE58_ENC_32_ALLOCA( &reasm_fec->cmr ), reasm_fec->slot, reasm_fec->fec_set_idx ));
  } FD_STORE_SHARED_LOCK_END;
  fd_histf_sample( ctx->metrics.store_link_wait, (ulong)fd_long_max( shacq_end - shacq_start, 0L ) );
  fd_histf_sample( ctx->metrics.store_link_work, (ulong)fd_long_max( shrel_end - shacq_end,   0L ) );

  /* Update the reasm_fec with the correct bank index and parent bank
     index.  If the FEC belongs to a leader, we have already allocated
     a bank index for the FEC and it just needs to be propagated to the
     reasm_fec. */

  reasm_fec->parent_bank_idx = fd_reasm_parent( ctx->reasm, reasm_fec )->bank_idx;

  if( FD_UNLIKELY( reasm_fec->leader ) ) {
    /* If we are the leader we just need to copy in the bank index that
       the leader slot is using. */
    FD_TEST( ctx->leader_bank!=NULL );
    reasm_fec->bank_idx = ctx->leader_bank->idx;
  } else if( FD_UNLIKELY( reasm_fec->fec_set_idx==0U ) ) {
    /* If we are seeing a FEC with fec set idx 0, this means that we are
       starting a new slot, and we need a new bank index. */
    reasm_fec->bank_idx = fd_banks_new_bank( ctx->banks, reasm_fec->parent_bank_idx, now )->idx;
  } else {
    /* We are continuing to execute through a slot that we already have
       a bank index for. */
    reasm_fec->bank_idx = reasm_fec->parent_bank_idx;
  }

  if( FD_UNLIKELY( reasm_fec->slot_complete ) ) {
    /* Once the block id for a block is known it must be added to the
       leader block mapping. */
    fd_block_id_ele_t * block_id_ele = &ctx->block_id_arr[ reasm_fec->bank_idx ];
    FD_TEST( block_id_ele );

    /* If an entry already exists for this bank index in the block id
       map, we can safely remove it and replace it with the new entry.
       This is safe because we know that the old entry for this fork
       index has already been pruned away. */
    if( FD_LIKELY( block_id_ele->slot!=FD_SLOT_NULL && fd_block_id_map_ele_query( ctx->block_id_map, &block_id_ele->block_id, NULL, ctx->block_id_arr ) ) ) {
      FD_TEST( fd_block_id_map_ele_remove( ctx->block_id_map, &block_id_ele->block_id, NULL, ctx->block_id_arr ) );
    }

    block_id_ele->block_id = reasm_fec->key;
    block_id_ele->slot     = reasm_fec->slot;

    FD_TEST( fd_block_id_map_ele_insert( ctx->block_id_map, block_id_ele, ctx->block_id_arr ) );

    if( FD_UNLIKELY( reasm_fec->leader ) ) {
      ctx->recv_block_id = 1;
    }
  }

  if( FD_UNLIKELY( reasm_fec->leader ) ) {
    return;
  }

  /* Forks form a partial ordering over FEC sets. The Repair tile
     delivers FEC sets in-order per fork, but FEC set ordering across
     forks is arbitrary */
  fd_sched_fec_t sched_fec[ 1 ];

# if DEBUG_LOGGING
  FD_LOG_INFO(( "replay processing FEC set for slot %lu fec_set_idx %u, mr %s cmr %s", reasm_fec->slot, reasm_fec->fec_set_idx, FD_BASE58_ENC_32_ALLOCA( &reasm_fec->key ), FD_BASE58_ENC_32_ALLOCA( &reasm_fec->cmr ) ));
# endif

  /* Read FEC set from the store.  This should happen before we try to
     ingest the FEC set.  This allows us to filter out frags that were
     in-flight when we published away minority forks that the frags land
     on.  These frags would have no bank to execute against, because
     their corresponding banks, or parent banks, have also been pruned
     during publishing.  A query against store will rightfully tell us
     that the underlying data is not found, implying that this is for a
     minority fork that we can safely ignore. */
  FD_STORE_SHARED_LOCK( ctx->store, shacq_start, shacq_end, shrel_end ) {
    fd_store_fec_t * store_fec = fd_store_query( ctx->store, &reasm_fec->key );
    if( FD_UNLIKELY( !store_fec ) ) {
      /* The only case in which a FEC is not found in the store after
         repair has notified is if the FEC was on a minority fork that
         has already been published away.  In this case we abandon the
         entire slice because it is no longer relevant.  */
      FD_LOG_WARNING(( "store fec for slot: %lu is on minority fork already pruned by publish. abandoning slice. root: %lu. pruned merkle: %s", reasm_fec->slot, ctx->consensus_root_slot, FD_BASE58_ENC_32_ALLOCA( &reasm_fec->key ) ));
      return;
    }
    FD_TEST( store_fec );
    sched_fec->fec       = store_fec;
    sched_fec->shred_cnt = reasm_fec->data_cnt;
  } FD_STORE_SHARED_LOCK_END;

  fd_histf_sample( ctx->metrics.store_read_wait, (ulong)fd_long_max( shacq_end - shacq_start, 0UL ) );
  fd_histf_sample( ctx->metrics.store_read_work, (ulong)fd_long_max( shrel_end - shacq_end,   0UL ) );

  sched_fec->is_last_in_batch       = !!reasm_fec->data_complete;
  sched_fec->is_last_in_block       = !!reasm_fec->slot_complete;
  sched_fec->bank_idx               = reasm_fec->bank_idx;
  sched_fec->parent_bank_idx        = reasm_fec->parent_bank_idx;
  sched_fec->slot                   = reasm_fec->slot;
  sched_fec->parent_slot            = reasm_fec->slot - reasm_fec->parent_off;
  sched_fec->is_first_in_block      = reasm_fec->fec_set_idx==0U;
  fd_funk_txn_xid_copy( sched_fec->alut_ctx->xid, fd_funk_last_publish( ctx->accdb->funk ) );
  sched_fec->alut_ctx->accdb[0]     = ctx->accdb[0];
  sched_fec->alut_ctx->els          = ctx->published_root_slot;

  if( FD_UNLIKELY( !fd_sched_fec_ingest( ctx->sched, sched_fec ) ) ) {
    fd_banks_mark_bank_dead( ctx->banks, fd_banks_bank_query( ctx->banks, sched_fec->bank_idx ) );
  }
}

static void
funk_publish( fd_replay_tile_t * ctx,
              ulong              slot,
              ulong              bank_idx ) {
  fd_funk_txn_xid_t xid = { .ul[0] = slot, .ul[1] = bank_idx };
  FD_LOG_DEBUG(( "publishing slot=%lu", slot ));

  /* This is the standard case.  Publish all transactions up to and
     including the watermark.  This will publish any in-prep ancestors
     of root_txn as well. */
  fd_accdb_advance_root( ctx->accdb_admin, &xid );
  fd_progcache_txn_advance_root( ctx->progcache_admin, &xid );
}

static int
advance_published_root( fd_replay_tile_t * ctx ) {

  fd_block_id_ele_t * block_id_ele = fd_block_id_map_ele_query( ctx->block_id_map, &ctx->consensus_root, NULL, ctx->block_id_arr );
  if( FD_UNLIKELY( !block_id_ele ) ) {
    FD_LOG_CRIT(( "invariant violation: block id ele not found for consensus root %s", FD_BASE58_ENC_32_ALLOCA( &ctx->consensus_root ) ));
  }
  ulong target_bank_idx = fd_block_id_ele_get_idx( ctx->block_id_arr, block_id_ele );

  fd_sched_root_notify( ctx->sched, target_bank_idx );

  /* If the identity vote has been seen on a bank that should be rooted,
     then we are now ready to produce blocks. */
  if( FD_UNLIKELY( !ctx->has_identity_vote_rooted ) ) {
    fd_bank_t * root_bank = fd_banks_bank_query( ctx->banks, target_bank_idx );
    if( FD_UNLIKELY( !root_bank ) ) FD_LOG_CRIT(( "invariant violation: root bank not found for bank index %lu", target_bank_idx ));
    if( FD_LIKELY( fd_bank_has_identity_vote_get( root_bank ) ) ) ctx->has_identity_vote_rooted = 1;
  }

  ulong advanceable_root_idx = ULONG_MAX;
  if( FD_UNLIKELY( !fd_banks_advance_root_prepare( ctx->banks, target_bank_idx, &advanceable_root_idx ) ) ) return 0;

  fd_bank_t * bank = fd_banks_bank_query( ctx->banks, advanceable_root_idx );
  FD_TEST( bank );

  fd_block_id_ele_t * advanceable_root_ele = &ctx->block_id_arr[ advanceable_root_idx ];
  if( FD_UNLIKELY( !advanceable_root_ele ) ) {
    FD_LOG_CRIT(( "invariant violation: advanceable root ele not found for bank index %lu", advanceable_root_idx ));
  }

  long exacq_start, exacq_end, exrel_end;
  FD_STORE_EXCLUSIVE_LOCK( ctx->store, exacq_start, exacq_end, exrel_end ) {
    fd_store_publish( ctx->store, &advanceable_root_ele->block_id );
  } FD_STORE_EXCLUSIVE_LOCK_END;

  fd_histf_sample( ctx->metrics.store_publish_wait, (ulong)fd_long_max( exacq_end-exacq_start, 0UL ) );
  fd_histf_sample( ctx->metrics.store_publish_work, (ulong)fd_long_max( exrel_end-exacq_end,   0UL ) );

  ulong advanceable_root_slot = fd_bank_slot_get( bank );
  funk_publish( ctx, advanceable_root_slot, bank->idx );

  fd_txncache_advance_root( ctx->txncache, bank->txncache_fork_id );
  fd_sched_advance_root( ctx->sched, advanceable_root_idx );
  fd_banks_advance_root( ctx->banks, advanceable_root_idx );
  fd_reasm_publish( ctx->reasm, &advanceable_root_ele->block_id );

  ctx->published_root_slot     = advanceable_root_slot;
  ctx->published_root_bank_idx = advanceable_root_idx;

  return 1;
}

static void
after_credit( fd_replay_tile_t *  ctx,
              fd_stem_context_t * stem,
              int *               opt_poll_in,
              int *               charge_busy ) {
  if( FD_UNLIKELY( !ctx->is_booted ) ) return;

  /* Send any outstanding vote states to tower.  TODO: Not sure why this
     is here?  Should happen when the slot completes instead? */
  if( FD_UNLIKELY( ctx->vote_tower_out_idx<ctx->vote_tower_out_len ) ) {
    *charge_busy = 1;
    publish_next_vote_tower( ctx, stem );
    /* Don't continue polling for fragments but instead skip to the next
       iteration of the stem loop.

       This is necessary so that all the votes states for the end of a
       particular slot are sent in one atomic block, and are not
       interleaved with votes states at the end of other slots. */
    *opt_poll_in = 0;
    return;
  }

  if( FD_UNLIKELY( maybe_become_leader( ctx, stem ) ) ) {
    *charge_busy = 1;
    *opt_poll_in = 0;
    return;
  }

  /* If the reassembler has a fec that is ready, we should process it
     and pass it to the scheduler. */

  fd_reasm_fec_t * fec;
  /* FIXME: The reasm logic needs to get reworked to support
     equivocation more robustly. */
  if( FD_LIKELY( fd_sched_can_ingest( ctx->sched, 1UL ) && !fd_banks_is_full( ctx->banks ) && (fec = fd_reasm_peek( ctx->reasm )) ) ) {

    /* If fec->eqvoc is set that means that equivocation mid-block was
       detected in fd_reasm_t.  We need to replay up to and including
       the equivocating FEC on a new bank. */

    if( FD_UNLIKELY( fec->eqvoc ) ) {
      FD_LOG_WARNING(( "Block equivocation detected at slot %lu", fec->slot ));

      /* We need to figure out which and how many FECs we need to
         (re)insert into the scheduler.  We work backwards from the
         equivocating FEC, querying for chained merkle roots until we
         reach the first FEC in the slot.
         TODO: replace the magic number with a constant for the max
               number of fecs possible in a slot with fix-32. */
      fd_reasm_fec_t * fecs[ 1024 ] = { [0] = fec };
      ulong            fec_cnt      = 1UL;
      while( fecs[ fec_cnt-1UL ]->fec_set_idx!=0UL ) {
        fec = fd_reasm_query( ctx->reasm, &fecs[ fec_cnt-1UL ]->cmr );
        fecs[ fec_cnt++ ] = fec;
      }

      /* If we don't have enough space in the scheduler to ingest all of
         FECs, we can't proceed yet. */
      if( FD_UNLIKELY( !fd_sched_can_ingest( ctx->sched, fec_cnt ) ) ) return;

      /* Now that we have validated that sched can ingest all of the
         required FECs, it is finally safe to remove the equivocating
         fec from the reasm deque. */
      fd_reasm_out( ctx->reasm );

      /* Now we can process all of the FECs. */
      for( ulong i=fec_cnt; i>0UL; i-- ) {
        process_fec_set( ctx, fecs[i-1UL] );
      }
    } else {
      /* Standard case. */
      fec = fd_reasm_out( ctx->reasm );
      process_fec_set( ctx, fec );
    }

    *charge_busy = 1;
    *opt_poll_in = 0;
    return;
  }

  /* If we are leader, we can only unbecome the leader iff we have
     received the poh hash from the poh tile and block id from reasm. */
  if( FD_UNLIKELY( ctx->is_leader && ctx->recv_block_id && ctx->recv_poh ) ) {
    fini_leader_bank( ctx, stem );
    *charge_busy = 1;
    *opt_poll_in = 0;
    return;
  }

  /* If the published_root is not caught up to the consensus root, then
     we should try to advance the published root. */
  if( FD_UNLIKELY( ctx->consensus_root_bank_idx!=ctx->published_root_bank_idx && advance_published_root( ctx ) ) ) {
    *charge_busy = 1;
    *opt_poll_in = 0;
    return;
  }

  *charge_busy = replay( ctx, stem );
  *opt_poll_in = !*charge_busy;
}

static int
before_frag( fd_replay_tile_t * ctx,
             ulong              in_idx,
             ulong              seq FD_PARAM_UNUSED,
             ulong              sig FD_PARAM_UNUSED ) {

  if( FD_UNLIKELY( ctx->in_kind[ in_idx ]==IN_KIND_SHRED ) ) {
    /* If reasm is full, we can not insert any more FEC sets.  We must
       not consume any frags from shred_out until reasm can process more
       FEC sets. */

    if( FD_UNLIKELY( !fd_reasm_free( ctx->reasm ) ) ) {
      return -1;
    }
  }

  return 0;
}

static void
process_solcap_account_update( fd_replay_tile_t *                          ctx,
                               fd_capture_ctx_account_update_msg_t const * msg ) {

  fd_bank_t * bank = fd_banks_bank_query( ctx->banks, msg->bank_idx );
  if( FD_UNLIKELY( !bank ) ) {
    FD_LOG_CRIT(( "invariant violation: bank is NULL for bank index %lu", msg->bank_idx ));
  }

  if( FD_UNLIKELY( !ctx->capture_ctx || !ctx->capture_ctx->capture ) ) return;
  if( FD_UNLIKELY( fd_bank_slot_get( bank )<ctx->capture_ctx->solcap_start_slot ) ) return;

  uchar const * account_data = (uchar const *)fd_type_pun_const( msg )+sizeof(fd_capture_ctx_account_update_msg_t);
  fd_solcap_write_account( ctx->capture_ctx->capture, &msg->pubkey, &msg->info, account_data, msg->data_sz );
}

static void
process_exec_task_done( fd_replay_tile_t *        ctx,
                        fd_exec_task_done_msg_t * msg,
                        ulong                     sig ) {
  if( FD_UNLIKELY( sig==0UL ) ) {
    // FIXME remove this branch with new solcap
    process_solcap_account_update( ctx, fd_type_pun( msg ) );
    return;
  }

  ulong exec_tile_idx = sig&0xFFFFFFFFUL;

  fd_bank_t * bank = fd_banks_bank_query( ctx->banks, msg->bank_idx );
  bank->refcnt--;

  switch( sig>>32 ) {
    case FD_EXEC_TT_TXN_EXEC: {
      if( FD_UNLIKELY( !ctx->has_identity_vote_rooted ) ) {
        /* Query the txn signature against our recently generated vote
           txn signatures.  If the query is successful, then we have
           seen our own vote transaction land and this should be marked
           in the bank.  We go through this exercise until we've seen
           our vote rooted. */
        fd_txn_p_t * txn_p = fd_sched_get_txn( ctx->sched, msg->txn_exec->txn_idx );
        if( fd_vote_tracker_query_sig( ctx->vote_tracker, fd_type_pun_const( txn_p->payload+TXN( txn_p )->signature_off ) ) ) {
          *fd_bank_has_identity_vote_modify( bank ) += 1;
        }
      }
      if( FD_UNLIKELY( msg->txn_exec->err && !(bank->flags&FD_BANK_FLAGS_DEAD) ) ) {
        /* Every transaction in a valid block has to execute.
           Otherwise, we should mark the block as dead.  Also freeze the
           bank if possible. */
        fd_banks_mark_bank_dead( ctx->banks, bank );
        fd_sched_block_abandon( ctx->sched, bank->idx );
      }
      if( FD_UNLIKELY( (bank->flags&FD_BANK_FLAGS_DEAD) && bank->refcnt==0UL ) ) {
        fd_banks_mark_bank_frozen( ctx->banks, bank );
      }
      fd_sched_task_done( ctx->sched, FD_SCHED_TT_TXN_EXEC, msg->txn_exec->txn_idx, exec_tile_idx );
      break;
    }
    case FD_EXEC_TT_TXN_SIGVERIFY: {
      if( FD_UNLIKELY( msg->txn_sigverify->err && !(bank->flags&FD_BANK_FLAGS_DEAD) ) ) {
        /* Every transaction in a valid block has to sigverify.
           Otherwise, we should mark the block as dead.  Also freeze the
           bank if possible. */
        fd_banks_mark_bank_dead( ctx->banks, bank );
        fd_sched_block_abandon( ctx->sched, bank->idx );
      }
      if( FD_UNLIKELY( (bank->flags&FD_BANK_FLAGS_DEAD) && bank->refcnt==0UL ) ) {
        fd_banks_mark_bank_frozen( ctx->banks, bank );
      }
      fd_sched_task_done( ctx->sched, FD_SCHED_TT_TXN_SIGVERIFY, msg->txn_sigverify->txn_idx, exec_tile_idx );
      break;
    }
    default: FD_LOG_CRIT(( "unexpected sig 0x%lx", sig ));
  }

  /* Reference counter just decreased, and an exec tile just got freed
     up.  If there's a need to be more aggressively pruning, we could
     check here if more slots just became publishable and publish.  Not
     publishing here shouldn't bloat the fork tree too much though.  We
     mark minority forks dead as soon as we can, and execution dispatch
     stops on dead blocks.  So shortly afterwards, dead blocks should be
     eligible for pruning as in-flight transactions retire from the
     execution pipeline. */

}

static void
process_tower_update( fd_replay_tile_t *           ctx,
                      fd_stem_context_t *          stem,
                      fd_tower_slot_done_t const * msg ) {
  ctx->reset_block_id = msg->reset_block_id;
  ctx->reset_slot     = msg->reset_slot;
  ctx->reset_timestamp_nanos = fd_log_wallclock();
  ulong min_leader_slot = fd_ulong_max( msg->reset_slot+1UL, fd_ulong_if( ctx->highwater_leader_slot==ULONG_MAX, 0UL, ctx->highwater_leader_slot+1UL ) );
  ctx->next_leader_slot = fd_multi_epoch_leaders_get_next_slot( ctx->mleaders, min_leader_slot, ctx->identity_pubkey );
  if( FD_LIKELY( ctx->next_leader_slot ) ) {
    ctx->next_leader_tickcount = (long)((double)(ctx->next_leader_slot-ctx->reset_slot-1UL)*ctx->slot_duration_ticks) + fd_tickcount();
  } else {
    ctx->next_leader_tickcount = LONG_MAX;
  }

  fd_block_id_ele_t * block_id_ele = fd_block_id_map_ele_query( ctx->block_id_map, &msg->reset_block_id, NULL, ctx->block_id_arr );
  if( FD_UNLIKELY( !block_id_ele ) ) {
    FD_LOG_CRIT(( "invariant violation: block id ele doesn't exist for reset block id: %s, slot: %lu", FD_BASE58_ENC_32_ALLOCA( &msg->reset_block_id ), msg->reset_slot ));
  }
  ulong reset_bank_idx = fd_block_id_ele_get_idx( ctx->block_id_arr, block_id_ele );

  fd_bank_t * bank = fd_banks_bank_query( ctx->banks, reset_bank_idx );
  if( FD_UNLIKELY( !bank ) ) {
    FD_LOG_CRIT(( "invariant violation: bank not found for bank index %lu", reset_bank_idx ));
  }

  if( FD_LIKELY( msg->new_root ) ) FD_TEST( msg->root_slot<=msg->reset_slot );
  ctx->reset_bank = bank;

  if( FD_LIKELY( ctx->replay_out->idx!=ULONG_MAX ) ) {
    fd_poh_reset_t * reset = fd_chunk_to_laddr( ctx->replay_out->mem, ctx->replay_out->chunk );

    reset->timestamp = ctx->reset_timestamp_nanos;
    reset->completed_slot = ctx->reset_slot;
    reset->hashcnt_per_tick = fd_bank_hashes_per_tick_get( bank );
    reset->ticks_per_slot = fd_bank_ticks_per_slot_get( bank );
    reset->tick_duration_ns = (ulong)(ctx->slot_duration_nanos/(double)reset->ticks_per_slot);

    fd_memcpy( reset->completed_block_id, &block_id_ele->block_id, sizeof(fd_hash_t) );

    fd_blockhashes_t const * block_hash_queue = fd_bank_block_hash_queue_query( bank );
    fd_hash_t const * last_hash = fd_blockhashes_peek_last( block_hash_queue );
    FD_TEST( last_hash );
    fd_memcpy( reset->completed_blockhash, last_hash->uc, sizeof(fd_hash_t) );

    ulong ticks_per_slot = fd_bank_ticks_per_slot_get( bank );
    if( FD_UNLIKELY( reset->hashcnt_per_tick==1UL ) ) {
      /* Low power producer, maximum of one microblock per tick in the slot */
      reset->max_microblocks_in_slot = ticks_per_slot;
    } else {
      /* See the long comment in after_credit for this limit */
      reset->max_microblocks_in_slot = fd_ulong_min( MAX_MICROBLOCKS_PER_SLOT, ticks_per_slot*(reset->hashcnt_per_tick-1UL) );
    }
    reset->next_leader_slot = ctx->next_leader_slot;

    fd_stem_publish( stem, ctx->replay_out->idx, REPLAY_SIG_RESET, ctx->replay_out->chunk, sizeof(fd_poh_reset_t), 0UL, 0UL, fd_frag_meta_ts_comp( fd_tickcount() ) );
    ctx->replay_out->chunk = fd_dcache_compact_next( ctx->replay_out->chunk, sizeof(fd_poh_reset_t), ctx->replay_out->chunk0, ctx->replay_out->wmark );
  }

  FD_LOG_INFO(( "tower_update(reset_slot=%lu, next_leader_slot=%lu, vote_slot=%lu, new_root=%d, root_slot=%lu, root_block_id=%s)", msg->reset_slot, ctx->next_leader_slot, msg->vote_slot, msg->new_root, msg->root_slot, FD_BASE58_ENC_32_ALLOCA( &msg->root_block_id ) ));
  maybe_become_leader( ctx, stem );

  if( FD_LIKELY( msg->new_root ) ) {

    FD_TEST( msg->root_slot>=ctx->consensus_root_slot );
    fd_block_id_ele_t * block_id_ele = fd_block_id_map_ele_query( ctx->block_id_map, &msg->root_block_id, NULL, ctx->block_id_arr );
    FD_TEST( block_id_ele );

    ctx->consensus_root_slot     = msg->root_slot;
    ctx->consensus_root          = msg->root_block_id;
    ctx->consensus_root_bank_idx = fd_block_id_ele_get_idx( ctx->block_id_arr, block_id_ele );

    publish_root_advanced( ctx, stem );
  }

  ulong distance = 0UL;
  fd_bank_t * parent = bank;
  while( parent ) {
    if( FD_UNLIKELY( parent->idx==ctx->consensus_root_bank_idx ) ) break;
    parent = fd_banks_get_parent( ctx->banks, parent );
    distance++;
  }

  FD_MGAUGE_SET( REPLAY, ROOT_DISTANCE, distance );
}

static void
process_fec_complete( fd_replay_tile_t * ctx,
                      uchar const *      shred_buf ) {
  fd_shred_t const * shred = (fd_shred_t const *)fd_type_pun_const( shred_buf );

  fd_hash_t const * merkle_root         = (fd_hash_t const *)fd_type_pun_const( shred_buf + FD_SHRED_DATA_HEADER_SZ );
  fd_hash_t const * chained_merkle_root = (fd_hash_t const *)fd_type_pun_const( shred_buf + FD_SHRED_DATA_HEADER_SZ + sizeof(fd_hash_t) );
  int               is_leader_fec       = *(int const *)     fd_type_pun_const( shred_buf + FD_SHRED_DATA_HEADER_SZ + sizeof(fd_hash_t) + sizeof(fd_hash_t) );

  int data_complete = !!( shred->data.flags & FD_SHRED_DATA_FLAG_DATA_COMPLETE );
  int slot_complete = !!( shred->data.flags & FD_SHRED_DATA_FLAG_SLOT_COMPLETE );

  FD_TEST( !fd_reasm_query( ctx->reasm, merkle_root ) );
  if( FD_UNLIKELY( shred->slot - shred->data.parent_off == fd_reasm_slot0( ctx->reasm ) && shred->fec_set_idx == 0) ) {
    chained_merkle_root = &fd_reasm_root( ctx->reasm )->key;
  }
  FD_TEST( fd_reasm_insert( ctx->reasm, merkle_root, chained_merkle_root, shred->slot, shred->fec_set_idx, shred->data.parent_off, (ushort)(shred->idx - shred->fec_set_idx + 1), data_complete, slot_complete, is_leader_fec ) );
}

static void
process_resolv_slot_completed( fd_replay_tile_t * ctx, ulong bank_idx ) {
  fd_bank_t * bank = fd_banks_bank_query( ctx->banks, bank_idx );
  FD_TEST( bank );

  bank->refcnt--;
}

static void
process_vote_txn_sent( fd_replay_tile_t *  ctx,
                       fd_txn_m_t *        txnm ) {
  /* The send tile has signed and sent a vote.  Add this vote to the
     vote tracker.  We go through this exercise until we've seen our
     vote rooted. */
  if( FD_UNLIKELY( !ctx->has_identity_vote_rooted ) ) {
    uchar *    payload = ((uchar *)txnm) + sizeof(fd_txn_m_t);
    uchar      txn_mem[ FD_TXN_MAX_SZ ] __attribute__((aligned(alignof(fd_txn_t))));
    fd_txn_t * txn = (fd_txn_t *)txn_mem;
    if( FD_UNLIKELY( !fd_txn_parse( payload, txnm->payload_sz, txn_mem, NULL ) ) ) {
      FD_LOG_CRIT(( "Could not parse txn from send tile" ));
    }
    fd_vote_tracker_insert( ctx->vote_tracker, fd_type_pun_const( payload+txn->signature_off ) );
  }
}

static inline void
maybe_verify_shred_version( fd_replay_tile_t * ctx ) {
  if( FD_LIKELY( ctx->expected_shred_version && ctx->ipecho_shred_version ) ) {
    if( FD_UNLIKELY( ctx->expected_shred_version!=ctx->ipecho_shred_version ) ) {
      FD_LOG_ERR(( "shred version mismatch: expected %u but got %u from ipecho", ctx->expected_shred_version, ctx->ipecho_shred_version ) );
    }
  }

  if( FD_LIKELY( ctx->has_genesis_hash && ctx->hard_forks_cnt!=ULONG_MAX && (ctx->expected_shred_version || ctx->ipecho_shred_version) ) ) {
    ushort expected_shred_version = ctx->expected_shred_version ? ctx->expected_shred_version : ctx->ipecho_shred_version;

    union {
      uchar  c[ 32 ];
      ushort s[ 16 ];
    } running_hash;
    fd_memcpy( running_hash.c, ctx->genesis_hash, sizeof(fd_hash_t) );

    ulong processed = 0UL;
    ulong min_value = 0UL;
    while( processed<ctx->hard_forks_cnt ) {
      ulong min_index = ULONG_MAX;
      for( ulong i=0UL; i<ctx->hard_forks_cnt; i++ ) {
        if( ctx->hard_forks[ i ]>=min_value && (min_index==ULONG_MAX || ctx->hard_forks[ i ]<ctx->hard_forks[ min_index ] ) ) {
          min_index = i;
        }
      }

      FD_TEST( min_index!=ULONG_MAX );
      min_value = ctx->hard_forks[ min_index ];
      ulong min_count = 0UL;
      for( ulong i=0UL; i<ctx->hard_forks_cnt; i++ ) {
        if( ctx->hard_forks[ i ]==min_value ) min_count++;
      }

      uchar data[ 48UL ];
      fd_memcpy( data, running_hash.c, sizeof(fd_hash_t) );
      fd_memcpy( data+32UL, &min_value, sizeof(ulong) );
      fd_memcpy( data+40UL, &min_count, sizeof(ulong) );

      FD_TEST( fd_sha256_hash( data, 48UL, running_hash.c ) );
      processed += min_count;
      min_value += 1UL;
    }

    ushort xor = 0;
    for( ulong i=0UL; i<16UL; i++ ) xor ^= running_hash.s[ i ];

    xor = fd_ushort_bswap( xor );
    xor = fd_ushort_if( xor<USHORT_MAX, (ushort)(xor + 1), USHORT_MAX );

    if( FD_UNLIKELY( expected_shred_version!=xor ) ) {
      FD_LOG_WARNING(( "shred version mismatch: expected %u but got %u from genesis hash %s and hard forks", expected_shred_version, xor, FD_BASE58_ENC_32_ALLOCA( &ctx->genesis_hash ) ));
    }
  }
}

static inline int
returnable_frag( fd_replay_tile_t *  ctx,
                 ulong               in_idx,
                 ulong               seq,
                 ulong               sig,
                 ulong               chunk,
                 ulong               sz,
                 ulong               ctl,
                 ulong               tsorig,
                 ulong               tspub,
                 fd_stem_context_t * stem ) {
  (void)seq;
  (void)ctl;
  (void)tsorig;
  (void)tspub;

  if( FD_UNLIKELY( sz!=0UL && (chunk<ctx->in[ in_idx ].chunk0 || chunk>ctx->in[ in_idx ].wmark || sz>ctx->in[ in_idx ].mtu ) ) )
    FD_LOG_ERR(( "chunk %lu %lu from in %d corrupt, not in range [%lu,%lu]", chunk, sz, ctx->in_kind[ in_idx ], ctx->in[ in_idx ].chunk0, ctx->in[ in_idx ].wmark ));

  switch( ctx->in_kind[in_idx] ) {
    case IN_KIND_GENESIS: {
      uchar const * src = fd_chunk_to_laddr( ctx->in[ in_idx ].mem, chunk );
      ctx->has_genesis_hash = 1;
      if( FD_LIKELY( sig==GENESI_SIG_BOOTSTRAP_COMPLETED ) ) {
        boot_genesis( ctx, stem, in_idx, chunk );
        fd_memcpy( ctx->genesis_hash, src+sizeof(fd_lthash_value_t), sizeof(fd_hash_t) );
      } else {
        fd_memcpy( ctx->genesis_hash, src, sizeof(fd_hash_t) );
      }
      maybe_verify_shred_version( ctx );
      break;
    }
    case IN_KIND_IPECHO: {
      FD_TEST( sig && sig<=USHORT_MAX );
      ctx->ipecho_shred_version = (ushort)sig;
      maybe_verify_shred_version( ctx );
      break;
    }
    case IN_KIND_SNAP:
      on_snapshot_message( ctx, stem, in_idx, chunk, sig );
      maybe_verify_shred_version( ctx );
      break;
    case IN_KIND_EXEC: {
      process_exec_task_done( ctx, fd_chunk_to_laddr( ctx->in[ in_idx ].mem, chunk ), sig );
      break;
    }
    case IN_KIND_POH: {
      process_poh_message( ctx, fd_chunk_to_laddr( ctx->in[ in_idx ].mem, chunk ) );
      break;
    }
    case IN_KIND_RESOLV: {
      fd_resolv_slot_exchanged_t * exchanged_slot = fd_chunk_to_laddr( ctx->in[ in_idx ].mem, chunk );
      process_resolv_slot_completed( ctx, exchanged_slot->bank_idx );
      break;
    }
    case IN_KIND_TOWER: {
      process_tower_update( ctx, stem, fd_chunk_to_laddr( ctx->in[ in_idx ].mem, chunk ) );
      break;
    }
    case IN_KIND_SHRED: {
      /* TODO: This message/sz should be defined. */
      if( sz==FD_SHRED_DATA_HEADER_SZ + sizeof(fd_hash_t) + sizeof(fd_hash_t) + sizeof(int) ) {
        /* If receive a FEC complete message. */
        process_fec_complete( ctx, fd_chunk_to_laddr( ctx->in[ in_idx ].mem, chunk ) );
      }
      break;
    }
    case IN_KIND_VTXN: {
      process_vote_txn_sent( ctx, fd_chunk_to_laddr( ctx->in[ in_idx ].mem, chunk ) );
      break;
    }
    case IN_KIND_GUI: {
      fd_bank_t * bank = fd_banks_bank_query( ctx->banks, sig );
      FD_TEST( bank );
      bank->refcnt--;
      break;
    }
    default:
      FD_LOG_ERR(( "unhandled kind %d", ctx->in_kind[ in_idx ] ));
  }

  return 0;
}

static inline fd_replay_out_link_t
out1( fd_topo_t const *      topo,
      fd_topo_tile_t const * tile,
      char const *           name ) {
  ulong idx = ULONG_MAX;

  for( ulong i=0UL; i<tile->out_cnt; i++ ) {
    fd_topo_link_t const * link = &topo->links[ tile->out_link_id[ i ] ];
    if( !strcmp( link->name, name ) ) {
      if( FD_UNLIKELY( idx!=ULONG_MAX ) ) FD_LOG_ERR(( "tile %s:%lu had multiple output links named %s but expected one", tile->name, tile->kind_id, name ));
      idx = i;
    }
  }

  if( FD_UNLIKELY( idx==ULONG_MAX ) ) return (fd_replay_out_link_t){ .idx = ULONG_MAX, .mem = NULL, .chunk0 = 0, .wmark = 0, .chunk = 0 };

  void * mem = topo->workspaces[ topo->objs[ topo->links[ tile->out_link_id[ idx ] ].dcache_obj_id ].wksp_id ].wksp;
  ulong chunk0 = fd_dcache_compact_chunk0( mem, topo->links[ tile->out_link_id[ idx ] ].dcache );
  ulong wmark  = fd_dcache_compact_wmark ( mem, topo->links[ tile->out_link_id[ idx ] ].dcache, topo->links[ tile->out_link_id[ idx ] ].mtu );

  return (fd_replay_out_link_t){ .idx = idx, .mem = mem, .chunk0 = chunk0, .wmark = wmark, .chunk = chunk0 };
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_replay_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_replay_tile_t), sizeof(fd_replay_tile_t) );

  if( FD_UNLIKELY( !strcmp( tile->replay.identity_key_path, "" ) ) ) FD_LOG_ERR(( "identity_key_path not set" ));

  ctx->identity_pubkey[ 0 ] = *(fd_pubkey_t const *)fd_type_pun_const( fd_keyload_load( tile->replay.identity_key_path, /* pubkey only: */ 1 ) );
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  ulong chain_cnt = fd_block_id_map_chain_cnt_est( tile->replay.max_live_slots );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_replay_tile_t * ctx   = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_replay_tile_t),   sizeof(fd_replay_tile_t) );
  void * block_id_arr_mem  = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_block_id_ele_t),  sizeof(fd_block_id_ele_t) * tile->replay.max_live_slots );
  void * block_id_map_mem  = FD_SCRATCH_ALLOC_APPEND( l, fd_block_id_map_align(),     fd_block_id_map_footprint( chain_cnt ) );
  void * _txncache         = FD_SCRATCH_ALLOC_APPEND( l, fd_txncache_align(),         fd_txncache_footprint( tile->replay.max_live_slots ) );
  void * reasm_mem         = FD_SCRATCH_ALLOC_APPEND( l, fd_reasm_align(),            fd_reasm_footprint( 1 << 20 ) );
  void * sched_mem         = FD_SCRATCH_ALLOC_APPEND( l, fd_sched_align(),            fd_sched_footprint( tile->replay.max_live_slots ) );
  void * vote_tracker_mem  = FD_SCRATCH_ALLOC_APPEND( l, fd_vote_tracker_align(),     fd_vote_tracker_footprint() );
  void * _capture_ctx      = FD_SCRATCH_ALLOC_APPEND( l, fd_capture_ctx_align(),      fd_capture_ctx_footprint() );
  void * block_dump_ctx    = NULL;
  if( FD_UNLIKELY( tile->replay.dump_block_to_pb ) ) {
    block_dump_ctx = FD_SCRATCH_ALLOC_APPEND( l, fd_block_dump_context_align(), fd_block_dump_context_footprint() );
  }

  ulong store_obj_id = fd_pod_query_ulong( topo->props, "store", ULONG_MAX );
  FD_TEST( store_obj_id!=ULONG_MAX );
  ctx->store = fd_store_join( fd_topo_obj_laddr( topo, store_obj_id ) );
  FD_TEST( ctx->store );

  ctx->vote_tower_out_idx = 0UL;
  ctx->vote_tower_out_len = 0UL;

  ulong banks_obj_id = fd_pod_query_ulong( topo->props, "banks", ULONG_MAX );
  FD_TEST( banks_obj_id!=ULONG_MAX );
  ctx->banks = fd_banks_join( fd_topo_obj_laddr( topo, banks_obj_id ) );
  FD_TEST( ctx->banks );

  fd_bank_t * bank_pool = fd_banks_get_bank_pool( ctx->banks );
  FD_MGAUGE_SET( REPLAY, MAX_LIVE_BANKS, fd_banks_pool_max( bank_pool ) );

  fd_bank_t * bank = fd_banks_init_bank( ctx->banks );
  fd_bank_slot_set( bank, 0UL );
  FD_TEST( bank );
  FD_TEST( bank->idx==FD_REPLAY_BOOT_BANK_IDX );

  ctx->consensus_root_slot = ULONG_MAX;
  ctx->consensus_root      = (fd_hash_t){ .ul[0] = FD_RUNTIME_INITIAL_BLOCK_ID };
  ctx->published_root_slot = ULONG_MAX;

  ctx->expected_shred_version = tile->replay.expected_shred_version;
  ctx->ipecho_shred_version = 0;
  ctx->has_genesis_hash = 0;
  ctx->hard_forks_cnt = ULONG_MAX;

  /* Set some initial values for the bank:  hardcoded features and the
     cluster version. */
  fd_cluster_version_t * cluster_version = fd_bank_cluster_version_modify( bank );
  if( FD_UNLIKELY( sscanf( tile->replay.cluster_version, "%u.%u.%u", &cluster_version->major, &cluster_version->minor, &cluster_version->patch )!=3 ) ) {
    FD_LOG_ERR(( "failed to decode cluster version, configured as \"%s\"", tile->replay.cluster_version ));
  }

  fd_features_t * features = fd_bank_features_modify( bank );
  fd_features_enable_cleaned_up( features, cluster_version );

  char const * one_off_features[ 16UL ];
  FD_TEST( tile->replay.enable_features_cnt<=sizeof(one_off_features)/sizeof(one_off_features[0]) );
  for( ulong i=0UL; i<tile->replay.enable_features_cnt; i++ ) one_off_features[ i ] = tile->replay.enable_features[i];
  fd_features_enable_one_offs( features, one_off_features, (uint)tile->replay.enable_features_cnt, 0UL );

  FD_TEST( fd_accdb_admin_join    ( ctx->accdb_admin,     fd_topo_obj_laddr( topo, tile->replay.funk_obj_id      ) ) );
  FD_TEST( fd_accdb_user_join     ( ctx->accdb,           fd_topo_obj_laddr( topo, tile->replay.funk_obj_id      ) ) );
  FD_TEST( fd_progcache_admin_join( ctx->progcache_admin, fd_topo_obj_laddr( topo, tile->replay.progcache_obj_id ) ) );

  void * _txncache_shmem = fd_topo_obj_laddr( topo, tile->replay.txncache_obj_id );
  fd_txncache_shmem_t * txncache_shmem = fd_txncache_shmem_join( _txncache_shmem );
  FD_TEST( txncache_shmem );
  ctx->txncache = fd_txncache_join( fd_txncache_new( _txncache, txncache_shmem ) );
  FD_TEST( ctx->txncache );

  ctx->capture_ctx = NULL;
  if( FD_UNLIKELY( strcmp( "", tile->replay.solcap_capture ) || strcmp( "", tile->replay.dump_proto_dir ) ) ) {
    ctx->capture_ctx = fd_capture_ctx_join( fd_capture_ctx_new( _capture_ctx ) );
  }

  if( FD_UNLIKELY( strcmp( "", tile->replay.solcap_capture ) ) ) {
    ctx->capture_ctx->checkpt_freq = ULONG_MAX;
    ctx->capture_file = fopen( tile->replay.solcap_capture, "w+" );
    if( FD_UNLIKELY( !ctx->capture_file ) ) FD_LOG_ERR(( "fopen(%s) failed (%d-%s)", tile->replay.solcap_capture, errno, fd_io_strerror( errno ) ));

    ctx->capture_ctx->capture_txns = 0;
    ctx->capture_ctx->solcap_start_slot = tile->replay.capture_start_slot;
    fd_solcap_writer_init( ctx->capture_ctx->capture, ctx->capture_file );
  }

  if( FD_UNLIKELY( strcmp( "", tile->replay.dump_proto_dir ) ) ) {
    ctx->capture_ctx->dump_proto_output_dir = tile->replay.dump_proto_dir;
    if( FD_LIKELY( tile->replay.dump_block_to_pb ) ) ctx->capture_ctx->dump_block_to_pb = tile->replay.dump_block_to_pb;
  }

  if( FD_UNLIKELY( tile->replay.dump_block_to_pb ) ) {
    ctx->block_dump_ctx = fd_block_dump_context_join( fd_block_dump_context_new( block_dump_ctx ) );
  } else {
    ctx->block_dump_ctx = NULL;
  }

  ctx->exec_cnt = fd_topo_tile_name_cnt( topo, "exec" );

  ctx->is_booted = 0;

  ctx->reasm = fd_reasm_join( fd_reasm_new( reasm_mem, 1 << 20, 0 ) );
  FD_TEST( ctx->reasm );

  ctx->sched = fd_sched_join( fd_sched_new( sched_mem, tile->replay.max_live_slots, ctx->exec_cnt ), tile->replay.max_live_slots );
  FD_TEST( ctx->sched );

  ctx->enable_bank_hash_cmp = !!tile->replay.enable_bank_hash_cmp;

  ulong bank_hash_cmp_obj_id = fd_pod_query_ulong( topo->props, "bh_cmp", ULONG_MAX );
  FD_TEST( bank_hash_cmp_obj_id!=ULONG_MAX );
  ctx->bank_hash_cmp = fd_bank_hash_cmp_join( fd_bank_hash_cmp_new( fd_topo_obj_laddr( topo, bank_hash_cmp_obj_id ) ) );
  FD_TEST( ctx->bank_hash_cmp );

  ctx->vote_tracker = fd_vote_tracker_join( fd_vote_tracker_new( vote_tracker_mem, 0UL ) );
  FD_TEST( ctx->vote_tracker );

  ctx->has_identity_vote_rooted = 0;

  ctx->mleaders = fd_multi_epoch_leaders_join( fd_multi_epoch_leaders_new( ctx->mleaders_mem ) );
  FD_TEST( ctx->mleaders );

  ctx->is_leader             = 0;
  ctx->reset_slot            = 0UL;
  ctx->reset_bank            = NULL;
  ctx->reset_block_id        = (fd_hash_t){ .ul[0] = FD_RUNTIME_INITIAL_BLOCK_ID };
  ctx->reset_timestamp_nanos = 0UL;
  ctx->next_leader_slot      = ULONG_MAX;
  ctx->next_leader_tickcount = LONG_MAX;
  ctx->highwater_leader_slot = ULONG_MAX;
  ctx->slot_duration_nanos   = 400L*1000L*1000L; /* TODO: Not fixed ... not always 400ms ... */
  ctx->slot_duration_ticks   = (double)ctx->slot_duration_nanos*fd_tempo_tick_per_ns( NULL );
  ctx->leader_bank           = NULL;

  /* TODO: We need a real seed here. */
  ctx->block_id_len = tile->replay.max_live_slots;
  ctx->block_id_arr = (fd_block_id_ele_t *)block_id_arr_mem;
  ctx->block_id_map = fd_block_id_map_join( fd_block_id_map_new( block_id_map_mem, chain_cnt, 999UL ) );
  FD_TEST( ctx->block_id_map );

  for( ulong i=0UL; i<tile->replay.max_live_slots; i++ ) {
    ctx->block_id_arr[ i ].slot = FD_SLOT_NULL;
  }

  ctx->resolv_tile_cnt = fd_topo_tile_name_cnt( topo, "resolv" );

  FD_TEST( tile->in_cnt<=sizeof(ctx->in)/sizeof(ctx->in[0]) );
  for( ulong i=0UL; i<tile->in_cnt; i++ ) {
    fd_topo_link_t * link = &topo->links[ tile->in_link_id[ i ] ];
    fd_topo_wksp_t * link_wksp = &topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ];

    if( FD_LIKELY( link->dcache ) ) {
      ctx->in[ i ].mem    = link_wksp->wksp;
      ctx->in[ i ].chunk0 = fd_dcache_compact_chunk0( ctx->in[ i ].mem, link->dcache );
      ctx->in[ i ].wmark  = fd_dcache_compact_wmark ( ctx->in[ i ].mem, link->dcache, link->mtu );
      ctx->in[ i ].mtu    = link->mtu;
    }

    if(      !strcmp( link->name, "genesi_out"   ) ) ctx->in_kind[ i ] = IN_KIND_GENESIS;
    else if( !strcmp( link->name, "ipecho_out"   ) ) ctx->in_kind[ i ] = IN_KIND_IPECHO;
    else if( !strcmp( link->name, "snapin_manif" ) ) ctx->in_kind[ i ] = IN_KIND_SNAP;
    else if( !strcmp( link->name, "exec_replay"  ) ) ctx->in_kind[ i ] = IN_KIND_EXEC;
    else if( !strcmp( link->name, "tower_out"    ) ) ctx->in_kind[ i ] = IN_KIND_TOWER;
    else if( !strcmp( link->name, "poh_replay"   ) ) ctx->in_kind[ i ] = IN_KIND_POH;
    else if( !strcmp( link->name, "resolv_repla" ) ) ctx->in_kind[ i ] = IN_KIND_RESOLV;
    else if( !strcmp( link->name, "shred_out"    ) ) ctx->in_kind[ i ] = IN_KIND_SHRED;
    else if( !strcmp( link->name, "send_out"     ) ) ctx->in_kind[ i ] = IN_KIND_VTXN;
    else if( !strcmp( link->name, "gui_replay"   ) ) ctx->in_kind[ i ] = IN_KIND_GUI;
    else FD_LOG_ERR(( "unexpected input link name %s", link->name ));
  }

  *ctx->stake_out  = out1( topo, tile, "replay_stake" ); FD_TEST( ctx->stake_out->idx!=ULONG_MAX );
  *ctx->replay_out = out1( topo, tile, "replay_out" ); FD_TEST( ctx->replay_out->idx!=ULONG_MAX );

  ulong idx = fd_topo_find_tile_out_link( topo, tile, "replay_exec", 0UL );
  FD_TEST( idx!=ULONG_MAX );
  fd_topo_link_t * link = &topo->links[ tile->out_link_id[ idx ] ];

  fd_replay_out_link_t * exec_out = ctx->exec_out;
  exec_out->idx    = idx;
  exec_out->mem    = topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ].wksp;
  exec_out->chunk0 = fd_dcache_compact_chunk0( exec_out->mem, link->dcache );
  exec_out->wmark  = fd_dcache_compact_wmark( exec_out->mem, link->dcache, link->mtu );
  exec_out->chunk  = exec_out->chunk0;

  ctx->gui_enabled = fd_topo_find_tile( topo, "gui", 0UL )!=ULONG_MAX;

  fd_memset( &ctx->metrics, 0, sizeof(ctx->metrics) );

  fd_histf_join( fd_histf_new( ctx->metrics.store_link_wait,    FD_MHIST_SECONDS_MIN( REPLAY, STORE_LINK_WAIT ),
                                                                FD_MHIST_SECONDS_MAX( REPLAY, STORE_LINK_WAIT ) ) );
  fd_histf_join( fd_histf_new( ctx->metrics.store_link_work,    FD_MHIST_SECONDS_MIN( REPLAY, STORE_LINK_WORK ),
                                                                FD_MHIST_SECONDS_MAX( REPLAY, STORE_LINK_WORK ) ) );
  fd_histf_join( fd_histf_new( ctx->metrics.store_read_wait,    FD_MHIST_SECONDS_MIN( REPLAY, STORE_READ_WAIT ),
                                                                FD_MHIST_SECONDS_MAX( REPLAY, STORE_READ_WAIT ) ) );
  fd_histf_join( fd_histf_new( ctx->metrics.store_read_work,    FD_MHIST_SECONDS_MIN( REPLAY, STORE_READ_WORK ),
                                                                FD_MHIST_SECONDS_MAX( REPLAY, STORE_READ_WORK ) ) );
  fd_histf_join( fd_histf_new( ctx->metrics.store_publish_wait, FD_MHIST_SECONDS_MIN( REPLAY, STORE_PUBLISH_WAIT ),
                                                                FD_MHIST_SECONDS_MAX( REPLAY, STORE_PUBLISH_WAIT ) ) );
  fd_histf_join( fd_histf_new( ctx->metrics.store_publish_work, FD_MHIST_SECONDS_MIN( REPLAY, STORE_PUBLISH_WORK ),
                                                                FD_MHIST_SECONDS_MAX( REPLAY, STORE_PUBLISH_WORK ) ) );

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, 1UL );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo FD_FN_UNUSED,
                          fd_topo_tile_t const * tile FD_FN_UNUSED,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {

  populate_sock_filter_policy_fd_replay_tile( out_cnt, out, (uint)fd_log_private_logfile_fd() );
  return sock_filter_policy_fd_replay_tile_instr_cnt;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo FD_FN_UNUSED,
                      fd_topo_tile_t const * tile FD_FN_UNUSED,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {

  if( FD_UNLIKELY( out_fds_cnt<2UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  return out_cnt;
}

#undef DEBUG_LOGGING

/* counting carefully, after_credit can generate at most 7 frags and
   returnable_frag boot_genesis can also generate at most 7 frags, so 14
   is a conservative bound. */
#define STEM_BURST (14UL)

/* TODO: calculate this properly/fix stem to work with larger numbers of links */
/* 1000 chosen empirically as anything larger slowed down replay times. Need to calculate
   this properly. */
#define STEM_LAZY ((long)10e3)

#define STEM_CALLBACK_CONTEXT_TYPE  fd_replay_tile_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_replay_tile_t)

#define STEM_CALLBACK_METRICS_WRITE   metrics_write
#define STEM_CALLBACK_AFTER_CREDIT    after_credit
#define STEM_CALLBACK_BEFORE_FRAG     before_frag
#define STEM_CALLBACK_RETURNABLE_FRAG returnable_frag

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_replay = {
  .name                     = "replay",
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};
