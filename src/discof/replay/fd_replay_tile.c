#include "fd_exec.h"
#include "generated/fd_replay_tile_seccomp.h"

#include "fd_replay_notif.h"
#include "../poh/fd_poh.h"
#include "../tower/fd_tower_tile.h"
#include "../restore/utils/fd_ssload.h"

#include "../../disco/tiles.h"
#include "../../disco/store/fd_store.h"
#include "../../discof/reasm/fd_reasm.h"
#include "../../discof/replay/fd_exec.h"
#include "../../disco/keyguard/fd_keyload.h"
#include "../../util/pod/fd_pod.h"
#include "../../flamenco/rewards/fd_rewards.h"
#include "../../flamenco/leaders/fd_multi_epoch_leaders.h"
#include "../../disco/metrics/fd_metrics.h"
#include "../../choreo/fd_choreo_base.h"

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

/* An estimate of the max number of transactions in a block.  If there are more
   transactions, they must be split into multiple sets. */
#define MAX_TXNS_PER_REPLAY ( ( FD_SHRED_BLK_MAX * FD_SHRED_MAX_SZ) / FD_TXN_MIN_SERIALIZED_SZ )

#define IN_KIND_REPAIR  (0)
#define IN_KIND_SNAP    (1)
#define IN_KIND_TOWER   (2)
#define IN_KIND_WRITER  (3)
#define IN_KIND_CAPTURE (4)
#define IN_KIND_POH     (5)

#define EXEC_SLICE_DEQUE_MAX (65536UL)

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

/* FIXME this is a temporary workaround because our bank is missing an
   important field block_id. This map can removed once that's fixed, and
   the slot->block_id is bank_mgr_query_bank(slot)->block_id. */

typedef struct {
  ulong     slot;
  fd_hash_t block_id;
} block_id_map_t;

#define MAP_NAME          block_id_map
#define MAP_T             block_id_map_t
#define MAP_KEY           slot
#define MAP_KEY_NULL      ULONG_MAX
#define MAP_KEY_INVAL(k) (ULONG_MAX==(k))
#define MAP_MEMOIZE 0
#include "../../util/tmpl/fd_map_dynamic.c"

#define MERKLES_MAX 1024 /* FIXME: hack for bounding # of merkle roots.
                            FEC sets are accumulated into entry batches.
                            1024 * 32 shreds = 32768 (max per slot).
                            Remove with new dispatcher. */

struct fd_exec_slice { /* FIXME: deleted with new dispatcher */
  ulong     slot;
  ushort    parent_off;
  int       slot_complete;
  uint      data_cnt;
  fd_hash_t merkles[MERKLES_MAX];
  ulong     merkles_cnt;
  /* Parent block_id of the first fec in the slice. */
  fd_hash_t parent_merkle_hash;
};
typedef struct fd_exec_slice fd_exec_slice_t;

#define MAP_NAME     fd_exec_slice_map
#define MAP_T        fd_exec_slice_t
#define MAP_KEY      slot
#define MAP_MEMOIZE  0
#include "../../util/tmpl/fd_map_dynamic.c"

#define DEQUE_NAME fd_exec_slice_deque
#define DEQUE_T    fd_exec_slice_t
#define DEQUE_MAX  USHORT_MAX
#include "../../util/tmpl/fd_deque_dynamic.c"

FD_STATIC_ASSERT( FD_PACK_MAX_BANK_TILES<=64UL, exec_bitset );

struct fd_replay_tile {
  fd_wksp_t * wksp;

  /* Inputs to plugin/gui */
  fd_replay_out_link_t plugin_out[1];
  fd_replay_out_link_t votes_plugin_out[1];
  long                 last_plugin_push_time;

  /* tx_metadata_storage enables the log collector if enabled */
  int tx_metadata_storage;

  int bootstrap;
  char genesis_path[ PATH_MAX ];

  /* Funk */
  fd_funk_t funk[1];

  /* Store */
  fd_store_t * store;

  /* Banks */
  fd_banks_t * banks;

  /* Maps slot to block id */
  block_id_map_t * block_id_map;

  /* slot_ctx is a wrapper used across the execution pipeline as a
     wrapper around funk, banks, and the capture ctx.  */
  fd_exec_slot_ctx_t * slot_ctx;

  /* slice_exec_ctx is used to maintain state as all of the transactions
     and/or microblocks from a slice are consumed and execued.
     TODO: This should get removed with the replay dispatcher. */
  fd_slice_exec_t slice_exec_ctx;

  /* TODO: Some of these arrays should be bitvecs that get masked into. */
  ulong                exec_cnt;
  ulong                exec_ready_bitset;                  /* Is tile ready */
  fd_replay_out_link_t exec_out[ FD_PACK_MAX_BANK_TILES ]; /* Sending to exec unexecuted txns */

  /* State tracking for exec slices.
     TODO: This should get removed with the replay dispatcher. */
  fd_exec_slice_t * exec_slice_map;
  fd_exec_slice_t * exec_slice_deque; /* Deque to buffer exec slices */

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
     concurrent activity, such as transaction execution through the
     exec-writer pipeline, should retain a refcnt on the block for as
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
  fd_hash_t consensus_root; /* The most recent block to have reached max lockout in the tower. */
  ulong     consensus_root_slot;

  /* Capture-related configs */
  fd_capture_ctx_t * capture_ctx;
  FILE *             capture_file;

  /* Whether the runtime has been booted either from snapshot loading
     or from genesis.*/
  int is_booted;

  /* Stack allocator for slot boundary allocations.
     TODO: Should be replaced by tile-level allocations. */
  fd_spad_t * runtime_spad;

  /* Bank hash cmp.  Maintains and compares bank hashes seen from votes
     against ones produced by the client. */
  fd_bank_hash_cmp_t * bank_hash_cmp;
  ulong                enable_bank_hash_cmp;

  /* Buffer to store vote towers that need to be published to the Tower
     tile. */
  ulong             vote_tower_out_idx; /* index of vote tower to publish next */
  ulong             vote_tower_out_len; /* number of vote towers in the buffer */
  fd_replay_tower_t vote_tower_out[FD_REPLAY_TOWER_VOTE_ACC_MAX];

  fd_multi_epoch_leaders_t * mleaders;

  fd_pubkey_t identity_pubkey[1]; /* TODO: Keyswitch */

  int    is_leader;
  ulong  next_leader_slot;
  ulong  highwater_leader_slot;
  ulong  reset_slot;
  long   reset_timestamp_nanos;
  double slot_duration_nanos;
  ulong  max_active_descendant;

  int in_kind[ 64 ];
  fd_replay_in_link_t in[ 64 ];

  fd_replay_out_link_t notif_out[1];
  fd_replay_out_link_t stake_out[1];
  fd_replay_out_link_t shredcap_out[1];
  fd_replay_out_link_t tower_out[1];
  fd_replay_out_link_t replay_out[1];
  fd_replay_out_link_t pack_out[1];

  struct {
    fd_histf_t store_read_wait[ 1 ];
    fd_histf_t store_read_work[ 1 ];
    fd_histf_t store_publish_wait[ 1 ];
    fd_histf_t store_publish_work[ 1 ];
  } metrics;

  uchar __attribute__((aligned(FD_MULTI_EPOCH_LEADERS_ALIGN))) mleaders_mem[ FD_MULTI_EPOCH_LEADERS_FOOTPRINT ];
};

typedef struct fd_replay_tile fd_replay_tile_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 128UL;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_replay_tile_t),   sizeof(fd_replay_tile_t) );
  l = FD_LAYOUT_APPEND( l, FD_CAPTURE_CTX_ALIGN,        FD_CAPTURE_CTX_FOOTPRINT );
  l = FD_LAYOUT_APPEND( l, block_id_map_align(),        block_id_map_footprint( fd_ulong_find_msb( fd_ulong_pow2_up( FD_BLOCK_MAX ) ) ) );
  l = FD_LAYOUT_APPEND( l, 128UL,                       FD_SLICE_MAX );
  l = FD_LAYOUT_APPEND( l, fd_exec_slice_map_align(),   fd_exec_slice_map_footprint( 20 ) );
  l = FD_LAYOUT_APPEND( l, fd_spad_align(),             fd_spad_footprint( tile->replay.heap_size_gib<<30 ) );
  l = FD_LAYOUT_APPEND( l, alignof(fd_exec_slot_ctx_t), sizeof(fd_exec_slot_ctx_t) );
  l = FD_LAYOUT_APPEND( l, fd_exec_slice_deque_align(), fd_exec_slice_deque_footprint( EXEC_SLICE_DEQUE_MAX ) );
  l = FD_LAYOUT_FINI  ( l, scratch_align() );
  return l;
}

static inline void
metrics_write( fd_replay_tile_t * ctx ) {
  FD_MHIST_COPY( REPLAY, STORE_READ_WAIT,    ctx->metrics.store_read_wait );
  FD_MHIST_COPY( REPLAY, STORE_READ_WORK,    ctx->metrics.store_read_work );
  FD_MHIST_COPY( REPLAY, STORE_PUBLISH_WAIT, ctx->metrics.store_publish_wait );
  FD_MHIST_COPY( REPLAY, STORE_PUBLISH_WORK, ctx->metrics.store_publish_work );
}

static void
publish_stake_weights( fd_replay_tile_t *   ctx,
                       fd_stem_context_t *  stem,
                       fd_exec_slot_ctx_t * slot_ctx,
                       int                  current_epoch ) {
  fd_epoch_schedule_t const * schedule = fd_bank_epoch_schedule_query( slot_ctx->bank );
  ulong epoch = fd_slot_to_epoch( schedule, fd_bank_slot_get( slot_ctx->bank ), NULL );

  fd_vote_states_t const * vote_states_prev;
  if( FD_LIKELY( current_epoch ) ) vote_states_prev = fd_bank_vote_states_prev_locking_query( slot_ctx->bank );
  else                             vote_states_prev = fd_bank_vote_states_prev_prev_locking_query( ctx->slot_ctx->bank );

  ulong * stake_weights_msg = fd_chunk_to_laddr( ctx->stake_out->mem, ctx->stake_out->chunk );
  ulong stake_weights_sz = generate_stake_weight_msg( epoch+fd_ulong_if( current_epoch, 1UL, 0UL), schedule, vote_states_prev, stake_weights_msg );
  ulong stake_weights_sig = 4UL;
  fd_stem_publish( stem, ctx->stake_out->idx, stake_weights_sig, ctx->stake_out->chunk, stake_weights_sz, 0UL, 0UL, fd_frag_meta_ts_comp( fd_tickcount() ) );
  ctx->stake_out->chunk = fd_dcache_compact_next( ctx->stake_out->chunk, stake_weights_sz, ctx->stake_out->chunk0, ctx->stake_out->wmark );

  FD_LOG_NOTICE(( "sending stake weights for epoch %lu (slot %lu - %lu) with %lu stakes", stake_weights_msg[ 0 ], stake_weights_msg[ 2 ], stake_weights_msg[ 3 ], stake_weights_msg[ 1 ] ));

  if( FD_LIKELY( current_epoch ) ) fd_bank_vote_states_prev_end_locking_query( slot_ctx->bank );
  else                             fd_bank_vote_states_prev_prev_end_locking_query( ctx->slot_ctx->bank );

  fd_multi_epoch_leaders_stake_msg_init( ctx->mleaders, fd_type_pun_const( stake_weights_msg ) );
  fd_multi_epoch_leaders_stake_msg_fini( ctx->mleaders );
}

static void
publish_slot_notifications( fd_replay_tile_t *  ctx,
                            fd_stem_context_t * stem,
                            ulong               block_entry_block_height,
                            ulong               curr_slot ) {
  if( FD_LIKELY( ctx->notif_out->idx==ULONG_MAX ) ) return;

  FD_TEST( curr_slot==fd_bank_slot_get( ctx->slot_ctx->bank ) );

  fd_epoch_schedule_t const * epoch_schedule = fd_bank_epoch_schedule_query( ctx->slot_ctx->bank );
  ulong slot_idx;
  ulong epoch = fd_slot_to_epoch( epoch_schedule, curr_slot, &slot_idx );

  fd_replay_notif_msg_t * msg = fd_chunk_to_laddr( ctx->notif_out->mem, ctx->notif_out->chunk );
  msg->slot_exec.ts                = fd_log_wallclock();
  msg->type                        = FD_REPLAY_SLOT_TYPE;
  msg->slot_exec.slot              = curr_slot;
  msg->slot_exec.epoch             = epoch;
  msg->slot_exec.slot_in_epoch     = slot_idx;
  msg->slot_exec.parent            = fd_bank_parent_slot_get( ctx->slot_ctx->bank );
  msg->slot_exec.root              = ctx->consensus_root_slot;
  msg->slot_exec.height            = block_entry_block_height;
  msg->slot_exec.transaction_count = fd_bank_txn_count_get( ctx->slot_ctx->bank );
  msg->slot_exec.shred_cnt         = fd_bank_shred_cnt_get( ctx->slot_ctx->bank );
  msg->slot_exec.bank_hash         = fd_bank_bank_hash_get( ctx->slot_ctx->bank );

  fd_blockhashes_t const * block_hash_queue = fd_bank_block_hash_queue_query( ctx->slot_ctx->bank );
  fd_hash_t const * last_hash = fd_blockhashes_peek_last( block_hash_queue );
  FD_TEST( last_hash );
  msg->slot_exec.block_hash = *last_hash;

  fd_stem_publish( stem, ctx->notif_out->idx, 0UL, ctx->notif_out->chunk, sizeof(fd_replay_notif_msg_t), 0UL, 0UL, fd_frag_meta_ts_comp( fd_tickcount() ) );
  ctx->notif_out->chunk = fd_dcache_compact_next( ctx->notif_out->chunk, sizeof(fd_replay_notif_msg_t), ctx->notif_out->chunk0, ctx->notif_out->wmark );
  fd_bank_shred_cnt_set( ctx->slot_ctx->bank, 0UL );
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
   - Vote account is not found in Funk (returns -1)
   - Account metadata has wrong magic (returns -1) */
static int
fd_replay_out_vote_tower_from_funk(
  fd_funk_t const *     funk,
  fd_funk_txn_t const * funk_txn,
  fd_pubkey_t const *   pubkey,
  ulong                 stake,
  fd_replay_tower_t *   vote_tower_out ) {

  fd_memset( vote_tower_out, 0, sizeof(fd_replay_tower_t) );
  vote_tower_out->key   = *pubkey;
  vote_tower_out->stake = stake;

  /* Speculatively copy out the raw vote account state from Funk */
  for(;;) {
    fd_memset( vote_tower_out->acc, 0, sizeof(vote_tower_out->acc) );

    fd_funk_rec_query_t query;
    fd_funk_rec_key_t funk_key = fd_funk_acc_key( pubkey );
    fd_funk_rec_t const * rec = fd_funk_rec_query_try_global( funk, funk_txn, &funk_key, NULL, &query );
    if( FD_UNLIKELY( !rec ) ) {
      FD_LOG_WARNING(( "vote account not found. address: %s",
        FD_BASE58_ENC_32_ALLOCA( pubkey->uc ) ));
      return -1;
    }

    uchar const * raw                  = fd_funk_val_const( rec, fd_funk_wksp(funk) );
    fd_account_meta_t const * metadata = fd_type_pun_const( raw );

    ulong data_sz = metadata->dlen;
    if( FD_UNLIKELY( data_sz > sizeof(vote_tower_out->acc) ) ) {
      FD_LOG_WARNING(( "vote account %s has too large data. dlen %lu > %lu",
        FD_BASE58_ENC_32_ALLOCA( pubkey->uc ),
        data_sz,
        sizeof(vote_tower_out->acc) ));
      return -1;
    }

    fd_memcpy( vote_tower_out->acc, raw + sizeof(fd_account_meta_t), data_sz );
    vote_tower_out->acc_sz = (ushort)data_sz;

    if( FD_LIKELY( fd_funk_rec_query_test( &query ) == FD_FUNK_SUCCESS ) ) {
      break;
    }
  }

  return 0;
}

/* This function buffers all the vote account towers that Tower needs at the end of this slot
   into the ctx->vote_tower_out buffer. These will then be published in after_credit.

   This function should be called at the end of a slot, before any epoch boundary processing. */
static void
buffer_vote_towers( fd_replay_tile_t * ctx ) {
  ctx->vote_tower_out_idx = 0;
  ctx->vote_tower_out_len = 0;

  fd_vote_states_t const * vote_states = fd_bank_vote_states_prev_locking_query( ctx->slot_ctx->bank );
  fd_vote_states_iter_t iter_[1];
  for( fd_vote_states_iter_t * iter = fd_vote_states_iter_init( iter_, vote_states );
       !fd_vote_states_iter_done( iter );
       fd_vote_states_iter_next( iter ) ) {
    fd_vote_state_ele_t const * vote_state = fd_vote_states_iter_ele( iter );
    if( FD_UNLIKELY( vote_state->stake == 0 ) ) continue; /* skip unstaked vote accounts */
    fd_pubkey_t const * vote_account_pubkey = &vote_state->vote_account;
    if( FD_UNLIKELY( ctx->vote_tower_out_len >= (FD_REPLAY_TOWER_VOTE_ACC_MAX-1UL) ) ) FD_LOG_ERR(( "vote_tower_out_len too large" ));
    if( FD_UNLIKELY( fd_replay_out_vote_tower_from_funk(
      ctx->funk, ctx->slot_ctx->funk_txn, vote_account_pubkey, vote_state->stake, &ctx->vote_tower_out[ctx->vote_tower_out_len++] ) ) ) {
        FD_LOG_ERR(( "failed to get vote state for vote account %s", FD_BASE58_ENC_32_ALLOCA( vote_account_pubkey->uc ) ));
      }
  }
  fd_bank_vote_states_prev_end_locking_query( ctx->slot_ctx->bank );
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

  fd_replay_tower_t * vote_state = fd_chunk_to_laddr( ctx->tower_out->mem, ctx->tower_out->chunk );
  *vote_state = ctx->vote_tower_out[ ctx->vote_tower_out_idx ];
  fd_stem_publish(
    stem,
    ctx->tower_out->idx,
    FD_REPLAY_SIG_VOTE_STATE,
    ctx->tower_out->chunk,
    sizeof(fd_replay_tower_t),
    fd_frag_meta_ctl( 0UL, som, eom, 0 ),
    fd_frag_meta_ts_comp( fd_tickcount() ),
    fd_frag_meta_ts_comp( fd_tickcount() ) );
    ctx->tower_out->chunk = fd_dcache_compact_next(
      ctx->tower_out->chunk,
      sizeof(fd_replay_tower_t),
      ctx->tower_out->chunk0,
      ctx->tower_out->wmark );

  ctx->vote_tower_out_idx++;
}

/**********************************************************************/
/* Transaction execution state machine helpers                        */
/**********************************************************************/

static void
handle_existing_block( fd_replay_tile_t * ctx,
                       fd_hash_t *        merkle_hash ) {

  ctx->slot_ctx->bank = fd_banks_get_bank( ctx->banks, merkle_hash );
  if( FD_UNLIKELY( !ctx->slot_ctx->bank ) ) {
    FD_LOG_CRIT(( "invariant violation: bank is NULL" ));
  }

  ulong slot = fd_bank_slot_get( ctx->slot_ctx->bank );

  fd_funk_txn_map_t * txn_map = fd_funk_txn_map( ctx->funk );
  fd_funk_txn_xid_t   xid     = { .ul = { slot, slot } };
  ctx->slot_ctx->funk_txn = fd_funk_txn_query( &xid, txn_map );
  if( FD_UNLIKELY( !ctx->slot_ctx->funk_txn ) ) {
    FD_LOG_CRIT(( "invariant violation: funk_txn is NULL for slot %lu", slot ));
  }
}

static fd_bank_t *
prepare_leader_bank( fd_replay_tile_t *  ctx,
                     ulong               slot,
                     ulong               parent_slot,
                     fd_stem_context_t * stem ) {

  block_id_map_t * block_id = block_id_map_query( ctx->block_id_map, parent_slot, NULL );
  fd_hash_t parent_key = {0};
  if( !block_id ) { /* parent was a leader */
    parent_key.ul[0] = parent_slot;
  } else {
    parent_key = block_id->block_id;
  }

  fd_hash_t leader_hash = { .ul[0] = slot };

  fd_bank_t * bank = fd_banks_clone_from_parent( ctx->banks, &leader_hash, &parent_key );

  /* prepare the funk transaction for the leader bank */
  fd_funk_txn_start_write( ctx->funk );

  fd_funk_txn_xid_t xid        = { .ul = { slot, slot } };
  fd_funk_txn_xid_t parent_xid = { .ul = { parent_slot, parent_slot } };

  fd_funk_txn_map_t * txn_map = fd_funk_txn_map( ctx->funk );
  if( FD_UNLIKELY( !txn_map ) ) {
    FD_LOG_CRIT(( "invariant violation: funk_txn_map is NULL for slot %lu", slot ));
  }

  fd_funk_txn_t * parent_txn = fd_funk_txn_query( &parent_xid, txn_map );

  fd_funk_txn_t * funk_txn = fd_funk_txn_prepare( ctx->funk, parent_txn, &xid, 1 );
  if( FD_UNLIKELY( !funk_txn ) ) {
    FD_LOG_CRIT(( "invariant violation: funk_txn is NULL for slot %lu", slot ));
  }

  fd_bank_done_executing_set( bank, 0 );

  fd_bank_slot_set( bank, slot );

  /* Set the parent slot. */
  fd_bank_parent_slot_set( bank, parent_slot );

  /* Set the tick height. */
  fd_bank_tick_height_set( bank, fd_bank_max_tick_height_get( bank ) );

  /* Update block height. */
  fd_bank_block_height_set( bank, fd_bank_block_height_get( bank ) + 1UL );

  ulong * max_tick_height = fd_bank_max_tick_height_modify( bank );
  ulong   ticks_per_slot  = fd_bank_ticks_per_slot_get( bank );
  if( FD_UNLIKELY( FD_RUNTIME_EXECUTE_SUCCESS != fd_runtime_compute_max_tick_height( ticks_per_slot, slot, max_tick_height ) ) ) {
    FD_LOG_CRIT(( "couldn't compute tick height/max tick height slot %lu ticks_per_slot %lu", slot, ticks_per_slot ));
  }

  bank->flags |= fd_ulong_if( ctx->tx_metadata_storage, FD_BANK_FLAGS_EXEC_RECORDING, 0UL );

  fd_exec_slot_ctx_t slot_ctx = {
    .bank     = bank,
    .funk     = ctx->funk,
    .banks    = ctx->banks,
    .funk_txn = funk_txn,
  };

  int is_epoch_boundary = 0;
  fd_runtime_block_pre_execute_process_new_epoch(
      &slot_ctx,
      ctx->capture_ctx,
      ctx->runtime_spad,
      &is_epoch_boundary );
  if( FD_UNLIKELY( is_epoch_boundary ) ) publish_stake_weights( ctx, stem, &slot_ctx, 1 );

  int res = fd_runtime_block_execute_prepare( &slot_ctx, ctx->runtime_spad );
  if( FD_UNLIKELY( res!=FD_RUNTIME_EXECUTE_SUCCESS ) ) {
    FD_LOG_CRIT(( "block prep execute failed" ));
  }

  bank->refcnt++;

  return bank;
}

static void
handle_new_block( fd_replay_tile_t *  ctx,
                  fd_stem_context_t * stem,
                  ulong               slot,
                  ulong               parent_slot,
                  fd_hash_t *         merkle_hash,
                  fd_hash_t *         parent_merkle_hash ) {
  /* Switch to a new block that we don't have a bank for. */
  FD_LOG_INFO(( "Creating new bank (slot: %lu, merkle hash: %s; parent slot: %lu, parent_merkle %s) ", slot, FD_BASE58_ENC_32_ALLOCA( merkle_hash ), parent_slot, FD_BASE58_ENC_32_ALLOCA( parent_merkle_hash ) ));

  fd_bank_t * bank = fd_banks_get_bank( ctx->banks, merkle_hash );
  if( FD_UNLIKELY( !!bank ) ) {
    FD_LOG_CRIT(( "invariant violation: block with slot: %lu and merkle hash: %s already exists", slot, FD_BASE58_ENC_32_ALLOCA( merkle_hash ) ));
  }

  /* Clone the bank from the parent.  We must special case the first
     slot that is executed as the snapshot does not provide a parent
     block id. */

  ctx->slot_ctx->bank = fd_banks_clone_from_parent( ctx->banks, merkle_hash, parent_merkle_hash );
  if( FD_UNLIKELY( !ctx->slot_ctx->bank ) ) {
    FD_LOG_CRIT(( "invariant violation: bank is NULL for slot %lu merkle hash %s", slot, FD_BASE58_ENC_32_ALLOCA( merkle_hash ) ));
  }

  /* Create a new funk txn for the block. */

  fd_funk_txn_start_write( ctx->funk );

  fd_funk_txn_xid_t xid        = { .ul = { slot, slot } };
  fd_funk_txn_xid_t parent_xid = { .ul = { parent_slot, parent_slot } };

  fd_funk_txn_map_t * txn_map = fd_funk_txn_map( ctx->funk );
  if( FD_UNLIKELY( !txn_map ) ) {
    FD_LOG_CRIT(( "invariant violation: funk_txn_map is NULL for slot %lu", slot ));
  }

  fd_funk_txn_t * parent_txn = fd_funk_txn_query( &parent_xid, txn_map );

  fd_funk_txn_t * funk_txn = fd_funk_txn_prepare( ctx->funk, parent_txn, &xid, 1 );
  if( FD_UNLIKELY( !funk_txn ) ) {
    FD_LOG_CRIT(( "invariant violation: funk_txn is NULL for slot %lu", slot ));
  }

  ctx->slot_ctx->funk_txn = funk_txn;

  fd_funk_txn_end_write( ctx->funk );

  /* Update any required runtime state and handle any potential epoch
     boundary change. */

  if( ctx->capture_ctx ) {
    fd_solcap_writer_set_slot( ctx->capture_ctx->capture, slot );
  }

  fd_bank_done_executing_set( ctx->slot_ctx->bank, 0 );

  fd_bank_slot_set( ctx->slot_ctx->bank, slot );

  fd_bank_parent_block_id_set( ctx->slot_ctx->bank, *parent_merkle_hash );

  /* Set the parent slot. */
  fd_bank_parent_slot_set( ctx->slot_ctx->bank, parent_slot );

  /* Set the tick height. */
  fd_bank_tick_height_set( ctx->slot_ctx->bank, fd_bank_max_tick_height_get( ctx->slot_ctx->bank ) );

  /* Update block height. */
  fd_bank_block_height_set( ctx->slot_ctx->bank, fd_bank_block_height_get( ctx->slot_ctx->bank ) + 1UL );

  ulong * max_tick_height = fd_bank_max_tick_height_modify( ctx->slot_ctx->bank );
  ulong   ticks_per_slot  = fd_bank_ticks_per_slot_get( ctx->slot_ctx->bank );
  if( FD_UNLIKELY( FD_RUNTIME_EXECUTE_SUCCESS != fd_runtime_compute_max_tick_height(ticks_per_slot, slot, max_tick_height ) ) ) {
    FD_LOG_CRIT(( "couldn't compute tick height/max tick height slot %lu ticks_per_slot %lu", slot, ticks_per_slot ));
  }
  ctx->slot_ctx->bank->flags |= fd_ulong_if( ctx->tx_metadata_storage, FD_BANK_FLAGS_EXEC_RECORDING, 0UL );

  int is_epoch_boundary = 0;
  fd_runtime_block_pre_execute_process_new_epoch(
      ctx->slot_ctx,
      ctx->capture_ctx,
      ctx->runtime_spad,
      &is_epoch_boundary );
  if( FD_UNLIKELY( is_epoch_boundary ) ) publish_stake_weights( ctx, stem, ctx->slot_ctx, 1 );

  int res = fd_runtime_block_execute_prepare( ctx->slot_ctx, ctx->runtime_spad );
  if( FD_UNLIKELY( res!=FD_RUNTIME_EXECUTE_SUCCESS ) ) {
    FD_LOG_CRIT(( "block prep execute failed" ));
  }
}

static void
handle_bank_change( fd_replay_tile_t *  ctx,
                    fd_stem_context_t * stem,
                    ulong               slot,
                    ulong               parent_slot,
                    fd_hash_t *         merkle_hash,
                    fd_hash_t *         parent_merkle_hash ) {

  /* At this point, we've found a slice that we are about to execute.
     So we must make sure that we have a bank to execute against.
     Three things can happen:
     1. We switch to an existing bank to execute against.
        a. This happens if the parent merkle hash of the slice is the
           same as the block_id of some bank that already exists but not
           the current bank.
     2. We create a new bank to execute against.
        a. This happens if the parent merkle hash of the slice
           corresponds to a bank that is done executing. This can be the
           current bank or some other bank that exists.
     3. We continue executing against the current bank.
        a. The parent merkle hash of the slice is the same as the
           current bank's block id and the current bank is not done
           executing.
    TODO: This handles the equivocation case where two block with the
    same slot number share a parent block id of a completed block (the
    equivocation happened off of a completed block and the equivocated
    block shares no fec sets). However, this does NOT handle the case
    where there is an equivocated block where the two blocks share some
    initial amount of FEC sets.
  */

  fd_hash_t parent_leader_hash = { .ul[0] = parent_slot };

  fd_bank_t * parent_bank = fd_banks_get_bank( ctx->banks, parent_merkle_hash );
  if( FD_UNLIKELY( !parent_bank ) ) {
    parent_bank = fd_banks_get_bank( ctx->banks, &parent_leader_hash );
    parent_merkle_hash = &parent_leader_hash;
    if( FD_UNLIKELY( !parent_bank ) ) {
      fd_banks_print( ctx->banks );
      FD_LOG_CRIT(( "invariant violation: parent bank is NULL for slot %lu parent leader hash %lu", slot, parent_slot ));
    }
  }

  if( fd_bank_done_executing_get( parent_bank ) ) {;
    /* Create a new bank. */
    handle_new_block( ctx, stem, slot, parent_slot, merkle_hash, parent_merkle_hash );
  } else if( ctx->slot_ctx->bank!=parent_bank  ) {
    /* We have already have a bank for the slot we are executing. And it
       is different from the current bank. */
    handle_existing_block( ctx, parent_merkle_hash );
  } else {
    /* Don't change the bank that is current executing. */
  }
}

static void
handle_new_slice( fd_replay_tile_t *  ctx,
                  fd_stem_context_t * stem ) {
  /* If there are no slices in slice deque, then there is nothing to
     execute. */
  if( FD_UNLIKELY( fd_exec_slice_deque_cnt( ctx->exec_slice_deque )==0UL ) ) {
    return;
  }
  if( FD_UNLIKELY( ctx->consensus_root_slot==ULONG_MAX ) ) { /* banks is not initialized yet */
    return;
  }

  fd_exec_slice_t slice = fd_exec_slice_deque_pop_head( ctx->exec_slice_deque );

  /* Pop the head of the slice deque and do some basic sanity checks. */
  ulong  slot          = slice.slot;
  ushort parent_off    = slice.parent_off;
  uint   data_cnt      = slice.data_cnt;
  int    slot_complete = slice.slot_complete;
  ulong  parent_slot   = slot - parent_off;

  /* We want to abandon FECs for slots that we were leader on. */
  fd_hash_t leader_hash = { .ul[0] = slot };
  if( FD_UNLIKELY( fd_banks_get_bank( ctx->banks, &leader_hash ) ) ) {
    FD_LOG_WARNING(( "abandoning slice for slot %lu because we were leader on it", slot ));
    return;
  }

  /* Read the slice from the store.  This should happen before we try to
     find a bank to execute against.  This allows us to filter out frags
     that were in-flight when we published away minority forks that the
     frags land on.  These frags would have no bank to execute against,
     because their corresponding banks, or parent banks, have also been
     pruned during publishing.  A query against store will rightfully
     tell us that the underlying data is not found, implying that this
     is for a minority fork that we can safely ignore. */
  long shacq_start, shacq_end, shrel_end;
  ulong slice_sz = 0;
  FD_STORE_SHARED_LOCK( ctx->store, shacq_start, shacq_end, shrel_end ) {
    for( ulong i = 0; i < slice.merkles_cnt; i++ ) {
      fd_store_fec_t * fec = fd_store_query( ctx->store, &slice.merkles[i] );
      if( FD_UNLIKELY( !fec ) ) {

        /* The only case in which a FEC is not found in the store after
           repair has notified is if the FEC was on a minority fork that
           has already been published away.  In this case we abandon the
           entire slice because it is no longer relevant.  */

        FD_LOG_WARNING(( "store fec for slot: %lu is on minority fork already pruned by publish. abandoning slice. root: %lu. pruned merkle: %s", slice.slot, ctx->consensus_root_slot, FD_BASE58_ENC_32_ALLOCA( &slice.merkles[i] ) ));
        return;
      }
      FD_TEST( fec );
      memcpy( ctx->slice_exec_ctx.buf + slice_sz, fec->data, fec->data_sz );
      slice_sz += fec->data_sz;
    }
  } FD_STORE_SHARED_LOCK_END;

  fd_histf_sample( ctx->metrics.store_read_wait, (ulong)fd_long_max( shacq_end - shacq_start, 0UL ) );
  fd_histf_sample( ctx->metrics.store_read_work, (ulong)fd_long_max( shrel_end - shacq_end,   0UL ) );

  fd_slice_exec_begin( &ctx->slice_exec_ctx, slice_sz, slot_complete );

  /* Either keep executing on the same bank, switch to another existing
     bank, or create a new bank. */
  handle_bank_change(
      ctx,
      stem,
      slot,
      parent_slot,
      &slice.merkles[0],
      &slice.parent_merkle_hash );

  fd_bank_shred_cnt_set( ctx->slot_ctx->bank, fd_bank_shred_cnt_get( ctx->slot_ctx->bank ) + data_cnt );

  /* At this point, we should have a valid bank to execute against.
     The bank's block id should be updated to the last merkle hash in
     the slice.  When we are in a post-dispatcher world, this will have
     to be done with each fec set.  Right now it is sufficient to do
     this per slice. */
  fd_banks_rekey_bank( ctx->banks, fd_bank_block_id_query( ctx->slot_ctx->bank ), &slice.merkles[slice.merkles_cnt-1UL] );
}

static void
fini_leader_bank( fd_replay_tile_t *  ctx,
                  fd_bank_t *         bank,
                  fd_stem_context_t * stem ) {
  bank->flags |= FD_BANK_FLAGS_FROZEN;

  ulong curr_slot = fd_bank_slot_get( bank );

  /* TODO: get the poh hash */

  fd_bank_done_executing_set( bank, 1 );

  /* Do hashing and other end-of-block processing */
  fd_funk_txn_map_t * txn_map = fd_funk_txn_map( ctx->funk );
  if( FD_UNLIKELY( !txn_map->map ) ) {
    FD_LOG_ERR(( "Could not find valid funk transaction map" ));
  }
  fd_funk_txn_xid_t xid = { .ul = { curr_slot, curr_slot } };
  fd_funk_txn_start_read( ctx->funk );
  fd_funk_txn_t * funk_txn = fd_funk_txn_query( &xid, txn_map );
  fd_funk_txn_end_read( ctx->funk );
  if( FD_UNLIKELY( !funk_txn ) ) {
    FD_LOG_ERR(( "Could not find valid funk transaction for slot %lu", curr_slot ));
  }

  fd_exec_slot_ctx_t slot_ctx = {
    .funk     = ctx->funk,
    .banks    = ctx->banks,
    .bank     = bank,
    .funk_txn = funk_txn,
  };

  fd_runtime_block_execute_finalize( &slot_ctx );

  ulong block_entry_height = fd_bank_block_height_get( bank );
  publish_slot_notifications( ctx, stem, block_entry_height, curr_slot );

  /* Construct the end of slot notification message */
  FD_TEST( block_id_map_query( ctx->block_id_map, fd_bank_parent_slot_get( bank ), NULL ) );
  fd_hash_t const * parent_block_id = &block_id_map_query( ctx->block_id_map, fd_bank_parent_slot_get( bank ), NULL )->block_id;
  fd_hash_t const * bank_hash       = fd_bank_bank_hash_query( bank );
  fd_hash_t const * block_hash      = fd_blockhashes_peek_last( fd_bank_block_hash_queue_query( bank ) );
  FD_TEST( parent_block_id );
  FD_TEST( bank_hash       );
  FD_TEST( block_hash      );

  fd_replay_slot_info_t slot_info[1];
  slot_info->slot            = curr_slot;
  // slot_info->block_id        = block_id;
  slot_info->parent_block_id = *parent_block_id;
  slot_info->bank_hash       = *bank_hash;
  slot_info->block_hash      = *block_hash;

  if( FD_LIKELY( ctx->replay_out->idx!=ULONG_MAX ) ) {
    fd_replay_slot_info_t * replay_slot_info = fd_chunk_to_laddr( ctx->replay_out->mem, ctx->replay_out->chunk );
    *replay_slot_info = *slot_info;
    fd_stem_publish( stem, ctx->replay_out->idx, FD_REPLAY_SIG_SLOT_INFO, ctx->replay_out->chunk, sizeof(fd_replay_slot_info_t), 0UL, fd_frag_meta_ts_comp( fd_tickcount() ), fd_frag_meta_ts_comp( fd_tickcount() ) );
    ctx->replay_out->chunk = fd_dcache_compact_next( ctx->replay_out->chunk, sizeof(fd_replay_slot_info_t), ctx->replay_out->chunk0, ctx->replay_out->wmark );
  }

  /* Send Tower the state needed for processing the end of a slot. We
     send a message with the summary information, and then buffer the
     state of each vote account to be sent in after_credit so that we
     don't have to burst all the vote state messages in one go.

     TODO: potentially send only the vote states of the vote accounts
           that voted in this slot. Not clear whether this is worth the
           complexity. */

  if( FD_LIKELY( ctx->tower_out->idx!=ULONG_MAX ) ) {
    fd_replay_slot_info_t * tower_slot_info = fd_chunk_to_laddr( ctx->tower_out->mem, ctx->tower_out->chunk );
    *tower_slot_info = *slot_info;
    fd_stem_publish( stem, ctx->tower_out->idx, FD_REPLAY_SIG_SLOT_INFO, ctx->tower_out->chunk, sizeof(fd_replay_slot_info_t), 0UL, fd_frag_meta_ts_comp( fd_tickcount() ), fd_frag_meta_ts_comp( fd_tickcount() ) );
    ctx->tower_out->chunk = fd_dcache_compact_next( ctx->tower_out->chunk, sizeof(fd_replay_slot_info_t), ctx->tower_out->chunk0, ctx->tower_out->wmark );

    /* Copy the vote tower of all the vote accounts into the buffer,
       which will be published in after_credit. */
    buffer_vote_towers( ctx );
  }
}

static void
exec_slice_fini_slot( fd_replay_tile_t *  ctx,
                      fd_stem_context_t * stem ) {
  if( FD_UNLIKELY( ctx->capture_ctx ) ) fd_solcap_writer_flush( ctx->capture_ctx->capture );

  fd_bank_t * bank = ctx->slot_ctx->bank;
  bank->flags |= FD_BANK_FLAGS_FROZEN;

  ulong curr_slot = fd_bank_slot_get( bank );

  fd_microblock_hdr_t * hdr = fd_type_pun( ctx->slice_exec_ctx.buf + ctx->slice_exec_ctx.last_mblk_off );
  fd_hash_t * poh = fd_bank_poh_modify( bank );
  memcpy( poh, hdr->hash, sizeof(fd_hash_t) );

  fd_bank_done_executing_set( bank, 1 );

  block_id_map_t * bid = block_id_map_query( ctx->block_id_map, curr_slot, NULL );
  if( FD_UNLIKELY( !bid ) ) FD_LOG_CRIT(( "Block id does not exist for slot %lu", curr_slot ));

  fd_hash_t const * block_id = fd_bank_block_id_query( bank );
  if( FD_UNLIKELY( memcmp( block_id, &bid->block_id, sizeof(fd_hash_t) ) ) ) FD_LOG_CRIT(( "Block id does not match for slot %lu", curr_slot ));

  /* Reset ctx for next slot */
  fd_slice_exec_reset( &ctx->slice_exec_ctx );

  /* Do hashing and other end-of-block processing */
  fd_runtime_block_execute_finalize( ctx->slot_ctx );

  ulong block_entry_height = fd_bank_block_height_get( bank );
  publish_slot_notifications( ctx, stem, block_entry_height, curr_slot );

  /* Construct the end of slot notification message */
  FD_TEST( block_id_map_query( ctx->block_id_map, fd_bank_parent_slot_get( bank ), NULL ) );
  fd_hash_t const * parent_block_id = &block_id_map_query( ctx->block_id_map, fd_bank_parent_slot_get( bank ), NULL )->block_id;
  fd_hash_t const * bank_hash       = fd_bank_bank_hash_query( bank );
  fd_hash_t const * block_hash      = fd_blockhashes_peek_last( fd_bank_block_hash_queue_query( bank ) );
  FD_TEST( parent_block_id );
  FD_TEST( bank_hash       );
  FD_TEST( block_hash      );

  fd_replay_slot_info_t slot_info[1];
  slot_info->slot            = curr_slot;
  slot_info->block_id        = *block_id;
  slot_info->parent_block_id = *parent_block_id;
  slot_info->bank_hash       = *bank_hash;
  slot_info->block_hash      = *block_hash;

  if( FD_LIKELY( ctx->replay_out->idx!=ULONG_MAX ) ) {
    fd_replay_slot_info_t * replay_slot_info = fd_chunk_to_laddr( ctx->replay_out->mem, ctx->replay_out->chunk );
    *replay_slot_info = *slot_info;
    fd_stem_publish( stem, ctx->replay_out->idx, FD_REPLAY_SIG_SLOT_INFO, ctx->replay_out->chunk, sizeof(fd_replay_slot_info_t), 0UL, fd_frag_meta_ts_comp( fd_tickcount() ), fd_frag_meta_ts_comp( fd_tickcount() ) );
    ctx->replay_out->chunk = fd_dcache_compact_next( ctx->replay_out->chunk, sizeof(fd_replay_slot_info_t), ctx->replay_out->chunk0, ctx->replay_out->wmark );
  }

  /* Send Tower the state needed for processing the end of a slot. We
     send a message with the summary information, and then buffer the
     state of each vote account to be sent in after_credit so that we
     don't have to burst all the vote state messages in one go.
f
     TODO: potentially send only the vote states of the vote accounts
           that voted in this slot. Not clear whether this is worth the
           complexity. */

  if( FD_LIKELY( ctx->tower_out->idx!=ULONG_MAX ) ) {
    fd_replay_slot_info_t * tower_slot_info = fd_chunk_to_laddr( ctx->tower_out->mem, ctx->tower_out->chunk );
    *tower_slot_info = *slot_info;
    fd_stem_publish( stem, ctx->tower_out->idx, FD_REPLAY_SIG_SLOT_INFO, ctx->tower_out->chunk, sizeof(fd_replay_slot_info_t), 0UL, fd_frag_meta_ts_comp( fd_tickcount() ), fd_frag_meta_ts_comp( fd_tickcount() ) );
    ctx->tower_out->chunk = fd_dcache_compact_next( ctx->tower_out->chunk, sizeof(fd_replay_slot_info_t), ctx->tower_out->chunk0, ctx->tower_out->wmark );

    /* Copy the vote tower of all the vote accounts into the buffer,
       which will be published in after_credit. */
    buffer_vote_towers( ctx );
  }

  /**********************************************************************/
  /* Prepare bank for the next execution and write to debugging files   */
  /**********************************************************************/

  fd_bank_execution_fees_set( bank, 0UL );
  fd_bank_priority_fees_set( bank, 0UL );

  /**********************************************************************/
  /* Bank hash comparison, and halt if there's a mismatch after replay  */
  /**********************************************************************/

  fd_bank_hash_cmp_t * bank_hash_cmp = ctx->bank_hash_cmp;
  fd_bank_hash_cmp_lock( bank_hash_cmp );
  fd_bank_hash_cmp_insert( bank_hash_cmp, curr_slot, bank_hash, 1, 0 );

  if( ctx->shredcap_out->idx!=ULONG_MAX ) {
    /* TODO: We need some way to define common headers. */
    uchar *           chunk_laddr = fd_chunk_to_laddr( ctx->shredcap_out->mem, ctx->shredcap_out->chunk );
    fd_hash_t const * bank_hash   = fd_bank_bank_hash_query( bank );
    ulong             slot        = fd_bank_slot_get( bank );
    memcpy( chunk_laddr, bank_hash, sizeof(fd_hash_t) );
    memcpy( chunk_laddr+sizeof(fd_hash_t), &slot, sizeof(ulong) );
    fd_stem_publish( stem, ctx->shredcap_out->idx, 0UL, ctx->shredcap_out->chunk, sizeof(fd_hash_t) + sizeof(ulong), 0UL, fd_frag_meta_ts_comp( fd_tickcount() ), fd_frag_meta_ts_comp( fd_tickcount() ) );
    ctx->shredcap_out->chunk = fd_dcache_compact_next( ctx->shredcap_out->chunk, sizeof(fd_hash_t) + sizeof(ulong), ctx->shredcap_out->chunk0, ctx->shredcap_out->wmark );
  }

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
}

static void
exec_and_handle_slice( fd_replay_tile_t *  ctx,
                       fd_stem_context_t * stem ) {

  /* If there are no txns left to execute in the microblock and the exec
     tiles are not busy, then we are ready to either start executing the
     the next microblock/slice/slot.

     We have to synchronize on the the microblock boundary because we
     only have the guarantee that all transactions within the same
     microblock can be executed in parallel. */
  if( !fd_slice_exec_txn_ready( &ctx->slice_exec_ctx ) && ctx->exec_ready_bitset==fd_ulong_mask_lsb( (int)ctx->exec_cnt ) ) {
    if( fd_slice_exec_microblock_ready( &ctx->slice_exec_ctx ) ) {
      fd_slice_exec_microblock_parse( &ctx->slice_exec_ctx );
    } else if( fd_slice_exec_slice_ready( &ctx->slice_exec_ctx ) ) {
      /* If the current slice was the last one for the slot we need to
         finalize the slot (update bank members/compare bank hash). */
      if( fd_slice_exec_slot_complete( &ctx->slice_exec_ctx ) ) {
        exec_slice_fini_slot( ctx, stem );
      }

      /* Now, we are ready to start executing the next buffered slice. */
      handle_new_slice( ctx, stem );
    }
  }

  if( FD_UNLIKELY( fd_banks_is_bank_dead( ctx->slot_ctx->bank ) ) ) {
    /* TODO: This is a temporary hack to handle dead banks.  We simply
       skip the txn.  This should be removed and instead be handled
       by the replay dispatcher. */
    FD_LOG_WARNING(( "Skipping slice because bank is dead (slot: %lu, block_id: %s)", fd_bank_slot_get( ctx->slot_ctx->bank ), FD_BASE58_ENC_32_ALLOCA( fd_bank_block_id_query( ctx->slot_ctx->bank ) ) ));
    fd_slice_exec_skip_slice( &ctx->slice_exec_ctx );
  }

  /* At this point, we know that we have some quantity of transactions
     in a microblock that we are ready to execute. */
  for( int i=0; i<fd_ulong_popcnt( ctx->exec_ready_bitset ); i++ ) {

    if( !fd_slice_exec_txn_ready( &ctx->slice_exec_ctx ) ) {
      return;
    }

    int exec_idx = fd_ulong_find_lsb( ctx->exec_ready_bitset );
    /* Mark the exec tile as busy */
    ctx->exec_ready_bitset = fd_ulong_pop_lsb( ctx->exec_ready_bitset );

    ulong tsorig = fd_frag_meta_ts_comp( fd_tickcount() );

    /* Parse the transaction from the current slice */
    fd_txn_p_t txn_p;
    fd_slice_exec_txn_parse( &ctx->slice_exec_ctx, &txn_p );

    /* Insert or reverify invoked programs for this epoch, if needed
       FIXME: this should be done during txn parsing so that we don't
       have to loop over all accounts a second time. */
    fd_runtime_update_program_cache( ctx->slot_ctx, &txn_p, ctx->runtime_spad );

    /* At this point, we are going to send the txn down the execution
       pipeline. Increment the refcnt so we don't prematurely prune a
       bank that's needed by an in-flight txn. */
    ctx->slot_ctx->bank->refcnt++;

    /* Dispatch dcache to exec tile */
    fd_replay_out_link_t * exec_out = &ctx->exec_out[ exec_idx ];
    fd_exec_txn_msg_t *    exec_msg = (fd_exec_txn_msg_t *)fd_chunk_to_laddr( exec_out->mem, exec_out->chunk );

    memcpy( &exec_msg->txn, &txn_p, sizeof(fd_txn_p_t) );
    exec_msg->bank_idx = fd_banks_get_pool_idx( ctx->banks, ctx->slot_ctx->bank );

    ulong tspub = fd_frag_meta_ts_comp( fd_tickcount() );
    fd_stem_publish( stem, exec_out->idx, EXEC_NEW_TXN_SIG, exec_out->chunk, sizeof(fd_exec_txn_msg_t), 0UL, tsorig, tspub );
    exec_out->chunk = fd_dcache_compact_next( exec_out->chunk, sizeof(fd_exec_txn_msg_t), exec_out->chunk0, exec_out->wmark );
  }
}

static void
init_after_snapshot( fd_replay_tile_t * ctx ) {
  /* Now that the snapshot has been loaded in, we have to refresh the
     stake delegations since the manifest does not contain the full set
     of data required for the stake delegations. See
     fd_stake_delegations.h for why this is required. */

  fd_stake_delegations_t * root_delegations = fd_banks_stake_delegations_root_query( ctx->slot_ctx->banks );

  fd_stake_delegations_refresh( root_delegations, ctx->funk, ctx->slot_ctx->funk_txn );

  /* After both snapshots have been loaded in, we can determine if we should
     start distributing rewards. */

  fd_rewards_recalculate_partitioned_rewards( ctx->slot_ctx, ctx->capture_ctx, ctx->runtime_spad );

  ulong snapshot_slot = fd_bank_slot_get( ctx->slot_ctx->bank );
  if( FD_UNLIKELY( !snapshot_slot ) ) {
    /* Genesis-specific setup. */
    /* FIXME: This branch does not set up a new block exec ctx
       properly. Needs to do whatever prepare_new_block_execution
       does, but just hacking that in breaks stuff. */
    fd_runtime_update_leaders( ctx->slot_ctx->bank,
                               fd_bank_slot_get( ctx->slot_ctx->bank ),
                               ctx->runtime_spad );

    fd_bank_parent_slot_set( ctx->slot_ctx->bank, 0UL );

    ulong hashcnt_per_slot = fd_bank_hashes_per_tick_get( ctx->slot_ctx->bank ) * fd_bank_ticks_per_slot_get( ctx->slot_ctx->bank );
    fd_hash_t * poh = fd_bank_poh_modify( ctx->slot_ctx->bank );
    while( hashcnt_per_slot-- ) {
      fd_sha256_hash( poh->hash, 32UL, poh->hash );
    }

    FD_TEST( fd_runtime_block_execute_prepare( ctx->slot_ctx, ctx->runtime_spad ) == 0 );
    fd_runtime_block_execute_finalize( ctx->slot_ctx );

    snapshot_slot = 0UL;

    /* Now setup exec tiles for execution */
    ctx->exec_ready_bitset = fd_ulong_mask_lsb( (int)ctx->exec_cnt );
  }

  /* Initialize consensus structures post-snapshot */

  fd_vote_states_t const * vote_states = fd_bank_vote_states_locking_query( ctx->slot_ctx->bank );

  fd_bank_hash_cmp_t * bank_hash_cmp = ctx->bank_hash_cmp;

  fd_vote_states_iter_t iter_[1];
  for( fd_vote_states_iter_t * iter = fd_vote_states_iter_init( iter_, vote_states ); !fd_vote_states_iter_done( iter ); fd_vote_states_iter_next( iter ) ) {
    fd_vote_state_ele_t const * vote_state = fd_vote_states_iter_ele( iter );
    bank_hash_cmp->total_stake += vote_state->stake;
  }
  bank_hash_cmp->watermark = snapshot_slot;

  fd_bank_vote_states_end_locking_query( ctx->slot_ctx->bank );

  /* Now that the snapshot(s) are done loading, we can mark all of the
     exec tiles as ready. */
  ctx->exec_ready_bitset = fd_ulong_mask_lsb( (int)ctx->exec_cnt );

  if( FD_UNLIKELY( ctx->capture_ctx ) ) fd_solcap_writer_flush( ctx->capture_ctx->capture );

  ctx->consensus_root_slot = snapshot_slot;
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

    ulong snapshot_slot = fd_bank_slot_get( ctx->slot_ctx->bank );
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
    publish_stake_weights( ctx, stem, ctx->slot_ctx, 0 );
    publish_stake_weights( ctx, stem, ctx->slot_ctx, 1 );

    block_id_map_t * entry = block_id_map_insert( ctx->block_id_map, snapshot_slot );
    entry->block_id = manifest_block_id;

    fd_features_restore( ctx->slot_ctx, ctx->runtime_spad );

    fd_runtime_update_leaders( ctx->slot_ctx->bank, fd_bank_slot_get( ctx->slot_ctx->bank ), ctx->runtime_spad );

    /* We call this after fd_runtime_read_genesis, which sets up the
       slot_bank needed in blockstore_init. */
    init_after_snapshot( ctx );

    ulong curr_slot          = fd_bank_slot_get( ctx->slot_ctx->bank );
    ulong block_entry_height = fd_bank_block_height_get( ctx->slot_ctx->bank );
    publish_slot_notifications( ctx, stem, block_entry_height, curr_slot );

    ctx->slot_ctx->bank->flags |= FD_BANK_FLAGS_FROZEN;

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

      fd_ssload_recover( fd_chunk_to_laddr( ctx->in[ in_idx ].mem, chunk ), ctx->slot_ctx );
      break;
    }
    default: {
      FD_LOG_ERR(( "Received unknown snapshot message with msg %lu", msg ));
      return;
    }
  }

  return;
}

static int
maybe_become_leader( fd_replay_tile_t *  ctx,
                     fd_stem_context_t * stem ) {
  FD_TEST( ctx->is_booted );
  if( FD_UNLIKELY( ctx->pack_out->idx==ULONG_MAX ) ) return 0;
  if( FD_UNLIKELY( ctx->is_leader || ctx->next_leader_slot==ULONG_MAX ) ) return 0;

  FD_TEST( ctx->next_leader_slot>ctx->reset_slot );
  long now = fd_log_wallclock();
  long next_leader_timestamp = (long)((double)(ctx->next_leader_slot-ctx->reset_slot-1UL)*ctx->slot_duration_nanos) + ctx->reset_timestamp_nanos;
  if( FD_UNLIKELY( now<next_leader_timestamp ) ) return 0;

  /* TODO:
  if( FD_UNLIKELY( ctx->halted_switching_key ) ) return 0; */

  /* If a prior leader is still in the process of publishing their slot,
     delay ours to let them finish ... unless they are so delayed that
     we risk getting skipped by the leader following us.  1.2 seconds
     is a reasonable default here, although any value between 0 and 1.6
     seconds could be considered reasonable.  This is arbitrary and
     chosen due to intuition. */
  if( FD_UNLIKELY( now<next_leader_timestamp+(long)(3.0*ctx->slot_duration_nanos) ) ) {
    /* If the max_active_descendant is >= next_leader_slot, we waited
       too long and a leader after us started publishing to try and skip
       us.  Just start our leader slot immediately, we might win ... */
    if( FD_LIKELY( ctx->max_active_descendant>=ctx->reset_slot && ctx->max_active_descendant<ctx->next_leader_slot ) ) {
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

  ctx->is_leader = 1;
  ctx->highwater_leader_slot = fd_ulong_max( ctx->next_leader_slot, fd_ulong_if( ctx->highwater_leader_slot==ULONG_MAX, 0UL, ctx->highwater_leader_slot ) );

  FD_LOG_NOTICE(( "becoming leader for slot %lu, parent slot is %lu", ctx->next_leader_slot, ctx->reset_slot ));

  /* Acquires bank, sets up initial state, and refcnts it. */
  fd_bank_t * bank = prepare_leader_bank( ctx, ctx->next_leader_slot, ctx->reset_slot, stem );

  fd_became_leader_t * msg = fd_chunk_to_laddr( ctx->pack_out->mem, ctx->pack_out->chunk );
  msg->slot_start_ns = now;
  msg->slot_end_ns   = now+(long)ctx->slot_duration_nanos;
  msg->bank = NULL;
  msg->ticks_per_slot = fd_bank_ticks_per_slot_get( bank );
  ulong hashes_per_tick = fd_bank_hashes_per_tick_get( bank );
  msg->max_microblocks_in_slot = fd_ulong_min( MAX_MICROBLOCKS_PER_SLOT, msg->ticks_per_slot*(hashes_per_tick-1UL) );
  msg->total_skipped_ticks = msg->ticks_per_slot*(ctx->next_leader_slot-ctx->reset_slot);
  msg->epoch = fd_slot_to_epoch( fd_bank_epoch_schedule_query( ctx->slot_ctx->bank ), ctx->next_leader_slot, NULL );
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

  ulong sig = fd_disco_poh_sig( ctx->next_leader_slot, POH_PKT_TYPE_BECAME_LEADER, 0UL );
  fd_stem_publish( stem, ctx->pack_out->idx, sig, ctx->pack_out->chunk, sizeof(fd_became_leader_t), 0UL, 0UL, 0UL );
  ctx->pack_out->chunk = fd_dcache_compact_next( ctx->pack_out->chunk, sizeof(fd_became_leader_t), ctx->pack_out->chunk0, ctx->pack_out->wmark );

  ctx->next_leader_slot = fd_multi_epoch_leaders_get_next_slot( ctx->mleaders, ctx->next_leader_slot+1UL, ctx->identity_pubkey );
  return 1;
}

static void
unbecome_leader( fd_replay_tile_t *  ctx,
                 fd_stem_context_t * stem ) {
  FD_TEST( ctx->is_booted );
  FD_TEST( ctx->is_leader );

  FD_TEST( ctx->highwater_leader_slot==ctx->next_leader_slot );
  ctx->is_leader = 0;

  /* Remove the refcnt for the leader bank and finalize it. */

  fd_hash_t key = { .ul[0] = ctx->next_leader_slot };
  fd_bank_t * bank = fd_banks_get_bank( ctx->banks, &key );
  FD_TEST( !!bank );

  fini_leader_bank( ctx, bank, stem );
  bank->refcnt--;

  ctx->next_leader_slot = fd_multi_epoch_leaders_get_next_slot( ctx->mleaders, ctx->next_leader_slot+1UL, ctx->identity_pubkey );
}

static void
init_from_genesis( fd_replay_tile_t *  ctx,
                   fd_stem_context_t * stem ) {
  fd_runtime_read_genesis( ctx->slot_ctx, ctx->genesis_path, ctx->runtime_spad );

  publish_stake_weights( ctx, stem, ctx->slot_ctx, 0 );
  publish_stake_weights( ctx, stem, ctx->slot_ctx, 1 );

  /* We call this after fd_runtime_read_genesis, which sets up the
  slot_bank needed in blockstore_init. */
  /* FIXME: We should really only call this once. */
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

  /* Add genesis block to block_id_map */
  block_id_map_t * entry = block_id_map_insert( ctx->block_id_map, 0UL );
  entry->block_id        = genesis_block_id;

  /* Publish slot notifs */
  ulong curr_slot = fd_bank_slot_get( ctx->slot_ctx->bank );
  ulong block_entry_height = 0;

  /* Block after genesis has a height of 1.
     TODO: We should be able to query slot 1 block_map entry to get this
     (using the above for loop), but blockstore/fork setup on genesis is
     broken for now. */
  block_entry_height = 1UL;

  publish_slot_notifications( ctx, stem, block_entry_height, curr_slot );

  if( FD_LIKELY( ctx->replay_out->idx!=ULONG_MAX ) ) {
    fd_hash_t   parent_block_id = {0};
    fd_bank_t * bank            = ctx->slot_ctx->bank;

    fd_hash_t const * block_id = fd_bank_block_id_query( bank );

    fd_hash_t const * bank_hash = fd_bank_bank_hash_query( bank );
    if( FD_UNLIKELY( !bank_hash ) ) {
      FD_LOG_CRIT(( "invariant violation: bank_hash is NULL for slot %lu", curr_slot ));
    }
    fd_hash_t const * block_hash = fd_blockhashes_peek_last( fd_bank_block_hash_queue_query( bank ) );
    if( FD_UNLIKELY( !block_hash ) ) {
      FD_LOG_CRIT(( "invariant violation: block_hash is NULL for slot %lu", curr_slot ));
    }
    fd_replay_slot_info_t out = {
      .slot            = 0UL,
      .block_id        = *block_id,
      .parent_block_id = parent_block_id,
      .bank_hash       = *bank_hash,
      .block_hash      = *block_hash,
    };

    uchar * chunk_laddr = fd_chunk_to_laddr( ctx->replay_out->mem, ctx->replay_out->chunk );
    memcpy( chunk_laddr, &out, sizeof(fd_replay_slot_info_t) );
    fd_stem_publish( stem, ctx->replay_out->idx, FD_REPLAY_SIG_SLOT_INFO, ctx->replay_out->chunk, sizeof(fd_replay_slot_info_t), 0UL, 0UL, fd_frag_meta_ts_comp( fd_tickcount() ) );
    ctx->replay_out->chunk = fd_dcache_compact_next( ctx->replay_out->chunk, sizeof(fd_replay_slot_info_t), ctx->replay_out->chunk0, ctx->replay_out->wmark );
  }

  ctx->reset_slot = 0UL;
  ctx->reset_timestamp_nanos = fd_log_wallclock();
  ctx->next_leader_slot = fd_multi_epoch_leaders_get_next_slot( ctx->mleaders, 1UL, ctx->identity_pubkey );
}

static void
after_credit( fd_replay_tile_t *  ctx,
              fd_stem_context_t * stem,
              int *               opt_poll_in,
              int *               charge_busy ) {
  if( FD_UNLIKELY( !ctx->is_booted ) ) {
    if( FD_UNLIKELY( ctx->bootstrap ) ) {
      *charge_busy = 1;
      init_from_genesis( ctx, stem );
      ctx->is_booted = 1;
      maybe_become_leader( ctx, stem );
      *opt_poll_in = 0;
    }
    return;
  }

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

  exec_and_handle_slice( ctx, stem );
}

static int
before_frag( fd_replay_tile_t * ctx,
             ulong              in_idx,
             ulong              seq,
             ulong              sig ) {
  (void)seq;
  (void)sig;

  if( FD_UNLIKELY( ctx->in_kind[ in_idx ]==IN_KIND_REPAIR ) ) {
    /* If the internal slice buffer is full, there is nowhere for the
       fragment to go and we cannot pull it off the incoming queue yet.
       This will eventually cause backpressure to the repair system. */

    /* FIXME: this isn't quite right anymore, because the slice queue
       no longer corresponds 1-1 with the input frag type.  FEC sets are
       delivered, not slices.  This could result in us backpressuring
       too early (in the worst case an entire block, if there is a
       single slice for the block). */

    if( FD_UNLIKELY( fd_exec_slice_deque_full( ctx->exec_slice_deque ) ) ) return -1;
  }

  return 0;
}

static void
process_txn_finalized( fd_replay_tile_t *                           ctx,
                       fd_writer_replay_txn_finalized_msg_t const * msg ) {
  FD_TEST( !fd_ulong_extract_bit( ctx->exec_ready_bitset, msg->exec_tile_id ) );
  ctx->exec_ready_bitset = fd_ulong_set_bit( ctx->exec_ready_bitset, msg->exec_tile_id );
  ctx->slot_ctx->bank->refcnt--;
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
process_solcap_account_update( fd_replay_tile_t *                         ctx,
                              fd_capture_ctx_account_update_msg_t const * msg ) {
  if( FD_UNLIKELY( !ctx->capture_ctx || !ctx->capture_ctx->capture ) ) return;
  if( FD_UNLIKELY( fd_bank_slot_get( ctx->slot_ctx->bank )<ctx->capture_ctx->solcap_start_slot ) ) return;

  uchar const * account_data = (uchar const *)fd_type_pun_const( msg )+sizeof(fd_capture_ctx_account_update_msg_t);
  fd_solcap_write_account( ctx->capture_ctx->capture, &msg->pubkey, &msg->info, account_data, msg->data_sz );
}

static void
funk_publish( fd_replay_tile_t * ctx,
              ulong              slot ) {
  fd_funk_txn_start_write( ctx->funk );

  fd_funk_txn_xid_t   xid         = { .ul[0] = slot, .ul[1] = slot };
  fd_funk_txn_map_t * txn_map     = fd_funk_txn_map( ctx->funk );
  fd_funk_txn_t *     to_root_txn = fd_funk_txn_query( &xid, txn_map );

  if( FD_UNLIKELY( xid.ul[0]!=slot ) ) FD_LOG_CRIT(( "Invariant violation: xid.ul[0] != slot %lu %lu", xid.ul[0], slot ));

  FD_LOG_DEBUG(( "publishing slot=%lu xid=%lu", slot, xid.ul[0] ));

  /* This is the standard case.  Publish all transactions up to and
     including the watermark.  This will publish any in-prep ancestors
     of root_txn as well. */
  if( FD_UNLIKELY( !fd_funk_txn_publish( ctx->funk, to_root_txn, 1 ) ) ) FD_LOG_CRIT(( "failed to funk publish slot %lu", slot ));

  fd_funk_txn_end_write( ctx->funk );
}

static void
advance_published_root( fd_replay_tile_t * ctx ) {
  fd_hash_t publishable_root;
  if( FD_UNLIKELY( !fd_banks_publish_prepare( ctx->banks, &ctx->consensus_root, &publishable_root ) ) ) return;

  fd_bank_t * bank = fd_banks_get_bank( ctx->banks, &publishable_root );
  FD_TEST( bank );

  ulong publishable_root_slot = fd_bank_slot_get( bank );

  block_id_map_t * block_id = block_id_map_query( ctx->block_id_map, publishable_root_slot, NULL );
  FD_TEST( block_id );

  long exacq_start, exacq_end, exrel_end;
  FD_STORE_EXCLUSIVE_LOCK( ctx->store, exacq_start, exacq_end, exrel_end ) {
    fd_store_publish( ctx->store, &block_id->block_id );
  } FD_STORE_EXCLUSIVE_LOCK_END;

  fd_histf_sample( ctx->metrics.store_publish_wait, (ulong)fd_long_max( exacq_end-exacq_start, 0UL ) );
  fd_histf_sample( ctx->metrics.store_publish_work, (ulong)fd_long_max( exrel_end-exacq_end,   0UL ) );

  block_id_map_remove( ctx->block_id_map, block_id );

  funk_publish( ctx, publishable_root_slot );
  fd_banks_publish( ctx->banks, &block_id->block_id );
}

static void
process_tower_update( fd_replay_tile_t *           ctx,
                      fd_tower_slot_done_t const * msg ) {
  if( FD_UNLIKELY( !msg->new_root ) ) return;

  /* We have recieved a root message.  We don't want to update the
     rooted slot and block id if we are processing the genesis block. */
  if( FD_UNLIKELY( !fd_bank_slot_get( ctx->slot_ctx->bank ) ) ) return;

  ctx->consensus_root_slot = msg->root_slot;

  /* TODO: Read this from msg->root_block_id, requires updating backtest
     to pass a correct root_block_id. */
  block_id_map_t * block_id = block_id_map_query( ctx->block_id_map, msg->root_slot, NULL );
  FD_TEST( block_id );
  ctx->consensus_root = block_id->block_id;

  advance_published_root( ctx );

  /* TODO fill in reset bank logic */
}

static void
process_fec_set( fd_replay_tile_t *     ctx,
                 fd_reasm_fec_t const * fec ) {
  /* Forks form a partial ordering over FEC sets. The Repair tile
     delivers FEC sets in-order per fork, but FEC set ordering across
     forks is arbitrary.

     The existing Replay interface can only replay on entry batch
     boundaries but the new Dispatcher interface will support processing
     individual FEC sets (ie. the repair_replay frag). So the following
     code is a temporary workaround to internally buffer and reassemble
     FEC sets into entry batches. */
  fd_exec_slice_t * slice = fd_exec_slice_map_query( ctx->exec_slice_map, fec->slot, NULL );
  if( FD_UNLIKELY( !slice ) ) slice = fd_exec_slice_map_insert( ctx->exec_slice_map, fec->slot );
  slice->parent_off    = fec->parent_off;
  slice->slot_complete = fec->slot_complete;
  slice->data_cnt += fec->data_cnt;
  FD_TEST( slice->merkles_cnt < MERKLES_MAX );
  memcpy( &slice->merkles[ slice->merkles_cnt++ ], &fec->key, sizeof(fd_hash_t) );

  /* Copy in the parent merkle_hash for the first FEC set in the slice.
     This is used to index the correct bank and is a temporary hack to
     support a fec/block id indexed bank in a pre-replay dispatcher
     world. */
  if( slice->merkles_cnt==1UL ) {
    slice->parent_merkle_hash    = fec->cmr;
    ulong            parent_slot = fec->slot - fec->parent_off;
    block_id_map_t * entry       = block_id_map_query( ctx->block_id_map, parent_slot, NULL );
    if( FD_UNLIKELY( !entry ) ) {
      FD_LOG_CRIT(( "invariant violation: block_id_map_query returned NULL for slot %lu", parent_slot ));
    }
    if( FD_UNLIKELY( fec->slot!=0UL && fec->fec_set_idx==0U && memcmp( &entry->block_id, &fec->cmr, sizeof(fd_hash_t) )!=0 ) ) {
      FD_LOG_CRIT(( "invariant violation: slot %lu, block_id_map_query returned block_id %s for slot %lu, but FEC set has cmr %s", fec->slot, FD_BASE58_ENC_32_ALLOCA( &entry->block_id ), parent_slot, FD_BASE58_ENC_32_ALLOCA( &fec->cmr ) ));
    }
  }

  if( FD_UNLIKELY( fec->data_complete ) ) {
    /* If the internal slice buffer is full, there is nowhere for the
       fragment to go and we cannot pull it off the incoming queue yet.
       This will eventually cause backpressure to the repair system.

       @chali: this comment reads like a bug. probably shouldn't have
       pulled it off the mcache / dcache at all? making it FD_LOG_ERR to
       be rewritten later. */
    if( FD_UNLIKELY( fd_exec_slice_deque_full( ctx->exec_slice_deque ) ) ) FD_LOG_CRIT(( "invariant violation" ));

    fd_exec_slice_deque_push_tail( ctx->exec_slice_deque, *slice ); /* push a copy */

    memset( slice, 0, sizeof(fd_exec_slice_t) );
    fd_exec_slice_map_remove( ctx->exec_slice_map, slice );
  }

  if( FD_UNLIKELY( fec->slot_complete ) ) {
    block_id_map_t * entry = block_id_map_insert( ctx->block_id_map, fec->slot );
    entry->block_id = fec->key; /* the "block_id" is the last FEC set's merkle root */
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
    case IN_KIND_SNAP:
      on_snapshot_message( ctx, stem, in_idx, chunk, sig );
      break;
    case IN_KIND_WRITER: {
      process_txn_finalized( ctx, fd_chunk_to_laddr( ctx->in[ in_idx ].mem, chunk ) );
      break;
    }
    case IN_KIND_CAPTURE: {
      process_solcap_account_update( ctx, fd_chunk_to_laddr( ctx->in[ in_idx ].mem, chunk ) );
      break;
    }
    case IN_KIND_POH: {
      fd_poh_leader_slot_ended_t const * slot_ended = fd_chunk_to_laddr( ctx->in[ in_idx ].mem, chunk );
      unbecome_leader( ctx, stem );
      (void)slot_ended;
      break;
    }
    case IN_KIND_TOWER: {
      process_tower_update( ctx, fd_chunk_to_laddr( ctx->in[ in_idx ].mem, chunk ) );
      break;
    }
    case IN_KIND_REPAIR: {
      FD_TEST( sz==sizeof(fd_reasm_fec_t) );
      process_fec_set( ctx, fd_chunk_to_laddr( ctx->in[ in_idx ].mem, chunk ) );
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

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_replay_tile_t * ctx    = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_replay_tile_t),   sizeof(fd_replay_tile_t) );
  void * _capture_ctx       = FD_SCRATCH_ALLOC_APPEND( l, FD_CAPTURE_CTX_ALIGN,        FD_CAPTURE_CTX_FOOTPRINT );
  void * block_id_map_mem   = FD_SCRATCH_ALLOC_APPEND( l, block_id_map_align(),        block_id_map_footprint( fd_ulong_find_msb( fd_ulong_pow2_up( FD_BLOCK_MAX ) ) ) );
  void * slice_buf          = FD_SCRATCH_ALLOC_APPEND( l, 128UL,                       FD_SLICE_MAX );
  void * exec_slice_map_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_exec_slice_map_align(),   fd_exec_slice_map_footprint( 20 ) );
  void * spad_mem           = FD_SCRATCH_ALLOC_APPEND( l, fd_spad_align(),             fd_spad_footprint( tile->replay.heap_size_gib<<30 ) );
  void * slot_ctx_mem       = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_exec_slot_ctx_t), sizeof(fd_exec_slot_ctx_t) );
  void * slice_deque_mem    = FD_SCRATCH_ALLOC_APPEND( l, fd_exec_slice_deque_align(), fd_exec_slice_deque_footprint( EXEC_SLICE_DEQUE_MAX ) );

  ulong store_obj_id = fd_pod_query_ulong( topo->props, "store", ULONG_MAX );
  FD_TEST( store_obj_id!=ULONG_MAX );
  ctx->store = fd_store_join( fd_topo_obj_laddr( topo, store_obj_id ) );
  FD_TEST( ctx->store );

  ctx->vote_tower_out_idx = 0UL;
  ctx->vote_tower_out_len = 0UL;

  ctx->consensus_root_slot = ULONG_MAX;

  ulong banks_obj_id = fd_pod_query_ulong( topo->props, "banks", ULONG_MAX );
  FD_TEST( banks_obj_id!=ULONG_MAX );
  ctx->banks = fd_banks_join( fd_topo_obj_laddr( topo, banks_obj_id ) );
  FD_TEST( ctx->banks );

  fd_hash_t   init_hash = {.ul[0] = FD_RUNTIME_INITIAL_BLOCK_ID };
  fd_bank_t * bank      = fd_banks_init_bank( ctx->banks, &init_hash );
  FD_TEST( bank );

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

  FD_TEST( fd_funk_join( ctx->funk, fd_topo_obj_laddr( topo, tile->replay.funk_obj_id ) ) );

  ctx->tx_metadata_storage = tile->replay.tx_metadata_storage;

  ctx->bootstrap = tile->replay.bootstrap;
  if( FD_UNLIKELY( ctx->bootstrap ) ) strncpy( ctx->genesis_path, tile->replay.genesis_path, sizeof(ctx->genesis_path) );

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

  ctx->exec_cnt = fd_topo_tile_name_cnt( topo, "exec" );
  ctx->exec_ready_bitset = 0UL;
  ctx->is_booted = 0;

  /* Now attach to the runtime spad which is part of the tile memory.
     FIXME: Replace runtime spad with a non-stack allocator. */
  ctx->runtime_spad = fd_spad_join( fd_spad_new( spad_mem, fd_spad_footprint( tile->replay.heap_size_gib<<30UL ) ) );
  FD_TEST( ctx->runtime_spad );

  ctx->slot_ctx = fd_exec_slot_ctx_join( fd_exec_slot_ctx_new( slot_ctx_mem ) );
  FD_TEST( ctx->slot_ctx );
  ctx->slot_ctx->banks = ctx->banks;

  fd_hash_t initial_hash = { .ul[0] = FD_RUNTIME_INITIAL_BLOCK_ID };
  ctx->slot_ctx->bank = fd_banks_get_bank( ctx->slot_ctx->banks, &initial_hash );
  FD_TEST( ctx->slot_ctx->bank );

  ctx->slot_ctx->funk         = ctx->funk;
  ctx->slot_ctx->status_cache = NULL; /* TODO: Integrate status cache */
  ctx->slot_ctx->capture_ctx  = ctx->capture_ctx;

  ctx->block_id_map = block_id_map_join( block_id_map_new( block_id_map_mem, fd_ulong_find_msb( fd_ulong_pow2_up( FD_BLOCK_MAX ) ) ) );
  FD_TEST( ctx->block_id_map );

  ctx->exec_slice_map = fd_exec_slice_map_join( fd_exec_slice_map_new( exec_slice_map_mem, 20UL ) );
  FD_TEST( ctx->exec_slice_map );
  FD_TEST( fd_exec_slice_map_key_max( ctx->exec_slice_map ) );
  FD_TEST( fd_exec_slice_map_key_cnt( ctx->exec_slice_map )==0UL );

  ulong bank_hash_cmp_obj_id = fd_pod_query_ulong( topo->props, "bh_cmp", ULONG_MAX );
  FD_TEST( bank_hash_cmp_obj_id!=ULONG_MAX );
  ctx->bank_hash_cmp = fd_bank_hash_cmp_join( fd_bank_hash_cmp_new( fd_topo_obj_laddr( topo, bank_hash_cmp_obj_id ) ) );
  FD_TEST( ctx->bank_hash_cmp );

  /* TODO: delete with replay dispatcher integration */
  FD_TEST( fd_slice_exec_join( &ctx->slice_exec_ctx ) );
  ctx->slice_exec_ctx.buf = slice_buf;

  FD_TEST( FD_PACK_MAX_BANK_TILES<=UCHAR_MAX ); /* Exec tile id needs to fit in a uchar for the writer tile txn done message. */
  if( FD_UNLIKELY( ctx->exec_cnt>FD_PACK_MAX_BANK_TILES ) ) FD_LOG_ERR(( "replay tile has too many exec tiles %lu", ctx->exec_cnt ));

  ctx->mleaders = fd_multi_epoch_leaders_join( fd_multi_epoch_leaders_new( ctx->mleaders_mem ) );
  FD_TEST( ctx->mleaders );

  ctx->is_leader = 0;
  ctx->reset_slot = 0UL;
  ctx->reset_timestamp_nanos = 0UL;
  ctx->next_leader_slot = ULONG_MAX;
  ctx->highwater_leader_slot = ULONG_MAX;
  ctx->slot_duration_nanos = 400L*1000L*1000L; /* TODO: Not fixed ... not always 400ms ... */
  ctx->max_active_descendant = 0UL; /* TODO: Update this properly ... */

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

    if(      !strcmp( link->name, "repair_repla" ) ) ctx->in_kind[ i ] = IN_KIND_REPAIR;
    else if( !strcmp( link->name, "snap_out"     ) ) ctx->in_kind[ i ] = IN_KIND_SNAP;
    else if( !strcmp( link->name, "writ_repl"    ) ) ctx->in_kind[ i ] = IN_KIND_WRITER;
    else if( !strcmp( link->name, "tower_out"    ) ) ctx->in_kind[ i ] = IN_KIND_TOWER;
    else if( !strcmp( link->name, "capt_replay"  ) ) ctx->in_kind[ i ] = IN_KIND_CAPTURE;
    else if( !strcmp( link->name, "poh_replay"   ) ) ctx->in_kind[ i ] = IN_KIND_POH;
    else FD_LOG_ERR(( "unexpected input link name %s", link->name ));
  }

  *ctx->notif_out        = out1( topo, tile, "replay_notif" );
  *ctx->shredcap_out     = out1( topo, tile, "replay_scap" );
  *ctx->tower_out        = out1( topo, tile, "replay_tower" );
  *ctx->plugin_out       = out1( topo, tile, "replay_plugi" );
  *ctx->votes_plugin_out = out1( topo, tile, "votes_plugin" ); /* TODO: Delete this */
  *ctx->stake_out        = out1( topo, tile, "replay_stake" ); FD_TEST( ctx->stake_out->idx!=ULONG_MAX );
  *ctx->replay_out       = out1( topo, tile, "replay_out" );
  *ctx->pack_out         = out1( topo, tile, "replay_pack" );

  for( ulong i=0UL; i<ctx->exec_cnt; i++ ) {
    ulong idx = fd_topo_find_tile_out_link( topo, tile, "replay_exec", i );
    FD_TEST( idx!=ULONG_MAX );
    fd_topo_link_t * link = &topo->links[ tile->out_link_id[ idx ] ];

    fd_replay_out_link_t * exec_out = &ctx->exec_out[ i ];
    exec_out->idx    = idx;
    exec_out->mem    = topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ].wksp;
    exec_out->chunk0 = fd_dcache_compact_chunk0( exec_out->mem, link->dcache );
    exec_out->wmark  = fd_dcache_compact_wmark( exec_out->mem, link->dcache, link->mtu );
    exec_out->chunk  = exec_out->chunk0;
  }

  ctx->exec_slice_deque = fd_exec_slice_deque_join( fd_exec_slice_deque_new( slice_deque_mem, EXEC_SLICE_DEQUE_MAX ) );
  if( FD_UNLIKELY( !ctx->exec_slice_deque ) ) FD_LOG_CRIT(( "failed to join and create exec slice deque" ));

  ctx->enable_bank_hash_cmp = tile->replay.enable_bank_hash_cmp;

  fd_memset( &ctx->metrics, 0, sizeof(ctx->metrics) );

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
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  (void)topo;
  (void)tile;

  populate_sock_filter_policy_fd_replay_tile( out_cnt, out, (uint)fd_log_private_logfile_fd() );
  return sock_filter_policy_fd_replay_tile_instr_cnt;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  (void)topo;
  (void)tile;

  if( FD_UNLIKELY( out_fds_cnt<2UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  return out_cnt;
}

/* TODO: This needs to get sized out correctly. */
#define STEM_BURST (64UL)

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
