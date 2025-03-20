#define _GNU_SOURCE
#include "../../disco/tiles.h"
#include "generated/fd_replay_tile_seccomp.h"

#include "../geyser/fd_replay_notif.h"
#include "../restart/fd_restart.h"
#include "../store/fd_epoch_forks.h"

#include "../../disco/keyguard/fd_keyload.h"
#include "../../disco/topo/fd_pod_format.h"
#include "../../flamenco/runtime/fd_txncache.h"
#include "../../flamenco/runtime/context/fd_capture_ctx.h"
#include "../../flamenco/runtime/context/fd_exec_epoch_ctx.h"
#include "../../flamenco/runtime/context/fd_exec_slot_ctx.h"
#include "../../flamenco/runtime/program/fd_bpf_program_util.h"
#include "../../flamenco/runtime/sysvar/fd_sysvar_epoch_schedule.h"
#include "../../flamenco/runtime/sysvar/fd_sysvar_slot_history.h"
#include "../../flamenco/runtime/fd_runtime_init.h"
#include "../../flamenco/snapshot/fd_snapshot.h"
#include "../../flamenco/stakes/fd_stakes.h"
#include "../../flamenco/runtime/fd_runtime.h"
#include "../../flamenco/rewards/fd_rewards.h"
#include "../../disco/metrics/fd_metrics.h"
#include "../../choreo/fd_choreo.h"
#include "../../funk/fd_funk_filemap.h"
#include "../../flamenco/snapshot/fd_snapshot_create.h"
#include "../../disco/plugin/fd_plugin.h"
#include "fd_replay.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/unistd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/* An estimate of the max number of transactions in a block.  If there are more
   transactions, they must be split into multiple sets. */
#define MAX_TXNS_PER_REPLAY ( ( FD_SHRED_MAX_PER_SLOT * FD_SHRED_MAX_SZ) / FD_TXN_MIN_SERIALIZED_SZ )

#define PLUGIN_PUBLISH_TIME_NS ((long)60e9)

#define STORE_IN_IDX   (0UL)
#define PACK_IN_IDX    (1UL)
#define BATCH_IN_IDX   (2UL)
#define SHRED_IN_IDX   (3UL)

#define STAKE_OUT_IDX  (0UL)
#define NOTIF_OUT_IDX  (1UL)
#define SENDER_OUT_IDX (2UL)
#define POH_OUT_IDX    (3UL)

#define VOTE_ACC_MAX   (2000000UL)

#define BANK_HASH_CMP_LG_MAX 16

struct fd_shred_replay_in_ctx {
  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
};
typedef struct fd_shred_replay_in_ctx fd_shred_replay_in_ctx_t;

struct fd_replay_out_ctx {
  ulong            idx; /* TODO refactor the bank_out to use this */

  fd_frag_meta_t * mcache;
  ulong *          sync;
  ulong            depth;
  ulong            seq;

  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
  ulong       chunk;

};
typedef struct fd_replay_out_ctx fd_replay_out_ctx_t;

struct fd_replay_tile_metrics {
  ulong slot;
  ulong last_voted_slot;
};
typedef struct fd_replay_tile_metrics fd_replay_tile_metrics_t;
#define FD_REPLAY_TILE_METRICS_FOOTPRINT ( sizeof( fd_replay_tile_metrics_t ) )

struct fd_slice_exec_ctx {
  ulong wmark;     /* offset to start executing from. Will be on a transaction or microblock boundary. */
  ulong sz;        /* total bytes occupied in the mbatch memory. Queried slices should be placed at this offset */
  ulong mblks_rem; /* microblocks remaining in the current batch iteration. If 0, the next batch can be read. */
  ulong txns_rem;  /* txns remaining in current microblock iteration. If 0, the next microblock can be read. */

  ulong last_mblk_off; /* offset to the last microblock hdr seen */
  int   last_batch;    /* signifies last batch execution for stopping condition */
};
typedef struct fd_slice_exec_ctx fd_slice_exec_ctx_t;

struct fd_replay_tile_ctx {
  fd_wksp_t * wksp;
  fd_wksp_t * blockstore_wksp;
  fd_wksp_t * funk_wksp;
  fd_wksp_t * status_cache_wksp;

  fd_wksp_t  * replay_public_wksp;
  fd_runtime_public_t * replay_public;

  // Store tile input
  fd_wksp_t * store_in_mem;
  ulong       store_in_chunk0;
  ulong       store_in_wmark;

  // Pack tile input
  fd_wksp_t * pack_in_mem;
  ulong       pack_in_chunk0;
  ulong       pack_in_wmark;

  // Batch tile input for epoch account hash
  fd_wksp_t * batch_in_mem;
  ulong       batch_in_chunk0;
  ulong       batch_in_wmark;

  // Shred tile input
  ulong             shred_in_cnt;
  fd_shred_replay_in_ctx_t shred_in[ 32 ];

  // Notification output defs
  fd_frag_meta_t * notif_out_mcache;
  ulong *          notif_out_sync;
  ulong            notif_out_depth;
  ulong            notif_out_seq;

  fd_wksp_t * notif_out_mem;
  ulong       notif_out_chunk0;
  ulong       notif_out_wmark;
  ulong       notif_out_chunk;

  // Sender output defs
  fd_frag_meta_t * sender_out_mcache;
  ulong *          sender_out_sync;
  ulong            sender_out_depth;
  ulong            sender_out_seq;

  fd_wksp_t * sender_out_mem;
  ulong       sender_out_chunk0;
  ulong       sender_out_wmark;
  ulong       sender_out_chunk;

  // Stake weights output link defs
  fd_frag_meta_t * stake_weights_out_mcache;
  ulong *          stake_weights_out_sync;
  ulong            stake_weights_out_depth;
  ulong            stake_weights_out_seq;

  fd_wksp_t * stake_weights_out_mem;
  ulong       stake_weights_out_chunk0;
  ulong       stake_weights_out_wmark;
  ulong       stake_weights_out_chunk;

  // Inputs to plugin/gui
  ulong       replay_plug_out_idx;
  fd_wksp_t * replay_plugin_out_mem;
  ulong       replay_plugin_out_chunk0;
  ulong       replay_plugin_out_wmark;
  ulong       replay_plugin_out_chunk;

  ulong       votes_plug_out_idx;
  fd_wksp_t * votes_plugin_out_mem;
  ulong       votes_plugin_out_chunk0;
  ulong       votes_plugin_out_wmark;
  ulong       votes_plugin_out_chunk;
  long        last_plugin_push_time;

  char const * blockstore_checkpt;
  int          tx_metadata_storage;
  char const * funk_checkpt;
  char const * genesis;
  char const * incremental;
  char const * snapshot;

  /* Do not modify order! This is join-order in unprivileged_init. */

  fd_alloc_t *          alloc;
  fd_valloc_t           valloc;
  fd_funk_t *           funk;
  fd_acc_mgr_t *        acc_mgr;
  fd_exec_epoch_ctx_t * epoch_ctx;
  fd_epoch_t *          epoch;
  fd_forks_t *          forks;
  fd_ghost_t *          ghost;
  fd_tower_t *          tower;
  fd_replay_t *         replay;

  fd_pubkey_t validator_identity[1];
  fd_pubkey_t vote_authority[1];
  fd_pubkey_t vote_acc[1];

  /* Vote accounts in the current epoch. Lifetimes of the vote account
     addresses (pubkeys) are valid for the epoch (the pubkey memory is
     owned by the epoch bank). */

  fd_voter_t *          epoch_voters; /* map chain of slot->voter */
  fd_bank_hash_cmp_t *  bank_hash_cmp;

  /* Microblock (entry) batch buffer for replay. */

  uchar * mbatch;
  fd_slice_exec_ctx_t slice_exec_ctx;

  /* Tpool */

  uchar        tpool_mem[FD_TPOOL_FOOTPRINT( FD_TILE_MAX )] __attribute__( ( aligned( FD_TPOOL_ALIGN ) ) );
  fd_tpool_t * tpool;

  /* Depends on store_int and is polled in after_credit */

  fd_blockstore_t   blockstore_ljoin;
  int               blockstore_fd; /* file descriptor for archival file */
  fd_blockstore_t * blockstore;

  /* Updated during execution */

  fd_exec_slot_ctx_t *  slot_ctx;

  /* Metadata updated during execution */

  ulong     curr_slot;
  ulong     parent_slot;
  ulong     snapshot_slot;
  ulong     last_completed_slot; /* questionable variable used for making sure we do post-block execution steps only once,
                                    probably can remove this if after we rip out ctx->curr_slot (recieved from STORE) */
  fd_hash_t blockhash;
  ulong     flags;
  ulong     txn_cnt;
  ulong     bank_idx;

  ulong     fecs_inserted;
  ulong     fecs_removed;
  /* Other metadata */

  ulong funk_seed;
  ulong status_cache_seed;
  fd_capture_ctx_t * capture_ctx;
  FILE *             capture_file;
  FILE *             slots_replayed_file;

  int skip_frag;

  ulong * first_turbine;

  ulong * bank_busy[ FD_PACK_MAX_BANK_TILES ];
  ulong   bank_cnt;
  fd_replay_out_ctx_t bank_out[ FD_PACK_MAX_BANK_TILES ]; /* Sending to PoH finished txns + a couple more tasks ??? */

  ulong   exec_cnt;
  ulong   exec_out_idx;
  fd_replay_out_ctx_t exec_out[ FD_PACK_MAX_BANK_TILES ]; /* Sending to exec unexecuted txns */

  ulong root; /* the root slot is the most recent slot to have reached
                 max lockout in the tower  */

  ulong * published_wmark; /* publish watermark. The watermark is defined as the
                  minimum of the tower root (root above) and blockstore
                  smr (blockstore->smr). The watermark is used to
                  publish our fork-aware structures eg. blockstore,
                  forks, ghost. In general, publishing has the effect of
                  pruning minority forks in those structures,
                  indicating that is ok to release the memory being
                  occupied by said forks.

                  The reason it has to be the minimum of the two, is the
                  tower root can lag the SMR and vice versa, but both
                  the fork-aware structures need to maintain information
                  through both of those slots. */

  ulong * poh;  /* proof-of-history slot */
  uint poh_init_done;
  int  snapshot_init_done;

  int         tower_checkpt_fileno;

  int         vote;
  fd_pubkey_t validator_identity_pubkey[ 1 ];
  fd_pubkey_t vote_acct_addr[ 1 ];

  fd_txncache_t * status_cache;
  void * bmtree[ FD_PACK_MAX_BANK_TILES ];

  fd_epoch_forks_t epoch_forks[1];

  /* The spad allocators used by the executor tiles are NOT the same as the
     spad used for general, longer-lasting spad allocations. The lifetime of
     the exec spad is just through an execution. The runtime spad is scoped
     to the runtime. The top-most frame will persist for the entire duration
     of the process. There will also be a potential second frame that persists
     across multiple slots that is created for rewards distrobution. Every other
     spad frame should NOT exist beyond the scope of a block. */
  fd_spad_t * exec_spads[ 128UL ];
  ulong       exec_spad_cnt;
  fd_spad_t * runtime_spad;

  /* TODO: refactor this all into fd_replay_tile_snapshot_ctx_t. */
  ulong   snapshot_interval;        /* User defined parameter */
  ulong   incremental_interval;     /* User defined parameter */
  ulong   last_full_snap;           /* If a full snapshot has been produced */
  ulong * is_constipated;           /* Shared fseq to determine if funk should be constipated */
  ulong   prev_full_snapshot_dist;  /* Tracking for snapshot creation */
  ulong   prev_incr_snapshot_dist;  /* Tracking for incremental snapshot creation */
  ulong   double_constipation_slot; /* Tracking for double constipation if any */

  fd_funk_txn_t * false_root;
  fd_funk_txn_t * second_false_root;

  int     is_caught_up;

  /* Metrics */
  fd_replay_tile_metrics_t metrics;
};
typedef struct fd_replay_tile_ctx fd_replay_tile_ctx_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 128UL;
}

FD_FN_PURE static inline ulong
loose_footprint( fd_topo_tile_t const * tile FD_PARAM_UNUSED ) {
  return 24UL * FD_SHMEM_GIGANTIC_PAGE_SZ;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile FD_PARAM_UNUSED ) {

  /* Do not modify order! This is join-order in unprivileged_init. */

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_replay_tile_ctx_t), sizeof(fd_replay_tile_ctx_t) );
  l = FD_LAYOUT_APPEND( l, fd_alloc_align(), fd_alloc_footprint() );
  l = FD_LAYOUT_APPEND( l, FD_CAPTURE_CTX_ALIGN, FD_CAPTURE_CTX_FOOTPRINT );
  l = FD_LAYOUT_APPEND( l, fd_epoch_align(), fd_epoch_footprint( FD_VOTER_MAX ) );
  l = FD_LAYOUT_APPEND( l, fd_forks_align(), fd_forks_footprint( FD_BLOCK_MAX ) );
  l = FD_LAYOUT_APPEND( l, fd_ghost_align(), fd_ghost_footprint( FD_BLOCK_MAX ) );
  l = FD_LAYOUT_APPEND( l, fd_replay_align(), fd_replay_footprint( tile->replay.fec_max, FD_SHRED_MAX_PER_SLOT, FD_BLOCK_MAX ) );
  l = FD_LAYOUT_APPEND( l, fd_tower_align(), fd_tower_footprint() );
  l = FD_LAYOUT_APPEND( l, fd_bank_hash_cmp_align(), fd_bank_hash_cmp_footprint( ) );
  for( ulong i = 0UL; i<FD_PACK_MAX_BANK_TILES; i++ ) {
    l = FD_LAYOUT_APPEND( l, FD_BMTREE_COMMIT_ALIGN, FD_BMTREE_COMMIT_FOOTPRINT(0) );
  }
  l = FD_LAYOUT_APPEND( l, 128UL, FD_SLICE_MAX );
  ulong  thread_spad_size  = fd_spad_footprint( FD_RUNTIME_TRANSACTION_EXECUTION_FOOTPRINT_DEFAULT );
  l = FD_LAYOUT_APPEND( l, fd_spad_align(), tile->replay.tpool_thread_count * fd_ulong_align_up( thread_spad_size, fd_spad_align() ) );
  l = FD_LAYOUT_APPEND( l, fd_spad_align(), FD_RUNTIME_BLOCK_EXECUTION_FOOTPRINT ); /* FIXME: make this configurable */
  l = FD_LAYOUT_FINI  ( l, scratch_align() );
  return l;
}

static void
hash_transactions( void *       mem,
                   fd_txn_p_t * txns,
                   ulong        txn_cnt,
                   uchar *      mixin ) {
  fd_bmtree_commit_t * bmtree = fd_bmtree_commit_init( mem, 32UL, 1UL, 0UL );
  for( ulong i=0; i<txn_cnt; i++ ) {
    fd_txn_p_t * _txn = txns + i;
    if( FD_UNLIKELY( !(_txn->flags & FD_TXN_P_FLAGS_EXECUTE_SUCCESS) ) ) continue;

    fd_txn_t * txn = TXN(_txn);
    for( ulong j=0; j<txn->signature_cnt; j++ ) {
      fd_bmtree_node_t node[1];
      fd_bmtree_hash_leaf( node, _txn->payload+txn->signature_off+64UL*j, 64UL, 1UL );
      fd_bmtree_commit_append( bmtree, node, 1UL );
    }
  }
  uchar * root = fd_bmtree_commit_fini( bmtree );
  fd_memcpy( mixin, root, 32UL );
}

void
publish_stake_weights( fd_replay_tile_ctx_t * ctx,
                       fd_stem_context_t *    stem,
                       fd_exec_slot_ctx_t *   slot_ctx ) {
  fd_epoch_bank_t * epoch_bank = fd_exec_epoch_ctx_epoch_bank( slot_ctx->epoch_ctx );
  if( slot_ctx->slot_bank.epoch_stakes.vote_accounts_root!=NULL ) {
    ulong *             stake_weights_msg = fd_chunk_to_laddr( ctx->stake_weights_out_mem,
                                                               ctx->stake_weights_out_chunk );
    fd_stake_weight_t * stake_weights     = (fd_stake_weight_t *)&stake_weights_msg[5];
    ulong               stake_weight_idx  = fd_stake_weights_by_node( &ctx->slot_ctx->slot_bank.epoch_stakes,
                                                                      stake_weights,
                                                                      ctx->runtime_spad );

    stake_weights_msg[0] = fd_slot_to_leader_schedule_epoch( &epoch_bank->epoch_schedule, slot_ctx->slot_bank.slot ) - 1; /* epoch */
    stake_weights_msg[1] = stake_weight_idx; /* staked_cnt */
    stake_weights_msg[2] = fd_epoch_slot0( &epoch_bank->epoch_schedule, stake_weights_msg[0] ); /* start_slot */
    stake_weights_msg[3] = epoch_bank->epoch_schedule.slots_per_epoch; /* slot_cnt */
    stake_weights_msg[4] = 0UL; /* excluded stake */
    FD_LOG_NOTICE(("sending current epoch stake weights - epoch: %lu, stake_weight_cnt: %lu, start_slot: %lu, slot_cnt: %lu", stake_weights_msg[0], stake_weights_msg[1], stake_weights_msg[2], stake_weights_msg[3]));
    ulong tspub = fd_frag_meta_ts_comp( fd_tickcount() );

    ulong stake_weights_sz  = 5*sizeof(ulong) + (stake_weight_idx * sizeof(fd_stake_weight_t));
    ulong stake_weights_sig = 4UL;
    fd_stem_publish( stem, 0UL, stake_weights_sig, ctx->stake_weights_out_chunk, stake_weights_sz, 0UL, 0UL, tspub );
    ctx->stake_weights_out_chunk = fd_dcache_compact_next( ctx->stake_weights_out_chunk, stake_weights_sz, ctx->stake_weights_out_chunk0, ctx->stake_weights_out_wmark );
  }

  if( epoch_bank->next_epoch_stakes.vote_accounts_root!=NULL ) {
    ulong * stake_weights_msg         = fd_chunk_to_laddr( ctx->stake_weights_out_mem, ctx->stake_weights_out_chunk );
    fd_stake_weight_t * stake_weights = (fd_stake_weight_t *)&stake_weights_msg[5];
    ulong stake_weight_idx            = fd_stake_weights_by_node( &epoch_bank->next_epoch_stakes, stake_weights, ctx->runtime_spad );

    stake_weights_msg[0] = fd_slot_to_leader_schedule_epoch( &epoch_bank->epoch_schedule,
                                                             slot_ctx->slot_bank.slot ); /* epoch */
    stake_weights_msg[1] = stake_weight_idx; /* staked_cnt */
    stake_weights_msg[2] = fd_epoch_slot0( &epoch_bank->epoch_schedule, stake_weights_msg[0] ); /* start_slot */
    stake_weights_msg[3] = epoch_bank->epoch_schedule.slots_per_epoch; /* slot_cnt */
    stake_weights_msg[4] = 0UL; /* excluded stake */
    FD_LOG_NOTICE(("sending next epoch stake weights - epoch: %lu, stake_weight_cnt: %lu, start_slot: %lu, slot_cnt: %lu", stake_weights_msg[0], stake_weights_msg[1], stake_weights_msg[2], stake_weights_msg[3]));
    ulong tspub = fd_frag_meta_ts_comp( fd_tickcount() );

    ulong stake_weights_sz = 5*sizeof(ulong) + (stake_weight_idx * sizeof(fd_stake_weight_t));
    ulong stake_weights_sig = 4UL;
    fd_stem_publish( stem, 0UL, stake_weights_sig, ctx->stake_weights_out_chunk, stake_weights_sz, 0UL, 0UL, tspub );
    ctx->stake_weights_out_chunk = fd_dcache_compact_next( ctx->stake_weights_out_chunk, stake_weights_sz, ctx->stake_weights_out_chunk0, ctx->stake_weights_out_wmark );
  }
}

/* Polls the blockstore block info object for newly completed slices of
   slot. Adds it to the tail of slice_deque (which should be the
   slice_deque object of the slot, slice_map[slot]) */

int
slice_poll( fd_replay_tile_ctx_t * ctx,
            fd_replay_slice_t    * slice_deque,
            ulong slot ) {
  uint consumed_idx, slices_added;
  for(;;) { /* speculative query */
    fd_block_map_query_t query[1] = { 0 };
    int err = fd_block_map_query_try( ctx->blockstore->block_map, &slot, NULL, query, 0 );
    fd_block_info_t * block_info = fd_block_map_query_ele( query );

    if( FD_UNLIKELY( err == FD_MAP_ERR_KEY   ) ) return 0;
    if( FD_UNLIKELY( err == FD_MAP_ERR_AGAIN ) ) continue;

    consumed_idx = block_info->consumed_idx;
    slices_added = 0;

    if( FD_UNLIKELY( block_info->buffered_idx == UINT_MAX ) ) return 1;

    for( uint idx = consumed_idx + 1; idx <= block_info->buffered_idx; idx++ ) {
      if( FD_UNLIKELY( fd_block_set_test( block_info->data_complete_idxs, idx ) ) ) {
        slices_added++;
        fd_replay_slice_deque_push_tail( slice_deque->deque, ((ulong)(consumed_idx + 1) << 32) | ((ulong)idx) );
        FD_LOG_INFO(( "adding slice replay: slot %lu, slice start: %u, slice end: %u", slot, consumed_idx + 1, idx ));
        consumed_idx = idx;
      }
    }
    if( FD_UNLIKELY( fd_block_map_query_test( query ) == FD_MAP_SUCCESS ) ) break;
    /* need to dequeue and try again speculatively */
    for( uint i = 0; i < slices_added; i++ ) {
      fd_replay_slice_deque_pop_tail( slice_deque->deque );
    }
  }

  if( slices_added ){
    fd_block_map_query_t query[1] = { 0 };
    fd_block_map_prepare( ctx->blockstore->block_map, &slot, NULL, query, FD_MAP_FLAG_BLOCKING );
    fd_block_info_t * block_info = fd_block_map_query_ele( query );
    block_info->consumed_idx = consumed_idx;
    fd_block_map_publish( query );
    return 1;
  }
  return 0;
}

static int
before_frag( fd_replay_tile_ctx_t * ctx,
             ulong                  in_idx,
             ulong                  seq,
             ulong                  sig ) {
  (void)seq;

  if( in_idx == SHRED_IN_IDX ) {
    //FD_LOG_NOTICE(( "in_idx: %lu, seq: %lu, sig: %lu", in_idx, seq, sig ));

    ulong slot        = fd_disco_shred_replay_sig_slot       ( sig );
    uint  shred_idx   = fd_disco_shred_replay_sig_shred_idx  ( sig );
    uint  fec_set_idx = fd_disco_shred_replay_sig_fec_set_idx( sig );
    int   is_code     = fd_disco_shred_replay_sig_is_code    ( sig );
    int   completes   = fd_disco_shred_replay_sig_completes  ( sig );

    fd_replay_fec_t * fec = fd_replay_fec_query( ctx->replay, slot, fec_set_idx );
    if( FD_UNLIKELY( !fec ) ) { /* first time receiving a shred for this FEC set */
      fec = fd_replay_fec_insert( ctx->replay, slot, fec_set_idx );
      ctx->fecs_inserted++;
      /* TODO implement eviction */
    }

    /* If the FEC set is complete we don't need to track it anymore. */

    if( FD_UNLIKELY( completes ) ) {
      fd_replay_slice_t * slice_deque = fd_replay_slice_map_query( ctx->replay->slice_map, slot, NULL );

      if( FD_UNLIKELY( !slice_deque ) ) slice_deque = fd_replay_slice_map_insert( ctx->replay->slice_map, slot ); /* create new map entry for this slot */

      FD_LOG_INFO(( "removing FEC set %u from slot %lu", fec_set_idx, slot ));
      fd_replay_fec_remove( ctx->replay, slot, fec_set_idx );
      ctx->fecs_removed++;
      slice_poll( ctx, slice_deque, slot );
      return 1; /* skip frag */
    }

    /* If it is a coding shred, check if it is the first coding shred
       we're receiving. We know it's the first if data_cnt is 0 because
       that is not a valid cnt and means it's uninitialized. */

    if( FD_LIKELY( is_code ) ) { /* optimize for |code| >= |data| */
      return fec->data_cnt != 0; /* process frag (shred hdr) if it's the first coding shred */
    } else {
      uint i = shred_idx - fec_set_idx;
      fd_replay_fec_idxs_insert( fec->idxs, i ); /* mark ith data shred as received */
      return 1; /* skip frag */
    }
  }

  return 0; /* non-shred in - don't skip */
}

static void
during_frag( fd_replay_tile_ctx_t * ctx,
             ulong                  in_idx,
             ulong                  seq FD_PARAM_UNUSED,
             ulong                  sig,
             ulong                  chunk,
             ulong                  sz,
             ulong                  ctl FD_PARAM_UNUSED ) {

  ctx->skip_frag = 0;

  if( in_idx == STORE_IN_IDX ) {
    if( FD_UNLIKELY( chunk<ctx->store_in_chunk0 || chunk>ctx->store_in_wmark || sz>MAX_TXNS_PER_REPLAY ) ) {
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->store_in_chunk0, ctx->store_in_wmark ));
    }
    uchar * src = (uchar *)fd_chunk_to_laddr( ctx->store_in_mem, chunk );
    /* Incoming packet from store tile. Format:
       Parent slot (ulong - 8 bytes)
       Updated block hash/PoH hash (fd_hash_t - 32 bytes)
       Microblock as a list of fd_txn_p_t (sz * sizeof(fd_txn_p_t)) */

    ctx->curr_slot = fd_disco_replay_old_sig_slot( sig );
    /* slot changes */
    if( FD_UNLIKELY( ctx->curr_slot < fd_fseq_query( ctx->published_wmark ) ) ) {
      FD_LOG_WARNING(( "store sent slot %lu before our root.", ctx->curr_slot ));
    }
    ctx->flags = 0; //fd_disco_replay_old_sig_flags( sig );
    ctx->txn_cnt = sz;

    ctx->parent_slot = FD_LOAD( ulong, src );
    src += sizeof(ulong);
    memcpy( ctx->blockhash.uc, src, sizeof(fd_hash_t) );
    src += sizeof(fd_hash_t);
    ctx->bank_idx = 0UL;
    fd_replay_out_ctx_t * bank_out = &ctx->bank_out[ ctx->bank_idx ];
    uchar * dst_poh = fd_chunk_to_laddr( bank_out->mem, bank_out->chunk );
    fd_memcpy( dst_poh, src, sz * sizeof(fd_txn_p_t) );

    FD_LOG_INFO(( "other microblock - slot: %lu, parent_slot: %lu, txn_cnt: %lu", ctx->curr_slot, ctx->parent_slot, sz ));
  } else if( in_idx == PACK_IN_IDX ) {
    if( FD_UNLIKELY( chunk<ctx->pack_in_chunk0 || chunk>ctx->pack_in_wmark || sz>USHORT_MAX ) ) {
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->pack_in_chunk0, ctx->pack_in_wmark ));
    }
    uchar * src = (uchar *)fd_chunk_to_laddr( ctx->pack_in_mem, chunk );
    /* Incoming packet from pack tile. Format:
       Microblock as a list of fd_txn_p_t (sz * sizeof(fd_txn_p_t))
       Microblock bank trailer
    */
    ctx->curr_slot = fd_disco_poh_sig_slot( sig );
    if( FD_UNLIKELY( ctx->curr_slot < fd_fseq_query( ctx->published_wmark ) ) ) {
      FD_LOG_WARNING(( "pack sent slot %lu before our watermark %lu.", ctx->curr_slot, fd_fseq_query( ctx->published_wmark ) ));
    }
    if( fd_disco_poh_sig_pkt_type( sig )==POH_PKT_TYPE_MICROBLOCK ) {
      ulong bank_idx = fd_disco_poh_sig_bank_tile( sig );
      fd_replay_out_ctx_t * bank_out = &ctx->bank_out[ bank_idx ];
      uchar * dst_poh = fd_chunk_to_laddr( bank_out->mem, bank_out->chunk );
      ctx->flags = REPLAY_FLAG_PACKED_MICROBLOCK;
      ctx->txn_cnt = (sz - sizeof(fd_microblock_bank_trailer_t)) / sizeof(fd_txn_p_t);
      ctx->bank_idx = bank_idx;
      fd_memcpy( dst_poh, src, (sz - sizeof(fd_microblock_bank_trailer_t)) );
      src += (sz-sizeof(fd_microblock_bank_trailer_t));
      dst_poh += (sz - sizeof(fd_microblock_bank_trailer_t));
      fd_microblock_bank_trailer_t * t = (fd_microblock_bank_trailer_t *)src;
      ctx->parent_slot = (ulong)t->bank;
    } else {
      FD_LOG_WARNING(("OTHER PACKET TYPE: %lu", fd_disco_poh_sig_pkt_type( sig )));
      ctx->skip_frag = 1;
      return;
    }

    FD_LOG_DEBUG(( "packed microblock - slot: %lu, parent_slot: %lu, txn_cnt: %lu", ctx->curr_slot, ctx->parent_slot, ctx->txn_cnt ));
  } else if( in_idx==BATCH_IN_IDX ) {
    uchar * src = (uchar *)fd_chunk_to_laddr( ctx->batch_in_mem, chunk );
    fd_memcpy( ctx->slot_ctx->slot_bank.epoch_account_hash.uc, src, sizeof(fd_hash_t) );
    FD_LOG_NOTICE(( "Epoch account hash calculated to be %s", FD_BASE58_ENC_32_ALLOCA( ctx->slot_ctx->slot_bank.epoch_account_hash.uc ) ));
  } else if ( in_idx >= SHRED_IN_IDX ) {

    fd_shred_replay_in_ctx_t * shred_in = &ctx->shred_in[ in_idx-SHRED_IN_IDX ];
    if( FD_UNLIKELY( chunk<shred_in->chunk0 || chunk>shred_in->wmark || sz > sizeof(fd_shred34_t) ) ) {
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, shred_in->chunk0 , shred_in->wmark ));
    }
    // uchar * src = (uchar *)fd_chunk_to_laddr( shred_in->mem, chunk );
    // fd_memcpy( (uchar *)ctx->shred, src, sz ); /* copy the hdr to read the code_cnt & data_cnt */

    ctx->skip_frag = 1;

    return;
  }
  // if( ctx->flags & REPLAY_FLAG_PACKED_MICROBLOCK ) {
  //   /* We do not know the parent slot, pick one from fork selection */
  //   ulong max_slot = 0; /* FIXME: default to snapshot slot/smr */
  //   for( fd_fork_frontier_iter_t iter = fd_fork_frontier_iter_init( ctx->forks->frontier, ctx->forks->pool );
  //      !fd_fork_frontier_iter_done( iter, ctx->forks->frontier, ctx->forks->pool );
  //      iter = fd_fork_frontier_iter_next( iter, ctx->forks->frontier, ctx->forks->pool ) ) {
  //     fd_exec_slot_ctx_t * ele = &fd_fork_frontier_iter_ele( iter, ctx->forks->frontier, ctx->forks->pool )->slot_ctx;
  //     if ( max_slot < ele->slot_bank.slot ) {
  //       max_slot = ele->slot_bank.slot;
  //     }
  //   }
  //   ctx->parent_slot = max_slot;
  // }

  uchar block_flags = 0;
  int err = FD_MAP_ERR_AGAIN;
  while( err == FD_MAP_ERR_AGAIN ){
    fd_block_map_query_t quer[1] = { 0 };
    err = fd_block_map_query_try( ctx->blockstore->block_map, &ctx->curr_slot, NULL, quer, 0 );
    fd_block_info_t * block_info = fd_block_map_query_ele( quer );
    if( FD_UNLIKELY( err == FD_MAP_ERR_AGAIN ) ) continue;
    if( FD_UNLIKELY( err == FD_MAP_ERR_KEY )) break;
    block_flags = block_info->flags;
    err = fd_block_map_query_test( quer );
  }

  if( FD_UNLIKELY( fd_uchar_extract_bit( block_flags, FD_BLOCK_FLAG_PROCESSED ) ) ) {
    FD_LOG_WARNING(( "block already processed - slot: %lu", ctx->curr_slot ));
    ctx->skip_frag = 1;
  }
  if( FD_UNLIKELY( fd_uchar_extract_bit( block_flags, FD_BLOCK_FLAG_DEADBLOCK ) ) ) {
    FD_LOG_WARNING(( "block already dead - slot: %lu", ctx->curr_slot ));
    ctx->skip_frag = 1;
  }
}

static void
checkpt( fd_replay_tile_ctx_t * ctx ) {
  if( FD_UNLIKELY( ctx->slots_replayed_file ) ) fclose( ctx->slots_replayed_file );
  if( FD_UNLIKELY( strcmp( ctx->blockstore_checkpt, "" ) ) ) {
    int rc = fd_wksp_checkpt( ctx->blockstore_wksp, ctx->blockstore_checkpt, 0666, 0, NULL );
    if( rc ) {
      FD_LOG_ERR( ( "blockstore checkpt failed: error %d", rc ) );
    }
  }
  int rc = fd_wksp_checkpt( ctx->funk_wksp, ctx->funk_checkpt, 0666, 0, NULL );
  if( rc ) {
    FD_LOG_ERR( ( "funk checkpt failed: error %d", rc ) );
  }
}

static void
funk_cancel( fd_replay_tile_ctx_t * ctx, ulong mismatch_slot ) {
  fd_funk_txn_xid_t xid        = { .ul = { mismatch_slot, mismatch_slot } };
  fd_funk_txn_t * txn_map      = fd_funk_txn_map( ctx->funk, fd_funk_wksp( ctx->funk ) );
  fd_funk_txn_t * mismatch_txn = fd_funk_txn_query( &xid, txn_map );
  fd_funk_start_write( ctx->funk );
  FD_TEST( fd_funk_txn_cancel( ctx->funk, mismatch_txn, 1 ) );
  fd_funk_end_write( ctx->funk );
}

struct fd_status_check_ctx {
  fd_slot_history_t * slot_history;
  fd_txncache_t * txncache;
  ulong current_slot;
};
typedef struct fd_status_check_ctx fd_status_check_ctx_t;

static void
txncache_publish( fd_replay_tile_ctx_t * ctx,
                  fd_funk_txn_t *        txn_map,
                  fd_funk_txn_t *        to_root_txn,
                  fd_funk_txn_t *        rooted_txn ) {


  /* For the status cache, we stop rooting until the status cache has been
     written out to the current snapshot. We also need to iterate up the
     funk transaction tree up until the current "root" to figure out what slots
     should be registered. This root can correspond to the latest false root if
     one exists.  */


  if( FD_UNLIKELY( !ctx->slot_ctx->status_cache ) ) {
    return;
  }

  fd_funk_txn_t * txn = to_root_txn;
  while( txn!=rooted_txn ) {
    ulong slot = txn->xid.ul[0];
    if( FD_LIKELY( !fd_txncache_get_is_constipated( ctx->slot_ctx->status_cache ) ) ) {
      FD_LOG_INFO(( "Registering slot %lu", slot ));
      fd_txncache_register_root_slot( ctx->slot_ctx->status_cache, slot );
    } else {
      FD_LOG_INFO(( "Registering constipated slot %lu", slot ));
      fd_txncache_register_constipated_slot( ctx->slot_ctx->status_cache, slot );
    }
    txn = fd_funk_txn_parent( txn, txn_map );
  }
}

static void
snapshot_state_update( fd_replay_tile_ctx_t * ctx, ulong wmk ) {

  /* We are ready for a snapshot if either we are on or just passed a snapshot
     interval and no snapshot is currently in progress. This is to handle the
     case where the snapshot interval falls on a skipped slot.

     We are ready to create a snapshot if:
     1. The node is caught up to the network.
     2. There is currently no snapshot in progress
     3. The current slot is at the snapshot interval OR
        The current slot has passed a snapshot interval

    If a snapshot is ready to be created we will constipate funk and the
    status cache. This will also notify the status cache via the funk
    constipation fseq. */

  if( ctx->snapshot_interval==ULONG_MAX ) {
    return;
  }

  uchar is_constipated = fd_fseq_query( ctx->is_constipated ) != 0UL;

  if( !ctx->is_caught_up ) {
    return;
  }

  if( is_constipated ) {
    return;
  }

  fd_epoch_bank_t * epoch_bank = fd_exec_epoch_ctx_epoch_bank( ctx->slot_ctx->epoch_ctx );

  /* The distance from the last snapshot should only grow until we skip
     past the last full snapshot. If it has shrunk that means we skipped
     over the snapshot interval. */
  ulong curr_full_snapshot_dist = wmk % ctx->snapshot_interval;
  uchar is_full_snapshot_ready  = curr_full_snapshot_dist < ctx->prev_full_snapshot_dist;
  ctx->prev_full_snapshot_dist  = curr_full_snapshot_dist;

  /* Do the same for incrementals, only try to create one if there has been
     a full snapshot. */

  ulong curr_incr_snapshot_dist = wmk % ctx->incremental_interval;

  uchar is_inc_snapshot_ready   = wmk % ctx->incremental_interval < ctx->prev_incr_snapshot_dist && ctx->last_full_snap;
  ctx->prev_incr_snapshot_dist  = curr_incr_snapshot_dist;

  ulong updated_fseq = 0UL;

  /* TODO: We need a better check if the wmk fell on an epoch boundary due to
     skipped slots. We just don't want to make a snapshot on an epoch boundary */
  if( (is_full_snapshot_ready || is_inc_snapshot_ready) &&
      !fd_runtime_is_epoch_boundary( epoch_bank, wmk, wmk-1UL ) ) {
    /* Constipate the status cache when a snapshot is ready to be created. */
    if( is_full_snapshot_ready ) {
      ctx->last_full_snap = wmk;
      FD_LOG_NOTICE(( "Ready to create a full snapshot" ));
      updated_fseq = fd_batch_fseq_pack( 1, 0, wmk );
    } else {
      FD_LOG_NOTICE(( "Ready to create an incremental snapshot" ));
      updated_fseq = fd_batch_fseq_pack( 1, 1, wmk );
    }
    fd_txncache_set_is_constipated( ctx->slot_ctx->status_cache, 1 );
    fd_fseq_update( ctx->is_constipated, updated_fseq );
  }
}

static void
funk_publish( fd_replay_tile_ctx_t * ctx,
              fd_funk_txn_t *        to_root_txn,
              fd_funk_txn_t *        txn_map,
              ulong                  wmk,
              uchar                  is_constipated ) {

  fd_funk_start_write( ctx->funk );

  fd_epoch_bank_t * epoch_bank = fd_exec_epoch_ctx_epoch_bank( ctx->slot_ctx->epoch_ctx );

  /* Now try to publish into funk, this is handled differently based on if
     funk is constipated or if funk is double-constipated. Even if funk was
     double-constipated and now no-longer is we still want to preserve the
     root for the epoch account hash. */
  if( ctx->double_constipation_slot ) {
    FD_LOG_NOTICE(( "Double constipation publish for wmk=%lu", wmk ));

    fd_funk_txn_t * txn = to_root_txn;
    while( txn!=ctx->second_false_root ) {
      if( FD_UNLIKELY( fd_funk_txn_publish_into_parent( ctx->funk, txn, 0 ) ) ) {
        FD_LOG_ERR(( "Can't publish funk transaction" ));
      }
      txn = fd_funk_txn_parent( txn, txn_map );
    }

  } else if( is_constipated ) {
    FD_LOG_NOTICE(( "Publishing slot=%lu while constipated", wmk ));

    /* At this point, first collapse the current transaction that should be
       published into the oldest child transaction. */

    if( FD_UNLIKELY( wmk>=epoch_bank->eah_start_slot ) ) {
      /* We need to double-constipate at this point. */

      /* First, find the txn where the corresponding slot is the minimum
         pending transaction where >= eah_start_slot. */

      fd_funk_txn_t * txn        = to_root_txn;
      fd_funk_txn_t * parent_txn = fd_funk_txn_parent( txn, txn_map );

      while( parent_txn ) {

        int is_curr_gteq_eah_start = txn->xid.ul[0] >= epoch_bank->eah_start_slot;
        int is_prev_lt_eah_start   = parent_txn->xid.ul[0] < epoch_bank->eah_start_slot;
        if( is_curr_gteq_eah_start && is_prev_lt_eah_start ) {
          break;
        }
        txn        = parent_txn;
        parent_txn = fd_funk_txn_parent( txn, txn_map );
      }

      /* We should never get to this point because of the constipated root.
         The constipated root is guaranteed to have a slot that's < eah_start_slot. */
      if( FD_UNLIKELY( !parent_txn ) ) {
        FD_LOG_ERR(( "Not possible for the parent_txn to be the root" ));
      }

      /* This transaction will now become the double-constipated root. */

      FD_LOG_NOTICE(( "Entering a double constipated state eah_start=%lu eah_slot=%lu",
                      epoch_bank->eah_start_slot, txn->xid.ul[0] ));

      ctx->double_constipation_slot = txn->xid.ul[0];

      /* Other pending transactions will get published into the child during
         the next invocation of funk_publish. */
    } else {

      FD_LOG_NOTICE(( "Publishing into constipated root for wmk=%lu", wmk ));
      /* Standard constipated case where we aren't considering the eah. */
      fd_funk_txn_t * txn        = to_root_txn;

      while( txn!=ctx->false_root ) {
        if( FD_UNLIKELY( fd_funk_txn_publish_into_parent( ctx->funk, txn, 0 ) ) ) {
          FD_LOG_ERR(( "Can't publish funk transaction" ));
        }
        txn = fd_funk_txn_parent( txn, txn_map );
      }
    }
  } else {

    /* This is the case where we are not in the constipated case. We only need
       to do special handling in the case where the epoch account hash is about
       to be calculated. */

    FD_LOG_NOTICE(( "Publishing slot=%lu", wmk ));

    if( FD_UNLIKELY( wmk>=epoch_bank->eah_start_slot ) ) {

      FD_LOG_NOTICE(( "EAH is ready to be calculated" ));

      /* This condition means that we want to start producing an epoch account
         hash at a slot that is in the set of transactions we are about to
         publish. We only want to publish all slots that are <= the slot that
         we will calculate the epoch account hash for. */

      fd_funk_txn_t * txn        = to_root_txn;
      fd_funk_txn_t * parent_txn = fd_funk_txn_parent( txn, txn_map );
      while( parent_txn ) {
        /* We need to be careful here because the eah start slot may be skipped
           so the actual slot that we calculate the eah for may be greater than
           the eah start slot. The transaction must correspond to a slot greater
           than or equal to the eah start slot, but its parent transaction must
           either have been published already or must be less than the eah start
           slot. */

        int is_curr_gteq_eah_start = txn->xid.ul[0] >= epoch_bank->eah_start_slot;
        int is_prev_lt_eah_start   = parent_txn->xid.ul[0] < epoch_bank->eah_start_slot;
        if( is_curr_gteq_eah_start && is_prev_lt_eah_start ) {
          break;
        }
        txn        = parent_txn;
        parent_txn = fd_funk_txn_parent( txn, txn_map );
      }

      /* At this point, we know txn is the funk txn that we will want to
         calculate the eah for since it's the minimum slot that is >=
         eah_start_slot. */

      FD_LOG_NOTICE(( "The eah has an expected start slot of %lu and is being created for slot %lu", epoch_bank->eah_start_slot, txn->xid.ul[0] ));

      if( FD_UNLIKELY( !fd_funk_txn_publish( ctx->funk, txn, 1 ) ) ) {
        FD_LOG_ERR(( "failed to funk publish" ));
      }

      /* At this point, we have the root for which we want to calculate the
         epoch account hash for. The other children that are > eah_start_slot
         but <= wmk will be published into the constipated root during the next
         invocation of funk_and_txncache_publish.

         Notify the batch tile that an eah should be computed. */

      ulong updated_fseq = fd_batch_fseq_pack( 0UL, 0UL, txn->xid.ul[0] );
      fd_fseq_update( ctx->is_constipated, updated_fseq );
      epoch_bank->eah_start_slot = FD_SLOT_NULL;

    } else {
      /* This is the standard case. Publish all transactions up to and
         including the watermark. This will publish any in-prep ancestors
         of root_txn as well. */

      if( FD_UNLIKELY( !fd_funk_txn_publish( ctx->funk, to_root_txn, 1 ) ) ) {
        FD_LOG_ERR(( "failed to funk publish slot %lu", wmk ));
      }
    }
  }

  fd_funk_end_write( ctx->funk );

}

static fd_funk_txn_t*
get_rooted_txn( fd_replay_tile_ctx_t * ctx,
                fd_funk_txn_t *        to_root_txn,
                fd_funk_txn_t *        txn_map,
                uchar                  is_constipated ) {

  /* We need to get the rooted transaction that we are publishing into. This
     needs to account for the three different cases: no constipation, single
     constipation, double constipation.

     Also, if it's the first time that we are setting the false root(s), then
     we must also register them into the status cache because we don't register
     the root in txncache_publish to avoid registering the same slot multiple times. */

  if( FD_UNLIKELY( ctx->double_constipation_slot ) ) {

    if( FD_UNLIKELY( !ctx->second_false_root ) ) {

      /* Set value of second false root, save it and publish to txncache. */
      fd_funk_txn_t * txn = to_root_txn;
      while( txn->xid.ul[0]>ctx->double_constipation_slot ) {
        txn = fd_funk_txn_parent( txn, txn_map );
      }

      if( FD_LIKELY( !fd_txncache_get_is_constipated( ctx->slot_ctx->status_cache ) ) ) {
        fd_txncache_register_root_slot( ctx->slot_ctx->status_cache, txn->xid.ul[0] );
      } else {
        fd_txncache_register_constipated_slot( ctx->slot_ctx->status_cache, txn->xid.ul[0] );
      }

      if( txn->xid.ul[0] != ctx->double_constipation_slot ) {
        FD_LOG_ERR(( "txn->xid.ul[0] = %lu, ctx->double_constipation_slot = %lu", txn->xid.ul[0], ctx->double_constipation_slot ));
      }
      ctx->second_false_root = txn;
    }
    return ctx->second_false_root;
  } else if( is_constipated ) {

    if( FD_UNLIKELY( !ctx->false_root ) ) {

      fd_funk_txn_t * txn        = to_root_txn;
      fd_funk_txn_t * parent_txn = fd_funk_txn_parent( txn, txn_map );
      while( parent_txn ) {
        txn        = parent_txn;
        parent_txn = fd_funk_txn_parent( txn, txn_map );
      }

      ctx->false_root = txn;
      if( !fd_txncache_get_is_constipated( ctx->slot_ctx->status_cache ) ) {
        fd_txncache_register_root_slot( ctx->slot_ctx->status_cache, txn->xid.ul[0] );
      } else {
        fd_txncache_register_constipated_slot( ctx->slot_ctx->status_cache, txn->xid.ul[0] );
      }
    }
    return ctx->false_root;
  } else {
    return NULL;
  }
}

static void
funk_and_txncache_publish( fd_replay_tile_ctx_t * ctx, ulong wmk, fd_funk_txn_xid_t const * xid ) {

  FD_LOG_NOTICE(( "Entering funk_and_txncache_publish for wmk=%lu", wmk ));

  /* This function is responsible for publishing/registering all in-prep slots
     up to and including the watermark slot into funk and the transaction cache.

     However, we need to modify this behavior to support snapshot creation and
     epoch account hash generation (which is handled by the batch tile).
     Specifically, we need to change the mechanism by introducing the concept of
     a constipated root. We want to keep the root of funk/txncache constant
     while the batch tile reads from the root of funk. At the same time, we
     want to keep publishing into funk. We accomplish this by treating the
     oldest in-prep ancestor of funk as the "constipated/false" root. While
     the batch tile "works", we will only publish into the false root. Once the
     batch tile is done producing a snapshot/eah, we will then flush the
     constipated root into the real root of funk as we no longer need a frozen
     funk transaction to read from. The batch tile will communicate with the
     replay tile via the is_constipated fseq and a link.

     There is a pretty important edge case to consider here: what do we do if
     we are currently in the middle of creating a snapshot, but we need to
     record our state for the epoch account hash? The epoch account hash must
     be created for a specific slot and we can't block execution to calculate
     this hash. The solution will be to introduce a second constipation via a
     second false root. This new false root will correspond to the oldest
     child transaction of the transaction that corresponds to the eah
     calculation slot. When the snapshot is done being produced, any further
     snapshot creation will be blocked until the epoch account hash is created.
     We will use the second false root to publish into while the batch tile
     produces the epoch account hash. We do not modify any of the parents of
     the second constipated root until we are done producing a snapshot.

     A similar mechanism for txncache constipation is needed only for snapshot
     creation. This is simpler than for funk because txncache operations are
     atomic and we can just register slots into a constipated set while the
     txncache is getting copied out. This is a much faster operation and the
     txncache will likely get unconstipated before funk.

     Single Funk Constipation Example:

     If we want to create a snapshot/eah for slot n, then we will publish
     all transactions up to and including those that correspond to slot n.
     We will then publish all transactions into the immediate child of n (lets
     assume it's n+1) in this case. So every transaction will be published into
     n+1 and NOT n. When the computation is done, we resume publishing as normal.

     Double Funk Constipation Example:

     Let's say we are creating a snapshot for slot n and we want
     the epoch account hash for slot m. A snapshot will take x slots to produce
     and we can assume that n + x > m. So at some slot y where n < y < m, the
     state of funk will be: a root at slot n with a constipated root at
     n+1 which gets published into. However, once it is time to publish slot m,
     we will now have a root at slot n, a constipated root at slot m, and we will
     then start publishing into the second constipated root at slot m + 1. */

  /* First wait for all tpool threads to finish. */

  for( ulong i = 0UL; i<ctx->bank_cnt; i++ ) {
    fd_tpool_wait( ctx->tpool, i+1 );
  }

  fd_epoch_bank_t * epoch_bank     = fd_exec_epoch_ctx_epoch_bank( ctx->slot_ctx->epoch_ctx );
  uchar             is_constipated = fd_fseq_query( ctx->is_constipated ) != 0;

  /* If the is_constipated fseq is set to 0 that means that the batch tile
     is currently in an idle state. However, if there was a double constipation
     active, that means that we need to kick off the pending epoch account hash
     calculation. */
  if( ctx->double_constipation_slot && !is_constipated ) {
    FD_LOG_NOTICE(( "No longer double constipated, ready to start computing the epoch account hash" ));

    /* At this point, the snapshot has been completed, so we are now ready to
       start the eah computation. */
    ulong updated_fseq = fd_batch_fseq_pack( 0UL, 0UL, ctx->double_constipation_slot );
    fd_fseq_update( ctx->is_constipated, updated_fseq );
    epoch_bank->eah_start_slot = FD_SLOT_NULL;
  }

  /* If the (second) false root is no longer needed, then we should stop
     tracking it. */
  if( FD_UNLIKELY( ctx->false_root && !is_constipated ) ) {
    FD_LOG_NOTICE(( "Unsetting false root tracking" ));
    ctx->false_root = NULL;
  }
  if( FD_UNLIKELY( ctx->second_false_root && !ctx->double_constipation_slot ) ) {
    FD_LOG_NOTICE(( "Unsetting second false root tracking" ));
    ctx->second_false_root = NULL;
  }


  /* Handle updates to funk and the status cache. */

  fd_funk_txn_t * txn_map     = fd_funk_txn_map( ctx->funk, fd_funk_wksp( ctx->funk ) );
  fd_funk_txn_t * to_root_txn = fd_funk_txn_query( xid, txn_map );
  fd_funk_txn_t * rooted_txn  = get_rooted_txn( ctx, to_root_txn, txn_map, is_constipated );

  txncache_publish( ctx, txn_map, to_root_txn, rooted_txn );

  funk_publish( ctx, to_root_txn, txn_map, wmk, is_constipated );

  /* Update the snapshot state and determine if one is ready to be created. */

  snapshot_state_update( ctx, wmk );

  if( FD_UNLIKELY( ctx->capture_ctx ) ) {
    fd_runtime_checkpt( ctx->capture_ctx, ctx->slot_ctx, wmk );
  }

}

static int
suppress_notify( const fd_pubkey_t * prog ) {
  /* Certain accounts are just noise and a waste of notification bandwidth */
  if( !memcmp( prog, fd_solana_vote_program_id.key, sizeof(fd_pubkey_t) ) ) {
    return 1;
  } else if( !memcmp( prog, fd_solana_system_program_id.key, sizeof(fd_pubkey_t) ) ) {
    return 1;
  } else if( !memcmp( prog, fd_solana_compute_budget_program_id.key, sizeof(fd_pubkey_t) ) ) {
    return 1;
  } else {
    return 0;
  }
}

static void
publish_account_notifications( fd_replay_tile_ctx_t * ctx,
                               fd_fork_t *            fork,
                               ulong                  curr_slot,
                               fd_txn_p_t const *     txns,
                               ulong                  txn_cnt ) {
  long notify_time_ns = -fd_log_wallclock();
#define NOTIFY_START msg = fd_chunk_to_laddr( ctx->notif_out_mem, ctx->notif_out_chunk )
#define NOTIFY_END                                                      \
  fd_mcache_publish( ctx->notif_out_mcache, ctx->notif_out_depth, ctx->notif_out_seq, \
                      0UL, ctx->notif_out_chunk, sizeof(fd_replay_notif_msg_t), 0UL, tsorig, tsorig ); \
  ctx->notif_out_seq   = fd_seq_inc( ctx->notif_out_seq, 1UL );     \
  ctx->notif_out_chunk = fd_dcache_compact_next( ctx->notif_out_chunk, sizeof(fd_replay_notif_msg_t), \
                                                  ctx->notif_out_chunk0, ctx->notif_out_wmark ); \
  msg = NULL

  ulong tsorig = fd_frag_meta_ts_comp( fd_tickcount() );
  fd_replay_notif_msg_t * msg = NULL;

  for( ulong i = 0; i < txn_cnt; ++i ) {
      uchar const * raw = txns[i].payload;
      fd_txn_t const * txn = TXN(txns + i);
      ushort acct_cnt = txn->acct_addr_cnt;
      const fd_pubkey_t * accts = (const fd_pubkey_t *)(raw + txn->acct_addr_off);
      FD_TEST((void*)(accts + acct_cnt) <= (void*)(raw + txns[i].payload_sz));
      fd_ed25519_sig_t const * sigs = (fd_ed25519_sig_t const *)(raw + txn->signature_off);
      FD_TEST((void*)(sigs + txn->signature_cnt) <= (void*)(raw + txns[i].payload_sz));
      for( ushort j = 0; j < acct_cnt; ++j ) {
        if( suppress_notify( accts + j ) ) continue;
        if( msg == NULL ) {
          NOTIFY_START;
          msg->type = FD_REPLAY_ACCTS_TYPE;
          msg->accts.funk_xid = fork->slot_ctx.funk_txn->xid;
          fd_memcpy( msg->accts.sig, sigs, sizeof(fd_ed25519_sig_t) );
          msg->accts.accts_cnt = 0;
        }
        struct fd_replay_notif_acct * out = &msg->accts.accts[ msg->accts.accts_cnt++ ];
        fd_memcpy( out->id, accts + j, sizeof(out->id) );
        int writable = ((j < txn->signature_cnt - txn->readonly_signed_cnt) ||
                        ((j >= txn->signature_cnt) && (j < acct_cnt - txn->readonly_unsigned_cnt)));
        out->flags = (writable ? FD_REPLAY_NOTIF_ACCT_WRITTEN : FD_REPLAY_NOTIF_ACCT_NO_FLAGS );

        if( msg->accts.accts_cnt == FD_REPLAY_NOTIF_ACCT_MAX ) {
          NOTIFY_END;
        }
      }
      if( msg ) {
        NOTIFY_END;
      }
    }

#undef NOTIFY_START
#undef NOTIFY_END
  notify_time_ns += fd_log_wallclock();
  FD_LOG_DEBUG(("TIMING: notify_account_time - slot: %lu, elapsed: %6.6f ms", curr_slot, (double)notify_time_ns * 1e-6));
}

static void
replay_plugin_publish( fd_replay_tile_ctx_t * ctx,
                       fd_stem_context_t * stem,
                       ulong sig,
                       uchar const * data,
                       ulong data_sz ) {
  uchar * dst = (uchar *)fd_chunk_to_laddr( ctx->replay_plugin_out_mem, ctx->replay_plugin_out_chunk );
  fd_memcpy( dst, data, data_sz );
  ulong tspub = (ulong)fd_frag_meta_ts_comp( fd_tickcount() );
  fd_stem_publish( stem, ctx->replay_plug_out_idx, sig, ctx->replay_plugin_out_chunk, data_sz, 0UL, 0UL, tspub );
  ctx->replay_plugin_out_chunk = fd_dcache_compact_next( ctx->replay_plugin_out_chunk, data_sz, ctx->replay_plugin_out_chunk0, ctx->replay_plugin_out_wmark );
}

static void
publish_slot_notifications( fd_replay_tile_ctx_t * ctx,
                            fd_stem_context_t *    stem,
                            fd_fork_t *            fork,
                            ulong                  block_entry_block_height,
                            ulong                  curr_slot ) {
  long notify_time_ns = -fd_log_wallclock();
#define NOTIFY_START msg = fd_chunk_to_laddr( ctx->notif_out_mem, ctx->notif_out_chunk )
#define NOTIFY_END                                                      \
  fd_mcache_publish( ctx->notif_out_mcache, ctx->notif_out_depth, ctx->notif_out_seq, \
                      0UL, ctx->notif_out_chunk, sizeof(fd_replay_notif_msg_t), 0UL, tsorig, tsorig ); \
  ctx->notif_out_seq   = fd_seq_inc( ctx->notif_out_seq, 1UL );     \
  ctx->notif_out_chunk = fd_dcache_compact_next( ctx->notif_out_chunk, sizeof(fd_replay_notif_msg_t), \
                                                  ctx->notif_out_chunk0, ctx->notif_out_wmark ); \
  msg = NULL

  ulong tsorig = fd_frag_meta_ts_comp( fd_tickcount() );
  fd_replay_notif_msg_t * msg = NULL;

  {
    NOTIFY_START;
    msg->type = FD_REPLAY_SLOT_TYPE;
    msg->slot_exec.slot = curr_slot;
    msg->slot_exec.parent = ctx->parent_slot;
    msg->slot_exec.root = fd_fseq_query( ctx->published_wmark );
    msg->slot_exec.height = block_entry_block_height;
    msg->slot_exec.transaction_count = fork->slot_ctx.slot_bank.transaction_count;
    memcpy( &msg->slot_exec.bank_hash, &fork->slot_ctx.slot_bank.banks_hash, sizeof( fd_hash_t ) );
    memcpy( &msg->slot_exec.block_hash, &ctx->blockhash, sizeof( fd_hash_t ) );
    memcpy( &msg->slot_exec.identity, ctx->validator_identity_pubkey, sizeof( fd_pubkey_t ) );
    NOTIFY_END;
  }

#undef NOTIFY_START
#undef NOTIFY_END
  notify_time_ns += fd_log_wallclock();
  FD_LOG_DEBUG(("TIMING: notify_slot_time - slot: %lu, elapsed: %6.6f ms", curr_slot, (double)notify_time_ns * 1e-6));

  if( ctx->replay_plugin_out_mem ) {
    fd_replay_complete_msg_t msg2 = {
      .slot = curr_slot,
      .total_txn_count = fork->slot_ctx.txn_count,
      .nonvote_txn_count = fork->slot_ctx.nonvote_txn_count,
      .failed_txn_count = fork->slot_ctx.failed_txn_count,
      .nonvote_failed_txn_count = fork->slot_ctx.nonvote_failed_txn_count,
      .compute_units = fork->slot_ctx.total_compute_units_used,
      .transaction_fee = fork->slot_ctx.slot_bank.collected_execution_fees,
      .priority_fee = fork->slot_ctx.slot_bank.collected_priority_fees,
      .parent_slot = ctx->parent_slot,
    };
    replay_plugin_publish( ctx, stem, FD_PLUGIN_MSG_SLOT_COMPLETED, (uchar const *)&msg2, sizeof(msg2) );
  }
}

static void
send_tower_sync( fd_replay_tile_ctx_t * ctx ) {
  if( FD_UNLIKELY( !ctx->vote ) ) return;
  FD_LOG_NOTICE( ( "sending tower sync" ) );
  ulong vote_slot = fd_tower_votes_peek_tail_const( ctx->tower )->slot;
  fd_hash_t vote_bank_hash[1]  = { 0 };
  fd_hash_t vote_block_hash[1] = { 0 };
  int err = fd_blockstore_bank_hash_query( ctx->blockstore, vote_slot, vote_bank_hash );
  if( err ) FD_LOG_ERR(( "invariant violation: missing bank hash for tower vote" ));
  err = fd_blockstore_block_hash_query( ctx->blockstore, vote_slot, vote_block_hash );
  if( err ) FD_LOG_ERR(( "invariant violation: missing block hash for tower vote" ));

  /* Build a vote state update based on current tower votes. */

  fd_txn_p_t * txn = (fd_txn_p_t *)fd_chunk_to_laddr( ctx->sender_out_mem, ctx->sender_out_chunk );
  fd_tower_to_vote_txn( ctx->tower,
                        ctx->root,
                        vote_bank_hash,
                        vote_block_hash,
                        ctx->validator_identity,
                        ctx->vote_authority,
                        ctx->vote_acc,
                        txn,
                        ctx->runtime_spad );

  /* TODO: Can use a smaller size, adjusted for payload length */
  ulong msg_sz     = sizeof( fd_txn_p_t );
  fd_mcache_publish( ctx->sender_out_mcache,
                     ctx->sender_out_depth,
                     ctx->sender_out_seq,
                     1UL,
                     ctx->sender_out_chunk,
                     msg_sz,
                     0UL,
                     0,
                     0 );
  ctx->sender_out_seq   = fd_seq_inc( ctx->sender_out_seq, 1UL );
  ctx->sender_out_chunk = fd_dcache_compact_next( ctx->sender_out_chunk,
                                                  msg_sz,
                                                  ctx->sender_out_chunk0,
                                                  ctx->sender_out_wmark );

  /* Dump the latest sent tower into the tower checkpoint file */
  if( FD_LIKELY( ctx->tower_checkpt_fileno > 0 ) ) fd_restart_tower_checkpt( vote_bank_hash, ctx->tower, ctx->ghost, ctx->root, ctx->tower_checkpt_fileno );
}

static fd_fork_t *
prepare_new_block_execution( fd_replay_tile_ctx_t * ctx,
                             fd_stem_context_t *    stem,
                             ulong                  curr_slot,
                             ulong                  flags ) {
  long prepare_time_ns = -fd_log_wallclock();

  int is_new_epoch_in_new_block = 0;
  fd_fork_t * fork = fd_forks_prepare( ctx->forks,
                                       ctx->parent_slot,
                                       ctx->acc_mgr,
                                       ctx->blockstore,
                                       ctx->epoch_ctx,
                                       ctx->funk,
                                       ctx->runtime_spad );
  // Remove slot ctx from frontier
  fd_fork_t * child = fd_fork_frontier_ele_remove( ctx->forks->frontier, &fork->slot, NULL, ctx->forks->pool );
  child->slot = curr_slot;
  if( FD_UNLIKELY( fd_fork_frontier_ele_query(
      ctx->forks->frontier, &curr_slot, NULL, ctx->forks->pool ) ) ) {
    FD_LOG_ERR( ( "invariant violation: child slot %lu was already in the frontier", curr_slot ) );
  }
  fd_fork_frontier_ele_insert( ctx->forks->frontier, child, ctx->forks->pool );
  fork->lock = 1;
  FD_TEST( fork == child );

  // fork is advancing
  FD_LOG_NOTICE(( "new block execution - slot: %lu, parent_slot: %lu", curr_slot, ctx->parent_slot ));
  fd_epoch_bank_t * epoch_bank = fd_exec_epoch_ctx_epoch_bank( fork->slot_ctx.epoch_ctx );

  /* if it is an epoch boundary, push out stake weights */
  if( fork->slot_ctx.slot_bank.slot != 0 ) {
    is_new_epoch_in_new_block = (int)fd_runtime_is_epoch_boundary( epoch_bank, fork->slot_ctx.slot_bank.slot, fork->slot_ctx.slot_bank.prev_slot );
  }

  fd_block_map_query_t query[1] = { 0 };
  int err = fd_block_map_prepare( ctx->blockstore->block_map, &curr_slot, NULL, query, FD_MAP_FLAG_BLOCKING );
  fd_block_info_t * curr_block_info = fd_block_map_query_ele( query );
  if( FD_UNLIKELY( err == FD_MAP_ERR_FULL ) ) FD_LOG_ERR(("Block map prepare failed, likely corrupt."));
  if( FD_UNLIKELY( curr_slot != curr_block_info->slot ) ) FD_LOG_ERR(("Block map prepare failed, likely corrupt."));
  curr_block_info->in_poh_hash = fork->slot_ctx.slot_bank.poh;
  fd_block_map_publish( query );

  fork->slot_ctx.slot_bank.prev_slot   = fork->slot_ctx.slot_bank.slot;
  fork->slot_ctx.slot_bank.slot        = curr_slot;
  fork->slot_ctx.slot_bank.tick_height = fork->slot_ctx.slot_bank.max_tick_height;
  if( FD_UNLIKELY( FD_RUNTIME_EXECUTE_SUCCESS != fd_runtime_compute_max_tick_height( epoch_bank->ticks_per_slot, curr_slot, &fork->slot_ctx.slot_bank.max_tick_height ) ) ) {
    FD_LOG_ERR(( "couldn't compute tick height/max tick height slot %lu ticks_per_slot %lu", curr_slot, epoch_bank->ticks_per_slot ));
  }
  fork->slot_ctx.enable_exec_recording = ctx->tx_metadata_storage;
  fork->slot_ctx.runtime_wksp          = fd_wksp_containing( ctx->runtime_spad );

  /* NOTE: By commenting this out, we don't support forking at the epoch boundary
     but this code is buggy and leads to crashes. */
  // if( fd_runtime_is_epoch_boundary( epoch_bank, fork->slot_ctx.slot_bank.slot, fork->slot_ctx.slot_bank.prev_slot ) ) {
  //   FD_LOG_WARNING(("Epoch boundary"));

  //   fd_epoch_fork_elem_t * epoch_fork = NULL;
  //   ulong new_epoch = fd_slot_to_epoch( &epoch_bank->epoch_schedule, fork->slot_ctx.slot_bank.slot, NULL );
  //   uint found = fd_epoch_forks_prepare( ctx->epoch_forks, fork->slot_ctx.slot_bank.prev_slot, new_epoch, &epoch_fork );

  //   if( FD_UNLIKELY( found ) ) {
  //     fd_exec_epoch_ctx_bank_mem_clear( epoch_fork->epoch_ctx );
  //   }
  //   fd_exec_epoch_ctx_t * prev_epoch_ctx = fork->slot_ctx.epoch_ctx;

  //   fd_exec_epoch_ctx_from_prev( epoch_fork->epoch_ctx, prev_epoch_ctx, ctx->runtime_spad );
  //   fork->slot_ctx.epoch_ctx = epoch_fork->epoch_ctx;
  // }

  fork->slot_ctx.status_cache = ctx->status_cache;

  fd_funk_txn_xid_t xid = { 0 };

  if( flags & REPLAY_FLAG_PACKED_MICROBLOCK ) {
    memset( xid.uc, 0, sizeof(fd_funk_txn_xid_t) );
  } else {
    xid.ul[1] = fork->slot_ctx.slot_bank.slot;
  }
  xid.ul[0] = fork->slot_ctx.slot_bank.slot;
  /* push a new transaction on the stack */
  fd_funk_start_write( ctx->funk );
  fork->slot_ctx.funk_txn = fd_funk_txn_prepare(ctx->funk, fork->slot_ctx.funk_txn, &xid, 1);
  fd_funk_end_write( ctx->funk );

  fd_runtime_block_pre_execute_process_new_epoch( &fork->slot_ctx,
                                                  ctx->tpool,
                                                  ctx->exec_spads,
                                                  ctx->exec_spad_cnt,
                                                  ctx->runtime_spad );

  /* We want to push on a spad frame before we start executing a block.
     Apart from allocations made at the epoch boundary, there should be no
     allocations that persist beyond the scope of a block. Before this point,
     there should only be 1 or 2 frames that are on the stack. The first frame
     will hold memory for the slot/epoch context. The potential second frame
     will only exist while rewards are being distributed (around the start of
     an epoch). We pop a frame when rewards are done being distributed. */
  fd_spad_push( ctx->runtime_spad );

  int res = fd_runtime_block_execute_prepare( &fork->slot_ctx, ctx->runtime_spad );
  if( res != FD_RUNTIME_EXECUTE_SUCCESS ) {
    FD_LOG_ERR(( "block prep execute failed" ));
  }

  /* Read slot history into slot ctx */
  fork->slot_ctx.slot_history = fd_sysvar_slot_history_read( fork->slot_ctx.acc_mgr, fork->slot_ctx.funk_txn, ctx->runtime_spad );

  if( is_new_epoch_in_new_block ) {
    publish_stake_weights( ctx, stem, &fork->slot_ctx );
  }

  prepare_time_ns += fd_log_wallclock();
  FD_LOG_DEBUG(("TIMING: prepare_time - slot: %lu, elapsed: %6.6f ms", curr_slot, (double)prepare_time_ns * 1e-6));

  return fork;
}

void
init_poh( fd_replay_tile_ctx_t * ctx ) {
  FD_LOG_INFO(( "sending init msg" ));
  fd_replay_out_ctx_t * bank_out = &ctx->bank_out[ 0UL ];
  fd_poh_init_msg_t * msg = fd_chunk_to_laddr( bank_out->mem, bank_out->chunk );
  fd_epoch_bank_t * epoch_bank = fd_exec_epoch_ctx_epoch_bank( ctx->epoch_ctx );
  msg->hashcnt_per_tick = ctx->epoch_ctx->epoch_bank.hashes_per_tick;
  msg->ticks_per_slot   = ctx->epoch_ctx->epoch_bank.ticks_per_slot;
  msg->tick_duration_ns = (ulong)(epoch_bank->ns_per_slot / epoch_bank->ticks_per_slot);
  if( ctx->slot_ctx->slot_bank.block_hash_queue.last_hash ) {
    memcpy(msg->last_entry_hash, ctx->slot_ctx->slot_bank.block_hash_queue.last_hash->uc, sizeof(fd_hash_t));
  } else {
    memset(msg->last_entry_hash, 0UL, sizeof(fd_hash_t));
  }
  msg->tick_height = ctx->slot_ctx->slot_bank.slot * msg->ticks_per_slot;

  ulong sig = fd_disco_replay_old_sig( ctx->slot_ctx->slot_bank.slot, REPLAY_FLAG_INIT );
  fd_mcache_publish( bank_out->mcache, bank_out->depth, bank_out->seq, sig, bank_out->chunk, sizeof(fd_poh_init_msg_t), 0UL, 0UL, 0UL );
  bank_out->chunk = fd_dcache_compact_next( bank_out->chunk, sizeof(fd_poh_init_msg_t), bank_out->chunk0, bank_out->wmark );
  bank_out->seq = fd_seq_inc( bank_out->seq, 1UL );
  ctx->poh_init_done = 1;
}

/* Verifies a microblock batch validity. */

static int FD_FN_UNUSED
process_and_exec_mbatch( fd_replay_tile_ctx_t * ctx,
                         fd_stem_context_t *    stem FD_PARAM_UNUSED,
                         ulong                  mbatch_sz,
                         bool                   last_batch ) {
  #define wait_and_check_success( worker_idx )         \
    fd_tpool_wait( ctx->tpool, worker_idx );           \
    if( poh_info[ worker_idx ].success ) {             \
      FD_LOG_WARNING(( "Failed to verify tick poh" )); \
      return -1; \
    }

  fd_hash_t in_poh_hash;
  fd_block_map_query_t query[1] = { 0 } ;
  int err = FD_MAP_ERR_AGAIN;
  while( err == FD_MAP_ERR_AGAIN ) {
    err = fd_block_map_query_try( ctx->blockstore->block_map, &ctx->curr_slot, NULL, query, 0 );
    fd_block_info_t * block_info = fd_block_map_query_ele( query );
    if( FD_UNLIKELY( err == FD_MAP_ERR_AGAIN ) ) continue;
    if( FD_UNLIKELY( err == FD_MAP_ERR_KEY )) { FD_LOG_ERR(( "Failed to query block map" )); }
    in_poh_hash = block_info->in_poh_hash;
    err = fd_block_map_query_test( query );
  }

  ulong micro_cnt = FD_LOAD( ulong, ctx->mbatch );

  if( FD_UNLIKELY( !micro_cnt ) ) { /* in the case of zero padding */
    FD_LOG_DEBUG(( "No microblocks in batch" ));
    return 0;
  }

  fd_poh_verifier_t     poh_info         = {0};
  (void)poh_info;

  fd_microblock_hdr_t * hdr              = NULL;
  ulong                 off              = sizeof(ulong);
  for( ulong i=0UL; i<micro_cnt; i++ ){
    hdr = (fd_microblock_hdr_t *)fd_type_pun( ctx->mbatch + off );
    int res = fd_runtime_microblock_verify_ticks( ctx->slot_ctx,
                                                  ctx->curr_slot,
                                                  hdr,
                                                  last_batch && i == micro_cnt - 1,
                                                  ctx->slot_ctx->slot_bank.tick_height,
                                                  ctx->slot_ctx->slot_bank.max_tick_height,
                                                  ctx->slot_ctx->epoch_ctx->epoch_bank.hashes_per_tick );

    if( res != FD_BLOCK_OK ) {
      FD_LOG_WARNING(( "Failed to verify tick metadata" ));
      return -1;
    }

    poh_info.success         = 0;
    poh_info.in_poh_hash     = &in_poh_hash;
    poh_info.microblock.hdr  = hdr;
    poh_info.spad            = ctx->runtime_spad;
    poh_info.microblk_max_sz = mbatch_sz - off;

    off += sizeof(fd_microblock_hdr_t);

    /* FIXME: This needs to be multithreaded. This will be reintroduced when
       the execution model changes are made */
    // fd_runtime_poh_verify( &poh_info );
    // if( poh_info.success==-1 ) {
    //   FD_LOG_WARNING(( "Failed to verify poh hash" ));
    //   return -1;
    // }

    in_poh_hash = *(fd_hash_t *)fd_type_pun( hdr->hash );

    /* seek past txns */
    fd_txn_p_t * txn_p  = fd_spad_alloc( ctx->runtime_spad, alignof(fd_txn_p_t*), sizeof(fd_txn_p_t) * hdr->txn_cnt );
    for( ulong t=0UL; t<hdr->txn_cnt; t++ ){
      ulong pay_sz = 0UL;
      ulong txn_sz = fd_txn_parse_core( ctx->mbatch + off,
                                        fd_ulong_min( FD_TXN_MTU, mbatch_sz - off ),
                                        TXN( &txn_p[t] ),
                                        NULL,
                                        &pay_sz );

      if( FD_UNLIKELY( !pay_sz || !txn_sz || txn_sz > FD_TXN_MTU ) ) {
        FD_LOG_WARNING(( "failed to parse transaction %lu in replay", t ));
        return -1;
      }
      fd_memcpy( txn_p[t].payload, ctx->mbatch + off, pay_sz );
      txn_p[t].payload_sz = pay_sz;
      off                += pay_sz;

      /* Execute Transaction  */

      /* dispatch into MCACHE / DCACHE */
      // fd_replay_out_ctx_t * out = &ctx->exec_out[ 0 ];
      // fd_stem_publish( stem, out->idx, 0, out->chunk, sizeof(fd_txn_p_t), 0UL, 0UL, 0UL );
      // out->chunk = fd_dcache_compact_next( out->chunk,  sizeof(fd_txn_p_t), out->chunk0, out->wmark );
    }

    /* Now that we have parsed the mblock, we are ready to execute the whole mblock */
    fd_fork_t * fork = fd_fork_frontier_ele_query( ctx->forks->frontier,
                                                   &ctx->curr_slot,
                                                   NULL,
                                                   ctx->forks->pool );
    if( FD_UNLIKELY( !fork ) ) {
      FD_LOG_ERR(( "Unable to select a fork" ));
    }

    err = fd_runtime_process_txns_in_microblock_stream( &fork->slot_ctx,
                                                        ctx->capture_ctx,
                                                        txn_p,
                                                        hdr->txn_cnt,
                                                        ctx->tpool,
                                                        ctx->exec_spads,
                                                        ctx->exec_spad_cnt,
                                                        ctx->runtime_spad,
                                                        NULL );

    fd_block_map_query_t query[1] = { 0 };
    fd_block_map_prepare( ctx->blockstore->block_map, &ctx->curr_slot, NULL, query, FD_MAP_FLAG_BLOCKING );
    fd_block_info_t * block_info = fd_block_map_query_ele( query );
    if( FD_UNLIKELY( !block_info || block_info->slot != ctx->curr_slot ) ) FD_LOG_ERR(( "[%s] invariant violation: missing block_info %lu", __func__, ctx->curr_slot ));

    if( err != FD_RUNTIME_EXECUTE_SUCCESS ) {
      FD_LOG_WARNING(( "microblk process: block invalid - slot: %lu", ctx->curr_slot ));
      block_info->flags = fd_uchar_set_bit( block_info->flags, FD_BLOCK_FLAG_DEADBLOCK );
      FD_COMPILER_MFENCE();
      block_info->flags = fd_uchar_clear_bit( block_info->flags, FD_BLOCK_FLAG_REPLAYING );
      fd_block_map_publish( query );
      return -1;
    }

    if( last_batch && i == micro_cnt - 1 ) {

      // Copy block hash to slot_bank poh for updating the sysvars

      memcpy( fork->slot_ctx.slot_bank.poh.uc, hdr->hash, sizeof(fd_hash_t) );

      block_info->flags = fd_uchar_set_bit( block_info->flags, FD_BLOCK_FLAG_PROCESSED );
      FD_COMPILER_MFENCE();
      block_info->flags = fd_uchar_clear_bit( block_info->flags, FD_BLOCK_FLAG_REPLAYING );
      memcpy( &block_info->block_hash, hdr->hash, sizeof(fd_hash_t) );
      memcpy( &block_info->bank_hash, &fork->slot_ctx.slot_bank.banks_hash, sizeof(fd_hash_t) );
    }
    publish_account_notifications( ctx, fork, ctx->curr_slot, txn_p, hdr->txn_cnt );
    fd_block_map_publish( query );
  }
  return 0;
# undef wait_and_check_success
}

static void
prepare_first_batch_execution( fd_replay_tile_ctx_t * ctx, fd_stem_context_t * stem ){
  ulong curr_slot   = ctx->curr_slot;
  ulong parent_slot = ctx->parent_slot;
  ulong flags       = ctx->flags;
  if( FD_UNLIKELY( curr_slot < fd_fseq_query( ctx->published_wmark ) ) ) {
    FD_LOG_WARNING(( "ignoring replay of slot %lu (parent: %lu). earlier than our watermark %lu.", curr_slot, parent_slot, fd_fseq_query( ctx->published_wmark ) ));
    return;
  }

  if( FD_UNLIKELY( parent_slot < fd_fseq_query( ctx->published_wmark ) ) ) {
    FD_LOG_WARNING(( "ignoring replay of slot %lu (parent: %lu). parent slot is earlier than our watermark %lu.", curr_slot, parent_slot, fd_fseq_query( ctx->published_wmark ) ) );
    return;
  }

  if( FD_UNLIKELY( !fd_blockstore_block_info_test( ctx->blockstore, parent_slot ) ) ) {
    FD_LOG_WARNING(( "[%s] unable to find slot %lu's parent block_info", __func__, curr_slot ));
    return;
  }

  /**********************************************************************/
  /* Get the epoch_ctx for replaying curr_slot                          */
  /**********************************************************************/

  ulong epoch_ctx_idx = fd_epoch_forks_get_epoch_ctx( ctx->epoch_forks, ctx->ghost, curr_slot, &ctx->parent_slot );
  ctx->epoch_ctx = ctx->epoch_forks->forks[ epoch_ctx_idx ].epoch_ctx;

  /**********************************************************************/
  /* Prepare the fork in ctx->forks for replaying curr_slot             */
  /**********************************************************************/

  fd_fork_t * parent_fork = fd_fork_frontier_ele_query( ctx->forks->frontier, &ctx->parent_slot, NULL, ctx->forks->pool );
  if( FD_UNLIKELY( parent_fork && parent_fork->lock ) ) {
    /* This is an edge case related to pack. The parent fork might
       already be in the frontier and currently executing (ie.
       fork->frozen = 0). */
    FD_LOG_ERR(( "parent slot is frozen in frontier. cannot execute. slot: %lu, parent_slot: %lu",
                 curr_slot,
                 ctx->parent_slot ));
  }

  fd_fork_t * fork = fd_fork_frontier_ele_query( ctx->forks->frontier, &curr_slot, NULL, ctx->forks->pool );
  if( fork == NULL ) {
    fork = prepare_new_block_execution( ctx, stem, curr_slot, flags );
  }
  ctx->slot_ctx = &fork->slot_ctx;

  /**********************************************************************/
  /* Get the solcap context for replaying curr_slot                     */
  /**********************************************************************/

  if( ctx->capture_ctx )
    fd_solcap_writer_set_slot( ctx->capture_ctx->capture, fork->slot_ctx.slot_bank.slot );

}

static void
exec_slices( fd_replay_tile_ctx_t * ctx,
             fd_stem_context_t * stem,
             ulong slot ) {
  /* Buffer up to a certain number of slices (configurable?). Then, for
     each microblock, round robin dispatch the transactions in that
     microblock to the exec tile. Once exec tile signifies with a
     retcode, we can continue dispatching transactions. Have to
     synchronize at the boundary of every microblock. After we dispatch
     one to each exec tile, we watermark (ctx->mbatch_wmark) where we
     are, and then continue on the following after_credit. If we still
     have txns to execute, start from wmark, pausing everytime we hit
     the microblock boundaries. */

  fd_replay_slice_t * slice = fd_replay_slice_map_query( ctx->replay->slice_map, slot, NULL );
  if( !slice ) {
    slice = fd_replay_slice_map_insert( ctx->replay->slice_map, slot );
  }

  /* Manual population of the slice deque occurs currently when we are:
      1. Repairing and catching up. All shreds in this case come through
         repair, and thus aren't processed in SHRED_IN_IDX in before_frag
      2. Repairing shreds after first turbine. Some of the batches will
         be added to the slice_deque through SHRED, but missing shreds
         are still recieved through repair, and aren't processed in  */

  if( ctx->last_completed_slot != slot && fd_replay_slice_deque_cnt( slice->deque ) == 0 ) {
    FD_LOG_INFO(( "Failed to query slice deque for slot %lu. Likely shreds were recieved through repair. Manually adding.", slot ));
    slice_poll( ctx, slice, slot );
  }

  //ulong free_exec_tiles = ctx->exec_cnt;
  ulong free_exec_tiles = 512;

  while( free_exec_tiles > 0 ){
    /* change to whatever condition handles if(exec free). */
    if( ctx->slice_exec_ctx.txns_rem > 0 ){
      //FD_LOG_WARNING(( "[%s] executing txn", __func__ ));
      ulong pay_sz = 0UL;
      fd_replay_out_ctx_t * exec_out = &ctx->exec_out[ ctx->exec_cnt - free_exec_tiles ];
      (void)exec_out;
      //fd_txn_p_t * txn_p = (fd_txn_p_t *) fd_chunk_to_laddr( exec_out->mem, exec_out->chunk );
      fd_txn_p_t txn_p[1];
      ulong txn_sz = fd_txn_parse_core( ctx->mbatch + ctx->slice_exec_ctx.wmark,
                                        fd_ulong_min( FD_TXN_MTU, ctx->slice_exec_ctx.sz - ctx->slice_exec_ctx.wmark ),
                                        TXN( txn_p ),
                                        NULL,
                                        &pay_sz );

      if( FD_UNLIKELY( !pay_sz || !txn_sz || txn_sz > FD_TXN_MTU ) ) {
        __asm__("int $3");
        FD_LOG_ERR(( "failed to parse transaction in replay" ));
      }
      fd_memcpy( txn_p->payload, ctx->mbatch + ctx->slice_exec_ctx.wmark, pay_sz );
      txn_p->payload_sz = pay_sz;
      ctx->slice_exec_ctx.wmark += pay_sz;

      /* dispatch dcache */
      //fd_stem_publish( stem, exec_out->idx, slot, exec_out->chunk, sizeof(fd_txn_p_t), 0UL, 0UL, 0UL );
      //exec_out->chunk = fd_dcache_compact_next( exec_out->chunk, sizeof(fd_txn_p_t), exec_out->chunk0, exec_out->wmark );

      /* dispatch tpool */

      fd_fork_t * fork = fd_fork_frontier_ele_query( ctx->forks->frontier,
                                                     &slot,
                                                     NULL,
                                                     ctx->forks->pool );
      if( FD_UNLIKELY( !fork ) ) {
        FD_LOG_ERR(( "Unable to select a fork" ));
      }

      int err = fd_runtime_process_txns_in_microblock_stream( &fork->slot_ctx,
                  ctx->capture_ctx,
                  txn_p,
                  1,
                  ctx->tpool,
                  ctx->exec_spads,
                  ctx->exec_spad_cnt,
                  ctx->runtime_spad,
                  NULL );

      if( err != FD_RUNTIME_EXECUTE_SUCCESS ) {
        FD_LOG_WARNING(( "microblk process: block invalid - slot: %lu", ctx->curr_slot ));

        fd_block_map_query_t query[1] = { 0 };
        fd_block_map_prepare( ctx->blockstore->block_map, &ctx->curr_slot, NULL, query, FD_MAP_FLAG_BLOCKING );
        fd_block_info_t * block_info = fd_block_map_query_ele( query );
        if( FD_UNLIKELY( !block_info || block_info->slot != ctx->curr_slot ) ) FD_LOG_ERR(( "[%s] invariant violation: missing block_info %lu", __func__, ctx->curr_slot ));

        block_info->flags = fd_uchar_set_bit( block_info->flags, FD_BLOCK_FLAG_DEADBLOCK );
        FD_COMPILER_MFENCE();
        block_info->flags = fd_uchar_clear_bit( block_info->flags, FD_BLOCK_FLAG_REPLAYING );

        fd_block_map_publish( query );
      }

      publish_account_notifications( ctx, fork, ctx->curr_slot, txn_p, 1 );

      ctx->slice_exec_ctx.txns_rem--;
      free_exec_tiles--;
      continue;
    }

    /* If the current microblock is complete, and we still have mblks
       to read, then advance to the next microblock */

    if( ctx->slice_exec_ctx.txns_rem == 0 && ctx->slice_exec_ctx.mblks_rem > 0 ){
      //FD_LOG_WARNING(( "[%s] reading microblock", __func__ ));

      fd_microblock_hdr_t * hdr = (fd_microblock_hdr_t *)fd_type_pun( ctx->mbatch + ctx->slice_exec_ctx.wmark );
      ctx->slice_exec_ctx.txns_rem      = hdr->txn_cnt;
      ctx->slice_exec_ctx.last_mblk_off = ctx->slice_exec_ctx.wmark;
      ctx->slice_exec_ctx.wmark        += sizeof(fd_microblock_hdr_t);
      ctx->slice_exec_ctx.mblks_rem--;
      if( free_exec_tiles == 512 ){
        /* no transactions were executed this credit, free to start executing new microblock txns */
        continue;
      }
      break; /* have to synchronize & wait for exec tiles to finish the prev microblock */
    }

    /* The prev batch is complete, but we have more batches to read. */

    if( ctx->slice_exec_ctx.mblks_rem == 0 && !ctx->slice_exec_ctx.last_batch ) {

      /* Waiting on batches to arrive from the shred tile */

      if( fd_replay_slice_deque_cnt( slice->deque ) == 0 ) break;

      if( FD_UNLIKELY( ctx->slice_exec_ctx.sz == 0 ) ) { /* I think maybe can move this out when */
        FD_LOG_NOTICE(("Preparing first batch execution of slot %lu", slot ));
        prepare_first_batch_execution( ctx, stem );
      }

      ulong key       = fd_replay_slice_deque_pop_head( slice->deque );
      uint  start_idx = fd_replay_slice_start_idx( key );
      uint  end_idx   = fd_replay_slice_end_idx  ( key );

      /* populate last shred idx. Can also do this just once but... */
      for(;;) { /* speculative query */
        fd_block_map_query_t query[1] = { 0 };
        int err = fd_block_map_query_try( ctx->blockstore->block_map, &slot, NULL, query, 0 );
        fd_block_info_t * block_info = fd_block_map_query_ele( query );

        if( FD_UNLIKELY( err == FD_MAP_ERR_KEY   ) ) FD_LOG_ERR(("Failed to query blockstore for slot %lu", slot ));
        if( FD_UNLIKELY( err == FD_MAP_ERR_AGAIN ) ) continue;

        ctx->slice_exec_ctx.last_batch = block_info->slot_complete_idx == end_idx;
        //slot_complete_idx = block_info->slot_complete_idx;
        if( FD_UNLIKELY( fd_block_map_query_test( query ) == FD_MAP_SUCCESS ) ) break;
      }
      //FD_LOG_WARNING(( "[%s] Executing batch %u %u, last: %u", __func__, start_idx, end_idx, slot_complete_idx ));

      ulong slice_sz;
      int err = fd_blockstore_slice_query( ctx->slot_ctx->blockstore,
                                                       slot,
                                                       start_idx,
                                                       end_idx,
                                                      FD_SLICE_MAX - ctx->slice_exec_ctx.sz,
                                                      ctx->mbatch + ctx->slice_exec_ctx.sz,
                                                      &slice_sz );

      if( err ) FD_LOG_ERR(( "Failed to query blockstore for slot %lu", slot ));
      ctx->slice_exec_ctx.mblks_rem = FD_LOAD( ulong, ctx->mbatch + ctx->slice_exec_ctx.sz );
      ctx->slice_exec_ctx.wmark = ctx->slice_exec_ctx.sz + sizeof(ulong);
      ctx->slice_exec_ctx.sz += slice_sz;
      if ( free_exec_tiles == 512 ) continue;
      break;
    }

    if( FD_UNLIKELY( ctx->slice_exec_ctx.last_batch &&
                     ctx->slice_exec_ctx.mblks_rem == 0 &&
                     ctx->slice_exec_ctx.txns_rem == 0 ) ) {
      /* block done. */
      break;
    }
  }

  if( ctx->slice_exec_ctx.last_batch && ctx->slice_exec_ctx.mblks_rem == 0 && ctx->slice_exec_ctx.txns_rem == 0 ){
    FD_LOG_WARNING(( "[%s] BLOCK EXECUTION COMPLETE", __func__ ));

     /* At this point, the entire block has been executed. */
     fd_fork_t * fork = fd_fork_frontier_ele_query( ctx->forks->frontier,
                                                    &slot,
                                                    NULL,
                                                    ctx->forks->pool );
     if( FD_UNLIKELY( !fork ) ) {
       FD_LOG_ERR(( "Unable to select a fork" ));
     }

     fd_microblock_hdr_t * hdr = (fd_microblock_hdr_t*)fd_type_pun( ctx->mbatch + ctx->slice_exec_ctx.last_mblk_off );

     // Copy block hash to slot_bank poh for updating the sysvars
     fd_block_map_query_t query[1] = { 0 };
     fd_block_map_prepare( ctx->blockstore->block_map, &ctx->curr_slot, NULL, query, FD_MAP_FLAG_BLOCKING );
     fd_block_info_t * block_info = fd_block_map_query_ele( query );

     memcpy( fork->slot_ctx.slot_bank.poh.uc, hdr->hash, sizeof(fd_hash_t) );
     block_info->flags = fd_uchar_set_bit( block_info->flags, FD_BLOCK_FLAG_PROCESSED );
     FD_COMPILER_MFENCE();
     block_info->flags = fd_uchar_clear_bit( block_info->flags, FD_BLOCK_FLAG_REPLAYING );
     memcpy( &block_info->block_hash, hdr->hash, sizeof(fd_hash_t) );
     memcpy( &block_info->bank_hash, &fork->slot_ctx.slot_bank.banks_hash, sizeof(fd_hash_t) );

     fd_block_map_publish( query );
     ctx->flags = fd_disco_replay_old_sig( slot, REPLAY_FLAG_FINISHED_BLOCK );

     ctx->slice_exec_ctx.last_batch = 0;
     ctx->slice_exec_ctx.txns_rem = 0;
     ctx->slice_exec_ctx.mblks_rem = 0;
     ctx->slice_exec_ctx.sz = 0;
     ctx->slice_exec_ctx.wmark = 0;
     ctx->slice_exec_ctx.last_mblk_off = 0;
  }
}

static void
after_frag( fd_replay_tile_ctx_t * ctx,
            ulong                  in_idx,
            ulong                  seq,
            ulong                  sig   FD_PARAM_UNUSED,
            ulong                  sz    FD_PARAM_UNUSED,
            ulong                  tsorig,
            ulong                  tspub FD_PARAM_UNUSED,
            fd_stem_context_t *    stem  FD_PARAM_UNUSED ) {
  (void)sig;
  (void)sz;

  /*if( FD_LIKELY( in_idx == SHRED_IN_IDX ) ) {

     after_frag only called if it's the first code shred we're
       receiving for the FEC set

    ulong slot        = fd_disco_shred_replay_sig_slot( sig );
    uint  fec_set_idx = fd_disco_shred_replay_sig_fec_set_idx( sig );

    fd_replay_fec_t * fec = fd_replay_fec_query( ctx->replay, slot, fec_set_idx );
    if( !fec ) return; // hack
    fec->data_cnt         = ctx->shred->code.data_cnt;

    return;
  }*/

  if( FD_UNLIKELY( ctx->skip_frag ) ) return;
  if( FD_UNLIKELY( in_idx == STORE_IN_IDX ) ) {
    FD_LOG_NOTICE(("Received store message, executing slot %lu", ctx->curr_slot ));
    //exec_slices( ctx, stem, ctx->curr_slot );
  }

  /**********************************************************************/
  /* The rest of after_frag replays some microblocks in block curr_slot */
  /**********************************************************************/

  ulong curr_slot   = ctx->curr_slot;
  ulong flags       = ctx->flags;
  ulong bank_idx    = ctx->bank_idx;

  fd_fork_t * fork = fd_fork_frontier_ele_query( ctx->forks->frontier, &ctx->curr_slot, NULL, ctx->forks->pool );

  /**********************************************************************/
  /* Execute the transactions which were gathered                       */
  /**********************************************************************/

  ulong                 txn_cnt  = ctx->txn_cnt;
  fd_replay_out_ctx_t * bank_out = &ctx->bank_out[ bank_idx ];
  fd_txn_p_t *          txns     = (fd_txn_p_t *)fd_chunk_to_laddr( bank_out->mem, bank_out->chunk );

  //Execute all txns which were successfully prepared
  ctx->metrics.slot = curr_slot;
  if( flags & REPLAY_FLAG_PACKED_MICROBLOCK ) {
    /* TODO: The leader pipeline execution needs to be optimized. This is
       very hacky and suboptimal. First, wait for the tpool workers to be idle.
       Then, execute the transactions, and notify the pack tile. We should be
       taking advantage of bank_busy flags. */

    for( ulong i=1UL; i<ctx->exec_spad_cnt; i++ ) {
      fd_tpool_wait( ctx->tpool, i );
    }

    fd_runtime_process_txns_in_microblock_stream( ctx->slot_ctx,
                                                  ctx->capture_ctx,
                                                  txns,
                                                  txn_cnt,
                                                  ctx->tpool,
                                                  ctx->exec_spads,
                                                  ctx->exec_spad_cnt,
                                                  ctx->runtime_spad,
                                                  NULL );

    fd_microblock_trailer_t * microblock_trailer = (fd_microblock_trailer_t *)(txns + txn_cnt);

    hash_transactions( ctx->bmtree[ bank_idx ], txns, txn_cnt, microblock_trailer->hash );

    ulong sig = fd_disco_replay_old_sig( curr_slot, flags );
    fd_mcache_publish( bank_out->mcache, bank_out->depth, bank_out->seq, sig, bank_out->chunk, txn_cnt, 0UL, 0UL, 0UL );
    bank_out->chunk = fd_dcache_compact_next( bank_out->chunk, (txn_cnt * sizeof(fd_txn_p_t)) + sizeof(fd_microblock_trailer_t), bank_out->chunk0, bank_out->wmark );
    bank_out->seq = fd_seq_inc( bank_out->seq, 1UL );

    /* Indicate to pack tile we are done processing the transactions so it
      can pack new microblocks using these accounts.  DO NOT USE THE
      SANITIZED TRANSACTIONS AFTER THIS POINT, THEY ARE NO LONGER VALID. */
    fd_fseq_update( ctx->bank_busy[ bank_idx ], seq );

    publish_account_notifications( ctx, fork, curr_slot, txns, txn_cnt );
  }

  /**********************************************************************/
  /* Init PoH if it is ready                                            */
  /**********************************************************************/

  if( FD_UNLIKELY( !(flags & REPLAY_FLAG_CATCHING_UP) && ctx->poh_init_done == 0 && ctx->slot_ctx->blockstore ) ) {
    init_poh( ctx );
  }

  /**********************************************************************/
  /* Publish mblk to POH                                                */
  /**********************************************************************/

  if( ctx->poh_init_done == 1 && !( flags & REPLAY_FLAG_FINISHED_BLOCK )
      && ( ( flags & REPLAY_FLAG_MICROBLOCK ) ) ) {
    // FD_LOG_INFO(( "publishing mblk to poh - slot: %lu, parent_slot: %lu", curr_slot, ctx->parent_slot ));
    ulong tspub = fd_frag_meta_ts_comp( fd_tickcount() );
    ulong sig = fd_disco_replay_old_sig( curr_slot, flags );
    fd_mcache_publish( bank_out->mcache, bank_out->depth, bank_out->seq, sig, bank_out->chunk, txn_cnt, 0UL, tsorig, tspub );
    bank_out->chunk = fd_dcache_compact_next( bank_out->chunk, (txn_cnt * sizeof(fd_txn_p_t)) + sizeof(fd_microblock_trailer_t), bank_out->chunk0, bank_out->wmark );
    bank_out->seq = fd_seq_inc( bank_out->seq, 1UL );
  } else {
    FD_LOG_DEBUG(( "NOT publishing mblk to poh - slot: %lu, parent_slot: %lu, flags: %lx", curr_slot, ctx->parent_slot, flags ));
  }

#if STOP_SLOT
  if( FD_UNLIKELY( curr_slot == STOP_SLOT ) ) {

    if( FD_UNLIKELY( ctx->capture_file ) ) fclose( ctx->slots_replayed_file );

    if( FD_UNLIKELY( strcmp( ctx->blockstore_checkpt, "" ) ) ) {
      int rc = fd_wksp_checkpt( ctx->blockstore_wksp, ctx->blockstore_checkpt, 0666, 0, NULL );
      if( rc ) {
        FD_LOG_ERR( ( "blockstore checkpt failed: error %d", rc ) );
      }
    }
    FD_LOG_ERR( ( "stopping at %lu (#define STOP_SLOT %lu). shutting down.", STOP_SLOT, STOP_SLOT ) );
  }
#endif
}

void
tpool_boot( fd_topo_t * topo, ulong total_thread_count ) {
  ushort tile_to_cpu[ FD_TILE_MAX ] = { 0 };
  ulong thread_count = 0;
  ulong main_thread_seen = 0;

  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    if( strcmp( topo->tiles[i].name, "rtpool" ) == 0 ) {
      tile_to_cpu[ 1+thread_count ] = (ushort)topo->tiles[i].cpu_idx;
      thread_count++;
    }
    if( strcmp( topo->tiles[i].name, "replay" ) == 0 ) {
      tile_to_cpu[ 0 ] = (ushort)topo->tiles[i].cpu_idx;
      main_thread_seen = 1;
    }
  }

  if( main_thread_seen ) {
    thread_count++;
  }

  if( thread_count != total_thread_count )
    FD_LOG_ERR(( "thread count mismatch thread_count=%lu total_thread_count=%lu main_thread_seen=%lu", thread_count, total_thread_count, main_thread_seen ));

  fd_tile_private_map_boot( tile_to_cpu, thread_count );
}

static void
kickoff_repair_orphans( fd_replay_tile_ctx_t * ctx, fd_stem_context_t * stem ) {

  fd_blockstore_init( ctx->slot_ctx->blockstore, ctx->blockstore_fd, FD_BLOCKSTORE_ARCHIVE_MIN_SIZE, &ctx->slot_ctx->slot_bank );

  publish_stake_weights( ctx, stem, ctx->slot_ctx );
  fd_fseq_update( ctx->published_wmark, ctx->slot_ctx->slot_bank.slot );

}

static void
read_snapshot( void *              _ctx,
               fd_stem_context_t * stem,
               char const *        snapshotfile,
               char const *        incremental ) {
  fd_replay_tile_ctx_t * ctx = (fd_replay_tile_ctx_t *)_ctx;

  if( ctx->replay_plugin_out_mem ) {
    // ValidatorStartProgress::DownloadingSnapshot
    uchar msg[56];
    fd_memset( msg, 0, sizeof(msg) );
    msg[0] = 2;
    msg[1] = 1;
    replay_plugin_publish( ctx, stem, FD_PLUGIN_MSG_START_PROGRESS, msg, sizeof(msg) );
  }

  /* Pass the slot_ctx to snapshot_load or recover_banks */
  /* Base slot is the slot we will compare against the base slot of the incremental snapshot, to ensure that the
     base slot of the incremental snapshot is the slot of the full snapshot.

     We pull this out of the full snapshot to use when verifying the incremental snapshot. */
  ulong        base_slot = 0UL;
  const char * snapshot  = snapshotfile;
  if( strcmp( snapshot, "funk" )==0 || strncmp( snapshot, "wksp:", 5 )==0 ) {
    /* Funk already has a snapshot loaded */
    fd_runtime_recover_banks( ctx->slot_ctx, 1, 1, ctx->runtime_spad );
    base_slot = ctx->slot_ctx->slot_bank.slot;
    publish_stake_weights( ctx, stem, ctx->slot_ctx );
    fd_fseq_update( ctx->published_wmark, ctx->slot_ctx->slot_bank.slot );
  } else {

    /* If we have an incremental snapshot try to prefetch the snapshot slot
       and manifest as soon as possible. In order to kick off repair effectively
       we need the snapshot slot and the stake weights. These are both available
       in the manifest. We will try to load in the manifest from the latest
       snapshot that is availble, then setup the blockstore and publish the
       stake weights. After this, repair will kick off concurrently with loading
       the rest of the snapshots. */

    /* TODO: enable snapshot verification for all 3 snapshot loads */

    if( strlen( incremental )>0UL ) {
      uchar *                  tmp_mem      = fd_spad_alloc( ctx->runtime_spad, fd_snapshot_load_ctx_align(), fd_snapshot_load_ctx_footprint() );
      /* TODO: enable snapshot verification */
      fd_snapshot_load_ctx_t * tmp_snap_ctx = fd_snapshot_load_new( tmp_mem,
                                                                    incremental,
                                                                    ctx->slot_ctx,
                                                                    ctx->tpool,
                                                                    false,
                                                                    false,
                                                                    FD_SNAPSHOT_TYPE_FULL,
                                                                    ctx->exec_spads,
                                                                    ctx->exec_spad_cnt,
                                                                    ctx->runtime_spad );
      /* Load the prefetch manifest, and initialize the status cache and slot context,
         so that we can use these to kick off repair. */
      fd_snapshot_load_prefetch_manifest( tmp_snap_ctx );
      kickoff_repair_orphans( ctx, stem );
    }

    /* In order to kick off repair effectively we need the snapshot slot and
       the stake weights. These are both available in the manifest. We will
       try to load in the manifest from the latest snapshot that is available,
       then setup the blockstore and publish the stake weights. After this,
       repair will kick off concurrently with loading the rest of the snapshots. */

    uchar *                  mem      = fd_spad_alloc( ctx->runtime_spad, fd_snapshot_load_ctx_align(), fd_snapshot_load_ctx_footprint() );
    /* TODO: enable snapshot verification */
    fd_snapshot_load_ctx_t * snap_ctx = fd_snapshot_load_new( mem,
                                                              snapshot,
                                                              ctx->slot_ctx,
                                                              ctx->tpool,
                                                              false,
                                                              false,
                                                              FD_SNAPSHOT_TYPE_FULL,
                                                              ctx->exec_spads,
                                                              ctx->exec_spad_cnt,
                                                              ctx->runtime_spad );

    fd_snapshot_load_init( snap_ctx );

    /* If we don't have an incremental snapshot, load the manifest and the status cache and initialize
         the objects because we don't have these from the incremental snapshot. */
    if( strlen( incremental )<=0UL ) {
      fd_snapshot_load_manifest_and_status_cache( snap_ctx, NULL,
        FD_SNAPSHOT_RESTORE_MANIFEST | FD_SNAPSHOT_RESTORE_STATUS_CACHE );

      /* If we don't have an incremental snapshot, we can still kick off
         sending the stake weights and snapshot slot to repair. */
      kickoff_repair_orphans( ctx, stem );
    } else {
      /* If we have an incremental snapshot, load the manifest and the status cache,
          and don't initialize the objects because we did this above from the incremental snapshot. */
      fd_snapshot_load_manifest_and_status_cache( snap_ctx, NULL, FD_SNAPSHOT_RESTORE_NONE );
    }
    base_slot = fd_snapshot_get_slot( snap_ctx );

    fd_snapshot_load_accounts( snap_ctx );
    fd_snapshot_load_fini( snap_ctx );
  }

  /* Load incremental */

  if( ctx->replay_plugin_out_mem ) {
    // ValidatorStartProgress::DownloadingSnapshot
    uchar msg[56];
    fd_memset( msg, 0, sizeof(msg) );
    msg[0] = 2;
    msg[1] = 0;
    replay_plugin_publish( ctx, stem, FD_PLUGIN_MSG_START_PROGRESS, msg, sizeof(msg) );
  }

  if( strlen( incremental ) > 0 && strcmp( snapshot, "funk" ) != 0 ) {

    /* The slot of the full snapshot should be used as the base slot to verify the incremental snapshot,
       not the slot context's slot - which is the slot of the incremental, not the full snapshot. */
    /* TODO: enable snapshot verification */
    fd_snapshot_load_all( incremental,
                          ctx->slot_ctx,
                          &base_slot,
                          ctx->tpool,
                          false,
                          false,
                          FD_SNAPSHOT_TYPE_INCREMENTAL,
                          ctx->exec_spads,
                          ctx->exec_spad_cnt,
                          ctx->runtime_spad );
  }

  if( ctx->replay_plugin_out_mem ) {
    // ValidatorStartProgress::DownloadedFullSnapshot
    uchar msg[56];
    fd_memset( msg, 0, sizeof(msg) );
    msg[0] = 3;
    replay_plugin_publish( ctx, stem, FD_PLUGIN_MSG_START_PROGRESS, msg, sizeof(msg) );
  }

  fd_runtime_update_leaders( ctx->slot_ctx,
                             ctx->slot_ctx->slot_bank.slot,
                             ctx->runtime_spad );
  FD_LOG_NOTICE(( "starting fd_bpf_scan_and_create_bpf_program_cache_entry..." ));
  fd_funk_start_write( ctx->slot_ctx->acc_mgr->funk );
  fd_bpf_scan_and_create_bpf_program_cache_entry_tpool( ctx->slot_ctx,
                                                        ctx->slot_ctx->funk_txn,
                                                        ctx->tpool,
                                                        ctx->runtime_spad );
  fd_funk_end_write( ctx->slot_ctx->acc_mgr->funk );
  FD_LOG_NOTICE(( "finished fd_bpf_scan_and_create_bpf_program_cache_entry..." ));

  fd_blockstore_init( ctx->slot_ctx->blockstore,
                      ctx->blockstore_fd,
                      FD_BLOCKSTORE_ARCHIVE_MIN_SIZE,
                      &ctx->slot_ctx->slot_bank );
}

static void
init_after_snapshot( fd_replay_tile_ctx_t * ctx ) {
  /* Do not modify order! */

  /* First, load in the sysvars into the sysvar cache. This is required to
     make the StakeHistory sysvar available to the rewards calculation. */

  fd_runtime_sysvar_cache_load( ctx->slot_ctx, ctx->runtime_spad );

  /* After both snapshots have been loaded in, we can determine if we should
     start distributing rewards. */

  fd_rewards_recalculate_partitioned_rewards( ctx->slot_ctx,
                                              ctx->tpool,
                                              ctx->exec_spads,
                                              ctx->exec_spad_cnt,
                                              ctx->runtime_spad );

  ulong snapshot_slot = ctx->slot_ctx->slot_bank.slot;
  if( FD_UNLIKELY( !snapshot_slot ) ) {
    fd_runtime_update_leaders( ctx->slot_ctx,
                               ctx->slot_ctx->slot_bank.slot,
                               ctx->runtime_spad );

    ctx->slot_ctx->slot_bank.prev_slot = 0UL;
    ctx->slot_ctx->slot_bank.slot      = 1UL;

    ulong hashcnt_per_slot = ctx->slot_ctx->epoch_ctx->epoch_bank.hashes_per_tick * ctx->slot_ctx->epoch_ctx->epoch_bank.ticks_per_slot;
    while(hashcnt_per_slot--) {
      fd_sha256_hash( ctx->slot_ctx->slot_bank.poh.uc, 32UL, ctx->slot_ctx->slot_bank.poh.uc );
    }

    FD_TEST( fd_runtime_block_execute_prepare( ctx->slot_ctx, ctx->runtime_spad ) == 0 );
    fd_runtime_block_info_t info = { .signature_cnt = 0 };
    FD_TEST( fd_runtime_block_execute_finalize_tpool( ctx->slot_ctx,
                                                      NULL,
                                                      &info,
                                                      ctx->tpool,
                                                      ctx->runtime_spad ) == 0 );

    ctx->slot_ctx->slot_bank.prev_slot = 0UL;
    ctx->slot_ctx->slot_bank.slot      = 1UL;
    snapshot_slot                      = 1UL;

    FD_LOG_NOTICE(( "starting fd_bpf_scan_and_create_bpf_program_cache_entry..." ));
    fd_funk_start_write( ctx->slot_ctx->acc_mgr->funk );
    fd_bpf_scan_and_create_bpf_program_cache_entry_tpool( ctx->slot_ctx,
                                                          ctx->slot_ctx->funk_txn,
                                                          ctx->tpool,
                                                          ctx->runtime_spad );
    fd_funk_end_write( ctx->slot_ctx->acc_mgr->funk );
    FD_LOG_NOTICE(( "finished fd_bpf_scan_and_create_bpf_program_cache_entry..." ));

  }

  ctx->curr_slot     = snapshot_slot;
  ctx->parent_slot   = ctx->slot_ctx->slot_bank.prev_slot;
  ctx->snapshot_slot = snapshot_slot;
  ctx->blockhash     = ( fd_hash_t ){ .hash = { 0 } };
  ctx->flags         = 0UL;
  ctx->txn_cnt       = 0UL;

  /* Initialize consensus structures post-snapshot */

  fd_fork_t * snapshot_fork = fd_forks_init( ctx->forks, ctx->slot_ctx );
  FD_TEST( snapshot_fork );
  fd_epoch_init( ctx->epoch, &snapshot_fork->slot_ctx.epoch_ctx->epoch_bank );
  fd_ghost_init( ctx->ghost, snapshot_slot );

  fd_funk_rec_key_t key = { 0 };
  fd_memcpy( key.c, ctx->vote_acc, sizeof(fd_pubkey_t) );
  key.c[FD_FUNK_REC_KEY_FOOTPRINT - 1] = FD_FUNK_KEY_TYPE_ACC;
  fd_tower_from_vote_acc( ctx->tower, ctx->funk, snapshot_fork->slot_ctx.funk_txn, &key );
  FD_LOG_NOTICE(( "vote account: %s", FD_BASE58_ENC_32_ALLOCA( key.c ) ));
  fd_tower_print( ctx->tower, ctx->root );

  fd_bank_hash_cmp_t * bank_hash_cmp = ctx->epoch_ctx->bank_hash_cmp;
  bank_hash_cmp->total_stake         = ctx->epoch->total_stake;
  bank_hash_cmp->watermark           = snapshot_slot;

  fd_epoch_fork_elem_t * curr_entry = &ctx->epoch_forks->forks[ 0 ];

  if( strlen( ctx->genesis ) > 0 ) {
    curr_entry->parent_slot = 0UL;
    curr_entry->epoch       = 0UL;
  } else {
    fd_epoch_bank_t * epoch_bank = fd_exec_epoch_ctx_epoch_bank( ctx->epoch_ctx );

    ulong curr_epoch = fd_slot_to_epoch( &epoch_bank->epoch_schedule, ctx->curr_slot, NULL );
    ulong last_slot_in_epoch = fd_ulong_sat_sub( fd_epoch_slot0( &epoch_bank->epoch_schedule, curr_epoch), 1UL );

    curr_entry->parent_slot = fd_ulong_min( ctx->parent_slot, last_slot_in_epoch );
    curr_entry->epoch = curr_epoch;
  }

  curr_entry->epoch_ctx = ctx->epoch_ctx;
  ctx->epoch_forks->curr_epoch_idx = 0UL;

  FD_LOG_NOTICE(( "snapshot slot %lu", snapshot_slot ));
  FD_LOG_NOTICE(( "total stake %lu", bank_hash_cmp->total_stake ));
}

void
init_snapshot( fd_replay_tile_ctx_t * ctx,
               fd_stem_context_t *    stem ) {
  FD_LOG_NOTICE(( "init snapshot" ));
  /* Init slot_ctx */

  fd_exec_slot_ctx_t slot_ctx = {0};
  ctx->slot_ctx               = fd_exec_slot_ctx_join( fd_exec_slot_ctx_new( &slot_ctx, ctx->runtime_spad ) );
  ctx->slot_ctx->acc_mgr      = ctx->acc_mgr;
  ctx->slot_ctx->blockstore   = ctx->blockstore;
  ctx->slot_ctx->epoch_ctx    = ctx->epoch_ctx;
  ctx->slot_ctx->status_cache = ctx->status_cache;
  fd_runtime_update_slots_per_epoch( ctx->slot_ctx, FD_DEFAULT_SLOTS_PER_EPOCH, ctx->runtime_spad );

  uchar is_snapshot = strlen( ctx->snapshot ) > 0;
  if( is_snapshot ) {
    read_snapshot( ctx, stem, ctx->snapshot, ctx->incremental );
  }

  fd_runtime_read_genesis( ctx->slot_ctx,
                           ctx->genesis,
                           is_snapshot,
                           ctx->capture_ctx,
                           ctx->tpool,
                           ctx->runtime_spad );
  ctx->epoch_ctx->bank_hash_cmp = ctx->bank_hash_cmp;
  ctx->epoch_ctx->replay_public = ctx->replay_public;
  init_after_snapshot( ctx );

  /* Redirect ctx->slot_ctx to point to the memory inside forks. */

  fd_fork_t * fork = fd_forks_query( ctx->forks, ctx->curr_slot );
  ctx->slot_ctx = &fork->slot_ctx;

  // Tell the world about the current activate features
  fd_memcpy ( &ctx->replay_public->features,  &ctx->slot_ctx->epoch_ctx->features, sizeof(ctx->replay_public->features) );

  FD_TEST( ctx->slot_ctx );
}

static void
publish_votes_to_plugin( fd_replay_tile_ctx_t * ctx,
                         fd_stem_context_t *    stem ) {
  uchar * dst = (uchar *)fd_chunk_to_laddr( ctx->votes_plugin_out_mem, ctx->votes_plugin_out_chunk );

  fd_fork_t * fork = fd_fork_frontier_ele_query( ctx->forks->frontier, &ctx->curr_slot, NULL, ctx->forks->pool );
  if( FD_UNLIKELY ( !fork  ) ) return;
  fd_vote_accounts_t * accts = &fork->slot_ctx.slot_bank.epoch_stakes;
  fd_vote_accounts_pair_t_mapnode_t * root = accts->vote_accounts_root;
  fd_vote_accounts_pair_t_mapnode_t * pool = accts->vote_accounts_pool;

  ulong i = 0;
  FD_SPAD_FRAME_BEGIN( ctx->runtime_spad ) {
  for( fd_vote_accounts_pair_t_mapnode_t const * n = fd_vote_accounts_pair_t_map_minimum_const( pool, root );
       n && i < FD_CLUSTER_NODE_CNT;
       n = fd_vote_accounts_pair_t_map_successor_const( pool, n ) ) {
    if( n->elem.stake == 0 ) continue;

    /* TODO: Define a helper that gets specific fields. */
    fd_bincode_decode_ctx_t dec_ctx = {
      .data    = n->elem.value.data,
      .dataend = n->elem.value.data + n->elem.value.data_len,
    };

    ulong total_sz = 0UL;
    int err = fd_vote_state_versioned_decode_footprint( &dec_ctx, &total_sz );
    if( FD_UNLIKELY( err ) ) {
      FD_LOG_ERR(( "Unexpected failure in decoding vote state" ));
    }

    uchar * mem = fd_spad_alloc( ctx->runtime_spad, fd_vote_state_versioned_align(), total_sz );
    if( FD_UNLIKELY( !mem ) ) {
      FD_LOG_ERR(( "Unable to allocate memory for memory" ));
    }

    fd_vote_state_versioned_t * vsv = fd_vote_state_versioned_decode( mem, &dec_ctx );

    fd_pubkey_t node_pubkey;
    ulong       last_ts_slot;
    switch( vsv->discriminant ) {
      case fd_vote_state_versioned_enum_v0_23_5:
        node_pubkey  = vsv->inner.v0_23_5.node_pubkey;
        last_ts_slot = vsv->inner.v0_23_5.last_timestamp.slot;
        break;
      case fd_vote_state_versioned_enum_v1_14_11:
        node_pubkey  = vsv->inner.v1_14_11.node_pubkey;
        last_ts_slot = vsv->inner.v1_14_11.last_timestamp.slot;
        break;
      case fd_vote_state_versioned_enum_current:
        node_pubkey  = vsv->inner.current.node_pubkey;
        last_ts_slot = vsv->inner.current.last_timestamp.slot;
        break;
      default:
        __builtin_unreachable();
    }

    fd_vote_update_msg_t * msg = (fd_vote_update_msg_t *)(dst + sizeof(ulong) + i*112U);
    memset( msg, 0, 112U );
    memcpy( msg->vote_pubkey, n->elem.key.uc, sizeof(fd_pubkey_t) );
    memcpy( msg->node_pubkey, node_pubkey.uc, sizeof(fd_pubkey_t) );
    msg->activated_stake = n->elem.stake;
    msg->last_vote       = last_ts_slot;
    msg->is_delinquent   = (uchar)(msg->last_vote == 0);
    ++i;
  }
  } FD_SPAD_FRAME_END;

  *(ulong *)dst = i;

  ulong tspub = (ulong)fd_frag_meta_ts_comp( fd_tickcount() );
  fd_stem_publish( stem, ctx->votes_plug_out_idx, FD_PLUGIN_MSG_VOTE_ACCOUNT_UPDATE, ctx->votes_plugin_out_chunk, 0, 0UL, 0UL, tspub );
  ctx->votes_plugin_out_chunk = fd_dcache_compact_next( ctx->votes_plugin_out_chunk, 8UL + 40200UL*(58UL+12UL*34UL), ctx->votes_plugin_out_chunk0, ctx->votes_plugin_out_wmark );
}

/* after_credit runs on every iteration of the replay tile loop except
   when backpressured.

   This callback spin-loops for whether the blockstore is ready to join.
   We need to join a blockstore and load a snapshot before we can begin
   replaying.

   store_int is responsible for initializing the blockstore (either by
   calling new or restoring an existing one). Once the blockstore is
   available in the wksp (discovered via tag_query), we join the
   blockstore and load the snapshot. */
static void
after_credit( fd_replay_tile_ctx_t * ctx,
              fd_stem_context_t *    stem,
              int *                  opt_poll_in FD_PARAM_UNUSED,
              int *                  charge_busy ) {
  (void)opt_poll_in;

  exec_slices( ctx, stem, ctx->curr_slot );

  ulong curr_slot   = ctx->curr_slot;
  ulong parent_slot = ctx->parent_slot;
  ulong flags       = ctx->flags;
  ulong bank_idx    = ctx->bank_idx;

  fd_fork_t * fork = fd_fork_frontier_ele_query( ctx->forks->frontier, &ctx->curr_slot, NULL, ctx->forks->pool );

  ulong                 txn_cnt  = ctx->txn_cnt;
  fd_replay_out_ctx_t * bank_out = &ctx->bank_out[ bank_idx ];
  fd_txn_p_t *          txns     = (fd_txn_p_t *)fd_chunk_to_laddr( bank_out->mem, bank_out->chunk );
  /**********************************************************************/
  /* Cleanup and handle consensus after replaying the whole block       */
  /**********************************************************************/

  if( FD_UNLIKELY( (flags & REPLAY_FLAG_FINISHED_BLOCK) && ( ctx->last_completed_slot != curr_slot )) ) {
    fork->slot_ctx.txn_count = fork->slot_ctx.slot_bank.transaction_count-fork->slot_ctx.parent_transaction_count;
    FD_LOG_WARNING(( "finished block - slot: %lu, parent_slot: %lu, txn_cnt: %lu, blockhash: %s",
                  curr_slot,
                  ctx->parent_slot,
                  fork->slot_ctx.txn_count,
                  FD_BASE58_ENC_32_ALLOCA( ctx->blockhash.uc ) ));
    ctx->last_completed_slot = curr_slot;

    /**************************************************************************************************/
    /* Call fd_runtime_block_execute_finalize_tpool which updates sysvar and cleanup some other stuff */
    /**************************************************************************************************/

    fd_runtime_block_info_t runtime_block_info[1];
    runtime_block_info->signature_cnt = fork->slot_ctx.signature_cnt;

    /* Destroy the slot history */
    fd_slot_history_destroy( fork->slot_ctx.slot_history );
    for( ulong i = 0UL; i<ctx->bank_cnt; i++ ) {
      fd_tpool_wait( ctx->tpool, i+1 );
    }

    int res = fd_runtime_block_execute_finalize_tpool( &fork->slot_ctx, ctx->capture_ctx, runtime_block_info, ctx->tpool, ctx->runtime_spad );
    if( res != FD_RUNTIME_EXECUTE_SUCCESS ) {
      FD_LOG_ERR(( "block finished failed" ));
    }

    fd_spad_pop( ctx->runtime_spad );
    FD_LOG_NOTICE(( "Spad memory after executing block %lu", ctx->runtime_spad->mem_used ));
    /**********************************************************************/
    /* Push notifications for slot updates and reset block_info flag */
    /**********************************************************************/

    ulong block_entry_height = 0;
    for(;;){
      fd_block_map_query_t query[1] = { 0 };
      int err = fd_block_map_query_try( ctx->blockstore->block_map, &curr_slot, NULL, query, FD_MAP_FLAG_BLOCKING );
      fd_block_info_t * block_info = fd_block_map_query_ele( query );
      if( FD_UNLIKELY( err == FD_MAP_ERR_KEY   ) ) FD_LOG_ERR(( "Failed to query blockstore for slot %lu", curr_slot ));
      if( FD_UNLIKELY( err == FD_MAP_ERR_AGAIN ) ) continue;
      block_entry_height = block_info->block_height;
      if( FD_UNLIKELY( fd_block_map_query_test( query ) == FD_MAP_SUCCESS ) ) break;
    }

    publish_slot_notifications( ctx, stem, fork, block_entry_height, curr_slot );

    ctx->blockstore->shmem->lps = curr_slot;

    /**********************************************************************/
    /* Unlock the fork meaning that execution of the fork is now complete */
    /**********************************************************************/
    FD_TEST(fork->slot == curr_slot);
    fork->lock = 0;

    /**********************************************************************/
    /* Consensus: update ghost and forks                                  */
    /**********************************************************************/

    FD_PARAM_UNUSED long tic_ = fd_log_wallclock();
    fd_ghost_node_t const * ghost_node = fd_ghost_insert( ctx->ghost, parent_slot, curr_slot );
#if FD_GHOST_USE_HANDHOLDING
    if( FD_UNLIKELY( !ghost_node ) ) {
      FD_LOG_ERR(( "failed to insert ghost node %lu", fork->slot ));
    }
#endif
    fd_forks_update( ctx->forks, ctx->epoch, ctx->funk, ctx->ghost, fork->slot );

    /**********************************************************************/
    /* Consensus: decide (1) the fork for pack; (2) the fork to vote on   */
    /**********************************************************************/

    ulong reset_slot = fd_tower_reset_slot( ctx->tower, ctx->epoch, ctx->ghost );
    fd_fork_t const * reset_fork = fd_forks_query_const( ctx->forks, reset_slot );
    if( FD_UNLIKELY( !reset_fork ) ) {
      FD_LOG_ERR( ( "failed to find reset fork %lu", reset_slot ) );
    }
    if( reset_fork->lock ) {
      FD_LOG_WARNING(("RESET FORK FROZEN: %lu", reset_fork->slot ));
      fd_fork_t * new_reset_fork = fd_forks_prepare( ctx->forks, reset_fork->slot_ctx.slot_bank.prev_slot, ctx->acc_mgr,
                                                     ctx->blockstore, ctx->epoch_ctx, ctx->funk, ctx->runtime_spad );
      new_reset_fork->lock = 0;
      reset_fork = new_reset_fork;
    }

    /* Update the gui */
    if( ctx->replay_plugin_out_mem ) {
      /* FIXME. We need a more efficient way to compute the ancestor chain. */
      uchar msg[4098*8] __attribute__( ( aligned( 8U ) ) );
      fd_memset( msg, 0, sizeof(msg) );
      ulong s = reset_fork->slot_ctx.slot_bank.slot;
      *(ulong*)(msg + 16U) = s;
      ulong i = 0;
      do {
        if( !fd_blockstore_block_info_test( ctx->blockstore, s ) ) {
          break;
        }
        s = fd_blockstore_parent_slot_query( ctx->blockstore, s );
        if( s < ctx->blockstore->shmem->wmk ) {
          break;
        }

        *(ulong*)(msg + 24U + i*8U) = s;
        if( ++i == 4095U ) {
          break;
        }
      } while( 1 );
      *(ulong*)(msg + 8U) = i;
      replay_plugin_publish( ctx, stem, FD_PLUGIN_MSG_SLOT_RESET, msg, sizeof(msg) );
    }

    fd_microblock_trailer_t * microblock_trailer = (fd_microblock_trailer_t *)(txns + txn_cnt);
    memcpy( microblock_trailer->hash, reset_fork->slot_ctx.slot_bank.block_hash_queue.last_hash->uc, sizeof(fd_hash_t) );
    if( ctx->poh_init_done == 1 ) {
      ulong parent_slot = reset_fork->slot_ctx.slot_bank.prev_slot;
      ulong curr_slot = reset_fork->slot_ctx.slot_bank.slot;
      FD_LOG_DEBUG(( "publishing mblk to poh - slot: %lu, parent_slot: %lu, flags: %lx", curr_slot, parent_slot, flags ));
      ulong tspub = fd_frag_meta_ts_comp( fd_tickcount() );
      ulong sig = fd_disco_replay_old_sig( curr_slot, flags );
      fd_mcache_publish( bank_out->mcache, bank_out->depth, bank_out->seq, sig, bank_out->chunk, txn_cnt, 0UL, 0, tspub );
      bank_out->chunk = fd_dcache_compact_next( bank_out->chunk, (txn_cnt * sizeof(fd_txn_p_t)) + sizeof(fd_microblock_trailer_t), bank_out->chunk0, bank_out->wmark );
      bank_out->seq = fd_seq_inc( bank_out->seq, 1UL );
    } else {
      FD_LOG_DEBUG(( "NOT publishing mblk to poh - slot: %lu, parent_slot: %lu, flags: %lx", curr_slot, ctx->parent_slot, flags ));
    }

    fd_forks_print( ctx->forks );
    fd_ghost_print( ctx->ghost, ctx->epoch, fd_ghost_root( ctx->ghost ) );
    fd_tower_print( ctx->tower, ctx->root );

    fd_fork_t * child = fd_fork_frontier_ele_query( ctx->forks->frontier, &fork->slot, NULL, ctx->forks->pool );
    ulong vote_slot   = fd_tower_vote_slot( ctx->tower, ctx->epoch, ctx->funk, child->slot_ctx.funk_txn, ctx->ghost, ctx->runtime_spad );

    FD_LOG_NOTICE( ( "\n\n[Fork Selection]\n"
                     "# of vote accounts: %lu\n"
                     "best fork:          %lu\n",
                     fd_epoch_voters_key_cnt( fd_epoch_voters( ctx->epoch ) ),
                     fd_ghost_head( ctx->ghost, fd_ghost_root( ctx->ghost ) )->slot ) );

    /**********************************************************************/
    /* Consensus: send out a new vote by calling send_tower_sync          */
    /**********************************************************************/

    if( FD_UNLIKELY( ctx->vote && fd_fseq_query( ctx->poh ) == ULONG_MAX ) ) {
      /* Only proceed with voting if we're caught up. */

      FD_LOG_WARNING(( "still catching up. not voting." ));
    } else {
      if( FD_UNLIKELY( !ctx->is_caught_up ) ) {
        ctx->is_caught_up = 1;
      }

      /* Proceed according to how local and cluster are synchronized. */

      if( FD_LIKELY( vote_slot != FD_SLOT_NULL ) ) {

        /* Invariant check: the vote_slot must be in the frontier */

        FD_TEST( fd_forks_query_const( ctx->forks, vote_slot ) );

        /* Vote locally */

        ulong root = fd_tower_vote( ctx->tower, vote_slot );
        ctx->metrics.last_voted_slot = vote_slot;

        /* Update to a new root, if there is one. */

        if ( FD_LIKELY ( root != FD_SLOT_NULL ) ) ctx->root = root; /* optimize for full tower (replay is keeping up) */
      }

      /* Send our updated tower to the cluster. */

      send_tower_sync( ctx );
    }

    /**********************************************************************/
    /* Prepare bank for the next execution and write to debugging files   */
    /**********************************************************************/

    ulong prev_slot = child->slot_ctx.slot_bank.slot;
    child->slot_ctx.slot_bank.slot           = curr_slot;
    child->slot_ctx.slot_bank.collected_execution_fees = 0;
    child->slot_ctx.slot_bank.collected_priority_fees = 0;
    child->slot_ctx.slot_bank.collected_rent = 0;

    if( FD_UNLIKELY( ctx->slots_replayed_file ) ) {
      FD_LOG_DEBUG(( "writing %lu to slots file", prev_slot ));
      fprintf( ctx->slots_replayed_file, "%lu\n", prev_slot );
      fflush( ctx->slots_replayed_file );
    }

    if (NULL != ctx->capture_ctx) {
      fd_solcap_writer_flush( ctx->capture_ctx->capture );
    }

    /**********************************************************************/
    /* Bank hash comparison, and halt if there's a mismatch after replay  */
    /**********************************************************************/

    fd_hash_t const * bank_hash = &child->slot_ctx.slot_bank.banks_hash;
    fd_bank_hash_cmp_t * bank_hash_cmp = child->slot_ctx.epoch_ctx->bank_hash_cmp;
    fd_bank_hash_cmp_lock( bank_hash_cmp );
    fd_bank_hash_cmp_insert( bank_hash_cmp, curr_slot, bank_hash, 1, 0 );

    /* Try to move the bank hash comparison watermark forward */
    for( ulong cmp_slot = bank_hash_cmp->watermark + 1; cmp_slot < curr_slot; cmp_slot++ ) {
      int rc = fd_bank_hash_cmp_check( bank_hash_cmp, cmp_slot );
      switch ( rc ) {
        case -1:

          /* Mismatch */

          funk_cancel( ctx, cmp_slot );
          checkpt( ctx );
          FD_LOG_ERR(( "Bank hash mismatch on slot: %lu. Halting.", cmp_slot ));

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
  } // end of if( FD_UNLIKELY( ( flags & REPLAY_FLAG_FINISHED_BLOCK ) ) )

  if( FD_UNLIKELY( ctx->snapshot_init_done==0 ) ) {
    init_snapshot( ctx, stem );
    ctx->snapshot_init_done = 1;
    *charge_busy = 1;
    if( ctx->replay_plugin_out_mem ) {
      // ValidatorStartProgress::Running
      uchar msg[56];
      fd_memset( msg, 0, sizeof(msg) );
      msg[0] = 11;
      replay_plugin_publish( ctx, stem, FD_PLUGIN_MSG_START_PROGRESS, msg, sizeof(msg) );
    }
  }

  long now = fd_log_wallclock();
  if( ctx->votes_plugin_out_mem && FD_UNLIKELY( ( now - ctx->last_plugin_push_time )>PLUGIN_PUBLISH_TIME_NS ) ) {
    ctx->last_plugin_push_time = now;
    publish_votes_to_plugin( ctx, stem );
  }

}

static void
during_housekeeping( void * _ctx ) {

  fd_replay_tile_ctx_t * ctx = (fd_replay_tile_ctx_t *)_ctx;

  /* Update watermark. The publish watermark is the minimum of the tower
     root and supermajority root. */

  ulong wmark = fd_ulong_min( ctx->root, ctx->forks->finalized );

  if ( FD_LIKELY( wmark <= fd_fseq_query( ctx->published_wmark ) ) ) return;
  FD_LOG_NOTICE(( "wmk %lu => %lu", fd_fseq_query( ctx->published_wmark ), wmark ));

  fd_funk_txn_xid_t xid = { .ul = { wmark, wmark } };
  if( FD_LIKELY( ctx->blockstore ) ) fd_blockstore_publish( ctx->blockstore, ctx->blockstore_fd, wmark );
  if( FD_LIKELY( ctx->forks ) ) fd_forks_publish( ctx->forks, wmark, ctx->ghost );
  if( FD_LIKELY( ctx->funk ) ) funk_and_txncache_publish( ctx, wmark, &xid );
  if( FD_LIKELY( ctx->ghost ) ) {
    fd_epoch_forks_publish( ctx->epoch_forks, ctx->ghost, wmark );
    fd_ghost_publish( ctx->ghost, wmark );
  }

  fd_fseq_update( ctx->published_wmark, wmark );


  // fd_mcache_seq_update( ctx->store_out_sync, ctx->store_out_seq );
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_replay_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_replay_tile_ctx_t), sizeof(fd_replay_tile_ctx_t) );
  FD_SCRATCH_ALLOC_FINI  ( l, scratch_align() );
  memset( ctx, 0, sizeof(fd_replay_tile_ctx_t) );

  FD_TEST( sizeof(ulong) == getrandom( &ctx->funk_seed, sizeof(ulong), 0 ) );
  FD_TEST( sizeof(ulong) == getrandom( &ctx->status_cache_seed, sizeof(ulong), 0 ) );

  ctx->blockstore_fd = open( tile->replay.blockstore_file, O_RDWR | O_CREAT, 0666 );
  if ( FD_UNLIKELY( ctx->blockstore_fd == -1 ) ) {
    FD_LOG_ERR(( "failed to open or create blockstore archival file %s %d %d %s", tile->replay.blockstore_file, ctx->blockstore_fd, errno, strerror(errno) ));
  }
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {

  FD_LOG_NOTICE(("finished unprivileged init"));
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  if( FD_UNLIKELY( tile->in_cnt < 4 ||
                   strcmp( topo->links[ tile->in_link_id[ STORE_IN_IDX  ] ].name, "store_replay" ) ||
                   strcmp( topo->links[ tile->in_link_id[ PACK_IN_IDX ] ].name, "pack_replay")   ||
                   strcmp( topo->links[ tile->in_link_id[ BATCH_IN_IDX  ] ].name, "batch_replay" ) ||
                   strcmp( topo->links[ tile->in_link_id[ SHRED_IN_IDX  ] ].name, "shred_replay" ) ) ) {
    FD_LOG_ERR(( "replay tile has none or unexpected input links %lu %s %s",
                 tile->in_cnt, topo->links[ tile->in_link_id[ 0 ] ].name, topo->links[ tile->in_link_id[ 1 ] ].name ));
  }

  /**********************************************************************/
  /* scratch (bump)-allocate memory owned by the replay tile            */
  /**********************************************************************/

  /* Do not modify order! This is join-order in unprivileged_init. */

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_replay_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_replay_tile_ctx_t), sizeof(fd_replay_tile_ctx_t) );
  void * alloc_shmem         = FD_SCRATCH_ALLOC_APPEND( l, fd_alloc_align(), fd_alloc_footprint() );
  void * capture_ctx_mem     = FD_SCRATCH_ALLOC_APPEND( l, FD_CAPTURE_CTX_ALIGN, FD_CAPTURE_CTX_FOOTPRINT );
  void * epoch_mem           = FD_SCRATCH_ALLOC_APPEND( l, fd_epoch_align(), fd_epoch_footprint( FD_VOTER_MAX ) );
  void * forks_mem           = FD_SCRATCH_ALLOC_APPEND( l, fd_forks_align(), fd_forks_footprint( FD_BLOCK_MAX ) );
  void * ghost_mem           = FD_SCRATCH_ALLOC_APPEND( l, fd_ghost_align(), fd_ghost_footprint( FD_BLOCK_MAX ) );
  void * tower_mem           = FD_SCRATCH_ALLOC_APPEND( l, fd_tower_align(), fd_tower_footprint() );
  void * replay_mem          = FD_SCRATCH_ALLOC_APPEND( l, fd_replay_align(), fd_replay_footprint( tile->replay.fec_max, FD_SHRED_MAX_PER_SLOT, FD_BLOCK_MAX ) );
  void * bank_hash_cmp_mem   = FD_SCRATCH_ALLOC_APPEND( l, fd_bank_hash_cmp_align(), fd_bank_hash_cmp_footprint( ) );
  for( ulong i = 0UL; i<FD_PACK_MAX_BANK_TILES; i++ ) {
    ctx->bmtree[i]           = FD_SCRATCH_ALLOC_APPEND( l, FD_BMTREE_COMMIT_ALIGN, FD_BMTREE_COMMIT_FOOTPRINT(0) );
  }
  void * mbatch_mem          = FD_SCRATCH_ALLOC_APPEND( l, 128UL, FD_SLICE_MAX );
  ulong  thread_spad_size    = fd_spad_footprint( FD_RUNTIME_TRANSACTION_EXECUTION_FOOTPRINT_DEFAULT );
  void * spad_mem            = FD_SCRATCH_ALLOC_APPEND( l, fd_spad_align(), tile->replay.tpool_thread_count * fd_ulong_align_up( thread_spad_size, fd_spad_align() ) + FD_RUNTIME_BLOCK_EXECUTION_FOOTPRINT );
  ulong  scratch_alloc_mem   = FD_SCRATCH_ALLOC_FINI  ( l, scratch_align() );

  if( FD_UNLIKELY( scratch_alloc_mem != ( (ulong)scratch + scratch_footprint( tile ) ) ) ) {
    FD_LOG_ERR( ( "scratch_alloc_mem did not match scratch_footprint diff: %lu alloc: %lu footprint: %lu",
          scratch_alloc_mem - (ulong)scratch - scratch_footprint( tile ),
          scratch_alloc_mem,
          (ulong)scratch + scratch_footprint( tile ) ) );
  }

  /**********************************************************************/
  /* wksp                                                               */
  /**********************************************************************/

  ctx->wksp = topo->workspaces[ topo->objs[ tile->tile_obj_id ].wksp_id ].wksp;

  ulong blockstore_obj_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "blockstore" );
  FD_TEST( blockstore_obj_id!=ULONG_MAX );
  ctx->blockstore_wksp = topo->workspaces[ topo->objs[ blockstore_obj_id ].wksp_id ].wksp;
  if( ctx->blockstore_wksp==NULL ) {
    FD_LOG_ERR(( "no blockstore wksp" ));
  }

  ctx->blockstore = fd_blockstore_join( &ctx->blockstore_ljoin, fd_topo_obj_laddr( topo, blockstore_obj_id ) );
  fd_buf_shred_pool_reset( ctx->blockstore->shred_pool, 0 );
  FD_TEST( ctx->blockstore->shmem->magic == FD_BLOCKSTORE_MAGIC );

  ulong status_cache_obj_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "txncache" );
  FD_TEST( status_cache_obj_id != ULONG_MAX );
  ctx->status_cache_wksp = topo->workspaces[topo->objs[status_cache_obj_id].wksp_id].wksp;
  if( ctx->status_cache_wksp == NULL ) {
    FD_LOG_ERR(( "no status cache wksp" ));
  }

  /**********************************************************************/
  /* snapshot                                                           */
  /**********************************************************************/

  ctx->snapshot_interval    = tile->replay.full_interval ? tile->replay.full_interval : ULONG_MAX;
  ctx->incremental_interval = tile->replay.incremental_interval ? tile->replay.incremental_interval : ULONG_MAX;
  ctx->last_full_snap       = 0UL;

  FD_LOG_NOTICE(( "Snapshot intervals full=%lu incremental=%lu", ctx->snapshot_interval, ctx->incremental_interval ));

  /**********************************************************************/
  /* funk                                                               */
  /**********************************************************************/

  /* TODO: This below code needs to be shared as a topology object. This
     will involve adding support to create a funk-based file here. */
  fd_funk_t * funk;
  const char * snapshot = tile->replay.snapshot;
  if( strcmp( snapshot, "funk" ) == 0 ) {
    /* Funk database already exists. The parameters are actually mostly ignored. */
    funk = fd_funk_open_file(
      tile->replay.funk_file, 1, ctx->funk_seed, tile->replay.funk_txn_max,
        tile->replay.funk_rec_max, tile->replay.funk_sz_gb * (1UL<<30),
        FD_FUNK_READ_WRITE, NULL );
  } else if( strncmp( snapshot, "wksp:", 5 ) == 0) {
    /* Recover funk database from a checkpoint. */
    funk = fd_funk_recover_checkpoint( tile->replay.funk_file, 1, snapshot+5, NULL );
  } else {
    /* Create new funk database */
    funk = fd_funk_open_file(
      tile->replay.funk_file, 1, ctx->funk_seed, tile->replay.funk_txn_max,
        tile->replay.funk_rec_max, tile->replay.funk_sz_gb * (1UL<<30),
        FD_FUNK_OVERWRITE, NULL );
    FD_LOG_NOTICE(( "Opened funk file at %s", tile->replay.funk_file ));
  }
  if( FD_UNLIKELY( funk == NULL ) ) {
    FD_LOG_ERR(( "no funk loaded" ));
  }
  ctx->funk = funk;
  ctx->funk_wksp = fd_funk_wksp( funk );
  if( FD_UNLIKELY( ctx->funk_wksp == NULL ) ) {
    FD_LOG_ERR(( "no funk wksp" ));
  }

  ctx->is_caught_up = 0;

  /**********************************************************************/
  /* root_slot fseq                                                     */
  /**********************************************************************/

  ulong root_slot_obj_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "root_slot" );
  FD_TEST( root_slot_obj_id!=ULONG_MAX );
  ctx->published_wmark = fd_fseq_join( fd_topo_obj_laddr( topo, root_slot_obj_id ) );
  if( FD_UNLIKELY( !ctx->published_wmark ) ) FD_LOG_ERR(( "replay tile has no root_slot fseq" ));
  FD_TEST( ULONG_MAX==fd_fseq_query( ctx->published_wmark ) );

  /**********************************************************************/
  /* constipated fseq                                                   */
  /**********************************************************************/

  /* When the replay tile boots, funk should not be constipated */

  ulong constipated_obj_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "constipate" );
  FD_TEST( constipated_obj_id!=ULONG_MAX );
  ctx->is_constipated = fd_fseq_join( fd_topo_obj_laddr( topo, constipated_obj_id ) );
  if( FD_UNLIKELY( !ctx->is_constipated ) ) FD_LOG_ERR(( "replay tile has no constipated fseq" ));
  fd_fseq_update( ctx->is_constipated, 0UL );
  FD_TEST( 0UL==fd_fseq_query( ctx->is_constipated ) );

  /**********************************************************************/
  /* poh_slot fseq                                                     */
  /**********************************************************************/

  ulong poh_slot_obj_id = fd_pod_query_ulong( topo->props, "poh_slot", ULONG_MAX );
  FD_TEST( poh_slot_obj_id!=ULONG_MAX );
  ctx->poh = fd_fseq_join( fd_topo_obj_laddr( topo, poh_slot_obj_id ) );

  /**********************************************************************/
  /* TOML paths                                                         */
  /**********************************************************************/

  ctx->blockstore_checkpt  = tile->replay.blockstore_checkpt;
  ctx->tx_metadata_storage = tile->replay.tx_metadata_storage;
  ctx->funk_checkpt        = tile->replay.funk_checkpt;
  ctx->genesis             = tile->replay.genesis;
  ctx->incremental         = tile->replay.incremental;
  ctx->snapshot            = tile->replay.snapshot;

  /**********************************************************************/
  /* alloc                                                              */
  /**********************************************************************/

  void * alloc_shalloc = fd_alloc_new( alloc_shmem, 3UL );
  if( FD_UNLIKELY( !alloc_shalloc ) ) {
    FD_LOG_ERR( ( "fd_alloc_new failed" ) ); }
  ctx->alloc = fd_alloc_join( alloc_shalloc, 3UL );
  if( FD_UNLIKELY( !ctx->alloc ) ) {
    FD_LOG_ERR( ( "fd_alloc_join failed" ) );
  }

  /**********************************************************************/
  /* status cache                                                       */
  /**********************************************************************/

  char const * status_cache_path = tile->replay.status_cache;
  if ( strlen( status_cache_path ) > 0 ) {
    FD_LOG_NOTICE(("starting status cache restore..."));
    int err = fd_wksp_restore( ctx->status_cache_wksp, status_cache_path, (uint)ctx->status_cache_seed );
    FD_LOG_NOTICE(("finished status cache restore..."));
    if (err) {
      FD_LOG_ERR(( "failed to restore %s: error %d", status_cache_path, err ));
    }
    fd_wksp_tag_query_info_t info;
    ulong tag = FD_TXNCACHE_MAGIC;
    if( fd_wksp_tag_query( ctx->status_cache_wksp, &tag, 1, &info, 1 ) > 0 ) {
      void * status_cache_mem = fd_wksp_laddr_fast( ctx->status_cache_wksp, info.gaddr_lo );
      /* Set up status cache. */
      ctx->status_cache = fd_txncache_join( status_cache_mem );
      if( ctx->status_cache == NULL ) {
        FD_LOG_ERR(( "failed to join status cache in %s", status_cache_path ));
      }
    } else {
      FD_LOG_ERR(( "failed to tag query status cache in %s", status_cache_path ));
    }
  } else {
    void * status_cache_mem = fd_topo_obj_laddr( topo, status_cache_obj_id );
    if (status_cache_mem == NULL) {
      FD_LOG_ERR(( "failed to allocate status cache" ));
    }
    ctx->status_cache = fd_txncache_join( fd_txncache_new( status_cache_mem, FD_TXNCACHE_DEFAULT_MAX_ROOTED_SLOTS,
                                                           FD_TXNCACHE_DEFAULT_MAX_LIVE_SLOTS, MAX_CACHE_TXNS_PER_SLOT,
                                                           FD_TXNCACHE_DEFAULT_MAX_CONSTIPATED_SLOTS ) );
    if (ctx->status_cache == NULL) {
      fd_wksp_free_laddr(status_cache_mem);
      FD_LOG_ERR(( "failed to join + new status cache" ));
    }
  }

  /**********************************************************************/
  /* spad                                                               */
  /**********************************************************************/

  /* TODO: The spad should probably have its own workspace. Eventually each
     spad allocator should be bound to a transaction executor tile and should
     be bounded out for the maximum amount of allocations used in the runtime. */

  uchar * spad_mem_cur = spad_mem;
  for( ulong i=0UL; i<tile->replay.tpool_thread_count; i++ ) {
    fd_spad_t * spad = fd_spad_join( fd_spad_new( spad_mem_cur, thread_spad_size ) );
    ctx->exec_spads[ ctx->exec_spad_cnt++ ] = spad;
    spad_mem_cur += fd_ulong_align_up( thread_spad_size, fd_spad_align() );
  }

  ctx->runtime_spad = fd_spad_join( fd_spad_new( spad_mem_cur, FD_RUNTIME_BLOCK_EXECUTION_FOOTPRINT ) );
  fd_spad_push( ctx->runtime_spad );

  /**********************************************************************/
  /* epoch forks                                                        */
  /**********************************************************************/

  void * epoch_ctx_mem = fd_spad_alloc( ctx->runtime_spad,
                                        fd_exec_epoch_ctx_align(),
                                        MAX_EPOCH_FORKS * fd_exec_epoch_ctx_footprint( VOTE_ACC_MAX ) );


  fd_epoch_forks_new( ctx->epoch_forks, epoch_ctx_mem );

  /**********************************************************************/
  /* joins                                                              */
  /**********************************************************************/

  uchar * acc_mgr_shmem = fd_spad_alloc( ctx->runtime_spad, FD_ACC_MGR_ALIGN, FD_ACC_MGR_FOOTPRINT );
  ctx->acc_mgr       = fd_acc_mgr_new( acc_mgr_shmem, ctx->funk );
  ctx->bank_hash_cmp = fd_bank_hash_cmp_join( fd_bank_hash_cmp_new( bank_hash_cmp_mem ) );
  ctx->epoch_ctx     = fd_exec_epoch_ctx_join( fd_exec_epoch_ctx_new( epoch_ctx_mem, VOTE_ACC_MAX ) );

  if( FD_UNLIKELY( sscanf( tile->replay.cluster_version, "%u.%u.%u", &ctx->epoch_ctx->epoch_bank.cluster_version[0], &ctx->epoch_ctx->epoch_bank.cluster_version[1], &ctx->epoch_ctx->epoch_bank.cluster_version[2] )!=3 ) ) {
    FD_LOG_ERR(( "failed to decode cluster version, configured as \"%s\"", tile->replay.cluster_version ));
  }
  fd_features_enable_cleaned_up( &ctx->epoch_ctx->features, ctx->epoch_ctx->epoch_bank.cluster_version );

  ctx->epoch = fd_epoch_join( fd_epoch_new( epoch_mem, FD_VOTER_MAX ) );
  ctx->forks = fd_forks_join( fd_forks_new( forks_mem, FD_BLOCK_MAX, 42UL ) );
  ctx->ghost = fd_ghost_join( fd_ghost_new( ghost_mem, 42UL, FD_BLOCK_MAX ) );
  ctx->tower = fd_tower_join( fd_tower_new( tower_mem ) );

  ctx->replay = fd_replay_join( fd_replay_new( replay_mem, tile->replay.fec_max, FD_SHRED_MAX_PER_SLOT, FD_BLOCK_MAX ) );

  /**********************************************************************/
  /* voter                                                              */
  /**********************************************************************/

  memcpy( ctx->validator_identity, fd_keyload_load( tile->replay.identity_key_path, 1 ), sizeof(fd_pubkey_t) );
  *ctx->vote_authority = *ctx->validator_identity; /* FIXME */
  memcpy( ctx->vote_acc, fd_keyload_load( tile->replay.vote_account_path, 1 ), sizeof(fd_pubkey_t) );

  /**********************************************************************/
  /* entry batch                                                        */
  /**********************************************************************/

  ctx->mbatch = mbatch_mem;
  memset( &ctx->slice_exec_ctx, 0, sizeof(fd_slice_exec_ctx_t) );

  /**********************************************************************/
  /* tpool                                                              */
  /**********************************************************************/

  if( FD_LIKELY( tile->replay.tpool_thread_count > 1 ) ) {
    tpool_boot( topo, tile->replay.tpool_thread_count );
  }
  ctx->tpool = fd_tpool_init( ctx->tpool_mem, tile->replay.tpool_thread_count );

  if( FD_LIKELY( tile->replay.tpool_thread_count > 1 ) ) {
    /* Start the tpool workers */
    for( ulong i=1UL; i<tile->replay.tpool_thread_count; i++ ) {
      if( fd_tpool_worker_push( ctx->tpool, i, NULL, 0UL ) == NULL ) {
        FD_LOG_ERR(( "failed to launch worker" ));
      }
    }
  }

  if( ctx->tpool == NULL ) {
    FD_LOG_ERR(("failed to create thread pool"));
  }

  /**********************************************************************/
  /* capture                                                            */
  /**********************************************************************/

  if( strlen(tile->replay.capture) > 0 ) {
    ctx->capture_ctx = fd_capture_ctx_new( capture_ctx_mem );
    ctx->capture_ctx->checkpt_freq = ULONG_MAX;
    ctx->capture_file = fopen( tile->replay.capture, "w+" );
    if( FD_UNLIKELY( !ctx->capture_file ) ) {
      FD_LOG_ERR(( "fopen(%s) failed (%d-%s)", tile->replay.capture, errno, strerror( errno ) ));
    }
    ctx->capture_ctx->capture_txns = 0;
    fd_solcap_writer_init( ctx->capture_ctx->capture, ctx->capture_file );
  }

  /**********************************************************************/
  /* bank                                                               */
  /**********************************************************************/

  ctx->bank_cnt         = tile->replay.bank_tile_count;
  for( ulong i=0UL; i<tile->replay.bank_tile_count; i++ ) {
    ulong busy_obj_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "bank_busy.%lu", i );
    FD_TEST( busy_obj_id!=ULONG_MAX );
    ctx->bank_busy[ i ] = fd_fseq_join( fd_topo_obj_laddr( topo, busy_obj_id ) );
    if( FD_UNLIKELY( !ctx->bank_busy[ i ] ) ) FD_LOG_ERR(( "banking tile %lu has no busy flag", i ));

    fd_topo_link_t * poh_out_link = &topo->links[ tile->out_link_id[ POH_OUT_IDX+i ] ];
    fd_replay_out_ctx_t * poh_out = &ctx->bank_out[ i ];
    poh_out->mcache           = poh_out_link->mcache;
    poh_out->sync             = fd_mcache_seq_laddr( poh_out->mcache );
    poh_out->depth            = fd_mcache_depth( poh_out->mcache );
    poh_out->seq              = fd_mcache_seq_query( poh_out->sync );
    poh_out->mem              = topo->workspaces[ topo->objs[ poh_out_link->dcache_obj_id ].wksp_id ].wksp;
    poh_out->chunk0           = fd_dcache_compact_chunk0( poh_out->mem, poh_out_link->dcache );
    poh_out->wmark            = fd_dcache_compact_wmark( poh_out->mem, poh_out_link->dcache, poh_out_link->mtu );
    poh_out->chunk            = poh_out->chunk0;
  }

  ctx->poh_init_done = 0U;
  ctx->snapshot_init_done = 0;

  /**********************************************************************/
  /* exec                                                               */
  /**********************************************************************/
  ctx->exec_cnt = tile->replay.exec_tile_count;
  for( ulong i = 0UL; i < ctx->exec_cnt; i++ ) {
    ulong idx = fd_topo_find_tile_out_link( topo, tile, "replay_exec", i );
    fd_topo_link_t * exec_out_link = &topo->links[ tile->out_link_id[ idx ] ];

    if( strcmp( exec_out_link->name, "replay_exec" ) ) {
      FD_LOG_ERR(("output link confusion for output %lu", idx ));
    }

    fd_replay_out_ctx_t * exec_out = &ctx->exec_out[ i ];
    exec_out->idx              = idx;
    exec_out->mem              = topo->workspaces[ topo->objs[ exec_out_link->dcache_obj_id ].wksp_id ].wksp;
    exec_out->chunk0           = fd_dcache_compact_chunk0( exec_out->mem, exec_out_link->dcache );
    exec_out->wmark            = fd_dcache_compact_wmark( exec_out->mem, exec_out_link->dcache, exec_out_link->mtu );
    exec_out->chunk            = exec_out->chunk0;
  }

  /* set up vote related items */
  ctx->vote                           = tile->replay.vote;
  ctx->validator_identity_pubkey[ 0 ] = *(fd_pubkey_t const *)fd_type_pun_const( fd_keyload_load( tile->replay.identity_key_path, 1 ) );
  ctx->vote_acct_addr[ 0 ]            = *(fd_pubkey_t const *)fd_type_pun_const( fd_keyload_load( tile->replay.vote_account_path, 1 ) );

  /**********************************************************************/
  /* tower checkpointing for wen-restart                                */
  /**********************************************************************/
  ctx->tower_checkpt_fileno = -1;
  if( FD_LIKELY( strlen( tile->replay.tower_checkpt )>0 ) ) {
    ctx->tower_checkpt_fileno = open( tile->replay.tower_checkpt,
                                      O_RDWR | O_CREAT,
                                      S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH );
    if( ctx->tower_checkpt_fileno<0 ) FD_LOG_ERR(( "Failed at opening the tower checkpoint file" ));
  }

  /**********************************************************************/
  /* links                                                              */
  /**********************************************************************/

  /* Setup store tile input */
  fd_topo_link_t * store_in_link = &topo->links[ tile->in_link_id[ STORE_IN_IDX ] ];
  ctx->store_in_mem              = topo->workspaces[ topo->objs[ store_in_link->dcache_obj_id ].wksp_id ].wksp;
  ctx->store_in_chunk0           = fd_dcache_compact_chunk0( ctx->store_in_mem, store_in_link->dcache );
  ctx->store_in_wmark            = fd_dcache_compact_wmark( ctx->store_in_mem, store_in_link->dcache, store_in_link->mtu );

  /* Setup pack tile input */
  fd_topo_link_t * pack_in_link = &topo->links[ tile->in_link_id[ PACK_IN_IDX ] ];
  ctx->pack_in_mem              = topo->workspaces[ topo->objs[ pack_in_link->dcache_obj_id ].wksp_id ].wksp;
  ctx->pack_in_chunk0           = fd_dcache_compact_chunk0( ctx->pack_in_mem, pack_in_link->dcache );
  ctx->pack_in_wmark            = fd_dcache_compact_wmark( ctx->pack_in_mem, pack_in_link->dcache, pack_in_link->mtu );

  /* Setup batch tile input for epoch account hash */
  fd_topo_link_t * batch_in_link = &topo->links[ tile->in_link_id[ BATCH_IN_IDX ] ];
  ctx->batch_in_mem              = topo->workspaces[ topo->objs[ batch_in_link->dcache_obj_id ].wksp_id ].wksp;
  ctx->batch_in_chunk0           = fd_dcache_compact_chunk0( ctx->batch_in_mem, batch_in_link->dcache );
  ctx->batch_in_wmark            = fd_dcache_compact_wmark( ctx->batch_in_mem, batch_in_link->dcache, batch_in_link->mtu );

  ctx->shred_in_cnt = tile->in_cnt-SHRED_IN_IDX;
  for( ulong i = 0; i<ctx->shred_in_cnt; i++ ) {
    fd_topo_link_t * shred_in_link = &topo->links[ tile->in_link_id[ i+SHRED_IN_IDX ] ];
    ctx->shred_in[ i ].mem    = topo->workspaces[ topo->objs[ shred_in_link->dcache_obj_id ].wksp_id ].wksp;
    ctx->shred_in[ i ].chunk0 = fd_dcache_compact_chunk0( ctx->shred_in[ i ].mem, shred_in_link->dcache );
    ctx->shred_in[ i ].wmark  = fd_dcache_compact_wmark( ctx->shred_in[ i ].mem, shred_in_link->dcache, shred_in_link->mtu );
  }

  fd_topo_link_t * notif_out = &topo->links[ tile->out_link_id[ NOTIF_OUT_IDX ] ];
  ctx->notif_out_mcache      = notif_out->mcache;
  ctx->notif_out_sync        = fd_mcache_seq_laddr( ctx->notif_out_mcache );
  ctx->notif_out_depth       = fd_mcache_depth( ctx->notif_out_mcache );
  ctx->notif_out_seq         = fd_mcache_seq_query( ctx->notif_out_sync );
  ctx->notif_out_mem         = topo->workspaces[ topo->objs[ notif_out->dcache_obj_id ].wksp_id ].wksp;
  ctx->notif_out_chunk0      = fd_dcache_compact_chunk0( ctx->notif_out_mem, notif_out->dcache );
  ctx->notif_out_wmark       = fd_dcache_compact_wmark ( ctx->notif_out_mem, notif_out->dcache, notif_out->mtu );
  ctx->notif_out_chunk       = ctx->notif_out_chunk0;

  fd_topo_link_t * sender_out = &topo->links[ tile->out_link_id[ SENDER_OUT_IDX ] ];
  ctx->sender_out_mcache      = sender_out->mcache;
  ctx->sender_out_sync        = fd_mcache_seq_laddr( ctx->sender_out_mcache );
  ctx->sender_out_depth       = fd_mcache_depth( ctx->sender_out_mcache );
  ctx->sender_out_seq         = fd_mcache_seq_query( ctx->sender_out_sync );
  ctx->sender_out_mem         = topo->workspaces[ topo->objs[ sender_out->dcache_obj_id ].wksp_id ].wksp;
  ctx->sender_out_chunk0      = fd_dcache_compact_chunk0( ctx->sender_out_mem, sender_out->dcache );
  ctx->sender_out_wmark       = fd_dcache_compact_wmark ( ctx->sender_out_mem, sender_out->dcache, sender_out->mtu );
  ctx->sender_out_chunk       = ctx->sender_out_chunk0;

  /* Set up stake weights tile output */
  fd_topo_link_t * stake_weights_out = &topo->links[ tile->out_link_id[ STAKE_OUT_IDX] ];
  ctx->stake_weights_out_mcache      = stake_weights_out->mcache;
  ctx->stake_weights_out_sync   = fd_mcache_seq_laddr( ctx->stake_weights_out_mcache );
  ctx->stake_weights_out_depth  = fd_mcache_depth( ctx->stake_weights_out_mcache );
  ctx->stake_weights_out_seq    = fd_mcache_seq_query( ctx->stake_weights_out_sync );
  ctx->stake_weights_out_mem    = topo->workspaces[ topo->objs[ stake_weights_out->dcache_obj_id ].wksp_id ].wksp;
  ctx->stake_weights_out_chunk0 = fd_dcache_compact_chunk0( ctx->stake_weights_out_mem, stake_weights_out->dcache );
  ctx->stake_weights_out_wmark  = fd_dcache_compact_wmark ( ctx->stake_weights_out_mem, stake_weights_out->dcache, stake_weights_out->mtu );
  ctx->stake_weights_out_chunk  = ctx->stake_weights_out_chunk0;

  if( FD_LIKELY( tile->replay.plugins_enabled ) ) {
    ctx->replay_plug_out_idx = fd_topo_find_tile_out_link( topo, tile, "replay_plugi", 0 );
    fd_topo_link_t const * replay_plugin_out = &topo->links[ tile->out_link_id[ ctx->replay_plug_out_idx] ];
    if( strcmp( replay_plugin_out->name, "replay_plugi" ) ) {
      FD_LOG_ERR(("output link confusion for output %lu", ctx->replay_plug_out_idx));
    }
    ctx->replay_plugin_out_mem    = topo->workspaces[ topo->objs[ replay_plugin_out->dcache_obj_id ].wksp_id ].wksp;
    ctx->replay_plugin_out_chunk0 = fd_dcache_compact_chunk0( ctx->replay_plugin_out_mem, replay_plugin_out->dcache );
    ctx->replay_plugin_out_wmark  = fd_dcache_compact_wmark ( ctx->replay_plugin_out_mem, replay_plugin_out->dcache, replay_plugin_out->mtu );
    ctx->replay_plugin_out_chunk  = ctx->replay_plugin_out_chunk0;

    ctx->votes_plug_out_idx = fd_topo_find_tile_out_link( topo, tile, "votes_plugin", 0 );
    fd_topo_link_t const * votes_plugin_out = &topo->links[ tile->out_link_id[ ctx->votes_plug_out_idx] ];
    if( strcmp( votes_plugin_out->name, "votes_plugin" ) ) {
      FD_LOG_ERR(("output link confusion for output %lu", ctx->votes_plug_out_idx));
    }
    ctx->votes_plugin_out_mem    = topo->workspaces[ topo->objs[ votes_plugin_out->dcache_obj_id ].wksp_id ].wksp;
    ctx->votes_plugin_out_chunk0 = fd_dcache_compact_chunk0( ctx->votes_plugin_out_mem, votes_plugin_out->dcache );
    ctx->votes_plugin_out_wmark  = fd_dcache_compact_wmark ( ctx->votes_plugin_out_mem, votes_plugin_out->dcache, votes_plugin_out->mtu );
    ctx->votes_plugin_out_chunk  = ctx->votes_plugin_out_chunk0;
  }

  if( strnlen( tile->replay.slots_replayed, sizeof(tile->replay.slots_replayed) )>0UL ) {
    ctx->slots_replayed_file = fopen( tile->replay.slots_replayed, "w" );
    FD_TEST( ctx->slots_replayed_file );
  }

  /* replay public setup */
  ulong replay_obj_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "replay_pub" );
  FD_TEST( replay_obj_id!=ULONG_MAX );
  ctx->replay_public_wksp = topo->workspaces[ topo->objs[ replay_obj_id ].wksp_id ].wksp;

  if( ctx->replay_public_wksp==NULL ) {
    FD_LOG_ERR(( "no replay_public workspace" ));
  }

  ctx->replay_public = fd_runtime_public_join( fd_topo_obj_laddr( topo, replay_obj_id ) );
  ctx->fecs_inserted = 0UL;
  ctx->fecs_removed  = 0UL;
  FD_TEST( ctx->replay_public!=NULL );
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_replay_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_replay_tile_ctx_t), sizeof(fd_replay_tile_ctx_t) );
  FD_SCRATCH_ALLOC_FINI( l, sizeof(fd_replay_tile_ctx_t) );

  populate_sock_filter_policy_fd_replay_tile( out_cnt, out, (uint)fd_log_private_logfile_fd(), (uint)ctx->blockstore_fd );
  return sock_filter_policy_fd_replay_tile_instr_cnt;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_replay_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_replay_tile_ctx_t), sizeof(fd_replay_tile_ctx_t) );
  FD_SCRATCH_ALLOC_FINI( l, sizeof(fd_replay_tile_ctx_t) );

  if( FD_UNLIKELY( out_fds_cnt<2UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  out_fds[ out_cnt++ ] = ctx->blockstore_fd;
  return out_cnt;
}

static inline void
metrics_write( fd_replay_tile_ctx_t * ctx ) {
  FD_MGAUGE_SET( REPLAY, LAST_VOTED_SLOT, ctx->metrics.last_voted_slot );
  FD_MGAUGE_SET( REPLAY, SLOT, ctx->metrics.slot );
}

/* TODO: This is definitely not correct */
#define STEM_BURST (1UL)

#define STEM_CALLBACK_CONTEXT_TYPE  fd_replay_tile_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_replay_tile_ctx_t)

#define STEM_CALLBACK_DURING_HOUSEKEEPING during_housekeeping
#define STEM_CALLBACK_BEFORE_FRAG         before_frag
#define STEM_CALLBACK_AFTER_CREDIT        after_credit
#define STEM_CALLBACK_DURING_FRAG         during_frag
#define STEM_CALLBACK_AFTER_FRAG          after_frag
#define STEM_CALLBACK_METRICS_WRITE       metrics_write

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_replay = {
    .name                     = "replay",
    .loose_footprint          = loose_footprint,
    .populate_allowed_seccomp = populate_allowed_seccomp,
    .populate_allowed_fds     = populate_allowed_fds,
    .scratch_align            = scratch_align,
    .scratch_footprint        = scratch_footprint,
    .privileged_init          = privileged_init,
    .unprivileged_init        = unprivileged_init,
    .run                      = stem_run,
};
