#define _GNU_SOURCE

#include "../../../../disco/fd_disco.h"
#include "../../../../disco/keyguard/fd_keyload.h"
#include "../../../../disco/tiles.h"
#include "../../../../disco/shred/fd_shred_dest.h"
#include "../../../../disco/topo/fd_pod_format.h"
#include "../../../../flamenco/fd_flamenco.h"
#include "../../../../flamenco/runtime/fd_txncache.h"
#include "../../../../flamenco/runtime/context/fd_capture_ctx.h"
#include "../../../../flamenco/runtime/context/fd_exec_epoch_ctx.h"
#include "../../../../flamenco/runtime/context/fd_exec_slot_ctx.h"
#include "../../../../flamenco/runtime/fd_borrowed_account.h"
#include "../../../../flamenco/runtime/fd_executor.h"
#include "../../../../flamenco/runtime/fd_hashes.h"
#include "../../../../flamenco/runtime/program/fd_bpf_program_util.h"
#include "../../../../flamenco/runtime/program/fd_builtin_programs.h"
#include "../../../../flamenco/runtime/sysvar/fd_sysvar_epoch_schedule.h"
#include "../../../../flamenco/runtime/sysvar/fd_sysvar_slot_history.h"
#include "../../../../flamenco/runtime/sysvar/fd_sysvar_recent_hashes.h"
#include "../../../../flamenco/runtime/fd_runtime_init.h"
#include "../../../../flamenco/snapshot/fd_snapshot.h"
#include "../../../../flamenco/stakes/fd_stakes.h"
#include "../../../../flamenco/runtime/fd_runtime.h"
#include "../../../../util/fd_util.h"
#include "../../../../util/tile/fd_tile_private.h"
#include "../../../../util/net/fd_net_headers.h"
#include "fd_replay_notif.h"
#include "generated/replay_seccomp.h"
#include "../../../../disco/restart/fd_restart.h"
#include "../../../../disco/metrics/fd_metrics.h"
#include "../../../../choreo/fd_choreo.h"
#include "../../../../disco/store/fd_epoch_forks.h"
#include "../../../../funk/fd_funk_filemap.h"
#include "../../../../flamenco/snapshot/fd_snapshot_create.h"
#include "../../../../disco/plugin/fd_plugin.h"

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
#define GOSSIP_IN_IDX  (2UL)
#define BATCH_IN_IDX   (3UL)

#define STAKE_OUT_IDX  (0UL)
#define NOTIF_OUT_IDX  (1UL)
#define SENDER_OUT_IDX (2UL)
#define GOSSIP_OUT_IDX (3UL)
#define STORE_OUT_IDX  (4UL)
#define POH_OUT_IDX    (5UL)
#define REPLAY_PLUG_OUT_IDX (6UL)
#define VOTES_PLUG_OUT_IDX (7UL)

/* Scratch space estimates.
   TODO: Update constants and add explanation
*/
#define SCRATCH_MAX    (1024UL /*MiB*/ << 21)
#define SCRATCH_DEPTH  (128UL) /* 128 scratch frames */
#define TPOOL_WORKER_MEM_SZ (1UL<<30UL) /* 256MB */

#define VOTE_ACC_MAX   (2000000UL)

#define BANK_HASH_CMP_LG_MAX 16

struct fd_replay_out_ctx {
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

struct fd_replay_tile_ctx {
  fd_wksp_t * wksp;
  fd_wksp_t * blockstore_wksp;
  fd_wksp_t * funk_wksp;
  fd_wksp_t * status_cache_wksp;

  // Store tile input
  fd_wksp_t * store_in_mem;
  ulong       store_in_chunk0;
  ulong       store_in_wmark;

  // Pack tile input
  fd_wksp_t * pack_in_mem;
  ulong       pack_in_chunk0;
  ulong       pack_in_wmark;

  // Gossip tile input for wen-restart
  fd_wksp_t * gossip_in_mem;
  ulong       gossip_in_chunk0;
  ulong       gossip_in_wmark;

  // Batch tile input for epoch account hash
  fd_wksp_t * batch_in_mem;
  ulong       batch_in_chunk0;
  ulong       batch_in_wmark;

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

  // Gossip tile output defs for wen-restart
  fd_frag_meta_t * gossip_out_mcache;
  ulong *          gossip_out_sync;
  ulong            gossip_out_depth;
  ulong            gossip_out_seq;

  fd_wksp_t * gossip_out_mem;
  ulong       gossip_out_chunk0;
  ulong       gossip_out_wmark;
  ulong       gossip_out_chunk;

  // Store tile output defs for wen-restart
  fd_frag_meta_t * store_out_mcache;
  ulong *          store_out_sync;
  ulong            store_out_depth;
  ulong            store_out_seq;

  fd_wksp_t * store_out_mem;
  ulong       store_out_chunk0;
  ulong       store_out_wmark;
  ulong       store_out_chunk;

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

  fd_wksp_t * replay_plugin_out_mem;
  ulong       replay_plugin_out_chunk0;
  ulong       replay_plugin_out_wmark;
  ulong       replay_plugin_out_chunk;

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

  fd_pubkey_t validator_identity[1];
  fd_pubkey_t vote_authority[1];
  fd_pubkey_t vote_acc[1];

  /* Vote accounts in the current epoch. Lifetimes of the vote account
     addresses (pubkeys) are valid for the epoch (the pubkey memory is
     owned by the epoch bank). */

  fd_voter_t *          epoch_voters; /* map chain of slot->voter */
  fd_bank_hash_cmp_t *  bank_hash_cmp;

  /* Tpool */

  uchar        tpool_mem[FD_TPOOL_FOOTPRINT( FD_TILE_MAX )] __attribute__( ( aligned( FD_TPOOL_ALIGN ) ) );
  fd_tpool_t * tpool;

  /* Depends on store_int and is polled in after_credit */

  fd_blockstore_t * blockstore;
  int               blockstore_fd; /* file descriptor for archival file */

  /* Updated during execution */

  fd_exec_slot_ctx_t *  slot_ctx;

  /* Metadata updated during execution */

  ulong     curr_slot;
  ulong     parent_slot;
  ulong     snapshot_slot;
  fd_hash_t blockhash;
  ulong     flags;
  ulong     txn_cnt;
  ulong     bank_idx;

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
  fd_replay_out_ctx_t bank_out[ FD_PACK_MAX_BANK_TILES ];

  ulong root; /* the root slot is the most recent slot to have reached
                 max lockout in the tower  */

  ulong * wmk; /* publish watermark. The watermark is defined as the
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

  int            in_wen_restart;
  fd_restart_t * restart;
  int            tower_checkpt_fileno;
  fd_pubkey_t    restart_coordinator;
  void *         restart_gossip_msg[ FD_RESTART_LINK_BYTES_MAX+sizeof(uint) ];

  int         vote;
  fd_pubkey_t validator_identity_pubkey[ 1 ];
  fd_pubkey_t vote_acct_addr[ 1 ];

  fd_txncache_t * status_cache;
  void * bmtree[ FD_PACK_MAX_BANK_TILES ];

  fd_epoch_forks_t epoch_forks[1];

  fd_spad_t * spads[ 128UL ];
  ulong       spad_cnt;

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
  l = FD_LAYOUT_APPEND( l, FD_ACC_MGR_ALIGN, FD_ACC_MGR_FOOTPRINT );
  l = FD_LAYOUT_APPEND( l, FD_CAPTURE_CTX_ALIGN, FD_CAPTURE_CTX_FOOTPRINT );
  l = FD_LAYOUT_APPEND( l, fd_exec_epoch_ctx_align(), MAX_EPOCH_FORKS * fd_exec_epoch_ctx_footprint( VOTE_ACC_MAX ) );
  l = FD_LAYOUT_APPEND( l, fd_epoch_align(), fd_epoch_footprint( FD_VOTER_MAX ) );
  l = FD_LAYOUT_APPEND( l, fd_forks_align(), fd_forks_footprint( FD_BLOCK_MAX ) );
  l = FD_LAYOUT_APPEND( l, fd_ghost_align(), fd_ghost_footprint( FD_BLOCK_MAX ) );
  l = FD_LAYOUT_APPEND( l, fd_tower_align(), fd_tower_footprint() );
  l = FD_LAYOUT_APPEND( l, fd_bank_hash_cmp_align(), fd_bank_hash_cmp_footprint( ) );
  for( ulong i = 0UL; i<FD_PACK_MAX_BANK_TILES; i++ ) {
    l = FD_LAYOUT_APPEND( l, FD_BMTREE_COMMIT_ALIGN, FD_BMTREE_COMMIT_FOOTPRINT(0) );
  }
  l = FD_LAYOUT_APPEND( l, FD_SCRATCH_ALIGN_DEFAULT, tile->replay.tpool_thread_count * TPOOL_WORKER_MEM_SZ );
  ulong  thread_spad_size    = fd_spad_footprint( FD_RUNTIME_TRANSACTION_EXECUTION_FOOTPRINT_DEFAULT );
  l = FD_LAYOUT_APPEND( l, fd_spad_align(), tile->replay.tpool_thread_count * fd_ulong_align_up( thread_spad_size, fd_spad_align() ) );
  l = FD_LAYOUT_APPEND( l, fd_scratch_smem_align(), fd_scratch_smem_footprint( SCRATCH_MAX   ) );
  l = FD_LAYOUT_APPEND( l, fd_scratch_fmem_align(), fd_scratch_fmem_footprint( SCRATCH_DEPTH ) );
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

static void FD_FN_UNUSED
fd_exec_packed_txns_task( void *tpool,
                          ulong t0 FD_PARAM_UNUSED, ulong t1 FD_PARAM_UNUSED,
                          void *args FD_PARAM_UNUSED,
                          void *reduce FD_PARAM_UNUSED, ulong stride FD_PARAM_UNUSED,
                          ulong l0 FD_PARAM_UNUSED, ulong l1 FD_PARAM_UNUSED,
                          ulong m0 FD_PARAM_UNUSED, ulong m1 FD_PARAM_UNUSED,
                          ulong n0 FD_PARAM_UNUSED, ulong n1 FD_PARAM_UNUSED ) {
  fd_txn_p_t * txns = (fd_txn_p_t *)tpool;
  fd_exec_slot_ctx_t * slot_ctx = (fd_exec_slot_ctx_t *)args;
  fd_capture_ctx_t * capture_ctx = (fd_capture_ctx_t *)reduce;
  ulong txn_cnt = t0;
  ulong curr_slot = t1;
  ulong flags = l0;
  ulong seq = l1;
  ulong * bank_busy = (ulong *)m0;
  fd_replay_out_ctx_t * bank_out = (fd_replay_out_ctx_t *)m1;
  void * bmtree = (void *)n0;
  fd_spad_t * spad = (fd_spad_t *)n1;

  fd_runtime_process_txns( slot_ctx, spad, capture_ctx, txns, txn_cnt );

  fd_microblock_trailer_t * microblock_trailer = (fd_microblock_trailer_t *)(txns + txn_cnt);

  hash_transactions( bmtree, txns, txn_cnt, microblock_trailer->hash );

  ulong sig = fd_disco_replay_sig( curr_slot, flags );
  fd_mcache_publish( bank_out->mcache, bank_out->depth, bank_out->seq, sig, bank_out->chunk, txn_cnt, 0UL, 0UL, 0UL );
  bank_out->chunk = fd_dcache_compact_next( bank_out->chunk, (txn_cnt * sizeof(fd_txn_p_t)) + sizeof(fd_microblock_trailer_t), bank_out->chunk0, bank_out->wmark );
  bank_out->seq = fd_seq_inc( bank_out->seq, 1UL );

  /* Indicate to pack tile we are done processing the transactions so it
     can pack new microblocks using these accounts.  DO NOT USE THE
     SANITIZED TRANSACTIONS AFTER THIS POINT, THEY ARE NO LONGER VALID. */
  fd_fseq_update( bank_busy, seq );
}

void
publish_stake_weights( fd_replay_tile_ctx_t * ctx,
                       fd_stem_context_t *    stem,
                       fd_exec_slot_ctx_t *   slot_ctx ) {
  fd_epoch_bank_t * epoch_bank = fd_exec_epoch_ctx_epoch_bank( slot_ctx->epoch_ctx );
  if( slot_ctx->slot_bank.epoch_stakes.vote_accounts_root!=NULL ) {
    ulong * stake_weights_msg         = fd_chunk_to_laddr( ctx->stake_weights_out_mem, ctx->stake_weights_out_chunk );
    fd_stake_weight_t * stake_weights = (fd_stake_weight_t *)&stake_weights_msg[5];
    ulong stake_weight_idx            = fd_stake_weights_by_node( &ctx->slot_ctx->slot_bank.epoch_stakes, stake_weights );

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
    ulong stake_weight_idx            = fd_stake_weights_by_node( &epoch_bank->next_epoch_stakes, stake_weights );

    stake_weights_msg[0] = fd_slot_to_leader_schedule_epoch( &epoch_bank->epoch_schedule, slot_ctx->slot_bank.slot ); /* epoch */
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

static void
during_frag( fd_replay_tile_ctx_t * ctx,
             ulong                  in_idx,
             ulong                  seq,
             ulong                  sig,
             ulong                  chunk,
             ulong                  sz ) {
  (void)seq;

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

    ctx->curr_slot = fd_disco_replay_sig_slot( sig );
    if( FD_UNLIKELY( ctx->curr_slot < fd_fseq_query( ctx->wmk ) ) ) {
      FD_LOG_WARNING(( "store sent slot %lu before our root.", ctx->curr_slot ));
    }
    ctx->flags = fd_disco_replay_sig_flags( sig );
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
    if( FD_UNLIKELY( ctx->curr_slot < fd_fseq_query( ctx->wmk ) ) ) {
      FD_LOG_WARNING(( "pack sent slot %lu before our watermark %lu.", ctx->curr_slot, fd_fseq_query( ctx->wmk ) ));
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
  } else if( in_idx==GOSSIP_IN_IDX ) {
    if( FD_UNLIKELY( chunk<ctx->gossip_in_chunk0 || chunk>ctx->gossip_in_wmark || sz>FD_RESTART_LINK_BYTES_MAX+sizeof(uint) ) ) {
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->gossip_in_chunk0, ctx->gossip_in_wmark ));
    }

    if( FD_LIKELY( ctx->in_wen_restart ) ) {
      fd_memcpy( ctx->restart_gossip_msg, fd_chunk_to_laddr( ctx->gossip_in_mem, chunk ), sz );
    } else {
      FD_LOG_WARNING(( "Received a gossip message for wen-restart while FD is not in wen-restart mode" ));
    }
    return;
  } else if( in_idx==BATCH_IN_IDX ) {
    uchar * src = (uchar *)fd_chunk_to_laddr( ctx->batch_in_mem, chunk );
    fd_memcpy( ctx->slot_ctx->slot_bank.epoch_account_hash.uc, src, sizeof(fd_hash_t) );
    FD_LOG_NOTICE(( "Epoch account hash calculated to be %s", FD_BASE58_ENC_32_ALLOCA( ctx->slot_ctx->slot_bank.epoch_account_hash.uc ) ));
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

  fd_blockstore_start_read( ctx->blockstore );
  fd_block_map_t * block_map_entry = fd_blockstore_block_map_query( ctx->blockstore, ctx->curr_slot );
  if( FD_LIKELY( block_map_entry ) ) {
    if( FD_UNLIKELY( fd_uchar_extract_bit( block_map_entry->flags, FD_BLOCK_FLAG_PROCESSED ) ) ) {
      FD_LOG_WARNING(( "block already processed - slot: %lu", ctx->curr_slot ));
      ctx->skip_frag = 1;
    }
    if( FD_UNLIKELY( fd_uchar_extract_bit( block_map_entry->flags, FD_BLOCK_FLAG_DEADBLOCK ) ) ) {
      FD_LOG_WARNING(( "block already dead - slot: %lu", ctx->curr_slot ));
      ctx->skip_frag = 1;
    }
  }

  fd_blockstore_end_read( ctx->blockstore );
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
  fd_blockstore_start_read( ctx->blockstore );
  fd_hash_t const * root_block_hash = fd_blockstore_block_hash_query( ctx->blockstore, mismatch_slot );
  fd_funk_txn_xid_t xid;
  memcpy( xid.uc, root_block_hash, sizeof( fd_funk_txn_xid_t ) );
  fd_blockstore_end_read( ctx->blockstore );

  fd_funk_start_write( ctx->funk );
  xid.ul[0]                    = mismatch_slot;
  fd_funk_txn_t * txn_map      = fd_funk_txn_map( ctx->funk, fd_funk_wksp( ctx->funk ) );
  fd_funk_txn_t * mismatch_txn = fd_funk_txn_query( &xid, txn_map );
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
blockstore_publish( fd_replay_tile_ctx_t * ctx, ulong wmk ) {
  fd_blockstore_start_write( ctx->blockstore );
  fd_blockstore_publish( ctx->blockstore, ctx->blockstore_fd, wmk );
  fd_blockstore_end_write( ctx->blockstore );
}

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
  fd_stem_publish( stem, REPLAY_PLUG_OUT_IDX, sig, ctx->replay_plugin_out_chunk, data_sz, 0UL, 0UL, tspub );
  ctx->replay_plugin_out_chunk = fd_dcache_compact_next( ctx->replay_plugin_out_chunk, data_sz, ctx->replay_plugin_out_chunk0, ctx->replay_plugin_out_wmark );
}

static void
publish_slot_notifications( fd_replay_tile_ctx_t * ctx,
                            fd_stem_context_t *    stem,
                            fd_fork_t *            fork,
                            fd_block_map_t const * block_map_entry,
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
    msg->slot_exec.root = ctx->blockstore->smr;
    msg->slot_exec.height = ( block_map_entry ? block_map_entry->height : 0UL );
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
  fd_blockstore_start_read( ctx->blockstore );
  fd_hash_t const * vote_bank_hash  = fd_blockstore_bank_hash_query( ctx->blockstore, vote_slot );
  fd_hash_t const * vote_block_hash = fd_blockstore_block_hash_query( ctx->blockstore, vote_slot );

  if( vote_bank_hash==NULL ) {
    FD_LOG_WARNING(("no vote bank hash found"));
    fd_blockstore_end_read( ctx->blockstore );
    return;
  }

  if( vote_block_hash==NULL ) {
    FD_LOG_WARNING(("no vote block hash found"));
    fd_blockstore_end_read( ctx->blockstore );
    return;
  }

  fd_blockstore_end_read( ctx->blockstore );

  /* Build a vote state update based on current tower votes. */

  FD_SCRATCH_SCOPE_BEGIN {
    fd_txn_p_t * txn = (fd_txn_p_t *)fd_chunk_to_laddr( ctx->sender_out_mem, ctx->sender_out_chunk );
    fd_tower_to_vote_txn( ctx->tower, ctx->root, vote_bank_hash, vote_block_hash, ctx->validator_identity, ctx->vote_authority, ctx->vote_acc, txn );
  } FD_SCRATCH_SCOPE_END;

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
  if( FD_LIKELY( ctx->tower_checkpt_fileno > 0 ) ) fd_restart_tower_checkpt( vote_bank_hash, ctx->tower, ctx->root, ctx->tower_checkpt_fileno );
}

static fd_fork_t *
prepare_new_block_execution( fd_replay_tile_ctx_t * ctx,
                             fd_stem_context_t *    stem,
                             ulong                  curr_slot,
                             ulong                  flags ) {
  long prepare_time_ns = -fd_log_wallclock();

  int is_new_epoch_in_new_block = 0;
  fd_fork_t * fork = fd_forks_prepare( ctx->forks, ctx->parent_slot, ctx->acc_mgr, ctx->blockstore, ctx->epoch_ctx, ctx->funk, ctx->valloc );
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

  fork->slot_ctx.slot_bank.prev_slot   = fork->slot_ctx.slot_bank.slot;
  fork->slot_ctx.slot_bank.slot        = curr_slot;
  fork->slot_ctx.slot_bank.tick_height = fork->slot_ctx.slot_bank.max_tick_height;
  if( FD_UNLIKELY( FD_RUNTIME_EXECUTE_SUCCESS != fd_runtime_compute_max_tick_height( epoch_bank->ticks_per_slot, curr_slot, &fork->slot_ctx.slot_bank.max_tick_height ) ) ) {
    FD_LOG_ERR(( "couldn't compute tick height/max tick height slot %lu ticks_per_slot %lu", curr_slot, epoch_bank->ticks_per_slot ));
  }
  fork->slot_ctx.enable_exec_recording = ctx->tx_metadata_storage;

  if( fd_runtime_is_epoch_boundary( epoch_bank, fork->slot_ctx.slot_bank.slot, fork->slot_ctx.slot_bank.prev_slot ) ) {
    FD_LOG_WARNING(("Epoch boundary"));

    fd_epoch_fork_elem_t * epoch_fork = NULL;
    ulong new_epoch = fd_slot_to_epoch( &epoch_bank->epoch_schedule, fork->slot_ctx.slot_bank.slot, NULL );
    uint found = fd_epoch_forks_prepare( ctx->epoch_forks, fork->slot_ctx.slot_bank.prev_slot, new_epoch, &epoch_fork );

    if( FD_UNLIKELY( found ) ) {
      fd_exec_epoch_ctx_bank_mem_clear( epoch_fork->epoch_ctx );
    }
    fd_exec_epoch_ctx_t * prev_epoch_ctx = fork->slot_ctx.epoch_ctx;

    fd_exec_epoch_ctx_from_prev( epoch_fork->epoch_ctx, prev_epoch_ctx );
    fork->slot_ctx.epoch_ctx = epoch_fork->epoch_ctx;
  }

  fork->slot_ctx.status_cache        = ctx->status_cache;

  fd_funk_txn_xid_t xid = { 0 };

  if( flags & REPLAY_FLAG_PACKED_MICROBLOCK ) {
    memset( xid.uc, 0, sizeof(fd_funk_txn_xid_t) );
  } else {
    fd_memcpy(xid.uc, ctx->blockhash.uc, sizeof(fd_funk_txn_xid_t));
  }
  xid.ul[0] = fork->slot_ctx.slot_bank.slot;
  /* push a new transaction on the stack */
  fd_funk_start_write( ctx->funk );
  fork->slot_ctx.funk_txn = fd_funk_txn_prepare(ctx->funk, fork->slot_ctx.funk_txn, &xid, 1);
  fd_funk_end_write( ctx->funk );

  if( FD_UNLIKELY( FD_RUNTIME_EXECUTE_SUCCESS != fd_runtime_block_pre_execute_process_new_epoch( &fork->slot_ctx ) ) ) {
    FD_LOG_ERR(( "couldn't process new epoch" ));
  }

  fd_blockstore_start_read( ctx->blockstore );
  fd_block_t * block = fd_blockstore_block_query( ctx->blockstore, curr_slot );
  fd_blockstore_end_read( ctx->blockstore );
  ulong tick_res = fd_runtime_block_verify_ticks(
    fd_blockstore_block_micro_laddr( ctx->blockstore, block ),
    block->micros_cnt,
    fd_blockstore_block_data_laddr( ctx->blockstore, block ),
    fork->slot_ctx.slot_bank.tick_height,
    fork->slot_ctx.slot_bank.max_tick_height,
    fork->slot_ctx.epoch_ctx->epoch_bank.hashes_per_tick
  );
  if( FD_UNLIKELY( tick_res != FD_BLOCK_OK ) ) {
    FD_LOG_WARNING(( "failed to verify ticks res %lu slot %lu prev_slot %lu", tick_res, curr_slot, fork->slot_ctx.slot_bank.prev_slot ));
  }

  int res = fd_runtime_block_execute_prepare( &fork->slot_ctx );
  if( res != FD_RUNTIME_EXECUTE_SUCCESS ) {
    FD_LOG_ERR(( "block prep execute failed" ));
  }

  /* Read slot history into slot ctx */
  res = fd_sysvar_slot_history_read( &fork->slot_ctx, fork->slot_ctx.valloc, fork->slot_ctx.slot_history );

  if( res != FD_RUNTIME_EXECUTE_SUCCESS ) {
    FD_LOG_ERR(( "slot history read failed" ));
  }

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

  ulong sig = fd_disco_replay_sig( ctx->slot_ctx->slot_bank.slot, REPLAY_FLAG_INIT );
  fd_mcache_publish( bank_out->mcache, bank_out->depth, bank_out->seq, sig, bank_out->chunk, sizeof(fd_poh_init_msg_t), 0UL, 0UL, 0UL );
  bank_out->chunk = fd_dcache_compact_next( bank_out->chunk, sizeof(fd_poh_init_msg_t), bank_out->chunk0, bank_out->wmark );
  bank_out->seq = fd_seq_inc( bank_out->seq, 1UL );
  ctx->poh_init_done = 1;
}

static void
after_frag( fd_replay_tile_ctx_t * ctx,
            ulong                  in_idx,
            ulong                  seq,
            ulong                  sig,
            ulong                  sz,
            ulong                  tsorig,
            fd_stem_context_t *    stem ) {
  (void)sig;
  (void)sz;

  if( FD_UNLIKELY( in_idx==GOSSIP_IN_IDX ) ) {
    if( FD_UNLIKELY( !ctx->in_wen_restart ) ) return;

    ulong heaviest_fork_found = 0;
    fd_restart_recv_gossip_msg( ctx->restart, ctx->restart_gossip_msg, &heaviest_fork_found );
    if( FD_UNLIKELY( heaviest_fork_found ) ) {
      ulong need_repair = 0;
      fd_restart_find_heaviest_fork_bank_hash( ctx->restart, ctx->funk, &need_repair );
      if( FD_LIKELY( need_repair ) ) {
        /* Send the heaviest fork slot to the store tile for repair and replay */
        uchar * buf = fd_chunk_to_laddr( ctx->store_out_mem, ctx->store_out_chunk );
        FD_STORE( ulong, buf, ctx->restart->heaviest_fork_slot );
        FD_STORE( ulong, buf+sizeof(ulong), ctx->restart->funk_root );
        fd_mcache_publish( ctx->store_out_mcache, ctx->store_out_depth, ctx->store_out_seq, 1UL, ctx->store_out_chunk,
                           sizeof(ulong)*2, 0UL, 0, 0 );
        ctx->store_out_seq   = fd_seq_inc( ctx->store_out_seq, 1UL );
        ctx->store_out_chunk = fd_dcache_compact_next( ctx->store_out_chunk, sizeof(ulong)*2, ctx->store_out_chunk0, ctx->store_out_wmark );
      }
    }
    return;
  }

  if( FD_UNLIKELY( ctx->skip_frag ) ) return;

  ulong curr_slot   = ctx->curr_slot;
  ulong parent_slot = ctx->parent_slot;
  ulong flags       = ctx->flags;
  ulong bank_idx    = ctx->bank_idx;
  if( FD_UNLIKELY( curr_slot < fd_fseq_query( ctx->wmk ) ) ) {
    FD_LOG_WARNING(( "ignoring replay of slot %lu (parent: %lu). earlier than our watermark %lu.", curr_slot, parent_slot, fd_fseq_query( ctx->wmk ) ));
    return;
  }

  if( FD_UNLIKELY( parent_slot < fd_fseq_query( ctx->wmk ) ) ) {
    FD_LOG_WARNING(( "ignoring replay of slot %lu (parent: %lu). parent slot is earlier than our watermark %lu.", curr_slot, parent_slot, fd_fseq_query( ctx->wmk ) ) );
    return;
  }

  fd_blockstore_start_read( ctx->blockstore );
  fd_block_map_t * parent_block_map_entry = fd_blockstore_block_map_query( ctx->blockstore, parent_slot );
  fd_blockstore_end_read( ctx->blockstore );
  if( FD_UNLIKELY( !parent_block_map_entry ) ) {
    FD_LOG_WARNING(( "[%s] unable to find slot %lu's parent block_map_entry", __func__, curr_slot ));
    return;
  }

  fd_replay_out_ctx_t * bank_out = &ctx->bank_out[ bank_idx ];

  /* do a replay */

  ulong        txn_cnt    = ctx->txn_cnt;
  fd_txn_p_t * txns       = (fd_txn_p_t *)fd_chunk_to_laddr( bank_out->mem, bank_out->chunk );

  ulong epoch_ctx_idx = fd_epoch_forks_get_epoch_ctx( ctx->epoch_forks, ctx->ghost, curr_slot, &ctx->parent_slot );
  ctx->epoch_ctx = ctx->epoch_forks->forks[ epoch_ctx_idx ].epoch_ctx;


  /* This is an edge case related to pack. The parent fork might
      already be in the frontier and currently executing (ie.
      fork->frozen = 0). */

  fd_fork_t * parent_fork = fd_fork_frontier_ele_query( ctx->forks->frontier, &ctx->parent_slot, NULL, ctx->forks->pool );
  if( FD_UNLIKELY( parent_fork && parent_fork->lock ) ) {
    FD_LOG_ERR(
        ( "parent slot is frozen in frontier. cannot execute. slot: %lu, parent_slot: %lu",
          curr_slot,
          ctx->parent_slot ) );
  }

  fd_fork_t * fork = fd_fork_frontier_ele_query( ctx->forks->frontier, &curr_slot, NULL, ctx->forks->pool );

  if( fork == NULL ) {
    fork = prepare_new_block_execution( ctx, stem, curr_slot, flags );
  }

  if( ctx->capture_ctx )
    fd_solcap_writer_set_slot( ctx->capture_ctx->capture, fork->slot_ctx.slot_bank.slot );
  // Execute all txns which were successfully prepared
  long execute_time_ns = -fd_log_wallclock();

    int res = 0UL;
    FD_SCRATCH_SCOPE_BEGIN {
      if( flags & REPLAY_FLAG_PACKED_MICROBLOCK ) {
        // FD_LOG_WARNING(("MBLK4: %lu %lu %lu", ctx->curr_slot, seq, bank_idx+1));
        fd_tpool_wait( ctx->tpool, bank_idx+1 );

        fd_tpool_exec( ctx->tpool, bank_idx+1, fd_exec_packed_txns_task, txns, txn_cnt, curr_slot, &fork->slot_ctx, ctx->capture_ctx, 0UL, flags, seq, (ulong)ctx->bank_busy[ bank_idx ], (ulong)&ctx->bank_out[ bank_idx ], (ulong)ctx->bmtree[ bank_idx ], (ulong)ctx->spads[ bank_idx ] );
      } else {
        for( ulong i = 0UL; i<ctx->bank_cnt; i++ ) {
          fd_tpool_wait( ctx->tpool, i+1 );
        }
        res = fd_runtime_process_txns_in_waves_tpool( &fork->slot_ctx,
                                                      ctx->capture_ctx,
                                                      txns,
                                                      txn_cnt,
                                                      ctx->tpool,
                                                      ctx->spads,
                                                      ctx->spad_cnt );
      }
    } FD_SCRATCH_SCOPE_END;

    // Notify for all the updated accounts
    publish_account_notifications( ctx, fork, curr_slot, txns, txn_cnt );

    execute_time_ns += fd_log_wallclock();
    FD_LOG_DEBUG(("TIMING: execute_time - slot: %lu, elapsed: %6.6f ms", curr_slot, (double)execute_time_ns * 1e-6));

    if( res != 0UL && !( flags & REPLAY_FLAG_PACKED_MICROBLOCK ) ) {
      FD_LOG_WARNING(( "block invalid - slot: %lu", curr_slot ));

      fd_blockstore_start_write( ctx->blockstore );

      fd_block_map_t * block_map_entry = fd_blockstore_block_map_query( ctx->blockstore, curr_slot );
      fd_block_t * block_ = fd_blockstore_block_query( ctx->blockstore, curr_slot );


      if( FD_LIKELY( block_ ) ) {
        block_map_entry->flags = fd_uchar_set_bit( block_map_entry->flags, FD_BLOCK_FLAG_DEADBLOCK );
        FD_COMPILER_MFENCE();
        block_map_entry->flags = fd_uchar_clear_bit( block_map_entry->flags, FD_BLOCK_FLAG_REPLAYING );
        memcpy( &block_map_entry->bank_hash, &fork->slot_ctx.slot_bank.banks_hash, sizeof( fd_hash_t ) );
      }

      fd_blockstore_end_write( ctx->blockstore );

      return;
    }

    if( flags & REPLAY_FLAG_FINISHED_BLOCK ) {
      fork->slot_ctx.txn_count = fork->slot_ctx.slot_bank.transaction_count-fork->slot_ctx.parent_transaction_count;
      FD_LOG_INFO(( "finished block - slot: %lu, parent_slot: %lu, txn_cnt: %lu, blockhash: %s",
                    curr_slot,
                    ctx->parent_slot,
                    fork->slot_ctx.txn_count,
                    FD_BASE58_ENC_32_ALLOCA( ctx->blockhash.uc ) ));
      // Copy over latest blockhash to slot_bank poh for updating the sysvars
      fd_memcpy( fork->slot_ctx.slot_bank.poh.uc, ctx->blockhash.uc, sizeof(fd_hash_t) );
      fd_block_info_t block_info[1];
      block_info->signature_cnt = fork->slot_ctx.signature_cnt;
      // long finalize_time_ns = -fd_log_wallclock();
      /* destroy the slot history */
      fd_bincode_destroy_ctx_t destroy_ctx = {
        .valloc = fork->slot_ctx.valloc,
      };
      fd_slot_history_destroy( fork->slot_ctx.slot_history, &destroy_ctx );
      for( ulong i = 0UL; i<ctx->bank_cnt; i++ ) {
        fd_tpool_wait( ctx->tpool, i+1 );
      }

      fd_blockstore_start_read( ctx->blockstore );
      fd_block_map_t * block_map_entry = fd_blockstore_block_map_query( ctx->blockstore, curr_slot );
      fd_block_t * block_ = fd_blockstore_block_query( ctx->blockstore, curr_slot );
      fd_blockstore_end_read( ctx->blockstore );
      fork->slot_ctx.block = block_;

      int res = fd_runtime_block_execute_finalize_tpool( &fork->slot_ctx, ctx->capture_ctx, block_info, ctx->tpool );

      if( res != FD_RUNTIME_EXECUTE_SUCCESS ) {
        FD_LOG_ERR(( "block finished failed" ));
      }

      // Notify for updated slot info
      publish_slot_notifications( ctx, stem, fork, block_map_entry, curr_slot );

      fd_blockstore_start_write( ctx->blockstore );

      if( FD_LIKELY( block_ ) ) {
        block_map_entry->flags = fd_uchar_set_bit( block_map_entry->flags, FD_BLOCK_FLAG_PROCESSED );
        block_map_entry->flags = fd_uchar_clear_bit( block_map_entry->flags, FD_BLOCK_FLAG_REPLAYING );
        ctx->blockstore->lps   = block_map_entry->slot;
        memcpy( &block_map_entry->bank_hash, &fork->slot_ctx.slot_bank.banks_hash, sizeof( fd_hash_t ) );
      }

      fd_blockstore_end_write( ctx->blockstore );

      fork->lock = 0;
      // Remove slot ctx from frontier once block is finalized
      fd_fork_t * child = fd_fork_frontier_ele_remove( ctx->forks->frontier, &fork->slot, NULL, ctx->forks->pool );
      child->slot = curr_slot;
      if( FD_UNLIKELY( fd_fork_frontier_ele_query(
          ctx->forks->frontier, &curr_slot, NULL, ctx->forks->pool ) ) ) {
        FD_LOG_ERR( ( "invariant violation: child slot %lu was already in the frontier", curr_slot ) );
      }
      fd_fork_frontier_ele_insert( ctx->forks->frontier, child, ctx->forks->pool );

      /* Consensus */

      FD_PARAM_UNUSED long tic_ = fd_log_wallclock();
      fd_ghost_node_t const * ghost_node = fd_ghost_insert( ctx->ghost, parent_slot, curr_slot );
      #if FD_GHOST_USE_HANDHOLDING
      if( FD_UNLIKELY( !ghost_node ) ) {
        FD_LOG_ERR(( "failed to insert ghost node %lu", fork->slot ));
      }
      #endif
      fd_forks_update( ctx->forks, ctx->blockstore, ctx->epoch, ctx->funk, ctx->ghost, fork->slot );

      /* Check which fork to reset to for pack. */

      ulong reset_slot = fd_tower_reset_slot( ctx->tower, ctx->epoch, ctx->ghost );
      fd_fork_t const * reset_fork = fd_forks_query_const( ctx->forks, reset_slot );
      if( FD_UNLIKELY( !reset_fork ) ) {
        FD_LOG_ERR( ( "failed to find reset fork %lu", reset_slot ) );
      }
      if( reset_fork->lock ) {
        FD_LOG_WARNING(("RESET FORK FROZEN: %lu", reset_fork->slot ));
        fd_fork_t * new_reset_fork = fd_forks_prepare( ctx->forks, reset_fork->slot_ctx.slot_bank.prev_slot, ctx->acc_mgr,
            ctx->blockstore, ctx->epoch_ctx, ctx->funk, ctx->valloc );
        new_reset_fork->lock = 0;
        reset_fork = new_reset_fork;
      }

      /* Update the gui */

      if( ctx->replay_plugin_out_mem ) {
        /* FIXME. We need a more efficient way to compute the ancestor chain. */
        uchar msg[4098*8] __attribute__( ( aligned( 8U ) ) );
        fd_memset( msg, 0, sizeof(msg) );
        fd_blockstore_start_read( ctx->blockstore );
        ulong s = reset_fork->slot_ctx.slot_bank.slot;
        *(ulong*)(msg + 16U) = s;
        ulong i = 0;
        do {
          block_map_entry = fd_blockstore_block_map_query( ctx->blockstore, s );
          if( block_map_entry == NULL ) {
            break;
          }
          s = block_map_entry->parent_slot;
          if( s < ctx->blockstore->smr ) {
            break;
          }
          *(ulong*)(msg + 24U + i*8U) = s;
          if( ++i == 4095U ) {
            break;
          }
        } while( 1 );
        *(ulong*)(msg + 8U) = i;
        fd_blockstore_end_read( ctx->blockstore );
        replay_plugin_publish( ctx, stem, FD_PLUGIN_MSG_SLOT_RESET, msg, sizeof(msg) );
      }

      fd_microblock_trailer_t * microblock_trailer = (fd_microblock_trailer_t *)(txns + txn_cnt);
      memcpy( microblock_trailer->hash, reset_fork->slot_ctx.slot_bank.block_hash_queue.last_hash->uc, sizeof(fd_hash_t) );
      if( ctx->poh_init_done == 1 ) {
        ulong parent_slot = reset_fork->slot_ctx.slot_bank.prev_slot;
        ulong curr_slot = reset_fork->slot_ctx.slot_bank.slot;
        FD_LOG_DEBUG(( "publishing mblk to poh - slot: %lu, parent_slot: %lu, flags: %lx", curr_slot, parent_slot, flags ));
        ulong tspub = fd_frag_meta_ts_comp( fd_tickcount() );
        ulong sig = fd_disco_replay_sig( curr_slot, flags );
        fd_mcache_publish( bank_out->mcache, bank_out->depth, bank_out->seq, sig, bank_out->chunk, txn_cnt, 0UL, tsorig, tspub );
        bank_out->chunk = fd_dcache_compact_next( bank_out->chunk, (txn_cnt * sizeof(fd_txn_p_t)) + sizeof(fd_microblock_trailer_t), bank_out->chunk0, bank_out->wmark );
        bank_out->seq = fd_seq_inc( bank_out->seq, 1UL );
      } else {
        FD_LOG_DEBUG(( "NOT publishing mblk to poh - slot: %lu, parent_slot: %lu, flags: %lx", curr_slot, ctx->parent_slot, flags ));
      }

      fd_forks_print( ctx->forks );
      fd_ghost_print( ctx->ghost, ctx->epoch, fd_ghost_root( ctx-> ghost ) );
      fd_tower_print( ctx->tower, ctx->root );

      ulong vote_slot = fd_tower_vote_slot( ctx->tower, ctx->epoch, ctx->funk, child->slot_ctx.funk_txn, ctx->ghost );

      FD_LOG_NOTICE( ( "\n\n[Fork Selection]\n"
                       "# of vote accounts: %lu\n"
                       "best fork:          %lu\n",
                       fd_epoch_voters_key_cnt( fd_epoch_voters( ctx->epoch ) ),
                       fd_ghost_head( ctx->ghost, fd_ghost_root( ctx->ghost ) )->slot ) );

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

          /* Update to a new root, if there is one. */

          if ( FD_LIKELY ( root != FD_SLOT_NULL ) ) ctx->root = root; /* optimize for full tower (replay is keeping up) */
        }

        /* Send our updated tower to the cluster. */

        send_tower_sync( ctx );
      }

      /* Prepare bank for next execution. */

      ulong prev_slot = child->slot_ctx.slot_bank.slot;
      child->slot_ctx.slot_bank.slot           = curr_slot;
      child->slot_ctx.slot_bank.collected_execution_fees = 0;
      child->slot_ctx.slot_bank.collected_priority_fees = 0;
      child->slot_ctx.slot_bank.collected_rent = 0;

      /* Write to debugging files. */

      if( FD_UNLIKELY( ctx->slots_replayed_file ) ) {
        FD_LOG_DEBUG(( "writing %lu to slots file", prev_slot ));
        fprintf( ctx->slots_replayed_file, "%lu\n", prev_slot );
        fflush( ctx->slots_replayed_file );
      }

      if (NULL != ctx->capture_ctx) {
        fd_solcap_writer_flush( ctx->capture_ctx->capture );
      }

      /* Wen-restart checks whether repair&replay has finished */

      if( FD_UNLIKELY( ctx->in_wen_restart && curr_slot==ctx->restart->heaviest_fork_slot ) ) {
        fd_hash_t const * bank_hash = &child->slot_ctx.slot_bank.banks_hash;
        fd_memcpy( &ctx->restart->heaviest_fork_bank_hash, bank_hash, sizeof(fd_hash_t) );
        ctx->restart->heaviest_fork_ready = 1;
      }

      /* Bank hash cmp */

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
    }

    /* Init PoH if it is ready*/

    if( FD_UNLIKELY( !(flags & REPLAY_FLAG_CATCHING_UP) && ctx->poh_init_done == 0 && ctx->slot_ctx->blockstore ) ) {
      init_poh( ctx );
    }

    /* Publish mblk to POH. */

    if( ctx->poh_init_done == 1 && !( flags & REPLAY_FLAG_FINISHED_BLOCK )
        && ( ( flags & REPLAY_FLAG_MICROBLOCK ) ) ) {
      // FD_LOG_INFO(( "publishing mblk to poh - slot: %lu, parent_slot: %lu", curr_slot, ctx->parent_slot ));
      ulong tspub = fd_frag_meta_ts_comp( fd_tickcount() );
      ulong sig = fd_disco_replay_sig( curr_slot, flags );
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

  fd_blockstore_start_write( ctx->slot_ctx->blockstore );
  fd_blockstore_init( ctx->slot_ctx->blockstore, ctx->blockstore_fd, FD_BLOCKSTORE_ARCHIVE_MIN_SIZE, &ctx->slot_ctx->slot_bank );
  fd_blockstore_end_write( ctx->slot_ctx->blockstore );

  publish_stake_weights( ctx, stem, ctx->slot_ctx );
  fd_fseq_update( ctx->wmk, ctx->slot_ctx->slot_bank.slot );

}

static void
read_snapshot( void * _ctx,
               fd_stem_context_t * stem,
               char const * snapshotfile,
               char const * incremental ) {
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

  const char * snapshot = snapshotfile;
  if( strcmp( snapshot, "funk" ) == 0 || strncmp( snapshot, "wksp:", 5 ) == 0) {
    /* Funk already has a snapshot loaded */
    fd_runtime_recover_banks( ctx->slot_ctx, 0, 1 );
  } else {
    
    /* If we have an incremental snapshot try to prefetch the snapshot slot
       and manifest as soon as possible. In order to kick off repair effectively 
       we need the snapshot slot and the stake weights. These are both available
       in the manifest. We will try to load in the manifest from the latest
       snapshot that is availble, then setup the blockstore and publish the 
       stake weights. After this, repair will kick off concurrently with loading 
       the rest of the snapshots. */

  if( strlen( incremental )>0UL ) {
    uchar *                  tmp_mem      = fd_scratch_alloc( fd_snapshot_load_ctx_align(), fd_snapshot_load_ctx_footprint() );
    fd_snapshot_load_ctx_t * tmp_snap_ctx = fd_snapshot_load_new( tmp_mem, incremental, ctx->slot_ctx, ctx->tpool, false, false, FD_SNAPSHOT_TYPE_FULL );
    fd_snapshot_load_prefetch_manifest( tmp_snap_ctx );
    kickoff_repair_orphans( ctx, stem );
  }

    /* In order to kick off repair effectively we need the snapshot slot and
       the stake weights. These are both available in the manifest. We will
       try to load in the manifest from the latest snapshot that is availble,
       then setup the blockstore and publish the stake weights. After this,
       repair will kick off concurrently with loading the rest of the snapshots. */

    uchar *                  mem      = fd_scratch_alloc( fd_snapshot_load_ctx_align(), fd_snapshot_load_ctx_footprint() );
    fd_snapshot_load_ctx_t * snap_ctx = fd_snapshot_load_new( mem, snapshot, ctx->slot_ctx, ctx->tpool, false, false, FD_SNAPSHOT_TYPE_FULL );
  
    fd_snapshot_load_init( snap_ctx );
    fd_snapshot_load_manifest_and_status_cache( snap_ctx );

    if( strlen( incremental )<=0UL ) {
      /* If we don't have an incremental snapshot, we can still kick off
         sending the stake weights and snapshot slot to repair. */
      kickoff_repair_orphans( ctx, stem );
    }

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

  if( strlen( incremental ) > 0 ) {
    fd_snapshot_load_all( incremental, ctx->slot_ctx, ctx->tpool, false, false, FD_SNAPSHOT_TYPE_INCREMENTAL );
  }

  if( ctx->replay_plugin_out_mem ) {
    // ValidatorStartProgress::DownloadedFullSnapshot
    uchar msg[56];
    fd_memset( msg, 0, sizeof(msg) );
    msg[0] = 3;
    replay_plugin_publish( ctx, stem, FD_PLUGIN_MSG_START_PROGRESS, msg, sizeof(msg) );
  }

  fd_runtime_update_leaders( ctx->slot_ctx, ctx->slot_ctx->slot_bank.slot );
  FD_LOG_NOTICE(( "starting fd_bpf_scan_and_create_bpf_program_cache_entry..." ));
  fd_funk_start_write( ctx->slot_ctx->acc_mgr->funk );
  fd_bpf_scan_and_create_bpf_program_cache_entry_tpool( ctx->slot_ctx, ctx->slot_ctx->funk_txn, ctx->tpool );
  fd_funk_end_write( ctx->slot_ctx->acc_mgr->funk );
  FD_LOG_NOTICE(( "finished fd_bpf_scan_and_create_bpf_program_cache_entry..." ));

  fd_blockstore_start_write( ctx->slot_ctx->blockstore );
  fd_blockstore_init( ctx->slot_ctx->blockstore, ctx->blockstore_fd, FD_BLOCKSTORE_ARCHIVE_MIN_SIZE, &ctx->slot_ctx->slot_bank );
  fd_blockstore_end_write( ctx->slot_ctx->blockstore );
}

static void
init_after_snapshot( fd_replay_tile_ctx_t * ctx ) {
  /* Do not modify order! */

  ulong snapshot_slot = ctx->slot_ctx->slot_bank.slot;
  if( FD_UNLIKELY( !snapshot_slot ) ) {
    fd_runtime_update_leaders(ctx->slot_ctx, ctx->slot_ctx->slot_bank.slot);

    ctx->slot_ctx->slot_bank.prev_slot = 0UL;
    ctx->slot_ctx->slot_bank.slot      = 1UL;

    ulong hashcnt_per_slot = ctx->slot_ctx->epoch_ctx->epoch_bank.hashes_per_tick * ctx->slot_ctx->epoch_ctx->epoch_bank.ticks_per_slot;
    while(hashcnt_per_slot--) {
      fd_sha256_hash( ctx->slot_ctx->slot_bank.poh.uc, 32UL, ctx->slot_ctx->slot_bank.poh.uc );
    }

    FD_TEST( fd_runtime_block_execute_prepare( ctx->slot_ctx ) == 0 );
    fd_block_info_t info = {.signature_cnt = 0 };
    FD_TEST( fd_runtime_block_execute_finalize_tpool( ctx->slot_ctx, NULL, &info, ctx->tpool ) == 0 );

    ctx->slot_ctx->slot_bank.prev_slot = 0UL;
    ctx->slot_ctx->slot_bank.slot      = 1UL;
    snapshot_slot                      = 1UL;

    FD_LOG_NOTICE(( "starting fd_bpf_scan_and_create_bpf_program_cache_entry..." ));
    fd_funk_start_write( ctx->slot_ctx->acc_mgr->funk );
    fd_bpf_scan_and_create_bpf_program_cache_entry_tpool( ctx->slot_ctx, ctx->slot_ctx->funk_txn, ctx->tpool );
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

  if( strlen(ctx->genesis) > 0 ) {
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

  FD_LOG_NOTICE( ( "snapshot slot %lu", snapshot_slot ) );
  FD_LOG_NOTICE( ( "total stake %lu", bank_hash_cmp->total_stake ) );

}

void
init_snapshot( fd_replay_tile_ctx_t * ctx,
               fd_stem_context_t *    stem ) {
  FD_LOG_NOTICE(( "init snapshot" ));
  /* Init slot_ctx */

  fd_exec_slot_ctx_t slot_ctx = { 0 };
  ctx->slot_ctx               = fd_exec_slot_ctx_join( fd_exec_slot_ctx_new( &slot_ctx, ctx->valloc ) );
  ctx->slot_ctx->acc_mgr      = ctx->acc_mgr;
  ctx->slot_ctx->blockstore   = ctx->blockstore;
  ctx->slot_ctx->epoch_ctx    = ctx->epoch_ctx;
  ctx->slot_ctx->status_cache = ctx->status_cache;

  FD_SCRATCH_SCOPE_BEGIN {
    uchar is_snapshot = strlen( ctx->snapshot ) > 0;
    if( is_snapshot ) {
      read_snapshot( ctx, stem, ctx->snapshot, ctx->incremental );
    }

    fd_runtime_read_genesis( ctx->slot_ctx, ctx->genesis, is_snapshot, ctx->capture_ctx, ctx->tpool );
    ctx->epoch_ctx->bank_hash_cmp = ctx->bank_hash_cmp;
    init_after_snapshot( ctx );

  } FD_SCRATCH_SCOPE_END;


  /* Redirect ctx->slot_ctx to point to the memory inside forks. */

  fd_fork_t * fork = fd_forks_query( ctx->forks, ctx->curr_slot );
  ctx->slot_ctx = &fork->slot_ctx;
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
  for( fd_vote_accounts_pair_t_mapnode_t const * n = fd_vote_accounts_pair_t_map_minimum_const( pool, root );
       n && i < FD_CLUSTER_NODE_CNT;
       n = fd_vote_accounts_pair_t_map_successor_const( pool, n ) ) {
    if( n->elem.stake == 0 ) continue;
    fd_vote_update_msg_t * msg = (fd_vote_update_msg_t *)(dst + sizeof(ulong) + i*112U);
    memset( msg, 0, 112U );
    memcpy( msg->vote_pubkey, n->elem.key.uc, sizeof(fd_pubkey_t) );
    memcpy( msg->node_pubkey, n->elem.value.node_pubkey.uc, sizeof(fd_pubkey_t) );
    msg->activated_stake = n->elem.stake;
    msg->last_vote = n->elem.value.last_timestamp_slot;
    msg->is_delinquent = (uchar)(msg->last_vote == 0);
    ++i;
  }

  *(ulong *)dst = i;

  ulong tspub = (ulong)fd_frag_meta_ts_comp( fd_tickcount() );
  fd_stem_publish( stem, VOTES_PLUG_OUT_IDX, FD_PLUGIN_MSG_VOTE_ACCOUNT_UPDATE, ctx->votes_plugin_out_chunk, 0, 0UL, 0UL, tspub );
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
              int *                  opt_poll_in,
              int *                  charge_busy ) {
  (void)opt_poll_in;

  if( FD_UNLIKELY( ctx->snapshot_init_done==0 ) ) {
    init_snapshot( ctx, stem );
    ctx->snapshot_init_done = 1;
    *charge_busy = 1;
    if( FD_UNLIKELY( ctx->in_wen_restart ) ) {
      FD_SCRATCH_SCOPE_BEGIN {
        ulong buf_len = 0;
        uchar * buf = fd_chunk_to_laddr( ctx->gossip_out_mem, ctx->gossip_out_chunk );
        fd_sysvar_slot_history_read( ctx->slot_ctx, fd_scratch_virtual(), ctx->slot_ctx->slot_history );

        fd_epoch_bank_t * epoch_bank = fd_exec_epoch_ctx_epoch_bank( ctx->slot_ctx->epoch_ctx );
        fd_vote_accounts_t const * epoch_stakes[ RESTART_EPOCHS_MAX ] = { &epoch_bank->stakes.vote_accounts,
                                                                          &epoch_bank->next_epoch_stakes };
        fd_restart_init( ctx->restart,
                         ctx->slot_ctx->slot_bank.slot,
                         &ctx->slot_ctx->slot_bank.banks_hash,
                         epoch_stakes,
                         &epoch_bank->epoch_schedule,
                         ctx->tower_checkpt_fileno,
                         ctx->slot_ctx->slot_history,
                         ctx->validator_identity_pubkey,
                         &ctx->restart_coordinator,
                         buf+sizeof(uint),
                         &buf_len );

        /* Send the restart_last_voted_fork_slots message to gossip tile */
        buf_len += sizeof(uint);
        FD_STORE( uint, buf, fd_crds_data_enum_restart_last_voted_fork_slots );
        fd_mcache_publish( ctx->gossip_out_mcache, ctx->gossip_out_depth, ctx->gossip_out_seq, 1UL, ctx->gossip_out_chunk,
                           buf_len, 0UL, 0, 0 );
        ctx->gossip_out_seq   = fd_seq_inc( ctx->gossip_out_seq, 1UL );
        ctx->gossip_out_chunk = fd_dcache_compact_next( ctx->gossip_out_chunk, buf_len, ctx->gossip_out_chunk0, ctx->gossip_out_wmark );
      } FD_SCRATCH_SCOPE_END;
    }

    if( ctx->replay_plugin_out_mem ) {
      // ValidatorStartProgress::Running
      uchar msg[56];
      fd_memset( msg, 0, sizeof(msg) );
      msg[0] = 11;
      replay_plugin_publish( ctx, stem, FD_PLUGIN_MSG_START_PROGRESS, msg, sizeof(msg) );
    }
  }

  if( FD_UNLIKELY( ctx->in_wen_restart ) ) {
    ulong send  = 0;
    uchar * buf = fd_chunk_to_laddr( ctx->gossip_out_mem, ctx->gossip_out_chunk );
    fd_restart_verify_heaviest_fork( ctx->restart, buf+sizeof(uint), &send );

    if( FD_UNLIKELY( send ) ) {
      /* Send the restart_heaviest_fork message to gossip tile */
      ulong buf_len = sizeof(uint) + sizeof(fd_gossip_restart_heaviest_fork_t);
      FD_STORE( uint, buf, fd_crds_data_enum_restart_heaviest_fork );
      fd_mcache_publish( ctx->gossip_out_mcache, ctx->gossip_out_depth, ctx->gossip_out_seq, 1UL, ctx->gossip_out_chunk,
                         buf_len, 0UL, 0, 0 );
      ctx->gossip_out_seq   = fd_seq_inc( ctx->gossip_out_seq, 1UL );
      ctx->gossip_out_chunk = fd_dcache_compact_next( ctx->gossip_out_chunk, buf_len, ctx->gossip_out_chunk0, ctx->gossip_out_wmark );
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
     root and blockstore smr. */

  fd_blockstore_start_read( ctx->blockstore );
  ulong wmk = fd_ulong_min( ctx->root, ctx->blockstore->smr );
  fd_blockstore_end_read( ctx->blockstore );

  if ( FD_LIKELY( wmk <= fd_fseq_query( ctx->wmk ) ) ) return;
  FD_LOG_NOTICE(( "wmk %lu => %lu", fd_fseq_query( ctx->wmk ), wmk ));

  fd_blockstore_start_read( ctx->blockstore );
  fd_hash_t const * root_block_hash = fd_blockstore_block_hash_query( ctx->blockstore, wmk );
  fd_funk_txn_xid_t xid;
  memcpy( xid.uc, root_block_hash, sizeof( fd_funk_txn_xid_t ) );
  fd_blockstore_end_read( ctx->blockstore );
  xid.ul[0] = wmk;

  if( FD_LIKELY( ctx->blockstore ) ) blockstore_publish( ctx, wmk );
  if( FD_LIKELY( ctx->forks ) ) fd_forks_publish( ctx->forks, wmk, ctx->ghost );
  if( FD_LIKELY( ctx->funk ) ) funk_and_txncache_publish( ctx, wmk, &xid );
  if( FD_LIKELY( ctx->ghost ) ) {
    fd_epoch_forks_publish( ctx->epoch_forks, ctx->ghost, wmk );
    fd_ghost_publish( ctx->ghost, wmk );
  }

  fd_fseq_update( ctx->wmk, wmk );


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
                   strcmp( topo->links[ tile->in_link_id[ GOSSIP_IN_IDX ] ].name, "gossip_repla")  || 
                   strcmp( topo->links[ tile->in_link_id[ BATCH_IN_IDX  ] ].name, "batch_replay" ) ) ) {
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
  void * acc_mgr_shmem       = FD_SCRATCH_ALLOC_APPEND( l, FD_ACC_MGR_ALIGN, FD_ACC_MGR_FOOTPRINT );
  void * capture_ctx_mem     = FD_SCRATCH_ALLOC_APPEND( l, FD_CAPTURE_CTX_ALIGN, FD_CAPTURE_CTX_FOOTPRINT );
  void * epoch_ctx_mem       = FD_SCRATCH_ALLOC_APPEND( l, fd_exec_epoch_ctx_align(), MAX_EPOCH_FORKS * fd_exec_epoch_ctx_footprint( VOTE_ACC_MAX ) );
  void * epoch_mem           = FD_SCRATCH_ALLOC_APPEND( l, fd_epoch_align(), fd_epoch_footprint( FD_VOTER_MAX ) );
  void * forks_mem           = FD_SCRATCH_ALLOC_APPEND( l, fd_forks_align(), fd_forks_footprint( FD_BLOCK_MAX ) );
  void * ghost_mem           = FD_SCRATCH_ALLOC_APPEND( l, fd_ghost_align(), fd_ghost_footprint( FD_BLOCK_MAX ) );
  void * tower_mem           = FD_SCRATCH_ALLOC_APPEND( l, fd_tower_align(), fd_tower_footprint() );
  void * bank_hash_cmp_mem   = FD_SCRATCH_ALLOC_APPEND( l, fd_bank_hash_cmp_align(), fd_bank_hash_cmp_footprint( ) );
  for( ulong i = 0UL; i<FD_PACK_MAX_BANK_TILES; i++ ) {
    ctx->bmtree[i]           = FD_SCRATCH_ALLOC_APPEND( l, FD_BMTREE_COMMIT_ALIGN, FD_BMTREE_COMMIT_FOOTPRINT(0) );
  }
  void * tpool_worker_mem    = FD_SCRATCH_ALLOC_APPEND( l, FD_SCRATCH_ALIGN_DEFAULT, tile->replay.tpool_thread_count * TPOOL_WORKER_MEM_SZ );
  ulong  thread_spad_size    = fd_spad_footprint( FD_RUNTIME_TRANSACTION_EXECUTION_FOOTPRINT_DEFAULT );
  void * spad_mem            = FD_SCRATCH_ALLOC_APPEND( l, fd_spad_align(), tile->replay.tpool_thread_count * fd_ulong_align_up( thread_spad_size, fd_spad_align() ) );
  void * scratch_smem        = FD_SCRATCH_ALLOC_APPEND( l, fd_scratch_smem_align(), fd_scratch_smem_footprint( SCRATCH_MAX   ) );
  void * scratch_fmem        = FD_SCRATCH_ALLOC_APPEND( l, fd_scratch_fmem_align(), fd_scratch_fmem_footprint( SCRATCH_DEPTH ) );
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
  ctx->blockstore = NULL;

  ulong blockstore_obj_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "blockstore" );
  FD_TEST( blockstore_obj_id!=ULONG_MAX );
  ctx->blockstore_wksp = topo->workspaces[ topo->objs[ blockstore_obj_id ].wksp_id ].wksp;
  if( ctx->blockstore_wksp==NULL ) {
    FD_LOG_ERR(( "no blockstore wksp" ));
  }

  ctx->blockstore = fd_blockstore_join( fd_topo_obj_laddr( topo, blockstore_obj_id ) );
  FD_TEST( ctx->blockstore!=NULL );

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
  ctx->wmk = fd_fseq_join( fd_topo_obj_laddr( topo, root_slot_obj_id ) );
  if( FD_UNLIKELY( !ctx->wmk ) ) FD_LOG_ERR(( "replay tile has no root_slot fseq" ));
  FD_TEST( ULONG_MAX==fd_fseq_query( ctx->wmk ) );

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
  /* valloc                                                             */
  /**********************************************************************/

  ctx->valloc = fd_alloc_virtual( ctx->alloc );

  /**********************************************************************/
  /* scratch                                                            */
  /**********************************************************************/

  fd_scratch_attach( scratch_smem, scratch_fmem, SCRATCH_MAX, SCRATCH_DEPTH );

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
  /* epoch forks                                                        */
  /**********************************************************************/

  fd_epoch_forks_new( ctx->epoch_forks, epoch_ctx_mem );

  /**********************************************************************/
  /* joins                                                              */
  /**********************************************************************/

  ctx->acc_mgr       = fd_acc_mgr_new( acc_mgr_shmem, ctx->funk );
  ctx->bank_hash_cmp = fd_bank_hash_cmp_join( fd_bank_hash_cmp_new( bank_hash_cmp_mem ) );
  ctx->epoch_ctx = fd_exec_epoch_ctx_join( fd_exec_epoch_ctx_new( epoch_ctx_mem, VOTE_ACC_MAX ) );

  if( FD_UNLIKELY( sscanf( tile->replay.cluster_version, "%u.%u.%u", &ctx->epoch_ctx->epoch_bank.cluster_version[0], &ctx->epoch_ctx->epoch_bank.cluster_version[1], &ctx->epoch_ctx->epoch_bank.cluster_version[2] )!=3 ) ) {
    FD_LOG_ERR(( "failed to decode cluster version, configured as \"%s\"", tile->replay.cluster_version ));
  }
  fd_features_enable_cleaned_up( &ctx->epoch_ctx->features, ctx->epoch_ctx->epoch_bank.cluster_version );

  ctx->epoch     = fd_epoch_join( fd_epoch_new( epoch_mem, FD_VOTER_MAX ) );
  ctx->forks     = fd_forks_join( fd_forks_new( forks_mem, FD_BLOCK_MAX, 42UL ) );
  ctx->ghost     = fd_ghost_join( fd_ghost_new( ghost_mem, 42UL, FD_BLOCK_MAX ) );
  ctx->tower     = fd_tower_join( fd_tower_new( tower_mem ) );

  /**********************************************************************/
  /* voter                                                              */
  /**********************************************************************/

  memcpy( ctx->validator_identity, fd_keyload_load( tile->replay.identity_key_path, 1 ), sizeof(fd_pubkey_t) );
  *ctx->vote_authority = *ctx->validator_identity; /* FIXME */
  memcpy( ctx->vote_acc, fd_keyload_load( tile->replay.vote_account_path, 1 ), sizeof(fd_pubkey_t) );

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
      if( fd_tpool_worker_push( ctx->tpool, i, (uchar *)tpool_worker_mem + TPOOL_WORKER_MEM_SZ*(i - 1U), TPOOL_WORKER_MEM_SZ ) == NULL ) {
        FD_LOG_ERR(( "failed to launch worker" ));
      }
    }
  }

  if( ctx->tpool == NULL ) {
    FD_LOG_ERR(("failed to create thread pool"));
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
    ctx->spads[ ctx->spad_cnt++ ] = spad;
    spad_mem_cur += fd_ulong_align_up( thread_spad_size, fd_spad_align() );
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

  /* set up vote related items */
  ctx->vote                           = tile->replay.vote;
  ctx->validator_identity_pubkey[ 0 ] = *(fd_pubkey_t const *)fd_type_pun_const( fd_keyload_load( tile->replay.identity_key_path, 1 ) );
  ctx->vote_acct_addr[ 0 ]            = *(fd_pubkey_t const *)fd_type_pun_const( fd_keyload_load( tile->replay.vote_account_path, 1 ) );

  /**********************************************************************/
  /* wen-restart                                                        */
  /**********************************************************************/
  ctx->in_wen_restart       = tile->replay.in_wen_restart;
  if( FD_LIKELY( strlen( tile->replay.tower_checkpt )>0 ) ) {
    ctx->tower_checkpt_fileno = open( tile->replay.tower_checkpt,
                                      O_RDWR | O_CREAT,
                                      S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH );
    if( ctx->tower_checkpt_fileno<0 ) FD_LOG_ERR(( "Failed at opening the tower checkpoint file" ));
  } else {
    ctx->tower_checkpt_fileno = -1;
  }

  if( FD_UNLIKELY( ctx->in_wen_restart ) ) {
    fd_base58_decode_32( tile->replay.wen_restart_coordinator, ctx->restart_coordinator.key );
    void *     restart_mem = fd_wksp_alloc_laddr( ctx->wksp,
                                                  fd_restart_align(),
                                                  fd_restart_footprint(),
                                                  RESTART_MAGIC_TAG );
    ctx->restart           = fd_restart_join( fd_restart_new( restart_mem ) );
  } else {
    ctx->restart           = NULL;
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

  /* Setup gossip tile input for wen-restart */
  fd_topo_link_t * gossip_in_link = &topo->links[ tile->in_link_id[ GOSSIP_IN_IDX ] ];
  ctx->gossip_in_mem              = topo->workspaces[ topo->objs[ gossip_in_link->dcache_obj_id ].wksp_id ].wksp;
  ctx->gossip_in_chunk0           = fd_dcache_compact_chunk0( ctx->gossip_in_mem, gossip_in_link->dcache );
  ctx->gossip_in_wmark            = fd_dcache_compact_wmark( ctx->gossip_in_mem, gossip_in_link->dcache, gossip_in_link->mtu );

  /* Setup batch tile input for epoch account hash */
  fd_topo_link_t * batch_in_link = &topo->links[ tile->in_link_id[ BATCH_IN_IDX ] ];
  ctx->batch_in_mem              = topo->workspaces[ topo->objs[ batch_in_link->dcache_obj_id ].wksp_id ].wksp;
  ctx->batch_in_chunk0           = fd_dcache_compact_chunk0( ctx->batch_in_mem, batch_in_link->dcache );
  ctx->batch_in_wmark            = fd_dcache_compact_wmark( ctx->batch_in_mem, batch_in_link->dcache, batch_in_link->mtu );

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

  fd_topo_link_t * gossip_out = &topo->links[ tile->out_link_id[ GOSSIP_OUT_IDX ] ];
  ctx->gossip_out_mcache      = gossip_out->mcache;
  ctx->gossip_out_sync        = fd_mcache_seq_laddr( ctx->gossip_out_mcache );
  ctx->gossip_out_depth       = fd_mcache_depth( ctx->gossip_out_mcache );
  ctx->gossip_out_seq         = fd_mcache_seq_query( ctx->gossip_out_sync );
  ctx->gossip_out_chunk0      = fd_dcache_compact_chunk0( fd_wksp_containing( gossip_out->dcache ), gossip_out->dcache );
  ctx->gossip_out_mem         = topo->workspaces[ topo->objs[ gossip_out->dcache_obj_id ].wksp_id ].wksp;
  ctx->gossip_out_wmark       = fd_dcache_compact_wmark( ctx->gossip_out_mem, gossip_out->dcache, gossip_out->mtu );
  ctx->gossip_out_chunk       = ctx->gossip_out_chunk0;

  fd_topo_link_t * store_out = &topo->links[ tile->out_link_id[ STORE_OUT_IDX ] ];
  ctx->store_out_mcache      = store_out->mcache;
  ctx->store_out_sync        = fd_mcache_seq_laddr( ctx->store_out_mcache );
  ctx->store_out_depth       = fd_mcache_depth( ctx->store_out_mcache );
  ctx->store_out_seq         = fd_mcache_seq_query( ctx->store_out_sync );
  ctx->store_out_chunk0      = fd_dcache_compact_chunk0( fd_wksp_containing( store_out->dcache ), store_out->dcache );
  ctx->store_out_mem         = topo->workspaces[ topo->objs[ store_out->dcache_obj_id ].wksp_id ].wksp;
  ctx->store_out_wmark       = fd_dcache_compact_wmark( ctx->store_out_mem, store_out->dcache, store_out->mtu );
  ctx->store_out_chunk       = ctx->store_out_chunk0;

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
    fd_topo_link_t const * replay_plugin_out = &topo->links[ tile->out_link_id[ REPLAY_PLUG_OUT_IDX] ];
    if( strcmp( replay_plugin_out->name, "replay_plugi" ) ) {
      FD_LOG_ERR(("output link confusion for output %lu", REPLAY_PLUG_OUT_IDX));
    }
    ctx->replay_plugin_out_mem    = topo->workspaces[ topo->objs[ replay_plugin_out->dcache_obj_id ].wksp_id ].wksp;
    ctx->replay_plugin_out_chunk0 = fd_dcache_compact_chunk0( ctx->replay_plugin_out_mem, replay_plugin_out->dcache );
    ctx->replay_plugin_out_wmark  = fd_dcache_compact_wmark ( ctx->replay_plugin_out_mem, replay_plugin_out->dcache, replay_plugin_out->mtu );
    ctx->replay_plugin_out_chunk  = ctx->replay_plugin_out_chunk0;

    fd_topo_link_t const * votes_plugin_out = &topo->links[ tile->out_link_id[ VOTES_PLUG_OUT_IDX] ];
    if( strcmp( votes_plugin_out->name, "votes_plugin" ) ) {
      FD_LOG_ERR(("output link confusion for output %lu", VOTES_PLUG_OUT_IDX));
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

  populate_sock_filter_policy_replay( out_cnt, out, (uint)fd_log_private_logfile_fd(), (uint)ctx->blockstore_fd );
  return sock_filter_policy_replay_instr_cnt;
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

/* TODO: This is definitely not correct */
#define STEM_BURST (1UL)

#define STEM_CALLBACK_CONTEXT_TYPE  fd_replay_tile_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_replay_tile_ctx_t)

#define STEM_CALLBACK_DURING_HOUSEKEEPING during_housekeeping
#define STEM_CALLBACK_AFTER_CREDIT        after_credit
#define STEM_CALLBACK_DURING_FRAG         during_frag
#define STEM_CALLBACK_AFTER_FRAG          after_frag

#include "../../../../disco/stem/fd_stem.c"

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
