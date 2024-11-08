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
#include "../../../../disco/metrics/fd_metrics.h"
#include "../../../../disco/metrics/generated/fd_metrics_replay.h"
#include "../../../../choreo/fd_choreo.h"
#include "../../../../disco/store/fd_epoch_forks.h"
#include "../../../../funk/fd_funk_filemap.h"

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


// #define STOP_SLOT 280859632

/* An estimate of the max number of transactions in a block.  If there are more
   transactions, they must be split into multiple sets. */
#define MAX_TXNS_PER_REPLAY ( ( FD_SHRED_MAX_PER_SLOT * FD_SHRED_MAX_SZ) / FD_TXN_MIN_SERIALIZED_SZ )


#define STORE_IN_IDX   (0UL)
#define PACK_IN_IDX    (1UL)

#define STAKE_OUT_IDX  (0UL)
#define NOTIF_OUT_IDX  (1UL)
#define SENDER_OUT_IDX (2UL)
#define POH_OUT_IDX    (3UL)

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

  char const * blockstore_checkpt;
  int          blockstore_publish;
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
  fd_forks_t *          forks;
  fd_ghost_t *          ghost;
  fd_tower_t *          tower;
  fd_voter_t *          voter;
  fd_bank_hash_cmp_t *  bank_hash_cmp;

  /* Tpool */

  uchar        tpool_mem[FD_TPOOL_FOOTPRINT( FD_TILE_MAX )] __attribute__( ( aligned( FD_TPOOL_ALIGN ) ) );
  fd_tpool_t * tpool;

  /* Depends on store_int and is polled in after_credit */

  fd_blockstore_t *     blockstore;

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

  ulong * smr;  /* supermajority root slot */
  ulong * poh;  /* proof-of-history slot */
  uint poh_init_done;
  int  snapshot_init_done;

  int         vote;
  fd_pubkey_t validator_identity_pubkey[ 1 ];
  fd_pubkey_t vote_acct_addr[ 1 ];

  fd_txncache_t * status_cache;
  void * bmtree[ FD_PACK_MAX_BANK_TILES ];

  fd_epoch_forks_t epoch_forks[1];

  fd_spad_t * spads[ 128UL ];
  ulong       spad_cnt;
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
  l = FD_LAYOUT_APPEND( l, fd_forks_align(), fd_forks_footprint( FD_BLOCK_MAX ) );
  l = FD_LAYOUT_APPEND( l, fd_ghost_align(), fd_ghost_footprint( FD_BLOCK_MAX, FD_VOTER_MAX ) );
  l = FD_LAYOUT_APPEND( l, fd_tower_align(), fd_tower_footprint() );
  l = FD_LAYOUT_APPEND( l, fd_voter_align(), fd_voter_footprint() );
  l = FD_LAYOUT_APPEND( l, fd_bank_hash_cmp_align(), fd_bank_hash_cmp_footprint( ) );
  for( ulong i = 0UL; i<FD_PACK_MAX_BANK_TILES; i++ ) {
    l = FD_LAYOUT_APPEND( l, FD_BMTREE_COMMIT_ALIGN, FD_BMTREE_COMMIT_FOOTPRINT(0) );
  }
  l = FD_LAYOUT_APPEND( l, FD_SCRATCH_ALIGN_DEFAULT, tile->replay.tpool_thread_count * TPOOL_WORKER_MEM_SZ );
  l = FD_LAYOUT_APPEND( l, fd_spad_align(), tile->replay.tpool_thread_count * fd_spad_footprint( MAX_TX_ACCOUNT_LOCKS * fd_ulong_align_up( FD_ACC_TOT_SZ_MAX, FD_ACCOUNT_REC_ALIGN ) ) );
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

  fd_runtime_execute_pack_txns( slot_ctx, spad, capture_ctx, txns, txn_cnt );

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
    FD_LOG_INFO(("sending current epoch stake weights - epoch: %lu, stake_weight_cnt: %lu, start_slot: %lu, slot_cnt: %lu", stake_weights_msg[0], stake_weights_msg[1], stake_weights_msg[2], stake_weights_msg[3]));
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
    FD_LOG_INFO(("sending next epoch stake weights - epoch: %lu, stake_weight_cnt: %lu, start_slot: %lu, slot_cnt: %lu", stake_weights_msg[0], stake_weights_msg[1], stake_weights_msg[2], stake_weights_msg[3]));
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
  /* Incoming packet from store tile. Format:
   * Parent slot (ulong - 8 bytes)
   * Updated block hash/PoH hash (fd_hash_t - 32 bytes)
   * Microblock as a list of fd_txn_p_t (sz * sizeof(fd_txn_p_t))
   */

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
    if( FD_UNLIKELY( ctx->curr_slot < ctx->tower->root ) ) {
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
    if( FD_UNLIKELY( ctx->curr_slot < ctx->tower->root ) ) {
      FD_LOG_WARNING(( "pack sent slot %lu before our root %lu.", ctx->curr_slot, ctx->tower->root ));
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
      fd_microblock_trailer_t * mblk_trailer = (fd_microblock_trailer_t *)dst_poh;
      mblk_trailer->bank_busy_seq = seq;
      mblk_trailer->bank_idx = bank_idx;
    } else {
      FD_LOG_WARNING(("OTHER PACKET TYPE: %lu", fd_disco_poh_sig_pkt_type( sig )));
      ctx->skip_frag = 1;
      return;
    }

    FD_LOG_DEBUG(( "packed microblock - slot: %lu, parent_slot: %lu, txn_cnt: %lu", ctx->curr_slot, ctx->parent_slot, ctx->txn_cnt ));
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
blockstore_publish( fd_replay_tile_ctx_t * ctx, ulong smr ) {
  if( FD_LIKELY( ctx->blockstore_publish ) ) {
    fd_blockstore_start_write( ctx->blockstore );
    int rc = fd_blockstore_publish( ctx->blockstore, smr );
    if( rc != FD_BLOCKSTORE_OK ) {
      FD_LOG_WARNING(( "err %d when publishing blockstore", rc ));
    }
    fd_blockstore_end_write( ctx->blockstore );
  }
}

static void
funk_publish( fd_replay_tile_ctx_t * ctx, ulong smr ) {
  fd_blockstore_start_read( ctx->blockstore );
  fd_hash_t const * root_block_hash = fd_blockstore_block_hash_query( ctx->blockstore, smr );
  fd_funk_txn_xid_t xid;
  memcpy( xid.uc, root_block_hash, sizeof( fd_funk_txn_xid_t ) );
  fd_blockstore_end_read( ctx->blockstore );

  xid.ul[0]                = smr;
  fd_funk_txn_t * txn_map  = fd_funk_txn_map( ctx->funk, fd_funk_wksp( ctx->funk ) );
  fd_funk_txn_t * root_txn = fd_funk_txn_query( &xid, txn_map );
  if( root_txn==NULL ) {
    memset( xid.uc, 0, sizeof( fd_funk_txn_xid_t ) );
    xid.ul[0] = smr;
    root_txn = fd_funk_txn_query( &xid, txn_map );
  }

  for( ulong i = 0UL; i<ctx->bank_cnt; i++ ) {
    fd_tpool_wait( ctx->tpool, i+1 );
  }
  fd_funk_start_write( ctx->funk );
  ulong rc = fd_funk_txn_publish( ctx->funk, root_txn, 1 );
  if( FD_UNLIKELY( !rc ) ) {
    FD_LOG_ERR(( "failed to funk publish slot %lu", smr ));
  }
  fd_funk_end_write( ctx->funk );

  if( FD_LIKELY( ctx->slot_ctx->status_cache ) ) {
    fd_txncache_register_root_slot( ctx->slot_ctx->status_cache, smr );
  }

  fd_epoch_bank_t * epoch_bank = fd_exec_epoch_ctx_epoch_bank( ctx->slot_ctx->epoch_ctx );
  if( smr >= epoch_bank->eah_start_slot ) {
    fd_accounts_hash( ctx->slot_ctx, ctx->tpool, &ctx->slot_ctx->slot_bank.epoch_account_hash );
    epoch_bank->eah_start_slot = FD_SLOT_NULL;
  }

  if( FD_UNLIKELY( ctx->capture_ctx ) ) {
    fd_runtime_checkpt( ctx->capture_ctx, ctx->slot_ctx, smr );
  }
}

static int
suppress_notify( const fd_pubkey_t * prog ) {
  /* Certain accounts are just noise and a waste of notification bandwidth */
  if ( !memcmp( prog, fd_solana_vote_program_id.key, sizeof( fd_pubkey_t ) ) ) {
    return 1;
  } else if ( !memcmp( prog, fd_solana_system_program_id.key, sizeof( fd_pubkey_t ) ) ) {
    return 1;
  } else if ( !memcmp( prog, fd_solana_compute_budget_program_id.key, sizeof( fd_pubkey_t ) ) ) {
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
publish_slot_notifications( fd_replay_tile_ctx_t * ctx,
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
}

static void
send_tower_sync( fd_replay_tile_ctx_t * ctx ) {
  if( FD_UNLIKELY( !ctx->vote ) ) return;
  FD_LOG_NOTICE( ( "sending tower sync" ) );
  ulong vote_slot = fd_tower_votes_peek_tail_const( ctx->tower->votes )->slot;
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

  fd_compact_vote_state_update_t update;
  fd_tower_to_tower_sync( ctx->tower, vote_bank_hash, &update );

  /* Send a vote txn. */

  fd_txn_p_t * txn = (fd_txn_p_t *)fd_chunk_to_laddr( ctx->sender_out_mem, ctx->sender_out_chunk );
  txn->payload_sz  = fd_voter_txn_generate( ctx->voter,
                                           &update,
                                           vote_block_hash,
                                           txn->_,
                                           txn->payload );
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
}

static uint
is_epoch_boundary( fd_epoch_bank_t * epoch_bank, ulong curr_slot, ulong prev_slot ) {
  ulong slot_idx;
  ulong prev_epoch = fd_slot_to_epoch( &epoch_bank->epoch_schedule, prev_slot, &slot_idx );
  ulong new_epoch  = fd_slot_to_epoch( &epoch_bank->epoch_schedule, curr_slot, &slot_idx );

  return ( prev_epoch < new_epoch || slot_idx == 0 );
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
  FD_LOG_NOTICE(( "new block execution - slowt: %lu, parent_slot: %lu", curr_slot, ctx->parent_slot ));
  fd_epoch_bank_t * epoch_bank = fd_exec_epoch_ctx_epoch_bank( fork->slot_ctx.epoch_ctx );

  /* if it is an epoch boundary, push out stake weights */
  if( fork->slot_ctx.slot_bank.slot != 0 ) {
    is_new_epoch_in_new_block = (int)is_epoch_boundary( epoch_bank, fork->slot_ctx.slot_bank.slot, fork->slot_ctx.slot_bank.prev_slot );
  }

  fork->slot_ctx.slot_bank.prev_slot = fork->slot_ctx.slot_bank.slot;
  fork->slot_ctx.slot_bank.slot      = curr_slot;
  fork->slot_ctx.enable_exec_recording = ctx->tx_metadata_storage;

  if( is_epoch_boundary( epoch_bank, fork->slot_ctx.slot_bank.slot, fork->slot_ctx.slot_bank.prev_slot ) ) {
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
  FD_TEST( !ctx->funk->speed_load );
  fork->slot_ctx.funk_txn = fd_funk_txn_prepare(ctx->funk, fork->slot_ctx.funk_txn, &xid, 1);
  fd_funk_end_write( ctx->funk );

  int res = fd_runtime_block_execute_prepare( &fork->slot_ctx );
  if( res != FD_RUNTIME_EXECUTE_SUCCESS ) {
    FD_LOG_ERR(( "block prep execute failed" ));
  }

  /* Read slot history into slot ctx */
  res = fd_sysvar_slot_history_read( &fork->slot_ctx, fork->slot_ctx.valloc, fork->slot_ctx.slot_history );

  if( res != FD_RUNTIME_EXECUTE_SUCCESS ) {
    FD_LOG_ERR(( "slot history read failed" ));
  }

  FD_LOG_NOTICE(("Current leader: %s", FD_BASE58_ENC_32_ALLOCA( fork->slot_ctx.leader->uc ) ));
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
            ulong                  chunk,
            ulong                  sz,
            ulong                  tsorig,
            fd_stem_context_t *    stem ) {
  (void)in_idx;
  (void)sig;
  (void)chunk;
  (void)sz;
  (void)tsorig;

  if( FD_UNLIKELY( ctx->skip_frag ) ) return;

  ulong curr_slot = ctx->curr_slot;
  ulong parent_slot = ctx->parent_slot;
  ulong flags     = ctx->flags;
  ulong bank_idx = ctx->bank_idx;
  if ( FD_UNLIKELY( curr_slot < ctx->tower->root ) ) {
    FD_LOG_WARNING(( "ignoring replay of slot %lu (parent: %lu). earlier than our root %lu.", curr_slot, parent_slot, ctx->tower->root ));
    return;
  }

  if ( FD_UNLIKELY( parent_slot < ctx->tower->root ) ) {
    FD_LOG_WARNING(( "ignoring replay of slot %lu (parent: %lu). parent slot is earlier than our root %lu.", curr_slot, parent_slot, ctx->tower->root ));
    return;
  }

  fd_replay_out_ctx_t * bank_out = &ctx->bank_out[ bank_idx ];
  /* do a replay */
  ulong        txn_cnt    = ctx->txn_cnt;
  fd_txn_p_t * txns       = (fd_txn_p_t *)fd_chunk_to_laddr( bank_out->mem, bank_out->chunk );
  fd_microblock_trailer_t * microblock_trailer = (fd_microblock_trailer_t *)(txns + txn_cnt);
  microblock_trailer->bank_idx                 = bank_idx;
  microblock_trailer->bank_busy_seq            = seq;

  ulong epoch_ctx_idx = fd_epoch_forks_get_epoch_ctx( ctx->epoch_forks, ctx->ghost, curr_slot, &ctx->parent_slot );
  ctx->epoch_ctx = ctx->epoch_forks->forks[ epoch_ctx_idx ].epoch_ctx;


  /* This is an edge case related to pack. The parent fork might
      already be in the frontier and currently executing (ie.
      fork->frozen = 0). */

  fd_fork_t * parent_fork = fd_fork_frontier_ele_query(
        ctx->forks->frontier, &ctx->parent_slot, NULL, ctx->forks->pool );
  if( FD_UNLIKELY ( parent_fork && parent_fork->lock ) ) {
    FD_LOG_ERR(
        ( "parent slot is frozen in frontier. cannot execute. slot: %lu, parent_slot: %lu",
          curr_slot,
          ctx->parent_slot ) );
  }

  fd_fork_t * fork = fd_fork_frontier_ele_query(
        ctx->forks->frontier, &curr_slot, NULL, ctx->forks->pool );

  if( fork == NULL ) {
    fork = prepare_new_block_execution( ctx, stem, curr_slot, flags );
  }

  if( ctx->capture_ctx )
    fd_solcap_writer_set_slot( ctx->capture_ctx->capture, fork->slot_ctx.slot_bank.slot );
  // Execute all txns which were succesfully prepared
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
        res = fd_runtime_execute_txns_in_waves_tpool( &fork->slot_ctx,
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

      fd_block_map_t * block_map_entry = fd_blockstore_block_map_query( ctx->blockstore, curr_slot );
      fd_block_t * block_ = fd_blockstore_block_query( ctx->blockstore, curr_slot );

      fd_blockstore_start_write( ctx->blockstore );

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
      FD_LOG_INFO(( "finished block - slot: %lu, parent_slot: %lu, txn_cnt: %lu, blockhash: %s",
                    curr_slot,
                    ctx->parent_slot,
                    fork->slot_ctx.slot_bank.transaction_count-fork->slot_ctx.parent_transaction_count,
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
      fd_block_map_t * block_map_entry = fd_blockstore_block_map_query( ctx->blockstore, curr_slot );
      fd_block_t * block_ = fd_blockstore_block_query( ctx->blockstore, curr_slot );
      fork->slot_ctx.block = block_;
      int res = fd_runtime_block_execute_finalize_tpool( &fork->slot_ctx, ctx->capture_ctx, block_info, ctx->tpool );

      if( res != FD_RUNTIME_EXECUTE_SUCCESS ) {
        FD_LOG_ERR(("block finished failed"));
      }

      // Notify for updated slot info
      publish_slot_notifications( ctx, fork, block_map_entry, curr_slot );

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
      fd_tower_fork_update( ctx->tower, fork, ctx->acc_mgr, ctx->blockstore, ctx->ghost );

      /* Check which fork to reset to for pack. */

      fd_fork_t const * reset_fork = fd_tower_reset_fork( ctx->tower, ctx->forks, ctx->ghost );
      if( reset_fork->lock ) {
        FD_LOG_WARNING(("RESET FORK FROZEN: %lu", reset_fork->slot ));
        fd_fork_t * new_reset_fork = fd_forks_prepare( ctx->forks, reset_fork->slot_ctx.slot_bank.prev_slot, ctx->acc_mgr,
            ctx->blockstore, ctx->epoch_ctx, ctx->funk, ctx->valloc );
        new_reset_fork->lock = 0;
        reset_fork = new_reset_fork;
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
      fd_ghost_print( ctx->ghost );
      fd_tower_print( ctx->tower );
      fd_fork_t const * vote_fork = fd_tower_vote_fork( ctx->tower,
                                                        ctx->forks,
                                                        ctx->acc_mgr,
                                                        ctx->ghost );

      FD_LOG_NOTICE( ( "\n\n[Fork Selection]\n"
                       "# of vote accounts: %lu\n"
                       "best fork:          %lu\n",
                       fd_tower_vote_accs_cnt( ctx->tower->vote_accs ),
                       fd_ghost_head( ctx->ghost )->slot ) );

      if( FD_UNLIKELY( ctx->vote && fd_fseq_query( ctx->poh ) == ULONG_MAX ) ) {

        /* Only proceed with voting if we're caught up. */

        FD_LOG_WARNING( ( "still catching up. not voting." ) );
      } else {

        /* Proceed according to how local and cluster are synchronized. */

        if( FD_LIKELY( vote_fork ) ) {
          fd_tower_vote( ctx->tower, vote_fork->slot );

          /* Check if we've reached max lockout. */

          if( FD_UNLIKELY( fd_tower_is_max_lockout( ctx->tower ) ) ) {

            /* Publish tower and get the new root. */

            ulong root = fd_tower_publish( ctx->tower );
            FD_LOG_NOTICE(( "new tower root: %lu", root ));

            /* Note that our local tower root is not used to publish our
               fork-aware structures eg. blockstore, forks, ghost.

               Instead the SMR is used.  The main reason to avoid using
               tower root is while starting up, the tower will be loaded
               from the vote account state (the "cluster tower") which
               might have an earlier root slot than the snapshot slot.
               The other structures are initialized to the snapshot
               slot. */
          }

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
          FD_LOG_ERR( ( "Bank hash mismatch on slot: %lu. Halting.", cmp_slot ) );

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
    if( strcmp( topo->tiles[i].name, "thread" ) == 0 ) {
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
read_snapshot( void * _ctx, char const * snapshotfile, char const * incremental ) {
  fd_replay_tile_ctx_t * ctx = (fd_replay_tile_ctx_t *)_ctx;

  /* Pass the slot_ctx to snapshot_load or recover_banks */

  const char * snapshot = snapshotfile;
  if( strcmp( snapshot, "funk" ) == 0 || strncmp( snapshot, "wksp:", 5 ) == 0) {
    /* Funk already has a snapshot loaded */
    fd_runtime_recover_banks( ctx->slot_ctx, 0, 1 );
  } else {
    FD_MCNT_SET( REPLAY, SNAPSHOT_STATUS_SNAPSHOT_BEGIN, 1 );
    fd_snapshot_load( snapshot, ctx->slot_ctx, ctx->tpool, false, false, FD_SNAPSHOT_TYPE_FULL );
    FD_MCNT_SET( REPLAY, SNAPSHOT_STATUS_SNAPSHOT_END, 1 );
  }

  /* Load incremental */

  if( strlen( incremental ) > 0 ) {
    FD_MCNT_SET( REPLAY, SNAPSHOT_STATUS_INCREMENTAL_BEGIN, 1 );
    fd_snapshot_load( incremental, ctx->slot_ctx, ctx->tpool, false, false, FD_SNAPSHOT_TYPE_INCREMENTAL );
    FD_MCNT_SET( REPLAY, SNAPSHOT_STATUS_INCREMENTAL_END, 1 );
  }

  fd_runtime_update_leaders( ctx->slot_ctx, ctx->slot_ctx->slot_bank.slot );
  FD_LOG_NOTICE(( "starting fd_bpf_scan_and_create_bpf_program_cache_entry..." ));
  fd_funk_start_write( ctx->slot_ctx->acc_mgr->funk );
  fd_bpf_scan_and_create_bpf_program_cache_entry_tpool( ctx->slot_ctx, ctx->slot_ctx->funk_txn, ctx->tpool );
  fd_funk_end_write( ctx->slot_ctx->acc_mgr->funk );
  FD_LOG_NOTICE(( "finished fd_bpf_scan_and_create_bpf_program_cache_entry..." ));

  fd_blockstore_start_write( ctx->slot_ctx->blockstore );
  fd_blockstore_init( ctx->slot_ctx->blockstore, &ctx->slot_ctx->slot_bank );
  fd_blockstore_end_write( ctx->slot_ctx->blockstore );
}

static void
init_after_snapshot( fd_replay_tile_ctx_t * ctx ) {
  /* Do not modify order! */

  ulong snapshot_slot = ctx->slot_ctx->slot_bank.slot;
  if( FD_UNLIKELY( !snapshot_slot ) ) {
    fd_runtime_update_leaders(ctx->slot_ctx, ctx->slot_ctx->slot_bank.slot);
    FD_LOG_WARNING(( "Updated leader %s", FD_BASE58_ENC_32_ALLOCA( ctx->slot_ctx->leader->uc) ));

    ctx->slot_ctx->slot_bank.prev_slot = 0UL;
    ctx->slot_ctx->slot_bank.slot = 1UL;

    ulong hashcnt_per_slot = ctx->slot_ctx->epoch_ctx->epoch_bank.hashes_per_tick * ctx->slot_ctx->epoch_ctx->epoch_bank.ticks_per_slot;
    while(hashcnt_per_slot--) {
      fd_sha256_hash( ctx->slot_ctx->slot_bank.poh.uc, 32UL, ctx->slot_ctx->slot_bank.poh.uc );
    }

    FD_TEST( fd_runtime_block_execute_prepare( ctx->slot_ctx ) == 0 );
    fd_block_info_t info = {.signature_cnt = 0 };
    FD_TEST( fd_runtime_block_execute_finalize_tpool( ctx->slot_ctx, NULL, &info, ctx->tpool ) == 0 );

    ctx->slot_ctx->slot_bank.prev_slot = 0UL;
    ctx->slot_ctx->slot_bank.slot = 1UL;
    snapshot_slot = 1UL;

    FD_LOG_NOTICE(( "starting fd_bpf_scan_and_create_bpf_program_cache_entry..." ));
    fd_funk_start_write( ctx->slot_ctx->acc_mgr->funk );
    fd_bpf_scan_and_create_bpf_program_cache_entry_tpool( ctx->slot_ctx, ctx->slot_ctx->funk_txn, ctx->tpool );
    fd_funk_end_write( ctx->slot_ctx->acc_mgr->funk );
    FD_LOG_NOTICE(( "finished fd_bpf_scan_and_create_bpf_program_cache_entry..." ));

    fd_blockstore_start_write( ctx->slot_ctx->blockstore );
    fd_blockstore_init( ctx->slot_ctx->blockstore, &ctx->slot_ctx->slot_bank );
    fd_blockstore_end_write( ctx->slot_ctx->blockstore );
  }
  fd_fseq_update( ctx->smr, snapshot_slot );

  ctx->curr_slot     = snapshot_slot;
  ctx->parent_slot   = ctx->slot_ctx->slot_bank.prev_slot;
  ctx->snapshot_slot = snapshot_slot;
  ctx->blockhash     = ( fd_hash_t ){ .hash = { 0 } };
  ctx->flags         = 0;
  ctx->txn_cnt       = 0;

  /* Initialize consensus structures post-snapshot */

  fd_fork_t * snapshot_fork = fd_forks_init( ctx->forks, ctx->slot_ctx );
  FD_TEST( snapshot_fork );
  fd_tower_init( ctx->tower,
                 &ctx->voter->vote_acc_addr,
                 ctx->acc_mgr,
                 ctx->epoch_ctx,
                 snapshot_fork,
                 ctx->smr );
  fd_ghost_init( ctx->ghost, snapshot_slot, ctx->tower->total_stake );
  fd_tower_print( ctx->tower );

  fd_bank_hash_cmp_t * bank_hash_cmp = ctx->epoch_ctx->bank_hash_cmp;
  bank_hash_cmp->total_stake         = ctx->tower->total_stake;
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
      read_snapshot( ctx, ctx->snapshot, ctx->incremental );
    }

    fd_runtime_read_genesis( ctx->slot_ctx, ctx->genesis, is_snapshot, ctx->capture_ctx );
    ctx->epoch_ctx->bank_hash_cmp = ctx->bank_hash_cmp;
    init_after_snapshot( ctx );

    publish_stake_weights( ctx, stem, ctx->slot_ctx );
  } FD_SCRATCH_SCOPE_END;


  /* Redirect ctx->slot_ctx to point to the memory inside forks. */

  fd_fork_t * fork = fd_forks_query( ctx->forks, ctx->curr_slot );
  ctx->slot_ctx = &fork->slot_ctx;
  FD_TEST( ctx->slot_ctx );
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
  }
}


static void
during_housekeeping( void * _ctx ) {
  fd_replay_tile_ctx_t * ctx = (fd_replay_tile_ctx_t *)_ctx;

  ulong smr = fd_fseq_query( ctx->smr );
  if( FD_UNLIKELY( smr == ULONG_MAX ) ) return;

  /* Use the blockstore's saved SMR to detect whether the smr has
     changed.

     TODO refactor this to a variable on the replay tile ctx. */

  if( FD_UNLIKELY( !ctx->blockstore ) ) return;
  fd_blockstore_start_read( ctx->blockstore );
  if( FD_UNLIKELY( ctx->blockstore->smr > smr ) ) {
    FD_LOG_ERR( ( "invariant violation. fseq SMR should always be monotonically increasing and "
                  ">= fork-aware data structures SMR. fseq SMR %lu, blockstore SMR %lu",
                  smr,
                  ctx->blockstore->smr ) );
  }
  fd_blockstore_end_read( ctx->blockstore );
  if( FD_LIKELY( ctx->blockstore->smr == smr ) ) return;
  if( FD_LIKELY( ctx->blockstore ) ) blockstore_publish( ctx, smr );
  if( FD_LIKELY( ctx->forks ) ) fd_forks_publish( ctx->forks, smr, ctx->ghost );
  if( FD_LIKELY( ctx->funk && ctx->blockstore ) ) funk_publish( ctx, smr );
  if( FD_LIKELY( ctx->ghost ) ) {
    fd_epoch_forks_publish( ctx->epoch_forks, ctx->ghost, smr );
    fd_ghost_publish( ctx->ghost, smr );
  }

  // fd_mcache_seq_update( ctx->store_out_sync, ctx->store_out_seq );
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_replay_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_replay_tile_ctx_t), sizeof(fd_replay_tile_ctx_t) );

  FD_TEST( sizeof(ulong) == getrandom( &ctx->funk_seed, sizeof(ulong), 0 ) );
  FD_TEST( sizeof(ulong) == getrandom( &ctx->status_cache_seed, sizeof(ulong), 0 ) );
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  /**********************************************************************/
  /* scratch (bump)-allocate memory owned by the replay tile                      */
  /**********************************************************************/

  /* Do not modify order! This is join-order in unprivileged_init. */

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_replay_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_replay_tile_ctx_t), sizeof(fd_replay_tile_ctx_t) );
  memset( ctx, 0, sizeof(fd_replay_tile_ctx_t) );
  void * alloc_shmem         = FD_SCRATCH_ALLOC_APPEND( l, fd_alloc_align(), fd_alloc_footprint() );
  void * acc_mgr_shmem       = FD_SCRATCH_ALLOC_APPEND( l, FD_ACC_MGR_ALIGN, FD_ACC_MGR_FOOTPRINT );
  void * capture_ctx_mem     = FD_SCRATCH_ALLOC_APPEND( l, FD_CAPTURE_CTX_ALIGN, FD_CAPTURE_CTX_FOOTPRINT );
  void * epoch_ctx_mem       = FD_SCRATCH_ALLOC_APPEND( l, fd_exec_epoch_ctx_align(), MAX_EPOCH_FORKS * fd_exec_epoch_ctx_footprint( VOTE_ACC_MAX ) );
  void * forks_mem           = FD_SCRATCH_ALLOC_APPEND( l, fd_forks_align(), fd_forks_footprint( FD_BLOCK_MAX ) );
  void * ghost_mem           = FD_SCRATCH_ALLOC_APPEND( l, fd_ghost_align(), fd_ghost_footprint( FD_BLOCK_MAX, FD_VOTER_MAX ) );
  void * tower_mem           = FD_SCRATCH_ALLOC_APPEND( l, fd_tower_align(), fd_tower_footprint() );
  void * voter_mem           = FD_SCRATCH_ALLOC_APPEND( l, fd_voter_align(), fd_voter_footprint() );
  void * bank_hash_cmp_mem   = FD_SCRATCH_ALLOC_APPEND( l, fd_bank_hash_cmp_align(), fd_bank_hash_cmp_footprint( ) );
  for( ulong i = 0UL; i<FD_PACK_MAX_BANK_TILES; i++ ) {
    ctx->bmtree[i]           = FD_SCRATCH_ALLOC_APPEND( l, FD_BMTREE_COMMIT_ALIGN, FD_BMTREE_COMMIT_FOOTPRINT(0) );
  }
  void * tpool_worker_mem    = FD_SCRATCH_ALLOC_APPEND( l, FD_SCRATCH_ALIGN_DEFAULT, tile->replay.tpool_thread_count * TPOOL_WORKER_MEM_SZ );
  ulong  thread_spad_size    = fd_spad_footprint( MAX_TX_ACCOUNT_LOCKS * fd_ulong_align_up( FD_ACC_TOT_SZ_MAX, FD_ACCOUNT_REC_ALIGN ) );
  void * spad_mem            = FD_SCRATCH_ALLOC_APPEND( l, fd_spad_align(), tile->replay.tpool_thread_count * thread_spad_size );
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
  FD_TEST( status_cache_obj_id!=ULONG_MAX );
  ctx->status_cache_wksp = topo->workspaces[ topo->objs[ status_cache_obj_id ].wksp_id ].wksp;
  if( ctx->status_cache_wksp==NULL ) {
    FD_LOG_ERR(( "no status cache wksp" ));
  }

  /**********************************************************************/
  /* funk                                                               */
  /**********************************************************************/

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
  }
  if( funk == NULL ) {
    FD_LOG_ERR(( "no funk loaded" ));
  }
  ctx->funk = funk;
  ctx->funk_wksp = fd_funk_wksp( funk );
  if( ctx->funk_wksp == NULL ) {
    FD_LOG_ERR(( "no funk wksp" ));
  }

  /**********************************************************************/
  /* root_slot fseq                                                     */
  /**********************************************************************/

  ulong root_slot_obj_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "root_slot" );
  FD_TEST( root_slot_obj_id!=ULONG_MAX );
  ctx->smr = fd_fseq_join( fd_topo_obj_laddr( topo, root_slot_obj_id ) );
  if( FD_UNLIKELY( !ctx->smr ) ) FD_LOG_ERR(( "replay tile has no root_slot fseq" ));
  FD_TEST( ULONG_MAX==fd_fseq_query( ctx->smr ) );

  /**********************************************************************/
  /* poh_slot fseq                                                     */
  /**********************************************************************/

  ulong poh_slot_obj_id = fd_pod_query_ulong( topo->props, "poh_slot", ULONG_MAX );
  FD_TEST( poh_slot_obj_id!=ULONG_MAX );
  ctx->poh = fd_fseq_join( fd_topo_obj_laddr( topo, poh_slot_obj_id ) );

  /**********************************************************************/
  /* TOML paths                                                         */
  /**********************************************************************/

  ctx->blockstore_checkpt = tile->replay.blockstore_checkpt;
  ctx->blockstore_publish = tile->replay.blockstore_publish;
  ctx->tx_metadata_storage = tile->replay.tx_metadata_storage;
  ctx->funk_checkpt       = tile->replay.funk_checkpt;
  ctx->genesis            = tile->replay.genesis;
  ctx->incremental        = tile->replay.incremental;
  ctx->snapshot           = tile->replay.snapshot;

  /**********************************************************************/
  /* alloc                                                              */
  /**********************************************************************/

  void * alloc_shalloc = fd_alloc_new( alloc_shmem, 3UL );
  if( FD_UNLIKELY( !alloc_shalloc ) ) {
    FD_LOG_ERR( ( "fd_allow_new failed" ) ); }
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
    ctx->status_cache = fd_txncache_join( fd_txncache_new( status_cache_mem, FD_TXNCACHE_DEFAULT_MAX_ROOTED_SLOTS, FD_TXNCACHE_DEFAULT_MAX_LIVE_SLOTS, MAX_CACHE_TXNS_PER_SLOT ) );
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

  ctx->forks     = fd_forks_join( fd_forks_new( forks_mem, FD_BLOCK_MAX, 42UL ) );
  ctx->ghost     = fd_ghost_join( fd_ghost_new( ghost_mem, FD_BLOCK_MAX, FD_VOTER_MAX, 42 ) );
  ctx->tower     = fd_tower_join( fd_tower_new( tower_mem ) );

  /**********************************************************************/
  /* voter                                                              */
  /**********************************************************************/

  ctx->voter = fd_voter_join( fd_voter_new( voter_mem ) );
  memcpy( &ctx->voter->vote_acc_addr.uc,
          fd_keyload_load( tile->replay.vote_account_path, 1 ),
          sizeof( fd_pubkey_t ) );
  memcpy( &ctx->voter->validator_identity.uc,
          fd_keyload_load( tile->replay.identity_key_path, 1 ),
          sizeof( fd_pubkey_t ) );
  ctx->voter->vote_authority = ctx->voter->validator_identity; /* FIXME */

  /**********************************************************************/
  /* tpool                                                              */
  /**********************************************************************/

  if( FD_LIKELY( tile->replay.tpool_thread_count > 1 ) ) {
    tpool_boot( topo, tile->replay.tpool_thread_count );
  }
  ctx->tpool = fd_tpool_init( ctx->tpool_mem, tile->replay.tpool_thread_count );

  if( FD_LIKELY( tile->replay.tpool_thread_count > 1 ) ) {
    /* start the tpool workers */
    for( ulong i =1; i<tile->replay.tpool_thread_count; i++ ) {
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
    spad_mem_cur += thread_spad_size;
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

  // ulong busy_obj_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "first_turbine" );
  // FD_TEST( busy_obj_id != ULONG_MAX );
  // ctx->first_turbine = fd_fseq_join( fd_topo_obj_laddr( topo, busy_obj_id ) );
  // if( FD_UNLIKELY( !ctx->first_turbine ) )
  //   FD_LOG_ERR( ( "replay tile %lu has no busy flag", tile->kind_id ) );

  ctx->poh_init_done = 0U;
  ctx->snapshot_init_done = 0;

  /* set up vote related items */
  ctx->vote                           = tile->replay.vote;
  ctx->validator_identity_pubkey[ 0 ] = *(fd_pubkey_t const *)fd_type_pun_const( fd_keyload_load( tile->replay.identity_key_path, 1 ) );
  ctx->vote_acct_addr[ 0 ]            = *(fd_pubkey_t const *)fd_type_pun_const( fd_keyload_load( tile->replay.vote_account_path, 1 ) );

  /**********************************************************************/
  /* links                                                              */
  /**********************************************************************/

  /* Set up store tile input */
  fd_topo_link_t * store_in_link = &topo->links[ tile->in_link_id[ STORE_IN_IDX ] ];
  ctx->store_in_mem              = topo->workspaces[ topo->objs[ store_in_link->dcache_obj_id ].wksp_id ].wksp;
  ctx->store_in_chunk0           = fd_dcache_compact_chunk0( ctx->store_in_mem, store_in_link->dcache );
  ctx->store_in_wmark            = fd_dcache_compact_wmark( ctx->store_in_mem, store_in_link->dcache, store_in_link->mtu );

  /* Set up pack tile input */
  fd_topo_link_t * pack_in_link = &topo->links[ tile->in_link_id[ PACK_IN_IDX ] ];
  ctx->pack_in_mem              = topo->workspaces[ topo->objs[ pack_in_link->dcache_obj_id ].wksp_id ].wksp;
  ctx->pack_in_chunk0           = fd_dcache_compact_chunk0( ctx->pack_in_mem, pack_in_link->dcache );
  ctx->pack_in_wmark            = fd_dcache_compact_wmark( ctx->pack_in_mem, pack_in_link->dcache, pack_in_link->mtu );

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
  (void)topo;
  (void)tile;

  populate_sock_filter_policy_replay( out_cnt, out, (uint)fd_log_private_logfile_fd() );
  return sock_filter_policy_replay_instr_cnt;
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
