#define _GNU_SOURCE

#include "../../../../disco/tiles.h"
#include "../../../../disco/shred/fd_stake_ci.h"
#include "../../../../disco/topo/fd_pod_format.h"
#include "../../../../disco/tvu/fd_replay.h"
#include "../../../../disco/tvu/fd_tvu.h"
#include "../../../../flamenco/fd_flamenco.h"
#include "../../../../flamenco/runtime/context/fd_exec_epoch_ctx.h"
#include "../../../../flamenco/runtime/context/fd_exec_slot_ctx.h"
#include "../../../../flamenco/runtime/fd_borrowed_account.h"
#include "../../../../flamenco/runtime/fd_executor.h"
#include "../../../../flamenco/runtime/fd_hashes.h"
#include "../../../../flamenco/runtime/program/fd_bpf_program_util.h"
#include "../../../../flamenco/runtime/program/fd_builtin_programs.h"
#include "../../../../flamenco/runtime/sysvar/fd_sysvar_epoch_schedule.h"
#include "../../../../flamenco/snapshot/fd_snapshot.h"
#include "../../../../flamenco/stakes/fd_stakes.h"
#include "../../../../util/fd_util.h"
#include "../../../../util/tile/fd_tile_private.h"
#include "fd_replay_notif.h"
#include "generated/replay_seccomp.h"
#include "../../../../choreo/fd_choreo.h"

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


#pragma GCC diagnostic ignored "-Wformat"
#pragma GCC diagnostic ignored "-Wformat-extra-args"

/* An estimate of the max number of transactions in a block.  If there are more
   transactions, they must be split into multiple sets. */
#define MAX_TXNS_PER_REPLAY ( ( FD_SHRED_MAX_PER_SLOT * FD_SHRED_MAX_SZ) / FD_TXN_MIN_SERIALIZED_SZ )

#define STORE_IN_IDX   (0UL)
#define PACK_IN_IDX    (1UL)
#define POH_OUT_IDX    (0UL)
#define NOTIF_OUT_IDX  (1UL)

/* Scratch space estimates.
   TODO: Update constants and add explanation
*/
#define SCRATCH_MAX    (1024UL /*MiB*/ << 21)
#define SCRATCH_DEPTH  (128UL) /* 128 scratch frames */

#define VOTE_ACC_MAX   (2000000UL)

#define BANK_HASH_CMP_LG_MAX 16

struct fd_replay_tile_ctx {
  fd_wksp_t * wksp;

  // Store tile input
  fd_wksp_t * store_in_mem;
  ulong       store_in_chunk0;
  ulong       store_in_wmark;

  // Pack tile input
  fd_wksp_t * pack_in_mem;
  ulong       pack_in_chunk0;
  ulong       pack_in_wmark;

  // PoH tile output defs
  fd_frag_meta_t * poh_out_mcache;
  ulong *          poh_out_sync;
  ulong            poh_out_depth;
  ulong            poh_out_seq;

  fd_wksp_t * poh_out_mem;
  ulong       poh_out_chunk0;
  ulong       poh_out_wmark;
  ulong       poh_out_chunk;

  // Notification output defs
  fd_frag_meta_t * notif_out_mcache;
  ulong *          notif_out_sync;
  ulong            notif_out_depth;
  ulong            notif_out_seq;

  fd_wksp_t * notif_out_mem;
  ulong       notif_out_chunk0;
  ulong       notif_out_wmark;
  ulong       notif_out_chunk;

  // Stake weights output link defs
  fd_frag_meta_t * stake_weights_out_mcache;
  ulong *          stake_weights_out_sync;
  ulong            stake_weights_out_depth;
  ulong            stake_weights_out_seq;

  fd_wksp_t * stake_weights_out_mem;
  ulong       stake_weights_out_chunk0;
  ulong       stake_weights_out_wmark;
  ulong       stake_weights_out_chunk;

  fd_acc_mgr_t          acc_mgr[1];
  uchar *               epoch_ctx_mem;
  fd_exec_epoch_ctx_t * epoch_ctx;
  fd_exec_slot_ctx_t *  slot_ctx;

  fd_replay_t *         replay;

  fd_wksp_t  * blockstore_wksp;
  fd_wksp_t  * funk_wksp;
  char const * snapshot;
  char const * incremental;
  char const * genesis;

  ulong     curr_slot;
  ulong     parent_slot;
  ulong     flags;
  fd_hash_t blockhash;
  ulong     txn_cnt;

  uchar        tpool_mem[FD_TPOOL_FOOTPRINT( FD_TILE_MAX )] __attribute__( ( aligned( FD_TPOOL_ALIGN ) ) );
  fd_tpool_t * tpool;
  ulong        max_workers;

  ulong funk_seed;
  fd_capture_ctx_t * capture_ctx;
  FILE *             capture_file;

  fd_bank_hash_cmp_t * bank_hash_cmp;
  fd_tower_t *         tower;
  fd_ghost_t *         ghost;

  ulong * first_turbine;

  ulong * bank_busy;
  uint poh_init_done;
};
typedef struct fd_replay_tile_ctx fd_replay_tile_ctx_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 128UL;
}

FD_FN_PURE static inline ulong
loose_footprint( fd_topo_tile_t const * tile FD_PARAM_UNUSED ) {
  return 22UL * FD_SHMEM_GIGANTIC_PAGE_SZ;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile FD_PARAM_UNUSED ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_replay_tile_ctx_t), sizeof(fd_replay_tile_ctx_t) );
  l = FD_LAYOUT_APPEND( l, fd_alloc_align(), fd_alloc_footprint() );
  l = FD_LAYOUT_APPEND( l, fd_scratch_smem_align(), fd_scratch_smem_footprint( SCRATCH_MAX   ) );
  l = FD_LAYOUT_APPEND( l, fd_scratch_fmem_align(), fd_scratch_fmem_footprint( SCRATCH_DEPTH ) );
  l = FD_LAYOUT_APPEND( l, fd_exec_epoch_ctx_align(), fd_exec_epoch_ctx_footprint( VOTE_ACC_MAX ) );
  l = FD_LAYOUT_APPEND( l, fd_replay_align(), fd_replay_footprint() );
  l = FD_LAYOUT_APPEND( l, fd_forks_align(), fd_forks_footprint( FD_SLOT_MAX ) );
  l = FD_LAYOUT_APPEND( l, FD_CAPTURE_CTX_ALIGN, FD_CAPTURE_CTX_FOOTPRINT );
  l = FD_LAYOUT_APPEND( l, fd_bank_hash_cmp_align(), fd_bank_hash_cmp_footprint( ) );
  l = FD_LAYOUT_APPEND( l, fd_tower_align(), fd_tower_footprint() );
  l = FD_LAYOUT_APPEND( l, fd_ghost_align(), fd_ghost_footprint( FD_SLOT_MAX, FD_VOTER_MAX  ) );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

FD_FN_CONST static inline void *
mux_ctx( void * scratch ) {
  return (void*)fd_ulong_align_up( (ulong)scratch, alignof(fd_replay_tile_ctx_t) );
}

void
publish_stake_weights( fd_replay_tile_ctx_t * ctx,
                       fd_mux_context_t *     mux_ctx,
                       fd_exec_slot_ctx_t *   slot_ctx ) {
  fd_epoch_bank_t * epoch_bank = fd_exec_epoch_ctx_epoch_bank( slot_ctx->epoch_ctx );
  if( ctx->slot_ctx->slot_bank.epoch_stakes.vote_accounts_root!=NULL ) {
    ulong * stake_weights_msg         = fd_chunk_to_laddr( ctx->stake_weights_out_mem, ctx->stake_weights_out_chunk );
    fd_stake_weight_t * stake_weights = (fd_stake_weight_t *)&stake_weights_msg[4];
    ulong stake_weight_idx            = fd_stake_weights_by_node( &ctx->slot_ctx->slot_bank.epoch_stakes, stake_weights );

    stake_weights_msg[0] = fd_slot_to_leader_schedule_epoch( &epoch_bank->epoch_schedule, ctx->slot_ctx->slot_bank.slot ) - 1; /* epoch */
    stake_weights_msg[1] = stake_weight_idx; /* staked_cnt */
    stake_weights_msg[2] = fd_epoch_slot0( &epoch_bank->epoch_schedule, stake_weights_msg[0] ); /* start_slot */
    stake_weights_msg[3] = epoch_bank->epoch_schedule.slots_per_epoch; /* slot_cnt */
    FD_LOG_INFO(("sending current epoch stake weights - epoch: %lu, stake_weight_cnt: %lu, start_slot: %lu, slot_cnt: %lu", stake_weights_msg[0], stake_weights_msg[1], stake_weights_msg[2], stake_weights_msg[3]));
    ulong tspub = fd_frag_meta_ts_comp( fd_tickcount() );

    ulong stake_weights_sz  = 4*sizeof(ulong) + (stake_weight_idx * sizeof(fd_stake_weight_t));
    ulong stake_weights_sig = 4UL;
    fd_mux_publish( mux_ctx, stake_weights_sig, ctx->stake_weights_out_chunk, stake_weights_sz, 0UL, 0UL, tspub );
    ctx->stake_weights_out_chunk = fd_dcache_compact_next( ctx->stake_weights_out_chunk, stake_weights_sz, ctx->stake_weights_out_chunk0, ctx->stake_weights_out_wmark );
  }

  if( epoch_bank->next_epoch_stakes.vote_accounts_root!=NULL ) {
    ulong * stake_weights_msg         = fd_chunk_to_laddr( ctx->stake_weights_out_mem, ctx->stake_weights_out_chunk );
    fd_stake_weight_t * stake_weights = (fd_stake_weight_t *)&stake_weights_msg[4];
    ulong stake_weight_idx            = fd_stake_weights_by_node( &epoch_bank->next_epoch_stakes, stake_weights );

    stake_weights_msg[0] = fd_slot_to_leader_schedule_epoch( &epoch_bank->epoch_schedule, ctx->slot_ctx->slot_bank.slot ); /* epoch */
    stake_weights_msg[1] = stake_weight_idx; /* staked_cnt */
    stake_weights_msg[2] = fd_epoch_slot0( &epoch_bank->epoch_schedule, stake_weights_msg[0] ); /* start_slot */
    stake_weights_msg[3] = epoch_bank->epoch_schedule.slots_per_epoch; /* slot_cnt */
    FD_LOG_INFO(("sending next epoch stake weights - epoch: %lu, stake_weight_cnt: %lu, start_slot: %lu, slot_cnt: %lu", stake_weights_msg[0], stake_weights_msg[1], stake_weights_msg[2], stake_weights_msg[3]));
    ulong tspub = fd_frag_meta_ts_comp( fd_tickcount() );

    ulong stake_weights_sz = 4*sizeof(ulong) + (stake_weight_idx * sizeof(fd_stake_weight_t));
    ulong stake_weights_sig = 4UL;
    fd_mux_publish( mux_ctx, stake_weights_sig, ctx->stake_weights_out_chunk, stake_weights_sz, 0UL, 0UL, tspub );
    ctx->stake_weights_out_chunk = fd_dcache_compact_next( ctx->stake_weights_out_chunk, stake_weights_sz, ctx->stake_weights_out_chunk0, ctx->stake_weights_out_wmark );
  }
}

static void
during_frag( void * _ctx,
             ulong  in_idx      FD_PARAM_UNUSED,
             ulong  seq         FD_PARAM_UNUSED,
             ulong  sig         FD_PARAM_UNUSED,
             ulong  chunk,
             ulong  sz,
             int *  opt_filter  FD_PARAM_UNUSED ) {
  fd_replay_tile_ctx_t * ctx = (fd_replay_tile_ctx_t *)_ctx;

  void * dst_poh = fd_chunk_to_laddr( ctx->poh_out_mem, ctx->poh_out_chunk );

  /* Incoming packet from store tile. Format:
   * Parent slot (ulong - 8 bytes)
   * Updated block hash/PoH hash (fd_hash_t - 32 bytes)
   * Microblock as a list of fd_txn_p_t (sz * sizeof(fd_txn_p_t))
   */

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
    ctx->flags = fd_disco_replay_sig_flags( sig );
    ctx->txn_cnt = sz;

    ctx->parent_slot = FD_LOAD( ulong, src );
    src += sizeof(ulong);
    memcpy( ctx->blockhash.uc, src, sizeof(fd_hash_t) );
    src += sizeof(fd_hash_t);
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
    if( fd_disco_poh_sig_pkt_type( sig )==POH_PKT_TYPE_MICROBLOCK ) {
      ctx->flags = REPLAY_FLAG_PACKED_MICROBLOCK;
      ctx->txn_cnt = (sz - sizeof(fd_microblock_bank_trailer_t)) / sizeof(fd_txn_p_t);

      fd_memcpy( dst_poh, src, (sz - sizeof(fd_microblock_bank_trailer_t)) );
      src += (sz-sizeof(fd_microblock_bank_trailer_t));
      fd_microblock_bank_trailer_t * t = (fd_microblock_bank_trailer_t *)src;
      ctx->parent_slot = (ulong)t->bank;
    // } else if( fd_disco_poh_sig_pkt_type( sig )==POH_PKT_TYPE_DONE_PACKING ) {
    //   ctx->flags = REPLAY_FLAG_FINISHED_BLOCK;
    //   ctx->txn_cnt = 0UL;
    } else {
      FD_LOG_WARNING(("OTHER PACKET TYPE: %lu", fd_disco_poh_sig_pkt_type( sig )));
      *opt_filter = 1;
      return;
    }

    FD_LOG_INFO(( "packed microblock - slot: %lu, parent_slot: %lu, txn_cnt: %lu", ctx->curr_slot, ctx->parent_slot, ctx->txn_cnt ));
  }

  // if( ctx->flags & REPLAY_FLAG_PACKED_MICROBLOCK ) {
  //   /* We do not know the parent slot, pick one from fork selection */
  //   ulong max_slot = 0; /* FIXME: default to snapshot slot/smr */
  //   for( fd_fork_frontier_iter_t iter = fd_fork_frontier_iter_init( ctx->replay->forks->frontier, ctx->replay->forks->pool );
  //      !fd_fork_frontier_iter_done( iter, ctx->replay->forks->frontier, ctx->replay->forks->pool );
  //      iter = fd_fork_frontier_iter_next( iter, ctx->replay->forks->frontier, ctx->replay->forks->pool ) ) {
  //     fd_exec_slot_ctx_t * ele = &fd_fork_frontier_iter_ele( iter, ctx->replay->forks->frontier, ctx->replay->forks->pool )->slot_ctx;
  //     if ( max_slot < ele->slot_bank.slot ) {
  //       max_slot = ele->slot_bank.slot;
  //     }
  //   }
  //   ctx->parent_slot = max_slot;
  // }

  fd_blockstore_start_read( ctx->replay->blockstore );
  fd_block_t * block_ = fd_blockstore_block_query( ctx->replay->blockstore, ctx->curr_slot );
  if( FD_LIKELY( block_ ) ) {
    if( fd_uchar_extract_bit( block_->flags, FD_BLOCK_FLAG_PROCESSED ) ) {
      FD_LOG_WARNING(( "block already processed - slot: %lu", ctx->curr_slot ));
      *opt_filter = 1;
    }
  }
  fd_blockstore_end_read( ctx->replay->blockstore );
}

static void
after_frag( void *             _ctx,
            ulong              in_idx     FD_PARAM_UNUSED,
            ulong              seq,
            ulong *            opt_sig    FD_PARAM_UNUSED,
            ulong *            opt_chunk  FD_PARAM_UNUSED,
            ulong *            opt_sz     FD_PARAM_UNUSED,
            ulong *            opt_tsorig FD_PARAM_UNUSED,
            int *              opt_filter,
            fd_mux_context_t * mux ) {
  fd_replay_tile_ctx_t * ctx = (fd_replay_tile_ctx_t *)_ctx;

  /* do a replay */
  ulong txn_cnt = ctx->txn_cnt;
  fd_txn_p_t * txns       = (fd_txn_p_t *)fd_chunk_to_laddr( ctx->poh_out_mem, ctx->poh_out_chunk );
  fd_microblock_trailer_t * microblock_trailer = (fd_microblock_trailer_t *)(txns + txn_cnt);
  
  // ctx->curr_slot = fd_disco_replay_sig_slot( *opt_sig );
  // ctx->flags = fd_disco_replay_sig_flags( *opt_sig );

  FD_SCRATCH_SCOPE_BEGIN {
    /* If the parent fork exists && is executing, give up */
    fd_fork_t * parent_fork = fd_fork_frontier_ele_query(
          ctx->replay->forks->frontier, &ctx->parent_slot, NULL, ctx->replay->forks->pool );
    if( parent_fork != NULL && parent_fork->executing ) {
      FD_LOG_WARNING(( "parent fork is still executing, cannot process block right now - slot: %lu, parent_slot: %lu", ctx->curr_slot, ctx->parent_slot ));
      return;
    }

    fd_fork_t * fork = fd_fork_frontier_ele_query(
          ctx->replay->forks->frontier, &ctx->curr_slot, NULL, ctx->replay->forks->pool );
    if( fork == NULL ) {
      long prepare_time_ns = -fd_log_wallclock();

      fork = fd_replay_prepare_ctx( ctx->replay, ctx->parent_slot );
      fork->executing = 1;
      // Remove slot ctx from frontier
      fd_fork_t * child = fd_fork_frontier_ele_remove( ctx->replay->forks->frontier, &fork->slot, NULL, ctx->replay->forks->pool );
      child->slot = ctx->curr_slot;
      if( FD_UNLIKELY( fd_fork_frontier_ele_query(
          ctx->replay->forks->frontier, &ctx->curr_slot, NULL, ctx->replay->forks->pool ) ) ) {
        FD_LOG_ERR( ( "invariant violation: child slot %lu was already in the frontier", ctx->curr_slot ) );
      }
      fd_fork_frontier_ele_insert( ctx->replay->forks->frontier, child, ctx->replay->forks->pool );
      FD_TEST( fork == child );

      // fork is advancing
      FD_LOG_NOTICE(( "new block execution - slot: %lu, parent_slot: %lu", ctx->curr_slot, ctx->parent_slot ));

      fork->slot_ctx.slot_bank.prev_slot = fork->slot_ctx.slot_bank.slot;
      fork->slot_ctx.slot_bank.slot      = ctx->curr_slot;

      fd_funk_txn_xid_t xid;

      fd_memcpy(xid.uc, ctx->blockhash.uc, sizeof(fd_funk_txn_xid_t));
      xid.ul[0] = fork->slot_ctx.slot_bank.slot;
      /* push a new transaction on the stack */
      fd_funk_start_write( ctx->replay->funk );
      fork->slot_ctx.funk_txn = fd_funk_txn_prepare(ctx->replay->funk, fork->slot_ctx.funk_txn, &xid, 1);
      fd_funk_end_write( ctx->replay->funk );

      int res = fd_runtime_publish_old_txns( &fork->slot_ctx, ctx->capture_ctx );
      if( res != FD_RUNTIME_EXECUTE_SUCCESS ) {
        FD_LOG_ERR(( "txn publishing failed" ));
      }

      /* if it is an epoch boundary, push out stake weights */
      int is_new_epoch = 0;
      if( fork->slot_ctx.slot_bank.slot != 0 ) {
        ulong slot_idx;
        fd_epoch_bank_t * epoch_bank = fd_exec_epoch_ctx_epoch_bank( fork->slot_ctx.epoch_ctx );
        ulong prev_epoch = fd_slot_to_epoch( &epoch_bank->epoch_schedule, fork->slot_ctx.slot_bank.prev_slot, &slot_idx );
        ulong new_epoch = fd_slot_to_epoch( &epoch_bank->epoch_schedule, fork->slot_ctx.slot_bank.slot, &slot_idx );

        if( prev_epoch < new_epoch || slot_idx == 0 ) {
          FD_LOG_DEBUG(("Epoch boundary"));
          is_new_epoch = 1;
        }
      }

      res = fd_runtime_block_execute_prepare( &fork->slot_ctx );

      if( is_new_epoch ) {
        publish_stake_weights( ctx, mux, &fork->slot_ctx );
      }

      if( res != FD_RUNTIME_EXECUTE_SUCCESS ) {
        FD_LOG_ERR(( "block prep execute failed" ));
      }

      prepare_time_ns += fd_log_wallclock();
      FD_LOG_DEBUG(("TIMING: prepare_time - slot: %lu, elapsed: %6.6f ms", ctx->curr_slot, (double)prepare_time_ns * 1e-6));
    }

    if( ctx->capture_ctx )
      fd_solcap_writer_set_slot( ctx->capture_ctx->capture, fork->slot_ctx.slot_bank.slot );
    // Execute all txns which were succesfully prepared
    long execute_time_ns = -fd_log_wallclock();
    int res = fd_runtime_execute_txns_in_waves_tpool( &fork->slot_ctx, ctx->capture_ctx,
                                                      txns, txn_cnt,
                                                      ctx->tpool, ctx->max_workers );
    execute_time_ns += fd_log_wallclock();
    FD_LOG_DEBUG(("TIMING: execute_time - slot: %lu, elapsed: %6.6f ms", ctx->curr_slot, (double)execute_time_ns * 1e-6));

    if( res != 0 && !( ctx->flags & REPLAY_FLAG_PACKED_MICROBLOCK ) ) {
      FD_LOG_WARNING(( "block invalid - slot: %lu", ctx->curr_slot ));
      *opt_filter = 1;
      return;
    }

    if( ctx->flags & REPLAY_FLAG_FINISHED_BLOCK ) {
      FD_LOG_INFO(( "finalizing block - slot: %lu, parent_slot: %lu, blockhash: %32J", ctx->curr_slot, ctx->parent_slot, ctx->blockhash.uc ));
      // Copy over latest blockhash to slot_bank poh for updating the sysvars
      fd_memcpy( fork->slot_ctx.slot_bank.poh.uc, ctx->blockhash.uc, sizeof(fd_hash_t) );
      fd_block_info_t block_info[1];
      block_info->signature_cnt = fork->slot_ctx.signature_cnt;
      long finalize_time_ns = -fd_log_wallclock();
      int res = fd_runtime_block_execute_finalize_tpool( &fork->slot_ctx, ctx->capture_ctx, block_info, NULL, 1UL );
      finalize_time_ns += fd_log_wallclock();
      FD_LOG_WARNING(("TIMING: finalize_time - slot: %lu, elapsed: %6.6f ms", ctx->curr_slot, (double)finalize_time_ns * 1e-6));

      if( res != FD_RUNTIME_EXECUTE_SUCCESS ) {
        FD_LOG_WARNING(("block finalize failed"));
        *opt_filter = 1;
        return;
      }

      // Notify for all the updated accounts
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
      for( fd_funk_rec_t const * rec = fd_funk_txn_first_rec( ctx->replay->funk, fork->slot_ctx.funk_txn );
           rec != NULL;
           rec = fd_funk_txn_next_rec( ctx->replay->funk, rec ) ) {
        if( !fd_funk_key_is_acc( rec->pair.key ) ) continue;
        if( msg == NULL ) {
          NOTIFY_START;
          msg->type = FD_REPLAY_SAVED_TYPE;
          msg->acct_saved.funk_xid = rec->pair.xid[0];
          msg->acct_saved.acct_id_cnt = 0;
        }
        fd_memcpy( msg->acct_saved.acct_id[ msg->acct_saved.acct_id_cnt++ ].uc, rec->pair.key->uc, sizeof(fd_pubkey_t) );
        if( msg->acct_saved.acct_id_cnt == FD_REPLAY_NOTIF_ACCT_MAX ) {
          NOTIFY_END;
        }
      }
      if( msg ) {
        NOTIFY_END;
      }

      {
        NOTIFY_START;
        msg->type = FD_REPLAY_SLOT_TYPE;
        msg->slot_exec.slot = fork->slot_ctx.slot_bank.slot;
        msg->slot_exec.parent = fork->slot_ctx.slot_bank.prev_slot;
        msg->slot_exec.root = ctx->replay->blockstore->smr;
        memcpy( &msg->slot_exec.bank_hash, &fork->slot_ctx.slot_bank.banks_hash, sizeof( fd_hash_t ) );
        NOTIFY_END;
      }

#undef NOTIFY_START
#undef NOTIFY_END
      notify_time_ns += fd_log_wallclock();
      FD_LOG_DEBUG(("TIMING: notify_time - slot: %lu, elapsed: %6.6f ms", ctx->curr_slot, (double)notify_time_ns * 1e-6));

      fd_blockstore_start_write( ctx->replay->blockstore );

      fd_block_t * block_ = fd_blockstore_block_query( ctx->replay->blockstore, ctx->curr_slot );
      if( FD_LIKELY( block_ ) ) {
        block_->flags = fd_uchar_set_bit( block_->flags, FD_BLOCK_FLAG_PROCESSED );
        memcpy( &block_->bank_hash, &fork->slot_ctx.slot_bank.banks_hash, sizeof( fd_hash_t ) );
      }

      fd_blockstore_end_write( ctx->replay->blockstore );

      fork->executing = 0;
      // Remove slot ctx from frontier once block is finalized
      fd_fork_t * child = fd_fork_frontier_ele_remove( ctx->replay->forks->frontier, &fork->slot, NULL, ctx->replay->forks->pool );
      child->slot = ctx->curr_slot;
      if( FD_UNLIKELY( fd_fork_frontier_ele_query(
          ctx->replay->forks->frontier, &ctx->curr_slot, NULL, ctx->replay->forks->pool ) ) ) {
        FD_LOG_ERR( ( "invariant violation: child slot %lu was already in the frontier", ctx->curr_slot ) );
      }
      fd_fork_frontier_ele_insert( ctx->replay->forks->frontier, child, ctx->replay->forks->pool );

      /* Consensus */

      FD_PARAM_UNUSED long tic_ = fd_log_wallclock();


      fd_tower_fork_update( ctx->tower, fork );
      long        now         = fd_log_wallclock();
      fd_ghost_node_t * head                = fd_ghost_head_query( ctx->tower->ghost );
      long        duration_ns         = fd_log_wallclock() - now;
      if( FD_UNLIKELY( head->slot_hash.slot < fork->slot - 32 ) ) {
        FD_LOG_WARNING( ( "Fork choice slot is too far behind executed slot. Likely there is a "
                          "bug in execution that is interfering with our ability to process recent votes." ) );

        /* Don't try to proceed with fork choice and voting as our view of where the stake is probably wrong */

      } else {

        /* TODO add voting and select_vote_and_reset_bank logic here if we have a valid picked fork */
        fd_vote_accounts_t const * vote_accounts = &fork->slot_ctx.epoch_ctx->epoch_bank.stakes.vote_accounts;

        FD_LOG_NOTICE( ( "\n\n[Fork Selection]\n"
                         "# of vote accounts: %lu \n"
                         "selected fork:      %lu\n"
                         "took:               %.2lf ms (%ld ns)\n",
                         fd_vote_accounts_pair_t_map_size( vote_accounts->vote_accounts_pool, vote_accounts->vote_accounts_root ),
                         head->slot_hash.slot,
                         (double)( duration_ns ) / 1e6,
                         duration_ns ) );

        fd_fork_t * reset_fork = fd_tower_reset_fork_select( ctx->tower );
        memcpy( microblock_trailer->hash, reset_fork->slot_ctx.slot_bank.block_hash_queue.last_hash->uc, sizeof(fd_hash_t) );
        if( ctx->poh_init_done == 1 ) {
          ulong parent_slot = reset_fork->slot_ctx.slot_bank.prev_slot;
          ulong curr_slot = reset_fork->slot_ctx.slot_bank.slot;
          FD_LOG_INFO(( "publishing mblk to poh - slot: %lu, parent_slot: %lu, flags: %lx", curr_slot, parent_slot, ctx->flags ));
          ulong tspub = fd_frag_meta_ts_comp( fd_tickcount() );
          ulong sig = fd_disco_replay_sig( curr_slot, ctx->flags );
          fd_mcache_publish( ctx->poh_out_mcache, ctx->poh_out_depth, ctx->poh_out_seq, sig, ctx->poh_out_chunk, txn_cnt, 0UL, *opt_tsorig, tspub );
          ctx->poh_out_chunk = fd_dcache_compact_next( ctx->poh_out_chunk, (txn_cnt * sizeof(fd_txn_p_t)) + sizeof(fd_microblock_trailer_t), ctx->poh_out_chunk0, ctx->poh_out_wmark );
          ctx->poh_out_seq = fd_seq_inc( ctx->poh_out_seq, 1UL );
        } else {
          FD_LOG_INFO(( "NOT publishing mblk to poh - slot: %lu, parent_slot: %lu, flags: %lx", ctx->curr_slot, ctx->parent_slot, ctx->flags ));
        }
      }

      fd_slot_hash_t    curr_slot_hash = { .slot = child->slot,
                                           .hash = fork->slot_ctx.slot_bank.banks_hash };
      fd_ghost_node_t * curr           = fd_ghost_node_query( ctx->tower->ghost, &curr_slot_hash );
      fd_ghost_node_t * prev           = curr;
      for( ulong i = 0; i < 8; i++ ) {
        if( !curr ) break;
        prev = curr;
        curr = curr->parent;
      }
      fd_ghost_node_t * root = fd_ptr_if( !!curr, curr, prev );
      fd_ghost_print( ctx->tower->ghost, root );

      /* Prepare bank for next execution. */

      child->slot_ctx.slot_bank.slot           = ctx->curr_slot;
      child->slot_ctx.slot_bank.collected_fees = 0;
      child->slot_ctx.slot_bank.collected_rent = 0;


      fd_hash_t const * bank_hash = &child->slot_ctx.slot_bank.banks_hash;

      fd_bank_hash_cmp_t * bank_hash_cmp = child->slot_ctx.epoch_ctx->bank_hash_cmp;
      fd_bank_hash_cmp_lock( bank_hash_cmp );
      fd_bank_hash_cmp_insert( bank_hash_cmp, ctx->curr_slot, bank_hash, 1, 0 );

      /* Try to move the bank hash comparison watermark forward */

      for( ulong cmp_slot = bank_hash_cmp->watermark + 1; cmp_slot < ctx->curr_slot; cmp_slot++ ) {
        if( FD_LIKELY( fd_bank_hash_cmp_check( bank_hash_cmp, cmp_slot ) ) ) {
          bank_hash_cmp->watermark = cmp_slot;
        }
      }

      fd_bank_hash_cmp_unlock( bank_hash_cmp );

      if (NULL != ctx->capture_ctx)
        fd_solcap_writer_flush( ctx->capture_ctx->capture );
    }

    /* Indicate to pack tile we are done processing the transactions so it
     can pack new microblocks using these accounts.  DO NOT USE THE
     SANITIZED TRANSACTIONS AFTER THIS POINT, THEY ARE NO LONGER VALID. */
    fd_fseq_update( ctx->bank_busy, seq );

    if( FD_UNLIKELY( !(ctx->flags & REPLAY_FLAG_CATCHING_UP) && ctx->poh_init_done == 0 && ctx->slot_ctx->blockstore ) ) {
      FD_LOG_INFO(( "sending init msg" ));
      fd_poh_init_msg_t * msg = fd_chunk_to_laddr(ctx->poh_out_mem, ctx->poh_out_chunk);
      fd_epoch_bank_t * epoch_bank = fd_exec_epoch_ctx_epoch_bank( ctx->epoch_ctx );
      msg->hashcnt_per_tick = ctx->epoch_ctx->epoch_bank.hashes_per_tick;
      msg->ticks_per_slot   = ctx->epoch_ctx->epoch_bank.ticks_per_slot;
      msg->hashcnt_duration_ns = (double)(epoch_bank->ns_per_slot / epoch_bank->ticks_per_slot) / (double) msg->hashcnt_per_tick;
      if( ctx->slot_ctx->slot_bank.block_hash_queue.last_hash ) {
        memcpy(msg->last_entry_hash, ctx->slot_ctx->slot_bank.block_hash_queue.last_hash->uc, sizeof(fd_hash_t));
      } else {
        memset(msg->last_entry_hash, 0UL, sizeof(fd_hash_t));
      }
      msg->tick_height = ctx->slot_ctx->slot_bank.slot * msg->ticks_per_slot;

      ulong sig = fd_disco_replay_sig( ctx->slot_ctx->slot_bank.slot, REPLAY_FLAG_INIT );
      fd_mcache_publish(ctx->poh_out_mcache, ctx->poh_out_depth, ctx->poh_out_seq, sig, ctx->poh_out_chunk, sizeof(fd_poh_init_msg_t), 0UL, *opt_tsorig, 0UL);
      ctx->poh_out_chunk = fd_dcache_compact_next(ctx->poh_out_chunk, sizeof(fd_poh_init_msg_t), ctx->poh_out_chunk0, ctx->poh_out_wmark);
      ctx->poh_out_seq = fd_seq_inc(ctx->poh_out_seq, 1UL);
      ctx->poh_init_done = 1;
    }
    /* Publish mblk to POH. */

    if( ctx->poh_init_done == 1 && !( ctx->flags & REPLAY_FLAG_FINISHED_BLOCK ) 
        && ( ( ctx->flags & REPLAY_FLAG_MICROBLOCK ) || ( ctx->flags & REPLAY_FLAG_PACKED_MICROBLOCK ) ) ) {
      FD_LOG_INFO(( "publishing mblk to poh - slot: %lu, parent_slot: %lu", ctx->curr_slot, ctx->parent_slot ));
      ulong tspub = fd_frag_meta_ts_comp( fd_tickcount() );
      ulong sig = fd_disco_replay_sig( ctx->curr_slot, ctx->flags );
      fd_mcache_publish( ctx->poh_out_mcache, ctx->poh_out_depth, ctx->poh_out_seq, sig, ctx->poh_out_chunk, txn_cnt, 0UL, *opt_tsorig, tspub );
      ctx->poh_out_chunk = fd_dcache_compact_next( ctx->poh_out_chunk, (txn_cnt * sizeof(fd_txn_p_t)) + sizeof(fd_microblock_trailer_t), ctx->poh_out_chunk0, ctx->poh_out_wmark );
      ctx->poh_out_seq = fd_seq_inc( ctx->poh_out_seq, 1UL );
    } else {
      FD_LOG_INFO(( "NOT publishing mblk to poh - slot: %lu, parent_slot: %lu, flags: %lx", ctx->curr_slot, ctx->parent_slot, ctx->flags ));
    }
  } FD_SCRATCH_SCOPE_END;
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

  const char * snapshot = snapshotfile;
  if( strncmp( snapshot, "wksp:", 5 ) != 0 ) {
    fd_snapshot_load( snapshot, ctx->slot_ctx, false, false, FD_SNAPSHOT_TYPE_FULL );
  } else {
    fd_runtime_recover_banks( ctx->slot_ctx, 0 );
  }

  // fd_blockstore_start_write( ctx->slot_ctx->blockstore );
  // fd_blockstore_clear( ctx->slot_ctx->blockstore );
  // fd_blockstore_end_write( ctx->slot_ctx->blockstore );

  char incremental_snapshot_out[128] = { 0 };
  if( strlen( incremental ) > 0 ) {
    if( strstr( incremental, "http" ) ) {
      // long last_now = fd_log_wallclock();
      // while( ULONG_MAX == fd_fseq_query( ctx->first_turbine ) ) {
      //   long now = fd_log_wallclock();
      //   if( FD_UNLIKELY( now - (long)1e9 > last_now ) ) {
      //     FD_LOG_NOTICE( ( "waiting for first turbine..." ) );
      //     last_now = now;
      //   }
      // }
      FD_LOG_NOTICE( ( "downloading incremental snapshot..." ) );
      FILE * fp;

      /* Open the command for reading. */
      char cmd[128];
      snprintf( cmd, sizeof( cmd ), "./download_incremental.sh %s", incremental );
      FD_LOG_NOTICE( ( "cmd: %s", cmd ) );
      fp = popen( cmd, "r" );
      if( fp == NULL ) {
        printf( "Failed to run command\n" );
        exit( 1 );
      }

      /* Read the output a line at a time - output it. */
      if( !fgets( incremental_snapshot_out, sizeof( incremental_snapshot_out ) - 1, fp ) ) {
        FD_LOG_NOTICE( ( "incremental snapshot %s", incremental_snapshot_out ) );
        FD_LOG_ERR( ( "failed to parse snapshot name" ) );
      }
      incremental_snapshot_out[strcspn( incremental_snapshot_out, "\n" )] = '\0';
      incremental = incremental_snapshot_out;
      pclose( fp );
    }

    /* Already loaded the main snapshot when we initialized funk */
    ulong i, j;
    FD_TEST( sscanf( incremental, "incremental-snapshot-%lu-%lu", &i, &j ) == 2 );
    FD_TEST( i == ctx->slot_ctx->slot_bank.slot );
    fd_epoch_bank_t * epoch_bank = fd_exec_epoch_ctx_epoch_bank( ctx->slot_ctx->epoch_ctx );
    FD_TEST( epoch_bank );
    FD_TEST( fd_slot_to_epoch( &epoch_bank->epoch_schedule, i, NULL ) ==
             fd_slot_to_epoch( &epoch_bank->epoch_schedule, j, NULL ) );
    FD_LOG_NOTICE( ( "starting load incremental..." ) );
    fd_snapshot_load( incremental, ctx->slot_ctx, false, false, FD_SNAPSHOT_TYPE_INCREMENTAL );
    ctx->epoch_ctx->bank_hash_cmp = ctx->bank_hash_cmp;
    FD_LOG_NOTICE( ( "finished load incremental..." ) );
  }

  fd_runtime_update_leaders( ctx->slot_ctx, ctx->slot_ctx->slot_bank.slot );
  FD_LOG_NOTICE( ( "starting fd_bpf_scan_and_create_bpf_program_cache_entry..." ) );
  fd_funk_start_write( ctx->slot_ctx->acc_mgr->funk );
  fd_bpf_scan_and_create_bpf_program_cache_entry_tpool(
      ctx->slot_ctx, ctx->slot_ctx->funk_txn, ctx->tpool, ctx->max_workers );
  fd_funk_end_write( ctx->slot_ctx->acc_mgr->funk );
  FD_LOG_NOTICE( ( "finished fd_bpf_scan_and_create_bpf_program_cache_entry..." ) );

  ctx->epoch_ctx->bank_hash_cmp = ctx->bank_hash_cmp;

  fd_blockstore_start_write( ctx->slot_ctx->blockstore );
  fd_blockstore_snapshot_insert( ctx->slot_ctx->blockstore, &ctx->slot_ctx->slot_bank );
  fd_blockstore_end_write( ctx->slot_ctx->blockstore );
}

static void
init_after_snapshot( fd_replay_tile_ctx_t * ctx ) {
  ulong snapshot_slot = ctx->slot_ctx->slot_bank.slot;
  FD_LOG_NOTICE( ( "snapshot slot %lu", snapshot_slot ) );
  fd_bank_hash_cmp_t * bank_hash_cmp = ctx->epoch_ctx->bank_hash_cmp;
  if( snapshot_slot != ctx->curr_slot ) {
    fd_fork_t * ele = fd_fork_frontier_ele_remove( ctx->replay->forks->frontier, &ctx->curr_slot, NULL, ctx->replay->forks->pool );
    ele->slot                = snapshot_slot;
    fd_fork_frontier_ele_insert( ctx->replay->forks->frontier, ele, ctx->replay->forks->pool );
    ctx->replay->smr         = snapshot_slot;
    bank_hash_cmp->watermark = snapshot_slot;
    ctx->curr_slot           = snapshot_slot;
    ctx->parent_slot         = ctx->slot_ctx->slot_bank.prev_slot;
  }

  ctx->tower->acc_mgr     = ctx->replay->acc_mgr;
  ctx->tower->blockstore  = ctx->replay->blockstore;
  ctx->tower->forks       = ctx->replay->forks;
  ctx->tower->ghost       = ctx->ghost;
  ctx->tower->valloc      = ctx->replay->valloc;

  ctx->tower->root = snapshot_slot;
  fd_tower_epoch_update( ctx->tower, ctx->epoch_ctx );
  bank_hash_cmp->total_stake = ctx->tower->total_stake;
  FD_LOG_NOTICE( ( "total stake: %lu", bank_hash_cmp->total_stake ) );

  fd_slot_hash_t key = { .slot = snapshot_slot, .hash = ctx->slot_ctx->slot_bank.banks_hash };
  fd_ghost_node_insert( ctx->ghost, &key, NULL );
  ctx->ghost->total_stake = ctx->tower->total_stake;
}

static void
after_credit( void *             _ctx,
              fd_mux_context_t * mux_ctx ) {
  fd_replay_tile_ctx_t * ctx = (fd_replay_tile_ctx_t *)_ctx;

  // Poll for blockstore
  if( FD_UNLIKELY( ctx->slot_ctx->blockstore == NULL ) ) {
    ulong                    tag = FD_BLOCKSTORE_MAGIC;
    fd_wksp_tag_query_info_t info;
    if( fd_wksp_tag_query( ctx->blockstore_wksp, &tag, 1, &info, 1 ) > 0 ) {
      void * shmem              = fd_wksp_laddr_fast( ctx->blockstore_wksp, info.gaddr_lo );
      ctx->slot_ctx->blockstore = fd_blockstore_join( shmem );
    }

    if( ctx->slot_ctx->blockstore != NULL ) {
      FD_SCRATCH_SCOPE_BEGIN {
        ctx->replay->blockstore        = ctx->slot_ctx->blockstore;
        ctx->replay->forks->blockstore = ctx->slot_ctx->blockstore;
        uchar is_snapshot              = strlen( ctx->snapshot ) > 0;
        if( is_snapshot ) { 
          read_snapshot( ctx, ctx->snapshot, ctx->incremental );
        }

        fd_runtime_read_genesis( ctx->slot_ctx, ctx->genesis, is_snapshot, NULL );
        init_after_snapshot( ctx );

        publish_stake_weights( ctx, mux_ctx, ctx->slot_ctx );
      } FD_SCRATCH_SCOPE_END;
    }
  }
}

static void
during_housekeeping( void * _ctx ) {
  fd_replay_tile_ctx_t * ctx = (fd_replay_tile_ctx_t *)_ctx;
  fd_mcache_seq_update( ctx->poh_out_sync, ctx->poh_out_seq );
  // fd_mcache_seq_update( ctx->store_out_sync, ctx->store_out_seq );
}

static void
privileged_init( fd_topo_t *      topo    FD_PARAM_UNUSED,
                 fd_topo_tile_t * tile    FD_PARAM_UNUSED,
                 void *           scratch ) {

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_replay_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_replay_tile_ctx_t), sizeof(fd_replay_tile_ctx_t) );

  FD_TEST( sizeof(ulong) == getrandom( &ctx->funk_seed, sizeof(ulong), 0 ) );
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile,
                   void *           scratch ) {
  if( FD_UNLIKELY( tile->out_link_id_primary==ULONG_MAX ) )
    FD_LOG_ERR(( "replay tile missing a primary output link" ));

  fd_flamenco_boot( NULL, NULL );
  /* Scratch mem setup */
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_replay_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_replay_tile_ctx_t), sizeof(fd_replay_tile_ctx_t) );
  void * alloc_shmem         = FD_SCRATCH_ALLOC_APPEND( l, fd_alloc_align(), fd_alloc_footprint() );
  /* Create scratch region */
  void * smem                = FD_SCRATCH_ALLOC_APPEND( l, fd_scratch_smem_align(), fd_scratch_smem_footprint( SCRATCH_MAX   ) );
  void * fmem                = FD_SCRATCH_ALLOC_APPEND( l, fd_scratch_fmem_align(), fd_scratch_fmem_footprint( SCRATCH_DEPTH ) );
  /* NOTE: incremental snapshot load resets this and care should be taken if
    adding any setup here. */
  ctx->epoch_ctx_mem         = FD_SCRATCH_ALLOC_APPEND( l, fd_exec_epoch_ctx_align(), fd_exec_epoch_ctx_footprint( VOTE_ACC_MAX ) );
  void * replay_mem          = FD_SCRATCH_ALLOC_APPEND( l, fd_replay_align(), fd_replay_footprint() );
  void * forks_mem           = FD_SCRATCH_ALLOC_APPEND( l, fd_forks_align(), fd_forks_footprint( FD_SLOT_MAX ) );
  void * capture_ctx_mem     = FD_SCRATCH_ALLOC_APPEND( l, FD_CAPTURE_CTX_ALIGN, FD_CAPTURE_CTX_FOOTPRINT );
  void * bank_hash_cmp_mem   = FD_SCRATCH_ALLOC_APPEND( l, fd_bank_hash_cmp_align(), fd_bank_hash_cmp_footprint( ) );
  void * tower_mem           = FD_SCRATCH_ALLOC_APPEND( l, fd_tower_align(), fd_tower_footprint() );
  void * ghost_mem           = FD_SCRATCH_ALLOC_APPEND( l, fd_ghost_align(), fd_ghost_footprint( FD_SLOT_MAX, FD_VOTER_MAX ) );

  fd_scratch_attach( smem, fmem, SCRATCH_MAX, SCRATCH_DEPTH );

  ctx->wksp = topo->workspaces[ topo->objs[ tile->tile_obj_id ].wksp_id ].wksp;

  /* Blockstore setup */
  ulong blockstore_obj_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "blockstore" );
  FD_TEST( blockstore_obj_id!=ULONG_MAX );
  ctx->blockstore_wksp = topo->workspaces[ topo->objs[ blockstore_obj_id ].wksp_id ].wksp;

  if( ctx->blockstore_wksp==NULL ) {
    FD_LOG_ERR(( "no blocktore workspace" ));
  }

  /* Funk setup */
  ulong funk_obj_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "funk" );
  FD_TEST( funk_obj_id!=ULONG_MAX );
  ctx->funk_wksp = topo->workspaces[ topo->objs[ funk_obj_id ].wksp_id ].wksp;

  if( ctx->funk_wksp == NULL ) {
    FD_LOG_ERR(( "no funk workspace" ));
  }

  fd_funk_t * funk = NULL;
  void * funk_shmem = NULL;
  ctx->snapshot = tile->replay.snapshot;
  if ( strncmp(ctx->snapshot, "wksp:", 5) == 0 ) {
    int err = fd_wksp_restore( ctx->funk_wksp, ctx->snapshot+5U, (uint)ctx->funk_seed );
    if (err) {
      FD_LOG_ERR(( "failed to restore %s: error %d", ctx->snapshot, err ));
    }
    fd_wksp_tag_query_info_t info;
    ulong tag = FD_FUNK_MAGIC;
    if( fd_wksp_tag_query( ctx->funk_wksp, &tag, 1, &info, 1 ) > 0 ) {
      funk_shmem = fd_wksp_laddr_fast( ctx->funk_wksp, info.gaddr_lo );
      funk = fd_funk_join( funk_shmem );
      if( funk == NULL ) {
        FD_LOG_ERR(( "failed to join funk in %s", ctx->snapshot ));
      }
    } else {
      FD_LOG_ERR(( "failed to tag query funk in %s", ctx->snapshot ));
    }
  } else {
    funk_shmem = fd_wksp_alloc_laddr( ctx->funk_wksp, fd_funk_align(), fd_funk_footprint(), FD_FUNK_MAGIC );
    if (funk_shmem == NULL) {
      FD_LOG_ERR(( "failed to allocate funk" ));
    }
    funk = fd_funk_join( fd_funk_new( funk_shmem, FD_FUNK_MAGIC, ctx->funk_seed, tile->replay.txn_max, tile->replay.index_max ) );
    if (funk == NULL) {
      fd_wksp_free_laddr(funk_shmem);
      FD_LOG_ERR(( "failed to join + new funk" ));
    }
  }

  /* Valloc setup */
  void * alloc_shalloc = fd_alloc_new( alloc_shmem, 3UL );
  if( FD_UNLIKELY( !alloc_shalloc ) ) {
    FD_LOG_ERR( ( "fd_allow_new failed" ) ); }
  fd_alloc_t * alloc = fd_alloc_join( alloc_shalloc, 3UL );
  if( FD_UNLIKELY( !alloc ) ) {
    FD_LOG_ERR( ( "fd_alloc_join failed" ) );
  }

  fd_valloc_t valloc = fd_alloc_virtual( alloc );

  ctx->epoch_ctx = fd_exec_epoch_ctx_join( fd_exec_epoch_ctx_new( ctx->epoch_ctx_mem , VOTE_ACC_MAX ) );

  ctx->snapshot    = tile->replay.snapshot;
  ctx->incremental = tile->replay.incremental;
  ctx->genesis     = tile->replay.genesis;

  ctx->curr_slot   = tile->replay.snapshot_slot;
  ctx->parent_slot = ctx->curr_slot;
  fd_memset( ctx->blockhash.uc, 0, sizeof(fd_hash_t));

  ctx->replay = fd_replay_join( fd_replay_new( replay_mem ) );
  ctx->replay->valloc       = valloc;
  ctx->replay->epoch_ctx    = ctx->epoch_ctx;

  fd_acc_mgr_t * acc_mgr = fd_acc_mgr_new( ctx->acc_mgr, funk );

  fd_forks_t * forks     = fd_forks_join( fd_forks_new( forks_mem, FD_SLOT_MAX, 42UL ) );
  FD_TEST( forks );

  forks->acc_mgr = acc_mgr;
  forks->funk = funk;
  forks->valloc = valloc;
  ctx->replay->forks = forks;

  ulong snapshot_slot = tile->replay.snapshot_slot;
  fd_fork_t * replay_slot = fd_fork_pool_ele_acquire( ctx->replay->forks->pool );
  replay_slot->slot   = snapshot_slot;
  ctx->replay->smr    = snapshot_slot;
  ctx->flags = ULONG_MAX;

  ctx->slot_ctx =
            fd_exec_slot_ctx_join( fd_exec_slot_ctx_new( &replay_slot->slot_ctx, valloc ) );
  ctx->slot_ctx->epoch_ctx = ctx->epoch_ctx;
  ctx->slot_ctx->valloc  = valloc;
  ctx->slot_ctx->acc_mgr  = acc_mgr;

  ctx->replay->acc_mgr      = ctx->slot_ctx->acc_mgr;
  ctx->replay->funk         = funk;

  ctx->max_workers = tile->replay.tpool_thread_count;
  if( FD_LIKELY( ctx->max_workers > 1 ) ) {
    tpool_boot( topo, ctx->max_workers );
  }
  ctx->tpool = fd_tpool_init( ctx->tpool_mem, ctx->max_workers );

  if( FD_LIKELY( ctx->max_workers > 1 ) ) {
    /* start the tpool workers */
    ulong tpool_worker_stack_sz = (1UL<<28UL); /* 256MB */
    uchar * tpool_worker_mem   = fd_wksp_alloc_laddr( ctx->wksp, FD_SCRATCH_ALIGN_DEFAULT, tpool_worker_stack_sz*ctx->max_workers, 421UL ); /* 256MB per thread */
    for( ulong i =1; i<ctx->max_workers; i++ ) {
      if( fd_tpool_worker_push( ctx->tpool, i, tpool_worker_mem + tpool_worker_stack_sz*(i - 1U), tpool_worker_stack_sz ) == NULL ) {
        FD_LOG_ERR(( "failed to launch worker" ));
      }
    }
  }

  ctx->replay->tpool = ctx->tpool;
  ctx->replay->max_workers = ctx->max_workers;

  if( ctx->tpool == NULL ) {
    FD_LOG_ERR(("failed to create thread pool"));
  }

  /* add it to the frontier */
  fd_fork_frontier_ele_insert( ctx->replay->forks->frontier, replay_slot, ctx->replay->forks->pool );

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
  ulong busy_obj_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "bank_busy.%lu", tile->kind_id );
  FD_TEST( busy_obj_id!=ULONG_MAX );
  ctx->bank_busy = fd_fseq_join( fd_topo_obj_laddr( topo, busy_obj_id ) );
  if( FD_UNLIKELY( !ctx->bank_busy ) ) FD_LOG_ERR(( "banking tile %lu has no busy flag", tile->kind_id ));

  ctx->bank_hash_cmp = fd_bank_hash_cmp_join( fd_bank_hash_cmp_new( bank_hash_cmp_mem ) );
  ctx->tower         = fd_tower_join( fd_tower_new( tower_mem ) );
  ctx->ghost         = fd_ghost_join( fd_ghost_new( ghost_mem, FD_SLOT_MAX, FD_VOTER_MAX, 42 ) );

  // ulong busy_obj_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "first_turbine" );
  // FD_TEST( busy_obj_id != ULONG_MAX );
  // ctx->first_turbine = fd_fseq_join( fd_topo_obj_laddr( topo, busy_obj_id ) );
  // if( FD_UNLIKELY( !ctx->first_turbine ) )
  //   FD_LOG_ERR( ( "replay tile %lu has no busy flag", tile->kind_id ) );

  ctx->poh_init_done = 0U;

  /* Set up store tile input */
  fd_topo_link_t * store_in_link = &topo->links[ tile->in_link_id[ STORE_IN_IDX ] ];
  ctx->store_in_mem    = topo->workspaces[ topo->objs[ store_in_link->dcache_obj_id ].wksp_id ].wksp;
  ctx->store_in_chunk0 = fd_dcache_compact_chunk0( ctx->store_in_mem, store_in_link->dcache );
  ctx->store_in_wmark  = fd_dcache_compact_wmark( ctx->store_in_mem, store_in_link->dcache, store_in_link->mtu );

  /* Set up pack tile input */
  fd_topo_link_t * pack_in_link = &topo->links[ tile->in_link_id[ PACK_IN_IDX ] ];
  ctx->pack_in_mem    = topo->workspaces[ topo->objs[ pack_in_link->dcache_obj_id ].wksp_id ].wksp;
  ctx->pack_in_chunk0 = fd_dcache_compact_chunk0( ctx->pack_in_mem, pack_in_link->dcache );
  ctx->pack_in_wmark  = fd_dcache_compact_wmark( ctx->pack_in_mem, pack_in_link->dcache, pack_in_link->mtu );
  
  fd_topo_link_t * poh_out_link = &topo->links[ tile->out_link_id[ POH_OUT_IDX ] ];
  ctx->poh_out_mcache = poh_out_link->mcache;
  ctx->poh_out_sync   = fd_mcache_seq_laddr( ctx->poh_out_mcache );
  ctx->poh_out_depth  = fd_mcache_depth( ctx->poh_out_mcache );
  ctx->poh_out_seq    = fd_mcache_seq_query( ctx->poh_out_sync );
  ctx->poh_out_mem    = topo->workspaces[ topo->objs[ poh_out_link->dcache_obj_id ].wksp_id ].wksp;
  ctx->poh_out_chunk0 = fd_dcache_compact_chunk0( ctx->poh_out_mem, poh_out_link->dcache );
  ctx->poh_out_wmark  = fd_dcache_compact_wmark( ctx->poh_out_mem, poh_out_link->dcache, poh_out_link->mtu );
  ctx->poh_out_chunk  = ctx->poh_out_chunk0;

  fd_topo_link_t * notif_out = &topo->links[ tile->out_link_id[ NOTIF_OUT_IDX ] ];
  ctx->notif_out_mcache = notif_out->mcache;
  ctx->notif_out_sync   = fd_mcache_seq_laddr( ctx->notif_out_mcache );
  ctx->notif_out_depth  = fd_mcache_depth( ctx->notif_out_mcache );
  ctx->notif_out_seq    = fd_mcache_seq_query( ctx->notif_out_sync );
  ctx->notif_out_mem    = topo->workspaces[ topo->objs[ notif_out->dcache_obj_id ].wksp_id ].wksp;
  ctx->notif_out_chunk0 = fd_dcache_compact_chunk0( ctx->notif_out_mem, notif_out->dcache );
  ctx->notif_out_wmark  = fd_dcache_compact_wmark ( ctx->notif_out_mem, notif_out->dcache, notif_out->mtu );
  ctx->notif_out_chunk  = ctx->notif_out_chunk0;

  /* Set up stake weights tile output */
  fd_topo_link_t * stake_weights_out = &topo->links[ tile->out_link_id_primary ];
  ctx->stake_weights_out_mcache = stake_weights_out->mcache;
  ctx->stake_weights_out_sync   = fd_mcache_seq_laddr( ctx->stake_weights_out_mcache );
  ctx->stake_weights_out_depth  = fd_mcache_depth( ctx->stake_weights_out_mcache );
  ctx->stake_weights_out_seq    = fd_mcache_seq_query( ctx->stake_weights_out_sync );
  ctx->stake_weights_out_mem    = topo->workspaces[ topo->objs[ stake_weights_out->dcache_obj_id ].wksp_id ].wksp;
  ctx->stake_weights_out_chunk0 = fd_dcache_compact_chunk0( ctx->stake_weights_out_mem, stake_weights_out->dcache );
  ctx->stake_weights_out_wmark  = fd_dcache_compact_wmark ( ctx->stake_weights_out_mem, stake_weights_out->dcache, stake_weights_out->mtu );
  ctx->stake_weights_out_chunk  = ctx->stake_weights_out_chunk0;

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, 1UL );
  if( FD_UNLIKELY( scratch_top>( (ulong)scratch + scratch_footprint( tile ) ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));
}

static ulong
populate_allowed_seccomp( void *               scratch FD_PARAM_UNUSED,
                          ulong                out_cnt,
                          struct sock_filter * out ) {
  populate_sock_filter_policy_replay( out_cnt, out, (uint)fd_log_private_logfile_fd() );
  return sock_filter_policy_replay_instr_cnt;
}

static ulong
populate_allowed_fds( void * scratch      FD_PARAM_UNUSED,
                      ulong  out_fds_cnt,
                      int *  out_fds ) {
  if( FD_UNLIKELY( out_fds_cnt<2 ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  return out_cnt;
}

fd_topo_run_tile_t fd_tile_replay = {
  .name                     = "replay",
  .mux_flags                = FD_MUX_FLAG_MANUAL_PUBLISH | FD_MUX_FLAG_COPY,
  .burst                    = 1UL,
  .loose_footprint          = loose_footprint,
  .mux_ctx                  = mux_ctx,
  .mux_after_credit         = after_credit,
  .mux_during_frag          = during_frag,
  .mux_after_frag           = after_frag,
  .mux_during_housekeeping  = during_housekeeping,
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
};
