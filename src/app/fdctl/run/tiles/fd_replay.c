#define _GNU_SOURCE

#include "tiles.h"

#include "generated/replay_seccomp.h"
#include "../../../../util/fd_util.h"
#include "../../../../util/tile/fd_tile_private.h"
#include "../../../../disco/shred/fd_stake_ci.h"
#include "../../../../disco/topo/fd_pod_format.h"
#include "../../../../disco/tvu/fd_replay.h"
#include "../../../../disco/tvu/fd_tvu.h"
#include "../../../../flamenco/runtime/context/fd_exec_epoch_ctx.h"
#include "../../../../flamenco/runtime/context/fd_exec_slot_ctx.h"
#include "../../../../flamenco/runtime/program/fd_bpf_program_util.h"
#include "../../../../flamenco/runtime/fd_borrowed_account.h"
#include "../../../../flamenco/runtime/fd_executor.h"
#include "../../../../flamenco/runtime/fd_hashes.h"
#include "../../../../flamenco/runtime/fd_snapshot_loader.h"
#include "../../../../flamenco/runtime/program/fd_builtin_programs.h"
#include "../../../../flamenco/runtime/sysvar/fd_sysvar_epoch_schedule.h"
#include "../../../../flamenco/stakes/fd_stakes.h"
#include "../../../../flamenco/fd_flamenco.h"
#include "fd_replay_notif.h"

#include <unistd.h>
#include <arpa/inet.h>
#include <linux/unistd.h>
#include <sys/random.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

/* An estimate of the max number of transactions in a block.  If there are more
   transactions, they must be split into multiple sets. */
#define MAX_TXNS_PER_REPLAY (8192UL)

#define STORE_IN_IDX   (0UL)
#define POH_OUT_IDX    (0UL)
#define NOTIF_OUT_IDX  (1UL)

/* Scratch space estimates.
   TODO: Update constants and add explanation
*/
#define SCRATCH_MAX    (1024UL /*MiB*/ << 21)
#define SCRATCH_DEPTH  (128UL) /* 128 scratch frames */

#define VOTE_ACC_MAX   (2000000UL)
#define FORKS_MAX      (fd_ulong_pow2_up( FD_DEFAULT_SLOTS_PER_EPOCH ))

struct fd_replay_tile_ctx {
  fd_wksp_t * wksp;

  // Store tile input
  fd_wksp_t * store_in_mem;
  ulong       store_in_chunk0;
  ulong       store_in_wmark;

  // PoH tile output defs
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

  long last_stake_weights_push_time;

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

  uchar        tpool_mem[FD_TPOOL_FOOTPRINT( FD_TILE_MAX )] __attribute__( ( aligned( FD_TPOOL_ALIGN ) ) );
  fd_tpool_t * tpool;
  ulong        max_workers;

  ulong funk_seed;
  fd_latest_vote_t * latest_votes;
  fd_capture_ctx_t * capture_ctx;
  FILE * capture_file;

  fd_bft_t * bft;
  fd_ghost_t * ghost;
  fd_root_stake_t * root_stakes;
  fd_root_vote_t * root_votes;


  ulong * first_turbine;
};
typedef struct fd_replay_tile_ctx fd_replay_tile_ctx_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 128UL;
}

FD_FN_PURE static inline ulong
loose_footprint( fd_topo_tile_t const * tile FD_PARAM_UNUSED ) {
  return 16UL * FD_SHMEM_GIGANTIC_PAGE_SZ;
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
  l = FD_LAYOUT_APPEND( l, fd_forks_align(), fd_forks_footprint( FORKS_MAX ) );
  l = FD_LAYOUT_APPEND( l, fd_latest_vote_deque_align(), fd_latest_vote_deque_footprint() );
  l = FD_LAYOUT_APPEND( l, FD_CAPTURE_CTX_ALIGN, FD_CAPTURE_CTX_FOOTPRINT );

  l = FD_LAYOUT_APPEND( l, fd_bft_align(), fd_bft_footprint() );
  l = FD_LAYOUT_APPEND( l, fd_ghost_align(), fd_ghost_footprint( 1 << FD_BFT_LG_SLOT_MAX, 1 << FD_LG_NODE_PUBKEY_MAX ) );
  l = FD_LAYOUT_APPEND( l, fd_root_stake_map_align(), fd_root_stake_map_footprint() );
  l = FD_LAYOUT_APPEND( l, fd_root_vote_map_align(), fd_root_vote_map_footprint() );

  return FD_LAYOUT_FINI( l, scratch_align() );
}

FD_FN_CONST static inline void *
mux_ctx( void * scratch ) {
  return (void*)fd_ulong_align_up( (ulong)scratch, alignof(fd_replay_tile_ctx_t) );
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

  if( FD_UNLIKELY( chunk<ctx->store_in_chunk0 || chunk>ctx->store_in_wmark || sz>MAX_TXNS_PER_REPLAY ) ) {
    FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->store_in_chunk0, ctx->store_in_wmark ));
  }

  void * dst_poh = fd_chunk_to_laddr( ctx->poh_out_mem, ctx->poh_out_chunk );
  uchar * src = (uchar *)fd_chunk_to_laddr( ctx->store_in_mem, chunk );

  /* Incoming packet from store tile. Format:
   * Parent slot (ulong - 8 bytes)
   * Updated block hash/PoH hash (fd_hash_t - 32 bytes)
   * Microblock as a list of fd_txn_p_t (sz * sizeof(fd_txn_p_t))
   */

  ctx->curr_slot = fd_disco_replay_sig_slot( sig );
  ctx->flags = fd_disco_replay_sig_flags( sig );

  ctx->parent_slot = FD_LOAD( ulong, src );
  src += sizeof(ulong);
  memcpy( ctx->blockhash.uc, src, sizeof(fd_hash_t) );
  src += sizeof(fd_hash_t);
  fd_memcpy( dst_poh, src, sz * sizeof(fd_txn_p_t) );

  if( ctx->flags & REPLAY_FLAG_PACKED_MICROBLOCK ) {
    /* We do not know the parent slot, pick one from fork selection */
    ulong max_slot = 0; /* FIXME: default to snapshot slot/smr */
    for( fd_fork_frontier_iter_t iter = fd_fork_frontier_iter_init( ctx->replay->forks->frontier, ctx->replay->forks->pool );
       !fd_fork_frontier_iter_done( iter, ctx->replay->forks->frontier, ctx->replay->forks->pool );
       iter = fd_fork_frontier_iter_next( iter, ctx->replay->forks->frontier, ctx->replay->forks->pool ) ) {
      fd_exec_slot_ctx_t * ele = &fd_fork_frontier_iter_ele( iter, ctx->replay->forks->frontier, ctx->replay->forks->pool )->slot_ctx;

      max_slot = ele->slot_bank.slot;
    }
    ctx->parent_slot = max_slot;
  }

  fd_blockstore_start_read( ctx->replay->blockstore );
  fd_block_t * block_ = fd_blockstore_block_query( ctx->replay->blockstore, ctx->curr_slot );
  if( FD_LIKELY( block_ ) ) {
    if( fd_uchar_extract_bit( block_->flags, FD_BLOCK_FLAG_PROCESSED ) ) {
      *opt_filter = 1;
    }
  }
  fd_blockstore_end_read( ctx->replay->blockstore );
}

static void
after_frag( void *             _ctx,
            ulong              in_idx     FD_PARAM_UNUSED,
            ulong              seq        FD_PARAM_UNUSED,
            ulong *            opt_sig    FD_PARAM_UNUSED,
            ulong *            opt_chunk  FD_PARAM_UNUSED,
            ulong *            opt_sz,
            ulong *            opt_tsorig FD_PARAM_UNUSED,
            int *              opt_filter,
            fd_mux_context_t * mux        FD_PARAM_UNUSED ) {
  fd_replay_tile_ctx_t * ctx = (fd_replay_tile_ctx_t *)_ctx;

  /* do a replay */
  ulong txn_cnt = *opt_sz;
  fd_txn_p_t * txns       = (fd_txn_p_t *)fd_chunk_to_laddr( ctx->poh_out_mem, ctx->poh_out_chunk );

  FD_SCRATCH_SCOPE_BEGIN {
    fd_fork_t * fork = fd_replay_prepare_ctx( ctx->replay, ctx->parent_slot );
    if( fork->slot_ctx.slot_bank.slot == ctx->parent_slot ) {
      // fork is advancing
      FD_LOG_NOTICE(( "new block execution - slot: %lu, parent_slot: %lu", ctx->curr_slot, ctx->parent_slot ));

      fd_latest_vote_deque_remove_all( ctx->latest_votes );
      fork->slot_ctx.latest_votes = ctx->latest_votes;

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

      res = fd_runtime_block_execute_prepare( &fork->slot_ctx );
      if( res != FD_RUNTIME_EXECUTE_SUCCESS ) {
        FD_LOG_ERR(( "block prep execute failed" ));
      }
    } else if ( fork->slot_ctx.slot_bank.slot != ctx->curr_slot ) {
      FD_LOG_ERR(( "unexpected fork switch mid block execution, cannot continue" ));
    }
    if( ctx->capture_ctx )
      fd_solcap_writer_set_slot( ctx->capture_ctx->capture, fork->slot_ctx.slot_bank.slot );

    // Exeecute all txns which were succesfully prepared
    int res = fd_runtime_execute_txns_in_waves_tpool( &fork->slot_ctx, ctx->capture_ctx,
                                                      txns, txn_cnt,
                                                      ctx->tpool, ctx->max_workers );
    if( res != 0 && !( ctx->flags & REPLAY_FLAG_PACKED_MICROBLOCK ) ) {
      FD_LOG_WARNING(( "block invalid - slot: %lu", ctx->curr_slot ));
      *opt_filter = 1;
      return;
    }
    if( ctx->flags & REPLAY_FLAG_FINALIZE_BLOCK ) {
      // Copy over latest blockhash to slot_bank poh for updating the sysvars
      fd_memcpy( fork->slot_ctx.slot_bank.poh.uc, ctx->blockhash.uc, sizeof(fd_hash_t) );
      fd_block_info_t block_info[1];
      block_info->signature_cnt = fork->slot_ctx.signature_cnt;
      int res = fd_runtime_block_execute_finalize_tpool( &fork->slot_ctx, ctx->capture_ctx, block_info, NULL, 1UL );
      if( res != FD_RUNTIME_EXECUTE_SUCCESS ) {
        FD_LOG_WARNING(("block finalize failed"));
        *opt_filter = 1;
        return;
      }

      // Notify for all the updated accounts
      ulong tsorig = fd_frag_meta_ts_comp( fd_tickcount() );
      fd_replay_notif_msg_t * msg = NULL;
      for( fd_funk_rec_t const * rec = fd_funk_txn_first_rec( ctx->replay->funk, fork->slot_ctx.funk_txn );
           rec != NULL;
           rec = fd_funk_txn_next_rec( ctx->replay->funk, rec ) ) {
        if( !fd_funk_key_is_acc( rec->pair.key ) ) continue;
        if( msg == NULL ) {
          msg = fd_chunk_to_laddr( ctx->notif_out_mem, ctx->notif_out_chunk );
          msg->type = FD_REPLAY_SAVED_TYPE;
          msg->acct_saved.funk_xid = rec->pair.xid[0];
          msg->acct_saved.acct_id_cnt = 0;
        }
        fd_memcpy( msg->acct_saved.acct_id[ msg->acct_saved.acct_id_cnt++ ].uc, rec->pair.key->uc, sizeof(fd_pubkey_t) );
        if( msg->acct_saved.acct_id_cnt == FD_REPLAY_NOTIF_ACCT_MAX ) {
          fd_mcache_publish( ctx->notif_out_mcache, ctx->notif_out_depth, ctx->notif_out_seq, 0UL, ctx->notif_out_chunk,
                             sizeof(fd_replay_notif_msg_t), 0UL, tsorig, tsorig );
          ctx->notif_out_seq   = fd_seq_inc( ctx->notif_out_seq, 1UL );
          ctx->notif_out_chunk = fd_dcache_compact_next( ctx->notif_out_chunk, sizeof(fd_replay_notif_msg_t),
                                                         ctx->notif_out_chunk0, ctx->notif_out_wmark );
          msg = NULL;
        }
      }
      if( msg ) {
        fd_mcache_publish( ctx->notif_out_mcache, ctx->notif_out_depth, ctx->notif_out_seq, 0UL, ctx->notif_out_chunk,
                           sizeof(fd_replay_notif_msg_t), 0UL, tsorig, tsorig );
        ctx->notif_out_seq   = fd_seq_inc( ctx->notif_out_seq, 1UL );
        ctx->notif_out_chunk = fd_dcache_compact_next( ctx->notif_out_chunk, sizeof(fd_replay_notif_msg_t),
                                                       ctx->notif_out_chunk0, ctx->notif_out_wmark );
      }

      fd_blockstore_start_write( ctx->replay->blockstore );

      fd_block_t * block_ = fd_blockstore_block_query( ctx->replay->blockstore, ctx->curr_slot );
      if( FD_LIKELY( block_ ) ) {
        block_->flags = fd_uchar_set_bit( block_->flags, FD_BLOCK_FLAG_PROCESSED );
        memcpy( &block_->bank_hash, &fork->slot_ctx.slot_bank.banks_hash, sizeof( fd_hash_t ) );
      }

      fd_blockstore_end_write( ctx->replay->blockstore );

      // Remove slot ctx from frontier once block is finalized
      fd_fork_t * child = fd_fork_frontier_ele_remove( ctx->replay->forks->frontier, &fork->slot, NULL, ctx->replay->forks->pool );
      child->slot = ctx->curr_slot;
      if( FD_UNLIKELY( fd_fork_frontier_ele_query(
          ctx->replay->forks->frontier, &ctx->curr_slot, NULL, ctx->replay->forks->pool ) ) ) {
        FD_LOG_ERR( ( "invariant violation: child slot %lu was already in the frontier", ctx->curr_slot ) );
      }
      fd_fork_frontier_ele_insert( ctx->replay->forks->frontier, child, ctx->replay->forks->pool );

      /* Consensus */

      // fd_bft_fork_update( ctx->bft, fork );
      // fd_bft_fork_choice( ctx->bft );

      /* Prepare bank for next execution. */

      child->slot_ctx.slot_bank.slot           = ctx->curr_slot;
      child->slot_ctx.slot_bank.collected_fees = 0;
      child->slot_ctx.slot_bank.collected_rent = 0;

      fd_hash_t const * bank_hash = &child->slot_ctx.slot_bank.banks_hash;

      fd_bank_hash_cmp_t * bank_hash_cmp = fd_exec_epoch_ctx_bank_hash_cmp( child->slot_ctx.epoch_ctx );
      fd_bank_hash_cmp_lock( bank_hash_cmp );
      fd_bank_hash_cmp_insert( bank_hash_cmp, ctx->curr_slot, bank_hash, 1 );

      /* Try to move the bank hash comparison window forward */
      ulong parent_slot = bank_hash_cmp->slot;
      for (ulong i = parent_slot; i <= ctx->curr_slot; i++) {
        if( FD_LIKELY( fd_bank_hash_cmp_check( bank_hash_cmp, i ) ) ) {
          bank_hash_cmp->slot = i;
        }
      }

      fd_bank_hash_cmp_unlock( bank_hash_cmp );

      if (NULL != ctx->capture_ctx)
        fd_solcap_writer_flush( ctx->capture_ctx->capture );
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

  char incremental_snapshot_out[128] = { 0 };
  if ( strncmp(snapshot, "wksp:", 5) == 0 ) {
    /* Already loaded the main snapshot when we initialized funk */
    if( strstr( incremental, "http" ) ) {
      // while( ULONG_MAX == fd_fseq_query( ctx->first_turbine ) ) {}
      FD_LOG_NOTICE( ( "downloading incremental snapshot..." ) );
      FILE * fp;

      /* Open the command for reading. */
      char cmd[128];
      snprintf( cmd, sizeof( cmd ), "./shenanigans.sh %s", incremental );
      FD_LOG_NOTICE( ( "cmd: %s", cmd ) );
      fp = popen( cmd, "r" );
      if( fp == NULL ) {
        printf( "Failed to run command\n" );
        exit( 1 );
      }

      /* Read the output a line at a time - output it. */
      if( !fgets( incremental_snapshot_out, sizeof( incremental_snapshot_out ) - 1, fp ) ) {
        FD_LOG_ERR( ( "failed to parse snapshot name" ) );
      }
      incremental_snapshot_out[strcspn( incremental_snapshot_out, "\n" )] = '\0';
      incremental = incremental_snapshot_out;
      pclose( fp );
    }
    if ( strlen(incremental) > 0 ) {
      ctx->epoch_ctx = fd_exec_epoch_ctx_join( fd_exec_epoch_ctx_new( ctx->epoch_ctx_mem, 2000000UL ) );
      fd_snapshot_load(incremental, ctx->slot_ctx, false, false, FD_SNAPSHOT_TYPE_INCREMENTAL );
    } else {
      fd_runtime_recover_banks( ctx->slot_ctx, 0 );
    }

  } else {
    fd_snapshot_load(snapshot, ctx->slot_ctx, false, false, FD_SNAPSHOT_TYPE_FULL );
    if ( strlen(incremental) > 0 ) {
      ctx->epoch_ctx = fd_exec_epoch_ctx_join( fd_exec_epoch_ctx_new( ctx->epoch_ctx_mem, 2000000UL ) );
      fd_snapshot_load(incremental, ctx->slot_ctx, false, false, FD_SNAPSHOT_TYPE_INCREMENTAL );
    }
  }

  fd_blockstore_snapshot_insert( ctx->slot_ctx->blockstore, &ctx->slot_ctx->slot_bank );
}

static void
init_after_snapshot( fd_replay_tile_ctx_t * ctx ) {
  ulong snapshot_slot = ctx->slot_ctx->slot_bank.slot;
  FD_LOG_NOTICE( ( "snapshot slot: %lu", snapshot_slot ) );
  if( snapshot_slot != ctx->curr_slot ) {
    /* The initial snapshot_slot was wrong or unspecified. Fix everything. */
    // FD_LOG_NOTICE(( "detected snapshot slot %lu, prev_slot %lu", snapshot_slot, ctx->slot_ctx->slot_bank.prev_slot ));
    fd_fork_t * ele = fd_fork_frontier_ele_remove( ctx->replay->forks->frontier, &ctx->curr_slot, NULL, ctx->replay->forks->pool );
    ele->slot                = snapshot_slot;
    fd_fork_frontier_ele_insert( ctx->replay->forks->frontier, ele, ctx->replay->forks->pool );
    ctx->replay->smr         = snapshot_slot;
    fd_bank_hash_cmp_t * bank_hash_cmp = fd_exec_epoch_ctx_bank_hash_cmp( ctx->epoch_ctx );
    bank_hash_cmp->slot      = snapshot_slot;
    ctx->curr_slot           = snapshot_slot;
    ctx->parent_slot         = ctx->slot_ctx->slot_bank.prev_slot;
  }

  fd_features_restore( ctx->slot_ctx );
  fd_runtime_update_leaders( ctx->slot_ctx, ctx->slot_ctx->slot_bank.slot );
  fd_calculate_epoch_accounts_hash_values( ctx->slot_ctx );
  fd_funk_start_write( ctx->slot_ctx->acc_mgr->funk );
  fd_bpf_scan_and_create_bpf_program_cache_entry( ctx->slot_ctx, ctx->slot_ctx->funk_txn );
  fd_funk_end_write( ctx->slot_ctx->acc_mgr->funk );

  ctx->bft->acc_mgr     = ctx->replay->acc_mgr;
  ctx->bft->blockstore  = ctx->replay->blockstore;
  ctx->bft->commitment  = NULL;
  ctx->bft->forks       = ctx->replay->forks;
  ctx->bft->funk        = ctx->replay->funk;
  ctx->bft->ghost       = ctx->ghost;
  ctx->bft->root_stakes = ctx->root_stakes;
  ctx->bft->root_votes  = ctx->root_votes;
  ctx->bft->valloc      = ctx->replay->valloc;

  ctx->bft->snapshot_slot = snapshot_slot;
  ctx->bft->smr           = snapshot_slot;
  fd_bft_epoch_stake_update( ctx->bft, ctx->epoch_ctx );

  fd_slot_hash_t key = { .slot = snapshot_slot,
                         .hash = ctx->slot_ctx->slot_bank.banks_hash };
  fd_ghost_leaf_insert( ctx->ghost, &key, NULL );
}

static void
after_credit( void *             _ctx,
              fd_mux_context_t * mux_ctx ) {
  fd_replay_tile_ctx_t * ctx = (fd_replay_tile_ctx_t *)_ctx;

  // Poll for blockstore
  if ( FD_UNLIKELY( ctx->slot_ctx->blockstore == NULL ) ) {
    ulong tag = FD_BLOCKSTORE_MAGIC;
    fd_wksp_tag_query_info_t info;
    if ( fd_wksp_tag_query(ctx->blockstore_wksp, &tag, 1, &info, 1) > 0 ) {
      void * shmem = fd_wksp_laddr_fast( ctx->blockstore_wksp, info.gaddr_lo );
      ctx->slot_ctx->blockstore = fd_blockstore_join( shmem );
    }

    if ( ctx->slot_ctx->blockstore != NULL ) {
      FD_SCRATCH_SCOPE_BEGIN {
        ctx->replay->blockstore = ctx->slot_ctx->blockstore;
        ctx->replay->forks->blockstore = ctx->slot_ctx->blockstore;
        FD_LOG_WARNING(("reading snapshot"));
        uchar is_snapshot = strlen( ctx->snapshot ) > 0;
        if ( is_snapshot ) {
          read_snapshot( ctx, ctx->snapshot, ctx->incremental );
        }
        fd_bank_hash_cmp_t * bank_hash_cmp = fd_exec_epoch_ctx_bank_hash_cmp( ctx->epoch_ctx );
        bank_hash_cmp->slot = ctx->replay->smr;

        fd_runtime_read_genesis( ctx->slot_ctx, ctx->genesis, is_snapshot );

        init_after_snapshot( ctx );
      } FD_SCRATCH_SCOPE_END;
    }
  }

  ulong tsorig = fd_frag_meta_ts_comp( fd_tickcount() );

  long now = fd_log_wallclock();
  if( now - ctx->last_stake_weights_push_time > (long)5e9 ) {
    ctx->last_stake_weights_push_time = now;
    fd_epoch_bank_t * epoch_bank = fd_exec_epoch_ctx_epoch_bank( ctx->slot_ctx->epoch_ctx );
    if( ctx->slot_ctx->slot_bank.epoch_stakes.vote_accounts_root!=NULL ) {
      ulong * stake_weights_msg         = fd_chunk_to_laddr( ctx->stake_weights_out_mem, ctx->stake_weights_out_chunk );
      fd_stake_weight_t * stake_weights = (fd_stake_weight_t *)&stake_weights_msg[4];
      ulong stake_weight_idx            = fd_stake_weights_by_node( &ctx->slot_ctx->slot_bank.epoch_stakes, stake_weights );

      stake_weights_msg[0] = fd_slot_to_leader_schedule_epoch( &epoch_bank->epoch_schedule, ctx->slot_ctx->slot_bank.slot ) - 1; /* epoch */
      stake_weights_msg[1] = stake_weight_idx; /* staked_cnt */
      stake_weights_msg[2] = fd_epoch_slot0( &epoch_bank->epoch_schedule, stake_weights_msg[0] ); /* start_slot */
      stake_weights_msg[3] = epoch_bank->epoch_schedule.slots_per_epoch; /* slot_cnt */
      // FD_LOG_WARNING(("Sending stake weights %lu %lu %lu %lu", stake_weights_msg[0], stake_weights_msg[1], stake_weights_msg[2], stake_weights_msg[3]));
      ulong tspub = fd_frag_meta_ts_comp( fd_tickcount() );

      ulong stake_weights_sz  = 4*sizeof(ulong) + (stake_weight_idx * sizeof(fd_stake_weight_t));
      ulong stake_weights_sig = 4UL;
      fd_mux_publish( mux_ctx, stake_weights_sig, ctx->stake_weights_out_chunk, stake_weights_sz, 0UL, tsorig, tspub );
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
      // FD_LOG_WARNING(("Sending stake weights %lu %lu %lu %lu", stake_weights_msg[0], stake_weights_msg[1], stake_weights_msg[2], stake_weights_msg[3]));
      ulong tspub = fd_frag_meta_ts_comp( fd_tickcount() );

      ulong stake_weights_sz = 4*sizeof(ulong) + (stake_weight_idx * sizeof(fd_stake_weight_t));
      ulong stake_weights_sig = 4UL;
      fd_mcache_publish( ctx->stake_weights_out_mcache, ctx->stake_weights_out_depth, ctx->stake_weights_out_seq, stake_weights_sig, ctx->stake_weights_out_chunk,
        stake_weights_sz, 0UL, tsorig, tspub );
      ctx->stake_weights_out_seq   = fd_seq_inc( ctx->stake_weights_out_seq, 1UL );
      ctx->stake_weights_out_chunk = fd_dcache_compact_next( ctx->stake_weights_out_chunk, stake_weights_sz, ctx->stake_weights_out_chunk0, ctx->stake_weights_out_wmark );
    }
  }
}

static void
during_housekeeping( void * _ctx ) {
  fd_replay_tile_ctx_t * ctx = (fd_replay_tile_ctx_t *)_ctx;
  (void)ctx;
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
  void * forks_mem           = FD_SCRATCH_ALLOC_APPEND( l, fd_forks_align(), fd_forks_footprint( FORKS_MAX ) );
  void * latest_votes_mem    = FD_SCRATCH_ALLOC_APPEND( l, fd_latest_vote_deque_align(), fd_latest_vote_deque_footprint() );
  void * capture_ctx_mem     = FD_SCRATCH_ALLOC_APPEND( l, FD_CAPTURE_CTX_ALIGN, FD_CAPTURE_CTX_FOOTPRINT );

  /* consensus */

  void * bft_mem             = FD_SCRATCH_ALLOC_APPEND( l, fd_bft_align(), fd_bft_footprint() );
  void * ghost_mem           = FD_SCRATCH_ALLOC_APPEND( l, fd_ghost_align(), fd_ghost_footprint( 1 << FD_BFT_LG_SLOT_MAX, 1 << FD_LG_NODE_PUBKEY_MAX ) );
  void * root_votes_mem      = FD_SCRATCH_ALLOC_APPEND( l, fd_root_vote_map_align(), fd_root_vote_map_footprint() );
  void * root_stakes_mem     = FD_SCRATCH_ALLOC_APPEND( l, fd_root_stake_map_align(), fd_root_stake_map_footprint() );

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
  void * shmem = NULL;
  ctx->snapshot = tile->replay.snapshot;
  if ( strncmp(ctx->snapshot, "wksp:", 5) == 0 ) {
    int err = fd_wksp_restore( ctx->funk_wksp, ctx->snapshot+5U, (uint)ctx->funk_seed );
    if (err) {
      FD_LOG_ERR(( "failed to restore %s: error %d", ctx->snapshot, err ));
    }
    fd_wksp_tag_query_info_t info;
    ulong tag = FD_FUNK_MAGIC;
    if( fd_wksp_tag_query( ctx->funk_wksp, &tag, 1, &info, 1 ) > 0 ) {
      shmem = fd_wksp_laddr_fast( ctx->funk_wksp, info.gaddr_lo );
      funk = fd_funk_join( shmem );
      if( funk == NULL ) {
        FD_LOG_ERR(( "failed to join a funky in %s", ctx->snapshot ));
      }
    } else {
      FD_LOG_ERR(( "failed to find a funky in %s", ctx->snapshot ));
    }

  } else {
    shmem = fd_wksp_alloc_laddr( ctx->funk_wksp, fd_funk_align(), fd_funk_footprint(), FD_FUNK_MAGIC );
    if (shmem == NULL)
      FD_LOG_ERR(( "failed to allocate a funky" ));
    funk = fd_funk_join( fd_funk_new( shmem, FD_FUNK_MAGIC, ctx->funk_seed, tile->replay.txn_max, tile->replay.index_max ) );
    if (funk == NULL) {
      fd_wksp_free_laddr(shmem);
      FD_LOG_ERR(( "failed to allocate a funky" ));
    }
  }

  ctx->last_stake_weights_push_time = 0;

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

  fd_forks_t * forks     = fd_forks_join( fd_forks_new( forks_mem, FORKS_MAX, 42UL ) );
  FD_TEST( forks );

  forks->acc_mgr = acc_mgr;
  forks->funk = funk;
  forks->valloc = valloc;
  ctx->replay->forks = forks;

  ulong snapshot_slot = tile->replay.snapshot_slot;
  fd_fork_t * replay_slot = fd_fork_pool_ele_acquire( ctx->replay->forks->pool );
  replay_slot->slot   = snapshot_slot;
  ctx->replay->smr    = snapshot_slot;

  fd_bank_hash_cmp_t * bank_hash_cmp = fd_exec_epoch_ctx_bank_hash_cmp( ctx->epoch_ctx );
  bank_hash_cmp->slot = snapshot_slot;

  ctx->slot_ctx =
            fd_exec_slot_ctx_join( fd_exec_slot_ctx_new( &replay_slot->slot_ctx, valloc ) );
  ctx->slot_ctx->epoch_ctx = ctx->epoch_ctx;
  ctx->slot_ctx->valloc  = valloc;
  ctx->slot_ctx->acc_mgr  = acc_mgr;

  ctx->replay->acc_mgr      = ctx->slot_ctx->acc_mgr;
  ctx->replay->funk         = funk;

  ctx->max_workers = tile->replay.tpool_thread_count;
  if( FD_LIKELY( ctx->max_workers > 1 ) )
    tpool_boot( topo, ctx->max_workers );
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

  ctx->latest_votes = fd_latest_vote_deque_join( fd_latest_vote_deque_new( latest_votes_mem ) );
  ctx->slot_ctx->latest_votes = ctx->latest_votes;

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

  ctx->bft = fd_bft_join( fd_bft_new( bft_mem ) );
  ctx->ghost = fd_ghost_join( fd_ghost_new( ghost_mem, 1 << FD_BFT_LG_SLOT_MAX, 1 << FD_LG_NODE_PUBKEY_MAX, 42 ) );
  ctx->root_votes = fd_root_vote_map_join( fd_root_vote_map_new( root_votes_mem ) );
  ctx->root_stakes = fd_root_stake_map_join( fd_root_stake_map_new( root_stakes_mem ) );
  ctx->replay->bft = ctx->bft;

  ulong busy_obj_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "first_turbine" );
  FD_TEST( busy_obj_id!=ULONG_MAX );
  ctx->first_turbine = fd_fseq_join( fd_topo_obj_laddr( topo, busy_obj_id ) );
  if( FD_UNLIKELY( !ctx->first_turbine ) ) FD_LOG_ERR(( "replay tile %lu has no busy flag", tile->kind_id ));

  /* Set up store tile input */
  fd_topo_link_t * store_in_link = &topo->links[ tile->in_link_id[ STORE_IN_IDX ] ];
  ctx->store_in_mem    = topo->workspaces[ topo->objs[ store_in_link->dcache_obj_id ].wksp_id ].wksp;
  ctx->store_in_chunk0 = fd_dcache_compact_chunk0( ctx->store_in_mem, store_in_link->dcache );
  ctx->store_in_wmark  = fd_dcache_compact_wmark( ctx->store_in_mem, store_in_link->dcache, store_in_link->mtu );

  fd_topo_link_t * poh_out_link = &topo->links[ tile->out_link_id[ POH_OUT_IDX ] ];
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
