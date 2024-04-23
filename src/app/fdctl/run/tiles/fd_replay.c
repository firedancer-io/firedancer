#define _GNU_SOURCE 

#include "tiles.h"

#include "generated/replay_seccomp.h"
#include "../../../../util/fd_util.h"
#include "../../../../disco/shred/fd_stake_ci.h"
#include "../../../../disco/tvu/fd_replay.h"
#include "../../../../disco/tvu/fd_tvu.h"

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

#include "../../../../util/net/fd_eth.h"
#include "../../../../util/net/fd_ip4.h"
#include "../../../../util/net/fd_udp.h"

#define IN_IDX    0
#define POH_OUT_IDX    0
#define STORE_OUT_IDX  1

struct fd_replay_tile_ctx {
  fd_wksp_t * wksp;

  // Store tile input
  fd_wksp_t * in_mem;
  ulong       in_chunk0;
  ulong       in_wmark;

  // PoH tile output defs
  fd_frag_meta_t * poh_out_mcache;
  ulong *          poh_out_sync;
  ulong            poh_out_depth;
  ulong            poh_out_seq;

  fd_wksp_t * poh_out_mem;
  ulong       poh_out_chunk0;
  ulong       poh_out_wmark;
  ulong       poh_out_chunk;

  // Store tile output defs
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

  long last_stake_weights_push_time;

  fd_acc_mgr_t          acc_mgr[1];
  uchar               * epoch_ctx_mem;
  fd_exec_epoch_ctx_t * epoch_ctx;
  fd_exec_slot_ctx_t *  slot_ctx;

  fd_replay_t *         replay;

  fd_wksp_t  * blockstore_wksp;
  char const * snapshot;
  char const * incremental;
  char const * genesis;

  ulong curr_slot;
  ulong parent_slot;
  ulong flags;
  fd_hash_t blockhash;
  
  uchar tpool_mem[FD_TPOOL_FOOTPRINT( FD_TILE_MAX )] __attribute__( ( aligned( FD_TPOOL_ALIGN ) ) );
  fd_tpool_t * tpool;
  ulong max_workers;
};
typedef struct fd_replay_tile_ctx fd_replay_tile_ctx_t;


FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 4096UL;
}

FD_FN_PURE static inline ulong
loose_footprint( fd_topo_tile_t * tile ) {
  (void)tile;
  return 9UL * FD_SHMEM_GIGANTIC_PAGE_SZ;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t * tile ) {
  (void)tile;

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_replay_tile_ctx_t), sizeof(fd_replay_tile_ctx_t) );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

FD_FN_CONST static inline void *
mux_ctx( void * scratch ) {
  return (void*)fd_ulong_align_up( (ulong)scratch, alignof(fd_replay_tile_ctx_t) );
}

static void
before_frag( void * _ctx,
             ulong  in_idx,
             ulong  seq,
             ulong  sig,
             int *  opt_filter ) {
  (void)seq;
  (void)sig;
  (void)opt_filter;

  fd_replay_tile_ctx_t * ctx = (fd_replay_tile_ctx_t *)_ctx;
  
  if( FD_UNLIKELY( in_idx!=IN_IDX ) ) {
    return;
  }

  ctx->curr_slot = fd_disco_replay_sig_slot( sig );
  ctx->flags = fd_disco_replay_sig_flags( sig );
}

static void
during_frag( void * _ctx,
             ulong  in_idx,
             ulong  seq,
             ulong  sig,
             ulong  chunk,
             ulong  sz,
             int *  opt_filter ) {
  (void)seq;
  (void)sig;

  fd_replay_tile_ctx_t * ctx = (fd_replay_tile_ctx_t *)_ctx;

  if( FD_UNLIKELY( in_idx!=IN_IDX ) ) {
    return;
  }
  
  if( FD_UNLIKELY( chunk<ctx->in_chunk0 || chunk>ctx->in_wmark || sz>FD_NET_MTU ) ) {
    FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->in_chunk0, ctx->in_wmark ));
    *opt_filter = 1;
    return;
  }

  void * dst_poh = fd_chunk_to_laddr( ctx->poh_out_mem, ctx->poh_out_chunk );
  uchar * src = (uchar *)fd_chunk_to_laddr( ctx->in_mem, chunk );
     
  /* Incoming packet from store tile. Format:
   * Parent slot (ulong - 8 bytes)
   * Updated block hash/PoH hash (fd_hash_t - 32 bytes)
   * Microblock as a list of fd_txn_p_t (sz * sizeof(fd_txn_p_t))
   */

  ctx->parent_slot = FD_LOAD( ulong, src );
  src += sizeof(ulong);
  memcpy( ctx->blockhash.uc, src, sizeof(fd_hash_t) );
  src += sizeof(fd_hash_t);
  fd_memcpy( dst_poh, src, sz * sizeof(fd_txn_p_t) );

  FD_LOG_WARNING(( "TXN SZ: %lu", sz ));

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
}

static void
after_frag( void *             _ctx,
            ulong              in_idx,
            ulong              seq,
            ulong *            opt_sig,
            ulong *            opt_chunk,
            ulong *            opt_sz,
            ulong *            opt_tsorig,
            int *              opt_filter,
            fd_mux_context_t * mux ) {
  (void)in_idx;
  (void)opt_chunk;
  (void)opt_sz;
  (void)opt_filter;
  (void)mux;
  (void)seq;
  (void)opt_tsorig;
  (void)opt_sig;

  fd_replay_tile_ctx_t * ctx = (fd_replay_tile_ctx_t *)_ctx;

  if( FD_UNLIKELY( in_idx!=IN_IDX ) ) {
    return;
  }

  /* do a replay */
  // ulong tsorig = fd_frag_meta_ts_comp( fd_tickcount() );
  ulong txn_cnt = *opt_sz;
  fd_txn_p_t * txns       = (fd_txn_p_t *)fd_chunk_to_laddr( ctx->poh_out_mem, ctx->poh_out_chunk );
  // fd_txn_p_t * store_txns = (fd_txn_p_t *)fd_chunk_to_laddr( ctx->store_out_mem, ctx->store_out_chunk );

  FD_SCRATCH_SCOPE_BEGIN {
    fd_execute_txn_task_info_t * task_info = fd_scratch_alloc( 8UL, txn_cnt * sizeof(fd_execute_txn_task_info_t) );

    fd_fork_t * fork = fd_replay_prepare_ctx( ctx->replay, ctx->parent_slot );
    if( fork->slot_ctx.slot_bank.slot == ctx->parent_slot ) {
      // fork is advancing
      FD_LOG_NOTICE(( "new block execution - slot: %lu, parent_slot: %lu", ctx->curr_slot, ctx->parent_slot ));
      fork->slot_ctx.slot_bank.prev_slot = fork->slot_ctx.slot_bank.slot;
      fork->slot_ctx.slot_bank.slot      = ctx->curr_slot;
  
      fd_funk_txn_xid_t xid;

      fd_memcpy(xid.uc, ctx->blockhash.uc, sizeof(fd_funk_txn_xid_t));
      xid.ul[0] = fork->slot_ctx.slot_bank.slot;
      /* push a new transaction on the stack */
      fork->slot_ctx.funk_txn = fd_funk_txn_prepare(ctx->replay->funk, fork->slot_ctx.funk_txn, &xid, 1);

      int res = fd_runtime_block_execute_prepare( &fork->slot_ctx );
      if( res != FD_RUNTIME_EXECUTE_SUCCESS ) {
        FD_LOG_ERR(( "block prep execute failed" ));
      }
    } else if ( fork->slot_ctx.slot_bank.slot != ctx->curr_slot ) {
      FD_LOG_ERR(( "unexpected fork switch mid block execution, cannot continue" ));
    }

    int res = fd_runtime_prepare_txns( &fork->slot_ctx, task_info, txns, txn_cnt );
    if( res != 0 && !( ctx->flags & REPLAY_FLAG_PACKED_MICROBLOCK ) ) {
      FD_LOG_WARNING(( "block invalid - slot: %lu", ctx->curr_slot ));
      // TODO: need to yeet this block from the replay frontier.
      return;
    }

    // ulong msg_sz = txn_cnt * sizeof(fd_txn_p_t);
    // ulong sig = opt_sig == NULL ? 0 : *opt_sig;
    // ulong tspub  = (ulong)fd_frag_meta_ts_comp( fd_tickcount() );

    // // Publish microblock to poh tile for stamping
    // fd_mcache_publish( ctx->poh_out_mcache, ctx->poh_out_depth, ctx->poh_out_seq, sig, ctx->poh_out_chunk,
    //     msg_sz, 0UL, tsorig, tspub );
    // ctx->poh_out_seq   = fd_seq_inc( ctx->poh_out_seq, 1UL );
    // ctx->poh_out_chunk = fd_dcache_compact_next( ctx->poh_out_chunk, msg_sz, ctx->poh_out_chunk0, ctx->poh_out_wmark );
    // if ( res != 0 ) {
    //   FD_LOG_DEBUG(("Prepare failed"));
    // }

    // Exeecute all txns which were succesfully prepared
    res = fd_runtime_execute_txns_tpool( &fork->slot_ctx, NULL,
                                        txns, txn_cnt, task_info,
                                        ctx->tpool, ctx->max_workers );
    if ( res != 0 ) {
      FD_LOG_WARNING(("txn finalize failed, should not happen"));
      *opt_filter = 1;
      return;
    }

    if( ctx->flags & REPLAY_FLAG_FINALIZE_BLOCK ) {
      fd_fork_t * replay_ctx = fd_replay_prepare_ctx( ctx->replay, ctx->parent_slot );
      // Copy over latest blockhash to slot_bank poh for updating the sysvars
      fd_memcpy( replay_ctx->slot_ctx.slot_bank.poh.uc, ctx->blockhash.uc, sizeof(fd_hash_t) );
      fd_block_info_t block_info[1];
      block_info->signature_cnt = replay_ctx->slot_ctx.signature_cnt;
      int res = fd_runtime_block_execute_finalize_tpool( &replay_ctx->slot_ctx, NULL, block_info, NULL, 1UL );
      if( res != FD_RUNTIME_EXECUTE_SUCCESS ) {
        FD_LOG_WARNING(("block finalize failed"));
        *opt_filter = 1;
        return;
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
      if( FD_UNLIKELY( fd_fork_frontier_ele_query(
          ctx->replay->forks->frontier, &ctx->curr_slot, NULL, ctx->replay->forks->pool ) ) ) {
        FD_LOG_ERR( ( "invariant violation: child slot %lu was already in the frontier", ctx->curr_slot ) );
      }
      fd_fork_frontier_ele_insert( ctx->replay->forks->frontier, child, ctx->replay->forks->pool );
    }

    
    // // Copy over microblock to dcache for store tile
    // fd_memcpy( store_txns, txns, msg_sz );
    // tspub  = (ulong)fd_frag_meta_ts_comp( fd_tickcount() );

    // // Publish to store tile with updated flags for execution
    // fd_mcache_publish( ctx->store_out_mcache, ctx->store_out_depth, ctx->store_out_seq, sig, ctx->store_out_chunk,
    //     msg_sz, 0UL, tsorig, tspub );
    // ctx->store_out_seq   = fd_seq_inc( ctx->store_out_seq, 1UL );
    // ctx->store_out_chunk = fd_dcache_compact_next( ctx->store_out_chunk, msg_sz, ctx->store_out_chunk0, ctx->store_out_wmark );
    *opt_filter = 0;

  } FD_SCRATCH_SCOPE_END;
}

static void
read_genesis( void * _ctx, char const * genesis_filepath, uchar is_snapshot ) {
  if ( strlen( genesis_filepath ) == 0 ) return;
  fd_replay_tile_ctx_t * ctx = (fd_replay_tile_ctx_t *)_ctx;
  // TODO: Have a solcap capture?
  fd_capture_ctx_t *    capture_ctx  = NULL;

  struct stat sbuf;
  if( FD_UNLIKELY( stat( genesis_filepath, &sbuf) < 0 ) )
    FD_LOG_ERR(("cannot open %s : %s", genesis_filepath, strerror(errno)));
  int fd = open( genesis_filepath, O_RDONLY );
  if( FD_UNLIKELY( fd < 0 ) )
    FD_LOG_ERR(("cannot open %s : %s", genesis_filepath, strerror(errno)));
  uchar * buf = malloc((ulong) sbuf.st_size);  /* TODO Make this a scratch alloc */
  ssize_t n = read(fd, buf, (ulong) sbuf.st_size);
  close(fd);

  fd_genesis_solana_t genesis_block;
  fd_genesis_solana_new(&genesis_block);
  fd_bincode_decode_ctx_t decode_ctx = {
    .data    = buf,
    .dataend = buf + n,
    .valloc  = ctx->slot_ctx->valloc,
  };
  if( fd_genesis_solana_decode(&genesis_block, &decode_ctx) )
    FD_LOG_ERR(("fd_genesis_solana_decode failed"));

  // The hash is generated from the raw data... don't mess with this..
  fd_hash_t genesis_hash;
  fd_sha256_hash( buf, (ulong)n, genesis_hash.uc );
  FD_LOG_NOTICE(( "Genesis Hash: %32J", &genesis_hash ));
  fd_epoch_bank_t * epoch_bank = fd_exec_epoch_ctx_epoch_bank( ctx->slot_ctx->epoch_ctx );
  fd_memcpy( epoch_bank->genesis_hash.uc, genesis_hash.uc, 32U );
  epoch_bank->cluster_type = genesis_block.cluster_type;

  free(buf);
  if ( !is_snapshot ) {
    fd_runtime_init_bank_from_genesis( ctx->slot_ctx, &genesis_block, &genesis_hash );

    fd_runtime_init_program( ctx->slot_ctx );

    FD_LOG_DEBUG(( "start genesis accounts - count: %lu", genesis_block.accounts_len));

    for( ulong i=0; i < genesis_block.accounts_len; i++ ) {
      fd_pubkey_account_pair_t * a = &genesis_block.accounts[i];

      FD_BORROWED_ACCOUNT_DECL(rec);

      int err = fd_acc_mgr_modify(
        ctx->slot_ctx->acc_mgr,
        ctx->slot_ctx->funk_txn,
        &a->key,
        /* do_create */ 1,
        a->account.data_len,
        rec);
      if( FD_UNLIKELY( err ) )
        FD_LOG_ERR(( "fd_acc_mgr_modify failed (%d)", err ));

      rec->meta->dlen            = a->account.data_len;
      rec->meta->info.lamports   = a->account.lamports;
      rec->meta->info.rent_epoch = a->account.rent_epoch;
      rec->meta->info.executable = a->account.executable;
      memcpy( rec->meta->info.owner, a->account.owner.key, 32UL );
      if( a->account.data_len )
        memcpy( rec->data, a->account.data, a->account.data_len );
    }

    FD_LOG_DEBUG(( "end genesis accounts"));

    FD_LOG_DEBUG(( "native instruction processors - count: %lu", genesis_block.native_instruction_processors_len));

    for( ulong i=0; i < genesis_block.native_instruction_processors_len; i++ ) {
      fd_string_pubkey_pair_t * a = &genesis_block.native_instruction_processors[i];
      fd_write_builtin_bogus_account( ctx->slot_ctx, a->pubkey.uc, a->string, strlen(a->string) );
    }

    /* sort and update bank hash */
    int result = fd_update_hash_bank( ctx->slot_ctx, capture_ctx, &ctx->slot_ctx->slot_bank.banks_hash, ctx->slot_ctx->signature_cnt );
    if (result != FD_EXECUTOR_INSTR_SUCCESS) {
      FD_LOG_ERR(("Failed to update bank hash with error=%d", result));
    }

    ctx->slot_ctx->slot_bank.slot = 0UL;
  }
  FD_TEST( FD_RUNTIME_EXECUTE_SUCCESS == fd_runtime_save_epoch_bank( ctx->slot_ctx ) );

  FD_TEST( FD_RUNTIME_EXECUTE_SUCCESS == fd_runtime_save_slot_bank( ctx->slot_ctx ) );

  fd_bincode_destroy_ctx_t ctx2 = { .valloc = ctx->slot_ctx->valloc };
  fd_genesis_solana_destroy(&genesis_block, &ctx2);

  // if( capture_ctx )  {
  //   fd_solcap_writer_fini( capture_ctx->capture );
  // }
}

static void
read_snapshot( void * _ctx, char const * snapshotfile, char const * incremental ) {
  fd_replay_tile_ctx_t * ctx = (fd_replay_tile_ctx_t *)_ctx;

  const char * snapshot = snapshotfile;

  fd_snapshot_load(snapshot, ctx->slot_ctx, false, false, FD_SNAPSHOT_TYPE_FULL );
  if ( strlen(incremental) > 0 ) {
    fd_snapshot_load(incremental, ctx->slot_ctx, false, false, FD_SNAPSHOT_TYPE_INCREMENTAL );
  }
}

static void
during_housekeeping( void * _ctx ) {
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

        read_genesis( ctx, ctx->genesis, is_snapshot );

        fd_features_restore( ctx->slot_ctx );
        fd_runtime_update_leaders( ctx->slot_ctx, ctx->slot_ctx->slot_bank.slot );
        fd_calculate_epoch_accounts_hash_values( ctx->slot_ctx );
        fd_bpf_scan_and_create_bpf_program_cache_entry( ctx->slot_ctx, ctx->slot_ctx->funk_txn );
      } FD_SCRATCH_SCOPE_END;
    }
  }

  ulong tsorig = fd_frag_meta_ts_comp( fd_tickcount() );

  long now = fd_log_wallclock();
  if( now - ctx->last_stake_weights_push_time > (long)5e9 ) {
    ctx->last_stake_weights_push_time = now;
    fd_epoch_bank_t * epoch_bank = fd_exec_epoch_ctx_epoch_bank( ctx->slot_ctx->epoch_ctx );
    {
      ulong * stake_weights_msg = fd_chunk_to_laddr( ctx->stake_weights_out_mem, ctx->stake_weights_out_chunk );
      fd_stake_weight_t * stake_weights = (fd_stake_weight_t *)&stake_weights_msg[4];
      ulong stake_weight_idx = fd_stake_weights_by_node( &ctx->slot_ctx->slot_bank.epoch_stakes, stake_weights );

      stake_weights_msg[0] = fd_slot_to_leader_schedule_epoch( &epoch_bank->epoch_schedule, ctx->slot_ctx->slot_bank.slot ) - 1; /* epoch */
      stake_weights_msg[1] = stake_weight_idx; /* staked_cnt */
      stake_weights_msg[2] = fd_epoch_slot0( &epoch_bank->epoch_schedule, stake_weights_msg[0] ); /* start_slot */
      stake_weights_msg[3] = epoch_bank->epoch_schedule.slots_per_epoch; /* slot_cnt */
      FD_LOG_WARNING(("Sending stake weights %lu %lu %lu %lu", stake_weights_msg[0], stake_weights_msg[1], stake_weights_msg[2], stake_weights_msg[3]));
      ulong tspub = fd_frag_meta_ts_comp( fd_tickcount() );

      ulong stake_weights_sz = 4*sizeof(ulong) + (stake_weight_idx * sizeof(fd_stake_weight_t));
      ulong stake_weights_sig = 4UL;
      fd_mcache_publish( ctx->stake_weights_out_mcache, ctx->stake_weights_out_depth, ctx->stake_weights_out_seq, stake_weights_sig, ctx->stake_weights_out_chunk,
        stake_weights_sz, 0UL, tsorig, tspub );
      ctx->stake_weights_out_seq   = fd_seq_inc( ctx->stake_weights_out_seq, 1UL );
      ctx->stake_weights_out_chunk = fd_dcache_compact_next( ctx->stake_weights_out_chunk, stake_weights_sz, ctx->stake_weights_out_chunk0, ctx->stake_weights_out_wmark );
    }

    {
      ulong * stake_weights_msg = fd_chunk_to_laddr( ctx->stake_weights_out_mem, ctx->stake_weights_out_chunk );
      fd_stake_weight_t * stake_weights = (fd_stake_weight_t *)&stake_weights_msg[4];
      ulong stake_weight_idx = fd_stake_weights_by_node( &epoch_bank->next_epoch_stakes, stake_weights );

      stake_weights_msg[0] = fd_slot_to_leader_schedule_epoch( &epoch_bank->epoch_schedule, ctx->slot_ctx->slot_bank.slot ); /* epoch */
      stake_weights_msg[1] = stake_weight_idx; /* staked_cnt */
      stake_weights_msg[2] = fd_epoch_slot0( &epoch_bank->epoch_schedule, stake_weights_msg[0] ); /* start_slot */
      stake_weights_msg[3] = epoch_bank->epoch_schedule.slots_per_epoch; /* slot_cnt */
      FD_LOG_WARNING(("Sending stake weights %lu %lu %lu %lu", stake_weights_msg[0], stake_weights_msg[1], stake_weights_msg[2], stake_weights_msg[3]));
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
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile,
                 void *           scratch ) {
  (void)topo;
  (void)tile;
  (void)scratch;

}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile,
                   void *           scratch ) {
  // if( FD_UNLIKELY( tile->in_cnt != 1 ||
  //                  topo->links[ tile->in_link_id[ STORE_IN_IDX     ] ].kind != FD_TOPO_LINK_KIND_STORE_TO_REPLAY ) ) {
  //   FD_LOG_ERR(( "replay tile has none or unexpected input links %lu %lu %lu",
  //                tile->in_cnt, topo->links[ tile->in_link_id[ 0 ] ].kind, topo->links[ tile->in_link_id[ 1 ] ].kind ));
  // }
  
  if( FD_UNLIKELY( tile->out_link_id_primary == ULONG_MAX ) )
    FD_LOG_ERR(( "store tile missing a primary output link" ));

  /* Scratch mem setup */
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_replay_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_replay_tile_ctx_t), sizeof(fd_replay_tile_ctx_t) );
  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, 1UL );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));
  
  ctx->wksp = topo->workspaces[ tile->wksp_id ].wksp;

  void * alloc_shmem = fd_wksp_alloc_laddr( ctx->wksp, fd_alloc_align(), fd_alloc_footprint(), 3UL );
  if( FD_UNLIKELY( !alloc_shmem ) ) { 
    FD_LOG_ERR( ( "fd_alloc too large for workspace" ) ); 
  }

  for (ulong i = 0; i < topo->wksp_cnt; i++) {
    if ( topo->workspaces[i].kind == FD_TOPO_WKSP_KIND_BLOCKSTORE ) {
      ctx->blockstore_wksp = topo->workspaces[i].wksp;
    }
  }

  if ( ctx->blockstore_wksp == NULL ) {
    FD_LOG_ERR( ( "Blockstore wksp not found" ) );
  }

  ctx->last_stake_weights_push_time = 0;

  /* Set up shred tile input */
  fd_topo_link_t * in_link = &topo->links[ tile->in_link_id[ IN_IDX ] ];
  ctx->in_mem    = topo->workspaces[ in_link->wksp_id ].wksp;
  ctx->in_chunk0 = fd_dcache_compact_chunk0( ctx->in_mem, in_link->dcache );
  ctx->in_wmark  = fd_dcache_compact_wmark( ctx->in_mem, in_link->dcache, in_link->mtu );

  fd_topo_link_t * poh_out_link = &topo->links[ tile->out_link_id[ POH_OUT_IDX ] ];
  ctx->poh_out_mem    = topo->workspaces[ poh_out_link->wksp_id ].wksp;
  ctx->poh_out_chunk0 = fd_dcache_compact_chunk0( ctx->poh_out_mem, poh_out_link->dcache );
  ctx->poh_out_wmark  = fd_dcache_compact_wmark( ctx->poh_out_mem, poh_out_link->dcache, poh_out_link->mtu );
  ctx->poh_out_chunk  = ctx->poh_out_chunk0;

  fd_topo_link_t * store_out_link = &topo->links[ tile->out_link_id[ STORE_OUT_IDX ] ];
  ctx->store_out_mem    = topo->workspaces[ store_out_link->wksp_id ].wksp;
  ctx->store_out_chunk0 = fd_dcache_compact_chunk0( ctx->store_out_mem, store_out_link->dcache );
  ctx->store_out_wmark  = fd_dcache_compact_wmark( ctx->store_out_mem, store_out_link->dcache, store_out_link->mtu );
  ctx->store_out_chunk  = ctx->store_out_chunk0;

/* Set up stake weights tile output */
  fd_topo_link_t * stake_weights_out = &topo->links[ tile->out_link_id_primary ];
  ctx->stake_weights_out_mcache = stake_weights_out->mcache;
  ctx->stake_weights_out_sync   = fd_mcache_seq_laddr( ctx->stake_weights_out_mcache );
  ctx->stake_weights_out_depth  = fd_mcache_depth( ctx->stake_weights_out_mcache );
  ctx->stake_weights_out_seq    = fd_mcache_seq_query( ctx->stake_weights_out_sync );
  ctx->stake_weights_out_mem    = topo->workspaces[ stake_weights_out->wksp_id ].wksp;
  ctx->stake_weights_out_chunk0 = fd_dcache_compact_chunk0( ctx->stake_weights_out_mem, stake_weights_out->dcache );
  ctx->stake_weights_out_wmark  = fd_dcache_compact_wmark ( ctx->stake_weights_out_mem, stake_weights_out->dcache, stake_weights_out->mtu );
  ctx->stake_weights_out_chunk  = ctx->stake_weights_out_chunk0;

  /* Valloc setup */
  void * alloc_shalloc = fd_alloc_new( alloc_shmem, 3UL );
  if( FD_UNLIKELY( !alloc_shalloc ) ) { 
    FD_LOG_ERR( ( "fd_allow_new failed" ) ); }
  fd_alloc_t * alloc = fd_alloc_join( alloc_shalloc, 3UL );
  if( FD_UNLIKELY( !alloc ) ) {
    FD_LOG_ERR( ( "fd_alloc_join failed" ) ); 
  }

  char hostname[64];
  gethostname(hostname, sizeof(hostname));
  ulong hashseed = fd_hash(0, hostname, strnlen(hostname, sizeof(hostname)));

  // Allocate new wksp
  fd_wksp_t * wksp;  
  wksp = fd_wksp_new_anonymous( FD_SHMEM_GIGANTIC_PAGE_SZ, tile->replay.pages, 0, "wksp", 0UL );
  if (wksp == NULL)
    FD_LOG_ERR(( "failed to attach to workspace" ));
  fd_wksp_reset( wksp, (uint)hashseed);

  // TODO: is this required here?
  /* Create scratch region */
  ulong  smax   = 1024UL /*MiB*/ << 21;
  ulong  sdepth = 128;      /* 128 scratch frames */
  void * smem   = fd_wksp_alloc_laddr( wksp, fd_scratch_smem_align(), fd_scratch_smem_footprint( smax   ), 421UL );
  void * fmem   = fd_wksp_alloc_laddr( wksp, fd_scratch_fmem_align(), fd_scratch_fmem_footprint( sdepth ), 421UL );
  FD_TEST( (!!smem) & (!!fmem) );
  fd_scratch_attach( smem, fmem, smax, sdepth );

  // Funky setup
  fd_funk_t * funk;
  void * shmem;
  shmem = fd_wksp_alloc_laddr( wksp, fd_funk_align(), fd_funk_footprint(), FD_FUNK_MAGIC );
  if (shmem == NULL)
    FD_LOG_ERR(( "failed to allocate a funky" ));
  funk = fd_funk_join(fd_funk_new(shmem, 42, hashseed, tile->replay.txn_max, tile->replay.index_max));
  if (funk == NULL) {
    fd_wksp_free_laddr(shmem);
    FD_LOG_ERR(( "failed to allocate a funky" ));
  }

  fd_valloc_t valloc = fd_alloc_virtual( alloc );
  ctx->epoch_ctx_mem = fd_wksp_alloc_laddr( wksp, fd_exec_epoch_ctx_align(), fd_exec_epoch_ctx_footprint(), FD_EXEC_EPOCH_CTX_MAGIC );
  ctx->epoch_ctx = fd_exec_epoch_ctx_join( fd_exec_epoch_ctx_new( ctx->epoch_ctx_mem ) );
  
  ctx->snapshot    = tile->replay.snapshot;
  ctx->incremental = tile->replay.incremental;
  ctx->genesis     = tile->replay.genesis;

  ctx->curr_slot   = tile->replay.snapshot_slot;
  ctx->parent_slot = ctx->curr_slot;
  fd_memset( ctx->blockhash.uc, 0, sizeof(fd_hash_t));

  void * replay_mem =
      fd_wksp_alloc_laddr( wksp, fd_replay_align(), fd_replay_footprint(), 42UL );
  ctx->replay = fd_replay_join( fd_replay_new( replay_mem ) );
  ctx->replay->valloc       = valloc;
  ctx->replay->epoch_ctx    = ctx->epoch_ctx;

  fd_acc_mgr_t * acc_mgr = fd_acc_mgr_new( ctx->acc_mgr, funk );

  ulong        forks_max = fd_ulong_pow2_up( FD_DEFAULT_SLOTS_PER_EPOCH );
  void *       forks_mem = fd_wksp_alloc_laddr( wksp, fd_forks_align(), fd_forks_footprint( forks_max ), 1UL );
  fd_forks_t * forks     = fd_forks_join( fd_forks_new( forks_mem, forks_max, 42UL ) );
  FD_TEST( forks );

  forks->acc_mgr = acc_mgr;
  forks->funk = funk;
  forks->valloc = valloc;
  ctx->replay->forks = forks;

  ulong snapshot_slot = tile->replay.snapshot_slot;
  fd_fork_t * replay_slot = fd_fork_pool_ele_acquire( ctx->replay->forks->pool );
  replay_slot->slot   = snapshot_slot;
  ctx->replay->smr    = snapshot_slot;

  ctx->slot_ctx =
            fd_exec_slot_ctx_join( fd_exec_slot_ctx_new( &replay_slot->slot_ctx, valloc ) );
  ctx->slot_ctx->epoch_ctx = ctx->epoch_ctx;
  ctx->slot_ctx->valloc  = valloc;
  ctx->slot_ctx->acc_mgr  = acc_mgr;

  ctx->replay->acc_mgr      = ctx->slot_ctx->acc_mgr;
  ctx->replay->funk         = funk;

  ctx->tpool = fd_tpool_init( ctx->tpool_mem, 1 );
  ctx->max_workers = 1;
 
  ctx->replay->tpool = ctx->tpool;
  ctx->replay->max_workers = 1;

  if( ctx->tpool == NULL ) {
    FD_LOG_ERR(("failed to create thread pool"));
  }

  /* add it to the frontier */
  fd_fork_frontier_ele_insert( ctx->replay->forks->frontier, replay_slot, ctx->replay->forks->pool );
}

static ulong
populate_allowed_seccomp( void *               scratch,
                          ulong                out_cnt,
                          struct sock_filter * out ) {
  (void)scratch;
  populate_sock_filter_policy_replay( out_cnt, out, (uint)fd_log_private_logfile_fd() );
  return sock_filter_policy_replay_instr_cnt;
}

static ulong
populate_allowed_fds( void * scratch,
                      ulong  out_fds_cnt,
                      int *  out_fds ) {
  (void)scratch;
  if( FD_UNLIKELY( out_fds_cnt<2 ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  return out_cnt;
}

fd_tile_config_t fd_tile_replay = {
  .mux_flags                = FD_MUX_FLAG_MANUAL_PUBLISH | FD_MUX_FLAG_COPY,
  .burst                    = 1UL,
  .loose_footprint          = loose_footprint,
  .mux_ctx                  = mux_ctx,
  .mux_before_frag          = before_frag,
  .mux_during_frag          = during_frag,
  .mux_after_frag           = after_frag,
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .mux_during_housekeeping  = during_housekeeping,
};
