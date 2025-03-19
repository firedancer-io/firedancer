#define _GNU_SOURCE
#include "../../disco/tiles.h"
#include "generated/fd_exec_tile_seccomp.h"

#include "../../disco/topo/fd_pod_format.h"

#include "../../flamenco/runtime/fd_runtime.h"
#include "../../flamenco/runtime/fd_executor.h"

#include "../../funk/fd_funk.h"
#include "../../funk/fd_funk_filemap.h"

#define EXEC_NEW_SLOT_SIG  (0UL)
#define EXEC_NEW_EPOCH_SIG (1UL)
#define EXEC_NEW_TXN_SIG   (2UL)

struct fd_exec_tile_ctx {
  ulong  replay_exec_in_idx;
  ulong  exec_replay_out_idx;
  ulong  tile_cnt;
  ulong  tile_idx;

  fd_wksp_t * replay_in_mem;
  ulong       replay_in_chunk0;
  ulong       replay_in_wmark;

  fd_wksp_t * replay_out_mem;
  ulong       replay_out_chunk0;
  ulong       replay_out_wmark;

  fd_wksp_t *           runtime_public_wksp;
  fd_runtime_public_t * runtime_public;

  fd_txn_p_t txn; /* current txn */

  fd_spad_t *       exec_spad;
  fd_spad_t const * runtime_spad;

  /* funk-specific setup */
  fd_funk_t * funk;
  fd_wksp_t * funk_wksp;
  char        funk_file[ PATH_MAX ];

  /* txn_ctx */
  fd_exec_txn_ctx_t * txn_ctx;
};
typedef struct fd_exec_tile_ctx fd_exec_tile_ctx_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 128UL;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile FD_PARAM_UNUSED ) {
  /* clang-format off */
  ulong l = FD_LAYOUT_INIT;
  l       = FD_LAYOUT_APPEND( l, alignof(fd_exec_tile_ctx_t),  sizeof(fd_exec_tile_ctx_t) );
  return FD_LAYOUT_FINI( l, scratch_align() );
  /* clang-format on */
}

static void FD_FN_UNUSED
prepare_new_epoch_execution( fd_exec_tile_ctx_t *            ctx,
                             fd_runtime_public_epoch_msg_t * epoch_msg ) {
  /* TODO: Implement. Here we will update the features,
     and refresh the epoch schedule, rent, slots per year, and stakes. */
  ctx->txn_ctx->features          = epoch_msg->features;
  ctx->txn_ctx->total_epoch_stake = epoch_msg->total_epoch_stake;
  ctx->txn_ctx->schedule          = epoch_msg->epoch_schedule;
  ctx->txn_ctx->rent              = epoch_msg->rent;
  ctx->txn_ctx->slots_per_year    = epoch_msg->slots_per_year;

  uchar * stakes_enc = fd_wksp_laddr( ctx->runtime_public_wksp, epoch_msg->stakes_encoded_gaddr );
  fd_bincode_decode_ctx_t decode = {
    .data    = stakes_enc,
    .dataend = stakes_enc + epoch_msg->stakes_encoded_sz
  };
  ulong total_sz = 0UL;
  int   err      = fd_stakes_decode_footprint( &decode, &total_sz );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_ERR(( "Could not decode stakes footprint" ));
  }

  uchar *       stakes_mem = fd_spad_alloc( ctx->exec_spad, fd_stakes_align(), total_sz );
  fd_stakes_t * stakes     = fd_stakes_decode( stakes_mem, &decode );
  if( FD_UNLIKELY( !stakes ) ) {
    FD_LOG_ERR(( "Could not decode stakes" ));
  }
  ctx->txn_ctx->stakes = *stakes;

  FD_LOG_WARNING(("MAKE IT IN HERE %lu", ctx->txn_ctx->stakes.epoch));
}

static void FD_FN_UNUSED
prepare_new_slot_execution( fd_exec_tile_ctx_t *           ctx,
                            fd_runtime_public_slot_msg_t * slot_msg ) {

  FD_LOG_WARNING(( "ENTERING HERE %lu", slot_msg->slot ));

  long ts_0 = fd_log_wallclock();

  fd_funk_txn_t * txn_map = fd_funk_txn_map( ctx->funk, ctx->funk_wksp );
  if( FD_UNLIKELY( !txn_map ) ) {
    FD_LOG_ERR(( "Could not find valid funk transaction map" ));
  }
  fd_funk_txn_xid_t xid = { .ul = { slot_msg->slot, slot_msg->slot } };
  fd_funk_txn_t * funk_txn = fd_funk_txn_query( &xid, txn_map );
  if( FD_UNLIKELY( !funk_txn ) ) {
    FD_LOG_ERR(( "Could not find valid funk transaction" ));
  }
  ctx->txn_ctx->funk_txn = funk_txn;

  ctx->txn_ctx->slot                        = slot_msg->slot;
  ctx->txn_ctx->prev_lamports_per_signature = slot_msg->prev_lamports_per_signature;
  ctx->txn_ctx->fee_rate_governor           = slot_msg->fee_rate_governor;

  uchar * block_hash_queue_enc = fd_wksp_laddr( ctx->runtime_public_wksp, slot_msg->block_hash_queue_encoded_gaddr );
  fd_bincode_decode_ctx_t decode = {
    .data    = block_hash_queue_enc,
    .dataend = block_hash_queue_enc + slot_msg->block_hash_queue_encoded_sz
  };
  ulong total_sz = 0UL;
  int   err      = fd_block_hash_queue_decode_footprint( &decode, &total_sz );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_ERR(( "Could not decode block hash queue footprint" ));
  }

  uchar * block_hash_queue_mem = fd_spad_alloc( ctx->exec_spad, fd_block_hash_queue_align(), total_sz );
  fd_block_hash_queue_t * block_hash_queue = fd_block_hash_queue_decode( block_hash_queue_mem, &decode );
  if( FD_UNLIKELY( !block_hash_queue ) ) {
    FD_LOG_ERR(( "Could not decode block hash queue" ));
  }

  ctx->txn_ctx->block_hash_queue = *block_hash_queue;

  long ts_1 = fd_log_wallclock();

  FD_LOG_WARNING(("BLOCK HASH QUEUE MEM %ld %lu", ts_1-ts_0, ctx->txn_ctx->block_hash_queue.max_age));
}

static void FD_FN_UNUSED
execute_txn( fd_exec_tile_ctx_t * ctx ) {
  fd_spad_push( ctx->exec_spad );

  fd_execute_txn_task_info_t task_info = {
    .txn_ctx  = ctx->txn_ctx,
    .exec_res = 0,
    .txn      = &ctx->txn,
  };

  fd_txn_t const * txn_descriptor = (fd_txn_t const *)task_info.txn->_;
  fd_rawtxn_b_t    raw_txn        = { .raw    = task_info.txn->payload,
                                      .txn_sz = (ushort)task_info.txn->payload_sz
  };

  fd_exec_txn_ctx_setup( ctx->txn_ctx, txn_descriptor, &raw_txn );

  fd_executor_setup_accessed_accounts_for_txn( ctx->txn_ctx );


  fd_spad_pop( ctx->exec_spad );
}

static void
during_frag( fd_exec_tile_ctx_t * ctx,
             ulong                in_idx,
             ulong                seq FD_PARAM_UNUSED,
             ulong                sig FD_PARAM_UNUSED,
             ulong                chunk,
             ulong                sz,
             ulong                ctl FD_PARAM_UNUSED ) {

  if( FD_UNLIKELY( in_idx == ctx->replay_exec_in_idx ) ) {
    if( FD_UNLIKELY( chunk < ctx->replay_in_chunk0 || chunk > ctx->replay_in_wmark ) ) {
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]",
                    chunk,
                    sz,
                    ctx->replay_in_chunk0,
                    ctx->replay_in_wmark ));
    }

    if( FD_LIKELY( sig==EXEC_NEW_TXN_SIG ) ) {
      //FD_LOG_NOTICE(("RECV TXN"));
      uchar * txn = fd_chunk_to_laddr( ctx->replay_in_mem, chunk );
      fd_memcpy( &ctx->txn, txn, sz );
      execute_txn( ctx );
      FD_LOG_HEXDUMP_DEBUG(( "exec tile recieved txn: ", txn, sz ));
    } else if( sig==EXEC_NEW_SLOT_SIG ) {
      fd_runtime_public_slot_msg_t * msg = fd_chunk_to_laddr( ctx->replay_in_mem, chunk );
      if( ctx->tile_idx == 0UL ) {
        FD_LOG_WARNING(( "new slot %lu", msg->slot ));
        prepare_new_slot_execution( ctx, msg );
      }
    } else if( sig==EXEC_NEW_EPOCH_SIG ) {
      fd_runtime_public_epoch_msg_t * msg = fd_chunk_to_laddr( ctx->replay_in_mem, chunk );
      if( ctx->tile_idx == 0UL ) {
        FD_LOG_WARNING(( "new epoch %lu", msg->epoch_schedule.slots_per_epoch ));
        prepare_new_epoch_execution( ctx, msg );
      }
    } else {
      FD_LOG_ERR(( "Unknown signature" ));
    }

  }
}

static void
after_frag( fd_exec_tile_ctx_t * ctx    FD_PARAM_UNUSED,
            ulong                in_idx FD_PARAM_UNUSED,
            ulong                seq    FD_PARAM_UNUSED,
            ulong                sig,
            ulong                sz     FD_PARAM_UNUSED,
            ulong                tsorig FD_PARAM_UNUSED,
            ulong                tspub  FD_PARAM_UNUSED,
            fd_stem_context_t *  stem ) {

  if( sig==EXEC_NEW_SLOT_SIG ) {
    /* At this point we can assume that all of the slot-level
       information was propogated to the executor tile. We can now
       notify that this tile is ready to consume transactions. */
    fd_stem_publish( stem, 0UL, EXEC_NEW_SLOT_SIG, ctx->replay_out_chunk0, 0UL, 0UL, tsorig, tsorig );
  } else if( sig==EXEC_NEW_TXN_SIG ) {
    /* At this point we can assume that the transaction is done
       executing. The replay tile will be repsonsible for commiting
       the transaction back to funk. */
    fd_stem_publish( stem, 0UL, EXEC_NEW_TXN_SIG, ctx->replay_out_chunk0, 0UL, 0UL, tsorig, tsorig );
  }

  uchar * out_buf = fd_chunk_to_laddr( ctx->replay_out_mem, ctx->replay_out_chunk0 );
  fd_memset( out_buf, 0, sizeof(fd_hash_t) );
  fd_stem_publish( stem, 0UL, 2UL, ctx->replay_out_chunk0, sizeof(fd_hash_t), 0UL, tsorig, tspub );
}

static void
privileged_init( fd_topo_t *      topo FD_PARAM_UNUSED,
                 fd_topo_tile_t * tile FD_PARAM_UNUSED ) {
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {

  /********************************************************************/
  /* validate allocations                                             */
  /********************************************************************/

  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_exec_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_exec_tile_ctx_t), sizeof(fd_exec_tile_ctx_t) );
  ulong scratch_alloc_mem = FD_SCRATCH_ALLOC_FINI( l, scratch_align() );
  if( FD_UNLIKELY( scratch_alloc_mem - (ulong)scratch  - scratch_footprint( tile ) ) ) {
    FD_LOG_ERR( ( "Scratch_alloc_mem did not match scratch_footprint diff: %lu alloc: %lu footprint: %lu",
      scratch_alloc_mem - (ulong)scratch - scratch_footprint( tile ),
      scratch_alloc_mem,
      (ulong)scratch + scratch_footprint( tile ) ) );
  }

  /********************************************************************/
  /* validate links                                                   */
  /********************************************************************/

  ctx->tile_cnt = fd_topo_tile_name_cnt( topo, tile->name );
  ctx->tile_idx = tile->kind_id;


  /* First find and setup the in-link from replay to exec. */
  ctx->replay_exec_in_idx = fd_topo_find_tile_in_link( topo, tile, "replay_exec", ctx->tile_idx );
  if( FD_UNLIKELY( ctx->replay_exec_in_idx==ULONG_MAX ) ) {
    FD_LOG_ERR(( "Could not find replay_exec in-link" ));
  }
  fd_topo_link_t * replay_exec_in_link = &topo->links[tile->in_link_id[ctx->replay_exec_in_idx]];
  if( FD_UNLIKELY( !replay_exec_in_link) ) {
    FD_LOG_ERR(( "Invalid replay_exec in-link" ));
  }
  ctx->replay_in_mem    = topo->workspaces[topo->objs[replay_exec_in_link->dcache_obj_id].wksp_id].wksp;
  ctx->replay_in_chunk0 = fd_dcache_compact_chunk0( ctx->replay_in_mem, replay_exec_in_link->dcache );
  ctx->replay_in_wmark  = fd_dcache_compact_wmark( ctx->replay_in_mem,
                                                   replay_exec_in_link->dcache,
                                                   replay_exec_in_link->mtu );


  /* Now find and setup the out-link from exec to replay. */
  ctx->exec_replay_out_idx = fd_topo_find_tile_out_link( topo, tile, "exec_replay", ctx->tile_idx );
  if( FD_UNLIKELY( ctx->exec_replay_out_idx==ULONG_MAX ) ) {
    FD_LOG_ERR(( "Could not find exec_replay out-link" ));
  }
  fd_topo_link_t * exec_replay_out_link = &topo->links[tile->out_link_id[ctx->exec_replay_out_idx]];
  if( FD_UNLIKELY( !exec_replay_out_link ) ) {
    FD_LOG_ERR(( "Could not find exec_replay out-link" ));
  }

  ctx->replay_out_mem    = topo->workspaces[topo->objs[exec_replay_out_link->dcache_obj_id].wksp_id].wksp;
  ctx->replay_out_chunk0 = fd_dcache_compact_chunk0( ctx->replay_out_mem, exec_replay_out_link->dcache );
  ctx->replay_out_wmark  = fd_dcache_compact_wmark( ctx->replay_out_mem,
                                                    exec_replay_out_link->dcache,
                                                    exec_replay_out_link->mtu );

  /********************************************************************/
  /* runtime public                                                   */
  /********************************************************************/

  ulong runtime_obj_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "runtime_pub" );
  if( FD_UNLIKELY( runtime_obj_id==ULONG_MAX ) ) {
    FD_LOG_ERR(( "Could not find topology object for runtime public" ));
  }

  ctx->runtime_public_wksp = topo->workspaces[ topo->objs[ runtime_obj_id ].wksp_id ].wksp;

  if( FD_UNLIKELY( ctx->runtime_public_wksp==NULL ) ) {
    FD_LOG_ERR(( "No runtime_public workspace" ));
  }

  ctx->runtime_public = fd_runtime_public_join( fd_topo_obj_laddr( topo, runtime_obj_id ) );
  if( FD_UNLIKELY( !ctx->runtime_public ) ) {
    FD_LOG_ERR(( "Failed to join runtime public" ));
  }

  /********************************************************************/
  /* spad allocator                                                   */
  /********************************************************************/

  /* First join the correct exec spad and hten the correct runtime spad
     which lives inside of the runtime public wksp. */

  ulong exec_spad_obj_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "exec_spad.%lu", ctx->tile_idx );
  if( FD_UNLIKELY( exec_spad_obj_id==ULONG_MAX ) ) {
    FD_LOG_ERR(( "Could not find topology object for exec spad" ));
  }

  ctx->exec_spad = fd_spad_join( fd_topo_obj_laddr( topo, exec_spad_obj_id ) );
  if( FD_UNLIKELY( !ctx->exec_spad ) ) {
    FD_LOG_ERR(( "Failed to join exec spad" ));
  }

  ctx->runtime_spad = fd_runtime_public_join_and_get_runtime_spad( ctx->runtime_public );
  if( FD_UNLIKELY( !ctx->runtime_spad ) ) {
    FD_LOG_ERR(( "Failed to get and join runtime spad" ));
  }

  /********************************************************************/
  /* funk-specific setup                                              */
  /********************************************************************/

  /* TODO:FIXME: this needs to be adjusted accordingly */
  memcpy( ctx->funk_file, tile->replay.funk_file, sizeof(tile->replay.funk_file) );
  memcpy( ctx->funk_file, "/data/ibhatt/funkfile\0", 22 );

  /* Setting these parameters are not required because we are joining
     the funk that was setup in the replay tile. */
  FD_LOG_WARNING(( "Trying to join funk at file=%s", ctx->funk_file ));
  ctx->funk = fd_funk_open_file( ctx->funk_file,
                                  1UL,
                                  0UL,
                                  0UL,
                                  0UL,
                                  0UL,
                                  FD_FUNK_READONLY,
                                  NULL );
  ctx->funk_wksp = fd_funk_wksp( ctx->funk );
  if( FD_UNLIKELY( !ctx->funk ) ) {
    FD_LOG_ERR(( "failed to join a funk" ));
  }

  FD_LOG_NOTICE(( "Just joined funk at file=%s", ctx->funk_file ));

  /********************************************************************/
  /* setup txn ctx                                                    */
  /********************************************************************/

  fd_spad_push( ctx->exec_spad );
  uchar * txn_ctx_mem = fd_spad_alloc( ctx->exec_spad, FD_EXEC_TXN_CTX_ALIGN, FD_EXEC_TXN_CTX_FOOTPRINT );
  ctx->txn_ctx        = fd_exec_txn_ctx_join( fd_exec_txn_ctx_new( txn_ctx_mem ) );

  uchar *        acc_mgr_mem = fd_spad_alloc( ctx->exec_spad, FD_ACC_MGR_ALIGN, FD_ACC_MGR_FOOTPRINT );
  fd_acc_mgr_t * acc_mgr     = fd_acc_mgr_new( acc_mgr_mem, ctx->funk );
  ctx->txn_ctx->acc_mgr      = acc_mgr;
  ctx->txn_ctx->spad         = ctx->exec_spad;

  FD_LOG_NOTICE(( "Done booting exec tile idx=%lu", ctx->tile_idx ));
}

static void
after_credit( fd_exec_tile_ctx_t * ctx,
              fd_stem_context_t *  stem        FD_PARAM_UNUSED,
              int *                opt_poll_in FD_PARAM_UNUSED,
              int *                charge_busy FD_PARAM_UNUSED ) {
  (void)ctx;
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  (void)topo;
  (void)tile;

  populate_sock_filter_policy_fd_exec_tile( out_cnt, out, (uint)fd_log_private_logfile_fd() );
  return sock_filter_policy_fd_exec_tile_instr_cnt;
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


#define STEM_BURST (1UL)

#define STEM_CALLBACK_CONTEXT_TYPE  fd_exec_tile_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_exec_tile_ctx_t)

#define STEM_CALLBACK_DURING_FRAG  during_frag
#define STEM_CALLBACK_AFTER_FRAG   after_frag
#define STEM_CALLBACK_AFTER_CREDIT after_credit


#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_execor = {
    .name                     = "exec",
    .loose_footprint          = 0UL,
    .populate_allowed_seccomp = populate_allowed_seccomp,
    .populate_allowed_fds     = populate_allowed_fds,
    .scratch_align            = scratch_align,
    .scratch_footprint        = scratch_footprint,
    .privileged_init          = privileged_init,
    .unprivileged_init        = unprivileged_init,
    .run                      = stem_run,
};
