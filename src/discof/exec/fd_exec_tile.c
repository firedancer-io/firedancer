#include "../../disco/tiles.h"
#include "generated/fd_exec_tile_seccomp.h"

#include "../../util/pod/fd_pod_format.h"
#include "../../discof/replay/fd_exec.h"
#include "../../flamenco/runtime/context/fd_capture_ctx.h"
#include "../../flamenco/runtime/fd_bank.h"
#include "../../flamenco/runtime/fd_runtime.h"
#include "../../flamenco/accdb/fd_accdb_impl_v1.h"
#include "../../flamenco/progcache/fd_progcache_user.h"
#include "../../flamenco/log_collector/fd_log_collector.h"
#include "../../disco/metrics/fd_metrics.h"

/* The exec tile is responsible for executing single transactions. The
   tile recieves a parsed transaction (fd_txn_p_t) and an identifier to
   which bank to execute against (index into the bank pool). With this,
   the exec tile is able to identify the correct bank and accounts db
   handle (funk_txn) to execute the transaction against.  The exec tile
   then commits the results of the transaction to the accounts db and
   makes any necessary updates to the bank. */

typedef struct link_ctx {
  ulong       idx;
  fd_wksp_t * mem;
  ulong       chunk;
  ulong       chunk0;
  ulong       wmark;
} link_ctx_t;

typedef struct fd_exec_tile_ctx {
  ulong                 tile_idx;

  /* link-related data structures. */
  link_ctx_t            replay_in[ 1 ];
  link_ctx_t            exec_replay_out[ 1 ]; /* TODO: Remove with solcap v2 */
  link_ctx_t            exec_sig_out[ 1 ];

  fd_sha512_t           sha_mem[ FD_TXN_ACTUAL_SIG_MAX ];
  fd_sha512_t *         sha_lj[ FD_TXN_ACTUAL_SIG_MAX ];

  /* Capture context for debugging runtime execution. */
  fd_capture_ctx_t *    capture_ctx;
  uchar *               solcap_publish_buffer_ptr;
  ulong                 account_updates_flushed;

  /* A transaction can be executed as long as there is a valid handle to
     a funk_txn and a bank. These are queried from fd_banks_t and
     fd_funk_t. */
  fd_banks_t *          banks;
  fd_accdb_user_t       accdb[1];
  fd_progcache_t        progcache[1];

  fd_txncache_t *       txncache;

  /* We need to ensure that all solcap updates have been published
     before this message. */
  int                   pending_txn_finalized_msg;
  ulong                 txn_idx;
  ulong                 slot;
  ulong                 dispatch_time_comp;

  fd_exec_accounts_t    exec_accounts;
  fd_log_collector_t    log_collector;

  fd_bank_t *           bank;

  fd_txn_in_t           txn_in;
  fd_txn_out_t          txn_out;

  /* tracing_mem is staging memory to dump instructions/transactions
     into protobuf files.  tracing_mem is staging memory to output vm
     execution traces.
     TODO: This should not be compiled in prod. */
  uchar                 dumping_mem[ FD_SPAD_FOOTPRINT( 1UL<<28UL ) ] __attribute__((aligned(FD_SPAD_ALIGN)));
  uchar                 tracing_mem[ FD_MAX_INSTRUCTION_STACK_DEPTH ][ FD_RUNTIME_VM_TRACE_STATIC_FOOTPRINT ] __attribute__((aligned(FD_RUNTIME_VM_TRACE_STATIC_ALIGN)));

  fd_runtime_t runtime[1];

} fd_exec_tile_ctx_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 128UL;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_exec_tile_ctx_t), sizeof(fd_exec_tile_ctx_t)                         );
  l = FD_LAYOUT_APPEND( l, fd_capture_ctx_align(),      fd_capture_ctx_footprint()                         );
  l = FD_LAYOUT_APPEND( l, fd_txncache_align(),         fd_txncache_footprint( tile->exec.max_live_slots ) );
  l = FD_LAYOUT_APPEND( l, FD_PROGCACHE_SCRATCH_ALIGN,  FD_PROGCACHE_SCRATCH_FOOTPRINT                     );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static void
metrics_write( fd_exec_tile_ctx_t * ctx ) {
  fd_progcache_t * progcache = ctx->progcache;
  FD_MCNT_SET( EXEC, PROGCACHE_MISSES,        progcache->metrics->miss_cnt       );
  FD_MCNT_SET( EXEC, PROGCACHE_HITS,          progcache->metrics->hit_cnt        );
  FD_MCNT_SET( EXEC, PROGCACHE_FILLS,         progcache->metrics->fill_cnt       );
  FD_MCNT_SET( EXEC, PROGCACHE_FILL_TOT_SZ,   progcache->metrics->fill_tot_sz    );
  FD_MCNT_SET( EXEC, PROGCACHE_INVALIDATIONS, progcache->metrics->invalidate_cnt );
  FD_MCNT_SET( EXEC, PROGCACHE_DUP_INSERTS,   progcache->metrics->dup_insert_cnt );
}

static inline int
returnable_frag( fd_exec_tile_ctx_t * ctx,
                 ulong                in_idx,
                 ulong                seq FD_PARAM_UNUSED,
                 ulong                sig,
                 ulong                chunk,
                 ulong                sz,
                 ulong                ctl FD_PARAM_UNUSED,
                 ulong                tsorig FD_PARAM_UNUSED,
                 ulong                tspub,
                 fd_stem_context_t *  stem ) {

  if( (sig&0xFFFFFFFFUL)!=ctx->tile_idx ) return 0;

  if( FD_LIKELY( in_idx==ctx->replay_in->idx ) ) {
    if( FD_UNLIKELY( chunk < ctx->replay_in->chunk0 || chunk > ctx->replay_in->wmark ) ) {
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->replay_in->chunk0, ctx->replay_in->wmark ));
    }
    switch( sig>>32 ) {
      case FD_EXEC_TT_TXN_EXEC: {
        /* Execute. */
        fd_exec_txn_exec_msg_t * msg = fd_chunk_to_laddr( ctx->replay_in->mem, chunk );
        ctx->bank = fd_banks_bank_query( ctx->banks, msg->bank_idx );
        FD_TEST( ctx->bank );
        ctx->txn_in.txn           = &msg->txn;
        ctx->txn_in.exec_accounts = &ctx->exec_accounts;

        fd_runtime_prepare_and_execute_txn( ctx->runtime, ctx->bank, &ctx->txn_in, &ctx->txn_out );

        /* Commit. */
        if( FD_LIKELY( ctx->txn_out.err.is_committable ) ) {
          fd_runtime_commit_txn( ctx->runtime, ctx->bank, &ctx->txn_in, &ctx->txn_out );
        }

        if( FD_LIKELY( ctx->exec_sig_out->idx!=ULONG_MAX ) ) {
          /* Copy the txn signature to the signature out link so the
             dedup/pack tiles can drop already executed transactions. */
          memcpy( fd_chunk_to_laddr( ctx->exec_sig_out->mem, ctx->exec_sig_out->chunk ),
                  (uchar *)ctx->txn_in.txn->payload + TXN( ctx->txn_in.txn )->signature_off,
                  64UL );
          fd_stem_publish( stem, ctx->exec_sig_out->idx, 0UL, ctx->exec_sig_out->chunk, 64UL, 0UL, 0UL, 0UL );
          ctx->exec_sig_out->chunk = fd_dcache_compact_next( ctx->exec_sig_out->chunk, 64UL, ctx->exec_sig_out->chunk0, ctx->exec_sig_out->wmark );
        }

        /* Notify replay. */
        ctx->txn_idx                   = msg->txn_idx;
        ctx->dispatch_time_comp        = tspub;
        ctx->slot                      = fd_bank_slot_get( ctx->bank );
        ctx->pending_txn_finalized_msg = 1;

        break;
      }
      case FD_EXEC_TT_TXN_SIGVERIFY: {
        fd_exec_txn_sigverify_msg_t * msg = fd_chunk_to_laddr( ctx->replay_in->mem, chunk );
        int res = fd_executor_txn_verify( &msg->txn, ctx->sha_lj );
        fd_exec_task_done_msg_t * out_msg = fd_chunk_to_laddr( ctx->exec_replay_out->mem, ctx->exec_replay_out->chunk );
        out_msg->bank_idx               = msg->bank_idx;
        out_msg->txn_sigverify->txn_idx = msg->txn_idx;
        out_msg->txn_sigverify->err     = (res!=FD_RUNTIME_EXECUTE_SUCCESS);
        fd_stem_publish( stem, ctx->exec_replay_out->idx, (FD_EXEC_TT_TXN_SIGVERIFY<<32)|ctx->tile_idx, ctx->exec_replay_out->chunk, sizeof(*out_msg), 0UL, 0UL, 0UL );
        ctx->exec_replay_out->chunk = fd_dcache_compact_next( ctx->exec_replay_out->chunk, sizeof(*out_msg), ctx->exec_replay_out->chunk0, ctx->exec_replay_out->wmark );
        break;
      }
      default: FD_LOG_CRIT(( "unexpected signature %lu", sig ));
    }
  } else FD_LOG_CRIT(( "invalid in_idx %lu", in_idx ));

  return 0;
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
  void * capture_ctx_mem   = FD_SCRATCH_ALLOC_APPEND( l, fd_capture_ctx_align(),      fd_capture_ctx_footprint() );
  void * _txncache         = FD_SCRATCH_ALLOC_APPEND( l, fd_txncache_align(),         fd_txncache_footprint( tile->exec.max_live_slots ) );
  uchar * pc_scratch       = FD_SCRATCH_ALLOC_APPEND( l, FD_PROGCACHE_SCRATCH_ALIGN,  FD_PROGCACHE_SCRATCH_FOOTPRINT );
  ulong  scratch_alloc_mem = FD_SCRATCH_ALLOC_FINI( l, scratch_align() );

  if( FD_UNLIKELY( scratch_alloc_mem - (ulong)scratch  - scratch_footprint( tile ) ) ) {
    FD_LOG_ERR( ( "Scratch_alloc_mem did not match scratch_footprint diff: %lu alloc: %lu footprint: %lu",
      scratch_alloc_mem - (ulong)scratch - scratch_footprint( tile ),
      scratch_alloc_mem,
      (ulong)scratch + scratch_footprint( tile ) ) );
  }

  for( ulong i=0UL; i<FD_TXN_ACTUAL_SIG_MAX; i++ ) {
    fd_sha512_t * sha = fd_sha512_join( fd_sha512_new( ctx->sha_mem+i ) );
    FD_TEST( sha );
    ctx->sha_lj[i] = sha;
  }

  /********************************************************************/
  /* validate links                                                   */
  /********************************************************************/

  ctx->tile_idx = tile->kind_id;

  /* First find and setup the in-link from replay to exec. */
  ctx->replay_in->idx = fd_topo_find_tile_in_link( topo, tile, "replay_exec", 0UL );
  FD_TEST( ctx->replay_in->idx!=ULONG_MAX );
  fd_topo_link_t * replay_in_link = &topo->links[ tile->in_link_id[ ctx->replay_in->idx ] ];
  FD_TEST( replay_in_link!=NULL );
  ctx->replay_in->mem    = topo->workspaces[ topo->objs[ replay_in_link->dcache_obj_id ].wksp_id ].wksp;
  ctx->replay_in->chunk0 = fd_dcache_compact_chunk0( ctx->replay_in->mem, replay_in_link->dcache );
  ctx->replay_in->wmark  = fd_dcache_compact_wmark( ctx->replay_in->mem, replay_in_link->dcache, replay_in_link->mtu );
  ctx->replay_in->chunk  = ctx->replay_in->chunk0;

  ctx->exec_replay_out->idx = fd_topo_find_tile_out_link( topo, tile, "exec_replay", ctx->tile_idx );
  if( FD_LIKELY( ctx->exec_replay_out->idx!=ULONG_MAX ) ) {
    fd_topo_link_t * exec_replay_link = &topo->links[ tile->out_link_id[ ctx->exec_replay_out->idx ] ];
    ctx->exec_replay_out->mem    = topo->workspaces[ topo->objs[ exec_replay_link->dcache_obj_id ].wksp_id ].wksp;
    ctx->exec_replay_out->chunk0 = fd_dcache_compact_chunk0( ctx->exec_replay_out->mem, exec_replay_link->dcache );
    ctx->exec_replay_out->wmark  = fd_dcache_compact_wmark( ctx->exec_replay_out->mem, exec_replay_link->dcache, exec_replay_link->mtu );
    ctx->exec_replay_out->chunk  = ctx->exec_replay_out->chunk0;
  }

  ctx->exec_sig_out->idx = fd_topo_find_tile_out_link( topo, tile, "exec_sig", ctx->tile_idx );
  if( FD_LIKELY( ctx->exec_sig_out->idx!=ULONG_MAX ) ) {
    fd_topo_link_t * exec_sig_link = &topo->links[ tile->out_link_id[ ctx->exec_sig_out->idx ] ];
    ctx->exec_sig_out->mem    = topo->workspaces[ topo->objs[ exec_sig_link->dcache_obj_id ].wksp_id ].wksp;
    ctx->exec_sig_out->chunk0 = fd_dcache_compact_chunk0( ctx->exec_sig_out->mem, exec_sig_link->dcache );
    ctx->exec_sig_out->wmark  = fd_dcache_compact_wmark( ctx->exec_sig_out->mem, exec_sig_link->dcache, exec_sig_link->mtu );
    ctx->exec_sig_out->chunk  = ctx->exec_sig_out->chunk0;
  }

  /********************************************************************/
  /* banks                                                            */
  /********************************************************************/

  ulong banks_obj_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "banks" );
  if( FD_UNLIKELY( banks_obj_id==ULONG_MAX ) ) {
    FD_LOG_ERR(( "Could not find topology object for banks" ));
  }

  ctx->banks = fd_banks_join( fd_topo_obj_laddr( topo, banks_obj_id ) );
  if( FD_UNLIKELY( !ctx->banks ) ) {
    FD_LOG_ERR(( "Failed to join banks" ));
  }

  void * shfunk = fd_topo_obj_laddr( topo, tile->exec.funk_obj_id );
  if( FD_UNLIKELY( !fd_accdb_user_v1_init( ctx->accdb, shfunk ) ) ) {
    FD_LOG_CRIT(( "fd_accdb_user_v1_init() failed" ));
  }

  void * shprogcache = fd_topo_obj_laddr( topo, tile->exec.progcache_obj_id );
  if( FD_UNLIKELY( !fd_progcache_join( ctx->progcache, shprogcache, pc_scratch, FD_PROGCACHE_SCRATCH_FOOTPRINT ) ) ) {
    FD_LOG_CRIT(( "fd_progcache_join() failed" ));
  }

  void * _txncache_shmem = fd_topo_obj_laddr( topo, tile->exec.txncache_obj_id );
  fd_txncache_shmem_t * txncache_shmem = fd_txncache_shmem_join( _txncache_shmem );
  FD_TEST( txncache_shmem );
  ctx->txncache = fd_txncache_join( fd_txncache_new( _txncache, txncache_shmem ) );
  FD_TEST( ctx->txncache );

  ctx->txn_in.bundle.is_bundle = 0;

  /********************************************************************/
  /* Capture context                                                 */
  /********************************************************************/

  ctx->capture_ctx               = NULL;
  ctx->solcap_publish_buffer_ptr = NULL;
  ctx->account_updates_flushed   = 0UL;
  if( FD_UNLIKELY( strlen( tile->exec.solcap_capture ) || strlen( tile->exec.dump_proto_dir ) ) ) {
    ctx->capture_ctx = fd_capture_ctx_join( fd_capture_ctx_new( capture_ctx_mem ) );

    if( strlen( tile->exec.dump_proto_dir ) ) {
      ctx->capture_ctx->dump_proto_output_dir = tile->exec.dump_proto_dir;
      ctx->capture_ctx->dump_proto_start_slot = tile->exec.capture_start_slot;
      ctx->capture_ctx->dump_instr_to_pb      = tile->exec.dump_instr_to_pb;
      ctx->capture_ctx->dump_txn_to_pb        = tile->exec.dump_txn_to_pb;
      ctx->capture_ctx->dump_syscall_to_pb    = tile->exec.dump_syscall_to_pb;
      ctx->capture_ctx->dump_elf_to_pb        = tile->exec.dump_elf_to_pb;
    }

    if( strlen( tile->exec.solcap_capture ) ) {
      ctx->capture_ctx->capture_txns      = 0;
      ctx->capture_ctx->solcap_start_slot = tile->exec.capture_start_slot;
      ctx->account_updates_flushed        = 0;
      ctx->solcap_publish_buffer_ptr      = ctx->capture_ctx->account_updates_buffer;
    }
  }

  ctx->pending_txn_finalized_msg = 0;

  /********************************************************************/
  /* Runtime                                                          */
  /********************************************************************/

  ctx->runtime->accdb                    = ctx->accdb;
  ctx->runtime->funk                     = fd_accdb_user_v1_funk( ctx->accdb );
  ctx->runtime->progcache                = ctx->progcache;
  ctx->runtime->status_cache             = ctx->txncache;
  ctx->runtime->log.log_collector        = &ctx->log_collector;
  ctx->runtime->log.enable_log_collector = 0;
  ctx->runtime->log.dumping_mem          = ctx->dumping_mem;
  ctx->runtime->log.enable_vm_tracing    = 0;
  ctx->runtime->log.tracing_mem          = &ctx->tracing_mem[0][0];
  ctx->runtime->log.capture_ctx          = ctx->capture_ctx;
}

/* Publish the next account update event buffered in the capture tile to the replay tile

   TODO: remove this when solcap v2 is here. */
static void
publish_next_capture_ctx_account_update( fd_exec_tile_ctx_t * ctx,
                                         fd_stem_context_t *  stem ) {
  if( FD_UNLIKELY( !ctx->capture_ctx ) ) {
    return;
  }

  /* Copy the account update event to the buffer */
  ulong chunk     = ctx->exec_replay_out->chunk;
  uchar * out_ptr = fd_chunk_to_laddr( ctx->exec_replay_out->mem, chunk );
  fd_capture_ctx_account_update_msg_t * msg = (fd_capture_ctx_account_update_msg_t *)ctx->solcap_publish_buffer_ptr;
  memcpy( out_ptr, msg, sizeof(fd_capture_ctx_account_update_msg_t) );
  ctx->solcap_publish_buffer_ptr += sizeof(fd_capture_ctx_account_update_msg_t);
  out_ptr                        += sizeof(fd_capture_ctx_account_update_msg_t);

  /* Copy the data to the buffer */
  ulong data_sz = msg->data_sz;
  memcpy( out_ptr, ctx->solcap_publish_buffer_ptr, data_sz );
  ctx->solcap_publish_buffer_ptr += data_sz;
  out_ptr                        += data_sz;

  /* Stem publish the account update event */
  ulong msg_sz = sizeof(fd_capture_ctx_account_update_msg_t) + msg->data_sz;
  fd_stem_publish( stem, ctx->exec_replay_out->idx, 0UL, chunk, msg_sz, 0UL, 0UL, 0UL );
  ctx->exec_replay_out->chunk = fd_dcache_compact_next(
    chunk,
    msg_sz,
    ctx->exec_replay_out->chunk0,
    ctx->exec_replay_out->wmark );

  /* Advance the number of account updates flushed */
  ctx->account_updates_flushed++;

  /* If we have published all the account updates, reset the buffer pointer and length */
  if( ctx->account_updates_flushed == ctx->capture_ctx->account_updates_len ) {
    ctx->capture_ctx->account_updates_buffer_ptr = ctx->capture_ctx->account_updates_buffer;
    ctx->solcap_publish_buffer_ptr               = ctx->capture_ctx->account_updates_buffer;
    ctx->capture_ctx->account_updates_len        = 0UL;
    ctx->account_updates_flushed                 = 0UL;
  }
}

/* Publish the txn finalized message to the replay tile */
static void
publish_txn_finalized_msg( fd_exec_tile_ctx_t * ctx,
                           fd_stem_context_t *  stem ) {
  fd_exec_task_done_msg_t * msg  = fd_chunk_to_laddr( ctx->exec_replay_out->mem, ctx->exec_replay_out->chunk );
  msg->bank_idx                  = ctx->bank->idx;
  msg->txn_exec->txn_idx         = ctx->txn_idx;
  msg->txn_exec->err             = !ctx->txn_out.err.is_committable;
  msg->txn_exec->slot            = ctx->slot;
  msg->txn_exec->start_shred_idx = ctx->txn_in.txn->start_shred_idx;
  msg->txn_exec->end_shred_idx   = ctx->txn_in.txn->end_shred_idx;
  if( FD_UNLIKELY( msg->txn_exec->err ) ) {
    uchar * signature = (uchar *)ctx->txn_in.txn->payload + TXN( ctx->txn_in.txn )->signature_off;
    FD_LOG_WARNING(( "txn failed to execute, bad block detected err=%d signature=%s", ctx->txn_out.err.txn_err, FD_BASE58_ENC_64_ALLOCA( signature ) ));
  }

  fd_stem_publish( stem, ctx->exec_replay_out->idx, (FD_EXEC_TT_TXN_EXEC<<32)|ctx->tile_idx, ctx->exec_replay_out->chunk, sizeof(*msg), 0UL, ctx->dispatch_time_comp, fd_frag_meta_ts_comp( fd_tickcount() ) );

  ctx->exec_replay_out->chunk = fd_dcache_compact_next( ctx->exec_replay_out->chunk, sizeof(*msg), ctx->exec_replay_out->chunk0, ctx->exec_replay_out->wmark );

  ctx->pending_txn_finalized_msg = 0;
}

static void
after_credit( fd_exec_tile_ctx_t * ctx,
              fd_stem_context_t *  stem,
              int *                opt_poll_in,
              int *                charge_busy FD_PARAM_UNUSED ) {
  /* If we have outstanding account updates to send to solcap, send
     them.  Note that we set opt_poll_in to 0 here because we must not
     consume any more fragments from the exec tiles before publishing
     our messages, so that solcap updates are not interleaved between
     slots. */
  if( FD_UNLIKELY( ctx->capture_ctx && ctx->account_updates_flushed < ctx->capture_ctx->account_updates_len ) ) {
    publish_next_capture_ctx_account_update( ctx, stem );
    *opt_poll_in = 0;
  } else if( ctx->pending_txn_finalized_msg ) {
    publish_txn_finalized_msg( ctx, stem );
    *opt_poll_in = 0;
  }
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo FD_PARAM_UNUSED,
                          fd_topo_tile_t const * tile FD_PARAM_UNUSED,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  populate_sock_filter_policy_fd_exec_tile( out_cnt, out, (uint)fd_log_private_logfile_fd() );
  return sock_filter_policy_fd_exec_tile_instr_cnt;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo FD_PARAM_UNUSED,
                      fd_topo_tile_t const * tile FD_PARAM_UNUSED,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {

  if( FD_UNLIKELY( out_fds_cnt<2UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  return out_cnt;
}

#define STEM_BURST (2UL)
/* Right now, depth of the replay_exec link and depth of the exec_replay
   links is 16K.  At 1M TPS, that's ~16ms to fill.  But we also want to
   be conservative here, so we use 1ms. */
#define STEM_LAZY  (1000000UL)

#define STEM_CALLBACK_CONTEXT_TYPE  fd_exec_tile_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_exec_tile_ctx_t)

#define STEM_CALLBACK_AFTER_CREDIT    after_credit
#define STEM_CALLBACK_RETURNABLE_FRAG returnable_frag
#define STEM_CALLBACK_METRICS_WRITE   metrics_write

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_execor = {
  .name                     = "exec",
  .loose_footprint          = 0UL,
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};
