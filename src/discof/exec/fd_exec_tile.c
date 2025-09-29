#include "../../disco/tiles.h"
#include "generated/fd_exec_tile_seccomp.h"

#include "../../util/pod/fd_pod_format.h"
#include "../../discof/replay/fd_exec.h"
#include "../../flamenco/runtime/context/fd_capture_ctx.h"
#include "../../flamenco/runtime/fd_bank.h"
#include "../../flamenco/runtime/fd_runtime.h"
#include "../../disco/metrics/fd_metrics.h"

#include "../../funk/fd_funk.h"

/* The exec tile is responsible for executing single transactions. The
   tile recieves a parsed transaction (fd_txn_p_t) and an identifier to
   which bank to execute against (index into the bank pool). With this,
   the exec tile is able to identify the correct bank and accounts db
   handle (funk_txn) to execute the transaction against. The results of
   the execution are then published to the writer tile(s). A writer tile
   is responsible for committing the results of the transaction to the
   accounts db and making any updates to the bank. */

struct fd_exec_tile_out_ctx {
  ulong       idx;
  fd_wksp_t * mem;
  ulong       chunk;
  ulong       chunk0;
  ulong       wmark;
};
typedef struct fd_exec_tile_out_ctx fd_exec_tile_out_ctx_t;

struct fd_exec_tile_ctx {

  /* link-related data structures. */
  ulong                 replay_exec_in_idx;
  ulong                 tile_idx;

  fd_wksp_t *           replay_in_mem;
  ulong                 replay_in_chunk0;
  ulong                 replay_in_wmark;

  fd_exec_tile_out_ctx_t exec_writer_out[ 1 ];
  uchar                  boot_msg_sent;

  /* Shared bank hash cmp object. */
  fd_bank_hash_cmp_t *  bank_hash_cmp;

  fd_spad_t *           exec_spad;
  fd_wksp_t *           exec_spad_wksp;

  /* Data structures related to managing and executing the transaction.
     The fd_txn_p_t is refreshed with every transaction and is sent
     from the dispatch/replay tile. The fd_exec_txn_ctx_t * is a valid
     local join that lives in the top-most frame of the spad that is
     setup when the exec tile is booted; its members are refreshed on
     the slot/epoch boundary. */
  fd_exec_txn_ctx_t *   txn_ctx;

  /* Capture context for debugging runtime execution. */
  fd_capture_ctx_t *    capture_ctx;

  /* A transaction can be executed as long as there is a valid handle to
     a funk_txn and a bank. These are queried from fd_banks_t and
     fd_funk_t.
     TODO: These should probably be made read-only handles. */
  fd_banks_t *          banks;
  fd_funk_t             funk[1];
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
  l       = FD_LAYOUT_APPEND( l, alignof(fd_exec_tile_ctx_t), sizeof(fd_exec_tile_ctx_t) );
  l       = FD_LAYOUT_APPEND( l, fd_capture_ctx_align(),      fd_capture_ctx_footprint() );
  return FD_LAYOUT_FINI( l, scratch_align() );
  /* clang-format on */
}

static int
before_frag( fd_exec_tile_ctx_t * ctx,
             ulong                in_idx FD_FN_UNUSED,
             ulong                seq    FD_FN_UNUSED,
             ulong                sig ) {
  return (sig&0xFFFFFFFFUL)!=ctx->tile_idx;
}

static void
during_frag( fd_exec_tile_ctx_t * ctx,
             ulong                in_idx,
             ulong                seq FD_PARAM_UNUSED,
             ulong                sig,
             ulong                chunk,
             ulong                sz,
             ulong                ctl FD_PARAM_UNUSED ) {

  if( FD_LIKELY( in_idx==ctx->replay_exec_in_idx ) ) {
    if( FD_UNLIKELY( chunk < ctx->replay_in_chunk0 || chunk > ctx->replay_in_wmark ) ) {
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]",
                   chunk,
                   sz,
                   ctx->replay_in_chunk0,
                   ctx->replay_in_wmark ));
    }

    if( FD_LIKELY( (sig>>32)==EXEC_NEW_TXN_SIG ) ) {
      fd_exec_txn_msg_t * txn = (fd_exec_txn_msg_t *)fd_chunk_to_laddr( ctx->replay_in_mem, chunk );

      ctx->txn_ctx->spad      = ctx->exec_spad;
      ctx->txn_ctx->spad_wksp = ctx->exec_spad_wksp;

      ctx->txn_ctx->exec_err = fd_runtime_prepare_and_execute_txn(
          ctx->banks,
          txn->bank_idx,
          ctx->txn_ctx,
          &txn->txn,
          ctx->exec_spad,
          ctx->capture_ctx,
          1 );

      return;
    } else {
      FD_LOG_CRIT(( "Unknown signature" ));
    }
  }
}

static void
after_frag( fd_exec_tile_ctx_t * ctx,
            ulong                in_idx FD_PARAM_UNUSED,
            ulong                seq    FD_PARAM_UNUSED,
            ulong                sig,
            ulong                sz     FD_PARAM_UNUSED,
            ulong                tsorig,
            ulong                tspub,
            fd_stem_context_t *  stem ) {

  if( FD_LIKELY( (sig>>32)==EXEC_NEW_TXN_SIG ) ) {
    //FD_LOG_DEBUG(( "Sending ack for new txn msg" ));
    /* At this point we can assume that the transaction is done
       executing. A writer tile will be repsonsible for commiting
       the transaction back to funk. */

    fd_exec_tile_out_ctx_t * exec_out = ctx->exec_writer_out;

    fd_exec_writer_txn_msg_t * msg = fd_type_pun( fd_chunk_to_laddr( exec_out->mem, exec_out->chunk ) );
    msg->exec_tile_id = (uchar)ctx->tile_idx;

    fd_stem_publish(
        stem,
        exec_out->idx,
        FD_WRITER_TXN_SIG,
        exec_out->chunk,
        sizeof(*msg),
        0UL,
        tsorig,
        tspub );
    exec_out->chunk = fd_dcache_compact_next( exec_out->chunk, sizeof(*msg), exec_out->chunk0, exec_out->wmark );
  } else {
    FD_LOG_ERR(( "Unknown message signature" ));
  }
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {

  /********************************************************************/
  /* validate allocations                                             */
  /********************************************************************/

  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_exec_tile_ctx_t * ctx               = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_exec_tile_ctx_t), sizeof(fd_exec_tile_ctx_t) );
  void *               capture_ctx_mem   = FD_SCRATCH_ALLOC_APPEND( l, fd_capture_ctx_align(),      fd_capture_ctx_footprint() );
  ulong                scratch_alloc_mem = FD_SCRATCH_ALLOC_FINI( l, scratch_align() );
  if( FD_UNLIKELY( scratch_alloc_mem - (ulong)scratch  - scratch_footprint( tile ) ) ) {
    FD_LOG_ERR( ( "Scratch_alloc_mem did not match scratch_footprint diff: %lu alloc: %lu footprint: %lu",
      scratch_alloc_mem - (ulong)scratch - scratch_footprint( tile ),
      scratch_alloc_mem,
      (ulong)scratch + scratch_footprint( tile ) ) );
  }

  /********************************************************************/
  /* validate links                                                   */
  /********************************************************************/

  ctx->tile_idx = tile->kind_id;

  /* First find and setup the in-link from replay to exec. */
  ctx->replay_exec_in_idx = fd_topo_find_tile_in_link( topo, tile, "replay_exec", 0UL );
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

  /* Setup out link. */
  ulong idx = fd_topo_find_tile_out_link( topo, tile, "exec_writer", ctx->tile_idx );
  fd_topo_link_t * exec_out_link = &topo->links[ tile->out_link_id[ idx ] ];

  if( strcmp( exec_out_link->name, "exec_writer" ) ) {
    FD_LOG_CRIT(("exec_writer link has unexpected name %s", exec_out_link->name ));
  }

  fd_exec_tile_out_ctx_t * exec_out = ctx->exec_writer_out;
  exec_out->idx                     = idx;
  exec_out->mem                     = topo->workspaces[ topo->objs[ exec_out_link->dcache_obj_id ].wksp_id ].wksp;
  exec_out->chunk0                  = fd_dcache_compact_chunk0( exec_out->mem, exec_out_link->dcache );
  exec_out->wmark                   = fd_dcache_compact_wmark( exec_out->mem, exec_out_link->dcache, exec_out_link->mtu );
  exec_out->chunk                   = exec_out->chunk0;
  ctx->boot_msg_sent                = 0U;

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
  ctx->exec_spad_wksp = fd_wksp_containing( ctx->exec_spad );

  /********************************************************************/
  /* bank hash cmp                                                    */
  /********************************************************************/

  ulong bank_hash_cmp_obj_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "bh_cmp" );
  if( FD_UNLIKELY( bank_hash_cmp_obj_id==ULONG_MAX ) ) {
    FD_LOG_ERR(( "Could not find topology object for bank hash cmp" ));
  }
  ctx->bank_hash_cmp = fd_bank_hash_cmp_join( fd_topo_obj_laddr( topo, bank_hash_cmp_obj_id ) );
  if( FD_UNLIKELY( !ctx->bank_hash_cmp ) ) {
    FD_LOG_ERR(( "Failed to join bank hash cmp" ));
  }

  /********************************************************************/
  /* funk-specific setup                                              */
  /********************************************************************/

  if( FD_UNLIKELY( !fd_funk_join( ctx->funk, fd_topo_obj_laddr( topo, tile->exec.funk_obj_id ) ) ) ) {
    FD_LOG_ERR(( "Failed to join database cache" ));
  }

  /********************************************************************/
  /* setup txncache                                                   */
  /********************************************************************/

  /* TODO: Implement this. */

  /********************************************************************/
  /* setup txn ctx                                                    */
  /********************************************************************/

  fd_spad_push( ctx->exec_spad );
  // FIXME account for this in exec spad footprint
  uchar * txn_ctx_mem         = fd_spad_alloc_check( ctx->exec_spad, FD_EXEC_TXN_CTX_ALIGN, FD_EXEC_TXN_CTX_FOOTPRINT );
  ctx->txn_ctx                = fd_exec_txn_ctx_join( fd_exec_txn_ctx_new( txn_ctx_mem ), ctx->exec_spad, ctx->exec_spad_wksp );
  *ctx->txn_ctx->funk         = *ctx->funk;
  ctx->txn_ctx->bank_hash_cmp = ctx->bank_hash_cmp;

  FD_LOG_INFO(( "Done booting exec tile idx=%lu", ctx->tile_idx ));

  if( strlen( tile->exec.dump_proto_dir )>0 ) {
    ctx->capture_ctx = fd_capture_ctx_new( capture_ctx_mem );
    ctx->capture_ctx->dump_proto_output_dir = tile->exec.dump_proto_dir;
    ctx->capture_ctx->dump_proto_start_slot = tile->exec.capture_start_slot;
    ctx->capture_ctx->dump_instr_to_pb      = tile->exec.dump_instr_to_pb;
    ctx->capture_ctx->dump_txn_to_pb        = tile->exec.dump_txn_to_pb;
    ctx->capture_ctx->dump_syscall_to_pb    = tile->exec.dump_syscall_to_pb;
    ctx->capture_ctx->dump_elf_to_pb        = tile->exec.dump_elf_to_pb;
  } else {
    ctx->capture_ctx = NULL;
  }
}

static void
after_credit( fd_exec_tile_ctx_t * ctx,
              fd_stem_context_t *  stem,
              int *                opt_poll_in FD_PARAM_UNUSED,
              int *                charge_busy FD_PARAM_UNUSED ) {

  if( FD_UNLIKELY( !ctx->boot_msg_sent ) ) {

    ctx->boot_msg_sent = 1U;

    ulong txn_ctx_gaddr = fd_wksp_gaddr( ctx->exec_spad_wksp, ctx->txn_ctx );
    if( FD_UNLIKELY( !txn_ctx_gaddr ) ) {
      FD_LOG_CRIT(( "Could not get gaddr for txn_ctx" ));
    }

    ulong exec_spad_gaddr = fd_wksp_gaddr( ctx->exec_spad_wksp, ctx->exec_spad );
    if( FD_UNLIKELY( !exec_spad_gaddr ) ) {
      FD_LOG_CRIT(( "Could not get gaddr for exec_spad" ));
    }

    if( FD_UNLIKELY( txn_ctx_gaddr-exec_spad_gaddr>UINT_MAX ) ) {
      FD_LOG_CRIT(( "txn_ctx offset from exec spad is too large" ));
    }

    uint txn_ctx_offset = (uint)(txn_ctx_gaddr-exec_spad_gaddr);

    /* Notify writer tiles. */

    ulong tsorig = fd_frag_meta_ts_comp( fd_tickcount() );

    fd_exec_tile_out_ctx_t * exec_out = ctx->exec_writer_out;

    fd_exec_writer_boot_msg_t * msg = fd_type_pun( fd_chunk_to_laddr( exec_out->mem, exec_out->chunk ) );

    msg->txn_ctx_offset = txn_ctx_offset;

    ulong tspub = fd_frag_meta_ts_comp( fd_tickcount() );
    fd_stem_publish( stem,
                     exec_out->idx,
                     FD_WRITER_BOOT_SIG,
                     exec_out->chunk,
                     sizeof(*msg),
                     0UL,
                     tsorig,
                     tspub );
    exec_out->chunk = fd_dcache_compact_next( exec_out->chunk, sizeof(*msg), exec_out->chunk0, exec_out->wmark );

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

#define STEM_BURST (1UL)
/* Right now, depth of the exec_writer link is 128.  At 1M TPS per exec, that's
   128us to fill.  In reality, we'd need more than 1 exec for 1M TPS,
   but we also want to be conservative here, and normally we have a /1.5
   factor in the calculation as well, so we use 75us. */
#define STEM_LAZY  (75000UL)

#define STEM_CALLBACK_CONTEXT_TYPE  fd_exec_tile_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_exec_tile_ctx_t)

#define STEM_CALLBACK_BEFORE_FRAG  before_frag
#define STEM_CALLBACK_AFTER_CREDIT after_credit
#define STEM_CALLBACK_DURING_FRAG  during_frag
#define STEM_CALLBACK_AFTER_FRAG   after_frag

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
