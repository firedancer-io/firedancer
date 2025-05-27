#define _GNU_SOURCE
#include "../../disco/tiles.h"
#include "generated/fd_writer_tile_seccomp.h"

#include "../../util/pod/fd_pod_format.h"

#include "../../flamenco/runtime/fd_runtime.h"
#include "../../flamenco/runtime/fd_runtime_public.h"
#include "../../flamenco/runtime/fd_executor.h"

#include "../../funk/fd_funk.h"
#include "../../funk/fd_funk_filemap.h"

struct fd_writer_tile_in_ctx {
  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
};
typedef struct fd_writer_tile_in_ctx fd_writer_tile_in_ctx_t;

struct fd_writer_tile_ctx {
  fd_wksp_t *                 wksp;
  fd_spad_t *                 spad;
  ulong                       tile_cnt;
  ulong                       tile_idx;
  ulong                       exec_tile_cnt;
  ulong                       replay_in_idx;

  /* R/W by this tile and the replay tile. */
  ulong *                     fseq;

  /* Local join of Funk.  R/W. */
  fd_funk_t                   funk[1];
  fd_wksp_t *                 funk_wksp;

  /* Link management. */
  fd_writer_tile_in_ctx_t     exec_writer_in[ FD_PACK_MAX_BANK_TILES ];
  fd_writer_tile_in_ctx_t     replay_writer_in[ 1 ];

  /* Runtime public and local joins of its members. */
  fd_wksp_t const *           runtime_public_wksp;
  fd_runtime_public_t const * runtime_public;
  fd_spad_t const *           runtime_spad;

  //FIXME this should be bank mgr
  /* Local join of replay tile slot ctx.  R/W. */
  fd_exec_slot_ctx_t *        slot_ctx;

  /* Local joins of exec spads.  Read-only. */
  fd_spad_t *                 exec_spad[ FD_PACK_MAX_BANK_TILES ];
  fd_wksp_t *                 exec_spad_wksp[ FD_PACK_MAX_BANK_TILES ];

  /* Local joins of exec tile txn ctx.  Read-only. */
  fd_exec_txn_ctx_t *         txn_ctx[ FD_PACK_MAX_BANK_TILES ];
};
typedef struct fd_writer_tile_ctx fd_writer_tile_ctx_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 128UL;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  ulong l = FD_LAYOUT_INIT;
  l       = FD_LAYOUT_APPEND( l, alignof(fd_writer_tile_ctx_t),  sizeof(fd_writer_tile_ctx_t) );
  l       = FD_LAYOUT_APPEND( l, fd_spad_align(), fd_spad_footprint( FD_RUNTIME_TRANSACTION_FINALIZATION_FOOTPRINT ) );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static void
join_txn_ctx( fd_writer_tile_ctx_t * ctx,
              ulong                  exec_tile_idx,
              uint                   txn_ctx_offset ) {

  ulong exec_spad_gaddr = fd_wksp_gaddr( ctx->exec_spad_wksp[ exec_tile_idx ], ctx->exec_spad[ exec_tile_idx ] );
  if( FD_UNLIKELY( !exec_spad_gaddr ) ) {
    FD_LOG_CRIT(( "Unable to get gaddr of exec_spad %lu", exec_tile_idx ));
  }

  ulong   txn_ctx_gaddr = exec_spad_gaddr + txn_ctx_offset;
  uchar * txn_ctx_laddr = fd_wksp_laddr( ctx->exec_spad_wksp[ exec_tile_idx ], txn_ctx_gaddr );
  if( FD_UNLIKELY( !txn_ctx_laddr ) ) {
    FD_LOG_CRIT(( "Unable to get laddr of the txn ctx at gaddr 0x%lx from exec_spad %lu", txn_ctx_gaddr, exec_tile_idx ));
  }

  ctx->txn_ctx[ exec_tile_idx ] = fd_exec_txn_ctx_join( txn_ctx_laddr,
                                                        ctx->exec_spad[ exec_tile_idx ],
                                                        ctx->exec_spad_wksp[ exec_tile_idx ] );
  if( FD_UNLIKELY( !ctx->txn_ctx[ exec_tile_idx ] ) ) {
    FD_LOG_CRIT(( "Unable to join txn ctx at gaddr 0x%lx laddr 0x%lx from exec_spad %lu", txn_ctx_gaddr, (ulong)txn_ctx_laddr, exec_tile_idx ));
  }
}

static int
before_frag( fd_writer_tile_ctx_t * ctx,
             ulong                  in_idx,
             ulong                  seq,
             ulong                  sig ) {
  if( FD_UNLIKELY( in_idx==ctx->replay_in_idx ) ) {
    /* All messages from replay go through. */
    return 0;
  }

  /* Round-robin.

     The usual round-robin strategy of returning
     (seq % ctx->tile_cnt) != ctx->tile_idx
     here suffers somewhat from a sort of convoy effect.
     This is because exec tiles do not proceed to the next transaction
     until transaction finalization has been done.  In other words, exec
     tiles block on writer tiles, rather than truly pipelining.  As a
     result, when all the exec tiles publish to seq 0, the 0th writer
     tile becomes busy, and all exec tiles block on it.  Then writer tile
     1 becomes busy, while all other writer tiles sit idle.  So on and so
     forth.

     So we offset by in_idx to try to mitigate this.
   */
  return ((seq+in_idx) % ctx->tile_cnt) != ctx->tile_idx && sig != FD_WRITER_BOOT_SIG; /* The boot message should go through to all writer tiles. */
}

static void
during_frag( fd_writer_tile_ctx_t * ctx,
             ulong                  in_idx,
             ulong                  seq,
             ulong                  sig,
             ulong                  chunk,
             ulong                  sz,
             ulong                  ctl ) {

  (void)seq;
  (void)ctl;

  if( FD_UNLIKELY( in_idx==ctx->replay_in_idx ) ) {
    fd_writer_tile_in_ctx_t * in_ctx = ctx->replay_writer_in;

    if( FD_UNLIKELY( chunk < in_ctx->chunk0 || chunk > in_ctx->wmark ) ) {
      FD_LOG_CRIT(( "chunk %lu %lu corrupt, not in range [%lu,%lu]",
                    chunk,
                    sz,
                    in_ctx->chunk0,
                    in_ctx->wmark ));
    }

    if( FD_LIKELY( sig==FD_WRITER_SLOT_SIG ) ) {
      //FIXME this should be replaced by bank mgr
      fd_runtime_public_replay_writer_slot_msg_t * msg = fd_type_pun( fd_chunk_to_laddr( in_ctx->mem, chunk ) );
      fd_exec_slot_ctx_t * slot_ctx = fd_wksp_laddr_fast( ctx->runtime_public_wksp, msg->slot_ctx_gaddr );
      if( FD_UNLIKELY( !slot_ctx ) ) {
        FD_LOG_CRIT(( "Unable to join slot_ctx at gaddr 0x%lx", msg->slot_ctx_gaddr ));
      }
      ctx->slot_ctx = slot_ctx;
      return;
    }

    FD_LOG_CRIT(( "Unknown sig %lu from replay to writer %lu", sig, ctx->tile_idx ));
  }

  /* exec_writer is a reliable flow controlled link so we are not gonna
     bother with copying the incoming frag. */

  fd_writer_tile_in_ctx_t * in_ctx = &(ctx->exec_writer_in[ in_idx ]);

  if( FD_UNLIKELY( chunk < in_ctx->chunk0 || chunk > in_ctx->wmark ) ) {
    FD_LOG_CRIT(( "chunk %lu %lu corrupt, not in range [%lu,%lu]",
                  chunk,
                  sz,
                  in_ctx->chunk0,
                  in_ctx->wmark ));
  }

  /* Process messages from exec tiles. */

  if( FD_LIKELY( sig == FD_WRITER_TXN_SIG ) ) {
    fd_runtime_public_exec_writer_txn_msg_t * msg = fd_type_pun( fd_chunk_to_laddr( in_ctx->mem, chunk ) );
    if( FD_UNLIKELY( msg->exec_tile_id!=in_idx ) ) {
      FD_LOG_CRIT(( "exec_tile_id %u should be == in_idx %lu", msg->exec_tile_id, in_idx ));
    }
    fd_execute_txn_task_info_t info = {0};
    info.txn_ctx  = ctx->txn_ctx[ in_idx ];
    info.exec_res = info.txn_ctx->exec_err;

    if( FD_LIKELY( info.txn_ctx->flags & FD_TXN_P_FLAGS_EXECUTE_SUCCESS ) ) {
      while( fd_writer_fseq_get_state( fd_fseq_query( ctx->fseq ) )!=FD_WRITER_STATE_READY ) {
        /* Spin to wait for the replay tile to ack the previous txn
           done. */
        FD_SPIN_PAUSE();
      }
      FD_SPAD_FRAME_BEGIN( ctx->spad ) {
        fd_runtime_finalize_txn( ctx->slot_ctx, NULL, &info, ctx->spad );
      } FD_SPAD_FRAME_END;
    }
    /* Notify the replay tile. */
    fd_fseq_update( ctx->fseq, fd_writer_fseq_set_txn_done( msg->txn_id, msg->exec_tile_id ) );
    return;
  }

  if( FD_UNLIKELY( sig == FD_WRITER_BOOT_SIG ) ) {
    fd_runtime_public_exec_writer_boot_msg_t * msg = fd_type_pun( fd_chunk_to_laddr( in_ctx->mem, chunk ) );
    join_txn_ctx( ctx, in_idx, msg->txn_ctx_offset );
    ulong txn_ctx_cnt = 0UL;
    for( ulong i=0UL; i<ctx->exec_tile_cnt; i++ ) {
      txn_ctx_cnt += fd_ulong_if( ctx->txn_ctx[ i ]!=NULL, 1UL, 0UL );
    }
    if( txn_ctx_cnt==ctx->exec_tile_cnt ) {
      fd_fseq_update( ctx->fseq, FD_WRITER_STATE_READY );
      FD_LOG_NOTICE(( "writer tile %lu fully booted", ctx->tile_idx ));
    }
    return;
  }

  FD_LOG_CRIT(( "Unknown sig %lu", sig ));
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  (void)topo;
  (void)tile;
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {

  /********************************************************************/
  /* Validate allocations                                             */
  /********************************************************************/

  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_writer_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_writer_tile_ctx_t), sizeof(fd_writer_tile_ctx_t) );
  void * spad_mem            = FD_SCRATCH_ALLOC_APPEND( l, fd_spad_align(), fd_spad_footprint( FD_RUNTIME_TRANSACTION_FINALIZATION_FOOTPRINT ) );
  ulong scratch_alloc_mem    = FD_SCRATCH_ALLOC_FINI( l, scratch_align() );
  if( FD_UNLIKELY( scratch_alloc_mem - (ulong)scratch  - scratch_footprint( tile ) ) ) {
    FD_LOG_CRIT( ( "scratch_alloc_mem did not match scratch_footprint diff: %lu alloc: %lu footprint: %lu",
      scratch_alloc_mem - (ulong)scratch - scratch_footprint( tile ),
      scratch_alloc_mem,
      (ulong)scratch + scratch_footprint( tile ) ) );
  }
  fd_memset( ctx, 0, sizeof(*ctx) );
  ctx->wksp = topo->workspaces[ topo->objs[ tile->tile_obj_id ].wksp_id ].wksp;
  ctx->spad = fd_spad_join( fd_spad_new( spad_mem, FD_RUNTIME_TRANSACTION_FINALIZATION_FOOTPRINT ) );

  /********************************************************************/
  /* Links                                                            */
  /********************************************************************/

  ctx->tile_cnt = fd_topo_tile_name_cnt( topo, tile->name );
  ctx->tile_idx = tile->kind_id;

  ulong exec_tile_cnt = fd_topo_tile_name_cnt( topo, "exec" );
  ctx->exec_tile_cnt  = exec_tile_cnt;

  /* Find and setup all the exec_writer links. */
  if( FD_UNLIKELY( exec_tile_cnt!=tile->in_cnt-1UL ) ) {
    FD_LOG_CRIT(( "Expecting one exec_writer link per exec tile but found %lu links and %lu tiles", tile->in_cnt, exec_tile_cnt ));
  }
  for( ulong i=0UL; i<tile->in_cnt-1UL; i++ ) {
    ulong exec_writer_idx = fd_topo_find_tile_in_link( topo, tile, "exec_writer", i );
    if( FD_UNLIKELY( exec_writer_idx==ULONG_MAX ) ) {
      FD_LOG_CRIT(( "Could not find exec_writer in-link %lu", i ));
    }
    fd_topo_link_t * exec_writer_in_link = &topo->links[ tile->in_link_id[ i ] ];
    if( FD_UNLIKELY( !exec_writer_in_link ) ) {
      FD_LOG_CRIT(( "Invalid exec_writer in-link %lu", i ));
    }
    ctx->exec_writer_in[ i ].mem    = topo->workspaces[ topo->objs[ exec_writer_in_link->dcache_obj_id ].wksp_id ].wksp;
    ctx->exec_writer_in[ i ].chunk0 = fd_dcache_compact_chunk0( ctx->exec_writer_in[ i ].mem, exec_writer_in_link->dcache );
    ctx->exec_writer_in[ i ].wmark  = fd_dcache_compact_wmark( ctx->exec_writer_in[ i ].mem,
                                                               exec_writer_in_link->dcache,
                                                               exec_writer_in_link->mtu );
  }

  /* Setup the replay-writer link. */
  fd_topo_link_t * replay_writer_in_link = &topo->links[ tile->in_link_id[ tile->in_cnt-1UL ] ];
  if( FD_UNLIKELY( !replay_writer_in_link ) ) {
    FD_LOG_CRIT(( "Invalid replay_writer in-link" ));
  }
  if( FD_UNLIKELY( strcmp( replay_writer_in_link->name, "replay_wtr" ) ) ) {
    FD_LOG_CRIT(( "Unexpected in link named %s", replay_writer_in_link->name ));
  }
  ctx->replay_in_idx            = tile->in_cnt - 1UL;
  ctx->replay_writer_in->mem    = topo->workspaces[ topo->objs[ replay_writer_in_link->dcache_obj_id ].wksp_id ].wksp;
  ctx->replay_writer_in->chunk0 = fd_dcache_compact_chunk0( ctx->replay_writer_in->mem, replay_writer_in_link->dcache );
  ctx->replay_writer_in->wmark  = fd_dcache_compact_wmark( ctx->replay_writer_in->mem,
                                                           replay_writer_in_link->dcache,
                                                           replay_writer_in_link->mtu );

  /********************************************************************/
  /* Setup runtime public                                             */
  /********************************************************************/

  ulong runtime_obj_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "runtime_pub" );
  if( FD_UNLIKELY( runtime_obj_id==ULONG_MAX ) ) {
    FD_LOG_ERR(( "Could not find topology object for runtime public" ));
  }

  ctx->runtime_public_wksp = topo->workspaces[ topo->objs[ runtime_obj_id ].wksp_id ].wksp;
  if( FD_UNLIKELY( !ctx->runtime_public_wksp ) ) {
    FD_LOG_ERR(( "No runtime_public workspace" ));
  }

  ctx->runtime_public = fd_runtime_public_join( fd_topo_obj_laddr( topo, runtime_obj_id ) );
  if( FD_UNLIKELY( !ctx->runtime_public ) ) {
    FD_LOG_ERR(( "Failed to join runtime public" ));
  }

  ctx->runtime_spad = fd_runtime_public_spad( ctx->runtime_public );
  if( FD_UNLIKELY( !ctx->runtime_spad ) ) {
    FD_LOG_ERR(( "Failed to get and join runtime spad" ));
  }

  /********************************************************************/
  /* Spad                                                             */
  /********************************************************************/

  /* Join all of the exec spads. */
  for( ulong i=0UL; i<exec_tile_cnt; i++ ) {
    ulong exec_spad_obj_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "exec_spad.%lu", i );
    if( FD_UNLIKELY( exec_spad_obj_id==ULONG_MAX ) ) {
      FD_LOG_CRIT(( "Could not find topology object for exec_spad.%lu", i ));
    }

    ctx->exec_spad[ i ] = fd_spad_join( fd_topo_obj_laddr( topo, exec_spad_obj_id ) );
    if( FD_UNLIKELY( !ctx->exec_spad[ i ] ) ) {
      FD_LOG_CRIT(( "Failed to join exec_spad.%lu", i ));
    }
    ctx->exec_spad_wksp[ i ] = fd_wksp_containing( ctx->exec_spad[ i ] );
    if( FD_UNLIKELY( !ctx->exec_spad_wksp[ i ] ) ) {
      FD_LOG_CRIT(( "Failed to find wksp for exec_spad.%lu", i ));
    }
  }

  /********************************************************************/
  /* Funk                                                             */
  /********************************************************************/

  FD_LOG_DEBUG(( "Trying to join funk at file=%s", tile->writer.funk_file ));
  fd_funk_txn_start_write( NULL );
  int funk_join_ok = !!fd_funk_open_file( ctx->funk,
      tile->writer.funk_file,
      1UL,
      0UL,
      0UL,
      0UL,
      0UL,
      FD_FUNK_READ_WRITE,
      NULL );
  fd_funk_txn_end_write( NULL );
  ctx->funk_wksp = fd_funk_wksp( ctx->funk );
  if( FD_UNLIKELY( !funk_join_ok ) ) {
    FD_LOG_CRIT(( "Failed to join funk" ));
  }
  FD_LOG_DEBUG(( "Just joined funk at file=%s", tile->writer.funk_file ));

  /********************************************************************/
  /* Setup fseq                                                       */
  /********************************************************************/

  ulong writer_fseq_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "writer_fseq.%lu", ctx->tile_idx );
  ctx->fseq = fd_fseq_join( fd_topo_obj_laddr( topo, writer_fseq_id ) );
  if( FD_UNLIKELY( !ctx->fseq ) ) {
    FD_LOG_CRIT(( "writer tile %lu fseq setup failed", ctx->tile_idx ));
  }
  fd_fseq_update( ctx->fseq, FD_WRITER_STATE_NOT_BOOTED );
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  (void)topo;
  (void)tile;

  populate_sock_filter_policy_fd_writer_tile( out_cnt, out, (uint)fd_log_private_logfile_fd() );
  return sock_filter_policy_fd_writer_tile_instr_cnt;
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

#define STEM_CALLBACK_CONTEXT_TYPE  fd_writer_tile_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_writer_tile_ctx_t)

#define STEM_CALLBACK_BEFORE_FRAG  before_frag
#define STEM_CALLBACK_DURING_FRAG  during_frag

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_writer = {
    .name                     = "writer",
    .loose_footprint          = 0UL,
    .populate_allowed_seccomp = populate_allowed_seccomp,
    .populate_allowed_fds     = populate_allowed_fds,
    .scratch_align            = scratch_align,
    .scratch_footprint        = scratch_footprint,
    .privileged_init          = privileged_init,
    .unprivileged_init        = unprivileged_init,
    .run                      = stem_run,
};
