#define _GNU_SOURCE

#include "../../disco/tiles.h"
#include "generated/fd_exec_tile_seccomp.h"

struct fd_exec_tile_ctx {
  ulong  replay_exec_in_idx;
  ulong  tile_cnt;
  ulong  tile_idx;

  fd_wksp_t * replay_in_mem;
  ulong       replay_in_chunk0;
  ulong       replay_in_wmark;

  fd_txn_p_t txn; /* current txn */
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
  return FD_LAYOUT_FINI( l, scratch_align() );
  /* clang-format on */
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
    uchar * txn = fd_chunk_to_laddr( ctx->replay_in_mem, chunk );
    fd_memcpy( &ctx->txn, txn, sz );
    FD_LOG_HEXDUMP_DEBUG(( "exec tile recieved txn: ", txn, sz ));
  }
}

static void
after_frag( fd_exec_tile_ctx_t * ctx FD_PARAM_UNUSED,
            ulong                in_idx FD_PARAM_UNUSED,
            ulong                seq,
            ulong                sig,
            ulong                sz,
            ulong                tsorig,
            ulong                tspub,
            fd_stem_context_t *  stem ) {
  (void)seq;
  (void)sig;
  (void)sz;
  (void)tsorig;
  (void)tspub;
  (void)stem;
}

static void
privileged_init( fd_topo_t *      topo FD_PARAM_UNUSED,
                 fd_topo_tile_t * tile FD_PARAM_UNUSED ) {
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_exec_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_exec_tile_ctx_t), sizeof(fd_exec_tile_ctx_t) );

  ctx->tile_cnt = fd_topo_tile_name_cnt( topo, tile->name );
  ctx->tile_idx = tile->kind_id;

  ctx->replay_exec_in_idx = fd_topo_find_tile_in_link( topo, tile, "replay_exec", ctx->tile_idx );
  FD_TEST( ctx->replay_exec_in_idx != ULONG_MAX );
  fd_topo_link_t * replay_exec_in_link = &topo->links[tile->in_link_id[ctx->replay_exec_in_idx]];
  ctx->replay_in_mem = topo->workspaces[topo->objs[replay_exec_in_link->dcache_obj_id].wksp_id].wksp;
  ctx->replay_in_chunk0 = fd_dcache_compact_chunk0( ctx->replay_in_mem, replay_exec_in_link->dcache );
  ctx->replay_in_wmark  = fd_dcache_compact_wmark( ctx->replay_in_mem,
                                                   replay_exec_in_link->dcache,
                                                   replay_exec_in_link->mtu );

  FD_SCRATCH_ALLOC_FINI( l, scratch_align() );
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

#define STEM_CALLBACK_DURING_FRAG during_frag
#define STEM_CALLBACK_AFTER_FRAG  after_frag

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
