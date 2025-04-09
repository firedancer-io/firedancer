#include <stdlib.h>
#define _GNU_SOURCE
#include "../../disco/tiles.h"
#include "generated/fd_arxiv_tile_seccomp.h"
#include "fd_shred_arxiv.h"
#include "../../disco/topo/fd_pod_format.h"

#define REPLAY_IN_IDX 0UL

struct fd_arxiv_tile_ctx {
  fd_shred_arxiver_t * arxiver;
  int arxiver_fd; /* file descriptor for the archive file */
  fd_blockstore_t   blockstore_ljoin;
  fd_blockstore_t * blockstore;

  void *            replay_in_mem;
  ulong             replay_in_chunk0;
  ulong             replay_in_wmark;
};
typedef struct fd_arxiv_tile_ctx fd_arxiv_tile_ctx_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 128UL;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile FD_PARAM_UNUSED ) {
  /* clang-format off */
  ulong l = FD_LAYOUT_INIT;
  l       = FD_LAYOUT_APPEND( l, alignof(fd_arxiv_tile_ctx_t),  sizeof(fd_arxiv_tile_ctx_t) );
  l       = FD_LAYOUT_APPEND( l, fd_shred_arxiv_align(),       fd_shred_arxiv_footprint( FD_SHRED_ARXIV_MIN_SIZE ) );
  return FD_LAYOUT_FINI( l, scratch_align() );
  /* clang-format on */
}

static void
during_frag( fd_arxiv_tile_ctx_t * ctx,
             ulong                in_idx,
             ulong                seq FD_PARAM_UNUSED,
             ulong                sig FD_PARAM_UNUSED,
             ulong                chunk,
             ulong                sz,
             ulong                ctl FD_PARAM_UNUSED ) {

  if( in_idx == REPLAY_IN_IDX ) {
    if( FD_UNLIKELY( chunk<ctx->replay_in_chunk0 || chunk>ctx->replay_in_wmark || sz>USHORT_MAX ) ) {
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->replay_in_chunk0, ctx->replay_in_wmark ));
    }
    ulong slot      = fd_disco_replay_arxiv_sig_slot( sig );
    uint  start_idx = fd_disco_replay_arxiv_sig_start_idx( sig );
    uint  end_idx   = fd_disco_replay_arxiv_sig_end_idx( sig );

    fd_shreds_checkpt( ctx->arxiver, ctx->blockstore, slot, start_idx, end_idx );
  }

  (void)chunk;
  (void)sz;
}

static void
after_frag( fd_arxiv_tile_ctx_t * ctx,
             ulong                in_idx FD_PARAM_UNUSED,
             ulong                seq    FD_PARAM_UNUSED,
             ulong                sig    FD_PARAM_UNUSED,
             ulong                sz     FD_PARAM_UNUSED,
             ulong                tsorig FD_PARAM_UNUSED,
             ulong                tspub  FD_PARAM_UNUSED,
             fd_stem_context_t *  stem   FD_PARAM_UNUSED ) {
  (void)ctx;
  /* Let's test for fun that the shred was written to file properly */
  if( in_idx == REPLAY_IN_IDX ) {
    FD_LOG_WARNING(( "replay in idx %lu", in_idx ));
    ulong slot      = fd_disco_replay_arxiv_sig_slot( sig );
    uint  end_idx   = fd_disco_replay_arxiv_sig_end_idx( sig );

    fd_shred_idx_t * idx = fd_shred_idx_query( ctx->arxiver->shred_idx, slot << 32 | end_idx, NULL );
    uchar shred_buf[FD_SHRED_MIN_SZ];
    int err = fd_shred_restore( ctx->arxiver, idx, shred_buf, FD_SHRED_MIN_SZ );
    FD_TEST( err == 0 );
    const fd_shred_t * shred = fd_shred_parse( shred_buf, FD_SHRED_MIN_SZ );
    FD_TEST( shred->slot == slot );
    FD_TEST( shred->idx  == end_idx );
  }

}

static void
privileged_init( fd_topo_t *      topo FD_PARAM_UNUSED,
                  fd_topo_tile_t * tile FD_PARAM_UNUSED ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_arxiv_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_arxiv_tile_ctx_t), sizeof(fd_arxiv_tile_ctx_t) );
  FD_SCRATCH_ALLOC_FINI( l, scratch_align() );
  memset( ctx, 0, sizeof(fd_arxiv_tile_ctx_t) );

  ctx->arxiver_fd = open( tile->arxiv.blockstore_file, O_RDWR|O_CREAT, 0666 );
  if( FD_UNLIKELY( ctx->arxiver_fd==-1 ) ) {
    FD_LOG_ERR(( "failed to open arxiver fd" ));
  }
}

static void
unprivileged_init( fd_topo_t *      topo,
                    fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_arxiv_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_arxiv_tile_ctx_t), sizeof(fd_arxiv_tile_ctx_t) );
  void * arxiver = FD_SCRATCH_ALLOC_APPEND( l, fd_shred_arxiv_align(), fd_shred_arxiv_footprint( FD_SHRED_ARXIV_MIN_SIZE ) );
  ulong scratch_alloc_mem = FD_SCRATCH_ALLOC_FINI( l, scratch_align() );
  if( FD_UNLIKELY( scratch_alloc_mem - (ulong)scratch - scratch_footprint( tile ) ) ) {
    FD_LOG_ERR(( "scratch footprint mismatch" ));
  }

  ulong blockstore_obj_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX,"blockstore" );
  FD_TEST( blockstore_obj_id!=ULONG_MAX );
  ctx->blockstore = fd_blockstore_join( &ctx->blockstore_ljoin, fd_topo_obj_laddr( topo, blockstore_obj_id ) );

  FD_TEST( ctx->blockstore->shmem->magic == FD_BLOCKSTORE_MAGIC );

  ctx->arxiver     = fd_shred_arxiv_join( fd_shred_arxiv_new( arxiver, FD_SHRED_ARXIV_MIN_SIZE ) );
  ctx->arxiver->fd = ctx->arxiver_fd;

  /**********************************************************************/
  /* links                                                              */
  /**********************************************************************/

  /* Setup replay tile input */
  fd_topo_link_t * replay_in_link = &topo->links[ tile->in_link_id[ REPLAY_IN_IDX ] ];
  ctx->replay_in_mem              = topo->workspaces[ topo->objs[ replay_in_link->dcache_obj_id ].wksp_id ].wksp;
  ctx->replay_in_chunk0           = fd_dcache_compact_chunk0( ctx->replay_in_mem, replay_in_link->dcache );
  ctx->replay_in_wmark            = fd_dcache_compact_wmark( ctx->replay_in_mem, replay_in_link->dcache, replay_in_link->mtu );

}

static void
after_credit( fd_arxiv_tile_ctx_t * ctx,
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

  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_arxiv_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_arxiv_tile_ctx_t), sizeof(fd_arxiv_tile_ctx_t) );
  FD_SCRATCH_ALLOC_FINI( l, sizeof(fd_arxiv_tile_ctx_t) );

  populate_sock_filter_policy_fd_arxiv_tile( out_cnt, out, (uint)fd_log_private_logfile_fd(), (uint)ctx->arxiver_fd );
  return sock_filter_policy_fd_arxiv_tile_instr_cnt;
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_arxiv_tile_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_arxiv_tile_ctx_t), sizeof(fd_arxiv_tile_ctx_t) );
  FD_SCRATCH_ALLOC_FINI( l, sizeof(fd_arxiv_tile_ctx_t) );

  if( FD_UNLIKELY( out_fds_cnt<2UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));

  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  out_fds[ out_cnt++ ] = ctx->arxiver_fd; /* shred store fd */
  return out_cnt;
}


#define STEM_BURST (1UL)

#define STEM_CALLBACK_CONTEXT_TYPE  fd_arxiv_tile_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_arxiv_tile_ctx_t)

#define STEM_CALLBACK_DURING_FRAG  during_frag
#define STEM_CALLBACK_AFTER_FRAG   after_frag
#define STEM_CALLBACK_AFTER_CREDIT after_credit

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_arxiv = {
    .name                     = "arxiv",
    .loose_footprint          = 0UL,
    .populate_allowed_seccomp = populate_allowed_seccomp,
    .populate_allowed_fds     = populate_allowed_fds,
    .scratch_align            = scratch_align,
    .scratch_footprint        = scratch_footprint,
    .privileged_init          = privileged_init,
    .unprivileged_init        = unprivileged_init,
    .run                      = stem_run,
};
