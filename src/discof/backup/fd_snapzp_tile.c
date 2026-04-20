#include "fd_snapmk.h"
#include "../../disco/topo/fd_topo.h"

struct fd_snapzp {
  uint    state;
  ulong * fseq;
};
typedef struct fd_snapzp fd_snapzp_t;

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  fd_snapzp_t * snapzp = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  memset( snapzp, 0, sizeof(fd_snapzp_t) );
  snapzp->state = SNAPMK_STATE_IDLE;
  snapzp->fseq  = fd_fseq_join( fd_topo_obj_laddr( topo, tile->in_link_fseq_obj_id[ 0 ] ) );
  FD_TEST( snapzp->fseq );
}

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 128UL;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_snapzp_t), sizeof(fd_snapzp_t) );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static ulong
populate_allowed_fds( fd_topo_t const *      topo,
                      fd_topo_tile_t const * tile,
                      ulong                  out_fds_cnt,
                      int *                  out_fds ) {
  (void)topo; (void)tile;
  if( FD_UNLIKELY( out_fds_cnt<2UL ) ) FD_LOG_ERR(( "out_fds_cnt %lu", out_fds_cnt ));
  ulong out_cnt = 0UL;
  out_fds[ out_cnt++ ] = 2; /* stderr */
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) )
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd(); /* logfile */
  return out_cnt;
}

static void
before_credit( fd_snapzp_t *       ctx,
               fd_stem_context_t * stem,
               int *               charge_busy ) {
  (void)ctx; (void)stem; (void)charge_busy;

  // if( ctx->state == SNAPMK_STATE_IDLE ) {
  //   fd_log_sleep( (long)1e6 );
  //   return;
  // }
}

static int
returnable_frag( fd_snapzp_t *       ctx,
                 ulong               in_idx,
                 ulong               seq,
                 ulong               sig,
                 ulong               chunk,
                 ulong               sz,
                 ulong               ctl,
                 ulong               tsorig,
                 ulong               tspub,
                 fd_stem_context_t * stem ) {
  (void)ctx; (void)in_idx; (void)seq; (void)sig; (void)chunk; (void)sz; (void)ctl; (void)tsorig; (void)tspub; (void)stem;
  fd_fseq_update( ctx->fseq, seq );
  return 0;
}

#define STEM_BURST 1UL
#define STEM_LAZY  10000UL
#define STEM_CALLBACK_CONTEXT_TYPE    fd_snapzp_t
#define STEM_CALLBACK_CONTEXT_ALIGN   alignof(fd_snapzp_t)
#define STEM_CALLBACK_BEFORE_CREDIT   before_credit
#define STEM_CALLBACK_RETURNABLE_FRAG returnable_frag
#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_snapzp = {
  .name                     = "snapzp",
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run
};
