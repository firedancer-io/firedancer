#include "fd_votor_tile.h"
#include "generated/fd_votor_tile_seccomp.h"

#include "../../disco/stem/fd_stem.h"
#include "../../disco/topo/fd_topo.h"

#define IN_KIND_REPLAY (0)
#define IN_KIND_EPOCH  (1)
#define IN_KIND_IPECHO (2)

struct fd_votor_tile {
  int in_kind[ 32 ];
};
typedef struct fd_votor_tile fd_votor_tile_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return alignof(fd_votor_tile_t);
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_votor_tile_t), sizeof(fd_votor_tile_t) );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static void
after_frag( fd_votor_tile_t *   ctx,
            ulong               in_idx,
            ulong               seq,
            ulong               sig,
            ulong               sz,
            ulong               tsorig,
            ulong               tspub,
            fd_stem_context_t * stem ) {
  (void)seq; (void)sig; (void)sz; (void)tsorig; (void)tspub; (void)stem;

  switch( ctx->in_kind[ in_idx ] ) {
  case IN_KIND_REPLAY: break;
  case IN_KIND_EPOCH:  break;
  case IN_KIND_IPECHO: break;
  default:             break;
  }
}

static void
unprivileged_init( fd_topo_t const *      topo,
                   fd_topo_tile_t const * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_votor_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_votor_tile_t), sizeof(fd_votor_tile_t) );
  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, scratch_align() );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));

  FD_TEST( tile->in_cnt<=sizeof(ctx->in_kind)/sizeof(ctx->in_kind[0]) );
  for( ulong i=0UL; i<tile->in_cnt; i++ ) {
    fd_topo_link_t const * link = &topo->links[ tile->in_link_id[ i ] ];

    if     ( FD_LIKELY( !strcmp( link->name, "replay_out"   ) ) ) ctx->in_kind[ i ] = IN_KIND_REPLAY;
    else if( FD_LIKELY( !strcmp( link->name, "replay_epoch" ) ) ) ctx->in_kind[ i ] = IN_KIND_EPOCH;
    else if( FD_LIKELY( !strcmp( link->name, "ipecho_out"   ) ) ) ctx->in_kind[ i ] = IN_KIND_IPECHO;
    else FD_LOG_ERR(( "votor tile has unexpected input link %lu %s", i, link->name ));
  }
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  (void)topo; (void)tile;
  populate_sock_filter_policy_fd_votor_tile( out_cnt, out, (uint)fd_log_private_logfile_fd() );
  return sock_filter_policy_fd_votor_tile_instr_cnt;
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
    out_fds[ out_cnt++ ] = fd_log_private_logfile_fd();
  return out_cnt;
}

#define STEM_BURST (1UL)
#define STEM_LAZY  (128L*3000L)

#define STEM_CALLBACK_CONTEXT_TYPE  fd_votor_tile_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_votor_tile_t)
#define STEM_CALLBACK_AFTER_FRAG    after_frag

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_votor = {
  .name                     = "votor",
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};
