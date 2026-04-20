#include "fd_snapmk.h"
#include "../../disco/topo/fd_topo.h"
#include "../../funk/fd_funk.h"
#include "../../util/pod/fd_pod.h"
#include "../../flamenco/runtime/fd_runtime_const.h"

struct fd_snapzp {
  fd_funk_t funk[1];

  fd_pubkey_t account;
  uchar       data[ FD_RUNTIME_ACC_SZ_MAX ];
};
typedef struct fd_snapzp fd_snapzp_t;

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  fd_snapzp_t * ctx = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  memset( ctx, 0, sizeof(fd_snapzp_t) );

  ulong funk_obj_id;  FD_TEST( (funk_obj_id  = fd_pod_query_ulong( topo->props, "funk",       ULONG_MAX ) )!=ULONG_MAX );
  ulong locks_obj_id; FD_TEST( (locks_obj_id = fd_pod_query_ulong( topo->props, "funk_locks", ULONG_MAX ) )!=ULONG_MAX );
  FD_TEST( fd_funk_join( ctx->funk, fd_topo_obj_laddr( topo, funk_obj_id ), fd_topo_obj_laddr( topo, locks_obj_id ) ) );
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
  ulong rec_idx   = tsorig;
  ulong val_gaddr = sig;

  fd_funk_rec_t const *     rec = &ctx->funk->rec_pool->ele[ rec_idx ];
  fd_account_meta_t const * val = fd_wksp_laddr_fast( ctx->funk->wksp, val_gaddr );
  ulong data_sz = val->dlen;
  fd_memcpy( ctx->account.key, rec->pair.key, sizeof(fd_pubkey_t) );
  fd_memcpy( ctx->data, fd_account_data( val ), data_sz );

  return 0;
}

#define STEM_BURST 1UL
#define STEM_LAZY  9400UL
#define STEM_CALLBACK_CONTEXT_TYPE    fd_snapzp_t
#define STEM_CALLBACK_CONTEXT_ALIGN   alignof(fd_snapzp_t)
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
