#include "../../disco/topo/fd_topo.h"
#include "generated/fd_alpen_tile_seccomp.h"

#include "../../choreo/fd_choreo.h"

#include "../../disco/fd_disco.h"
#include "../../disco/keyguard/fd_keyload.h"
#include "../../disco/shred/fd_stake_ci.h"

typedef struct {
  fd_pubkey_t identity_key[1];
  ulong       seed;
} ctx_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 128UL;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile FD_PARAM_UNUSED ) {
  return FD_LAYOUT_FINI(
    FD_LAYOUT_APPEND(
      FD_LAYOUT_INIT,
      alignof(ctx_t), sizeof(ctx_t) ),
    scratch_align() );
}

static void
during_frag( ctx_t *   ctx,
             ulong     in_idx,
             ulong     seq FD_PARAM_UNUSED,
             ulong     sig,
             ulong     chunk,
             ulong     sz,
             ulong     ctl FD_PARAM_UNUSED ) {
  (void)ctx;
  (void)sig;
  FD_TEST( in_idx==0 );
  FD_TEST( chunk==0 );
  FD_TEST( sz==0 );
}

static void
after_frag( ctx_t * ctx,
            ulong                 in_idx,
            ulong                 seq,
            ulong                 sig,
            ulong                 sz,
            ulong                 tsorig,
            ulong                 tspub,
            fd_stem_context_t *   stem ) {
  (void)ctx;
  (void)seq;
  (void)tsorig;
  (void)tspub;
  (void)stem;

  FD_TEST( in_idx==0 );
  FD_TEST( sz==0 );

  FD_LOG_NOTICE(( "got replay sig %lu", sig ));
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(ctx_t), sizeof(ctx_t) );

  if( FD_UNLIKELY( !strcmp( tile->alpen.identity_key_path, "" ) ) )
    FD_LOG_ERR(( "identity_key_path not set" ));

  ctx->identity_key[0] = *(fd_pubkey_t const *)fd_type_pun_const( fd_keyload_load( tile->alpen.identity_key_path, /* pubkey only: */ 1 ) );

  FD_TEST( fd_rng_secure( &ctx->seed, sizeof(ulong) ) );
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( ctx_t ), sizeof( ctx_t ) );
  (void)ctx;
  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, scratch_align() );
  FD_TEST( scratch_top == (ulong)scratch + scratch_footprint( tile ) );
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  (void)topo;
  (void)tile;

  populate_sock_filter_policy_fd_alpen_tile( out_cnt, out, (uint)fd_log_private_logfile_fd() );
  return sock_filter_policy_fd_alpen_tile_instr_cnt;
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

#define STEM_CALLBACK_CONTEXT_TYPE  ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(ctx_t)

#define STEM_CALLBACK_DURING_FRAG during_frag
#define STEM_CALLBACK_AFTER_FRAG  after_frag

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_alpen = {
    .name                     = "alpen",
    .populate_allowed_seccomp = populate_allowed_seccomp,
    .populate_allowed_fds     = populate_allowed_fds,
    .scratch_align            = scratch_align,
    .scratch_footprint        = scratch_footprint,
    .privileged_init          = privileged_init,
    .unprivileged_init        = unprivileged_init,
    .run                      = stem_run,
};
