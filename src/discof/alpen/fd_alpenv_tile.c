#include "../../disco/topo/fd_topo.h"
#include "generated/fd_alpenv_tile_seccomp.h"

#include "../../choreo/fd_choreo.h"
#include "../../disco/fd_disco.h"
#include "../../ballet/bls/fd_bls12_381.h"

typedef struct {
  ulong round_robin_idx;
  ulong round_robin_cnt;

  struct {
    fd_wksp_t * mem;
    ulong       chunk0;
    ulong       wmark;
  } in[ 1 ];

  fd_wksp_t * out_mem;
  ulong       out_chunk0;
  ulong       out_wmark;
  ulong       out_chunk;

  struct {
    ulong verify_fail_cnt;
  } metrics;
} fd_verify_ctx_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 128UL;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile FD_PARAM_UNUSED ) {
  return FD_LAYOUT_FINI(
    FD_LAYOUT_APPEND(
      FD_LAYOUT_INIT,
      alignof(fd_verify_ctx_t), sizeof(fd_verify_ctx_t) ),
    scratch_align() );
}

static inline void
metrics_write( fd_verify_ctx_t * ctx ) {
  (void)ctx;
  // FD_MCNT_SET( VERIFY, TRANSACTION_VERIFY_FAILURE,      ctx->metrics.verify_fail_cnt );
}

static int
before_frag( fd_verify_ctx_t * ctx,
             ulong             in_idx,
             ulong             seq,
             ulong             sig FD_PARAM_UNUSED ) {
  FD_TEST( in_idx==0 );
  return (seq % ctx->round_robin_cnt) != ctx->round_robin_idx;
}

static void
during_frag( fd_verify_ctx_t * ctx,
             ulong             in_idx FD_PARAM_UNUSED,
             ulong             seq    FD_PARAM_UNUSED,
             ulong             sig,
             ulong             chunk,
             ulong             sz,
             ulong             ctl FD_PARAM_UNUSED ) {
  /* This tile works as an accelerator.
     The caller (alpen tile) sets data to sigverify in dcache, and sends
     a message via mcache.  This tile runs the sigverify and responds in
     mcache with a pointer to the same dcache entry.
     It's responsibility of the caller to not override the dcache before
     the sigverify returns, therefore we can run all the logic as part of
     during_frag. */

  int verif = 0; /* 0=failed, 1=success */

  if( FD_UNLIKELY( chunk<ctx->in[in_idx].chunk0 || chunk>ctx->in[in_idx].wmark || sz>FD_TPU_MTU ) )
    FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->in[in_idx].chunk0, ctx->in[in_idx].wmark ));

  /* Expects data as: pubkey | signature | msg */
  uchar * pubkey = (uchar *)fd_chunk_to_laddr( ctx->in[in_idx].mem, chunk );

  /* Perform sigverify (supports BLS and Ed25519) */
  if( FD_LIKELY( sig==0x01 ) ) {
    uchar * signature = pubkey + 96UL;
    uchar * msg = signature + 192UL;
    ulong   msg_sz = sz - 192UL - 96UL;
    verif = fd_bls12_381_verify( msg, msg_sz, signature, pubkey )==FD_BLS_SUCCESS;
  } else if( FD_LIKELY( sig==0x02 ) ) {
    uchar * signature = pubkey + 32UL;
    uchar * msg = signature + 64UL;
    ulong   msg_sz = sz - 64UL - 32UL;
    fd_sha512_t sha[1];
    verif = fd_ed25519_verify( msg, msg_sz, signature, pubkey, sha )==FD_ED25519_SUCCESS;
  }

  if( FD_UNLIKELY( verif==0 ) ) {
    ctx->metrics.verify_fail_cnt++;
  }

  /* Send response back */
}

static void
after_frag( fd_verify_ctx_t *   ctx    FD_PARAM_UNUSED,
            ulong               in_idx FD_PARAM_UNUSED,
            ulong               seq    FD_PARAM_UNUSED,
            ulong               sig    FD_PARAM_UNUSED,
            ulong               sz     FD_PARAM_UNUSED,
            ulong               tsorig FD_PARAM_UNUSED,
            ulong               tspub  FD_PARAM_UNUSED,
            fd_stem_context_t * stem   FD_PARAM_UNUSED ) {
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_verify_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_verify_ctx_t), sizeof(fd_verify_ctx_t) );
  (void)ctx;
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_verify_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_verify_ctx_t ), sizeof( fd_verify_ctx_t ) );
  (void)ctx;
  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, scratch_align() );
  FD_TEST( scratch_top == (ulong)scratch + scratch_footprint( tile ) );

  ctx->round_robin_cnt = fd_topo_tile_name_cnt( topo, tile->name );
  ctx->round_robin_idx = tile->kind_id;
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  (void)topo;
  (void)tile;

  populate_sock_filter_policy_fd_alpenv_tile( out_cnt, out, (uint)fd_log_private_logfile_fd() );
  return sock_filter_policy_fd_alpenv_tile_instr_cnt;
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

#define STEM_CALLBACK_CONTEXT_TYPE  fd_verify_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_verify_ctx_t)

#define STEM_CALLBACK_BEFORE_FRAG   before_frag
#define STEM_CALLBACK_DURING_FRAG   during_frag
#define STEM_CALLBACK_AFTER_FRAG    after_frag
#define STEM_CALLBACK_METRICS_WRITE metrics_write

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_alpenv = {
  .name                     = "alpenv",
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};
