/* The jit tile transpiles sBPF programs to native code at run time.  It is the
   untrusted half of the JIT: it only sees verified program images
   (jitmap_jit frags), runs the transpiler on them, and sends the
   resulting relocatable code to jitmap (jit_jitmap frags).  It maps no
   workspace beyond its links and never touches the program cache or
   the code arena. */

#include "../../disco/topo/fd_topo.h"
#include "../../disco/metrics/fd_metrics.h"
#include "../../flamenco/vm/transpile/fd_jit_proto.h"
#include "../../flamenco/vm/transpile/fd_transpile.h"
#include "../../flamenco/vm/syscall/fd_vm_syscall.h"
#include "../../ballet/base58/fd_base58.h"

#include <linux/futex.h>
#include "generated/fd_jit_tile_seccomp.h"

#define NAME "jit"

struct fd_jit_in {
  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
};

typedef struct fd_jit_in fd_jit_in_t;

struct fd_jit_tile {
  fd_jit_in_t in[ FD_TOPO_MAX_TILE_IN_LINKS ];

  fd_wksp_t * out_mem;
  ulong       out_chunk0;
  ulong       out_wmark;
  ulong       out_chunk;

  uchar *           req;   /* FD_JIT_REQ_MTU copy of the request */
  fd_transpiler_t * t;

  struct {
    ulong compiled;
    ulong failed;
    ulong overrun;
  } metrics;
};

typedef struct fd_jit_tile fd_jit_tile_t;

static ulong
scratch_align( void ) {
  return 128UL;
}

static ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_jit_tile_t), sizeof(fd_jit_tile_t) );
  l = FD_LAYOUT_APPEND( l, 64UL,                   FD_JIT_REQ_MTU         );
  l = FD_LAYOUT_APPEND( l, 64UL,                   sizeof(fd_transpiler_t) );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static void
metrics_write( fd_jit_tile_t * ctx ) {
  FD_MCNT_SET( JIT, PROGRAM_COMPILED,        ctx->metrics.compiled );
  FD_MCNT_SET( JIT, PROGRAM_FAILED,          ctx->metrics.failed   );
  FD_MCNT_SET( JIT, REQUEST_OVERRUN_DROPPED, ctx->metrics.overrun  );
}

static void
during_frag( fd_jit_tile_t * ctx,
             ulong           in_idx,
             ulong           seq,
             ulong           sig,
             ulong           chunk,
             ulong           sz,
             ulong           ctl ) {
  (void)seq; (void)sig; (void)ctl; (void)sz;
  fd_jit_in_t const * in = &ctx->in[ in_idx ];
  if( FD_UNLIKELY( chunk<in->chunk0 || chunk>in->wmark ) ) {
    FD_LOG_ERR(( "chunk %lu corrupt, not in range [%lu,%lu]", chunk, in->chunk0, in->wmark ));
  }
  /* The producer does not wait for us, so copy before the frag can be
     overwritten; after_frag runs only if the copy was not overrun.  The
     header may be torn here, so only its length is trusted (bounded). */
  fd_jit_req_t const * src = fd_chunk_to_laddr_const( in->mem, chunk );
  ulong len = sizeof(fd_jit_req_t) + (ulong)FD_VOLATILE_CONST( src->val_sz );
  fd_memcpy( ctx->req, src, fd_ulong_min( len, FD_JIT_REQ_MTU ) );
}

static void
after_poll_overrun( fd_jit_tile_t * ctx ) {
  ctx->metrics.overrun++;
}

/* publish_failed tells jitmap that req cannot be compiled, so it stops
   waiting for it. */

static void
publish_failed( fd_jit_tile_t *      ctx,
                fd_stem_context_t *  stem,
                fd_jit_req_t const * req ) {
  fd_jit_res_t * res = fd_chunk_to_laddr( ctx->out_mem, ctx->out_chunk );
  memset( res, 0, sizeof(fd_jit_res_t) );
  res->key          = req->key;
  res->feature_slot = req->feature_slot;
  res->deploy_slot  = req->deploy_slot;
  res->rec_idx      = req->rec_idx;
  res->failed       = 1U;
  fd_stem_publish( stem, 0UL, 0UL, ctx->out_chunk, 0UL, 0UL, 0UL, 0UL );
  ctx->out_chunk = fd_dcache_compact_next( ctx->out_chunk, sizeof(fd_jit_res_t), ctx->out_chunk0, ctx->out_wmark );
  ctx->metrics.failed++;
}

static void
after_frag( fd_jit_tile_t *     ctx,
            ulong               in_idx,
            ulong               seq,
            ulong               sig,
            ulong               sz,
            ulong               tsorig,
            ulong               tspub,
            fd_stem_context_t * stem ) {
  (void)in_idx; (void)seq; (void)sig; (void)sz; (void)tsorig; (void)tspub;

  fd_jit_req_t const * req = (fd_jit_req_t const *)ctx->req;
  FD_BASE58_ENCODE_32_BYTES( req->key.prog.uc, prog_b58 );

  /* Rebuild the program view the exec tiles have.  The image is the
     progcache value slot, already loaded and verified; only shape
     checks are needed before handing it to the transpiler. */

  ulong val_sz = req->val_sz;
  if( FD_UNLIKELY( sizeof(fd_jit_req_t)+val_sz>FD_JIT_REQ_MTU ) ) {
    FD_LOG_WARNING(( "jit %s: oversized request", prog_b58 ));
    publish_failed( ctx, stem, req );
    return;
  }
  uchar const * val = ctx->req + sizeof(fd_jit_req_t);
  /* v3 places text after the rodata segment, so bound text by the
     whole image, not by rodata_sz. */
  if( FD_UNLIKELY( (ulong)req->rodata_off+req->rodata_sz>val_sz ||
                   (ulong)req->rodata_off+req->text_off+(ulong)req->text_cnt*8UL>val_sz ||
                   !req->text_cnt || req->entry_pc>=req->text_cnt ||
                   ( req->calldests_off!=UINT_MAX && (ulong)req->calldests_off+fd_sbpf_calldests_footprint( req->text_cnt )>val_sz ) ) ) {
    FD_LOG_WARNING(( "jit %s: malformed request (val_sz %lu rodata_off %u rodata_sz %u text_off %u text_cnt %u entry_pc %u calldests_off %u)",
                     prog_b58, val_sz, req->rodata_off, req->rodata_sz, req->text_off, req->text_cnt, req->entry_pc, req->calldests_off ));
    publish_failed( ctx, stem, req );
    return;
  }
  uchar const * rodata = val + req->rodata_off;
  uchar const * text   = rodata + req->text_off;
  fd_sbpf_calldests_t const * calldests = req->calldests_off==UINT_MAX ? NULL
    : fd_sbpf_calldests_join( (void *)( val + req->calldests_off ) );

  fd_sbpf_syscalls_t _syscalls[ FD_SBPF_SYSCALLS_SLOT_CNT ];
  fd_sbpf_syscalls_t * syscalls = fd_sbpf_syscalls_join( fd_sbpf_syscalls_new( _syscalls ) );
  if( FD_UNLIKELY( fd_vm_syscall_register_slot( syscalls, req->feature_slot, &req->features, 0 )!=FD_VM_SUCCESS ) ) {
    FD_LOG_WARNING(( "jit %s: syscall registration failed", prog_b58 ));
    publish_failed( ctx, stem, req );
    return;
  }

  long dt = -fd_log_wallclock();
  int err = fd_vm_transpile_code( ctx->t, req->sbpf_version, text, req->text_cnt, req->entry_pc,
                                  calldests, syscalls, rodata, req->rodata_sz, req->text_off );
  dt += fd_log_wallclock();
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_WARNING(( "jit %s: transpile failed", prog_b58 ));
    publish_failed( ctx, stem, req );
    return;
  }
  fd_transpiler_t const * t = ctx->t;
  if( FD_UNLIKELY( t->code_sz>FD_JIT_RES_CODE_MAX || t->rodata_sz>FD_JIT_RES_RODATA_MAX ||
                   t->reloc_cnt>FD_JIT_RES_RELOC_MAX || t->rodata_reloc_cnt>FD_JIT_RES_RODATA_RELOC_MAX ) ) {
    FD_LOG_WARNING(( "jit %s: output too large (code %lu rodata %lu reloc %lu/%lu)",
                     prog_b58, t->code_sz, t->rodata_sz, t->reloc_cnt, t->rodata_reloc_cnt ));
    publish_failed( ctx, stem, req );
    return;
  }

  fd_jit_res_t * res = fd_chunk_to_laddr( ctx->out_mem, ctx->out_chunk );
  *res = (fd_jit_res_t) {
    .key              = req->key,
    .feature_slot     = req->feature_slot,
    .deploy_slot      = req->deploy_slot,
    .rec_idx          = req->rec_idx,
    .code_sz          = t->code_sz,
    .rodata_sz        = t->rodata_sz,
    .reloc_cnt        = t->reloc_cnt,
    .rodata_reloc_cnt = t->rodata_reloc_cnt,
    .entrypoint_off   = t->entrypoint_off,
    .meta             = t->meta,
    .features         = req->features,
  };

  ulong code_off, rodata_off, reloc_off, rodata_reloc_off;
  ulong res_sz = fd_jit_res_layout( res, &code_off, &rodata_off, &reloc_off, &rodata_reloc_off );
  uchar * out = (uchar *)res;
  memcpy( out+code_off,         t->code,         t->code_sz );
  memcpy( out+rodata_off,       t->rodata,       t->rodata_sz );
  memcpy( out+reloc_off,        t->reloc,        t->reloc_cnt*sizeof(fd_elf64_rela) );
  memcpy( out+rodata_reloc_off, t->rodata_reloc, t->rodata_reloc_cnt*sizeof(fd_elf64_rela) );

  fd_stem_publish( stem, 0UL, 0UL, ctx->out_chunk, 0UL, 0UL, 0UL, 0UL );
  ctx->out_chunk = fd_dcache_compact_next( ctx->out_chunk, res_sz, ctx->out_chunk0, ctx->out_wmark );
  ctx->metrics.compiled++;
  FD_LOG_INFO(( "jit %s: %lu sBPF insns -> %lu bytes native in %ld us", prog_b58, (ulong)req->text_cnt, t->code_sz, dt/1000L ));
}

static void
unprivileged_init( fd_topo_t const *      topo,
                   fd_topo_tile_t const * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_jit_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_jit_tile_t), sizeof(fd_jit_tile_t) );
  ctx->req            = FD_SCRATCH_ALLOC_APPEND( l, 64UL,                   FD_JIT_REQ_MTU         );
  ctx->t              = FD_SCRATCH_ALLOC_APPEND( l, 64UL,                   sizeof(fd_transpiler_t) );
  memset( &ctx->metrics, 0, sizeof(ctx->metrics) );

  if( FD_UNLIKELY( tile->in_cnt>FD_TOPO_MAX_TILE_IN_LINKS ) ) FD_LOG_ERR(( "too many in links" ));
  for( ulong i=0UL; i<tile->in_cnt; i++ ) {
    fd_topo_link_t const * link = &topo->links[ tile->in_link_id[ i ] ];
    ctx->in[ i ].mem    = topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ].wksp;
    ctx->in[ i ].chunk0 = fd_dcache_compact_chunk0( ctx->in[ i ].mem, link->dcache );
    ctx->in[ i ].wmark  = fd_dcache_compact_wmark( ctx->in[ i ].mem, link->dcache, link->mtu );
  }

  if( FD_UNLIKELY( tile->out_cnt!=1UL ) ) FD_LOG_ERR(( "jit tile expects one out link, has %lu", tile->out_cnt ));
  fd_topo_link_t const * out = &topo->links[ tile->out_link_id[ 0 ] ];
  ctx->out_mem    = topo->workspaces[ topo->objs[ out->dcache_obj_id ].wksp_id ].wksp;
  ctx->out_chunk0 = fd_dcache_compact_chunk0( ctx->out_mem, out->dcache );
  ctx->out_wmark  = fd_dcache_compact_wmark( ctx->out_mem, out->dcache, out->mtu );
  ctx->out_chunk  = ctx->out_chunk0;

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, 1UL );
  if( FD_UNLIKELY( scratch_top>(ulong)scratch+scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top-(ulong)scratch-scratch_footprint( tile ), scratch_top, (ulong)scratch+scratch_footprint( tile ) ));
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  (void)topo; (void)tile;
  populate_sock_filter_policy_fd_jit_tile( out_cnt, out, (uint)fd_log_private_logfile_fd() );
  return sock_filter_policy_fd_jit_tile_instr_cnt;
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
  if( FD_LIKELY( -1!=fd_log_private_logfile_fd() ) ) out_fds[ out_cnt++ ] = fd_log_private_logfile_fd();
  return out_cnt;
}

#define STEM_BURST (1UL)

#define STEM_CALLBACK_CONTEXT_TYPE  fd_jit_tile_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_jit_tile_t)

#define STEM_CALLBACK_METRICS_WRITE      metrics_write
#define STEM_CALLBACK_DURING_FRAG        during_frag
#define STEM_CALLBACK_AFTER_FRAG         after_frag
#define STEM_CALLBACK_AFTER_POLL_OVERRUN after_poll_overrun

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_jit = {
  .name                     = NAME,
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};
