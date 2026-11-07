/* The jitmap tile owns the JIT code arena.  It is the trusted half of
   the JIT: it takes relocatable code from the jit tile (jit_jitmap
   frags), places it into the arena (the only writable mapping of it
   anywhere), and binds the program cache record that requested it. */

#include "../../disco/topo/fd_topo.h"
#include "../../disco/metrics/fd_metrics.h"
#include "../../flamenco/vm/transpile/fd_jit_arena.h"
#include "../../flamenco/vm/transpile/fd_transpile_bind.h"
#include "../../flamenco/progcache/fd_progcache.h"
#include "../../flamenco/fd_rwlock.h"
#include "../../ballet/base58/fd_base58.h"

#include <linux/futex.h>
#include "generated/fd_jitmap_tile_seccomp.h"

#define NAME "jitmap"

struct fd_jitmap_tile {
  fd_wksp_t * in_mem;
  ulong       in_chunk0;
  ulong       in_wmark;

  uchar *               res;  /* FD_JIT_RES_MTU copy of the response */
  ulong                 res_sz;
  fd_jit_arena_t *      arena;
  fd_progcache_join_t   progcache[1];

  struct {
    ulong placed;
    ulong dedup;
    ulong rejected;
    ulong stale;
    ulong overrun;
  } metrics;
};

typedef struct fd_jitmap_tile fd_jitmap_tile_t;

static ulong
scratch_align( void ) {
  return 128UL;
}

static ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_jitmap_tile_t), sizeof(fd_jitmap_tile_t) );
  l = FD_LAYOUT_APPEND( l, 64UL,                      FD_JIT_RES_MTU            );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static void
metrics_write( fd_jitmap_tile_t * ctx ) {
  FD_MCNT_SET  ( JITMAP, PROGRAM_PLACED,        ctx->metrics.placed   );
  FD_MCNT_SET  ( JITMAP, PROGRAM_DUPLICATE_HIT,  ctx->metrics.dedup    );
  FD_MCNT_SET  ( JITMAP, PROGRAM_REJECTED,      ctx->metrics.rejected );
  FD_MCNT_SET  ( JITMAP, PROGRAM_STALE_DROPPED, ctx->metrics.stale    );
  FD_MCNT_SET  ( JITMAP, RESULT_OVERRUN_DROPPED, ctx->metrics.overrun  );
  FD_MGAUGE_SET( JITMAP, ARENA_USED_BYTES,      ctx->arena->code_used );
  FD_MGAUGE_SET( JITMAP, ARENA_CAPACITY_BYTES,  ctx->arena->code_max  );
  FD_MGAUGE_SET( JITMAP, PROGRAM_COUNT,         ctx->arena->prog_cnt  );
}

static void
during_frag( fd_jitmap_tile_t * ctx,
             ulong              in_idx,
             ulong              seq,
             ulong              sig,
             ulong              chunk,
             ulong              sz,
             ulong              ctl ) {
  (void)in_idx; (void)seq; (void)sig; (void)ctl; (void)sz;
  if( FD_UNLIKELY( chunk<ctx->in_chunk0 || chunk>ctx->in_wmark ) ) {
    FD_LOG_ERR(( "chunk %lu corrupt, not in range [%lu,%lu]", chunk, ctx->in_chunk0, ctx->in_wmark ));
  }
  /* Header may be torn; only a bounded length is derived from it. */
  fd_jit_res_t hdr = *(fd_jit_res_t const *)fd_chunk_to_laddr_const( ctx->in_mem, chunk );
  hdr.code_sz          = fd_ulong_min( hdr.code_sz,          FD_JIT_RES_CODE_MAX   );
  hdr.rodata_sz        = fd_ulong_min( hdr.rodata_sz,        FD_JIT_RES_RODATA_MAX );
  hdr.reloc_cnt        = fd_ulong_min( hdr.reloc_cnt,        FD_JIT_RES_RELOC_MAX  );
  hdr.rodata_reloc_cnt = fd_ulong_min( hdr.rodata_reloc_cnt, FD_JIT_RES_RODATA_RELOC_MAX );
  ulong a, b, c, d;
  ctx->res_sz = fd_ulong_min( fd_jit_res_layout( &hdr, &a, &b, &c, &d ), FD_JIT_RES_MTU );
  fd_memcpy( ctx->res, fd_chunk_to_laddr_const( ctx->in_mem, chunk ), ctx->res_sz );
}

static void
after_poll_overrun( fd_jitmap_tile_t * ctx ) {
  ctx->metrics.overrun++;
}

/* bind_rec points the progcache record the request came from at the
   arena slot, provided it still holds the same revision.  The record
   may have been evicted and reused for anything since the exec tile
   sent the request; the key, deploy and feature slots identify the
   revision, and a read lock keeps it from being released underneath
   the check.  A write-locked record is skipped: it is being freed or
   reloaded, so the binding would be stale anyway. */

static int
bind_rec( fd_jitmap_tile_t *   ctx,
          fd_jit_res_t const * res,
          ulong                slot ) {
  if( FD_UNLIKELY( res->rec_idx>=ctx->progcache->rec.max ) ) return 0;
  fd_progcache_rec_t * rec = &ctx->progcache->rec.ele[ res->rec_idx ];
  if( FD_UNLIKELY( !fd_rwlock_tryread( &rec->lock ) ) ) return 0;
  int ok = rec->exists && rec->data_gaddr &&
           fd_progcache_rec_key_eq( &rec->pair, &res->key ) &&
           rec->deploy_slot==res->deploy_slot && rec->feature_slot==res->feature_slot;
  if( ok ) FD_VOLATILE( rec->transpiled_idx ) = FD_TRANSPILE_BIND_JIT | (uint)slot;
  fd_rwlock_unread( &rec->lock );
  return ok;
}

static void
after_frag( fd_jitmap_tile_t *  ctx,
            ulong               in_idx,
            ulong               seq,
            ulong               sig,
            ulong               sz,
            ulong               tsorig,
            ulong               tspub,
            fd_stem_context_t * stem ) {
  (void)in_idx; (void)seq; (void)sig; (void)sz; (void)tsorig; (void)tspub; (void)stem;

  fd_jit_res_t const * res = (fd_jit_res_t const *)ctx->res;
  FD_BASE58_ENCODE_32_BYTES( res->key.prog.uc, prog_b58 );

  int  dedup = 0;
  long slot  = fd_jit_arena_place( ctx->arena, res, ctx->res, ctx->res_sz, &dedup );
  if( FD_UNLIKELY( slot<0L ) ) {
    ctx->metrics.rejected++;
    return;
  }
  if( dedup ) ctx->metrics.dedup++;
  else        ctx->metrics.placed++;

  if( FD_UNLIKELY( !bind_rec( ctx, res, (ulong)slot ) ) ) {
    ctx->metrics.stale++;
    FD_LOG_INFO(( "jit %s: record %u moved on before code arrived", prog_b58, res->rec_idx ));
    return;
  }
  FD_LOG_NOTICE(( "jit program %s bound (slot %ld, %s, %lu bytes, arena %lu/%lu)",
                  prog_b58, slot, dedup ? "reused" : "new", ctx->arena->slot[ slot ].prog_sz,
                  ctx->arena->code_used, ctx->arena->code_max ));
}

static void
unprivileged_init( fd_topo_t const *      topo,
                   fd_topo_tile_t const * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_jitmap_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_jitmap_tile_t), sizeof(fd_jitmap_tile_t) );
  ctx->res               = FD_SCRATCH_ALLOC_APPEND( l, 64UL,                      FD_JIT_RES_MTU            );
  memset( &ctx->metrics, 0, sizeof(ctx->metrics) );

  if( FD_UNLIKELY( tile->in_cnt!=1UL ) ) FD_LOG_ERR(( "jitmap tile expects one in link, has %lu", tile->in_cnt ));
  fd_topo_link_t const * in = &topo->links[ tile->in_link_id[ 0 ] ];
  ctx->in_mem    = topo->workspaces[ topo->objs[ in->dcache_obj_id ].wksp_id ].wksp;
  ctx->in_chunk0 = fd_dcache_compact_chunk0( ctx->in_mem, in->dcache );
  ctx->in_wmark  = fd_dcache_compact_wmark( ctx->in_mem, in->dcache, in->mtu );

  ctx->arena = fd_jit_arena_join( fd_topo_obj_laddr( topo, tile->jitmap.jit_arena_obj_id ) );
  FD_TEST( ctx->arena );
  FD_TEST( fd_progcache_shmem_join( ctx->progcache, fd_topo_obj_laddr( topo, tile->jitmap.progcache_obj_id ) ) );

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
  populate_sock_filter_policy_fd_jitmap_tile( out_cnt, out, (uint)fd_log_private_logfile_fd() );
  return sock_filter_policy_fd_jitmap_tile_instr_cnt;
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

#define STEM_CALLBACK_CONTEXT_TYPE  fd_jitmap_tile_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_jitmap_tile_t)

#define STEM_CALLBACK_METRICS_WRITE      metrics_write
#define STEM_CALLBACK_DURING_FRAG        during_frag
#define STEM_CALLBACK_AFTER_FRAG         after_frag
#define STEM_CALLBACK_AFTER_POLL_OVERRUN after_poll_overrun

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_jitmap = {
  .name                     = NAME,
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};
