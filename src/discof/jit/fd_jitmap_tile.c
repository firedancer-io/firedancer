/* The jitmap tile owns the JIT code arena and decides what gets
   compiled.  It is the trusted half of the JIT.

   Exec tiles count the compute units they spend interpreting each
   program cache record (fd_jit_heat.h).  jitmap periodically folds
   those counters into a decaying score per record.  While no request
   is in flight it takes the hottest record without a binding, copies
   its image into a jitmap_jit frag and lets the jit tile compile it.
   It places the relocatable code that comes back (jit_jitmap frags)
   into the arena (the only writable mapping of it anywhere) and binds
   the record, which exec tiles pick up on their next invocation.

   Code lives as long as a record is bound to it.  jitmap is the only
   binder, so it knows which records it bound to which arena slot.  An
   exec tile holds a record's read lock for as long as it runs the
   record's code.  A binding goes away when the program cache reuses
   the record (under the write lock) or an exec tile puts it on hold.
   Once jitmap has seen the binding gone and then the lock without
   readers, no tile is in the code through that record and none can
   enter.  When that holds for every record of a slot, the slot is
   freed. */

#include "../../disco/topo/fd_topo.h"
#include "../../disco/metrics/fd_metrics.h"
#include "../../flamenco/vm/transpile/fd_jit_arena.h"
#include "../../flamenco/vm/transpile/fd_jit_heat.h"
#include "../../flamenco/vm/transpile/fd_transpile_bind.h"
#include "../../flamenco/progcache/fd_progcache.h"
#include "../../flamenco/progcache/fd_progcache_clock.h"
#include "../../flamenco/fd_rwlock.h"
#include "../../ballet/base58/fd_base58.h"
#include "../../ballet/blake3/fd_blake3.h"

#include <linux/futex.h>
#include "generated/fd_jitmap_tile_seccomp.h"

#define NAME "jitmap"

/* A score loses 1/2^SCORE_DECAY_SHIFT of its value per sweep, which
   ages out heat that belongs to a previous user of the record. */

#define SCORE_DECAY_SHIFT (3)

/* A request the jit tile has not answered by then is given up on. */

#define REQ_TIMEOUT_NS (1000000000L)

struct fd_jitmap_tile {
  fd_wksp_t * in_mem;
  ulong       in_chunk0;
  ulong       in_wmark;

  fd_wksp_t * out_mem;
  ulong       out_chunk0;
  ulong       out_wmark;
  ulong       out_chunk;

  uchar *               res;  /* FD_JIT_RES_MTU copy of the response */
  ulong                 res_sz;
  fd_jit_arena_t *      arena;
  fd_progcache_join_t   progcache[1];

  fd_jit_heat_t * heat;
  uint *          heat_prev;  /* per record: sum over rows at the last sweep */
  uint *          score;      /* per record: decayed compute units */
  uint            score_min;  /* score a record needs to be compiled */

  uint * rec_slot;            /* per record: 1+arena slot jitmap bound it to, 0 if none */
  uint   slot_ref[ FD_JIT_ARENA_SLOT_MAX ]; /* records in rec_slot per arena slot */
  int    arena_full;          /* a program did not fit and nothing was freed since */

  long sweep_ticks;
  long timeout_ticks;
  long sweep_next;            /* tickcount of the next score update */
  int  idle;                  /* no candidate until scores change */

  /* The request in flight */
  int                    req_busy;
  long                   req_deadline;
  uint                   req_rec_idx;
  fd_progcache_rec_key_t req_key;
  ulong                  req_feature_slot;
  ulong                  req_deploy_slot;
  uchar                  req_hash[ 32 ]; /* BLAKE3 of the image sent */

  struct {
    ulong requested;
    ulong failed;
    ulong timeout;
    ulong placed;
    ulong freed;
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
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_jitmap_tile_t), sizeof(fd_jitmap_tile_t)            );
  l = FD_LAYOUT_APPEND( l, 64UL,                      FD_JIT_RES_MTU                      );
  l = FD_LAYOUT_APPEND( l, 64UL,                      tile->jitmap.rec_max*sizeof(uint)   );
  l = FD_LAYOUT_APPEND( l, 64UL,                      tile->jitmap.rec_max*sizeof(uint)   );
  l = FD_LAYOUT_APPEND( l, 64UL,                      tile->jitmap.rec_max*sizeof(uint)   );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static void
metrics_write( fd_jitmap_tile_t * ctx ) {
  FD_MCNT_SET  ( JITMAP, PROGRAM_REQUESTED,     ctx->metrics.requested );
  FD_MCNT_SET  ( JITMAP, PROGRAM_FAILED,        ctx->metrics.failed   );
  FD_MCNT_SET  ( JITMAP, REQUEST_TIMED_OUT,     ctx->metrics.timeout  );
  FD_MCNT_SET  ( JITMAP, PROGRAM_PLACED,        ctx->metrics.placed   );
  FD_MCNT_SET  ( JITMAP, PROGRAM_FREED,         ctx->metrics.freed    );
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

/* rec_tryread read locks the record at rec_idx if it is a loaded,
   mapped program of the given revision.  The record may have been
   evicted and reused for anything since it was last looked at; the
   key, deploy and feature slots identify the revision, and the read
   lock keeps it from being released underneath the caller.  A loader
   also holds a read lock while it fills the value slot, so the image
   is only complete once the record is LIVE.  A write-locked record is
   being freed. */

static fd_progcache_rec_t *
rec_tryread( fd_jitmap_tile_t *             ctx,
             ulong                          rec_idx,
             fd_progcache_rec_key_t const * key,
             ulong                          feature_slot,
             ulong                          deploy_slot ) {
  if( FD_UNLIKELY( rec_idx>=ctx->progcache->rec.max ) ) return NULL;
  fd_progcache_rec_t * rec = &ctx->progcache->rec.ele[ rec_idx ];
  if( FD_UNLIKELY( !fd_rwlock_tryread( &rec->lock ) ) ) return NULL;
  uchar st = __atomic_load_n( &rec->state, __ATOMIC_ACQUIRE );
  int ok = ( ( st & ( FD_PROGCACHE_REC_LIVE|FD_PROGCACHE_REC_MAPPED ) )==( FD_PROGCACHE_REC_LIVE|FD_PROGCACHE_REC_MAPPED ) ) &&
           rec->exists && rec->data_gaddr;
  if( ok && key ) {
    ok = fd_progcache_rec_key_eq( &rec->pair, key ) &&
         rec->deploy_slot==deploy_slot && rec->feature_slot==feature_slot;
  }
  if( FD_UNLIKELY( !ok ) ) {
    fd_rwlock_unread( &rec->lock );
    return NULL;
  }
  return rec;
}

/* slot_unref drops one record's claim on an arena slot and frees the
   slot with the last one. */

static void
slot_unref( fd_jitmap_tile_t * ctx,
            ulong              slot ) {
  if( --ctx->slot_ref[ slot ] ) return;
  fd_jit_arena_free( ctx->arena, slot );
  ctx->arena_full = 0;
  ctx->idle       = 0;
  ctx->metrics.freed++;
}

/* rec_bind binds rec, which the caller holds read locked, to idx if it
   has no binding.  A record an exec tile put on hold stays on hold.
   A binding only returns to none when the record is reused, which
   takes the write lock, so an earlier binding jitmap still tracks for
   this record has no tile left in it. */

static int
rec_bind( fd_jitmap_tile_t *   ctx,
          fd_progcache_rec_t * rec,
          uint                 idx ) {
  if( FD_UNLIKELY( FD_ATOMIC_CAS( &rec->transpiled_idx, 0U, idx )!=0U ) ) return 0;
  ulong rec_idx = (ulong)( rec - ctx->progcache->rec.ele );
  uint  prev    = ctx->rec_slot[ rec_idx ];
  if( idx & FD_TRANSPILE_BIND_JIT ) {
    uint slot = idx & ~FD_TRANSPILE_BIND_JIT;
    ctx->rec_slot[ rec_idx ] = slot+1U;
    ctx->slot_ref[ slot ]++;
  } else {
    ctx->rec_slot[ rec_idx ] = 0U;
  }
  if( prev ) slot_unref( ctx, prev-1U );
  return 1;
}

/* bind_rec is rec_bind on the given revision, if the record still
   holds it. */

static int
bind_rec( fd_jitmap_tile_t *             ctx,
          ulong                          rec_idx,
          fd_progcache_rec_key_t const * key,
          ulong                          feature_slot,
          ulong                          deploy_slot,
          uint                           idx ) {
  fd_progcache_rec_t * rec = rec_tryread( ctx, rec_idx, key, feature_slot, deploy_slot );
  if( FD_UNLIKELY( !rec ) ) return 0;
  int ok = rec_bind( ctx, rec, idx );
  fd_rwlock_unread( &rec->lock );
  return ok;
}

/* reclaim frees the arena slots whose records have all moved on. */

static void
reclaim( fd_jitmap_tile_t * ctx ) {
  fd_progcache_rec_t * recs    = ctx->progcache->rec.ele;
  ulong                rec_max = ctx->heat->rec_max;
  for( ulong i=0UL; i<rec_max; i++ ) {
    uint bound = ctx->rec_slot[ i ];
    if( FD_LIKELY( !bound ) ) continue;
    if( FD_VOLATILE_CONST( recs[ i ].transpiled_idx )==( FD_TRANSPILE_BIND_JIT | ( bound-1U ) ) ) continue;
    FD_COMPILER_MFENCE();
    ushort lock = atomic_load_explicit( &recs[ i ].lock.value, memory_order_acquire );
    if( FD_UNLIKELY( lock && lock!=FD_RWLOCK_WRITE_LOCK ) ) continue;
    ctx->rec_slot[ i ] = 0U;
    slot_unref( ctx, bound-1U );
  }
}

/* score_update folds the compute units the exec tiles interpreted
   since the last call into the per record scores. */

static void
score_update( fd_jitmap_tile_t * ctx ) {
  fd_jit_heat_t * heat    = ctx->heat;
  ulong           rec_max = heat->rec_max;
  ulong           row_cnt = heat->row_cnt;
  for( ulong i=0UL; i<rec_max; i++ ) {
    uint sum = 0U;
    for( ulong r=0UL; r<row_cnt; r++ ) sum += FD_VOLATILE_CONST( fd_jit_heat_row( heat, r )->cu[ i ] );
    uint delta = sum - ctx->heat_prev[ i ];
    uint score = ctx->score[ i ];
    ctx->heat_prev[ i ] = sum;
    ctx->score    [ i ] = fd_uint_sat_add( score - ( score>>SCORE_DECAY_SHIFT ), delta );
  }
}

/* request sends the hottest record without a binding to the jit tile,
   unless the arena already holds its code, in which case it binds the
   record right away and moves on to the next.  Returns 1 if a request
   went out, 0 if no record qualifies. */

static int
request( fd_jitmap_tile_t *  ctx,
         fd_stem_context_t * stem ) {
  fd_progcache_rec_t * recs    = ctx->progcache->rec.ele;
  ulong                rec_max = ctx->heat->rec_max;

  for(;;) {
    ulong best_idx = ULONG_MAX;
    uint  best     = 0U;
    for( ulong i=0UL; i<rec_max; i++ ) {
      uint score = ctx->score[ i ];
      if( FD_LIKELY( score<ctx->score_min || score<=best ) ) continue;
      if( FD_VOLATILE_CONST( recs[ i ].transpiled_idx ) ) continue;
      best     = score;
      best_idx = i;
    }
    if( best_idx==ULONG_MAX ) return 0;

    /* Whatever happens to this candidate, it has to earn its score
       again before it is looked at next. */
    ctx->score[ best_idx ] = 0U;

    fd_progcache_rec_t * rec = rec_tryread( ctx, best_idx, NULL, 0UL, 0UL );
    if( FD_UNLIKELY( !rec ) ) continue;
    if( FD_UNLIKELY( FD_VOLATILE_CONST( rec->transpiled_idx ) ) ) {
      fd_rwlock_unread( &rec->lock );
      continue;
    }

    ulong val_sz = fd_ulong_min( (ulong)rec->rodata_off + fd_ulong_max( (ulong)rec->rodata_sz, (ulong)rec->text_off+(ulong)rec->text_cnt*8UL ), (ulong)rec->data_max );
    ulong sz     = sizeof(fd_jit_req_t) + val_sz;
    if( FD_UNLIKELY( sz>FD_JIT_REQ_MTU ) ) {
      FD_ATOMIC_CAS( &rec->transpiled_idx, 0U, FD_TRANSPILE_BIND_HOLD );
      fd_rwlock_unread( &rec->lock );
      continue;
    }

    uchar const * val = fd_wksp_laddr_fast( (fd_wksp_t *)ctx->progcache->data_base, rec->data_gaddr );
    uchar hash[ 32 ];
    fd_blake3_hash( val+rec->rodata_off, val_sz-fd_ulong_min( val_sz, (ulong)rec->rodata_off ), hash );
    long hit = fd_jit_arena_find( ctx->arena, rec->pair.prog.uc, hash, rec->feature_slot );
    if( hit>=0L ) {
      if( FD_LIKELY( rec_bind( ctx, rec, FD_TRANSPILE_BIND_JIT | (uint)hit ) ) ) ctx->metrics.dedup++;
      fd_rwlock_unread( &rec->lock );
      continue;
    }
    if( FD_UNLIKELY( ctx->arena_full ) ) {
      fd_rwlock_unread( &rec->lock );
      continue;
    }

    /* The feature set comes from an exec tile that interpreted under
       this feature_slot.  If every tile has moved on, so has the
       cluster, and the record is about to go cold. */
    fd_jit_req_t * req = fd_chunk_to_laddr( ctx->out_mem, ctx->out_chunk );
    int have_features = 0;
    for( ulong r=0UL; r<ctx->heat->row_cnt && !have_features; r++ ) {
      have_features = fd_jit_heat_row_features_query( fd_jit_heat_row( ctx->heat, r ), rec->feature_slot, &req->features );
    }
    if( FD_UNLIKELY( !have_features ) ) {
      fd_rwlock_unread( &rec->lock );
      continue;
    }

    req->key           = rec->pair;
    req->feature_slot  = rec->feature_slot;
    req->deploy_slot   = rec->deploy_slot;
    req->rec_idx       = (uint)best_idx;
    req->data_max      = rec->data_max;
    req->entry_pc      = rec->entry_pc;
    req->text_cnt      = rec->text_cnt;
    req->text_off      = rec->text_off;
    req->text_sz       = rec->text_sz;
    req->rodata_sz     = rec->rodata_sz;
    req->calldests_off = rec->calldests_off;
    req->rodata_off    = rec->rodata_off;
    req->sbpf_version  = rec->sbpf_version;
    req->val_sz        = (uint)val_sz;
    fd_memcpy( req+1, val, val_sz );

    ctx->req_busy         = 1;
    ctx->req_deadline     = fd_tickcount() + ctx->timeout_ticks;
    ctx->req_rec_idx      = (uint)best_idx;
    ctx->req_key          = rec->pair;
    ctx->req_feature_slot = rec->feature_slot;
    ctx->req_deploy_slot  = rec->deploy_slot;
    memcpy( ctx->req_hash, hash, 32UL );
    fd_rwlock_unread( &rec->lock );

    fd_stem_publish( stem, 0UL, 0UL, ctx->out_chunk, 0UL, 0UL, 0UL, 0UL );
    ctx->out_chunk = fd_dcache_compact_next( ctx->out_chunk, sz, ctx->out_chunk0, ctx->out_wmark );
    ctx->metrics.requested++;
    return 1;
  }
}

static inline long
next_deadline( fd_jitmap_tile_t const * ctx ) {
  return ctx->req_busy ? fd_long_min( ctx->sweep_next, ctx->req_deadline ) : ctx->sweep_next;
}

static void
after_credit( fd_jitmap_tile_t *  ctx,
              fd_stem_context_t * stem,
              int *               opt_poll_in,
              int *               charge_busy ) {
  (void)opt_poll_in;
  long now = fd_tickcount();

  if( FD_UNLIKELY( now>=ctx->sweep_next ) ) {
    score_update( ctx );
    reclaim( ctx );
    ctx->sweep_next = now + ctx->sweep_ticks;
    ctx->idle       = 0;
    *charge_busy    = 1;
  }

  if( ctx->req_busy ) {
    if( FD_LIKELY( now<ctx->req_deadline ) ) return;
    bind_rec( ctx, ctx->req_rec_idx, &ctx->req_key, ctx->req_feature_slot, ctx->req_deploy_slot, FD_TRANSPILE_BIND_HOLD );
    ctx->req_busy = 0;
    ctx->metrics.timeout++;
  }

  if( ctx->idle ) return;
  *charge_busy = 1;
  if( !request( ctx, stem ) ) ctx->idle = 1;
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

  fd_jit_res_t * res = (fd_jit_res_t *)ctx->res;
  FD_BASE58_ENCODE_32_BYTES( res->key.prog.uc, prog_b58 );

  if( FD_UNLIKELY( !( ctx->req_busy && res->rec_idx==ctx->req_rec_idx && fd_progcache_rec_key_eq( &res->key, &ctx->req_key ) &&
                      res->feature_slot==ctx->req_feature_slot && res->deploy_slot==ctx->req_deploy_slot ) ) ) {
    ctx->metrics.stale++;
    return;
  }
  ctx->req_busy = 0;

  /* The arena identifies code by the image jitmap sent, not by what
     the compiler says it compiled. */
  memcpy( res->meta.prog_id,  ctx->req_key.prog.uc, 32UL );
  memcpy( res->meta.elf_hash, ctx->req_hash,        32UL );

  if( FD_UNLIKELY( res->failed ) ) {
    ctx->metrics.failed++;
    bind_rec( ctx, res->rec_idx, &res->key, res->feature_slot, res->deploy_slot, FD_TRANSPILE_BIND_HOLD );
    return;
  }

  int  dedup = 0;
  long slot  = fd_jit_arena_place( ctx->arena, res, ctx->res, ctx->res_sz, &dedup );
  if( FD_UNLIKELY( slot<0L ) ) {
    ctx->metrics.rejected++;
    if( slot==FD_JIT_ARENA_ERR_FULL ) {
      if( !ctx->arena_full ) FD_LOG_WARNING(( "jit arena full (%lu programs, %lu/%lu bytes)", ctx->arena->prog_cnt, ctx->arena->code_used, ctx->arena->code_max ));
      ctx->arena_full = 1;
      return;
    }
    bind_rec( ctx, res->rec_idx, &res->key, res->feature_slot, res->deploy_slot, FD_TRANSPILE_BIND_HOLD );
    return;
  }
  if( dedup ) ctx->metrics.dedup++;
  else        ctx->metrics.placed++;

  if( FD_UNLIKELY( !bind_rec( ctx, res->rec_idx, &res->key, res->feature_slot, res->deploy_slot, FD_TRANSPILE_BIND_JIT | (uint)slot ) ) ) {
    ctx->metrics.stale++;
    FD_LOG_INFO(( "jit %s: record %u moved on before code arrived", prog_b58, res->rec_idx ));
    if( !ctx->slot_ref[ slot ] ) {
      ctx->slot_ref[ slot ] = 1U;
      slot_unref( ctx, (ulong)slot );
    }
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
  ctx->res               = FD_SCRATCH_ALLOC_APPEND( l, 64UL,                      FD_JIT_RES_MTU                    );
  ctx->heat_prev         = FD_SCRATCH_ALLOC_APPEND( l, 64UL,                      tile->jitmap.rec_max*sizeof(uint) );
  ctx->score             = FD_SCRATCH_ALLOC_APPEND( l, 64UL,                      tile->jitmap.rec_max*sizeof(uint) );
  ctx->rec_slot          = FD_SCRATCH_ALLOC_APPEND( l, 64UL,                      tile->jitmap.rec_max*sizeof(uint) );
  memset( &ctx->metrics, 0, sizeof(ctx->metrics) );
  memset( ctx->heat_prev, 0, tile->jitmap.rec_max*sizeof(uint) );
  memset( ctx->score,     0, tile->jitmap.rec_max*sizeof(uint) );
  memset( ctx->rec_slot,  0, tile->jitmap.rec_max*sizeof(uint) );
  memset( ctx->slot_ref,  0, sizeof(ctx->slot_ref) );
  ctx->arena_full = 0;

  if( FD_UNLIKELY( tile->in_cnt!=1UL ) ) FD_LOG_ERR(( "jitmap tile expects one in link, has %lu", tile->in_cnt ));
  fd_topo_link_t const * in = &topo->links[ tile->in_link_id[ 0 ] ];
  ctx->in_mem    = topo->workspaces[ topo->objs[ in->dcache_obj_id ].wksp_id ].wksp;
  ctx->in_chunk0 = fd_dcache_compact_chunk0( ctx->in_mem, in->dcache );
  ctx->in_wmark  = fd_dcache_compact_wmark( ctx->in_mem, in->dcache, in->mtu );

  if( FD_UNLIKELY( tile->out_cnt!=1UL ) ) FD_LOG_ERR(( "jitmap tile expects one out link, has %lu", tile->out_cnt ));
  fd_topo_link_t const * out = &topo->links[ tile->out_link_id[ 0 ] ];
  ctx->out_mem    = topo->workspaces[ topo->objs[ out->dcache_obj_id ].wksp_id ].wksp;
  ctx->out_chunk0 = fd_dcache_compact_chunk0( ctx->out_mem, out->dcache );
  ctx->out_wmark  = fd_dcache_compact_wmark( ctx->out_mem, out->dcache, out->mtu );
  ctx->out_chunk  = ctx->out_chunk0;

  ctx->arena = fd_jit_arena_join( fd_topo_obj_laddr( topo, tile->jitmap.jit_arena_obj_id ) );
  FD_TEST( ctx->arena );
  FD_TEST( fd_progcache_shmem_join( ctx->progcache, fd_topo_obj_laddr( topo, tile->jitmap.progcache_obj_id ) ) );
  ctx->heat = fd_jit_heat_join( fd_topo_obj_laddr( topo, tile->jitmap.jit_heat_obj_id ) );
  FD_TEST( ctx->heat );
  FD_TEST( ctx->heat->rec_max==tile->jitmap.rec_max );
  FD_TEST( ctx->heat->rec_max==ctx->progcache->rec.max );

  double tick_per_ns = fd_tempo_tick_per_ns( NULL );
  ctx->score_min     = (uint)fd_ulong_min( tile->jitmap.hot_cu_threshold, UINT_MAX );
  ctx->sweep_ticks   = (long)( (double)tile->jitmap.sweep_interval_millis*1e6*tick_per_ns );
  ctx->timeout_ticks = (long)( (double)REQ_TIMEOUT_NS*tick_per_ns );
  ctx->sweep_next    = fd_tickcount();
  ctx->idle          = 0;
  ctx->req_busy      = 0;

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
#define STEM_CALLBACK_NEXT_DEADLINE      next_deadline
#define STEM_CALLBACK_AFTER_CREDIT       after_credit
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
