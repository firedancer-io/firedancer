#include "../poh/fd_poh.h"
#include "../replay/fd_replay_tile.h"
#include "../../util/pod/fd_pod.h"
#include "../../disco/tiles.h"
#include "../../disco/fd_clock_tile.h"
#include "../../discof/fd_startup.h"
#include <time.h>
#include "generated/fd_motor_tile_seccomp.h"

/* The motor tile is the Alpenglow leader tile.  It replaces the poh tile
   when alpenglow is enabled, taking over its links, and additionally
   takes votor_out, which will carry parent-ready.

   Block production is not implemented yet, so motor declines every
   leader slot: it answers REPLAY_SIG_BECAME_LEADER with an incomplete
   fd_poh_leader_slot_ended_t so replay releases the leader bank instead
   of holding a refcnt on it forever. */

#define IN_KIND_REPLAY (0)
#define IN_KIND_PACK   (1)
#define IN_KIND_EXECLE (2)
#define IN_KIND_VOTOR  (3)

struct fd_motor_in {
  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
  ulong       mtu;
};

typedef struct fd_motor_in fd_motor_in_t;

struct fd_motor_tile {
  fd_poh_t poh[1];

  ulong in_cnt;
  ulong idle_cnt;

  fd_startup_gate_t startup_gate[1];

  int in_kind[ 64 ];
  fd_motor_in_t in[ 64 ];

  fd_poh_out_t shred_out[ 1 ];
  fd_poh_out_t replay_out[ 1 ];
};

typedef struct fd_motor_tile fd_motor_tile_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 128UL;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_motor_tile_t), sizeof(fd_motor_tile_t) );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static inline void
during_housekeeping( fd_motor_tile_t * ctx ) {
  if( FD_UNLIKELY( fd_clock_tile_recal_due( ctx->poh->clock ) ) ) {
    fd_clock_tile_recal( ctx->poh->clock );
  }
}

static inline void
after_credit( fd_motor_tile_t *   ctx,
              fd_stem_context_t * stem,
              int *               opt_poll_in,
              int *               charge_busy ) {
  (void)stem;
  (void)opt_poll_in;
  (void)charge_busy;

  if( FD_UNLIKELY( !fd_startup_gate_idle( ctx->startup_gate ) ) ) return;

  ctx->idle_cnt++;
}

static void
decline_leader_slot( fd_motor_tile_t *   ctx,
                     fd_stem_context_t * stem,
                     ulong               slot ) {
  fd_poh_leader_slot_ended_t * dst = fd_chunk_to_laddr( ctx->replay_out->mem, ctx->replay_out->chunk );
  fd_memset( dst, 0, sizeof(fd_poh_leader_slot_ended_t) );
  dst->completed        = 0;
  dst->slot             = slot;
  dst->timing_table_idx = ULONG_MAX;

  ulong tspub = (ulong)fd_frag_meta_ts_comp( fd_tickcount() );
  fd_stem_publish( stem, ctx->replay_out->idx, 0UL, ctx->replay_out->chunk, sizeof(fd_poh_leader_slot_ended_t), 0UL, 0UL, tspub );
  ctx->replay_out->chunk = fd_dcache_compact_next( ctx->replay_out->chunk, sizeof(fd_poh_leader_slot_ended_t), ctx->replay_out->chunk0, ctx->replay_out->wmark );
}

static int
before_frag( fd_motor_tile_t * ctx,
             ulong             in_idx,
             ulong             seq FD_PARAM_UNUSED,
             ulong             sig ) {
  if( FD_LIKELY( ctx->in_kind[ in_idx ]==IN_KIND_REPLAY ) )
    return sig!=REPLAY_SIG_RESET && sig!=REPLAY_SIG_BECAME_LEADER && sig!=REPLAY_SIG_WFS_DONE;

  /* motor consumes no votor frags yet. */
  if( FD_UNLIKELY( ctx->in_kind[ in_idx ]==IN_KIND_VOTOR ) ) return 1;

  return 0;
}

static inline int
returnable_frag( fd_motor_tile_t *   ctx,
                 ulong               in_idx,
                 ulong               seq,
                 ulong               sig,
                 ulong               chunk,
                 ulong               sz,
                 ulong               ctl,
                 ulong               tsorig,
                 ulong               tspub,
                 fd_stem_context_t * stem ) {
  (void)seq;
  (void)ctl;
  (void)tsorig;
  (void)tspub;
  (void)stem;

  fd_startup_gate_busy( ctx->startup_gate );

  /* Control frags carrying no payload, published with chunk 0.  These
     must be handled before the bounds check below. */
  if( FD_UNLIKELY( ctx->in_kind[ in_idx ]==IN_KIND_PACK &&
                   ( sig==FD_PACK_MSG_DONE_DRAINING || sig==FD_PACK_MSG_REDUCE_MB_BOUND ) ) ) {
    ctx->idle_cnt = 0UL;
    return 0;
  }

  if( FD_UNLIKELY( ctx->in_kind[ in_idx ]==IN_KIND_REPLAY && sig==REPLAY_SIG_WFS_DONE ) ) {
    ctx->idle_cnt = 0UL;
    return 0;
  }

  if( FD_UNLIKELY( chunk<ctx->in[ in_idx ].chunk0 || chunk>ctx->in[ in_idx ].wmark || sz>ctx->in[ in_idx ].mtu ) )
    FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->in[ in_idx ].chunk0, ctx->in[ in_idx ].wmark ));

  switch( ctx->in_kind[ in_idx ] ) {
    case IN_KIND_REPLAY: {
      if( FD_UNLIKELY( sig==REPLAY_SIG_BECAME_LEADER ) ) {
        fd_became_leader_t const * became_leader = fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, chunk );
        decline_leader_slot( ctx, stem, became_leader->slot );
      }
      break;
    }
    case IN_KIND_PACK:   break;
    case IN_KIND_EXECLE: break;
    case IN_KIND_VOTOR:  break;
    default: {
      FD_LOG_ERR(( "unexpected input kind %d", ctx->in_kind[ in_idx ] ));
      break;
    }
  }

  ctx->idle_cnt = 0UL;
  return 0;
}

static inline fd_poh_out_t
out1( fd_topo_t const *      topo,
      fd_topo_tile_t const * tile,
      char const *           name ) {
  ulong idx = ULONG_MAX;

  for( ulong i=0UL; i<tile->out_cnt; i++ ) {
    fd_topo_link_t const * link = &topo->links[ tile->out_link_id[ i ] ];
    if( !strcmp( link->name, name ) ) {
      if( FD_UNLIKELY( idx!=ULONG_MAX ) ) FD_LOG_ERR(( "tile %s:%lu had multiple output links named %s but expected one", tile->name, tile->kind_id, name ));
      idx = i;
    }
  }

  if( FD_UNLIKELY( idx==ULONG_MAX ) ) FD_LOG_ERR(( "tile %s:%lu had no output link named %s", tile->name, tile->kind_id, name ));

  void * mem = topo->workspaces[ topo->objs[ topo->links[ tile->out_link_id[ idx ] ].dcache_obj_id ].wksp_id ].wksp;
  ulong chunk0 = fd_dcache_compact_chunk0( mem, topo->links[ tile->out_link_id[ idx ] ].dcache );
  ulong wmark  = fd_dcache_compact_wmark ( mem, topo->links[ tile->out_link_id[ idx ] ].dcache, topo->links[ tile->out_link_id[ idx ] ].mtu );

  return (fd_poh_out_t){ .idx = idx, .mem = mem, .chunk0 = chunk0, .wmark = wmark, .chunk = chunk0 };
}

static void
unprivileged_init( fd_topo_t const *      topo,
                   fd_topo_tile_t const * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_motor_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_motor_tile_t ), sizeof( fd_motor_tile_t ) );

  ctx->in_cnt   = tile->in_cnt;
  ctx->idle_cnt = 0UL;

  for( ulong i=0UL; i<tile->in_cnt; i++ ) {
    fd_topo_link_t const * link = &topo->links[ tile->in_link_id[ i ] ];
    fd_topo_wksp_t const * link_wksp = &topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ];

    ctx->in[ i ].mem    = link_wksp->wksp;
    ctx->in[ i ].chunk0 = fd_dcache_compact_chunk0( ctx->in[ i ].mem, link->dcache );
    ctx->in[ i ].wmark  = fd_dcache_compact_wmark ( ctx->in[ i ].mem, link->dcache, link->mtu );
    ctx->in[ i ].mtu    = link->mtu;

    if(      !strcmp( link->name, "replay_out" ) ) ctx->in_kind[ i ] = IN_KIND_REPLAY;
    else if( !strcmp( link->name, "pack_poh"   ) ) ctx->in_kind[ i ] = IN_KIND_PACK;
    else if( !strcmp( link->name, "execle_poh" ) ) ctx->in_kind[ i ] = IN_KIND_EXECLE;
    else if( !strcmp( link->name, "votor_out"  ) ) ctx->in_kind[ i ] = IN_KIND_VOTOR;
    else FD_LOG_ERR(( "unexpected input link name %s", link->name ));
  }

  *ctx->shred_out = out1( topo, tile, "poh_shred" );
  *ctx->replay_out = out1( topo, tile, "poh_replay" );

  void * timing_tables = NULL;
  ulong ldr_tt_obj_id = fd_pod_query_ulong( topo->props, "ldr_tt", ULONG_MAX );
  if( FD_LIKELY( ldr_tt_obj_id!=ULONG_MAX ) ) timing_tables = fd_topo_obj_laddr( topo, ldr_tt_obj_id );

  FD_TEST( fd_poh_join( fd_poh_new( ctx->poh ), ctx->shred_out, ctx->replay_out, timing_tables ) );

  fd_clock_tile_init( ctx->poh->clock );

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, scratch_align() );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));

  fd_startup_gate_init( ctx->startup_gate, topo, tile->in_cnt );
}

static ulong
populate_allowed_seccomp( fd_topo_t const *      topo,
                          fd_topo_tile_t const * tile,
                          ulong                  out_cnt,
                          struct sock_filter *   out ) {
  (void)topo;
  (void)tile;

  populate_sock_filter_policy_fd_motor_tile( out_cnt, out, (uint)fd_log_private_logfile_fd() );
  return sock_filter_policy_fd_motor_tile_instr_cnt;
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

/* One declined leader slot */
#define STEM_BURST (1UL)

/* See explanation in fd_pack */
#define STEM_LAZY  (128L*3000L)

#define STEM_CALLBACK_CONTEXT_TYPE  fd_motor_tile_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_motor_tile_t)

#define STEM_CALLBACK_DURING_HOUSEKEEPING during_housekeeping
#define STEM_CALLBACK_AFTER_CREDIT        after_credit
#define STEM_CALLBACK_BEFORE_FRAG         before_frag
#define STEM_CALLBACK_RETURNABLE_FRAG     returnable_frag

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_motor = {
  .name                     = "motor",
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = NULL,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};
