#include "fd_poh.h"
#include "fd_poh_tile.h"
#include "../replay/fd_replay_tile.h"
#include "../../util/pod/fd_pod.h"
#include "../../disco/tiles.h"
#include "../../disco/fd_clock_tile.h"
#include "../../discof/fd_startup.h"
#include <time.h>
#include "generated/fd_poh_tile_seccomp.h"

#define IN_KIND_REPLAY (0)
#define IN_KIND_PACK   (1)
#define IN_KIND_EXECLE (2)

struct fd_poh_in {
  fd_wksp_t *            mem;
  ulong                  chunk0;
  ulong                  wmark;
  ulong                  mtu;
  fd_frag_meta_t const * mcache;
  ulong                  depth;
};

typedef struct fd_poh_in fd_poh_in_t;

/* Microblocks (execle_poh) and done_packing (pack_poh) arrive across
   links out of pack_idx order.  Rather than holding a frag on its link
   until its turn, consume it into a ring indexed by pack_idx and mix
   from the ring in order.  Frags REORDER_DEPTH or more ahead of
   expect_pack_idx are still held. */
#define REORDER_DEPTH (4096UL)

struct __attribute__((aligned(64UL))) fd_poh_reorder {
  ulong slot;
  ulong sz;   /* 0 if empty */
  int   kind;
  uchar data[ FD_EXECLE_POH_MTU ] __attribute__((aligned(64UL)));
};

typedef struct fd_poh_reorder fd_poh_reorder_t;

FD_STATIC_ASSERT( sizeof(fd_done_packing_t)<=FD_EXECLE_POH_MTU, reorder_done_packing );

struct fd_poh_tile {
  fd_poh_t poh[1];

  /* There's a race condition ... let's say two execles A and B, execle
     A processes some transactions, then releases the account locks, and
     sends the microblock to PoH to be stamped.  Pack now re-packs the
     same accounts with a new microblock, sends to execle B, execle B
     executes and sends the microblock to PoH, and this all happens fast
     enough that PoH picks the 2nd block to stamp before the 1st.  The
     accounts database changes now are misordered with respect to PoH so
     replay could fail.

     To prevent this race, we order all microblocks and only process
     them in PoH in the order they are produced by pack.  This is a
     little bit over-strict, we just need to ensure that microblocks
     with conflicting accounts execute in order, but this is easiest to
     implement for now. */
  uint expect_pack_idx;

  ulong in_cnt;
  ulong idle_cnt;

  fd_startup_gate_t startup_gate[1];

  int in_kind[ 64 ];
  fd_poh_in_t in[ 64 ];

  fd_poh_out_t shred_out[ 1 ];
  fd_poh_out_t replay_out[ 1 ];

  ulong            reorder_cnt; /* occupied ring entries */
  fd_poh_reorder_t reorder[ REORDER_DEPTH ];
};

typedef struct fd_poh_tile fd_poh_tile_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 128UL;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_poh_tile_t), sizeof(fd_poh_tile_t) );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static inline void
during_housekeeping( fd_poh_tile_t * ctx ) {
  if( FD_UNLIKELY( fd_clock_tile_recal_due( ctx->poh->clock ) ) ) {
    fd_clock_tile_recal( ctx->poh->clock );
  }
}

/* Whether poh state lets a pack_idx-ordered frag of this kind be applied
   now.  See the hold comments in returnable_frag. */
static inline int
mixable( fd_poh_tile_t * ctx,
         int             kind ) {
  if( FD_UNLIKELY( !fd_poh_have_leader_bank( ctx->poh ) ) ) return 0;
  if( FD_UNLIKELY( fd_poh_hashing_to_leader_slot( ctx->poh ) ) ) return 0;
  return kind==IN_KIND_PACK || !fd_poh_must_publish_skipped_tick( ctx->poh );
}

static void
apply_frag( fd_poh_tile_t *     ctx,
            fd_stem_context_t * stem,
            int                 kind,
            ulong               slot,
            uchar const *       data,
            ulong               sz ) {
  if( FD_UNLIKELY( kind==IN_KIND_PACK ) ) {
    fd_poh_done_packing( ctx->poh, stem, fd_type_pun_const( data ) );
    return;
  }

  FD_TEST( sz>=sizeof(fd_microblock_trailer_t) && (sz-sizeof(fd_microblock_trailer_t))%sizeof(fd_txn_p_t)==0UL );
  ulong txn_cnt = (sz-sizeof(fd_microblock_trailer_t))/sizeof(fd_txn_p_t);
  fd_txn_p_t const * txns = fd_type_pun_const( data );
  fd_microblock_trailer_t const * trailer = fd_type_pun_const( data+sz-sizeof(fd_microblock_trailer_t) );

  fd_leader_txn_timing_rec_t timing = {
    .dispatched_ticks = trailer->exec_start_ticks,
    .replayed_ticks   = trailer->exec_end_ticks,
  };
  fd_poh1_mixin( ctx->poh, stem, slot, trailer->hash, txn_cnt, txns, &timing );
}

/* Apply ring entries in pack_idx order while the head is present, poh
   state allows and out credits remain.  Each entry gets the same
   treatment a frag polled on its own would: after_credit's forced
   advance (tick boundary, skipped ticks) first, then the hold checks. */
static void
drain_reorder( fd_poh_tile_t *     ctx,
               fd_stem_context_t * stem,
               int *               charge_busy ) {
  while( FD_LIKELY( ctx->reorder_cnt ) ) {
    fd_poh_reorder_t * r = &ctx->reorder[ ctx->expect_pack_idx & (REORDER_DEPTH-1UL) ];
    if( FD_UNLIKELY( !r->sz ) ) break;
    if( FD_UNLIKELY( *stem->min_cr_avail<2UL ) ) break; /* one tick, one microblock */
    if( FD_UNLIKELY( fd_poh_must_tick( ctx->poh ) || fd_poh_must_publish_skipped_tick( ctx->poh ) ) ) {
      int poll_in = 1;
      fd_poh_advance( ctx->poh, stem, &poll_in, charge_busy );
      if( FD_UNLIKELY( !poll_in ) ) break;
    }
    if( FD_UNLIKELY( !mixable( ctx, r->kind ) ) ) break;
    apply_frag( ctx, stem, r->kind, r->slot, r->data, r->sz );
    r->sz = 0UL;
    ctx->reorder_cnt--;
    ctx->expect_pack_idx++;
    *charge_busy = 1;
  }
}

static inline void
after_credit( fd_poh_tile_t *     ctx,
              fd_stem_context_t * stem,
              int *               opt_poll_in,
              int *               charge_busy ) {
  if( FD_UNLIKELY( !ctx->startup_gate->started && !fd_startup_gate_idle( ctx->startup_gate ) ) ) return;

  ctx->idle_cnt++;
  if( FD_LIKELY( ctx->idle_cnt>=2UL*ctx->in_cnt || fd_poh_must_tick( ctx->poh ) || fd_poh_must_publish_skipped_tick( ctx->poh ) ) ) {
    /* We would like to fully drain input links to the best of our
       knowledge, before we spend cycles on hashing.  That is, we would
       like to assert that all input links have stayed empty since the
       last time we polled.  Given an arbitrary input link L, the worst
       case is when L is at idx 0 in the input link shuffle the last
       time we polled a frag from it, but then link L ends up at idx
       in_cnt-1 in the subsequent input link shuffle.  So strictly
       speaking we will need to have observed 2*in_cnt-1 consecutive
       empty in links to be able to assert that link L has been empty
       since the last time we polled it.

       Except that when we are leader and the hashcnt is right before a
       tick boundary, poh must advance to the tick boundary and produce
       the tick.  Otherwise, a tick will be skipped if a microblock
       mixin happens.  Additionally, when there are pending skipped
       ticks to be published, we should do that before processing any
       incoming microblocks.

       Input has run dry, so any coalesced microblocks go out now
       rather than wait for the next one. */
    fd_poh_flush_shred( ctx->poh, stem );
    fd_poh_advance( ctx->poh, stem, opt_poll_in, charge_busy );
    ctx->idle_cnt = 0UL;
  }

  /* Buffered frags may have become mixable (leader bank arrived, hashed
     to the leader slot, skipped ticks published). */
  if( FD_UNLIKELY( ctx->reorder_cnt && *opt_poll_in ) ) drain_reorder( ctx, stem, charge_busy );
}

/* ....

    1. replay -> (pack, poh) ... start packing for slot
    2. if slot in progress -> pack -> poh (abandon_packing) for old slot
    3. pack free to start packing
    4. if poh slot in progress, refuse replay frag ... until see abandon_packing
    5. poh must process pack frags in order
    6. when poh sees done_packing/abandon_packing, return poh -> replay saying execle unused now */

static int
before_frag( fd_poh_tile_t * ctx,
             ulong           in_idx,
             ulong           seq FD_PARAM_UNUSED,
             ulong           sig ) {
  if( FD_LIKELY( ctx->in_kind[ in_idx ]==IN_KIND_REPLAY ) )
    return sig!=REPLAY_SIG_RESET && sig!=REPLAY_SIG_BECAME_LEADER && sig!=REPLAY_SIG_WFS_DONE;
  return 0;
}

static inline int
returnable_frag( fd_poh_tile_t *     ctx,
                 ulong               in_idx,
                 ulong               seq,
                 ulong               sig,
                 ulong               chunk,
                 ulong               sz,
                 ulong               ctl,
                 ulong               tsorig,
                 ulong               tspub,
                 fd_stem_context_t * stem ) {
  (void)ctl;
  (void)tsorig;
  (void)tspub;

  fd_startup_gate_busy( ctx->startup_gate );

  /* TODO: Pack has a workaround for Frankendancer that sequences bank
     release to manage lifetimes, but it's not needed in Firedancer so
     we just drop it.  We shouldn't send it at all in future. */
  if( FD_UNLIKELY( sig==FD_PACK_MSG_DONE_DRAINING && ctx->in_kind[ in_idx ]==IN_KIND_PACK ) ) {
    ctx->idle_cnt = 0UL;
    return 0;
  }

  /* Pack periodically publishes a tighter microblock bound over the
     pack_poh link. */
  if( FD_UNLIKELY( sig==FD_PACK_MSG_REDUCE_MB_BOUND && ctx->in_kind[ in_idx ]==IN_KIND_PACK ) ) {
    ctx->idle_cnt = 0UL;
    if( FD_UNLIKELY( !fd_poh_have_leader_bank( ctx->poh ) ) ) return 0; /* must have become leader first */
    FD_TEST( sz==sizeof(ulong) );
    ulong const * new_max = fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, chunk );
    fd_poh_update_max_microblocks( ctx->poh, *new_max );
    return 0;
  }

  if( FD_UNLIKELY( sig==REPLAY_SIG_WFS_DONE && ctx->in_kind[ in_idx ]==IN_KIND_REPLAY ) ) {
    fd_poh_wfs_done( ctx->poh );
    ctx->idle_cnt = 0UL;
    return 0;
  }

  if( FD_UNLIKELY( chunk<ctx->in[ in_idx ].chunk0 || chunk>ctx->in[ in_idx ].wmark || sz>ctx->in[ in_idx ].mtu ) )
    FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->in[ in_idx ].chunk0, ctx->in[ in_idx ].wmark ));

  int kind = ctx->in_kind[ in_idx ];
  uchar const * src = fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, chunk );

  if( FD_UNLIKELY( kind==IN_KIND_REPLAY ) ) {
    if( FD_UNLIKELY( fd_poh_have_leader_bank( ctx->poh ) ) ) return 1;
    if( FD_LIKELY( sig==REPLAY_SIG_BECAME_LEADER ) ) {
      fd_became_leader_t const * became_leader = fd_type_pun_const( src );
      fd_poh_begin_leader( ctx->poh, became_leader->slot, became_leader->hashcnt_per_tick, became_leader->ticks_per_slot, became_leader->tick_duration_ns, became_leader->max_microblocks_in_slot, became_leader->slot_start_ns );
    } else if( sig==REPLAY_SIG_RESET ) {
      fd_poh_reset_t const * reset = fd_type_pun_const( src );
      fd_poh_reset( ctx->poh, stem, reset->timestamp, reset->hashcnt_per_tick, reset->ticks_per_slot, reset->tick_duration_ns, reset->completed_slot, reset->completed_blockhash, reset->next_leader_slot, reset->max_microblocks_in_slot, reset->completed_cmr );
      ctx->poh->wfs_paused = reset->wfs_paused;
    }
    ctx->idle_cnt = 0UL;
    return 0; /* after_credit drains the ring once state allows */
  }

  /* Execle microblocks and pack's done_packing are applied strictly in
     pack_idx order (see expect_pack_idx).  A frag whose turn has not
     come, or that poh cannot yet accept, is copied into the ring and
     applied from drain_reorder once it can be.

     Poh cannot accept a frag when:

     - We have not yet learned the leader bank from replay.  Microblocks
       (or pack's done_packing, when pack ends the block on a reset) can
       race ahead of it, since become_leader travels
       replay->pack->execle->poh as well as replay->poh.  become_leader
       always precedes the reset on the replay link, so this clears.

     - Prior leaders skipped and poh is still hashing through the
       skipped slots.  It might be allowed by the protocol to mixin
       earlier, but that really doesn't seem like a good idea.  Blocking
       pack/execles on hashing is fine, they are going to have to wait
       for the full block to timeout once it starts.

     - Prior leaders skipped and the skipped ticks have not all been
       published.  They must precede any microblock, and go out in the
       immediate after_credit iterations. */
  uint pack_idx = (uint)fd_disco_execle_sig_pack_idx( sig );
  int  dist     = (int)(pack_idx-ctx->expect_pack_idx);
  if( FD_UNLIKELY( dist<0 ) ) FD_LOG_ERR(( "received out of order pack_idx %u (expecting %u)", pack_idx, ctx->expect_pack_idx ));
  if( FD_UNLIKELY( (ulong)dist>=REORDER_DEPTH ) ) return 1; /* too far ahead for the ring, hold */

  if( FD_LIKELY( kind==IN_KIND_EXECLE ) ) {
    /* The execle wrote the result flags and the trailer just before
       publishing, so those lines are still modified in its cache and
       cost a snoop each.  Request them together, before the state
       checks and payload copy, rather than one at a time below.  With
       sticky polling this link's next frag is polled next; if it is
       already published (its data is then complete) request its lines
       too.  Never touch unpublished frag data: the execle would pay an
       invalidation on every line it then writes. */
    fd_poh_in_t const * in = &ctx->in[ in_idx ];
    __builtin_prefetch( src+offsetof(fd_txn_p_t, flags),             0, 3 );
    __builtin_prefetch( src+sz-sizeof(fd_microblock_trailer_t),      0, 3 );
    __builtin_prefetch( src+sz-sizeof(fd_microblock_trailer_t)+64UL, 0, 3 );
    fd_frag_meta_t const * next = in->mcache+fd_mcache_line_idx( seq+1UL, in->depth );
    if( FD_LIKELY( FD_VOLATILE_CONST( next->seq )==seq+1UL ) ) {
      ulong         nsz  = (ulong)next->sz; /* torn read only misdirects a hint */
      uchar const * nsrc = fd_chunk_to_laddr_const( in->mem, (ulong)next->chunk );
      __builtin_prefetch( nsrc+offsetof(fd_txn_p_t, flags),              0, 3 );
      __builtin_prefetch( nsrc+nsz-sizeof(fd_microblock_trailer_t),      0, 3 );
      __builtin_prefetch( nsrc+nsz-sizeof(fd_microblock_trailer_t)+64UL, 0, 3 );
    }
  }

  if( FD_LIKELY( !dist && mixable( ctx, kind ) ) ) {
    apply_frag( ctx, stem, kind, fd_disco_execle_sig_slot( sig ), src, sz );
    ctx->expect_pack_idx++;
    int busy;
    drain_reorder( ctx, stem, &busy );
  } else {
    fd_poh_reorder_t * r = &ctx->reorder[ pack_idx & (REORDER_DEPTH-1UL) ];
    FD_TEST( !r->sz && sz && sz<=sizeof(r->data) ); /* full slot means duplicate pack_idx */
    r->slot = fd_disco_execle_sig_slot( sig );
    r->sz   = sz;
    r->kind = kind;
    if( FD_UNLIKELY( kind==IN_KIND_PACK ) ) fd_memcpy( r->data, src, sz );
    else {
      /* Same layout, but only the bytes mixin reads: each txn's payload
         prefix and the fields after it (not the parsed txn), plus the
         trailer.  A full 5 KiB copy per microblock is DRAM bound.  The
         fixed size pieces are copied by word, since znver tuning turns
         a 16..8192 byte memcpy into a slow rep movsl. */
      FD_TEST( sz>=sizeof(fd_microblock_trailer_t) && (sz-sizeof(fd_microblock_trailer_t))%sizeof(fd_txn_p_t)==0UL );
      ulong txn_cnt = (sz-sizeof(fd_microblock_trailer_t))/sizeof(fd_txn_p_t);
      fd_txn_p_t const * s = fd_type_pun_const( src );
      fd_txn_p_t *       d = fd_type_pun( r->data );
      for( ulong i=0UL; i<txn_cnt; i++ ) {
        fd_memcpy( d[ i ].payload, s[ i ].payload, fd_ulong_min( s[ i ].payload_sz, FD_TPU_MTU ) );
        uchar const * sf = (uchar const *)&s[ i ].payload_sz;
        uchar *       df = (uchar *)      &d[ i ].payload_sz;
        for( ulong j=0UL; j<offsetof(fd_txn_p_t, _)-offsetof(fd_txn_p_t, payload_sz); j+=8UL ) FD_STORE( ulong, df+j, FD_LOAD( ulong, sf+j ) );
      }
      for( ulong j=sz-sizeof(fd_microblock_trailer_t); j<sz; j+=8UL ) FD_STORE( ulong, r->data+j, FD_LOAD( ulong, src+j ) );
    }
    ctx->reorder_cnt++;
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
  fd_poh_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_poh_tile_t ), sizeof( fd_poh_tile_t ) );

  ctx->expect_pack_idx = 0UL;

  ctx->in_cnt   = tile->in_cnt;
  ctx->idle_cnt = 0UL;

  ctx->reorder_cnt = 0UL;
  for( ulong i=0UL; i<REORDER_DEPTH; i++ ) ctx->reorder[ i ].sz = 0UL;

  FD_CHECK_ERR( tile->in_cnt<=sizeof(ctx->in)/sizeof(ctx->in[0]), "too many input links" );

  for( ulong i=0UL; i<tile->in_cnt; i++ ) {
    fd_topo_link_t const * link = &topo->links[ tile->in_link_id[ i ] ];
    fd_topo_wksp_t const * link_wksp = &topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ];

    ctx->in[ i ].mem    = link_wksp->wksp;
    ctx->in[ i ].chunk0 = fd_dcache_compact_chunk0( ctx->in[ i ].mem, link->dcache );
    ctx->in[ i ].wmark  = fd_dcache_compact_wmark ( ctx->in[ i ].mem, link->dcache, link->mtu );
    ctx->in[ i ].mtu    = link->mtu;
    ctx->in[ i ].mcache = link->mcache;
    ctx->in[ i ].depth  = fd_mcache_depth( link->mcache );

    if(      !strcmp( link->name, "replay_out" ) ) ctx->in_kind[ i ] = IN_KIND_REPLAY;
    else if( !strcmp( link->name, "pack_poh"   ) ) ctx->in_kind[ i ] = IN_KIND_PACK;
    else if( !strcmp( link->name, "execle_poh" ) ) ctx->in_kind[ i ] = IN_KIND_EXECLE;
    else FD_LOG_ERR(( "unexpected input link name %s", link->name ));
  }

  *ctx->shred_out = out1( topo, tile, "poh_shred" );
  *ctx->replay_out = out1( topo, tile, "poh_replay" );

  void * timing_tables = NULL;
  ulong ldr_tt_obj_id = fd_pod_query_ulong( topo->props, "ldr_tt", ULONG_MAX );
  if( FD_LIKELY( ldr_tt_obj_id!=ULONG_MAX ) ) timing_tables = fd_topo_obj_laddr( topo, ldr_tt_obj_id );

  FD_TEST( fd_poh_join( fd_poh_new( ctx->poh ), ctx->shred_out, ctx->replay_out, timing_tables, tile->poh.max_txn_per_slot ) );

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

  populate_sock_filter_policy_fd_poh_tile( out_cnt, out, (uint)fd_log_private_logfile_fd() );
  return sock_filter_policy_fd_poh_tile_instr_cnt;
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

/* One tick, one microblock */
#define STEM_BURST (2UL)

/* Frags are consumed out of pack_idx order into the reorder ring, so
   keep draining a link that just had one. */
#define STEM_STICKY_POLL_MAX (16UL)

/* See explanation in fd_pack */
#define STEM_LAZY  (128L*3000L)

#define STEM_CALLBACK_CONTEXT_TYPE  fd_poh_tile_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_poh_tile_t)

#define STEM_CALLBACK_DURING_HOUSEKEEPING during_housekeeping
#define STEM_CALLBACK_AFTER_CREDIT        after_credit
#define STEM_CALLBACK_BEFORE_FRAG         before_frag
#define STEM_CALLBACK_RETURNABLE_FRAG     returnable_frag

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_poh = {
  .name                     = "poh",
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = NULL,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};
