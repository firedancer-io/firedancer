#include "fd_poh.h"
#include "generated/fd_poh_tile_seccomp.h"
#include "fd_poh_tile.h"
#include "../replay/fd_replay_tile.h"
#include "../../disco/tiles.h"

#define IN_KIND_REPLAY (0)
#define IN_KIND_PACK   (1)
#define IN_KIND_BANK   (2)

struct fd_poh_in {
  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
  ulong       mtu;
};

typedef struct fd_poh_in fd_poh_in_t;

struct fd_poh_tile {
  fd_poh_t poh[1];

  /* There's a race condition ... let's say two banks A and B, bank A
     processes some transactions, then releases the account locks, and
     sends the microblock to PoH to be stamped.  Pack now re-packs the
     same accounts with a new microblock, sends to bank B, bank B
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

  int in_kind[ 64 ];
  fd_poh_in_t in[ 64 ];

  fd_poh_out_t shred_out[ 1 ];
  fd_poh_out_t replay_out[ 1 ];
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
after_credit( fd_poh_tile_t *     ctx,
              fd_stem_context_t * stem,
              int *               opt_poll_in,
              int *               charge_busy ) {
  ctx->idle_cnt++;
  if( FD_LIKELY( ctx->idle_cnt>=2UL*ctx->in_cnt || fd_poh_must_tick( ctx->poh ) ) ) {
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
       mixin happens. */
    fd_poh_advance( ctx->poh, stem, opt_poll_in, charge_busy );
    ctx->idle_cnt = 0UL;
  }
}

/* ....

    1. replay -> (pack, poh) ... start packing for slot
    2. if slot in progress -> pack -> poh (abandon_packing) for old slot
    3. pack free to start packing
    4. if poh slot in progress, refuse replay frag ... until see abandon_packing
    5. poh must process pack frags in order
    6. when poh sees done_packing/abandon_packing, return poh -> replay saying bank unused now */

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
  (void)seq;
  (void)ctl;
  (void)tsorig;
  (void)tspub;

  /* TODO: Pack has a workaround for Frankendancer that sequences bank
     release to manage lifetimes, but it's not needed in Firedancer so
     we just drop it.  We shouldn't send it at all in future. */
  if( FD_UNLIKELY( sig==ULONG_MAX && ctx->in_kind[ in_idx ]==IN_KIND_PACK ) ) {
    ctx->idle_cnt = 0UL;
    return 0;
  }

  if( FD_UNLIKELY( chunk<ctx->in[ in_idx ].chunk0 || chunk>ctx->in[ in_idx ].wmark || sz>ctx->in[ in_idx ].mtu ) )
    FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->in[ in_idx ].chunk0, ctx->in[ in_idx ].wmark ));

  /* There's a race condition where we might receive microblocks from
     banks before we have learned what the leader bank is from replay
     (the become_leader message makes it from replay->pack->bank->poh)
     before it just makes it from replay->poh.  This is rare but
     violates invariants in poh, so we simply do not process any
     transactions for mixin until we have learned what the leader bank
     is. */
  if( FD_UNLIKELY( ctx->in_kind[ in_idx ]==IN_KIND_BANK && !fd_poh_have_leader_bank( ctx->poh ) ) ) return 1;

  if( FD_UNLIKELY( ctx->in_kind[ in_idx ]==IN_KIND_REPLAY && fd_poh_have_leader_bank( ctx->poh ) ) ) return 1;
  /* If prior leaders skipped, it might happen that replay tells us to
     become leader, but poh is still hashing through the skipped slots
     and could not yet mixin any microblocks.  In this case, we hold
     the microblocks and do not mixin them yet until we have hashed
     through to the actual leader slot.

     It might actually be allowed by the protocol to mixin earlier, but
     that really doesn't seem like a good idea.

     It's fine to block pack/banks on hashing here, because they we are
     going to have the wait for the full block to timeout once it starts */
  if( FD_UNLIKELY( ctx->in_kind[ in_idx ]==IN_KIND_BANK && fd_poh_hashing_to_leader_slot( ctx->poh ) ) ) return 1;
  if( FD_LIKELY( ctx->in_kind[ in_idx ]==IN_KIND_BANK || ctx->in_kind[ in_idx ]==IN_KIND_PACK ) ) {
    uint pack_idx = (uint)fd_disco_bank_sig_pack_idx( sig );
    if( FD_UNLIKELY( ((int)(pack_idx-ctx->expect_pack_idx))<0L ) ) FD_LOG_ERR(( "received out of order pack_idx %u (expecting %u)", pack_idx, ctx->expect_pack_idx ));
    if( FD_UNLIKELY( pack_idx!=ctx->expect_pack_idx ) ) return 1;
    ctx->expect_pack_idx++;
  }

  switch( ctx->in_kind[ in_idx ] ) {
    case IN_KIND_PACK: {
      fd_done_packing_t const * done_packing = fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, chunk );
      fd_poh_done_packing( ctx->poh, done_packing->microblocks_in_slot );
      break;
    }
    case IN_KIND_REPLAY: {
      if( FD_LIKELY( sig==REPLAY_SIG_BECAME_LEADER ) ) {
        fd_became_leader_t const * became_leader = fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, chunk );
        fd_poh_begin_leader( ctx->poh, became_leader->slot, became_leader->hashcnt_per_tick, became_leader->ticks_per_slot, became_leader->tick_duration_ns, became_leader->max_microblocks_in_slot );
      } else if( sig==REPLAY_SIG_RESET ) {
        fd_poh_reset_t const * reset = fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, chunk );
        fd_poh_reset( ctx->poh, stem, reset->timestamp, reset->hashcnt_per_tick, reset->ticks_per_slot, reset->tick_duration_ns, reset->completed_slot, reset->completed_blockhash, reset->next_leader_slot, reset->max_microblocks_in_slot, reset->completed_block_id );
      }
      break;
    }
    case IN_KIND_BANK: {
      ulong target_slot = fd_disco_bank_sig_slot( sig );
      ulong txn_cnt = (sz-sizeof(fd_microblock_trailer_t))/sizeof(fd_txn_p_t);
      fd_txn_p_t const * txns = fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, chunk );
      fd_microblock_trailer_t const * trailer = fd_type_pun_const( (uchar const*)txns+sz-sizeof(fd_microblock_trailer_t) );
      fd_poh1_mixin( ctx->poh, stem, target_slot, trailer->hash, txn_cnt, txns );
      break;
    }
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
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_poh_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_poh_tile_t ), sizeof( fd_poh_tile_t ) );

  ctx->expect_pack_idx = 0UL;

  ctx->in_cnt   = tile->in_cnt;
  ctx->idle_cnt = 0UL;

  for( ulong i=0UL; i<tile->in_cnt; i++ ) {
    fd_topo_link_t * link = &topo->links[ tile->in_link_id[ i ] ];
    fd_topo_wksp_t * link_wksp = &topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ];

    ctx->in[ i ].mem    = link_wksp->wksp;
    ctx->in[ i ].chunk0 = fd_dcache_compact_chunk0( ctx->in[ i ].mem, link->dcache );
    ctx->in[ i ].wmark  = fd_dcache_compact_wmark ( ctx->in[ i ].mem, link->dcache, link->mtu );
    ctx->in[ i ].mtu    = link->mtu;

    if(      !strcmp( link->name, "replay_out" ) ) ctx->in_kind[ i ] = IN_KIND_REPLAY;
    else if( !strcmp( link->name, "pack_poh"   ) ) ctx->in_kind[ i ] = IN_KIND_PACK;
    else if( !strcmp( link->name, "bank_poh"   ) ) ctx->in_kind[ i ] = IN_KIND_BANK;
    else FD_LOG_ERR(( "unexpected input link name %s", link->name ));
  }

  *ctx->shred_out = out1( topo, tile, "poh_shred" );
  *ctx->replay_out = out1( topo, tile, "poh_replay" );

  FD_TEST( fd_poh_join( fd_poh_new( ctx->poh ), ctx->shred_out, ctx->replay_out ) );

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, 1UL );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));
}

#if defined(__linux__)

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

#endif /* defined(__linux__) */

/* One tick, one microblock, one slot ended */
#define STEM_BURST (3UL)

/* See explanation in fd_pack */
#define STEM_LAZY  (128L*3000L)

#define STEM_CALLBACK_CONTEXT_TYPE  fd_poh_tile_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_poh_tile_t)

#define STEM_CALLBACK_AFTER_CREDIT    after_credit
#define STEM_CALLBACK_RETURNABLE_FRAG returnable_frag

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_poh = {
  .name                     = "poh",
# if defined(__linux__)
  .populate_allowed_seccomp = populate_allowed_seccomp,
  .populate_allowed_fds     = populate_allowed_fds,
# endif
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = NULL,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};
