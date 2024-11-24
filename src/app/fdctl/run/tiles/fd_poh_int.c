#include "../../fdctl.h"
#include "../../../../disco/poh/fd_poh_tile.h"

#include "../../../../ballet/pack/fd_pack.h"
#include "../../../../ballet/sha256/fd_sha256.h"
#include "../../../../disco/topo/fd_pod_format.h"
#include "../../../../disco/shred/fd_shredder.h"
#include "../../../../disco/shred/fd_stake_ci.h"
#include "../../../../disco/bank/fd_bank_abi.h"
#include "../../../../disco/keyguard/fd_keyload.h"
#include "../../../../disco/metrics/generated/fd_metrics_poh.h"
#include "../../../../flamenco/leaders/fd_leaders.h"
#include "../../../../flamenco/fd_flamenco.h"

/* The PoH recorder is implemented in Firedancer but for now needs to
   work with Agave, so we have a locking scheme for them to
   co-operate.

   This is because the PoH tile lives in the Agave memory address
   space and their version of concurrency is locking the PoH recorder
   and reading arbitrary fields.

   So we allow them to lock the PoH tile, although with a very bad (for
   them) locking scheme.  By default, the tile has full and exclusive
   access to the data.  If part of Agave wishes to read/write they
   can either,

     1. Rewrite their concurrency to message passing based on mcache
        (preferred, but not feasible).
     2. Signal to the tile they wish to acquire the lock, by setting
        fd_poh_waiting_lock to 1.

   During housekeeping, the tile will check if there is the waiting lock
   is set to 1, and if so, set the returned lock to 1, indicating to the
   waiter that they may now proceed.

   When the waiter is done reading and writing, they restore the
   returned lock value back to zero, and the POH tile continues with its
   day. */

typedef struct {
  fd_poh_tile_ctx_t * poh_tile_ctx;

  int filter_frag;

  ulong bank_cnt;
  ulong * bank_busy[ 64UL ];

  ulong stake_in_idx;

  ulong pack_in_idx;

  /* These are temporarily set in during_frag so they can be used in
     after_frag once the frag has been validated as not overrun. */
  uchar _txns[ 1024* USHORT_MAX ];
  fd_microblock_trailer_t _microblock_trailer[1];

  int is_initialized;
  int recently_reset;

  ulong * current_slot;

  fd_poh_tile_in_ctx_t bank_in[ 32 ];
  fd_poh_tile_in_ctx_t stake_in;
  fd_poh_tile_in_ctx_t pack_in;

  fd_wksp_t * shred_out_mem;
  ulong       shred_out_chunk0;
  ulong       shred_out_wmark;
  ulong       shred_out_chunk;

  fd_frag_meta_t * pack_out_mcache;
  ulong            pack_out_depth;
  ulong            pack_out_seq;
  ulong *          pack_out_sync;

  fd_wksp_t *      pack_out_mem;
  ulong            pack_out_chunk0;
  ulong            pack_out_wmark;
  ulong            pack_out_chunk;

  fd_stem_context_t * stem;

} fd_poh_ctx_t;

static void
signal_leader_change( void * _arg FD_PARAM_UNUSED ) {
  // TODO publishing etc
}

static void *
get_mircoblock_buffer( void * _arg ) {
  fd_poh_ctx_t * ctx = (fd_poh_ctx_t *)_arg;
  uchar * dst = (uchar *)fd_chunk_to_laddr( ctx->shred_out_mem, ctx->shred_out_chunk );
  return dst;
}

static void
publish_microblock( void * _arg, ulong tspub, ulong sig, ulong sz ) {
  fd_poh_ctx_t * ctx = (fd_poh_ctx_t *)_arg;
  fd_stem_publish( ctx->stem, 0UL, sig, ctx->shred_out_chunk, sz, 0UL, 0UL, tspub );
  ctx->shred_out_chunk = fd_dcache_compact_next( ctx->shred_out_chunk, sz, ctx->shred_out_chunk0, ctx->shred_out_wmark );
}

static void *
get_pack_buffer( void * _arg ) {
  fd_poh_ctx_t * ctx = (fd_poh_ctx_t *)_arg;
  uchar * dst = (uchar *)fd_chunk_to_laddr( ctx->pack_out_mem, ctx->pack_out_chunk );
  return dst;
}

static void
publish_pack( void * _arg, ulong tspub, ulong sig, ulong sz ) {
  fd_poh_ctx_t * ctx = (fd_poh_ctx_t *)_arg;
  fd_mcache_publish( ctx->pack_out_mcache, ctx->pack_out_depth, ctx->pack_out_seq, sig, ctx->pack_out_chunk, sizeof(fd_became_leader_t), 0UL, 0UL, tspub );
  ctx->pack_out_chunk = fd_dcache_compact_next( ctx->pack_out_chunk, sz, ctx->pack_out_chunk0, ctx->pack_out_wmark );
  ctx->pack_out_seq = fd_seq_inc( ctx->pack_out_seq, 1UL );
}

static void
register_tick( void * _arg                FD_PARAM_UNUSED,
               ulong  current_leader_slot FD_PARAM_UNUSED,
               uchar  hash[ static 32 ]   FD_PARAM_UNUSED ) { }

/* The PoH tile needs to interact with the Agave address space to
   do certain operations that Firedancer hasn't reimplemented yet, a.k.a
   transaction execution.  We have Agave export some wrapper
   functions that we call into during regular tile execution.  These do
   not need any locking, since they are called serially from the single
   PoH tile. */

extern void fd_ext_bank_acquire( void const * bank );
extern void fd_ext_bank_release( void const * bank );

void fd_poh_signal_leader_change( fd_poh_ctx_t * ctx FD_PARAM_UNUSED ) { }

void fd_poh_register_tick( fd_poh_ctx_t * ctx         FD_PARAM_UNUSED,
                           ulong          reset_slot  FD_PARAM_UNUSED,
                           uchar const *  hash        FD_PARAM_UNUSED ) { }

/* fd_ext_poh_initialize is called by Agave on startup to
   initialize the PoH tile with some static configuration, and the
   initial reset slot and hash which it retrieves from a snapshot.

   This function is called by some random Agave thread, but
   it blocks booting of the PoH tile.  The tile will spin until it
   determines that this initialization has happened.

   signal_leader_change is an opaque Rust object that is used to
   tell the replay stage that the leader has changed.  It is a
   Box::into_raw(Arc::increment_strong(crossbeam::Sender)), so it
   has infinite lifetime unless this C code releases the refcnt.

   It can be used with `fd_ext_poh_signal_leader_change` which
   will just issue a nonblocking send on the channel. */

void
fd_poh_initialize( fd_poh_ctx_t * ctx,
                   ulong          tick_duration_ns, /* See clock comments above, will be 500ns for mainnet-beta. */
                   ulong          hashcnt_per_tick,    /* See clock comments above, will be 12,500 for mainnet-beta. */
                   ulong          ticks_per_slot,      /* See clock comments above, will almost always be 64. */
                   ulong          tick_height,         /* The counter (height) of the tick to start hashing on top of. */
                   uchar const *  last_entry_hash      /* Points to start of a 32 byte region of memory, the hash itself at the tick height. */ ) {
  fd_poh_tile_initialize( ctx->poh_tile_ctx, tick_duration_ns, hashcnt_per_tick, ticks_per_slot, tick_height,
      last_entry_hash );
  ctx->recently_reset = 1;
  ctx->is_initialized = 1;
}

/* fd_ext_poh_reset is called by the Agave client when a slot on
   the active fork has finished a block and we need to reset our PoH to
   be ticking on top of the block it produced. */

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 128UL;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof( fd_poh_ctx_t ), sizeof( fd_poh_ctx_t ) );
  l = FD_LAYOUT_APPEND( l, fd_poh_tile_align(), fd_poh_tile_footprint() );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static inline void
after_credit( fd_poh_ctx_t *      ctx,
              fd_stem_context_t * stem,
              int *               opt_poll_in,
              int *               charge_busy ) {
  ctx->stem = stem;

  if( FD_UNLIKELY( !ctx->is_initialized ) ) return;

  if( FD_LIKELY( ctx->poh_tile_ctx->current_leader_slot==FD_SLOT_NULL && ctx->recently_reset ) ) {
    /* We are not leader, but we should check if we have reached a leader slot! */
    ulong leader_slot = FD_SLOT_NULL;
    ulong reset_slot = FD_SLOT_NULL;
    int has_reached_leader_slot = fd_poh_tile_reached_leader_slot( ctx->poh_tile_ctx, &leader_slot, &reset_slot );
    if( has_reached_leader_slot ) {
      fd_poh_tile_begin_leader( ctx->poh_tile_ctx, leader_slot, ctx->poh_tile_ctx->hashcnt_per_tick );
      ctx->recently_reset = 0;
    }
    *charge_busy = 1;
  }

  if( FD_LIKELY( fd_poh_tile_after_credit( ctx->poh_tile_ctx, opt_poll_in ) ) ) {
    *charge_busy = 1;
  }

  fd_fseq_update( ctx->current_slot, ctx->poh_tile_ctx->slot );
}

static inline void
during_housekeeping( fd_poh_ctx_t * ctx ) {
  fd_poh_tile_during_housekeeping( ctx->poh_tile_ctx );
}

static inline void
during_frag( fd_poh_ctx_t * ctx,
             ulong         in_idx,
             ulong         seq,
             ulong         sig,
             ulong         chunk,
             ulong         sz ) {
  (void)seq;
  (void)sig;

  ctx->filter_frag = 0;

  if( FD_UNLIKELY( in_idx==ctx->stake_in_idx ) ) {
    if( FD_UNLIKELY( chunk<ctx->stake_in.chunk0 || chunk>ctx->stake_in.wmark ) )
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz,
            ctx->stake_in.chunk0, ctx->stake_in.wmark ));

    uchar const * dcache_entry = fd_chunk_to_laddr_const( ctx->stake_in.mem, chunk );
    fd_poh_tile_init_stakes( ctx->poh_tile_ctx, dcache_entry );
    return;
  }

  ulong pkt_type;
  ulong slot;
  if( FD_UNLIKELY( in_idx==ctx->pack_in_idx ) ) {
    pkt_type = fd_disco_poh_sig_pkt_type( sig );
    slot = fd_disco_poh_sig_slot( sig );
  } else {
    pkt_type = POH_PKT_TYPE_MICROBLOCK;
    slot = fd_disco_bank_sig_slot( sig );
  }

  int is_frag_for_prior_leader_slot = 0;
  if( FD_LIKELY( pkt_type==POH_PKT_TYPE_DONE_PACKING || pkt_type==POH_PKT_TYPE_MICROBLOCK ) ) {
    /* The following sequence is possible...

        1. We become leader in slot 10
        2. While leader, we switch to a fork that is on slot 8, where
            we are leader
        3. We get the in-flight microblocks for slot 10

      These in-flight microblocks need to be dropped, so we check
      against the high water mark (highwater_leader_slot) rather than
      the current hashcnt here when determining what to drop.

      We know if the slot is lower than the high water mark it's from a stale
      leader slot, because we will not become leader for the same slot twice
      even if we are reset back in time (to prevent duplicate blocks). */
    is_frag_for_prior_leader_slot = slot<ctx->poh_tile_ctx->highwater_leader_slot;
  }

  if( FD_UNLIKELY( in_idx==ctx->pack_in_idx ) ) {
    /* We now know the real amount of microblocks published, so set an
       exact bound for once we receive them. */
    ctx->filter_frag = 1;
    if( fd_disco_poh_sig_pkt_type( sig )==POH_PKT_TYPE_DONE_PACKING ) {
      if( FD_UNLIKELY( is_frag_for_prior_leader_slot ) ) return;

      fd_done_packing_t const * done_packing = fd_chunk_to_laddr( ctx->pack_in.mem, chunk );
      fd_poh_tile_done_packing( ctx->poh_tile_ctx, done_packing->microblocks_in_slot );
    }
    return;
  } else {
    if( FD_UNLIKELY( chunk<ctx->bank_in[ in_idx ].chunk0 || chunk>ctx->bank_in[ in_idx ].wmark || sz>USHORT_MAX ) )
      FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->bank_in[ in_idx ].chunk0, ctx->bank_in[ in_idx ].wmark ));

    if( !ctx->is_initialized && fd_disco_replay_sig_flags( sig )==REPLAY_FLAG_INIT ) {
      FD_LOG_INFO(( "init msg rx" ));
      fd_poh_init_msg_t * init_msg = (fd_poh_init_msg_t *)fd_chunk_to_laddr( ctx->bank_in[ in_idx ].mem, chunk );
      fd_poh_initialize( ctx, init_msg->tick_duration_ns, init_msg->hashcnt_per_tick, init_msg->ticks_per_slot, init_msg->tick_height, init_msg->last_entry_hash );
      ctx->filter_frag = 1;
      return;
    }
    uchar * src = (uchar *)fd_chunk_to_laddr( ctx->bank_in[ in_idx ].mem, chunk );

    ulong raw_sz = (sz * sizeof(fd_txn_p_t))+sizeof(fd_microblock_trailer_t);
    FD_TEST( raw_sz<=1024*USHORT_MAX );
    fd_memcpy( ctx->_txns, src, raw_sz-sizeof(fd_microblock_trailer_t) );
    fd_memcpy( ctx->_microblock_trailer, src+(sz * sizeof(fd_txn_p_t)), sizeof(fd_microblock_trailer_t) );

    ctx->filter_frag = is_frag_for_prior_leader_slot;
  }
}

static inline void
after_frag( fd_poh_ctx_t *      ctx,
            ulong               in_idx,
            ulong               seq,
            ulong               sig,
            ulong               sz,
            ulong               tsorig,
            fd_stem_context_t * stem ) {
  (void)in_idx;
  (void)seq;
  (void)tsorig;
  (void)stem;

  if( FD_UNLIKELY( ctx->filter_frag ) ) return;

  if( FD_UNLIKELY( in_idx==ctx->stake_in_idx ) ) {
    /* Nothing to do if we transition into being leader, since it
       will just get picked up by the regular tick loop. */
    fd_poh_tile_fini_stakes( ctx->poh_tile_ctx );
    return;
  }

  if( FD_UNLIKELY( !ctx->poh_tile_ctx->microblocks_lower_bound ) ) {
    double tick_per_ns = fd_tempo_tick_per_ns( NULL );
    fd_histf_sample( ctx->poh_tile_ctx->first_microblock_delay, (ulong)((double)(fd_log_wallclock()-ctx->poh_tile_ctx->reset_slot_start_ns)/tick_per_ns) );
  }

  ulong target_flags = fd_disco_replay_sig_flags( sig );
  ulong target_slot = fd_disco_replay_sig_slot( sig );

  ulong is_packed_microblock = target_flags & REPLAY_FLAG_PACKED_MICROBLOCK;
  ulong is_finalized_block = target_flags & REPLAY_FLAG_FINISHED_BLOCK;
  // ulong is_catching_up = target_flags & REPLAY_FLAG_CATCHING_UP;

  if( is_packed_microblock ) {
    ulong txn_cnt = sz;
    fd_txn_p_t * txns = (fd_txn_p_t *)(ctx->_txns);
    ulong sig = fd_disco_poh_sig( target_slot, POH_PKT_TYPE_MICROBLOCK, in_idx );
    fd_poh_tile_process_packed_microblock( ctx->poh_tile_ctx, target_slot, sig, txns, txn_cnt, ctx->_microblock_trailer->hash );
  } else {
     if( is_finalized_block && ctx->is_initialized ) {
      fd_poh_tile_reset( ctx->poh_tile_ctx, target_slot, ctx->_microblock_trailer->hash, ctx->poh_tile_ctx->hashcnt_per_tick );
      ctx->recently_reset = 1;
    }
  }
}

static void
privileged_init( fd_topo_t *      topo,
                 fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_poh_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_poh_ctx_t ), sizeof( fd_poh_ctx_t ) );
  ctx->poh_tile_ctx = FD_SCRATCH_ALLOC_APPEND( l, fd_poh_tile_align(), fd_poh_tile_footprint()  );

  if( FD_UNLIKELY( !strcmp( tile->poh.identity_key_path, "" ) ) )
    FD_LOG_ERR(( "identity_key_path not set" ));

  const uchar * identity_key = fd_keyload_load( tile->poh.identity_key_path, /* pubkey only: */ 1 );
  fd_memcpy( ctx->poh_tile_ctx->identity_key.uc, identity_key, 32UL );
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_poh_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_poh_ctx_t ), sizeof( fd_poh_ctx_t ) );
  ctx->poh_tile_ctx = FD_SCRATCH_ALLOC_APPEND( l, fd_poh_tile_align(), fd_poh_tile_footprint()  );
#define NONNULL( x ) (__extension__({                                        \
      __typeof__((x)) __x = (x);                                             \
      if( FD_UNLIKELY( !__x ) ) FD_LOG_ERR(( #x " was unexpectedly NULL" )); \
      __x; }))

  // TODO: scratch alloc needs fixing!
  fd_poh_tile_new( ctx->poh_tile_ctx, ctx, get_mircoblock_buffer, publish_microblock, get_pack_buffer, publish_pack, register_tick, signal_leader_change );

  ulong poh_slot_obj_id = fd_pod_query_ulong( topo->props, "poh_slot", ULONG_MAX );
  FD_TEST( poh_slot_obj_id!=ULONG_MAX );
  ctx->current_slot = fd_fseq_join( fd_topo_obj_laddr( topo, poh_slot_obj_id ) );

  ctx->is_initialized = 0;
  ctx->recently_reset = 0;
  ctx->bank_cnt = tile->in_cnt-2UL;
  ctx->stake_in_idx = tile->in_cnt-2UL;
  ctx->pack_in_idx = tile->in_cnt-1UL;

  FD_TEST( ctx->bank_cnt<=sizeof(ctx->bank_busy)/sizeof(ctx->bank_busy[0]) );
  for( ulong i=0UL; i<ctx->bank_cnt; i++ ) {
    ulong busy_obj_id = fd_pod_queryf_ulong( topo->props, ULONG_MAX, "bank_busy.%lu", i );
    FD_TEST( busy_obj_id!=ULONG_MAX );
    ctx->bank_busy[ i ] = fd_fseq_join( fd_topo_obj_laddr( topo, busy_obj_id ) );
    if( FD_UNLIKELY( !ctx->bank_busy[ i ] ) ) FD_LOG_ERR(( "banking tile %lu has no busy flag", i ));
  }

  for( ulong i=0UL; i<tile->in_cnt-2UL; i++ ) {
    fd_topo_link_t * link = &topo->links[ tile->in_link_id[ i ] ];
    fd_topo_wksp_t * link_wksp = &topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ];
    FD_TEST( strcmp( link->name, "replay_poh" )==0 );

    ctx->bank_in[ i ].mem    = link_wksp->wksp;
    ctx->bank_in[ i ].chunk0 = fd_dcache_compact_chunk0( ctx->bank_in[i].mem, link->dcache );
    ctx->bank_in[ i ].wmark  = fd_dcache_compact_wmark ( ctx->bank_in[i].mem, link->dcache, link->mtu );
  }

  FD_TEST( strcmp( topo->links[ tile->in_link_id[ ctx->stake_in_idx ] ].name, "stake_out" )==0 );
  ctx->stake_in.mem    = topo->workspaces[ topo->objs[ topo->links[ tile->in_link_id[ ctx->stake_in_idx ] ].dcache_obj_id ].wksp_id ].wksp;
  ctx->stake_in.chunk0 = fd_dcache_compact_chunk0( ctx->stake_in.mem, topo->links[ tile->in_link_id[ ctx->stake_in_idx ] ].dcache );
  ctx->stake_in.wmark  = fd_dcache_compact_wmark ( ctx->stake_in.mem, topo->links[ tile->in_link_id[ ctx->stake_in_idx ] ].dcache, topo->links[ tile->in_link_id[ ctx->stake_in_idx ] ].mtu );

  FD_TEST( strcmp( topo->links[ tile->in_link_id[ ctx->pack_in_idx ] ].name, "pack_replay" )==0 );
  ctx->pack_in.mem    = topo->workspaces[ topo->objs[ topo->links[ tile->in_link_id[ ctx->pack_in_idx ] ].dcache_obj_id ].wksp_id ].wksp;
  ctx->pack_in.chunk0 = fd_dcache_compact_chunk0( ctx->stake_in.mem, topo->links[ tile->in_link_id[ ctx->pack_in_idx ] ].dcache );
  ctx->pack_in.wmark  = fd_dcache_compact_wmark ( ctx->stake_in.mem, topo->links[ tile->in_link_id[ ctx->pack_in_idx ] ].dcache, topo->links[ tile->in_link_id[ ctx->pack_in_idx ] ].mtu );

  ctx->shred_out_mem    = topo->workspaces[ topo->objs[ topo->links[ tile->out_link_id[ 0 ] ].dcache_obj_id ].wksp_id ].wksp;
  ctx->shred_out_chunk0 = fd_dcache_compact_chunk0( ctx->shred_out_mem, topo->links[ tile->out_link_id[ 0 ] ].dcache );
  ctx->shred_out_wmark  = fd_dcache_compact_wmark ( ctx->shred_out_mem, topo->links[ tile->out_link_id[ 0 ] ].dcache, topo->links[ tile->out_link_id[ 0 ] ].mtu );
  ctx->shred_out_chunk  = ctx->shred_out_chunk0;

  ctx->pack_out_mcache = topo->links[ tile->out_link_id[ 1 ] ].mcache;
  ctx->pack_out_sync   = fd_mcache_seq_laddr( ctx->pack_out_mcache );
  ctx->pack_out_depth  = fd_mcache_depth( ctx->pack_out_mcache );
  ctx->pack_out_seq    = fd_mcache_seq_query( ctx->pack_out_sync );

  ctx->pack_out_mem    = topo->workspaces[ topo->objs[ topo->links[ tile->out_link_id[ 1 ] ].dcache_obj_id ].wksp_id ].wksp;
  ctx->pack_out_chunk0 = fd_dcache_compact_chunk0( ctx->pack_out_mem, topo->links[ tile->out_link_id[ 1 ] ].dcache );
  ctx->pack_out_wmark  = fd_dcache_compact_wmark ( ctx->pack_out_mem, topo->links[ tile->out_link_id[ 1 ] ].dcache, topo->links[ tile->out_link_id[ 1 ] ].mtu );
  ctx->pack_out_chunk  = ctx->pack_out_chunk0;

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, 1UL );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));
}

/* One tick, one microblock, and one leader update. */
#define STEM_BURST (3UL)

/* See explanation in fd_pack */
#define STEM_LAZY  (128L*3000L)

#define STEM_CALLBACK_CONTEXT_TYPE  fd_poh_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_poh_ctx_t)

#define STEM_CALLBACK_DURING_HOUSEKEEPING during_housekeeping
#define STEM_CALLBACK_AFTER_CREDIT        after_credit
#define STEM_CALLBACK_DURING_FRAG         during_frag
#define STEM_CALLBACK_AFTER_FRAG          after_frag

#include "../../../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_poh_int = {
  .name                     = "pohi",
  .populate_allowed_seccomp = NULL,
  .populate_allowed_fds     = NULL,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};
