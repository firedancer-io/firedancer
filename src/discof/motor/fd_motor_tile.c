#include "../poh/fd_poh.h"
#include "../replay/fd_block_marker.h"
#include "../replay/fd_replay_tile.h"
#include "../../util/pod/fd_pod.h"
#include "../../disco/tiles.h"
#include "../../disco/fd_clock_tile.h"
#include "../../discof/fd_startup.h"
#include <time.h>
#include "generated/fd_motor_tile_seccomp.h"

/* The motor tile replaces the poh tile under Alpenglow.

   Structure of an Alpenglow block:

     header | entries* | footer | alpentick

   PoH is no longer relevant in the Alpenglow protocol, but for legacy
   reasons Agave continues to produce PoH-style ticks.  This format is
   validated by Agave or the block will not be accepted, so Firedancer
   is required to do the same.

   Every entry in the block has num_hashes==1.  A transaction entry
   hashes sha256(prev || merkle_root(txn signatures)), where the mixin
   is computed by the execle tile (this is the same as in PoH).  Every
   block concludes with the alpentick, the only tick in the block, which
   as in PoH is sha256(prev) with no mixin.

   The footer requires a bank hash, which replay computes, not motor,
   but the block finishes with the alpentick which motor computes, but
   replay needs in order to compute the bank hash.  The result is a
   circular dance involving delicate coordination between motor and
   replay.

   When pack is done, motor hashes the alpentick and sends it to replay
   in the slot ended message.  Replay picks the footer timestamp,
   applies it, computes the bank hash, serializes the footer, and
   publishes the marker bytes back (REPLAY_SIG_LEADER_FOOTER).  Motor
   then sends both the footer and alpentick to shred to finish the
   block. */

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
  fd_poh_t  poh[1];
  fd_hash_t poh_hash; /* alpenglow retains remnants of poh... see top-level documentation  */

  uint expect_pack_idx; /* see long comment in fd_poh_tile */

  /* Replay only ever resets us to the parent of the block we are about
     to produce, and publishes the reset immediately before became
     leader, so the reset is latched straight into the parent. */
  ulong     slot;
  ulong     parent_slot;
  fd_hash_t parent_cmr; /* what the shred tile chains our block off */
  fd_hash_t parent_dmr; /* what the block header names its parent by */
  fd_hash_t parent_alpentick;

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

/* batch_payload returns the payload of the entry batch frag motor is
   about to publish.  The caller writes at most
   FD_POH_SHRED_MTU-sizeof(fd_entry_batch_meta_t) bytes there and then
   calls publish_batch. */

static inline uchar *
batch_payload( fd_motor_tile_t * ctx ) {
  return (uchar *)fd_chunk_to_laddr( ctx->shred_out->mem, ctx->shred_out->chunk )+sizeof(fd_entry_batch_meta_t);
}

static void
publish_batch( fd_motor_tile_t *   ctx,
               fd_stem_context_t * stem,
               ulong               payload_sz,
               int                 block_complete ) {
  fd_entry_batch_meta_t * meta = fd_chunk_to_laddr( ctx->shred_out->mem, ctx->shred_out->chunk );
  meta->parent_offset  = ctx->slot-ctx->parent_slot;
  meta->reference_tick = 0UL; /* Alpenglow blocks have no tick schedule */
  meta->block_complete = block_complete;

  /* The shred tile chains the block off this, but only for the first
     frag of the slot. */
  meta->parent_block_id_valid = 1;
  fd_memcpy( meta->parent_block_id, ctx->parent_cmr.uc, sizeof(fd_hash_t) );

  ulong sz    = sizeof(fd_entry_batch_meta_t)+payload_sz;
  ulong sig   = fd_disco_poh_sig( ctx->slot, POH_PKT_TYPE_MICROBLOCK, 0UL );
  ulong tspub = (ulong)fd_frag_meta_ts_comp( fd_tickcount() );
  fd_stem_publish( stem, ctx->shred_out->idx, sig, ctx->shred_out->chunk, sz, 0UL, 0UL, tspub );
  ctx->shred_out->chunk = fd_dcache_compact_next( ctx->shred_out->chunk, sz, ctx->shred_out->chunk0, ctx->shred_out->wmark );
}

/* publish_entry publishes one transaction entry, hashing the merkle
   root of the transaction signatures into the entry chain.  An entry
   with no transactions in it would be a tick, and the alpentick is the
   only tick in an Alpenglow block, so microblocks where nothing
   executed successfully are dropped rather than published. */

static void
publish_entry( fd_motor_tile_t *   ctx,
               fd_stem_context_t * stem,
               uchar const *       mixin,
               ulong               txn_cnt,
               fd_txn_p_t const *  txns ) {
  ulong executed_txn_cnt = 0UL;
  for( ulong i=0UL; i<txn_cnt; i++ ) executed_txn_cnt += !!(txns[ i ].flags & FD_TXN_P_FLAGS_EXECUTE_SUCCESS);
  if( FD_UNLIKELY( !executed_txn_cnt ) ) return;

  uchar data[ 64 ];
  fd_memcpy( data,      ctx->poh_hash.uc, sizeof(fd_hash_t) );
  fd_memcpy( data+32UL, mixin,        sizeof(fd_hash_t) );
  fd_sha256_hash( data, sizeof(data), ctx->poh_hash.uc );

  fd_entry_batch_header_t * entry = (fd_entry_batch_header_t *)batch_payload( ctx );
  entry->hashcnt_delta = 1UL; /* every Alpenglow entry has num_hashes==1 */
  entry->txn_cnt       = executed_txn_cnt;
  fd_memcpy( entry->hash, ctx->poh_hash.uc, sizeof(fd_hash_t) );

  uchar * payload    = (uchar *)(entry+1UL);
  ulong   payload_sz = 0UL;
  for( ulong i=0UL; i<txn_cnt; i++ ) {
    fd_txn_p_t const * txn = txns + i;
    if( FD_UNLIKELY( !(txn->flags & FD_TXN_P_FLAGS_EXECUTE_SUCCESS) ) ) continue;

    fd_memcpy( payload+payload_sz, txn->payload, txn->payload_sz );
    payload_sz += txn->payload_sz;
  }

  publish_batch( ctx, stem, sizeof(fd_entry_batch_header_t)+payload_sz, 0 );
}

static void
begin_leader_slot( fd_motor_tile_t *          ctx,
                   fd_stem_context_t *        stem,
                   fd_became_leader_t const * became_leader ) {
  FD_TEST( ctx->slot==ULONG_MAX );
  if( FD_UNLIKELY( ctx->parent_slot==ULONG_MAX ) ) FD_LOG_ERR(( "became leader for slot %lu before any reset", became_leader->slot ));
  FD_TEST( became_leader->slot>ctx->parent_slot );

  ctx->slot     = became_leader->slot;
  ctx->poh_hash = ctx->parent_alpentick;

  /* The header must be the first frag of the slot.  It names its parent
     by double merkle root, which is the namespace votor and the
     certificates use, not by the chained merkle root that parent_cmr
     carries and the shred tile chains our own shreds off. */
  fd_block_marker_t marker[1];
  marker->variant                = HEADER;
  marker->header.parent_slot     = ctx->parent_slot;
  marker->header.parent_block_id = ctx->parent_dmr;

  ulong marker_sz;
  int err = fd_block_marker_ser( marker,
                                 batch_payload( ctx ),
                                 FD_POH_SHRED_MTU-sizeof(fd_entry_batch_meta_t),
                                 &marker_sz );
  if( FD_UNLIKELY( err ) ) FD_LOG_ERR(( "fd_block_marker_ser(HEADER) failed (%d)", err ));

  publish_batch( ctx, stem, marker_sz, -1 );
}

/* end_leader_slot is the first half of ending the block: all of the
   transaction entries have been published, so motor closes the entry
   chain with the alpentick hash and tells replay to finish the bank.
   Nothing is published to shred until the footer comes back.  A block
   pack abandoned is instead handed back incomplete, exactly as the poh
   tile does, so that replay releases the leader bank; the alpentick was
   never published so no slot complete FEC set will ever arrive. */

static void
end_leader_slot( fd_motor_tile_t *         ctx,
                 fd_stem_context_t *       stem,
                 fd_done_packing_t const * done_packing ) {
  int completed = done_packing->end_slot_reason!=FD_PACK_END_SLOT_REASON_ABANDONED;

  /* The alpentick is a tick, so it mixes nothing in and its hash is
     known before it is published. */
  if( FD_LIKELY( completed ) ) fd_sha256_hash( ctx->poh_hash.uc, sizeof(fd_hash_t), ctx->poh_hash.uc );

  fd_poh_leader_slot_ended_t * dst = fd_chunk_to_laddr( ctx->replay_out->mem, ctx->replay_out->chunk );
  fd_memset( dst, 0, sizeof(fd_poh_leader_slot_ended_t) );
  dst->completed        = completed;
  dst->slot             = ctx->slot;
  dst->timing_table_idx = ULONG_MAX;
  fd_memcpy( dst->blockhash, ctx->poh_hash.uc, sizeof(fd_hash_t) );

  dst->microblock_count = done_packing->microblocks_in_slot;
  dst->pack_block_cost  = done_packing->limits_usage->block_cost;
  dst->pack_vote_cost   = done_packing->limits_usage->vote_cost;
  dst->pack_data_bytes  = done_packing->limits_usage->block_data_bytes;
  dst->bundle_txn_count = done_packing->bundle_txn_count;
  dst->pack_end_reason  = done_packing->end_slot_reason;
  dst->pack_start_ns    = done_packing->pack_start_ns;
  dst->pack_end_ns      = done_packing->pack_end_ns;

  ulong tspub = (ulong)fd_frag_meta_ts_comp( fd_tickcount() );
  fd_stem_publish( stem, ctx->replay_out->idx, 0UL, ctx->replay_out->chunk, sizeof(fd_poh_leader_slot_ended_t), 0UL, 0UL, tspub );
  ctx->replay_out->chunk = fd_dcache_compact_next( ctx->replay_out->chunk, sizeof(fd_poh_leader_slot_ended_t), ctx->replay_out->chunk0, ctx->replay_out->wmark );

  if( FD_UNLIKELY( !completed ) ) ctx->slot = ULONG_MAX;
}

/* complete_leader_slot is the second half: replay serialized the
   footer, so motor forwards the marker bytes verbatim, and the
   alpentick closes the block. */

static void
complete_leader_slot( fd_motor_tile_t *                 ctx,
                      fd_stem_context_t *               stem,
                      fd_replay_leader_footer_t const * footer ) {
  FD_TEST( footer->slot==ctx->slot );
  FD_TEST( footer->sz  >=sizeof(fd_entry_batch_header_t) && footer->sz<=FD_REPLAY_LEADER_FOOTER_MAX );

  /* publish footer */

  fd_memcpy( batch_payload( ctx ), footer->footer, footer->sz );
  publish_batch( ctx, stem, footer->sz, -1 );

  /* publish alpentick */

  fd_entry_batch_header_t * entry = (fd_entry_batch_header_t *)batch_payload( ctx );
  entry->hashcnt_delta            = 1UL;
  entry->txn_cnt                  = 0UL;
  fd_memcpy( entry->hash, ctx->poh_hash.uc, sizeof(fd_hash_t) );
  publish_batch( ctx, stem, sizeof(fd_entry_batch_header_t), 1 );

  /* mark done */

  ctx->slot = ULONG_MAX;
}

static int
before_frag( fd_motor_tile_t * ctx,
             ulong             in_idx,
             ulong             seq FD_PARAM_UNUSED,
             ulong             sig ) {
  if( FD_LIKELY( ctx->in_kind[ in_idx ]==IN_KIND_REPLAY ) )
    return sig!=REPLAY_SIG_RESET && sig!=REPLAY_SIG_BECAME_LEADER && sig!=REPLAY_SIG_WFS_DONE &&
           sig!=REPLAY_SIG_LEADER_FOOTER;

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

  fd_startup_gate_busy( ctx->startup_gate );

  if( FD_UNLIKELY( sig==FD_PACK_MSG_DONE_DRAINING && ctx->in_kind[ in_idx ]==IN_KIND_PACK ) ) {
    ctx->idle_cnt = 0UL;
    return 0;
  }

  if( FD_UNLIKELY( sig==FD_PACK_MSG_REDUCE_MB_BOUND && ctx->in_kind[ in_idx ]==IN_KIND_PACK ) ) {
    ctx->idle_cnt = 0UL;
    return 0;
  }

  if( FD_UNLIKELY( sig==REPLAY_SIG_WFS_DONE && ctx->in_kind[ in_idx ]==IN_KIND_REPLAY ) ) {
    ctx->idle_cnt = 0UL;
    return 0;
  }

  if( FD_UNLIKELY( chunk<ctx->in[ in_idx ].chunk0 || chunk>ctx->in[ in_idx ].wmark || sz>ctx->in[ in_idx ].mtu ) )
    FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->in[ in_idx ].chunk0, ctx->in[ in_idx ].wmark ));

  if( FD_UNLIKELY( ( ctx->in_kind[ in_idx ]==IN_KIND_EXECLE || ctx->in_kind[ in_idx ]==IN_KIND_PACK ) && ctx->slot==ULONG_MAX ) ) return 1;

  if( FD_UNLIKELY( ctx->in_kind[ in_idx ]==IN_KIND_REPLAY && sig!=REPLAY_SIG_LEADER_FOOTER && ctx->slot!=ULONG_MAX ) ) return 1;

  if( FD_LIKELY( ctx->in_kind[ in_idx ]==IN_KIND_EXECLE || ctx->in_kind[ in_idx ]==IN_KIND_PACK ) ) {
    uint pack_idx = (uint)fd_disco_execle_sig_pack_idx( sig );
    if( FD_UNLIKELY( ((int)(pack_idx-ctx->expect_pack_idx))<0L ) ) FD_LOG_ERR(( "received out of order pack_idx %u (expecting %u)", pack_idx, ctx->expect_pack_idx ));
    if( FD_UNLIKELY( pack_idx!=ctx->expect_pack_idx ) ) return 1;
    ctx->expect_pack_idx++;
  }

  switch( ctx->in_kind[ in_idx ] ) {
    case IN_KIND_REPLAY: {
      if( FD_UNLIKELY( sig==REPLAY_SIG_BECAME_LEADER ) ) {
        fd_became_leader_t const * became_leader = fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, chunk );
        begin_leader_slot( ctx, stem, became_leader );
      } else if( FD_UNLIKELY( sig==REPLAY_SIG_LEADER_FOOTER ) ) {
        fd_replay_leader_footer_t const * footer = fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, chunk );
        complete_leader_slot( ctx, stem, footer );
      } else if( FD_LIKELY( sig==REPLAY_SIG_RESET ) ) {
        FD_TEST( ctx->slot==ULONG_MAX ); /* currently do not support mid-block resets in Alpenglow */
        fd_poh_reset_t const * reset = fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, chunk );
        ctx->parent_slot = reset->completed_slot;
        fd_memcpy( ctx->parent_cmr.uc,       reset->completed_cmr,       sizeof(fd_hash_t) );
        fd_memcpy( ctx->parent_dmr.uc,       reset->completed_dmr,       sizeof(fd_hash_t) );
        fd_memcpy( ctx->parent_alpentick.uc, reset->completed_blockhash, sizeof(fd_hash_t) );
      }
      break;
    }
    case IN_KIND_PACK: {
      fd_done_packing_t const * done_packing = fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, chunk );
      FD_TEST( fd_disco_execle_sig_slot( sig )==ctx->slot );
      end_leader_slot( ctx, stem, done_packing );
      break;
    }
    case IN_KIND_EXECLE: {
      FD_TEST( fd_disco_execle_sig_slot( sig )==ctx->slot );
      FD_TEST( sz>=sizeof(fd_microblock_trailer_t) && (sz-sizeof(fd_microblock_trailer_t))%sizeof(fd_txn_p_t)==0UL );
      ulong txn_cnt = (sz-sizeof(fd_microblock_trailer_t))/sizeof(fd_txn_p_t);
      fd_txn_p_t const * txns = fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, chunk );
      fd_microblock_trailer_t const * trailer = fd_type_pun_const( (uchar const *)txns+sz-sizeof(fd_microblock_trailer_t) );
      publish_entry( ctx, stem, trailer->hash, txn_cnt, txns );
      break;
    }
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

  ctx->expect_pack_idx = 0U;
  ctx->parent_slot     = ULONG_MAX;
  ctx->slot            = ULONG_MAX;

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

/* The footer and the alpentick, or one entry batch, or one slot ended
   message */
#define STEM_BURST (2UL)

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
