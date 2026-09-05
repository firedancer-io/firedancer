#include "../poh/fd_poh.h"
#include "../replay/fd_block_marker.h"
#include "../replay/fd_replay_tile.h"
#include "../../disco/tiles.h"
#include "../../discof/fd_startup.h"
#include "../../util/pod/fd_pod.h"
#include <time.h> /* CLOCK_REALTIME for the startup gate seccomp policy */
#include "generated/fd_motor_tile_seccomp.h"

/* The motor tile replaces the poh tile under Alpenglow.

   Structure of an Alpenglow block:

     header | entries* | footer | alpentick

   Every block begins with a header, which contains the parent slot and
   parent block hash.  The header is serialized and sent to shred, which
   produces an entire entry batch (a fixed-32 shred FEC set) containing
   exclusively those two fields (the remainder is padding).

   Following the header are entries.  As in PoH, each entry is sent to
   shred which groups into entry batches that divide into FEC sets.
   Unlike in PoH, entries cannot be interleaved with ticks.  Every entry
   in the block has num_hashes==1.  A transaction entry hashes
   sha256(prev || merkle_root(txn signatures)), where the mixin is
   computed by the execle tile (again, this is the same as in PoH).

   Next is the footer, which contains various fields, most notably the
   bank hash.  The various fields in the footer feed into the bank hash
   itself, resulting in a sequential and somewhat circular dependency
   to construct the footer.

   Every block concludes with the alpentick, the only tick in the block,
   which as in PoH is sha256(prev) with no mixin.  PoH is not a
   component of the Alpenglow protocol, but for legacy reasons Agave
   continues to produce a PoH-style tick at the very end of a block.
   This format is validated by Agave or the block will not be accepted,
   so Firedancer is required to do the same.

   Currently, the motor tile computes the alpentick, but
   replay needs in order to compute the bank hash.  The result is a
   circular dance involving delicate coordination between motor and
   replay.

   When pack is done, motor hashes the alpentick and sends it to replay
   in the slot ended message.  Replay picks the footer timestamp and
   certs, applies them, computes the bank hash, and publishes the footer
   fields back (REPLAY_SIG_LEADER_FOOTER).  Motor then serializes the
   footer and sends it and the alpentick to shred to finish the block. */

#define IN_KIND_REPLAY (0)
#define IN_KIND_PACK   (1)
#define IN_KIND_EXECLE (2)

struct fd_motor_in {
  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
  ulong       mtu;
};
typedef struct fd_motor_in fd_motor_in_t;

struct fd_motor_tile {

  /* Alpenglow-specific */

  ulong     slot;
  ulong     parent_slot;
  fd_hash_t parent_cmr; /* required by shred to produce chained merkle shreds */
  fd_hash_t parent_dmr;
  fd_hash_t parent_alpentick;

  /* Inherited from fd_poh_tile.c */

  fd_hash_t poh_hash;

  uint expect_pack_idx; /* see long comment in fd_poh_tile */

  fd_leader_txn_timing_table_t * timing_tables; /* per-transaction leader timings for the GUI, read by replay */
  ulong                          timing_table_idx;

  fd_startup_gate_t startup_gate[1];

  int in_kind[ 64 ];
  fd_motor_in_t in[ 64 ];

  fd_poh_out_t shred_out[ 1 ];
  fd_poh_out_t replay_out[ 1 ];
};
typedef struct fd_motor_tile fd_motor_tile_t;

static ulong
prepare_header( fd_motor_tile_t * ctx ) {
  fd_block_marker_t marker[1];
  marker->variant                = HEADER;
  marker->header.parent_slot     = ctx->parent_slot;
  marker->header.parent_block_id = ctx->parent_dmr;

  ulong marker_sz;
  int err = fd_block_marker_ser( marker, (uchar *)fd_chunk_to_laddr( ctx->shred_out->mem, ctx->shred_out->chunk )+sizeof(fd_entry_batch_meta_t), FD_POH_SHRED_MTU-sizeof(fd_entry_batch_meta_t), &marker_sz );
  if( FD_UNLIKELY( err ) ) FD_LOG_ERR(( "fd_block_marker_ser(HEADER) failed (%d)", err ));
  return marker_sz;
}

static ulong
prepare_entry( fd_motor_tile_t *               ctx,
               fd_microblock_trailer_t const * trailer,
               ulong                           txn_cnt,
               fd_txn_p_t const *              txns ) {
  ulong executed_txn_cnt = 0UL;
  for( ulong i=0UL; i<txn_cnt; i++ ) executed_txn_cnt += !!(txns[ i ].flags & FD_TXN_P_FLAGS_EXECUTE_SUCCESS);
  if( FD_UNLIKELY( !executed_txn_cnt ) ) return 0UL;

  if( FD_LIKELY( ctx->timing_tables ) ) {
    fd_leader_txn_timing_table_t * table = &ctx->timing_tables[ ctx->timing_table_idx ];
    long mixed_ticks = fd_tickcount();
    for( ulong i=0UL; i<txn_cnt && table->cnt<FD_MAX_TXN_PER_SLOT; i++ ) {
      if( FD_UNLIKELY( !(txns[ i ].flags & FD_TXN_P_FLAGS_EXECUTE_SUCCESS) ) ) continue;
      table->rec[ table->cnt++ ] = (fd_leader_txn_timing_rec_t){
        .received_ns      = txns[ i ].first_seen_nanos,
        .dispatched_ticks = trailer->exec_start_ticks,
        .replayed_ticks   = trailer->exec_end_ticks,
        .poh_mixed_ticks  = mixed_ticks,
      };
    }
  }

  uchar data[ 64 ];
  memcpy( data,      ctx->poh_hash.uc, sizeof(fd_hash_t) );
  memcpy( data+32UL, trailer->hash,    sizeof(fd_hash_t) );
  fd_sha256_hash( data, sizeof(data), ctx->poh_hash.uc );

  fd_entry_batch_header_t * entry = (fd_entry_batch_header_t *)((uchar *)fd_chunk_to_laddr( ctx->shred_out->mem, ctx->shred_out->chunk )+sizeof(fd_entry_batch_meta_t));
  entry->hashcnt_delta            = 1UL; /* every Alpenglow entry has num_hashes==1 */
  entry->txn_cnt                  = executed_txn_cnt;
  memcpy( entry->hash, ctx->poh_hash.uc, sizeof(fd_hash_t) );

  uchar * payload    = (uchar *)(entry+1UL);
  ulong   payload_sz = 0UL;
  for( ulong i=0UL; i<txn_cnt; i++ ) {
    fd_txn_p_t const * txn = txns + i;
    if( FD_UNLIKELY( !(txn->flags & FD_TXN_P_FLAGS_EXECUTE_SUCCESS) ) ) continue;

    fd_memcpy( payload+payload_sz, txn->payload, txn->payload_sz );
    payload_sz += txn->payload_sz;
  }

  return sizeof(fd_entry_batch_header_t)+payload_sz;
}

static ulong
prepare_footer( fd_motor_tile_t *                 ctx,
                fd_replay_leader_footer_t const * footer ) {
  fd_block_marker_t marker[1];
  marker->variant = FOOTER;
  marker->footer  = footer->footer;

  ulong marker_sz;
  int err = fd_block_marker_ser( marker, (uchar *)fd_chunk_to_laddr( ctx->shred_out->mem, ctx->shred_out->chunk )+sizeof(fd_entry_batch_meta_t), FD_POH_SHRED_MTU-sizeof(fd_entry_batch_meta_t), &marker_sz );
  if( FD_UNLIKELY( err ) ) FD_LOG_ERR(( "fd_block_marker_ser(FOOTER) failed (%d)", err ));
  return marker_sz;
}

static ulong
prepare_alpentick( fd_motor_tile_t * ctx ) {
  fd_entry_batch_header_t * entry = (fd_entry_batch_header_t *)((uchar *)fd_chunk_to_laddr( ctx->shred_out->mem, ctx->shred_out->chunk )+sizeof(fd_entry_batch_meta_t));
  entry->hashcnt_delta            = 1UL;
  entry->txn_cnt                  = 0UL;
  memcpy( entry->hash, ctx->poh_hash.uc, sizeof(fd_hash_t) );

  return sizeof(fd_entry_batch_header_t);
}

static void
publish_shred( fd_motor_tile_t *   ctx,
               fd_stem_context_t * stem,
               ulong               payload_sz,
               int                 block_complete ) {
  fd_entry_batch_meta_t * meta = fd_chunk_to_laddr( ctx->shred_out->mem, ctx->shred_out->chunk );
  meta->parent_offset          = ctx->slot - ctx->parent_slot;
  meta->reference_tick         = 0UL; /* Alpenglow blocks have no tick schedule */
  meta->block_complete         = block_complete;

  memcpy( meta->parent_block_id, ctx->parent_cmr.uc, sizeof(fd_hash_t) );
  meta->parent_block_id_valid = 1;

  ulong sz    = sizeof(fd_entry_batch_meta_t)+payload_sz;
  ulong sig   = fd_disco_poh_sig( ctx->slot, POH_PKT_TYPE_MICROBLOCK, 0UL );
  ulong tspub = (ulong)fd_frag_meta_ts_comp( fd_tickcount() );
  fd_stem_publish( stem, ctx->shred_out->idx, sig, ctx->shred_out->chunk, sz, 0UL, 0UL, tspub );
  ctx->shred_out->chunk = fd_dcache_compact_next( ctx->shred_out->chunk, sz, ctx->shred_out->chunk0, ctx->shred_out->wmark );
}

static void
init_block( fd_motor_tile_t *          ctx,
            fd_stem_context_t *        stem,
            fd_became_leader_t const * became_leader ) {
  ctx->slot     = became_leader->slot;
  ctx->poh_hash = ctx->parent_alpentick;

  if( FD_LIKELY( ctx->timing_tables ) ) {
    ctx->timing_table_idx ^= 1UL;
    fd_leader_txn_timing_table_t * table = &ctx->timing_tables[ ctx->timing_table_idx ];
    table->slot = ctx->slot;
    table->cnt  = 0UL;
  }

  publish_shred( ctx, stem, prepare_header( ctx ), -1 );
}

static void
done_packing( fd_motor_tile_t *         ctx,
              fd_stem_context_t *       stem,
              fd_done_packing_t const * msg ) {

  fd_sha256_hash( ctx->poh_hash.uc, sizeof(fd_hash_t), ctx->poh_hash.uc ); /* alpentick */

  fd_poh_leader_slot_ended_t * dst = fd_chunk_to_laddr( ctx->replay_out->mem, ctx->replay_out->chunk );
  fd_memset( dst, 0, sizeof(fd_poh_leader_slot_ended_t) );
  dst->completed        = 1;
  dst->slot             = ctx->slot;
  dst->timing_table_idx = ctx->timing_table_idx;
  memcpy( dst->blockhash, ctx->poh_hash.uc, sizeof(fd_hash_t) ); /* write the "alpentick" to the existing blockhash field */

  dst->microblock_count = msg->microblocks_in_slot;
  dst->pack_block_cost  = msg->limits_usage->block_cost;
  dst->pack_vote_cost   = msg->limits_usage->vote_cost;
  dst->pack_data_bytes  = msg->limits_usage->block_data_bytes;
  dst->bundle_txn_count = msg->bundle_txn_count;
  dst->pack_end_reason  = msg->end_slot_reason;
  dst->pack_start_ns    = msg->pack_start_ns;
  dst->pack_end_ns      = msg->pack_end_ns;

  /* publish alpentick to replay */

  ulong tspub = (ulong)fd_frag_meta_ts_comp( fd_tickcount() );
  fd_stem_publish( stem, ctx->replay_out->idx, 0UL, ctx->replay_out->chunk, sizeof(fd_poh_leader_slot_ended_t), 0UL, 0UL, tspub );
  ctx->replay_out->chunk = fd_dcache_compact_next( ctx->replay_out->chunk, sizeof(fd_poh_leader_slot_ended_t), ctx->replay_out->chunk0, ctx->replay_out->wmark );
}

static void
fini_block( fd_motor_tile_t *                 ctx,
            fd_stem_context_t *               stem,
            fd_replay_leader_footer_t const * footer ) {
  publish_shred( ctx, stem, prepare_footer( ctx, footer ), -1 );
  publish_shred( ctx, stem, prepare_alpentick( ctx ), 1 );
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
after_credit( fd_motor_tile_t *   ctx,
              fd_stem_context_t * stem,
              int *               opt_poll_in,
              int *               charge_busy ) {
  (void)stem;
  (void)opt_poll_in;
  (void)charge_busy;

  fd_startup_gate_idle( ctx->startup_gate );
}

static int
before_frag( fd_motor_tile_t * ctx,
             ulong             in_idx,
             ulong             seq FD_PARAM_UNUSED,
             ulong             sig ) {
  switch( ctx->in_kind[ in_idx ] ) {
  case IN_KIND_REPLAY: return !( sig==REPLAY_SIG_RESET         ||
                                 sig==REPLAY_SIG_BECAME_LEADER ||
                                 sig==REPLAY_SIG_LEADER_FOOTER );
  case IN_KIND_PACK:   return fd_disco_execle_sig_slot( sig )!=ctx->slot; /* done packing is the only pack frag that names our slot */
  case IN_KIND_EXECLE: return fd_disco_execle_sig_slot( sig )!=ctx->slot; /* microblocks of our block */
  default:             return 1;
  }
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

  if( FD_UNLIKELY( chunk<ctx->in[ in_idx ].chunk0 || chunk>ctx->in[ in_idx ].wmark || sz>ctx->in[ in_idx ].mtu ) )
    FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->in[ in_idx ].chunk0, ctx->in[ in_idx ].wmark ));

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
        init_block( ctx, stem, became_leader );
      } else if( FD_UNLIKELY( sig==REPLAY_SIG_LEADER_FOOTER ) ) {
        fd_replay_leader_footer_t const * footer = fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, chunk );
        fini_block( ctx, stem, footer );
      } else if( FD_LIKELY( sig==REPLAY_SIG_RESET ) ) {
        fd_poh_reset_t const * reset = fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, chunk );
        ctx->parent_slot = reset->completed_slot;
        memcpy( ctx->parent_cmr.uc,       reset->completed_cmr,       sizeof(fd_hash_t) );
        memcpy( ctx->parent_dmr.uc,       reset->completed_dmr,       sizeof(fd_hash_t) );
        memcpy( ctx->parent_alpentick.uc, reset->completed_blockhash, sizeof(fd_hash_t) );
      }
      break;
    }
    case IN_KIND_PACK: {
      fd_done_packing_t const * msg = fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, chunk );
      done_packing( ctx, stem, msg );
      break;
    }
    case IN_KIND_EXECLE: {
      FD_TEST( sz>=sizeof(fd_microblock_trailer_t) && (sz-sizeof(fd_microblock_trailer_t))%sizeof(fd_txn_p_t)==0UL );
      ulong txn_cnt = (sz-sizeof(fd_microblock_trailer_t))/sizeof(fd_txn_p_t);
      fd_txn_p_t const * txns = fd_chunk_to_laddr_const( ctx->in[ in_idx ].mem, chunk );
      fd_microblock_trailer_t const * trailer = fd_type_pun_const( (uchar const *)txns+sz-sizeof(fd_microblock_trailer_t) );
      ulong payload_sz = prepare_entry( ctx, trailer, txn_cnt, txns );
      if( FD_LIKELY( payload_sz ) ) publish_shred( ctx, stem, payload_sz, 0 );
      break;
    }
    default: {
      FD_LOG_ERR(( "unexpected input kind %d", ctx->in_kind[ in_idx ] ));
      break;
    }
  }

  return 0;
}

static void
unprivileged_init( fd_topo_t const *      topo,
                   fd_topo_tile_t const * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_motor_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_motor_tile_t ), sizeof( fd_motor_tile_t ) );

  ctx->expect_pack_idx = 0U;

  FD_CHECK_ERR( tile->in_cnt<=sizeof(ctx->in)/sizeof(ctx->in[0]), "too many input links" );

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
    else FD_LOG_ERR(( "unexpected input link name %s", link->name ));
  }

  *ctx->replay_out = out1( topo, tile, "poh_replay" );
  *ctx->shred_out  = out1( topo, tile, "poh_shred"  );

  ulong ldr_tt_obj_id   = fd_pod_query_ulong( topo->props, "ldr_tt", ULONG_MAX );
  ctx->timing_tables    = ldr_tt_obj_id==ULONG_MAX ? NULL : fd_topo_obj_laddr( topo, ldr_tt_obj_id );
  ctx->timing_table_idx = 0UL;

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
