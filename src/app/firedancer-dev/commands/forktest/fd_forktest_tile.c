#include "../../../../disco/topo/fd_topo.h"
#include "../../../../disco/fd_disco_base.h"
#include "../../../../discof/fd_startup.h"
#include "../../../../discof/backtest/fd_backtest_src.h"
#include "../../../../discof/replay/fd_replay_tile.h"
#include "../../../../ballet/base58/fd_base58.h"
#include "../../../../ballet/shred/fd_shred.h"
#include "../../../../util/net/fd_net_headers.h"

#include <stdlib.h> /* exit */

#define IN_KIND_REPLAY_EPOCH (0)
#define IN_KIND_TOWER_OUT    (1)
#define IN_KIND_SHRED_NET    (2)
#define IN_KIND_REPLAY_OUT   (3)

#define OUT_IDX_GOSSIP_OUT   (0)
#define OUT_IDX_NET_SHRED    (1)

#define FD_FORKT_DRAIN_PAIRS_MAX (512UL)

#define FD_LOG_WARN_ONCE( args ) \
  do {                           \
    FD_THREAD_ONCE_BEGIN {       \
      FD_LOG_WARNING( args );    \
    } FD_THREAD_ONCE_END;        \
  } while(0)

struct fd_forkt_drain_pair {
  fd_frag_meta_t const * mcache;
  ulong                  depth;
  ulong const *          fseq;
};

typedef struct fd_forkt_drain_pair fd_forkt_drain_pair_t;

struct fd_forkt_in {
  fd_wksp_t * wksp;
  ulong       chunk0;
  ulong       wmark;
  ulong       mtu;
  uint        kind;
};

typedef struct fd_forkt_in fd_forkt_in_t;

struct fd_forkt_out {
  fd_wksp_t * wksp;
  ulong       chunk0;
  ulong       wmark;
  ulong       mtu;
  ulong       chunk;
  ulong       seq;
};

typedef struct fd_forkt_out fd_forkt_out_t;

struct fd_forkt_tile {
  fd_backt_src_t * src;

  uint done : 1;

  ulong  end_slot;
  ushort shred_listen_port;

  ulong idle_cnt;

  fd_forkt_in_t  in [ FD_TOPO_MAX_TILE_IN_LINKS  ];
  fd_forkt_out_t out[ FD_TOPO_MAX_TILE_OUT_LINKS ];

  ulong                 drain_pair_cnt;
  fd_forkt_drain_pair_t drain_pairs[ FD_FORKT_DRAIN_PAIRS_MAX ];
};

typedef struct fd_forkt_tile fd_forkt_tile_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return 128UL;
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_forkt_tile_t), sizeof(fd_forkt_tile_t) );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

static void
on_root_advanced( fd_forkt_tile_t *                 ctx,
                  fd_replay_root_advanced_t const * msg ) {
  ulong slot = msg->slot;
  FD_BASE58_ENCODE_32_BYTES( msg->bank_hash.hash, bank_hash_b58 );
  fd_backt_slot_info_t info;
  if( FD_UNLIKELY( !fd_backtest_src_slot_info( ctx->src, &info, slot ) ) ) {
    FD_LOG_WARN_ONCE(( "cannot validate rooted slot; no slot info in input data" ));
    return;
  }
  if( FD_UNLIKELY( info.dead ) ) {
    FD_LOG_ERR(( "rooted slot %lu, but this slot is dead according to input data", slot ));
  }
  if( FD_UNLIKELY( !info.bank_hash_set ) ) {
    FD_LOG_WARN_ONCE(( "cannot validate bank hash of rooted slot; no bank hash data in input data" ));
    return;
  }
  if( FD_UNLIKELY( memcmp( info.bank_hash.uc, msg->bank_hash.uc, 32UL ) ) ) {
    FD_BASE58_ENCODE_32_BYTES( info.bank_hash.uc, expected_b58 );
    FD_LOG_ERR(( "Bank hash mismatch! slot=%lu expected=%s, got=%s", slot, expected_b58, bank_hash_b58 ));
  }
  FD_LOG_NOTICE(( "Bank hash matches! slot=%lu hash=%-44s", slot, bank_hash_b58 ));
}

static void
on_slot_completed( fd_forkt_tile_t *                  ctx,
                   fd_replay_slot_completed_t const * msg ) {
  if( FD_UNLIKELY( msg->slot>=ctx->end_slot ) ) ctx->done = 1;
}

static void
on_slot_dead( fd_forkt_tile_t *             ctx,
              fd_replay_slot_dead_t const * msg ) {
  fd_backt_slot_info_t info;
  if( FD_LIKELY( fd_backtest_src_slot_info( ctx->src, &info, msg->slot ) ) ) {
    if( FD_UNLIKELY( info.rooted ) ) {
      FD_LOG_ERR(( "dead slot %lu is rooted in source", msg->slot ));
    }
    if( FD_UNLIKELY( info.optimistic_confirmed ) ) {
      FD_LOG_ERR(( "dead slot %lu is optimistically confirmed in source", msg->slot ));
    }
    FD_LOG_NOTICE(( "slot dead %lu ok", msg->slot ));
  } else {
    FD_LOG_NOTICE(( "slot dead %lu (no slot info in source)", msg->slot ));
  }
}

static void
handle_replay_msg( fd_forkt_tile_t * ctx,
                   ulong             sig,
                   void const *      msg_base,
                   ulong             sz ) {
  switch( sig ) {
  case REPLAY_SIG_SLOT_COMPLETED:
    FD_TEST( sz==sizeof(fd_replay_slot_completed_t) );
    on_slot_completed( ctx, msg_base );
    break;
  case REPLAY_SIG_ROOT_ADVANCED:
    FD_TEST( sz==sizeof(fd_replay_root_advanced_t) );
    on_root_advanced( ctx, msg_base );
    break;
  case REPLAY_SIG_SLOT_DEAD:
    FD_TEST( sz==sizeof(fd_replay_slot_dead_t) );
    on_slot_dead( ctx, msg_base );
    break;
  default:
    break;
  }
}

static int
returnable_frag( fd_forkt_tile_t *   ctx,
                 ulong               in_idx,
                 ulong               seq    FD_PARAM_UNUSED,
                 ulong               sig,
                 ulong               chunk,
                 ulong               sz,
                 ulong               ctl    FD_PARAM_UNUSED,
                 ulong               tsorig FD_PARAM_UNUSED,
                 ulong               tspub  FD_PARAM_UNUSED,
                 fd_stem_context_t * stem   FD_PARAM_UNUSED ) {
  ctx->idle_cnt = 0;
  if( FD_UNLIKELY( chunk<ctx->in[ in_idx ].chunk0 || chunk>ctx->in[ in_idx ].wmark || sz>ctx->in[ in_idx ].mtu ) )
    FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->in[ in_idx ].chunk0, ctx->in[ in_idx ].wmark ));
  void const * msg_base = fd_chunk_to_laddr_const( ctx->in[ in_idx ].wksp, chunk );
  switch( ctx->in[ in_idx ].kind ) {
  case IN_KIND_REPLAY_OUT:
    handle_replay_msg( ctx, sig, msg_base, sz );
    break;
  }
  return 0;
}

static void
during_housekeeping( fd_forkt_tile_t * ctx ) {
  if( FD_UNLIKELY( ctx->idle_cnt > (ulong)10e3 ) ) {
    fd_log_sleep( 500e3 ); /* 0.5ms */
  }
}

static void
inject_shred( fd_forkt_tile_t *   ctx,
              fd_stem_context_t * stem,
              uchar *             shred,
              ulong               shred_sz ) {
  if( FD_UNLIKELY( shred_sz+sizeof(fd_ip4_udp_hdrs_t) > FD_NET_MTU ) ) return;

  fd_forkt_out_t * out = &ctx->out[ OUT_IDX_NET_SHRED ];
  uchar * packet = fd_chunk_to_laddr( out->wksp, out->chunk );

  fd_ip4_udp_hdrs_t * hdrs = fd_type_pun( packet );
  fd_ip4_udp_hdr_init( hdrs, shred_sz, 0U, ctx->shred_listen_port );
  hdrs->ip4->daddr     = FD_IP4_ADDR( 127, 0, 0, 1 );
  hdrs->ip4->check     = fd_ip4_hdr_check_fast( hdrs->ip4 );
  hdrs->udp->net_dport = fd_ushort_bswap( ctx->shred_listen_port );

  fd_memcpy( packet + sizeof(fd_ip4_udp_hdrs_t), shred, shred_sz );

  ulong pkt_sz = sizeof(fd_ip4_udp_hdrs_t) + shred_sz;
  ulong sig = fd_disco_netmux_sig( hdrs->ip4->daddr, ctx->shred_listen_port, hdrs->ip4->daddr, DST_PROTO_SHRED, sizeof(fd_ip4_udp_hdrs_t) );
  ulong tspub = fd_frag_meta_ts_comp( fd_tickcount() );
  fd_stem_publish( stem, OUT_IDX_NET_SHRED, sig, out->chunk, pkt_sz, 0UL, 0UL, tspub );

  out->chunk = fd_dcache_compact_next( out->chunk, pkt_sz, out->chunk0, out->wmark );
  out->seq   = fd_seq_inc( out->seq, 1UL );
}

static void
after_credit( fd_forkt_tile_t *   ctx,
              fd_stem_context_t * stem,
              int *               opt_poll_in,
              int *               charge_busy ) {
  (void)opt_poll_in;
  if( ctx->idle_cnt++ < 4UL ) return;
  if( FD_UNLIKELY( ctx->done ) ) return;
  uchar shred[ FD_SHRED_MAX_SZ ];
  ulong shred_sz = fd_backtest_src_shred( ctx->src, shred, sizeof(shred) );
  if( FD_UNLIKELY( shred_sz==ULONG_MAX ) ) {
    ctx->done = 1;
    return;
  }
  FD_TEST( shred_sz<=sizeof(shred) );
  fd_shred_t const * parsed = fd_shred_parse( shred, shred_sz );
  if( FD_UNLIKELY( parsed && parsed->slot > ctx->end_slot ) ) return;
  inject_shred( ctx, stem, shred, shred_sz );
  *charge_busy = 1;
}

static int
should_shutdown( fd_forkt_tile_t const * ctx ) {
  if( FD_LIKELY( !ctx->done ) ) return 0;
  if( FD_LIKELY( ctx->idle_cnt < (ulong)1e6 ) ) return 0;

  for( ulong i=0UL; i<ctx->drain_pair_cnt; i++ ) {
    fd_forkt_drain_pair_t const * pair = &ctx->drain_pairs[ i ];
    ulong fseq_val = fd_fseq_query( pair->fseq );
    if( FD_UNLIKELY( fseq_val==(ULONG_MAX-1UL) ) ) continue;

    /* overran? */
    ulong seq_found = fd_mcache_query( pair->mcache, pair->depth, fseq_val );
    if( FD_UNLIKELY( !fd_seq_lt( seq_found, fseq_val ) ) ) return 0;

    /* newer frag? */
    ulong fseq_next  = fd_seq_inc( fseq_val, 1UL );
    ulong seq_found1 = fd_mcache_query( pair->mcache, pair->depth, fseq_next );
    if( FD_UNLIKELY( !fd_seq_lt( seq_found1, fseq_next ) ) ) return 0;
  }

  FD_LOG_NOTICE(( "all shreds processed, exiting" ));
  exit( 0 );
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( l, scratch );

  fd_forkt_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_forkt_tile_t), sizeof(fd_forkt_tile_t) );
  fd_memset( ctx, 0, sizeof(fd_forkt_tile_t) );

  struct fd_backtest_src_opts src_opts = {
    .path        = tile->forktest.ledger_path,
    .format      = tile->forktest.ledger_format,
    .code_shreds = 1
  };
  ctx->src = fd_backtest_src_create( &src_opts );
  if( FD_UNLIKELY( !ctx->src ) ) FD_LOG_ERR(( "failed to start forkt" ));

  ctx->shred_listen_port = tile->forktest.shred_listen_port;
  ctx->end_slot          = tile->forktest.end_slot ? tile->forktest.end_slot : ULONG_MAX;

  FD_TEST( tile->in_cnt<=FD_TOPO_MAX_TILE_IN_LINKS  );
  FD_TEST( tile->out_cnt<=FD_TOPO_MAX_TILE_OUT_LINKS );

  for( ulong i=0UL; i<tile->in_cnt; i++ ) {
    fd_topo_link_t * link = &topo->links[ tile->in_link_id[ i ] ];
    fd_topo_wksp_t * link_wksp = &topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ];

    if     ( FD_LIKELY( !strcmp( link->name, "replay_epoch" ) ) ) ctx->in[ i ].kind = IN_KIND_REPLAY_EPOCH;
    else if( FD_LIKELY( !strcmp( link->name, "tower_out"    ) ) ) ctx->in[ i ].kind = IN_KIND_TOWER_OUT;
    else if( FD_LIKELY( !strcmp( link->name, "shred_net"    ) ) ) ctx->in[ i ].kind = IN_KIND_SHRED_NET;
    else if( FD_LIKELY( !strcmp( link->name, "replay_out"   ) ) ) ctx->in[ i ].kind = IN_KIND_REPLAY_OUT;
    else FD_LOG_ERR(( "forkt tile has unexpected input link %lu %s", i, link->name ));

    if( FD_LIKELY( link->mtu ) ) {
      ctx->in[ i ].wksp   = link_wksp->wksp;
      ctx->in[ i ].mtu    = link->mtu;
      ctx->in[ i ].chunk0 = fd_dcache_compact_chunk0( ctx->in[ i ].wksp, link->dcache );
      ctx->in[ i ].wmark  = fd_dcache_compact_wmark ( ctx->in[ i ].wksp, link->dcache, link->mtu );
    }
  }

  for( ulong i=0UL; i<tile->out_cnt; i++ ) {
    fd_topo_link_t * out_link = &topo->links[ tile->out_link_id[ i ] ];
    fd_topo_wksp_t * out_wksp = &topo->workspaces[ topo->objs[ out_link->dcache_obj_id ].wksp_id ];

    if     ( FD_LIKELY( !strcmp( out_link->name, "gossip_out" ) ) ) FD_TEST( i==OUT_IDX_GOSSIP_OUT );
    else if( FD_LIKELY( !strcmp( out_link->name, "net_shred"  ) ) ) FD_TEST( i==OUT_IDX_NET_SHRED   );
    else FD_LOG_ERR(( "forkt tile has unexpected output link %lu %s", i, out_link->name ));

    ctx->out[ i ].wksp   = out_wksp->wksp;
    ctx->out[ i ].mtu    = out_link->mtu;
    ctx->out[ i ].chunk0 = fd_dcache_compact_chunk0( ctx->out[ i ].wksp, out_link->dcache );
    ctx->out[ i ].wmark  = fd_dcache_compact_wmark ( ctx->out[ i ].wksp, out_link->dcache, out_link->mtu );
    ctx->out[ i ].chunk  = ctx->out[ i ].chunk0;
    ctx->out[ i ].seq    = 0UL;
  }
  FD_TEST( ctx->out[ OUT_IDX_NET_SHRED ].wksp );

  /* Enumerate all (consumer tile, input link) pairs in the topology for
     drain detection.  For each polled input, store the link's mcache,
     depth, and the consumer's fseq so should_shutdown can probe them. */

  ctx->drain_pair_cnt = 0UL;
  for( ulong i=0UL; i<topo->tile_cnt; i++ ) {
    fd_topo_tile_t * t = &topo->tiles[ i ];
    for( ulong j=0UL; j<t->in_cnt; j++ ) {
      if( !t->in_link_poll[ j ] ) continue; /* unpolled => no fseq tracking */

      fd_topo_link_t * link = &topo->links[ t->in_link_id[ j ] ];
      ulong * fseq = fd_fseq_join( fd_topo_obj_laddr( topo, t->in_link_fseq_obj_id[ j ] ) );
      FD_TEST( fseq );
      FD_TEST( link->mcache );
      FD_TEST( ctx->drain_pair_cnt<FD_FORKT_DRAIN_PAIRS_MAX );

      ctx->drain_pairs[ ctx->drain_pair_cnt++ ] = (fd_forkt_drain_pair_t){
        .mcache = link->mcache,
        .depth  = fd_mcache_depth( link->mcache ),
        .fseq   = fseq,
      };
    }
  }

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, 1UL );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));

  fd_sleep_until_replay_started( topo );
}

#define STEM_BURST (1UL)
#define STEM_CALLBACK_CONTEXT_TYPE        fd_forkt_tile_t
#define STEM_CALLBACK_CONTEXT_ALIGN       alignof(fd_forkt_tile_t)
#define STEM_CALLBACK_AFTER_CREDIT        after_credit
#define STEM_CALLBACK_RETURNABLE_FRAG     returnable_frag
#define STEM_CALLBACK_DURING_HOUSEKEEPING during_housekeeping
#define STEM_CALLBACK_SHOULD_SHUTDOWN     should_shutdown
#include "../../../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_forktest = {
  .name              = "forkt",
  .scratch_align     = scratch_align,
  .scratch_footprint = scratch_footprint,
  .unprivileged_init = unprivileged_init,
  .run               = stem_run,
};
