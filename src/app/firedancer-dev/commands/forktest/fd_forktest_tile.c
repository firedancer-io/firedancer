#include "../../../../disco/topo/fd_topo.h"
#include "../../../../disco/fd_disco_base.h"
#include "../../../../discof/fd_startup.h"
#include "../../../../util/net/fd_net_headers.h"
#include <rocksdb/c.h>

#define CF_IDX_DEFAULT 0
#define CF_IDX_META    1
#define CF_IDX_SHRED   2
#define CF_CNT         3

#define IN_KIND_REPLAY_EPOCH (0)
#define IN_KIND_TOWER_OUT    (1)
#define IN_KIND_SHRED_NET    (2)

#define OUT_IDX_GOSSIP_OUT   (0)
#define OUT_IDX_NET_SHRED    (1)

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
  rocksdb_t * db;

  rocksdb_iterator_t * iter_shred;

  rocksdb_column_family_handle_t * cf[ CF_CNT ];

  ushort shred_listen_port;

  fd_forkt_in_t  in [ FD_TOPO_MAX_TILE_IN_LINKS  ];
  fd_forkt_out_t out[ FD_TOPO_MAX_TILE_OUT_LINKS ];
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
inject_shred( fd_forkt_tile_t *   ctx,
              fd_stem_context_t * stem ) {
  size_t val_sz = 0UL;
  char const * val = rocksdb_iter_value( ctx->iter_shred, &val_sz );

  ulong shred_sz = (ulong)val_sz;
  if( FD_UNLIKELY( shred_sz+sizeof(fd_ip4_udp_hdrs_t) > FD_NET_MTU ) ) return;

  fd_forkt_out_t * out = &ctx->out[ OUT_IDX_NET_SHRED ];
  uchar * packet = fd_chunk_to_laddr( out->wksp, out->chunk );

  fd_ip4_udp_hdrs_t * hdrs = fd_type_pun( packet );
  fd_ip4_udp_hdr_init( hdrs, shred_sz, 0U, ctx->shred_listen_port );
  hdrs->ip4->daddr     = FD_IP4_ADDR( 127, 0, 0, 1 );
  hdrs->ip4->check     = fd_ip4_hdr_check_fast( hdrs->ip4 );
  hdrs->udp->net_dport = fd_ushort_bswap( ctx->shred_listen_port );

  fd_memcpy( packet + sizeof(fd_ip4_udp_hdrs_t), val, shred_sz );

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
  if( rocksdb_iter_valid( ctx->iter_shred ) ) {
    inject_shred( ctx, stem );
    *charge_busy = 1;
    rocksdb_iter_next( ctx->iter_shred );
  }
}

static void
rocksdb_init( fd_forkt_tile_t * ctx,
              char const *      path ) {

  static char const * cf_names[ CF_CNT ] = {
    [ CF_IDX_DEFAULT ] = "default",
    [ CF_IDX_META    ] = "meta",
    [ CF_IDX_SHRED   ] = "data_shred"
  };

  rocksdb_options_t * options = rocksdb_options_create();
  if( FD_UNLIKELY( !options ) ) FD_LOG_ERR(( "rocksdb_options_create() failed" ));

  rocksdb_options_t const * cf_options[ CF_CNT ];
  for( ulong i=0UL; i<CF_CNT; i++ ) cf_options[ i ] = options;

  char * err = NULL;
  ctx->db = rocksdb_open_for_read_only_column_families(
      options,
      path,
      CF_CNT,
      cf_names,
      cf_options,
      ctx->cf,
      false,
      &err
  );
  if( FD_UNLIKELY( !ctx->db ) ) FD_LOG_ERR(( "rocksdb_open_for_read_only_column_families(%s) failed: %s", path, err ));

  rocksdb_options_destroy( options );

  rocksdb_readoptions_t * readoptions = rocksdb_readoptions_create();
  if( FD_UNLIKELY( !readoptions ) ) FD_LOG_ERR(( "rocksdb_readoptions_create() failed" ));

  ctx->iter_shred = rocksdb_create_iterator_cf( ctx->db, readoptions, ctx->cf[ CF_IDX_SHRED ] );
  if( FD_UNLIKELY( !ctx->iter_shred ) ) FD_LOG_ERR(( "rocksdb_create_iterator_cf(shred) failed" ));
  rocksdb_iter_seek_to_first( ctx->iter_shred );

  rocksdb_readoptions_destroy( readoptions );
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );
  FD_SCRATCH_ALLOC_INIT( l, scratch );

  fd_forkt_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_forkt_tile_t), sizeof(fd_forkt_tile_t) );
  fd_memset( ctx, 0, sizeof(fd_forkt_tile_t) );

  rocksdb_init( ctx, tile->forktest.rocksdb_path );
  ctx->shred_listen_port = tile->forktest.shred_listen_port;

  FD_TEST( tile->in_cnt<=FD_TOPO_MAX_TILE_IN_LINKS  );
  FD_TEST( tile->out_cnt<=FD_TOPO_MAX_TILE_OUT_LINKS );

  for( ulong i=0UL; i<tile->in_cnt; i++ ) {
    fd_topo_link_t * link = &topo->links[ tile->in_link_id[ i ] ];
    fd_topo_wksp_t * link_wksp = &topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ];

    if     ( FD_LIKELY( !strcmp( link->name, "replay_epoch" ) ) ) ctx->in[ i ].kind = IN_KIND_REPLAY_EPOCH;
    else if( FD_LIKELY( !strcmp( link->name, "tower_out"    ) ) ) ctx->in[ i ].kind = IN_KIND_TOWER_OUT;
    else if( FD_LIKELY( !strcmp( link->name, "shred_net"    ) ) ) ctx->in[ i ].kind = IN_KIND_SHRED_NET;
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

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, 1UL );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));

  fd_sleep_until_replay_started( topo );
}

#define STEM_BURST (1UL)
#define STEM_CALLBACK_CONTEXT_TYPE  fd_forkt_tile_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_forkt_tile_t)
#define STEM_CALLBACK_AFTER_CREDIT  after_credit
#include "../../../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_forktest = {
  .name              = "forkt",
  .scratch_align     = scratch_align,
  .scratch_footprint = scratch_footprint,
  .unprivileged_init = unprivileged_init,
  .run               = stem_run,
};
