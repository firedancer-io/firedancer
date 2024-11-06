#include "../../../../disco/tiles.h"

#include "../../../../disco/metrics/fd_metrics.h"
#include "../../../../disco/bank/fd_bank_abi.h"
#include "../../../../flamenco/types/fd_types.h"
#include "../../../../flamenco/runtime/fd_system_ids.h"

#define FD_RESOLV_IN_KIND_FRAGMENT (0)
#define FD_RESOLV_IN_KIND_BANK     (1)

struct blockhash {
  uchar b[ 32 ];
};

typedef struct blockhash blockhash_t;

struct blockhash_map {
  blockhash_t key;
  ulong       slot;
};

typedef struct blockhash_map blockhash_map_t;

static const blockhash_t null_blockhash = { 0 };

#define MAP_NAME              map
#define MAP_T                 blockhash_map_t
#define MAP_KEY_T             blockhash_t
#define MAP_LG_SLOT_CNT       13UL
#define MAP_KEY_NULL          null_blockhash
#if FD_HAS_AVX
# define MAP_KEY_INVAL(k)     _mm256_testz_si256( wb_ldu( (k).b ), wb_ldu( (k).b ) )
#else
# define MAP_KEY_INVAL(k)     MAP_KEY_EQUAL(k, null_blockhash)
#endif
#define MAP_KEY_EQUAL(k0,k1)  (!memcmp((k0).b,(k1).b, 32UL))
#define MAP_MEMOIZE           0
#define MAP_KEY_EQUAL_IS_SLOW 1
#define MAP_KEY_HASH(key)     fd_uint_load_4( (key).b )
#define MAP_QUERY_OPT         1

#include "../../../../util/tmpl/fd_map.c"

typedef struct {
  int         kind;

  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
  ulong       mtu;
} fd_resolv_in_ctx_t;

typedef struct {
  ulong round_robin_idx;
  ulong round_robin_cnt;

  void * root_bank;
  ulong  root_slot;

  blockhash_map_t * blockhash_map;

  ulong completed_slot;
  ulong blockhash_ring_idx;
  blockhash_t blockhash_ring[ 4096 ];

  uchar _bank_msg[ sizeof(fd_completed_bank_t) ];

  struct {
    ulong lut[ FD_METRICS_COUNTER_RESOLV_LUT_RESOLVED_CNT ];
    ulong blockhash_expired;
  } metrics;

  fd_resolv_in_ctx_t in[ 64UL ];

  fd_wksp_t * out_mem;
  ulong       out_chunk0;
  ulong       out_wmark;
  ulong       out_chunk;
} fd_resolv_ctx_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return alignof( fd_resolv_ctx_t );
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof( fd_resolv_ctx_t ), sizeof( fd_resolv_ctx_t ) );
  l = FD_LAYOUT_APPEND( l, map_align(),                map_footprint() );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

extern void fd_ext_bank_release( void const * bank );

static ulong _fd_ext_resolv_tile_cnt;

ulong
fd_ext_resolv_tile_cnt( void ) {
  while( !_fd_ext_resolv_tile_cnt ) {}
  return _fd_ext_resolv_tile_cnt;
}

static inline void
metrics_write( fd_resolv_ctx_t * ctx ) {
  FD_MCNT_SET( RESOLV, BLOCKHASH_EXPIRED, ctx->metrics.blockhash_expired );
  FD_MCNT_ENUM_COPY( RESOLV, LUT_RESOLVED, ctx->metrics.lut );
}

static int
before_frag( fd_resolv_ctx_t * ctx,
             ulong             in_idx,
             ulong             seq,
             ulong             sig ) {
  (void)in_idx;
  (void)sig;

  if( FD_UNLIKELY( ctx->in[in_idx].kind==FD_RESOLV_IN_KIND_BANK ) ) return 0;

  return (seq % ctx->round_robin_cnt) != ctx->round_robin_idx;
}

static inline void
during_frag( fd_resolv_ctx_t * ctx,
             ulong             in_idx,
             ulong             seq,
             ulong             sig,
             ulong             chunk,
             ulong             sz ) {
  (void)seq;
  (void)sig;

  if( FD_UNLIKELY( chunk<ctx->in[ in_idx ].chunk0 || chunk>ctx->in[ in_idx ].wmark || sz>ctx->in[ in_idx ].mtu ) )
    FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->in[ in_idx ].chunk0, ctx->in[ in_idx ].wmark ));

  switch( ctx->in[in_idx].kind ) {
    case FD_RESOLV_IN_KIND_BANK:
      fd_memcpy( ctx->_bank_msg, fd_chunk_to_laddr_const( ctx->in[in_idx].mem, chunk ), sz );
      break;
    case FD_RESOLV_IN_KIND_FRAGMENT: {
      uchar * src = (uchar *)fd_chunk_to_laddr( ctx->in[in_idx].mem, chunk );
      uchar * dst = (uchar *)fd_chunk_to_laddr( ctx->out_mem, ctx->out_chunk );
      fd_memcpy( dst, src, sz );
      break;
    }
    default:
      FD_LOG_ERR(( "unknown in kind %d", ctx->in[in_idx].kind ));
  }
}

static inline void
after_frag( fd_resolv_ctx_t *   ctx,
            ulong               in_idx,
            ulong               seq,
            ulong               sig,
            ulong               chunk,
            ulong               sz,
            ulong               tsorig,
            fd_stem_context_t * stem ) {
  (void)seq;
  (void)sig;
  (void)chunk;

  if( FD_UNLIKELY( ctx->in[in_idx].kind==FD_RESOLV_IN_KIND_BANK ) ) {
    switch( sig ) {
      case 0: {
        fd_rooted_bank_t * frag = (fd_rooted_bank_t *)ctx->_bank_msg;
        if( FD_LIKELY( ctx->root_bank ) ) fd_ext_bank_release( ctx->root_bank );

        ctx->root_bank = frag->bank;
        ctx->root_slot = frag->slot;
        break;
      }
      case 1: {
        fd_completed_bank_t * frag = (fd_completed_bank_t *)ctx->_bank_msg;

        blockhash_map_t * entry = map_query( ctx->blockhash_map, ctx->blockhash_ring[ ctx->blockhash_ring_idx%4096UL ], NULL );
        if( FD_LIKELY( entry ) ) map_remove( ctx->blockhash_map, entry );

        memcpy( ctx->blockhash_ring[ ctx->blockhash_ring_idx%4096UL ].b, frag->hash, 32UL );
        ctx->blockhash_ring_idx++;

        blockhash_map_t * blockhash = map_insert( ctx->blockhash_map, *(blockhash_t *)frag->hash );
        blockhash->slot = frag->slot;

        ctx->completed_slot = frag->slot;
        break;
      }
      default:
        FD_LOG_ERR(( "unknown sig %lu", sig ));
    }
    return;
  }

  uchar const * dcache_entry = fd_chunk_to_laddr_const( ctx->out_mem, ctx->out_chunk );

  ulong payload_sz = *(ushort*)(dcache_entry + sz - sizeof(ushort));
  uchar    const * payload = dcache_entry;
  fd_txn_t const * txn     = (fd_txn_t const *)( dcache_entry + fd_ulong_align_up( payload_sz, 2UL ) );

  /* If we can't find the recent blockhash ... it means one of three things,
  
     (1) It's really old (more than 28 minutes) or just non-existent.
     (2) It's really new (we haven't seen the bank yet).
     (3) It's a durable nonce transaction (just let it pass).
     
    We want to assume case (2) for now, because we don't want to drop
    early incoming votes and things if we don't yet know the bank.  If
    there's a lot of spam coming in with old blockhashes, we can
    introduce a holding area here to keep them until we know if they
    are valid or not. */

  ulong reference_slot = ctx->completed_slot;
  blockhash_map_t const * blockhash = map_query_const( ctx->blockhash_map, *(blockhash_t*)( payload+txn->recent_blockhash_off ), NULL );
  if( FD_LIKELY( blockhash ) ) {
    reference_slot = blockhash->slot;
    if( FD_UNLIKELY( reference_slot+151UL<ctx->completed_slot ) ) {
      ctx->metrics.blockhash_expired++;
      return;
    }
  }

  if( FD_UNLIKELY( txn->addr_table_adtl_cnt ) ) {
    if( FD_UNLIKELY( !ctx->root_bank ) ) {
      FD_MCNT_INC( RESOLV, NO_BANK_DROP, 1 );
      return;
    }

    ulong txn_t_sz = fd_ulong_align_up( fd_ulong_align_up( payload_sz, 2UL ) + fd_txn_footprint( txn->instr_cnt, txn->addr_table_lookup_cnt ), 32UL );
    fd_acct_addr_t * lut_accts = (fd_acct_addr_t*)(dcache_entry+txn_t_sz);
    ushort * next_payload_sz = (ushort*)(dcache_entry+txn_t_sz+txn->addr_table_adtl_cnt*sizeof(fd_acct_addr_t));
    int result = fd_bank_abi_resolve_address_lookup_tables( ctx->root_bank, 0, ctx->root_slot, txn, payload, lut_accts );
    /* result is in [-5, 0]. We want to map -5 to 0, -4 to 1, etc. */
    ctx->metrics.lut[ (ulong)((long)FD_METRICS_COUNTER_RESOLV_LUT_RESOLVED_CNT+result-1L) ]++;

    if( FD_UNLIKELY( result!=FD_BANK_ABI_TXN_INIT_SUCCESS ) ) return;

    *next_payload_sz = (ushort)payload_sz;
    sz = txn_t_sz+txn->addr_table_adtl_cnt*sizeof(fd_acct_addr_t)+sizeof(ushort);
  }

  fd_stem_publish( stem, 0UL, reference_slot, ctx->out_chunk, sz, 0UL, tsorig, 0UL );
  ctx->out_chunk = fd_dcache_compact_next( ctx->out_chunk, sz, ctx->out_chunk0, ctx->out_wmark );
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_resolv_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_resolv_ctx_t ), sizeof( fd_resolv_ctx_t ) );

  ctx->round_robin_cnt = fd_topo_tile_name_cnt( topo, tile->name );
  ctx->round_robin_idx = tile->kind_id;

  ctx->completed_slot = 0UL;
  ctx->blockhash_ring_idx = 0UL;

  if( FD_LIKELY( !tile->kind_id ) ) _fd_ext_resolv_tile_cnt = ctx->round_robin_cnt;

  ctx->root_bank = NULL;

  memset( ctx->blockhash_ring, 0, sizeof( ctx->blockhash_ring ) );
  memset( &ctx->metrics, 0, sizeof( ctx->metrics ) );

  ctx->blockhash_map = map_join( map_new( FD_SCRATCH_ALLOC_APPEND( l, map_align(), map_footprint() ) ) );
  FD_TEST( ctx->blockhash_map );

  FD_TEST( tile->in_cnt<=sizeof( ctx->in )/sizeof( ctx->in[ 0 ] ) );
  for( ulong i=0UL; i<tile->in_cnt; i++ ) {
    fd_topo_link_t * link = &topo->links[ tile->in_link_id[ i ] ];
    fd_topo_wksp_t * link_wksp = &topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ];

    if( FD_LIKELY( !strcmp( link->name, "replay_resol" ) ) ) ctx->in[i].kind = FD_RESOLV_IN_KIND_BANK;
    else                                                     ctx->in[i].kind = FD_RESOLV_IN_KIND_FRAGMENT;

    ctx->in[i].mem    = link_wksp->wksp;
    ctx->in[i].chunk0 = fd_dcache_compact_chunk0( ctx->in[i].mem, link->dcache );
    ctx->in[i].wmark  = fd_dcache_compact_wmark ( ctx->in[i].mem, link->dcache, link->mtu );
    ctx->in[i].mtu    = link->mtu;
  }

  ctx->out_mem    = topo->workspaces[ topo->objs[ topo->links[ tile->out_link_id[ 0 ] ].dcache_obj_id ].wksp_id ].wksp;
  ctx->out_chunk0 = fd_dcache_compact_chunk0( ctx->out_mem, topo->links[ tile->out_link_id[ 0 ] ].dcache );
  ctx->out_wmark  = fd_dcache_compact_wmark ( ctx->out_mem, topo->links[ tile->out_link_id[ 0 ] ].dcache, topo->links[ tile->out_link_id[ 0 ] ].mtu );
  ctx->out_chunk  = ctx->out_chunk0;

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, 1UL );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));
}

#define STEM_BURST (1UL)

#define STEM_CALLBACK_CONTEXT_TYPE  fd_resolv_ctx_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_resolv_ctx_t)

#define STEM_CALLBACK_METRICS_WRITE metrics_write
#define STEM_CALLBACK_BEFORE_FRAG   before_frag
#define STEM_CALLBACK_DURING_FRAG   during_frag
#define STEM_CALLBACK_AFTER_FRAG    after_frag

#include "../../../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_resolv = {
  .name                     = "resolv",
  .populate_allowed_seccomp = NULL,
  .populate_allowed_fds     = NULL,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};
