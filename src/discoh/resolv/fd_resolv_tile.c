#include "../bank/fd_bank_abi.h"

#include "../../disco/tiles.h"
#include "../../disco/metrics/fd_metrics.h"
#include "../../flamenco/runtime/fd_system_ids.h"
#include "../../flamenco/runtime/fd_system_ids_pp.h"

#if FD_HAS_AVX
#include "../../util/simd/fd_avx.h"
#endif

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

/* The blockhash ring holds recent blockhashes, so we can identify when
   a transaction arrives, what slot it will expire (and can no longer be
   packed) in.  This is useful so we don't send transactions to pack
   that are no longer packable.

   Unfortunately, poorly written transaction senders frequently send
   transactions from millions of slots ago, so we need a large ring to
   be able to determine and evict these.  The highest practically useful
   value here is around 22, which works out to 19 days of blockhash
   history.  Beyond this, the validator is likely to be restarted, and
   lose the history anyway. */

#define BLOCKHASH_LG_RING_CNT 22UL
#define BLOCKHASH_RING_LEN   (1UL<<BLOCKHASH_LG_RING_CNT)

#define MAP_NAME              map
#define MAP_T                 blockhash_map_t
#define MAP_KEY_T             blockhash_t
#define MAP_LG_SLOT_CNT       (BLOCKHASH_LG_RING_CNT+1UL)
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

#include "../../util/tmpl/fd_map.c"

typedef struct {
  union {
    ulong pool_next; /* Used when it's released */
    ulong lru_next;  /* Used when it's acquired */
  };                 /* .. so it's okay to store them in the same memory */
  ulong lru_prev;

  ulong map_next;
  ulong map_prev;

  blockhash_t * blockhash;
  uchar _[ FD_TPU_PARSED_MTU ] __attribute__((aligned(alignof(fd_txn_m_t))));
} fd_stashed_txn_m_t;

#define POOL_NAME      pool
#define POOL_T         fd_stashed_txn_m_t
#define POOL_NEXT      pool_next
#define POOL_IDX_T     ulong

#include "../../util/tmpl/fd_pool.c"

/* We'll push at the head, which means the tail is the oldest. */
#define DLIST_NAME  lru_list
#define DLIST_ELE_T fd_stashed_txn_m_t
#define DLIST_PREV  lru_prev
#define DLIST_NEXT  lru_next

#include "../../util/tmpl/fd_dlist.c"

#define MAP_NAME          map_chain
#define MAP_ELE_T         fd_stashed_txn_m_t
#define MAP_KEY_T         blockhash_t *
#define MAP_KEY           blockhash
#define MAP_IDX_T         ulong
#define MAP_NEXT          map_next
#define MAP_PREV          map_prev
#define MAP_KEY_HASH(k,s) ((s) ^ fd_ulong_load_8( (*(k))->b ))
#define MAP_KEY_EQ(k0,k1) (!memcmp((*(k0))->b, (*(k1))->b, 32UL))
#define MAP_OPTIMIZE_RANDOM_ACCESS_REMOVAL 1
#define MAP_MULTI         1

#include "../../util/tmpl/fd_map_chain.c"

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

  int   bundle_failed;
  ulong bundle_id;

  void * root_bank;
  ulong  root_slot;

  blockhash_map_t * blockhash_map;

  ulong flushing_slot;
  ulong flush_pool_idx;

  fd_stashed_txn_m_t * pool;
  map_chain_t *        map_chain;
  lru_list_t           lru_list[1];

  ulong completed_slot;
  ulong blockhash_ring_idx;
  blockhash_t blockhash_ring[ BLOCKHASH_RING_LEN ];

  uchar _bank_msg[ sizeof(fd_completed_bank_t) ];

  struct {
    ulong lut[ FD_METRICS_COUNTER_RESOLV_LUT_RESOLVED_CNT ];
    ulong blockhash_expired;
    ulong blockhash_unknown;
    ulong bundle_peer_failure_cnt;
    ulong stash[ FD_METRICS_COUNTER_RESOLV_STASH_OPERATION_CNT ];
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
  l = FD_LAYOUT_APPEND( l, alignof( fd_resolv_ctx_t ), sizeof( fd_resolv_ctx_t )        );
  l = FD_LAYOUT_APPEND( l, pool_align(),               pool_footprint     ( 1UL<<16UL ) );
  l = FD_LAYOUT_APPEND( l, map_chain_align(),          map_chain_footprint( 8192UL    ) );
  l = FD_LAYOUT_APPEND( l, map_align(),                map_footprint()                  );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

extern void fd_ext_bank_release( void const * bank );

static ulong _fd_ext_resolv_tile_cnt;

ulong
fd_ext_resolv_tile_cnt( void ) {
  while(  !FD_VOLATILE( _fd_ext_resolv_tile_cnt ) ) {}
  return _fd_ext_resolv_tile_cnt;
}

static inline void
metrics_write( fd_resolv_ctx_t * ctx ) {
  FD_MCNT_SET( RESOLV, BLOCKHASH_EXPIRED, ctx->metrics.blockhash_expired );
  FD_MCNT_ENUM_COPY( RESOLV, LUT_RESOLVED, ctx->metrics.lut );
  FD_MCNT_ENUM_COPY( RESOLV, STASH_OPERATION, ctx->metrics.stash );
  FD_MCNT_SET( RESOLV, TRANSACTION_BUNDLE_PEER_FAILURE, ctx->metrics.bundle_peer_failure_cnt );
}

static int
before_frag( fd_resolv_ctx_t * ctx,
             ulong             in_idx,
             ulong             seq,
             ulong             sig ) {
  (void)sig;

  if( FD_UNLIKELY( ctx->in[in_idx].kind==FD_RESOLV_IN_KIND_BANK ) ) return 0;

  return (seq % ctx->round_robin_cnt) != ctx->round_robin_idx;
}

static inline void
during_frag( fd_resolv_ctx_t * ctx,
             ulong             in_idx,
             ulong             seq FD_PARAM_UNUSED,
             ulong             sig FD_PARAM_UNUSED,
             ulong             chunk,
             ulong             sz,
             ulong             ctl FD_PARAM_UNUSED ) {

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

static inline int
publish_txn( fd_resolv_ctx_t *          ctx,
             fd_stem_context_t *        stem,
             fd_stashed_txn_m_t const * stashed ) {
  fd_txn_m_t *     txnm = (fd_txn_m_t *)fd_chunk_to_laddr( ctx->out_mem, ctx->out_chunk );
  fd_memcpy( txnm, stashed->_, fd_txn_m_realized_footprint( (fd_txn_m_t *)stashed->_, 1, 0 ) );

  fd_txn_t const * txnt = fd_txn_m_txn_t( txnm );

  txnm->reference_slot = ctx->flushing_slot;

  if( FD_UNLIKELY( txnt->addr_table_adtl_cnt ) ) {
    if( FD_UNLIKELY( !ctx->root_bank ) ) {
      FD_MCNT_INC( RESOLV, NO_BANK_DROP, 1 );
      return 0;
    } else {
      int result = fd_bank_abi_resolve_address_lookup_tables( ctx->root_bank, 0, ctx->root_slot, txnt, fd_txn_m_payload( txnm ), fd_txn_m_alut( txnm ) );
      /* result is in [-5, 0]. We want to map -5 to 0, -4 to 1, etc. */
      ctx->metrics.lut[ (ulong)((long)FD_METRICS_COUNTER_RESOLV_LUT_RESOLVED_CNT+result-1L) ]++;

      if( FD_UNLIKELY( result!=FD_BANK_ABI_TXN_INIT_SUCCESS ) ) return 0;
    }
  }

  ulong realized_sz = fd_txn_m_realized_footprint( txnm, 1, 1 );
  ulong tspub = fd_frag_meta_ts_comp( fd_tickcount() );
  fd_stem_publish( stem, 0UL, txnm->reference_slot, ctx->out_chunk, realized_sz, 0UL, 0UL, tspub );
  ctx->out_chunk = fd_dcache_compact_next( ctx->out_chunk, realized_sz, ctx->out_chunk0, ctx->out_wmark );

  return 1;
}

static inline void
after_credit( fd_resolv_ctx_t *   ctx,
              fd_stem_context_t * stem,
              int *               opt_poll_in,
              int *               charge_busy ) {
  if( FD_LIKELY( ctx->flush_pool_idx==ULONG_MAX ) ) return;

  *charge_busy = 1;
  *opt_poll_in = 0;

  ulong next = map_chain_idx_next_const( ctx->flush_pool_idx, ULONG_MAX, ctx->pool );
  map_chain_idx_remove_fast( ctx->map_chain, ctx->flush_pool_idx, ctx->pool );
  if( FD_LIKELY( publish_txn( ctx, stem, pool_ele( ctx->pool, ctx->flush_pool_idx ) ) ) ) {
    ctx->metrics.stash[ FD_METRICS_ENUM_RESOLVE_STASH_OPERATION_V_PUBLISHED_IDX ]++;
  } else {
    ctx->metrics.stash[ FD_METRICS_ENUM_RESOLVE_STASH_OPERATION_V_REMOVED_IDX ]++;
  }
  lru_list_idx_remove( ctx->lru_list, ctx->flush_pool_idx, ctx->pool );
  pool_idx_release( ctx->pool, ctx->flush_pool_idx );
  ctx->flush_pool_idx = next;
}

/* Returns 0 if not a durable nonce transaction and 1 if it may be a
   durable nonce transaction */

FD_FN_PURE static inline int
fd_resolv_is_durable_nonce( fd_txn_t const * txn,
                            uchar    const * payload ) {
  if( FD_UNLIKELY( txn->instr_cnt==0 ) ) return 0;

  fd_txn_instr_t const * ix0 = &txn->instr[ 0 ];
  fd_acct_addr_t const * prog0 = fd_txn_get_acct_addrs( txn, payload ) + ix0->program_id;
  /* First instruction must be SystemProgram nonceAdvance instruction */
  fd_acct_addr_t const system_program[1] = { { { SYS_PROG_ID } } };
  if( FD_LIKELY( memcmp( prog0, system_program, sizeof(fd_acct_addr_t) ) ) )        return 0;

  /* instruction with three accounts and a four byte instruction data, a
     little-endian uint value 4 */
  if( FD_UNLIKELY( (ix0->data_sz!=4) | (ix0->acct_cnt!=3) ) ) return 0;

  return fd_uint_load_4( payload + ix0->data_off )==4U;
}

static inline void
after_frag( fd_resolv_ctx_t *   ctx,
            ulong               in_idx,
            ulong               seq,
            ulong               sig,
            ulong               sz,
            ulong               tsorig,
            ulong               _tspub,
            fd_stem_context_t * stem ) {
  (void)seq;
  (void)sz;
  (void)_tspub;

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

        blockhash_map_t * entry = map_query( ctx->blockhash_map, ctx->blockhash_ring[ ctx->blockhash_ring_idx%BLOCKHASH_RING_LEN ], NULL );
        if( FD_LIKELY( entry ) ) map_remove( ctx->blockhash_map, entry );

        memcpy( ctx->blockhash_ring[ ctx->blockhash_ring_idx%BLOCKHASH_RING_LEN ].b, frag->hash, 32UL );
        ctx->blockhash_ring_idx++;

        blockhash_map_t * blockhash = map_insert( ctx->blockhash_map, *(blockhash_t *)frag->hash );
        blockhash->slot = frag->slot;

        blockhash_t * hash = (blockhash_t *)frag->hash;
        ctx->flush_pool_idx  = map_chain_idx_query_const( ctx->map_chain, &hash, ULONG_MAX, ctx->pool );
        ctx->flushing_slot   = frag->slot;

        ctx->completed_slot = frag->slot;
        break;
      }
      default:
        FD_LOG_ERR(( "unknown sig %lu", sig ));
    }
    return;
  }

  fd_txn_m_t *     txnm = (fd_txn_m_t *)fd_chunk_to_laddr( ctx->out_mem, ctx->out_chunk );
  FD_TEST( txnm->payload_sz<=FD_TPU_MTU );
  FD_TEST( txnm->txn_t_sz<=FD_TXN_MAX_SZ );
  fd_txn_t const * txnt = fd_txn_m_txn_t( txnm );

  /* If we find the recent blockhash, life is simple.  We drop
     transactions that couldn't possibly execute any more, and forward
     to pack ones that could.

     If we can't find the recent blockhash ... it means one of four
     things,

     (1) The blockhash is really old (more than 19 days) or just
         non-existent.
     (2) The blockhash is not that old, but was created before this
         validator was started.
     (3) It's really new (we haven't seen the bank yet).
     (4) It's a durable nonce transaction, or part of a bundle (just let
         it pass).

    For durable nonce transactions, there isn't much we can do except
    pass them along and see if they execute.

    For the other three cases ... we don't want to flood pack with what
    might be junk transactions, so we accumulate them into a local
    buffer.  If we later see the blockhash come to exist, we forward any
    buffered transactions to back. */

  if( FD_UNLIKELY( txnm->block_engine.bundle_id && (txnm->block_engine.bundle_id!=ctx->bundle_id) ) ) {
    ctx->bundle_failed = 0;
    ctx->bundle_id     = txnm->block_engine.bundle_id;
  }

  if( FD_UNLIKELY( txnm->block_engine.bundle_id && ctx->bundle_failed ) ) {
    ctx->metrics.bundle_peer_failure_cnt++;
    return;
  }

  txnm->reference_slot = ctx->completed_slot;
  blockhash_map_t const * blockhash = map_query_const( ctx->blockhash_map, *(blockhash_t*)( fd_txn_m_payload( txnm )+txnt->recent_blockhash_off ), NULL );
  if( FD_LIKELY( blockhash ) ) {
    txnm->reference_slot = blockhash->slot;
    if( FD_UNLIKELY( txnm->reference_slot+151UL<ctx->completed_slot ) ) {
      if( FD_UNLIKELY( txnm->block_engine.bundle_id ) ) ctx->bundle_failed = 1;
      ctx->metrics.blockhash_expired++;
      return;
    }
  }

  int is_bundle_member = !!txnm->block_engine.bundle_id;
  int is_durable_nonce = fd_resolv_is_durable_nonce( txnt, fd_txn_m_payload( txnm ) );

  if( FD_UNLIKELY( !is_bundle_member && !is_durable_nonce && !blockhash ) ) {
    ulong pool_idx;
    if( FD_UNLIKELY( !pool_free( ctx->pool ) ) ) {
      pool_idx = lru_list_idx_pop_tail( ctx->lru_list, ctx->pool );
      map_chain_idx_remove_fast( ctx->map_chain, pool_idx, ctx->pool );
      ctx->metrics.stash[ FD_METRICS_ENUM_RESOLVE_STASH_OPERATION_V_OVERRUN_IDX ]++;
    } else {
      pool_idx = pool_idx_acquire( ctx->pool );
    }

    fd_stashed_txn_m_t * stash_txn = pool_ele( ctx->pool, pool_idx );
    /* There's a compiler bug in GCC version 12 (at least 12.1, 12.3 and
       12.4) that cause it to think stash_txn is a null pointer.  It
       then complains that the memcpy is bad and refuses to compile the
       memcpy below.  It is possible for pool_ele to return NULL, but
       that can't happen because if pool_free is 0, then all the pool
       elements must be in the LRU list, so idx_pop_tail won't return
       IDX_NULL; and if pool_free returns non-zero, then
       pool_idx_acquire won't return POOL_IDX_NULL. */
    FD_COMPILER_FORGET( stash_txn );
    fd_memcpy( stash_txn->_, txnm, fd_txn_m_realized_footprint( txnm, 1, 0 ) );
    stash_txn->blockhash = (blockhash_t *)(fd_txn_m_payload( (fd_txn_m_t *)(stash_txn->_) ) + txnt->recent_blockhash_off);
    ctx->metrics.stash[ FD_METRICS_ENUM_RESOLVE_STASH_OPERATION_V_INSERTED_IDX ]++;

    map_chain_ele_insert( ctx->map_chain, stash_txn, ctx->pool );
    lru_list_idx_push_head( ctx->lru_list, pool_idx, ctx->pool );

    return;
  }

  if( FD_UNLIKELY( txnt->addr_table_adtl_cnt ) ) {
    if( FD_UNLIKELY( !ctx->root_bank ) ) {
      FD_MCNT_INC( RESOLV, NO_BANK_DROP, 1 );
      if( FD_UNLIKELY( txnm->block_engine.bundle_id ) ) ctx->bundle_failed = 1;
      return;
    }

    int result = fd_bank_abi_resolve_address_lookup_tables( ctx->root_bank, 0, ctx->root_slot, txnt, fd_txn_m_payload( txnm ), fd_txn_m_alut( txnm ) );
    /* result is in [-5, 0]. We want to map -5 to 0, -4 to 1, etc. */
    ctx->metrics.lut[ (ulong)((long)FD_METRICS_COUNTER_RESOLV_LUT_RESOLVED_CNT+result-1L) ]++;

    if( FD_UNLIKELY( result!=FD_BANK_ABI_TXN_INIT_SUCCESS ) ) {
      if( FD_UNLIKELY( txnm->block_engine.bundle_id ) ) ctx->bundle_failed = 1;
      return;
    }
  }

  ulong realized_sz = fd_txn_m_realized_footprint( txnm, 1, 1 );
  ulong tspub = fd_frag_meta_ts_comp( fd_tickcount() );
  fd_stem_publish( stem, 0UL, txnm->reference_slot, ctx->out_chunk, realized_sz, 0UL, tsorig, tspub );
  ctx->out_chunk = fd_dcache_compact_next( ctx->out_chunk, realized_sz, ctx->out_chunk0, ctx->out_wmark );
}

static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_resolv_ctx_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_resolv_ctx_t ), sizeof( fd_resolv_ctx_t ) );

  ctx->round_robin_cnt = fd_topo_tile_name_cnt( topo, tile->name );
  ctx->round_robin_idx = tile->kind_id;

  ctx->bundle_failed = 0;
  ctx->bundle_id     = 0UL;

  ctx->completed_slot = 0UL;
  ctx->blockhash_ring_idx = 0UL;

  ctx->flush_pool_idx = ULONG_MAX;

  ctx->pool = pool_join( pool_new( FD_SCRATCH_ALLOC_APPEND( l, pool_align(), pool_footprint( 1UL<<16UL ) ), 1UL<<16UL ) );
  FD_TEST( ctx->pool );

  ctx->map_chain = map_chain_join( map_chain_new( FD_SCRATCH_ALLOC_APPEND( l, map_chain_align(), map_chain_footprint( 8192ULL ) ), 8192UL , 0UL ) );
  FD_TEST( ctx->map_chain );

  FD_TEST( ctx->lru_list==lru_list_join( lru_list_new( ctx->lru_list ) ) );

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
#define STEM_CALLBACK_AFTER_CREDIT  after_credit
#define STEM_CALLBACK_BEFORE_FRAG   before_frag
#define STEM_CALLBACK_DURING_FRAG   during_frag
#define STEM_CALLBACK_AFTER_FRAG    after_frag

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_resolv = {
  .name                     = "resolv",
  .populate_allowed_seccomp = NULL,
  .populate_allowed_fds     = NULL,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};
