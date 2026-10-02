#include "../bank/fd_bank_abi.h"

#include "../../util/fd_hash32.h"
#include "../../disco/tiles.h"
#include "../../disco/fd_txn_m.h"
#include "../../disco/metrics/fd_metrics.h"
#include "../../flamenco/runtime/fd_system_ids_pp.h"

#if FD_HAS_AVX
#include "../../util/simd/fd_avx.h"
#endif

#define FD_RESOLH_IN_KIND_FRAGMENT (0)
#define FD_RESOLH_IN_KIND_BANK     (1)

struct blockhash {
  uchar b[ 32 ];
};

typedef struct blockhash blockhash_t;

struct blockhash_map {
  blockhash_t key;
  ulong       slot;
  ulong       block_height;
  /* The map_chain variables: */
  uint        next;
  /* It's probably not worth 4 bytes of cache per element to store
     chain_prev, since the query/delete ratio is probably about 1000:1,
     but alignof is 8, so we'd just store padding here instead */
  uint        prev;
};

typedef struct blockhash_map blockhash_map_t;

/* The blockhash ring holds recent blockhashes, so we can identify when
   a transaction arrives, what slot it will expire (and can no longer be
   packed) in.  This is useful so we don't send transactions to pack
   that are no longer packable.

   Similarly, we also store the nonce version of the blockhash, which is
   stored in nonce accounts when a transaction executes in the following
   slot.  Since nonce transactions stay valid for arbitrarily long, this
   just helps us order nonce transactions that try to advance the same
   account.

   Unfortunately, poorly written transaction senders frequently send
   transactions from millions of slots ago, so we need a large ring to
   be able to determine and evict these.  The highest practically useful
   value here is around 22, which works out to 19 days of blockhash
   history.  Beyond this, the validator is likely to be restarted, and
   lose the history anyway. */

#define BLOCKHASH_LG_RING_CNT 22UL
#define BLOCKHASH_RING_LEN   (1UL<<BLOCKHASH_LG_RING_CNT)

#define MAP_NAME               map
#define MAP_ELE_T              blockhash_map_t
#define MAP_KEY_T              blockhash_t
#define MAP_IDX_T              uint
#define MAP_OPTIMIZE_RANDOM_ACCESS_REMOVAL 1
#define MAP_KEY_EQ(k0,k1)      (!memcmp((k0)->b,(k1)->b, 32UL))
#define MAP_KEY_HASH(key,seed) ((uint)fd_hash32( (key)->b, (seed) ))

#include "../../util/tmpl/fd_map_chain.c"

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
#define MAP_KEY_HASH(k,s) fd_hash( (s), (*(k))->b, sizeof((*(k))->b) )
#define MAP_KEY_EQ(k0,k1) (!memcmp((*(k0))->b, (*(k1))->b, 32UL))
#define MAP_OPTIMIZE_RANDOM_ACCESS_REMOVAL 1
#define MAP_MULTI         1

#include "../../util/tmpl/fd_map_chain.c"

struct fd_resolh_in {
  int         kind;

  fd_wksp_t * mem;
  ulong       chunk0;
  ulong       wmark;
  ulong       mtu;
};

typedef struct fd_resolh_in fd_resolh_in_t;

struct fd_resolh_tile {
  ulong round_robin_idx;
  ulong round_robin_cnt;
  ulong map_seed;

  int   bundle_failed;
  ulong bundle_id;

  void * root_bank;
  ulong  root_slot;

  map_t * blockhash_map;
  map_t * nonce_blockhash_map;

  ulong flushing_block_height;
  ulong flush_pool_idx;

  fd_stashed_txn_m_t * pool;
  map_chain_t *        map_chain;
  lru_list_t           lru_list[1];

  ulong completed_slot;
  ulong completed_block_height;
  /* The total number of blockhashes that have been inserted in
     blockhash_ring (and since nonce_blockhash_ring is parallel, also in
     nonce_blockhash_ring. */
  ulong blockhash_ring_idx;

  /* These are the pools used the blockhash_map */
  blockhash_map_t blockhash_ring      [ BLOCKHASH_RING_LEN ];
  blockhash_map_t nonce_blockhash_ring[ BLOCKHASH_RING_LEN ];

  uchar _bank_msg[ sizeof(fd_completed_bank_t) ];

  struct {
    ulong lut[ FD_METRICS_COUNTER_RESOLH_LUT_RESOLVED_CNT ];
    ulong blockhash_expired;
    ulong blockhash_unknown;
    ulong bundle_peer_failure_cnt;
    ulong stash[ FD_METRICS_COUNTER_RESOLH_STASH_OPERATION_CNT ];
  } metrics;

  fd_resolh_in_t in[ 64UL ];

  fd_wksp_t * out_mem;
  ulong       out_chunk0;
  ulong       out_wmark;
  ulong       out_chunk;
};

typedef struct fd_resolh_tile fd_resolh_tile_t;

FD_FN_CONST static inline ulong
scratch_align( void ) {
  return fd_ulong_max( fd_ulong_max( alignof( fd_resolh_tile_t ), pool_align() ), fd_ulong_max( map_chain_align(), map_align() ) );
}

FD_FN_PURE static inline ulong
scratch_footprint( fd_topo_tile_t const * tile ) {
  (void)tile;
  /* The map is normally full, so make the chain cnt a bit bigger */
  ulong map_chain_cnt = 2UL*map_chain_cnt_est( BLOCKHASH_RING_LEN );
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof( fd_resolh_tile_t ), sizeof( fd_resolh_tile_t )       );
  l = FD_LAYOUT_APPEND( l, pool_align(),                pool_footprint( 1UL<<16UL )      );
  l = FD_LAYOUT_APPEND( l, map_chain_align(),           map_chain_footprint( 8192UL )    );
  l = FD_LAYOUT_APPEND( l, map_align(),                 map_footprint( map_chain_cnt )   );
  l = FD_LAYOUT_APPEND( l, map_align(),                 map_footprint( map_chain_cnt )   );
  return FD_LAYOUT_FINI( l, scratch_align() );
}

extern void fd_ext_bank_release( void const * bank );

static ulong _fd_ext_resolh_tile_cnt;

ulong
fd_ext_resolv_tile_cnt( void ) {
  while(  !FD_VOLATILE( _fd_ext_resolh_tile_cnt ) ) {}
  return _fd_ext_resolh_tile_cnt;
}

static inline void
metrics_write( fd_resolh_tile_t * ctx ) {
  FD_MCNT_SET( RESOLH, BLOCKHASH_EXPIRED, ctx->metrics.blockhash_expired );
  FD_MCNT_ENUM_COPY( RESOLH, LUT_RESOLVED, ctx->metrics.lut );
  FD_MCNT_ENUM_COPY( RESOLH, STASH_OPERATION, ctx->metrics.stash );
  FD_MCNT_SET( RESOLH, TXN_BUNDLE_PEER_FAILED, ctx->metrics.bundle_peer_failure_cnt );
}

static int
before_frag( fd_resolh_tile_t * ctx,
             ulong              in_idx,
             ulong              seq,
             ulong              sig ) {
  if( FD_UNLIKELY( ctx->in[in_idx].kind==FD_RESOLH_IN_KIND_BANK ) ) return 0;

  /* Bundle transactions (sig==1) must arrive at pack in order.  Route
     all bundle traffic to resolh:0. */
  if( FD_UNLIKELY( sig ) ) return ctx->round_robin_idx!=0UL;

  return (seq % ctx->round_robin_cnt) != ctx->round_robin_idx;
}

static inline void
during_frag( fd_resolh_tile_t * ctx,
             ulong              in_idx,
             ulong              seq FD_PARAM_UNUSED,
             ulong              sig FD_PARAM_UNUSED,
             ulong              chunk,
             ulong              sz,
             ulong              ctl FD_PARAM_UNUSED ) {

  if( FD_UNLIKELY( chunk<ctx->in[ in_idx ].chunk0 || chunk>ctx->in[ in_idx ].wmark || sz>ctx->in[ in_idx ].mtu ) )
    FD_LOG_ERR(( "chunk %lu %lu corrupt, not in range [%lu,%lu]", chunk, sz, ctx->in[ in_idx ].chunk0, ctx->in[ in_idx ].wmark ));

  switch( ctx->in[in_idx].kind ) {
    case FD_RESOLH_IN_KIND_BANK:
      fd_memcpy( ctx->_bank_msg, fd_chunk_to_laddr_const( ctx->in[in_idx].mem, chunk ), sz );
      break;
    case FD_RESOLH_IN_KIND_FRAGMENT: {
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
publish_txn( fd_resolh_tile_t *         ctx,
             fd_stem_context_t *        stem,
             fd_stashed_txn_m_t const * stashed ) {
  fd_txn_m_t *     txnm = (fd_txn_m_t *)fd_chunk_to_laddr( ctx->out_mem, ctx->out_chunk );
  fd_memcpy( txnm, stashed->_, fd_txn_m_realized_footprint( (fd_txn_m_t *)stashed->_, 1, 0 ) );

  fd_txn_t const * txnt = fd_txn_m_txn_t( txnm );

  txnm->reference_block_height = ctx->flushing_block_height;

  if( FD_UNLIKELY( txnt->addr_table_adtl_cnt ) ) {
    if( FD_UNLIKELY( !ctx->root_bank ) ) {
      FD_MCNT_INC( RESOLH, TXN_NO_BANK, 1 );
      return 0;
    } else {
      int result = fd_bank_abi_resolve_address_lookup_tables( ctx->root_bank, 0, ctx->root_slot, txnt, fd_txn_m_payload( txnm ), fd_txn_m_alut( txnm ) );
      /* result is in [-5, 0]. We want to map -5 to 0, -4 to 1, etc. */
      ctx->metrics.lut[ (ulong)((long)FD_METRICS_COUNTER_RESOLH_LUT_RESOLVED_CNT+result-1L) ]++;

      if( FD_UNLIKELY( result!=FD_BANK_ABI_TXN_INIT_SUCCESS ) ) return 0;
    }
  }

  ulong realized_sz = fd_txn_m_realized_footprint( txnm, 1, 1 );
  ulong tspub = fd_frag_meta_ts_comp( fd_tickcount() );
  fd_stem_publish( stem, 0UL, txnm->reference_block_height, ctx->out_chunk, realized_sz, 0UL, 0UL, tspub );
  ctx->out_chunk = fd_dcache_compact_next( ctx->out_chunk, realized_sz, ctx->out_chunk0, ctx->out_wmark );

  return 1;
}

static inline void
after_credit( fd_resolh_tile_t *  ctx,
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

static inline void
after_frag( fd_resolh_tile_t *  ctx,
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

  if( FD_UNLIKELY( ctx->in[in_idx].kind==FD_RESOLH_IN_KIND_BANK ) ) {
    switch( sig ) {
      case 0: {
        fd_rooted_bank_t * frag = (fd_rooted_bank_t *)ctx->_bank_msg;
        if( FD_LIKELY( ctx->root_bank ) ) fd_ext_bank_release( ctx->root_bank );

        ctx->root_bank = frag->bank;
        ctx->root_slot = frag->slot;
        break;
      }
      case 1: {
        fd_completed_bank_t * msg = (fd_completed_bank_t *)ctx->_bank_msg;

        if( FD_UNLIKELY( ctx->blockhash_ring_idx>=BLOCKHASH_RING_LEN ) ) {
          map_idx_remove_fast( ctx->blockhash_map,       ctx->blockhash_ring_idx%BLOCKHASH_RING_LEN, ctx->blockhash_ring       );
          map_idx_remove_fast( ctx->nonce_blockhash_map, ctx->blockhash_ring_idx%BLOCKHASH_RING_LEN, ctx->nonce_blockhash_ring );
        }
        blockhash_map_t * entry       = ctx->blockhash_ring      +(ctx->blockhash_ring_idx%BLOCKHASH_RING_LEN);
        blockhash_map_t * nonce_entry = ctx->nonce_blockhash_ring+(ctx->blockhash_ring_idx%BLOCKHASH_RING_LEN);

        /* See fd_durable_nonce_from_blockhash */
        struct {
          char      tag[13];
          fd_hash_t bh[1];
        } hash_buf[1] = {{ .tag = "DURABLE_NONCE", .bh = { *(fd_hash_t *)(msg->hash) } }};

        memcpy( entry->key.b, msg->hash, 32UL );    fd_sha256_hash( hash_buf, sizeof(hash_buf), nonce_entry->key.b );
        entry->slot         = msg->slot;            nonce_entry->slot         = msg->slot;
        entry->block_height = msg->block_height;    nonce_entry->block_height = msg->block_height;

        map_ele_insert( ctx->blockhash_map,       entry,       ctx->blockhash_ring       );
        map_ele_insert( ctx->nonce_blockhash_map, nonce_entry, ctx->nonce_blockhash_ring );
        ctx->blockhash_ring_idx++;

        blockhash_t * hash = (blockhash_t *)msg->hash;
        ctx->flush_pool_idx  = map_chain_idx_query_const( ctx->map_chain, &hash, ULONG_MAX, ctx->pool );
        ctx->flushing_block_height  = msg->block_height;

        ctx->completed_slot         = msg->slot;
        ctx->completed_block_height = msg->block_height;
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

  /* If the transaction doesn't look like a nonce transaction and we
     find the recent blockhash, life is simple.  We drop transactions
     that couldn't possibly execute any more, and forward to pack ones
     that could.

     If we can't find the recent blockhash ... it means one of three
     things,

     (1) The blockhash is really old (more than 19 days) or just
         non-existent.
     (2) The blockhash is not that old, but was created before this
         validator was started.
     (3) It's really new (we haven't seen the bank yet).

    For durable nonce transactions, we map the value in the recent
    blockhash field to a slot and its block height.  This doesn't
    immediately let us discard any transactions, but it lets pack order
    nonce transactions, which allows it to throw out old ones.

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

  txnm->reference_block_height = ctx->completed_block_height;

  int is_durable_nonce = fd_disco_tpu_is_durable_nonce( txnt, fd_txn_m_payload( txnm ) );
  map_t const *           map  = fd_ptr_if( is_durable_nonce, ctx->nonce_blockhash_map, ctx->blockhash_map );
  blockhash_map_t const * pool = is_durable_nonce ? ctx->nonce_blockhash_ring : ctx->blockhash_ring;

  blockhash_t const * recent_blockhash = (blockhash_t const *)( fd_txn_m_payload( txnm )+txnt->recent_blockhash_off );

  blockhash_map_t const * blockhash = map_ele_query_const( map, recent_blockhash, NULL, pool );
  if( FD_LIKELY( blockhash ) ) {
    txnm->reference_block_height = blockhash->block_height;
    if( FD_UNLIKELY( (!is_durable_nonce) & (txnm->reference_block_height+151UL<ctx->completed_block_height) ) ) {
      if( FD_UNLIKELY( txnm->block_engine.bundle_id ) ) ctx->bundle_failed = 1;
      ctx->metrics.blockhash_expired++;
      return;
    }
  }

  int is_bundle_member = !!txnm->block_engine.bundle_id;

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
      FD_MCNT_INC( RESOLH, TXN_NO_BANK, 1 );
      if( FD_UNLIKELY( txnm->block_engine.bundle_id ) ) ctx->bundle_failed = 1;
      return;
    }

    int result = fd_bank_abi_resolve_address_lookup_tables( ctx->root_bank, 0, ctx->root_slot, txnt, fd_txn_m_payload( txnm ), fd_txn_m_alut( txnm ) );
    /* result is in [-5, 0]. We want to map -5 to 0, -4 to 1, etc. */
    ctx->metrics.lut[ (ulong)((long)FD_METRICS_COUNTER_RESOLH_LUT_RESOLVED_CNT+result-1L) ]++;

    if( FD_UNLIKELY( result!=FD_BANK_ABI_TXN_INIT_SUCCESS ) ) {
      if( FD_UNLIKELY( txnm->block_engine.bundle_id ) ) ctx->bundle_failed = 1;
      return;
    }
  }

  ulong realized_sz = fd_txn_m_realized_footprint( txnm, 1, 1 );
  ulong tspub = fd_frag_meta_ts_comp( fd_tickcount() );
  fd_stem_publish( stem, 0UL, txnm->reference_block_height, ctx->out_chunk, realized_sz, 0UL, tsorig, tspub );
  ctx->out_chunk = fd_dcache_compact_next( ctx->out_chunk, realized_sz, ctx->out_chunk0, ctx->out_wmark );
}

static void
privileged_init( fd_topo_t const *      topo,
                 fd_topo_tile_t const * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_resolh_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_resolh_tile_t ), sizeof( fd_resolh_tile_t ) );
  FD_TEST( fd_rng_secure( &ctx->map_seed, sizeof(ctx->map_seed) ) );
}

static void
unprivileged_init( fd_topo_t const *      topo,
                   fd_topo_tile_t const * tile ) {
  void * scratch = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  FD_SCRATCH_ALLOC_INIT( l, scratch );
  fd_resolh_tile_t * ctx = FD_SCRATCH_ALLOC_APPEND( l, alignof( fd_resolh_tile_t ), sizeof( fd_resolh_tile_t ) );

  ctx->round_robin_cnt = fd_topo_tile_name_cnt( topo, tile->name );
  ctx->round_robin_idx = tile->kind_id;

  ctx->bundle_failed = 0;
  ctx->bundle_id     = 0UL;

  ctx->completed_slot         = 0UL;
  ctx->completed_block_height = 0UL;
  ctx->blockhash_ring_idx     = 0UL;

  ctx->flush_pool_idx = ULONG_MAX;

  ctx->pool = pool_join( pool_new( FD_SCRATCH_ALLOC_APPEND( l, pool_align(), pool_footprint( 1UL<<16UL ) ), 1UL<<16UL ) );
  FD_TEST( ctx->pool );

  ctx->map_chain = map_chain_join( map_chain_new( FD_SCRATCH_ALLOC_APPEND( l, map_chain_align(), map_chain_footprint( 8192ULL ) ), 8192UL, ctx->map_seed ) );
  FD_TEST( ctx->map_chain );

  FD_TEST( ctx->lru_list==lru_list_join( lru_list_new( ctx->lru_list ) ) );

  if( FD_LIKELY( !tile->kind_id ) ) _fd_ext_resolh_tile_cnt = ctx->round_robin_cnt;

  ctx->root_bank = NULL;

  memset( ctx->blockhash_ring,       0, sizeof( ctx->blockhash_ring      ) );
  memset( ctx->nonce_blockhash_ring, 0, sizeof( ctx->nonce_blockhash_ring ) );
  memset( &ctx->metrics, 0, sizeof( ctx->metrics ) );

  ulong map_chain_cnt = 2UL*map_chain_cnt_est( BLOCKHASH_RING_LEN );
  ulong footprint     = map_footprint( map_chain_cnt );
  ctx->blockhash_map       = map_join( map_new( FD_SCRATCH_ALLOC_APPEND( l, map_align(), footprint ), map_chain_cnt, ctx->map_seed ) );
  ctx->nonce_blockhash_map = map_join( map_new( FD_SCRATCH_ALLOC_APPEND( l, map_align(), footprint ), map_chain_cnt, ctx->map_seed ) );
  FD_TEST( ctx->blockhash_map       );
  FD_TEST( ctx->nonce_blockhash_map );

  FD_TEST( tile->in_cnt<=sizeof( ctx->in )/sizeof( ctx->in[ 0 ] ) );
  for( ulong i=0UL; i<tile->in_cnt; i++ ) {
    fd_topo_link_t const * link = &topo->links[ tile->in_link_id[ i ] ];
    fd_topo_wksp_t const * link_wksp = &topo->workspaces[ topo->objs[ link->dcache_obj_id ].wksp_id ];

    if( FD_LIKELY( !strcmp( link->name, "replay_resol" ) ) ) ctx->in[i].kind = FD_RESOLH_IN_KIND_BANK;
    else                                                     ctx->in[i].kind = FD_RESOLH_IN_KIND_FRAGMENT;

    ctx->in[i].mem    = link_wksp->wksp;
    ctx->in[i].chunk0 = fd_dcache_compact_chunk0( ctx->in[i].mem, link->dcache );
    ctx->in[i].wmark  = fd_dcache_compact_wmark ( ctx->in[i].mem, link->dcache, link->mtu );
    ctx->in[i].mtu    = link->mtu;
  }

  ctx->out_mem    = topo->workspaces[ topo->objs[ topo->links[ tile->out_link_id[ 0 ] ].dcache_obj_id ].wksp_id ].wksp;
  ctx->out_chunk0 = fd_dcache_compact_chunk0( ctx->out_mem, topo->links[ tile->out_link_id[ 0 ] ].dcache );
  ctx->out_wmark  = fd_dcache_compact_wmark ( ctx->out_mem, topo->links[ tile->out_link_id[ 0 ] ].dcache, topo->links[ tile->out_link_id[ 0 ] ].mtu );
  ctx->out_chunk  = ctx->out_chunk0;

  ulong scratch_top = FD_SCRATCH_ALLOC_FINI( l, scratch_align() );
  if( FD_UNLIKELY( scratch_top > (ulong)scratch + scratch_footprint( tile ) ) )
    FD_LOG_ERR(( "scratch overflow %lu %lu %lu", scratch_top - (ulong)scratch - scratch_footprint( tile ), scratch_top, (ulong)scratch + scratch_footprint( tile ) ));
}

#define STEM_BURST (1UL)

#define STEM_CALLBACK_CONTEXT_TYPE  fd_resolh_tile_t
#define STEM_CALLBACK_CONTEXT_ALIGN alignof(fd_resolh_tile_t)

#define STEM_CALLBACK_METRICS_WRITE metrics_write
#define STEM_CALLBACK_AFTER_CREDIT  after_credit
#define STEM_CALLBACK_BEFORE_FRAG   before_frag
#define STEM_CALLBACK_DURING_FRAG   during_frag
#define STEM_CALLBACK_AFTER_FRAG    after_frag

#include "../../disco/stem/fd_stem.c"

fd_topo_run_tile_t fd_tile_resolh = {
  .name                     = "resolh",
  .populate_allowed_seccomp = NULL,
  .populate_allowed_fds     = NULL,
  .scratch_align            = scratch_align,
  .scratch_footprint        = scratch_footprint,
  .privileged_init          = privileged_init,
  .unprivileged_init        = unprivileged_init,
  .run                      = stem_run,
};
