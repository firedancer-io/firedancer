#include "fd_prune_finder.h"

#define FD_PRUNE_FINDER_ALIGN 32UL
#define FD_PRUNE_FINDER_MAGIC (0xf17eda2c379702e0UL) /* firedancer prune version 0*/

#define PRUNE_MIN_INGRESS_NODES   2UL
#define PRUNE_MIN_UPSERTS         20UL
#define PRUNE_STAKE_THRESHOLD_PCT 0.15

#define PF_DEBUG (0)

struct pubkey_private {
  uchar b[ 32UL ];
};

typedef struct pubkey_private pubkey_private_t;

struct fd_prune_relayer_score {
  ulong hit_count;
  ulong stake;
};

typedef struct fd_prune_relayer_score fd_prune_relayer_score_t;

static inline int
fd_prune_relayer_score_cmp( fd_prune_relayer_score_t const * a, fd_prune_relayer_score_t const * b ) {
  if( FD_UNLIKELY( a->hit_count!=b->hit_count ) ) {
    return (a->hit_count > b->hit_count) - (a->hit_count < b->hit_count);
  }
  return (a->stake > b->stake) - (a->stake < b->stake);
}

static inline int
fd_prune_relayer_score_lt( fd_prune_relayer_score_t const * a, fd_prune_relayer_score_t const * b ) {
  if( FD_UNLIKELY( a->hit_count!=b->hit_count ) ) {
    return a->hit_count < b->hit_count;
  }
  return a->stake < b->stake;
}

struct fd_prune_relayer {
  fd_pubkey_t              pubkey;
  fd_prune_relayer_score_t score[1];
  struct {
    ulong next;
  } pool;

  struct {
    ulong next;
    ulong prev;
  } map;

  struct {
    ulong next;
    ulong prev;
  } lru;

  struct {
    ulong parent;
    ulong left;
    ulong right;
    ulong prio;

    ulong next;
    ulong prev;
  } treap;
};

typedef struct fd_prune_relayer fd_prune_relayer_t;

#define POOL_NAME relayer_pool
#define POOL_NEXT pool.next
#define POOL_T    fd_prune_relayer_t
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME  relayer_map
#define MAP_ELE_T fd_prune_relayer_t
#define MAP_KEY_T fd_pubkey_t
#define MAP_KEY   pubkey
#define MAP_IDX_T ulong
#define MAP_NEXT  map.next
#define MAP_PREV  map.prev
#define MAP_KEY_HASH(k,s) ((s) ^ fd_ulong_load_8( (k)->uc ))
#define MAP_KEY_EQ(k0,k1) (!memcmp((k0)->uc, (k1)->uc, 32UL))
#define MAP_OPTIMIZE_RANDOM_ACCESS_REMOVAL 1
#include "../../util/tmpl/fd_map_chain.c"

#define DLIST_NAME  relayer_lru
#define DLIST_ELE_T fd_prune_relayer_t
#define DLIST_PREV  lru.prev
#define DLIST_NEXT  lru.next
#include "../../util/tmpl/fd_dlist.c"

#define TREAP_NAME      relayer_treap
#define TREAP_T         fd_prune_relayer_t
#define TREAP_QUERY_T   fd_prune_relayer_score_t
#define TREAP_CMP(q,e)  fd_prune_relayer_score_cmp( &(q), e->score )
#define TREAP_LT(e0,e1) fd_prune_relayer_score_lt( e0->score, e1->score )
#define TREAP_PARENT    treap.parent
#define TREAP_LEFT      treap.left
#define TREAP_RIGHT     treap.right
#define TREAP_PRIO      treap.prio
#define TREAP_NEXT      treap.next
#define TREAP_PREV      treap.prev
#define TREAP_OPTIMIZE_ITERATION 1
#include "../../util/tmpl/fd_treap.c"
struct fd_prune_origin {
  fd_pubkey_t pubkey;
  ulong       stake;

  ulong num_upserts;

  struct {
    fd_prune_relayer_t * pool;
    relayer_map_t *      map;
    relayer_lru_t *      lru;
    relayer_treap_t *    treap;
  } relayers;

  struct {
    ulong next;
  } pool;

  struct {
    ulong next;
    ulong prev;
  } map;

  struct {
    ulong next;
    ulong prev;
  } lru;
};

typedef struct fd_prune_origin fd_prune_origin_t;

#define POOL_NAME origin_pool
#define POOL_NEXT pool.next
#define POOL_T    fd_prune_origin_t
#include "../../util/tmpl/fd_pool.c"

#define DLIST_NAME  origin_lru_list
#define DLIST_ELE_T fd_prune_origin_t
#define DLIST_PREV  lru.prev
#define DLIST_NEXT  lru.next
#include "../../util/tmpl/fd_dlist.c"

#define MAP_NAME  origin_map
#define MAP_ELE_T fd_prune_origin_t
#define MAP_KEY_T fd_pubkey_t
#define MAP_KEY   pubkey
#define MAP_IDX_T ulong
#define MAP_NEXT  map.next
#define MAP_PREV  map.prev
#define MAP_KEY_HASH(k,s) ((s) ^ fd_ulong_load_8( (k)->uc ))
#define MAP_KEY_EQ(k0,k1) (!memcmp((k0)->uc, (k1)->uc, 32UL))
#define MAP_OPTIMIZE_RANDOM_ACCESS_REMOVAL 1
#include "../../util/tmpl/fd_map_chain.c"


#define POOL_NAME prunes_pool
#define POOL_NEXT pool.next
#define POOL_T    fd_prune_finder_prune_t
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME  prunes_map
#define MAP_ELE_T fd_prune_finder_prune_t
#define MAP_KEY_T fd_pubkey_t
#define MAP_KEY   relayer_pubkey
#define MAP_IDX_T ulong
#define MAP_NEXT  map.next
#define MAP_PREV  map.prev
#define MAP_KEY_HASH(k,s) ((s) ^ fd_ulong_load_8( (k)->uc ))
#define MAP_KEY_EQ(k0,k1) (!memcmp((k0)->uc, (k1)->uc, 32UL))
#define MAP_OPTIMIZE_RANDOM_ACCESS_REMOVAL 1
#include "../../util/tmpl/fd_map_chain.c"

#if PF_DEBUG
typedef struct {
  uchar relayer_pubkey[32];
  uchar origin_pubkey[32];
} prune_path_key_t;

typedef struct {
  prune_path_key_t key;
  ulong            prunes_sent;
  ulong            rx_after_pruned_cnt;
  long             last_rx_ts;

  long             first_prune_sent_ts;
  long             last_prune_sent_ts;

  struct {
    ulong next;
  } pool;

  struct {
    ulong next;
    ulong prev;
  } map;

  struct {
    ulong next;
    ulong prev;
  } lru;
} prune_path_t;

#define POOL_NAME debug_pruned_pool
#define POOL_NEXT pool.next
#define POOL_T    prune_path_t
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME  debug_pruned_map
#define MAP_ELE_T prune_path_t
#define MAP_KEY_T prune_path_key_t
#define MAP_KEY   key
#define MAP_IDX_T ulong
#define MAP_NEXT  map.next
#define MAP_PREV  map.prev
#define MAP_KEY_HASH(k,s) ((s) ^ fd_ulong_load_8( (k)->relayer_pubkey ) ^ fd_ulong_load_8( (k)->origin_pubkey ))
#define MAP_KEY_EQ(k0,k1) ( !memcmp((k0)->relayer_pubkey, (k1)->relayer_pubkey, 32UL) && !memcmp((k0)->origin_pubkey, (k1)->origin_pubkey, 32UL) )
#define MAP_OPTIMIZE_RANDOM_ACCESS_REMOVAL 1
#include "../../util/tmpl/fd_map_chain.c"

#define DLIST_NAME  debug_pruned_lru
#define DLIST_ELE_T prune_path_t
#define DLIST_PREV  lru.prev
#define DLIST_NEXT  lru.next
#include "../../util/tmpl/fd_dlist.c"

#endif

struct fd_prune_finder_private {
  fd_prune_finder_metrics_t metrics[1];

  fd_prune_origin_t * pool;
  origin_map_t *      origins;
  origin_lru_list_t * lru;

  struct {
    fd_prune_finder_prune_t * pool;
    prunes_map_t *            map;
    ulong                     count;
  } prunes;

#if PF_DEBUG
  struct {
    prune_path_t *       pool;
    debug_pruned_map_t * map;
    debug_pruned_lru_t * lru;
  } debug;
#endif

  ulong magic;
};

FD_FN_CONST ulong
fd_prune_finder_align( void ) {
  return 32UL;
}

FD_FN_CONST ulong
fd_prune_finder_footprint( ulong origin_max, ulong relayer_max_per_origin ) {
  ulong l;
  l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, fd_prune_finder_align(), sizeof(fd_prune_finder_t) );
  l = FD_LAYOUT_APPEND( l, origin_pool_align(), origin_pool_footprint( origin_max ) );
  l = FD_LAYOUT_APPEND( l, origin_map_align(),  origin_map_footprint( origin_map_chain_cnt_est( origin_max ) ) );
  l = FD_LAYOUT_APPEND( l, origin_lru_list_align(), origin_lru_list_footprint() );
  l = FD_LAYOUT_APPEND( l, prunes_pool_align(), prunes_pool_footprint( relayer_max_per_origin*FD_GOSSIP_MSG_MAX_CRDS ) );
  l = FD_LAYOUT_APPEND( l, prunes_map_align(),  prunes_map_footprint( prunes_map_chain_cnt_est( relayer_max_per_origin*FD_GOSSIP_MSG_MAX_CRDS ) ) );

#if PF_DEBUG
  ulong debug_pruned_pool_cnt = origin_max * relayer_max_per_origin / 10;
  l = FD_LAYOUT_APPEND( l, debug_pruned_pool_align(), debug_pruned_pool_footprint( debug_pruned_pool_cnt ) );
  l = FD_LAYOUT_APPEND( l, debug_pruned_map_align(),  debug_pruned_map_footprint( debug_pruned_map_chain_cnt_est( debug_pruned_pool_cnt ) ) );
  l = FD_LAYOUT_APPEND( l, debug_pruned_lru_align(),  debug_pruned_lru_footprint() );
#endif

  for( ulong i=0UL; i<origin_max; i++ ) {
    l = FD_LAYOUT_APPEND( l, relayer_pool_align(), relayer_pool_footprint( relayer_max_per_origin ) );
    l = FD_LAYOUT_APPEND( l, relayer_map_align(),  relayer_map_footprint( relayer_map_chain_cnt_est( relayer_max_per_origin ) ) );
    l = FD_LAYOUT_APPEND( l, relayer_lru_align(),  relayer_lru_footprint() );
    l = FD_LAYOUT_APPEND( l, relayer_treap_align(), relayer_treap_footprint( relayer_max_per_origin ) );
  }
  l = FD_LAYOUT_FINI( l, fd_prune_finder_align() );
  return l;
}

void *
fd_prune_finder_new( void * shmem, ulong origin_max, ulong relayer_max_per_origin, fd_rng_t * rng ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_prune_finder_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }
  if( FD_UNLIKELY( !rng ) ) {
    FD_LOG_WARNING(( "NULL rng" ));
    return NULL;
  }

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_prune_finder_t * pf = FD_SCRATCH_ALLOC_APPEND( l, fd_prune_finder_align(),            sizeof(fd_prune_finder_t) );
  void * _origins_pool   = FD_SCRATCH_ALLOC_APPEND( l, origin_pool_align(),              origin_pool_footprint( origin_max ) );
  void * _origins_map    = FD_SCRATCH_ALLOC_APPEND( l, origin_map_align(),               origin_map_footprint( origin_map_chain_cnt_est( origin_max ) ) );
  void * _origins_lru    = FD_SCRATCH_ALLOC_APPEND( l, origin_lru_list_align(),          origin_lru_list_footprint() );
  void * _prunes_pool    = FD_SCRATCH_ALLOC_APPEND( l, prunes_pool_align(),              prunes_pool_footprint( relayer_max_per_origin*FD_GOSSIP_MSG_MAX_CRDS ) );
  void * _prunes_map     = FD_SCRATCH_ALLOC_APPEND( l, prunes_map_align(),               prunes_map_footprint( prunes_map_chain_cnt_est( relayer_max_per_origin*FD_GOSSIP_MSG_MAX_CRDS ) ) );

  pf->pool = origin_pool_join( origin_pool_new( _origins_pool, origin_max ) );
  FD_TEST( pf->pool );

  pf->origins = origin_map_join( origin_map_new( _origins_map, origin_map_chain_cnt_est( origin_max ), fd_rng_ulong( rng ) ) );
  FD_TEST( pf->origins );

  pf->lru = origin_lru_list_join( origin_lru_list_new( _origins_lru ) );
  FD_TEST( pf->lru );

  pf->prunes.pool = prunes_pool_join( prunes_pool_new( _prunes_pool, relayer_max_per_origin*FD_GOSSIP_MSG_MAX_CRDS ) );
  FD_TEST( pf->prunes.pool );

  pf->prunes.map = prunes_map_join( prunes_map_new( _prunes_map, prunes_map_chain_cnt_est( relayer_max_per_origin*FD_GOSSIP_MSG_MAX_CRDS ), fd_rng_ulong( rng ) ) );
  FD_TEST( pf->prunes.map );

  pf->prunes.count = 0UL;

  for( ulong i=0UL; i<origin_max; i++ ) {
    fd_prune_origin_t * origin = &pf->pool[i];

    void * _relayers_pool  = FD_SCRATCH_ALLOC_APPEND( l, relayer_pool_align(), relayer_pool_footprint( relayer_max_per_origin ) );
    void * _relayers_map   = FD_SCRATCH_ALLOC_APPEND( l, relayer_map_align(),  relayer_map_footprint( relayer_map_chain_cnt_est( relayer_max_per_origin ) ) );
    void * _relayers_lru   = FD_SCRATCH_ALLOC_APPEND( l, relayer_lru_align(),  relayer_lru_footprint() );
    void * _relayers_treap = FD_SCRATCH_ALLOC_APPEND( l, relayer_treap_align(), relayer_treap_footprint( relayer_max_per_origin ) );

    origin->relayers.pool = relayer_pool_join( relayer_pool_new( _relayers_pool, relayer_max_per_origin ) );
    FD_TEST( origin->relayers.pool );

    origin->relayers.map = relayer_map_join( relayer_map_new( _relayers_map, relayer_map_chain_cnt_est( relayer_max_per_origin ), fd_rng_ulong( rng ) ) );
    FD_TEST( origin->relayers.map );

    origin->relayers.lru = relayer_lru_join( relayer_lru_new( _relayers_lru ) );
    FD_TEST( origin->relayers.lru );

    origin->relayers.treap = relayer_treap_join( relayer_treap_new( _relayers_treap, relayer_max_per_origin ) );
    relayer_treap_seed( origin->relayers.pool, relayer_max_per_origin, fd_rng_ulong( rng ) );
    FD_TEST( origin->relayers.treap );
  }
  FD_SCRATCH_ALLOC_FINI( l, fd_prune_finder_align() );
  fd_memset( pf->metrics, 0, sizeof(fd_prune_finder_metrics_t) );

#if PF_DEBUG
  ulong debug_pruned_pool_cnt = origin_max * relayer_max_per_origin / 10;
  void * _debug_pruned_pool = FD_SCRATCH_ALLOC_APPEND( l, debug_pruned_pool_align(), debug_pruned_pool_footprint( debug_pruned_pool_cnt ) );
  void * _debug_pruned_map  = FD_SCRATCH_ALLOC_APPEND( l, debug_pruned_map_align(),  debug_pruned_map_footprint( debug_pruned_map_chain_cnt_est( debug_pruned_pool_cnt ) ) );
  void * _debug_pruned_lru  = FD_SCRATCH_ALLOC_APPEND( l, debug_pruned_lru_align(),  debug_pruned_lru_footprint() );
  pf->debug.pool = debug_pruned_pool_join( debug_pruned_pool_new( _debug_pruned_pool, debug_pruned_pool_cnt ) );
  FD_TEST( pf->debug.pool );
  pf->debug.map  = debug_pruned_map_join( debug_pruned_map_new( _debug_pruned_map, debug_pruned_map_chain_cnt_est( debug_pruned_pool_cnt ), fd_rng_ulong( rng ) ) );
  FD_TEST( pf->debug.map );
  pf->debug.lru  = debug_pruned_lru_join( debug_pruned_lru_new( _debug_pruned_lru ) );
  FD_TEST( pf->debug.lru );
#endif

  FD_COMPILER_MFENCE();
  FD_VOLATILE( pf->magic ) = FD_PRUNE_FINDER_MAGIC;
  FD_COMPILER_MFENCE();

  return shmem;
}

fd_prune_finder_t *
fd_prune_finder_join( void * shpf ) {
  if( FD_UNLIKELY( !shpf ) ) {
    FD_LOG_WARNING(( "NULL shpf" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shpf, fd_prune_finder_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shpf" ));
    return NULL;
  }
  fd_prune_finder_t * pf = (fd_prune_finder_t *)shpf;
  if( FD_UNLIKELY( pf->magic!=FD_PRUNE_FINDER_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }
  return pf;
}

fd_prune_finder_metrics_t const *
fd_prune_finder_metrics( fd_prune_finder_t const * pf ) {
  return pf->metrics;
}

static inline void
reset_origin_state( fd_prune_origin_t * origin ) {
  while( !relayer_lru_is_empty( origin->relayers.lru, origin->relayers.pool ) ) {
    fd_prune_relayer_t * r = relayer_lru_ele_pop_head( origin->relayers.lru, origin->relayers.pool );
    relayer_map_ele_remove( origin->relayers.map, &r->pubkey, NULL, origin->relayers.pool );
    relayer_treap_ele_remove( origin->relayers.treap, r, origin->relayers.pool );
    relayer_pool_ele_release( origin->relayers.pool, r );
  }
  origin->num_upserts = 0UL;
}

static inline void
update_relayer_score( fd_prune_origin_t *         origin,
                      fd_prune_finder_metrics_t * metrics,
                      uchar const *               relayer,
                      ulong                       relayer_stake,
                      ulong                       num_dups ) {
  fd_prune_relayer_t * r = relayer_map_ele_query( origin->relayers.map, fd_type_pun_const( relayer ), NULL, origin->relayers.pool );
  int needs_treap_reinsert = 0;
  if( FD_UNLIKELY( !r ) ) {
    if( FD_LIKELY( relayer_pool_free( origin->relayers.pool ) ) ) {
      r = relayer_pool_ele_acquire( origin->relayers.pool );
    } else {
      r = relayer_lru_ele_pop_head( origin->relayers.lru,   origin->relayers.pool );
      relayer_map_ele_remove      ( origin->relayers.map,   &r->pubkey, NULL, origin->relayers.pool );
      relayer_treap_ele_remove    ( origin->relayers.treap, r, origin->relayers.pool );
      metrics->origin_relayer_evicted_cnt++;
    }
    r->score[0].hit_count = 0UL;
    r->score[0].stake     = relayer_stake;
    fd_memcpy( r->pubkey.uc, relayer, 32UL );

    relayer_map_ele_insert   ( origin->relayers.map,   r, origin->relayers.pool );
    relayer_lru_ele_push_tail( origin->relayers.lru,   r, origin->relayers.pool );
    relayer_treap_ele_insert ( origin->relayers.treap, r, origin->relayers.pool );
    metrics->record_insertions_cnt++;
  } else {
    /* Move to back of the LRU list */
    relayer_lru_ele_remove   ( origin->relayers.lru, r, origin->relayers.pool );
    relayer_lru_ele_push_tail( origin->relayers.lru, r, origin->relayers.pool );
    if( FD_UNLIKELY( r->score[0].stake!=relayer_stake ) ) {
      /* Modifying treap query, need to remove before modifying. Check if already removed with needs_treap_reinsert */
      if( FD_LIKELY( !needs_treap_reinsert ) ) relayer_treap_ele_remove( origin->relayers.treap, r, origin->relayers.pool );
      r->score[0].stake = relayer_stake;
      needs_treap_reinsert = 1;
    }
  }
  if( FD_LIKELY( num_dups<2UL ) ) {
    if( FD_LIKELY( !needs_treap_reinsert ) ) relayer_treap_ele_remove( origin->relayers.treap, r, origin->relayers.pool );
    r->score[0].hit_count++;
    needs_treap_reinsert = 1;
  }

  if( FD_LIKELY( needs_treap_reinsert ) ) {
    relayer_treap_ele_insert( origin->relayers.treap, r, origin->relayers.pool );
    metrics->record_insertions_cnt++;
  }
}

void
fd_prune_finder_record( fd_prune_finder_t * pf,
                        uchar const *       origin_pubkey,
                        ulong               origin_stake,
                        uchar const *       relayer_pubkey,
                        ulong               relayer_stake,
                        ulong               num_dups  ) {
  fd_prune_origin_t * origin = origin_map_ele_query( pf->origins, fd_type_pun_const( origin_pubkey ), NULL, pf->pool );

  if( FD_UNLIKELY( !origin ) ) {
    if( FD_LIKELY( origin_pool_free( pf->pool ) ) ) {
      origin = origin_pool_ele_acquire( pf->pool );
    } else {
      origin = origin_lru_list_ele_pop_head( pf->lru, pf->pool );
      reset_origin_state( origin );
      origin_map_ele_remove( pf->origins, &origin->pubkey, NULL, pf->pool );
      pf->metrics->origin_evicted_cnt++;
    }
    origin->num_upserts = 0UL;
    fd_memcpy( origin->pubkey.uc, origin_pubkey, 32UL );

    origin_map_ele_insert( pf->origins, origin, pf->pool );
    origin_lru_list_ele_push_tail( pf->lru, origin, pf->pool );
  } else {
    /* Move to back of the LRU list */
    origin_lru_list_ele_remove   ( pf->lru, origin, pf->pool );
    origin_lru_list_ele_push_tail( pf->lru, origin, pf->pool );
  }

  origin->stake = origin_stake;
  if( FD_UNLIKELY( !num_dups ) ) origin->num_upserts++;
  update_relayer_score( origin, pf->metrics, relayer_pubkey, relayer_stake, num_dups );
#if PF_DEBUG
  prune_path_key_t key = { .relayer_pubkey = {0}, .origin_pubkey = {0} };
  fd_memcpy( key.relayer_pubkey, relayer_pubkey, 32UL );
  fd_memcpy( key.origin_pubkey , origin_pubkey , 32UL );
  prune_path_t * pp = debug_pruned_map_ele_query( pf->debug.map, &key, NULL, pf->debug.pool );
  if( FD_LIKELY( pp ) ) {
    pp->rx_after_pruned_cnt++;
    pp->last_rx_ts = fd_log_wallclock();
    pf->metrics->rx_from_pruned_path_cnt++;
    debug_pruned_lru_ele_remove( pf->debug.lru, pp, pf->debug.pool );
    debug_pruned_lru_ele_push_tail( pf->debug.lru, pp, pf->debug.pool );
  }
#endif
}

/* Akin to ReceivedCacheEntry::prune */
static inline void
prune_origin( fd_prune_finder_t * pf,
              fd_prune_origin_t * origin,
              ulong               my_stake ) {
  if( FD_LIKELY( relayer_pool_used( origin->relayers.pool )<=PRUNE_MIN_INGRESS_NODES ) ) return;

  /* TODO: the use of minimum aggregate ingress stake threshold is quite weird to me, discuss with Michael/Greg
      https://github.com/solana-labs/solana/issues/3214#issuecomment-475211810 */
  ulong min_ingress_stake = (ulong)(PRUNE_STAKE_THRESHOLD_PCT*(double)fd_ulong_min( my_stake, origin->stake ));

  relayer_treap_rev_iter_t it = relayer_treap_rev_iter_init( origin->relayers.treap, origin->relayers.pool );
  pf->metrics->relayer_treap_traversals_cnt++;

  /* Skip first PRUNE_MIN_INGRESS_NODES for threshold checks */
  for( ulong skip=0; skip<PRUNE_MIN_INGRESS_NODES && !relayer_treap_rev_iter_done( it ); skip++ ) it = relayer_treap_rev_iter_next( it, origin->relayers.pool );

  /* Skip until min_ingress_stake threshold is exceeded */
  ulong cumulative_stake = 0UL;
  while( !relayer_treap_rev_iter_done( it ) ) {
    fd_prune_relayer_t const * r = relayer_treap_rev_iter_ele_const( it, origin->relayers.pool );
    cumulative_stake += r->score[0].stake;
    if( FD_LIKELY( cumulative_stake>=min_ingress_stake ) ) break;
    it = relayer_treap_rev_iter_next( it, origin->relayers.pool );
  }
  while( !relayer_treap_rev_iter_done( it ) ) {
    fd_prune_relayer_t const * r = relayer_treap_rev_iter_ele_const( it, origin->relayers.pool );

    fd_prune_finder_prune_t * p = prunes_map_ele_query( pf->prunes.map, &r->pubkey, NULL, pf->prunes.pool );
    if( FD_UNLIKELY( !p ) ) {
      p = prunes_pool_ele( pf->prunes.pool, pf->prunes.count );
      fd_memcpy( p->relayer_pubkey.uc, r->pubkey.uc, 32UL );
      p->prune_len = 0UL;
      prunes_map_ele_insert( pf->prunes.map, p, pf->prunes.pool );
      pf->prunes.count++;
    }
    FD_TEST( p->prune_len<FD_GOSSIP_MSG_MAX_CRDS );
    fd_memcpy( p->prunes[ p->prune_len ].uc, origin->pubkey.uc, 32UL );
    p->prune_len++;
    it = relayer_treap_rev_iter_next( it, origin->relayers.pool );
#if PF_DEBUG
    prune_path_key_t key = { .relayer_pubkey = {0}, .origin_pubkey = {0} };
    fd_memcpy( key.relayer_pubkey, r->pubkey.uc, 32UL );
    fd_memcpy( key.origin_pubkey, origin->pubkey.uc, 32UL );
    prune_path_t * pp = debug_pruned_map_ele_query( pf->debug.map, &key, NULL, pf->debug.pool );
    long now = fd_log_wallclock();
    if( FD_LIKELY( !pp ) ) {
      if( FD_LIKELY( debug_pruned_pool_free( pf->debug.pool ) ) ) {
        pp = debug_pruned_pool_ele_acquire( pf->debug.pool );
      } else {
        pp = debug_pruned_lru_ele_pop_head( pf->debug.lru, pf->debug.pool );
        debug_pruned_map_ele_remove( pf->debug.map, &pp->key, NULL, pf->debug.pool );
      }
      pp->key                 = key;
      pp->prunes_sent         = 0UL;
      pp->rx_after_pruned_cnt = 0UL;
      pp->last_rx_ts          = 0L;
      pp->first_prune_sent_ts = now;
      pp->last_prune_sent_ts  = 0L;
      debug_pruned_map_ele_insert( pf->debug.map, pp, pf->debug.pool );
      debug_pruned_lru_ele_push_tail( pf->debug.lru, pp, pf->debug.pool );
    }
    pp->prunes_sent++;
    pp->last_prune_sent_ts = now;
#endif
  }
}

void
fd_prune_finder_get_prunes( fd_prune_finder_t *               pf,
                            ulong                             my_stake,
                            uchar const * const *             origins,
                            ulong                             origins_len,
                            fd_prune_finder_prune_t const **  out_prunes,
                            ulong *                           out_prunes_len ) {
  /* Clear out current prunes map */
  for( ulong i=0UL; i<pf->prunes.count; i++ ) {
    fd_prune_finder_prune_t * p = prunes_pool_ele( pf->prunes.pool, i );
    prunes_map_ele_remove( pf->prunes.map, &p->relayer_pubkey, NULL, pf->prunes.pool );
  }
  pf->prunes.count = 0UL;

  FD_TEST( origins_len<=FD_GOSSIP_MSG_MAX_CRDS );
  for( ulong i=0UL; i<origins_len; i++ ) {
    fd_prune_origin_t * origin = origin_map_ele_query( pf->origins, fd_type_pun_const( origins[i] ), NULL, pf->pool );
    /* Impossible because all origins must have been recorded at least once prior to a get_prunes call */
    FD_TEST( origin );

    /* Akin to ReceivedCache::prune */
    if( FD_LIKELY( origin->num_upserts<PRUNE_MIN_UPSERTS ) ) continue;
    prune_origin( pf, origin, my_stake );
    reset_origin_state( origin );
  }
#if PF_DEBUG
  /* Evict debug pruned paths that haven't been updated in a while */
  long now = fd_log_wallclock();
  while( !debug_pruned_lru_is_empty( pf->debug.lru, pf->debug.pool ) ) {
    prune_path_t * p = debug_pruned_lru_ele_peek_head( pf->debug.lru, pf->debug.pool );

    long last_update = !!p->last_rx_ts ? p->last_rx_ts : p->first_prune_sent_ts;
    if( FD_LIKELY( now - last_update < 10*1000*1000*1000L ) ) break;

    if( !p->last_rx_ts ) {
      FD_LOG_NOTICE(( "Evicting pruned path from tracking: prunes sent %lu, no rx after pruned", p->prunes_sent ));
    } else {
      FD_LOG_NOTICE(( "Evicting pruned path from tracking: prunes sent %lu, %lu rx'd after prune, %ldms between first prune sent and last rx, %ldms between last prune sent and last rx",
                      p->prunes_sent,
                      p->rx_after_pruned_cnt,
                      (p->last_rx_ts - p->first_prune_sent_ts)/1000000L,
                      (p->last_rx_ts - p->last_prune_sent_ts )/1000000L ));
    }

    debug_pruned_lru_ele_pop_head( pf->debug.lru, pf->debug.pool );
    debug_pruned_map_ele_remove( pf->debug.map, &p->key, NULL, pf->debug.pool );
    debug_pruned_pool_ele_release( pf->debug.pool, p );
  }
#endif
  *out_prunes = prunes_pool_ele( pf->prunes.pool, 0UL );
  *out_prunes_len = pf->prunes.count;
}
