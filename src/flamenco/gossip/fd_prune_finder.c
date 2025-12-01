#include "fd_prune_finder.h"

#define FD_PRUNE_FINDER_ALIGN 32UL
#define FD_PRUNE_FINDER_MAGIC (0xf17eda2c379702e0UL) /* firedancer prune version 0*/

struct pubkey_private {
  uchar b[ 32UL ];
};

typedef struct pubkey_private pubkey_private_t;

struct relayer_score {
  ulong hit_count;
  ulong stake;
};

typedef struct relayer_score relayer_score_t;

static inline int
relayer_score_lt( relayer_score_t const * a, relayer_score_t const * b ) {
  if( FD_UNLIKELY( a->hit_count!=b->hit_count ) ) {
    return a->hit_count < b->hit_count;
  }
  return a->stake < b->stake;
}

struct origin_relayer {
  fd_pubkey_t     pubkey;
  relayer_score_t score[1];
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

typedef struct origin_relayer origin_relayer_t;

#define SORT_NAME        relayer_score_desc
#define SORT_KEY_T       origin_relayer_t *
#define SORT_BEFORE(a,b) relayer_score_lt( (b)->score, (a)->score )
#include "../../util/tmpl/fd_sort.c"

#define POOL_NAME relayer_pool
#define POOL_NEXT pool.next
#define POOL_T    origin_relayer_t
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME  relayer_map
#define MAP_ELE_T origin_relayer_t
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
#define DLIST_ELE_T origin_relayer_t
#define DLIST_PREV  lru.prev
#define DLIST_NEXT  lru.next
#include "../../util/tmpl/fd_dlist.c"

struct fd_prune_origin {
  fd_pubkey_t pubkey;
  ulong       stake;
  ulong       num_upserts;

  struct {
    origin_relayer_t * pool;
    relayer_map_t *    map;
    relayer_lru_t *    lru;
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

struct fd_prune_finder_prune {
  fd_relayer_prune_data_t relayer_prunes[ 1 ];

   struct {
    ulong next;
  } pool;

  struct {
    ulong next;
    ulong prev;
  } map;
};

typedef struct fd_prune_finder_prune fd_prune_finder_prune_t;

#define POOL_NAME prunes_pool
#define POOL_NEXT pool.next
#define POOL_T    fd_prune_finder_prune_t
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME  prunes_map
#define MAP_ELE_T fd_prune_finder_prune_t
#define MAP_KEY_T fd_pubkey_t
#define MAP_KEY   relayer_prunes->relayer_pubkey
#define MAP_IDX_T ulong
#define MAP_NEXT  map.next
#define MAP_PREV  map.prev
#define MAP_KEY_HASH(k,s) ((s) ^ fd_ulong_load_8( (k)->uc ))
#define MAP_KEY_EQ(k0,k1) (!memcmp((k0)->uc, (k1)->uc, 32UL))
#define MAP_OPTIMIZE_RANDOM_ACCESS_REMOVAL 1
#include "../../util/tmpl/fd_map_chain.c"

struct fd_prune_finder_private {
  fd_prune_finder_metrics_t metrics[1];

  fd_prune_origin_t * pool;
  origin_map_t *      origins;
  origin_lru_list_t * lru;

  /* Scratch space used by prune_origin() for relayer score sorting. */
  struct{
    origin_relayer_t ** relayers;
    void *              sort_scratch;
  } prune_origin_scratch;

  /* Static pool of relayer prunes populated updated every
     fd_prune_finder_get_prunes() call */
  struct {
    fd_prune_finder_prune_t * pool;
    prunes_map_t *            map;
    ulong                     count;
  } prunes;

  ulong magic;
};

FD_FN_CONST ulong
fd_prune_finder_align( void ) {
  return 128UL;
}

FD_FN_CONST ulong
fd_prune_finder_footprint( ulong origin_max, ulong relayer_max_per_origin ) {
  ulong l;
  l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, fd_prune_finder_align(), sizeof(fd_prune_finder_t)                                      );
  l = FD_LAYOUT_APPEND( l, origin_pool_align(),     origin_pool_footprint( origin_max )                            );
  l = FD_LAYOUT_APPEND( l, origin_map_align(),      origin_map_footprint( origin_map_chain_cnt_est( origin_max ) ) );
  l = FD_LAYOUT_APPEND( l, origin_lru_list_align(), origin_lru_list_footprint()                                    );

  l = FD_LAYOUT_APPEND( l, alignof(origin_relayer_t),                 sizeof(origin_relayer_t*)*relayer_max_per_origin                      );
  l = FD_LAYOUT_APPEND( l, relayer_score_desc_stable_scratch_align(), relayer_score_desc_stable_scratch_footprint( relayer_max_per_origin ) );

  l = FD_LAYOUT_APPEND( l, prunes_pool_align(), prunes_pool_footprint( relayer_max_per_origin*FD_GOSSIP_MSG_MAX_CRDS )                            );
  l = FD_LAYOUT_APPEND( l, prunes_map_align(),  prunes_map_footprint( prunes_map_chain_cnt_est( relayer_max_per_origin*FD_GOSSIP_MSG_MAX_CRDS ) ) );

  for( ulong i=0UL; i<origin_max; i++ ) {
    l = FD_LAYOUT_APPEND( l, relayer_pool_align(), relayer_pool_footprint( relayer_max_per_origin )                             );
    l = FD_LAYOUT_APPEND( l, relayer_map_align(),  relayer_map_footprint( relayer_map_chain_cnt_est( relayer_max_per_origin ) ) );
    l = FD_LAYOUT_APPEND( l, relayer_lru_align(),  relayer_lru_footprint()                                                      );
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
  fd_prune_finder_t * pf = FD_SCRATCH_ALLOC_APPEND( l, fd_prune_finder_align(), sizeof(fd_prune_finder_t)                                      );
  void * _origins_pool   = FD_SCRATCH_ALLOC_APPEND( l, origin_pool_align(),     origin_pool_footprint( origin_max )                            );
  void * _origins_map    = FD_SCRATCH_ALLOC_APPEND( l, origin_map_align(),      origin_map_footprint( origin_map_chain_cnt_est( origin_max ) ) );
  void * _origins_lru    = FD_SCRATCH_ALLOC_APPEND( l, origin_lru_list_align(), origin_lru_list_footprint()                                    );

  pf->prune_origin_scratch.relayers     = FD_SCRATCH_ALLOC_APPEND( l, alignof(origin_relayer_t),                 sizeof(origin_relayer_t*)*relayer_max_per_origin                      );
  pf->prune_origin_scratch.sort_scratch = FD_SCRATCH_ALLOC_APPEND( l, relayer_score_desc_stable_scratch_align(), relayer_score_desc_stable_scratch_footprint( relayer_max_per_origin ) );

  void * _prunes_pool = FD_SCRATCH_ALLOC_APPEND( l, prunes_pool_align(), prunes_pool_footprint( relayer_max_per_origin*FD_GOSSIP_MSG_MAX_CRDS )                            );
  void * _prunes_map  = FD_SCRATCH_ALLOC_APPEND( l, prunes_map_align(),  prunes_map_footprint( prunes_map_chain_cnt_est( relayer_max_per_origin*FD_GOSSIP_MSG_MAX_CRDS ) ) );

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

    void * _relayers_pool = FD_SCRATCH_ALLOC_APPEND( l, relayer_pool_align(), relayer_pool_footprint( relayer_max_per_origin )                             );
    void * _relayers_map  = FD_SCRATCH_ALLOC_APPEND( l, relayer_map_align(),  relayer_map_footprint( relayer_map_chain_cnt_est( relayer_max_per_origin ) ) );
    void * _relayers_lru  = FD_SCRATCH_ALLOC_APPEND( l, relayer_lru_align(),  relayer_lru_footprint()                                                      );

    origin->relayers.pool = relayer_pool_join( relayer_pool_new( _relayers_pool, relayer_max_per_origin ) );
    FD_TEST( origin->relayers.pool );

    origin->relayers.map = relayer_map_join( relayer_map_new( _relayers_map, relayer_map_chain_cnt_est( relayer_max_per_origin ), fd_rng_ulong( rng ) ) );
    FD_TEST( origin->relayers.map );

    origin->relayers.lru = relayer_lru_join( relayer_lru_new( _relayers_lru ) );
    FD_TEST( origin->relayers.lru );
  }
  fd_memset( pf->metrics, 0, sizeof(fd_prune_finder_metrics_t) );
  FD_SCRATCH_ALLOC_FINI( l, fd_prune_finder_align() );

  FD_TEST( (ulong)shmem + fd_prune_finder_footprint( origin_max, relayer_max_per_origin )==_l );

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
    origin_relayer_t * r = relayer_lru_ele_pop_head( origin->relayers.lru, origin->relayers.pool );
    relayer_map_ele_remove( origin->relayers.map, &r->pubkey, NULL, origin->relayers.pool );
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
  origin_relayer_t * r = relayer_map_ele_query( origin->relayers.map, fd_type_pun_const( relayer ), NULL, origin->relayers.pool );
  if( FD_UNLIKELY( !r ) ) {
    if( FD_LIKELY( relayer_pool_free( origin->relayers.pool ) ) ) {
      r = relayer_pool_ele_acquire( origin->relayers.pool );
    } else {
      r = relayer_lru_ele_pop_head( origin->relayers.lru, origin->relayers.pool );
      relayer_map_ele_remove      ( origin->relayers.map, &r->pubkey, NULL, origin->relayers.pool );
      metrics->origin_relayer_evicted_cnt++;
    }
    r->score->hit_count = 0UL;
    fd_memcpy( r->pubkey.uc, relayer, 32UL );

    relayer_map_ele_insert   ( origin->relayers.map, r, origin->relayers.pool );
    relayer_lru_ele_push_tail( origin->relayers.lru, r, origin->relayers.pool );
  } else {
    /* Move to back of the LRU list */
    relayer_lru_ele_remove   ( origin->relayers.lru, r, origin->relayers.pool );
    relayer_lru_ele_push_tail( origin->relayers.lru, r, origin->relayers.pool );
  }

  r->score->stake = relayer_stake;
  if( FD_LIKELY( num_dups<FD_PRUNE_MIN_INGRESS_NODES ) ) {
    r->score->hit_count++;
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
}

/* Akin to ReceivedCacheEntry::prune */
static inline void
prune_origin( fd_prune_finder_t * pf,
              fd_prune_origin_t * origin,
              ulong               my_stake ) {
  if( FD_LIKELY( relayer_pool_used( origin->relayers.pool )<=FD_PRUNE_MIN_INGRESS_NODES ) ) return;

  /* https://github.com/solana-labs/solana/issues/3214#issuecomment-475211810 */
  ulong min_ingress_stake = (ulong)(FD_PRUNE_STAKE_THRESHOLD_PCT*(double)fd_ulong_min( my_stake, origin->stake ));

  /* Sort relayers, start with copying relayer ptrs into contiguous array */
  relayer_map_iter_t it = relayer_map_iter_init( origin->relayers.map, origin->relayers.pool );
  ulong cnt = 0UL;
  while( !relayer_map_iter_done( it, origin->relayers.map, origin->relayers.pool ) ) {
    pf->prune_origin_scratch.relayers[cnt] = relayer_map_iter_ele ( it, origin->relayers.map, origin->relayers.pool );
    it                                     = relayer_map_iter_next( it, origin->relayers.map, origin->relayers.pool );
    cnt++;
  }
  FD_TEST( cnt==relayer_pool_used( origin->relayers.pool ) );

  /* Sort relayers by score */
  origin_relayer_t ** sorted_relayers = relayer_score_desc_stable_fast( pf->prune_origin_scratch.relayers, cnt, pf->prune_origin_scratch.sort_scratch );

  /* Skip first FD_PRUNE_MIN_INGRESS_NODES, but add them to cumulative
     stake */
  ulong i                = 0UL;
  ulong cumulative_stake = 0UL;
  for( ; i<FD_PRUNE_MIN_INGRESS_NODES && i<cnt; i++ ) {
    cumulative_stake += sorted_relayers[i]->score->stake;
  }

  /* Skip until min_ingress_stake threshold is exceeded */
  while( i<cnt ) {
    /* https://github.com/firedancer-io/agave/blob/01781bb975bf9f91a789288837021f7eb89b9cb8/gossip/src/received_cache.rs#L116-L122 */
    if( FD_LIKELY( cumulative_stake>=min_ingress_stake ) ) break;
    cumulative_stake += sorted_relayers[i]->score->stake;
    i++;
  }

  while( i<cnt ) {
    origin_relayer_t const *         r = sorted_relayers[i];
    fd_prune_finder_prune_t * p = prunes_map_ele_query( pf->prunes.map, &r->pubkey, NULL, pf->prunes.pool );

    if( FD_UNLIKELY( !p ) ) {
      FD_TEST( pf->prunes.count<prunes_pool_max( pf->prunes.pool ) );
      p = prunes_pool_ele( pf->prunes.pool, pf->prunes.count );
      fd_memcpy( p->relayer_prunes->relayer_pubkey.uc, r->pubkey.uc, 32UL );
      p->relayer_prunes->prune_len = 0UL;

      prunes_map_ele_insert( pf->prunes.map, p, pf->prunes.pool );
      pf->prunes.count++;
    }
    FD_TEST( p->relayer_prunes->prune_len<FD_GOSSIP_MSG_MAX_CRDS );
    fd_memcpy( p->relayer_prunes->prunes[ p->relayer_prunes->prune_len ].uc, origin->pubkey.uc, 32UL );
    p->relayer_prunes->prune_len++;
    i++;
  }
}

fd_prune_data_iter_t
fd_prune_finder_relayer_prune_data_iter_next( fd_prune_finder_t * pf, fd_prune_data_iter_t iter ) {
  (void)pf;
  return iter+1UL;
}

fd_relayer_prune_data_t const *
fd_prune_finder_relayer_prune_data_iter_ele( fd_prune_finder_t * pf, fd_prune_data_iter_t iter ) {
  FD_TEST( iter<pf->prunes.count );
  fd_prune_finder_prune_t * p = prunes_pool_ele( pf->prunes.pool, iter );
  return p->relayer_prunes;
}

int
fd_prune_finder_relayer_prune_data_iter_done( fd_prune_finder_t * pf, fd_prune_data_iter_t iter ) {
  return iter>=pf->prunes.count;
}

fd_prune_data_iter_t
fd_prune_finder_gen_prunes( fd_prune_finder_t *   pf,
                            ulong                 my_stake,
                            uchar const * const * origins,
                            ulong                 origins_len ) {
  FD_TEST( origins_len<=FD_GOSSIP_MSG_MAX_CRDS );
  /* Clear out current prunes map */
  for( ulong i=0UL; i<pf->prunes.count; i++ ) {
    fd_prune_finder_prune_t * p = prunes_pool_ele( pf->prunes.pool, i );
    prunes_map_ele_remove( pf->prunes.map, &p->relayer_prunes->relayer_pubkey, NULL, pf->prunes.pool );
  }
  pf->prunes.count = 0UL;

  for( ulong i=0UL; i<origins_len; i++ ) {
    fd_prune_origin_t * origin = origin_map_ele_query( pf->origins, fd_type_pun_const( origins[i] ), NULL, pf->pool );
    if( FD_UNLIKELY( !origin ) ) continue;

    /* Akin to ReceivedCache::prune */
    if( FD_LIKELY( origin->num_upserts<FD_PRUNE_MIN_UPSERTS ) ) continue;
    prune_origin( pf, origin, my_stake );
    reset_origin_state( origin );
  }

  return 0UL;
}
