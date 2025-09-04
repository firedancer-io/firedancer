#include "fd_prune_finder.h"

#define FD_PRUNE_FINDER_ALIGN 32UL
#define FD_PRUNE_FINDER_MAGIC (0xf17eda2c379702e0UL) /* firedancer prune version 0*/

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
  pubkey_private_t         identity_pubkey;
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

  // struct {
  //   ulong parent;
  //   ulong left;
  //   ulong right;
  //   ulong prio;

  //   ulong next;
  //   ulong prev;
  // } treap;
};

typedef struct fd_prune_relayer fd_prune_relayer_t;

#define POOL_NAME relayer_pool
#define POOL_NEXT pool.next
#define POOL_T    fd_prune_relayer_t
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME  relayer_map
#define MAP_ELE_T fd_prune_relayer_t
#define MAP_KEY_T pubkey_private_t
#define MAP_KEY   identity_pubkey
#define MAP_IDX_T ulong
#define MAP_NEXT  map.next
#define MAP_PREV  map.prev
#define MAP_KEY_HASH(k,s) ((s) ^ fd_ulong_load_8( (k)->b ))
#define MAP_KEY_EQ(k0,k1) (!memcmp((k0)->b, (k1)->b, 32UL))
#define MAP_OPTIMIZE_RANDOM_ACCESS_REMOVAL 1
#include "../../util/tmpl/fd_map_chain.c"

#define DLIST_NAME  relayer_lru
#define DLIST_ELE_T fd_prune_relayer_t
#define DLIST_PREV  lru.prev
#define DLIST_NEXT  lru.next
#include "../../util/tmpl/fd_dlist.c"

// #define TREAP_NAME      relayer_treap
// #define TREAP_T         fd_prune_relayer_t
// #define TREAP_QUERY_T   fd_prune_relayer_score_t
// #define TREAP_CMP(q,e)  fd_prune_relayer_score_cmp( &(q), e->score )
// #define TREAP_LT(e0,e1) fd_prune_relayer_score_lt( e0->score, e1->score )
// #define TREAP_PARENT    treap.parent
// #define TREAP_LEFT      treap.left
// #define TREAP_RIGHT     treap.right
// #define TREAP_PRIO      treap.prio
// #define TREAP_NEXT      treap.next
// #define TREAP_PREV      treap.prev
// #define TREAP_OPTIMIZE_ITERATION 1
// #include "../../util/tmpl/fd_treap.c"
struct fd_prune_origin {
  pubkey_private_t identity_pubkey;

  ulong num_upserts;
  ulong stake;

  struct {
    fd_prune_relayer_t * pool;
    relayer_map_t *      map;
    relayer_lru_t *      lru;
    // relayer_treap_t *    treap;
  } relayers;

  ulong pool_next;

  ulong map_next;
  ulong map_prev;

  ulong lru_prev;
  ulong lru_next;
};

typedef struct fd_prune_origin fd_prune_origin_t;

#define POOL_NAME origin_pool
#define POOL_NEXT pool_next
#define POOL_T    fd_prune_origin_t
#include "../../util/tmpl/fd_pool.c"

#define DLIST_NAME  origin_lru_list
#define DLIST_ELE_T fd_prune_origin_t
#define DLIST_PREV  lru_prev
#define DLIST_NEXT  lru_next
#include "../../util/tmpl/fd_dlist.c"

#define MAP_NAME  origin_map
#define MAP_ELE_T fd_prune_origin_t
#define MAP_KEY_T pubkey_private_t
#define MAP_KEY   identity_pubkey
#define MAP_IDX_T ulong
#define MAP_NEXT  map_next
#define MAP_PREV  map_prev
#define MAP_KEY_HASH(k,s) ((s) ^ fd_ulong_load_8( (k)->b ))
#define MAP_KEY_EQ(k0,k1) (!memcmp((k0)->b, (k1)->b, 32UL))
#define MAP_OPTIMIZE_RANDOM_ACCESS_REMOVAL 1
#include "../../util/tmpl/fd_map_chain.c"

struct fd_prune_finder_private {
  fd_prune_finder_metrics_t metrics[1];

  fd_prune_origin_t * pool;
  origin_map_t *      origins;
  origin_lru_list_t * lru;

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

  for( ulong i=0UL; i<origin_max; i++ ) {
    l = FD_LAYOUT_APPEND( l, relayer_pool_align(), relayer_pool_footprint( relayer_max_per_origin ) );
    l = FD_LAYOUT_APPEND( l, relayer_map_align(),  relayer_map_footprint( relayer_map_chain_cnt_est( relayer_max_per_origin ) ) );
    l = FD_LAYOUT_APPEND( l, relayer_lru_align(),  relayer_lru_footprint() );
    // l = FD_LAYOUT_APPEND( l, relayer_treap_align(), relayer_treap_footprint( relayer_max_per_origin ) );
  }
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
  fd_prune_finder_t * pf = FD_SCRATCH_ALLOC_APPEND( l, FD_PRUNE_FINDER_ALIGN, sizeof(fd_prune_finder_t) );
  void * _origins_pool   = FD_SCRATCH_ALLOC_APPEND( l, origin_pool_align(), origin_pool_footprint( origin_max ) );
  void * _origins_map    = FD_SCRATCH_ALLOC_APPEND( l, origin_map_align(),  origin_map_footprint( origin_map_chain_cnt_est( origin_max ) ) );
  void * _origins_lru    = FD_SCRATCH_ALLOC_APPEND( l, origin_lru_list_align(), origin_lru_list_footprint() );

  pf->pool = origin_pool_join( origin_pool_new( _origins_pool, origin_max ) );
  FD_TEST( pf->pool );

  pf->origins = origin_map_join( origin_map_new( _origins_map, origin_map_chain_cnt_est( origin_max ), fd_rng_ulong( rng ) ) );
  FD_TEST( pf->origins );

  pf->lru = origin_lru_list_join( origin_lru_list_new( _origins_lru ) );
  FD_TEST( pf->lru );

  for( ulong i=0UL; i<origin_max; i++ ) {
    fd_prune_origin_t * origin = &pf->pool[i];

    void * _relayers_pool = FD_SCRATCH_ALLOC_APPEND( l, relayer_pool_align(), relayer_pool_footprint( relayer_max_per_origin ) );
    void * _relayers_map  = FD_SCRATCH_ALLOC_APPEND( l, relayer_map_align(),  relayer_map_footprint( relayer_map_chain_cnt_est( relayer_max_per_origin ) ) );
    void * _relayers_lru  = FD_SCRATCH_ALLOC_APPEND( l, relayer_lru_align(),  relayer_lru_footprint() );
    // void * _relayers_treap = FD_SCRATCH_ALLOC_APPEND( l, relayer_treap_align(), relayer_treap_footprint( relayer_max_per_origin ) );

    origin->relayers.pool = relayer_pool_join( relayer_pool_new( _relayers_pool, relayer_max_per_origin ) );
    FD_TEST( origin->relayers.pool );

    origin->relayers.map = relayer_map_join( relayer_map_new( _relayers_map, relayer_map_chain_cnt_est( relayer_max_per_origin ), fd_rng_ulong( rng ) ) );
    FD_TEST( origin->relayers.map );

    origin->relayers.lru = relayer_lru_join( relayer_lru_new( _relayers_lru ) );
    FD_TEST( origin->relayers.lru );

    // origin->relayers.treap = relayer_treap_join( relayer_treap_new( _relayers_treap, relayer_max_per_origin ) );
    // relayer_treap_seed( origin->relayers.map, relayer_max_per_origin, fd_rng_ulong( rng ) );
    // FD_TEST( origin->relayers.treap );
  }
  fd_memset( pf->metrics, 0, sizeof(fd_prune_finder_metrics_t) );

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
update_relayer_score( fd_prune_origin_t *         origin,
                      fd_prune_finder_metrics_t * metrics,
                      uchar const *               relayer,
                      ulong                       relayer_stake,
                      ulong                       num_dups ) {
  fd_prune_relayer_t * r = relayer_map_ele_query( origin->relayers.map, fd_type_pun_const( relayer ), NULL, origin->relayers.pool );

  if( FD_UNLIKELY( !r ) ) {
    if( FD_LIKELY( relayer_pool_free( origin->relayers.pool ) ) ) {
      r = relayer_pool_ele_acquire( origin->relayers.pool );
    } else {
      r = relayer_lru_ele_pop_head( origin->relayers.lru, origin->relayers.pool );
      relayer_map_ele_remove( origin->relayers.map, &r->identity_pubkey, NULL, origin->relayers.pool );
      metrics->origin_relayer_evicted_cnt++;
    }

    r->score[0].hit_count = 0UL;
    r->score[0].stake     = relayer_stake;
    fd_memcpy( r->identity_pubkey.b, relayer, 32UL );

    relayer_map_ele_insert   ( origin->relayers.map, r, origin->relayers.pool );
    relayer_lru_ele_push_tail( origin->relayers.lru, r, origin->relayers.pool );
  } else {
    /* Move to back of the LRU list */
    relayer_lru_ele_remove   ( origin->relayers.lru, r, origin->relayers.pool );
    relayer_lru_ele_push_tail( origin->relayers.lru, r, origin->relayers.pool );
    if( FD_UNLIKELY( r->score[0].stake!=relayer_stake ) ) r->score[0].stake = relayer_stake;
  }
  if( FD_LIKELY( num_dups<2UL ) ) r->score[0].hit_count++;

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
      origin_map_ele_remove( pf->origins, &origin->identity_pubkey, NULL, pf->pool );
    }
    origin->num_upserts = 0UL;
    fd_memcpy( origin->identity_pubkey.b, origin_pubkey, 32UL );

    origin_map_ele_insert( pf->origins, origin, pf->pool );
    origin_lru_list_ele_push_tail( pf->lru, origin, pf->pool );
  } else {
    /* Move to back of the LRU list */
    origin_lru_list_ele_remove( pf->lru, origin, pf->pool );
    origin_lru_list_ele_push_tail( pf->lru, origin, pf->pool );
  }

  origin->stake = origin_stake;
  if( FD_UNLIKELY( !num_dups ) ) origin->num_upserts++;
  update_relayer_score( origin, pf->metrics, relayer_pubkey, relayer_stake, num_dups );
}
