#include "fd_sspeer_selector.h"

struct fd_sspeer_private {
  fd_ip4_port_t addr;
  ulong         full_slot;
  ulong         incr_slot;
  ulong         latency;
  ulong         score;
  int           valid;

  struct {
    ulong next;
  } pool;

  struct {
    ulong next;
    ulong prev;
  } map;

  struct {
    ulong parent;
    ulong left;
    ulong right;
    ulong prio;
  } score_treap;
};

typedef struct fd_sspeer_private fd_sspeer_private_t;

#define POOL_NAME  peer_pool
#define POOL_T     fd_sspeer_private_t
#define POOL_IDX_T ulong
#define POOL_NEXT  pool.next
#include "../../../util/tmpl/fd_pool.c"

#define MAP_NAME               peer_map
#define MAP_KEY                addr
#define MAP_ELE_T              fd_sspeer_private_t
#define MAP_KEY_T              fd_ip4_port_t
#define MAP_PREV               map.prev
#define MAP_NEXT               map.next
#define MAP_KEY_EQ(k0,k1)      ((k0)->l==(k1)->l)
#define MAP_KEY_HASH(key,seed) (seed^(key)->l)
#define MAP_OPTIMIZE_RANDOM_ACCESS_REMOVAL 1
#include "../../../util/tmpl/fd_map_chain.c"

#define COMPARE_WORSE(x,y) ( (x)->score<(y)->score )

#define TREAP_T         fd_sspeer_private_t
#define TREAP_NAME      score_treap
#define TREAP_QUERY_T   void *                                         /* We don't use query ... */
#define TREAP_CMP(a,b)  (__extension__({ (void)(a); (void)(b); -1; })) /* which means we don't need to give a real
                                                                          implementation to cmp either */
#define TREAP_IDX_T     ulong
#define TREAP_LT        COMPARE_WORSE
#define TREAP_PARENT    score_treap.parent
#define TREAP_LEFT      score_treap.left
#define TREAP_RIGHT     score_treap.right
#define TREAP_PRIO      score_treap.prio
#include "../../../util/tmpl/fd_treap.c"

#define DEFAULT_SLOTS_BEHIND   (1000UL*1000UL)        /* 1,000,000 slots behind */
#define DEFAULT_PEER_LATENCY   (100L*1000L*1000L)     /* 100ms */

#define FD_SSPEER_SELECTOR_DEBUG 0

struct fd_sspeer_selector_private {
  fd_sspeer_private_t * pool;
  peer_map_t *          map;
  score_treap_t *       score_treap;
  score_treap_t *       shadow_score_treap;
  ulong *               peer_idx_list;
  fd_sscluster_slot_t   cluster_slot;
  int                   incremental_snapshot_fetch;

  ulong                 magic; /* ==FD_SSPEER_SELECTOR_MAGIC */
};

FD_FN_CONST ulong
fd_sspeer_selector_align( void ) {
  return fd_ulong_max( alignof( fd_sspeer_selector_t), fd_ulong_max( peer_pool_align(), fd_ulong_max( score_treap_align(), alignof(ulong) ) ) );
}

FD_FN_CONST ulong
fd_sspeer_selector_footprint( ulong max_peers ) {
  ulong l;
  l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_sspeer_selector_t), sizeof(fd_sspeer_selector_t) );
  l = FD_LAYOUT_APPEND( l, peer_pool_align(),             peer_pool_footprint( 2UL*max_peers ) );
  l = FD_LAYOUT_APPEND( l, peer_map_align(),              peer_map_footprint( peer_map_chain_cnt_est( 2UL*max_peers ) ) );
  l = FD_LAYOUT_APPEND( l, score_treap_align(),           score_treap_footprint( max_peers ) );
  l = FD_LAYOUT_APPEND( l, score_treap_align(),           score_treap_footprint( max_peers ) );
  l = FD_LAYOUT_APPEND( l, alignof(ulong),                max_peers * sizeof(ulong) );
  return FD_LAYOUT_FINI( l, fd_sspeer_selector_align() );
}

void *
fd_sspeer_selector_new( void * shmem,
                        ulong  max_peers,
                        int    incremental_snapshot_fetch,
                        ulong  seed ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_sspeer_selector_align() ) ) ) {
    FD_LOG_WARNING(( "unaligned shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( max_peers < 1UL ) ) {
    FD_LOG_WARNING(( "max_peers must be at least 1" ));
    return NULL;
  }

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_sspeer_selector_t * selector = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_sspeer_selector_t), sizeof(fd_sspeer_selector_t) );
  void * _pool                    = FD_SCRATCH_ALLOC_APPEND( l, peer_pool_align(),             peer_pool_footprint( 2UL*max_peers ) );
  void * _map                     = FD_SCRATCH_ALLOC_APPEND( l, peer_map_align(),              peer_map_footprint( peer_map_chain_cnt_est( 2UL*max_peers ) )  );
  void * _score_treap             = FD_SCRATCH_ALLOC_APPEND( l, score_treap_align(),           score_treap_footprint( max_peers ) );
  void * _shadow_score_treap      = FD_SCRATCH_ALLOC_APPEND( l, score_treap_align(),           score_treap_footprint( max_peers ) );
  void * _peer_idx_list           = FD_SCRATCH_ALLOC_APPEND( l, alignof(ulong),                max_peers * sizeof(ulong) );

  selector->pool               = peer_pool_join( peer_pool_new( _pool, max_peers ) );
  selector->map                = peer_map_join( peer_map_new( _map, peer_map_chain_cnt_est( 2UL*max_peers ), seed ) );
  selector->score_treap        = score_treap_join( score_treap_new( _score_treap, max_peers ) );
  selector->shadow_score_treap = score_treap_join( score_treap_new( _shadow_score_treap, max_peers ) );
  selector->peer_idx_list      = (ulong *)_peer_idx_list;

  selector->cluster_slot.full          = 0UL;
  selector->cluster_slot.incremental   = 0UL;
  selector->incremental_snapshot_fetch = incremental_snapshot_fetch;

  FD_COMPILER_MFENCE();
  FD_VOLATILE( selector->magic ) = FD_SSPEER_SELECTOR_MAGIC;
  FD_COMPILER_MFENCE();

  return (void *)selector;
}

fd_sspeer_selector_t *
fd_sspeer_selector_join( void * shselector ) {
  if( FD_UNLIKELY( !shselector ) ) {
    FD_LOG_WARNING(( "NULL shselector" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shselector, fd_sspeer_selector_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shselector" ));
    return NULL;
  }

  fd_sspeer_selector_t * selector = (fd_sspeer_selector_t *)shselector;

  if( FD_UNLIKELY( selector->magic!=FD_SSPEER_SELECTOR_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return selector;
}

void *
fd_sspeer_selector_leave( fd_sspeer_selector_t * selector ) {
  if( FD_UNLIKELY( !selector ) ) {
    FD_LOG_WARNING(( "NULL selector" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)selector, fd_sspeer_selector_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned selector" ));
    return NULL;
  }

  if( FD_UNLIKELY( selector->magic!=FD_SSPEER_SELECTOR_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  selector->pool               = peer_pool_leave( selector->pool );
  selector->map                = peer_map_leave( selector->map );
  selector->score_treap        = score_treap_leave( selector->score_treap );
  selector->shadow_score_treap = score_treap_leave( selector->shadow_score_treap );

  return (void *)selector;
}

void *
fd_sspeer_selector_delete( void * shselector ) {
  if( FD_UNLIKELY( !shselector ) ) {
    FD_LOG_WARNING(( "NULL shselector" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shselector, fd_sspeer_selector_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shselector" ));
    return NULL;
  }

  fd_sspeer_selector_t * selector = (fd_sspeer_selector_t *)shselector;

  if( FD_UNLIKELY( selector->magic!=FD_SSPEER_SELECTOR_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  selector->pool               = peer_pool_delete( selector->pool );
  selector->map                = peer_map_delete( selector->map );
  selector->score_treap        = score_treap_delete( selector->score_treap );
  selector->shadow_score_treap = score_treap_delete( selector->shadow_score_treap );

  FD_COMPILER_MFENCE();
  FD_VOLATILE( selector->magic ) = 0UL;
  FD_COMPILER_MFENCE();

  return (void *)selector;
}

/* Calculates a score for a peer given its latency and its resolved
   full and incremental slots */
ulong
fd_sspeer_selector_score( fd_sspeer_selector_t * selector,
                          ulong                  peer_latency,
                          ulong                  full_slot,
                          ulong                  incr_slot ) {
  static const ulong slots_behind_penalty = 1000UL;
  ulong slot                              = ULONG_MAX;
  ulong slots_behind                      = DEFAULT_SLOTS_BEHIND;
  peer_latency = peer_latency!=ULONG_MAX ? peer_latency : DEFAULT_PEER_LATENCY;

  if( FD_LIKELY( full_slot!=ULONG_MAX ) ) {
    if( FD_UNLIKELY( incr_slot==ULONG_MAX ) ) {
      slot         = full_slot;
      slots_behind = selector->cluster_slot.full>slot ? selector->cluster_slot.full - slot : 0UL;
    } else {
      slot         = incr_slot;
      slots_behind = selector->cluster_slot.incremental>slot ? selector->cluster_slot.incremental - slot : 0UL;
    }
  }

  /* TODO: come up with a better/more dynamic score function */
  return peer_latency + slots_behind_penalty*slots_behind;
}

/* Updates a peer's score with new values for latency and/or resolved
   full/incremental slots */
static void
fd_sspeer_selector_update( fd_sspeer_selector_t * selector,
                           fd_sspeer_private_t *  peer,
                           ulong                  latency,
                           ulong                  full_slot,
                           ulong                  incr_slot ) {
  score_treap_ele_remove( selector->score_treap, peer, selector->pool );

  ulong peer_latency = latency!=ULONG_MAX ? latency : peer->latency;
  peer->score = fd_sspeer_selector_score( selector, peer_latency, full_slot, incr_slot );

  peer->full_slot = full_slot!=ULONG_MAX ? full_slot : peer->full_slot;
  peer->incr_slot = incr_slot!=ULONG_MAX ? incr_slot : peer->incr_slot;

  if( FD_LIKELY( latency!=ULONG_MAX ) ) {
    peer->latency = latency;
  }

  score_treap_ele_insert( selector->score_treap, peer, selector->pool );
}

ulong
fd_sspeer_selector_add( fd_sspeer_selector_t * selector,
                        fd_ip4_port_t          addr,
                        ulong                  latency,
                        ulong                  full_slot,
                        ulong                  incr_slot ) {
  fd_sspeer_private_t * peer = peer_map_ele_query( selector->map, &addr, NULL, selector->pool );
  if( FD_LIKELY( peer ) ) {
    fd_sspeer_selector_update( selector, peer, latency, full_slot, incr_slot );
  } else {
    if( FD_UNLIKELY( !peer_pool_free( selector->pool ) ) ) return ULONG_MAX;

    peer = peer_pool_ele_acquire( selector->pool );
    peer->addr      = addr;
    peer->latency   = latency;
    peer->score     = fd_sspeer_selector_score( selector, latency, full_slot, incr_slot );
    peer->full_slot = full_slot;
    peer->incr_slot = incr_slot;
    peer_map_ele_insert( selector->map, peer, selector->pool );
    score_treap_ele_insert( selector->score_treap, peer, selector->pool );
  }
  peer->valid = peer->latency!=ULONG_MAX && peer->full_slot!=ULONG_MAX;
  return peer->score;
}

void
fd_sspeer_selector_remove( fd_sspeer_selector_t * selector,
                           fd_ip4_port_t          addr ) {
  fd_sspeer_private_t * peer = peer_map_ele_query( selector->map, &addr, NULL, selector->pool );
  if( FD_UNLIKELY( !peer ) ) return;

  score_treap_ele_remove( selector->score_treap, peer, selector->pool );
  peer_map_ele_remove_fast( selector->map, peer, selector->pool );
  peer_pool_ele_release( selector->pool, peer );
}

fd_sspeer_t
fd_sspeer_selector_best( fd_sspeer_selector_t * selector,
                         int                    incremental,
                         ulong                  base_slot ) {
  if( FD_UNLIKELY( incremental ) ) {
    FD_TEST( base_slot!=ULONG_MAX );
  }

  for( score_treap_fwd_iter_t iter = score_treap_fwd_iter_init( selector->score_treap, selector->pool );
       !score_treap_fwd_iter_done( iter );
       iter = score_treap_fwd_iter_next( iter, selector->pool ) ) {
    fd_sspeer_private_t const * peer = score_treap_fwd_iter_ele_const( iter, selector->pool );
    if( FD_LIKELY( peer->valid &&
                   (!incremental ||
                   (incremental && peer->full_slot==base_slot) ) ) ) {
      return (fd_sspeer_t){
        .addr      = peer->addr,
        .full_slot = peer->full_slot,
        .incr_slot = peer->incr_slot,
        .score     = peer->score,
      };
    }
  }

  return (fd_sspeer_t){
    .addr      = { .l=0UL },
    .full_slot = ULONG_MAX,
    .incr_slot = ULONG_MAX,
    .score     = ULONG_MAX,
  };
}

void
fd_sspeer_selector_process_cluster_slot( fd_sspeer_selector_t * selector,
                                         ulong                  full_slot,
                                         ulong                  incr_slot ) {
  if( full_slot==ULONG_MAX && incr_slot==ULONG_MAX ) return;

  FD_TEST( full_slot!=ULONG_MAX );
  if( FD_LIKELY( selector->incremental_snapshot_fetch ) ) {
    /* incremental slot is less than or equal to cluster incremental slot */
    if( FD_UNLIKELY( incr_slot!=ULONG_MAX && selector->cluster_slot.incremental!=ULONG_MAX && incr_slot<=selector->cluster_slot.incremental ) ) return;
    /* incremental slot is less than or equal to cluster full slot when cluster incremental slot does not exist */
    else if( FD_UNLIKELY( incr_slot!=ULONG_MAX && selector->cluster_slot.incremental==ULONG_MAX && incr_slot<=selector->cluster_slot.full ) )   return;
    /* full slot is less than cluster full slot when incremental slot does not exist */
    else if( FD_UNLIKELY( incr_slot==ULONG_MAX && full_slot<=selector->cluster_slot.full ) )                                                           return;
  } else {
    if( FD_UNLIKELY( full_slot<=selector->cluster_slot.full ) ) return;
  }

  selector->cluster_slot.full        = full_slot;
  selector->cluster_slot.incremental = incr_slot;

  if( FD_UNLIKELY( score_treap_ele_cnt( selector->score_treap )==0UL ) ) return;

  /* Rescore all peers
     TODO: make more performant, maybe make a treap rebalance API */
  ulong idx = 0UL;
  for( score_treap_fwd_iter_t iter = score_treap_fwd_iter_init( selector->score_treap, selector->pool );
        !score_treap_fwd_iter_done( iter );
        iter = score_treap_fwd_iter_next( iter, selector->pool ) ) {
    fd_sspeer_private_t const * peer  = score_treap_fwd_iter_ele_const( iter, selector->pool );
    fd_sspeer_private_t * shadow_peer = peer_pool_ele_acquire( selector->pool );
    shadow_peer->latency   = peer->latency;
    shadow_peer->full_slot = peer->full_slot;
    shadow_peer->incr_slot = peer->incr_slot;
    shadow_peer->addr      = peer->addr;
    shadow_peer->score     = fd_sspeer_selector_score( selector, shadow_peer->latency, shadow_peer->full_slot, shadow_peer->incr_slot );
    score_treap_ele_insert( selector->shadow_score_treap, shadow_peer, selector->pool );
    selector->peer_idx_list[ idx++ ] = peer_pool_idx( selector->pool, peer );
    peer_map_ele_remove( selector->map, &peer->addr, NULL, selector->pool );
    peer_map_ele_insert( selector->map, shadow_peer, selector->pool );
  }

  /* clear score treap*/
  for( ulong i=0UL; i<idx; i++ ) {
    fd_sspeer_private_t * peer = peer_pool_ele( selector->pool, selector->peer_idx_list[ i ] );
    score_treap_ele_remove( selector->score_treap, peer, selector->pool );
    peer_pool_ele_release( selector->pool, peer );
  }

  score_treap_t * tmp          = selector->score_treap;
  selector->score_treap        = selector->shadow_score_treap;
  selector->shadow_score_treap = tmp;

#if FD_SSPEER_SELECTOR_DEBUG
  FD_TEST( score_treap_verify( selector->score_treap, selector->pool )==0 );
#endif
}

fd_sscluster_slot_t
fd_sspeer_selector_cluster_slot( fd_sspeer_selector_t * selector ) {
  return selector->cluster_slot;
}
