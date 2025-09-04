#include "fd_sspeer_selector.h"

struct fd_sspeer_private {
  fd_ip4_port_t addr;   /* address of the peer */
  fd_ssinfo_t   ssinfo; /* resolved snapshot info of the peer */
  ulong         latency;
  ulong         score;

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

#define COMPARE_WORSE(x,y) ( (x)->score>(y)->score )

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

struct fd_sspeer_selector_private {
  fd_sspeer_private_t * pool;
  peer_map_t *          map;
  score_treap_t *       score_treap;

  ulong                 magic;
};

FD_FN_CONST ulong
fd_sspeer_selector_align( void ) {
  return alignof(fd_sspeer_t);
}

FD_FN_CONST ulong
fd_sspeer_selector_footprint( ulong max_peers ) {
  ulong l;
  l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, fd_sspeer_selector_align(), sizeof(fd_sspeer_selector_t) );
  l = FD_LAYOUT_APPEND( l, peer_pool_align(),          peer_pool_footprint( max_peers ) );
  l = FD_LAYOUT_APPEND( l, peer_map_align(),           peer_map_footprint( max_peers ) );
  l = FD_LAYOUT_APPEND( l, score_treap_align(),        score_treap_footprint( max_peers ) );
  return FD_LAYOUT_FINI( l, fd_sspeer_selector_align() );
}

void *
fd_sspeer_selector_new( void * shmem,
                        ulong  max_peers,
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
  void * _pool                    = FD_SCRATCH_ALLOC_APPEND( l, peer_pool_align(),             peer_pool_footprint( max_peers ) );
  void * _map                     = FD_SCRATCH_ALLOC_APPEND( l, peer_map_align(),              peer_map_footprint( max_peers ) );
  void * _score_treap             = FD_SCRATCH_ALLOC_APPEND( l, score_treap_align(),           score_treap_footprint( max_peers ) );

  selector->pool        = peer_pool_join( peer_pool_new( _pool, max_peers ) );
  selector->map         = peer_map_join( peer_map_new( _map, max_peers, seed ) );
  selector->score_treap = score_treap_join( score_treap_new( _score_treap, max_peers ) );

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

  FD_COMPILER_MFENCE();
  FD_VOLATILE( selector->magic ) = 0UL;
  FD_COMPILER_MFENCE();

  return (void *)selector;
}

ulong
fd_sspeer_selector_score( ulong peer_latency,
                          fd_ssinfo_t const * ssinfo ) {
  (void)ssinfo;
  return peer_latency;
}

static void
fd_sspeer_selector_update( fd_sspeer_selector_t * selector,
                           fd_sspeer_private_t *  peer,
                           ulong                  latency,
                           fd_ssinfo_t const *    ssinfo ) {
  score_treap_ele_remove( selector->score_treap, peer, selector->pool );

  ulong               peer_latency = latency!=ULONG_MAX ? latency : peer->latency;
  fd_ssinfo_t const * peer_ssinfo  = ssinfo ? ssinfo : &peer->ssinfo;

  peer->score = fd_sspeer_selector_score( peer_latency, peer_ssinfo );

  if( FD_LIKELY( ssinfo ) ) {
    peer->ssinfo = *ssinfo;
  }

  if( FD_LIKELY( latency!=ULONG_MAX ) ) {
    peer->latency = latency;
  }

  score_treap_ele_insert( selector->score_treap, peer, selector->pool );
}

void
fd_sspeer_selector_add( fd_sspeer_selector_t * selector,
                        fd_ip4_port_t          addr,
                        ulong                  latency,
                        fd_ssinfo_t const *    ssinfo ) {
  FD_TEST( selector && ssinfo );

  fd_sspeer_private_t * peer = peer_map_ele_query( selector->map, &addr, NULL, selector->pool );
  if( FD_LIKELY( peer ) ) {
    fd_sspeer_selector_update( selector, peer, latency, ssinfo );
  } else {
    if( FD_UNLIKELY( !peer_pool_free( selector->pool ) ) ) return;

    peer = peer_pool_ele_acquire( selector->pool );
    FD_TEST( peer );
    if( FD_LIKELY( ssinfo ) ) {
      peer->ssinfo  = *ssinfo;
    }

    peer->addr    = addr;
    peer->latency = latency;
    peer->score   = fd_sspeer_selector_score( latency, ssinfo );
    peer_map_ele_insert( selector->map, peer, selector->pool );
    score_treap_ele_insert( selector->score_treap, peer, selector->pool );
  }
}

void
fd_sspeer_selector_remove( fd_sspeer_selector_t * selector,
                           fd_ip4_port_t          addr ) {
  fd_sspeer_private_t * peer = peer_map_ele_query( selector->map, &addr, NULL, selector->pool );
  FD_TEST( peer );
  
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

  score_treap_fwd_iter_t iter = score_treap_fwd_iter_init( selector->score_treap, selector->pool );
  if( FD_UNLIKELY( score_treap_fwd_iter_done( iter ) ) ) return (fd_sspeer_t){.addr={.l=0UL}};

  for( ; !score_treap_fwd_iter_done( iter ); iter = score_treap_fwd_iter_next( iter, selector->pool ) ) {
    fd_sspeer_private_t const * peer = score_treap_fwd_iter_ele_const( iter, selector->pool );
    if( FD_LIKELY( !incremental || 
                   (incremental && peer->ssinfo.full.slot==base_slot) ) ) {
      return (fd_sspeer_t){
        .addr    = peer->addr,
        .ssinfo  = peer->ssinfo,
      };
    }
  }

  return (fd_sspeer_t){.addr={.l=0UL}};
}
