#include "fd_sspeer_selector.h"
#include "../../../util/bits/fd_sat.h"
#include "../../../util/log/fd_log.h"

static int
fd_sspeer_key_private_eq( fd_sspeer_key_t const * k0,
                          fd_sspeer_key_t const * k1 ) {
  if( k0->is_url!=k1->is_url ) return 0;
  if( k0->is_url ) {
    return !strncmp( k0->url.hostname, k1->url.hostname, sizeof(k0->url.hostname) )
           && k0->url.resolved_addr.l==k1->url.resolved_addr.l;
  }
  return !memcmp( k0->pubkey, k1->pubkey, FD_PUBKEY_FOOTPRINT );
}

static ulong
fd_sspeer_key_private_hash( fd_sspeer_key_t const * key,
                            ulong                   seed ) {
  if( key->is_url ) {
    /* Use strnlen in case the string is not properly \0 terminated.
       Ideally, one would prefer sizeof(key->url.hostname) but that
       requires guaranteed zero-padding. */
    ulong h = fd_hash( seed, key->url.hostname, strnlen( key->url.hostname, sizeof(key->url.hostname) ) );
    /* fd_ip4_port_t is not a complete 64bit ulong, therefore compose
       the word from its parts to avoid random unused bytes. */
    ulong a = (ulong)key->url.resolved_addr.addr | ( ((ulong)key->url.resolved_addr.port) << 32 );
    /* Chaining "a" through fd_hash would give better avalanche
       properties, but it is probably overkill for a chain hash map. */
    return h ^ a;
  }
  return fd_hash( seed, key->pubkey, FD_PUBKEY_FOOTPRINT );
}

struct fd_sspeer_private {
  fd_sspeer_key_t key;
  fd_ip4_port_t addr;
  ulong         full_slot;
  ulong         incr_slot;
  uchar         full_hash[ FD_HASH_FOOTPRINT ];
  uchar         incr_hash[ FD_HASH_FOOTPRINT ];
  ulong         latency;
  ulong         score;
  int           valid;

  struct {
    ulong next;
  } pool;

  struct {
    ulong next;
    ulong prev;
  } map_by_key;

  struct {
    ulong next;
    ulong prev;
  } map_by_addr;

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

#define MAP_NAME               peer_map_by_key
#define MAP_KEY                key
#define MAP_ELE_T              fd_sspeer_private_t
#define MAP_KEY_T              fd_sspeer_key_t
#define MAP_PREV               map_by_key.prev
#define MAP_NEXT               map_by_key.next
#define MAP_KEY_EQ(k0,k1)      (fd_sspeer_key_private_eq(k0,k1))
#define MAP_KEY_HASH(key,seed) (fd_sspeer_key_private_hash(key,seed))
#define MAP_OPTIMIZE_RANDOM_ACCESS_REMOVAL 1
#include "../../../util/tmpl/fd_map_chain.c"

#define MAP_NAME               peer_map_by_addr
#define MAP_KEY                addr
#define MAP_ELE_T              fd_sspeer_private_t
#define MAP_KEY_T              fd_ip4_port_t
#define MAP_PREV               map_by_addr.prev
#define MAP_NEXT               map_by_addr.next
#define MAP_KEY_EQ(k0,k1)      ((k0)->l==(k1)->l)
#define MAP_KEY_HASH(key,seed) (seed^(key)->l)
#define MAP_OPTIMIZE_RANDOM_ACCESS_REMOVAL 1
#define MAP_MULTI              1
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

#define DEFAULT_SLOTS_BEHIND         (1000UL*1000UL) /* 1,000,000 slots behind */
/* Assumed latency (in nanos) for peers that have not been pinged yet.
   Pings are sent immediately on peer discovery, so this default is
   short-lived.  100ms is a neutral middle-ground: high enough that
   any peer with a measured latency is preferred, low enough that slot
   distance still meaningfully differentiates unpinged peers. */
#define DEFAULT_PEER_LATENCY         (100UL*1000UL*1000UL)  /* 100ms */
#define DEFAULT_SLOTS_BEHIND_PENALTY (1000UL)

#define FD_SSPEER_SELECTOR_DEBUG 0

struct fd_sspeer_selector_private {
  fd_sspeer_private_t *     pool;
  peer_map_by_key_t *       map_by_key;
  peer_map_by_addr_t *      map_by_addr;
  score_treap_t *           score_treap;
  score_treap_t *           shadow_score_treap;
  ulong *                   peer_idx_list;
  fd_sscluster_slot_t       cluster_slot;
  int                       incremental_snapshot_fetch;
  ulong                     max_peers;

  ulong                     magic; /* ==FD_SSPEER_SELECTOR_MAGIC */
};

FD_FN_CONST ulong
fd_sspeer_selector_align( void ) {
  return fd_ulong_max( alignof( fd_sspeer_selector_t), fd_ulong_max( peer_pool_align(),
          fd_ulong_max( peer_map_by_key_align(), fd_ulong_max( peer_map_by_addr_align(),
          fd_ulong_max( score_treap_align(), alignof(ulong) ) ) ) ) );
}

FD_FN_CONST ulong
fd_sspeer_selector_footprint( ulong max_peers ) {
  ulong l;
  l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_sspeer_selector_t), sizeof(fd_sspeer_selector_t) );
  l = FD_LAYOUT_APPEND( l, peer_pool_align(),             peer_pool_footprint( 2UL*max_peers ) );
  l = FD_LAYOUT_APPEND( l, peer_map_by_key_align(),       peer_map_by_key_footprint( peer_map_by_key_chain_cnt_est( 2UL*max_peers ) ) );
  l = FD_LAYOUT_APPEND( l, peer_map_by_addr_align(),      peer_map_by_addr_footprint( peer_map_by_addr_chain_cnt_est( 2UL*max_peers ) ) );
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
  void * _pool                    = FD_SCRATCH_ALLOC_APPEND( l, peer_pool_align(),        peer_pool_footprint( 2UL*max_peers ) );
  void * _map                     = FD_SCRATCH_ALLOC_APPEND( l, peer_map_by_key_align(),  peer_map_by_key_footprint( peer_map_by_key_chain_cnt_est( 2UL*max_peers ) )  );
  void * _multimap_by_addr        = FD_SCRATCH_ALLOC_APPEND( l, peer_map_by_addr_align(), peer_map_by_addr_footprint( peer_map_by_addr_chain_cnt_est( 2UL*max_peers ) )  );
  void * _score_treap             = FD_SCRATCH_ALLOC_APPEND( l, score_treap_align(),      score_treap_footprint( max_peers ) );
  void * _shadow_score_treap      = FD_SCRATCH_ALLOC_APPEND( l, score_treap_align(),      score_treap_footprint( max_peers ) );
  void * _peer_idx_list           = FD_SCRATCH_ALLOC_APPEND( l, alignof(ulong),           max_peers * sizeof(ulong) );

  selector->pool               = peer_pool_join( peer_pool_new( _pool, 2UL*max_peers ) );
  /* Seed treap priorities so the treap is balanced. */
  score_treap_seed( selector->pool, 2UL*max_peers, seed );
  selector->map_by_key         = peer_map_by_key_join( peer_map_by_key_new( _map, peer_map_by_key_chain_cnt_est( 2UL*max_peers ), seed ) );
  selector->map_by_addr        = peer_map_by_addr_join( peer_map_by_addr_new( _multimap_by_addr, peer_map_by_addr_chain_cnt_est( 2UL*max_peers ), seed ) );
  selector->score_treap        = score_treap_join( score_treap_new( _score_treap, max_peers ) );
  selector->shadow_score_treap = score_treap_join( score_treap_new( _shadow_score_treap, max_peers ) );
  selector->peer_idx_list      = (ulong *)_peer_idx_list;
  selector->max_peers          = max_peers;

  selector->cluster_slot.full          = 0UL;
  selector->cluster_slot.incremental   = FD_SSPEER_SLOT_UNKNOWN;
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
  selector->map_by_key         = peer_map_by_key_leave( selector->map_by_key );
  selector->map_by_addr        = peer_map_by_addr_leave( selector->map_by_addr );
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
  selector->map_by_key         = peer_map_by_key_delete( selector->map_by_key );
  selector->map_by_addr        = peer_map_by_addr_delete( selector->map_by_addr );
  selector->score_treap        = score_treap_delete( selector->score_treap );
  selector->shadow_score_treap = score_treap_delete( selector->shadow_score_treap );

  FD_COMPILER_MFENCE();
  FD_VOLATILE( selector->magic ) = 0UL;
  FD_COMPILER_MFENCE();

  return (void *)selector;
}

/* Calculates a score for a peer given its latency and its resolved
   full and incremental slots */
static ulong
fd_sspeer_selector_score( fd_sspeer_selector_t const * selector,
                          ulong                        peer_latency,
                          ulong                        full_slot,
                          ulong                        incr_slot ) {
  peer_latency = peer_latency!=FD_SSPEER_LATENCY_UNKNOWN ? peer_latency : DEFAULT_PEER_LATENCY;

  ulong slots_behind = DEFAULT_SLOTS_BEHIND;

  if( FD_LIKELY( full_slot!=FD_SSPEER_SLOT_UNKNOWN ) ) {
    if( FD_LIKELY( incr_slot!=FD_SSPEER_SLOT_UNKNOWN &&
                   selector->cluster_slot.incremental!=FD_SSPEER_SLOT_UNKNOWN ) ) {
      slots_behind = selector->cluster_slot.incremental>incr_slot ? selector->cluster_slot.incremental - incr_slot : 0UL;
    } else {
      /* Either the peer has no incremental or the cluster has no
         incremental reference yet.  Fall back to comparing full_slot
         against the cluster full slot. */
      slots_behind = selector->cluster_slot.full>full_slot ? selector->cluster_slot.full - full_slot : 0UL;
    }
  }

  /* Using saturating arithmetic to avoid overflow and cap at
     FD_SSPEER_SCORE_MAX. */
  ulong penalty = fd_ulong_sat_mul( DEFAULT_SLOTS_BEHIND_PENALTY, slots_behind );
  ulong score   = fd_ulong_sat_add( peer_latency, penalty );
  return fd_ulong_min( score, FD_SSPEER_SCORE_MAX );
}

/* Validates slot arguments for both new and existing peers.  Returns
   0 on success, -1 on failure due to incr_slot<full_slot, and -2 on
   failure due to full_slot==UNKNOWN with incr_slot!=UNKNOWN.  The
   caller passes in the effective (already-resolved) full_slot and
   incr_slot values.  No log on failure (the caller is responsible
   for logging whenever needed).

   Two invariants are enforced:
   1. When both slots are known, incr_slot must be >= full_slot.
   2. An incremental slot requires a known full slot. */
static int
fd_sspeer_validate_slot_args( ulong full_slot,
                              ulong incr_slot ) {
  if( FD_UNLIKELY( incr_slot!=FD_SSPEER_SLOT_UNKNOWN &&
                   full_slot!=FD_SSPEER_SLOT_UNKNOWN &&
                   incr_slot<full_slot ) ) {
    return -1;
  }

  if( FD_UNLIKELY( full_slot==FD_SSPEER_SLOT_UNKNOWN &&
                   incr_slot!=FD_SSPEER_SLOT_UNKNOWN ) ) {
    return -2;
  }

  return 0;
}

/* Updates a peer's score with new values for latency and/or resolved
   full/incremental slots.  Returns FD_SSPEER_UPDATE_SUCCESS on
   success, or the specific fd_sspeer_validate_slot_args error code
   on failure without modifying the peer or any data structure.

   Slot-based incremental clearing: when the caller provides
   incr_slot==UNKNOWN and full_slot!=UNKNOWN, the peer's existing
   incremental data is cleared if it is stale (peer->incr_slot <
   full_slot).  Otherwise, the existing incremental data is preserved. */
static int
fd_sspeer_selector_update( fd_sspeer_selector_t * selector,
                           fd_sspeer_private_t *  peer,
                           ulong                  latency,
                           ulong                  full_slot,
                           ulong                  incr_slot,
                           uchar const            full_hash[ FD_HASH_FOOTPRINT ],
                           uchar const            incr_hash[ FD_HASH_FOOTPRINT ] ) {
  ulong peer_latency   = latency!=FD_SSPEER_LATENCY_UNKNOWN ? latency : peer->latency;
  ulong peer_full_slot = full_slot!=FD_SSPEER_SLOT_UNKNOWN ? full_slot : peer->full_slot;

  ulong peer_incr_slot;
  int   clear_incr = 0;
  if( incr_slot!=FD_SSPEER_SLOT_UNKNOWN ) {
    peer_incr_slot = incr_slot;
  } else if( full_slot!=FD_SSPEER_SLOT_UNKNOWN &&
             peer->incr_slot!=FD_SSPEER_SLOT_UNKNOWN &&
             peer->incr_slot<full_slot ) {
    /* The caller is providing a new full_slot that has advanced past
       the peer's existing incremental — the incremental is stale. */
    peer_incr_slot = FD_SSPEER_SLOT_UNKNOWN;
    clear_incr     = 1;
  } else {
    peer_incr_slot = peer->incr_slot;
  }

  int validate_err = fd_sspeer_validate_slot_args( peer_full_slot, peer_incr_slot );
  if( FD_UNLIKELY( validate_err ) ) return validate_err;

  score_treap_ele_remove( selector->score_treap, peer, selector->pool );

  peer->score = fd_sspeer_selector_score( selector, peer_latency, peer_full_slot, peer_incr_slot );

  peer->latency   = peer_latency;
  peer->full_slot = peer_full_slot;
  peer->incr_slot = peer_incr_slot;
  if( FD_LIKELY( full_hash ) ) {
    fd_memcpy( peer->full_hash, full_hash, FD_HASH_FOOTPRINT );
  }
  if( FD_UNLIKELY( clear_incr ) ) {
    fd_memset( peer->incr_hash, 0, FD_HASH_FOOTPRINT );
  } else if( FD_LIKELY( incr_hash ) ) {
    fd_memcpy( peer->incr_hash, incr_hash, FD_HASH_FOOTPRINT );
  }

  score_treap_ele_insert( selector->score_treap, peer, selector->pool );
  return FD_SSPEER_UPDATE_SUCCESS;
}

int
fd_sspeer_selector_update_on_resolve( fd_sspeer_selector_t *  selector,
                                      fd_sspeer_key_t const * key,
                                      ulong                   full_slot,
                                      ulong                   incr_slot,
                                      uchar const             full_hash[ FD_HASH_FOOTPRINT ],
                                      uchar const             incr_hash[ FD_HASH_FOOTPRINT ] ) {
  if( FD_UNLIKELY( key==NULL ) ) return FD_SSPEER_UPDATE_ERR_NULL_KEY;
  fd_sspeer_private_t * peer = peer_map_by_key_ele_query( selector->map_by_key, key, NULL, selector->pool );
  if( FD_UNLIKELY( peer==NULL ) ) return FD_SSPEER_UPDATE_ERR_NOT_FOUND;
  int update_status = fd_sspeer_selector_update( selector, peer, FD_SSPEER_LATENCY_UNKNOWN, full_slot, incr_slot, full_hash, incr_hash );
  if( FD_UNLIKELY( update_status!=FD_SSPEER_UPDATE_SUCCESS ) ) return FD_SSPEER_UPDATE_ERR_INVALID_ARG;
  peer->valid = peer->full_slot!=FD_SSPEER_SLOT_UNKNOWN;
  return FD_SSPEER_UPDATE_SUCCESS;
}

ulong
fd_sspeer_selector_update_on_ping( fd_sspeer_selector_t * selector,
                                   fd_ip4_port_t          addr,
                                   ulong                  latency ) {
  ulong ele_idx = peer_map_by_addr_idx_query_const( selector->map_by_addr, &addr, ULONG_MAX, selector->pool );
  ulong cnt = 0UL;
  for(;;) {
    if( FD_UNLIKELY( ele_idx==ULONG_MAX ) ) break;
    fd_sspeer_private_t * peer = selector->pool + ele_idx;
    /* Update cannot fail here: slots are FD_SSPEER_SLOT_UNKNOWN and
       hashes are NULL, so fd_sspeer_validate_slot_args always
       returns FD_SSPEER_UPDATE_SUCCESS (no clear_incr trigger,
       no incr<full violation). */
    int update_status = fd_sspeer_selector_update( selector, peer, latency,
                                                   FD_SSPEER_SLOT_UNKNOWN, FD_SSPEER_SLOT_UNKNOWN,
                                                   NULL, NULL );
    if( FD_UNLIKELY( update_status!=FD_SSPEER_UPDATE_SUCCESS ) ) {
      /* A warning is a tradeoff between crashing with FD_LOG_CRIT and
         potentially missing the log altogether with FD_LOG_DEBUG. */
      if( peer->key.is_url ) {
        FD_LOG_WARNING(( "unexpected selector update returned %d for peer %s " FD_IP4_ADDR_FMT ":%hu",
                         update_status, peer->key.url.hostname,
                         FD_IP4_ADDR_FMT_ARGS( peer->key.url.resolved_addr.addr ), fd_ushort_bswap( peer->key.url.resolved_addr.port ) ));
      } else {
        FD_BASE58_ENCODE_32_BYTES( peer->key.pubkey->uc, peer_pubkey_b58 );
        FD_LOG_WARNING(( "unexpected selector update returned %d for peer %s " FD_IP4_ADDR_FMT ":%hu",
                         update_status, peer_pubkey_b58,
                         FD_IP4_ADDR_FMT_ARGS( peer->addr.addr ), fd_ushort_bswap( peer->addr.port ) ));
      }
    }
    ele_idx = peer_map_by_addr_idx_next_const( ele_idx, ULONG_MAX, selector->pool );
    cnt++;
  }
  return cnt;
}

ulong
fd_sspeer_selector_add( fd_sspeer_selector_t * selector,
                        fd_sspeer_key_t const * key,
                        fd_ip4_port_t          addr,
                        ulong                  latency,
                        ulong                  full_slot,
                        ulong                  incr_slot,
                        uchar const            full_hash[ FD_HASH_FOOTPRINT ],
                        uchar const            incr_hash[ FD_HASH_FOOTPRINT ] ) {
  if( FD_UNLIKELY( key==NULL ) ) return FD_SSPEER_SCORE_INVALID;
  /* A peer without a valid address cannot be added to the selector.
     For an existing peer changing from a valid address to 0, it is
     the caller's responsibility to remove them. */
  if( FD_UNLIKELY( !addr.l ) ) return FD_SSPEER_SCORE_INVALID;

  fd_sspeer_private_t * peer = peer_map_by_key_ele_query( selector->map_by_key, key, NULL, selector->pool );
  if( FD_LIKELY( peer ) ) {
    int update_status = fd_sspeer_selector_update( selector, peer, latency, full_slot, incr_slot, full_hash, incr_hash );
    if( FD_UNLIKELY( update_status!=FD_SSPEER_UPDATE_SUCCESS ) ) return FD_SSPEER_SCORE_INVALID;
    /* Update the addr map after the selector update so that the peer
       is not mutated when the update fails. */
    if( FD_UNLIKELY( peer->addr.l!=addr.l ) ) {
      peer_map_by_addr_ele_remove_fast( selector->map_by_addr, peer, selector->pool );
      peer->addr = addr;
      peer_map_by_addr_ele_insert( selector->map_by_addr, peer, selector->pool );
    }
  } else {
    if( FD_UNLIKELY( !peer_pool_free( selector->pool ) ) ) {
      FD_LOG_WARNING(( "peer selector pool exhausted" ));
      return FD_SSPEER_SCORE_INVALID;
    }
    if( FD_UNLIKELY( score_treap_ele_cnt(selector->score_treap)>=selector->max_peers ) ) {
      FD_LOG_WARNING(( "peer selector at max capacity" ));
      return FD_SSPEER_SCORE_INVALID;
    }

    if( FD_UNLIKELY( fd_sspeer_validate_slot_args( full_slot, incr_slot ) ) ) {
      return FD_SSPEER_SCORE_INVALID;
    }

    peer = peer_pool_ele_acquire( selector->pool );
    peer->key       = *key;
    peer->addr      = addr;
    peer->latency   = latency;
    peer->score     = fd_sspeer_selector_score( selector, latency, full_slot, incr_slot );
    peer->full_slot = full_slot;
    peer->incr_slot = incr_slot;
    if( FD_LIKELY( full_hash ) ) fd_memcpy( peer->full_hash, full_hash, FD_HASH_FOOTPRINT );
    else                         fd_memset( peer->full_hash, 0, FD_HASH_FOOTPRINT );
    /* full_hash and incr_hash are treated independently here. */
    if( FD_LIKELY( incr_hash ) ) fd_memcpy( peer->incr_hash, incr_hash, FD_HASH_FOOTPRINT );
    else                         fd_memset( peer->incr_hash, 0, FD_HASH_FOOTPRINT );
    peer_map_by_key_ele_insert( selector->map_by_key, peer, selector->pool );
    peer_map_by_addr_ele_insert( selector->map_by_addr, peer, selector->pool );
    score_treap_ele_insert( selector->score_treap, peer, selector->pool );
  }
  peer->valid = peer->full_slot!=FD_SSPEER_SLOT_UNKNOWN;
  return peer->score;
}

void
fd_sspeer_selector_remove( fd_sspeer_selector_t * selector,
                           fd_sspeer_key_t const * key ) {
  if( FD_UNLIKELY( key==NULL ) ) return;
  fd_sspeer_private_t * peer = peer_map_by_key_ele_query( selector->map_by_key, key, NULL, selector->pool );
  if( FD_UNLIKELY( peer==NULL ) ) return;
  score_treap_ele_remove( selector->score_treap, peer, selector->pool );
  peer_map_by_key_ele_remove_fast( selector->map_by_key, peer, selector->pool );
  peer_map_by_addr_ele_remove_fast( selector->map_by_addr, peer, selector->pool );
  peer_pool_ele_release( selector->pool, peer );
}

void
fd_sspeer_selector_remove_by_addr( fd_sspeer_selector_t * selector,
                                   fd_ip4_port_t          addr ) {
  for(;;) {
    fd_sspeer_private_t * peer = peer_map_by_addr_ele_remove( selector->map_by_addr, &addr, NULL, selector->pool );
    if( FD_UNLIKELY( peer==NULL ) ) break;
    score_treap_ele_remove( selector->score_treap, peer, selector->pool );
    peer_map_by_key_ele_remove_fast( selector->map_by_key, peer, selector->pool );
    peer_pool_ele_release( selector->pool, peer );
  }
}

fd_sspeer_t
fd_sspeer_selector_best( fd_sspeer_selector_t * selector,
                         int                    incremental,
                         ulong                  base_slot ) {
  if( FD_UNLIKELY( incremental && base_slot==FD_SSPEER_SLOT_UNKNOWN ) ) {
    FD_LOG_WARNING(( "incremental selection requires a valid base_slot" ));
    return (fd_sspeer_t){
      .addr      = { .l=0UL },
      .full_slot = FD_SSPEER_SLOT_UNKNOWN,
      .incr_slot = FD_SSPEER_SLOT_UNKNOWN,
      .score     = FD_SSPEER_SCORE_INVALID,
      .full_hash = {0},
      .incr_hash = {0},
    };
  }

  for( score_treap_fwd_iter_t iter = score_treap_fwd_iter_init( selector->score_treap, selector->pool );
       !score_treap_fwd_iter_done( iter );
       iter = score_treap_fwd_iter_next( iter, selector->pool ) ) {
    fd_sspeer_private_t const * peer = score_treap_fwd_iter_ele_const( iter, selector->pool );
    /* For full selection (!incremental), any valid peer is eligible.
       For incremental selection, the peer must serve the same base full
       snapshot and must actually offer an incremental snapshot. */
    if( FD_LIKELY( peer->valid &&
                   (!incremental ||
                   (peer->full_slot==base_slot && peer->incr_slot!=FD_SSPEER_SLOT_UNKNOWN) ) ) ) {
      fd_sspeer_t best = {
        .addr      = peer->addr,
        .full_slot = peer->full_slot,
        .incr_slot = peer->incr_slot,
        .score     = peer->score,
      };
      fd_memcpy( best.full_hash, peer->full_hash, FD_HASH_FOOTPRINT );
      fd_memcpy( best.incr_hash, peer->incr_hash, FD_HASH_FOOTPRINT );
      return best;
    }
  }

  return (fd_sspeer_t){
    .addr      = { .l=0UL },
    .full_slot = FD_SSPEER_SLOT_UNKNOWN,
    .incr_slot = FD_SSPEER_SLOT_UNKNOWN,
    .score     = FD_SSPEER_SCORE_INVALID,
    .full_hash = {0},
    .incr_hash = {0},
  };
}

void
fd_sspeer_selector_process_cluster_slot( fd_sspeer_selector_t * selector,
                                         ulong                  full_slot,
                                         ulong                  incr_slot ) {
  if( FD_UNLIKELY( full_slot==FD_SSPEER_SLOT_UNKNOWN ) ) return;

  /* Reject cluster slot updates where the incremental slot is before
     the full slot.  Both must be known for the check to apply.  Genesis
     (full_slot=0, incr_slot=0) is supported. */
  if( FD_UNLIKELY( incr_slot!=FD_SSPEER_SLOT_UNKNOWN && incr_slot<full_slot ) ) return;

  if( FD_LIKELY( selector->incremental_snapshot_fetch ) ) {
    /* The full slot must never regress, regardless of incr_slot. */
    if( FD_UNLIKELY( full_slot<selector->cluster_slot.full ) ) return;

    /* Reject updates that do not advance the cluster slot.
       incr_slot     | stored incr   | reject when
       --------------|---------------|--------------------------------
       valid         | valid         | incr_slot < stored.incremental
                     |               |   OR (incr_slot == stored.incremental
                     |               |       AND full_slot <= stored.full)
       valid         | _SLOT_UNKNOWN | incr_slot <  stored.full
                     |               |   (strict: genesis accepted)
       _SLOT_UNKNOWN | valid         | full_slot <= stored.full
       _SLOT_UNKNOWN | _SLOT_UNKNOWN | full_slot <= stored.full  */
    if( FD_UNLIKELY( incr_slot!=FD_SSPEER_SLOT_UNKNOWN ) ) {
      if( FD_UNLIKELY( selector->cluster_slot.incremental!=FD_SSPEER_SLOT_UNKNOWN ) ) {
        if( FD_UNLIKELY( ( incr_slot<selector->cluster_slot.incremental ||
                         ( incr_slot==selector->cluster_slot.incremental &&
                           full_slot<=selector->cluster_slot.full ) ) ) ) return;
      } else {
        if( FD_UNLIKELY( incr_slot<selector->cluster_slot.full ) ) return;
      }
    } else if( FD_UNLIKELY( full_slot<=selector->cluster_slot.full ) ) return;

  } else {
    if( FD_UNLIKELY( full_slot<=selector->cluster_slot.full ) ) return;
  }

  selector->cluster_slot.full = full_slot;
  if( FD_LIKELY( incr_slot!=FD_SSPEER_SLOT_UNKNOWN ) ) {
    selector->cluster_slot.incremental = incr_slot;
  } else if( FD_UNLIKELY( selector->cluster_slot.incremental!=FD_SSPEER_SLOT_UNKNOWN &&
                           selector->cluster_slot.incremental<full_slot ) ) {
    /* The full slot advanced past the incremental slot, so the
       incremental reference is stale and must be invalidated. */
    selector->cluster_slot.incremental = FD_SSPEER_SLOT_UNKNOWN;
  }

  if( FD_UNLIKELY( score_treap_ele_cnt( selector->score_treap )==0UL ) ) return;

  /* Rescore all peers
     TODO: make more performant, maybe make a treap rebalance API */
  ulong idx = 0UL;
  for( score_treap_fwd_iter_t iter = score_treap_fwd_iter_init( selector->score_treap, selector->pool );
        !score_treap_fwd_iter_done( iter );
        iter = score_treap_fwd_iter_next( iter, selector->pool ) ) {
    /* Do not remove the peer from the treap while the iterator is
       running.  Removing from peer_map(s) here is ok. */
    fd_sspeer_private_t * peer = score_treap_fwd_iter_ele( iter, selector->pool );
    fd_sspeer_private_t * shadow_peer = peer_pool_ele_acquire( selector->pool );
    shadow_peer->latency   = peer->latency;
    shadow_peer->full_slot = peer->full_slot;
    shadow_peer->incr_slot = peer->incr_slot;
    shadow_peer->addr      = peer->addr;
    shadow_peer->key       = peer->key;
    shadow_peer->score     = fd_sspeer_selector_score( selector, shadow_peer->latency, shadow_peer->full_slot, shadow_peer->incr_slot );
    shadow_peer->valid     = peer->valid;
    fd_memcpy( shadow_peer->full_hash, peer->full_hash, FD_HASH_FOOTPRINT );
    fd_memcpy( shadow_peer->incr_hash, peer->incr_hash, FD_HASH_FOOTPRINT );
    score_treap_ele_insert( selector->shadow_score_treap, shadow_peer, selector->pool );
    selector->peer_idx_list[ idx++ ] = peer_pool_idx( selector->pool, peer );
    peer_map_by_key_ele_remove_fast( selector->map_by_key, peer, selector->pool );
    peer_map_by_addr_ele_remove_fast( selector->map_by_addr, peer, selector->pool );
    peer_map_by_key_ele_insert( selector->map_by_key, shadow_peer, selector->pool );
    peer_map_by_addr_ele_insert( selector->map_by_addr, shadow_peer, selector->pool );
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

ulong
fd_sspeer_selector_peer_map_by_key_ele_cnt( fd_sspeer_selector_t * selector ) {
  ulong cnt = 0UL;
  for( peer_map_by_key_iter_t iter = peer_map_by_key_iter_init( selector->map_by_key, selector->pool );
      !peer_map_by_key_iter_done( iter, selector->map_by_key, selector->pool );
      iter = peer_map_by_key_iter_next( iter, selector->map_by_key, selector->pool ) ) {
    cnt++;
  }
  return cnt;
}

ulong
fd_sspeer_selector_peer_map_by_addr_ele_cnt( fd_sspeer_selector_t * selector ) {
  ulong cnt = 0UL;
  for( peer_map_by_addr_iter_t iter = peer_map_by_addr_iter_init( selector->map_by_addr, selector->pool );
      !peer_map_by_addr_iter_done( iter, selector->map_by_addr, selector->pool );
      iter = peer_map_by_addr_iter_next( iter, selector->map_by_addr, selector->pool ) ) {
    cnt++;
  }
  return cnt;
}
