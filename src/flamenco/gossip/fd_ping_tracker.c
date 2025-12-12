#include "fd_ping_tracker.h"

#include "../../ballet/sha256/fd_sha256.h"
#include "../../util/log/fd_log.h"

#define FD_PING_TRACKER_STATE_UNPINGED         (0)
#define FD_PING_TRACKER_STATE_INVALID          (1)
#define FD_PING_TRACKER_STATE_VALID            (2)
#define FD_PING_TRACKER_STATE_VALID_REFRESHING (3)
#define FD_PING_TRACKER_STATE_PERMANENT        (4)

#define FD_PING_TRACKER_EXEMPT_STAKE (1000000000UL)

struct pubkey_private {
  uchar b[ 32UL ];
};

typedef struct pubkey_private pubkey_private_t;

struct fd_ping_peer {
  fd_ip4_port_t    address;
  int              is_entrypoint;
  pubkey_private_t identity_pubkey;
  uchar            ping_token[ 32UL ];
  uchar            expected_pong_hash[ 32UL ];

  uchar state;

  long  next_ping_nanos;
  long  valid_until_nanos;
  long  last_rx_nanos;

  ulong pool_next;

  ulong lru_prev;
  ulong lru_next;

  ulong map_next;
  ulong map_prev;

  union {
    struct {
      ulong unpinged_next;
      ulong unpinged_prev;
    };

    struct {
      ulong waiting_next;
      ulong waiting_prev;
    };

    struct {
      ulong refreshing_next;
      ulong refreshing_prev;
    };
  };
};

typedef struct fd_ping_peer fd_ping_peer_t;

#define POOL_NAME pool
#define POOL_NEXT pool_next
#define POOL_T    fd_ping_peer_t
#include "../../util/tmpl/fd_pool.c"

#define DLIST_NAME  lru_list
#define DLIST_ELE_T fd_ping_peer_t
#define DLIST_PREV  lru_prev
#define DLIST_NEXT  lru_next
#include "../../util/tmpl/fd_dlist.c"

#define DLIST_NAME  unpinged_list
#define DLIST_ELE_T fd_ping_peer_t
#define DLIST_PREV  unpinged_prev
#define DLIST_NEXT  unpinged_next
#include "../../util/tmpl/fd_dlist.c"

#define DLIST_NAME  waiting_list
#define DLIST_ELE_T fd_ping_peer_t
#define DLIST_PREV  waiting_prev
#define DLIST_NEXT  waiting_next
#include "../../util/tmpl/fd_dlist.c"

#define DLIST_NAME  refreshing_list
#define DLIST_ELE_T fd_ping_peer_t
#define DLIST_PREV  refreshing_prev
#define DLIST_NEXT  refreshing_next
#include "../../util/tmpl/fd_dlist.c"

#define MAP_NAME  peer_map
#define MAP_ELE_T fd_ping_peer_t
#define MAP_KEY_T pubkey_private_t
#define MAP_KEY   identity_pubkey
#define MAP_IDX_T ulong
#define MAP_NEXT  map_next
#define MAP_PREV  map_prev
#define MAP_KEY_HASH(k,s) ((s) ^ fd_ulong_load_8( (k)->b ))
#define MAP_KEY_EQ(k0,k1) (!memcmp((k0)->b, (k1)->b, 32UL))
#define MAP_OPTIMIZE_RANDOM_ACCESS_REMOVAL 1
#include "../../util/tmpl/fd_map_chain.c"

struct __attribute__((aligned(FD_PING_TRACKER_ALIGN))) fd_ping_tracker_private {
  fd_rng_t * rng;
  fd_sha256_t sha[1];

  ulong           entrypoints_cnt;
  fd_ip4_port_t * entrypoints;

  fd_ping_tracker_metrics_t metrics[1];

  fd_ping_peer_t *    pool;
  lru_list_t *        lru;

  unpinged_list_t *   unpinged;
  waiting_list_t *    waiting;
  refreshing_list_t * refreshing;

  peer_map_t *        peers;

  fd_ping_tracker_change_fn change_fn;
  void *                    change_fn_ctx;

  ulong magic; /* ==FD_PING_TRACKER_MAGIC */
};

FD_FN_CONST ulong
fd_ping_tracker_align( void ) {
  return FD_PING_TRACKER_ALIGN;
}

FD_FN_CONST ulong
fd_ping_tracker_footprint( ulong entrypoints_len ) {
  ulong l;
  l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, FD_PING_TRACKER_ALIGN,   sizeof(fd_ping_tracker_t)             );
  l = FD_LAYOUT_APPEND( l, alignof(fd_ip4_port_t),  entrypoints_len*sizeof(fd_ip4_port_t) );
  l = FD_LAYOUT_APPEND( l, pool_align(),            pool_footprint( FD_PING_TRACKER_MAX ) );
  l = FD_LAYOUT_APPEND( l, lru_list_align(),        lru_list_footprint()                  );
  l = FD_LAYOUT_APPEND( l, unpinged_list_align(),   unpinged_list_footprint()             );
  l = FD_LAYOUT_APPEND( l, waiting_list_align(),    waiting_list_footprint()              );
  l = FD_LAYOUT_APPEND( l, refreshing_list_align(), refreshing_list_footprint()           );
  l = FD_LAYOUT_APPEND( l, peer_map_align(),        peer_map_footprint( 8192UL )          );
  return FD_LAYOUT_FINI( l, FD_PING_TRACKER_ALIGN );
}

void *
fd_ping_tracker_new( void *                    shmem,
                     fd_rng_t *                rng,
                     ulong                     entrypoints_len,
                     fd_ip4_port_t const *     entrypoints,
                     fd_ping_tracker_change_fn change_fn,
                     void *                    change_fn_ctx ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !rng ) ) {
    FD_LOG_WARNING(( "NULL rng" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_ping_tracker_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_ping_tracker_t * ping_tracker = FD_SCRATCH_ALLOC_APPEND( l, FD_PING_TRACKER_ALIGN,   sizeof(fd_ping_tracker_t)             );
  void * _entrypoints              = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_ip4_port_t),  entrypoints_len*sizeof(fd_ip4_port_t) );
  void * _pool                     = FD_SCRATCH_ALLOC_APPEND( l, pool_align(),            pool_footprint( FD_PING_TRACKER_MAX ) );
  void * _lru                      = FD_SCRATCH_ALLOC_APPEND( l, lru_list_align(),        lru_list_footprint()                  );
  void * _unpinged                 = FD_SCRATCH_ALLOC_APPEND( l, unpinged_list_align(),   unpinged_list_footprint()             );
  void * _waiting                  = FD_SCRATCH_ALLOC_APPEND( l, waiting_list_align(),    waiting_list_footprint()              );
  void * _refreshing               = FD_SCRATCH_ALLOC_APPEND( l, refreshing_list_align(), refreshing_list_footprint()           );
  void * _peers                    = FD_SCRATCH_ALLOC_APPEND( l, peer_map_align(),        peer_map_footprint( 8192UL )          );

  ping_tracker->rng = rng;
  ping_tracker->pool = pool_join( pool_new( _pool, FD_PING_TRACKER_MAX ) );
  FD_TEST( ping_tracker->pool );
  ping_tracker->lru  = lru_list_join( lru_list_new( _lru ) );
  FD_TEST( ping_tracker->lru );
  ping_tracker->unpinged = unpinged_list_join( unpinged_list_new( _unpinged ) );
  FD_TEST( ping_tracker->unpinged );
  ping_tracker->waiting = waiting_list_join( waiting_list_new( _waiting ) );
  FD_TEST( ping_tracker->waiting );
  ping_tracker->refreshing = refreshing_list_join( refreshing_list_new( _refreshing ) );
  FD_TEST( ping_tracker->refreshing );
  ping_tracker->peers = peer_map_join( peer_map_new( _peers, 8192UL, fd_rng_ulong( rng ) ) );
  FD_TEST( ping_tracker->peers );

  ping_tracker->entrypoints_cnt = entrypoints_len;
  ping_tracker->entrypoints = (fd_ip4_port_t *)_entrypoints;
  fd_memcpy( ping_tracker->entrypoints, entrypoints, entrypoints_len*sizeof(fd_ip4_port_t) );

  ping_tracker->change_fn     = change_fn;
  ping_tracker->change_fn_ctx = change_fn_ctx;

  FD_TEST( fd_sha256_join( fd_sha256_new( ping_tracker->sha ) ) );

  fd_memset( ping_tracker->metrics, 0, sizeof(fd_ping_tracker_metrics_t) );

  FD_COMPILER_MFENCE();
  FD_VOLATILE( ping_tracker->magic ) = FD_PING_TRACKER_MAGIC;
  FD_COMPILER_MFENCE();

  return (void *)ping_tracker;
}

fd_ping_tracker_t *
fd_ping_tracker_join( void * shpt ) {
  if( FD_UNLIKELY( !shpt ) ) {
    FD_LOG_WARNING(( "NULL shpt" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shpt, fd_ping_tracker_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shpt" ));
    return NULL;
  }

  fd_ping_tracker_t * ping_tracker = (fd_ping_tracker_t *)shpt;

  if( FD_UNLIKELY( ping_tracker->magic!=FD_PING_TRACKER_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return ping_tracker;
}

fd_ping_tracker_metrics_t const *
fd_ping_tracker_metrics( fd_ping_tracker_t const * ping_tracker ) {
  return ping_tracker->metrics;
}

static int
state_is_active( uchar state ) {
  switch( state ) {
    case FD_PING_TRACKER_STATE_VALID:
    case FD_PING_TRACKER_STATE_VALID_REFRESHING:
    case FD_PING_TRACKER_STATE_PERMANENT:
      return 1;
    case FD_PING_TRACKER_STATE_UNPINGED:
    case FD_PING_TRACKER_STATE_INVALID:
    default:
      return 0;
  }
}

static void
remove_tracking( fd_ping_tracker_t * ping_tracker,
                 fd_ping_peer_t *    peer ) {
  switch( peer->state ) {
    case FD_PING_TRACKER_STATE_UNPINGED:
      ping_tracker->metrics->unpinged_cnt--;
      unpinged_list_ele_remove( ping_tracker->unpinged, peer, ping_tracker->pool );
      break;
    case FD_PING_TRACKER_STATE_INVALID:
      ping_tracker->metrics->invalid_cnt--;
      refreshing_list_ele_remove( ping_tracker->refreshing, peer, ping_tracker->pool );
      break;
    case FD_PING_TRACKER_STATE_VALID:
      ping_tracker->metrics->valid_cnt--;
      waiting_list_ele_remove( ping_tracker->waiting, peer, ping_tracker->pool );
      break;
    case FD_PING_TRACKER_STATE_VALID_REFRESHING:
      ping_tracker->metrics->refreshing_cnt--;
      refreshing_list_ele_remove( ping_tracker->refreshing, peer, ping_tracker->pool );
      break;
    case FD_PING_TRACKER_STATE_PERMANENT:
      ping_tracker->metrics->permanent_cnt--;
      break;
    default:
      FD_LOG_ERR(( "Unknown state %d", peer->state ));
  }
}

static void
generate_ping_token( fd_ping_peer_t * peer,
                     fd_rng_t *       rng,
                     fd_sha256_t *    sha ) {
  fd_memcpy( peer->ping_token, "SOLANA_PING_PONG", 16UL );
  for( ulong i=16UL; i<32UL; i++ ) peer->ping_token[ i ] = fd_rng_uchar( rng );

  fd_sha256_init( sha );
  fd_sha256_append( sha, "SOLANA_PING_PONG", 16UL );
  fd_sha256_append( sha, peer->ping_token, 32UL );
  fd_sha256_fini( sha, peer->expected_pong_hash );
}

static inline int
is_entrypoint( fd_ping_tracker_t const * ping_tracker,
               fd_ip4_port_t             peer_addr ) {
  for( ulong i=0UL; i<ping_tracker->entrypoints_cnt; i++ ) {
    if( FD_UNLIKELY( peer_addr.l==ping_tracker->entrypoints[ i ].l ) ) return 1;
  }
  return 0;
}

void
fd_ping_tracker_track( fd_ping_tracker_t * ping_tracker,
                       uchar const *       peer_pubkey,
                       ulong               peer_stake,
                       fd_ip4_port_t       peer_address,
                       long                now ) {
  fd_ping_peer_t * peer = peer_map_ele_query( ping_tracker->peers, fd_type_pun_const( peer_pubkey ), NULL, ping_tracker->pool );

  if( FD_UNLIKELY( !peer ) ) {
    if( FD_UNLIKELY( !pool_free( ping_tracker->pool ) ) ) {
      ping_tracker->metrics->evicted_cnt++;
      peer = lru_list_ele_pop_head( ping_tracker->lru, ping_tracker->pool );
      FD_TEST( peer );
      remove_tracking( ping_tracker, peer );
      peer_map_ele_remove_fast( ping_tracker->peers, peer, ping_tracker->pool );
      ping_tracker->change_fn( ping_tracker->change_fn_ctx, peer->identity_pubkey.b, peer->address, now, FD_PING_TRACKER_CHANGE_TYPE_REMOVE, pool_idx( ping_tracker->pool, peer ) );
    } else {
      peer = pool_ele_acquire( ping_tracker->pool );
      FD_TEST( peer );
    }

    fd_memcpy( peer->identity_pubkey.b, peer_pubkey, 32UL );
    peer->address       = peer_address;
    peer->is_entrypoint = is_entrypoint( ping_tracker, peer_address );
    peer->last_rx_nanos = now;
    generate_ping_token( peer, ping_tracker->rng, ping_tracker->sha );
    ping_tracker->metrics->tracked_cnt++;

    if( peer_stake>=FD_PING_TRACKER_EXEMPT_STAKE || peer->is_entrypoint ) {
      peer->state             = FD_PING_TRACKER_STATE_PERMANENT;
      peer->valid_until_nanos = LONG_MAX;
      peer->next_ping_nanos   = LONG_MAX;
      ping_tracker->metrics->permanent_cnt++;
      ping_tracker->change_fn( ping_tracker->change_fn_ctx, peer->identity_pubkey.b, peer->address, now, FD_PING_TRACKER_CHANGE_TYPE_ACTIVE, pool_idx( ping_tracker->pool, peer ) );
    } else {
      peer->state             = FD_PING_TRACKER_STATE_UNPINGED;
      peer->valid_until_nanos = 0L;
      peer->next_ping_nanos   = now;
      unpinged_list_ele_push_head( ping_tracker->unpinged, peer, ping_tracker->pool );
      ping_tracker->metrics->unpinged_cnt++;
      ping_tracker->change_fn( ping_tracker->change_fn_ctx, peer->identity_pubkey.b, peer->address, now, FD_PING_TRACKER_CHANGE_TYPE_INACTIVE, pool_idx( ping_tracker->pool, peer ) );
    }

    peer_map_ele_insert( ping_tracker->peers, peer, ping_tracker->pool );
    lru_list_ele_push_tail( ping_tracker->lru, peer, ping_tracker->pool );
  } else {
    if( FD_UNLIKELY( peer_address.l!=peer->address.l ) ) {
      /* Node changed address, update the address.  Any existing pongs
         are no longer valid. */
      ping_tracker->metrics->address_changed_cnt++;
      ping_tracker->change_fn( ping_tracker->change_fn_ctx, peer->identity_pubkey.b, peer->address, now, FD_PING_TRACKER_CHANGE_TYPE_REMOVE, pool_idx( ping_tracker->pool, peer ) );
      remove_tracking( ping_tracker, peer );
      lru_list_ele_remove( ping_tracker->lru, peer, ping_tracker->pool );
      peer_map_ele_remove_fast( ping_tracker->peers, peer, ping_tracker->pool );
      pool_ele_release( ping_tracker->pool, peer );
      ping_tracker->metrics->tracked_cnt--;
      fd_ping_tracker_track( ping_tracker, peer_pubkey, peer_stake, peer_address, now );
      return;
    }
    peer->last_rx_nanos = now;
    lru_list_ele_remove( ping_tracker->lru, peer, ping_tracker->pool );
    lru_list_ele_push_tail( ping_tracker->lru, peer, ping_tracker->pool );
  }
}

void
fd_ping_tracker_update_stake( fd_ping_tracker_t * ping_tracker,
                              uchar const *       peer_pubkey,
                              ulong               peer_stake,
                              long                now ) {
  fd_ping_peer_t * peer = peer_map_ele_query( ping_tracker->peers, fd_type_pun_const( peer_pubkey ), NULL, ping_tracker->pool );

  if( FD_UNLIKELY( !peer ) ) return;

  if( FD_UNLIKELY( peer->is_entrypoint ) ) {
    FD_TEST( peer->state==FD_PING_TRACKER_STATE_PERMANENT );
    return;
  }

  int const was_exempt = peer->state==FD_PING_TRACKER_STATE_PERMANENT;
  int const is_exempt  = peer_stake>=FD_PING_TRACKER_EXEMPT_STAKE;
  if( FD_UNLIKELY( was_exempt && !is_exempt ) ) {
    /* Peer used to be exempted by stake amount but no longer has the
       required stake, set to inactive and ping them the normal way. */
    ping_tracker->metrics->stake_changed_cnt++;
    remove_tracking( ping_tracker, peer );
    ping_tracker->change_fn( ping_tracker->change_fn_ctx, peer->identity_pubkey.b, peer->address, now, FD_PING_TRACKER_CHANGE_TYPE_INACTIVE, pool_idx( ping_tracker->pool, peer ) );
    peer->state             = FD_PING_TRACKER_STATE_UNPINGED;
    peer->next_ping_nanos   = now;
    peer->valid_until_nanos = 0L;
    ping_tracker->metrics->unpinged_cnt++;
    unpinged_list_ele_push_head( ping_tracker->unpinged, peer, ping_tracker->pool );
  }
  else if( FD_UNLIKELY( !was_exempt && is_exempt ) ) {
    /* Peer used to be pinged normally but now has the enough stake to
       be exempted. */
    ping_tracker->metrics->stake_changed_cnt++;
    remove_tracking( ping_tracker, peer );
    if( FD_UNLIKELY( !state_is_active( peer->state ) ) ) ping_tracker->change_fn( ping_tracker->change_fn_ctx, peer->identity_pubkey.b, peer->address, now, FD_PING_TRACKER_CHANGE_TYPE_ACTIVE, pool_idx( ping_tracker->pool, peer ) );
    peer->state             = FD_PING_TRACKER_STATE_PERMANENT;
    peer->next_ping_nanos   = LONG_MAX;
    peer->valid_until_nanos = LONG_MAX;
    ping_tracker->metrics->permanent_cnt++;
  }
}

void
fd_ping_tracker_register( fd_ping_tracker_t * ping_tracker,
                          uchar const *       peer_pubkey,
                          fd_ip4_port_t       peer_address,
                          uchar const *       pong_token,
                          long                now ) {
  fd_ping_peer_t * peer = peer_map_ele_query( ping_tracker->peers, fd_type_pun_const( peer_pubkey ), NULL, ping_tracker->pool );

  if( FD_UNLIKELY( !peer ) ) {
    ping_tracker->metrics->pong_result[ 0UL ]++;
    return;
  }

  if( FD_UNLIKELY( peer->state!=FD_PING_TRACKER_STATE_INVALID && peer->state!=FD_PING_TRACKER_STATE_VALID_REFRESHING ) ) {
    ping_tracker->metrics->pong_result[ 1UL ]++;
    return;
  }

  /* If a peer responds with the wrong pong hash or has an unexpected
     source address, ignore the invalid pong and invalidate the peer. */
  if( FD_UNLIKELY( peer_address.l!=peer->address.l || memcmp( pong_token, peer->expected_pong_hash, 32UL ) ) ) {
    if( peer_address.l!=peer->address.l ) ping_tracker->metrics->pong_result[ 2UL ]++;
    else                                  ping_tracker->metrics->pong_result[ 3UL ]++;
    if( peer->state==FD_PING_TRACKER_STATE_VALID_REFRESHING ) {
      ping_tracker->change_fn( ping_tracker->change_fn_ctx, peer->identity_pubkey.b, peer->address, now, FD_PING_TRACKER_CHANGE_TYPE_INACTIVE, pool_idx( ping_tracker->pool, peer ) );
      ping_tracker->metrics->refreshing_cnt--;
      peer->state = FD_PING_TRACKER_STATE_INVALID;
      peer->valid_until_nanos = 0L;
      ping_tracker->metrics->invalid_cnt++;
    }
    return;
  }

  remove_tracking( ping_tracker, peer );
  peer->valid_until_nanos = now+20L*60L*1000L*1000L*1000L; /* 20 mintues of validity */
  peer->next_ping_nanos   = now+18L*60L*1000L*1000L*1000L; /* 18 minutes til we start trying to refresh */
  if( FD_UNLIKELY( !state_is_active( peer->state ) ) ) ping_tracker->change_fn( ping_tracker->change_fn_ctx, peer->identity_pubkey.b, peer->address, now, FD_PING_TRACKER_CHANGE_TYPE_ACTIVE, pool_idx( ping_tracker->pool, peer ) );
  peer->state = FD_PING_TRACKER_STATE_VALID;
  ping_tracker->metrics->valid_cnt++;
  waiting_list_ele_push_tail( ping_tracker->waiting, peer, ping_tracker->pool );
  ping_tracker->metrics->pong_result[ 4UL ]++;
}

void
fd_ping_tracker_advance( fd_ping_tracker_t * ping_tracker,
                         long                now ) {
  /* Remove peers that have not sent us contact information recently. */
  while( FD_LIKELY( !lru_list_is_empty( ping_tracker->lru, ping_tracker->pool ) ) ) {
    fd_ping_peer_t * peer = lru_list_ele_peek_head( ping_tracker->lru, ping_tracker->pool );
    if( FD_LIKELY( peer->last_rx_nanos>=now-20L*1000L*1000L*1000L ) ) break;
    ping_tracker->metrics->retired_cnt++;
    ping_tracker->change_fn( ping_tracker->change_fn_ctx, peer->identity_pubkey.b, peer->address, now, FD_PING_TRACKER_CHANGE_TYPE_REMOVE, pool_idx( ping_tracker->pool, peer ) );
    remove_tracking( ping_tracker, peer );
    lru_list_ele_pop_head( ping_tracker->lru, ping_tracker->pool );
    peer_map_ele_remove_fast( ping_tracker->peers, peer, ping_tracker->pool );
    pool_ele_release( ping_tracker->pool, peer );
  }

  /* Move peers from waiting to refreshing when they are soon to expire. */
  while( FD_LIKELY( !waiting_list_is_empty( ping_tracker->waiting, ping_tracker->pool ) ) ) {
    fd_ping_peer_t * peer = waiting_list_ele_peek_head( ping_tracker->waiting, ping_tracker->pool );
    if( FD_LIKELY( peer->next_ping_nanos>now ) ) break;
    waiting_list_ele_pop_head( ping_tracker->waiting, ping_tracker->pool );
    FD_TEST( peer->state==FD_PING_TRACKER_STATE_VALID );
    ping_tracker->metrics->valid_cnt--;
    refreshing_list_ele_push_tail( ping_tracker->refreshing, peer, ping_tracker->pool );
    peer->state = FD_PING_TRACKER_STATE_VALID_REFRESHING;
    ping_tracker->metrics->refreshing_cnt++;
  }
}

int
fd_ping_tracker_pop_request( fd_ping_tracker_t *    ping_tracker,
                             long                   now,
                             uchar const **         out_peer_pubkey,
                             fd_ip4_port_t const ** out_peer_address,
                             uchar const **         out_token ) {
  if( FD_UNLIKELY( !unpinged_list_is_empty( ping_tracker->unpinged, ping_tracker->pool ) ) ) {
    fd_ping_peer_t * unpinged = unpinged_list_ele_pop_head( ping_tracker->unpinged, ping_tracker->pool );
    FD_TEST( unpinged->state==FD_PING_TRACKER_STATE_UNPINGED );
    refreshing_list_ele_push_tail( ping_tracker->refreshing, unpinged, ping_tracker->pool );
    unpinged->state           = FD_PING_TRACKER_STATE_INVALID;
    ping_tracker->metrics->unpinged_cnt--;
    ping_tracker->metrics->invalid_cnt++;
    unpinged->next_ping_nanos = now+1L*1000L*1000L*1000L;
    *out_peer_pubkey          = unpinged->identity_pubkey.b;
    *out_peer_address         = &unpinged->address;
    *out_token                = unpinged->ping_token;
    ping_tracker->metrics->ping_cnt++;
    return 1;
  }

  if( FD_UNLIKELY( !refreshing_list_is_empty( ping_tracker->refreshing, ping_tracker->pool ) ) ) {
    fd_ping_peer_t * next = refreshing_list_ele_peek_head( ping_tracker->refreshing, ping_tracker->pool );

    FD_TEST( next->state==FD_PING_TRACKER_STATE_VALID_REFRESHING || next->state==FD_PING_TRACKER_STATE_INVALID );
    FD_TEST( next->next_ping_nanos && next->next_ping_nanos!=LONG_MAX );
    if( FD_LIKELY( next->state!=FD_PING_TRACKER_STATE_INVALID ) ) FD_TEST( next->valid_until_nanos );
    else                                                          FD_TEST( !next->valid_until_nanos );

    if( FD_UNLIKELY( next->state==FD_PING_TRACKER_STATE_VALID_REFRESHING && next->valid_until_nanos<now ) ) {
      ping_tracker->metrics->expired_cnt++;
      ping_tracker->change_fn( ping_tracker->change_fn_ctx, next->identity_pubkey.b, next->address, now, FD_PING_TRACKER_CHANGE_TYPE_INACTIVE, pool_idx( ping_tracker->pool, next ) );
      ping_tracker->metrics->refreshing_cnt--;
      next->state = FD_PING_TRACKER_STATE_INVALID;
      next->valid_until_nanos = 0L;
      ping_tracker->metrics->invalid_cnt++;
    }

    /* The next ping we want to send is still in the future, so do
       nothing for now. */
    if( FD_LIKELY( next->next_ping_nanos>now ) ) return 0;

    /* Push the element to the back of the refreshing list now, so it
       starts getting pinged every second. */
    refreshing_list_ele_pop_head( ping_tracker->refreshing, ping_tracker->pool );
    refreshing_list_ele_push_tail( ping_tracker->refreshing, next, ping_tracker->pool );
    next->next_ping_nanos = now+1L*1000L*1000L*1000L;
    *out_peer_pubkey      = next->identity_pubkey.b;
    *out_peer_address     = &next->address;
    *out_token            = next->ping_token;
    ping_tracker->metrics->ping_cnt++;
    return 1;
  }

  return 0;
}
