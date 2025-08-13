#include "fd_ping_tracker.h"

#include "../../ballet/sha256/fd_sha256.h"
#include "../../util/log/fd_log.h"

#define FD_PING_TRACKER_STATE_UNPINGED         (0)
#define FD_PING_TRACKER_STATE_INVALID          (1)
#define FD_PING_TRACKER_STATE_VALID            (2)
#define FD_PING_TRACKER_STATE_VALID_REFRESHING (3)

struct pubkey_private {
  uchar b[ 32UL ];
};

typedef struct pubkey_private pubkey_private_t;

struct fd_ping_peer {
  fd_ip4_port_t    address;
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

static inline void
hash_ping_token( uchar const * ping_token,
                 uchar         expected_pong_token[ static 32UL ],
                 fd_sha256_t * sha ) {
  fd_sha256_init( sha );
  fd_sha256_append( sha, "SOLANA_PING_PONG", 16UL );
  fd_sha256_append( sha, ping_token, 32UL );
  fd_sha256_fini( sha, expected_pong_token );
}

static void
remove_tracking( fd_ping_tracker_t * ping_tracker,
                 fd_ping_peer_t *    peer ) {
  if( FD_UNLIKELY( peer->state==FD_PING_TRACKER_STATE_UNPINGED ) ) unpinged_list_ele_remove( ping_tracker->unpinged, peer, ping_tracker->pool );
  else if( FD_LIKELY( peer->state==FD_PING_TRACKER_STATE_VALID ) ) waiting_list_ele_remove( ping_tracker->waiting, peer, ping_tracker->pool );
  else                                                             refreshing_list_ele_remove( ping_tracker->refreshing, peer, ping_tracker->pool );
}

static void
generate_ping_token( fd_ping_peer_t * peer,
                     fd_rng_t *       rng ) {
  fd_memcpy( peer->ping_token, "SOLANA_PING_PONG", 16UL );
  for( ulong i=16UL; i<32UL; i++ ) peer->ping_token[ i ] = fd_rng_uchar( rng );
}

static inline int
is_entrypoint( fd_ping_tracker_t const * ping_tracker,
               fd_ip4_port_t             peer_addr ) {
  for( ulong i=0UL; i<ping_tracker->entrypoints_cnt; i++ ) {
    if( FD_UNLIKELY( peer_addr.addr==ping_tracker->entrypoints[ i ].addr && peer_addr.port==ping_tracker->entrypoints[ i ].port ) ) return 1;
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
    if( FD_LIKELY( peer_stake>=1000000000UL ) ) return;
    if( FD_UNLIKELY( is_entrypoint( ping_tracker, peer_address ) ) ) return;

    if( FD_UNLIKELY( !pool_free( ping_tracker->pool ) ) ) {
      peer = lru_list_ele_pop_head( ping_tracker->lru, ping_tracker->pool );
      remove_tracking( ping_tracker, peer );
      peer_map_ele_remove_fast( ping_tracker->peers, peer, ping_tracker->pool );
      if( FD_LIKELY( peer->state==FD_PING_TRACKER_STATE_VALID || peer->state==FD_PING_TRACKER_STATE_VALID_REFRESHING ) ) {
        ping_tracker->change_fn( ping_tracker->change_fn_ctx, peer->identity_pubkey.b, peer->address, now, FD_PING_TRACKER_CHANGE_TYPE_INACTIVE );
      }
      switch( peer->state ) {
        case FD_PING_TRACKER_STATE_UNPINGED:         ping_tracker->metrics->unpinged_cnt--; break;
        case FD_PING_TRACKER_STATE_INVALID:          ping_tracker->metrics->invalid_cnt--; break;
        case FD_PING_TRACKER_STATE_VALID:            ping_tracker->metrics->valid_cnt--; break;
        case FD_PING_TRACKER_STATE_VALID_REFRESHING: ping_tracker->metrics->refreshing_cnt--; break;
        default: FD_LOG_ERR(( "Unknown state %d", peer->state )); return;
      }
      ping_tracker->metrics->peers_evicted++;
    } else {
      peer = pool_ele_acquire( ping_tracker->pool );
    }

    fd_memcpy( peer->identity_pubkey.b, peer_pubkey, 32UL );
    peer->address           = peer_address;
    peer->valid_until_nanos = 0L;
    peer->next_ping_nanos   = now;
    peer->state             = FD_PING_TRACKER_STATE_UNPINGED;
    ping_tracker->metrics->unpinged_cnt++;
    ping_tracker->metrics->tracked_cnt++;

    generate_ping_token( peer, ping_tracker->rng );
    hash_ping_token( peer->ping_token, peer->expected_pong_hash, ping_tracker->sha );

    unpinged_list_ele_push_head( ping_tracker->unpinged, peer, ping_tracker->pool );
    peer_map_ele_insert( ping_tracker->peers, peer, ping_tracker->pool );
    lru_list_ele_push_tail( ping_tracker->lru, peer, ping_tracker->pool );
  } else {
    if( FD_LIKELY( peer_stake>=1000000000UL || is_entrypoint( ping_tracker, peer_address ) ) ) {
      /* Node went from unstaked (or low staked) to >=1 SOL, or to being
         an entrypoint.  No longer need to ping it. */
      peer_map_ele_remove_fast( ping_tracker->peers, peer, ping_tracker->pool );
      lru_list_ele_remove( ping_tracker->lru, peer, ping_tracker->pool );
      remove_tracking( ping_tracker, peer );
      pool_ele_release( ping_tracker->pool, peer );
      if( FD_LIKELY( peer->state==FD_PING_TRACKER_STATE_VALID || peer->state==FD_PING_TRACKER_STATE_VALID_REFRESHING ) ) {
        ping_tracker->change_fn( ping_tracker->change_fn_ctx, peer->identity_pubkey.b, peer->address, now, FD_PING_TRACKER_CHANGE_TYPE_INACTIVE_STAKED );
      }
      ping_tracker->metrics->stake_changed_cnt++;
      switch( peer->state ) {
        case FD_PING_TRACKER_STATE_UNPINGED:         ping_tracker->metrics->unpinged_cnt--; break;
        case FD_PING_TRACKER_STATE_INVALID:          ping_tracker->metrics->invalid_cnt--; break;
        case FD_PING_TRACKER_STATE_VALID:            ping_tracker->metrics->valid_cnt--; break;
        case FD_PING_TRACKER_STATE_VALID_REFRESHING: ping_tracker->metrics->refreshing_cnt--; break;
        default: FD_LOG_ERR(( "Unknown state %d", peer->state )); return;
      }
      return;
    }

    if( FD_UNLIKELY( peer_address.addr!=peer->address.addr || peer_address.port!=peer->address.port ) ) {
      /* Node changed address, update the address.  Any existing pongs
         are no longer valid. */
      peer->address           = peer_address;
      peer->valid_until_nanos = 0UL;
      remove_tracking( ping_tracker, peer );
      if( FD_LIKELY( peer->state==FD_PING_TRACKER_STATE_VALID || peer->state==FD_PING_TRACKER_STATE_VALID_REFRESHING ) ) {
        ping_tracker->change_fn( ping_tracker->change_fn_ctx, peer->identity_pubkey.b, peer->address, now, FD_PING_TRACKER_CHANGE_TYPE_INACTIVE );
      }
      ping_tracker->metrics->address_changed_cnt++;
      switch( peer->state ) {
        case FD_PING_TRACKER_STATE_UNPINGED:         ping_tracker->metrics->unpinged_cnt--; break;
        case FD_PING_TRACKER_STATE_INVALID:          ping_tracker->metrics->invalid_cnt--; break;
        case FD_PING_TRACKER_STATE_VALID:            ping_tracker->metrics->valid_cnt--; break;
        case FD_PING_TRACKER_STATE_VALID_REFRESHING: ping_tracker->metrics->refreshing_cnt--; break;
        default: FD_LOG_ERR(( "Unknown state %d", peer->state )); return;
      }
      peer->next_ping_nanos = now;
      peer->state           = FD_PING_TRACKER_STATE_UNPINGED;
      ping_tracker->metrics->unpinged_cnt++;
      generate_ping_token( peer, ping_tracker->rng );
      hash_ping_token( peer->ping_token, peer->expected_pong_hash, ping_tracker->sha );

      unpinged_list_ele_push_head( ping_tracker->unpinged, peer, ping_tracker->pool );
    }
  }

  peer->last_rx_nanos = now;
  lru_list_ele_remove( ping_tracker->lru, peer, ping_tracker->pool );
  lru_list_ele_push_tail( ping_tracker->lru, peer, ping_tracker->pool );
}

void
fd_ping_tracker_register( fd_ping_tracker_t * ping_tracker,
                          uchar const *       peer_pubkey,
                          ulong               peer_stake,
                          fd_ip4_port_t       peer_address,
                          uchar const *       pong_token,
                          long                now ) {
  if( FD_UNLIKELY( peer_stake>=1000000000UL ) ) {
    ping_tracker->metrics->pong_result[ 0UL ]++;
    return;
  }
  if( FD_UNLIKELY( is_entrypoint( ping_tracker, peer_address ) ) ) {
    ping_tracker->metrics->pong_result[ 1UL ]++;
    return;
  }

  fd_ping_peer_t * peer = peer_map_ele_query( ping_tracker->peers, fd_type_pun_const( peer_pubkey ), NULL, ping_tracker->pool );
  if( FD_UNLIKELY( !peer ) ) {
    ping_tracker->metrics->pong_result[ 2UL ]++;
    return;
  }

  if( FD_UNLIKELY( peer_address.addr!=peer->address.addr || peer_address.port!=peer->address.port ) ) {
    ping_tracker->metrics->pong_result[ 3UL ]++;
    return;
  }
  if( FD_UNLIKELY( memcmp( pong_token, peer->expected_pong_hash, 32UL ) ) ) {
    ping_tracker->metrics->pong_result[ 4UL ]++;
    return;
  }

  remove_tracking( ping_tracker, peer );
  peer->valid_until_nanos = now+20L*60L*1000L*1000L*1000L; /* 20 mintues of validity */
  peer->next_ping_nanos   = now+18L*60L*1000L*1000L*1000L; /* 18 minutes til we start trying to refresh */
  if( FD_UNLIKELY( peer->state==FD_PING_TRACKER_STATE_INVALID || peer->state==FD_PING_TRACKER_STATE_UNPINGED ) ) {
    ping_tracker->change_fn( ping_tracker->change_fn_ctx, peer->identity_pubkey.b, peer->address, now, FD_PING_TRACKER_CHANGE_TYPE_ACTIVE );
  }
  switch( peer->state ) {
    case FD_PING_TRACKER_STATE_UNPINGED:         ping_tracker->metrics->unpinged_cnt--; break;
    case FD_PING_TRACKER_STATE_INVALID:          ping_tracker->metrics->invalid_cnt--; break;
    case FD_PING_TRACKER_STATE_VALID:            ping_tracker->metrics->valid_cnt--; break;
    case FD_PING_TRACKER_STATE_VALID_REFRESHING: ping_tracker->metrics->refreshing_cnt--; break;
    default: FD_LOG_ERR(( "Unknown state %d", peer->state )); return;
  }
  peer->state = FD_PING_TRACKER_STATE_VALID;
  ping_tracker->metrics->valid_cnt++;
  waiting_list_ele_push_tail( ping_tracker->waiting, peer, ping_tracker->pool );
  ping_tracker->metrics->pong_result[ 5UL ]++;
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
    return 1;
  }

  for(;;) {
    fd_ping_peer_t * peer_refreshing = NULL;
    if( FD_UNLIKELY( !refreshing_list_is_empty( ping_tracker->refreshing, ping_tracker->pool ) ) ) peer_refreshing = refreshing_list_ele_peek_head( ping_tracker->refreshing, ping_tracker->pool );
    fd_ping_peer_t * peer_waiting = NULL;
    if( FD_UNLIKELY( !waiting_list_is_empty( ping_tracker->waiting, ping_tracker->pool ) ) ) peer_waiting = waiting_list_ele_peek_head( ping_tracker->waiting, ping_tracker->pool );

    fd_ping_peer_t * next;
    if(      FD_UNLIKELY( !peer_refreshing && !peer_waiting ) ) return 0;
    else if( FD_UNLIKELY(  peer_refreshing && !peer_waiting ) ) next = peer_refreshing;
    else if( FD_UNLIKELY( !peer_refreshing &&  peer_waiting ) ) next = peer_waiting;
    else if( FD_UNLIKELY( peer_waiting->next_ping_nanos<peer_refreshing->next_ping_nanos ) ) next = peer_waiting;
    else next = peer_refreshing;

    FD_TEST( next->state!=FD_PING_TRACKER_STATE_UNPINGED );
    FD_TEST( next->next_ping_nanos );
    if( FD_LIKELY( next->state!=FD_PING_TRACKER_STATE_INVALID ) ) FD_TEST( next->valid_until_nanos );
    else                                                          FD_TEST( !next->valid_until_nanos );

    if( FD_UNLIKELY( next->last_rx_nanos<now-20L*1000L*1000L*1000L ) ) {
      /* The peer is no longer sending us contact information, no need
         to ping it and instead remove it from the table. */
      peer_map_ele_remove_fast( ping_tracker->peers, next, ping_tracker->pool );
      lru_list_ele_remove( ping_tracker->lru, next, ping_tracker->pool );
      remove_tracking( ping_tracker, next );
      pool_ele_release( ping_tracker->pool, next );
      if( FD_LIKELY( next->state==FD_PING_TRACKER_STATE_VALID || next->state==FD_PING_TRACKER_STATE_VALID_REFRESHING ) ) {
        ping_tracker->change_fn( ping_tracker->change_fn_ctx, next->identity_pubkey.b, next->address, now, FD_PING_TRACKER_CHANGE_TYPE_INACTIVE );
      }
      switch( next->state ) {
        case FD_PING_TRACKER_STATE_UNPINGED:         ping_tracker->metrics->unpinged_cnt--; break;
        case FD_PING_TRACKER_STATE_INVALID:          ping_tracker->metrics->invalid_cnt--; break;
        case FD_PING_TRACKER_STATE_VALID:            ping_tracker->metrics->valid_cnt--; break;
        case FD_PING_TRACKER_STATE_VALID_REFRESHING: ping_tracker->metrics->refreshing_cnt--; break;
        default: FD_LOG_ERR(( "Unknown state %d", next->state ));
      }
      continue;
    }

    /* The next ping we want to send is still in the future, so do
       nothing for now. */
    if( FD_LIKELY( next->next_ping_nanos>now ) ) return 0;

    if( FD_LIKELY( next==peer_refreshing ) )   refreshing_list_ele_pop_head( ping_tracker->refreshing, ping_tracker->pool );
    else if( FD_LIKELY( next==peer_waiting ) ) waiting_list_ele_pop_head( ping_tracker->waiting, ping_tracker->pool );
    else                                       __builtin_unreachable();

    /* Push the element to the back of the refreshing list now, so it
       starts getting pinged every 60 seconds. */
    refreshing_list_ele_push_tail( ping_tracker->refreshing, next, ping_tracker->pool );
    if( FD_LIKELY( next->state==FD_PING_TRACKER_STATE_VALID ) ) {
      next->state = FD_PING_TRACKER_STATE_VALID_REFRESHING;
      ping_tracker->metrics->valid_cnt--;
      ping_tracker->metrics->refreshing_cnt++;
    } else if( FD_LIKELY( next->state==FD_PING_TRACKER_STATE_VALID_REFRESHING && next->valid_until_nanos<=now ) ) {
      ping_tracker->change_fn( ping_tracker->change_fn_ctx, next->identity_pubkey.b, next->address, now, FD_PING_TRACKER_CHANGE_TYPE_INACTIVE );
      switch( next->state ) {
        case FD_PING_TRACKER_STATE_UNPINGED:         ping_tracker->metrics->unpinged_cnt--; break;
        case FD_PING_TRACKER_STATE_INVALID:          ping_tracker->metrics->invalid_cnt--; break;
        case FD_PING_TRACKER_STATE_VALID:            ping_tracker->metrics->valid_cnt--; break;
        case FD_PING_TRACKER_STATE_VALID_REFRESHING: ping_tracker->metrics->refreshing_cnt--; break;
        default: FD_LOG_ERR(( "Unknown state %d", next->state ));
      }
      next->state = FD_PING_TRACKER_STATE_INVALID;
      ping_tracker->metrics->invalid_cnt++;
    }
    next->next_ping_nanos = now+1L*1000L*1000L*1000L;
    *out_peer_pubkey      = next->identity_pubkey.b;
    *out_peer_address     = &next->address;
    *out_token            = next->ping_token;
    return 1;
  }
}

fd_ping_tracker_metrics_t const *
fd_ping_tracker_metrics( fd_ping_tracker_t const * ping_tracker ) {
  return ping_tracker->metrics;
}
