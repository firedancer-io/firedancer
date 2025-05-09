#include "fd_ping_tracker.h"

#include "../../ballet/sha256/fd_sha256.h"
#include "../../util/log/fd_log.h"

#define FD_PING_TRACKER_STATE_INVALID    (0)
#define FD_PING_TRACKER_STATE_VALID      (1)
#define FD_PING_TRACKER_STATE_REFRESHING (2)

struct pubkey_private {
  uchar b[ 32UL ];
};

typedef struct pubkey_private pubkey_private_t;

struct fd_ping_peer {
  fd_ip4_port_t    address;
  pubkey_private_t identity_pubkey;
  uchar            ping_token[ 32UL ];
  uchar            expected_pong_token[ 32UL ];

  uchar state;

  ulong stake;

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
      ulong invalid_next;
      ulong invalid_prev;
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

#define DLIST_NAME  invalid_list
#define DLIST_ELE_T fd_ping_peer_t
#define DLIST_PREV  invalid_prev
#define DLIST_NEXT  invalid_next
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

  fd_ping_peer_t *    pool;
  lru_list_t *        lru;
  invalid_list_t *    invalid;
  waiting_list_t *    waiting;
  refreshing_list_t * refreshing;
  peer_map_t *        peers;

  ulong magic; /* ==FD_PING_TRACKER_MAGIC */
};

FD_FN_CONST ulong
fd_ping_tracker_align( void ) {
  return FD_PING_TRACKER_ALIGN;
}

FD_FN_CONST ulong
fd_ping_tracker_footprint( void ) {
  ulong l;
  l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, FD_PING_TRACKER_ALIGN,   sizeof(fd_ping_tracker_t)    );
  l = FD_LAYOUT_APPEND( l, pool_align(),            pool_footprint( 65536UL )    );
  l = FD_LAYOUT_APPEND( l, lru_list_align(),        lru_list_footprint()         );
  l = FD_LAYOUT_APPEND( l, invalid_list_align(),    invalid_list_footprint()     );
  l = FD_LAYOUT_APPEND( l, waiting_list_align(),    waiting_list_footprint()     );
  l = FD_LAYOUT_APPEND( l, refreshing_list_align(), refreshing_list_footprint()  );
  l = FD_LAYOUT_APPEND( l, peer_map_align(),        peer_map_footprint( 8192UL ) );
  return FD_LAYOUT_FINI( l, FD_PING_TRACKER_ALIGN );
}

void *
fd_ping_tracker_new( void *     shmem,
                     fd_rng_t * rng ) {
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
  fd_ping_tracker_t * ping_tracker = FD_SCRATCH_ALLOC_APPEND( l, FD_PING_TRACKER_ALIGN,   sizeof(fd_ping_tracker_t)    );
  void * _pool                     = FD_SCRATCH_ALLOC_APPEND( l, pool_align(),            pool_footprint( 65536UL )    );
  void * _lru                      = FD_SCRATCH_ALLOC_APPEND( l, lru_list_align(),        lru_list_footprint()         );
  void * _invalid                  = FD_SCRATCH_ALLOC_APPEND( l, invalid_list_align(),    invalid_list_footprint()     );
  void * _waiting                  = FD_SCRATCH_ALLOC_APPEND( l, waiting_list_align(),    waiting_list_footprint()     );
  void * _refreshing               = FD_SCRATCH_ALLOC_APPEND( l, refreshing_list_align(), refreshing_list_footprint()  );
  void * _peers                    = FD_SCRATCH_ALLOC_APPEND( l, peer_map_align(),        peer_map_footprint( 8192UL ) );

  ping_tracker->rng = rng;
  ping_tracker->pool = pool_join( pool_new( _pool, 65536UL ) );
  FD_TEST( ping_tracker->pool );
  ping_tracker->lru  = lru_list_join( lru_list_new( _lru ) );
  FD_TEST( ping_tracker->lru );
  ping_tracker->invalid = invalid_list_join( invalid_list_new( _invalid ) );
  FD_TEST( ping_tracker->invalid );
  ping_tracker->waiting = waiting_list_join( waiting_list_new( _waiting ) );
  FD_TEST( ping_tracker->waiting );
  ping_tracker->refreshing = refreshing_list_join( refreshing_list_new( _refreshing ) );
  FD_TEST( ping_tracker->refreshing );
  ping_tracker->peers = peer_map_join( peer_map_new( _peers, 8192UL, fd_rng_ulong( rng ) ) );
  FD_TEST( ping_tracker->peers );

  FD_TEST( fd_sha256_join( fd_sha256_new( ping_tracker->sha ) ) );

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

static void
remove_tracking( fd_ping_tracker_t * ping_tracker,
                 fd_ping_peer_t *    peer ) {
  if( FD_LIKELY( peer->state==FD_PING_TRACKER_STATE_INVALID ) )         invalid_list_ele_remove( ping_tracker->invalid, peer, ping_tracker->pool );
  else if( FD_LIKELY( peer->state==FD_PING_TRACKER_STATE_REFRESHING ) ) refreshing_list_ele_remove( ping_tracker->refreshing, peer, ping_tracker->pool );
  else if( FD_LIKELY( peer->state==FD_PING_TRACKER_STATE_VALID ) )      waiting_list_ele_remove( ping_tracker->waiting, peer, ping_tracker->pool );
}

void
fd_ping_tracker_track( fd_ping_tracker_t *   ping_tracker,
                       uchar const *         peer_pubkey,
                       ulong                 peer_stake,
                       fd_ip4_port_t const * peer_address,
                       long                  now ) {
  fd_ping_peer_t * peer = peer_map_ele_query( ping_tracker->peers, fd_type_pun_const( peer_pubkey ), NULL, ping_tracker->pool );

  if( FD_UNLIKELY( !peer ) ) {
    if( FD_LIKELY( peer_stake>=1000000000UL ) ) return;

    if( FD_UNLIKELY( !pool_free( ping_tracker->pool ) ) ) {
      peer = lru_list_ele_pop_head( ping_tracker->lru, ping_tracker->pool );
      remove_tracking( ping_tracker, peer );
      peer_map_ele_remove_fast( ping_tracker->peers, peer, ping_tracker->pool );
    } else {
      peer = pool_ele_acquire( ping_tracker->pool );
    }

    fd_memcpy( peer->identity_pubkey.b, peer_pubkey, 32UL );
    peer->address           = *peer_address;
    peer->valid_until_nanos = 0L;
    peer->next_ping_nanos   = now;
    peer->state             = FD_PING_TRACKER_STATE_INVALID;

    for( ulong i=0UL; i<32UL; i++ ) peer->ping_token[ i ] = fd_rng_uchar( ping_tracker->rng );
    fd_sha256_init( ping_tracker->sha );
    fd_sha256_append( ping_tracker->sha, "SOLANA_PING_PONG", 16UL );
    fd_sha256_append( ping_tracker->sha, peer->ping_token, 32UL );
    fd_sha256_fini( ping_tracker->sha, peer->expected_pong_token );

    invalid_list_ele_push_head( ping_tracker->invalid, peer, ping_tracker->pool );
    peer_map_ele_insert( ping_tracker->peers, peer, ping_tracker->pool );
    lru_list_ele_push_tail( ping_tracker->lru, peer, ping_tracker->pool );
  } else {
    if( FD_LIKELY( peer_stake>=1000000000UL ) ) {
      /* Node went from unstaked (or low staked) to >=1 SOL, no longer
         need to ping it. */
      peer_map_ele_remove_fast( ping_tracker->peers, peer, ping_tracker->pool );
      lru_list_ele_remove( ping_tracker->lru, peer, ping_tracker->pool );
      remove_tracking( ping_tracker, peer );
      pool_ele_release( ping_tracker->pool, peer );
      return;
    }
    
    if( FD_UNLIKELY( peer_address->addr!=peer->address.addr || peer_address->port!=peer->address.port ) ) {
      /* Node changed address, update the address.  Any existing pongs
         are no longer valid. */
      peer->address           = *peer_address;
      peer->valid_until_nanos = 0UL;
      remove_tracking( ping_tracker, peer );
      peer->next_ping_nanos = now;
      peer->state           = FD_PING_TRACKER_STATE_INVALID;
      for( ulong i=0UL; i<32UL; i++ ) peer->ping_token[ i ] = fd_rng_uchar( ping_tracker->rng );
      fd_sha256_init( ping_tracker->sha );
      fd_sha256_append( ping_tracker->sha, "SOLANA_PING_PONG", 16UL );
      fd_sha256_append( ping_tracker->sha, peer->ping_token, 32UL );
      fd_sha256_fini( ping_tracker->sha, peer->expected_pong_token );
      invalid_list_ele_push_head( ping_tracker->invalid, peer, ping_tracker->pool );
    }
  }

  peer->stake         = peer_stake;
  peer->last_rx_nanos = now;
  lru_list_ele_remove( ping_tracker->lru, peer, ping_tracker->pool );
  lru_list_ele_push_tail( ping_tracker->lru, peer, ping_tracker->pool );
}

void
fd_ping_tracker_register( fd_ping_tracker_t *   ping_tracker,
                          uchar const *         peer_pubkey,
                          ulong                 peer_stake,
                          fd_ip4_port_t const * peer_address,
                          uchar const *         pong_token,
                          long                  now ) {
  if( FD_UNLIKELY( peer_stake>=1000000000UL ) ) return;

  fd_ping_peer_t * peer = peer_map_ele_query( ping_tracker->peers, fd_type_pun_const( peer_pubkey ), NULL, ping_tracker->pool );
  if( FD_UNLIKELY( !peer ) ) return;

  if( FD_UNLIKELY( peer_address->addr!=peer->address.addr || peer_address->port!=peer->address.port ) ) return;
  if( FD_UNLIKELY( memcmp( pong_token, peer->expected_pong_token, 32UL ) ) ) return;

  peer->valid_until_nanos = now+20L*60L*1000L*1000L*1000L; /* 20 minutes */
  peer->next_ping_nanos   = now+18L*60L*1000L*1000L*1000L; /* 18 minutes til we start trying to refresh */
  remove_tracking( ping_tracker, peer );
  peer->state = FD_PING_TRACKER_STATE_VALID;
  for( ulong i=0UL; i<32UL; i++ ) peer->ping_token[ i ] = fd_rng_uchar( ping_tracker->rng );
  fd_sha256_init( ping_tracker->sha );
  fd_sha256_append( ping_tracker->sha, "SOLANA_PING_PONG", 16UL );
  fd_sha256_append( ping_tracker->sha, peer->ping_token, 32UL );
  fd_sha256_fini( ping_tracker->sha, peer->expected_pong_token );
  waiting_list_ele_push_tail( ping_tracker->waiting, peer, ping_tracker->pool );
}

int
fd_ping_tracker_active( fd_ping_tracker_t const * ping_tracker,
                        uchar const *             peer_pubkey,
                        ulong                     peer_stake,
                        fd_ip4_port_t const *     peer_address,
                        long                      now ) {
  /* Peer with >=1 SOL of stake is always considered valid.  If it's
     still in the table it will get pruned soon enough. */
  if( FD_LIKELY( peer_stake>=1000000000UL ) ) return 1;

  fd_ping_peer_t * peer = peer_map_ele_query( ping_tracker->peers, fd_type_pun_const( peer_pubkey ), NULL, ping_tracker->pool );
  if( FD_UNLIKELY( !peer ) ) return 0;

  if( FD_UNLIKELY( peer_address->addr!=peer->address.addr || peer_address->port!=peer->address.port ) ) return 0;

  return peer->valid_until_nanos>=now;
}

int
fd_ping_tracker_pop_request( fd_ping_tracker_t *    ping_tracker,
                             long                   now,
                             uchar const **         out_peer_pubkey,
                             fd_ip4_port_t const ** out_peer_address,
                             uchar const **         out_token ) {
  for(;;) {
    fd_ping_peer_t * peer_invalid = NULL;
    if( FD_UNLIKELY( !invalid_list_is_empty( ping_tracker->invalid, ping_tracker->pool ) ) ) peer_invalid = invalid_list_ele_peek_head( ping_tracker->invalid, ping_tracker->pool );
    fd_ping_peer_t * peer_refreshing = NULL;
    if( FD_UNLIKELY( !refreshing_list_is_empty( ping_tracker->refreshing, ping_tracker->pool ) ) ) peer_refreshing = refreshing_list_ele_peek_head( ping_tracker->refreshing, ping_tracker->pool );
    fd_ping_peer_t * peer_waiting = NULL;
    if( FD_UNLIKELY( !waiting_list_is_empty( ping_tracker->waiting, ping_tracker->pool ) ) ) peer_waiting = waiting_list_ele_peek_head( ping_tracker->waiting, ping_tracker->pool );

    fd_ping_peer_t * next;
    if( FD_UNLIKELY( !peer_refreshing && !peer_waiting && !peer_invalid ) ) return 0;
    else if( FD_UNLIKELY( peer_refreshing && !peer_waiting && !peer_invalid ) ) next = peer_refreshing;
    else if( FD_UNLIKELY( !peer_refreshing && peer_waiting && !peer_invalid ) ) next = peer_waiting;
    else if( FD_UNLIKELY( !peer_refreshing && !peer_waiting && peer_invalid ) ) next = peer_invalid;
    else if( FD_LIKELY( peer_invalid->next_ping_nanos<peer_refreshing->next_ping_nanos && peer_invalid->next_ping_nanos<peer_waiting->next_ping_nanos ) ) next = peer_invalid;
    else if( FD_LIKELY( peer_refreshing->next_ping_nanos<peer_waiting->next_ping_nanos && peer_refreshing->next_ping_nanos<peer_invalid->next_ping_nanos ) ) next = peer_refreshing;
    else next = peer_waiting;
  
    if( FD_UNLIKELY( next->last_rx_nanos<now-20L*1000L*1000L*1000L ) ) {
      /* The peer is no longer sending us contact information, no need
         to ping it and instead remove it from the table. */
      peer_map_ele_remove_fast( ping_tracker->peers, next, ping_tracker->pool );
      lru_list_ele_remove( ping_tracker->lru, next, ping_tracker->pool );
      remove_tracking( ping_tracker, next );
      pool_ele_release( ping_tracker->pool, next );
      continue;
    }

    /* The next ping we want to send is still in the future, so do
       nothing for now. */
    if( FD_LIKELY( next->next_ping_nanos>now ) ) return 0;

    if( FD_LIKELY( next==peer_invalid ) )         invalid_list_ele_pop_head( ping_tracker->invalid, ping_tracker->pool );
    else if( FD_LIKELY( next==peer_refreshing ) ) refreshing_list_ele_pop_head( ping_tracker->refreshing, ping_tracker->pool );
    else if( FD_LIKELY( next==peer_waiting ) )    waiting_list_ele_pop_head( ping_tracker->waiting, ping_tracker->pool );
    else                                          FD_LOG_CRIT(( "Invalid state" ));

    /* Push the element to the back of the refreshing list now, so it
       starts getting pinged every 2 seconds. */
    refreshing_list_ele_push_tail( ping_tracker->refreshing, next, ping_tracker->pool );
    next->state           = FD_PING_TRACKER_STATE_REFRESHING;
    next->next_ping_nanos = now+2L*1000L*1000L*1000L;
    *out_peer_pubkey      = next->identity_pubkey.b;
    *out_peer_address     = &next->address;
    *out_token            = next->ping_token;
    return 1;
  }
}
