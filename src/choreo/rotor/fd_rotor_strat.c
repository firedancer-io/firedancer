#include "fd_rotor_strat.h"

FD_FN_CONST ulong
fd_rotor_strat_align( void ) {
  return 128UL;
}

FD_FN_CONST ulong
fd_rotor_strat_footprint( void ) {
  ulong chain_cnt = fd_rotor_strat_peer_map_chain_cnt_est( FD_ROTOR_STRAT_PEER_MAX );
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, fd_rotor_strat_align(),         sizeof(fd_rotor_strat_t)                              );
  l = FD_LAYOUT_APPEND( l, alignof(fd_rotor_strat_peer_t), sizeof(fd_rotor_strat_peer_t)*FD_ROTOR_STRAT_PEER_MAX );
  l = FD_LAYOUT_APPEND( l, alignof(fd_rotor_strat_peer_t), sizeof(fd_rotor_strat_peer_t)*FD_ROTOR_STRAT_PEER_MAX );
  l = FD_LAYOUT_APPEND( l, fd_rotor_strat_peer_map_align(), fd_rotor_strat_peer_map_footprint( chain_cnt )         );
  l = FD_LAYOUT_APPEND( l, fd_rotor_strat_peer_map_align(), fd_rotor_strat_peer_map_footprint( chain_cnt )         );
  l = FD_LAYOUT_APPEND( l, alignof(uint),                  sizeof(uint)*FD_ROTOR_STRAT_PEER_MAX                   );
  for( ulong b=0UL; b<FD_ROTOR_STRAT_BUCKET_CNT; b++ ) l = FD_LAYOUT_APPEND( l, fd_rotor_strat_set_align(), fd_rotor_strat_set_footprint() );
  return FD_LAYOUT_FINI( l, fd_rotor_strat_align() );
}

void *
fd_rotor_strat_new( void * shmem,
                    ulong  seed ) {
  ulong chain_cnt = fd_rotor_strat_peer_map_chain_cnt_est( FD_ROTOR_STRAT_PEER_MAX );

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_rotor_strat_t * strat     = FD_SCRATCH_ALLOC_APPEND( l, fd_rotor_strat_align(),          sizeof(fd_rotor_strat_t)                              );
  void *             cur_peers = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_rotor_strat_peer_t),  sizeof(fd_rotor_strat_peer_t)*FD_ROTOR_STRAT_PEER_MAX );
  void *             old_peers = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_rotor_strat_peer_t),  sizeof(fd_rotor_strat_peer_t)*FD_ROTOR_STRAT_PEER_MAX );
  void *             cur_map   = FD_SCRATCH_ALLOC_APPEND( l, fd_rotor_strat_peer_map_align(), fd_rotor_strat_peer_map_footprint( chain_cnt )        );
  void *             old_map   = FD_SCRATCH_ALLOC_APPEND( l, fd_rotor_strat_peer_map_align(), fd_rotor_strat_peer_map_footprint( chain_cnt )        );
  uint *             free      = FD_SCRATCH_ALLOC_APPEND( l, alignof(uint),                   sizeof(uint)*FD_ROTOR_STRAT_PEER_MAX                  );
  for( ulong b=0UL; b<FD_ROTOR_STRAT_BUCKET_CNT; b++ ) {
    strat->buckets[ b ] = fd_rotor_strat_set_join( fd_rotor_strat_set_new( FD_SCRATCH_ALLOC_APPEND( l, fd_rotor_strat_set_align(), fd_rotor_strat_set_footprint() ) ) );
    strat->cursor [ b ] = fd_ulong_hash( seed^b ) % FD_ROTOR_STRAT_PEER_MAX; /* random start, so nodes with the same stake order do not herd */
  }
  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, fd_rotor_strat_align() )==(ulong)shmem + fd_rotor_strat_footprint() );

  strat->cur.peers  = (fd_rotor_strat_peer_t *)cur_peers;
  strat->old.peers  = (fd_rotor_strat_peer_t *)old_peers;
  strat->cur.map    = fd_rotor_strat_peer_map_join( fd_rotor_strat_peer_map_new( cur_map, chain_cnt, seed ) );
  strat->old.map    = fd_rotor_strat_peer_map_join( fd_rotor_strat_peer_map_new( old_map, chain_cnt, seed ) );
  strat->staked_cnt = 0UL;
  strat->free       = free;
  strat->free_cnt   = FD_ROTOR_STRAT_PEER_MAX;
  for( ulong i=0UL; i<FD_ROTOR_STRAT_PEER_MAX; i++ ) free[ i ] = (uint)( FD_ROTOR_STRAT_PEER_MAX-1UL-i ); /* lowest slot on top */
  strat->pick_cnt   = 0UL;
  strat->seed       = seed;
  strat->epoch_cnt  = 0UL;
  strat->turbine_srtt   = 0L;
  strat->turbine_rttvar = 0L;
  return shmem;
}

fd_rotor_strat_t *
fd_rotor_strat_join( void * shstrat ) {
  return (fd_rotor_strat_t *)shstrat;
}

static ulong
bucket( fd_rotor_strat_peer_t const * peer ) {
  long rtt = fd_long_max( peer->srtt-peer->rttvar, 1L ); /* the lower confidence bound, so one bad sample does not demote */
  if( FD_UNLIKELY( !peer->srtt        ) ) return FD_ROTOR_STRAT_BUCKET_UNMEASURED;
  if( FD_LIKELY  ( rtt< 25L*1000000L  ) ) return FD_ROTOR_STRAT_BUCKET_25MS;
  if( FD_LIKELY  ( rtt< 50L*1000000L  ) ) return FD_ROTOR_STRAT_BUCKET_50MS;
  if( FD_LIKELY  ( rtt<100L*1000000L  ) ) return FD_ROTOR_STRAT_BUCKET_100MS;
  if( FD_LIKELY  ( rtt<200L*1000000L  ) ) return FD_ROTOR_STRAT_BUCKET_200MS;
  return FD_ROTOR_STRAT_BUCKET_SLOW;
}

/* place puts slot idx in the bucket of its rtt if it can take another
   request, and in no bucket otherwise. */

static void
place( fd_rotor_strat_t * strat,
       ulong              idx ) {
  fd_rotor_strat_peer_t * peer = &strat->cur.peers[ idx ];
  fd_rotor_strat_set_remove( strat->buckets[ peer->bucket ], idx );
  peer->bucket = bucket( peer );
  if( FD_LIKELY( peer->ip4 && peer->inflight<FD_ROTOR_STRAT_INFLIGHT_MAX ) ) fd_rotor_strat_set_insert( strat->buckets[ peer->bucket ], idx );
}

void
fd_rotor_strat_epoch_advanced( fd_rotor_strat_t *        strat,
                               fd_stake_weight_t const * ids,
                               ulong                     id_cnt ) {
  fd_rotor_strat_order_t old = strat->cur;
  strat->cur = strat->old;
  strat->old = old;

  fd_rotor_strat_peer_map_reset( strat->cur.map );
  strat->epoch_cnt++;
  for( ulong b=0UL; b<FD_ROTOR_STRAT_BUCKET_CNT; b++ ) {
    fd_rotor_strat_set_null( strat->buckets[ b ] );
    strat->cursor[ b ] = fd_ulong_hash( strat->seed^(strat->epoch_cnt<<8)^b ) % FD_ROTOR_STRAT_PEER_MAX;
  }

  /* Staked identities take [0,staked_cnt) by stake rank, keeping what
     was known about them. */

  ulong cnt = fd_ulong_min( id_cnt, FD_ROTOR_STRAT_PEER_MAX );
  for( ulong rank=0UL; rank<cnt; rank++ ) {
    fd_rotor_strat_peer_t *       peer = &strat->cur.peers[ rank ];
    fd_rotor_strat_peer_t const * prev = fd_rotor_strat_peer_map_ele_query_const( strat->old.map, &ids[ rank ].key, NULL, strat->old.peers );
    if( FD_LIKELY( prev ) ) *peer = *prev;
    else {
      fd_memset( peer, 0, sizeof(fd_rotor_strat_peer_t) );
      peer->id_key = ids[ rank ].key;
      peer->bucket = FD_ROTOR_STRAT_BUCKET_UNMEASURED;
    }
    fd_rotor_strat_peer_map_ele_insert( strat->cur.map, peer, strat->cur.peers );
    place( strat, rank );
  }
  strat->staked_cnt = cnt;

  /* Unstaked peers with an address take the slots after. */

  strat->free_cnt = 0UL;
  for( ulong i=FD_ROTOR_STRAT_PEER_MAX; i>cnt; i-- ) strat->free[ strat->free_cnt++ ] = (uint)( i-1UL );
  for( fd_rotor_strat_peer_map_iter_t iter = fd_rotor_strat_peer_map_iter_init( strat->old.map, strat->old.peers );
                                             !fd_rotor_strat_peer_map_iter_done( iter, strat->old.map, strat->old.peers );
                                       iter = fd_rotor_strat_peer_map_iter_next( iter, strat->old.map, strat->old.peers ) ) {
    fd_rotor_strat_peer_t const * prev = fd_rotor_strat_peer_map_iter_ele_const( iter, strat->old.map, strat->old.peers );
    if( FD_UNLIKELY( !prev->ip4 || !strat->free_cnt ) ) continue;
    if( FD_LIKELY( fd_rotor_strat_peer_map_ele_query_const( strat->cur.map, &prev->id_key, NULL, strat->cur.peers ) ) ) continue; /* staked now */
    ulong idx = strat->free[ --strat->free_cnt ];
    strat->cur.peers[ idx ] = *prev;
    fd_rotor_strat_peer_map_ele_insert( strat->cur.map, &strat->cur.peers[ idx ], strat->cur.peers );
    place( strat, idx );
  }
}

void
fd_rotor_strat_contact_info_updated( fd_rotor_strat_t *  strat,
                                     fd_pubkey_t const * id_key,
                                     uint                ip4,
                                     ushort              port ) {
  fd_rotor_strat_peer_t * peer = fd_rotor_strat_peer_map_ele_query( strat->cur.map, id_key, NULL, strat->cur.peers );
  if( FD_UNLIKELY( !peer && !strat->free_cnt ) ) return;
  if( FD_UNLIKELY( !peer ) ) {
    peer = &strat->cur.peers[ strat->free[ --strat->free_cnt ] ];
    fd_memset( peer, 0, sizeof(fd_rotor_strat_peer_t) );
    peer->id_key = *id_key;
    peer->bucket = FD_ROTOR_STRAT_BUCKET_UNMEASURED;
    fd_rotor_strat_peer_map_ele_insert( strat->cur.map, peer, strat->cur.peers );
  }
  if( FD_LIKELY( peer->ip4==ip4 && peer->port==port ) ) return;

  peer->ip4     = ip4;
  peer->port    = port;
  peer->srtt    = 0L;
  peer->rttvar  = 0L;
  peer->ping_ts = 0L;
  place( strat, (ulong)( peer-strat->cur.peers ) );
}

void
fd_rotor_strat_contact_info_removed( fd_rotor_strat_t *  strat,
                                     fd_pubkey_t const * id_key ) {
  fd_rotor_strat_peer_t * peer = fd_rotor_strat_peer_map_ele_query( strat->cur.map, id_key, NULL, strat->cur.peers );
  if( FD_UNLIKELY( !peer ) ) return;

  ulong idx = (ulong)( peer-strat->cur.peers );
  peer->ip4 = 0U;
  place( strat, idx );
  if( FD_LIKELY( idx<strat->staked_cnt ) ) return; /* a staked peer keeps its slot */

  fd_rotor_strat_peer_map_ele_remove( strat->cur.map, id_key, NULL, strat->cur.peers );
  strat->free[ strat->free_cnt++ ] = (uint)idx;
}

fd_rotor_strat_peer_t *
fd_rotor_strat_pick( fd_rotor_strat_t * strat,
                     long               now,
                     int                staked ) {
  ulong end     = fd_ulong_if( staked, strat->staked_cnt, FD_ROTOR_STRAT_PEER_MAX );
  int   explore = !( ++strat->pick_cnt % FD_ROTOR_STRAT_EXPLORE );
  for( ulong i=0UL; i<FD_ROTOR_STRAT_BUCKET_CNT; i++ ) {
    ulong                        b     = fd_ulong_if( explore, (i+FD_ROTOR_STRAT_BUCKET_UNMEASURED)%FD_ROTOR_STRAT_BUCKET_CNT, i ); /* unmeasured first when exploring */
    fd_rotor_strat_set_t const * set   = strat->buckets[ b ];
    ulong                        start = strat->cursor[ b ];

    /* The next two peers after the cursor, walking to end and then
       from the start back to the cursor. */

    ulong cand[ 2 ];
    ulong cand_cnt = 0UL;
    int   wrap     = 0;
    ulong idx      = fd_rotor_strat_set_const_iter_next( set, start );
    while( cand_cnt<2UL ) {
      if( FD_UNLIKELY( fd_rotor_strat_set_const_iter_done( idx ) || idx>=end ) ) {
        if( wrap ) break;
        wrap = 1;
        idx  = fd_rotor_strat_set_const_iter_init( set );
        continue;
      }
      if( FD_UNLIKELY( wrap && idx>start ) ) break;
      if( FD_LIKELY( strat->cur.peers[ idx ].ban_ts<=now ) ) cand[ cand_cnt++ ] = idx;
      idx = fd_rotor_strat_set_const_iter_next( set, idx );
    }
    if( FD_UNLIKELY( !cand_cnt ) ) continue;

    fd_rotor_strat_peer_t const * c0  = &strat->cur.peers[ cand[ 0 ] ];
    fd_rotor_strat_peer_t const * c1  = &strat->cur.peers[ cand[ cand_cnt-1UL ] ];
    ulong                         won = fd_ulong_if( (ulong)(c1->srtt+1L)*(c1->inflight+1UL)<(ulong)(c0->srtt+1L)*(c0->inflight+1UL), cand[ cand_cnt-1UL ], cand[ 0 ] );
    strat->cursor[ b ] = cand[ cand_cnt-1UL ];
    strat->cur.peers[ won ].inflight++;
    place( strat, won );
    return &strat->cur.peers[ won ];
  }
  return NULL;
}

void
fd_rotor_strat_request_done( fd_rotor_strat_t *  strat,
                             fd_pubkey_t const * id_key,
                             long                rtt ) {
  fd_rotor_strat_peer_t * peer = fd_rotor_strat_peer_map_ele_query( strat->cur.map, id_key, NULL, strat->cur.peers );
  if( FD_UNLIKELY( !peer ) ) return; /* forgotten while the request was in flight */

  peer->inflight -= !!peer->inflight;
  peer->rttvar    = fd_long_if( !!peer->srtt, (3L*peer->rttvar+(long)fd_long_abs( peer->srtt-rtt ))/4L, rtt/2L ); /* RFC 6298 */
  peer->srtt      = fd_long_if( !!peer->srtt, (7L*peer->srtt+rtt)/8L,                                   rtt     );
  place( strat, (ulong)( peer-strat->cur.peers ) );
}

void
fd_rotor_strat_request_failed( fd_rotor_strat_t *  strat,
                               fd_pubkey_t const * id_key,
                               long                ban_ts ) {
  fd_rotor_strat_peer_t * peer = fd_rotor_strat_peer_map_ele_query( strat->cur.map, id_key, NULL, strat->cur.peers );
  if( FD_UNLIKELY( !peer ) ) return; /* forgotten while the request was in flight */

  peer->inflight -= !!peer->inflight;
  peer->ban_ts    = ban_ts;
  place( strat, (ulong)( peer-strat->cur.peers ) );
}

void
fd_rotor_strat_turbine_done( fd_rotor_strat_t *  strat,
                             fd_pubkey_t const * id_key,
                             long                t ) {
  strat->turbine_rttvar = fd_long_if( !!strat->turbine_srtt, (3L*strat->turbine_rttvar+(long)fd_long_abs( strat->turbine_srtt-t ))/4L, t/2L );
  strat->turbine_srtt   = fd_long_if( !!strat->turbine_srtt, (7L*strat->turbine_srtt+t)/8L,                                             t    );

  fd_rotor_strat_peer_t * peer = id_key ? fd_rotor_strat_peer_map_ele_query( strat->cur.map, id_key, NULL, strat->cur.peers ) : NULL;
  if( FD_UNLIKELY( !peer ) ) return;
  peer->turbine_rttvar = fd_long_if( !!peer->turbine_srtt, (3L*peer->turbine_rttvar+(long)fd_long_abs( peer->turbine_srtt-t ))/4L, t/2L );
  peer->turbine_srtt   = fd_long_if( !!peer->turbine_srtt, (7L*peer->turbine_srtt+t)/8L,                                            t    );
  peer->turbine_cnt++;
}

long
fd_rotor_strat_eager_ns( fd_rotor_strat_t *  strat,
                         fd_pubkey_t const * id_key ) {
  fd_rotor_strat_peer_t const * peer   = id_key ? fd_rotor_strat_peer_map_ele_query_const( strat->cur.map, id_key, NULL, strat->cur.peers ) : NULL;
  int                           own    = peer && peer->turbine_cnt>=FD_ROTOR_STRAT_TURBINE_MIN;
  long                          srtt   = own ? peer->turbine_srtt   : strat->turbine_srtt;
  long                          rttvar = own ? peer->turbine_rttvar : strat->turbine_rttvar;
  if( FD_UNLIKELY( !srtt ) ) return FD_ROTOR_STRAT_EAGER_MAX_NS;
  return fd_long_min( fd_long_max( srtt+4L*rttvar, FD_ROTOR_STRAT_EAGER_MIN_NS ), FD_ROTOR_STRAT_EAGER_MAX_NS );
}

fd_rotor_strat_peer_t *
fd_rotor_strat_query( fd_rotor_strat_t *  strat,
                      fd_pubkey_t const * id_key ) {
  return fd_rotor_strat_peer_map_ele_query( strat->cur.map, id_key, NULL, strat->cur.peers );
}
