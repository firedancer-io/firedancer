#include "fd_repair_strat.h"

FD_FN_CONST ulong
fd_repair_strat_align( void ) {
  return 128UL;
}

FD_FN_CONST ulong
fd_repair_strat_footprint( void ) {
  ulong chain_cnt = fd_repair_strat_peer_map_chain_cnt_est( FD_REPAIR_STRAT_PEER_MAX );
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, fd_repair_strat_align(),         sizeof(fd_repair_strat_t)                               );
  l = FD_LAYOUT_APPEND( l, alignof(fd_repair_strat_peer_t), sizeof(fd_repair_strat_peer_t)*FD_REPAIR_STRAT_PEER_MAX );
  l = FD_LAYOUT_APPEND( l, alignof(fd_repair_strat_peer_t), sizeof(fd_repair_strat_peer_t)*FD_REPAIR_STRAT_PEER_MAX );
  l = FD_LAYOUT_APPEND( l, fd_repair_strat_peer_map_align(), fd_repair_strat_peer_map_footprint( chain_cnt )         );
  l = FD_LAYOUT_APPEND( l, fd_repair_strat_peer_map_align(), fd_repair_strat_peer_map_footprint( chain_cnt )         );
  l = FD_LAYOUT_APPEND( l, alignof(uint),                   sizeof(uint)*FD_REPAIR_STRAT_PEER_MAX                   );
  for( ulong b=0UL; b<FD_REPAIR_STRAT_BUCKET_CNT; b++ ) l = FD_LAYOUT_APPEND( l, fd_repair_strat_set_align(), fd_repair_strat_set_footprint() );
  return FD_LAYOUT_FINI( l, fd_repair_strat_align() );
}

void *
fd_repair_strat_new( void * shmem,
                     ulong  seed ) {
  ulong chain_cnt =  fd_repair_strat_peer_map_chain_cnt_est( FD_REPAIR_STRAT_PEER_MAX );

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_repair_strat_t * strat     = FD_SCRATCH_ALLOC_APPEND( l, fd_repair_strat_align(),          sizeof(fd_repair_strat_t)                               );
  void *              cur_peers = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_repair_strat_peer_t),  sizeof(fd_repair_strat_peer_t)*FD_REPAIR_STRAT_PEER_MAX );
  void *              old_peers = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_repair_strat_peer_t),  sizeof(fd_repair_strat_peer_t)*FD_REPAIR_STRAT_PEER_MAX );
  void *              cur_map   = FD_SCRATCH_ALLOC_APPEND( l, fd_repair_strat_peer_map_align(), fd_repair_strat_peer_map_footprint( chain_cnt )         );
  void *              old_map   = FD_SCRATCH_ALLOC_APPEND( l, fd_repair_strat_peer_map_align(), fd_repair_strat_peer_map_footprint( chain_cnt )         );
  uint *              free      = FD_SCRATCH_ALLOC_APPEND( l, alignof(uint),                    sizeof(uint)*FD_REPAIR_STRAT_PEER_MAX                   );
  for( ulong b=0UL; b<FD_REPAIR_STRAT_BUCKET_CNT; b++ ) {
    strat->buckets[ b ] = fd_repair_strat_set_join( fd_repair_strat_set_new( FD_SCRATCH_ALLOC_APPEND( l, fd_repair_strat_set_align(), fd_repair_strat_set_footprint() ) ) );
    strat->cursor [ b ] = fd_ulong_hash( seed^b ) % FD_REPAIR_STRAT_PEER_MAX; /* random start, so nodes with the same stake order do not herd */
  }
  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, fd_repair_strat_align() )==(ulong)shmem + fd_repair_strat_footprint() );

  strat->cur.peers  = (fd_repair_strat_peer_t *)cur_peers;
  strat->old.peers  = (fd_repair_strat_peer_t *)old_peers;
  strat->cur.map    = fd_repair_strat_peer_map_join( fd_repair_strat_peer_map_new( cur_map, chain_cnt, seed ) );
  strat->old.map    = fd_repair_strat_peer_map_join( fd_repair_strat_peer_map_new( old_map, chain_cnt, seed ) );
  strat->staked_cnt = 0UL;
  strat->free       = free;
  strat->free_cnt   = FD_REPAIR_STRAT_PEER_MAX;
  for( ulong i=0UL; i<FD_REPAIR_STRAT_PEER_MAX; i++ ) free[ i ] = (uint)( FD_REPAIR_STRAT_PEER_MAX-1UL-i ); /* lowest slot on top */
  strat->pick_cnt   = 0UL;
  strat->seed       = seed;
  strat->epoch_cnt  = 0UL;
  strat->turbine_srtt   = 0L;
  strat->turbine_rttvar = 0L;
  return shmem;
}

fd_repair_strat_t *
fd_repair_strat_join( void * shstrat ) {
  return (fd_repair_strat_t *)shstrat;
}

static ulong
bucket( fd_repair_strat_peer_t const * peer ) {
  long rtt = peer->srtt_ns+(peer->rttvar_ns>>2); /* a quarter weight on jitter: a jittery peer ranks slower, as its hedge does, but a first sample's rttvar of rtt/2 does not demote a new peer */
  if( FD_UNLIKELY( !peer->srtt_ns        ) ) return FD_REPAIR_STRAT_BUCKET_UNMEASURED;
  if( FD_LIKELY  ( rtt< 25L*1000000L  ) ) return FD_REPAIR_STRAT_BUCKET_25MS;
  if( FD_LIKELY  ( rtt< 50L*1000000L  ) ) return FD_REPAIR_STRAT_BUCKET_50MS;
  if( FD_LIKELY  ( rtt<100L*1000000L  ) ) return FD_REPAIR_STRAT_BUCKET_100MS;
  if( FD_LIKELY  ( rtt<200L*1000000L  ) ) return FD_REPAIR_STRAT_BUCKET_200MS;
  return FD_REPAIR_STRAT_BUCKET_SLOW;
}

/* place puts slot idx in the bucket of its rtt if it can take another
   request, and in no bucket otherwise. */

static void
place( fd_repair_strat_t * self,
       ulong               idx ) {
  fd_repair_strat_peer_t * peer = &self->cur.peers[ idx ];
  fd_repair_strat_set_remove( self->buckets[ peer->bucket ], idx );
  peer->bucket = bucket( peer );
  if( FD_LIKELY( peer->ip4 && peer->out_cnt<FD_REPAIR_STRAT_INFLIGHT_MAX ) ) fd_repair_strat_set_insert( self->buckets[ peer->bucket ], idx );
}

void
fd_repair_strat_epoch_advanced( fd_repair_strat_t *       self,
                                fd_stake_weight_t const * ids,
                                ulong                     id_cnt ) {
  fd_repair_strat_order_t old = self->cur;
  self->cur = self->old;
  self->old = old;

  fd_repair_strat_peer_map_reset( self->cur.map );
  self->epoch_cnt++;
  for( ulong b=0UL; b<FD_REPAIR_STRAT_BUCKET_CNT; b++ ) {
    fd_repair_strat_set_null( self->buckets[ b ] );
    self->cursor[ b ] = fd_ulong_hash( self->seed^(self->epoch_cnt<<8)^b ) % FD_REPAIR_STRAT_PEER_MAX;
  }

  /* Staked identities take [0,staked_cnt) by stake rank, keeping what
     was known about them. */

  ulong cnt = fd_ulong_min( id_cnt, FD_REPAIR_STRAT_PEER_MAX );
  for( ulong rank=0UL; rank<cnt; rank++ ) {
    fd_repair_strat_peer_t *       peer = &self->cur.peers[ rank ];
    fd_repair_strat_peer_t const * prev = fd_repair_strat_peer_map_ele_query_const( self->old.map, &ids[ rank ].key, NULL, self->old.peers );
    if( FD_LIKELY( prev ) ) *peer  = *prev;
    else {
      fd_memset( peer, 0, sizeof(fd_repair_strat_peer_t) );
      peer->id_key = ids[ rank ].key;
      peer->bucket = FD_REPAIR_STRAT_BUCKET_UNMEASURED;
    }
    fd_repair_strat_peer_map_ele_insert( self->cur.map, peer, self->cur.peers );
    place( self, rank );
  }
  self->staked_cnt = cnt;

  /* Unstaked peers with an address take the slots after. */

  self->free_cnt = 0UL;
  for( ulong i=FD_REPAIR_STRAT_PEER_MAX; i>cnt; i-- ) self->free[ self->free_cnt++ ] = (uint)( i-1UL );
  for( fd_repair_strat_peer_map_iter_t iter = fd_repair_strat_peer_map_iter_init( self->old.map, self->old.peers );
                                              !fd_repair_strat_peer_map_iter_done( iter, self->old.map, self->old.peers );
                                        iter = fd_repair_strat_peer_map_iter_next( iter, self->old.map, self->old.peers ) ) {
    fd_repair_strat_peer_t const * prev = fd_repair_strat_peer_map_iter_ele_const( iter, self->old.map, self->old.peers );
    if( FD_UNLIKELY( !prev->ip4 || !self->free_cnt ) ) continue;
    if( FD_LIKELY( fd_repair_strat_peer_map_ele_query_const( self->cur.map, &prev->id_key, NULL, self->cur.peers ) ) ) continue; /* staked now */
    ulong idx = self->free[ --self->free_cnt ];
    self->cur.peers[ idx ] = *prev;
    fd_repair_strat_peer_map_ele_insert( self->cur.map, &self->cur.peers[ idx ], self->cur.peers );
    place( self, idx );
  }
}

void
fd_repair_strat_contact_info_updated( fd_repair_strat_t * self,
                                      fd_pubkey_t const * id_key,
                                      uint                ip4,
                                      ushort              port ) {
  fd_repair_strat_peer_t * peer = fd_repair_strat_peer_map_ele_query( self->cur.map, id_key, NULL, self->cur.peers );
  if( FD_UNLIKELY( !peer && !self->free_cnt ) ) return;
  if( FD_UNLIKELY( !peer ) ) {
    peer = &self->cur.peers[ self->free[ --self->free_cnt ] ];
    fd_memset( peer, 0, sizeof(fd_repair_strat_peer_t) );
    peer->id_key = *id_key;
    peer->bucket = FD_REPAIR_STRAT_BUCKET_UNMEASURED;
    fd_repair_strat_peer_map_ele_insert( self->cur.map, peer, self->cur.peers );
  }
  if( FD_LIKELY( peer->ip4==ip4 && peer->port==port ) ) return;

  peer->ip4       = ip4;
  peer->port      = port;
  peer->srtt_ns   = 0L;
  peer->rttvar_ns = 0L;
  peer->ping_ts   = 0L;
  place( self, (ulong)( peer-self->cur.peers ) );
}

void
fd_repair_strat_contact_info_removed( fd_repair_strat_t * self,
                                      fd_pubkey_t const * id_key ) {
  fd_repair_strat_peer_t * peer = fd_repair_strat_peer_map_ele_query( self->cur.map, id_key, NULL, self->cur.peers );
  if( FD_UNLIKELY( !peer ) ) return;

  ulong idx = (ulong)( peer-self->cur.peers );
  peer->ip4 = 0U;
  place( self, idx );
  if( FD_LIKELY( idx<self->staked_cnt ) ) return; /* a staked peer keeps its slot */

  fd_repair_strat_peer_map_ele_remove( self->cur.map, id_key, NULL, self->cur.peers );
  self->free[ self->free_cnt++ ] = (uint)idx;
}

fd_repair_strat_peer_t *
fd_repair_strat_pick( fd_repair_strat_t * self,
                      long                now,
                      int                 staked,
                      ulong               avoid ) {
  ulong end      = fd_ulong_if( staked,   self->staked_cnt, FD_REPAIR_STRAT_PEER_MAX );
  int   explore  = !( ++self->pick_cnt   % FD_REPAIR_STRAT_EXPLORE );
  int   fallback = 0; /* avoid was available */
  for( ulong i=0UL; i<FD_REPAIR_STRAT_BUCKET_CNT; i++ ) {
    ulong                         b     = fd_ulong_if( explore, (i+FD_REPAIR_STRAT_BUCKET_UNMEASURED)%FD_REPAIR_STRAT_BUCKET_CNT, i ); /* unmeasured first when exploring */
    fd_repair_strat_set_t const * set   = self->buckets[ b ];
    ulong                         start = self->cursor[ b ];

    /* The next two peers after the cursor, walking to end and then
       from the start back to the cursor. */

    ulong cand[ 2 ];
    ulong cand_cnt = 0UL;
    ulong first    = ULONG_MAX; /* first available peer, avoid included */
    int   wrap     = 0;
    ulong idx      = fd_repair_strat_set_const_iter_next( set, start );
    while( cand_cnt<2UL ) {
      if( FD_UNLIKELY( fd_repair_strat_set_const_iter_done( idx ) || idx>=end ) ) {
        if( wrap ) break;
        wrap = 1;
        idx  = fd_repair_strat_set_const_iter_init( set );
        continue;
      }
      if( FD_UNLIKELY( wrap && idx>start ) ) break;
      if( FD_LIKELY( self->cur.peers[ idx ].ban_ts<=now ) ) {
        first = fd_ulong_if( first==ULONG_MAX, idx, first );
        if( FD_LIKELY( idx!=avoid ) ) cand[ cand_cnt++ ] = idx;
        else                          fallback = 1;
      }
      idx = fd_repair_strat_set_const_iter_next( set, idx );
    }
    if( FD_UNLIKELY( !cand_cnt ) ) continue;

    fd_repair_strat_peer_t const * c0  = &self->cur.peers[ cand[ 0 ] ];
    fd_repair_strat_peer_t const * c1  = &self->cur.peers[ cand[ cand_cnt-1UL ] ];
    ulong                          won = fd_ulong_if( (ulong)(c1->srtt_ns+1L)*(c1->out_cnt+1UL)<(ulong)(c0->srtt_ns+1L)*(c0->out_cnt+1UL), cand[ cand_cnt-1UL ], cand[ 0 ] );
    self->cursor[ b ] = first; /* one peer on, avoided or not, so pairs shift rather than repeat */
    self->cur.peers[ won ].out_cnt++;
    place( self, won );
    return &self->cur.peers[ won ];
  }
  if( FD_UNLIKELY( fallback ) ) {
    self->cur.peers[ avoid ].out_cnt++;
    place( self, avoid );
    return &self->cur.peers[ avoid ];
  }
  return NULL;
}

fd_repair_strat_peer_t *
fd_repair_strat_pick_staked( fd_repair_strat_t * self,
                             long                now,
                             ulong               avoid,
                             ulong               r ) {
  ulong n = fd_ulong_min( self->staked_cnt, FD_REPAIR_STRAT_ESCAPE_TOP );
  ulong m = 0UL;
  for( ulong idx=0UL; idx<n; idx++ ) {
    fd_repair_strat_peer_t const * peer = &self->cur.peers[ idx ];
    m += (ulong)( idx!=avoid && peer->ip4 && peer->out_cnt<FD_REPAIR_STRAT_INFLIGHT_MAX && peer->ban_ts<=now );
  }
  if( FD_UNLIKELY( !m ) ) return NULL;

  ulong k = fd_ulong_min( (r&UINT_MAX)%m, (r>>32)%m ); /* among the available peers, in stake order */
  for( ulong idx=0UL; idx<n; idx++ ) {
    fd_repair_strat_peer_t * peer = &self->cur.peers[ idx ];
    if( idx==avoid || !peer->ip4 || peer->out_cnt>=FD_REPAIR_STRAT_INFLIGHT_MAX || peer->ban_ts>now ) continue;
    if( k-- ) continue;
    peer->out_cnt++;
    place( self, idx );
    return peer;
  }
  return NULL;
}

void
fd_repair_strat_request_done( fd_repair_strat_t * self,
                              fd_pubkey_t const * id_key,
                              long                rtt,
                              int                 byid ) {
  fd_repair_strat_peer_t * peer = fd_repair_strat_peer_map_ele_query( self->cur.map, id_key, NULL, self->cur.peers );
  if( FD_UNLIKELY( !peer ) ) return; /* forgotten while the request was in flight */

  peer->out_cnt    -= !!peer->out_cnt;
  peer->expired_cnt = 0U;
  peer->byid_expired_cnt = fd_uint_if( byid, 0U, peer->byid_expired_cnt ); /* a positional reply does not vouch for by-id */
  peer->rttvar_ns = fd_long_if( !!peer->srtt_ns, (3L*peer->rttvar_ns+(long)fd_long_abs( peer->srtt_ns-rtt ))/4L, rtt/2L ); /* RFC 6298 */
  peer->srtt_ns   = fd_long_if( !!peer->srtt_ns, (7L*peer->srtt_ns+rtt)/8L,                                   rtt     );
  place( self, (ulong)( peer-self->cur.peers ) );
}

void
fd_repair_strat_request_failed( fd_repair_strat_t * self,
                                fd_pubkey_t const * id_key,
                                long                ban_ts ) {
  fd_repair_strat_peer_t * peer = fd_repair_strat_peer_map_ele_query( self->cur.map, id_key, NULL, self->cur.peers );
  if( FD_UNLIKELY( !peer ) ) return; /* forgotten while the request was in flight */

  peer->out_cnt  -= !!peer->out_cnt;
  peer->ban_ts    = fd_long_max( peer->ban_ts, ban_ts ); /* an expiry does not shorten a verify failure's ban */
  place( self, (ulong)( peer-self->cur.peers ) );
}

int
fd_repair_strat_request_expired( fd_repair_strat_t * self,
                                 fd_pubkey_t const * id_key,
                                 long                ban_ts,
                                 int                 byid ) {
  fd_repair_strat_peer_t * peer = fd_repair_strat_peer_map_ele_query( self->cur.map, id_key, NULL, self->cur.peers );
  if( FD_UNLIKELY( !peer ) ) return 0; /* forgotten while the request was in flight */

  peer->out_cnt -= !!peer->out_cnt;
  peer->byid_expired_cnt += (uint)!!byid;
  int byid_ban = peer->byid_expired_cnt>=FD_REPAIR_STRAT_BYID_MAX;
  int ban      = fd_int_if( byid_ban, 1, -(++peer->expired_cnt>=FD_REPAIR_STRAT_EXPIRED_MAX) );
  if( FD_UNLIKELY( ban ) ) {
    peer->ban_ts           = fd_long_max( peer->ban_ts, ban_ts );
    peer->expired_cnt      = 0U;
    peer->byid_expired_cnt = 0U;
  }
  place( self, (ulong)( peer-self->cur.peers ) );
  return ban;
}

void
fd_repair_strat_turbine_done( fd_repair_strat_t * self,
                              fd_pubkey_t const * id_key,
                              long                t ) {
  self->turbine_rttvar = fd_long_if( !!self->turbine_srtt, (3L*self->turbine_rttvar+(long)fd_long_abs( self->turbine_srtt-t ))/4L, t/2L );
  self->turbine_srtt   = fd_long_if( !!self->turbine_srtt, (7L*self->turbine_srtt+t)/8L,                                            t    );

  fd_repair_strat_peer_t * peer = id_key ? fd_repair_strat_peer_map_ele_query( self->cur.map, id_key, NULL, self->cur.peers ) : NULL;
  if( FD_UNLIKELY( !peer ) ) return;
  peer->turbine_rttvar = fd_long_if( !!peer->turbine_srtt, (3L*peer->turbine_rttvar+(long)fd_long_abs( peer->turbine_srtt-t ))/4L, t/2L );
  peer->turbine_srtt   = fd_long_if( !!peer->turbine_srtt, (7L*peer->turbine_srtt+t)/8L,                                            t    );
  peer->turbine_cnt++;
}

long
fd_repair_strat_eager_ns( fd_repair_strat_t * self,
                          fd_pubkey_t const * id_key ) {
  fd_repair_strat_peer_t const * peer   = id_key ? fd_repair_strat_peer_map_ele_query_const( self->cur.map, id_key, NULL, self->cur.peers ) : NULL;
  int                            own    = peer && peer->turbine_cnt>=FD_REPAIR_STRAT_TURBINE_MIN;
  long                           srtt   = own ? peer->turbine_srtt   : self->turbine_srtt;
  long                           rttvar = own ? peer->turbine_rttvar : self->turbine_rttvar;
  if( FD_UNLIKELY( !srtt ) ) return FD_REPAIR_STRAT_EAGER_MAX_NS;
  return fd_long_min( fd_long_max( srtt+4L*rttvar, FD_REPAIR_STRAT_EAGER_MIN_NS ), FD_REPAIR_STRAT_EAGER_MAX_NS );
}

fd_repair_strat_peer_t *
fd_repair_strat_query( fd_repair_strat_t * self,
                       fd_pubkey_t const * id_key ) {
  return fd_repair_strat_peer_map_ele_query( self->cur.map, id_key, NULL, self->cur.peers );
}

ulong
fd_repair_strat_slot_remap( fd_repair_strat_t const * self,
                            ulong                     idx ) {
  if( FD_UNLIKELY( idx>=FD_REPAIR_STRAT_PEER_MAX ) )  return ULONG_MAX;
  fd_repair_strat_peer_t const * peer = fd_repair_strat_peer_map_ele_query_const( self->cur.map, &self->old.peers[ idx ].id_key, NULL, self->cur.peers );
  return peer ? (ulong)( peer-self->cur.peers ) : ULONG_MAX;
}
