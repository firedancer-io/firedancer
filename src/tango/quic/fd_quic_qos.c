#include "fd_quic_qos.h"
#include "../../util/rng/fd_rng.h"
#include "tls/fd_quic_tls.h"

int
fd_stake_pubkey_from_cert( fd_stake_pubkey_t * pubkey, X509 * cert ) {
  EVP_PKEY * pubkey_openssl = X509_get_pubkey( cert );
  size_t     len            = FD_TXN_PUBKEY_SZ;
  FD_TEST( pubkey_openssl != NULL );
  EVP_PKEY_get_raw_public_key( pubkey_openssl, pubkey->pubkey, &len );
  EVP_PKEY_free( pubkey_openssl );
  return 0;
}

/* Unprivileged connection LRU algorithm:

   1. The LRU contains a map of conn_id -> conn (ele) and a doubly-linked list
   of conns.
   2. When a new conn comes in, we check if it is already in the LRU by looking
   it up in the map.
   3. If it is already in the LRU, we move it to the back of the list.
   4. If it is not in the LRU, we check if the LRU is full.
   5. If the LRU is full, we evict 10% of the conns in the LRU.
   6. We then pop the next conn off the free list, push it onto the used list,
   and insert it into the map. */
fd_quic_qos_unpriv_conn_lru_t *
fd_quic_qos_unpriv_conn_upsert( fd_quic_qos_unpriv_conn_lru_t * lru, fd_quic_conn_t * conn ) {
  fd_quic_qos_unpriv_conn_map_t * curr_slot =
      fd_quic_qos_unpriv_conn_map_query( lru->map, conn->local_conn_id, NULL );
  if ( FD_LIKELY( curr_slot ) ) { /* more likely to be handling existing conns that new
                                conns */
    /* update existing conn to be the MRU */
    fd_list_push_back( lru->used_list, fd_list_remove( curr_slot->list ) );
  } else { /* new conn */
    /* check if LRU is full */
    if ( FD_UNLIKELY( fd_list_is_full( lru->free_list ) ) ) {
      /* if full, evict 12.5% (n >> 3) of conns */
      int n = (int)( 1 << ( lru->lg_max_sz - 3 ) );
      for ( int i = 0; i < n; i++ ) {
        fd_list_t *      pop_push      = fd_list_pop_front( lru->used_list );
        fd_quic_conn_t * pop_push_conn = pop_push->ele;
        /* add to the free list */
        fd_list_push_back( lru->free_list, pop_push );
        fd_quic_qos_unpriv_conn_map_t * map_slot =
            fd_quic_qos_unpriv_conn_map_query( lru->map, pop_push_conn->local_conn_id, NULL );
        /* if the conn is in the LRU list but not the map this is a programming error */
        if ( FD_UNLIKELY( fd_quic_qos_unpriv_conn_map_key_inval( map_slot->key ) ) ) {
          FD_LOG_ERR( ( "LRU list and map are out of sync. conn_id: %lu is in list but not map.",
                        pop_push_conn->local_conn_id ) );
        }
        /* remove from the lookup cache */
        fd_quic_qos_unpriv_conn_map_remove( lru->map, map_slot );
      }
    }
    fd_list_t * curr = fd_list_pop_front( lru->free_list );
    curr->ele        = conn;
    fd_list_push_back( lru->used_list, curr );
    fd_quic_qos_unpriv_conn_map_insert( lru->map, conn->local_conn_id );
  }
  return lru;
}

ulong
fd_quic_qos_unpriv_conn_lru_align( void ) {
  return FD_QUIC_QOS_UNPRIV_CONN_LRU_ALIGN;
}

ulong
fd_quic_qos_unpriv_conn_lru_footprint( ulong lg_max_sz ) {
  ulong l;
  l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND(
      l, fd_quic_qos_unpriv_conn_lru_align(), sizeof( fd_quic_qos_unpriv_conn_lru_t ) );
  l = FD_LAYOUT_APPEND( l, fd_list_align(), fd_list_footprint( lg_max_sz ) );
  l = FD_LAYOUT_APPEND( l,
                        fd_quic_qos_unpriv_conn_map_align(),
                        fd_quic_qos_unpriv_conn_map_footprint( (int)lg_max_sz ) );
  return FD_QUIC_QOS_UNPRIV_CONN_LRU_ALIGN;
}

void *
fd_quic_qos_unpriv_conn_lru_new( void * mem, ulong lg_max_sz ) {
  if ( lg_max_sz < 3 ) FD_LOG_ERR( ( "too small fd_quic_qos_unpriv_conn_lru" ) );
  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_quic_qos_unpriv_conn_lru_t * lru = FD_SCRATCH_ALLOC_APPEND(
      l, fd_quic_qos_unpriv_conn_lru_align(), sizeof( fd_quic_qos_unpriv_conn_lru_t ) );
  lru->lg_max_sz = lg_max_sz;
  lru->used_list = fd_list_new(
      FD_SCRATCH_ALLOC_APPEND( l, fd_list_align(), fd_list_footprint( lg_max_sz ) ), lg_max_sz );
  lru->free_list = fd_list_new(
      FD_SCRATCH_ALLOC_APPEND( l, fd_list_align(), fd_list_footprint( lg_max_sz ) ), lg_max_sz );
  lru->map = fd_quic_qos_unpriv_conn_map_new(
      FD_SCRATCH_ALLOC_APPEND( l,
                               fd_quic_qos_unpriv_conn_map_align(),
                               fd_quic_qos_unpriv_conn_map_footprint( (int)lg_max_sz ) ),
      (int)lg_max_sz );
  FD_SCRATCH_ALLOC_FINI( l, fd_quic_qos_unpriv_conn_lru_align() );
  return mem;
}

fd_quic_qos_unpriv_conn_lru_t *
fd_quic_qos_unpriv_conn_lru_join( void * mem ) {
  return (fd_quic_qos_unpriv_conn_lru_t *)mem;
}

ulong
fd_quic_qos_align( void ) {
  return FD_QUIC_QOS_ALIGN;
}

ulong
fd_quic_qos_footprint( fd_quic_qos_limits_t * limits ) {
  ulong l;
  l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, fd_quic_qos_align(), sizeof( fd_quic_qos_t ) );
  l = FD_LAYOUT_APPEND( l,
                        fd_quic_qos_priv_conn_align(),
                        fd_quic_qos_priv_conn_footprint( (int)limits->lg_priv_conns ) );
  l = FD_LAYOUT_APPEND( l,
                        fd_quic_qos_priv_conn_align(),
                        fd_quic_qos_priv_conn_footprint( (int)limits->lg_unpriv_conns ) );
  return FD_LAYOUT_FINI( l, fd_quic_qos_align() );
}

void *
fd_quic_qos_new( void * mem, fd_quic_qos_limits_t * limits ) {
  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_quic_qos_t * qos = FD_SCRATCH_ALLOC_APPEND( l, fd_quic_qos_align(), sizeof( fd_quic_qos_t ) );
  qos->limits         = *limits;
  qos->stake          = fd_stake_new(
      FD_SCRATCH_ALLOC_APPEND( l, fd_stake_align(), fd_stake_footprint( limits->lg_unpriv_conns ) ),
      limits->lg_unpriv_conns );
  qos->priv_conn_map = fd_quic_qos_priv_conn_new(
      FD_SCRATCH_ALLOC_APPEND( l,
                               fd_quic_qos_priv_conn_align(),
                               fd_quic_qos_priv_conn_footprint( (int)limits->lg_priv_conns ) ),
      (int)limits->lg_unpriv_conns );
  qos->unpriv_conn_lru = fd_quic_qos_unpriv_conn_lru_new(
      FD_SCRATCH_ALLOC_APPEND( l,
                               fd_quic_qos_unpriv_conn_lru_align(),
                               fd_quic_qos_unpriv_conn_lru_footprint( limits->lg_unpriv_conns ) ),
      limits->lg_unpriv_conns );
  return mem;
}

fd_quic_qos_t *
fd_quic_qos_join( void * mem ) {
  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_quic_qos_t * qos  = FD_SCRATCH_ALLOC_APPEND( l, fd_quic_qos_align(), sizeof( fd_quic_qos_t ) );
  qos->stake           = fd_stake_join( qos->stake );
  qos->priv_conn_map   = fd_quic_qos_priv_conn_join( qos->priv_conn_map );
  qos->unpriv_conn_lru = fd_quic_qos_unpriv_conn_lru_join( qos->unpriv_conn_lru );
  return qos;
}

void
fd_quic_qos_conn_new( fd_quic_qos_t * qos, fd_quic_conn_t * conn ) {
  fd_stake_pubkey_t pubkey;
  fd_stake_pubkey_from_cert( &pubkey, SSL_get_peer_certificate( conn->tls_hs->ssl ) );
  fd_stake_staked_node_t * node =
      fd_stake_staked_node_query( qos->stake->staked_nodes, pubkey, NULL );

  ulong stake = 0;
  if ( FD_UNLIKELY( ( !node ) ) ) { /* most incoming traffic likely unstaked */
    fd_quic_conn_set_context( conn, node );
    stake = node->stake;
  }

  ulong total_stake = fd_ulong_max( qos->stake->total_stake, 1UL ); /* avoid division by zero */
  ulong share       = ( stake * 100 / total_stake * 100 );          /* truncating division */
  fd_quic_qos_limits_t limits      = qos->limits;
  ulong                max_streams = share * ( limits.max_streams - limits.min_streams );
  /* clamp */
  max_streams = fd_ulong_min( fd_ulong_max( max_streams, limits.min_streams ), limits.max_streams );
  fd_quic_conn_set_max_streams( conn, FD_QUIC_TYPE_UNIDIR, max_streams );
  FD_LOG_NOTICE(
      ( "server: new connection with max streams %lu",
        ( conn->max_streams[FD_QUIC_STREAM_TYPE_UNI_CLIENT] - FD_QUIC_STREAM_TYPE_UNI_CLIENT ) /
            4 ) );
}

void
fd_quic_qos_conn_evict( fd_quic_qos_t * qos, fd_quic_conn_t * conn ) {
  fd_stake_pubkey_t pubkey;
  fd_stake_pubkey_from_cert( &pubkey, SSL_get_peer_certificate( conn->tls_hs->ssl ) );
  fd_stake_staked_node_t * node =
      fd_stake_staked_node_query( qos->stake->staked_nodes, pubkey, NULL );

  if ( FD_LIKELY( ( node ) ) ) { /* optimize this eviction code path */
    /* Randomly sample 2 * lg(n) entries in the staked map and evict the
     * smallest. Multiply by 2 because the map is sparse. */
    fd_quic_qos_priv_conn_t * arg_min = NULL;
    ulong                     min     = node->stake;
    int                       lg_n    = fd_quic_qos_priv_conn_lg_slot_cnt( qos->priv_conn_map );
    ulong                     n       = fd_quic_qos_priv_conn_slot_cnt( qos->priv_conn_map );
    for ( int i = 0; i < 2 * lg_n; i++ ) {
      ulong                   slot_idx    = fd_rng_ulong( qos->rng ) % n;
      fd_quic_qos_priv_conn_t random_slot = qos->priv_conn_map[slot_idx];
      /* Likely to find something given the map is full (linear-probing) */
      if ( FD_LIKELY( !fd_quic_qos_priv_conn_key_inval( random_slot.key ) ) ) {
        fd_quic_conn_t * random_conn = random_slot.conn;
        ulong stake = ( (fd_stake_staked_node_t *)fd_quic_conn_get_context( random_conn ) )->stake;
        if ( stake < min ) arg_min = &random_slot;
      }
    }
    /* Unclear how likely this is... but probably won't evict anything */
    if ( FD_UNLIKELY( arg_min ) ) {
      fd_quic_qos_priv_conn_remove( qos->priv_conn_map, arg_min );
      fd_quic_qos_priv_conn_insert( qos->priv_conn_map, conn->local_conn_id )->conn = conn;
      return;
    }
  }
  /* Otherwise upsert it into the LRU cache (which will update and evict as * neccessary) */
  fd_quic_qos_unpriv_conn_upsert( qos->unpriv_conn_lru, conn );
}
