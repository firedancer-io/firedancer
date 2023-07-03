#include "../../util/rng/fd_rng.h"
#include "tls/fd_quic_tls.h"
#include "fd_quic_qos.h"

int
fd_stake_pubkey_from_cert( fd_stake_pubkey_t * pubkey, X509 * cert ) {
  EVP_PKEY * pubkey_openssl = X509_get_pubkey( cert );
  size_t     len            = FD_TXN_PUBKEY_SZ;
  FD_TEST( pubkey_openssl != NULL );
  EVP_PKEY_get_raw_public_key( pubkey_openssl, pubkey->pubkey, &len );
  EVP_PKEY_free( pubkey_openssl );
  return 0;
}

fd_quic_qos_unpriv_conn_ele_t *
fd_quic_qos_unpriv_conn_ele_insert( fd_quic_qos_unpriv_conn_ele_t * prev,
                                    fd_quic_qos_unpriv_conn_ele_t * ele ) {
  ele->next        = prev->next;
  ele->prev        = prev;
  prev->next->prev = ele;
  prev->next       = ele;
  return ele;
}

fd_quic_qos_unpriv_conn_ele_t *
fd_quic_qos_unpriv_conn_ele_remove( fd_quic_qos_unpriv_conn_ele_t * ele ) {
  if ( FD_UNLIKELY( ele->next == ele ) ) return NULL; /* this is the sentinel */
  ele->prev->next = ele->next;
  ele->next->prev = ele->prev;
  ele->prev       = NULL;
  ele->next       = NULL;
  ele->conn       = NULL;
  return ele;
}

ulong
fd_quic_qos_unpriv_conn_list_align( void ) {
  return FD_QUIC_QOS_UNPRIV_CONN_LIST_ALIGN;
}

ulong
fd_quic_qos_unpriv_conn_list_footprint( ulong max ) {
  return sizeof( fd_quic_qos_unpriv_conn_list_t ) + sizeof( fd_quic_qos_unpriv_conn_ele_t ) * max;
}

ulong
fd_quic_qos_unpriv_conn_list_new( void * mem ) {
  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_quic_qos_unpriv_conn_list_t * list = FD_SCRATCH_ALLOC_APPEND(
      l, fd_quic_qos_unpriv_conn_list_align(), sizeof( fd_quic_qos_unpriv_conn_list_t ) );
  FD_SCRATCH_ALLOC_FINI( l, fd_quic_qos_unpriv_conn_list_align() );
  fd_quic_qos_unpriv_conn_ele_t sentinel = {
      .conn = NULL, .next = list->sentinel, .prev = list->sentinel };
  *list->sentinel = sentinel;
  return 0;
}

fd_quic_qos_unpriv_conn_ele_t *
fd_quic_qos_unpriv_conn_list_push_back( fd_quic_qos_unpriv_conn_list_t * list,
                                        fd_quic_qos_unpriv_conn_ele_t *  curr ) {
  fd_quic_qos_unpriv_conn_ele_t * tail = list->sentinel->prev;
  return fd_quic_qos_unpriv_conn_ele_insert( tail, curr );
}

fd_quic_qos_unpriv_conn_ele_t *
fd_quic_qos_unpriv_conn_list_pop_front( fd_quic_qos_unpriv_conn_list_t * list ) {
  if ( FD_UNLIKELY( list->sentinel->next == list->sentinel ) ) { /* list is empty*/
    return NULL;
  }
  return fd_quic_qos_unpriv_conn_ele_remove( list->sentinel->next );
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
  fd_quic_qos_unpriv_conn_map_t * curr =
      fd_quic_qos_unpriv_conn_map_query( lru->map, conn->local_conn_id, NULL );
  if ( FD_LIKELY( curr ) ) { /* more likely to be handling existing conns that new
                                conns */
    /* update existing conn to be the MRU */
    fd_quic_qos_unpriv_conn_list_push_back( lru->used_list,
                                            fd_quic_qos_unpriv_conn_ele_remove( curr->ele ) );
  } else { /* new conn */
    /* check if LRU is full */
    if ( FD_UNLIKELY( lru->free_list->sentinel->next == lru->free_list->sentinel ) ) {
      fd_quic_qos_unpriv_conn_ele_t * curr = lru->used_list->sentinel->prev;
      /* if full, evict 10% of conns */
      int n = (int)( lru->max / 10 );
      for ( int i = 0; i < n; i++ ) {
        fd_quic_qos_unpriv_conn_ele_t * pop_push =
            fd_quic_qos_unpriv_conn_list_pop_front( lru->used_list );
        /* add to the free list */
        fd_quic_qos_unpriv_conn_list_push_back( lru->free_list, pop_push );
        fd_quic_qos_unpriv_conn_map_t * map_slot =
            fd_quic_qos_unpriv_conn_map_query( lru->map, pop_push->conn->local_conn_id, NULL );
        /* if the ele is in the LRU list but not the map this is a programming error */
        if ( FD_UNLIKELY( fd_quic_qos_unpriv_conn_map_key_inval( map_slot->key ) ) ) {
          FD_LOG_ERR(
              ( "LRU list and map are out of sync. conn_id: %lu", curr->conn->local_conn_id ) );
        }
        /* remove from the lookup cache */
        fd_quic_qos_unpriv_conn_map_remove( lru->map, map_slot );
      }
    }
    fd_quic_qos_unpriv_conn_ele_t * curr = fd_quic_qos_unpriv_conn_list_pop_front( lru->free_list );
    curr->conn                           = conn;
    fd_quic_qos_unpriv_conn_list_push_back( lru->used_list, curr );
    fd_quic_qos_unpriv_conn_map_insert( lru->map, conn->local_conn_id );
  }
  return lru;
}

ulong
fd_quic_qos_unpriv_conn_lru_align( void ) {
  return FD_QUIC_QOS_UNPRIV_CONN_LRU_ALIGN;
}

ulong
fd_quic_qos_unpriv_conn_lru_footprint( ulong max ) {
  ulong l;
  l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND(
      l, fd_quic_qos_unpriv_conn_lru_align(), sizeof( fd_quic_qos_unpriv_conn_lru_t ) );
  l = FD_LAYOUT_APPEND(
      l, fd_quic_qos_unpriv_conn_list_align(), fd_quic_qos_unpriv_conn_list_footprint( max ) );
  l = FD_LAYOUT_APPEND(
      l, fd_quic_qos_unpriv_conn_list_align(), fd_quic_qos_unpriv_conn_list_footprint( max ) );

  return FD_QUIC_QOS_UNPRIV_CONN_LRU_ALIGN;
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
                        fd_quic_qos_priv_conn_footprint( (int)limits->priv_conns ) );
  l = FD_LAYOUT_APPEND( l,
                        fd_quic_qos_priv_conn_align(),
                        fd_quic_qos_priv_conn_footprint( (int)limits->unpriv_conns ) );
  return FD_LAYOUT_FINI( l, fd_quic_qos_align() );
}

void *
fd_quic_qos_new( void * mem ) {
  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_quic_qos_t * qos = FD_SCRATCH_ALLOC_APPEND( l, fd_quic_qos_align(), sizeof( fd_quic_qos_t ) );
  (void)qos;
  return mem;
}

fd_quic_qos_t *
fd_quic_qos_join( void * mem ) {
  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_quic_qos_t * qos  = FD_SCRATCH_ALLOC_APPEND( l, fd_quic_qos_align(), sizeof( fd_quic_qos_t ) );
  // qos->staked_node_map = fd_quic_qos_staked_node_join( FD_SCRATCH_ALLOC_APPEND(
  //     l, fd_quic_qos_staked_node_align(), fd_quic_qos_staked_node_footprint( 2 ) ) );
  (void)qos;
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

  ulong total_stake           = fd_ulong_max( qos->stake->total_stake, 1UL ); /* avoid division by zero */
  ulong share                 = ( stake * 100 / total_stake * 100 );   /* truncating division */
  fd_quic_qos_limits_t limits = qos->limits;
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
        ulong            stake =
            ( (fd_stake_staked_node_t *)fd_quic_conn_get_context( random_conn ) )->stake;
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
