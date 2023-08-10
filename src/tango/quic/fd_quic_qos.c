#include "fd_quic_qos.h"
#include "../../util/rng/fd_rng.h"
#include "../stake/fd_stake.h"
#include "fd_quic.h"
#include "fd_quic_conn.h"
#include "fd_quic_enum.h"
#include "fd_quic_private.h"
#include "tls/fd_quic_tls.h"

ulong
fd_quic_qos_align( void ) {
  return FD_QUIC_QOS_ALIGN;
}

ulong
fd_quic_qos_footprint( fd_quic_qos_limits_t * limits ) {
  ulong l;
  l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, fd_quic_qos_align(), sizeof( fd_quic_qos_t ) );
  l = FD_LAYOUT_APPEND(
      l, fd_quic_qos_pq_align(), fd_quic_qos_pq_footprint( limits->pq_lg_slot_cnt ) );
  l = FD_LAYOUT_APPEND( l, fd_lru_align(), fd_lru_footprint( limits->lru_depth, 0UL ) );
  return FD_LAYOUT_FINI( l, fd_quic_qos_align() );
}

/* fd_quic_qos_new formats an unused memory for use a QoS (Quality of Service) component. Not
 * designed to be shared across multiple joins (pointer addresses are local to the joined process).
 */
void *
fd_quic_qos_new( void * mem, fd_quic_qos_limits_t * limits ) {
  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_quic_qos_t * qos = FD_SCRATCH_ALLOC_APPEND( l, fd_quic_qos_align(), sizeof( fd_quic_qos_t ) );
  qos->limits         = *limits;
  void * pq           = FD_SCRATCH_ALLOC_APPEND(
      l, fd_quic_qos_pq_align(), fd_quic_qos_pq_footprint( limits->pq_lg_slot_cnt ) );
  fd_quic_qos_pq_new( pq, limits->pq_lg_slot_cnt );
  void * lru =
      FD_SCRATCH_ALLOC_APPEND( l, fd_lru_align(), fd_lru_footprint( limits->lru_depth, 0UL ) );
  fd_lru_new( lru, limits->lru_depth, 0UL );
  void * cnt = FD_SCRATCH_ALLOC_APPEND(
      l, fd_quic_qos_cnt_align(), fd_quic_qos_cnt_footprint( limits->cnt_lg_slot_cnt ) );
  fd_quic_qos_cnt_new( cnt, limits->cnt_lg_slot_cnt );
  return mem;
}

fd_quic_qos_t *
fd_quic_qos_join( void * mem ) {
  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_quic_qos_t * qos = FD_SCRATCH_ALLOC_APPEND( l, fd_quic_qos_align(), sizeof( fd_quic_qos_t ) );
  qos->pq             = fd_quic_qos_pq_join( FD_SCRATCH_ALLOC_APPEND(
      l, fd_quic_qos_pq_align(), fd_quic_qos_pq_footprint( qos->limits.pq_lg_slot_cnt ) ) );
  qos->lru            = fd_lru_join( FD_SCRATCH_ALLOC_APPEND(
      l, fd_lru_align(), fd_lru_footprint( qos->limits.lru_depth, 0UL ) ) );
  qos->cnt            = fd_quic_qos_cnt_join( FD_SCRATCH_ALLOC_APPEND(
      l, fd_quic_qos_cnt_align(), fd_quic_qos_cnt_footprint( qos->limits.cnt_lg_slot_cnt ) ) );
  return qos;
}

void
fd_quic_qos_conn_new( fd_quic_qos_t *     qos,
                      fd_stake_t *        stake,
                      fd_rng_t *          rng,
                      fd_quic_conn_t *    conn,
                      fd_stake_pubkey_t * pubkey ) {
  /* check the incoming connection's origin key (pubkey / ipv4) is not exceeding max */
  fd_quic_qos_cnt_key_t check_cnt_keys[2] = { 0 };
  if ( FD_UNLIKELY( pubkey ) ) check_cnt_keys[0].pubkey = *pubkey;
  check_cnt_keys[1].ip4_addr = conn->peer[conn->cur_peer_idx].net.ip_addr;
  for ( ulong i = 0; i < fd_quic_qos_cnt_slot_cnt( qos->cnt ); i++ ) {
    if ( !fd_quic_qos_cnt_key_inval( qos->cnt[i].key ) ) {
      FD_LOG_NOTICE( ( "%u: %lu", qos->cnt[i].key.ip4_addr, qos->cnt[i].count ) );
    }
  }
  for ( ulong i = 0; i < 2; i++ ) {
    fd_quic_qos_cnt_t * query = fd_quic_qos_cnt_query( qos->cnt, check_cnt_keys[i], NULL );
    FD_LOG_NOTICE( ( "query is null? %d", query == NULL ) );
    if ( FD_UNLIKELY( query && query->count >= qos->limits.cnt_max_conns ) ) {
      fd_quic_conn_close( conn, FD_QUIC_CONN_REASON_CONNECTION_REFUSED );
      return;
    }
  }

  ulong            begin       = ULONG_MAX;
  ulong            end         = 0;
  fd_quic_conn_t * evict       = NULL;
  ulong            max_streams = 0;

  do {
    begin = fd_mvcc_begin_read( &stake->mvcc );

    /* get connection stake (pubkey is stored in a conn) */
    ulong conn_stake = 0;
    if ( FD_LIKELY( pubkey ) ) { /* optimize for authenticated conns */
      fd_stake_node_t * node = fd_stake_node_query( fd_stake_nodes_laddr( stake ), *pubkey, NULL );
      if ( FD_LIKELY( ( node ) ) ) { /* optimize for staked traffic */
        conn_stake = node->stake;
      }
    }

    /* determine conn eviction and update conn counts for a given origin key (pubkey / ipv4 addr) */
    fd_quic_conn_t * evict = conn;
    if ( conn_stake > 0 ) evict = fd_quic_qos_pq_conn_upsert( qos, stake, rng, conn, pubkey );
    if ( FD_LIKELY( evict == conn ) ) { /* unlikely to evict from pq */
      fd_list_t * lru_evict = fd_lru_upsert( qos->lru, (ulong)conn ); /* NULL if no evict */

      if ( FD_LIKELY( lru_evict ) ) {
        /* save the evicted conn to return */
        evict = (fd_quic_conn_t *)lru_evict->tag;

        /* decrement the evicted key */
        fd_quic_qos_cnt_key_t cnt_key = { 0 };
        cnt_key.ip4_addr              = conn->peer[conn->cur_peer_idx].net.ip_addr;
        fd_quic_qos_cnt_t * query     = fd_quic_qos_cnt_query( qos->cnt, cnt_key, NULL );
        if ( FD_UNLIKELY( !query ) ) FD_LOG_ERR( ( "fd_quic_qos: key in lru missing from cnt!" ) );
        if ( FD_UNLIKELY( !--query->count ) ) fd_quic_qos_cnt_remove( qos->cnt, query );
      }

      /* increment the inserted key */
      fd_quic_qos_cnt_key_t cnt_key = { 0 };
      cnt_key.ip4_addr              = conn->peer[conn->cur_peer_idx].net.ip_addr;
      fd_quic_qos_cnt_t * query     = fd_quic_qos_cnt_query( qos->cnt, cnt_key, NULL );
      if ( FD_LIKELY( !query ) ) fd_quic_qos_cnt_insert( qos->cnt, cnt_key )->count = 1;
      else query->count++;
    }

    /* determine flow control (max streams) based on stake */
    ulong total_stake = fd_ulong_max( stake->total_stake, 1UL );  /* avoid division by zero */
    ulong share       = ( conn_stake * 100 / total_stake * 100 ); /* truncating division */
    max_streams       = ( share * qos->limits.total_streams ) / 100;
    max_streams       = fd_ulong_min( max_streams, qos->limits.max_streams );

    end = fd_mvcc_end_read( &stake->mvcc );
  } while ( end % 2 != 0 || end != begin );

  if ( FD_LIKELY( evict ) ) {
    /* The logic here is that we will first gracefully close a connection.
       fd_quic_service will later attempt to service the pending close.

       If there are still no connections available when a new connection arrives,
       it will attempt to service any pending closes again. If there are still
       no available connections, it will refuse the connection.

       See also "Early check" in the initial pkt handler. */
    fd_quic_conn_close( evict, FD_QUIC_CONN_REASON_INTERNAL_ERROR );
    conn->quic->metrics.conn_aborted_cnt++;
  }

  max_streams = fd_ulong_max( max_streams, qos->limits.min_streams );
  FD_DEBUG( FD_LOG_DEBUG( ( "server: new connection with alloted max streams %lu",
                            conn->max_streams[FD_QUIC_STREAM_TYPE_UNI_CLIENT] ) ) );
  fd_quic_conn_set_max_streams( conn, FD_QUIC_TYPE_UNIDIR, max_streams );
}

fd_quic_conn_t *
fd_quic_qos_pq_conn_upsert( fd_quic_qos_t *     qos,
                            fd_stake_t *        stake,
                            fd_rng_t *          rng,
                            fd_quic_conn_t *    conn,
                            fd_stake_pubkey_t * pubkey ) {
  ulong                 key_cnt = fd_quic_qos_pq_key_cnt( qos->pq );
  ulong                 key_max = fd_quic_qos_pq_key_max( qos->pq );
  fd_quic_conn_t *      evict   = NULL;
  fd_quic_qos_cnt_key_t cnt_key = { 0 };

  /* only evict if the pq map is >= half full */
  if ( FD_LIKELY( key_cnt >= key_max / 2 ) ) {
    /* randomly sample lg(n) entries in the staked map and evict the conn with the smallest stake */
    fd_stake_node_t * node = fd_stake_node_query( fd_stake_nodes_laddr( stake ), *pubkey, NULL );
    ulong             conn_stake = 0UL;
    if ( node ) conn_stake = node->stake;
    fd_quic_qos_pq_t * arg_min = NULL;
    ulong              min     = conn_stake;
    int                lg_n    = fd_quic_qos_pq_lg_slot_cnt( qos->pq );
    ulong              n       = fd_quic_qos_pq_slot_cnt( qos->pq );
    for ( int i = 0; i < lg_n; i++ ) {
      ulong              slot_idx    = fd_rng_ulong( rng ) % n;
      fd_quic_qos_pq_t * random_slot = &qos->pq[slot_idx];
      /* optimize for key exists when random sampling a key to evict */
      if ( FD_LIKELY( !fd_quic_qos_pq_key_inval( random_slot->key ) ) ) {
        fd_stake_node_t * random_node =
            fd_stake_node_query( fd_stake_nodes_laddr( stake ), random_slot->pubkey, NULL );
        if ( random_node && random_node->stake < min ) arg_min = random_slot;
      }
    }
    if ( FD_UNLIKELY( arg_min ) ) { /* unlikely to meet stake threshold to evict */
      /* save the evicted conn to return */
      evict = arg_min->conn;

      /* remove the evicted key */
      fd_quic_qos_pq_remove( qos->pq, arg_min );
      fd_quic_qos_pq_insert( qos->pq, conn->local_conn_id );

      /* decrement the evicted key */
      memset( &cnt_key, 0, sizeof( fd_quic_qos_cnt_key_t ) );
      cnt_key.pubkey            = arg_min->pubkey;
      fd_quic_qos_cnt_t * query = fd_quic_qos_cnt_query( qos->cnt, cnt_key, NULL );
      if ( FD_UNLIKELY( !query ) ) FD_LOG_ERR( ( "fd_quic_qos: key in pq missing from cnt!" ) );
      if ( FD_UNLIKELY( !--query->count ) ) fd_quic_qos_cnt_remove( qos->cnt, query );
    }
  }

  /* if there is space (regardless of whether we evicted), insert the conn  */
  if ( FD_LIKELY( key_cnt < key_max / 2 ) ) {
    fd_quic_qos_pq_t * insert = fd_quic_qos_pq_insert( qos->pq, conn->local_conn_id );
    /* if insert is NULL (key already in map), this indicates a programming error. even though
       connections are pooled, the previous usage of the connection should have been freed (and
       removed from the map) already. */

    if ( FD_UNLIKELY( insert == NULL ) )
      FD_LOG_ERR( ( "fd_quic_qos: detected reuse of conn without free!" ) );
    insert->conn   = conn;
    insert->pubkey = *pubkey;

    /* increment the inserted key */
    memset( &cnt_key, 0, sizeof( fd_quic_qos_cnt_key_t ) );
    cnt_key.pubkey            = *pubkey;
    fd_quic_qos_cnt_t * query = fd_quic_qos_cnt_query( qos->cnt, cnt_key, NULL );
    if ( FD_LIKELY( !query ) ) fd_quic_qos_cnt_insert( qos->cnt, cnt_key )->count = 1;
    else query->count++;
  }
  return evict;
}
