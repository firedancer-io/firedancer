#include "fd_quic_qos.h"
#include "../../util/rng/fd_rng.h"
#include "../stake/fd_stake.h"
#include "fd_quic_conn.h"
#include "fd_quic_enum.h"
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
  return qos;
}

void
fd_quic_qos_conn_new( fd_quic_qos_t *  qos,
                      fd_stake_t *     stake,
                      fd_rng_t *       rng,
                      fd_quic_conn_t * conn ) {
  fd_stake_node_t *   staked_nodes = fd_stake_nodes_laddr( stake );
  fd_stake_pubkey_t * pubkey       = (fd_stake_pubkey_t *)conn->context;
  fd_stake_node_t *   node         = fd_stake_node_query( staked_nodes, *pubkey, NULL );

  ulong conn_stake = 0;
  if ( FD_UNLIKELY( ( node ) ) ) { /* most incoming traffic likely unstaked */
    fd_quic_conn_set_context( conn, node );
    conn_stake = node->stake;
  }

  fd_quic_conn_t * evict = fd_quic_qos_pq_conn_upsert( qos, stake, rng, conn );
  if ( FD_LIKELY( evict == conn ) ) { /* likely to be below stake eviction threshold */
    fd_list_t * lru_evict = fd_lru_upsert( qos->lru, (ulong)conn ); /* NULL if no evict */
    if ( FD_LIKELY( lru_evict ) ) evict = (fd_quic_conn_t *)lru_evict->tag;
  }
  if ( FD_LIKELY( evict ) ) {
    conn->state      = FD_QUIC_CONN_STATE_DEAD;
    fd_quic_t * quic = conn->quic;
    quic->metrics.conn_aborted_cnt++;
  }

  ulong total_stake = fd_ulong_max( stake->total_stake, 1UL );  /* avoid division by zero */
  ulong share       = ( conn_stake * 100 / total_stake * 100 ); /* truncating division */
  fd_quic_qos_limits_t limits      = qos->limits;
  ulong                max_streams = ( share * limits.total_streams ) / 100;
  /* clamp */
  max_streams = fd_ulong_min( fd_ulong_max( max_streams, limits.min_streams ), limits.max_streams );
  fd_quic_conn_set_max_streams( conn, FD_QUIC_TYPE_UNIDIR, max_streams );
  FD_LOG_NOTICE( ( "server: new connection with alloted max streams %lu",
                   conn->max_streams[FD_QUIC_STREAM_TYPE_UNI_CLIENT] ) );
}

fd_quic_conn_t *
fd_quic_qos_pq_conn_upsert( fd_quic_qos_t *  qos,
                            fd_stake_t *     stake,
                            fd_rng_t *       rng,
                            fd_quic_conn_t * conn ) {
  ulong key_cnt = fd_quic_qos_pq_key_cnt( qos->pq );
  ulong key_max = fd_quic_qos_pq_key_max( qos->pq );

  if ( key_cnt <= key_max / 2 ) {
    fd_quic_qos_pq_insert( qos->pq, (ulong)conn );
    return NULL; /* pq map still has room */
  }

  /* attempt to evict from the prioritized pq: randomly sample lg(n) entries in the staked map and
   * evict the smallest */
  fd_stake_node_t * node = fd_stake_node_query(
      fd_stake_nodes_laddr( stake ), *(fd_stake_pubkey_t *)conn->context, NULL );
  ulong conn_stake = 0UL;
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
      fd_quic_conn_t *    random_conn = (fd_quic_conn_t *)random_slot->key;
      fd_stake_pubkey_t * pubkey = (fd_stake_pubkey_t *)fd_quic_conn_get_context( random_conn );
      fd_stake_node_t *   random_node =
          fd_stake_node_query( fd_stake_nodes_laddr( stake ), *pubkey, NULL );
      if ( random_node && random_node->stake < min ) arg_min = random_slot;
    }
  }
  if ( FD_UNLIKELY( arg_min ) ) { /* unlikely to meet stake threshold to evict */
    fd_quic_conn_t * conn = (fd_quic_conn_t *)arg_min->key;
    fd_quic_qos_pq_remove( qos->pq, arg_min );
    fd_quic_qos_pq_insert( qos->pq, (ulong)conn );
    return (fd_quic_conn_t *)arg_min->key;
  }
  /* didn't meet threshold to evict, so return the input conn itself */
  return conn;
}
