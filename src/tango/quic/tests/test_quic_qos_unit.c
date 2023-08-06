#include "../../../util/fd_util.h"
#include "../../../util/sanitize/fd_asan.h"
#include "../../stake/fd_stake.h"
#include "../../tcache/fd_tcache.h"
#include "../fd_quic_qos.h"
#include "../tls/fd_quic_tls.h"
#include "fd_quic_test_helpers.h"

#define PQ_LG_SLOT_CNT    6UL
#define PQ_SLOT_CNT       1UL << PQ_LG_SLOT_CNT
#define LRU_DEPTH         1UL << PQ_LG_SLOT_CNT
#define STAKE_LG_SLOT_CNT PQ_LG_SLOT_CNT + 2UL
#define PUBKEY_CNT        1UL << ( PQ_LG_SLOT_CNT + 1UL )

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  if ( FD_UNLIKELY( argc > 1 ) ) FD_LOG_ERR( ( "unrecognized argument: %s", argv[1] ) );

  fd_wksp_t * wksp = fd_wksp_new_anonymous(
      FD_SHMEM_HUGE_PAGE_SZ, 1, fd_shmem_cpu_idx( fd_shmem_numa_idx( 0 ) ), "wksp", 0UL );
  FD_TEST( wksp );

  fd_quic_limits_t const quic_limits = {
      .conn_cnt         = 2,
      .conn_id_cnt      = 4,
      .conn_id_sparsity = 4.0,
      .handshake_cnt    = 10,
      .stream_cnt       = {0, 0, 2, 0},
      .inflight_pkt_cnt = 100,
      .tx_buf_sz        = 1 << 16
  };
  ulong quic_footprint = fd_quic_footprint( &quic_limits );
  FD_TEST( quic_footprint );
  fd_quic_t * quic = fd_quic_new_anonymous( wksp, &quic_limits, FD_QUIC_ROLE_SERVER );
  FD_TEST( quic );
  FD_LOG_NOTICE( ( "quic %p, footprint: %lu", (void *)quic, quic_footprint ) );

  ulong   stake_footprint = fd_stake_footprint( STAKE_LG_SLOT_CNT );
  uchar * stake_mem = (uchar *)fd_wksp_alloc_laddr( wksp, fd_stake_align(), stake_footprint, 1UL );
  FD_TEST( stake_mem );
  fd_stake_t *      stake        = fd_stake_join( fd_stake_new( stake_mem, STAKE_LG_SLOT_CNT ) );
  fd_stake_node_t * staked_nodes = fd_stake_nodes_laddr( stake );
  FD_TEST( stake );
  FD_TEST( staked_nodes );
  FD_LOG_NOTICE( ( "stake: %p, footprint: %lu", (void *)stake, stake_footprint ) );
  FD_LOG_NOTICE( ( "  ->staked_nodes: %p", (void *)staked_nodes ) );

  fd_quic_qos_limits_t limits = {
      .min_streams    = FD_QUIC_QOS_DEFAULT_MIN_STREAMS,
      .max_streams    = FD_QUIC_QOS_DEFAULT_MAX_STREAMS,
      .total_streams  = FD_QUIC_QOS_DEFAULT_TOTAL_STREAMS,
      .pq_lg_slot_cnt = PQ_LG_SLOT_CNT,
      .lru_depth      = LRU_DEPTH,
  };
  ulong   qos_footprint = fd_quic_qos_footprint( &limits );
  uchar * qos_mem = (uchar *)fd_wksp_alloc_laddr( wksp, fd_quic_qos_align(), qos_footprint, 1UL );
  FD_TEST( qos_mem );
  fd_quic_qos_t * qos = fd_quic_qos_join( fd_quic_qos_new( qos_mem, &limits ) );
  FD_TEST( qos );
  FD_TEST( qos->pq );
  FD_TEST( qos->lru );
  FD_LOG_NOTICE( ( "qos: %p, footprint %lu", (void *)qos_mem, qos_footprint ) );
  FD_LOG_NOTICE( ( "  ->pq:  %p", (void *)qos->pq ) );
  FD_LOG_NOTICE( ( "  ->lru: %p", (void *)qos->lru ) );

  /* initialize stakes*/
  ulong stakes[PUBKEY_CNT] = { [PUBKEY_CNT >> 2] = 1UL << 15, 1UL << 14, 1UL << 13, 1UL << 13 };
  fd_stake_pubkey_t pubkeys[PUBKEY_CNT];
  for ( ulong i = 0; i < PUBKEY_CNT; i++ ) {
    fd_stake_pubkey_t pubkey = { .pubkey = { (uchar)( i + 1 ) } };
    pubkeys[i]               = pubkey;
  }
  for ( ulong i = 0; i < PUBKEY_CNT; i++ ) {
    fd_stake_node_t * staked_node = fd_stake_node_insert( staked_nodes, pubkeys[i] );
    FD_TEST( staked_node );
    staked_node->key   = pubkeys[i];
    staked_node->stake = stakes[i];
    stake->total_stake += stakes[i];
  }
  FD_TEST( stake->total_stake == 1UL << 16 );

  for ( ulong i = 0; i < PUBKEY_CNT; i++ ) {
    fd_stake_node_t * staked_node = fd_stake_node_query( staked_nodes, pubkeys[i], NULL );
    FD_TEST( staked_node );
    FD_TEST( !memcmp( staked_node->key.pubkey, pubkeys[i].pubkey, FD_TXN_PUBKEY_SZ ) );
    FD_TEST( staked_node->stake == stakes[i] );
  }

  /* initialize mock conns */
  fd_quic_conn_t conns[PUBKEY_CNT];
  for ( ulong i = 0; i < PUBKEY_CNT; i++ ) {
    memset( &conns[i], 0, sizeof( fd_quic_conn_t ) );
    conns[i].context       = &pubkeys[i];
    conns[i].local_conn_id = i + 1;
    conns[i].server        = 1;
    conns[i].quic          = quic;
  }

  fd_rng_t   _rng[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  for ( ulong i = 0; i < PUBKEY_CNT; i++ ) {
    FD_TEST( &conns[i] );
    fd_quic_qos_conn_new( qos, stake, rng, &conns[i] );
  }

  FD_LOG_NOTICE( ( "pass" ) );
  fd_halt();
  return 0;
}
