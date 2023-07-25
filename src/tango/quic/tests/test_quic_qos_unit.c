#include "../../../util/fd_util.h"
#include "../../stake/fd_stake.h"
#include "../fd_quic_qos.h"

#define LG_NODE_CNT 2
#define NODE_CNT    ( 1UL << LG_NODE_CNT )

fd_stake_pubkey_t pubkeys[NODE_CNT] = {
    { .pubkey = { 44, 174, 25,  39, 43, 255, 200, 81, 55, 73, 10,  113, 174, 91, 223, 80,
                  50, 51,  102, 25, 63, 110, 36,  28, 51, 11, 174, 179, 110, 8,  25,  152 } },

    { .pubkey = { 250, 56, 248, 84,  190, 46,  154, 76,  15, 72, 181, 205, 32, 96, 128, 213,
                  158, 33, 81,  193, 63,  154, 93,  254, 15, 81, 32,  175, 54, 60, 179, 224 } },

    { .pubkey = { 225, 102, 95, 246, 174, 91, 1,  240, 118, 174, 119, 113, 150, 146, 149, 29,
                  253, 10,  69, 168, 188, 51, 31, 11,  67,  18,  201, 181, 189, 178, 159, 178 } },
    { .pubkey = { 160, 58,  145, 16, 41,  55,  193, 27,  132, 112, 36, 109, 233, 125, 206,
                  165, 200, 130, 76, 147, 173, 151, 180, 73,  248, 4,  165, 8,   163, 42 } } };

void
test_fd_quic_qos_conn_lru( void ) {
  fd_wksp_t * wksp = fd_wksp_new_anonymous(
      FD_SHMEM_GIGANTIC_PAGE_SZ, 1, fd_shmem_cpu_idx( fd_shmem_numa_idx( 0 ) ), "wksp", 0UL );
  FD_TEST( wksp );

  fd_quic_qos_limits_t qos_limits = {
      .min_streams     = 1,
      .max_streams     = 1,
      .total_streams   = 1,
      .lg_priv_conns   = LG_NODE_CNT,
      .lg_unpriv_conns = LG_NODE_CNT,
  };
  void * mem =
      fd_wksp_alloc_laddr( wksp, fd_quic_qos_align(), fd_quic_qos_footprint( &qos_limits ), 42UL );
  fd_quic_qos_t *          qos          = fd_quic_qos_join( fd_quic_qos_new( mem, &qos_limits ) );

  /* initialize stakes */
  fd_stake_staked_node_t * staked_nodes = qos->stake->staked_nodes;
  for ( ulong i = 0; i < NODE_CNT; i++ ) {
    fd_stake_staked_node_t * staked_node = fd_stake_staked_node_insert( staked_nodes, pubkeys[i] );
    FD_TEST( staked_node );
    staked_node->stake = i;
  }
  for ( ulong i = 0; i < NODE_CNT; i++ ) {
    fd_stake_staked_node_t * staked_node =
        fd_stake_staked_node_query( staked_nodes, pubkeys[i], NULL );
    FD_TEST( staked_node );
    FD_TEST( staked_node->stake == i );
  }

  // for ( ulong i = 0; i < fd_stake_staked_node_slot_cnt( staked_nodes ); i++ ) {
  //   fd_stake_staked_node_t staked_node = staked_nodes[i];
  //   if ( !fd_stake_staked_node_key_inval( staked_node.key ) ) {
  //     FD_LOG_HEXDUMP_NOTICE( ( "pubkey", &staked_node.key, sizeof( staked_node.key ) ) );
  //   }
  // }

  // for ( ulong i = 0; i < NUM_PUBKEYS; i++ ) {
  //   for ( ulong j = 0; j < fd_stake_staked_node_slot_cnt( staked_nodes ); j++ ) {
  //     // fd_stake_staked_node_t staked_node = qos->staked_node_map[j];
  //     // int rc = !( memcmp( staked_node.key.pubkey, pubkeys[i].pubkey, FD_TXN_PUBKEY_SZ ) );
  //     // FD_LOG_NOTICE(("rc %d", rc));
  //   }
  //   fd_stake_staked_node_t * staked_node =
  //       fd_stake_staked_node_query( staked_nodes, pubkeys[i], NULL );
  //   FD_TEST( staked_node );
  //   FD_TEST( staked_node->stake == i );
  // }
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  if ( FD_UNLIKELY( argc > 1 ) ) FD_LOG_ERR( ( "unrecognized argument: %s", argv[1] ) );

  test_fd_quic_qos_conn_lru();

  FD_LOG_NOTICE( ( "pass" ) );
  fd_halt();
  return 0;
}
