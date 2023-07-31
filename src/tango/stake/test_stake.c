#include "../../util/fd_util.h"
#include "fd_stake.h"

#define LG_SLOT_CNT 10
#define MAX_NODE_CNT    ( 1UL << LG_SLOT_CNT )
#define NUM_PUBKEYS     4

fd_stake_pubkey_t pubkeys[NUM_PUBKEYS] = {
    { .pubkey = { 44, 174, 25,  39, 43, 255, 200, 81, 55, 73, 10,  113, 174, 91, 223, 80,
                  50, 51,  102, 25, 63, 110, 36,  28, 51, 11, 174, 179, 110, 8,  25,  152 } },
    { .pubkey = { 250, 56, 248, 84,  190, 46,  154, 76,  15, 72, 181, 205, 32, 96, 128, 213,
                  158, 33, 81,  193, 63,  154, 93,  254, 15, 81, 32,  175, 54, 60, 179, 224 } },
    { .pubkey = { 225, 102, 95, 246, 174, 91, 1,  240, 118, 174, 119, 113, 150, 146, 149, 29,
                  253, 10,  69, 168, 188, 51, 31, 11,  67,  18,  201, 181, 189, 178, 159, 178 } },
    { .pubkey = { 160, 58,  145, 16, 41,  55,  193, 27,  132, 112, 36, 109, 233, 125, 206,
                  165, 200, 130, 76, 147, 173, 151, 180, 73,  248, 4,  165, 8,   163, 42 } } };

void
test_stake( void ) {
  fd_wksp_t * wksp = fd_wksp_new_anonymous(
      FD_SHMEM_GIGANTIC_PAGE_SZ, 1, fd_shmem_cpu_idx( fd_shmem_numa_idx( 0 ) ), "wksp", 0UL );
  FD_TEST( wksp );
  void * mem =
      fd_wksp_alloc_laddr( wksp, fd_stake_align(), fd_stake_footprint( LG_SLOT_CNT ), 42UL );

  fd_stake_t *      stake        = fd_stake_join( fd_stake_new( mem, LG_SLOT_CNT ) );
  fd_stake_node_t * staked_nodes = fd_stake_nodes_laddr( stake );

  for ( ulong i = 0; i < NUM_PUBKEYS; i++ ) {
    fd_stake_node_t * staked_node = fd_stake_node_insert( staked_nodes, pubkeys[i] );
    staked_node->stake            = i;
    FD_TEST( staked_node );
  }
  for ( ulong i = 0; i < NUM_PUBKEYS; i++ ) {
    fd_stake_node_t * staked_node = fd_stake_node_query( staked_nodes, pubkeys[i], NULL );
    FD_TEST( staked_node );
    FD_TEST( staked_node->stake == i );
  }
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );

  if ( FD_UNLIKELY( argc > 1 ) ) FD_LOG_ERR( ( "unrecognized argument: %s", argv[1] ) );

  test_stake();

  FD_LOG_NOTICE( ( "pass" ) );
  fd_halt();
  return 0;
}
