#include "fd_blockhashes.h"

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  FD_TEST( fd_blockhash_map_footprint( FD_BLOCKHASH_MAP_CHAIN_MAX )==FD_BLOCKHASH_MAP_FOOTPRINT );
  FD_LOG_NOTICE(( "%lu", fd_blockhash_map_footprint( FD_BLOCKHASH_MAP_FOOTPRINT ) ));

  fd_halt();
  return 0;
}
