#include "../../util/fd_util.h"
#include "fd_gossip_purged.h"

#include <stdlib.h>

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong footprint = fd_gossip_purged_footprint( 8UL );
  void * mem = aligned_alloc( fd_gossip_purged_align(), footprint );
  FD_TEST( mem );

  fd_rng_t rng_mem[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( rng_mem, 0U, 0UL ) );
  FD_TEST( rng );

  fd_gossip_purged_t * purged = fd_gossip_purged_join( fd_gossip_purged_new( mem, rng, 8UL ) );
  FD_TEST( purged );
  FD_TEST( !fd_gossip_purged_len( purged ) );

  uchar iter_mem[16UL] __attribute__((aligned(8)));
  fd_gossip_purged_mask_iter_t * iter = fd_gossip_purged_mask_iter_init( purged, 0UL, 0U, iter_mem );
  FD_TEST( fd_gossip_purged_mask_iter_done( iter, purged ) );

  fd_rng_delete( fd_rng_leave( rng ) );
  free( mem );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
