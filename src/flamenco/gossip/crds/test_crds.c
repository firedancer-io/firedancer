#include "../../../util/fd_util.h"
#include "fd_crds.h"

#include <stdlib.h>

void
stub_ci_change( void *              ctx,
                ulong               crds_pool_idx,
                ulong               stake,
                int                 change_type,
                fd_stem_context_t * ctx_unused,
                long                now ) {
  (void)ctx; (void)crds_pool_idx; (void)stake; (void)change_type; (void)ctx_unused; (void)now;
}

static void
test_crds_new_basic( void ) {
  ulong ele_max    = 1024UL;
  ulong purged_max =  512UL;

  void * mem = aligned_alloc( fd_crds_align(), fd_crds_footprint( ele_max, purged_max ) );
  FD_TEST( mem );

  fd_rng_t _rng[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );
  FD_TEST( rng );

  static fd_gossip_out_ctx_t gossip_out = {0};

  void * shcrds = fd_crds_new( mem, rng, ele_max, purged_max, &gossip_out, stub_ci_change, NULL );
  FD_TEST( shcrds );

  fd_crds_t * crds = fd_crds_join( shcrds );
  FD_TEST( crds );

  free( mem );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_crds_new_basic();
  FD_LOG_NOTICE(( "test_crds_new_basic() passed" ));
  fd_halt();
  return 0;
}

