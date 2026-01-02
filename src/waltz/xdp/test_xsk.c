#include "fd_xsk.h"
#include "../../util/fd_util.h"

#if defined(__linux__)

static void
test_fd_xdp_ring_empty( void ) {
  fd_xdp_ring_t ring;
  uint prod_val = 0;
  uint cons_val = 0;

  ring.prod = &prod_val;
  ring.cons = &cons_val;
  ring.depth = 128;

  /* Producer perspective - empty ring (cached values equal) */
  prod_val = ring.cached_prod = 100;
  cons_val = ring.cached_cons = 100;
  FD_TEST( fd_xdp_ring_empty( &ring, FD_XDP_RING_ROLE_PROD ) == 1 );

  /* Producer perspective - non-empty ring (cached values differ) */
  prod_val = ring.cached_prod = 105;
  cons_val = ring.cached_cons = 100;
  FD_TEST( fd_xdp_ring_empty( &ring, FD_XDP_RING_ROLE_PROD ) == 0 );

  /* Producer perspective - stale cached_cons, actually empty */
  ring.cached_prod = 200;
  ring.cached_cons = 190;
  prod_val = 200;
  cons_val = 200; /* consumer caught up */
  FD_TEST( fd_xdp_ring_empty( &ring, FD_XDP_RING_ROLE_PROD ) == 1 );
  FD_TEST( ring.cached_cons == 200 ); /* verify cache was updated */

  /* Producer perspective - stale cached_cons, actually not empty */
  ring.cached_prod = 300;
  ring.cached_cons = 290;
  prod_val = 300;
  cons_val = 295; /* consumer partially caught up */
  FD_TEST( fd_xdp_ring_empty( &ring, FD_XDP_RING_ROLE_PROD ) == 0 );
  FD_TEST( ring.cached_cons == 295 ); /* verify cache was updated */

  /* Consumer perspective - empty ring (cached values equal) */
  prod_val = ring.cached_prod = 400;
  cons_val = ring.cached_cons = 400;
  FD_TEST( fd_xdp_ring_empty( &ring, FD_XDP_RING_ROLE_CONS ) == 1 );

  /* Consumer perspective - non-empty ring (fast path) */
  prod_val = ring.cached_prod = 410;
  cons_val = ring.cached_cons = 400;
  FD_TEST( fd_xdp_ring_empty( &ring, FD_XDP_RING_ROLE_CONS ) == 0 );

  /* Consumer perspective - stale cached_prod, actually not empty */
  ring.cached_prod = 600;
  ring.cached_cons = 600;
  prod_val = 605; /* producer added more */
  cons_val = 600;
  FD_TEST( fd_xdp_ring_empty( &ring, FD_XDP_RING_ROLE_CONS ) == 0 );
  FD_TEST( ring.cached_prod == 605 ); /* verify cache was updated */

  /* Wraparound handling - producer perspective */
  prod_val = ring.cached_prod = UINT_MAX + 5U;
  cons_val = ring.cached_cons = UINT_MAX;
  FD_TEST( fd_xdp_ring_empty( &ring, FD_XDP_RING_ROLE_PROD ) == 0 );

  /* Wraparound handling - consumer perspective */
  prod_val = ring.cached_prod = UINT_MAX + 5U;
  cons_val = ring.cached_cons = UINT_MAX;
  FD_TEST( fd_xdp_ring_empty( &ring, FD_XDP_RING_ROLE_CONS ) == 0 );

  FD_LOG_NOTICE(( "test_fd_xdp_ring_empty: pass" ));
}

static void
test_fd_xdp_ring_full( void ) {
  fd_xdp_ring_t ring;
  uint prod_val = 0;
  uint cons_val = 0;

  ring.prod = &prod_val;
  ring.cons = &cons_val;
  ring.depth = 128;

  /* Not full - fast path (plenty of space) */
  prod_val = ring.cached_prod = 100;
  cons_val = ring.cached_cons = 90;
  FD_TEST( fd_xdp_ring_full( &ring ) == 0 );

  /* Not full - fast path (one slot available) */
  prod_val = ring.cached_prod = 200;
  cons_val = ring.cached_cons = 73; /* 200 - 73 = 127, one less than depth */
  FD_TEST( fd_xdp_ring_full( &ring ) == 0 );

  /* Full - cached values exactly at depth */
  prod_val = ring.cached_prod = 300;
  cons_val = ring.cached_cons = 172; /* 300 - 172 = 128, exactly depth */
  FD_TEST( fd_xdp_ring_full( &ring ) == 1 );

  /* Stale cached_cons, actually not full */
  ring.cached_prod = 400;
  ring.cached_cons = 272; /* 400 - 272 = 128, appears full */
  prod_val = 400;
  cons_val = 300; /* consumer made progress, 400 - 300 = 100 */
  FD_TEST( fd_xdp_ring_full( &ring ) == 0 );
  FD_TEST( ring.cached_cons == 300 ); /* verify cache was updated */

  /* Wraparound handling - not full */
  prod_val = ring.cached_prod = UINT_MAX + 5U;
  cons_val = ring.cached_cons = UINT_MAX;
  FD_TEST( fd_xdp_ring_full( &ring ) == 0 );

  /* Wraparound handling - full */
  prod_val = ring.cached_prod = UINT_MAX + 128U;
  cons_val = ring.cached_cons = UINT_MAX;
  FD_TEST( fd_xdp_ring_full( &ring ) == 1 );

  /* Empty ring should not be full */
  prod_val = ring.cached_prod = 2000;
  cons_val = ring.cached_cons = 2000;
  FD_TEST( fd_xdp_ring_full( &ring ) == 0 );

  /* Although should not happen, overfull should still return full */
  prod_val = ring.cached_prod = 3000;
  cons_val = ring.cached_cons = 2800; /* 3000 - 2800 = 200, more than depth */
  FD_TEST( fd_xdp_ring_full( &ring ) == 1 );

  FD_LOG_NOTICE(( "test_fd_xdp_ring_full: pass" ));
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  FD_LOG_NOTICE(( "Testing fd_xdp_ring helper functions" ));
  test_fd_xdp_ring_empty();
  test_fd_xdp_ring_full();
  FD_LOG_NOTICE(( "All tests pass" ));

  fd_halt();
  return 0;
}

#else

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  FD_LOG_NOTICE(( "skip: unit test requires Linux" ));
  fd_halt();
  return 0;
}

#endif
