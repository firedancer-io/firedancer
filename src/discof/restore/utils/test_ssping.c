#include "fd_ssping.h"

#include "../../../util/fd_util.h"

static void
noop_on_ping( void *        _ctx,
              fd_ip4_port_t addr,
              ulong         latency ) {
  (void)_ctx; (void)addr; (void)latency;
}

static void
test_is_invalidated_null_ssping( void ) {
  FD_LOG_NOTICE(( "testing is_invalidated with NULL ssping" ));
  fd_ip4_port_t addr = { .addr = FD_IP4_ADDR( 10, 0, 0, 1 ), .port = fd_ushort_bswap( 8899 ) };
  FD_TEST( fd_ssping_is_invalidated( NULL, addr )==0 );
  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_is_invalidated_unknown_peer( fd_ssping_t * ssping ) {
  FD_LOG_NOTICE(( "testing is_invalidated with unknown peer" ));
  fd_ip4_port_t addr = { .addr = FD_IP4_ADDR( 192, 168, 0, 99 ), .port = fd_ushort_bswap( 9999 ) };
  FD_TEST( fd_ssping_is_invalidated( ssping, addr )==0 );
  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_is_invalidated_unpinged_peer( fd_ssping_t * ssping ) {
  FD_LOG_NOTICE(( "testing is_invalidated with unpinged (valid) peer" ));
  fd_ip4_port_t addr = { .addr = FD_IP4_ADDR( 10, 0, 0, 1 ), .port = fd_ushort_bswap( 8899 ) };
  fd_ssping_add( ssping, addr );

  /* Peer is in UNPINGED state, not invalidated. */
  FD_TEST( fd_ssping_is_invalidated( ssping, addr )==0 );

  fd_ssping_remove( ssping, addr );
  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_is_invalidated_after_invalidate( fd_ssping_t * ssping ) {
  FD_LOG_NOTICE(( "testing is_invalidated after invalidation" ));
  fd_ip4_port_t addr = { .addr = FD_IP4_ADDR( 10, 0, 0, 2 ), .port = fd_ushort_bswap( 8900 ) };
  fd_ssping_add( ssping, addr );

  FD_TEST( fd_ssping_is_invalidated( ssping, addr )==0 );

  fd_ssping_invalidate( ssping, addr );

  FD_TEST( fd_ssping_is_invalidated( ssping, addr )==1 );

  /* Cleanup: remove drops the peer entirely. */
  fd_ssping_remove( ssping, addr );
  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_is_invalidated_double_invalidate( fd_ssping_t * ssping ) {
  FD_LOG_NOTICE(( "testing is_invalidated after double invalidation" ));
  fd_ip4_port_t addr = { .addr = FD_IP4_ADDR( 10, 0, 0, 3 ), .port = fd_ushort_bswap( 8901 ) };
  fd_ssping_add( ssping, addr );

  fd_ssping_invalidate( ssping, addr );
  FD_TEST( fd_ssping_is_invalidated( ssping, addr )==1 );

  /* Invalidating an already-invalid peer should be a no-op. */
  fd_ssping_invalidate( ssping, addr );
  FD_TEST( fd_ssping_is_invalidated( ssping, addr )==1 );

  fd_ssping_remove( ssping, addr );
  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_is_invalidated_after_remove( fd_ssping_t * ssping ) {
  FD_LOG_NOTICE(( "testing is_invalidated after remove" ));
  fd_ip4_port_t addr = { .addr = FD_IP4_ADDR( 10, 0, 0, 4 ), .port = fd_ushort_bswap( 8902 ) };
  fd_ssping_add( ssping, addr );
  fd_ssping_invalidate( ssping, addr );
  FD_TEST( fd_ssping_is_invalidated( ssping, addr )==1 );

  /* Removing the peer should make it no longer queryable. */
  fd_ssping_remove( ssping, addr );
  FD_TEST( fd_ssping_is_invalidated( ssping, addr )==0 );

  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_is_invalidated_refcounted_peer( fd_ssping_t * ssping ) {
  FD_LOG_NOTICE(( "testing is_invalidated with refcounted peer" ));
  fd_ip4_port_t addr = { .addr = FD_IP4_ADDR( 10, 0, 0, 5 ), .port = fd_ushort_bswap( 8903 ) };

  /* Add the peer twice (refcount=2). */
  fd_ssping_add( ssping, addr );
  fd_ssping_add( ssping, addr );

  fd_ssping_invalidate( ssping, addr );
  FD_TEST( fd_ssping_is_invalidated( ssping, addr )==1 );

  /* First remove decrements refcount but does not free. */
  FD_TEST( fd_ssping_remove( ssping, addr )==0 );
  FD_TEST( fd_ssping_is_invalidated( ssping, addr )==1 );

  /* Second remove frees the peer. */
  FD_TEST( fd_ssping_remove( ssping, addr )==1 );
  FD_TEST( fd_ssping_is_invalidated( ssping, addr )==0 );

  FD_LOG_NOTICE(( "... pass" ));
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong max_peers = 32UL;

  ulong ssping_footprint = fd_ssping_footprint( max_peers );
  ulong ssping_align     = fd_ssping_align();

  ulong  page_cnt  = 1;
  char * _page_sz  = "gigantic";
  ulong  numa_idx  = fd_shmem_numa_idx( 0 );
  fd_wksp_t * wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  void * shmem = fd_wksp_alloc_laddr( wksp, ssping_align, ssping_footprint, 1UL );
  FD_TEST( shmem );

  fd_ssping_t * ssping = fd_ssping_join( fd_ssping_new( shmem, max_peers, 42UL/*seed*/, noop_on_ping, NULL ) );
  FD_TEST( ssping );

  test_is_invalidated_null_ssping();
  test_is_invalidated_unknown_peer( ssping );
  test_is_invalidated_unpinged_peer( ssping );
  test_is_invalidated_after_invalidate( ssping );
  test_is_invalidated_double_invalidate( ssping );
  test_is_invalidated_after_remove( ssping );
  test_is_invalidated_refcounted_peer( ssping );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
