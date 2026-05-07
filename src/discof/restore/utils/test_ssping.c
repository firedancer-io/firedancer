#include "fd_ssping.h"

#include "../../../util/fd_util.h"

/* Stub on_ping callback, required by fd_ssping_new but not exercised
   in these unit tests (no actual pings are sent/received). */
static void
on_ping_stub( void *        _ctx,
              fd_ip4_port_t addr,
              ulong         latency ) {
  (void)_ctx;
  (void)addr;
  (void)latency;
}

static void
test_invalidate_and_remove( fd_ssping_t * ssping ) {
  FD_LOG_NOTICE(( "testing invalidate and remove" ));

  fd_ip4_port_t addr = { .addr = FD_IP4_ADDR( 10, 0, 0, 1 ), .port = fd_ushort_bswap( 8000 ) };
  long now = fd_log_wallclock();

  fd_ssping_add( ssping, addr );
  fd_ssping_invalidate( ssping, addr, now );

  /* Full removal (refcnt goes to 0). */
  FD_TEST( fd_ssping_remove( ssping, addr ) );

  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_double_invalidate( fd_ssping_t * ssping ) {
  FD_LOG_NOTICE(( "testing double invalidate" ));

  fd_ip4_port_t addr = { .addr = FD_IP4_ADDR( 10, 0, 0, 2 ), .port = fd_ushort_bswap( 8001 ) };
  long now = fd_log_wallclock();

  fd_ssping_add( ssping, addr );
  fd_ssping_invalidate( ssping, addr, now );

  /* Second invalidation should be a no-op (already INVALID). */
  fd_ssping_invalidate( ssping, addr, now );

  /* Cleanup. */
  fd_ssping_remove( ssping, addr );

  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_invalidate_refcounted( fd_ssping_t * ssping ) {
  FD_LOG_NOTICE(( "testing invalidate refcounted" ));

  fd_ip4_port_t addr = { .addr = FD_IP4_ADDR( 10, 0, 0, 3 ), .port = fd_ushort_bswap( 8002 ) };
  long now = fd_log_wallclock();

  /* Add twice (refcnt=2). */
  fd_ssping_add( ssping, addr );
  fd_ssping_add( ssping, addr );

  fd_ssping_invalidate( ssping, addr, now );

  /* First remove: refcnt drops to 1, peer stays. */
  FD_TEST( !fd_ssping_remove( ssping, addr ) );

  /* Second remove: refcnt drops to 0, peer fully removed. */
  FD_TEST( fd_ssping_remove( ssping, addr ) );

  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_is_invalidated_null_ssping( void ) {
  FD_LOG_NOTICE(( "testing is_invalidated null ssping" ));

  fd_ip4_port_t addr = { .addr = FD_IP4_ADDR( 10, 0, 0, 4 ), .port = fd_ushort_bswap( 8003 ) };
  FD_TEST( !fd_ssping_is_invalidated( NULL, addr ) );

  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_is_invalidated_unknown_peer( fd_ssping_t * ssping ) {
  FD_LOG_NOTICE(( "testing is_invalidated unknown peer" ));

  fd_ip4_port_t addr = { .addr = FD_IP4_ADDR( 10, 0, 0, 5 ), .port = fd_ushort_bswap( 8004 ) };
  FD_TEST( !fd_ssping_is_invalidated( ssping, addr ) );

  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_is_invalidated_after_invalidate( fd_ssping_t * ssping ) {
  FD_LOG_NOTICE(( "testing is_invalidated after invalidate" ));

  fd_ip4_port_t addr = { .addr = FD_IP4_ADDR( 10, 0, 0, 6 ), .port = fd_ushort_bswap( 8005 ) };
  long now = fd_log_wallclock();

  fd_ssping_add( ssping, addr );

  /* Before invalidation: peer is UNPINGED, not INVALID. */
  FD_TEST( !fd_ssping_is_invalidated( ssping, addr ) );

  fd_ssping_invalidate( ssping, addr, now );

  /* After invalidation: peer should be INVALID. */
  FD_TEST( fd_ssping_is_invalidated( ssping, addr ) );

  /* After removal: peer is gone, should return 0. */
  fd_ssping_remove( ssping, addr );
  FD_TEST( !fd_ssping_is_invalidated( ssping, addr ) );

  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_pool_exhaustion( fd_ssping_t * ssping,
                      ulong         max_peers ) {
  FD_LOG_NOTICE(( "testing pool exhaustion" ));

  /* Fill all max_peers slots, then verify the next add is silently
     dropped (no crash). */
  fd_ip4_port_t addrs[256]; /* large enough for max_peers=8 */
  FD_TEST( max_peers<=sizeof(addrs)/sizeof(addrs[0]) );

  for( ulong i=0; i<max_peers; i++ ) {
    addrs[i] = (fd_ip4_port_t){ .addr = FD_IP4_ADDR( 10, 0, 1, (uchar)(i+1UL) ),
                                .port = fd_ushort_bswap( (ushort)(9000U+i) ) };
    fd_ssping_add( ssping, addrs[i] );
  }

  /* Pool is full.  This should be a no-op (logged warning). */
  fd_ip4_port_t overflow_addr = { .addr = FD_IP4_ADDR( 10, 0, 1, 255 ),
                                  .port = fd_ushort_bswap( 9999 ) };
  fd_ssping_add( ssping, overflow_addr );

  /* overflow_addr was never inserted, so remove returns 0. */
  FD_TEST( !fd_ssping_remove( ssping, overflow_addr ) );

  /* First and last tracked peers are still there and not invalidated. */
  FD_TEST( !fd_ssping_is_invalidated( ssping, addrs[0] ) );
  FD_TEST( !fd_ssping_is_invalidated( ssping, addrs[max_peers-1UL] ) );

  /* Cleanup */
  for( ulong i=0; i<max_peers; i++ ) {
    fd_ssping_remove( ssping, addrs[i] );
  }

  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_add_after_invalidate( fd_ssping_t * ssping ) {
  FD_LOG_NOTICE(( "testing add after invalidate" ));

  /* Adding a peer that is already invalidated should bump the refcnt
     but the peer should remain in the INVALID state. */
  fd_ip4_port_t addr = { .addr = FD_IP4_ADDR( 10, 0, 2, 1 ), .port = fd_ushort_bswap( 9010 ) };
  long now = fd_log_wallclock();

  fd_ssping_add( ssping, addr );
  fd_ssping_invalidate( ssping, addr, now );
  FD_TEST( fd_ssping_is_invalidated( ssping, addr ) );

  /* Re-add: refcnt goes from 1 to 2, but state stays INVALID. */
  fd_ssping_add( ssping, addr );
  FD_TEST( fd_ssping_is_invalidated( ssping, addr ) );

  /* First remove: refcnt drops to 1, peer stays. */
  FD_TEST( !fd_ssping_remove( ssping, addr ) );
  FD_TEST( fd_ssping_is_invalidated( ssping, addr ) );

  /* Second remove: refcnt drops to 0, peer fully removed. */
  FD_TEST( fd_ssping_remove( ssping, addr ) );
  FD_TEST( !fd_ssping_is_invalidated( ssping, addr ) );

  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_remove_without_invalidate( fd_ssping_t * ssping ) {
  FD_LOG_NOTICE(( "testing remove without invalidate" ));

  /* A peer can be removed without ever being invalidated. */
  fd_ip4_port_t addr = { .addr = FD_IP4_ADDR( 10, 0, 3, 1 ), .port = fd_ushort_bswap( 9020 ) };

  fd_ssping_add( ssping, addr );
  FD_TEST( !fd_ssping_is_invalidated( ssping, addr ) );

  /* Remove directly: peer is fully removed. */
  FD_TEST( fd_ssping_remove( ssping, addr ) );
  FD_TEST( !fd_ssping_is_invalidated( ssping, addr ) );

  FD_LOG_NOTICE(( "... pass" ));
}

static void
test_remove_unknown( fd_ssping_t * ssping ) {
  FD_LOG_NOTICE(( "testing remove unknown" ));
  fd_ip4_port_t addr = { .addr = FD_IP4_ADDR( 192, 168, 99, 99 ), .port = fd_ushort_bswap( 9999 ) };
  FD_TEST( !fd_ssping_remove( ssping, addr ) );
  fd_ssping_invalidate( ssping, addr, fd_log_wallclock() ); /* should not crash */
  FD_TEST( !fd_ssping_is_invalidated( ssping, addr ) );     /* not tracked -> 0 */
  FD_LOG_NOTICE(( "... pass" ));
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong  page_cnt  = 1;
  char * _page_sz  = "gigantic";
  ulong  numa_idx  = fd_shmem_numa_idx( 0 );
  fd_wksp_t * wksp = fd_wksp_new_anonymous( fd_cstr_to_shmem_page_sz( _page_sz ), page_cnt, fd_shmem_cpu_idx( numa_idx ), "wksp", 0UL );
  FD_TEST( wksp );

  /* Create a single ssping instance.  max_peers=8 is enough for all
     tests (each test cleans up after itself). */
  ulong max_peers = 8UL;
  void * shmem = fd_wksp_alloc_laddr( wksp, fd_ssping_align(), fd_ssping_footprint( max_peers ), 1UL );
  fd_ssping_t * ssping = fd_ssping_join( fd_ssping_new( shmem, max_peers, 42UL, on_ping_stub, NULL ) );
  FD_TEST( ssping );

  test_invalidate_and_remove( ssping );
  test_double_invalidate( ssping );
  test_invalidate_refcounted( ssping );
  test_is_invalidated_null_ssping();
  test_is_invalidated_unknown_peer( ssping );
  test_is_invalidated_after_invalidate( ssping );
  test_pool_exhaustion( ssping, max_peers );
  test_add_after_invalidate( ssping );
  test_remove_without_invalidate( ssping );
  test_remove_unknown( ssping );

  FD_LOG_NOTICE(( "all ssping tests passed" ));

  fd_halt();
  return 0;
}
