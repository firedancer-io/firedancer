/* test_verify_tile.c injects mock inputs into the verify tile.
   Uses libc malloc instead of wksp alloc for better memory sanitization
   check accuracy. */

#define FD_TILE_TEST
#include "fd_verify_tile.c"
#include "../topo/fd_topob.h"
#include "../quic/fd_tpu.h"
#include <stdlib.h>
#include <unistd.h>

#define TCACHE_DEPTH (128UL)

#if defined(__linux__)

static void
test_seccomp( void ) {
  int   out_fds[2];
  ulong nfds = populate_allowed_fds( NULL, NULL, 2UL, out_fds );
  FD_TEST( nfds>=1 && nfds<=2 );
  FD_TEST( out_fds[0]==STDERR_FILENO );
  if( nfds==2 ) FD_TEST( out_fds[1]==fd_log_private_logfile_fd() );

  struct sock_filter filter[ 32 ];
  populate_allowed_seccomp( NULL, NULL, 32UL, filter );
}

#endif /* defined(__linux__) */

#define TEST_ALLOC_MAX (64UL)
static void * test_allocs[ TEST_ALLOC_MAX ];
static ulong  test_alloc_cnt;

static void *
test_malloc( ulong align, ulong sz ) {
  FD_TEST( test_alloc_cnt<TEST_ALLOC_MAX );
  void * p = aligned_alloc( align, sz );
  FD_TEST( p );
  test_allocs[ test_alloc_cnt ] = p;
  test_alloc_cnt++;
  return p;
}

static void
test_free_all( void ) {
  while( test_alloc_cnt ) free( test_allocs[ --test_alloc_cnt ] );
}

static void
mock_link_create( fd_topo_t *  topo,
                  char const * name ) {
#define LINK_DEPTH (16UL)
  fd_topo_link_t * link = fd_topob_link( topo, name, "wksp", LINK_DEPTH, 0UL, 0UL );
  ulong data_sz = fd_dcache_req_data_sz( FD_TPU_REASM_MTU, LINK_DEPTH, 1UL, 1 );
  link->mcache  = fd_mcache_join( fd_mcache_new( test_malloc( fd_mcache_align(), fd_mcache_footprint( LINK_DEPTH, 0UL ) ), LINK_DEPTH, 0UL, 0UL ) );
  link->dcache  = fd_dcache_join( fd_dcache_new( test_malloc( fd_dcache_align(), fd_dcache_footprint( data_sz, 0UL ) ), data_sz, 0UL ) );
}

static fd_topo_t *
mock_topo_create( void ) {
  fd_topo_t * topo = fd_topob_new( test_malloc( alignof(fd_topo_t), sizeof(fd_topo_t) ), "verify-test" );

  fd_topo_wksp_t * wksp = fd_topob_wksp( topo, "wksp" );
  wksp->wksp = NULL;

  fd_topo_tile_t * verify = fd_topob_tile( topo, "verify", "wksp", "wksp", 0UL, 0, 0 );
  verify->verify.tcache_depth = TCACHE_DEPTH;

  fd_verify_ctx_t * ctx = test_malloc( scratch_align(), scratch_footprint( verify ) );
  topo->objs[ verify->tile_obj_id ].offset = (ulong)ctx;

  mock_link_create( topo, "quic_verify"  );
  mock_link_create( topo, "bundle_verif" );
  mock_link_create( topo, "gossip_out"   );
  mock_link_create( topo, "send_out"     );

  /* Declare link ins in opposite order than IN_KIND_* to check for in
     idx confusion */
#define IN_IDX_SEND   0
#define IN_IDX_GOSSIP 1
#define IN_IDX_BUNDLE 2
#define IN_IDX_QUIC   3
  fd_topob_tile_in( topo, "verify", 0UL, "wksp", "send_out",     0UL, 0, 1 );
  fd_topob_tile_in( topo, "verify", 0UL, "wksp", "gossip_out",   0UL, 0, 1 );
  fd_topob_tile_in( topo, "verify", 0UL, "wksp", "bundle_verif", 0UL, 0, 1 );
  fd_topob_tile_in( topo, "verify", 0UL, "wksp", "quic_verify",  0UL, 0, 1 );

  return topo;
}

static void
test_load_balance( void ) {
  test_free_all();
  fd_topo_t *       topo = mock_topo_create();
  fd_topo_tile_t *  tile = &topo->tiles[ fd_topo_find_tile( topo, "verify", 0UL ) ];
  privileged_init( topo, tile );
  unprivileged_init( topo, tile );
  fd_verify_ctx_t * ctx  = fd_topo_obj_laddr( topo, tile->tile_obj_id );

  /* Tile should accept all traffic if it's the only tile */
  ctx->round_robin_idx = 0UL;
  ctx->round_robin_cnt = 1UL;
  FD_TEST( before_frag( ctx, IN_IDX_BUNDLE, 0UL, 0UL )==0 );
  FD_TEST( before_frag( ctx, IN_IDX_BUNDLE, 1UL, 0UL )==0 );
  FD_TEST( before_frag( ctx, IN_IDX_BUNDLE, 0UL, 1UL )==0 );
  FD_TEST( before_frag( ctx, IN_IDX_BUNDLE, 1UL, 1UL )==0 );
  FD_TEST( before_frag( ctx, IN_IDX_QUIC,   0UL, 0UL )==0 );
  FD_TEST( before_frag( ctx, IN_IDX_QUIC,   1UL, 0UL )==0 );

  /* Tile 0 should accept all bundle traffic */
  ctx->round_robin_idx = 0UL;
  ctx->round_robin_cnt = 4UL;
  FD_TEST( before_frag( ctx, IN_IDX_BUNDLE, 0UL, 1UL )==0 );
  FD_TEST( before_frag( ctx, IN_IDX_BUNDLE, 1UL, 1UL )==0 );

  /* Tile 0 should load balance other traffic */
  FD_TEST( before_frag( ctx, IN_IDX_BUNDLE, 0UL, 0UL )==0 );
  FD_TEST( before_frag( ctx, IN_IDX_BUNDLE, 1UL, 0UL )==1 );
  FD_TEST( before_frag( ctx, IN_IDX_BUNDLE, 2UL, 0UL )==1 );
  FD_TEST( before_frag( ctx, IN_IDX_QUIC,   0UL, 0UL )==0 );
  FD_TEST( before_frag( ctx, IN_IDX_QUIC,   1UL, 0UL )==1 );
  FD_TEST( before_frag( ctx, IN_IDX_QUIC,   2UL, 0UL )==1 );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

# if defined(__linux__)
  test_seccomp();
# endif
  test_load_balance();
  test_free_all();
  /* further tests here ... */

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
