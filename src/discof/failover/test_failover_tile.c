#include "fd_failover_tile.c"
#include "../../util/net/fd_ip4.h"

static uchar ch_mem[ 8UL<<20 ] __attribute__((aligned(128)));
static fd_topo_tile_t         tile[1];
static fd_failover_tile_ctx_t ctx[1];

static void
test_pool_layout( void ) {
  fd_memset( tile, 0, sizeof(tile) );
  tile->failov.member_cnt = 3UL;
  for( ulong i=0UL; i<3UL; i++ ) fd_memset( tile->failov.member_junk_pubkey[ i ], (int)(i+1UL), 32UL );

  /* The middle member accepts from the first and dials the last. */
  FD_TEST( !pool_layout( ctx, tile, tile->failov.member_junk_pubkey[ 1 ] ) );
  FD_TEST( ctx->member_cnt==3UL && ctx->self_idx==1UL && ctx->peer_cnt==2UL );
  FD_TEST( ctx->peers[ 0 ].member_idx==0UL && !ctx->peers[ 0 ].dial );
  FD_TEST( ctx->peers[ 1 ].member_idx==2UL &&  ctx->peers[ 1 ].dial );

  /* The first member only dials, the last only accepts. */
  FD_TEST( !pool_layout( ctx, tile, tile->failov.member_junk_pubkey[ 0 ] ) );
  FD_TEST( ctx->self_idx==0UL && ctx->peer_cnt==2UL && ctx->peers[ 0 ].dial && ctx->peers[ 1 ].dial );
  FD_TEST( ctx->peers[ 0 ].member_idx==1UL && ctx->peers[ 1 ].member_idx==2UL );
  FD_TEST( !pool_layout( ctx, tile, tile->failov.member_junk_pubkey[ 2 ] ) );
  FD_TEST( ctx->self_idx==2UL && ctx->peer_cnt==2UL && !ctx->peers[ 0 ].dial && !ctx->peers[ 1 ].dial );

  /* A junk key that is unlisted or listed twice is refused. */
  uchar other[ 32 ];
  fd_memset( other, 9, 32UL );
  FD_TEST( pool_layout( ctx, tile, other )==-1 );
  fd_memcpy( tile->failov.member_junk_pubkey[ 2 ], tile->failov.member_junk_pubkey[ 0 ], 32UL );
  FD_TEST( pool_layout( ctx, tile, tile->failov.member_junk_pubkey[ 0 ] )==-1 );

  /* A two-member pool is one dialer and one listener. */
  fd_memset( tile->failov.member_junk_pubkey[ 2 ], 3, 32UL );
  tile->failov.member_cnt = 2UL;
  FD_TEST( !pool_layout( ctx, tile, tile->failov.member_junk_pubkey[ 0 ] ) );
  FD_TEST( ctx->peer_cnt==1UL && ctx->peers[ 0 ].member_idx==1UL && ctx->peers[ 0 ].dial );
  FD_TEST( !pool_layout( ctx, tile, tile->failov.member_junk_pubkey[ 1 ] ) );
  FD_TEST( ctx->peer_cnt==1UL && ctx->peers[ 0 ].member_idx==0UL && !ctx->peers[ 0 ].dial );
  FD_LOG_NOTICE(( "pass: pool layout, self index and dial direction from list order" ));
}

static void
test_listen_fd( void ) {
  fd_memset( ctx, 0, sizeof(ctx) );
  ctx->peer_cnt        = 2UL;
  ctx->peers[ 0 ].dial = 1;
  ctx->peers[ 1 ].dial = 0;
  FD_TEST( pool_listen_fd( ctx )==-1 );

  FD_TEST( fd_failover_channel_footprint()<=sizeof(ch_mem) );
  fd_failover_channel_t * ch = fd_failover_channel_join( fd_failover_channel_new( ch_mem ) );
  FD_TEST( ch );
  ctx->peers[ 1 ].channel = ch;
  FD_TEST( pool_listen_fd( ctx )==-1 );

  fd_failover_channel_init_listener( ch, FD_IP4_ADDR(127,0,0,1), 0 );
  int fd = fd_failover_channel_listen_fd( ch );
  FD_TEST( fd!=-1 && pool_listen_fd( ctx )==fd );

  /* A dialing peer never contributes a listener, whatever its channel holds. */
  ctx->peers[ 0 ].channel = ch;
  ctx->peers[ 1 ].channel = NULL;
  FD_TEST( pool_listen_fd( ctx )==-1 );

  fd_failover_channel_fini( ch );
  FD_LOG_NOTICE(( "pass: the listener descriptor comes from the accepting peer only" ));
}

static void
test_footprint( void ) {
  fd_memset( tile, 0, sizeof(tile) );
  tile->failov.member_cnt = 2UL;
  ulong one = scratch_footprint( tile );
  tile->failov.member_cnt = 3UL;
  ulong two = scratch_footprint( tile );
  FD_TEST( one>=sizeof(fd_failover_tile_ctx_t)+fd_failover_channel_footprint() );
  FD_TEST( two>=one+fd_failover_channel_footprint() );
  FD_LOG_NOTICE(( "pass: one channel per peer in the scratch footprint" ));
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  test_pool_layout();
  test_listen_fd();
  test_footprint();
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
