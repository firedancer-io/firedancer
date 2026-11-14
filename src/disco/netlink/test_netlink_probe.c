#define _GNU_SOURCE
#include "fd_netlink_tile_private.h"
#include <sys/socket.h>
#include <errno.h>
static long test_now;
static ulong send_cnt;
static int send_error;
static long test_tickcount( void ) { return test_now; }
static ssize_t
test_sendto( int fd, void const * buf, size_t len, int flags, struct sockaddr const * addr, socklen_t addr_len ) {
  (void)fd; (void)buf; (void)len; (void)flags; (void)addr; (void)addr_len;
  send_cnt++;
  if( send_error ) { errno=send_error; return -1; }
  return 0;
}
/* Real solicit path, deterministic clock, no sockets or packets. */
#undef fd_tickcount
#define fd_tickcount test_tickcount
#define sendto test_sendto
#include "fd_netlink_tile.c"
#include "../../waltz/neigh/fd_neigh4_probe.c"
#undef sendto
#undef fd_tickcount
static fd_netlink_tile_ctx_t ctx[1];
static uchar map_mem[4096] __attribute__((aligned(128)));
#define SECOND (1L<<28)
static void
reset( void ) {
  fd_memset( ctx, 0, sizeof(*ctx) );
  FD_TEST( fd_neigh4_hmap_footprint( 64UL )<=sizeof(map_mem) );
  FD_TEST( fd_neigh4_hmap_new( map_mem, 64UL, 1UL ) );
  FD_TEST( fd_neigh4_hmap_join( ctx->neigh4, fd_type_pun( map_mem ), 64UL, 16UL, 1UL ) );
  ctx->neigh4_ifidx=7U;
  test_now=100L*SECOND;
  *ctx->prober=(fd_neigh4_prober_t){ .sock_fd=-1, .probe_delay=15L*SECOND,
    .rate_limit={ .ts=test_now, .rate=3.f/(float)SECOND, .burst=128.f, .balance=128.f } };
  send_cnt=0UL; send_error=EHOSTUNREACH;
}
static void
solicit( uint ip ) {
  after_frag( ctx, 0UL, 0UL, fd_netlink_neigh4_solicit_sig( ip, 7U ), 0UL, 0UL, 0UL, NULL );
}
int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );
  reset(); solicit( 1U );
  FD_TEST( send_cnt==1UL );
  FD_TEST( !fd_neigh4_hmap_query( ctx->neigh4, &(uint){1U} ) );
  test_now+=SECOND; solicit( 1U );
  FD_TEST( send_cnt==1UL );
  FD_TEST( ctx->prober->local_rate_limited_cnt==1UL );
  FD_TEST( ctx->metrics.neigh_probe[ FD_METRICS_ENUM_NEIGHBOR_PROBE_RESULT_V_SEND_FAILED_IDX ]==1UL );
  FD_TEST( !fd_neigh4_hmap_query( ctx->neigh4, &(uint){1U} ) );
  /* Suppressed requests neither consume tokens nor extend the deadline. */
  float balance=ctx->prober->rate_limit.balance;
  test_now=115L*SECOND-1L; solicit( 1U );
  FD_TEST( send_cnt==1UL && ctx->prober->rate_limit.balance==balance );
  test_now++; solicit( 1U );
  FD_TEST( send_cnt==2UL );

  /* Successful probes retain a placeholder only until kernel removal.
     The independent history must survive that removal too. */
  reset(); send_error=0; solicit( 2U );
  fd_neigh4_entry_t * ele=fd_neigh4_hmap_update( ctx->neigh4, &(uint){2U} );
  FD_TEST( ele );
  solicit( 2U ); FD_TEST( send_cnt==1UL );
  FD_TEST( ctx->metrics.neigh_probe[ FD_METRICS_ENUM_NEIGHBOR_PROBE_RESULT_V_SENT_IDX ]==1UL );
  FD_TEST( ctx->metrics.neigh_probe[ FD_METRICS_ENUM_NEIGHBOR_PROBE_RESULT_V_IN_FLIGHT_IDX ]==1UL );
  fd_neigh4_hmap_remove( ctx->neigh4, ele );
  solicit( 2U ); FD_TEST( send_cnt==1UL );
  FD_TEST( !fd_neigh4_hmap_query( ctx->neigh4, &(uint){2U} ) );

  /* Global denial must not consume history or poison a fresh entry. */
  reset(); ctx->prober->rate_limit.balance=0.f;
  for( uint ip=1U; ip<=1000U; ip++ ) solicit( ip );
  FD_TEST( !send_cnt && ctx->prober->global_rate_limited_cnt==1000UL );
  for( ulong i=0UL; i<FD_NEIGH4_PROBE_HISTORY_MAX; i++ ) FD_TEST( !ctx->prober->history[ i ].valid );
  for( ulong i=0UL; i<64UL; i++ ) FD_TEST( fd_neigh4_hmap_ele_is_free( fd_neigh4_hmap_ele0( ctx->neigh4 )+i ) );
  test_now+=SECOND; solicit( 1U ); FD_TEST( send_cnt==1UL );

  /* Preserve the real 128-packet burst and 3/s refill.  Failure cleanup
     keeps the smaller neighbor map empty under distinct-IP pressure. */
  reset();
  for( uint ip=1U; ip<=128U; ip++ ) solicit( ip );
  FD_TEST( send_cnt==128UL );
  solicit( 129U ); FD_TEST( send_cnt==128UL );
  test_now+=SECOND;
  for( uint ip=129U; ip<=132U; ip++ ) solicit( ip );
  FD_TEST( send_cnt==131UL );
  for( ulong i=0UL; i<64UL; i++ ) FD_TEST( fd_neigh4_hmap_ele_is_free( fd_neigh4_hmap_ele0( ctx->neigh4 )+i ) );

  /* A free early slot must not hide an active matching later slot. */
  reset(); solicit( 1U ); solicit( 2U );
  ctx->prober->history[ 0 ].valid=0;
  solicit( 2U ); FD_TEST( send_cnt==2UL );

  /* Defensive saturation cannot evict active history or spend tokens.
     IP zero is not an empty-history sentinel (test below the map API). */
  reset();
  for( ulong i=0UL; i<FD_NEIGH4_PROBE_HISTORY_MAX; i++ ) {
    ctx->prober->history[ i ].ip4_addr=(uint)i;
    ctx->prober->history[ i ].valid=1;
    ctx->prober->history[ i ].suppress_until=test_now+15L*SECOND;
  }
  fd_neigh4_entry_t entry={0};
  FD_TEST( fd_neigh4_probe_rate_limited( ctx->prober, &entry, 0U, test_now )==-1 );
  FD_TEST( ctx->prober->local_rate_limited_cnt==1UL );
  FD_TEST( fd_neigh4_probe_rate_limited( ctx->prober, &entry, 1000U, test_now )==-1 );
  FD_TEST( !send_cnt && ctx->prober->rate_limit.balance==128.f );
  FD_TEST( ctx->prober->global_rate_limited_cnt==1UL );
  for( ulong i=0UL; i<FD_NEIGH4_PROBE_HISTORY_MAX; i++ ) FD_TEST( ctx->prober->history[ i ].ip4_addr==(uint)i );
  test_now+=15L*SECOND;
  FD_TEST( fd_neigh4_probe_rate_limited( ctx->prober, &entry, 1000U, test_now )==EHOSTUNREACH );
  FD_TEST( send_cnt==1UL );
  FD_LOG_NOTICE(( "pass" )); fd_halt(); return 0;
}
