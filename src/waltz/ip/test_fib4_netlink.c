#include <stdio.h>
#include <sys/socket.h> /* AF_INET */
#include <linux/rtnetlink.h> /* RT_TABLE_MAIN */
#include "fd_fib4_netlink.h"
#include "../../util/fd_util.h"
#include "../../util/net/fd_ip4.h"

#define DEFAULT_FIB_SZ (1<<20) /* 1 MiB */

static uchar __attribute__((aligned(FD_FIB4_ALIGN)))
fib1_mem[ DEFAULT_FIB_SZ ];

/* Translate local and main tables and dump them to stdout */

void
dump_table( fd_netlink_t * netlink,
            uint           table ) {
  ulong const route_max           = 256UL;
  ulong const route_peer_max      = 256UL;
  ulong const route_peer_seed     = 123456UL;
  FD_TEST( fd_fib4_footprint( route_max, route_peer_max )<=sizeof(fib1_mem) );
  fd_fib4_t fib[1];
  FD_TEST( fd_fib4_join( fib, fd_fib4_new( fib1_mem, route_max, route_peer_max, route_peer_seed ) ) );

  int load_err = fd_fib4_netlink_load_table( fib, netlink, table );
  if( FD_UNLIKELY( load_err ) ) {
    FD_LOG_WARNING(( "Failed to load table %u (%i-%s)", table, load_err, fd_fib4_netlink_strerror( load_err ) ));
    return;
  }

  fprintf( stderr, "# ip route show table %u\n", table );
  fd_log_flush();
  fd_fib4_fprintf( fib, stderr );
  fputs( "\n", stderr );

  fd_fib4_delete( fd_fib4_leave( fib ) );
}

/* Translate a synthetic route message of the given type */

static fd_iproute_msg_t
translate_rtype( uchar rtm_type ) {
  struct {
    struct nlmsghdr nlh;
    struct rtmsg    rtm;
    struct rtattr   rta_dst;
    uint            dst;
  } msg = {
    .nlh = { .nlmsg_len = sizeof(msg), .nlmsg_type = RTM_NEWROUTE },
    .rtm = { .rtm_family = AF_INET, .rtm_dst_len = 16, .rtm_table = RT_TABLE_MAIN, .rtm_type = rtm_type },
    .rta_dst = { .rta_len = RTA_LENGTH( sizeof(uint) ), .rta_type = RTA_DST },
    .dst = FD_IP4_ADDR( 10,20,0,0 )
  };
  FD_STATIC_ASSERT( sizeof(msg)==NLMSG_LENGTH( sizeof(struct rtmsg) )+RTA_LENGTH( sizeof(uint) ), layout );
  fd_iproute_msg_t route;
  FD_TEST( fd_fib4_netlink_translate( &msg.nlh, RT_TABLE_MAIN, &route )==1 );
  FD_TEST( route.dst_addr==FD_IP4_ADDR( 10,20,0,0 ) );
  FD_TEST( route.prefix==16 );
  FD_TEST( route.op==FD_IPROUTE_OP_UPSERT );
  return route;
}

static void
test_translate_rtype( void ) {
  fd_iproute_msg_t route;

  route = translate_rtype( RTN_UNICAST );
  FD_TEST( route.hop.rtype==FD_FIB4_RTYPE_UNICAST );
  FD_TEST( !( route.hop.flags & FD_FIB4_FLAG_RTYPE_UNSUPPORTED ) );

  route = translate_rtype( RTN_BLACKHOLE );
  FD_TEST( route.hop.rtype==FD_FIB4_RTYPE_BLACKHOLE );
  FD_TEST( !( route.hop.flags & FD_FIB4_FLAG_RTYPE_UNSUPPORTED ) );

  /* Throw routes must continue lookup in the next table */
  route = translate_rtype( RTN_THROW );
  FD_TEST( route.hop.rtype==FD_FIB4_RTYPE_THROW );
  FD_TEST( !( route.hop.flags & FD_FIB4_FLAG_RTYPE_UNSUPPORTED ) );

  route = translate_rtype( RTN_UNREACHABLE );
  FD_TEST( route.hop.rtype==FD_FIB4_RTYPE_BLACKHOLE );
  FD_TEST( route.hop.flags & FD_FIB4_FLAG_RTYPE_UNSUPPORTED );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_translate_rtype();

  fd_netlink_t _netlink[1];
  fd_netlink_t * netlink = fd_netlink_init( _netlink, 42U );
  FD_TEST( netlink );

  FD_LOG_NOTICE(( "Dumping local and main routing tables to stderr\n" ));
  fd_log_flush();
  dump_table( netlink, RT_TABLE_LOCAL );
  dump_table( netlink, RT_TABLE_MAIN  );
  fflush( stderr );

  fd_netlink_fini( netlink );

  fd_halt();
  return 0;
}
