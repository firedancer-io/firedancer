#include <stdio.h>
#include <linux/rtnetlink.h> /* RT_TABLE_MAIN */
#include <netinet/in.h>      /* AF_INET */
#include "fd_fib4_netlink.h"
#include "../../util/fd_util.h"
#include "../../util/net/fd_ip4.h"

#define DEFAULT_FIB_SZ (1<<20) /* 1 MiB */

static uchar __attribute__((aligned(FD_FIB4_ALIGN)))
fib1_mem[ DEFAULT_FIB_SZ ];

struct test_route_msg {
  struct nlmsghdr nlh;
  struct rtmsg    rtm;
  struct rtattr   dst_attr;
  uint            dst;
  struct rtattr   gw_attr;
  uint            gw;
  struct rtattr   oif_attr;
  uint            oif;
};

static void
test_delta_update( void ) {
  ulong const route_max       = 16UL;
  ulong const route_peer_max  = 16UL;
  ulong const route_peer_seed = 123456UL;
  fd_fib4_t fib[1];
  FD_TEST( fd_fib4_join( fib, fd_fib4_new( fib1_mem, route_max, route_peer_max, route_peer_seed ) ) );

  uint const subnet = FD_IP4_ADDR( 192, 0, 2, 0 );
  uint const peer   = FD_IP4_ADDR( 192, 0, 2, 9 );
  uint const gw     = FD_IP4_ADDR( 192, 0, 2, 1 );
  fd_fib4_hop_t subnet_hop = { .rtype=FD_FIB4_RTYPE_UNICAST, .if_idx=1U };
  FD_TEST( fd_fib4_insert( fib, subnet, 24, 0U, &subnet_hop ) );

  struct test_route_msg msg = {
    .nlh = {
      .nlmsg_len  = sizeof(struct test_route_msg),
      .nlmsg_type = RTM_NEWROUTE,
    },
    .rtm = {
      .rtm_family  = AF_INET,
      .rtm_dst_len = 32U,
      .rtm_table   = RT_TABLE_MAIN,
      .rtm_type    = RTN_UNICAST,
    },
    .dst_attr = { .rta_len=RTA_LENGTH( sizeof(uint) ), .rta_type=RTA_DST     },
    .dst      = peer,
    .gw_attr  = { .rta_len=RTA_LENGTH( sizeof(uint) ), .rta_type=RTA_GATEWAY },
    .gw       = gw,
    .oif_attr = { .rta_len=RTA_LENGTH( sizeof(uint) ), .rta_type=RTA_OIF     },
    .oif      = 7U,
  };

  FD_TEST( fd_fib4_netlink_apply_message( fib, &msg.nlh, RT_TABLE_MAIN ) );
  FD_TEST( fd_fib4_cnt( fib )==3UL );
  fd_fib4_hop_t hop = fd_fib4_lookup( fib, peer, 0UL );
  FD_TEST( hop.rtype==FD_FIB4_RTYPE_UNICAST && hop.ip4_gw==gw && hop.if_idx==7U );

  msg.nlh.nlmsg_type = RTM_DELROUTE;
  FD_TEST( fd_fib4_netlink_apply_message( fib, &msg.nlh, RT_TABLE_MAIN ) );
  FD_TEST( fd_fib4_cnt( fib )==2UL );
  hop = fd_fib4_lookup( fib, peer, 0UL );
  FD_TEST( hop.rtype==FD_FIB4_RTYPE_UNICAST && hop.if_idx==1U );

  msg.rtm.rtm_dst_len = 24U;
  FD_TEST( !fd_fib4_netlink_apply_message( fib, &msg.nlh, RT_TABLE_MAIN ) );
  msg.rtm.rtm_table = RT_TABLE_LOCAL;
  FD_TEST( fd_fib4_netlink_apply_message( fib, &msg.nlh, RT_TABLE_MAIN ) );

  fd_fib4_delete( fd_fib4_leave( fib ) );
}

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

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_delta_update();

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
