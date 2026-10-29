#include <stdio.h>
#include <sys/socket.h>
#include <linux/rtnetlink.h> /* RT_TABLE_MAIN */
#include "fd_fib4_netlink.h"
#include "../../util/fd_util.h"

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

static void
test_translate_attributes( void ) {
  ushort const types[] = { RTA_DST, RTA_TABLE, RTA_GATEWAY, RTA_OIF, RTA_PREFSRC, RTA_PRIORITY };
  for( ulong i=0UL; i<sizeof(types)/sizeof(types[0]); i++ ) for( uint len=0U; len<=5U; len++ ) {
    struct {
      struct nlmsghdr nlh;
      struct rtmsg rtm;
      struct rtattr rta;
      uchar data[8];
    } msg = {
      .nlh = { .nlmsg_type=RTM_NEWROUTE },
      .rtm = { .rtm_family=AF_INET, .rtm_table=RT_TABLE_MAIN, .rtm_type=RTN_UNICAST, .rtm_dst_len=24 },
      .rta = { .rta_type=types[i], .rta_len=(ushort)RTA_LENGTH( len ) },
    };
    msg.nlh.nlmsg_len = (uint)(NLMSG_LENGTH( sizeof(struct rtmsg) )+RTA_ALIGN( msg.rta.rta_len ));
    uint val = types[i]==RTA_TABLE ? RT_TABLE_MAIN : 7U;
    fd_memcpy( msg.data, &val, sizeof(val) );
    fd_iproute_msg_t route;
    fd_memset( &route, 0xa5, sizeof(route) );
    fd_iproute_msg_t saved = route;
    int result = fd_fib4_netlink_translate( &msg.nlh, RT_TABLE_MAIN, &route );
    FD_TEST( result==(len==4U) );
    if( !result ) FD_TEST( !memcmp( &route, &saved, sizeof(route) ) );
    else {
      FD_TEST( route.op==FD_IPROUTE_OP_UPSERT );
      FD_TEST( route.table_id==RT_TABLE_MAIN );
      FD_TEST( route.prefix==(types[i]==RTA_DST ? 24U : 0U) );
      if( types[i]==RTA_TABLE ) {
        msg.rtm.rtm_table = RT_TABLE_UNSPEC;
        FD_TEST( !fd_fib4_netlink_translate( &msg.nlh, RT_TABLE_LOCAL, &route ) );
        FD_TEST( fd_fib4_netlink_translate( &msg.nlh, RT_TABLE_MAIN, &route ) );
      }
    }
  }

  struct { struct nlmsghdr nlh; struct rtmsg rtm; } msg = {
    .nlh = { .nlmsg_type=RTM_NEWROUTE, .nlmsg_len=NLMSG_LENGTH( sizeof(struct rtmsg) ) },
    .rtm = { .rtm_family=AF_INET, .rtm_table=RT_TABLE_MAIN, .rtm_type=RTN_UNICAST },
  };
  fd_iproute_msg_t route;
  FD_TEST( fd_fib4_netlink_translate( &msg.nlh, RT_TABLE_MAIN, &route ) );
  FD_TEST( !route.dst_addr && !route.prefix );
  FD_TEST( !fd_fib4_netlink_translate( &msg.nlh, RT_TABLE_LOCAL, &route ) );
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_translate_attributes();

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
