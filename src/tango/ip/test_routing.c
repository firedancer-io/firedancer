#include "fd_ip.h"

#include <stdlib.h>
#include <stdio.h>


#define TEST_IP( a, b, c, d ) ( ( (uint)(a) << 24U ) | ( (uint)(b) << 16U ) | \
                                ( (uint)(c) <<  8U ) | ( (uint)(d) <<  0U ) )
#define IP_FMT          "%3u.%3u.%3u.%3u"
#define IP_VAR(IP) (((IP)>>030) & 0xffU), \
                   (((IP)>>020) & 0xffU), \
                   (((IP)>>010) & 0xffU), \
                   (((IP)>>000) & 0xffU)
#define MAC_FMT    "%02x:%02x:%02x:%02x:%02x:%02x"
#define MAC_VAR(X) (X)[0], (X)[1], (X)[2], (X)[3], (X)[4], (X)[5]

/* set netmasks on routing entries */
void
route_table_complete( fd_ip_route_entry_t * test_table, ulong test_table_sz ) {
  /* netmasks and dest net ip addrs are calculated from nh_netmask_sz */
  for( long j = 0L; j < (long)test_table_sz; ++j ) {
    fd_nl_route_entry_t * entry = test_table + j;
    entry->dst_netmask = (uint)( 0xffffffff00000000LU >> (ulong)entry->dst_netmask_sz );
  }
}


/* build custom route table */
ulong
build_route_table( fd_ip_route_entry_t * output, ulong output_cap ) {
  /* clear original table */

  fd_memset( output, 0, output_cap * sizeof( output[0] ) );

  /* construct a table */

  uint flags = FD_NL_RT_FLAGS_USED;

  fd_nl_route_entry_t test_table[] = {
    { .dst_ip_addr = TEST_IP( 192, 168, 200,   0 ), .nh_ip_addr = TEST_IP(   0,   0,   0,   0 ), .dst_netmask_sz = 24, .oif = 100, .flags = flags },
    { .dst_ip_addr = TEST_IP( 192, 168,   0,   0 ), .nh_ip_addr = TEST_IP( 200,   1,   1, 101 ), .dst_netmask_sz = 16, .oif = 101, .flags = flags },
    { .dst_ip_addr = TEST_IP(  10,   0,   0,   0 ), .nh_ip_addr = TEST_IP( 200,   1,   1, 102 ), .dst_netmask_sz =  8, .oif = 102, .flags = flags },
    { .dst_ip_addr = TEST_IP(   0,   0,   0,   0 ), .nh_ip_addr = TEST_IP( 200,   1,   1, 103 ), .dst_netmask_sz =  0, .oif = 103, .flags = flags },
  };

  /* number of entries in the test table */
  ulong test_table_sz = sizeof( test_table ) / sizeof( test_table[0] );

  FD_TEST( test_table_sz < output_cap );

  route_table_complete( test_table, test_table_sz );

  /* copy the table into the output */
  for( long j = 0L; j < (long)test_table_sz; ++j ) {
    fd_memcpy( output + j, test_table + j, sizeof( test_table[0] ) );
  }

  return test_table_sz;
}


/* build custom route table */
ulong
build_route_table_1( fd_ip_route_entry_t * output, ulong output_cap ) {
  /* clear original table */

  fd_memset( output, 0, output_cap * sizeof( output[0] ) );

  /* construct a table */

  uint flags = FD_NL_RT_FLAGS_USED;

  fd_nl_route_entry_t test_table[] = {
    { .dst_ip_addr = TEST_IP( 192, 168, 200,   0 ), .nh_ip_addr = TEST_IP(   0,   0,   0,   0 ), .dst_netmask_sz = 24, .oif = 100, .flags = flags },
    { .dst_ip_addr = TEST_IP( 192, 168,   0,   0 ), .nh_ip_addr = TEST_IP( 200,   1,   1, 101 ), .dst_netmask_sz = 16, .oif = 101, .flags = flags },
    { .dst_ip_addr = TEST_IP(  10,   0,   0,   0 ), .nh_ip_addr = TEST_IP( 200,   1,   1, 102 ), .dst_netmask_sz =  8, .oif = 102, .flags = flags },
  };

  /* number of entries in the test table */
  ulong test_table_sz = sizeof( test_table ) / sizeof( test_table[0] );

  FD_TEST( test_table_sz < output_cap );

  route_table_complete( test_table, test_table_sz );

  /* copy the table into the output */
  for( long j = 0L; j < (long)test_table_sz; ++j ) {
    fd_memcpy( output + j, test_table + j, sizeof( test_table[0] ) );
  }

  return test_table_sz;
}

ulong
build_arp_table( fd_ip_arp_entry_t * output, ulong output_cap ) {
  /* construct a table */

  uint flags = FD_NL_ARP_FLAGS_USED;

  /* define all the gateways */
  fd_nl_arp_entry_t test_table[] = {
    { .dst_ip_addr = TEST_IP( 200,   1,   1, 100 ), .mac_addr = {0}, .ifindex =  0, .flags = flags, .state = NUD_REACHABLE },
    { .dst_ip_addr = TEST_IP( 200,   1,   1, 101 ), .mac_addr = {0}, .ifindex =  1, .flags = flags, .state = NUD_REACHABLE },
    { .dst_ip_addr = TEST_IP( 200,   1,   1, 102 ), .mac_addr = {0}, .ifindex =  2, .flags = flags, .state = NUD_REACHABLE },
    { .dst_ip_addr = TEST_IP( 200,   1,   1, 103 ), .mac_addr = {0}, .ifindex =  3, .flags = flags, .state = NUD_REACHABLE },

    { .dst_ip_addr = TEST_IP( 192, 168, 200,   1 ), .mac_addr = {0}, .ifindex =  4, .flags = flags, .state = NUD_REACHABLE },
    { .dst_ip_addr = TEST_IP( 192, 168, 200,   2 ), .mac_addr = {0}, .ifindex =  5, .flags = flags, .state = NUD_REACHABLE },
    { .dst_ip_addr = TEST_IP( 192, 168, 200,   3 ), .mac_addr = {0}, .ifindex =  6, .flags = flags, .state = NUD_REACHABLE },
  };

  /* number of entries in the test table */
  ulong test_table_sz = sizeof( test_table ) / sizeof( test_table[0] );

  FD_TEST( test_table_sz < output_cap );

  /* set some mac addresses */
  for( long j = 0L; j < (long)test_table_sz; ++j ) {
    fd_memcpy( output + j, test_table + j, sizeof( test_table[0] ) );
    test_table[j].mac_addr[0] = 0x42;
    test_table[j].mac_addr[1] = 0x42;
    test_table[j].mac_addr[2] = (uchar)( ( test_table[j].dst_ip_addr >> 030 ) & 0xffU );
    test_table[j].mac_addr[3] = (uchar)( ( test_table[j].dst_ip_addr >> 020 ) & 0xffU );
    test_table[j].mac_addr[4] = (uchar)( ( test_table[j].dst_ip_addr >> 010 ) & 0xffU );
    test_table[j].mac_addr[5] = (uchar)( ( test_table[j].dst_ip_addr >> 000 ) & 0xffU );
  }

  /* copy the table into the output */
  for( long j = 0L; j < (long)test_table_sz; ++j ) {
    fd_memcpy( output + j, test_table + j, sizeof( test_table[0] ) );
  }

  return test_table_sz;
}


#if 0
void
test_route( fd_ip_t * ip,
            uint      ip_addr,
            int       exp_rtn,
            uint      exp_next_ip_addr,
            uint      exp_ifindex,
            uchar *   exp_dst_mac ) {
  uchar dst_mac[6]      = {0};
  uint  next_ip_addr[1] = {0};
  uint  ifindex[1]      = {0};

  int rtn = fd_ip_route_ip_addr( dst_mac, next_ip_addr, ifindex, ip, ip_addr );

  FD_LOG_NOTICE(( "rtn:              " "%d",    rtn                      ));
  FD_LOG_NOTICE(( "dst_mac:          " MAC_FMT, MAC_VAR(dst_mac)         ));
  FD_LOG_NOTICE(( "next_ip_addr:     " IP_FMT,  IP_VAR(next_ip_addr[0])  ));
  FD_LOG_NOTICE(( "ifindex:          " "%u",    ifindex[0]               ));

  FD_LOG_NOTICE(( "exp_rtn:          " "%d",    exp_rtn                  ));
  FD_LOG_NOTICE(( "exp_dst_mac:      " MAC_FMT, MAC_VAR(exp_dst_mac)     ));
  FD_LOG_NOTICE(( "exp_next_ip_addr: " IP_FMT,  IP_VAR(exp_next_ip_addr) ));
  FD_LOG_NOTICE(( "exp_ifindex:      " "%u",    exp_ifindex              ));

  FD_TEST( rtn             == exp_rtn             );
  FD_TEST( memcmp( dst_mac, exp_dst_mac, 6 ) == 0 );
  FD_TEST( next_ip_addr[0] == exp_next_ip_addr    );
  FD_TEST( ifindex[0]      == exp_ifindex         );
}
#else
/* making this a macro helps the error reporting in the failure case */
#define \
test_route( /* fd_ip_t * */ ip,                                                        \
            /* uint      */ ip_addr,                                                   \
            /* int       */ exp_rtn,                                                   \
            /* uint      */ exp_next_ip_addr,                                          \
            /* uint      */ exp_ifindex,                                               \
            /* uchar *   */ exp_dst_mac ) do {                                         \
  uchar dst_mac[6]      = {0};                                                         \
  uint  next_ip_addr[1] = {0};                                                         \
  uint  ifindex[1]      = {0};                                                         \
                                                                                       \
  int rtn = fd_ip_route_ip_addr( dst_mac, next_ip_addr, ifindex, ip, ip_addr );              \
                                                                                       \
  FD_LOG_NOTICE(( "rtn:              " "%d",    rtn                      ));           \
  FD_LOG_NOTICE(( "dst_mac:          " MAC_FMT, MAC_VAR(dst_mac)         ));           \
  FD_LOG_NOTICE(( "next_ip_addr:     " IP_FMT,  IP_VAR(next_ip_addr[0])  ));           \
  FD_LOG_NOTICE(( "ifindex:          " "%u",    ifindex[0]               ));           \
                                                                                       \
  FD_LOG_NOTICE(( "exp_rtn:          " "%d",    exp_rtn                  ));           \
  FD_LOG_NOTICE(( "exp_dst_mac:      " MAC_FMT, MAC_VAR(exp_dst_mac)     ));           \
  FD_LOG_NOTICE(( "exp_next_ip_addr: " IP_FMT,  IP_VAR(exp_next_ip_addr) ));           \
  FD_LOG_NOTICE(( "exp_ifindex:      " "%u",    exp_ifindex              ));           \
                                                                                       \
  FD_TEST( rtn             == exp_rtn             );                                   \
  FD_TEST( memcmp( dst_mac, exp_dst_mac, 6 ) == 0 );                                   \
  FD_TEST( next_ip_addr[0] == exp_next_ip_addr    );                                   \
  FD_TEST( ifindex[0]      == exp_ifindex         );                                   \
} while(0)
#endif


void
test_routes_0( fd_ip_t * ip ) {
  /*
  { .dst_ip_addr = TEST_IP( 192, 168, 200,   0 ), .nh_ip_addr = TEST_IP(   0,   0,   0,   0 ), .dst_netmask_sz = 24, .oif = 100, .flags = flags },
  { .dst_ip_addr = TEST_IP( 192, 168,   1,   0 ), .nh_ip_addr = TEST_IP( 200,   1,   1, 101 ), .dst_netmask_sz = 16, .oif = 101, .flags = flags },
  { .dst_ip_addr = TEST_IP(  10,   1,   1,   0 ), .nh_ip_addr = TEST_IP( 200,   1,   1, 102 ), .dst_netmask_sz =  8, .oif = 102, .flags = flags },
  { .dst_ip_addr = TEST_IP(   0,   0,   0,   0 ), .nh_ip_addr = TEST_IP( 200,   1,   1, 103 ), .dst_netmask_sz =  0, .oif = 103, .flags = flags },

  { .dst_ip_addr = TEST_IP( 200,   1,   1, 100 ), .mac_addr = {0}, .ifindex =  0, .flags = flags },
  { .dst_ip_addr = TEST_IP( 200,   1,   1, 101 ), .mac_addr = {0}, .ifindex =  1, .flags = flags },
  { .dst_ip_addr = TEST_IP( 200,   1,   1, 102 ), .mac_addr = {0}, .ifindex =  2, .flags = flags },
  { .dst_ip_addr = TEST_IP( 200,   1,   1, 103 ), .mac_addr = {0}, .ifindex =  3, .flags = flags },
  */

#define TEST_MAC( a, b, c, d, e, f ) ((uchar[]){a,b,c,d,e,f})
  /* local ip addresses */
  test_route( ip, TEST_IP( 192, 168, 200,   1 ), FD_IP_SUCCESS,   TEST_IP( 192, 168, 200,   1 ), 100, TEST_MAC( 0x42, 0x42, 192, 168, 200,   1 ) );
  test_route( ip, TEST_IP( 192, 168, 200,   2 ), FD_IP_SUCCESS,   TEST_IP( 192, 168, 200,   2 ), 100, TEST_MAC( 0x42, 0x42, 192, 168, 200,   2 ) );
  test_route( ip, TEST_IP( 192, 168, 200,   3 ), FD_IP_SUCCESS,   TEST_IP( 192, 168, 200,   3 ), 100, TEST_MAC( 0x42, 0x42, 192, 168, 200,   3 ) );

  /* local ip addresses - need probe */
  test_route( ip, TEST_IP( 192, 168, 200, 101 ), FD_IP_PROBE_RQD, TEST_IP( 192, 168, 200, 101 ), 100, TEST_MAC(    0,    0,   0,   0,   0,   0 ) );
  test_route( ip, TEST_IP( 192, 168, 200, 102 ), FD_IP_PROBE_RQD, TEST_IP( 192, 168, 200, 102 ), 100, TEST_MAC(    0,    0,   0,   0,   0,   0 ) );
  test_route( ip, TEST_IP( 192, 168, 200, 103 ), FD_IP_PROBE_RQD, TEST_IP( 192, 168, 200, 103 ), 100, TEST_MAC(    0,    0,   0,   0,   0,   0 ) );

  /* routable ip addresses */
  test_route( ip, TEST_IP( 192, 168,   1,   1 ), FD_IP_SUCCESS,   TEST_IP( 200,   1,   1, 101 ), 101, TEST_MAC( 0x42, 0x42, 200,   1,   1, 101 ) );
  test_route( ip, TEST_IP( 192, 168,   1,   2 ), FD_IP_SUCCESS,   TEST_IP( 200,   1,   1, 101 ), 101, TEST_MAC( 0x42, 0x42, 200,   1,   1, 101 ) );
  test_route( ip, TEST_IP( 192, 168,   1,   3 ), FD_IP_SUCCESS,   TEST_IP( 200,   1,   1, 101 ), 101, TEST_MAC( 0x42, 0x42, 200,   1,   1, 101 ) );

  test_route( ip, TEST_IP( 192, 168,   2,   1 ), FD_IP_SUCCESS,   TEST_IP( 200,   1,   1, 101 ), 101, TEST_MAC( 0x42, 0x42, 200,   1,   1, 101 ) );
  test_route( ip, TEST_IP( 192, 168,   2,   2 ), FD_IP_SUCCESS,   TEST_IP( 200,   1,   1, 101 ), 101, TEST_MAC( 0x42, 0x42, 200,   1,   1, 101 ) );
  test_route( ip, TEST_IP( 192, 168,   2,   3 ), FD_IP_SUCCESS,   TEST_IP( 200,   1,   1, 101 ), 101, TEST_MAC( 0x42, 0x42, 200,   1,   1, 101 ) );

  /* .169 doesn't match any of the specific rules */
  test_route( ip, TEST_IP( 192, 169,   2,   1 ), FD_IP_SUCCESS,   TEST_IP( 200,   1,   1, 103 ), 103, TEST_MAC( 0x42, 0x42, 200,   1,   1, 103 ) );
  test_route( ip, TEST_IP( 192, 169,   2,   2 ), FD_IP_SUCCESS,   TEST_IP( 200,   1,   1, 103 ), 103, TEST_MAC( 0x42, 0x42, 200,   1,   1, 103 ) );
  test_route( ip, TEST_IP( 192, 169,   2,   3 ), FD_IP_SUCCESS,   TEST_IP( 200,   1,   1, 103 ), 103, TEST_MAC( 0x42, 0x42, 200,   1,   1, 103 ) );

  test_route( ip, TEST_IP(  10,   1,   1,   1 ), FD_IP_SUCCESS,   TEST_IP( 200,   1,   1, 102 ), 102, TEST_MAC( 0x42, 0x42, 200,   1,   1, 102 ) );
  test_route( ip, TEST_IP(  10,   1,   1,   2 ), FD_IP_SUCCESS,   TEST_IP( 200,   1,   1, 102 ), 102, TEST_MAC( 0x42, 0x42, 200,   1,   1, 102 ) );
  test_route( ip, TEST_IP(  10,   1,   1,   3 ), FD_IP_SUCCESS,   TEST_IP( 200,   1,   1, 102 ), 102, TEST_MAC( 0x42, 0x42, 200,   1,   1, 102 ) );

}


/* test multicast and broadcast routes */
void
test_routes_1( fd_ip_t * ip ) {
  /*
  { .dst_ip_addr = TEST_IP( 192, 168, 200,   0 ), .nh_ip_addr = TEST_IP(   0,   0,   0,   0 ), .dst_netmask_sz = 24, .oif = 100, .flags = flags },
  { .dst_ip_addr = TEST_IP( 192, 168,   1,   0 ), .nh_ip_addr = TEST_IP( 200,   1,   1, 101 ), .dst_netmask_sz = 16, .oif = 101, .flags = flags },
  { .dst_ip_addr = TEST_IP(  10,   1,   1,   0 ), .nh_ip_addr = TEST_IP( 200,   1,   1, 102 ), .dst_netmask_sz =  8, .oif = 102, .flags = flags },
  { .dst_ip_addr = TEST_IP(   0,   0,   0,   0 ), .nh_ip_addr = TEST_IP( 200,   1,   1, 103 ), .dst_netmask_sz =  0, .oif = 103, .flags = flags },

  { .dst_ip_addr = TEST_IP( 200,   1,   1, 100 ), .mac_addr = {0}, .ifindex =  0, .flags = flags },
  { .dst_ip_addr = TEST_IP( 200,   1,   1, 101 ), .mac_addr = {0}, .ifindex =  1, .flags = flags },
  { .dst_ip_addr = TEST_IP( 200,   1,   1, 102 ), .mac_addr = {0}, .ifindex =  2, .flags = flags },
  { .dst_ip_addr = TEST_IP( 200,   1,   1, 103 ), .mac_addr = {0}, .ifindex =  3, .flags = flags },
  */

#define TEST_MAC( a, b, c, d, e, f ) ((uchar[]){a,b,c,d,e,f})
  /* local subnet broadcast ip */
  test_route( ip, TEST_IP( 192, 168, 200, 255 ), FD_IP_BROADCAST, TEST_IP(   0,   0,   0,   0 ), 100, TEST_MAC( 0xff, 0xff, 0xff, 0xff, 0xff, 0xff ) );

  /* routable subnet broadcast ip addresses */
  test_route( ip, TEST_IP( 192, 168, 255, 255 ), FD_IP_SUCCESS,   TEST_IP( 200,   1,   1, 101 ), 101, TEST_MAC( 0x42, 0x42, 200,   1,   1, 101 ) );

  /* .169 doesn't match any of the specific rules */
  test_route( ip, TEST_IP( 192, 169, 255, 255 ), FD_IP_SUCCESS,   TEST_IP( 200,   1,   1, 103 ), 103, TEST_MAC( 0x42, 0x42, 200,   1,   1, 103 ) );

  /* /24 subnet broadcast */
  test_route( ip, TEST_IP(  10, 255, 255, 255 ), FD_IP_SUCCESS,   TEST_IP( 200,   1,   1, 102 ), 102, TEST_MAC( 0x42, 0x42, 200,   1,   1, 102 ) );

  /* multicast */
  test_route( ip, TEST_IP( 239,   1,   2,   3 ), FD_IP_MULTICAST, TEST_IP(   0,   0,   0,   0 ),   0, TEST_MAC( 0x01, 0x00, 0x5e,  1,   2,   3 ) );
}


void
test_routes_2( fd_ip_t * ip ) {
  /*
  { .dst_ip_addr = TEST_IP( 192, 168, 200,   0 ), .nh_ip_addr = TEST_IP(   0,   0,   0,   0 ), .dst_netmask_sz = 24, .oif = 100, .flags = flags },
  { .dst_ip_addr = TEST_IP( 192, 168,   1,   0 ), .nh_ip_addr = TEST_IP( 200,   1,   1, 101 ), .dst_netmask_sz = 16, .oif = 101, .flags = flags },
  { .dst_ip_addr = TEST_IP(  10,   1,   1,   0 ), .nh_ip_addr = TEST_IP( 200,   1,   1, 102 ), .dst_netmask_sz =  8, .oif = 102, .flags = flags },
  { .dst_ip_addr = TEST_IP(   0,   0,   0,   0 ), .nh_ip_addr = TEST_IP( 200,   1,   1, 103 ), .dst_netmask_sz =  0, .oif = 103, .flags = flags },

  { .dst_ip_addr = TEST_IP( 200,   1,   1, 100 ), .mac_addr = {0}, .ifindex =  0, .flags = flags },
  { .dst_ip_addr = TEST_IP( 200,   1,   1, 101 ), .mac_addr = {0}, .ifindex =  1, .flags = flags },
  { .dst_ip_addr = TEST_IP( 200,   1,   1, 102 ), .mac_addr = {0}, .ifindex =  2, .flags = flags },
  { .dst_ip_addr = TEST_IP( 200,   1,   1, 103 ), .mac_addr = {0}, .ifindex =  3, .flags = flags },
  */

  /* local ip addresses */
  test_route( ip, TEST_IP( 192, 168, 200,   1 ), FD_IP_SUCCESS,   TEST_IP( 192, 168, 200,   1 ), 100, TEST_MAC( 0x42, 0x42, 192, 168, 200,   1 ) );
  test_route( ip, TEST_IP( 192, 168, 200,   2 ), FD_IP_SUCCESS,   TEST_IP( 192, 168, 200,   2 ), 100, TEST_MAC( 0x42, 0x42, 192, 168, 200,   2 ) );
  test_route( ip, TEST_IP( 192, 168, 200,   3 ), FD_IP_SUCCESS,   TEST_IP( 192, 168, 200,   3 ), 100, TEST_MAC( 0x42, 0x42, 192, 168, 200,   3 ) );

  /* local ip addresses - need probe */
  test_route( ip, TEST_IP( 192, 168, 200, 101 ), FD_IP_PROBE_RQD, TEST_IP( 192, 168, 200, 101 ), 100, TEST_MAC(    0,    0,   0,   0,   0,   0 ) );
  test_route( ip, TEST_IP( 192, 168, 200, 102 ), FD_IP_PROBE_RQD, TEST_IP( 192, 168, 200, 102 ), 100, TEST_MAC(    0,    0,   0,   0,   0,   0 ) );
  test_route( ip, TEST_IP( 192, 168, 200, 103 ), FD_IP_PROBE_RQD, TEST_IP( 192, 168, 200, 103 ), 100, TEST_MAC(    0,    0,   0,   0,   0,   0 ) );

  /* routable ip addresses */
  test_route( ip, TEST_IP( 192, 168,   1,   1 ), FD_IP_SUCCESS,   TEST_IP( 200,   1,   1, 101 ), 101, TEST_MAC( 0x42, 0x42, 200,   1,   1, 101 ) );
  test_route( ip, TEST_IP( 192, 168,   1,   2 ), FD_IP_SUCCESS,   TEST_IP( 200,   1,   1, 101 ), 101, TEST_MAC( 0x42, 0x42, 200,   1,   1, 101 ) );
  test_route( ip, TEST_IP( 192, 168,   1,   3 ), FD_IP_SUCCESS,   TEST_IP( 200,   1,   1, 101 ), 101, TEST_MAC( 0x42, 0x42, 200,   1,   1, 101 ) );

  test_route( ip, TEST_IP( 192, 168,   2,   1 ), FD_IP_SUCCESS,   TEST_IP( 200,   1,   1, 101 ), 101, TEST_MAC( 0x42, 0x42, 200,   1,   1, 101 ) );
  test_route( ip, TEST_IP( 192, 168,   2,   2 ), FD_IP_SUCCESS,   TEST_IP( 200,   1,   1, 101 ), 101, TEST_MAC( 0x42, 0x42, 200,   1,   1, 101 ) );
  test_route( ip, TEST_IP( 192, 168,   2,   3 ), FD_IP_SUCCESS,   TEST_IP( 200,   1,   1, 101 ), 101, TEST_MAC( 0x42, 0x42, 200,   1,   1, 101 ) );

  /* .169 doesn't match any of the specific rules, and now we don't have a default entry */
  test_route( ip, TEST_IP( 192, 169,   2,   1 ), FD_IP_NO_ROUTE,  TEST_IP(   0,   0,   0,   0 ),   0, TEST_MAC(    0,   0,   0,   0,   0,   0 ) );
  test_route( ip, TEST_IP( 192, 169,   2,   2 ), FD_IP_NO_ROUTE,  TEST_IP(   0,   0,   0,   0 ),   0, TEST_MAC(    0,   0,   0,   0,   0,   0 ) );
  test_route( ip, TEST_IP( 192, 169,   2,   3 ), FD_IP_NO_ROUTE,  TEST_IP(   0,   0,   0,   0 ),   0, TEST_MAC(    0,   0,   0,   0,   0,   0 ) );

  test_route( ip, TEST_IP(  10,   1,   1,   1 ), FD_IP_SUCCESS,   TEST_IP( 200,   1,   1, 102 ), 102, TEST_MAC( 0x42, 0x42, 200,   1,   1, 102 ) );
  test_route( ip, TEST_IP(  10,   1,   1,   2 ), FD_IP_SUCCESS,   TEST_IP( 200,   1,   1, 102 ), 102, TEST_MAC( 0x42, 0x42, 200,   1,   1, 102 ) );
  test_route( ip, TEST_IP(  10,   1,   1,   3 ), FD_IP_SUCCESS,   TEST_IP( 200,   1,   1, 102 ), 102, TEST_MAC( 0x42, 0x42, 200,   1,   1, 102 ) );

}


/* test multicast and broadcast routes */
void
test_routes_3( fd_ip_t * ip ) {
  /*
  { .dst_ip_addr = TEST_IP( 192, 168, 200,   0 ), .nh_ip_addr = TEST_IP(   0,   0,   0,   0 ), .dst_netmask_sz = 24, .oif = 100, .flags = flags },
  { .dst_ip_addr = TEST_IP( 192, 168,   1,   0 ), .nh_ip_addr = TEST_IP( 200,   1,   1, 101 ), .dst_netmask_sz = 16, .oif = 101, .flags = flags },
  { .dst_ip_addr = TEST_IP(  10,   1,   1,   0 ), .nh_ip_addr = TEST_IP( 200,   1,   1, 102 ), .dst_netmask_sz =  8, .oif = 102, .flags = flags },
  { .dst_ip_addr = TEST_IP(   0,   0,   0,   0 ), .nh_ip_addr = TEST_IP( 200,   1,   1, 103 ), .dst_netmask_sz =  0, .oif = 103, .flags = flags },

  { .dst_ip_addr = TEST_IP( 200,   1,   1, 100 ), .mac_addr = {0}, .ifindex =  0, .flags = flags },
  { .dst_ip_addr = TEST_IP( 200,   1,   1, 101 ), .mac_addr = {0}, .ifindex =  1, .flags = flags },
  { .dst_ip_addr = TEST_IP( 200,   1,   1, 102 ), .mac_addr = {0}, .ifindex =  2, .flags = flags },
  { .dst_ip_addr = TEST_IP( 200,   1,   1, 103 ), .mac_addr = {0}, .ifindex =  3, .flags = flags },
  */

#define TEST_MAC( a, b, c, d, e, f ) ((uchar[]){a,b,c,d,e,f})
  /* local subnet broadcast ip */
  test_route( ip, TEST_IP( 192, 168, 200, 255 ), FD_IP_BROADCAST, TEST_IP(   0,   0,   0,   0 ), 100, TEST_MAC( 0xff, 0xff, 0xff, 0xff, 0xff, 0xff ) );

  /* routable subnet broadcast ip addresses */
  test_route( ip, TEST_IP( 192, 168, 255, 255 ), FD_IP_SUCCESS,   TEST_IP( 200,   1,   1, 101 ), 101, TEST_MAC( 0x42, 0x42, 200,   1,   1, 101 ) );

  /* .169 doesn't match any of the specific rules */
  test_route( ip, TEST_IP( 192, 169, 255, 255 ), FD_IP_NO_ROUTE,  TEST_IP(   0,   0,   0,   0 ),   0, TEST_MAC(    0,    0,   0,   0,   0,   0 ) );

  /* /24 subnet broadcast */
  test_route( ip, TEST_IP(  10, 255, 255, 255 ), FD_IP_SUCCESS,   TEST_IP( 200,   1,   1, 102 ), 102, TEST_MAC( 0x42, 0x42, 200,   1,   1, 102 ) );

  /* multicast */
  test_route( ip, TEST_IP( 239,   1,   2,   3 ), FD_IP_MULTICAST, TEST_IP(   0,   0,   0,   0 ),   0, TEST_MAC( 0x01, 0x00, 0x5e,  1,   2,   3 ) );
}


int
main( int argc, char **argv ) {
  fd_boot( &argc, &argv );

  ulong num_arp_entries   = 32;
  ulong num_route_entries = 32;

  ulong ip_footprint = fd_ip_footprint( num_arp_entries, num_route_entries );
  FD_LOG_NOTICE(( "ip_footprint: %lu", ip_footprint ));

  ulong ip_align = fd_ip_align();
  FD_LOG_NOTICE(( "ip_align: %lu", ip_align ));

  void * base_mem = aligned_alloc( ip_align, ip_footprint );
  FD_TEST( base_mem );

  void * mem = fd_ip_new( base_mem, num_arp_entries, num_route_entries );
  FD_TEST( mem );

  fd_ip_t * ip = fd_ip_join( mem );
  FD_TEST( ip );

  fd_ip_arp_entry_t * arp_table = fd_ip_arp_table_get( ip );

  /* construct a custom table */
  ulong arp_table_sz = ip->cur_num_arp_entries = build_arp_table( arp_table, num_arp_entries );

  FD_LOG_NOTICE(( "ARP table:" ));
  for( ulong j = 0L; j < arp_table_sz; ++j ) {
    fd_ip_arp_entry_t * arp_entry = arp_table + j;

    if( arp_entry->flags == 0 ) break;

#define IP_FMT          "%3u.%3u.%3u.%3u"
#define IP_VAR(IP) (((IP)>>030) & 0xffU), \
                   (((IP)>>020) & 0xffU), \
                   (((IP)>>010) & 0xffU), \
                   (((IP)>>000) & 0xffU)

    FD_LOG_NOTICE(( "  " IP_FMT "  %02x:%02x:%02x:%02x:%02x:%02x  %2u  %x",
          IP_VAR(arp_table[j].dst_ip_addr),
          arp_table[j].mac_addr[0],
          arp_table[j].mac_addr[1],
          arp_table[j].mac_addr[2],
          arp_table[j].mac_addr[3],
          arp_table[j].mac_addr[4],
          arp_table[j].mac_addr[5],
          arp_table[j].ifindex,
          arp_table[j].flags ));
  }

  /* route table */

  fd_ip_route_entry_t * route_table = fd_ip_route_table_get( ip );

  /* construct a custom table */
  ulong route_table_sz = ip->cur_num_route_entries
                       = build_route_table( route_table, num_route_entries );

  FD_LOG_NOTICE(( "Routing table:" ));
  for( ulong j = 0L; j < route_table_sz; ++j ) {
    fd_ip_route_entry_t * route_entry = route_table + j;

    if( route_entry->flags == 0 ) break;

    FD_LOG_NOTICE(( "  " IP_FMT "  " IP_FMT "  " IP_FMT "  %2u  " IP_FMT "  %2u  %x",
          IP_VAR(route_table[j].nh_ip_addr),
          IP_VAR(route_table[j].dst_ip_addr),
          IP_VAR(route_table[j].dst_netmask),
          route_table[j].dst_netmask_sz,
          IP_VAR(route_table[j].src_ip_addr),
          route_table[j].oif,
          route_table[j].flags ));
  }

  /* test some routing */

  test_routes_0( ip );
  test_routes_1( ip );

  /* construct another routing table */

  route_table_sz = build_route_table_1( route_table, route_table_sz );

  /* test the new routing */

  test_routes_2( ip );
  test_routes_3( ip );

  /* clean up */

  fd_ip_leave( ip );

  free( base_mem );

  fd_halt();

  return 0;
}
