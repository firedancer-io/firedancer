#include "fd_netlink.h"

#include <stdlib.h>


#define TEST_IP( a, b, c, d ) ( ( (uint)(a) << 24U ) | ( (uint)(b) << 16U ) | \
                                ( (uint)(c) <<  8U ) | ( (uint)(d) <<  0U ) )

void
test_route_query( fd_nl_route_entry_t * test_table,
                  ulong                 test_table_sz,
                  uint                  ip_addr,
                  long                  expected_idx ) {
  fd_nl_route_entry_t * result = fd_nl_route_query( test_table, test_table_sz, ip_addr );

  long idx = result == NULL ? -1 : (long)( result - test_table );

  FD_LOG_NOTICE(( "route test %08x matched idx %ld  %s", ip_addr, idx,
        idx == expected_idx ? "PASSED" : "FAILED" ));
}

void
test_arp_query( fd_nl_arp_entry_t * arp_table,
                ulong               arp_table_sz,
                uint                ip_addr,
                long                expected_idx ) {
  fd_nl_arp_entry_t * result = fd_nl_arp_query( arp_table, arp_table_sz, ip_addr );

  long idx = result == NULL ? -1 : (long)( result - arp_table );

  FD_LOG_NOTICE(( "arp test %08x matched idx %ld  %s", ip_addr, idx,
        idx == expected_idx ? "PASSED" : "FAILED" ));
}


void
test_routes( void ) {
  /* construct a table and test the entries directly */

  uint flags = FD_NL_RT_FLAGS_USED;

  fd_nl_route_entry_t test_table[] = {
    { .nh_ip_addr = TEST_IP(  10,   1,   2, 2 ), .dst_netmask_sz = 31, .oif =  0, .flags = flags },
    { .nh_ip_addr = TEST_IP(  10,   1,   2, 1 ), .dst_netmask_sz = 24, .oif =  1, .flags = flags },
    { .nh_ip_addr = TEST_IP(  10,   1,   3, 1 ), .dst_netmask_sz = 24, .oif =  2, .flags = flags },
    { .nh_ip_addr = TEST_IP(  10,   1, 128, 1 ), .dst_netmask_sz = 24, .oif =  3, .flags = flags },
    { .nh_ip_addr = TEST_IP(  10,   1,   1, 1 ), .dst_netmask_sz = 16, .oif =  4, .flags = flags },
    { .nh_ip_addr = TEST_IP(  10,   2,   2, 2 ), .dst_netmask_sz = 16, .oif =  5, .flags = flags },
    { .nh_ip_addr = TEST_IP(  10, 128,   8, 3 ), .dst_netmask_sz = 16, .oif =  6, .flags = flags },
    { .nh_ip_addr = TEST_IP(  10,   1,   1, 5 ), .dst_netmask_sz =  8, .oif =  7, .flags = flags },
    { .nh_ip_addr = TEST_IP(  15,   1,   2, 2 ), .dst_netmask_sz =  8, .oif =  8, .flags = flags },
    { .nh_ip_addr = TEST_IP( 128,   1,   8, 3 ), .dst_netmask_sz =  8, .oif =  9, .flags = flags },
    { .nh_ip_addr = TEST_IP( 191,   1,   8, 3 ), .dst_netmask_sz =  0, .oif = 10, .flags = flags },
  };

  /* number of entries in the test table */
  ulong test_table_sz = sizeof( test_table ) / sizeof( test_table[0] );

  /* netmasks and dest net ip addrs are calculated from nh_netmask_sz */
  for( long j = 0L; j < (long)test_table_sz; ++j ) {
    fd_nl_route_entry_t * entry = test_table + j;
    entry->dst_netmask = (uint)( 0xffffffff00000000LU >> (ulong)entry->dst_netmask_sz );
    entry->dst_ip_addr = entry->nh_ip_addr & entry->dst_netmask;
  }

  test_route_query( test_table, test_table_sz,   TEST_IP(  10,   1,   2,   2 ),  0 );
  test_route_query( test_table, test_table_sz,   TEST_IP( 192, 168,   1,   2 ), 10 );
  test_route_query( test_table, test_table_sz-1, TEST_IP( 192, 168,   1,   2 ), -1 );

  test_route_query( test_table, test_table_sz,   TEST_IP(  10,   1,   2,   2 ),  0 );
  test_route_query( test_table, test_table_sz,   TEST_IP(  10,   1,   2,   3 ),  0 );

  test_route_query( test_table, test_table_sz,   TEST_IP(  10,   1,   2,   4 ),  1 );
  test_route_query( test_table, test_table_sz,   TEST_IP(  10,   1,   2,   5 ),  1 );

  test_route_query( test_table, test_table_sz,   TEST_IP(  10,   1,   3,   1 ),  2 );
  test_route_query( test_table, test_table_sz,   TEST_IP(  10,   1,   3,   2 ),  2 );
  test_route_query( test_table, test_table_sz,   TEST_IP(  10,   1,   3,   3 ),  2 );
  test_route_query( test_table, test_table_sz,   TEST_IP(  10,   1,   3, 127 ),  2 );

  test_route_query( test_table, test_table_sz,   TEST_IP(  10,   1,   3, 129 ),  2 );
  test_route_query( test_table, test_table_sz,   TEST_IP(  10,   1,   3, 130 ),  2 );
  test_route_query( test_table, test_table_sz,   TEST_IP(  10,   1,   3, 131 ),  2 );
  test_route_query( test_table, test_table_sz,   TEST_IP(  10,   1,   3, 255 ),  2 );

  test_route_query( test_table, test_table_sz,   TEST_IP(  10,   1, 127,   1 ),  4 );
  test_route_query( test_table, test_table_sz,   TEST_IP(  10,   1, 128,   1 ),  3 );
  test_route_query( test_table, test_table_sz,   TEST_IP(  10,   1, 129,   1 ),  4 );

  test_route_query( test_table, test_table_sz,   TEST_IP(  10,   2,   1,   1 ),  5 );

  test_route_query( test_table, test_table_sz,   TEST_IP(  10,   3,   1,   1 ),  7 );
  test_route_query( test_table, test_table_sz,   TEST_IP(  10, 254,   1,   1 ),  7 );
  test_route_query( test_table, test_table_sz,   TEST_IP(  10, 255,   1,   1 ),  7 );

  test_route_query( test_table, test_table_sz,   TEST_IP(  10, 127,   1,   1 ),  7 );
  test_route_query( test_table, test_table_sz,   TEST_IP(  10, 128,   1,   1 ),  6 );
  test_route_query( test_table, test_table_sz,   TEST_IP(  10, 129,   1,   1 ),  7 );

  test_route_query( test_table, test_table_sz,   TEST_IP(  14,   1,   1,  91 ), 10 );
  test_route_query( test_table, test_table_sz,   TEST_IP(  15,   1,   1,  91 ),  8 );
  test_route_query( test_table, test_table_sz,   TEST_IP(  16,   1,   1,  91 ), 10 );

}

void
test_arp_queries( void ) {
  /* construct a table and test the entries directly */

  uint flags = FD_NL_ARP_FLAGS_USED;

  fd_nl_arp_entry_t test_table[] = {
    { .dst_ip_addr = TEST_IP(  10,   1,   2, 2 ), .mac_addr = {0}, .ifindex =  0, .flags = flags },
    { .dst_ip_addr = TEST_IP(  10,   1,   2, 1 ), .mac_addr = {0}, .ifindex =  1, .flags = flags },
    { .dst_ip_addr = TEST_IP(  10,   1,   3, 1 ), .mac_addr = {0}, .ifindex =  2, .flags = flags },
    { .dst_ip_addr = TEST_IP(  10,   1, 128, 1 ), .mac_addr = {0}, .ifindex =  3, .flags = flags },
    { .dst_ip_addr = TEST_IP(  10,   1,   1, 1 ), .mac_addr = {0}, .ifindex =  4, .flags = flags },
    { .dst_ip_addr = TEST_IP(  10,   2,   2, 2 ), .mac_addr = {0}, .ifindex =  5, .flags = flags },
    { .dst_ip_addr = TEST_IP(  10, 128,   8, 3 ), .mac_addr = {0}, .ifindex =  6, .flags = flags },
    { .dst_ip_addr = TEST_IP(  10,   1,   1, 5 ), .mac_addr = {0}, .ifindex =  7, .flags = flags },
    { .dst_ip_addr = TEST_IP(  15,   1,   2, 2 ), .mac_addr = {0}, .ifindex =  8, .flags = flags },
    { .dst_ip_addr = TEST_IP( 128,   1,   8, 3 ), .mac_addr = {0}, .ifindex =  9, .flags = flags },
    { .dst_ip_addr = TEST_IP( 191,   1,   8, 3 ), .mac_addr = {0}, .ifindex = 10, .flags = flags },
  };

  /* number of entries in the test table */
  ulong test_table_sz = sizeof( test_table ) / sizeof( test_table[0] );

  test_arp_query( test_table, test_table_sz,   TEST_IP(  10,   1,   2,   2 ),  0 );
  test_arp_query( test_table, test_table_sz,   TEST_IP(  10,   1,   2,   1 ),  1 );
  test_arp_query( test_table, test_table_sz,   TEST_IP(  10,   1,   3,   1 ),  2 );
  test_arp_query( test_table, test_table_sz,   TEST_IP(  10,   1, 128,   1 ),  3 );

  test_arp_query( test_table, test_table_sz,   TEST_IP( 192, 168,   1,   1 ), -1 );
  test_arp_query( test_table, test_table_sz,   TEST_IP( 192, 168,   1,   2 ), -1 );
  test_arp_query( test_table, test_table_sz,   TEST_IP( 192, 168,   1,   2 ), -1 );
  test_arp_query( test_table, test_table_sz,   TEST_IP( 192, 168,   2,   2 ), -1 );
}



int
main( int argc, char **argv ) {
  fd_boot( &argc, &argv );

  fd_nl_t nl[1];

  if( fd_nl_init( nl, 1234U ) ) {
    FD_LOG_ERR(( "Unable to initialize netlink fd_nl_init" ));
    exit(1);
  }

#define ROUTE_TABLE_CAP 32
  fd_nl_route_entry_t route_table[ROUTE_TABLE_CAP];
  ulong               route_table_cap = ROUTE_TABLE_CAP;

  if( 1 ) {
    long route_num_entries = fd_nl_load_route_table( nl, route_table, route_table_cap );

    FD_LOG_NOTICE(( "number of routing entries: %ld", route_num_entries ));

    for( long j = 0L; j < route_num_entries; ++j ) {
      FD_LOG_NOTICE(( "  route entry: %08x  %08x  %08x  %2u  %08x %u",
            route_table[j].nh_ip_addr,
            route_table[j].dst_ip_addr,
            route_table[j].dst_netmask,
            route_table[j].dst_netmask_sz,
            route_table[j].src_ip_addr,
            route_table[j].oif ));
    }
  }


#define ARP_TABLE_CAP 32
  fd_nl_arp_entry_t arp_table[ARP_TABLE_CAP];
  ulong             arp_table_cap = ARP_TABLE_CAP;

  long arp_num_entries = fd_nl_load_arp_table( nl, arp_table, arp_table_cap );

  FD_LOG_NOTICE(( "number of arp entries: %ld", arp_num_entries ));

  for( long j = 0L; j < arp_num_entries; ++j ) {
    FD_LOG_NOTICE(( "  arp entry: %08x  %02x:%02x:%02x:%02x:%02x:%02x  %u",
          arp_table[j].dst_ip_addr,
          arp_table[j].mac_addr[0],
          arp_table[j].mac_addr[1],
          arp_table[j].mac_addr[2],
          arp_table[j].mac_addr[3],
          arp_table[j].mac_addr[4],
          arp_table[j].mac_addr[5],
          arp_table[j].ifindex ));
  }


  test_routes();

  test_arp_queries();

  fd_halt();

  return 0;
}

