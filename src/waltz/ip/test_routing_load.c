#include "fd_ip.h"

#include <stdlib.h>
#include <stdio.h>
#include <time.h>


#define TEST_IP( a, b, c, d ) ( ( (uint)(a) << 24U ) | ( (uint)(b) << 16U ) | \
                                ( (uint)(c) <<  8U ) | ( (uint)(d) <<  0U ) )
#define IP_FMT          "%3u.%3u.%3u.%3u"
#define IP_VAR(IP) (((IP)>>030) & 0xffU), \
                   (((IP)>>020) & 0xffU), \
                   (((IP)>>010) & 0xffU), \
                   (((IP)>>000) & 0xffU)
#define MAC_FMT    "%02x:%02x:%02x:%02x:%02x:%02x"
#define MAC_VAR(X) (X)[0], (X)[1], (X)[2], (X)[3], (X)[4], (X)[5]


int
main( int argc, char **argv ) {
  fd_boot( &argc, &argv );

  ulong num_arp_entries   = 2048;
  ulong num_route_entries = 512;

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

  /* route table */

  fd_ip_route_entry_t * route_table = fd_ip_route_table_get( ip );

  fd_nl_t * netlink = fd_ip_netlink_get( ip );

  /* construct a custom table */
  long rtn = fd_nl_load_route_table( netlink, route_table, num_route_entries );

  if( rtn < 0 ) {
    FD_LOG_ERR(( "Unable to load routning table" ));
  }

  if( rtn == 0 ) { 
    FD_LOG_ERR(( "No routing table entries returned" ));
  }

  ulong route_table_sz = ip->cur_num_route_entries = (ulong)rtn;

      uint rqd0 = FD_NL_RT_FLAGS_DST_IP_ADDR |
                  FD_NL_RT_FLAGS_DST_NETMASK |
                  FD_NL_RT_FLAGS_OIF;
      uint rqd1 = FD_NL_RT_FLAGS_NH_IP_ADDR  |
                  FD_NL_RT_FLAGS_OIF;

  FD_LOG_NOTICE(( "Routing table:" ));
  for( ulong j = 0L; j < route_table_sz; ++j ) {
    fd_ip_route_entry_t * route_entry = route_table + j;

    if( route_entry->flags == 0 ) break;

      uint rqd_mask = rqd0 | rqd1;
      uint flags = route_table[j].flags & rqd_mask;

    FD_LOG_NOTICE(( "  " IP_FMT "  " IP_FMT "  " IP_FMT "  %2u  " IP_FMT "  %2u  %x  %x  %x  %x",
          IP_VAR(route_table[j].nh_ip_addr),
          IP_VAR(route_table[j].dst_ip_addr),
          IP_VAR(route_table[j].dst_netmask),
          route_table[j].dst_netmask_sz,
          IP_VAR(route_table[j].src_ip_addr),
          route_table[j].oif,
          route_table[j].flags,
          (uint)rqd0,
          (uint)rqd1,
          (uint)flags ));
  }

  /* try a few times */

  ulong ITER_CNT = 50;

  FD_LOG_NOTICE(( "Running %lu times...", ITER_CNT ));

  for( ulong j = 0; j < ITER_CNT; ++j ) {
    /* load routing table */
    fd_ip_route_fetch( ip );

    if( ip->cur_num_route_entries == 0 ) {
      FD_LOG_ERR(( "no routing table entries" ));
    }

    fd_ip_arp_fetch( ip );

    if( ip->cur_num_arp_entries == 0 ) {
      FD_LOG_ERR(( "no arp table entries" ));
    }

    FD_LOG_WARNING(( "ip->arp_table_idx: %u  ip->route_table_idx: %u",
          ip->arp_table_idx, ip->route_table_idx ));
  }

  /* clean up */

  fd_ip_leave( ip );

  free( base_mem );

  fd_halt();

  return 0;
}
