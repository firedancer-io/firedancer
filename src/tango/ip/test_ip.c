#include "fd_ip.h"

#include <stdlib.h>
#include <stdio.h>

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

  /* fetch the arp table */
  fd_ip_arp_fetch( ip );

  fd_ip_arp_entry_t * arp_table     = fd_ip_arp_table_get( ip );
  ulong               arp_table_sz  = ip->cur_num_arp_entries;

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

  /* fetch the route table */
  fd_ip_route_fetch( ip );

  fd_ip_route_entry_t * route_table     = fd_ip_route_table_get( ip );
  ulong                 route_table_sz  = ip->cur_num_route_entries;

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

  fd_ip_leave( ip );

  free( base_mem );

  fd_halt();

  return 0;
}

