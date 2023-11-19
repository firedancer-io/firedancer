#include <tango/ip/fd_ip.h>

int
fd_ip_route_ip_addr( uchar *   out_dst_mac,
                     uint *    out_next_ip_addr,
                     uint *    out_ifindex,
                     fd_ip_t * ip,
                     uint      ip_addr ) {
  uchar dst_mac[ 6 ];
  uint  next_ip_addr;
  uint  ifindex;

  memcpy( out_dst_mac, dst_mac, 6 );
  *out_next_ip_addr = next_ip_addr;
  *out_ifindex      = ifindex;

  int res;
  __CPROVER_assume( (res==FD_IP_MULTICAST) |
                    (res==FD_IP_BROADCAST) |
                    (res==FD_IP_NO_ROUTE ) |
                    (res==FD_IP_PROBE_RQD) |
                    (res==FD_IP_SUCCESS  ) );
  return res;
}
