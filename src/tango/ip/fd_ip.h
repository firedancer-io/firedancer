#ifndef HEADER_fd_src_tango_ip_fd_ip_h
#define HEADER_fd_src_tango_ip_fd_ip_h

#include "fd_netlink.h"
#include "../../util/fd_util.h"

/* implements a number of IP protocol functions required by XDP, since we're bypassing
   parts of the kernel */


/* ARP

   We use netlink to retrieve the ARP table

   Whenever an IP we're trying to resolve is not in the ARP table, we'll simply send an
   ARP request. The Kernel should see the responses and update its ARP table

   */

/* Routing

   We use netlink to obtain the routing table

   In particular we need to choose which next hop IP is required

   */

#define FD_IP_NO_ROUTE -1
#define FD_IP_SUCCESS   0
#define FD_IP_PROBE_RQD 1
#define FD_IP_MULTICAST 2
#define FD_IP_BROADCAST 3

/* magic */
#define FD_IP_MAGIC (0x37ad94a6ec098fc1UL)

/* alias fd_ip_route_entry_t to fd_nl_route_entry_t
   and   fd_ip_arp_entry_t   to fd_nl_arp_entry_t */
typedef fd_nl_route_entry_t fd_ip_route_entry_t;
typedef fd_nl_arp_entry_t   fd_ip_arp_entry_t;


struct fd_ip {
  ulong magic;

  /* capacity */
  ulong num_arp_entries;
  ulong num_route_entries;

  /* current state */
  ulong cur_num_arp_entries;
  ulong cur_num_route_entries;

  ulong ofs_netlink;
  ulong ofs_arp_table;
  ulong ofs_route_table;
};
typedef struct fd_ip fd_ip_t;


struct fd_ip_arp {
  /* Ethernet header */
  uchar  dst_mac_addr[6];        /* broadcast address */
  uchar  src_mac_addr[6];        /* source mac address */
  ushort ethtype;                /* Ethertype - ARP is 0x0806 */

  /* ARP */
  ushort hw_type;                /* Ethernet is 1 */
  ushort proto_type;             /* IP is 0x0800 */
  uchar  hw_addr_len;            /* hardware address length - ethernet is 6 */
  uchar  proto_addr_len;         /* protocol address length - IPv4 is 4 */
  ushort op;                     /* operation - request is 1 */
  uchar  sender_hw_addr[6];      /* sender hardware address */
  uchar  sender_proto_addr[4];   /* sender protocol (IPv4) address */
  uchar  target_hw_addr[6];      /* target hardware address - ignored for request */
  uchar  target_proto_addr[4];   /* target protocol (IPv4) address - ignored for request */

};
typedef struct fd_ip_arp fd_ip_arp_t;


FD_PROTOTYPES_BEGIN

/* footprint and align

   obtain the required footprint and alignment */

#define FD_IP_ALIGN (64UL)

FD_FN_CONST ulong fd_ip_footprint( ulong arp_entries, ulong routing_entries );
FD_FN_CONST ulong fd_ip_align( void );


/* new IP

   create IP stack in the workspace

   arp_entries        the maximum number of arp entries allowed
   routing_entries    the maximum number ot routing entries allowed

   returns
     a void pointer to the value required by fd_ip_join */

void *
fd_ip_new( void * shmem, ulong arp_entries, ulong routing_entries  );


/* join existing IP stack

   joins the IP stack that already exists in the workspace

   returns pointer to the fd_ip_t instance or NULL in a failure

   only one join to each fd_ip_t per process is allowed
   each join creates a netlink file descriptor

   args
     mem           the return value from fd_ip_new

   returns
     pointer to the fd_ip_t joined for use, or NULL if an error occurred */


fd_ip_t *
fd_ip_join( void * mem );


/* leave the fd_ip

   cleans up local resources
   the supplied ip pointer should not be used after

   args
     ip            the fd_ip to leave */
void
fd_ip_leave( fd_ip_t * ip );


/* get pointer to netlink
   this is used internally */
fd_nl_t *
fd_ip_netlink_get( fd_ip_t * ip );


/* get pointer to start of routing table
   this is used internally
   probably best not to modify the data */
fd_ip_route_entry_t *
fd_ip_route_table_get( fd_ip_t * ip );


/* get pointer to start of arp table
   this is used internally
   probably best not to modify the data */
fd_ip_arp_entry_t *
fd_ip_arp_table_get( fd_ip_t * ip );


/* fetch the ARP table from the kernel

   The table is written into the workspace

   use fd_ip_arp_query to access the data */

void
fd_ip_arp_fetch( fd_ip_t * ip );


/* query an arp entry

   searches for an IP address in the table

   if found, *arp is set to point to the entry and the function
       returns 0

   otherwise, the function returns 1 */

int
fd_ip_arp_query( fd_ip_t * ip, fd_ip_arp_entry_t ** arp, uint ip_addr );


/* generate a raw ARP probe (request) packet

   used for caller to generate an ARP packet to send in the event
     we don't have an existing ARP entry

   writes ARP packet into buf

   if successful, returns 0

   if unable to generate ARP, if the dest capacity (dest_cap) is not enough space
     then the function returns 1

   args
     buf          the buffer used to accept the raw ethernet packet
     buf_cap      the capacity in bytes of buf
     ip_addr      the IPv4 address of the target to be probed
     src_mac_addr the MAC address of the source (caller)

   returns
     0 on success
     1 on failure (buf_cap not large enough) */

int
fd_ip_arp_gen_arp_probe( uchar *   buf,
                         ulong     buf_cap,
                         uint      ip_addr,
                         uchar *   src_mac_addr );


/* fetch the routing table from the kernel

   the routing table will be written into the workspace, completely replacing
   any existing routing entries */

void
fd_ip_route_fetch( fd_ip_t * ip );


/* query the routing table

   the provided IP address is looked up in the routing table

   if an appropriate entry is found, *route is set to point to it
     and 0 is returned

   otherwise, 1 is returned */

int
fd_ip_route_query( fd_ip_t *              ip,
                   fd_ip_route_entry_t ** route,
                   uint                   ip_addr );


/* Do routing for an ip_addr

   Handles unicast, broadcast and multicast
       broadcast:
         ff.ff.ff.ff -> mac: ff:ff:ff:ff:ff:ff
       subnet broadcast:
         a.ff.ff.ff/8
         a.b.ff.ff/16
         a.b.c.ff/24 -> if local, ff:ff:ff:ff:ff:ff
                        else normal routing
       multicast:
         224+a,b,c,d -> 01:00:5e:B:c:d (B = b & 0x7f)

   Queries the routing table
     If no match return -1 error
     If match,
       Determines which ip_addr to use
         If local, uses dst_ip_addr
         Else, uses the gateway/next hop ip addr
    Queries the arp table
      If no match returns 1 - send probe
      If match, sets mac and ifindex and returns 0

    returns
      FD_IP_NO_ROUTE  -1  No route to destination
      FD_IP_SUCCESS    0  Route (and arp if necessary) found. out_* have been set
      FD_IP_PROBE_RQD  1  Route, but we need to send an ARP probe to resolve the MAC address
                            Resolve the supplied out_next_ip_addr by sending a probe packet
      FD_IP_MULTICAST  2  Multicast
      FD_IP_BROADCAST  3  Local broadcast */
int
fd_ip_route_ip_addr( uchar *   out_dst_mac,
                     uint *    out_next_ip_addr,
                     uint *    out_ifindex,
                     fd_ip_t * ip,
                     uint      ip_addr );


FD_PROTOTYPES_END

#endif
