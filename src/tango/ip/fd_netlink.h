#ifndef HEADER_fd_src_tango_fd_netlink_h
#define HEADER_fd_src_tango_fd_netlink_h

#include "../../util/fd_util.h"



struct fd_nl {
  int   fd;  /* netlink socket */
  uint  seq; /* netlink sequence number */
};
typedef struct fd_nl fd_nl_t;


struct fd_nl_route_entry {
  uint dst_ip_addr;    /* destination subnet */
  uint dst_netmask;    /* destination netmask  */
  uint dst_netmask_sz; /* size of netmask in bits */

  uint nh_ip_addr;     /* next hop ip address - AKA gateway */
                       /* zero if no next hop */

  /* IPv4 address - source ip addr */
  uint src_ip_addr;

  /* output interface index */
  uint oif;

  /* flags
     FD_NL_RT_FLAGS_USED        Entry contains data
     FD_NL_RT_FLAGS_DST_IP_ADDR Entry contains an ip address
     FD_NL_RT_FLAGS_DST_NETMASK Entry contains a netmask
     FD_NL_RT_FLAGS_NH_IP_ADDR  Entry contains an ip address
     FD_NL_RT_FLAGS_SRC_IP_ADDR Entry contains a (perferred) source ip address
     FD_NL_RT_FLAGS_OIF         Entry contains an output interface index
     FD_NL_RT_FLAGS_UNSUPPORTED Entry contains an unsupported feature */
  uint flags;
# define  FD_NL_RT_FLAGS_USED        (1U << 0U)
# define  FD_NL_RT_FLAGS_UNSUPPORTED (1U << 1U)
# define  FD_NL_RT_FLAGS_DST_IP_ADDR (1U << 2U)
# define  FD_NL_RT_FLAGS_DST_NETMASK (1U << 3U)
# define  FD_NL_RT_FLAGS_NH_IP_ADDR  (1U << 4U)
# define  FD_NL_RT_FLAGS_SRC_IP_ADDR (1U << 5U)
# define  FD_NL_RT_FLAGS_OIF         (1U << 6U)
};
typedef struct fd_nl_route_entry fd_nl_route_entry_t;


/* ARP entries for IPv4 and Ethernet */
struct fd_nl_arp_entry {
  uint  dst_ip_addr;
  uchar mac_addr[6];
  uint  ifindex;

  /* flags
     FD_NL_ARP_FLAGS_USED        Entry contains data
     FD_NL_ARP_FLAGS_IP_ADDR     Entry contains an ip address
     FD_NL_ARP_FLAGS_MAC_ADDR    Entry contains a MAC address
     FD_NL_ARP_FLAGS_IFINDEX     Entry contains a interface index
     FD_NL_ARP_FLAGS_UNSUPPORTED Entry contains an unsupported feature */
  uint flags;
# define  FD_NL_ARP_FLAGS_USED        (1U << 0U)
# define  FD_NL_ARP_FLAGS_UNSUPPORTED (1U << 1U)
# define  FD_NL_ARP_FLAGS_IP_ADDR     (1U << 2U)
# define  FD_NL_ARP_FLAGS_MAC_ADDR    (1U << 3U)
# define  FD_NL_ARP_FLAGS_IFINDEX     (1U << 4U)
};
typedef struct fd_nl_arp_entry fd_nl_arp_entry_t;


FD_PROTOTYPES_BEGIN


/* creates and configures a socket for netlink

   used by fd_nl_init */
int
fd_nl_create_socket( void );


/* closes a netlink socket */
void
fd_nl_close_socket( int fd );


/* initializes fd_nl_t

   seq should be set to some reasonably random value */
int
fd_nl_init( fd_nl_t * nl, uint seq );


/* finilizes fd_nl_t, closes socket */
void
fd_nl_fini( fd_nl_t * nl );


/* loads the routing table referred to as route_table
   from the kernel using the netlink socket definted in
   nl */
long
fd_nl_load_route_table( fd_nl_t *             nl,
                        fd_nl_route_entry_t * route_table,
                        ulong                 route_table_cap );


/* queries the routing table for a suitable routing entry
   for the given ip_addr

   returns a pointer to the entry, or NULL if none is found */
fd_nl_route_entry_t *
fd_nl_route_query( fd_nl_route_entry_t * route_table, ulong route_table_sz, uint ip_addr );


/* loads the specified arp_table with entries from the kernel
   using the netlink socket defined in nl */
long
fd_nl_load_arp_table( fd_nl_t *           nl,
                      fd_nl_arp_entry_t * arp_table,
                      ulong               arp_table_cap );


/* queries the specified arp_table for an entry matching ip_addr
   
   TODO this is currently O(N), which is fine for small tables
   but we might want to use a hashmap for larger tables */
fd_nl_arp_entry_t *
fd_nl_arp_query( fd_nl_arp_entry_t * arp_table,
                 ulong               arp_table_sz,
                 uint                ip_addr );


FD_PROTOTYPES_END

#endif
