#include "fd_ip.h"

#include <arpa/inet.h>

ulong
fd_ip_align( void ) {
  return FD_IP_ALIGN;
}


ulong
fd_ip_footprint( ulong arp_entries,
                 ulong route_entries ) {

  /* use 256 as a default */
  if( arp_entries   == 0 ) arp_entries   = 256;
  if( route_entries == 0 ) route_entries = 256;

  ulong l;

  l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, FD_IP_ALIGN, sizeof(fd_ip_t)                                 );
  l = FD_LAYOUT_APPEND( l, FD_IP_ALIGN, sizeof(fd_nl_t)                                 );
  /* allocate enough space for two of each kind of table */
  l = FD_LAYOUT_APPEND( l, FD_IP_ALIGN, 2 * arp_entries   * sizeof(fd_nl_arp_entry_t)   );
  l = FD_LAYOUT_APPEND( l, FD_IP_ALIGN, 2 * route_entries * sizeof(fd_nl_route_entry_t) );

  return FD_LAYOUT_FINI( l, FD_IP_ALIGN );
}


void *
fd_ip_new( void * shmem,
           ulong  arp_entries,
           ulong  route_entries ) {
  if( !fd_ulong_is_aligned( (ulong)shmem, FD_IP_ALIGN ) ) {
    FD_LOG_ERR(( "Attempt to fd_ip_new with unaligned memory" ));
    return NULL;
  }

  /* use 256 as a default */
  if( arp_entries   == 0 ) arp_entries   = 256;
  if( route_entries == 0 ) route_entries = 256;

  ulong l;
  uchar * mem = (uchar*)shmem;

  l = FD_LAYOUT_INIT;

  fd_ip_t * ip = (fd_ip_t*)mem;
  l = FD_LAYOUT_APPEND( l, FD_IP_ALIGN, sizeof(fd_ip_t)                             );

  ulong ofs_netlink = l;
  l = FD_LAYOUT_APPEND( l, FD_IP_ALIGN, sizeof(fd_nl_t)                             );

  ulong ofs_arp_table   = FD_ULONG_ALIGN_UP( l, FD_IP_ALIGN );
  l = FD_LAYOUT_APPEND( l, FD_IP_ALIGN, 2 * arp_entries   * sizeof(fd_nl_arp_entry_t)   );

  ulong ofs_route_table = FD_ULONG_ALIGN_UP( l, FD_IP_ALIGN );
  l = FD_LAYOUT_APPEND( l, FD_IP_ALIGN, 2 * route_entries * sizeof(fd_nl_route_entry_t) );

  ulong mem_sz = FD_LAYOUT_FINI( l, FD_IP_ALIGN );

  /* clear all to zero */
  fd_memset( ip, 0, mem_sz );

  /* set values in ip */
  ip->num_arp_entries      = arp_entries;
  ip->num_route_entries    = route_entries;
  ip->ofs_netlink          = ofs_netlink;
  ip->ofs_arp_table        = ofs_arp_table;
  ip->ofs_route_table      = ofs_route_table;
  ip->arp_table_idx        = 0;
  ip->route_table_idx      = 0;

  /* set magic last, after a fence */
  FD_COMPILER_MFENCE();
  ip->magic                = FD_IP_MAGIC;

  return (void*)ip;
}


fd_ip_t *
fd_ip_join( void * mem ) {
  if( !mem ) {
    FD_LOG_ERR(( "Attempt to fd_ip_join a NULL" ));
    return NULL;
  }

  if( !fd_ulong_is_aligned( (ulong)mem, FD_IP_ALIGN ) ) {
    FD_LOG_ERR(( "Attempt to fd_ip_join with unaligned memory" ));
    return NULL;
  }

  fd_ip_t * ip = (fd_ip_t*)mem;

  if( ip->magic != FD_IP_MAGIC ) {
    FD_LOG_ERR(( "Failed to fd_ip_join. Possibly memory corrupt" ));
    return NULL;
  }

  /* initialize netlink */
  fd_nl_t * netlink = fd_ip_netlink_get( ip );
  if( fd_nl_init( netlink, 0 ) ) {
    FD_LOG_ERR(( "Failed to initialize fd_netlink." ));
    return NULL;
  }

  return ip;
}


void *
fd_ip_leave( fd_ip_t * ip ) {
  if( !ip ) {
    return NULL;
  }

  /* clear out the magic first */
  ip->magic = 0;

  /* then fence */
  FD_COMPILER_MFENCE();

  /* finalize the netlink */
  fd_nl_t * netlink = fd_ip_netlink_get( ip );
  fd_nl_fini( netlink );

  fd_memset( ip, 0, sizeof( *ip ) );

  return (void*)ip;
}


/* get pointer to fd_nl_t */
fd_nl_t *
fd_ip_netlink_get( fd_ip_t * ip ) {
  ulong mem = (ulong)ip;

  return (fd_nl_t*)( mem + ip->ofs_netlink );
}


/* get pointer to start of current routing table */
fd_ip_route_entry_t *
fd_ip_route_table_get( fd_ip_t * ip ) {
  ulong mem = (ulong)ip;

  /* find the first table from the offset */
  fd_ip_route_entry_t * first_table = (fd_ip_route_entry_t*)( mem + ip->ofs_route_table );

  /* find the table index */
  uint idx = ip->route_table_idx;

  /* offset to the current table */
  return first_table + ( idx * ip->num_route_entries );
}


/* get pointer to start of alternate routing table */
fd_ip_route_entry_t *
fd_ip_route_table_get_alt( fd_ip_t * ip ) {
  ulong mem = (ulong)ip;

  /* find the first table from the offset */
  fd_ip_route_entry_t * first_table = (fd_ip_route_entry_t*)( mem + ip->ofs_route_table );

  /* find the table index of the alternate table */
  uint idx = !ip->route_table_idx;

  /* offset to the alternate table */
  return first_table + ( idx * ip->num_route_entries );
}


/* get pointer to start of current arp table */
fd_ip_arp_entry_t *
fd_ip_arp_table_get( fd_ip_t * ip ) {
  ulong mem = (ulong)ip;

  /* find the table from the offset */
  fd_ip_arp_entry_t * first_table = (fd_ip_arp_entry_t*)( mem + ip->ofs_arp_table );

  /* find the table index */
  uint idx = ip->arp_table_idx;

  /* offset to the current table */
  return first_table + ( idx * ip->num_arp_entries );
}


/* get pointer to start of alternate arp table */
fd_ip_arp_entry_t *
fd_ip_arp_table_get_alt( fd_ip_t * ip ) {
  ulong mem = (ulong)ip;

  /* find the table from the offset */
  fd_ip_arp_entry_t * first_table = (fd_ip_arp_entry_t*)( mem + ip->ofs_arp_table );

  /* find the table index */
  uint idx = !ip->arp_table_idx;

  /* offset to the alternate table */
  return first_table + ( idx * ip->num_arp_entries );
}


void
fd_ip_arp_fetch( fd_ip_t * ip ) {
  /* we fetch into a temp space. If it is successful we switch temp and current */

  /* get pointer to alt table */
  fd_ip_arp_entry_t * alt_arp_table = fd_ip_arp_table_get_alt( ip );
  ulong               arp_table_cap = ip->num_arp_entries;
  fd_nl_t *           netlink       = fd_ip_netlink_get( ip );

  long num_entries = fd_nl_load_arp_table( netlink, alt_arp_table, arp_table_cap );

  if( num_entries <= 0L ) {
    /* don't switch */
    return;
  }

  /* success - switch to other table */
  ip->arp_table_idx      ^= 1;
  ip->cur_num_arp_entries = (ulong)num_entries;
}


/* query an arp entry

   searches for an IP address in the table

   if found, the resulting data is written into the destination and the function
       returns FD_IP_SUCCESS

   otherwise, the function returns FD_IP_ERROR */

int
fd_ip_arp_query( fd_ip_t *            ip,
                 fd_ip_arp_entry_t ** arp,
                 uint                 ip_addr ) {
  fd_ip_arp_entry_t * arp_table     = fd_ip_arp_table_get( ip );
  ulong               arp_table_sz  = ip->cur_num_arp_entries;

  fd_ip_arp_entry_t * entry = fd_nl_arp_query( arp_table, arp_table_sz, ip_addr );
  if( FD_UNLIKELY( !entry ) ) return FD_IP_ERROR;

  *arp = entry;

  return FD_IP_SUCCESS;
}


/* generate a raw ARP packet

   used for caller to generate an ARP packet to send in the event
     we don't have an existing ARP entry

   writes ARP packet into dest

   if successful, returns FD_IP_SUCCESS

   if unable to generate ARP, if the dest capacity (dest_cap) is not enough space
     then the function returns FD_IP_ERROR */

int
fd_ip_arp_gen_arp_probe( uchar *         buf,
                         ulong           buf_cap,
                         ulong *         arp_len,
                         uint            dst_ip_addr,
                         uint            src_ip_addr,
                         uchar const *   src_mac_addr ) {
  if( buf_cap < sizeof( fd_ip_arp_t ) ) {
    return FD_IP_ERROR;
  }

  /* convert ip_addr */
  uint net_dst_ip_addr = htonl( dst_ip_addr );
  uint net_src_ip_addr = htonl( src_ip_addr );

  fd_ip_arp_t * arp = (fd_ip_arp_t*)buf;

  fd_memset( arp->dst_mac_addr, 0xff, 6 );         /* set broadcast */
  fd_memcpy( arp->src_mac_addr, src_mac_addr, 6 ); /* source mac address */

  arp->ethtype        = htons( 0x0806 );       /* Ethertype - ARP is 0x0806 */
  arp->hw_type        = htons( 1 );            /* Ethernet is 1 */
  arp->proto_type     = htons( 0x0800 );       /* IP is 0x0800 */
  arp->hw_addr_len    = 6;                     /* hardware address length - ethernet is 6 */
  arp->proto_addr_len = 4;                     /* protocol address length - IPv4 is 4 */
  arp->op             = htons( 1 );            /* operation - request is 1 */

  fd_memcpy( arp->sender_hw_addr,    src_mac_addr,     6 ); /* sender hardware address */
  fd_memcpy( arp->sender_proto_addr, &net_src_ip_addr, 4 ); /* sender protocol (IPv4) address */

  fd_memset( arp->target_hw_addr,    0,                6 ); /* target hardware address - ignored for request */
  fd_memcpy( arp->target_proto_addr, &net_dst_ip_addr, 4 ); /* target protocol (IPv4) address - ignored for request */

  if( arp_len ) *arp_len = sizeof( *arp );

  return FD_IP_SUCCESS;
}


/* fetch the routing table from the kernel

   the routing table will be written into the workspace, completely replacing
   any existing routing entries */

void
fd_ip_route_fetch( fd_ip_t * ip ) {
  fd_ip_route_entry_t * alt_route_table = fd_ip_route_table_get_alt( ip );
  ulong                 route_table_cap = ip->num_route_entries;
  fd_nl_t *             netlink         = fd_ip_netlink_get( ip );

  long num_entries = fd_nl_load_route_table( netlink, alt_route_table, route_table_cap );

  if( FD_UNLIKELY( num_entries < 0 ) ) {
    /* as a workaround for some systems that return EBUSY, but succeed
     * immediately after, we will retry once */
    num_entries = fd_nl_load_route_table( netlink, alt_route_table, route_table_cap );
  }

  if( FD_UNLIKELY( num_entries <= 0L ) ) {
    /* don't switch */
    return;
  }

  /* switch to new table */
  ip->route_table_idx      ^= 1U;
  ip->cur_num_route_entries = (ulong)num_entries;
}

/* query the routing table

   the provided IP address is looked up in the routing table

   if an appropriate entry is found, the details are written into
     the destination and FD_IP_SUCCESS is returned

   otherwise, FD_IP_ERROR is returned */

int
fd_ip_route_query( fd_ip_t *              ip,
                   fd_ip_route_entry_t ** route,
                   uint                   ip_addr ) {
  fd_ip_route_entry_t * route_table     = fd_ip_route_table_get( ip );
  ulong                 route_table_cap = ip->num_route_entries;

  if( FD_UNLIKELY( route_table_cap == 0 ) ) return FD_IP_RETRY;

  fd_ip_route_entry_t * entry = fd_nl_route_query( route_table, route_table_cap, ip_addr );

  if( FD_UNLIKELY( !entry ) ) return FD_IP_NO_ROUTE;

  *route = entry;

  return FD_IP_SUCCESS;
}


int
fd_ip_route_ip_addr( uchar *   out_dst_mac,
                     uint *    out_next_ip_addr,
                     uint *    out_ifindex,
                     fd_ip_t * ip,
                     uint      ip_addr ) {
  /* handle broadcasts and multicast */

  /* multicast is 224.0.0.0/4 */
  if( ( ip_addr & 0xf0000000 ) == 0xe0000000 ) {
    /* multicast */

    /* map to ethernet space */
    out_dst_mac[0] = 0x01;
    out_dst_mac[1] = 0x00;
    out_dst_mac[2] = 0x5e;
    out_dst_mac[3] = (uchar)( ( ip_addr >> 020 ) & 0x7fU );
    out_dst_mac[4] = (uchar)( ( ip_addr >> 010 ) & 0xffU );
    out_dst_mac[5] = (uchar)( ( ip_addr >> 000 ) & 0xffU );

    return FD_IP_MULTICAST;
  }

  if( ip_addr == 0xffffffff ) {
    /* broadcast */
    out_dst_mac[0] = 0xffU;
    out_dst_mac[1] = 0xffU;
    out_dst_mac[2] = 0xffU;
    out_dst_mac[3] = 0xffU;
    out_dst_mac[4] = 0xffU;
    out_dst_mac[5] = 0xffU;

    return FD_IP_BROADCAST;
  }

  /* query routing table */
  fd_ip_route_entry_t * route_entry = NULL;
  int route_rtn = fd_ip_route_query( ip, &route_entry, ip_addr );
  if( route_rtn != FD_IP_SUCCESS ) {
    return route_rtn; /* no routing entry */
  }

  /* routing entry found */

  uint next_ip_addr = ip_addr; /* assume local */

  /* which ip address to use?
       if the routing entry has a gateway, use that */
  if( route_entry->nh_ip_addr ) {
    next_ip_addr = route_entry->nh_ip_addr; /* use next hop */
  } else {
    next_ip_addr = ip_addr;
  }

  /* have a next IP address, so look up ARP table */

  /* set out_next_ip_addr and out_ifindex */
  *out_next_ip_addr = next_ip_addr;
  *out_ifindex      = route_entry->oif;

  /* query ARP table */
  fd_ip_arp_entry_t * arp_entry = NULL;
  int arp_rtn = fd_ip_arp_query( ip, &arp_entry, next_ip_addr );
  if( arp_rtn != FD_IP_SUCCESS ) {
    return FD_IP_PROBE_RQD; /* no entry, so send probe */
  }

  /* arp entry found - store mac addr in out_dst_mac */
  fd_memcpy( out_dst_mac, arp_entry->mac_addr, 6 );

  /* check the status */
  /* both NUD_REACHABLE and NUD_PERMANENT are acceptable */
  uint accept_states = (uint)NUD_REACHABLE | (uint)NUD_PERMANENT;
  if( FD_LIKELY( (uint)arp_entry->state & accept_states ) ) return FD_IP_SUCCESS;

  /* all other statutes, try probing */
  return FD_IP_PROBE_RQD;
}


int
fd_ip_update_arp_table( fd_ip_t * ip,
                        uint      ip_addr,
                        uint      ifindex ) {
  fd_nl_t * netlink = fd_ip_netlink_get( ip );

  /* ensure the table is up-to-date */
  fd_ip_arp_fetch( ip );

  /* query the table */
  fd_ip_arp_entry_t * arp = NULL;

  /* if entry already exists, return success */
  if( fd_ip_arp_query( ip, &arp, ip_addr ) == FD_IP_SUCCESS ) return FD_IP_SUCCESS;

  return fd_nl_update_arp_table( netlink,
                                 fd_ip_arp_table_get(ip),
                                 ip->num_arp_entries,
                                 ip_addr,
                                 ifindex );
}
