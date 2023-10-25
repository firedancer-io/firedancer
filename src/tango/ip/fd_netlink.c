#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/neighbour.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>

#include "fd_netlink.h"

void
fd_dump_nla_err( struct nlmsghdr * nlh, uint ip_addr, uint ifindex );

#define FD_NL_DATATYPE(X,...) \
  X( FD_NL_IGN   , 1 , ignore , __VA_ARGS__ ) \
  X( FD_NL_CHAR  , 0 , int    , __VA_ARGS__ ) \
  X( FD_NL_SHORT , 0 , int    , __VA_ARGS__ ) \
  X( FD_NL_INT   , 0 , int    , __VA_ARGS__ ) \
  X( FD_NL_ADDR  , 0 , addr   , __VA_ARGS__ )

#define FD_NL_RTA_TYPE(X,...) \
  X( RTA_UNSPEC      , FD_NL_IGN   , "ignored"                            , __VA_ARGS__ ) \
  X( RTA_DST         , FD_NL_ADDR  , "Route destination address"          , __VA_ARGS__ ) \
  X( RTA_SRC         , FD_NL_ADDR  , "Route source address"               , __VA_ARGS__ ) \
  X( RTA_IIF         , FD_NL_INT   , "Input interface index"              , __VA_ARGS__ ) \
  X( RTA_OIF         , FD_NL_INT   , "Output interface index"             , __VA_ARGS__ ) \
  X( RTA_GATEWAY     , FD_NL_ADDR  , "The gateway of the route"           , __VA_ARGS__ ) \
  X( RTA_PRIORITY    , FD_NL_INT   , "Priority of route"                  , __VA_ARGS__ ) \
  X( RTA_PREFSRC     , FD_NL_ADDR  , "Preferred source address"           , __VA_ARGS__ ) \
  X( RTA_METRICS     , FD_NL_INT   , "Route metric"                       , __VA_ARGS__ ) \
  X( RTA_MULTIPATH   , FD_NL_IGN   , "Multipath nexthop data br"          , __VA_ARGS__ ) \
  X( RTA_PROTOINFO   , FD_NL_IGN   , "RTA_PROTOINFO No longer used"       , __VA_ARGS__ ) \
  X( RTA_FLOW        , FD_NL_INT   , "Route realm"                        , __VA_ARGS__ ) \
  X( RTA_CACHEINFO   , FD_NL_IGN   , "Cache info"                         , __VA_ARGS__ ) \
  X( RTA_SESSION     , FD_NL_IGN   , "RTA_SESSION No longer used"         , __VA_ARGS__ ) \
  X( RTA_MP_ALGO     , FD_NL_IGN   , "RTA_MP_ALGO No longer used"         , __VA_ARGS__ ) \
  X( RTA_TABLE       , FD_NL_INT   , "Routing table ID; if set,"          , __VA_ARGS__ ) \
  X( RTA_MARK        , FD_NL_INT   , "RTA_MARK"                           , __VA_ARGS__ ) \
  X( RTA_MFC_STATS   , FD_NL_IGN   , "RTA_MFC_STATS"                      , __VA_ARGS__ ) \
  X( RTA_VIA         , FD_NL_IGN   , "Gateway in different AF"            , __VA_ARGS__ ) \
  X( RTA_NEWDST      , FD_NL_ADDR  , "Change packet destination"          , __VA_ARGS__ ) \
  X( RTA_PREF        , FD_NL_CHAR  , "RFC4191 IPv6 router"                , __VA_ARGS__ ) \
  X( RTA_ENCAP_TYPE  , FD_NL_SHORT , "Encapsulation type"                 , __VA_ARGS__ ) \
  X( RTA_ENCAP       , FD_NL_IGN   , "Defined by RTA_ENCAP_TYPE"          , __VA_ARGS__ ) \
  X( RTA_EXPIRES     , FD_NL_INT   , "Expire time for IPv6"               , __VA_ARGS__ )

char const *
fd_rta_type_to_label( uint rta_type ) {
# define FD_RTA_MATCH( LABEL, CLASS, DESC, ... ) \
  if( rta_type == LABEL ) return #LABEL;
  FD_NL_RTA_TYPE(FD_RTA_MATCH,x)
  return "RTA_UNKNOWN";
# undef FD_RTA_MATCH
}

char const *
fd_rta_type_to_class( uint rta_type ) {
# define FD_RTA_MATCH( LABEL, CLASS, DESC, ... ) \
  if( rta_type == LABEL ) return #CLASS;
  FD_NL_RTA_TYPE(FD_RTA_MATCH,x)
  return "RTA_UNKNOWN";
# undef FD_RTA_MATCH
}

#define FD_NL_RTM_TYPE(X,...) \
  X( RTN_UNSPEC        , "unknown route"                                   , __VA_ARGS__ ) \
  X( RTN_UNICAST       , "a gateway or direct route"                       , __VA_ARGS__ ) \
  X( RTN_LOCAL         , "a local interface route"                         , __VA_ARGS__ ) \
  X( RTN_BROADCAST     , "a local broadcast route (sent as a broadcast)"   , __VA_ARGS__ ) \
  X( RTN_ANYCAST       , "a local broadcast route (sent as a unicast)"     , __VA_ARGS__ ) \
  X( RTN_MULTICAST     , "a multicast route"                               , __VA_ARGS__ ) \
  X( RTN_BLACKHOLE     , "a packet dropping route"                         , __VA_ARGS__ ) \
  X( RTN_UNREACHABLE   , "an unreachable destination"                      , __VA_ARGS__ ) \
  X( RTN_PROHIBIT      , "a packet rejection route"                        , __VA_ARGS__ ) \
  X( RTN_THROW         , "continue routing lookup in another table"        , __VA_ARGS__ ) \
  X( RTN_NAT           , "a network address translation rule"              , __VA_ARGS__ ) \
  X( RTN_XRESOLVE      , "refer to an external resolver (not implemented)" , __VA_ARGS__ )

char const *
fd_rtm_type_to_label( uint rtm_type ) {
# define FD_RTN_MATCH( LABEL, ... ) \
  if( rtm_type == LABEL ) return #LABEL;
  FD_NL_RTM_TYPE(FD_RTN_MATCH,y)
  return "RTN_UNKNOWN";
# undef FD_RTN_MATCH
}

#define FD_NL_NDA_TYPE(X,...) \
  X( NDA_UNSPEC             , __VA_ARGS__ ) \
  X( NDA_DST                , __VA_ARGS__ ) \
  X( NDA_LLADDR             , __VA_ARGS__ ) \
  X( NDA_CACHEINFO          , __VA_ARGS__ ) \
  X( NDA_PROBES             , __VA_ARGS__ ) \
  X( NDA_VLAN               , __VA_ARGS__ ) \
  X( NDA_PORT               , __VA_ARGS__ ) \
  X( NDA_VNI                , __VA_ARGS__ ) \
  X( NDA_IFINDEX            , __VA_ARGS__ ) \
  X( NDA_MASTER             , __VA_ARGS__ ) \
  X( NDA_LINK_NETNSID       , __VA_ARGS__ ) \
  X( NDA_SRC_VNI            , __VA_ARGS__ ) \
  X( NDA_PROTOCOL           , __VA_ARGS__ ) \
  X( NDA_FDB_EXT_ATTRS      , __VA_ARGS__ )

char const *
fd_nda_type_to_label( uint nda_type ) {
# define FD_NDA_MATCH( LABEL, ... ) \
  if( nda_type == LABEL ) return #LABEL;
  FD_NL_NDA_TYPE(FD_NDA_MATCH,)
  return "NDA_UNKNOWN";
# undef FD_NDA_MATCH
}


int
fd_nl_create_socket( void ) {
  int fd = socket( AF_NETLINK, SOCK_RAW | SOCK_NONBLOCK, NETLINK_ROUTE );

  if( fd < 0 ) {
    FD_LOG_WARNING(( "Unable to create netlink socket. Error: %d %s", errno,
          strerror( errno ) ));
    return -1;
  }

  int one = 1;
  if( setsockopt( fd, SOL_NETLINK, NETLINK_EXT_ACK,
        &one, sizeof(one) ) < 0 ) {
    FD_LOG_WARNING(( "Netlink error reporting not supported" ));
    /* continue regardless */
  }

  struct sockaddr_nl sa;
  fd_memset( &sa, 0, sizeof(sa) );
  sa.nl_family = AF_NETLINK;
  if( bind( fd, (void*)&sa, sizeof(sa) ) < 0 ) {
    FD_LOG_WARNING(( "Unable to bind netlink socket. Error: %d %s",
          errno, strerror( errno ) ));
    close( fd );
    return -1;
  }

  return fd;
}


void
fd_nl_close_socket( int fd ) {
  if( fd >= 0 ) {
    close( fd );
  }
}

long
fd_nl_read_socket( int fd, uchar * buf, ulong buf_sz ) {
  /* netlink is datagram based
     once a recv succeeds, any un-received bytes are lost
     and the next datagram will be properly aligned in the buffer */
  long len = -1;
  do {
    len = recv( fd, buf, buf_sz, 0 );
  } while( len <= 0 && errno == EINTR );

  if( len < 0 ) {
    if( errno == EAGAIN ) {
      /* EAGAIN means no data. We can simply try again later */
      return -1;
    }

    FD_LOG_WARNING(( "netlink recv failed with %d %s", errno, strerror( errno ) ));
    return -1;
  }

  return len;
}

int
fd_nl_init( fd_nl_t * nl, uint seq ) {
  nl->seq  = seq;
  nl->fd   = fd_nl_create_socket();
  nl->init = 1;

  /* returns 1 for failure, 0 for success */
  return nl->fd < 0 ? 1 : 0;
}

void
fd_nl_fini( fd_nl_t * nl ) {
  fd_nl_close_socket( nl->fd );
}


long
fd_nl_load_route_table( fd_nl_t *             nl,
                        fd_nl_route_entry_t * route_table,
                        ulong                 route_table_cap ) {
  int fd = nl->fd;
  if( fd < 0 ) {
    FD_LOG_ERR(( "fd_nl_load_route_table called without valid file descriptor" ));
    return -1;
  }

  /* format the request */

  /* Request struct */
  struct {
    struct nlmsghdr nlh;  /* Netlink header */
    struct rtmsg    rtm;  /* Payload - route message */
  } nl_request;

  fd_memset( &nl_request, 0, sizeof( nl_request ) );

  uint seq = nl->seq++;

  nl_request.nlh.nlmsg_type  = RTM_GETROUTE;  /* We wish to get routes */
#if 0
  /* CAP_NET_ADMIN required for NLM_F_ATOMIC */
  nl_request.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ROOT | NLM_F_ATOMIC;
#else
  nl_request.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ROOT;
#endif
  nl_request.nlh.nlmsg_len   = sizeof(nl_request);
  nl_request.nlh.nlmsg_pid   = 0;
  nl_request.nlh.nlmsg_seq   = seq;

  /* request only IPv4 routes */
  nl_request.rtm.rtm_family  = AF_INET;

  ulong send_sz = sizeof(nl_request);
  long  sent    = send( fd, &nl_request, send_sz, 0 );
  if( sent == -1 ) {
    FD_LOG_WARNING(( "Unable to make netlink request. Error: %d %s", errno, strerror( errno ) ));
    return -1;
  }

  if( sent != (long)send_sz ) {
    FD_LOG_WARNING(( "netlink send returned unexpected size: %lu expected: %lu", sent, send_sz ));
    return -1;
  }

  /* receiving */
  long len;

  /* set alignment such that the returned data is aligned */
  uchar __attribute__(( aligned(16) )) ibuf[FD_NL_BUF_SZ] = {0};

  /* Pointer to the messages head */
  struct nlmsghdr *h = (struct nlmsghdr *)ibuf;

  while(1) {
    len = fd_nl_read_socket( fd, ibuf, sizeof(ibuf) );
    if( len <= 0 ) {
      return -1;
    }

    if( h->nlmsg_seq == seq ) break;
  }

  /* index into route_entries */
  long route_entry_idx = 0L;

  /* interpret the response */

  long msglen = len;

  /* Iterate through all messages in buffer */

  for( ; NLMSG_OK( h, msglen ); h = NLMSG_NEXT( h, msglen ) ) {
    /* are we still within the bounds of the table? */
    if( route_entry_idx >= (long)route_table_cap ) {
      /* we filled the table */
      FD_LOG_ERR(( "fd_nl_load_route_table, but table larger than reserved storage" ));
      return -1; /* return failure */
    }

    /* current route entry */
    fd_nl_route_entry_t * entry = route_table + route_entry_idx;

    /* clear current entry */
    fd_memset( entry, 0, sizeof( *entry ) );

    if( h->nlmsg_flags & NLM_F_DUMP_INTR ) {
      /* function was interrupted */

      return -1; /* return failure */
    }

    if( h->nlmsg_type == NLMSG_ERROR ) {
      struct nlmsgerr * err = (struct nlmsgerr*)NLMSG_DATA(h);

      /* acknowledgements have no error */
      if( !err->error ) {
        continue;
      }

      FD_LOG_WARNING(( "netlink returned data with error: %d %s", -err->error, strerror( -err->error) ));

      /* error occurred */

      return -1; /* return failure */
    }

    struct rtmsg *  msg       = NLMSG_DATA( h );
    struct rtattr * rat       = RTM_RTA(msg);
    long            ratmsglen = (long)RTM_PAYLOAD(h);

    /* only care about RTN_UNICAST */
    if( msg->rtm_type == RTN_UNICAST ) {

      while( RTA_OK( rat, ratmsglen ) ) {
        uchar * rta_data    = RTA_DATA( rat );
        ulong   rta_data_sz = RTA_PAYLOAD( rat );

        switch( rat->rta_type ) {
          case RTA_GATEWAY:
            if( rta_data_sz != 4 ) {
              FD_LOG_WARNING(( "Routing entry has gateway address with other than"
                    " 4 byte address" ));
            } else {
              uint nh_ip_addr;
              memcpy( &nh_ip_addr, rta_data, 4 );

              entry->nh_ip_addr     = ntohl( nh_ip_addr );

              entry->flags |= FD_NL_RT_FLAGS_NH_IP_ADDR;
            }
            break;

          case RTA_DST:
            if( rta_data_sz != 4 ) {
              FD_LOG_WARNING(( "Routing entry has destination address with other than"
                    " 4 byte destination address" ));
            } else {
              uint nh_ip_addr;
              memcpy( &nh_ip_addr, rta_data, 4 );

              entry->dst_netmask    = (uint)( 0xffffffff00000000LU >> (ulong)msg->rtm_dst_len );
              entry->dst_netmask_sz = (uint)msg->rtm_dst_len;
              entry->dst_ip_addr    = ntohl( nh_ip_addr ) & entry->dst_netmask;

              entry->flags |= FD_NL_RT_FLAGS_DST_IP_ADDR | FD_NL_RT_FLAGS_DST_NETMASK;
            }
            break;

          case RTA_OIF:
            if( rta_data_sz != 4 ) {
              FD_LOG_WARNING(( "Routing entry has output interface with other than"
                    " 4 byte index" ));
            } else {
              memcpy( &entry->oif, rta_data, 4 );

              entry->flags |= FD_NL_RT_FLAGS_OIF;
            }
            break;

          case RTA_PREFSRC:
            if( rta_data_sz != 4 ) {
              FD_LOG_WARNING(( "Routing entry has destination address with other than"
                    " 4 byte destination address" ));
            } else {
              uint src_ip_addr;
              memcpy( &src_ip_addr, rta_data, 4 );

              entry->src_ip_addr = ntohl( src_ip_addr );

              entry->flags |= FD_NL_RT_FLAGS_SRC_IP_ADDR;
            }
            break;

          case RTA_MULTIPATH:
          case RTA_VIA:
            /* not currently supported */
            FD_LOG_WARNING(( "Routing entry contains an unsupported feature: %s",
                  fd_rta_type_to_label( rat->rta_type ) ));
            entry->flags |= FD_NL_RT_FLAGS_UNSUPPORTED;
            break;
        }

        if( entry->flags & FD_NL_RT_FLAGS_UNSUPPORTED ) {
          break;
        }

        rat = RTA_NEXT( rat, ratmsglen );
      }
    }

    /* the FD_NL_RT_FLAGS_UNSUPPORTED flags must not be present */
    if( ( entry->flags & FD_NL_RT_FLAGS_UNSUPPORTED ) == 0 ) {
      /* supported combinations of flags */
      uint rqd0 = FD_NL_RT_FLAGS_DST_IP_ADDR |
                  FD_NL_RT_FLAGS_DST_NETMASK |
                  FD_NL_RT_FLAGS_OIF;
      uint rqd1 = FD_NL_RT_FLAGS_NH_IP_ADDR  |
                  FD_NL_RT_FLAGS_OIF;
      uint rqd_mask = rqd0 | rqd1;
      uint flags = entry->flags & rqd_mask;
      if( flags == rqd0 || flags == rqd1 ) {
        entry->flags |= FD_NL_RT_FLAGS_USED;
        route_entry_idx++;
      }
    }

  }

  /* clear remaining entries */
  for( long j = route_entry_idx; j < (long)route_table_cap; ++j ) {
    fd_memset( route_table + j, 0, sizeof( route_table[0] ) );
  }

  return route_entry_idx;
}


fd_nl_route_entry_t *
fd_nl_route_query( fd_nl_route_entry_t * route_table, ulong route_table_sz, uint ip_addr ) {
  long best_idx   = -1;
  uint best_class = -1U;

  for( long j = 0L; j < (long)route_table_sz; ++j ) {
    fd_nl_route_entry_t * entry = route_table + j;

    /* the used entries are always contiguous */
    if( ( entry->flags & FD_NL_RT_FLAGS_USED ) == 0 ) break;

    uint netmask = entry->dst_netmask;
    uint clazz   = entry->dst_netmask_sz;
    uint nh_net  = entry->dst_ip_addr;
    uint dst_net = ip_addr & netmask;

    if( nh_net == dst_net && ( best_idx == -1 || clazz > best_class ) ) {
      best_idx   = j;
      best_class = clazz;
    }
  }

  if( best_idx < 0L ) {
    return NULL;
  } else {
    return route_table + best_idx;
  }
}


long
fd_nl_load_arp_table( fd_nl_t *           nl,
                      fd_nl_arp_entry_t * arp_table,
                      ulong               arp_table_cap ) {
  int fd = nl->fd;
  if( fd < 0 ) return FD_IP_ERROR;

  /* format the request */

  /* Request struct */
  struct {
    struct nlmsghdr nlh;  /* Netlink header */
    struct ndmsg    ndm;  /* Payload - neighbor message */
  } nl_request;

  fd_memset( &nl_request, 0, sizeof( nl_request ) );

  uint seq = nl->seq++;

  nl_request.nlh.nlmsg_type  = RTM_GETNEIGH;  /* We wish to get neighbors */
  nl_request.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
  nl_request.nlh.nlmsg_len   = NLMSG_LENGTH(sizeof(struct rtmsg));
  nl_request.nlh.nlmsg_pid   = 0;
  nl_request.nlh.nlmsg_seq   = seq;

  /* request IPv4 entries */
  nl_request.ndm.ndm_family  = AF_INET;

  ulong send_sz = sizeof(nl_request);
  long  sent    = send( fd, &nl_request, send_sz, 0 );
  if( sent == -1 ) {
    FD_LOG_WARNING(( "Unable to make netlink request. Error: %d %s", errno, strerror( errno ) ));
    return FD_IP_ERROR;
  }

  if( sent != (long)send_sz ) {
    FD_LOG_WARNING(( "netlink send returned unexpected size: %lu expected: %lu", sent, send_sz ));
    return FD_IP_ERROR;
  }

  /* receiving */
  long len;

  /* set alignment such that the returned data is aligned */
  uchar __attribute__(( aligned(16) )) ibuf[FD_NL_BUF_SZ] = {0};

  /* Pointer to the messages head */
  struct nlmsghdr *h = (struct nlmsghdr *)ibuf;

  while(1) {
    len = fd_nl_read_socket( fd, ibuf, sizeof(ibuf) );
    if( len <= 0 ) {
      return FD_IP_ERROR;
    }

    if( h->nlmsg_seq == seq ) break;
  }

  /* index into arp_table */
  long arp_entry_idx = 0L;

  /* interpret the response */

  long msglen = len;

  /* Iterate through all messages in buffer */

  while( NLMSG_OK(h, msglen) ) {
    /* are we still within the bounds of the table? */
    if( arp_entry_idx >= (long)arp_table_cap ) {
      /* we filled the table */
      FD_LOG_ERR(( "fd_nl_load_arp_table, but table larger than reserved storage" ));
      return FD_IP_ERROR; /* return failure */
    }

    /* current arp entry */
    fd_nl_arp_entry_t * entry = arp_table + arp_entry_idx;

    /* clear current entry */
    fd_memset( entry, 0, sizeof( *entry ) );

    if( h->nlmsg_flags & NLM_F_DUMP_INTR ) {
      /* function was interrupted - don't switch to new routing table */

      return FD_IP_RETRY; /* return transient failure */
    }

    if( h->nlmsg_type == NLMSG_ERROR ) {
      struct nlmsgerr * err = NLMSG_DATA(h);

      FD_LOG_WARNING(( "netlink returned data with error: %d %s", -err->error, strerror( -err->error) ));

      /* error occurred - don't switch to new routing table */

      return FD_IP_ERROR; /* return failure */
    }

    struct ndmsg *  msg       = NLMSG_DATA( h );
    struct rtattr * rat       = RTM_RTA(msg);
    long            ratmsglen = (long)RTM_PAYLOAD( h );

    /* store the interface */
    entry->ifindex = (uint)msg->ndm_ifindex;
    entry->flags  |= FD_NL_ARP_FLAGS_IFINDEX;

    /* we want to skip some entries based on state
       here are the states:
           NUD_INCOMPLETE   a currently resolving cache entry
           NUD_REACHABLE    a confirmed working cache entry
           NUD_STALE        an expired cache entry
           NUD_DELAY        an entry waiting for a timer
           NUD_PROBE        a cache entry that is currently reprobed
           NUD_FAILED       an invalid cache entry
           NUD_NOARP        a device with no destination cache
           NUD_PERMANENT    a static entry

       Keeping:
           NUD_REACHABLE    valid, so use it
           NUD_STALE        probably better to use the existing address
                              than wait or discard packet
           NUD_DELAY        an entry waiting for a timer
           NUD_PROBE        being reprobed, so it's probably valid
           NUD_PERMANENT    a static entry, so use it */

    while( RTA_OK( rat, ratmsglen ) ) {
      uchar * rta_data    = RTA_DATA( rat );
      ulong   rta_data_sz = RTA_PAYLOAD( rat );

      switch( rat->rta_type ) {
        case NDA_DST:
          if( rta_data_sz != 4 ) {
            FD_LOG_WARNING(( "Neighbor entry has IP address with other than"
                  " 4 byte address" ));
          } else {
            uint dst_ip_addr;
            memcpy( &dst_ip_addr, rta_data, 4 );
            entry->dst_ip_addr = ntohl( dst_ip_addr );

            entry->flags |= FD_NL_ARP_FLAGS_IP_ADDR;
          }
          break;

        case NDA_LLADDR:
          if( rta_data_sz != 6 ) {
            FD_LOG_WARNING(( "Neighbor entry has LL address with other than"
                  " 6 byte MAC address" ));
          } else {
            memcpy( &entry->mac_addr[0], rta_data, 6 );

            entry->flags |= FD_NL_ARP_FLAGS_MAC_ADDR;
          }
          break;

      }

      if( entry->flags & FD_NL_RT_FLAGS_UNSUPPORTED ) {
        break;
      }

      rat = RTA_NEXT( rat, ratmsglen );
    }

    /* at present, each entry must have at least the following:
           FD_NL_ARP_FLAGS_IP_ADDR
           FD_NL_ARP_FLAGS_MAC_ADDR
           FD_NL_ARP_FLAGS_IFINDEX

       the FD_NL_ARP_FLAGS_UNSUPPORTED flags must not be present */
    if( ( entry->flags & FD_NL_ARP_FLAGS_UNSUPPORTED ) == 0 ) {
      entry->flags |= FD_NL_ARP_FLAGS_USED;
      entry->state = msg->ndm_state;
      arp_entry_idx++;
    }

    h = NLMSG_NEXT( h, msglen );
  }

  /* clear remaining entries */
  for( long j = arp_entry_idx; j < (long)arp_table_cap; ++j ) {
    fd_memset( arp_table + j, 0, sizeof( arp_table[0] ) );
  }

  return arp_entry_idx;
}


fd_nl_arp_entry_t *
fd_nl_arp_query( fd_nl_arp_entry_t * arp_table,
                 ulong               arp_table_sz,
                 uint                ip_addr ) {
  for( long j = 0L; j < (long)arp_table_sz; ++j ) {
    fd_nl_arp_entry_t * entry = arp_table + j;
    if( ( entry->flags & FD_NL_ARP_FLAGS_USED ) == 0 ) break;

    if( entry->dst_ip_addr == ip_addr ) {
      return entry;
    }
  }

  return NULL;
}


int
fd_nl_update_arp_table( fd_nl_t *           nl,
                        fd_nl_arp_entry_t * arp_table,
                        ulong               arp_table_cap,
                        uint                ip_addr,
                        uint                ifindex ) {
  int rtn = FD_IP_ERROR;

  int fd = nl->fd;
  if( fd < 0 ) {
    FD_LOG_ERR(( "fd_nl_update_arp_table called with invalid file descriptor" ));
    return FD_IP_ERROR;
  }

  /* find the entry, if one exists */
  long idx       = -1L;
  int  cur_state = -1; /* -1 indicates no existing entry */
  for( ulong j = 0; j < arp_table_cap; ++j ) {
    fd_nl_arp_entry_t * entry = &arp_table[j];

    /* indicates the end */
    if( ( entry->flags & FD_NL_RT_FLAGS_USED ) == 0 ) break;

    if( entry->dst_ip_addr == ip_addr ) {
      idx       = (long)j;
      cur_state = (int)entry->state;
      break;
    }
  }

  /* ARP state transitions

     NONE  --->  INCOMPLETE ---+
                               |
     DELAY --->  PROBE         |
       ^           |           |
       |           V           |
     STALE <---  REACHABLE <---+

     PERMANENT and NOARP do not participate */

  /* nothing to do - either in final state, or kernel handles the transition */
  int rtn_states = (int)( NUD_NOARP     |
                          NUD_PERMANENT |
                          NUD_DELAY     |
                          NUD_STALE     |
                          NUD_REACHABLE );
  if( cur_state > 0 && ( cur_state & rtn_states ) ) return FD_IP_SUCCESS;

  /* determine next state */
  int next_state = 0;
  switch( cur_state ) {
    case -1:             next_state = NUD_NONE;       rtn = FD_IP_RETRY;     break;
    case NUD_NONE:       next_state = NUD_INCOMPLETE; rtn = FD_IP_PROBE_RQD; break;
    case NUD_INCOMPLETE: return FD_IP_PROBE_RQD;
    case NUD_PROBE:      return FD_IP_PROBE_RQD;
    default:
      FD_LOG_WARNING(( "Unexpected state: %d", cur_state ));
      return FD_IP_ERROR;
  }

  /* TODO For NUD_STALE, the kernel may never see UDP packets from the IP
     (We steal them)
     In this case, the kernel will push to DELAY and then PROBE resulting
     in unnecessary ARP probes to be sent.
     What we should do is update the stale ARP entry to NUD_REACHABLE when
     we receive a packet from local IPs */

  uint net_ip_addr = htonl( ip_addr );

  /* format the request */

# define IP_ADDR_LEN 4
# define NLMSG_LEN   NLMSG_LENGTH( sizeof(struct rtmsg) )
# define TOT_SZ      ( NLMSG_LEN + RTA_LENGTH(IP_ADDR_LEN) )
# define BUF_OFFS    ( sizeof( struct nlmsghdr ) + sizeof( struct ndmsg ) )
# define BUF_SZ      ( TOT_SZ - BUF_OFFS )

  /* Request struct */
  struct {
    struct nlmsghdr nlh;         /* Netlink header */
    struct ndmsg    ndm;         /* Payload - neighbor message */
    uchar           buf[BUF_SZ]; /* sized to match the request exactly */
  } nl_request;

  fd_memset( &nl_request, 0, sizeof( nl_request ) );

  uint seq = nl->seq++;

  nl_request.nlh.nlmsg_type  = RTM_NEWNEIGH;  /* We wish to get neighbors */
  nl_request.nlh.nlmsg_flags = cur_state == -1 ? ( NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL )
                                               : ( NLM_F_REQUEST | NLM_F_ACK | NLM_F_REPLACE );
  nl_request.nlh.nlmsg_len   = (uint)NLMSG_LEN;
  nl_request.nlh.nlmsg_pid   = 0;
  nl_request.nlh.nlmsg_seq   = seq;

  /* request IPv4 entries */
  nl_request.ndm.ndm_family  = AF_INET;
  nl_request.ndm.ndm_ifindex = (int)ifindex;
  nl_request.ndm.ndm_state   = (ushort)next_state;
  nl_request.ndm.ndm_flags   = 0;
  nl_request.ndm.ndm_type    = RTN_UNICAST;

  /* not necessarily defined! */
#ifndef NLMSG_TAIL
#define NLMSG_TAIL(nmsg) ((struct rtattr *)(((uchar *)(nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))
#endif

  /* write required attributes */
  struct rtattr * rqs_rat = NLMSG_TAIL(&nl_request.nlh);

  rqs_rat->rta_type = NDA_DST;
  rqs_rat->rta_len =  RTA_LENGTH(4);

  memcpy( RTA_DATA(rqs_rat), &net_ip_addr, 4 );
  nl_request.nlh.nlmsg_len += (int)sizeof(struct rtattr) + 4;

  ulong nl_request_sz = (ulong)nl_request.nlh.nlmsg_len;

  if( nl_request_sz != TOT_SZ ) {
    FD_LOG_ERR(( "request size does not match expected size" ));
    return FD_IP_ERROR;
  }

  ulong send_sz = nl_request_sz;
  long  sent    = send( fd, &nl_request, send_sz, 0 );
  if( sent == -1 ) {
    FD_LOG_WARNING(( "Unable to make netlink request. Error: %d %s", errno, strerror( errno ) ));
    return FD_IP_ERROR;
  }

  if( sent != (long)send_sz ) {
    FD_LOG_WARNING(( "netlink send returned unexpected size: %lu expected: %lu", sent, send_sz ));
    return FD_IP_ERROR;
  }

  /* receiving */
  long len;

  /* set alignment such that the returned data is aligned */
  uchar __attribute__(( aligned(16) )) ibuf[FD_NL_BUF_SZ] = {0};

  /* Pointer to the messages head */
  struct nlmsghdr *h = (struct nlmsghdr *)ibuf;

  while(1) {
    len = fd_nl_read_socket( fd, ibuf, sizeof(ibuf) );
    if( len <= 0 ) {
      return FD_IP_ERROR;
    }

    if( h->nlmsg_seq == seq ) break;
  }

  /* interpret the response */

  long msglen = len;

  /* check for errors */

  while( NLMSG_OK(h, msglen) ) {
    if( h->nlmsg_type == NLMSG_ERROR ) {
      struct nlmsgerr * err = NLMSG_DATA(h);

      /* we are expecting the ARP entry to sometimes exist
         so simply return SUCCESS here */
      if( err->error != -EEXIST && err->error != 0 ) {
        /* all other errors are reported */

        fd_dump_nla_err( h, ip_addr, ifindex );

        /* error occurred - don't switch to new routing table */

        return FD_IP_ERROR; /* return failure */
      }
    }

    h = NLMSG_NEXT( h, msglen );
  }

  /* state has changed, reload table */
  fd_nl_load_arp_table( nl, arp_table, arp_table_cap );
  (void)idx; /* TODO remove idx, as unneeded */

  return rtn;
}

/* dump netlink extended ack error message */
void
fd_dump_nla_err( struct nlmsghdr * nlh, uint ip_addr, uint ifindex ) {

#define FD_NLA_ERR_DEFS(X,...) \
  X( msg  , NLMSGERR_ATTR_MSG  , CSTRING , __VA_ARGS__ ) \
  X( offs , NLMSGERR_ATTR_OFFS , UINT    , __VA_ARGS__ )

#   define FD_NLA_MBR(MBR,ATTR,TYPE,...) FD_NLA_MBR_TYPE_##TYPE MBR;
#   define FD_NLA_MBR_TYPE_CSTRING char const *
#   define FD_NLA_MBR_TYPE_UINT    uint

#   define FD_NLA_CPY(MBR,TYPE,DATA) FD_NLA_CPY_##TYPE(MBR,DATA)
#   define FD_NLA_CPY_CSTRING(MBR,DATA) (char const *)data
#   define FD_NLA_CPY_UINT(MBR,DATA)    *(uint *)data

  struct fd_err_attr {
    FD_NLA_ERR_DEFS(FD_NLA_MBR,x,y)
  } err_attr = {0};

  struct nlmsgerr * err = NLMSG_DATA( nlh );

  /* no extended info, just report what we have */
  if( ( nlh->nlmsg_flags & NLM_F_ACK_TLVS ) == 0 ) {
#   define EXPAND_IP4(ip) (((ip)>>24u)&0xffU), (((ip)>>16u)&0xffU), (((ip)>>8u)&0xffU), ((ip)&0xffU)
    FD_LOG_WARNING(( "netlink returned data with error: %d %s"
          " adding ip address: %u.%u.%u.%u on ifindex: %u",
          -err->error, strerror( -err->error ),
          EXPAND_IP4( (uint)ip_addr ),
          (uint)ifindex ));
#   undef EXPAND_IP4
    return;
  }

  struct nlattr *attr = NULL;

  int hlen = sizeof(*err);

  /* if NLM_F_CAPPED is set then the inner err msg was capped */
  if( !(nlh->nlmsg_flags & NLM_F_CAPPED) ) {
    hlen += (int)err->msg.nlmsg_len - (int)NLMSG_HDRLEN;
  }

  attr = (struct nlattr *)( (uchar *)err + hlen );
  int alen = (int)( (uchar *)nlh + nlh->nlmsg_len - (uchar *)attr );

# ifndef NLA_OK
#   define NLA_OK(NLA,REM)                      \
     (                                          \
       (REM)          >= (int)sizeof(*(NLA)) && \
       (NLA)->nla_len >= sizeof(*(NLA))      && \
       (REM)          >= (NLA)->nla_len         \
     )
# endif

# ifndef NLA_NEXT
# define NLA_NEXT_ALIGN(NLA,REM,TOTLEN) \
    ( (*(REM) -= (TOTLEN) ), (struct nlattr *)((uchar *)(NLA) + (TOTLEN)) )
# define NLA_NEXT(NLA,REM) NLA_NEXT_ALIGN(NLA,REM,NLA_ALIGN((NLA)->nla_len))
# endif

  /* the NLA_HDRLEN macro in netlink.h causes sign conversion errors
     so replacing with this: */
#define FD_NLA_ALIGN(len) (((long)(len) +   (long)(NLA_ALIGNTO) - 1L) & \
                                          ~((long)(NLA_ALIGNTO) - 1L))
#define FD_NLA_HDRLEN     ((long)(FD_NLA_ALIGN(sizeof(struct nlattr))))

  /* walk thru extended error attributes and populate err_attr */
  for( int rem = alen; NLA_OK( attr, rem ); attr = NLA_NEXT(attr,&rem) ) {
    /* get type */
    int type = attr->nla_type & NLA_TYPE_MASK;
    void * data = (void*)( (long)attr + FD_NLA_HDRLEN );

    /* lookup type */

#   define FD_NLA_POPULATE( MBR, ATTR, TYPE, ATTR_VAR, ... ) \
      if( type == ATTR ) {                                   \
        (ATTR_VAR).MBR = FD_NLA_CPY(MBR,TYPE,data);          \
      } else

    FD_NLA_ERR_DEFS( FD_NLA_POPULATE, err_attr, dummy ) {
      /* ignore */
    }
  }

# define EXPAND_IP4(ip) (((ip)>>24u)&0xffu), (((ip)>>16u)&0xffu), (((ip)>>8u)&0xffu), ((ip)&0xffu)
  FD_LOG_WARNING(( "netlink returned data with error: %d %s"
        " adding ip address: %u.%u.%u.%u  on ifindex: %u"
        " extended info: %s  offset: %u",
        -err->error, strerror( -err->error ),
        EXPAND_IP4( (uint)ip_addr ),
        (uint)ifindex, (char const *)err_attr.msg,
        (uint)err_attr.offs ));
# undef EXPAND_IP4

  return;
}
