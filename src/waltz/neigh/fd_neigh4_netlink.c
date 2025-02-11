#include "fd_neigh4_netlink.h"

#include <errno.h>
#include <sys/socket.h> /* AF_INET */
#include <linux/netlink.h> /* struct nlmsghdr */
#include <linux/rtnetlink.h> /* RTM_NEWNEIGH */
#include <linux/neighbour.h> /* struct ndmsg */
#include "../ip/fd_netlink1.h"
#include "../../util/fd_util.h"
#include "../../util/net/fd_ip4.h"
#include "fd_neigh4_map.h"

int
fd_neigh4_netlink_request_dump( fd_netlink_t * netlink,
                                uint           if_idx ) {

  uint seq = netlink->seq++;

  struct {
    struct nlmsghdr nlh;
    struct ndmsg    ndm;
  } request;
  request.nlh = (struct nlmsghdr) {
    .nlmsg_type  = RTM_GETNEIGH,
    .nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP,
    .nlmsg_len   = sizeof(request),
    .nlmsg_seq   = seq
  };
  request.ndm = (struct ndmsg) {
    .ndm_family  = AF_INET,
    .ndm_ifindex = (int)if_idx
  };

  long send_res = send( netlink->fd, &request, sizeof(request), 0 );
  if( FD_UNLIKELY( send_res<0 ) ) {
    FD_LOG_WARNING(( "netlink send(RTM_GETNEIGH,NLM_F_REQUEST|NLM_F_DUMP) failed (%d-%s)", errno, fd_io_strerror( errno ) ));
    return errno;
  }
  if( FD_UNLIKELY( send_res!=sizeof(request ) ) ) {
    FD_LOG_WARNING(( "netlink send(RTM_GETROUTE,NLM_F_REQUEST|NLM_F_DUMP) failed (short write)" ));
    return EPIPE;
  }

  return 0;
}

void
fd_neigh4_netlink_ingest_message( fd_neigh4_hmap_t *      map,
                                  struct nlmsghdr const * msg_hdr,
                                  uint                    if_idx ) {
  if( FD_UNLIKELY( msg_hdr->nlmsg_type!=RTM_NEWNEIGH && msg_hdr->nlmsg_type!=RTM_DELNEIGH ) ) {
    FD_LOG_WARNING(( "unexpected nlmsg_type %u", msg_hdr->nlmsg_type ));
    return;
  }

  struct ndmsg const *  ndm    = NLMSG_DATA( msg_hdr );
  struct rtattr const * rat    = RTM_RTA( ndm );
  long                  rat_sz = (long)(int)RTM_PAYLOAD( msg_hdr );

  if( FD_UNLIKELY( ndm->ndm_family!=AF_INET       ) ) return;
  if( FD_UNLIKELY( (uint)ndm->ndm_ifindex!=if_idx ) ) return;

  uint ip4_dst = 0U;
  union {
    uchar u6[6];
    ulong ul;
  } mac_addr = {0};

  for( ; RTA_OK( rat, rat_sz ); rat=RTA_NEXT( rat, rat_sz ) ) {

    void * rta    = RTA_DATA( rat );
    ulong  rta_sz = RTA_PAYLOAD( rat );

    switch( rat->rta_type ) {

    case NDA_DST:
      if( FD_UNLIKELY( rta_sz!=4UL ) ) {
        FD_LOG_WARNING(( "unexpected NDA_DST size %lu", rta_sz ));
        return;
      }
      ip4_dst = FD_LOAD( uint, rta ); /* big endian */
      break;

    case NDA_LLADDR:
      if( FD_UNLIKELY( rta_sz!=6UL ) ) {
        FD_LOG_WARNING(( "unexpected NDA_LLADDR size %lu (is this an Ethernet interface?)", rta_sz ));
        return;
      }
      memcpy( mac_addr.u6, rta, 6 );
      break;

    default:
      break; /* ignore */
    }

  }

  if( FD_UNLIKELY( !mac_addr.ul || !ip4_dst ) ) {
    FD_LOG_DEBUG(( "Ignoring neighbor table update with missing or invalid L2 or L3 address" ));
    return;
  }

  /* Determine if we should remove or insert/update entry */

  int remove = 0;
  switch( ndm->ndm_state ) {
  case NUD_REACHABLE:
  case NUD_STALE:
  case NUD_DELAY:
  case NUD_PROBE:
  case NUD_PERMANENT:
    remove = 0;
    break;
  default:
    remove = 1;
    break;
  }
  if( msg_hdr->nlmsg_type==RTM_DELNEIGH ) {
    remove = 1;
  }

  /* Perform update */

  if( remove ) {

    fd_neigh4_hmap_remove( map, &ip4_dst, NULL, FD_MAP_FLAG_BLOCKING );

  } else {

    fd_neigh4_hmap_query_t query[1];
    int prepare_res = fd_neigh4_hmap_prepare( map, &ip4_dst, NULL, query, FD_MAP_FLAG_BLOCKING );
    if( FD_UNLIKELY( prepare_res!=FD_MAP_SUCCESS ) ) {
      FD_LOG_WARNING(( "Failed to update neighbor table" ));
      return;
    }

    fd_neigh4_entry_t * ele = fd_neigh4_hmap_query_ele( query );

    ele->state    = FD_NEIGH4_STATE_ACTIVE;
    ele->ip4_addr = ip4_dst;
    memcpy( ele->mac_addr, mac_addr.u6, 6 );

    fd_neigh4_hmap_publish( query );

  }

}

int
fd_neigh4_netlink_solicit( fd_netlink_t * netlink,
                           uint           if_idx,
                           uint           ip4_addr ) {

  uint seq = netlink->seq++;

  struct {
    struct nlmsghdr nlh;
    struct ndmsg    ndm;
    struct nlattr   nla_dst;
    uint            dst_addr;
  } request;
  request.nlh = (struct nlmsghdr) {
    .nlmsg_type  = RTM_NEWNEIGH,
    .nlmsg_flags = NLM_F_REQUEST|NLM_F_ACK|NLM_F_EXCL|NLM_F_CREATE,
    .nlmsg_seq   = seq
  };
  request.ndm = (struct ndmsg) {
    .ndm_family  = AF_INET,
    .ndm_ifindex = (int)if_idx,
    .ndm_state   = NUD_INCOMPLETE, /* neighbor entry starts out as empty */
    .ndm_flags   = NTF_USE /* mark neighbor as used which triggers ARP request */
  };
  request.nla_dst = (struct nlattr) {
    .nla_type = NDA_DST,
    .nla_len  = (ushort)( sizeof(struct nlattr) + fd_uint_align_up( sizeof(uint), NLA_ALIGNTO ) )
  };
  request.dst_addr = ip4_addr; /* big endian */

  /* Send request */

  long send_res = sendto( netlink->fd, &request, sizeof(request), 0, NULL, 0 );
  if( FD_UNLIKELY( send_res<0 ) ) {
    FD_LOG_WARNING(( "netlink send(RTM_NEWNEIGH,NLM_F_REQUEST|NLM_F_ACK|NLM_F_EXCL|NLM_F_CREATE," FD_IP4_ADDR_FMT ") failed (%d-%s)",
                     FD_IP4_ADDR_FMT_ARGS( ip4_addr ), errno, fd_io_strerror( errno ) ));
    return errno;
  }
  if( FD_UNLIKELY( send_res!=sizeof(request) ) ) {
    FD_LOG_WARNING(( "netlink send(RTM_NEWNEIGH,NLM_F_REQUEST|NLM_F_ACK|NLM_F_EXCL|NLM_F_CREATE," FD_IP4_ADDR_FMT ") failed (short write)",
                     FD_IP4_ADDR_FMT_ARGS( ip4_addr ) ));
    return EPIPE;
  }

  /* Get error code */

  for( ulong attempt=0UL; attempt<64UL; attempt++ ) {
    uchar buf[ 4096 ];
    long recv_res = fd_netlink_read_socket( netlink->fd, buf, sizeof(buf) );
    if( FD_UNLIKELY( recv_res<0 ) ) {
      FD_LOG_WARNING(( "netlink recv failed (%d-%s)", errno, fd_io_strerror( errno ) ));
      return errno;
    }

    struct nlmsghdr const * nlh = fd_type_pun_const( buf );
    if( FD_UNLIKELY( nlh->nlmsg_seq != seq ) ) {
      /* Should only happen if caller misbehaves */
      FD_LOG_WARNING(( "Dropping rtnetlink message type=%u seq=%u", nlh->nlmsg_type, nlh->nlmsg_seq ));
      continue;
    }

    if( FD_UNLIKELY( nlh->nlmsg_type!=NLMSG_ERROR ) ) {
      /* Should never happen */
      FD_LOG_WARNING(( "unexpected nlmsg_type %u for RTM_NEWNEIGH request", nlh->nlmsg_type ));
      continue;
    }

    struct nlmsgerr * err = NLMSG_DATA( nlh );
    int nl_err = -err->error;
    return nl_err;
  }

  FD_LOG_WARNING(( "Giving up on receiving response code for RTM_NEWNEIGH request" ));
  return 0;
}
