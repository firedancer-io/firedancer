#include "fd_fib4_netlink.h"
#include "fd_fib4.h"
#include "fd_netlink1.h"

#if !defined(__linux__)
#error "fd_fib4_netlink.c requires a Linux system with kernel headers"
#endif

#include <errno.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <arpa/inet.h>
#include "../../util/fd_util.h"

FD_STATIC_ASSERT( FD_FIB4_RTYPE_UNSPEC   ==RTN_UNSPEC,    linux );
FD_STATIC_ASSERT( FD_FIB4_RTYPE_UNICAST  ==RTN_UNICAST,   linux );
FD_STATIC_ASSERT( FD_FIB4_RTYPE_LOCAL    ==RTN_LOCAL,     linux );
FD_STATIC_ASSERT( FD_FIB4_RTYPE_BROADCAST==RTN_BROADCAST, linux );
FD_STATIC_ASSERT( FD_FIB4_RTYPE_MULTICAST==RTN_MULTICAST, linux );
FD_STATIC_ASSERT( FD_FIB4_RTYPE_BLACKHOLE==RTN_BLACKHOLE, linux );
FD_STATIC_ASSERT( FD_FIB4_RTYPE_THROW    ==RTN_THROW,     linux );

static void
fd_fib4_rta_gateway( fd_fib4_hop_t * hop,
                     void const *    rta,
                     ulong           rta_sz ) {
  if( FD_UNLIKELY( rta_sz!=4UL ) ) {
    FD_LOG_HEXDUMP_DEBUG(( "Failed to parse RTA_GATEWAY", rta, rta_sz ));
    hop->flags |= FD_FIB4_FLAG_RTA_PARSE_ERR;
    return;
  }
  uint ip_addr = FD_LOAD( uint, rta ); /* big endian */
  hop->ip4_gw = ip_addr;
}

static void
fd_fib4_rta_oif( fd_fib4_hop_t * hop,
                 void const *    rta,
                 ulong           rta_sz ) {
  if( FD_UNLIKELY( rta_sz!=4UL ) ) {
    FD_LOG_HEXDUMP_DEBUG(( "Failed to parse RTA_OIF", rta, rta_sz ));
    hop->flags |= FD_FIB4_FLAG_RTA_PARSE_ERR;
    return;
  }
  hop->if_idx = FD_LOAD( uint, rta ); /* host byte order */
}

static void
fd_fib4_rta_prefsrc( fd_fib4_hop_t * hop,
                     void const *    rta,
                     ulong           rta_sz ) {
  if( FD_UNLIKELY( rta_sz!=4UL ) ) {
    FD_LOG_HEXDUMP_DEBUG(( "Failed to parse RTA_PREFSRC", rta, rta_sz ));
    hop->flags |= FD_FIB4_FLAG_RTA_PARSE_ERR;
    return;
  }
  hop->ip4_src = FD_LOAD( uint, rta ); /* big endian */
}

static int
fd_fib4_netlink_translate( fd_fib4_t *             fib,
                           struct nlmsghdr const * msg_hdr,
                           uint                    table_id ) {
  uint ip4_dst = 0U;
  int  prefix  = -1; /* -1 indicates unset ip4_dst / prefix */
  uint prio    = 0U; /* default metric */

  fd_fib4_hop_t hop[1] = {0};

  struct rtmsg *  msg    = NLMSG_DATA( msg_hdr );
  struct rtattr * rat    = RTM_RTA( msg );
  long            rat_sz = (long)(int)RTM_PAYLOAD( msg_hdr );

  if( FD_UNLIKELY(msg->rtm_flags & RTM_F_CLONED) ) {
    return 0;
  }

  if( FD_UNLIKELY(msg->rtm_table != RT_TABLE_UNSPEC &&
       msg->rtm_table != table_id ) ) {
    return 0;
  }

  switch( msg->rtm_type ) {
  case RTN_UNICAST:
    hop->rtype = FD_FIB4_RTYPE_UNICAST;
    break;
  case RTN_LOCAL:
    hop->rtype = FD_FIB4_RTYPE_LOCAL;
    break;
  case RTN_BROADCAST:
    hop->rtype = FD_FIB4_RTYPE_BROADCAST;
    break;
  case RTN_MULTICAST:
    hop->rtype = FD_FIB4_RTYPE_MULTICAST;
    break;
  case RTN_BLACKHOLE:
    hop->rtype = FD_FIB4_RTYPE_BLACKHOLE;
    break;
  default:
    FD_LOG_DEBUG(( "Unsupported route type (%u-%s)", msg->rtm_type, fd_netlink_rtm_type_str( msg->rtm_type ) ));
    hop->rtype = FD_FIB4_RTYPE_BLACKHOLE;
    hop->flags |= FD_FIB4_FLAG_RTYPE_UNSUPPORTED;
    break;
  }

  for( ; RTA_OK( rat, rat_sz ); rat=RTA_NEXT( rat, rat_sz ) ) {
    void * rta    = RTA_DATA( rat );
    ulong  rta_sz = RTA_PAYLOAD( rat );

    switch( rat->rta_type ) {

    case RTA_GATEWAY:
      fd_fib4_rta_gateway( hop, rta, rta_sz );
      break;

    case RTA_DST:
      if( FD_UNLIKELY( rta_sz!=4UL ) ) {
        hop->flags |= FD_FIB4_FLAG_RTA_PARSE_ERR;
        continue;
      }
      ip4_dst = FD_LOAD( uint, rta ); /* big endian */
      prefix  = msg->rtm_dst_len;
      break;

    case RTA_OIF:
      fd_fib4_rta_oif( hop, rta, rta_sz );
      break;

    case RTA_PREFSRC:
      fd_fib4_rta_prefsrc( hop, rta, rta_sz );
      break;

    case RTA_PRIORITY:
      if( FD_UNLIKELY( rta_sz!=4UL ) ) {
        hop->flags |= FD_FIB4_FLAG_RTA_PARSE_ERR;
        continue;
      }
      prio = FD_LOAD( uint, rta ); /* host byte order */
      break;

    case RTA_TABLE:
      /* Skip routes that aren't in the requested table */
      if( FD_UNLIKELY( rta_sz!=4UL ) ) {
        hop->flags |= FD_FIB4_FLAG_RTA_PARSE_ERR;
        continue;
      }
      if( FD_LOAD( uint, rta )!=table_id ) return 0;
      break;

    default:
      FD_LOG_DEBUG(( "Unsupported route table attribute (%u-%s)", rat->rta_type, fd_netlink_rtattr_str( rat->rta_type ) ));
      hop->flags |= FD_FIB4_FLAG_RTA_UNSUPPORTED;
      break;
    }
  }

  if( fd_fib4_free_cnt( fib )==0UL ) return ENOSPC;
  *fd_fib4_append( fib, ip4_dst, prefix, prio ) = *hop;

  return 0;
}

int
fd_fib4_netlink_load_table( fd_fib4_t *    fib,
                            fd_netlink_t * netlink,
                            uint           table_id ) {

  uint seq = netlink->seq++;

  struct {
    struct nlmsghdr nlh;  /* Netlink header */
    struct rtmsg    rtm;  /* Payload - route message */
    struct rtattr   rta;
    uint            table_id;
  } request;
  request.nlh = (struct nlmsghdr) {
    .nlmsg_type  = RTM_GETROUTE,
    .nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP,
    .nlmsg_len   = sizeof(request),
    .nlmsg_seq   = seq
  };
  request.rtm = (struct rtmsg) {
    .rtm_family = AF_INET, /* IPv4 */
  };
  request.rta = (struct rtattr) {
    .rta_type = RTA_TABLE,
    .rta_len  = RTA_LENGTH( sizeof(uint) )
  };
  request.table_id = table_id;

  long send_res = sendto( netlink->fd, &request, sizeof(request), 0, NULL, 0 );
  if( FD_UNLIKELY( send_res<0 ) ) {
    FD_LOG_WARNING(( "netlink send(%d,RTM_GETROUTE,NLM_F_REQUEST|NLM_F_DUMP) failed (%d-%s)", netlink->fd, errno, fd_io_strerror( errno ) ));
    return errno;
  }
  if( FD_UNLIKELY( send_res!=sizeof(request) ) ) {
    FD_LOG_WARNING(( "netlink send(%d,RTM_GETROUTE,NLM_F_REQUEST|NLM_F_DUMP) failed (short write)", netlink->fd ));
    return EPIPE;
  }

  fd_fib4_clear( fib );

  int   dump_intr = 0;
  int   no_space  = 0;
  ulong route_cnt = 0UL;

  uchar buf[ 4096 ];
  fd_netlink_iter_t iter[1];
  for( fd_netlink_iter_init( iter, netlink, buf, sizeof(buf) );
       !fd_netlink_iter_done( iter );
       fd_netlink_iter_next( iter, netlink ) ) {
    struct nlmsghdr const * nlh = fd_netlink_iter_msg( iter );
    if( FD_UNLIKELY( nlh->nlmsg_flags & NLM_F_DUMP_INTR ) ) dump_intr = 1;
    if( FD_UNLIKELY( nlh->nlmsg_type==NLMSG_ERROR ) ) {
      struct nlmsgerr * err = NLMSG_DATA( nlh );
      int nl_err = -err->error;
      FD_LOG_WARNING(( "netlink RTM_GETROUTE,NLM_F_REQUEST|NLM_F_DUMP failed (%d-%s)", nl_err, fd_io_strerror( nl_err ) ));
      return nl_err;
    }
    if( FD_UNLIKELY( nlh->nlmsg_type!=RTM_NEWROUTE ) ) {
      FD_LOG_DEBUG(( "unexpected nlmsg_type %u", nlh->nlmsg_type ));
      continue;
    }
    route_cnt++;

    int translate_err = fd_fib4_netlink_translate( fib, nlh, table_id );
    if( FD_UNLIKELY( translate_err==ENOSPC ) ) {
      no_space = 1;
      break;
    }
  }
  if( FD_UNLIKELY( iter->err > 0 ) ) return FD_FIB_NETLINK_ERR_IO;
  ulong drain_cnt = fd_netlink_iter_drain( iter, netlink );

  if( no_space ) {
    FD_LOG_WARNING(( "Routing table is too small! `ip route show table %u` returned %lu entries, which exceeds the configured maximum of %lu",
                     table_id, route_cnt+drain_cnt, fd_fib4_max( fib ) ));
    fd_fib4_clear( fib );
    return FD_FIB_NETLINK_ERR_SPACE;
  }

  if( dump_intr ) {
    FD_LOG_DEBUG(( "received NLM_F_DUMP_INTR (our read of the routing table was overrun by a concurrent write)" ));
    return FD_FIB_NETLINK_ERR_INTR;
  }

  if( FD_UNLIKELY( drain_cnt ) ) {
    FD_LOG_WARNING(( "Unexpectedly skipped %lu routes. This is a bug!", drain_cnt ));
    return FD_FIB_NETLINK_ERR_OOPS;
  }

  return 0;
}

FD_FN_CONST char const *
fd_fib4_netlink_strerror( int err ) {
  switch( err ) {
  case FD_FIB_NETLINK_SUCCESS:
    return "success";
  case FD_FIB_NETLINK_ERR_OOPS:
    return "oops";
  case FD_FIB_NETLINK_ERR_IO:
    return "io";
  case FD_FIB_NETLINK_ERR_INTR:
    return "interrupt";
  case FD_FIB_NETLINK_ERR_SPACE:
    return "out of space";
  default:
    return "unknown";
  }
}
