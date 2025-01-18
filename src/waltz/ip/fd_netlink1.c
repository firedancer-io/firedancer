#include <sys/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <errno.h>
#include <unistd.h>

#include "fd_netlink1.h"
#include "../../util/fd_util.h"

FD_TL ulong fd_netlink_enobufs_cnt;

static int
fd_nl_create_socket( void ) {
  int fd = socket( AF_NETLINK, SOCK_RAW, NETLINK_ROUTE );

  if( FD_UNLIKELY( fd<0 ) ) {
    FD_LOG_WARNING(( "socket(AF_NETLINK,SOCK_RAW,NETLINK_ROUTE) failed (%i-%s)",
                      errno, fd_io_strerror( errno ) ));
    return -1;
  }

  int one = 1;
  if( setsockopt( fd, SOL_NETLINK, NETLINK_EXT_ACK, &one, sizeof(one) )<0 ) {
    FD_LOG_WARNING(( "setsockopt(sock,SOL_NETLINK,NETLINK_EXT_ACK) failed (%i-%s)",
                     errno, fd_io_strerror( errno ) ));
    close( fd );
    return -1;
  }

  return fd;
}

static void
fd_nl_close_socket( int fd ) {
  if( fd >= 0 ) {
    close( fd );
  }
}

long
fd_netlink_read_socket( int     fd,
                        uchar * buf,
                        ulong   buf_sz ) {
  /* netlink is datagram based
     once a recv succeeds, any un-received bytes are lost
     and the next datagram will be properly aligned in the buffer */
  for(;;) {
    long len = recvfrom( fd, buf, buf_sz, 0, NULL, NULL );
    if( FD_UNLIKELY( len<=0L ) ) {
      if( len==0L      ) continue;
      if( errno==EINTR ) continue;
      if( errno==ENOBUFS ) {
        fd_netlink_enobufs_cnt++;
        continue;
      }
      FD_LOG_WARNING(( "netlink recv failed (%d-%s)", errno, fd_io_strerror( errno ) ));
      return -(long)errno;
    }
    return len;
  }
}

fd_netlink_t *
fd_netlink_init( fd_netlink_t * nl,
                 uint           seq0 ) {
  nl->fd = fd_nl_create_socket();
  if( FD_UNLIKELY( nl->fd<0 ) ) return NULL;
  nl->seq = seq0;
  return nl;
}

void *
fd_netlink_fini( fd_netlink_t * nl ) {
  fd_nl_close_socket( nl->fd );
  nl->fd = -1;
  return nl;
}

static void
fd_netlink_iter_recvmsg( fd_netlink_iter_t * iter,
                         fd_netlink_t *      netlink ) {
  long len = fd_netlink_read_socket( netlink->fd, iter->buf, iter->buf_sz );
  if( len<0L ) {
    iter->err = (int)-len;
    return;
  }
  iter->msg0 = iter->buf;
  iter->msg1 = iter->buf+len;
}

/* fd_netlink_iter_verify_next bounds checks the next message.  If out-of-
   bounds, logs warning and sets error EPROTO.  This prevents the iterator
   from returning an out-of-bounds netlink message. */

static void
fd_netlink_iter_bounds_check( fd_netlink_iter_t * iter ) {
  if( fd_netlink_iter_done( iter ) ) return;

  struct nlmsghdr const * nlh = fd_type_pun_const( iter->msg0 );
  if( FD_UNLIKELY( iter->msg0 + sizeof(struct nlmsghdr) > iter->msg1 ) ) {
    FD_LOG_WARNING(( "netlink message header out-of-bounds" ));
    iter->err = EPROTO;
    return;
  }
  if( FD_UNLIKELY( nlh->nlmsg_len < sizeof(struct nlmsghdr) ) ) {
    /* prevent infinite loop */
    FD_LOG_WARNING(( "netlink message smaller than header" ));
    iter->err = EPROTO;
    return;
  }
  if( FD_UNLIKELY( iter->msg0 + nlh->nlmsg_len > iter->msg1 ) ) {
    FD_LOG_WARNING(( "netlink message out-of-bounds: cur=[%p,%p) buf=[%p,%p)",
                     (void *)iter->msg0, (void *)iter->msg1, (void *)iter->buf, (void *)( iter->buf+iter->buf_sz ) ));
    iter->err = EPROTO;
    return;
  }
}

fd_netlink_iter_t *
fd_netlink_iter_init( fd_netlink_iter_t * iter,
                      fd_netlink_t *      netlink,
                      uchar *             buf,
                      ulong               buf_sz ) {
  *iter = (fd_netlink_iter_t) {
    .buf    = buf,
    .buf_sz = buf_sz,
    .msg0   = buf,
    .msg1   = buf,
  };

  fd_netlink_iter_recvmsg( iter, netlink );
  fd_netlink_iter_bounds_check( iter );

  return iter;
}

int
fd_netlink_iter_done( fd_netlink_iter_t const * iter ) {
  if( (iter->err!=0) | ( iter->msg1 - iter->msg0 < (long)sizeof(struct nlmsghdr) ) ) {
    return 1;
  }
  struct nlmsghdr const * nlh = fd_type_pun_const( iter->msg0 );
  return nlh->nlmsg_type==NLMSG_DONE;
}

fd_netlink_iter_t *
fd_netlink_iter_next( fd_netlink_iter_t * iter,
                      fd_netlink_t *      netlink ) {

  if( fd_netlink_iter_done( iter ) ) return iter;

  struct nlmsghdr const * nlh = fd_type_pun_const( iter->msg0 );
  if( !(nlh->nlmsg_flags & NLM_F_MULTI) ) {
    /* Last message was not a multipart message */
    iter->err = -1; /* eof */
    return iter;
  }
  iter->msg0 += NLMSG_ALIGN( nlh->nlmsg_len );

  if( iter->msg0 >= iter->msg1 ) {
    fd_netlink_iter_recvmsg( iter, netlink );
  }
  fd_netlink_iter_bounds_check( iter );

  return iter;
}

char const *
fd_netlink_rtm_type_str( int rtm_type ) {
  switch( rtm_type ) {
  case RTN_UNSPEC:      return "unspec";
  case RTN_UNICAST:     return "unicast";
  case RTN_LOCAL:       return "local";
  case RTN_BROADCAST:   return "broadcast";
  case RTN_ANYCAST:     return "anycast";
  case RTN_MULTICAST:   return "multicast";
  case RTN_BLACKHOLE:   return "blackhole";
  case RTN_UNREACHABLE: return "unreachable";
  case RTN_PROHIBIT:    return "prohibit";
  case RTN_THROW:       return "throw";
  case RTN_NAT:         return "nat";
  case RTN_XRESOLVE:    return "xresolve";
  default:              return "unknown";
  }
}

char const *
fd_netlink_rtattr_str( int rta_type ) {
  switch( rta_type ) {
  /* These exist since at least Linux v3.7 */
  case RTA_DST:                return "dst";
  case RTA_SRC:                return "src";
  case RTA_IIF:                return "iif";
  case RTA_OIF:                return "oif";
  case RTA_GATEWAY:            return "gateway";
  case RTA_PRIORITY:           return "priority";
  case RTA_PREFSRC:            return "prefsrc";
  case RTA_METRICS:            return "metrics";
  case RTA_MULTIPATH:          return "multipath";
  case RTA_FLOW:               return "flow";
  case RTA_CACHEINFO:          return "cacheinfo";
  case RTA_TABLE:              return "table";
  case RTA_MARK:               return "mark";
#ifdef RTA_MFC_STATS
  case RTA_MFC_STATS:          return "mfc_stats";
#endif
#ifdef RTA_VIA
  case RTA_VIA:                return "via";
#endif
#ifdef RTA_NEWDST
  case RTA_NEWDST:             return "newdst";
#endif
#ifdef RTA_PREF
  case RTA_PREF:               return "pref";
#endif
#ifdef RTA_ENCAP_TYPE
  case RTA_ENCAP_TYPE:         return "encap_type";
#endif
#ifdef RTA_ENCAP
  case RTA_ENCAP:              return "encap";
#endif
#ifdef RTA_EXPIRES
  case RTA_EXPIRES:            return "expires";
#endif
#ifdef RTA_PAD
  case RTA_PAD:                return "pad";
#endif
#ifdef RTA_UID
  case RTA_UID:                return "uid";
#endif
#ifdef RTA_TTL_PROPAGATE
  case RTA_TTL_PROPAGATE:      return "ttl_propagate";
#endif
#ifdef RTA_IP_PROTO
  case RTA_IP_PROTO:           return "ip_proto";
#endif
#ifdef RTA_SPORT
  case RTA_SPORT:              return "sport";
#endif
#ifdef RTA_DPORT
  case RTA_DPORT:              return "dport";
#endif
#ifdef RTA_NH_ID
  case RTA_NH_ID:              return "nh_id";
#endif
  default:                     return "unknown";
  }
}
