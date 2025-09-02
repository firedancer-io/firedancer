#include "../../../../util/fd_util.h"
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/genetlink.h>
#include <linux/ethtool_netlink.h>
#include <arpa/inet.h>

#define NLA_DATA(nla)  ((void *)((char*)(nla) + NLA_HDRLEN))
#define NLA_PAYLOAD(nla) ((int)((nla)->nla_len) - NLA_HDRLEN)
#define NLA_OK(nla,len) ((len) >= (int)sizeof(struct nlattr) && \
                        (nla)->nla_len >= sizeof(struct nlattr) && \
                        (nla)->nla_len <= (len))
#define NLA_NEXT(nla,len) ((len) -= NLA_ALIGN((nla)->nla_len), \
                          (struct nlattr*)(((char*)(nla)) + NLA_ALIGN((nla)->nla_len)))

#define NLMSG_TAIL(nlh) (void *)((char *)(nlh) + NLMSG_ALIGN((nlh)->nlmsg_len))

struct fd_ethtool_nl {
  int fd;
};

typedef struct fd_ethtool_nl fd_ethtool_nl_t;

static int
fd_ethtool_nl_get_family( int fd ) {
  struct {
    struct nlmsghdr   nlh;
    struct genlmsghdr gnlh;
    struct nlattr     attr;
    char              buf[ 8 ];
  } req = {
    .nlh = {
      .nlmsg_len   = sizeof(req),
      .nlmsg_type  = GENL_ID_CTRL,
      .nlmsg_flags = NLM_F_REQUEST,
      .nlmsg_seq   = 1
    },
    .gnlh = {
      .cmd     = CTRL_CMD_GETFAMILY,
      .version = 1
    },
    .attr = {
      .nla_type = CTRL_ATTR_FAMILY_NAME,
      .nla_len  = sizeof(struct nlattr) + 7
    }
  };
  fd_memcpy( req.buf, "ethtool", 8 );

  if( FD_UNLIKELY( send( fd, &req, req.nlh.nlmsg_len, 0 )<0 ) ) {
    FD_LOG_WARNING(( "send(CTRL_CMD_GETFAMILY) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    return -errno;
  }

  struct {
    struct nlmsghdr   nlh;
    struct genlmsghdr gnlh;
    uchar             buf[ 2048 ];
  } resp;
  if( FD_UNLIKELY( recv( fd, &resp, sizeof(resp), 0 )<0 ) ) {
    FD_LOG_WARNING(( "recv(CTRL_CMD_GETFAMILY) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    return -errno;
  }
  if( FD_UNLIKELY( !NLMSG_OK( &resp.nlh, sizeof(resp) ) ) ) {
    FD_LOG_WARNING(( "recv(CTRL_CMD_GETFAMILY) returned invalid message" ));
    return -EPROTO;
  }
  if( FD_UNLIKELY( resp.nlh.nlmsg_type==NLMSG_ERROR ) ) {
    struct nlmsgerr * err = NLMSG_DATA( &resp.nlh );
    FD_LOG_WARNING(( "netlink-genl CTRL_CMD_GETFAMILY failed (%d-%s)", err->error, fd_io_strerror( -err->error ) ));
    return err->error;
  }
  struct nlattr const * nla = fd_type_pun_const( resp.buf );
  int rem = (int)resp.nlh.nlmsg_len - (int)offsetof( __typeof__( resp ), buf );
  while( NLA_OK( nla, rem ) ) {
    if( nla->nla_type==CTRL_ATTR_FAMILY_ID ) {
      return (int)FD_LOAD( ushort, NLA_DATA( nla ) );
    }
    nla = NLA_NEXT( nla, rem );
  }
  FD_LOG_WARNING(( "netlink-genl CTRL_CMD_GETFAMILY returned no family ID" ));
  return -1;
}

fd_ethtool_nl_t *
fd_ethtool_nl_init( void ) {
  int fd = socket( PF_NETLINK, SOCK_RAW, NETLINK_GENERIC );
  if( FD_UNLIKELY( fd<0 ) ) {
    FD_LOG_WARNING(( "socket(PF_NETLINK,SOCK_RAW,NETLINK_GENERIC) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    return NULL;
  }

  struct sockaddr_nl sa = {
    .nl_family = AF_NETLINK
  };
  if( FD_UNLIKELY( bind( fd, fd_type_pun_const( &sa ), sizeof(struct sockaddr_nl) ) ) ) {
    FD_LOG_WARNING(( "bind(AF_NETLINK) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    close( fd );
    return NULL;
  }

  ushort family_id = fd_ethtool_nl_get_family( fd );
  FD_LOG_NOTICE(( "family: %hu", family_id ));
  return NULL;
}

void
fd_ethtool_nl_fini( fd_ethtool_nl_t * nl ) {
  close( nl->fd );
}
