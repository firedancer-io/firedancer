#define _GNU_SOURCE
#include "fd_net_util.h"

#include <fcntl.h>
#include <errno.h>
#include <sched.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <netinet/in.h>

int
fd_net_util_internet_ifindex( uint * ifindex ) {
  int sock = socket( AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE );
  if( FD_UNLIKELY( -1==sock ) ) return -1;

  struct {
    struct nlmsghdr nlh;
    struct rtmsg rt;
    char buf[ 8192UL ];
  } request;

  memset(&request, 0, sizeof(request));
  request.nlh.nlmsg_len   = NLMSG_LENGTH(sizeof(struct rtmsg));
  request.nlh.nlmsg_flags = NLM_F_REQUEST;
  request.nlh.nlmsg_type  = RTM_GETROUTE;
  request.rt.rtm_family   = AF_INET;
  request.rt.rtm_dst_len  = 32;

  struct rtattr *rta = (struct rtattr *)( ( (char *)&request ) + NLMSG_ALIGN( request.nlh.nlmsg_len ) );
  rta->rta_len          = RTA_LENGTH(4);
  rta->rta_type         = RTA_DST;
  request.nlh.nlmsg_len = NLMSG_ALIGN( request.nlh.nlmsg_len ) + (uint)RTA_LENGTH( 4 );

  uint ip = (8 << 24) | (8 << 16) | (8 << 8) | 8;
  fd_memcpy( RTA_DATA( rta ), &ip, 4 );

  long sent = send( sock, &request, request.nlh.nlmsg_len, 0 );
  if( FD_UNLIKELY( -1==sent ) ) {
    close( sock );
    return -1;
  }
  FD_TEST( sent==request.nlh.nlmsg_len );

  char response[ 8192UL ];
  long len = recv( sock, response, sizeof(response), 0 );
  if( FD_UNLIKELY( -1==len ) ) {
    close( sock );
    return -1;
  } else if( FD_UNLIKELY( len==sizeof(response) ) ) {
    errno = ENOBUFS;
    close( sock );
    return -1;
  }

  struct nlmsghdr *nlh;
  int result = -1;
  for( nlh = (struct nlmsghdr *)response; NLMSG_OK( nlh, len ); nlh = NLMSG_NEXT( nlh, len ) ) {
      struct rtmsg *rt = NLMSG_DATA( nlh );

      struct rtattr *rta = RTM_RTA( rt );
      uint rtl = (uint)RTM_PAYLOAD( nlh );

      for (; RTA_OK( rta, rtl ); rta = RTA_NEXT( rta, rtl ) ) {
          if (rta->rta_type == RTA_OIF) {
            result = *(int *)RTA_DATA(rta);
          }
      }
  }

  if( FD_UNLIKELY( -1==close( sock ) ) ) return -1;

  if( FD_LIKELY( result>=0 ) ) {
    *ifindex = (uint)result;
    return 0;
  } else {
    errno = ENODEV;
    return -1;
  }
}

int
fd_net_util_if_addr( const char * interface,
                     uint *       addr ) {
  int fd = socket( AF_INET, SOCK_DGRAM, 0 );
  if( FD_UNLIKELY( -1==fd ) ) return -1;

  struct ifreq ifr = {0};
  ifr.ifr_addr.sa_family = AF_INET;
  strncpy( ifr.ifr_name, interface, IFNAMSIZ );
  ifr.ifr_name[ IFNAMSIZ-1 ] = '\0';

  if( FD_UNLIKELY( -1==ioctl( fd, SIOCGIFADDR, &ifr ) ) ) return -1;
  if( FD_UNLIKELY( -1==close( fd ) ) ) return -1;

  *addr = ((struct sockaddr_in *)fd_type_pun( &ifr.ifr_addr ))->sin_addr.s_addr;
  return 0;
}
