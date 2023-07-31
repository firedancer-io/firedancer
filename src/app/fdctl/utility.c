#define _GNU_SOURCE
#include "utility.h"

#include <unistd.h>
#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <fcntl.h>
#include <sched.h>

#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

static int entered = 0;

void
enter_network_namespace( config_t * const config ) {
  if( FD_LIKELY( !config->development.netns.enabled || entered ) ) return;
  entered = 1;

  char path[ PATH_MAX ];
  snprintf1( path, PATH_MAX, "/var/run/netns/%s", config->tiles.quic.interface );

  int fd = open( path, O_RDONLY | O_CLOEXEC );
  if( FD_UNLIKELY( fd < 0 ) ) FD_LOG_ERR(( "failed to open `%s` (%i-%s)", path, errno, strerror( errno ) ));
  if( FD_UNLIKELY( setns( fd, CLONE_NEWNET ) ) ) FD_LOG_ERR(( "failed to enter network namespace `%s` (%i-%s)", path, errno, strerror( errno ) ));
}

void
exit_group( int status ) {
  syscall( SYS_exit_group, status );
}

void
mkdir_all( const char * _path,
           uid_t uid,
           gid_t gid ) {
  char path[ PATH_MAX + 1 ] = {0};
  strncpy( path, _path, PATH_MAX );

  char * p = path;
  if( FD_LIKELY( *p == '/' ) ) p++;
  while( FD_LIKELY( *p ) ) {
    if( FD_UNLIKELY( *p == '/' ) ) {
      *p = '\0';
      if( FD_UNLIKELY( mkdir( path, 0777 ) && errno != EEXIST ) )
        FD_LOG_ERR(( "mkdir( `%s` ) failed (%i-%s)", path, errno, strerror( errno ) ) );
      if( FD_UNLIKELY( chown( path, uid, gid ) ) )
        FD_LOG_ERR(( "chown `%s` failed (%i-%s)", path, errno, strerror( errno ) ));
      if( FD_UNLIKELY( chmod( path, S_IRUSR | S_IWUSR | S_IXUSR ) ) )
        FD_LOG_ERR(( "chmod `%s` failed (%i-%s)", path, errno, strerror( errno ) ));
      *p = '/';
    }
    p++;
  }
  if( FD_UNLIKELY( mkdir( path, 0777 ) && errno != EEXIST ) )
    FD_LOG_ERR(( "mkdir( `%s` ) failed (%i-%s)", path, errno, strerror( errno ) ) );
  if( FD_UNLIKELY( chown( path, uid, gid ) ) )
    FD_LOG_ERR(( "chown `%s` failed (%i-%s)", path, errno, strerror( errno ) ));
  if( FD_UNLIKELY( chmod( path, S_IRUSR | S_IWUSR | S_IXUSR ) ) )
    FD_LOG_ERR(( "chmod `%s` failed (%i-%s)", path, errno, strerror( errno ) ));
}

int
internet_routing_interface( void ) {
  int sock = socket( AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE );
  if( FD_UNLIKELY( sock < 0 ) ) FD_LOG_ERR(( "error finding default interface, socket(AF_INET,SOCK_DGRAM,0) failed (%i-%s)", errno, strerror( errno ) ));

  struct {
    struct nlmsghdr nlh;
    struct rtmsg rt;
    char buf[8192];
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

  unsigned int ip = (8 << 24) | (8 << 16) | (8 << 8) | 8;
  fd_memcpy( RTA_DATA( rta ), &ip, 4 );

  if( FD_UNLIKELY( send( sock, &request, request.nlh.nlmsg_len, 0 ) < 0 ) )
    FD_LOG_ERR(( "error finding default interface, send() failed (%i-%s)", errno, strerror( errno ) ));

  char response[ 8192 ];
  long len = recv( sock, response, sizeof(response), 0 );
  if( FD_UNLIKELY( len == sizeof( response ) ) )
    FD_LOG_ERR(( "error finding default interface, response too large" ));

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

  if( FD_UNLIKELY( close( sock ) ) )
    FD_LOG_ERR(( "error finding default interface, close() socket failed (%i-%s)", errno, strerror( errno ) ));

  return result;
}

void
nanosleep1( uint secs, uint nanos ) {
  struct timespec ts = { .tv_sec = secs, .tv_nsec = nanos };
  struct timespec rem;
  while( FD_UNLIKELY( nanosleep( &ts, &rem ) ) ) {
    if( FD_LIKELY( errno == EINTR ) ) ts = rem;
    else FD_LOG_ERR(( "nanosleep failed (%i-%s)", errno, strerror( errno ) ));
  }
}

char *
snprintf1( char * s,
           ulong  maxlen,
           char * format,
           ... ) {
  va_list args;
  va_start( args, format );
  int len = vsnprintf( s, maxlen, format, args );
  va_end( args );
  if( FD_UNLIKELY( len < 0 ) )
    FD_LOG_ERR(( "vsnprintf failed (%i-%s)", errno, strerror( errno ) ));
  if( FD_UNLIKELY( (ulong)len >= maxlen ) )
    FD_LOG_ERR(( "vsnprintf truncated output (maxlen=%lu)", maxlen ));
  return s;
}

void
self_exe( char * path ) {
  long count = readlink( "/proc/self/exe", path, PATH_MAX );
  if( FD_UNLIKELY( count < 0 ) ) FD_LOG_ERR(( "readlink(/proc/self/exe) failed (%i-%s)", errno, strerror( errno ) ));
  if( FD_UNLIKELY( count >= PATH_MAX ) ) FD_LOG_ERR(( "readlink(/proc/self/exe) returned truncated path" ));
  path[ count ] = '\0';
}
