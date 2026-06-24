#define _GNU_SOURCE
#include "fd_irqbalance_client.h"
#include <errno.h>
#include <dirent.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#define IRQBALANCE_RUN_DIR "/run/irqbalance"

static int
fd_irqbalance_connect1( char const * path ) {
  int sock = socket( AF_UNIX, SOCK_STREAM, 0 );
  if( FD_UNLIKELY( sock<0 ) ) FD_LOG_ERR(( "socket(AF_UNIX,SOCK_STREAM) failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  int err;

  if( FD_UNLIKELY( setsockopt( sock, SOL_SOCKET, SO_PASSCRED, &(int){1}, sizeof(int) )<0 ) ) {
    FD_LOG_ERR(( "setsockopt(SO_PASSCRED) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }

  struct sockaddr_un addr;
  fd_memset( &addr, 0, sizeof(addr) );
  addr.sun_family = AF_UNIX;
  if( FD_UNLIKELY( strlen( path ) >= sizeof(addr.sun_path) ) ) {
    err = ENOENT;
    goto cleanup;
  }
  strcpy( addr.sun_path, path );

  if( FD_UNLIKELY( connect( sock, fd_type_pun( &addr ), sizeof(addr) )<0 ) ) {
    err = errno;
    if( FD_UNLIKELY( err!=ENOENT && err!=ECONNREFUSED && err!=EACCES ) ) {
      FD_LOG_ERR(( "connect(`%s`) failed (%i-%s)", path, err, fd_io_strerror( err ) ));
    }
    goto cleanup;
  }

  return sock;

cleanup:
  if( FD_UNLIKELY( 0!=close( sock ) ) ) {
    FD_LOG_ERR(( "close() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
  errno = err;
  return -1;
}

static int
fd_irqbalance_connect( void ) {
  /* Unfortunately the irqbalance daemon does not use a fixed file path */
  char path[ PATH_MAX ];
  DIR * dir = opendir( "/run/irqbalance" );
  if( FD_UNLIKELY( !dir ) ) {
    if( FD_UNLIKELY( errno!=ENOENT && errno!=EACCES ) ) {
      FD_LOG_ERR(( "opendir(`%s`) failed (%i-%s)", IRQBALANCE_RUN_DIR, errno, fd_io_strerror( errno ) ));
    }
    return -1;
  }
  struct dirent * entry;
  int sock = -1;
  int err = ENOENT;
  while( (entry = readdir( dir )) ) {
    if( FD_UNLIKELY( entry->d_type!=DT_SOCK ) ) continue;
    if( FD_UNLIKELY( strncmp( entry->d_name, "irqbalance", 10 ) ) ) continue;
    FD_TEST( fd_cstr_printf_check( path, PATH_MAX, NULL, "%s/%s", IRQBALANCE_RUN_DIR, entry->d_name ) );
    sock = fd_irqbalance_connect1( path );
    if( FD_UNLIKELY( sock<0 ) ) {
      err = errno;
      if( FD_UNLIKELY( errno==EACCES ) ) break;
      continue;
    }
    break;
  }
  if( FD_UNLIKELY( closedir( dir ) ) ) {
    FD_LOG_ERR(( "closedir() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
  if( FD_UNLIKELY( sock<0 ) ) errno = err;
  return sock;
}

static int
fd_irqbalance_send( int          fd,
                    void const * req,
                    ulong        req_len ) {
  struct iovec iov = {
    .iov_base = (void *)req,
    .iov_len  = req_len
  };

  union {
    struct cmsghdr hdr;
    uchar          buf[ CMSG_SPACE( sizeof(struct ucred) ) ];
  } ctrl;
  fd_memset( &ctrl, 0, sizeof(ctrl) );

  struct msghdr msg;
  fd_memset( &msg, 0, sizeof(msg) );
  msg.msg_iov        = &iov;
  msg.msg_iovlen     = 1U;
  msg.msg_control    = ctrl.buf;
  msg.msg_controllen = sizeof(ctrl.buf);

  struct cmsghdr * cmsg = CMSG_FIRSTHDR( &msg );
  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type  = SCM_CREDENTIALS;
  cmsg->cmsg_len   = CMSG_LEN( sizeof(struct ucred) );

  struct ucred cred = {
    .pid = getpid(),
    .uid = geteuid(),
    .gid = getegid()
  };
  fd_memcpy( CMSG_DATA( cmsg ), &cred, sizeof(cred) );

  return sendmsg( fd, &msg, MSG_NOSIGNAL )==(long)req_len;
}

static int
fd_irqbalance_request( void const * req,
                       ulong        req_len,
                       char *       resp,
                       ulong        resp_sz ) {

  if( FD_LIKELY( resp && resp_sz ) ) resp[0] = '\0';

  int fd = fd_irqbalance_connect();
  if( FD_UNLIKELY( fd<0 ) ) return -1;

  if( FD_UNLIKELY( !fd_irqbalance_send( fd, req, req_len ) ) ) {
    FD_LOG_ERR(( "failed to send command to irqbalance (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
  if( FD_UNLIKELY( 0!=shutdown( fd, SHUT_WR ) ) ) {
    FD_LOG_ERR(( "shutdown(irqbalance_sock_fd) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
  if( FD_LIKELY( resp ) ) {
    ulong off = 0UL;
    for(;;) {
      long n = recv( fd, resp+off, resp_sz-off-1UL, 0 );
      if( FD_UNLIKELY( n<0 ) ) {
        if( FD_UNLIKELY( errno==EINTR ) ) continue;
        FD_LOG_ERR(( "failed to recv response from irqbalance (%i-%s)", errno, fd_io_strerror( errno ) ));
      }
      if( !n ) break; /* EOF */
      off += (ulong)n;
      if( FD_UNLIKELY( off>=resp_sz-1UL ) ) {
        FD_LOG_ERR(( "response from irqbalance is too large for the receive buffer (>=%lu)", resp_sz ));
      }
    }
    if( FD_UNLIKELY( !off ) ) {
      /* The daemon accepted the connection but closed it without replying.
         It does this when it rejects our SCM_CREDENTIALS (non-root), so
         treat an empty response as the expected permission error. */
      if( FD_UNLIKELY( 0!=close( fd ) ) ) {
        FD_LOG_ERR(( "close(irqbalance_sock_fd) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
      }
      errno = EACCES;
      return -1;
    }
    resp[ off ] = '\0';
  }

  if( FD_UNLIKELY( 0!=close( fd ) ) ) {
    FD_LOG_ERR(( "close(irqbalance_sock_fd) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
  return 0;
}

int
fd_irqbalance_ban_cpus_set( fd_cpuset_t const * cpuset ) {
  /* 1024x (FD_TILE_MAX) comma-separated 4 char strings is approx 5kB */
  char req[ 16384 ];
  char * p = fd_cstr_init( req );
  p = fd_cstr_append_cstr( p, "settings cpus " );
  int first = 1;
  for( ulong iter = fd_cpuset_const_iter_init( cpuset );
       !fd_cpuset_const_iter_done( iter );
       iter = fd_cpuset_const_iter_next( cpuset, iter ) ) {
    if( FD_LIKELY( !first ) ) p = fd_cstr_append_char( p, ',' );
    else                      first = 0;
    if( FD_UNLIKELY( p-req+32 >= (long)sizeof(req) ) ) break; /* unreachable */
    p = fd_cstr_append_ulong_as_text( p, 0, 0, iter, fd_ulong_base10_dig_cnt( iter ) );
  }
  if( FD_UNLIKELY( first ) ) p = fd_cstr_append_cstr( p, "NULL" );
  ulong len = (ulong)( p - req );
  fd_cstr_fini( p );

  return fd_irqbalance_request( req, len, NULL, 0UL );
}

static int
fd_irqbalance_hex_digit( char c ) {
  if( FD_LIKELY( (c>='0') & (c<='9') ) ) return c-'0';
  if( FD_LIKELY( (c>='a') & (c<='f') ) ) return 10+c-'a';
  if( FD_LIKELY( (c>='A') & (c<='F') ) ) return 10+c-'A';
  return -1;
}

int
fd_irqbalance_ban_cpus_get( fd_cpuset_t * cpuset ) {
  char resp[ 16384 ];
  fd_cpuset_new( cpuset );

  int err = fd_irqbalance_request( "setup", 5UL, resp, sizeof(resp) );
  if( FD_UNLIKELY( -1==err ) ) return -1;

  char * banned = strstr( resp, "BANNED " );
  if( FD_UNLIKELY( !banned ) ) {
    FD_LOG_ERR(( "failed to parse irqbalance setup response: missing BANNED token" ));
  }

  banned += 7UL;
  char * end = banned;
  while( FD_LIKELY( *end && (*end!=' ') ) ) end++;

  ulong cpu = 0UL;
  for( char * p=end; p>banned; ) {
    p--;
    if( FD_UNLIKELY( *p==',' ) ) continue;

    int digit = fd_irqbalance_hex_digit( *p );
    if( FD_UNLIKELY( digit<0 ) ) {
      FD_LOG_ERR(( "failed to parse irqbalance banned CPU mask" ));
    }

    for( ulong bit=0UL; bit<4UL; bit++ ) {
      if( FD_UNLIKELY( cpu>=FD_TILE_MAX ) ) {
        FD_LOG_ERR(( "irqbalance banned CPU mask exceeds FD_TILE_MAX (%lu) CPUs", (ulong)FD_TILE_MAX ));
      }
      if( FD_UNLIKELY( digit & (1<<bit) ) ) fd_cpuset_insert( cpuset, cpu );
      cpu++;
    }
  }

  return 0;
}
