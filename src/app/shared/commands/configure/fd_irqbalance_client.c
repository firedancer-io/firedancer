#define _GNU_SOURCE
#include "fd_irqbalance_client.h"
#include <errno.h>
#include <dirent.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#define IRQBALANCE_RUN_DIR "/run/irqbalance"

static int
fd_irqbalance_connect( char const * path ) {
  int sock = socket( AF_UNIX, SOCK_STREAM, 0 );
  if( sock<0 ) return -1;

  int err;

  if( FD_UNLIKELY( setsockopt( sock, SOL_SOCKET, SO_PASSCRED, &(int){1}, sizeof(int) )<0 ) ) {
    err = errno;
    goto cleanup;
  }

  struct sockaddr_un addr;
  addr.sun_family = AF_UNIX;
  if( FD_UNLIKELY( strlen( path ) >= sizeof(addr.sun_path) ) ) {
    err = ENOENT;
    goto cleanup;
  }
  strcpy( addr.sun_path, path );

  if( FD_UNLIKELY( connect( sock, fd_type_pun( &addr ), sizeof(addr) )<0 ) ) {
    err = errno;
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

char const *
fd_irqbalance_socket_path( char * path,
                           ulong  path_max ) {
  /* Unfortunately the irqbalance daemon does not use a fixed file path */
  DIR * dir = opendir( "/run/irqbalance" );
  if( FD_UNLIKELY( !dir ) ) return NULL;
  struct dirent * entry;
  char const * ret = NULL;
  while( (entry = readdir( dir )) ) {
    if( FD_UNLIKELY( entry->d_type!=DT_SOCK ) ) continue;
    if( FD_UNLIKELY( strncmp( entry->d_name, "irqbalance", 10 ) ) ) continue;
    FD_TEST( fd_cstr_printf_check( path, path_max, NULL, "%s/%s", IRQBALANCE_RUN_DIR, entry->d_name ) );
    int sock = fd_irqbalance_connect( path );
    if( FD_UNLIKELY( sock<0 ) ) {
      FD_LOG_WARNING(( "failed to connect to %s/%s (%i-%s)", IRQBALANCE_RUN_DIR, entry->d_name, errno, fd_io_strerror( errno ) ));
      continue;
    }
    if( FD_UNLIKELY( 0!=close( sock ) ) ) {
      FD_LOG_ERR(( "close(%s/%s) failed (%i-%s)", IRQBALANCE_RUN_DIR, entry->d_name, errno, fd_io_strerror( errno ) ));
    }
    ret = path;
    break;
  }
  if( FD_UNLIKELY( closedir( dir ) ) ) {
    FD_LOG_ERR(( "closedir() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
  return ret;
}

static void
fd_irqbalance_request( char const * irqbalance_path,
                       void const * req,
                       ulong        req_len ) {

  int fd = fd_irqbalance_connect( irqbalance_path );
  if( FD_UNLIKELY( fd<0 ) ) {
    FD_LOG_ERR(( "failed to connect to %s (%i-%s)", irqbalance_path, errno, fd_io_strerror( errno ) ));
    return;
  }

  if( FD_UNLIKELY( send( fd, req, req_len, 0 )<0 ) ) {
    FD_LOG_WARNING(( "failed to send command to %s (%i-%s)", irqbalance_path, errno, fd_io_strerror( errno ) ));
    goto cleanup;
  }
  if( FD_UNLIKELY( 0!=shutdown( fd, SHUT_WR ) ) ) {
    FD_LOG_WARNING(( "shutdown(%s) failed (%i-%s)", irqbalance_path, errno, fd_io_strerror( errno ) ));
    goto cleanup;
  }

cleanup:
  if( FD_UNLIKELY( 0!=close( fd ) ) ) {
    FD_LOG_ERR(( "close(%s) failed (%i-%s)", irqbalance_path, errno, fd_io_strerror( errno ) ));
  }
}

void
fd_irqbalance_ban_cpus( fd_cpuset_t const * cpuset,
                        char const *        irqbalance_path ) {

  /* 1024x (FD_TILE_MAX) space-separated 4 char strings is approx 5kB */
  char req[ 16384 ];
  char * p = fd_cstr_init( req );
  p = fd_cstr_append_cstr( p, "settings cpus " );
  for( ulong iter = fd_cpuset_const_iter_init( cpuset );
       !fd_cpuset_const_iter_done( iter );
       iter = fd_cpuset_const_iter_next( cpuset, iter ) ) {
    if( FD_UNLIKELY( p-req+32 >= (long)sizeof(req) ) ) break; /* unreachable */
    p = fd_cstr_append_ulong_as_text( p, 0, 0, iter, fd_ulong_base10_dig_cnt( iter ) );
    p = fd_cstr_append_char( p, ' ' );
  }
  ulong len = (ulong)( p - req );
  fd_cstr_fini( p );

  fd_irqbalance_request( irqbalance_path, req, len );
}
