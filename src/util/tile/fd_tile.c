#define _GNU_SOURCE
#include <errno.h>
#include <sched.h>

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

#include "fd_tile_private.h"

int
fd_cpuset_getaffinity( ulong         pid,
                       fd_cpuset_t * mask ) {
# if defined(__linux__)
  return sched_getaffinity( (int)pid, fd_cpuset_word_cnt<<3, (cpu_set_t *)fd_type_pun( mask ) );
# else
  (void)pid; (void)mask;
  errno = ENOTSUP;
  return -1;
# endif
}

int
fd_cpuset_setaffinity( ulong               pid,
                       fd_cpuset_t const * mask ) {
# if defined(__linux__)
  return sched_setaffinity( (int)pid, fd_cpuset_word_cnt<<3, (cpu_set_t const *)fd_type_pun_const( mask ) );
# else
  (void)pid; (void)mask;
  errno = ENOTSUP;
  return -1;
# endif
}

ulong
fd_tile_private_sibling_parse( char const * list,
                               ulong        cpu_idx ) {
  ulong cnt     = 0UL;
  ulong other   = ULONG_MAX;
  int   found   = 0;
  char const * p = list;
  for(;;) {
    if( FD_UNLIKELY( !fd_isdigit( (int)p[0] ) ) ) return ULONG_MAX-1UL;
    char * end;
    ulong lo = strtoul( p, &end, 10 );
    ulong hi = lo;
    p = end;
    if( p[0]=='-' ) {
      p++;
      if( FD_UNLIKELY( !fd_isdigit( (int)p[0] ) ) ) return ULONG_MAX-1UL;
      hi = strtoul( p, &end, 10 );
      p  = end;
    }
    if( FD_UNLIKELY( hi<lo || hi>=FD_TILE_MAX ) ) return ULONG_MAX-1UL;
    cnt += hi-lo+1UL;
    if( cpu_idx>=lo && cpu_idx<=hi ) found = 1;
    if( lo!=cpu_idx )      other = lo;
    else if( hi!=cpu_idx ) other = hi;
    if( p[0]!=',' ) break;
    p++;
  }
  if( FD_UNLIKELY( !( p[0]=='\0' || ( p[0]=='\n' && p[1]=='\0' ) ) || !found || cnt>2UL ) ) return ULONG_MAX-1UL;
  return cnt==2UL ? other : ULONG_MAX;
}

ulong
fd_tile_private_sibling_idx( ulong cpu_idx ) {
# if defined(__linux__)
  char path[ PATH_MAX ];
  FD_TEST( fd_cstr_printf_check( path, PATH_MAX, NULL, "/sys/devices/system/cpu/cpu%lu/topology/thread_siblings_list", cpu_idx ) );

  int fd = open( path, O_RDONLY );
  if( FD_UNLIKELY( -1==fd ) ) FD_LOG_ERR(( "open( \"%s\" ) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));

  char line[ 1024 ] = {0};
  long bytes_read = read( fd, line, sizeof( line ) );
  if( FD_UNLIKELY( -1==bytes_read ) ) FD_LOG_ERR(( "read( \"%s\" ) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
  else if ( FD_UNLIKELY( (ulong)bytes_read>=sizeof( line ) ) ) FD_LOG_ERR(( "read( \"%s\" ) failed: buffer too small", path ));

  if( FD_UNLIKELY( close( fd ) ) ) FD_LOG_ERR(( "close( \"%s\" ) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));

  ulong sibling = fd_tile_private_sibling_parse( line, cpu_idx );
  if( FD_UNLIKELY( sibling==ULONG_MAX-1UL ) ) FD_LOG_ERR(( "failed to parse cpu siblings list of cpu%lu `%s`", cpu_idx, line ));
  return sibling;
# else
  (void)cpu_idx;
  return ULONG_MAX;
# endif
}
