#define _GNU_SOURCE
#include <errno.h>
#include <sched.h>

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>

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

  char * sep = strchr( line, ',' );
  if( FD_UNLIKELY( !sep ) ) return ULONG_MAX;

  *sep = '\0';
  errno = 0;
  char * endptr;
  ulong pair1 = strtoul( line, &endptr, 10 );
  if( FD_UNLIKELY( *endptr!='\0' || errno==ERANGE || errno==EINVAL ) ) FD_LOG_ERR(( "failed to parse cpu siblings list of cpu%lu `%s`", cpu_idx, line ));

  ulong pair2 = strtoul( sep+1UL, &endptr, 10 );
  if( FD_UNLIKELY( *endptr!='\n' || errno==ERANGE || errno==EINVAL ) ) FD_LOG_ERR(( "failed to parse cpu siblings list of cpu%lu `%s`", pair1, sep+1UL ));

  if( FD_LIKELY( pair1==cpu_idx ) )      return pair2;
  else if( FD_LIKELY( pair2==cpu_idx ) ) return pair1;
  else FD_LOG_ERR(( "failed to find sibling of cpu%lu", cpu_idx ));
# else
  (void)cpu_idx;
  return ULONG_MAX;
# endif
}
