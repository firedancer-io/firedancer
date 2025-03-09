#include "fd_cpu_topo.h"

#include "../../util/shmem/fd_shmem_private.h"

#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>

static uint
read_uint_file( char const * path,
                char const * errmsg_enoent ) {
  FILE * fp = fopen( path, "r" );
  if( FD_UNLIKELY( !fp ) ) {
    if( FD_LIKELY( errno==ENOENT ) ) FD_LOG_ERR(( "%s fopen failed `%s` (%i-%s)", errmsg_enoent, path, errno, fd_io_strerror( errno ) ));
    else                             FD_LOG_ERR(( "fopen failed `%s` (%i-%s)", path, errno, fd_io_strerror( errno ) ));
  }

  uint value = 0U;
  if( FD_UNLIKELY( 1!=fscanf( fp, "%u\n", &value ) ) ) FD_LOG_ERR(( "failed to read uint from `%s`", path ));
  if( FD_UNLIKELY( fclose( fp ) ) ) FD_LOG_ERR(( "fclose failed `%s` (%i-%s)", path, errno, fd_io_strerror( errno ) ));
  return value;
}

static ulong
fd_topo_cpu_cnt( void ) {
  char path[ PATH_MAX ];
  fd_cstr_printf_check( path, PATH_MAX, NULL, "/sys/devices/system/cpu/present" );

  char line[ 128 ];
  int fd = open( path, O_RDONLY );
  if( FD_UNLIKELY( -1==fd ) ) FD_LOG_ERR(( "open( \"%s\" ) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));

  long bytes_read = read( fd, line, sizeof( line ) );
  if( FD_UNLIKELY( -1==bytes_read ) ) FD_LOG_ERR(( "read( \"%s\" ) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
  else if ( FD_UNLIKELY( (ulong)bytes_read>=sizeof( line ) ) ) FD_LOG_ERR(( "read( \"%s\" ) failed: buffer too small", path ));

  if( FD_UNLIKELY( close( fd ) ) ) FD_LOG_ERR(( "close( \"%s\" ) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));

  line[ bytes_read ] = '\0';
  char * saveptr;
  char * token = strtok_r( line, "-", &saveptr );
  token = strtok_r( NULL, "-", &saveptr );
  ulong end = fd_cstr_to_ulong( token );

  return end+1UL;
}

/* Return the sibling CPU (hyperthreaded pair) of the provided CPU, if
   there is one, otherwise return ULONG_MAX.  On error, logs an error
   and exits the process. */

ulong
fd_topob_sibling_idx( ulong cpu_idx ) {
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
}

static int
fd_topo_cpus_online( ulong cpu_idx ) {
  if( FD_UNLIKELY( cpu_idx==0UL ) ) return 1; /* Cannot set cpu0 to offline */

  char path[ PATH_MAX ];
  FD_TEST( fd_cstr_printf_check( path, sizeof( path ), NULL, "/sys/devices/system/cpu/cpu%lu/online", cpu_idx ) );
  return (int)read_uint_file( path, "error reading cpu online status" );
}

void
fd_topo_cpus_init( fd_topo_cpus_t * cpus ) {
  cpus->numa_node_cnt = fd_numa_node_cnt();
  cpus->cpu_cnt = fd_topo_cpu_cnt();

  for( ulong i=0UL; i<cpus->cpu_cnt; i++ ) {
    cpus->cpu[ i ].idx = i;
    cpus->cpu[ i ].online = fd_topo_cpus_online( i );
    cpus->cpu[ i ].numa_node = fd_numa_node_idx( i );
    if( FD_LIKELY( cpus->cpu[ i ].online ) ) cpus->cpu[ i ].sibling = fd_topob_sibling_idx( i );
    else                                     cpus->cpu[ i ].sibling = ULONG_MAX;
  }
}

void
fd_topo_cpus_printf( fd_topo_cpus_t * cpus ) {
  for( ulong i=0UL; i<cpus->cpu_cnt; i++ ) {
    FD_LOG_NOTICE(( "cpu%lu: online=%i sibling=%lu numa_node=%lu", i, cpus->cpu[ i ].online, cpus->cpu[ i ].sibling, cpus->cpu[ i ].numa_node ));
  }
}
