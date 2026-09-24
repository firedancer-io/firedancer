#include "fd_cpu_topo.h"

#include "../../util/shmem/fd_shmem_private.h"
#include "../../util/tile/fd_tile_private.h"

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

static int
parse_topology_id( char const * buf,
                   ulong        sz ) {
  if( FD_UNLIKELY( !sz ) ) return -1;
  ulong i = 0UL;
  uint id = 0U;
  while( i<sz && buf[ i ]>='0' && buf[ i ]<='9' ) {
    uint digit = (uint)(buf[ i++ ]-'0');
    if( FD_UNLIKELY( id>((uint)INT_MAX-digit)/10U ) ) return -1;
    id = 10U*id+digit;
  }
  if( FD_UNLIKELY( !i || (i!=sz && !(i+1UL==sz && buf[ i ]=='\n')) ) ) return -1;
  return (int)id;
}

static int
read_topology_id( char const * path ) {
  int fd;
retry:
  do fd = open( path, O_RDONLY ); while( fd<0 && errno==EINTR );
  if( FD_UNLIKELY( fd<0 ) ) {
    if( errno!=ENOENT ) FD_LOG_WARNING(( "open `%s` failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
    return -1;
  }

  char buf[ 64 ];
  ulong sz;
  int err = fd_io_read( fd, buf, sizeof(buf), sizeof(buf), &sz );
  if( FD_UNLIKELY( close( fd ) ) ) {
    FD_LOG_WARNING(( "close `%s` failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
    return -1;
  }
  /* fd_io_read may have advanced the file offset before EINTR. */
  if( FD_UNLIKELY( err==EINTR ) ) goto retry;
  if( FD_UNLIKELY( err>0 ) ) {
    FD_LOG_WARNING(( "read `%s` failed (%i-%s)", path, err, fd_io_strerror( err ) ));
    return -1;
  }
  if( FD_UNLIKELY( sz==sizeof(buf) ) ) return -1;
  return parse_topology_id( buf, sz );
}

static void
assign_die_indices( fd_topo_cpus_t * cpus,
                    int const *      package_ids,
                    int const *      die_ids ) {
  ulong die_cnt = 0UL;
  for( ulong i=0UL; i<cpus->cpu_cnt; i++ ) {
    cpus->cpu[ i ].die_idx = ULONG_MAX;
    if( FD_UNLIKELY( package_ids[ i ]<0 || die_ids[ i ]<0 ) ) continue;
    for( ulong j=0UL; j<i; j++ ) {
      if( package_ids[ i ]==package_ids[ j ] && die_ids[ i ]==die_ids[ j ] ) {
        cpus->cpu[ i ].die_idx = cpus->cpu[ j ].die_idx;
        break;
      }
    }
    if( cpus->cpu[ i ].die_idx==ULONG_MAX ) cpus->cpu[ i ].die_idx = die_cnt++;
  }
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
  ulong end = fd_cstr_to_ulong( token ? token : line );

  return end+1UL;
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
  cpus->numa_node_cnt = fd_numa_node_cnt( 0 );
  cpus->cpu_cnt = fd_topo_cpu_cnt();
  if( FD_UNLIKELY( cpus->cpu_cnt > FD_TILE_MAX ) ) {
    FD_LOG_ERR(( "unsupported system: Firedancer supports up to %lu CPUs", FD_TILE_MAX ));
  }

  int package_ids[ FD_TILE_MAX ];
  int die_ids    [ FD_TILE_MAX ];
  for( ulong i=0UL; i<cpus->cpu_cnt; i++ ) {
    cpus->cpu[ i ].idx = i;
    cpus->cpu[ i ].online = fd_topo_cpus_online( i );
    cpus->cpu[ i ].numa_node = fd_numa_node_idx( i, 0 );
    if( FD_LIKELY( cpus->cpu[ i ].online ) ) cpus->cpu[ i ].sibling = fd_tile_private_sibling_idx( i );
    else                                     cpus->cpu[ i ].sibling = ULONG_MAX;

    char path[ PATH_MAX ];
    fd_cstr_printf_check( path, sizeof(path), NULL, "/sys/devices/system/cpu/cpu%lu/topology/physical_package_id", i );
    package_ids[ i ] = read_topology_id( path );
    fd_cstr_printf_check( path, sizeof(path), NULL, "/sys/devices/system/cpu/cpu%lu/topology/die_id", i );
    die_ids[ i ] = read_topology_id( path );
  }
  assign_die_indices( cpus, package_ids, die_ids );
}

void
fd_topo_cpus_printf( fd_topo_cpus_t * cpus ) {
  for( ulong i=0UL; i<cpus->cpu_cnt; i++ ) {
    FD_LOG_NOTICE(( "cpu%lu: online=%i sibling=%lu numa_node=%lu die_idx=%lu", i, cpus->cpu[ i ].online, cpus->cpu[ i ].sibling, cpus->cpu[ i ].numa_node, cpus->cpu[ i ].die_idx ));
  }
}
