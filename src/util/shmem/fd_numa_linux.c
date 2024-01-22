/* syscall API requires _GNU_SOURCE */
#define _GNU_SOURCE
#include "fd_shmem_private.h"
#include <errno.h>
#include <dirent.h>
#include <sys/sysinfo.h>

/* The below uses the sysfs API added ~2009-Dec.  See
   https://github.com/torvalds/linux/commit/1830794ae6392ce12d36dbcc5ff52f11298ddab6 */

/* fd_numa_private_parse_node_idx parses a cstr of the form
   `node[0-9]+` into a node idx.  The value will strictly interpreted as
   a non-negative base 10 value.  Returns -1 if the value could not be
   parsed (e.g. s is NULL, s does not have a node prefix, s does not
   have a base 10 suffix, the value overflows an int representation).
   FIXME: consider having the user pass the prefix to scan for to allow
   extracting more general indices from sysfs paths. */

FD_FN_PURE static int
fd_numa_private_parse_node_idx( char const * s ) {
  if( FD_UNLIKELY( !s ) ) return -1;
  if( FD_UNLIKELY( strncmp( s, "node", 4UL ) ) ) return -1;
  s += 4;

  long val = 0L;

  char const * t = s;
  for(;;) {
    char c = *t;
    if( !c ) break; /* host dep branch prob */
    if( FD_UNLIKELY( !(('0'<=c) | (c<='9')) ) ) return -1; /* non-digit encountered */
    val = (long)(c-'0') + 10L*val;
    if( FD_UNLIKELY( val>(long)INT_MAX ) ) return -1; /* overflow */
    t++;
  }
  if( FD_UNLIKELY( s==t ) ) return -1; /* empty idx */

  return (int)val;
}

ulong
fd_numa_node_cnt( void ) {

  /* Open sysfs dir containing NUMA config.  Abort if this fails. */

  char const * path = "/sys/devices/system/node";
  DIR *        dir  = opendir( path );
  if( FD_UNLIKELY( !dir ) ) {
    FD_LOG_WARNING(( "opendir( \"%s\" ) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
    return 0UL;
  }

  /* Scan dir to get number of NUMA nodes.  Note that we do not assume
     the system indexes numa nodes contiguously (but it almost certainly
     does). */

  int node_idx_max = INT_MIN;
  for(;;) {
    struct dirent * dirent = readdir( dir );
    if( !dirent ) break;
    node_idx_max = fd_int_max( fd_numa_private_parse_node_idx( dirent->d_name ), node_idx_max );
  }

  /* Close dir and return what was found */

  if( FD_UNLIKELY( closedir( dir ) ) )
    FD_LOG_WARNING(( "closedir( \"%s\" ) failed (%i-%s); attempting to continue", path, errno, fd_io_strerror( errno ) ));

  if( FD_UNLIKELY( node_idx_max<0 ) ) {
    FD_LOG_WARNING(( "No numa nodes found in \"%s\"", path ));
    return 0UL;
  }

  return ((ulong)node_idx_max) + 1UL;
}

ulong
fd_numa_cpu_cnt( void ) {

  /* FIXME: Consider using get_nprocs_conf, syscall or sysfs director
     scan. */

  int cpu_cnt = get_nprocs();
  if( FD_UNLIKELY( cpu_cnt<=0 ) ) {
    FD_LOG_WARNING(( "Unexpected return (%i) from get_nprocs", cpu_cnt ));
    return 0UL;
  }

  return (ulong)cpu_cnt;
}

ulong
fd_numa_node_idx( ulong cpu_idx ) {

  /* Open sysfs dir containing CPU config.  Abort if this fails. */

  char  path[64];
  DIR * dir = opendir( fd_cstr_printf( path, 64UL, NULL, "/sys/devices/system/cpu/cpu%lu", cpu_idx ) );
  if( FD_UNLIKELY( !dir ) ) {
    FD_LOG_WARNING(( "opendir( \"%s\" ) failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
    return ULONG_MAX;
  }

  /* Scan dir for symlink to numa config */

  int node_idx = -1;
  for(;;) {
    struct dirent * dirent = readdir( dir );
    if( !dirent ) break;
    node_idx = fd_numa_private_parse_node_idx( dirent->d_name );
    if( node_idx!=-1 ) break;
  }

  /* Close dir and return what was found */

  if( FD_UNLIKELY( closedir( dir ) ) )
    FD_LOG_WARNING(( "closedir( \"%s\" ) failed (%i-%s); attempting to continue", path, errno, fd_io_strerror( errno ) ));

  if( FD_UNLIKELY( node_idx<0 ) ) {
    FD_LOG_WARNING(( "No numa node found in \"%s\"", path ));
    return ULONG_MAX;
  }

  return (ulong)node_idx;
}

/* FIXME: probably should do a FD_HAS_ASAN switch for the below to use
   the appropriate functionality when FD_HAS_ASAN is set (or maybe have
   a separate implementation for compiling under FD_HAS_ASAN). */

#include <unistd.h>
#include <sys/syscall.h>

/* Note that the LLVM AddressSanitizer (ASan) intercepts all mlock
   calls.

   This has an interesting history.  These interceptors were first added
   in 2012 and are still present in LLVM 14.0.6:

     https://github.com/llvm/llvm-project/commit/71d759d392f03025bcc8b20f060bc5c22e580ea1

   They stub `mlock`, `munlock`, `mlockall`, `munlockall` to no-ops.

   ASan is known to map large amounts (~16TiB) of unbacked pages.  This
   rules out the use of `mlockall`.

   `mlock` only locks selected pages, therefore should be fine.  The
   comments in various revisions of these interceptors suggest that
   older Linux kernels had a bug that prevented the use of `mlock`.

   However, current Firedancer will use the `move_pages` syscall to
   verify whether "allocated" pages are actually backed by DRAM.

   This makes Firedancer and ASan incompatible unless we either

     1) Remove the `mlock` interceptor upstream, or
     2) Circumvent the interceptor with a raw syscall

   We do option 2 below */

int
fd_numa_mlock( void const * addr,
               ulong        len ) {
  return (int)syscall( __NR_mlock, addr, len );
}

int
fd_numa_munlock( void const * addr,
                 ulong        len ) {
  return (int)syscall( __NR_mlock, addr, len );
}

long
fd_numa_get_mempolicy( int *   mode,
                       ulong * nodemask,
                       ulong   maxnode,
                       void *  addr,
                       uint    flags ) {
  return syscall( SYS_get_mempolicy, mode, nodemask, maxnode, addr, flags );
}

long
fd_numa_set_mempolicy( int           mode,
                       ulong const * nodemask,
                       ulong         maxnode ) {
  return syscall( SYS_set_mempolicy, mode, nodemask, maxnode );
}

long
fd_numa_mbind( void *        addr,
               ulong         len,
               int           mode,
               ulong const * nodemask,
               ulong         maxnode,
               uint          flags ) {
  return syscall( SYS_mbind, addr, len, mode, nodemask, maxnode, flags );
}

long
fd_numa_move_pages( int         pid,
                    ulong       count,
                    void **     pages,
                    int const * nodes,
                    int *       status,
                    int         flags ) {
  return syscall( SYS_move_pages, pid, count, pages, nodes, status, flags );
}
