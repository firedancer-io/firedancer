#include "fd_shmem_private.h"
#include <errno.h>
#include <sys/mman.h>

#include <sys/sysctl.h>
#include <unistd.h>
#include <sys/mman.h>

/* Apple Silicon is a unified memory architecture. We treat it as 1 NUMA node. */

ulong
fd_numa_node_cnt( void ) {
  return 1UL;
}

ulong
fd_numa_cpu_cnt( void ) {
  int ncpu;
  size_t len = sizeof(ncpu);
  if( sysctlbyname("hw.ncpu", &ncpu, &len, NULL, 0) == -1 ) {
    FD_LOG_WARNING(( "sysctlbyname(hw.ncpu) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    return 1UL;
  }
  return (ulong)ncpu;
}

ulong
fd_numa_node_idx( ulong cpu_idx ) {
  (void)cpu_idx;
  return 0UL; /* All CPUs are on the same node */
}

int
fd_numa_mlock( void const * addr,
               ulong        len ) {
  if( FD_UNLIKELY( mlock( addr, len ) ) ) {
    return -1;
  }
  return 0;
}

int
fd_numa_munlock( void const * addr,
                 ulong        len ) {
  if( FD_UNLIKELY( munlock( addr, len ) ) ) {
    return -1;
  }
  return 0;
}

/* Mempolicy and mbind are not applicable to the unified Apple memory model.
   Subsequent calls should handle these appropriately or return success if trivial. */

long
fd_numa_get_mempolicy( int *   mode,
                       ulong * nodemask,
                       ulong   maxnode,
                       void *  addr,
                       uint    flags ) {
  (void)addr; (void)flags;
  if( mode ) *mode = 0;
  if( nodemask && maxnode>0 ) *nodemask = 1UL;
  return 0;
}

long
fd_numa_set_mempolicy( int           mode,
                       ulong const * nodemask,
                       ulong         maxnode ) {
  (void)mode; (void)nodemask; (void)maxnode;
  return 0;
}

long
fd_numa_mbind( void *        addr,
               ulong         len,
               int           mode,
               ulong const * nodemask,
               ulong         maxnode,
               uint          flags ) {
  (void)addr; (void)len; (void)mode; (void)nodemask; (void)maxnode; (void)flags;
  return 0;
}

long
fd_numa_move_pages( int         pid,
                    ulong       count,
                    void **     pages,
                    int const * nodes,
                    int *       status,
                    int         flags ) {
  (void)pid; (void)nodes; (void)flags;
  for( ulong i=0UL; i<count; i++ ) {
    if( status ) status[i] = 0; /* All pages are on node 0 on macOS unified memory */
  }
  (void)pages;
  return 0;
}
