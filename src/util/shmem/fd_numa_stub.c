#include "fd_shmem_private.h"

ulong
fd_numa_node_cnt( int numa_enabled ) {
  (void)numa_enabled;
  FD_LOG_WARNING(( "no numa support for this build target" ));
  return 0UL;
}

ulong
fd_numa_cpu_cnt ( void ) {
  FD_LOG_WARNING(( "no numa support for this build target" ));
  return 0UL;
}

ulong
fd_numa_node_idx( ulong cpu_idx,
                  int   numa_enabled ) {
  (void)cpu_idx; (void)numa_enabled;
  FD_LOG_WARNING(( "no numa support for this build target" ));
  return ULONG_MAX;
}

#include <errno.h>

int
fd_numa_mlock( void const * addr,
               ulong        len ) {
  (void)addr; (void)len;
  FD_LOG_WARNING(( "no numa support for this build target" ));
  errno = EINVAL;
  return -1;
}

int
fd_numa_munlock( void const * addr,
                 ulong        len ) {
  (void)addr; (void)len;
  FD_LOG_WARNING(( "no numa support for this build target" ));
  errno = EINVAL;
  return -1;
}

long
fd_numa_get_mempolicy( int *   mode,
                       ulong * nodemask,
                       ulong   maxnode,
                       void *  addr,
                       uint    flags,
                       int     numa_enabled ) {
  (void)mode; (void)nodemask; (void)maxnode; (void)addr; (void)flags; (void)numa_enabled;
  FD_LOG_WARNING(( "no numa support for this build target" ));
  errno = EINVAL;
  return -1L;
}

long
fd_numa_set_mempolicy( int           mode,
                       ulong const * nodemask,
                       ulong         maxnode,
                       int           numa_enabled ) {
  (void)mode; (void)nodemask; (void)maxnode; (void)numa_enabled;
  FD_LOG_WARNING(( "no numa support for this build target" ));
  errno = EINVAL;
  return -1L;
}

long
fd_numa_mbind( void *        addr,
               ulong         len,
               int           mode,
               ulong const * nodemask,
               ulong         maxnode,
               uint          flags,
               int           numa_enabled ) {
  (void)addr; (void)len; (void)mode; (void)nodemask; (void)maxnode; (void)flags; (void)numa_enabled;
  FD_LOG_WARNING(( "no numa support for this build target" ));
  errno = EINVAL;
  return -1L;
}

long
fd_numa_move_pages( int         pid,
                    ulong       count,
                    void **     pages,
                    int const * nodes,
                    int *       status,
                    int         flags ) {
  (void)pid; (void)count; (void)pages; (void)nodes; (void)status; (void)flags;
  FD_LOG_WARNING(( "no numa support for this build target" ));
  errno = EINVAL;
  return -1L;
}
