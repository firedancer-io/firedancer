#define _DARWIN_C_SOURCE
#include "fd_shmem_private.h"
#include <unistd.h>
#include <sys/mman.h>

#define _SC_NPROCESSORS_CONF 57
#define _SC_NPROCESSORS_ONLN 58

ulong
fd_numa_cpu_cnt( void ) {
  /* Arm devices can turn off CPUs to save power */
  return (ulong)sysconf( _SC_NPROCESSORS_ONLN );
}

ulong
fd_numa_node_idx( ulong cpu_idx ) {
  (void)cpu_idx;
  return 0UL;
}

ulong
fd_numa_node_cnt( void ) {
  return 1UL;
}

int
fd_numa_mlock( void const * addr,
               ulong        len ) {
  return mlock( addr, len );
}

int
fd_numa_munlock( void const * addr,
                 ulong        len ) {
  return munlock( addr, len );
}

int
fd_shmem_numa_validate( void const * mem,
                        ulong        page_sz,
                        ulong        page_cnt,
                        ulong        cpu_idx ) {
  (void)mem;
  (void)page_sz;
  (void)page_cnt;
  (void)cpu_idx;
  return 0;
}
