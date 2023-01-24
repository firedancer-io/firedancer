#ifndef SOURCE_fd_src_util_shmem_fd_shmem_admin
#error "Do not compile this file directly"
#endif

#include <unistd.h>

/* NUMA API support for macOS (without the N).

   Assume there is only one NUMA node. */

int
fd_numa_available( void ) {
  return 1;
}

int
fd_shmem_numa_cnt_private( void ) {
  return 1;
}

int
fd_shmem_cpu_cnt_private( void ) {
  /* Arm devices can turn off CPUs to save power */
  return sysconf( _SC_NPROCESSORS_ONLN );
}

int
fd_numa_cpu_max_cnt( void ) {
  return sysconf( _SC_NPROCESSORS_CONF );
}

int
fd_numa_node_of_cpu( int cpu_idx ) {
  if( FD_UNLIKELY( cpu_idx<0 || cpu_idx>fd_shmem_cpu_cnt_private() ) )
    return -ENOENT;
  return 0;
}
