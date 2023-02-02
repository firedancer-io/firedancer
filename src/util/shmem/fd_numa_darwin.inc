#ifndef SOURCE_fd_src_util_shmem_fd_shmem_admin
#error "Do not compile this file directly"
#endif

#define _DARWIN_C_SOURCE

#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <pthread.h>
#include <mach/thread_policy.h>
#include <mach/thread_act.h>
#include <mach/mach_init.h>
#include "../fd_util.h"

/* NUMA API support for macOS (without the N).

   Assume there is only one NUMA node. */

#define _SC_NPROCESSORS_CONF 57
#define _SC_NPROCESSORS_ONLN 58

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
  return (int)sysconf( _SC_NPROCESSORS_ONLN );
}

int
fd_numa_cpu_max_cnt( void ) {
  return (int)sysconf( _SC_NPROCESSORS_CONF );
}

int
fd_numa_node_of_cpu( int cpu_idx ) {
  if( FD_UNLIKELY( cpu_idx<0 || cpu_idx>fd_shmem_cpu_cnt_private() ) )
    return -ENOENT;
  return 0;
}

__attribute__((weak)) long
move_pages( int pid,
            ulong count,
            void **pages,
            int const *nodes,
            int *status,
            int flags ) {
    (void)pid;
    (void)count;
    (void)pages;
    (void)nodes;
    (void)status;
    (void)flags;
    return 0;
}
