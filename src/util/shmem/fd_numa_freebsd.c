/* fd_numa_freebsd.c targets FreeBSD 14.1.
   As of 2024-Jun, FreeBSD NUMA support is incomplete.
   See https://wiki.freebsd.org/NUMA and https://man.freebsd.org/cgi/man.cgi?numa(4) */ 

#include <sys/cdefs.h>
#include <sys/types.h>
#include <sys/cpuset.h>
#include <sys/sysctl.h>

#include "fd_shmem_private.h"
#include <errno.h>

ulong
fd_numa_node_cnt( void ) {
  ulong domain_cnt;
  ulong domain_cnt_sz = sizeof(ulong);
  if( FD_UNLIKELY( 0!=sysctlbyname( "vm.ndomains", &domain_cnt, &domain_cnt_sz, NULL, 0UL ) ) ) {
    FD_LOG_ERR(( "sysctlbyname(vm.ndomains) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
  return domain_cnt;
}

ulong
fd_numa_cpu_cnt( void ) {
  int mib[2] = { CTL_HW, HW_NCPU };
  ulong cpu_cnt;
  ulong cpu_cnt_sz = sizeof(ulong);
  if( FD_UNLIKELY( 0!=sysctl( mib, 2U, &cpu_cnt, &cpu_cnt_sz, NULL, 0UL ) ) ) {
    FD_LOG_ERR(( "sysctl(hw.ncpu) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
  }
  return cpu_cnt;
}

ulong
fd_numa_node_idx( ulong cpu_idx ) {
  ulong domain_cnt = fd_numa_node_cnt();
  cpuset_t set;
  for( ulong domain=0UL; domain<domain_cnt; domain++ ) {
    CPU_ZERO( &set );
    if( FD_UNLIKELY( 0!=cpuset_getaffinity( CPU_LEVEL_WHICH, CPU_WHICH_DOMAIN, domain, sizeof(cpuset_t), &set ) ) ) {
      FD_LOG_ERR(( "cpuset_getaffinity(CPU_LEVEL_WHICH,CPU_WHICH_DOMAIN,%lu) failed (%i-%s)", domain, errno, fd_io_strerror( errno ) ));
    }
    if( CPU_ISSET( cpu_idx, &set ) ) {
      return domain;
    } 
  }
  FD_LOG_INFO(( "cpu %lu does not belong to any NUMA domain, defaulting to 0", cpu_idx ));
  return 0UL;
}

int
fd_numa_mlock( void const * addr,
               ulong        len ) {
  errno = ENOTSUP;
  return -1;
}

int
fd_numa_munlock( void const * addr,
                 ulong        len ) {
  errno = ENOTSUP;
  return -1;
}

long
fd_numa_get_mempolicy( int *   mode,
                       ulong * nodemask,
                       ulong   maxnode,
                       void *  addr,
                       uint    flags ) {
  errno = ENOTSUP;
  return -1L;
}

long
fd_numa_set_mempolicy( int           mode,
                       ulong const * nodemask,
                       ulong         maxnode ) {
  errno = ENOTSUP;
  return -1L;
}

long
fd_numa_mbind( void *        addr,
               ulong         len,
               int           mode,
               ulong const * nodemask,
               ulong         maxnode,
               uint          flags ) {
  errno = ENOTSUP;
  return -1L;
}

long
fd_numa_move_pages( int         pid,
                    ulong       count,
                    void **     pages,
                    int const * nodes,
                    int *       status,
                    int         flags ) {
  errno = ENOTSUP;
  return -1L;
}
