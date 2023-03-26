#ifndef HEADER_fd_src_util_shmem_fd_numa_linux_h
#define HEADER_fd_src_util_shmem_fd_numa_linux_h
#if defined(__linux__) && FD_HAS_HOSTED && FD_HAS_X86

#include "fd_shmem.h"

FD_PROTOTYPES_BEGIN

/* NUMA backend ******************************************************/

/* fd_numa_get_mempolicy retrieves the NUMA memory policy of the
   current thread.  Wraps the `get_mempolicy(2)` Linux syscall.  See:

     https://man7.org/linux/man-pages/man2/get_mempolicy.2.html */

long
fd_numa_get_mempolicy( int *   mode,
                       ulong * nodemask,
                       ulong   maxnode,
                       void *  addr,
                       uint    flags );

/* fd_numa_set_mempolicy sets the default NUMA memory policy of the
   current thread and its children.  Wraps the `set_mempolicy(2)` Linux
   syscall.  See:

     https://man7.org/linux/man-pages/man2/set_mempolicy.2.html */

long
fd_numa_set_mempolicy( int           mode,
                       ulong const * nodemask,
                       ulong         maxnode );

/* fd_numa_mbind sets the NUMA memory policy for a range of memory.
   Wraps the `mbind(2)` Linux syscall.  See:

     https://man7.org/linux/man-pages/man2/mbind.2.html */

long
fd_numa_mbind( void *        addr,
               ulong         len,
               int           mode,
               ulong const * nodemask,
               ulong         maxnode,
               uint          flags );

/* fd_numa_move_page moves pages of a process to another node.  Wraps
   the `move_pages(2)` Linux syscall.  See:

     https://man7.org/linux/man-pages/man2/move_pages.2.html

   Also useful to detect the true NUMA node ownership of pages of memory
   after calls to `mlock(2)` and `mbind(2)`. */

long
fd_numa_move_pages( int         pid,
                    ulong       count,
                    void **     pages,
                    int const * nodes,
                    int *       status,
                    int         flags );

FD_PROTOTYPES_END

#endif /* defined(__linux__) && FD_HAS_HOSTED && FD_HAS_X86 */
#endif /* HEADER_fd_src_util_shmem_fd_numa_linux_h */
