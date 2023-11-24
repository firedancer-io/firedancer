#ifndef HEADER_fd_src_util_shmem_fd_shmem_private_h
#define HEADER_fd_src_util_shmem_fd_shmem_private_h

#include "fd_shmem.h"

#if FD_HAS_THREADS
#include <pthread.h>
#endif

/* Want strlen(base)+strlen("/.")+strlen(page)+strlen("/")+strlen(name)+1 <= BUF_MAX
     -> BASE_MAX-1  +2           +PAGE_MAX-1  +1          +NAME_MAX-1  +1 == BUF_MAX
     -> BASE_MAX == BUF_MAX - NAME_MAX - PAGE_MAX - 1 */

#define FD_SHMEM_PRIVATE_PATH_BUF_MAX (256UL)
#define FD_SHMEM_PRIVATE_BASE_MAX     (FD_SHMEM_PRIVATE_PATH_BUF_MAX-FD_SHMEM_NAME_MAX-FD_SHMEM_PAGE_SZ_CSTR_MAX-1UL)

#define FD_SHMEM_PRIVATE_MMAP_NORMAL_MASK 0x7ffffffff000
#define FD_SHMEM_PRIVATE_MMAP_HUGE_MASK 0x7fffffc00000
#define FD_SHMEM_PRIVATE_MMAP_GIGANTIC_MASK 0x7fffc0000000

#if FD_HAS_THREADS
#define FD_SHMEM_LOCK   pthread_mutex_lock(   fd_shmem_private_lock )
#define FD_SHMEM_UNLOCK pthread_mutex_unlock( fd_shmem_private_lock )
#else
#define FD_SHMEM_LOCK   ((void)0)
#define FD_SHMEM_UNLOCK ((void)0)
#endif

FD_PROTOTYPES_BEGIN

/* NUMA backend ******************************************************/

/* fd_numa_node_cnt / fd_numa_cpu_cnt determines the current number of
   configured numa nodes / cpus (roughly equivalent to libnuma's
   numa_num_configured_nodes / numa_num_configured_cpus).  Returns 0 if
   this could not be determined (logs details on failure).  These
   function are only used during shmem initialization as part of
   topology discovery so should not do any fancy caching under the hood. */

ulong
fd_numa_node_cnt( void );

ulong
fd_numa_cpu_cnt( void );

/* fd_numa_node_idx determines the numa node closest to the given
   cpu_idx (roughly equivalent to libnuma's numa_node_of_cpu).  Returns
   ULONG_MAX if this could not be determined (logs details on failure).
   This function is only used during shmem initialization as part of
   topology discovery so should not do any fancy caching under the hood. */

ulong
fd_numa_node_idx( ulong cpu_idx );

/* FIXME: probably should clean up the below APIs to get something
   that allows for cleaner integration with fd_shmem_admin.c (e.g. if we
   are going to replace libnuma calls with our own, no reason to use the
   historical clunky APIs). */

/* fd_numa_mlock locks the memory region to reside at a stable position
   in physical DRAM.  Wraps the `mlock(2)` Linux syscall.  See:

     https://man7.org/linux/man-pages/man2/mlock.2.html */

int
fd_numa_mlock( void const * addr,
               ulong        len );

/* fd_numa_mlock unlocks the memory region.  Wraps the `munlock(2)`
   Linux syscall.  See:

     https://man7.org/linux/man-pages/man2/munlock.2.html */

int
fd_numa_munlock( void const * addr,
                 ulong        len );

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

/**********************************************************************/

#if FD_HAS_THREADS
extern pthread_mutex_t fd_shmem_private_lock[1];
#endif

extern char  fd_shmem_private_base[ FD_SHMEM_PRIVATE_BASE_MAX ]; /* ""  at thread group start, initialized at boot */
extern ulong fd_shmem_private_base_len;                          /* 0UL at ",                  initialized at boot */

static inline char *                         /* ==buf always */
fd_shmem_private_path( char const * name,    /* Valid name */
                       ulong        page_sz, /* Valid page size (normal, huge, gigantic) */
                       char *       buf ) {  /* Non-NULL with FD_SHMEM_PRIVATE_PATH_BUF_MAX bytes */
  return fd_cstr_printf( buf, FD_SHMEM_PRIVATE_PATH_BUF_MAX, NULL, "%s/.%s/%s",
                         fd_shmem_private_base, fd_shmem_page_sz_to_cstr( page_sz ), name );
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_util_shmem_fd_shmem_private_h */
