#ifndef HEADER_fd_src_util_shmem_fd_shmem_private_h
#define HEADER_fd_src_util_shmem_fd_shmem_private_h

#include "fd_shmem.h"

#if FD_HAS_HOSTED && FD_HAS_X86

#if FD_HAS_THREADS
#include <pthread.h>
#endif

/* Want strlen(base)+strlen("/.")+strlen(page)+strlen("/")+strlen(name)+1 <= BUF_MAX
     -> BASE_MAX-1  +2           +PAGE_MAX-1  +1          +NAME_MAX-1  +1 == BUF_MAX
     -> BASE_MAX == BUF_MAX - NAME_MAX - PAGE_MAX - 1 */

#define FD_SHMEM_PRIVATE_PATH_BUF_MAX (256UL)
#define FD_SHMEM_PRIVATE_BASE_MAX     (FD_SHMEM_PRIVATE_PATH_BUF_MAX-FD_SHMEM_NAME_MAX-FD_SHMEM_PAGE_SZ_CSTR_MAX-1UL)

#if FD_HAS_THREADS
#define FD_SHMEM_LOCK   pthread_mutex_lock(   fd_shmem_private_lock )
#define FD_SHMEM_UNLOCK pthread_mutex_unlock( fd_shmem_private_lock )
#else
#define FD_SHMEM_LOCK   ((void)0)
#define FD_SHMEM_UNLOCK ((void)0)
#endif

#if defined(__unix__) && FD_HAS_ASAN

/* LLVM AddressSanitizer (ASan) intercepts all mlock calls.

   This has an interesting history.
   These interceptors were first added in 2012 and are still present in
   LLVM 14.0.6: https://github.com/llvm/llvm-project/commit/71d759d392f03025bcc8b20f060bc5c22e580ea1
   They stub `mlock`, `munlock`, `mlockall`, `munlockall` to no-ops.

   ASan is known to map large amounts (~16TiB) of unbacked pages.
   This rules out the use of `mlockall`.

   `mlock` only locks selected pages, therefore should be fine.
   The comments in various revisions of these interceptors suggest
   that older Linux kernels had a bug that prevented the use of `mlock`.

   However, current Firedancer will use the `move_pages` syscall
   to verify whether "allocated" pages are actually backed by DRAM.

   This makes Firedancer and ASan incompatible unless we either
     1) Remove the `mlock` interceptor upstream, or
     2) Circumvent the interceptor with a raw syscall

   This macro implements option 2. */

#include <sys/syscall.h>
#define fd_mlock(...)   syscall( __NR_mlock,   __VA_ARGS__ )
#define fd_munlock(...) syscall( __NR_munlock, __VA_ARGS__ )

#else

#define fd_mlock   mlock
#define fd_munlock munlock

#endif /* defined(__unix__) && FD_HAS_ASAN */

FD_PROTOTYPES_BEGIN

/* Linux syscall APIs *************************************************/

/* get_mempolicy: Retrieves the NUMA memory policy of the current thread.

   Wraps the `get_mempolicy(2)` Linux syscall.
   See https://man7.org/linux/man-pages/man2/get_mempolicy.2.html */
long
get_mempolicy( int *   mode,
               ulong * nodemask,
               ulong   maxnode,
               void *  addr,
               uint    flags );

/* set_mempolicy: Sets the default NUMA memory policy
   of the current thread and its children.

   Wraps the `set_mempolicy(2)` Linux syscall.
   See https://man7.org/linux/man-pages/man2/set_mempolicy.2.html */
long
set_mempolicy( int           mode,
               ulong const * nodemask,
               ulong         maxnode );

/* mbind: Sets the NUMA memory policy for a range of memory.

   Wraps the `mbind(2)` Linux syscall.
   See https://man7.org/linux/man-pages/man2/mbind.2.html */
long
mbind( void *        addr,
       ulong         len,
       int           mode,
       ulong const * nodemask,
       ulong         maxnode,
       uint          flags );

/* move_pages: Moves pages of a process to another node.

   Wraps the `move_pages(2)` Linux syscall.
   See https://man7.org/linux/man-pages/man2/move_pages.2.html

   Also useful to detect the true NUMA node ownership
   of pages of memory after calls to `mlock(2)` and `mbind(2)`. */
long
move_pages( int         pid,
            ulong       count,
            void **     pages,
            int const * nodes,
            int *       status,
            int         flags );

/* Linux sysctl/sysconf APIs ******************************************/

/* fd_numa_available: Checks whether NUMA API is supported.

   Returns 1 if NUMA API is supported, 0 otherwise.

   Note that 1 can be returned on systems with only one NUMA node,
   or even operating systems that do not support NUMA
   (for compatibility). */
int
fd_numa_available( void );

/* fd_shmem_numa_cnt_private: Get number of configured NUMA nodes.

   Returns a libc -errno on failure. (`x<=0`) */
int
fd_shmem_numa_cnt_private( void );

/* fd_shmem_cpu_cnt_private: Get number of available CPU cores.

   Returns a libc -errno on failure. (`x<=0`) */
int
fd_shmem_cpu_cnt_private( void );

/* fd_numa_cpu_max_cnt: Get number of configured CPU cores.

   Returns one plus the highest possible CPU index on this system.

   Note that some of the configured CPUs might be unavailable.
   To get the actual number of CPUs, use `fd_shmem_cpu_cnt_private`.

   Returns a libc -errno or zero on failure. (`x<=0`) */
int
fd_numa_cpu_max_cnt( void );

/* fd_numa_node_of_cpu: Gets NUMA node index of CPU.

   Returns -ENOENT if the CPU is not accessible or does not exist.
   Returns a libc -errno on failure. (`x<0`) */
int
fd_numa_node_of_cpu( int cpu_idx );

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

#endif

#endif /* HEADER_fd_src_util_shmem_fd_shmem_private_h */
