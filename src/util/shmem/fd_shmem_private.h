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

FD_PROTOTYPES_BEGIN

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
