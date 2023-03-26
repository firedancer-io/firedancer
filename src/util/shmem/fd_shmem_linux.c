#ifndef SOURCE_fd_src_util_shmem_fd_shmem_admin
#error "Do not compile this file directly"
#endif

#if !defined(__linux__)
#error "Unsupported platform"
#endif

#define _GNU_SOURCE
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <sys/types.h>
#include <signal.h>
#include <errno.h>
#include <dirent.h>

#include <linux/mempolicy.h>
#include <linux/mman.h>

#include "fd_shmem_private.h"
#include "../fd_util_base.h"
#include "../cstr/fd_cstr.h"
#include "../log/fd_log.h"

int
fd_shmem_numa_validate( void const * mem,
                        ulong        page_sz,
                        ulong        page_cnt,
                        ulong        cpu_idx ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return EINVAL;
  }

  if( FD_UNLIKELY( !fd_shmem_is_page_sz( page_sz ) ) ) {
    FD_LOG_WARNING(( "bad page_sz (%lu)", page_sz ));
    return EINVAL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, page_sz ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return EINVAL;
  }

  if( FD_UNLIKELY( !((1UL<=page_cnt) & (page_cnt<=(((ulong)LONG_MAX)/page_sz))) ) ) {
    FD_LOG_WARNING(( "bad page_cnt (%lu)", page_cnt ));
    return EINVAL;
  }

  if( FD_UNLIKELY( !(cpu_idx<fd_shmem_cpu_cnt()) ) ) {
    FD_LOG_WARNING(( "bad cpu_idx (%lu)", cpu_idx ));
    return EINVAL;
  }

  ulong numa_idx = fd_shmem_numa_idx( cpu_idx );

  ulong   page = (ulong)mem;
  int     batch_status[ 512 ];
  void *  batch_page  [ 512 ];
  ulong   batch_cnt = 0UL;
  while( page_cnt ) {
    batch_page[ batch_cnt++ ] = (void *)page;
    page += page_sz;
    page_cnt--;
    if( FD_UNLIKELY( ((batch_cnt==512UL) | (!page_cnt) ) ) ) {
      if( FD_UNLIKELY( fd_numa_move_pages( 0, batch_cnt, batch_page, NULL, batch_status, 0 ) ) ) {
        FD_LOG_WARNING(( "fd_numa_move_pages query failed (%i-%s)", errno, strerror( errno ) ));
        return errno;
      }
      for( ulong batch_idx=0UL; batch_idx<batch_cnt; batch_idx++ ) {
        if( FD_UNLIKELY( batch_status[batch_idx]<0 ) ) {
          int err = -batch_status[batch_idx];
          FD_LOG_WARNING(( "page status failed (%i-%s)", err, strerror( err ) ));
          return err;
        }
        if( FD_UNLIKELY( batch_status[batch_idx]!=(int)numa_idx ) ) {
          FD_LOG_WARNING(( "page allocated to numa %i instead of numa %lu", batch_status[batch_idx], numa_idx ));
          return EFAULT;
        }
      }
      batch_cnt = 0UL;
    }
  }

  return 0;
}


/* SHMEM REGION CREATION AND DESTRUCTION ******************************/

pthread_mutex_t fd_shmem_private_lock[1] = { PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP };

int
fd_shmem_create( char const * name,
                 ulong        page_sz,
                 ulong        page_cnt,
                 ulong        cpu_idx,
                 ulong        mode ) {

  /* Check input args */

  if( FD_UNLIKELY( !fd_shmem_name_len( name ) ) ) { FD_LOG_WARNING(( "bad name (%s)", name ? name : "NULL" )); return EINVAL; }

  if( FD_UNLIKELY( !fd_shmem_is_page_sz( page_sz ) ) ) { FD_LOG_WARNING(( "bad page_sz (%lu)", page_sz )); return EINVAL; }

  if( FD_UNLIKELY( !((1UL<=page_cnt) & (page_cnt<=(((ulong)LONG_MAX)/page_sz))) ) ) {
    FD_LOG_WARNING(( "bad page_cnt (%lu)", page_cnt ));
    return EINVAL;
  }

  if( FD_UNLIKELY( !(cpu_idx<fd_shmem_cpu_cnt()) ) ) { FD_LOG_WARNING(( "bad cpu_idx (%lu)", cpu_idx )); return EINVAL; }

  if( FD_UNLIKELY( mode!=(ulong)(mode_t)mode ) ) { FD_LOG_WARNING(( "bad mode (0%03lo)", mode )); return EINVAL; }

  ulong sz       = page_cnt*page_sz;

  /* We use the FD_SHMEM_LOCK in create just to be safe given some
     thread safety ambiguities in the documentation for some of the
     below APIs. */

  FD_SHMEM_LOCK;

  int err;
# define ERROR( cleanup ) do { err = errno; goto cleanup; } while(0)

  char   path[ FD_SHMEM_PRIVATE_PATH_BUF_MAX ];
  int    fd;
  void * shmem;

  ulong numa_idx = fd_shmem_numa_idx( cpu_idx );
  int    orig_mempolicy;
  ulong  orig_nodemask[ (FD_SHMEM_NUMA_MAX+63UL)/64UL ];
  ulong  nodemask[ (FD_SHMEM_NUMA_MAX+63UL)/64UL ];

  /* Save this thread's numa node mempolicy and then set it to bind
     newly created memory to the numa idx corresponding to logical cpu
     cpu_idx.  This should force page allocation to be on the desired
     numa node even if triggered preemptively in the ftruncate / mmap
     because the user thread group has configured things like
     mlockall(MCL_FUTURE).  Theoretically, the fd_numa_mbind below
     should do it without this but the Linux kernel tends to view
     requests to move pages between numa nodes after allocation as for
     entertainment purposes only. */

  if( FD_UNLIKELY( fd_numa_get_mempolicy( &orig_mempolicy, orig_nodemask, FD_SHMEM_NUMA_MAX, NULL, 0UL ) ) ) {
    FD_LOG_WARNING(( "fd_numa_get_mempolicy failed (%i-%s)", errno, strerror( errno ) ));
    ERROR( done );
  }

  fd_memset( nodemask, 0, 8UL*((FD_SHMEM_NUMA_MAX+63UL)/64UL) );
  nodemask[ numa_idx >> 6 ] = 1UL << (numa_idx & 63UL);
  if( FD_UNLIKELY( fd_numa_set_mempolicy( MPOL_BIND | MPOL_F_STATIC_NODES, nodemask, FD_SHMEM_NUMA_MAX ) ) ) {
    FD_LOG_WARNING(( "fd_numa_set_mempolicy failed (%i-%s)", errno, strerror( errno ) ));
    ERROR( done );
  }

  /* Create the region */

  fd = open( fd_shmem_private_path( name, page_sz, path ), O_RDWR | O_CREAT | O_EXCL, (mode_t)mode );
  if( FD_UNLIKELY( fd==-1 ) ) {
    FD_LOG_WARNING(( "open(\"%s\",O_RDWR|O_CREAT|O_EXCL,0%03lo) failed (%i-%s)", path, mode, errno, strerror( errno ) ));
    ERROR( restore );
  }

  /* Size the region */

  if( FD_UNLIKELY( ftruncate( fd, (off_t)sz ) ) ) {
    FD_LOG_WARNING(( "ftruncate(\"%s\",%lu KiB) failed (%i-%s)", path, sz>>10, errno, strerror( errno ) ));
    ERROR( close );
  }

  /* Map the region into our address space. */

  shmem = mmap( NULL, sz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, (off_t)0);
  if( FD_UNLIKELY( shmem==MAP_FAILED ) ) {
    FD_LOG_WARNING(( "mmap(NULL,%lu KiB,PROT_READ|PROT_WRITE,MAP_SHARED,\"%s\",0) failed (%i-%s)",
        sz>>10, path, errno, strerror( errno ) ));
    ERROR( close );
  }

  /* Validate the mapping */

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, page_sz ) ) ) {
    FD_LOG_WARNING(( "misaligned memory mapping for \"%s\""
                     "This thread group's hugetlbfs mount path (--shmem-path / FD_SHMEM_PATH):\n\t"
                     "\t%s\n\t"
                     "has probably been corrupted and needs to be redone.\n\t"
                     "See 'bin/fd_shmem_cfg help' for more information.",
        path, fd_shmem_private_base ));
    errno = EFAULT; /* ENOMEM is arguable */
    ERROR( unmap );
  }

  /* If a mempolicy has been set and the numa_idx node does not have
     sufficient pages to back the mapping, touching the memory will
     trigger a a SIGBUS when it touches the first part of the mapping
     for which there are no pages.  Unfortunately, mmap will only error
     if there are insufficient pages across all NUMA nodes (even if
     using mlockall( MCL_FUTURE ) or passing MAP_POPULATE), so we need
     to check that the mapping can be backed without handling signals.

     So we mlock the region to force the region to be backed by pages
     now.  The region should be backed by page_sz pages (thanks to the
     hugetlbfs configuration) and should be on the correct NUMA node
     (thanks to the mempolicy above).  Specifically, mlock will error
     with ENOMEM if there were insufficient pages available.  mlock
     guarantees that if it succeeds, the mapping has been fully backed
     by pages and these pages will remain resident in DRAM at least
     until the mapping is closed.  We can then proceed as usual without
     the risk of meeting SIGBUS or its friends. */

  if( FD_UNLIKELY( fd_numa_mlock( shmem, sz ) ) ) {
    FD_LOG_WARNING(( "fd_numa_mlock(\"%s\",%lu KiB) failed (%i-%s)", path, sz>>10, errno, strerror( errno ) ));
    ERROR( unmap );
  }

  /* At this point all pages should be allocated on the right NUMA node
     and resident in DRAM.  But in the spirit of not trusting Linux to
     get this right robustly, we continue with touching pages from
     cpu_idx. */

  /* FIXME: NUMA TOUCH HERE (ALSO WOULD A LOCAL TOUCH WORK GIVEN THE
     MEMPOLICY DONE ABOVE?) */

  /* fd_numa_mbind the memory region to this numa node to nominally stay
     put after we unmap it. */

  /* Just in case set_mempolicy clobbered it */
  fd_memset( nodemask, 0, 8UL*((FD_SHMEM_NUMA_MAX+63UL)/64UL) );
  nodemask[ numa_idx >> 6 ] = 1UL << (numa_idx & 63UL);
  if( FD_UNLIKELY( fd_numa_mbind( shmem, sz, MPOL_BIND, nodemask, FD_SHMEM_NUMA_MAX, MPOL_MF_MOVE | MPOL_MF_STRICT ) ) ) {
    FD_LOG_WARNING(( "fd_numa_mbind(\"%s\",%lu KiB,MPOL_BIND,1UL<<%lu,MPOL_MF_MOVE|MPOL_MF_STRICT) failed (%i-%s)",
        path, sz>>10, numa_idx, errno, strerror( errno ) ));
    ERROR( unmap );
  }

  /* And since the fd_numa_mbind still often will ignore requests, we
     double check that the pages are in the right place. */

  err = fd_shmem_numa_validate( shmem, page_sz, page_cnt, cpu_idx ); /* logs details */
  if( FD_UNLIKELY( err ) )
    FD_LOG_WARNING(( "mmap(NULL,%lu KiB,PROT_READ|PROT_WRITE,MAP_SHARED,\"%s\",0) numa binding failed (%i-%s)",
        sz>>10, path, err, strerror( err ) ));

# undef ERROR

unmap:
  if( FD_UNLIKELY( munmap( shmem, sz ) ) )
    FD_LOG_WARNING(( "munmap(\"%s\",%lu KiB) failed (%i-%s); attempting to continue", path, sz>>10, errno, strerror( errno ) ));

close:
  if( FD_UNLIKELY( err ) && FD_UNLIKELY( unlink( path ) ) )
    FD_LOG_WARNING(( "unlink(\"%s\") failed (%i-%s)", path, errno, strerror( errno ) )); /* Don't log "attempting ..." */
  if( FD_UNLIKELY( close( fd ) ) )
    FD_LOG_WARNING(( "close(\"%s\") failed (%i-%s); attempting to continue", path, errno, strerror( errno ) ));

restore:
  if( FD_UNLIKELY( fd_numa_set_mempolicy( orig_mempolicy, orig_nodemask, FD_SHMEM_NUMA_MAX ) ) )
    FD_LOG_WARNING(( "fd_numa_set_mempolicy failed (%i-%s); attempting to continue", errno, strerror( errno ) ));

done:
  FD_SHMEM_UNLOCK;
  return err;
}


void *
fd_shmem_acquire( ulong page_sz,
                  ulong page_cnt,
                  ulong cpu_idx ) {

  if( FD_UNLIKELY( !fd_shmem_is_page_sz( page_sz ) ) ) {
    FD_LOG_WARNING(( "bad page_sz (%lu)", page_sz ));
    return NULL;
  }

  if( FD_UNLIKELY( !((1UL<=page_cnt) & (page_cnt<=(((ulong)LONG_MAX)/page_sz))) ) ) {
    FD_LOG_WARNING(( "bad page_cnt (%lu)", page_cnt ));
    return NULL;
  }

  if( FD_UNLIKELY( !(cpu_idx<fd_shmem_cpu_cnt()) ) ) {
    FD_LOG_WARNING(( "bad cpu_idx (%lu)", cpu_idx ));
    return NULL;
  }

  ulong sz       = page_cnt*page_sz;

  int flags = MAP_PRIVATE | MAP_ANONYMOUS;
  if( page_sz==FD_SHMEM_HUGE_PAGE_SZ     ) flags |= (int)MAP_HUGETLB | (int)MAP_HUGE_2MB;
  if( page_sz==FD_SHMEM_GIGANTIC_PAGE_SZ ) flags |= (int)MAP_HUGETLB | (int)MAP_HUGE_1GB;

  int fd = -1;

  /* See fd_shmem_create for details on the locking, mempolicy
     and what not tricks */

  FD_SHMEM_LOCK;

  int err;
# define ERROR( cleanup ) do { err = errno; goto cleanup; } while(0)

  void * mem = NULL;

  int    orig_mempolicy;
  ulong  orig_nodemask[ (FD_SHMEM_NUMA_MAX+63UL)/64UL ];
  ulong  nodemask[ (FD_SHMEM_NUMA_MAX+63UL)/64UL ];

  if( FD_UNLIKELY( fd_numa_get_mempolicy( &orig_mempolicy, orig_nodemask, FD_SHMEM_NUMA_MAX, NULL, 0UL ) ) ) {
    FD_LOG_WARNING(( "fd_numa_get_mempolicy failed (%i-%s)", errno, strerror( errno ) ));
    ERROR( done );
  }

  fd_memset( nodemask, 0, 8UL*((FD_SHMEM_NUMA_MAX+63UL)/64UL) );
  nodemask[ numa_idx >> 6 ] = 1UL << (numa_idx & 63UL);
  if( FD_UNLIKELY( fd_numa_set_mempolicy( MPOL_BIND | MPOL_F_STATIC_NODES, nodemask, FD_SHMEM_NUMA_MAX ) ) ) {
    FD_LOG_WARNING(( "fd_numa_set_mempolicy failed (%i-%s)", errno, strerror( errno ) ));
    ERROR( done );
  }

  mem = mmap( NULL, sz, PROT_READ | PROT_WRITE, flags, fd, (off_t)0);
  if( FD_UNLIKELY( mem==MAP_FAILED ) ) {
    FD_LOG_WARNING(( "mmap(NULL,%lu KiB,PROT_READ|PROT_WRITE,%x,-1,0) failed (%i-%s)", sz>>10, flags, errno, strerror( errno ) ));
    ERROR( restore );
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, page_sz ) ) ) {
    FD_LOG_WARNING(( "mmap(NULL,%lu KiB,PROT_READ|PROT_WRITE,%x,-1,0) misaligned", sz>>10, flags ));
    errno = EFAULT; /* ENOMEM is arguable */
    ERROR( unmap );
  }

  if( FD_UNLIKELY( fd_numa_mlock( mem, sz ) ) ) {
    FD_LOG_WARNING(( "fd_numa_mlock(anon,%lu KiB) failed (%i-%s)", sz>>10, errno, strerror( errno ) ));
    ERROR( unmap );
  }

  /* FIXME: NUMA TOUCH HERE (ALSO WOULD A LOCAL TOUCH WORK GIVEN THE
     MEMPOLICY DONE ABOVE?) */

  /* Just in case fd_numa_set_mempolicy clobbered it */

  fd_memset( nodemask, 0, 8UL*((FD_SHMEM_NUMA_MAX+63UL)/64UL) );
  nodemask[ numa_idx >> 6 ] = 1UL << (numa_idx & 63UL);
  if( FD_UNLIKELY( fd_numa_mbind( mem, sz, MPOL_BIND, nodemask, FD_SHMEM_NUMA_MAX, MPOL_MF_MOVE | MPOL_MF_STRICT ) ) ) {
    FD_LOG_WARNING(( "fd_numa_mbind(anon,%lu KiB,MPOL_BIND,1UL<<%lu,MPOL_MF_MOVE|MPOL_MF_STRICT) failed (%i-%s)",
                     sz>>10, numa_idx, errno, strerror( errno ) ));
    ERROR( unmap );
  }

  err = fd_shmem_numa_validate( mem, page_sz, page_cnt, numa_idx ); /* logs details */
  if( FD_UNLIKELY( err ) )
    FD_LOG_WARNING(( "mmap(NULL,%lu KiB,PROT_READ|PROT_WRITE,%x,-1,0) numa binding failed (%i-%s)",
                     sz>>10, flags, err, strerror( err ) ));

# undef ERROR

unmap:
  if( FD_UNLIKELY( err ) && FD_UNLIKELY( munmap( mem, sz ) ) )
    FD_LOG_WARNING(( "munmap(anon,%lu KiB) failed (%i-%s); attempting to continue", sz>>10, errno, strerror( errno ) ));

restore:
  if( FD_UNLIKELY( fd_numa_set_mempolicy( orig_mempolicy, orig_nodemask, FD_SHMEM_NUMA_MAX ) ) )
    FD_LOG_WARNING(( "fd_numa_set_mempolicy failed (%i-%s); attempting to continue", errno, strerror( errno ) ));

done:
  FD_SHMEM_UNLOCK;
  return err ? NULL : mem;
}
