#if FD_HAS_THREADS /* THREADS implies HOSTED */
#define _GNU_SOURCE
#endif

#include "fd_shmem_private.h"

#if FD_HAS_HOSTED

#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <linux/mempolicy.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <linux/mman.h>

#if FD_HAS_THREADS
pthread_mutex_t fd_shmem_private_lock[1];
#endif

char  fd_shmem_private_base[ FD_SHMEM_PRIVATE_BASE_MAX ]; /* ""  at thread group start, initialized at boot */
ulong fd_shmem_private_base_len;                          /* 0UL at ",                  initialized at boot */

/* NUMA TOPOLOGY APIS *************************************************/

static ulong  fd_shmem_private_numa_cnt;                      /* 0UL at thread group start, initialized at boot */
static ulong  fd_shmem_private_cpu_cnt;                       /* " */
static ushort fd_shmem_private_numa_idx[ FD_SHMEM_CPU_MAX  ]; /* " */
static ushort fd_shmem_private_cpu_idx [ FD_SHMEM_NUMA_MAX ]; /* " */

ulong fd_shmem_numa_cnt( void ) { return fd_shmem_private_numa_cnt; }
ulong fd_shmem_cpu_cnt ( void ) { return fd_shmem_private_cpu_cnt;  }

ulong
fd_shmem_numa_idx( ulong cpu_idx ) {
  if( FD_UNLIKELY( cpu_idx>=fd_shmem_private_cpu_cnt ) ) return ULONG_MAX;
  return (ulong)fd_shmem_private_numa_idx[ cpu_idx ];
}

ulong
fd_shmem_cpu_idx( ulong numa_idx ) {
  if( FD_UNLIKELY( numa_idx>=fd_shmem_private_numa_cnt ) ) return ULONG_MAX;
  return (ulong)fd_shmem_private_cpu_idx[ numa_idx ];
}

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
        FD_LOG_WARNING(( "fd_numa_move_pages query failed (%i-%s)", errno, fd_io_strerror( errno ) ));
        return errno;
      }
      for( ulong batch_idx=0UL; batch_idx<batch_cnt; batch_idx++ ) {
        if( FD_UNLIKELY( batch_status[batch_idx]<0 ) ) {
          int err = -batch_status[batch_idx];
          FD_LOG_WARNING(( "page status failed (%i-%s)", err, fd_io_strerror( err ) ));
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

int
fd_shmem_create_multi( char const *  name,
                       ulong         page_sz,
                       ulong         sub_cnt,
                       ulong const * _sub_page_cnt,
                       ulong const * _sub_cpu_idx,
                       ulong         mode ) {

  /* Check input args */

  if( FD_UNLIKELY( !fd_shmem_name_len( name ) ) ) { FD_LOG_WARNING(( "bad name (%s)", name ? name : "NULL" )); return EINVAL; }

  if( FD_UNLIKELY( !fd_shmem_is_page_sz( page_sz ) ) ) { FD_LOG_WARNING(( "bad page_sz (%lu)", page_sz )); return EINVAL; }

  if( FD_UNLIKELY( !sub_cnt       ) ) { FD_LOG_WARNING(( "zero sub_cnt"      )); return EINVAL; }
  if( FD_UNLIKELY( !_sub_page_cnt ) ) { FD_LOG_WARNING(( "NULL sub_page_cnt" )); return EINVAL; }
  if( FD_UNLIKELY( !_sub_cpu_idx  ) ) { FD_LOG_WARNING(( "NULL sub_cpu_idx"  )); return EINVAL; }

  ulong cpu_cnt = fd_shmem_cpu_cnt();

  ulong page_cnt = 0UL;
  for( ulong sub_idx=0UL; sub_idx<sub_cnt; sub_idx++ ) {
    ulong sub_page_cnt = _sub_page_cnt[ sub_idx ];
    if( FD_UNLIKELY( !sub_page_cnt ) ) continue; /* Skip over empty subregions */

    page_cnt += sub_page_cnt;
    if( FD_UNLIKELY( page_cnt<sub_page_cnt ) ) {
      FD_LOG_WARNING(( "sub[%lu] sub page_cnt overflow (page_cnt %lu, sub_page_cnt %lu)",
                       sub_idx, page_cnt-sub_page_cnt, sub_page_cnt ));
      return EINVAL;
    }

    ulong sub_cpu_idx = _sub_cpu_idx[ sub_idx ];
    if( FD_UNLIKELY( sub_cpu_idx>=cpu_cnt ) ) {
      FD_LOG_WARNING(( "sub[%lu] bad cpu_idx (%lu)", sub_idx, sub_cpu_idx ));
      return EINVAL;
    }
  }

  if( FD_UNLIKELY( !((1UL<=page_cnt) & (page_cnt<=(((ulong)LONG_MAX)/page_sz))) ) ) { /* LONG_MAX from off_t */
    FD_LOG_WARNING(( "bad total page_cnt (%lu)", page_cnt ));
    return EINVAL;
  }

  if( FD_UNLIKELY( mode!=(ulong)(mode_t)mode ) ) { FD_LOG_WARNING(( "bad mode (0%03lo)", mode )); return EINVAL; }

  /* We use the FD_SHMEM_LOCK in create just to be safe given some
     thread safety ambiguities in the documentation for some of the
     below APIs. */

  FD_SHMEM_LOCK;

  int err;

# define ERROR( cleanup ) do { err = errno; goto cleanup; } while(0)

  int    orig_mempolicy;
  ulong  orig_nodemask[ (FD_SHMEM_NUMA_MAX+63UL)/64UL ];
  char   path[ FD_SHMEM_PRIVATE_PATH_BUF_MAX ];
  int    fd;
  void * shmem;

  ulong  sz = page_cnt*page_sz;

  /* Save this thread's numa node mempolicy */

  if( FD_UNLIKELY( fd_numa_get_mempolicy( &orig_mempolicy, orig_nodemask, FD_SHMEM_NUMA_MAX, NULL, 0UL ) ) ) {
    FD_LOG_WARNING(( "fd_numa_get_mempolicy failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    ERROR( done );
  }

  /* Create the region */

  fd = open( fd_shmem_private_path( name, page_sz, path ), O_RDWR | O_CREAT | O_EXCL, (mode_t)mode );
  if( FD_UNLIKELY( fd==-1 ) ) {
    FD_LOG_WARNING(( "open(\"%s\",O_RDWR|O_CREAT|O_EXCL,0%03lo) failed (%i-%s)", path, mode, errno, fd_io_strerror( errno ) ));
    ERROR( restore );
  }

  /* Size the region */

  if( FD_UNLIKELY( ftruncate( fd, (off_t)sz ) ) ) {
    FD_LOG_WARNING(( "ftruncate(\"%s\",%lu KiB) failed (%i-%s)", path, sz>>10, errno, fd_io_strerror( errno ) ));
    ERROR( close );
  }

  /* Map the region into our address space. */

  shmem = mmap( NULL, sz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, (off_t)0);
  if( FD_UNLIKELY( shmem==MAP_FAILED ) ) {
    FD_LOG_WARNING(( "mmap(NULL,%lu KiB,PROT_READ|PROT_WRITE,MAP_SHARED,\"%s\",0) failed (%i-%s)",
                     sz>>10, path, errno, fd_io_strerror( errno ) ));
    ERROR( close );
  }

  /* Validate the mapping */

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, page_sz ) ) ) {
    FD_LOG_WARNING(( "misaligned memory mapping for \"%s\"\n\t"
                     "This thread group's hugetlbfs mount path (--shmem-path / FD_SHMEM_PATH):\n\t"
                     "\t%s\n\t"
                     "has probably been corrupted and needs to be redone.\n\t"
                     "See 'bin/fd_shmem_cfg help' for more information.",
                     path, fd_shmem_private_base ));
    errno = EFAULT; /* ENOMEM is arguable */
    ERROR( unmap );
  }

  /* For each subregion */

  uchar * sub_shmem = (uchar *)shmem;
  for( ulong sub_idx=0UL; sub_idx<sub_cnt; sub_idx++ ) {
    ulong sub_page_cnt = _sub_page_cnt[ sub_idx ];
    if( FD_UNLIKELY( !sub_page_cnt ) ) continue; /* Skip over empty sub-regions */

    ulong sub_sz       = sub_page_cnt*page_sz;
    ulong sub_cpu_idx  = _sub_cpu_idx[ sub_idx ];
    ulong sub_numa_idx = fd_shmem_numa_idx( sub_cpu_idx );

    ulong nodemask[ (FD_SHMEM_NUMA_MAX+63UL)/64UL ];

    /* Set the mempolicy to bind newly allocated memory to the numa idx
       corresponding to logical cpu cpu_idx.  This should force page
       allocation to be on the desired numa node, keeping our fingers
       crossed that even the ftruncate / mmap above did not trigger
       this; it doesn't seem too, even when the user's thread group has
       configured things like mlockall(MCL_CURRENT | MCL_FUTURE ).
       Theoretically, the fd_numa_mbind below should do it without this
       but the Linux kernel tends to view requests to move pages between
       numa nodes after allocation as for entertainment purposes only. */

    fd_memset( nodemask, 0, 8UL*((FD_SHMEM_NUMA_MAX+63UL)/64UL) );
    nodemask[ sub_numa_idx >> 6 ] = 1UL << (sub_numa_idx & 63UL);

    if( FD_UNLIKELY( fd_numa_set_mempolicy( MPOL_BIND | MPOL_F_STATIC_NODES, nodemask, FD_SHMEM_NUMA_MAX ) ) ) {
      FD_LOG_WARNING(( "fd_numa_set_mempolicy failed (%i-%s)", errno, fd_io_strerror( errno ) ));
      ERROR( unmap );
    }

    /* If a mempolicy has been set and the numa_idx node does not have
       sufficient pages to back the mapping, touching the memory will
       trigger a SIGBUS when it touches the first part of the mapping
       for which there are no pages.  Unfortunately, mmap will only
       error if there are insufficient pages across all NUMA nodes (even
       if using mlockall( MCL_FUTURE ) or passing MAP_POPULATE), so we
       need to check that the mapping can be backed without handling
       signals.

       So we mlock the subregion to force the region to be backed by
       pages now.  The subregion should be backed by page_sz pages
       (thanks to the hugetlbfs configuration) and should be on the
       correct NUMA node (thanks to the mempolicy above).  Specifically,
       mlock will error with ENOMEM if there were insufficient pages
       available.  mlock guarantees that if it succeeds, the mapping has
       been fully backed by pages and these pages will remain resident
       in DRAM at least until the mapping is closed.  We can then
       proceed as usual without the risk of meeting SIGBUS or its
       friends. */

    if( FD_UNLIKELY( fd_numa_mlock( sub_shmem, sub_sz ) ) ) {
      FD_LOG_WARNING(( "sub[%lu]: fd_numa_mlock(\"%s\",%lu KiB) failed (%i-%s)",
                       sub_idx, path, sub_sz>>10, errno, fd_io_strerror( errno ) ));
      ERROR( unmap );
    }

    /* At this point all pages in this subregion should be allocated on
       the right NUMA node and resident in DRAM.  But in the spirit of
       not trusting Linux to get this right robustly, we continue with
       touching pages from cpu_idx. */

    /* FIXME: NUMA TOUCH HERE (ALSO WOULD A LOCAL TOUCH WORK GIVEN THE
       MEMPOLICY DONE ABOVE?) */

    /* fd_numa_mbind the memory subregion to this numa node to nominally
       stay put after we unmap it.  We recompute the nodemask to be on
       the safe side in case set mempolicy above clobbered it. */

    fd_memset( nodemask, 0, 8UL*((FD_SHMEM_NUMA_MAX+63UL)/64UL) );
    nodemask[ sub_numa_idx >> 6 ] = 1UL << (sub_numa_idx & 63UL);

    if( FD_UNLIKELY( fd_numa_mbind( sub_shmem, sub_sz, MPOL_BIND, nodemask, FD_SHMEM_NUMA_MAX, MPOL_MF_MOVE|MPOL_MF_STRICT ) ) ) {
      FD_LOG_WARNING(( "sub[%lu]: fd_numa_mbind(\"%s\",%lu KiB,MPOL_BIND,1UL<<%lu,MPOL_MF_MOVE|MPOL_MF_STRICT) failed (%i-%s)",
                       sub_idx, path, sub_sz>>10, sub_numa_idx, errno, fd_io_strerror( errno ) ));
      ERROR( unmap );
    }

    /* And since the fd_numa_mbind still often will ignore requests, we
       double check that the pages are in the right place. */

    int warn = fd_shmem_numa_validate( sub_shmem, page_sz, sub_page_cnt, sub_cpu_idx ); /* logs details */
    if( FD_UNLIKELY( warn ) )
      FD_LOG_WARNING(( "sub[%lu]: mmap(NULL,%lu KiB,PROT_READ|PROT_WRITE,MAP_SHARED,\"%s\",0) numa binding failed (%i-%s)",
                       sub_idx, sub_sz>>10, path, warn, fd_io_strerror( warn ) ));

    sub_shmem += sub_sz;
  }

  err = 0;

# undef ERROR

unmap:
  if( FD_UNLIKELY( munmap( shmem, sz ) ) )
    FD_LOG_WARNING(( "munmap(\"%s\",%lu KiB) failed (%i-%s); attempting to continue",
                     path, sz>>10, errno, fd_io_strerror( errno ) ));

close:
  if( FD_UNLIKELY( err ) && FD_UNLIKELY( unlink( path ) ) )
    FD_LOG_WARNING(( "unlink(\"%s\") failed (%i-%s)", path, errno, fd_io_strerror( errno ) )); /* Don't log "attempting ..." */
  if( FD_UNLIKELY( close( fd ) ) )
    FD_LOG_WARNING(( "close(\"%s\") failed (%i-%s); attempting to continue", path, errno, fd_io_strerror( errno ) ));

restore:
  if( FD_UNLIKELY( fd_numa_set_mempolicy( orig_mempolicy, orig_nodemask, FD_SHMEM_NUMA_MAX ) ) )
    FD_LOG_WARNING(( "fd_numa_set_mempolicy failed (%i-%s); attempting to continue", errno, fd_io_strerror( errno ) ));

done:
  FD_SHMEM_UNLOCK;
  return err;
}

int
fd_shmem_unlink( char const * name,
                 ulong        page_sz ) {
  char path[ FD_SHMEM_PRIVATE_PATH_BUF_MAX ];

  /* Check input args */

  if( FD_UNLIKELY( !fd_shmem_name_len( name ) ) ) { FD_LOG_WARNING(( "bad name (%s)", name ? name : "NULL" )); return EINVAL; }

  if( FD_UNLIKELY( !fd_shmem_is_page_sz( page_sz ) ) ) { FD_LOG_WARNING(( "bad page_sz (%lu)", page_sz )); return EINVAL; }

  /* Unlink the name */

  if( FD_UNLIKELY( unlink( fd_shmem_private_path( name, page_sz, path ) ) ) ) {
    FD_LOG_WARNING(( "unlink(\"%s\") failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
    return errno;
  }

  return 0;
}

int
fd_shmem_info( char const *      name,
               ulong             page_sz,
               fd_shmem_info_t * opt_info ) {

  if( FD_UNLIKELY( !fd_shmem_name_len( name ) ) ) { FD_LOG_WARNING(( "bad name (%s)", name ? name : "NULL" )); return EINVAL; }

  if( !page_sz ) {
    if( !fd_shmem_info( name, FD_SHMEM_GIGANTIC_PAGE_SZ, opt_info ) ) return 0;
    if( !fd_shmem_info( name, FD_SHMEM_HUGE_PAGE_SZ,     opt_info ) ) return 0;
    if( !fd_shmem_info( name, FD_SHMEM_NORMAL_PAGE_SZ,   opt_info ) ) return 0;
    return ENOENT;
  }

  if( FD_UNLIKELY( !fd_shmem_is_page_sz( page_sz ) ) ) { FD_LOG_WARNING(( "bad page_sz (%lu)", page_sz )); return EINVAL; }

  char path[ FD_SHMEM_PRIVATE_PATH_BUF_MAX ];
  int  fd = open( fd_shmem_private_path( name, page_sz, path ), O_RDONLY, (mode_t)0 );
  if( FD_UNLIKELY( fd==-1 ) ) return errno; /* no logging here as this might be an existence check */

  struct stat stat[1];
  if( FD_UNLIKELY( fstat( fd, stat ) ) ) {
    FD_LOG_WARNING(( "fstat failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    int err = errno;
    if( FD_UNLIKELY( close( fd ) ) )
      FD_LOG_WARNING(( "close(\"%s\") failed (%i-%s); attempting to continue", path, errno, fd_io_strerror( errno ) ));
    return err;
  }

  ulong sz = (ulong)stat->st_size;
  if( FD_UNLIKELY( !fd_ulong_is_aligned( sz, page_sz ) ) ) {
    FD_LOG_WARNING(( "\"%s\" size (%lu) not a page size (%lu) multiple\n\t"
                     "This thread group's hugetlbfs mount path (--shmem-path / FD_SHMEM_PATH):\n\t"
                     "\t%s\n\t"
                     "has probably been corrupted and needs to be redone.\n\t"
                     "See 'bin/fd_shmem_cfg help' for more information.",
                     path, sz, page_sz, fd_shmem_private_base ));
    if( FD_UNLIKELY( close( fd ) ) )
      FD_LOG_WARNING(( "close(\"%s\") failed (%i-%s); attempting to continue", path, errno, fd_io_strerror( errno ) ));
    return EFAULT;
  }
  ulong page_cnt = sz / page_sz;

  if( FD_UNLIKELY( close( fd ) ) )
    FD_LOG_WARNING(( "close(\"%s\") failed (%i-%s); attempting to continue", path, errno, fd_io_strerror( errno ) ));

  if( opt_info ) {
    opt_info->page_sz  = page_sz;
    opt_info->page_cnt = page_cnt;
  }
  return 0;
}

/* RAW PAGE ALLOCATION APIS *******************************************/

void *
fd_shmem_acquire_multi( ulong         page_sz,
                        ulong         sub_cnt,
                        ulong const * _sub_page_cnt,
                        ulong const * _sub_cpu_idx ) {

  /* Check input args */

  if( FD_UNLIKELY( !fd_shmem_is_page_sz( page_sz ) ) ) { FD_LOG_WARNING(( "bad page_sz (%lu)", page_sz )); return NULL; }

  if( FD_UNLIKELY( !sub_cnt       ) ) { FD_LOG_WARNING(( "zero sub_cnt"      )); return NULL; }
  if( FD_UNLIKELY( !_sub_page_cnt ) ) { FD_LOG_WARNING(( "NULL sub_page_cnt" )); return NULL; }
  if( FD_UNLIKELY( !_sub_cpu_idx  ) ) { FD_LOG_WARNING(( "NULL sub_cpu_idx"  )); return NULL; }

  ulong cpu_cnt = fd_shmem_cpu_cnt();

  ulong page_cnt = 0UL;
  for( ulong sub_idx=0UL; sub_idx<sub_cnt; sub_idx++ ) {
    ulong sub_page_cnt = _sub_page_cnt[ sub_idx ];
    if( FD_UNLIKELY( !sub_page_cnt ) ) continue; /* Skip over empty subregions */

    page_cnt += sub_page_cnt;
    if( FD_UNLIKELY( page_cnt<sub_page_cnt ) ) {
      FD_LOG_WARNING(( "sub[%lu] sub page_cnt overflow (page_cnt %lu, sub_page_cnt %lu)",
                       sub_idx, page_cnt-sub_page_cnt, sub_page_cnt ));
      return NULL;
    }

    ulong sub_cpu_idx = _sub_cpu_idx[ sub_idx ];
    if( FD_UNLIKELY( sub_cpu_idx>=cpu_cnt ) ) {
      FD_LOG_WARNING(( "sub[%lu] bad cpu_idx (%lu)", sub_idx, sub_cpu_idx ));
      return NULL;
    }
  }

  if( FD_UNLIKELY( !((1UL<=page_cnt) & (page_cnt<=(((ulong)LONG_MAX)/page_sz))) ) ) { /* LONG_MAX from off_t */
    FD_LOG_WARNING(( "bad total page_cnt (%lu)", page_cnt ));
    return NULL;
  }

  int flags = MAP_PRIVATE | MAP_ANONYMOUS;
  if( page_sz==FD_SHMEM_HUGE_PAGE_SZ     ) flags |= (int)MAP_HUGETLB | (int)MAP_HUGE_2MB;
  if( page_sz==FD_SHMEM_GIGANTIC_PAGE_SZ ) flags |= (int)MAP_HUGETLB | (int)MAP_HUGE_1GB;

  /* See fd_shmem_create_multi for details on the locking, mempolicy
     and what not tricks */

  FD_SHMEM_LOCK;

  int err;

# define ERROR( cleanup ) do { err = errno; goto cleanup; } while(0)

  int    orig_mempolicy;
  ulong  orig_nodemask[ (FD_SHMEM_NUMA_MAX+63UL)/64UL ];
  void * mem = NULL;

  ulong  sz = page_cnt*page_sz;

  if( FD_UNLIKELY( fd_numa_get_mempolicy( &orig_mempolicy, orig_nodemask, FD_SHMEM_NUMA_MAX, NULL, 0UL ) ) ) {
    FD_LOG_WARNING(( "fd_numa_get_mempolicy failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    ERROR( done );
  }

  mem = mmap( NULL, sz, PROT_READ | PROT_WRITE, flags, -1, (off_t)0);
  if( FD_UNLIKELY( mem==MAP_FAILED ) ) {
    FD_LOG_WARNING(( "mmap(NULL,%lu KiB,PROT_READ|PROT_WRITE,%x,-1,0) failed (%i-%s)",
                     sz>>10, flags, errno, fd_io_strerror( errno ) ));
    ERROR( restore );
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, page_sz ) ) ) {
    FD_LOG_WARNING(( "mmap(NULL,%lu KiB,PROT_READ|PROT_WRITE,%x,-1,0) misaligned", sz>>10, flags ));
    errno = EFAULT; /* ENOMEM is arguable */
    ERROR( unmap );
  }

  uchar * sub_mem = (uchar *)mem;
  for( ulong sub_idx=0UL; sub_idx<sub_cnt; sub_idx++ ) {
    ulong sub_page_cnt = _sub_page_cnt[ sub_idx ];
    if( FD_UNLIKELY( !sub_page_cnt ) ) continue;

    ulong sub_sz       = sub_page_cnt*page_sz;
    ulong sub_cpu_idx  = _sub_cpu_idx[ sub_idx ];
    ulong sub_numa_idx = fd_shmem_numa_idx( sub_cpu_idx );

    ulong nodemask[ (FD_SHMEM_NUMA_MAX+63UL)/64UL ];

    fd_memset( nodemask, 0, 8UL*((FD_SHMEM_NUMA_MAX+63UL)/64UL) );
    nodemask[ sub_numa_idx >> 6 ] = 1UL << (sub_numa_idx & 63UL);

    if( FD_UNLIKELY( fd_numa_set_mempolicy( MPOL_BIND | MPOL_F_STATIC_NODES, nodemask, FD_SHMEM_NUMA_MAX ) ) ) {
      FD_LOG_WARNING(( "fd_numa_set_mempolicy failed (%i-%s)", errno, fd_io_strerror( errno ) ));
      ERROR( unmap );
    }

    if( FD_UNLIKELY( fd_numa_mlock( sub_mem, sub_sz ) ) ) {
      FD_LOG_WARNING(( "sub[%lu]: fd_numa_mlock(anon,%lu KiB) failed (%i-%s)",
                       sub_idx, sub_sz>>10, errno, fd_io_strerror( errno ) ));
      ERROR( unmap );
    }

    /* FIXME: NUMA TOUCH HERE (ALSO WOULD A LOCAL TOUCH WORK GIVEN THE
       MEMPOLICY DONE ABOVE?) */

    fd_memset( nodemask, 0, 8UL*((FD_SHMEM_NUMA_MAX+63UL)/64UL) );
    nodemask[ sub_numa_idx >> 6 ] = 1UL << (sub_numa_idx & 63UL);

    if( FD_UNLIKELY( fd_numa_mbind( sub_mem, sub_sz, MPOL_BIND, nodemask, FD_SHMEM_NUMA_MAX, MPOL_MF_MOVE|MPOL_MF_STRICT ) ) ) {
      FD_LOG_WARNING(( "sub[%lu]: fd_numa_mbind(anon,%lu KiB,MPOL_BIND,1UL<<%lu,MPOL_MF_MOVE|MPOL_MF_STRICT) failed (%i-%s)",
                       sub_idx, sub_sz>>10, sub_numa_idx, errno, fd_io_strerror( errno ) ));
      ERROR( unmap );
    }

    int warn = fd_shmem_numa_validate( sub_mem, page_sz, sub_page_cnt, sub_cpu_idx ); /* logs details */
    if( FD_UNLIKELY( warn ) )
      FD_LOG_WARNING(( "sub[%lu]: mmap(NULL,%lu KiB,PROT_READ|PROT_WRITE,%x,-1,0) numa binding failed (%i-%s)",
                       sub_idx, sub_sz>>10, flags, warn, fd_io_strerror( warn ) ));

    sub_mem += sub_sz;
  }

  err = 0;

# undef ERROR

unmap:
  if( FD_UNLIKELY( err ) && FD_UNLIKELY( munmap( mem, sz ) ) )
    FD_LOG_WARNING(( "munmap(anon,%lu KiB) failed (%i-%s); attempting to continue",
                     sz>>10, errno, fd_io_strerror( errno ) ));

restore:
  if( FD_UNLIKELY( fd_numa_set_mempolicy( orig_mempolicy, orig_nodemask, FD_SHMEM_NUMA_MAX ) ) )
    FD_LOG_WARNING(( "fd_numa_set_mempolicy failed (%i-%s); attempting to continue", errno, fd_io_strerror( errno ) ));

done:
  FD_SHMEM_UNLOCK;
  return err ? NULL : mem;
}

void
fd_shmem_release( void * mem,
                  ulong  page_sz,
                  ulong  page_cnt ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return;
  }

  if( FD_UNLIKELY( !fd_shmem_is_page_sz( page_sz ) ) ) {
    FD_LOG_WARNING(( "bad page_sz (%lu)", page_sz ));
    return;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, page_sz ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return;
  }

  if( FD_UNLIKELY( !((1UL<=page_cnt) & (page_cnt<=(((ulong)LONG_MAX)/page_sz))) ) ) {
    FD_LOG_WARNING(( "bad page_cnt (%lu)", page_cnt ));
    return;
  }

  ulong sz = page_sz*page_cnt;

  if( FD_UNLIKELY( munmap( mem, sz ) ) )
    FD_LOG_WARNING(( "munmap(anon,%lu KiB) failed (%i-%s); attempting to continue", sz>>10, errno, fd_io_strerror( errno ) ));
}

/* SHMEM PARSING APIS *************************************************/

ulong
fd_shmem_name_len( char const * name ) {
  if( FD_UNLIKELY( !name ) ) return 0UL; /* NULL name */

  ulong len = 0UL;
  while( FD_LIKELY( len<FD_SHMEM_NAME_MAX ) ) {
    char c = name[len];
    if( FD_UNLIKELY( !c ) ) break;
    if( FD_UNLIKELY( !( (!!isalnum( c )) | ((len>0UL) & ((c=='_') | (c=='-') | (c=='.'))) ) ) ) return 0UL; /* Bad character */
    len++;
  }

  if( FD_UNLIKELY( !len                   ) ) return 0UL; /* Name too short (empty string) */
  if( FD_UNLIKELY( len>=FD_SHMEM_NAME_MAX ) ) return 0UL; /* Name too long */
  return len;
}

int
fd_cstr_to_shmem_lg_page_sz( char const * cstr ) {
  if( !cstr ) return FD_SHMEM_UNKNOWN_LG_PAGE_SZ;

  if( !fd_cstr_casecmp( cstr, "normal"   ) ) return FD_SHMEM_NORMAL_LG_PAGE_SZ;
  if( !fd_cstr_casecmp( cstr, "huge"     ) ) return FD_SHMEM_HUGE_LG_PAGE_SZ;
  if( !fd_cstr_casecmp( cstr, "gigantic" ) ) return FD_SHMEM_GIGANTIC_LG_PAGE_SZ;

  int i = fd_cstr_to_int( cstr );
  if( i==FD_SHMEM_NORMAL_LG_PAGE_SZ   ) return FD_SHMEM_NORMAL_LG_PAGE_SZ;
  if( i==FD_SHMEM_HUGE_LG_PAGE_SZ     ) return FD_SHMEM_HUGE_LG_PAGE_SZ;
  if( i==FD_SHMEM_GIGANTIC_LG_PAGE_SZ ) return FD_SHMEM_GIGANTIC_LG_PAGE_SZ;

  return FD_SHMEM_UNKNOWN_LG_PAGE_SZ;
}

char const *
fd_shmem_lg_page_sz_to_cstr( int lg_page_sz ) {
  switch( lg_page_sz ) {
  case FD_SHMEM_NORMAL_LG_PAGE_SZ:   return "normal";
  case FD_SHMEM_HUGE_LG_PAGE_SZ:     return "huge";
  case FD_SHMEM_GIGANTIC_LG_PAGE_SZ: return "gigantic";
  default:                           break;
  }
  return "unknown";
}

ulong
fd_cstr_to_shmem_page_sz( char const * cstr ) {
  if( !cstr ) return FD_SHMEM_UNKNOWN_PAGE_SZ;

  if( !fd_cstr_casecmp( cstr, "normal"   ) ) return FD_SHMEM_NORMAL_PAGE_SZ;
  if( !fd_cstr_casecmp( cstr, "huge"     ) ) return FD_SHMEM_HUGE_PAGE_SZ;
  if( !fd_cstr_casecmp( cstr, "gigantic" ) ) return FD_SHMEM_GIGANTIC_PAGE_SZ;

  ulong u = fd_cstr_to_ulong( cstr );
  if( u==FD_SHMEM_NORMAL_PAGE_SZ   ) return FD_SHMEM_NORMAL_PAGE_SZ;
  if( u==FD_SHMEM_HUGE_PAGE_SZ     ) return FD_SHMEM_HUGE_PAGE_SZ;
  if( u==FD_SHMEM_GIGANTIC_PAGE_SZ ) return FD_SHMEM_GIGANTIC_PAGE_SZ;

  return FD_SHMEM_UNKNOWN_PAGE_SZ;
}

char const *
fd_shmem_page_sz_to_cstr( ulong page_sz ) {
  switch( page_sz ) {
  case FD_SHMEM_NORMAL_PAGE_SZ:   return "normal";
  case FD_SHMEM_HUGE_PAGE_SZ:     return "huge";
  case FD_SHMEM_GIGANTIC_PAGE_SZ: return "gigantic";
  default:                        break;
  }
  return "unknown";
}

/* BOOT/HALT APIs *****************************************************/

void
fd_shmem_private_boot( int *    pargc,
                       char *** pargv ) {
  FD_LOG_INFO(( "fd_shmem: booting" ));

  /* Initialize the phtread mutex */

# if FD_HAS_THREADS
  pthread_mutexattr_t lockattr[1];

  if( FD_UNLIKELY( pthread_mutexattr_init( lockattr ) ) )
    FD_LOG_ERR(( "fd_shmem: pthread_mutexattr_init failed" ));

  if( FD_UNLIKELY( pthread_mutexattr_settype( lockattr, PTHREAD_MUTEX_RECURSIVE ) ) )
    FD_LOG_ERR(( "fd_shmem: pthread_mutexattr_settype failed" ));

  if( FD_UNLIKELY( pthread_mutex_init( fd_shmem_private_lock, lockattr ) ) )
    FD_LOG_ERR(( "fd_shmem: pthread_mutex_init failed" ));

  if( FD_UNLIKELY( pthread_mutexattr_destroy( lockattr ) ) )
    FD_LOG_WARNING(( "fd_shmem: pthread_mutexattr_destroy failed; attempting to continue" ));
# endif /* FD_HAS_THREADS */

  /* Cache the numa topology for this thread group's host for
     subsequent fast use by the application. */

  ulong numa_cnt = fd_numa_node_cnt();
  if( FD_UNLIKELY( !((1UL<=numa_cnt) & (numa_cnt<=FD_SHMEM_NUMA_MAX)) ) )
    FD_LOG_ERR(( "fd_shmem: unexpected numa_cnt %lu (expected in [1,%lu])", numa_cnt, FD_SHMEM_NUMA_MAX ));
  fd_shmem_private_numa_cnt = numa_cnt;

  ulong cpu_cnt = fd_numa_cpu_cnt();
  if( FD_UNLIKELY( !((1UL<=cpu_cnt) & (cpu_cnt<=FD_SHMEM_CPU_MAX)) ) )
    FD_LOG_ERR(( "fd_shmem: unexpected cpu_cnt %lu (expected in [1,%lu])", cpu_cnt, FD_SHMEM_CPU_MAX ));
  fd_shmem_private_cpu_cnt = cpu_cnt;

  for( ulong cpu_rem=cpu_cnt; cpu_rem; cpu_rem-- ) {
    ulong cpu_idx  = cpu_rem-1UL;
    ulong numa_idx = fd_numa_node_idx( cpu_idx );
    if( FD_UNLIKELY( numa_idx>=FD_SHMEM_NUMA_MAX) )
      FD_LOG_ERR(( "fd_shmem: unexpected numa idx (%lu) for cpu idx %lu", numa_idx, cpu_idx ));
    fd_shmem_private_numa_idx[ cpu_idx  ] = (ushort)numa_idx;
    fd_shmem_private_cpu_idx [ numa_idx ] = (ushort)cpu_idx;
  }

  /* Determine the shared memory domain for this thread group */

  char const * shmem_base = fd_env_strip_cmdline_cstr( pargc, pargv, "--shmem-path", "FD_SHMEM_PATH", "/mnt/.fd" );

  ulong len = strlen( shmem_base );
  while( (len>1UL) && (shmem_base[len-1UL]=='/') ) len--; /* lop off any trailing slashes */
  if( FD_UNLIKELY( !len ) ) FD_LOG_ERR(( "Too short --shmem-base" ));
  if( FD_UNLIKELY( len>=FD_SHMEM_PRIVATE_BASE_MAX ) ) FD_LOG_ERR(( "Too long --shmem-base" ));
  fd_memcpy( fd_shmem_private_base, shmem_base, len );
  fd_shmem_private_base[len] = '\0';
  fd_shmem_private_base_len = (ulong)len;

  /* At this point, shared memory is online */

  FD_LOG_INFO(( "fd_shmem: --shmem-path %s", fd_shmem_private_base ));
  FD_LOG_INFO(( "fd_shmem: boot success" ));
}

void
fd_shmem_private_halt( void ) {
  FD_LOG_INFO(( "fd_shmem: halting" ));

  /* At this point, shared memory is offline */

  fd_shmem_private_numa_cnt = 0;
  fd_shmem_private_cpu_cnt  = 0;
  fd_memset( fd_shmem_private_numa_idx, 0, FD_SHMEM_CPU_MAX );

  fd_shmem_private_base[0] = '\0';
  fd_shmem_private_base_len = 0UL;

# if FD_HAS_THREADS
  if( FD_UNLIKELY( pthread_mutex_destroy( fd_shmem_private_lock ) ) )
    FD_LOG_WARNING(( "fd_shmem: pthread_mutex_destroy failed; attempting to continue" ));
# endif /* FD_HAS_THREADS */

  FD_LOG_INFO(( "fd_shmem: halt success" ));
}

#else /* unhosted */

void
fd_shmem_private_boot( int *    pargc,
                       char *** pargv ) {
  FD_LOG_INFO(( "fd_shmem: booting" ));

  /* Strip the command line even though ignored to make environment
     parsing identical to downstream regardless of platform. */

  (void)fd_env_strip_cmdline_cstr( pargc, pargv, "--shmem-path", "FD_SHMEM_PATH", "/mnt/.fd" );

  FD_LOG_INFO(( "fd_shmem: --shmem-path (ignored)" ));
  FD_LOG_INFO(( "fd_shmem: boot success" ));
}

void
fd_shmem_private_halt( void ) {
  FD_LOG_INFO(( "fd_shmem: halting" ));
  FD_LOG_INFO(( "fd_shmem: halt success" ));
}

#endif
