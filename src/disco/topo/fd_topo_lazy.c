#define _GNU_SOURCE
#include "fd_topo.h"

#include "../../util/shmem/fd_shmem_private.h"
#include "../../util/wksp/fd_wksp_private.h"

#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>

/* Lazy-paged workspace creation.  Same as fd_shmem_create_multi /
   fd_shmem_update_multi but skips mlock, mbind, and NUMA validation so
   that pages are demand-faulted rather than pre-allocated.  This
   greatly reduces startup time at the cost of production performance
   and reliability. */

static int
fd_shmem_create_multi_lazy_paged( char const *  name,
                                  ulong         page_sz,
                                  ulong         sub_cnt,
                                  ulong const * _sub_page_cnt,
                                  ulong const * _sub_cpu_idx,
                                  ulong         mode,
                                  int           open_flags ) {

  if( FD_UNLIKELY( !fd_shmem_name_len( name ) ) ) { FD_LOG_WARNING(( "bad name (%s)", name ? name : "NULL" )); return EINVAL; }
  if( FD_UNLIKELY( !fd_shmem_is_page_sz( page_sz ) ) ) { FD_LOG_WARNING(( "bad page_sz (%lu)", page_sz )); return EINVAL; }
  if( FD_UNLIKELY( !sub_cnt       ) ) { FD_LOG_WARNING(( "zero sub_cnt"      )); return EINVAL; }
  if( FD_UNLIKELY( !_sub_page_cnt ) ) { FD_LOG_WARNING(( "NULL sub_page_cnt" )); return EINVAL; }
  if( FD_UNLIKELY( !_sub_cpu_idx  ) ) { FD_LOG_WARNING(( "NULL sub_cpu_idx"  )); return EINVAL; }

  ulong cpu_cnt = fd_shmem_cpu_cnt();

  ulong page_cnt = 0UL;
  for( ulong sub_idx=0UL; sub_idx<sub_cnt; sub_idx++ ) {
    ulong sub_page_cnt = _sub_page_cnt[ sub_idx ];
    if( FD_UNLIKELY( !sub_page_cnt ) ) continue;

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

  if( FD_UNLIKELY( !((1UL<=page_cnt) & (page_cnt<=(((ulong)LONG_MAX)/page_sz))) ) ) {
    FD_LOG_WARNING(( "bad total page_cnt (%lu)", page_cnt ));
    return EINVAL;
  }

  if( FD_UNLIKELY( mode!=(ulong)(mode_t)mode ) ) { FD_LOG_WARNING(( "bad mode (0%03lo)", mode )); return EINVAL; }

  FD_SHMEM_LOCK;

  int err;

# define ERROR( cleanup ) do { err = errno; goto cleanup; } while(0)

  char   path[ FD_SHMEM_PRIVATE_PATH_BUF_MAX ];
  int    fd;
  void * shmem;

  ulong  sz = page_cnt*page_sz;

  fd = open( fd_shmem_private_path( name, page_sz, path ), open_flags, (mode_t)mode );
  if( FD_UNLIKELY( fd==-1 ) ) {
    FD_LOG_WARNING(( "open(\"%s\",%#x,0%03lo) failed (%i-%s)", path, (uint)open_flags, mode, errno, fd_io_strerror( errno ) ));
    ERROR( done );
  }

  if( FD_UNLIKELY( ftruncate( fd, (off_t)sz ) ) ) {
    FD_LOG_WARNING(( "ftruncate(\"%s\",%lu KiB) failed (%i-%s)", path, sz>>10, errno, fd_io_strerror( errno ) ));
    ERROR( close );
  }

  shmem = mmap( NULL, sz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, (off_t)0);
  if( FD_UNLIKELY( shmem==MAP_FAILED ) ) {
    FD_LOG_WARNING(( "mmap(NULL,%lu KiB,PROT_READ|PROT_WRITE,MAP_SHARED,\"%s\",0) failed (%i-%s)",
                     sz>>10, path, errno, fd_io_strerror( errno ) ));
    ERROR( close );
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, page_sz ) ) ) {
    FD_LOG_WARNING(( "misaligned memory mapping for \"%s\"\n\t"
                     "This thread group's hugetlbfs mount path (--shmem-path / FD_SHMEM_PATH):\n\t"
                     "\t%s\n\t"
                     "has probably been corrupted and needs to be redone.\n\t"
                     "See 'bin/fd_shmem_cfg help' for more information.",
                     path, fd_shmem_private_base ));
    errno = EFAULT;
    ERROR( unmap );
  }

  err = 0;

# undef ERROR

unmap:
  if( FD_UNLIKELY( munmap( shmem, sz ) ) )
    FD_LOG_ERR(( "munmap(\"%s\",%lu KiB) failed (%i-%s)",
                 path, sz>>10, errno, fd_io_strerror( errno ) ));

close:
  if( FD_UNLIKELY( err ) && FD_UNLIKELY( unlink( path ) ) )
    FD_LOG_ERR(( "unlink(\"%s\") failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( close( fd ) ) )
    FD_LOG_ERR(( "close(\"%s\") failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));

done:
  FD_SHMEM_UNLOCK;
  return err;
}

/* Lazy-paged workspace join.  Same as fd_shmem_join but skips mlock so
   that pages are demand-faulted. */

static void *
fd_shmem_join_lazy_paged( char const *           name,
                          int                    mode,
                          int                    dump,
                          fd_shmem_join_info_t * opt_info ) {

  /* For regions already joined, defer to the normal join path (which
     just bumps the refcount). */
  fd_shmem_join_info_t existing;
  if( !fd_shmem_join_query_by_name( name, &existing ) ) {
    return fd_shmem_join( name, mode, dump, NULL, NULL, opt_info );
  }

  fd_shmem_info_t shmem_info[1];
  if( FD_UNLIKELY( fd_shmem_info( name, 0UL, shmem_info ) ) ) {
    FD_LOG_WARNING(( "unable to query region \"%s\"\n\tprobably does not exist or bad permissions", name ));
    return NULL;
  }
  ulong page_sz  = shmem_info->page_sz;
  ulong page_cnt = shmem_info->page_cnt;
  ulong sz       = page_sz*page_cnt;
  int   rw       = (mode==FD_SHMEM_JOIN_MODE_READ_WRITE);

  char path[ FD_SHMEM_PRIVATE_PATH_BUF_MAX ];
  int fd = open( fd_shmem_private_path( name, page_sz, path ), rw ? O_RDWR : O_RDONLY, (mode_t)0 );
  if( FD_UNLIKELY( fd==-1 ) ) {
    FD_LOG_WARNING(( "open(\"%s\",%s,0) failed (%i-%s)", path, rw ? "O_RDWR" : "O_RDONLY", errno, fd_io_strerror( errno ) ));
    return NULL;
  }

  void * const map_addr = fd_shmem_private_map_rand( sz, page_sz, PROT_READ );
  if( FD_UNLIKELY( map_addr==MAP_FAILED ) ) FD_LOG_ERR(( "fd_shmem_private_map_rand failed" ));

  void * shmem = mmap( map_addr, sz, PROT_READ|( rw?PROT_WRITE:0 ), MAP_SHARED|MAP_FIXED, fd, (off_t)0 );

  int mmap_errno = errno;
  if( FD_UNLIKELY( close( fd ) ) )
    FD_LOG_WARNING(( "close(\"%s\") failed (%i-%s); attempting to continue", path, errno, fd_io_strerror( errno ) ));

  if( FD_UNLIKELY( shmem==MAP_FAILED ) ) {
    FD_LOG_WARNING(( "mmap(%p,%lu KiB,%s,MAP_SHARED,\"%s\",0) failed (%i-%s)",
                     map_addr, sz>>10, rw ? "PROT_READ|PROT_WRITE" : "PROT_READ", path, mmap_errno, fd_io_strerror( mmap_errno ) ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, page_sz ) ) ) {
    if( FD_UNLIKELY( munmap( shmem, sz ) ) )
      FD_LOG_WARNING(( "munmap(\"%s\",%lu KiB) failed (%i-%s); attempting to continue",
                       path, sz>>10, errno, fd_io_strerror( errno ) ));
    FD_LOG_WARNING(( "misaligned memory mapping for \"%s\"\n\t"
                     "This thread group's hugetlbfs mount path (--shmem-path / FD_SHMEM_PATH):\n\t"
                     "\t%s\n\t"
                     "has probably been corrupted and needs to be redone.\n\t"
                     "See 'bin/fd_shmem_cfg help' for more information.",
                     path, fd_shmem_private_base ));
    return NULL;
  }

  if( FD_LIKELY( !dump ) ) {
    if( FD_UNLIKELY( madvise( shmem, sz, MADV_DONTDUMP ) ) )
      FD_LOG_WARNING(( "madvise(\"%s\",%lu KiB) failed (%i-%s); attempting to continue",
                      path, sz>>10, errno, fd_io_strerror( errno ) ));
  }

  if( FD_UNLIKELY( fd_shmem_join_anonymous( name, mode, shmem, shmem, page_sz, page_cnt ) ) ) {
    FD_LOG_WARNING(( "fd_shmem_join_anonymous(\"%s\") failed", name ));
    munmap( shmem, sz );
    return NULL;
  }

  if( opt_info ) {
    fd_shmem_join_query_by_name( name, opt_info );
  }

  return shmem;
}

/* Public topo-level lazy-paged APIs */

int
fd_topo_create_workspace_lazy_paged( fd_topo_t *      topo,
                                     fd_topo_wksp_t * wksp,
                                     int              update_existing ) {
  char name[ PATH_MAX ];
  FD_TEST( fd_cstr_printf_check( name, PATH_MAX, NULL, "%s_%s.wksp", topo->app_name, wksp->name ) );

  ulong sub_page_cnt[ 1 ] = { wksp->page_cnt };
  ulong sub_cpu_idx [ 1 ] = { fd_shmem_cpu_idx( wksp->numa_idx ) };

  int err;
  if( FD_UNLIKELY( update_existing ) ) {
    err = fd_shmem_create_multi_lazy_paged( name, wksp->page_sz, 1, sub_page_cnt, sub_cpu_idx, S_IRUSR | S_IWUSR, O_RDWR );
  } else {
    err = fd_shmem_create_multi_lazy_paged( name, wksp->page_sz, 1, sub_page_cnt, sub_cpu_idx, S_IRUSR | S_IWUSR, O_RDWR | O_CREAT | O_EXCL );
  }
  if( FD_UNLIKELY( err && errno==ENOMEM ) ) return -1;
  else if( FD_UNLIKELY( err ) ) FD_LOG_ERR(( "fd_shmem_create_multi_lazy_paged failed" ));

  /* Temporarily mmap the region to initialize the workspace header.
     No shmem join registration needed — this mapping is short-lived. */

  ulong sz = wksp->page_cnt * wksp->page_sz;

  fd_shmem_info_t shmem_info[1];
  if( FD_UNLIKELY( fd_shmem_info( name, 0UL, shmem_info ) ) )
    FD_LOG_ERR(( "fd_shmem_info(\"%s\") failed", name ));

  char path[ FD_SHMEM_PRIVATE_PATH_BUF_MAX ];
  int fd = open( fd_shmem_private_path( name, shmem_info->page_sz, path ), O_RDWR, (mode_t)0 );
  if( FD_UNLIKELY( fd==-1 ) )
    FD_LOG_ERR(( "open(\"%s\") failed (%i-%s)", path, errno, fd_io_strerror( errno ) ));

  void * shmem = mmap( NULL, sz, PROT_READ | PROT_WRITE, MAP_SHARED, fd, (off_t)0 );
  if( FD_UNLIKELY( shmem==MAP_FAILED ) )
    FD_LOG_ERR(( "mmap(\"%s\",%lu KiB) failed (%i-%s)", path, sz>>10, errno, fd_io_strerror( errno ) ));
  if( FD_UNLIKELY( close( fd ) ) )
    FD_LOG_WARNING(( "close(\"%s\") failed (%i-%s); attempting to continue", path, errno, fd_io_strerror( errno ) ));

  void * wkspmem = fd_wksp_new( shmem, name, 0U, wksp->part_max, wksp->total_footprint );
  if( FD_UNLIKELY( !wkspmem ) ) FD_LOG_ERR(( "fd_wksp_new failed" ));

  fd_wksp_t * join = fd_wksp_join( wkspmem );
  if( FD_UNLIKELY( !join ) ) FD_LOG_ERR(( "fd_wksp_join failed" ));

  if( FD_LIKELY( wksp->known_footprint ) ) {
    ulong offset = fd_wksp_alloc( join, fd_topo_workspace_align(), wksp->known_footprint, 1UL );
    if( FD_UNLIKELY( !offset ) ) FD_LOG_ERR(( "fd_wksp_alloc failed" ));

    if( FD_UNLIKELY( fd_ulong_align_up( ((struct fd_wksp_private*)join)->gaddr_lo, fd_topo_workspace_align() ) != offset ) )
      FD_LOG_ERR(( "wksp gaddr_lo %lu != offset %lu", fd_ulong_align_up( ((struct fd_wksp_private*)join)->gaddr_lo, fd_topo_workspace_align() ), offset ));
  }

  fd_wksp_leave( join );

  if( FD_UNLIKELY( munmap( shmem, sz ) ) )
    FD_LOG_ERR(( "munmap failed (%i-%s)", errno, fd_io_strerror( errno ) ));

  return 0;
}

void
fd_topo_join_workspace_lazy_paged( fd_topo_t *      topo,
                                   fd_topo_wksp_t * wksp,
                                   int              mode,
                                   int              dump ) {
  (void)dump;

  char name[ PATH_MAX ];
  FD_TEST( fd_cstr_printf_check( name, PATH_MAX, NULL, "%s_%s.wksp", topo->app_name, wksp->name ) );

  wksp->wksp = fd_wksp_join( fd_shmem_join_lazy_paged( name, mode, dump, NULL ) );
  if( FD_UNLIKELY( !wksp->wksp ) ) FD_LOG_ERR(( "fd_wksp_join failed" ));
}
