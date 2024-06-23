#include "fd_shmem_private.h"
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include "fd_shmem_freebsd_private.h"

ulong fd_shmem_numa_cnt( void ) { return fd_numa_node_cnt(); }
ulong fd_shmem_cpu_cnt ( void ) { return fd_numa_cpu_cnt();  }

ulong
fd_shmem_numa_idx( ulong cpu_idx ) {
  return fd_numa_node_idx( cpu_idx );
}

ulong
fd_shmem_cpu_idx( ulong numa_idx ) {
  (void)numa_idx;
  FD_LOG_WARNING(( "fd_shmem_cpu_idx not supported on this platform" ));
  return 0UL;
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

  (void)cpu_idx;
  /* FIXME FreeBSD 14.1 has no proper NUMA support */

  return 0;
}

static int
fd_page_sz_to_psind( ulong page_sz ) {
# define FD_PSIND_CNT (64)
  static int  psind[ FD_PSIND_CNT ];
  static uint psind_cnt = 0U;

  FD_ONCE_BEGIN {
    for( ulong j=0UL; j<FD_PSIND_CNT; j++ ) psind[j] = -1;

    size_t page_sizes[ FD_PSIND_CNT ];
    int page_cnt = getpagesizes( page_sizes, FD_PSIND_CNT );
    if( FD_UNLIKELY( page_cnt<0 ) ) {
      FD_LOG_ERR(( "getpagesizes() failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    }
    psind_cnt = (uint)page_cnt;

    for( uint j=0U; j<psind_cnt; j++ ) {
      int page_shift = fd_ulong_find_lsb( page_sizes[j] );
      FD_TEST( page_shift>=0 && page_shift<FD_PSIND_CNT );
      psind[ page_shift ] = (int)j;
    }
  }
  FD_ONCE_END;

  int page_shift = fd_ulong_find_lsb( page_sz );
  if( FD_UNLIKELY( page_shift<0 || page_shift>=FD_PSIND_CNT ) ) return -1;
  return psind[ page_shift ];
}

int
fd_shmem_create_multi( char const *  name,
                       ulong         page_sz,
                       ulong         sub_cnt,
                       ulong const * _sub_page_cnt,
                       ulong const * _sub_cpu_idx,
                       ulong         mode ) {

  /* Check input args */

  int psind = fd_page_sz_to_psind( page_sz );
  if( FD_UNLIKELY( psind<0 ) ) {
    FD_LOG_WARNING(( "unsupported page size: %#lx", page_sz ));
    return EINVAL;
  }

  if( FD_UNLIKELY( !sub_cnt       ) ) { FD_LOG_WARNING(( "zero sub_cnt"      )); return EINVAL; }
  if( FD_UNLIKELY( !_sub_page_cnt ) ) { FD_LOG_WARNING(( "NULL sub_page_cnt" )); return EINVAL; }
  if( FD_UNLIKELY( !_sub_cpu_idx  ) ) { FD_LOG_WARNING(( "NULL sub_cpu_idx"  )); return EINVAL; }

  FD_SHMEM_LOCK;

  /* FIXME NUMA affinity not yet supported */

  int shm_fd = fd_shm_create_largepage( name, O_RDWR, psind, SHM_LARGEPAGE_ALLOC_NOWAIT, (mode_t)mode );

  if( FD_UNLIKELY( shm_fd<0 ) ) {
    FD_LOG_WARNING(( "shm_create_largepage(SHM_ANON,O_RDWR) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    FD_SHMEM_UNLOCK;
    return errno;
  }

  ulong page_cnt = 0UL;
  for( ulong sub_idx=0UL; sub_idx<sub_cnt; sub_idx++ ) {
    page_cnt += _sub_page_cnt[ sub_idx ];
  }
  ulong sz = page_cnt * page_sz;

  int grow_res = ftruncate( shm_fd, (off_t)sz );
  int grow_err = errno;
  close( shm_fd );

  if( FD_UNLIKELY( grow_res!=0 ) ) {
    FD_LOG_WARNING(( "ftruncate(sz=%#lx) failed (%i-%s)", sz, grow_err, fd_io_strerror( grow_err ) ));
    shm_unlink( name );
    FD_SHMEM_UNLOCK;
    return grow_err;
  }

  FD_SHMEM_UNLOCK;
  return 0;
}

int
fd_shmem_unlink( char const * name,
                 ulong        page_sz ) {
  (void)page_sz;
  return shm_unlink( name );
}

int
fd_shmem_info( char const *      name,
               ulong             page_sz,
               fd_shmem_info_t * opt_info ) {

  if( FD_UNLIKELY( !name ) ) { FD_LOG_WARNING(( "bad name (NULL)" )); return EINVAL; }

  if( !page_sz ) {
    if( !fd_shmem_info( name, FD_SHMEM_GIGANTIC_PAGE_SZ, opt_info ) ) return 0;
    if( !fd_shmem_info( name, FD_SHMEM_HUGE_PAGE_SZ,     opt_info ) ) return 0;
    if( !fd_shmem_info( name, FD_SHMEM_NORMAL_PAGE_SZ,   opt_info ) ) return 0;
    return ENOENT;
  }

  if( FD_UNLIKELY( !fd_shmem_is_page_sz( page_sz ) ) ) { FD_LOG_WARNING(( "bad page_sz (%lu)", page_sz )); return EINVAL; }

  int fd = fd_shm_open( name, O_RDONLY, 0 );
  if( FD_UNLIKELY( fd<0 ) ) {
    FD_LOG_WARNING(( "shm_open(%s,O_RDONLY) failed (%i-%s)",
                     name, errno, fd_io_strerror( errno ) ));
    return errno;
  }

  struct stat stat[1];
  if( FD_UNLIKELY( fstat( fd, stat ) ) ) {
    FD_LOG_WARNING(( "fstat failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    int err = errno;
    if( FD_UNLIKELY( close( fd ) ) )
      FD_LOG_WARNING(( "close(shmem \"%s\") failed (%i-%s); attempting to continue", name, errno, fd_io_strerror( errno ) ));
    return err;
  }

  ulong sz = (ulong)stat->st_size;
  if( FD_UNLIKELY( !fd_ulong_is_aligned( sz, page_sz ) ) ) {
    FD_LOG_WARNING(( "shmem \"%s\" size (%lu) not a page size (%lu) multiple",
                     name, sz, page_sz ));
    if( FD_UNLIKELY( close( fd ) ) )
      FD_LOG_WARNING(( "close(shmem \"%s\") failed (%i-%s); attempting to continue", name, errno, fd_io_strerror( errno ) ));
    return EFAULT;
  }
  ulong page_cnt = sz / page_sz;

  if( FD_UNLIKELY( close( fd ) ) )
    FD_LOG_WARNING(( "close(shmem \"%s\") failed (%i-%s); attempting to continue", name, errno, fd_io_strerror( errno ) ));

  if( opt_info ) {
    opt_info->page_sz  = page_sz;
    opt_info->page_cnt = page_cnt;
  }
  return 0;
}

void *
fd_shmem_acquire_multi( ulong         page_sz,
                        ulong         sub_cnt,
                        ulong const * _sub_page_cnt,
                        ulong const * _sub_cpu_idx ) {

  /* Check input args */

  int psind = fd_page_sz_to_psind( page_sz );
  if( FD_UNLIKELY( psind<0 ) ) {
    FD_LOG_WARNING(( "unsupported page size: %#lx", page_sz ));
    return NULL;
  }

  if( FD_UNLIKELY( !sub_cnt       ) ) { FD_LOG_WARNING(( "zero sub_cnt"      )); return NULL; }
  if( FD_UNLIKELY( !_sub_page_cnt ) ) { FD_LOG_WARNING(( "NULL sub_page_cnt" )); return NULL; }
  if( FD_UNLIKELY( !_sub_cpu_idx  ) ) { FD_LOG_WARNING(( "NULL sub_cpu_idx"  )); return NULL; }

  /* FIXME NUMA affinity not yet supported */

  int shm_fd = fd_shm_create_largepage( SHM_ANON, O_RDWR, psind, SHM_LARGEPAGE_ALLOC_NOWAIT, 0 );
  if( FD_UNLIKELY( shm_fd<0 ) ) {
    FD_LOG_WARNING(( "shm_create_largepage(SHM_ANON,O_RDWR) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    return NULL;
  }

  ulong page_cnt = 0UL;
  for( ulong sub_idx=0UL; sub_idx<sub_cnt; sub_idx++ ) {
    page_cnt += _sub_page_cnt[ sub_idx ];
  }
  ulong sz = page_cnt * page_sz;

  if( FD_UNLIKELY( 0!=ftruncate( shm_fd, (off_t)sz ) ) ) {
    FD_LOG_WARNING(( "ftruncate(sz=%#lx) failed (%i-%s)", sz, errno, fd_io_strerror( errno ) ));
    close( shm_fd );
    return NULL;
  }

  int    page_shift = fd_ulong_find_lsb( page_sz );
  int    map_flags  = MAP_ALIGNED( page_shift ) | MAP_SHARED;
  void * mem        = mmap( NULL, sz, PROT_READ|PROT_WRITE, map_flags, shm_fd, 0 );
  int    map_err    = errno;
  close( shm_fd );
  if( FD_UNLIKELY( mem==MAP_FAILED ) ) {
    FD_LOG_WARNING(( "mmap(NULL,%#lx,PROT_READ|PROT_WRITE,MAP_ALIGNED(%d)|MAP_SHARED,shm_fd,0) failed (%i-%s)",
                     sz, page_shift, map_err, fd_io_strerror( map_err ) ));
    return NULL;
  }

  if( FD_UNLIKELY( 0!=mlock( mem, sz ) ) ) {
    FD_LOG_WARNING(( "mlock(%p,%#lx) failed (%i-%s); attempting to continue",
                     mem, sz, errno, fd_io_strerror( errno ) ));
  }

  return mem;
}

int
fd_shmem_release( void * mem,
                  ulong  page_sz,
                  ulong  page_cnt ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return -1;
  }

  if( FD_UNLIKELY( !fd_shmem_is_page_sz( page_sz ) ) ) {
    FD_LOG_WARNING(( "bad page_sz (%lu)", page_sz ));
    return -1;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, page_sz ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return -1;
  }

  if( FD_UNLIKELY( !((1UL<=page_cnt) & (page_cnt<=(((ulong)LONG_MAX)/page_sz))) ) ) {
    FD_LOG_WARNING(( "bad page_cnt (%lu)", page_cnt ));
    return -1;
  }

  ulong sz = page_sz*page_cnt;

  int result = munmap( mem, sz );
  if( FD_UNLIKELY( result ) ) {
    FD_LOG_WARNING(( "munmap(anon,%lu KiB) failed (%i-%s); attempting to continue", sz>>10, errno, fd_io_strerror( errno ) ));
  }
  return result;
}

void
fd_shmem_private_boot( int *    pargc,
                       char *** pargv ) {
  FD_LOG_INFO(( "fd_shmem: booting" ));
  (void)fd_env_strip_cmdline_cstr( pargc, pargv, "--shmem-path", "FD_SHMEM_PATH", "/mnt/.fd" );
  FD_LOG_INFO(( "fd_shmem: --shmem-path (ignored)" ));
  FD_LOG_INFO(( "fd_shmem: boot success" ));
}

void
fd_shmem_private_halt( void ) {
  FD_LOG_INFO(( "fd_shmem: halting" ));
  FD_LOG_INFO(( "fd_shmem: halt success" ));
}

