#include "fd_shmem_private.h"
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

void *
fd_shmem_join( char const *               name,
               int                        mode,
               fd_shmem_joinleave_func_t  join_func,
               void *                     context,
               fd_shmem_join_info_t *     opt_info ) {

  int rw        = (mode==FD_SHMEM_JOIN_MODE_READ_WRITE);
  int map_prot  = rw ? (PROT_READ|PROT_WRITE) : PROT_READ;
  int open_mode = rw ? O_RDWR : O_RDONLY;

  int shm_fd = shm_open( name, open_mode, 0 );
  if( FD_UNLIKELY( shm_fd<0 ) ) {
    FD_LOG_WARNING(( "shm_open(%s,%s) failed (%i-%s)",
                     name, rw ? "O_RDWR" : "O_RDONLY", errno, fd_io_strerror( errno ) ));
    return NULL;
  }

  struct stat st;
  if( FD_UNLIKELY( 0!=fstat( shm_fd, &st ) ) ) {
    FD_LOG_WARNING(( "fstat(shm_fd) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    close( shm_fd );
    return NULL;
  }

  /* TODO determine page size? */

  ulong  sz      = (ulong)st.st_size;
  void * mem     = mmap( NULL, sz, map_prot, MAP_SHARED, shm_fd, 0 );
  int    map_err = errno;
  close( shm_fd );

  if( FD_UNLIKELY( mem==MAP_FAILED ) ) {
    FD_LOG_WARNING(( "mmap(NULL,%#lx,%s,MAP_SHARED,shm_fd,0) failed (%i-%s)",
                     sz, rw ? "PROT_READ|PROT_WRITE" : "PROT_READ", errno, fd_io_strerror( errno ) ));
    return NULL;
  }

  if( FD_UNLIKELY( 0!=mlock( mem, sz ) ) ) {
    FD_LOG_WARNING(( "mlock(%p,%#lx) failed (%i-%s); attempting to continue",
                     mem, sz, errno, fd_io_strerror( errno ) ));
  }

  /* FIXME Add a join registry */
  fd_shmem_join_info_t * join_info = aligned_alloc( alignof(fd_shmem_join_info_t), sizeof(fd_shmem_join_info_t) );
  FD_TEST( join_info );
  *join_info = (fd_shmem_join_info_t) {
    .ref_cnt  = -1L,  /* unsupported */
    .join     = NULL, /* overridden below */
    .shmem    = mem,
    .page_sz  = 4096,      /* TODO */
    .page_cnt = sz/4096UL, /* TODO */
    .mode     = mode
  };

  void * join = join_func ? join_func( context, join_info ) : mem;
  if( FD_UNLIKELY( !join ) ) {
    if( FD_UNLIKELY( 0!=munmap( mem, sz ) ) ) {
      FD_LOG_WARNING(( "munmap failed (%i-%s); attempting to continue", errno, fd_io_strerror( errno ) ));
    }
    return NULL;
  } 

  join_info->join = join;
  if( opt_info ) {
    *opt_info = *join_info;
  }
  return join;
}

int
fd_shmem_leave( void *                    join,
                fd_shmem_joinleave_func_t leave_func,
                void *                    context ) {
  if( FD_UNLIKELY( !join ) ) { FD_LOG_WARNING(( "NULL join" )); return 1; }
  FD_LOG_WARNING(( "fd_shmem_leave not supported on this platform; leaving memory mapped" ));
  return 0;
}

