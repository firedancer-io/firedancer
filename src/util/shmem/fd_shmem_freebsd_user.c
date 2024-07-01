#include "fd_shmem_private.h"
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include "fd_shmem_freebsd_private.h"

void *
fd_shmem_join( char const *               name,
               int                        mode,
               fd_shmem_joinleave_func_t  join_func,
               void *                     context,
               fd_shmem_join_info_t *     opt_info ) {

  /* Check input args */

  fd_shmem_private_key_t key;
  if( FD_UNLIKELY( !fd_shmem_private_key( &key, name ) ) ) {
    FD_LOG_WARNING(( "bad name (%s)", name ? name : "NULL" ));
    return NULL;
  }

  if( FD_UNLIKELY( !( (mode==FD_SHMEM_JOIN_MODE_READ_ONLY) | (mode==FD_SHMEM_JOIN_MODE_READ_WRITE) ) ) ) {
    FD_LOG_WARNING(( "unsupported join mode (%i) for %s", mode, name ));
    return NULL;
  }

  FD_SHMEM_LOCK;

  /* Query for an existing mapping */

  fd_shmem_join_info_t * join_info = fd_shmem_private_map_query( fd_shmem_private_map, key, NULL );
  if( join_info ) {
    if( FD_UNLIKELY( join_info->ref_cnt<0L ) ) {
      FD_LOG_WARNING(( "join/leave circular dependency detected for %s", name ));
      FD_SHMEM_UNLOCK;
      return NULL;
    }
    join_info->ref_cnt++;

    if( opt_info ) *opt_info = *join_info;
    FD_SHMEM_UNLOCK;
    return join_info->join;
  }

  /* Not currently mapped.  See if we have enough room.  */

  if( FD_UNLIKELY( fd_shmem_private_map_cnt>=FD_SHMEM_JOIN_MAX ) ) {
    FD_SHMEM_UNLOCK;
    FD_LOG_WARNING(( "too many concurrent joins for %s", name ));
    return NULL;
  }

  /* We have enough room for it.  Try to map the memory. */

  fd_shmem_info_t shmem_info[1];
  if( FD_UNLIKELY( fd_shmem_info( name, 0UL, shmem_info ) ) ) {
    FD_SHMEM_UNLOCK;
    FD_LOG_WARNING(( "unable to query region \"%s\"\n\tprobably does not exist or bad permissions", name ));
    return NULL;
  }
  ulong page_sz    = shmem_info->page_sz;
  ulong page_cnt   = shmem_info->page_cnt;
  ulong sz         = page_sz*page_cnt;
  int   page_shift = fd_ulong_find_lsb( page_sz );
  int   rw         = (mode==FD_SHMEM_JOIN_MODE_READ_WRITE);
  int   map_prot   = rw ? (PROT_READ|PROT_WRITE) : PROT_READ;
  int   map_flags  = MAP_ALIGNED( page_shift ) | MAP_SHARED;
  int   open_mode  = rw ? O_RDWR : O_RDONLY;

  /* Map the region into our address space. */

  int shm_fd = fd_shm_open( name, open_mode, 0 );
  if( FD_UNLIKELY( shm_fd<0 ) ) {
    FD_LOG_WARNING(( "shm_open(%s,%s) failed (%i-%s)",
                     name, rw ? "O_RDWR" : "O_RDONLY", errno, fd_io_strerror( errno ) ));
    FD_SHMEM_UNLOCK;
    return NULL;
  }

  struct stat st;
  if( FD_UNLIKELY( 0!=fstat( shm_fd, &st ) ) ) {
    FD_LOG_WARNING(( "fstat(shm_fd) failed (%i-%s)", errno, fd_io_strerror( errno ) ));
    close( shm_fd );
    FD_SHMEM_UNLOCK;
    return NULL;
  }

  void * shmem   = mmap( NULL, sz, map_prot, map_flags, shm_fd, 0 );
  int    map_err = errno;
  close( shm_fd );

  if( FD_UNLIKELY( shmem==MAP_FAILED ) ) {
    FD_LOG_WARNING(( "mmap(NULL,%#lx,%s,MAP_ALIGNED(%d)|MAP_SHARED,shm_fd,0) failed (%i-%s)",
                     sz, rw ? "PROT_READ|PROT_WRITE" : "PROT_READ", page_shift, map_err, fd_io_strerror( map_err ) ));
    FD_SHMEM_UNLOCK;
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, page_sz ) ) ) {
    FD_LOG_WARNING(( "misaligned memory mapping for shmem \"%s\"\n\t", name ));
  }

  if( FD_UNLIKELY( 0!=mlock( shmem, sz ) ) ) {
    FD_LOG_WARNING(( "mlock(%p,%#lx) failed (%i-%s); attempting to continue",
                     shmem, sz, errno, fd_io_strerror( errno ) ));
  }

  join_info = fd_shmem_private_map_insert( fd_shmem_private_map, key );
  if( FD_UNLIKELY( !join_info ) ) /* should be impossible */
    FD_LOG_ERR(( "unable to insert region \"%s\" (internal error)", name ));
  fd_shmem_private_map_cnt++;

  join_info->ref_cnt  = -1L;  /* Mark join/leave in progress so we can detect circular join/leave dependencies */
  join_info->join     = NULL; /* Overridden below */
  join_info->shmem    = shmem;
  join_info->page_sz  = page_sz;
  join_info->page_cnt = page_cnt;
  join_info->mode     = mode;
  /* join_info->hash handled by insert */
  /* join_info->name "                 */
  /* join_info->key  "                 */

  void * join = join_func ? join_func( context, join_info ): shmem; /* Reset by the join func if provided */
  if( FD_UNLIKELY( !join ) ) {
    fd_shmem_private_map_remove( fd_shmem_private_map, join_info );
    fd_shmem_private_map_cnt--;
    if( FD_UNLIKELY( munmap( shmem, sz ) ) )
      FD_LOG_WARNING(( "munmap(\"%s\",%lu KiB) failed (%i-%s); attempting to continue",
                       name, sz>>10, errno, fd_io_strerror( errno ) ));
    FD_SHMEM_UNLOCK;
    FD_LOG_WARNING(( "unable to join region \"%s\"", name ));
    return NULL;
  }
  join_info->ref_cnt = 1UL;
  join_info->join    = join;

  if( opt_info ) *opt_info = *join_info;
  FD_SHMEM_UNLOCK;
  return join;
}

int
fd_shmem_leave( void *                    join,
                fd_shmem_joinleave_func_t leave_func,
                void *                    context ) {
  if( FD_UNLIKELY( !join ) ) { FD_LOG_WARNING(( "NULL join" )); return 1; }

  FD_SHMEM_LOCK;

  if( FD_UNLIKELY( !fd_shmem_private_map_cnt ) ) {
    FD_SHMEM_UNLOCK;
    FD_LOG_WARNING(( "join is not a current join" ));
    return 1;
  }
  fd_shmem_join_info_t * join_info = fd_shmem_private_map_query_by_join( fd_shmem_private_map, join, NULL );
  if( FD_UNLIKELY( !join_info ) ) {
    FD_SHMEM_UNLOCK;
    FD_LOG_WARNING(( "join is not a current join" ));
    return 1;
  }

  long ref_cnt = join_info->ref_cnt;
  if( join_info->ref_cnt>1L ) {
    join_info->ref_cnt = ref_cnt-1L;
    FD_SHMEM_UNLOCK;
    return 0;
  }

  if( join_info->ref_cnt==-1L ) {
    FD_SHMEM_UNLOCK;
    FD_LOG_WARNING(( "join/leave circular dependency detected for %s", join_info->name ));
    return 1;
  }

  if( FD_UNLIKELY( join_info->ref_cnt!=1L ) ) /* Should be impossible */
    FD_LOG_WARNING(( "unexpected ref count for %s; attempting to continue", join_info->name ));

  char const * name     = join_info->name;     /* Just in case leave_func clobbers */
  void *       shmem    = join_info->shmem;    /* " */
  ulong        page_sz  = join_info->page_sz;  /* " */
  ulong        page_cnt = join_info->page_cnt; /* " */

  if( leave_func ) {
    join_info->ref_cnt = -1L; /* Mark join/leave is in progress so we can detect join/leave circular dependencies */
    leave_func( context, join_info );
  }

  int error = 0;
  ulong sz = page_sz*page_cnt;
  if( FD_UNLIKELY( munmap( shmem, sz ) ) ) {
    FD_LOG_WARNING(( "munmap(\"%s\",%lu KiB) failed (%i-%s); attempting to continue",
                     name, sz>>10, errno, fd_io_strerror( errno ) ));
    error = 1;
  }

  fd_shmem_private_map_remove( fd_shmem_private_map, join_info );
  fd_shmem_private_map_cnt--;
  FD_SHMEM_UNLOCK;
  return error;
}
