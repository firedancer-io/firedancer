#if !defined(__APPLE__)
#error "Unsupported platform"
#endif

#include "fd_shmem_private.h"

#define _DARWIN_C_SOURCE
#include <pthread.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <mach/thread_policy.h>
#include <mach/thread_act.h>
#include <mach/mach_init.h>
#include <mach/vm_statistics.h>
#include "../fd_util.h"

#define _SC_NPROCESSORS_CONF 57
#define _SC_NPROCESSORS_ONLN 58

int
fd_shmem_cpu_cnt_private( void ) {
  /* Arm devices can turn off CPUs to save power */
  return (int)sysconf( _SC_NPROCESSORS_ONLN );
}

/* SHMEM REGION CREATION AND DESTRUCTION ******************************/

pthread_mutex_t fd_shmem_private_lock[1] = { {_PTHREAD_RECURSIVE_MUTEX_SIG_init, {0}} };

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

  int err = 0;
# define ERROR( cleanup ) do { err = errno; goto cleanup; } while(0)

  char   path[ FD_SHMEM_PRIVATE_PATH_BUF_MAX ];
  int    fd;
  void * shmem;

  /* Create the region */

  fd = open( fd_shmem_private_path( name, page_sz, path ), O_RDWR | O_CREAT | O_EXCL, (mode_t)mode );
  if( FD_UNLIKELY( fd==-1 ) ) {
    FD_LOG_WARNING(( "open(\"%s\",O_RDWR|O_CREAT|O_EXCL,0%03lo) failed (%i-%s)", path, mode, errno, strerror( errno ) ));
    ERROR( done );
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
    FD_LOG_WARNING(( "misaligned memory mapping for \"%s\"", path ));
    errno = EFAULT; /* ENOMEM is arguable */
    ERROR( unmap );
  }

# undef ERROR

unmap:
  if( FD_UNLIKELY( munmap( shmem, sz ) ) )
    FD_LOG_WARNING(( "munmap(\"%s\",%lu KiB) failed (%i-%s); attempting to continue", path, sz>>10, errno, strerror( errno ) ));

close:
  if( FD_UNLIKELY( err ) && FD_UNLIKELY( unlink( path ) ) )
    FD_LOG_WARNING(( "unlink(\"%s\") failed (%i-%s)", path, errno, strerror( errno ) )); /* Don't log "attempting ..." */
  if( FD_UNLIKELY( close( fd ) ) )
    FD_LOG_WARNING(( "close(\"%s\") failed (%i-%s); attempting to continue", path, errno, strerror( errno ) ));

done:
  FD_SHMEM_UNLOCK;
  return 0;
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

  int fd = -1;

  /* Superpage allocation (2MB) on macOS is done by passing VM_FLAGS_SUPERPAGE_SIZE_2MB as
     the 'fd' argument to the mmap() interface. */
  if( FD_LIKELY( page_sz==FD_SHMEM_HUGE_PAGE_SZ ) ) fd = VM_FLAGS_SUPERPAGE_SIZE_2MB;

  /* See fd_shmem_create for details on the locking, mempolicy
     and what not tricks */

  FD_SHMEM_LOCK;

  int err = 0;
# define ERROR( cleanup ) do { err = errno; goto cleanup; } while(0)

  void * mem = NULL;

  mem = mmap( NULL, sz, PROT_READ | PROT_WRITE, flags, fd, (off_t)0);
  if( FD_UNLIKELY( mem==MAP_FAILED ) ) {
    FD_LOG_WARNING(( "mmap(NULL,%lu KiB,PROT_READ|PROT_WRITE,%x,-1,0) failed (%i-%s)", sz>>10, flags, errno, strerror( errno ) ));
    ERROR( done );
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, page_sz ) ) ) {
    FD_LOG_WARNING(( "mmap(NULL,%lu KiB,PROT_READ|PROT_WRITE,%x,-1,0) misaligned", sz>>10, flags ));
    errno = EFAULT; /* ENOMEM is arguable */
    ERROR( unmap );
  }

  if( FD_UNLIKELY( mlock( mem, sz ) ) ) {
    FD_LOG_WARNING(( "mlock(anon,%lu KiB) failed (%i-%s)", sz>>10, errno, strerror( errno ) ));
    ERROR( unmap );
  }

# undef ERROR

unmap:
  if( FD_UNLIKELY( err ) && FD_UNLIKELY( munmap( mem, sz ) ) )
    FD_LOG_WARNING(( "munmap(anon,%lu KiB) failed (%i-%s); attempting to continue", sz>>10, errno, strerror( errno ) ));

done:
  FD_SHMEM_UNLOCK;
  return err ? NULL : mem;
}
