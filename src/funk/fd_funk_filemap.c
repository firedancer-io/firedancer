#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64
#include "fd_funk_filemap.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>

#define PAGESIZE (1UL<<12)  /* 4 KiB */

fd_funk_t *
fd_funk_open_file( const char * filename,
                   ulong        wksp_tag,
                   ulong        seed,
                   ulong        txn_max,
                   ulong        rec_max,
                   ulong        total_sz,
                   fd_funk_file_mode_t mode,
                   fd_funk_close_file_args_t * close_args_out ) {

  /* See if we already have the file open */

  if( mode == FD_FUNK_READONLY || mode == FD_FUNK_READ_WRITE ) {
    fd_shmem_join_info_t info;
    if( !fd_shmem_join_query_by_name("funk", &info) ) {
      void * shmem = info.join;
      fd_wksp_t * wksp = fd_wksp_join( shmem );
      if( FD_UNLIKELY( !wksp ) ) {
        FD_LOG_ERR(( "fd_wksp_join(%p) failed", shmem ));
        return NULL;
      }

      fd_wksp_tag_query_info_t info2;
      if( !fd_wksp_tag_query( wksp, &wksp_tag, 1, &info2, 1 ) ) {
        FD_LOG_ERR(( "%s does not contain a funky", filename ));
        return NULL;
      }

      void * funk_shmem = fd_wksp_laddr_fast( wksp, info2.gaddr_lo );
      fd_funk_t * funk = fd_funk_join( funk_shmem );
      if( funk == NULL ) {
        FD_LOG_ERR(( "failed to join a funky" ));
        return NULL;
      }

      FD_LOG_NOTICE(( "reopened funk with %lu records", fd_funk_rec_cnt( fd_funk_rec_map( funk, wksp ) ) ));

      if( close_args_out != NULL ) {
        close_args_out->shmem = shmem;
        close_args_out->fd = -1;
        close_args_out->total_sz = 0;
      }
      return funk;
    }
  }

  /* Open the file */

  int open_flags, can_resize, can_create, do_new;
  switch (mode) {
  case FD_FUNK_READONLY:
    if( filename == NULL  || filename[0] == '\0' ) {
      FD_LOG_ERR(( "mode FD_FUNK_READONLY can not be used with an anonymous workspace, funk file required" ));
      return NULL;
    }
    open_flags = O_RDWR; /* We mark the memory as read-only after we are done setting up */
    can_create = 0;
    can_resize = 0;
    do_new = 0;
    break;
  case FD_FUNK_READ_WRITE:
    if( filename == NULL  || filename[0] == '\0' ) {
      FD_LOG_ERR(( "mode FD_FUNK_READ_WRITE can not be used with an anonymous workspace, funk file required" ));
      return NULL;
    }
    open_flags = O_RDWR;
    can_create = 0;
    can_resize = 0;
    do_new = 0;
    break;
  case FD_FUNK_CREATE:
    open_flags = O_CREAT|O_RDWR;
    can_create = 1;
    can_resize = 0;
    do_new = 0;
    break;
  case FD_FUNK_OVERWRITE:
    open_flags = O_CREAT|O_RDWR;
    can_create = 1;
    can_resize = 1;
    do_new = 1;
    break;
  case FD_FUNK_CREATE_EXCL:
    open_flags = O_CREAT|O_EXCL|O_RDWR;
    can_create = 1;
    can_resize = 1;
    do_new = 1;
    break;
  default:
    FD_LOG_ERR(( "invalid mode when opening %s", filename ));
    return NULL;
  }

  int fd;
  if( filename == NULL || filename[0] == '\0'  ) {
    fd = -1; /* Anonymous */
    do_new = 1;
  } else {

    /* Open the file */
    FD_LOG_DEBUG(( "opening %s", filename ));
    fd = open( filename, open_flags, S_IRUSR|S_IWUSR );
    if( fd < 0 ) {
      FD_LOG_ERR(( "error opening %s: %s", filename, strerror(errno) ));
      return NULL;
    }

    /* Resize the file */

    struct stat statbuf;
    int r = fstat( fd, &statbuf );
    if( r < 0 ) {
      FD_LOG_ERR(( "error opening %s: %s", filename, strerror(errno) ));
      close( fd );
      return NULL;
    }
    if( (can_create && statbuf.st_size == 0) ||
        (can_resize && statbuf.st_size != (off_t)total_sz) ) {
      FD_LOG_DEBUG(( "resizing %s to %lu", filename, total_sz ));
      if( ftruncate( fd, (off_t)total_sz ) < 0 ) {
        FD_LOG_ERR(( "error resizing %s: %s", filename, strerror(errno) ));
        close( fd );
        return NULL;
      }
      do_new = 1;
    } else {
      total_sz = (ulong)statbuf.st_size;
    }
  }

  if( total_sz & (PAGESIZE-1) ) {
    FD_LOG_ERR(( "file size must be a multiple of a %lu", PAGESIZE ));
    close( fd );
    return NULL;
  }

  /* Force all the disk blocks to be physically allocated to avoid major faults in the future */

  if( do_new && fd != -1 ) {
    FD_LOG_DEBUG(( "zeroing %s", (filename ? filename : "(NULL)") ));
    uchar zeros[4<<20];
    memset( zeros, 0, sizeof(zeros) );
    for( ulong i = 0; i < total_sz; ) {
      ulong sz = fd_ulong_min( sizeof(zeros), total_sz - i );
      if( pwrite( fd, zeros, sz, (__off_t)i ) < (ssize_t)sz ) {
        FD_LOG_ERR(( "error zeroing %s: %s", (filename ? filename : "(NULL)"), strerror(errno) ));
        close( fd );
        return NULL;
      }
      sync_file_range( fd, (__off64_t)i, (__off64_t)sz, SYNC_FILE_RANGE_WRITE );
      i += sz;
    }
  }

  /* Create the memory map */

  FD_LOG_DEBUG(( "mapping %s", (filename ? filename : "(NULL)") ));
  void * shmem = mmap( NULL, total_sz, (PROT_READ|PROT_WRITE),
                       (fd == -1 ? (MAP_ANONYMOUS|MAP_PRIVATE) : MAP_SHARED), fd, 0 );
  if( shmem == NULL || shmem == MAP_FAILED ) {
    FD_LOG_ERR(( "error mapping %s: %s", (filename ? filename : "(NULL)"), strerror(errno) ));
    close( fd );
    return NULL;
  }

  if( do_new ) {

    /* Create the data structures */

    ulong part_max = fd_wksp_part_max_est( total_sz, 1U<<18U );
    if( FD_UNLIKELY( !part_max ) ) {
      FD_LOG_ERR(( "fd_wksp_part_max_est(%lu,64KiB) failed", total_sz ));
      munmap( shmem, total_sz );
      close( fd );
      return NULL;
    }

    ulong data_max = fd_wksp_data_max_est( total_sz, part_max );
    if( FD_UNLIKELY( !data_max ) ) {
      FD_LOG_ERR(( "part_max (%lu) too large for footprint %lu", part_max, total_sz ));
      munmap( shmem, total_sz );
      close( fd );
      return NULL;
    }

    FD_LOG_DEBUG(( "creating workspace in %s", (filename ? filename : "(NULL)") ));
    void * shwksp = fd_wksp_new( shmem, "funk", (uint)seed, part_max, data_max );
    if( FD_UNLIKELY( !shwksp ) ) {
      FD_LOG_ERR(( "fd_wksp_new(%p,\"%s\",%lu,%lu,%lu) failed", shmem, "funk", seed, part_max, data_max ));
      munmap( shmem, total_sz );
      close( fd );
      return NULL;
    }

    fd_wksp_t * wksp = fd_wksp_join( shwksp );
    if( FD_UNLIKELY( !wksp ) ) {
      FD_LOG_ERR(( "fd_wksp_join(%p) failed", shwksp ));
      munmap( shmem, total_sz );
      close( fd );
      return NULL;
    }

    ulong page_sz  = PAGESIZE;
    ulong page_cnt = total_sz/PAGESIZE;
    int join_err = fd_shmem_join_anonymous( "funk", FD_SHMEM_JOIN_MODE_READ_WRITE, wksp, shmem, page_sz, page_cnt );
    if( join_err ) {
      FD_LOG_WARNING(( "fd_shmem_join_anonymous failed" ));
    }

    FD_LOG_DEBUG(( "creating funk in %s", (filename ? filename : "(NULL)") ));
    void * funk_shmem = fd_wksp_alloc_laddr( wksp, fd_funk_align(), fd_funk_footprint(), wksp_tag );
    if( funk_shmem == NULL ) {
      FD_LOG_ERR(( "failed to allocate a funky" ));
      munmap( shmem, total_sz );
      close( fd );
      return NULL;
    }

    fd_funk_t * funk = fd_funk_join( fd_funk_new( funk_shmem, wksp_tag, seed, txn_max, rec_max ) );
    if( funk == NULL ) {
      FD_LOG_ERR(( "failed to allocate a funky" ));
      munmap( shmem, total_sz );
      close( fd );
      return NULL;
    }

    FD_LOG_NOTICE(( "opened funk size %f GB, %lu records, backing file %s", ((double)total_sz)/((double)(1LU<<30)), fd_funk_rec_cnt( fd_funk_rec_map( funk, wksp ) ), (filename ? filename : "(NULL)") ));

    if( close_args_out != NULL ) {
      close_args_out->shmem = shmem;
      close_args_out->fd = fd;
      close_args_out->total_sz = total_sz;
    }
    return funk;

  } else {

    /* Join the data existiing structures */

    fd_wksp_t * wksp = fd_wksp_join( shmem );
    if( FD_UNLIKELY( !wksp ) ) {
      FD_LOG_ERR(( "fd_wksp_join(%p) failed", shmem ));
      munmap( shmem, total_sz );
      close( fd );
      return NULL;
    }

    ulong page_sz  = PAGESIZE;
    ulong page_cnt = total_sz/PAGESIZE;
    int join_err = fd_shmem_join_anonymous( "funk", FD_SHMEM_JOIN_MODE_READ_WRITE, wksp, shmem, page_sz, page_cnt );
    if( join_err ) {
      FD_LOG_WARNING(( "fd_shmem_join_anonymous failed" ));
    }

    fd_wksp_tag_query_info_t info;
    if( !fd_wksp_tag_query( wksp, &wksp_tag, 1, &info, 1 ) ) {
      FD_LOG_ERR(( "%s does not contain a funky", filename ));
      munmap( shmem, total_sz );
      close( fd );
      return NULL;
    }

    void * funk_shmem = fd_wksp_laddr_fast( wksp, info.gaddr_lo );
    fd_funk_t * funk = fd_funk_join( funk_shmem );
    if( funk == NULL ) {
      FD_LOG_ERR(( "failed to join a funky" ));
      munmap( shmem, total_sz );
      close( fd );
      return NULL;
    }

    if( mode == FD_FUNK_READONLY ) {
      if( FD_UNLIKELY( mprotect( shmem, total_sz, PROT_READ ) ) ) {
        FD_LOG_WARNING(( "mprotect failed (%i-%s)", errno, fd_io_strerror( errno ) ));
      }
    }

    FD_LOG_NOTICE(( "opened funk size %f GB, %lu records, backing file %s", ((double)total_sz)/((double)(1LU<<30)), fd_funk_rec_cnt( fd_funk_rec_map( funk, wksp ) ), (filename ? filename : "(NULL)") ));

    if( close_args_out != NULL ) {
      close_args_out->shmem = shmem;
      close_args_out->fd = fd;
      close_args_out->total_sz = total_sz;
    }
    return funk;
  }
}

fd_funk_t *
fd_funk_recover_checkpoint( const char * funk_filename,
                            ulong        wksp_tag,
                            const char * checkpt_filename,
                            fd_funk_close_file_args_t * close_args_out ) {
  /* Make the funk workspace match the parameters used to create the
     checkpoint. */
  uint seed;
  ulong part_max;
  ulong data_max;
  int err = fd_wksp_restore_preview( checkpt_filename, &seed, &part_max, &data_max );
  if( err ) {
    FD_LOG_ERR(( "unable to preview %s", checkpt_filename ));
    return NULL;
  }
  ulong total_sz = fd_wksp_footprint( part_max, data_max );

  int fd;
  if( funk_filename == NULL || funk_filename[0] == '\0' ) {
    fd = -1; /* Anonymous */

  } else {

    /* Open the file */
    fd = open( funk_filename, O_CREAT|O_RDWR, S_IRUSR|S_IWUSR );
    if( fd < 0 ) {
      FD_LOG_ERR(( "error opening %s: %s", funk_filename, strerror(errno) ));
      return NULL;
    }

    /* Resize the file */

    struct stat statbuf;
    int r = fstat( fd, &statbuf );
    if( r < 0 ) {
      FD_LOG_ERR(( "error opening %s: %s", funk_filename, strerror(errno) ));
      close( fd );
      return NULL;
    }
    if( statbuf.st_size != (off_t)total_sz ) {
      if( ftruncate( fd, (off_t)total_sz ) < 0 ) {
        FD_LOG_ERR(( "error resizing %s: %s", funk_filename, strerror(errno) ));
        close( fd );
        return NULL;
      }
    }

    /* Force all the disk blocks to be physically allocated to avoid major faults in the future */

    uchar zeros[4<<20];
    memset( zeros, 0, sizeof(zeros) );
    for( ulong i = 0; i < total_sz; ) {
      ulong sz = fd_ulong_min( sizeof(zeros), total_sz - i );
      if( pwrite( fd, zeros, sz, (__off_t)i ) < (ssize_t)sz ) {
        FD_LOG_ERR(( "error zeroing %s: %s", (funk_filename ? funk_filename : "(NULL)"), strerror(errno) ));
        close( fd );
        return NULL;
      }
      sync_file_range( fd, (__off64_t)i, (__off64_t)sz, SYNC_FILE_RANGE_WRITE );
      i += sz;
    }
  }

  /* Create the memory map */

  void * shmem = mmap( NULL, total_sz, PROT_READ|PROT_WRITE,
                       (fd == -1 ? (MAP_ANONYMOUS|MAP_PRIVATE) : MAP_SHARED), fd, 0 );

  if( shmem == NULL || shmem == MAP_FAILED ) {
    FD_LOG_ERR(( "error mapping %s: %s", (funk_filename ? funk_filename : "(NULL)"), strerror(errno) ));
    close( fd );
    return NULL;
  }

  /* Create the workspace */

  void * shwksp = fd_wksp_new( shmem, "funk", seed, part_max, data_max );
  if( FD_UNLIKELY( !shwksp ) ) {
    FD_LOG_ERR(( "fd_wksp_new(%p,\"%s\",%u,%lu,%lu) failed", shmem, "funk", seed, part_max, data_max ));
    munmap( shmem, total_sz );
    close( fd );
    return NULL;
  }

  fd_wksp_t * wksp = fd_wksp_join( shwksp );
  if( FD_UNLIKELY( !wksp ) ) {
    FD_LOG_ERR(( "fd_wksp_join(%p) failed", shwksp ));
    munmap( shmem, total_sz );
    close( fd );
    return NULL;
  }

  ulong page_sz  = PAGESIZE;
  ulong page_cnt = total_sz/PAGESIZE;
  int join_err = fd_shmem_join_anonymous( "funk", FD_SHMEM_JOIN_MODE_READ_WRITE, wksp, shmem, page_sz, page_cnt );
  if( join_err ) {
    FD_LOG_ERR(( "fd_shmem_join_anonymous failed" ));
    munmap( shmem, total_sz );
    close( fd );
    return NULL;
  }

  /* Restore the checkpoint */

  if( fd_wksp_restore( wksp, checkpt_filename, seed ) ) {
    FD_LOG_ERR(( "restoring %s failed", checkpt_filename ));
    munmap( shmem, total_sz );
    close( fd );
    return NULL;
  }

  /* Let's play find the funk */

  fd_wksp_tag_query_info_t info;
  if( !fd_wksp_tag_query( wksp, &wksp_tag, 1, &info, 1 ) ) {
    FD_LOG_ERR(( "%s does not contain a funky", checkpt_filename ));
    munmap( shmem, total_sz );
    close( fd );
    return NULL;
  }

  void * funk_shmem = fd_wksp_laddr_fast( wksp, info.gaddr_lo );
  fd_funk_t * funk = fd_funk_join( funk_shmem );
  if( funk == NULL ) {
    FD_LOG_ERR(( "failed to join a funky" ));
    munmap( shmem, total_sz );
    close( fd );
    return NULL;
  }

  FD_LOG_NOTICE(( "opened funk size %f GB, %lu records, backing file %s", ((double)total_sz)/((double)(1LU<<30)), fd_funk_rec_cnt( fd_funk_rec_map( funk, wksp ) ), (funk_filename ? funk_filename : "(NULL)") ));

  if( close_args_out != NULL ) {
    close_args_out->shmem = shmem;
    close_args_out->fd = fd;
    close_args_out->total_sz = total_sz;
  }
  return funk;
}

void
fd_funk_close_file( fd_funk_close_file_args_t * close_args ) {
  fd_shmem_leave_anonymous( close_args->shmem, NULL );
  munmap( close_args->shmem, close_args->total_sz );
  close( close_args->fd );
}
