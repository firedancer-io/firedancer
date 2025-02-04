#include "fd_tar.h"
#include "../fd_util.h"

#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>

static char null_tar_block[ FD_TAR_BLOCK_SZ ] = {0};

#define FD_TAR_PERM           ("0000644\0")
#define FD_TAR_MAGIC_VERSION  ("ustar  \0")
#define FD_TAR_DEFAULT_CHKSUM ("        " )

fd_tar_writer_t *
fd_tar_writer_new( void * mem, int fd ) {

  /* Allocate the relevant memory for the writer. */

  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_tar_writer_align() ) ) ) {
    FD_LOG_WARNING(( "unaligned mem" ));
    return NULL;
  }

  fd_tar_writer_t * writer = (fd_tar_writer_t *)mem;

  /* Make sure that the file descriptor is valid. */

  if( FD_UNLIKELY( fd<=0 ) ) {
    FD_LOG_WARNING(( "Invalid file descriptor" ));
    return NULL;
  }

  /* If the file already exists, truncate it's length to zero. */

  int err = ftruncate( fd, 0UL );
  if( FD_UNLIKELY( err==-1 ) ) {
    FD_LOG_WARNING(( "Failed to truncate tarball (%i-%s)", errno, fd_io_strerror( errno ) ));
    return NULL;
  }

  writer->fd         = fd;
  writer->header_pos = ULONG_MAX;
  writer->data_sz    = ULONG_MAX;
  writer->wb_pos     = ULONG_MAX;

  return writer;
}

void *
fd_tar_writer_delete( fd_tar_writer_t * writer ) {

  /* The end of a tar archive is marked with two EOF 512 byte blocks that are
     filled with zeros. These must be written out. */

  ulong out_sz = 0UL;
  int err = fd_io_write( writer->fd, null_tar_block, FD_TAR_BLOCK_SZ, FD_TAR_BLOCK_SZ, &out_sz );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_WARNING(( "Failed to write out the first tar trailer (%i-%s)", errno, fd_io_strerror( errno ) ));
    return NULL;
  }
  err = fd_io_write( writer->fd, null_tar_block, FD_TAR_BLOCK_SZ, FD_TAR_BLOCK_SZ, &out_sz );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_WARNING(( "Failed to write out the second tar trailer (%i-%s)", errno, fd_io_strerror( errno ) ));
    return NULL;
  }

  return (void*)writer;
}

int
fd_tar_writer_new_file( fd_tar_writer_t * writer,
                        char const *      file_name ) {

  /* TODO: This function currently fills in the bare minimum to get processed
     by Agave, Firedancer, and most tar command line tools. To make this tool
     more robust and generalizable, it may make sense to populate some of the
     other fields in the tar header. */

  /* Save position of the header in the file and do simple sanity checks. */

  long header_pos = lseek( writer->fd, 0, SEEK_CUR );
  if( FD_UNLIKELY( header_pos==-1L ) ) {
    FD_LOG_WARNING(( "Failed to get the current file position" ));
    return -1;
  }


  writer->header_pos = (ulong)header_pos;

  if( FD_UNLIKELY( !fd_ulong_is_aligned( writer->header_pos, FD_TAR_BLOCK_SZ ) ) ) {
    FD_LOG_WARNING(( "Unaligned header position %lu", writer->header_pos ));
    return -1;
  }

  /* Populate what fields you can in the header */

  fd_tar_meta_t meta = {0};

  /* Copy in file name */

  fd_memcpy( &meta.name, file_name, strlen( file_name ) );

  /* Copy in the mode: it will always be 0644 and will be left padded.
     TODO: make this mode configurable in the future. */

  fd_memcpy( &meta.mode, FD_TAR_PERM, sizeof(FD_TAR_PERM) );

  /* Copy in the magic and version */

  fd_memcpy( &meta.magic, FD_TAR_MAGIC_VERSION, sizeof(FD_TAR_MAGIC_VERSION) );

  /* Write in the temporary value for the checksum. The tar format dictates
     that the checksum bytes should be spaces when it is calculated. */

  fd_memcpy( &meta.chksum, FD_TAR_DEFAULT_CHKSUM, sizeof(FD_TAR_DEFAULT_CHKSUM) );

  ulong out_sz = 0UL;
  int   err    = fd_io_write( writer->fd, &meta, FD_TAR_BLOCK_SZ, FD_TAR_BLOCK_SZ, &out_sz );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_WARNING(( "Failed to write out the header (%i-%s)", errno, fd_io_strerror( errno ) ));
    return -1;
  }

  if( FD_UNLIKELY( out_sz!=FD_TAR_BLOCK_SZ ) ) {
    FD_LOG_WARNING(( "Failed to write out correct size header (%lu)", out_sz ));
    return -1;
  }

  /* Now that the header is written out, reset the data size to prepare
     for the file to be written out. */

  writer->data_sz  = 0UL;

  return 0;
}

int
fd_tar_writer_write_file_data( fd_tar_writer_t * writer,
                               void const *      data,
                               ulong             data_sz ) {

  if( FD_UNLIKELY( writer->header_pos==ULONG_MAX ) ) {
    FD_LOG_WARNING(( "There is no corresponding tar header for the tar write" ));
    return -1;
  }

  /* Simply write out the data and update the data_sz field. */

  ulong out_sz = 0UL;
  int   err    = fd_io_write( writer->fd, data, data_sz, data_sz, &out_sz );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_WARNING(( "Failed to write out the data (%i-%s)", errno, fd_io_strerror( errno ) ));
    return -1;
  }
  if( FD_UNLIKELY( out_sz!=data_sz ) ) {
    FD_LOG_WARNING(( "Failed to write out the data (%lu)", out_sz ));
    return -1;
  }

  writer->data_sz += data_sz;

  return 0;
}

int
fd_tar_writer_fini_file( fd_tar_writer_t * writer ) {

  /* If the current file that has been written out does not meet the tar
     alignment requirements (512), pad out the rest of the file and update the
     header with the file sz and checksum. */

  ulong out_sz   = 0UL;
  ulong align_sz = fd_ulong_align_up( writer->data_sz, FD_TAR_BLOCK_SZ ) - writer->data_sz;
  int   err      = fd_io_write( writer->fd, null_tar_block, align_sz, align_sz, &out_sz );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_WARNING(( "Failed to write out the padding (%i-%s)", errno, fd_io_strerror( errno ) ));
    return -1;
  }
  if( FD_UNLIKELY( out_sz!=align_sz ) ) {
    FD_LOG_WARNING(( "Failed to write out the correct size padding (%lu)", out_sz ));
    return -1;
  }

  /* Now we need to write back to the header of the file. This involves
     first setting the file pointer to where we expect the header to be.  */

  long eof_pos = lseek( writer->fd, 0L, SEEK_CUR );
  if( FD_UNLIKELY( eof_pos==-1L ) ) {
    FD_LOG_WARNING(( "Failed to get the current file position" ));
    return -1;
  }
  long seek = lseek( writer->fd, (long)writer->header_pos, SEEK_SET );
  if( FD_UNLIKELY( (ulong)seek!=writer->header_pos ) ) {
    FD_LOG_WARNING(( "Failed to seek to the header position (%ld)", seek ));
    return -1;
  }

  fd_tar_meta_t meta = {0};
  err = fd_io_read( writer->fd, &meta, FD_TAR_BLOCK_SZ, FD_TAR_BLOCK_SZ, &out_sz );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_WARNING(( "Failed to write out the header (%i-%s)", errno, fd_io_strerror( errno ) ));
    return -1;
  }
  if( FD_UNLIKELY( out_sz!=FD_TAR_BLOCK_SZ ) ) {
    FD_LOG_WARNING(( "Failed to write out the correct size header (%lu)", out_sz ));
    return -1;
  }

  /* The file pointer is now at the start of the file data and should be
     moved back to the start of the file header. */

  seek = lseek( writer->fd, (long)writer->header_pos, SEEK_SET );
  if( FD_UNLIKELY( (ulong)seek!=writer->header_pos ) ) {
    FD_LOG_WARNING(( "Failed to seek to the header position (%ld)", seek ));
    return -1;
  }

  /* Now that the tar header is read in, update the size in the header. */

  err = fd_tar_meta_set_size( &meta, writer->data_sz );
  if( FD_UNLIKELY( !err ) ) {
    FD_LOG_WARNING(( "Failed to set the size in the header" ));
    return -1;
  }

  /* Write in the checksum which is left padded with zeros */

  uint checksum = 0UL;
  for( ulong i=0UL; i<FD_TAR_BLOCK_SZ; i++ ) {
    checksum += ((uchar *)&meta)[i];
  }
  snprintf( meta.chksum, sizeof(meta.chksum), "%07o", checksum );

  /* Now write out the updated header */

  err = fd_io_write( writer->fd, &meta, FD_TAR_BLOCK_SZ, FD_TAR_BLOCK_SZ, &out_sz );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_WARNING(( "Failed to write out the header (%i-%s)", errno, fd_io_strerror( errno ) ));
    return -1;
  }
  if( FD_UNLIKELY( out_sz!=FD_TAR_BLOCK_SZ ) ) {
    FD_LOG_WARNING(( "Failed to write out the correct size header (%lu)", out_sz ));
    return -1;
  }

  /* Reset the file pointer to the end of the file so that we can continue
     writing out the next file. */

  seek = lseek( writer->fd, 0L, SEEK_END );
  if( FD_UNLIKELY( seek!=eof_pos ) ) {
    return -1;
  }

  /* Reset the data_sz/header pointers as there is no outstanding write. */

  writer->header_pos = ULONG_MAX;
  writer->data_sz    = ULONG_MAX;

  return 0;
}

int
fd_tar_writer_make_space( fd_tar_writer_t * writer, ulong data_sz ) {

  if( FD_UNLIKELY( writer->wb_pos!=ULONG_MAX )) {
    FD_LOG_WARNING(( "There is an outstanding write back position" ));
    return -1;
  }

  /* Extend the size of the file to make space that can be written back to.
     TODO: In the future, this can be made into a hole to avoid preallocating
     space. */

  long file_sz = lseek( writer->fd, 0L, SEEK_END );
  if( FD_UNLIKELY( file_sz==-1L ) ) {
    FD_LOG_WARNING(( "Failed to get the size of the tarball" ));
    return -1;
  }

  int err = ftruncate( writer->fd, file_sz + (long)data_sz );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_WARNING(( "Failed to make space in the tarball (%i-%s)", errno, fd_io_strerror( errno ) ));
    return -1;
  }

  /* Seek to the new end of the file. */

  long new_sz = lseek( writer->fd, 0, SEEK_END );
  if( FD_UNLIKELY( new_sz!=file_sz+(long)data_sz ) ) {
    FD_LOG_WARNING(( "Failed to make space in the tarball" ));
    return -1;
  }

  writer->data_sz = data_sz;
  writer->wb_pos  = (ulong)file_sz;

  return 0;
}

int
fd_tar_writer_fill_space( fd_tar_writer_t * writer, void const * data, ulong data_sz ) {

  if( FD_UNLIKELY( writer->wb_pos==ULONG_MAX ) ) {
    FD_LOG_WARNING(( "There is no outstanding write back position" ));
    return -1;
  }

  long eof_pos = lseek( writer->fd, 0, SEEK_END );
  if( FD_UNLIKELY( eof_pos==-1L ) ) {
    FD_LOG_WARNING(( "Failed to seek to the end of the file" ));
    return -1;
  }

  long seek = lseek( writer->fd, (long)writer->wb_pos, SEEK_SET );
  if( FD_UNLIKELY( (ulong)seek!=writer->wb_pos ) ) {
    FD_LOG_WARNING(( "Failed to seek to the write back position (%ld %lu)", seek, writer->wb_pos ));
    return -1;
  }

  /* Write back to the specified location. Once again, this is unsafe and
     you can override the rest of the tar archive making it invalid. */

  ulong out_sz = 0UL;
  int err = fd_io_write( writer->fd, data, data_sz, data_sz, &out_sz );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_WARNING(( "Failed to write out the data (%i-%s)", errno, fd_io_strerror( errno ) ));
    return -1;
  }
  if( FD_UNLIKELY( out_sz!=data_sz ) ) {
    FD_LOG_WARNING(( "Failed to write out the data (%lu)", out_sz ));
    return -1;
  }

  writer->wb_pos = ULONG_MAX;

  seek = lseek( writer->fd, 0, SEEK_END );
  if( FD_UNLIKELY( seek!=eof_pos ) ) {
    FD_LOG_WARNING(( "Failed to seek to the end of the file (%ld)", seek ));
    return -1;
  }

  return 0;
}
