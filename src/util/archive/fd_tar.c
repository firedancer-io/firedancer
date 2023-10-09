#include "fd_tar.h"
#include "../fd_util.h"

#include <errno.h>

fd_tar_reader_t *
fd_tar_reader_new( void *                       mem,
                   fd_tar_read_vtable_t const * cb_vt,
                   void *                       cb_arg ) {

  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }
  if( FD_UNLIKELY( !cb_vt || !cb_vt->file || !cb_vt->read ) ) {
    FD_LOG_WARNING(( "NULL callback" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_tar_reader_align() ) ) ) {
    FD_LOG_WARNING(( "unaligned mem" ));
    return NULL;
  }

  fd_tar_reader_t * self = (fd_tar_reader_t *)mem;
  fd_memset( self, 0, sizeof(fd_tar_reader_t) );
  self->cb_vt  = *cb_vt;
  self->cb_arg = cb_arg;
  return self;
}

void *
fd_tar_reader_delete( fd_tar_reader_t * reader ) {
  if( FD_UNLIKELY( !reader ) ) return NULL;
  fd_memset( reader, 0, sizeof(fd_tar_reader_t) );
  return reader;
}

static int
fd_tar_process_hdr( fd_tar_reader_t * reader ) {

  fd_tar_meta_t const * hdr = (fd_tar_meta_t const *)reader->buf;

  /* "ustar\x00" and "ustar  \x00" (overlaps with version) are both
     valid values for magic.  These are POSIX ustar and OLDGNU versions
     respectively. */
  if( FD_UNLIKELY( 0!=memcmp( hdr->magic, FD_TAR_MAGIC, 5UL ) ) ) {

    /* Detect EOF.  A TAR EOF is marked by 1024 bytes of zeros.
       We abort after 512 bytes. */
    int not_zero=0;
    for( ulong i=0UL; i<sizeof(fd_tar_meta_t); i++ )
      not_zero |= reader->buf[ i ];
    if( !not_zero ) return -1;

    /* Not an EOF, so must be a protocol error */
    FD_LOG_WARNING(( "Invalid tar header magic at %#lx", reader->pos ));
    FD_LOG_HEXDUMP_WARNING(( "Tar header", hdr, sizeof(fd_tar_meta_t) ));
    return EPROTO;
  }

  ulong file_sz = fd_tar_meta_get_size( &reader->header );
  if( FD_UNLIKELY( file_sz==ULONG_MAX ) ) {
    FD_LOG_WARNING(( "Failed to parse file size in tar header" ));
    return EPROTO;
  }
  reader->file_sz = file_sz;
  reader->buf_ctr = (ushort)0U;

  /* Ensure name is terminated */
  reader->header.name[ FD_TAR_NAME_SZ-1 ] = '\0';

  /* Call back to recipient */
  int err = reader->cb_vt.file( reader->cb_arg, &reader->header, file_sz );
  return fd_int_if( err, EIO, 0 );
}

static int
fd_tar_read_hdr( fd_tar_reader_t * reader,
                 uchar const **    pcur,
                 uchar const *     end ) {

  uchar const * cur = *pcur;

  /* Skip padding */
  if( reader->buf_ctr==0UL ) {
    ulong  pad_sz = fd_ulong_align_up( reader->pos, 512UL ) - reader->pos;
           pad_sz = fd_ulong_min( pad_sz, (ulong)( end-cur ) );
    cur += pad_sz;
  }

  /* Determine number of bytes to read */
  long chunk_sz = (long)sizeof(fd_tar_meta_t) - (long)reader->buf_ctr;
  FD_TEST( chunk_sz>=0L );
  if( end-cur < chunk_sz ) chunk_sz = end-cur;

  /* Copy to header */
  fd_memcpy( reader->buf + reader->buf_ctr, cur, (ulong)chunk_sz );
  cur             +=         chunk_sz;
  reader->buf_ctr += (ushort)chunk_sz;

  /* Handle complete header */
  int ret = 0;
  if( reader->buf_ctr == sizeof(fd_tar_meta_t) )
    ret = fd_tar_process_hdr( reader );

  *pcur = cur;
  return ret;
}

static int
fd_tar_read_data( fd_tar_reader_t * reader,
                  uchar const **    pcur,
                  uchar const *     end ) {

  uchar const * cur = *pcur;
  FD_TEST( cur<=end );

  /* Determine number of bytes to read */
  ulong chunk_sz = reader->file_sz;
  ulong avail_sz = (ulong)( end-cur );
  if( avail_sz < chunk_sz ) chunk_sz = avail_sz;

  /* Call back to recipient */
  int err = reader->cb_vt.read( reader->cb_arg, cur, chunk_sz );

  /* Consume bytes */
  cur             += chunk_sz;
  reader->file_sz -= chunk_sz;

  *pcur = cur;
  return fd_int_if( err, EIO, 0 );
}

int
fd_tar_read( void *        const reader_,
             uchar const * const data,
             ulong         const data_sz ) {

  fd_tar_reader_t * reader = reader_;
  ulong const pos = reader->pos;

  uchar const * cur = data;
  uchar const * end = cur+data_sz;

  while( cur!=end ) {
    if( reader->file_sz ) {
      int err = fd_tar_read_data( reader, &cur, end );
      if( FD_UNLIKELY( !!err ) ) return err;
      reader->pos = pos + (ulong)( cur-data );
    }
    if( !reader->file_sz ) {
      int err = fd_tar_read_hdr( reader, &cur, end );
      if( FD_UNLIKELY( !!err ) ) return err;
      reader->pos = pos + (ulong)( cur-data );
    }
  }

  return 0;
}

FD_FN_PURE ulong
fd_tar_meta_get_size( fd_tar_meta_t const * meta ) {
  char const * buf = meta->size;

  ulong ret = 0UL;
  for( char const * p=buf; p<buf+12; p++ ) {
    if( *p == '\0' ) break;
    ret = (ret << 3) + (ulong)(*p - '0');
  }

  return ret;
}

int
fd_tar_set_octal( char  buf[ static 12 ],
                  ulong val ) {
  buf[ 11 ] = '\0';
  for( int i=10; i>=0; i-- ) {
    buf[ i ] = '0' + (char)( val&7UL );
    val>>=3;
  }
  return val==0UL;
}
