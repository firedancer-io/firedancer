#include "fd_snapshot_istream.h"
#include "fd_snapshot_restore.h"
#include "../../util/fd_util.h"
#include "fd_snapshot_create.h"
#include <errno.h>

#if FD_HAS_ZSTD

/* fd_io_istream_zstd_t ***********************************************/

fd_io_istream_zstd_t *
fd_io_istream_zstd_new( void *              mem,
                        fd_zstd_dstream_t * dstream,
                        fd_io_istream_obj_t src ) {
  fd_io_istream_zstd_t * this = mem;
  *this = (fd_io_istream_zstd_t){
    .dstream = dstream,
    .src     = src,
    .in_cur  = this->in_buf,
    .in_end  = this->in_buf,
    .dirty   = 0
  };
  return this;
}

void *
fd_io_istream_zstd_delete( fd_io_istream_zstd_t * this ) {
  fd_memset( this, 0, sizeof(fd_io_istream_zstd_t) );
  return (void *)this;
}

int
fd_io_istream_zstd_read( void *  _this,
                         void *  dst,
                         ulong   dst_max,
                         ulong * dst_sz,
                         ulong   dst_offset ) {

  fd_io_istream_zstd_t * restrict this = _this;

  if( (!this->dirty) & (this->in_cur == this->in_end) ) {
    /* needs refill */
    ulong in_sz = 0UL;
    int read_err = fd_io_istream_obj_read( &this->src, this->in_buf, FD_IO_ISTREAM_ZSTD_BUFSZ, &in_sz, 0 );
    if( FD_LIKELY( read_err==0 ) ) { /* ok */ }
    else if( read_err<0 ) { /* EOF */ return -1; /* TODO handle unexpected EOF case */ }
    else {
      FD_LOG_DEBUG(( "failed to read from source (%d-%s)", read_err, fd_io_strerror( read_err ) ));
      return read_err;
    }
    this->in_cur = this->in_buf;
    this->in_end = this->in_buf + in_sz;
    if( FD_UNLIKELY( in_sz==0 ) ) {
      *dst_sz = 0UL;
      return 0;
    }
  }

  uchar * out     = dst;
  uchar * out_end = out + dst_max;
  int zstd_err = fd_zstd_dstream_read( this->dstream, (uchar const **)&this->in_cur, this->in_end, &out, out_end, dst_offset, NULL );
  if( FD_UNLIKELY( zstd_err>0 ) ) {
    FD_LOG_WARNING(( "fd_zstd_dstream_read failed" ));
    /* TODO set out pointers? */
    return EPROTO;
  }
  this->dirty = (out==out_end);

  *dst_sz = (ulong)out - (ulong)dst;
  return 0;
}

fd_io_istream_vt_t const fd_io_istream_zstd_vt =
  { .read = fd_io_istream_zstd_read };

#endif /* FD_HAS_ZSTD */

/* fd_io_istream_file_t ***********************************************/

fd_io_istream_file_t *
fd_io_istream_file_new( void * mem,
                        int    fd ) {
  fd_io_istream_file_t * this = mem;
  *this = (fd_io_istream_file_t){
    .fd = fd  /* borrowed for lifetime */
  };
  return this;
}

void *
fd_io_istream_file_delete( fd_io_istream_file_t * this ) {
  fd_memset( this, 0, sizeof(fd_io_istream_file_t) );
  return (void *)this;
}

int
fd_io_istream_file_read( void *  _this,
                         void *  dst,
                         ulong   dst_max,
                         ulong * dst_sz,
                         ulong   dst_offset FD_PARAM_UNUSED ) {
  fd_io_istream_file_t * this = _this;
  return fd_io_read( this->fd, dst, 1UL, dst_max, dst_sz );
}

fd_io_istream_vt_t const fd_io_istream_file_vt =
  { .read = fd_io_istream_file_read };


/* fd_tar_io_reader_t *************************************************/

fd_tar_io_reader_t *
fd_tar_io_reader_new( void *              mem,
                      fd_tar_reader_t *   reader,
                      fd_io_istream_obj_t src ) {

  if( FD_UNLIKELY( !reader ) ) {
    FD_LOG_WARNING(( "NULL reader" ));
    return NULL;
  }
  if( FD_UNLIKELY( !src.vt ) ) {
    FD_LOG_WARNING(( "NULL source" ));
    return NULL;
  }

  fd_tar_io_reader_t * this = mem;
  *this = (fd_tar_io_reader_t){
    .reader = reader,
    .src    = src
  };
  return this;
}

void *
fd_tar_io_reader_delete( fd_tar_io_reader_t * this ) {
  fd_memset( this, 0, sizeof(fd_tar_io_reader_t) );
  return (void *)this;
}

int
fd_tar_io_reader_advance( fd_tar_io_reader_t * this ) {

  uchar buf[ 16384 ];
  ulong buf_sz = 0UL;
  int read_err = fd_io_istream_obj_read( &this->src, buf, sizeof(buf), &buf_sz, 0 );
  if( FD_LIKELY( read_err==0 ) ) { /* ok */ }
  else if( read_err<0 ) { /* EOF */ return -1; /* TODO handle unexpected EOF case */ }
  else {
    FD_LOG_WARNING(( "Snapshot tar stream failed (%d-%s)", read_err, fd_io_strerror( read_err ) ));
    return read_err;
  }

  int tar_err = fd_tar_read( this->reader, buf, buf_sz, MANIFEST_DONE );
  if( tar_err==MANIFEST_DONE ) {
    FD_LOG_NOTICE(( "Finished reading manifest" ));
    return tar_err;
  }
  if( FD_UNLIKELY( tar_err>0 ) ) {
    FD_LOG_WARNING(( "Snapshot tar stream failed (%d-%s)", tar_err, fd_io_strerror( tar_err ) ));
    return tar_err;
  }
  if( tar_err<0 ) {
    FD_LOG_NOTICE(( "Encountered end of tar stream" ));
    return -1;
  }

  return 0;
}

int
fd_tar_io_reader_advance_file( fd_tar_io_reader_t * this,
                               uchar * buf,
                               ulong * buf_offset,
                               ulong   buf_cap FD_PARAM_UNUSED ) {
  // static ulong total_bytes_read = 0;
  ulong buf_sz       = 0UL;
  ulong read_bytes   = 0UL;
  ulong file_sz      = 0UL;

  while ( 1 ) {
    // FD_LOG_WARNING(("writing to buf at offset %lu", *buf_offset));
    int read_err = fd_io_istream_obj_read( &this->src, buf + *buf_offset, 16384, &buf_sz, 0 );
    // FD_LOG_WARNING(("zstd read %lu bytes", buf_sz));
    if( FD_LIKELY( read_err==0 ) ) { /* ok */ }
    else if( read_err<0 ) { /* EOF */ return -1; /* TODO handle unexpected EOF case */ }
    else {
      FD_LOG_WARNING(( "Snapshot tar stream failed (%d-%s)", read_err, fd_io_strerror( read_err ) ));
      return read_err;
    }

    ulong bytes_consumed = 0;
    *buf_offset = *buf_offset + buf_sz;

    ulong data_sz = *buf_offset - (read_bytes);
    // FD_LOG_WARNING(("total_bytes_read is %lu", total_bytes_read));
    // if( !file_sz )
    //   FD_LOG_WARNING(("reading tar at offset %lu", read_bytes));
    int tar_err = fd_tar_read_file( this->reader, buf + read_bytes, data_sz, &file_sz, &bytes_consumed );
    // total_bytes_read += bytes_consumed;
    // FD_LOG_WARNING(("tar consumed %lu bytes", bytes_consumed ));

    if( FD_UNLIKELY( tar_err>0 ) ) {
      FD_LOG_WARNING(( "Snapshot tar stream failed (%d-%s)", tar_err, fd_io_strerror( tar_err ) ));
      return tar_err;
    }
    if( tar_err<0 ) {
      FD_LOG_NOTICE(( "Encountered end of tar stream" ));
      return -1;
    }

    read_bytes += bytes_consumed;
    // FD_LOG_WARNING(("file size is %lu", file_sz));
    // FD_LOG_WARNING(("read %lu bytes from buf", read_bytes));
    if( this->reader->hdr_done && this->reader->file_sz == 0 ) {
      // FD_LOG_WARNING(("done with file!"));
      /* call callback on buffer now that it has been untarred */
      // FD_LOG_WARNING(("buf offset is %lu", *buf_offset));
      // FD_LOG_WARNING(("file offset is %lu", this->reader->file_start_offset));
      // FD_LOG_WARNING(("read bytes is %lu", read_bytes));
      int err = this->reader->cb_vt.read( this->reader->cb_arg, buf+this->reader->file_start_offset, file_sz );

      /* move remaining bytes to start of buf */
      if( read_bytes < *buf_offset ) {
        ulong new_buf_offset = *buf_offset - read_bytes;
        memcpy( buf, buf + read_bytes, *buf_offset - read_bytes );
        *buf_offset = new_buf_offset;
      } else {
        *buf_offset = 0;
      }

      // FD_LOG_WARNING(("new buf offset is %lu", *buf_offset));

      if( err==MANIFEST_DONE ) {
        FD_LOG_NOTICE(( "Finished reading manifest" ));
        return err;
      }

      break;
    }
  }
  return 0;
}
