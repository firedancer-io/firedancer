#include "fd_snapshot_load.h"
#include <errno.h>

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
                         ulong * dst_sz ) {

  fd_io_istream_zstd_t * restrict this = _this;

  if( (!this->dirty) & (this->in_cur == this->in_end) ) {
    /* needs refill */
    ulong in_sz = 0UL;
    int read_err = fd_io_istream_obj_read( &this->src, this->in_buf, FD_IO_ISTREAM_ZSTD_BUFSZ, &in_sz );
    if( FD_LIKELY( read_err==0 ) ) { /* ok */ }
    else if( read_err<0 ) { /* EOF */ return 0; /* TODO handle unexpected EOF case */ }
    else {
      FD_LOG_DEBUG(( "failed to read from source (%d-%s)", read_err, fd_io_strerror( read_err ) ));
      return read_err;
    }
    this->in_cur = this->in_buf;
    this->in_end = this->in_buf + in_sz;
  }

  uchar * out     = dst;
  uchar * out_end = out + dst_max;
  int zstd_err = fd_zstd_dstream_read( this->dstream, (uchar const **)&this->in_cur, this->in_end, &out, out_end, NULL );
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
                         ulong * dst_sz ) {
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
  int read_err = fd_io_istream_obj_read( &this->src, buf, sizeof(buf), &buf_sz );
  if( FD_LIKELY( read_err==0 ) ) { /* ok */ }
  else if( read_err<0 ) { /* EOF */ return -1; /* TODO handle unexpected EOF case */ }
  else {
    FD_LOG_WARNING(( "snapshot tar stream failed (%d-%s)", read_err, fd_io_strerror( read_err ) ));
    return read_err;
  }

  int tar_err = fd_tar_read( this->reader, buf, buf_sz );
  if( FD_UNLIKELY( tar_err>0 ) ) {
    FD_LOG_WARNING(( "snapshot tar stream failed (%d-%s)", tar_err, fd_io_strerror( tar_err ) ));
    return tar_err;
  }

  return 0;
}
