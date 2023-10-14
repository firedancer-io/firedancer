#include "fd_compress.h"
#include "../fd_util.h"

#include <errno.h>
#include <unistd.h>

#if !FD_HAS_ZSTD
#error "fd_compress requires Zstandard"
#endif

#define ZSTD_STATIC_LINKING_ONLY
#include <zstd.h>

/* Compression ********************************************************/

ulong
fd_zstd_ofstream_align( void ) {
  return alignof(fd_zstd_ofstream_t);
}

ulong
fd_zstd_ofstream_footprint( int   lvl,
                            ulong bufsz )  {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND ( l, alignof(fd_zstd_ofstream_t), sizeof(fd_zstd_ofstream_t)      );
  l = FD_LAYOUT_APPEND ( l, alignof(fd_zstd_ofstream_t), ZSTD_estimateCStreamSize( lvl ) );
  l = FD_LAYOUT_APPEND ( l, alignof(fd_zstd_ofstream_t), bufsz                           );
  return FD_LAYOUT_FINI( l, alignof(fd_zstd_ofstream_t) );
}

void *
fd_zstd_ofstream_new( void * mem,
                      int    lvl,
                      ulong  bufsz,
                      int    file ) {

  /* Check params ... */

  if( FD_UNLIKELY(( !mem ) ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_zstd_ofstream_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }
  if( FD_UNLIKELY( lvl<0 || lvl>22 ) ) {
    FD_LOG_WARNING(( "invalid compression level (%d)", lvl ));
    return NULL;
  }

  /* Create memory layout ... */

  ulong footprint = fd_zstd_ofstream_footprint( lvl, bufsz );

  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_zstd_ofstream_t * comp =
      FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_zstd_ofstream_t), sizeof(fd_zstd_ofstream_t) );
  fd_memset( comp, 0, sizeof(fd_zstd_ofstream_t) );

  ulong  ctx_sz = ZSTD_estimateCStreamSize( lvl );
  void * ctx =
      FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_zstd_ofstream_t), ctx_sz );

  uchar * buf = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_zstd_ofstream_t), bufsz );

  /* Initialize ... */

  /* Paranoia: Ensure scratch layout matches footprint */
  FD_TEST( (ulong)FD_SCRATCH_ALLOC_FINI( l, alignof(fd_zstd_ofstream_t) )-(ulong)mem == footprint );

  ZSTD_CStream * stream = ZSTD_initStaticCStream( ctx, ctx_sz );
  if( FD_UNLIKELY( !stream ) ) {
    FD_LOG_WARNING(( "ZSTD_initStaticCStream failed" ));
    return NULL;
  }
  /* Paranoia: Ensure that ZSTD_CStream handle is within footprint */
  FD_TEST( (ulong)stream > (ulong)mem && (ulong)stream < (ulong)mem + footprint );

  comp->magic   = FD_ZSTD_OFSTREAM_MAGIC;
  comp->ctx     = stream;
  comp->buf     = buf;
  comp->buf_sz  = 0UL;
  comp->buf_cap = bufsz;
  comp->file    = file;

  return comp;
}

fd_zstd_ofstream_t *
fd_zstd_ofstream_join( void * shcomp ) {

  if( FD_UNLIKELY( !shcomp ) ) {
    FD_LOG_WARNING(( "NULL shcomp" ));
    return NULL;
  }

  fd_zstd_ofstream_t * comp = (fd_zstd_ofstream_t *)shcomp;
  if( FD_UNLIKELY( comp->magic != FD_ZSTD_OFSTREAM_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return comp;
}

void *
fd_zstd_ofstream_leave( fd_zstd_ofstream_t * comp ) {
  return comp;
}

void *
fd_zstd_ofstream_delete( fd_zstd_ofstream_t * comp ) {

  if( FD_UNLIKELY( !comp ) ) return NULL;
  if( FD_UNLIKELY( comp->magic!=FD_ZSTD_OFSTREAM_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  fd_memset( comp, 0, sizeof(fd_zstd_ofstream_t) );
  /* No libzstd free required */
  return comp;
}

/* fd_zstd_flush_soft flushes buffered out to the file descriptor.
   Compression state is not flushed. */

static int
fd_zstd_ofstream_flush_soft( fd_zstd_ofstream_t * comp ) {
  if( comp->buf_sz==0UL ) return 0;

  ulong sz;
  int err = fd_io_write( comp->file, comp->buf, comp->buf_sz, comp->buf_sz, &sz );
  if( FD_UNLIKELY( err ) ) {
    FD_LOG_WARNING(( "fd_io_write failed (%d-%s)", err, fd_io_strerror( err ) ));
    return err;
  }
  comp->comp_sz += comp->buf_sz;
  comp->buf_sz   = 0UL;
  return 0;
}

int
fd_zstd_ofstream_flush( fd_zstd_ofstream_t * comp ) {
  int err = fd_zstd_ofstream_flush_soft( comp );
  if( FD_UNLIKELY( err ) ) return err;

  ZSTD_outBuffer out =
    { .dst  = comp->buf,
      .pos  = 0UL,
      .size = comp->buf_cap };
  ulong ret = ZSTD_flushStream( comp->ctx, &out );
  if( FD_UNLIKELY( ZSTD_isError( ret ) ) ) {
    FD_LOG_WARNING(( "ZSTD_flushStream failed (%s)", ZSTD_getErrorName( ret ) ));
    return EPROTO;
  }
  comp->buf_sz = out.pos;

  err = fd_zstd_ofstream_flush_soft( comp );
  return err;
}

int
fd_zstd_ofstream_end( fd_zstd_ofstream_t * comp ) {
  int err = fd_zstd_ofstream_flush_soft( comp );
  if( FD_UNLIKELY( err ) ) return err;

  ZSTD_outBuffer out =
    { .dst  = comp->buf,
      .pos  = 0UL,
      .size = comp->buf_cap };
  ulong ret = ZSTD_endStream( comp->ctx, &out );
  if( FD_UNLIKELY( ZSTD_isError( ret ) ) ) {
    FD_LOG_WARNING(( "ZSTD_endStream failed (%s)", ZSTD_getErrorName( ret ) ));
    return EPROTO;
  }
  comp->buf_sz = out.pos;

  err = fd_zstd_ofstream_flush_soft( comp );
  return err;
}

int
fd_zstd_ofstream_compress( fd_zstd_ofstream_t * comp,
                           void const *         data,
                           ulong                data_sz ) {

  comp->raw_sz += data_sz;

  ZSTD_inBuffer in = { .src = data, .size = data_sz };
  while( in.pos != in.size ) {

    ZSTD_outBuffer out =
      { .dst  = comp->buf,
        .pos  = comp->buf_sz,
        .size = comp->buf_cap };

    ulong in_prev_pos  = in.pos;
    ulong out_prev_pos = out.pos;
    ulong ret = ZSTD_compressStream( comp->ctx, &out, &in );
    if( FD_UNLIKELY( ZSTD_isError( ret ) ) ) {
      FD_LOG_WARNING(( "ZSTD_compressStream failed (%s)", ZSTD_getErrorName( ret ) ));
      return EPROTO;
    };
    comp->buf_sz = out.pos;

    if( ( in_prev_pos  == in.pos  )
      & ( out_prev_pos == out.pos ) ) {
      /* Nothing happened, indicating we have insufficient buffer space */
      int err = fd_zstd_ofstream_flush_soft( comp );
      if( FD_UNLIKELY( err!=0 ) ) return err;
    }

  }

  return 0;
}
