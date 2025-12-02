#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64
#include <stdio.h>
#include <stdlib.h>
#include <zstd.h>
#include "../../util/log/fd_log.h"
#include "fd_libc_zstd.h"

#define BUFSZ 128UL<<10

struct fd_zstd_rstream {
  FILE *         file;
  ZSTD_DStream * dstream;
  ulong          in_rd;
  uchar          in_buf[ BUFSZ ];
  ZSTD_inBuffer  input;
  uint           eof : 1;
};

typedef struct fd_zstd_rstream fd_zstd_rstream_t;

static ssize_t
rstream_read( void * cookie,
              char * buf,
              size_t size ) {
  fd_zstd_rstream_t * zs = cookie;
  if( zs->eof ) return 0;

  ZSTD_outBuffer output = { buf, size, 0 };
  while( output.pos < output.size ) {
    if( zs->input.pos >= zs->input.size ) {
      size_t read_sz = fread( zs->in_buf, 1, sizeof(zs->in_buf), zs->file );
      if( read_sz==0 ) {
        if( feof( zs->file ) ) break;
        return -1;
      }
      zs->input.src  = zs->in_buf;
      zs->input.size = read_sz;
      zs->input.pos  = 0;
    }

    size_t const ret = ZSTD_decompressStream( zs->dstream, &output, &zs->input );
    if( FD_UNLIKELY( ZSTD_isError( ret ) ) ) {
      FD_LOG_WARNING(( "ZSTD_decompressStream failed (%u-%s)", ZSTD_getErrorCode( ret ), ZSTD_getErrorName( ret ) ));
      return -1;
    }

    if( output.pos>0 && ret==0 ) break;
  }

  zs->eof    = (!!feof( zs->file )) && (zs->input.pos >= zs->input.size);
  zs->in_rd += output.pos;
  return (ssize_t)output.pos;
}

static int
rstream_seek( void *    cookie,
              off64_t * pos,
              int       w ) {
  fd_zstd_rstream_t * zs = cookie;
  if( FD_UNLIKELY( *pos ) ) {
    FD_LOG_WARNING(( "Invalid seek(%ld,%i) on fd_libc_zstd_rstream handle", *pos, w ));
    return -1;
  }
  if( w==SEEK_SET ) {
    if( FD_UNLIKELY( 0!=fseek( zs->file, 0L, SEEK_SET ) ) ) {
      return -1;
    }
    zs->input.src  = zs->in_buf;
    zs->input.size = 0;
    zs->input.pos  = 0;
    zs->in_rd      = 0UL;
    zs->eof        = 0;
    ZSTD_DCtx_reset( zs->dstream, ZSTD_reset_session_only );
    *pos = 0L;
  } else if( w==SEEK_CUR ) {
    *pos = (long)zs->in_rd;
  } else {
    FD_LOG_CRIT(( "unsupported seek mode" ));
  }
  return 0;
}

static int
rstream_close( void * cookie ) {
  fd_zstd_rstream_t * zs = cookie;
  int close_ret = fclose( zs->file );
  free( zs );
  return close_ret;
}

FILE *
fd_zstd_rstream_open( FILE *         file,
                      ZSTD_DStream * dstream ) {
  fd_zstd_rstream_t * zs = malloc( sizeof(fd_zstd_rstream_t) );
  if( FD_UNLIKELY( !zs ) ) return NULL;

  zs->file    = file;
  zs->dstream = dstream;

  size_t const init_ret = ZSTD_DCtx_reset( dstream, ZSTD_reset_session_only );
  if( FD_UNLIKELY( ZSTD_isError( init_ret ) ) ) {
    FD_LOG_WARNING(( "ZSTD_DCtx_reset failed: %s", ZSTD_getErrorName( init_ret ) ));
    free( zs );
    return NULL;
  }

  zs->in_rd      = 0UL;
  zs->input.src  = zs->in_buf;
  zs->input.size = 0;
  zs->input.pos  = 0;
  zs->eof        = 0;

  static cookie_io_functions_t const io_funcs = {
    .read  = rstream_read,
    .write = NULL,
    .seek  = rstream_seek,
    .close = rstream_close
  };
  return fopencookie( zs, "rb", io_funcs );
}

struct fd_zstd_wstream {
  FILE *         file;
  ZSTD_CStream * cstream;
  uchar          out_buf[ BUFSZ ];
  ulong          wr_cnt;
};

typedef struct fd_zstd_wstream fd_zstd_wstream_t;

static ssize_t
wstream_write( void *       cookie,
               char const * buf,
               size_t       size ) {
  fd_zstd_wstream_t * zs = cookie;
  ZSTD_inBuffer input = { buf, size, 0 };
  while( input.pos < input.size ) {
    ZSTD_outBuffer output = { zs->out_buf, sizeof(zs->out_buf), 0 };
    size_t const ret = ZSTD_compressStream( zs->cstream, &output, &input );
    if( FD_UNLIKELY( ZSTD_isError( ret ) ) ) {
      FD_LOG_WARNING(( "ZSTD_compressStream failed (%u-%s)", ZSTD_getErrorCode( ret ), ZSTD_getErrorName( ret ) ));
      return -1;
    }
    if( output.pos > 0 ) {
      size_t written = fwrite( zs->out_buf, 1, output.pos, zs->file );
      if( FD_UNLIKELY( written != output.pos ) ) return -1;
    }
  }
  zs->wr_cnt += size;
  return (ssize_t)size;
}

static int
wstream_close( void * cookie ) {
  fd_zstd_wstream_t * zs = cookie;

  ZSTD_outBuffer output = { zs->out_buf, sizeof(zs->out_buf), 0 };
  size_t const ret = ZSTD_endStream( zs->cstream, &output );
  if( FD_UNLIKELY( ZSTD_isError( ret ) ) ) {
    FD_LOG_WARNING(( "ZSTD_endStream failed (%u-%s)", ZSTD_getErrorCode( ret ), ZSTD_getErrorName( ret ) ));
    return -1;
  }
  if( output.pos > 0 ) {
    size_t written = fwrite( zs->out_buf, 1, output.pos, zs->file );
    if( FD_UNLIKELY( written != output.pos ) ) return -1;
  }

  ZSTD_freeCStream( zs->cstream );
  int close_ret = fclose( zs->file );
  free( zs );
  return close_ret;
}

static int
wstream_seek( void *    cookie,
              off64_t * pos,
              int       w ) {
  fd_zstd_wstream_t * zs = cookie;
  if( FD_UNLIKELY( !( w==SEEK_CUR && *pos==0 ) ) ) {
    FD_LOG_WARNING(( "Attempted to seek in fd_libc_zstd_wstream handle" ));
    return -1;
  }
  *pos = (long)zs->wr_cnt;
  return 0;
}

FILE *
fd_zstd_wstream_open( FILE * file,
                      int    level ) {
  fd_zstd_wstream_t * zs = malloc( sizeof(fd_zstd_wstream_t) );
  if( FD_UNLIKELY( !zs ) ) return NULL;

  zs->file = file;
  zs->cstream = ZSTD_createCStream();
  zs->wr_cnt = 0UL;
  if( FD_UNLIKELY( !zs->cstream ) ) {
    free( zs );
    return NULL;
  }

  size_t const init_ret = ZSTD_initCStream( zs->cstream, level );
  if( FD_UNLIKELY( ZSTD_isError( init_ret ) ) ) {
    ZSTD_freeCStream( zs->cstream );
    free( zs );
    return NULL;
  }

  static cookie_io_functions_t const io_funcs = {
    .read  = NULL,
    .write = wstream_write,
    .seek  = wstream_seek,
    .close = wstream_close
  };
  return fopencookie( zs, "wb", io_funcs );
}
