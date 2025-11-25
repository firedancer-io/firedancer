/* Create a snapshot consisting of many small Zstandard frames.  Frames
   are aligned to TAR files. */

#define SNAPMK_MAGIC (0xf212f209fd944ba2UL)

#include "../../util/fd_util.h"
#include "../../util/archive/fd_tar.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <zstd.h>

__attribute__((noreturn)) static void
usage( int rc ) {
  fputs( "Usage: fd_snapmk --in FILE.tar --out FILE.tar.zst\n", stderr );
  exit( rc );
}

struct zst_wr {
  ZSTD_CStream * zst;
  ZSTD_outBuffer out;
  FILE *         f;
  ulong          frame_sz;
};

typedef struct zst_wr zst_wr_t;

static zst_wr_t *
zst_wr_init( zst_wr_t *     wr,
             ZSTD_CStream * zst,
             FILE *         f,
             uchar *        out_buf,
             ulong          out_buf_sz ) {
  *wr = (zst_wr_t){
    .zst = zst,
    .out = {
      .dst  = out_buf,
      .size = out_buf_sz,
      .pos  = 0
    },
    .f = f
  };
  return wr;
}

static void
zst_wr_flush( zst_wr_t * wr ) {
  if( !wr->out.pos ) return;
  for(;;) {
    size_t const written = fwrite( wr->out.dst, 1, wr->out.pos, wr->f );
    if( FD_UNLIKELY( written!=wr->out.pos ) ) {
      FD_LOG_ERR(( "fwrite() failed: (%i-%s)", errno, fd_io_strerror( errno ) ));
    }
    wr->out.pos -= written;
    if( FD_LIKELY( !wr->out.pos ) ) break;
  }
}

static void
zst_wr_end_frame( zst_wr_t * wr ) {
  for(;;) {
    ulong ret = ZSTD_endStream( wr->zst, &wr->out );
    if( FD_UNLIKELY( ZSTD_isError( ret ) ) ) {
      FD_LOG_ERR(( "ZSTD_endStream() failed: %s", ZSTD_getErrorName( ret ) ));
    }
    if( ret==0 ) break;
    zst_wr_flush( wr );
  }
  zst_wr_flush( wr );
}

static void
zst_wr_push( zst_wr_t *    wr,
             uchar const * in,
             ulong         in_sz ) {
  ZSTD_inBuffer zstd_in = {
    .src  = in,
    .size = in_sz,
    .pos  = 0
  };
  for(;;) {
    size_t const ret = ZSTD_compressStream( wr->zst, &wr->out, &zstd_in );
    if( FD_UNLIKELY( ZSTD_isError( ret ) ) ) {
      FD_LOG_ERR(( "ZSTD_compressStream() failed: %s", ZSTD_getErrorName( ret ) ));
    }
    if( FD_LIKELY( zstd_in.pos==zstd_in.size ) ) break;
    zst_wr_flush( wr );
  }
  wr->frame_sz += in_sz;
}

int
main( int     argc,
      char ** argv ) {
  if( fd_env_strip_cmdline_contains( &argc, &argv, "--help" ) ) {
    fputs( "fd_snapmk creates a backwards-compatible Firedancer-optimized Solana snapshot\n", stderr );
    usage( EXIT_SUCCESS );
  }

  fd_boot( &argc, &argv );

  char const * in_path  = fd_env_strip_cmdline_cstr ( &argc, &argv, "--in",       NULL, NULL       );
  char const * out_path = fd_env_strip_cmdline_cstr ( &argc, &argv, "--out",      NULL, NULL       );
  ulong        frame_sz = fd_env_strip_cmdline_ulong( &argc, &argv, "--frame-sz", NULL, 33554432UL );
  if( FD_UNLIKELY( !in_path ) ) usage( EXIT_FAILURE );
  if( !out_path ) {
    ulong in_len = strlen( in_path );
    if( FD_UNLIKELY( in_len+strlen( ".zst" )+1UL>PATH_MAX ) ) FD_LOG_ERR(( "--in argument is too long" ));
    static char output_path[ PATH_MAX ];
    fd_cstr_fini( fd_cstr_append_cstr( fd_cstr_append_text( fd_cstr_init( output_path ), in_path, in_len ), ".zst" ) );
    out_path = output_path;
  }

  FILE * in_file = fopen( in_path, "rb" );
  if( FD_UNLIKELY( !in_file ) ) {
    FD_LOG_ERR(( "fopen(%s,\"rb\") failed (%i-%s)", in_path, errno, fd_io_strerror( errno ) ));
  }

  ulong in_file_sz;
  if( FD_UNLIKELY( fseek( in_file, 0L, SEEK_END )!=0 ) ) {
    FD_LOG_ERR(( "fseek(%s,0,SEEK_END) failed (%i-%s)", in_path, errno, fd_io_strerror( errno ) ));
  }
  long ftell_res = ftell( in_file );
  if( FD_UNLIKELY( ftell_res<0L ) ) {
    FD_LOG_ERR(( "ftell(%s) failed (%i-%s)", in_path, errno, fd_io_strerror( errno ) ));
  }
  in_file_sz = (ulong)ftell_res;
  if( FD_UNLIKELY( fseek( in_file, 0L, SEEK_SET )!=0 ) ) {
    FD_LOG_ERR(( "fseek(%s,0,SEEK_SET) failed (%i-%s)", in_path, errno, fd_io_strerror( errno ) ));
  }

  FILE * out_file = fopen( out_path, "wb" );
  if( FD_UNLIKELY( !out_file ) ) {
    FD_LOG_ERR(( "fopen(%s,\"wb\") failed (%i-%s)", out_path, errno, fd_io_strerror( errno ) ));
  }
  struct __attribute__((packed)) {
    uint  magic;
    uint  frame_sz;
    ulong user;
  } header = {
    .magic    = 0x184D2A50U,
    .frame_sz = 8U,
    .user     = SNAPMK_MAGIC
  };
  if( FD_UNLIKELY( fwrite( &header, sizeof(header), 1UL, out_file )!=1UL ) ) {
    FD_LOG_ERR(( "fwrite header to %s failed (%i-%s)", out_path, errno, fd_io_strerror( errno ) ));
  }

  ZSTD_CStream * zst = ZSTD_createCStream();
  if( FD_UNLIKELY( !zst ) ) FD_LOG_ERR(( "ZSTD_createCStream() failed" ));
  ZSTD_initCStream( zst, 3 );

  static uchar out_buffer[ 1UL<<25 ];

  zst_wr_t wr[1];
  zst_wr_init( wr, zst, out_file, out_buffer, sizeof(out_buffer) );

  ulong last_stat_off = 0UL;
  long  last_stat     = fd_log_wallclock();
  for(;;) {
    long off = ftell( in_file );
    if( FD_LIKELY( off>=0L ) ) {
      ulong since_last_stat = (ulong)off - last_stat_off;
      if( FD_UNLIKELY( since_last_stat>=(1UL<<27) ) ) {
        long now = fd_log_wallclock();
        last_stat_off = (ulong)off;
        printf( "%.3f / %.3f GB (%.1f %%)  %.2f MB/s\n",
                (double)last_stat_off/1e9,
                (double)in_file_sz   /1e9,
                100.0 * (double)last_stat_off/(double)in_file_sz,
                ((double)since_last_stat*1e3) / (double)(now - last_stat) );
        last_stat = now;
      }
    }

    /* Process TAR header */

    union {
      fd_tar_meta_t hdr[1];
      uchar         buf[512];
    } tar;
    if( FD_UNLIKELY( fread( &tar, sizeof(tar), 1UL, in_file )!=1UL ) ) {
      if( feof( in_file ) ) break;
      FD_LOG_ERR(( "fread tar header from %s failed (%i-%s)", in_path, errno, fd_io_strerror( errno ) ));
    }
    zst_wr_push( wr, tar.buf, sizeof(tar) );

    if( FD_UNLIKELY( memcmp( tar.hdr->magic, FD_TAR_MAGIC, 5UL ) ) ) {
      int not_zero = 0;
      for( ulong i=0UL; i<512UL; i++ ) not_zero |= tar.buf[i];
      if( FD_UNLIKELY( not_zero ) ) FD_LOG_ERR(( "invalid tar header magic `%s`", tar.hdr->magic ));
      break; /* EOF marker reached */
    }

    ulong file_sz = fd_tar_meta_get_size( tar.hdr );
    if( FD_UNLIKELY( file_sz==ULONG_MAX ) ) FD_LOG_ERR(( "invalid tar file size" ));

    if( FD_UNLIKELY( tar.hdr->typeflag==FD_TAR_TYPE_DIR ) ) continue;
    if( FD_UNLIKELY( !fd_tar_meta_is_reg( tar.hdr ) ) ) {
      FD_LOG_WARNING(( "invalid tar header type %d", tar.hdr->typeflag ));
    }

    /* Process file content */

    ulong align_sz = fd_ulong_align_up( file_sz, 512UL );
    ulong rem      = align_sz;
    while( rem ) {
      static uchar in_buf[ 1UL<<20 ];
      ulong chunk_sz = fd_ulong_min( rem, sizeof(in_buf) );
      if( FD_UNLIKELY( fread( in_buf, chunk_sz, 1UL, in_file )!=1UL ) ) {
        FD_LOG_ERR(( "fread tar file content from %s failed (%i-%s)", in_path, errno, fd_io_strerror( errno ) ));
      }
      zst_wr_push( wr, in_buf, chunk_sz );
      rem -= chunk_sz;
    }

    /* End frames periodically */

    if( wr->frame_sz>=frame_sz ) {
      zst_wr_end_frame( wr );
      wr->frame_sz = 0UL;
    }
  }

  /* Blindly pipe through remaining bytes */

  for(;;) {
    static uchar in_buf[ 1UL<<20 ];
    size_t const read_sz = fread( in_buf, 1, sizeof(in_buf), in_file );
    if( FD_UNLIKELY( read_sz==0UL ) ) {
      if( feof( in_file ) ) break;
      FD_LOG_ERR(( "fread remaining bytes from %s failed (%i-%s)", in_path, errno, fd_io_strerror( errno ) ));
    }
    zst_wr_push( wr, in_buf, read_sz );
  }

  zst_wr_flush( wr );

  ZSTD_freeCStream( zst );

  if( FD_UNLIKELY( 0!=fclose( in_file ) ) ) {
    FD_LOG_ERR(( "fclose(%s) failed (%i-%s)", in_path, errno, fd_io_strerror( errno ) ));
  }

  if( FD_UNLIKELY( 0!=fclose( out_file ) ) ) {
    FD_LOG_ERR(( "fclose(%s) failed (%i-%s)", out_path, errno, fd_io_strerror( errno ) ));
  }

  fd_halt();
  return 0;
}
