#include "fd_zstd_dskip.h"
#include "../../../util/fd_util.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  if( argc!=2 ) {
    fprintf( stderr, "Usage: %s file.zst\n", argv[0] );
    return EXIT_FAILURE;
  }

  FILE * file = fopen( argv[1], "rb" );
  if( FD_UNLIKELY( !file ) ) FD_LOG_ERR(( "fopen(%s,\"rb\") failed (%i-%s)", argv[1], errno, fd_io_strerror( errno ) ));

  fd_zstd_dskip_t dskip[1];
  fd_zstd_dskip_init( dskip );

  ulong frame_idx = 0UL;
  ulong frame_start = 0UL;
  ulong total_offset = 0UL;

  for(;;) {
    uchar buf[ 2 ];
    size_t nread = fread( buf, 1, sizeof(buf), file );
    if( nread==0 ) {
      if( feof( file ) ) break;
      FD_LOG_ERR(( "fread(%s) failed (%i-%s)", argv[1], errno, fd_io_strerror( errno ) ));
    }
    ulong offset = 0UL;
    while( offset<nread ) {
      ulong src_consumed;
      ulong res = fd_zstd_dskip_advance( dskip, buf+offset, nread-offset, &src_consumed );
      if( FD_UNLIKELY( res==ULONG_MAX ) ) {
        FD_LOG_ERR(( "fd_zstd_dskip_advance failed at offset %lu (state=%u, buf_sz=%lu, skip_rem=%lu)",
                     total_offset+offset, dskip->state, dskip->buf_sz, dskip->skip_rem ));
      }
      if( FD_UNLIKELY( src_consumed>(nread-offset) ) ) {
        FD_LOG_ERR(( "src_consumed=%lu > avail=%lu (state=%u, buf_sz=%lu)",
                     src_consumed, nread-offset, dskip->state, dskip->buf_sz ));
      }
      FD_TEST( src_consumed<=(nread-offset) );
      offset += src_consumed;
      total_offset += src_consumed;
      if( res==0UL ) {
        FD_LOG_NOTICE(( "Frame %lu at [%lu,%lu) bytes", frame_idx, frame_start, total_offset ));
        frame_idx++;
        frame_start = total_offset;
      }
    }
    FD_TEST( offset==nread );
  }

  if( FD_UNLIKELY( 0!=fclose( file ) ) ) {
    FD_LOG_ERR(( "fclose(%s) failed (%i-%s)", argv[1], errno, fd_io_strerror( errno ) ));
  }

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return EXIT_SUCCESS;
}
