#include "fd_compress.h"
#include "../fd_util.h"

#include <errno.h>
#include <unistd.h>

/* BZip2 **************************************************************/

#if FD_HAS_BZ2

#include <bzlib.h>

int
fd_decompress_bz2( int                fd,
                   fd_decompress_cb_t cb,
                   void *             arg ) {

  /* BZip2 stream state */

  bz_stream bStream = {
    .next_in  = NULL,
    .avail_in = 0,
    .bzalloc  = NULL,
    .bzfree   = NULL,
    .opaque   = NULL
  };

  int init_err = BZ2_bzDecompressInit( &bStream, 0, 0 );
  if( FD_UNLIKELY( init_err!=BZ_OK ) )
    FD_LOG_ERR(( "BZ2_bzDecompressInit failed (%d)", init_err ));

  /* Large stack allocations */

  uchar buf_in [ 1<<17 ];  /* 128 KiB */
  uchar buf_out[ 1<<19 ];  /* 512 KiB */

  /* Buffer descriptors */

  ulong const buf_in_sz  = sizeof(buf_in);
  ulong const buf_out_sz = sizeof(buf_out);
  ulong       buf_in_ctr = 0UL;

  /* Main loop */

  int retval = 0;
  for(;;) {

    /* Read next chunk */

    ulong read_cnt = 0UL;
    int   read_err =
        fd_io_read( fd, buf_in + buf_in_ctr,
                    /* dst_min */ 1UL,
                    /* dst_max */ buf_in_sz - buf_in_ctr,
                    /* dst_sz  */ &read_cnt );

    if( read_err<0 ) {
      /* Encountered EOF before BZ_STREAM_END */
      if( read_cnt==0UL && bStream.avail_in==0U ) {
        FD_LOG_WARNING(( "incomplete bzip2 stream" ));
        retval = EPROTO;
        break;
      }
    } else if( FD_UNLIKELY( read_err!=0 ) ) {
      FD_LOG_WARNING(( "fd_io_read failed (%d-%s)", read_err, fd_io_strerror( read_err ) ));
      retval = read_err;
      break;
    }

    buf_in_ctr += (ulong)read_cnt;

    /* Decompress chunk */

    bStream.next_in   = (char *)buf_in;
    bStream.avail_in  = (uint)buf_in_ctr;
    bStream.next_out  = (char *)buf_out;
    bStream.avail_out = (uint)buf_out_sz;

    int decomp_err = BZ2_bzDecompress( &bStream );
    if( FD_UNLIKELY( decomp_err!=BZ_OK && decomp_err!=BZ_STREAM_END ) ) {
      FD_LOG_WARNING(( "BZ2_bzDecompress failed (%d)", decomp_err ));
      retval = EPROTO;
      break;
    }

    /* Call back with decompressed data */

    int cb_err = (*cb)( arg, buf_out, buf_out_sz - bStream.avail_out );
    if( FD_UNLIKELY( cb_err ) ) break;

    /* Wind up for next iteration */

    if( decomp_err==BZ_STREAM_END ) {
      if( FD_UNLIKELY( bStream.avail_in!=0U ) )
        FD_LOG_WARNING(( "ignoring trailing garbage after end of bzip2 stream" ));
      break;
    }

    /* If not all compressed bytes were consumed, move them to beginning
       of compressed data buffer. */

    memmove( buf_in, buf_in + buf_in_ctr - bStream.avail_in, bStream.avail_in );
    buf_in_ctr = bStream.avail_in;
    FD_TEST( buf_in_ctr < buf_in_sz );  /* just to be sure */

  }

  /* Free compressor */

  BZ2_bzDecompressEnd(&bStream);
  return retval;
}

#endif /* FD_HAS_BZ2 */

/* Zstandard **********************************************************/

#if FD_HAS_ZSTD

#include <zstd.h>

int
fd_decompress_zstd( int                fd,
                    fd_decompress_cb_t cb,
                    void *             arg ) {

  /* Zstandard stream state */

  ZSTD_DCtx * const dctx = ZSTD_createDCtx();
  if( FD_UNLIKELY( !dctx ) )
    FD_LOG_ERR(( "ZSTD_createDCtx() failed!" ));

  /* Buffer descriptors */

  ulong const buf_in_sz  = ZSTD_DStreamInSize();
  ulong const buf_out_sz = ZSTD_DStreamOutSize();
  FD_TEST( buf_in_sz < UINT_MAX );  /* just to be sure */

  /* Large stack allocations (VLA) */

  uchar buf_in [ buf_in_sz  ];
  uchar buf_out[ buf_out_sz ];

  /* Main Loop

     This loop assumes that the input file is one or more concatenated
     zstd streams.  This won't work if there is trailing non-zstd data
     at the end, but streaming decompression in general handles this
     case.  ZSTD_decompressStream() returns 0 exactly when the frame is
     completed, and doesn't consume input after the frame. */

  int end_of_stream = 0;
  int retval = 0;
  for(;;) {

    /* Read next chunk */

    ulong read_cnt;
    int   read_err =
        fd_io_read( fd, buf_in,
                    /* dst_min, dst_max */ buf_in_sz, buf_in_sz,
                    /* dst_sz */ &read_cnt );

    if( read_err<0 ) {
      /* Buffer not completely filled */
      if( read_cnt==0UL ) break;  /* EOF */
    } else if( FD_UNLIKELY( read_err!=0 ) ) {
      FD_LOG_WARNING(( "fd_io_read failed (%d-%s)", read_err, fd_io_strerror( read_err ) ));
      retval = read_err;
      break;
    }

    /* Given a valid frame, zstd won't consume the last byte of the
       frame until it has flushed all of the decompressed data of the
       frame.  Therefore, instead of checking if the return code is 0,
       we can decompress while input.pos < input.size. */

    ZSTD_inBuffer input = { buf_in, (uint)read_cnt, 0 };

    while( input.pos < input.size ) {
      ZSTD_outBuffer output = { buf_out, buf_out_sz, 0 };

      /* The return code is zero if the frame is complete, but there may
         be multiple frames concatenated together. Zstd will auto-
         matically reset the context when a frame is complete. Still,
         calling ZSTD_DCtx_reset() can be useful to reset the context to
         a clean state. */

      ulong const decomp_ret = ZSTD_decompressStream( dctx, &output, &input );
      if( FD_UNLIKELY( ZSTD_isError( decomp_ret ) ) ) {
        FD_LOG_WARNING(( "ZSTD_decompressStream failed (%s)", ZSTD_getErrorName( decomp_ret ) ));
        ZSTD_freeDCtx(dctx);
        return EPROTO;
      }

      /* Detect graceful end of stream */

      end_of_stream = fd_int_if( decomp_ret==0UL, 1, 0 );

      /* Call back with decompressed data */

      int cb_err = (*cb)( arg, buf_out, output.pos );
      if( FD_UNLIKELY( cb_err ) ) goto stop;
    }

  }
stop:

  /* Free compressor */

  ZSTD_freeDCtx(dctx);
  if( retval==0 && !end_of_stream ) {
    FD_LOG_WARNING(( "incomplete zstd stream" ));
    retval = EPROTO;
  }
  return retval;
}

#endif /* FD_HAS_ZSTD */
