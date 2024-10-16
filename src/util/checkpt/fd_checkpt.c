#include "fd_checkpt.h"

int
fd_checkpt_frame_style_is_supported( int frame_style ) {
  int supported;
  supported  = (frame_style==FD_CHECKPT_FRAME_STYLE_RAW);
# if FD_HAS_LZ4
  supported |= (frame_style==FD_CHECKPT_FRAME_STYLE_LZ4);
# endif
  return supported;
}

char const *
fd_checkpt_strerror( int err ) {
  switch( err ) {
  case FD_CHECKPT_SUCCESS:   return "success";
  case FD_CHECKPT_ERR_INVAL: return "bad input args";
  case FD_CHECKPT_ERR_UNSUP: return "unsupported on this target";
  case FD_CHECKPT_ERR_IO:    return "io error";
  case FD_CHECKPT_ERR_COMP:  return "compression error";
  default: break;
  }
  return "unknown";
}

#if FD_HAS_LZ4
#include <lz4.h>

/* fd_checkpt_private_lz4 compresses the ubuf_usz byte size memory
   region pointed to by ubuf into the cbuf_max memory region pointed to
   by cbuf using the given lz4 compressor.  Assumes lz4, ubuf and cbuf
   are valid.  On success, returns the compressed size (will be in
   [4,cbuf_max]).  The ubuf passed to this should not be modified
   until the given lz4 stream is reset / closed or there has been an
   additional 64 KiB passed to the stream.  On failure, returns 0 and
   retains no interest in ubuf.  In, either case, this retains no
   interest in cbuf on return.

   _gbuf, gbuf_sz, gbuf_thresh, _gbuf_cursor specify the small buf
   gather ring state.  It is detailed below. */

static ulong
fd_checkpt_private_lz4( LZ4_stream_t * lz4,
                        void const *   _ubuf,
                        ulong          ubuf_usz,
                        void *         _cbuf,
                        ulong          cbuf_max,
                        void *         _gbuf,
                        ulong          gbuf_sz,
                        ulong          gbuf_thresh,
                        ulong *        _gbuf_cursor ) {
  char *       cbuf = (char *)      _cbuf;
  char const * ubuf = (char const *)_ubuf;

  /* Verify ubuf_usz is in [1,LZ4_MAX_INPUT_SIZE] and cbuf_max is large
     enough to store a header and a non-trivial compressed body. */

  if( FD_UNLIKELY( !((1UL<=ubuf_usz) & (ubuf_usz<=(ulong)LZ4_MAX_INPUT_SIZE)) ) ) {
    FD_LOG_WARNING(( "bad ubuf_usz" ));
    return 0UL;
  }

  if( FD_UNLIKELY( cbuf_max<4UL ) ) {
    FD_LOG_WARNING(( "not enough room to compress" ));
    return 0UL;
  }

  /* Small ubuf gather optimization.  Though the LZ4 streaming API looks
     like it is designed for scatter/gather operation, the
     implementation under the hood is heavily optimized for the case
     when incoming data buffers are stored in a ring buffer (basically,
     the compression dictionary has a size of the most recent 64 KiB of
     _contiguous_ _in_ _memory_ buffers passed to it ... see
     lz4-1.9.4@lz4/lib/lz4.c:2636-2665 for an example).

     When a buffer >> 64 KiB is checkpointed, it will be compressed as
     CHUNK_USZ sequential chunks contiguous in memory.  So outside of
     minor startup effects (where the initial dictionary might not be as
     large as it could have been), this case is optimal.

     But when lots of disjoint tiny buffers << 64 KiB are checkpointed,
     LZ4 is constantly reseting its dictionary to only use the most
     recently previously compressed (tiny) buffer.  This case is
     suboptimal.

     At the same time, we don't want to use a ring buffer because that
     would imply an extra copy when compressing large data.  This is a
     complete waste because that case was already optimal.  And this is
     the most important case for high performance.

     Below, if the incoming buffer to compress is large enough
     (>thresh), we compress it in place as it will be optimal as before.

     If not, we first copy it into a gather buffer and have LZ4 compress
     out of the gather buffer location.  Then, when compressing lots of
     tiny buffer disjoint buffers, it will appear to LZ4 as though they
     were contiguous in memory and LZ4 will handle that optimally too.

     Then our dictionary size is optimal in both asymptotic regimes and
     we are still zero copy in the important case of compressing large
     data.  The dictionary will also be reasonable when toggling
     frequently between asymptotic regimes, as often happens in
     checkpointing (small metadata checkpts/large checkpt/small metadata
     checkpts/large data checkpt/...).

     This is also necessary to satisfy fd_checkpt_data's and
     fd_checkpt_meta's API guarantees.  The lz4 streaming API requires
     the most recent 64KiB of uncompressed bytes to be unmodified and in
     the same place when called.  If FD_CHECKPT_META_MAX<=thresh<=64KiB,
     the copying into the gather buffer here and out of the scatter
     buffer on restore means the unmodified-in-place part of the
     requirement can be satified even if the user passes a temporary
     buffer and immediately modifies/frees it on return.  That is, the
     checkpt/restore will be prompt and retain no interest in buf on
     return.

     We also have to make the gather/scatter buffers large enough to
     satify the most-recent-64KiB part of the requirement.  Suppose we
     have only been compressing small buffers and we are trying to
     compress a thresh byte buffer when only thresh-1 bytes of gather
     buffer space remains.  Since we wrap at buffer granularity, we will
     need to put thresh bytes at the head of the buffer.  To ensure this
     doesn't clobber any of the 64 KiB previously compressed bytes, we
     need a gather buffer at least:

       thresh + 64KiB + thresh-1 = 2 thresh + 64 KiB - 1

     in size.  Larger is fine.  Smaller will violate this part of the
     requirement.

     We do the corresponding in the restore and the restore
     configuration must match our checkpt configuration exactly in order
     to keep the dictionaries on both sides synchronized.

     TL;DR  We store small buffers into a gather ring at buffer
     granularity for better compression and compress large buffers in
     place for extra performance due to the details of how LZ4 stream
     APIs are implemented  We also do this to support immediate use and
     reuse of the metadata checkpt/restores buffers. */

  int is_small = ubuf_usz<=gbuf_thresh;
  if( is_small ) { /* app dependent branch prob */
    ulong gbuf_cursor = *_gbuf_cursor;
    if( (gbuf_sz-gbuf_cursor)<ubuf_usz ) gbuf_cursor = 0UL; /* cmov */
    ubuf = (char *)_gbuf + gbuf_cursor;
    *_gbuf_cursor = gbuf_cursor + ubuf_usz;
    memcpy( (char *)ubuf, _ubuf, ubuf_usz );
  }

  /* Compress ubuf into cbuf, leaving space for the header.  Compression
     will fail if there is no room to the resulting compressed size into
     the header as we clamp the capacity to 2^24-1. */

  ulong ubuf_csz_max = fd_ulong_min( cbuf_max-3UL, (1UL<<24)-1UL ); /* In [1,2^24) */

  int _ubuf_csz = LZ4_compress_fast_continue( lz4, ubuf, cbuf+3UL, (int)ubuf_usz, (int)ubuf_csz_max, 1 /* default */ );
  if( FD_UNLIKELY( _ubuf_csz<=0 ) ) {
    FD_LOG_WARNING(( "LZ4_compress_fast_continue error (%i)", _ubuf_csz ));
    return 0UL;
  }

  ulong ubuf_csz = (ulong)_ubuf_csz;
  if( FD_UNLIKELY( ubuf_csz>ubuf_csz_max ) ) {
    FD_LOG_WARNING(( "unexpected compressed size" ));
    return 0UL;
  }

  /* Write compressed size we obtained into the header as a 24-bit
     little endian unsigned integer.  This need to do this is a
     limitation of how the recent LZ4 APIs (>=1.9) work. */

  cbuf[0] = (char)( ubuf_csz      & 255UL);
  cbuf[1] = (char)((ubuf_csz>> 8) & 255UL);
  cbuf[2] = (char)((ubuf_csz>>16) & 255UL);

  return ubuf_csz + 3UL;
}
#endif

fd_checkpt_t *
fd_checkpt_init_stream( void * mem,
                        int    fd,
                        void * wbuf,
                        ulong  wbuf_sz ) {

  /* Check input args */

  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, FD_CHECKPT_ALIGN ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( fd<0 ) ) {
    FD_LOG_WARNING(( "bad fd" ));
    return NULL;
  }

  if( FD_UNLIKELY( !wbuf ) ) {
    FD_LOG_WARNING(( "NULL wbuf" ));
    return NULL;
  }

  if( FD_UNLIKELY( wbuf_sz<FD_CHECKPT_WBUF_MIN ) ) {
    FD_LOG_WARNING(( "wbuf_sz too small" ));
    return NULL;
  }

  /* Create the compressor */

# if FD_HAS_LZ4
  LZ4_stream_t * lz4 = LZ4_createStream();
  if( FD_UNLIKELY( !lz4 ) ) {
    FD_LOG_WARNING(( "lz4 error" ));
    return NULL;
  }
# else
  void * lz4 = NULL;
# endif

  /* Init the checkpt */

  fd_checkpt_t * checkpt = (fd_checkpt_t *)mem;

  checkpt->fd          = fd; /* streaming mode */
  checkpt->frame_style = 0;  /* not in frame */
  checkpt->lz4         = (void *)lz4;
  checkpt->gbuf_cursor = 0UL;
  checkpt->off         = 0UL;
  checkpt->wbuf.mem    = (uchar *)wbuf;
  checkpt->wbuf.sz     = wbuf_sz;
  checkpt->wbuf.used   = 0UL;

  return checkpt;
}

fd_checkpt_t *
fd_checkpt_init_mmio( void * mem,
                      void * mmio,
                      ulong  mmio_sz ) {

  /* Check input args */

  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, FD_CHECKPT_ALIGN ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( (!mmio) & (!!mmio_sz) ) ) {
    FD_LOG_WARNING(( "NULL mmio" ));
    return NULL;
  }

  /* Create the compressor */

# if FD_HAS_LZ4
  LZ4_stream_t * lz4 = LZ4_createStream();
  if( FD_UNLIKELY( !lz4 ) ) {
    FD_LOG_WARNING(( "lz4 error" ));
    return NULL;
  }
# else
  void * lz4 = NULL;
# endif

  /* Init the checkpt */

  fd_checkpt_t * checkpt = (fd_checkpt_t *)mem;

  checkpt->fd          = -1; /* mmio mode */
  checkpt->frame_style = 0;  /* not in frame */
  checkpt->lz4         = (void *)lz4;
  checkpt->gbuf_cursor = 0UL;
  checkpt->off         = 0UL;
  checkpt->mmio.mem    = (uchar *)mmio;
  checkpt->mmio.sz     = mmio_sz;

  return checkpt;
}

void *
fd_checkpt_fini( fd_checkpt_t * checkpt ) {

  if( FD_UNLIKELY( !checkpt ) ) {
    FD_LOG_WARNING(( "NULL checkpt" ));
    return NULL;
  }

  if( FD_UNLIKELY( fd_checkpt_in_frame( checkpt ) ) ) {
    FD_LOG_WARNING(( "in a frame" ));
    checkpt->frame_style = -1; /* failed */
    return NULL;
  }

# if FD_HAS_LZ4

  /* Note: Though this this doesn't seem to be officially documented,
     the lz4-1.9.4@lz4/lib/lz4.c:1575) suggests that this always returns
     0.  That is, 0 is success and non-zero is failure. */

  if( FD_UNLIKELY( LZ4_freeStream( (LZ4_stream_t *)checkpt->lz4 ) ) )
    FD_LOG_WARNING(( "LZ4 freeStream error, attempting to continue" ));

# endif

  return (void *)checkpt;
}

int
fd_checkpt_open_advanced( fd_checkpt_t * checkpt,
                          int            frame_style,
                          ulong *        _off ) {

  if( FD_UNLIKELY( !checkpt ) ) {
    FD_LOG_WARNING(( "NULL checkpt" ));
    return FD_CHECKPT_ERR_INVAL;
  }

  if( FD_UNLIKELY( !fd_checkpt_can_open( checkpt ) ) ) {
    FD_LOG_WARNING(( "in a frame or failed" ));
    checkpt->frame_style = -1; /* failed */
    return FD_CHECKPT_ERR_INVAL;
  }

  if( FD_UNLIKELY( !_off ) ) {
    FD_LOG_WARNING(( "NULL _off" ));
    checkpt->frame_style = -1; /* failed */
    return FD_CHECKPT_ERR_INVAL;
  }

  frame_style = fd_int_if( !!frame_style, frame_style, FD_CHECKPT_FRAME_STYLE_DEFAULT );

  switch( frame_style ) {

  case FD_CHECKPT_FRAME_STYLE_RAW: {
    break;
  }

# if FD_HAS_LZ4
  case FD_CHECKPT_FRAME_STYLE_LZ4: {
    LZ4_resetStream_fast( (LZ4_stream_t *)checkpt->lz4 ); /* Note: no error code for this API */
    checkpt->gbuf_cursor = 0UL;
    break;
  }
# endif

  default: {
    FD_LOG_WARNING(( "unsupported frame_style" ));
    checkpt->frame_style = -1; /* failed */
    return FD_CHECKPT_ERR_UNSUP;
  }

  }

  checkpt->frame_style = frame_style;

  *_off = checkpt->off;
  return FD_CHECKPT_SUCCESS;
}

int
fd_checkpt_close_advanced( fd_checkpt_t * checkpt,
                           ulong *        _off ) {

  if( FD_UNLIKELY( !checkpt ) ) {
    FD_LOG_WARNING(( "NULL checkpt" ));
    return FD_CHECKPT_ERR_INVAL;
  }

  if( FD_UNLIKELY( !fd_checkpt_in_frame( checkpt ) ) ) {
    FD_LOG_WARNING(( "not in a frame" ));
    checkpt->frame_style = -1; /* failed */
    return FD_CHECKPT_ERR_INVAL;
  }

  if( FD_UNLIKELY( !_off ) ) {
    FD_LOG_WARNING(( "NULL _off" ));
    checkpt->frame_style = -1; /* failed */
    return FD_CHECKPT_ERR_INVAL;
  }

  ulong off = checkpt->off;

  if( fd_checkpt_is_mmio( checkpt ) ) { /* mmio mode (app dependent branch prob) */

    /* Nothing to do */

  } else { /* streaming mode */

    /* Flush out all pending bytes for this frame */

    ulong wbuf_used = checkpt->wbuf.used;

    if( FD_LIKELY( wbuf_used ) ) {

      ulong wsz;
      int   err = fd_io_write( checkpt->fd, checkpt->wbuf.mem, wbuf_used, wbuf_used, &wsz );
      if( FD_UNLIKELY( err ) ) {
        FD_LOG_WARNING(( "fd_io_write failed (%i-%s)", err, fd_io_strerror( err ) ));
        checkpt->frame_style = -1; /* failed */
        return FD_CHECKPT_ERR_IO;
      }

      off += wsz;
      if( FD_UNLIKELY( off<wsz ) ) {
        FD_LOG_WARNING(( "checkpt sz overflow" ));
        checkpt->frame_style = -1; /* failed */
        return FD_CHECKPT_ERR_IO;
      }

    }

    checkpt->wbuf.used = 0UL;

  }

  checkpt->off         = off;
  checkpt->frame_style = 0;   /* not in frame */

  *_off = off;
  return FD_CHECKPT_SUCCESS;
}

static int
fd_checkpt_private_buf( fd_checkpt_t * checkpt,
                        void const *   buf,
                        ulong          sz,
                        ulong          max ) {

  if( FD_UNLIKELY( !checkpt ) ) {
    FD_LOG_WARNING(( "NULL checkpt" ));
    return FD_CHECKPT_ERR_INVAL;
  }

  if( FD_UNLIKELY( !fd_checkpt_in_frame( checkpt ) ) ) {
    FD_LOG_WARNING(( "not in a frame" ));
    checkpt->frame_style = -1; /* failed */
    return FD_CHECKPT_ERR_INVAL;
  }

  if( FD_UNLIKELY( !sz ) ) return FD_CHECKPT_SUCCESS; /* nothing to do */

  if( FD_UNLIKELY( sz>max ) ) {
    FD_LOG_WARNING(( "sz too large" ));
    checkpt->frame_style = -1; /* failed */
    return FD_CHECKPT_ERR_INVAL;
  }

  if( FD_UNLIKELY( !buf ) ) {
    FD_LOG_WARNING(( "NULL buf with non-zero sz" ));
    checkpt->frame_style = -1; /* failed */
    return FD_CHECKPT_ERR_INVAL;
  }

  ulong off = checkpt->off;

  switch( checkpt->frame_style ) {

  case FD_CHECKPT_FRAME_STYLE_RAW: {

    if( fd_checkpt_is_mmio( checkpt ) ) { /* mmio mode (app dependent branch prob) */

      if( FD_UNLIKELY( sz > (checkpt->mmio.sz-off) ) ) {
        FD_LOG_WARNING(( "mmio_sz too small" ));
        checkpt->frame_style = -1; /* failed */
        return FD_CHECKPT_ERR_IO;
      }

      memcpy( checkpt->mmio.mem + off, buf, sz );

      off += sz; /* at most mmio.sz */

    } else { /* streaming mode */

      ulong wbuf_used = checkpt->wbuf.used;

      ulong wsz_max = wbuf_used + sz;
      if( FD_UNLIKELY( wsz_max<sz ) ) {
        FD_LOG_WARNING(( "sz overflow" ));
        checkpt->frame_style = -1; /* failed */
        return FD_CHECKPT_ERR_IO;
      }

      int err = fd_io_buffered_write( checkpt->fd, buf, sz, checkpt->wbuf.mem, checkpt->wbuf.sz, &wbuf_used );
      if( FD_UNLIKELY( err ) ) {
        FD_LOG_WARNING(( "fd_io_buffered_write failed (%i-%s)", err, fd_io_strerror( err ) ));
        checkpt->frame_style = -1; /* failed */
        return FD_CHECKPT_ERR_IO;
      }

      if( FD_UNLIKELY( wsz_max<wbuf_used ) ) {
        FD_LOG_WARNING(( "unexpected buffered write size" ));
        checkpt->frame_style = -1; /* failed */
        return FD_CHECKPT_ERR_IO;
      }

      ulong wsz = wsz_max - wbuf_used;

      off += wsz;
      if( FD_UNLIKELY( off<wsz ) ) {
        FD_LOG_WARNING(( "checkpt sz overflow" ));
        checkpt->frame_style = -1; /* failed */
        return FD_CHECKPT_ERR_IO;
      }

      checkpt->wbuf.used = wbuf_used;

    }

    break;
  }

# if FD_HAS_LZ4
  case FD_CHECKPT_FRAME_STYLE_LZ4: {
    LZ4_stream_t * lz4 = (LZ4_stream_t *)checkpt->lz4;

    if( fd_checkpt_is_mmio( checkpt ) ) { /* mmio mode, app dependent branch prob */

      uchar * mmio    = checkpt->mmio.mem;
      ulong   mmio_sz = checkpt->mmio.sz;

      uchar const * chunk = (uchar const *)buf;
      do {
        ulong chunk_usz = fd_ulong_min( sz, FD_CHECKPT_PRIVATE_CHUNK_USZ_MAX );

        ulong chunk_csz = fd_checkpt_private_lz4( lz4, chunk, chunk_usz, mmio + off, mmio_sz - off,
                                                  checkpt->gbuf, FD_CHECKPT_PRIVATE_GBUF_SZ, FD_CHECKPT_META_MAX,
                                                  &checkpt->gbuf_cursor ); /* logs details */
        if( FD_UNLIKELY( !chunk_csz ) ) {
          checkpt->frame_style = -1; /* failed */
          return FD_CHECKPT_ERR_COMP;
        }

        off += chunk_csz; /* at most mmio_sz */

        chunk += chunk_usz;
        sz    -= chunk_usz;
      } while( sz );

    } else { /* streaming mode */

      int     fd        = checkpt->fd;
      uchar * wbuf      = checkpt->wbuf.mem;
      ulong   wbuf_sz   = checkpt->wbuf.sz;
      ulong   wbuf_used = checkpt->wbuf.used;

      uchar const * chunk = (uchar const *)buf;
      do {
        ulong chunk_usz = fd_ulong_min( sz, FD_CHECKPT_PRIVATE_CHUNK_USZ_MAX );

        /* If we are not guaranteed to have enough room in the write
           buffer to hold the compressed chunk, flush it to make room. */

        ulong chunk_csz_max = FD_CHECKPT_PRIVATE_CSZ_MAX( chunk_usz );
        ulong wbuf_free     = wbuf_sz - wbuf_used;
        if( FD_UNLIKELY( chunk_csz_max > wbuf_free ) ) {

          ulong wsz;
          int   err = fd_io_write( fd, wbuf, wbuf_used, wbuf_used, &wsz );
          if( FD_UNLIKELY( err ) ) {
            FD_LOG_WARNING(( "fd_io_write failed (%i-%s)", err, fd_io_strerror( err ) ));
            checkpt->frame_style = -1; /* failed */
            return FD_CHECKPT_ERR_IO;
          }

          off += wsz;
          if( FD_UNLIKELY( off<wsz ) ) {
            FD_LOG_WARNING(( "checkpt sz overflow" ));
            checkpt->frame_style = -1; /* failed */
            return FD_CHECKPT_ERR_IO;
          }

          wbuf_used = 0UL;
          wbuf_free = wbuf_sz; /* >= WBUF_MIN >= CSZ_MAX( CHUNK_USZ_MAX ) >= CSZ_MAX( chunk_usz ) */

        }

        /* At this point, wbuf_free >= chunk_csz_max */

        ulong chunk_csz = fd_checkpt_private_lz4( lz4, chunk, chunk_usz, wbuf + wbuf_used, wbuf_free,
                                                  checkpt->gbuf, FD_CHECKPT_PRIVATE_GBUF_SZ, FD_CHECKPT_META_MAX,
                                                  &checkpt->gbuf_cursor ); /* logs details */
        if( FD_UNLIKELY( !chunk_csz ) ) {
          checkpt->frame_style = -1; /* failed */
          return FD_CHECKPT_ERR_COMP;
        }

        wbuf_used += chunk_csz;

        chunk += chunk_usz;
        sz    -= chunk_usz;

      } while( sz );

      checkpt->wbuf.used = wbuf_used;

    }

    break;
  }
# endif

  default: { /* never get here */
    FD_LOG_WARNING(( "unsupported frame style" ));
    checkpt->frame_style = -1; /* failed */
    return FD_CHECKPT_ERR_UNSUP;
  }

  }

  checkpt->off = off;
  return FD_CHECKPT_SUCCESS;
}

int
fd_checkpt_meta( fd_checkpt_t * checkpt,
                 void const *   buf,
                 ulong          sz ) {
  return fd_checkpt_private_buf( checkpt, buf, sz, FD_CHECKPT_META_MAX );
}

int
fd_checkpt_data( fd_checkpt_t * checkpt,
                 void const *   buf,
                 ulong          sz ) {
  /* TODO: optimize sz <= META_MAX better? */
  return fd_checkpt_private_buf( checkpt, buf, sz, ULONG_MAX );
}
