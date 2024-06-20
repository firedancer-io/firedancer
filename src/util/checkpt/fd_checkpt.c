#include "fd_checkpt.h"

#if FD_HAS_LZ4
#include <lz4.h>
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
  checkpt->lz4         = lz4;
  checkpt->off         = 0UL;
  checkpt->wbuf.mem    = (char *)wbuf;
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
  checkpt->lz4         = lz4;
  checkpt->off         = 0UL;
  checkpt->mmio.mem    = (char *)mmio;
  checkpt->mmio.sz     = mmio_sz;

  return checkpt;
}

void *
fd_checkpt_fini( fd_checkpt_t * checkpt ) {

  if( FD_UNLIKELY( !checkpt ) ) {
    FD_LOG_WARNING(( "NULL checkpt" ));
    return NULL;
  }

  if( FD_UNLIKELY( fd_checkpt_private_in_frame( checkpt ) ) ) {
    FD_LOG_WARNING(( "in a frame" ));
    checkpt->frame_style = -1; /* failed */
    return NULL;
  }

# if FD_HAS_LZ4

  /* Note: Though this this doesn't seem to be officially documented,
     the LZ4-1.9.4 source code (lz4/lib/lz4.c:1575) suggests that this
     always returns 0.  That is, 0 is success and non-zero is failure. */

  if( FD_UNLIKELY( LZ4_freeStream( (LZ4_stream_t *)checkpt->lz4 ) ) )
    FD_LOG_WARNING(( "LZ4 freeStream error, attempting to continue" ));

# endif

  return (void *)checkpt;
}

int
fd_checkpt_frame_open_advanced( fd_checkpt_t * checkpt,
                                int            frame_style,
                                ulong *        _off ) {

  if( FD_UNLIKELY( !checkpt ) ) {
    FD_LOG_WARNING(( "NULL checkpt" ));
    return FD_CHECKPT_ERR_INVAL;
  }

  if( FD_UNLIKELY( fd_checkpt_private_in_frame( checkpt ) ) ) {
    FD_LOG_WARNING(( "in a frame" ));
    checkpt->frame_style = -1; /* failed */
    return FD_CHECKPT_ERR_INVAL;
  }

  if( FD_UNLIKELY( !_off ) ) {
    FD_LOG_WARNING(( "NULL _off" ));
    return FD_CHECKPT_ERR_INVAL;
  }

  frame_style = fd_int_if( !!frame_style, frame_style, FD_CHECKPT_FRAME_STYLE_DEFAULT );

  switch( frame_style ) {

  case FD_CHECKPT_FRAME_STYLE_RAW: {
    break;
  }

# if FD_HAS_LZ4
  case FD_CHECKPT_FRAME_STYLE_LZ4: {
    LZ4_resetStream( (LZ4_stream_t *)checkpt->lz4 ); /* Note: no error code for this API */
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
fd_checkpt_frame_close_advanced( fd_checkpt_t * checkpt,
                                 ulong *        _off ) {

  if( FD_UNLIKELY( !checkpt ) ) {
    FD_LOG_WARNING(( "NULL checkpt" ));
    return FD_CHECKPT_ERR_INVAL;
  }

  if( FD_UNLIKELY( !fd_checkpt_private_in_frame( checkpt ) ) ) {
    FD_LOG_WARNING(( "not in a frame" ));
    checkpt->frame_style = -1; /* failed */
    return FD_CHECKPT_ERR_INVAL;
  }

  if( FD_UNLIKELY( !_off ) ) {
    FD_LOG_WARNING(( "NULL _off" ));
    return FD_CHECKPT_ERR_INVAL;
  }

  ulong off = checkpt->off;

  if( fd_checkpt_private_is_mmio( checkpt ) ) { /* mmio mode (app dependent branch prob) */

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

int
fd_checkpt_buf( fd_checkpt_t * checkpt,
                void const *   buf,
                ulong          sz ) {

  if( FD_UNLIKELY( !checkpt ) ) {
    FD_LOG_WARNING(( "NULL checkpt" ));
    return FD_CHECKPT_ERR_INVAL;
  }

  if( FD_UNLIKELY( !fd_checkpt_private_in_frame( checkpt ) ) ) {
    FD_LOG_WARNING(( "not in a frame" ));
    checkpt->frame_style = -1; /* failed */
    return FD_CHECKPT_ERR_INVAL;
  }

  if( FD_UNLIKELY( !sz ) ) return FD_CHECKPT_SUCCESS; /* nothing to do */

  if( FD_UNLIKELY( !buf ) ) {
    FD_LOG_WARNING(( "NULL buf with non-zero sz" ));
    checkpt->frame_style = -1; /* failed */
    return FD_CHECKPT_ERR_INVAL;
  }

  ulong off = checkpt->off;

  switch( checkpt->frame_style ) {

  case FD_CHECKPT_FRAME_STYLE_RAW: {

    if( fd_checkpt_private_is_mmio( checkpt ) ) { /* mmio mode (app dependent branch prob) */

      if( FD_UNLIKELY( sz > (checkpt->mmio.sz-off) ) ) {
        FD_LOG_WARNING(( "mmio_sz too small" ));
        checkpt->frame_style = -1; /* failed */
        return FD_CHECKPT_ERR_IO;
      }

      memcpy( checkpt->mmio.mem + off, buf, sz );
      off += sz;

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

    if( fd_checkpt_private_is_mmio( checkpt ) ) { /* mmio mode, app dependent branch prob */
      char * mmio      = checkpt->mmio.mem;
      ulong  mmio_sz   = checkpt->mmio.sz;

      char const * chunk = (char const *)buf;
      do {
        ulong mmio_rem = mmio_sz - off;
        if( FD_UNLIKELY( !mmio_rem ) ) {
          FD_LOG_WARNING(( "mmio_sz too small" ));
          checkpt->frame_style = -1; /* failed */
          return FD_CHECKPT_ERR_IO;
        }

        ulong chunk_usz     = fd_ulong_min( sz, FD_CHECKPT_PRIVATE_CHUNK_USZ_MAX );
        ulong chunk_csz_max = fd_ulong_min( FD_CHECKPT_PRIVATE_CSZ_MAX( chunk_usz ), mmio_rem );

        /* At this point, chunk_usz is in [1,CHUNK_USZ_MAX] and
           chunk_csz_max is in [1,CSZ_MAX( USZ_MAX )].  chunk_csz_max is
           also at most the amount of space remaining in the mmio
           region.

           FIXME: DOES CHUNK_CSZ_MAX (DSTCAPACITY) AFFECT HOW LZ4 DOES
           ITS COMPRESSION/DECOMPRESSION?  THE APIS SUGGEST NO AND THIS
           ASSUMES IT DOESNT.  IF IT DOES, THIS CALL AND VARIOUS CALLS
           BELOW MIGHT NEED TO BE ADJUST TO PROVIDE IDENTICAL VALUES FOR
           DST_CAPACITY BETWEEN STREAMING AND MMIO AND BETWEEN CHECKPT
           AND RESTORE. */

        /* Note: 1 is default LZ4 acceleration */
        int _chunk_csz = LZ4_compress_fast_continue( lz4, chunk, mmio + off, (int)chunk_usz, (int)chunk_csz_max, 1 );
        if( FD_UNLIKELY( _chunk_csz<=0 ) ) {
          FD_LOG_WARNING(( "LZ4_compress_fast_continue error (%i), mmio_sz probably too small", _chunk_csz ));
          checkpt->frame_style = -1; /* failed */
          return FD_CHECKPT_ERR_COMP;
        }

        ulong chunk_csz = (ulong)_chunk_csz;
        if( FD_UNLIKELY( chunk_csz>chunk_csz_max ) ) {
          FD_LOG_WARNING(( "unexpected chunk_csz" ));
          checkpt->frame_style = -1; /* failed */
          return FD_CHECKPT_ERR_COMP;
        }

        off += chunk_csz;

        chunk += chunk_usz;
        sz    -= chunk_usz;
      } while( sz );

    } else { /* streaming mode */

      int    fd        = checkpt->fd;
      char * wbuf      = checkpt->wbuf.mem;
      ulong  wbuf_sz   = checkpt->wbuf.sz;
      ulong  wbuf_used = checkpt->wbuf.used;

      char const * chunk = (char const *)buf;
      do {
        ulong chunk_usz     = fd_ulong_min( sz, FD_CHECKPT_PRIVATE_CHUNK_USZ_MAX );
        ulong chunk_csz_max = FD_CHECKPT_PRIVATE_CSZ_MAX( chunk_usz );

        /* At this point, chunk_usz is in [1,CHUNK_USZ_MAX] and
           chunk_csz_max is in [1,CSZ_MAX(CHUNK_USZ_MAX)].  If we don't
           have enough room in the write buffer, flush it to make room. */

        ulong wbuf_free = wbuf_sz - wbuf_used; /* In [0,wbuf_sz] */
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

        /* At this point, wbuf_free >= CSZ_MAX(chunk_usz) such that
           LZ4_compressed_fast_continue cannot fail (at least, according
           to its documentation).  We use the default acceleration.
           ALSO SEE FIXME IN CHECKPT_BUF MMIO */

        /* Note: 1 is default LZ4 acceleration */
        int _chunk_csz = LZ4_compress_fast_continue( lz4, chunk, wbuf + wbuf_used, (int)chunk_usz, (int)wbuf_free, 1 );
        if( FD_UNLIKELY( _chunk_csz<=0 ) ) {
          FD_LOG_WARNING(( "lz4 error" ));
          checkpt->frame_style = -1; /* failed */
          return FD_CHECKPT_ERR_COMP;
        }

        ulong chunk_csz = (ulong)_chunk_csz;
        if( FD_UNLIKELY( chunk_csz>chunk_csz_max ) ) {
          FD_LOG_WARNING(( "unexpected chunk_csz" ));
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

fd_restore_t *
fd_restore_init_stream( void * mem,
                        int    fd,
                        void * rbuf,
                        ulong  rbuf_sz ) {

  /* Check input args */

  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, FD_RESTORE_ALIGN ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( fd<0 ) ) {
    FD_LOG_WARNING(( "bad fd" ));
    return NULL;
  }

  if( FD_UNLIKELY( !rbuf ) ) {
    FD_LOG_WARNING(( "NULL rbuf" ));
    return NULL;
  }

  if( FD_UNLIKELY( rbuf_sz<FD_RESTORE_RBUF_MIN ) ) {
    FD_LOG_WARNING(( "rbuf_sz too small" ));
    return NULL;
  }

  /* Create decompressor */

# if FD_HAS_LZ4
  LZ4_streamDecode_t * lz4 = LZ4_createStreamDecode();
  if( FD_UNLIKELY( !lz4 ) ) {
    FD_LOG_WARNING(( "lz4 error" ));
    return NULL;
  }
# else
  void * lz4 = NULL;
# endif

  /* Init restore */

  fd_restore_t * restore = (fd_restore_t *)mem;

  restore->fd          = fd; /* streaming mode */
  restore->frame_style = 0;  /* not in frame */
  restore->lz4         = lz4;
  restore->rbuf.mem    = rbuf;
  restore->rbuf.sz     = rbuf_sz;
  restore->rbuf.lo     = 0UL;
  restore->rbuf.ready  = 0UL;

  return restore;
}

fd_restore_t *
fd_restore_init_mmio( void *       mem,
                      void const * mmio,
                      ulong        mmio_sz ) {

  /* Check input args */

  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, FD_RESTORE_ALIGN ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( (!mmio) & (!!mmio_sz) ) ) {
    FD_LOG_WARNING(( "NULL mmio with non-zero mmio_sz" ));
    return NULL;
  }

  /* Create decompressor */

# if FD_HAS_LZ4
  LZ4_streamDecode_t * lz4 = LZ4_createStreamDecode();
  if( FD_UNLIKELY( !lz4 ) ) {
    FD_LOG_WARNING(( "lz4 error" ));
    return NULL;
  }
# else
  void * lz4 = NULL;
# endif

  /* Init restore */

  fd_restore_t * restore = (fd_restore_t *)mem;

  restore->fd          = -1; /* mmio mode */
  restore->frame_style = 0;  /* not in frame */
  restore->lz4         = lz4;
  restore->mmio.mem    = (char const *)mmio;
  restore->mmio.sz     = mmio_sz;
  restore->mmio.off    = 0UL;

  return restore;
}

void *
fd_restore_fini( fd_restore_t * restore ) {

  if( FD_UNLIKELY( !restore ) ) {
    FD_LOG_WARNING(( "NULL restore" ));
    return NULL;
  }

  if( FD_UNLIKELY( fd_restore_private_in_frame( restore ) ) ) {
    FD_LOG_WARNING(( "in a frame" ));
    restore->frame_style = -1; /* failed */
    return NULL;
  }

# if FD_HAS_LZ4

  /* Note: Though this this doesn't seem to be officially documented,
     the LZ4-1.9.4 source code (lz4/lib/lz4.c:2575) suggests that this
     always returns 0.  That is, 0 is success and non-zero is failure. */

  if( FD_UNLIKELY( LZ4_freeStreamDecode( (LZ4_streamDecode_t *)restore->lz4 ) ) )
    FD_LOG_WARNING(( "LZ4 freeStreamDecode error, attempting to continue" ));

# endif

  return restore;
}

int
fd_restore_frame_open( fd_restore_t * restore,
                       int            frame_style ) {

  if( FD_UNLIKELY( !restore ) ) {
    FD_LOG_WARNING(( "NULL restore" ));
    return FD_CHECKPT_ERR_INVAL;
  }

  if( FD_UNLIKELY( fd_restore_private_in_frame( restore ) ) ) {
    FD_LOG_WARNING(( "in a frame" ));
    restore->frame_style = -1; /* failed */
    return FD_CHECKPT_ERR_INVAL;
  }

  frame_style = fd_int_if( !!frame_style, frame_style, FD_CHECKPT_FRAME_STYLE_DEFAULT );

  switch( frame_style ) {

  case FD_CHECKPT_FRAME_STYLE_RAW: {
    break;
  }

# if FD_HAS_LZ4
  case FD_CHECKPT_FRAME_STYLE_LZ4: {
    if( FD_UNLIKELY( !LZ4_setStreamDecode( (LZ4_streamDecode_t *)restore->lz4, NULL, 0 ) ) ) {
      FD_LOG_WARNING(( "LZ4_setStreamDecode failed" ));
      restore->frame_style = -1; /* failed */
      return FD_CHECKPT_ERR_COMP;
    }
    break;
  }
# endif

  default: {
    FD_LOG_WARNING(( "unsupported frame_style" ));
    restore->frame_style = -1; /* failed */
    return FD_CHECKPT_ERR_UNSUP;
  }

  }

  restore->frame_style = frame_style;
  return FD_CHECKPT_SUCCESS;
}

int
fd_restore_frame_close( fd_restore_t * restore ) {

  if( FD_UNLIKELY( !restore ) ) {
    FD_LOG_WARNING(( "NULL restore" ));
    return FD_CHECKPT_ERR_INVAL;
  }

  if( FD_UNLIKELY( !fd_restore_private_in_frame( restore ) ) ) {
    FD_LOG_WARNING(( "not in a frame" ));
    restore->frame_style = -1; /* failed */
    return FD_CHECKPT_ERR_INVAL;
  }

  restore->frame_style = 0;
  return FD_CHECKPT_SUCCESS;
}

int
fd_restore_buf( fd_restore_t * restore,
                void *         buf,
                ulong          sz ) {

  if( FD_UNLIKELY( !restore ) ) {
    FD_LOG_WARNING(( "NULL restore" ));
    return FD_CHECKPT_ERR_INVAL;
  }

  if( FD_UNLIKELY( !fd_restore_private_in_frame( restore ) ) ) {
    FD_LOG_WARNING(( "not in a frame" ));
    restore->frame_style = -1; /* failed */
    return FD_CHECKPT_ERR_INVAL;
  }

  if( FD_UNLIKELY( !sz ) ) return FD_CHECKPT_SUCCESS; /* nothing to do */

  if( FD_UNLIKELY( !buf ) ) {
    FD_LOG_WARNING(( "NULL buf with non-zero sz" ));
    restore->frame_style = -1; /* failed */
    return FD_CHECKPT_ERR_INVAL;
  }

  switch( restore->frame_style ) {

  case FD_CHECKPT_FRAME_STYLE_RAW: {

    if( fd_restore_private_is_mmio( restore ) ) { /* mmio mode, app dependent branch prob */

      ulong mmio_sz  = restore->mmio.sz;
      ulong mmio_off = restore->mmio.off;

      if( FD_UNLIKELY( sz > (mmio_sz-mmio_off) ) ) {
        FD_LOG_WARNING(( "sz overflow" ));
        restore->frame_style = -1; /* failed */
        return FD_CHECKPT_ERR_IO;
      }

      memcpy( buf, restore->mmio.mem + mmio_off, sz );

      restore->mmio.off = mmio_off + sz;

    } else { /* streaming mode */

      int err = fd_io_buffered_read( restore->fd, buf, sz, restore->rbuf.mem, restore->rbuf.sz,
                                     &restore->rbuf.lo, &restore->rbuf.ready );

      if( FD_UNLIKELY( err ) ) {
        FD_LOG_WARNING(( "fd_io_buffered_read failed (%i-%s)", err, fd_io_strerror( err ) ));
        restore->frame_style = -1; /* failed */
        return FD_CHECKPT_ERR_IO;
      }

    }

    break;
  }

# if FD_HAS_LZ4
  case FD_CHECKPT_FRAME_STYLE_LZ4: {

    LZ4_streamDecode_t * lz4 = (LZ4_streamDecode_t *)restore->lz4;

    if( fd_restore_private_is_mmio( restore ) ) { /* mmio mode */

      char const * mmio     = restore->mmio.mem;
      ulong        mmio_sz  = restore->mmio.sz;
      ulong        mmio_off = restore->mmio.off;

      char * chunk = (char *)buf;
      do {
        ulong mmio_rem = mmio_sz - mmio_off;
        if( FD_UNLIKELY( !mmio_rem ) ) {
          FD_LOG_WARNING(( "sz error" ));
          restore->frame_style = -1; /* failed */
          return FD_CHECKPT_ERR_IO;
        }

        ulong chunk_usz     = fd_ulong_min( sz, FD_CHECKPT_PRIVATE_CHUNK_USZ_MAX );
        ulong chunk_csz_max = FD_CHECKPT_PRIVATE_CSZ_MAX( chunk_usz );

        /* At this point, chunk_usz is in [1,CHUNK_USZ_MAX] and
           chunk_csz_max is in [0,CSZ_MAX( USZ_MAX )].  chunk_csz_max is
           also at most the amount of space remaining in the mmio
           region.

           Note: The LZ4 header doesn't thoroughly document these APIs
           so we make some guesses.  If we assume no checkpoint
           corruption or truncation, the fast variant should "just
           work".  If we don't, when mmio_rem<chunk_csz_max, it looks
           like the fast variant could read up to chunk_csz_max-mmio_rem
           bytes past the end of the mmio region.  Though this is
           reasonably bounded, it is not easy or natural to append a
           tail reading guard to the end of a memory mapped fail.  So,
           we fall back the safe variant when we are too close for
           comfort.  ALSO SEE FIXME IN CHECKPT_BUF MMIO. */

        int _chunk_csz = FD_LIKELY( (chunk_csz_max<=mmio_rem) )
          ? LZ4_decompress_fast_continue( lz4, mmio + mmio_off, chunk,                (int)chunk_usz )
          : LZ4_decompress_safe_continue( lz4, mmio + mmio_off, chunk, (int)mmio_rem, (int)chunk_usz );
        if( FD_UNLIKELY( _chunk_csz<=0 ) ) {
          FD_LOG_WARNING(( "LZ4_decompress_fast/safe_continue error (%i)", _chunk_csz ));
          restore->frame_style = -1; /* failed */
          return FD_CHECKPT_ERR_COMP;
        }

        ulong chunk_csz = (ulong)_chunk_csz;
        if( FD_UNLIKELY( chunk_csz>fd_ulong_min( chunk_csz_max, mmio_rem ) ) ) {
          FD_LOG_WARNING(( "unexpected chunk_csz" ));
          restore->frame_style = -1; /* failed */
          return FD_CHECKPT_ERR_COMP;
        }

        mmio_off += chunk_csz;

        chunk += chunk_usz;
        sz    -= chunk_usz;
      } while( sz );

      restore->mmio.off = mmio_off;

    } else { /* streaming mode */

      int    fd         = restore->fd;
      char * rbuf       = restore->rbuf.mem;
      ulong  rbuf_sz    = restore->rbuf.sz;
      ulong  rbuf_lo    = restore->rbuf.lo;
      ulong  rbuf_ready = restore->rbuf.ready;

      char * chunk = (char *)buf;
      do {
        ulong chunk_usz     = fd_ulong_min( sz, FD_CHECKPT_PRIVATE_CHUNK_USZ_MAX );
        ulong chunk_csz_max = FD_CHECKPT_PRIVATE_CSZ_MAX( chunk_usz );

        /* At this point, chunk_usz is in [1,CHUNK_USZ_MAX] and
           chunk_csz_max is in [1,CSZ_MAX(CHUNK_USZ_MAX)].  If we don't
           have enough bytes buffered from the file to guarantee
           successful decompression, read more from the file. */

        if( FD_UNLIKELY( rbuf_ready < chunk_csz_max ) ) {

          /* Move the unprocessed bytes to the beginning of the buffer */

          memmove( rbuf, rbuf+rbuf_lo, rbuf_ready );

          /* Try to read at least enough bytes to get to chunk_csz_max
             unprocessed bytes into rbuf and at most enough bytes to
             fill up the read buffer. */

          ulong rsz;
          int   err = fd_io_read( fd, rbuf+rbuf_ready, chunk_csz_max-rbuf_ready, rbuf_sz-rbuf_ready, &rsz );
          if( FD_UNLIKELY( err>0 ) ) {
            FD_LOG_WARNING(( "fd_io_read failed (%i-%s)", err, fd_io_strerror( err ) ));
            restore->frame_style = -1; /* failed */
            return FD_CHECKPT_ERR_IO;
          }
          rbuf_ready += rsz;

          rbuf_lo = 0UL;

          /* At this point, if we didn't hit eof (err==0), we have at
             least chunk_csz_max unprocessed bytes in rbuf.

             If we hit eof (err<0) before getting to at least
             chunk_csz_max unprocessed bytes in rbuf, rbuf_ready should
             be still enough to decompress this block if there was no
             file corruption.

             If we hit eof prematurely due to file corruption though,
             decompression should not crash (the decompressor will not
             touch more than chunk_csz_max and rbuf has a size of
             rbuf_sz >= RBUF_MIN >= CSZ_MAX( CHUNK_CSZ_MAX ) >=
             chunk_csz_max).  The decompressed result will almost
             certainly be corrupt (and potentially previous restores in
             this frame were too as we don't know when the corruption
             occurred).  We can detect this adjusting chunk_csz_max to
             the number of bytes available to eof.

             ALSO SEE FIXME IN CHECKPT_BUF MMIO. */

          chunk_csz_max = fd_ulong_min( chunk_csz_max, rbuf_ready );
        }

        int _chunk_csz = LZ4_decompress_fast_continue( lz4, rbuf + rbuf_lo, chunk, (int)chunk_usz );
        if( FD_UNLIKELY( _chunk_csz<=0 ) ) {
          FD_LOG_WARNING(( "LZ4 decompress_fast_continue failed (%i)", _chunk_csz ));
          restore->frame_style = -1; /* failed */
          return FD_CHECKPT_ERR_COMP;
        }

        ulong chunk_csz = (ulong)_chunk_csz;
        if( FD_UNLIKELY( chunk_csz>chunk_csz_max ) ) {
          FD_LOG_WARNING(( "unexpected chunk_csz" ));
          restore->frame_style = -1; /* failed */
          return FD_CHECKPT_ERR_COMP;
        }

        rbuf_lo    += chunk_csz;
        rbuf_ready -= chunk_csz;

        chunk += chunk_usz;
        sz    -= chunk_usz;
      } while( sz );

      restore->rbuf.lo    = rbuf_lo;
      restore->rbuf.ready = rbuf_ready;

    }

    break;
  }
# endif

  default: { /* never get here */
    FD_LOG_WARNING(( "unsupported frame style" ));
    restore->frame_style = -1; /* failed */
    return FD_CHECKPT_ERR_UNSUP;
  }

  }

  return FD_CHECKPT_SUCCESS;
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
