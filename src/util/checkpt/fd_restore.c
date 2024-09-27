#include "fd_checkpt.h"

#if FD_HAS_LZ4
#include <lz4.h>

/* fd_restore_private_lz4 decompresses the cbuf_max memory region
   pointed to by cbuf into the ubuf_usz memory region pointed to by ubuf
   using the given lz4 decompressor.  Assumes lz4, ubuf and cbuf are
   valid and assumes ubuf_usz matches the corresponding
   fd_checkpt_private_lz4 call and cbuf is valid.  On success, returns
   the number of leading bytes cbuf bytes that were used for the
   decompression (will be in [4,cbuf_max]) and the ubuf should not
   be modified until the stream is reset, closed or an additional 64 KiB
   has been decompressed.  On failure, returns 0 and retains no interest
   in ubuf.  In either case, this retains no interest in cbuf on return.

   _sbuf, sbuf_sz, sbuf_thresh, _sbuf_cursor specify the small buf
   scatter ring state.  See fd_checkpt_private_lz4 for more details. */

static ulong
fd_restore_private_lz4( LZ4_streamDecode_t * lz4,
                        void *               _ubuf,
                        ulong                ubuf_usz,
                        void const *         _cbuf,
                        ulong                cbuf_max,
                        void *               _sbuf,
                        ulong                sbuf_sz,
                        ulong                sbuf_thresh,
                        ulong *              _sbuf_cursor ) {
  char *       ubuf = (char *)      _ubuf;
  char const * cbuf = (char const *)_cbuf;

  /* Verify ubuf_usz is in [1,LZ4_MAX_INPUT_SIZE] and cbuf_max is large
     enough to store a header and a non-trivial compressed body. */

  if( FD_UNLIKELY( !((1UL<=ubuf_usz) & (ubuf_usz<=(ulong)LZ4_MAX_INPUT_SIZE)) ) ) {
    FD_LOG_WARNING(( "bad ubuf_usz" ));
    return 0UL;
  }

  if( FD_UNLIKELY( cbuf_max<4UL ) ) { /* 3 bytes for header, 1 byte minimum for body */
    FD_LOG_WARNING(( "truncated header" ));
    return 0UL;
  }

  /* Restore and validate header */

  ulong ubuf_csz = (((ulong)(uchar)cbuf[0])      )
                 | (((ulong)(uchar)cbuf[1]) <<  8)
                 | (((ulong)(uchar)cbuf[2]) << 16); /* In [1,2^24) */

  ulong cbuf_sz  = ubuf_csz + 3UL;
  if( FD_UNLIKELY( !((4UL<=cbuf_sz) | (cbuf_sz<=FD_CHECKPT_PRIVATE_CSZ_MAX( ubuf_usz ))) ) ) {
    FD_LOG_WARNING(( "corrupt header" ));
    return 0UL;
  }

  if( FD_UNLIKELY( cbuf_sz>cbuf_max ) ) {
    FD_LOG_WARNING(( "truncated checkpt" ));
    return 0UL;
  }

  /* Small ubuf scatter optimization.  See note in
     fd_checkpt_private_lz4 for details. */

  int is_small = ubuf_usz<=sbuf_thresh;
  if( is_small ) { /* app dependent branch prob */
    ulong sbuf_cursor = *_sbuf_cursor;
    if( (sbuf_sz-sbuf_cursor)<ubuf_usz ) sbuf_cursor = 0UL; /* cmov */
    ubuf = (char *)_sbuf + sbuf_cursor;
    *_sbuf_cursor = sbuf_cursor + ubuf_usz;
  }

  /* Restore the buffer */

  int res = LZ4_decompress_safe_continue( lz4, cbuf+3UL, ubuf, (int)ubuf_csz, (int)ubuf_usz );
  if( FD_UNLIKELY( res<=0 ) ) {
    FD_LOG_WARNING(( "LZ4_decompress_safe_continue error (%i)", res ));
    return 0UL;
  }

  /* Small ubuf scatter optimization */

  if( is_small ) memcpy( _ubuf, ubuf, ubuf_usz ); /* app dependent branch prob */

  return cbuf_sz;
}
#endif

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

  /* Get the position and size of the checkpt.  If we can't (e.g. we are
     restoring from a non-seekable stream / pipe), treat the start of
     the checkpt as the fd's current position and the size as
     (practically) infinite. */

  ulong sz;
  ulong off;

  int err = fd_io_sz( fd, &sz );
  if( FD_LIKELY( !err ) ) err = fd_io_seek( fd, 0L, FD_IO_SEEK_TYPE_CUR, &off );
  if( FD_UNLIKELY( err ) ) { /* fd does not appear seekable */
    off = 0L;
    sz  = ULONG_MAX;
  } else if( FD_UNLIKELY( !((off<=sz) & (sz<=(ulong)LONG_MAX)) ) ) { /* fd claimed to be seekable but parameters are weird */
    FD_LOG_WARNING(( "sz too large or unexpected file position" ));
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
  restore->lz4         = (void *)lz4;
  restore->sbuf_cursor = 0UL;
  restore->sz          = sz;
  restore->off         = off;
  restore->rbuf.mem    = (uchar *)rbuf;
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

  if( FD_UNLIKELY( mmio_sz>(ulong)LONG_MAX ) ) {
    FD_LOG_WARNING(( "bad mmio_sz" ));
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
  restore->lz4         = (void *)lz4;
  restore->sbuf_cursor = 0UL;
  restore->sz          = mmio_sz;
  restore->off         = 0UL;
  restore->mmio.mem    = (uchar const *)mmio;

  return restore;
}

void *
fd_restore_fini( fd_restore_t * restore ) {

  if( FD_UNLIKELY( !restore ) ) {
    FD_LOG_WARNING(( "NULL restore" ));
    return NULL;
  }

  if( FD_UNLIKELY( fd_restore_in_frame( restore ) ) ) {
    FD_LOG_WARNING(( "in a frame" ));
    restore->frame_style = -1; /* failed */
    return NULL;
  }

# if FD_HAS_LZ4

  /* Note: Though this this doesn't seem to be officially documented,
     the lz4-1.9.4@lz4/lib/lz4.c:2575 suggests that this always returns
     0.  That is, 0 is success and non-zero is failure. */

  if( FD_UNLIKELY( LZ4_freeStreamDecode( (LZ4_streamDecode_t *)restore->lz4 ) ) )
    FD_LOG_WARNING(( "LZ4 freeStreamDecode error, attempting to continue" ));

# endif

  return restore;
}

int
fd_restore_open_advanced( fd_restore_t * restore,
                          int            frame_style,
                          ulong *        _off ) {

  if( FD_UNLIKELY( !restore ) ) {
    FD_LOG_WARNING(( "NULL restore" ));
    return FD_CHECKPT_ERR_INVAL;
  }

  if( FD_UNLIKELY( !fd_restore_can_open( restore ) ) ) {
    FD_LOG_WARNING(( "in a frame or failed" ));
    restore->frame_style = -1; /* failed */
    return FD_CHECKPT_ERR_INVAL;
  }

  if( FD_UNLIKELY( !_off ) ) {
    FD_LOG_WARNING(( "NULL _off" ));
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
    restore->sbuf_cursor = 0UL;
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

  *_off = restore->off;
  return FD_CHECKPT_SUCCESS;
}

int
fd_restore_close_advanced( fd_restore_t * restore,
                           ulong *        _off ) {

  if( FD_UNLIKELY( !restore ) ) {
    FD_LOG_WARNING(( "NULL restore" ));
    return FD_CHECKPT_ERR_INVAL;
  }

  if( FD_UNLIKELY( !fd_restore_in_frame( restore ) ) ) {
    FD_LOG_WARNING(( "not in a frame" ));
    restore->frame_style = -1; /* failed */
    return FD_CHECKPT_ERR_INVAL;
  }

  if( FD_UNLIKELY( !_off ) ) {
    FD_LOG_WARNING(( "NULL _off" ));
    restore->frame_style = -1; /* failed */
    return FD_CHECKPT_ERR_INVAL;
  }

  restore->frame_style = 0;

  *_off = restore->off;
  return FD_CHECKPT_SUCCESS;
}

int
fd_restore_seek( fd_restore_t * restore,
                 ulong          off ) {

  if( FD_UNLIKELY( !restore ) ) {
    FD_LOG_WARNING(( "NULL restore" ));
    return FD_CHECKPT_ERR_INVAL;
  }

  if( FD_UNLIKELY( !fd_restore_can_open( restore ) ) ) {
    FD_LOG_WARNING(( "restore in frame or failed" ));
    restore->frame_style = -1;/* failed */
    return FD_CHECKPT_ERR_INVAL;
  }

  ulong sz = restore->sz;
  if( FD_UNLIKELY( sz>(ulong)LONG_MAX ) ) {
    FD_LOG_WARNING(( "restore not seekable" ));
    restore->frame_style = -1;/* failed */
    return FD_CHECKPT_ERR_INVAL;
  }

  if( FD_UNLIKELY( off>sz ) ) {
    FD_LOG_WARNING(( "bad off" ));
    restore->frame_style = -1;/* failed */
    return FD_CHECKPT_ERR_INVAL;
  }

  /* Note: off<=sz<=LONG_MAX here */

  if( fd_restore_is_mmio( restore ) ) { /* mmio mode, app dependent branch prob */

    restore->off = off;

  } else {

    /* Compute the fd offset range [off0,off1) currently buffered at
       rbuf [0,lo+ready).  If off is in this range, update lo and ready
       accordingly.  Otherwise, seek the underlying fd to off and flush
       rbuf.  Note: though this theoretically could be used to support
       limited seeking within streams / pipes, we don't expose this as
       the API semantics would be tricky to make well defined, robust,
       predictable and easy to use. */

    /* Note: minimizing I/O seeks currently disabled because it is not a
       very important opt and it has no test coverage currently.  Set
       this to 1 to enable. */
#   if 0
    ulong off_old = restore->off;
    ulong off0    = off_old - restore->rbuf.lo;
    ulong off1    = off_old + restore->rbuf.ready;
    if( FD_UNLIKELY( (off0<=off) & (off<off1) ) ) {

      restore->off        = off;
      restore->rbuf.lo    = off  - off0;
      restore->rbuf.ready = off1 - off;

    } else
#   endif

    {

      ulong idx;
      int   err = fd_io_seek( restore->fd, (long)off, FD_IO_SEEK_TYPE_SET, &idx );
      if( FD_UNLIKELY( err ) ) {
        FD_LOG_WARNING(( "fd_io_seek failed (%i-%s)", err, fd_io_strerror( err ) ));
        restore->frame_style = -1; /* failed */
        return FD_CHECKPT_ERR_IO;
      }

      if( FD_UNLIKELY( idx!=off ) ) {
        FD_LOG_WARNING(( "unexpected fd_io_seek result" ));
        restore->frame_style = -1; /* failed */
        return FD_CHECKPT_ERR_IO;
      }

      restore->off        = off;
      restore->rbuf.lo    = 0UL;
      restore->rbuf.ready = 0UL;

    }

  }

  return FD_CHECKPT_SUCCESS;
}

static int
fd_restore_private_buf( fd_restore_t * restore,
                        void *         buf,
                        ulong          sz,
                        ulong          max ) {

  if( FD_UNLIKELY( !restore ) ) {
    FD_LOG_WARNING(( "NULL restore" ));
    return FD_CHECKPT_ERR_INVAL;
  }

  if( FD_UNLIKELY( !fd_restore_in_frame( restore ) ) ) {
    FD_LOG_WARNING(( "not in a frame" ));
    restore->frame_style = -1; /* failed */
    return FD_CHECKPT_ERR_INVAL;
  }

  if( FD_UNLIKELY( !sz ) ) return FD_CHECKPT_SUCCESS; /* nothing to do */

  if( FD_UNLIKELY( sz>max ) ) {
    FD_LOG_WARNING(( "sz too large" ));
    restore->frame_style = -1; /* failed */
    return FD_CHECKPT_ERR_INVAL;
  }

  if( FD_UNLIKELY( !buf ) ) {
    FD_LOG_WARNING(( "NULL buf with non-zero sz" ));
    restore->frame_style = -1; /* failed */
    return FD_CHECKPT_ERR_INVAL;
  }

  ulong off = restore->off;

  switch( restore->frame_style ) {

  case FD_CHECKPT_FRAME_STYLE_RAW: {

    if( fd_restore_is_mmio( restore ) ) { /* mmio mode, app dependent branch prob */

      ulong mmio_sz = restore->sz;

      if( FD_UNLIKELY( sz > (mmio_sz-off) ) ) {
        FD_LOG_WARNING(( "sz overflow" ));
        restore->frame_style = -1; /* failed */
        return FD_CHECKPT_ERR_IO;
      }

      memcpy( buf, restore->mmio.mem + off, sz );

    } else { /* streaming mode */

      int err = fd_io_buffered_read( restore->fd, buf, sz, restore->rbuf.mem, restore->rbuf.sz,
                                     &restore->rbuf.lo, &restore->rbuf.ready );

      if( FD_UNLIKELY( err ) ) {
        FD_LOG_WARNING(( "fd_io_buffered_read failed (%i-%s)", err, fd_io_strerror( err ) ));
        restore->frame_style = -1; /* failed */
        return FD_CHECKPT_ERR_IO;
      }

    }

    off += sz; /* at most mmio_sz */
    break;
  }

# if FD_HAS_LZ4
  case FD_CHECKPT_FRAME_STYLE_LZ4: {

    LZ4_streamDecode_t * lz4 = (LZ4_streamDecode_t *)restore->lz4;

    if( fd_restore_is_mmio( restore ) ) { /* mmio mode */

      uchar const * mmio    = restore->mmio.mem;
      ulong         mmio_sz = restore->sz;

      uchar * chunk = (uchar *)buf;
      do {
        ulong chunk_usz = fd_ulong_min( sz, FD_CHECKPT_PRIVATE_CHUNK_USZ_MAX );

        ulong chunk_csz = fd_restore_private_lz4( lz4, chunk, chunk_usz, mmio + off, mmio_sz - off,
                                                  restore->sbuf, FD_RESTORE_PRIVATE_SBUF_SZ, FD_RESTORE_META_MAX,
                                                  &restore->sbuf_cursor ); /* logs details */
        if( FD_UNLIKELY( !chunk_csz ) ) {
          restore->frame_style = -1; /* failed */
          return FD_CHECKPT_ERR_COMP;
        }

        off += chunk_csz; /* at most mmio_sz */

        chunk += chunk_usz;
        sz    -= chunk_usz;
      } while( sz );

    } else { /* streaming mode */

      int     fd         = restore->fd;
      uchar * rbuf       = restore->rbuf.mem;
      ulong   rbuf_sz    = restore->rbuf.sz;
      ulong   rbuf_lo    = restore->rbuf.lo;
      ulong   rbuf_ready = restore->rbuf.ready;

      uchar * chunk = (uchar *)buf;
      do {
        ulong chunk_usz = fd_ulong_min( sz, FD_CHECKPT_PRIVATE_CHUNK_USZ_MAX );

        /* Pre-buffer the header and the first body byte to figure out
           how large the compressed chunk actually is.

           Note: This can buffer bytes past the end of the checkpoint in
           the uncommon case of there being data past the end of the
           checkpoint (e.g. is a stream like stdin without an EOF or the
           checkpoint is embedded in a larger file).  We could have
           fd_io_read below use min_sz-rbuf_ready for the min and max sz
           arguments to not overread (but then there isn't much point to
           using buffered reads).  We could also make an unbuffered
           streaming a restore option (but it probably much slower if
           there are lots of tiny buffers).  Regardless, overreading in
           such scenarios is an unavoidable possibility if the incoming
           file is corrupt anyway and the caller will usually be able to
           seek such streams.  So we currently just allow it to get the
           benefits of buffering. */

#       define BUFFER(min_ready)                                                                         \
        if( FD_UNLIKELY( rbuf_ready<min_ready ) ) { /* If not enough bytes buffered */                   \
                                                                                                         \
          /* Move the unprocessed bytes to the beginning of the buffer */                                \
                                                                                                         \
          if( FD_LIKELY( (rbuf_lo>0UL) & (rbuf_ready>0UL) ) ) memmove( rbuf, rbuf+rbuf_lo, rbuf_ready ); \
                                                                                                         \
          /* Read at least enough bytes to make progress and at most */                                  \
          /* enough bytes to fill the rbuf.  If we hit EOF or another */                                 \
          /* error, the restore failed. */                                                               \
                                                                                                         \
          ulong rsz;                                                                                     \
          int   err = fd_io_read( fd, rbuf+rbuf_ready, min_ready-rbuf_ready, rbuf_sz-rbuf_ready, &rsz ); \
          if( FD_UNLIKELY( err ) ) {                                                                     \
            FD_LOG_WARNING(( "fd_io_read failed (%i-%s)", err, fd_io_strerror( err ) ));                 \
            restore->frame_style = -1; /* failed */                                                      \
            return FD_CHECKPT_ERR_IO;                                                                    \
          }                                                                                              \
                                                                                                         \
          rbuf_ready += rsz; /* in [min_ready,rbuf_sz] */                                                \
          rbuf_lo     = 0UL;                                                                             \
        }

        BUFFER( 4UL )

        ulong chunk_csz = 3UL + ( ((ulong)rbuf[ rbuf_lo     ]      )
                                | ((ulong)rbuf[ rbuf_lo+1UL ] <<  8)
                                | ((ulong)rbuf[ rbuf_lo+2UL ] << 16) );

        if( FD_UNLIKELY( !((4UL<=chunk_csz) & (chunk_csz<=FD_CHECKPT_PRIVATE_CSZ_MAX( chunk_usz ))) ) ) {
          FD_LOG_WARNING(( "corrupt header" ));
          restore->frame_style = -1; /* failed */
          return FD_CHECKPT_ERR_COMP;
        }

        /* Buffer the compressed chunk.  If the fd doesn't have
           chunk_csz bytes available (e.g. we hit EOF unexpectedly or
           other I/O error), this will fail the restore.  Note that we
           haven't advanced rbuf_lo yet so we invoke buffer with the
           entire chunk_csz.  Also note that at this point:

             rbuf_sz >= RBUF_MIN >= CSZ_MAX( USZ_MAX ) >= CSZ_MAX( chunk_usz ) >= chunk_csz

           such that we always can buffer chunk_csz bytes into rbuf. */

        BUFFER( chunk_csz );

        /* Decompress the compressed chunk in rbuf */

        ulong res = fd_restore_private_lz4( lz4, chunk, chunk_usz, rbuf + rbuf_lo, rbuf_ready,
                                            restore->sbuf, FD_RESTORE_PRIVATE_SBUF_SZ, FD_RESTORE_META_MAX,
                                            &restore->sbuf_cursor ); /* logs details */
        if( FD_UNLIKELY( !res ) ) {
          restore->frame_style = -1; /* failed */
          return FD_CHECKPT_ERR_COMP;
        }

        if( FD_UNLIKELY( res!=chunk_csz ) ) {
          FD_LOG_WARNING(( "corrupt body" ));
          restore->frame_style = -1; /* failed */
          return FD_CHECKPT_ERR_COMP;
        }

#       undef BUFFER

        rbuf_lo    += chunk_csz;
        rbuf_ready -= chunk_csz;

        off += chunk_csz;

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

  restore->off = off;
  return FD_CHECKPT_SUCCESS;
}

int
fd_restore_meta( fd_restore_t * restore,
                 void *         buf,
                 ulong          sz ) {
  return fd_restore_private_buf( restore, buf, sz, FD_CHECKPT_META_MAX );
}

int
fd_restore_data( fd_restore_t * restore,
                 void *         buf,
                 ulong          sz ) {
  return fd_restore_private_buf( restore, buf, sz, ULONG_MAX );
}
