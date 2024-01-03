#include "fd_zstd.h"
#include "fd_zstd_private.h"
#include "../../util/fd_util.h"

#if !FD_HAS_ZSTD
#error "fd_zstd requires libzstd"
#endif

#define ZSTD_STATIC_LINKING_ONLY
#include <zstd.h>
#include <errno.h>

fd_zstd_peek_t *
fd_zstd_peek( fd_zstd_peek_t * peek,
              void const *     buf,
              ulong            bufsz ) {
  ZSTD_frameHeader hdr[1];
  ulong const err = ZSTD_getFrameHeader( hdr, buf, bufsz );
  if( FD_UNLIKELY( ZSTD_isError( err ) ) ) return NULL;
  if( FD_UNLIKELY( err>0               ) ) return NULL;
  if( FD_UNLIKELY( hdr->windowSize > (1U<<ZSTD_WINDOWLOG_MAX) ) ) return NULL;
  peek->window_sz          = hdr->windowSize;
  peek->frame_content_sz   = hdr->frameContentSize;
  peek->frame_is_skippable = hdr->frameType == ZSTD_skippableFrame;
  return peek;
}

ulong
fd_zstd_dstream_align( void ) {
  return FD_ZSTD_DSTREAM_ALIGN;
}

ulong
fd_zstd_dstream_footprint( ulong max_window_sz ) {
  return offsetof(fd_zstd_dstream_t, mem) + ZSTD_estimateDStreamSize( max_window_sz );
}

fd_zstd_dstream_t *
fd_zstd_dstream_new( void * mem,
                     ulong  max_window_sz ) {
  fd_zstd_dstream_t * dstream = mem;
  dstream->mem_sz = ZSTD_estimateDStreamSize( max_window_sz );

  ZSTD_DCtx * ctx = ZSTD_initStaticDStream( dstream->mem, ZSTD_estimateDStreamSize( max_window_sz ) );
  if( FD_UNLIKELY( !ctx ) ) {
    /* should never happen */
    FD_LOG_WARNING(( "ZSTD_initStaticDStream failed (max_window_sz=%lu)", max_window_sz ));
    return NULL;
  }
  if( FD_UNLIKELY( (ulong)ctx != (ulong)dstream->mem ) )
    FD_LOG_CRIT(( "ZSTD_initStaticDStream returned unexpected pointer (ctx=%p, mem=%p)",
                  (void *)ctx, (void *)dstream->mem ));

  FD_COMPILER_MFENCE();
  dstream->magic = FD_ZSTD_DSTREAM_MAGIC;
  FD_COMPILER_MFENCE();
  return dstream;
}

static ZSTD_DCtx *
fd_zstd_dstream_ctx( fd_zstd_dstream_t * dstream ) {
  if( FD_UNLIKELY( dstream->magic != FD_ZSTD_DSTREAM_MAGIC ) )
    FD_LOG_CRIT(( "fd_zstd_dstream_t at %p has invalid magic (memory corruption?)", (void *)dstream ));
  return (ZSTD_DCtx *)fd_type_pun( dstream->mem );
}

void *
fd_zstd_dstream_delete( fd_zstd_dstream_t * dstream ) {

  if( FD_UNLIKELY( !dstream ) ) return NULL;
  fd_zstd_dstream_ctx( dstream );

  /* No need to inform libzstd */

  FD_COMPILER_MFENCE();
  dstream->magic  = 0UL;
  dstream->mem_sz = 0UL;
  FD_COMPILER_MFENCE();

  return (void *)dstream;
}

void
fd_zstd_dstream_reset( fd_zstd_dstream_t * dstream ) {
  ZSTD_DCtx_reset( fd_zstd_dstream_ctx( dstream ), ZSTD_reset_session_only );
}

int
fd_zstd_dstream_read( fd_zstd_dstream_t *     dstream,
                      uchar const ** restrict in_p,
                      uchar const *           in_end,
                      uchar ** restrict       out_p,
                      uchar *                 out_end,
                      ulong *                 opt_errcode ) {

  ulong _opt_errcode[1];
  opt_errcode = opt_errcode ? opt_errcode : _opt_errcode;

  uchar const * in_start  = *in_p;
  uchar *       out_start = *out_p;

  if( FD_UNLIKELY( ( in_start  > in_end  ) |
                   ( out_start > out_end ) ) )
    return EINVAL;

  ZSTD_inBuffer in_buf =
    { .src  = in_start,
      .size = (ulong)in_end - (ulong)in_start,
      .pos  = 0UL };
  ZSTD_outBuffer out_buf =
    { .dst  = out_start,
      .size = (ulong)out_end - (ulong)out_start,
      .pos  = 0UL };

  ZSTD_DCtx * ctx = fd_zstd_dstream_ctx( dstream );
  ulong const rc = ZSTD_decompressStream( ctx, &out_buf, &in_buf );
  if( FD_UNLIKELY( ZSTD_isError( rc ) ) ) {
    FD_LOG_WARNING(( "err: %s", ZSTD_getErrorName( rc ) ));
    *opt_errcode = rc;
    return EPROTO;
  }

  if( FD_UNLIKELY( (in_buf.size ) & (!in_buf.pos ) &
                   (out_buf.size) & (!out_buf.pos) ) ) {
    /* should not happen */
    FD_LOG_WARNING(( "libzstd returned success but failed to do any progress" ));
    *opt_errcode = 0UL;
    return EPIPE;
  }

  *in_p  = (void const *)((ulong)in_start  + in_buf.pos );
  *out_p = (void *      )((ulong)out_start + out_buf.pos);
  return rc==0UL ? -1 /* frame complete */ : 0 /* still working */;
}
