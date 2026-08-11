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
  fd_msan_unpoison( hdr, sizeof(ZSTD_frameHeader) );
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

  if( FD_UNLIKELY( dstream->magic != FD_ZSTD_DSTREAM_MAGIC ) )
      FD_LOG_CRIT(( "fd_zstd_dstream_t at %p has invalid magic (memory corruption?)", (void *)dstream ));

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

ulong
fd_zstd_find_frame_boundaries( ulong const *     buffer,
                               ulong             sz,
                               fd_zstd_frame_t * arr,
                               ulong             arr_sz ) {
  if( FD_UNLIKELY( arr_sz<1UL || sz<9UL ) ) return 0UL;

  ulong curr                     = 0UL;
  ulong curr_fr                  = 0UL;
  ulong content_checksum_enabled = 0UL;

  while( curr<sz ) {
    if( FD_UNLIKELY( curr>=sz || sz-curr<9UL ) ) return 0UL;
    ulong fr_start = curr;

    /* fr_header_sz also includes magic; skipping +4 for magic will result in reading garbage. */
    ulong magic = ZSTD_isFrame( (char const *)buffer + curr, sz - curr );
    if( FD_UNLIKELY( !magic ) ) return 0UL;

    ulong skip         = ZSTD_isSkippableFrame( (char const *)buffer + curr, sz - curr );
    ulong fr_header_sz = ZSTD_frameHeaderSize( (char const *)buffer + curr, sz - curr );

    if( skip ) {
      if( FD_UNLIKELY( arr_sz<=curr_fr ) ) return 0UL;
      if( FD_UNLIKELY( curr>=sz || sz-curr<8UL ) ) return 0UL;

      curr += 4UL;
      ulong skip_fr_sz = fd_uint_load_4( (char const *)buffer + curr );
      curr += 4UL; /* skip frame size field */

      if( FD_UNLIKELY( curr>=sz || sz-curr<skip_fr_sz ) ) return 0UL;
      curr += skip_fr_sz;

      arr[curr_fr].skip   = 1;
      arr[curr_fr].offset = fr_start;
      arr[curr_fr].sz     = curr - fr_start;
      ++curr_fr;
      continue;
    }

    ulong fr_header          = fd_uint_load_1( (char const *)buffer + curr + 4UL );
    content_checksum_enabled = fd_extract_bit( fr_header, 2 );
    if( FD_UNLIKELY( ZSTD_isError( fr_header_sz ) ) ) return 0UL;

    curr += fr_header_sz;

    while( 1 ) {
      if( FD_UNLIKELY( curr>=sz || sz-curr<5UL ) ) return 0UL;
      uint b_header   = fd_uint_load_3( (char const *)buffer + curr );
      uint last       = fd_extract_bit( b_header, 0 );
      uint block_type = fd_extract( b_header, 1, 2 );
      uint block_size = fd_extract( b_header, 3, 23 );
      uint payload_sz;

      switch( block_type ) {
      case 0U: payload_sz = block_size; break; /* raw */
      case 1U: payload_sz = 1U;         break; /* RLE */
      case 2U: payload_sz = block_size; break; /* compressed */
      default: return 0UL;                      /* block type 3 reserved, treated as error */
      }

      if( FD_UNLIKELY( curr>=sz || sz-curr<payload_sz+3UL ) ) return 0UL;
      curr += payload_sz + 3UL; /* block header */

      if( last ) {
        if( content_checksum_enabled ) {
          if( FD_UNLIKELY( curr>=sz || sz-curr<4UL ) ) return 0UL;
          curr += 4UL;
        }
        if( FD_UNLIKELY( arr_sz<=curr_fr ) ) return 0UL;
        arr[curr_fr].offset = fr_start;
        arr[curr_fr].sz     = curr - fr_start;
        ++curr_fr;
        break;
      }
    }
  }

  return curr_fr;
}
