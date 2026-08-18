#include "fd_zstd_frame.h"

#include "../../../util/bits/fd_bits.h"
#include "../../../util/log/fd_log.h"
#include "../../../util/sanitize/fd_msan.h"

#if !FD_HAS_ZSTD
#error "fd_zstd_frame requires Zstandard"
#endif

#define ZSTD_STATIC_LINKING_ONLY
#include <zstd.h>

/* Different states of the ZSTD frame parser state machine */
#define FD_ZSTD_FRAME_STATE_HEADER       (0U)
#define FD_ZSTD_FRAME_STATE_BLOCK_HEADER (1U)
#define FD_ZSTD_FRAME_STATE_PAYLOAD      (2U)
#define FD_ZSTD_FRAME_STATE_SKIPPABLE    (3U)
#define FD_ZSTD_FRAME_STATE_END          (4U)
#define FD_ZSTD_FRAME_STATE_ERR          (5U)

/* Different block types
   https://github.com/facebook/zstd/blob/dev/doc/zstd_compression_format.md#blocks */
#define FD_ZSTD_FRAME_BLOCK_TYPE_RAW        (0U)
#define FD_ZSTD_FRAME_BLOCK_TYPE_RLE        (1U)
#define FD_ZSTD_FRAME_BLOCK_TYPE_COMPRESSED (2U)
#define FD_ZSTD_FRAME_BLOCK_TYPE_RESERVED   (3U)

#define FAIL_IF( c, frame, consumed, off ) do { \
  if( FD_UNLIKELY( c ) ) {                      \
    (frame)->state = FD_ZSTD_FRAME_STATE_ERR;   \
    *(consumed)    = (off);                     \
    return FD_ZSTD_FRAME_ERR;                   \
  }                                             \
} while( 0 )

int
fd_zstd_frame_advance( fd_zstd_frame_t * frame,
                       void const *      data,
                       ulong             data_sz,
                       ulong *           consumed ) {
  uchar const * bytes = (uchar const *)data;
  ulong off = 0UL;

  for(;;) {
    switch( frame->state ) {
      case FD_ZSTD_FRAME_STATE_HEADER: {
        ZSTD_frameHeader header[1];

        for(;;) {
          ulong rc = ZSTD_getFrameHeader( header, frame->header, frame->header_sz );
          FAIL_IF( ZSTD_isError( rc ), frame, consumed, off );

          if( !rc ) break;

          /* Library invariants for rc > 0 */
          FD_TEST( rc<=FD_ZSTD_FRAME_HEADER_MAX );
          FD_TEST( frame->header_sz<rc );

          if( off==data_sz ) {
            *consumed = off;
            return FD_ZSTD_FRAME_MORE;
          }

          ulong need    = rc-frame->header_sz;
          ulong copy_sz = fd_ulong_min( need, data_sz-off );

          fd_memcpy( frame->header+frame->header_sz, bytes+off, copy_sz );
          frame->header_sz += (uchar)copy_sz;
          off              += copy_sz;
        }

        fd_msan_unpoison( header, sizeof(ZSTD_frameHeader) );
        if( header->frameType==ZSTD_skippableFrame ) {
          frame->bytes_remaining = (ulong)header->frameContentSize;
          frame->state           = FD_ZSTD_FRAME_STATE_SKIPPABLE;
        } else {
          frame->block_sz_max = header->blockSizeMax;
          frame->checksum_sz  = header->checksumFlag ? 4U : 0U;
          frame->state        = FD_ZSTD_FRAME_STATE_BLOCK_HEADER;
        }
        continue;
      }

      case FD_ZSTD_FRAME_STATE_BLOCK_HEADER: {
        ulong need    = FD_ZSTD_FRAME_BLOCK_HEADER_SZ-frame->block_header_sz;
        ulong copy_sz = fd_ulong_min( need, data_sz-off );

        fd_memcpy( frame->block_header+frame->block_header_sz, bytes+off, copy_sz );
        frame->block_header_sz += (uchar)copy_sz;
        off                    += copy_sz;

        if( FD_UNLIKELY( copy_sz<need ) ) {
          *consumed = data_sz;
          return FD_ZSTD_FRAME_MORE;
        }

        uint block_header = fd_uint_load_3( frame->block_header );
        uint last_block   = block_header & 1U;      /* bit 0 */
        uint block_type   = (block_header>>1) & 3U; /* bits 1-2 */
        uint block_sz     = block_header>>3;        /* bits 3-23 */

        FAIL_IF( block_type==FD_ZSTD_FRAME_BLOCK_TYPE_RESERVED || block_sz>frame->block_sz_max, frame, consumed, off );

        frame->block_header_sz = 0U;
        frame->last_block      = (uchar)last_block;
        frame->bytes_remaining = block_type==FD_ZSTD_FRAME_BLOCK_TYPE_RLE ? 1UL : (ulong)block_sz;
        frame->state           = FD_ZSTD_FRAME_STATE_PAYLOAD;

        if( last_block ) frame->bytes_remaining += frame->checksum_sz;

        continue;
      }

      case FD_ZSTD_FRAME_STATE_PAYLOAD:
      case FD_ZSTD_FRAME_STATE_SKIPPABLE: {
        ulong skip = fd_ulong_min( frame->bytes_remaining, data_sz-off );
        frame->bytes_remaining -= skip;
        off                    += skip;

        if( frame->bytes_remaining ) {
          *consumed = data_sz;
          return FD_ZSTD_FRAME_MORE;
        }

        if( frame->state==FD_ZSTD_FRAME_STATE_PAYLOAD && !frame->last_block ) {
          frame->state = FD_ZSTD_FRAME_STATE_BLOCK_HEADER;
          continue;
        }

        frame->state = FD_ZSTD_FRAME_STATE_END;
        *consumed    = off;
        return FD_ZSTD_FRAME_END;
      }

      case FD_ZSTD_FRAME_STATE_END:
        *consumed = 0UL;
        return FD_ZSTD_FRAME_END;

      default:
        *consumed = 0UL;
        return FD_ZSTD_FRAME_ERR;
    }
  }
}
