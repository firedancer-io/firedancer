#include "fd_zstd_dskip.h"
#include "../../../util/fd_util.h"
#include <string.h>

/* Zstandard format constants */
#define FD_ZSTD_MAGICNUMBER            0xFD2FB528U
#define FD_ZSTD_MAGIC_SKIPPABLE_START  0x184D2A50U
#define FD_ZSTD_MAGIC_SKIPPABLE_MASK   0xFFFFFFF0U
#define FD_ZSTD_FRAMEIDSIZE            4
#define FD_ZSTD_SKIPPABLEHEADERSIZE    8
#define FD_ZSTD_BLOCKHEADERSIZE        3
#define FD_ZSTD_FRAMEHEADERSIZE_PREFIX 5  /* min bytes to determine frame header size */
#define FD_ZSTD_FRAMECHECKSUMSIZE      4

/* Parser states */
#define FD_ZSTD_DSKIP_STATE_MAGIC      0  /* Reading magic number */
#define FD_ZSTD_DSKIP_STATE_SKIP_SIZE  1  /* Reading skippable frame size */
#define FD_ZSTD_DSKIP_STATE_SKIP_DATA  2  /* Skipping skippable frame data */
#define FD_ZSTD_DSKIP_STATE_FRAME_HDR  3  /* Reading frame header */
#define FD_ZSTD_DSKIP_STATE_BLOCK_HDR  4  /* Reading block header */
#define FD_ZSTD_DSKIP_STATE_BLOCK_DATA 5  /* Skipping block data */
#define FD_ZSTD_DSKIP_STATE_CHECKSUM   6  /* Skipping frame checksum */

fd_zstd_dskip_t *
fd_zstd_dskip_init( fd_zstd_dskip_t * dskip ) {
  memset( dskip, 0, sizeof( fd_zstd_dskip_t ) );
  dskip->state = FD_ZSTD_DSKIP_STATE_MAGIC;
  return dskip;
}

/* Helper to read little-endian integers */
static inline uint
fd_zstd_read_le32( uchar const * buf ) {
  return (uint)buf[0] | ((uint)buf[1]<<8) | ((uint)buf[2]<<16) | ((uint)buf[3]<<24);
}

static inline uint
fd_zstd_read_le24( uchar const * buf ) {
  return (uint)buf[0] | ((uint)buf[1]<<8) | ((uint)buf[2]<<16);
}

/* Helper to calculate frame header size from frame header descriptor byte
   Based on ZSTD_frameHeaderSize_internal */
static inline ulong
fd_zstd_frame_header_size( uchar fhd ) {
  static uchar const did_field_size[4] = { 0, 1, 2, 4 };
  static uchar const fcs_field_size[4] = { 0, 2, 4, 8 };

  uint dict_id       = fhd & 3;
  uint single_seg    = (fhd >> 5) & 1;
  uint fcs_id        = fhd >> 6;

  return (ulong)FD_ZSTD_FRAMEHEADERSIZE_PREFIX + (ulong)(!single_seg) +
         (ulong)did_field_size[dict_id] + (ulong)fcs_field_size[fcs_id] +
         (ulong)(single_seg && !fcs_id);
}

ulong
fd_zstd_dskip_advance( fd_zstd_dskip_t * dskip,
                       void const *      src,
                       ulong             src_sz,
                       ulong *           src_consumed ) {

  uchar const * src_ptr = (uchar const *)src;
  ulong consumed = 0UL;

  while( consumed < src_sz ) {
    ulong avail = src_sz - consumed;

    switch( dskip->state ) {

    case FD_ZSTD_DSKIP_STATE_MAGIC: {
      /* Need to buffer the 4-byte magic number */
      ulong need = FD_ZSTD_FRAMEIDSIZE - dskip->buf_sz;
      ulong copy = (avail < need) ? avail : need;
      memcpy( dskip->buf + dskip->buf_sz, src_ptr + consumed, copy );
      dskip->buf_sz += copy;
      consumed += copy;

      if( dskip->buf_sz < FD_ZSTD_FRAMEIDSIZE ) {
        /* Need more data */
        *src_consumed = consumed;
        return 1UL;
      }

      /* Parse magic number */
      uint magic = fd_zstd_read_le32( dskip->buf );

      if( (magic & FD_ZSTD_MAGIC_SKIPPABLE_MASK) == FD_ZSTD_MAGIC_SKIPPABLE_START ) {
        /* Skippable frame */
        dskip->state = FD_ZSTD_DSKIP_STATE_SKIP_SIZE;
        dskip->buf_sz = 0;
      } else if( magic == FD_ZSTD_MAGICNUMBER ) {
        /* Regular Zstandard frame - keep magic in buffer for FRAME_HDR */
        dskip->state = FD_ZSTD_DSKIP_STATE_FRAME_HDR;
        /* buf_sz = 4, keep the magic bytes in buffer */
      } else {
        /* Invalid magic number */
        *src_consumed = consumed;
        return ULONG_MAX;
      }
      break;
    }

    case FD_ZSTD_DSKIP_STATE_SKIP_SIZE: {
      /* Read 4-byte size field for skippable frame */
      ulong need = FD_ZSTD_FRAMEIDSIZE - dskip->buf_sz;
      ulong copy = (avail < need) ? avail : need;
      memcpy( dskip->buf + dskip->buf_sz, src_ptr + consumed, copy );
      dskip->buf_sz += copy;
      consumed += copy;

      if( dskip->buf_sz < FD_ZSTD_FRAMEIDSIZE ) {
        *src_consumed = consumed;
        return 1UL;
      }

      uint size = fd_zstd_read_le32( dskip->buf );
      dskip->skip_rem = (ulong)size;
      dskip->buf_sz = 0;

      if( dskip->skip_rem == 0 ) {
        /* Empty skippable frame - done with this frame */
        dskip->state = FD_ZSTD_DSKIP_STATE_MAGIC;
        *src_consumed = consumed;
        return 0UL;
      }

      dskip->state = FD_ZSTD_DSKIP_STATE_SKIP_DATA;
      break;
    }

    case FD_ZSTD_DSKIP_STATE_SKIP_DATA: {
      /* Skip over skippable frame data */
      ulong skip = (avail < dskip->skip_rem) ? avail : dskip->skip_rem;
      consumed += skip;
      dskip->skip_rem -= skip;

      if( dskip->skip_rem == 0 ) {
        /* Done with skippable frame */
        dskip->state = FD_ZSTD_DSKIP_STATE_MAGIC;
        *src_consumed = consumed;
        return 0UL;
      }

      *src_consumed = consumed;
      return 1UL;
    }

    case FD_ZSTD_DSKIP_STATE_FRAME_HDR: {
      /* Need to read enough to determine frame header size */
      if( dskip->buf_sz < FD_ZSTD_FRAMEHEADERSIZE_PREFIX ) {
        ulong need = FD_ZSTD_FRAMEHEADERSIZE_PREFIX - dskip->buf_sz;
        ulong copy = (avail < need) ? avail : need;
        memcpy( dskip->buf + dskip->buf_sz, src_ptr + consumed, copy );
        dskip->buf_sz += copy;
        consumed += copy;

        if( dskip->buf_sz < FD_ZSTD_FRAMEHEADERSIZE_PREFIX ) {
          *src_consumed = consumed;
          return 1UL;
        }
      }

      /* Calculate full frame header size */
      uchar fhd = dskip->buf[ FD_ZSTD_FRAMEHEADERSIZE_PREFIX - 1 ];
      ulong hdr_size = fd_zstd_frame_header_size( fhd );

      /* Read the rest of the header */
      ulong need = hdr_size - dskip->buf_sz;
      avail = src_sz - consumed;  /* Recalculate avail after consuming bytes above */
      ulong copy = (avail < need) ? avail : need;
      memcpy( dskip->buf + dskip->buf_sz, src_ptr + consumed, copy );
      dskip->buf_sz += copy;
      consumed += copy;

      if( dskip->buf_sz < hdr_size ) {
        *src_consumed = consumed;
        return 1UL;
      }

      /* Parse frame header descriptor for checksum flag */
      dskip->has_checksum = (fhd >> 2) & 1;
      dskip->buf_sz = 0;
      dskip->state = FD_ZSTD_DSKIP_STATE_BLOCK_HDR;
      break;
    }

    case FD_ZSTD_DSKIP_STATE_BLOCK_HDR: {
      /* Read 3-byte block header */
      ulong need = FD_ZSTD_BLOCKHEADERSIZE - dskip->buf_sz;
      ulong copy = (avail < need) ? avail : need;
      memcpy( dskip->buf + dskip->buf_sz, src_ptr + consumed, copy );
      dskip->buf_sz += copy;
      consumed += copy;

      if( dskip->buf_sz < FD_ZSTD_BLOCKHEADERSIZE ) {
        *src_consumed = consumed;
        return 1UL;
      }

      /* Parse block header */
      uint block_hdr = fd_zstd_read_le24( dskip->buf );
      uint last_block = block_hdr & 1;
      uint block_type = (block_hdr >> 1) & 3;
      uint block_size = block_hdr >> 3;

      /* Block types: 0=raw, 1=rle, 2=compressed, 3=reserved */

      /* Check for reserved block type */
      if( block_type == 3 ) {
        *src_consumed = consumed;
        return ULONG_MAX;
      }

      /* RLE blocks store only 1 byte (the byte to repeat) */
      if( block_type == 1 ) {
        block_size = 1;
      }

      dskip->skip_rem = (ulong)block_size;
      dskip->last_block = last_block;
      dskip->buf_sz = 0;

      if( dskip->skip_rem == 0 ) {
        /* Empty block */
        if( last_block ) {
          /* Last block and empty, check for checksum */
          if( dskip->has_checksum ) {
            dskip->skip_rem = FD_ZSTD_FRAMECHECKSUMSIZE;
            dskip->state = FD_ZSTD_DSKIP_STATE_CHECKSUM;
          } else {
            /* Frame complete */
            dskip->state = FD_ZSTD_DSKIP_STATE_MAGIC;
            *src_consumed = consumed;
            return 0UL;
          }
        } else {
          /* Not last block and empty, go to next block */
          dskip->state = FD_ZSTD_DSKIP_STATE_BLOCK_HDR;
        }
      } else {
        /* Block has data to skip */
        dskip->state = FD_ZSTD_DSKIP_STATE_BLOCK_DATA;
      }
      break;
    }

    case FD_ZSTD_DSKIP_STATE_BLOCK_DATA: {
      /* Skip over block data */
      ulong skip = (avail < dskip->skip_rem) ? avail : dskip->skip_rem;
      consumed += skip;
      dskip->skip_rem -= skip;

      if( dskip->skip_rem > 0 ) {
        *src_consumed = consumed;
        return 1UL;
      }

      /* Block data consumed, check if this was the last block */
      if( dskip->last_block ) {
        /* Last block completed, check for checksum */
        if( dskip->has_checksum ) {
          dskip->skip_rem = FD_ZSTD_FRAMECHECKSUMSIZE;
          dskip->state = FD_ZSTD_DSKIP_STATE_CHECKSUM;
        } else {
          /* Frame complete */
          dskip->state = FD_ZSTD_DSKIP_STATE_MAGIC;
          *src_consumed = consumed;
          return 0UL;
        }
      } else {
        /* More blocks to read */
        dskip->buf_sz = 0;
        dskip->state = FD_ZSTD_DSKIP_STATE_BLOCK_HDR;
      }
      break;
    }

    case FD_ZSTD_DSKIP_STATE_CHECKSUM: {
      /* Skip 4-byte checksum */
      ulong skip = (avail < dskip->skip_rem) ? avail : dskip->skip_rem;
      consumed += skip;
      dskip->skip_rem -= skip;

      if( dskip->skip_rem > 0 ) {
        *src_consumed = consumed;
        return 1UL;
      }

      /* Frame complete */
      dskip->state = FD_ZSTD_DSKIP_STATE_MAGIC;
      *src_consumed = consumed;
      return 0UL;
    }

    default:
      *src_consumed = consumed;
      return ULONG_MAX;
    }
  }

  /* Consumed all input but haven't finished the frame yet */
  *src_consumed = consumed;
  return 1UL;
}
