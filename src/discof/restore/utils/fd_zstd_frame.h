#ifndef HEADER_fd_src_discof_restore_utils_fd_zstd_frame_h
#define HEADER_fd_src_discof_restore_utils_fd_zstd_frame_h

/* A Zstandard stream is a sequence of independent frames.  A normal
   frame contains a variable-size header, repeated 3-byte block headers
   and payloads, and an optional 4-byte checksum.  The last-block bit
   marks the frame boundary.  A skippable frame contains an 8-byte
   header followed by a sized payload.

     stream:
       +---------- frame 0 ----------+ +---------- frame 1 ----------+
       | header | blocks | checksum? | | header | blocks | checksum? |
       +-----------------------------+ +-----------------------------+

     normal frame:
       +--------+ +-------------------------+     +-----------+
       | header | | block header(3) | data | ... | checksum? |
       +--------+ +-------------------------+     +-----------+
                         `last` marks the final block

     skippable frame:
       +----------+-----------------+---------+
       | magic(4) | payload size(4) | payload |
       +----------+-----------------+---------+

   This scanner accepts fragmented input, keeps only partial headers,
   skips payload bytes without decompressing them, and returns END at
   the exact frame boundary. */

#include "../../../util/fd_util_base.h"

#define FD_ZSTD_FRAME_MORE (0)  /* Frame end not reached */
#define FD_ZSTD_FRAME_END  (1)  /* Frame end reached */
#define FD_ZSTD_FRAME_ERR  (-1) /* Frame is invalid */

#define FD_ZSTD_FRAME_HEADER_MAX      (18UL)
#define FD_ZSTD_FRAME_BLOCK_HEADER_SZ (3UL)

struct fd_zstd_frame {
  uchar header      [ FD_ZSTD_FRAME_HEADER_MAX ];
  uchar block_header[ FD_ZSTD_FRAME_BLOCK_HEADER_SZ ];
  ulong bytes_remaining;
  uint  block_sz_max;
  uchar header_sz;
  uchar block_header_sz;
  uchar state;
  uchar checksum_sz;
  uchar last_block;
};

typedef struct fd_zstd_frame fd_zstd_frame_t;

FD_PROTOTYPES_BEGIN

static inline fd_zstd_frame_t *
fd_zstd_frame_new( fd_zstd_frame_t * frame ) {
  if( FD_UNLIKELY( !frame ) ) return NULL;
  fd_memset( frame, 0, sizeof(fd_zstd_frame_t) );
  return frame;
}

/* fd_zstd_frame_advance assumes frame, data, and consumed are non-NULL.
   It scans up to data_sz bytes and writes the number used to *consumed.
   It returns MORE if more input is needed, END at the frame boundary,
   or ERR for invalid framing. */

int
fd_zstd_frame_advance( fd_zstd_frame_t * frame,
                       void const *      data,
                       ulong             data_sz,
                       ulong *           consumed );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_restore_utils_fd_zstd_frame_h */
