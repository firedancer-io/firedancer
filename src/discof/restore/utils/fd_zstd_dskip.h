#ifndef HEADER_fd_discof_restore_utils_fd_zstd_dskip_h
#define HEADER_fd_discof_restore_utils_fd_zstd_dskip_h

/* fd_zstd_dskip.h provides an API to skip through Zstandard compressed
   frames.  This is useful for when multiple threads take turns
   decompressing frames from the same compressed byte stream. */

#include "../../../util/fd_util_base.h"

struct fd_zstd_dskip {
  uchar buf[ 32 ];      /* Buffer for partial headers */
  ulong buf_sz;         /* Number of bytes in buffer */
  ulong skip_rem;       /* Bytes remaining to skip in current element */
  uint  state;          /* Current parser state */
  uint  has_checksum;   /* Whether current frame has checksum */
  uint  last_block;     /* Whether current block is the last in frame */
};

typedef struct fd_zstd_dskip fd_zstd_dskip_t;

FD_PROTOTYPES_BEGIN

fd_zstd_dskip_t *
fd_zstd_dskip_init( fd_zstd_dskip_t * dskip );

/* fd_zstd_dskip_advance skips through Zstandard compressed data.
   *src_consumed is set to the number of bytes consumed.  Returns
   ULONG_MAX on decompress error.  Returns 1UL if everything was
   skipped, but the current frame has not yet ended.  Returns 0UL on end
   of Zstandard frame. */

ulong
fd_zstd_dskip_advance( fd_zstd_dskip_t * dskip,
                       void const *      src,
                       ulong             src_sz,
                       ulong *           src_consumed );

FD_PROTOTYPES_END

#endif /* HEADER_fd_discof_restore_utils_fd_zstd_dskip_h */
