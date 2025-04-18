#ifndef HEADER_fd_src_ballet_shred_fd_deshredder_h
#define HEADER_fd_src_ballet_shred_fd_deshredder_h

#include "../fd_ballet_base.h"
#include "fd_shred.h"

FD_PROTOTYPES_BEGIN

/* fd_deshredder_t: Deserializes a vector of shreds into block entries. */

struct fd_deshredder {
  /* Vector of data shreds */
  fd_shred_t const ** shreds;

  /* Number of shreds left in buffer */
  uint shred_cnt;

  /* Cursor to target buffer

     Note that this points to the end of the data
     that was previously deserialized. */
  uchar * buf;

  /* Free space in target buffer */
  ulong bufsz;

  /* Cached return code */
  long result;
};
typedef struct fd_deshredder fd_deshredder_t;

/* fd_deshredder_init: Initializes the deshredder.

   `buf` is the buffer into which dconcatenated shreds get written.

   `bufsz` is the size of `buf` in bytes.

   `shreds` is a contiguous vector of data shreds:
   The shred `idx` of each shred increments by exactly by one,
   The `slot` and `version` must be the same.

   `shred_cnt` is the number of `fd_shred_t` in the `shreds` buffer.

   Each shred must have passed the validation checks in `fd_shred_parse`
   and ideally should have passed authentication checks (sig verify). */
void
fd_deshredder_init( fd_deshredder_t *          shredder,
                    void *                     buf,
                    ulong                      bufsz,
                    fd_shred_t const ** shreds,
                    ulong                      shred_cnt );

/* fd_deshredder_next: Concatenates a batch of shreds.

   Concatenates a batch of shreds provided by the caller in
   `fd_deshredder_init`.

   Note that it usually takes multiple calls to process all provided
   shreds because each block can have numerous batches.

   If at least one shred was consumed, returns the number of bytes
   written to `buf` which the caller previously provided in
   `fd_deshredder_init`.  In such cases, result code is set to reflect
   the reason that the deshredder returned.

   Set to `FD_SHRED_EBATCH` if no more shreds are available
   and the end of the current batch has been reached.
   Also implies that there are more shreds/batches in this slot.

   Set to `FD_SHRED_ESLOT` if no more shreds are available
   and the end of the current slot has been reached.

   Set to `FD_SHRED_EPIPE` if no more shreds are available
   but we are in the middle of concatenating a batch.

   Otherwise, returns a negative value indicating the error code.
   In the error case, the caller must not make any further calls to
   `fd_deshredder_next` on this shredder.

   Returns `-FD_SHRED_ENOMEM` if the target buffer is too small.

   Returns `-FD_SHRED_EINVAL` if shred type is not a data shred.
 */
long
fd_deshredder_next( fd_deshredder_t * shredder );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_shred_fd_shred_h */
