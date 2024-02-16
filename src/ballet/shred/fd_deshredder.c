#include "fd_shred.h"
#include "fd_deshredder.h"

void
fd_deshredder_init( fd_deshredder_t *   shredder,
                    void *              buf,
                    ulong               bufsz,
                    fd_shred_t const ** shreds,
                    ulong               shred_cnt ) {
  shredder->shreds    = shreds;
  shredder->shred_cnt = (uint)shred_cnt;
  shredder->data_off  = 0U;
  shredder->buf       = buf;
  shredder->bufsz     = bufsz;
  shredder->result    = -FD_SHRED_EPIPE;
}

long
fd_deshredder_next( fd_deshredder_t * const shredder ) {
  /* Remember start of provided buffer */
  uchar * const orig_buf = shredder->buf;

  /* Consume shreds, appending each shred buffer into entry buffer */
  for(;;) {
    /* Sanity check: No unexpected "end of shred batch" */
    if( FD_UNLIKELY( shredder->shred_cnt == 0U ) )
      break;

    fd_shred_t const * shred = *shredder->shreds;

    /* Sanity check: Type must be data shred */
    uchar shred_type = fd_shred_type( shred->variant );
    if( FD_UNLIKELY( shred_type!=FD_SHRED_TYPE_LEGACY_DATA
                  && shred_type!=FD_SHRED_TYPE_MERKLE_DATA
                  && shred_type!=FD_SHRED_TYPE_MERKLE_DATA_CHAINED ) )
      return -FD_SHRED_EINVAL;

    /* Ensure entry fits next shred */
    if( FD_UNLIKELY( shredder->bufsz < fd_shred_payload_sz(shred) ) )
      return -FD_SHRED_ENOMEM;

    /* Copy shred data into entry buffer.
       Prior validation ensures that `data_sz` is valid. */
    ulong payload_sz = fd_shred_payload_sz( shred );
    fd_memcpy( shredder->buf, fd_shred_data_payload( shred ), payload_sz );

    /* Seek forward dst cursor */
    shredder->buf   += payload_sz;
    shredder->bufsz -= payload_sz;

    /* Seek forward src cursor */
    shredder->shreds   ++;
    shredder->shred_cnt--;

    /* Terminate loop if shred/entry batch is complete */
    if( FD_UNLIKELY( shred->data.flags & FD_SHRED_DATA_FLAG_SLOT_COMPLETE ) ) {
      shredder->result = FD_SHRED_ESLOT;
      break;
    }
    if( FD_UNLIKELY( shred->data.flags & FD_SHRED_DATA_FLAG_DATA_COMPLETE ) ) {
      shredder->result = FD_SHRED_EBATCH;
      break;
    }
  }

  /* Graceful completion */
  return shredder->buf - orig_buf;
}
