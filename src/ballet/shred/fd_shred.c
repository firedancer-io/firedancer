#include "fd_shred.h"

fd_shred_t const *
fd_shred_parse( uchar const * const buf,
                ulong         const sz ) {
  /* Reinterpret size as long: `sz` cannot realistically underflow.
     `sz1` is the size of the entire shred. */
  long const sz1 = (long)sz;

  /* Initial bounds check */
  if( FD_UNLIKELY( sz1<0x58L ) ) return NULL;

  fd_shred_t const * shred = (fd_shred_t *)buf;

  /* Validate shred type.
     Safe to access because `variant` ends at 0x41, which is <= 0x58 */
  uchar type = fd_shred_type( shred->variant );
  if( FD_UNLIKELY( type!=FD_SHRED_TYPE_MERKLE_DATA &&
                   type!=FD_SHRED_TYPE_MERKLE_CODE &&
                   shred->variant!=0xa5 /*FD_SHRED_TYPE_LEGACY_DATA*/ &&
                   shred->variant!=0x5a /*FD_SHRED_TYPE_LEGACY_CODE*/ ) )
    return NULL;

  /* Bounds check merkle data
     `sz2` is the shred size excluding Merkle proof data. */
  long const sz2 = sz1 - (long)fd_shred_merkle_sz( shred->variant );
  if( FD_UNLIKELY( sz2<0L ) ) return NULL;

  /* `sz3` is the payload size of the shred. */
  if( FD_LIKELY( type & (FD_SHRED_TYPE_LEGACY_DATA|FD_SHRED_TYPE_MERKLE_DATA) ) ) {
    /* Bounds check actual size
       TODO Verify whether this includes the merkle (sz1) or not (sz2) */
    if( sz2 < shred->data.size )
      return NULL;
    /* Bounds check header */
    long const sz3 = sz2 - (long)FD_SHRED_DATA_HEADER_SZ;
    if( sz3<0L )
      return NULL;
  }
  if( FD_LIKELY( type & (FD_SHRED_TYPE_LEGACY_CODE|FD_SHRED_TYPE_MERKLE_CODE) ) ) {
    /* Bounds check header */
    long const sz3 = sz2 - (long)FD_SHRED_CODE_HEADER_SZ;
    if( FD_UNLIKELY( sz3<0L ) )
      return NULL;
    /* sz3==sz4 as data is implicitly consuming the rest of the shred */
  }

  /* Constraints:
      sz1 >=  0L
      sz1 >= sz2
      sz2 >=  0L
      sz2 >  sz3
      sz3 >=  0L */

  return shred;
}

void
fd_deshredder_init( fd_deshredder_t *          shredder,
                    void *                     buf,
                    ulong                      bufsz,
                    fd_shred_t const * const * shreds,
                    ulong                      shred_cnt ) {
  shredder->shreds    = shreds;
  shredder->shred_cnt = (uint)shred_cnt;
  shredder->data_off  = 0U;
  shredder->buf       = buf;
  shredder->bufsz     = bufsz;
  shredder->result    = -FD_SHRED_EPIPE;
}

long
fd_deshredder_next( fd_deshredder_t * const shredder ) {
  /* Terminate early if no shreds are left */
  if( FD_UNLIKELY( shredder->shred_cnt == 0U ) )
    return shredder->result;

  /* Remember start of provided buffer */
  uchar * const orig_buf = shredder->buf;

  /* Consume shreds, appending each shred buffer into entry buffer */
  for(;;) {
    /* Sanity check: No unexpected "end of shred batch" */
    if( FD_UNLIKELY( shredder->shred_cnt == 0U ) )
      return (shredder->result = -FD_SHRED_EPIPE);

    fd_shred_t const * shred = *shredder->shreds;

    /* Sanity check: Type must be data shred */
    uchar shred_type = fd_shred_type( shred->variant );
    if( FD_UNLIKELY( shred_type!=FD_SHRED_TYPE_LEGACY_DATA
                  && shred_type!=FD_SHRED_TYPE_MERKLE_DATA ) )
      return -FD_SHRED_EINVAL;

    /* Ensure entry fits next shred */
    if( FD_UNLIKELY( shredder->bufsz < shred->data.size ) )
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
