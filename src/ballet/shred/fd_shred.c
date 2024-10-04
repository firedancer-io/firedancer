#include "fd_shred.h"

fd_shred_t const *
fd_shred_parse( uchar const * const buf,
                ulong         const sz ) {
  ulong total_shred_sz = sz;
  /* Initial bounds check */
  if( FD_UNLIKELY( total_shred_sz<fd_ulong_min( FD_SHRED_DATA_HEADER_SZ, FD_SHRED_CODE_HEADER_SZ ) ) ) return NULL;

  fd_shred_t const * shred = (fd_shred_t *)buf;

  /* Validate shred type.
     Safe to access because `variant` ends at 0x41, which is <= 0x58 */
  uchar variant = shred->variant;
  uchar type = fd_shred_type( variant );
  if( FD_UNLIKELY( (type!=FD_SHRED_TYPE_MERKLE_DATA) &
                   (type!=FD_SHRED_TYPE_MERKLE_CODE) &
                   (type!=FD_SHRED_TYPE_MERKLE_DATA_CHAINED) &
                   (type!=FD_SHRED_TYPE_MERKLE_CODE_CHAINED) &
                   (type!=FD_SHRED_TYPE_MERKLE_DATA_CHAINED_RESIGNED) &
                   (type!=FD_SHRED_TYPE_MERKLE_CODE_CHAINED_RESIGNED) &
                   (variant!=0xa5 /*FD_SHRED_TYPE_LEGACY_DATA*/ ) &
                   (variant!=0x5a /*FD_SHRED_TYPE_LEGACY_CODE*/ ) ) )
    return NULL;

  /* There are six sections of a shred that can contribute to the size:
     header, payload, zero-padding, Merkle root of previous erasure
     batch, Merkle proof, and retransmitter signature.
     Some of these may have 0 size in certain cases.  sz is the sum of
     all 5, while for data shreds, shred->data.size == header+payload.
     We'll call the last three section the trailer. */
  ulong header_sz       = fd_shred_header_sz( variant ); /* between 88 and 89 bytes */
  ulong trailer_sz      = fd_shred_merkle_sz( shred->variant )   /* between 0 and 300 bytes */
                           + fd_ulong_if( fd_shred_is_resigned( type ), FD_SHRED_SIGNATURE_SZ, 0UL ) /* 0 or 64 */
                           + fd_ulong_if( fd_shred_is_chained( type ),  FD_SHRED_MERKLE_ROOT_SZ, 0UL ); /* 0 or 32 */
  ulong zero_padding_sz;
  ulong payload_sz;

  if( FD_LIKELY( type & FD_SHRED_TYPEMASK_DATA ) ) {
    if( FD_UNLIKELY( shred->data.size<header_sz ) ) return NULL;
    payload_sz = (ulong)shred->data.size - header_sz; /* between 0 and USHORT_MAX */
    if( FD_UNLIKELY( (type!=FD_SHRED_TYPE_LEGACY_DATA) & (sz<FD_SHRED_MIN_SZ) ) ) return NULL;

    /* legacy data shreds might be shorter than the normal
       FD_SHRED_MIN_SZ, but they don't have Merkle proofs, so everything
       after the payload is zero-padding/ignored.  On the other hand,
       Merkle data shreds might have some zero-padding, but anything
       between [FD_SHRED_MIN_SZ, sz) is extra bytes after the shred
       (which we don't care about the contents of but also tolerate).
       The Merkle proof is not in bytes [sz-merkle_proof_sz, sz) but in
       [FD_SHRED_MIN_SZ-merkle_proof_sz, FD_SHRED_MIN_SZ).  From above,
       we know sz >= FD_SHRED_MIN_SZ in this case. */
    uchar is_legacy_data_shred = type==FD_SHRED_TYPE_LEGACY_DATA;
    ulong effective_sz = fd_ulong_if( is_legacy_data_shred, sz, FD_SHRED_MIN_SZ );
    if( FD_UNLIKELY( effective_sz < header_sz+payload_sz+trailer_sz ) ) return NULL;
    zero_padding_sz = effective_sz - header_sz - payload_sz - trailer_sz;
  }
  else if( FD_LIKELY( type & FD_SHRED_TYPEMASK_CODE ) ) {
    zero_padding_sz = 0UL;
    /* Payload size is not specified directly, but the whole shred must
       be FD_SHRED_MAX_SZ. */
    if( FD_UNLIKELY( header_sz+zero_padding_sz+trailer_sz > FD_SHRED_MAX_SZ ) ) return NULL;
    payload_sz      = FD_SHRED_MAX_SZ - header_sz - zero_padding_sz - trailer_sz;
  }
  else return NULL;

  if( FD_UNLIKELY( sz < header_sz + payload_sz + zero_padding_sz + trailer_sz ) ) return NULL;

  /* At this point we know all the fields exist, but we need to sanity
     check a few fields that would make a shred illegal. */
  if( FD_LIKELY( type & FD_SHRED_TYPEMASK_DATA ) ) {
    ulong parent_off = (ulong)shred->data.parent_off;
    ulong slot       = shred->slot;
    if( FD_UNLIKELY( (shred->data.flags&0xC0)==0x80                              ) ) return NULL;
    if( FD_UNLIKELY( parent_off>slot                                             ) ) return NULL;
    /* The property we want to enforce is
           slot==0 <=> parent_off==0 <=> slot==parent_off,
       where <=> means if and only if.  It's a strange expression
       though, because any two of the statements automatically imply the
       other one, so it's logically equivalent to:
            (slot==0 or parent_off==0)   <=> slot==parent_off
       We want the complement though, so that we can return NULL, and
       the complement of iff is xor. */
    if( FD_UNLIKELY( ((parent_off==0) | (slot==0UL)) ^ (slot==parent_off)        ) ) return NULL;
    if( FD_UNLIKELY( shred->idx<shred->fec_set_idx                               ) ) return NULL;
  } else {
    if( FD_UNLIKELY( shred->code.idx>=shred->code.code_cnt                       ) ) return NULL;
    if( FD_UNLIKELY( shred->code.idx> shred->idx                                 ) ) return NULL;
    if( FD_UNLIKELY( (shred->code.data_cnt==0)|(shred->code.code_cnt==0)         ) ) return NULL;
    if( FD_UNLIKELY( shred->code.code_cnt>256                                    ) ) return NULL;
    if( FD_UNLIKELY( (ulong)shred->code.data_cnt+(ulong)shred->code.code_cnt>256 ) ) return NULL; /* I don't see this check in Agave, but it seems necessary */
  }

  return shred;
}
