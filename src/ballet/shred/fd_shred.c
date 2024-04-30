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

  /* There are five sections of a shred that can contribute to the size:
     header, payload, zero-padding, Merkle root of previous erasure batch and Merkle proof.
     Some of these may have 0 size in certain cases.  sz is the sum of all 5, while for
     data shreds, shred->data.size == header+payload. */
  ulong header_sz       = fd_shred_header_sz( variant ); /* between 88 and 89 bytes */
  ulong merkle_proof_sz = fd_shred_merkle_sz( shred->variant ); /* between 0 and 300 bytes */
  ulong zero_padding_sz;
  ulong payload_sz;

  /* only present for chained merkle shreds */
  ulong previous_merkle_root_sz = fd_ulong_if(
   (type == FD_SHRED_TYPE_MERKLE_DATA_CHAINED) | (type == FD_SHRED_TYPE_MERKLE_CODE_CHAINED) |
     (type == FD_SHRED_TYPE_MERKLE_DATA_CHAINED_RESIGNED) | (type == FD_SHRED_TYPE_MERKLE_CODE_CHAINED_RESIGNED)
     , FD_SHRED_MERKLE_ROOT_SZ, 0UL );

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
    uchar is_legacy_data_shred = type & 0x20;
    ulong effective_sz = fd_ulong_if( is_legacy_data_shred, sz, FD_SHRED_MIN_SZ );
    if( FD_UNLIKELY( effective_sz < header_sz+merkle_proof_sz+payload_sz+previous_merkle_root_sz ) ) return NULL;
    zero_padding_sz = effective_sz - header_sz - merkle_proof_sz - payload_sz - previous_merkle_root_sz;
  }
  else if( FD_LIKELY( type & FD_SHRED_TYPEMASK_CODE ) ) {
    zero_padding_sz = 0UL;
    /* Payload size is not specified directly, but the whole shred must
       be FD_SHRED_MAX_SZ. */
    if( FD_UNLIKELY( header_sz+previous_merkle_root_sz+merkle_proof_sz+zero_padding_sz > FD_SHRED_MAX_SZ ) ) return NULL;
    payload_sz      = FD_SHRED_MAX_SZ - header_sz - merkle_proof_sz - zero_padding_sz - previous_merkle_root_sz;
  }
  else return NULL;

  if( FD_UNLIKELY( sz < header_sz + payload_sz + zero_padding_sz + merkle_proof_sz + previous_merkle_root_sz ) ) return NULL;

  return shred;
}
