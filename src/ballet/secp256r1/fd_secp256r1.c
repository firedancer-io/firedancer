#include "fd_secp256r1_private.h"

int
fd_secp256r1_verify( uchar const   msg[], /* msg_sz */
                     ulong         msg_sz,
                     uchar const   sig[ 64 ],
                     uchar const   public_key[ 33 ],
                     fd_sha256_t * sha ) {
  fd_secp256r1_scalar_t r[1], s[1], u1[1], u2[1];
  fd_secp256r1_point_t pub[1], Rcmp[1];

  /* Deserialize signature.
     Note: we enforce 0 < r < n, 0 < s <= (n-1)/2.
     The condition on s is required to avoid signature malleability. */
  if( FD_UNLIKELY( !fd_secp256r1_scalar_frombytes( r, sig ) ) ) {
    return FD_SECP256R1_FAILURE;
  }
  if( FD_UNLIKELY( !fd_secp256r1_scalar_frombytes_positive( s, sig+32 ) ) ) {
    return FD_SECP256R1_FAILURE;
  }
  if( FD_UNLIKELY( fd_secp256r1_scalar_is_zero( r ) || fd_secp256r1_scalar_is_zero( s ) ) ) {
    return FD_SECP256R1_FAILURE;
  }

  /* Deserialize public key. */
  if( FD_UNLIKELY( !fd_secp256r1_point_frombytes( pub, public_key ) ) ) {
    return FD_SECP256R1_FAILURE;
  }

  /* Hash message. */
  uchar hash[ FD_SHA256_HASH_SZ ];
  fd_sha256_fini( fd_sha256_append( fd_sha256_init( sha ), msg, msg_sz ), hash );
  fd_secp256r1_scalar_from_digest( u1, hash );

  /* ECDSA sig verify. */
  fd_secp256r1_scalar_inv( s, s );
  fd_secp256r1_scalar_mul( u1, u1, s );
  fd_secp256r1_scalar_mul( u2, r, s );
  fd_secp256r1_double_scalar_mul_base( Rcmp, u1, pub, u2 );
  if( FD_LIKELY( fd_secp256r1_point_eq_x( Rcmp, r ) ) ) {
    return FD_SECP256R1_SUCCESS;
  }

  return FD_SECP256R1_FAILURE;
}
