#include "fd_bls12_381.h"

#include <blst.h>

int
fd_bls12_381_g1_add_syscall( uchar       rr[48],
                             uchar const pp[48],
                             uchar const qq[48] ) {
  blst_p1_affine pa[1], qa[1];
  blst_p1 p[1], r[1];
  if( FD_UNLIKELY( blst_p1_uncompress( pa, pp )!=BLST_SUCCESS ) ) {
    return -1;
  }
  if( FD_UNLIKELY( blst_p1_uncompress( qa, qq )!=BLST_SUCCESS ) ) {
    return -1;
  }
  blst_p1_from_affine( p, pa );
  blst_p1_add_or_double_affine( r, p, qa );
  blst_p1_compress( rr, r );
  return 0;
}

uchar * FD_FN_SENSITIVE
fd_bls12_381_public_from_private( uchar       public_key [ 96 ],
                                  uchar const private_key[ 32 ] ) {
  blst_scalar secret[1];
  blst_p1 public[1];

  blst_scalar_from_lendian( secret, private_key );
  blst_sk_to_pk_in_g1( public, secret );
  blst_p1_serialize( public_key, public );

  fd_memset_explicit( secret, 0, sizeof(blst_scalar) );
  return public_key;
}

uchar * FD_FN_SENSITIVE
fd_bls12_381_sign( uchar         sig[ 192 ],
                   uchar const   msg[], /* msg_sz */
                   ulong         msg_sz,
                   uchar const   public_key[ 96 ],
                   uchar const   private_key[ 32 ] ) {
  (void)public_key;
  blst_scalar secret[1];
  blst_p2 msg_hash[1];

  blst_scalar_from_lendian( secret, private_key );
  blst_hash_to_g2( msg_hash, msg, msg_sz, NULL, 0, NULL, 0 );
  blst_sign_pk2_in_g1( sig, NULL, msg_hash, secret );

  fd_memset_explicit( secret, 0, sizeof(blst_scalar) );
  return sig;
}

int
fd_bls12_381_verify( uchar const   msg[], /* msg_sz */
                     ulong         msg_sz,
                     uchar const   sig[ 192 ],
                     uchar const   public_key[ 96 ] ) {
  blst_p1_affine point_pk[1];
  blst_p2_affine point_sig[1];
  int hash_or_encode = 1; /* hash */

  if( FD_UNLIKELY( blst_p1_deserialize( point_pk, public_key )!=BLST_SUCCESS ) ) {
    return -1;
  }
  if( FD_UNLIKELY( blst_p2_deserialize( point_sig, sig )!=BLST_SUCCESS ) ) {
    return -1;
  }

  if( FD_LIKELY( blst_core_verify_pk_in_g1(
    point_pk, point_sig, hash_or_encode, msg, msg_sz, NULL, 0, NULL, 0
  )==BLST_SUCCESS ) ) {
    return 0;
  }
  return -1;
}
