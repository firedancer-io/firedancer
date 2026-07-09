#include "fd_secp256k1_private.h"


/* Given the coordinate X and the odd-ness of the Y coordinate, recovers Y and
   returns the affine group element. Returns NULL if there is no valid pair. */
static inline fd_secp256k1_point_t *
fd_secp256k1_recovery_y( fd_secp256k1_point_t *r, fd_secp256k1_fp_t const *x, int odd ) {
  fd_secp256k1_fp_t x2[1], x3[1];

  /* x^3 + b */
  fd_secp256k1_fp_sqr( x2, x );
  fd_secp256k1_fp_mul( x3, x2, x );
  fd_secp256k1_fp_add( x3, x3, fd_secp256k1_const_b_mont );

  /* y^2 = x^3 + b <=> y = sqrt(x^3 + b) */
  if( FD_UNLIKELY( !fd_secp256k1_fp_sqrt( r->y, x3 ) ) ) {
    return NULL;
  }

  if( fd_secp256k1_fp_is_odd( r->y ) != odd ) {
    fd_secp256k1_fp_negate( r->y, r->y );
  }

  fd_secp256k1_fp_set( r->x, x );
  fd_secp256k1_fp_set( r->z, fd_secp256k1_const_one_mont );
  return r;
}

uchar *
fd_secp256k1_recover( uchar        public_key[64],
                      uchar const  msg_hash[32],
                      uchar const  sig[64],
                      int          recovery_id ) {
  if( FD_UNLIKELY( !( recovery_id>=0 && recovery_id<=3 ) ) ) {
    /* COV: the callers do the same check */
    return NULL;
  }

  fd_secp256k1_scalar_t s[1];
  fd_secp256k1_scalar_t rs[1];
  if( FD_UNLIKELY( !fd_secp256k1_scalar_frombytes( rs, &sig[  0 ] ) ) ) {
    return NULL;
  }
  if( FD_UNLIKELY( !fd_secp256k1_scalar_frombytes(  s, &sig[ 32 ] ) ) ) {
    return NULL;
  }

  fd_secp256k1_fp_t r[1];
  bignum_tomont_p256k1( r->limbs, rs->limbs );

  if( recovery_id & 2 ) {
    /* If rs >= p - n, return NULL. Otherwise, add the n to r.
       https://github.com/bitcoin-core/secp256k1/blob/v0.7.1/src/modules/recovery/main_impl.h#L104-L109 */
    if( FD_UNLIKELY( fd_uint256_cmp( rs, fd_secp256k1_const_p_minus_n ) >= 0 ) ) {
      return NULL;
    }
    /* Note that *only* r is incremented, rs is left unchanged. */
    fd_secp256k1_fp_add( r, r, fd_secp256k1_const_n_mont );
  }

  /* Recover the full public key group element. */
  fd_secp256k1_point_t a[1];
  if( FD_UNLIKELY( !fd_secp256k1_recovery_y( a, r, recovery_id & 1 ) ) ) {
    return NULL;
  }

  fd_uint256_t msg[1];
  memcpy( msg, msg_hash, 32 );
  fd_uint256_bswap( msg, msg );
  /* The message scalar is unconditionally reduced to the scalar field.
     https://github.com/bitcoin-core/secp256k1/blob/v0.7.1/src/scalar_4x64_impl.h#L151 */
  bignum_mod_n256k1_4( msg->limbs, (ulong *)msg->limbs );
  fd_secp256k1_scalar_tomont( msg, msg );

  fd_secp256k1_scalar_t rn[1], u1[1], u2[1];
  fd_secp256k1_point_t pubkey[1];

  /* We delay converting rs into montgomery domain since
     we may need to perform the comparison against p-n first. */
  fd_secp256k1_scalar_tomont( s, s );

  /* Unfortunately s2n-bignum has no API for performing
     in-montgomery inversion, so we invert and then convert. */
  fd_secp256k1_scalar_invert( rn, rs );
  fd_secp256k1_scalar_tomont( rn, rn );

  fd_secp256k1_scalar_mul   ( u1, rn, msg );
  fd_secp256k1_scalar_negate( u1, u1      );
  fd_secp256k1_scalar_mul   ( u2, rn, s   );

  fd_secp256k1_scalar_demont( u2, u2 );
  fd_secp256k1_scalar_demont( u1, u1 );
  fd_secp256k1_double_base_mul( pubkey, u1, a, u2 );

  /* If the computed pubkey is the identity point, we return NULL
     https://github.com/bitcoin-core/secp256k1/blob/v0.7.1/src/modules/recovery/main_impl.h#L120 */
  if( FD_UNLIKELY( fd_secp256k1_point_is_identity( pubkey ) ) ) {
    return NULL;
  }

  /* Serialize the public key into an uncompressed form.
     The output does not have the recovery_id. */
  fd_secp256k1_point_to_affine( pubkey, pubkey );
  fd_secp256k1_fp_tobytes( &public_key[  0 ], pubkey->x );
  fd_secp256k1_fp_tobytes( &public_key[ 32 ], pubkey->y );
  return public_key;
}
