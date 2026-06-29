#include "fd_x25519.h"
#include "fd_f25519.h"

/*
 * Constant time primitives
 */

static inline int FD_FN_SENSITIVE
fd_x25519_is_zero_const_time( uchar const point[ 32 ] ) {
  //TODO: this is generally done by (x)or-ing the limbs, see also RFC 7748, page 13.
  int is_zero = 1;
  for( ulong i=0UL; i<32UL; i++ ) {
    is_zero &= ( !point[ i ] );
  }
  return is_zero;
}

#ifdef FD_HAS_S2NBIGNUM
#include "fd_x25519_s2n.c"
#else

static inline void FD_FN_SENSITIVE
fd_x25519_montgomery_ladder( fd_f25519_t *       x2,
                             fd_f25519_t *       z2,
                             fd_f25519_t const * x1,
                             uchar const *       secret_scalar ) {
  /* memory areas that will contain (partial) secrets and will be cleared at the end */
  fd_f25519_t secret_tmp_f[4];
  int swap = 0;
  int b = 0;

  /* human-readable variables */
  fd_f25519_t * x3   = &secret_tmp_f[0];
  fd_f25519_t * z3   = &secret_tmp_f[1];
  fd_f25519_t * tmp0 = &secret_tmp_f[2];
  fd_f25519_t * tmp1 = &secret_tmp_f[3];

  fd_f25519_set( x2, fd_f25519_one );
  fd_f25519_set( z2, fd_f25519_zero );

  /* use fd_f25519_add to reduce x1 mod p. this is required (we have a test). */
  fd_f25519_add( x3, fd_f25519_zero, x1 );
  fd_f25519_set( z3, fd_f25519_one );

  for( long pos=254UL; pos>=0; pos-- ) {
    b = (secret_scalar[ pos / 8L ] >> ( pos & 7L )) & 1;
    swap ^= b;
    fd_f25519_swap_if( x2, x3, swap );
    fd_f25519_swap_if( z2, z3, swap );
    swap = b;

    fd_f25519_sub_nr( tmp0, x3,   z3   );
    fd_f25519_sub_nr( tmp1, x2,   z2   );
    fd_f25519_add_nr( x2,   x2,   z2   );
    fd_f25519_add_nr( z2,   x3,   z3   );

    fd_f25519_mul2( z3,   tmp0, x2,
                    z2,   z2,   tmp1 );
    fd_f25519_sqr2( tmp0, tmp1,
                    tmp1, x2         );
    fd_f25519_add_nr( x3,   z3,   z2 );
    fd_f25519_sub_nr( z2,   z3,   z2 );
    fd_f25519_mul(  x2,   tmp1, tmp0 );
    fd_f25519_sqr(  z2,   z2         );
    fd_f25519_sub_nr( tmp1, tmp1, tmp0 );

    fd_f25519_mul_121666( z3, tmp1 );

    fd_f25519_add_nr( tmp0, tmp0, z3   );
    fd_f25519_sqr ( x3,   x3         );
    fd_f25519_mul2( z3,   x1,   z2,
                    z2,   tmp1, tmp0 );
  }

  fd_f25519_swap_if( x2, x3, swap );
  fd_f25519_swap_if( z2, z3, swap );

  /* Sanitize */

  fd_memzero_explicit( secret_tmp_f, sizeof(secret_tmp_f) );
  fd_memzero_explicit( &b, sizeof(int) );
  fd_memzero_explicit( &swap, sizeof(int) );
}

/*
 * X25519 Protocol
 */

static inline void FD_FN_SENSITIVE
fd_x25519_scalar_mul_const_time( uchar               out[ 32 ],
                                 uchar const *       secret_scalar,
                                 fd_f25519_t const * point_x ) {
  fd_f25519_t x2[1], z2[1];

  fd_x25519_montgomery_ladder( x2, z2, point_x, secret_scalar );

  fd_f25519_inv( z2, z2 );
  fd_f25519_mul( x2, x2, z2 );

  fd_f25519_tobytes( out, x2 );
}

static const uchar fd_x25519_basepoint[ 32 ] = { 9 };

uchar * FD_FN_SENSITIVE
fd_x25519_public( uchar       self_public_key [ 32 ],
                  uchar const self_private_key[ 32 ] ) {
  /* IETF RFC 7748 Section 4.1 (page 3) */
  return fd_x25519_exchange( self_public_key, self_private_key, fd_x25519_basepoint );
}

uchar * FD_FN_SENSITIVE
fd_x25519_exchange( uchar       shared_secret   [ 32 ],
                    uchar const self_private_key[ 32 ],
                    uchar const peer_public_key [ 32 ] ) {

  /* Memory areas that will contain secrets */
  uchar secret_scalar[ 32UL ];

  /* Public local variables */
  fd_f25519_t peer_public_key_point_u[1];

  //  RFC 7748 - Elliptic Curves for Security
  //
  //  5. The X25519 and X448 Functions
  //
  //  The "X25519" and "X448" functions perform scalar multiplication on
  //  the Montgomery form of the above curves.  (This is used when
  //  implementing Diffie-Hellman.)  The functions take a scalar and a
  //  u-coordinate as inputs and produce a u-coordinate as output.
  //  Although the functions work internally with integers, the inputs and
  //  outputs are 32-byte strings (for X25519) or 56-byte strings (for
  //  X448) and this specification defines their encoding.

  //  The u-coordinates are elements of the underlying field GF(2^255 - 19)
  //  or GF(2^448 - 2^224 - 1) and are encoded as an array of bytes, u, in
  //  little-endian order such that u[0] + 256*u[1] + 256^2*u[2] + ... +
  //  256^(n-1)*u[n-1] is congruent to the value modulo p and u[n-1] is
  //  minimal.  When receiving such an array, implementations of X25519
  //  (but not X448) MUST mask the most significant bit in the final byte.
  //  This is done to preserve compatibility with point formats that
  //  reserve the sign bit for use in other protocols and to increase
  //  resistance to implementation fingerprinting.

  //  Implementations MUST accept non-canonical values and process them as
  //  if they had been reduced modulo the field prime.  The non-canonical
  //  values are 2^255 - 19 through 2^255 - 1 for X25519 and 2^448 - 2^224
  //  - 1 through 2^448 - 1 for X448.

  /* From the text above:
     1. When receiving such an array, implementations of X25519 [...]
        MUST mask the most significant bit in the final byte
        >> this is done by fd_f25519_frombytes
     2. Implementations MUST accept non-canonical values
        >> no extra check needed */
  fd_f25519_frombytes( peer_public_key_point_u, peer_public_key );

  //  Scalars are assumed to be randomly generated bytes.  For X25519, in
  //  order to decode 32 random bytes as an integer scalar, set the three
  //  least significant bits of the first byte and the most significant bit
  //  of the last to zero, set the second most significant bit of the last
  //  byte to 1 and, finally, decode as little-endian.  This means that the
  //  resulting integer is of the form 2^254 plus eight times a value
  //  between 0 and 2^251 - 1 (inclusive).  Likewise, for X448, set the two
  //  least significant bits of the first byte to 0, and the most
  //  significant bit of the last byte to 1.  This means that the resulting
  //  integer is of the form 2^447 plus four times a value between 0 and
  //  2^445 - 1 (inclusive).

  /* decodeScalar25519
     note: e need to copy the private key, because we need to sanitize it. */
  memcpy( secret_scalar, self_private_key, 32UL );
  secret_scalar[ 0] &= (uchar)0xF8;
  secret_scalar[31] &= (uchar)0x7F;
  secret_scalar[31] |= (uchar)0x40;

  fd_x25519_scalar_mul_const_time( shared_secret, secret_scalar, peer_public_key_point_u );

  /* Sanitize */
  fd_memzero_explicit( secret_scalar, 32UL );

  /* Reject low order points */
  if( FD_UNLIKELY( fd_x25519_is_zero_const_time( shared_secret ) ) ) {
    return NULL;
  }

  return shared_secret;
}

#endif /* FD_HAS_S2NBIGNUM */
