#include <stdint.h>
#include "../../third_party/s2n-bignum/include/s2n-bignum.h"
#include "../../util/sanitize/fd_msan.h"

#ifndef __ADX__
#define edwards25519_scalarmulbase   edwards25519_scalarmulbase_alt
#define edwards25519_scalarmuldouble edwards25519_scalarmuldouble_alt
#endif

/* s2n-bignum implementation of the Ed25519 scalar multiplications. */

/* fd_ed25519_scalar_mul_base_tobytes writes the RFC 8032 encoding of
   [n]B to out.  n can be a secret. */
static inline void FD_FN_SENSITIVE
fd_ed25519_scalar_mul_base_tobytes( uchar       out[ 32 ],
                                    uchar const n[ 32 ] ) {
  ulong s[ 4 ], res[ 8 ];
  memcpy( s, n, 32UL );
  edwards25519_scalarmulbase( res, s );
  fd_msan_unpoison( res, 64UL );
  memcpy( out, res+4, 32UL );
  out[31] |= (uchar)( ( res[0] & 1UL )<<7 );
  fd_memzero_explicit( s, 32UL );
}

/* fd_ed25519_affine_to_limbs writes the canonical (x,y) of the
   affine point a as two 4x64-bit little-endian integers. */
static inline void
fd_ed25519_affine_to_limbs( ulong                      out[ 8 ],
                            fd_ed25519_point_t const * a ) {
  fd_f25519_t x[1], y[1], z[1], t[1];
  fd_ed25519_point_to( x, y, z, t, a );
  fd_f25519_tobytes( (uchar *)out,      x );
  fd_f25519_tobytes( (uchar *)out + 32, y );
}

/* fd_ed25519_verify_equation returns 1 iff [S]B == R + [k]A,
   computed as [k](-A) + [S]B == R.  A and R must be affine (Z==1).
   A is clobbered.  k and S are 32-byte little-endian scalars, S < L. */
static inline int
fd_ed25519_verify_equation( uchar const                k[ 32 ],
                            fd_ed25519_point_t *       A,
                            uchar const                S[ 32 ],
                            fd_ed25519_point_t const * R ) {
  ulong n[ 4 ], m[ 4 ], negA[ 8 ], expR[ 8 ], res[ 8 ];
  memcpy( n, k, 32UL );
  memcpy( m, S, 32UL );
  fd_ed25519_point_neg( A, A );
  fd_ed25519_affine_to_limbs( negA, A );
  fd_ed25519_affine_to_limbs( expR, R );
  edwards25519_scalarmuldouble( res, n, negA, m );
  fd_msan_unpoison( res, 64UL );
  return fd_memeq( res, expR, 64UL );
}
