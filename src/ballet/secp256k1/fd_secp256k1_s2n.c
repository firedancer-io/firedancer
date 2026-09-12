#include <stdint.h>
#include "../../third_party/s2n-bignum/include/s2n-bignum.h"
#include "../../util/sanitize/fd_msan.h"

/* On CPUs without ADX (mulx/adcx/adox), redirect the ADX-optimized
   s2n-bignum symbols to their _alt equivalents, which use only base
   x86-64 instructions and are functionally identical. */
#ifndef __ADX__
#define bignum_montmul_p256k1  bignum_montmul_p256k1_alt
#define bignum_montsqr_p256k1  bignum_montsqr_p256k1_alt
#define bignum_tomont_p256k1   bignum_tomont_p256k1_alt
#define bignum_triple_p256k1   bignum_triple_p256k1_alt
#endif

/* Scalars */

static inline int
fd_secp256k1_scalar_is_zero( fd_secp256k1_scalar_t const *r ) {
  return fd_uint256_eq( r, fd_secp256k1_const_zero );
}

/* Returns the scalar in NON Montgomery form. */
static inline fd_secp256k1_scalar_t *
fd_secp256k1_scalar_frombytes( fd_secp256k1_scalar_t * r,
                               uchar const             input[ 32 ] ) {
  memcpy( r, input, 32 );
  fd_uint256_bswap( r, r );

  /*
    The verifier SHALL check that 0 < r' < q and 0 < s' < q.
    The r' element is parsed as a scalar, and checked against r' < n.
    Later it is re-used as fp_t, however n < p, so we do not need to
    perform any additional checks after this.
  */
  if( FD_UNLIKELY( fd_uint256_cmp( r, fd_secp256k1_const_n ) >= 0 ) ) {
    return NULL;
  }
  if( FD_UNLIKELY( fd_secp256k1_scalar_is_zero( r ) ) ) {
    return NULL;
  }
  return r;
}

/* r = 1 / a
   Operates on scalars NOT in the montgomery domain.
   a MUST not be 0. */
fd_secp256k1_scalar_t *
fd_secp256k1_scalar_invert( fd_secp256k1_scalar_t *       r,
                            fd_secp256k1_scalar_t const * a ) {
  ulong t[ 12 ];
  bignum_modinv( 4, r->limbs, (ulong *)a->limbs, (ulong *)fd_secp256k1_const_n[ 0 ].limbs, t );
  fd_msan_unpoison( r->limbs, 32UL );
  return r;
}

/* None of the arguments may alias. */
static inline fd_secp256k1_scalar_t *
fd_secp256k1_scalar_mul( fd_secp256k1_scalar_t *       restrict r,
                         fd_secp256k1_scalar_t const * restrict a,
                         fd_secp256k1_scalar_t const * restrict b ) {
  bignum_montmul( 4, r->limbs, (ulong *)a->limbs, (ulong *)b->limbs, (ulong *)fd_secp256k1_const_n[0].limbs );
  fd_msan_unpoison( r->limbs, 32UL );
  return r;
}

/* r = -a */
static inline fd_secp256k1_scalar_t *
fd_secp256k1_scalar_negate( fd_secp256k1_scalar_t *       r,
                            fd_secp256k1_scalar_t const * a ) {
  /* We cannot use bignum_modsub() as it requires a < n /\ b < n.

     The best way to implement it using the current API is to use
     bignum_sub(n, a), getting a result bounded within [0, n+1). Then
     we perform a second reduction from [0, n+1) to [0, n) with
     bignum_mod_n256k1_4(). */

  /* t \in [0, n + 1). There is no carry-out, as a < n. */
  ulong t[4];
  bignum_sub( 4, t, 4, (ulong *)fd_secp256k1_const_n[ 0 ].limbs, 4, (ulong *)a->limbs );
  fd_msan_unpoison( t, 32UL );
  bignum_mod_n256k1_4( r->limbs, t );
  fd_msan_unpoison( r->limbs, 32UL );
  return r;
}

static inline fd_secp256k1_scalar_t *
fd_secp256k1_scalar_tomont( fd_secp256k1_scalar_t *       r,
                            fd_secp256k1_scalar_t const * a ) {
  /* bignum_montmul has an undocumented restriction
     that the input and outputs may not alias. */
  ulong t[4];
  memcpy( t, a->limbs, 32 );
  bignum_montmul( 4, r->limbs, t, (ulong *)fd_secp256k1_const_scalar_rr_mont, (ulong *)fd_secp256k1_const_n[ 0 ].limbs );
  fd_msan_unpoison( r->limbs, 32UL );
  return r;
}

static inline fd_secp256k1_scalar_t *
fd_secp256k1_scalar_demont( fd_secp256k1_scalar_t *       r,
                            fd_secp256k1_scalar_t const * a ) {
  bignum_demont( 4, r->limbs, (ulong *)a->limbs, (ulong *)fd_secp256k1_const_n[ 0 ].limbs );
  fd_msan_unpoison( r->limbs, 32UL );
  return r;
}

/* r = a mod n, where a < 2^256 < 2n. NOT Montgomery. */
static inline fd_secp256k1_scalar_t *
fd_secp256k1_scalar_reduce( fd_secp256k1_scalar_t *       r,
                            fd_secp256k1_scalar_t const * a ) {
  bignum_mod_n256k1_4( r->limbs, (ulong *)a->limbs );
  fd_msan_unpoison( r->limbs, 32UL );
  return r;
}

/* Field */

static inline fd_secp256k1_fp_t *
fd_secp256k1_fp_set( fd_secp256k1_fp_t *       r,
                     fd_secp256k1_fp_t const * a ) {
  r->limbs[ 0 ] = a->limbs[ 0 ];
  r->limbs[ 1 ] = a->limbs[ 1 ];
  r->limbs[ 2 ] = a->limbs[ 2 ];
  r->limbs[ 3 ] = a->limbs[ 3 ];
  return r;
}

/* r = (a == b) */
static inline int
fd_secp256k1_fp_eq( fd_secp256k1_fp_t const * a,
                    fd_secp256k1_fp_t const * b ) {
  return fd_uint256_eq( a, b );
}

/* r = a + b */
static inline fd_secp256k1_fp_t *
fd_secp256k1_fp_add( fd_secp256k1_fp_t *       r,
                     fd_secp256k1_fp_t const * a,
                     fd_secp256k1_fp_t const * b ) {
  bignum_add_p256k1( r->limbs, (ulong *)a->limbs, (ulong *)b->limbs );
  fd_msan_unpoison( r->limbs, 32UL );
  return r;
}

/* r = a - b */
static inline fd_secp256k1_fp_t *
fd_secp256k1_fp_sub( fd_secp256k1_fp_t *       r,
                     fd_secp256k1_fp_t const * a,
                     fd_secp256k1_fp_t const * b ) {
  bignum_sub_p256k1( r->limbs, (ulong *)a->limbs, (ulong *)b->limbs );
  fd_msan_unpoison( r->limbs, 32UL );
  return r;
}

/* r = 2 * a */
static inline fd_secp256k1_fp_t *
fd_secp256k1_fp_dbl( fd_secp256k1_fp_t *       r,
                     fd_secp256k1_fp_t const * a ) {
  bignum_double_p256k1( r->limbs, (ulong *)a->limbs );
  fd_msan_unpoison( r->limbs, 32UL );
  return r;
}

/* r = a * b */
static inline fd_secp256k1_fp_t *
fd_secp256k1_fp_mul( fd_secp256k1_fp_t *       r,
                     fd_secp256k1_fp_t const * a,
                     fd_secp256k1_fp_t const * b ) {
  bignum_montmul_p256k1( r->limbs, (ulong *)a->limbs, (ulong *)b->limbs );
  fd_msan_unpoison( r->limbs, 32UL );
  return r;
}

/* r = a^2 */
static inline fd_secp256k1_fp_t *
fd_secp256k1_fp_sqr( fd_secp256k1_fp_t *       r,
                     fd_secp256k1_fp_t const * a ) {
  bignum_montsqr_p256k1( r->limbs, (ulong *)a->limbs );
  fd_msan_unpoison( r->limbs, 32UL );
  return r;
}

/* r = -a */
static inline fd_secp256k1_fp_t *
fd_secp256k1_fp_negate( fd_secp256k1_fp_t *       r,
                        fd_secp256k1_fp_t const * a ) {
  bignum_neg_p256k1( r->limbs, (ulong *)a->limbs );
  fd_msan_unpoison( r->limbs, 32UL );
  return r;
}

static inline int
fd_secp256k1_fp_is_odd( fd_secp256k1_fp_t const *r ) {
  fd_secp256k1_fp_t scratch[1];
  bignum_demont_p256k1( scratch->limbs, (ulong *)r->limbs );
  fd_msan_unpoison( scratch->limbs, 32UL );
  return scratch->limbs[ 0 ] & 1;
}

/* r = 1 / a
   a MUST not be 0. */
static inline fd_secp256k1_fp_t *
fd_secp256k1_fp_invert( fd_secp256k1_fp_t *       r,
                        fd_secp256k1_fp_t const * a ) {
  fd_secp256k1_fp_t ad[1];
  bignum_demont_p256k1( ad->limbs, (ulong *)a->limbs );
  fd_msan_unpoison( ad->limbs, 32UL );
  ulong t[ 12 ];
  bignum_modinv( 4, r->limbs, (ulong *)ad->limbs, (ulong *)fd_secp256k1_const_p[0].limbs, t );
  fd_msan_unpoison( r->limbs, 32UL );
  bignum_tomont_p256k1( r->limbs, (ulong *)r->limbs );
  fd_msan_unpoison( r->limbs, 32UL );
  return r;
}

static inline uchar *
fd_secp256k1_fp_tobytes( uchar                    r[ 32 ],
                         fd_secp256k1_fp_t const *a ) {
  fd_secp256k1_fp_t swapped[1];
  bignum_demont_p256k1( swapped->limbs, (ulong *)a->limbs );
  fd_msan_unpoison( swapped->limbs, 32UL );
  fd_uint256_bswap( swapped, swapped );
  memcpy( r, swapped->buf, 32 );
  return r;
}

/* r = 3 * a */
static inline fd_secp256k1_fp_t *
fd_secp256k1_fp_triple( fd_secp256k1_fp_t *       r,
                        fd_secp256k1_fp_t const * a ) {
  bignum_triple_p256k1( r->limbs, (ulong *)a->limbs );
  fd_msan_unpoison( r->limbs, 32UL );
  return r;
}

/* r = a * R, i.e. converts a plain residue into the Montgomery domain. */
static inline fd_secp256k1_fp_t *
fd_secp256k1_fp_tomont( fd_secp256k1_fp_t *       r,
                        fd_secp256k1_fp_t const * a ) {
  bignum_tomont_p256k1( r->limbs, (ulong *)a->limbs );
  fd_msan_unpoison( r->limbs, 32UL );
  return r;
}
