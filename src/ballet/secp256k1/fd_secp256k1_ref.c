/* Portable secp256k1 backend (no s2n-bignum).  Included by
   fd_secp256k1_private.h when FD_HAS_S2NBIGNUM is unset.  Provides the
   scalar and field primitives that fd_secp256k1_point.c and
   fd_secp256k1.c build on, with the same semantics as
   fd_secp256k1_s2n.c.  Arithmetic is fiat-crypto generated Montgomery
   arithmetic; inversions are Fermat exponentiations.  Only public data
   flows through this code (public key recovery). */

/* fiat-crypto's generated cmovznz casts a signed char mask to uint64_t */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-conversion"
#include "../../third_party/fiat-crypto/secp256k1_montgomery_64.c"
#include "../../third_party/fiat-crypto/secp256k1_montgomery_scalar_64.c"
#pragma GCC diagnostic pop
#include "../pcurves/fd_pcurve_ref_util.h"

/* p-2, exponent for field inversion */
static const ulong fd_secp256k1_const_p_m2[4] = {
  0xfffffffefffffc2dUL, 0xffffffffffffffffUL, 0xffffffffffffffffUL, 0xffffffffffffffffUL,
};

/* n-2, exponent for scalar inversion */
static const ulong fd_secp256k1_const_n_m2[4] = {
  0xbfd25e8cd036413fUL, 0xbaaedce6af48a03bUL, 0xfffffffffffffffeUL, 0xffffffffffffffffUL,
};

FD_PCURVE_REF_DEFINE_POW( fd_secp256k1_fp_pow_limbs, 4,
                          fiat_secp256k1_montgomery_mul,
                          fiat_secp256k1_montgomery_square,
                          fiat_secp256k1_montgomery_set_one )
FD_PCURVE_REF_DEFINE_POW( fd_secp256k1_scalar_pow_limbs, 4,
                          fiat_secp256k1_montgomery_scalar_mul,
                          fiat_secp256k1_montgomery_scalar_square,
                          fiat_secp256k1_montgomery_scalar_set_one )

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

/* r = a mod n, where a < 2^256 < 2n. NOT Montgomery. */
static inline fd_secp256k1_scalar_t *
fd_secp256k1_scalar_reduce( fd_secp256k1_scalar_t *       r,
                            fd_secp256k1_scalar_t const * a ) {
  fd_pcurve_ref_reduce_once( r->limbs, a->limbs, fd_secp256k1_const_n->limbs, 4UL );
  return r;
}

/* r = 1 / a
   Operates on scalars NOT in the montgomery domain.
   a MUST not be 0. */
static inline fd_secp256k1_scalar_t *
fd_secp256k1_scalar_invert( fd_secp256k1_scalar_t *       r,
                            fd_secp256k1_scalar_t const * a ) {
  ulong t[ 4 ];
  fiat_secp256k1_montgomery_scalar_to_montgomery( t, a->limbs );
  fd_secp256k1_scalar_pow_limbs( t, t, fd_secp256k1_const_n_m2 );
  fiat_secp256k1_montgomery_scalar_from_montgomery( r->limbs, t );
  return r;
}

/* Montgomery domain multiplication. */
static inline fd_secp256k1_scalar_t *
fd_secp256k1_scalar_mul( fd_secp256k1_scalar_t *       restrict r,
                         fd_secp256k1_scalar_t const * restrict a,
                         fd_secp256k1_scalar_t const * restrict b ) {
  fiat_secp256k1_montgomery_scalar_mul( r->limbs, a->limbs, b->limbs );
  return r;
}

/* r = -a.  Domain agnostic (negation commutes with the Montgomery
   map). */
static inline fd_secp256k1_scalar_t *
fd_secp256k1_scalar_negate( fd_secp256k1_scalar_t *       r,
                            fd_secp256k1_scalar_t const * a ) {
  fiat_secp256k1_montgomery_scalar_opp( r->limbs, a->limbs );
  return r;
}

static inline fd_secp256k1_scalar_t *
fd_secp256k1_scalar_tomont( fd_secp256k1_scalar_t *       r,
                            fd_secp256k1_scalar_t const * a ) {
  fiat_secp256k1_montgomery_scalar_to_montgomery( r->limbs, a->limbs );
  return r;
}

static inline fd_secp256k1_scalar_t *
fd_secp256k1_scalar_demont( fd_secp256k1_scalar_t *       r,
                            fd_secp256k1_scalar_t const * a ) {
  fiat_secp256k1_montgomery_scalar_from_montgomery( r->limbs, a->limbs );
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
  fiat_secp256k1_montgomery_add( r->limbs, a->limbs, b->limbs );
  return r;
}

/* r = a - b */
static inline fd_secp256k1_fp_t *
fd_secp256k1_fp_sub( fd_secp256k1_fp_t *       r,
                     fd_secp256k1_fp_t const * a,
                     fd_secp256k1_fp_t const * b ) {
  fiat_secp256k1_montgomery_sub( r->limbs, a->limbs, b->limbs );
  return r;
}

/* r = 2 * a */
static inline fd_secp256k1_fp_t *
fd_secp256k1_fp_dbl( fd_secp256k1_fp_t *       r,
                     fd_secp256k1_fp_t const * a ) {
  fiat_secp256k1_montgomery_add( r->limbs, a->limbs, a->limbs );
  return r;
}

/* r = 3 * a */
static inline fd_secp256k1_fp_t *
fd_secp256k1_fp_triple( fd_secp256k1_fp_t *       r,
                        fd_secp256k1_fp_t const * a ) {
  ulong t[ 4 ];
  fiat_secp256k1_montgomery_add( t, a->limbs, a->limbs );
  fiat_secp256k1_montgomery_add( r->limbs, t, a->limbs );
  return r;
}

/* r = a * b */
static inline fd_secp256k1_fp_t *
fd_secp256k1_fp_mul( fd_secp256k1_fp_t *       r,
                     fd_secp256k1_fp_t const * a,
                     fd_secp256k1_fp_t const * b ) {
  fiat_secp256k1_montgomery_mul( r->limbs, a->limbs, b->limbs );
  return r;
}

/* r = a^2 */
static inline fd_secp256k1_fp_t *
fd_secp256k1_fp_sqr( fd_secp256k1_fp_t *       r,
                     fd_secp256k1_fp_t const * a ) {
  fiat_secp256k1_montgomery_square( r->limbs, a->limbs );
  return r;
}

/* r = -a */
static inline fd_secp256k1_fp_t *
fd_secp256k1_fp_negate( fd_secp256k1_fp_t *       r,
                        fd_secp256k1_fp_t const * a ) {
  fiat_secp256k1_montgomery_opp( r->limbs, a->limbs );
  return r;
}

static inline int
fd_secp256k1_fp_is_odd( fd_secp256k1_fp_t const *r ) {
  ulong scratch[ 4 ];
  fiat_secp256k1_montgomery_from_montgomery( scratch, r->limbs );
  return scratch[ 0 ] & 1;
}

/* r = 1 / a, Montgomery domain in and out.
   a MUST not be 0. */
static inline fd_secp256k1_fp_t *
fd_secp256k1_fp_invert( fd_secp256k1_fp_t *       r,
                        fd_secp256k1_fp_t const * a ) {
  fd_secp256k1_fp_pow_limbs( r->limbs, a->limbs, fd_secp256k1_const_p_m2 );
  return r;
}

/* r = a * R, i.e. converts a plain residue into the Montgomery domain. */
static inline fd_secp256k1_fp_t *
fd_secp256k1_fp_tomont( fd_secp256k1_fp_t *       r,
                        fd_secp256k1_fp_t const * a ) {
  fiat_secp256k1_montgomery_to_montgomery( r->limbs, a->limbs );
  return r;
}

static inline uchar *
fd_secp256k1_fp_tobytes( uchar                    r[ 32 ],
                         fd_secp256k1_fp_t const *a ) {
  fd_secp256k1_fp_t swapped[1];
  fiat_secp256k1_montgomery_from_montgomery( swapped->limbs, a->limbs );
  fd_uint256_bswap( swapped, swapped );
  memcpy( r, swapped->buf, 32 );
  return r;
}
