#ifndef HEADER_fd_src_ballet_bn254_avx512_fd_bn254_fp52_g2_h
#define HEADER_fd_src_ballet_bn254_avx512_fd_bn254_fp52_g2_h

/* fd_bn254_fp52_g2.h provides G2 point operations for the BN254 twist
   curve using AVX-512 IFMA radix-2^52 Montgomery arithmetic.

   Points are in Jacobian coordinates (X:Y:Z) over Fp2 with the twist
   curve equation y^2 = x^3 + b' where b' = 3/(9+i).

   All Fp2 components are in radix-2^52 R=2^260 Montgomery form. */

#if FD_HAS_AVX512

#include "fd_bn254_fp52_fp12.h"    /* includes fp6->fp2; provides fp52_mul_scalar */
#include "../fd_bn254_internal.h"  /* for fd_bn254_fp_t, fd_bn254_fp2_t */
#include "../fd_bn254_scalar.h"    /* for fd_bn254_scalar_t */
#include "../fd_bn254_glv.h"       /* for GLV decomposition */
#include "../../bigint/fd_uint256.h"

FD_PROTOTYPES_BEGIN

/* fd_bn254_fp52_g2_t -- a G2 point in Jacobian coordinates over Fp2. */

struct fd_bn254_fp52_g2 {
  fd_bn254_fp52_fp2_t X, Y, Z;
};
typedef struct fd_bn254_fp52_g2 fd_bn254_fp52_g2_t;

/* fd_bn254_fp52_g2_is_zero returns 1 if p is the point at infinity. */

FD_FN_UNUSED static inline int
fd_bn254_fp52_g2_is_zero( fd_bn254_fp52_g2_t const * p ) {
  return fd_bn254_fp52_fp2_is_zero( &p->Z );
}

/* fd_bn254_fp52_g2_set copies p into r. */

FD_FN_UNUSED static inline fd_bn254_fp52_g2_t *
fd_bn254_fp52_g2_set( fd_bn254_fp52_g2_t *       r,
                      fd_bn254_fp52_g2_t const * p ) {
  fd_bn254_fp52_fp2_set( &r->X, &p->X );
  fd_bn254_fp52_fp2_set( &r->Y, &p->Y );
  fd_bn254_fp52_fp2_set( &r->Z, &p->Z );
  return r;
}

/* fd_bn254_fp52_g2_neg computes r = -p (negate Y). */

FD_FN_UNUSED static inline fd_bn254_fp52_g2_t *
fd_bn254_fp52_g2_neg( fd_bn254_fp52_g2_t *       r,
                      fd_bn254_fp52_g2_t const * p ) {
  fd_bn254_fp52_fp2_set( &r->X, &p->X );
  fd_bn254_fp52_fp2_neg( &r->Y, &p->Y );
  fd_bn254_fp52_fp2_set( &r->Z, &p->Z );
  return r;
}

/* fd_bn254_fp52_g2_set_zero sets r to the point at infinity. */

FD_FN_UNUSED static inline fd_bn254_fp52_g2_t *
fd_bn254_fp52_g2_set_zero( fd_bn254_fp52_g2_t * r ) {
  fd_bn254_fp52_fp2_set_zero( &r->Z );
  return r;
}

/* fd_bn254_fp52_g2_eq tests projective equality of two G2 points.
   Returns 1 if the affine representations are equal, 0 otherwise. */

FD_FN_UNUSED static inline int
fd_bn254_fp52_g2_eq( fd_bn254_fp52_g2_t const * p,
                     fd_bn254_fp52_g2_t const * q ) {
  if( fd_bn254_fp52_g2_is_zero( p ) ) {
    return fd_bn254_fp52_g2_is_zero( q );
  }
  if( fd_bn254_fp52_g2_is_zero( q ) ) {
    return 0;
  }

  fd_bn254_fp52_fp2_t pz2[1], qz2[1];
  fd_bn254_fp52_fp2_t l[1], rr[1];

  fd_bn254_fp52_fp2_sqr( pz2, &p->Z );
  fd_bn254_fp52_fp2_sqr( qz2, &q->Z );

  fd_bn254_fp52_fp2_mul( l,  &p->X, qz2 );
  fd_bn254_fp52_fp2_mul( rr, &q->X, pz2 );
  if( !fd_bn254_fp52_fp2_eq( l, rr ) ) {
    return 0;
  }

  fd_bn254_fp52_fp2_mul( l, &p->Y, qz2 );
  fd_bn254_fp52_fp2_mul( l, l, &q->Z );
  fd_bn254_fp52_fp2_mul( rr, &q->Y, pz2 );
  fd_bn254_fp52_fp2_mul( rr, rr, &p->Z );
  return fd_bn254_fp52_fp2_eq( l, rr );
}

/* fd_bn254_fp52_g2_to_affine converts from Jacobian to affine.
   Computes (X/Z^2, Y/Z^3) and sets Z=1. */

FD_FN_UNUSED static inline fd_bn254_fp52_g2_t *
fd_bn254_fp52_g2_to_affine( fd_bn254_fp52_g2_t *       r,
                            fd_bn254_fp52_g2_t const * p ) {
  if( FD_UNLIKELY( fd_bn254_fp52_g2_is_zero( p ) ) ) {
    return fd_bn254_fp52_g2_set( r, p );
  }

  /* Check if already affine */
  fd_bn254_fp52_fp2_t one[1];
  fd_bn254_fp52_fp2_set_one( one );
  if( fd_bn254_fp52_fp2_eq( &p->Z, one ) ) {
    return fd_bn254_fp52_g2_set( r, p );
  }

  fd_bn254_fp52_fp2_t iz[1], iz2[1];
  fd_bn254_fp52_fp2_inv( iz, &p->Z );
  fd_bn254_fp52_fp2_sqr( iz2, iz );

  /* X = X / Z^2, Y = Y / Z^3 */
  fd_bn254_fp52_fp2_mul( &r->X, &p->X, iz2 );
  fd_bn254_fp52_fp2_mul( &r->Y, &p->Y, iz2 );
  fd_bn254_fp52_fp2_mul( &r->Y, &r->Y, iz );
  fd_bn254_fp52_fp2_set_one( &r->Z );
  return r;
}

/* fd_bn254_fp52_g2_dbl computes r = 2*p.
   https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#doubling-dbl-2009-l
   Same formula as G1 but over Fp2. */

FD_FN_UNUSED static inline fd_bn254_fp52_g2_t *
fd_bn254_fp52_g2_dbl( fd_bn254_fp52_g2_t *       r,
                      fd_bn254_fp52_g2_t const * p ) {
  if( FD_UNLIKELY( fd_bn254_fp52_g2_is_zero( p ) ) ) {
    return fd_bn254_fp52_g2_set_zero( r );
  }

  fd_bn254_fp52_fp2_t a[1], b[1], c[1];
  fd_bn254_fp52_fp2_t d[1], e[1], f[1];

  /* A = X1^2,  B = Y1^2 (2 independent squarings) */
  fd_bn254_fp52_fp2_sqr2( a, &p->X, b, &p->Y );

  /* C = B^2 */
  fd_bn254_fp52_fp2_sqr( c, b );

  /* D = 4*X1*B */
  fd_bn254_fp52_fp2_mul( d, &p->X, b );
  fd_bn254_fp52_fp2_add( d, d, d );
  fd_bn254_fp52_fp2_add( d, d, d );

  /* E = 3*A */
  fd_bn254_fp52_fp2_add( e, a, a );
  fd_bn254_fp52_fp2_add( e, a, e );

  /* F = E^2 */
  fd_bn254_fp52_fp2_sqr( f, e );

  /* X3 = F - 2*D */
  fd_bn254_fp52_fp2_add( &r->X, d, d );
  fd_bn254_fp52_fp2_sub( &r->X, f, &r->X );

  /* Z3 = 2*Y1*Z1
     Compute before Y3 because p->Y may alias r->Y. */
  fd_bn254_fp52_fp2_mul( &r->Z, &p->Y, &p->Z );
  fd_bn254_fp52_fp2_add( &r->Z, &r->Z, &r->Z );

  /* Y3 = E*(D - X3) - 8*C */
  fd_bn254_fp52_fp2_sub( &r->Y, d, &r->X );
  fd_bn254_fp52_fp2_mul( &r->Y, e, &r->Y );
  fd_bn254_fp52_fp2_add( c, c, c ); /* 2*C */
  fd_bn254_fp52_fp2_add( c, c, c ); /* 4*C */
  fd_bn254_fp52_fp2_add( c, c, c ); /* 8*C */
  fd_bn254_fp52_fp2_sub( &r->Y, &r->Y, c );
  return r;
}

/* fd_bn254_fp52_g2_add_mixed computes r = p + q, where q is affine.
   http://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#addition-madd-2007-bl */

FD_FN_UNUSED static inline fd_bn254_fp52_g2_t *
fd_bn254_fp52_g2_add_mixed( fd_bn254_fp52_g2_t *       r,
                            fd_bn254_fp52_g2_t const * p,
                            fd_bn254_fp52_g2_t const * q ) {
  if( FD_UNLIKELY( fd_bn254_fp52_g2_is_zero( p ) ) ) {
    return fd_bn254_fp52_g2_set( r, q );
  }
  if( FD_UNLIKELY( fd_bn254_fp52_g2_is_zero( q ) ) ) {
    return fd_bn254_fp52_g2_set( r, p );
  }

  fd_bn254_fp52_fp2_t zz[1], u2[1], s2[1];
  fd_bn254_fp52_fp2_t h[1], hh[1];
  fd_bn254_fp52_fp2_t ii[1], j[1];
  fd_bn254_fp52_fp2_t rr[1], v[1];

  /* Z1Z1 = Z1^2 */
  fd_bn254_fp52_fp2_sqr( zz, &p->Z );

  /* U2 = X2*Z1Z1 */
  fd_bn254_fp52_fp2_mul( u2, &q->X, zz );

  /* S2 = Y2*Z1*Z1Z1 */
  fd_bn254_fp52_fp2_mul( s2, &q->Y, &p->Z );
  fd_bn254_fp52_fp2_mul( s2, s2, zz );

  /* If p==q, do doubling */
  if( FD_UNLIKELY( fd_bn254_fp52_fp2_eq( u2, &p->X ) &&
                   fd_bn254_fp52_fp2_eq( s2, &p->Y ) ) ) {
    return fd_bn254_fp52_g2_dbl( r, p );
  }

  /* H = U2 - X1 */
  fd_bn254_fp52_fp2_sub( h, u2, &p->X );

  /* HH = H^2 */
  fd_bn254_fp52_fp2_sqr( hh, h );

  /* I = 4*HH */
  fd_bn254_fp52_fp2_add( ii, hh, hh );
  fd_bn254_fp52_fp2_add( ii, ii, ii );

  /* J = H*I */
  fd_bn254_fp52_fp2_mul( j, h, ii );

  /* rr = 2*(S2 - Y1) */
  fd_bn254_fp52_fp2_sub( rr, s2, &p->Y );
  fd_bn254_fp52_fp2_add( rr, rr, rr );

  /* V = X1*I */
  fd_bn254_fp52_fp2_mul( v, &p->X, ii );

  /* X3 = rr^2 - J - 2*V */
  fd_bn254_fp52_fp2_sqr( &r->X, rr );
  fd_bn254_fp52_fp2_sub( &r->X, &r->X, j );
  fd_bn254_fp52_fp2_sub( &r->X, &r->X, v );
  fd_bn254_fp52_fp2_sub( &r->X, &r->X, v );

  /* Y3 = rr*(V - X3) - 2*Y1*J */
  {
    fd_bn254_fp52_fp2_t t[1];
    fd_bn254_fp52_fp2_mul( t, &p->Y, j ); /* Y1*J */
    fd_bn254_fp52_fp2_add( t, t, t );      /* 2*Y1*J */
    fd_bn254_fp52_fp2_sub( &r->Y, v, &r->X );
    fd_bn254_fp52_fp2_mul( &r->Y, &r->Y, rr );
    fd_bn254_fp52_fp2_sub( &r->Y, &r->Y, t );
  }

  /* Z3 = (Z1+H)^2 - Z1Z1 - HH */
  fd_bn254_fp52_fp2_add( &r->Z, &p->Z, h );
  fd_bn254_fp52_fp2_sqr( &r->Z, &r->Z );
  fd_bn254_fp52_fp2_sub( &r->Z, &r->Z, zz );
  fd_bn254_fp52_fp2_sub( &r->Z, &r->Z, hh );
  return r;
}

/* fd_bn254_fp52_g2_add computes r = p + q (full projective addition).
   p MUST not be equal to q, unless p==0.
   http://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#addition-add-2007-bl */

FD_FN_UNUSED static inline fd_bn254_fp52_g2_t *
fd_bn254_fp52_g2_add( fd_bn254_fp52_g2_t *       r,
                      fd_bn254_fp52_g2_t const * p,
                      fd_bn254_fp52_g2_t const * q ) {
  if( FD_UNLIKELY( fd_bn254_fp52_g2_is_zero( p ) ) ) {
    return fd_bn254_fp52_g2_set( r, q );
  }
  if( FD_UNLIKELY( fd_bn254_fp52_g2_is_zero( q ) ) ) {
    return fd_bn254_fp52_g2_set( r, p );
  }

  fd_bn254_fp52_fp2_t zz1[1], zz2[1];
  fd_bn254_fp52_fp2_t u1[1], s1[1];
  fd_bn254_fp52_fp2_t u2[1], s2[1];
  fd_bn254_fp52_fp2_t h[1];
  fd_bn254_fp52_fp2_t ii[1], j[1];
  fd_bn254_fp52_fp2_t rr[1], v[1];

  /* Z1Z1 = Z1^2,  Z2Z2 = Z2^2 */
  fd_bn254_fp52_fp2_sqr2( zz1, &p->Z, zz2, &q->Z );

  /* U1 = X1*Z2Z2,  U2 = X2*Z1Z1 */
  fd_bn254_fp52_fp2_mul2( u1, &p->X, zz2,
                          u2, &q->X, zz1 );

  /* S1 = Y1*Z2*Z2Z2 */
  fd_bn254_fp52_fp2_mul( s1, &p->Y, &q->Z );
  fd_bn254_fp52_fp2_mul( s1, s1, zz2 );

  /* S2 = Y2*Z1*Z1Z1 */
  fd_bn254_fp52_fp2_mul( s2, &q->Y, &p->Z );
  fd_bn254_fp52_fp2_mul( s2, s2, zz1 );

  /* H = U2 - U1 */
  fd_bn254_fp52_fp2_sub( h, u2, u1 );

  /* HH = (2*H)^2 */
  fd_bn254_fp52_fp2_add( ii, h, h );
  fd_bn254_fp52_fp2_sqr( ii, ii );

  /* J = H*I */
  fd_bn254_fp52_fp2_mul( j, h, ii );

  /* rr = 2*(S2 - S1) */
  fd_bn254_fp52_fp2_sub( rr, s2, s1 );
  fd_bn254_fp52_fp2_add( rr, rr, rr );

  /* V = U1*I */
  fd_bn254_fp52_fp2_mul( v, u1, ii );

  /* X3 = rr^2 - J - 2*V */
  fd_bn254_fp52_fp2_sqr( &r->X, rr );
  fd_bn254_fp52_fp2_sub( &r->X, &r->X, j );
  fd_bn254_fp52_fp2_sub( &r->X, &r->X, v );
  fd_bn254_fp52_fp2_sub( &r->X, &r->X, v );

  /* Y3 = rr*(V - X3) - 2*S1*J */
  {
    fd_bn254_fp52_fp2_t t[1];
    fd_bn254_fp52_fp2_mul( t, s1, j ); /* S1*J */
    fd_bn254_fp52_fp2_add( t, t, t );  /* 2*S1*J */
    fd_bn254_fp52_fp2_sub( &r->Y, v, &r->X );
    fd_bn254_fp52_fp2_mul( &r->Y, &r->Y, rr );
    fd_bn254_fp52_fp2_sub( &r->Y, &r->Y, t );
  }

  /* Z3 = ((Z1+Z2)^2 - Z1Z1 - Z2Z2) * H */
  fd_bn254_fp52_fp2_add( &r->Z, &p->Z, &q->Z );
  fd_bn254_fp52_fp2_sqr( &r->Z, &r->Z );
  fd_bn254_fp52_fp2_sub( &r->Z, &r->Z, zz1 );
  fd_bn254_fp52_fp2_sub( &r->Z, &r->Z, zz2 );
  fd_bn254_fp52_fp2_mul( &r->Z, &r->Z, h );
  return r;
}

/* fd_bn254_fp52_g2_frob computes the Frobenius endomorphism r = pi(p).
   For a point (X, Y, Z) on the twist curve over Fp2:
     pi(X, Y, Z) = (conj(X)*gamma_1_1, conj(Y)*gamma_1_2, conj(Z))

   The gamma constants are the Frobenius preimages of the twist
   isomorphism, from fd_bn254_const_frob_gamma1_mont. */

FD_FN_UNUSED static inline fd_bn254_fp52_g2_t *
fd_bn254_fp52_g2_frob( fd_bn254_fp52_g2_t *       r,
                       fd_bn254_fp52_g2_t const * p ) {
  /* Convert gamma_1 constants from R=2^256 to R=2^260 inline. */

  /* gamma_1,1 (for X) */
  fd_bn254_fp52_fp2_t gamma11;
  {
    ulong g_re[4] = { 0xaf9ba69633144907UL, 0xca6b1d7387afb78aUL,
                       0x11bded5ef08a2087UL, 0x02f34d751a1f3a7cUL };
    ulong g_im[4] = { 0xa222ae234c492d72UL, 0xd00f02a4565de15bUL,
                       0xdc2ff3a253dfc926UL, 0x10a75716b3899551UL };
    fd_bn254_fp52_fp2_from_r256( &gamma11, g_re, g_im );
  }

  /* gamma_1,2 (for Y) */
  fd_bn254_fp52_fp2_t gamma12;
  {
    ulong g_re[4] = { 0xb5773b104563ab30UL, 0x347f91c8a9aa6454UL,
                       0x7a007127242e0991UL, 0x1956bcd8118214ecUL };
    ulong g_im[4] = { 0x6e849f1ea0aa4757UL, 0xaa1c7b6d89f89141UL,
                       0xb6e713cdfae0ca3aUL, 0x26694fbb4e82ebc3UL };
    fd_bn254_fp52_fp2_from_r256( &gamma12, g_re, g_im );
  }

  fd_bn254_fp52_fp2_conj( &r->X, &p->X );
  fd_bn254_fp52_fp2_mul ( &r->X, &r->X, &gamma11 );
  fd_bn254_fp52_fp2_conj( &r->Y, &p->Y );
  fd_bn254_fp52_fp2_mul ( &r->Y, &r->Y, &gamma12 );
  fd_bn254_fp52_fp2_conj( &r->Z, &p->Z );
  return r;
}

/* fd_bn254_fp52_g2_frob2 computes r = pi^2(p) (double Frobenius).
   pi^2 acts trivially on Fp2 (no conjugation), but multiplies by
   gamma_2 constants (Fp scalars, not Fp2).

   gamma_2,1 (for X), gamma_2,2 (for Y).
   Each Fp2 component is multiplied by the same Fp scalar. */

FD_FN_UNUSED static inline fd_bn254_fp52_g2_t *
fd_bn254_fp52_g2_frob2( fd_bn254_fp52_g2_t *       r,
                        fd_bn254_fp52_g2_t const * p ) {
  /* gamma_2,1 (for X) */
  static const ulong gamma2_1_64[4] = {
    0xca8d800500fa1bf2UL, 0xf0c5d61468b39769UL,
    0x0e201271ad0d4418UL, 0x04290f65bad856e6UL
  };
  /* gamma_2,2 (for Y) */
  static const ulong gamma2_2_64[4] = {
    0x3350c88e13e80b9cUL, 0x7dce557cdb5e56b9UL,
    0x6001b4b8b615564aUL, 0x2682e617020217e0UL
  };

  ulong g2_1[5], g2_2[5];
  fd_bn254_fp52_fp_from_r256( g2_1, gamma2_1_64 );
  fd_bn254_fp52_fp_from_r256( g2_2, gamma2_2_64 );

  /* X: multiply both Fp components by gamma_2,1 */
  fd_bn254_fp52_mul_scalar( r->X.el[0], p->X.el[0], g2_1 );
  fd_bn254_fp52_mul_scalar( r->X.el[1], p->X.el[1], g2_1 );

  /* Y: multiply both Fp components by gamma_2,2 */
  fd_bn254_fp52_mul_scalar( r->Y.el[0], p->Y.el[0], g2_2 );
  fd_bn254_fp52_mul_scalar( r->Y.el[1], p->Y.el[1], g2_2 );

  /* Z: identity */
  fd_bn254_fp52_fp2_set( &r->Z, &p->Z );
  return r;
}

/* fd_bn254_fp52_g2_affine_add computes r = p + q where both are affine. */

FD_FN_UNUSED static inline fd_bn254_fp52_g2_t *
fd_bn254_fp52_g2_affine_add( fd_bn254_fp52_g2_t *       r,
                             fd_bn254_fp52_g2_t const * p,
                             fd_bn254_fp52_g2_t const * q ) {
  if( FD_UNLIKELY( fd_bn254_fp52_g2_is_zero( p ) ) ) {
    return fd_bn254_fp52_g2_set( r, q );
  }
  if( FD_UNLIKELY( fd_bn254_fp52_g2_is_zero( q ) ) ) {
    return fd_bn254_fp52_g2_set( r, p );
  }

  fd_bn254_fp52_fp2_t lambda[1], x[1], y[1];

  if( fd_bn254_fp52_fp2_eq( &p->X, &q->X ) ) {
    if( fd_bn254_fp52_fp2_eq( &p->Y, &q->Y ) ) {
      /* p==q: lambda = 3*x1^2 / (2*y1) */
      fd_bn254_fp52_fp2_sqr( x, &p->X );
      fd_bn254_fp52_fp2_add( y, x, x );
      fd_bn254_fp52_fp2_add( x, x, y );
      fd_bn254_fp52_fp2_add( y, &p->Y, &p->Y );
      fd_bn254_fp52_fp2_inv( lambda, y );
      fd_bn254_fp52_fp2_mul( lambda, lambda, x );
    } else {
      return fd_bn254_fp52_g2_set_zero( r );
    }
  } else {
    fd_bn254_fp52_fp2_sub( x, &p->X, &q->X );
    fd_bn254_fp52_fp2_sub( y, &p->Y, &q->Y );
    fd_bn254_fp52_fp2_inv( lambda, x );
    fd_bn254_fp52_fp2_mul( lambda, lambda, y );
  }

  /* x3 = lambda^2 - x1 - x2 */
  fd_bn254_fp52_fp2_sqr( x, lambda );
  fd_bn254_fp52_fp2_sub( x, x, &p->X );
  fd_bn254_fp52_fp2_sub( x, x, &q->X );

  /* y3 = lambda*(x1 - x3) - y1 */
  fd_bn254_fp52_fp2_sub( y, &p->X, x );
  fd_bn254_fp52_fp2_mul( y, y, lambda );
  fd_bn254_fp52_fp2_sub( y, y, &p->Y );

  fd_bn254_fp52_fp2_set( &r->X, x );
  fd_bn254_fp52_fp2_set( &r->Y, y );
  fd_bn254_fp52_fp2_set_one( &r->Z );
  return r;
}

/* fd_bn254_fp52_g2_scalar_mul computes r = [s]*P using the GLV method.
   P must be affine.  Result is in Jacobian coordinates.

   For G2, the GLV lattice basis is arranged differently:
     | -N_C  -N_B |
     | +N_B  -N_A |
   so k1 = s - b1*N_C - b2*N_B (may be negative)
      k2 = b2*N_A - b1*N_B     (may be negative). */

FD_FN_UNUSED static inline fd_bn254_fp52_g2_t *
fd_bn254_fp52_g2_scalar_mul( fd_bn254_fp52_g2_t *           r,
                             fd_bn254_fp52_g2_t const *     p,
                             fd_bn254_scalar_t const *      s ) {
  if( FD_UNLIKELY( fd_uint256_is_zero( s ) || fd_bn254_fp52_g2_is_zero( p ) ) ) {
    return fd_bn254_fp52_g2_set_zero( r );
  }

  /* g1_const for G2 = round(2^256 * N_A / r), 3 limbs. */
  const ulong g1_const[ 3 ] = {
    0x7a7bd9d4391eb18eUL, 0x4ccef014a773d2cfUL, 0x0000000000000002UL
  };
  ulong b1[ 3 ], b2[ 2 ];
  fd_bn254_glv_sxg3( b1, s, g1_const );
  fd_bn254_glv_sxg2( b2, s, g2_const );

  /* k1 = s - b1*N_C - b2*N_B (may be negative for G2) */
  fd_uint256_t k1_abs[1];
  int k1_neg = 0;
  {
    ulong p_nc[ 4 ];
    ulong p_nb[ 4 ] = {0};
    ulong    t[ 4 ];
    fd_bn254_glv_mul3x2( p_nc, b1, nc );
    fd_bn254_glv_mul2x1( p_nb, b2, nb );
    fd_bn254_glv_add4( t, p_nc, p_nb );
    ulong borrow = fd_bn254_glv_sub4( k1_abs->limbs, s->limbs, t );
    if( borrow ) {
      k1_neg = 1;
      fd_bn254_glv_negate4( k1_abs->limbs );
    }
  }

  /* k2 = b2*N_A - b1*N_B (usually negative for G2) */
  fd_uint256_t k2_abs[1];
  int k2_neg = 0;
  {
    ulong pos[ 4 ], neg[ 4 ];
    fd_bn254_glv_mul2x2( pos, b2, na );
    fd_bn254_glv_mul3x1( neg, b1, nb );
    ulong borrow = fd_bn254_glv_sub4( k2_abs->limbs, pos, neg );
    if( borrow ) {
      k2_neg = 1;
      fd_bn254_glv_negate4( k2_abs->limbs );
    }
  }

  /* beta in R=2^260 radix-2^52 Montgomery form.
     beta (R=2^256) = gamma_2,2 = 0x2682e617020217e06001b4b8b615564a7dce557cdb5e56b93350c88e13e80b9c */
  static const ulong beta_r256_64[4] = {
    0x3350c88e13e80b9cUL, 0x7dce557cdb5e56b9UL,
    0x6001b4b8b615564aUL, 0x2682e617020217e0UL
  };
  ulong beta_52[5];
  fd_bn254_fp52_fp_from_r256( beta_52, beta_r256_64 );

  /* pt1 = P (possibly negated), pt2 = phi(P) = (beta*P.x, P.y).
     If k1 < 0, negate pt1.  If k2 < 0, negate pt2. */
  fd_bn254_fp52_g2_t pt1[1], pt2[1];
  fd_bn254_fp52_g2_set( pt1, p );
  fd_bn254_fp52_mul_scalar( pt2->X.el[0], p->X.el[0], beta_52 );
  fd_bn254_fp52_mul_scalar( pt2->X.el[1], p->X.el[1], beta_52 );
  fd_bn254_fp52_fp2_set( &pt2->Y, &p->Y );
  fd_bn254_fp52_fp2_set_one( &pt2->Z );
  if( k1_neg ) {
    fd_bn254_fp52_fp2_neg( &pt1->Y, &pt1->Y );
  }
  if( k2_neg ) {
    fd_bn254_fp52_fp2_neg( &pt2->Y, &pt2->Y );
  }

  fd_bn254_fp52_g2_t pt12[1];
  fd_bn254_fp52_g2_affine_add( pt12, pt1, pt2 );

  /* Shamir's trick */
  int i = 255;
  for( ; i>=0; i-- ) {
    int k1b = !!fd_uint256_bit( k1_abs, i );
    int k2b = !!fd_uint256_bit( k2_abs, i );
    if( k1b || k2b ) {
      fd_bn254_fp52_g2_set( r, ( k1b && k2b ) ? pt12 : ( k1b ? pt1 : pt2 ) );
      break;
    }
  }
  if( FD_UNLIKELY( i<0 ) ) {
    return fd_bn254_fp52_g2_set_zero( r );
  }

  for( i--; i >= 0; i-- ) {
    fd_bn254_fp52_g2_dbl( r, r );
    int k1b = !!fd_uint256_bit( k1_abs, i );
    int k2b = !!fd_uint256_bit( k2_abs, i );
    if( k1b && k2b ) {
      fd_bn254_fp52_g2_add_mixed( r, r, pt12 );
    } else if( k1b ) {
      fd_bn254_fp52_g2_add_mixed( r, r, pt1 );
    } else if( k2b ) {
      fd_bn254_fp52_g2_add_mixed( r, r, pt2 );
    }
  }

  return r;
}

FD_PROTOTYPES_END

#endif /* FD_HAS_AVX512 */

#endif /* HEADER_fd_src_ballet_bn254_avx512_fd_bn254_fp52_g2_h */
