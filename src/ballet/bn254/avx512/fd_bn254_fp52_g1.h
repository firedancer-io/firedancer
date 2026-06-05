#ifndef HEADER_fd_src_ballet_bn254_avx512_fd_bn254_fp52_g1_h
#define HEADER_fd_src_ballet_bn254_avx512_fd_bn254_fp52_g1_h

/* fd_bn254_fp52_g1.h provides G1 point operations for the BN254 curve
   using AVX-512 IFMA radix-2^52 Montgomery arithmetic.

   Points are in Jacobian coordinates (X:Y:Z) with the curve equation
   y^2 = x^3 + 3 over Fp.  A point at infinity has Z == 0.

   All field elements are in radix-2^52 R=2^260 Montgomery form. */

#if FD_HAS_AVX512

#include "fd_bn254_fp52_fp12.h"    /* includes fp6->fp2; provides fp52_mul/inv_scalar */
#include "../fd_bn254_internal.h"  /* for fd_bn254_fp_t, fd_bn254_scalar_t */
#include "../fd_bn254_scalar.h"    /* for fd_bn254_scalar_t */
#include "../fd_bn254_glv.h"       /* for GLV decomposition */
#include "../../bigint/fd_uint256.h"

FD_PROTOTYPES_BEGIN

/* fd_bn254_fp52_g1_t -- a G1 point in Jacobian coordinates.
   Each coordinate is 5 ulong limbs in radix-2^52 R=2^260 Montgomery. */

struct fd_bn254_fp52_g1 {
  ulong X[5], Y[5], Z[5];
};
typedef struct fd_bn254_fp52_g1 fd_bn254_fp52_g1_t;

/* fd_bn254_fp52_g1_is_zero returns 1 if p is the point at infinity. */

FD_FN_UNUSED static inline int
fd_bn254_fp52_g1_is_zero( fd_bn254_fp52_g1_t const * p ) {
  return (p->Z[0] | p->Z[1] | p->Z[2] | p->Z[3] | p->Z[4]) == 0;
}

/* fd_bn254_fp52_g1_set copies p into r. */

FD_FN_UNUSED static inline fd_bn254_fp52_g1_t *
fd_bn254_fp52_g1_set( fd_bn254_fp52_g1_t *       r,
                      fd_bn254_fp52_g1_t const * p ) {
  fd_bn254_fp52_set_scalar( r->X, p->X );
  fd_bn254_fp52_set_scalar( r->Y, p->Y );
  fd_bn254_fp52_set_scalar( r->Z, p->Z );
  return r;
}

/* fd_bn254_fp52_g1_set_zero sets r to the point at infinity. */

FD_FN_UNUSED static inline fd_bn254_fp52_g1_t *
fd_bn254_fp52_g1_set_zero( fd_bn254_fp52_g1_t * r ) {
  r->Z[0] = 0; r->Z[1] = 0; r->Z[2] = 0; r->Z[3] = 0; r->Z[4] = 0;
  return r;
}

/* fd_bn254_fp52_g1_dbl computes r = 2*p.
   https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#doubling-dbl-2009-l

   Algorithm (a=0 for BN254):
     A = X1^2
     B = Y1^2
     C = B^2
     D = 4*X1*B    (simplified from 2*((X1+B)^2-A-C))
     E = 3*A
     F = E^2
     X3 = F - 2*D
     Z3 = 2*Y1*Z1
     Y3 = E*(D - X3) - 8*C */

FD_FN_UNUSED static inline fd_bn254_fp52_g1_t *
fd_bn254_fp52_g1_dbl( fd_bn254_fp52_g1_t *       r,
                      fd_bn254_fp52_g1_t const * p ) {
  if( FD_UNLIKELY( fd_bn254_fp52_g1_is_zero( p ) ) ) {
    return fd_bn254_fp52_g1_set_zero( r );
  }

  ulong a[5], b[5], c[5];
  ulong d[5], e[5], f[5];

  /* A = X1^2 and B = Y1^2.
     Pack both squarings into one batched mul (lanes 0,1). */
  {
    fd_bn254_fp52x8_t ax, bx;
    fd_bn254_fp52x8_zero( &ax );
    fd_bn254_fp52x8_zero( &bx );
    fd_bn254_fp52x8_pack_lane( &ax, 0, p->X );
    fd_bn254_fp52x8_pack_lane( &bx, 0, p->X );
    fd_bn254_fp52x8_pack_lane( &ax, 1, p->Y );
    fd_bn254_fp52x8_pack_lane( &bx, 1, p->Y );
    fd_bn254_fp52x8_t px = fd_bn254_fp52x8_mul( &ax, &bx );
    fd_bn254_fp52x8_extract_lane( a, &px, 0 );
    fd_bn254_fp52x8_extract_lane( b, &px, 1 );
  }

  /* C = B^2 */
  fd_bn254_fp52_sqr_scalar( c, b );

  /* D = 4*X1*B */
  fd_bn254_fp52_mul_scalar( d, p->X, b );
  fd_bn254_fp52_add_scalar( d, d, d );
  fd_bn254_fp52_add_scalar( d, d, d );

  /* E = 3*A */
  fd_bn254_fp52_add_scalar( e, a, a );
  fd_bn254_fp52_add_scalar( e, a, e );

  /* F = E^2 */
  fd_bn254_fp52_sqr_scalar( f, e );

  /* X3 = F - 2*D */
  fd_bn254_fp52_add_scalar( r->X, d, d );
  fd_bn254_fp52_sub_scalar( r->X, f, r->X );

  /* Z3 = 2*Y1*Z1
     Compute before Y3 because p->Y may be overwritten if r==p. */
  fd_bn254_fp52_mul_scalar( r->Z, p->Y, p->Z );
  fd_bn254_fp52_add_scalar( r->Z, r->Z, r->Z );

  /* Y3 = E*(D - X3) - 8*C */
  fd_bn254_fp52_sub_scalar( r->Y, d, r->X );
  fd_bn254_fp52_mul_scalar( r->Y, e, r->Y );
  fd_bn254_fp52_add_scalar( c, c, c ); /* 2*C */
  fd_bn254_fp52_add_scalar( c, c, c ); /* 4*C */
  fd_bn254_fp52_add_scalar( c, c, c ); /* 8*C */
  fd_bn254_fp52_sub_scalar( r->Y, r->Y, c );
  return r;
}

/* fd_bn254_fp52_g1_add_mixed computes r = p + q, where q is affine (q.Z==1).
   http://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#addition-madd-2007-bl

   Algorithm:
     Z1Z1 = Z1^2
     U2   = X2*Z1Z1
     S2   = Y2*Z1*Z1Z1
     H    = U2 - X1
     HH   = H^2
     I    = 4*HH
     J    = H*I
     rr   = 2*(S2 - Y1)
     V    = X1*I
     X3   = rr^2 - J - 2*V
     Y3   = rr*(V - X3) - 2*Y1*J
     Z3   = (Z1+H)^2 - Z1Z1 - HH */

FD_FN_UNUSED static inline fd_bn254_fp52_g1_t *
fd_bn254_fp52_g1_add_mixed( fd_bn254_fp52_g1_t *       r,
                            fd_bn254_fp52_g1_t const * p,
                            fd_bn254_fp52_g1_t const * q ) {
  /* p==0 => return q */
  if( FD_UNLIKELY( fd_bn254_fp52_g1_is_zero( p ) ) ) {
    return fd_bn254_fp52_g1_set( r, q );
  }

  ulong zz[5], u2[5], s2[5];
  ulong h[5], hh[5];
  ulong ii[5], j[5];
  ulong rr[5], v[5];

  /* Z1Z1 = Z1^2 */
  fd_bn254_fp52_sqr_scalar( zz, p->Z );

  /* U2 = X2*Z1Z1 */
  fd_bn254_fp52_mul_scalar( u2, q->X, zz );

  /* S2 = Y2*Z1*Z1Z1 */
  fd_bn254_fp52_mul_scalar( s2, q->Y, p->Z );
  fd_bn254_fp52_mul_scalar( s2, s2, zz );

  /* If p==q, do doubling instead */
  if( FD_UNLIKELY(
    (u2[0]==p->X[0]) && (u2[1]==p->X[1]) && (u2[2]==p->X[2]) &&
    (u2[3]==p->X[3]) && (u2[4]==p->X[4]) &&
    (s2[0]==p->Y[0]) && (s2[1]==p->Y[1]) && (s2[2]==p->Y[2]) &&
    (s2[3]==p->Y[3]) && (s2[4]==p->Y[4])
  ) ) {
    return fd_bn254_fp52_g1_dbl( r, p );
  }

  /* H = U2 - X1 */
  fd_bn254_fp52_sub_scalar( h, u2, p->X );

  /* HH = H^2 */
  fd_bn254_fp52_sqr_scalar( hh, h );

  /* I = 4*HH */
  fd_bn254_fp52_add_scalar( ii, hh, hh );
  fd_bn254_fp52_add_scalar( ii, ii, ii );

  /* J = H*I */
  fd_bn254_fp52_mul_scalar( j, h, ii );

  /* rr = 2*(S2 - Y1) */
  fd_bn254_fp52_sub_scalar( rr, s2, p->Y );
  fd_bn254_fp52_add_scalar( rr, rr, rr );

  /* V = X1*I */
  fd_bn254_fp52_mul_scalar( v, p->X, ii );

  /* X3 = rr^2 - J - 2*V */
  fd_bn254_fp52_sqr_scalar( r->X, rr );
  fd_bn254_fp52_sub_scalar( r->X, r->X, j );
  fd_bn254_fp52_sub_scalar( r->X, r->X, v );
  fd_bn254_fp52_sub_scalar( r->X, r->X, v );

  /* Y3 = rr*(V - X3) - 2*Y1*J */
  {
    ulong t[5];
    fd_bn254_fp52_mul_scalar( t, p->Y, j ); /* Y1*J */
    fd_bn254_fp52_add_scalar( t, t, t );     /* 2*Y1*J */
    fd_bn254_fp52_sub_scalar( r->Y, v, r->X );
    fd_bn254_fp52_mul_scalar( r->Y, r->Y, rr );
    fd_bn254_fp52_sub_scalar( r->Y, r->Y, t );
  }

  /* Z3 = (Z1+H)^2 - Z1Z1 - HH */
  fd_bn254_fp52_add_scalar( r->Z, p->Z, h );
  fd_bn254_fp52_sqr_scalar( r->Z, r->Z );
  fd_bn254_fp52_sub_scalar( r->Z, r->Z, zz );
  fd_bn254_fp52_sub_scalar( r->Z, r->Z, hh );
  return r;
}

/* fd_bn254_fp52_g1_to_affine converts from Jacobian to affine.
   Computes (X/Z^2, Y/Z^3) and sets Z=1. */

FD_FN_UNUSED static inline fd_bn254_fp52_g1_t *
fd_bn254_fp52_g1_to_affine( fd_bn254_fp52_g1_t *       r,
                            fd_bn254_fp52_g1_t const * p ) {
  if( FD_UNLIKELY( fd_bn254_fp52_g1_is_zero( p ) ) ) {
    return fd_bn254_fp52_g1_set( r, p );
  }

  /* Check if already affine (Z==1 in Montgomery) */
  if( p->Z[0]==FD_BN254_FP52_ONE_0 && p->Z[1]==FD_BN254_FP52_ONE_1 &&
      p->Z[2]==FD_BN254_FP52_ONE_2 && p->Z[3]==FD_BN254_FP52_ONE_3 &&
      p->Z[4]==FD_BN254_FP52_ONE_4 ) {
    return fd_bn254_fp52_g1_set( r, p );
  }

  ulong iz[5], iz2[5];
  fd_bn254_fp52_inv_scalar( iz, p->Z );
  fd_bn254_fp52_sqr_scalar( iz2, iz );

  /* X = X / Z^2 */
  fd_bn254_fp52_mul_scalar( r->X, p->X, iz2 );

  /* Y = Y / Z^3 */
  fd_bn254_fp52_mul_scalar( r->Y, p->Y, iz2 );
  fd_bn254_fp52_mul_scalar( r->Y, r->Y, iz );

  /* Z = 1 (Montgomery) */
  r->Z[0] = FD_BN254_FP52_ONE_0;
  r->Z[1] = FD_BN254_FP52_ONE_1;
  r->Z[2] = FD_BN254_FP52_ONE_2;
  r->Z[3] = FD_BN254_FP52_ONE_3;
  r->Z[4] = FD_BN254_FP52_ONE_4;
  return r;
}

/* fd_bn254_fp52_g1_affine_add computes r = p + q where both p, q are
   affine (Z==1).  This is the simple formula used for precomputation
   in the GLV scalar multiplication. */

FD_FN_UNUSED static inline fd_bn254_fp52_g1_t *
fd_bn254_fp52_g1_affine_add( fd_bn254_fp52_g1_t *       r,
                             fd_bn254_fp52_g1_t const * p,
                             fd_bn254_fp52_g1_t const * q ) {
  if( FD_UNLIKELY( fd_bn254_fp52_g1_is_zero( p ) ) ) {
    return fd_bn254_fp52_g1_set( r, q );
  }
  if( FD_UNLIKELY( fd_bn254_fp52_g1_is_zero( q ) ) ) {
    return fd_bn254_fp52_g1_set( r, p );
  }

  ulong lambda[5], x[5], y[5];

  /* Same X: either equal or opposite points */
  int same_x = (p->X[0]==q->X[0]) && (p->X[1]==q->X[1]) &&
               (p->X[2]==q->X[2]) && (p->X[3]==q->X[3]) && (p->X[4]==q->X[4]);
  if( same_x ) {
    int same_y = (p->Y[0]==q->Y[0]) && (p->Y[1]==q->Y[1]) &&
                 (p->Y[2]==q->Y[2]) && (p->Y[3]==q->Y[3]) && (p->Y[4]==q->Y[4]);
    if( same_y ) {
      /* p==q: lambda = 3*x1^2 / (2*y1) */
      fd_bn254_fp52_sqr_scalar( x, p->X );       /* x1^2 */
      fd_bn254_fp52_add_scalar( y, x, x );        /* 2*x1^2 */
      fd_bn254_fp52_add_scalar( x, x, y );        /* 3*x1^2 */
      fd_bn254_fp52_add_scalar( y, p->Y, p->Y );  /* 2*y1 */
      fd_bn254_fp52_inv_scalar( lambda, y );
      fd_bn254_fp52_mul_scalar( lambda, lambda, x );
    } else {
      /* p==-q => infinity */
      return fd_bn254_fp52_g1_set_zero( r );
    }
  } else {
    /* lambda = (y1 - y2) / (x1 - x2) */
    fd_bn254_fp52_sub_scalar( x, p->X, q->X );
    fd_bn254_fp52_sub_scalar( y, p->Y, q->Y );
    fd_bn254_fp52_inv_scalar( lambda, x );
    fd_bn254_fp52_mul_scalar( lambda, lambda, y );
  }

  /* x3 = lambda^2 - x1 - x2 */
  fd_bn254_fp52_sqr_scalar( x, lambda );
  fd_bn254_fp52_sub_scalar( x, x, p->X );
  fd_bn254_fp52_sub_scalar( x, x, q->X );

  /* y3 = lambda*(x1 - x3) - y1 */
  fd_bn254_fp52_sub_scalar( y, p->X, x );
  fd_bn254_fp52_mul_scalar( y, y, lambda );
  fd_bn254_fp52_sub_scalar( y, y, p->Y );

  fd_bn254_fp52_set_scalar( r->X, x );
  fd_bn254_fp52_set_scalar( r->Y, y );
  r->Z[0] = FD_BN254_FP52_ONE_0;
  r->Z[1] = FD_BN254_FP52_ONE_1;
  r->Z[2] = FD_BN254_FP52_ONE_2;
  r->Z[3] = FD_BN254_FP52_ONE_3;
  r->Z[4] = FD_BN254_FP52_ONE_4;
  return r;
}

/* fd_bn254_fp52_g1_scalar_mul computes r = [s]*P using the GLV method.

   P must be in affine form (Z==1).  The result is in Jacobian
   coordinates.

   GLV decomposes the scalar s into two ~128-bit half-scalars k1, k2
   such that [s]P = [k1]P + [k2]*phi(P), where phi is the efficient
   endomorphism (x,y) -> (beta*x, y).  Shamir's trick evaluates both
   scalar multiplications simultaneously in a single double-and-add
   loop, cutting the number of doublings roughly in half. */

FD_FN_UNUSED static inline fd_bn254_fp52_g1_t *
fd_bn254_fp52_g1_scalar_mul( fd_bn254_fp52_g1_t *           r,
                             fd_bn254_fp52_g1_t const *     p,
                             fd_bn254_scalar_t const *      s ) {
  if( FD_UNLIKELY( fd_uint256_is_zero( s ) || fd_bn254_fp52_g1_is_zero( p ) ) ) {
    return fd_bn254_fp52_g1_set_zero( r );
  }

  /* GLV decomposition for G1.
     g1_const = round(2^256 * N_C / r), 3 limbs. */
  const ulong g1_const[ 3 ] = {
    0x5398fd0300ff6565UL, 0x4ccef014a773d2d2UL, 0x0000000000000002UL
  };
  ulong b1[ 3 ];
  ulong b2[ 2 ];
  fd_bn254_glv_sxg3( b1, s, g1_const );
  fd_bn254_glv_sxg2( b2, s, g2_const );

  /* k1 = s - b1*N_A - b2*N_B (always non-negative for G1) */
  fd_uint256_t k1[1];
  {
    ulong p11[ 4 ];
    ulong p21[ 4 ] = {0};
    ulong  t[ 4 ];
    fd_bn254_glv_mul3x2( p11, b1, na );
    fd_bn254_glv_mul2x1( p21, b2, nb );
    fd_bn254_glv_add4( t, p11, p21 );
    fd_bn254_glv_sub4( k1->limbs, s->limbs, t );
  }

  /* k2 = b1*N_B - b2*N_C (may be negative) */
  fd_uint256_t k2_abs[1];
  int k2_neg = 0;
  {
    ulong pos[ 4 ], neg[ 4 ];
    fd_bn254_glv_mul3x1( pos, b1, nb );
    fd_bn254_glv_mul2x2( neg, b2, nc );
    ulong borrow = fd_bn254_glv_sub4( k2_abs->limbs, pos, neg );
    if( borrow ) {
      k2_neg = 1;
      fd_bn254_glv_negate4( k2_abs->limbs );
    }
  }

  /* beta in R=2^260 radix-2^52 Montgomery form.
     beta (R=2^256) = 0x2682e617020217e06001b4b8b615564a7dce557cdb5e56b93350c88e13e80b9c
     Convert: radix change + multiply by 16. */
  static const ulong beta_r256_64[4] = {
    0x3350c88e13e80b9cUL, 0x7dce557cdb5e56b9UL,
    0x6001b4b8b615564aUL, 0x2682e617020217e0UL
  };
  ulong beta_52[5];
  fd_bn254_fp52_fp_from_r256( beta_52, beta_r256_64 );

  /* pt2 = phi(P) = (beta*P.x, P.y).  If k2 < 0, negate pt2. */
  fd_bn254_fp52_g1_t pt2[1];
  fd_bn254_fp52_mul_scalar( pt2->X, p->X, beta_52 );
  fd_bn254_fp52_set_scalar( pt2->Y, p->Y );
  pt2->Z[0] = FD_BN254_FP52_ONE_0;
  pt2->Z[1] = FD_BN254_FP52_ONE_1;
  pt2->Z[2] = FD_BN254_FP52_ONE_2;
  pt2->Z[3] = FD_BN254_FP52_ONE_3;
  pt2->Z[4] = FD_BN254_FP52_ONE_4;
  if( k2_neg ) {
    fd_bn254_fp52_neg_scalar( pt2->Y, pt2->Y );
  }

  /* pt12 = P + pt2 (both affine) */
  fd_bn254_fp52_g1_t pt12[1];
  fd_bn254_fp52_g1_affine_add( pt12, p, pt2 );

  /* Shamir's trick: scan bits of k1 and k2_abs from MSB to LSB.
     Initialize r to the first nonzero pair. */
  int i = 255;
  for( ; i>=0; i-- ) {
    int k1b = !!fd_uint256_bit( k1, i );
    int k2b = !!fd_uint256_bit( k2_abs, i );
    if( k1b || k2b ) {
      fd_bn254_fp52_g1_set( r, ( k1b && k2b ) ? pt12 : ( k1b ? p : pt2 ) );
      break;
    }
  }
  if( FD_UNLIKELY( i<0 ) ) {
    return fd_bn254_fp52_g1_set_zero( r );
  }

  /* Double-and-add loop */
  for( i--; i >= 0; i-- ) {
    fd_bn254_fp52_g1_dbl( r, r );
    int k1b = !!fd_uint256_bit( k1, i );
    int k2b = !!fd_uint256_bit( k2_abs, i );
    if( k1b && k2b ) {
      fd_bn254_fp52_g1_add_mixed( r, r, pt12 );
    } else if( k1b ) {
      fd_bn254_fp52_g1_add_mixed( r, r, p );
    } else if( k2b ) {
      fd_bn254_fp52_g1_add_mixed( r, r, pt2 );
    }
  }

  return r;
}

FD_PROTOTYPES_END

#endif /* FD_HAS_AVX512 */

#endif /* HEADER_fd_src_ballet_bn254_avx512_fd_bn254_fp52_g1_h */
