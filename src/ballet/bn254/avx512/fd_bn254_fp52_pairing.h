#ifndef HEADER_fd_src_ballet_bn254_avx512_fd_bn254_fp52_pairing_h
#define HEADER_fd_src_ballet_bn254_avx512_fd_bn254_fp52_pairing_h

/* fd_bn254_fp52_pairing.h provides the Miller loop for BN254 optimal
   Ate pairing using AVX-512 IFMA radix-2^52 Montgomery arithmetic.

   The final exponentiation is provided by fd_bn254_fp52_final_exp()
   in fd_bn254_fp52_fp12.h.

   References:
     - https://eprint.iacr.org/2012/408 (line function evaluation)
     - https://eprint.iacr.org/2013/722 (optimal Ate pairing)
     - https://github.com/Consensys/gnark-crypto/blob/v0.12.1/ecc/bn254/pairing.go */

#if FD_HAS_AVX512

#include "fd_bn254_fp52_fp12.h"
#include "fd_bn254_fp52_g1.h"
#include "fd_bn254_fp52_g2.h"

/* Maximum batch size for multi-pairing.  Must match FD_BN254_PAIRING_BATCH_MAX. */
#define FD_BN254_FP52_PAIRING_BATCH_MAX 16UL

FD_PROTOTYPES_BEGIN

/* fd_bn254_fp52_twist_b returns the twist curve constant b' = 3/(9+i)
   in radix-2^52 R=2^260 Montgomery form.

   The original value in R=2^256 Montgomery:
     b'.re = 0x2514c6324384a86d26b7edf049755260020b1b273633535d3bf938e377b802a8
     b'.im = 0x0141b9ce4a688d4dd749d0dd22ac00aa65f0b37d93ce0d3e38e7ecccd1dcff67

   We convert inline (radix change + *16). */

FD_FN_UNUSED static inline void
fd_bn254_fp52_twist_b_get( fd_bn254_fp52_fp2_t * twist_b ) {
  static const ulong tb_re[4] = {
    0x3bf938e377b802a8UL, 0x020b1b273633535dUL,
    0x26b7edf049755260UL, 0x2514c6324384a86dUL
  };
  static const ulong tb_im[4] = {
    0x38e7ecccd1dcff67UL, 0x65f0b37d93ce0d3eUL,
    0xd749d0dd22ac00aaUL, 0x0141b9ce4a688d4dUL
  };
  fd_bn254_fp52_fp2_from_r256( twist_b, tb_re, tb_im );
}

/* fd_bn254_fp52_pairing_proj_dbl computes the line function evaluation
   and doubles the G2 point t, during the Miller loop.

   This implements the "doubling step" from Algorithm 1 of
   https://eprint.iacr.org/2012/408, Sec. 4.2 (Eq. 11).

   Inputs:
     t -- G2 point (Jacobian, modified in-place)
     p -- G1 affine point

   Output:
     r -- sparse Fp12 element (line function value)
     t -- updated to 2*t */

FD_FN_UNUSED static inline void
fd_bn254_fp52_pairing_proj_dbl( fd_bn254_fp52_fp12_t *     r,
                                fd_bn254_fp52_g2_t *       t,
                                fd_bn254_fp52_g1_t const * p ) {
  fd_bn254_fp52_fp2_t * X = &t->X;
  fd_bn254_fp52_fp2_t * Y = &t->Y;
  fd_bn254_fp52_fp2_t * Z = &t->Z;
  ulong const * x = p->X;
  ulong const * y = p->Y;
  fd_bn254_fp52_fp2_t a[1], b[1], c[1], d[1];
  fd_bn254_fp52_fp2_t e[1], f[1], g[1], h[1];
  ulong x3[5];

  /* Twist b' constant */
  fd_bn254_fp52_fp2_t twist_b[1];
  fd_bn254_fp52_twist_b_get( twist_b );

  /* A = X1*Y1/2 */
  fd_bn254_fp52_fp2_mul( a, X, Y );
  fd_bn254_fp52_fp2_halve( a, a );

  /* B = Y1^2 */
  fd_bn254_fp52_fp2_sqr( b, Y );

  /* C = Z1^2 */
  fd_bn254_fp52_fp2_sqr( c, Z );

  /* D = 3*C */
  fd_bn254_fp52_fp2_add( d, c, c );
  fd_bn254_fp52_fp2_add( d, d, c );

  /* E = b'*D */
  fd_bn254_fp52_fp2_mul( e, d, twist_b );

  /* F = 3*E */
  fd_bn254_fp52_fp2_add( f, e, e );
  fd_bn254_fp52_fp2_add( f, f, e );

  /* G = (B+F)/2 */
  fd_bn254_fp52_fp2_add( g, b, f );
  fd_bn254_fp52_fp2_halve( g, g );

  /* H = (Y1+Z1)^2 - (B+C) */
  fd_bn254_fp52_fp2_add( h, Y, Z );
  fd_bn254_fp52_fp2_sqr( h, h );
  fd_bn254_fp52_fp2_sub( h, h, b );
  fd_bn254_fp52_fp2_sub( h, h, c );

  /* Line function: g(P) = (H * -y) + (3*X^2 * x)*w + (E - B)*w^3
     Stored in sparse Fp12 form:
       el[0][0] = -(H * y)
       el[0][1] = 0
       el[0][2] = 0
       el[1][0] = 3*X^2 * x
       el[1][1] = E - B
       el[1][2] = 0 */

  /* el[0][0] = -(H * y) */
  fd_bn254_fp52_fp2_neg( &r->el[0].el[0], h );
  fd_bn254_fp52_mul_scalar( r->el[0].el[0].el[0], r->el[0].el[0].el[0], y );
  fd_bn254_fp52_mul_scalar( r->el[0].el[0].el[1], r->el[0].el[0].el[1], y );

  /* el[0][1] = 0,  el[0][2] = 0 */
  fd_bn254_fp52_fp2_set_zero( &r->el[0].el[1] );
  fd_bn254_fp52_fp2_set_zero( &r->el[0].el[2] );

  /* el[1][0] = 3*X^2 * x */
  fd_bn254_fp52_fp2_sqr( &r->el[1].el[0], X );
  fd_bn254_fp52_add_scalar( x3, x, x );
  fd_bn254_fp52_add_scalar( x3, x3, x );
  fd_bn254_fp52_mul_scalar( r->el[1].el[0].el[0], r->el[1].el[0].el[0], x3 );
  fd_bn254_fp52_mul_scalar( r->el[1].el[0].el[1], r->el[1].el[0].el[1], x3 );

  /* el[1][1] = E - B */
  fd_bn254_fp52_fp2_sub( &r->el[1].el[1], e, b );

  /* el[1][2] = 0 */
  fd_bn254_fp52_fp2_set_zero( &r->el[1].el[2] );

  /* Update t: the point doubling.
     X3 = A * (B - F) */
  fd_bn254_fp52_fp2_sub( X, b, f );
  fd_bn254_fp52_fp2_mul( X, X, a );

  /* Y3 = G^2 - 3*E^2 */
  fd_bn254_fp52_fp2_sqr( Y, g );
  fd_bn254_fp52_fp2_sqr( c, e );       /* reuse c = E^2 */
  fd_bn254_fp52_fp2_add( d, c, c );    /* reuse d = 2*E^2 */
  fd_bn254_fp52_fp2_add( d, d, c );    /* 3*E^2 */
  fd_bn254_fp52_fp2_sub( Y, Y, d );

  /* Z3 = B * H */
  fd_bn254_fp52_fp2_mul( Z, b, h );
}

/* fd_bn254_fp52_pairing_proj_add_sub computes the line function
   evaluation and optionally updates the G2 point t, during the
   Miller loop addition/subtraction step.

   This implements the "addition step" from Algorithm 1 of
   https://eprint.iacr.org/2012/408, Sec. 4.2 (Eq. 12-13).

   Inputs:
     t         -- G2 point (Jacobian, modified in-place if add_point)
     q         -- G2 affine point
     p         -- G1 affine point
     is_add    -- if 1, add q; if 0, subtract q (negate q.Y)
     add_point -- if 1, update t; if 0, only compute line function

   Output:
     r -- sparse Fp12 element (line function value)
     t -- updated to t +/- q (if add_point) */

FD_FN_UNUSED static inline void
fd_bn254_fp52_pairing_proj_add_sub( fd_bn254_fp52_fp12_t *     r,
                                    fd_bn254_fp52_g2_t *       t,
                                    fd_bn254_fp52_g2_t const * q,
                                    fd_bn254_fp52_g1_t const * p,
                                    int                        is_add,
                                    int                        add_point ) {
  fd_bn254_fp52_fp2_t * X = &t->X;
  fd_bn254_fp52_fp2_t * Y = &t->Y;
  fd_bn254_fp52_fp2_t * Z = &t->Z;
  fd_bn254_fp52_fp2_t const * X2 = &q->X;
  fd_bn254_fp52_fp2_t Y2[1];
  ulong const * x = p->X;
  ulong const * y = p->Y;
  fd_bn254_fp52_fp2_t a[1], b_[1], c[1], d[1];
  fd_bn254_fp52_fp2_t e[1], f[1], g[1], h[1];
  fd_bn254_fp52_fp2_t ii[1], j[1], k[1];
  fd_bn254_fp52_fp2_t o[1], l[1];

  if( is_add ) {
    fd_bn254_fp52_fp2_set( Y2, &q->Y );
  } else {
    fd_bn254_fp52_fp2_neg( Y2, &q->Y );
  }

  fd_bn254_fp52_fp2_mul( a, Y2, Z );
  fd_bn254_fp52_fp2_mul( b_, X2, Z );
  fd_bn254_fp52_fp2_sub( o, Y, a );
  fd_bn254_fp52_fp2_sub( l, X, b_ );

  fd_bn254_fp52_fp2_mul( j, o, X2 );
  fd_bn254_fp52_fp2_mul( k, l, Y2 );

  /* Line function: g(P) = (l*y) + (-o*x)*w + (j-k)*w^3
     Stored in sparse Fp12 form. */

  /* el[0][0] = l * y */
  fd_bn254_fp52_mul_scalar( r->el[0].el[0].el[0], l->el[0], y );
  fd_bn254_fp52_mul_scalar( r->el[0].el[0].el[1], l->el[1], y );

  /* el[0][1] = 0,  el[0][2] = 0 */
  fd_bn254_fp52_fp2_set_zero( &r->el[0].el[1] );
  fd_bn254_fp52_fp2_set_zero( &r->el[0].el[2] );

  /* el[1][0] = -(o * x) */
  fd_bn254_fp52_fp2_neg( &r->el[1].el[0], o );
  fd_bn254_fp52_mul_scalar( r->el[1].el[0].el[0], r->el[1].el[0].el[0], x );
  fd_bn254_fp52_mul_scalar( r->el[1].el[0].el[1], r->el[1].el[0].el[1], x );

  /* el[1][1] = j - k */
  fd_bn254_fp52_fp2_sub( &r->el[1].el[1], j, k );

  /* el[1][2] = 0 */
  fd_bn254_fp52_fp2_set_zero( &r->el[1].el[2] );

  /* Optionally update t: t = t +/- q */
  if( add_point ) {
    fd_bn254_fp52_fp2_sqr( c, o );
    fd_bn254_fp52_fp2_sqr( d, l );
    fd_bn254_fp52_fp2_mul( e, d, l );
    fd_bn254_fp52_fp2_mul( f, Z, c );
    fd_bn254_fp52_fp2_mul( g, X, d );
    fd_bn254_fp52_fp2_add( h, e, f );
    fd_bn254_fp52_fp2_sub( h, h, g );
    fd_bn254_fp52_fp2_sub( h, h, g );
    fd_bn254_fp52_fp2_mul( ii, Y, e );

    /* X3 = l * h */
    fd_bn254_fp52_fp2_mul( X, l, h );

    /* Y3 = o * (g - h) - Y1*e */
    fd_bn254_fp52_fp2_sub( Y, g, h );
    fd_bn254_fp52_fp2_mul( Y, Y, o );
    fd_bn254_fp52_fp2_sub( Y, Y, ii );

    /* Z3 = Z1 * e */
    fd_bn254_fp52_fp2_mul( Z, Z, e );
  }
}

/* fd_bn254_fp52_miller_loop computes the Miller loop for the optimal
   Ate pairing on BN254.

   Inputs:
     p[]  -- array of sz G1 affine points (must have Z==1 in Montgomery)
     q[]  -- array of sz G2 affine points (must have Z==1 in Montgomery)
     sz   -- number of pairings to accumulate

   Output:
     f -- Fp12 element (product of all line functions)

   The Miller loop uses the NAF representation of the BN254 parameter
   6x+2 to minimize additions.  After the main loop, two correction
   terms involving Frobenius of Q are applied.

   The final exponentiation should be applied separately via
   fd_bn254_fp52_final_exp(). */

FD_FN_UNUSED static inline fd_bn254_fp52_fp12_t *
fd_bn254_fp52_miller_loop( fd_bn254_fp52_fp12_t *     f,
                           fd_bn254_fp52_g1_t const   p_arr[],
                           fd_bn254_fp52_g2_t const   q_arr[],
                           ulong                      sz ) {
  /* NAF table for 6x+2 where x = 0x44e992b44a6909f1.
     Length 66, stored LSB-first (index 0 = bit 0).
     From gnark-crypto: https://github.com/Consensys/gnark-crypto/blob/v0.12.1/ecc/bn254/pairing.go#L168 */
  static const schar naf[] = {
    0,  0,  0,  1,  0,  1,  0, -1,
    0,  0, -1,  0,  0,  0,  1,  0,
    0, -1,  0, -1,  0,  0,  0,  1,
    0, -1,  0,  0,  0,  0, -1,  0,
    0,  1,  0, -1,  0,  0,  1,  0,
    0,  0,  0,  0, -1,  0,  0, -1,
    0,  1,  0, -1,  0,  0,  0, -1,
    0, -1,  0,  0,  0,  1,  0, -1, /* 0, 1 */
  };

  fd_bn254_fp52_g2_t  tpts[FD_BN254_FP52_PAIRING_BATCH_MAX];
  fd_bn254_fp52_g2_t  frob[1];
  fd_bn254_fp52_fp12_t l[1];

  fd_bn254_fp52_fp12_set_one( f );
  for( ulong j=0; j<sz; j++ ) {
    fd_bn254_fp52_g2_set( &tpts[j], &q_arr[j] );
  }

  /* First iteration: bit 64 (the MSB of the NAF, which is implicitly 1).
     Perform one doubling step. */
  for( ulong j=0; j<sz; j++ ) {
    fd_bn254_fp52_pairing_proj_dbl( l, &tpts[j], &p_arr[j] );
    fd_bn254_fp52_fp12_mul_sparse( f, f, l );
  }
  fd_bn254_fp52_fp12_sqr( f, f );

  /* Second iteration: bit 63 (NAF value is 1, from the "0, 1" at the end).
     First the subtraction (NAF=-1 trick from gnark: sub then add),
     then the addition. */
  for( ulong j=0; j<sz; j++ ) {
    fd_bn254_fp52_pairing_proj_add_sub( l, &tpts[j], &q_arr[j], &p_arr[j], 0, 0 ); /* line only, no point update */
    fd_bn254_fp52_fp12_mul_sparse( f, f, l );

    fd_bn254_fp52_pairing_proj_add_sub( l, &tpts[j], &q_arr[j], &p_arr[j], 1, 1 );
    fd_bn254_fp52_fp12_mul_sparse( f, f, l );
  }

  /* Main loop: bits 62 down to 0 */
  for( int i = 65-3; i>=0; i-- ) {
    fd_bn254_fp52_fp12_sqr( f, f );

    for( ulong j=0; j<sz; j++ ) {
      fd_bn254_fp52_pairing_proj_dbl( l, &tpts[j], &p_arr[j] );
      fd_bn254_fp52_fp12_mul_sparse( f, f, l );
    }

    if( naf[i] != 0 ) {
      for( ulong j=0; j<sz; j++ ) {
        fd_bn254_fp52_pairing_proj_add_sub( l, &tpts[j], &q_arr[j], &p_arr[j], naf[i] > 0, 1 );
        fd_bn254_fp52_fp12_mul_sparse( f, f, l );
      }
    }
  }

  /* Frobenius correction terms.
     line(t, frob(Q), P) * line(t, -frob^2(Q), P) */
  for( ulong j=0; j<sz; j++ ) {
    fd_bn254_fp52_g2_frob( frob, &q_arr[j] );      /* frob(Q) */
    fd_bn254_fp52_pairing_proj_add_sub( l, &tpts[j], frob, &p_arr[j], 1, 1 );
    fd_bn254_fp52_fp12_mul_sparse( f, f, l );

    fd_bn254_fp52_g2_frob2( frob, &q_arr[j] );     /* frob^2(Q) */
    fd_bn254_fp52_g2_neg( frob, frob );              /* -frob^2(Q) */
    fd_bn254_fp52_pairing_proj_add_sub( l, &tpts[j], frob, &p_arr[j], 1, 0 ); /* line only */
    fd_bn254_fp52_fp12_mul_sparse( f, f, l );
  }

  return f;
}

FD_PROTOTYPES_END

#endif /* FD_HAS_AVX512 */

#endif /* HEADER_fd_src_ballet_bn254_avx512_fd_bn254_fp52_pairing_h */
