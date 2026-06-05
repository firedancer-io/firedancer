#ifndef HEADER_fd_src_ballet_bn254_avx512_fd_bn254_fp52_fp12_h
#define HEADER_fd_src_ballet_bn254_avx512_fd_bn254_fp52_fp12_h

#if FD_HAS_AVX512

#include "fd_bn254_fp52_fp6.h"

/* fd_bn254_fp52_fp12_t represents an Fp12 element in the tower
   Fp12 = Fp6[w] / (w^2 - v), where v is the Fp6 generator (gamma).

   An element is (a0 + a1*w) with a0, a1 in Fp6.

   el[0] = a0,  el[1] = a1.

   The tower is:
     Fp2  = Fp[i]  / (i^2 + 1)        with xi = 9 + i
     Fp6  = Fp2[v] / (v^3 - xi)       with gamma = v
     Fp12 = Fp6[w] / (w^2 - v)

   Each Fp2 component is in radix-2^52 R=2^260 Montgomery form.

   Reference: https://eprint.iacr.org/2010/354 */

struct fd_bn254_fp52_fp12 {
  fd_bn254_fp52_fp6_t el[2];
};
typedef struct fd_bn254_fp52_fp12 fd_bn254_fp52_fp12_t;

FD_PROTOTYPES_BEGIN

/* ---- Utility functions ---- */

/* fd_bn254_fp52_fp12_set_one sets r = 1 in Fp12.
   That is el[0] = 1 (in Fp6), el[1] = 0. */
FD_FN_UNUSED static inline fd_bn254_fp52_fp12_t *
fd_bn254_fp52_fp12_set_one( fd_bn254_fp52_fp12_t * r ) {
  fd_bn254_fp52_fp6_set_one( &r->el[0] );
  fd_bn254_fp52_fp6_set_zero( &r->el[1] );
  return r;
}

/* fd_bn254_fp52_fp12_set copies a into r. */
FD_FN_UNUSED static inline fd_bn254_fp52_fp12_t *
fd_bn254_fp52_fp12_set( fd_bn254_fp52_fp12_t *       r,
                        fd_bn254_fp52_fp12_t const * a ) {
  fd_bn254_fp52_fp6_set( &r->el[0], &a->el[0] );
  fd_bn254_fp52_fp6_set( &r->el[1], &a->el[1] );
  return r;
}

/* fd_bn254_fp52_fp12_is_one returns 1 if a == 1 in Fp12. */
FD_FN_UNUSED static inline int
fd_bn254_fp52_fp12_is_one( fd_bn254_fp52_fp12_t const * a ) {
  return fd_bn254_fp52_fp6_is_one( &a->el[0] )
      && fd_bn254_fp52_fp6_is_zero( &a->el[1] );
}

/* fd_bn254_fp52_fp12_conj computes the Fp12 conjugation:
   r0 = a0, r1 = -a1.   (Since Fp12 = Fp6[w]/(w^2-v), conjugation
   negates the w coefficient.) */
FD_FN_UNUSED static inline fd_bn254_fp52_fp12_t *
fd_bn254_fp52_fp12_conj( fd_bn254_fp52_fp12_t *       r,
                         fd_bn254_fp52_fp12_t const * a ) {
  fd_bn254_fp52_fp6_set( &r->el[0], &a->el[0] );
  fd_bn254_fp52_fp6_neg( &r->el[1], &a->el[1] );
  return r;
}

/* ---- Multiplication (Karatsuba over Fp6, Alg. 20) ----

   r = a * b in Fp12.
     sa   = a0 + a1
     sb   = b0 + b1
     a0b0 = a0 * b0                (Fp6 mul)
     a1b1 = a1 * b1                (Fp6 mul)
     r1   = sa * sb - a0b0 - a1b1  (Fp6 mul + 2 Fp6 sub)
     r0   = a0b0 + gamma * a1b1

   Cost: 3 Fp6_mul. */
FD_FN_UNUSED static inline fd_bn254_fp52_fp12_t *
fd_bn254_fp52_fp12_mul( fd_bn254_fp52_fp12_t *       r,
                        fd_bn254_fp52_fp12_t const * a,
                        fd_bn254_fp52_fp12_t const * b ) {
  fd_bn254_fp52_fp6_t const * a0 = &a->el[0];
  fd_bn254_fp52_fp6_t const * a1 = &a->el[1];
  fd_bn254_fp52_fp6_t const * b0 = &b->el[0];
  fd_bn254_fp52_fp6_t const * b1 = &b->el[1];
  fd_bn254_fp52_fp6_t * r0 = &r->el[0];
  fd_bn254_fp52_fp6_t * r1 = &r->el[1];
  fd_bn254_fp52_fp6_t a0b0[1], a1b1[1], sa[1], sb[1];

  fd_bn254_fp52_fp6_add( sa, a0, a1 );
  fd_bn254_fp52_fp6_add( sb, b0, b1 );

  fd_bn254_fp52_fp6_mul( a0b0, a0, b0 );
  fd_bn254_fp52_fp6_mul( a1b1, a1, b1 );
  fd_bn254_fp52_fp6_mul( r1,   sa, sb );

  fd_bn254_fp52_fp6_sub( r1, r1, a0b0 );
  fd_bn254_fp52_fp6_sub( r1, r1, a1b1 );

  fd_bn254_fp52_fp6_mul_by_gamma( a1b1, a1b1 );
  fd_bn254_fp52_fp6_add( r0, a0b0, a1b1 );
  return r;
}

/* ---- Squaring (Alg. 22) ----

   r = a^2 in Fp12.
     c0 = a0 - a1
     c3 = a0 - gamma * a1
     c2 = a0 * a1               (Fp6 mul)
     c0 = c0 * c3               (Fp6 mul)
     c0 = c0 + c2
     r1 = 2 * c2
     r0 = c0 + gamma * c2

   Cost: 2 Fp6_mul. */
FD_FN_UNUSED static inline fd_bn254_fp52_fp12_t *
fd_bn254_fp52_fp12_sqr( fd_bn254_fp52_fp12_t *       r,
                        fd_bn254_fp52_fp12_t const * a ) {
  fd_bn254_fp52_fp6_t c0[1], c2[1], c3[1];

  fd_bn254_fp52_fp6_sub( c0, &a->el[0], &a->el[1] );
  fd_bn254_fp52_fp6_mul_by_gamma( c3, &a->el[1] );
  fd_bn254_fp52_fp6_sub( c3, &a->el[0], c3 );
  fd_bn254_fp52_fp6_mul( c2, &a->el[0], &a->el[1] );
  fd_bn254_fp52_fp6_mul( c0, c0, c3 );
  fd_bn254_fp52_fp6_add( c0, c0, c2 );
  fd_bn254_fp52_fp6_add( &r->el[1], c2, c2 );
  fd_bn254_fp52_fp6_mul_by_gamma( &r->el[0], c2 );
  fd_bn254_fp52_fp6_add( &r->el[0], &r->el[0], c0 );
  return r;
}

/* ---- Cyclotomic squaring (Alg. 24) — THE HOTTEST FUNCTION ----

   Cyclotomic squaring for elements satisfying a^(p^6+1) = 1.
   This is the case during the final exponentiation of pairing.

   Reference: https://eprint.iacr.org/2009/565, Sec. 3.2.
   Variant of https://eprint.iacr.org/2010/354, Alg. 24.

   The Fp12 element is viewed as 6 Fp2 components:
     g0 = a.el[0].el[0],  g1 = a.el[0].el[1],  g2 = a.el[0].el[2]
     h0 = a.el[1].el[0],  h1 = a.el[1].el[1],  h2 = a.el[1].el[2]

   Algorithm:
     t0 = h1^2,  t1 = g0^2,  t2 = g2^2,  t3 = h0^2  (4 sqrs: fp2_sqr4)
     t4 = h2^2,  t5 = g1^2                            (2 sqrs: fp2_sqr2)
     sum6 = h1 + g0,  sum7 = g2 + h0,  sum8 = h2 + g1
     t6 = sum6^2 - t0 - t1                            \
     t7 = sum7^2 - t2 - t3                             > 3 sqrs: fp2_sqr3
     t8 = sum8^2 - t4 - t5                            /

     t0 = xi*t0 + t1,  t2 = xi*t2 + t3,  t4 = xi*t4 + t5
     t8 = xi*t8

     r.g0 = 3*t0 - 2*g0
     r.g1 = 3*t2 - 2*g1
     r.g2 = 3*t4 - 2*g2
     r.h0 = 3*t8 + 2*h0
     r.h1 = 3*t6 + 2*h1
     r.h2 = 3*t7 + 2*h2 */
FD_FN_UNUSED static inline fd_bn254_fp52_fp12_t *
fd_bn254_fp52_fp12_sqr_fast( fd_bn254_fp52_fp12_t *       r,
                             fd_bn254_fp52_fp12_t const * a ) {
  fd_bn254_fp52_fp2_t t[9];

  /* Batch 1: 4 independent Fp2 squarings (8/8 lanes, perfect).
     t0 = h1^2,  t1 = g0^2,  t2 = g2^2,  t3 = h0^2 */
  fd_bn254_fp52_fp2_sqr4(
    &t[0], &a->el[1].el[1],
    &t[1], &a->el[0].el[0],
    &t[2], &a->el[0].el[2],
    &t[3], &a->el[1].el[0] );

  /* Batch 2: 2 independent Fp2 squarings (4/8 lanes).
     t4 = h2^2,  t5 = g1^2 */
  fd_bn254_fp52_fp2_sqr2(
    &t[4], &a->el[1].el[2],
    &t[5], &a->el[0].el[1] );

  /* Precompute sums for cross-terms */
  fd_bn254_fp52_fp2_t sum6, sum7, sum8;
  fd_bn254_fp52_fp2_add( &sum6, &a->el[1].el[1], &a->el[0].el[0] );
  fd_bn254_fp52_fp2_add( &sum7, &a->el[0].el[2], &a->el[1].el[0] );
  fd_bn254_fp52_fp2_add( &sum8, &a->el[1].el[2], &a->el[0].el[1] );

  /* Batch 3: 3 independent Fp2 squarings (6/8 lanes).
     t6s = sum6^2,  t7s = sum7^2,  t8s = sum8^2 */
  fd_bn254_fp52_fp2_t t6s, t7s, t8s;
  fd_bn254_fp52_fp2_sqr3(
    &t6s, &sum6,
    &t7s, &sum7,
    &t8s, &sum8 );

  /* Cross-terms: t6 = t6s - t0 - t1,  t7 = t7s - t2 - t3,
                  t8 = t8s - t4 - t5 */
  fd_bn254_fp52_fp2_sub( &t[6], &t6s, &t[0] );
  fd_bn254_fp52_fp2_sub( &t[6], &t[6], &t[1] );

  fd_bn254_fp52_fp2_sub( &t[7], &t7s, &t[2] );
  fd_bn254_fp52_fp2_sub( &t[7], &t[7], &t[3] );

  fd_bn254_fp52_fp2_sub( &t[8], &t8s, &t[4] );
  fd_bn254_fp52_fp2_sub( &t[8], &t[8], &t[5] );
  fd_bn254_fp52_fp2_mul_by_xi( &t[8], &t[8] );

  /* Assembly: combine pairs with xi multiplication.
     t0 = xi*t0 + t1  (c0 pair)
     t2 = xi*t2 + t3  (c2 pair)
     t4 = xi*t4 + t5  (c4 pair) */
  fd_bn254_fp52_fp2_mul_by_xi( &t[0], &t[0] );
  fd_bn254_fp52_fp2_add( &t[0], &t[0], &t[1] );

  fd_bn254_fp52_fp2_mul_by_xi( &t[2], &t[2] );
  fd_bn254_fp52_fp2_add( &t[2], &t[2], &t[3] );

  fd_bn254_fp52_fp2_mul_by_xi( &t[4], &t[4] );
  fd_bn254_fp52_fp2_add( &t[4], &t[4], &t[5] );

  /* Final assembly:
     r.g0 = 3*t0 - 2*g0  =>  tmp = t0 - g0; r.g0 = 2*tmp + t0
     r.g1 = 3*t2 - 2*g1
     r.g2 = 3*t4 - 2*g2
     r.h0 = 3*t8 + 2*h0  =>  tmp = t8 + h0; r.h0 = 2*tmp + t8
     r.h1 = 3*t6 + 2*h1
     r.h2 = 3*t7 + 2*h2 */

  /* g0: r.el[0].el[0] = 3*t0 - 2*g0 */
  fd_bn254_fp52_fp2_sub( &r->el[0].el[0], &t[0], &a->el[0].el[0] );
  fd_bn254_fp52_fp2_add( &r->el[0].el[0], &r->el[0].el[0], &r->el[0].el[0] );
  fd_bn254_fp52_fp2_add( &r->el[0].el[0], &r->el[0].el[0], &t[0] );

  /* g1: r.el[0].el[1] = 3*t2 - 2*g1 */
  fd_bn254_fp52_fp2_sub( &r->el[0].el[1], &t[2], &a->el[0].el[1] );
  fd_bn254_fp52_fp2_add( &r->el[0].el[1], &r->el[0].el[1], &r->el[0].el[1] );
  fd_bn254_fp52_fp2_add( &r->el[0].el[1], &r->el[0].el[1], &t[2] );

  /* g2: r.el[0].el[2] = 3*t4 - 2*g2 */
  fd_bn254_fp52_fp2_sub( &r->el[0].el[2], &t[4], &a->el[0].el[2] );
  fd_bn254_fp52_fp2_add( &r->el[0].el[2], &r->el[0].el[2], &r->el[0].el[2] );
  fd_bn254_fp52_fp2_add( &r->el[0].el[2], &r->el[0].el[2], &t[4] );

  /* h0: r.el[1].el[0] = 3*t8 + 2*h0 */
  fd_bn254_fp52_fp2_add( &r->el[1].el[0], &t[8], &a->el[1].el[0] );
  fd_bn254_fp52_fp2_add( &r->el[1].el[0], &r->el[1].el[0], &r->el[1].el[0] );
  fd_bn254_fp52_fp2_add( &r->el[1].el[0], &r->el[1].el[0], &t[8] );

  /* h1: r.el[1].el[1] = 3*t6 + 2*h1 */
  fd_bn254_fp52_fp2_add( &r->el[1].el[1], &t[6], &a->el[1].el[1] );
  fd_bn254_fp52_fp2_add( &r->el[1].el[1], &r->el[1].el[1], &r->el[1].el[1] );
  fd_bn254_fp52_fp2_add( &r->el[1].el[1], &r->el[1].el[1], &t[6] );

  /* h2: r.el[1].el[2] = 3*t7 + 2*h2 */
  fd_bn254_fp52_fp2_add( &r->el[1].el[2], &t[7], &a->el[1].el[2] );
  fd_bn254_fp52_fp2_add( &r->el[1].el[2], &r->el[1].el[2], &r->el[1].el[2] );
  fd_bn254_fp52_fp2_add( &r->el[1].el[2], &r->el[1].el[2], &t[7] );

  return r;
}

/* ---- Sparse multiplication (for Miller loop line functions) ----

   r = a * l in Fp12, where l has the "034" sparse pattern:
     l.el[0] = (c0, 0, 0)
     l.el[1] = (c3, c4, 0)

   This is the pattern produced by line evaluation functions.

   a0b0 = fp6_mul_by_fp2(a0, c0)        (3 Fp2_muls)
   a1b1 = fp6_mul_by_01(a1, c3, c4)     (5 Fp2_muls)
   sa   = a0 + a1
   sc0  = c0 + c3
   r1   = fp6_mul_by_01(sa, sc0, c4) - a0b0 - a1b1
   r0   = a0b0 + gamma * a1b1

   Cost: 13 Fp2_mul (vs 18 for full Fp12_mul). */
FD_FN_UNUSED static inline fd_bn254_fp52_fp12_t *
fd_bn254_fp52_fp12_mul_sparse( fd_bn254_fp52_fp12_t *       r,
                               fd_bn254_fp52_fp12_t const * a,
                               fd_bn254_fp52_fp12_t const * b ) {
  fd_bn254_fp52_fp2_t const * c0 = &b->el[0].el[0];
  fd_bn254_fp52_fp2_t const * c3 = &b->el[1].el[0];
  fd_bn254_fp52_fp2_t const * c4 = &b->el[1].el[1];
  fd_bn254_fp52_fp6_t a0b0[1], a1b1[1], sa[1];
  fd_bn254_fp52_fp2_t sc0[1];

  /* a0*b0 = a.el[0] * (c0, 0, 0) : 3 Fp2_mul */
  fd_bn254_fp52_fp6_mul_by_fp2( a0b0, &a->el[0], c0 );

  /* a1*b1 = a.el[1] * (c3, c4, 0) : 5 Fp2_mul */
  fd_bn254_fp52_fp6_mul_by_01( a1b1, &a->el[1], c3, c4 );

  /* r1 = (a0+a1) * (c0+c3, c4, 0) - a0b0 - a1b1 : 5 Fp2_mul */
  fd_bn254_fp52_fp6_add( sa, &a->el[0], &a->el[1] );
  fd_bn254_fp52_fp2_add( sc0, c0, c3 );
  fd_bn254_fp52_fp6_mul_by_01( &r->el[1], sa, sc0, c4 );
  fd_bn254_fp52_fp6_sub( &r->el[1], &r->el[1], a0b0 );
  fd_bn254_fp52_fp6_sub( &r->el[1], &r->el[1], a1b1 );

  /* r0 = a0b0 + gamma * a1b1 */
  fd_bn254_fp52_fp6_mul_by_gamma( a1b1, a1b1 );
  fd_bn254_fp52_fp6_add( &r->el[0], a0b0, a1b1 );
  return r;
}

/* ---- Inversion (Alg. 23) ----

   r = a^(-1) in Fp12.
     t0 = a0^2                 (Fp6 sqr)
     t1 = a1^2                 (Fp6 sqr)
     t0 = t0 - gamma * t1
     t1 = t0^(-1)              (Fp6 inv)
     r0 =  a0 * t1
     r1 = -a1 * t1 */
FD_FN_UNUSED static inline fd_bn254_fp52_fp12_t *
fd_bn254_fp52_fp12_inv( fd_bn254_fp52_fp12_t *       r,
                        fd_bn254_fp52_fp12_t const * a ) {
  fd_bn254_fp52_fp6_t t0[1], t1[1];

  fd_bn254_fp52_fp6_sqr( t0, &a->el[0] );
  fd_bn254_fp52_fp6_sqr( t1, &a->el[1] );
  fd_bn254_fp52_fp6_mul_by_gamma( t1, t1 );
  fd_bn254_fp52_fp6_sub( t0, t0, t1 );
  fd_bn254_fp52_fp6_inv( t1, t0 );
  fd_bn254_fp52_fp6_mul( &r->el[0], &a->el[0], t1 );
  fd_bn254_fp52_fp6_mul( &r->el[1], &a->el[1], t1 );
  fd_bn254_fp52_fp6_neg( &r->el[1], &r->el[1] );
  return r;
}

/* ---- Frobenius endomorphisms ----

   These require the Frobenius gamma constants, which are defined in
   the scalar code in R=2^256 Montgomery form (radix-2^64).  We need
   them in R=2^260 Montgomery form (radix-2^52).

   The conversion is:
     1. Radix convert from 2^64 to 2^52 (pure bit manipulation)
     2. Multiply by 16 mod p (4 doublings) to go from R=2^256 to R=2^260

   Since frob/frob2 are called only a few times per pairing (about 10
   times total), we convert inline.  TODO: precompute these constants. */

/* fd_bn254_fp52_fp_mul16 multiplies an Fp element (radix-2^52) by 16
   mod p using 4 doublings.  This converts from R=2^256 to R=2^260
   Montgomery form after radix conversion. */
FD_FN_UNUSED static inline void
fd_bn254_fp52_fp_mul16( ulong r[5], ulong const a[5] ) {
  ulong t[5];
  fd_bn254_fp52_add_scalar( t, a, a );   /* 2x */
  fd_bn254_fp52_add_scalar( t, t, t );   /* 4x */
  fd_bn254_fp52_add_scalar( t, t, t );   /* 8x */
  fd_bn254_fp52_add_scalar( r, t, t );   /* 16x */
}

/* fd_bn254_fp52_fp2_from_r256 converts an Fp2 element from R=2^256
   Montgomery (radix-2^64) to R=2^260 Montgomery (radix-2^52). */
FD_FN_UNUSED static inline void
fd_bn254_fp52_fp2_from_r256( fd_bn254_fp52_fp2_t *   r,
                             ulong const             a0_64[4],
                             ulong const             a1_64[4] ) {
  ulong t0[5], t1[5];
  fd_bn254_fp52_from64( t0, a0_64 );
  fd_bn254_fp52_from64( t1, a1_64 );
  fd_bn254_fp52_fp_mul16( r->el[0], t0 );
  fd_bn254_fp52_fp_mul16( r->el[1], t1 );
}

/* fd_bn254_fp52_fp_from_r256 converts an Fp element from R=2^256
   Montgomery (radix-2^64) to R=2^260 Montgomery (radix-2^52). */
FD_FN_UNUSED static inline void
fd_bn254_fp52_fp_from_r256( ulong       r[5],
                            ulong const a64[4] ) {
  ulong t[5];
  fd_bn254_fp52_from64( t, a64 );
  fd_bn254_fp52_fp_mul16( r, t );
}

/* fd_bn254_fp52_fp12_frob computes the Frobenius endomorphism r = a^p.

   Algorithm (Alg. 28 from [2010/354]):
     1. Conjugate each Fp2 component (negate imaginary part)
     2. Multiply by precomputed gamma_1 constants:
        g0 -> conj(g0)                   (conjugate only)
        g1 -> conj(g1) * gamma_1,2
        g2 -> conj(g2) * gamma_1,4
        h0 -> conj(h0) * gamma_1,1
        h1 -> conj(h1) * gamma_1,3
        h2 -> conj(h2) * gamma_1,5

   Gamma_1 constants are Fp2 values from fd_bn254_const_frob_gamma1_mont
   converted from R=2^256 to R=2^260 inline. */
FD_FN_UNUSED static inline fd_bn254_fp52_fp12_t *
fd_bn254_fp52_fp12_frob( fd_bn254_fp52_fp12_t *       r,
                         fd_bn254_fp52_fp12_t const * a ) {
  fd_bn254_fp52_fp2_t t[5];

  /* Conjugate all 6 Fp2 components */
  fd_bn254_fp52_fp2_conj( &r->el[0].el[0], &a->el[0].el[0] );
  fd_bn254_fp52_fp2_conj( &t[0], &a->el[0].el[1] );
  fd_bn254_fp52_fp2_conj( &t[1], &a->el[0].el[2] );
  fd_bn254_fp52_fp2_conj( &t[2], &a->el[1].el[0] );
  fd_bn254_fp52_fp2_conj( &t[3], &a->el[1].el[1] );
  fd_bn254_fp52_fp2_conj( &t[4], &a->el[1].el[2] );

  /* Convert gamma_1 constants from R=2^256 to R=2^260 and multiply.
     TODO: precompute these conversions for better performance. */

  /* conj(g1) * gamma_1,2 */
  {
    fd_bn254_fp52_fp2_t gamma;
    ulong g_re[4] = { 0xb5773b104563ab30UL, 0x347f91c8a9aa6454UL,
                       0x7a007127242e0991UL, 0x1956bcd8118214ecUL };
    ulong g_im[4] = { 0x6e849f1ea0aa4757UL, 0xaa1c7b6d89f89141UL,
                       0xb6e713cdfae0ca3aUL, 0x26694fbb4e82ebc3UL };
    fd_bn254_fp52_fp2_from_r256( &gamma, g_re, g_im );
    fd_bn254_fp52_fp2_mul( &r->el[0].el[1], &t[0], &gamma );
  }

  /* conj(g2) * gamma_1,4 */
  {
    fd_bn254_fp52_fp2_t gamma;
    ulong g_re[4] = { 0x7361d77f843abe92UL, 0xa5bb2bd3273411fbUL,
                       0x9c941f314b3e2399UL, 0x15df9cddbb9fd3ecUL };
    ulong g_im[4] = { 0x5dddfd154bd8c949UL, 0x62cb29a5a4445b60UL,
                       0x37bc870a0c7dd2b9UL, 0x24830a9d3171f0fdUL };
    fd_bn254_fp52_fp2_from_r256( &gamma, g_re, g_im );
    fd_bn254_fp52_fp2_mul( &r->el[0].el[2], &t[1], &gamma );
  }

  /* conj(h0) * gamma_1,1 */
  {
    fd_bn254_fp52_fp2_t gamma;
    ulong g_re[4] = { 0xaf9ba69633144907UL, 0xca6b1d7387afb78aUL,
                       0x11bded5ef08a2087UL, 0x02f34d751a1f3a7cUL };
    ulong g_im[4] = { 0xa222ae234c492d72UL, 0xd00f02a4565de15bUL,
                       0xdc2ff3a253dfc926UL, 0x10a75716b3899551UL };
    fd_bn254_fp52_fp2_from_r256( &gamma, g_re, g_im );
    fd_bn254_fp52_fp2_mul( &r->el[1].el[0], &t[2], &gamma );
  }

  /* conj(h1) * gamma_1,3 */
  {
    fd_bn254_fp52_fp2_t gamma;
    ulong g_re[4] = { 0xe4bbdd0c2936b629UL, 0xbb30f162e133bacbUL,
                       0x31a9d1b6f9645366UL, 0x253570bea500f8ddUL };
    ulong g_im[4] = { 0xa1d77ce45ffe77c7UL, 0x07affd117826d1dbUL,
                       0x6d16bd27bb7edc6bUL, 0x2c87200285defeccUL };
    fd_bn254_fp52_fp2_from_r256( &gamma, g_re, g_im );
    fd_bn254_fp52_fp2_mul( &r->el[1].el[1], &t[3], &gamma );
  }

  /* conj(h2) * gamma_1,5 */
  {
    fd_bn254_fp52_fp2_t gamma;
    ulong g_re[4] = { 0xc970692f41690fe7UL, 0xe240342127694b0bUL,
                       0x32bee66b83c459e8UL, 0x12aabced0ab08841UL };
    ulong g_im[4] = { 0x0d485d2340aebfa9UL, 0x05193418ab2fcc57UL,
                       0xd3b0a40b8a4910f5UL, 0x2f21ebb535d2925aUL };
    fd_bn254_fp52_fp2_from_r256( &gamma, g_re, g_im );
    fd_bn254_fp52_fp2_mul( &r->el[1].el[2], &t[4], &gamma );
  }

  return r;
}

/* fd_bn254_fp52_fp12_frob2 computes r = a^(p^2).

   Algorithm (Alg. 29 from [2010/354]):
     No conjugation needed (p^2 acts trivially on Fp2).
     Multiply by gamma_2 constants (Fp scalars, not Fp2):
       g0 -> g0                     (identity)
       g1 -> g1 * gamma_2,2
       g2 -> g2 * gamma_2,4
       h0 -> h0 * gamma_2,1
       h1 -> h1 * gamma_2,3
       h2 -> h2 * gamma_2,5

   Since gamma_2 values are Fp (not Fp2), the multiplication of an
   Fp2 element (a0 + a1*i) by a scalar c gives (c*a0 + c*a1*i),
   i.e., multiply each component independently.

   We batch 10 Fp multiplications into two SIMD batches:
     Batch 1 (8/8): g1.re*g2_2, g1.im*g2_2, g2.re*g2_4, g2.im*g2_4,
                    h0.re*g2_1, h0.im*g2_1, h1.re*g2_3, h1.im*g2_3
     Batch 2 (2/8): h2.re*g2_5, h2.im*g2_5 */
FD_FN_UNUSED static inline fd_bn254_fp52_fp12_t *
fd_bn254_fp52_fp12_frob2( fd_bn254_fp52_fp12_t *       r,
                          fd_bn254_fp52_fp12_t const * a ) {
  /* gamma_2 constants in R=2^256 Montgomery (radix-2^64) */
  static const ulong gamma2_1_64[4] = { 0xca8d800500fa1bf2UL, 0xf0c5d61468b39769UL,
                                         0x0e201271ad0d4418UL, 0x04290f65bad856e6UL };
  static const ulong gamma2_2_64[4] = { 0x3350c88e13e80b9cUL, 0x7dce557cdb5e56b9UL,
                                         0x6001b4b8b615564aUL, 0x2682e617020217e0UL };
  static const ulong gamma2_3_64[4] = { 0x68c3488912edefaaUL, 0x8d087f6872aabf4fUL,
                                         0x51e1a24709081231UL, 0x2259d6b14729c0faUL };
  static const ulong gamma2_4_64[4] = { 0x71930c11d782e155UL, 0xa6bb947cffbe3323UL,
                                         0xaa303344d4741444UL, 0x2c3b3f0d26594943UL };
  static const ulong gamma2_5_64[4] = { 0x08cfc388c494f1abUL, 0x19b315148d1373d4UL,
                                         0x584e90fdcb6c0213UL, 0x09e1685bdf2f8849UL };

  /* Convert gamma_2 constants to R=2^260 (radix-2^52).
     TODO: precompute these for better performance. */
  ulong g2_1[5], g2_2[5], g2_3[5], g2_4[5], g2_5[5];
  fd_bn254_fp52_fp_from_r256( g2_1, gamma2_1_64 );
  fd_bn254_fp52_fp_from_r256( g2_2, gamma2_2_64 );
  fd_bn254_fp52_fp_from_r256( g2_3, gamma2_3_64 );
  fd_bn254_fp52_fp_from_r256( g2_4, gamma2_4_64 );
  fd_bn254_fp52_fp_from_r256( g2_5, gamma2_5_64 );

  /* g0: identity */
  fd_bn254_fp52_fp2_set( &r->el[0].el[0], &a->el[0].el[0] );

  /* Batch 1 (8/8 lanes): 4 Fp2 * Fp scalar multiplications.
       lane 0: g1.re * gamma2_2    lane 1: g1.im * gamma2_2
       lane 2: g2.re * gamma2_4    lane 3: g2.im * gamma2_4
       lane 4: h0.re * gamma2_1    lane 5: h0.im * gamma2_1
       lane 6: h1.re * gamma2_3    lane 7: h1.im * gamma2_3 */
  fd_bn254_fp52x8_t ax, bx;
  fd_bn254_fp52x8_zero( &ax );
  fd_bn254_fp52x8_zero( &bx );

  fd_bn254_fp52x8_pack_lane( &ax, 0, a->el[0].el[1].el[0] );
  fd_bn254_fp52x8_pack_lane( &bx, 0, g2_2 );
  fd_bn254_fp52x8_pack_lane( &ax, 1, a->el[0].el[1].el[1] );
  fd_bn254_fp52x8_pack_lane( &bx, 1, g2_2 );

  fd_bn254_fp52x8_pack_lane( &ax, 2, a->el[0].el[2].el[0] );
  fd_bn254_fp52x8_pack_lane( &bx, 2, g2_4 );
  fd_bn254_fp52x8_pack_lane( &ax, 3, a->el[0].el[2].el[1] );
  fd_bn254_fp52x8_pack_lane( &bx, 3, g2_4 );

  fd_bn254_fp52x8_pack_lane( &ax, 4, a->el[1].el[0].el[0] );
  fd_bn254_fp52x8_pack_lane( &bx, 4, g2_1 );
  fd_bn254_fp52x8_pack_lane( &ax, 5, a->el[1].el[0].el[1] );
  fd_bn254_fp52x8_pack_lane( &bx, 5, g2_1 );

  fd_bn254_fp52x8_pack_lane( &ax, 6, a->el[1].el[1].el[0] );
  fd_bn254_fp52x8_pack_lane( &bx, 6, g2_3 );
  fd_bn254_fp52x8_pack_lane( &ax, 7, a->el[1].el[1].el[1] );
  fd_bn254_fp52x8_pack_lane( &bx, 7, g2_3 );

  fd_bn254_fp52x8_t px1 = fd_bn254_fp52x8_mul( &ax, &bx );

  /* Batch 2 (2/8 lanes): 1 Fp2 * Fp scalar multiplication.
       lane 0: h2.re * gamma2_5    lane 1: h2.im * gamma2_5 */
  fd_bn254_fp52x8_zero( &ax );
  fd_bn254_fp52x8_zero( &bx );
  fd_bn254_fp52x8_pack_lane( &ax, 0, a->el[1].el[2].el[0] );
  fd_bn254_fp52x8_pack_lane( &bx, 0, g2_5 );
  fd_bn254_fp52x8_pack_lane( &ax, 1, a->el[1].el[2].el[1] );
  fd_bn254_fp52x8_pack_lane( &bx, 1, g2_5 );

  fd_bn254_fp52x8_t px2 = fd_bn254_fp52x8_mul( &ax, &bx );

  /* Extract results */
  fd_bn254_fp52x8_extract_lane( r->el[0].el[1].el[0], &px1, 0 );  /* g1.re * gamma2_2 */
  fd_bn254_fp52x8_extract_lane( r->el[0].el[1].el[1], &px1, 1 );  /* g1.im * gamma2_2 */
  fd_bn254_fp52x8_extract_lane( r->el[0].el[2].el[0], &px1, 2 );  /* g2.re * gamma2_4 */
  fd_bn254_fp52x8_extract_lane( r->el[0].el[2].el[1], &px1, 3 );  /* g2.im * gamma2_4 */
  fd_bn254_fp52x8_extract_lane( r->el[1].el[0].el[0], &px1, 4 );  /* h0.re * gamma2_1 */
  fd_bn254_fp52x8_extract_lane( r->el[1].el[0].el[1], &px1, 5 );  /* h0.im * gamma2_1 */
  fd_bn254_fp52x8_extract_lane( r->el[1].el[1].el[0], &px1, 6 );  /* h1.re * gamma2_3 */
  fd_bn254_fp52x8_extract_lane( r->el[1].el[1].el[1], &px1, 7 );  /* h1.im * gamma2_3 */
  fd_bn254_fp52x8_extract_lane( r->el[1].el[2].el[0], &px2, 0 );  /* h2.re * gamma2_5 */
  fd_bn254_fp52x8_extract_lane( r->el[1].el[2].el[1], &px2, 1 );  /* h2.im * gamma2_5 */

  return r;
}

/* ---- Exponentiation by BN254 parameter x ----

   x = 0x44e992b44a6909f1 (the BN254 curve parameter).

   Uses an addition chain of cyclotomic squarings and multiplications.
   Reference: https://github.com/Consensys/gnark-crypto/blob/v0.12.1/ecc/bn254/internal/fptower/e12_pairing.go#L16 */
FD_FN_UNUSED static inline fd_bn254_fp52_fp12_t *
fd_bn254_fp52_fp12_pow_x( fd_bn254_fp52_fp12_t *         r,
                          fd_bn254_fp52_fp12_t const *    a ) {
  fd_bn254_fp52_fp12_t t[7];

  fd_bn254_fp52_fp12_sqr_fast( &t[3], a );
  fd_bn254_fp52_fp12_sqr_fast( &t[5], &t[3] );
  fd_bn254_fp52_fp12_sqr_fast( r,     &t[5] );
  fd_bn254_fp52_fp12_sqr_fast( &t[0], r );
  fd_bn254_fp52_fp12_mul     ( &t[2], &t[0], a );
  fd_bn254_fp52_fp12_mul     ( &t[0], &t[2], &t[3] );
  fd_bn254_fp52_fp12_mul     ( &t[1], &t[0], a );
  fd_bn254_fp52_fp12_mul     ( &t[4], &t[2], r );
  fd_bn254_fp52_fp12_sqr_fast( &t[6], &t[2] );
  fd_bn254_fp52_fp12_mul     ( &t[1], &t[1], &t[0] );
  fd_bn254_fp52_fp12_mul     ( &t[0], &t[1], &t[3] );

  for( int i=0; i<6; i++ ) fd_bn254_fp52_fp12_sqr_fast( &t[6], &t[6] );
  fd_bn254_fp52_fp12_mul     ( &t[5], &t[5], &t[6] );
  fd_bn254_fp52_fp12_mul     ( &t[5], &t[5], &t[4] );

  for( int i=0; i<7; i++ ) fd_bn254_fp52_fp12_sqr_fast( &t[5], &t[5] );
  fd_bn254_fp52_fp12_mul     ( &t[4], &t[4], &t[5] );

  for( int i=0; i<8; i++ ) fd_bn254_fp52_fp12_sqr_fast( &t[4], &t[4] );
  fd_bn254_fp52_fp12_mul     ( &t[4], &t[4], &t[0] );
  fd_bn254_fp52_fp12_mul     ( &t[3], &t[3], &t[4] );

  for( int i=0; i<6; i++ ) fd_bn254_fp52_fp12_sqr_fast( &t[3], &t[3] );
  fd_bn254_fp52_fp12_mul     ( &t[2], &t[2], &t[3] );

  for( int i=0; i<8; i++ ) fd_bn254_fp52_fp12_sqr_fast( &t[2], &t[2] );
  fd_bn254_fp52_fp12_mul     ( &t[2], &t[2], &t[0] );

  for( int i=0; i<6; i++ ) fd_bn254_fp52_fp12_sqr_fast( &t[2], &t[2] );
  fd_bn254_fp52_fp12_mul     ( &t[2], &t[2], &t[0] );

  for( int i=0; i<10; i++ ) fd_bn254_fp52_fp12_sqr_fast( &t[2], &t[2] );
  fd_bn254_fp52_fp12_mul     ( &t[1], &t[1], &t[2] );

  for( int i=0; i<6; i++ ) fd_bn254_fp52_fp12_sqr_fast( &t[1], &t[1] );
  fd_bn254_fp52_fp12_mul     ( &t[0], &t[0], &t[1] );

  fd_bn254_fp52_fp12_mul     ( r, r, &t[0] );
  return r;
}

/* ---- Final exponentiation ----

   Computes r = x^((p^12 - 1) / r) where r is the group order.
   This is decomposed into:
     1. Easy part:  x^(p^6 - 1) * x^(p^2 + 1)
     2. Hard part:  addition chain using pow_x, frob, frob2, sqr_fast

   Reference: https://github.com/Consensys/gnark-crypto/blob/v0.12.1/ecc/bn254/pairing.go#L62
   and https://eprint.iacr.org/2015/192, Alg. 10. */
FD_FN_UNUSED static inline fd_bn254_fp52_fp12_t *
fd_bn254_fp52_final_exp( fd_bn254_fp52_fp12_t *       r,
                         fd_bn254_fp52_fp12_t * const x ) {
  fd_bn254_fp52_fp12_t t[5], s[1];

  /* Easy part: x^(p^6-1)(p^2+1) */
  fd_bn254_fp52_fp12_conj ( &t[0], x );             /* x^(p^6) */
  fd_bn254_fp52_fp12_inv  ( &t[1], x );             /* x^(-1) */
  fd_bn254_fp52_fp12_mul  ( &t[0], &t[0], &t[1] );  /* x^(p^6-1) */
  fd_bn254_fp52_fp12_frob2( &t[2], &t[0] );         /* x^(p^6-1)(p^2) */
  fd_bn254_fp52_fp12_mul  ( s, &t[0], &t[2] );      /* x^(p^6-1)(p^2+1) */

  /* Hard part: fast chain from [2015/192], Alg. 10.
     Variant of [2010/354], Alg. 31. */
  fd_bn254_fp52_fp12_pow_x   ( &t[0], s );
  fd_bn254_fp52_fp12_conj    ( &t[0], &t[0] );
  fd_bn254_fp52_fp12_sqr_fast( &t[0], &t[0] );
  fd_bn254_fp52_fp12_sqr_fast( &t[1], &t[0] );
  fd_bn254_fp52_fp12_mul     ( &t[1], &t[1], &t[0] );

  fd_bn254_fp52_fp12_pow_x   ( &t[2], &t[1] );
  fd_bn254_fp52_fp12_conj    ( &t[2], &t[2] );
  fd_bn254_fp52_fp12_conj    ( &t[3], &t[1] );
  fd_bn254_fp52_fp12_mul     ( &t[1], &t[2], &t[3] );

  fd_bn254_fp52_fp12_sqr_fast( &t[3], &t[2] );
  fd_bn254_fp52_fp12_pow_x   ( &t[4], &t[3] );
  fd_bn254_fp52_fp12_mul     ( &t[4], &t[1], &t[4] );
  fd_bn254_fp52_fp12_mul     ( &t[3], &t[0], &t[4] );
  fd_bn254_fp52_fp12_mul     ( &t[0], &t[2], &t[4] );
  fd_bn254_fp52_fp12_mul     ( &t[0], &t[0], s );

  fd_bn254_fp52_fp12_frob    ( &t[2], &t[3] );
  fd_bn254_fp52_fp12_mul     ( &t[0], &t[0], &t[2] );
  fd_bn254_fp52_fp12_frob2   ( &t[2], &t[4] );
  fd_bn254_fp52_fp12_mul     ( &t[0], &t[0], &t[2] );

  fd_bn254_fp52_fp12_conj    ( &t[2], s );
  fd_bn254_fp52_fp12_mul     ( &t[2], &t[2], &t[3] );
  /* frob3 = frob2 o frob (no dedicated frob3 implementation) */
  fd_bn254_fp52_fp12_frob2   ( &t[2], &t[2] );
  fd_bn254_fp52_fp12_frob    ( &t[2], &t[2] );
  fd_bn254_fp52_fp12_mul     ( r, &t[0], &t[2] );
  return r;
}

FD_PROTOTYPES_END

#endif /* FD_HAS_AVX512 */

#endif /* HEADER_fd_src_ballet_bn254_avx512_fd_bn254_fp52_fp12_h */
