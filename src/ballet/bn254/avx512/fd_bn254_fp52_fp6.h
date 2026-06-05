#ifndef HEADER_fd_src_ballet_bn254_avx512_fd_bn254_fp52_fp6_h
#define HEADER_fd_src_ballet_bn254_avx512_fd_bn254_fp52_fp6_h

#if FD_HAS_AVX512

#include "fd_bn254_fp52_fp2.h"

/* fd_bn254_fp52_fp6_t represents an element of Fp6 = Fp2[v] / (v^3 - xi)
   where xi = 9 + i.  An Fp6 element is (el[0], el[1], el[2]) representing
   el[0] + el[1]*v + el[2]*v^2.

   Multiplication by v (the "gamma" operation) sends
     (a0, a1, a2) -> (xi * a2, a0, a1)
   since v^3 = xi. */

struct fd_bn254_fp52_fp6 {
  fd_bn254_fp52_fp2_t el[3];
};
typedef struct fd_bn254_fp52_fp6 fd_bn254_fp52_fp6_t;

FD_PROTOTYPES_BEGIN

/* ---- Utility functions (cheap, no batching) ---- */

FD_FN_UNUSED static inline fd_bn254_fp52_fp6_t *
fd_bn254_fp52_fp6_set_zero( fd_bn254_fp52_fp6_t * r ) {
  fd_bn254_fp52_fp2_set_zero( &r->el[0] );
  fd_bn254_fp52_fp2_set_zero( &r->el[1] );
  fd_bn254_fp52_fp2_set_zero( &r->el[2] );
  return r;
}

FD_FN_UNUSED static inline fd_bn254_fp52_fp6_t *
fd_bn254_fp52_fp6_set_one( fd_bn254_fp52_fp6_t * r ) {
  fd_bn254_fp52_fp2_set_one( &r->el[0] );
  fd_bn254_fp52_fp2_set_zero( &r->el[1] );
  fd_bn254_fp52_fp2_set_zero( &r->el[2] );
  return r;
}

FD_FN_UNUSED static inline fd_bn254_fp52_fp6_t *
fd_bn254_fp52_fp6_set( fd_bn254_fp52_fp6_t *       r,
                       fd_bn254_fp52_fp6_t const * a ) {
  fd_bn254_fp52_fp2_set( &r->el[0], &a->el[0] );
  fd_bn254_fp52_fp2_set( &r->el[1], &a->el[1] );
  fd_bn254_fp52_fp2_set( &r->el[2], &a->el[2] );
  return r;
}

FD_FN_UNUSED static inline int
fd_bn254_fp52_fp6_is_zero( fd_bn254_fp52_fp6_t const * a ) {
  return fd_bn254_fp52_fp2_is_zero( &a->el[0] ) &&
         fd_bn254_fp52_fp2_is_zero( &a->el[1] ) &&
         fd_bn254_fp52_fp2_is_zero( &a->el[2] );
}

FD_FN_UNUSED static inline int
fd_bn254_fp52_fp6_is_one( fd_bn254_fp52_fp6_t const * a ) {
  fd_bn254_fp52_fp2_t one[1];
  fd_bn254_fp52_fp2_set_one( one );
  return fd_bn254_fp52_fp2_eq( &a->el[0], one ) &&
         fd_bn254_fp52_fp2_is_zero( &a->el[1] ) &&
         fd_bn254_fp52_fp2_is_zero( &a->el[2] );
}

FD_FN_UNUSED static inline int
fd_bn254_fp52_fp6_eq( fd_bn254_fp52_fp6_t const * a,
                      fd_bn254_fp52_fp6_t const * b ) {
  return fd_bn254_fp52_fp2_eq( &a->el[0], &b->el[0] ) &&
         fd_bn254_fp52_fp2_eq( &a->el[1], &b->el[1] ) &&
         fd_bn254_fp52_fp2_eq( &a->el[2], &b->el[2] );
}

/* ---- Addition, subtraction, negation (3 Fp2 ops each) ---- */

FD_FN_UNUSED static inline fd_bn254_fp52_fp6_t *
fd_bn254_fp52_fp6_add( fd_bn254_fp52_fp6_t *       r,
                       fd_bn254_fp52_fp6_t const * a,
                       fd_bn254_fp52_fp6_t const * b ) {
  fd_bn254_fp52_fp2_add( &r->el[0], &a->el[0], &b->el[0] );
  fd_bn254_fp52_fp2_add( &r->el[1], &a->el[1], &b->el[1] );
  fd_bn254_fp52_fp2_add( &r->el[2], &a->el[2], &b->el[2] );
  return r;
}

FD_FN_UNUSED static inline fd_bn254_fp52_fp6_t *
fd_bn254_fp52_fp6_sub( fd_bn254_fp52_fp6_t *       r,
                       fd_bn254_fp52_fp6_t const * a,
                       fd_bn254_fp52_fp6_t const * b ) {
  fd_bn254_fp52_fp2_sub( &r->el[0], &a->el[0], &b->el[0] );
  fd_bn254_fp52_fp2_sub( &r->el[1], &a->el[1], &b->el[1] );
  fd_bn254_fp52_fp2_sub( &r->el[2], &a->el[2], &b->el[2] );
  return r;
}

FD_FN_UNUSED static inline fd_bn254_fp52_fp6_t *
fd_bn254_fp52_fp6_neg( fd_bn254_fp52_fp6_t *       r,
                       fd_bn254_fp52_fp6_t const * a ) {
  fd_bn254_fp52_fp2_neg( &r->el[0], &a->el[0] );
  fd_bn254_fp52_fp2_neg( &r->el[1], &a->el[1] );
  fd_bn254_fp52_fp2_neg( &r->el[2], &a->el[2] );
  return r;
}

/* ---- Multiply by gamma (v, the Fp6 generator) ----

   https://eprint.iacr.org/2010/354, Alg. 12.
   (a0, a1, a2) * v = (xi*a2, a0, a1)
   since v^3 = xi and v * (a0 + a1*v + a2*v^2) = xi*a2 + a0*v + a1*v^2. */

FD_FN_UNUSED static inline fd_bn254_fp52_fp6_t *
fd_bn254_fp52_fp6_mul_by_gamma( fd_bn254_fp52_fp6_t *       r,
                                fd_bn254_fp52_fp6_t const * a ) {
  fd_bn254_fp52_fp2_t t[1];
  fd_bn254_fp52_fp2_mul_by_xi( t, &a->el[2] );
  fd_bn254_fp52_fp2_set( &r->el[2], &a->el[1] );
  fd_bn254_fp52_fp2_set( &r->el[1], &a->el[0] );
  fd_bn254_fp52_fp2_set( &r->el[0], t );
  return r;
}

/* ---- Fp6 multiplication (Karatsuba, Alg. 13 of [2010/354]) ----

   6 Fp2 multiplications organized in 2 waves of 3 independent muls
   each, using fd_bn254_fp52_fp2_mul3 for batched execution.

   Given a = (a0, a1, a2), b = (b0, b1, b2):

   Wave 1 (3 independent Fp2 muls):
     a0b0 = a0 * b0
     a1b1 = a1 * b1
     a2b2 = a2 * b2

   Wave 2 (3 independent Fp2 muls):
     t0 = (a1+a2) * (b1+b2)   -> r0 = t0 - a1b1 - a2b2; r0 = xi*r0 + a0b0
     t2 = (a0+a2) * (b0+b2)   -> r2 = t2 - a0b0 - a2b2 + a1b1
     t1 = (a0+a1) * (b0+b1)   -> r1 = t1 - a0b0 - a1b1 + xi*a2b2 */

FD_FN_UNUSED static inline fd_bn254_fp52_fp6_t *
fd_bn254_fp52_fp6_mul( fd_bn254_fp52_fp6_t *       r,
                       fd_bn254_fp52_fp6_t const * a,
                       fd_bn254_fp52_fp6_t const * b ) {
  fd_bn254_fp52_fp2_t const * a0 = &a->el[0];
  fd_bn254_fp52_fp2_t const * a1 = &a->el[1];
  fd_bn254_fp52_fp2_t const * a2 = &a->el[2];
  fd_bn254_fp52_fp2_t const * b0 = &b->el[0];
  fd_bn254_fp52_fp2_t const * b1 = &b->el[1];
  fd_bn254_fp52_fp2_t const * b2 = &b->el[2];

  fd_bn254_fp52_fp2_t a0b0[1], a1b1[1], a2b2[1];
  fd_bn254_fp52_fp2_t sa01[1], sb01[1]; /* sums for cross products */
  fd_bn254_fp52_fp2_t sa02[1], sb02[1];
  fd_bn254_fp52_fp2_t sa12[1], sb12[1];
  fd_bn254_fp52_fp2_t t0[1], t1[1], t2[1];

  /* Wave 1: 3 independent Fp2 muls */
  fd_bn254_fp52_fp2_mul3( a0b0, a0, b0,
                          a1b1, a1, b1,
                          a2b2, a2, b2 );

  /* Precompute sums for wave 2 */
  fd_bn254_fp52_fp2_add( sa12, a1, a2 );
  fd_bn254_fp52_fp2_add( sb12, b1, b2 );
  fd_bn254_fp52_fp2_add( sa02, a0, a2 );
  fd_bn254_fp52_fp2_add( sb02, b0, b2 );
  fd_bn254_fp52_fp2_add( sa01, a0, a1 );
  fd_bn254_fp52_fp2_add( sb01, b0, b1 );

  /* Wave 2: 3 independent Fp2 muls */
  fd_bn254_fp52_fp2_mul3( t0, sa12, sb12,
                          t2, sa02, sb02,
                          t1, sa01, sb01 );

  /* Assemble r0 = xi * ((a1+a2)(b1+b2) - a1b1 - a2b2) + a0b0 */
  fd_bn254_fp52_fp2_sub( t0, t0, a1b1 );
  fd_bn254_fp52_fp2_sub( t0, t0, a2b2 );
  fd_bn254_fp52_fp2_mul_by_xi( t0, t0 );
  fd_bn254_fp52_fp2_add( &r->el[0], t0, a0b0 );

  /* Assemble r2 = (a0+a2)(b0+b2) - a0b0 - a2b2 + a1b1 */
  fd_bn254_fp52_fp2_sub( t2, t2, a0b0 );
  fd_bn254_fp52_fp2_sub( t2, t2, a2b2 );
  fd_bn254_fp52_fp2_add( &r->el[2], t2, a1b1 );

  /* Assemble r1 = (a0+a1)(b0+b1) - a0b0 - a1b1 + xi*a2b2 */
  fd_bn254_fp52_fp2_sub( t1, t1, a0b0 );
  fd_bn254_fp52_fp2_sub( t1, t1, a1b1 );
  fd_bn254_fp52_fp2_mul_by_xi( a2b2, a2b2 );
  fd_bn254_fp52_fp2_add( &r->el[1], t1, a2b2 );

  return r;
}

/* ---- Fp6 squaring (Alg. 16 of [2010/354]) ----

   From the scalar code:
     c4 = 2 * a0 * a1          (Fp2 mul)
     c5 = a2^2                  (Fp2 sqr) -- independent of c4

     c2_partial = c4 - c5       (will be completed later)
     c1 = c4 + xi*c5

     c3 = a0^2                  (Fp2 sqr)
     c4_in = a0 - a1 + a2
     c5 = 2 * a1 * a2          (Fp2 mul) -- independent of c3
     c4 = c4_in^2               (Fp2 sqr) -- independent of c5

     c2 = c2_partial + c4 + c5 - c3
     c0 = c3 + xi*c5

   Total: 2 Fp2 muls + 3 Fp2 sqrs. */

FD_FN_UNUSED static inline fd_bn254_fp52_fp6_t *
fd_bn254_fp52_fp6_sqr( fd_bn254_fp52_fp6_t *       r,
                       fd_bn254_fp52_fp6_t const * a ) {
  fd_bn254_fp52_fp2_t const * a0 = &a->el[0];
  fd_bn254_fp52_fp2_t const * a1 = &a->el[1];
  fd_bn254_fp52_fp2_t const * a2 = &a->el[2];
  fd_bn254_fp52_fp2_t c0[1], c1[1], c2[1];
  fd_bn254_fp52_fp2_t c3[1], c4[1], c5[1];

  /* c4 = 2 * a0 * a1 (Fp2 mul)
     c5 = a2^2         (Fp2 sqr)
     These are independent.  Compute sequentially using single
     operations (one mul, one sqr have different internal structure). */
  fd_bn254_fp52_fp2_mul( c4, a0, a1 );
  fd_bn254_fp52_fp2_add( c4, c4, c4 );  /* c4 = 2*a0*a1 */
  fd_bn254_fp52_fp2_sqr( c5, a2 );      /* c5 = a2^2 */

  /* c2_partial = c4 - c5 (saved in c2 for now) */
  fd_bn254_fp52_fp2_sub( c2, c4, c5 );

  /* c1 = c4 + xi*c5 */
  fd_bn254_fp52_fp2_mul_by_xi( c5, c5 );
  fd_bn254_fp52_fp2_add( c1, c4, c5 );

  /* c3 = a0^2 (Fp2 sqr) */
  fd_bn254_fp52_fp2_sqr( c3, a0 );

  /* c4_input = a0 - a1 + a2 */
  fd_bn254_fp52_fp2_sub( c4, a0, a1 );
  fd_bn254_fp52_fp2_add( c4, c4, a2 );

  /* c5 = 2 * a1 * a2 (Fp2 mul) -- independent of c3
     c4 = c4_input^2   (Fp2 sqr) -- independent of c5
     Compute sequentially. */
  fd_bn254_fp52_fp2_mul( c5, a1, a2 );
  fd_bn254_fp52_fp2_add( c5, c5, c5 );  /* c5 = 2*a1*a2 */
  fd_bn254_fp52_fp2_sqr( c4, c4 );      /* c4 = (a0-a1+a2)^2 */

  /* c2 = c2_partial + c4 + c5 - c3 */
  fd_bn254_fp52_fp2_add( c2, c2, c4 );
  fd_bn254_fp52_fp2_add( c2, c2, c5 );
  fd_bn254_fp52_fp2_sub( c2, c2, c3 );

  /* c0 = c3 + xi*c5 */
  fd_bn254_fp52_fp2_mul_by_xi( c5, c5 );
  fd_bn254_fp52_fp2_add( c0, c3, c5 );

  fd_bn254_fp52_fp2_set( &r->el[0], c0 );
  fd_bn254_fp52_fp2_set( &r->el[1], c1 );
  fd_bn254_fp52_fp2_set( &r->el[2], c2 );
  return r;
}

/* ---- Multiply by (b0, b1, 0) in Fp6 (sparse Karatsuba) ----

   Used in Fp12 sparse multiplication.
   Karatsuba with b2 = 0.  Cost: 5 Fp2 muls.

   From the scalar code:
     a0b0 = a0 * b0   \
     a1b1 = a1 * b1    > wave 1 (3 independent Fp2 muls)
     a2b1 = a2 * b1   /

     r0 = xi * a2b1 + a0b0

     sa = a0 + a1; sb = b0 + b1
     r1 = sa * sb - a0b0 - a1b1     \ wave 2 (2 independent Fp2 muls)

     sa2 = a0 + a2
     r2 = sa2 * b0 - a0b0 + a1b1   / */

FD_FN_UNUSED static inline fd_bn254_fp52_fp6_t *
fd_bn254_fp52_fp6_mul_by_01( fd_bn254_fp52_fp6_t *       r,
                             fd_bn254_fp52_fp6_t const * a,
                             fd_bn254_fp52_fp2_t const * b0,
                             fd_bn254_fp52_fp2_t const * b1 ) {
  fd_bn254_fp52_fp2_t const * a0 = &a->el[0];
  fd_bn254_fp52_fp2_t const * a1 = &a->el[1];
  fd_bn254_fp52_fp2_t const * a2 = &a->el[2];
  fd_bn254_fp52_fp2_t a0b0[1], a1b1[1], a2b1[1];
  fd_bn254_fp52_fp2_t sa[1], sb[1], sa2[1];
  fd_bn254_fp52_fp2_t r0[1], r1[1], r2[1];

  /* Wave 1: 3 independent Fp2 muls */
  fd_bn254_fp52_fp2_mul3( a0b0, a0, b0,
                          a1b1, a1, b1,
                          a2b1, a2, b1 );

  /* r0 = xi * a2b1 + a0b0 */
  fd_bn254_fp52_fp2_mul_by_xi( r0, a2b1 );
  fd_bn254_fp52_fp2_add( r0, r0, a0b0 );

  /* Precompute sums for wave 2 */
  fd_bn254_fp52_fp2_add( sa, a0, a1 );
  fd_bn254_fp52_fp2_add( sb, b0, b1 );
  fd_bn254_fp52_fp2_add( sa2, a0, a2 );

  /* Wave 2: 2 independent Fp2 muls */
  fd_bn254_fp52_fp2_mul2( r1, sa, sb,
                          r2, sa2, b0 );

  /* r1 = (a0+a1)*(b0+b1) - a0b0 - a1b1 */
  fd_bn254_fp52_fp2_sub( r1, r1, a0b0 );
  fd_bn254_fp52_fp2_sub( r1, r1, a1b1 );

  /* r2 = (a0+a2)*b0 - a0b0 + a1b1 */
  fd_bn254_fp52_fp2_sub( r2, r2, a0b0 );
  fd_bn254_fp52_fp2_add( r2, r2, a1b1 );

  fd_bn254_fp52_fp2_set( &r->el[0], r0 );
  fd_bn254_fp52_fp2_set( &r->el[1], r1 );
  fd_bn254_fp52_fp2_set( &r->el[2], r2 );
  return r;
}

/* ---- Multiply by a single Fp2 element ----

   r = a * (b, 0, 0) in Fp6.
   Simply r0 = a0*b, r1 = a1*b, r2 = a2*b.
   3 independent Fp2 muls -> use fp2_mul3. */

FD_FN_UNUSED static inline fd_bn254_fp52_fp6_t *
fd_bn254_fp52_fp6_mul_by_fp2( fd_bn254_fp52_fp6_t *       r,
                              fd_bn254_fp52_fp6_t const * a,
                              fd_bn254_fp52_fp2_t const * b ) {
  fd_bn254_fp52_fp2_mul3( &r->el[0], &a->el[0], b,
                          &r->el[1], &a->el[1], b,
                          &r->el[2], &a->el[2], b );
  return r;
}

/* ---- Fp2 inversion (needed for Fp6 inversion) ----

   fd_bn254_fp52_fp2_inv computes r = 1/a in Fp2.
   Algorithm 8 of [2010/354]:
     norm = a0^2 + a1^2
     inv_norm = norm^{p-2}  (Fp inversion via Fermat's little theorem)
     r0 =  a0 * inv_norm
     r1 = -a1 * inv_norm

   The Fp inversion uses a square-and-multiply chain on the scalar
   radix-2^52 representation.  This is the most expensive step. */

/* Scalar Fp mul via single-lane batched Montgomery multiply. */
static inline void
fd_bn254_fp52_mul_scalar( ulong       r[5],
                          ulong const a[5],
                          ulong const b[5] ) {
  fd_bn254_fp52x8_t ax, bx;
  fd_bn254_fp52x8_zero( &ax );
  fd_bn254_fp52x8_zero( &bx );
  fd_bn254_fp52x8_pack_lane( &ax, 0, a );
  fd_bn254_fp52x8_pack_lane( &bx, 0, b );
  fd_bn254_fp52x8_t px = fd_bn254_fp52x8_mul( &ax, &bx );
  fd_bn254_fp52x8_extract_lane( r, &px, 0 );
}

/* Scalar Fp sqr via single-lane batched Montgomery multiply. */
static inline void
fd_bn254_fp52_sqr_scalar( ulong       r[5],
                          ulong const a[5] ) {
  fd_bn254_fp52_mul_scalar( r, a, a );
}

/* fd_bn254_fp52_inv_scalar computes r = a^{-1} mod p = a^{p-2} mod p
   using square-and-multiply.

   p-2 = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd45

   We use a simple binary method scanning bits from MSB to LSB. */
static inline void
fd_bn254_fp52_inv_scalar( ulong       r[5],
                          ulong const a[5] ) {
  /* p - 2 in 4 x 64-bit limbs (little-endian) */
  ulong pm2[4] = {
    0x3c208c16d87cfd45UL,
    0x97816a916871ca8dUL,
    0xb85045b68181585dUL,
    0x30644e72e131a029UL
  };

  /* Start with r = 1 in Montgomery form */
  ulong acc[5] = {
    FD_BN254_FP52_ONE_0, FD_BN254_FP52_ONE_1, FD_BN254_FP52_ONE_2,
    FD_BN254_FP52_ONE_3, FD_BN254_FP52_ONE_4
  };

  /* Find the highest set bit.  p-2 has 254 bits, so bit 253 is set. */
  int started = 0;
  for( int i=255; i>=0; i-- ) {
    int limb_idx = i / 64;
    int bit_idx  = i % 64;
    int bit = (int)( ( pm2[limb_idx] >> bit_idx ) & 1UL );

    if( started ) {
      fd_bn254_fp52_sqr_scalar( acc, acc );
      if( bit ) {
        fd_bn254_fp52_mul_scalar( acc, acc, a );
      }
    } else if( bit ) {
      fd_bn254_fp52_set_scalar( acc, a );
      started = 1;
    }
  }

  fd_bn254_fp52_set_scalar( r, acc );
}

/* fd_bn254_fp52_fp2_inv computes r = 1/a in Fp2.
   Uses the norm-based formula: 1/(a0+a1*i) = conj(a) / |a|^2
   where |a|^2 = a0^2 + a1^2 (in Fp, since i^2 = -1). */
FD_FN_UNUSED static inline fd_bn254_fp52_fp2_t *
fd_bn254_fp52_fp2_inv( fd_bn254_fp52_fp2_t *       r,
                       fd_bn254_fp52_fp2_t const * a ) {
  /* norm = a0^2 + a1^2 */
  ulong t0[5], t1[5], norm[5], inv_norm[5];
  fd_bn254_fp52_sqr_scalar( t0, a->el[0] );
  fd_bn254_fp52_sqr_scalar( t1, a->el[1] );
  fd_bn254_fp52_add_scalar( norm, t0, t1 );

  /* inv_norm = norm^{p-2} */
  fd_bn254_fp52_inv_scalar( inv_norm, norm );

  /* r0 =  a0 * inv_norm
     r1 = -a1 * inv_norm */
  fd_bn254_fp52_mul_scalar( r->el[0], a->el[0], inv_norm );
  fd_bn254_fp52_mul_scalar( r->el[1], a->el[1], inv_norm );
  fd_bn254_fp52_neg_scalar( r->el[1], r->el[1] );
  return r;
}

/* ---- Fp6 inversion (Alg. 17 of [2010/354]) ----

   Given a = (a0, a1, a2), compute a^{-1} in Fp6.

   Step 1: Compute cofactors
     t0 = a0^2,  t1 = a1^2,  t2 = a2^2
     t3 = a0*a1, t4 = a0*a2, t5 = a1*a2

     c0 = t0 - xi * t5
     c1 = xi * t2 - t3
     c2 = t1 - t4

   Step 2: Compute norm
     t6 = a0*c0 + xi*(a2*c1 + a1*c2)
     t6_inv = t6^{-1}  (in Fp2)

   Step 3: Result
     r0 = c0 * t6_inv
     r1 = c1 * t6_inv
     r2 = c2 * t6_inv */

FD_FN_UNUSED static inline fd_bn254_fp52_fp6_t *
fd_bn254_fp52_fp6_inv( fd_bn254_fp52_fp6_t *       r,
                       fd_bn254_fp52_fp6_t const * a ) {
  fd_bn254_fp52_fp2_t t[6];

  /* t0 = a0^2, t1 = a1^2, t2 = a2^2 (3 independent sqrs) */
  fd_bn254_fp52_fp2_sqr3( &t[0], &a->el[0],
                          &t[1], &a->el[1],
                          &t[2], &a->el[2] );

  /* t3 = a0*a1, t4 = a0*a2, t5 = a1*a2 (3 independent muls) */
  fd_bn254_fp52_fp2_mul3( &t[3], &a->el[0], &a->el[1],
                          &t[4], &a->el[0], &a->el[2],
                          &t[5], &a->el[1], &a->el[2] );

  /* c0 = t0 - xi * t5 */
  fd_bn254_fp52_fp2_mul_by_xi( &t[5], &t[5] );
  fd_bn254_fp52_fp2_sub( &t[0], &t[0], &t[5] );

  /* c1 = xi * t2 - t3 */
  fd_bn254_fp52_fp2_mul_by_xi( &t[2], &t[2] );
  fd_bn254_fp52_fp2_sub( &t[2], &t[2], &t[3] );

  /* c2 = t1 - t4 */
  fd_bn254_fp52_fp2_sub( &t[1], &t[1], &t[4] );

  /* t6 = a0 * c0 (store in t3) */
  fd_bn254_fp52_fp2_mul( &t[3], &a->el[0], &t[0] );

  /* t6 += xi * a2 * c1 */
  fd_bn254_fp52_fp2_mul( &t[4], &a->el[2], &t[2] );
  fd_bn254_fp52_fp2_mul_by_xi( &t[4], &t[4] );
  fd_bn254_fp52_fp2_add( &t[3], &t[3], &t[4] );

  /* t6 += xi * a1 * c2 */
  fd_bn254_fp52_fp2_mul( &t[5], &a->el[1], &t[1] );
  fd_bn254_fp52_fp2_mul_by_xi( &t[5], &t[5] );
  fd_bn254_fp52_fp2_add( &t[3], &t[3], &t[5] );

  /* t4 = t6^{-1} */
  fd_bn254_fp52_fp2_inv( &t[4], &t[3] );

  /* r0 = c0 * t6_inv, r1 = c1 * t6_inv, r2 = c2 * t6_inv */
  fd_bn254_fp52_fp2_mul3( &r->el[0], &t[0], &t[4],
                          &r->el[1], &t[2], &t[4],
                          &r->el[2], &t[1], &t[4] );

  return r;
}

FD_PROTOTYPES_END

#endif /* FD_HAS_AVX512 */

#endif /* HEADER_fd_src_ballet_bn254_avx512_fd_bn254_fp52_fp6_h */
