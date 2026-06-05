#ifndef HEADER_fd_src_ballet_bn254_avx512_fd_bn254_fp52_fp2_h
#define HEADER_fd_src_ballet_bn254_avx512_fd_bn254_fp52_fp2_h

#if FD_HAS_AVX512

#include "fd_bn254_fp52_mul.h"

/* fd_bn254_fp52_fp2_t represents an Fp2 element (a0 + a1*i) where
   i^2 = -1, with each component in radix-2^52 R=2^260 Montgomery form.

   el[0] = a0 (real part), el[1] = a1 (imaginary part).
   Each component is 5 ulong limbs in radix-2^52. */

struct fd_bn254_fp52_fp2 {
  ulong el[2][5];
};
typedef struct fd_bn254_fp52_fp2 fd_bn254_fp52_fp2_t;

FD_PROTOTYPES_BEGIN

/* Scalar-limb Fp helpers for radix-2^52 representation.
   These operate on single ulong[5] field elements (not batched). */

static inline void
fd_bn254_fp52_add_scalar( ulong       r[5],
                          ulong const a[5],
                          ulong const b[5] ) {
  ulong const mask52 = FD_BN254_FP52_MASK;

  /* Limb-wise addition */
  ulong t0 = a[0] + b[0];
  ulong t1 = a[1] + b[1];
  ulong t2 = a[2] + b[2];
  ulong t3 = a[3] + b[3];
  ulong t4 = a[4] + b[4];

  /* Carry propagation */
  t1 += t0 >> 52; t0 &= mask52;
  t2 += t1 >> 52; t1 &= mask52;
  t3 += t2 >> 52; t2 &= mask52;
  t4 += t3 >> 52; t3 &= mask52;

  /* Conditional subtraction of p if t >= p.
     Since a, b < p, we have t < 2p, so at most one subtraction. */
  ulong d0, d1, d2, d3, d4;
  int borrow;

  d0 = t0 - FD_BN254_FP52_P0;
  borrow = (t0 < FD_BN254_FP52_P0);

  d1 = t1 - FD_BN254_FP52_P1 - (ulong)borrow;
  borrow = (t1 < FD_BN254_FP52_P1 + (ulong)borrow) ? 1 :
           (t1 == FD_BN254_FP52_P1 && borrow)       ? 1 : 0;

  d2 = t2 - FD_BN254_FP52_P2 - (ulong)borrow;
  borrow = (t2 < FD_BN254_FP52_P2 + (ulong)borrow) ? 1 :
           (t2 == FD_BN254_FP52_P2 && borrow)       ? 1 : 0;

  d3 = t3 - FD_BN254_FP52_P3 - (ulong)borrow;
  borrow = (t3 < FD_BN254_FP52_P3 + (ulong)borrow) ? 1 :
           (t3 == FD_BN254_FP52_P3 && borrow)       ? 1 : 0;

  d4 = t4 - FD_BN254_FP52_P4 - (ulong)borrow;
  borrow = (t4 < FD_BN254_FP52_P4 + (ulong)borrow) ? 1 :
           (t4 == FD_BN254_FP52_P4 && borrow)       ? 1 : 0;

  d0 &= mask52; d1 &= mask52; d2 &= mask52; d3 &= mask52; d4 &= mask52;

  /* If borrow, t < p: keep t. Otherwise use d = t - p. */
  if( borrow ) { r[0]=t0; r[1]=t1; r[2]=t2; r[3]=t3; r[4]=t4; }
  else         { r[0]=d0; r[1]=d1; r[2]=d2; r[3]=d3; r[4]=d4; }
}

static inline void
fd_bn254_fp52_sub_scalar( ulong       r[5],
                          ulong const a[5],
                          ulong const b[5] ) {
  ulong const mask52 = FD_BN254_FP52_MASK;

  /* Multi-limb subtraction d = a - b with borrow. */
  ulong d0, d1, d2, d3, d4;
  int borrow;

  d0 = a[0] - b[0];
  borrow = (a[0] < b[0]);

  d1 = a[1] - b[1] - (ulong)borrow;
  borrow = (a[1] < b[1] + (ulong)borrow) ? 1 :
           (a[1] == b[1] && borrow)       ? 1 : 0;

  d2 = a[2] - b[2] - (ulong)borrow;
  borrow = (a[2] < b[2] + (ulong)borrow) ? 1 :
           (a[2] == b[2] && borrow)       ? 1 : 0;

  d3 = a[3] - b[3] - (ulong)borrow;
  borrow = (a[3] < b[3] + (ulong)borrow) ? 1 :
           (a[3] == b[3] && borrow)       ? 1 : 0;

  d4 = a[4] - b[4] - (ulong)borrow;
  borrow = (a[4] < b[4] + (ulong)borrow) ? 1 :
           (a[4] == b[4] && borrow)       ? 1 : 0;

  d0 &= mask52; d1 &= mask52; d2 &= mask52; d3 &= mask52; d4 &= mask52;

  /* If borrow, a < b: add p to correct. */
  if( borrow ) {
    ulong c;
    d0 += FD_BN254_FP52_P0; c = d0>>52; d0 &= mask52;
    d1 += FD_BN254_FP52_P1 + c; c = d1>>52; d1 &= mask52;
    d2 += FD_BN254_FP52_P2 + c; c = d2>>52; d2 &= mask52;
    d3 += FD_BN254_FP52_P3 + c; c = d3>>52; d3 &= mask52;
    d4 += FD_BN254_FP52_P4 + c; d4 &= mask52;
  }

  r[0]=d0; r[1]=d1; r[2]=d2; r[3]=d3; r[4]=d4;
}

static inline void
fd_bn254_fp52_neg_scalar( ulong       r[5],
                          ulong const a[5] ) {
  /* -a mod p = p - a (unless a == 0). */
  if( a[0]==0 && a[1]==0 && a[2]==0 && a[3]==0 && a[4]==0 ) {
    r[0]=0; r[1]=0; r[2]=0; r[3]=0; r[4]=0;
    return;
  }
  ulong const mask52 = FD_BN254_FP52_MASK;
  ulong d0, d1, d2, d3, d4;
  int borrow;

  d0 = FD_BN254_FP52_P0 - a[0];
  borrow = (FD_BN254_FP52_P0 < a[0]);

  d1 = FD_BN254_FP52_P1 - a[1] - (ulong)borrow;
  borrow = (FD_BN254_FP52_P1 < a[1] + (ulong)borrow) ? 1 :
           (FD_BN254_FP52_P1 == a[1] && borrow)       ? 1 : 0;

  d2 = FD_BN254_FP52_P2 - a[2] - (ulong)borrow;
  borrow = (FD_BN254_FP52_P2 < a[2] + (ulong)borrow) ? 1 :
           (FD_BN254_FP52_P2 == a[2] && borrow)       ? 1 : 0;

  d3 = FD_BN254_FP52_P3 - a[3] - (ulong)borrow;
  borrow = (FD_BN254_FP52_P3 < a[3] + (ulong)borrow) ? 1 :
           (FD_BN254_FP52_P3 == a[3] && borrow)       ? 1 : 0;

  d4 = FD_BN254_FP52_P4 - a[4] - (ulong)borrow;
  (void)borrow;

  r[0] = d0 & mask52;
  r[1] = d1 & mask52;
  r[2] = d2 & mask52;
  r[3] = d3 & mask52;
  r[4] = d4 & mask52;
}

static inline void
fd_bn254_fp52_set_scalar( ulong r[5], ulong const a[5] ) {
  r[0]=a[0]; r[1]=a[1]; r[2]=a[2]; r[3]=a[3]; r[4]=a[4];
}

/* ---- Fp2 utility functions (operate on scalar limbs) ---- */

static inline fd_bn254_fp52_fp2_t *
fd_bn254_fp52_fp2_set_zero( fd_bn254_fp52_fp2_t * r ) {
  for( int i=0; i<5; i++ ) { r->el[0][i] = 0; r->el[1][i] = 0; }
  return r;
}

static inline fd_bn254_fp52_fp2_t *
fd_bn254_fp52_fp2_set_one( fd_bn254_fp52_fp2_t * r ) {
  r->el[0][0] = FD_BN254_FP52_ONE_0; r->el[0][1] = FD_BN254_FP52_ONE_1;
  r->el[0][2] = FD_BN254_FP52_ONE_2; r->el[0][3] = FD_BN254_FP52_ONE_3;
  r->el[0][4] = FD_BN254_FP52_ONE_4;
  for( int i=0; i<5; i++ ) r->el[1][i] = 0;
  return r;
}

static inline fd_bn254_fp52_fp2_t *
fd_bn254_fp52_fp2_set( fd_bn254_fp52_fp2_t *       r,
                       fd_bn254_fp52_fp2_t const * a ) {
  fd_bn254_fp52_set_scalar( r->el[0], a->el[0] );
  fd_bn254_fp52_set_scalar( r->el[1], a->el[1] );
  return r;
}

static inline int
fd_bn254_fp52_fp2_is_zero( fd_bn254_fp52_fp2_t const * a ) {
  return (a->el[0][0] | a->el[0][1] | a->el[0][2] | a->el[0][3] | a->el[0][4] |
          a->el[1][0] | a->el[1][1] | a->el[1][2] | a->el[1][3] | a->el[1][4]) == 0;
}

static inline int
fd_bn254_fp52_fp2_eq( fd_bn254_fp52_fp2_t const * a,
                      fd_bn254_fp52_fp2_t const * b ) {
  return (a->el[0][0]==b->el[0][0]) && (a->el[0][1]==b->el[0][1]) &&
         (a->el[0][2]==b->el[0][2]) && (a->el[0][3]==b->el[0][3]) &&
         (a->el[0][4]==b->el[0][4]) &&
         (a->el[1][0]==b->el[1][0]) && (a->el[1][1]==b->el[1][1]) &&
         (a->el[1][2]==b->el[1][2]) && (a->el[1][3]==b->el[1][3]) &&
         (a->el[1][4]==b->el[1][4]);
}

static inline fd_bn254_fp52_fp2_t *
fd_bn254_fp52_fp2_add( fd_bn254_fp52_fp2_t *       r,
                       fd_bn254_fp52_fp2_t const * a,
                       fd_bn254_fp52_fp2_t const * b ) {
  fd_bn254_fp52_add_scalar( r->el[0], a->el[0], b->el[0] );
  fd_bn254_fp52_add_scalar( r->el[1], a->el[1], b->el[1] );
  return r;
}

static inline fd_bn254_fp52_fp2_t *
fd_bn254_fp52_fp2_sub( fd_bn254_fp52_fp2_t *       r,
                       fd_bn254_fp52_fp2_t const * a,
                       fd_bn254_fp52_fp2_t const * b ) {
  fd_bn254_fp52_sub_scalar( r->el[0], a->el[0], b->el[0] );
  fd_bn254_fp52_sub_scalar( r->el[1], a->el[1], b->el[1] );
  return r;
}

static inline fd_bn254_fp52_fp2_t *
fd_bn254_fp52_fp2_neg( fd_bn254_fp52_fp2_t *       r,
                       fd_bn254_fp52_fp2_t const * a ) {
  fd_bn254_fp52_neg_scalar( r->el[0], a->el[0] );
  fd_bn254_fp52_neg_scalar( r->el[1], a->el[1] );
  return r;
}

static inline fd_bn254_fp52_fp2_t *
fd_bn254_fp52_fp2_conj( fd_bn254_fp52_fp2_t *       r,
                        fd_bn254_fp52_fp2_t const * a ) {
  fd_bn254_fp52_set_scalar( r->el[0], a->el[0] );
  fd_bn254_fp52_neg_scalar( r->el[1], a->el[1] );
  return r;
}

/* fd_bn254_fp52_fp2_mul_by_i computes r = a * i.
   (a0 + a1*i) * i = -a1 + a0*i. */
static inline fd_bn254_fp52_fp2_t *
fd_bn254_fp52_fp2_mul_by_i( fd_bn254_fp52_fp2_t *       r,
                            fd_bn254_fp52_fp2_t const * a ) {
  ulong t[5];
  fd_bn254_fp52_neg_scalar( t, a->el[1] );
  fd_bn254_fp52_set_scalar( r->el[1], a->el[0] );
  fd_bn254_fp52_set_scalar( r->el[0], t );
  return r;
}

/* fd_bn254_fp52_fp2_mul_by_xi computes r = a * (9+i).
   r = (9*a0 - a1) + (9*a1 + a0)*i.
   No Fp multiplications needed — only additions. */
static inline fd_bn254_fp52_fp2_t *
fd_bn254_fp52_fp2_mul_by_xi( fd_bn254_fp52_fp2_t *       r,
                             fd_bn254_fp52_fp2_t const * a ) {
  ulong r0[5], r1[5], t[5];

  /* 9*a0 = 8*a0 + a0 = ((a0 << 1) << 1) << 1 + a0 */
  fd_bn254_fp52_add_scalar( t,  a->el[0], a->el[0] ); /* 2*a0 */
  fd_bn254_fp52_add_scalar( t,  t,  t );                /* 4*a0 */
  fd_bn254_fp52_add_scalar( t,  t,  t );                /* 8*a0 */
  fd_bn254_fp52_add_scalar( r0, t,  a->el[0] );         /* 9*a0 */
  fd_bn254_fp52_sub_scalar( r0, r0, a->el[1] );         /* 9*a0 - a1 */

  /* 9*a1 */
  fd_bn254_fp52_add_scalar( t,  a->el[1], a->el[1] );
  fd_bn254_fp52_add_scalar( t,  t,  t );
  fd_bn254_fp52_add_scalar( t,  t,  t );
  fd_bn254_fp52_add_scalar( r1, t,  a->el[1] );         /* 9*a1 */
  fd_bn254_fp52_add_scalar( r1, r1, a->el[0] );         /* 9*a1 + a0 */

  fd_bn254_fp52_set_scalar( r->el[0], r0 );
  fd_bn254_fp52_set_scalar( r->el[1], r1 );
  return r;
}

/* fd_bn254_fp52_fp2_halve computes r = a / 2. */
static inline fd_bn254_fp52_fp2_t *
fd_bn254_fp52_fp2_halve( fd_bn254_fp52_fp2_t *       r,
                         fd_bn254_fp52_fp2_t const * a ) {
  /* For each component: if odd, add p first, then shift right by 1.
     In radix-2^52, "odd" means limb 0 bit 0 is set.
     Shift right by 1: each limb shifts right, high bit of next limb
     becomes bit 51 of current limb. */
  for( int c=0; c<2; c++ ) {
    ulong t[5];
    fd_bn254_fp52_set_scalar( t, a->el[c] );
    if( t[0] & 1 ) {
      /* Add p */
      ulong carry = 0;
      t[0] += FD_BN254_FP52_P0; carry = t[0]>>52; t[0] &= FD_BN254_FP52_MASK;
      t[1] += FD_BN254_FP52_P1 + carry; carry = t[1]>>52; t[1] &= FD_BN254_FP52_MASK;
      t[2] += FD_BN254_FP52_P2 + carry; carry = t[2]>>52; t[2] &= FD_BN254_FP52_MASK;
      t[3] += FD_BN254_FP52_P3 + carry; carry = t[3]>>52; t[3] &= FD_BN254_FP52_MASK;
      t[4] += FD_BN254_FP52_P4 + carry; t[4] &= FD_BN254_FP52_MASK;
    }
    /* Shift right by 1 across all limbs */
    r->el[c][0] = (t[0] >> 1) | ((t[1] & 1) << 51);
    r->el[c][1] = (t[1] >> 1) | ((t[2] & 1) << 51);
    r->el[c][2] = (t[2] >> 1) | ((t[3] & 1) << 51);
    r->el[c][3] = (t[3] >> 1) | ((t[4] & 1) << 51);
    r->el[c][4] = t[4] >> 1;
  }
  return r;
}

/* ---- Batched Fp2 multiplication using AVX-512 IFMA ----

   The core idea: pack multiple independent Fp multiplications from
   one or more Fp2 Karatsuba formulas into a single fd_bn254_fp52x8_mul
   call, utilizing as many of the 8 SIMD lanes as possible.

   Fp2 mul Karatsuba formula:
     sa = a0 + a1,  sb = b0 + b1
     p0 = a0 * b0,  p1 = a1 * b1,  p2 = sa * sb
     r0 = p0 - p1,  r1 = p2 - p0 - p1

   Three Fp muls: p0, p1 are independent; p2 depends on sa, sb. */

/* Helper: pack an Fp element (5 ulong limbs) into a specific lane
   of an fd_bn254_fp52x8_t by constructing each limb register. */
static inline void
fd_bn254_fp52x8_pack_lane( fd_bn254_fp52x8_t * batch,
                           int                 lane,
                           ulong const         a[5] ) {
  fd_bn254_fp52x8_set_lane( batch, lane, a );
}

/* Helper: extract an Fp element from a specific lane. */
static inline void
fd_bn254_fp52x8_extract_lane( ulong                     r[5],
                              fd_bn254_fp52x8_t const * batch,
                              int                       lane ) {
  fd_bn254_fp52x8_get_lane( r, batch, lane );
}

/* fd_bn254_fp52_fp2_mul computes r = a * b in Fp2.
   Uses Karatsuba with 3 Fp muls packed into one 8-way batch. */
FD_FN_UNUSED static inline fd_bn254_fp52_fp2_t *
fd_bn254_fp52_fp2_mul( fd_bn254_fp52_fp2_t *       r,
                       fd_bn254_fp52_fp2_t const * a,
                       fd_bn254_fp52_fp2_t const * b ) {
  /* Precompute sums */
  ulong sa[5], sb[5];
  fd_bn254_fp52_add_scalar( sa, a->el[0], a->el[1] );
  fd_bn254_fp52_add_scalar( sb, b->el[0], b->el[1] );

  /* Pack 3 multiplications into lanes 0,1,2:
     lane 0: a0 * b0
     lane 1: a1 * b1
     lane 2: sa * sb */
  fd_bn254_fp52x8_t ax, bx;
  fd_bn254_fp52x8_zero( &ax );
  fd_bn254_fp52x8_zero( &bx );

  /* Set lane 0 */ fd_bn254_fp52x8_pack_lane( &ax, 0, a->el[0] );
                   fd_bn254_fp52x8_pack_lane( &bx, 0, b->el[0] );
  /* Set lane 1 */ fd_bn254_fp52x8_pack_lane( &ax, 1, a->el[1] );
                   fd_bn254_fp52x8_pack_lane( &bx, 1, b->el[1] );
  /* Set lane 2 */ fd_bn254_fp52x8_pack_lane( &ax, 2, sa );
                   fd_bn254_fp52x8_pack_lane( &bx, 2, sb );

  /* One batched multiply: all 3 products in parallel */
  fd_bn254_fp52x8_t px = fd_bn254_fp52x8_mul( &ax, &bx );

  /* Extract products */
  ulong p0[5], p1[5], p2[5];
  fd_bn254_fp52x8_extract_lane( p0, &px, 0 );  /* a0*b0 */
  fd_bn254_fp52x8_extract_lane( p1, &px, 1 );  /* a1*b1 */
  fd_bn254_fp52x8_extract_lane( p2, &px, 2 );  /* sa*sb */

  /* Assemble: r0 = a0*b0 - a1*b1,  r1 = sa*sb - a0*b0 - a1*b1 */
  fd_bn254_fp52_sub_scalar( r->el[0], p0, p1 );
  fd_bn254_fp52_sub_scalar( r->el[1], p2, p0 );
  fd_bn254_fp52_sub_scalar( r->el[1], r->el[1], p1 );
  return r;
}

/* fd_bn254_fp52_fp2_sqr computes r = a^2 in Fp2.
   Alg. 3 of [2010/354]: r0 = (a0+a1)(a0-a1), r1 = 2*a0*a1.
   Uses 2 Fp muls packed into one 8-way batch. */
FD_FN_UNUSED static inline fd_bn254_fp52_fp2_t *
fd_bn254_fp52_fp2_sqr( fd_bn254_fp52_fp2_t *       r,
                       fd_bn254_fp52_fp2_t const * a ) {
  ulong p[5], m[5];
  fd_bn254_fp52_add_scalar( p, a->el[0], a->el[1] ); /* a0 + a1 */
  fd_bn254_fp52_sub_scalar( m, a->el[0], a->el[1] ); /* a0 - a1 */

  /* Pack 2 multiplications:
     lane 0: a0 * a1  (for r1)
     lane 1: p  * m   (for r0) */
  fd_bn254_fp52x8_t ax, bx;
  fd_bn254_fp52x8_zero( &ax );
  fd_bn254_fp52x8_zero( &bx );

  fd_bn254_fp52x8_pack_lane( &ax, 0, a->el[0] );
  fd_bn254_fp52x8_pack_lane( &bx, 0, a->el[1] );
  fd_bn254_fp52x8_pack_lane( &ax, 1, p );
  fd_bn254_fp52x8_pack_lane( &bx, 1, m );

  fd_bn254_fp52x8_t px = fd_bn254_fp52x8_mul( &ax, &bx );

  ulong a0a1[5], pm[5];
  fd_bn254_fp52x8_extract_lane( a0a1, &px, 0 );
  fd_bn254_fp52x8_extract_lane( pm,   &px, 1 );

  /* r0 = p*m = (a0+a1)(a0-a1) */
  fd_bn254_fp52_set_scalar( r->el[0], pm );
  /* r1 = 2 * a0*a1 */
  fd_bn254_fp52_add_scalar( r->el[1], a0a1, a0a1 );
  return r;
}

/* ---- Batched Fp2 operations for higher-level callers ---- */

/* fd_bn254_fp52_fp2_mul2 computes two independent Fp2 multiplications
   in a single 8-way batch (6 of 8 lanes used). */
FD_FN_UNUSED static inline void
fd_bn254_fp52_fp2_mul2( fd_bn254_fp52_fp2_t *       r1,
                        fd_bn254_fp52_fp2_t const * a1,
                        fd_bn254_fp52_fp2_t const * b1,
                        fd_bn254_fp52_fp2_t *       r2,
                        fd_bn254_fp52_fp2_t const * a2,
                        fd_bn254_fp52_fp2_t const * b2 ) {
  ulong sa1[5], sb1[5], sa2[5], sb2[5];
  fd_bn254_fp52_add_scalar( sa1, a1->el[0], a1->el[1] );
  fd_bn254_fp52_add_scalar( sb1, b1->el[0], b1->el[1] );
  fd_bn254_fp52_add_scalar( sa2, a2->el[0], a2->el[1] );
  fd_bn254_fp52_add_scalar( sb2, b2->el[0], b2->el[1] );

  /* Pack 6 Fp muls into lanes 0-5:
     0: a1_0*b1_0, 1: a1_1*b1_1, 2: sa1*sb1,
     3: a2_0*b2_0, 4: a2_1*b2_1, 5: sa2*sb2 */
  fd_bn254_fp52x8_t ax, bx;
  fd_bn254_fp52x8_zero( &ax );
  fd_bn254_fp52x8_zero( &bx );

  fd_bn254_fp52x8_pack_lane( &ax, 0, a1->el[0] ); fd_bn254_fp52x8_pack_lane( &bx, 0, b1->el[0] );
  fd_bn254_fp52x8_pack_lane( &ax, 1, a1->el[1] ); fd_bn254_fp52x8_pack_lane( &bx, 1, b1->el[1] );
  fd_bn254_fp52x8_pack_lane( &ax, 2, sa1 );        fd_bn254_fp52x8_pack_lane( &bx, 2, sb1 );
  fd_bn254_fp52x8_pack_lane( &ax, 3, a2->el[0] ); fd_bn254_fp52x8_pack_lane( &bx, 3, b2->el[0] );
  fd_bn254_fp52x8_pack_lane( &ax, 4, a2->el[1] ); fd_bn254_fp52x8_pack_lane( &bx, 4, b2->el[1] );
  fd_bn254_fp52x8_pack_lane( &ax, 5, sa2 );        fd_bn254_fp52x8_pack_lane( &bx, 5, sb2 );

  fd_bn254_fp52x8_t px = fd_bn254_fp52x8_mul( &ax, &bx );

  ulong p10[5], p11[5], p12[5], p20[5], p21[5], p22[5];
  fd_bn254_fp52x8_extract_lane( p10, &px, 0 );
  fd_bn254_fp52x8_extract_lane( p11, &px, 1 );
  fd_bn254_fp52x8_extract_lane( p12, &px, 2 );
  fd_bn254_fp52x8_extract_lane( p20, &px, 3 );
  fd_bn254_fp52x8_extract_lane( p21, &px, 4 );
  fd_bn254_fp52x8_extract_lane( p22, &px, 5 );

  fd_bn254_fp52_sub_scalar( r1->el[0], p10, p11 );
  fd_bn254_fp52_sub_scalar( r1->el[1], p12, p10 );
  fd_bn254_fp52_sub_scalar( r1->el[1], r1->el[1], p11 );

  fd_bn254_fp52_sub_scalar( r2->el[0], p20, p21 );
  fd_bn254_fp52_sub_scalar( r2->el[1], p22, p20 );
  fd_bn254_fp52_sub_scalar( r2->el[1], r2->el[1], p21 );
}

/* fd_bn254_fp52_fp2_mul3 computes three independent Fp2 multiplications.
   Uses 2 batches: batch 1 has 8/8 lanes, batch 2 has 1/8 lanes. */
FD_FN_UNUSED static inline void
fd_bn254_fp52_fp2_mul3( fd_bn254_fp52_fp2_t *       r1,
                        fd_bn254_fp52_fp2_t const * a1,
                        fd_bn254_fp52_fp2_t const * b1,
                        fd_bn254_fp52_fp2_t *       r2,
                        fd_bn254_fp52_fp2_t const * a2,
                        fd_bn254_fp52_fp2_t const * b2,
                        fd_bn254_fp52_fp2_t *       r3,
                        fd_bn254_fp52_fp2_t const * a3,
                        fd_bn254_fp52_fp2_t const * b3 ) {
  ulong sa1[5], sb1[5], sa2[5], sb2[5], sa3[5], sb3[5];
  fd_bn254_fp52_add_scalar( sa1, a1->el[0], a1->el[1] );
  fd_bn254_fp52_add_scalar( sb1, b1->el[0], b1->el[1] );
  fd_bn254_fp52_add_scalar( sa2, a2->el[0], a2->el[1] );
  fd_bn254_fp52_add_scalar( sb2, b2->el[0], b2->el[1] );
  fd_bn254_fp52_add_scalar( sa3, a3->el[0], a3->el[1] );
  fd_bn254_fp52_add_scalar( sb3, b3->el[0], b3->el[1] );

  /* Batch 1 (8/8 lanes): the 6 independent products + 2 cross products
     0: a1_0*b1_0, 1: a1_1*b1_1, 2: a2_0*b2_0, 3: a2_1*b2_1,
     4: a3_0*b3_0, 5: a3_1*b3_1, 6: sa1*sb1,   7: sa2*sb2 */
  fd_bn254_fp52x8_t ax, bx;
  fd_bn254_fp52x8_zero( &ax );
  fd_bn254_fp52x8_zero( &bx );

  fd_bn254_fp52x8_pack_lane( &ax, 0, a1->el[0] ); fd_bn254_fp52x8_pack_lane( &bx, 0, b1->el[0] );
  fd_bn254_fp52x8_pack_lane( &ax, 1, a1->el[1] ); fd_bn254_fp52x8_pack_lane( &bx, 1, b1->el[1] );
  fd_bn254_fp52x8_pack_lane( &ax, 2, a2->el[0] ); fd_bn254_fp52x8_pack_lane( &bx, 2, b2->el[0] );
  fd_bn254_fp52x8_pack_lane( &ax, 3, a2->el[1] ); fd_bn254_fp52x8_pack_lane( &bx, 3, b2->el[1] );
  fd_bn254_fp52x8_pack_lane( &ax, 4, a3->el[0] ); fd_bn254_fp52x8_pack_lane( &bx, 4, b3->el[0] );
  fd_bn254_fp52x8_pack_lane( &ax, 5, a3->el[1] ); fd_bn254_fp52x8_pack_lane( &bx, 5, b3->el[1] );
  fd_bn254_fp52x8_pack_lane( &ax, 6, sa1 );        fd_bn254_fp52x8_pack_lane( &bx, 6, sb1 );
  fd_bn254_fp52x8_pack_lane( &ax, 7, sa2 );        fd_bn254_fp52x8_pack_lane( &bx, 7, sb2 );

  fd_bn254_fp52x8_t px1 = fd_bn254_fp52x8_mul( &ax, &bx );

  /* Batch 2 (1/8 lanes): remaining cross product */
  fd_bn254_fp52x8_zero( &ax );
  fd_bn254_fp52x8_zero( &bx );
  fd_bn254_fp52x8_pack_lane( &ax, 0, sa3 );
  fd_bn254_fp52x8_pack_lane( &bx, 0, sb3 );

  fd_bn254_fp52x8_t px2 = fd_bn254_fp52x8_mul( &ax, &bx );

  /* Extract all 9 products */
  ulong p10[5], p11[5], p12[5];
  ulong p20[5], p21[5], p22[5];
  ulong p30[5], p31[5], p32[5];
  fd_bn254_fp52x8_extract_lane( p10, &px1, 0 );  /* a1_0*b1_0 */
  fd_bn254_fp52x8_extract_lane( p11, &px1, 1 );  /* a1_1*b1_1 */
  fd_bn254_fp52x8_extract_lane( p20, &px1, 2 );  /* a2_0*b2_0 */
  fd_bn254_fp52x8_extract_lane( p21, &px1, 3 );  /* a2_1*b2_1 */
  fd_bn254_fp52x8_extract_lane( p30, &px1, 4 );  /* a3_0*b3_0 */
  fd_bn254_fp52x8_extract_lane( p31, &px1, 5 );  /* a3_1*b3_1 */
  fd_bn254_fp52x8_extract_lane( p12, &px1, 6 );  /* sa1*sb1 */
  fd_bn254_fp52x8_extract_lane( p22, &px1, 7 );  /* sa2*sb2 */
  fd_bn254_fp52x8_extract_lane( p32, &px2, 0 );  /* sa3*sb3 */

  /* Assemble results */
  fd_bn254_fp52_sub_scalar( r1->el[0], p10, p11 );
  fd_bn254_fp52_sub_scalar( r1->el[1], p12, p10 );
  fd_bn254_fp52_sub_scalar( r1->el[1], r1->el[1], p11 );

  fd_bn254_fp52_sub_scalar( r2->el[0], p20, p21 );
  fd_bn254_fp52_sub_scalar( r2->el[1], p22, p20 );
  fd_bn254_fp52_sub_scalar( r2->el[1], r2->el[1], p21 );

  fd_bn254_fp52_sub_scalar( r3->el[0], p30, p31 );
  fd_bn254_fp52_sub_scalar( r3->el[1], p32, p30 );
  fd_bn254_fp52_sub_scalar( r3->el[1], r3->el[1], p31 );
}

/* fd_bn254_fp52_fp2_sqr2 computes two independent Fp2 squarings
   in a single 8-way batch (4 of 8 lanes used). */
FD_FN_UNUSED static inline void
fd_bn254_fp52_fp2_sqr2( fd_bn254_fp52_fp2_t *       r1,
                        fd_bn254_fp52_fp2_t const * a1,
                        fd_bn254_fp52_fp2_t *       r2,
                        fd_bn254_fp52_fp2_t const * a2 ) {
  ulong p1[5], m1[5], p2[5], m2[5];
  fd_bn254_fp52_add_scalar( p1, a1->el[0], a1->el[1] );
  fd_bn254_fp52_sub_scalar( m1, a1->el[0], a1->el[1] );
  fd_bn254_fp52_add_scalar( p2, a2->el[0], a2->el[1] );
  fd_bn254_fp52_sub_scalar( m2, a2->el[0], a2->el[1] );

  fd_bn254_fp52x8_t ax, bx;
  fd_bn254_fp52x8_zero( &ax );
  fd_bn254_fp52x8_zero( &bx );

  fd_bn254_fp52x8_pack_lane( &ax, 0, a1->el[0] ); fd_bn254_fp52x8_pack_lane( &bx, 0, a1->el[1] );
  fd_bn254_fp52x8_pack_lane( &ax, 1, p1 );         fd_bn254_fp52x8_pack_lane( &bx, 1, m1 );
  fd_bn254_fp52x8_pack_lane( &ax, 2, a2->el[0] ); fd_bn254_fp52x8_pack_lane( &bx, 2, a2->el[1] );
  fd_bn254_fp52x8_pack_lane( &ax, 3, p2 );         fd_bn254_fp52x8_pack_lane( &bx, 3, m2 );

  fd_bn254_fp52x8_t px = fd_bn254_fp52x8_mul( &ax, &bx );

  ulong q10[5], q11[5], q20[5], q21[5];
  fd_bn254_fp52x8_extract_lane( q10, &px, 0 );  /* a1_0*a1_1 */
  fd_bn254_fp52x8_extract_lane( q11, &px, 1 );  /* p1*m1 */
  fd_bn254_fp52x8_extract_lane( q20, &px, 2 );  /* a2_0*a2_1 */
  fd_bn254_fp52x8_extract_lane( q21, &px, 3 );  /* p2*m2 */

  fd_bn254_fp52_set_scalar( r1->el[0], q11 );            /* (a0+a1)(a0-a1) */
  fd_bn254_fp52_add_scalar( r1->el[1], q10, q10 );       /* 2*a0*a1 */

  fd_bn254_fp52_set_scalar( r2->el[0], q21 );
  fd_bn254_fp52_add_scalar( r2->el[1], q20, q20 );
}

/* fd_bn254_fp52_fp2_sqr4 computes four independent Fp2 squarings
   in a single 8-way batch (8/8 lanes — perfect utilization). */
FD_FN_UNUSED static inline void
fd_bn254_fp52_fp2_sqr4( fd_bn254_fp52_fp2_t *       r1,
                        fd_bn254_fp52_fp2_t const * a1,
                        fd_bn254_fp52_fp2_t *       r2,
                        fd_bn254_fp52_fp2_t const * a2,
                        fd_bn254_fp52_fp2_t *       r3,
                        fd_bn254_fp52_fp2_t const * a3,
                        fd_bn254_fp52_fp2_t *       r4,
                        fd_bn254_fp52_fp2_t const * a4 ) {
  ulong p1[5], m1[5], p2[5], m2[5], p3[5], m3[5], p4[5], m4[5];
  fd_bn254_fp52_add_scalar( p1, a1->el[0], a1->el[1] );
  fd_bn254_fp52_sub_scalar( m1, a1->el[0], a1->el[1] );
  fd_bn254_fp52_add_scalar( p2, a2->el[0], a2->el[1] );
  fd_bn254_fp52_sub_scalar( m2, a2->el[0], a2->el[1] );
  fd_bn254_fp52_add_scalar( p3, a3->el[0], a3->el[1] );
  fd_bn254_fp52_sub_scalar( m3, a3->el[0], a3->el[1] );
  fd_bn254_fp52_add_scalar( p4, a4->el[0], a4->el[1] );
  fd_bn254_fp52_sub_scalar( m4, a4->el[0], a4->el[1] );

  /* Batch 1 (8/8): all a0*a1 products in even lanes, p*m in odd lanes */
  fd_bn254_fp52x8_t ax, bx;
  fd_bn254_fp52x8_zero( &ax );
  fd_bn254_fp52x8_zero( &bx );

  fd_bn254_fp52x8_pack_lane( &ax, 0, a1->el[0] ); fd_bn254_fp52x8_pack_lane( &bx, 0, a1->el[1] );
  fd_bn254_fp52x8_pack_lane( &ax, 1, p1 );         fd_bn254_fp52x8_pack_lane( &bx, 1, m1 );
  fd_bn254_fp52x8_pack_lane( &ax, 2, a2->el[0] ); fd_bn254_fp52x8_pack_lane( &bx, 2, a2->el[1] );
  fd_bn254_fp52x8_pack_lane( &ax, 3, p2 );         fd_bn254_fp52x8_pack_lane( &bx, 3, m2 );
  fd_bn254_fp52x8_pack_lane( &ax, 4, a3->el[0] ); fd_bn254_fp52x8_pack_lane( &bx, 4, a3->el[1] );
  fd_bn254_fp52x8_pack_lane( &ax, 5, p3 );         fd_bn254_fp52x8_pack_lane( &bx, 5, m3 );
  fd_bn254_fp52x8_pack_lane( &ax, 6, a4->el[0] ); fd_bn254_fp52x8_pack_lane( &bx, 6, a4->el[1] );
  fd_bn254_fp52x8_pack_lane( &ax, 7, p4 );         fd_bn254_fp52x8_pack_lane( &bx, 7, m4 );

  fd_bn254_fp52x8_t px = fd_bn254_fp52x8_mul( &ax, &bx );

  ulong q[8][5];
  for( int i=0; i<8; i++ ) fd_bn254_fp52x8_extract_lane( q[i], &px, i );

  fd_bn254_fp52_set_scalar( r1->el[0], q[1] );       fd_bn254_fp52_add_scalar( r1->el[1], q[0], q[0] );
  fd_bn254_fp52_set_scalar( r2->el[0], q[3] );       fd_bn254_fp52_add_scalar( r2->el[1], q[2], q[2] );
  fd_bn254_fp52_set_scalar( r3->el[0], q[5] );       fd_bn254_fp52_add_scalar( r3->el[1], q[4], q[4] );
  fd_bn254_fp52_set_scalar( r4->el[0], q[7] );       fd_bn254_fp52_add_scalar( r4->el[1], q[6], q[6] );
}

/* fd_bn254_fp52_fp2_sqr3 computes three independent Fp2 squarings
   in one batch (6/8 lanes used). */
FD_FN_UNUSED static inline void
fd_bn254_fp52_fp2_sqr3( fd_bn254_fp52_fp2_t *       r1,
                        fd_bn254_fp52_fp2_t const * a1,
                        fd_bn254_fp52_fp2_t *       r2,
                        fd_bn254_fp52_fp2_t const * a2,
                        fd_bn254_fp52_fp2_t *       r3,
                        fd_bn254_fp52_fp2_t const * a3 ) {
  ulong p1[5], m1[5], p2[5], m2[5], p3[5], m3[5];
  fd_bn254_fp52_add_scalar( p1, a1->el[0], a1->el[1] );
  fd_bn254_fp52_sub_scalar( m1, a1->el[0], a1->el[1] );
  fd_bn254_fp52_add_scalar( p2, a2->el[0], a2->el[1] );
  fd_bn254_fp52_sub_scalar( m2, a2->el[0], a2->el[1] );
  fd_bn254_fp52_add_scalar( p3, a3->el[0], a3->el[1] );
  fd_bn254_fp52_sub_scalar( m3, a3->el[0], a3->el[1] );

  fd_bn254_fp52x8_t ax, bx;
  fd_bn254_fp52x8_zero( &ax );
  fd_bn254_fp52x8_zero( &bx );

  fd_bn254_fp52x8_pack_lane( &ax, 0, a1->el[0] ); fd_bn254_fp52x8_pack_lane( &bx, 0, a1->el[1] );
  fd_bn254_fp52x8_pack_lane( &ax, 1, p1 );         fd_bn254_fp52x8_pack_lane( &bx, 1, m1 );
  fd_bn254_fp52x8_pack_lane( &ax, 2, a2->el[0] ); fd_bn254_fp52x8_pack_lane( &bx, 2, a2->el[1] );
  fd_bn254_fp52x8_pack_lane( &ax, 3, p2 );         fd_bn254_fp52x8_pack_lane( &bx, 3, m2 );
  fd_bn254_fp52x8_pack_lane( &ax, 4, a3->el[0] ); fd_bn254_fp52x8_pack_lane( &bx, 4, a3->el[1] );
  fd_bn254_fp52x8_pack_lane( &ax, 5, p3 );         fd_bn254_fp52x8_pack_lane( &bx, 5, m3 );

  fd_bn254_fp52x8_t px = fd_bn254_fp52x8_mul( &ax, &bx );

  ulong q[6][5];
  for( int i=0; i<6; i++ ) fd_bn254_fp52x8_extract_lane( q[i], &px, i );

  fd_bn254_fp52_set_scalar( r1->el[0], q[1] );       fd_bn254_fp52_add_scalar( r1->el[1], q[0], q[0] );
  fd_bn254_fp52_set_scalar( r2->el[0], q[3] );       fd_bn254_fp52_add_scalar( r2->el[1], q[2], q[2] );
  fd_bn254_fp52_set_scalar( r3->el[0], q[5] );       fd_bn254_fp52_add_scalar( r3->el[1], q[4], q[4] );
}

FD_PROTOTYPES_END

#endif /* FD_HAS_AVX512 */

#endif /* HEADER_fd_src_ballet_bn254_avx512_fd_bn254_fp52_fp2_h */
