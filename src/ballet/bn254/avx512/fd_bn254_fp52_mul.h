#ifndef HEADER_fd_src_ballet_bn254_avx512_fd_bn254_fp52_mul_h
#define HEADER_fd_src_ballet_bn254_avx512_fd_bn254_fp52_mul_h

#if FD_HAS_AVX512

#include "fd_bn254_fp52.h"

/* fd_bn254_fp52_mul.h provides 8-way batched Montgomery arithmetic on
   bn254 base field elements (Fp) using AVX-512 IFMA instructions.

   Each fd_bn254_fp52x8_t holds 8 independent field elements in
   radix-2^52 representation with 5 limbs per element.  Limb k of all 8
   elements is stored in a single wwv_t (512-bit vector), so limb-level
   operations naturally parallelize across all 8 lanes.

   Montgomery form: elements are stored as a*R mod p, where
   R = 2^260 = 2^(5*52).  Multiplication computes
   (a*R) * (b*R) * R^{-1} mod p = a*b*R mod p via the CIOS
   (Coarsely Integrated Operand Scanning) method.

   Radix-2^52 was chosen so that the AVX-512 IFMA instructions
   (madd52lo / madd52hi) directly produce the low/high parts of a
   52x52->104 bit product without any shift correction (unlike the
   radix-2^43 representation in fd_r43x6.h which needs a <<9 fixup for
   madd52hi). */

FD_PROTOTYPES_BEGIN

/* Broadcast constants for the bn254 base field prime p.

   p = 21888242871839275222246405745257275088696311157297823662689037894645226208583

   In radix-2^52:
     p[0] = 0x08c16d87cfd47
     p[1] = 0x916871ca8d3c2
     p[2] = 0x181585d97816a
     p[3] = 0xa029b85045b68
     p[4] = 0x30644e72e131

   p_inv = -p^{-1} mod 2^52 = 0x20782e4866389

   These are broadcast across all 8 lanes of a wwv_t so that the same
   constant applies independently to each of the 8 field elements. */

#define FD_BN254_FP52X8_P0     wwv_bcast( 0x08c16d87cfd47UL )
#define FD_BN254_FP52X8_P1     wwv_bcast( 0x916871ca8d3c2UL )
#define FD_BN254_FP52X8_P2     wwv_bcast( 0x181585d97816aUL )
#define FD_BN254_FP52X8_P3     wwv_bcast( 0xa029b85045b68UL )
#define FD_BN254_FP52X8_P4     wwv_bcast( 0x30644e72e131UL  )
#define FD_BN254_FP52X8_P_INV  wwv_bcast( 0x20782e4866389UL )
#define FD_BN254_FP52X8_MASK52 wwv_bcast( 0xfffffffffffffUL )

/* fd_bn254_fp52x8_cond_sub_p subtracts p from a 5-limb carry-
   propagated result if the result is >= p.  After CIOS Montgomery
   multiplication, the result satisfies t < 2p, so at most one
   subtraction is needed.  The subtraction and selection are fully
   branchless and lane-independent.

   Inputs: t0..t4 are wwv_t's with each lane's value in [0, 2^52).
   Outputs: r->l[0..4] set to (t - p) if t >= p, else t, per lane. */

FD_FN_UNUSED static inline fd_bn254_fp52x8_t
fd_bn254_fp52x8_cond_sub_p( wwv_t t0, wwv_t t1, wwv_t t2, wwv_t t3, wwv_t t4 ) {
  wwv_t const p0     = FD_BN254_FP52X8_P0;
  wwv_t const p1     = FD_BN254_FP52X8_P1;
  wwv_t const p2     = FD_BN254_FP52X8_P2;
  wwv_t const p3     = FD_BN254_FP52X8_P3;
  wwv_t const p4     = FD_BN254_FP52X8_P4;
  wwv_t const mask52 = FD_BN254_FP52X8_MASK52;
  wwv_t const one    = wwv_one();

  /* Multi-limb subtraction d = t - p with borrow propagation.
     Since all limbs are in [0, 2^52), the unsigned 64-bit subtraction
     wraps correctly: the low 52 bits of each difference give the
     correct limb value, and we track borrow as a per-lane mask. */

  /* Limb 0 */
  wwv_t d0 = wwv_and( wwv_sub( t0, p0 ), mask52 );
  int   b0 = wwv_lt( t0, p0 );

  /* Limb 1: subtract p1 and borrow from limb 0 */
  wwv_t d1 = wwv_sub( t1, p1 );
  d1        = wwv_sub_if( b0, d1, one, d1 );
  int   b1  = wwv_lt( t1, p1 ) | ( wwv_eq( t1, p1 ) & b0 );
  d1        = wwv_and( d1, mask52 );

  /* Limb 2 */
  wwv_t d2 = wwv_sub( t2, p2 );
  d2        = wwv_sub_if( b1, d2, one, d2 );
  int   b2  = wwv_lt( t2, p2 ) | ( wwv_eq( t2, p2 ) & b1 );
  d2        = wwv_and( d2, mask52 );

  /* Limb 3 */
  wwv_t d3 = wwv_sub( t3, p3 );
  d3        = wwv_sub_if( b2, d3, one, d3 );
  int   b3  = wwv_lt( t3, p3 ) | ( wwv_eq( t3, p3 ) & b2 );
  d3        = wwv_and( d3, mask52 );

  /* Limb 4 */
  wwv_t d4 = wwv_sub( t4, p4 );
  d4        = wwv_sub_if( b3, d4, one, d4 );
  int   b4  = wwv_lt( t4, p4 ) | ( wwv_eq( t4, p4 ) & b3 );
  d4        = wwv_and( d4, mask52 );

  /* If final borrow is set, t < p: keep t.
     If final borrow is clear, t >= p: use d = t - p. */

  fd_bn254_fp52x8_t r;
  r.l[0] = wwv_if( b4, t0, d0 );
  r.l[1] = wwv_if( b4, t1, d1 );
  r.l[2] = wwv_if( b4, t2, d2 );
  r.l[3] = wwv_if( b4, t3, d3 );
  r.l[4] = wwv_if( b4, t4, d4 );
  return r;
}

/* fd_bn254_fp52x8_mul computes r = a * b in Montgomery form using 8-way
   batched CIOS (Coarsely Integrated Operand Scanning) with AVX-512 IFMA
   instructions.

   Each of the 8 lanes independently computes:
     r = a * b * R^{-1} mod p

   where R = 2^260 and p is the bn254 base field prime.

   Algorithm (per lane, executed in parallel across all 8 lanes):

     t[0..5] = 0

     for i = 0..4:
       // Step 1: t += a * b[i]
       // Step 2: m = (t[0] * p_inv) mod 2^52
       // Step 3: t += m * p
       // Step 4: t >>= 52  (shift right one limb)

     Carry propagate, then conditionally subtract p.

   Bit-width safety: accumulator limbs reach at most ~55 bits during the
   5 iterations, well within the 64-bit wwv_t lane width. No inner carry
   propagation is needed.

   The IFMA split is natural for radix-2^52: madd52lo gives the low 52
   bits of a product, and madd52hi gives the bits [52..103] which are
   exactly the carry to the next limb. No shift correction is needed
   (unlike radix-2^43 which requires <<9 on madd52hi). */

FD_FN_UNUSED static inline fd_bn254_fp52x8_t
fd_bn254_fp52x8_mul( fd_bn254_fp52x8_t const * a,
                     fd_bn254_fp52x8_t const * b ) {
  wwv_t const zero   = wwv_zero();
  wwv_t const p0     = FD_BN254_FP52X8_P0;
  wwv_t const p1     = FD_BN254_FP52X8_P1;
  wwv_t const p2     = FD_BN254_FP52X8_P2;
  wwv_t const p3     = FD_BN254_FP52X8_P3;
  wwv_t const p4     = FD_BN254_FP52X8_P4;
  wwv_t const p_inv  = FD_BN254_FP52X8_P_INV;
  wwv_t const mask52 = FD_BN254_FP52X8_MASK52;

  /* Load a's limbs */
  wwv_t a0 = a->l[0];
  wwv_t a1 = a->l[1];
  wwv_t a2 = a->l[2];
  wwv_t a3 = a->l[3];
  wwv_t a4 = a->l[4];

  /* Initialize 6-limb accumulator to zero */
  wwv_t t0 = zero;
  wwv_t t1 = zero;
  wwv_t t2 = zero;
  wwv_t t3 = zero;
  wwv_t t4 = zero;
  wwv_t t5 = zero;

  /* Unrolled CIOS loop: 5 iterations for 5 limbs of b.
     Each iteration:
       1. Accumulate a * b[i] into t (schoolbook multiply, one row)
       2. Compute Montgomery factor m = LO52( t[0] * p_inv )
       3. Accumulate m * p into t (Montgomery reduction, one row)
       4. Shift t right by one limb (divide by 2^52)

     The hi parts are computed first (before the lo parts modify t)
     for better ILP.  Each madd52hi is independent, while the
     madd52lo/add chain has sequential dependencies only through
     the carry from the previous limb's hi part. */

# define FD_BN254_FP52X8_CIOS_ITER(BI)                                 \
  do {                                                                  \
    wwv_t bi = (BI);                                                    \
                                                                        \
    /* Step 1: t += a * b[i]                                            \
       Compute hi parts first for ILP — they are independent of each    \
       other and of the lo accumulation chain. */                       \
    wwv_t h0 = wwv_madd52hi( zero, a0, bi );                           \
    wwv_t h1 = wwv_madd52hi( zero, a1, bi );                           \
    wwv_t h2 = wwv_madd52hi( zero, a2, bi );                           \
    wwv_t h3 = wwv_madd52hi( zero, a3, bi );                           \
    wwv_t h4 = wwv_madd52hi( zero, a4, bi );                           \
                                                                        \
    t0 = wwv_madd52lo( t0, a0, bi );                                    \
    t1 = wwv_add( wwv_madd52lo( t1, a1, bi ), h0 );                    \
    t2 = wwv_add( wwv_madd52lo( t2, a2, bi ), h1 );                    \
    t3 = wwv_add( wwv_madd52lo( t3, a3, bi ), h2 );                    \
    t4 = wwv_add( wwv_madd52lo( t4, a4, bi ), h3 );                    \
    t5 = wwv_add(               t5,           h4 );                     \
                                                                        \
    /* Step 2: Montgomery factor                                        \
       m = LO52( t[0] * p_inv ).                                       \
       madd52lo( zero, t0, p_inv ) computes LO52(LO52(t0)*LO52(p_inv)) \
       which equals LO52(t0 * p_inv) since we only need m mod 2^52.    \
       Mask to 52 bits so that subsequent madd52 uses only 52-bit m. */ \
    wwv_t m = wwv_and( wwv_madd52lo( zero, t0, p_inv ), mask52 );      \
                                                                        \
    /* Step 3: t += m * p                                               \
       Same ILP pattern as step 1: hi parts first. */                   \
    h0 = wwv_madd52hi( zero, m, p0 );                                  \
    h1 = wwv_madd52hi( zero, m, p1 );                                  \
    h2 = wwv_madd52hi( zero, m, p2 );                                  \
    h3 = wwv_madd52hi( zero, m, p3 );                                  \
    h4 = wwv_madd52hi( zero, m, p4 );                                  \
                                                                        \
    t0 = wwv_madd52lo( t0, m, p0 );                                     \
    t1 = wwv_add( wwv_madd52lo( t1, m, p1 ), h0 );                     \
    t2 = wwv_add( wwv_madd52lo( t2, m, p2 ), h1 );                     \
    t3 = wwv_add( wwv_madd52lo( t3, m, p3 ), h2 );                     \
    t4 = wwv_add( wwv_madd52lo( t4, m, p4 ), h3 );                     \
    t5 = wwv_add(               t5,          h4 );                      \
                                                                        \
    /* Step 4: Divide by 2^52 (shift right one limb position).          \
       By the Montgomery property, LO52(t[0]) == 0 after step 3.       \
       Extract the carry (high bits of t[0]) and add to t[1]. */        \
    wwv_t carry = wwv_shr( t0, 52 );                                   \
    t0 = wwv_add( t1, carry );                                          \
    t1 = t2;                                                            \
    t2 = t3;                                                            \
    t3 = t4;                                                            \
    t4 = t5;                                                            \
    t5 = zero;                                                          \
  } while(0)

  FD_BN254_FP52X8_CIOS_ITER( b->l[0] );
  FD_BN254_FP52X8_CIOS_ITER( b->l[1] );
  FD_BN254_FP52X8_CIOS_ITER( b->l[2] );
  FD_BN254_FP52X8_CIOS_ITER( b->l[3] );
  FD_BN254_FP52X8_CIOS_ITER( b->l[4] );

# undef FD_BN254_FP52X8_CIOS_ITER

  /* Final carry propagation.
     After 5 CIOS iterations, limbs may have accumulated bits beyond
     position 52 (up to ~55 bits per limb).  Sweep carries from low
     to high to normalize all limbs to [0, 2^52). */

  t1 = wwv_add( t1, wwv_shr( t0, 52 ) ); t0 = wwv_and( t0, mask52 );
  t2 = wwv_add( t2, wwv_shr( t1, 52 ) ); t1 = wwv_and( t1, mask52 );
  t3 = wwv_add( t3, wwv_shr( t2, 52 ) ); t2 = wwv_and( t2, mask52 );
  t4 = wwv_add( t4, wwv_shr( t3, 52 ) ); t3 = wwv_and( t3, mask52 );
  /* t4 is at most ~47 bits (result < 2p < 2^255, and top limb covers
     bits 208..259), so no further carry needed. */

  /* Conditional subtraction: if t >= p, return t - p, else return t.
     After CIOS, t < 2p (standard Montgomery bound). */

  return fd_bn254_fp52x8_cond_sub_p( t0, t1, t2, t3, t4 );
}

/* fd_bn254_fp52x8_sqr computes r = a^2 in Montgomery form.
   Currently implemented as mul(a, a).  Can be optimized later with
   symmetric products to save ~40% of the multiplications. */

FD_FN_UNUSED static inline fd_bn254_fp52x8_t
fd_bn254_fp52x8_sqr( fd_bn254_fp52x8_t const * a ) {
  return fd_bn254_fp52x8_mul( a, a );
}

/* fd_bn254_fp52x8_add computes r = (a + b) mod p in Montgomery form.
   Each of the 8 lanes independently computes the modular sum.

   Algorithm:
     1. Add limbs pairwise (result < 2^53 per limb, fits in 64 bits).
     2. Carry propagate to normalize limbs to [0, 2^52).
     3. Conditionally subtract p if the result >= p.

   Since a, b < p, we have a + b < 2p, so at most one subtraction
   of p is needed. */

FD_FN_UNUSED static inline fd_bn254_fp52x8_t
fd_bn254_fp52x8_add( fd_bn254_fp52x8_t const * a,
                     fd_bn254_fp52x8_t const * b ) {
  wwv_t const mask52 = FD_BN254_FP52X8_MASK52;

  /* Limb-wise addition */
  wwv_t t0 = wwv_add( a->l[0], b->l[0] );
  wwv_t t1 = wwv_add( a->l[1], b->l[1] );
  wwv_t t2 = wwv_add( a->l[2], b->l[2] );
  wwv_t t3 = wwv_add( a->l[3], b->l[3] );
  wwv_t t4 = wwv_add( a->l[4], b->l[4] );

  /* Carry propagation: each limb sum is < 2^53, so the carry is at
     most 1 bit.  Sweep low to high. */
  t1 = wwv_add( t1, wwv_shr( t0, 52 ) ); t0 = wwv_and( t0, mask52 );
  t2 = wwv_add( t2, wwv_shr( t1, 52 ) ); t1 = wwv_and( t1, mask52 );
  t3 = wwv_add( t3, wwv_shr( t2, 52 ) ); t2 = wwv_and( t2, mask52 );
  t4 = wwv_add( t4, wwv_shr( t3, 52 ) ); t3 = wwv_and( t3, mask52 );

  /* Conditional subtraction: if t >= p, return t - p. */
  return fd_bn254_fp52x8_cond_sub_p( t0, t1, t2, t3, t4 );
}

/* fd_bn254_fp52x8_sub computes r = (a - b) mod p in Montgomery form.
   Each of the 8 lanes independently computes the modular difference.

   Algorithm:
     1. Subtract limbs pairwise with borrow propagation.
     2. If the final borrow is set (a < b in that lane), add p to
        correct the underflow.

   Since a, b < p, if a >= b the result is in [0, p) and no correction
   is needed.  If a < b, the result is a - b + p which is in [0, p). */

FD_FN_UNUSED static inline fd_bn254_fp52x8_t
fd_bn254_fp52x8_sub( fd_bn254_fp52x8_t const * a,
                     fd_bn254_fp52x8_t const * b ) {
  wwv_t const p0     = FD_BN254_FP52X8_P0;
  wwv_t const p1     = FD_BN254_FP52X8_P1;
  wwv_t const p2     = FD_BN254_FP52X8_P2;
  wwv_t const p3     = FD_BN254_FP52X8_P3;
  wwv_t const p4     = FD_BN254_FP52X8_P4;
  wwv_t const mask52 = FD_BN254_FP52X8_MASK52;
  wwv_t const one    = wwv_one();

  /* Multi-limb unsigned subtraction d = a - b with borrow chain.
     Borrow is tracked as a per-lane mask (__mmask8 as int). */

  /* Limb 0 */
  wwv_t d0 = wwv_and( wwv_sub( a->l[0], b->l[0] ), mask52 );
  int   bw0 = wwv_lt( a->l[0], b->l[0] );

  /* Limb 1 */
  wwv_t d1 = wwv_sub( a->l[1], b->l[1] );
  d1        = wwv_sub_if( bw0, d1, one, d1 );
  int   bw1 = wwv_lt( a->l[1], b->l[1] ) | ( wwv_eq( a->l[1], b->l[1] ) & bw0 );
  d1        = wwv_and( d1, mask52 );

  /* Limb 2 */
  wwv_t d2 = wwv_sub( a->l[2], b->l[2] );
  d2        = wwv_sub_if( bw1, d2, one, d2 );
  int   bw2 = wwv_lt( a->l[2], b->l[2] ) | ( wwv_eq( a->l[2], b->l[2] ) & bw1 );
  d2        = wwv_and( d2, mask52 );

  /* Limb 3 */
  wwv_t d3 = wwv_sub( a->l[3], b->l[3] );
  d3        = wwv_sub_if( bw2, d3, one, d3 );
  int   bw3 = wwv_lt( a->l[3], b->l[3] ) | ( wwv_eq( a->l[3], b->l[3] ) & bw2 );
  d3        = wwv_and( d3, mask52 );

  /* Limb 4 */
  wwv_t d4 = wwv_sub( a->l[4], b->l[4] );
  d4        = wwv_sub_if( bw3, d4, one, d4 );
  int   bw4 = wwv_lt( a->l[4], b->l[4] ) | ( wwv_eq( a->l[4], b->l[4] ) & bw3 );
  d4        = wwv_and( d4, mask52 );

  /* If final borrow is set, a < b: add p to correct.
     If final borrow is clear, a >= b: result is correct as-is.

     Adding p with carry propagation when borrow is set: use
     wwv_add_if to conditionally add p[i] to d[i] per lane. */

  wwv_t r0 = wwv_add_if( bw4, d0, p0, d0 );
  wwv_t r1 = wwv_add_if( bw4, d1, p1, d1 );
  wwv_t r2 = wwv_add_if( bw4, d2, p2, d2 );
  wwv_t r3 = wwv_add_if( bw4, d3, p3, d3 );
  wwv_t r4 = wwv_add_if( bw4, d4, p4, d4 );

  /* Carry propagate after the conditional addition of p.
     d was in [0, 2^52) per limb (masked).  Adding p[i] < 2^52 gives
     at most 2^53 - 2, so carries are at most 1 bit. */

  r1 = wwv_add( r1, wwv_shr( r0, 52 ) ); r0 = wwv_and( r0, mask52 );
  r2 = wwv_add( r2, wwv_shr( r1, 52 ) ); r1 = wwv_and( r1, mask52 );
  r3 = wwv_add( r3, wwv_shr( r2, 52 ) ); r2 = wwv_and( r2, mask52 );
  r4 = wwv_add( r4, wwv_shr( r3, 52 ) ); r3 = wwv_and( r3, mask52 );
  r4 = wwv_and( r4, mask52 );

  fd_bn254_fp52x8_t res;
  res.l[0] = r0;
  res.l[1] = r1;
  res.l[2] = r2;
  res.l[3] = r3;
  res.l[4] = r4;
  return res;
}

FD_PROTOTYPES_END

#endif /* FD_HAS_AVX512 */

#endif /* HEADER_fd_src_ballet_bn254_avx512_fd_bn254_fp52_mul_h */
