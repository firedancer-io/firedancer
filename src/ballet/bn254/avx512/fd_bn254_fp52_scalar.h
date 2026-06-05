#ifndef HEADER_fd_src_ballet_bn254_avx512_fd_bn254_fp52_scalar_h
#define HEADER_fd_src_ballet_bn254_avx512_fd_bn254_fp52_scalar_h

#if FD_HAS_AVX512

/* fd_bn254_fp52_scalar.h provides 8-way batched and single-lane
   Montgomery arithmetic on the BN254 scalar field (Fr) using AVX-512
   IFMA instructions, with radix-2^52 and R = 2^260.

   The scalar field modulus is:
     r = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001

   This mirrors the structure of fd_bn254_fp52_mul.h but uses scalar
   field (Fr) constants instead of base field (Fp) constants.

   The primary consumer is Poseidon hashing over the BN254 scalar
   field. */

#include "fd_bn254_fp52_mul.h"
#include "../fd_bn254_scalar.h"

/* BN254 scalar field modulus r in radix-2^52 limbs. */

static const ulong FD_BN254_FR52_R0    = 0x1f593f0000001UL;
static const ulong FD_BN254_FR52_R1    = 0x4879b9709143eUL;
static const ulong FD_BN254_FR52_R2    = 0x181585d2833e8UL;
static const ulong FD_BN254_FR52_R3    = 0xa029b85045b68UL;
static const ulong FD_BN254_FR52_R4    = 0x030644e72e131UL;

/* Montgomery inverse: r[0] * r_inv == -1 (mod 2^52) */

static const ulong FD_BN254_FR52_R_INV = 0x1f593efffffffUL;

/* One in Montgomery form: R mod r in radix-2^52, where R = 2^260. */

static const ulong FD_BN254_FR52_ONE_0 = 0xb6b753fffffacUL;
static const ulong FD_BN254_FR52_ONE_1 = 0x380f271055b9dUL;
static const ulong FD_BN254_FR52_ONE_2 = 0x18f016ecef7c8UL;
static const ulong FD_BN254_FR52_ONE_3 = 0x724f85a9201d8UL;
static const ulong FD_BN254_FR52_ONE_4 = 0x01f16424e1bb7UL;

/* R^2 mod r in radix-2^52.  Used to convert a non-Montgomery value
   into R=2^260 Montgomery form via Montgomery multiplication:
   mont(a) = CIOS(a, R^2 mod r). */

static const ulong FD_BN254_FR52_R2_0  = 0x0b852d16da6f5UL;
static const ulong FD_BN254_FR52_R2_1  = 0xc621620cddce3UL;
static const ulong FD_BN254_FR52_R2_2  = 0xaf1b95343ffb6UL;
static const ulong FD_BN254_FR52_R2_3  = 0xc3c15e103e7c2UL;
static const ulong FD_BN254_FR52_R2_4  = 0x00281528fa122UL;

/* Conversion factor from R_256 to R_260 Montgomery form.
   If the input is a*R_256 mod r, multiplying (in R_260 Montgomery)
   by this factor yields a*R_260 mod r.
   This is 16 * R_260 mod r in radix-2^52. */

static const ulong FD_BN254_FR52_CONV_TO_260_0 = 0x31f8c9ffffab6UL;
static const ulong FD_BN254_FR52_CONV_TO_260_1 = 0xac31329faef6eUL;
static const ulong FD_BN254_FR52_CONV_TO_260_2 = 0x9e2a3495d7570UL;
static const ulong FD_BN254_FR52_CONV_TO_260_3 = 0xe357276f48b70UL;
static const ulong FD_BN254_FR52_CONV_TO_260_4 = 0x00d791464ef86UL;

/* Conversion factor from R_260 to R_256 Montgomery form.
   If we have a*R_260 mod r, multiplying (in R_260 Montgomery)
   by this factor yields a*R_256 mod r.
   This is R_256 mod r in radix-2^52 (NOT in Montgomery form). */

static const ulong FD_BN254_FR52_CONV_TO_256_0 = 0x6341c4ffffffbUL;
static const ulong FD_BN254_FR52_CONV_TO_256_1 = 0x959f60cd29ac9UL;
static const ulong FD_BN254_FR52_CONV_TO_256_2 = 0x879462e36fc76UL;
static const ulong FD_BN254_FR52_CONV_TO_256_3 = 0xdf2f666ea36f7UL;
static const ulong FD_BN254_FR52_CONV_TO_256_4 = 0x00e0a77c19a07UL;

/* Broadcast constants for 8-way batched operations. */

#define FD_BN254_FR52X8_R0     wwv_bcast( 0x1f593f0000001UL )
#define FD_BN254_FR52X8_R1     wwv_bcast( 0x4879b9709143eUL )
#define FD_BN254_FR52X8_R2     wwv_bcast( 0x181585d2833e8UL )
#define FD_BN254_FR52X8_R3     wwv_bcast( 0xa029b85045b68UL )
#define FD_BN254_FR52X8_R4     wwv_bcast( 0x030644e72e131UL )
#define FD_BN254_FR52X8_R_INV  wwv_bcast( 0x1f593efffffffUL )
#define FD_BN254_FR52X8_MASK52 wwv_bcast( 0xfffffffffffffUL )

FD_PROTOTYPES_BEGIN

/* fd_bn254_fr52x8_cond_sub_r subtracts r from a 5-limb carry-
   propagated result if the result is >= r.  Identical to
   fd_bn254_fp52x8_cond_sub_p but for the scalar field modulus. */

FD_FN_UNUSED static inline fd_bn254_fp52x8_t
fd_bn254_fr52x8_cond_sub_r( wwv_t t0, wwv_t t1, wwv_t t2, wwv_t t3, wwv_t t4 ) {
  wwv_t const r0     = FD_BN254_FR52X8_R0;
  wwv_t const r1     = FD_BN254_FR52X8_R1;
  wwv_t const r2     = FD_BN254_FR52X8_R2;
  wwv_t const r3     = FD_BN254_FR52X8_R3;
  wwv_t const r4     = FD_BN254_FR52X8_R4;
  wwv_t const mask52 = FD_BN254_FR52X8_MASK52;
  wwv_t const one    = wwv_one();

  /* Multi-limb subtraction d = t - r with borrow propagation. */

  /* Limb 0 */
  wwv_t d0 = wwv_and( wwv_sub( t0, r0 ), mask52 );
  int   b0 = wwv_lt( t0, r0 );

  /* Limb 1 */
  wwv_t d1 = wwv_sub( t1, r1 );
  d1        = wwv_sub_if( b0, d1, one, d1 );
  int   b1  = wwv_lt( t1, r1 ) | ( wwv_eq( t1, r1 ) & b0 );
  d1        = wwv_and( d1, mask52 );

  /* Limb 2 */
  wwv_t d2 = wwv_sub( t2, r2 );
  d2        = wwv_sub_if( b1, d2, one, d2 );
  int   b2  = wwv_lt( t2, r2 ) | ( wwv_eq( t2, r2 ) & b1 );
  d2        = wwv_and( d2, mask52 );

  /* Limb 3 */
  wwv_t d3 = wwv_sub( t3, r3 );
  d3        = wwv_sub_if( b2, d3, one, d3 );
  int   b3  = wwv_lt( t3, r3 ) | ( wwv_eq( t3, r3 ) & b2 );
  d3        = wwv_and( d3, mask52 );

  /* Limb 4 */
  wwv_t d4 = wwv_sub( t4, r4 );
  d4        = wwv_sub_if( b3, d4, one, d4 );
  int   b4  = wwv_lt( t4, r4 ) | ( wwv_eq( t4, r4 ) & b3 );
  d4        = wwv_and( d4, mask52 );

  /* If final borrow is set, t < r: keep t.
     If final borrow is clear, t >= r: use d = t - r. */

  fd_bn254_fp52x8_t res;
  res.l[0] = wwv_if( b4, t0, d0 );
  res.l[1] = wwv_if( b4, t1, d1 );
  res.l[2] = wwv_if( b4, t2, d2 );
  res.l[3] = wwv_if( b4, t3, d3 );
  res.l[4] = wwv_if( b4, t4, d4 );
  return res;
}

/* fd_bn254_fr52x8_mul computes r = a * b in Montgomery form using
   8-way batched CIOS with AVX-512 IFMA for the BN254 scalar field.

   Each of the 8 lanes independently computes:
     r = a * b * R^{-1} mod r_mod

   where R = 2^260 and r_mod is the BN254 scalar field modulus. */

FD_FN_UNUSED static inline fd_bn254_fp52x8_t
fd_bn254_fr52x8_mul( fd_bn254_fp52x8_t const * a,
                     fd_bn254_fp52x8_t const * b ) {
  wwv_t const zero   = wwv_zero();
  wwv_t const r0     = FD_BN254_FR52X8_R0;
  wwv_t const r1     = FD_BN254_FR52X8_R1;
  wwv_t const r2     = FD_BN254_FR52X8_R2;
  wwv_t const r3     = FD_BN254_FR52X8_R3;
  wwv_t const r4     = FD_BN254_FR52X8_R4;
  wwv_t const r_inv  = FD_BN254_FR52X8_R_INV;
  wwv_t const mask52 = FD_BN254_FR52X8_MASK52;

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

# define FD_BN254_FR52X8_CIOS_ITER(BI)                                  \
  do {                                                                   \
    wwv_t bi = (BI);                                                     \
                                                                         \
    /* Step 1: t += a * b[i] */                                          \
    wwv_t h0 = wwv_madd52hi( zero, a0, bi );                            \
    wwv_t h1 = wwv_madd52hi( zero, a1, bi );                            \
    wwv_t h2 = wwv_madd52hi( zero, a2, bi );                            \
    wwv_t h3 = wwv_madd52hi( zero, a3, bi );                            \
    wwv_t h4 = wwv_madd52hi( zero, a4, bi );                            \
                                                                         \
    t0 = wwv_madd52lo( t0, a0, bi );                                     \
    t1 = wwv_add( wwv_madd52lo( t1, a1, bi ), h0 );                     \
    t2 = wwv_add( wwv_madd52lo( t2, a2, bi ), h1 );                     \
    t3 = wwv_add( wwv_madd52lo( t3, a3, bi ), h2 );                     \
    t4 = wwv_add( wwv_madd52lo( t4, a4, bi ), h3 );                     \
    t5 = wwv_add(               t5,           h4 );                      \
                                                                         \
    /* Step 2: Montgomery factor m = LO52( t[0] * r_inv ) */            \
    wwv_t m = wwv_and( wwv_madd52lo( zero, t0, r_inv ), mask52 );       \
                                                                         \
    /* Step 3: t += m * r_mod */                                         \
    h0 = wwv_madd52hi( zero, m, r0 );                                   \
    h1 = wwv_madd52hi( zero, m, r1 );                                   \
    h2 = wwv_madd52hi( zero, m, r2 );                                   \
    h3 = wwv_madd52hi( zero, m, r3 );                                   \
    h4 = wwv_madd52hi( zero, m, r4 );                                   \
                                                                         \
    t0 = wwv_madd52lo( t0, m, r0 );                                      \
    t1 = wwv_add( wwv_madd52lo( t1, m, r1 ), h0 );                      \
    t2 = wwv_add( wwv_madd52lo( t2, m, r2 ), h1 );                      \
    t3 = wwv_add( wwv_madd52lo( t3, m, r3 ), h2 );                      \
    t4 = wwv_add( wwv_madd52lo( t4, m, r4 ), h3 );                      \
    t5 = wwv_add(               t5,          h4 );                       \
                                                                         \
    /* Step 4: Divide by 2^52 (shift right one limb). */                 \
    wwv_t carry = wwv_shr( t0, 52 );                                    \
    t0 = wwv_add( t1, carry );                                           \
    t1 = t2;                                                             \
    t2 = t3;                                                             \
    t3 = t4;                                                             \
    t4 = t5;                                                             \
    t5 = zero;                                                           \
  } while(0)

  FD_BN254_FR52X8_CIOS_ITER( b->l[0] );
  FD_BN254_FR52X8_CIOS_ITER( b->l[1] );
  FD_BN254_FR52X8_CIOS_ITER( b->l[2] );
  FD_BN254_FR52X8_CIOS_ITER( b->l[3] );
  FD_BN254_FR52X8_CIOS_ITER( b->l[4] );

# undef FD_BN254_FR52X8_CIOS_ITER

  /* Final carry propagation. */
  t1 = wwv_add( t1, wwv_shr( t0, 52 ) ); t0 = wwv_and( t0, mask52 );
  t2 = wwv_add( t2, wwv_shr( t1, 52 ) ); t1 = wwv_and( t1, mask52 );
  t3 = wwv_add( t3, wwv_shr( t2, 52 ) ); t2 = wwv_and( t2, mask52 );
  t4 = wwv_add( t4, wwv_shr( t3, 52 ) ); t3 = wwv_and( t3, mask52 );

  return fd_bn254_fr52x8_cond_sub_r( t0, t1, t2, t3, t4 );
}

/* fd_bn254_fr52x8_sqr computes r = a^2 in Montgomery form.
   Currently implemented as mul(a, a). */

FD_FN_UNUSED static inline fd_bn254_fp52x8_t
fd_bn254_fr52x8_sqr( fd_bn254_fp52x8_t const * a ) {
  return fd_bn254_fr52x8_mul( a, a );
}

/* fd_bn254_fr52x8_add computes r = (a + b) mod r_mod in Montgomery
   form.  Each of the 8 lanes independently computes the modular sum. */

FD_FN_UNUSED static inline fd_bn254_fp52x8_t
fd_bn254_fr52x8_add( fd_bn254_fp52x8_t const * a,
                     fd_bn254_fp52x8_t const * b ) {
  wwv_t const mask52 = FD_BN254_FR52X8_MASK52;

  wwv_t t0 = wwv_add( a->l[0], b->l[0] );
  wwv_t t1 = wwv_add( a->l[1], b->l[1] );
  wwv_t t2 = wwv_add( a->l[2], b->l[2] );
  wwv_t t3 = wwv_add( a->l[3], b->l[3] );
  wwv_t t4 = wwv_add( a->l[4], b->l[4] );

  /* Carry propagation */
  t1 = wwv_add( t1, wwv_shr( t0, 52 ) ); t0 = wwv_and( t0, mask52 );
  t2 = wwv_add( t2, wwv_shr( t1, 52 ) ); t1 = wwv_and( t1, mask52 );
  t3 = wwv_add( t3, wwv_shr( t2, 52 ) ); t2 = wwv_and( t2, mask52 );
  t4 = wwv_add( t4, wwv_shr( t3, 52 ) ); t3 = wwv_and( t3, mask52 );

  return fd_bn254_fr52x8_cond_sub_r( t0, t1, t2, t3, t4 );
}

/* fd_bn254_fr52x8_sub computes r = (a - b) mod r_mod in Montgomery
   form.  Each of the 8 lanes independently computes the modular
   difference. */

FD_FN_UNUSED static inline fd_bn254_fp52x8_t
fd_bn254_fr52x8_sub( fd_bn254_fp52x8_t const * a,
                     fd_bn254_fp52x8_t const * b ) {
  wwv_t const r0     = FD_BN254_FR52X8_R0;
  wwv_t const r1     = FD_BN254_FR52X8_R1;
  wwv_t const r2     = FD_BN254_FR52X8_R2;
  wwv_t const r3     = FD_BN254_FR52X8_R3;
  wwv_t const r4     = FD_BN254_FR52X8_R4;
  wwv_t const mask52 = FD_BN254_FR52X8_MASK52;
  wwv_t const one    = wwv_one();

  /* Multi-limb unsigned subtraction d = a - b with borrow chain. */

  wwv_t d0 = wwv_and( wwv_sub( a->l[0], b->l[0] ), mask52 );
  int   bw0 = wwv_lt( a->l[0], b->l[0] );

  wwv_t d1 = wwv_sub( a->l[1], b->l[1] );
  d1        = wwv_sub_if( bw0, d1, one, d1 );
  int   bw1 = wwv_lt( a->l[1], b->l[1] ) | ( wwv_eq( a->l[1], b->l[1] ) & bw0 );
  d1        = wwv_and( d1, mask52 );

  wwv_t d2 = wwv_sub( a->l[2], b->l[2] );
  d2        = wwv_sub_if( bw1, d2, one, d2 );
  int   bw2 = wwv_lt( a->l[2], b->l[2] ) | ( wwv_eq( a->l[2], b->l[2] ) & bw1 );
  d2        = wwv_and( d2, mask52 );

  wwv_t d3 = wwv_sub( a->l[3], b->l[3] );
  d3        = wwv_sub_if( bw2, d3, one, d3 );
  int   bw3 = wwv_lt( a->l[3], b->l[3] ) | ( wwv_eq( a->l[3], b->l[3] ) & bw2 );
  d3        = wwv_and( d3, mask52 );

  wwv_t d4 = wwv_sub( a->l[4], b->l[4] );
  d4        = wwv_sub_if( bw3, d4, one, d4 );
  int   bw4 = wwv_lt( a->l[4], b->l[4] ) | ( wwv_eq( a->l[4], b->l[4] ) & bw3 );
  d4        = wwv_and( d4, mask52 );

  /* If final borrow set, a < b: add r_mod to correct. */

  wwv_t s0 = wwv_add_if( bw4, d0, r0, d0 );
  wwv_t s1 = wwv_add_if( bw4, d1, r1, d1 );
  wwv_t s2 = wwv_add_if( bw4, d2, r2, d2 );
  wwv_t s3 = wwv_add_if( bw4, d3, r3, d3 );
  wwv_t s4 = wwv_add_if( bw4, d4, r4, d4 );

  /* Carry propagation after conditional addition. */
  s1 = wwv_add( s1, wwv_shr( s0, 52 ) ); s0 = wwv_and( s0, mask52 );
  s2 = wwv_add( s2, wwv_shr( s1, 52 ) ); s1 = wwv_and( s1, mask52 );
  s3 = wwv_add( s3, wwv_shr( s2, 52 ) ); s2 = wwv_and( s2, mask52 );
  s4 = wwv_add( s4, wwv_shr( s3, 52 ) ); s3 = wwv_and( s3, mask52 );
  s4 = wwv_and( s4, mask52 );

  fd_bn254_fp52x8_t res;
  res.l[0] = s0;
  res.l[1] = s1;
  res.l[2] = s2;
  res.l[3] = s3;
  res.l[4] = s4;
  return res;
}

/* fd_bn254_fr52x8_set_one sets all 8 lanes to one in Montgomery form
   (R mod r). */

FD_FN_UNUSED static inline void
fd_bn254_fr52x8_set_one( fd_bn254_fp52x8_t * res ) {
  res->l[0] = wwv_bcast( FD_BN254_FR52_ONE_0 );
  res->l[1] = wwv_bcast( FD_BN254_FR52_ONE_1 );
  res->l[2] = wwv_bcast( FD_BN254_FR52_ONE_2 );
  res->l[3] = wwv_bcast( FD_BN254_FR52_ONE_3 );
  res->l[4] = wwv_bcast( FD_BN254_FR52_ONE_4 );
}

/* Scalar (single-element) operations on radix-2^52 Montgomery form.
   These operate on ulong[5] arrays and use a single CIOS loop
   (no AVX-512 batching).

   These are used for operations that are not easily batchable, such
   as the scalar accumulation in MDS matrix-vector multiply. */

/* fd_bn254_fr52_cond_sub_r conditionally subtracts the scalar field
   modulus r from a 5-limb carry-propagated value if it is >= r. */

FD_FN_UNUSED static inline void
fd_bn254_fr52_cond_sub_r( ulong t[5] ) {
  /* Check if t >= r by attempting subtraction. */
  long  bw = 0;
  ulong d[5];

  long diff;
  diff = (long)t[0] - (long)FD_BN254_FR52_R0 - bw;
  d[0] = (ulong)diff & FD_BN254_FP52_MASK;
  bw   = (diff < 0) ? 1 : 0;

  diff = (long)t[1] - (long)FD_BN254_FR52_R1 - bw;
  d[1] = (ulong)diff & FD_BN254_FP52_MASK;
  bw   = (diff < 0) ? 1 : 0;

  diff = (long)t[2] - (long)FD_BN254_FR52_R2 - bw;
  d[2] = (ulong)diff & FD_BN254_FP52_MASK;
  bw   = (diff < 0) ? 1 : 0;

  diff = (long)t[3] - (long)FD_BN254_FR52_R3 - bw;
  d[3] = (ulong)diff & FD_BN254_FP52_MASK;
  bw   = (diff < 0) ? 1 : 0;

  diff = (long)t[4] - (long)FD_BN254_FR52_R4 - bw;
  d[4] = (ulong)diff & FD_BN254_FP52_MASK;
  bw   = (diff < 0) ? 1 : 0;

  /* If no borrow, t >= r: use d.  Otherwise keep t. */
  if( !bw ) {
    t[0] = d[0]; t[1] = d[1]; t[2] = d[2]; t[3] = d[3]; t[4] = d[4];
  }
}

/* fd_bn254_fr52_mul_scalar computes r = a * b * R^{-1} mod r_mod
   using scalar (non-batched) CIOS.  a and b are in radix-2^52
   Montgomery form with R = 2^260. */

FD_FN_UNUSED static inline void
fd_bn254_fr52_mul_scalar( ulong       res[5],
                          ulong const a[5],
                          ulong const b[5] ) {
  static const ulong rmod[5] = {
    0x1f593f0000001UL, 0x4879b9709143eUL, 0x181585d2833e8UL,
    0xa029b85045b68UL, 0x030644e72e131UL
  };

  /* 6-limb accumulator */
  ulong t[6] = { 0, 0, 0, 0, 0, 0 };

  for( ulong i=0; i<5; i++ ) {
    ulong bi = b[i];

    /* Step 1: t += a * bi.
       Use __uint128_t for 52x52->104 bit products. */
    __uint128_t carry = 0;
    for( ulong j=0; j<5; j++ ) {
      __uint128_t prod = (__uint128_t)a[j] * bi + t[j] + carry;
      t[j]  = (ulong)prod & FD_BN254_FP52_MASK;
      carry = prod >> 52;
    }
    t[5] += (ulong)carry;

    /* Step 2: Montgomery factor m = t[0] * r_inv mod 2^52 */
    ulong m = (t[0] * FD_BN254_FR52_R_INV) & FD_BN254_FP52_MASK;

    /* Step 3: t += m * r_mod */
    carry = 0;
    for( ulong j=0; j<5; j++ ) {
      __uint128_t prod = (__uint128_t)m * rmod[j] + t[j] + carry;
      t[j]  = (ulong)prod & FD_BN254_FP52_MASK;
      carry = prod >> 52;
    }
    t[5] += (ulong)carry;

    /* Step 4: Shift right by one limb */
    t[0] = t[1]; t[1] = t[2]; t[2] = t[3]; t[3] = t[4]; t[4] = t[5];
    t[5] = 0;
  }

  /* Copy and conditionally subtract */
  res[0] = t[0]; res[1] = t[1]; res[2] = t[2]; res[3] = t[3]; res[4] = t[4];
  fd_bn254_fr52_cond_sub_r( res );
}

/* fd_bn254_fr52_sqr_scalar computes r = a^2 mod r_mod. */

FD_FN_UNUSED static inline void
fd_bn254_fr52_sqr_scalar( ulong       res[5],
                          ulong const a[5] ) {
  fd_bn254_fr52_mul_scalar( res, a, a );
}

/* fd_bn254_fr52_add_scalar computes r = (a + b) mod r_mod. */

FD_FN_UNUSED static inline void
fd_bn254_fr52_add_scalar( ulong       res[5],
                          ulong const a[5],
                          ulong const b[5] ) {
  /* Limb-wise addition with carry propagation */
  ulong t[5];
  ulong carry = 0;
  for( ulong i=0; i<5; i++ ) {
    ulong sum = a[i] + b[i] + carry;
    t[i]  = sum & FD_BN254_FP52_MASK;
    carry = sum >> 52;
  }
  (void)carry;

  fd_bn254_fr52_cond_sub_r( t );
  res[0] = t[0]; res[1] = t[1]; res[2] = t[2]; res[3] = t[3]; res[4] = t[4];
}

/* fd_bn254_fr52_sub_scalar computes r = (a - b) mod r_mod. */

FD_FN_UNUSED static inline void
fd_bn254_fr52_sub_scalar( ulong       res[5],
                          ulong const a[5],
                          ulong const b[5] ) {
  static const ulong rmod[5] = {
    0x1f593f0000001UL, 0x4879b9709143eUL, 0x181585d2833e8UL,
    0xa029b85045b68UL, 0x030644e72e131UL
  };

  long bw = 0;
  ulong d[5];

  for( ulong i=0; i<5; i++ ) {
    long diff = (long)a[i] - (long)b[i] - bw;
    d[i] = (ulong)diff & FD_BN254_FP52_MASK;
    bw   = (diff < 0) ? 1 : 0;
  }

  /* If borrow, add r_mod */
  if( bw ) {
    ulong carry = 0;
    for( ulong i=0; i<5; i++ ) {
      ulong sum = d[i] + rmod[i] + carry;
      d[i]  = sum & FD_BN254_FP52_MASK;
      carry = sum >> 52;
    }
  }

  res[0] = d[0]; res[1] = d[1]; res[2] = d[2]; res[3] = d[3]; res[4] = d[4];
}

/* fd_bn254_fr52_from_scalar converts a fd_bn254_scalar_t (radix-2^64,
   R_256 = 2^256 Montgomery form) to radix-2^52, R_260 = 2^260
   Montgomery form.

   The conversion is:
     1. Rebase from radix-2^64 to radix-2^52 (pure bit manipulation).
     2. Montgomery-multiply by 16*R_260 mod r to convert from R_256
        to R_260 domain:
        CIOS(a*R_256, 16*R_260) = a*R_256 * 16*R_260 * R_260^{-1}
                                = a * R_256 * 16  = a * R_260. */

FD_FN_UNUSED static inline void
fd_bn254_fr52_from_scalar( ulong                     r52[5],
                           fd_bn254_scalar_t const * s ) {
  ulong tmp[5];
  fd_bn254_fp52_from64( tmp, s->limbs );

  /* Multiply by conversion factor to go R_256 -> R_260 */
  ulong conv[5] = {
    FD_BN254_FR52_CONV_TO_260_0, FD_BN254_FR52_CONV_TO_260_1,
    FD_BN254_FR52_CONV_TO_260_2, FD_BN254_FR52_CONV_TO_260_3,
    FD_BN254_FR52_CONV_TO_260_4
  };
  fd_bn254_fr52_mul_scalar( r52, tmp, conv );
}

/* fd_bn254_fr52_to_scalar converts from radix-2^52 R_260 Montgomery
   form back to fd_bn254_scalar_t (radix-2^64 R_256 Montgomery).

   The conversion is:
     1. Montgomery-multiply by R_256 mod r (non-Montgomery) to convert:
        CIOS(a*R_260, R_256) = a*R_260 * R_256 * R_260^{-1}
                             = a * R_256.
     2. Rebase from radix-2^52 to radix-2^64 (pure bit manipulation). */

FD_FN_UNUSED static inline void
fd_bn254_fr52_to_scalar( fd_bn254_scalar_t * s,
                         ulong const         r52[5] ) {
  ulong conv[5] = {
    FD_BN254_FR52_CONV_TO_256_0, FD_BN254_FR52_CONV_TO_256_1,
    FD_BN254_FR52_CONV_TO_256_2, FD_BN254_FR52_CONV_TO_256_3,
    FD_BN254_FR52_CONV_TO_256_4
  };
  ulong tmp[5];
  fd_bn254_fr52_mul_scalar( tmp, r52, conv );
  fd_bn254_fp52_to64( s->limbs, tmp );
}

/* fd_bn254_fr52_from_bytes converts a 32-byte little-endian integer
   (NOT in Montgomery form) to radix-2^52 R_260 Montgomery form.
   The input must be < r. */

FD_FN_UNUSED static inline void
fd_bn254_fr52_from_bytes( ulong       r52[5],
                          uchar const in[32] ) {
  /* Load as 4 ulongs, convert to radix-2^52 */
  ulong a64[4];
  a64[0] = FD_LOAD( ulong, in     );
  a64[1] = FD_LOAD( ulong, in+8   );
  a64[2] = FD_LOAD( ulong, in+16  );
  a64[3] = FD_LOAD( ulong, in+24  );

  ulong tmp[5];
  fd_bn254_fp52_from64( tmp, a64 );

  /* Multiply by R^2 mod r to get into Montgomery form */
  ulong r2[5] = {
    FD_BN254_FR52_R2_0, FD_BN254_FR52_R2_1,
    FD_BN254_FR52_R2_2, FD_BN254_FR52_R2_3,
    FD_BN254_FR52_R2_4
  };
  fd_bn254_fr52_mul_scalar( r52, tmp, r2 );
}

/* fd_bn254_fr52_to_bytes converts from radix-2^52 R_260 Montgomery
   form to a 32-byte little-endian integer. */

FD_FN_UNUSED static inline void
fd_bn254_fr52_to_bytes( uchar       out[32],
                        ulong const r52[5] ) {
  /* Montgomery reduction: multiply by 1 (in non-Montgomery form).
     CIOS(a*R, 1) = a*R * 1 * R^{-1} = a. */
  ulong one_raw[5] = { 1, 0, 0, 0, 0 };
  ulong tmp[5];
  fd_bn254_fr52_mul_scalar( tmp, r52, one_raw );

  ulong a64[4];
  fd_bn254_fp52_to64( a64, tmp );

  FD_STORE( ulong, out,    a64[0] );
  FD_STORE( ulong, out+8,  a64[1] );
  FD_STORE( ulong, out+16, a64[2] );
  FD_STORE( ulong, out+24, a64[3] );
}

FD_PROTOTYPES_END

#endif /* FD_HAS_AVX512 */

#endif /* HEADER_fd_src_ballet_bn254_avx512_fd_bn254_fp52_scalar_h */
