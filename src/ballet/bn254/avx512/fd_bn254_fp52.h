#ifndef HEADER_fd_src_ballet_bn254_avx512_fd_bn254_fp52_h
#define HEADER_fd_src_ballet_bn254_avx512_fd_bn254_fp52_h

#if FD_HAS_AVX512

#include "../../../util/simd/fd_avx.h"
#include "../../../util/simd/fd_avx512.h"

/* fd_bn254_fp52x8_t represents 8 independent bn254 base field (Fp)
   elements packed into AVX-512 registers.  Each element is in
   radix-2^52 Montgomery form with R = 2^260.

   The struct contains 5 wwv_t (unsigned 8-wide 64-bit) registers.
   Each register holds one limb across all 8 independent elements:

     l[0] = [a0_0 a1_0 a2_0 a3_0 a4_0 a5_0 a6_0 a7_0]  (limb 0 of 8 elems)
     l[1] = [a0_1 a1_1 a2_1 a3_1 a4_1 a5_1 a6_1 a7_1]  (limb 1)
     l[2] = [a0_2 a1_2 a2_2 a3_2 a4_2 a5_2 a6_2 a7_2]  (limb 2)
     l[3] = [a0_3 a1_3 a2_3 a3_3 a4_3 a5_3 a6_3 a7_3]  (limb 3)
     l[4] = [a0_4 a1_4 a2_4 a3_4 a4_4 a5_4 a6_4 a7_4]  (limb 4)

   For element k (0 <= k < 8):
     value_k = l[0]_k + l[1]_k * 2^52 + l[2]_k * 2^104
             + l[3]_k * 2^156 + l[4]_k * 2^208

   The bn254 base field prime p has 254 bits, which fits in 5 limbs of
   52 bits (5*52 = 260 bits).  We use R = 2^260 for Montgomery
   arithmetic, so that Montgomery reduction aligns with limb boundaries.

   This layout is optimized for AVX-512 IFMA (Integer Fused Multiply-
   Add) instructions which operate on 52-bit unsigned integers natively
   via _mm512_madd52lo_epu64 and _mm512_madd52hi_epu64.  All 8
   independent field operations execute in parallel with a single
   instruction stream. */

struct fd_bn254_fp52x8 {
  wwv_t l[5];
};

typedef struct fd_bn254_fp52x8 fd_bn254_fp52x8_t;

/* bn254 base field prime p in radix-2^52 limbs:
   p = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47 */

static const ulong FD_BN254_FP52_P0    = 0x08c16d87cfd47UL;
static const ulong FD_BN254_FP52_P1    = 0x916871ca8d3c2UL;
static const ulong FD_BN254_FP52_P2    = 0x181585d97816aUL;
static const ulong FD_BN254_FP52_P3    = 0xa029b85045b68UL;
static const ulong FD_BN254_FP52_P4    = 0x030644e72e131UL;

/* Montgomery inverse: p[0] * p_inv == -1 (mod 2^52) */

static const ulong FD_BN254_FP52_P_INV = 0x20782e4866389UL;

/* R^2 mod p in radix-2^52, where R = 2^260.
   Used to convert a non-Montgomery value into R=2^260 Montgomery form
   via Montgomery multiplication: mont(a) = CIOS(a, R^2 mod p). */

static const ulong FD_BN254_FP52_R2_0  = 0x8a81d1966eb04UL;
static const ulong FD_BN254_FP52_R2_1  = 0x6195018016b86UL;
static const ulong FD_BN254_FP52_R2_2  = 0xb4f898c98e615UL;
static const ulong FD_BN254_FP52_R2_3  = 0x9969bfd531600UL;
static const ulong FD_BN254_FP52_R2_4  = 0x00a8469a30d3aUL;

/* One in Montgomery form: R mod p in radix-2^52. */

static const ulong FD_BN254_FP52_ONE_0 = 0x20880f6fce4b4UL;
static const ulong FD_BN254_FP52_ONE_1 = 0x49baa989a8455UL;
static const ulong FD_BN254_FP52_ONE_2 = 0x18f014a498908UL;
static const ulong FD_BN254_FP52_ONE_3 = 0x724f85a9201d8UL;
static const ulong FD_BN254_FP52_ONE_4 = 0x01f16424e1bb7UL;

/* 52-bit limb mask */

#define FD_BN254_FP52_MASK ((1UL<<52)-1)

FD_PROTOTYPES_BEGIN

/* fd_bn254_fp52_from64 converts a 256-bit integer from radix-2^64
   (4 limbs) to radix-2^52 (5 limbs).  The input a64 is little-endian
   (a64[0] is the least significant limb).  No modular reduction is
   performed; this is a pure radix conversion. */

static inline void
fd_bn254_fp52_from64( ulong       r52[5],
                      ulong const a64[4] ) {
  r52[0] =   a64[0]                          & FD_BN254_FP52_MASK;
  r52[1] = ( a64[0]>>52 | a64[1]<<12 )       & FD_BN254_FP52_MASK;
  r52[2] = ( a64[1]>>40 | a64[2]<<24 )       & FD_BN254_FP52_MASK;
  r52[3] = ( a64[2]>>28 | a64[3]<<36 )       & FD_BN254_FP52_MASK;
  r52[4] =   a64[3]>>16;
}

/* fd_bn254_fp52_to64 converts a 256-bit integer from radix-2^52
   (5 limbs) to radix-2^64 (4 limbs).  The input a52 must have limbs
   in [0, 2^52).  No modular reduction is performed; this is a pure
   radix conversion. */

static inline void
fd_bn254_fp52_to64( ulong       r64[4],
                    ulong const a52[5] ) {
  r64[0] =  a52[0]       | ( a52[1]<<52 );
  r64[1] = ( a52[1]>>12 ) | ( a52[2]<<40 );
  r64[2] = ( a52[2]>>24 ) | ( a52[3]<<28 );
  r64[3] = ( a52[3]>>36 ) | ( a52[4]<<16 );
}

/* fd_bn254_fp52x8_get_lane extracts one of the 8 field elements from
   the batched representation.  lane must be in [0,8).  The result is
   written to r52 as 5 radix-2^52 limbs. */

FD_FN_UNUSED static void
fd_bn254_fp52x8_get_lane( ulong                       r52[5],
                          fd_bn254_fp52x8_t const *   a,
                          int                         lane ) {
  ulong __attribute__((aligned(64))) buf[8];
  for( int i=0; i<5; i++ ) {
    wwv_st( buf, a->l[i] );
    r52[i] = buf[lane];
  }
}

/* fd_bn254_fp52x8_set_lane sets one of the 8 field elements in the
   batched representation.  lane must be in [0,8).  The value is taken
   from a52 as 5 radix-2^52 limbs.  Other lanes are preserved. */

FD_FN_UNUSED static void
fd_bn254_fp52x8_set_lane( fd_bn254_fp52x8_t *   r,
                          int                   lane,
                          ulong const           a52[5] ) {
  ulong __attribute__((aligned(64))) buf[8];
  for( int i=0; i<5; i++ ) {
    wwv_st( buf, r->l[i] );
    buf[lane] = a52[i];
    r->l[i] = wwv_ld( buf );
  }
}

/* fd_bn254_fp52x8_bcast broadcasts a single field element (5 radix-2^52
   limbs) to all 8 lanes. */

static inline void
fd_bn254_fp52x8_bcast( fd_bn254_fp52x8_t *   r,
                       ulong const           a52[5] ) {
  r->l[0] = wwv_bcast( a52[0] );
  r->l[1] = wwv_bcast( a52[1] );
  r->l[2] = wwv_bcast( a52[2] );
  r->l[3] = wwv_bcast( a52[3] );
  r->l[4] = wwv_bcast( a52[4] );
}

/* fd_bn254_fp52x8_zero sets all 8 field elements to zero. */

static inline void
fd_bn254_fp52x8_zero( fd_bn254_fp52x8_t * r ) {
  r->l[0] = wwv_zero();
  r->l[1] = wwv_zero();
  r->l[2] = wwv_zero();
  r->l[3] = wwv_zero();
  r->l[4] = wwv_zero();
}

/* fd_bn254_fp52x8_set_one sets all 8 field elements to one in
   Montgomery form (R mod p). */

static inline void
fd_bn254_fp52x8_set_one( fd_bn254_fp52x8_t * r ) {
  r->l[0] = wwv_bcast( FD_BN254_FP52_ONE_0 );
  r->l[1] = wwv_bcast( FD_BN254_FP52_ONE_1 );
  r->l[2] = wwv_bcast( FD_BN254_FP52_ONE_2 );
  r->l[3] = wwv_bcast( FD_BN254_FP52_ONE_3 );
  r->l[4] = wwv_bcast( FD_BN254_FP52_ONE_4 );
}

/* fd_bn254_fp52_from_fp64_mont converts a field element from
   radix-2^64 (as used by the existing bn254 implementation, which uses
   R=2^256 Montgomery) to radix-2^52.

   The result is in radix-2^52 representation of the same 256-bit
   integer.  If the input was a*R_256 mod p (R_256 = 2^256 Montgomery),
   the output represents a*R_256 in radix-2^52.  To convert to R_260
   Montgomery (R_260 = 2^260), a subsequent Montgomery multiply by 2^4
   (i.e., by 16 mod p in the R_260 domain) is needed.  This is
   typically done externally. */

static inline void
fd_bn254_fp52_from_fp64_mont( ulong       r52[5],
                              ulong const a64[4] ) {
  fd_bn254_fp52_from64( r52, a64 );
}

/* fd_bn254_fp52_to_fp64_mont converts a field element from radix-2^52
   back to radix-2^64.  The caller is responsible for ensuring the
   Montgomery domain is appropriate (e.g., converting from R_260 back
   to R_256 before calling this if interoperating with the existing
   bn254 code). */

static inline void
fd_bn254_fp52_to_fp64_mont( ulong       r64[4],
                            ulong const a52[5] ) {
  fd_bn254_fp52_to64( r64, a52 );
}

FD_PROTOTYPES_END

#endif /* FD_HAS_AVX512 */

#endif /* HEADER_fd_src_ballet_bn254_avx512_fd_bn254_fp52_h */
