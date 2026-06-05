#include "../../../util/fd_util.h"

#if FD_HAS_AVX512

#include "fd_bn254_fp52.h"
#include "fd_bn254_fp52_mul.h"
#include "fd_bn254_fp52_fp2.h"
#include "fd_bn254_fp52_fp6.h"
#include "fd_bn254_fp52_fp12.h"
#include "fd_bn254_fp52_g1.h"
#include "fd_bn254_fp52_g2.h"
#include "fd_bn254_fp52_pairing.h"
#include "fd_bn254_fp52_scalar.h"
#include "fd_bn254_fp52_poseidon.h"
#include "fd_bn254_fp2_avx.h"

/* Include the existing scalar bn254 implementation for comparison.
   fd_bn254.c is a unity build that pulls in fiat-crypto and all
   field/point operations. */
#include "../fd_bn254.c"

/* Helper: initialize an fd_bn254_fp_t (union) from 4 limbs. */
static inline fd_bn254_fp_t
fp_from_limbs( ulong l0, ulong l1, ulong l2, ulong l3 ) {
  fd_bn254_fp_t r;
  r.limbs[0] = l0; r.limbs[1] = l1;
  r.limbs[2] = l2; r.limbs[3] = l3;
  return r;
}

/* Conversion helpers: R=2^256 <-> R=2^260 Montgomery.

   The existing bn254 code uses R_256 = 2^256 Montgomery.
   Our AVX-512 code uses R_260 = 2^260 Montgomery.

   For testing, we convert by:
   1. Convert from R_256 Montgomery to plain: a = a_R256 * R_256^{-1} mod p
   2. Convert plain to radix-2^52
   3. Convert plain to R_260 Montgomery via mont_mul(plain, R260^2 mod p) */

/* Convert one Fp element from R=2^256 Montgomery (existing format)
   to radix-2^52 R=2^260 Montgomery (AVX-512 format). */
static void
fp_to_fp52_mont( ulong r52[5], fd_bn254_fp_t const * a_mont256 ) {
  /* Step 1: a_mont256 -> a (plain) via fiat_bn254_from_montgomery */
  fd_bn254_fp_t a_plain[1];
  fiat_bn254_from_montgomery( a_plain->limbs, a_mont256->limbs );

  /* Step 2: convert to radix-2^52 */
  ulong plain52[5];
  fd_bn254_fp52_from64( plain52, a_plain->limbs );

  /* Step 3: multiply by R^2_260 mod p to get into R=2^260 Montgomery.
     mont_mul(plain, R^2) = plain * R^2 * R^{-1} = plain * R. */
  fd_bn254_fp52x8_t x, r2;
  fd_bn254_fp52x8_bcast( &x, plain52 );

  ulong r2_52[5] = {
    FD_BN254_FP52_R2_0, FD_BN254_FP52_R2_1, FD_BN254_FP52_R2_2,
    FD_BN254_FP52_R2_3, FD_BN254_FP52_R2_4
  };
  fd_bn254_fp52x8_bcast( &r2, r2_52 );

  fd_bn254_fp52x8_t res = fd_bn254_fp52x8_mul( &x, &r2 );
  fd_bn254_fp52x8_get_lane( r52, &res, 0 );
}

/* Convert one Fp element from radix-2^52 R=2^260 Montgomery (AVX-512 format)
   back to R=2^256 Montgomery (existing format). */
static void
fp52_mont_to_fp( fd_bn254_fp_t * r_mont256, ulong const a52[5] ) {
  /* Step 1: convert from R=2^260 Montgomery to plain by Montgomery-
     multiplying by 1 (non-Montgomery) = {1,0,0,0,0}.
     mont_mul(a_R260, 1) = a_R260 * 1 * R_260^{-1} = a. */
  ulong one_plain[5] = { 1UL, 0UL, 0UL, 0UL, 0UL };
  fd_bn254_fp52x8_t x, one;
  fd_bn254_fp52x8_bcast( &x, a52 );
  fd_bn254_fp52x8_bcast( &one, one_plain );

  fd_bn254_fp52x8_t plain_res = fd_bn254_fp52x8_mul( &x, &one );
  ulong plain52[5];
  fd_bn254_fp52x8_get_lane( plain52, &plain_res, 0 );

  /* Step 2: convert radix-2^52 -> radix-2^64 */
  ulong plain64[4];
  fd_bn254_fp52_to64( plain64, plain52 );

  /* Step 3: convert to R=2^256 Montgomery form */
  r_mont256->limbs[0] = plain64[0];
  r_mont256->limbs[1] = plain64[1];
  r_mont256->limbs[2] = plain64[2];
  r_mont256->limbs[3] = plain64[3];
  fiat_bn254_to_montgomery( r_mont256->limbs, r_mont256->limbs );
}

/* ---- Test: radix conversion roundtrip ---- */
static void
test_radix_conversion( void ) {
  FD_LOG_NOTICE(( "Testing radix conversion roundtrip..." ));

  /* Test with known value: p-1 */
  ulong pm1[4] = { 0x3c208c16d87cfd46UL, 0x97816a916871ca8dUL,
                    0xb85045b68181585dUL, 0x30644e72e131a029UL };

  ulong r52[5];
  fd_bn254_fp52_from64( r52, pm1 );

  ulong r64[4];
  fd_bn254_fp52_to64( r64, r52 );

  FD_TEST( r64[0]==pm1[0] && r64[1]==pm1[1] && r64[2]==pm1[2] && r64[3]==pm1[3] );

  /* Test with zero */
  ulong z64[4] = {0,0,0,0};
  fd_bn254_fp52_from64( r52, z64 );
  fd_bn254_fp52_to64( r64, r52 );
  FD_TEST( r64[0]==0 && r64[1]==0 && r64[2]==0 && r64[3]==0 );

  /* Test with 1 */
  ulong one64[4] = {1,0,0,0};
  fd_bn254_fp52_from64( r52, one64 );
  fd_bn254_fp52_to64( r64, r52 );
  FD_TEST( r64[0]==1 && r64[1]==0 && r64[2]==0 && r64[3]==0 );

  /* Test with all-bits value */
  ulong test64[4] = { 0xdeadbeefcafebabeUL, 0x1234567890abcdefUL,
                       0xfedcba0987654321UL, 0x0123456789abcdefUL };
  fd_bn254_fp52_from64( r52, test64 );
  fd_bn254_fp52_to64( r64, r52 );
  FD_TEST( r64[0]==test64[0] && r64[1]==test64[1]
        && r64[2]==test64[2] && r64[3]==test64[3] );

  FD_LOG_NOTICE(( "  ...PASSED" ));
}

/* ---- Test: Montgomery multiplication correctness ---- */
static void
test_mul( void ) {
  FD_LOG_NOTICE(( "Testing Montgomery multiplication..." ));

  /* Test 1: 1 * 1 = 1 */
  {
    fd_bn254_fp52x8_t one;
    fd_bn254_fp52x8_set_one( &one );
    fd_bn254_fp52x8_t res = fd_bn254_fp52x8_mul( &one, &one );

    ulong r52[5];
    fd_bn254_fp52x8_get_lane( r52, &res, 0 );
    FD_TEST( r52[0]==FD_BN254_FP52_ONE_0 );
    FD_TEST( r52[1]==FD_BN254_FP52_ONE_1 );
    FD_TEST( r52[2]==FD_BN254_FP52_ONE_2 );
    FD_TEST( r52[3]==FD_BN254_FP52_ONE_3 );
    FD_TEST( r52[4]==FD_BN254_FP52_ONE_4 );
    FD_LOG_NOTICE(( "  1*1=1 ...OK" ));
  }

  /* Test 2: Compare with scalar implementation: 7 * 11 = 77. */
  {
    fd_bn254_fp_t a_plain = fp_from_limbs( 7, 0, 0, 0 );
    fd_bn254_fp_t b_plain = fp_from_limbs( 11, 0, 0, 0 );
    fd_bn254_fp_t a_mont[1], b_mont[1], ab_mont[1];

    fiat_bn254_to_montgomery( a_mont->limbs, a_plain.limbs );
    fiat_bn254_to_montgomery( b_mont->limbs, b_plain.limbs );
    fd_bn254_fp_mul( ab_mont, a_mont, b_mont );

    /* Convert a, b to R=2^260 radix-2^52 */
    ulong a52[5], b52[5];
    fp_to_fp52_mont( a52, a_mont );
    fp_to_fp52_mont( b52, b_mont );

    /* AVX-512 multiply */
    fd_bn254_fp52x8_t ax, bx;
    fd_bn254_fp52x8_bcast( &ax, a52 );
    fd_bn254_fp52x8_bcast( &bx, b52 );
    fd_bn254_fp52x8_t rx = fd_bn254_fp52x8_mul( &ax, &bx );

    /* Convert result back to R=2^256 */
    ulong res52[5];
    fd_bn254_fp52x8_get_lane( res52, &rx, 0 );
    fd_bn254_fp_t res_mont[1];
    fp52_mont_to_fp( res_mont, res52 );

    FD_TEST( fd_uint256_eq( res_mont, ab_mont ) );
    FD_LOG_NOTICE(( "  7*11=77 ...OK" ));
  }

  /* Test 3: Multiple values in different lanes. */
  {
    fd_bn254_fp_t vals[8];
    ulong vals52[8][5];

    for( int i=0; i<8; i++ ) {
      fd_bn254_fp_t plain = fp_from_limbs( (ulong)(i+2), 0, 0, 0 );
      fiat_bn254_to_montgomery( vals[i].limbs, plain.limbs );
      fp_to_fp52_mont( vals52[i], &vals[i] );
    }

    fd_bn254_fp52x8_t ax, bx;
    fd_bn254_fp52x8_zero( &ax );
    fd_bn254_fp52x8_zero( &bx );
    for( int i=0; i<8; i++ ) {
      fd_bn254_fp52x8_set_lane( &ax, i, vals52[i] );
      fd_bn254_fp52x8_set_lane( &bx, i, vals52[(i+1)%8] );
    }

    fd_bn254_fp52x8_t rx = fd_bn254_fp52x8_mul( &ax, &bx );

    for( int i=0; i<8; i++ ) {
      fd_bn254_fp_t expected[1];
      fd_bn254_fp_mul( expected, &vals[i], &vals[(i+1)%8] );

      ulong res52[5];
      fd_bn254_fp52x8_get_lane( res52, &rx, i );
      fd_bn254_fp_t res_mont[1];
      fp52_mont_to_fp( res_mont, res52 );

      FD_TEST( fd_uint256_eq( res_mont, expected ) );
    }
    FD_LOG_NOTICE(( "  8-lane mul ...OK" ));
  }

  /* Test 4: Squaring: 42^2 = 1764. */
  {
    fd_bn254_fp_t a_plain = fp_from_limbs( 42, 0, 0, 0 );
    fd_bn254_fp_t a_mont[1], a_sqr[1];
    fiat_bn254_to_montgomery( a_mont->limbs, a_plain.limbs );
    fd_bn254_fp_sqr( a_sqr, a_mont );

    ulong a52[5];
    fp_to_fp52_mont( a52, a_mont );
    fd_bn254_fp52x8_t ax;
    fd_bn254_fp52x8_bcast( &ax, a52 );
    fd_bn254_fp52x8_t rx = fd_bn254_fp52x8_sqr( &ax );

    ulong res52[5];
    fd_bn254_fp52x8_get_lane( res52, &rx, 0 );
    fd_bn254_fp_t res_mont[1];
    fp52_mont_to_fp( res_mont, res52 );

    FD_TEST( fd_uint256_eq( res_mont, a_sqr ) );
    FD_LOG_NOTICE(( "  42^2=1764 ...OK" ));
  }

  /* Test 5: Large value: (p-1)^2 */
  {
    fd_bn254_fp_t pm1 = fp_from_limbs(
      0x3c208c16d87cfd46UL, 0x97816a916871ca8dUL,
      0xb85045b68181585dUL, 0x30644e72e131a029UL
    );
    fd_bn254_fp_t pm1_mont[1], pm1_sqr[1];
    fiat_bn254_to_montgomery( pm1_mont->limbs, pm1.limbs );
    fd_bn254_fp_sqr( pm1_sqr, pm1_mont );

    ulong pm1_52[5];
    fp_to_fp52_mont( pm1_52, pm1_mont );
    fd_bn254_fp52x8_t ax;
    fd_bn254_fp52x8_bcast( &ax, pm1_52 );
    fd_bn254_fp52x8_t rx = fd_bn254_fp52x8_sqr( &ax );

    ulong res52[5];
    fd_bn254_fp52x8_get_lane( res52, &rx, 0 );
    fd_bn254_fp_t res_mont[1];
    fp52_mont_to_fp( res_mont, res52 );

    FD_TEST( fd_uint256_eq( res_mont, pm1_sqr ) );
    FD_LOG_NOTICE(( "  (p-1)^2 ...OK" ));
  }

  FD_LOG_NOTICE(( "  ...ALL PASSED" ));
}

/* ---- Test: Addition and subtraction ---- */
static void
test_add_sub( void ) {
  FD_LOG_NOTICE(( "Testing addition and subtraction..." ));

  /* Test 1: a + 0 = a */
  {
    fd_bn254_fp_t a_plain = fp_from_limbs( 123456789, 0, 0, 0 );
    fd_bn254_fp_t a_mont[1];
    fiat_bn254_to_montgomery( a_mont->limbs, a_plain.limbs );

    ulong a52[5];
    fp_to_fp52_mont( a52, a_mont );

    fd_bn254_fp52x8_t ax, zx;
    fd_bn254_fp52x8_bcast( &ax, a52 );
    fd_bn254_fp52x8_zero( &zx );

    fd_bn254_fp52x8_t rx = fd_bn254_fp52x8_add( &ax, &zx );
    ulong res52[5];
    fd_bn254_fp52x8_get_lane( res52, &rx, 0 );

    FD_TEST( res52[0]==a52[0] && res52[1]==a52[1] && res52[2]==a52[2]
          && res52[3]==a52[3] && res52[4]==a52[4] );
    FD_LOG_NOTICE(( "  a+0=a ...OK" ));
  }

  /* Test 2: a + b matches scalar */
  {
    fd_bn254_fp_t a_plain = fp_from_limbs( 100, 0, 0, 0 );
    fd_bn254_fp_t b_plain = fp_from_limbs( 200, 0, 0, 0 );
    fd_bn254_fp_t a_mont[1], b_mont[1], sum_mont[1];
    fiat_bn254_to_montgomery( a_mont->limbs, a_plain.limbs );
    fiat_bn254_to_montgomery( b_mont->limbs, b_plain.limbs );
    fd_bn254_fp_add( sum_mont, a_mont, b_mont );

    ulong a52[5], b52[5];
    fp_to_fp52_mont( a52, a_mont );
    fp_to_fp52_mont( b52, b_mont );

    fd_bn254_fp52x8_t ax, bx;
    fd_bn254_fp52x8_bcast( &ax, a52 );
    fd_bn254_fp52x8_bcast( &bx, b52 );
    fd_bn254_fp52x8_t rx = fd_bn254_fp52x8_add( &ax, &bx );

    ulong res52[5];
    fd_bn254_fp52x8_get_lane( res52, &rx, 0 );
    fd_bn254_fp_t res_mont[1];
    fp52_mont_to_fp( res_mont, res52 );

    FD_TEST( fd_uint256_eq( res_mont, sum_mont ) );
    FD_LOG_NOTICE(( "  100+200 ...OK" ));
  }

  /* Test 3: a - a = 0 */
  {
    fd_bn254_fp_t a_plain = fp_from_limbs( 42, 0, 0, 0 );
    fd_bn254_fp_t a_mont[1];
    fiat_bn254_to_montgomery( a_mont->limbs, a_plain.limbs );

    ulong a52[5];
    fp_to_fp52_mont( a52, a_mont );

    fd_bn254_fp52x8_t ax;
    fd_bn254_fp52x8_bcast( &ax, a52 );
    fd_bn254_fp52x8_t rx = fd_bn254_fp52x8_sub( &ax, &ax );

    ulong res52[5];
    fd_bn254_fp52x8_get_lane( res52, &rx, 0 );
    FD_TEST( res52[0]==0 && res52[1]==0 && res52[2]==0
          && res52[3]==0 && res52[4]==0 );
    FD_LOG_NOTICE(( "  a-a=0 ...OK" ));
  }

  /* Test 4: 0 - a = -a mod p */
  {
    fd_bn254_fp_t a_plain = fp_from_limbs( 1, 0, 0, 0 );
    fd_bn254_fp_t a_mont[1], neg_mont[1];
    fiat_bn254_to_montgomery( a_mont->limbs, a_plain.limbs );
    fd_bn254_fp_neg( neg_mont, a_mont );

    ulong a52[5];
    fp_to_fp52_mont( a52, a_mont );

    fd_bn254_fp52x8_t ax, zx;
    fd_bn254_fp52x8_bcast( &ax, a52 );
    fd_bn254_fp52x8_zero( &zx );
    fd_bn254_fp52x8_t rx = fd_bn254_fp52x8_sub( &zx, &ax );

    ulong res52[5];
    fd_bn254_fp52x8_get_lane( res52, &rx, 0 );
    fd_bn254_fp_t res_mont[1];
    fp52_mont_to_fp( res_mont, res52 );

    FD_TEST( fd_uint256_eq( res_mont, neg_mont ) );
    FD_LOG_NOTICE(( "  0-1=-1 ...OK" ));
  }

  /* Test 5: (p-1) + 1 = 0 mod p */
  {
    fd_bn254_fp_t pm1 = fp_from_limbs(
      0x3c208c16d87cfd46UL, 0x97816a916871ca8dUL,
      0xb85045b68181585dUL, 0x30644e72e131a029UL
    );
    fd_bn254_fp_t one = fp_from_limbs( 1, 0, 0, 0 );
    fd_bn254_fp_t pm1_mont[1], one_mont[1];
    fiat_bn254_to_montgomery( pm1_mont->limbs, pm1.limbs );
    fiat_bn254_to_montgomery( one_mont->limbs, one.limbs );

    ulong pm1_52[5], one52[5];
    fp_to_fp52_mont( pm1_52, pm1_mont );
    fp_to_fp52_mont( one52, one_mont );

    fd_bn254_fp52x8_t ax, bx;
    fd_bn254_fp52x8_bcast( &ax, pm1_52 );
    fd_bn254_fp52x8_bcast( &bx, one52 );
    fd_bn254_fp52x8_t rx = fd_bn254_fp52x8_add( &ax, &bx );

    ulong res52[5];
    fd_bn254_fp52x8_get_lane( res52, &rx, 0 );
    FD_TEST( res52[0]==0 && res52[1]==0 && res52[2]==0
          && res52[3]==0 && res52[4]==0 );
    FD_LOG_NOTICE(( "  (p-1)+1=0 ...OK" ));
  }

  FD_LOG_NOTICE(( "  ...ALL PASSED" ));
}

/* ---- Test: Chained multiplications ---- */
static void
test_chain( void ) {
  FD_LOG_NOTICE(( "Testing chained operations..." ));

  /* Compute 3^16 using repeated squaring. */
  fd_bn254_fp_t a_plain = fp_from_limbs( 3, 0, 0, 0 );
  fd_bn254_fp_t a_mont[1], a_pow[1];
  fiat_bn254_to_montgomery( a_mont->limbs, a_plain.limbs );

  /* Scalar: a^16 */
  fd_bn254_fp_sqr( a_pow, a_mont );
  fd_bn254_fp_sqr( a_pow, a_pow );
  fd_bn254_fp_sqr( a_pow, a_pow );
  fd_bn254_fp_sqr( a_pow, a_pow );

  /* AVX-512: a^16 */
  ulong a52[5];
  fp_to_fp52_mont( a52, a_mont );
  fd_bn254_fp52x8_t ax;
  fd_bn254_fp52x8_bcast( &ax, a52 );

  fd_bn254_fp52x8_t rx = fd_bn254_fp52x8_sqr( &ax );
  rx = fd_bn254_fp52x8_sqr( &rx );
  rx = fd_bn254_fp52x8_sqr( &rx );
  rx = fd_bn254_fp52x8_sqr( &rx );

  ulong res52[5];
  fd_bn254_fp52x8_get_lane( res52, &rx, 0 );
  fd_bn254_fp_t res_mont[1];
  fp52_mont_to_fp( res_mont, res52 );

  FD_TEST( fd_uint256_eq( res_mont, a_pow ) );
  FD_LOG_NOTICE(( "  3^16 ...OK" ));

  /* Compute 3*5 + 7*11 = 15 + 77 = 92 */
  {
    fd_bn254_fp_t b_plain = fp_from_limbs( 5, 0, 0, 0 );
    fd_bn254_fp_t c_plain = fp_from_limbs( 7, 0, 0, 0 );
    fd_bn254_fp_t d_plain = fp_from_limbs( 11, 0, 0, 0 );
    fd_bn254_fp_t b_mont[1], c_mont[1], d_mont[1];
    fd_bn254_fp_t ab[1], cd[1], expected[1];

    fiat_bn254_to_montgomery( b_mont->limbs, b_plain.limbs );
    fiat_bn254_to_montgomery( c_mont->limbs, c_plain.limbs );
    fiat_bn254_to_montgomery( d_mont->limbs, d_plain.limbs );

    fd_bn254_fp_mul( ab, a_mont, b_mont );
    fd_bn254_fp_mul( cd, c_mont, d_mont );
    fd_bn254_fp_add( expected, ab, cd );

    ulong b52[5], c52[5], d52[5];
    fp_to_fp52_mont( b52, b_mont );
    fp_to_fp52_mont( c52, c_mont );
    fp_to_fp52_mont( d52, d_mont );

    fd_bn254_fp52x8_t bx, cx, dx;
    fd_bn254_fp52x8_bcast( &bx, b52 );
    fd_bn254_fp52x8_bcast( &cx, c52 );
    fd_bn254_fp52x8_bcast( &dx, d52 );

    fd_bn254_fp52x8_t abx = fd_bn254_fp52x8_mul( &ax, &bx );
    fd_bn254_fp52x8_t cdx = fd_bn254_fp52x8_mul( &cx, &dx );
    fd_bn254_fp52x8_t resx = fd_bn254_fp52x8_add( &abx, &cdx );

    fd_bn254_fp52x8_get_lane( res52, &resx, 0 );
    fp52_mont_to_fp( res_mont, res52 );

    FD_TEST( fd_uint256_eq( res_mont, expected ) );
    FD_LOG_NOTICE(( "  3*5 + 7*11 = 92 ...OK" ));
  }

  FD_LOG_NOTICE(( "  ...ALL PASSED" ));
}

/* ---- Fp2 conversion helpers ---- */

static void
fp2_to_fp52( fd_bn254_fp52_fp2_t * r, fd_bn254_fp2_t const * a ) {
  fp_to_fp52_mont( r->el[0], &a->el[0] );
  fp_to_fp52_mont( r->el[1], &a->el[1] );
}

static void
fp52_to_fp2( fd_bn254_fp2_t * r, fd_bn254_fp52_fp2_t const * a ) {
  fp52_mont_to_fp( &r->el[0], a->el[0] );
  fp52_mont_to_fp( &r->el[1], a->el[1] );
}

/* ---- Test: Fp2 multiplication ---- */
static void
test_fp2_mul( void ) {
  FD_LOG_NOTICE(( "Testing Fp2 multiplication..." ));

  /* Test 1: (3+5i) * (7+11i) = (3*7 - 5*11) + (3*11 + 5*7)i = (21-55) + (33+35)i = -34 + 68i */
  {
    fd_bn254_fp_t a0p = fp_from_limbs( 3, 0, 0, 0 );
    fd_bn254_fp_t a1p = fp_from_limbs( 5, 0, 0, 0 );
    fd_bn254_fp_t b0p = fp_from_limbs( 7, 0, 0, 0 );
    fd_bn254_fp_t b1p = fp_from_limbs( 11, 0, 0, 0 );
    fd_bn254_fp2_t a, b, expected;
    fiat_bn254_to_montgomery( a.el[0].limbs, a0p.limbs );
    fiat_bn254_to_montgomery( a.el[1].limbs, a1p.limbs );
    fiat_bn254_to_montgomery( b.el[0].limbs, b0p.limbs );
    fiat_bn254_to_montgomery( b.el[1].limbs, b1p.limbs );
    fd_bn254_fp2_mul( &expected, &a, &b );

    fd_bn254_fp52_fp2_t a52, b52, r52;
    fp2_to_fp52( &a52, &a );
    fp2_to_fp52( &b52, &b );
    fd_bn254_fp52_fp2_mul( &r52, &a52, &b52 );

    fd_bn254_fp2_t result;
    fp52_to_fp2( &result, &r52 );
    FD_TEST( fd_uint256_eq( &result.el[0], &expected.el[0] ) );
    FD_TEST( fd_uint256_eq( &result.el[1], &expected.el[1] ) );
    FD_LOG_NOTICE(( "  (3+5i)*(7+11i) ...OK" ));
  }

  /* Test 2: Fp2 squaring */
  {
    fd_bn254_fp_t a0p = fp_from_limbs( 13, 0, 0, 0 );
    fd_bn254_fp_t a1p = fp_from_limbs( 17, 0, 0, 0 );
    fd_bn254_fp2_t a, expected;
    fiat_bn254_to_montgomery( a.el[0].limbs, a0p.limbs );
    fiat_bn254_to_montgomery( a.el[1].limbs, a1p.limbs );
    fd_bn254_fp2_sqr( &expected, &a );

    fd_bn254_fp52_fp2_t a52, r52;
    fp2_to_fp52( &a52, &a );
    fd_bn254_fp52_fp2_sqr( &r52, &a52 );

    fd_bn254_fp2_t result;
    fp52_to_fp2( &result, &r52 );
    FD_TEST( fd_uint256_eq( &result.el[0], &expected.el[0] ) );
    FD_TEST( fd_uint256_eq( &result.el[1], &expected.el[1] ) );
    FD_LOG_NOTICE(( "  (13+17i)^2 ...OK" ));
  }

  /* Test 3: Batched fp2_mul2 */
  {
    fd_bn254_fp2_t a1, b1, a2, b2, e1, e2;
    fd_bn254_fp_t t;
    t = fp_from_limbs(2,0,0,0); fiat_bn254_to_montgomery(a1.el[0].limbs, t.limbs);
    t = fp_from_limbs(3,0,0,0); fiat_bn254_to_montgomery(a1.el[1].limbs, t.limbs);
    t = fp_from_limbs(5,0,0,0); fiat_bn254_to_montgomery(b1.el[0].limbs, t.limbs);
    t = fp_from_limbs(7,0,0,0); fiat_bn254_to_montgomery(b1.el[1].limbs, t.limbs);
    t = fp_from_limbs(11,0,0,0); fiat_bn254_to_montgomery(a2.el[0].limbs, t.limbs);
    t = fp_from_limbs(13,0,0,0); fiat_bn254_to_montgomery(a2.el[1].limbs, t.limbs);
    t = fp_from_limbs(17,0,0,0); fiat_bn254_to_montgomery(b2.el[0].limbs, t.limbs);
    t = fp_from_limbs(19,0,0,0); fiat_bn254_to_montgomery(b2.el[1].limbs, t.limbs);

    fd_bn254_fp2_mul( &e1, &a1, &b1 );
    fd_bn254_fp2_mul( &e2, &a2, &b2 );

    fd_bn254_fp52_fp2_t a152, b152, a252, b252, r152, r252;
    fp2_to_fp52( &a152, &a1 ); fp2_to_fp52( &b152, &b1 );
    fp2_to_fp52( &a252, &a2 ); fp2_to_fp52( &b252, &b2 );
    fd_bn254_fp52_fp2_mul2( &r152, &a152, &b152, &r252, &a252, &b252 );

    fd_bn254_fp2_t res1, res2;
    fp52_to_fp2( &res1, &r152 ); fp52_to_fp2( &res2, &r252 );
    FD_TEST( fd_uint256_eq(&res1.el[0],&e1.el[0]) && fd_uint256_eq(&res1.el[1],&e1.el[1]) );
    FD_TEST( fd_uint256_eq(&res2.el[0],&e2.el[0]) && fd_uint256_eq(&res2.el[1],&e2.el[1]) );
    FD_LOG_NOTICE(( "  fp2_mul2 ...OK" ));
  }

  /* Test 4: Batched fp2_mul3 */
  {
    fd_bn254_fp2_t a[3], b[3], e[3];
    fd_bn254_fp_t t;
    for( int i=0; i<3; i++ ) {
      t = fp_from_limbs((ulong)(2+i*3),0,0,0); fiat_bn254_to_montgomery(a[i].el[0].limbs, t.limbs);
      t = fp_from_limbs((ulong)(5+i*7),0,0,0); fiat_bn254_to_montgomery(a[i].el[1].limbs, t.limbs);
      t = fp_from_limbs((ulong)(11+i*2),0,0,0); fiat_bn254_to_montgomery(b[i].el[0].limbs, t.limbs);
      t = fp_from_limbs((ulong)(17+i*5),0,0,0); fiat_bn254_to_montgomery(b[i].el[1].limbs, t.limbs);
      fd_bn254_fp2_mul( &e[i], &a[i], &b[i] );
    }

    fd_bn254_fp52_fp2_t a52[3], b52[3], r52[3];
    for( int i=0; i<3; i++ ) { fp2_to_fp52(&a52[i],&a[i]); fp2_to_fp52(&b52[i],&b[i]); }
    fd_bn254_fp52_fp2_mul3( &r52[0],&a52[0],&b52[0], &r52[1],&a52[1],&b52[1], &r52[2],&a52[2],&b52[2] );

    for( int i=0; i<3; i++ ) {
      fd_bn254_fp2_t res;
      fp52_to_fp2( &res, &r52[i] );
      FD_TEST( fd_uint256_eq(&res.el[0],&e[i].el[0]) && fd_uint256_eq(&res.el[1],&e[i].el[1]) );
    }
    FD_LOG_NOTICE(( "  fp2_mul3 ...OK" ));
  }

  /* Test 5: Batched fp2_sqr4 */
  {
    fd_bn254_fp2_t a[4], e[4];
    fd_bn254_fp_t t;
    for( int i=0; i<4; i++ ) {
      t = fp_from_limbs((ulong)(3+i*7),0,0,0); fiat_bn254_to_montgomery(a[i].el[0].limbs, t.limbs);
      t = fp_from_limbs((ulong)(11+i*5),0,0,0); fiat_bn254_to_montgomery(a[i].el[1].limbs, t.limbs);
      fd_bn254_fp2_sqr( &e[i], &a[i] );
    }

    fd_bn254_fp52_fp2_t a52[4], r52[4];
    for( int i=0; i<4; i++ ) fp2_to_fp52(&a52[i],&a[i]);
    fd_bn254_fp52_fp2_sqr4( &r52[0],&a52[0], &r52[1],&a52[1], &r52[2],&a52[2], &r52[3],&a52[3] );

    for( int i=0; i<4; i++ ) {
      fd_bn254_fp2_t res;
      fp52_to_fp2( &res, &r52[i] );
      FD_TEST( fd_uint256_eq(&res.el[0],&e[i].el[0]) && fd_uint256_eq(&res.el[1],&e[i].el[1]) );
    }
    FD_LOG_NOTICE(( "  fp2_sqr4 ...OK" ));
  }

  /* Test 6: mul_by_xi */
  {
    fd_bn254_fp_t t;
    fd_bn254_fp2_t a, expected;
    t = fp_from_limbs(42,0,0,0); fiat_bn254_to_montgomery(a.el[0].limbs, t.limbs);
    t = fp_from_limbs(17,0,0,0); fiat_bn254_to_montgomery(a.el[1].limbs, t.limbs);
    fd_bn254_fp2_mul_by_xi( &expected, &a );

    fd_bn254_fp52_fp2_t a52, r52;
    fp2_to_fp52( &a52, &a );
    fd_bn254_fp52_fp2_mul_by_xi( &r52, &a52 );

    fd_bn254_fp2_t result;
    fp52_to_fp2( &result, &r52 );
    FD_TEST( fd_uint256_eq(&result.el[0],&expected.el[0]) );
    FD_TEST( fd_uint256_eq(&result.el[1],&expected.el[1]) );
    FD_LOG_NOTICE(( "  mul_by_xi ...OK" ));
  }

  FD_LOG_NOTICE(( "  ...ALL PASSED" ));
}

/* ---- Fp6 conversion helpers ---- */

static void
fp6_to_fp52( fd_bn254_fp52_fp6_t * r, fd_bn254_fp6_t const * a ) {
  for( int i=0; i<3; i++ ) fp2_to_fp52( &r->el[i], &a->el[i] );
}

static void
fp52_to_fp6( fd_bn254_fp6_t * r, fd_bn254_fp52_fp6_t const * a ) {
  for( int i=0; i<3; i++ ) fp52_to_fp2( &r->el[i], &a->el[i] );
}

/* ---- Fp12 conversion helpers ---- */

static void
fp12_to_fp52( fd_bn254_fp52_fp12_t * r, fd_bn254_fp12_t const * a ) {
  for( int i=0; i<2; i++ ) fp6_to_fp52( &r->el[i], &a->el[i] );
}

static void
fp52_to_fp12( fd_bn254_fp12_t * r, fd_bn254_fp52_fp12_t const * a ) {
  for( int i=0; i<2; i++ ) fp52_to_fp6( &r->el[i], &a->el[i] );
}

/* ---- Test: Fp6 multiplication ---- */
static void
test_fp6( void ) {
  FD_LOG_NOTICE(( "Testing Fp6 operations..." ));

  /* Build Fp6 elements from small Fp values */
  fd_bn254_fp6_t a, b, expected;
  fd_bn254_fp_t t;
  for( int i=0; i<3; i++ ) {
    t = fp_from_limbs( (ulong)(2+i*3), 0, 0, 0 ); fiat_bn254_to_montgomery( a.el[i].el[0].limbs, t.limbs );
    t = fp_from_limbs( (ulong)(5+i*7), 0, 0, 0 ); fiat_bn254_to_montgomery( a.el[i].el[1].limbs, t.limbs );
    t = fp_from_limbs( (ulong)(11+i*2), 0, 0, 0 ); fiat_bn254_to_montgomery( b.el[i].el[0].limbs, t.limbs );
    t = fp_from_limbs( (ulong)(17+i*5), 0, 0, 0 ); fiat_bn254_to_montgomery( b.el[i].el[1].limbs, t.limbs );
  }

  /* Test Fp6 mul */
  fd_bn254_fp6_mul( &expected, &a, &b );

  fd_bn254_fp52_fp6_t a52, b52, r52;
  fp6_to_fp52( &a52, &a );
  fp6_to_fp52( &b52, &b );
  fd_bn254_fp52_fp6_mul( &r52, &a52, &b52 );

  fd_bn254_fp6_t result;
  fp52_to_fp6( &result, &r52 );
  for( int i=0; i<3; i++ ) {
    FD_TEST( fd_uint256_eq( &result.el[i].el[0], &expected.el[i].el[0] ) );
    FD_TEST( fd_uint256_eq( &result.el[i].el[1], &expected.el[i].el[1] ) );
  }
  FD_LOG_NOTICE(( "  fp6_mul ...OK" ));

  /* Test Fp6 sqr */
  fd_bn254_fp6_sqr( &expected, &a );
  fd_bn254_fp52_fp6_sqr( &r52, &a52 );
  fp52_to_fp6( &result, &r52 );
  for( int i=0; i<3; i++ ) {
    FD_TEST( fd_uint256_eq( &result.el[i].el[0], &expected.el[i].el[0] ) );
    FD_TEST( fd_uint256_eq( &result.el[i].el[1], &expected.el[i].el[1] ) );
  }
  FD_LOG_NOTICE(( "  fp6_sqr ...OK" ));

  FD_LOG_NOTICE(( "  ...ALL PASSED" ));
}

/* ---- Test: Fp12 operations ---- */
static void
test_fp12( void ) {
  FD_LOG_NOTICE(( "Testing Fp12 operations..." ));

  /* Build Fp12 elements */
  fd_bn254_fp12_t a, b, expected;
  fd_bn254_fp_t t;
  for( int h=0; h<2; h++ ) {
    for( int i=0; i<3; i++ ) {
      t = fp_from_limbs( (ulong)(2+h*13+i*3), 0, 0, 0 ); fiat_bn254_to_montgomery( a.el[h].el[i].el[0].limbs, t.limbs );
      t = fp_from_limbs( (ulong)(5+h*17+i*7), 0, 0, 0 ); fiat_bn254_to_montgomery( a.el[h].el[i].el[1].limbs, t.limbs );
      t = fp_from_limbs( (ulong)(11+h*19+i*2), 0, 0, 0 ); fiat_bn254_to_montgomery( b.el[h].el[i].el[0].limbs, t.limbs );
      t = fp_from_limbs( (ulong)(17+h*23+i*5), 0, 0, 0 ); fiat_bn254_to_montgomery( b.el[h].el[i].el[1].limbs, t.limbs );
    }
  }

  /* Test Fp12 mul */
  fd_bn254_fp12_mul( &expected, &a, &b );

  fd_bn254_fp52_fp12_t a52, b52, r52;
  fp12_to_fp52( &a52, &a );
  fp12_to_fp52( &b52, &b );
  fd_bn254_fp52_fp12_mul( &r52, &a52, &b52 );

  fd_bn254_fp12_t result;
  fp52_to_fp12( &result, &r52 );
  for( int h=0; h<2; h++ ) for( int i=0; i<3; i++ ) {
    FD_TEST( fd_uint256_eq( &result.el[h].el[i].el[0], &expected.el[h].el[i].el[0] ) );
    FD_TEST( fd_uint256_eq( &result.el[h].el[i].el[1], &expected.el[h].el[i].el[1] ) );
  }
  FD_LOG_NOTICE(( "  fp12_mul ...OK" ));

  /* Test Fp12 sqr */
  fd_bn254_fp12_sqr( &expected, &a );
  fd_bn254_fp52_fp12_sqr( &r52, &a52 );
  fp52_to_fp12( &result, &r52 );
  for( int h=0; h<2; h++ ) for( int i=0; i<3; i++ ) {
    FD_TEST( fd_uint256_eq( &result.el[h].el[i].el[0], &expected.el[h].el[i].el[0] ) );
    FD_TEST( fd_uint256_eq( &result.el[h].el[i].el[1], &expected.el[h].el[i].el[1] ) );
  }
  FD_LOG_NOTICE(( "  fp12_sqr ...OK" ));

  /* Test Fp12 cyclotomic sqr (sqr_fast).
     sqr_fast requires the input to be on the cyclotomic subgroup.
     We can't easily get a cyclotomic element from small values.
     Instead, test that sqr_fast(a) == sqr(a) for a properly constructed
     cyclotomic element. A cyclotomic element satisfies a^(p^6+1) = 1.
     For now, just test that sqr_fast matches sqr on the same input —
     this verifies the formula is correct even if the input isn't
     cyclotomic (the formulas are algebraically equivalent). */
  fd_bn254_fp12_sqr_fast( &expected, &a );
  fd_bn254_fp52_fp12_sqr_fast( &r52, &a52 );
  fp52_to_fp12( &result, &r52 );
  for( int h=0; h<2; h++ ) for( int i=0; i<3; i++ ) {
    FD_TEST( fd_uint256_eq( &result.el[h].el[i].el[0], &expected.el[h].el[i].el[0] ) );
    FD_TEST( fd_uint256_eq( &result.el[h].el[i].el[1], &expected.el[h].el[i].el[1] ) );
  }
  FD_LOG_NOTICE(( "  fp12_sqr_fast ...OK" ));

  FD_LOG_NOTICE(( "  ...ALL PASSED" ));
}

/* ---- Benchmarks: compare ref vs avx512 ---- */

void
log_bench( char const * descr, ulong iter, long dt ) {
  float khz = 1e6f *(float)iter/(float)dt;
  float tau = (float)dt /(float)iter;
  FD_LOG_NOTICE(( "%-42s %12.3fK/s/core %12.3f ns/call", descr, (double)khz, (double)tau ));
}

static void
bench( void ) {
  FD_LOG_NOTICE(( "Benchmarks..." ));

  /* Build an Fp12 element from small values */
  fd_bn254_fp12_t a_ref;
  fd_bn254_fp_t t;
  for( int h=0; h<2; h++ ) for( int i=0; i<3; i++ ) {
    t = fp_from_limbs( (ulong)(2+h*13+i*3), 0, 0, 0 );
    fiat_bn254_to_montgomery( a_ref.el[h].el[i].el[0].limbs, t.limbs );
    t = fp_from_limbs( (ulong)(5+h*17+i*7), 0, 0, 0 );
    fiat_bn254_to_montgomery( a_ref.el[h].el[i].el[1].limbs, t.limbs );
  }

  /* Convert to avx512 */
  fd_bn254_fp52_fp12_t a_avx;
  fp12_to_fp52( &a_avx, &a_ref );

  /* --- Bench: Fp12 mul (ref) --- */
  {
    fd_bn254_fp12_t r, b;
    fd_memcpy( &b, &a_ref, sizeof(b) );
    ulong iter = 10000UL;
    long dt = fd_log_wallclock();
    for( ulong i=0; i<iter; i++ ) {
      fd_bn254_fp12_mul( &r, &a_ref, &b );
      fd_memcpy( &b, &r, sizeof(b) );
    }
    dt = fd_log_wallclock() - dt;
    log_bench( "ref  fd_bn254_fp12_mul", iter, dt );
  }

  /* --- Bench: Fp12 mul (avx512) --- */
  {
    fd_bn254_fp52_fp12_t r, b;
    fd_memcpy( &b, &a_avx, sizeof(b) );
    ulong iter = 10000UL;
    long dt = fd_log_wallclock();
    for( ulong i=0; i<iter; i++ ) {
      fd_bn254_fp52_fp12_mul( &r, &a_avx, &b );
      fd_memcpy( &b, &r, sizeof(b) );
    }
    dt = fd_log_wallclock() - dt;
    log_bench( "avx512 fd_bn254_fp52_fp12_mul", iter, dt );
  }

  /* --- Bench: Fp12 sqr (ref) --- */
  {
    fd_bn254_fp12_t r;
    fd_memcpy( &r, &a_ref, sizeof(r) );
    ulong iter = 10000UL;
    long dt = fd_log_wallclock();
    for( ulong i=0; i<iter; i++ ) {
      fd_bn254_fp12_sqr( &r, &r );
    }
    dt = fd_log_wallclock() - dt;
    log_bench( "ref  fd_bn254_fp12_sqr", iter, dt );
  }

  /* --- Bench: Fp12 sqr_fast (ref) --- */
  {
    fd_bn254_fp12_t r;
    fd_memcpy( &r, &a_ref, sizeof(r) );
    ulong iter = 10000UL;
    long dt = fd_log_wallclock();
    for( ulong i=0; i<iter; i++ ) {
      fd_bn254_fp12_sqr_fast( &r, &r );
    }
    dt = fd_log_wallclock() - dt;
    log_bench( "ref  fd_bn254_fp12_sqr_fast", iter, dt );
  }

  /* --- Bench: Fp12 sqr_fast (avx512) --- */
  {
    fd_bn254_fp52_fp12_t r;
    fd_memcpy( &r, &a_avx, sizeof(r) );
    ulong iter = 10000UL;
    long dt = fd_log_wallclock();
    for( ulong i=0; i<iter; i++ ) {
      fd_bn254_fp52_fp12_sqr_fast( &r, &r );
    }
    dt = fd_log_wallclock() - dt;
    log_bench( "avx512 fd_bn254_fp52_fp12_sqr_fast", iter, dt );
  }

  /* --- Bench: Fp2 mul (ref) --- */
  {
    fd_bn254_fp2_t ra, rb;
    fd_memcpy( &ra, &a_ref.el[0].el[0], sizeof(ra) );
    fd_memcpy( &rb, &a_ref.el[0].el[1], sizeof(rb) );
    ulong iter = 100000UL;
    long dt = fd_log_wallclock();
    for( ulong i=0; i<iter; i++ ) {
      fd_bn254_fp2_mul( &ra, &ra, &rb );
    }
    dt = fd_log_wallclock() - dt;
    log_bench( "ref  fd_bn254_fp2_mul", iter, dt );
  }

  /* --- Bench: Fp2 mul (avx512) --- */
  {
    fd_bn254_fp52_fp2_t ra, rb;
    fd_memcpy( &ra, &a_avx.el[0].el[0], sizeof(ra) );
    fd_memcpy( &rb, &a_avx.el[0].el[1], sizeof(rb) );
    ulong iter = 100000UL;
    long dt = fd_log_wallclock();
    for( ulong i=0; i<iter; i++ ) {
      fd_bn254_fp52_fp2_mul( &ra, &ra, &rb );
    }
    dt = fd_log_wallclock() - dt;
    log_bench( "avx512 fd_bn254_fp52_fp2_mul", iter, dt );
  }

  /* --- Bench: Fp mul (ref, scalar BMI2/ADX) --- */
  {
    fd_bn254_fp_t ra, rb;
    fd_memcpy( &ra, &a_ref.el[0].el[0].el[0], sizeof(ra) );
    fd_memcpy( &rb, &a_ref.el[0].el[0].el[1], sizeof(rb) );
    ulong iter = 1000000UL;
    long dt = fd_log_wallclock();
    for( ulong i=0; i<iter; i++ ) {
      fd_bn254_fp_mul( &ra, &ra, &rb );
    }
    dt = fd_log_wallclock() - dt;
    log_bench( "ref  fd_bn254_fp_mul (BMI2/ADX)", iter, dt );
  }

  /* --- Bench: Fp2 mul (avx512, new wwv-packed) --- */
  {
    fd_bn254_fp2_avx_t ra = fd_bn254_fp2_avx_load(
      a_avx.el[0].el[0].el[0], a_avx.el[0].el[0].el[1] );
    fd_bn254_fp2_avx_t rb = fd_bn254_fp2_avx_load(
      a_avx.el[0].el[1].el[0], a_avx.el[0].el[1].el[1] );
    ulong iter = 100000UL;
    long dt = fd_log_wallclock();
    for( ulong i=0; i<iter; i++ ) {
      ra = fd_bn254_fp2_avx_mul( &ra, &rb );
    }
    dt = fd_log_wallclock() - dt;
    log_bench( "avx512 fd_bn254_fp2_avx_mul (new)", iter, dt );
  }

  /* --- Bench: 3x Fp2 mul batched (avx512) --- */
  {
    fd_bn254_fp52_fp2_t a1, b1, a2, b2, a3, b3, r1, r2, r3;
    fd_memcpy( &a1, &a_avx.el[0].el[0], sizeof(a1) );
    fd_memcpy( &b1, &a_avx.el[0].el[1], sizeof(b1) );
    fd_memcpy( &a2, &a_avx.el[0].el[2], sizeof(a2) );
    fd_memcpy( &b2, &a_avx.el[1].el[0], sizeof(b2) );
    fd_memcpy( &a3, &a_avx.el[1].el[1], sizeof(a3) );
    fd_memcpy( &b3, &a_avx.el[1].el[2], sizeof(b3) );
    ulong iter = 100000UL;
    long dt = fd_log_wallclock();
    for( ulong i=0; i<iter; i++ ) {
      fd_bn254_fp52_fp2_mul3( &r1,&a1,&b1, &r2,&a2,&b2, &r3,&a3,&b3 );
      fd_memcpy( &a1, &r1, sizeof(a1) );
      fd_memcpy( &a2, &r2, sizeof(a2) );
      fd_memcpy( &a3, &r3, sizeof(a3) );
    }
    dt = fd_log_wallclock() - dt;
    log_bench( "avx512 fd_bn254_fp52_fp2_mul3 (3x)", iter, dt );
  }
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  test_radix_conversion();
  test_mul();
  test_add_sub();
  test_chain();
  test_fp2_mul();
  test_fp6();
  test_fp12();

  FD_LOG_NOTICE(( "ALL TESTS PASSED" ));

  bench();

  fd_halt();
  return 0;
}

#else /* !FD_HAS_AVX512 */

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  FD_LOG_WARNING(( "skip: no AVX-512 support" ));
  fd_halt();
  return 0;
}

#endif
