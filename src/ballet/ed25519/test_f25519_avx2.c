#include "fd_f25519.h"

#if !FD_HAS_AVX || FD_HAS_AVX512 || USE_FIAT_32
#error "This test requires the AVX2, 64-bit reference field representation"
#endif

#define RADIX (1UL<<51)
#define LOOSE (3UL*RADIX)

/* Exercise the public helpers, including the scalar two-lane fallback. */
static void
mul_batch( ulong               n,
           fd_f25519_t         r[4],
           fd_f25519_t const   a[4],
           fd_f25519_t const   b[4] ) {
  if( n==2UL )
    fd_f25519_mul2( r, a, b, r+1, a+1, b+1 );
  else if( n==3UL )
    fd_f25519_mul3( r, a, b, r+1, a+1, b+1, r+2, a+2, b+2 );
  else
    fd_f25519_mul4( r, a, b, r+1, a+1, b+1, r+2, a+2, b+2, r+3, a+3, b+3 );
}

static void
sqr_batch( ulong               n,
           fd_f25519_t         r[4],
           fd_f25519_t const   a[4] ) {
  if( n==2UL )
    fd_f25519_sqr2( r, a, r+1, a+1 );
  else if( n==3UL )
    fd_f25519_sqr3( r, a, r+1, a+1, r+2, a+2 );
  else
    fd_f25519_sqr4( r, a, r+1, a+1, r+2, a+2, r+3, a+3 );
}

static void
check_equal( ulong               n,
             fd_f25519_t const   actual[4],
             fd_f25519_t const   expected[4] ) {
  for( ulong lane=0UL; lane<n; lane++ ) {
    /* Reduction must also preserve Fiat's tight output bounds. */
    for( ulong limb=0UL; limb<5UL; limb++ ) FD_TEST( actual[lane].el[limb]<=RADIX );
    uchar actual_bytes[32], expected_bytes[32];
    fiat_25519_to_bytes( actual_bytes, actual[lane].el );
    fiat_25519_to_bytes( expected_bytes, expected[lane].el );
    FD_TEST( fd_memeq( actual_bytes, expected_bytes, 32UL ) );
  }
}

static void
check_unchanged_tail( ulong               n,
                      fd_f25519_t const   actual[4],
                      fd_f25519_t const   original[4] ) {
  FD_TEST( fd_memeq( actual+n, original+n, (4UL-n)*sizeof(fd_f25519_t) ) );
}

static void
check_case( fd_f25519_t const a[4],
            fd_f25519_t const b[4] ) {
  fd_f25519_t saved_a[4], saved_b[4], product[4], square[4], r[4], sentinel[4];
  fd_memcpy( saved_a, a, sizeof(saved_a) );
  fd_memcpy( saved_b, b, sizeof(saved_b) );
  fd_memset( sentinel, 0xa5, sizeof(sentinel) );
  for( ulong lane=0UL; lane<4UL; lane++ ) {
    fiat_25519_carry_mul( product[lane].el, a[lane].el, b[lane].el );
    fiat_25519_carry_square( square[lane].el, a[lane].el );
  }

  for( ulong n=2UL; n<=4UL; n++ ) {
    fd_memcpy( r, sentinel, sizeof(r) );
    mul_batch( n, r, a, b );
    check_equal( n, r, product );
    check_unchanged_tail( n, r, sentinel );

    /* In-place output is supported within each lane.  Cross-lane output
       aliases are deliberately excluded: scalar helpers execute in order. */
    fd_memcpy( r, a, sizeof(r) );
    mul_batch( n, r, r, b );
    check_equal( n, r, product );
    check_unchanged_tail( n, r, a );

    fd_memcpy( r, b, sizeof(r) );
    mul_batch( n, r, a, r );
    check_equal( n, r, product );
    check_unchanged_tail( n, r, b );

    fd_memcpy( r, sentinel, sizeof(r) );
    sqr_batch( n, r, a );
    check_equal( n, r, square );
    check_unchanged_tail( n, r, sentinel );

    fd_memcpy( r, a, sizeof(r) );
    sqr_batch( n, r, r );
    check_equal( n, r, square );
    check_unchanged_tail( n, r, a );

    fd_memcpy( r, a, sizeof(r) );
    mul_batch( n, r, r, r );
    check_equal( n, r, square );
    check_unchanged_tail( n, r, a );

    FD_TEST( fd_memeq( a, saved_a, sizeof(saved_a) ) );
    FD_TEST( fd_memeq( b, saved_b, sizeof(saved_b) ) );
  }
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  fd_rng_t rng[1];
  fd_rng_new( rng, 0U, 0UL );
  fd_f25519_t a[4], b[4];
  ulong cases = 0UL;
  ulong const edges[] = {
    0UL, 1UL, 18UL, 19UL, RADIX-20UL, RADIX-19UL, RADIX-1UL,
    RADIX, RADIX+1UL, 2UL*RADIX-1UL, 2UL*RADIX, 2UL*RADIX+1UL,
    LOOSE-1UL, LOOSE
  };
  ulong const edge_cnt = sizeof(edges)/sizeof(edges[0]);

  /* Uniform extremes provoke long carry chains; mixed lanes expose
     packing, lane selection and scattering errors. */
  for( ulong i=0UL; i<edge_cnt; i++ ) {
    for( ulong j=0UL; j<edge_cnt; j++ ) {
      for( ulong mixed=0UL; mixed<2UL; mixed++ ) {
        for( ulong lane=0UL; lane<4UL; lane++ ) {
          for( ulong limb=0UL; limb<5UL; limb++ ) {
            a[lane].el[limb] = edges[(i+mixed*(lane+limb))%edge_cnt];
            b[lane].el[limb] = edges[(j+mixed*(2UL*lane+limb))%edge_cnt];
          }
        }
        check_case( a, b );
        cases++;
      }
    }
  }

  /* Exercise every input bit in each limb, including the split-limb
     boundaries used by AVX2 multiplication. */
  for( ulong limb=0UL; limb<5UL; limb++ ) {
    for( ulong bit=0UL; bit<=52UL; bit++ ) {
      fd_memset( a, 0, sizeof(a) );
      for( ulong lane=0UL; lane<4UL; lane++ ) {
        a[lane].el[(limb+lane)%5UL] = 1UL<<bit;
        for( ulong j=0UL; j<5UL; j++ ) b[lane].el[j] = LOOSE;
      }
      check_case( a, b );
      cases++;
    }
  }

  for( ulong iter=0UL; iter<20000UL; iter++ ) {
    for( ulong lane=0UL; lane<4UL; lane++ ) {
      for( ulong limb=0UL; limb<5UL; limb++ ) {
        a[lane].el[limb] = fd_rng_ulong_roll( rng, LOOSE+1UL );
        b[lane].el[limb] = fd_rng_ulong_roll( rng, LOOSE+1UL );
      }
      if( iter & 1UL ) {
        /* Match the unreduced sum/difference inputs used by the curve
           addition and doubling formulas. */
        fd_f25519_t x, y;
        fiat_25519_carry( x.el, a[lane].el );
        fiat_25519_carry( y.el, b[lane].el );
        fiat_25519_add( a[lane].el, x.el, y.el );
        fiat_25519_sub( b[lane].el, x.el, y.el );
      }
    }
    check_case( a, b );
    cases++;
  }

  fd_rng_delete( rng );
  FD_LOG_NOTICE(( "pass: %lu field input sets; mul/sqr counts 2, 3, 4 and in-place aliases", cases ));
  fd_halt();
  return 0;
}
