#include "../fd_util.h"

#if FD_HAS_INT128

#include "fd_fxp.h"
#include <math.h>

/* Create random bit patterns with lots of leading and/or trailing zeros
   or ones to really stress limits of implementations. */

static inline ulong            /* Random fxp */
make_rand_fxp( ulong x,        /* Random 64-bit */
               uint *_ctl ) { /* Least significant 8 bits random, uses them up */
  uint ctl = *_ctl;
  int s = (int)(ctl & 63U); ctl >>= 6; /* Shift, in [0,63] */
  int d = (int)(ctl &  1U); ctl >>= 1; /* Direction, in [0,1] */
  int i = (int)(ctl &  1U); ctl >>= 1; /* Invert, in [0,1] */
  *_ctl = ctl;
  x = d ? (x<<s) : (x>>s);
  return i ? (~x) : x;
}

static inline ulong split_hi( uint128 x ) { return (ulong)(x>>64); }
static inline ulong split_lo( uint128 x ) { return (ulong) x;      }

static inline ulong
fd_fxp_add_ref( ulong   x,
                ulong   y,
                ulong * _c ) {
  uint128 z = ((uint128)x) + ((uint128)y);
  *_c = split_hi( z );
  return split_lo( z );
}

static inline ulong
fd_fxp_sub_ref( ulong   x,
                ulong   y,
                ulong * _b ) {
  ulong  b = (ulong)(x<y);
  uint128 z = (((uint128)b)<<64) + ((uint128)x) - ((uint128)y);
  *_b = b;
  return split_lo( z );
}

static inline ulong
fd_fxp_mul_rtz_ref( ulong   x,
                    ulong   y,
                    ulong * _c ) {
  uint128 z = ((uint128)x)*((uint128)y);
  z >>= 30;
  *_c = split_hi( z );
  return split_lo( z );
}

static inline ulong
fd_fxp_mul_raz_ref( ulong   x,
                    ulong   y,
                    ulong * _c ) {
  uint128 z = (((uint128)x)*((uint128)y) + ((uint128)((1UL<<30)-1UL))) >> 30;
  *_c = split_hi( z );
  return split_lo( z );
}

static inline ulong
fd_fxp_mul_rnz_ref( ulong   x,
                    ulong   y,
                    ulong * _c ) {
  uint128 z = (((uint128)x)*((uint128)y) + ((uint128)((1UL<<29)-1UL))) >> 30;
  *_c = split_hi( z );
  return split_lo( z );
}

static inline ulong
fd_fxp_mul_rna_ref( ulong   x,
                    ulong   y,
                    ulong * _c ) {
  uint128 z = (((uint128)x)*((uint128)y) + ((uint128)(1UL<<29))) >> 30;
  *_c = split_hi( z );
  return split_lo( z );
}

static inline ulong
fd_fxp_mul_rne_ref( ulong   x,
                    ulong   y,
                    ulong * _c ) {
  uint128 z = ((uint128)x)*((uint128)y);
  ulong f = split_lo( z ) & ((1UL<<30)-1UL);
  z >>= 30;
  if( (f>(1UL<<29)) || ((f==(1UL<<29)) && (z & 1UL)) ) z++;
  *_c = split_hi( z );
  return split_lo( z );
}

static inline ulong
fd_fxp_mul_rno_ref( ulong   x,
                    ulong   y,
                    ulong * _c ) {
  uint128 z = ((uint128)x)*((uint128)y);
  ulong f = split_lo( z ) & ((1UL<<30)-1UL);
  z >>= 30;
  if( (f>(1UL<<29)) || ((f==(1UL<<29)) && !(z & 1UL)) ) z++;
  *_c = split_hi( z );
  return split_lo( z );
}

static inline ulong
fd_fxp_div_rtz_ref( ulong   x,
                    ulong   _y,
                    ulong * _c ) {
  if( !_y ) { *_c = ULONG_MAX; return 0UL; }
  uint128 ex = ((uint128)x) << 30;
  uint128 y  = (uint128)_y;
  uint128 z  = ex / y;
  *_c = split_hi( z );
  return split_lo( z );
}

static inline ulong
fd_fxp_div_raz_ref( ulong   x,
                    ulong   _y,
                    ulong * _c ) {
  if( !_y ) { *_c = ULONG_MAX; return 0UL; }
  uint128 ex = ((uint128)x) << 30;
  uint128 y  = (uint128)_y;
  uint128 z  = (ex + y - (uint128)1) / y;
  *_c = split_hi( z );
  return split_lo( z );
}

static inline ulong
fd_fxp_div_rnz_ref( ulong   x,
                    ulong   _y,
                    ulong * _c ) {
  if( !_y ) { *_c = ULONG_MAX; return 0UL; }
  uint128 ex = ((uint128)x) << 30;
  uint128 y  = (uint128)_y;
  uint128 z  = (ex + ((y-(uint128)1)>>1)) / y;
  *_c = split_hi( z );
  return split_lo( z );
}

static inline ulong
fd_fxp_div_rna_ref( ulong   x,
                    ulong   _y,
                    ulong * _c ) {
  if( !_y ) { *_c = ULONG_MAX; return 0UL; }
  uint128 ex = ((uint128)x) << 30;
  uint128 y  = (uint128)_y;
  uint128 z  = (ex + (y>>1)) / y;
  *_c = split_hi( z );
  return split_lo( z );
}

static inline ulong
fd_fxp_div_rne_ref( ulong   x,
                    ulong   _y,
                    ulong * _c ) {
  if( !_y ) { *_c = ULONG_MAX; return 0UL; }
  uint128 ex = ((uint128)x) << 30;
  uint128 y  = (uint128)_y;
  uint128 z  = ex / y;
  uint128 r2 = (ex - z*y) << 1;
  if( r2>y || (r2==y && (z & (uint128)1)) ) z++;
  *_c = split_hi( z );
  return split_lo( z );
}

static inline ulong
fd_fxp_div_rno_ref( ulong   x,
                    ulong   _y,
                    ulong * _c ) {
  if( !_y ) { *_c = ULONG_MAX; return 0UL; }
  uint128 ex = ((uint128)x) << 30;
  uint128 y  = (uint128)_y;
  uint128 z  = ex / y;
  uint128 r2 = (ex - z*y) << 1;
  if( r2>y || (r2==y && !(z & (uint128)1)) ) z++;
  *_c = split_hi( z );
  return split_lo( z );
}

FD_FN_CONST static inline int
test_fd_fxp_sqrt_rtz( ulong x,
                      ulong y ) {
  if( !x ) return !!y;
  if( !(((1UL<<15)<=y) && (y<=(1UL<<(32+15)))) ) return 1;
  uint128 xw  = ((uint128)x) << 30;
  uint128 ysq = ((uint128)y)*((uint128)y);
  return ysq>xw || (xw-ysq)>(((uint128)y)<<1);
}

FD_FN_CONST static inline int
test_fd_fxp_sqrt_raz( ulong x,
                      ulong y ) {
  if( !x ) return !!y;
  if( !(((1UL<<15)<=y) && (y<=(1UL<<(32+15)))) ) return 1;
  uint128 xw  = ((uint128)x) << 30;
  uint128 ysq = ((uint128)y)*((uint128)y);
  return xw>ysq || (ysq-xw)>(((uint128)(y<<1))-(uint128)2);
}

FD_FN_CONST static inline int
test_fd_fxp_sqrt_rnz( ulong x,
                      ulong y ) {
  if( !x ) return !!y;
  if( !(((1UL<<15)<=y) && (y<=(1UL<<(32+15)))) ) return 1;
  uint128 xw  = ((uint128)x) << 30;
  uint128 ysq = ((uint128)y)*((uint128)y) - ((uint128)y) + ((uint128)1);
  return ysq>xw || (xw-ysq)>=(((uint128)y)<<1);
}

#if FD_HAS_DOUBLE==0

/* These aren't full precision but does avoid any expectation of full
   double precision on the target.  These have the issue that they are
   less precise than fxp though. */

static inline ulong
fd_fxp_log2_ref( ulong x,
                 int * _e ) {
  if( !x ) { *_e = INT_MIN; return 0UL; }
  float ef = log2f( (float)x );
  int e = fd_ulong_find_msb( x );
  *_e = e - 30;
  return (ulong)roundf( (ef - (float)e)*(float)(1UL<<30) );
}

FD_FN_CONST static inline ulong
fd_fxp_exp2_ref( ulong x ) {
  if( x>=0x880000000UL ) return ULONG_MAX;
  return (ulong)roundf( ((float)(1UL<<30))*exp2f( ((float)x)*(1.f/(float)(1UL<<30)) ) );
}

FD_FN_CONST static inline ulong
fd_fxp_rexp2_ref( ulong x ) {
  return (ulong)roundf( ((float)(1UL<<30))*exp2f( ((float)x)*(-1.f/(float)(1UL<<30)) ) );
}

#else /* FD_HAS_DOUBLE==1 */

static inline ulong
fd_fxp_log2_ref( ulong x,
                 int * _e ) {
  if( !x ) { *_e = INT_MIN; return 0UL; }
  double ef = log2( (double)x );
  int e = fd_ulong_find_msb( x );
  *_e = e - 30;
  return (ulong)round( (ef - (double)e)*(double)(1UL<<30) );
}

FD_FN_CONST static inline ulong
fd_fxp_exp2_ref( ulong x ) {
  if( x>=0x880000000UL ) return ULONG_MAX;
  return (ulong)round( ((double)(1UL<<30))*exp2( ((double)x)*(1./(double)(1UL<<30)) ) );
}

FD_FN_CONST static inline ulong
fd_fxp_rexp2_ref( ulong x ) {
  return (ulong)round( ((double)(1UL<<30))*exp2( ((double)x)*(-1./(double)(1UL<<30)) ) );
}

#endif

int
main( int     argc,
      char ** argv ) {

  fd_boot( &argc, &argv );

  fd_rng_t _rng[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  ulong fd_fxp_log2_approx_ulp  = 0UL;
  ulong fd_fxp_exp2_approx_ulp  = 0UL;
  ulong fd_fxp_rexp2_approx_ulp = 0UL;

  int ctr = 0;
  for( int i=0; i<100000000; i++ ) {
    if( !ctr ) { FD_LOG_NOTICE(( "Completed %i iterations", i )); ctr = 10000000; }
    ctr--;

    uint  t =                fd_rng_uint ( rng );
    ulong x = make_rand_fxp( fd_rng_ulong( rng ), &t );
    ulong y = make_rand_fxp( fd_rng_ulong( rng ), &t );

#   define TEST(op)                                  \
    do {                                             \
      ulong c0,z0 = fd_fxp_##op##_ref ( x, y, &c0 ); \
      ulong c1,z1 = fd_fxp_##op       ( x, y, &c1 ); \
      ulong    z2 = fd_fxp_##op##_fast( x, y );      \
      if( c0!=c1 || z0!=z1 || (!c0 && z0!=z2) )      \
        FD_LOG_ERR(( "FAIL: %i fd_fxp_" #op " x %016lx y %016lx cz0 %016lx %016lx cz1 %016lx %016lx z2 %016lx", \
                     i, x, y, c0,z0, c1,z1, z2 ));   \
    } while(0)

    TEST(add);
    TEST(sub);

#   undef TEST
#   define TEST(op)                                  \
    do {                                             \
      ulong c0,z0 = fd_fxp_##op##_ref ( x, y, &c0 ); \
      ulong c1,z1 = fd_fxp_##op       ( x, y, &c1 ); \
      ulong    z2 = fd_fxp_##op##_fast( x, y );      \
      if( c0!=c1 || z0!=z1 || (!c0 && z0<0x3c0000000UL && z0!=z2) ) \
        FD_LOG_ERR(( "FAIL: %i fd_fxp_" #op " x %016lx y %016lx cz0 %016lx %016lx cz1 %016lx %016lx z2 %016lx", \
                     i, x, y, c0,z0, c1,z1, z2 ));   \
    } while(0)

    TEST(mul_rtz);
    TEST(mul_raz);
    TEST(mul_rnz);
    TEST(mul_rna);
    TEST(mul_rne);
    TEST(mul_rno);

#   undef TEST
#   define TEST(op)                                  \
    do {                                             \
      ulong c0,z0 = fd_fxp_##op##_ref ( x, y, &c0 ); \
      ulong c1,z1 = fd_fxp_##op       ( x, y, &c1 ); \
      ulong    z2 = y ? fd_fxp_##op##_fast( x, y ) : 0UL; \
      if( c0!=c1 || z0!=z1 || ((x<0x400000000UL) && (y<=ULONG_MAX-(x<<30)) && (z0!=z2)) ) \
        FD_LOG_ERR(( "FAIL: %i fd_fxp_" #op " x %016lx y %016lx cz0 %016lx %016lx cz1 %016lx %016lx z2 %016lx", \
                     i, x, y, c0,z0, c1,z1, z2 ));   \
    } while(0)

    TEST(div_rtz);
    TEST(div_raz);
    TEST(div_rnz);
    TEST(div_rna);
    TEST(div_rne);
    TEST(div_rno);

#   undef TEST
#   define TEST(op)                       \
    do {                                  \
      ulong z1 = fd_fxp_##op       ( x ); \
      ulong z2 = fd_fxp_##op##_fast( x ); \
      if( test_fd_fxp_##op( x, z1 ) || ((x<0x400000000UL) && (z1!=z2)) ) { \
        FD_LOG_ERR(( "FAIL: %i fd_fxp_" #op " x %016lx z1 %016lx z2 %016lx", i, x, z1, z2 )); \
      }                                   \
    } while(0)

    TEST(sqrt_rtz);
    TEST(sqrt_raz);
    TEST(sqrt_rnz);

#   undef TEST

    do {
      int e0; ulong f0 = fd_fxp_log2_ref   ( x, &e0 );
      int e1; ulong f1 = fd_fxp_log2_approx( x, &e1 );
      ulong ulp = f0>f1 ? f0-f1 : f1-f0;
      if( ulp > fd_fxp_log2_approx_ulp ) fd_fxp_log2_approx_ulp = ulp;
      /* FIXME: when double support is not available, fxp is more
         precise than the reference and the larger ULP limit reflects
         this (and potentially the build target also having a less
         accurate libm). */
      if( e0!=e1 || (ulp > (FD_HAS_DOUBLE ? 2UL : 5263UL)) )
        FD_LOG_ERR(( "FAIL: %i fd_fxp_log2_approx x %016lx z0 %3i %016lx z1 %3i %016lx ulp %016lx", i, x, e0,f0, e1,f1, ulp ));
    } while(0);

    do {
      ulong z0  = fd_fxp_exp2_ref   ( x );
      ulong z1  = fd_fxp_exp2_approx( x );
      ulong ulp = z0>z1 ? z0-z1 : z1-z0;
      /* Only consider first 30 bits (with RNA rounding) for large x */
      ulong ix = x>>30; if( 0UL<ix && ix<64UL ) ulp = (ulp + (1UL<<(ix-1UL))) >> ix;
      if( ulp > fd_fxp_exp2_approx_ulp ) fd_fxp_exp2_approx_ulp = ulp;
      if( ulp > (FD_HAS_DOUBLE ? 1UL : 2865UL) )
        FD_LOG_ERR(( "FAIL: %i fd_fxp_exp2_approx x %016lx z0 %016lx z1 %016lx ulp %016lx", i, x, z0, z1, ulp ));
    } while(0);

    do {
      ulong z0 = fd_fxp_rexp2_ref   ( x );
      ulong z1 = fd_fxp_rexp2_approx( x );
      ulong ulp = z0>z1 ? z0-z1 : z1-z0;
      if( ulp > fd_fxp_rexp2_approx_ulp ) fd_fxp_rexp2_approx_ulp = ulp;
      /* FIXME: when double support is not available, fxp is more
         precise than the reference and the larger ULP limit reflects
         this (and potentially the build target also having a less
         accurate libm). */
      if( ulp > (FD_HAS_DOUBLE ? 1UL : 59UL) )
        FD_LOG_ERR(( "FAIL: %i fd_fxp_rexp2_approx x %016lx z0 %016lx z1 %016lx ulp %016lx", i, x, z0, z1, ulp ));
    } while(0);

  }
  FD_LOG_NOTICE(( "ulp fd_fxp_log2_approx ~ %lu fd_fxp_exp2_approx ~ %lu fd_fxp_rexp2_approx ~ %lu",
                  fd_fxp_log2_approx_ulp, fd_fxp_exp2_approx_ulp, fd_fxp_rexp2_approx_ulp ));

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

#else

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  FD_LOG_WARNING(( "skip: unit test requires FD_HAS_INT128 capability" ));
  fd_halt();
  return 0;
}

#endif

