#include "../fd_util.h"

#if FD_HAS_AVX

#include "fd_avx.h"
#include <math.h>

/* From test_avx_common.c */

int wc_test( wc_t c, int    c0, int    c1, int    c2, int    c3, int   c4, int   c5, int   c6, int   c7 );
int wf_test( wf_t f, float  f0, float  f1, float  f2, float  f3, float f4, float f5, float f6, float f7 );
int wi_test( wi_t i, int    i0, int    i1, int    i2, int    i3, int   i4, int   i5, int   i6, int   i7 );
int wu_test( wu_t u, uint   u0, uint   u1, uint   u2, uint   u3, uint  u4, uint  u5, uint  u6, uint  u7 );
int wd_test( wd_t d, double d0, double d1, double d2, double d3 );
int wl_test( wl_t l, long   l0, long   l1, long   l2, long   l3 );
int wv_test( wv_t v, ulong  v0, ulong  v1, ulong  v2, ulong  v3 );

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

# define crand() (!(fd_rng_uint( rng ) & 1U))
# define frand() (0.5f*(float)(fd_rng_uint( rng ) % 15U)-3.5f) /* [-3.5,-3,...+3,+3.5] */
# define irand() ((int)(fd_rng_uint( rng ) % 7U)-3)            /* [-3,-2,-1,0,1,2,3] */
# define urand() ((fd_rng_uint( rng ) % 7U)-3U)                /* [2^32-3,2^32-2,2^32-1,0,1,2,3] */
# define drand() (0.5*(double)(fd_rng_uint( rng ) % 15U)-3.5)  /* [-3.5,-3,...+3,+3.5] */
# define lrand() ((long)(fd_rng_uint( rng ) % 7U)-3L)          /* [-3,-2,-1,0,1,2,3] */
# define vrand() ((ulong)(fd_rng_uint( rng ) % 7U)-3UL)        /* [2^64-3,2^64-2,2^64-1,0,1,2,3] */

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  /* WD tests */

  FD_TEST( wd_test( wd_zero(), 0., 0., 0., 0. ) );
  FD_TEST( wd_test( wd_one(),  1., 1., 1., 1. ) );

  for( int i=0; i<65536; i++ ) {
    double x0 = drand(); double x1 = drand(); double x2 = drand(); double x3 = drand(); wd_t x = wd( x0, x1, x2, x3 );
    double y0 = drand(); double y1 = drand(); double y2 = drand(); double y3 = drand(); wd_t y = wd( y0, y1, y2, y3 );
    double z0 = drand(); double z1 = drand(); double z2 = drand(); double z3 = drand(); wd_t z = wd( z0, z1, z2, z3 );
    int    c0 = crand(); int    c1 = crand(); int    c2 = crand(); int    c3 = crand(); wc_t c = wc_bcast_wide( c0, c1, c2, c3 );

    /* Constructors */

    FD_TEST( wd_test( x, x0, x1, x2, x3 ) );

    FD_TEST( wd_test( wd_bcast( x0 ), x0, x0, x0, x0 ) );

    FD_TEST( wd_test( wd_bcast_pair( x0,x1 ), x0, x1, x0, x1 ) );
    FD_TEST( wd_test( wd_bcast_wide( x0,x1 ), x0, x0, x1, x1 ) );

    FD_TEST( wd_test( wd_permute( x, 0, 0, 0, 0 ), x0, x0, x0, x0 ) );
    FD_TEST( wd_test( wd_permute( x, 1, 1, 1, 1 ), x1, x1, x1, x1 ) );
    FD_TEST( wd_test( wd_permute( x, 2, 2, 2, 2 ), x2, x2, x2, x2 ) );
    FD_TEST( wd_test( wd_permute( x, 3, 3, 3, 3 ), x3, x3, x3, x3 ) );
    FD_TEST( wd_test( wd_permute( x, 0, 1, 2, 3 ), x0, x1, x2, x3 ) );
    FD_TEST( wd_test( wd_permute( x, 0, 0, 2, 2 ), x0, x0, x2, x2 ) );
    FD_TEST( wd_test( wd_permute( x, 1, 1, 3, 3 ), x1, x1, x3, x3 ) );
    FD_TEST( wd_test( wd_permute( x, 1, 0, 3, 2 ), x1, x0, x3, x2 ) );
    FD_TEST( wd_test( wd_permute( x, 2, 3, 0, 1 ), x2, x3, x0, x1 ) );
    FD_TEST( wd_test( wd_permute( x, 0, 2, 1, 3 ), x0, x2, x1, x3 ) );
    FD_TEST( wd_test( wd_permute( x, 3, 2, 1, 0 ), x3, x2, x1, x0 ) );

    /* Arithmetic operations */

    FD_TEST( wd_test( wd_neg(    x ),              -x0,          -x1,          -x2,         -x3   ) );
    FD_TEST( wd_test( wd_sign(   x ),      x0<0.?-1.:1., x1<0.?-1.:1., x2<0.?-1.:1., x3<0.?-1.:1. ) );
    FD_TEST( wd_test( wd_abs(    x ),          fabs(x0),     fabs(x1),     fabs(x2),     fabs(x3) ) );
    FD_TEST( wd_test( wd_negabs( x ),         -fabs(x0),    -fabs(x1),    -fabs(x2),    -fabs(x3) ) );
    FD_TEST( wd_test( wd_ceil(   x ),          ceil(x0),     ceil(x1),     ceil(x2),     ceil(x3) ) );
    FD_TEST( wd_test( wd_floor(  x ),         floor(x0),    floor(x1),    floor(x2),    floor(x3) ) );
    FD_TEST( wd_test( wd_rint(   x ),          rint(x0),     rint(x1),     rint(x2),     rint(x3) ) );
    FD_TEST( wd_test( wd_trunc(  x ),         trunc(x0),    trunc(x1),    trunc(x2),    trunc(x3) ) );
    FD_TEST( wd_test( wd_sqrt( wd_mul(x,x) ),  fabs(x0),     fabs(x1),     fabs(x2),     fabs(x3) ) );

    wd_t expected;
    
    expected = wd( 1./sqrt(x0+4.), 1./sqrt(x1+4.), 1./sqrt(x2+4.), 1./sqrt(x3+4.) );
    FD_TEST( !wc_any( wd_gt( wd_abs( wd_div( wd_sub( wd_rsqrt_fast( wd_add( x, wd_bcast(4.) ) ), expected ), expected ) ),
                             wd_bcast( 1./1024. ) ) ) );

    expected = wd( 1./(x0+4.), 1./(x1+4.), 1./(x2+4.), 1./(x3+4.) );
    FD_TEST( !wc_any( wd_gt( wd_abs( wd_div( wd_sub( wd_rcp_fast( wd_add( x, wd_bcast(4.) ) ), expected ), expected ) ),
                             wd_bcast( 1./1024. ) ) ) );

    FD_TEST( wd_test( wd_add(      x, y ), x0+y0, x1+y1, x2+y2, x3+y3 ) );
    FD_TEST( wd_test( wd_sub(      x, y ), x0-y0, x1-y1, x2-y2, x3-y3 ) );
    FD_TEST( wd_test( wd_mul(      x, y ), x0*y0, x1*y1, x2*y2, x3*y3 ) );
    FD_TEST( wd_test( wd_div( x, wd_add( y, wd_bcast( 4. ) ) ), x0/(y0+4.), x1/(y1+4.), x2/(y2+4.), x3/(y3+4.) ) );
    FD_TEST( wd_test( wd_min(      x, y ), fmin(x0,y0), fmin(x1,y1), fmin(x2,y2), fmin(x3,y3) ) );
    FD_TEST( wd_test( wd_max(      x, y ), fmax(x0,y0), fmax(x1,y1), fmax(x2,y2), fmax(x3,y3) ) );
    FD_TEST( wd_test( wd_copysign( x, y ), copysign(x0,y0), copysign(x1,y1), copysign(x2,y2), copysign(x3,y3) ) );
    FD_TEST( wd_test( wd_flipsign( x, y ), y0<0.?-x0:x0, y1<0.?-x1:x1, y2<0.?-x2:x2, y3<0.?-x3:x3 ) );

    FD_TEST( wd_test( wd_fma(  x, y, z ),  x0*y0+z0,  x1*y1+z1,  x2*y2+z2,  x3*y3+z3 ) );
    FD_TEST( wd_test( wd_fms(  x, y, z ),  x0*y0-z0,  x1*y1-z1,  x2*y2-z2,  x3*y3-z3 ) );
    FD_TEST( wd_test( wd_fnma( x, y, z ), -x0*y0+z0, -x1*y1+z1, -x2*y2+z2, -x3*y3+z3 ) );

    /* Logical operations */

    FD_TEST( wc_test( wd_lnot(    x ),   x0==0.,    x0==0.,    x1==0.,    x1==0.,    x2==0.,    x2==0.,    x3==0.,    x3==0.  ) ); /* clang makes babies cry */
    FD_TEST( wc_test( wd_lnotnot( x ), !(x0==0.), !(x0==0.), !(x1==0.), !(x1==0.), !(x2==0.), !(x2==0.), !(x3==0.), !(x3==0.) ) ); /* floating point too */
    FD_TEST( wc_test( wd_signbit( x ), signbit(x0), signbit(x0), signbit(x1), signbit(x1),
                                       signbit(x2), signbit(x2), signbit(x3), signbit(x3) ) );

    FD_TEST( wc_test( wd_eq( x, y ), x0==y0, x0==y0, x1==y1, x1==y1, x2==y2, x2==y2, x3==y3, x3==y3 ) );
    FD_TEST( wc_test( wd_gt( x, y ), x0> y0, x0> y0, x1> y1, x1> y1, x2> y2, x2> y2, x3> y3, x3> y3 ) );
    FD_TEST( wc_test( wd_lt( x, y ), x0< y0, x0< y0, x1< y1, x1< y1, x2< y2, x2< y2, x3< y3, x3< y3 ) );
    FD_TEST( wc_test( wd_ne( x, y ), x0!=y0, x0!=y0, x1!=y1, x1!=y1, x2!=y2, x2!=y2, x3!=y3, x3!=y3 ) );
    FD_TEST( wc_test( wd_ge( x, y ), x0>=y0, x0>=y0, x1>=y1, x1>=y1, x2>=y2, x2>=y2, x3>=y3, x3>=y3 ) );
    FD_TEST( wc_test( wd_le( x, y ), x0<=y0, x0<=y0, x1<=y1, x1<=y1, x2<=y2, x2<=y2, x3<=y3, x3<=y3 ) );

    FD_TEST( wd_test( wd_czero(    c, x ), c0?0.:x0, c1?0.:x1, c2?0.:x2, c3?0.:x3 ) );
    FD_TEST( wd_test( wd_notczero( c, x ), c0?x0:0., c1?x1:0., c2?x2:0., c3?x3:0. ) );

    FD_TEST( wd_test( wd_if( c, x, y ), c0?x0:y0, c1?x1:y1, c2?x2:y2, c3?x3:y3 ) );

    /* Conversion operations */
    /* FIXME: TEST LARGE MAG CONVERSION */

    FD_TEST( wc_test( wd_to_wc( x ), !(x0==0.), !(x0==0.), !(x1==0.), !(x1==0.), !(x2==0.), !(x2==0.), !(x3==0.), !(x3==0.) ) ); /* see wd_lnotnot */

    FD_TEST( wf_test( wd_to_wf( x, wf( 0.f, 1.f, 2.f, 3.f, 4.f, 5.f, 6.f, 7.f ), 0 ),
                      (float)x0, (float)x1, (float)x2, (float)x3, 4.f, 5.f, 6.f, 7.f ) );
    FD_TEST( wf_test( wd_to_wf( x, wf( 0.f, 1.f, 2.f, 3.f, 4.f, 5.f, 6.f, 7.f ), 1 ),
                      0.f, 1.f, 2.f, 3.f, (float)x0, (float)x1, (float)x2, (float)x3 ) );

    FD_TEST( wi_test( wd_to_wi( x, wi( 0, 1, 2, 3, 4, 5, 6, 7 ), 0 ), (int)x0, (int)x1, (int)x2, (int)x3, 4, 5, 6, 7 ) );
    FD_TEST( wi_test( wd_to_wi( x, wi( 0, 1, 2, 3, 4, 5, 6, 7 ), 1 ), 0, 1, 2, 3, (int)x0, (int)x1, (int)x2, (int)x3 ) );

    FD_TEST( wi_test( wd_to_wi_fast( x, wi( 0, 1, 2, 3, 4, 5, 6, 7 ), 0 ), 
                      (int)rint(x0), (int)rint(x1), (int)rint(x2), (int)rint(x3), 4, 5, 6, 7 ) );
    FD_TEST( wi_test( wd_to_wi_fast( x, wi( 0, 1, 2, 3, 4, 5, 6, 7 ), 1 ),
                      0, 1, 2, 3, (int)rint(x0), (int)rint(x1), (int)rint(x2), (int)rint(x3) ) );

    /* The behaviour when converting from negative double to uint is highly
       dependent on the compiler version and the flags used ( e.g. gcc 8.5
       vs 9.3 with -march=native ).  Refer also to wd_to_wu_fast.  In order
       to make the test portable, negative values need to be excluded. */
    FD_TEST( wu_test( wd_to_wu( wd_abs( x ), wu(0U,1U,2U,3U,4U,5U,6U,7U), 0 ), (uint)fabs(x0),(uint)fabs(x1),(uint)fabs(x2),(uint)fabs(x3), 4U,5U,6U,7U ) );
    FD_TEST( wu_test( wd_to_wu( wd_abs( x ), wu(0U,1U,2U,3U,4U,5U,6U,7U), 1 ), 0U,1U,2U,3U, (uint)fabs(x0),(uint)fabs(x1),(uint)fabs(x2),(uint)fabs(x3) ) );

    FD_TEST( wu_test( wd_to_wu_fast( wd_abs( x ), wu(0U,1U,2U,3U,4U,5U,6U,7U), 0 ),
                      (uint)rint(fabs(x0)),(uint)rint(fabs(x1)),(uint)rint(fabs(x2)),(uint)rint(fabs(x3)), 4U,5U,6U,7U ) );
    FD_TEST( wu_test( wd_to_wu_fast( wd_abs( x ), wu(0U,1U,2U,3U,4U,5U,6U,7U), 1 ),
                      0U,1U,2U,3U, (uint)rint(fabs(x0)),(uint)rint(fabs(x1)),(uint)rint(fabs(x2)),(uint)rint(fabs(x3)) ) );

    FD_TEST( wl_test( wd_to_wl( x ), (long)x0, (long)x1, (long)x2, (long)x3 ) );

    FD_TEST( wv_test( wd_to_wv( x ), (ulong)x0, (ulong)x1, (ulong)x2, (ulong)x3 ) );

    /* Reduction operations */

    FD_TEST( !wc_any( wd_ne( wd_sum_all( x ), wd_bcast( x0 + x1 + x2 + x3 ) ) ) );
    FD_TEST( !wc_any( wd_ne( wd_min_all( x ), wd_bcast( fmin( fmin( x0, x1 ), fmin( x2, x3 ) ) ) ) ) );
    FD_TEST( !wc_any( wd_ne( wd_max_all( x ), wd_bcast( fmax( fmax( x0, x1 ), fmax( x2, x3 ) ) ) ) ) );

    /* Misc operations */

    /* FIXME: test with more general cases */
    wd_t m0; wd_t m1; wd_t m2; wd_t m3;
    wd_transpose_4x4( wd_bcast( x0 ), wd_bcast( x1 ), wd_bcast( x2 ), wd_bcast( x3 ), m0, m1, m2, m3 );
    wd_t mm = wd( x0, x1, x2, x3 );
    FD_TEST( wc_all( wc_and( wc_and( wd_eq( m0, mm ), wd_eq( m1, mm ) ), wc_and( wd_eq( m2, mm ), wd_eq( m3, mm ) ) ) ) );
  }

  /* WL tests */

  FD_TEST( wl_test( wl_zero(), 0L, 0L, 0L, 0L ) );
  FD_TEST( wl_test( wl_one(),  1L, 1L, 1L, 1L ) );

  for( int i=0; i<65536; i++ ) {
    long x0 = lrand(); long x1 = lrand(); long x2 = lrand(); long x3 = lrand(); wl_t x = wl( x0, x1, x2, x3 );
    long y0 = lrand(); long y1 = lrand(); long y2 = lrand(); long y3 = lrand(); wl_t y = wl( y0, y1, y2, y3 );
    int  c0 = crand(); int  c1 = crand(); int  c2 = crand(); int  c3 = crand(); wc_t c = wc_bcast_wide( c0, c1, c2, c3 );

    /* Constructors */

    FD_TEST( wl_test( x, x0, x1, x2, x3 ) );

    FD_TEST( wl_test( wl_bcast( x0 ), x0, x0, x0, x0 ) );

    FD_TEST( wl_test( wl_bcast_pair( x0, x1 ), x0, x1, x0, x1 ) );
    FD_TEST( wl_test( wl_bcast_wide( x0, x1 ), x0, x0, x1, x1 ) );

    FD_TEST( wl_test( wl_permute( x, 0, 0, 0, 0 ), x0, x0, x0, x0 ) );
    FD_TEST( wl_test( wl_permute( x, 1, 1, 1, 1 ), x1, x1, x1, x1 ) );
    FD_TEST( wl_test( wl_permute( x, 2, 2, 2, 2 ), x2, x2, x2, x2 ) );
    FD_TEST( wl_test( wl_permute( x, 3, 3, 3, 3 ), x3, x3, x3, x3 ) );
    FD_TEST( wl_test( wl_permute( x, 0, 1, 2, 3 ), x0, x1, x2, x3 ) );
    FD_TEST( wl_test( wl_permute( x, 0, 0, 2, 2 ), x0, x0, x2, x2 ) );
    FD_TEST( wl_test( wl_permute( x, 1, 1, 3, 3 ), x1, x1, x3, x3 ) );
    FD_TEST( wl_test( wl_permute( x, 1, 0, 3, 2 ), x1, x0, x3, x2 ) );
    FD_TEST( wl_test( wl_permute( x, 2, 3, 0, 1 ), x2, x3, x0, x1 ) );
    FD_TEST( wl_test( wl_permute( x, 0, 2, 1, 3 ), x0, x2, x1, x3 ) );
    FD_TEST( wl_test( wl_permute( x, 3, 2, 1, 0 ), x3, x2, x1, x0 ) );

    /* Bit operations */

    FD_TEST( wl_test( wl_not( x ), ~x0, ~x1, ~x2, ~x3 ) );

#   define SHL(x,n)  ((long)(((ulong)(x))<<(n)))
#   define SHRU(x,n) ((long)(((ulong)(x))>>(n)))
#   define ROL(x,n)  fd_long_rotate_left ((x),(n))
#   define ROR(x,n)  fd_long_rotate_right((x),(n))

#   define _(n)                                                                            \
    FD_TEST( wl_test( wl_shl(  x, n ), SHL( x0,n), SHL( x1,n), SHL( x2,n), SHL( x3,n) ) ); \
    FD_TEST( wl_test( wl_shr(  x, n ), x0>>n,      x1>>n,      x2>>n,      x3>>n      ) ); \
    FD_TEST( wl_test( wl_shru( x, n ), SHRU(x0,n), SHRU(x1,n), SHRU(x2,n), SHRU(x3,n) ) ); \
    FD_TEST( wl_test( wl_rol(  x, n ), ROL( x0,n), ROL( x1,n), ROL( x2,n), ROL( x3,n) ) ); \
    FD_TEST( wl_test( wl_ror(  x, n ), ROR( x0,n), ROR( x1,n), ROR( x2,n), ROR( x3,n) ) )
    _( 0); _( 1); _( 2); _( 3); _( 4); _( 5); _( 6); _( 7); _( 8); _( 9); _(10); _(11); _(12); _(13); _(14); _(15);
    _(16); _(17); _(18); _(19); _(20); _(21); _(22); _(23); _(24); _(25); _(26); _(27); _(28); _(29); _(30); _(31);
    _(32); _(33); _(34); _(35); _(36); _(37); _(38); _(39); _(40); _(41); _(42); _(43); _(44); _(45); _(46); _(47);
    _(48); _(49); _(50); _(51); _(52); _(53); _(54); _(55); _(56); _(57); _(58); _(59); _(60); _(61); _(62); _(63);
#   undef _

    for( int n=0; n<64; n++ ) {
      int volatile m[1]; m[0] = n;
      FD_TEST( wl_test( wl_shl_variable(  x, m[0] ), SHL( x0,n), SHL( x1,n), SHL( x2,n), SHL( x3,n) ) );
      FD_TEST( wl_test( wl_shr_variable(  x, m[0] ), x0>>n,      x1>>n,      x2>>n,      x3>>n      ) );
      FD_TEST( wl_test( wl_shru_variable( x, m[0] ), SHRU(x0,n), SHRU(x1,n), SHRU(x2,n), SHRU(x3,n) ) );
      FD_TEST( wl_test( wl_rol_variable(  x, m[0] ), ROL( x0,n), ROL( x1,n), ROL( x2,n), ROL( x3,n) ) );
      FD_TEST( wl_test( wl_ror_variable(  x, m[0] ), ROR( x0,n), ROR( x1,n), ROR( x2,n), ROR( x3,n) ) );
    }

#   undef ROR
#   undef ROL
#   undef SHRU
#   undef SHL

    FD_TEST( wl_test( wl_and(    x, y ),   x0 &y0,   x1 &y1,   x2 &y2,   x3 &y3 ) );
    FD_TEST( wl_test( wl_andnot( x, y ), (~x0)&y0, (~x1)&y1, (~x2)&y2, (~x3)&y3 ) );
    FD_TEST( wl_test( wl_or(     x, y ),   x0| y0,   x1| y1,   x2| y2,   x3| y3 ) );
    FD_TEST( wl_test( wl_xor(    x, y ),   x0^ y0,   x1^ y1,   x2^ y2,   x3^ y3 ) );

    /* Arithmetic operations */

    FD_TEST( wl_test( wl_neg( x ), -x0, -x1, -x2, -x3 ) );
    FD_TEST( wl_test( wl_abs( x ), (long)fd_long_abs(x0), (long)fd_long_abs(x1), (long)fd_long_abs(x2), (long)fd_long_abs(x3) ) );

    FD_TEST( wl_test( wl_min( x, y ), fd_long_min(x0,y0), fd_long_min(x1,y1), fd_long_min(x2,y2), fd_long_min(x3,y3) ) );
    FD_TEST( wl_test( wl_max( x, y ), fd_long_max(x0,y0), fd_long_max(x1,y1), fd_long_max(x2,y2), fd_long_max(x3,y3) ) );
    FD_TEST( wl_test( wl_add( x, y ), x0+y0, x1+y1, x2+y2, x3+y3 ) );
    FD_TEST( wl_test( wl_sub( x, y ), x0-y0, x1-y1, x2-y2, x3-y3 ) );
  //FD_TEST( wl_test( wl_mul( x, y ), x0*y0, x1*y1, x2*y2, x3*y3 ) );

#   define SE_LO(x) ((long)(int)(x))
    FD_TEST( wl_test( wl_mul_ll( x, y ), SE_LO(x0)*SE_LO(y0), SE_LO(x1)*SE_LO(y1), SE_LO(x2)*SE_LO(y2), SE_LO(x3)*SE_LO(y3) ) );
#   undef SE_LO

    /* Logical operations */

    FD_TEST( wc_test( wl_lnot(    x ),  !x0,  !x0,  !x1,  !x1,  !x2,  !x2,  !x3,  !x3 ) );
    FD_TEST( wc_test( wl_lnotnot( x ), !!x0, !!x0, !!x1, !!x1, !!x2, !!x2, !!x3, !!x3 ) );

    FD_TEST( wc_test( wl_eq( x, y ), x0==y0, x0==y0, x1==y1, x1==y1, x2==y2, x2==y2, x3==y3, x3==y3 ) );
    FD_TEST( wc_test( wl_gt( x, y ), x0> y0, x0> y0, x1> y1, x1> y1, x2> y2, x2> y2, x3> y3, x3> y3 ) );
    FD_TEST( wc_test( wl_lt( x, y ), x0< y0, x0< y0, x1< y1, x1< y1, x2< y2, x2< y2, x3< y3, x3< y3 ) );
    FD_TEST( wc_test( wl_ne( x, y ), x0!=y0, x0!=y0, x1!=y1, x1!=y1, x2!=y2, x2!=y2, x3!=y3, x3!=y3 ) );
    FD_TEST( wc_test( wl_ge( x, y ), x0>=y0, x0>=y0, x1>=y1, x1>=y1, x2>=y2, x2>=y2, x3>=y3, x3>=y3 ) );
    FD_TEST( wc_test( wl_le( x, y ), x0<=y0, x0<=y0, x1<=y1, x1<=y1, x2<=y2, x2<=y2, x3<=y3, x3<=y3 ) );

    FD_TEST( wl_test( wl_czero(    c, x ), c0?0L:x0, c1?0L:x1, c2?0L:x2, c3?0L:x3 ) );
    FD_TEST( wl_test( wl_notczero( c, x ), c0?x0:0L, c1?x1:0L, c2?x2:0L, c3?x3:0L ) );

    FD_TEST( wl_test( wl_if( c, x, y ), c0?x0:y0, c1?x1:y1, c2?x2:y2, c3?x3:y3 ) );

    /* Conversion operations */

    FD_TEST( wc_test( wl_to_wc( x ), !!x0, !!x0, !!x1, !!x1, !!x2, !!x2, !!x3, !!x3 ) );

    FD_TEST( wf_test( wl_to_wf( x, wf( 0.f, 1.f, 2.f, 3.f, 4.f, 5.f, 6.f, 7.f ), 0 ),
                      (float)x0, (float)x1, (float)x2, (float)x3, 4.f, 5.f, 6.f, 7.f ) );
    FD_TEST( wf_test( wl_to_wf( x, wf( 0.f, 1.f, 2.f, 3.f, 4.f, 5.f, 6.f, 7.f ), 1 ),
                      0.f, 1.f, 2.f, 3.f, (float)x0, (float)x1, (float)x2, (float)x3 ) );

    FD_TEST( wi_test( wl_to_wi( x, wi(0,1,2,3,4,5,6,7), 0 ), (int)x0,(int)x1,(int)x2,(int)x3, 4,5,6,7 ) );
    FD_TEST( wi_test( wl_to_wi( x, wi(0,1,2,3,4,5,6,7), 1 ), 0,1,2,3, (int)x0,(int)x1,(int)x2,(int)x3 ) );

    FD_TEST( wu_test( wl_to_wu( x, wu(0U,1U,2U,3U,4U,5U,6U,7U), 0 ), (uint)x0,(uint)x1,(uint)x2,(uint)x3, 4U,5U,6U,7U ) );
    FD_TEST( wu_test( wl_to_wu( x, wu(0U,1U,2U,3U,4U,5U,6U,7U), 1 ), 0U,1U,2U,3U, (uint)x0,(uint)x1,(uint)x2,(uint)x3 ) );

    FD_TEST( wd_test( wl_to_wd( x ), (double)x0, (double)x1, (double)x2, (double)x3 ) );

    FD_TEST( wv_test( wl_to_wv( x ), (ulong)x0, (ulong)x1, (ulong)x2, (ulong)x3 ) );

    /* Reduction operations */

    FD_TEST( !wc_any( wl_ne( wl_sum_all( x ), wl_bcast( x0 + x1 + x2 + x3 ) ) ) );
    FD_TEST( !wc_any( wl_ne( wl_min_all( x ), wl_bcast( fd_long_min( fd_long_min( x0, x1 ), fd_long_min( x2, x3 ) ) ) ) ) );
    FD_TEST( !wc_any( wl_ne( wl_max_all( x ), wl_bcast( fd_long_max( fd_long_max( x0, x1 ), fd_long_max( x2, x3 ) ) ) ) ) );

    /* Misc operations */

    /* FIXME: test with more general cases */
    wl_t m0; wl_t m1; wl_t m2; wl_t m3;
    wl_transpose_4x4( wl_bcast( x0 ), wl_bcast( x1 ), wl_bcast( x2 ), wl_bcast( x3 ), m0, m1, m2, m3 );
    wl_t mm = wl( x0, x1, x2, x3 );
    FD_TEST( wc_all( wc_and( wc_and( wl_eq( m0, mm ), wl_eq( m1, mm ) ), wc_and( wl_eq( m2, mm ), wl_eq( m3, mm ) ) ) ) );
  }

  /* WV tests */

  FD_TEST( wv_test( wv_zero(), 0UL, 0UL, 0UL, 0UL ) );
  FD_TEST( wv_test( wv_one(),  1UL, 1UL, 1UL, 1UL ) );

  for( int i=0; i<65536; i++ ) {
    ulong x0 = vrand(); ulong x1 = vrand(); ulong x2 = vrand(); ulong x3 = vrand(); wv_t x = wv( x0, x1, x2, x3 );
    ulong y0 = vrand(); ulong y1 = vrand(); ulong y2 = vrand(); ulong y3 = vrand(); wv_t y = wv( y0, y1, y2, y3 );
    int   c0 = crand(); int   c1 = crand(); int   c2 = crand(); int   c3 = crand(); wc_t c = wc_bcast_wide( c0, c1, c2, c3 );

    /* Constructors */

    FD_TEST( wv_test( x, x0, x1, x2, x3 ) );

    FD_TEST( wv_test( wv_bcast( x0 ), x0, x0, x0, x0 ) );

    FD_TEST( wv_test( wv_bcast_pair( x0, x1 ), x0, x1, x0, x1 ) );
    FD_TEST( wv_test( wv_bcast_wide( x0, x1 ), x0, x0, x1, x1 ) );

    FD_TEST( wv_test( wv_permute( x, 0, 0, 0, 0 ), x0, x0, x0, x0 ) );
    FD_TEST( wv_test( wv_permute( x, 1, 1, 1, 1 ), x1, x1, x1, x1 ) );
    FD_TEST( wv_test( wv_permute( x, 2, 2, 2, 2 ), x2, x2, x2, x2 ) );
    FD_TEST( wv_test( wv_permute( x, 3, 3, 3, 3 ), x3, x3, x3, x3 ) );
    FD_TEST( wv_test( wv_permute( x, 0, 1, 2, 3 ), x0, x1, x2, x3 ) );
    FD_TEST( wv_test( wv_permute( x, 0, 0, 2, 2 ), x0, x0, x2, x2 ) );
    FD_TEST( wv_test( wv_permute( x, 1, 1, 3, 3 ), x1, x1, x3, x3 ) );
    FD_TEST( wv_test( wv_permute( x, 1, 0, 3, 2 ), x1, x0, x3, x2 ) );
    FD_TEST( wv_test( wv_permute( x, 2, 3, 0, 1 ), x2, x3, x0, x1 ) );
    FD_TEST( wv_test( wv_permute( x, 0, 2, 1, 3 ), x0, x2, x1, x3 ) );
    FD_TEST( wv_test( wv_permute( x, 3, 2, 1, 0 ), x3, x2, x1, x0 ) );

    /* Bit operations */

    FD_TEST( wv_test( wv_not( x ), ~x0, ~x1, ~x2, ~x3 ) );

    FD_TEST( wv_test( wv_bswap( x ), fd_ulong_bswap( x0 ), fd_ulong_bswap( x1 ), fd_ulong_bswap( x2 ), fd_ulong_bswap( x3 ) ) );

#   define ROL(x,n) fd_ulong_rotate_left ((x),(n))
#   define ROR(x,n) fd_ulong_rotate_right((x),(n))

#   define _(n)                                                                       \
    FD_TEST( wv_test( wv_shl( x, n ), x0<<n,     x1<<n,     x2<<n,     x3<<n     ) ); \
    FD_TEST( wv_test( wv_shr( x, n ), x0>>n,     x1>>n,     x2>>n,     x3>>n     ) ); \
    FD_TEST( wv_test( wv_rol( x, n ), ROL(x0,n), ROL(x1,n), ROL(x2,n), ROL(x3,n) ) ); \
    FD_TEST( wv_test( wv_ror( x, n ), ROR(x0,n), ROR(x1,n), ROR(x2,n), ROR(x3,n) ) )
    _( 0); _( 1); _( 2); _( 3); _( 4); _( 5); _( 6); _( 7); _( 8); _( 9); _(10); _(11); _(12); _(13); _(14); _(15);
    _(16); _(17); _(18); _(19); _(20); _(21); _(22); _(23); _(24); _(25); _(26); _(27); _(28); _(29); _(30); _(31);
    _(32); _(33); _(34); _(35); _(36); _(37); _(38); _(39); _(40); _(41); _(42); _(43); _(44); _(45); _(46); _(47);
    _(48); _(49); _(50); _(51); _(52); _(53); _(54); _(55); _(56); _(57); _(58); _(59); _(60); _(61); _(62); _(63);
#   undef _

    for( int n=0; n<64; n++ ) {
      int volatile m[1]; m[0] = n;
      FD_TEST( wv_test( wv_shl_variable( x, m[0] ), x0<<n,     x1<<n,     x2<<n,     x3<<n     ) );
      FD_TEST( wv_test( wv_shr_variable( x, m[0] ), x0>>n,     x1>>n,     x2>>n,     x3>>n     ) );
      FD_TEST( wv_test( wv_rol_variable( x, m[0] ), ROL(x0,n), ROL(x1,n), ROL(x2,n), ROL(x3,n) ) );
      FD_TEST( wv_test( wv_ror_variable( x, m[0] ), ROR(x0,n), ROR(x1,n), ROR(x2,n), ROR(x3,n) ) );
    }

#   undef ROR
#   undef ROL

    FD_TEST( wv_test( wv_and(    x, y ),   x0 &y0,   x1 &y1,   x2 &y2,   x3 &y3 ) );
    FD_TEST( wv_test( wv_andnot( x, y ), (~x0)&y0, (~x1)&y1, (~x2)&y2, (~x3)&y3 ) );
    FD_TEST( wv_test( wv_or(     x, y ),   x0| y0,   x1| y1,   x2| y2,   x3| y3 ) );
    FD_TEST( wv_test( wv_xor(    x, y ),   x0^ y0,   x1^ y1,   x2^ y2,   x3^ y3 ) );

    /* Arithmetic operations */

    FD_TEST( wv_test( wv_neg( x ), -x0, -x1, -x2, -x3 ) );
    FD_TEST( wv_test( wv_abs( x ), fd_ulong_abs(x0), fd_ulong_abs(x1), fd_ulong_abs(x2), fd_ulong_abs(x3) ) );

    FD_TEST( wv_test( wv_min( x, y ), fd_ulong_min(x0,y0), fd_ulong_min(x1,y1), fd_ulong_min(x2,y2), fd_ulong_min(x3,y3) ) );
    FD_TEST( wv_test( wv_max( x, y ), fd_ulong_max(x0,y0), fd_ulong_max(x1,y1), fd_ulong_max(x2,y2), fd_ulong_max(x3,y3) ) );
    FD_TEST( wv_test( wv_add( x, y ), x0+y0, x1+y1, x2+y2, x3+y3 ) );
    FD_TEST( wv_test( wv_sub( x, y ), x0-y0, x1-y1, x2-y2, x3-y3 ) );
  //FD_TEST( wv_test( wv_mul( x, y ), x0*y0, x1*y1, x2*y2, x3*y3 ) );

#   define SE_LO(x) ((ulong)(uint)(x))
    FD_TEST( wv_test( wv_mul_ll( x, y ), SE_LO(x0)*SE_LO(y0), SE_LO(x1)*SE_LO(y1), SE_LO(x2)*SE_LO(y2), SE_LO(x3)*SE_LO(y3) ) );
#   undef SE_LO

    /* Logical operations */

    FD_TEST( wc_test( wv_lnot(    x ),  !x0,  !x0,  !x1,  !x1,  !x2,  !x2,  !x3,  !x3 ) );
    FD_TEST( wc_test( wv_lnotnot( x ), !!x0, !!x0, !!x1, !!x1, !!x2, !!x2, !!x3, !!x3 ) );

    FD_TEST( wc_test( wv_eq( x, y ), x0==y0, x0==y0, x1==y1, x1==y1, x2==y2, x2==y2, x3==y3, x3==y3 ) );
    FD_TEST( wc_test( wv_gt( x, y ), x0> y0, x0> y0, x1> y1, x1> y1, x2> y2, x2> y2, x3> y3, x3> y3 ) );
    FD_TEST( wc_test( wv_lt( x, y ), x0< y0, x0< y0, x1< y1, x1< y1, x2< y2, x2< y2, x3< y3, x3< y3 ) );
    FD_TEST( wc_test( wv_ne( x, y ), x0!=y0, x0!=y0, x1!=y1, x1!=y1, x2!=y2, x2!=y2, x3!=y3, x3!=y3 ) );
    FD_TEST( wc_test( wv_ge( x, y ), x0>=y0, x0>=y0, x1>=y1, x1>=y1, x2>=y2, x2>=y2, x3>=y3, x3>=y3 ) );
    FD_TEST( wc_test( wv_le( x, y ), x0<=y0, x0<=y0, x1<=y1, x1<=y1, x2<=y2, x2<=y2, x3<=y3, x3<=y3 ) );

    FD_TEST( wv_test( wv_czero(    c, x ), c0?0UL:x0, c1?0UL:x1, c2?0UL:x2, c3?0UL:x3 ) );
    FD_TEST( wv_test( wv_notczero( c, x ), c0?x0:0UL, c1?x1:0UL, c2?x2:0UL, c3?x3:0UL ) );

    FD_TEST( wv_test( wv_if( c, x, y ), c0?x0:y0, c1?x1:y1, c2?x2:y2, c3?x3:y3 ) );

    /* Conversion operations */

    FD_TEST( wc_test( wv_to_wc( x ), !!x0, !!x0, !!x1, !!x1, !!x2, !!x2, !!x3, !!x3 ) );

    FD_TEST( wf_test( wv_to_wf( x, wf( 0.f, 1.f, 2.f, 3.f, 4.f, 5.f, 6.f, 7.f ), 0 ),
                      (float)x0, (float)x1, (float)x2, (float)x3, 4.f, 5.f, 6.f, 7.f ) );
    FD_TEST( wf_test( wv_to_wf( x, wf( 0.f, 1.f, 2.f, 3.f, 4.f, 5.f, 6.f, 7.f ), 1 ),
                      0.f, 1.f, 2.f, 3.f, (float)x0, (float)x1, (float)x2, (float)x3 ) );

    FD_TEST( wi_test( wv_to_wi( x, wi(0,1,2,3,4,5,6,7), 0 ), (int)x0,(int)x1,(int)x2,(int)x3, 4,5,6,7 ) );
    FD_TEST( wi_test( wv_to_wi( x, wi(0,1,2,3,4,5,6,7), 1 ), 0,1,2,3, (int)x0,(int)x1,(int)x2,(int)x3 ) );

    FD_TEST( wu_test( wv_to_wu( x, wu(0U,1U,2U,3U,4U,5U,6U,7U), 0 ), (uint)x0,(uint)x1,(uint)x2,(uint)x3, 4U,5U,6U,7U ) );
    FD_TEST( wu_test( wv_to_wu( x, wu(0U,1U,2U,3U,4U,5U,6U,7U), 1 ), 0U,1U,2U,3U, (uint)x0,(uint)x1,(uint)x2,(uint)x3 ) );

    FD_TEST( wd_test( wv_to_wd( x ), (double)x0, (double)x1, (double)x2, (double)x3 ) );

    FD_TEST( wl_test( wv_to_wl( x ), (long)x0, (long)x1, (long)x2, (long)x3 ) );

    /* Reduction operations */

    FD_TEST( !wc_any( wv_ne( wv_sum_all( x ), wv_bcast( x0 + x1 + x2 + x3 ) ) ) );
    FD_TEST( !wc_any( wv_ne( wv_min_all( x ), wv_bcast( fd_ulong_min( fd_ulong_min( x0, x1 ), fd_ulong_min( x2, x3 ) ) ) ) ) );
    FD_TEST( !wc_any( wv_ne( wv_max_all( x ), wv_bcast( fd_ulong_max( fd_ulong_max( x0, x1 ), fd_ulong_max( x2, x3 ) ) ) ) ) );

    /* Misc operations */

    /* FIXME: test with more general cases */
    wv_t m0; wv_t m1; wv_t m2; wv_t m3;
    wv_transpose_4x4( wv_bcast( x0 ), wv_bcast( x1 ), wv_bcast( x2 ), wv_bcast( x3 ), m0, m1, m2, m3 );
    wv_t mm = wv( x0, x1, x2, x3 );
    FD_TEST( wc_all( wc_and( wc_and( wv_eq( m0, mm ), wv_eq( m1, mm ) ), wc_and( wv_eq( m2, mm ), wv_eq( m3, mm ) ) ) ) );
  }

  /* FIXME: TEST LDIF/STIF AND GATHER VARIANTS */
  /* FIXME: TEST VECTOR SHIFT AND ROTATE VARIANTS */

  fd_rng_delete( fd_rng_leave( rng ) );

# undef vrand
# undef lrand
# undef drand
# undef urand
# undef irand
# undef frand
# undef crand

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}

#else

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );
  FD_LOG_WARNING(( "skip: unit test requires FD_HAS_AVX capability" ));
  fd_halt();
  return 0;
}

#endif
