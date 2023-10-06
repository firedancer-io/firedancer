#include "../fd_util.h"

#if FD_HAS_SSE

#include "fd_sse.h"
#include <math.h>

/* From test_avx_common.c */

int vc_test( vc_t c, int    c0, int    c1, int    c2, int    c3 );
int vf_test( vf_t f, float  f0, float  f1, float  f2, float  f3 );
int vi_test( vi_t i, int    i0, int    i1, int    i2, int    i3 );
int vu_test( vu_t u, uint   u0, uint   u1, uint   u2, uint   u3 );
int vd_test( vd_t d, double d0, double d1 );
int vl_test( vl_t l, long   l0, long   l1 );
int vv_test( vv_t v, ulong  v0, ulong  v1 );

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

  /* VD tests */

  FD_TEST( vd_test( vd_zero(), 0., 0. ) );
  FD_TEST( vd_test( vd_one(),  1., 1. ) );

  for( int i=0; i<65536; i++ ) {
    double x0 = drand(); double x1 = drand(); vd_t x = vd( x0, x1 );
    double y0 = drand(); double y1 = drand(); vd_t y = vd( y0, y1 );
    double z0 = drand(); double z1 = drand(); vd_t z = vd( z0, z1 );
    int    c0 = crand(); int    c1 = crand(); vc_t c = vc_bcast_wide( c0, c1 );

    /* Constructors */

    FD_TEST( vd_test( x, x0, x1 ) );

    FD_TEST( vd_test( vd_bcast( x0 ), x0, x0 ) );

    FD_TEST( vd_test( vd_permute( x, 0, 0 ), x0, x0 ) );
    FD_TEST( vd_test( vd_permute( x, 0, 1 ), x0, x1 ) );
    FD_TEST( vd_test( vd_permute( x, 1, 0 ), x1, x0 ) );
    FD_TEST( vd_test( vd_permute( x, 1, 1 ), x1, x1 ) );

    /* Arithmetic operations */

    FD_TEST( vd_test( vd_neg(    x ),              -x0,          -x1  ) );
    FD_TEST( vd_test( vd_sign(   x ),      x0<0.?-1.:1., x1<0.?-1.:1. ) );
    FD_TEST( vd_test( vd_abs(    x ),          fabs(x0),     fabs(x1) ) );
    FD_TEST( vd_test( vd_negabs( x ),         -fabs(x0),    -fabs(x1) ) );
    FD_TEST( vd_test( vd_ceil(   x ),          ceil(x0),     ceil(x1) ) );
    FD_TEST( vd_test( vd_floor(  x ),         floor(x0),    floor(x1) ) );
    FD_TEST( vd_test( vd_rint(   x ),          rint(x0),     rint(x1) ) );
    FD_TEST( vd_test( vd_trunc(  x ),         trunc(x0),    trunc(x1) ) );
    FD_TEST( vd_test( vd_sqrt( vd_mul(x,x) ),  fabs(x0),     fabs(x1) ) );

    vd_t expected;
    
    expected = vd( 1./sqrt(x0+4.), 1./sqrt(x1+4.) );
    FD_TEST( !vc_any( vd_gt( vd_abs( vd_div( vd_sub( vd_rsqrt_fast( vd_add( x, vd_bcast(4.) ) ), expected ), expected ) ),
                             vd_bcast( 1./1024. ) ) ) );

    expected = vd( 1./(x0+4.), 1./(x1+4.) );
    FD_TEST( !vc_any( vd_gt( vd_abs( vd_div( vd_sub( vd_rcp_fast( vd_add( x, vd_bcast(4.) ) ), expected ), expected ) ),
                             vd_bcast( 1./1024. ) ) ) );

    FD_TEST( vd_test( vd_add(      x, y ), x0+y0, x1+y1 ) );
    FD_TEST( vd_test( vd_sub(      x, y ), x0-y0, x1-y1 ) );
    FD_TEST( vd_test( vd_mul(      x, y ), x0*y0, x1*y1 ) );
    FD_TEST( vd_test( vd_div( x, vd_add( y, vd_bcast( 4. ) ) ), x0/(y0+4.), x1/(y1+4.) ) );
    FD_TEST( vd_test( vd_min(      x, y ), fmin(x0,y0), fmin(x1,y1) ) );
    FD_TEST( vd_test( vd_max(      x, y ), fmax(x0,y0), fmax(x1,y1) ) );
    FD_TEST( vd_test( vd_copysign( x, y ), copysign(x0,y0), copysign(x1,y1) ) );
    FD_TEST( vd_test( vd_flipsign( x, y ), y0<0.?-x0:x0, y1<0.?-x1:x1 ) );

    FD_TEST( vd_test( vd_fma(  x, y, z ),  x0*y0+z0,  x1*y1+z1 ) );
    FD_TEST( vd_test( vd_fms(  x, y, z ),  x0*y0-z0,  x1*y1-z1 ) );
    FD_TEST( vd_test( vd_fnma( x, y, z ), -x0*y0+z0, -x1*y1+z1 ) );

    /* Logical operations */

    FD_TEST( vc_test( vd_lnot(    x ),   x0==0.,    x0==0.,    x1==0.,    x1==0.  ) ); /* clang makes babies cry */
    FD_TEST( vc_test( vd_lnotnot( x ), !(x0==0.), !(x0==0.), !(x1==0.), !(x1==0.) ) ); /* floating point too */
    FD_TEST( vc_test( vd_signbit( x ), signbit(x0), signbit(x0), signbit(x1), signbit(x1) ) );

    FD_TEST( vc_test( vd_eq( x, y ), x0==y0, x0==y0, x1==y1, x1==y1 ) );
    FD_TEST( vc_test( vd_gt( x, y ), x0> y0, x0> y0, x1> y1, x1> y1 ) );
    FD_TEST( vc_test( vd_lt( x, y ), x0< y0, x0< y0, x1< y1, x1< y1 ) );
    FD_TEST( vc_test( vd_ne( x, y ), x0!=y0, x0!=y0, x1!=y1, x1!=y1 ) );
    FD_TEST( vc_test( vd_ge( x, y ), x0>=y0, x0>=y0, x1>=y1, x1>=y1 ) );
    FD_TEST( vc_test( vd_le( x, y ), x0<=y0, x0<=y0, x1<=y1, x1<=y1 ) );

    FD_TEST( vd_test( vd_czero(    c, x ), c0?0.:x0, c1?0.:x1 ) );
    FD_TEST( vd_test( vd_notczero( c, x ), c0?x0:0., c1?x1:0. ) );

    FD_TEST( vd_test( vd_if( c, x, y ), c0?x0:y0, c1?x1:y1 ) );

    /* Conversion operations */
    /* FIXME: TEST LARGE MAG CONVERSION */

    FD_TEST( vc_test( vd_to_vc( x ), !(x0==0.), !(x0==0.), !(x1==0.), !(x1==0.) ) ); /* see vd_lnotnot */

    FD_TEST( vf_test( vd_to_vf( x, vf( 0.f, 1.f, 2.f, 3.f ), 0 ), (float)x0, (float)x1, 2.f, 3.f ) );
    FD_TEST( vf_test( vd_to_vf( x, vf( 0.f, 1.f, 2.f, 3.f ), 1 ), 0.f, 1.f, (float)x0, (float)x1 ) );

    FD_TEST( vi_test( vd_to_vi( x, vi( 0, 1, 2, 3 ), 0 ), (int)x0, (int)x1, 2, 3 ) );
    FD_TEST( vi_test( vd_to_vi( x, vi( 0, 1, 2, 3 ), 1 ), 0, 1, (int)x0, (int)x1 ) );

    FD_TEST( vi_test( vd_to_vi_fast( x, vi( 0, 1, 2, 3), 0 ), (int)rint(x0), (int)rint(x1), 2, 3 ) );
    FD_TEST( vi_test( vd_to_vi_fast( x, vi( 0, 1, 2, 3), 1 ), 0, 1, (int)rint(x0), (int)rint(x1) ) );

    /* The behaviour when converting from negative double to uint is highly
       dependent on the compiler version and the flags used ( e.g. gcc 8.5
       vs 9.3 with -march=native ).  Refer also to vd_to_vu_fast.  In order
       to make the test portable, negative values need to be excluded. */
    FD_TEST( vu_test( vd_to_vu( vd_abs( x ), vu(0U,1U,2U,3U), 0 ), (uint)fabs(x0),(uint)fabs(x1), 2U,3U ) );
    FD_TEST( vu_test( vd_to_vu( vd_abs( x ), vu(0U,1U,2U,3U), 1 ), 0U,1U, (uint)fabs(x0),(uint)fabs(x1) ) );

    FD_TEST( vu_test( vd_to_vu_fast( vd_abs( x ), vu(0U,1U,2U,3U), 0 ), (uint)rint(fabs(x0)),(uint)rint(fabs(x1)), 2U,3U ) );
    FD_TEST( vu_test( vd_to_vu_fast( vd_abs( x ), vu(0U,1U,2U,3U), 1 ), 0U,1U, (uint)rint(fabs(x0)),(uint)rint(fabs(x1)) ) );

    FD_TEST( vl_test( vd_to_vl( x ), (long)x0, (long)x1 ) );

    FD_TEST( vv_test( vd_to_vv( x ), (ulong)x0, (ulong)x1 ) );

    /* Reduction operations */

    FD_TEST( !vc_any( vd_ne( vd_sum_all( x ), vd_bcast( x0 + x1        ) ) ) );
    FD_TEST( !vc_any( vd_ne( vd_min_all( x ), vd_bcast( fmin( x0, x1 ) ) ) ) );
    FD_TEST( !vc_any( vd_ne( vd_max_all( x ), vd_bcast( fmax( x0, x1 ) ) ) ) );

    /* Misc operations */

    /* FIXME: test with more general cases */
    vd_t m0; vd_t m1;
    vd_transpose_2x2( vd_bcast( x0 ), vd_bcast( x1 ), m0, m1 );
    vd_t mm = vd( x0, x1 );
    FD_TEST( vc_all( vc_and( vd_eq( m0, mm ), vd_eq( m1, mm ) ) ) );
  }

  /* VL tests */

  FD_TEST( vl_test( vl_zero(), 0L, 0L ) );
  FD_TEST( vl_test( vl_one(),  1L, 1L ) );

  for( int i=0; i<65536; i++ ) {
    long x0 = lrand(); long x1 = lrand(); vl_t x = vl( x0, x1 );
    long y0 = lrand(); long y1 = lrand(); vl_t y = vl( y0, y1 );
    int  c0 = crand(); int  c1 = crand(); vc_t c = vc_bcast_wide( c0, c1 );

    /* Constructors */

    FD_TEST( vl_test( x, x0, x1 ) );

    FD_TEST( vl_test( vl_bcast( x0 ), x0, x0 ) );

    FD_TEST( vl_test( vl_permute( x, 0, 0 ), x0, x0 ) );
    FD_TEST( vl_test( vl_permute( x, 0, 1 ), x0, x1 ) );
    FD_TEST( vl_test( vl_permute( x, 1, 0 ), x1, x0 ) );
    FD_TEST( vl_test( vl_permute( x, 1, 1 ), x1, x1 ) );

    /* Bit operations */

    FD_TEST( vl_test( vl_not( x ), ~x0, ~x1 ) );

#   define SHL(x,n)  ((long)(((ulong)(x))<<(n)))
#   define SHRU(x,n) ((long)(((ulong)(x))>>(n)))
#   define ROL(x,n)  fd_long_rotate_left ((x),(n))
#   define ROR(x,n)  fd_long_rotate_right((x),(n))

#   define _(n)                                                    \
    FD_TEST( vl_test( vl_shl(  x, n ), SHL( x0,n), SHL( x1,n) ) ); \
    FD_TEST( vl_test( vl_shr(  x, n ), x0>>n,      x1>>n      ) ); \
    FD_TEST( vl_test( vl_shru( x, n ), SHRU(x0,n), SHRU(x1,n) ) ); \
    FD_TEST( vl_test( vl_rol(  x, n ), ROL( x0,n), ROL( x1,n) ) ); \
    FD_TEST( vl_test( vl_ror(  x, n ), ROR( x0,n), ROR( x1,n) ) )
    _( 0); _( 1); _( 2); _( 3); _( 4); _( 5); _( 6); _( 7); _( 8); _( 9); _(10); _(11); _(12); _(13); _(14); _(15);
    _(16); _(17); _(18); _(19); _(20); _(21); _(22); _(23); _(24); _(25); _(26); _(27); _(28); _(29); _(30); _(31);
    _(32); _(33); _(34); _(35); _(36); _(37); _(38); _(39); _(40); _(41); _(42); _(43); _(44); _(45); _(46); _(47);
    _(48); _(49); _(50); _(51); _(52); _(53); _(54); _(55); _(56); _(57); _(58); _(59); _(60); _(61); _(62); _(63);
#   undef _

    for( int n=0; n<64; n++ ) {
      int volatile m[1]; m[0] = n;
      FD_TEST( vl_test( vl_shl_variable(  x, m[0] ), SHL( x0,n), SHL( x1,n) ) );
      FD_TEST( vl_test( vl_shr_variable(  x, m[0] ), x0>>n,      x1>>n      ) );
      FD_TEST( vl_test( vl_shru_variable( x, m[0] ), SHRU(x0,n), SHRU(x1,n) ) );
      FD_TEST( vl_test( vl_rol_variable(  x, m[0] ), ROL(x0,n),  ROL(x1,n)  ) );
      FD_TEST( vl_test( vl_ror_variable(  x, m[0] ), ROR(x0,n),  ROR(x1,n)  ) );
    }

#   undef ROR
#   undef ROL
#   undef SHRU
#   undef SHL

    FD_TEST( vl_test( vl_and(    x, y ),   x0 &y0,   x1 &y1 ) );
    FD_TEST( vl_test( vl_andnot( x, y ), (~x0)&y0, (~x1)&y1 ) );
    FD_TEST( vl_test( vl_or(     x, y ),   x0| y0,   x1| y1 ) );
    FD_TEST( vl_test( vl_xor(    x, y ),   x0^ y0,   x1^ y1 ) );

    /* Arithmetic operations */

    FD_TEST( vl_test( vl_neg( x ), -x0, -x1 ) );
    FD_TEST( vl_test( vl_abs( x ), (long)fd_long_abs(x0), (long)fd_long_abs(x1) ) );

    FD_TEST( vl_test( vl_min( x, y ), fd_long_min(x0,y0), fd_long_min(x1,y1) ) );
    FD_TEST( vl_test( vl_max( x, y ), fd_long_max(x0,y0), fd_long_max(x1,y1) ) );
    FD_TEST( vl_test( vl_add( x, y ), x0+y0,              x1+y1              ) );
    FD_TEST( vl_test( vl_sub( x, y ), x0-y0,              x1-y1              ) );
  //FD_TEST( vl_test( vl_mul( x, y ), x0*y0,              x1*y1              ) );

#   define SE_LO(x) ((long)(int)(x))
    FD_TEST( vl_test( vl_mul_ll( x, y ), SE_LO(x0)*SE_LO(y0), SE_LO(x1)*SE_LO(y1) ) );
#   undef SE_LO

    /* Logical operations */

    FD_TEST( vc_test( vl_lnot(    x ),  !x0,  !x0,  !x1,  !x1 ) );
    FD_TEST( vc_test( vl_lnotnot( x ), !!x0, !!x0, !!x1, !!x1 ) );

    FD_TEST( vc_test( vl_eq( x, y ), x0==y0, x0==y0, x1==y1, x1==y1 ) );
    FD_TEST( vc_test( vl_gt( x, y ), x0> y0, x0> y0, x1> y1, x1> y1 ) );
    FD_TEST( vc_test( vl_lt( x, y ), x0< y0, x0< y0, x1< y1, x1< y1 ) );
    FD_TEST( vc_test( vl_ne( x, y ), x0!=y0, x0!=y0, x1!=y1, x1!=y1 ) );
    FD_TEST( vc_test( vl_ge( x, y ), x0>=y0, x0>=y0, x1>=y1, x1>=y1 ) );
    FD_TEST( vc_test( vl_le( x, y ), x0<=y0, x0<=y0, x1<=y1, x1<=y1 ) );

    FD_TEST( vl_test( vl_czero(    c, x ), c0?0L:x0, c1?0L:x1 ) );
    FD_TEST( vl_test( vl_notczero( c, x ), c0?x0:0L, c1?x1:0L ) );

    FD_TEST( vl_test( vl_if( c, x, y ), c0?x0:y0, c1?x1:y1 ) );

    /* Conversion operations */

    FD_TEST( vc_test( vl_to_vc( x ), !!x0, !!x0, !!x1, !!x1 ) );

    FD_TEST( vf_test( vl_to_vf( x, vf( 0.f, 1.f, 2.f, 3.f ), 0 ), (float)x0, (float)x1, 2.f, 3.f ) );
    FD_TEST( vf_test( vl_to_vf( x, vf( 0.f, 1.f, 2.f, 3.f ), 1 ), 0.f, 1.f, (float)x0, (float)x1 ) );

    FD_TEST( vi_test( vl_to_vi( x, vi( 0, 1, 2, 3 ), 0 ), (int)x0, (int)x1, 2, 3 ) );
    FD_TEST( vi_test( vl_to_vi( x, vi( 0, 1, 2, 3 ), 1 ), 0, 1, (int)x0, (int)x1 ) );

    FD_TEST( vu_test( vl_to_vu( x, vu(0U,1U,2U,3U), 0 ), (uint)x0,(uint)x1, 2U,3U ) );
    FD_TEST( vu_test( vl_to_vu( x, vu(0U,1U,2U,3U), 1 ), 0U,1U, (uint)x0,(uint)x1 ) );

    FD_TEST( vd_test( vl_to_vd( x ), (double)x0, (double)x1 ) );

    FD_TEST( vv_test( vl_to_vv( x ), (ulong)x0, (ulong)x1 ) );

    /* Reduction operations */

    FD_TEST( !vc_any( vl_ne( vl_sum_all( x ), vl_bcast( x0 + x1 ) ) ) );
    FD_TEST( !vc_any( vl_ne( vl_min_all( x ), vl_bcast( fd_long_min( x0, x1 ) ) ) ) );
    FD_TEST( !vc_any( vl_ne( vl_max_all( x ), vl_bcast( fd_long_max( x0, x1 ) ) ) ) );

    /* Misc operations */

    /* FIXME: test with more general cases */
    vl_t m0; vl_t m1;
    vl_transpose_2x2( vl_bcast( x0 ), vl_bcast( x1 ), m0, m1 );
    vl_t mm = vl( x0, x1 );
    FD_TEST( vc_all( vc_and( vl_eq( m0, mm ), vl_eq( m1, mm ) ) ) );
  }

  /* VV tests */

  FD_TEST( vv_test( vv_zero(), 0UL, 0UL ) );
  FD_TEST( vv_test( vv_one(),  1UL, 1UL ) );

  for( int i=0; i<65536; i++ ) {
    ulong x0 = vrand(); ulong x1 = vrand(); vv_t x = vv( x0, x1 );
    ulong y0 = vrand(); ulong y1 = vrand(); vv_t y = vv( y0, y1 );
    int   c0 = crand(); int   c1 = crand(); vc_t c = vc_bcast_wide( c0, c1 );

    /* Constructors */

    FD_TEST( vv_test( x, x0, x1 ) );

    FD_TEST( vv_test( vv_bcast( x0 ), x0, x0 ) );

    FD_TEST( vv_test( vv_permute( x, 0, 0 ), x0, x0 ) );
    FD_TEST( vv_test( vv_permute( x, 0, 1 ), x0, x1 ) );
    FD_TEST( vv_test( vv_permute( x, 1, 0 ), x1, x0 ) );
    FD_TEST( vv_test( vv_permute( x, 1, 1 ), x1, x1 ) );

    /* Bit operations */

    FD_TEST( vv_test( vv_not( x ), ~x0, ~x1 ) );

    FD_TEST( vv_test( vv_bswap( x ), fd_ulong_bswap( x0 ), fd_ulong_bswap( x1 ) ) );

#   define ROL(x,n) fd_ulong_rotate_left ((x),(n))
#   define ROR(x,n) fd_ulong_rotate_right((x),(n))

#   define _(n)                                                 \
    FD_TEST( vv_test( vv_shl( x, n ), x0<<n,     x1<<n     ) ); \
    FD_TEST( vv_test( vv_shr( x, n ), x0>>n,     x1>>n     ) ); \
    FD_TEST( vv_test( vv_rol( x, n ), ROL(x0,n), ROL(x1,n) ) ); \
    FD_TEST( vv_test( vv_ror( x, n ), ROR(x0,n), ROR(x1,n) ) )
    _( 0); _( 1); _( 2); _( 3); _( 4); _( 5); _( 6); _( 7); _( 8); _( 9); _(10); _(11); _(12); _(13); _(14); _(15);
    _(16); _(17); _(18); _(19); _(20); _(21); _(22); _(23); _(24); _(25); _(26); _(27); _(28); _(29); _(30); _(31);
    _(32); _(33); _(34); _(35); _(36); _(37); _(38); _(39); _(40); _(41); _(42); _(43); _(44); _(45); _(46); _(47);
    _(48); _(49); _(50); _(51); _(52); _(53); _(54); _(55); _(56); _(57); _(58); _(59); _(60); _(61); _(62); _(63);
#   undef _

    for( int n=0; n<64; n++ ) {
      int volatile m[1]; m[0] = n;
      FD_TEST( vv_test( vv_shl_variable( x, m[0] ), x0<<n,     x1<<n     ) );
      FD_TEST( vv_test( vv_shr_variable( x, m[0] ), x0>>n,     x1>>n     ) );
      FD_TEST( vv_test( vv_rol_variable( x, m[0] ), ROL(x0,n), ROL(x1,n) ) );
      FD_TEST( vv_test( vv_ror_variable( x, m[0] ), ROR(x0,n), ROR(x1,n) ) );
    }

#   undef ROR
#   undef ROL

    FD_TEST( vv_test( vv_and(    x, y ),   x0 &y0,   x1 &y1 ) );
    FD_TEST( vv_test( vv_andnot( x, y ), (~x0)&y0, (~x1)&y1 ) );
    FD_TEST( vv_test( vv_or(     x, y ),   x0| y0,   x1| y1 ) );
    FD_TEST( vv_test( vv_xor(    x, y ),   x0^ y0,   x1^ y1 ) );

    /* Arithmetic operations */

    FD_TEST( vv_test( vv_neg( x ), -x0, -x1 ) );
    FD_TEST( vv_test( vv_abs( x ), fd_ulong_abs(x0), fd_ulong_abs(x1) ) );

    FD_TEST( vv_test( vv_min( x, y ), fd_ulong_min(x0,y0), fd_ulong_min(x1,y1) ) );
    FD_TEST( vv_test( vv_max( x, y ), fd_ulong_max(x0,y0), fd_ulong_max(x1,y1) ) );
    FD_TEST( vv_test( vv_add( x, y ), x0+y0,               x1+y1               ) );
    FD_TEST( vv_test( vv_sub( x, y ), x0-y0,               x1-y1               ) );
  //FD_TEST( vv_test( vv_mul( x, y ), x0*y0,               x1*y1               ) );

#   define SE_LO(x) ((ulong)(uint)(x))
    FD_TEST( vv_test( vv_mul_ll( x, y ), SE_LO(x0)*SE_LO(y0), SE_LO(x1)*SE_LO(y1) ) );
#   undef SE_LO

    /* Logical operations */

    FD_TEST( vc_test( vv_lnot(    x ),  !x0,  !x0,  !x1,  !x1 ) );
    FD_TEST( vc_test( vv_lnotnot( x ), !!x0, !!x0, !!x1, !!x1 ) );

    FD_TEST( vc_test( vv_eq( x, y ), x0==y0, x0==y0, x1==y1, x1==y1 ) );
    FD_TEST( vc_test( vv_gt( x, y ), x0> y0, x0> y0, x1> y1, x1> y1 ) );
    FD_TEST( vc_test( vv_lt( x, y ), x0< y0, x0< y0, x1< y1, x1< y1 ) );
    FD_TEST( vc_test( vv_ne( x, y ), x0!=y0, x0!=y0, x1!=y1, x1!=y1 ) );
    FD_TEST( vc_test( vv_ge( x, y ), x0>=y0, x0>=y0, x1>=y1, x1>=y1 ) );
    FD_TEST( vc_test( vv_le( x, y ), x0<=y0, x0<=y0, x1<=y1, x1<=y1 ) );

    FD_TEST( vv_test( vv_czero(    c, x ), c0?0UL:x0, c1?0UL:x1 ) );
    FD_TEST( vv_test( vv_notczero( c, x ), c0?x0:0UL, c1?x1:0UL ) );

    FD_TEST( vv_test( vv_if( c, x, y ), c0?x0:y0, c1?x1:y1 ) );

    /* Conversion operations */

    FD_TEST( vc_test( vv_to_vc( x ), !!x0, !!x0, !!x1, !!x1 ) );

    FD_TEST( vf_test( vv_to_vf( x, vf( 0.f, 1.f, 2.f, 3.f ), 0 ), (float)x0, (float)x1, 2.f, 3.f ) );
    FD_TEST( vf_test( vv_to_vf( x, vf( 0.f, 1.f, 2.f, 3.f ), 1 ), 0.f, 1.f, (float)x0, (float)x1 ) );

    FD_TEST( vi_test( vv_to_vi( x, vi( 0, 1, 2, 3 ), 0 ), (int)x0, (int)x1, 2, 3 ) );
    FD_TEST( vi_test( vv_to_vi( x, vi( 0, 1, 2, 3 ), 1 ), 0, 1, (int)x0, (int)x1 ) );

    FD_TEST( vu_test( vv_to_vu( x, vu(0U,1U,2U,3U), 0 ), (uint)x0,(uint)x1, 2U,3U ) );
    FD_TEST( vu_test( vv_to_vu( x, vu(0U,1U,2U,3U), 1 ), 0U,1U, (uint)x0,(uint)x1 ) );

    FD_TEST( vd_test( vv_to_vd( x ), (double)x0, (double)x1 ) );

    FD_TEST( vl_test( vv_to_vl( x ), (long)x0, (long)x1 ) );

    /* Reduction operations */

    FD_TEST( !vc_any( vv_ne( vv_sum_all( x ), vv_bcast( x0 + x1 ) ) ) );
    FD_TEST( !vc_any( vv_ne( vv_min_all( x ), vv_bcast( fd_ulong_min( x0, x1 ) ) ) ) );
    FD_TEST( !vc_any( vv_ne( vv_max_all( x ), vv_bcast( fd_ulong_max( x0, x1 ) ) ) ) );

    /* Misc operations */

    /* FIXME: test with more general cases */
    vv_t m0; vv_t m1;
    vv_transpose_2x2( vv_bcast( x0 ), vv_bcast( x1 ), m0, m1 );
    vv_t mm = vv( x0, x1 );
    FD_TEST( vc_all( vc_and( vv_eq( m0, mm ), vv_eq( m1, mm ) ) ) );
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
  FD_LOG_WARNING(( "skip: unit test requires FD_HAS_SSE capability" ));
  fd_halt();
  return 0;
}

#endif
