#include "../fd_util.h"
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

  /* WC tests */

  FD_TEST( vc_test( vc_false(), 0, 0, 0, 0 ) );
  FD_TEST( vc_test( vc_true(),  1, 1, 1, 1 ) );

  for( int b=0; b<15; b++ ) {
    int c0 = (b>>0) & 1; int c1 = (b>>1) & 1; int c2 = (b>>2) & 1; int c3 = (b>>3) & 1; vc_t c = vc( c0, c1, c2, c3 );

    /* Constructors */

    FD_TEST( vc_test( c, c0, c1, c2, c3 ) );

    FD_TEST( vc_test( vc_bcast( c0 ), c0, c0, c0, c0 ) );

    FD_TEST( vc_test( vc_bcast_pair( c0, c1 ), c0, c1, c0, c1 ) );
    FD_TEST( vc_test( vc_bcast_wide( c0, c1 ), c0, c0, c1, c1 ) );

    FD_TEST( vc_test( vc_permute( c, 0, 0, 0, 0 ), c0, c0, c0, c0 ) );
    FD_TEST( vc_test( vc_permute( c, 1, 1, 1, 1 ), c1, c1, c1, c1 ) );
    FD_TEST( vc_test( vc_permute( c, 2, 2, 2, 2 ), c2, c2, c2, c2 ) );
    FD_TEST( vc_test( vc_permute( c, 3, 3, 3, 3 ), c3, c3, c3, c3 ) );
    FD_TEST( vc_test( vc_permute( c, 0, 1, 2, 3 ), c0, c1, c2, c3 ) );
    FD_TEST( vc_test( vc_permute( c, 0, 0, 2, 2 ), c0, c0, c2, c2 ) );
    FD_TEST( vc_test( vc_permute( c, 1, 1, 3, 3 ), c1, c1, c3, c3 ) );
    FD_TEST( vc_test( vc_permute( c, 1, 0, 3, 2 ), c1, c0, c3, c2 ) );
    FD_TEST( vc_test( vc_permute( c, 2, 3, 0, 1 ), c2, c3, c0, c1 ) );
    FD_TEST( vc_test( vc_permute( c, 0, 2, 1, 3 ), c0, c2, c1, c3 ) );
    FD_TEST( vc_test( vc_permute( c, 3, 2, 1, 0 ), c3, c2, c1, c0 ) );

    /* Binary, logical and conditional operations (more below) */

    FD_TEST( vc_test( vc_not( c ), !c0, !c1, !c2, !c3 ) );

    FD_TEST( vc_test( vc_lnot( c ),     !c0,  !c1,  !c2,  !c3 ) );
    FD_TEST( vc_test( vc_lnotnot( c ), !!c0, !!c1, !!c2, !!c3 ) );

    /* Conversion operations */

    FD_TEST( vi_test( vc_to_vi( c ), c0, c1, c2, c3 ) );

    FD_TEST( vu_test( vc_to_vu( c ), (uint)c0, (uint)c1, (uint)c2, (uint)c3 ) );

    FD_TEST( vf_test( vc_to_vf( c ), (float)c0, (float)c1, (float)c2, (float)c3 ) );

    FD_TEST( vd_test( vc_to_vd( vc_bcast_wide( c0,c1 ) ), (double)c0, (double)c1 ) );

    FD_TEST( vl_test( vc_to_vl( vc_bcast_wide( c0,c1 ) ), (long)c0, (long)c1 ) );

    FD_TEST( vv_test( vc_to_vv( vc_bcast_wide( c0,c1 ) ), (ulong)c0, (ulong)c1 ) );

    /* Reduction operations */

    FD_TEST( vc_any(c) == (c0 | c1 | c2 | c3) );
    FD_TEST( vc_all(c) == (c0 & c1 & c2 & c3) );

    /* Misc operations */

    vc_t cl = vc_expand( c, 0 );
    vc_t ch = vc_expand( c, 1 );
    FD_TEST( vc_test( cl, c0,c0, c1,c1 ) );
    FD_TEST( vc_test( ch, c2,c2, c3,c3 ) );
    FD_TEST( vc_test( vc_narrow(cl,ch), c0, c1, c2, c3 ) );

    /* FIXME: test with more general cases */
    vc_t m0; vc_t m1; vc_t m2; vc_t m3;
    vc_transpose_4x4( vc_bcast( c0 ), vc_bcast( c1 ), vc_bcast( c2 ), vc_bcast( c3 ), m0, m1, m2, m3 );
    vc_t mm = vc( c0, c1, c2, c3 );
    FD_TEST( vc_all( vc_and( vc_and( vc_eq( m0, mm ), vc_eq( m1, mm ) ), vc_and( vc_eq( m2, mm ), vc_eq( m3, mm ) ) ) ) );
  }

  for( int x=0; x<16; x++ ) {
    for( int y=0; y<16; y++ ) {
      vc_t vx = vc_unpack( x );
      vc_t vy = vc_unpack( y );

      FD_TEST( vc_pack( vc_and(    vx, vy ) ) == ((  x &  y )&0xf) );
      FD_TEST( vc_pack( vc_or(     vx, vy ) ) == ((  x |  y )&0xf) );
      FD_TEST( vc_pack( vc_xor(    vx, vy ) ) == ((  x ^  y )&0xf) );
      FD_TEST( vc_pack( vc_andnot( vx, vy ) ) == (((~x)&  y )&0xf) );

      FD_TEST( vc_pack( vc_eq(     vx, vy ) ) == ((~(x ^  y))&0xf) );
      FD_TEST( vc_pack( vc_gt(     vx, vy ) ) == ((  x &(~y))&0xf) );
      FD_TEST( vc_pack( vc_lt(     vx, vy ) ) == (((~x)&  y )&0xf) );
      FD_TEST( vc_pack( vc_ne(     vx, vy ) ) == ((  x ^  y )&0xf) );
      FD_TEST( vc_pack( vc_ge(     vx, vy ) ) == ((  x |(~y))&0xf) );
      FD_TEST( vc_pack( vc_le(     vx, vy ) ) == (((~x)|  y )&0xf) );
    }
  }

  for( int x=0; x<16; x++ )
    for( int y=0; y<16; y++ )
      for( int z=0; z<16; z++ )
        FD_TEST( vc_pack( vc_if( vc_unpack(x), vc_unpack(y), vc_unpack(z) ) ) == (((x&y)|((~x)&z))&0xf) );

  /* VF tests */

  FD_TEST( vf_test( vf_zero(), 0.f,0.f,0.f,0.f ) );
  FD_TEST( vf_test( vf_one(),  1.f,1.f,1.f,1.f ) );

  for( int i=0; i<65536; i++ ) {
    float x0 = frand(); float x1 = frand(); float x2 = frand(); float x3 = frand(); vf_t x = vf( x0, x1, x2, x3 );
    float y0 = frand(); float y1 = frand(); float y2 = frand(); float y3 = frand(); vf_t y = vf( y0, y1, y2, y3 );
    float z0 = frand(); float z1 = frand(); float z2 = frand(); float z3 = frand(); vf_t z = vf( z0, z1, z2, z3 );
    int c0   = crand(); int   c1 = crand(); int   c2 = crand(); int   c3 = crand(); vc_t c = vc( c0, c1, c2, c3 );

    /* Constructors */

    FD_TEST( vf_test( x, x0, x1, x2, x3 ) );

    FD_TEST( vf_test( vf_bcast( x0 ), x0, x0, x0, x0 ) );

    FD_TEST( vf_test( vf_bcast_pair( x0, x1 ), x0, x1, x0, x1 ) );
    FD_TEST( vf_test( vf_bcast_wide( x0, x1 ), x0, x0, x1, x1 ) );

    FD_TEST( vf_test( vf_permute( x, 0, 0, 0, 0 ), x0, x0, x0, x0 ) );
    FD_TEST( vf_test( vf_permute( x, 1, 1, 1, 1 ), x1, x1, x1, x1 ) );
    FD_TEST( vf_test( vf_permute( x, 2, 2, 2, 2 ), x2, x2, x2, x2 ) );
    FD_TEST( vf_test( vf_permute( x, 3, 3, 3, 3 ), x3, x3, x3, x3 ) );
    FD_TEST( vf_test( vf_permute( x, 0, 1, 2, 3 ), x0, x1, x2, x3 ) );
    FD_TEST( vf_test( vf_permute( x, 0, 0, 2, 2 ), x0, x0, x2, x2 ) );
    FD_TEST( vf_test( vf_permute( x, 1, 1, 3, 3 ), x1, x1, x3, x3 ) );
    FD_TEST( vf_test( vf_permute( x, 1, 0, 3, 2 ), x1, x0, x3, x2 ) );
    FD_TEST( vf_test( vf_permute( x, 2, 3, 0, 1 ), x2, x3, x0, x1 ) );
    FD_TEST( vf_test( vf_permute( x, 0, 2, 1, 3 ), x0, x2, x1, x3 ) );
    FD_TEST( vf_test( vf_permute( x, 3, 2, 1, 0 ), x3, x2, x1, x0 ) );

    /* Arithmetic operations */

    FD_TEST( vf_test( vf_neg(    x ),       -x0,        -x1,        -x2,        -x3  ) );
    FD_TEST( vf_test( vf_sign(   x ), x0<0.f?-1.f:1.f, x1<0.f?-1.f:1.f, x2<0.f?-1.f:1.f, x3<0.f?-1.f:1.f ) );
    FD_TEST( vf_test( vf_abs(    x ),  fabsf(x0),  fabsf(x1),  fabsf(x2),  fabsf(x3) ) );
    FD_TEST( vf_test( vf_negabs( x ), -fabsf(x0), -fabsf(x1), -fabsf(x2), -fabsf(x3) ) );
    FD_TEST( vf_test( vf_ceil(   x ),  ceilf(x0),  ceilf(x1),  ceilf(x2),  ceilf(x3) ) );
    FD_TEST( vf_test( vf_floor(  x ), floorf(x0), floorf(x1), floorf(x2), floorf(x3) ) );
    FD_TEST( vf_test( vf_rint(   x ),  rintf(x0),  rintf(x1),  rintf(x2),  rintf(x3) ) );
    FD_TEST( vf_test( vf_trunc(  x ), truncf(x0), truncf(x1), truncf(x2), truncf(x3) ) );
    FD_TEST( vf_test( vf_sqrt( vf_mul( x, x ) ), fabsf(x0), fabsf(x1), fabsf(x2), fabsf(x3) ) );

    vf_t expected;

    expected = vf( 1.f/sqrtf(x0+4.f), 1.f/sqrtf(x1+4.f), 1.f/sqrtf(x2+4.f), 1.f/sqrtf(x3+4.f) );
    FD_TEST( !vc_any( vf_gt( vf_abs( vf_div( vf_sub( vf_rsqrt_fast( vf_add( x, vf_bcast(4.f) ) ), expected ), expected ) ),
                             vf_bcast( 1.f/1024.f ) ) ) );

    expected = vf( 1.f/(x0+4.f), 1.f/(x1+4.f), 1.f/(x2+4.f), 1.f/(x3+4.f) );
    FD_TEST( !vc_any( vf_gt( vf_abs( vf_div( vf_sub( vf_rcp_fast( vf_add( x, vf_bcast(4.f) ) ), expected ), expected ) ),
                             vf_bcast( 1.f/1024.f ) ) ) );

    FD_TEST( vf_test( vf_add(      x, y ), x0+y0, x1+y1, x2+y2, x3+y3 ) );
    FD_TEST( vf_test( vf_sub(      x, y ), x0-y0, x1-y1, x2-y2, x3-y3 ) );
    FD_TEST( vf_test( vf_mul(      x, y ), x0*y0, x1*y1, x2*y2, x3*y3 ) );
    FD_TEST( vf_test( vf_div( x, vf_add( y, vf_bcast( 4.f ) ) ), x0/(y0+4.f), x1/(y1+4.f), x2/(y2+4.f), x3/(y3+4.f) ) );
    FD_TEST( vf_test( vf_min(      x, y ), fminf(x0,y0), fminf(x1,y1), fminf(x2,y2), fminf(x3,y3) ) );
    FD_TEST( vf_test( vf_max(      x, y ), fmaxf(x0,y0), fmaxf(x1,y1), fmaxf(x2,y2), fmaxf(x3,y3) ) );
    FD_TEST( vf_test( vf_copysign( x, y ), copysignf(x0,y0), copysignf(x1,y1), copysignf(x2,y2), copysignf(x3,y3) ) );
    FD_TEST( vf_test( vf_flipsign( x, y ), y0<0.f?-x0:x0, y1<0.f?-x1:x1, y2<0.f?-x2:x2, y3<0.f?-x3:x3 ) );

    FD_TEST( vf_test( vf_fma(  x, y, z ),  x0*y0+z0,  x1*y1+z1,  x2*y2+z2,  x3*y3+z3 ) );
    FD_TEST( vf_test( vf_fms(  x, y, z ),  x0*y0-z0,  x1*y1-z1,  x2*y2-z2,  x3*y3-z3 ) );
    FD_TEST( vf_test( vf_fnma( x, y, z ), -x0*y0+z0, -x1*y1+z1, -x2*y2+z2, -x3*y3+z3 ) );

    /* Logical operations */

    FD_TEST( vc_test( vf_lnot(    x ),   x0==0.f,    x1==0.f,    x2==0.f,    x3==0.f  ) ); /* clang makes babies cry */
    FD_TEST( vc_test( vf_lnotnot( x ), !(x0==0.f), !(x1==0.f), !(x2==0.f), !(x3==0.f) ) ); /* floating point too */
    FD_TEST( vc_test( vf_signbit( x ), signbit(x0), signbit(x1), signbit(x2), signbit(x3) ) );

    FD_TEST( vc_test( vf_eq( x, y ), x0==y0, x1==y1, x2==y2, x3==y3 ) );
    FD_TEST( vc_test( vf_gt( x, y ), x0> y0, x1> y1, x2> y2, x3> y3 ) );
    FD_TEST( vc_test( vf_lt( x, y ), x0< y0, x1< y1, x2< y2, x3< y3 ) );
    FD_TEST( vc_test( vf_ne( x, y ), x0!=y0, x1!=y1, x2!=y2, x3!=y3 ) );
    FD_TEST( vc_test( vf_ge( x, y ), x0>=y0, x1>=y1, x2>=y2, x3>=y3 ) );
    FD_TEST( vc_test( vf_le( x, y ), x0<=y0, x1<=y1, x2<=y2, x3<=y3 ) );

    FD_TEST( vf_test( vf_czero(    c, x ), c0?0.f:x0, c1?0.f:x1, c2?0.f:x2, c3?0.f:x3 ) );
    FD_TEST( vf_test( vf_notczero( c, x ), c0?x0:0.f, c1?x1:0.f, c2?x2:0.f, c3?x3:0.f ) );

    FD_TEST( vf_test( vf_if( c, x, y ), c0?x0:y0, c1?x1:y1, c2?x2:y2, c3?x3:y3 ) );

    /* Conversion operations */
    /* FIXME: TEST LARGE MAG CONVERSION */

    FD_TEST( vc_test( vf_to_vc( x ), !(x0==0.f), !(x1==0.f), !(x2==0.f), !(x3==0.f) ) ); /* see vf_lnotnot */

    FD_TEST( vi_test( vf_to_vi( x ), (int)x0, (int)x1, (int)x2, (int)x3 ) );
    FD_TEST( vi_test( vf_to_vi_fast( x ), (int)rintf(x0), (int)rintf(x1), (int)rintf(x2), (int)rintf(x3) ) );

    /* The behaviour when converting from negative float to uint is highly
       dependent on the compiler version and the flags used ( e.g. gcc 8.5
       vs 9.3 with -march=native ).  Refer also to vf_to_vu_fast.  In order
       to make the test portable, negative values need to be excluded. */
    FD_TEST( vu_test( vf_to_vu( vf_abs( x ) ), (uint)fabsf(x0), (uint)fabsf(x1), (uint)fabsf(x2), (uint)fabsf(x3) ) );
    FD_TEST( vu_test( vf_to_vu_fast( vf_abs( x ) ), (uint)rintf(fabsf(x0)), (uint)rintf(fabsf(x1)), (uint)rintf(fabsf(x2)), (uint)rintf(fabsf(x3)) ) );

    FD_TEST( vd_test( vf_to_vd( x, 0, 0 ), (double)x0, (double)x0 ) );
    FD_TEST( vd_test( vf_to_vd( x, 0, 1 ), (double)x0, (double)x1 ) );
    FD_TEST( vd_test( vf_to_vd( x, 0, 2 ), (double)x0, (double)x2 ) );
    FD_TEST( vd_test( vf_to_vd( x, 0, 3 ), (double)x0, (double)x3 ) );
    FD_TEST( vd_test( vf_to_vd( x, 1, 0 ), (double)x1, (double)x0 ) );
    FD_TEST( vd_test( vf_to_vd( x, 1, 1 ), (double)x1, (double)x1 ) );
    FD_TEST( vd_test( vf_to_vd( x, 1, 2 ), (double)x1, (double)x2 ) );
    FD_TEST( vd_test( vf_to_vd( x, 1, 3 ), (double)x1, (double)x3 ) );
    FD_TEST( vd_test( vf_to_vd( x, 2, 0 ), (double)x2, (double)x0 ) );
    FD_TEST( vd_test( vf_to_vd( x, 2, 1 ), (double)x2, (double)x1 ) );
    FD_TEST( vd_test( vf_to_vd( x, 2, 2 ), (double)x2, (double)x2 ) );
    FD_TEST( vd_test( vf_to_vd( x, 2, 3 ), (double)x2, (double)x3 ) );
    FD_TEST( vd_test( vf_to_vd( x, 3, 0 ), (double)x3, (double)x0 ) );
    FD_TEST( vd_test( vf_to_vd( x, 3, 1 ), (double)x3, (double)x1 ) );
    FD_TEST( vd_test( vf_to_vd( x, 3, 2 ), (double)x3, (double)x2 ) );
    FD_TEST( vd_test( vf_to_vd( x, 3, 3 ), (double)x3, (double)x3 ) );

    FD_TEST( vl_test( vf_to_vl( x, 0, 0 ), (long)x0, (long)x0 ) );
    FD_TEST( vl_test( vf_to_vl( x, 0, 1 ), (long)x0, (long)x1 ) );
    FD_TEST( vl_test( vf_to_vl( x, 0, 2 ), (long)x0, (long)x2 ) );
    FD_TEST( vl_test( vf_to_vl( x, 0, 3 ), (long)x0, (long)x3 ) );
    FD_TEST( vl_test( vf_to_vl( x, 1, 0 ), (long)x1, (long)x0 ) );
    FD_TEST( vl_test( vf_to_vl( x, 1, 1 ), (long)x1, (long)x1 ) );
    FD_TEST( vl_test( vf_to_vl( x, 1, 2 ), (long)x1, (long)x2 ) );
    FD_TEST( vl_test( vf_to_vl( x, 1, 3 ), (long)x1, (long)x3 ) );
    FD_TEST( vl_test( vf_to_vl( x, 2, 0 ), (long)x2, (long)x0 ) );
    FD_TEST( vl_test( vf_to_vl( x, 2, 1 ), (long)x2, (long)x1 ) );
    FD_TEST( vl_test( vf_to_vl( x, 2, 2 ), (long)x2, (long)x2 ) );
    FD_TEST( vl_test( vf_to_vl( x, 2, 3 ), (long)x2, (long)x3 ) );
    FD_TEST( vl_test( vf_to_vl( x, 3, 0 ), (long)x3, (long)x0 ) );
    FD_TEST( vl_test( vf_to_vl( x, 3, 1 ), (long)x3, (long)x1 ) );
    FD_TEST( vl_test( vf_to_vl( x, 3, 2 ), (long)x3, (long)x2 ) );
    FD_TEST( vl_test( vf_to_vl( x, 3, 3 ), (long)x3, (long)x3 ) );

    FD_TEST( vv_test( vf_to_vv( x, 0, 0 ), (ulong)x0, (ulong)x0 ) );
    FD_TEST( vv_test( vf_to_vv( x, 0, 1 ), (ulong)x0, (ulong)x1 ) );
    FD_TEST( vv_test( vf_to_vv( x, 0, 2 ), (ulong)x0, (ulong)x2 ) );
    FD_TEST( vv_test( vf_to_vv( x, 0, 3 ), (ulong)x0, (ulong)x3 ) );
    FD_TEST( vv_test( vf_to_vv( x, 1, 0 ), (ulong)x1, (ulong)x0 ) );
    FD_TEST( vv_test( vf_to_vv( x, 1, 1 ), (ulong)x1, (ulong)x1 ) );
    FD_TEST( vv_test( vf_to_vv( x, 1, 2 ), (ulong)x1, (ulong)x2 ) );
    FD_TEST( vv_test( vf_to_vv( x, 1, 3 ), (ulong)x1, (ulong)x3 ) );
    FD_TEST( vv_test( vf_to_vv( x, 2, 0 ), (ulong)x2, (ulong)x0 ) );
    FD_TEST( vv_test( vf_to_vv( x, 2, 1 ), (ulong)x2, (ulong)x1 ) );
    FD_TEST( vv_test( vf_to_vv( x, 2, 2 ), (ulong)x2, (ulong)x2 ) );
    FD_TEST( vv_test( vf_to_vv( x, 2, 3 ), (ulong)x2, (ulong)x3 ) );
    FD_TEST( vv_test( vf_to_vv( x, 3, 0 ), (ulong)x3, (ulong)x0 ) );
    FD_TEST( vv_test( vf_to_vv( x, 3, 1 ), (ulong)x3, (ulong)x1 ) );
    FD_TEST( vv_test( vf_to_vv( x, 3, 2 ), (ulong)x3, (ulong)x2 ) );
    FD_TEST( vv_test( vf_to_vv( x, 3, 3 ), (ulong)x3, (ulong)x3 ) );

    /* Reduction operations */

    FD_TEST( !vc_any( vf_ne( vf_sum_all( x ), vf_bcast( x0 + x1 + x2 + x3 ) ) ) );
    FD_TEST( !vc_any( vf_ne( vf_min_all( x ), vf_bcast( fminf( fminf( x0, x1 ), fminf( x2, x3 ) ) ) ) ) );
    FD_TEST( !vc_any( vf_ne( vf_max_all( x ), vf_bcast( fmaxf( fmaxf( x0, x1 ), fmaxf( x2, x3 ) ) ) ) ) );

    /* Misc operations */

    /* FIXME: test with more general cases */
    vf_t m0; vf_t m1; vf_t m2; vf_t m3;
    vf_transpose_4x4( vf_bcast( x0 ), vf_bcast( x1 ), vf_bcast( x2 ), vf_bcast( x3 ), m0, m1, m2, m3 );
    vf_t mm = vf( x0, x1, x2, x3 );
    FD_TEST( vc_all( vc_and( vc_and( vf_eq( m0, mm ), vf_eq( m1, mm ) ), vc_and( vf_eq( m2, mm ), vf_eq( m3, mm ) ) ) ) );
  }

  /* VI tests */

  FD_TEST( vi_test( vi_zero(), 0, 0, 0, 0 ) );
  FD_TEST( vi_test( vi_one(),  1, 1, 1, 1 ) );

  for( int i=0; i<65536; i++ ) {
    int x0 = irand(); int x1 = irand(); int x2 = irand(); int x3 = irand(); vi_t x = vi( x0, x1, x2, x3 );
    int y0 = irand(); int y1 = irand(); int y2 = irand(); int y3 = irand(); vi_t y = vi( y0, y1, y2, y3 );
    int c0 = crand(); int c1 = crand(); int c2 = crand(); int c3 = crand(); vc_t c = vc( c0, c1, c2, c3 );

    /* Constructors */

    FD_TEST( vi_test( x, x0, x1, x2, x3 ) );

    FD_TEST( vi_test( vi_bcast( x0 ), x0, x0, x0, x0 ) );

    FD_TEST( vi_test( vi_bcast_pair( x0, x1 ), x0, x1, x0, x1 ) );
    FD_TEST( vi_test( vi_bcast_wide( x0, x1 ), x0, x0, x1, x1 ) );

    FD_TEST( vi_test( vi_permute( x, 0, 0, 0, 0 ), x0, x0, x0, x0 ) );
    FD_TEST( vi_test( vi_permute( x, 1, 1, 1, 1 ), x1, x1, x1, x1 ) );
    FD_TEST( vi_test( vi_permute( x, 2, 2, 2, 2 ), x2, x2, x2, x2 ) );
    FD_TEST( vi_test( vi_permute( x, 3, 3, 3, 3 ), x3, x3, x3, x3 ) );
    FD_TEST( vi_test( vi_permute( x, 0, 1, 2, 3 ), x0, x1, x2, x3 ) );
    FD_TEST( vi_test( vi_permute( x, 0, 0, 2, 2 ), x0, x0, x2, x2 ) );
    FD_TEST( vi_test( vi_permute( x, 1, 1, 3, 3 ), x1, x1, x3, x3 ) );
    FD_TEST( vi_test( vi_permute( x, 1, 0, 3, 2 ), x1, x0, x3, x2 ) );
    FD_TEST( vi_test( vi_permute( x, 2, 3, 0, 1 ), x2, x3, x0, x1 ) );
    FD_TEST( vi_test( vi_permute( x, 0, 2, 1, 3 ), x0, x2, x1, x3 ) );
    FD_TEST( vi_test( vi_permute( x, 3, 2, 1, 0 ), x3, x2, x1, x0 ) );

    /* Bit operations */

    FD_TEST( vi_test( vi_not( x ), ~x0, ~x1, ~x2, ~x3 ) );

#   define SHL(x,n)  ((int)(((uint)(x))<<(n)))
#   define SHRU(x,n) ((int)(((uint)(x))>>(n)))
#   define ROL(x,n)  fd_int_rotate_left ((x),(n))
#   define ROR(x,n)  fd_int_rotate_right((x),(n))

#   define _(n)                                                                            \
    FD_TEST( vi_test( vi_shl(  x, n ), SHL( x0,n), SHL( x1,n), SHL( x2,n), SHL( x3,n) ) ); \
    FD_TEST( vi_test( vi_shr(  x, n ), x0>>n,      x1>>n,      x2>>n,      x3>>n      ) ); \
    FD_TEST( vi_test( vi_shru( x, n ), SHRU(x0,n), SHRU(x1,n), SHRU(x2,n), SHRU(x3,n) ) ); \
    FD_TEST( vi_test( vi_rol(  x, n ), ROL( x0,n), ROL( x1,n), ROL( x2,n), ROL( x3,n) ) ); \
    FD_TEST( vi_test( vi_ror(  x, n ), ROR( x0,n), ROR( x1,n), ROR( x2,n), ROR( x3,n) ) )
    _( 0); _( 1); _( 2); _( 3); _( 4); _( 5); _( 6); _( 7); _( 8); _( 9); _(10); _(11); _(12); _(13); _(14); _(15);
    _(16); _(17); _(18); _(19); _(20); _(21); _(22); _(23); _(24); _(25); _(26); _(27); _(28); _(29); _(30); _(31);
#   undef _

    for( int n=0; n<32; n++ ) {
      int volatile m[1]; m[0] = n;
      FD_TEST( vi_test( vi_shl_variable(  x, m[0] ), SHL( x0,n), SHL( x1,n), SHL( x2,n), SHL( x3,n) ) );
      FD_TEST( vi_test( vi_shr_variable(  x, m[0] ), x0>>n,      x1>>n,      x2>>n,      x3>>n      ) );
      FD_TEST( vi_test( vi_shru_variable( x, m[0] ), SHRU(x0,n), SHRU(x1,n), SHRU(x2,n), SHRU(x3,n) ) );
      FD_TEST( vi_test( vi_rol_variable(  x, m[0] ), ROL( x0,n), ROL( x1,n), ROL( x2,n), ROL( x3,n) ) );
      FD_TEST( vi_test( vi_ror_variable(  x, m[0] ), ROR( x0,n), ROR( x1,n), ROR( x2,n), ROR( x3,n) ) );
    }

#   undef ROR
#   undef ROL
#   undef SHRU
#   undef SHL

    FD_TEST( vi_test( vi_and(    x, y ),   x0 &y0,   x1 &y1,   x2 &y2,   x3 &y3 ) );
    FD_TEST( vi_test( vi_andnot( x, y ), (~x0)&y0, (~x1)&y1, (~x2)&y2, (~x3)&y3 ) );
    FD_TEST( vi_test( vi_or(     x, y ),   x0| y0,   x1| y1,   x2| y2,   x3| y3 ) );
    FD_TEST( vi_test( vi_xor(    x, y ),   x0^ y0,   x1^ y1,   x2^ y2,   x3^ y3 ) );

    /* Arithmetic operations */

    FD_TEST( vi_test( vi_neg( x ), -x0, -x1, -x2, -x3 ) );
    FD_TEST( vi_test( vi_abs( x ), (int)fd_int_abs(x0), (int)fd_int_abs(x1), (int)fd_int_abs(x2), (int)fd_int_abs(x3) ) );

    FD_TEST( vi_test( vi_min( x, y ), fd_int_min(x0,y0), fd_int_min(x1,y1), fd_int_min(x2,y2), fd_int_min(x3,y3) ) );
    FD_TEST( vi_test( vi_max( x, y ), fd_int_max(x0,y0), fd_int_max(x1,y1), fd_int_max(x2,y2), fd_int_max(x3,y3) ) );
    FD_TEST( vi_test( vi_add( x, y ), x0+y0, x1+y1, x2+y2, x3+y3 ) );
    FD_TEST( vi_test( vi_sub( x, y ), x0-y0, x1-y1, x2-y2, x3-y3 ) );
    FD_TEST( vi_test( vi_mul( x, y ), x0*y0, x1*y1, x2*y2, x3*y3 ) );

    /* Logical operations */

    FD_TEST( vc_test( vi_lnot(    x ),  !x0,  !x1,  !x2,  !x3 ) );
    FD_TEST( vc_test( vi_lnotnot( x ), !!x0, !!x1, !!x2, !!x3 ) );

    FD_TEST( vc_test( vi_eq( x, y ), x0==y0, x1==y1, x2==y2, x3==y3 ) );
    FD_TEST( vc_test( vi_gt( x, y ), x0> y0, x1> y1, x2> y2, x3> y3 ) );
    FD_TEST( vc_test( vi_lt( x, y ), x0< y0, x1< y1, x2< y2, x3< y3 ) );
    FD_TEST( vc_test( vi_ne( x, y ), x0!=y0, x1!=y1, x2!=y2, x3!=y3 ) );
    FD_TEST( vc_test( vi_ge( x, y ), x0>=y0, x1>=y1, x2>=y2, x3>=y3 ) );
    FD_TEST( vc_test( vi_le( x, y ), x0<=y0, x1<=y1, x2<=y2, x3<=y3 ) );

    FD_TEST( vi_test( vi_czero(    c, x ), c0? 0:x0, c1? 0:x1, c2? 0:x2, c3? 0:x3 ) );
    FD_TEST( vi_test( vi_notczero( c, x ), c0?x0: 0, c1?x1: 0, c2?x2: 0, c3?x3: 0 ) );
    FD_TEST( vi_test( vi_if( c, x, y ),    c0?x0:y0, c1?x1:y1, c2?x2:y2, c3?x3:y3 ) );

    /* Conversion operations */

    FD_TEST( vc_test( vi_to_vc( x ), !!x0, !!x1, !!x2, !!x3 ) );

    FD_TEST( vf_test( vi_to_vf( x ), (float)x0, (float)x1, (float)x2, (float)x3 ) );

    FD_TEST( vu_test( vi_to_vu( x ), (uint)x0, (uint)x1, (uint)x2, (uint)x3 ) );

    FD_TEST( vd_test( vi_to_vd( x, 0, 0 ), (double)x0, (double)x0 ) );
    FD_TEST( vd_test( vi_to_vd( x, 0, 1 ), (double)x0, (double)x1 ) );
    FD_TEST( vd_test( vi_to_vd( x, 0, 2 ), (double)x0, (double)x2 ) );
    FD_TEST( vd_test( vi_to_vd( x, 0, 3 ), (double)x0, (double)x3 ) );
    FD_TEST( vd_test( vi_to_vd( x, 1, 0 ), (double)x1, (double)x0 ) );
    FD_TEST( vd_test( vi_to_vd( x, 1, 1 ), (double)x1, (double)x1 ) );
    FD_TEST( vd_test( vi_to_vd( x, 1, 2 ), (double)x1, (double)x2 ) );
    FD_TEST( vd_test( vi_to_vd( x, 1, 3 ), (double)x1, (double)x3 ) );
    FD_TEST( vd_test( vi_to_vd( x, 2, 0 ), (double)x2, (double)x0 ) );
    FD_TEST( vd_test( vi_to_vd( x, 2, 1 ), (double)x2, (double)x1 ) );
    FD_TEST( vd_test( vi_to_vd( x, 2, 2 ), (double)x2, (double)x2 ) );
    FD_TEST( vd_test( vi_to_vd( x, 2, 3 ), (double)x2, (double)x3 ) );
    FD_TEST( vd_test( vi_to_vd( x, 3, 0 ), (double)x3, (double)x0 ) );
    FD_TEST( vd_test( vi_to_vd( x, 3, 1 ), (double)x3, (double)x1 ) );
    FD_TEST( vd_test( vi_to_vd( x, 3, 2 ), (double)x3, (double)x2 ) );
    FD_TEST( vd_test( vi_to_vd( x, 3, 3 ), (double)x3, (double)x3 ) );

    FD_TEST( vl_test( vi_to_vl( x, 0, 0 ), (long)x0, (long)x0 ) );
    FD_TEST( vl_test( vi_to_vl( x, 0, 1 ), (long)x0, (long)x1 ) );
    FD_TEST( vl_test( vi_to_vl( x, 0, 2 ), (long)x0, (long)x2 ) );
    FD_TEST( vl_test( vi_to_vl( x, 0, 3 ), (long)x0, (long)x3 ) );
    FD_TEST( vl_test( vi_to_vl( x, 1, 0 ), (long)x1, (long)x0 ) );
    FD_TEST( vl_test( vi_to_vl( x, 1, 1 ), (long)x1, (long)x1 ) );
    FD_TEST( vl_test( vi_to_vl( x, 1, 2 ), (long)x1, (long)x2 ) );
    FD_TEST( vl_test( vi_to_vl( x, 1, 3 ), (long)x1, (long)x3 ) );
    FD_TEST( vl_test( vi_to_vl( x, 2, 0 ), (long)x2, (long)x0 ) );
    FD_TEST( vl_test( vi_to_vl( x, 2, 1 ), (long)x2, (long)x1 ) );
    FD_TEST( vl_test( vi_to_vl( x, 2, 2 ), (long)x2, (long)x2 ) );
    FD_TEST( vl_test( vi_to_vl( x, 2, 3 ), (long)x2, (long)x3 ) );
    FD_TEST( vl_test( vi_to_vl( x, 3, 0 ), (long)x3, (long)x0 ) );
    FD_TEST( vl_test( vi_to_vl( x, 3, 1 ), (long)x3, (long)x1 ) );
    FD_TEST( vl_test( vi_to_vl( x, 3, 2 ), (long)x3, (long)x2 ) );
    FD_TEST( vl_test( vi_to_vl( x, 3, 3 ), (long)x3, (long)x3 ) );

    FD_TEST( vv_test( vi_to_vv( x, 0, 0 ), (ulong)x0, (ulong)x0 ) );
    FD_TEST( vv_test( vi_to_vv( x, 0, 1 ), (ulong)x0, (ulong)x1 ) );
    FD_TEST( vv_test( vi_to_vv( x, 0, 2 ), (ulong)x0, (ulong)x2 ) );
    FD_TEST( vv_test( vi_to_vv( x, 0, 3 ), (ulong)x0, (ulong)x3 ) );
    FD_TEST( vv_test( vi_to_vv( x, 1, 0 ), (ulong)x1, (ulong)x0 ) );
    FD_TEST( vv_test( vi_to_vv( x, 1, 1 ), (ulong)x1, (ulong)x1 ) );
    FD_TEST( vv_test( vi_to_vv( x, 1, 2 ), (ulong)x1, (ulong)x2 ) );
    FD_TEST( vv_test( vi_to_vv( x, 1, 3 ), (ulong)x1, (ulong)x3 ) );
    FD_TEST( vv_test( vi_to_vv( x, 2, 0 ), (ulong)x2, (ulong)x0 ) );
    FD_TEST( vv_test( vi_to_vv( x, 2, 1 ), (ulong)x2, (ulong)x1 ) );
    FD_TEST( vv_test( vi_to_vv( x, 2, 2 ), (ulong)x2, (ulong)x2 ) );
    FD_TEST( vv_test( vi_to_vv( x, 2, 3 ), (ulong)x2, (ulong)x3 ) );
    FD_TEST( vv_test( vi_to_vv( x, 3, 0 ), (ulong)x3, (ulong)x0 ) );
    FD_TEST( vv_test( vi_to_vv( x, 3, 1 ), (ulong)x3, (ulong)x1 ) );
    FD_TEST( vv_test( vi_to_vv( x, 3, 2 ), (ulong)x3, (ulong)x2 ) );
    FD_TEST( vv_test( vi_to_vv( x, 3, 3 ), (ulong)x3, (ulong)x3 ) );

    /* Reduction operations */

    FD_TEST( !vc_any( vi_ne( vi_sum_all( x ), vi_bcast( x0 + x1 + x2 + x3 ) ) ) );
    FD_TEST( !vc_any( vi_ne( vi_min_all( x ), vi_bcast( fd_int_min( fd_int_min( x0, x1 ), fd_int_min( x2, x3 ) ) ) ) ) );
    FD_TEST( !vc_any( vi_ne( vi_max_all( x ), vi_bcast( fd_int_max( fd_int_max( x0, x1 ), fd_int_max( x2, x3 ) ) ) ) ) );

    /* Misc operations */

    /* FIXME: test with more general cases */
    vi_t m0; vi_t m1; vi_t m2; vi_t m3;
    vi_transpose_4x4( vi_bcast( x0 ), vi_bcast( x1 ), vi_bcast( x2 ), vi_bcast( x3 ), m0, m1, m2, m3 );
    vi_t mm = vi( x0, x1, x2, x3 );
    FD_TEST( vc_all( vc_and( vc_and( vi_eq( m0, mm ), vi_eq( m1, mm ) ), vc_and( vi_eq( m2, mm ), vi_eq( m3, mm ) ) ) ) );
  }

  /* VU tests */

  FD_TEST( vu_test( vu_zero(), 0, 0, 0, 0 ) );
  FD_TEST( vu_test( vu_one(),  1, 1, 1, 1 ) );

  for( int i=0; i<65536; i++ ) {
    uint x0 = urand(); uint x1 = urand(); uint x2 = urand(); uint x3 = urand(); vu_t x = vu( x0, x1, x2, x3 );
    uint y0 = urand(); uint y1 = urand(); uint y2 = urand(); uint y3 = urand(); vu_t y = vu( y0, y1, y2, y3 );
    int  c0 = crand(); int  c1 = crand(); int  c2 = crand(); int  c3 = crand(); vc_t c = vc( c0, c1, c2, c3 );

    /* Constructors */

    FD_TEST( vu_test( x, x0, x1, x2, x3 ) );

    FD_TEST( vu_test( vu_bcast( x0 ), x0, x0, x0, x0 ) );

    FD_TEST( vu_test( vu_bcast_pair( x0, x1 ), x0, x1, x0, x1 ) );
    FD_TEST( vu_test( vu_bcast_wide( x0, x1 ), x0, x0, x1, x1 ) );

    FD_TEST( vu_test( vu_permute( x, 0, 0, 0, 0 ), x0, x0, x0, x0 ) );
    FD_TEST( vu_test( vu_permute( x, 1, 1, 1, 1 ), x1, x1, x1, x1 ) );
    FD_TEST( vu_test( vu_permute( x, 2, 2, 2, 2 ), x2, x2, x2, x2 ) );
    FD_TEST( vu_test( vu_permute( x, 3, 3, 3, 3 ), x3, x3, x3, x3 ) );
    FD_TEST( vu_test( vu_permute( x, 0, 1, 2, 3 ), x0, x1, x2, x3 ) );
    FD_TEST( vu_test( vu_permute( x, 0, 0, 2, 2 ), x0, x0, x2, x2 ) );
    FD_TEST( vu_test( vu_permute( x, 1, 1, 3, 3 ), x1, x1, x3, x3 ) );
    FD_TEST( vu_test( vu_permute( x, 1, 0, 3, 2 ), x1, x0, x3, x2 ) );
    FD_TEST( vu_test( vu_permute( x, 2, 3, 0, 1 ), x2, x3, x0, x1 ) );
    FD_TEST( vu_test( vu_permute( x, 0, 2, 1, 3 ), x0, x2, x1, x3 ) );
    FD_TEST( vu_test( vu_permute( x, 3, 2, 1, 0 ), x3, x2, x1, x0 ) );

    /* Bit operations */

    FD_TEST( vu_test( vu_not( x ), ~x0, ~x1, ~x2, ~x3 ) );

    FD_TEST( vu_test( vu_bswap( x ), fd_uint_bswap( x0 ), fd_uint_bswap( x1 ), fd_uint_bswap( x2 ), fd_uint_bswap( x3 ) ) );

#   define ROL(x,n) fd_uint_rotate_left ((x),(n))
#   define ROR(x,n) fd_uint_rotate_right((x),(n))

#   define _(n)                                                                       \
    FD_TEST( vu_test( vu_shl( x, n ), x0<<n,     x1<<n,     x2<<n,     x3<<n     ) ); \
    FD_TEST( vu_test( vu_shr( x, n ), x0>>n,     x1>>n,     x2>>n,     x3>>n     ) ); \
    FD_TEST( vu_test( vu_rol( x, n ), ROL(x0,n), ROL(x1,n), ROL(x2,n), ROL(x3,n) ) ); \
    FD_TEST( vu_test( vu_ror( x, n ), ROR(x0,n), ROR(x1,n), ROR(x2,n), ROR(x3,n) ) )
    _( 0); _( 1); _( 2); _( 3); _( 4); _( 5); _( 6); _( 7); _( 8); _( 9); _(10); _(11); _(12); _(13); _(14); _(15);
    _(16); _(17); _(18); _(19); _(20); _(21); _(22); _(23); _(24); _(25); _(26); _(27); _(28); _(29); _(30); _(31);
#   undef _

    for( int n=0; n<32; n++ ) {
      int volatile m[1]; m[0] = n;
      FD_TEST( vu_test( vu_shl_variable( x, m[0] ), x0<<n,     x1<<n,     x2<<n,     x3<<n     ) );
      FD_TEST( vu_test( vu_shr_variable( x, m[0] ), x0>>n,     x1>>n,     x2>>n,     x3>>n     ) );
      FD_TEST( vu_test( vu_rol_variable( x, m[0] ), ROL(x0,n), ROL(x1,n), ROL(x2,n), ROL(x3,n) ) );
      FD_TEST( vu_test( vu_ror_variable( x, m[0] ), ROR(x0,n), ROR(x1,n), ROR(x2,n), ROR(x3,n) ) );
    }

#   undef ROR
#   undef ROL

    FD_TEST( vu_test( vu_and(    x, y ),   x0 &y0,   x1 &y1,   x2 &y2,   x3 &y3 ) );
    FD_TEST( vu_test( vu_andnot( x, y ), (~x0)&y0, (~x1)&y1, (~x2)&y2, (~x3)&y3 ) );
    FD_TEST( vu_test( vu_or(     x, y ),   x0| y0,   x1| y1,   x2| y2,   x3| y3 ) );
    FD_TEST( vu_test( vu_xor(    x, y ),   x0^ y0,   x1^ y1,   x2^ y2,   x3^ y3 ) );

    /* Arithmetic operations */

    FD_TEST( vu_test( vu_neg( x ), -x0, -x1, -x2, -x3 ) );
    FD_TEST( vu_test( vu_abs( x ), fd_uint_abs(x0), fd_uint_abs(x1), fd_uint_abs(x2), fd_uint_abs(x3) ) );

    FD_TEST( vu_test( vu_min( x, y ), fd_uint_min(x0,y0), fd_uint_min(x1,y1), fd_uint_min(x2,y2), fd_uint_min(x3,y3) ) );
    FD_TEST( vu_test( vu_max( x, y ), fd_uint_max(x0,y0), fd_uint_max(x1,y1), fd_uint_max(x2,y2), fd_uint_max(x3,y3) ) );
    FD_TEST( vu_test( vu_add( x, y ), x0+y0, x1+y1, x2+y2, x3+y3 ) );
    FD_TEST( vu_test( vu_sub( x, y ), x0-y0, x1-y1, x2-y2, x3-y3 ) );
    FD_TEST( vu_test( vu_mul( x, y ), x0*y0, x1*y1, x2*y2, x3*y3 ) );

    /* Logical operations */

    FD_TEST( vc_test( vu_lnot(    x ),  !x0,  !x1,  !x2,  !x3 ) );
    FD_TEST( vc_test( vu_lnotnot( x ), !!x0, !!x1, !!x2, !!x3 ) );

    FD_TEST( vc_test( vu_eq( x, y ), x0==y0, x1==y1, x2==y2, x3==y3 ) );
    FD_TEST( vc_test( vu_gt( x, y ), x0> y0, x1> y1, x2> y2, x3> y3 ) );
    FD_TEST( vc_test( vu_lt( x, y ), x0< y0, x1< y1, x2< y2, x3< y3 ) );
    FD_TEST( vc_test( vu_ne( x, y ), x0!=y0, x1!=y1, x2!=y2, x3!=y3 ) );
    FD_TEST( vc_test( vu_ge( x, y ), x0>=y0, x1>=y1, x2>=y2, x3>=y3 ) );
    FD_TEST( vc_test( vu_le( x, y ), x0<=y0, x1<=y1, x2<=y2, x3<=y3 ) );

    FD_TEST( vu_test( vu_czero(    c, x ), c0?0U:x0, c1?0U:x1, c2?0U:x2, c3?0U:x3 ) );
    FD_TEST( vu_test( vu_notczero( c, x ), c0?x0:0U, c1?x1:0U, c2?x2:0U, c3?x3:0U ) );
    FD_TEST( vu_test( vu_if( c, x, y ),    c0?x0:y0, c1?x1:y1, c2?x2:y2, c3?x3:y3 ) );

    /* Conversion operations */

    FD_TEST( vc_test( vu_to_vc( x ), !!x0, !!x1, !!x2, !!x3 ) );

    FD_TEST( vf_test( vu_to_vf( x ), (float)x0, (float)x1, (float)x2, (float)x3 ) );

    FD_TEST( vi_test( vu_to_vi( x ), (int)x0, (int)x1, (int)x2, (int)x3 ) );

    FD_TEST( vd_test( vu_to_vd( x, 0, 0 ), (double)x0, (double)x0 ) );
    FD_TEST( vd_test( vu_to_vd( x, 0, 1 ), (double)x0, (double)x1 ) );
    FD_TEST( vd_test( vu_to_vd( x, 0, 2 ), (double)x0, (double)x2 ) );
    FD_TEST( vd_test( vu_to_vd( x, 0, 3 ), (double)x0, (double)x3 ) );
    FD_TEST( vd_test( vu_to_vd( x, 1, 0 ), (double)x1, (double)x0 ) );
    FD_TEST( vd_test( vu_to_vd( x, 1, 1 ), (double)x1, (double)x1 ) );
    FD_TEST( vd_test( vu_to_vd( x, 1, 2 ), (double)x1, (double)x2 ) );
    FD_TEST( vd_test( vu_to_vd( x, 1, 3 ), (double)x1, (double)x3 ) );
    FD_TEST( vd_test( vu_to_vd( x, 2, 0 ), (double)x2, (double)x0 ) );
    FD_TEST( vd_test( vu_to_vd( x, 2, 1 ), (double)x2, (double)x1 ) );
    FD_TEST( vd_test( vu_to_vd( x, 2, 2 ), (double)x2, (double)x2 ) );
    FD_TEST( vd_test( vu_to_vd( x, 2, 3 ), (double)x2, (double)x3 ) );
    FD_TEST( vd_test( vu_to_vd( x, 3, 0 ), (double)x3, (double)x0 ) );
    FD_TEST( vd_test( vu_to_vd( x, 3, 1 ), (double)x3, (double)x1 ) );
    FD_TEST( vd_test( vu_to_vd( x, 3, 2 ), (double)x3, (double)x2 ) );
    FD_TEST( vd_test( vu_to_vd( x, 3, 3 ), (double)x3, (double)x3 ) );

    FD_TEST( vl_test( vu_to_vl( x, 0, 0 ), (long)x0, (long)x0 ) );
    FD_TEST( vl_test( vu_to_vl( x, 0, 1 ), (long)x0, (long)x1 ) );
    FD_TEST( vl_test( vu_to_vl( x, 0, 2 ), (long)x0, (long)x2 ) );
    FD_TEST( vl_test( vu_to_vl( x, 0, 3 ), (long)x0, (long)x3 ) );
    FD_TEST( vl_test( vu_to_vl( x, 1, 0 ), (long)x1, (long)x0 ) );
    FD_TEST( vl_test( vu_to_vl( x, 1, 1 ), (long)x1, (long)x1 ) );
    FD_TEST( vl_test( vu_to_vl( x, 1, 2 ), (long)x1, (long)x2 ) );
    FD_TEST( vl_test( vu_to_vl( x, 1, 3 ), (long)x1, (long)x3 ) );
    FD_TEST( vl_test( vu_to_vl( x, 2, 0 ), (long)x2, (long)x0 ) );
    FD_TEST( vl_test( vu_to_vl( x, 2, 1 ), (long)x2, (long)x1 ) );
    FD_TEST( vl_test( vu_to_vl( x, 2, 2 ), (long)x2, (long)x2 ) );
    FD_TEST( vl_test( vu_to_vl( x, 2, 3 ), (long)x2, (long)x3 ) );
    FD_TEST( vl_test( vu_to_vl( x, 3, 0 ), (long)x3, (long)x0 ) );
    FD_TEST( vl_test( vu_to_vl( x, 3, 1 ), (long)x3, (long)x1 ) );
    FD_TEST( vl_test( vu_to_vl( x, 3, 2 ), (long)x3, (long)x2 ) );
    FD_TEST( vl_test( vu_to_vl( x, 3, 3 ), (long)x3, (long)x3 ) );

    FD_TEST( vv_test( vu_to_vv( x, 0, 0 ), (ulong)x0, (ulong)x0 ) );
    FD_TEST( vv_test( vu_to_vv( x, 0, 1 ), (ulong)x0, (ulong)x1 ) );
    FD_TEST( vv_test( vu_to_vv( x, 0, 2 ), (ulong)x0, (ulong)x2 ) );
    FD_TEST( vv_test( vu_to_vv( x, 0, 3 ), (ulong)x0, (ulong)x3 ) );
    FD_TEST( vv_test( vu_to_vv( x, 1, 0 ), (ulong)x1, (ulong)x0 ) );
    FD_TEST( vv_test( vu_to_vv( x, 1, 1 ), (ulong)x1, (ulong)x1 ) );
    FD_TEST( vv_test( vu_to_vv( x, 1, 2 ), (ulong)x1, (ulong)x2 ) );
    FD_TEST( vv_test( vu_to_vv( x, 1, 3 ), (ulong)x1, (ulong)x3 ) );
    FD_TEST( vv_test( vu_to_vv( x, 2, 0 ), (ulong)x2, (ulong)x0 ) );
    FD_TEST( vv_test( vu_to_vv( x, 2, 1 ), (ulong)x2, (ulong)x1 ) );
    FD_TEST( vv_test( vu_to_vv( x, 2, 2 ), (ulong)x2, (ulong)x2 ) );
    FD_TEST( vv_test( vu_to_vv( x, 2, 3 ), (ulong)x2, (ulong)x3 ) );
    FD_TEST( vv_test( vu_to_vv( x, 3, 0 ), (ulong)x3, (ulong)x0 ) );
    FD_TEST( vv_test( vu_to_vv( x, 3, 1 ), (ulong)x3, (ulong)x1 ) );
    FD_TEST( vv_test( vu_to_vv( x, 3, 2 ), (ulong)x3, (ulong)x2 ) );
    FD_TEST( vv_test( vu_to_vv( x, 3, 3 ), (ulong)x3, (ulong)x3 ) );

    /* Reduction operations */

    FD_TEST( !vc_any( vu_ne( vu_sum_all( x ), vu_bcast( x0 + x1 + x2 + x3 ) ) ) );
    FD_TEST( !vc_any( vu_ne( vu_min_all( x ), vu_bcast( fd_uint_min( fd_uint_min( x0, x1 ), fd_uint_min( x2, x3 ) ) ) ) ) );
    FD_TEST( !vc_any( vu_ne( vu_max_all( x ), vu_bcast( fd_uint_max( fd_uint_max( x0, x1 ), fd_uint_max( x2, x3 ) ) ) ) ) );

    /* Misc operations */

    /* FIXME: test with more general cases */
    vu_t m0; vu_t m1; vu_t m2; vu_t m3;
    vu_transpose_4x4( vu_bcast( x0 ), vu_bcast( x1 ), vu_bcast( x2 ), vu_bcast( x3 ), m0, m1, m2, m3 );
    vu_t mm = vu( x0, x1, x2, x3 );
    FD_TEST( vc_all( vc_and( vc_and( vu_eq( m0, mm ), vu_eq( m1, mm ) ), vc_and( vu_eq( m2, mm ), vu_eq( m3, mm ) ) ) ) );
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
