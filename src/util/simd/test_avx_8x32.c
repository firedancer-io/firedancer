#include "../fd_util.h"
#include "fd_avx.h"
#include <math.h>

/* From test_avx_common.c */

int wc_test( wc_t c, int    c0, int    c1, int    c2, int    c3, int    c4, int    c5, int    c6, int    c7 );
int wf_test( wf_t f, float  f0, float  f1, float  f2, float  f3, float  f4, float  f5, float  f6, float  f7 );
int wi_test( wi_t i, int    i0, int    i1, int    i2, int    i3, int    i4, int    i5, int    i6, int    i7 );
int wu_test( wu_t u, uint   u0, uint   u1, uint   u2, uint   u3, uint   u4, uint   u5, uint   u6, uint   u7 );
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

  /* WC tests */

  FD_TEST( wc_test( wc_false(), 0, 0, 0, 0, 0, 0, 0, 0 ) );
  FD_TEST( wc_test( wc_true(),  1, 1, 1, 1, 1, 1, 1, 1 ) );

  for( int b=0; b<255; b++ ) {
    int c0 = (b>>0) & 1; int c1 = (b>>1) & 1; int c2 = (b>>2) & 1; int c3 = (b>>3) & 1;
    int c4 = (b>>4) & 1; int c5 = (b>>5) & 1; int c6 = (b>>6) & 1; int c7 = (b>>7) & 1;
    wc_t c = wc( c0, c1, c2, c3, c4, c5, c6, c7 );

    FD_TEST( wc_test( c, c0, c1, c2, c3, c4, c5, c6, c7 ) );

    /* Constructors */

    FD_TEST( wc_test( wc_bcast( c0 ), c0, c0, c0, c0, c0, c0, c0, c0 ) );

    FD_TEST( wc_test( wc_bcast_pair( c0, c1 ), c0, c1, c0, c1, c0, c1, c0, c1 ) );
    FD_TEST( wc_test( wc_bcast_lohi( c0, c1 ), c0, c0, c0, c0, c1, c1, c1, c1 ) );

    FD_TEST( wc_test( wc_bcast_quad( c0, c1, c2, c3 ), c0, c1, c2, c3, c0, c1, c2, c3 ) );
    FD_TEST( wc_test( wc_bcast_wide( c0, c1, c2, c3 ), c0, c0, c1, c1, c2, c2, c3, c3 ) );

    FD_TEST( wc_test( wc_bcast_even(    c ), c0, c0, c2, c2, c4, c4, c6, c6 ) );
    FD_TEST( wc_test( wc_bcast_odd(     c ), c1, c1, c3, c3, c5, c5, c7, c7 ) );
    FD_TEST( wc_test( wc_exch_adj(      c ), c1, c0, c3, c2, c5, c4, c7, c6 ) );
    FD_TEST( wc_test( wc_exch_adj_pair( c ), c2, c3, c0, c1, c6, c7, c4, c5 ) );
    FD_TEST( wc_test( wc_exch_adj_quad( c ), c4, c5, c6, c7, c0, c1, c2, c3 ) );

    /* Binary, logical and conditional operations (more below) */

    FD_TEST( wc_test( wc_not( c ), !c0, !c1, !c2, !c3, !c4, !c5, !c6, !c7 ) );

    FD_TEST( wc_test( wc_lnot( c ),     !c0,  !c1,  !c2,  !c3,  !c4,  !c5,  !c6,  !c7 ) );
    FD_TEST( wc_test( wc_lnotnot( c ), !!c0, !!c1, !!c2, !!c3, !!c4, !!c5, !!c6, !!c7 ) );

    /* Conversion operations */

    FD_TEST( wi_test( wc_to_wi( c ), c0, c1, c2, c3, c4, c5, c6, c7 ) );

    FD_TEST( wu_test( wc_to_wu( c ), (uint)c0, (uint)c1, (uint)c2, (uint)c3, (uint)c4, (uint)c5, (uint)c6, (uint)c7 ) );

    FD_TEST( wf_test( wc_to_wf( c ), (float)c0, (float)c1, (float)c2, (float)c3, (float)c4, (float)c5, (float)c6, (float)c7 ) );

    FD_TEST( wd_test( wc_to_wd( wc_bcast_wide( c0,c1,c2,c3 ) ), (double)c0, (double)c1, (double)c2,( double)c3 ) );

    FD_TEST( wl_test( wc_to_wl( wc_bcast_wide( c0,c1,c2,c3 ) ), (long)c0, (long)c1, (long)c2, (long)c3 ) );

    FD_TEST( wv_test( wc_to_wv( wc_bcast_wide( c0,c1,c2,c3 ) ), (ulong)c0, (ulong)c1, (ulong)c2, (ulong)c3 ) );

    /* Reduction operations */

    FD_TEST( wc_any(c) == (c0 | c1 | c2 | c3 | c4 | c5 | c6 | c7) );
    FD_TEST( wc_all(c) == (c0 & c1 & c2 & c3 & c4 & c5 & c6 & c7) );

    /* Misc operations */

    wc_t cl = wc_expand( c, 0 );
    wc_t ch = wc_expand( c, 1 );
    FD_TEST( wc_test( cl, c0,c0, c1,c1, c2,c2, c3,c3 ) );
    FD_TEST( wc_test( ch, c4,c4, c5,c5, c6,c6, c7,c7 ) );
    FD_TEST( wc_test( wc_narrow(cl,ch), c0, c1, c2, c3, c4, c5, c6, c7 ) );

    /* FIXME: test with more general cases */
    wc_t m0; wc_t m1; wc_t m2; wc_t m3; wc_t m4; wc_t m5; wc_t m6; wc_t m7;
    wc_transpose_8x8( wc_bcast( c0 ), wc_bcast( c1 ), wc_bcast( c2 ), wc_bcast( c3 ),
                      wc_bcast( c4 ), wc_bcast( c5 ), wc_bcast( c6 ), wc_bcast( c7 ), m0, m1, m2, m3, m4, m5, m6, m7 );
    wc_t mm = wc( c0, c1, c2, c3, c4, c5, c6, c7 );
    FD_TEST( wc_all( wc_and( wc_and( wc_and( wc_eq( m0, mm ), wc_eq( m1, mm ) ), wc_and( wc_eq( m2, mm ), wc_eq( m3, mm ) ) ),
                             wc_and( wc_and( wc_eq( m4, mm ), wc_eq( m5, mm ) ), wc_and( wc_eq( m6, mm ), wc_eq( m7, mm ) ) ) ) ) );
  }

  for( int x=0; x<256; x++ ) {
    for( int y=0; y<256; y++ ) {
      wc_t vx = wc_unpack( x );
      wc_t vy = wc_unpack( y );

      FD_TEST( wc_pack( wc_and(    vx, vy ) ) == ((  x &  y )&0xff) );
      FD_TEST( wc_pack( wc_or(     vx, vy ) ) == ((  x |  y )&0xff) );
      FD_TEST( wc_pack( wc_xor(    vx, vy ) ) == ((  x ^  y )&0xff) );
      FD_TEST( wc_pack( wc_andnot( vx, vy ) ) == (((~x)&  y )&0xff) );

      FD_TEST( wc_pack( wc_eq(     vx, vy ) ) == ((~(x ^  y))&0xff) );
      FD_TEST( wc_pack( wc_gt(     vx, vy ) ) == ((  x &(~y))&0xff) );
      FD_TEST( wc_pack( wc_lt(     vx, vy ) ) == (((~x)&  y )&0xff) );
      FD_TEST( wc_pack( wc_ne(     vx, vy ) ) == ((  x ^  y )&0xff) );
      FD_TEST( wc_pack( wc_ge(     vx, vy ) ) == ((  x |(~y))&0xff) );
      FD_TEST( wc_pack( wc_le(     vx, vy ) ) == (((~x)|  y )&0xff) );
    }
  }

  for( int x=0; x<256; x++ )
    for( int y=0; y<256; y++ )
      for( int z=0; z<256; z++ )
        FD_TEST( wc_pack( wc_if( wc_unpack(x), wc_unpack(y), wc_unpack(z) ) ) == (((x&y)|((~x)&z))&0xff) );

  /* WF tests */

  FD_TEST( wf_test( wf_zero(), 0.f, 0.f, 0.f, 0.f, 0.f, 0.f, 0.f, 0.f ) );
  FD_TEST( wf_test( wf_one(),  1.f, 1.f, 1.f, 1.f, 1.f, 1.f, 1.f, 1.f ) );

  for( int i=0; i<65536; i++ ) {
    float x0 = frand(); float x1 = frand(); float x2 = frand(); float x3 = frand();
    float x4 = frand(); float x5 = frand(); float x6 = frand(); float x7 = frand(); wf_t x = wf( x0, x1, x2, x3, x4, x5, x6, x7 );

    float y0 = frand(); float y1 = frand(); float y2 = frand(); float y3 = frand();
    float y4 = frand(); float y5 = frand(); float y6 = frand(); float y7 = frand(); wf_t y = wf( y0, y1, y2, y3, y4, y5, y6, y7 );

    float z0 = frand(); float z1 = frand(); float z2 = frand(); float z3 = frand();
    float z4 = frand(); float z5 = frand(); float z6 = frand(); float z7 = frand(); wf_t z = wf( z0, z1, z2, z3, z4, z5, z6, z7 );

    int c0 = crand(); int c1 = crand(); int c2 = crand(); int c3 = crand();
    int c4 = crand(); int c5 = crand(); int c6 = crand(); int c7 = crand(); wc_t c = wc( c0, c1, c2, c3, c4, c5, c6, c7 );

    /* Constructors */

    FD_TEST( wf_test( x, x0, x1, x2, x3, x4, x5, x6, x7 ) );

    FD_TEST( wf_test( wf_bcast( x0 ), x0, x0, x0, x0, x0, x0, x0, x0 ) );

    FD_TEST( wf_test( wf_bcast_pair( x0, x1 ), x0, x1, x0, x1, x0, x1, x0, x1 ) );
    FD_TEST( wf_test( wf_bcast_lohi( x0, x1 ), x0, x0, x0, x0, x1, x1, x1, x1 ) );

    FD_TEST( wf_test( wf_bcast_quad( x0, x1, x2, x3 ), x0, x1, x2, x3, x0, x1, x2, x3 ) );
    FD_TEST( wf_test( wf_bcast_wide( x0, x1, x2, x3 ), x0, x0, x1, x1, x2, x2, x3, x3 ) );

    FD_TEST( wf_test( wf_bcast_even(    x ), x0, x0, x2, x2, x4, x4, x6, x6 ) );
    FD_TEST( wf_test( wf_bcast_odd(     x ), x1, x1, x3, x3, x5, x5, x7, x7 ) );
    FD_TEST( wf_test( wf_exch_adj(      x ), x1, x0, x3, x2, x5, x4, x7, x6 ) );
    FD_TEST( wf_test( wf_exch_adj_pair( x ), x2, x3, x0, x1, x6, x7, x4, x5 ) );
    FD_TEST( wf_test( wf_exch_adj_quad( x ), x4, x5, x6, x7, x0, x1, x2, x3 ) );

    /* Arithmetic operations */

    FD_TEST( wf_test( wf_neg(    x ),                     -x0,             -x1,             -x2,             -x3,
                                                          -x4,             -x5,             -x6,             -x7  ) );
    FD_TEST( wf_test( wf_sign(   x ),         x0<0.f?-1.f:1.f, x1<0.f?-1.f:1.f, x2<0.f?-1.f:1.f, x3<0.f?-1.f:1.f,
                                              x4<0.f?-1.f:1.f, x5<0.f?-1.f:1.f, x6<0.f?-1.f:1.f, x7<0.f?-1.f:1.f ) );
    FD_TEST( wf_test( wf_abs(    x ),               fabsf(x0),       fabsf(x1),       fabsf(x2),       fabsf(x3),
                                                    fabsf(x4),       fabsf(x5),       fabsf(x6),       fabsf(x7) ) );
    FD_TEST( wf_test( wf_negabs( x ),              -fabsf(x0),      -fabsf(x1),      -fabsf(x2),      -fabsf(x3),
                                                   -fabsf(x4),      -fabsf(x5),      -fabsf(x6),      -fabsf(x7) ) );
    FD_TEST( wf_test( wf_ceil(   x ),               ceilf(x0),       ceilf(x1),       ceilf(x2),       ceilf(x3),
                                                    ceilf(x4),       ceilf(x5),       ceilf(x6),       ceilf(x7) ) );
    FD_TEST( wf_test( wf_floor(  x ),              floorf(x0),      floorf(x1),      floorf(x2),      floorf(x3),
                                                   floorf(x4),      floorf(x5),      floorf(x6),      floorf(x7) ) );
    FD_TEST( wf_test( wf_rint(   x ),               rintf(x0),       rintf(x1),       rintf(x2),       rintf(x3),
                                                    rintf(x4),       rintf(x5),       rintf(x6),       rintf(x7) ) );
    FD_TEST( wf_test( wf_trunc(  x ),              truncf(x0),      truncf(x1),      truncf(x2),      truncf(x3),
                                                   truncf(x4),      truncf(x5),      truncf(x6),      truncf(x7) ) );
    FD_TEST( wf_test( wf_sqrt( wf_mul(x,x) ),       fabsf(x0),       fabsf(x1),       fabsf(x2),       fabsf(x3),
                                                    fabsf(x4),       fabsf(x5),       fabsf(x6),       fabsf(x7) ) );

    wf_t expected;

    expected = wf( 1.f/sqrtf(x0+4.f), 1.f/sqrtf(x1+4.f), 1.f/sqrtf(x2+4.f), 1.f/sqrtf(x3+4.f),
                   1.f/sqrtf(x4+4.f), 1.f/sqrtf(x5+4.f), 1.f/sqrtf(x6+4.f), 1.f/sqrtf(x7+4.f) );
    FD_TEST( !wc_any( wf_gt( wf_abs( wf_div( wf_sub( wf_rsqrt_fast( wf_add( x, wf_bcast(4.f) ) ), expected ), expected ) ),
                             wf_bcast( 1.f/1024.f ) ) ) );

    expected = wf( 1.f/(x0+4.f), 1.f/(x1+4.f), 1.f/(x2+4.f), 1.f/(x3+4.f),
                   1.f/(x4+4.f), 1.f/(x5+4.f), 1.f/(x6+4.f), 1.f/(x7+4.f) );
    FD_TEST( !wc_any( wf_gt( wf_abs( wf_div( wf_sub( wf_rcp_fast( wf_add( x, wf_bcast(4.f) ) ), expected ), expected ) ),
                             wf_bcast( 1.f/1024.f ) ) ) );

    FD_TEST( wf_test( wf_add(      x, y ), x0+y0, x1+y1, x2+y2, x3+y3, x4+y4, x5+y5, x6+y6, x7+y7 ) );
    FD_TEST( wf_test( wf_sub(      x, y ), x0-y0, x1-y1, x2-y2, x3-y3, x4-y4, x5-y5, x6-y6, x7-y7 ) );
    FD_TEST( wf_test( wf_mul(      x, y ), x0*y0, x1*y1, x2*y2, x3*y3, x4*y4, x5*y5, x6*y6, x7*y7 ) );
    FD_TEST( wf_test( wf_div( x, wf_add( y, wf_bcast( 4.f ) ) ), x0/(y0+4.f), x1/(y1+4.f), x2/(y2+4.f), x3/(y3+4.f),
                                                                 x4/(y4+4.f), x5/(y5+4.f), x6/(y6+4.f), x7/(y7+4.f) ) );
    FD_TEST( wf_test( wf_min(      x, y ), fminf(x0,y0), fminf(x1,y1), fminf(x2,y2), fminf(x3,y3),
                                           fminf(x4,y4), fminf(x5,y5), fminf(x6,y6), fminf(x7,y7) ) );
    FD_TEST( wf_test( wf_max(      x, y ), fmaxf(x0,y0), fmaxf(x1,y1), fmaxf(x2,y2), fmaxf(x3,y3),
                                           fmaxf(x4,y4), fmaxf(x5,y5), fmaxf(x6,y6), fmaxf(x7,y7) ) );
    FD_TEST( wf_test( wf_copysign( x, y ), copysignf(x0,y0), copysignf(x1,y1), copysignf(x2,y2), copysignf(x3,y3),
                                           copysignf(x4,y4), copysignf(x5,y5), copysignf(x6,y6), copysignf(x7,y7) ) );
    FD_TEST( wf_test( wf_flipsign( x, y ), y0<0.f?-x0:x0, y1<0.f?-x1:x1, y2<0.f?-x2:x2, y3<0.f?-x3:x3,
                                           y4<0.f?-x4:x4, y5<0.f?-x5:x5, y6<0.f?-x6:x6, y7<0.f?-x7:x7 ) );

    FD_TEST( wf_test( wf_fma(  x, y, z ),  x0*y0+z0,  x1*y1+z1,  x2*y2+z2,  x3*y3+z3,  x4*y4+z4,  x5*y5+z5,  x6*y6+z6,  x7*y7+z7 ) );
    FD_TEST( wf_test( wf_fms(  x, y, z ),  x0*y0-z0,  x1*y1-z1,  x2*y2-z2,  x3*y3-z3,  x4*y4-z4,  x5*y5-z5,  x6*y6-z6,  x7*y7-z7 ) );
    FD_TEST( wf_test( wf_fnma( x, y, z ), -x0*y0+z0, -x1*y1+z1, -x2*y2+z2, -x3*y3+z3, -x4*y4+z4, -x5*y5+z5, -x6*y6+z6, -x7*y7+z7 ) );

    /* Logical operations */

    FD_TEST( wc_test( wf_lnot(    x ),   x0==0.f,    x1==0.f,    x2==0.f,    x3==0.f,    x4==0.f,    x5==0.f,    x6==0.f,    x7==0.f  ) ); /* clang makes babies cry */
    FD_TEST( wc_test( wf_lnotnot( x ), !(x0==0.f), !(x1==0.f), !(x2==0.f), !(x3==0.f), !(x4==0.f), !(x5==0.f), !(x6==0.f), !(x7==0.f) ) ); /* floating point too */
    FD_TEST( wc_test( wf_signbit( x ), signbit(x0), signbit(x1), signbit(x2), signbit(x3),
                                       signbit(x4), signbit(x5), signbit(x6), signbit(x7) ) );

    FD_TEST( wc_test( wf_eq( x, y ), x0==y0, x1==y1, x2==y2, x3==y3, x4==y4, x5==y5, x6==y6, x7==y7 ) );
    FD_TEST( wc_test( wf_gt( x, y ), x0> y0, x1> y1, x2> y2, x3> y3, x4> y4, x5> y5, x6> y6, x7> y7 ) );
    FD_TEST( wc_test( wf_lt( x, y ), x0< y0, x1< y1, x2< y2, x3< y3, x4< y4, x5< y5, x6< y6, x7< y7 ) );
    FD_TEST( wc_test( wf_ne( x, y ), x0!=y0, x1!=y1, x2!=y2, x3!=y3, x4!=y4, x5!=y5, x6!=y6, x7!=y7 ) );
    FD_TEST( wc_test( wf_ge( x, y ), x0>=y0, x1>=y1, x2>=y2, x3>=y3, x4>=y4, x5>=y5, x6>=y6, x7>=y7 ) );
    FD_TEST( wc_test( wf_le( x, y ), x0<=y0, x1<=y1, x2<=y2, x3<=y3, x4<=y4, x5<=y5, x6<=y6, x7<=y7 ) );

    FD_TEST( wf_test( wf_czero(    c, x ), c0?0.f:x0, c1?0.f:x1, c2?0.f:x2, c3?0.f:x3,
                                           c4?0.f:x4, c5?0.f:x5, c6?0.f:x6, c7?0.f:x7 ) );
    FD_TEST( wf_test( wf_notczero( c, x ), c0?x0:0.f, c1?x1:0.f, c2?x2:0.f, c3?x3:0.f,
                                           c4?x4:0.f, c5?x5:0.f, c6?x6:0.f, c7?x7:0.f ) );

    FD_TEST( wf_test( wf_if( c, x, y ), c0?x0:y0, c1?x1:y1, c2?x2:y2, c3?x3:y3, c4?x4:y4, c5?x5:y5, c6?x6:y6, c7?x7:y7 ) );

    /* Conversion operations */
    /* FIXME: TEST LARGE MAG CONVERSION */

    FD_TEST( wc_test( wf_to_wc( x ), !(x0==0.f), !(x1==0.f), !(x2==0.f), !(x3==0.f), !(x4==0.f), !(x5==0.f), !(x6==0.f), !(x7==0.f) ) ); /* see wf_lnotnot */

    FD_TEST( wi_test( wf_to_wi( x ), (int)x0, (int)x1, (int)x2, (int)x3, (int)x4, (int)x5, (int)x6, (int)x7 ) );
    FD_TEST( wi_test( wf_to_wi_fast( x ), (int)rintf(x0), (int)rintf(x1), (int)rintf(x2), (int)rintf(x3),
                                          (int)rintf(x4), (int)rintf(x5), (int)rintf(x6), (int)rintf(x7)) );

    /* The behaviour when converting from negative float to uint is highly
       dependent on the compiler version and the flags used ( e.g. gcc 8.5
       vs 9.3 with -march=native ).  Refer also to wf_to_wu_fast.  In order
       to make the test portable, negative values need to be excluded. */
    FD_TEST( wu_test( wf_to_wu( wf_abs( x ) ), (uint)fabsf(x0), (uint)fabsf(x1), (uint)fabsf(x2), (uint)fabsf(x3),
                                               (uint)fabsf(x4), (uint)fabsf(x5), (uint)fabsf(x6), (uint)fabsf(x7) ) );
    FD_TEST( wu_test( wf_to_wu_fast( wf_abs( x ) ), (uint)rintf(fabsf(x0)), (uint)rintf(fabsf(x1)), (uint)rintf(fabsf(x2)), (uint)rintf(fabsf(x3)),
                                                    (uint)rintf(fabsf(x4)), (uint)rintf(fabsf(x5)), (uint)rintf(fabsf(x6)), (uint)rintf(fabsf(x7))) );

    FD_TEST( wd_test( wf_to_wd( x, 0 ), (double)x0, (double)x1, (double)x2, (double)x3 ) );
    FD_TEST( wd_test( wf_to_wd( x, 1 ), (double)x4, (double)x5, (double)x6, (double)x7 ) );

    FD_TEST( wl_test( wf_to_wl( x, 0 ), (long)x0, (long)x1, (long)x2, (long)x3 ) );
    FD_TEST( wl_test( wf_to_wl( x, 1 ), (long)x4, (long)x5, (long)x6, (long)x7 ) );

    FD_TEST( wv_test( wf_to_wv( x, 0 ), (ulong)x0, (ulong)x1, (ulong)x2, (ulong)x3 ) );
    FD_TEST( wv_test( wf_to_wv( x, 1 ), (ulong)x4, (ulong)x5, (ulong)x6, (ulong)x7 ) );

    /* Reduction operations */

    FD_TEST( !wc_any( wf_ne( wf_sum_all( x ), wf_bcast( x0+x1+x2+x3+x4+x5+x6+x7 ) ) ) );
    FD_TEST( !wc_any( wf_ne( wf_min_all( x ), wf_bcast( fminf( fminf( fminf( x0, x1 ), fminf( x2, x3 ) ),
                                                               fminf( fminf( x4, x5 ), fminf( x6, x7 ) ) ) ) ) ) );
    FD_TEST( !wc_any( wf_ne( wf_max_all( x ), wf_bcast( fmaxf( fmaxf( fmaxf( x0, x1 ), fmaxf( x2, x3 ) ),
                                                               fmaxf( fmaxf( x4, x5 ), fmaxf( x6, x7 ) ) ) ) ) ) );

    /* Misc operations */

    /* FIXME: test with more general cases */
    wf_t m0; wf_t m1; wf_t m2; wf_t m3; wf_t m4; wf_t m5; wf_t m6; wf_t m7;
    wf_transpose_8x8( wf_bcast( x0 ), wf_bcast( x1 ), wf_bcast( x2 ), wf_bcast( x3 ),
                      wf_bcast( x4 ), wf_bcast( x5 ), wf_bcast( x6 ), wf_bcast( x7 ), m0, m1, m2, m3, m4, m5, m6, m7 );
    wf_t mm = wf( x0, x1, x2, x3, x4, x5, x6, x7 );
    FD_TEST( wc_all( wc_and( wc_and( wc_and( wf_eq( m0, mm ), wf_eq( m1, mm ) ), wc_and( wf_eq( m2, mm ), wf_eq( m3, mm ) ) ),
                             wc_and( wc_and( wf_eq( m4, mm ), wf_eq( m5, mm ) ), wc_and( wf_eq( m6, mm ), wf_eq( m7, mm ) ) ) ) ) );
  }

  /* WI tests */

  FD_TEST( wi_test( wi_zero(), 0, 0, 0, 0, 0, 0, 0, 0 ) );
  FD_TEST( wi_test( wi_one(),  1, 1, 1, 1, 1, 1, 1, 1 ) );

  for( int i=0; i<65536; i++ ) {
    int x0 = irand(); int x1 = irand(); int x2 = irand(); int x3 = irand();
    int x4 = irand(); int x5 = irand(); int x6 = irand(); int x7 = irand(); wi_t x = wi( x0, x1, x2, x3, x4, x5, x6, x7 );

    int y0 = irand(); int y1 = irand(); int y2 = irand(); int y3 = irand();
    int y4 = irand(); int y5 = irand(); int y6 = irand(); int y7 = irand(); wi_t y = wi( y0, y1, y2, y3, y4, y5, y6, y7 );

    int c0 = crand(); int c1 = crand(); int c2 = crand(); int c3 = crand();
    int c4 = crand(); int c5 = crand(); int c6 = crand(); int c7 = crand(); wc_t c = wc( c0, c1, c2, c3, c4, c5, c6, c7 );

    /* Constructors */

    FD_TEST( wi_test( x, x0, x1, x2, x3, x4, x5, x6, x7 ) );

    FD_TEST( wi_test( wi_bcast( x0 ), x0, x0, x0, x0, x0, x0, x0, x0 ) );

    FD_TEST( wi_test( wi_bcast_pair( x0, x1 ), x0, x1, x0, x1, x0, x1, x0, x1 ) );
    FD_TEST( wi_test( wi_bcast_lohi( x0, x1 ), x0, x0, x0, x0, x1, x1, x1, x1 ) );

    FD_TEST( wi_test( wi_bcast_quad( x0, x1, x2, x3 ), x0, x1, x2, x3, x0, x1, x2, x3 ) );
    FD_TEST( wi_test( wi_bcast_wide( x0, x1, x2, x3 ), x0, x0, x1, x1, x2, x2, x3, x3 ) );

    FD_TEST( wi_test( wi_bcast_even(    x ), x0, x0, x2, x2, x4, x4, x6, x6 ) );
    FD_TEST( wi_test( wi_bcast_odd(     x ), x1, x1, x3, x3, x5, x5, x7, x7 ) );
    FD_TEST( wi_test( wi_exch_adj(      x ), x1, x0, x3, x2, x5, x4, x7, x6 ) );
    FD_TEST( wi_test( wi_exch_adj_pair( x ), x2, x3, x0, x1, x6, x7, x4, x5 ) );
    FD_TEST( wi_test( wi_exch_adj_quad( x ), x4, x5, x6, x7, x0, x1, x2, x3 ) );

    /* Bit operations */

    FD_TEST( wi_test( wi_not( x ), ~x0, ~x1, ~x2, ~x3, ~x4, ~x5, ~x6, ~x7  ) );

#   define SHL(x,n)  ((int)(((uint)(x))<<(n)))
#   define SHRU(x,n) ((int)(((uint)(x))>>(n)))
#   define ROL(x,n)  fd_int_rotate_left ((x),(n))
#   define ROR(x,n)  fd_int_rotate_right((x),(n))

#   define _(n)                                                                                    \
    FD_TEST( wi_test( wi_shl(  x, n ), SHL( x0,n), SHL (x1,n), SHL( x2,n), SHL( x3,n),             \
                                       SHL( x4,n), SHL( x5,n), SHL( x6,n), SHL( x7,n) ) );         \
    FD_TEST( wi_test( wi_shr(  x, n ), x0>>n, x1>>n, x2>>n, x3>>n, x4>>n, x5>>n, x6>>n, x7>>n ) ); \
    FD_TEST( wi_test( wi_shru( x, n ), SHRU(x0,n), SHRU(x1,n), SHRU(x2,n), SHRU(x3,n),             \
                                       SHRU(x4,n), SHRU(x5,n), SHRU(x6,n), SHRU(x7,n) ) );         \
    FD_TEST( wi_test( wi_rol(  x, n ), ROL( x0,n), ROL( x1,n), ROL( x2,n), ROL( x3,n),             \
                                       ROL( x4,n), ROL( x5,n), ROL( x6,n), ROL( x7,n) ) );         \
    FD_TEST( wi_test( wi_ror(  x, n ), ROR( x0,n), ROR( x1,n), ROR( x2,n), ROR( x3,n),             \
                                       ROR( x4,n), ROR( x5,n), ROR( x6,n), ROR( x7,n) ) )
    _( 0); _( 1); _( 2); _( 3); _( 4); _( 5); _( 6); _( 7); _( 8); _( 9); _(10); _(11); _(12); _(13); _(14); _(15);
    _(16); _(17); _(18); _(19); _(20); _(21); _(22); _(23); _(24); _(25); _(26); _(27); _(28); _(29); _(30); _(31);
#   undef _

    for( int n=0; n<32; n++ ) {
      int volatile m[1]; m[0] = n;
      FD_TEST( wi_test( wi_shl_variable(  x, m[0] ), SHL( x0,n), SHL( x1,n), SHL( x2,n), SHL( x3,n),
                                                     SHL( x4,n), SHL( x5,n), SHL( x6,n), SHL( x7,n) ) );
      FD_TEST( wi_test( wi_shr_variable(  x, m[0] ), x0>>n, x1>>n, x2>>n, x3>>n, x4>>n, x5>>n, x6>>n, x7>>n ) );
      FD_TEST( wi_test( wi_shru_variable( x, m[0] ), SHRU(x0,n), SHRU(x1,n), SHRU(x2,n), SHRU(x3,n),
                                                     SHRU(x4,n), SHRU(x5,n), SHRU(x6,n), SHRU(x7,n) ) );
      FD_TEST( wi_test( wi_rol_variable(  x, m[0] ), ROL( x0,n), ROL( x1,n), ROL( x2,n), ROL( x3,n),
                                                     ROL( x4,n), ROL( x5,n), ROL( x6,n), ROL( x7,n) ) );
      FD_TEST( wi_test( wi_ror_variable(  x, m[0] ), ROR( x0,n), ROR( x1,n), ROR( x2,n), ROR( x3,n),
                                                     ROR( x4,n), ROR( x5,n), ROR( x6,n), ROR( x7,n) ) );
    }

#   undef ROR
#   undef ROL
#   undef SHRU
#   undef SHL

    FD_TEST( wi_test( wi_and(    x, y ),   x0 &y0,   x1 &y1,   x2 &y2,   x3 &y3,   x4 &y4,   x5 &y5,   x6 &y6,   x7 &y7 ) );
    FD_TEST( wi_test( wi_andnot( x, y ), (~x0)&y0, (~x1)&y1, (~x2)&y2, (~x3)&y3, (~x4)&y4, (~x5)&y5, (~x6)&y6, (~x7)&y7 ) );
    FD_TEST( wi_test( wi_or(     x, y ),   x0| y0,   x1| y1,   x2| y2,   x3| y3,   x4| y4,   x5| y5,   x6| y6,   x7| y7 ) );
    FD_TEST( wi_test( wi_xor(    x, y ),   x0^ y0,   x1^ y1,   x2^ y2,   x3^ y3,   x4^ y4,   x5^ y5,   x6^ y6,   x7^ y7 ) );

    /* Arithmetic operations */

    FD_TEST( wi_test( wi_neg( x ), -x0, -x1, -x2, -x3, -x4, -x5, -x6, -x7  ) );
    FD_TEST( wi_test( wi_abs( x ), (int)fd_int_abs(x0), (int)fd_int_abs(x1), (int)fd_int_abs(x2), (int)fd_int_abs(x3),
                                   (int)fd_int_abs(x4), (int)fd_int_abs(x5), (int)fd_int_abs(x6), (int)fd_int_abs(x7) ) );

    FD_TEST( wi_test( wi_min( x, y ), fd_int_min(x0,y0), fd_int_min(x1,y1), fd_int_min(x2,y2), fd_int_min(x3,y3),
                                      fd_int_min(x4,y4), fd_int_min(x5,y5), fd_int_min(x6,y6), fd_int_min(x7,y7) ) );
    FD_TEST( wi_test( wi_max( x, y ), fd_int_max(x0,y0), fd_int_max(x1,y1), fd_int_max(x2,y2), fd_int_max(x3,y3),
                                      fd_int_max(x4,y4), fd_int_max(x5,y5), fd_int_max(x6,y6), fd_int_max(x7,y7) ) );
    FD_TEST( wi_test( wi_add( x, y ), x0+y0, x1+y1, x2+y2, x3+y3, x4+y4, x5+y5, x6+y6, x7+y7 ) );
    FD_TEST( wi_test( wi_sub( x, y ), x0-y0, x1-y1, x2-y2, x3-y3, x4-y4, x5-y5, x6-y6, x7-y7 ) );
    FD_TEST( wi_test( wi_mul( x, y ), x0*y0, x1*y1, x2*y2, x3*y3, x4*y4, x5*y5, x6*y6, x7*y7 ) );

    /* Logical operations */

    FD_TEST( wc_test( wi_lnot(    x ),  !x0,  !x1,  !x2,  !x3,  !x4,  !x5,  !x6,  !x7 ) );
    FD_TEST( wc_test( wi_lnotnot( x ), !!x0, !!x1, !!x2, !!x3, !!x4, !!x5, !!x6, !!x7 ) );

    FD_TEST( wc_test( wi_eq( x, y ), x0==y0, x1==y1, x2==y2, x3==y3, x4==y4, x5==y5, x6==y6, x7==y7 ) );
    FD_TEST( wc_test( wi_gt( x, y ), x0> y0, x1> y1, x2> y2, x3> y3, x4> y4, x5> y5, x6> y6, x7> y7 ) );
    FD_TEST( wc_test( wi_lt( x, y ), x0< y0, x1< y1, x2< y2, x3< y3, x4< y4, x5< y5, x6< y6, x7< y7 ) );
    FD_TEST( wc_test( wi_ne( x, y ), x0!=y0, x1!=y1, x2!=y2, x3!=y3, x4!=y4, x5!=y5, x6!=y6, x7!=y7 ) );
    FD_TEST( wc_test( wi_ge( x, y ), x0>=y0, x1>=y1, x2>=y2, x3>=y3, x4>=y4, x5>=y5, x6>=y6, x7>=y7 ) );
    FD_TEST( wc_test( wi_le( x, y ), x0<=y0, x1<=y1, x2<=y2, x3<=y3, x4<=y4, x5<=y5, x6<=y6, x7<=y7 ) );

    FD_TEST( wi_test( wi_czero(    c, x ), c0? 0:x0, c1? 0:x1, c2? 0:x2, c3? 0:x3, c4? 0:x4, c5? 0:x5, c6? 0:x6, c7? 0:x7 ) );
    FD_TEST( wi_test( wi_notczero( c, x ), c0?x0: 0, c1?x1: 0, c2?x2: 0, c3?x3: 0, c4?x4: 0, c5?x5: 0, c6?x6: 0, c7?x7: 0 ) );
    FD_TEST( wi_test( wi_if( c, x, y ),    c0?x0:y0, c1?x1:y1, c2?x2:y2, c3?x3:y3, c4?x4:y4, c5?x5:y5, c6?x6:y6, c7?x7:y7 ) );

    /* Conversion operations */

    FD_TEST( wc_test( wi_to_wc( x ), !!x0, !!x1, !!x2, !!x3, !!x4, !!x5, !!x6, !!x7 ) );

    FD_TEST( wf_test( wi_to_wf( x ), (float)x0, (float)x1, (float)x2, (float)x3, (float)x4, (float)x5, (float)x6, (float)x7 ) );

    FD_TEST( wu_test( wi_to_wu( x ), (uint)x0, (uint)x1, (uint)x2, (uint)x3, (uint)x4, (uint)x5, (uint)x6, (uint)x7 ) );

    FD_TEST( wd_test( wi_to_wd( x, 0 ), (double)x0, (double)x1, (double)x2, (double)x3 ) );
    FD_TEST( wd_test( wi_to_wd( x, 1 ), (double)x4, (double)x5, (double)x6, (double)x7 ) );

    FD_TEST( wl_test( wi_to_wl( x, 0 ), (long)x0, (long)x1, (long)x2, (long)x3 ) );
    FD_TEST( wl_test( wi_to_wl( x, 1 ), (long)x4, (long)x5, (long)x6, (long)x7 ) );

    FD_TEST( wv_test( wi_to_wv( x, 0 ), (ulong)x0, (ulong)x1, (ulong)x2, (ulong)x3 ) );
    FD_TEST( wv_test( wi_to_wv( x, 1 ), (ulong)x4, (ulong)x5, (ulong)x6, (ulong)x7 ) );

    /* Reduction operations */

    FD_TEST( !wc_any( wi_ne( wi_sum_all( x ), wi_bcast( x0 + x1 + x2 + x3 + x4 + x5 + x6 + x7 ) ) ) );
    FD_TEST( !wc_any( wi_ne( wi_min_all( x ), wi_bcast( fd_int_min( fd_int_min( fd_int_min( x0, x1 ), fd_int_min( x2, x3 ) ),
                                                                    fd_int_min( fd_int_min( x4, x5 ), fd_int_min( x6, x7 ) ) ) ) ) ) );
    FD_TEST( !wc_any( wi_ne( wi_max_all( x ), wi_bcast( fd_int_max( fd_int_max( fd_int_max( x0, x1 ), fd_int_max( x2, x3 ) ),
                                                                    fd_int_max( fd_int_max( x4, x5 ), fd_int_max( x6, x7 ) ) ) ) ) ) );

    /* Misc operations */

    /* FIXME: test with more general cases */
    wi_t m0; wi_t m1; wi_t m2; wi_t m3; wi_t m4; wi_t m5; wi_t m6; wi_t m7;
    wi_transpose_8x8( wi_bcast( x0 ), wi_bcast( x1 ), wi_bcast( x2 ), wi_bcast( x3 ),
                      wi_bcast( x4 ), wi_bcast( x5 ), wi_bcast( x6 ), wi_bcast( x7 ), m0, m1, m2, m3, m4, m5, m6, m7 );
    wi_t mm = wi( x0, x1, x2, x3, x4, x5, x6, x7 );
    FD_TEST( wc_all( wc_and( wc_and( wc_and( wi_eq( m0, mm ), wi_eq( m1, mm ) ), wc_and( wi_eq( m2, mm ), wi_eq( m3, mm ) ) ),
                             wc_and( wc_and( wi_eq( m4, mm ), wi_eq( m5, mm ) ), wc_and( wi_eq( m6, mm ), wi_eq( m7, mm ) ) ) ) ) );
  }

  /* WU tests */

  FD_TEST( wu_test( wu_zero(), 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U ) );
  FD_TEST( wu_test( wu_one(),  1U, 1U, 1U, 1U, 1U, 1U, 1U, 1U ) );

  for( int i=0; i<65536; i++ ) {
    uint x0 = urand(); uint x1 = urand(); uint x2 = urand(); uint x3 = urand();
    uint x4 = urand(); uint x5 = urand(); uint x6 = urand(); uint x7 = urand(); wu_t x = wu( x0, x1, x2, x3, x4, x5, x6, x7 );

    uint y0 = urand(); uint y1 = urand(); uint y2 = urand(); uint y3 = urand();
    uint y4 = urand(); uint y5 = urand(); uint y6 = urand(); uint y7 = urand(); wu_t y = wu( y0, y1, y2, y3, y4, y5, y6, y7 );

    int  c0 = crand(); int  c1 = crand(); int  c2 = crand(); int  c3 = crand();
    int  c4 = crand(); int  c5 = crand(); int  c6 = crand(); int  c7 = crand(); wc_t c = wc( c0, c1, c2, c3, c4, c5, c6, c7 );

    /* Constructors */

    FD_TEST( wu_test( x, x0, x1, x2, x3, x4, x5, x6, x7 ) );

    FD_TEST( wu_test( wu_bcast( x0 ), x0, x0, x0, x0, x0, x0, x0, x0 ) );

    FD_TEST( wu_test( wu_bcast_pair( x0, x1 ), x0, x1, x0, x1, x0, x1, x0, x1 ) );
    FD_TEST( wu_test( wu_bcast_lohi( x0, x1 ), x0, x0, x0, x0, x1, x1, x1, x1 ) );

    FD_TEST( wu_test( wu_bcast_quad( x0, x1, x2, x3 ), x0, x1, x2, x3, x0, x1, x2, x3 ) );
    FD_TEST( wu_test( wu_bcast_wide( x0, x1, x2, x3 ), x0, x0, x1, x1, x2, x2, x3, x3 ) );

    FD_TEST( wu_test( wu_bcast_even(    x ), x0, x0, x2, x2, x4, x4, x6, x6 ) );
    FD_TEST( wu_test( wu_bcast_odd(     x ), x1, x1, x3, x3, x5, x5, x7, x7 ) );
    FD_TEST( wu_test( wu_exch_adj(      x ), x1, x0, x3, x2, x5, x4, x7, x6 ) );
    FD_TEST( wu_test( wu_exch_adj_pair( x ), x2, x3, x0, x1, x6, x7, x4, x5 ) );
    FD_TEST( wu_test( wu_exch_adj_quad( x ), x4, x5, x6, x7, x0, x1, x2, x3 ) );

    /* Bit operations */

    FD_TEST( wu_test( wu_not( x ), ~x0, ~x1, ~x2, ~x3, ~x4, ~x5, ~x6, ~x7  ) );

    FD_TEST( wu_test( wu_bswap( x ), fd_uint_bswap( x0 ), fd_uint_bswap( x1 ), fd_uint_bswap( x2 ), fd_uint_bswap( x3 ),
                                     fd_uint_bswap( x4 ), fd_uint_bswap( x5 ), fd_uint_bswap( x6 ), fd_uint_bswap( x7 ) ) );

#   define ROL(x,n) fd_uint_rotate_left ((x),(n))
#   define ROR(x,n) fd_uint_rotate_right((x),(n))

#   define _(n)                                                                                   \
    FD_TEST( wu_test( wu_shl( x, n ), x0<<n, x1<<n, x2<<n, x3<<n, x4<<n, x5<<n, x6<<n, x7<<n ) ); \
    FD_TEST( wu_test( wu_shr( x, n ), x0>>n, x1>>n, x2>>n, x3>>n, x4>>n, x5>>n, x6>>n, x7>>n ) ); \
    FD_TEST( wu_test( wu_rol( x, n ), ROL(x0,n), ROL(x1,n), ROL(x2,n), ROL(x3,n),                 \
                                      ROL(x4,n), ROL(x5,n), ROL(x6,n), ROL(x7,n) ) );             \
    FD_TEST( wu_test( wu_ror( x, n ), ROR(x0,n), ROR(x1,n), ROR(x2,n), ROR(x3,n),                 \
                                      ROR(x4,n), ROR(x5,n), ROR(x6,n), ROR(x7,n) ) )
    _( 0); _( 1); _( 2); _( 3); _( 4); _( 5); _( 6); _( 7); _( 8); _( 9); _(10); _(11); _(12); _(13); _(14); _(15);
    _(16); _(17); _(18); _(19); _(20); _(21); _(22); _(23); _(24); _(25); _(26); _(27); _(28); _(29); _(30); _(31);
#   undef _

    for( int n=0; n<32; n++ ) {
      int volatile m[1]; m[0] = n;
      FD_TEST( wu_test( wu_shl_variable( x, m[0] ), x0<<n, x1<<n, x2<<n, x3<<n, x4<<n, x5<<n, x6<<n, x7<<n ) );
      FD_TEST( wu_test( wu_shr_variable( x, m[0] ), x0>>n, x1>>n, x2>>n, x3>>n, x4>>n, x5>>n, x6>>n, x7>>n ) );
      FD_TEST( wu_test( wu_rol_variable( x, m[0] ), ROL(x0,n), ROL(x1,n), ROL(x2,n), ROL(x3,n),
                                                    ROL(x4,n), ROL(x5,n), ROL(x6,n), ROL(x7,n) ) );
      FD_TEST( wu_test( wu_ror_variable( x, m[0] ), ROR(x0,n), ROR(x1,n), ROR(x2,n), ROR(x3,n),
                                                    ROR(x4,n), ROR(x5,n), ROR(x6,n), ROR(x7,n) ) );
    }

#   undef ROR
#   undef ROL

    FD_TEST( wu_test( wu_and(    x, y ),   x0 &y0,   x1 &y1,   x2 &y2,   x3 &y3,   x4 &y4,   x5 &y5,   x6 &y6,   x7 &y7 ) );
    FD_TEST( wu_test( wu_andnot( x, y ), (~x0)&y0, (~x1)&y1, (~x2)&y2, (~x3)&y3, (~x4)&y4, (~x5)&y5, (~x6)&y6, (~x7)&y7 ) );
    FD_TEST( wu_test( wu_or(     x, y ),   x0| y0,   x1| y1,   x2| y2,   x3| y3,   x4| y4,   x5| y5,   x6| y6,   x7| y7 ) );
    FD_TEST( wu_test( wu_xor(    x, y ),   x0^ y0,   x1^ y1,   x2^ y2,   x3^ y3,   x4^ y4,   x5^ y5,   x6^ y6,   x7^ y7 ) );

    /* Arithmetic operations */

    FD_TEST( wu_test( wu_neg( x ), -x0, -x1, -x2, -x3, -x4, -x5, -x6, -x7  ) );
    FD_TEST( wu_test( wu_abs( x ), fd_uint_abs(x0), fd_uint_abs(x1), fd_uint_abs(x2), fd_uint_abs(x3),
                                   fd_uint_abs(x4), fd_uint_abs(x5), fd_uint_abs(x6), fd_uint_abs(x7) ) );

    FD_TEST( wu_test( wu_min( x, y ), fd_uint_min(x0,y0), fd_uint_min(x1,y1), fd_uint_min(x2,y2), fd_uint_min(x3,y3),
                                      fd_uint_min(x4,y4), fd_uint_min(x5,y5), fd_uint_min(x6,y6), fd_uint_min(x7,y7) ) );
    FD_TEST( wu_test( wu_max( x, y ), fd_uint_max(x0,y0), fd_uint_max(x1,y1), fd_uint_max(x2,y2), fd_uint_max(x3,y3),
                                      fd_uint_max(x4,y4), fd_uint_max(x5,y5), fd_uint_max(x6,y6), fd_uint_max(x7,y7) ) );
    FD_TEST( wu_test( wu_add( x, y ), x0+y0, x1+y1, x2+y2, x3+y3, x4+y4, x5+y5, x6+y6, x7+y7 ) );
    FD_TEST( wu_test( wu_sub( x, y ), x0-y0, x1-y1, x2-y2, x3-y3, x4-y4, x5-y5, x6-y6, x7-y7 ) );
    FD_TEST( wu_test( wu_mul( x, y ), x0*y0, x1*y1, x2*y2, x3*y3, x4*y4, x5*y5, x6*y6, x7*y7 ) );

    /* Logical operations */

    FD_TEST( wc_test( wu_lnot(    x ),  !x0,  !x1,  !x2,  !x3,  !x4,  !x5,  !x6,  !x7 ) );
    FD_TEST( wc_test( wu_lnotnot( x ), !!x0, !!x1, !!x2, !!x3, !!x4, !!x5, !!x6, !!x7 ) );

    FD_TEST( wc_test( wu_eq( x, y ), x0==y0, x1==y1, x2==y2, x3==y3, x4==y4, x5==y5, x6==y6, x7==y7 ) );
    FD_TEST( wc_test( wu_gt( x, y ), x0> y0, x1> y1, x2> y2, x3> y3, x4> y4, x5> y5, x6> y6, x7> y7 ) );
    FD_TEST( wc_test( wu_lt( x, y ), x0< y0, x1< y1, x2< y2, x3< y3, x4< y4, x5< y5, x6< y6, x7< y7 ) );
    FD_TEST( wc_test( wu_ne( x, y ), x0!=y0, x1!=y1, x2!=y2, x3!=y3, x4!=y4, x5!=y5, x6!=y6, x7!=y7 ) );
    FD_TEST( wc_test( wu_ge( x, y ), x0>=y0, x1>=y1, x2>=y2, x3>=y3, x4>=y4, x5>=y5, x6>=y6, x7>=y7 ) );
    FD_TEST( wc_test( wu_le( x, y ), x0<=y0, x1<=y1, x2<=y2, x3<=y3, x4<=y4, x5<=y5, x6<=y6, x7<=y7 ) );

    FD_TEST( wu_test( wu_czero(    c, x ), c0?0U:x0, c1?0U:x1, c2?0U:x2, c3?0U:x3, c4?0U:x4, c5?0U:x5, c6?0U:x6, c7?0U:x7 ) );
    FD_TEST( wu_test( wu_notczero( c, x ), c0?x0:0U, c1?x1:0U, c2?x2:0U, c3?x3:0U, c4?x4:0U, c5?x5:0U, c6?x6:0U, c7?x7:0U ) );
    FD_TEST( wu_test( wu_if( c, x, y ),    c0?x0:y0, c1?x1:y1, c2?x2:y2, c3?x3:y3, c4?x4:y4, c5?x5:y5, c6?x6:y6, c7?x7:y7 ) );

    /* Conversion operations */

    FD_TEST( wc_test( wu_to_wc( x ), !!x0, !!x1, !!x2, !!x3, !!x4, !!x5, !!x6, !!x7 ) );

    FD_TEST( wf_test( wu_to_wf( x ), (float)x0, (float)x1, (float)x2, (float)x3, (float)x4, (float)x5, (float)x6, (float)x7 ) );

    FD_TEST( wi_test( wu_to_wi( x ), (int)x0, (int)x1, (int)x2, (int)x3, (int)x4, (int)x5, (int)x6, (int)x7 ) );

    FD_TEST( wd_test( wu_to_wd( x, 0 ), (double)x0, (double)x1, (double)x2, (double)x3 ) );
    FD_TEST( wd_test( wu_to_wd( x, 1 ), (double)x4, (double)x5, (double)x6, (double)x7 ) );

    FD_TEST( wl_test( wu_to_wl( x, 0 ), (long)x0, (long)x1, (long)x2, (long)x3 ) );
    FD_TEST( wl_test( wu_to_wl( x, 1 ), (long)x4, (long)x5, (long)x6, (long)x7 ) );

    FD_TEST( wv_test( wu_to_wv( x, 0 ), (ulong)x0, (ulong)x1, (ulong)x2, (ulong)x3 ) );
    FD_TEST( wv_test( wu_to_wv( x, 1 ), (ulong)x4, (ulong)x5, (ulong)x6, (ulong)x7 ) );

    /* Reduction operations */

    FD_TEST( !wc_any( wu_ne( wu_sum_all( x ), wu_bcast( x0 + x1 + x2 + x3 + x4 + x5 + x6 + x7 ) ) ) );
    FD_TEST( !wc_any( wu_ne( wu_min_all( x ), wu_bcast( fd_uint_min( fd_uint_min( fd_uint_min( x0, x1 ), fd_uint_min( x2, x3 ) ),
                                                                     fd_uint_min( fd_uint_min( x4, x5 ), fd_uint_min( x6, x7 ) ) ) ) ) ) );
    FD_TEST( !wc_any( wu_ne( wu_max_all( x ), wu_bcast( fd_uint_max( fd_uint_max( fd_uint_max( x0, x1 ), fd_uint_max( x2, x3 ) ),
                                                                     fd_uint_max( fd_uint_max( x4, x5 ), fd_uint_max( x6, x7 ) ) ) ) ) ) );

    /* Misc operations */

    /* FIXME: test with more general cases */
    wu_t m0; wu_t m1; wu_t m2; wu_t m3; wu_t m4; wu_t m5; wu_t m6; wu_t m7;
    wu_transpose_8x8( wu_bcast( x0 ), wu_bcast( x1 ), wu_bcast( x2 ), wu_bcast( x3 ),
                      wu_bcast( x4 ), wu_bcast( x5 ), wu_bcast( x6 ), wu_bcast( x7 ), m0, m1, m2, m3, m4, m5, m6, m7 );
    wu_t mm = wu( x0, x1, x2, x3, x4, x5, x6, x7 );
    FD_TEST( wc_all( wc_and( wc_and( wc_and( wu_eq( m0, mm ), wu_eq( m1, mm ) ), wc_and( wu_eq( m2, mm ), wu_eq( m3, mm ) ) ),
                             wc_and( wc_and( wu_eq( m4, mm ), wu_eq( m5, mm ) ), wc_and( wu_eq( m6, mm ), wu_eq( m7, mm ) ) ) ) ) );
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
