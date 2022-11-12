#include "../fd_util.h"

#if FD_HAS_SSE

#include "fd_sse.h"
#include <math.h>

static int vc_test( vc_t c, int c0, int c1, int c2, int c3 ) {
  c0 = !!c0; c1 = !!c1; c2 = !!c2; c3 = !!c3;
  int volatile _[1];
  int          m[23] V_ATTR;
  vc_t         d;

  fd_memset( m, 0, 23UL*sizeof(int) );

  int b = (c0<<0) | (c1<<1) | (c2<<2) | (c3<<3);
  if( vc_pack( c )!=b ) return 0;
  if( vc_pack( vc_eq( vc_unpack( b ), c ) )!=15 ) return 0;

  if( vc_extract( c, 0 )!=c0 ) return 0;
  if( vc_extract( c, 1 )!=c1 ) return 0;
  if( vc_extract( c, 2 )!=c2 ) return 0;
  if( vc_extract( c, 3 )!=c3 ) return 0;

  _[0] = 0; if( vc_extract_variable( c, _[0] )!=c0 ) return 0;
  _[0] = 1; if( vc_extract_variable( c, _[0] )!=c1 ) return 0;
  _[0] = 2; if( vc_extract_variable( c, _[0] )!=c2 ) return 0;
  _[0] = 3; if( vc_extract_variable( c, _[0] )!=c3 ) return 0;

  vc_st(  m,    c ); /*   Aligned store to aligned   */
  vc_stu( m+ 4, c ); /* Unaligned store to aligned   */
  vc_stu( m+ 9, c ); /* Unaligned store to aligned+1 */
  vc_stu( m+14, c ); /* Unaligned store to aligned+2 */
  vc_stu( m+19, c ); /* Unaligned store to aligned+3 */

  d = vc_ld_fast(  m    ); if( vc_any( vc_ne( c, d ) ) ) return 0;
  d = vc_ldu_fast( m+ 4 ); if( vc_any( vc_ne( c, d ) ) ) return 0;
  d = vc_ldu_fast( m+ 9 ); if( vc_any( vc_ne( c, d ) ) ) return 0;
  d = vc_ldu_fast( m+14 ); if( vc_any( vc_ne( c, d ) ) ) return 0;
  d = vc_ldu_fast( m+19 ); if( vc_any( vc_ne( c, d ) ) ) return 0;

  d = vc_gather_fast( m, vi(9,20,6,17) ); if( vc_any( vc_ne( c, d ) ) ) return 0;

  for( int i=0; i<23; i++ ) m[i] *= (i+1);

  d = vc_ld(  m    ); if( !vc_all( vc_eq( c, d ) ) ) return 0;
  d = vc_ldu( m+ 4 ); if( !vc_all( vc_eq( c, d ) ) ) return 0;
  d = vc_ldu( m+ 9 ); if( !vc_all( vc_eq( c, d ) ) ) return 0;
  d = vc_ldu( m+14 ); if( !vc_all( vc_eq( c, d ) ) ) return 0;
  d = vc_ldu( m+19 ); if( !vc_all( vc_eq( c, d ) ) ) return 0;

  d = vc_gather( m, vi(19,5,16,12) ); if( !vc_all( vc_eq( c, d ) ) ) return 0;

  d = vc_insert( vc_false(),0, c0 );
  d = vc_insert( d,         1, c1 );
  d = vc_insert( d,         2, c2 );
  d = vc_insert( d,         3, c3 ); if( vc_any( vc_ne( c, d ) ) ) return 0;

  _[0] = 0; d = vc_insert_variable( vc_true(),_[0], c0 );
  _[0] = 1; d = vc_insert_variable( d,        _[0], c1 );
  _[0] = 2; d = vc_insert_variable( d,        _[0], c2 );
  _[0] = 3; d = vc_insert_variable( d,        _[0], c3 ); if( vc_any( vc_ne( c, d ) ) ) return 0;

  return 1;
}

static int vf_test( vf_t f, float f0, float f1, float f2, float f3 ) {
  int volatile _[1];
  float        m[23] V_ATTR;
  vf_t         g;

  if( vf_extract( f, 0 )!=f0 ) return 0;
  if( vf_extract( f, 1 )!=f1 ) return 0;
  if( vf_extract( f, 2 )!=f2 ) return 0;
  if( vf_extract( f, 3 )!=f3 ) return 0;

  _[0] = 0; if( vf_extract_variable( f, _[0] )!=f0 ) return 0;
  _[0] = 1; if( vf_extract_variable( f, _[0] )!=f1 ) return 0;
  _[0] = 2; if( vf_extract_variable( f, _[0] )!=f2 ) return 0;
  _[0] = 3; if( vf_extract_variable( f, _[0] )!=f3 ) return 0;

  vf_st(  m,    f ); /*   Aligned store to aligned   */
  vf_stu( m+ 4, f ); /* Unaligned store to aligned   */
  vf_stu( m+ 9, f ); /* Unaligned store to aligned+1 */
  vf_stu( m+14, f ); /* Unaligned store to aligned+2 */
  vf_stu( m+19, f ); /* Unaligned store to aligned+3 */

  g = vf_ld(  m    ); if( vc_pack( vf_eq( f, g ) )!=15 ) return 0;
  g = vf_ldu( m+ 4 ); if( vc_pack( vf_eq( f, g ) )!=15 ) return 0;
  g = vf_ldu( m+ 9 ); if( vc_pack( vf_eq( f, g ) )!=15 ) return 0;
  g = vf_ldu( m+14 ); if( vc_pack( vf_eq( f, g ) )!=15 ) return 0;
  g = vf_ldu( m+19 ); if( vc_pack( vf_eq( f, g ) )!=15 ) return 0;

  g = vf_gather( m, vi(14,5,21,12) ); if( !vc_all( vf_eq( f, g ) ) ) return 0;

  g = vf_insert( vf_zero(),0, f0 );
  g = vf_insert( g,        1, f1 );
  g = vf_insert( g,        2, f2 );
  g = vf_insert( g,        3, f3 ); if( vc_any( vf_ne( f, g ) ) ) return 0;

  _[0] = 0; g = vf_insert_variable( vf_one(),_[0], f0 );
  _[0] = 1; g = vf_insert_variable( g,       _[0], f1 );
  _[0] = 2; g = vf_insert_variable( g,       _[0], f2 );
  _[0] = 3; g = vf_insert_variable( g,       _[0], f3 ); if( vc_any( vf_ne( f, g ) ) ) return 0;

  return 1;
}

static int vi_test( vi_t i, int i0, int i1, int i2, int i3 ) {
  int volatile _[1];
  int          m[23] V_ATTR;
  vi_t         j;

  if( vi_extract( i, 0 )!=i0 ) return 0;
  if( vi_extract( i, 1 )!=i1 ) return 0;
  if( vi_extract( i, 2 )!=i2 ) return 0;
  if( vi_extract( i, 3 )!=i3 ) return 0;

  _[0] = 0; if( vi_extract_variable( i, _[0] )!=i0 ) return 0;
  _[0] = 1; if( vi_extract_variable( i, _[0] )!=i1 ) return 0;
  _[0] = 2; if( vi_extract_variable( i, _[0] )!=i2 ) return 0;
  _[0] = 3; if( vi_extract_variable( i, _[0] )!=i3 ) return 0;

  vi_st(  m,    i ); /*   Aligned store to aligned   */
  vi_stu( m+ 4, i ); /* Unaligned store to aligned   */
  vi_stu( m+ 9, i ); /* Unaligned store to aligned+1 */
  vi_stu( m+14, i ); /* Unaligned store to aligned+2 */
  vi_stu( m+19, i ); /* Unaligned store to aligned+3 */

  j = vi_ld(  m    ); if( vc_pack( vi_eq( i, j ) )!=15 ) return 0;
  j = vi_ldu( m+ 4 ); if( vc_pack( vi_eq( i, j ) )!=15 ) return 0;
  j = vi_ldu( m+ 9 ); if( vc_pack( vi_eq( i, j ) )!=15 ) return 0;
  j = vi_ldu( m+14 ); if( vc_pack( vi_eq( i, j ) )!=15 ) return 0;
  j = vi_ldu( m+19 ); if( vc_pack( vi_eq( i, j ) )!=15 ) return 0;

  j = vi_gather( m, vi(9,5,21,17) ); if( !vc_all( vi_eq( i, j ) ) ) return 0;

  j = vi_insert( vi_zero(),0, i0 );
  j = vi_insert( j,        1, i1 );
  j = vi_insert( j,        2, i2 );
  j = vi_insert( j,        3, i3 ); if( vc_any( vi_ne( i, j ) ) ) return 0;

  _[0] = 0; j = vi_insert_variable( vi_one(),_[0], i0 );
  _[0] = 1; j = vi_insert_variable( j,       _[0], i1 );
  _[0] = 2; j = vi_insert_variable( j,       _[0], i2 );
  _[0] = 3; j = vi_insert_variable( j,       _[0], i3 ); if( vc_any( vi_ne( i, j ) ) ) return 0;

  return 1;
}

static int vd_test( vd_t d, double d0, double d1 ) {
  int volatile _[1];
  double       m[7] V_ATTR;
  vd_t         e;

  if( vd_extract( d, 0 )!=d0 ) return 0;
  if( vd_extract( d, 1 )!=d1 ) return 0;

  _[0] = 0; if( vd_extract_variable( d, _[0] )!=d0 ) return 0;
  _[0] = 1; if( vd_extract_variable( d, _[0] )!=d1 ) return 0;

  vd_st(  m,    d ); /*   Aligned store to aligned   */
  vd_stu( m+2,  d ); /* Unaligned store to aligned   */
  vd_stu( m+5,  d ); /* Unaligned store to aligned+1 */

  e = vd_ld(  m   ); if( vc_pack( vd_eq( d, e ) )!=15 ) return 0;
  e = vd_ldu( m+2 ); if( vc_pack( vd_eq( d, e ) )!=15 ) return 0;
  e = vd_ldu( m+5 ); if( vc_pack( vd_eq( d, e ) )!=15 ) return 0;

  e = vd_gather( m, vi( 2, 6, 5, 3 ), 0,1 ); if( !vc_all( vd_eq( d, e ) ) ) return 0;
  e = vd_gather( m, vi( 2, 6, 5, 3 ), 0,3 ); if( !vc_all( vd_eq( d, e ) ) ) return 0;
  e = vd_gather( m, vi( 2, 6, 5, 3 ), 2,1 ); if( !vc_all( vd_eq( d, e ) ) ) return 0;
  e = vd_gather( m, vi( 2, 6, 5, 3 ), 2,3 ); if( !vc_all( vd_eq( d, e ) ) ) return 0;

  e = vd_insert( vd_zero(),0, d0 );
  e = vd_insert( e,        1, d1 ); if( vc_any( vd_ne( d, e ) ) ) return 0;

  _[0] = 0; e = vd_insert_variable( vd_one(),_[0], d0 );
  _[0] = 1; e = vd_insert_variable( e,       _[0], d1 ); if( vc_any( vd_ne( d, e ) ) ) return 0;

  return 1;
}

static int vl_test( vl_t l, long l0, long l1 ) {
  long volatile _[1];
  long          m[7] V_ATTR;
  vl_t          k;

  if( vl_extract( l, 0 )!=l0 ) return 0;
  if( vl_extract( l, 1 )!=l1 ) return 0;

  _[0] = 0; if( vl_extract_variable( l, _[0] )!=l0 ) return 0;
  _[0] = 1; if( vl_extract_variable( l, _[0] )!=l1 ) return 0;

  vl_st(  m,    l ); /*   Aligned store to aligned   */
  vl_stu( m+2,  l ); /* Unaligned store to aligned   */
  vl_stu( m+5,  l ); /* Unaligned store to aligned+1 */

  k = vl_ld(  m    ); if( vc_pack( vl_eq( l, k ) )!=15 ) return 0;
  k = vl_ldu( m+2  ); if( vc_pack( vl_eq( l, k ) )!=15 ) return 0;
  k = vl_ldu( m+5  ); if( vc_pack( vl_eq( l, k ) )!=15 ) return 0;

  k = vl_gather( m, vi( 2, 6, 5, 3 ), 0,1 ); if( !vc_all( vl_eq( l, k ) ) ) return 0;
  k = vl_gather( m, vi( 2, 6, 5, 3 ), 0,3 ); if( !vc_all( vl_eq( l, k ) ) ) return 0;
  k = vl_gather( m, vi( 2, 6, 5, 3 ), 2,1 ); if( !vc_all( vl_eq( l, k ) ) ) return 0;
  k = vl_gather( m, vi( 2, 6, 5, 3 ), 2,3 ); if( !vc_all( vl_eq( l, k ) ) ) return 0;

  k = vl_insert( vl_zero(),0, l0 );
  k = vl_insert( k,        1, l1 ); if( vc_any( vl_ne( l, k ) ) ) return 0;

  _[0] = 0; k = vl_insert_variable( vl_one(),_[0], l0 );
  _[0] = 1; k = vl_insert_variable( k,       _[0], l1 ); if( vc_any( vl_ne( l, k ) ) ) return 0;

  return 1;
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

# define crand() (!(fd_rng_uint( rng ) & 1U))
# define frand() (0.5f*(float)(fd_rng_uint( rng ) % 15U)-3.5f) /* [-3.5,-3,...+3,+3.5] */
# define irand() ((int)(fd_rng_uint( rng ) % 7U)-3)            /* [-3,-2,-1,0,1,2,3] */
# define drand() (0.5*(double)(fd_rng_uint( rng ) % 15U)-3.5)  /* [-3.5,-3,...+3,+3.5] */
# define lrand() ((long)(fd_rng_uint( rng ) % 7U)-3L)          /* [-3,-2,-1,0,1,2,3] */

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

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

    FD_TEST( vc_test( vc_not( c ), !c0, !c1, !c2, !c3 ) );

    FD_TEST( vc_test( vc_lnot( c ),     !c0,  !c1,  !c2,  !c3 ) );
    FD_TEST( vc_test( vc_lnotnot( c ), !!c0, !!c1, !!c2, !!c3 ) );

    FD_TEST( vi_test( vc_to_vi( c ), c0, c1, c2, c3 ) );

    FD_TEST( vf_test( vc_to_vf( c ), (float)c0, (float)c1, (float)c2, (float)c3 ) );

    FD_TEST( vd_test( vc_to_vd( vc_bcast_wide( c0,c1 ) ), (double)c0, (double)c1 ) );

    FD_TEST( vl_test( vc_to_vl( vc_bcast_wide( c0,c1 ) ), (long)c0, (long)c1 ) );

    FD_TEST( vc_any(c) == (c0 | c1 | c2 | c3) );
    FD_TEST( vc_all(c) == (c0 & c1 & c2 & c3) );
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

    /* Reduction operations */

    FD_TEST( !vc_any( vf_ne( vf_sum_all( x ), vf_bcast( x0 + x1 + x2 + x3 ) ) ) );
    FD_TEST( !vc_any( vf_ne( vf_min_all( x ), vf_bcast( fminf( fminf( x0, x1 ), fminf( x2, x3 ) ) ) ) ) );
    FD_TEST( !vc_any( vf_ne( vf_max_all( x ), vf_bcast( fmaxf( fmaxf( x0, x1 ), fmaxf( x2, x3 ) ) ) ) ) );
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

#   define _(n) \
    FD_TEST( vi_test( vi_shl( x, n ), x0<<n, x1<<n, x2<<n, x3<<n ) ); \
    FD_TEST( vi_test( vi_shr( x, n ), x0>>n, x1>>n, x2>>n, x3>>n ) ); \
    FD_TEST( vi_test( vi_shru( x, n ), (int)(((uint)x0)>>n), (int)(((uint)x1)>>n), (int)(((uint)x2)>>n), (int)(((uint)x3)>>n) ) )
    _( 0); _( 1); _( 2); _( 3); _( 4); _( 5); _( 6); _( 7); _( 8); _( 9); _(10); _(11); _(12); _(13); _(14); _(15);
    _(16); _(17); _(18); _(19); _(20); _(21); _(22); _(23); _(24); _(25); _(26); _(27); _(28); _(29); _(30); _(31);
#   undef _
    for( int n=0; n<32; n++ ) {
      int volatile m[1]; m[0] = n;
      FD_TEST( vi_test( vi_shl_variable(  x, m[0] ), x0<<n, x1<<n, x2<<n, x3<<n ) );
      FD_TEST( vi_test( vi_shr_variable(  x, m[0] ), x0>>n, x1>>n, x2>>n, x3>>n ) );
      FD_TEST( vi_test( vi_shru_variable( x, m[0] ),
                        (int)(((uint)x0)>>n), (int)(((uint)x1)>>n), (int)(((uint)x2)>>n), (int)(((uint)x3)>>n) ) );
    }

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

    /* Reduction operations */

    FD_TEST( !vc_any( vi_ne( vi_sum_all( x ), vi_bcast( x0 + x1 + x2 + x3 ) ) ) );
    FD_TEST( !vc_any( vi_ne( vi_min_all( x ), vi_bcast( fd_int_min( fd_int_min( x0, x1 ), fd_int_min( x2, x3 ) ) ) ) ) );
    FD_TEST( !vc_any( vi_ne( vi_max_all( x ), vi_bcast( fd_int_max( fd_int_max( x0, x1 ), fd_int_max( x2, x3 ) ) ) ) ) );
  }

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

    FD_TEST( vl_test( vd_to_vl( x ), (long)x0, (long)x1 ) );

    /* Reduction operations */

    FD_TEST( !vc_any( vd_ne( vd_sum_all( x ), vd_bcast( x0 + x1        ) ) ) );
    FD_TEST( !vc_any( vd_ne( vd_min_all( x ), vd_bcast( fmin( x0, x1 ) ) ) ) );
    FD_TEST( !vc_any( vd_ne( vd_max_all( x ), vd_bcast( fmax( x0, x1 ) ) ) ) );
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

#   define _(n) \
    FD_TEST( vl_test( vl_shl( x, n ), x0<<n, x1<<n ) ); \
    FD_TEST( vl_test( vl_shr( x, n ), x0>>n, x1>>n ) ); \
    FD_TEST( vl_test( vl_shru( x, n ), (long)(((ulong)x0)>>n), (long)(((ulong)x1)>>n) ) )
    _( 0); _( 1); _( 2); _( 3); _( 4); _( 5); _( 6); _( 7); _( 8); _( 9); _(10); _(11); _(12); _(13); _(14); _(15);
    _(16); _(17); _(18); _(19); _(20); _(21); _(22); _(23); _(24); _(25); _(26); _(27); _(28); _(29); _(30); _(31);
    _(32); _(33); _(34); _(35); _(36); _(37); _(38); _(39); _(40); _(41); _(42); _(43); _(44); _(45); _(46); _(47);
    _(48); _(49); _(50); _(51); _(52); _(53); _(54); _(55); _(56); _(57); _(58); _(59); _(60); _(61); _(62); _(63);
#   undef _
    for( int n=0; n<64; n++ ) {
      int volatile m[1]; m[0] = n;
      FD_TEST( vl_test( vl_shl_variable(  x, m[0] ), x0<<n, x1<<n ) );
      FD_TEST( vl_test( vl_shr_variable(  x, m[0] ), x0>>n, x1>>n ) );
      FD_TEST( vl_test( vl_shru_variable( x, m[0] ), (long)(((ulong)x0)>>n), (long)(((ulong)x1)>>n) ) );
    }

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

    FD_TEST( vd_test( vl_to_vd( x ), (double)x0, (double)x1 ) );

    /* Reduction operations */

    FD_TEST( !vc_any( vl_ne( vl_sum_all( x ), vl_bcast( x0 + x1 ) ) ) );
    FD_TEST( !vc_any( vl_ne( vl_min_all( x ), vl_bcast( fd_long_min( x0, x1 ) ) ) ) );
    FD_TEST( !vc_any( vl_ne( vl_max_all( x ), vl_bcast( fd_long_max( x0, x1 ) ) ) ) );
  }

  /* FIXME: TEST LDIF/STIF VARIANTS */
  /* FIXME: TEST VECTOR SHIFT VARIANTS */

  fd_rng_delete( fd_rng_leave( rng ) );

# undef drand
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
