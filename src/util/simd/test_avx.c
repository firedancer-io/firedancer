#include "../fd_util.h"

#if FD_HAS_AVX

#include "fd_avx.h"
#include <math.h>

static int wc_test( wc_t c, int c0, int c1, int c2, int c3, int c4, int c5, int c6, int c7 ) {
  c0 = !!c0; c1 = !!c1; c2 = !!c2; c3 = !!c3; c4 = !!c4; c5 = !!c5; c6 = !!c6; c7 = !!c7;
  int volatile _[1];
  int          m[79] W_ATTR;
  wc_t         d;

  fd_memset( m, 0, 79UL*sizeof(int) );

  int b = (c0<<0) | (c1<<1) | (c2<<2) | (c3<<3) | (c4<<4) | (c5<<5) | (c6<<6) | (c7<<7);
  if( wc_pack( c )!=b ) return 0;
  if( wc_pack( wc_eq( wc_unpack( b ), c ) )!=255 ) return 0;

  if( wc_extract( c, 0 )!=c0 ) return 0;
  if( wc_extract( c, 1 )!=c1 ) return 0;
  if( wc_extract( c, 2 )!=c2 ) return 0;
  if( wc_extract( c, 3 )!=c3 ) return 0;
  if( wc_extract( c, 4 )!=c4 ) return 0;
  if( wc_extract( c, 5 )!=c5 ) return 0;
  if( wc_extract( c, 6 )!=c6 ) return 0;
  if( wc_extract( c, 7 )!=c7 ) return 0;

  _[0] = 0; if( wc_extract_variable( c, _[0] )!=c0 ) return 0;
  _[0] = 1; if( wc_extract_variable( c, _[0] )!=c1 ) return 0;
  _[0] = 2; if( wc_extract_variable( c, _[0] )!=c2 ) return 0;
  _[0] = 3; if( wc_extract_variable( c, _[0] )!=c3 ) return 0;
  _[0] = 4; if( wc_extract_variable( c, _[0] )!=c4 ) return 0;
  _[0] = 5; if( wc_extract_variable( c, _[0] )!=c5 ) return 0;
  _[0] = 6; if( wc_extract_variable( c, _[0] )!=c6 ) return 0;
  _[0] = 7; if( wc_extract_variable( c, _[0] )!=c7 ) return 0;

  wc_st(  m,    c ); /*   Aligned store to aligned   */
  wc_stu( m+8,  c ); /* Unaligned store to aligned   */
  wc_stu( m+17, c ); /* Unaligned store to aligned+1 */
  wc_stu( m+26, c ); /* Unaligned store to aligned+2 */
  wc_stu( m+35, c ); /* Unaligned store to aligned+3 */
  wc_stu( m+44, c ); /* Unaligned store to aligned+4 */
  wc_stu( m+53, c ); /* Unaligned store to aligned+5 */
  wc_stu( m+62, c ); /* Unaligned store to aligned+6 */
  wc_stu( m+71, c ); /* Unaligned store to aligned+7 */

  d = wc_ld_fast(  m    ); if( wc_any( wc_ne( c, d ) ) ) return 0;
  d = wc_ldu_fast( m+8  ); if( wc_any( wc_ne( c, d ) ) ) return 0;
  d = wc_ldu_fast( m+17 ); if( wc_any( wc_ne( c, d ) ) ) return 0;
  d = wc_ldu_fast( m+26 ); if( wc_any( wc_ne( c, d ) ) ) return 0;
  d = wc_ldu_fast( m+35 ); if( wc_any( wc_ne( c, d ) ) ) return 0;
  d = wc_ldu_fast( m+44 ); if( wc_any( wc_ne( c, d ) ) ) return 0;
  d = wc_ldu_fast( m+53 ); if( wc_any( wc_ne( c, d ) ) ) return 0;
  d = wc_ldu_fast( m+62 ); if( wc_any( wc_ne( c, d ) ) ) return 0;
  d = wc_ldu_fast( m+71 ); if( wc_any( wc_ne( c, d ) ) ) return 0;

  d = wc_gather_fast( m, wi(44,54,19,65,39,76,32,15) ); if( wc_any( wc_ne( c, d ) ) ) return 0;

  for( int i=0; i<79; i++ ) m[i] *= (i+1);

  d = wc_ld(  m    ); if( !wc_all( wc_eq( c, d ) ) ) return 0;
  d = wc_ldu( m+8  ); if( !wc_all( wc_eq( c, d ) ) ) return 0;
  d = wc_ldu( m+17 ); if( !wc_all( wc_eq( c, d ) ) ) return 0;
  d = wc_ldu( m+26 ); if( !wc_all( wc_eq( c, d ) ) ) return 0;
  d = wc_ldu( m+35 ); if( !wc_all( wc_eq( c, d ) ) ) return 0;
  d = wc_ldu( m+44 ); if( !wc_all( wc_eq( c, d ) ) ) return 0;
  d = wc_ldu( m+53 ); if( !wc_all( wc_eq( c, d ) ) ) return 0;
  d = wc_ldu( m+62 ); if( !wc_all( wc_eq( c, d ) ) ) return 0;
  d = wc_ldu( m+71 ); if( !wc_all( wc_eq( c, d ) ) ) return 0;

  d = wc_gather( m, wi(35,54,10,74,21,67,50,33) ); if( !wc_all( wc_eq( c, d ) ) ) return 0;

  d = wc_insert( wc_false(),0, c0 );
  d = wc_insert( d,         1, c1 );
  d = wc_insert( d,         2, c2 );
  d = wc_insert( d,         3, c3 );
  d = wc_insert( d,         4, c4 );
  d = wc_insert( d,         5, c5 );
  d = wc_insert( d,         6, c6 );
  d = wc_insert( d,         7, c7 ); if( wc_any( wc_ne( c, d ) ) ) return 0;

  _[0] = 0; d = wc_insert_variable( wc_true(),_[0], c0 );
  _[0] = 1; d = wc_insert_variable( d,        _[0], c1 );
  _[0] = 2; d = wc_insert_variable( d,        _[0], c2 );
  _[0] = 3; d = wc_insert_variable( d,        _[0], c3 );
  _[0] = 4; d = wc_insert_variable( d,        _[0], c4 );
  _[0] = 5; d = wc_insert_variable( d,        _[0], c5 );
  _[0] = 6; d = wc_insert_variable( d,        _[0], c6 );
  _[0] = 7; d = wc_insert_variable( d,        _[0], c7 ); if( wc_any( wc_ne( c, d ) ) ) return 0;

  return 1;
}

static int wf_test( wf_t f, float f0, float f1, float f2, float f3, float f4, float f5, float f6, float f7 ) {
  int volatile _[1];
  float        m[79] W_ATTR;
  wf_t         g;

  if( wf_extract( f, 0 )!=f0 ) return 0;
  if( wf_extract( f, 1 )!=f1 ) return 0;
  if( wf_extract( f, 2 )!=f2 ) return 0;
  if( wf_extract( f, 3 )!=f3 ) return 0;
  if( wf_extract( f, 4 )!=f4 ) return 0;
  if( wf_extract( f, 5 )!=f5 ) return 0;
  if( wf_extract( f, 6 )!=f6 ) return 0;
  if( wf_extract( f, 7 )!=f7 ) return 0;

  _[0] = 0; if( wf_extract_variable( f, _[0] )!=f0 ) return 0;
  _[0] = 1; if( wf_extract_variable( f, _[0] )!=f1 ) return 0;
  _[0] = 2; if( wf_extract_variable( f, _[0] )!=f2 ) return 0;
  _[0] = 3; if( wf_extract_variable( f, _[0] )!=f3 ) return 0;
  _[0] = 4; if( wf_extract_variable( f, _[0] )!=f4 ) return 0;
  _[0] = 5; if( wf_extract_variable( f, _[0] )!=f5 ) return 0;
  _[0] = 6; if( wf_extract_variable( f, _[0] )!=f6 ) return 0;
  _[0] = 7; if( wf_extract_variable( f, _[0] )!=f7 ) return 0;

  wf_st(  m,    f ); /*   Aligned store to aligned   */
  wf_stu( m+8,  f ); /* Unaligned store to aligned   */
  wf_stu( m+17, f ); /* Unaligned store to aligned+1 */
  wf_stu( m+26, f ); /* Unaligned store to aligned+2 */
  wf_stu( m+35, f ); /* Unaligned store to aligned+3 */
  wf_stu( m+44, f ); /* Unaligned store to aligned+4 */
  wf_stu( m+53, f ); /* Unaligned store to aligned+5 */
  wf_stu( m+62, f ); /* Unaligned store to aligned+6 */
  wf_stu( m+71, f ); /* Unaligned store to aligned+7 */

  g = wf_ld(  m    ); if( wc_pack( wf_eq( f, g ) )!=255 ) return 0;
  g = wf_ldu( m+8  ); if( wc_pack( wf_eq( f, g ) )!=255 ) return 0;
  g = wf_ldu( m+17 ); if( wc_pack( wf_eq( f, g ) )!=255 ) return 0;
  g = wf_ldu( m+26 ); if( wc_pack( wf_eq( f, g ) )!=255 ) return 0;
  g = wf_ldu( m+35 ); if( wc_pack( wf_eq( f, g ) )!=255 ) return 0;
  g = wf_ldu( m+44 ); if( wc_pack( wf_eq( f, g ) )!=255 ) return 0;
  g = wf_ldu( m+53 ); if( wc_pack( wf_eq( f, g ) )!=255 ) return 0;
  g = wf_ldu( m+62 ); if( wc_pack( wf_eq( f, g ) )!=255 ) return 0;
  g = wf_ldu( m+71 ); if( wc_pack( wf_eq( f, g ) )!=255 ) return 0;

  g = wf_gather( m, wi(26,72,19,11,66,49,59,42) ); if( !wc_all( wf_eq( f, g ) ) ) return 0;

  g = wf_insert( wf_zero(),0, f0 );
  g = wf_insert( g,        1, f1 );
  g = wf_insert( g,        2, f2 );
  g = wf_insert( g,        3, f3 );
  g = wf_insert( g,        4, f4 );
  g = wf_insert( g,        5, f5 );
  g = wf_insert( g,        6, f6 );
  g = wf_insert( g,        7, f7 ); if( wc_any( wf_ne( f, g ) ) ) return 0;

  _[0] = 0; g = wf_insert_variable( wf_one(),_[0], f0 );
  _[0] = 1; g = wf_insert_variable( g,       _[0], f1 );
  _[0] = 2; g = wf_insert_variable( g,       _[0], f2 );
  _[0] = 3; g = wf_insert_variable( g,       _[0], f3 );
  _[0] = 4; g = wf_insert_variable( g,       _[0], f4 );
  _[0] = 5; g = wf_insert_variable( g,       _[0], f5 );
  _[0] = 6; g = wf_insert_variable( g,       _[0], f6 );
  _[0] = 7; g = wf_insert_variable( g,       _[0], f7 ); if( wc_any( wf_ne( f, g ) ) ) return 0;

  return 1;
}

static int wi_test( wi_t i, int i0, int i1, int i2, int i3, int i4, int i5, int i6, int i7 ) {
  int volatile _[1];
  int          m[79] W_ATTR;
  wi_t         j;

  if( wi_extract( i, 0 )!=i0 ) return 0;
  if( wi_extract( i, 1 )!=i1 ) return 0;
  if( wi_extract( i, 2 )!=i2 ) return 0;
  if( wi_extract( i, 3 )!=i3 ) return 0;
  if( wi_extract( i, 4 )!=i4 ) return 0;
  if( wi_extract( i, 5 )!=i5 ) return 0;
  if( wi_extract( i, 6 )!=i6 ) return 0;
  if( wi_extract( i, 7 )!=i7 ) return 0;

  _[0] = 0; if( wi_extract_variable( i, _[0] )!=i0 ) return 0;
  _[0] = 1; if( wi_extract_variable( i, _[0] )!=i1 ) return 0;
  _[0] = 2; if( wi_extract_variable( i, _[0] )!=i2 ) return 0;
  _[0] = 3; if( wi_extract_variable( i, _[0] )!=i3 ) return 0;
  _[0] = 4; if( wi_extract_variable( i, _[0] )!=i4 ) return 0;
  _[0] = 5; if( wi_extract_variable( i, _[0] )!=i5 ) return 0;
  _[0] = 6; if( wi_extract_variable( i, _[0] )!=i6 ) return 0;
  _[0] = 7; if( wi_extract_variable( i, _[0] )!=i7 ) return 0;

  wi_st(  m,    i ); /*   Aligned store to aligned   */
  wi_stu( m+8,  i ); /* Unaligned store to aligned   */
  wi_stu( m+17, i ); /* Unaligned store to aligned+1 */
  wi_stu( m+26, i ); /* Unaligned store to aligned+2 */
  wi_stu( m+35, i ); /* Unaligned store to aligned+3 */
  wi_stu( m+44, i ); /* Unaligned store to aligned+4 */
  wi_stu( m+53, i ); /* Unaligned store to aligned+5 */
  wi_stu( m+62, i ); /* Unaligned store to aligned+6 */
  wi_stu( m+71, i ); /* Unaligned store to aligned+7 */

  j = wi_ld(  m    ); if( wc_pack( wi_eq( i, j ) )!=255 ) return 0;
  j = wi_ldu( m+8  ); if( wc_pack( wi_eq( i, j ) )!=255 ) return 0;
  j = wi_ldu( m+17 ); if( wc_pack( wi_eq( i, j ) )!=255 ) return 0;
  j = wi_ldu( m+26 ); if( wc_pack( wi_eq( i, j ) )!=255 ) return 0;
  j = wi_ldu( m+35 ); if( wc_pack( wi_eq( i, j ) )!=255 ) return 0;
  j = wi_ldu( m+44 ); if( wc_pack( wi_eq( i, j ) )!=255 ) return 0;
  j = wi_ldu( m+53 ); if( wc_pack( wi_eq( i, j ) )!=255 ) return 0;
  j = wi_ldu( m+62 ); if( wc_pack( wi_eq( i, j ) )!=255 ) return 0;
  j = wi_ldu( m+71 ); if( wc_pack( wi_eq( i, j ) )!=255 ) return 0;

  j = wi_gather( m, wi(53,18,37,74,12,67,50,33) ); if( !wc_all( wi_eq( i, j ) ) ) return 0;

  j = wi_insert( wi_zero(),0, i0 );
  j = wi_insert( j,        1, i1 );
  j = wi_insert( j,        2, i2 );
  j = wi_insert( j,        3, i3 );
  j = wi_insert( j,        4, i4 );
  j = wi_insert( j,        5, i5 );
  j = wi_insert( j,        6, i6 );
  j = wi_insert( j,        7, i7 ); if( wc_any( wi_ne( i, j ) ) ) return 0;

  _[0] = 0; j = wi_insert_variable( wi_one(),_[0], i0 );
  _[0] = 1; j = wi_insert_variable( j,       _[0], i1 );
  _[0] = 2; j = wi_insert_variable( j,       _[0], i2 );
  _[0] = 3; j = wi_insert_variable( j,       _[0], i3 );
  _[0] = 4; j = wi_insert_variable( j,       _[0], i4 );
  _[0] = 5; j = wi_insert_variable( j,       _[0], i5 );
  _[0] = 6; j = wi_insert_variable( j,       _[0], i6 );
  _[0] = 7; j = wi_insert_variable( j,       _[0], i7 ); if( wc_any( wi_ne( i, j ) ) ) return 0;

  return 1;
}

static int wd_test( wd_t d, double d0, double d1, double d2, double d3 ) {
  int volatile _[1];
  double       m[23] W_ATTR;
  wd_t         e;

  if( wd_extract( d, 0 )!=d0 ) return 0;
  if( wd_extract( d, 1 )!=d1 ) return 0;
  if( wd_extract( d, 2 )!=d2 ) return 0;
  if( wd_extract( d, 3 )!=d3 ) return 0;

  _[0] = 0; if( wd_extract_variable( d, _[0] )!=d0 ) return 0;
  _[0] = 1; if( wd_extract_variable( d, _[0] )!=d1 ) return 0;
  _[0] = 2; if( wd_extract_variable( d, _[0] )!=d2 ) return 0;
  _[0] = 3; if( wd_extract_variable( d, _[0] )!=d3 ) return 0;

  wd_st(  m,    d ); /*   Aligned store to aligned   */
  wd_stu( m+4,  d ); /* Unaligned store to aligned   */
  wd_stu( m+9,  d ); /* Unaligned store to aligned+1 */
  wd_stu( m+14, d ); /* Unaligned store to aligned+2 */
  wd_stu( m+19, d ); /* Unaligned store to aligned+3 */

  e = wd_ld(  m    ); if( wc_pack( wd_eq( d, e ) )!=255 ) return 0;
  e = wd_ldu( m+4  ); if( wc_pack( wd_eq( d, e ) )!=255 ) return 0;
  e = wd_ldu( m+9  ); if( wc_pack( wd_eq( d, e ) )!=255 ) return 0;
  e = wd_ldu( m+14 ); if( wc_pack( wd_eq( d, e ) )!=255 ) return 0;
  e = wd_ldu( m+19 ); if( wc_pack( wd_eq( d, e ) )!=255 ) return 0;

  e = wd_gather( m, wi( 9,20,21,17, 3, 2, 1, 0), 0 ); if( !wc_all( wd_eq( d, e ) ) ) return 0;
  e = wd_gather( m, wi( 3, 2, 1, 0, 4,10, 6,12), 1 ); if( !wc_all( wd_eq( d, e ) ) ) return 0;

  e = wd_insert( wd_zero(),0, d0 );
  e = wd_insert( e,        1, d1 );
  e = wd_insert( e,        2, d2 );
  e = wd_insert( e,        3, d3 ); if( wc_any( wd_ne( d, e ) ) ) return 0;

  _[0] = 0; e = wd_insert_variable( wd_one(),_[0], d0 );
  _[0] = 1; e = wd_insert_variable( e,       _[0], d1 );
  _[0] = 2; e = wd_insert_variable( e,       _[0], d2 );
  _[0] = 3; e = wd_insert_variable( e,       _[0], d3 ); if( wc_any( wd_ne( d, e ) ) ) return 0;

  return 1;
}

static int wl_test( wl_t l, long l0, long l1, long l2, long l3 ) {
  long volatile _[1];
  long          m[23] W_ATTR;
  wl_t          k;

  if( wl_extract( l, 0 )!=l0 ) return 0;
  if( wl_extract( l, 1 )!=l1 ) return 0;
  if( wl_extract( l, 2 )!=l2 ) return 0;
  if( wl_extract( l, 3 )!=l3 ) return 0;

  _[0] = 0; if( wl_extract_variable( l, _[0] )!=l0 ) return 0;
  _[0] = 1; if( wl_extract_variable( l, _[0] )!=l1 ) return 0;
  _[0] = 2; if( wl_extract_variable( l, _[0] )!=l2 ) return 0;
  _[0] = 3; if( wl_extract_variable( l, _[0] )!=l3 ) return 0;

  wl_st(  m,    l ); /*   Aligned store to aligned   */
  wl_stu( m+4,  l ); /* Unaligned store to aligned   */
  wl_stu( m+9,  l ); /* Unaligned store to aligned+1 */
  wl_stu( m+14, l ); /* Unaligned store to aligned+2 */
  wl_stu( m+19, l ); /* Unaligned store to aligned+3 */

  k = wl_ld(  m    ); if( wc_pack( wl_eq( l, k ) )!=255 ) return 0;
  k = wl_ldu( m+4  ); if( wc_pack( wl_eq( l, k ) )!=255 ) return 0;
  k = wl_ldu( m+9  ); if( wc_pack( wl_eq( l, k ) )!=255 ) return 0;
  k = wl_ldu( m+14 ); if( wc_pack( wl_eq( l, k ) )!=255 ) return 0;
  k = wl_ldu( m+19 ); if( wc_pack( wl_eq( l, k ) )!=255 ) return 0;

  k = wl_gather( m, wi( 9,20,21,17, 3, 2, 1, 0), 0 ); if( !wc_all( wl_eq( l, k ) ) ) return 0;
  k = wl_gather( m, wi( 3, 2, 1, 0, 4,10, 6,12), 1 ); if( !wc_all( wl_eq( l, k ) ) ) return 0;

  k = wl_insert( wl_zero(),0, l0 );
  k = wl_insert( k,        1, l1 );
  k = wl_insert( k,        2, l2 );
  k = wl_insert( k,        3, l3 ); if( wc_any( wl_ne( l, k ) ) ) return 0;

  _[0] = 0; k = wl_insert_variable( wl_one(),_[0], l0 );
  _[0] = 1; k = wl_insert_variable( k,       _[0], l1 );
  _[0] = 2; k = wl_insert_variable( k,       _[0], l2 );
  _[0] = 3; k = wl_insert_variable( k,       _[0], l3 ); if( wc_any( wl_ne( l, k ) ) ) return 0;

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

    FD_TEST( wc_test( wc_not( c ), !c0, !c1, !c2, !c3, !c4, !c5, !c6, !c7 ) );

    FD_TEST( wc_test( wc_lnot( c ),     !c0,  !c1,  !c2,  !c3,  !c4,  !c5,  !c6,  !c7 ) );
    FD_TEST( wc_test( wc_lnotnot( c ), !!c0, !!c1, !!c2, !!c3, !!c4, !!c5, !!c6, !!c7 ) );

    FD_TEST( wi_test( wc_to_wi( c ), c0, c1, c2, c3, c4, c5, c6, c7 ) );

    FD_TEST( wf_test( wc_to_wf( c ), (float)c0, (float)c1, (float)c2, (float)c3, (float)c4, (float)c5, (float)c6, (float)c7 ) );

    FD_TEST( wd_test( wc_to_wd( wc_bcast_wide( c0,c1,c2,c3 ) ), (double)c0, (double)c1, (double)c2,( double)c3 ) );

    FD_TEST( wl_test( wc_to_wl( wc_bcast_wide( c0,c1,c2,c3 ) ), (long)c0, (long)c1, (long)c2, (long)c3 ) );

    FD_TEST( wc_any(c) == (c0 | c1 | c2 | c3 | c4 | c5 | c6 | c7) );
    FD_TEST( wc_all(c) == (c0 & c1 & c2 & c3 & c4 & c5 & c6 & c7) );
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

    FD_TEST( wd_test( wf_to_wd( x, 0 ), (double)x0, (double)x1, (double)x2, (double)x3 ) );
    FD_TEST( wd_test( wf_to_wd( x, 1 ), (double)x4, (double)x5, (double)x6, (double)x7 ) );

    FD_TEST( wl_test( wf_to_wl( x, 0 ), (long)x0, (long)x1, (long)x2, (long)x3 ) );
    FD_TEST( wl_test( wf_to_wl( x, 1 ), (long)x4, (long)x5, (long)x6, (long)x7 ) );

    /* Reduction operations */

    FD_TEST( !wc_any( wf_ne( wf_sum_all( x ), wf_bcast( x0+x1+x2+x3+x4+x5+x6+x7 ) ) ) );
    FD_TEST( !wc_any( wf_ne( wf_min_all( x ), wf_bcast( fminf( fminf( fminf( x0, x1 ), fminf( x2, x3 ) ),
                                                               fminf( fminf( x4, x5 ), fminf( x6, x7 ) ) ) ) ) ) );
    FD_TEST( !wc_any( wf_ne( wf_max_all( x ), wf_bcast( fmaxf( fmaxf( fmaxf( x0, x1 ), fmaxf( x2, x3 ) ),
                                                               fmaxf( fmaxf( x4, x5 ), fmaxf( x6, x7 ) ) ) ) ) ) );
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

#   define _(n) \
    FD_TEST( wi_test( wi_shl( x, n ), x0<<n, x1<<n, x2<<n, x3<<n, x4<<n, x5<<n, x6<<n, x7<<n ) ); \
    FD_TEST( wi_test( wi_shr( x, n ), x0>>n, x1>>n, x2>>n, x3>>n, x4>>n, x5>>n, x6>>n, x7>>n ) ); \
    FD_TEST( wi_test( wi_shru( x, n ), (int)(((uint)x0)>>n), (int)(((uint)x1)>>n), (int)(((uint)x2)>>n), (int)(((uint)x3)>>n), \
                                       (int)(((uint)x4)>>n), (int)(((uint)x5)>>n), (int)(((uint)x6)>>n), (int)(((uint)x7)>>n) ) )
    _( 0); _( 1); _( 2); _( 3); _( 4); _( 5); _( 6); _( 7); _( 8); _( 9); _(10); _(11); _(12); _(13); _(14); _(15);
    _(16); _(17); _(18); _(19); _(20); _(21); _(22); _(23); _(24); _(25); _(26); _(27); _(28); _(29); _(30); _(31);
#   undef _
    for( int n=0; n<32; n++ ) {
      int volatile m[1]; m[0] = n;
      FD_TEST( wi_test( wi_shl_variable(  x, m[0] ), x0<<n, x1<<n, x2<<n, x3<<n, x4<<n, x5<<n, x6<<n, x7<<n ) );
      FD_TEST( wi_test( wi_shr_variable(  x, m[0] ), x0>>n, x1>>n, x2>>n, x3>>n, x4>>n, x5>>n, x6>>n, x7>>n ) );
      FD_TEST( wi_test( wi_shru_variable( x, m[0] ),
                        (int)(((uint)x0)>>n), (int)(((uint)x1)>>n), (int)(((uint)x2)>>n), (int)(((uint)x3)>>n),
                        (int)(((uint)x4)>>n), (int)(((uint)x5)>>n), (int)(((uint)x6)>>n), (int)(((uint)x7)>>n) ) );
    }

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

    FD_TEST( wd_test( wi_to_wd( x, 0 ), (double)x0, (double)x1, (double)x2, (double)x3 ) );
    FD_TEST( wd_test( wi_to_wd( x, 1 ), (double)x4, (double)x5, (double)x6, (double)x7 ) );

    FD_TEST( wl_test( wi_to_wl( x, 0 ), (long)x0, (long)x1, (long)x2, (long)x3 ) );
    FD_TEST( wl_test( wi_to_wl( x, 1 ), (long)x4, (long)x5, (long)x6, (long)x7 ) );

    /* Reduction operations */

    FD_TEST( !wc_any( wi_ne( wi_sum_all( x ), wi_bcast( x0 + x1 + x2 + x3 + x4 + x5 + x6 + x7 ) ) ) );
    FD_TEST( !wc_any( wi_ne( wi_min_all( x ), wi_bcast( fd_int_min( fd_int_min( fd_int_min( x0, x1 ), fd_int_min( x2, x3 ) ),
                                                                    fd_int_min( fd_int_min( x4, x5 ), fd_int_min( x6, x7 ) ) ) ) ) ) );
    FD_TEST( !wc_any( wi_ne( wi_max_all( x ), wi_bcast( fd_int_max( fd_int_max( fd_int_max( x0, x1 ), fd_int_max( x2, x3 ) ),
                                                                    fd_int_max( fd_int_max( x4, x5 ), fd_int_max( x6, x7 ) ) ) ) ) ) );
  }

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

    FD_TEST( wl_test( wd_to_wl( x ), (long)x0, (long)x1, (long)x2, (long)x3 ) );

    /* Reduction operations */

    FD_TEST( !wc_any( wd_ne( wd_sum_all( x ), wd_bcast( x0 + x1 + x2 + x3 ) ) ) );
    FD_TEST( !wc_any( wd_ne( wd_min_all( x ), wd_bcast( fmin( fmin( x0, x1 ), fmin( x2, x3 ) ) ) ) ) );
    FD_TEST( !wc_any( wd_ne( wd_max_all( x ), wd_bcast( fmax( fmax( x0, x1 ), fmax( x2, x3 ) ) ) ) ) );
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

#   define _(n) \
    FD_TEST( wl_test( wl_shl( x, n ), x0<<n, x1<<n, x2<<n, x3<<n ) ); \
    FD_TEST( wl_test( wl_shr( x, n ), x0>>n, x1>>n, x2>>n, x3>>n ) ); \
    FD_TEST( wl_test( wl_shru( x, n ), \
                      (long)(((ulong)x0)>>n), (long)(((ulong)x1)>>n), (long)(((ulong)x2)>>n), (long)(((ulong)x3)>>n) ) )
    _( 0); _( 1); _( 2); _( 3); _( 4); _( 5); _( 6); _( 7); _( 8); _( 9); _(10); _(11); _(12); _(13); _(14); _(15);
    _(16); _(17); _(18); _(19); _(20); _(21); _(22); _(23); _(24); _(25); _(26); _(27); _(28); _(29); _(30); _(31);
    _(32); _(33); _(34); _(35); _(36); _(37); _(38); _(39); _(40); _(41); _(42); _(43); _(44); _(45); _(46); _(47);
    _(48); _(49); _(50); _(51); _(52); _(53); _(54); _(55); _(56); _(57); _(58); _(59); _(60); _(61); _(62); _(63);
#   undef _
    for( int n=0; n<64; n++ ) {
      int volatile m[1]; m[0] = n;
      FD_TEST( wl_test( wl_shl_variable(  x, m[0] ), x0<<n, x1<<n, x2<<n, x3<<n ) );
      FD_TEST( wl_test( wl_shr_variable(  x, m[0] ), x0>>n, x1>>n, x2>>n, x3>>n ) );
      FD_TEST( wl_test( wl_shru_variable( x, m[0] ),
                        (long)(((ulong)x0)>>n), (long)(((ulong)x1)>>n), (long)(((ulong)x2)>>n), (long)(((ulong)x3)>>n)) );
    }

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

    FD_TEST( wi_test( wl_to_wi( x, wi( 0, 1, 2, 3, 4, 5, 6, 7 ), 0 ), (int)x0, (int)x1, (int)x2, (int)x3, 4, 5, 6, 7 ) );
    FD_TEST( wi_test( wl_to_wi( x, wi( 0, 1, 2, 3, 4, 5, 6, 7 ), 1 ), 0, 1, 2, 3, (int)x0, (int)x1, (int)x2, (int)x3 ) );

    FD_TEST( wd_test( wl_to_wd( x ), (double)x0, (double)x1, (double)x2, (double)x3 ) );

    /* Reduction operations */

    FD_TEST( !wc_any( wl_ne( wl_sum_all( x ), wl_bcast( x0 + x1 + x2 + x3 ) ) ) );
    FD_TEST( !wc_any( wl_ne( wl_min_all( x ), wl_bcast( fd_long_min( fd_long_min( x0, x1 ), fd_long_min( x2, x3 ) ) ) ) ) );
    FD_TEST( !wc_any( wl_ne( wl_max_all( x ), wl_bcast( fd_long_max( fd_long_max( x0, x1 ), fd_long_max( x2, x3 ) ) ) ) ) );
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
  FD_LOG_WARNING(( "skip: unit test requires FD_HAS_AVX capability" ));
  fd_halt();
  return 0;
}

#endif
