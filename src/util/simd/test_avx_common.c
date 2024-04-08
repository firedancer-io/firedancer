#include "../fd_util.h"
#include "fd_avx.h"

int wc_test( wc_t c, int c0, int c1, int c2, int c3, int c4, int c5, int c6, int c7 ) {
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

int wf_test( wf_t f, float f0, float f1, float f2, float f3, float f4, float f5, float f6, float f7 ) {
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

int wi_test( wi_t i, int i0, int i1, int i2, int i3, int i4, int i5, int i6, int i7 ) {
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

int wu_test( wu_t u, uint u0, uint u1, uint u2, uint u3, uint u4, uint u5, uint u6, uint u7 ) {
  int volatile _[1];
  uint         m[79] W_ATTR;
  wu_t         v;

  if( wu_extract( u, 0 )!=u0 ) return 0;
  if( wu_extract( u, 1 )!=u1 ) return 0;
  if( wu_extract( u, 2 )!=u2 ) return 0;
  if( wu_extract( u, 3 )!=u3 ) return 0;
  if( wu_extract( u, 4 )!=u4 ) return 0;
  if( wu_extract( u, 5 )!=u5 ) return 0;
  if( wu_extract( u, 6 )!=u6 ) return 0;
  if( wu_extract( u, 7 )!=u7 ) return 0;

  _[0] = 0; if( wu_extract_variable( u, _[0] )!=u0 ) return 0;
  _[0] = 1; if( wu_extract_variable( u, _[0] )!=u1 ) return 0;
  _[0] = 2; if( wu_extract_variable( u, _[0] )!=u2 ) return 0;
  _[0] = 3; if( wu_extract_variable( u, _[0] )!=u3 ) return 0;
  _[0] = 4; if( wu_extract_variable( u, _[0] )!=u4 ) return 0;
  _[0] = 5; if( wu_extract_variable( u, _[0] )!=u5 ) return 0;
  _[0] = 6; if( wu_extract_variable( u, _[0] )!=u6 ) return 0;
  _[0] = 7; if( wu_extract_variable( u, _[0] )!=u7 ) return 0;

  wu_st(  m,    u ); /*   Aligned store to aligned   */
  wu_stu( m+8,  u ); /* Unaligned store to aligned   */
  wu_stu( m+17, u ); /* Unaligned store to aligned+1 */
  wu_stu( m+26, u ); /* Unaligned store to aligned+2 */
  wu_stu( m+35, u ); /* Unaligned store to aligned+3 */
  wu_stu( m+44, u ); /* Unaligned store to aligned+4 */
  wu_stu( m+53, u ); /* Unaligned store to aligned+5 */
  wu_stu( m+62, u ); /* Unaligned store to aligned+6 */
  wu_stu( m+71, u ); /* Unaligned store to aligned+7 */

  v = wu_ld(  m    ); if( wc_pack( wu_eq( u, v ) )!=255 ) return 0;
  v = wu_ldu( m+8  ); if( wc_pack( wu_eq( u, v ) )!=255 ) return 0;
  v = wu_ldu( m+17 ); if( wc_pack( wu_eq( u, v ) )!=255 ) return 0;
  v = wu_ldu( m+26 ); if( wc_pack( wu_eq( u, v ) )!=255 ) return 0;
  v = wu_ldu( m+35 ); if( wc_pack( wu_eq( u, v ) )!=255 ) return 0;
  v = wu_ldu( m+44 ); if( wc_pack( wu_eq( u, v ) )!=255 ) return 0;
  v = wu_ldu( m+53 ); if( wc_pack( wu_eq( u, v ) )!=255 ) return 0;
  v = wu_ldu( m+62 ); if( wc_pack( wu_eq( u, v ) )!=255 ) return 0;
  v = wu_ldu( m+71 ); if( wc_pack( wu_eq( u, v ) )!=255 ) return 0;

  v = wu_gather( m, wu(53,18,37,74,12,67,50,33) ); if( !wc_all( wu_eq( u, v ) ) ) return 0;

  v = wu_insert( wu_zero(),0, u0 );
  v = wu_insert( v,        1, u1 );
  v = wu_insert( v,        2, u2 );
  v = wu_insert( v,        3, u3 );
  v = wu_insert( v,        4, u4 );
  v = wu_insert( v,        5, u5 );
  v = wu_insert( v,        6, u6 );
  v = wu_insert( v,        7, u7 ); if( wc_any( wu_ne( u, v ) ) ) return 0;

  _[0] = 0; v = wu_insert_variable( wu_one(),_[0], u0 );
  _[0] = 1; v = wu_insert_variable( v,       _[0], u1 );
  _[0] = 2; v = wu_insert_variable( v,       _[0], u2 );
  _[0] = 3; v = wu_insert_variable( v,       _[0], u3 );
  _[0] = 4; v = wu_insert_variable( v,       _[0], u4 );
  _[0] = 5; v = wu_insert_variable( v,       _[0], u5 );
  _[0] = 6; v = wu_insert_variable( v,       _[0], u6 );
  _[0] = 7; v = wu_insert_variable( v,       _[0], u7 ); if( wc_any( wu_ne( u, v ) ) ) return 0;

  return 1;
}

int wd_test( wd_t d, double d0, double d1, double d2, double d3 ) {
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

int wl_test( wl_t l, long l0, long l1, long l2, long l3 ) {
  int volatile _[1];
  long         m[23] W_ATTR;
  wl_t         k;

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

int wv_test( wv_t v, ulong v0, ulong v1, ulong v2, ulong v3 ) {
  int volatile _[1];
  ulong        m[23] W_ATTR;
  wv_t         w;

  if( wv_extract( v, 0 )!=v0 ) return 0;
  if( wv_extract( v, 1 )!=v1 ) return 0;
  if( wv_extract( v, 2 )!=v2 ) return 0;
  if( wv_extract( v, 3 )!=v3 ) return 0;

  _[0] = 0; if( wv_extract_variable( v, _[0] )!=v0 ) return 0;
  _[0] = 1; if( wv_extract_variable( v, _[0] )!=v1 ) return 0;
  _[0] = 2; if( wv_extract_variable( v, _[0] )!=v2 ) return 0;
  _[0] = 3; if( wv_extract_variable( v, _[0] )!=v3 ) return 0;

  wv_st(  m,    v ); /*   Aligned store to aligned   */
  wv_stu( m+4,  v ); /* Unaligned store to aligned   */
  wv_stu( m+9,  v ); /* Unaligned store to aligned+1 */
  wv_stu( m+14, v ); /* Unaligned store to aligned+2 */
  wv_stu( m+19, v ); /* Unaligned store to aligned+3 */

  w = wv_ld(  m    ); if( wc_pack( wv_eq( v, w ) )!=255 ) return 0;
  w = wv_ldu( m+4  ); if( wc_pack( wv_eq( v, w ) )!=255 ) return 0;
  w = wv_ldu( m+9  ); if( wc_pack( wv_eq( v, w ) )!=255 ) return 0;
  w = wv_ldu( m+14 ); if( wc_pack( wv_eq( v, w ) )!=255 ) return 0;
  w = wv_ldu( m+19 ); if( wc_pack( wv_eq( v, w ) )!=255 ) return 0;

  w = wv_gather( m, wi( 9,20,21,17, 3, 2, 1, 0), 0 ); if( !wc_all( wv_eq( v, w ) ) ) return 0;
  w = wv_gather( m, wi( 3, 2, 1, 0, 4,10, 6,12), 1 ); if( !wc_all( wv_eq( v, w ) ) ) return 0;

  w = wv_insert( wv_zero(),0, v0 );
  w = wv_insert( w,        1, v1 );
  w = wv_insert( w,        2, v2 );
  w = wv_insert( w,        3, v3 ); if( wc_any( wv_ne( v, w ) ) ) return 0;

  _[0] = 0; w = wv_insert_variable( wv_one(),_[0], v0 );
  _[0] = 1; w = wv_insert_variable( w,       _[0], v1 );
  _[0] = 2; w = wv_insert_variable( w,       _[0], v2 );
  _[0] = 3; w = wv_insert_variable( w,       _[0], v3 ); if( wc_any( wv_ne( v, w ) ) ) return 0;

  return 1;
}

int wb_test( wb_t b, uchar const * bi ) {
  int volatile _[1];
  uchar        m[295] W_ATTR;
  wb_t         g;

  if( wb_extract( b,  0 ) !=bi[ 0] ) return 0;
  if( wb_extract( b,  1 ) !=bi[ 1] ) return 0;
  if( wb_extract( b,  2 ) !=bi[ 2] ) return 0;
  if( wb_extract( b,  3 ) !=bi[ 3] ) return 0;
  if( wb_extract( b,  4 ) !=bi[ 4] ) return 0;
  if( wb_extract( b,  5 ) !=bi[ 5] ) return 0;
  if( wb_extract( b,  6 ) !=bi[ 6] ) return 0;
  if( wb_extract( b,  7 ) !=bi[ 7] ) return 0;
  if( wb_extract( b,  8 ) !=bi[ 8] ) return 0;
  if( wb_extract( b,  9 ) !=bi[ 9] ) return 0;
  if( wb_extract( b, 10 ) !=bi[10] ) return 0;
  if( wb_extract( b, 11 ) !=bi[11] ) return 0;
  if( wb_extract( b, 12 ) !=bi[12] ) return 0;
  if( wb_extract( b, 13 ) !=bi[13] ) return 0;
  if( wb_extract( b, 14 ) !=bi[14] ) return 0;
  if( wb_extract( b, 15 ) !=bi[15] ) return 0;
  if( wb_extract( b, 16 ) !=bi[16] ) return 0;
  if( wb_extract( b, 17 ) !=bi[17] ) return 0;
  if( wb_extract( b, 18 ) !=bi[18] ) return 0;
  if( wb_extract( b, 19 ) !=bi[19] ) return 0;
  if( wb_extract( b, 20 ) !=bi[20] ) return 0;
  if( wb_extract( b, 21 ) !=bi[21] ) return 0;
  if( wb_extract( b, 22 ) !=bi[22] ) return 0;
  if( wb_extract( b, 23 ) !=bi[23] ) return 0;
  if( wb_extract( b, 24 ) !=bi[24] ) return 0;
  if( wb_extract( b, 25 ) !=bi[25] ) return 0;
  if( wb_extract( b, 26 ) !=bi[26] ) return 0;
  if( wb_extract( b, 27 ) !=bi[27] ) return 0;
  if( wb_extract( b, 28 ) !=bi[28] ) return 0;
  if( wb_extract( b, 29 ) !=bi[29] ) return 0;
  if( wb_extract( b, 30 ) !=bi[30] ) return 0;
  if( wb_extract( b, 31 ) !=bi[31] ) return 0;

  for( int j=0; j<32; j++ ) { _[0]=j; if( wb_extract_variable( b, _[0] )!=bi[j] ) return 0; }

  wb_st(  m,     b ); /*   Aligned store to aligned   */
  wb_stu( m+32,  b ); /* Unaligned store to aligned   */
  wb_stu( m+65,  b ); /* Unaligned store to aligned+1 */
  wb_stu( m+98,  b ); /* Unaligned store to aligned+2 */
  wb_stu( m+131, b ); /* Unaligned store to aligned+3 */
  wb_stu( m+164, b ); /* Unaligned store to aligned+4 */
  wb_stu( m+197, b ); /* Unaligned store to aligned+5 */
  wb_stu( m+230, b ); /* Unaligned store to aligned+6 */
  wb_stu( m+263, b ); /* Unaligned store to aligned+7 */

  g = wb_ld ( m     ); if( !wb_all( wb_eq( b, g ) ) ) return 0;
  g = wb_ldu( m+32  ); if( !wb_all( wb_eq( b, g ) ) ) return 0;
  g = wb_ldu( m+65  ); if( !wb_all( wb_eq( b, g ) ) ) return 0;
  g = wb_ldu( m+98  ); if( !wb_all( wb_eq( b, g ) ) ) return 0;
  g = wb_ldu( m+131 ); if( !wb_all( wb_eq( b, g ) ) ) return 0;
  g = wb_ldu( m+164 ); if( !wb_all( wb_eq( b, g ) ) ) return 0;
  g = wb_ldu( m+197 ); if( !wb_all( wb_eq( b, g ) ) ) return 0;
  g = wb_ldu( m+230 ); if( !wb_all( wb_eq( b, g ) ) ) return 0;
  g = wb_ldu( m+263 ); if( !wb_all( wb_eq( b, g ) ) ) return 0;

  g = wb_zero();
  g = wb_insert( g,  0, bi[ 0] );
  g = wb_insert( g,  1, bi[ 1] );
  g = wb_insert( g,  2, bi[ 2] );
  g = wb_insert( g,  3, bi[ 3] );
  g = wb_insert( g,  4, bi[ 4] );
  g = wb_insert( g,  5, bi[ 5] );
  g = wb_insert( g,  6, bi[ 6] );
  g = wb_insert( g,  7, bi[ 7] );
  g = wb_insert( g,  8, bi[ 8] );
  g = wb_insert( g,  9, bi[ 9] );
  g = wb_insert( g, 10, bi[10] );
  g = wb_insert( g, 11, bi[11] );
  g = wb_insert( g, 12, bi[12] );
  g = wb_insert( g, 13, bi[13] );
  g = wb_insert( g, 14, bi[14] );
  g = wb_insert( g, 15, bi[15] );
  g = wb_insert( g, 16, bi[16] );
  g = wb_insert( g, 17, bi[17] );
  g = wb_insert( g, 18, bi[18] );
  g = wb_insert( g, 19, bi[19] );
  g = wb_insert( g, 20, bi[20] );
  g = wb_insert( g, 21, bi[21] );
  g = wb_insert( g, 22, bi[22] );
  g = wb_insert( g, 23, bi[23] );
  g = wb_insert( g, 24, bi[24] );
  g = wb_insert( g, 25, bi[25] );
  g = wb_insert( g, 26, bi[26] );
  g = wb_insert( g, 27, bi[27] );
  g = wb_insert( g, 28, bi[28] );
  g = wb_insert( g, 29, bi[29] );
  g = wb_insert( g, 30, bi[30] );
  g = wb_insert( g, 31, bi[31] ); if( wb_any( wb_ne( b, g ) ) ) return 0;

  g = wb_zero();
  for( int j=0; j<32; j++ ) { _[0]=j; g=wb_insert_variable( g, _[0], bi[j] ); }
  if( wb_any( wb_ne( b, g ) ) ) return 0;

  return 1;
}
