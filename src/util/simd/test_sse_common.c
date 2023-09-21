#include "../fd_util.h"
#include "fd_sse.h"

int vc_test( vc_t c, int c0, int c1, int c2, int c3 ) {
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

int vf_test( vf_t f, float f0, float f1, float f2, float f3 ) {
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

int vi_test( vi_t i, int i0, int i1, int i2, int i3 ) {
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

int vu_test( vu_t u, uint u0, uint u1, uint u2, uint u3 ) {
  int volatile _[1];
  uint         m[23] V_ATTR;
  vu_t         v;

  if( vu_extract( u, 0 )!=u0 ) return 0;
  if( vu_extract( u, 1 )!=u1 ) return 0;
  if( vu_extract( u, 2 )!=u2 ) return 0;
  if( vu_extract( u, 3 )!=u3 ) return 0;

  _[0] = 0; if( vu_extract_variable( u, _[0] )!=u0 ) return 0;
  _[0] = 1; if( vu_extract_variable( u, _[0] )!=u1 ) return 0;
  _[0] = 2; if( vu_extract_variable( u, _[0] )!=u2 ) return 0;
  _[0] = 3; if( vu_extract_variable( u, _[0] )!=u3 ) return 0;

  vu_st(  m,    u ); /*   Aligned store to aligned   */
  vu_stu( m+ 4, u ); /* Unaligned store to aligned   */
  vu_stu( m+ 9, u ); /* Unaligned store to aligned+1 */
  vu_stu( m+14, u ); /* Unaligned store to aligned+2 */
  vu_stu( m+19, u ); /* Unaligned store to aligned+3 */

  v = vu_ld(  m    ); if( vc_pack( vu_eq( u, v ) )!=15 ) return 0;
  v = vu_ldu( m+ 4 ); if( vc_pack( vu_eq( u, v ) )!=15 ) return 0;
  v = vu_ldu( m+ 9 ); if( vc_pack( vu_eq( u, v ) )!=15 ) return 0;
  v = vu_ldu( m+14 ); if( vc_pack( vu_eq( u, v ) )!=15 ) return 0;
  v = vu_ldu( m+19 ); if( vc_pack( vu_eq( u, v ) )!=15 ) return 0;

  v = vu_gather( m, vu(9,5,21,17) ); if( !vc_all( vu_eq( u, v ) ) ) return 0;

  v = vu_insert( vu_zero(),0, u0 );
  v = vu_insert( v,        1, u1 );
  v = vu_insert( v,        2, u2 );
  v = vu_insert( v,        3, u3 ); if( vc_any( vu_ne( u, v ) ) ) return 0;

  _[0] = 0; v = vu_insert_variable( vu_one(),_[0], u0 );
  _[0] = 1; v = vu_insert_variable( v,       _[0], u1 );
  _[0] = 2; v = vu_insert_variable( v,       _[0], u2 );
  _[0] = 3; v = vu_insert_variable( v,       _[0], u3 ); if( vc_any( vu_ne( u, v ) ) ) return 0;

  return 1;
}

int vd_test( vd_t d, double d0, double d1 ) {
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

int vl_test( vl_t l, long l0, long l1 ) {
  int volatile _[1];
  long         m[7] V_ATTR;
  vl_t         k;

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

int vv_test( vv_t v, ulong v0, ulong v1 ) {
  int volatile _[1];
  ulong        m[7] V_ATTR;
  vv_t         w;

  if( vv_extract( v, 0 )!=v0 ) return 0;
  if( vv_extract( v, 1 )!=v1 ) return 0;

  _[0] = 0; if( vv_extract_variable( v, _[0] )!=v0 ) return 0;
  _[0] = 1; if( vv_extract_variable( v, _[0] )!=v1 ) return 0;

  vv_st(  m,    v ); /*   Aligned store to aligned   */
  vv_stu( m+2,  v ); /* Unaligned store to aligned   */
  vv_stu( m+5,  v ); /* Unaligned store to aligned+1 */

  w = vv_ld(  m    ); if( vc_pack( vv_eq( v, w ) )!=15 ) return 0;
  w = vv_ldu( m+2  ); if( vc_pack( vv_eq( v, w ) )!=15 ) return 0;
  w = vv_ldu( m+5  ); if( vc_pack( vv_eq( v, w ) )!=15 ) return 0;

  w = vv_gather( m, vi( 2, 6, 5, 3 ), 0,1 ); if( !vc_all( vv_eq( v, w ) ) ) return 0;
  w = vv_gather( m, vi( 2, 6, 5, 3 ), 0,3 ); if( !vc_all( vv_eq( v, w ) ) ) return 0;
  w = vv_gather( m, vi( 2, 6, 5, 3 ), 2,1 ); if( !vc_all( vv_eq( v, w ) ) ) return 0;
  w = vv_gather( m, vi( 2, 6, 5, 3 ), 2,3 ); if( !vc_all( vv_eq( v, w ) ) ) return 0;

  w = vv_insert( vv_zero(),0, v0 );
  w = vv_insert( w,        1, v1 ); if( vc_any( vv_ne( v, w ) ) ) return 0;

  _[0] = 0; w = vv_insert_variable( vv_one(),_[0], v0 );
  _[0] = 1; w = vv_insert_variable( w,       _[0], v1 ); if( vc_any( vv_ne( v, w ) ) ) return 0;

  return 1;
}

int vb_test( vb_t b, uchar const * bi ) {
  int volatile _[1];
  uchar        m[151] V_ATTR;
  vb_t         g;

  if( vb_extract( b,  0 ) !=bi[ 0] ) return 0;
  if( vb_extract( b,  1 ) !=bi[ 1] ) return 0;
  if( vb_extract( b,  2 ) !=bi[ 2] ) return 0;
  if( vb_extract( b,  3 ) !=bi[ 3] ) return 0;
  if( vb_extract( b,  4 ) !=bi[ 4] ) return 0;
  if( vb_extract( b,  5 ) !=bi[ 5] ) return 0;
  if( vb_extract( b,  6 ) !=bi[ 6] ) return 0;
  if( vb_extract( b,  7 ) !=bi[ 7] ) return 0;
  if( vb_extract( b,  8 ) !=bi[ 8] ) return 0;
  if( vb_extract( b,  9 ) !=bi[ 9] ) return 0;
  if( vb_extract( b, 10 ) !=bi[10] ) return 0;
  if( vb_extract( b, 11 ) !=bi[11] ) return 0;
  if( vb_extract( b, 12 ) !=bi[12] ) return 0;
  if( vb_extract( b, 13 ) !=bi[13] ) return 0;
  if( vb_extract( b, 14 ) !=bi[14] ) return 0;
  if( vb_extract( b, 15 ) !=bi[15] ) return 0;

  for( int j=0; j<16; j++ ) { _[0]=j; if( vb_extract_variable( b, _[0] )!=bi[j] ) return 0; }

  vb_st(  m,     b ); /*   Aligned store to aligned   */
  vb_stu( m+16,  b ); /* Unaligned store to aligned   */
  vb_stu( m+33,  b ); /* Unaligned store to aligned+1 */
  vb_stu( m+50,  b ); /* Unaligned store to aligned+2 */
  vb_stu( m+67,  b ); /* Unaligned store to aligned+3 */
  vb_stu( m+84,  b ); /* Unaligned store to aligned+4 */
  vb_stu( m+101, b ); /* Unaligned store to aligned+5 */
  vb_stu( m+118, b ); /* Unaligned store to aligned+6 */
  vb_stu( m+135, b ); /* Unaligned store to aligned+7 */

  g = vb_ld ( m     ); if( !vb_all( vb_eq( b, g ) ) ) return 0;
  g = vb_ldu( m+16  ); if( !vb_all( vb_eq( b, g ) ) ) return 0;
  g = vb_ldu( m+33  ); if( !vb_all( vb_eq( b, g ) ) ) return 0;
  g = vb_ldu( m+50  ); if( !vb_all( vb_eq( b, g ) ) ) return 0;
  g = vb_ldu( m+67  ); if( !vb_all( vb_eq( b, g ) ) ) return 0;
  g = vb_ldu( m+84  ); if( !vb_all( vb_eq( b, g ) ) ) return 0;
  g = vb_ldu( m+101 ); if( !vb_all( vb_eq( b, g ) ) ) return 0;
  g = vb_ldu( m+118 ); if( !vb_all( vb_eq( b, g ) ) ) return 0;
  g = vb_ldu( m+135 ); if( !vb_all( vb_eq( b, g ) ) ) return 0;

  g = vb_zero();
  g = vb_insert( g,  0, bi[ 0] );
  g = vb_insert( g,  1, bi[ 1] );
  g = vb_insert( g,  2, bi[ 2] );
  g = vb_insert( g,  3, bi[ 3] );
  g = vb_insert( g,  4, bi[ 4] );
  g = vb_insert( g,  5, bi[ 5] );
  g = vb_insert( g,  6, bi[ 6] );
  g = vb_insert( g,  7, bi[ 7] );
  g = vb_insert( g,  8, bi[ 8] );
  g = vb_insert( g,  9, bi[ 9] );
  g = vb_insert( g, 10, bi[10] );
  g = vb_insert( g, 11, bi[11] );
  g = vb_insert( g, 12, bi[12] );
  g = vb_insert( g, 13, bi[13] );
  g = vb_insert( g, 14, bi[14] );
  g = vb_insert( g, 15, bi[15] ); if( vb_any( vb_ne( b, g ) ) ) return 0;

  g = vb_zero();
  for( int j=0; j<16; j++ ) { _[0]=j; g=vb_insert_variable( g, _[0], bi[j] ); }
  if( vb_any( vb_ne( b, g ) ) ) return 0;

  return 1;
}
