#include "../fd_util.h"

#if FD_HAS_AVX

#include "fd_sse.h"
#include <math.h>

static int
vb_test( vb_t b, uchar bi[ 16 ] ) {
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

#define EXPAND_2_INDICES( x, offset ) x[ (offset) ], x[ (offset)+1UL ]
#define EXPAND_4_INDICES( x, offset ) x[ (offset) ], x[ (offset)+1UL ], x[ (offset)+2UL ], x[ (offset)+3UL ]
#define EXPAND_8_INDICES( x, offset )  EXPAND_4_INDICES(  x, offset ), EXPAND_4_INDICES(  x, (offset)+4UL  )
#define EXPAND_16_INDICES( x, offset ) EXPAND_8_INDICES(  x, offset ), EXPAND_8_INDICES(  x, (offset)+8UL  )

#define INVOKE_EXPAND( M, ... ) M(  __VA_ARGS__ )

# define brand() (uchar)((fd_rng_uchar( rng ) % 7U)-3U)                /* [253,254,255,0,1,2,3] */
  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  /* VB tests */
  uchar xi[ 16 ], yi[ 16 ], ci[ 16 ];
  uchar ti[ 16 ];

  fd_memset( xi, 0, 16UL ); FD_TEST( vb_test( vb_zero(), xi ) );
  fd_memset( xi, 1, 16UL ); FD_TEST( vb_test( vb_one(),  xi ) );

  for( int i=0; i<65536; i++ ) {
    for( ulong j=0UL; j<16UL; j++ ) xi[ j ] = brand();
    vb_t x = INVOKE_EXPAND( vb, EXPAND_16_INDICES( xi, 0 ) );

    for( ulong j=0UL; j<16UL; j++ ) yi[ j ] = brand();
    vb_t y = INVOKE_EXPAND( vb, EXPAND_16_INDICES( yi, 0 ) );

    for( ulong j=0UL; j<16UL; j++ ) ci[ j ] = (uchar)(fd_rng_uint( rng ) & 1 ? 0xFF : 0);
    vb_t c = INVOKE_EXPAND( vb, EXPAND_16_INDICES( ci, 0 ) );

#   define INIT_TI( EXPR ) do { for( ulong j=0UL; j<16UL; j++ ) { ti[j] = (EXPR); } } while( 0 )
#   define C(cond) (uchar)( (cond) ? 0xFF : 0 )
#   define ROL(x,n) fd_uint_rotate_left ( (x),(n) )
#   define ROR(x,n) fd_uint_rotate_right( (x),(n) )


    /* Constructors */

    FD_TEST( vb_test( x, xi ) );

    INIT_TI( yi[0]                        );       FD_TEST( vb_test( vb_bcast( yi[0] ), ti )                           );

    INIT_TI( yi[j&1UL]                    );       FD_TEST( vb_test( vb_bcast_pair( yi[0], yi[1] ), ti )               );
    INIT_TI( yi[j>>3 ]                    );       FD_TEST( vb_test( vb_bcast_lohi( yi[0], yi[1] ), ti )               );

    INIT_TI( yi[j&3UL]                    );       FD_TEST( vb_test( vb_bcast_quad( yi[0], yi[1], yi[2], yi[3] ), ti ) );
    INIT_TI( yi[j>>1 ]                    );       FD_TEST( vb_test( vb_bcast_wide( EXPAND_8_INDICES( yi, 0 ) ), ti )  );

    INIT_TI( yi[j & (~1UL)]               );       FD_TEST( vb_test( vb_bcast_even(     y ), ti )                      );
    INIT_TI( yi[j |   1   ]               );       FD_TEST( vb_test( vb_bcast_odd(      y ), ti )                      );
    INIT_TI( yi[j ^   1   ]               );       FD_TEST( vb_test( vb_exch_adj(       y ), ti )                      );
    INIT_TI( yi[j ^   2   ]               );       FD_TEST( vb_test( vb_exch_adj_pair(  y ), ti )                      );
    INIT_TI( yi[j ^   4   ]               );       FD_TEST( vb_test( vb_exch_adj_quad(  y ), ti )                      );

    /* Bit operations */

    INIT_TI( (uchar)~yi[j]                );       FD_TEST( vb_test( vb_not( y ), ti )                                 );


#   define _(n)                                                                                                            \
    INIT_TI( (uchar)(yi[j]<<n)            );       FD_TEST( vb_test( vb_shl ( y, n ), ti )                             );  \
    INIT_TI( (uchar)(yi[j]>>n)            );       FD_TEST( vb_test( vb_shru( y, n ), ti )                             )
    _( 0); _( 1); _( 2); _( 3); _( 4); _( 5); _( 6); _( 7); _( 8); _( 9); _(10); _(11); _(12); _(13); _(14); _(15); _(16);
#   undef _

    for( int n=0; n<8; n++ ) {
      int volatile m[1]; m[0] = n;
      INIT_TI( (uchar)(yi[j]<<n)          );       FD_TEST( vb_test( vb_shl_variable(  y, m[0] ), ti )                 );
      INIT_TI( (uchar)(yi[j]>>n)          );       FD_TEST( vb_test( vb_shru_variable( y, m[0] ), ti )                 );
    }


    INIT_TI(   xi[j]  & yi[j]             );       FD_TEST( vb_test( vb_and(    x, y ), ti )                           );
    INIT_TI( ((uchar)~xi[j]) & yi[j]      );       FD_TEST( vb_test( vb_andnot( x, y ), ti )                           );
    INIT_TI(   xi[j]  | yi[j]             );       FD_TEST( vb_test( vb_or(     x, y ), ti )                           );
    INIT_TI(   xi[j]  ^ yi[j]             );       FD_TEST( vb_test( vb_xor(    x, y ), ti )                           );

    /* Arithmetic operations */

    INIT_TI( (uchar)-xi[j]                );       FD_TEST( vb_test( vb_neg( x    ), ti )                              );
    INIT_TI( fd_uchar_abs( xi[j] )        );       FD_TEST( vb_test( vb_abs( x    ), ti )                              );
    INIT_TI( fd_uchar_min( xi[j], yi[j] ) );       FD_TEST( vb_test( vb_min( x, y ), ti )                              );
    INIT_TI( fd_uchar_max( xi[j], yi[j] ) );       FD_TEST( vb_test( vb_max( x, y ), ti )                              );
    INIT_TI( (uchar)(xi[j]+yi[j])         );       FD_TEST( vb_test( vb_add( x, y ), ti )                              );
    INIT_TI( (uchar)(xi[j]-yi[j])         );       FD_TEST( vb_test( vb_sub( x, y ), ti )                              );

    /* Logical operations */

    INIT_TI( C( !xi[j])                   );       FD_TEST( vb_test( vb_lnot(    x ), ti )                             );
    INIT_TI( C(!!xi[j])                   );       FD_TEST( vb_test( vb_lnotnot( x ), ti )                             );

    INIT_TI( C(xi[j]==yi[j])              );       FD_TEST( vb_test( vb_eq( x, y ), ti )                               );
    INIT_TI( C(xi[j]> yi[j])              );       FD_TEST( vb_test( vb_gt( x, y ), ti )                               );
    INIT_TI( C(xi[j]< yi[j])              );       FD_TEST( vb_test( vb_lt( x, y ), ti )                               );
    INIT_TI( C(xi[j]!=yi[j])              );       FD_TEST( vb_test( vb_ne( x, y ), ti )                               );
    INIT_TI( C(xi[j]>=yi[j])              );       FD_TEST( vb_test( vb_ge( x, y ), ti )                               );
    INIT_TI( C(xi[j]<=yi[j])              );       FD_TEST( vb_test( vb_le( x, y ), ti )                               );

    INIT_TI( (uchar)(ci[j]?0:xi[j])       );       FD_TEST( vb_test( vb_czero(    c, x ), ti )                         );
    INIT_TI( (uchar)(ci[j]?xi[j]:0)       );       FD_TEST( vb_test( vb_notczero( c, x ), ti )                         );
    INIT_TI(        (ci[j]?xi[j]:yi[j])   );       FD_TEST( vb_test( vb_if( c, x, y ),    ti )                         );

#   undef ROR
#   undef ROL
#   undef C
#   undef INIT_TI

    /* Conversion operations */

    FD_TEST( vc_test( vb_to_vc( x, 0 ), EXPAND_4_INDICES( !!xi,  0 ) ) );
    FD_TEST( vc_test( vb_to_vc( x, 1 ), EXPAND_4_INDICES( !!xi,  4 ) ) );
    FD_TEST( vc_test( vb_to_vc( x, 2 ), EXPAND_4_INDICES( !!xi,  8 ) ) );
    FD_TEST( vc_test( vb_to_vc( x, 3 ), EXPAND_4_INDICES( !!xi, 12 ) ) );

    FD_TEST( vf_test( vb_to_vf( x, 0 ), EXPAND_4_INDICES( (float)xi,  0 ) ) );
    FD_TEST( vf_test( vb_to_vf( x, 1 ), EXPAND_4_INDICES( (float)xi,  4 ) ) );
    FD_TEST( vf_test( vb_to_vf( x, 2 ), EXPAND_4_INDICES( (float)xi,  8 ) ) );
    FD_TEST( vf_test( vb_to_vf( x, 3 ), EXPAND_4_INDICES( (float)xi, 12 ) ) );

    FD_TEST( vi_test( vb_to_vi( x, 0 ), EXPAND_4_INDICES( (int)xi,  0 ) ) );
    FD_TEST( vi_test( vb_to_vi( x, 1 ), EXPAND_4_INDICES( (int)xi,  4 ) ) );
    FD_TEST( vi_test( vb_to_vi( x, 2 ), EXPAND_4_INDICES( (int)xi,  8 ) ) );
    FD_TEST( vi_test( vb_to_vi( x, 3 ), EXPAND_4_INDICES( (int)xi, 12 ) ) );


    FD_TEST( vd_test( vb_to_vd( x, 0 ), EXPAND_2_INDICES( (double)xi,  0 ) ) );
    FD_TEST( vd_test( vb_to_vd( x, 1 ), EXPAND_2_INDICES( (double)xi,  2 ) ) );
    FD_TEST( vd_test( vb_to_vd( x, 2 ), EXPAND_2_INDICES( (double)xi,  4 ) ) );
    FD_TEST( vd_test( vb_to_vd( x, 3 ), EXPAND_2_INDICES( (double)xi,  6 ) ) );
    FD_TEST( vd_test( vb_to_vd( x, 4 ), EXPAND_2_INDICES( (double)xi,  8 ) ) );
    FD_TEST( vd_test( vb_to_vd( x, 5 ), EXPAND_2_INDICES( (double)xi, 10 ) ) );
    FD_TEST( vd_test( vb_to_vd( x, 6 ), EXPAND_2_INDICES( (double)xi, 12 ) ) );
    FD_TEST( vd_test( vb_to_vd( x, 7 ), EXPAND_2_INDICES( (double)xi, 14 ) ) );

    FD_TEST( vl_test( vb_to_vl( x, 0 ), EXPAND_2_INDICES( (long)xi,  0 ) ) );
    FD_TEST( vl_test( vb_to_vl( x, 1 ), EXPAND_2_INDICES( (long)xi,  2 ) ) );
    FD_TEST( vl_test( vb_to_vl( x, 2 ), EXPAND_2_INDICES( (long)xi,  4 ) ) );
    FD_TEST( vl_test( vb_to_vl( x, 3 ), EXPAND_2_INDICES( (long)xi,  6 ) ) );
    FD_TEST( vl_test( vb_to_vl( x, 4 ), EXPAND_2_INDICES( (long)xi,  8 ) ) );
    FD_TEST( vl_test( vb_to_vl( x, 5 ), EXPAND_2_INDICES( (long)xi, 10 ) ) );
    FD_TEST( vl_test( vb_to_vl( x, 6 ), EXPAND_2_INDICES( (long)xi, 12 ) ) );
    FD_TEST( vl_test( vb_to_vl( x, 7 ), EXPAND_2_INDICES( (long)xi, 14 ) ) );

    FD_TEST( vv_test( vb_to_vv( x, 0 ), EXPAND_2_INDICES( (ulong)xi,  0 ) ) );
    FD_TEST( vv_test( vb_to_vv( x, 1 ), EXPAND_2_INDICES( (ulong)xi,  2 ) ) );
    FD_TEST( vv_test( vb_to_vv( x, 2 ), EXPAND_2_INDICES( (ulong)xi,  4 ) ) );
    FD_TEST( vv_test( vb_to_vv( x, 3 ), EXPAND_2_INDICES( (ulong)xi,  6 ) ) );
    FD_TEST( vv_test( vb_to_vv( x, 4 ), EXPAND_2_INDICES( (ulong)xi,  8 ) ) );
    FD_TEST( vv_test( vb_to_vv( x, 5 ), EXPAND_2_INDICES( (ulong)xi, 10 ) ) );
    FD_TEST( vv_test( vb_to_vv( x, 6 ), EXPAND_2_INDICES( (ulong)xi, 12 ) ) );
    FD_TEST( vv_test( vb_to_vv( x, 7 ), EXPAND_2_INDICES( (ulong)xi, 14 ) ) );


    /* Reduction operations */
    ulong acc;
    acc=0UL;   for( ulong j=0UL; j<16UL; j++ ) acc += xi[j];  FD_TEST( !vb_any( vb_ne( vb_sum_all( x ), vb_bcast( (uchar)acc ) )));
    acc=255UL; for( ulong j=0UL; j<16UL; j++ ) acc =  fd_uchar_min( (uchar)acc, xi[j] );
                                                              FD_TEST( !vb_any( vb_ne( vb_min_all( x ), vb_bcast( (uchar)acc ) )));
    acc=0UL;   for( ulong j=0UL; j<16UL; j++ ) acc =  fd_uchar_max( (uchar)acc, xi[j] );
                                                              FD_TEST( !vb_any( vb_ne( vb_max_all( x ), vb_bcast( (uchar)acc ) )));

    /* Misc operations */
    FD_TEST( (!!xi[0] & !!xi[1]) == vb_all( vb_bcast_pair( xi[0], xi[1] ) ) );
    FD_TEST( (!!xi[0] | !!xi[1]) == vb_any( vb_bcast_pair( xi[0], xi[1] ) ) );

    FD_TEST( (!!ci[0] & !!ci[1]) == vb_all_fast( vb_bcast_pair( ci[0], ci[1] ) ) );
    FD_TEST( (!!ci[0] | !!ci[1]) == vb_any_fast( vb_bcast_pair( ci[0], ci[1] ) ) );


  }


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
