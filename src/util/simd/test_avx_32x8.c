#include "../fd_util.h"

#if FD_HAS_AVX

#include "fd_avx.h"
#include <math.h>

static int
wb_test( wb_t b, uchar bi[ 32 ] ) {
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

#define EXPAND_4_INDICES( x, offset ) x[ (offset) ], x[ (offset)+1UL ], x[ (offset)+2UL ], x[ (offset)+3UL ]
#define EXPAND_8_INDICES( x, offset )  EXPAND_4_INDICES(  x, offset ), EXPAND_4_INDICES(  x, (offset)+4UL  )
#define EXPAND_16_INDICES( x, offset ) EXPAND_8_INDICES(  x, offset ), EXPAND_8_INDICES(  x, (offset)+8UL  )
#define EXPAND_32_INDICES( x, offset ) EXPAND_16_INDICES( x, offset ), EXPAND_16_INDICES( x, (offset)+16UL )

#define INVOKE_EXPAND( M, ... ) M(  __VA_ARGS__ )

# define brand() (uchar)((fd_rng_uchar( rng ) % 7U)-3U)                /* [253,254,255,0,1,2,3] */
  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  /* WB tests */
  uchar xi[ 32 ], yi[ 32 ], ci[ 32 ];
  uchar ti[ 32 ];

  fd_memset( xi, 0, 32UL ); FD_TEST( wb_test( wb_zero(), xi ) );
  fd_memset( xi, 1, 32UL ); FD_TEST( wb_test( wb_one(),  xi ) );

  for( int i=0; i<65536; i++ ) {
    for( ulong j=0UL; j<32UL; j++ ) xi[ j ] = brand();
    wb_t x = INVOKE_EXPAND( wb, EXPAND_32_INDICES( xi, 0 ) );

    for( ulong j=0UL; j<32UL; j++ ) yi[ j ] = brand();
    wb_t y = INVOKE_EXPAND( wb, EXPAND_32_INDICES( yi, 0 ) );

    for( ulong j=0UL; j<32UL; j++ ) ci[ j ] = (uchar)(fd_rng_uint( rng ) & 1 ? 0xFF : 0);
    wb_t c = INVOKE_EXPAND( wb, EXPAND_32_INDICES( ci, 0 ) );

#   define INIT_TI( EXPR ) do { for( ulong j=0UL; j<32UL; j++ ) { ti[j] = (EXPR); } } while( 0 )
#   define C(cond) (uchar)( (cond) ? 0xFF : 0 )
#   define ROL(x,n) fd_uint_rotate_left ( (x),(n) )
#   define ROR(x,n) fd_uint_rotate_right( (x),(n) )


    /* Constructors */

    FD_TEST( wb_test( x, xi ) );

    INIT_TI( yi[0]                        );       FD_TEST( wb_test( wb_bcast( yi[0] ), ti )                           );

    INIT_TI( yi[j&1UL]                    );       FD_TEST( wb_test( wb_bcast_pair( yi[0], yi[1] ), ti )               );
    INIT_TI( yi[j>>4 ]                    );       FD_TEST( wb_test( wb_bcast_lohi( yi[0], yi[1] ), ti )               );

    INIT_TI( yi[j&3UL]                    );       FD_TEST( wb_test( wb_bcast_quad( yi[0], yi[1], yi[2], yi[3] ), ti ) );
    INIT_TI( yi[j>>1 ]                    );       FD_TEST( wb_test( wb_bcast_wide( EXPAND_16_INDICES( yi, 0 ) ), ti ) );

    INIT_TI( yi[j & (~1UL)]               );       FD_TEST( wb_test( wb_bcast_even(     y ), ti )                      );
    INIT_TI( yi[j |   1   ]               );       FD_TEST( wb_test( wb_bcast_odd(      y ), ti )                      );
    INIT_TI( yi[j ^   1   ]               );       FD_TEST( wb_test( wb_exch_adj(       y ), ti )                      );
    INIT_TI( yi[j ^   2   ]               );       FD_TEST( wb_test( wb_exch_adj_pair(  y ), ti )                      );
    INIT_TI( yi[j ^   4   ]               );       FD_TEST( wb_test( wb_exch_adj_quad(  y ), ti )                      );

    /* Bit operations */

    INIT_TI( (uchar)~yi[j]                );       FD_TEST( wb_test( wb_not( y ), ti )                                 );


#   define _(n)                                                                                                            \
    INIT_TI( (uchar)(yi[j]<<n)            );       FD_TEST( wb_test( wb_shl ( y, n ), ti )                             );  \
    INIT_TI( (uchar)(yi[j]>>n)            );       FD_TEST( wb_test( wb_shru( y, n ), ti )                             )
    _( 0); _( 1); _( 2); _( 3); _( 4); _( 5); _( 6); _( 7); _( 8); _( 9); _(10); _(11); _(12); _(13); _(14); _(15); _(16);
#   undef _

    for( int n=0; n<8; n++ ) {
      int volatile m[1]; m[0] = n;
      INIT_TI( (uchar)(yi[j]<<n)          );       FD_TEST( wb_test( wb_shl_variable(  y, m[0] ), ti )                 );
      INIT_TI( (uchar)(yi[j]>>n)          );       FD_TEST( wb_test( wb_shru_variable( y, m[0] ), ti )                 );
    }


    INIT_TI(   xi[j]  & yi[j]             );       FD_TEST( wb_test( wb_and(    x, y ), ti )                           );
    INIT_TI( ((uchar)~xi[j]) & yi[j]      );       FD_TEST( wb_test( wb_andnot( x, y ), ti )                           );
    INIT_TI(   xi[j]  | yi[j]             );       FD_TEST( wb_test( wb_or(     x, y ), ti )                           );
    INIT_TI(   xi[j]  ^ yi[j]             );       FD_TEST( wb_test( wb_xor(    x, y ), ti )                           );

    /* Arithmetic operations */

    INIT_TI( (uchar)-xi[j]                );       FD_TEST( wb_test( wb_neg( x    ), ti )                              );
    INIT_TI( fd_uchar_abs( xi[j] )        );       FD_TEST( wb_test( wb_abs( x    ), ti )                              );
    INIT_TI( fd_uchar_min( xi[j], yi[j] ) );       FD_TEST( wb_test( wb_min( x, y ), ti )                              );
    INIT_TI( fd_uchar_max( xi[j], yi[j] ) );       FD_TEST( wb_test( wb_max( x, y ), ti )                              );
    INIT_TI( (uchar)(xi[j]+yi[j])         );       FD_TEST( wb_test( wb_add( x, y ), ti )                              );
    INIT_TI( (uchar)(xi[j]-yi[j])         );       FD_TEST( wb_test( wb_sub( x, y ), ti )                              );

    /* Logical operations */

    INIT_TI( C( !xi[j])                   );       FD_TEST( wb_test( wb_lnot(    x ), ti )                             );
    INIT_TI( C(!!xi[j])                   );       FD_TEST( wb_test( wb_lnotnot( x ), ti )                             );

    INIT_TI( C(xi[j]==yi[j])              );       FD_TEST( wb_test( wb_eq( x, y ), ti )                               );
    INIT_TI( C(xi[j]> yi[j])              );       FD_TEST( wb_test( wb_gt( x, y ), ti )                               );
    INIT_TI( C(xi[j]< yi[j])              );       FD_TEST( wb_test( wb_lt( x, y ), ti )                               );
    INIT_TI( C(xi[j]!=yi[j])              );       FD_TEST( wb_test( wb_ne( x, y ), ti )                               );
    INIT_TI( C(xi[j]>=yi[j])              );       FD_TEST( wb_test( wb_ge( x, y ), ti )                               );
    INIT_TI( C(xi[j]<=yi[j])              );       FD_TEST( wb_test( wb_le( x, y ), ti )                               );

    INIT_TI( (uchar)(ci[j]?0:xi[j])       );       FD_TEST( wb_test( wb_czero(    c, x ), ti )                         );
    INIT_TI( (uchar)(ci[j]?xi[j]:0)       );       FD_TEST( wb_test( wb_notczero( c, x ), ti )                         );
    INIT_TI(        (ci[j]?xi[j]:yi[j])   );       FD_TEST( wb_test( wb_if( c, x, y ),    ti )                         );

#   undef ROR
#   undef ROL
#   undef C
#   undef INIT_TI

    /* Conversion operations */

    FD_TEST( wc_test( wb_to_wc( x, 0 ), EXPAND_8_INDICES( !!xi,  0 ) ) );
    FD_TEST( wc_test( wb_to_wc( x, 1 ), EXPAND_8_INDICES( !!xi,  8 ) ) );
    FD_TEST( wc_test( wb_to_wc( x, 2 ), EXPAND_8_INDICES( !!xi, 16 ) ) );
    FD_TEST( wc_test( wb_to_wc( x, 3 ), EXPAND_8_INDICES( !!xi, 24 ) ) );

    FD_TEST( wf_test( wb_to_wf( x, 0 ), EXPAND_8_INDICES( (float)xi,  0 ) ) );
    FD_TEST( wf_test( wb_to_wf( x, 1 ), EXPAND_8_INDICES( (float)xi,  8 ) ) );
    FD_TEST( wf_test( wb_to_wf( x, 2 ), EXPAND_8_INDICES( (float)xi, 16 ) ) );
    FD_TEST( wf_test( wb_to_wf( x, 3 ), EXPAND_8_INDICES( (float)xi, 24 ) ) );

    FD_TEST( wi_test( wb_to_wi( x, 0 ), EXPAND_8_INDICES( (int)xi,  0 ) ) );
    FD_TEST( wi_test( wb_to_wi( x, 1 ), EXPAND_8_INDICES( (int)xi,  8 ) ) );
    FD_TEST( wi_test( wb_to_wi( x, 2 ), EXPAND_8_INDICES( (int)xi, 16 ) ) );
    FD_TEST( wi_test( wb_to_wi( x, 3 ), EXPAND_8_INDICES( (int)xi, 24 ) ) );


    FD_TEST( wd_test( wb_to_wd( x, 0 ), EXPAND_4_INDICES( (double)xi, 0 ) ) );
    FD_TEST( wd_test( wb_to_wd( x, 1 ), EXPAND_4_INDICES( (double)xi, 4 ) ) );
    FD_TEST( wd_test( wb_to_wd( x, 2 ), EXPAND_4_INDICES( (double)xi, 8 ) ) );
    FD_TEST( wd_test( wb_to_wd( x, 3 ), EXPAND_4_INDICES( (double)xi, 12 ) ) );
    FD_TEST( wd_test( wb_to_wd( x, 4 ), EXPAND_4_INDICES( (double)xi, 16 ) ) );
    FD_TEST( wd_test( wb_to_wd( x, 5 ), EXPAND_4_INDICES( (double)xi, 20 ) ) );
    FD_TEST( wd_test( wb_to_wd( x, 6 ), EXPAND_4_INDICES( (double)xi, 24 ) ) );
    FD_TEST( wd_test( wb_to_wd( x, 7 ), EXPAND_4_INDICES( (double)xi, 28 ) ) );

    FD_TEST( wl_test( wb_to_wl( x, 0 ), EXPAND_4_INDICES( (long)xi, 0 ) ) );
    FD_TEST( wl_test( wb_to_wl( x, 1 ), EXPAND_4_INDICES( (long)xi, 4 ) ) );
    FD_TEST( wl_test( wb_to_wl( x, 2 ), EXPAND_4_INDICES( (long)xi, 8 ) ) );
    FD_TEST( wl_test( wb_to_wl( x, 3 ), EXPAND_4_INDICES( (long)xi, 12 ) ) );
    FD_TEST( wl_test( wb_to_wl( x, 4 ), EXPAND_4_INDICES( (long)xi, 16 ) ) );
    FD_TEST( wl_test( wb_to_wl( x, 5 ), EXPAND_4_INDICES( (long)xi, 20 ) ) );
    FD_TEST( wl_test( wb_to_wl( x, 6 ), EXPAND_4_INDICES( (long)xi, 24 ) ) );
    FD_TEST( wl_test( wb_to_wl( x, 7 ), EXPAND_4_INDICES( (long)xi, 28 ) ) );

    FD_TEST( wv_test( wb_to_wv( x, 0 ), EXPAND_4_INDICES( (ulong)xi, 0 ) ) );
    FD_TEST( wv_test( wb_to_wv( x, 1 ), EXPAND_4_INDICES( (ulong)xi, 4 ) ) );
    FD_TEST( wv_test( wb_to_wv( x, 2 ), EXPAND_4_INDICES( (ulong)xi, 8 ) ) );
    FD_TEST( wv_test( wb_to_wv( x, 3 ), EXPAND_4_INDICES( (ulong)xi, 12 ) ) );
    FD_TEST( wv_test( wb_to_wv( x, 4 ), EXPAND_4_INDICES( (ulong)xi, 16 ) ) );
    FD_TEST( wv_test( wb_to_wv( x, 5 ), EXPAND_4_INDICES( (ulong)xi, 20 ) ) );
    FD_TEST( wv_test( wb_to_wv( x, 6 ), EXPAND_4_INDICES( (ulong)xi, 24 ) ) );
    FD_TEST( wv_test( wb_to_wv( x, 7 ), EXPAND_4_INDICES( (ulong)xi, 28 ) ) );


    /* Reduction operations */
    ulong acc;
    acc=0UL;   for( ulong j=0UL; j<32UL; j++ ) acc += xi[j];
                                                              FD_TEST( !wb_any( wb_ne( wb_sum_all( x ), wb_bcast( (uchar)acc ) )));
    acc=255UL; for( ulong j=0UL; j<32UL; j++ ) acc =  fd_uchar_min( (uchar)acc, xi[j] );
                                                              FD_TEST( !wb_any( wb_ne( wb_min_all( x ), wb_bcast( (uchar)acc ) )));
    acc=0UL;   for( ulong j=0UL; j<32UL; j++ ) acc =  fd_uchar_max( (uchar)acc, xi[j] );
                                                              FD_TEST( !wb_any( wb_ne( wb_max_all( x ), wb_bcast( (uchar)acc ) )));

    /* Misc operations */
    FD_TEST( (!!xi[0] & !!xi[1]) == wb_all( wb_bcast_pair( xi[0], xi[1] ) ) );
    FD_TEST( (!!xi[0] | !!xi[1]) == wb_any( wb_bcast_pair( xi[0], xi[1] ) ) );

    FD_TEST( (!!ci[0] & !!ci[1]) == wb_all_fast( wb_bcast_pair( ci[0], ci[1] ) ) );
    FD_TEST( (!!ci[0] | !!ci[1]) == wb_any_fast( wb_bcast_pair( ci[0], ci[1] ) ) );


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
