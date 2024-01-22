#include "../fd_util.h"
#include "fd_avx.h"

int wc_test( wc_t c, int    c0, int    c1, int    c2, int    c3, int    c4, int    c5, int    c6, int    c7 );
int wf_test( wf_t f, float  f0, float  f1, float  f2, float  f3, float  f4, float  f5, float  f6, float  f7 );
int wi_test( wi_t i, int    i0, int    i1, int    i2, int    i3, int    i4, int    i5, int    i6, int    i7 );
int wu_test( wu_t u, uint   u0, uint   u1, uint   u2, uint   u3, uint   u4, uint   u5, uint   u6, uint   u7 );
int wd_test( wd_t d, double d0, double d1, double d2, double d3 );
int wl_test( wl_t l, long   l0, long   l1, long   l2, long   l3 );
int wv_test( wv_t v, ulong  v0, ulong  v1, ulong  v2, ulong  v3 );
int wb_test( wb_t b, uchar const * bi );

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

# define brand() ((uchar)((fd_rng_uint( rng ) % 7U)-3U)) /* [253,254,255,0,1,2,3] */

  uchar ti[ 32 ];

# define INIT_TI( EXPR ) do { for( ulong j=0UL; j<32UL; j++ ) { ti[j] = (EXPR); } } while( 0 )

  /* TODO: Proper typing */
# define EXPAND_2_INDICES(  x, offset )                    x[ (offset) ],                    x[ (offset)+ 1UL ]
# define EXPAND_4_INDICES(  x, offset ) EXPAND_2_INDICES(  x, (offset) ), EXPAND_2_INDICES(  x, (offset)+ 2UL )
# define EXPAND_8_INDICES(  x, offset ) EXPAND_4_INDICES(  x, (offset) ), EXPAND_4_INDICES(  x, (offset)+ 4UL )
# define EXPAND_16_INDICES( x, offset ) EXPAND_8_INDICES(  x, (offset) ), EXPAND_8_INDICES(  x, (offset)+ 8UL )
# define EXPAND_32_INDICES( x, offset ) EXPAND_16_INDICES( x, (offset) ), EXPAND_16_INDICES( x, (offset)+16UL )

# define INVOKE_EXPAND( M, ... ) M(  __VA_ARGS__ )

  /* WB tests */

  INIT_TI( (uchar)0 ); FD_TEST( wb_test( wb_zero(), ti ) );
  INIT_TI( (uchar)1 ); FD_TEST( wb_test( wb_one(),  ti ) );

  for( int i=0; i<65536; i++ ) {

    /* Constructors */

    uchar xi[ 32 ]; for( ulong j=0UL; j<32UL; j++ ) xi[ j ] = brand();
    uchar yi[ 32 ]; for( ulong j=0UL; j<32UL; j++ ) yi[ j ] = brand();
    uchar ci[ 32 ]; for( ulong j=0UL; j<32UL; j++ ) ci[ j ] = (uchar)(-(fd_rng_uint( rng ) & 1U));

    wb_t x = INVOKE_EXPAND( wb, EXPAND_32_INDICES( xi, 0 ) ); FD_TEST( wb_test( x, xi ) );
    wb_t y = INVOKE_EXPAND( wb, EXPAND_32_INDICES( yi, 0 ) ); FD_TEST( wb_test( y, yi ) );
    wb_t c = INVOKE_EXPAND( wb, EXPAND_32_INDICES( ci, 0 ) ); FD_TEST( wb_test( c, ci ) );

    INIT_TI( yi[ 0          ] ); FD_TEST( wb_test( wb_bcast( yi[0] ), ti ) );

    INIT_TI( yi[ j &  1UL   ] ); FD_TEST( wb_test( wb_bcast_pair( EXPAND_2_INDICES ( yi, 0 ) ), ti ) );
    INIT_TI( yi[ j &  3UL   ] ); FD_TEST( wb_test( wb_bcast_quad( EXPAND_4_INDICES ( yi, 0 ) ), ti ) );
    INIT_TI( yi[ j &  7UL   ] ); FD_TEST( wb_test( wb_bcast_oct ( EXPAND_8_INDICES ( yi, 0 ) ), ti ) );
    INIT_TI( yi[ j & 15UL   ] ); FD_TEST( wb_test( wb_bcast_hex ( EXPAND_16_INDICES( yi, 0 ) ), ti ) );

    INIT_TI( yi[ j >> 4     ] ); FD_TEST( wb_test( wb_expand_pair( EXPAND_2_INDICES ( yi, 0 ) ), ti ) );
    INIT_TI( yi[ j >> 3     ] ); FD_TEST( wb_test( wb_expand_quad( EXPAND_4_INDICES ( yi, 0 ) ), ti ) );
    INIT_TI( yi[ j >> 2     ] ); FD_TEST( wb_test( wb_expand_oct ( EXPAND_8_INDICES ( yi, 0 ) ), ti ) );
    INIT_TI( yi[ j >> 1     ] ); FD_TEST( wb_test( wb_expand_hex ( EXPAND_16_INDICES( yi, 0 ) ), ti ) );

    INIT_TI( yi[ j ^  1     ] ); FD_TEST( wb_test( wb_exch_adj     ( y ), ti ) );
    INIT_TI( yi[ j ^  2     ] ); FD_TEST( wb_test( wb_exch_adj_pair( y ), ti ) );
    INIT_TI( yi[ j ^  4     ] ); FD_TEST( wb_test( wb_exch_adj_quad( y ), ti ) );
    INIT_TI( yi[ j ^  8     ] ); FD_TEST( wb_test( wb_exch_adj_oct ( y ), ti ) );
    INIT_TI( yi[ j ^ 16     ] ); FD_TEST( wb_test( wb_exch_adj_hex ( y ), ti ) );

    INIT_TI( yi[ j & (~1UL) ] ); FD_TEST( wb_test( wb_bcast_even( y ), ti ) );
    INIT_TI( yi[ j |   1UL  ] ); FD_TEST( wb_test( wb_bcast_odd ( y ), ti ) );

    /* Arithmetic operations */

    INIT_TI( (uchar)-xi[j]                ); FD_TEST( wb_test( wb_neg( x    ), ti ) );
    INIT_TI( fd_uchar_abs( xi[j] )        ); FD_TEST( wb_test( wb_abs( x    ), ti ) );
    INIT_TI( fd_uchar_min( xi[j], yi[j] ) ); FD_TEST( wb_test( wb_min( x, y ), ti ) );
    INIT_TI( fd_uchar_max( xi[j], yi[j] ) ); FD_TEST( wb_test( wb_max( x, y ), ti ) );
    INIT_TI( (uchar)(xi[j]+yi[j])         ); FD_TEST( wb_test( wb_add( x, y ), ti ) );
    INIT_TI( (uchar)(xi[j]-yi[j])         ); FD_TEST( wb_test( wb_sub( x, y ), ti ) );

    /* Bit operations */

    INIT_TI( (uchar)~yi[j] ); FD_TEST( wb_test( wb_not( y ), ti ) );

#   define ROL(x,n) fd_uchar_rotate_left ( (x), (n) )
#   define ROR(x,n) fd_uchar_rotate_right( (x), (n) )

#   define _(n)                                                             \
    INIT_TI( (uchar)(yi[j]<<n) ); FD_TEST( wb_test( wb_shl( y, n ), ti ) ); \
    INIT_TI( (uchar)(yi[j]>>n) ); FD_TEST( wb_test( wb_shr( y, n ), ti ) ); \
    INIT_TI( ROL( yi[j], n )   ); FD_TEST( wb_test( wb_rol( y, n ), ti ) ); \
    INIT_TI( ROR( yi[j], n )   ); FD_TEST( wb_test( wb_ror( y, n ), ti ) )
    _( 0); _( 1); _( 2); _( 3); _( 4); _( 5); _( 6); _( 7);
#   undef _

    for( int n=0; n<8; n++ ) {
      int volatile m[1]; m[0] = n;
      INIT_TI( (uchar)(yi[j]<<n) ); FD_TEST( wb_test( wb_shl_variable( y, m[0] ), ti ) );
      INIT_TI( (uchar)(yi[j]>>n) ); FD_TEST( wb_test( wb_shr_variable( y, m[0] ), ti ) );
      INIT_TI( ROL( yi[j], n )   ); FD_TEST( wb_test( wb_rol_variable( y, m[0] ), ti ) );
      INIT_TI( ROR( yi[j], n )   ); FD_TEST( wb_test( wb_ror_variable( y, m[0] ), ti ) );
    }

#   undef ROR
#   undef ROL

    INIT_TI(   xi[j]  & yi[j]        ); FD_TEST( wb_test( wb_and(    x, y ), ti ) );
    INIT_TI( ((uchar)~xi[j]) & yi[j] ); FD_TEST( wb_test( wb_andnot( x, y ), ti ) );
    INIT_TI(   xi[j]  | yi[j]        ); FD_TEST( wb_test( wb_or(     x, y ), ti ) );
    INIT_TI(   xi[j]  ^ yi[j]        ); FD_TEST( wb_test( wb_xor(    x, y ), ti ) );

    /* Logical operations */

    /* TODO: eliminate this hack (see note in fd_avx_wc.h about
       properly generalizing wc to 8/16/32/64-bit wide SIMD lanes). */

#   define wc_to_wb_raw( x ) (x)

#   define C(cond) ((uchar)(-(cond)))

    INIT_TI( C( !xi[j]) ); FD_TEST( wb_test( wc_to_wb_raw( wb_lnot   ( x ) ), ti ) );
    INIT_TI( C(!!xi[j]) ); FD_TEST( wb_test( wc_to_wb_raw( wb_lnotnot( x ) ), ti ) );

    INIT_TI( C(xi[j]==yi[j]) ); FD_TEST( wb_test( wc_to_wb_raw( wb_eq( x, y ) ), ti ) );
    INIT_TI( C(xi[j]> yi[j]) ); FD_TEST( wb_test( wc_to_wb_raw( wb_gt( x, y ) ), ti ) );
    INIT_TI( C(xi[j]< yi[j]) ); FD_TEST( wb_test( wc_to_wb_raw( wb_lt( x, y ) ), ti ) );
    INIT_TI( C(xi[j]!=yi[j]) ); FD_TEST( wb_test( wc_to_wb_raw( wb_ne( x, y ) ), ti ) );
    INIT_TI( C(xi[j]>=yi[j]) ); FD_TEST( wb_test( wc_to_wb_raw( wb_ge( x, y ) ), ti ) );
    INIT_TI( C(xi[j]<=yi[j]) ); FD_TEST( wb_test( wc_to_wb_raw( wb_le( x, y ) ), ti ) );

#   undef C

#   undef wc_to_wb_raw

    INIT_TI( ci[j]?(uchar)0:xi[j] ); FD_TEST( wb_test( wb_czero   ( c, x ), ti ) );
    INIT_TI( ci[j]?xi[j]:(uchar)0 ); FD_TEST( wb_test( wb_notczero( c, x ), ti ) );

    INIT_TI( ci[j]?xi[j]:yi[j] ); FD_TEST( wb_test( wb_if( c, x, y ), ti ) );

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

    FD_TEST( wu_test( wb_to_wu( x, 0 ), EXPAND_8_INDICES( (uint)xi,  0 ) ) );
    FD_TEST( wu_test( wb_to_wu( x, 1 ), EXPAND_8_INDICES( (uint)xi,  8 ) ) );
    FD_TEST( wu_test( wb_to_wu( x, 2 ), EXPAND_8_INDICES( (uint)xi, 16 ) ) );
    FD_TEST( wu_test( wb_to_wu( x, 3 ), EXPAND_8_INDICES( (uint)xi, 24 ) ) );

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

    acc=0UL; for( ulong j=0UL; j<32UL; j++ ) acc += xi[j];
    FD_TEST( !wb_any( wb_ne( wb_sum_all( x ), wb_bcast( (uchar)acc ) )));

    acc=255UL; for( ulong j=0UL; j<32UL; j++ ) acc = fd_uchar_min( (uchar)acc, xi[j] );
    FD_TEST( !wb_any( wb_ne( wb_min_all( x ), wb_bcast( (uchar)acc ) )));

    acc=0UL; for( ulong j=0UL; j<32UL; j++ ) acc = fd_uchar_max( (uchar)acc, xi[j] );
    FD_TEST( !wb_any( wb_ne( wb_max_all( x ), wb_bcast( (uchar)acc ) )));

    /* Misc operations */

    FD_TEST( (!!xi[0] & !!xi[1]) == wb_all( wb_bcast_pair( xi[0], xi[1] ) ) );
    FD_TEST( (!!xi[0] | !!xi[1]) == wb_any( wb_bcast_pair( xi[0], xi[1] ) ) );

    FD_TEST( (!!ci[0] & !!ci[1]) == wb_all_fast( wb_bcast_pair( ci[0], ci[1] ) ) );
    FD_TEST( (!!ci[0] | !!ci[1]) == wb_any_fast( wb_bcast_pair( ci[0], ci[1] ) ) );

  }

# undef INIT_TI

# undef brand

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
