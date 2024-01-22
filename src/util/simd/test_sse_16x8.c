#include "../fd_util.h"
#include "fd_sse.h"

int vc_test( vc_t c, int    c0, int    c1, int    c2, int    c3 );
int vf_test( vf_t f, float  f0, float  f1, float  f2, float  f3 );
int vi_test( vi_t i, int    i0, int    i1, int    i2, int    i3 );
int vu_test( vu_t u, uint   u0, uint   u1, uint   u2, uint   u3 );
int vd_test( vd_t d, double d0, double d1 );
int vl_test( vl_t l, long   l0, long   l1 );
int vv_test( vv_t v, ulong  v0, ulong  v1 );
int vb_test( vb_t b, uchar const * bi );

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

# define brand() ((uchar)((fd_rng_uint( rng ) % 7U)-3U)) /* [253,254,255,0,1,2,3] */

  uchar ti[ 16 ];

# define INIT_TI( EXPR ) do { for( ulong j=0UL; j<16UL; j++ ) { ti[j] = (EXPR); } } while( 0 )

  /* TODO: Proper typing */
# define EXPAND_2_INDICES(  x, offset )                    x[ (offset) ],                    x[ (offset)+ 1UL ]
# define EXPAND_4_INDICES(  x, offset ) EXPAND_2_INDICES(  x, (offset) ), EXPAND_2_INDICES(  x, (offset)+ 2UL )
# define EXPAND_8_INDICES(  x, offset ) EXPAND_4_INDICES(  x, (offset) ), EXPAND_4_INDICES(  x, (offset)+ 4UL )
# define EXPAND_16_INDICES( x, offset ) EXPAND_8_INDICES(  x, (offset) ), EXPAND_8_INDICES(  x, (offset)+ 8UL )

# define INVOKE_EXPAND( M, ... ) M(  __VA_ARGS__ )

  /* VB tests */

  INIT_TI( (uchar)0 ); FD_TEST( vb_test( vb_zero(), ti ) );
  INIT_TI( (uchar)1 ); FD_TEST( vb_test( vb_one(),  ti ) );

  for( int i=0; i<65536; i++ ) {

    /* Constructors */

    uchar xi[ 16 ]; for( ulong j=0UL; j<16UL; j++ ) xi[ j ] = brand();
    uchar yi[ 16 ]; for( ulong j=0UL; j<16UL; j++ ) yi[ j ] = brand();
    uchar ci[ 16 ]; for( ulong j=0UL; j<16UL; j++ ) ci[ j ] = (uchar)(fd_rng_uint( rng ) & 1 ? 0xFF : 0);

    vb_t x = INVOKE_EXPAND( vb, EXPAND_16_INDICES( xi, 0 ) ); FD_TEST( vb_test( x, xi ) );
    vb_t y = INVOKE_EXPAND( vb, EXPAND_16_INDICES( yi, 0 ) ); FD_TEST( vb_test( y, yi ) );
    vb_t c = INVOKE_EXPAND( vb, EXPAND_16_INDICES( ci, 0 ) ); FD_TEST( vb_test( c, ci ) );

    INIT_TI( yi[ 0          ] ); FD_TEST( vb_test( vb_bcast( yi[0] ), ti ) );

    INIT_TI( yi[ j & 1UL    ] ); FD_TEST( vb_test( vb_bcast_pair( EXPAND_2_INDICES( yi, 0 ) ), ti )  );
    INIT_TI( yi[ j & 3UL    ] ); FD_TEST( vb_test( vb_bcast_quad( EXPAND_4_INDICES( yi, 0 ) ), ti )  );
    INIT_TI( yi[ j & 7UL    ] ); FD_TEST( vb_test( vb_bcast_oct ( EXPAND_8_INDICES( yi, 0 ) ), ti )  );

    INIT_TI( yi[ j >> 3     ] ); FD_TEST( vb_test( vb_expand_pair( EXPAND_2_INDICES( yi, 0 ) ), ti )  );
    INIT_TI( yi[ j >> 2     ] ); FD_TEST( vb_test( vb_expand_quad( EXPAND_4_INDICES( yi, 0 ) ), ti )  );
    INIT_TI( yi[ j >> 1     ] ); FD_TEST( vb_test( vb_expand_oct ( EXPAND_8_INDICES( yi, 0 ) ), ti )  );

    INIT_TI( yi[ j ^ 1      ] ); FD_TEST( vb_test( vb_exch_adj     (  y ), ti ) );
    INIT_TI( yi[ j ^ 2      ] ); FD_TEST( vb_test( vb_exch_adj_pair(  y ), ti ) );
    INIT_TI( yi[ j ^ 4      ] ); FD_TEST( vb_test( vb_exch_adj_quad(  y ), ti ) );
    INIT_TI( yi[ j ^ 8      ] ); FD_TEST( vb_test( vb_exch_adj_oct (  y ), ti ) );

    INIT_TI( yi[ j & (~1UL) ] ); FD_TEST( vb_test( vb_bcast_even( y ), ti ) );
    INIT_TI( yi[ j |   1UL  ] ); FD_TEST( vb_test( vb_bcast_odd ( y ), ti ) );

    /* Arithmetic operations */

    INIT_TI( (uchar)-xi[j]                ); FD_TEST( vb_test( vb_neg( x    ), ti ) );
    INIT_TI( fd_uchar_abs( xi[j] )        ); FD_TEST( vb_test( vb_abs( x    ), ti ) );
    INIT_TI( fd_uchar_min( xi[j], yi[j] ) ); FD_TEST( vb_test( vb_min( x, y ), ti ) );
    INIT_TI( fd_uchar_max( xi[j], yi[j] ) ); FD_TEST( vb_test( vb_max( x, y ), ti ) );
    INIT_TI( (uchar)(xi[j]+yi[j])         ); FD_TEST( vb_test( vb_add( x, y ), ti ) );
    INIT_TI( (uchar)(xi[j]-yi[j])         ); FD_TEST( vb_test( vb_sub( x, y ), ti ) );

    /* Bit operations */

    INIT_TI( (uchar)~yi[j] ); FD_TEST( vb_test( vb_not( y ), ti ) );

#   define ROL(x,n) fd_uchar_rotate_left ( (x), (n) )
#   define ROR(x,n) fd_uchar_rotate_right( (x), (n) )

#   define _(n)                                                             \
    INIT_TI( (uchar)(yi[j]<<n) ); FD_TEST( vb_test( vb_shl( y, n ), ti ) ); \
    INIT_TI( (uchar)(yi[j]>>n) ); FD_TEST( vb_test( vb_shr( y, n ), ti ) ); \
    INIT_TI( ROL( yi[j], n )   ); FD_TEST( vb_test( vb_rol( y, n ), ti ) ); \
    INIT_TI( ROR( yi[j], n )   ); FD_TEST( vb_test( vb_ror( y, n ), ti ) )
    _( 0); _( 1); _( 2); _( 3); _( 4); _( 5); _( 6); _( 7);
#   undef _

    for( int n=0; n<8; n++ ) {
      int volatile m[1]; m[0] = n;
      INIT_TI( (uchar)(yi[j]<<n) ); FD_TEST( vb_test( vb_shl_variable( y, m[0] ), ti ) );
      INIT_TI( (uchar)(yi[j]>>n) ); FD_TEST( vb_test( vb_shr_variable( y, m[0] ), ti ) );
      INIT_TI( ROL( yi[j], n )   ); FD_TEST( vb_test( vb_rol_variable( y, m[0] ), ti ) );
      INIT_TI( ROR( yi[j], n )   ); FD_TEST( vb_test( vb_ror_variable( y, m[0] ), ti ) );
    }

#   undef ROR
#   undef ROL

    INIT_TI(   xi[j]  & yi[j]        ); FD_TEST( vb_test( vb_and(    x, y ), ti ) );
    INIT_TI( ((uchar)~xi[j]) & yi[j] ); FD_TEST( vb_test( vb_andnot( x, y ), ti ) );
    INIT_TI(   xi[j]  | yi[j]        ); FD_TEST( vb_test( vb_or(     x, y ), ti ) );
    INIT_TI(   xi[j]  ^ yi[j]        ); FD_TEST( vb_test( vb_xor(    x, y ), ti ) );

    /* Logical operations */

    /* TODO: eliminate this hack (see note in fd_sse_vc.h about
       properly generalizing vc to 8/16/32/64-bit wide SIMD lanes). */

#   define vc_to_vb_raw( x ) (x)

#   define C(cond) ((uchar)(-(cond)))

    INIT_TI( C( !xi[j]) ); FD_TEST( vb_test( vc_to_vb_raw( vb_lnot   ( x ) ), ti ) );
    INIT_TI( C(!!xi[j]) ); FD_TEST( vb_test( vc_to_vb_raw( vb_lnotnot( x ) ), ti ) );

    INIT_TI( C(xi[j]==yi[j]) ); FD_TEST( vb_test( vc_to_vb_raw( vb_eq( x, y ) ), ti ) );
    INIT_TI( C(xi[j]> yi[j]) ); FD_TEST( vb_test( vc_to_vb_raw( vb_gt( x, y ) ), ti ) );
    INIT_TI( C(xi[j]< yi[j]) ); FD_TEST( vb_test( vc_to_vb_raw( vb_lt( x, y ) ), ti ) );
    INIT_TI( C(xi[j]!=yi[j]) ); FD_TEST( vb_test( vc_to_vb_raw( vb_ne( x, y ) ), ti ) );
    INIT_TI( C(xi[j]>=yi[j]) ); FD_TEST( vb_test( vc_to_vb_raw( vb_ge( x, y ) ), ti ) );
    INIT_TI( C(xi[j]<=yi[j]) ); FD_TEST( vb_test( vc_to_vb_raw( vb_le( x, y ) ), ti ) );

#   undef C

#   undef vc_to_vb_raw

    INIT_TI( ci[j]?(uchar)0:xi[j] ); FD_TEST( vb_test( vb_czero(    c, x ), ti ) );
    INIT_TI( ci[j]?xi[j]:(uchar)0 ); FD_TEST( vb_test( vb_notczero( c, x ), ti ) );

    INIT_TI( ci[j]?xi[j]:yi[j] ); FD_TEST( vb_test( vb_if( c, x, y ),    ti ) );

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

    FD_TEST( vu_test( vb_to_vu( x, 0 ), EXPAND_4_INDICES( (uint)xi,  0 ) ) );
    FD_TEST( vu_test( vb_to_vu( x, 1 ), EXPAND_4_INDICES( (uint)xi,  4 ) ) );
    FD_TEST( vu_test( vb_to_vu( x, 2 ), EXPAND_4_INDICES( (uint)xi,  8 ) ) );
    FD_TEST( vu_test( vb_to_vu( x, 3 ), EXPAND_4_INDICES( (uint)xi, 12 ) ) );

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

    acc=0UL; for( ulong j=0UL; j<16UL; j++ ) acc += xi[j];
    FD_TEST( !vb_any( vb_ne( vb_sum_all( x ), vb_bcast( (uchar)acc ) )));

    acc=255UL; for( ulong j=0UL; j<16UL; j++ ) acc = fd_uchar_min( (uchar)acc, xi[j] );
    FD_TEST( !vb_any( vb_ne( vb_min_all( x ), vb_bcast( (uchar)acc ) )));

    acc=0UL; for( ulong j=0UL; j<16UL; j++ ) acc = fd_uchar_max( (uchar)acc, xi[j] );
    FD_TEST( !vb_any( vb_ne( vb_max_all( x ), vb_bcast( (uchar)acc ) )));

    /* Misc operations */

    FD_TEST( (!!xi[0] & !!xi[1]) == vb_all( vb_bcast_pair( xi[0], xi[1] ) ) );
    FD_TEST( (!!xi[0] | !!xi[1]) == vb_any( vb_bcast_pair( xi[0], xi[1] ) ) );

    FD_TEST( (!!ci[0] & !!ci[1]) == vb_all_fast( vb_bcast_pair( ci[0], ci[1] ) ) );
    FD_TEST( (!!ci[0] | !!ci[1]) == vb_any_fast( vb_bcast_pair( ci[0], ci[1] ) ) );

  }

# undef INIT_TI

# undef brand

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
