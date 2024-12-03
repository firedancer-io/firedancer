#include "../fd_util.h"
#include "fd_avx.h"

/* From test_avx_common.c */

int wc_test( wc_t c, int    c0, int    c1, int    c2, int    c3, int    c4, int    c5, int    c6, int    c7 );
int ws_test( ws_t s, short  const * si );
int wh_test( wh_t h, ushort const * hj );

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

# define hrand() ((ushort)((fd_rng_uint( rng ) % 7U)-3U)) /* [65533,65534,65535,0,1,2,3] */

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  /* TODO: Proper typing */
# define EXPAND_2_INDICES(  x, offset )                    x[ (offset) ],                    x[ (offset)+ 1UL ]
# define EXPAND_4_INDICES(  x, offset ) EXPAND_2_INDICES(  x, (offset) ), EXPAND_2_INDICES(  x, (offset)+ 2UL )
# define EXPAND_8_INDICES(  x, offset ) EXPAND_4_INDICES(  x, (offset) ), EXPAND_4_INDICES(  x, (offset)+ 4UL )
# define EXPAND_16_INDICES( x, offset ) EXPAND_8_INDICES(  x, (offset) ), EXPAND_8_INDICES(  x, (offset)+ 8UL )

# define INVOKE_EXPAND( M, ... ) M(  __VA_ARGS__ )

  /* WH tests */

  ushort hj[ 16 ];
# define INIT_HJ( EXPR ) do { for( ulong j=0UL; j<16UL; j++ ) { hj[j] = (EXPR); } } while(0)

  INIT_HJ( (ushort)0 ); FD_TEST( wh_test( wh_zero(), hj ) );
  INIT_HJ( (ushort)1 ); FD_TEST( wh_test( wh_one(),  hj ) );

  for( int i=0; i<65536; i++ ) {

    /* Constructors */

    ushort xi[ 16 ]; for( ulong j=0UL; j<16UL; j++ ) xi[ j ] = hrand();
    ushort yi[ 16 ]; for( ulong j=0UL; j<16UL; j++ ) yi[ j ] = hrand();

    INIT_HJ( yi[ 0 ] ); FD_TEST( wh_test( wh_bcast( yi[0] ), hj ) );

    wh_t x = INVOKE_EXPAND( wh, EXPAND_16_INDICES( xi, 0 ) ); FD_TEST( wh_test( x, xi ) );
    wh_t y = INVOKE_EXPAND( wh, EXPAND_16_INDICES( yi, 0 ) ); FD_TEST( wh_test( y, yi ) );

    /* Arithmetic operations */

    INIT_HJ( (ushort)-xi[j]                              ); FD_TEST( wh_test( wh_neg(   x    ), hj ) );
    INIT_HJ( fd_ushort_abs( xi[j] )                      ); FD_TEST( wh_test( wh_abs(   x    ), hj ) );
    INIT_HJ( fd_ushort_min( xi[j], yi[j] )               ); FD_TEST( wh_test( wh_min(   x, y ), hj ) );
    INIT_HJ( fd_ushort_max( xi[j], yi[j] )               ); FD_TEST( wh_test( wh_max(   x, y ), hj ) );
    INIT_HJ( (ushort)(xi[j]+yi[j])                       ); FD_TEST( wh_test( wh_add(   x, y ), hj ) );
    INIT_HJ( (ushort)(xi[j]-yi[j])                       ); FD_TEST( wh_test( wh_sub(   x, y ), hj ) );
    INIT_HJ( (ushort)(xi[j]*yi[j])                       ); FD_TEST( wh_test( wh_mul(   x, y ), hj ) );
    /*                                                   */ FD_TEST( wh_test( wh_mullo( x, y ), hj ) );
    INIT_HJ( (ushort)((((uint)xi[j])*((uint)yi[j]))>>16) ); FD_TEST( wh_test( wh_mulhi( x, y ), hj ) );

    /* Logical operations */

    /* TODO: eliminate this hack (see note in fd_avx_wc.h about
       properly generalizing wc to 8/16/32/64-bit wide SIMD lanes). */

#   define wc_to_wh_raw( x ) (x)

#   define C(cond) ((ushort)(-(cond)))

    INIT_HJ( C(xi[j]==yi[j]) ); FD_TEST( wh_test( wc_to_wh_raw( wh_eq( x, y ) ), hj ) );
    INIT_HJ( C(xi[j]!=yi[j]) ); FD_TEST( wh_test( wc_to_wh_raw( wh_ne( x, y ) ), hj ) );

  }

# undef hrand

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
