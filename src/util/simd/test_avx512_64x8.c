#include "test_avx512.h"

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

# define brand() ((uchar)((fd_rng_uint( rng ) % 7U)-3U)) /* [253,254,255,0,1,2,3] */

  uchar ti[ 64 ];

# define INIT_TI( EXPR ) do { for( ulong j=0UL; j<64UL; j++ ) { ti[j] = (EXPR); } } while( 0 )

  /* TODO: Proper typing */
# define EXPAND_2_INDICES(  x, offset )                    x[ (offset) ],                    x[ (offset)+ 1UL ]
# define EXPAND_4_INDICES(  x, offset ) EXPAND_2_INDICES(  x, (offset) ), EXPAND_2_INDICES(  x, (offset)+ 2UL )
# define EXPAND_8_INDICES(  x, offset ) EXPAND_4_INDICES(  x, (offset) ), EXPAND_4_INDICES(  x, (offset)+ 4UL )
# define EXPAND_16_INDICES( x, offset ) EXPAND_8_INDICES(  x, (offset) ), EXPAND_8_INDICES(  x, (offset)+ 8UL )
# define EXPAND_32_INDICES( x, offset ) EXPAND_16_INDICES( x, (offset) ), EXPAND_16_INDICES( x, (offset)+16UL )
# define EXPAND_64_INDICES( x, offset ) EXPAND_32_INDICES( x, (offset) ), EXPAND_32_INDICES( x, (offset)+32UL )

# define INVOKE_EXPAND( M, ... ) M(  __VA_ARGS__ )

  /* WB tests */

  INIT_TI( (uchar)0 ); WWB_TEST( wwb_zero(), ti );
  INIT_TI( (uchar)1 ); WWB_TEST( wwb_one(),  ti );

  for( int i=0; i<65536; i++ ) {

    /* Constructors */

    uchar xi[ 64 ]; for( ulong j=0UL; j<64UL; j++ ) xi[ j ] = brand();
    uchar yi[ 64 ]; for( ulong j=0UL; j<64UL; j++ ) yi[ j ] = brand();
    uchar ci[ 64 ]; for( ulong j=0UL; j<64UL; j++ ) ci[ j ] = (uchar)(-(fd_rng_uint( rng ) & 1U));

    wwb_t x = INVOKE_EXPAND( wwb, EXPAND_64_INDICES( xi, 0 ) ); WWB_TEST( x, xi );
    wwb_t y = INVOKE_EXPAND( wwb, EXPAND_64_INDICES( yi, 0 ) ); WWB_TEST( y, yi );
    wwb_t c = INVOKE_EXPAND( wwb, EXPAND_64_INDICES( ci, 0 ) ); WWB_TEST( c, ci );

    INIT_TI( yi[ 0          ] ); WWB_TEST( wwb_bcast( yi[0] ), ti );

    INIT_TI( yi[ j &  1UL   ] ); WWB_TEST( wwb_bcast_pair( EXPAND_2_INDICES ( yi, 0 ) ), ti );
    INIT_TI( yi[ j &  3UL   ] ); WWB_TEST( wwb_bcast_quad( EXPAND_4_INDICES ( yi, 0 ) ), ti );
    INIT_TI( yi[ j &  7UL   ] ); WWB_TEST( wwb_bcast_oct ( EXPAND_8_INDICES ( yi, 0 ) ), ti );
    INIT_TI( yi[ j & 15UL   ] ); WWB_TEST( wwb_bcast_hex ( EXPAND_16_INDICES( yi, 0 ) ), ti );

    INIT_TI( yi[ j ^  1     ] ); WWB_TEST( wwb_exch_adj     ( y ), ti );
    INIT_TI( yi[ j ^  2     ] ); WWB_TEST( wwb_exch_adj_pair( y ), ti );

    /* Bit operations */

    INIT_TI( (uchar)~yi[j] ); WWB_TEST( wwb_not( y ), ti );

#   define ROL(x,n) fd_uchar_rotate_left ( (x), (n) )
#   define ROR(x,n) fd_uchar_rotate_right( (x), (n) )

#   define _(n)                                                    \
    INIT_TI( (uchar)(yi[j]<<n) ); WWB_TEST( wwb_shl( y, n ), ti ); \
    INIT_TI( (uchar)(yi[j]>>n) ); WWB_TEST( wwb_shr( y, n ), ti );
    _( 0); _( 1); _( 2); _( 3); _( 4); _( 5); _( 6); _( 7);
#   undef _

#   undef ROR
#   undef ROL

    INIT_TI(   xi[j]  & yi[j]        ); WWB_TEST( wwb_and(    x, y ), ti );
    INIT_TI( ((uchar)~xi[j]) & yi[j] ); WWB_TEST( wwb_andnot( x, y ), ti );
    INIT_TI(   xi[j]  | yi[j]        ); WWB_TEST( wwb_or(     x, y ), ti );
    INIT_TI(   xi[j]  ^ yi[j]        ); WWB_TEST( wwb_xor(    x, y ), ti );

  }

# undef INIT_TI

# undef brand

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
