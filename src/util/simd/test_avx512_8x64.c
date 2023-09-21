#include "../fd_util.h"
#include "fd_avx512.h"

FD_STATIC_ASSERT( WW_WIDTH       ==16, unit_test );
FD_STATIC_ASSERT( WW_FOOTPRINT   ==64, unit_test );
FD_STATIC_ASSERT( WW_ALIGN       ==64, unit_test );
FD_STATIC_ASSERT( WW_LG_WIDTH    == 4, unit_test );
FD_STATIC_ASSERT( WW_LG_FOOTPRINT== 6, unit_test );
FD_STATIC_ASSERT( WW_LG_ALIGN    == 6, unit_test );

#define WWL_TEST( x, x0,x1,x2,x3,x4,x5,x6,x7 ) do {                                                                 \
    long _t[8] WW_ATTR;                                                                                             \
    long _u[8] WW_ATTR;                                                                                             \
    wwl_st( _t, (x) );                                                                                              \
    _u[0] = (x0); _u[1] = (x1); _u[2] = (x2); _u[3] = (x3); _u[4] = (x4); _u[5] = (x5); _u[6] = (x6); _u[7] = (x7); \
    for( int _lane=0; _lane<8; _lane++ )                                                                            \
      if( FD_UNLIKELY( _t[_lane]!=_u[_lane] ) )                                                                     \
        FD_LOG_ERR(( "FAIL: %s @ lane %i\n\t"                                                                       \
                     "  got 0x%016lxL 0x%016lxL 0x%016lxL 0x%016lxL 0x%016lxL 0x%016lxL 0x%016lxL 0x%016lxL\n\t"    \
                     "  exp 0x%016lxL 0x%016lxL 0x%016lxL 0x%016lxL 0x%016lxL 0x%016lxL 0x%016lxL 0x%016lxL",       \
                     #x, _lane,                                                                                     \
                     (ulong)_t[0], (ulong)_t[1], (ulong)_t[2], (ulong)_t[3],                                        \
                     (ulong)_t[4], (ulong)_t[5], (ulong)_t[6], (ulong)_t[7],                                        \
                     (ulong)_u[0], (ulong)_u[1], (ulong)_u[2], (ulong)_u[3],                                        \
                     (ulong)_u[4], (ulong)_u[5], (ulong)_u[6], (ulong)_u[7] ));                                     \
  } while(0)

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  for( ulong rem=1000000UL; rem; rem-- ) {

    /* Test construct */

    long x0 = (long)fd_rng_ulong( rng ); long x1 = (long)fd_rng_ulong( rng );
    long x2 = (long)fd_rng_ulong( rng ); long x3 = (long)fd_rng_ulong( rng );
    long x4 = (long)fd_rng_ulong( rng ); long x5 = (long)fd_rng_ulong( rng );
    long x6 = (long)fd_rng_ulong( rng ); long x7 = (long)fd_rng_ulong( rng );
    wwl_t x = wwl( x0, x1, x2, x3, x4, x5, x6, x7 );
    WWL_TEST( x, x0, x1, x2, x3, x4, x5, x6, x7 );

    long y0 = (long)fd_rng_ulong( rng ); long y1 = (long)fd_rng_ulong( rng );
    long y2 = (long)fd_rng_ulong( rng ); long y3 = (long)fd_rng_ulong( rng );
    long y4 = (long)fd_rng_ulong( rng ); long y5 = (long)fd_rng_ulong( rng );
    long y6 = (long)fd_rng_ulong( rng ); long y7 = (long)fd_rng_ulong( rng );
    wwl_t y = wwl( y0, y1, y2, y3, y4, y5, y6, y7 );
    WWL_TEST( y, y0, y1, y2, y3, y4, y5, y6, y7 );

    long z0 = (long)fd_rng_ulong( rng ); long z1 = (long)fd_rng_ulong( rng );
    long z2 = (long)fd_rng_ulong( rng ); long z3 = (long)fd_rng_ulong( rng );
    long z4 = (long)fd_rng_ulong( rng ); long z5 = (long)fd_rng_ulong( rng );
    long z6 = (long)fd_rng_ulong( rng ); long z7 = (long)fd_rng_ulong( rng );
    wwl_t z = wwl( z0, z1, z2, z3, z4, z5, z6, z7 );
    WWL_TEST( z, z0, z1, z2, z3, z4, z5, z6, z7 );

    long i0; long i1; long i2; long i3; long i4; long i5; long i6; long i7;
    wwl_t i;

    long _b[16] WW_ATTR;

    /* Test permute/select */

    wwl_st( _b, y ); wwl_st( _b+8, z );

    i0 = x0 & 7L; i1 = x1 & 7L; i2 = x2 & 7L; i3 = x3 & 7L; i4 = x4 & 7L; i5 = x5 & 7L; i6 = x6 & 7L; i7 = x7 & 7L;
    i = wwl( i0, i1, i2, i3, i4, i5, i6, i7 );
    WWL_TEST( wwl_permute( i, y ), _b[ i0 ], _b[ i1 ], _b[ i2 ], _b[ i3 ], _b[ i4 ], _b[ i5 ], _b[ i6 ], _b[ i7 ] );

    i0 = x0 & 15L; i1 = x1 & 15L; i2 = x2 & 15L; i3 = x3 & 15L; i4 = x4 & 15L; i5 = x5 & 15L; i6 = x6 & 15L; i7 = x7 & 15L;
    i = wwl( i0, i1, i2, i3, i4, i5, i6, i7 );
    WWL_TEST( wwl_select( i, y, z ), _b[ i0 ], _b[ i1 ], _b[ i2 ], _b[ i3 ], _b[ i4 ], _b[ i5 ], _b[ i6 ], _b[ i7 ] );

    /* Test bcast / zero / one */

    WWL_TEST( wwl_bcast(x0), x0, x0, x0, x0, x0, x0, x0, x0 );
    WWL_TEST( wwl_zero(),    0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L );
    WWL_TEST( wwl_one(),     1L, 1L, 1L, 1L, 1L, 1L, 1L, 1L );

    /* Test ld/st */

    wwl_st( _b, x );
    WWL_TEST( wwl_ld( _b ), x0, x1, x2, x3, x4, x5, x6, x7 );

    /* Test unary ops */

    WWL_TEST( wwl_neg(x), -x0, -x1, -x2, -x3, -x4, -x5, -x6, -x7 );
    WWL_TEST( wwl_abs(x), (long)fd_long_abs(x0), (long)fd_long_abs(x1), (long)fd_long_abs(x2), (long)fd_long_abs(x3),
                          (long)fd_long_abs(x4), (long)fd_long_abs(x5), (long)fd_long_abs(x6), (long)fd_long_abs(x7) );

    WWL_TEST( wwl_min(x,y),    fd_long_min(x0,y0), fd_long_min(x1,y1), fd_long_min(x2,y2), fd_long_min(x3,y3),
                               fd_long_min(x4,y4), fd_long_min(x5,y5), fd_long_min(x6,y6), fd_long_min(x7,y7) );
    WWL_TEST( wwl_max(x,y),    fd_long_max(x0,y0), fd_long_max(x1,y1), fd_long_max(x2,y2), fd_long_max(x3,y3),
                               fd_long_max(x4,y4), fd_long_max(x5,y5), fd_long_max(x6,y6), fd_long_max(x7,y7) );
    WWL_TEST( wwl_add(x,y),    x0+y0, x1+y1, x2+y2, x3+y3, x4+y4, x5+y5, x6+y6, x7+y7 );
    WWL_TEST( wwl_sub(x,y),    x0-y0, x1-y1, x2-y2, x3-y3, x4-y4, x5-y5, x6-y6, x7-y7 );
    WWL_TEST( wwl_mul(x,y),    x0*y0, x1*y1, x2*y2, x3*y3, x4*y4, x5*y5, x6*y6, x7*y7 );
    WWL_TEST( wwl_mul_ll(x,y), ((long)(int)x0)*((long)(int)y0), ((long)(int)x1)*((long)(int)y1),
                               ((long)(int)x2)*((long)(int)y2), ((long)(int)x3)*((long)(int)y3),
                               ((long)(int)x4)*((long)(int)y4), ((long)(int)x5)*((long)(int)y5),
                               ((long)(int)x6)*((long)(int)y6), ((long)(int)x7)*((long)(int)y7) );

    /* Test binary ops */

    i0 = y0 & 63L; i1 = y1 & 63L; i2 = y2 & 63L; i3 = y3 & 63L; i4 = y4 & 63L; i5 = y5 & 63L; i6 = y6 & 63L; i7 = y7 & 63L;
    i = wwl( i0, i1, i2, i3, i4, i5, i6, i7 );

    WWL_TEST( wwl_not(x), ~x0, ~x1, ~x2, ~x3, ~x4, ~x5, ~x6, ~x7 );

    WWL_TEST( wwl_shl ( x, i0 ), x0<<i0, x1<<i0, x2<<i0, x3<<i0, x4<<i0, x5<<i0, x6<<i0, x7<<i0 );
    WWL_TEST( wwl_shr ( x, i0 ), x0>>i0, x1>>i0, x2>>i0, x3>>i0, x4>>i0, x5>>i0, x6>>i0, x7>>i0 );
    WWL_TEST( wwl_shru( x, i0 ),
              (long)(((ulong)x0)>>i0), (long)(((ulong)x1)>>i0), (long)(((ulong)x2)>>i0), (long)(((ulong)x3)>>i0),
              (long)(((ulong)x4)>>i0), (long)(((ulong)x5)>>i0), (long)(((ulong)x6)>>i0), (long)(((ulong)x7)>>i0) );

    WWL_TEST( wwl_shl_vector ( x, i ), x0<<i0, x1<<i1, x2<<i2, x3<<i3, x4<<i4, x5<<i5, x6<<i6, x7<<i7 );
    WWL_TEST( wwl_shr_vector ( x, i ), x0>>i0, x1>>i1, x2>>i2, x3>>i3, x4>>i4, x5>>i5, x6>>i6, x7>>i7 );
    WWL_TEST( wwl_shru_vector( x, i ),
              (long)(((ulong)x0)>>i0), (long)(((ulong)x1)>>i1), (long)(((ulong)x2)>>i2), (long)(((ulong)x3)>>i3),
              (long)(((ulong)x4)>>i4), (long)(((ulong)x5)>>i5), (long)(((ulong)x6)>>i6), (long)(((ulong)x7)>>i7) );

    WWL_TEST( wwl_and   (x,y),   x0  & y0,   x1  & y1,   x2  & y2,   x3  & y3,   x4  & y4,   x5  & y5,   x6  & y6,   x7  & y7 );
    WWL_TEST( wwl_andnot(x,y), (~x0) & y0, (~x1) & y1, (~x2) & y2, (~x3) & y3, (~x4) & y4, (~x5) & y5, (~x6) & y6, (~x7) & y7 );
    WWL_TEST( wwl_or    (x,y),   x0  | y0,   x1  | y1,   x2  | y2,   x3  | y3,   x4  | y4,   x5  | y5,   x6  | y6,   x7  | y7 );
    WWL_TEST( wwl_xor   (x,y),   x0  ^ y0,   x1  ^ y1,   x2  ^ y2,   x3  ^ y3,   x4  ^ y4,   x5  ^ y5,   x6  ^ y6,   x7  ^ y7 );

    /* Misc ops */

    i0 = x0 & 0xffL;
    WWL_TEST( wwl_blend( i0, y, z ), ((i0>>0)&1L) ? z0 : y0, ((i0>>1)&1L) ? z1 : y1,
                                     ((i0>>2)&1L) ? z2 : y2, ((i0>>3)&1L) ? z3 : y3,
                                     ((i0>>4)&1L) ? z4 : y4, ((i0>>5)&1L) ? z5 : y5,
                                     ((i0>>6)&1L) ? z6 : y6, ((i0>>7)&1L) ? z7 : y7 );

    WWL_TEST( wwl_pack_halves( y,0, z,0 ), y0,y1,y2,y3, z0,z1,z2,z3 );
    WWL_TEST( wwl_pack_halves( y,1, z,0 ), y4,y5,y6,y7, z0,z1,z2,z3 );
    WWL_TEST( wwl_pack_halves( y,0, z,1 ), y0,y1,y2,y3, z4,z5,z6,z7 );
    WWL_TEST( wwl_pack_halves( y,1, z,1 ), y4,y5,y6,y7, z4,z5,z6,z7 );
    WWL_TEST( wwl_pack_h0_h1 ( y,   z   ), y0,y1,y2,y3, z4,z5,z6,z7 );

    long const m52 = (1L<<52)-1L;

#   define MADD52LO(x,y,z) ((x) + (((long)((((uint128)((y) & m52))*((uint128)((z) & m52)))    ))&m52))
#   define MADD52HI(x,y,z) ((x) + (((long)((((uint128)((y) & m52))*((uint128)((z) & m52)))>>52))    ))
    WWL_TEST( wwl_madd52lo( x, y, z ), MADD52LO(x0,y0,z0), MADD52LO(x1,y1,z1), MADD52LO(x2,y2,z2), MADD52LO(x3,y3,z3),
                                       MADD52LO(x4,y4,z4), MADD52LO(x5,y5,z5), MADD52LO(x6,y6,z6), MADD52LO(x7,y7,z7) );
    WWL_TEST( wwl_madd52hi( x, y, z ), MADD52HI(x0,y0,z0), MADD52HI(x1,y1,z1), MADD52HI(x2,y2,z2), MADD52HI(x3,y3,z3),
                                       MADD52HI(x4,y4,z4), MADD52HI(x5,y5,z5), MADD52HI(x6,y6,z6), MADD52HI(x7,y7,z7) );

    WWL_TEST( wwl_slide( x, y, 0 ), x0,x1,x2,x3,x4,x5,x6,x7 );
    WWL_TEST( wwl_slide( x, y, 1 ), x1,x2,x3,x4,x5,x6,x7,y0 );
    WWL_TEST( wwl_slide( x, y, 2 ), x2,x3,x4,x5,x6,x7,y0,y1 );
    WWL_TEST( wwl_slide( x, y, 3 ), x3,x4,x5,x6,x7,y0,y1,y2 );
    WWL_TEST( wwl_slide( x, y, 4 ), x4,x5,x6,x7,y0,y1,y2,y3 );
    WWL_TEST( wwl_slide( x, y, 5 ), x5,x6,x7,y0,y1,y2,y3,y4 );
    WWL_TEST( wwl_slide( x, y, 6 ), x6,x7,y0,y1,y2,y3,y4,y5 );
    WWL_TEST( wwl_slide( x, y, 7 ), x7,y0,y1,y2,y3,y4,y5,y6 );
  }

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
