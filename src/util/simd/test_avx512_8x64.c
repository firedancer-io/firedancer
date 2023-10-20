#include "test_avx512.h"

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  FD_LOG_NOTICE(( "Testing wwl_t" ));

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

    /* Test bcast/zero/one */

    WWL_TEST( wwl_bcast(x0), x0, x0, x0, x0, x0, x0, x0, x0 );
    WWL_TEST( wwl_zero(),    0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L );
    WWL_TEST( wwl_one(),     1L, 1L, 1L, 1L, 1L, 1L, 1L, 1L );

    /* Test ld/st/ldu/stu */

    wwl_st( _b, x );
    WWL_TEST( wwl_ld( _b ), x0, x1, x2, x3, x4, x5, x6, x7 );

    uchar _m[128] WW_ATTR;
    i0 = x0 & 63L;
    wwl_stu( _m+i0, y );
    WWL_TEST( wwl_ldu( _m+i0 ), y0, y1, y2, y3, y4, y5, y6, y7 );

    /* Test arithmetic ops */

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

    /* Test bit ops */

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

#   define ROL(x,y) (long)fd_ulong_rotate_left ( (ulong)(x), (int)(uint)(y) )
#   define ROR(x,y) (long)fd_ulong_rotate_right( (ulong)(x), (int)(uint)(y) )
    WWL_TEST( wwl_rol( x, y0 ),       ROL( x0, y0 ), ROL( x1, y0 ), ROL( x2, y0 ), ROL( x3, y0 ),
                                      ROL( x4, y0 ), ROL( x5, y0 ), ROL( x6, y0 ), ROL( x7, y0 ) );
    WWL_TEST( wwl_ror( x, y0 ),       ROR( x0, y0 ), ROR( x1, y0 ), ROR( x2, y0 ), ROR( x3, y0 ),
                                      ROR( x4, y0 ), ROR( x5, y0 ), ROR( x6, y0 ), ROR( x7, y0 ) );
    WWL_TEST( wwl_rol_vector( x, y ), ROL( x0, y0 ), ROL( x1, y1 ), ROL( x2, y2 ), ROL( x3, y3 ),
                                      ROL( x4, y4 ), ROL( x5, y5 ), ROL( x6, y6 ), ROL( x7, y7 ) );
    WWL_TEST( wwl_ror_vector( x, y ), ROR( x0, y0 ), ROR( x1, y1 ), ROR( x2, y2 ), ROR( x3, y3 ),
                                      ROR( x4, y4 ), ROR( x5, y5 ), ROR( x6, y6 ), ROR( x7, y7 ) );
#   undef ROR
#   undef ROL

    /* Test comparison */

    int c = (int)(fd_rng_uint( rng ) & 255U);
    wwl_t t = wwl_if( c, x, y );
    wwl_st( _b, t );
    long t0 = _b[0]; long t1 = _b[1]; long t2 = _b[2]; long t3 = _b[3];
    long t4 = _b[4]; long t5 = _b[5]; long t6 = _b[6]; long t7 = _b[7];

#   define TEST_CMP(fn,op)                                                                                      \
    FD_TEST( fn(x,t)==( ((x##0 op t##0)<<0) | ((x##1 op t##1)<<1) | ((x##2 op t##2)<<2) | ((x##3 op t##3)<<3) | \
                        ((x##4 op t##4)<<4) | ((x##5 op t##5)<<5) | ((x##6 op t##6)<<6) | ((x##7 op t##7)<<7) ) );

    TEST_CMP( wwl_eq, == );
    TEST_CMP( wwl_gt, >  );
    TEST_CMP( wwl_lt, <  );

    TEST_CMP( wwl_ne, != );
    TEST_CMP( wwl_ge, >= );
    TEST_CMP( wwl_le, <= );

    wwl_t tt = wwl_if( c, wwl_or( x, wwl_one() ), wwl_zero() );
    FD_TEST( wwl_lnot   ( tt )==wwl_eq( tt, wwl_zero() ) );
    FD_TEST( wwl_lnotnot( tt )==wwl_ne( tt, wwl_zero() ) );

#   undef TEST_CMP

    /* Test lane ops */

    WWL_TEST( wwl_if( c, y, z ),
              ((c>>0)&1) ? y0 : z0, ((c>>1)&1) ? y1 : z1, ((c>>2)&1) ? y2 : z2, ((c>>3)&1) ? y3 : z3,
              ((c>>4)&1) ? y4 : z4, ((c>>5)&1) ? y5 : z5, ((c>>6)&1) ? y6 : z6, ((c>>7)&1) ? y7 : z7 );
    WWL_TEST( wwl_add_if( c, x, y, z ),
              ((c>>0)&1) ? (x0+y0) : z0, ((c>>1)&1) ? (x1+y1) : z1, ((c>>2)&1) ? (x2+y2) : z2, ((c>>3)&1) ? (x3+y3) : z3,
              ((c>>4)&1) ? (x4+y4) : z4, ((c>>5)&1) ? (x5+y5) : z5, ((c>>6)&1) ? (x6+y6) : z6, ((c>>7)&1) ? (x7+y7) : z7 );
    WWL_TEST( wwl_sub_if( c, x, y, z ),
              ((c>>0)&1) ? (x0-y0) : z0, ((c>>1)&1) ? (x1-y1) : z1, ((c>>2)&1) ? (x2-y2) : z2, ((c>>3)&1) ? (x3-y3) : z3,
              ((c>>4)&1) ? (x4-y4) : z4, ((c>>5)&1) ? (x5-y5) : z5, ((c>>6)&1) ? (x6-y6) : z6, ((c>>7)&1) ? (x7-y7) : z7 );

    /* Test conversions */

    WWI_TEST( wwl_to_wwi(x),  (int)x0,0,  (int)x1,0,  (int)x2,0,  (int)x3,0,  (int)x4,0,  (int)x5,0,  (int)x6,0,  (int)x7,0 );
    WWU_TEST( wwl_to_wwu(x), (uint)x0,0, (uint)x1,0, (uint)x2,0, (uint)x3,0, (uint)x4,0, (uint)x5,0, (uint)x6,0, (uint)x7,0 );
    WWV_TEST( wwl_to_wwv(x), (ulong)x0,  (ulong)x1,  (ulong)x2,  (ulong)x3,  (ulong)x4,  (ulong)x5,  (ulong)x6,  (ulong)x7  );

    /* Test misc operations */

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
#   undef MADD52HI
#   undef MADD52LO

    WWL_TEST( wwl_slide( x, y, 0 ), x0,x1,x2,x3,x4,x5,x6,x7 );
    WWL_TEST( wwl_slide( x, y, 1 ), x1,x2,x3,x4,x5,x6,x7,y0 );
    WWL_TEST( wwl_slide( x, y, 2 ), x2,x3,x4,x5,x6,x7,y0,y1 );
    WWL_TEST( wwl_slide( x, y, 3 ), x3,x4,x5,x6,x7,y0,y1,y2 );
    WWL_TEST( wwl_slide( x, y, 4 ), x4,x5,x6,x7,y0,y1,y2,y3 );
    WWL_TEST( wwl_slide( x, y, 5 ), x5,x6,x7,y0,y1,y2,y3,y4 );
    WWL_TEST( wwl_slide( x, y, 6 ), x6,x7,y0,y1,y2,y3,y4,y5 );
    WWL_TEST( wwl_slide( x, y, 7 ), x7,y0,y1,y2,y3,y4,y5,y6 );

    wwl_unpack( x, t0,t1,t2,t3,t4,t5,t6,t7 );
    WWL_TEST( wwl( t0,t1,t2,t3,t4,t5,t6,t7 ), x0,x1,x2,x3,x4,x5,x6,x7 );

    wwl_t r0 = x;            wwl_t r1 = y;            wwl_t r2 = z;            wwl_t r3 = t;
    wwl_t r4 = wwl_not( x ); wwl_t r5 = wwl_not( y ); wwl_t r6 = wwl_not( z ); wwl_t r7 = wwl_not( t );

    long A[64] WW_ATTR;
    wwl_st( A,    r0 ); wwl_st( A+ 8, r1 ); wwl_st( A+16, r2 ); wwl_st( A+24, r3 );
    wwl_st( A+32, r4 ); wwl_st( A+40, r5 ); wwl_st( A+48, r6 ); wwl_st( A+56, r7 );

    wwl_t c0; wwl_t c1; wwl_t c2; wwl_t c3; wwl_t c4; wwl_t c5; wwl_t c6; wwl_t c7;
    wwl_transpose_8x8( r0,r1,r2,r3,r4,r5,r6,r7, c0,c1,c2,c3,c4,c5,c6,c7 );

    long AT[64] WW_ATTR;
    wwl_st( AT,    c0 ); wwl_st( AT+ 8, c1 ); wwl_st( AT+16, c2 ); wwl_st( AT+24, c3 );
    wwl_st( AT+32, c4 ); wwl_st( AT+40, c5 ); wwl_st( AT+48, c6 ); wwl_st( AT+56, c7 );

    for( int ii=0; ii<8; ii++ ) for( int jj=0; jj<8; jj++ ) FD_TEST( A[ii+8*jj]==AT[jj+8*ii] );
  }

  FD_LOG_NOTICE(( "Testing wwv_t" ));

  for( ulong rem=1000000UL; rem; rem-- ) {

    /* Test construct */

    ulong x0 = fd_rng_ulong( rng ); ulong x1 = fd_rng_ulong( rng );
    ulong x2 = fd_rng_ulong( rng ); ulong x3 = fd_rng_ulong( rng );
    ulong x4 = fd_rng_ulong( rng ); ulong x5 = fd_rng_ulong( rng );
    ulong x6 = fd_rng_ulong( rng ); ulong x7 = fd_rng_ulong( rng );
    wwv_t x = wwv( x0, x1, x2, x3, x4, x5, x6, x7 );
    WWV_TEST( x, x0, x1, x2, x3, x4, x5, x6, x7 );

    ulong y0 = fd_rng_ulong( rng ); ulong y1 = fd_rng_ulong( rng );
    ulong y2 = fd_rng_ulong( rng ); ulong y3 = fd_rng_ulong( rng );
    ulong y4 = fd_rng_ulong( rng ); ulong y5 = fd_rng_ulong( rng );
    ulong y6 = fd_rng_ulong( rng ); ulong y7 = fd_rng_ulong( rng );
    wwv_t y = wwv( y0, y1, y2, y3, y4, y5, y6, y7 );
    WWV_TEST( y, y0, y1, y2, y3, y4, y5, y6, y7 );

    ulong z0 = fd_rng_ulong( rng ); ulong z1 = fd_rng_ulong( rng );
    ulong z2 = fd_rng_ulong( rng ); ulong z3 = fd_rng_ulong( rng );
    ulong z4 = fd_rng_ulong( rng ); ulong z5 = fd_rng_ulong( rng );
    ulong z6 = fd_rng_ulong( rng ); ulong z7 = fd_rng_ulong( rng );
    wwv_t z = wwv( z0, z1, z2, z3, z4, z5, z6, z7 );
    WWV_TEST( z, z0, z1, z2, z3, z4, z5, z6, z7 );

    ulong i0; ulong i1; ulong i2; ulong i3; ulong i4; ulong i5; ulong i6; ulong i7;
    wwv_t i;

    ulong _b[16] WW_ATTR;

    /* Test permute/select */

    wwv_st( _b, y ); wwv_st( _b+8, z );

    i0 = x0 & 7UL; i1 = x1 & 7UL; i2 = x2 & 7UL; i3 = x3 & 7UL; i4 = x4 & 7UL; i5 = x5 & 7UL; i6 = x6 & 7UL; i7 = x7 & 7UL;
    i = wwv( i0, i1, i2, i3, i4, i5, i6, i7 );
    WWV_TEST( wwv_permute( i, y ), _b[ i0 ], _b[ i1 ], _b[ i2 ], _b[ i3 ], _b[ i4 ], _b[ i5 ], _b[ i6 ], _b[ i7 ] );

    i0 = x0 & 15UL; i1 = x1 & 15UL; i2 = x2 & 15UL; i3 = x3 & 15UL; i4 = x4 & 15UL; i5 = x5 & 15UL; i6 = x6 & 15UL; i7 = x7 & 15UL;
    i = wwv( i0, i1, i2, i3, i4, i5, i6, i7 );
    WWV_TEST( wwv_select( i, y, z ), _b[ i0 ], _b[ i1 ], _b[ i2 ], _b[ i3 ], _b[ i4 ], _b[ i5 ], _b[ i6 ], _b[ i7 ] );

    /* Test bcast/zero/one */

    WWV_TEST( wwv_bcast(x0), x0,  x0,  x0,  x0,  x0,  x0,  x0,  x0  );
    WWV_TEST( wwv_zero(),    0UL, 0UL, 0UL, 0UL, 0UL, 0UL, 0UL, 0UL );
    WWV_TEST( wwv_one(),     1UL, 1UL, 1UL, 1UL, 1UL, 1UL, 1UL, 1UL );

    /* Test ld/st/ldu/stu */

    wwv_st( _b, x );
    WWV_TEST( wwv_ld( _b ), x0, x1, x2, x3, x4, x5, x6, x7 );

    uchar _m[128] WW_ATTR;
    i0 = x0 & 63UL;
    wwv_stu( _m+i0, y );
    WWV_TEST( wwv_ldu( _m+i0 ), y0, y1, y2, y3, y4, y5, y6, y7 );

    /* Test arithmetic ops */

    WWV_TEST( wwv_neg(x), -x0, -x1, -x2, -x3, -x4, -x5, -x6, -x7 );
    WWV_TEST( wwv_abs(x),  x0,  x1,  x2,  x3,  x4,  x5,  x6,  x7 );

    WWV_TEST( wwv_min(x,y),    fd_ulong_min(x0,y0), fd_ulong_min(x1,y1), fd_ulong_min(x2,y2), fd_ulong_min(x3,y3),
                               fd_ulong_min(x4,y4), fd_ulong_min(x5,y5), fd_ulong_min(x6,y6), fd_ulong_min(x7,y7) );
    WWV_TEST( wwv_max(x,y),    fd_ulong_max(x0,y0), fd_ulong_max(x1,y1), fd_ulong_max(x2,y2), fd_ulong_max(x3,y3),
                               fd_ulong_max(x4,y4), fd_ulong_max(x5,y5), fd_ulong_max(x6,y6), fd_ulong_max(x7,y7) );
    WWV_TEST( wwv_add(x,y),    x0+y0, x1+y1, x2+y2, x3+y3, x4+y4, x5+y5, x6+y6, x7+y7 );
    WWV_TEST( wwv_sub(x,y),    x0-y0, x1-y1, x2-y2, x3-y3, x4-y4, x5-y5, x6-y6, x7-y7 );
    WWV_TEST( wwv_mul(x,y),    x0*y0, x1*y1, x2*y2, x3*y3, x4*y4, x5*y5, x6*y6, x7*y7 );
    WWV_TEST( wwv_mul_ll(x,y), ((ulong)(uint)x0)*((ulong)(uint)y0), ((ulong)(uint)x1)*((ulong)(uint)y1),
                               ((ulong)(uint)x2)*((ulong)(uint)y2), ((ulong)(uint)x3)*((ulong)(uint)y3),
                               ((ulong)(uint)x4)*((ulong)(uint)y4), ((ulong)(uint)x5)*((ulong)(uint)y5),
                               ((ulong)(uint)x6)*((ulong)(uint)y6), ((ulong)(uint)x7)*((ulong)(uint)y7) );

    /* Test bit ops */

    i0 = y0 & 63UL; i1 = y1 & 63UL; i2 = y2 & 63UL; i3 = y3 & 63UL; i4 = y4 & 63UL; i5 = y5 & 63UL; i6 = y6 & 63UL; i7 = y7 & 63UL;
    i = wwv( i0, i1, i2, i3, i4, i5, i6, i7 );

    WWV_TEST( wwv_not(x), ~x0, ~x1, ~x2, ~x3, ~x4, ~x5, ~x6, ~x7 );

    WWV_TEST( wwv_shl       ( x, i0 ), x0<<i0, x1<<i0, x2<<i0, x3<<i0, x4<<i0, x5<<i0, x6<<i0, x7<<i0 );
    WWV_TEST( wwv_shr       ( x, i0 ), x0>>i0, x1>>i0, x2>>i0, x3>>i0, x4>>i0, x5>>i0, x6>>i0, x7>>i0 );
    WWV_TEST( wwv_shl_vector( x, i  ), x0<<i0, x1<<i1, x2<<i2, x3<<i3, x4<<i4, x5<<i5, x6<<i6, x7<<i7 );
    WWV_TEST( wwv_shr_vector( x, i  ), x0>>i0, x1>>i1, x2>>i2, x3>>i3, x4>>i4, x5>>i5, x6>>i6, x7>>i7 );

    WWV_TEST( wwv_and   (x,y),   x0  & y0,   x1  & y1,   x2  & y2,   x3  & y3,   x4  & y4,   x5  & y5,   x6  & y6,   x7  & y7 );
    WWV_TEST( wwv_andnot(x,y), (~x0) & y0, (~x1) & y1, (~x2) & y2, (~x3) & y3, (~x4) & y4, (~x5) & y5, (~x6) & y6, (~x7) & y7 );
    WWV_TEST( wwv_or    (x,y),   x0  | y0,   x1  | y1,   x2  | y2,   x3  | y3,   x4  | y4,   x5  | y5,   x6  | y6,   x7  | y7 );
    WWV_TEST( wwv_xor   (x,y),   x0  ^ y0,   x1  ^ y1,   x2  ^ y2,   x3  ^ y3,   x4  ^ y4,   x5  ^ y5,   x6  ^ y6,   x7  ^ y7 );

#   define ROL(x,y) fd_ulong_rotate_left ( (x), (int)(uint)(y) )
#   define ROR(x,y) fd_ulong_rotate_right( (x), (int)(uint)(y) )
    WWV_TEST( wwv_rol( x, y0 ),       ROL( x0, y0 ), ROL( x1, y0 ), ROL( x2, y0 ), ROL( x3, y0 ),
                                      ROL( x4, y0 ), ROL( x5, y0 ), ROL( x6, y0 ), ROL( x7, y0 ) );
    WWV_TEST( wwv_ror( x, y0 ),       ROR( x0, y0 ), ROR( x1, y0 ), ROR( x2, y0 ), ROR( x3, y0 ),
                                      ROR( x4, y0 ), ROR( x5, y0 ), ROR( x6, y0 ), ROR( x7, y0 ) );
    WWV_TEST( wwv_rol_vector( x, y ), ROL( x0, y0 ), ROL( x1, y1 ), ROL( x2, y2 ), ROL( x3, y3 ),
                                      ROL( x4, y4 ), ROL( x5, y5 ), ROL( x6, y6 ), ROL( x7, y7 ) );
    WWV_TEST( wwv_ror_vector( x, y ), ROR( x0, y0 ), ROR( x1, y1 ), ROR( x2, y2 ), ROR( x3, y3 ),
                                      ROR( x4, y4 ), ROR( x5, y5 ), ROR( x6, y6 ), ROR( x7, y7 ) );
#   undef ROR
#   undef ROL

    WWV_TEST( wwv_bswap(x), fd_ulong_bswap(x0), fd_ulong_bswap(x1), fd_ulong_bswap(x2), fd_ulong_bswap(x3),
                            fd_ulong_bswap(x4), fd_ulong_bswap(x5), fd_ulong_bswap(x6), fd_ulong_bswap(x7) );

    /* Test comparison */

    int c = (int)(fd_rng_uint( rng ) & 255U);
    wwv_t t = wwv_if( c, x, y );
    wwv_st( _b, t );
    ulong t0 = _b[0]; ulong t1 = _b[1]; ulong t2 = _b[2]; ulong t3 = _b[3];
    ulong t4 = _b[4]; ulong t5 = _b[5]; ulong t6 = _b[6]; ulong t7 = _b[7];

#   define TEST_CMP(fn,op)                                                                                      \
    FD_TEST( fn(x,t)==( ((x##0 op t##0)<<0) | ((x##1 op t##1)<<1) | ((x##2 op t##2)<<2) | ((x##3 op t##3)<<3) | \
                        ((x##4 op t##4)<<4) | ((x##5 op t##5)<<5) | ((x##6 op t##6)<<6) | ((x##7 op t##7)<<7) ) );

    TEST_CMP( wwv_eq, == );
    TEST_CMP( wwv_gt, >  );
    TEST_CMP( wwv_lt, <  );

    TEST_CMP( wwv_ne, != );
    TEST_CMP( wwv_ge, >= );
    TEST_CMP( wwv_le, <= );

    wwv_t tt = wwv_if( c, wwv_or( x, wwv_one() ), wwv_zero() );
    FD_TEST( wwv_lnot   ( tt )==wwv_eq( tt, wwv_zero() ) );
    FD_TEST( wwv_lnotnot( tt )==wwv_ne( tt, wwv_zero() ) );

#   undef TEST_CMP

    /* Test lane ops */

    WWV_TEST( wwv_if( c, y, z ),
              ((c>>0)&1) ? y0 : z0, ((c>>1)&1) ? y1 : z1, ((c>>2)&1) ? y2 : z2, ((c>>3)&1) ? y3 : z3,
              ((c>>4)&1) ? y4 : z4, ((c>>5)&1) ? y5 : z5, ((c>>6)&1) ? y6 : z6, ((c>>7)&1) ? y7 : z7 );
    WWV_TEST( wwv_add_if( c, x, y, z ),
              ((c>>0)&1) ? (x0+y0) : z0, ((c>>1)&1) ? (x1+y1) : z1, ((c>>2)&1) ? (x2+y2) : z2, ((c>>3)&1) ? (x3+y3) : z3,
              ((c>>4)&1) ? (x4+y4) : z4, ((c>>5)&1) ? (x5+y5) : z5, ((c>>6)&1) ? (x6+y6) : z6, ((c>>7)&1) ? (x7+y7) : z7 );
    WWV_TEST( wwv_sub_if( c, x, y, z ),
              ((c>>0)&1) ? (x0-y0) : z0, ((c>>1)&1) ? (x1-y1) : z1, ((c>>2)&1) ? (x2-y2) : z2, ((c>>3)&1) ? (x3-y3) : z3,
              ((c>>4)&1) ? (x4-y4) : z4, ((c>>5)&1) ? (x5-y5) : z5, ((c>>6)&1) ? (x6-y6) : z6, ((c>>7)&1) ? (x7-y7) : z7 );

    /* Test conversions */

    WWI_TEST( wwv_to_wwi(x),  (int)x0,0,  (int)x1,0,  (int)x2,0,  (int)x3,0,  (int)x4,0,  (int)x5,0,  (int)x6,0,  (int)x7,0 );
    WWU_TEST( wwv_to_wwu(x), (uint)x0,0, (uint)x1,0, (uint)x2,0, (uint)x3,0, (uint)x4,0, (uint)x5,0, (uint)x6,0, (uint)x7,0 );
    WWL_TEST( wwv_to_wwl(x), (long)x0,   (long)x1,   (long)x2,   (long)x3,   (long)x4,   (long)x5,   (long)x6,   (long)x7   );

    /* Test misc operations */

    WWV_TEST( wwv_pack_halves( y,0, z,0 ), y0,y1,y2,y3, z0,z1,z2,z3 );
    WWV_TEST( wwv_pack_halves( y,1, z,0 ), y4,y5,y6,y7, z0,z1,z2,z3 );
    WWV_TEST( wwv_pack_halves( y,0, z,1 ), y0,y1,y2,y3, z4,z5,z6,z7 );
    WWV_TEST( wwv_pack_halves( y,1, z,1 ), y4,y5,y6,y7, z4,z5,z6,z7 );
    WWV_TEST( wwv_pack_h0_h1 ( y,   z   ), y0,y1,y2,y3, z4,z5,z6,z7 );

    ulong const m52 = (1UL<<52)-1UL;

#   define MADD52LO(x,y,z) ((x) + (((ulong)((((uint128)((y) & m52))*((uint128)((z) & m52)))    ))&m52))
#   define MADD52HI(x,y,z) ((x) + (((ulong)((((uint128)((y) & m52))*((uint128)((z) & m52)))>>52))    ))
    WWV_TEST( wwv_madd52lo( x, y, z ), MADD52LO(x0,y0,z0), MADD52LO(x1,y1,z1), MADD52LO(x2,y2,z2), MADD52LO(x3,y3,z3),
                                       MADD52LO(x4,y4,z4), MADD52LO(x5,y5,z5), MADD52LO(x6,y6,z6), MADD52LO(x7,y7,z7) );
    WWV_TEST( wwv_madd52hi( x, y, z ), MADD52HI(x0,y0,z0), MADD52HI(x1,y1,z1), MADD52HI(x2,y2,z2), MADD52HI(x3,y3,z3),
                                       MADD52HI(x4,y4,z4), MADD52HI(x5,y5,z5), MADD52HI(x6,y6,z6), MADD52HI(x7,y7,z7) );
#   undef MADD52HI
#   undef MADD52LO

    WWV_TEST( wwv_slide( x, y, 0 ), x0,x1,x2,x3,x4,x5,x6,x7 );
    WWV_TEST( wwv_slide( x, y, 1 ), x1,x2,x3,x4,x5,x6,x7,y0 );
    WWV_TEST( wwv_slide( x, y, 2 ), x2,x3,x4,x5,x6,x7,y0,y1 );
    WWV_TEST( wwv_slide( x, y, 3 ), x3,x4,x5,x6,x7,y0,y1,y2 );
    WWV_TEST( wwv_slide( x, y, 4 ), x4,x5,x6,x7,y0,y1,y2,y3 );
    WWV_TEST( wwv_slide( x, y, 5 ), x5,x6,x7,y0,y1,y2,y3,y4 );
    WWV_TEST( wwv_slide( x, y, 6 ), x6,x7,y0,y1,y2,y3,y4,y5 );
    WWV_TEST( wwv_slide( x, y, 7 ), x7,y0,y1,y2,y3,y4,y5,y6 );

    wwv_unpack( x, t0,t1,t2,t3,t4,t5,t6,t7 );
    WWV_TEST( wwv( t0,t1,t2,t3,t4,t5,t6,t7 ), x0,x1,x2,x3,x4,x5,x6,x7 );

    wwv_t r0 = x;            wwv_t r1 = y;            wwv_t r2 = z;            wwv_t r3 = t;
    wwv_t r4 = wwv_not( x ); wwv_t r5 = wwv_not( y ); wwv_t r6 = wwv_not( z ); wwv_t r7 = wwv_not( t );

    ulong A[64] WW_ATTR;
    wwv_st( A,    r0 ); wwv_st( A+ 8, r1 ); wwv_st( A+16, r2 ); wwv_st( A+24, r3 );
    wwv_st( A+32, r4 ); wwv_st( A+40, r5 ); wwv_st( A+48, r6 ); wwv_st( A+56, r7 );

    wwv_t c0; wwv_t c1; wwv_t c2; wwv_t c3; wwv_t c4; wwv_t c5; wwv_t c6; wwv_t c7;
    wwv_transpose_8x8( r0,r1,r2,r3,r4,r5,r6,r7, c0,c1,c2,c3,c4,c5,c6,c7 );

    ulong AT[64] WW_ATTR;
    wwv_st( AT,    c0 ); wwv_st( AT+ 8, c1 ); wwv_st( AT+16, c2 ); wwv_st( AT+24, c3 );
    wwv_st( AT+32, c4 ); wwv_st( AT+40, c5 ); wwv_st( AT+48, c6 ); wwv_st( AT+56, c7 );

    for( int ii=0; ii<8; ii++ ) for( int jj=0; jj<8; jj++ ) FD_TEST( A[ii+8*jj]==AT[jj+8*ii] );
  }

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
