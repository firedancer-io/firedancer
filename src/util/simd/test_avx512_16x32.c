#include "test_avx512.h"

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  FD_LOG_NOTICE(( "Testing wwi_t" ));

  for( ulong rem=1000000UL; rem; rem-- ) {

    /* Test construct */

    int x0 = (int)fd_rng_uint( rng ); int x1 = (int)fd_rng_uint( rng );
    int x2 = (int)fd_rng_uint( rng ); int x3 = (int)fd_rng_uint( rng );
    int x4 = (int)fd_rng_uint( rng ); int x5 = (int)fd_rng_uint( rng );
    int x6 = (int)fd_rng_uint( rng ); int x7 = (int)fd_rng_uint( rng );
    int x8 = (int)fd_rng_uint( rng ); int x9 = (int)fd_rng_uint( rng );
    int xa = (int)fd_rng_uint( rng ); int xb = (int)fd_rng_uint( rng );
    int xc = (int)fd_rng_uint( rng ); int xd = (int)fd_rng_uint( rng );
    int xe = (int)fd_rng_uint( rng ); int xf = (int)fd_rng_uint( rng );
    wwi_t x = wwi( x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, xa, xb, xc, xd, xe, xf );
    WWI_TEST( x, x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, xa, xb, xc, xd, xe, xf );

    int y0 = (int)fd_rng_uint( rng ); int y1 = (int)fd_rng_uint( rng );
    int y2 = (int)fd_rng_uint( rng ); int y3 = (int)fd_rng_uint( rng );
    int y4 = (int)fd_rng_uint( rng ); int y5 = (int)fd_rng_uint( rng );
    int y6 = (int)fd_rng_uint( rng ); int y7 = (int)fd_rng_uint( rng );
    int y8 = (int)fd_rng_uint( rng ); int y9 = (int)fd_rng_uint( rng );
    int ya = (int)fd_rng_uint( rng ); int yb = (int)fd_rng_uint( rng );
    int yc = (int)fd_rng_uint( rng ); int yd = (int)fd_rng_uint( rng );
    int ye = (int)fd_rng_uint( rng ); int yf = (int)fd_rng_uint( rng );
    wwi_t y = wwi( y0, y1, y2, y3, y4, y5, y6, y7, y8, y9, ya, yb, yc, yd, ye, yf );
    WWI_TEST( y, y0, y1, y2, y3, y4, y5, y6, y7, y8, y9, ya, yb, yc, yd, ye, yf );

    int z0 = (int)fd_rng_uint( rng ); int z1 = (int)fd_rng_uint( rng );
    int z2 = (int)fd_rng_uint( rng ); int z3 = (int)fd_rng_uint( rng );
    int z4 = (int)fd_rng_uint( rng ); int z5 = (int)fd_rng_uint( rng );
    int z6 = (int)fd_rng_uint( rng ); int z7 = (int)fd_rng_uint( rng );
    int z8 = (int)fd_rng_uint( rng ); int z9 = (int)fd_rng_uint( rng );
    int za = (int)fd_rng_uint( rng ); int zb = (int)fd_rng_uint( rng );
    int zc = (int)fd_rng_uint( rng ); int zd = (int)fd_rng_uint( rng );
    int ze = (int)fd_rng_uint( rng ); int zf = (int)fd_rng_uint( rng );
    wwi_t z = wwi( z0, z1, z2, z3, z4, z5, z6, z7, z8, z9, za, zb, zc, zd, ze, zf );
    WWI_TEST( z, z0, z1, z2, z3, z4, z5, z6, z7, z8, z9, za, zb, zc, zd, ze, zf );

    int u0; int u1; int u2; int u3; int u4; int u5; int u6; int u7;
    int u8; int u9; int ua; int ub; int uc; int ud; int ue; int uf;
    wwi_t u;

    int _b[32] WW_ATTR;

    /* Test permute/select */

    wwi_st( _b, y ); wwi_st( _b+16, z );

    u0 = x0 & 15; u1 = x1 & 15; u2 = x2 & 15; u3 = x3 & 15; u4 = x4 & 15; u5 = x5 & 15; u6 = x6 & 15; u7 = x7 & 15;
    u8 = x8 & 15; u9 = x9 & 15; ua = xa & 15; ub = xb & 15; uc = xc & 15; ud = xd & 15; ue = xe & 15; uf = xf & 15;
    u = wwi( u0, u1, u2, u3, u4, u5, u6, u7, u8, u9, ua, ub, uc, ud, ue, uf );
    WWI_TEST( wwi_permute( u, y ), _b[ u0 ], _b[ u1 ], _b[ u2 ], _b[ u3 ], _b[ u4 ], _b[ u5 ], _b[ u6 ], _b[ u7 ],
                                   _b[ u8 ], _b[ u9 ], _b[ ua ], _b[ ub ], _b[ uc ], _b[ ud ], _b[ ue ], _b[ uf ] );

    u0 = x0 & 31; u1 = x1 & 31; u2 = x2 & 31; u3 = x3 & 31; u4 = x4 & 31; u5 = x5 & 31; u6 = x6 & 31; u7 = x7 & 31;
    u8 = x8 & 31; u9 = x9 & 31; ua = xa & 31; ub = xb & 31; uc = xc & 31; ud = xd & 31; ue = xe & 31; uf = xf & 31;
    u = wwi( u0, u1, u2, u3, u4, u5, u6, u7, u8, u9, ua, ub, uc, ud, ue, uf );
    WWI_TEST( wwi_select( u, y, z ), _b[ u0 ], _b[ u1 ], _b[ u2 ], _b[ u3 ], _b[ u4 ], _b[ u5 ], _b[ u6 ], _b[ u7 ],
                                     _b[ u8 ], _b[ u9 ], _b[ ua ], _b[ ub ], _b[ uc ], _b[ ud ], _b[ ue ], _b[ uf ] );

    /* Test bcast/zero/one */

    WWI_TEST( wwi_bcast(x0), x0, x0, x0, x0, x0, x0, x0, x0, x0, x0, x0, x0, x0, x0, x0, x0 );
    WWI_TEST( wwi_zero(),    0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0  );
    WWI_TEST( wwi_one(),     1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1,  1  );

    /* Test ld/st/ldu/stu */

    wwi_st( _b, x );
    WWI_TEST( wwi_ld( _b ), x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, xa, xb, xc, xd, xe, xf );

    uchar _m[128] WW_ATTR;
    u0 = x0 & 63;
    wwi_stu( _m+u0, y );
    WWI_TEST( wwi_ldu( _m+u0 ), y0, y1, y2, y3, y4, y5, y6, y7, y8, y9, ya, yb, yc, yd, ye, yf );

    /* Test arithmetic ops */

    WWI_TEST( wwi_neg(x), -x0, -x1, -x2, -x3, -x4, -x5, -x6, -x7, -x8, -x9, -xa, -xb, -xc, -xd, -xe, -xf );
    WWI_TEST( wwi_abs(x), (int)fd_int_abs(x0), (int)fd_int_abs(x1), (int)fd_int_abs(x2), (int)fd_int_abs(x3),
                          (int)fd_int_abs(x4), (int)fd_int_abs(x5), (int)fd_int_abs(x6), (int)fd_int_abs(x7),
                          (int)fd_int_abs(x8), (int)fd_int_abs(x9), (int)fd_int_abs(xa), (int)fd_int_abs(xb),
                          (int)fd_int_abs(xc), (int)fd_int_abs(xd), (int)fd_int_abs(xe), (int)fd_int_abs(xf) );

    WWI_TEST( wwi_min(x,y), fd_int_min(x0,y0), fd_int_min(x1,y1), fd_int_min(x2,y2), fd_int_min(x3,y3),
                            fd_int_min(x4,y4), fd_int_min(x5,y5), fd_int_min(x6,y6), fd_int_min(x7,y7),
                            fd_int_min(x8,y8), fd_int_min(x9,y9), fd_int_min(xa,ya), fd_int_min(xb,yb),
                            fd_int_min(xc,yc), fd_int_min(xd,yd), fd_int_min(xe,ye), fd_int_min(xf,yf) );
    WWI_TEST( wwi_max(x,y), fd_int_max(x0,y0), fd_int_max(x1,y1), fd_int_max(x2,y2), fd_int_max(x3,y3),
                            fd_int_max(x4,y4), fd_int_max(x5,y5), fd_int_max(x6,y6), fd_int_max(x7,y7),
                            fd_int_max(x8,y8), fd_int_max(x9,y9), fd_int_max(xa,ya), fd_int_max(xb,yb),
                            fd_int_max(xc,yc), fd_int_max(xd,yd), fd_int_max(xe,ye), fd_int_max(xf,yf) );
    WWI_TEST( wwi_add(x,y), x0+y0, x1+y1, x2+y2, x3+y3, x4+y4, x5+y5, x6+y6, x7+y7,
                            x8+y8, x9+y9, xa+ya, xb+yb, xc+yc, xd+yd, xe+ye, xf+yf );
    WWI_TEST( wwi_sub(x,y), x0-y0, x1-y1, x2-y2, x3-y3, x4-y4, x5-y5, x6-y6, x7-y7,
                            x8-y8, x9-y9, xa-ya, xb-yb, xc-yc, xd-yd, xe-ye, xf-yf );
    WWI_TEST( wwi_mul(x,y), x0*y0, x1*y1, x2*y2, x3*y3, x4*y4, x5*y5, x6*y6, x7*y7,
                            x8*y8, x9*y9, xa*ya, xb*yb, xc*yc, xd*yd, xe*ye, xf*yf );

    /* Test bit ops */

    u0 = y0 & 31; u1 = y1 & 31; u2 = y2 & 31; u3 = y3 & 31; u4 = y4 & 31; u5 = y5 & 31; u6 = y6 & 31; u7 = y7 & 31;
    u8 = y8 & 31; u9 = y9 & 31; ua = ya & 31; ub = yb & 31; uc = yc & 31; ud = yd & 31; ue = ye & 31; uf = yf & 31;
    u = wwi( u0, u1, u2, u3, u4, u5, u6, u7, u8, u9, ua, ub, uc, ud, ue, uf );

    WWI_TEST( wwi_not(x), ~x0, ~x1, ~x2, ~x3, ~x4, ~x5, ~x6, ~x7, ~x8, ~x9, ~xa, ~xb, ~xc, ~xd, ~xe, ~xf );

    WWI_TEST( wwi_shl ( x, u0 ), x0<<u0, x1<<u0, x2<<u0, x3<<u0, x4<<u0, x5<<u0, x6<<u0, x7<<u0,
                                 x8<<u0, x9<<u0, xa<<u0, xb<<u0, xc<<u0, xd<<u0, xe<<u0, xf<<u0 );
    WWI_TEST( wwi_shr ( x, u0 ), x0>>u0, x1>>u0, x2>>u0, x3>>u0, x4>>u0, x5>>u0, x6>>u0, x7>>u0,
                                 x8>>u0, x9>>u0, xa>>u0, xb>>u0, xc>>u0, xd>>u0, xe>>u0, xf>>u0 );
    WWI_TEST( wwi_shru( x, u0 ),
      (int)(((uint)x0)>>u0), (int)(((uint)x1)>>u0), (int)(((uint)x2)>>u0), (int)(((uint)x3)>>u0),
      (int)(((uint)x4)>>u0), (int)(((uint)x5)>>u0), (int)(((uint)x6)>>u0), (int)(((uint)x7)>>u0),
      (int)(((uint)x8)>>u0), (int)(((uint)x9)>>u0), (int)(((uint)xa)>>u0), (int)(((uint)xb)>>u0),
      (int)(((uint)xc)>>u0), (int)(((uint)xd)>>u0), (int)(((uint)xe)>>u0), (int)(((uint)xf)>>u0) );

    WWI_TEST( wwi_shl_vector ( x, u ), x0<<u0, x1<<u1, x2<<u2, x3<<u3, x4<<u4, x5<<u5, x6<<u6, x7<<u7,
                                       x8<<u8, x9<<u9, xa<<ua, xb<<ub, xc<<uc, xd<<ud, xe<<ue, xf<<uf );
    WWI_TEST( wwi_shr_vector ( x, u ), x0>>u0, x1>>u1, x2>>u2, x3>>u3, x4>>u4, x5>>u5, x6>>u6, x7>>u7,
                                       x8>>u8, x9>>u9, xa>>ua, xb>>ub, xc>>uc, xd>>ud, xe>>ue, xf>>uf );
    WWI_TEST( wwi_shru_vector( x, u ),
      (int)(((uint)x0)>>u0), (int)(((uint)x1)>>u1), (int)(((uint)x2)>>u2), (int)(((uint)x3)>>u3),
      (int)(((uint)x4)>>u4), (int)(((uint)x5)>>u5), (int)(((uint)x6)>>u6), (int)(((uint)x7)>>u7),
      (int)(((uint)x8)>>u8), (int)(((uint)x9)>>u9), (int)(((uint)xa)>>ua), (int)(((uint)xb)>>ub),
      (int)(((uint)xc)>>uc), (int)(((uint)xd)>>ud), (int)(((uint)xe)>>ue), (int)(((uint)xf)>>uf) );

    WWI_TEST( wwi_and   (x,y),   x0  & y0,   x1  & y1,   x2  & y2,   x3  & y3,   x4  & y4,   x5  & y5,   x6  & y6,   x7  & y7,
                                 x8  & y8,   x9  & y9,   xa  & ya,   xb  & yb,   xc  & yc,   xd  & yd,   xe  & ye,   xf  & yf );
    WWI_TEST( wwi_andnot(x,y), (~x0) & y0, (~x1) & y1, (~x2) & y2, (~x3) & y3, (~x4) & y4, (~x5) & y5, (~x6) & y6, (~x7) & y7,
                               (~x8) & y8, (~x9) & y9, (~xa) & ya, (~xb) & yb, (~xc) & yc, (~xd) & yd, (~xe) & ye, (~xf) & yf );
    WWI_TEST( wwi_or    (x,y),   x0  | y0,   x1  | y1,   x2  | y2,   x3  | y3,   x4  | y4,   x5  | y5,   x6  | y6,   x7  | y7,
                                 x8  | y8,   x9  | y9,   xa  | ya,   xb  | yb,   xc  | yc,   xd  | yd,   xe  | ye,   xf  | yf );
    WWI_TEST( wwi_xor   (x,y),   x0  ^ y0,   x1  ^ y1,   x2  ^ y2,   x3  ^ y3,   x4  ^ y4,   x5  ^ y5,   x6  ^ y6,   x7  ^ y7,
                                 x8  ^ y8,   x9  ^ y9,   xa  ^ ya,   xb  ^ yb,   xc  ^ yc,   xd  ^ yd,   xe  ^ ye,   xf  ^ yf );

#   define ROL(x,y) fd_int_rotate_left ( (x), (y) )
#   define ROR(x,y) fd_int_rotate_right( (x), (y) )
    WWI_TEST( wwi_rol_variable( x, y0 ), ROL( x0, y0 ), ROL( x1, y0 ), ROL( x2, y0 ), ROL( x3, y0 ),
                                         ROL( x4, y0 ), ROL( x5, y0 ), ROL( x6, y0 ), ROL( x7, y0 ),
                                         ROL( x8, y0 ), ROL( x9, y0 ), ROL( xa, y0 ), ROL( xb, y0 ),
                                         ROL( xc, y0 ), ROL( xd, y0 ), ROL( xe, y0 ), ROL( xf, y0 ) );
    WWI_TEST( wwi_ror_variable( x, y0 ), ROR( x0, y0 ), ROR( x1, y0 ), ROR( x2, y0 ), ROR( x3, y0 ),
                                         ROR( x4, y0 ), ROR( x5, y0 ), ROR( x6, y0 ), ROR( x7, y0 ),
                                         ROR( x8, y0 ), ROR( x9, y0 ), ROR( xa, y0 ), ROR( xb, y0 ),
                                         ROR( xc, y0 ), ROR( xd, y0 ), ROR( xe, y0 ), ROR( xf, y0 ) );
    WWI_TEST( wwi_rol_vector( x, y ),    ROL( x0, y0 ), ROL( x1, y1 ), ROL( x2, y2 ), ROL( x3, y3 ),
                                         ROL( x4, y4 ), ROL( x5, y5 ), ROL( x6, y6 ), ROL( x7, y7 ),
                                         ROL( x8, y8 ), ROL( x9, y9 ), ROL( xa, ya ), ROL( xb, yb ),
                                         ROL( xc, yc ), ROL( xd, yd ), ROL( xe, ye ), ROL( xf, yf ) );
    WWI_TEST( wwi_ror_vector( x, y ),    ROR( x0, y0 ), ROR( x1, y1 ), ROR( x2, y2 ), ROR( x3, y3 ),
                                         ROR( x4, y4 ), ROR( x5, y5 ), ROR( x6, y6 ), ROR( x7, y7 ),
                                         ROR( x8, y8 ), ROR( x9, y9 ), ROR( xa, ya ), ROR( xb, yb ),
                                         ROR( xc, yc ), ROR( xd, yd ), ROR( xe, ye ), ROR( xf, yf ) );
#   define COMPARE_WWI_ROL( j ) COMPARE16( WWI_TEST, x, wwi_rol, ROL, j );
#   define COMPARE_WWI_ROR( j ) COMPARE16( WWI_TEST, x, wwi_ror, ROR, j );
    EXPAND_32(COMPARE_WWI_ROL, 0)
    EXPAND_32(COMPARE_WWI_ROR, 0)
#   undef COMPARE_WWI_ROR
#   undef COMPARE_WWI_ROL
#   undef ROR
#   undef ROL

    /* Test comparison */

    int c = (int)(fd_rng_uint( rng ) & 65535U);
    wwi_t t = wwi_if( c, x, y );
    wwi_st( _b, t );
    int t0 = _b[ 0]; int t1 = _b[ 1]; int t2 = _b[ 2]; int t3 = _b[ 3];
    int t4 = _b[ 4]; int t5 = _b[ 5]; int t6 = _b[ 6]; int t7 = _b[ 7];
    int t8 = _b[ 8]; int t9 = _b[ 9]; int ta = _b[10]; int tb = _b[11];
    int tc = _b[12]; int td = _b[13]; int te = _b[14]; int tf = _b[15];

#   define TEST_CMP(fn,op)                                                                                          \
    FD_TEST( fn(x,t)==( ((x##0 op t##0)<< 0) | ((x##1 op t##1)<< 1) | ((x##2 op t##2)<< 2) | ((x##3 op t##3)<< 3) | \
                        ((x##4 op t##4)<< 4) | ((x##5 op t##5)<< 5) | ((x##6 op t##6)<< 6) | ((x##7 op t##7)<< 7) | \
                        ((x##8 op t##8)<< 8) | ((x##9 op t##9)<< 9) | ((x##a op t##a)<<10) | ((x##b op t##b)<<11) | \
                        ((x##c op t##c)<<12) | ((x##d op t##d)<<13) | ((x##e op t##e)<<14) | ((x##f op t##f)<<15) ) );

    TEST_CMP( wwi_eq, == );
    TEST_CMP( wwi_gt, >  );
    TEST_CMP( wwi_lt, <  );

    TEST_CMP( wwi_ne, != );
    TEST_CMP( wwi_ge, >= );
    TEST_CMP( wwi_le, <= );

    wwi_t tt = wwi_if( c, wwi_or( x, wwi_one() ), wwi_zero() );
    FD_TEST( wwi_lnot   ( tt )==wwi_eq( tt, wwi_zero() ) );
    FD_TEST( wwi_lnotnot( tt )==wwi_ne( tt, wwi_zero() ) );

#   undef TEST_CMP

    /* Test lane ops */

    WWI_TEST( wwi_if( c, y, z ),
              ((c>> 0)&1) ? y0 : z0, ((c>> 1)&1) ? y1 : z1, ((c>> 2)&1) ? y2 : z2, ((c>> 3)&1) ? y3 : z3,
              ((c>> 4)&1) ? y4 : z4, ((c>> 5)&1) ? y5 : z5, ((c>> 6)&1) ? y6 : z6, ((c>> 7)&1) ? y7 : z7,
              ((c>> 8)&1) ? y8 : z8, ((c>> 9)&1) ? y9 : z9, ((c>>10)&1) ? ya : za, ((c>>11)&1) ? yb : zb,
              ((c>>12)&1) ? yc : zc, ((c>>13)&1) ? yd : zd, ((c>>14)&1) ? ye : ze, ((c>>15)&1) ? yf : zf );
    WWI_TEST( wwi_add_if( c, x, y, z ),
              ((c>> 0)&1) ? (x0+y0) : z0, ((c>> 1)&1) ? (x1+y1) : z1, ((c>> 2)&1) ? (x2+y2) : z2, ((c>> 3)&1) ? (x3+y3) : z3,
              ((c>> 4)&1) ? (x4+y4) : z4, ((c>> 5)&1) ? (x5+y5) : z5, ((c>> 6)&1) ? (x6+y6) : z6, ((c>> 7)&1) ? (x7+y7) : z7,
              ((c>> 8)&1) ? (x8+y8) : z8, ((c>> 9)&1) ? (x9+y9) : z9, ((c>>10)&1) ? (xa+ya) : za, ((c>>11)&1) ? (xb+yb) : zb,
              ((c>>12)&1) ? (xc+yc) : zc, ((c>>13)&1) ? (xd+yd) : zd, ((c>>14)&1) ? (xe+ye) : ze, ((c>>15)&1) ? (xf+yf) : zf );
    WWI_TEST( wwi_sub_if( c, x, y, z ),
              ((c>> 0)&1) ? (x0-y0) : z0, ((c>> 1)&1) ? (x1-y1) : z1, ((c>> 2)&1) ? (x2-y2) : z2, ((c>> 3)&1) ? (x3-y3) : z3,
              ((c>> 4)&1) ? (x4-y4) : z4, ((c>> 5)&1) ? (x5-y5) : z5, ((c>> 6)&1) ? (x6-y6) : z6, ((c>> 7)&1) ? (x7-y7) : z7,
              ((c>> 8)&1) ? (x8-y8) : z8, ((c>> 9)&1) ? (x9-y9) : z9, ((c>>10)&1) ? (xa-ya) : za, ((c>>11)&1) ? (xb-yb) : zb,
              ((c>>12)&1) ? (xc-yc) : zc, ((c>>13)&1) ? (xd-yd) : zd, ((c>>14)&1) ? (xe-ye) : ze, ((c>>15)&1) ? (xf-yf) : zf );

    /* Test conversions */

    WWU_TEST( wwi_to_wwu( x ),     (uint)x0,  (uint)x1,  (uint)x2,  (uint)x3,  (uint)x4,  (uint)x5,  (uint)x6,  (uint)x7,
                                   (uint)x8,  (uint)x9,  (uint)xa,  (uint)xb,  (uint)xc,  (uint)xd,  (uint)xe,  (uint)xf );
    WWL_TEST( wwi_to_wwl( x, 0 ),  (long)x0,  (long)x2,  (long)x4,  (long)x6,  (long)x8,  (long)xa,  (long)xc,  (long)xe );
    WWL_TEST( wwi_to_wwl( x, 1 ),  (long)x1,  (long)x3,  (long)x5,  (long)x7,  (long)x9,  (long)xb,  (long)xd,  (long)xf );
    WWV_TEST( wwi_to_wwv( x, 0 ), (ulong)x0, (ulong)x2, (ulong)x4, (ulong)x6, (ulong)x8, (ulong)xa, (ulong)xc, (ulong)xe );
    WWV_TEST( wwi_to_wwv( x, 1 ), (ulong)x1, (ulong)x3, (ulong)x5, (ulong)x7, (ulong)x9, (ulong)xb, (ulong)xd, (ulong)xf );

    /* Test misc operations */

    WWI_TEST( wwi_pack_halves( y,0, z,0 ), y0,y1,y2,y3,y4,y5,y6,y7, z0,z1,z2,z3,z4,z5,z6,z7 );
    WWI_TEST( wwi_pack_halves( y,1, z,0 ), y8,y9,ya,yb,yc,yd,ye,yf, z0,z1,z2,z3,z4,z5,z6,z7 );
    WWI_TEST( wwi_pack_halves( y,0, z,1 ), y0,y1,y2,y3,y4,y5,y6,y7, z8,z9,za,zb,zc,zd,ze,zf );
    WWI_TEST( wwi_pack_halves( y,1, z,1 ), y8,y9,ya,yb,yc,yd,ye,yf, z8,z9,za,zb,zc,zd,ze,zf );
    WWI_TEST( wwi_pack_h0_h1 ( y,   z   ), y0,y1,y2,y3,y4,y5,y6,y7, z8,z9,za,zb,zc,zd,ze,zf );

    WWI_TEST( wwi_slide( x, y,  0 ), x0,x1,x2,x3,x4,x5,x6,x7,x8,x9,xa,xb,xc,xd,xe,xf );
    WWI_TEST( wwi_slide( x, y,  1 ), x1,x2,x3,x4,x5,x6,x7,x8,x9,xa,xb,xc,xd,xe,xf,y0 );
    WWI_TEST( wwi_slide( x, y,  2 ), x2,x3,x4,x5,x6,x7,x8,x9,xa,xb,xc,xd,xe,xf,y0,y1 );
    WWI_TEST( wwi_slide( x, y,  3 ), x3,x4,x5,x6,x7,x8,x9,xa,xb,xc,xd,xe,xf,y0,y1,y2 );
    WWI_TEST( wwi_slide( x, y,  4 ), x4,x5,x6,x7,x8,x9,xa,xb,xc,xd,xe,xf,y0,y1,y2,y3 );
    WWI_TEST( wwi_slide( x, y,  5 ), x5,x6,x7,x8,x9,xa,xb,xc,xd,xe,xf,y0,y1,y2,y3,y4 );
    WWI_TEST( wwi_slide( x, y,  6 ), x6,x7,x8,x9,xa,xb,xc,xd,xe,xf,y0,y1,y2,y3,y4,y5 );
    WWI_TEST( wwi_slide( x, y,  7 ), x7,x8,x9,xa,xb,xc,xd,xe,xf,y0,y1,y2,y3,y4,y5,y6 );
    WWI_TEST( wwi_slide( x, y,  8 ), x8,x9,xa,xb,xc,xd,xe,xf,y0,y1,y2,y3,y4,y5,y6,y7 );
    WWI_TEST( wwi_slide( x, y,  9 ), x9,xa,xb,xc,xd,xe,xf,y0,y1,y2,y3,y4,y5,y6,y7,y8 );
    WWI_TEST( wwi_slide( x, y, 10 ), xa,xb,xc,xd,xe,xf,y0,y1,y2,y3,y4,y5,y6,y7,y8,y9 );
    WWI_TEST( wwi_slide( x, y, 11 ), xb,xc,xd,xe,xf,y0,y1,y2,y3,y4,y5,y6,y7,y8,y9,ya );
    WWI_TEST( wwi_slide( x, y, 12 ), xc,xd,xe,xf,y0,y1,y2,y3,y4,y5,y6,y7,y8,y9,ya,yb );
    WWI_TEST( wwi_slide( x, y, 13 ), xd,xe,xf,y0,y1,y2,y3,y4,y5,y6,y7,y8,y9,ya,yb,yc );
    WWI_TEST( wwi_slide( x, y, 14 ), xe,xf,y0,y1,y2,y3,y4,y5,y6,y7,y8,y9,ya,yb,yc,yd );
    WWI_TEST( wwi_slide( x, y, 15 ), xf,y0,y1,y2,y3,y4,y5,y6,y7,y8,y9,ya,yb,yc,yd,ye );

    wwi_unpack( x, t0,t1,t2,t3,t4,t5,t6,t7,t8,t9,ta,tb,tc,td,te,tf );
    WWI_TEST( wwi( t0,t1,t2,t3,t4,t5,t6,t7,t8,t9,ta,tb,tc,td,te,tf ), x0,x1,x2,x3,x4,x5,x6,x7,x8,x9,xa,xb,xc,xd,xe,xf );

    wwi_t r0 = x;               wwi_t r1 = y;               wwi_t r2 = z;               wwi_t r3 = t;
    wwi_t r4 = wwi_not( x );    wwi_t r5 = wwi_not( y );    wwi_t r6 = wwi_not( z );    wwi_t r7 = wwi_not( t );
    wwi_t r8 = wwi_ror( x, 8 ); wwi_t r9 = wwi_ror( y, 8 ); wwi_t ra = wwi_ror( z, 8 ); wwi_t rb = wwi_ror( t, 8 );
    wwi_t rc = wwi_rol( x, 8 ); wwi_t rd = wwi_rol( y, 8 ); wwi_t re = wwi_rol( z, 8 ); wwi_t rf = wwi_rol( t, 8 );

    int A [256] WW_ATTR;
    int AT[256] WW_ATTR;

    wwi_st( A,     r0 ); wwi_st( A+ 16, r1 ); wwi_st( A+ 32, r2 ); wwi_st( A+ 48, r3 );
    wwi_st( A+ 64, r4 ); wwi_st( A+ 80, r5 ); wwi_st( A+ 96, r6 ); wwi_st( A+112, r7 );
    wwi_st( A+128, r8 ); wwi_st( A+144, r9 ); wwi_st( A+160, ra ); wwi_st( A+176, rb );
    wwi_st( A+192, rc ); wwi_st( A+208, rd ); wwi_st( A+224, re ); wwi_st( A+240, rf );

    wwi_t c0; wwi_t c1; wwi_t c2; wwi_t c3; wwi_t c4; wwi_t c5; wwi_t c6; wwi_t c7;
    wwi_t c8; wwi_t c9; wwi_t ca; wwi_t cb; wwi_t cc; wwi_t cd; wwi_t ce; wwi_t cf;

    wwi_transpose_16x16( r0,r1,r2,r3,r4,r5,r6,r7,r8,r9,ra,rb,rc,rd,re,rf, c0,c1,c2,c3,c4,c5,c6,c7,c8,c9,ca,cb,cc,cd,ce,cf );

    wwi_st( AT,     c0 ); wwi_st( AT+ 16, c1 ); wwi_st( AT+ 32, c2 ); wwi_st( AT+ 48, c3 );
    wwi_st( AT+ 64, c4 ); wwi_st( AT+ 80, c5 ); wwi_st( AT+ 96, c6 ); wwi_st( AT+112, c7 );
    wwi_st( AT+128, c8 ); wwi_st( AT+144, c9 ); wwi_st( AT+160, ca ); wwi_st( AT+176, cb );
    wwi_st( AT+192, cc ); wwi_st( AT+208, cd ); wwi_st( AT+224, ce ); wwi_st( AT+240, cf );

    for( int ii=0; ii<16; ii++ ) for( int jj=0; jj<16; jj++ ) FD_TEST( A[ii+16*jj]==AT[jj+16*ii] );

    wwi_transpose_2x8x8( r0,r1,r2,r3,r4,r5,r6,r7, c0,c1,c2,c3,c4,c5,c6,c7 );

    wwi_st( AT,     c0 ); wwi_st( AT+ 16, c1 ); wwi_st( AT+ 32, c2 ); wwi_st( AT+ 48, c3 );
    wwi_st( AT+ 64, c4 ); wwi_st( AT+ 80, c5 ); wwi_st( AT+ 96, c6 ); wwi_st( AT+112, c7 );
    for( int kk=0; kk<2; kk++ )
      for( int ii=0; ii<8; ii++ )
        for( int jj=0; jj<8; jj++ ) FD_TEST( A[8*kk+ii+16*jj]==AT[8*kk+jj+16*ii] );
  }

  FD_LOG_NOTICE(( "Testing wwu_t" ));

  for( ulong rem=1000000UL; rem; rem-- ) {

    /* Test construct */

    uint x0 = fd_rng_uint( rng ); uint x1 = fd_rng_uint( rng ); uint x2 = fd_rng_uint( rng ); uint x3 = fd_rng_uint( rng );
    uint x4 = fd_rng_uint( rng ); uint x5 = fd_rng_uint( rng ); uint x6 = fd_rng_uint( rng ); uint x7 = fd_rng_uint( rng );
    uint x8 = fd_rng_uint( rng ); uint x9 = fd_rng_uint( rng ); uint xa = fd_rng_uint( rng ); uint xb = fd_rng_uint( rng );
    uint xc = fd_rng_uint( rng ); uint xd = fd_rng_uint( rng ); uint xe = fd_rng_uint( rng ); uint xf = fd_rng_uint( rng );
    wwu_t x = wwu( x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, xa, xb, xc, xd, xe, xf );
    WWU_TEST( x, x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, xa, xb, xc, xd, xe, xf );

    uint y0 = fd_rng_uint( rng ); uint y1 = fd_rng_uint( rng ); uint y2 = fd_rng_uint( rng ); uint y3 = fd_rng_uint( rng );
    uint y4 = fd_rng_uint( rng ); uint y5 = fd_rng_uint( rng ); uint y6 = fd_rng_uint( rng ); uint y7 = fd_rng_uint( rng );
    uint y8 = fd_rng_uint( rng ); uint y9 = fd_rng_uint( rng ); uint ya = fd_rng_uint( rng ); uint yb = fd_rng_uint( rng );
    uint yc = fd_rng_uint( rng ); uint yd = fd_rng_uint( rng ); uint ye = fd_rng_uint( rng ); uint yf = fd_rng_uint( rng );
    wwu_t y = wwu( y0, y1, y2, y3, y4, y5, y6, y7, y8, y9, ya, yb, yc, yd, ye, yf );
    WWU_TEST( y, y0, y1, y2, y3, y4, y5, y6, y7, y8, y9, ya, yb, yc, yd, ye, yf );

    uint z0 = fd_rng_uint( rng ); uint z1 = fd_rng_uint( rng ); uint z2 = fd_rng_uint( rng ); uint z3 = fd_rng_uint( rng );
    uint z4 = fd_rng_uint( rng ); uint z5 = fd_rng_uint( rng ); uint z6 = fd_rng_uint( rng ); uint z7 = fd_rng_uint( rng );
    uint z8 = fd_rng_uint( rng ); uint z9 = fd_rng_uint( rng ); uint za = fd_rng_uint( rng ); uint zb = fd_rng_uint( rng );
    uint zc = fd_rng_uint( rng ); uint zd = fd_rng_uint( rng ); uint ze = fd_rng_uint( rng ); uint zf = fd_rng_uint( rng );
    wwu_t z = wwu( z0, z1, z2, z3, z4, z5, z6, z7, z8, z9, za, zb, zc, zd, ze, zf );
    WWU_TEST( z, z0, z1, z2, z3, z4, z5, z6, z7, z8, z9, za, zb, zc, zd, ze, zf );

    uint u0; uint u1; uint u2; uint u3; uint u4; uint u5; uint u6; uint u7;
    uint u8; uint u9; uint ua; uint ub; uint uc; uint ud; uint ue; uint uf;
    wwu_t u;

    uint _b[32] WW_ATTR;

    /* Test permute/select */

    wwu_st( _b, y ); wwu_st( _b+16, z );

    u0 = x0 & 15U; u1 = x1 & 15U; u2 = x2 & 15U; u3 = x3 & 15U; u4 = x4 & 15U; u5 = x5 & 15U; u6 = x6 & 15U; u7 = x7 & 15U;
    u8 = x8 & 15U; u9 = x9 & 15U; ua = xa & 15U; ub = xb & 15U; uc = xc & 15U; ud = xd & 15U; ue = xe & 15U; uf = xf & 15U;
    u = wwu( u0, u1, u2, u3, u4, u5, u6, u7, u8, u9, ua, ub, uc, ud, ue, uf );
    WWU_TEST( wwu_permute( u, y ), _b[ u0 ], _b[ u1 ], _b[ u2 ], _b[ u3 ], _b[ u4 ], _b[ u5 ], _b[ u6 ], _b[ u7 ],
                                   _b[ u8 ], _b[ u9 ], _b[ ua ], _b[ ub ], _b[ uc ], _b[ ud ], _b[ ue ], _b[ uf ] );

    u0 = x0 & 31U; u1 = x1 & 31U; u2 = x2 & 31U; u3 = x3 & 31U; u4 = x4 & 31U; u5 = x5 & 31U; u6 = x6 & 31U; u7 = x7 & 31U;
    u8 = x8 & 31U; u9 = x9 & 31U; ua = xa & 31U; ub = xb & 31U; uc = xc & 31U; ud = xd & 31U; ue = xe & 31U; uf = xf & 31U;
    u = wwu( u0, u1, u2, u3, u4, u5, u6, u7, u8, u9, ua, ub, uc, ud, ue, uf );
    WWU_TEST( wwu_select( u, y, z ), _b[ u0 ], _b[ u1 ], _b[ u2 ], _b[ u3 ], _b[ u4 ], _b[ u5 ], _b[ u6 ], _b[ u7 ],
                                     _b[ u8 ], _b[ u9 ], _b[ ua ], _b[ ub ], _b[ uc ], _b[ ud ], _b[ ue ], _b[ uf ] );

    /* Test bcast/zero/one */

    WWU_TEST( wwu_bcast(x0), x0, x0, x0, x0, x0, x0, x0, x0, x0, x0, x0, x0, x0, x0, x0, x0 );
    WWU_TEST( wwu_zero(),    0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U );
    WWU_TEST( wwu_one(),     1U, 1U, 1U, 1U, 1U, 1U, 1U, 1U, 1U, 1U, 1U, 1U, 1U, 1U, 1U, 1U );

    /* Test ld/st/ldu/stu */

    wwu_st( _b, x );
    WWU_TEST( wwu_ld( _b ), x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, xa, xb, xc, xd, xe, xf );

    uchar _m[128] WW_ATTR;
    u0 = x0 & 63U;
    wwu_stu( _m+u0, y );
    WWU_TEST( wwu_ldu( _m+u0 ), y0, y1, y2, y3, y4, y5, y6, y7, y8, y9, ya, yb, yc, yd, ye, yf );

    /* Test arithmetic ops */

    WWU_TEST( wwu_neg(x), -x0, -x1, -x2, -x3, -x4, -x5, -x6, -x7, -x8, -x9, -xa, -xb, -xc, -xd, -xe, -xf );
    WWU_TEST( wwu_abs(x),  x0,  x1,  x2,  x3,  x4,  x5,  x6,  x7,  x8,  x9,  xa,  xb,  xc,  xd,  xe,  xf );

    WWU_TEST( wwu_min(x,y), fd_uint_min(x0,y0), fd_uint_min(x1,y1), fd_uint_min(x2,y2), fd_uint_min(x3,y3),
                            fd_uint_min(x4,y4), fd_uint_min(x5,y5), fd_uint_min(x6,y6), fd_uint_min(x7,y7),
                            fd_uint_min(x8,y8), fd_uint_min(x9,y9), fd_uint_min(xa,ya), fd_uint_min(xb,yb),
                            fd_uint_min(xc,yc), fd_uint_min(xd,yd), fd_uint_min(xe,ye), fd_uint_min(xf,yf) );
    WWU_TEST( wwu_max(x,y), fd_uint_max(x0,y0), fd_uint_max(x1,y1), fd_uint_max(x2,y2), fd_uint_max(x3,y3),
                            fd_uint_max(x4,y4), fd_uint_max(x5,y5), fd_uint_max(x6,y6), fd_uint_max(x7,y7),
                            fd_uint_max(x8,y8), fd_uint_max(x9,y9), fd_uint_max(xa,ya), fd_uint_max(xb,yb),
                            fd_uint_max(xc,yc), fd_uint_max(xd,yd), fd_uint_max(xe,ye), fd_uint_max(xf,yf) );
    WWU_TEST( wwu_add(x,y), x0+y0, x1+y1, x2+y2, x3+y3, x4+y4, x5+y5, x6+y6, x7+y7,
                            x8+y8, x9+y9, xa+ya, xb+yb, xc+yc, xd+yd, xe+ye, xf+yf );
    WWU_TEST( wwu_sub(x,y), x0-y0, x1-y1, x2-y2, x3-y3, x4-y4, x5-y5, x6-y6, x7-y7,
                            x8-y8, x9-y9, xa-ya, xb-yb, xc-yc, xd-yd, xe-ye, xf-yf );
    WWU_TEST( wwu_mul(x,y), x0*y0, x1*y1, x2*y2, x3*y3, x4*y4, x5*y5, x6*y6, x7*y7,
                            x8*y8, x9*y9, xa*ya, xb*yb, xc*yc, xd*yd, xe*ye, xf*yf );

    /* Test bit ops */

    u0 = y0 & 31U; u1 = y1 & 31U; u2 = y2 & 31U; u3 = y3 & 31U; u4 = y4 & 31U; u5 = y5 & 31U; u6 = y6 & 31U; u7 = y7 & 31U;
    u8 = y8 & 31U; u9 = y9 & 31U; ua = ya & 31U; ub = yb & 31U; uc = yc & 31U; ud = yd & 31U; ue = ye & 31U; uf = yf & 31U;
    u = wwu( u0, u1, u2, u3, u4, u5, u6, u7, u8, u9, ua, ub, uc, ud, ue, uf );

    WWU_TEST( wwu_not(x), ~x0, ~x1, ~x2, ~x3, ~x4, ~x5, ~x6, ~x7, ~x8, ~x9, ~xa, ~xb, ~xc, ~xd, ~xe, ~xf );

    WWU_TEST( wwu_shl       ( x, u0 ), x0<<u0, x1<<u0, x2<<u0, x3<<u0, x4<<u0, x5<<u0, x6<<u0, x7<<u0,
                                       x8<<u0, x9<<u0, xa<<u0, xb<<u0, xc<<u0, xd<<u0, xe<<u0, xf<<u0 );
    WWU_TEST( wwu_shr       ( x, u0 ), x0>>u0, x1>>u0, x2>>u0, x3>>u0, x4>>u0, x5>>u0, x6>>u0, x7>>u0,
                                       x8>>u0, x9>>u0, xa>>u0, xb>>u0, xc>>u0, xd>>u0, xe>>u0, xf>>u0 );
    WWU_TEST( wwu_shl_vector( x, u  ), x0<<u0, x1<<u1, x2<<u2, x3<<u3, x4<<u4, x5<<u5, x6<<u6, x7<<u7,
                                       x8<<u8, x9<<u9, xa<<ua, xb<<ub, xc<<uc, xd<<ud, xe<<ue, xf<<uf );
    WWU_TEST( wwu_shr_vector( x, u  ), x0>>u0, x1>>u1, x2>>u2, x3>>u3, x4>>u4, x5>>u5, x6>>u6, x7>>u7,
                                       x8>>u8, x9>>u9, xa>>ua, xb>>ub, xc>>uc, xd>>ud, xe>>ue, xf>>uf );

    WWU_TEST( wwu_and   (x,y),   x0  & y0,   x1  & y1,   x2  & y2,   x3  & y3,   x4  & y4,   x5  & y5,   x6  & y6,   x7  & y7,
                                 x8  & y8,   x9  & y9,   xa  & ya,   xb  & yb,   xc  & yc,   xd  & yd,   xe  & ye,   xf  & yf );
    WWU_TEST( wwu_andnot(x,y), (~x0) & y0, (~x1) & y1, (~x2) & y2, (~x3) & y3, (~x4) & y4, (~x5) & y5, (~x6) & y6, (~x7) & y7,
                               (~x8) & y8, (~x9) & y9, (~xa) & ya, (~xb) & yb, (~xc) & yc, (~xd) & yd, (~xe) & ye, (~xf) & yf );
    WWU_TEST( wwu_or    (x,y),   x0  | y0,   x1  | y1,   x2  | y2,   x3  | y3,   x4  | y4,   x5  | y5,   x6  | y6,   x7  | y7,
                                 x8  | y8,   x9  | y9,   xa  | ya,   xb  | yb,   xc  | yc,   xd  | yd,   xe  | ye,   xf  | yf );
    WWU_TEST( wwu_xor   (x,y),   x0  ^ y0,   x1  ^ y1,   x2  ^ y2,   x3  ^ y3,   x4  ^ y4,   x5  ^ y5,   x6  ^ y6,   x7  ^ y7,
                                 x8  ^ y8,   x9  ^ y9,   xa  ^ ya,   xb  ^ yb,   xc  ^ yc,   xd  ^ yd,   xe  ^ ye,   xf  ^ yf );

#   define ROL(x,y) fd_uint_rotate_left ( (x), (int)(uint)(y) )
#   define ROR(x,y) fd_uint_rotate_right( (x), (int)(uint)(y) )
    WWU_TEST( wwu_rol_variable( x, y0 ), ROL( x0, y0 ), ROL( x1, y0 ), ROL( x2, y0 ), ROL( x3, y0 ),
                                         ROL( x4, y0 ), ROL( x5, y0 ), ROL( x6, y0 ), ROL( x7, y0 ),
                                         ROL( x8, y0 ), ROL( x9, y0 ), ROL( xa, y0 ), ROL( xb, y0 ),
                                         ROL( xc, y0 ), ROL( xd, y0 ), ROL( xe, y0 ), ROL( xf, y0 ) );
    WWU_TEST( wwu_ror_variable( x, y0 ), ROR( x0, y0 ), ROR( x1, y0 ), ROR( x2, y0 ), ROR( x3, y0 ),
                                         ROR( x4, y0 ), ROR( x5, y0 ), ROR( x6, y0 ), ROR( x7, y0 ),
                                         ROR( x8, y0 ), ROR( x9, y0 ), ROR( xa, y0 ), ROR( xb, y0 ),
                                         ROR( xc, y0 ), ROR( xd, y0 ), ROR( xe, y0 ), ROR( xf, y0 ) );
    WWU_TEST( wwu_rol_vector( x, y ),    ROL( x0, y0 ), ROL( x1, y1 ), ROL( x2, y2 ), ROL( x3, y3 ),
                                         ROL( x4, y4 ), ROL( x5, y5 ), ROL( x6, y6 ), ROL( x7, y7 ),
                                         ROL( x8, y8 ), ROL( x9, y9 ), ROL( xa, ya ), ROL( xb, yb ),
                                         ROL( xc, yc ), ROL( xd, yd ), ROL( xe, ye ), ROL( xf, yf ) );
    WWU_TEST( wwu_ror_vector( x, y ),    ROR( x0, y0 ), ROR( x1, y1 ), ROR( x2, y2 ), ROR( x3, y3 ),
                                         ROR( x4, y4 ), ROR( x5, y5 ), ROR( x6, y6 ), ROR( x7, y7 ),
                                         ROR( x8, y8 ), ROR( x9, y9 ), ROR( xa, ya ), ROR( xb, yb ),
                                         ROR( xc, yc ), ROR( xd, yd ), ROR( xe, ye ), ROR( xf, yf ) );
#   define COMPARE_WWU_ROL( j ) COMPARE16( WWU_TEST, x, wwu_rol, ROL, j );
#   define COMPARE_WWU_ROR( j ) COMPARE16( WWU_TEST, x, wwu_ror, ROR, j );
    EXPAND_32(COMPARE_WWU_ROL, 0)
    EXPAND_32(COMPARE_WWU_ROR, 0)
#   undef COMPARE_WWU_ROR
#   undef COMPARE_WWU_ROL
#   undef ROR
#   undef ROL

    WWU_TEST( wwu_bswap(x), fd_uint_bswap(x0), fd_uint_bswap(x1), fd_uint_bswap(x2), fd_uint_bswap(x3),
                            fd_uint_bswap(x4), fd_uint_bswap(x5), fd_uint_bswap(x6), fd_uint_bswap(x7),
                            fd_uint_bswap(x8), fd_uint_bswap(x9), fd_uint_bswap(xa), fd_uint_bswap(xb),
                            fd_uint_bswap(xc), fd_uint_bswap(xd), fd_uint_bswap(xe), fd_uint_bswap(xf) );

    /* Test comparison */

    int c = (int)(fd_rng_uint( rng ) & 65535U);
    wwu_t t = wwu_if( c, x, y );
    wwu_st( _b, t );
    uint t0 = _b[ 0]; uint t1 = _b[ 1]; uint t2 = _b[ 2]; uint t3 = _b[ 3];
    uint t4 = _b[ 4]; uint t5 = _b[ 5]; uint t6 = _b[ 6]; uint t7 = _b[ 7];
    uint t8 = _b[ 8]; uint t9 = _b[ 9]; uint ta = _b[10]; uint tb = _b[11];
    uint tc = _b[12]; uint td = _b[13]; uint te = _b[14]; uint tf = _b[15];

#   define TEST_CMP(fn,op)                                                                                          \
    FD_TEST( fn(x,t)==( ((x##0 op t##0)<< 0) | ((x##1 op t##1)<< 1) | ((x##2 op t##2)<< 2) | ((x##3 op t##3)<< 3) | \
                        ((x##4 op t##4)<< 4) | ((x##5 op t##5)<< 5) | ((x##6 op t##6)<< 6) | ((x##7 op t##7)<< 7) | \
                        ((x##8 op t##8)<< 8) | ((x##9 op t##9)<< 9) | ((x##a op t##a)<<10) | ((x##b op t##b)<<11) | \
                        ((x##c op t##c)<<12) | ((x##d op t##d)<<13) | ((x##e op t##e)<<14) | ((x##f op t##f)<<15) ) );

    TEST_CMP( wwu_eq, == );
    TEST_CMP( wwu_gt, >  );
    TEST_CMP( wwu_lt, <  );

    TEST_CMP( wwu_ne, != );
    TEST_CMP( wwu_ge, >= );
    TEST_CMP( wwu_le, <= );

    wwu_t tt = wwu_if( c, wwu_or( x, wwu_one() ), wwu_zero() );
    FD_TEST( wwu_lnot   ( tt )==wwu_eq( tt, wwu_zero() ) );
    FD_TEST( wwu_lnotnot( tt )==wwu_ne( tt, wwu_zero() ) );

#   undef TEST_CMP

    /* Test lane ops */

    WWU_TEST( wwu_if( c, y, z ),
              ((c>> 0)&1) ? y0 : z0, ((c>> 1)&1) ? y1 : z1, ((c>> 2)&1) ? y2 : z2, ((c>> 3)&1) ? y3 : z3,
              ((c>> 4)&1) ? y4 : z4, ((c>> 5)&1) ? y5 : z5, ((c>> 6)&1) ? y6 : z6, ((c>> 7)&1) ? y7 : z7,
              ((c>> 8)&1) ? y8 : z8, ((c>> 9)&1) ? y9 : z9, ((c>>10)&1) ? ya : za, ((c>>11)&1) ? yb : zb,
              ((c>>12)&1) ? yc : zc, ((c>>13)&1) ? yd : zd, ((c>>14)&1) ? ye : ze, ((c>>15)&1) ? yf : zf );
    WWU_TEST( wwu_add_if( c, x, y, z ),
              ((c>> 0)&1) ? (x0+y0) : z0, ((c>> 1)&1) ? (x1+y1) : z1, ((c>> 2)&1) ? (x2+y2) : z2, ((c>> 3)&1) ? (x3+y3) : z3,
              ((c>> 4)&1) ? (x4+y4) : z4, ((c>> 5)&1) ? (x5+y5) : z5, ((c>> 6)&1) ? (x6+y6) : z6, ((c>> 7)&1) ? (x7+y7) : z7,
              ((c>> 8)&1) ? (x8+y8) : z8, ((c>> 9)&1) ? (x9+y9) : z9, ((c>>10)&1) ? (xa+ya) : za, ((c>>11)&1) ? (xb+yb) : zb,
              ((c>>12)&1) ? (xc+yc) : zc, ((c>>13)&1) ? (xd+yd) : zd, ((c>>14)&1) ? (xe+ye) : ze, ((c>>15)&1) ? (xf+yf) : zf );
    WWU_TEST( wwu_sub_if( c, x, y, z ),
              ((c>> 0)&1) ? (x0-y0) : z0, ((c>> 1)&1) ? (x1-y1) : z1, ((c>> 2)&1) ? (x2-y2) : z2, ((c>> 3)&1) ? (x3-y3) : z3,
              ((c>> 4)&1) ? (x4-y4) : z4, ((c>> 5)&1) ? (x5-y5) : z5, ((c>> 6)&1) ? (x6-y6) : z6, ((c>> 7)&1) ? (x7-y7) : z7,
              ((c>> 8)&1) ? (x8-y8) : z8, ((c>> 9)&1) ? (x9-y9) : z9, ((c>>10)&1) ? (xa-ya) : za, ((c>>11)&1) ? (xb-yb) : zb,
              ((c>>12)&1) ? (xc-yc) : zc, ((c>>13)&1) ? (xd-yd) : zd, ((c>>14)&1) ? (xe-ye) : ze, ((c>>15)&1) ? (xf-yf) : zf );

    /* Test conversions */

    WWI_TEST( wwu_to_wwi( x ),      (int)x0,   (int)x1,   (int)x2,   (int)x3,   (int)x4,   (int)x5,   (int)x6,   (int)x7,
                                    (int)x8,   (int)x9,   (int)xa,   (int)xb,   (int)xc,   (int)xd,   (int)xe,   (int)xf );
    WWL_TEST( wwu_to_wwl( x, 0 ),  (long)x0,  (long)x2,  (long)x4,  (long)x6,  (long)x8,  (long)xa,  (long)xc,  (long)xe );
    WWL_TEST( wwu_to_wwl( x, 1 ),  (long)x1,  (long)x3,  (long)x5,  (long)x7,  (long)x9,  (long)xb,  (long)xd,  (long)xf );
    WWV_TEST( wwu_to_wwv( x, 0 ), (ulong)x0, (ulong)x2, (ulong)x4, (ulong)x6, (ulong)x8, (ulong)xa, (ulong)xc, (ulong)xe );
    WWV_TEST( wwu_to_wwv( x, 1 ), (ulong)x1, (ulong)x3, (ulong)x5, (ulong)x7, (ulong)x9, (ulong)xb, (ulong)xd, (ulong)xf );

    /* Test misc operations */

    WWU_TEST( wwu_pack_halves( y,0, z,0 ), y0,y1,y2,y3,y4,y5,y6,y7, z0,z1,z2,z3,z4,z5,z6,z7 );
    WWU_TEST( wwu_pack_halves( y,1, z,0 ), y8,y9,ya,yb,yc,yd,ye,yf, z0,z1,z2,z3,z4,z5,z6,z7 );
    WWU_TEST( wwu_pack_halves( y,0, z,1 ), y0,y1,y2,y3,y4,y5,y6,y7, z8,z9,za,zb,zc,zd,ze,zf );
    WWU_TEST( wwu_pack_halves( y,1, z,1 ), y8,y9,ya,yb,yc,yd,ye,yf, z8,z9,za,zb,zc,zd,ze,zf );
    WWU_TEST( wwu_pack_h0_h1 ( y,   z   ), y0,y1,y2,y3,y4,y5,y6,y7, z8,z9,za,zb,zc,zd,ze,zf );

    WWU_TEST( wwu_slide( x, y,  0 ), x0,x1,x2,x3,x4,x5,x6,x7,x8,x9,xa,xb,xc,xd,xe,xf );
    WWU_TEST( wwu_slide( x, y,  1 ), x1,x2,x3,x4,x5,x6,x7,x8,x9,xa,xb,xc,xd,xe,xf,y0 );
    WWU_TEST( wwu_slide( x, y,  2 ), x2,x3,x4,x5,x6,x7,x8,x9,xa,xb,xc,xd,xe,xf,y0,y1 );
    WWU_TEST( wwu_slide( x, y,  3 ), x3,x4,x5,x6,x7,x8,x9,xa,xb,xc,xd,xe,xf,y0,y1,y2 );
    WWU_TEST( wwu_slide( x, y,  4 ), x4,x5,x6,x7,x8,x9,xa,xb,xc,xd,xe,xf,y0,y1,y2,y3 );
    WWU_TEST( wwu_slide( x, y,  5 ), x5,x6,x7,x8,x9,xa,xb,xc,xd,xe,xf,y0,y1,y2,y3,y4 );
    WWU_TEST( wwu_slide( x, y,  6 ), x6,x7,x8,x9,xa,xb,xc,xd,xe,xf,y0,y1,y2,y3,y4,y5 );
    WWU_TEST( wwu_slide( x, y,  7 ), x7,x8,x9,xa,xb,xc,xd,xe,xf,y0,y1,y2,y3,y4,y5,y6 );
    WWU_TEST( wwu_slide( x, y,  8 ), x8,x9,xa,xb,xc,xd,xe,xf,y0,y1,y2,y3,y4,y5,y6,y7 );
    WWU_TEST( wwu_slide( x, y,  9 ), x9,xa,xb,xc,xd,xe,xf,y0,y1,y2,y3,y4,y5,y6,y7,y8 );
    WWU_TEST( wwu_slide( x, y, 10 ), xa,xb,xc,xd,xe,xf,y0,y1,y2,y3,y4,y5,y6,y7,y8,y9 );
    WWU_TEST( wwu_slide( x, y, 11 ), xb,xc,xd,xe,xf,y0,y1,y2,y3,y4,y5,y6,y7,y8,y9,ya );
    WWU_TEST( wwu_slide( x, y, 12 ), xc,xd,xe,xf,y0,y1,y2,y3,y4,y5,y6,y7,y8,y9,ya,yb );
    WWU_TEST( wwu_slide( x, y, 13 ), xd,xe,xf,y0,y1,y2,y3,y4,y5,y6,y7,y8,y9,ya,yb,yc );
    WWU_TEST( wwu_slide( x, y, 14 ), xe,xf,y0,y1,y2,y3,y4,y5,y6,y7,y8,y9,ya,yb,yc,yd );
    WWU_TEST( wwu_slide( x, y, 15 ), xf,y0,y1,y2,y3,y4,y5,y6,y7,y8,y9,ya,yb,yc,yd,ye );

    wwu_unpack( x, t0,t1,t2,t3,t4,t5,t6,t7,t8,t9,ta,tb,tc,td,te,tf );
    WWU_TEST( wwu( t0,t1,t2,t3,t4,t5,t6,t7,t8,t9,ta,tb,tc,td,te,tf ), x0,x1,x2,x3,x4,x5,x6,x7,x8,x9,xa,xb,xc,xd,xe,xf );

    wwu_t r0 = x;               wwu_t r1 = y;               wwu_t r2 = z;               wwu_t r3 = t;
    wwu_t r4 = wwu_not( x );    wwu_t r5 = wwu_not( y );    wwu_t r6 = wwu_not( z );    wwu_t r7 = wwu_not( t );
    wwu_t r8 = wwu_ror( x, 8 ); wwu_t r9 = wwu_ror( y, 8 ); wwu_t ra = wwu_ror( z, 8 ); wwu_t rb = wwu_ror( t, 8 );
    wwu_t rc = wwu_rol( x, 8 ); wwu_t rd = wwu_rol( y, 8 ); wwu_t re = wwu_rol( z, 8 ); wwu_t rf = wwu_rol( t, 8 );

    uint A [256] WW_ATTR;
    uint AT[256] WW_ATTR;

    wwu_st( A,     r0 ); wwu_st( A+ 16, r1 ); wwu_st( A+ 32, r2 ); wwu_st( A+ 48, r3 );
    wwu_st( A+ 64, r4 ); wwu_st( A+ 80, r5 ); wwu_st( A+ 96, r6 ); wwu_st( A+112, r7 );
    wwu_st( A+128, r8 ); wwu_st( A+144, r9 ); wwu_st( A+160, ra ); wwu_st( A+176, rb );
    wwu_st( A+192, rc ); wwu_st( A+208, rd ); wwu_st( A+224, re ); wwu_st( A+240, rf );

    wwu_t c0; wwu_t c1; wwu_t c2; wwu_t c3; wwu_t c4; wwu_t c5; wwu_t c6; wwu_t c7;
    wwu_t c8; wwu_t c9; wwu_t ca; wwu_t cb; wwu_t cc; wwu_t cd; wwu_t ce; wwu_t cf;

    wwu_transpose_16x16( r0,r1,r2,r3,r4,r5,r6,r7,r8,r9,ra,rb,rc,rd,re,rf, c0,c1,c2,c3,c4,c5,c6,c7,c8,c9,ca,cb,cc,cd,ce,cf );

    wwu_st( AT,     c0 ); wwu_st( AT+ 16, c1 ); wwu_st( AT+ 32, c2 ); wwu_st( AT+ 48, c3 );
    wwu_st( AT+ 64, c4 ); wwu_st( AT+ 80, c5 ); wwu_st( AT+ 96, c6 ); wwu_st( AT+112, c7 );
    wwu_st( AT+128, c8 ); wwu_st( AT+144, c9 ); wwu_st( AT+160, ca ); wwu_st( AT+176, cb );
    wwu_st( AT+192, cc ); wwu_st( AT+208, cd ); wwu_st( AT+224, ce ); wwu_st( AT+240, cf );

    for( int ii=0; ii<16; ii++ ) for( int jj=0; jj<16; jj++ ) FD_TEST( A[ii+16*jj]==AT[jj+16*ii] );

    wwu_transpose_2x8x8( r0,r1,r2,r3,r4,r5,r6,r7, c0,c1,c2,c3,c4,c5,c6,c7 );

    wwu_st( AT,     c0 ); wwu_st( AT+ 16, c1 ); wwu_st( AT+ 32, c2 ); wwu_st( AT+ 48, c3 );
    wwu_st( AT+ 64, c4 ); wwu_st( AT+ 80, c5 ); wwu_st( AT+ 96, c6 ); wwu_st( AT+112, c7 );
    for( int kk=0; kk<2; kk++ )
      for( int ii=0; ii<8; ii++ )
        for( int jj=0; jj<8; jj++ ) FD_TEST( A[8*kk+ii+16*jj]==AT[8*kk+jj+16*ii] );
  }

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
