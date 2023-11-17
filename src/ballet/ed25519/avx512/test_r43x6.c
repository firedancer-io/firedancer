#include "../../fd_ballet.h"
#include "fd_r43x6.h"

FD_FN_CONST static fd_r43x6_t
fd_r43x6_unpack_ref( wv_t x ) {
  union { wv_t    v; ulong lane[4]; } xx;
  union { __m512i v; ulong lane[8]; } yy;

  xx.v = x;
  ulong x0 = xx.lane[0]; /* x0 arbitrary */
  ulong x1 = xx.lane[1]; /* x1 arbitrary */
  ulong x2 = xx.lane[2]; /* x2 arbitrary */
  ulong x3 = xx.lane[3]; /* x3 arbitrary */

  ulong const m43 = (1UL<<43)-1UL;
  ulong y0 =   x0                      & m43;
  ulong y1 = ((x0 >> 43) | (x1 << 21)) & m43;
  ulong y2 = ((x1 >> 22) | (x2 << 42)) & m43;
  ulong y3 =  (x2 >>  1)               & m43;
  ulong y4 = ((x2 >> 44) | (x3 << 20)) & m43;
  ulong y5 =  (x3 >> 23);
  ulong y6 = 0UL;
  ulong y7 = 0UL;

  yy.lane[0] = y0; FD_TEST( y0<(1UL<<43) );
  yy.lane[1] = y1; FD_TEST( y1<(1UL<<43) );
  yy.lane[2] = y2; FD_TEST( y2<(1UL<<43) );
  yy.lane[3] = y3; FD_TEST( y3<(1UL<<43) );
  yy.lane[4] = y4; FD_TEST( y4<(1UL<<43) );
  yy.lane[5] = y5; FD_TEST( y5<(1UL<<41) );
  yy.lane[6] = y6; FD_TEST( y6==0UL      );
  yy.lane[7] = y7; FD_TEST( y7==0UL      );
  return yy.v;
}

FD_FN_CONST static wv_t
fd_r43x6_pack_ref( fd_r43x6_t x ) {
  union { __m512i v; ulong lane[8]; } xx;

  xx.v = x;
  ulong x0 = xx.lane[0]; FD_TEST( x0 < (1UL<<43) );
  ulong x1 = xx.lane[1]; FD_TEST( x1 < (1UL<<43) );
  ulong x2 = xx.lane[2]; FD_TEST( x2 < (1UL<<43) );
  ulong x3 = xx.lane[3]; FD_TEST( x3 < (1UL<<43) );
  ulong x4 = xx.lane[4]; FD_TEST( x4 < (1UL<<43) );
  ulong x5 = xx.lane[5]; FD_TEST( x5 < (1UL<<41) );
  /* x6 arbitrary */
  /* x7 arbitrary */

  ulong u0 =  x0      | (x1<<43);            /* u0 arbitrary */
  ulong u1 = (x1>>21) | (x2<<22);            /* u1 arbitrary */
  ulong u2 = (x2>>42) | (x3<< 1) | (x4<<44); /* u2 arbitrary */
  ulong u3 = (x4>>20) | (x5<<23);            /* u3 arbitrary */

  return wv( u0, u1, u2, u3 );
}

FD_FN_CONST static fd_r43x6_t
fd_r43x6_approx_carry_propagate_ref( fd_r43x6_t x ) {
  union { __m512i v; long lane[8]; } xx, yy;

  xx.v = x;
  long x0 = xx.lane[0]; /* x0 arbitrary */
  long x1 = xx.lane[1]; /* x1 arbitrary */
  long x2 = xx.lane[2]; /* x2 arbitrary */
  long x3 = xx.lane[3]; /* x3 arbitrary */
  long x4 = xx.lane[4]; /* x4 arbitrary */
  long x5 = xx.lane[5]; /* x5 arbitrary */
  /* x6 and x7 arbitrary */

  long const m43 = (1L<<43) - 1L;
  long const m40 = (1L<<40) - 1L;
  long y0 = (x0 & m43) + 19L*(x5 >> 40);
  long y1 = (x1 & m43) +     (x0 >> 43);
  long y2 = (x2 & m43) +     (x1 >> 43);
  long y3 = (x3 & m43) +     (x2 >> 43);
  long y4 = (x4 & m43) +     (x3 >> 43);
  long y5 = (x5 & m40) +     (x4 >> 43);

  yy.lane[0] = y0; FD_TEST( (-(19L<<23))<=y0 ); FD_TEST( y0<=(m43+(19L<<23)-19L) );
  yy.lane[1] = y1; FD_TEST( (-( 1L<<20))<=y1 ); FD_TEST( y1<=(m43+( 1L<<20)- 1L) );
  yy.lane[2] = y2; FD_TEST( (-( 1L<<20))<=y2 ); FD_TEST( y2<=(m43+( 1L<<20)- 1L) );
  yy.lane[3] = y3; FD_TEST( (-( 1L<<20))<=y3 ); FD_TEST( y3<=(m43+( 1L<<20)- 1L) );
  yy.lane[4] = y4; FD_TEST( (-( 1L<<20))<=y4 ); FD_TEST( y4<=(m43+( 1L<<20)- 1L) );
  yy.lane[5] = y5; FD_TEST( (-( 1L<<20))<=y5 ); FD_TEST( y5<=(m40+( 1L<<20)- 1L) );
  yy.lane[6] = 0L;
  yy.lane[7] = 0L;

  return yy.v;
}

FD_FN_CONST static fd_r43x6_t
fd_r43x6_fold_unsigned_ref( fd_r43x6_t x ) {
  union { __m512i v; long lane[8]; } yy;

  yy.v = x;
  FD_TEST( 0L<=yy.lane[0] );
  FD_TEST( 0L<=yy.lane[1] );
  FD_TEST( 0L<=yy.lane[2] );
  FD_TEST( 0L<=yy.lane[3] );
  FD_TEST( 0L<=yy.lane[4] );
  FD_TEST( 0L<=yy.lane[5] );

  yy.v = fd_r43x6_approx_carry_propagate_ref( yy.v );

  FD_TEST( 0L<=yy.lane[0] );
  FD_TEST( 0L<=yy.lane[1] );
  FD_TEST( 0L<=yy.lane[2] );
  FD_TEST( 0L<=yy.lane[3] );
  FD_TEST( 0L<=yy.lane[4] );
  FD_TEST( 0L<=yy.lane[5] );

  return yy.v;
}

FD_FN_CONST static fd_r43x6_t
fd_r43x6_fold_signed_ref( fd_r43x6_t x ) {
  union { __m512i v; long lane[8]; } yy;

  yy.v = x;
  FD_TEST( (LONG_MIN+(19L<<23))<=yy.lane[0] );
  FD_TEST( (LONG_MIN+( 1L<<20))<=yy.lane[1] );
  FD_TEST( (LONG_MIN+( 1L<<20))<=yy.lane[2] );
  FD_TEST( (LONG_MIN+( 1L<<20))<=yy.lane[3] );
  FD_TEST( (LONG_MIN+( 1L<<20))<=yy.lane[4] );
  FD_TEST( (LONG_MIN+( 1L<<20))<=yy.lane[5] );
  /* x6 and x7 arbitrary */

  yy.lane[0] -= 19L<<23;
  yy.lane[1] -=  1L<<20;
  yy.lane[2] -=  1L<<20;
  yy.lane[3] -=  1L<<20;
  yy.lane[4] -=  1L<<20;
  yy.lane[5] -=  1L<<20;

  yy.v = fd_r43x6_approx_carry_propagate_ref( yy.v );

  yy.lane[0] += 19L<<23;
  yy.lane[1] +=  1L<<20;
  yy.lane[2] +=  1L<<20;
  yy.lane[3] +=  1L<<20;
  yy.lane[4] +=  1L<<20;
  yy.lane[5] +=  1L<<20;

  return yy.v;
}

FD_FN_CONST static fd_r43x6_t
fd_r43x6_biased_carry_propagate_ref( fd_r43x6_t x,
                                     long       b ) {
  union { __m512i v; long lane[8]; } yy;

  yy.v = x;
  long y0 = yy.lane[0]; FD_TEST( (LONG_MIN+(19L<<23))<=y0 ); FD_TEST( y0<=(LONG_MAX-(19L<<23)+19L) );
  long y1 = yy.lane[1]; FD_TEST( (LONG_MIN+( 1L<<20))<=y1 ); FD_TEST( y1<=(LONG_MAX-( 1L<<20)+ 1L) );
  long y2 = yy.lane[2]; FD_TEST( (LONG_MIN+( 1L<<20))<=y2 ); FD_TEST( y2<=(LONG_MAX-( 1L<<20)+ 1L) );
  long y3 = yy.lane[3]; FD_TEST( (LONG_MIN+( 1L<<20))<=y3 ); FD_TEST( y3<=(LONG_MAX-( 1L<<20)+ 1L) );
  long y4 = yy.lane[4]; FD_TEST( (LONG_MIN+( 1L<<20))<=y4 ); FD_TEST( y4<=(LONG_MAX-( 1L<<20)+ 1L) );
  long y5 = yy.lane[5]; FD_TEST( (LONG_MIN+b        )<=y5 );

  FD_TEST( 0L<=b ); FD_TEST( b<=(1L<<20) );

  long const m43 = (1L<<43) - 1L;
  long const m40 = (1L<<40) - 1L;
  long c;
  y5 -= b;
  c = y5>>40; y5 &= m40; y0 += 19L*c;
  c = y0>>43; y0 &= m43; y1 +=     c;
  c = y1>>43; y1 &= m43; y2 +=     c;
  c = y2>>43; y2 &= m43; y3 +=     c;
  c = y3>>43; y3 &= m43; y4 +=     c;
  c = y4>>43; y4 &= m43; y5 +=     c;
  y5 += b;

  yy.lane[0] = y0; FD_TEST( 0L           <=y0 ); FD_TEST( y0<= m43                );
  yy.lane[1] = y1; FD_TEST( 0L           <=y1 ); FD_TEST( y1<= m43                );
  yy.lane[2] = y2; FD_TEST( 0L           <=y2 ); FD_TEST( y2<= m43                );
  yy.lane[3] = y3; FD_TEST( 0L           <=y3 ); FD_TEST( y3<= m43                );
  yy.lane[4] = y4; FD_TEST( 0L           <=y4 ); FD_TEST( y4<= m43                );
  yy.lane[5] = y5; FD_TEST( (-(1L<<20)+b)<=y5 ); FD_TEST( y5<=(m40+(1L<<20)-1L+b) );
  yy.lane[6] = 0L;
  yy.lane[7] = 0L;

  return yy.v;
}

FD_FN_CONST static fd_r43x6_t
fd_r43x6_mod_nearly_reduced_ref( fd_r43x6_t x ) {
  union { __m512i v; long lane[8]; } yy;

  yy.v = x;
  long y0 = yy.lane[0]; FD_TEST( 0L<=y0 ); FD_TEST( y0<=(1L<<43) );
  long y1 = yy.lane[1]; FD_TEST( 0L<=y1 ); FD_TEST( y1<=(1L<<43) );
  long y2 = yy.lane[2]; FD_TEST( 0L<=y2 ); FD_TEST( y2<=(1L<<43) );
  long y3 = yy.lane[3]; FD_TEST( 0L<=y3 ); FD_TEST( y3<=(1L<<43) );
  long y4 = yy.lane[4]; FD_TEST( 0L<=y4 ); FD_TEST( y4<=(1L<<43) );
  long y5 = yy.lane[5]; FD_TEST( 0L<=y5 ); FD_TEST( y5<=(1L<<41) );
  long y6 = 0L;         /* x6 arbitrary */
  long y7 = 0L;         /* x7 arbitrary */

  long const m43 = (1L<<43) - 1L;
  long const m40 = (1L<<40) - 1L;
  long c;

  y0 += 19L;
  c = y0 >> 43; y0 &= m43; y1 += c;
  c = y1 >> 43; y1 &= m43; y2 += c;
  c = y2 >> 43; y2 &= m43; y3 += c;
  c = y3 >> 43; y3 &= m43; y4 += c;
  c = y4 >> 43; y5 &= m43; y5 += c;
  c = y5 >> 40; y5 &= m40;          FD_TEST( 0L<=c ); FD_TEST( c<=1L ); /* Makes sure x in [0,2*p) too */

  y0 -= fd_long_if( !c, 19L, 0L );
  c = y0 >> 43; y0 &= m43; y1 += c;
  c = y1 >> 43; y1 &= m43; y2 += c;
  c = y2 >> 43; y2 &= m43; y3 += c;
  c = y3 >> 43; y3 &= m43; y4 += c;
  c = y4 >> 43; y4 &= m43; y5 += c;

  yy.lane[0] = y0; FD_TEST( 0L<=y0 ); FD_TEST( y0<(1L<<43) );
  yy.lane[1] = y1; FD_TEST( 0L<=y1 ); FD_TEST( y1<(1L<<43) );
  yy.lane[2] = y2; FD_TEST( 0L<=y2 ); FD_TEST( y2<(1L<<43) );
  yy.lane[3] = y3; FD_TEST( 0L<=y3 ); FD_TEST( y3<(1L<<43) );
  yy.lane[4] = y4; FD_TEST( 0L<=y4 ); FD_TEST( y4<(1L<<43) );
  yy.lane[5] = y5; FD_TEST( 0L<=y5 ); FD_TEST( y5<(1L<<40) );
  yy.lane[6] = y6; FD_TEST( 0L==y6 );
  yy.lane[7] = y7; FD_TEST( 0L==y7 );

  y0 += 19L;
  c = y0 >> 43; y0 &= m43; y1 += c;
  c = y1 >> 43; y1 &= m43; y2 += c;
  c = y2 >> 43; y2 &= m43; y3 += c;
  c = y3 >> 43; y3 &= m43; y4 += c;
  c = y4 >> 43; y4 &= m43; y5 += c;
  c = y5 >> 40; FD_TEST( !c ); /* Makes sure y in [0,p) */

  return yy.v;
}

FD_FN_CONST static fd_r43x6_t
fd_r43x6_approx_mod_ref( fd_r43x6_t x ) {
  union { __m512i v; long lane[8]; } xx;

  x = fd_r43x6_biased_carry_propagate_ref( fd_r43x6_approx_carry_propagate_ref( x ), 1L );

  xx.v = x;
  FD_TEST( 0L<=xx.lane[5] ); FD_TEST( xx.lane[5]<((1L<<40)+2L) );

  return x;
}

#define fd_r43x6_approx_mod_signed_ref( x ) fd_r43x6_biased_carry_propagate_ref( (x), 1L<<20 )

FD_FN_CONST static fd_r43x6_t
fd_r43x6_approx_mod_unsigned_ref( fd_r43x6_t x ) {
  union { __m512i v; long lane[8]; } xx;

  xx.v = x;
  FD_TEST( 0L<=xx.lane[0] );
  FD_TEST( 0L<=xx.lane[1] );
  FD_TEST( 0L<=xx.lane[2] );
  FD_TEST( 0L<=xx.lane[3] );
  FD_TEST( 0L<=xx.lane[4] );
  FD_TEST( 0L<=xx.lane[5] );

  x = fd_r43x6_biased_carry_propagate_ref( x, 0L );

  xx.v = x;
  FD_TEST( 0L<=xx.lane[5] ); FD_TEST( xx.lane[5]<((1L<<40)+(1L<<20)-1L) );

  return x;
}

/* TODO: Test tighter y5 ranges */
#define fd_r43x6_approx_mod_unreduced_ref fd_r43x6_approx_mod_unsigned_ref
#define fd_r43x6_approx_mod_unpacked_ref  fd_r43x6_approx_mod_unsigned_ref

#define fd_r43x6_mod_ref( x ) fd_r43x6_mod_nearly_reduced_ref( fd_r43x6_approx_mod( (x) ) )

FD_FN_CONST static fd_r43x6_t
fd_r43x6_add_fast_ref( fd_r43x6_t x,
                       fd_r43x6_t y ) {
  union { __m512i v; long lane[8]; } xx, yy, zz;
  xx.v = x; /* Arb */
  yy.v = y; /* Arb */
  for( ulong i=0UL; i<8UL; i++ ) zz.lane[i] = xx.lane[i] + yy.lane[i];
  return zz.v; /* Arb */
}

FD_FN_CONST static fd_r43x6_t
fd_r43x6_sub_fast_ref( fd_r43x6_t x,
                       fd_r43x6_t y ) {
  union { __m512i v; long lane[8]; } xx, yy, zz;
  xx.v = x; /* Arb */
  yy.v = y; /* Arb */
  for( ulong i=0UL; i<8UL; i++ ) zz.lane[i] = xx.lane[i] - yy.lane[i];
  return zz.v; /* Arb */
}

static fd_r43x6_t
fd_r43x6_mul_fast_ref( fd_r43x6_t x,
                       fd_r43x6_t y ) {
  union { __m512i v; ulong lane[8]; } xx, yy, zz;

  xx.v = x;                        yy.v = y;
  FD_TEST( xx.lane[0]<(1UL<<47) ); FD_TEST( yy.lane[0]<(1UL<<47) );
  FD_TEST( xx.lane[1]<(1UL<<47) ); FD_TEST( yy.lane[1]<(1UL<<47) );
  FD_TEST( xx.lane[2]<(1UL<<47) ); FD_TEST( yy.lane[2]<(1UL<<47) );
  FD_TEST( xx.lane[3]<(1UL<<47) ); FD_TEST( yy.lane[3]<(1UL<<47) );
  FD_TEST( xx.lane[4]<(1UL<<47) ); FD_TEST( yy.lane[4]<(1UL<<47) );
  FD_TEST( xx.lane[5]<(1UL<<47) ); FD_TEST( yy.lane[5]<(1UL<<47) );
  /* xx 6 lane arb */              FD_TEST( yy.lane[6]==0UL );
  /* xx 7 lane arb */              FD_TEST( yy.lane[7]==0UL );

  ulong const m52 = (1UL<<52)-1UL;

  ulong s[12]; for( ulong i=0UL; i<12UL; i++ ) s[i] = 0UL;

  for( ulong i=0UL; i<6UL; i++ ) {
    for( ulong j=0UL; j<6UL; j++ ) {
      uint128 pij = ((uint128)xx.lane[i])*((uint128)yy.lane[j]);
      s[i+j    ] += ((ulong) pij     ) & m52;
      s[i+j+1UL] += ((ulong)(pij>>52)) << 9;
    }
  }

  FD_TEST( s[ 0] < ( 2UL<<51) ); FD_TEST( s[ 6] < (16UL<<51) );
  FD_TEST( s[ 1] < ( 5UL<<51) ); FD_TEST( s[ 7] < (13UL<<51) );
  FD_TEST( s[ 2] < ( 8UL<<51) ); FD_TEST( s[ 8] < (10UL<<51) );
  FD_TEST( s[ 3] < (11UL<<51) ); FD_TEST( s[ 9] < ( 7UL<<51) );
  FD_TEST( s[ 4] < (14UL<<51) ); FD_TEST( s[10] < ( 4UL<<51) );
  FD_TEST( s[ 5] < (17UL<<51) ); FD_TEST( s[11] < ( 1UL<<51) );

  ulong z0 = s[0] + 152UL*s[ 6];
  ulong z1 = s[1] + 152UL*s[ 7];
  ulong z2 = s[2] + 152UL*s[ 8];
  ulong z3 = s[3] + 152UL*s[ 9];
  ulong z4 = s[4] + 152UL*s[10];
  ulong z5 = s[5] + 152UL*s[11];
  ulong z6 = 0UL;
  ulong z7 = 0UL;

  zz.lane[0] = z0; FD_TEST( z0<(2434UL<<51) );
  zz.lane[1] = z1; FD_TEST( z1<(1981UL<<51) );
  zz.lane[2] = z2; FD_TEST( z2<(1528UL<<51) );
  zz.lane[3] = z3; FD_TEST( z3<(1075UL<<51) );
  zz.lane[4] = z4; FD_TEST( z4<( 622UL<<51) );
  zz.lane[5] = z5; FD_TEST( z5<( 169UL<<51) );
  zz.lane[6] = z6; FD_TEST( z6==0L          );
  zz.lane[7] = z7; FD_TEST( z7==0L          );

  return zz.v;
}

static fd_r43x6_t
fd_r43x6_sqr_fast_ref( fd_r43x6_t y ) {
  union { __m512i v; ulong lane[8]; } yy, zz;

  yy.v = y;
  FD_TEST( yy.lane[0]<(1UL<<47) );
  FD_TEST( yy.lane[1]<(1UL<<47) );
  FD_TEST( yy.lane[2]<(1UL<<47) );
  FD_TEST( yy.lane[3]<(1UL<<47) );
  FD_TEST( yy.lane[4]<(1UL<<47) );
  FD_TEST( yy.lane[5]<(1UL<<47) );
  FD_TEST( yy.lane[6]==0UL );
  FD_TEST( yy.lane[7]==0UL );

  ulong const m52 = (1UL<<52)-1UL;

  ulong s[12]; for( ulong i=0UL; i<12UL; i++ ) s[i] = 0UL;

  for( ulong i=0UL; i<6UL; i++ ) {
    for( ulong j=0; j<=i; j++ ) {
      uint128 pij = ((uint128)yy.lane[i])*((uint128)yy.lane[j]);
      pij <<= (int)(j<i);
      s[i+j    ] += ((ulong) pij     ) & m52;
      s[i+j+1UL] += ((ulong)(pij>>52)) << 9;
    }
  }

  FD_TEST( s[ 0] < ( 2UL<<51) ); FD_TEST( s[ 6] < (16UL<<51) );
  FD_TEST( s[ 1] < ( 5UL<<51) ); FD_TEST( s[ 7] < (13UL<<51) );
  FD_TEST( s[ 2] < ( 8UL<<51) ); FD_TEST( s[ 8] < (10UL<<51) );
  FD_TEST( s[ 3] < (11UL<<51) ); FD_TEST( s[ 9] < ( 7UL<<51) );
  FD_TEST( s[ 4] < (14UL<<51) ); FD_TEST( s[10] < ( 4UL<<51) );
  FD_TEST( s[ 5] < (17UL<<51) ); FD_TEST( s[11] < ( 1UL<<51) );

  ulong z0 = s[0] + 152UL*s[ 6];
  ulong z1 = s[1] + 152UL*s[ 7];
  ulong z2 = s[2] + 152UL*s[ 8];
  ulong z3 = s[3] + 152UL*s[ 9];
  ulong z4 = s[4] + 152UL*s[10];
  ulong z5 = s[5] + 152UL*s[11];
  ulong z6 = 0UL;
  ulong z7 = 0UL;

  zz.lane[0] = z0; FD_TEST( z0<(1826UL<<51) );
  zz.lane[1] = z1; FD_TEST( z1<(1371UL<<51) );
  zz.lane[2] = z2; FD_TEST( z2<(1222UL<<51) );
  zz.lane[3] = z3; FD_TEST( z3<( 767UL<<51) );
  zz.lane[4] = z4; FD_TEST( z4<( 618UL<<51) );
  zz.lane[5] = z5; FD_TEST( z5<( 163UL<<51) );
  zz.lane[6] = z6; FD_TEST( z6==0L          );
  zz.lane[7] = z7; FD_TEST( z7==0L          );

  return zz.v;
}

/**********************************************************************/

static wv_t
uint256_rand( fd_rng_t * rng ) {
  ulong u0 = fd_rng_ulong( rng );
  ulong u1 = fd_rng_ulong( rng );
  ulong u2 = fd_rng_ulong( rng );
  ulong u3 = fd_rng_ulong( rng );
  return wv( u0, u1, u2, u3 );
}

FD_FN_CONST static inline int
uint256_eq( wv_t x,
            wv_t y ) {
  return wc_all( wv_eq( x, y ) );
}

static fd_r43x6_t
fd_r43x6_rand( fd_rng_t * rng ) {
  union { __m512i v; ulong lane[8]; } t;
  for( ulong l=0UL; l<8UL; l++ ) t.lane[l] = fd_rng_ulong( rng );
  return t.v;
}

static fd_r43x6_t
fd_r43x6_rand_unsigned( fd_rng_t * rng ) {
  union { __m512i v; ulong lane[8]; } t;
  for( ulong l=0UL; l<6UL; l++ ) t.lane[l] = fd_rng_ulong( rng ) >> 2; /* In u62 */
  t.lane[6] = fd_rng_ulong( rng );
  t.lane[7] = fd_rng_ulong( rng );
  return t.v;
}

static fd_r43x6_t
fd_r43x6_rand_signed( fd_rng_t * rng ) {
  union { __m512i v; ulong lane[8]; } t;
  for( ulong l=0UL; l<6UL; l++ ) t.lane[l] = (fd_rng_ulong( rng ) >> 1) - (1UL<<62); /* In [-2^62,2^62) after casting to long */
  t.lane[6] = fd_rng_ulong( rng );
  t.lane[7] = fd_rng_ulong( rng );
  return t.v;
}

static fd_r43x6_t
fd_r43x6_rand_unreduced( fd_rng_t * rng ) {
  union { __m512i v; ulong lane[8]; } t;
  for( ulong l=0UL; l<6UL; l++ ) t.lane[l] = fd_rng_ulong( rng ) >> 17; /* In u47 */
  t.lane[6] = fd_rng_ulong( rng );
  t.lane[7] = fd_rng_ulong( rng );
  return t.v;
}

static fd_r43x6_t
fd_r43x6_rand_unpacked( fd_rng_t * rng ) {
  union { __m512i v; ulong lane[8]; } t;
  for( ulong l=0UL; l<5UL; l++ ) t.lane[l] = fd_rng_ulong( rng ) >> 21; /* In u43 */
  t.lane[5] = fd_rng_ulong( rng ) >> 23; /* In u41 */
  t.lane[6] = fd_rng_ulong( rng );
  t.lane[7] = fd_rng_ulong( rng );
  return t.v;
}

static fd_r43x6_t
fd_r43x6_rand_unreduced_z67( fd_rng_t * rng ) {
  union { __m512i v; ulong lane[8]; } t;
  for( ulong l=0UL; l<6UL; l++ ) t.lane[l] = fd_rng_ulong( rng ) >> 17; /* In u47 */
  t.lane[6] = 0UL;
  t.lane[7] = 0UL;
  return t.v;
}

/* Note this tests that the two representations are the same, including
   lanes 6 and 7.  Reduce x and y first or, if applicable, compute x-y
   and test if the result is a zero representation if testing if x and y
   represent the same element. */

FD_FN_CONST static inline int
fd_r43x6_eq( fd_r43x6_t x,
             fd_r43x6_t y ) {
  union { __m512i v; wv_t lane[2]; } t, u;
  t.v = x;
  u.v = y;
  return uint256_eq( t.lane[0], u.lane[0] ) & uint256_eq( t.lane[1], u.lane[1] ); /* FIXME: CAN BE FASTER */
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  ulong iter_max = fd_env_strip_cmdline_ulong( &argc, &argv, "--iter-max", NULL, 10000000UL );
  ulong warm_max = fd_env_strip_cmdline_ulong( &argc, &argv, "--warm-max", NULL, 100UL      );

  FD_LOG_NOTICE(( "Testing with --iter-max %lu --warm-max %lu", iter_max, warm_max ));

  fd_rng_t _rng[1]; fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, 0U, 0UL ) );

  ulong ctr = 0UL;
  for( ulong rem=iter_max; rem; rem-- ) {
    if( FD_UNLIKELY( !ctr ) ) {
      FD_LOG_NOTICE(( "%20lu iterations remaining", rem ));
      ctr = 1000000UL;
    }
    ctr--;

    fd_r43x6_t x; long x0, x1, x2, x3, x4, x5;
    fd_r43x6_t y; long y0, y1, y2, y3, y4, y5;
    wv_t u;
    wv_t v;
    wv_t w;

    /* Test constructors */

    x0 = (long)fd_rng_ulong( rng );
    x1 = (long)fd_rng_ulong( rng );
    x2 = (long)fd_rng_ulong( rng );
    x3 = (long)fd_rng_ulong( rng );
    x4 = (long)fd_rng_ulong( rng );
    x5 = (long)fd_rng_ulong( rng );
    x = fd_r43x6( x0, x1, x2, x3, x4, x5 );
    fd_r43x6_extract_limbs( x, y );
    FD_TEST( x0==y0 ); FD_TEST( x1==y1 ); FD_TEST( x2==y2 ); FD_TEST( x3==y3 ); FD_TEST( x4==y4 ); FD_TEST( x5==y5 );

    /* Testing pack/unpack */

    u = uint256_rand( rng );
    x = fd_r43x6_unpack( u );   y = fd_r43x6_unpack_ref( u ); FD_TEST( fd_r43x6_eq  ( x, y ) );
    v = fd_r43x6_pack( x );     w = fd_r43x6_pack_ref( x );   FD_TEST( uint256_eq( v, w ) );
    FD_TEST( uint256_eq( u, v ) );

    /* Test fold/approx_mod/mod */

    x = fd_r43x6_rand( rng );
    FD_TEST( fd_r43x6_eq( fd_r43x6_approx_mod( x ), fd_r43x6_approx_mod_ref( x ) ) );
    FD_TEST( fd_r43x6_eq( fd_r43x6_mod       ( x ), fd_r43x6_mod_ref       ( x ) ) );

    x = fd_r43x6_rand_signed( rng );
    FD_TEST( fd_r43x6_eq( fd_r43x6_fold_signed      ( x ), fd_r43x6_fold_signed_ref      ( x ) ) );
    FD_TEST( fd_r43x6_eq( fd_r43x6_approx_mod_signed( x ), fd_r43x6_approx_mod_signed_ref( x ) ) );
    FD_TEST( fd_r43x6_eq( fd_r43x6_mod_signed       ( x ), fd_r43x6_mod_ref              ( x ) ) );

    x = fd_r43x6_rand_unsigned( rng );
    FD_TEST( fd_r43x6_eq( fd_r43x6_fold_unsigned      ( x ), fd_r43x6_fold_unsigned_ref      ( x ) ) );
    FD_TEST( fd_r43x6_eq( fd_r43x6_approx_mod_unsigned( x ), fd_r43x6_approx_mod_unsigned_ref( x ) ) );
    FD_TEST( fd_r43x6_eq( fd_r43x6_mod_unsigned       ( x ), fd_r43x6_mod_ref                ( x ) ) );

    x = fd_r43x6_rand_unreduced( rng );
    FD_TEST( fd_r43x6_eq( fd_r43x6_approx_mod_unreduced( x ), fd_r43x6_approx_mod_unreduced_ref( x ) ) );
    FD_TEST( fd_r43x6_eq( fd_r43x6_mod_unreduced       ( x ), fd_r43x6_mod_ref                 ( x ) ) );

    x = fd_r43x6_rand_unpacked( rng );
    FD_TEST( fd_r43x6_eq( fd_r43x6_approx_mod_unpacked( x ), fd_r43x6_approx_mod_unpacked_ref( x ) ) );
    FD_TEST( fd_r43x6_eq( fd_r43x6_mod_unpacked       ( x ), fd_r43x6_mod_ref                ( x ) ) );

    x = fd_r43x6_approx_mod( fd_r43x6_rand( rng ) );
    FD_TEST( fd_r43x6_eq( fd_r43x6_mod_nearly_reduced( x ), fd_r43x6_mod_ref( x ) ) );

    /* Test neg_fast/add_fast/sub_fast */

    x = fd_r43x6_rand( rng );
    y = fd_r43x6_rand( rng );

    FD_TEST( fd_r43x6_eq( fd_r43x6_neg_fast( x ),    fd_r43x6_sub_fast_ref( fd_r43x6_zero(), x ) ) );
    FD_TEST( fd_r43x6_eq( fd_r43x6_add_fast( x, y ), fd_r43x6_add_fast_ref( x, y ) ) );
    FD_TEST( fd_r43x6_eq( fd_r43x6_sub_fast( x, y ), fd_r43x6_sub_fast_ref( x, y ) ) );

    /* Test mul_fast/sqr_fast/scale_fast */

    x = fd_r43x6_rand_unreduced    ( rng );
    y = fd_r43x6_rand_unreduced_z67( rng );

    x0 &= (1L<<47)-1L;

    FD_TEST( fd_r43x6_eq( fd_r43x6_mul_fast  ( x, y ),  fd_r43x6_mul_fast_ref( x, y ) ) );
    FD_TEST( fd_r43x6_eq( fd_r43x6_sqr_fast  ( y ),     fd_r43x6_sqr_fast_ref( y )    ) );
    FD_TEST( fd_r43x6_eq( fd_r43x6_scale_fast( x0, y ), fd_r43x6_mul_fast( fd_r43x6(x0,0L,0L,0L,0L,0L), y ) ) );

    /* Test neg/add/sub/mul/sqr/scale */

    FD_TEST( fd_r43x6_eq( fd_r43x6_neg( x ),       fd_r43x6_fold_signed  ( fd_r43x6_neg_fast( x ) ) ) );
    FD_TEST( fd_r43x6_eq( fd_r43x6_add( x, y ),    fd_r43x6_fold_unsigned( fd_r43x6_add_fast( x, y ) ) ) );
    FD_TEST( fd_r43x6_eq( fd_r43x6_sub( x, y ),    fd_r43x6_fold_signed  ( fd_r43x6_sub_fast( x, y ) ) ) );
    FD_TEST( fd_r43x6_eq( fd_r43x6_mul( x, y ),    fd_r43x6_fold_unsigned( fd_r43x6_mul_fast( x, y ) ) ) );
    FD_TEST( fd_r43x6_eq( fd_r43x6_sqr( y ),       fd_r43x6_fold_unsigned( fd_r43x6_sqr_fast( y ) ) ) );
    FD_TEST( fd_r43x6_eq( fd_r43x6_scale( x0, y ), fd_r43x6_fold_unsigned( fd_r43x6_scale_fast( x0, y ) ) ) );

    /* Note: invert uses a separate tester */

    /* Test if / swap_if */

    int c = (int)(fd_rng_uint( rng ) & 1U);
    FD_TEST( fd_r43x6_eq( fd_r43x6_if( c, x, y ), c ? x : y ) );
    fd_r43x6_t xx = x;
    fd_r43x6_t yy = y;
    fd_r43x6_swap_if( c, xx, yy );
    FD_TEST( fd_r43x6_eq( xx, c ? y : x ) );
    FD_TEST( fd_r43x6_eq( yy, c ? x : y ) );

    /* Note: is_nonzero, diagnose, pow22523 use a separate tester */

    /* Test inlines */

    if(1) {
      fd_r43x6_t x0 = fd_r43x6_rand_unreduced_z67( rng ); fd_r43x6_t y0 = fd_r43x6_rand_unreduced_z67( rng ); fd_r43x6_t z0;
      fd_r43x6_t x1 = fd_r43x6_rand_unreduced_z67( rng ); fd_r43x6_t y1 = fd_r43x6_rand_unreduced_z67( rng ); fd_r43x6_t z1;
      fd_r43x6_t x2 = fd_r43x6_rand_unreduced_z67( rng ); fd_r43x6_t y2 = fd_r43x6_rand_unreduced_z67( rng ); fd_r43x6_t z2;
      fd_r43x6_t x3 = fd_r43x6_rand_unreduced_z67( rng ); fd_r43x6_t y3 = fd_r43x6_rand_unreduced_z67( rng ); fd_r43x6_t z3;

      FD_R43X6_QUAD_DECL( X ); FD_R43X6_QUAD_PACK( X, x0,x1,x2,x3 );
      FD_R43X6_QUAD_DECL( Y ); FD_R43X6_QUAD_PACK( Y, y0,y1,y2,y3 );
      FD_R43X6_QUAD_DECL( Z );

      /* Test PACK/UNPACK/PERMUTE inlines */

      FD_R43X6_QUAD_MOV( Z, Y );
      FD_R43X6_QUAD_UNPACK( z0,z1,z2,z3, Z );
      FD_TEST( fd_r43x6_eq( y0, z0 ) ); FD_TEST( fd_r43x6_eq( y1, z1 ) );
      FD_TEST( fd_r43x6_eq( y2, z2 ) ); FD_TEST( fd_r43x6_eq( y3, z3 ) );

      uint perm = fd_rng_uint( rng );
      int p0 = (int)(perm & 3U); perm >>= 2; int p1 = (int)(perm & 3U); perm >>= 4;
      int p2 = (int)(perm & 3U); perm >>= 6; int p3 = (int)(perm & 3U); perm >>= 8;
      fd_r43x6_t b[4]; b[0] = x0; b[1] = x1; b[2] = x2; b[3] = x3;
      FD_R43X6_QUAD_PERMUTE( Z, p0,p1,p2,p3, X );
      FD_R43X6_QUAD_UNPACK( z0,z1,z2,z3, Z );
      FD_TEST( fd_r43x6_eq( b[p0], z0 ) ); FD_TEST( fd_r43x6_eq( b[p1], z1 ) );
      FD_TEST( fd_r43x6_eq( b[p2], z2 ) ); FD_TEST( fd_r43x6_eq( b[p3], z3 ) );

      /* Test LANE inlines */

      p0 &= 1; p1 &= 1; p2 &= 1; p3 &= 1;
      FD_R43X6_QUAD_LANE_IF( Z, p0,p1,p2,p3, Y, X );
      FD_R43X6_QUAD_UNPACK( z0,z1,z2,z3, Z );
      FD_TEST( fd_r43x6_eq( p0?y0:x0, z0 ) ); FD_TEST( fd_r43x6_eq( p1?y1:x1, z1 ) );
      FD_TEST( fd_r43x6_eq( p2?y2:x2, z2 ) ); FD_TEST( fd_r43x6_eq( p3?y3:x3, z3 ) );

      FD_R43X6_QUAD_LANE_ADD_FAST( Z, X, p0,p1,p2,p3, X, Y );
      FD_R43X6_QUAD_UNPACK( z0,z1,z2,z3, Z );
      FD_TEST( fd_r43x6_eq( p0?fd_r43x6_add_fast(x0,y0):x0, z0 ) ); FD_TEST( fd_r43x6_eq( p1?fd_r43x6_add_fast(x1,y1):x1, z1 ) );
      FD_TEST( fd_r43x6_eq( p2?fd_r43x6_add_fast(x2,y2):x2, z2 ) ); FD_TEST( fd_r43x6_eq( p3?fd_r43x6_add_fast(x3,y3):x3, z3 ) );

      FD_R43X6_QUAD_LANE_SUB_FAST( Z, X, p0,p1,p2,p3, X, Y );
      FD_R43X6_QUAD_UNPACK( z0,z1,z2,z3, Z );
      FD_TEST( fd_r43x6_eq( p0?fd_r43x6_sub_fast(x0,y0):x0, z0 ) ); FD_TEST( fd_r43x6_eq( p1?fd_r43x6_sub_fast(x1,y1):x1, z1 ) );
      FD_TEST( fd_r43x6_eq( p2?fd_r43x6_sub_fast(x2,y2):x2, z2 ) ); FD_TEST( fd_r43x6_eq( p3?fd_r43x6_sub_fast(x3,y3):x3, z3 ) );

      /* Test FOLD inlines */

      FD_R43X6_QUAD_FOLD_UNSIGNED( Z, X );
      FD_R43X6_QUAD_UNPACK( z0,z1,z2,z3, Z );
      FD_TEST( fd_r43x6_eq( fd_r43x6_fold_unsigned( x0 ), z0 ) ); FD_TEST( fd_r43x6_eq( fd_r43x6_fold_unsigned( x1 ), z1 ) );
      FD_TEST( fd_r43x6_eq( fd_r43x6_fold_unsigned( x2 ), z2 ) ); FD_TEST( fd_r43x6_eq( fd_r43x6_fold_unsigned( x3 ), z3 ) );

      FD_R43X6_QUAD_FOLD_SIGNED( Z, X );
      FD_R43X6_QUAD_UNPACK( z0,z1,z2,z3, Z );
      FD_TEST( fd_r43x6_eq( fd_r43x6_fold_signed( x0 ), z0 ) ); FD_TEST( fd_r43x6_eq( fd_r43x6_fold_signed( x1 ), z1 ) );
      FD_TEST( fd_r43x6_eq( fd_r43x6_fold_signed( x2 ), z2 ) ); FD_TEST( fd_r43x6_eq( fd_r43x6_fold_signed( x3 ), z3 ) );

      /* Test MUL inlines */

      fd_r43x6_t w0 = fd_r43x6_mul_fast( x0, y0 ); fd_r43x6_t w1 = fd_r43x6_mul_fast( x1, y1 );
      fd_r43x6_t w2 = fd_r43x6_mul_fast( x2, y2 ); fd_r43x6_t w3 = fd_r43x6_mul_fast( x3, y3 );

      FD_R43X6_QUAD_MUL_FAST( Z, X, Y );
      FD_R43X6_QUAD_UNPACK( z0,z1,z2,z3, Z );
      FD_TEST( fd_r43x6_eq( w0, z0 ) ); FD_TEST( fd_r43x6_eq( w1, z1 ) );
      FD_TEST( fd_r43x6_eq( w2, z2 ) ); FD_TEST( fd_r43x6_eq( w3, z3 ) );

      w0 = fd_r43x6_fold_unsigned( w0 ); w1 = fd_r43x6_fold_unsigned( w1 );
      w2 = fd_r43x6_fold_unsigned( w2 ); w3 = fd_r43x6_fold_unsigned( w3 );

      FD_R43X6_MUL1_INL( z0,x0,y0 );
      FD_TEST( fd_r43x6_eq( w0, z0 ) );

      FD_R43X6_MUL2_INL( z0,x0,y0, z1,x1,y1 );
      FD_TEST( fd_r43x6_eq( w0, z0 ) ); FD_TEST( fd_r43x6_eq( w1, z1 ) );

      FD_R43X6_MUL3_INL( z0,x0,y0, z1,x1,y1, z2,x2,y2 );
      FD_TEST( fd_r43x6_eq( w0, z0 ) ); FD_TEST( fd_r43x6_eq( w1, z1 ) );
      FD_TEST( fd_r43x6_eq( w2, z2 ) );

      FD_R43X6_MUL4_INL( z0,x0,y0, z1,x1,y1, z2,x2,y2, z3,x3,y3 );
      FD_TEST( fd_r43x6_eq( w0, z0 ) ); FD_TEST( fd_r43x6_eq( w1, z1 ) );
      FD_TEST( fd_r43x6_eq( w2, z2 ) ); FD_TEST( fd_r43x6_eq( w3, z3 ) );

      /* Test SQR inlines */

      w0 = fd_r43x6_sqr_fast( y0 ); w1 = fd_r43x6_sqr_fast( y1 );
      w2 = fd_r43x6_sqr_fast( y2 ); w3 = fd_r43x6_sqr_fast( y3 );

      FD_R43X6_QUAD_SQR_FAST( Z, Y );
      FD_R43X6_QUAD_UNPACK( z0,z1,z2,z3, Z );
      FD_TEST( fd_r43x6_eq( z0, w0 ) ); FD_TEST( fd_r43x6_eq( z1, w1 ) );
      FD_TEST( fd_r43x6_eq( z2, w2 ) ); FD_TEST( fd_r43x6_eq( w3, w3 ) );

      w0 = fd_r43x6_fold_unsigned( w0 ); w1 = fd_r43x6_fold_unsigned( w1 );
      w2 = fd_r43x6_fold_unsigned( w2 ); w3 = fd_r43x6_fold_unsigned( w3 );

      FD_R43X6_SQR1_INL( z0,y0 );
      FD_TEST( fd_r43x6_eq( z0, w0 ) );

      FD_R43X6_SQR2_INL( z0,y0, z1,y1 );
      FD_TEST( fd_r43x6_eq( z0, w0 ) ); FD_TEST( fd_r43x6_eq( z1, w1 ) );

      FD_R43X6_SQR3_INL( z0,y0, z1,y1, z2,y2 );
      FD_TEST( fd_r43x6_eq( z0, w0 ) ); FD_TEST( fd_r43x6_eq( z1, w1 ) );
      FD_TEST( fd_r43x6_eq( z2, w2 ) );

      FD_R43X6_SQR4_INL( z0,y0, z1,y1, z2,y2, z3,y3 );
      FD_TEST( fd_r43x6_eq( z0, w0 ) ); FD_TEST( fd_r43x6_eq( z1, w1 ) );
      FD_TEST( fd_r43x6_eq( z2, w2 ) ); FD_TEST( fd_r43x6_eq( z3, w3 ) );
    }
  }

  FD_LOG_NOTICE(( "Testing invert" ));

  FD_TEST( fd_r43x6_eq( fd_r43x6_zero(), fd_r43x6_invert( fd_r43x6_zero() ) ) );
  FD_TEST( fd_r43x6_eq( fd_r43x6_one (), fd_r43x6_invert( fd_r43x6_one () ) ) );

  for( ulong rem=131072UL; rem; rem-- ) {
    fd_r43x6_t x = fd_r43x6_unpack( uint256_rand( rng ) ); // unpacked
    FD_TEST( fd_r43x6_eq( fd_r43x6_one(), fd_r43x6_mod( fd_r43x6_mul( x, fd_r43x6_invert( x ) ) ) ) );
    FD_TEST( fd_r43x6_eq( fd_r43x6_one(), fd_r43x6_mod( fd_r43x6_mul( fd_r43x6_invert( x ), x ) ) ) );
  }

  FD_LOG_NOTICE(( "Testing constants" ));

  FD_TEST( fd_r43x6_eq( fd_r43x6_zero(), fd_r43x6(0L,0L,0L,0L,0L,0L) ) );

  FD_TEST( fd_r43x6_eq( fd_r43x6_one(), fd_r43x6(1L,0L,0L,0L,0L,0L) ) );

  FD_TEST( fd_r43x6_eq( fd_r43x6_p(),
                        fd_r43x6_add_fast( fd_r43x6_mod_signed( fd_r43x6_neg( fd_r43x6_one() ) ), fd_r43x6_one() ) ) );

  FD_TEST( fd_r43x6_eq( fd_r43x6_d(),
                        fd_r43x6_mod_unreduced( fd_r43x6_mul( fd_r43x6_fold_signed( fd_r43x6(-121665L,0L,0L,0L,0L,0L) ),
                                                              fd_r43x6_invert(      fd_r43x6( 121666L,0L,0L,0L,0L,0L) ) ) ) ) );

  FD_TEST( fd_r43x6_eq( fd_r43x6_2d(),
                        fd_r43x6_mod_unreduced( fd_r43x6_mul( fd_r43x6_fold_signed( fd_r43x6(-2L*121665L,0L,0L,0L,0L,0L) ),
                                                              fd_r43x6_invert(      fd_r43x6(    121666L,0L,0L,0L,0L,0L) ) ) ) ) );

  FD_TEST( fd_r43x6_eq( fd_r43x6_mod( fd_r43x6_imag() ), fd_r43x6_imag() ) );
  FD_TEST( !fd_r43x6_is_nonzero( fd_r43x6_add_fast( fd_r43x6_sqr( fd_r43x6_imag() ), fd_r43x6_one() ) ) );

  FD_LOG_NOTICE(( "Testing is_nonzero / diagnose" ));

  do {
    fd_r43x6_t p = fd_r43x6_p();
    fd_r43x6_t _0 = fd_r43x6_zero();          fd_r43x6_t _1 = fd_r43x6_one();          fd_r43x6_t _2 = fd_r43x6(2L,0L,0L,0L,0L,0L);
    for( ulong rem=1024UL; rem; rem-- ) {
      FD_TEST( !fd_r43x6_is_nonzero( _0 )  );   FD_TEST( fd_r43x6_is_nonzero( _1 )  );   FD_TEST( fd_r43x6_is_nonzero( _2 )  );
      FD_TEST( fd_r43x6_diagnose( _0 )==-1 );   FD_TEST( fd_r43x6_diagnose( _1 )==1 );   FD_TEST( fd_r43x6_diagnose( _2 )==0 );
      _0 = fd_r43x6_add_fast( _0, p );          _1 = fd_r43x6_add_fast( _1, p );         _2 = fd_r43x6_add_fast( _2, p );
    }
  } while(0);

  FD_LOG_NOTICE(( "Testing pow22523" ));

  FD_TEST( fd_r43x6_eq( fd_r43x6_zero(), fd_r43x6_pow22523( fd_r43x6_zero() ) ) );
  FD_TEST( fd_r43x6_eq( fd_r43x6_one (), fd_r43x6_pow22523( fd_r43x6_one () ) ) );
  FD_TEST( fd_r43x6_eq( fd_r43x6(6131687051343L,3291145326305L,7003047988570L,164542477801L,6661365914216L,736639615055L),
                        fd_r43x6_mod_unreduced( fd_r43x6_pow22523( fd_r43x6(2L,0L,0L,0L,0L,0L) ) ) ) );
  /* TODO: add more test vectors */

  for( ulong rem=131072UL; rem; rem-- ) {
    fd_r43x6_t x = fd_r43x6_unpack( uint256_rand( rng ) ); // unpacked
    fd_r43x6_t y = fd_r43x6_pow22523( x );
    fd_r43x6_t z; FD_R43X6_POW22523_1_INL( z,x      ); FD_TEST( fd_r43x6_eq( z,y ) );
    fd_r43x6_t w; FD_R43X6_POW22523_2_INL( z,x, w,x ); FD_TEST( fd_r43x6_eq( z,y ) ); FD_TEST( fd_r43x6_eq( w,y ) );
    fd_r43x6_t zz; fd_r43x6_t ww;
    FD_R43X6_POW22523_4_INL( z,x, w,x, zz,x, ww,x ); FD_TEST( fd_r43x6_eq( z,y ) ); FD_TEST( fd_r43x6_eq( w,y ) ); FD_TEST( fd_r43x6_eq( zz,y ) ); FD_TEST( fd_r43x6_eq( ww,y ) );
  }

  FD_LOG_NOTICE(( "Benchmarking" ));

  do {
    wv_t u = uint256_rand( rng ); fd_r43x6_t x = fd_r43x6_unpack( u );
    wv_t v = uint256_rand( rng ); fd_r43x6_t y = fd_r43x6_unpack( v );

#   define BENCH(op) do {                                                     \
      for( ulong rem=warm_max; rem; rem-- ) op;                               \
      long dt = -fd_log_wallclock();                                          \
      for( ulong rem=iter_max; rem; rem-- ) op;                               \
      dt += fd_log_wallclock();                                               \
      FD_LOG_NOTICE(( "%-77s: %9.3f ns", #op, (double)dt/(double)iter_max )); \
    } while(0)

    BENCH( u = fd_r43x6_pack( fd_r43x6_unpack( u ) ) );
    BENCH( x = fd_r43x6_unpack( fd_r43x6_pack( x ) ) );

    BENCH( x = fd_r43x6_fold_unsigned( x ) );
    BENCH( x = fd_r43x6_fold_signed( x ) );

    BENCH( x = fd_r43x6_approx_mod( x ) );
    BENCH( x = fd_r43x6_approx_mod_signed( x ) );
    BENCH( x = fd_r43x6_approx_mod_unsigned( x ) );
    BENCH( x = fd_r43x6_approx_mod_unreduced( x ) );
    BENCH( x = fd_r43x6_approx_mod_unpacked( x ) );

    BENCH( x = fd_r43x6_mod( x ) );
    BENCH( x = fd_r43x6_mod_signed( x ) );
    BENCH( x = fd_r43x6_mod_unsigned( x ) );
    BENCH( x = fd_r43x6_mod_unreduced( x ) );
    BENCH( x = fd_r43x6_mod_unpacked( x ) );
    BENCH( x = fd_r43x6_mod_nearly_reduced( x ) );

    BENCH( x = fd_r43x6_neg_fast( x ) );
    BENCH( x = fd_r43x6_add_fast( x, y ) );
    BENCH( x = fd_r43x6_sub_fast( x, y ) );
    BENCH( x = fd_r43x6_mul_fast( x, y ) );
    BENCH( x = fd_r43x6_sqr_fast( x ) );
    BENCH( x = fd_r43x6_scale_fast( 121665L, x ) );

    BENCH( x = fd_r43x6_neg( x ) );
    BENCH( x = fd_r43x6_add( x, y ) );
    BENCH( x = fd_r43x6_sub( x, y ) );
    BENCH( x = fd_r43x6_mul( x, y ) );
    BENCH( x = fd_r43x6_sqr( x ) );
    BENCH( x = fd_r43x6_scale( 121665L, x ) );

    /* TODO: BENCH IF / SWAP_IF / IS_NONZERO / DIAGNOSE */

    fd_r43x6_t volatile dummy[1]; dummy[0] = x;
    fd_r43x6_t x0 = dummy[0]; fd_r43x6_t y0 = dummy[0];
    fd_r43x6_t x1 = dummy[0]; fd_r43x6_t y1 = dummy[0];
    fd_r43x6_t x2 = dummy[0]; fd_r43x6_t y2 = dummy[0];
    fd_r43x6_t x3 = dummy[0]; fd_r43x6_t y3 = dummy[0];

    FD_R43X6_QUAD_DECL( X ); FD_R43X6_QUAD_PACK( X, x0,x1,x2,x3 );
    FD_R43X6_QUAD_DECL( Y ); FD_R43X6_QUAD_PACK( Y, y0,y1,y2,y3 );

    BENCH( FD_R43X6_QUAD_PACK( X, x0,x1,x2,x3 ); FD_R43X6_QUAD_UNPACK( x0,x1,x2,x3, X ) );
    BENCH( FD_R43X6_QUAD_PERMUTE( X, 1,2,3,0, X ) );
    BENCH( FD_R43X6_QUAD_LANE_IF( X, 0,0,1,1, Y, X ) );
    BENCH( FD_R43X6_QUAD_LANE_ADD_FAST( X, X, 0,1,0,1, X, Y ) );
    BENCH( FD_R43X6_QUAD_LANE_SUB_FAST( X, X, 1,0,1,1, X, Y ) );
    BENCH( FD_R43X6_QUAD_FOLD_UNSIGNED( X, X ) );
    BENCH( FD_R43X6_QUAD_FOLD_SIGNED( X, X ) );
    BENCH( FD_R43X6_QUAD_MUL_FAST( X, X, Y ) );
    BENCH( FD_R43X6_QUAD_SQR_FAST( X, X ) );

    FD_R43X6_QUAD_UNPACK( x0,x1,x2,x3, X );

    BENCH( FD_R43X6_MUL1_INL( x0,x0,y0 ) );
    BENCH( FD_R43X6_MUL2_INL( x0,x0,y0, x1,x1,y1 ) );
    BENCH( FD_R43X6_MUL3_INL( x0,x0,y0, x1,x1,y1, x2,x2,y2 ) );
    BENCH( FD_R43X6_MUL4_INL( x0,x0,y0, x1,x1,y1, x2,x2,y2, x3,x3,y3 ) );

    BENCH( FD_R43X6_SQR1_INL( x0,x0 ) );
    BENCH( FD_R43X6_SQR2_INL( x0,x0, x1,x1 ) );
    BENCH( FD_R43X6_SQR3_INL( x0,x0, x1,x1, x2,x2 ) );
    BENCH( FD_R43X6_SQR4_INL( x0,x0, x1,x1, x2,x2, x3,x3 ) );

    iter_max = 131072;

    BENCH( x = fd_r43x6_invert( x ) );
    BENCH( x = fd_r43x6_pow22523( x ) );
    BENCH( FD_R43X6_POW22523_1_INL( x0,x0 ) );
    BENCH( FD_R43X6_POW22523_2_INL( x0,x0, x1,x1 ) );
    BENCH( FD_R43X6_POW22523_4_INL( x0,x0, x1,x1, x2,x2, x3,x3 ) );

    /* Prevent compiler from optimizing away */
    dummy[0] = x0; dummy[0] = x1; dummy[0] = x2; dummy[0] = x3;
    dummy[0] = x;
    wv_t volatile dummy0[1]; dummy0[0] = u; u = dummy0[0];
  } while(0);

  fd_rng_delete( fd_rng_leave( rng ) );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
