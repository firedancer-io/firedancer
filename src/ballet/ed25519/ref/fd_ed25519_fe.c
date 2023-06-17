#include "../fd_ed25519_private.h"

fd_ed25519_fe_t *
fd_ed25519_fe_frombytes( fd_ed25519_fe_t * h,
                         uchar const *     s ) {

  /* FIXME: THIS CAN PROBABLY BE ACCELERATED BY DOING 4 64-BIT LOADS AND
     THEN UNPACKING FOR HIGH ILP.  UNCLEAR IF BELOW DOES A FULL
     REDUCTION THOUGH SO THIS ALTERNATIVE MIGHT YIELD ONLY AN EQUIVALENT
     INTERMEDIATE REPRESENTATION (AND FOR SANITY WE ARE KEEPING
     INTERMEDIATES BIT LEVEL EXACT TOO).  CHECK FD_LOADS ELSEWHERE TO
     MAKE SURE THIS IS THE CASE IN GENERAL. */

  long h0 = (long)  fd_ulong_load_4_fast( s      );
  long h1 = (long)  fd_ulong_load_3_fast( s +  4 ) << 6;
  long h2 = (long)  fd_ulong_load_3_fast( s +  7 ) << 5;
  long h3 = (long)  fd_ulong_load_3_fast( s + 10 ) << 3;
  long h4 = (long)  fd_ulong_load_3_fast( s + 13 ) << 2;
  long h5 = (long)  fd_ulong_load_4_fast( s + 16 );
  long h6 = (long)  fd_ulong_load_3_fast( s + 20 ) << 7;
  long h7 = (long)  fd_ulong_load_3_fast( s + 23 ) << 5;
  long h8 = (long)  fd_ulong_load_3_fast( s + 26 ) << 4;
  long h9 = (long)((fd_ulong_load_3     ( s + 29 ) & 0x7fffffUL) << 2); /* Ignores top bit of h. */

  long m39u = (long)FD_ULONG_MASK_MSB(39);
  long carry9 = h9 + (1 << 24); h0 += (carry9 >> 25)*19L; h9 -= carry9 & m39u;
  long carry1 = h1 + (1 << 24); h2 +=  carry1 >> 25;      h1 -= carry1 & m39u;
  long carry3 = h3 + (1 << 24); h4 +=  carry3 >> 25;      h3 -= carry3 & m39u;
  long carry5 = h5 + (1 << 24); h6 +=  carry5 >> 25;      h5 -= carry5 & m39u;
  long carry7 = h7 + (1 << 24); h8 +=  carry7 >> 25;      h7 -= carry7 & m39u;

  long m38u = (long)FD_ULONG_MASK_MSB(38);
  long carry0 = h0 + (1 << 25); h1 +=  carry0 >> 26;      h0 -= carry0 & m38u;
  long carry2 = h2 + (1 << 25); h3 +=  carry2 >> 26;      h2 -= carry2 & m38u;
  long carry4 = h4 + (1 << 25); h5 +=  carry4 >> 26;      h4 -= carry4 & m38u;
  long carry6 = h6 + (1 << 25); h7 +=  carry6 >> 26;      h6 -= carry6 & m38u;
  long carry8 = h8 + (1 << 25); h9 +=  carry8 >> 26;      h8 -= carry8 & m38u;

  h->limb[0] = (int)h0; h->limb[1] = (int)h1;
  h->limb[2] = (int)h2; h->limb[3] = (int)h3;
  h->limb[4] = (int)h4; h->limb[5] = (int)h5;
  h->limb[6] = (int)h6; h->limb[7] = (int)h7;
  h->limb[8] = (int)h8; h->limb[9] = (int)h9;
  return h;
}

uchar *
fd_ed25519_fe_tobytes( uchar *                 s,
                       fd_ed25519_fe_t const * h ) {

  /* Load limbs of h */

  int h0 = h->limb[0]; int h1 = h->limb[1];
  int h2 = h->limb[2]; int h3 = h->limb[3];
  int h4 = h->limb[4]; int h5 = h->limb[5];
  int h6 = h->limb[6]; int h7 = h->limb[7];
  int h8 = h->limb[8]; int h9 = h->limb[9];

  /* Write p=2^255-19; q=floor(h/p).
     Basic claim: q = floor(2^(-255)(h + 19 2^(-25)h9 + 2^(-1))).

     Proof:
       Have |h|<=p so |q|<=1 so |19^2 2^(-255) q|<1/4.
       Also have |h-2^230 h9|<2^231 so |19 2^(-255)(h-2^230 h9)|<1/4.

       Write y=2^(-1)-19^2 2^(-255)q-19 2^(-255)(h-2^230 h9).
       Then 0<y<1.

       Write r=h-pq.
       Have 0<=r<=p-1=2^255-20.
       Thus 0<=r+19(2^-255)r<r+19(2^-255)2^255<=2^255-1.

       Write x=r+19(2^-255)r+y.
       Then 0<x<2^255 so floor(2^(-255)x) = 0 so floor(q+2^(-255)x) = q.

       Have q+2^(-255)x = 2^(-255)(h + 19 2^(-25) h9 + 2^(-1))
       so floor(2^(-255)(h + 19 2^(-25) h9 + 2^(-1))) = q.  */

  int q = (19*h9 + (1<<24)) >> 25;
  q = (h0 + q) >> 26; q = (h1 + q) >> 25;
  q = (h2 + q) >> 26; q = (h3 + q) >> 25;
  q = (h4 + q) >> 26; q = (h5 + q) >> 25;
  q = (h6 + q) >> 26; q = (h7 + q) >> 25;
  q = (h8 + q) >> 26; q = (h9 + q) >> 25;

  /* Goal: Output h-(2^255-19)q, which is between 0 and 2^255-20. */

  h0 += 19*q;

  /* Goal: Output h-2^255 q, which is between 0 and 2^255-20. */

  int m26 = (int)FD_ULONG_MASK_LSB(26);
  int m25 = (int)FD_ULONG_MASK_LSB(25);

  h1 += h0 >> 26; h0 &= m26; h2 += h1 >> 25; h1 &= m25;
  h3 += h2 >> 26; h2 &= m26; h4 += h3 >> 25; h3 &= m25;
  h5 += h4 >> 26; h4 &= m26; h6 += h5 >> 25; h5 &= m25;
  h7 += h6 >> 26; h6 &= m26; h8 += h7 >> 25; h7 &= m25;
  h9 += h8 >> 26; h8 &= m26; /*h10=carry9*/  h9 &= m25;

  /* Pack the results into s */

  *(ulong *) s     = (((ulong)(uint)h0)    ) | (((ulong)(uint)h1)<<26) | (((ulong)(uint)h2)<<51);
  *(ulong *)(s+ 8) = (((ulong)(uint)h2)>>13) | (((ulong)(uint)h3)<<13) | (((ulong)(uint)h4)<<38);
  *(ulong *)(s+16) = (((ulong)(uint)h5)    ) | (((ulong)(uint)h6)<<25) | (((ulong)(uint)h7)<<51);
  *(ulong *)(s+24) = (((ulong)(uint)h7)>>13) | (((ulong)(uint)h8)<<12) | (((ulong)(uint)h9)<<38);

  return s;
}

fd_ed25519_fe_t *
fd_ed25519_fe_mul( fd_ed25519_fe_t *       h,
                   fd_ed25519_fe_t const * f,
                   fd_ed25519_fe_t const * g ) {

  /* Notes on implementation strategy:

     Using schoolbook multiplication.
     Karatsuba would save a little in some cost models.

     Most multiplications by 2 and 19 are 32-bit precomputations;
     cheaper than 64-bit postcomputations.

     There is one remaining multiplication by 19 in the carry chain;
     one *19 precomputation can be merged into this,
     but the resulting data flow is considerably less clean.

     There are 12 carries below.
     10 of them are 2-way parallelizable and vectorizable.
     Can get away with 11 carries, but then data flow is much deeper.

     With tighter constraints on inputs can squeeze carries into int. */

  int f0 = f->limb[0]; int f1 = f->limb[1];
  int f2 = f->limb[2]; int f3 = f->limb[3];
  int f4 = f->limb[4]; int f5 = f->limb[5];
  int f6 = f->limb[6]; int f7 = f->limb[7];
  int f8 = f->limb[8]; int f9 = f->limb[9];

  int g0 = g->limb[0]; int g1 = g->limb[1];
  int g2 = g->limb[2]; int g3 = g->limb[3];
  int g4 = g->limb[4]; int g5 = g->limb[5];
  int g6 = g->limb[6]; int g7 = g->limb[7];
  int g8 = g->limb[8]; int g9 = g->limb[9];

  int g1_19 = 19*g1; /* 1.959375*2^29 */
  int g2_19 = 19*g2; /* 1.959375*2^30; still ok */
  int g3_19 = 19*g3;
  int g4_19 = 19*g4;
  int g5_19 = 19*g5;
  int g6_19 = 19*g6;
  int g7_19 = 19*g7;
  int g8_19 = 19*g8;
  int g9_19 = 19*g9;

  int f1_2 = 2*f1;
  int f3_2 = 2*f3;
  int f5_2 = 2*f5;
  int f7_2 = 2*f7;
  int f9_2 = 2*f9;

  long f0g0    = ((long)f0)*((long)g0   ); long f0g1    = ((long)f0  )*((long)g1   );
  long f0g2    = ((long)f0)*((long)g2   ); long f0g3    = ((long)f0  )*((long)g3   );
  long f0g4    = ((long)f0)*((long)g4   ); long f0g5    = ((long)f0  )*((long)g5   );
  long f0g6    = ((long)f0)*((long)g6   ); long f0g7    = ((long)f0  )*((long)g7   );
  long f0g8    = ((long)f0)*((long)g8   ); long f0g9    = ((long)f0  )*((long)g9   );

  long f1g0    = ((long)f1)*((long)g0   ); long f1g1_2  = ((long)f1_2)*((long)g1   );
  long f1g2    = ((long)f1)*((long)g2   ); long f1g3_2  = ((long)f1_2)*((long)g3   );
  long f1g4    = ((long)f1)*((long)g4   ); long f1g5_2  = ((long)f1_2)*((long)g5   );
  long f1g6    = ((long)f1)*((long)g6   ); long f1g7_2  = ((long)f1_2)*((long)g7   );
  long f1g8    = ((long)f1)*((long)g8   ); long f1g9_38 = ((long)f1_2)*((long)g9_19);

  long f2g0    = ((long)f2)*((long)g0   ); long f2g1    = ((long)f2  )*((long)g1   );
  long f2g2    = ((long)f2)*((long)g2   ); long f2g3    = ((long)f2  )*((long)g3   );
  long f2g4    = ((long)f2)*((long)g4   ); long f2g5    = ((long)f2  )*((long)g5   );
  long f2g6    = ((long)f2)*((long)g6   ); long f2g7    = ((long)f2  )*((long)g7   );
  long f2g8_19 = ((long)f2)*((long)g8_19); long f2g9_19 = ((long)f2  )*((long)g9_19);

  long f3g0    = ((long)f3)*((long)g0   ); long f3g1_2  = ((long)f3_2)*((long)g1   );
  long f3g2    = ((long)f3)*((long)g2   ); long f3g3_2  = ((long)f3_2)*((long)g3   );
  long f3g4    = ((long)f3)*((long)g4   ); long f3g5_2  = ((long)f3_2)*((long)g5   );
  long f3g6    = ((long)f3)*((long)g6   ); long f3g7_38 = ((long)f3_2)*((long)g7_19);
  long f3g8_19 = ((long)f3)*((long)g8_19); long f3g9_38 = ((long)f3_2)*((long)g9_19);

  long f4g0    = ((long)f4)*((long)g0   ); long f4g1    = ((long)f4  )*((long)g1   );
  long f4g2    = ((long)f4)*((long)g2   ); long f4g3    = ((long)f4  )*((long)g3   );
  long f4g4    = ((long)f4)*((long)g4   ); long f4g5    = ((long)f4  )*((long)g5   );
  long f4g6_19 = ((long)f4)*((long)g6_19); long f4g7_19 = ((long)f4  )*((long)g7_19);
  long f4g8_19 = ((long)f4)*((long)g8_19); long f4g9_19 = ((long)f4  )*((long)g9_19);

  long f5g0    = ((long)f5)*((long)g0   ); long f5g1_2  = ((long)f5_2)*((long)g1   );
  long f5g2    = ((long)f5)*((long)g2   ); long f5g3_2  = ((long)f5_2)*((long)g3   );
  long f5g4    = ((long)f5)*((long)g4   ); long f5g5_38 = ((long)f5_2)*((long)g5_19);
  long f5g6_19 = ((long)f5)*((long)g6_19); long f5g7_38 = ((long)f5_2)*((long)g7_19);
  long f5g8_19 = ((long)f5)*((long)g8_19); long f5g9_38 = ((long)f5_2)*((long)g9_19);

  long f6g0    = ((long)f6)*((long)g0   ); long f6g1    = ((long)f6  )*((long)g1   );
  long f6g2    = ((long)f6)*((long)g2   ); long f6g3    = ((long)f6  )*((long)g3   );
  long f6g4_19 = ((long)f6)*((long)g4_19); long f6g5_19 = ((long)f6  )*((long)g5_19);
  long f6g6_19 = ((long)f6)*((long)g6_19); long f6g7_19 = ((long)f6  )*((long)g7_19);
  long f6g8_19 = ((long)f6)*((long)g8_19); long f6g9_19 = ((long)f6  )*((long)g9_19);

  long f7g0    = ((long)f7)*((long)g0   ); long f7g1_2  = ((long)f7_2)*((long)g1   );
  long f7g2    = ((long)f7)*((long)g2   ); long f7g3_38 = ((long)f7_2)*((long)g3_19);
  long f7g4_19 = ((long)f7)*((long)g4_19); long f7g5_38 = ((long)f7_2)*((long)g5_19);
  long f7g6_19 = ((long)f7)*((long)g6_19); long f7g7_38 = ((long)f7_2)*((long)g7_19);
  long f7g8_19 = ((long)f7)*((long)g8_19); long f7g9_38 = ((long)f7_2)*((long)g9_19);

  long f8g0    = ((long)f8)*((long)g0   ); long f8g1    = ((long)f8  )*((long)g1   );
  long f8g2_19 = ((long)f8)*((long)g2_19); long f8g3_19 = ((long)f8  )*((long)g3_19);
  long f8g4_19 = ((long)f8)*((long)g4_19); long f8g5_19 = ((long)f8  )*((long)g5_19);
  long f8g6_19 = ((long)f8)*((long)g6_19); long f8g7_19 = ((long)f8  )*((long)g7_19);
  long f8g8_19 = ((long)f8)*((long)g8_19); long f8g9_19 = ((long)f8  )*((long)g9_19);

  long f9g0    = ((long)f9)*((long)g0   ); long f9g1_38 = ((long)f9_2)*((long)g1_19);
  long f9g2_19 = ((long)f9)*((long)g2_19); long f9g3_38 = ((long)f9_2)*((long)g3_19);
  long f9g4_19 = ((long)f9)*((long)g4_19); long f9g5_38 = ((long)f9_2)*((long)g5_19);
  long f9g6_19 = ((long)f9)*((long)g6_19); long f9g7_38 = ((long)f9_2)*((long)g7_19);
  long f9g8_19 = ((long)f9)*((long)g8_19); long f9g9_38 = ((long)f9_2)*((long)g9_19);

  long h0 = f0g0 + f1g9_38 + f2g8_19 + f3g7_38 + f4g6_19 + f5g5_38 + f6g4_19 + f7g3_38 + f8g2_19 + f9g1_38;
  long h1 = f0g1 + f1g0    + f2g9_19 + f3g8_19 + f4g7_19 + f5g6_19 + f6g5_19 + f7g4_19 + f8g3_19 + f9g2_19;
  long h2 = f0g2 + f1g1_2  + f2g0    + f3g9_38 + f4g8_19 + f5g7_38 + f6g6_19 + f7g5_38 + f8g4_19 + f9g3_38;
  long h3 = f0g3 + f1g2    + f2g1    + f3g0    + f4g9_19 + f5g8_19 + f6g7_19 + f7g6_19 + f8g5_19 + f9g4_19;
  long h4 = f0g4 + f1g3_2  + f2g2    + f3g1_2  + f4g0    + f5g9_38 + f6g8_19 + f7g7_38 + f8g6_19 + f9g5_38;
  long h5 = f0g5 + f1g4    + f2g3    + f3g2    + f4g1    + f5g0    + f6g9_19 + f7g8_19 + f8g7_19 + f9g6_19;
  long h6 = f0g6 + f1g5_2  + f2g4    + f3g3_2  + f4g2    + f5g1_2  + f6g0    + f7g9_38 + f8g8_19 + f9g7_38;
  long h7 = f0g7 + f1g6    + f2g5    + f3g4    + f4g3    + f5g2    + f6g1    + f7g0    + f8g9_19 + f9g8_19;
  long h8 = f0g8 + f1g7_2  + f2g6    + f3g5_2  + f4g4    + f5g3_2  + f6g2    + f7g1_2  + f8g0    + f9g9_38;
  long h9 = f0g9 + f1g8    + f2g7    + f3g6    + f4g5    + f5g4    + f6g3    + f7g2    + f8g1    + f9g0   ;

  /* |h0| <= (1.65*1.65*2^52*(1+19+19+19+19)+1.65*1.65*2^50*(38+38+38+38+38))
       i.e. |h0| <= 1.4*2^60; narrower ranges for h2, h4, h6, h8
     |h1| <= (1.65*1.65*2^51*(1+1+19+19+19+19+19+19+19+19))
       i.e. |h1| <= 1.7*2^59; narrower ranges for h3, h5, h7, h9 */

  long m38u = (long)FD_ULONG_MASK_MSB(38);
  long m39u = (long)FD_ULONG_MASK_MSB(39);

  long carry0 = h0 + (1L << 25); h1 += carry0 >> 26; h0 -= carry0 & m38u;
  long carry4 = h4 + (1L << 25); h5 += carry4 >> 26; h4 -= carry4 & m38u;
  /* |h0| <= 2^25 */
  /* |h4| <= 2^25 */
  /* |h1| <= 1.71*2^59 */
  /* |h5| <= 1.71*2^59 */

  long carry1 = h1 + (1L << 24); h2 += carry1 >> 25; h1 -= carry1 & m39u;
  long carry5 = h5 + (1L << 24); h6 += carry5 >> 25; h5 -= carry5 & m39u;
  /* |h1| <= 2^24; from now on fits into int */
  /* |h5| <= 2^24; from now on fits into int */
  /* |h2| <= 1.41*2^60 */
  /* |h6| <= 1.41*2^60 */

  long carry2 = h2 + (1L << 25); h3 += carry2 >> 26; h2 -= carry2 & m38u;
  long carry6 = h6 + (1L << 25); h7 += carry6 >> 26; h6 -= carry6 & m38u;
  /* |h2| <= 2^25; from now on fits into int unchanged */
  /* |h6| <= 2^25; from now on fits into int unchanged */
  /* |h3| <= 1.71*2^59 */
  /* |h7| <= 1.71*2^59 */

  long carry3 = h3 + (1L << 24); h4 += carry3 >> 25; h3 -= carry3 & m39u;
  long carry7 = h7 + (1L << 24); h8 += carry7 >> 25; h7 -= carry7 & m39u;
  /* |h3| <= 2^24; from now on fits into int unchanged */
  /* |h7| <= 2^24; from now on fits into int unchanged */
  /* |h4| <= 1.72*2^34 */
  /* |h8| <= 1.41*2^60 */

  /**/ carry4 = h4 + (1L << 25); h5 += carry4 >> 26; h4 -= carry4 & m38u;
  long carry8 = h8 + (1L << 25); h9 += carry8 >> 26; h8 -= carry8 & m38u;
  /* |h4| <= 2^25; from now on fits into int unchanged */
  /* |h8| <= 2^25; from now on fits into int unchanged */
  /* |h5| <= 1.01*2^24 */
  /* |h9| <= 1.71*2^59 */

  long carry9 = h9 + (1L << 24); h0 += (carry9 >> 25)*19L; h9 -= carry9 & m39u;
  /* |h9| <= 2^24; from now on fits into int unchanged */
  /* |h0| <= 1.1*2^39 */

  /**/ carry0 = h0 + (1L << 25); h1 += carry0 >> 26; h0 -= carry0 & m38u;
  /* |h0| <= 2^25; from now on fits into int unchanged */
  /* |h1| <= 1.01*2^24 */

  h->limb[0] = (int)h0; h->limb[1] = (int)h1;
  h->limb[2] = (int)h2; h->limb[3] = (int)h3;
  h->limb[4] = (int)h4; h->limb[5] = (int)h5;
  h->limb[6] = (int)h6; h->limb[7] = (int)h7;
  h->limb[8] = (int)h8; h->limb[9] = (int)h9;
  return h;
}

fd_ed25519_fe_t *
fd_ed25519_fe_sq( fd_ed25519_fe_t *       h,
                  fd_ed25519_fe_t const * f ) {

  /* See fd_ed25519_fe_mul for discussion of implementation strategy. */

  int f0 = f->limb[0]; int f1 = f->limb[1];
  int f2 = f->limb[2]; int f3 = f->limb[3];
  int f4 = f->limb[4]; int f5 = f->limb[5];
  int f6 = f->limb[6]; int f7 = f->limb[7];
  int f8 = f->limb[8]; int f9 = f->limb[9];

  int f0_2 = 2*f0; int f1_2 = 2*f1;
  int f2_2 = 2*f2; int f3_2 = 2*f3;
  int f4_2 = 2*f4; int f5_2 = 2*f5;
  int f6_2 = 2*f6; int f7_2 = 2*f7;

  int f5_38 = 38*f5; /* 1.959375*2^30 */ int f6_19 = 19*f6; /* 1.959375*2^30 */
  int f7_38 = 38*f7; /* 1.959375*2^30 */ int f8_19 = 19*f8; /* 1.959375*2^30 */
  int f9_38 = 38*f9; /* 1.959375*2^30 */

  long f0f0    = ((long)f0  )*((long)f0   ); long f0f1_2  = ((long)f0_2)*((long)f1   );
  long f0f2_2  = ((long)f0_2)*((long)f2   ); long f0f3_2  = ((long)f0_2)*((long)f3   );
  long f0f4_2  = ((long)f0_2)*((long)f4   ); long f0f5_2  = ((long)f0_2)*((long)f5   );
  long f0f6_2  = ((long)f0_2)*((long)f6   ); long f0f7_2  = ((long)f0_2)*((long)f7   );
  long f0f8_2  = ((long)f0_2)*((long)f8   ); long f0f9_2  = ((long)f0_2)*((long)f9   );

  long f1f1_2  = ((long)f1_2)*((long)f1   ); long f1f2_2  = ((long)f1_2)*((long)f2   );
  long f1f3_4  = ((long)f1_2)*((long)f3_2 ); long f1f4_2  = ((long)f1_2)*((long)f4   );
  long f1f5_4  = ((long)f1_2)*((long)f5_2 ); long f1f6_2  = ((long)f1_2)*((long)f6   );
  long f1f7_4  = ((long)f1_2)*((long)f7_2 ); long f1f8_2  = ((long)f1_2)*((long)f8   );
  long f1f9_76 = ((long)f1_2)*((long)f9_38);

  long f2f2    = ((long)f2  )*((long)f2   ); long f2f3_2  = ((long)f2_2)*((long)f3   );
  long f2f4_2  = ((long)f2_2)*((long)f4   ); long f2f5_2  = ((long)f2_2)*((long)f5   );
  long f2f6_2  = ((long)f2_2)*((long)f6   ); long f2f7_2  = ((long)f2_2)*((long)f7   );
  long f2f8_38 = ((long)f2_2)*((long)f8_19); long f2f9_38 = ((long)f2  )*((long)f9_38);

  long f3f3_2  = ((long)f3_2)*((long)f3   ); long f3f4_2  = ((long)f3_2)*((long)f4   );
  long f3f5_4  = ((long)f3_2)*((long)f5_2 ); long f3f6_2  = ((long)f3_2)*((long)f6   );
  long f3f7_76 = ((long)f3_2)*((long)f7_38); long f3f8_38 = ((long)f3_2)*((long)f8_19);
  long f3f9_76 = ((long)f3_2)*((long)f9_38);

  long f4f4    = ((long)f4  )*((long)f4   ); long f4f5_2  = ((long)f4_2)*((long)f5   );
  long f4f6_38 = ((long)f4_2)*((long)f6_19); long f4f7_38 = ((long)f4  )*((long)f7_38);
  long f4f8_38 = ((long)f4_2)*((long)f8_19); long f4f9_38 = ((long)f4  )*((long)f9_38);

  long f5f5_38 = ((long)f5  )*((long)f5_38); long f5f6_38 = ((long)f5_2)*((long)f6_19);
  long f5f7_76 = ((long)f5_2)*((long)f7_38); long f5f8_38 = ((long)f5_2)*((long)f8_19);
  long f5f9_76 = ((long)f5_2)*((long)f9_38);

  long f6f6_19 = ((long)f6  )*((long)f6_19); long f6f7_38 = ((long)f6  )*((long)f7_38);
  long f6f8_38 = ((long)f6_2)*((long)f8_19); long f6f9_38 = ((long)f6  )*((long)f9_38);

  long f7f7_38 = ((long)f7  )*((long)f7_38); long f7f8_38 = ((long)f7_2)*((long)f8_19);
  long f7f9_76 = ((long)f7_2)*((long)f9_38);

  long f8f8_19 = ((long)f8  )*((long)f8_19); long f8f9_38 = ((long)f8  )*((long)f9_38);

  long f9f9_38 = ((long)f9  )*((long)f9_38);

  long h0 = f0f0   + f1f9_76 + f2f8_38 + f3f7_76 + f4f6_38 + f5f5_38;
  long h1 = f0f1_2 + f2f9_38 + f3f8_38 + f4f7_38 + f5f6_38;
  long h2 = f0f2_2 + f1f1_2  + f3f9_76 + f4f8_38 + f5f7_76 + f6f6_19;
  long h3 = f0f3_2 + f1f2_2  + f4f9_38 + f5f8_38 + f6f7_38;
  long h4 = f0f4_2 + f1f3_4  + f2f2    + f5f9_76 + f6f8_38 + f7f7_38;
  long h5 = f0f5_2 + f1f4_2  + f2f3_2  + f6f9_38 + f7f8_38;
  long h6 = f0f6_2 + f1f5_4  + f2f4_2  + f3f3_2  + f7f9_76 + f8f8_19;
  long h7 = f0f7_2 + f1f6_2  + f2f5_2  + f3f4_2  + f8f9_38;
  long h8 = f0f8_2 + f1f7_4  + f2f6_2  + f3f5_4  + f4f4    + f9f9_38;
  long h9 = f0f9_2 + f1f8_2  + f2f7_2  + f3f6_2  + f4f5_2;

  long m38u = (long)FD_ULONG_MASK_MSB(38);
  long m39u = (long)FD_ULONG_MASK_MSB(39);

  long carry0 = h0 + (1 << 25); h1 +=  carry0 >> 26;      h0 -= carry0 & m38u;
  long carry4 = h4 + (1 << 25); h5 +=  carry4 >> 26;      h4 -= carry4 & m38u;

  long carry1 = h1 + (1 << 24); h2 +=  carry1 >> 25;      h1 -= carry1 & m39u;
  long carry5 = h5 + (1 << 24); h6 +=  carry5 >> 25;      h5 -= carry5 & m39u;

  long carry2 = h2 + (1 << 25); h3 +=  carry2 >> 26;      h2 -= carry2 & m38u;
  long carry6 = h6 + (1 << 25); h7 +=  carry6 >> 26;      h6 -= carry6 & m38u;

  long carry3 = h3 + (1 << 24); h4 +=  carry3 >> 25;      h3 -= carry3 & m39u;
  long carry7 = h7 + (1 << 24); h8 +=  carry7 >> 25;      h7 -= carry7 & m39u;

  /**/ carry4 = h4 + (1 << 25); h5 +=  carry4 >> 26;      h4 -= carry4 & m38u;
  long carry8 = h8 + (1 << 25); h9 +=  carry8 >> 26;      h8 -= carry8 & m38u;

  long carry9 = h9 + (1 << 24); h0 += (carry9 >> 25)*19L; h9 -= carry9 & m39u;

  /**/ carry0 = h0 + (1 << 25); h1 +=  carry0 >> 26;      h0 -= carry0 & m38u;

  h->limb[0] = (int)h0; h->limb[1] = (int)h1;
  h->limb[2] = (int)h2; h->limb[3] = (int)h3;
  h->limb[4] = (int)h4; h->limb[5] = (int)h5;
  h->limb[6] = (int)h6; h->limb[7] = (int)h7;
  h->limb[8] = (int)h8; h->limb[9] = (int)h9;
  return h;
}

fd_ed25519_fe_t *
fd_ed25519_fe_sq2( fd_ed25519_fe_t *       h,
                   fd_ed25519_fe_t const * f ) {

  /* See fd_ed25519_fe_mul for discussion of implementation strategy. */

  int f0 = f->limb[0]; int f1 = f->limb[1];
  int f2 = f->limb[2]; int f3 = f->limb[3];
  int f4 = f->limb[4]; int f5 = f->limb[5];
  int f6 = f->limb[6]; int f7 = f->limb[7];
  int f8 = f->limb[8]; int f9 = f->limb[9];

  int f0_2  = 2*f0; int f1_2  = 2*f1;
  int f2_2  = 2*f2; int f3_2  = 2*f3;
  int f4_2  = 2*f4; int f5_2  = 2*f5;
  int f6_2  = 2*f6; int f7_2  = 2*f7;

  int f5_38 = 38*f5; /* 1.959375*2^30 */ int f6_19 = 19*f6; /* 1.959375*2^30 */
  int f7_38 = 38*f7; /* 1.959375*2^30 */ int f8_19 = 19*f8; /* 1.959375*2^30 */
  int f9_38 = 38*f9; /* 1.959375*2^30 */

  long f0f0    = ((long)f0  )*((long)f0   ); long f0f1_2  = ((long)f0_2)*((long)f1   );
  long f0f2_2  = ((long)f0_2)*((long)f2   ); long f0f3_2  = ((long)f0_2)*((long)f3   );
  long f0f4_2  = ((long)f0_2)*((long)f4   ); long f0f5_2  = ((long)f0_2)*((long)f5   );
  long f0f6_2  = ((long)f0_2)*((long)f6   ); long f0f7_2  = ((long)f0_2)*((long)f7   );
  long f0f8_2  = ((long)f0_2)*((long)f8   ); long f0f9_2  = ((long)f0_2)*((long)f9   );

  long f1f1_2  = ((long)f1_2)*((long)f1   ); long f1f2_2  = ((long)f1_2)*((long)f2   );
  long f1f3_4  = ((long)f1_2)*((long)f3_2 ); long f1f4_2  = ((long)f1_2)*((long)f4   );
  long f1f5_4  = ((long)f1_2)*((long)f5_2 ); long f1f6_2  = ((long)f1_2)*((long)f6   );
  long f1f7_4  = ((long)f1_2)*((long)f7_2 ); long f1f8_2  = ((long)f1_2)*((long)f8   );
  long f1f9_76 = ((long)f1_2)*((long)f9_38);

  long f2f2    = ((long)f2  )*((long)f2   ); long f2f3_2  = ((long)f2_2)*((long)f3   );
  long f2f4_2  = ((long)f2_2)*((long)f4   ); long f2f5_2  = ((long)f2_2)*((long)f5   );
  long f2f6_2  = ((long)f2_2)*((long)f6   ); long f2f7_2  = ((long)f2_2)*((long)f7   );
  long f2f8_38 = ((long)f2_2)*((long)f8_19); long f2f9_38 = ((long)f2  )*((long)f9_38);

  long f3f3_2  = ((long)f3_2)*((long)f3   ); long f3f4_2  = ((long)f3_2)*((long)f4   );
  long f3f5_4  = ((long)f3_2)*((long)f5_2 ); long f3f6_2  = ((long)f3_2)*((long)f6   );
  long f3f7_76 = ((long)f3_2)*((long)f7_38); long f3f8_38 = ((long)f3_2)*((long)f8_19);
  long f3f9_76 = ((long)f3_2)*((long)f9_38);

  long f4f4    = ((long)f4  )*((long)f4   ); long f4f5_2  = ((long)f4_2)*((long)f5   );
  long f4f6_38 = ((long)f4_2)*((long)f6_19); long f4f7_38 = ((long)f4  )*((long)f7_38);
  long f4f8_38 = ((long)f4_2)*((long)f8_19); long f4f9_38 = ((long)f4  )*((long)f9_38);

  long f5f5_38 = ((long)f5  )*((long)f5_38); long f5f6_38 = ((long)f5_2)*((long)f6_19);
  long f5f7_76 = ((long)f5_2)*((long)f7_38); long f5f8_38 = ((long)f5_2)*((long)f8_19);
  long f5f9_76 = ((long)f5_2)*((long)f9_38);

  long f6f6_19 = ((long)f6  )*((long)f6_19); long f6f7_38 = ((long)f6  )*((long)f7_38);
  long f6f8_38 = ((long)f6_2)*((long)f8_19); long f6f9_38 = ((long)f6  )*((long)f9_38);

  long f7f7_38 = ((long)f7  )*((long)f7_38); long f7f8_38 = ((long)f7_2)*((long)f8_19);
  long f7f9_76 = ((long)f7_2)*((long)f9_38);

  long f8f8_19 = ((long)f8  )*((long)f8_19); long f8f9_38 = ((long)f8  )*((long)f9_38);

  long f9f9_38 = ((long)f9  )*((long)f9_38);

  long h0 = f0f0   + f1f9_76 + f2f8_38 + f3f7_76 + f4f6_38 + f5f5_38; h0 += h0;
  long h1 = f0f1_2 + f2f9_38 + f3f8_38 + f4f7_38 + f5f6_38;           h1 += h1;
  long h2 = f0f2_2 + f1f1_2  + f3f9_76 + f4f8_38 + f5f7_76 + f6f6_19; h2 += h2;
  long h3 = f0f3_2 + f1f2_2  + f4f9_38 + f5f8_38 + f6f7_38;           h3 += h3;
  long h4 = f0f4_2 + f1f3_4  + f2f2    + f5f9_76 + f6f8_38 + f7f7_38; h4 += h4;
  long h5 = f0f5_2 + f1f4_2  + f2f3_2  + f6f9_38 + f7f8_38;           h5 += h5;
  long h6 = f0f6_2 + f1f5_4  + f2f4_2  + f3f3_2  + f7f9_76 + f8f8_19; h6 += h6;
  long h7 = f0f7_2 + f1f6_2  + f2f5_2  + f3f4_2  + f8f9_38;           h7 += h7;
  long h8 = f0f8_2 + f1f7_4  + f2f6_2  + f3f5_4  + f4f4    + f9f9_38; h8 += h8;
  long h9 = f0f9_2 + f1f8_2  + f2f7_2  + f3f6_2  + f4f5_2;            h9 += h9;

  long m38u = (long)FD_ULONG_MASK_MSB(38);
  long m39u = (long)FD_ULONG_MASK_MSB(39);

  long carry0 = h0 + (1 << 25); h1 +=  carry0 >> 26;      h0 -= carry0 & m38u;
  long carry4 = h4 + (1 << 25); h5 +=  carry4 >> 26;      h4 -= carry4 & m38u;

  long carry1 = h1 + (1 << 24); h2 +=  carry1 >> 25;      h1 -= carry1 & m39u;
  long carry5 = h5 + (1 << 24); h6 +=  carry5 >> 25;      h5 -= carry5 & m39u;

  long carry2 = h2 + (1 << 25); h3 +=  carry2 >> 26;      h2 -= carry2 & m38u;
  long carry6 = h6 + (1 << 25); h7 +=  carry6 >> 26;      h6 -= carry6 & m38u;

  long carry3 = h3 + (1 << 24); h4 +=  carry3 >> 25;      h3 -= carry3 & m39u;
  long carry7 = h7 + (1 << 24); h8 +=  carry7 >> 25;      h7 -= carry7 & m39u;

  /**/ carry4 = h4 + (1 << 25); h5 +=  carry4 >> 26;      h4 -= carry4 & m38u;
  long carry8 = h8 + (1 << 25); h9 +=  carry8 >> 26;      h8 -= carry8 & m38u;

  long carry9 = h9 + (1 << 24); h0 += (carry9 >> 25)*19L; h9 -= carry9 & m39u;

  /**/ carry0 = h0 + (1 << 25); h1 +=  carry0 >> 26;      h0 -= carry0 & m38u;

  h->limb[0] = (int)h0; h->limb[1] = (int)h1;
  h->limb[2] = (int)h2; h->limb[3] = (int)h3;
  h->limb[4] = (int)h4; h->limb[5] = (int)h5;
  h->limb[6] = (int)h6; h->limb[7] = (int)h7;
  h->limb[8] = (int)h8; h->limb[9] = (int)h9;
  return h;
}

fd_ed25519_fe_t *
fd_ed25519_fe_invert( fd_ed25519_fe_t * out,
                      fd_ed25519_fe_t const * z ) {
  fd_ed25519_fe_t t0[1];
  fd_ed25519_fe_t t1[1];
  fd_ed25519_fe_t t2[1];
  fd_ed25519_fe_t t3[1];

  /* Compute z**-1 = z**(2**255 - 19 - 2) with the exponent as
     2**255 - 21 = (2**5) * (2**250 - 1) + 11. */

  fd_ed25519_fe_sq ( t0,  z     );                       /* t0 = z**2 */
  fd_ed25519_fe_sq ( t1, t0     );
  fd_ed25519_fe_sq ( t1, t1     );                       /* t1 = t0**(2**2) = z**8 */
  fd_ed25519_fe_mul( t1,  z, t1 );                       /* t1 = z * t1 = z**9 */
  fd_ed25519_fe_mul( t0, t0, t1 );                       /* t0 = t0 * t1 = z**11 -- stash t0 away for the end. */
  fd_ed25519_fe_sq ( t2, t0     );                       /* t2 = t0**2 = z**22 */
  fd_ed25519_fe_mul( t1, t1, t2 );                       /* t1 = t1 * t2 = z**(2**5 - 1) */
  fd_ed25519_fe_sq ( t2, t1     );
  for( int i=1; i<  5; i++ ) fd_ed25519_fe_sq( t2, t2 ); /* t2 = t1**(2**5) = z**((2**5) * (2**5 - 1)) */
  fd_ed25519_fe_mul( t1, t2, t1 );                       /* t1 = t1 * t2 = z**((2**5 + 1) * (2**5 - 1)) = z**(2**10 - 1) */
  fd_ed25519_fe_sq ( t2, t1     );
  for( int i=1; i< 10; i++ ) fd_ed25519_fe_sq( t2, t2 );
  fd_ed25519_fe_mul( t2, t2, t1 );                       /* t2 = z**(2**20 - 1) */
  fd_ed25519_fe_sq ( t3, t2     );
  for( int i=1; i< 20; i++ ) fd_ed25519_fe_sq( t3, t3 );
  fd_ed25519_fe_mul( t2, t3, t2 );                       /* t2 = z**(2**40 - 1) */
  for( int i=0; i< 10; i++ ) fd_ed25519_fe_sq( t2, t2 ); /* t2 = z**(2**10) * (2**40 - 1) */
  fd_ed25519_fe_mul( t1, t2, t1 );                       /* t1 = z**(2**50 - 1) */
  fd_ed25519_fe_sq ( t2, t1     );
  for( int i=1; i< 50; i++ ) fd_ed25519_fe_sq( t2, t2 );
  fd_ed25519_fe_mul( t2, t2, t1 );                       /* t2 = z**(2**100 - 1) */
  fd_ed25519_fe_sq ( t3, t2     );
  for( int i=1; i<100; i++ ) fd_ed25519_fe_sq( t3, t3 );
  fd_ed25519_fe_mul( t2, t3, t2 );                       /* t2 = z**(2**200 - 1) */
  fd_ed25519_fe_sq ( t2, t2     );
  for( int i=1; i< 50; i++ ) fd_ed25519_fe_sq( t2, t2 ); /* t2 = z**((2**50) * (2**200 - 1) */
  fd_ed25519_fe_mul( t1, t2, t1 );                       /* t1 = z**(2**250 - 1) */
  fd_ed25519_fe_sq ( t1, t1     );
  for( int i=1; i<  5; i++ ) fd_ed25519_fe_sq( t1, t1 ); /* t1 = z**((2**5) * (2**250 - 1)) */
  return fd_ed25519_fe_mul( out, t1, t0 );               /* Recall t0 = z**11; out = z**(2**255 - 21) */
}

fd_ed25519_fe_t *
fd_ed25519_fe_pow22523( fd_ed25519_fe_t *       out,
                        fd_ed25519_fe_t const * z ) {
  fd_ed25519_fe_t t0[1];
  fd_ed25519_fe_t t1[1];
  fd_ed25519_fe_t t2[1];

  fd_ed25519_fe_sq ( t0, z      );
  fd_ed25519_fe_sq ( t1, t0     );
  for( int i=1; i<  2; i++ ) fd_ed25519_fe_sq( t1, t1 );

  fd_ed25519_fe_mul( t1, z,  t1 );
  fd_ed25519_fe_mul( t0, t0, t1 );
  fd_ed25519_fe_sq ( t0, t0     );
  fd_ed25519_fe_mul( t0, t1, t0 );
  fd_ed25519_fe_sq ( t1, t0     );
  for( int i=1; i<  5; i++ ) fd_ed25519_fe_sq( t1, t1 );

  fd_ed25519_fe_mul( t0, t1, t0 );
  fd_ed25519_fe_sq ( t1, t0     );
  for( int i=1; i< 10; i++ ) fd_ed25519_fe_sq( t1, t1 );

  fd_ed25519_fe_mul( t1, t1, t0 );
  fd_ed25519_fe_sq ( t2, t1     );
  for( int i=1; i< 20; i++ ) fd_ed25519_fe_sq( t2, t2 );

  fd_ed25519_fe_mul( t1, t2, t1 );
  fd_ed25519_fe_sq ( t1, t1     );
  for( int i=1; i< 10; i++ ) fd_ed25519_fe_sq( t1, t1 );

  fd_ed25519_fe_mul( t0, t1, t0 );
  fd_ed25519_fe_sq ( t1, t0     );
  for( int i=1; i< 50; i++ ) fd_ed25519_fe_sq( t1, t1 );

  fd_ed25519_fe_mul( t1, t1, t0 );
  fd_ed25519_fe_sq ( t2, t1     );
  for( int i=1; i<100; i++ ) fd_ed25519_fe_sq( t2, t2 );

  fd_ed25519_fe_mul( t1, t2, t1 );
  fd_ed25519_fe_sq ( t1, t1     );
  for( int i=1; i< 50; i++ ) fd_ed25519_fe_sq( t1, t1 );

  fd_ed25519_fe_mul( t0, t1, t0 );
  fd_ed25519_fe_sq ( t0, t0     );
  for( int i=1; i<  2; i++ ) fd_ed25519_fe_sq( t0, t0 );

  fd_ed25519_fe_mul(out, t0, z  );
  return out;
}

void
fd_ed25519_fe_mul121666( fd_ed25519_fe_t *       h,
                         fd_ed25519_fe_t const * f ) {
  long tmp = 0L;
  for( int i=0; i<10; i+=2 ) {
    tmp = ( tmp >> 25 ) + ( (long)f->limb[ i   ] * 121666L );
    h->limb[ i   ] = (int)tmp & ((1<<26)-1);
    tmp = ( tmp >> 26 ) + ( (long)f->limb[ i+1 ] * 121666L );
    h->limb[ i+1 ] = (int)tmp & ((1<<25)-1);
  }
  h->limb[ 0 ] += 19 * (int)(tmp >> 25);
}

