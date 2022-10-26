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

  long h0 = (long)  fd_load_4_fast( s      );
  long h1 = (long)  fd_load_3_fast( s +  4 ) << 6;
  long h2 = (long)  fd_load_3_fast( s +  7 ) << 5;
  long h3 = (long)  fd_load_3_fast( s + 10 ) << 3;
  long h4 = (long)  fd_load_3_fast( s + 13 ) << 2;
  long h5 = (long)  fd_load_4_fast( s + 16 );
  long h6 = (long)  fd_load_3_fast( s + 20 ) << 7;
  long h7 = (long)  fd_load_3_fast( s + 23 ) << 5;
  long h8 = (long)  fd_load_3_fast( s + 26 ) << 4;
  long h9 = (long)((fd_load_3     ( s + 29 ) & 0x7fffffUL) << 2); /* Ignores top bit of h. */

  long m39u = (long)FD_MASK_MSB(39);
  long carry9 = h9 + (1 << 24); h0 += (carry9 >> 25)*19L; h9 -= carry9 & m39u;
  long carry1 = h1 + (1 << 24); h2 +=  carry1 >> 25;      h1 -= carry1 & m39u;
  long carry3 = h3 + (1 << 24); h4 +=  carry3 >> 25;      h3 -= carry3 & m39u;
  long carry5 = h5 + (1 << 24); h6 +=  carry5 >> 25;      h5 -= carry5 & m39u;
  long carry7 = h7 + (1 << 24); h8 +=  carry7 >> 25;      h7 -= carry7 & m39u;

  long m38u = (long)FD_MASK_MSB(38);
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

  int m26 = (int)FD_MASK_LSB(26);
  int m25 = (int)FD_MASK_LSB(25);

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

  long f0 = (long)f->limb[0]; long f1 = (long)f->limb[1];
  long f2 = (long)f->limb[2]; long f3 = (long)f->limb[3];
  long f4 = (long)f->limb[4]; long f5 = (long)f->limb[5];
  long f6 = (long)f->limb[6]; long f7 = (long)f->limb[7];
  long f8 = (long)f->limb[8]; long f9 = (long)f->limb[9];

  long g0 = (long)g->limb[0]; long g1 = (long)g->limb[1];
  long g2 = (long)g->limb[2]; long g3 = (long)g->limb[3];
  long g4 = (long)g->limb[4]; long g5 = (long)g->limb[5];
  long g6 = (long)g->limb[6]; long g7 = (long)g->limb[7];
  long g8 = (long)g->limb[8]; long g9 = (long)g->limb[9];

  long g1_19 = 19L*g1; /* 1.959375*2^29 */
  long g2_19 = 19L*g2; /* 1.959375*2^30; still ok */
  long g3_19 = 19L*g3;
  long g4_19 = 19L*g4;
  long g5_19 = 19L*g5;
  long g6_19 = 19L*g6;
  long g7_19 = 19L*g7;
  long g8_19 = 19L*g8;
  long g9_19 = 19L*g9;

  long f1_2 = 2L*f1;
  long f3_2 = 2L*f3;
  long f5_2 = 2L*f5;
  long f7_2 = 2L*f7;
  long f9_2 = 2L*f9;

  long f0g0    = f0*g0   ; long f0g1    = f0  *g1   ;
  long f0g2    = f0*g2   ; long f0g3    = f0  *g3   ;
  long f0g4    = f0*g4   ; long f0g5    = f0  *g5   ;
  long f0g6    = f0*g6   ; long f0g7    = f0  *g7   ;
  long f0g8    = f0*g8   ; long f0g9    = f0  *g9   ;

  long f1g0    = f1*g0   ; long f1g1_2  = f1_2*g1   ;
  long f1g2    = f1*g2   ; long f1g3_2  = f1_2*g3   ;
  long f1g4    = f1*g4   ; long f1g5_2  = f1_2*g5   ;
  long f1g6    = f1*g6   ; long f1g7_2  = f1_2*g7   ;
  long f1g8    = f1*g8   ; long f1g9_38 = f1_2*g9_19;

  long f2g0    = f2*g0   ; long f2g1    = f2  *g1   ;
  long f2g2    = f2*g2   ; long f2g3    = f2  *g3   ;
  long f2g4    = f2*g4   ; long f2g5    = f2  *g5   ;
  long f2g6    = f2*g6   ; long f2g7    = f2  *g7   ;
  long f2g8_19 = f2*g8_19; long f2g9_19 = f2  *g9_19;

  long f3g0    = f3*g0   ; long f3g1_2  = f3_2*g1   ;
  long f3g2    = f3*g2   ; long f3g3_2  = f3_2*g3   ;
  long f3g4    = f3*g4   ; long f3g5_2  = f3_2*g5   ;
  long f3g6    = f3*g6   ; long f3g7_38 = f3_2*g7_19;
  long f3g8_19 = f3*g8_19; long f3g9_38 = f3_2*g9_19;

  long f4g0    = f4*g0   ; long f4g1    = f4  *g1   ;
  long f4g2    = f4*g2   ; long f4g3    = f4  *g3   ;
  long f4g4    = f4*g4   ; long f4g5    = f4  *g5   ;
  long f4g6_19 = f4*g6_19; long f4g7_19 = f4  *g7_19;
  long f4g8_19 = f4*g8_19; long f4g9_19 = f4  *g9_19;

  long f5g0    = f5*g0   ; long f5g1_2  = f5_2*g1   ;
  long f5g2    = f5*g2   ; long f5g3_2  = f5_2*g3   ;
  long f5g4    = f5*g4   ; long f5g5_38 = f5_2*g5_19;
  long f5g6_19 = f5*g6_19; long f5g7_38 = f5_2*g7_19;
  long f5g8_19 = f5*g8_19; long f5g9_38 = f5_2*g9_19;

  long f6g0    = f6*g0   ; long f6g1    = f6  *g1   ;
  long f6g2    = f6*g2   ; long f6g3    = f6  *g3   ;
  long f6g4_19 = f6*g4_19; long f6g5_19 = f6  *g5_19;
  long f6g6_19 = f6*g6_19; long f6g7_19 = f6  *g7_19;
  long f6g8_19 = f6*g8_19; long f6g9_19 = f6  *g9_19;

  long f7g0    = f7*g0   ; long f7g1_2  = f7_2*g1   ;
  long f7g2    = f7*g2   ; long f7g3_38 = f7_2*g3_19;
  long f7g4_19 = f7*g4_19; long f7g5_38 = f7_2*g5_19;
  long f7g6_19 = f7*g6_19; long f7g7_38 = f7_2*g7_19;
  long f7g8_19 = f7*g8_19; long f7g9_38 = f7_2*g9_19;

  long f8g0    = f8*g0   ; long f8g1    = f8  *g1   ;
  long f8g2_19 = f8*g2_19; long f8g3_19 = f8  *g3_19;
  long f8g4_19 = f8*g4_19; long f8g5_19 = f8  *g5_19;
  long f8g6_19 = f8*g6_19; long f8g7_19 = f8  *g7_19;
  long f8g8_19 = f8*g8_19; long f8g9_19 = f8  *g9_19;

  long f9g0    = f9*g0   ; long f9g1_38 = f9_2*g1_19;
  long f9g2_19 = f9*g2_19; long f9g3_38 = f9_2*g3_19;
  long f9g4_19 = f9*g4_19; long f9g5_38 = f9_2*g5_19;
  long f9g6_19 = f9*g6_19; long f9g7_38 = f9_2*g7_19;
  long f9g8_19 = f9*g8_19; long f9g9_38 = f9_2*g9_19;

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

  long m38u = (long)FD_MASK_MSB(38);
  long m39u = (long)FD_MASK_MSB(39);

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

  long f0 = f->limb[0]; long f1 = f->limb[1];
  long f2 = f->limb[2]; long f3 = f->limb[3];
  long f4 = f->limb[4]; long f5 = f->limb[5];
  long f6 = f->limb[6]; long f7 = f->limb[7];
  long f8 = f->limb[8]; long f9 = f->limb[9];

  long f0_2 = 2L*f0; long f1_2 = 2L*f1;
  long f2_2 = 2L*f2; long f3_2 = 2L*f3;
  long f4_2 = 2L*f4; long f5_2 = 2L*f5;
  long f6_2 = 2L*f6; long f7_2 = 2L*f7;

  long f5_38 = 38L*f5; /* 1.959375*2^30 */ long f6_19 = 19L*f6; /* 1.959375*2^30 */
  long f7_38 = 38L*f7; /* 1.959375*2^30 */ long f8_19 = 19L*f8; /* 1.959375*2^30 */
  long f9_38 = 38L*f9; /* 1.959375*2^30 */

  long f0f0    = f0  *f0   ; long f0f1_2  = f0_2*f1   ;
  long f0f2_2  = f0_2*f2   ; long f0f3_2  = f0_2*f3   ;
  long f0f4_2  = f0_2*f4   ; long f0f5_2  = f0_2*f5   ;
  long f0f6_2  = f0_2*f6   ; long f0f7_2  = f0_2*f7   ;
  long f0f8_2  = f0_2*f8   ; long f0f9_2  = f0_2*f9   ;

  long f1f1_2  = f1_2*f1   ; long f1f2_2  = f1_2*f2   ;
  long f1f3_4  = f1_2*f3_2 ; long f1f4_2  = f1_2*f4   ;
  long f1f5_4  = f1_2*f5_2 ; long f1f6_2  = f1_2*f6   ;
  long f1f7_4  = f1_2*f7_2 ; long f1f8_2  = f1_2*f8   ;
  long f1f9_76 = f1_2*f9_38; 

  long f2f2    = f2  *f2   ; long f2f3_2  = f2_2*f3   ;
  long f2f4_2  = f2_2*f4   ; long f2f5_2  = f2_2*f5   ;
  long f2f6_2  = f2_2*f6   ; long f2f7_2  = f2_2*f7   ;
  long f2f8_38 = f2_2*f8_19; long f2f9_38 = f2  *f9_38;

  long f3f3_2  = f3_2*f3   ; long f3f4_2  = f3_2*f4   ;
  long f3f5_4  = f3_2*f5_2 ; long f3f6_2  = f3_2*f6   ;
  long f3f7_76 = f3_2*f7_38; long f3f8_38 = f3_2*f8_19;
  long f3f9_76 = f3_2*f9_38;

  long f4f4    = f4  *f4   ; long f4f5_2  = f4_2*f5   ;
  long f4f6_38 = f4_2*f6_19; long f4f7_38 = f4  *f7_38;
  long f4f8_38 = f4_2*f8_19; long f4f9_38 = f4  *f9_38;

  long f5f5_38 = f5  *f5_38; long f5f6_38 = f5_2*f6_19;
  long f5f7_76 = f5_2*f7_38; long f5f8_38 = f5_2*f8_19;
  long f5f9_76 = f5_2*f9_38;

  long f6f6_19 = f6  *f6_19; long f6f7_38 = f6  *f7_38;
  long f6f8_38 = f6_2*f8_19; long f6f9_38 = f6  *f9_38;

  long f7f7_38 = f7  *f7_38; long f7f8_38 = f7_2*f8_19;
  long f7f9_76 = f7_2*f9_38;

  long f8f8_19 = f8  *f8_19; long f8f9_38 = f8  *f9_38;

  long f9f9_38 = f9  *f9_38;

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

  long m38u = (long)FD_MASK_MSB(38);
  long m39u = (long)FD_MASK_MSB(39);

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

  long f0 = f->limb[0]; long f1 = f->limb[1];
  long f2 = f->limb[2]; long f3 = f->limb[3];
  long f4 = f->limb[4]; long f5 = f->limb[5];
  long f6 = f->limb[6]; long f7 = f->limb[7];
  long f8 = f->limb[8]; long f9 = f->limb[9];

  long f0_2  = 2L*f0; long f1_2 = 2L*f1;
  long f2_2  = 2L*f2; long f3_2 = 2L*f3;
  long f4_2  = 2L*f4; long f5_2 = 2L*f5;
  long f6_2  = 2L*f6; long f7_2 = 2L*f7;

  long f5_38 = 38L*f5; /* 1.959375*2^30 */ long f6_19 = 19L*f6; /* 1.959375*2^30 */
  long f7_38 = 38L*f7; /* 1.959375*2^30 */ long f8_19 = 19L*f8; /* 1.959375*2^30 */
  long f9_38 = 38L*f9; /* 1.959375*2^30 */

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

  long m38u = (long)FD_MASK_MSB(38);
  long m39u = (long)FD_MASK_MSB(39);

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

/* SWIZZLE_IN4 loads 4 field elements into a 10x4 long matrix stored
   in 10 wl_ts.

   Does limbs 0:7 as a 8x8->8x8 int matrix transpose (recursive top down
   implementation) optimized for the case where input row 1,3,5,7 are zero.
   Result can be treated as a 8x4 long matrix with no additional operations.

   Does limbs 8:9 as a 8x2->2x8 int matrix transpose (recursive top down
   implementation) optimized for the case where input rows 1,3,5,7 are
   zero.  Result can be treated as a 2x4 long matrix with no additional
   operations.

   These two tranposes are then interleaved for lots of ILP. */

#define SWIZZLE_IN4( v0,v1,v2,v3,v4,v5,v6,v7,v8,v9, a,b,c,d ) do {     \
    int const * _a = (a)->limb;                                        \
    int const * _b = (b)->limb;                                        \
    int const * _c = (c)->limb;                                        \
    int const * _d = (d)->limb;                                        \
    wi_t _z  = wi_zero();                                              \
    wi_t _r0 = wi_ld( _a   );                                          \
    wi_t _r8 = wi_ld( _a+8 );                                          \
    wi_t _r2 = wi_ld( _b   );                                          \
    wi_t _ra = wi_ld( _b+8 );                                          \
    wi_t _r4 = wi_ld( _c   );                                          \
    wi_t _rc = wi_ld( _c+8 );                                          \
    wi_t _r6 = wi_ld( _d   );                                          \
    wi_t _re = wi_ld( _d+8 );                                          \
    wi_t _ta = _r0; _r0 = _mm256_permute2f128_si256( _ta, _r4, 0x20 ); \
    /**/            _r4 = _mm256_permute2f128_si256( _ta, _r4, 0x31 ); \
    wi_t _tc = _r2; _r2 = _mm256_permute2f128_si256( _tc, _r6, 0x20 ); \
    /**/            _r6 = _mm256_permute2f128_si256( _tc, _r6, 0x31 ); \
    wi_t _ti = _r8; _r8 = _mm256_permute2f128_si256( _ti, _rc, 0x20 ); \
    /**/            _rc = _mm256_permute2f128_si256( _ti, _rc, 0x31 ); \
    wi_t _tk = _ra; _ra = _mm256_permute2f128_si256( _tk, _re, 0x20 ); \
    /**/            _re = _mm256_permute2f128_si256( _tk, _re, 0x31 ); \
    wi_t _te = _r0; _r0 = _mm256_unpacklo_epi32    ( _te, _r2       ); \
    /**/            _r2 = _mm256_unpackhi_epi32    ( _te, _r2       ); \
    wi_t _tg = _r4; _r4 = _mm256_unpacklo_epi32    ( _tg, _r6       ); \
    /**/            _r6 = _mm256_unpackhi_epi32    ( _tg, _r6       ); \
    /**/            _r8 = _mm256_unpacklo_epi32    ( _r8, _ra       ); \
    (v0) = _mm256_unpacklo_epi32( _r0, _z );                           \
    (v1) = _mm256_unpackhi_epi32( _r0, _z );                           \
    (v2) = _mm256_unpacklo_epi32( _r2, _z );                           \
    (v3) = _mm256_unpackhi_epi32( _r2, _z );                           \
    (v4) = _mm256_unpacklo_epi32( _r4, _z );                           \
    (v5) = _mm256_unpackhi_epi32( _r4, _z );                           \
    (v6) = _mm256_unpacklo_epi32( _r6, _z );                           \
    (v7) = _mm256_unpackhi_epi32( _r6, _z );                           \
    (v8) = _mm256_unpacklo_epi32( _r8, _z );                           \
    (v9) = _mm256_unpackhi_epi32( _r8, _z );                           \
  } while(0)

/* SWIZZLE_IN3 is SWIZZLE_IN4 optimized for the d column zeroed. */

#define SWIZZLE_IN3( v0,v1,v2,v3,v4,v5,v6,v7,v8,v9, a,b,c ) do {       \
    int const * _a = (a)->limb;                                        \
    int const * _b = (b)->limb;                                        \
    int const * _c = (c)->limb;                                        \
    wi_t _z  = wi_zero();                                              \
    wi_t _r0 = wi_ld( _a   );                                          \
    wi_t _r8 = wi_ld( _a+8 );                                          \
    wi_t _r2 = wi_ld( _b   );                                          \
    wi_t _ra = wi_ld( _b+8 );                                          \
    wi_t _r4 = wi_ld( _c   );                                          \
    wi_t _rc = wi_ld( _c+8 );                                          \
    wi_t _ta = _r0; _r0 = _mm256_permute2f128_si256( _ta, _r4, 0x20 ); \
    /**/            _r4 = _mm256_permute2f128_si256( _ta, _r4, 0x31 ); \
    wi_t _tc = _r2; _r2 = _mm256_permute2f128_si256( _tc, _z,  0x20 ); \
    wi_t            _r6 = _mm256_permute2f128_si256( _tc, _z,  0x31 ); \
    wi_t _ti = _r8; _r8 = _mm256_permute2f128_si256( _ti, _rc, 0x20 ); \
    /**/            _rc = _mm256_permute2f128_si256( _ti, _rc, 0x31 ); \
    wi_t _tk = _ra; _ra = _mm256_permute2f128_si256( _tk, _z,  0x20 ); \
    wi_t _te = _r0; _r0 = _mm256_unpacklo_epi32    ( _te, _r2       ); \
    /**/            _r2 = _mm256_unpackhi_epi32    ( _te, _r2       ); \
    wi_t _tg = _r4; _r4 = _mm256_unpacklo_epi32    ( _tg, _r6       ); \
    /**/            _r6 = _mm256_unpackhi_epi32    ( _tg, _r6       ); \
    /**/            _r8 = _mm256_unpacklo_epi32    ( _r8, _ra       ); \
    (v0) = _mm256_unpacklo_epi32( _r0, _z );                           \
    (v1) = _mm256_unpackhi_epi32( _r0, _z );                           \
    (v2) = _mm256_unpacklo_epi32( _r2, _z );                           \
    (v3) = _mm256_unpackhi_epi32( _r2, _z );                           \
    (v4) = _mm256_unpacklo_epi32( _r4, _z );                           \
    (v5) = _mm256_unpackhi_epi32( _r4, _z );                           \
    (v6) = _mm256_unpacklo_epi32( _r6, _z );                           \
    (v7) = _mm256_unpackhi_epi32( _r6, _z );                           \
    (v8) = _mm256_unpacklo_epi32( _r8, _z );                           \
    (v9) = _mm256_unpackhi_epi32( _r8, _z );                           \
  } while(0)

/* SWIZZLE_IN2 is SWIZZLE_IN3 optimized for the c column zeroed. */

#define SWIZZLE_IN2( v0,v1,v2,v3,v4,v5,v6,v7,v8,v9, a,b ) do {         \
    int const * _a = (a)->limb;                                        \
    int const * _b = (b)->limb;                                        \
    wi_t _z  = wi_zero();                                              \
    wi_t _r0 = wi_ld( _a   );                                          \
    wi_t _r8 = wi_ld( _a+8 );                                          \
    wi_t _r2 = wi_ld( _b   );                                          \
    wi_t _ra = wi_ld( _b+8 );                                          \
    wi_t _ta = _r0; _r0 = _mm256_permute2f128_si256( _ta, _z,  0x20 ); \
    wi_t            _r4 = _mm256_permute2f128_si256( _ta, _z,  0x31 ); \
    wi_t _tc = _r2; _r2 = _mm256_permute2f128_si256( _tc, _z,  0x20 ); \
    wi_t            _r6 = _mm256_permute2f128_si256( _tc, _z,  0x31 ); \
    wi_t _ti = _r8; _r8 = _mm256_permute2f128_si256( _ti, _z,  0x20 ); \
    wi_t _tk = _ra; _ra = _mm256_permute2f128_si256( _tk, _z,  0x20 ); \
    wi_t _te = _r0; _r0 = _mm256_unpacklo_epi32    ( _te, _r2       ); \
    /**/            _r2 = _mm256_unpackhi_epi32    ( _te, _r2       ); \
    wi_t _tg = _r4; _r4 = _mm256_unpacklo_epi32    ( _tg, _r6       ); \
    /**/            _r6 = _mm256_unpackhi_epi32    ( _tg, _r6       ); \
    /**/            _r8 = _mm256_unpacklo_epi32    ( _r8, _ra       ); \
    (v0) = _mm256_unpacklo_epi32( _r0, _z );                           \
    (v1) = _mm256_unpackhi_epi32( _r0, _z );                           \
    (v2) = _mm256_unpacklo_epi32( _r2, _z );                           \
    (v3) = _mm256_unpackhi_epi32( _r2, _z );                           \
    (v4) = _mm256_unpacklo_epi32( _r4, _z );                           \
    (v5) = _mm256_unpackhi_epi32( _r4, _z );                           \
    (v6) = _mm256_unpacklo_epi32( _r6, _z );                           \
    (v7) = _mm256_unpackhi_epi32( _r6, _z );                           \
    (v8) = _mm256_unpacklo_epi32( _r8, _z );                           \
    (v9) = _mm256_unpackhi_epi32( _r8, _z );                           \
  } while(0)

/* SWIZZLE_OUT4 writes a 10x4 long matrix (where every element is fits into
   32-bits) in 10 wl_t into 4 field elements.  The input 10x4 long
   matrix can be reinterpreted for free as a 10x8 int matrix where columns
   1,3,5,7.

   This then does a 8x8 int matrix transpose (recursive bottom up
   implementation) for the first 8 rows.  As the first step does
   transposes for 2x2 subblocks, the zeros in columns 1,3,5,7
   immediately get compacted into the rows 1,3,5,7 and thus can be
   immediately discarded.

   Similar, the last two rows are done as an 2x8 int matrix transpose in
   the same matter and the operations are interleaved for lots of ILP. */

#define SWIZZLE_OUT4( a,b,c,d, v0,v1,v2,v3,v4,v5,v6,v7,v8,v9 ) do {                                                 \
    wf_t _z  = wf_zero();                                                                                           \
    wf_t _r0 = _mm256_shuffle_ps( _mm256_castsi256_ps( (v0) ), _mm256_castsi256_ps( (v1) ), _MM_SHUFFLE(2,0,2,0) ); \
    wf_t _r2 = _mm256_shuffle_ps( _mm256_castsi256_ps( (v2) ), _mm256_castsi256_ps( (v3) ), _MM_SHUFFLE(2,0,2,0) ); \
    wf_t _r4 = _mm256_shuffle_ps( _mm256_castsi256_ps( (v4) ), _mm256_castsi256_ps( (v5) ), _MM_SHUFFLE(2,0,2,0) ); \
    wf_t _r6 = _mm256_shuffle_ps( _mm256_castsi256_ps( (v6) ), _mm256_castsi256_ps( (v7) ), _MM_SHUFFLE(2,0,2,0) ); \
    wf_t _r8 = _mm256_shuffle_ps( _mm256_castsi256_ps( (v8) ), _mm256_castsi256_ps( (v9) ), _MM_SHUFFLE(2,0,2,0) ); \
    wf_t _ta = _r0; _r0 = _mm256_shuffle_ps( _ta, _r2, _MM_SHUFFLE(2,0,2,0) );                                      \
                    _r2 = _mm256_shuffle_ps( _ta, _r2, _MM_SHUFFLE(3,1,3,1) );                                      \
    wf_t _tb = _r4; _r4 = _mm256_shuffle_ps( _tb, _r6, _MM_SHUFFLE(2,0,2,0) );                                      \
                    _r6 = _mm256_shuffle_ps( _tb, _r6, _MM_SHUFFLE(3,1,3,1) );                                      \
    wf_t _tc = _r8; _r8 = _mm256_shuffle_ps( _tc, _z,  _MM_SHUFFLE(2,0,2,0) );                                      \
    wf_t            _ra = _mm256_shuffle_ps( _tc, _z,  _MM_SHUFFLE(3,1,3,1) );                                      \
    wf_t _td = _r0; _r0 = _mm256_permute2f128_ps( _td, _r4, 0x20 );                                                 \
                    _r4 = _mm256_permute2f128_ps( _td, _r4, 0x31 );                                                 \
    wf_t _te = _r2; _r2 = _mm256_permute2f128_ps( _te, _r6, 0x20 );                                                 \
                    _r6 = _mm256_permute2f128_ps( _te, _r6, 0x31 );                                                 \
    wf_t _tf = _r8; _r8 = _mm256_permute2f128_ps( _tf, _z,  0x20 );                                                 \
    wf_t            _rc = _mm256_permute2f128_ps( _tf, _z,  0x31 );                                                 \
    wf_t _tg = _ra; _ra = _mm256_permute2f128_ps( _tg, _z,  0x20 );                                                 \
    wf_t            _re = _mm256_permute2f128_ps( _tg, _z,  0x31 );                                                 \
    int * _a = (a)->limb;                                                                                           \
    int * _b = (b)->limb;                                                                                           \
    int * _c = (c)->limb;                                                                                           \
    int * _d = (d)->limb;                                                                                           \
    wi_st( _a,   _mm256_castps_si256( _r0 ) );                                                                      \
    wi_st( _a+8, _mm256_castps_si256( _r8 ) );                                                                      \
    wi_st( _b,   _mm256_castps_si256( _r2 ) );                                                                      \
    wi_st( _b+8, _mm256_castps_si256( _ra ) );                                                                      \
    wi_st( _c,   _mm256_castps_si256( _r4 ) );                                                                      \
    wi_st( _c+8, _mm256_castps_si256( _rc ) );                                                                      \
    wi_st( _d,   _mm256_castps_si256( _r6 ) );                                                                      \
    wi_st( _d+8, _mm256_castps_si256( _re ) );                                                                      \
  } while(0)

/* SWIZZLE_OUT3 is SWIZZLE_OUT4 optimized to discard the d column */

#define SWIZZLE_OUT3( a,b,c, v0,v1,v2,v3,v4,v5,v6,v7,v8,v9 ) do {                                                   \
    wf_t _z  = wf_zero();                                                                                           \
    wf_t _r0 = _mm256_shuffle_ps( _mm256_castsi256_ps( (v0) ), _mm256_castsi256_ps( (v1) ), _MM_SHUFFLE(2,0,2,0) ); \
    wf_t _r2 = _mm256_shuffle_ps( _mm256_castsi256_ps( (v2) ), _mm256_castsi256_ps( (v3) ), _MM_SHUFFLE(2,0,2,0) ); \
    wf_t _r4 = _mm256_shuffle_ps( _mm256_castsi256_ps( (v4) ), _mm256_castsi256_ps( (v5) ), _MM_SHUFFLE(2,0,2,0) ); \
    wf_t _r6 = _mm256_shuffle_ps( _mm256_castsi256_ps( (v6) ), _mm256_castsi256_ps( (v7) ), _MM_SHUFFLE(2,0,2,0) ); \
    wf_t _r8 = _mm256_shuffle_ps( _mm256_castsi256_ps( (v8) ), _mm256_castsi256_ps( (v9) ), _MM_SHUFFLE(2,0,2,0) ); \
    wf_t _ta = _r0; _r0 = _mm256_shuffle_ps( _ta, _r2, _MM_SHUFFLE(2,0,2,0) );                                      \
                    _r2 = _mm256_shuffle_ps( _ta, _r2, _MM_SHUFFLE(3,1,3,1) );                                      \
    wf_t _tb = _r4; _r4 = _mm256_shuffle_ps( _tb, _r6, _MM_SHUFFLE(2,0,2,0) );                                      \
                    _r6 = _mm256_shuffle_ps( _tb, _r6, _MM_SHUFFLE(3,1,3,1) );                                      \
    wf_t _ra = _r8; _r8 = _mm256_shuffle_ps( _ra, _z,  _MM_SHUFFLE(2,0,2,0) );                                      \
    /**/            _ra = _mm256_shuffle_ps( _ra, _z,  _MM_SHUFFLE(3,1,3,1) );                                      \
    wf_t _tc = _r0; _r0 = _mm256_permute2f128_ps( _tc, _r4, 0x20 );                                                 \
                    _r4 = _mm256_permute2f128_ps( _tc, _r4, 0x31 );                                                 \
    /**/            _r2 = _mm256_permute2f128_ps( _r2, _r6, 0x20 );                                                 \
    wf_t _rc = _r8; _r8 = _mm256_permute2f128_ps( _rc, _z,  0x20 );                                                 \
    /**/            _rc = _mm256_permute2f128_ps( _rc, _z,  0x31 );                                                 \
    /**/            _ra = _mm256_permute2f128_ps( _ra, _z,  0x20 );                                                 \
    int * _a = (a)->limb;                                                                                           \
    int * _b = (b)->limb;                                                                                           \
    int * _c = (c)->limb;                                                                                           \
    wi_st( _a,   _mm256_castps_si256( _r0 ) );                                                                      \
    wi_st( _a+8, _mm256_castps_si256( _r8 ) );                                                                      \
    wi_st( _b,   _mm256_castps_si256( _r2 ) );                                                                      \
    wi_st( _b+8, _mm256_castps_si256( _ra ) );                                                                      \
    wi_st( _c,   _mm256_castps_si256( _r4 ) );                                                                      \
    wi_st( _c+8, _mm256_castps_si256( _rc ) );                                                                      \
  } while(0)

/* SWIZZLE_OUT2 is SWIZZLE_OUT3 optimized to discard the c column */   

#define SWIZZLE_OUT2( a,b, v0,v1,v2,v3,v4,v5,v6,v7,v8,v9 ) do {                                                     \
    wf_t _z  = wf_zero();                                                                                           \
    wf_t _r0 = _mm256_shuffle_ps( _mm256_castsi256_ps( (v0) ), _mm256_castsi256_ps( (v1) ), _MM_SHUFFLE(2,0,2,0) ); \
    wf_t _r2 = _mm256_shuffle_ps( _mm256_castsi256_ps( (v2) ), _mm256_castsi256_ps( (v3) ), _MM_SHUFFLE(2,0,2,0) ); \
    wf_t _r4 = _mm256_shuffle_ps( _mm256_castsi256_ps( (v4) ), _mm256_castsi256_ps( (v5) ), _MM_SHUFFLE(2,0,2,0) ); \
    wf_t _r6 = _mm256_shuffle_ps( _mm256_castsi256_ps( (v6) ), _mm256_castsi256_ps( (v7) ), _MM_SHUFFLE(2,0,2,0) ); \
    wf_t _r8 = _mm256_shuffle_ps( _mm256_castsi256_ps( (v8) ), _mm256_castsi256_ps( (v9) ), _MM_SHUFFLE(2,0,2,0) ); \
    wf_t _ta = _r0; _r0 = _mm256_shuffle_ps( _ta, _r2, _MM_SHUFFLE(2,0,2,0) );                                      \
                    _r2 = _mm256_shuffle_ps( _ta, _r2, _MM_SHUFFLE(3,1,3,1) );                                      \
    wf_t _tb = _r4; _r4 = _mm256_shuffle_ps( _tb, _r6, _MM_SHUFFLE(2,0,2,0) );                                      \
                    _r6 = _mm256_shuffle_ps( _tb, _r6, _MM_SHUFFLE(3,1,3,1) );                                      \
    wf_t _ra = _r8; _r8 = _mm256_shuffle_ps( _ra, _z,  _MM_SHUFFLE(2,0,2,0) );                                      \
    /**/            _ra = _mm256_shuffle_ps( _ra, _z,  _MM_SHUFFLE(3,1,3,1) );                                      \
    /**/            _r0 = _mm256_permute2f128_ps( _r0, _r4, 0x20 );                                                 \
    /**/            _r2 = _mm256_permute2f128_ps( _r2, _r6, 0x20 );                                                 \
    /**/            _r8 = _mm256_permute2f128_ps( _r8, _z,  0x20 );                                                 \
    /**/            _ra = _mm256_permute2f128_ps( _ra, _z,  0x20 );                                                 \
    int * _a = (a)->limb;                                                                                           \
    int * _b = (b)->limb;                                                                                           \
    wi_st( _a,   _mm256_castps_si256( _r0 ) );                                                                      \
    wi_st( _a+8, _mm256_castps_si256( _r8 ) );                                                                      \
    wi_st( _b,   _mm256_castps_si256( _r2 ) );                                                                      \
    wi_st( _b+8, _mm256_castps_si256( _ra ) );                                                                      \
  } while(0)

/* PAIR_SWIZZLE_IN4 is an optimized implementation of:
     SWIZZLE_IN4( v0,v1,v2,v3,v4,v5,v6,v7,v8,v9, a,b,c,d )
     SWIZZLE_IN4( w0,w1,w2,w3,w4,w5,w6,w7,w8,w9, e,f,g,h )
   Basically, the 2 8x8 transposes are done as before but the 2 2x8
   transposes are merged into 1 2x4 transpose. */

#define PAIR_SWIZZLE_IN4( v0,v1,v2,v3,v4,v5,v6,v7,v8,v9, a,b,c,d,                                                                 \
                          w0,w1,w2,w3,w4,w5,w6,w7,w8,w9, e,f,g,h ) do {                                                           \
    wi_t _z  = wi_zero();                                                                                                         \
    int const * _a = (a)->limb;                                         int const * _e = (e)->limb;                               \
    int const * _b = (b)->limb;                                         int const * _f = (f)->limb;                               \
    int const * _c = (c)->limb;                                         int const * _g = (g)->limb;                               \
    int const * _d = (d)->limb;                                         int const * _h = (h)->limb;                               \
    wi_t _r0 = wi_ld( _a   );                                           wi_t _s0 = wi_ld( _e   );                                 \
    wi_t _r8 = wi_ld( _a+8 );                                           wi_t _s8 = wi_ld( _e+8 );                                 \
    wi_t _r2 = wi_ld( _b   );                                           wi_t _s2 = wi_ld( _f   );                                 \
    wi_t _ra = wi_ld( _b+8 );                                           wi_t _sa = wi_ld( _f+8 );                                 \
    wi_t _r4 = wi_ld( _c   );                                           wi_t _s4 = wi_ld( _g   );                                 \
    wi_t _rc = wi_ld( _c+8 );                                           wi_t _sc = wi_ld( _g+8 );                                 \
    wi_t _r6 = wi_ld( _d   );                                           wi_t _s6 = wi_ld( _h   );                                 \
    wi_t _re = wi_ld( _d+8 );                                           wi_t _se = wi_ld( _h+8 );                                 \
    wi_t _ta = _r0; _r0 = _mm256_permute2f128_si256( _ta, _r4, 0x20 );  wi_t _ua = _s0; _s0 = _mm256_permute2f128_si256( _ua, _s4, 0x20 ); \
    /**/            _r4 = _mm256_permute2f128_si256( _ta, _r4, 0x31 );  /**/            _s4 = _mm256_permute2f128_si256( _ua, _s4, 0x31 ); \
    wi_t _tc = _r2; _r2 = _mm256_permute2f128_si256( _tc, _r6, 0x20 );  wi_t _uc = _s2; _s2 = _mm256_permute2f128_si256( _uc, _s6, 0x20 ); \
    /**/            _r6 = _mm256_permute2f128_si256( _tc, _r6, 0x31 );  /**/            _s6 = _mm256_permute2f128_si256( _uc, _s6, 0x31 ); \
    /**/            _r8 = _mm256_permute2f128_si256( _r8, _s8, 0x20 );  /**/            _ra = _mm256_permute2f128_si256( _ra, _sa, 0x20 ); \
    /**/            _rc = _mm256_permute2f128_si256( _rc, _sc, 0x20 );  /**/            _re = _mm256_permute2f128_si256( _re, _se, 0x20 ); \
    wi_t _te = _r0; _r0 = _mm256_unpacklo_epi32    ( _te, _r2       );  wi_t _ue = _s0; _s0 = _mm256_unpacklo_epi32    ( _ue, _s2       ); \
    /**/            _r2 = _mm256_unpackhi_epi32    ( _te, _r2       );  /**/            _s2 = _mm256_unpackhi_epi32    ( _ue, _s2       ); \
    wi_t _tg = _r4; _r4 = _mm256_unpacklo_epi32    ( _tg, _r6       );  wi_t _ug = _s4; _s4 = _mm256_unpacklo_epi32    ( _ug, _s6       ); \
    /**/            _r6 = _mm256_unpackhi_epi32    ( _tg, _r6       );  /**/            _s6 = _mm256_unpackhi_epi32    ( _ug, _s6       ); \
    wi_t _ti = _r8; _r8 = _mm256_permute2f128_si256( _ti, _rc, 0x20 );  /**/            _rc = _mm256_permute2f128_si256( _ti, _rc, 0x31 ); \
    wi_t _tk = _ra; _ra = _mm256_permute2f128_si256( _tk, _re, 0x20 );  /**/            _re = _mm256_permute2f128_si256( _tk, _re, 0x31 ); \
    /**/            _r8 = _mm256_unpacklo_epi32    ( _r8, _ra       );  /**/            _rc = _mm256_unpacklo_epi32    ( _rc, _re       ); \
    (v0) = _mm256_unpacklo_epi32( _r0, _z );                            (w0) = _mm256_unpacklo_epi32( _s0, _z );                  \
    (v1) = _mm256_unpackhi_epi32( _r0, _z );                            (w1) = _mm256_unpackhi_epi32( _s0, _z );                  \
    (v2) = _mm256_unpacklo_epi32( _r2, _z );                            (w2) = _mm256_unpacklo_epi32( _s2, _z );                  \
    (v3) = _mm256_unpackhi_epi32( _r2, _z );                            (w3) = _mm256_unpackhi_epi32( _s2, _z );                  \
    (v4) = _mm256_unpacklo_epi32( _r4, _z );                            (w4) = _mm256_unpacklo_epi32( _s4, _z );                  \
    (v5) = _mm256_unpackhi_epi32( _r4, _z );                            (w5) = _mm256_unpackhi_epi32( _s4, _z );                  \
    (v6) = _mm256_unpacklo_epi32( _r6, _z );                            (w6) = _mm256_unpacklo_epi32( _s6, _z );                  \
    (v7) = _mm256_unpackhi_epi32( _r6, _z );                            (w7) = _mm256_unpackhi_epi32( _s6, _z );                  \
    (v8) = _mm256_unpacklo_epi32( _r8, _z );                            (w8) = _mm256_unpacklo_epi32( _rc, _z );                  \
    (v9) = _mm256_unpackhi_epi32( _r8, _z );                            (w9) = _mm256_unpackhi_epi32( _rc, _z );                  \
  } while(0)

/* PAIR_SWIZZLE_IN3 is PAIR_SWIZZLE_IN4 optimized for the d and h column
   zeroed. */

#define PAIR_SWIZZLE_IN3( v0,v1,v2,v3,v4,v5,v6,v7,v8,v9, a,b,c,                                                                   \
                          w0,w1,w2,w3,w4,w5,w6,w7,w8,w9, e,f,g ) do {                                                             \
    wi_t _z  = wi_zero();                                                                                                         \
    int const * _a = (a)->limb;                                         int const * _e = (e)->limb;                               \
    int const * _b = (b)->limb;                                         int const * _f = (f)->limb;                               \
    int const * _c = (c)->limb;                                         int const * _g = (g)->limb;                               \
    wi_t _r0 = wi_ld( _a   );                                           wi_t _s0 = wi_ld( _e   );                                 \
    wi_t _r8 = wi_ld( _a+8 );                                           wi_t _s8 = wi_ld( _e+8 );                                 \
    wi_t _r2 = wi_ld( _b   );                                           wi_t _s2 = wi_ld( _f   );                                 \
    wi_t _ra = wi_ld( _b+8 );                                           wi_t _sa = wi_ld( _f+8 );                                 \
    wi_t _r4 = wi_ld( _c   );                                           wi_t _s4 = wi_ld( _g   );                                 \
    wi_t _rc = wi_ld( _c+8 );                                           wi_t _sc = wi_ld( _g+8 );                                 \
    wi_t _ta = _r0; _r0 = _mm256_permute2f128_si256( _ta, _r4, 0x20 );  wi_t _ua = _s0; _s0 = _mm256_permute2f128_si256( _ua, _s4, 0x20 ); \
    /**/            _r4 = _mm256_permute2f128_si256( _ta, _r4, 0x31 );  /**/            _s4 = _mm256_permute2f128_si256( _ua, _s4, 0x31 ); \
    wi_t _tc = _r2; _r2 = _mm256_permute2f128_si256( _tc, _z,  0x20 );  wi_t _uc = _s2; _s2 = _mm256_permute2f128_si256( _uc, _z,  0x20 ); \
    wi_t            _r6 = _mm256_permute2f128_si256( _tc, _z,  0x31 );  wi_t            _s6 = _mm256_permute2f128_si256( _uc, _z,  0x31 ); \
    /**/            _r8 = _mm256_permute2f128_si256( _r8, _s8, 0x20 );  /**/            _ra = _mm256_permute2f128_si256( _ra, _sa, 0x20 ); \
    /**/            _rc = _mm256_permute2f128_si256( _rc, _sc, 0x20 );                                                                     \
    wi_t _te = _r0; _r0 = _mm256_unpacklo_epi32    ( _te, _r2       );  wi_t _ue = _s0; _s0 = _mm256_unpacklo_epi32    ( _ue, _s2       ); \
    /**/            _r2 = _mm256_unpackhi_epi32    ( _te, _r2       );  /**/            _s2 = _mm256_unpackhi_epi32    ( _ue, _s2       ); \
    wi_t _tg = _r4; _r4 = _mm256_unpacklo_epi32    ( _tg, _r6       );  wi_t _ug = _s4; _s4 = _mm256_unpacklo_epi32    ( _ug, _s6       ); \
    /**/            _r6 = _mm256_unpackhi_epi32    ( _tg, _r6       );  /**/            _s6 = _mm256_unpackhi_epi32    ( _ug, _s6       ); \
    wi_t _ti = _r8; _r8 = _mm256_permute2f128_si256( _ti, _rc, 0x20 );  /**/            _rc = _mm256_permute2f128_si256( _ti, _rc, 0x31 ); \
    wi_t _tk = _ra; _ra = _mm256_permute2f128_si256( _tk, _z,  0x20 );  wi_t            _re = _mm256_permute2f128_si256( _tk, _z,  0x31 ); \
    /**/            _r8 = _mm256_unpacklo_epi32    ( _r8, _ra       );  /**/            _rc = _mm256_unpacklo_epi32    ( _rc, _re       ); \
    (v0) = _mm256_unpacklo_epi32( _r0, _z );                            (w0) = _mm256_unpacklo_epi32( _s0, _z );                  \
    (v1) = _mm256_unpackhi_epi32( _r0, _z );                            (w1) = _mm256_unpackhi_epi32( _s0, _z );                  \
    (v2) = _mm256_unpacklo_epi32( _r2, _z );                            (w2) = _mm256_unpacklo_epi32( _s2, _z );                  \
    (v3) = _mm256_unpackhi_epi32( _r2, _z );                            (w3) = _mm256_unpackhi_epi32( _s2, _z );                  \
    (v4) = _mm256_unpacklo_epi32( _r4, _z );                            (w4) = _mm256_unpacklo_epi32( _s4, _z );                  \
    (v5) = _mm256_unpackhi_epi32( _r4, _z );                            (w5) = _mm256_unpackhi_epi32( _s4, _z );                  \
    (v6) = _mm256_unpacklo_epi32( _r6, _z );                            (w6) = _mm256_unpacklo_epi32( _s6, _z );                  \
    (v7) = _mm256_unpackhi_epi32( _r6, _z );                            (w7) = _mm256_unpackhi_epi32( _s6, _z );                  \
    (v8) = _mm256_unpacklo_epi32( _r8, _z );                            (w8) = _mm256_unpacklo_epi32( _rc, _z );                  \
    (v9) = _mm256_unpackhi_epi32( _r8, _z );                            (w9) = _mm256_unpackhi_epi32( _rc, _z );                  \
  } while(0)

/* PAIR_SWIZZLE_IN2 is PAIR_SWIZZLE_IN3 optimized for the c and g column
   zeroed. */

#define PAIR_SWIZZLE_IN2( v0,v1,v2,v3,v4,v5,v6,v7,v8,v9, a,b,                                                                     \
                          w0,w1,w2,w3,w4,w5,w6,w7,w8,w9, e,f ) do {                                                               \
    wi_t _z  = wi_zero();                                                                                                         \
    int const * _a = (a)->limb;                                         int const * _e = (e)->limb;                               \
    int const * _b = (b)->limb;                                         int const * _f = (f)->limb;                               \
    wi_t _r0 = wi_ld( _a   );                                           wi_t _s0 = wi_ld( _e   );                                 \
    wi_t _r8 = wi_ld( _a+8 );                                           wi_t _s8 = wi_ld( _e+8 );                                 \
    wi_t _r2 = wi_ld( _b   );                                           wi_t _s2 = wi_ld( _f   );                                 \
    wi_t _ra = wi_ld( _b+8 );                                           wi_t _sa = wi_ld( _f+8 );                                 \
    wi_t _ta = _r0; _r0 = _mm256_permute2f128_si256( _ta, _z,  0x20 );  wi_t _ua = _s0; _s0 = _mm256_permute2f128_si256( _ua, _z,  0x20 ); \
    wi_t            _r4 = _mm256_permute2f128_si256( _ta, _z,  0x31 );  wi_t            _s4 = _mm256_permute2f128_si256( _ua, _z,  0x31 ); \
    wi_t _tc = _r2; _r2 = _mm256_permute2f128_si256( _tc, _z,  0x20 );  wi_t _uc = _s2; _s2 = _mm256_permute2f128_si256( _uc, _z,  0x20 ); \
    wi_t            _r6 = _mm256_permute2f128_si256( _tc, _z,  0x31 );  wi_t            _s6 = _mm256_permute2f128_si256( _uc, _z,  0x31 ); \
    /**/            _r8 = _mm256_permute2f128_si256( _r8, _s8, 0x20 );  /**/            _ra = _mm256_permute2f128_si256( _ra, _sa, 0x20 ); \
    wi_t _te = _r0; _r0 = _mm256_unpacklo_epi32    ( _te, _r2       );  wi_t _ue = _s0; _s0 = _mm256_unpacklo_epi32    ( _ue, _s2       ); \
    /**/            _r2 = _mm256_unpackhi_epi32    ( _te, _r2       );  /**/            _s2 = _mm256_unpackhi_epi32    ( _ue, _s2       ); \
    wi_t _tg = _r4; _r4 = _mm256_unpacklo_epi32    ( _tg, _r6       );  wi_t _ug = _s4; _s4 = _mm256_unpacklo_epi32    ( _ug, _s6       ); \
    /**/            _r6 = _mm256_unpackhi_epi32    ( _tg, _r6       );  /**/            _s6 = _mm256_unpackhi_epi32    ( _ug, _s6       ); \
    wi_t _ti = _r8; _r8 = _mm256_permute2f128_si256( _ti, _z,  0x20 );  wi_t            _rc = _mm256_permute2f128_si256( _ti, _z,  0x31 ); \
    wi_t _tk = _ra; _ra = _mm256_permute2f128_si256( _tk, _z,  0x20 );  wi_t            _re = _mm256_permute2f128_si256( _tk, _z,  0x31 ); \
    /**/            _r8 = _mm256_unpacklo_epi32    ( _r8, _ra       );  /**/            _rc = _mm256_unpacklo_epi32    ( _rc, _re       ); \
    (v0) = _mm256_unpacklo_epi32( _r0, _z );                            (w0) = _mm256_unpacklo_epi32( _s0, _z );                  \
    (v1) = _mm256_unpackhi_epi32( _r0, _z );                            (w1) = _mm256_unpackhi_epi32( _s0, _z );                  \
    (v2) = _mm256_unpacklo_epi32( _r2, _z );                            (w2) = _mm256_unpacklo_epi32( _s2, _z );                  \
    (v3) = _mm256_unpackhi_epi32( _r2, _z );                            (w3) = _mm256_unpackhi_epi32( _s2, _z );                  \
    (v4) = _mm256_unpacklo_epi32( _r4, _z );                            (w4) = _mm256_unpacklo_epi32( _s4, _z );                  \
    (v5) = _mm256_unpackhi_epi32( _r4, _z );                            (w5) = _mm256_unpackhi_epi32( _s4, _z );                  \
    (v6) = _mm256_unpacklo_epi32( _r6, _z );                            (w6) = _mm256_unpacklo_epi32( _s6, _z );                  \
    (v7) = _mm256_unpackhi_epi32( _r6, _z );                            (w7) = _mm256_unpackhi_epi32( _s6, _z );                  \
    (v8) = _mm256_unpacklo_epi32( _r8, _z );                            (w8) = _mm256_unpacklo_epi32( _rc, _z );                  \
    (v9) = _mm256_unpackhi_epi32( _r8, _z );                            (w9) = _mm256_unpackhi_epi32( _rc, _z );                  \
  } while(0)

#define REDUCE_0()                       wl_zero()
#define REDUCE_1(  a                   ) (a)
#define REDUCE_2(  a,b                 ) wl_add( (a), (b) )
#define REDUCE_3(  a,b,c               ) REDUCE_2( REDUCE_2( (a),(b) ),             (c) )
#define REDUCE_4(  a,b,c,d             ) REDUCE_2( REDUCE_2( (a),(b) ),             REDUCE_2( (c),(d) ) )
#define REDUCE_5(  a,b,c,d,e           ) REDUCE_2( REDUCE_3( (a),(b),(c) ),         REDUCE_2( (d),(e) ) )
#define REDUCE_6(  a,b,c,d,e,f         ) REDUCE_2( REDUCE_3( (a),(b),(c) ),         REDUCE_3( (d),(e),(f) ) )
#define REDUCE_7(  a,b,c,d,e,f,g       ) REDUCE_2( REDUCE_4( (a),(b),(c),(d) ),     REDUCE_3( (e),(f),(g) ) )
#define REDUCE_8(  a,b,c,d,e,f,g,h     ) REDUCE_2( REDUCE_4( (a),(b),(c),(d) ),     REDUCE_4( (e),(f),(g),(h) ) )
#define REDUCE_9(  a,b,c,d,e,f,g,h,i   ) REDUCE_2( REDUCE_5( (a),(b),(c),(d),(e) ), REDUCE_4( (f),(g),(h),(i) ) )
#define REDUCE_10( a,b,c,d,e,f,g,h,i,j ) REDUCE_2( REDUCE_5( (a),(b),(c),(d),(e) ), REDUCE_5( (f),(g),(h),(i),(j) ) )

/* wl_shr_x19 returns [ (x0>>n)*19L (x1>>n)*19L ... (x3>>n)*19L ] */

static inline wl_t
wl_shr_x19( wl_t x,
            int  n ) {
  x = wl_shr( x, n );
  return REDUCE_3( x, wl_shl( x, 1 ), wl_shl( x, 4 ) );
}

#define MUL_AVX_CORE                                                                                                       \
  wl_t _19     = wl_bcast( 19L );                                                                                          \
                                                                                                                           \
  wl_t g1_19   = wl_mul_ll( _19, g1 );                                                                                     \
  wl_t g2_19   = wl_mul_ll( _19, g2 );                                                                                     \
  wl_t g3_19   = wl_mul_ll( _19, g3 );                                                                                     \
  wl_t g4_19   = wl_mul_ll( _19, g4 );                                                                                     \
  wl_t g5_19   = wl_mul_ll( _19, g5 );                                                                                     \
  wl_t g6_19   = wl_mul_ll( _19, g6 );                                                                                     \
  wl_t g7_19   = wl_mul_ll( _19, g7 );                                                                                     \
  wl_t g8_19   = wl_mul_ll( _19, g8 );                                                                                     \
  wl_t g9_19   = wl_mul_ll( _19, g9 );                                                                                     \
                                                                                                                           \
  wl_t f1_2    = wl_add( f1, f1 );                                                                                         \
  wl_t f3_2    = wl_add( f3, f3 );                                                                                         \
  wl_t f5_2    = wl_add( f5, f5 );                                                                                         \
  wl_t f7_2    = wl_add( f7, f7 );                                                                                         \
  wl_t f9_2    = wl_add( f9, f9 );                                                                                         \
                                                                                                                           \
  wl_t f0g0    = wl_mul_ll( f0, g0    ); wl_t f0g1    = wl_mul_ll( f0,   g1    );                                          \
  wl_t f0g2    = wl_mul_ll( f0, g2    ); wl_t f0g3    = wl_mul_ll( f0,   g3    );                                          \
  wl_t f0g4    = wl_mul_ll( f0, g4    ); wl_t f0g5    = wl_mul_ll( f0,   g5    );                                          \
  wl_t f0g6    = wl_mul_ll( f0, g6    ); wl_t f0g7    = wl_mul_ll( f0,   g7    );                                          \
  wl_t f0g8    = wl_mul_ll( f0, g8    ); wl_t f0g9    = wl_mul_ll( f0,   g9    );                                          \
                                                                                                                           \
  wl_t f1g0    = wl_mul_ll( f1, g0    ); wl_t f1g1_2  = wl_mul_ll( f1_2, g1    );                                          \
  wl_t f1g2    = wl_mul_ll( f1, g2    ); wl_t f1g3_2  = wl_mul_ll( f1_2, g3    );                                          \
  wl_t f1g4    = wl_mul_ll( f1, g4    ); wl_t f1g5_2  = wl_mul_ll( f1_2, g5    );                                          \
  wl_t f1g6    = wl_mul_ll( f1, g6    ); wl_t f1g7_2  = wl_mul_ll( f1_2, g7    );                                          \
  wl_t f1g8    = wl_mul_ll( f1, g8    ); wl_t f1g9_38 = wl_mul_ll( f1_2, g9_19 );                                          \
                                                                                                                           \
  wl_t f2g0    = wl_mul_ll( f2, g0    ); wl_t f2g1    = wl_mul_ll( f2,   g1    );                                          \
  wl_t f2g2    = wl_mul_ll( f2, g2    ); wl_t f2g3    = wl_mul_ll( f2,   g3    );                                          \
  wl_t f2g4    = wl_mul_ll( f2, g4    ); wl_t f2g5    = wl_mul_ll( f2,   g5    );                                          \
  wl_t f2g6    = wl_mul_ll( f2, g6    ); wl_t f2g7    = wl_mul_ll( f2,   g7    );                                          \
  wl_t f2g8_19 = wl_mul_ll( f2, g8_19 ); wl_t f2g9_19 = wl_mul_ll( f2,   g9_19 );                                          \
                                                                                                                           \
  wl_t f3g0    = wl_mul_ll( f3, g0    ); wl_t f3g1_2  = wl_mul_ll( f3_2, g1    );                                          \
  wl_t f3g2    = wl_mul_ll( f3, g2    ); wl_t f3g3_2  = wl_mul_ll( f3_2, g3    );                                          \
  wl_t f3g4    = wl_mul_ll( f3, g4    ); wl_t f3g5_2  = wl_mul_ll( f3_2, g5    );                                          \
  wl_t f3g6    = wl_mul_ll( f3, g6    ); wl_t f3g7_38 = wl_mul_ll( f3_2, g7_19 );                                          \
  wl_t f3g8_19 = wl_mul_ll( f3, g8_19 ); wl_t f3g9_38 = wl_mul_ll( f3_2, g9_19 );                                          \
                                                                                                                           \
  wl_t f4g0    = wl_mul_ll( f4, g0    ); wl_t f4g1    = wl_mul_ll( f4,   g1    );                                          \
  wl_t f4g2    = wl_mul_ll( f4, g2    ); wl_t f4g3    = wl_mul_ll( f4,   g3    );                                          \
  wl_t f4g4    = wl_mul_ll( f4, g4    ); wl_t f4g5    = wl_mul_ll( f4,   g5    );                                          \
  wl_t f4g6_19 = wl_mul_ll( f4, g6_19 ); wl_t f4g7_19 = wl_mul_ll( f4,   g7_19 );                                          \
  wl_t f4g8_19 = wl_mul_ll( f4, g8_19 ); wl_t f4g9_19 = wl_mul_ll( f4,   g9_19 );                                          \
                                                                                                                           \
  wl_t f5g0    = wl_mul_ll( f5, g0    ); wl_t f5g1_2  = wl_mul_ll( f5_2, g1    );                                          \
  wl_t f5g2    = wl_mul_ll( f5, g2    ); wl_t f5g3_2  = wl_mul_ll( f5_2, g3    );                                          \
  wl_t f5g4    = wl_mul_ll( f5, g4    ); wl_t f5g5_38 = wl_mul_ll( f5_2, g5_19 );                                          \
  wl_t f5g6_19 = wl_mul_ll( f5, g6_19 ); wl_t f5g7_38 = wl_mul_ll( f5_2, g7_19 );                                          \
  wl_t f5g8_19 = wl_mul_ll( f5, g8_19 ); wl_t f5g9_38 = wl_mul_ll( f5_2, g9_19 );                                          \
                                                                                                                           \
  wl_t f6g0    = wl_mul_ll( f6, g0    ); wl_t f6g1    = wl_mul_ll( f6,   g1    );                                          \
  wl_t f6g2    = wl_mul_ll( f6, g2    ); wl_t f6g3    = wl_mul_ll( f6,   g3    );                                          \
  wl_t f6g4_19 = wl_mul_ll( f6, g4_19 ); wl_t f6g5_19 = wl_mul_ll( f6,   g5_19 );                                          \
  wl_t f6g6_19 = wl_mul_ll( f6, g6_19 ); wl_t f6g7_19 = wl_mul_ll( f6,   g7_19 );                                          \
  wl_t f6g8_19 = wl_mul_ll( f6, g8_19 ); wl_t f6g9_19 = wl_mul_ll( f6,   g9_19 );                                          \
                                                                                                                           \
  wl_t f7g0    = wl_mul_ll( f7, g0    ); wl_t f7g1_2  = wl_mul_ll( f7_2, g1    );                                          \
  wl_t f7g2    = wl_mul_ll( f7, g2    ); wl_t f7g3_38 = wl_mul_ll( f7_2, g3_19 );                                          \
  wl_t f7g4_19 = wl_mul_ll( f7, g4_19 ); wl_t f7g5_38 = wl_mul_ll( f7_2, g5_19 );                                          \
  wl_t f7g6_19 = wl_mul_ll( f7, g6_19 ); wl_t f7g7_38 = wl_mul_ll( f7_2, g7_19 );                                          \
  wl_t f7g8_19 = wl_mul_ll( f7, g8_19 ); wl_t f7g9_38 = wl_mul_ll( f7_2, g9_19 );                                          \
                                                                                                                           \
  wl_t f8g0    = wl_mul_ll( f8, g0    ); wl_t f8g1    = wl_mul_ll( f8,   g1    );                                          \
  wl_t f8g2_19 = wl_mul_ll( f8, g2_19 ); wl_t f8g3_19 = wl_mul_ll( f8,   g3_19 );                                          \
  wl_t f8g4_19 = wl_mul_ll( f8, g4_19 ); wl_t f8g5_19 = wl_mul_ll( f8,   g5_19 );                                          \
  wl_t f8g6_19 = wl_mul_ll( f8, g6_19 ); wl_t f8g7_19 = wl_mul_ll( f8,   g7_19 );                                          \
  wl_t f8g8_19 = wl_mul_ll( f8, g8_19 ); wl_t f8g9_19 = wl_mul_ll( f8,   g9_19 );                                          \
                                                                                                                           \
  wl_t f9g0    = wl_mul_ll( f9, g0    ); wl_t f9g1_38 = wl_mul_ll( f9_2, g1_19 );                                          \
  wl_t f9g2_19 = wl_mul_ll( f9, g2_19 ); wl_t f9g3_38 = wl_mul_ll( f9_2, g3_19 );                                          \
  wl_t f9g4_19 = wl_mul_ll( f9, g4_19 ); wl_t f9g5_38 = wl_mul_ll( f9_2, g5_19 );                                          \
  wl_t f9g6_19 = wl_mul_ll( f9, g6_19 ); wl_t f9g7_38 = wl_mul_ll( f9_2, g7_19 );                                          \
  wl_t f9g8_19 = wl_mul_ll( f9, g8_19 ); wl_t f9g9_38 = wl_mul_ll( f9_2, g9_19 );                                          \
                                                                                                                           \
  wl_t h0      = REDUCE_10( f0g0, f1g9_38, f2g8_19, f3g7_38, f4g6_19, f5g5_38, f6g4_19, f7g3_38, f8g2_19, f9g1_38 );       \
  wl_t h1      = REDUCE_10( f0g1, f1g0   , f2g9_19, f3g8_19, f4g7_19, f5g6_19, f6g5_19, f7g4_19, f8g3_19, f9g2_19 );       \
  wl_t h2      = REDUCE_10( f0g2, f1g1_2 , f2g0   , f3g9_38, f4g8_19, f5g7_38, f6g6_19, f7g5_38, f8g4_19, f9g3_38 );       \
  wl_t h3      = REDUCE_10( f0g3, f1g2   , f2g1   , f3g0   , f4g9_19, f5g8_19, f6g7_19, f7g6_19, f8g5_19, f9g4_19 );       \
  wl_t h4      = REDUCE_10( f0g4, f1g3_2 , f2g2   , f3g1_2 , f4g0   , f5g9_38, f6g8_19, f7g7_38, f8g6_19, f9g5_38 );       \
  wl_t h5      = REDUCE_10( f0g5, f1g4   , f2g3   , f3g2   , f4g1   , f5g0   , f6g9_19, f7g8_19, f8g7_19, f9g6_19 );       \
  wl_t h6      = REDUCE_10( f0g6, f1g5_2 , f2g4   , f3g3_2 , f4g2   , f5g1_2 , f6g0   , f7g9_38, f8g8_19, f9g7_38 );       \
  wl_t h7      = REDUCE_10( f0g7, f1g6   , f2g5   , f3g4   , f4g3   , f5g2   , f6g1   , f7g0   , f8g9_19, f9g8_19 );       \
  wl_t h8      = REDUCE_10( f0g8, f1g7_2 , f2g6   , f3g5_2 , f4g4   , f5g3_2 , f6g2   , f7g1_2 , f8g0   , f9g9_38 );       \
  wl_t h9      = REDUCE_10( f0g9, f1g8   , f2g7   , f3g6   , f4g5   , f5g4   , f6g3   , f7g2   , f8g1   , f9g0    );       \
                                                                                                                           \
  wl_t m38u    = wl_bcast( (long)FD_MASK_MSB(38) );                                                                        \
  wl_t m39u    = wl_bcast( (long)FD_MASK_MSB(39) );                                                                        \
  wl_t b24     = wl_bcast( 1L << 24 );                                                                                     \
  wl_t b25     = wl_bcast( 1L << 25 );                                                                                     \
                                                                                                                           \
  wl_t carry0 = wl_add( h0, b25 ); h1 = wl_add( h1, wl_shr    ( carry0, 26 ) ); h0 = wl_sub( h0, wl_and( carry0, m38u ) ); \
  wl_t carry4 = wl_add( h4, b25 ); h5 = wl_add( h5, wl_shr    ( carry4, 26 ) ); h4 = wl_sub( h4, wl_and( carry4, m38u ) ); \
  wl_t carry1 = wl_add( h1, b24 ); h2 = wl_add( h2, wl_shr    ( carry1, 25 ) ); h1 = wl_sub( h1, wl_and( carry1, m39u ) ); \
  wl_t carry5 = wl_add( h5, b24 ); h6 = wl_add( h6, wl_shr    ( carry5, 25 ) ); h5 = wl_sub( h5, wl_and( carry5, m39u ) ); \
  wl_t carry2 = wl_add( h2, b25 ); h3 = wl_add( h3, wl_shr    ( carry2, 26 ) ); h2 = wl_sub( h2, wl_and( carry2, m38u ) ); \
  wl_t carry6 = wl_add( h6, b25 ); h7 = wl_add( h7, wl_shr    ( carry6, 26 ) ); h6 = wl_sub( h6, wl_and( carry6, m38u ) ); \
  wl_t carry3 = wl_add( h3, b24 ); h4 = wl_add( h4, wl_shr    ( carry3, 25 ) ); h3 = wl_sub( h3, wl_and( carry3, m39u ) ); \
  wl_t carry7 = wl_add( h7, b24 ); h8 = wl_add( h8, wl_shr    ( carry7, 25 ) ); h7 = wl_sub( h7, wl_and( carry7, m39u ) ); \
  /**/ carry4 = wl_add( h4, b25 ); h5 = wl_add( h5, wl_shr    ( carry4, 26 ) ); h4 = wl_sub( h4, wl_and( carry4, m38u ) ); \
  wl_t carry8 = wl_add( h8, b25 ); h9 = wl_add( h9, wl_shr    ( carry8, 26 ) ); h8 = wl_sub( h8, wl_and( carry8, m38u ) ); \
  wl_t carry9 = wl_add( h9, b24 ); h0 = wl_add( h0, wl_shr_x19( carry9, 25 ) ); h9 = wl_sub( h9, wl_and( carry9, m39u ) ); \
  /**/ carry0 = wl_add( h0, b25 ); h1 = wl_add( h1, wl_shr    ( carry0, 26 ) ); h0 = wl_sub( h0, wl_and( carry0, m38u ) ) 

#define SQ_AVX_CORE                                                                                                        \
  wl_t f0_2  = wl_add( f0, f0 );     wl_t f1_2  = wl_add( f1, f1 );                                                        \
  wl_t f2_2  = wl_add( f2, f2 );     wl_t f3_2  = wl_add( f3, f3 );                                                        \
  wl_t f4_2  = wl_add( f4, f4 );     wl_t f5_2  = wl_add( f5, f5 );                                                        \
  wl_t f6_2  = wl_add( f6, f6 );     wl_t f7_2  = wl_add( f7, f7 );                                                        \
                                                                                                                           \
  wl_t _38   = wl_bcast( 38L );      wl_t _19   = wl_bcast( 19L );                                                         \
                                                                                                                           \
  wl_t f5_38 = wl_mul_ll( _38, f5 ); wl_t f6_19 = wl_mul_ll( _19, f6 );                                                    \
  wl_t f7_38 = wl_mul_ll( _38, f7 ); wl_t f8_19 = wl_mul_ll( _19, f8 );                                                    \
  wl_t f9_38 = wl_mul_ll( _38, f9 );                                                                                       \
                                                                                                                           \
  wl_t f0f0    = wl_mul_ll( f0  , f0    ); wl_t f0f1_2  = wl_mul_ll( f0_2, f1    );                                        \
  wl_t f0f2_2  = wl_mul_ll( f0_2, f2    ); wl_t f0f3_2  = wl_mul_ll( f0_2, f3    );                                        \
  wl_t f0f4_2  = wl_mul_ll( f0_2, f4    ); wl_t f0f5_2  = wl_mul_ll( f0_2, f5    );                                        \
  wl_t f0f6_2  = wl_mul_ll( f0_2, f6    ); wl_t f0f7_2  = wl_mul_ll( f0_2, f7    );                                        \
  wl_t f0f8_2  = wl_mul_ll( f0_2, f8    ); wl_t f0f9_2  = wl_mul_ll( f0_2, f9    );                                        \
                                                                                                                           \
  wl_t f1f1_2  = wl_mul_ll( f1_2, f1    ); wl_t f1f2_2  = wl_mul_ll( f1_2, f2    );                                        \
  wl_t f1f3_4  = wl_mul_ll( f1_2, f3_2  ); wl_t f1f4_2  = wl_mul_ll( f1_2, f4    );                                        \
  wl_t f1f5_4  = wl_mul_ll( f1_2, f5_2  ); wl_t f1f6_2  = wl_mul_ll( f1_2, f6    );                                        \
  wl_t f1f7_4  = wl_mul_ll( f1_2, f7_2  ); wl_t f1f8_2  = wl_mul_ll( f1_2, f8    );                                        \
  wl_t f1f9_76 = wl_mul_ll( f1_2, f9_38 );                                                                                 \
                                                                                                                           \
  wl_t f2f2    = wl_mul_ll( f2  , f2    ); wl_t f2f3_2  = wl_mul_ll( f2_2, f3    );                                        \
  wl_t f2f4_2  = wl_mul_ll( f2_2, f4    ); wl_t f2f5_2  = wl_mul_ll( f2_2, f5    );                                        \
  wl_t f2f6_2  = wl_mul_ll( f2_2, f6    ); wl_t f2f7_2  = wl_mul_ll( f2_2, f7    );                                        \
  wl_t f2f8_38 = wl_mul_ll( f2_2, f8_19 ); wl_t f2f9_38 = wl_mul_ll( f2  , f9_38 );                                        \
                                                                                                                           \
  wl_t f3f3_2  = wl_mul_ll( f3_2, f3    ); wl_t f3f4_2  = wl_mul_ll( f3_2, f4    );                                        \
  wl_t f3f5_4  = wl_mul_ll( f3_2, f5_2  ); wl_t f3f6_2  = wl_mul_ll( f3_2, f6    );                                        \
  wl_t f3f7_76 = wl_mul_ll( f3_2, f7_38 ); wl_t f3f8_38 = wl_mul_ll( f3_2, f8_19 );                                        \
  wl_t f3f9_76 = wl_mul_ll( f3_2, f9_38 );                                                                                 \
                                                                                                                           \
  wl_t f4f4    = wl_mul_ll( f4  , f4    ); wl_t f4f5_2  = wl_mul_ll( f4_2, f5    );                                        \
  wl_t f4f6_38 = wl_mul_ll( f4_2, f6_19 ); wl_t f4f7_38 = wl_mul_ll( f4  , f7_38 );                                        \
  wl_t f4f8_38 = wl_mul_ll( f4_2, f8_19 ); wl_t f4f9_38 = wl_mul_ll( f4  , f9_38 );                                        \
                                                                                                                           \
  wl_t f5f5_38 = wl_mul_ll( f5  , f5_38 ); wl_t f5f6_38 = wl_mul_ll( f5_2, f6_19 );                                        \
  wl_t f5f7_76 = wl_mul_ll( f5_2, f7_38 ); wl_t f5f8_38 = wl_mul_ll( f5_2, f8_19 );                                        \
  wl_t f5f9_76 = wl_mul_ll( f5_2, f9_38 );                                                                                 \
                                                                                                                           \
  wl_t f6f6_19 = wl_mul_ll( f6  , f6_19 ); wl_t f6f7_38 = wl_mul_ll( f6  , f7_38 );                                        \
  wl_t f6f8_38 = wl_mul_ll( f6_2, f8_19 ); wl_t f6f9_38 = wl_mul_ll( f6  , f9_38 );                                        \
                                                                                                                           \
  wl_t f7f7_38 = wl_mul_ll( f7  , f7_38 ); wl_t f7f8_38 = wl_mul_ll( f7_2, f8_19 );                                        \
  wl_t f7f9_76 = wl_mul_ll( f7_2, f9_38 );                                                                                 \
                                                                                                                           \
  wl_t f8f8_19 = wl_mul_ll( f8  , f8_19 ); wl_t f8f9_38 = wl_mul_ll( f8  , f9_38 );                                        \
                                                                                                                           \
  wl_t f9f9_38 = wl_mul_ll( f9  , f9_38 );                                                                                 \
                                                                                                                           \
  wl_t m  = wl( 1L-na, 1L-nb, 1L-nc, 1L-nd );                                                                              \
                                                                                                                           \
  wl_t h0 = REDUCE_6( f0f0  , f1f9_76, f2f8_38, f3f7_76, f4f6_38, f5f5_38 ); h0 = wl_add( h0, wl_and( h0, m ) );           \
  wl_t h1 = REDUCE_5( f0f1_2, f2f9_38, f3f8_38, f4f7_38, f5f6_38          ); h1 = wl_add( h1, wl_and( h1, m ) );           \
  wl_t h2 = REDUCE_6( f0f2_2, f1f1_2 , f3f9_76, f4f8_38, f5f7_76, f6f6_19 ); h2 = wl_add( h2, wl_and( h2, m ) );           \
  wl_t h3 = REDUCE_5( f0f3_2, f1f2_2 , f4f9_38, f5f8_38, f6f7_38          ); h3 = wl_add( h3, wl_and( h3, m ) );           \
  wl_t h4 = REDUCE_6( f0f4_2, f1f3_4 , f2f2   , f5f9_76, f6f8_38, f7f7_38 ); h4 = wl_add( h4, wl_and( h4, m ) );           \
  wl_t h5 = REDUCE_5( f0f5_2, f1f4_2 , f2f3_2 , f6f9_38, f7f8_38          ); h5 = wl_add( h5, wl_and( h5, m ) );           \
  wl_t h6 = REDUCE_6( f0f6_2, f1f5_4 , f2f4_2 , f3f3_2 , f7f9_76, f8f8_19 ); h6 = wl_add( h6, wl_and( h6, m ) );           \
  wl_t h7 = REDUCE_5( f0f7_2, f1f6_2 , f2f5_2 , f3f4_2 , f8f9_38          ); h7 = wl_add( h7, wl_and( h7, m ) );           \
  wl_t h8 = REDUCE_6( f0f8_2, f1f7_4 , f2f6_2 , f3f5_4 , f4f4   , f9f9_38 ); h8 = wl_add( h8, wl_and( h8, m ) );           \
  wl_t h9 = REDUCE_5( f0f9_2, f1f8_2 , f2f7_2 , f3f6_2 , f4f5_2           ); h9 = wl_add( h9, wl_and( h9, m ) );           \
                                                                                                                           \
  wl_t m38u = wl_bcast( (long)FD_MASK_MSB(38) );                                                                           \
  wl_t m39u = wl_bcast( (long)FD_MASK_MSB(39) );                                                                           \
  wl_t b24  = wl_bcast( 1L << 24 );                                                                                        \
  wl_t b25  = wl_bcast( 1L << 25 );                                                                                        \
                                                                                                                           \
  wl_t carry0 = wl_add( h0, b25 ); h1 = wl_add( h1, wl_shr    ( carry0, 26 ) ); h0 = wl_sub( h0, wl_and( carry0, m38u ) ); \
  wl_t carry4 = wl_add( h4, b25 ); h5 = wl_add( h5, wl_shr    ( carry4, 26 ) ); h4 = wl_sub( h4, wl_and( carry4, m38u ) ); \
  wl_t carry1 = wl_add( h1, b24 ); h2 = wl_add( h2, wl_shr    ( carry1, 25 ) ); h1 = wl_sub( h1, wl_and( carry1, m39u ) ); \
  wl_t carry5 = wl_add( h5, b24 ); h6 = wl_add( h6, wl_shr    ( carry5, 25 ) ); h5 = wl_sub( h5, wl_and( carry5, m39u ) ); \
  wl_t carry2 = wl_add( h2, b25 ); h3 = wl_add( h3, wl_shr    ( carry2, 26 ) ); h2 = wl_sub( h2, wl_and( carry2, m38u ) ); \
  wl_t carry6 = wl_add( h6, b25 ); h7 = wl_add( h7, wl_shr    ( carry6, 26 ) ); h6 = wl_sub( h6, wl_and( carry6, m38u ) ); \
  wl_t carry3 = wl_add( h3, b24 ); h4 = wl_add( h4, wl_shr    ( carry3, 25 ) ); h3 = wl_sub( h3, wl_and( carry3, m39u ) ); \
  wl_t carry7 = wl_add( h7, b24 ); h8 = wl_add( h8, wl_shr    ( carry7, 25 ) ); h7 = wl_sub( h7, wl_and( carry7, m39u ) ); \
  /**/ carry4 = wl_add( h4, b25 ); h5 = wl_add( h5, wl_shr    ( carry4, 26 ) ); h4 = wl_sub( h4, wl_and( carry4, m38u ) ); \
  wl_t carry8 = wl_add( h8, b25 ); h9 = wl_add( h9, wl_shr    ( carry8, 26 ) ); h8 = wl_sub( h8, wl_and( carry8, m38u ) ); \
  wl_t carry9 = wl_add( h9, b24 ); h0 = wl_add( h0, wl_shr_x19( carry9, 25 ) ); h9 = wl_sub( h9, wl_and( carry9, m39u ) ); \
  /**/ carry0 = wl_add( h0, b25 ); h1 = wl_add( h1, wl_shr    ( carry0, 26 ) ); h0 = wl_sub( h0, wl_and( carry0, m38u ) )

#define SQ_AVX_CORE_LOOP                                                                                                   \
  wl_t f0_2  = wl_add( f0, f0 );     wl_t f1_2  = wl_add( f1, f1 );                                                        \
  wl_t f2_2  = wl_add( f2, f2 );     wl_t f3_2  = wl_add( f3, f3 );                                                        \
  wl_t f4_2  = wl_add( f4, f4 );     wl_t f5_2  = wl_add( f5, f5 );                                                        \
  wl_t f6_2  = wl_add( f6, f6 );     wl_t f7_2  = wl_add( f7, f7 );                                                        \
                                                                                                                           \
  wl_t _38   = wl_bcast( 38L );      wl_t _19   = wl_bcast( 19L );                                                         \
                                                                                                                           \
  wl_t f5_38 = wl_mul_ll( _38, f5 ); wl_t f6_19 = wl_mul_ll( _19, f6 );                                                    \
  wl_t f7_38 = wl_mul_ll( _38, f7 ); wl_t f8_19 = wl_mul_ll( _19, f8 );                                                    \
  wl_t f9_38 = wl_mul_ll( _38, f9 );                                                                                       \
                                                                                                                           \
  wl_t f0f0    = wl_mul_ll( f0  , f0    ); wl_t f0f1_2  = wl_mul_ll( f0_2, f1    );                                        \
  wl_t f0f2_2  = wl_mul_ll( f0_2, f2    ); wl_t f0f3_2  = wl_mul_ll( f0_2, f3    );                                        \
  wl_t f0f4_2  = wl_mul_ll( f0_2, f4    ); wl_t f0f5_2  = wl_mul_ll( f0_2, f5    );                                        \
  wl_t f0f6_2  = wl_mul_ll( f0_2, f6    ); wl_t f0f7_2  = wl_mul_ll( f0_2, f7    );                                        \
  wl_t f0f8_2  = wl_mul_ll( f0_2, f8    ); wl_t f0f9_2  = wl_mul_ll( f0_2, f9    );                                        \
                                                                                                                           \
  wl_t f1f1_2  = wl_mul_ll( f1_2, f1    ); wl_t f1f2_2  = wl_mul_ll( f1_2, f2    );                                        \
  wl_t f1f3_4  = wl_mul_ll( f1_2, f3_2  ); wl_t f1f4_2  = wl_mul_ll( f1_2, f4    );                                        \
  wl_t f1f5_4  = wl_mul_ll( f1_2, f5_2  ); wl_t f1f6_2  = wl_mul_ll( f1_2, f6    );                                        \
  wl_t f1f7_4  = wl_mul_ll( f1_2, f7_2  ); wl_t f1f8_2  = wl_mul_ll( f1_2, f8    );                                        \
  wl_t f1f9_76 = wl_mul_ll( f1_2, f9_38 );                                                                                 \
                                                                                                                           \
  wl_t f2f2    = wl_mul_ll( f2  , f2    ); wl_t f2f3_2  = wl_mul_ll( f2_2, f3    );                                        \
  wl_t f2f4_2  = wl_mul_ll( f2_2, f4    ); wl_t f2f5_2  = wl_mul_ll( f2_2, f5    );                                        \
  wl_t f2f6_2  = wl_mul_ll( f2_2, f6    ); wl_t f2f7_2  = wl_mul_ll( f2_2, f7    );                                        \
  wl_t f2f8_38 = wl_mul_ll( f2_2, f8_19 ); wl_t f2f9_38 = wl_mul_ll( f2  , f9_38 );                                        \
                                                                                                                           \
  wl_t f3f3_2  = wl_mul_ll( f3_2, f3    ); wl_t f3f4_2  = wl_mul_ll( f3_2, f4    );                                        \
  wl_t f3f5_4  = wl_mul_ll( f3_2, f5_2  ); wl_t f3f6_2  = wl_mul_ll( f3_2, f6    );                                        \
  wl_t f3f7_76 = wl_mul_ll( f3_2, f7_38 ); wl_t f3f8_38 = wl_mul_ll( f3_2, f8_19 );                                        \
  wl_t f3f9_76 = wl_mul_ll( f3_2, f9_38 );                                                                                 \
                                                                                                                           \
  wl_t f4f4    = wl_mul_ll( f4  , f4    ); wl_t f4f5_2  = wl_mul_ll( f4_2, f5    );                                        \
  wl_t f4f6_38 = wl_mul_ll( f4_2, f6_19 ); wl_t f4f7_38 = wl_mul_ll( f4  , f7_38 );                                        \
  wl_t f4f8_38 = wl_mul_ll( f4_2, f8_19 ); wl_t f4f9_38 = wl_mul_ll( f4  , f9_38 );                                        \
                                                                                                                           \
  wl_t f5f5_38 = wl_mul_ll( f5  , f5_38 ); wl_t f5f6_38 = wl_mul_ll( f5_2, f6_19 );                                        \
  wl_t f5f7_76 = wl_mul_ll( f5_2, f7_38 ); wl_t f5f8_38 = wl_mul_ll( f5_2, f8_19 );                                        \
  wl_t f5f9_76 = wl_mul_ll( f5_2, f9_38 );                                                                                 \
                                                                                                                           \
  wl_t f6f6_19 = wl_mul_ll( f6  , f6_19 ); wl_t f6f7_38 = wl_mul_ll( f6  , f7_38 );                                        \
  wl_t f6f8_38 = wl_mul_ll( f6_2, f8_19 ); wl_t f6f9_38 = wl_mul_ll( f6  , f9_38 );                                        \
                                                                                                                           \
  wl_t f7f7_38 = wl_mul_ll( f7  , f7_38 ); wl_t f7f8_38 = wl_mul_ll( f7_2, f8_19 );                                        \
  wl_t f7f9_76 = wl_mul_ll( f7_2, f9_38 );                                                                                 \
                                                                                                                           \
  wl_t f8f8_19 = wl_mul_ll( f8  , f8_19 ); wl_t f8f9_38 = wl_mul_ll( f8  , f9_38 );                                        \
                                                                                                                           \
  wl_t f9f9_38 = wl_mul_ll( f9  , f9_38 );                                                                                 \
                                                                                                                           \
  wl_t m  = wl( 1L-na, 1L-nb, 1L-nc, 1L-nd );                                                                              \
                                                                                                                           \
  f0 = REDUCE_6( f0f0  , f1f9_76, f2f8_38, f3f7_76, f4f6_38, f5f5_38 ); f0 = wl_add( f0, wl_and( f0, m ) );                \
  f1 = REDUCE_5( f0f1_2, f2f9_38, f3f8_38, f4f7_38, f5f6_38          ); f1 = wl_add( f1, wl_and( f1, m ) );                \
  f2 = REDUCE_6( f0f2_2, f1f1_2 , f3f9_76, f4f8_38, f5f7_76, f6f6_19 ); f2 = wl_add( f2, wl_and( f2, m ) );                \
  f3 = REDUCE_5( f0f3_2, f1f2_2 , f4f9_38, f5f8_38, f6f7_38          ); f3 = wl_add( f3, wl_and( f3, m ) );                \
  f4 = REDUCE_6( f0f4_2, f1f3_4 , f2f2   , f5f9_76, f6f8_38, f7f7_38 ); f4 = wl_add( f4, wl_and( f4, m ) );                \
  f5 = REDUCE_5( f0f5_2, f1f4_2 , f2f3_2 , f6f9_38, f7f8_38          ); f5 = wl_add( f5, wl_and( f5, m ) );                \
  f6 = REDUCE_6( f0f6_2, f1f5_4 , f2f4_2 , f3f3_2 , f7f9_76, f8f8_19 ); f6 = wl_add( f6, wl_and( f6, m ) );                \
  f7 = REDUCE_5( f0f7_2, f1f6_2 , f2f5_2 , f3f4_2 , f8f9_38          ); f7 = wl_add( f7, wl_and( f7, m ) );                \
  f8 = REDUCE_6( f0f8_2, f1f7_4 , f2f6_2 , f3f5_4 , f4f4   , f9f9_38 ); f8 = wl_add( f8, wl_and( f8, m ) );                \
  f9 = REDUCE_5( f0f9_2, f1f8_2 , f2f7_2 , f3f6_2 , f4f5_2           ); f9 = wl_add( f9, wl_and( f9, m ) );                \
                                                                                                                           \
  wl_t m38u = wl_bcast( (long)FD_MASK_MSB(38) );                                                                           \
  wl_t m39u = wl_bcast( (long)FD_MASK_MSB(39) );                                                                           \
  wl_t b24  = wl_bcast( 1L << 24 );                                                                                        \
  wl_t b25  = wl_bcast( 1L << 25 );                                                                                        \
                                                                                                                           \
  wl_t carry0 = wl_add( f0, b25 ); f1 = wl_add( f1, wl_shr    ( carry0, 26 ) ); f0 = wl_sub( f0, wl_and( carry0, m38u ) ); \
  wl_t carry4 = wl_add( f4, b25 ); f5 = wl_add( f5, wl_shr    ( carry4, 26 ) ); f4 = wl_sub( f4, wl_and( carry4, m38u ) ); \
  wl_t carry1 = wl_add( f1, b24 ); f2 = wl_add( f2, wl_shr    ( carry1, 25 ) ); f1 = wl_sub( f1, wl_and( carry1, m39u ) ); \
  wl_t carry5 = wl_add( f5, b24 ); f6 = wl_add( f6, wl_shr    ( carry5, 25 ) ); f5 = wl_sub( f5, wl_and( carry5, m39u ) ); \
  wl_t carry2 = wl_add( f2, b25 ); f3 = wl_add( f3, wl_shr    ( carry2, 26 ) ); f2 = wl_sub( f2, wl_and( carry2, m38u ) ); \
  wl_t carry6 = wl_add( f6, b25 ); f7 = wl_add( f7, wl_shr    ( carry6, 26 ) ); f6 = wl_sub( f6, wl_and( carry6, m38u ) ); \
  wl_t carry3 = wl_add( f3, b24 ); f4 = wl_add( f4, wl_shr    ( carry3, 25 ) ); f3 = wl_sub( f3, wl_and( carry3, m39u ) ); \
  wl_t carry7 = wl_add( f7, b24 ); f8 = wl_add( f8, wl_shr    ( carry7, 25 ) ); f7 = wl_sub( f7, wl_and( carry7, m39u ) ); \
  /**/ carry4 = wl_add( f4, b25 ); f5 = wl_add( f5, wl_shr    ( carry4, 26 ) ); f4 = wl_sub( f4, wl_and( carry4, m38u ) ); \
  wl_t carry8 = wl_add( f8, b25 ); f9 = wl_add( f9, wl_shr    ( carry8, 26 ) ); f8 = wl_sub( f8, wl_and( carry8, m38u ) ); \
  wl_t carry9 = wl_add( f9, b24 ); f0 = wl_add( f0, wl_shr_x19( carry9, 25 ) ); f9 = wl_sub( f9, wl_and( carry9, m39u ) ); \
  /**/ carry0 = wl_add( f0, b25 ); f1 = wl_add( f1, wl_shr    ( carry0, 26 ) ); f0 = wl_sub( f0, wl_and( carry0, m38u ) )

void
fd_ed25519_fe_mul2( fd_ed25519_fe_t * ha, fd_ed25519_fe_t const * fa, fd_ed25519_fe_t const * ga,
                    fd_ed25519_fe_t * hb, fd_ed25519_fe_t const * fb, fd_ed25519_fe_t const * gb ) {
  wl_t f0; wl_t f1; wl_t f2; wl_t f3; wl_t f4; wl_t f5; wl_t f6; wl_t f7; wl_t f8; wl_t f9;
  wl_t g0; wl_t g1; wl_t g2; wl_t g3; wl_t g4; wl_t g5; wl_t g6; wl_t g7; wl_t g8; wl_t g9;
  PAIR_SWIZZLE_IN2( f0,f1,f2,f3,f4,f5,f6,f7,f8,f9, fa,fb,
                    g0,g1,g2,g3,g4,g5,g6,g7,g8,g9, ga,gb );
  MUL_AVX_CORE;
  SWIZZLE_OUT2( ha,hb, h0,h1,h2,h3,h4,h5,h6,h7,h8,h9 );
}

void
fd_ed25519_fe_mul3( fd_ed25519_fe_t * ha, fd_ed25519_fe_t const * fa, fd_ed25519_fe_t const * ga,
                    fd_ed25519_fe_t * hb, fd_ed25519_fe_t const * fb, fd_ed25519_fe_t const * gb,
                    fd_ed25519_fe_t * hc, fd_ed25519_fe_t const * fc, fd_ed25519_fe_t const * gc ) {
  wl_t f0; wl_t f1; wl_t f2; wl_t f3; wl_t f4; wl_t f5; wl_t f6; wl_t f7; wl_t f8; wl_t f9;
  wl_t g0; wl_t g1; wl_t g2; wl_t g3; wl_t g4; wl_t g5; wl_t g6; wl_t g7; wl_t g8; wl_t g9;
  PAIR_SWIZZLE_IN3( f0,f1,f2,f3,f4,f5,f6,f7,f8,f9, fa,fb,fc,
                    g0,g1,g2,g3,g4,g5,g6,g7,g8,g9, ga,gb,gc );
  MUL_AVX_CORE;
  SWIZZLE_OUT3( ha,hb,hc, h0,h1,h2,h3,h4,h5,h6,h7,h8,h9 );
}

void
fd_ed25519_fe_mul4( fd_ed25519_fe_t * ha, fd_ed25519_fe_t const * fa, fd_ed25519_fe_t const * ga,
                    fd_ed25519_fe_t * hb, fd_ed25519_fe_t const * fb, fd_ed25519_fe_t const * gb,
                    fd_ed25519_fe_t * hc, fd_ed25519_fe_t const * fc, fd_ed25519_fe_t const * gc,
                    fd_ed25519_fe_t * hd, fd_ed25519_fe_t const * fd, fd_ed25519_fe_t const * gd ) {
  wl_t f0; wl_t f1; wl_t f2; wl_t f3; wl_t f4; wl_t f5; wl_t f6; wl_t f7; wl_t f8; wl_t f9;
  wl_t g0; wl_t g1; wl_t g2; wl_t g3; wl_t g4; wl_t g5; wl_t g6; wl_t g7; wl_t g8; wl_t g9;
  PAIR_SWIZZLE_IN4( f0,f1,f2,f3,f4,f5,f6,f7,f8,f9, fa,fb,fc,fd,
                    g0,g1,g2,g3,g4,g5,g6,g7,g8,g9, ga,gb,gc,gd );
  MUL_AVX_CORE;
  SWIZZLE_OUT4( ha,hb,hc,hd, h0,h1,h2,h3,h4,h5,h6,h7,h8,h9 );
}

void
fd_ed25519_fe_sqn2( fd_ed25519_fe_t * ha, fd_ed25519_fe_t const * fa, long na,
                    fd_ed25519_fe_t * hb, fd_ed25519_fe_t const * fb, long nb ) {
  wl_t f0; wl_t f1; wl_t f2; wl_t f3; wl_t f4; wl_t f5; wl_t f6; wl_t f7; wl_t f8; wl_t f9;
  SWIZZLE_IN2( f0,f1,f2,f3,f4,f5,f6,f7,f8,f9, fa,fb );
  long nc = 1L; long nd = 1L; SQ_AVX_CORE;
  SWIZZLE_OUT2( ha,hb, h0,h1,h2,h3,h4,h5,h6,h7,h8,h9 );
}

void
fd_ed25519_fe_sqn3( fd_ed25519_fe_t * ha, fd_ed25519_fe_t const * fa, long na,
                    fd_ed25519_fe_t * hb, fd_ed25519_fe_t const * fb, long nb,
                    fd_ed25519_fe_t * hc, fd_ed25519_fe_t const * fc, long nc ) {
  wl_t f0; wl_t f1; wl_t f2; wl_t f3; wl_t f4; wl_t f5; wl_t f6; wl_t f7; wl_t f8; wl_t f9;
  SWIZZLE_IN3( f0,f1,f2,f3,f4,f5,f6,f7,f8,f9, fa,fb,fc );
  long nd = 1L; SQ_AVX_CORE;
  SWIZZLE_OUT3( ha,hb,hc, h0,h1,h2,h3,h4,h5,h6,h7,h8,h9 );
}

void
fd_ed25519_fe_sqn4( fd_ed25519_fe_t * ha, fd_ed25519_fe_t const * fa, long na,
                    fd_ed25519_fe_t * hb, fd_ed25519_fe_t const * fb, long nb,
                    fd_ed25519_fe_t * hc, fd_ed25519_fe_t const * fc, long nc,
                    fd_ed25519_fe_t * hd, fd_ed25519_fe_t const * fd, long nd ) {
  wl_t f0; wl_t f1; wl_t f2; wl_t f3; wl_t f4; wl_t f5; wl_t f6; wl_t f7; wl_t f8; wl_t f9;
  SWIZZLE_IN4( f0,f1,f2,f3,f4,f5,f6,f7,f8,f9, fa,fb,fc,fd );
  SQ_AVX_CORE;
  SWIZZLE_OUT4( ha,hb,hc,hd, h0,h1,h2,h3,h4,h5,h6,h7,h8,h9 );
}

static void
fd_ed25519_fe_sqn2_loop( fd_ed25519_fe_t * ha, long na,
                         fd_ed25519_fe_t * hb, long nb, long N ) {

  wl_t f0; wl_t f1; wl_t f2; wl_t f3; wl_t f4; wl_t f5; wl_t f6; wl_t f7; wl_t f8; wl_t f9;
  long nc = 1L; long nd = 1L;
  SWIZZLE_IN2( f0,f1,f2,f3,f4,f5,f6,f7,f8,f9, ha,hb );
  for (long l_i=0; l_i<N; l_i++) { SQ_AVX_CORE_LOOP; }
  SWIZZLE_OUT2( ha,hb, f0,f1,f2,f3,f4,f5,f6,f7,f8,f9 );
}

void
fd_ed25519_fe_pow22523_2( fd_ed25519_fe_t *       out0,
                          fd_ed25519_fe_t *       out1,
                          fd_ed25519_fe_t const * z0,
                          fd_ed25519_fe_t const * z1 ) {
  fd_ed25519_fe_t t0_0[1]; fd_ed25519_fe_t t0_1[1];
  fd_ed25519_fe_t t1_0[1]; fd_ed25519_fe_t t1_1[1];
  fd_ed25519_fe_t t2_0[1]; fd_ed25519_fe_t t2_1[1];

  fd_ed25519_fe_sqn2     ( t0_0,   z0, 1,
                           t0_1,   z1, 1     );
  fd_ed25519_fe_sqn2     ( t1_0, t0_0, 1,
                           t1_1, t0_1, 1     );
  fd_ed25519_fe_sqn2     ( t1_0, t1_0, 1,
                           t1_1, t1_1, 1     );

  fd_ed25519_fe_mul2     ( t1_0, z0,   t1_0,
                           t1_1, z1,   t1_1  );
  fd_ed25519_fe_mul2     ( t0_0, t0_0, t1_0,
                           t0_1, t0_1, t1_1  );
  fd_ed25519_fe_sqn2     ( t0_0, t0_0, 1,
                           t0_1, t0_1, 1     );
  fd_ed25519_fe_mul2     ( t0_0, t1_0, t0_0,
                           t0_1, t1_1, t0_1  );
  fd_ed25519_fe_sqn2     ( t1_0, t0_0, 1,
                           t1_1, t0_1, 1     );
  fd_ed25519_fe_sqn2_loop( t1_0, 1,
                           t1_1, 1, 4        );

  fd_ed25519_fe_mul2     ( t0_0, t1_0, t0_0,
                           t0_1, t1_1, t0_1  );
  fd_ed25519_fe_sqn2     ( t1_0, t0_0, 1,
                           t1_1, t0_1, 1     );
  fd_ed25519_fe_sqn2_loop( t1_0, 1,
                           t1_1, 1, 9        );

  fd_ed25519_fe_mul2     ( t1_0, t1_0, t0_0,
                           t1_1, t1_1, t0_1  );
  fd_ed25519_fe_sqn2     ( t2_0, t1_0, 1,
                           t2_1, t1_1, 1     );
  fd_ed25519_fe_sqn2_loop( t2_0, 1,
                           t2_1, 1, 19       );

  fd_ed25519_fe_mul2     ( t1_0, t2_0, t1_0,
                           t1_1, t2_1, t1_1  );
  fd_ed25519_fe_sqn2     ( t1_0, t1_0, 1,
                           t1_1, t1_1, 1     );
  fd_ed25519_fe_sqn2_loop( t1_0, 1,
                           t1_1, 1, 9        );

  fd_ed25519_fe_mul2     ( t0_0, t1_0, t0_0,
                           t0_1, t1_1, t0_1  );
  fd_ed25519_fe_sqn2     ( t1_0, t0_0, 1,
                           t1_1, t0_1, 1     );
  fd_ed25519_fe_sqn2_loop( t1_0, 1,
                           t1_1, 1, 49       );

  fd_ed25519_fe_mul2     ( t1_0, t1_0, t0_0,
                           t1_1, t1_1, t0_1  );
  fd_ed25519_fe_sqn2     ( t2_0, t1_0, 1,
                           t2_1, t1_1, 1     );

  fd_ed25519_fe_sqn2_loop( t2_0, 1,
                           t2_1, 1, 99       );

  fd_ed25519_fe_mul2     ( t1_0, t2_0, t1_0,
                           t1_1, t2_1, t1_1  );
  fd_ed25519_fe_sqn2     ( t1_0, t1_0, 1,
                           t1_1, t1_1, 1     );
  fd_ed25519_fe_sqn2_loop( t1_0, 1,
                           t1_1, 1, 49       );

  fd_ed25519_fe_mul2     ( t0_0, t1_0, t0_0,
                           t0_1, t1_1, t0_1  );
  fd_ed25519_fe_sqn2     ( t0_0, t0_0, 1,
                           t0_1, t0_1, 1     );
  fd_ed25519_fe_sqn2     ( t0_0, t0_0, 1,
                           t0_1, t0_1, 1     );

  fd_ed25519_fe_mul2     ( out0, t0_0, z0,
                           out1, t0_1, z1    );
}
