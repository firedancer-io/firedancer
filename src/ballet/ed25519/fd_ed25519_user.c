#include "fd_ed25519_private.h"

uchar *
fd_ed25519_sc_reduce( uchar *       out, 
                      uchar const * in ) {

  /* Load the 512 bits to reduce */

  ulong in0 = fd_ulong_load_8_fast( in      );
  ulong in1 = fd_ulong_load_8_fast( in +  8 );
  ulong in2 = fd_ulong_load_8_fast( in + 16 );
  ulong in3 = fd_ulong_load_8_fast( in + 24 );
  ulong in4 = fd_ulong_load_8_fast( in + 32 );
  ulong in5 = fd_ulong_load_8_fast( in + 40 );
  ulong in6 = fd_ulong_load_8_fast( in + 48 );
  ulong in7 = fd_ulong_load_8_fast( in + 56 );

  /* Unpack into 23 21-bit integers and a 29-bit straggler */

  ulong mask = FD_ULONG_MASK_LSB( 21 );

  long s0  = (long)(              in0      & mask); long s1  = (long)((in0>>21) & mask); long s2  = (long)((in0>>42) & mask);
  long s3  = (long)(((in0>>63) | (in1<<1)) & mask); long s4  = (long)((in1>>20) & mask); long s5  = (long)((in1>>41) & mask);
  long s6  = (long)(((in1>>62) | (in2<<2)) & mask); long s7  = (long)((in2>>19) & mask); long s8  = (long)((in2>>40) & mask);
  long s9  = (long)(((in2>>61) | (in3<<3)) & mask); long s10 = (long)((in3>>18) & mask); long s11 = (long)((in3>>39) & mask);
  long s12 = (long)(((in3>>60) | (in4<<4)) & mask); long s13 = (long)((in4>>17) & mask); long s14 = (long)((in4>>38) & mask);
  long s15 = (long)(((in4>>59) | (in5<<5)) & mask); long s16 = (long)((in5>>16) & mask); long s17 = (long)((in5>>37) & mask);
  long s18 = (long)(((in5>>58) | (in6<<6)) & mask); long s19 = (long)((in6>>15) & mask); long s20 = (long)((in6>>36) & mask);
  long s21 = (long)(((in6>>57) | (in7<<7)) & mask); long s22 = (long)((in7>>14) & mask); long s23 = (long)( in7>>35        );

  /* Do the reduction */

  s11 += s23*666643L; s12 += s23*470296L; s13 += s23*654183L; s14 -= s23*997805L; s15 += s23*136657L; s16 -= s23*683901L; s23 = 0L;
  s10 += s22*666643L; s11 += s22*470296L; s12 += s22*654183L; s13 -= s22*997805L; s14 += s22*136657L; s15 -= s22*683901L; s22 = 0L;
  s9  += s21*666643L; s10 += s21*470296L; s11 += s21*654183L; s12 -= s21*997805L; s13 += s21*136657L; s14 -= s21*683901L; s21 = 0L;
  s8  += s20*666643L; s9  += s20*470296L; s10 += s20*654183L; s11 -= s20*997805L; s12 += s20*136657L; s13 -= s20*683901L; s20 = 0L;
  s7  += s19*666643L; s8  += s19*470296L; s9  += s19*654183L; s10 -= s19*997805L; s11 += s19*136657L; s12 -= s19*683901L; s19 = 0L;
  s6  += s18*666643L; s7  += s18*470296L; s8  += s18*654183L; s9  -= s18*997805L; s10 += s18*136657L; s11 -= s18*683901L; s18 = 0L;

  long carry6  = (s6  + (1L << 20)) >> 21; s7  += carry6;  s6  -= (long)((ulong)carry6  << 21);
  long carry8  = (s8  + (1L << 20)) >> 21; s9  += carry8;  s8  -= (long)((ulong)carry8  << 21);
  long carry10 = (s10 + (1L << 20)) >> 21; s11 += carry10; s10 -= (long)((ulong)carry10 << 21);
  long carry12 = (s12 + (1L << 20)) >> 21; s13 += carry12; s12 -= (long)((ulong)carry12 << 21);
  long carry14 = (s14 + (1L << 20)) >> 21; s15 += carry14; s14 -= (long)((ulong)carry14 << 21);
  long carry16 = (s16 + (1L << 20)) >> 21; s17 += carry16; s16 -= (long)((ulong)carry16 << 21);

  long carry7  = (s7  + (1L << 20)) >> 21; s8  += carry7;  s7  -= (long)((ulong)carry7  << 21);
  long carry9  = (s9  + (1L << 20)) >> 21; s10 += carry9;  s9  -= (long)((ulong)carry9  << 21);
  long carry11 = (s11 + (1L << 20)) >> 21; s12 += carry11; s11 -= (long)((ulong)carry11 << 21);
  long carry13 = (s13 + (1L << 20)) >> 21; s14 += carry13; s13 -= (long)((ulong)carry13 << 21);
  long carry15 = (s15 + (1L << 20)) >> 21; s16 += carry15; s15 -= (long)((ulong)carry15 << 21);

  s5  += s17*666643L; s6  += s17*470296L; s7  += s17*654183L; s8  -= s17*997805L; s9  += s17*136657L; s10 -= s17*683901L; s17 = 0L;
  s4  += s16*666643L; s5  += s16*470296L; s6  += s16*654183L; s7  -= s16*997805L; s8  += s16*136657L; s9  -= s16*683901L; s16 = 0L;
  s3  += s15*666643L; s4  += s15*470296L; s5  += s15*654183L; s6  -= s15*997805L; s7  += s15*136657L; s8  -= s15*683901L; s15 = 0L;
  s2  += s14*666643L; s3  += s14*470296L; s4  += s14*654183L; s5  -= s14*997805L; s6  += s14*136657L; s7  -= s14*683901L; s14 = 0L;
  s1  += s13*666643L; s2  += s13*470296L; s3  += s13*654183L; s4  -= s13*997805L; s5  += s13*136657L; s6  -= s13*683901L; s13 = 0L;
  s0  += s12*666643L; s1  += s12*470296L; s2  += s12*654183L; s3  -= s12*997805L; s4  += s12*136657L; s5  -= s12*683901L; s12 = 0L;

  long carry0  = (s0  + (1L << 20)) >> 21; s1  += carry0;  s0  -= (long)((ulong)carry0  << 21);
  long carry2  = (s2  + (1L << 20)) >> 21; s3  += carry2;  s2  -= (long)((ulong)carry2  << 21);
  long carry4  = (s4  + (1L << 20)) >> 21; s5  += carry4;  s4  -= (long)((ulong)carry4  << 21);
  /**/ carry6  = (s6  + (1L << 20)) >> 21; s7  += carry6;  s6  -= (long)((ulong)carry6  << 21);
  /**/ carry8  = (s8  + (1L << 20)) >> 21; s9  += carry8;  s8  -= (long)((ulong)carry8  << 21);
  /**/ carry10 = (s10 + (1L << 20)) >> 21; s11 += carry10; s10 -= (long)((ulong)carry10 << 21);

  long carry1  = (s1  + (1L << 20)) >> 21; s2  += carry1;  s1  -= (long)((ulong)carry1  << 21);
  long carry3  = (s3  + (1L << 20)) >> 21; s4  += carry3;  s3  -= (long)((ulong)carry3  << 21);
  long carry5  = (s5  + (1L << 20)) >> 21; s6  += carry5;  s5  -= (long)((ulong)carry5  << 21);
  /**/ carry7  = (s7  + (1L << 20)) >> 21; s8  += carry7;  s7  -= (long)((ulong)carry7  << 21);
  /**/ carry9  = (s9  + (1L << 20)) >> 21; s10 += carry9;  s9  -= (long)((ulong)carry9  << 21);
  /**/ carry11 = (s11 + (1L << 20)) >> 21; s12 += carry11; s11 -= (long)((ulong)carry11 << 21);

  s0  += s12*666643L; s1  += s12*470296L; s2  += s12*654183L; s3  -= s12*997805L; s4  += s12*136657L; s5  -= s12*683901L; s12 = 0L;

  carry0  = s0  >> 21; s1  += carry0;  s0  -= (long)((ulong)carry0  << 21);
  carry1  = s1  >> 21; s2  += carry1;  s1  -= (long)((ulong)carry1  << 21);
  carry2  = s2  >> 21; s3  += carry2;  s2  -= (long)((ulong)carry2  << 21);
  carry3  = s3  >> 21; s4  += carry3;  s3  -= (long)((ulong)carry3  << 21);
  carry4  = s4  >> 21; s5  += carry4;  s4  -= (long)((ulong)carry4  << 21);
  carry5  = s5  >> 21; s6  += carry5;  s5  -= (long)((ulong)carry5  << 21);
  carry6  = s6  >> 21; s7  += carry6;  s6  -= (long)((ulong)carry6  << 21);
  carry7  = s7  >> 21; s8  += carry7;  s7  -= (long)((ulong)carry7  << 21);
  carry8  = s8  >> 21; s9  += carry8;  s8  -= (long)((ulong)carry8  << 21);
  carry9  = s9  >> 21; s10 += carry9;  s9  -= (long)((ulong)carry9  << 21);
  carry10 = s10 >> 21; s11 += carry10; s10 -= (long)((ulong)carry10 << 21);
  carry11 = s11 >> 21; s12 += carry11; s11 -= (long)((ulong)carry11 << 21);

  s0  += s12*666643L; s1  += s12*470296L; s2  += s12*654183L; s3  -= s12*997805L; s4  += s12*136657L; s5  -= s12*683901L; s12 = 0L;

  carry0  = s0  >> 21; s1  += carry0;  s0  -= (long)((ulong)carry0  << 21);
  carry1  = s1  >> 21; s2  += carry1;  s1  -= (long)((ulong)carry1  << 21);
  carry2  = s2  >> 21; s3  += carry2;  s2  -= (long)((ulong)carry2  << 21);
  carry3  = s3  >> 21; s4  += carry3;  s3  -= (long)((ulong)carry3  << 21);
  carry4  = s4  >> 21; s5  += carry4;  s4  -= (long)((ulong)carry4  << 21);
  carry5  = s5  >> 21; s6  += carry5;  s5  -= (long)((ulong)carry5  << 21);
  carry6  = s6  >> 21; s7  += carry6;  s6  -= (long)((ulong)carry6  << 21);
  carry7  = s7  >> 21; s8  += carry7;  s7  -= (long)((ulong)carry7  << 21);
  carry8  = s8  >> 21; s9  += carry8;  s8  -= (long)((ulong)carry8  << 21);
  carry9  = s9  >> 21; s10 += carry9;  s9  -= (long)((ulong)carry9  << 21);
  carry10 = s10 >> 21; s11 += carry10; s10 -= (long)((ulong)carry10 << 21);

  /* Pack the results into out */

  *(ulong *) out     = (((ulong)s0 )   ) | (((ulong)s1 )<<21) | (((ulong)s2 )<<42) | (((ulong)s3 )<<63);
  *(ulong *)(out+ 8) = (((ulong)s3 )>>1) | (((ulong)s4 )<<20) | (((ulong)s5 )<<41) | (((ulong)s6 )<<62);
  *(ulong *)(out+16) = (((ulong)s6 )>>2) | (((ulong)s7 )<<19) | (((ulong)s8 )<<40) | (((ulong)s9 )<<61);
  *(ulong *)(out+24) = (((ulong)s9 )>>3) | (((ulong)s10)<<18) | (((ulong)s11)<<39);
  return out;
}

uchar *
fd_ed25519_sc_muladd( uchar *       s,
                      uchar const * a,
                      uchar const * b,
                      uchar const * c ) {

  /* Load a, b and c */

  ulong ia0 = fd_ulong_load_8( a      ); ulong ib0 = fd_ulong_load_8( b      ); ulong ic0 = fd_ulong_load_8( c      );
  ulong ia1 = fd_ulong_load_8( a +  8 ); ulong ib1 = fd_ulong_load_8( b +  8 ); ulong ic1 = fd_ulong_load_8( c +  8 );
  ulong ia2 = fd_ulong_load_8( a + 16 ); ulong ib2 = fd_ulong_load_8( b + 16 ); ulong ic2 = fd_ulong_load_8( c + 16 );
  ulong ia3 = fd_ulong_load_8( a + 24 ); ulong ib3 = fd_ulong_load_8( b + 24 ); ulong ic3 = fd_ulong_load_8( c + 24 );

  /* Unpack each into 11 21-bit integers and a 25-bit straggler */

  ulong mask = FD_ULONG_MASK_LSB( 21 );

  long a0  = (long)(              ia0      & mask); long a1  = (long)((ia0>>21) & mask); long a2  = (long)((ia0>>42) & mask);
  long a3  = (long)(((ia0>>63) | (ia1<<1)) & mask); long a4  = (long)((ia1>>20) & mask); long a5  = (long)((ia1>>41) & mask);
  long a6  = (long)(((ia1>>62) | (ia2<<2)) & mask); long a7  = (long)((ia2>>19) & mask); long a8  = (long)((ia2>>40) & mask);
  long a9  = (long)(((ia2>>61) | (ia3<<3)) & mask); long a10 = (long)((ia3>>18) & mask); long a11 = (long)( ia3>>39        );

  long b0  = (long)(              ib0      & mask); long b1  = (long)((ib0>>21) & mask); long b2  = (long)((ib0>>42) & mask);
  long b3  = (long)(((ib0>>63) | (ib1<<1)) & mask); long b4  = (long)((ib1>>20) & mask); long b5  = (long)((ib1>>41) & mask);
  long b6  = (long)(((ib1>>62) | (ib2<<2)) & mask); long b7  = (long)((ib2>>19) & mask); long b8  = (long)((ib2>>40) & mask);
  long b9  = (long)(((ib2>>61) | (ib3<<3)) & mask); long b10 = (long)((ib3>>18) & mask); long b11 = (long)( ib3>>39        );

  long c0  = (long)(              ic0      & mask); long c1  = (long)((ic0>>21) & mask); long c2  = (long)((ic0>>42) & mask);
  long c3  = (long)(((ic0>>63) | (ic1<<1)) & mask); long c4  = (long)((ic1>>20) & mask); long c5  = (long)((ic1>>41) & mask);
  long c6  = (long)(((ic1>>62) | (ic2<<2)) & mask); long c7  = (long)((ic2>>19) & mask); long c8  = (long)((ic2>>40) & mask);
  long c9  = (long)(((ic2>>61) | (ic3<<3)) & mask); long c10 = (long)((ic3>>18) & mask); long c11 = (long)( ic3>>39        );

  /* Do the muladd */

  long s0  = c0  +  a0*b0;
  long s1  = c1  +  a0*b1  +  a1*b0;
  long s2  = c2  +  a0*b2  +  a1*b1  +  a2*b0;
  long s3  = c3  +  a0*b3  +  a1*b2  +  a2*b1 +  a3*b0;
  long s4  = c4  +  a0*b4  +  a1*b3  +  a2*b2 +  a3*b1 +  a4*b0;
  long s5  = c5  +  a0*b5  +  a1*b4  +  a2*b3 +  a3*b2 +  a4*b1 +  a5*b0;
  long s6  = c6  +  a0*b6  +  a1*b5  +  a2*b4 +  a3*b3 +  a4*b2 +  a5*b1 +  a6*b0;
  long s7  = c7  +  a0*b7  +  a1*b6  +  a2*b5 +  a3*b4 +  a4*b3 +  a5*b2 +  a6*b1 +  a7*b0;
  long s8  = c8  +  a0*b8  +  a1*b7  +  a2*b6 +  a3*b5 +  a4*b4 +  a5*b3 +  a6*b2 +  a7*b1 +  a8*b0;
  long s9  = c9  +  a0*b9  +  a1*b8  +  a2*b7 +  a3*b6 +  a4*b5 +  a5*b4 +  a6*b3 +  a7*b2 +  a8*b1 +  a9*b0;
  long s10 = c10 +  a0*b10 +  a1*b9  +  a2*b8 +  a3*b7 +  a4*b6 +  a5*b5 +  a6*b4 +  a7*b3 +  a8*b2 +  a9*b1 + a10*b0;
  long s11 = c11 +  a0*b11 +  a1*b10 +  a2*b9 +  a3*b8 +  a4*b7 +  a5*b6 +  a6*b5 +  a7*b4 +  a8*b3 +  a9*b2 + a10*b1 + a11*b0;
  long s12 =        a1*b11 +  a2*b10 +  a3*b9 +  a4*b8 +  a5*b7 +  a6*b6 +  a7*b5 +  a8*b4 +  a9*b3 + a10*b2 + a11*b1;
  long s13 =        a2*b11 +  a3*b10 +  a4*b9 +  a5*b8 +  a6*b7 +  a7*b6 +  a8*b5 +  a9*b4 + a10*b3 + a11*b2;
  long s14 =        a3*b11 +  a4*b10 +  a5*b9 +  a6*b8 +  a7*b7 +  a8*b6 +  a9*b5 + a10*b4 + a11*b3;
  long s15 =        a4*b11 +  a5*b10 +  a6*b9 +  a7*b8 +  a8*b7 +  a9*b6 + a10*b5 + a11*b4;
  long s16 =        a5*b11 +  a6*b10 +  a7*b9 +  a8*b8 +  a9*b7 + a10*b6 + a11*b5;
  long s17 =        a6*b11 +  a7*b10 +  a8*b9 +  a9*b8 + a10*b7 + a11*b6;
  long s18 =        a7*b11 +  a8*b10 +  a9*b9 + a10*b8 + a11*b7;
  long s19 =        a8*b11 +  a9*b10 + a10*b9 + a11*b8;
  long s20 =        a9*b11 + a10*b10 + a11*b9;
  long s21 =       a10*b11 + a11*b10;
  long s22 =       a11*b11;
  long s23 = 0L;

  /* Reduce the result */

  long carry0  = (s0  + (1L << 20)) >> 21; s1  += carry0;  s0  -= (long)((ulong)carry0  << 21);
  long carry2  = (s2  + (1L << 20)) >> 21; s3  += carry2;  s2  -= (long)((ulong)carry2  << 21);
  long carry4  = (s4  + (1L << 20)) >> 21; s5  += carry4;  s4  -= (long)((ulong)carry4  << 21);
  long carry6  = (s6  + (1L << 20)) >> 21; s7  += carry6;  s6  -= (long)((ulong)carry6  << 21);
  long carry8  = (s8  + (1L << 20)) >> 21; s9  += carry8;  s8  -= (long)((ulong)carry8  << 21);
  long carry10 = (s10 + (1L << 20)) >> 21; s11 += carry10; s10 -= (long)((ulong)carry10 << 21);
  long carry12 = (s12 + (1L << 20)) >> 21; s13 += carry12; s12 -= (long)((ulong)carry12 << 21);
  long carry14 = (s14 + (1L << 20)) >> 21; s15 += carry14; s14 -= (long)((ulong)carry14 << 21);
  long carry16 = (s16 + (1L << 20)) >> 21; s17 += carry16; s16 -= (long)((ulong)carry16 << 21);
  long carry18 = (s18 + (1L << 20)) >> 21; s19 += carry18; s18 -= (long)((ulong)carry18 << 21);
  long carry20 = (s20 + (1L << 20)) >> 21; s21 += carry20; s20 -= (long)((ulong)carry20 << 21);
  long carry22 = (s22 + (1L << 20)) >> 21; s23 += carry22; s22 -= (long)((ulong)carry22 << 21);

  long carry1  = (s1  + (1L << 20)) >> 21; s2  += carry1;  s1  -= (long)((ulong)carry1  << 21);
  long carry3  = (s3  + (1L << 20)) >> 21; s4  += carry3;  s3  -= (long)((ulong)carry3  << 21);
  long carry5  = (s5  + (1L << 20)) >> 21; s6  += carry5;  s5  -= (long)((ulong)carry5  << 21);
  long carry7  = (s7  + (1L << 20)) >> 21; s8  += carry7;  s7  -= (long)((ulong)carry7  << 21);
  long carry9  = (s9  + (1L << 20)) >> 21; s10 += carry9;  s9  -= (long)((ulong)carry9  << 21);
  long carry11 = (s11 + (1L << 20)) >> 21; s12 += carry11; s11 -= (long)((ulong)carry11 << 21);
  long carry13 = (s13 + (1L << 20)) >> 21; s14 += carry13; s13 -= (long)((ulong)carry13 << 21);
  long carry15 = (s15 + (1L << 20)) >> 21; s16 += carry15; s15 -= (long)((ulong)carry15 << 21);
  long carry17 = (s17 + (1L << 20)) >> 21; s18 += carry17; s17 -= (long)((ulong)carry17 << 21);
  long carry19 = (s19 + (1L << 20)) >> 21; s20 += carry19; s19 -= (long)((ulong)carry19 << 21);
  long carry21 = (s21 + (1L << 20)) >> 21; s22 += carry21; s21 -= (long)((ulong)carry21 << 21);

  s11 += s23*666643L; s12 += s23*470296L; s13 += s23*654183L; s14 -= s23*997805L; s15 += s23*136657L; s16 -= s23*683901L; s23 = 0L;
  s10 += s22*666643L; s11 += s22*470296L; s12 += s22*654183L; s13 -= s22*997805L; s14 += s22*136657L; s15 -= s22*683901L; s22 = 0L;
  s9  += s21*666643L; s10 += s21*470296L; s11 += s21*654183L; s12 -= s21*997805L; s13 += s21*136657L; s14 -= s21*683901L; s21 = 0L;
  s8  += s20*666643L; s9  += s20*470296L; s10 += s20*654183L; s11 -= s20*997805L; s12 += s20*136657L; s13 -= s20*683901L; s20 = 0L;
  s7  += s19*666643L; s8  += s19*470296L; s9  += s19*654183L; s10 -= s19*997805L; s11 += s19*136657L; s12 -= s19*683901L; s19 = 0L;
  s6  += s18*666643L; s7  += s18*470296L; s8  += s18*654183L; s9  -= s18*997805L; s10 += s18*136657L; s11 -= s18*683901L; s18 = 0L;

  carry6  = (s6  + (1L << 20)) >> 21; s7  += carry6;  s6  -= (long)((ulong)carry6  << 21);
  carry8  = (s8  + (1L << 20)) >> 21; s9  += carry8;  s8  -= (long)((ulong)carry8  << 21);
  carry10 = (s10 + (1L << 20)) >> 21; s11 += carry10; s10 -= (long)((ulong)carry10 << 21);
  carry12 = (s12 + (1L << 20)) >> 21; s13 += carry12; s12 -= (long)((ulong)carry12 << 21);
  carry14 = (s14 + (1L << 20)) >> 21; s15 += carry14; s14 -= (long)((ulong)carry14 << 21);
  carry16 = (s16 + (1L << 20)) >> 21; s17 += carry16; s16 -= (long)((ulong)carry16 << 21);

  carry7  = (s7  + (1L << 20)) >> 21; s8  += carry7;  s7  -= (long)((ulong)carry7  << 21);
  carry9  = (s9  + (1L << 20)) >> 21; s10 += carry9;  s9  -= (long)((ulong)carry9  << 21);
  carry11 = (s11 + (1L << 20)) >> 21; s12 += carry11; s11 -= (long)((ulong)carry11 << 21);
  carry13 = (s13 + (1L << 20)) >> 21; s14 += carry13; s13 -= (long)((ulong)carry13 << 21);
  carry15 = (s15 + (1L << 20)) >> 21; s16 += carry15; s15 -= (long)((ulong)carry15 << 21);

  s5  += s17*666643L; s6  += s17*470296L; s7  += s17*654183L; s8  -= s17*997805L; s9  += s17*136657L; s10 -= s17*683901L; s17 = 0L;
  s4  += s16*666643L; s5  += s16*470296L; s6  += s16*654183L; s7  -= s16*997805L; s8  += s16*136657L; s9  -= s16*683901L; s16 = 0L;
  s3  += s15*666643L; s4  += s15*470296L; s5  += s15*654183L; s6  -= s15*997805L; s7  += s15*136657L; s8  -= s15*683901L; s15 = 0L;
  s2  += s14*666643L; s3  += s14*470296L; s4  += s14*654183L; s5  -= s14*997805L; s6  += s14*136657L; s7  -= s14*683901L; s14 = 0L;
  s1  += s13*666643L; s2  += s13*470296L; s3  += s13*654183L; s4  -= s13*997805L; s5  += s13*136657L; s6  -= s13*683901L; s13 = 0L;
  s0  += s12*666643L; s1  += s12*470296L; s2  += s12*654183L; s3  -= s12*997805L; s4  += s12*136657L; s5  -= s12*683901L; s12 = 0L;

  carry0  = (s0  + (1L << 20)) >> 21; s1  += carry0;  s0  -= (long)((ulong)carry0  << 21);
  carry2  = (s2  + (1L << 20)) >> 21; s3  += carry2;  s2  -= (long)((ulong)carry2  << 21);
  carry4  = (s4  + (1L << 20)) >> 21; s5  += carry4;  s4  -= (long)((ulong)carry4  << 21);
  carry6  = (s6  + (1L << 20)) >> 21; s7  += carry6;  s6  -= (long)((ulong)carry6  << 21);
  carry8  = (s8  + (1L << 20)) >> 21; s9  += carry8;  s8  -= (long)((ulong)carry8  << 21);
  carry10 = (s10 + (1L << 20)) >> 21; s11 += carry10; s10 -= (long)((ulong)carry10 << 21);

  carry1  = (s1  + (1L << 20)) >> 21; s2  += carry1;  s1  -= (long)((ulong)carry1  << 21);
  carry3  = (s3  + (1L << 20)) >> 21; s4  += carry3;  s3  -= (long)((ulong)carry3  << 21);
  carry5  = (s5  + (1L << 20)) >> 21; s6  += carry5;  s5  -= (long)((ulong)carry5  << 21);
  carry7  = (s7  + (1L << 20)) >> 21; s8  += carry7;  s7  -= (long)((ulong)carry7  << 21);
  carry9  = (s9  + (1L << 20)) >> 21; s10 += carry9;  s9  -= (long)((ulong)carry9  << 21);
  carry11 = (s11 + (1L << 20)) >> 21; s12 += carry11; s11 -= (long)((ulong)carry11 << 21);

  s0  += s12*666643L; s1  += s12*470296L; s2  += s12*654183L; s3  -= s12*997805L; s4  += s12*136657L; s5  -= s12*683901L; s12 = 0L;

  carry0  = s0  >> 21; s1  += carry0;  s0  -= (long)((ulong)carry0  << 21);
  carry1  = s1  >> 21; s2  += carry1;  s1  -= (long)((ulong)carry1  << 21);
  carry2  = s2  >> 21; s3  += carry2;  s2  -= (long)((ulong)carry2  << 21);
  carry3  = s3  >> 21; s4  += carry3;  s3  -= (long)((ulong)carry3  << 21);
  carry4  = s4  >> 21; s5  += carry4;  s4  -= (long)((ulong)carry4  << 21);
  carry5  = s5  >> 21; s6  += carry5;  s5  -= (long)((ulong)carry5  << 21);
  carry6  = s6  >> 21; s7  += carry6;  s6  -= (long)((ulong)carry6  << 21);
  carry7  = s7  >> 21; s8  += carry7;  s7  -= (long)((ulong)carry7  << 21);
  carry8  = s8  >> 21; s9  += carry8;  s8  -= (long)((ulong)carry8  << 21);
  carry9  = s9  >> 21; s10 += carry9;  s9  -= (long)((ulong)carry9  << 21);
  carry10 = s10 >> 21; s11 += carry10; s10 -= (long)((ulong)carry10 << 21);
  carry11 = s11 >> 21; s12 += carry11; s11 -= (long)((ulong)carry11 << 21);

  s0  += s12*666643L; s1  += s12*470296L; s2  += s12*654183L; s3  -= s12*997805L; s4  += s12*136657L; s5  -= s12*683901L; s12 = 0L;

  carry0  = s0  >> 21; s1  += carry0;  s0  -= (long)((ulong)carry0  << 21);
  carry1  = s1  >> 21; s2  += carry1;  s1  -= (long)((ulong)carry1  << 21);
  carry2  = s2  >> 21; s3  += carry2;  s2  -= (long)((ulong)carry2  << 21);
  carry3  = s3  >> 21; s4  += carry3;  s3  -= (long)((ulong)carry3  << 21);
  carry4  = s4  >> 21; s5  += carry4;  s4  -= (long)((ulong)carry4  << 21);
  carry5  = s5  >> 21; s6  += carry5;  s5  -= (long)((ulong)carry5  << 21);
  carry6  = s6  >> 21; s7  += carry6;  s6  -= (long)((ulong)carry6  << 21);
  carry7  = s7  >> 21; s8  += carry7;  s7  -= (long)((ulong)carry7  << 21);
  carry8  = s8  >> 21; s9  += carry8;  s8  -= (long)((ulong)carry8  << 21);
  carry9  = s9  >> 21; s10 += carry9;  s9  -= (long)((ulong)carry9  << 21);
  carry10 = s10 >> 21; s11 += carry10; s10 -= (long)((ulong)carry10 << 21);

  /* Pack the results into s */

  *(ulong *) s     = (((ulong)s0 )   ) | (((ulong)s1 )<<21) | (((ulong)s2 )<<42) | (((ulong)s3 )<<63);
  *(ulong *)(s+ 8) = (((ulong)s3 )>>1) | (((ulong)s4 )<<20) | (((ulong)s5 )<<41) | (((ulong)s6 )<<62);
  *(ulong *)(s+16) = (((ulong)s6 )>>2) | (((ulong)s7 )<<19) | (((ulong)s8 )<<40) | (((ulong)s9 )<<61);
  *(ulong *)(s+24) = (((ulong)s9 )>>3) | (((ulong)s10)<<18) | (((ulong)s11)<<39);
  return s;
}

/**********************************************************************/

void *
fd_ed25519_public_from_private( void *        public_key,
                                void const *  private_key,
                                fd_sha512_t * sha ) {

  /* Hash the private key */

  uchar az[ 64 ];
  fd_sha512_fini( fd_sha512_append( fd_sha512_init( sha ), private_key, 32UL ), az );
  az[ 0] &= (uchar)248;
  az[31] &= (uchar)63;
  az[31] |= (uchar)64;
 
  /* Compute the corresponding public key from the hash */

  fd_ed25519_ge_p3_t A[1];
  fd_ed25519_ge_scalarmult_base( A, az );
  fd_ed25519_ge_p3_tobytes( public_key, A );

  /* Sanitize */

  fd_memset( az, 0, 64UL );
  fd_sha512_init( sha );

  return public_key;
}

void *
fd_ed25519_sign( void *        sig,
                 void const *  msg,
                 ulong         sz,
                 void const *  public_key,
                 void const *  private_key,
                 fd_sha512_t * sha ) {

  uchar az[ FD_SHA512_HASH_SZ ];
  fd_sha512_fini( fd_sha512_append( fd_sha512_init( sha ), private_key, 32UL ), az );
  az[ 0] &= (uchar)248;
  az[31] &= (uchar) 63;
  az[31] |= (uchar) 64;

  uchar nonce[ FD_SHA512_HASH_SZ ];
  fd_sha512_fini( fd_sha512_append( fd_sha512_append( fd_sha512_init( sha ), az + 32, 32UL ), msg, sz ), nonce );
  fd_ed25519_sc_reduce( nonce, nonce );

  fd_ed25519_ge_p3_t R[1];
  fd_ed25519_ge_scalarmult_base( R, nonce );
  fd_ed25519_ge_p3_tobytes( sig, R );

  uchar hram[ FD_SHA512_HASH_SZ ];
  fd_sha512_fini( fd_sha512_append( fd_sha512_append( fd_sha512_append( fd_sha512_init( sha ),
                  sig, 32UL ), public_key, 32UL ), msg, sz ), hram );

  fd_ed25519_sc_reduce( hram, hram );

  fd_ed25519_sc_muladd( ((uchar *)sig)+32, hram, az, nonce );

  /* Sanitize */

  fd_memset( nonce, 0, FD_SHA512_HASH_SZ );
  fd_memset( az,    0, FD_SHA512_HASH_SZ );
  fd_sha512_init( sha );

  return sig;
}

int
fd_ed25519_verify( void const *  msg,
                   ulong         sz,
                   void const *  sig,
                   void const *  public_key,
                   fd_sha512_t * sha ) {
  uchar const * r = (uchar const *)sig;
  uchar const * s = r + 32;

# ifndef FD_ED25519_VERIFY_USE_2POINT
# if FD_ED25519_FE_POW25523_2_FAST
# define FD_ED25519_VERIFY_USE_2POINT 1
# else
# define FD_ED25519_VERIFY_USE_2POINT 0
# endif
# endif

  /* Check 0 <= s < L where:

       L = 2^252 + 27742317777372353535851937790883648493

     If not the signature is publicly invalid.  Since it's public we can
     do the check in variable time.

     First check the most significant byte */
  /* FIXME: THIS COULD BE DONE 64-BIT AT A TIME FASTER */

  if( FD_UNLIKELY( s[31]> 0x10 ) ) return FD_ED25519_ERR_SIG;
  if( FD_UNLIKELY( s[31]==0x10 ) ) {

    /* Most significant byte indicates a value close to 2^252 so check
       the rest */

    static uchar const allzeroes[ 15 ];
    if( memcmp( s+16, allzeroes, 15UL )!=0 ) return 0;

    /* 27742317777372353535851937790883648493 in little endian format */
    static uchar const l_low[16] = {
      (uchar)0xED, (uchar)0xD3, (uchar)0xF5, (uchar)0x5C, (uchar)0x1A, (uchar)0x63, (uchar)0x12, (uchar)0x58,
      (uchar)0xD6, (uchar)0x9C, (uchar)0xF7, (uchar)0xA2, (uchar)0xDE, (uchar)0xF9, (uchar)0xDE, (uchar)0x14
    };

    int i;
    for( i=15; i>=0; i--) {
      if( FD_LIKELY(   s[i]<l_low[i] ) ) break;
      if( FD_UNLIKELY( s[i]>l_low[i] ) ) return FD_ED25519_ERR_SIG;
    }
    if( FD_UNLIKELY( i<0 ) ) return FD_ED25519_ERR_SIG;
  }

  fd_ed25519_ge_p3_t A[1];

# if FD_ED25519_VERIFY_USE_2POINT
  /* 2-point decompression - this approach avoids doing a compression
     (and hence an inversion) at the end */
  fd_ed25519_ge_p3_t rD[1];
  int err = fd_ed25519_ge_frombytes_vartime_2( A, public_key, rD, r ); if( FD_UNLIKELY( err ) ) return err;
  if( fd_ed25519_ge_p3_is_small_order(A) )  return FD_ED25519_ERR_PUBKEY;
  if( fd_ed25519_ge_p3_is_small_order(rD) ) return FD_ED25519_ERR_SIG;
# else
  int err = fd_ed25519_ge_frombytes_vartime( A, public_key ); if( FD_UNLIKELY( err ) ) return err;
# endif

  fd_ed25519_fe_neg( A->X, A->X );
  fd_ed25519_fe_neg( A->T, A->T );

  uchar h[ 64 ];
  fd_sha512_fini( fd_sha512_append( fd_sha512_append( fd_sha512_append( fd_sha512_init( sha ),
                  r, 32UL ), public_key, 32UL ), msg, sz ), h );
  fd_ed25519_sc_reduce( h, h );

  fd_ed25519_ge_p2_t R[1];
  fd_ed25519_ge_double_scalarmult_vartime( R, h, A, s );

# if FD_ED25519_VERIFY_USE_2POINT
  /* Comparison:
       r.x * R.Z == R.X
       r.y * R.Z == R.Y
     mod p*/

  uchar xcheck[32] __attribute__((aligned(32))); uchar ycheck[32] __attribute__((aligned(32)));
  fd_ed25519_fe_t dx[1];                         fd_ed25519_fe_t dy[1];
  fd_ed25519_fe_mul2( dx, R->Z, rD->X,           dy, R->Z, rD->Y );
  fd_ed25519_fe_sub( dx, dx, R->X );             fd_ed25519_fe_sub( dy, dy, R->Y );
  fd_ed25519_fe_tobytes( xcheck, dx );           fd_ed25519_fe_tobytes( ycheck, dy );

  uchar zcheck[32] __attribute__((aligned(32)));
  memset( zcheck, 0, 32UL );
  if( FD_UNLIKELY( (!!memcmp( xcheck, zcheck, 32UL )) | (!!memcmp( ycheck, zcheck, 32UL )) ) ) return FD_ED25519_ERR_MSG;

  return FD_ED25519_SUCCESS;
# else
  uchar rcheck[ 32 ];
  fd_ed25519_ge_tobytes( rcheck, R );
  return memcmp( rcheck, r, 32UL ) ? FD_ED25519_ERR_MSG : FD_ED25519_SUCCESS;
# endif
}

char const *
fd_ed25519_strerror( int err ) {
  switch( err ) {
  case FD_ED25519_SUCCESS:    return "success";
  case FD_ED25519_ERR_SIG:    return "bad signature";
  case FD_ED25519_ERR_PUBKEY: return "bad public key";
  case FD_ED25519_ERR_MSG:    return "bad message";
  default: break;
  }
  return "unknown";
}

