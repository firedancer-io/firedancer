#include "fd_bls_final.h"

#if FD_HAS_AVX512

#include "fd_bls_constants.h"

static void
fp12_conjugate_final( fd_bls_fp12_t *       out,
                      fd_bls_fp12_t const * in ) {
  /* Quadratic conjugation a+b*w -> a-b*w, equal to the p^6-Frobenius. */
  *out = *in;
  for( int i=6; i<12; i++ ) fd_bls_fp_neg( &out->c[i], &out->c[i] ); /* out=a-b*w=in^(p^6). */
}

/* Native inversion.  The old path converted twelve RNS elements to BLST,
   inverted there, and converted all twelve back.  Keep the whole tower in
   RNS instead: one fixed base-field addition chain plus ordinary Fp2/Fp6
   tower formulas. */

typedef struct { fd_bls_fp2_t c[3]; } fp6_final_t;

static inline void
fp_inverse_shift( fd_bls_fp_t *       out,
                  fd_bls_fp_t const * in,
                  uint                  bits ) {
  fd_bls_fp_t r = *in;                                      /* r=in=in^(2^0).              */
  for( uint i=0U; i<bits; i++ ) fd_bls_fp_sqr( &r, &r );    /* r<-r^2 doubles its exponent. */
  *out = r;                                                  /* out=in^(2^bits).             */
}

static void
fp_inverse_exp_x( fd_bls_fp_t *       out,
                  fd_bls_fp_t const * base ) {
  /* Write a=base and x=0xd201000000010000.  The variable names give the
     binary exponent assembled before the final two zero runs. */
  fd_bls_fp_t base10, base11, base1100, base1101, base1101000, base1101001;
  fd_bls_fp_t t0, t1;
  fd_bls_fp_sqr( &base10, base );                    /* base10      = a^2                                      */
  fd_bls_fp_mul( &base11, &base10, base );           /* base11      = a^3                                      */
  fp_inverse_shift( &base1100, &base11, 2U );        /* base1100    = a^(3*2^2)   = a^12                       */
  fd_bls_fp_mul( &base1101, &base1100, base );       /* base1101    = a^13                                     */
  fp_inverse_shift( &base1101000, &base1101, 3U );   /* base1101000 = a^(13*2^3)  = a^104                      */
  fd_bls_fp_mul( &base1101001, &base1101000, base ); /* base1101001 = a^105                                    */
  fp_inverse_shift( &t0, &base1101001, 9U );         /* t0          = a^(105*2^9) = a^53760                    */
  fd_bls_fp_mul( &t1, &t0, base );                   /* t1          = a^53761      = a^0xd201                   */
  fp_inverse_shift( &t0, &t1, 32U );                 /* t0          = a^(0xd201*2^32)                          */
  fd_bls_fp_mul( &t1, &t0, base );                   /* t1          = a^(0xd201*2^32+1)                        */
  fp_inverse_shift( out, &t1, 16U );                 /* out         = a^x                                     */
}

static void
fp_inverse_exp_x_m3( fd_bls_fp_t *       out,
                     fd_bls_fp_t const * base ) {
  /* Write a=base, h=0xd201, and E=h*2^36.  This assembles x-3 without
     inversion; the last four hexadecimal digits are 0xfffd. */
  fd_bls_fp_t base2, base3, base12, base13, base15, base104, base105;
  fd_bls_fp_t i610, i611, i612, i614, i61, r1, r2, r3, r4;
  fd_bls_fp_sqr( &base2, base );                  /* base2   = a^2                                             */
  fd_bls_fp_mul( &base3, &base2, base );          /* base3   = a^3                                             */
  fp_inverse_shift( &base12, &base3, 2U );        /* base12  = a^12                                            */
  fd_bls_fp_mul( &base13, &base12, base );        /* base13  = a^13                                            */
  fd_bls_fp_mul( &base15, &base13, &base2 );      /* base15  = a^15                                            */
  fp_inverse_shift( &base104, &base13, 3U );      /* base104 = a^104                                           */
  fd_bls_fp_mul( &base105, &base104, base );      /* base105 = a^105                                           */
  fp_inverse_shift( &i610, &base105, 9U );        /* i610    = a^(h-1)                                         */
  fd_bls_fp_mul( &i611, &i610, base );            /* i611    = a^h                                             */
  fp_inverse_shift( &i612, &i611, 36U );          /* i612    = a^E                                             */
  fd_bls_fp_mul( &i614, &i612, &base15 );         /* i614    = a^(E+15)                                        */
  fp_inverse_shift( &i61, &i614, 4U );            /* i61     = a^(16(E+15))                                    */
  fd_bls_fp_mul( &r1, &base15, &i61 );            /* r1      = a^(16(E+15)+15)                                 */
  fp_inverse_shift( &r2, &r1, 4U );               /* r2      = a^(16(16(E+15)+15))                             */
  fd_bls_fp_mul( &r3, &r2, &base15 );             /* r3      = a^(16(16(E+15)+15)+15)                          */
  fp_inverse_shift( &r4, &r3, 4U );               /* r4      = a^(16(16(16(E+15)+15)+15))                      */
  fd_bls_fp_mul( out, &r4, &base13 );             /* out     = a^(16(16(16(E+15)+15)+15)+13) = a^(x-3)        */
}

static void
fp_inverse_addchain_final( fd_bls_fp_t *       out,
                           fd_bls_fp_t const * base ) {
  /* For x=-z=0xd201000000010000 this chain raises to
     x^6+2x^5-2x^3-x-3 = 3p-4, which is -1 modulo p-1. */
  fd_bls_fp_t ax_m3, ax_m2, ax2_m2x, ax, ax2_mx, ax3_mx2;
  fd_bls_fp_t ax4_mx3, ax5_mx4, ax6_mx5, ax2_mx_m3, ax3_mx_m3;
  fd_bls_fp_t a3x4_m3x2, a3x4_m2x3_mx_m3, a3x5_m3x4;
  fd_bls_fp_t a3x5_m2x3_mx_m3, t0, t1;
  /* Here a=base; every suffix is the exponent of a. */
  fp_inverse_exp_x_m3( &ax_m3, base );                                      /* ax_m3                 = a^(x-3)                    */
  fd_bls_fp_mul( &ax_m2, &ax_m3, base );                                    /* ax_m2                 = a^(x-2)                    */
  fp_inverse_exp_x( &ax2_m2x, &ax_m2 );                                     /* ax2_m2x               = a^(x^2-2x)                 */
  fd_bls_fp_mul( &t0, &ax_m2, base );                                       /* t0                    = a^(x-1)                    */
  fd_bls_fp_mul( &ax, &t0, base );                                          /* ax                    = a^x                        */
  fd_bls_fp_mul( &ax2_mx, &ax2_m2x, &ax );                                 /* ax2_mx                = a^(x^2-x)                  */
  fp_inverse_exp_x( &ax3_mx2, &ax2_mx );                                    /* ax3_mx2               = a^(x^3-x^2)                */
  fp_inverse_exp_x( &ax4_mx3, &ax3_mx2 );                                   /* ax4_mx3               = a^(x^4-x^3)                */
  fp_inverse_exp_x( &ax5_mx4, &ax4_mx3 );                                   /* ax5_mx4               = a^(x^5-x^4)                */
  fp_inverse_exp_x( &ax6_mx5, &ax5_mx4 );                                   /* ax6_mx5               = a^(x^6-x^5)                */
  fd_bls_fp_mul( &ax2_mx_m3, &ax2_m2x, &ax_m3 );                            /* ax2_mx_m3             = a^(x^2-x-3)                */
  fd_bls_fp_mul( &ax3_mx_m3, &ax2_mx_m3, &ax3_mx2 );                        /* ax3_mx_m3             = a^(x^3-x-3)                */
  fd_bls_fp_sqr( &t0, &ax4_mx3 );                                          /* t0                    = a^(2x^4-2x^3)              */
  fd_bls_fp_mul( &a3x4_m3x2, &t0, &ax4_mx3 );                              /* a3x4_m3x2             = a^(3x^4-3x^3)              */
  fd_bls_fp_mul( &a3x4_m2x3_mx_m3, &a3x4_m3x2, &ax3_mx_m3 );               /* a3x4_m2x3_mx_m3      = a^(3x^4-2x^3-x-3)          */
  fd_bls_fp_sqr( &t0, &ax5_mx4 );                                          /* t0                    = a^(2x^5-2x^4)              */
  fd_bls_fp_mul( &a3x5_m3x4, &t0, &ax5_mx4 );                              /* a3x5_m3x4             = a^(3x^5-3x^4)              */
  fd_bls_fp_mul( &a3x5_m2x3_mx_m3, &a3x5_m3x4, &a3x4_m2x3_mx_m3 );         /* a3x5_m2x3_mx_m3      = a^(3x^5-2x^3-x-3)          */
  fd_bls_fp_mul( &t1, &ax6_mx5, &a3x5_m2x3_mx_m3 );                        /* t1                    = a^(x^6+2x^5-2x^3-x-3)     */
  *out = t1;                                                                /* out                   = a^(3p-4) = a^(-1 mod p-1) */
}

static inline int
uint384_is_zero_final( ulong const a[6] ) {
  return !(a[0] | a[1] | a[2] | a[3] | a[4] | a[5]);
}

static inline int
uint384_is_one_final( ulong const a[6] ) {
  return a[0]==1UL && !(a[1] | a[2] | a[3] | a[4] | a[5]);
}

static inline int
uint384_ge_final( ulong const a[6],
                  ulong const b[6] ) {
  for( int i=5; i>=0; i-- ) {
    if( a[i]>b[i] ) return 1;
    if( a[i]<b[i] ) return 0;
  }
  return 1;
}

static inline void
uint384_sub_final( ulong       a[6],
                   ulong const b[6] ) {
  ulong borrow = 0UL;
  for( int i=0; i<6; i++ ) {
    ulong bi = b[i] + borrow;
    ulong carry = bi<b[i];
    ulong ai = a[i];
    a[i] = ai-bi;
    borrow = carry | (ai<bi);
  }
}

static inline void
uint384_rshift_final( ulong a[6] ) {
  ulong carry = 0UL;
  for( int i=5; i>=0; i-- ) {
    ulong next = a[i] & 1UL;
    a[i] = (a[i]>>1) | (carry<<63);
    carry = next;
  }
}

static inline void
uint384_add_modulus_final( ulong a[6] ) {
  static ulong const p[6] = {
    0xb9feffffffffaaabUL, 0x1eabfffeb153ffffUL,
    0x6730d2a0f6b0f624UL, 0x64774b84f38512bfUL,
    0x4b1ba7b6434bacd7UL, 0x1a0111ea397fe69aUL
  };
  ulong carry = 0UL;
  for( int i=0; i<6; i++ ) {
    uint128 sum = (uint128)a[i] + (uint128)p[i] + (uint128)carry;
    a[i] = (ulong)sum;
    carry = (ulong)(sum>>64);
  }
}

static inline void
uint384_half_mod_final( ulong a[6] ) {
  if( a[0]&1UL ) uint384_add_modulus_final( a );
  uint384_rshift_final( a );
}

static inline void
uint384_sub_mod_final( ulong       a[6],
                       ulong const b[6] ) {
  if( !uint384_ge_final( a, b ) ) uint384_add_modulus_final( a );
  uint384_sub_final( a, b );
}

/* Public pairing inputs are not secret.  A variable-time binary extended
   GCD is substantially cheaper here than 425 RNS multiplications, while the
   fixed addition chain remains as a defensive fallback. */
static void
fp_inverse_final( fd_bls_fp_t *       out,
                  fd_bls_fp_t const * base ) {
  static ulong const p[6] = {
    0xb9feffffffffaaabUL, 0x1eabfffeb153ffffUL,
    0x6730d2a0f6b0f624UL, 0x64774b84f38512bfUL,
    0x4b1ba7b6434bacd7UL, 0x1a0111ea397fe69aUL
  };
  ulong u[6], v[6], x1[6] = {1UL}, x2[6] = {0UL};
  fd_bls_fp_to_uint64( u, base );              /* u=a, x1=1, so u=a*x1 (mod p). */
  for( int i=0; i<6; i++ ) v[i] = p[i];       /* v=p, x2=0, so v=a*x2 (mod p). */
  if( FD_UNLIKELY( uint384_is_zero_final( u ) ) ) {
    fd_bls_fp_zero( out );
    return;
  }

  for( uint steps=0U; steps<4096U; steps++ ) {
    if( uint384_is_one_final( u ) ) { fd_bls_fp_from_uint64( out, x1 ); return; }
    if( uint384_is_one_final( v ) ) { fd_bls_fp_from_uint64( out, x2 ); return; }
    while( !(u[0]&1UL) ) { uint384_rshift_final( u ); uint384_half_mod_final( x1 ); } /* (u,x1) <- (u/2,x1/2 mod p). */
    while( !(v[0]&1UL) ) { uint384_rshift_final( v ); uint384_half_mod_final( x2 ); } /* (v,x2) <- (v/2,x2/2 mod p). */
    if( uint384_ge_final( u, v ) ) {
      uint384_sub_final( u, v );               /* u  <- u-v.             */
      uint384_sub_mod_final( x1, x2 );         /* x1 <- x1-x2 mod p; invariant u=a*x1 remains. */
    } else {
      uint384_sub_final( v, u );               /* v  <- v-u.             */
      uint384_sub_mod_final( x2, x1 );         /* x2 <- x2-x1 mod p; invariant v=a*x2 remains. */
    }
  }
  fp_inverse_addchain_final( out, base );
}

static inline void
fp2_mul_nonres_final( fd_bls_fp2_t *       out,
                      fd_bls_fp2_t const * in ) {
  fd_bls_fp_t a = in->c[0], b = in->c[1];
  fd_bls_fp_sub( &out->c[0], &a, &b ); /* Re((1+u)(a+bu)) = a-b, since u^2=-1. */
  fd_bls_fp_add( &out->c[1], &a, &b ); /* Im((1+u)(a+bu)) = a+b.                 */
}

static void
fp2_inverse_final( fd_bls_fp2_t *       out,
                   fd_bls_fp2_t const * in ) {
  /* (a+b*u)^-1=(a-b*u)/(a^2+b^2), since u^2=-1. */
  fd_bls_fp_t aa, bb, norm, norm_inv;
  fd_bls_fp_sqr( &aa, &in->c[0] );                       /* aa      = a^2.                 */
  fd_bls_fp_sqr( &bb, &in->c[1] );                       /* bb      = b^2.                 */
  fd_bls_fp_add( &norm, &aa, &bb );                      /* norm    = a^2+b^2.             */
  fp_inverse_final( &norm_inv, &norm );                   /* normInv = 1/(a^2+b^2).         */
  fd_bls_fp_mul( &out->c[0], &in->c[0], &norm_inv );     /* out.re  = a/(a^2+b^2).         */
  fd_bls_fp_mul( &out->c[1], &in->c[1], &norm_inv );     /* out.im  = b/(a^2+b^2).         */
  fd_bls_fp_neg( &out->c[1], &out->c[1] );               /* out     = (a-bu)/(a^2+b^2).    */
}

static void
fp6_mul_final( fp6_final_t *       out,
               fp6_final_t const * a,
               fp6_final_t const * b ) {
  /* In Fp2[v]/(v^3-xi), xi=1+u.  First form every a_i*b_j, then fold
     v^3=xi and v^4=xi*v into the three output coefficients. */
  fd_bls_fp2_t a0b0, a0b1, a0b2, a1b0, a1b1, a1b2;
  fd_bls_fp2_t a2b0, a2b1, a2b2, t0, t1;
  fd_bls_fp2_mul( &a0b0, &a->c[0], &b->c[0] );       /* a0b0 = a0*b0.                                  */
  fd_bls_fp2_mul( &a0b1, &a->c[0], &b->c[1] );       /* a0b1 = a0*b1.                                  */
  fd_bls_fp2_mul( &a0b2, &a->c[0], &b->c[2] );       /* a0b2 = a0*b2.                                  */
  fd_bls_fp2_mul( &a1b0, &a->c[1], &b->c[0] );       /* a1b0 = a1*b0.                                  */
  fd_bls_fp2_mul( &a1b1, &a->c[1], &b->c[1] );       /* a1b1 = a1*b1.                                  */
  fd_bls_fp2_mul( &a1b2, &a->c[1], &b->c[2] );       /* a1b2 = a1*b2.                                  */
  fd_bls_fp2_mul( &a2b0, &a->c[2], &b->c[0] );       /* a2b0 = a2*b0.                                  */
  fd_bls_fp2_mul( &a2b1, &a->c[2], &b->c[1] );       /* a2b1 = a2*b1.                                  */
  fd_bls_fp2_mul( &a2b2, &a->c[2], &b->c[2] );       /* a2b2 = a2*b2.                                  */
  fd_bls_fp2_add( &t0, &a1b2, &a2b1 );              /* t0   = a1*b2+a2*b1, coefficient of v^3.        */
  fp2_mul_nonres_final( &t1, &t0 );                  /* t1   = xi*(a1*b2+a2*b1), because v^3=xi.       */
  fd_bls_fp2_add( &out->c[0], &a0b0, &t1 );         /* c0   = a0*b0+xi*(a1*b2+a2*b1).                 */
  fd_bls_fp2_add( &t0, &a0b1, &a1b0 );              /* t0   = a0*b1+a1*b0, coefficient of v.          */
  fp2_mul_nonres_final( &t1, &a2b2 );                /* t1   = xi*a2*b2, from a2*b2*v^4=xi*a2*b2*v.    */
  fd_bls_fp2_add( &out->c[1], &t0, &t1 );           /* c1   = a0*b1+a1*b0+xi*a2*b2.                   */
  fd_bls_fp2_add( &t0, &a0b2, &a1b1 );              /* t0   = a0*b2+a1*b1, coefficient of v^2.        */
  fd_bls_fp2_add( &out->c[2], &t0, &a2b0 );         /* c2   = a0*b2+a1*b1+a2*b0.                      */
}

static inline void
fp6_mul_v_final( fp6_final_t *       out,
                 fp6_final_t const * in ) {
  fp6_final_t r;
  fp2_mul_nonres_final( &r.c[0], &in->c[2] ); /* v*(c0+c1*v+c2*v^2) has c0'=xi*c2. */
  r.c[1] = in->c[0];                         /* c1'=c0.                              */
  r.c[2] = in->c[1];                         /* c2'=c1.                              */
  *out = r;                                  /* out=v*in modulo v^3-xi.              */
}

static void
fp6_inverse_final( fp6_final_t *       out,
                   fp6_final_t const * in ) {
  /* Adjugate inversion in Fp2[v]/(v^3-(1+u)); only its Fp2 norm is inverted. */
  fd_bls_fp2_t c0, c1, c2, t0, t1, tmp, tmp_inv;
  fd_bls_fp2_sqr( &c0, &in->c[0] );                   /* c0  = a0^2.                         */
  fd_bls_fp2_mul( &t0, &in->c[1], &in->c[2] );       /* t0  = a1*a2.                        */
  fp2_mul_nonres_final( &t1, &t0 );                   /* t1  = xi*a1*a2.                     */
  fd_bls_fp2_sub( &c0, &c0, &t1 );                   /* c0  = a0^2-xi*a1*a2.                */

  fd_bls_fp2_sqr( &t0, &in->c[2] );                  /* t0  = a2^2.                          */
  fp2_mul_nonres_final( &c1, &t0 );                  /* c1  = xi*a2^2.                       */
  fd_bls_fp2_mul( &t0, &in->c[0], &in->c[1] );       /* t0  = a0*a1.                         */
  fd_bls_fp2_sub( &c1, &c1, &t0 );                   /* c1  = xi*a2^2-a0*a1.                 */

  fd_bls_fp2_sqr( &c2, &in->c[1] );                  /* c2  = a1^2.                          */
  fd_bls_fp2_mul( &t0, &in->c[0], &in->c[2] );       /* t0  = a0*a2.                         */
  fd_bls_fp2_sub( &c2, &c2, &t0 );                   /* c2  = a1^2-a0*a2.                    */

  fd_bls_fp2_mul( &t0, &in->c[2], &c1 );             /* t0  = a2*c1.                         */
  fd_bls_fp2_mul( &t1, &in->c[1], &c2 );             /* t1  = a1*c2.                         */
  fd_bls_fp2_add( &tmp, &t0, &t1 );                  /* tmp = a2*c1+a1*c2.                   */
  fp2_mul_nonres_final( &tmp, &tmp );                 /* tmp = xi*(a2*c1+a1*c2).              */
  fd_bls_fp2_mul( &t0, &in->c[0], &c0 );             /* t0  = a0*c0.                         */
  fd_bls_fp2_add( &tmp, &tmp, &t0 );                 /* tmp = a0*c0+xi*(a2*c1+a1*c2)=Norm(a). */
  fp2_inverse_final( &tmp_inv, &tmp );                /* tmpInv = 1/Norm(a).                  */
  fd_bls_fp2_mul( &out->c[0], &c0, &tmp_inv );       /* out0 = c0/Norm(a).                   */
  fd_bls_fp2_mul( &out->c[1], &c1, &tmp_inv );       /* out1 = c1/Norm(a).                   */
  fd_bls_fp2_mul( &out->c[2], &c2, &tmp_inv );       /* out2 = c2/Norm(a), hence out=a^-1.   */
}

void
fd_bls_fp12_inverse( fd_bls_fp12_t *       out,
                         fd_bls_fp12_t const * in ) {
  /* (a+b*w)^-1=(a-b*w)/(a^2-v*b^2) over Fp6. */
  fp6_final_t a, b, aa, bb, vb, denominator, denominator_inv, r0, r1;
  for( int i=0; i<3; i++ ) {
    a.c[i].c[0] = in->c[2*i];
    a.c[i].c[1] = in->c[2*i+1];
    b.c[i].c[0] = in->c[6+2*i];
    b.c[i].c[1] = in->c[7+2*i];
  }
  fp6_mul_final( &aa, &a, &a );                    /* aa          = a^2.              */
  fp6_mul_final( &bb, &b, &b );                    /* bb          = b^2.              */
  fp6_mul_v_final( &vb, &bb );                     /* vb          = v*b^2.            */
  for( int i=0; i<3; i++ )
    fd_bls_fp2_sub( &denominator.c[i], &aa.c[i], &vb.c[i] ); /* denominator = a^2-v*b^2. */
  fp6_inverse_final( &denominator_inv, &denominator ); /* denominatorInv = 1/(a^2-v*b^2). */
  fp6_mul_final( &r0, &a, &denominator_inv );      /* r0          = a/(a^2-v*b^2).   */
  fp6_mul_final( &r1, &b, &denominator_inv );      /* r1          = b/(a^2-v*b^2).   */
  for( int i=0; i<3; i++ )
    fd_bls_fp2_neg( &r1.c[i], &r1.c[i] );          /* r1          = -b/(a^2-v*b^2).  */
  for( int i=0; i<3; i++ ) {
    out->c[2*i]   = r0.c[i].c[0];
    out->c[2*i+1] = r0.c[i].c[1];
    out->c[6+2*i] = r1.c[i].c[0];
    out->c[7+2*i] = r1.c[i].c[1];
  }
}

static inline fd_bls_fp_t
fp_const_final( ulong const m1[8],
                ulong const m2[8] ) {
  return (fd_bls_fp_t){
    .m1 = wwv_ld( m1 ),
    .m2 = wwv_ld( m2 )
  };
}

static inline void
fp_mul2_final( fd_bls_fp_t *       out,
               fd_bls_fp_t const * a,
               fd_bls_fp_t const * ac,
               fd_bls_fp_t const * b,
               fd_bls_fp_t const * bc ) {
  fd_bls_fp_wide_t w;
  fd_bls_fp_wide_offset( &w );          /* w   = 0 mod p, represented by a positive lazy offset. */
  fd_bls_fp_wide_addmul( &w, a, ac );   /* w  += a*ac.                                            */
  fd_bls_fp_wide_addmul( &w, b, bc );   /* w  += b*bc.                                            */
  fd_bls_fp_reduce_wide( out, &w );     /* out = a*ac+b*bc mod p.                                 */
}

void
fd_bls_fp12_frobenius( fd_bls_fp12_t *       out,
                           fd_bls_fp12_t const * in,
                           ulong                   n ) {
  /* Apply x -> x^(p^n); conjugations and the fixed tower coefficients make
     this linear over Fp. */
#define FP_CONST(name) fp_const_final( fd_bls_##name##_m1, fd_bls_##name##_m2 )
  fd_bls_fp12_t r;
  if( n==1UL ) {
    fd_bls_fp_t f12=FP_CONST(frob1_2), f13=FP_CONST(frob1_3);
    fd_bls_fp_t f14=FP_CONST(frob1_4), f15=FP_CONST(frob1_5);
    fd_bls_fp_t f16=FP_CONST(frob1_6), f17=FP_CONST(frob1_7);
    fd_bls_fp_t f18=FP_CONST(frob1_8), f19=FP_CONST(frob1_9);
    fd_bls_fp_t f110=FP_CONST(frob1_10);
    r.c[0] = in->c[0];                                                   /* c'_0  = c0.                 */
    fd_bls_fp_neg( &r.c[1], &in->c[1] );                                /* c'_1  = -c1.                */
    fd_bls_fp_mul( &r.c[2], &in->c[3], &f12 );                          /* c'_2  = f12*c3.             */
    fd_bls_fp_mul( &r.c[3], &in->c[2], &f12 );                          /* c'_3  = f12*c2.             */
    fd_bls_fp_mul( &r.c[4], &in->c[4], &f13 );                          /* c'_4  = f13*c4.             */
    fd_bls_fp_mul( &r.c[5], &in->c[5], &f14 );                          /* c'_5  = f14*c5.             */
    fp_mul2_final( &r.c[6],  &in->c[7],  &f16,  &in->c[6],  &f15  );   /* c'_6  = f16*c7+f15*c6.     */
    fp_mul2_final( &r.c[7],  &in->c[7],  &f16,  &in->c[6],  &f16  );   /* c'_7  = f16*c7+f16*c6.     */
    fp_mul2_final( &r.c[8],  &in->c[8],  &f17,  &in->c[9],  &f17  );   /* c'_8  = f17*c8+f17*c9.     */
    fp_mul2_final( &r.c[9],  &in->c[8],  &f17,  &in->c[9],  &f18  );   /* c'_9  = f17*c8+f18*c9.     */
    fp_mul2_final( &r.c[10], &in->c[11], &f110, &in->c[10], &f19  );   /* c'_10 = f110*c11+f19*c10.  */
    fp_mul2_final( &r.c[11], &in->c[11], &f110, &in->c[10], &f110 );   /* c'_11 = f110*c11+f110*c10. */
  } else if( n==2UL ) {
    fd_bls_fp_t f21=FP_CONST(frob2_1), f22=FP_CONST(frob2_2);
    fd_bls_fp_t f23=FP_CONST(frob2_3), f25=FP_CONST(frob2_5);
    r.c[0] = in->c[0]; r.c[1] = in->c[1];                    /* c'_{0,1}   = c_{0,1}.     */
    fd_bls_fp_mul( &r.c[2],  &in->c[2],  &f21 );             /* c'_2       = f21*c2.      */
    fd_bls_fp_mul( &r.c[3],  &in->c[3],  &f21 );             /* c'_3       = f21*c3.      */
    fd_bls_fp_mul( &r.c[4],  &in->c[4],  &f22 );             /* c'_4       = f22*c4.      */
    fd_bls_fp_mul( &r.c[5],  &in->c[5],  &f22 );             /* c'_5       = f22*c5.      */
    fd_bls_fp_mul( &r.c[6],  &in->c[6],  &f23 );             /* c'_6       = f23*c6.      */
    fd_bls_fp_mul( &r.c[7],  &in->c[7],  &f23 );             /* c'_7       = f23*c7.      */
    fd_bls_fp_neg( &r.c[8],  &in->c[8] );                   /* c'_8       = -c8.         */
    fd_bls_fp_neg( &r.c[9],  &in->c[9] );                   /* c'_9       = -c9.         */
    fd_bls_fp_mul( &r.c[10], &in->c[10], &f25 );            /* c'_10      = f25*c10.       */
    fd_bls_fp_mul( &r.c[11], &in->c[11], &f25 );            /* c'_11      = f25*c11.       */
  } else if( n==3UL ) {
    fd_bls_fp_t f32=FP_CONST(frob3_2), f33=FP_CONST(frob3_3);
    r.c[0] = in->c[0];                                                /* c'_0  = c0.               */
    fd_bls_fp_neg( &r.c[1], &in->c[1] );                             /* c'_1  = -c1.              */
    r.c[2] = in->c[3]; r.c[3] = in->c[2];                            /* c'_2  = c3; c'_3=c2.      */
    fd_bls_fp_neg( &r.c[4], &in->c[4] );                             /* c'_4  = -c4.              */
    r.c[5] = in->c[5];                                               /* c'_5  = c5.               */
    fp_mul2_final( &r.c[6],  &in->c[7],  &f33, &in->c[6],  &f32 );  /* c'_6  = f33*c7+f32*c6.   */
    fp_mul2_final( &r.c[7],  &in->c[7],  &f33, &in->c[6],  &f33 );  /* c'_7  = f33*c7+f33*c6.   */
    fp_mul2_final( &r.c[8],  &in->c[8],  &f32, &in->c[9],  &f32 );  /* c'_8  = f32*c8+f32*c9.   */
    fp_mul2_final( &r.c[9],  &in->c[8],  &f32, &in->c[9],  &f33 );  /* c'_9  = f32*c8+f33*c9.   */
    fp_mul2_final( &r.c[10], &in->c[11], &f32, &in->c[10], &f33 );  /* c'_10 = f32*c11+f33*c10. */
    fp_mul2_final( &r.c[11], &in->c[11], &f32, &in->c[10], &f32 );  /* c'_11 = f32*c11+f32*c10. */
  } else {
    r = *in;
  }
  *out = r;
#undef FP_CONST
}

static void
mul_n_sqr( fd_bls_fp12_t *       out,
           fd_bls_fp12_t const * a,
           fd_bls_fp12_t const * b,
           uint                    n ) {
  fd_bls_fp12_mul( out, a, b );                                      /* out = a*b.         */
  for( uint i=0U; i<n; i++ ) fd_bls_fp12_cyclotomic_sqr( out, out ); /* out = (a*b)^(2^n). */
}

static void
raise_to_z_div_by_2( fd_bls_fp12_t *       out,
                     fd_bls_fp12_t const * in ) {
  /* The square/add chain reaches (-z)/2; conjugation is inversion in the
     cyclotomic subgroup, so the result is in^(z/2) for negative z. */
  fd_bls_fp12_t r;
  fd_bls_fp12_cyclotomic_sqr( &r, in ); /* r   = in^2.                                             */
  mul_n_sqr( &r, &r, in, 2U );         /* r   = (in^2*in)^4       = in^12.                         */
  mul_n_sqr( &r, &r, in, 3U );         /* r   = (in^12*in)^8      = in^104.                        */
  mul_n_sqr( &r, &r, in, 9U );         /* r   = (in^104*in)^512   = in^53760.                      */
  mul_n_sqr( &r, &r, in, 32U );        /* r   = in^(53761*2^32).                                  */
  mul_n_sqr( &r, &r, in, 15U );        /* r   = in^((53761*2^32+1)*2^15) = in^((-z)/2).            */
  fp12_conjugate_final( out, &r );      /* out = r^-1 in the cyclotomic group       = in^(z/2).     */
}

static void
raise_to_z( fd_bls_fp12_t *       out,
            fd_bls_fp12_t const * in ) {
  fd_bls_fp12_t half;
  raise_to_z_div_by_2( &half, in );               /* half = in^(z/2). */
  fd_bls_fp12_cyclotomic_sqr( out, &half );       /* out  = in^z.     */
}

void
fd_bls_final_exp( fd_bls_fp12_t *       out,
                      fd_bls_fp12_t const * f ) {
  fd_bls_fp12_t inverse, conj, ret1, frob2_ret1, ret2, ret2_sqr;
  fd_bls_fp12_t y0_to_z, y0_to_z_div2, ret2_conj, y1_mul_y3;
  fd_bls_fp12_t y1_mul_y3_conj, y1_final, y1_to_z, y2_to_z;
  fd_bls_fp12_t y1_final_conj, y3_mul_y1, y1_frob3, y1_to_z_frob2;
  fd_bls_fp12_t y1_mul_y2, y3_to_z, y2_mul_y0, y2_mul_ret;
  fd_bls_fp12_t y1_mul_y2_final, y3_frob1;

  /* Easy part.  Write g=f^((p^6-1)(p^2+1)); g is cyclotomic, so conjugation
     below is inversion and Frobenius calls are cheap exponentiations by p. */
  fd_bls_fp12_inverse( &inverse, f );                         /* inverse   = f^-1.                              */
  fp12_conjugate_final( &conj, f );                           /* conj      = f^(p^6).                           */
  fd_bls_fp12_mul( &ret1, &conj, &inverse );                  /* ret1      = f^(p^6-1).                         */
  fd_bls_fp12_frobenius( &frob2_ret1, &ret1, 2UL );           /* frob2Ret1 = ret1^(p^2).                        */
  fd_bls_fp12_mul( &ret2, &frob2_ret1, &ret1 );               /* ret2      = f^((p^6-1)(p^2+1)) = g.           */

  /* Hard part.  The aligned exponents show the BLS12 addition chain for
     h=(p^4-p^2+1)/r.  The final product is g^h. */
  fd_bls_fp12_cyclotomic_sqr( &ret2_sqr, &ret2 );             /* ret2Sqr     = g^2.                              */
  raise_to_z( &y0_to_z, &ret2_sqr );                          /* y0ToZ       = g^(2z).                           */
  raise_to_z_div_by_2( &y0_to_z_div2, &y0_to_z );             /* y0ToZDiv2   = g^(z^2).                          */
  fp12_conjugate_final( &ret2_conj, &ret2 );                  /* ret2Conj    = g^-1.                             */
  fd_bls_fp12_mul( &y1_mul_y3, &ret2_conj, &y0_to_z );        /* y1MulY3     = g^(2z-1).                         */
  fp12_conjugate_final( &y1_mul_y3_conj, &y1_mul_y3 );        /* y1MulY3Conj = g^(1-2z).                         */
  fd_bls_fp12_mul( &y1_final, &y1_mul_y3_conj, &y0_to_z_div2 ); /* y1Final   = g^(z^2-2z+1).                     */
  raise_to_z( &y1_to_z, &y1_final );                          /* y1ToZ       = g^(z^3-2z^2+z).                   */
  raise_to_z( &y2_to_z, &y1_to_z );                           /* y2ToZ       = g^(z^4-2z^3+z^2).                 */
  fp12_conjugate_final( &y1_final_conj, &y1_final );          /* y1FinalConj = g^(-z^2+2z-1).                   */
  fd_bls_fp12_mul( &y3_mul_y1, &y2_to_z, &y1_final_conj );    /* y3MulY1     = g^(z^4-2z^3+2z-1).               */
  fd_bls_fp12_frobenius( &y1_frob3, &y1_final, 3UL );         /* y1Frob3     = g^(p^3*(z^2-2z+1)).              */
  fd_bls_fp12_frobenius( &y1_to_z_frob2, &y1_to_z, 2UL );    /* y1ToZFrob2  = g^(p^2*(z^3-2z^2+z)).           */
  fd_bls_fp12_mul( &y1_mul_y2, &y1_frob3, &y1_to_z_frob2 );  /* y1MulY2     = y1Frob3*y1ToZFrob2.              */
  raise_to_z( &y3_to_z, &y3_mul_y1 );                         /* y3ToZ       = y3MulY1^z.                        */
  fd_bls_fp12_mul( &y2_mul_y0, &y3_to_z, &ret2_sqr );         /* y2MulY0     = y3ToZ*g^2.                        */
  fd_bls_fp12_mul( &y2_mul_ret, &y2_mul_y0, &ret2 );          /* y2MulRet    = y3ToZ*g^3.                        */
  fd_bls_fp12_mul( &y1_mul_y2_final, &y1_mul_y2, &y2_mul_ret ); /* y1MulY2Final = y1MulY2*y3ToZ*g^3.           */
  fd_bls_fp12_frobenius( &y3_frob1, &y3_mul_y1, 1UL );        /* y3Frob1     = y3MulY1^p.                        */
  fd_bls_fp12_mul( out, &y1_mul_y2_final, &y3_frob1 );        /* out         = g^h = f^((p^12-1)/r).            */
}

int
fd_bls_fp12_is_one( fd_bls_fp12_t const * in ) {
  wwv_t mod1 = wwv_ld( fd_bls_m1 );
  wwv_t mod2 = wwv_ld( fd_bls_m2 );
  wwv_t p1   = wwv_ld( fd_bls_field_modulus_m1 );
  wwv_t p2   = wwv_ld( fd_bls_field_modulus_m2 );
  wwv_t one1 = wwv_ld( fd_bls_one_m1 );
  wwv_t one2 = wwv_ld( fd_bls_one_m2 );
  wwv_t zero = wwv_zero();

#define CANONICAL(x,m) wwv_min( (x), wwv_sub( (x), (m) ) )
  p1   = CANONICAL( p1,   mod1 );
  p2   = CANONICAL( p2,   mod2 );
  one1 = CANONICAL( one1, mod1 );
  one2 = CANONICAL( one2, mod2 );
  for( int i=0; i<12; i++ ) {
    wwv_t x1 = CANONICAL( in->c[i].m1, mod1 );
    wwv_t x2 = CANONICAL( in->c[i].m2, mod2 );
    wwv_t candidate1 = i ? zero : one1;
    wwv_t candidate2 = i ? zero : one2;
    int matched = 0;
    /* A reduced RNS element has bound one.  One unit of that bound is
       40*p, so the exact representative is value+k*p for 0<=k<=40. */
    for( int k=0; k<=40; k++ ) {
      if( wwv_eq( x1, candidate1 )==0xff &&
          wwv_eq( x2, candidate2 )==0xff ) {
        matched = 1;
        break;
      }
      candidate1 = CANONICAL( wwv_add( candidate1, p1 ), mod1 );
      candidate2 = CANONICAL( wwv_add( candidate2, p2 ), mod2 );
    }
    if( FD_UNLIKELY( !matched ) ) return 0;
  }
#undef CANONICAL
  return 1;
}

#endif
