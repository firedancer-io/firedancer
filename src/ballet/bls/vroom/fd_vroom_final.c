#include "fd_vroom_final.h"

#if FD_HAS_AVX512

#include "fd_vroom_constants.h"

static void
fp12_conjugate_final( fd_vroom_fp12_t *       out,
                      fd_vroom_fp12_t const * in ) {
  *out = *in;
  for( int i=6; i<12; i++ ) fd_vroom_fp_neg( &out->c[i], &out->c[i] );
}

/* Native inversion.  The old path converted twelve RNS elements to BLST,
   inverted there, and converted all twelve back.  Keep the whole tower in
   RNS instead: one fixed base-field addition chain plus ordinary Fp2/Fp6
   tower formulas. */

typedef struct { fd_vroom_fp2_t c[3]; } fp6_final_t;

static inline void
fp_inverse_shift( fd_vroom_fp_t *       out,
                  fd_vroom_fp_t const * in,
                  uint                  bits ) {
  fd_vroom_fp_t r = *in;
  for( uint i=0U; i<bits; i++ ) fd_vroom_fp_sqr( &r, &r );
  *out = r;
}

static void
fp_inverse_exp_x( fd_vroom_fp_t *       out,
                  fd_vroom_fp_t const * base ) {
  fd_vroom_fp_t base10, base11, base1100, base1101, base1101000, base1101001;
  fd_vroom_fp_t t0, t1;
  fd_vroom_fp_sqr( &base10, base );
  fd_vroom_fp_mul( &base11, &base10, base );
  fp_inverse_shift( &base1100, &base11, 2U );
  fd_vroom_fp_mul( &base1101, &base1100, base );
  fp_inverse_shift( &base1101000, &base1101, 3U );
  fd_vroom_fp_mul( &base1101001, &base1101000, base );
  fp_inverse_shift( &t0, &base1101001, 9U );
  fd_vroom_fp_mul( &t1, &t0, base );
  fp_inverse_shift( &t0, &t1, 32U );
  fd_vroom_fp_mul( &t1, &t0, base );
  fp_inverse_shift( out, &t1, 16U );
}

static void
fp_inverse_exp_x_m3( fd_vroom_fp_t *       out,
                     fd_vroom_fp_t const * base ) {
  fd_vroom_fp_t base2, base3, base12, base13, base15, base104, base105;
  fd_vroom_fp_t i610, i611, i612, i614, i61, r1, r2, r3, r4;
  fd_vroom_fp_sqr( &base2, base );
  fd_vroom_fp_mul( &base3, &base2, base );
  fp_inverse_shift( &base12, &base3, 2U );
  fd_vroom_fp_mul( &base13, &base12, base );
  fd_vroom_fp_mul( &base15, &base13, &base2 );
  fp_inverse_shift( &base104, &base13, 3U );
  fd_vroom_fp_mul( &base105, &base104, base );
  fp_inverse_shift( &i610, &base105, 9U );
  fd_vroom_fp_mul( &i611, &i610, base );
  fp_inverse_shift( &i612, &i611, 36U );
  fd_vroom_fp_mul( &i614, &i612, &base15 );
  fp_inverse_shift( &i61, &i614, 4U );
  fd_vroom_fp_mul( &r1, &base15, &i61 );
  fp_inverse_shift( &r2, &r1, 4U );
  fd_vroom_fp_mul( &r3, &r2, &base15 );
  fp_inverse_shift( &r4, &r3, 4U );
  fd_vroom_fp_mul( out, &r4, &base13 );
}

static void
fp_inverse_addchain_final( fd_vroom_fp_t *       out,
                           fd_vroom_fp_t const * base ) {
  fd_vroom_fp_t ax_m3, ax_m2, ax2_m2x, ax, ax2_mx, ax3_mx2;
  fd_vroom_fp_t ax4_mx3, ax5_mx4, ax6_mx5, ax2_mx_m3, ax3_mx_m3;
  fd_vroom_fp_t a3x4_m3x2, a3x4_m2x3_mx_m3, a3x5_m3x4;
  fd_vroom_fp_t a3x5_m2x3_mx_m2, t0, t1;
  fp_inverse_exp_x_m3( &ax_m3, base );
  fd_vroom_fp_mul( &ax_m2, &ax_m3, base );
  fp_inverse_exp_x( &ax2_m2x, &ax_m2 );
  fd_vroom_fp_mul( &t0, &ax_m2, base );
  fd_vroom_fp_mul( &ax, &t0, base );
  fd_vroom_fp_mul( &ax2_mx, &ax2_m2x, &ax );
  fp_inverse_exp_x( &ax3_mx2, &ax2_mx );
  fp_inverse_exp_x( &ax4_mx3, &ax3_mx2 );
  fp_inverse_exp_x( &ax5_mx4, &ax4_mx3 );
  fp_inverse_exp_x( &ax6_mx5, &ax5_mx4 );
  fd_vroom_fp_mul( &ax2_mx_m3, &ax2_m2x, &ax_m3 );
  fd_vroom_fp_mul( &ax3_mx_m3, &ax2_mx_m3, &ax3_mx2 );
  fd_vroom_fp_sqr( &t0, &ax4_mx3 );
  fd_vroom_fp_mul( &a3x4_m3x2, &t0, &ax4_mx3 );
  fd_vroom_fp_mul( &a3x4_m2x3_mx_m3, &a3x4_m3x2, &ax3_mx_m3 );
  fd_vroom_fp_sqr( &t0, &ax5_mx4 );
  fd_vroom_fp_mul( &a3x5_m3x4, &t0, &ax5_mx4 );
  fd_vroom_fp_mul( &a3x5_m2x3_mx_m2, &a3x5_m3x4, &a3x4_m2x3_mx_m3 );
  fd_vroom_fp_mul( &t1, &ax6_mx5, &a3x5_m2x3_mx_m2 );
  *out = t1;
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
fp_inverse_final( fd_vroom_fp_t *       out,
                  fd_vroom_fp_t const * base ) {
  static ulong const p[6] = {
    0xb9feffffffffaaabUL, 0x1eabfffeb153ffffUL,
    0x6730d2a0f6b0f624UL, 0x64774b84f38512bfUL,
    0x4b1ba7b6434bacd7UL, 0x1a0111ea397fe69aUL
  };
  ulong u[6], v[6], x1[6] = {1UL}, x2[6] = {0UL};
  fd_vroom_fp_to_uint64( u, base );
  for( int i=0; i<6; i++ ) v[i] = p[i];
  if( FD_UNLIKELY( uint384_is_zero_final( u ) ) ) {
    fd_vroom_fp_zero( out );
    return;
  }

  for( uint steps=0U; steps<4096U; steps++ ) {
    if( uint384_is_one_final( u ) ) { fd_vroom_fp_from_uint64( out, x1 ); return; }
    if( uint384_is_one_final( v ) ) { fd_vroom_fp_from_uint64( out, x2 ); return; }
    while( !(u[0]&1UL) ) { uint384_rshift_final( u ); uint384_half_mod_final( x1 ); }
    while( !(v[0]&1UL) ) { uint384_rshift_final( v ); uint384_half_mod_final( x2 ); }
    if( uint384_ge_final( u, v ) ) {
      uint384_sub_final( u, v );
      uint384_sub_mod_final( x1, x2 );
    } else {
      uint384_sub_final( v, u );
      uint384_sub_mod_final( x2, x1 );
    }
  }
  fp_inverse_addchain_final( out, base );
}

static inline void
fp2_mul_nonres_final( fd_vroom_fp2_t *       out,
                      fd_vroom_fp2_t const * in ) {
  fd_vroom_fp_t a = in->c[0], b = in->c[1];
  fd_vroom_fp_sub( &out->c[0], &a, &b );
  fd_vroom_fp_add( &out->c[1], &a, &b );
}

static void
fp2_inverse_final( fd_vroom_fp2_t *       out,
                   fd_vroom_fp2_t const * in ) {
  fd_vroom_fp_t aa, bb, norm, norm_inv;
  fd_vroom_fp_sqr( &aa, &in->c[0] );
  fd_vroom_fp_sqr( &bb, &in->c[1] );
  fd_vroom_fp_add( &norm, &aa, &bb );
  fp_inverse_final( &norm_inv, &norm );
  fd_vroom_fp_mul( &out->c[0], &in->c[0], &norm_inv );
  fd_vroom_fp_mul( &out->c[1], &in->c[1], &norm_inv );
  fd_vroom_fp_neg( &out->c[1], &out->c[1] );
}

static void
fp6_mul_final( fp6_final_t *       out,
               fp6_final_t const * a,
               fp6_final_t const * b ) {
  fd_vroom_fp2_t a0b0, a0b1, a0b2, a1b0, a1b1, a1b2;
  fd_vroom_fp2_t a2b0, a2b1, a2b2, t0, t1;
  fd_vroom_fp2_mul( &a0b0, &a->c[0], &b->c[0] );
  fd_vroom_fp2_mul( &a0b1, &a->c[0], &b->c[1] );
  fd_vroom_fp2_mul( &a0b2, &a->c[0], &b->c[2] );
  fd_vroom_fp2_mul( &a1b0, &a->c[1], &b->c[0] );
  fd_vroom_fp2_mul( &a1b1, &a->c[1], &b->c[1] );
  fd_vroom_fp2_mul( &a1b2, &a->c[1], &b->c[2] );
  fd_vroom_fp2_mul( &a2b0, &a->c[2], &b->c[0] );
  fd_vroom_fp2_mul( &a2b1, &a->c[2], &b->c[1] );
  fd_vroom_fp2_mul( &a2b2, &a->c[2], &b->c[2] );
  fd_vroom_fp2_add( &t0, &a1b2, &a2b1 );
  fp2_mul_nonres_final( &t1, &t0 );
  fd_vroom_fp2_add( &out->c[0], &a0b0, &t1 );
  fd_vroom_fp2_add( &t0, &a0b1, &a1b0 );
  fp2_mul_nonres_final( &t1, &a2b2 );
  fd_vroom_fp2_add( &out->c[1], &t0, &t1 );
  fd_vroom_fp2_add( &t0, &a0b2, &a1b1 );
  fd_vroom_fp2_add( &out->c[2], &t0, &a2b0 );
}

static inline void
fp6_mul_v_final( fp6_final_t *       out,
                 fp6_final_t const * in ) {
  fp6_final_t r;
  fp2_mul_nonres_final( &r.c[0], &in->c[2] );
  r.c[1] = in->c[0];
  r.c[2] = in->c[1];
  *out = r;
}

static void
fp6_inverse_final( fp6_final_t *       out,
                   fp6_final_t const * in ) {
  fd_vroom_fp2_t c0, c1, c2, t0, t1, tmp, tmp_inv;
  fd_vroom_fp2_sqr( &c0, &in->c[0] );
  fd_vroom_fp2_mul( &t0, &in->c[1], &in->c[2] );
  fp2_mul_nonres_final( &t1, &t0 );
  fd_vroom_fp2_sub( &c0, &c0, &t1 );

  fd_vroom_fp2_sqr( &t0, &in->c[2] );
  fp2_mul_nonres_final( &c1, &t0 );
  fd_vroom_fp2_mul( &t0, &in->c[0], &in->c[1] );
  fd_vroom_fp2_sub( &c1, &c1, &t0 );

  fd_vroom_fp2_sqr( &c2, &in->c[1] );
  fd_vroom_fp2_mul( &t0, &in->c[0], &in->c[2] );
  fd_vroom_fp2_sub( &c2, &c2, &t0 );

  fd_vroom_fp2_mul( &t0, &in->c[2], &c1 );
  fd_vroom_fp2_mul( &t1, &in->c[1], &c2 );
  fd_vroom_fp2_add( &tmp, &t0, &t1 );
  fp2_mul_nonres_final( &tmp, &tmp );
  fd_vroom_fp2_mul( &t0, &in->c[0], &c0 );
  fd_vroom_fp2_add( &tmp, &tmp, &t0 );
  fp2_inverse_final( &tmp_inv, &tmp );
  fd_vroom_fp2_mul( &out->c[0], &c0, &tmp_inv );
  fd_vroom_fp2_mul( &out->c[1], &c1, &tmp_inv );
  fd_vroom_fp2_mul( &out->c[2], &c2, &tmp_inv );
}

void
fd_vroom_fp12_inverse_c( fd_vroom_fp12_t *       out,
                         fd_vroom_fp12_t const * in ) {
  fp6_final_t a, b, aa, bb, vb, denominator, denominator_inv, r0, r1;
  for( int i=0; i<3; i++ ) {
    a.c[i].c[0] = in->c[2*i];
    a.c[i].c[1] = in->c[2*i+1];
    b.c[i].c[0] = in->c[6+2*i];
    b.c[i].c[1] = in->c[7+2*i];
  }
  fp6_mul_final( &aa, &a, &a );
  fp6_mul_final( &bb, &b, &b );
  fp6_mul_v_final( &vb, &bb );
  for( int i=0; i<3; i++ ) fd_vroom_fp2_sub( &denominator.c[i], &aa.c[i], &vb.c[i] );
  fp6_inverse_final( &denominator_inv, &denominator );
  fp6_mul_final( &r0, &a, &denominator_inv );
  fp6_mul_final( &r1, &b, &denominator_inv );
  for( int i=0; i<3; i++ ) fd_vroom_fp2_neg( &r1.c[i], &r1.c[i] );
  for( int i=0; i<3; i++ ) {
    out->c[2*i]   = r0.c[i].c[0];
    out->c[2*i+1] = r0.c[i].c[1];
    out->c[6+2*i] = r1.c[i].c[0];
    out->c[7+2*i] = r1.c[i].c[1];
  }
}

static inline fd_vroom_fp_t
fp_const_final( ulong const m1[8],
                ulong const m2[8] ) {
  return (fd_vroom_fp_t){
    .m1 = _mm512_load_si512( (__m512i const *)m1 ),
    .m2 = _mm512_load_si512( (__m512i const *)m2 )
  };
}

static inline void
fp_mul2_final( fd_vroom_fp_t *       out,
               fd_vroom_fp_t const * a,
               fd_vroom_fp_t const * ac,
               fd_vroom_fp_t const * b,
               fd_vroom_fp_t const * bc ) {
  fd_vroom_fp_wide_t w;
  fd_vroom_fp_wide_offset( &w );
  fd_vroom_fp_wide_addmul( &w, a, ac );
  fd_vroom_fp_wide_addmul( &w, b, bc );
  fd_vroom_fp_reduce_wide( out, &w );
}

void
fd_vroom_fp12_frobenius_c( fd_vroom_fp12_t *       out,
                           fd_vroom_fp12_t const * in,
                           ulong                   n ) {
#define FP_CONST(name) fp_const_final( fd_vroom_##name##_m1, fd_vroom_##name##_m2 )
  fd_vroom_fp12_t r;
  if( n==1UL ) {
    fd_vroom_fp_t f12=FP_CONST(frob1_2), f13=FP_CONST(frob1_3);
    fd_vroom_fp_t f14=FP_CONST(frob1_4), f15=FP_CONST(frob1_5);
    fd_vroom_fp_t f16=FP_CONST(frob1_6), f17=FP_CONST(frob1_7);
    fd_vroom_fp_t f18=FP_CONST(frob1_8), f19=FP_CONST(frob1_9);
    fd_vroom_fp_t f110=FP_CONST(frob1_10);
    r.c[0] = in->c[0];
    fd_vroom_fp_neg( &r.c[1], &in->c[1] );
    fd_vroom_fp_mul( &r.c[2], &in->c[3], &f12 );
    fd_vroom_fp_mul( &r.c[3], &in->c[2], &f12 );
    fd_vroom_fp_mul( &r.c[4], &in->c[4], &f13 );
    fd_vroom_fp_mul( &r.c[5], &in->c[5], &f14 );
    fp_mul2_final( &r.c[6],  &in->c[7],  &f16,  &in->c[6],  &f15  );
    fp_mul2_final( &r.c[7],  &in->c[7],  &f16,  &in->c[6],  &f16  );
    fp_mul2_final( &r.c[8],  &in->c[8],  &f17,  &in->c[9],  &f17  );
    fp_mul2_final( &r.c[9],  &in->c[8],  &f17,  &in->c[9],  &f18  );
    fp_mul2_final( &r.c[10], &in->c[11], &f110, &in->c[10], &f19  );
    fp_mul2_final( &r.c[11], &in->c[11], &f110, &in->c[10], &f110 );
  } else if( n==2UL ) {
    fd_vroom_fp_t f21=FP_CONST(frob2_1), f22=FP_CONST(frob2_2);
    fd_vroom_fp_t f23=FP_CONST(frob2_3), f25=FP_CONST(frob2_5);
    r.c[0] = in->c[0]; r.c[1] = in->c[1];
    fd_vroom_fp_mul( &r.c[2],  &in->c[2],  &f21 );
    fd_vroom_fp_mul( &r.c[3],  &in->c[3],  &f21 );
    fd_vroom_fp_mul( &r.c[4],  &in->c[4],  &f22 );
    fd_vroom_fp_mul( &r.c[5],  &in->c[5],  &f22 );
    fd_vroom_fp_mul( &r.c[6],  &in->c[6],  &f23 );
    fd_vroom_fp_mul( &r.c[7],  &in->c[7],  &f23 );
    fd_vroom_fp_neg( &r.c[8],  &in->c[8] );
    fd_vroom_fp_neg( &r.c[9],  &in->c[9] );
    fd_vroom_fp_mul( &r.c[10], &in->c[10], &f25 );
    fd_vroom_fp_mul( &r.c[11], &in->c[11], &f25 );
  } else if( n==3UL ) {
    fd_vroom_fp_t f32=FP_CONST(frob3_2), f33=FP_CONST(frob3_3);
    r.c[0] = in->c[0];
    fd_vroom_fp_neg( &r.c[1], &in->c[1] );
    r.c[2] = in->c[3]; r.c[3] = in->c[2];
    fd_vroom_fp_neg( &r.c[4], &in->c[4] );
    r.c[5] = in->c[5];
    fp_mul2_final( &r.c[6],  &in->c[7],  &f33, &in->c[6],  &f32 );
    fp_mul2_final( &r.c[7],  &in->c[7],  &f33, &in->c[6],  &f33 );
    fp_mul2_final( &r.c[8],  &in->c[8],  &f32, &in->c[9],  &f32 );
    fp_mul2_final( &r.c[9],  &in->c[8],  &f32, &in->c[9],  &f33 );
    fp_mul2_final( &r.c[10], &in->c[11], &f32, &in->c[10], &f33 );
    fp_mul2_final( &r.c[11], &in->c[11], &f32, &in->c[10], &f32 );
  } else {
    r = *in;
  }
  *out = r;
#undef FP_CONST
}

static void
mul_n_sqr( fd_vroom_fp12_t *       out,
           fd_vroom_fp12_t const * a,
           fd_vroom_fp12_t const * b,
           uint                    n ) {
  fd_vroom_fp12_mul( out, a, b );
  for( uint i=0U; i<n; i++ ) fd_vroom_fp12_cyclotomic_sqr( out, out );
}

static void
raise_to_z_div_by_2( fd_vroom_fp12_t *       out,
                     fd_vroom_fp12_t const * in ) {
  fd_vroom_fp12_t r;
  fd_vroom_fp12_cyclotomic_sqr( &r, in );
  mul_n_sqr( &r, &r, in, 2U );
  mul_n_sqr( &r, &r, in, 3U );
  mul_n_sqr( &r, &r, in, 9U );
  mul_n_sqr( &r, &r, in, 32U );
  mul_n_sqr( &r, &r, in, 15U );
  fp12_conjugate_final( out, &r );
}

static void
raise_to_z( fd_vroom_fp12_t *       out,
            fd_vroom_fp12_t const * in ) {
  fd_vroom_fp12_t half;
  raise_to_z_div_by_2( &half, in );
  fd_vroom_fp12_cyclotomic_sqr( out, &half );
}

void
fd_vroom_final_exp_c( fd_vroom_fp12_t *       out,
                      fd_vroom_fp12_t const * f ) {
  fd_vroom_fp12_t inverse, conj, ret1, frob2_ret1, ret2, ret2_sqr;
  fd_vroom_fp12_t y0_to_z, y0_to_z_div2, ret2_conj, y1_mul_y3;
  fd_vroom_fp12_t y1_mul_y3_conj, y1_final, y1_to_z, y2_to_z;
  fd_vroom_fp12_t y1_final_conj, y3_mul_y1, y1_frob3, y1_to_z_frob2;
  fd_vroom_fp12_t y1_mul_y2, y3_to_z, y2_mul_y0, y2_mul_ret;
  fd_vroom_fp12_t y1_mul_y2_final, y3_frob1;

  fd_vroom_fp12_inverse_c( &inverse, f );
  fp12_conjugate_final( &conj, f );
  fd_vroom_fp12_mul( &ret1, &conj, &inverse );
  fd_vroom_fp12_frobenius_c( &frob2_ret1, &ret1, 2UL );
  fd_vroom_fp12_mul( &ret2, &frob2_ret1, &ret1 );
  fd_vroom_fp12_cyclotomic_sqr( &ret2_sqr, &ret2 );
  raise_to_z( &y0_to_z, &ret2_sqr );
  raise_to_z_div_by_2( &y0_to_z_div2, &y0_to_z );
  fp12_conjugate_final( &ret2_conj, &ret2 );
  fd_vroom_fp12_mul( &y1_mul_y3, &ret2_conj, &y0_to_z );
  fp12_conjugate_final( &y1_mul_y3_conj, &y1_mul_y3 );
  fd_vroom_fp12_mul( &y1_final, &y1_mul_y3_conj, &y0_to_z_div2 );
  raise_to_z( &y1_to_z, &y1_final );
  raise_to_z( &y2_to_z, &y1_to_z );
  fp12_conjugate_final( &y1_final_conj, &y1_final );
  fd_vroom_fp12_mul( &y3_mul_y1, &y2_to_z, &y1_final_conj );
  fd_vroom_fp12_frobenius_c( &y1_frob3, &y1_final, 3UL );
  fd_vroom_fp12_frobenius_c( &y1_to_z_frob2, &y1_to_z, 2UL );
  fd_vroom_fp12_mul( &y1_mul_y2, &y1_frob3, &y1_to_z_frob2 );
  raise_to_z( &y3_to_z, &y3_mul_y1 );
  fd_vroom_fp12_mul( &y2_mul_y0, &y3_to_z, &ret2_sqr );
  fd_vroom_fp12_mul( &y2_mul_ret, &y2_mul_y0, &ret2 );
  fd_vroom_fp12_mul( &y1_mul_y2_final, &y1_mul_y2, &y2_mul_ret );
  fd_vroom_fp12_frobenius_c( &y3_frob1, &y3_mul_y1, 1UL );
  fd_vroom_fp12_mul( out, &y1_mul_y2_final, &y3_frob1 );
}

int
fd_vroom_fp12_is_one_c( fd_vroom_fp12_t const * in ) {
  __m512i mod1 = _mm512_load_si512( (__m512i const *)fd_vroom_m1 );
  __m512i mod2 = _mm512_load_si512( (__m512i const *)fd_vroom_m2 );
  __m512i p1   = _mm512_load_si512( (__m512i const *)fd_vroom_field_modulus_m1 );
  __m512i p2   = _mm512_load_si512( (__m512i const *)fd_vroom_field_modulus_m2 );
  __m512i one1 = _mm512_load_si512( (__m512i const *)fd_vroom_one_m1 );
  __m512i one2 = _mm512_load_si512( (__m512i const *)fd_vroom_one_m2 );
  __m512i zero = _mm512_setzero_si512();

#define CANONICAL(x,m) _mm512_min_epu64( (x), _mm512_sub_epi64( (x), (m) ) )
  p1   = CANONICAL( p1,   mod1 );
  p2   = CANONICAL( p2,   mod2 );
  one1 = CANONICAL( one1, mod1 );
  one2 = CANONICAL( one2, mod2 );
  for( int i=0; i<12; i++ ) {
    __m512i x1 = CANONICAL( in->c[i].m1, mod1 );
    __m512i x2 = CANONICAL( in->c[i].m2, mod2 );
    __m512i candidate1 = i ? zero : one1;
    __m512i candidate2 = i ? zero : one2;
    int matched = 0;
    /* A reduced VROOM element has RNS bound one.  One unit of that bound is
       40*p, so the exact representative is value+k*p for 0<=k<=40. */
    for( int k=0; k<=40; k++ ) {
      if( _mm512_cmpeq_epu64_mask( x1, candidate1 )==(__mmask8)0xff &&
          _mm512_cmpeq_epu64_mask( x2, candidate2 )==(__mmask8)0xff ) {
        matched = 1;
        break;
      }
      candidate1 = CANONICAL( _mm512_add_epi64( candidate1, p1 ), mod1 );
      candidate2 = CANONICAL( _mm512_add_epi64( candidate2, p2 ), mod2 );
    }
    if( FD_UNLIKELY( !matched ) ) return 0;
  }
#undef CANONICAL
  return 1;
}

#endif
