/* BN254 final exponentiation over the VROOM engine: easy part
   (p^6-1)(p^2+1), then the Fuentes-Castaneda hard part (eprint 2015/192
   Alg. 10) with gnark's Expt chain for z = 0x44e992b44a6909f1, matching
   the scalar fd_bn254_final_exp.c.  Frobenius uses the dense gamma1/
   gamma2 constants.  Part of the BN254 unity TU. */

#if FD_HAS_AVX512

static void
bn254_fp12_conjugate( vroom_fp12_t *       out,
                      vroom_fp12_t const * in ) {
  /* a+b*w -> a-b*w: negate the w-coefficients (slots 6..11). */
  *out = *in;
  for( int i=6; i<12; i++ ) vroom_fp_neg( &out->c[i], &out->c[i] );
}

/* Fp12 frobenius x -> x^p.  In the flat basis c[6w+2v+u]: conjugate each
   Fp2 coefficient, then scale the (w,v) component by gamma1_k where
   k = 2v + 3w - ... following Alg. 28 of eprint 2010/354: coefficient of
   v^j is scaled by gamma1_{2j} and of w*v^j by gamma1_{2j+1}. */
static void
bn254_fp12_frob( vroom_fp12_t *       out,
                 vroom_fp12_t const * in ) {
  static const int gidx[6] = { 0, 2, 4, 1, 3, 5 }; /* gamma1 index per (w,v) slot, 0 = none */
  vroom_fp2_t g[6];
  g[1].c[0] = VROOM_FP_CONST( gamma1_1_re ); g[1].c[1] = VROOM_FP_CONST( gamma1_1_im );
  g[2].c[0] = VROOM_FP_CONST( gamma1_2_re ); g[2].c[1] = VROOM_FP_CONST( gamma1_2_im );
  g[3].c[0] = VROOM_FP_CONST( gamma1_3_re ); g[3].c[1] = VROOM_FP_CONST( gamma1_3_im );
  g[4].c[0] = VROOM_FP_CONST( gamma1_4_re ); g[4].c[1] = VROOM_FP_CONST( gamma1_4_im );
  g[5].c[0] = VROOM_FP_CONST( gamma1_5_re ); g[5].c[1] = VROOM_FP_CONST( gamma1_5_im );
  for( int s=0; s<6; s++ ) {       /* s = 3*w + v slot index: c[2s], c[2s+1] */
    int w_deg = s/3, v_deg = s%3;
    int flat  = 6*w_deg + 2*v_deg;
    vroom_fp2_t conj;
    conj.c[0] = in->c[flat];
    vroom_fp_neg( &conj.c[1], &in->c[flat+1] );
    int k = gidx[s];
    if( k ) {
      vroom_fp2_t r;
      vroom_fp2_mul( &r, &conj, &g[k] );
      out->c[flat]   = r.c[0];
      out->c[flat+1] = r.c[1];
    } else {
      out->c[flat]   = conj.c[0];
      out->c[flat+1] = conj.c[1];
    }
  }
}

/* Fp12 frobenius^2: scale by the Fp gamma2 constants (no conjugation). */
static void
bn254_fp12_frob2( vroom_fp12_t *       out,
                  vroom_fp12_t const * in ) {
  static const int gidx[6] = { 0, 2, 4, 1, 3, 5 };
  vroom_fp_t g[6];
  g[1] = VROOM_FP_CONST( gamma2_1 );
  g[2] = VROOM_FP_CONST( gamma2_2 );
  g[3] = VROOM_FP_CONST( gamma2_3 );
  g[4] = VROOM_FP_CONST( gamma2_4 );
  g[5] = VROOM_FP_CONST( gamma2_5 );
  for( int s=0; s<6; s++ ) {
    int w_deg = s/3, v_deg = s%3;
    int flat  = 6*w_deg + 2*v_deg;
    int k = gidx[s];
    if( k ) {
      vroom_fp_mul( &out->c[flat],   &in->c[flat],   &g[k] );
      vroom_fp_mul( &out->c[flat+1], &in->c[flat+1], &g[k] );
    } else {
      out->c[flat]   = in->c[flat];
      out->c[flat+1] = in->c[flat+1];
    }
  }
}

/* x^z for z = 0x44e992b44a6909f1: gnark's Expt addition chain
   (fd_bn254_fp12_pow_x), cyclotomic squarings throughout. */
static void
bn254_fp12_pow_x( vroom_fp12_t * restrict r,
                  vroom_fp12_t const *    a ) {
  vroom_fp12_t t[7];
  vroom_fp12_cyclotomic_sqr( &t[3], a );
  vroom_fp12_cyclotomic_sqr( &t[5], &t[3] );
  vroom_fp12_cyclotomic_sqr( r,     &t[5] );
  vroom_fp12_cyclotomic_sqr( &t[0], r );
  vroom_fp12_mul( &t[2], &t[0], a );
  vroom_fp12_mul( &t[0], &t[2], &t[3] );
  vroom_fp12_mul( &t[1], &t[0], a );
  vroom_fp12_mul( &t[4], &t[2], r );
  vroom_fp12_cyclotomic_sqr( &t[6], &t[2] );
  vroom_fp12_mul( &t[1], &t[1], &t[0] );
  vroom_fp12_mul( &t[0], &t[1], &t[3] );
  for( int i=0; i<6; i++ ) vroom_fp12_cyclotomic_sqr( &t[6], &t[6] );
  vroom_fp12_mul( &t[5], &t[5], &t[6] );
  vroom_fp12_mul( &t[5], &t[5], &t[4] );
  for( int i=0; i<7; i++ ) vroom_fp12_cyclotomic_sqr( &t[5], &t[5] );
  vroom_fp12_mul( &t[4], &t[4], &t[5] );
  for( int i=0; i<8; i++ ) vroom_fp12_cyclotomic_sqr( &t[4], &t[4] );
  vroom_fp12_mul( &t[4], &t[4], &t[0] );
  vroom_fp12_mul( &t[3], &t[3], &t[4] );
  for( int i=0; i<6; i++ ) vroom_fp12_cyclotomic_sqr( &t[3], &t[3] );
  vroom_fp12_mul( &t[2], &t[2], &t[3] );
  for( int i=0; i<8; i++ ) vroom_fp12_cyclotomic_sqr( &t[2], &t[2] );
  vroom_fp12_mul( &t[2], &t[2], &t[0] );
  for( int i=0; i<6; i++ ) vroom_fp12_cyclotomic_sqr( &t[2], &t[2] );
  vroom_fp12_mul( &t[2], &t[2], &t[0] );
  for( int i=0; i<10; i++ ) vroom_fp12_cyclotomic_sqr( &t[2], &t[2] );
  vroom_fp12_mul( &t[1], &t[1], &t[2] );
  for( int i=0; i<6; i++ ) vroom_fp12_cyclotomic_sqr( &t[1], &t[1] );
  vroom_fp12_mul( &t[0], &t[0], &t[1] );
  vroom_fp12_mul( r, r, &t[0] );
}

/* out = x^((p^12-1)/r), matching fd_bn254_final_exp. */
static void
bn254_final_exp( vroom_fp12_t *       out,
                 vroom_fp12_t const * x ) {
  vroom_fp12_t t[5], s[1];
  bn254_fp12_conjugate( &t[0], x );        /* x^(p^6)          */
  vroom_fp12_inverse( &t[1], x );          /* x^-1             */
  vroom_fp12_mul( &t[0], &t[0], &t[1] );   /* x^(p^6-1)        */
  bn254_fp12_frob2( &t[2], &t[0] );        /* ^(p^2)           */
  vroom_fp12_mul( s, &t[0], &t[2] );       /* x^((p^6-1)(p^2+1)) */

  bn254_fp12_pow_x( &t[0], s );
  bn254_fp12_conjugate( &t[0], &t[0] );
  vroom_fp12_cyclotomic_sqr( &t[0], &t[0] );
  vroom_fp12_cyclotomic_sqr( &t[1], &t[0] );
  vroom_fp12_mul( &t[1], &t[1], &t[0] );

  bn254_fp12_pow_x( &t[2], &t[1] );
  bn254_fp12_conjugate( &t[2], &t[2] );
  bn254_fp12_conjugate( &t[3], &t[1] );
  vroom_fp12_mul( &t[1], &t[2], &t[3] );

  vroom_fp12_cyclotomic_sqr( &t[3], &t[2] );
  bn254_fp12_pow_x( &t[4], &t[3] );
  vroom_fp12_mul( &t[4], &t[1], &t[4] );
  vroom_fp12_mul( &t[3], &t[0], &t[4] );
  vroom_fp12_mul( &t[0], &t[2], &t[4] );
  vroom_fp12_mul( &t[0], &t[0], s );

  bn254_fp12_frob( &t[2], &t[3] );
  vroom_fp12_mul( &t[0], &t[0], &t[2] );
  bn254_fp12_frob2( &t[2], &t[4] );
  vroom_fp12_mul( &t[0], &t[0], &t[2] );

  bn254_fp12_conjugate( &t[2], s );
  vroom_fp12_mul( &t[2], &t[2], &t[3] );
  bn254_fp12_frob2( &t[2], &t[2] );        /* frob3 = frob2 o frob */
  bn254_fp12_frob( &t[2], &t[2] );
  vroom_fp12_mul( out, &t[0], &t[2] );
}

#endif /* FD_HAS_AVX512 */
