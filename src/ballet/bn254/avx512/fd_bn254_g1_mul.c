/* BN254 G1 GLV scalar multiplication over the VROOM engine.  The GLV
   scalar decomposition (fd_bn254_glv.h helpers and lattice constants)
   is reused from the scalar backend; point arithmetic runs on the
   complete Fp projective formulas.  Part of the BN254 unity TU. */

#if FD_HAS_AVX512

/* Complete homogeneous doubling over Fp (vroom_ec_double specialized to
   the base field; 3b hook = vroom_fp_mul_3b_g1).  p = (X:Y:Z) column
   vector acc[3]. */
static void
bn254_g1_double( vroom_fp_t p[3] ) {
  vroom_fp_wide_t w1[4];
  vroom_fp_wide_mul_raw( &w1[0], &p[1], &p[1] ); /* Y^2. */
  vroom_fp_wide_mul_raw( &w1[1], &p[2], &p[2] ); /* Z^2. */
  vroom_fp_wide_mul_raw( &w1[2], &p[0], &p[1] ); /* X*Y. */
  vroom_fp_wide_mul_raw( &w1[3], &p[1], &p[2] ); /* Y*Z. */
  vroom_fp_t r1[4];
  vroom_fp_reduce_wide_batch4( r1, w1 );
  vroom_fp_t const * yy=&r1[0], * zz=&r1[1], * xy=&r1[2], * yz=&r1[3];

  vroom_fp_t eight_yy, b3_zz, yy_plus_b3, b9_zz, yy_minus_b9, two_xy;
  vroom_fp_mul_small( &eight_yy, yy, 8U );
  vroom_fp_mul_3b_g1( &b3_zz, zz );
  vroom_fp_add( &yy_plus_b3, yy, &b3_zz );
  vroom_fp_mul_small( &b9_zz, &b3_zz, 3U );
  vroom_fp_sub( &yy_minus_b9, yy, &b9_zz );
  vroom_fp_mul_small( &two_xy, xy, 2U );

  vroom_fp_wide_t w2[3];
  vroom_fp_wide_offset( &w2[0] );
  vroom_fp_wide_addmul( &w2[0], &yy_minus_b9, &yy_plus_b3 ); /* Y3 ... */
  vroom_fp_wide_addmul( &w2[0], &eight_yy, &b3_zz );
  vroom_fp_wide_mul_raw( &w2[1], &yy_minus_b9, &two_xy );    /* X3 */
  vroom_fp_wide_mul_raw( &w2[2], &eight_yy, yz );            /* Z3 */
  vroom_fp_t r2[3];
  vroom_fp_reduce_wide_batch3( r2, w2 );
  p[0]=r2[1]; p[1]=r2[0]; p[2]=r2[2];
}

/* r = [s]P for an affine P = (x, y) in RNS, with the scalar handled
   exactly as fd_bn254_g1_scalar_mul: GLV split of the raw (unreduced)
   256-bit scalar, then a Shamir double-and-add over {P, phi(P), P+phi(P)}.
   Result is left projective in r[3]; the zero result has Z = 0. */
static void
bn254_g1_mul_rns( vroom_fp_t                r[3],
                  vroom_fp_t const          px[2], /* x, y */
                  fd_bn254_scalar_t const * s ) {
  ulong b1[3];
  ulong b2[2];
  fd_bn254_glv_sxg3( b1, s, g1_const_g1 );
  fd_bn254_glv_sxg2( b2, s, g2_const );

  /* k1 = s - b1*N_A - b2*N_B (always non-negative for G1) */
  fd_uint256_t k1[1];
  {
    ulong p11[4];
    ulong p21[4] = {0};
    ulong t[4];
    fd_bn254_glv_mul3x2( p11, b1, na );
    fd_bn254_glv_mul2x1( p21, b2, nb );
    fd_bn254_glv_add4( t, p11, p21 );
    fd_bn254_glv_sub4( k1->limbs, s->limbs, t );
  }

  /* k2 = b1*N_B - b2*N_C (may be negative) */
  fd_uint256_t k2_abs[1];
  int k2_neg = 0;
  {
    ulong pos[4], neg[4];
    fd_bn254_glv_mul3x1( pos, b1, nb );
    fd_bn254_glv_mul2x2( neg, b2, nc );
    ulong borrow = fd_bn254_glv_sub4( k2_abs->limbs, pos, neg );
    if( borrow ) {
      k2_neg = 1;
      fd_bn254_glv_negate4( k2_abs->limbs );
    }
  }

  /* pt2 = phi(P) = (beta*x, +-y) affine. */
  vroom_fp_t beta = VROOM_FP_CONST( glv_beta );
  vroom_fp_t pt2[2];
  vroom_fp_mul( &pt2[0], &px[0], &beta );
  if( k2_neg ) vroom_fp_neg( &pt2[1], &px[1] );
  else         pt2[1] = px[1];

  /* pt12 = P + pt2, kept projective (complete formulas, no edge cases). */
  vroom_fp_t pt12[3];
  pt12[0] = px[0]; pt12[1] = px[1]; vroom_fp_one( &pt12[2] );
  vroom_g1_mixed_add( pt12, pt2 );

  /* Shamir ladder. */
  int i = 255;
  int have = 0;
  for( ; i>=0; i-- ) {
    int k1b = !!fd_uint256_bit( k1, i );
    int k2b = !!fd_uint256_bit( k2_abs, i );
    if( k1b || k2b ) {
      if( k1b && k2b )      { r[0]=pt12[0]; r[1]=pt12[1]; r[2]=pt12[2]; }
      else if( k1b )        { r[0]=px[0];   r[1]=px[1];   vroom_fp_one( &r[2] ); }
      else                  { r[0]=pt2[0];  r[1]=pt2[1];  vroom_fp_one( &r[2] ); }
      have = 1;
      break;
    }
  }
  if( FD_UNLIKELY( !have ) ) {
    vroom_fp_zero( &r[0] ); vroom_fp_zero( &r[1] ); vroom_fp_zero( &r[2] );
    return;
  }
  for( i--; i>=0; i-- ) {
    bn254_g1_double( r );
    int k1b = !!fd_uint256_bit( k1, i );
    int k2b = !!fd_uint256_bit( k2_abs, i );
    if( k1b && k2b )      vroom_g1_proj_add( r, pt12 );
    else if( k1b )        vroom_g1_mixed_add( r, px );
    else if( k2b )        vroom_g1_mixed_add( r, pt2 );
  }
}

#endif /* FD_HAS_AVX512 */
