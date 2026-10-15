/* BN254 G2 operations over the VROOM engine: psi on projective points,
   the Scott subgroup check (eprint 2022/348 Sec 3.1), and GLV scalar
   multiplication.  The GLV scalar decomposition is reused from the
   scalar backend (fd_bn254_glv.h); only the point arithmetic runs on
   vroom.  Part of the BN254 unity TU. */

#if FD_HAS_AVX512

/* psi on a homogeneous projective point: conjugate all coordinates,
   scale X by gamma1_2 and Y by gamma1_3 (fd_bn254_g2_frob, which is
   coordinate-system agnostic since it is componentwise). */
static void
bn254_g2_psi_proj( vroom_p2_projective_t *       out,
                   vroom_p2_projective_t const * p ) {
  vroom_fp2_t xc = p->x, yc = p->y, zc = p->z;
  vroom_fp_neg( &xc.c[1], &xc.c[1] );
  vroom_fp_neg( &yc.c[1], &yc.c[1] );
  vroom_fp_neg( &zc.c[1], &zc.c[1] );
  bn254_psi_affine( &out->x, &out->y, &p->x, &p->y ); /* conj+scale x,y */
  out->z = zc;
}

/* psi^2 on a projective point: componentwise Fp scaling, Z unchanged. */
static void
bn254_g2_psi2_proj( vroom_p2_projective_t *       out,
                    vroom_p2_projective_t const * p ) {
  bn254_psi2_affine( &out->x, &out->y, &p->x, &p->y );
  out->z = p->z;
}

/* Projective equality: X1*Z2 == X2*Z1 and Y1*Z2 == Y2*Z1.  Both sides
   must be valid representatives (Z may be zero only for infinity). */
static int
bn254_g2_proj_eq( vroom_p2_projective_t const * p,
                  vroom_p2_projective_t const * q ) {
  vroom_fp2_wide_t w[4];
  vroom_fp2_wide_set_mul( &w[0], &p->x, &q->z );
  vroom_fp2_wide_set_mul( &w[1], &q->x, &p->z );
  vroom_fp2_wide_set_mul( &w[2], &p->y, &q->z );
  vroom_fp2_wide_set_mul( &w[3], &q->y, &p->z );
  vroom_fp2_t r[4];
  vroom_fp2_reduce_batch4( r, w );
  return vroom_fp2_equal( &r[0], &r[1] ) & vroom_fp2_equal( &r[2], &r[3] );
}

/* [k]Q for a 64-bit scalar on an affine base, plain double-and-add MSB
   first (variable time; inputs are public). */
static vroom_p2_projective_t
bn254_g2_mul_u64_affine( vroom_fp2_t const * qx,
                         vroom_fp2_t const * qy,
                         ulong               k ) {
  /* k is fixed to the BN parameter in practice (never 0/1). */
  int top = 63 - __builtin_clzl( k );
  vroom_p2_projective_t r = { .x = *qx, .y = *qy };
  vroom_fp2_one( &r.z );
  int first = 1;
  for( int i=top-1; i>=0; i-- ) {
    r = vroom_ec_double( &r, first );
    first = 0;
    if( (k>>i) & 1UL ) r = vroom_ec_add_pa( &r, qx, qy );
  }
  return r;
}

/* Scott subgroup check (eprint 2022/348 Sec 3.1), matching the scalar
   fd_bn254_g2_frombytes_check_subgroup:
     [x+1]Q + psi([x]Q) + psi^2([x]Q) == psi^3([2x]Q)
   Input is an affine on-curve point (not infinity). */
static int
bn254_g2_in_subgroup( vroom_fp2_t const * qx,
                      vroom_fp2_t const * qy ) {
  vroom_p2_projective_t xq = bn254_g2_mul_u64_affine( qx, qy, 0x44e992b44a6909f1UL );

  vroom_p2_projective_t l = vroom_ec_add_pa( &xq, qx, qy );  /* [x+1]Q */
  vroom_p2_projective_t psi1, psi2, psi3, r;
  bn254_g2_psi_proj( &psi1, &xq );
  l = vroom_ec_add_pp( &l, &psi1 );
  bn254_g2_psi2_proj( &psi2, &xq );
  l = vroom_ec_add_pp( &l, &psi2 );

  bn254_g2_psi_proj( &psi3, &psi2 );          /* psi^3([x]Q) */
  r = vroom_ec_double( &psi3, 0 );            /* psi^3([2x]Q) */
  return bn254_g2_proj_eq( &l, &r );
}

/* r = [s]Q for an affine Q = (x, y) in RNS, matching the scalar
   fd_bn254_g2_scalar_mul: GLV split, then Shamir double-and-add over
   {Q', phi(Q)', Q'+phi(Q)'} with per-half sign folding. */
static vroom_p2_projective_t
bn254_g2_mul_rns( vroom_fp2_t const *       qx,
                  vroom_fp2_t const *       qy,
                  fd_bn254_scalar_t const * s ) {
  vroom_p2_projective_t r;
  ulong b1[3], b2[2];
  fd_bn254_glv_sxg3( b1, s, g1_const_g2 );
  fd_bn254_glv_sxg2( b2, s, g2_const );

  /* k1 = s - b1*N_C - b2*N_B (may be negative for G2) */
  fd_uint256_t k1_abs[1];
  int k1_neg = 0;
  {
    ulong p_nc[4];
    ulong p_nb[4] = {0};
    ulong t[4];
    fd_bn254_glv_mul3x2( p_nc, b1, nc );
    fd_bn254_glv_mul2x1( p_nb, b2, nb );
    fd_bn254_glv_add4( t, p_nc, p_nb );
    ulong borrow = fd_bn254_glv_sub4( k1_abs->limbs, s->limbs, t );
    if( borrow ) { k1_neg = 1; fd_bn254_glv_negate4( k1_abs->limbs ); }
  }

  /* k2 = b2*N_A - b1*N_B (usually negative for G2) */
  fd_uint256_t k2_abs[1];
  int k2_neg = 0;
  {
    ulong pos[4], neg[4];
    fd_bn254_glv_mul2x2( pos, b2, na );
    fd_bn254_glv_mul3x1( neg, b1, nb );
    ulong borrow = fd_bn254_glv_sub4( k2_abs->limbs, pos, neg );
    if( borrow ) { k2_neg = 1; fd_bn254_glv_negate4( k2_abs->limbs ); }
  }

  /* pt1 = +-Q, pt2 = +-phi(Q) = (beta*x, +-y), both affine. */
  vroom_fp_t beta = VROOM_FP_CONST( glv_beta );
  vroom_fp2_t pt1x = *qx, pt1y = *qy, pt2x, pt2y;
  vroom_fp_mul( &pt2x.c[0], &qx->c[0], &beta );
  vroom_fp_mul( &pt2x.c[1], &qx->c[1], &beta );
  pt2y = *qy;
  if( k1_neg ) vroom_fp2_neg( &pt1y, &pt1y );
  if( k2_neg ) vroom_fp2_neg( &pt2y, &pt2y );

  /* pt12 = pt1 + pt2, kept projective. */
  vroom_p2_projective_t pt12 = { .x = pt1x, .y = pt1y };
  vroom_fp2_one( &pt12.z );
  pt12 = vroom_ec_add_pa( &pt12, &pt2x, &pt2y );

  int i = 255;
  int have = 0;
  for( ; i>=0; i-- ) {
    int k1b = !!fd_uint256_bit( k1_abs, i );
    int k2b = !!fd_uint256_bit( k2_abs, i );
    if( k1b || k2b ) {
      if( k1b && k2b ) r = pt12;
      else {
        r.x = k1b ? pt1x : pt2x;
        r.y = k1b ? pt1y : pt2y;
        vroom_fp2_one( &r.z );
      }
      have = 1;
      break;
    }
  }
  if( FD_UNLIKELY( !have ) ) {
    vroom_fp2_one( &r.x ); vroom_fp2_one( &r.y );
    vroom_fp_zero( &r.z.c[0] ); vroom_fp_zero( &r.z.c[1] ); /* infinity: Z=0 */
    return r;
  }
  for( i--; i>=0; i-- ) {
    r = vroom_ec_double( &r, 0 );
    int k1b = !!fd_uint256_bit( k1_abs, i );
    int k2b = !!fd_uint256_bit( k2_abs, i );
    if( k1b && k2b )      r = vroom_ec_add_pp( &r, &pt12 );
    else if( k1b )        r = vroom_ec_add_pa( &r, &pt1x, &pt1y );
    else if( k2b )        r = vroom_ec_add_pa( &r, &pt2x, &pt2y );
  }
  return r;
}

#endif /* FD_HAS_AVX512 */

