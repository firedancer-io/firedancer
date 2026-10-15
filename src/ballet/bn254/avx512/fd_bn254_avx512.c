/* BN254 AVX-512 backend entry points.  Inputs arrive as validated
   affine points in fd_bn254's 4x64 Montgomery form (the byte parsing,
   flag handling and curve-equation checks stay in the portable code);
   subgroup checks for the pairing and G2 paths happen here, matching
   where the reference backend performs them.  Part of the BN254 TU. */

#if FD_HAS_AVX512

/* One iff q (affine, on-curve, not infinity) is in the order-r subgroup. */
int
fd_bn254_avx512_g2_in_subgroup( fd_bn254_g2_t const * q ) {
  vroom_fp2_t qx, qy;
  bn254_fp2_enter( &qx, &q->X );
  bn254_fp2_enter( &qy, &q->Y );
  return bn254_g2_in_subgroup( &qx, &qy );
}

/* GT product of the already-validated affine pairs; one iff it is 1.
   Mirrors the reference loop: batches of FD_BN254_PAIRING_BATCH_MAX
   Miller products folded into one accumulator, one final exponentiation. */
int
fd_bn254_avx512_pairing_is_one( fd_bn254_g1_t const * p,
                                fd_bn254_g2_t const * q,
                                ulong                 sz ) {
  vroom_fp12_t r;
  vroom_fp12_one( &r );
  bn254_miller_state_t st[ BN254_MILLER_BATCH_MAX ];
  ulong batch = 0UL;
  for( ulong i=0UL; i<sz; i++ ) {
    bn254_fp_enter( &st[batch].e1x, &p[i].X );
    bn254_fp_enter( &st[batch].e1y, &p[i].Y );
    bn254_fp2_enter( &st[batch].e2x, &q[i].X );
    bn254_fp2_enter( &st[batch].e2y, &q[i].Y );
    st[batch].r.x = st[batch].e2x;
    st[batch].r.y = st[batch].e2y;
    vroom_fp2_one( &st[batch].r.z );
    batch++;
    if( batch==BN254_MILLER_BATCH_MAX ) {
      vroom_fp12_t tmp;
      bn254_miller_loop_n( &tmp, st, batch );
      vroom_fp12_mul( &r, &r, &tmp );
      batch = 0UL;
    }
  }
  if( batch ) {
    vroom_fp12_t tmp;
    bn254_miller_loop_n( &tmp, st, batch );
    vroom_fp12_mul( &r, &r, &tmp );
  }
  bn254_final_exp( &r, &r );
  return vroom_fp12_is_one( &r );
}

/* r = [s]p (p affine, s raw 256-bit little-endian scalar, unreduced).
   Result in Jacobian form matching fd_bn254_g1_scalar_mul's contract
   (fd_bn254_g1_tobytes affinizes; Z == 0 encodes infinity).  The
   homogeneous projective (X:Y:Z) rescales to Jacobian as
   (X*Z : Y*Z^2 : Z). */
void
fd_bn254_avx512_g1_scalar_mul( fd_bn254_g1_t *           r,
                               fd_bn254_g1_t const *     p,
                               fd_bn254_scalar_t const * s ) {
  if( FD_UNLIKELY( fd_uint256_is_zero( s ) || fd_bn254_g1_is_zero( p ) ) ) {
    fd_bn254_fp_set_zero( &r->Z );
    return;
  }
  vroom_fp_t a[2], acc[3];
  bn254_fp_batch_enter( a, &p->X, 1 );
  bn254_fp_batch_enter( a+1, &p->Y, 1 );
  bn254_g1_mul_rns( acc, a, s );

  vroom_fp_t xj, yj, zs;
  vroom_fp_mul( &xj, &acc[0], &acc[2] );
  vroom_fp_mul( &zs, &acc[2], &acc[2] );
  vroom_fp_mul( &yj, &acc[1], &zs );
  bn254_fp_exit( &r->X, &xj );
  bn254_fp_exit( &r->Y, &yj );
  bn254_fp_exit( &r->Z, &acc[2] );
}

/* r = [s]q (q affine, in-subgroup), Jacobian out, Z == 0 for infinity. */
void
fd_bn254_avx512_g2_scalar_mul( fd_bn254_g2_t *           r,
                               fd_bn254_g2_t const *     q,
                               fd_bn254_scalar_t const * s ) {
  if( FD_UNLIKELY( fd_uint256_is_zero( s ) || fd_bn254_g2_is_zero( q ) ) ) {
    fd_bn254_fp2_set_zero( &r->Z );
    return;
  }
  vroom_fp2_t qx, qy;
  bn254_fp2_enter( &qx, &q->X );
  bn254_fp2_enter( &qy, &q->Y );
  vroom_p2_projective_t acc = bn254_g2_mul_rns( &qx, &qy, s );

  vroom_fp2_wide_t w[2];
  vroom_fp2_wide_set_mul( &w[0], &acc.x, &acc.z );   /* X*Z   */
  vroom_fp2_wide_set_mul( &w[1], &acc.z, &acc.z );   /* Z^2   */
  vroom_fp2_t t[2];
  vroom_fp2_reduce_batch2( t, w );
  vroom_fp2_t yj;
  vroom_fp2_mul( &yj, &acc.y, &t[1] );               /* Y*Z^2 */
  bn254_fp2_exit( &r->X, &t[0] );
  bn254_fp2_exit( &r->Y, &yj );
  bn254_fp2_exit( &r->Z, &acc.z );
}

/* Test support: raw Miller product for n pairs, exported in
   fd_bn254 Montgomery Fp12 layout (el[i].el[j].el[k] = c[6i+2j+k]). */
void
fd_bn254_avx512_miller_diff( fd_bn254_fp12_t *     out,
                            fd_bn254_g1_t const * p,
                            fd_bn254_g2_t const * q,
                            ulong                 sz ) {
  bn254_miller_state_t st[ BN254_MILLER_BATCH_MAX ];
  for( ulong i=0UL; i<sz; i++ ) {
    bn254_fp_enter( &st[i].e1x, &p[i].X );
    bn254_fp_enter( &st[i].e1y, &p[i].Y );
    bn254_fp2_enter( &st[i].e2x, &q[i].X );
    bn254_fp2_enter( &st[i].e2y, &q[i].Y );
    st[i].r.x = st[i].e2x;
    st[i].r.y = st[i].e2y;
    vroom_fp2_one( &st[i].r.z );
  }
  vroom_fp12_t f;
  bn254_miller_loop_n( &f, st, sz );
  for( int w=0; w<2; w++ )
    for( int v=0; v<3; v++ )
      for( int u=0; u<2; u++ ) {
        vroom_fp_t const * c = &f.c[6*w+2*v+u];
        bn254_fp_exit( &out->el[w].el[v].el[u], c );
      }
}

/* Test support: run one fp12 op on a Montgomery fp12 and export.
   op: 0=final_exp, 1=cyclotomic_sqr, 2=frob, 3=frob2, 4=inverse,
   5=mul(a,a), 6=sqr. */
void
fd_bn254_avx512_fp12_diff( fd_bn254_fp12_t *       out,
                          fd_bn254_fp12_t const * in,
                          int                     op ) {
  vroom_fp12_t a, r;
  for( int w=0; w<2; w++ )
    for( int v=0; v<3; v++ )
      for( int u=0; u<2; u++ )
        bn254_fp_enter( &a.c[6*w+2*v+u], &in->el[w].el[v].el[u] );
  switch( op ) {
  case 0: bn254_final_exp( &r, &a ); break;
  case 1: vroom_fp12_cyclotomic_sqr( &r, &a ); break;
  case 2: bn254_fp12_frob( &r, &a ); break;
  case 3: bn254_fp12_frob2( &r, &a ); break;
  case 4: vroom_fp12_inverse( &r, &a ); break;
  case 5: vroom_fp12_mul( &r, &a, &a ); break;
  default: vroom_fp12_sqr( &r, &a ); break;
  }
  for( int w=0; w<2; w++ )
    for( int v=0; v<3; v++ )
      for( int u=0; u<2; u++ )
        bn254_fp_exit( &out->el[w].el[v].el[u], &r.c[6*w+2*v+u] );
}

#endif /* FD_HAS_AVX512 */
