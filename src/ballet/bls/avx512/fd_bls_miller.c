/* BLS12-381 Miller loop, line evaluation, and the prepared-G2
   (precomputed lines) variant.  Part of the BLS unity TU. */

#if FD_HAS_AVX512

typedef struct {
  vroom_p2_projective_t r;
  vroom_fp_t            e1x, e1y, three_e1x, minus_two_e1y;
  vroom_fp2_t           e2x, e2y;
} fd_bls_miller_state_t;

/* Addition chain for -z=0xd201000000010000: start at 2Q, then repeatedly
   add Q and double by the listed count. */
static uint const vroom_miller_iterations[5] = { 2U, 3U, 9U, 32U, 16U };

#define FD_BLS_MILLER_PREPARED_LINE_CNT (1UL + 5UL + 2UL + 3UL + 9UL + 32UL + 16UL)

typedef struct {
  vroom_fp2_t c;
  vroom_fp2_t x;
  vroom_fp2_t y;
} vroom_prepared_line_t;

typedef struct {
  vroom_prepared_line_t line[ FD_BLS_MILLER_PREPARED_LINE_CNT ];
} fd_bls_g2_prepared_private_t;

FD_STATIC_ASSERT( sizeof(fd_bls_g2_prepared_private_t)==FD_BLS_G2_PREPARED_FOOTPRINT,
                  bls_avx512_g2_prepared_footprint );
FD_STATIC_ASSERT( alignof(fd_bls_g2_prepared_private_t)<=FD_BLS_G2_PREPARED_ALIGN,
                  bls_avx512_g2_prepared_alignment );

/* Scott's G2 subgroup relation is psi(Q)=[z]Q.  The Miller chain below
   already leaves state->r=[-z]Q, so checking the relation only needs psi
   and a projective equality instead of another 64-bit scalar multiply. */
static int
miller_state_q_in_g2( fd_bls_miller_state_t const * state ) {
  vroom_fp2_t x_conj = state->e2x;
  vroom_fp2_t y_conj = state->e2y;
  vroom_fp_neg( &x_conj.c[1], &x_conj.c[1] ); /* x_conj = xQ^p, since u^p=-u. */
  vroom_fp_neg( &y_conj.c[1], &y_conj.c[1] ); /* y_conj = yQ^p.                 */

  vroom_fp2_t frob_x, frob_y, psi_x, psi_y;
  vroom_fp_zero( &frob_x.c[0] );
  frob_x.c[1] = VROOM_FP_CONST( frob1_3 );
  frob_y.c[0] = VROOM_FP_CONST( frob3_2 );
  frob_y.c[1] = VROOM_FP_CONST( frob3_3 );
  vroom_fp2_mul( &psi_x, &x_conj, &frob_x ); /* psi_x = xQ^p*xi^((1-p)/3). */
  vroom_fp2_mul( &psi_y, &y_conj, &frob_y ); /* psi_y = yQ^p*xi^((1-p)/2). */

  /* The complete Algorithm 8/9 formulas use homogeneous projective
     coordinates (x=X/Z, y=Y/Z), not Jacobian coordinates. */
  vroom_fp2_t rhs_x, rhs_y;
  vroom_fp2_mul( &rhs_x, &psi_x, &state->r.z ); /* rhs_x = psi_x*Z, the homogeneous X coordinate. */
  vroom_fp2_mul( &rhs_y, &psi_y, &state->r.z ); /* rhs_y = psi_y*Z, the homogeneous Y coordinate. */
  vroom_fp2_neg( &rhs_y, &rhs_y );              /* rhs  = -psi(Q)=[-z]Q, which must equal R.     */
  return vroom_fp2_equal( &state->r.x, &rhs_x ) & vroom_fp2_equal( &state->r.y, &rhs_y );
}

static inline void
fp12_conjugate( vroom_fp12_t * out ) {
  /* The p^6-Frobenius is a+b*w -> a-b*w because w^2=v. */
  for( int i=6; i<12; i++ ) vroom_fp_neg( &out->c[i], &out->c[i] );
}

static inline void
fp12_set_line( vroom_fp12_t * out,
               vroom_fp_t const line[6] ) {
  /* Embed the evaluated line as c + x*v + y*w*v in the Fp12 tower. */
  for( int i=0; i<12; i++ ) vroom_fp_zero( &out->c[i] );
  out->c[0]=line[0]; out->c[1]=line[1]; out->c[2]=line[2];
  out->c[3]=line[3]; out->c[8]=line[4]; out->c[9]=line[5];
}

static inline void
miller_g1_init( vroom_fp_t *             e1x,
                vroom_fp_t *             e1y,
                vroom_fp_t *             three_e1x,
                vroom_fp_t *             minus_two_e1y,
                fd_bls_g1_t const * p ) {
  if( FD_UNLIKELY( !memcmp( p->x, vroom_neg_g1_x_normal, sizeof(p->x) ) &&
                           !memcmp( p->y, vroom_neg_g1_y_normal, sizeof(p->y) ) ) ) {
    *e1x           = VROOM_FP_CONST( neg_g1_x );
    *e1y           = VROOM_FP_CONST( neg_g1_y );
    *three_e1x     = VROOM_FP_CONST( neg_g1_3x );
    *minus_two_e1y = VROOM_FP_CONST( neg_g1_minus_2y );
  } else {
    vroom_fp_from_normal( e1x, p->x );
    vroom_fp_from_normal( e1y, p->y );
    vroom_fp_mul_small( three_e1x, e1x, 3U );
    vroom_fp_neg( minus_two_e1y, e1y );
    vroom_fp_mul_small( minus_two_e1y, minus_two_e1y, 2U );
  }
}

static inline void
miller_state_init( fd_bls_miller_state_t * state,
                   fd_bls_g1_t const *     p,
                   fd_bls_g2_t const *     q ) {
  miller_g1_init( &state->e1x, &state->e1y, &state->three_e1x,
                  &state->minus_two_e1y, p );
  vroom_fp2_from_normal( &state->e2x, q->x );
  vroom_fp2_from_normal( &state->e2y, q->y );
  state->r.x = state->e2x;
  state->r.y = state->e2y;
  vroom_fp2_one( &state->r.z );
}

/* [-z] ladder over an affine base, line-free: 2Q then the {2,3,9,32,16}
   add+double groups of -z = 0xd201000000010000. */
static vroom_p2_projective_t
ladder_minus_z_affine( vroom_fp2_t const * qx,
                       vroom_fp2_t const * qy ) {
  vroom_p2_projective_t r = { .x = *qx, .y = *qy };
  vroom_fp2_one( &r.z );
  r = vroom_ec_double( &r, 1 );
  for( int i=0; i<5; i++ ) {
    r = vroom_ec_add_pa( &r, qx, qy );
    for( uint j=0U; j<vroom_miller_iterations[i]; j++ )
      r = vroom_ec_double( &r, 0 );
  }
  return r;
}

/* The G2 state transition and the unevaluated line coefficients depend only
   on Q.  Preparing those once leaves just the two base-field evaluations at
   P for each subsequent pairing. */
static vroom_p2_projective_t
double_step_prepare( vroom_p2_projective_t const *  p,
                     vroom_prepared_line_t * prepared,
                     int                             first ) {
  vroom_fp2_t round1[5];
  if( FD_UNLIKELY( first ) ) {
    vroom_fp2_wide_t wide1[3];
    vroom_fp2_t reduced[3];
    vroom_fp2_wide_set_mul( &wide1[0], &p->x, &p->x ); /* wide1[0] = X^2. */
    vroom_fp2_wide_set_mul( &wide1[1], &p->y, &p->y ); /* wide1[1] = Y^2. */
    vroom_fp2_wide_set_mul( &wide1[2], &p->x, &p->y ); /* wide1[2] = X*Y. */
    vroom_fp2_reduce_batch3( reduced, wide1 );
    round1[0]=reduced[0]; round1[1]=reduced[1]; round1[2]=p->z; /* xx=X^2, yy=Y^2, zz=1. */
    round1[3]=reduced[2]; round1[4]=p->y;                       /* xy=X*Y, yz=Y.          */
  } else {
    vroom_fp2_wide_t wide1[5];
    vroom_fp2_wide_set_mul( &wide1[0], &p->x, &p->x ); /* wide1[0] = X^2. */
    vroom_fp2_wide_set_mul( &wide1[1], &p->y, &p->y ); /* wide1[1] = Y^2. */
    vroom_fp2_wide_set_mul( &wide1[2], &p->z, &p->z ); /* wide1[2] = Z^2. */
    vroom_fp2_wide_set_mul( &wide1[3], &p->x, &p->y ); /* wide1[3] = X*Y. */
    vroom_fp2_wide_set_mul( &wide1[4], &p->y, &p->z ); /* wide1[4] = Y*Z. */
    vroom_fp2_reduce_batch5( round1, wide1 );
  }
  vroom_fp2_t const * xx=&round1[0], * yy=&round1[1], * zz=&round1[2];
  vroom_fp2_t const * xy=&round1[3], * yz=&round1[4];

  vroom_fp2_t eight_yy, b3_zz, yy_plus_b3, b9_zz;
  vroom_fp2_t yy_minus_b9, two_xy;
  vroom_fp2_mul_small( &eight_yy, yy, 8U );                /* eight_yy    = 8Y^2.               */
  vroom_fp2_mul_3b( &b3_zz, zz );                          /* b3_zz       = 3bZ^2.              */
  vroom_fp2_sub( &prepared->c, &b3_zz, yy );        /* prepared.c = ell_0=3bZ^2-Y^2.   */
  prepared->x = *xx;                                 /* prepared.x = X^2; multiply by 3xP later. */
  prepared->y = *yz;                                 /* prepared.y = YZ;  multiply by -2yP later. */
  vroom_fp2_add( &yy_plus_b3, yy, &b3_zz );         /* yy_plus_b3   = Y^2+3bZ^2.          */
  vroom_fp2_mul_small( &b9_zz, &b3_zz, 3U );               /* b9ZZ       = 9bZ^2.              */
  vroom_fp2_sub( &yy_minus_b9, yy, &b9_zz );        /* yyMinusB9  = Y^2-9bZ^2.          */
  vroom_fp2_mul_small( &two_xy, xy, 2U );                  /* twoXY      = 2XY.                 */

  vroom_fp2_wide_t wide2[3];
  vroom_fp2_wide_set_mul( &wide2[0], &yy_minus_b9, &yy_plus_b3 ); /* Y3 = (Y^2-9bZ^2)(Y^2+3bZ^2) ... */
  vroom_fp2_wide_addmul( &wide2[0], &eight_yy, &b3_zz );          /* ... + (8Y^2)(3bZ^2).              */
  vroom_fp2_wide_set_mul( &wide2[1], &yy_minus_b9, &two_xy );     /* X3 = (Y^2-9bZ^2)(2XY).             */
  vroom_fp2_wide_set_mul( &wide2[2], &eight_yy, yz );             /* Z3 = (8Y^2)(YZ).                    */
  vroom_fp2_t round2[3];
  vroom_fp2_reduce_batch3( round2, wide2 );
  return (vroom_p2_projective_t){ round2[1], round2[0], round2[2] };
}

static vroom_p2_projective_t
add_step_prepare( vroom_p2_projective_t const *  p,
                  vroom_prepared_line_t * prepared,
                  vroom_fp2_t const *            e2x,
                  vroom_fp2_t const *            e2y ) {
  vroom_fp2_wide_t wide1[6];
  vroom_fp2_wide_set_mul( &wide1[0], e2x, &p->x ); /* wide1[0] = xQ*X. */
  vroom_fp2_wide_set_mul( &wide1[1], e2x, &p->y ); /* wide1[1] = xQ*Y. */
  vroom_fp2_wide_set_mul( &wide1[2], e2x, &p->z ); /* wide1[2] = xQ*Z. */
  vroom_fp2_wide_set_mul( &wide1[3], e2y, &p->x ); /* wide1[3] = yQ*X. */
  vroom_fp2_wide_set_mul( &wide1[4], e2y, &p->y ); /* wide1[4] = yQ*Y. */
  vroom_fp2_wide_set_mul( &wide1[5], e2y, &p->z ); /* wide1[5] = yQ*Z. */
  vroom_fp2_t round1[6];
  vroom_fp2_reduce_batch6( round1, wide1 );
  vroom_fp2_t const * x2x1=&round1[0], * x2y1=&round1[1], * x2z1=&round1[2];
  vroom_fp2_t const * y2x1=&round1[3], * y2y1=&round1[4], * y2z1=&round1[5];

  vroom_fp2_t x2y1_plus_y2x1, y2z1_plus_y1, x2z1_plus_x1, three_x2x1;
  vroom_fp2_t b3z1, y2y1_plus_b3, y2y1_minus_b3, b3_xsum;
  vroom_fp2_sub( &prepared->c, x2y1, y2x1 );               /* prepared.c = ell_0=xQ*Y-yQ*X. */
  vroom_fp2_sub( &prepared->x, y2z1, &p->y );              /* prepared.x = yQ*Z-Y; times xP later. */
  vroom_fp2_sub( &prepared->y, &p->x, x2z1 );              /* prepared.y = X-xQ*Z; times yP later. */
  vroom_fp2_add( &x2y1_plus_y2x1, x2y1, y2x1 );          /* xysum   = xQ*Y+yQ*X. */
  vroom_fp2_add( &y2z1_plus_y1, y2z1, &p->y );            /* yzsum   = yQ*Z+Y.    */
  vroom_fp2_add( &x2z1_plus_x1, x2z1, &p->x );            /* xzsum   = xQ*Z+X.    */
  vroom_fp2_mul_small( &three_x2x1, x2x1, 3U );                  /* threeXX = 3xQ*X.     */
  vroom_fp2_mul_3b( &b3z1, &p->z );                              /* b3Z     = 3bZ.       */
  vroom_fp2_add( &y2y1_plus_b3, y2y1, &b3z1 );           /* yp      = yQ*Y+3bZ.  */
  vroom_fp2_sub( &y2y1_minus_b3, y2y1, &b3z1 );          /* ym      = yQ*Y-3bZ.  */
  vroom_fp2_mul_3b( &b3_xsum, &x2z1_plus_x1 );                  /* bx      = 3b*xzsum.   */

  vroom_fp2_wide_t wide2[3];
  vroom_fp2_wide_set_mul( &wide2[0], &x2y1_plus_y2x1, &y2y1_minus_b3 ); /* X3 = xysum*ym ...  */
  vroom_fp2_wide_submul( &wide2[0], &b3_xsum, &y2z1_plus_y1 );          /* ... - bx*yzsum.     */
  vroom_fp2_wide_set_mul( &wide2[1], &b3_xsum, &three_x2x1 );           /* Y3 = bx*threeXX ...  */
  vroom_fp2_wide_addmul( &wide2[1], &y2y1_plus_b3, &y2y1_minus_b3 );   /* ... + yp*ym.        */
  vroom_fp2_wide_set_mul( &wide2[2], &y2y1_plus_b3, &y2z1_plus_y1 );   /* Z3 = yp*yzsum ...    */
  vroom_fp2_wide_addmul( &wide2[2], &x2y1_plus_y2x1, &three_x2x1 );    /* ... + xysum*threeXX. */
  vroom_fp2_t round2[3];
  vroom_fp2_reduce_batch3( round2, wide2 );
  return (vroom_p2_projective_t){ round2[0], round2[1], round2[2] };
}

static inline void
prepared_line_eval( vroom_fp_t                           out[6],
                    vroom_prepared_line_t const * prepared,
                    vroom_fp_t const *                   x,
                    vroom_fp_t const *                   y ) {
  vroom_fp2_wide_t wide[2];
  vroom_fp2_wide_set_mul_fp( &wide[0], &prepared->x, x ); /* evaluated[0] = ell_x*xP. */
  vroom_fp2_wide_set_mul_fp( &wide[1], &prepared->y, y ); /* evaluated[1] = ell_y*yP. */
  vroom_fp2_t evaluated[2];
  vroom_fp2_reduce_batch2( evaluated, wide );
  out[0]=prepared->c.c[0]; out[1]=prepared->c.c[1];
  out[2]=evaluated[0].c[0]; out[3]=evaluated[0].c[1];
  out[4]=evaluated[1].c[0]; out[5]=evaluated[1].c[1];
}

int
fd_bls_g2_prepare_avx512( fd_bls_g2_prepared_t * out,
                          fd_bls_g2_t const *    q ) {
  if( FD_UNLIKELY( !out || !q ) ) return -1;
  fd_bls_g2_prepared_private_t * prepared = (fd_bls_g2_prepared_private_t *)out;
  vroom_fp2_t e2x, e2y;
  vroom_fp2_from_normal( &e2x, q->x );
  vroom_fp2_from_normal( &e2y, q->y );
  vroom_p2_projective_t r = { .x=e2x, .y=e2y };
  vroom_fp2_one( &r.z );

  ulong line_idx = 0UL;
  r = double_step_prepare( &r, prepared->line+line_idx++, 1 ); /* R=2Q; save tangent ell_{Q,Q}. */
  for( int i=0; i<5; i++ ) {
    r = add_step_prepare( &r, prepared->line+line_idx++, &e2x, &e2y ); /* R<-R+Q; save secant ell_{R,Q}. */
    for( uint j=0U; j<vroom_miller_iterations[i]; j++ )
      r = double_step_prepare( &r, prepared->line+line_idx++, 0 ); /* R<-2R; save tangent ell_{R,R}. */
  }
  return line_idx==FD_BLS_MILLER_PREPARED_LINE_CNT ? 0 : -1;
}

int
fd_bls_pairing_finalverify_prepared_checked_avx512(
    fd_bls_g1_t const *          p_prepared,
    fd_bls_g2_prepared_t const * q_prepared,
    fd_bls_g1_t const *          p_checked,
    fd_bls_g2_t const *          q_checked ) {
  if( FD_UNLIKELY( !p_prepared || !q_prepared || !p_checked || !q_checked ) ) return -1;
  fd_bls_g2_prepared_private_t const * prepared = (fd_bls_g2_prepared_private_t const *)q_prepared;

  vroom_fp_t e1x, e1y, three_e1x, minus_two_e1y;
  miller_g1_init( &e1x, &e1y, &three_e1x, &minus_two_e1y, p_prepared );
  fd_bls_miller_state_t checked;
  miller_state_init( &checked, p_checked, q_checked );

  vroom_fp_t prepared_line[6], checked_line[6];
  ulong line_idx = 0UL;
  prepared_line_eval( prepared_line, prepared->line+line_idx++, &three_e1x, &minus_two_e1y ); /* lp=ell_{Qp,Qp}(Pp). */
  checked.r = vroom_ec_double_step( &checked.r, checked_line, &checked.three_e1x,
                           &checked.minus_two_e1y, 1 ); /* Rc=2Qc; lc=ell_{Qc,Qc}(Pc). */
  vroom_fp12_t product;
  fp12_set_line( &product, prepared_line );                         /* product = lp.    */
  vroom_fp12_mul_sparse( &product, &product, checked_line );       /* product = lp*lc. */

  for( int i=0; i<5; i++ ) {
    prepared_line_eval( prepared_line, prepared->line+line_idx++, &e1x, &e1y ); /* lp=ell_{Rp,Qp}(Pp). */
    vroom_fp12_mul_sparse( &product, &product, prepared_line );              /* product *= lp.         */
    checked.r = vroom_ec_add_step( &checked.r, checked_line, &checked.e1x, &checked.e1y,
                          &checked.e2x, &checked.e2y );                       /* Rc<-Rc+Qc; lc=ell_{Rc,Qc}(Pc). */
    vroom_fp12_mul_sparse( &product, &product, checked_line );               /* product *= lc. */
    for( uint j=0U; j<vroom_miller_iterations[i]; j++ ) {
      vroom_fp12_sqr( &product, &product );                                 /* product <- product^2. */
      prepared_line_eval( prepared_line, prepared->line+line_idx++,
                          &three_e1x, &minus_two_e1y );                       /* lp=ell_{Rp,Rp}(Pp).    */
      vroom_fp12_mul_sparse( &product, &product, prepared_line );           /* product *= lp.         */
      checked.r = vroom_ec_double_step( &checked.r, checked_line, &checked.three_e1x,
                               &checked.minus_two_e1y, 0 );                   /* Rc<-2Rc; lc=ell_{Rc,Rc}(Pc). */
      vroom_fp12_mul_sparse( &product, &product, checked_line );            /* product *= lc. */
    }
  }
  if( FD_UNLIKELY( line_idx!=FD_BLS_MILLER_PREPARED_LINE_CNT ) ) return -1;
  if( FD_UNLIKELY( !miller_state_q_in_g2( &checked ) ) ) return 0;
  fp12_conjugate( &product ); /* product^-1 = f_{z,Qp}(Pp)*f_{z,Qc}(Pc), since z<0. */

  vroom_fp12_t final;
  fd_bls_final_exp( &final, &product ); /* final=product^((p^12-1)/r)=e(Pp,Qp)e(Pc,Qc). */
  return vroom_fp12_is_one( &final );  /* Verify that the pairing product is one.                   */
}

static int
miller_loop_n_small( vroom_fp12_t *     out,
                     fd_bls_g1_t const * p,
                     fd_bls_g2_t const * q,
                     ulong               cnt,
                     ulong               q_subgroup_mask ) {
  /* Accumulate product_k f_{z,Q_k}(P_k); shared squarings let the whole
     pairing product use one final exponentiation. */
  fd_bls_miller_state_t state[3];
  vroom_fp_t line[3][6];
  for( ulong k=0UL; k<cnt; k++ ) {
    miller_state_init( &state[k], &p[k], &q[k] );
    state[k].r = vroom_ec_double_step( &state[k].r, line[k], &state[k].three_e1x, &state[k].minus_two_e1y, 1 ); /* Rk=2Qk; lk=ell_{Qk,Qk}(Pk). */
  }
  fp12_set_line( out, line[0] );                                               /* out = l0.             */
  for( ulong k=1UL; k<cnt; k++ ) vroom_fp12_mul_sparse( out, out, line[k] ); /* out = product_k lk.   */

  for( int i=0; i<5; i++ ) {
    for( ulong k=0UL; k<cnt; k++ ) {
      state[k].r = vroom_ec_add_step( &state[k].r, line[k], &state[k].e1x, &state[k].e1y,
                            &state[k].e2x, &state[k].e2y ); /* Rk<-Rk+Qk; lk=ell_{Rk,Qk}(Pk). */
      vroom_fp12_mul_sparse( out, out, line[k] );         /* out *= lk.                        */
    }
    for( uint j=0U; j<vroom_miller_iterations[i]; j++ ) {
      vroom_fp12_sqr( out, out );                         /* out <- out^2 for the next scalar bit. */
      for( ulong k=0UL; k<cnt; k++ ) {
        state[k].r = vroom_ec_double_step( &state[k].r, line[k], &state[k].three_e1x,
                                  &state[k].minus_two_e1y, 0 ); /* Rk<-2Rk; lk=ell_{Rk,Rk}(Pk). */
        vroom_fp12_mul_sparse( out, out, line[k] );             /* out *= lk.                         */
      }
    }
  }
  for( ulong k=0UL; k<cnt; k++ )
    if( (q_subgroup_mask & (1UL<<k)) && FD_UNLIKELY( !miller_state_q_in_g2( &state[k] ) ) )
      return 0;
  fp12_conjugate( out ); /* out^-1 = product_k f_{z,Qk}(Pk), accounting for z<0. */
  return 1;
}

void
fd_bls_miller_loop_avx512( vroom_fp12_t *     out,
                           fd_bls_g1_t const * p,
                           fd_bls_g2_t const * q ) {
  (void)miller_loop_n_small( out, p, q, 1UL, 0UL );
}

int
fd_bls_pairing_avx512( vroom_fp12_t *     out,
                       fd_bls_g1_t const * p,
                       fd_bls_g2_t const * q,
                       ulong               cnt ) {
  if( FD_UNLIKELY( !out || (cnt && (!p || !q)) ) ) return -1;
  if( FD_UNLIKELY( !cnt ) ) {
    vroom_fp12_one( out );
    return 0;
  }

  /* Multiply Miller functions first, then apply the exponent once:
     (prod_i f_i)^((p^12-1)/r) = prod_i e(P_i,Q_i). */
  vroom_fp12_t product;
  if( FD_LIKELY( cnt<=3UL ) ) {
    (void)miller_loop_n_small( &product, p, q, cnt, 0UL );
  } else {
    vroom_fp12_t term;
    (void)miller_loop_n_small( &product, p, q, 1UL, 0UL );
    for( ulong i=1UL; i<cnt; i++ ) {
      (void)miller_loop_n_small( &term, p+i, q+i, 1UL, 0UL );
      vroom_fp12_mul( &product, &product, &term );
    }
  }
  fd_bls_final_exp( out, &product );
  return 0;
}

int
fd_bls_pairing_finalverify_checked_avx512( fd_bls_g1_t const * p,
                                           fd_bls_g2_t const * q,
                                           ulong               cnt,
                                           ulong               q_subgroup_mask ) {
  if( FD_UNLIKELY( !p || !q || !cnt ) ) return -1;
  if( FD_UNLIKELY( cnt<8UL*sizeof(ulong) && (q_subgroup_mask>>cnt) ) ) return -1;
  vroom_fp12_t product;
  if( FD_LIKELY( cnt<=3UL ) ) {
    if( FD_UNLIKELY( !miller_loop_n_small( &product, p, q, cnt, q_subgroup_mask ) ) ) return 0;
  } else {
    vroom_fp12_t term;
    if( FD_UNLIKELY( !miller_loop_n_small( &product, &p[0], &q[0], 1UL, q_subgroup_mask & 1UL ) ) ) return 0;
    for( ulong i=1UL; i<cnt; i++ ) {
      ulong check = i<8UL*sizeof(ulong) ? ((q_subgroup_mask>>i)&1UL) : 0UL;
      if( FD_UNLIKELY( !miller_loop_n_small( &term, &p[i], &q[i], 1UL, check ) ) ) return 0;
      vroom_fp12_mul( &product, &product, &term );
    }
  }
  vroom_fp12_t final;
  fd_bls_final_exp( &final, &product );
  return vroom_fp12_is_one( &final );
}

int
fd_bls_pairing_finalverify_avx512( fd_bls_g1_t const * p,
                                   fd_bls_g2_t const * q,
                                   ulong               cnt ) {
  return fd_bls_pairing_finalverify_checked_avx512( p, q, cnt, 0UL );
}

#endif
