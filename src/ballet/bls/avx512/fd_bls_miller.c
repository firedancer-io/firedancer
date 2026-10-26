/* Miller loop, line evaluation, and projective G2 curve arithmetic for
   the AVX-512 pairing, including the prepared-G2 (precomputed lines)
   variant. */

#include "fd_bls_miller.h"
#include "fd_bls_final.h"

#include "fd_bls_constants.h"

typedef struct {
  fd_bls_p2_projective_t r;
  fd_bls_fp_t            e1x, e1y, three_e1x, minus_two_e1y;
  fd_bls_fp2_t           e2x, e2y;
} fd_bls_miller_state_t;

/* Addition chain for -z=0xd201000000010000: start at 2Q, then repeatedly
   add Q and double by the listed count. */
#define FD_BLS_MILLER_PREPARED_LINE_CNT (1UL + 5UL + 2UL + 3UL + 9UL + 32UL + 16UL)

typedef struct {
  fd_bls_fp2_t c;
  fd_bls_fp2_t x;
  fd_bls_fp2_t y;
} fd_bls_miller_prepared_line_t;

typedef struct {
  fd_bls_miller_prepared_line_t line[ FD_BLS_MILLER_PREPARED_LINE_CNT ];
} fd_bls_g2_prepared_private_t;

FD_STATIC_ASSERT( sizeof(fd_bls_g2_prepared_private_t)==FD_BLS_G2_PREPARED_FOOTPRINT,
                  bls_g2_prepared_footprint );
FD_STATIC_ASSERT( alignof(fd_bls_g2_prepared_private_t)<=FD_BLS_G2_PREPARED_ALIGN,
                  bls_g2_prepared_alignment );

/* Scott's G2 subgroup relation is psi(Q)=[z]Q.  The Miller chain below
   already leaves state->r=[-z]Q, so checking the relation only needs psi
   and a projective equality instead of another 64-bit scalar multiply. */
static int
miller_state_q_in_g2( fd_bls_miller_state_t const * state ) {
  fd_bls_fp2_t x_conj = state->e2x;
  fd_bls_fp2_t y_conj = state->e2y;
  fd_bls_fp_neg( &x_conj.c[1], &x_conj.c[1] ); /* x_conj = xQ^p, since u^p=-u. */
  fd_bls_fp_neg( &y_conj.c[1], &y_conj.c[1] ); /* y_conj = yQ^p.                 */

  fd_bls_fp2_t frob_x, frob_y, psi_x, psi_y;
  fd_bls_fp_zero( &frob_x.c[0] );
  frob_x.c[1] = fd_bls_frob1_3;
  frob_y.c[0] = fd_bls_frob3_2;
  frob_y.c[1] = fd_bls_frob3_3;
  fd_bls_fp2_mul( &psi_x, &x_conj, &frob_x ); /* psi_x = xQ^p*xi^((1-p)/3). */
  fd_bls_fp2_mul( &psi_y, &y_conj, &frob_y ); /* psi_y = yQ^p*xi^((1-p)/2). */

  /* The complete Algorithm 8/9 formulas use homogeneous projective
     coordinates (x=X/Z, y=Y/Z), not Jacobian coordinates. */
  fd_bls_fp2_t rhs_x, rhs_y;
  fd_bls_fp2_mul( &rhs_x, &psi_x, &state->r.z ); /* rhs_x = psi_x*Z, the homogeneous X coordinate. */
  fd_bls_fp2_mul( &rhs_y, &psi_y, &state->r.z ); /* rhs_y = psi_y*Z, the homogeneous Y coordinate. */
  fd_bls_fp2_neg( &rhs_y, &rhs_y );              /* rhs  = -psi(Q)=[-z]Q, which must equal R.     */
  return fd_bls_fp2_equal( &state->r.x, &rhs_x ) & fd_bls_fp2_equal( &state->r.y, &rhs_y );
}

static inline void
fp12_conjugate( fd_bls_fp12_t * out ) {
  /* The p^6-Frobenius is a+b*w -> a-b*w because w^2=v. */
  for( int i=6; i<12; i++ ) fd_bls_fp_neg( &out->c[i], &out->c[i] );
}

static inline void
fp12_set_line( fd_bls_fp12_t * out,
               fd_bls_fp_t const line[6] ) {
  /* Embed the evaluated line as c + x*v + y*w*v in the Fp12 tower. */
  for( int i=0; i<12; i++ ) fd_bls_fp_zero( &out->c[i] );
  out->c[0]=line[0]; out->c[1]=line[1]; out->c[2]=line[2];
  out->c[3]=line[3]; out->c[8]=line[4]; out->c[9]=line[5];
}

static inline void
miller_g1_init( fd_bls_fp_t *             e1x,
                fd_bls_fp_t *             e1y,
                fd_bls_fp_t *             three_e1x,
                fd_bls_fp_t *             minus_two_e1y,
                fd_bls_g1_affine_t const * p ) {
  if( FD_UNLIKELY( !memcmp( p->x, fd_bls_neg_g1_x_normal, sizeof(p->x) ) &&
                           !memcmp( p->y, fd_bls_neg_g1_y_normal, sizeof(p->y) ) ) ) {
    *e1x           = fd_bls_neg_g1_x;
    *e1y           = fd_bls_neg_g1_y;
    *three_e1x     = fd_bls_neg_g1_3x;
    *minus_two_e1y = fd_bls_neg_g1_minus_2y;
  } else {
    fd_bls_fp_from_normal( e1x, p->x );
    fd_bls_fp_from_normal( e1y, p->y );
    fd_bls_fp_mul_small( three_e1x, e1x, 3U );
    fd_bls_fp_neg( minus_two_e1y, e1y );
    fd_bls_fp_mul_small( minus_two_e1y, minus_two_e1y, 2U );
  }
}

static inline void
miller_state_init( fd_bls_miller_state_t * state,
                   fd_bls_g1_affine_t const *     p,
                   fd_bls_g2_affine_t const *     q ) {
  miller_g1_init( &state->e1x, &state->e1y, &state->three_e1x,
                  &state->minus_two_e1y, p );
  fd_bls_fp2_from_normal( &state->e2x, q->x );
  fd_bls_fp2_from_normal( &state->e2y, q->y );
  state->r.x = state->e2x;
  state->r.y = state->e2y;
  fd_bls_fp2_one( &state->r.z );
}

static void
miller_states_init_rns( fd_bls_miller_state_t           state[3],
                        fd_bls_g1_rns_affine_t const * p,
                        fd_bls_g2_rns_affine_t const * q,
                        ulong                           cnt ) {
  for( ulong k=0UL; k<cnt; k++ ) {
    state[k].e1x=p[k].x; state[k].e1y=p[k].y;
    fd_bls_fp_mul_small( &state[k].three_e1x, &state[k].e1x, 3U );
    fd_bls_fp_neg( &state[k].minus_two_e1y, &state[k].e1y );
    fd_bls_fp_mul_small( &state[k].minus_two_e1y, &state[k].minus_two_e1y, 2U );
    state[k].e2x=q[k].x; state[k].e2y=q[k].y; state[k].r.x=q[k].x; state[k].r.y=q[k].y;
    fd_bls_fp2_one( &state[k].r.z );
  }
}

static void
miller_states_init_mont( fd_bls_miller_state_t state[3],
                         blst_p1_affine const * p,
                         blst_p2_affine const * q,
                         ulong                  cnt ) {
  FD_STATIC_ASSERT( sizeof(blst_p1_affine)==2UL*6UL*sizeof(ulong), blst_p1_affine_layout );
  FD_STATIC_ASSERT( sizeof(blst_p2_affine)==4UL*6UL*sizeof(ulong), blst_p2_affine_layout );
  fd_bls_fp_t pxy[6];
  fd_bls_fp_t qxy[12];
  fd_bls_fp_from_mont_batch( pxy, (ulong const *)p, (int)(2UL*cnt) );
  fd_bls_fp_from_mont_batch( qxy, (ulong const *)q, (int)(4UL*cnt) );
  for( ulong k=0UL; k<cnt; k++ ) {
    state[k].e1x = pxy[2UL*k];
    state[k].e1y = pxy[2UL*k+1UL];
    fd_bls_fp_mul_small( &state[k].three_e1x, &state[k].e1x, 3U );
    fd_bls_fp_neg( &state[k].minus_two_e1y, &state[k].e1y );
    fd_bls_fp_mul_small( &state[k].minus_two_e1y, &state[k].minus_two_e1y, 2U );
    state[k].e2x = (fd_bls_fp2_t){ .c = { qxy[4UL*k], qxy[4UL*k+1UL] } };
    state[k].e2y = (fd_bls_fp2_t){ .c = { qxy[4UL*k+2UL], qxy[4UL*k+3UL] } };
    state[k].r.x = state[k].e2x;
    state[k].r.y = state[k].e2y;
    fd_bls_fp2_one( &state[k].r.z );
  }
}

static void
double_step( fd_bls_p2_projective_t *       out,
             fd_bls_p2_projective_t const * p,
             fd_bls_fp_t                    line[6],
             fd_bls_fp_t const *            three_e1x,
             fd_bls_fp_t const *            minus_two_e1y,
             int                            first ) {
  /* Complete homogeneous doubling plus tangent evaluation.  Independent
     products are reduced in two batches; the initial Z=1 skips Z^2 and YZ. */
  fd_bls_fp2_t round1[5];
  if( FD_UNLIKELY( first ) ) {
    fd_bls_fp2_wide_t wide1[3];
    fd_bls_fp2_t reduced[3];
    fd_bls_fp2_wide_set_mul( &wide1[0], &p->x, &p->x ); /* wide1[0] = X^2. */
    fd_bls_fp2_wide_set_mul( &wide1[1], &p->y, &p->y ); /* wide1[1] = Y^2. */
    fd_bls_fp2_wide_set_mul( &wide1[2], &p->x, &p->y ); /* wide1[2] = X*Y. */
    fd_bls_fp2_reduce_batch3( reduced, wide1 );
    round1[0]=reduced[0]; round1[1]=reduced[1]; round1[2]=p->z; /* xx=X^2, yy=Y^2, zz=Z^2=1. */
    round1[3]=reduced[2]; round1[4]=p->y;                       /* xy=X*Y, yz=Y*Z=Y.          */
  } else {
    fd_bls_fp2_wide_t wide1[5];
    fd_bls_fp2_wide_set_mul( &wide1[0], &p->x, &p->x ); /* wide1[0] = X^2. */
    fd_bls_fp2_wide_set_mul( &wide1[1], &p->y, &p->y ); /* wide1[1] = Y^2. */
    fd_bls_fp2_wide_set_mul( &wide1[2], &p->z, &p->z ); /* wide1[2] = Z^2. */
    fd_bls_fp2_wide_set_mul( &wide1[3], &p->x, &p->y ); /* wide1[3] = X*Y. */
    fd_bls_fp2_wide_set_mul( &wide1[4], &p->y, &p->z ); /* wide1[4] = Y*Z. */
    fd_bls_fp2_reduce_batch5( round1, wide1 );
  }
  fd_bls_fp2_t const * xx=&round1[0], * yy=&round1[1], * zz=&round1[2]; /* xx=X^2, yy=Y^2, zz=Z^2. */
  fd_bls_fp2_t const * xy=&round1[3], * yz=&round1[4];                 /* xy=X*Y, yz=Y*Z.          */

  fd_bls_fp2_t eight_yy, b3_zz, line_c, yy_plus_b3, b9_zz;
  fd_bls_fp2_t yy_minus_b9, two_xy;
  fd_bls_fp2_mul_small( &eight_yy, yy, 8U );                    /* eight_yy  = 8Y^2.                    */
  fd_bls_fp2_mul_3b( &b3_zz, zz );                              /* b3_zz     = 3bZ^2.                   */
  fd_bls_fp2_sub( &line_c, &b3_zz, yy );                 /* ell_0    = 3bZ^2-Y^2.               */
  fd_bls_fp2_add( &yy_plus_b3, yy, &b3_zz );             /* yy_plus_b3 = Y^2+3bZ^2.               */
  fd_bls_fp2_mul_small( &b9_zz, &b3_zz, 3U );                   /* b9ZZ     = 9bZ^2.                   */
  fd_bls_fp2_sub( &yy_minus_b9, yy, &b9_zz );            /* yyMinusB9= Y^2-9bZ^2.               */
  fd_bls_fp2_mul_small( &two_xy, xy, 2U );                      /* twoXY    = 2XY.                      */

  fd_bls_fp2_wide_t wide2[5];
  fd_bls_fp2_wide_set_mul_fp( &wide2[0], xx, three_e1x );        /* ell_x(P) = X^2*(3xP).                              */
  fd_bls_fp2_wide_set_mul_fp( &wide2[1], yz, minus_two_e1y );    /* ell_y(P) = YZ*(-2yP).                              */
  fd_bls_fp2_wide_set_mul( &wide2[2], &yy_minus_b9, &yy_plus_b3 ); /* Y3      = (Y^2-9bZ^2)(Y^2+3bZ^2) ...             */
  fd_bls_fp2_wide_addmul( &wide2[2], &eight_yy, &b3_zz );        /* ...       + (8Y^2)(3bZ^2).                         */
  fd_bls_fp2_wide_set_mul( &wide2[3], &yy_minus_b9, &two_xy );   /* X3        = (Y^2-9bZ^2)(2XY).                      */
  fd_bls_fp2_wide_set_mul( &wide2[4], &eight_yy, yz );           /* Z3        = (8Y^2)(YZ).                             */
  fd_bls_fp2_t round2[5];
  fd_bls_fp2_reduce_batch5( round2, wide2 );
  fd_bls_fp2_t const * line_x=&round2[0], * line_y=&round2[1];
  fd_bls_fp2_t const * y3=&round2[2], * x3=&round2[3], * z3=&round2[4];

  line[0]=line_c.c[0];  line[1]=line_c.c[1];  /* line[0:2] = ell_0.    */
  line[2]=line_x->c[0]; line[3]=line_x->c[1]; /* line[2:4] = ell_x(P). */
  line[4]=line_y->c[0]; line[5]=line_y->c[1]; /* line[4:6] = ell_y(P). */
  fd_bls_fp2_copy( &out->x, x3 ); fd_bls_fp2_copy( &out->y, y3 ); fd_bls_fp2_copy( &out->z, z3 );   /* (X3:Y3:Z3)=2(X:Y:Z). */
}

static void
add_step( fd_bls_p2_projective_t *       out,
          fd_bls_p2_projective_t const * p,
          fd_bls_fp_t                    line[6],
          fd_bls_fp_t const *            e1x,
          fd_bls_fp_t const *            e1y,
          fd_bls_fp2_t const *           e2x,
          fd_bls_fp2_t const *           e2y ) {
  /* Complete R+Q addition plus secant evaluation, using Appendix G's pattern:
     reduce each product layer, but reduce sums of products only once. */
  fd_bls_fp2_wide_t wide1[6];
  fd_bls_fp2_wide_set_mul( &wide1[0], e2x, &p->x ); /* wide1[0] = xQ*X. */
  fd_bls_fp2_wide_set_mul( &wide1[1], e2x, &p->y ); /* wide1[1] = xQ*Y. */
  fd_bls_fp2_wide_set_mul( &wide1[2], e2x, &p->z ); /* wide1[2] = xQ*Z. */
  fd_bls_fp2_wide_set_mul( &wide1[3], e2y, &p->x ); /* wide1[3] = yQ*X. */
  fd_bls_fp2_wide_set_mul( &wide1[4], e2y, &p->y ); /* wide1[4] = yQ*Y. */
  fd_bls_fp2_wide_set_mul( &wide1[5], e2y, &p->z ); /* wide1[5] = yQ*Z. */
  fd_bls_fp2_t round1[6];
  fd_bls_fp2_reduce_batch6( round1, wide1 );
  fd_bls_fp2_t const * x2x1=&round1[0], * x2y1=&round1[1], * x2z1=&round1[2];
  fd_bls_fp2_t const * y2x1=&round1[3], * y2y1=&round1[4], * y2z1=&round1[5];

  fd_bls_fp2_t line_c, xq_coef, yq_coef, x2y1_plus_y2x1;
  fd_bls_fp2_t y2z1_plus_y1, x2z1_plus_x1, three_x2x1;
  fd_bls_fp2_t b3z1, y2y1_plus_b3, y2y1_minus_b3, b3_xsum;
  fd_bls_fp2_sub( &line_c, x2y1, y2x1 );                   /* ell_0   = xQ*Y-yQ*X.               */
  fd_bls_fp2_sub( &xq_coef, y2z1, &p->y );                 /* ell_x   = yQ*Z-Y.                  */
  fd_bls_fp2_sub( &yq_coef, &p->x, x2z1 );                 /* ell_y   = X-xQ*Z.                  */
  fd_bls_fp2_add( &x2y1_plus_y2x1, x2y1, y2x1 );          /* xysum   = xQ*Y+yQ*X.               */
  fd_bls_fp2_add( &y2z1_plus_y1, y2z1, &p->y );            /* yzsum   = yQ*Z+Y.                  */
  fd_bls_fp2_add( &x2z1_plus_x1, x2z1, &p->x );            /* xzsum   = xQ*Z+X.                  */
  fd_bls_fp2_mul_small( &three_x2x1, x2x1, 3U );                  /* threeXX = 3xQ*X.                   */
  fd_bls_fp2_mul_3b( &b3z1, &p->z );                              /* b3Z     = 3bZ.                     */
  fd_bls_fp2_add( &y2y1_plus_b3, y2y1, &b3z1 );           /* yp      = yQ*Y+3bZ.                */
  fd_bls_fp2_sub( &y2y1_minus_b3, y2y1, &b3z1 );          /* ym      = yQ*Y-3bZ.                */
  fd_bls_fp2_mul_3b( &b3_xsum, &x2z1_plus_x1 );                  /* bx      = 3b(xQ*Z+X).              */

  fd_bls_fp2_wide_t wide2[5];
  fd_bls_fp2_wide_set_mul( &wide2[0], &x2y1_plus_y2x1, &y2y1_minus_b3 ); /* X3 = xysum*ym ...       */
  fd_bls_fp2_wide_submul( &wide2[0], &b3_xsum, &y2z1_plus_y1 );          /* ... - bx*yzsum.          */
  fd_bls_fp2_wide_set_mul( &wide2[1], &b3_xsum, &three_x2x1 );           /* Y3 = bx*threeXX ...       */
  fd_bls_fp2_wide_addmul( &wide2[1], &y2y1_plus_b3, &y2y1_minus_b3 );   /* ... + yp*ym.             */
  fd_bls_fp2_wide_set_mul( &wide2[2], &y2y1_plus_b3, &y2z1_plus_y1 );   /* Z3 = yp*yzsum ...         */
  fd_bls_fp2_wide_addmul( &wide2[2], &x2y1_plus_y2x1, &three_x2x1 );    /* ... + xysum*threeXX.      */
  fd_bls_fp2_wide_set_mul_fp( &wide2[3], &xq_coef, e1x );                /* ell_x(P) = (yQ*Z-Y)*xP.   */
  fd_bls_fp2_wide_set_mul_fp( &wide2[4], &yq_coef, e1y );                /* ell_y(P) = (X-xQ*Z)*yP.   */
  fd_bls_fp2_t round2[5];
  fd_bls_fp2_reduce_batch5( round2, wide2 );
  fd_bls_fp2_t const * x3=&round2[0], * y3=&round2[1], * z3=&round2[2];
  fd_bls_fp2_t const * line_x=&round2[3], * line_y=&round2[4];

  line[0]=line_c.c[0];  line[1]=line_c.c[1];  /* line[0:2] = ell_0.    */
  line[2]=line_x->c[0]; line[3]=line_x->c[1]; /* line[2:4] = ell_x(P). */
  line[4]=line_y->c[0]; line[5]=line_y->c[1]; /* line[4:6] = ell_y(P). */
  fd_bls_fp2_copy( &out->x, x3 ); fd_bls_fp2_copy( &out->y, y3 ); fd_bls_fp2_copy( &out->z, z3 );   /* (X3:Y3:Z3)=(X:Y:Z)+Q. */
}

/* The G2 state transition and the unevaluated line coefficients depend only
   on Q.  Preparing those once leaves just the two base-field evaluations at
   P for each subsequent pairing. */
static fd_bls_p2_projective_t
double_step_prepare( fd_bls_p2_projective_t const *  p,
                     fd_bls_miller_prepared_line_t * prepared,
                     int                             first ) {
  fd_bls_fp2_t round1[5];
  if( FD_UNLIKELY( first ) ) {
    fd_bls_fp2_wide_t wide1[3];
    fd_bls_fp2_t reduced[3];
    fd_bls_fp2_wide_set_mul( &wide1[0], &p->x, &p->x ); /* wide1[0] = X^2. */
    fd_bls_fp2_wide_set_mul( &wide1[1], &p->y, &p->y ); /* wide1[1] = Y^2. */
    fd_bls_fp2_wide_set_mul( &wide1[2], &p->x, &p->y ); /* wide1[2] = X*Y. */
    fd_bls_fp2_reduce_batch3( reduced, wide1 );
    round1[0]=reduced[0]; round1[1]=reduced[1]; round1[2]=p->z; /* xx=X^2, yy=Y^2, zz=1. */
    round1[3]=reduced[2]; round1[4]=p->y;                       /* xy=X*Y, yz=Y.          */
  } else {
    fd_bls_fp2_wide_t wide1[5];
    fd_bls_fp2_wide_set_mul( &wide1[0], &p->x, &p->x ); /* wide1[0] = X^2. */
    fd_bls_fp2_wide_set_mul( &wide1[1], &p->y, &p->y ); /* wide1[1] = Y^2. */
    fd_bls_fp2_wide_set_mul( &wide1[2], &p->z, &p->z ); /* wide1[2] = Z^2. */
    fd_bls_fp2_wide_set_mul( &wide1[3], &p->x, &p->y ); /* wide1[3] = X*Y. */
    fd_bls_fp2_wide_set_mul( &wide1[4], &p->y, &p->z ); /* wide1[4] = Y*Z. */
    fd_bls_fp2_reduce_batch5( round1, wide1 );
  }
  fd_bls_fp2_t const * xx=&round1[0], * yy=&round1[1], * zz=&round1[2];
  fd_bls_fp2_t const * xy=&round1[3], * yz=&round1[4];

  fd_bls_fp2_t eight_yy, b3_zz, yy_plus_b3, b9_zz;
  fd_bls_fp2_t yy_minus_b9, two_xy;
  fd_bls_fp2_mul_small( &eight_yy, yy, 8U );                /* eight_yy    = 8Y^2.               */
  fd_bls_fp2_mul_3b( &b3_zz, zz );                          /* b3_zz       = 3bZ^2.              */
  fd_bls_fp2_sub( &prepared->c, &b3_zz, yy );        /* prepared.c = ell_0=3bZ^2-Y^2.   */
  prepared->x = *xx;                                 /* prepared.x = X^2; multiply by 3xP later. */
  prepared->y = *yz;                                 /* prepared.y = YZ;  multiply by -2yP later. */
  fd_bls_fp2_add( &yy_plus_b3, yy, &b3_zz );         /* yy_plus_b3   = Y^2+3bZ^2.          */
  fd_bls_fp2_mul_small( &b9_zz, &b3_zz, 3U );               /* b9ZZ       = 9bZ^2.              */
  fd_bls_fp2_sub( &yy_minus_b9, yy, &b9_zz );        /* yyMinusB9  = Y^2-9bZ^2.          */
  fd_bls_fp2_mul_small( &two_xy, xy, 2U );                  /* twoXY      = 2XY.                 */

  fd_bls_fp2_wide_t wide2[3];
  fd_bls_fp2_wide_set_mul( &wide2[0], &yy_minus_b9, &yy_plus_b3 ); /* Y3 = (Y^2-9bZ^2)(Y^2+3bZ^2) ... */
  fd_bls_fp2_wide_addmul( &wide2[0], &eight_yy, &b3_zz );          /* ... + (8Y^2)(3bZ^2).              */
  fd_bls_fp2_wide_set_mul( &wide2[1], &yy_minus_b9, &two_xy );     /* X3 = (Y^2-9bZ^2)(2XY).             */
  fd_bls_fp2_wide_set_mul( &wide2[2], &eight_yy, yz );             /* Z3 = (8Y^2)(YZ).                    */
  fd_bls_fp2_t round2[3];
  fd_bls_fp2_reduce_batch3( round2, wide2 );
  return (fd_bls_p2_projective_t){ round2[1], round2[0], round2[2] };
}

static fd_bls_p2_projective_t
add_step_prepare( fd_bls_p2_projective_t const *  p,
                  fd_bls_miller_prepared_line_t * prepared,
                  fd_bls_fp2_t const *            e2x,
                  fd_bls_fp2_t const *            e2y ) {
  fd_bls_fp2_wide_t wide1[6];
  fd_bls_fp2_wide_set_mul( &wide1[0], e2x, &p->x ); /* wide1[0] = xQ*X. */
  fd_bls_fp2_wide_set_mul( &wide1[1], e2x, &p->y ); /* wide1[1] = xQ*Y. */
  fd_bls_fp2_wide_set_mul( &wide1[2], e2x, &p->z ); /* wide1[2] = xQ*Z. */
  fd_bls_fp2_wide_set_mul( &wide1[3], e2y, &p->x ); /* wide1[3] = yQ*X. */
  fd_bls_fp2_wide_set_mul( &wide1[4], e2y, &p->y ); /* wide1[4] = yQ*Y. */
  fd_bls_fp2_wide_set_mul( &wide1[5], e2y, &p->z ); /* wide1[5] = yQ*Z. */
  fd_bls_fp2_t round1[6];
  fd_bls_fp2_reduce_batch6( round1, wide1 );
  fd_bls_fp2_t const * x2x1=&round1[0], * x2y1=&round1[1], * x2z1=&round1[2];
  fd_bls_fp2_t const * y2x1=&round1[3], * y2y1=&round1[4], * y2z1=&round1[5];

  fd_bls_fp2_t x2y1_plus_y2x1, y2z1_plus_y1, x2z1_plus_x1, three_x2x1;
  fd_bls_fp2_t b3z1, y2y1_plus_b3, y2y1_minus_b3, b3_xsum;
  fd_bls_fp2_sub( &prepared->c, x2y1, y2x1 );               /* prepared.c = ell_0=xQ*Y-yQ*X. */
  fd_bls_fp2_sub( &prepared->x, y2z1, &p->y );              /* prepared.x = yQ*Z-Y; times xP later. */
  fd_bls_fp2_sub( &prepared->y, &p->x, x2z1 );              /* prepared.y = X-xQ*Z; times yP later. */
  fd_bls_fp2_add( &x2y1_plus_y2x1, x2y1, y2x1 );          /* xysum   = xQ*Y+yQ*X. */
  fd_bls_fp2_add( &y2z1_plus_y1, y2z1, &p->y );            /* yzsum   = yQ*Z+Y.    */
  fd_bls_fp2_add( &x2z1_plus_x1, x2z1, &p->x );            /* xzsum   = xQ*Z+X.    */
  fd_bls_fp2_mul_small( &three_x2x1, x2x1, 3U );                  /* threeXX = 3xQ*X.     */
  fd_bls_fp2_mul_3b( &b3z1, &p->z );                              /* b3Z     = 3bZ.       */
  fd_bls_fp2_add( &y2y1_plus_b3, y2y1, &b3z1 );           /* yp      = yQ*Y+3bZ.  */
  fd_bls_fp2_sub( &y2y1_minus_b3, y2y1, &b3z1 );          /* ym      = yQ*Y-3bZ.  */
  fd_bls_fp2_mul_3b( &b3_xsum, &x2z1_plus_x1 );                  /* bx      = 3b*xzsum.   */

  fd_bls_fp2_wide_t wide2[3];
  fd_bls_fp2_wide_set_mul( &wide2[0], &x2y1_plus_y2x1, &y2y1_minus_b3 ); /* X3 = xysum*ym ...  */
  fd_bls_fp2_wide_submul( &wide2[0], &b3_xsum, &y2z1_plus_y1 );          /* ... - bx*yzsum.     */
  fd_bls_fp2_wide_set_mul( &wide2[1], &b3_xsum, &three_x2x1 );           /* Y3 = bx*threeXX ...  */
  fd_bls_fp2_wide_addmul( &wide2[1], &y2y1_plus_b3, &y2y1_minus_b3 );   /* ... + yp*ym.        */
  fd_bls_fp2_wide_set_mul( &wide2[2], &y2y1_plus_b3, &y2z1_plus_y1 );   /* Z3 = yp*yzsum ...    */
  fd_bls_fp2_wide_addmul( &wide2[2], &x2y1_plus_y2x1, &three_x2x1 );    /* ... + xysum*threeXX. */
  fd_bls_fp2_t round2[3];
  fd_bls_fp2_reduce_batch3( round2, wide2 );
  return (fd_bls_p2_projective_t){ round2[0], round2[1], round2[2] };
}

static inline void
prepared_line_eval( fd_bls_fp_t                           out[6],
                    fd_bls_miller_prepared_line_t const * prepared,
                    fd_bls_fp_t const *                   x,
                    fd_bls_fp_t const *                   y ) {
  fd_bls_fp2_wide_t wide[2];
  fd_bls_fp2_wide_set_mul_fp( &wide[0], &prepared->x, x ); /* evaluated[0] = ell_x*xP. */
  fd_bls_fp2_wide_set_mul_fp( &wide[1], &prepared->y, y ); /* evaluated[1] = ell_y*yP. */
  fd_bls_fp2_t evaluated[2];
  fd_bls_fp2_reduce_batch2( evaluated, wide );
  out[0]=prepared->c.c[0]; out[1]=prepared->c.c[1];
  out[2]=evaluated[0].c[0]; out[3]=evaluated[0].c[1];
  out[4]=evaluated[1].c[0]; out[5]=evaluated[1].c[1];
}

int
fd_bls_g2_prepare( fd_bls_g2_prepared_t * out,
                          fd_bls_g2_affine_t const *    q ) {
  if( FD_UNLIKELY( !out || !q ) ) return -1;
  fd_bls_g2_prepared_private_t * prepared = (fd_bls_g2_prepared_private_t *)out;
  fd_bls_fp2_t e2x, e2y;
  fd_bls_fp2_from_normal( &e2x, q->x );
  fd_bls_fp2_from_normal( &e2y, q->y );
  fd_bls_p2_projective_t r = { .x=e2x, .y=e2y };
  fd_bls_fp2_one( &r.z );

  ulong line_idx = 0UL;
  r = double_step_prepare( &r, prepared->line+line_idx++, 1 ); /* R=2Q; save tangent ell_{Q,Q}. */
  for( int i=0; i<5; i++ ) {
    r = add_step_prepare( &r, prepared->line+line_idx++, &e2x, &e2y ); /* R<-R+Q; save secant ell_{R,Q}. */
    for( uint j=0U; j<fd_bls_miller_iterations[i]; j++ )
      r = double_step_prepare( &r, prepared->line+line_idx++, 0 ); /* R<-2R; save tangent ell_{R,R}. */
  }
  return line_idx==FD_BLS_MILLER_PREPARED_LINE_CNT ? 0 : -1;
}

int
fd_bls_pairing_finalverify_prepared_checked(
    fd_bls_g1_affine_t const *          p_prepared,
    fd_bls_g2_prepared_t const * q_prepared,
    fd_bls_g1_affine_t const *          p_checked,
    fd_bls_g2_affine_t const *          q_checked ) {
  if( FD_UNLIKELY( !p_prepared || !q_prepared || !p_checked || !q_checked ) ) return -1;
  fd_bls_g2_prepared_private_t const * prepared = (fd_bls_g2_prepared_private_t const *)q_prepared;

  fd_bls_fp_t e1x, e1y, three_e1x, minus_two_e1y;
  miller_g1_init( &e1x, &e1y, &three_e1x, &minus_two_e1y, p_prepared );
  fd_bls_miller_state_t checked;
  miller_state_init( &checked, p_checked, q_checked );

  fd_bls_fp_t prepared_line[6], checked_line[6];
  ulong line_idx = 0UL;
  prepared_line_eval( prepared_line, prepared->line+line_idx++, &three_e1x, &minus_two_e1y ); /* lp=ell_{Qp,Qp}(Pp). */
  double_step( &checked.r, &checked.r, checked_line, &checked.three_e1x,
                           &checked.minus_two_e1y, 1 ); /* Rc=2Qc; lc=ell_{Qc,Qc}(Pc). */
  fd_bls_fp12_t product;
  fp12_set_line( &product, prepared_line );                         /* product = lp.    */
  fd_bls_fp12_mul_sparse( &product, &product, checked_line );       /* product = lp*lc. */

  for( int i=0; i<5; i++ ) {
    prepared_line_eval( prepared_line, prepared->line+line_idx++, &e1x, &e1y ); /* lp=ell_{Rp,Qp}(Pp). */
    fd_bls_fp12_mul_sparse( &product, &product, prepared_line );              /* product *= lp.         */
    add_step( &checked.r, &checked.r, checked_line, &checked.e1x, &checked.e1y,
                          &checked.e2x, &checked.e2y );                       /* Rc<-Rc+Qc; lc=ell_{Rc,Qc}(Pc). */
    fd_bls_fp12_mul_sparse( &product, &product, checked_line );               /* product *= lc. */
    for( uint j=0U; j<fd_bls_miller_iterations[i]; j++ ) {
      fd_bls_fp12_sqr( &product, &product );                                 /* product <- product^2. */
      prepared_line_eval( prepared_line, prepared->line+line_idx++,
                          &three_e1x, &minus_two_e1y );                       /* lp=ell_{Rp,Rp}(Pp).    */
      fd_bls_fp12_mul_sparse( &product, &product, prepared_line );           /* product *= lp.         */
      double_step( &checked.r, &checked.r, checked_line, &checked.three_e1x,
                               &checked.minus_two_e1y, 0 );                   /* Rc<-2Rc; lc=ell_{Rc,Rc}(Pc). */
      fd_bls_fp12_mul_sparse( &product, &product, checked_line );            /* product *= lc. */
    }
  }
  if( FD_UNLIKELY( line_idx!=FD_BLS_MILLER_PREPARED_LINE_CNT ) ) return -1;
  if( FD_UNLIKELY( !miller_state_q_in_g2( &checked ) ) ) return 0;
  fp12_conjugate( &product ); /* product^-1 = f_{z,Qp}(Pp)*f_{z,Qc}(Pc), since z<0. */

  fd_bls_fp12_t final;
  fd_bls_final_exp( &final, &product ); /* final=product^(3(p^12-1)/r)=(e(Pp,Qp)e(Pc,Qc))^3 (blst convention; gcd(3,r)=1). */
  return fd_bls_fp12_is_one( &final );  /* Verify that the pairing product is one.                   */
}

static int
miller_loop_states( fd_bls_fp12_t *       out,
                    fd_bls_miller_state_t state[3],
                    ulong                 cnt,
                    ulong                 q_subgroup_mask ) {
  /* Accumulate product_k f_{z,Q_k}(P_k); shared squarings let the whole
     pairing product use one final exponentiation. */
  fd_bls_fp_t line[3][6];
  for( ulong k=0UL; k<cnt; k++ )
    double_step( &state[k].r, &state[k].r, line[k], &state[k].three_e1x, &state[k].minus_two_e1y, 1 ); /* Rk=2Qk; lk=ell_{Qk,Qk}(Pk). */
  fp12_set_line( out, line[0] );                                               /* out = l0.             */
  for( ulong k=1UL; k<cnt; k++ ) fd_bls_fp12_mul_sparse( out, out, line[k] ); /* out = product_k lk.   */

  for( int i=0; i<5; i++ ) {
    for( ulong k=0UL; k<cnt; k++ ) {
      add_step( &state[k].r, &state[k].r, line[k], &state[k].e1x, &state[k].e1y,
                            &state[k].e2x, &state[k].e2y ); /* Rk<-Rk+Qk; lk=ell_{Rk,Qk}(Pk). */
      fd_bls_fp12_mul_sparse( out, out, line[k] );         /* out *= lk.                        */
    }
    for( uint j=0U; j<fd_bls_miller_iterations[i]; j++ ) {
      /* The doubling steps and the squaring are independent; issuing them
         back to back lets their reductions overlap before the dependent
         line multiplications. */
      for( ulong k=0UL; k<cnt; k++ )
        double_step( &state[k].r, &state[k].r, line[k], &state[k].three_e1x,
                                  &state[k].minus_two_e1y, 0 ); /* Rk<-2Rk; lk=ell_{Rk,Rk}(Pk). */
      fd_bls_fp12_sqr( out, out );                              /* out <- out^2 for the next bit.     */
      for( ulong k=0UL; k<cnt; k++ )
        fd_bls_fp12_mul_sparse( out, out, line[k] );             /* out *= lk.                         */
    }
  }
  for( ulong k=0UL; k<cnt; k++ )
    if( (q_subgroup_mask & (1UL<<k)) && FD_UNLIKELY( !miller_state_q_in_g2( &state[k] ) ) )
      return 0;
  fp12_conjugate( out ); /* out^-1 = product_k f_{z,Qk}(Pk), accounting for z<0. */
  return 1;
}

static int
miller_loop_n_small( fd_bls_fp12_t *     out,
                     fd_bls_g1_affine_t const * p,
                     fd_bls_g2_affine_t const * q,
                     ulong               cnt,
                     ulong               q_subgroup_mask ) {
  fd_bls_miller_state_t state[3];
  for( ulong k=0UL; k<cnt; k++ ) miller_state_init( &state[k], &p[k], &q[k] );
  return miller_loop_states( out, state, cnt, q_subgroup_mask );
}

void
fd_bls_miller_loop( fd_bls_fp12_t *     out,
                           fd_bls_g1_affine_t const * p,
                           fd_bls_g2_affine_t const * q ) {
  (void)miller_loop_n_small( out, p, q, 1UL, 0UL );
}

int
fd_bls_pairing( fd_bls_fp12_t *     out,
                       fd_bls_g1_affine_t const * p,
                       fd_bls_g2_affine_t const * q,
                       ulong               cnt ) {
  if( FD_UNLIKELY( !out || (cnt && (!p || !q)) ) ) return -1;
  if( FD_UNLIKELY( !cnt ) ) {
    fd_bls_fp12_one( out );
    return 0;
  }

  /* Multiply Miller functions first, then apply the exponent once: (prod_i f_i)^(3(p^12-1)/r) = (prod_i e(P_i,Q_i))^3;
     the cube is fd_bls_final_exp's chain, the same convention as blst_final_exp and Agave's pairing syscall. */
  fd_bls_fp12_t product;
  if( FD_LIKELY( cnt<=3UL ) ) {
    (void)miller_loop_n_small( &product, p, q, cnt, 0UL );
  } else {
    fd_bls_fp12_t term;
    (void)miller_loop_n_small( &product, p, q, 1UL, 0UL );
    for( ulong i=1UL; i<cnt; i++ ) {
      (void)miller_loop_n_small( &term, p+i, q+i, 1UL, 0UL );
      fd_bls_fp12_mul( &product, &product, &term );
    }
  }
  fd_bls_final_exp( out, &product );
  return 0;
}

int
fd_bls_pairing_finalverify_checked( fd_bls_g1_affine_t const * p,
                                           fd_bls_g2_affine_t const * q,
                                           ulong               cnt,
                                           ulong               q_subgroup_mask ) {
  if( FD_UNLIKELY( !p || !q || !cnt ) ) return -1;
  if( FD_UNLIKELY( cnt<8UL*sizeof(ulong) && (q_subgroup_mask>>cnt) ) ) return -1;
  fd_bls_fp12_t product;
  if( FD_LIKELY( cnt<=3UL ) ) {
    if( FD_UNLIKELY( !miller_loop_n_small( &product, p, q, cnt, q_subgroup_mask ) ) ) return 0;
  } else {
    fd_bls_fp12_t term;
    if( FD_UNLIKELY( !miller_loop_n_small( &product, &p[0], &q[0], 1UL, q_subgroup_mask & 1UL ) ) ) return 0;
    for( ulong i=1UL; i<cnt; i++ ) {
      ulong check = i<8UL*sizeof(ulong) ? ((q_subgroup_mask>>i)&1UL) : 0UL;
      if( FD_UNLIKELY( !miller_loop_n_small( &term, &p[i], &q[i], 1UL, check ) ) ) return 0;
      fd_bls_fp12_mul( &product, &product, &term );
    }
  }
  fd_bls_fp12_t final;
  fd_bls_final_exp( &final, &product );
  return fd_bls_fp12_is_one( &final );
}

int
fd_bls_pairing_finalverify( fd_bls_g1_affine_t const * p,
                                   fd_bls_g2_affine_t const * q,
                                   ulong               cnt ) {
  return fd_bls_pairing_finalverify_checked( p, q, cnt, 0UL );
}

int
fd_bls_pairing_rns( fd_bls_fp12_t *                out,
                    fd_bls_g1_rns_affine_t const * p,
                    fd_bls_g2_rns_affine_t const * q,
                    ulong                          cnt ) {
  if( FD_UNLIKELY( !out || !p || !q || !cnt || cnt>3UL ) ) return -1;
  fd_bls_miller_state_t state[3]; miller_states_init_rns( state, p, q, cnt );
  fd_bls_fp12_t product;
  if( FD_UNLIKELY( !miller_loop_states( &product, state, cnt, 0UL ) ) ) return 0;
  fd_bls_final_exp( out, &product );
  return 1;
}

int
fd_bls_pairing_finalverify_rns( fd_bls_g1_rns_affine_t const * p,
                                fd_bls_g2_rns_affine_t const * q,
                                ulong                           cnt ) {
  fd_bls_fp12_t final;
  int ok = fd_bls_pairing_rns( &final, p, q, cnt );
  return ok==1 ? fd_bls_fp12_is_one( &final ) : ok;
}

int
fd_bls_pairing_finalverify_mont( blst_p1_affine const * p,
                                        blst_p2_affine const * q,
                                        ulong                  cnt ) {
  if( FD_UNLIKELY( !p || !q || !cnt || cnt>3UL ) ) return -1;
  fd_bls_miller_state_t state[3];
  miller_states_init_mont( state, p, q, cnt );
  fd_bls_fp12_t product, final;
  if( FD_UNLIKELY( !miller_loop_states( &product, state, cnt, 0UL ) ) ) return 0;
  fd_bls_final_exp( &final, &product );
  return fd_bls_fp12_is_one( &final );
}
