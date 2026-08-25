/* Miller loop, line evaluation, and projective G2 curve arithmetic for
   the AVX-512 pairing, including the prepared-G2 (precomputed lines)
   variant. */

#include "fd_bls_miller.h"
#include "fd_bls_final.h"

#if FD_HAS_AVX512

#include "fd_bls_constants.h"

typedef struct { fd_bls_fp2_t x, y, z; } fd_bls_p2_projective_t;
typedef struct { fd_bls_fp_wide_t c[2]; } fd_bls_fp2_wide_t;
typedef struct {
  fd_bls_p2_projective_t r;
  fd_bls_fp_t            e1x, e1y, three_e1x, minus_two_e1y;
  fd_bls_fp2_t           e2x, e2y;
} fd_bls_miller_state_t;

/* Addition chain for -z=0xd201000000010000: start at 2Q, then repeatedly
   add Q and double by the listed count. */
static uint const fd_bls_miller_iterations[5] = { 2U, 3U, 9U, 32U, 16U };

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
                  bls_avx512_g2_prepared_footprint );
FD_STATIC_ASSERT( alignof(fd_bls_g2_prepared_private_t)<=FD_BLS_G2_PREPARED_ALIGN,
                  bls_avx512_g2_prepared_alignment );

static inline void
fp2_wide_zero( fd_bls_fp2_wide_t * out ) {
  fd_bls_fp_wide_offset( &out->c[0] ); /* out.re = 0 mod p, with a positive lazy offset. */
  fd_bls_fp_wide_offset( &out->c[1] ); /* out.im = 0 mod p.                              */
}

static inline void
fp2_wide_addmul( fd_bls_fp2_wide_t * out,
                 fd_bls_fp2_t const * a,
                 fd_bls_fp2_t const * b ) {
  fd_bls_fp_wide_addmul( &out->c[0], &a->c[0], &b->c[0] ); /* out.re += a0*b0. */
  fd_bls_fp_wide_submul( &out->c[0], &a->c[1], &b->c[1] ); /* out.re -= a1*b1. */
  fd_bls_fp_wide_addmul( &out->c[1], &a->c[0], &b->c[1] ); /* out.im += a0*b1. */
  fd_bls_fp_wide_addmul( &out->c[1], &a->c[1], &b->c[0] ); /* out.im += a1*b0, hence out += a*b. */
}

static inline void
fp2_wide_submul( fd_bls_fp2_wide_t * out,
                 fd_bls_fp2_t const * a,
                 fd_bls_fp2_t const * b ) {
  fd_bls_fp_wide_submul( &out->c[0], &a->c[0], &b->c[0] ); /* out.re -= a0*b0. */
  fd_bls_fp_wide_addmul( &out->c[0], &a->c[1], &b->c[1] ); /* out.re += a1*b1. */
  fd_bls_fp_wide_submul( &out->c[1], &a->c[0], &b->c[1] ); /* out.im -= a0*b1. */
  fd_bls_fp_wide_submul( &out->c[1], &a->c[1], &b->c[0] ); /* out.im -= a1*b0, hence out -= a*b. */
}

static inline void
fp2_wide_addmul_fp( fd_bls_fp2_wide_t * out,
                    fd_bls_fp2_t const * a,
                    fd_bls_fp_t const *  b ) {
  fd_bls_fp_wide_addmul( &out->c[0], &a->c[0], b ); /* out.re += a0*b. */
  fd_bls_fp_wide_addmul( &out->c[1], &a->c[1], b ); /* out.im += a1*b, hence out += a*b. */
}

static inline void
fp2_wide_set_mul( fd_bls_fp2_wide_t * out,
                  fd_bls_fp2_t const * a,
                  fd_bls_fp2_t const * b ) {
  fp2_wide_zero( out );
  fp2_wide_addmul( out, a, b );
}

static inline void
fp2_wide_set_mul_fp( fd_bls_fp2_wide_t * out,
                     fd_bls_fp2_t const * a,
                     fd_bls_fp_t const *  b ) {
  fp2_wide_zero( out );
  fp2_wide_addmul_fp( out, a, b );
}

static inline void
fp2_reduce_batch3( fd_bls_fp2_t       out[3],
                   fd_bls_fp2_wide_t  in [3] ) {
  fd_bls_fp_reduce_wide_batch6( &out[0].c[0], &in[0].c[0] );
}

static inline void
fp2_reduce_batch2( fd_bls_fp2_t       out[2],
                   fd_bls_fp2_wide_t  in [2] ) {
  fd_bls_fp_reduce_wide_batch4( &out[0].c[0], &in[0].c[0] );
}

static inline void
fp2_reduce_batch5( fd_bls_fp2_t       out[5],
                   fd_bls_fp2_wide_t  in [5] ) {
  /* One interleaved batch10 over all 10 base-field wide elements of the
     five Fp2 products. */
  fd_bls_fp_reduce_wide_batch10( &out[0].c[0], &in[0].c[0] );
}

static inline void
fp2_reduce_batch6( fd_bls_fp2_t       out[6],
                   fd_bls_fp2_wide_t  in [6] ) {
  fd_bls_fp_reduce_wide_batch6( &out[0].c[0], &in[0].c[0] );
  fd_bls_fp_reduce_wide_batch6( &out[3].c[0], &in[3].c[0] );
}

static inline void
fp_from_normal( fd_bls_fp_t * out,
                ulong const     in[6] ) {
  fd_bls_fp_from_uint64( out, in );
}

static inline void
fp2_from_normal( fd_bls_fp2_t * out,
                 ulong const      in[2][6] ) {
  fp_from_normal( &out->c[0], in[0] );
  fp_from_normal( &out->c[1], in[1] );
}

static inline void
fp_mul_small( fd_bls_fp_t *       out,
              fd_bls_fp_t const * a,
              uint                  n ) {
  /* Double-and-add over RAW 64-bit lane sums.  Lanes are 64-bit and only
     madd52 operands must stay below 2^52, so for n<=2^8 every intermediate
     (bounded by n*2^51 < 2^60) accumulates without per-step normalization;
     one trailing normalize restores the standard bound. */
  wwv_t r1 = wwv_zero(), r2 = wwv_zero();
  wwv_t x1 = a->m1,      x2 = a->m2;              /* r=0, x=a, so r+n*x=N*a. */
  while( n ) {
    if( n & 1U ) { r1 = wwv_add( r1, x1 ); r2 = wwv_add( r2, x2 ); } /* r<-r+x.  */
    n >>= 1;                                      /* Remove that scalar bit.      */
    if( n ) { x1 = wwv_add( x1, x1 ); x2 = wwv_add( x2, x2 ); }      /* x<-2x.   */
  }
  out->m1 = normalize( r1, wwv_ld( fd_bls_m1_t ) ); /* out=N*a, back in [0,2m).  */
  out->m2 = normalize( r2, wwv_ld( fd_bls_m2_t ) );
}

static inline void
fp2_mul_small( fd_bls_fp2_t *       out,
               fd_bls_fp2_t const * a,
               uint                   n ) {
  fp_mul_small( &out->c[0], &a->c[0], n );
  fp_mul_small( &out->c[1], &a->c[1], n );
}

static inline void
fp2_one( fd_bls_fp2_t * out ) {
  fd_bls_fp_one( &out->c[0] );
  fd_bls_fp_zero( &out->c[1] );
}

static inline int
fp2_equal( fd_bls_fp2_t const * a,
           fd_bls_fp2_t const * b ) {
  return fd_bls_fp_equal( &a->c[0], &b->c[0] ) &
         fd_bls_fp_equal( &a->c[1], &b->c[1] );
}

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
  frob_x.c[1] = FD_BLS_FP_CONST( frob1_3 );
  frob_y.c[0] = FD_BLS_FP_CONST( frob3_2 );
  frob_y.c[1] = FD_BLS_FP_CONST( frob3_3 );
  fd_bls_fp2_mul( &psi_x, &x_conj, &frob_x ); /* psi_x = xQ^p*xi^((1-p)/3). */
  fd_bls_fp2_mul( &psi_y, &y_conj, &frob_y ); /* psi_y = yQ^p*xi^((1-p)/2). */

  /* The complete Algorithm 8/9 formulas use homogeneous projective
     coordinates (x=X/Z, y=Y/Z), not Jacobian coordinates. */
  fd_bls_fp2_t rhs_x, rhs_y;
  fd_bls_fp2_mul( &rhs_x, &psi_x, &state->r.z ); /* rhs_x = psi_x*Z, the homogeneous X coordinate. */
  fd_bls_fp2_mul( &rhs_y, &psi_y, &state->r.z ); /* rhs_y = psi_y*Z, the homogeneous Y coordinate. */
  fd_bls_fp2_neg( &rhs_y, &rhs_y );              /* rhs  = -psi(Q)=[-z]Q, which must equal R.     */
  return fp2_equal( &state->r.x, &rhs_x ) & fp2_equal( &state->r.y, &rhs_y );
}

static inline void
fp2_mul_3b( fd_bls_fp2_t *       out,
            fd_bls_fp2_t const * a ) {
  /* The twist has b=4(1+u), hence 3b*a=12(1+u)*a. */
  fd_bls_fp2_t nonres;
  fd_bls_fp_sub( &nonres.c[0], &a->c[0], &a->c[1] );
  fd_bls_fp_add( &nonres.c[1], &a->c[0], &a->c[1] );
  fp2_mul_small( out, &nonres, 12U );
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
                fd_bls_g1_t const * p ) {
  if( FD_UNLIKELY( !memcmp( p->x, fd_bls_neg_g1_x_normal, sizeof(p->x) ) &&
                           !memcmp( p->y, fd_bls_neg_g1_y_normal, sizeof(p->y) ) ) ) {
    *e1x           = FD_BLS_FP_CONST( neg_g1_x );
    *e1y           = FD_BLS_FP_CONST( neg_g1_y );
    *three_e1x     = FD_BLS_FP_CONST( neg_g1_3x );
    *minus_two_e1y = FD_BLS_FP_CONST( neg_g1_minus_2y );
  } else {
    fp_from_normal( e1x, p->x );
    fp_from_normal( e1y, p->y );
    fp_mul_small( three_e1x, e1x, 3U );
    fd_bls_fp_neg( minus_two_e1y, e1y );
    fp_mul_small( minus_two_e1y, minus_two_e1y, 2U );
  }
}

static inline void
miller_state_init( fd_bls_miller_state_t * state,
                   fd_bls_g1_t const *     p,
                   fd_bls_g2_t const *     q ) {
  miller_g1_init( &state->e1x, &state->e1y, &state->three_e1x,
                  &state->minus_two_e1y, p );
  fp2_from_normal( &state->e2x, q->x );
  fp2_from_normal( &state->e2y, q->y );
  state->r.x = state->e2x;
  state->r.y = state->e2y;
  fp2_one( &state->r.z );
}

static fd_bls_p2_projective_t
double_step( fd_bls_p2_projective_t const * p,
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
    fp2_wide_set_mul( &wide1[0], &p->x, &p->x ); /* wide1[0] = X^2. */
    fp2_wide_set_mul( &wide1[1], &p->y, &p->y ); /* wide1[1] = Y^2. */
    fp2_wide_set_mul( &wide1[2], &p->x, &p->y ); /* wide1[2] = X*Y. */
    fp2_reduce_batch3( reduced, wide1 );
    round1[0]=reduced[0]; round1[1]=reduced[1]; round1[2]=p->z; /* xx=X^2, yy=Y^2, zz=Z^2=1. */
    round1[3]=reduced[2]; round1[4]=p->y;                       /* xy=X*Y, yz=Y*Z=Y.          */
  } else {
    fd_bls_fp2_wide_t wide1[5];
    fp2_wide_set_mul( &wide1[0], &p->x, &p->x ); /* wide1[0] = X^2. */
    fp2_wide_set_mul( &wide1[1], &p->y, &p->y ); /* wide1[1] = Y^2. */
    fp2_wide_set_mul( &wide1[2], &p->z, &p->z ); /* wide1[2] = Z^2. */
    fp2_wide_set_mul( &wide1[3], &p->x, &p->y ); /* wide1[3] = X*Y. */
    fp2_wide_set_mul( &wide1[4], &p->y, &p->z ); /* wide1[4] = Y*Z. */
    fp2_reduce_batch5( round1, wide1 );
  }
  fd_bls_fp2_t const * xx=&round1[0], * yy=&round1[1], * zz=&round1[2]; /* xx=X^2, yy=Y^2, zz=Z^2. */
  fd_bls_fp2_t const * xy=&round1[3], * yz=&round1[4];                 /* xy=X*Y, yz=Y*Z.          */

  fd_bls_fp2_t eight_yy, b3_zz, line_c, yy_plus_b3, b9_zz;
  fd_bls_fp2_t yy_minus_b9, two_xy;
  fp2_mul_small( &eight_yy, yy, 8U );                    /* eight_yy  = 8Y^2.                    */
  fp2_mul_3b( &b3_zz, zz );                              /* b3_zz     = 3bZ^2.                   */
  fd_bls_fp2_sub( &line_c, &b3_zz, yy );                 /* ell_0    = 3bZ^2-Y^2.               */
  fd_bls_fp2_add( &yy_plus_b3, yy, &b3_zz );             /* yy_plus_b3 = Y^2+3bZ^2.               */
  fp2_mul_small( &b9_zz, &b3_zz, 3U );                   /* b9ZZ     = 9bZ^2.                   */
  fd_bls_fp2_sub( &yy_minus_b9, yy, &b9_zz );            /* yyMinusB9= Y^2-9bZ^2.               */
  fp2_mul_small( &two_xy, xy, 2U );                      /* twoXY    = 2XY.                      */

  fd_bls_fp2_wide_t wide2[5];
  fp2_wide_set_mul_fp( &wide2[0], xx, three_e1x );        /* ell_x(P) = X^2*(3xP).                              */
  fp2_wide_set_mul_fp( &wide2[1], yz, minus_two_e1y );    /* ell_y(P) = YZ*(-2yP).                              */
  fp2_wide_set_mul( &wide2[2], &yy_minus_b9, &yy_plus_b3 ); /* Y3      = (Y^2-9bZ^2)(Y^2+3bZ^2) ...             */
  fp2_wide_addmul( &wide2[2], &eight_yy, &b3_zz );        /* ...       + (8Y^2)(3bZ^2).                         */
  fp2_wide_set_mul( &wide2[3], &yy_minus_b9, &two_xy );   /* X3        = (Y^2-9bZ^2)(2XY).                      */
  fp2_wide_set_mul( &wide2[4], &eight_yy, yz );           /* Z3        = (8Y^2)(YZ).                             */
  fd_bls_fp2_t round2[5];
  fp2_reduce_batch5( round2, wide2 );
  fd_bls_fp2_t const * line_x=&round2[0], * line_y=&round2[1];
  fd_bls_fp2_t const * y3=&round2[2], * x3=&round2[3], * z3=&round2[4];

  line[0]=line_c.c[0];  line[1]=line_c.c[1];  /* line[0:2] = ell_0.    */
  line[2]=line_x->c[0]; line[3]=line_x->c[1]; /* line[2:4] = ell_x(P). */
  line[4]=line_y->c[0]; line[5]=line_y->c[1]; /* line[4:6] = ell_y(P). */
  return (fd_bls_p2_projective_t){ *x3, *y3, *z3 }; /* (X3:Y3:Z3)=2(X:Y:Z). */
}

static fd_bls_p2_projective_t
add_step( fd_bls_p2_projective_t const * p,
          fd_bls_fp_t                    line[6],
          fd_bls_fp_t const *            e1x,
          fd_bls_fp_t const *            e1y,
          fd_bls_fp2_t const *           e2x,
          fd_bls_fp2_t const *           e2y ) {
  /* Complete R+Q addition plus secant evaluation, using Appendix G's pattern:
     reduce each product layer, but reduce sums of products only once. */
  fd_bls_fp2_wide_t wide1[6];
  fp2_wide_set_mul( &wide1[0], e2x, &p->x ); /* wide1[0] = xQ*X. */
  fp2_wide_set_mul( &wide1[1], e2x, &p->y ); /* wide1[1] = xQ*Y. */
  fp2_wide_set_mul( &wide1[2], e2x, &p->z ); /* wide1[2] = xQ*Z. */
  fp2_wide_set_mul( &wide1[3], e2y, &p->x ); /* wide1[3] = yQ*X. */
  fp2_wide_set_mul( &wide1[4], e2y, &p->y ); /* wide1[4] = yQ*Y. */
  fp2_wide_set_mul( &wide1[5], e2y, &p->z ); /* wide1[5] = yQ*Z. */
  fd_bls_fp2_t round1[6];
  fp2_reduce_batch6( round1, wide1 );
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
  fp2_mul_small( &three_x2x1, x2x1, 3U );                  /* threeXX = 3xQ*X.                   */
  fp2_mul_3b( &b3z1, &p->z );                              /* b3Z     = 3bZ.                     */
  fd_bls_fp2_add( &y2y1_plus_b3, y2y1, &b3z1 );           /* yp      = yQ*Y+3bZ.                */
  fd_bls_fp2_sub( &y2y1_minus_b3, y2y1, &b3z1 );          /* ym      = yQ*Y-3bZ.                */
  fp2_mul_3b( &b3_xsum, &x2z1_plus_x1 );                  /* bx      = 3b(xQ*Z+X).              */

  fd_bls_fp2_wide_t wide2[5];
  fp2_wide_set_mul( &wide2[0], &x2y1_plus_y2x1, &y2y1_minus_b3 ); /* X3 = xysum*ym ...       */
  fp2_wide_submul( &wide2[0], &b3_xsum, &y2z1_plus_y1 );          /* ... - bx*yzsum.          */
  fp2_wide_set_mul( &wide2[1], &b3_xsum, &three_x2x1 );           /* Y3 = bx*threeXX ...       */
  fp2_wide_addmul( &wide2[1], &y2y1_plus_b3, &y2y1_minus_b3 );   /* ... + yp*ym.             */
  fp2_wide_set_mul( &wide2[2], &y2y1_plus_b3, &y2z1_plus_y1 );   /* Z3 = yp*yzsum ...         */
  fp2_wide_addmul( &wide2[2], &x2y1_plus_y2x1, &three_x2x1 );    /* ... + xysum*threeXX.      */
  fp2_wide_set_mul_fp( &wide2[3], &xq_coef, e1x );                /* ell_x(P) = (yQ*Z-Y)*xP.   */
  fp2_wide_set_mul_fp( &wide2[4], &yq_coef, e1y );                /* ell_y(P) = (X-xQ*Z)*yP.   */
  fd_bls_fp2_t round2[5];
  fp2_reduce_batch5( round2, wide2 );
  fd_bls_fp2_t const * x3=&round2[0], * y3=&round2[1], * z3=&round2[2];
  fd_bls_fp2_t const * line_x=&round2[3], * line_y=&round2[4];

  line[0]=line_c.c[0];  line[1]=line_c.c[1];  /* line[0:2] = ell_0.    */
  line[2]=line_x->c[0]; line[3]=line_x->c[1]; /* line[2:4] = ell_x(P). */
  line[4]=line_y->c[0]; line[5]=line_y->c[1]; /* line[4:6] = ell_y(P). */
  return (fd_bls_p2_projective_t){ *x3, *y3, *z3 }; /* (X3:Y3:Z3)=(X:Y:Z)+Q. */
}

/* Line-free complete homogeneous doubling (double_step minus the Miller
   tangent evaluation).  Pure EC work: X^2 and the two line products are
   never formed, so round 1 reduces four products and round 2 three. */
static fd_bls_p2_projective_t
ec_double( fd_bls_p2_projective_t const * p,
           int                            first ) {
  fd_bls_fp2_t round1[4];
  if( FD_UNLIKELY( first ) ) {
    fd_bls_fp2_wide_t wide1[2];
    fd_bls_fp2_t reduced[2];
    fp2_wide_set_mul( &wide1[0], &p->y, &p->y ); /* Y^2. */
    fp2_wide_set_mul( &wide1[1], &p->x, &p->y ); /* X*Y. */
    fp2_reduce_batch2( reduced, wide1 );
    round1[0]=reduced[0]; round1[1]=p->z;        /* yy=Y^2, zz=Z^2=1. */
    round1[2]=reduced[1]; round1[3]=p->y;        /* xy=X*Y, yz=Y*Z=Y. */
  } else {
    fd_bls_fp2_wide_t wide1[4];
    fp2_wide_set_mul( &wide1[0], &p->y, &p->y ); /* Y^2. */
    fp2_wide_set_mul( &wide1[1], &p->z, &p->z ); /* Z^2. */
    fp2_wide_set_mul( &wide1[2], &p->x, &p->y ); /* X*Y. */
    fp2_wide_set_mul( &wide1[3], &p->y, &p->z ); /* Y*Z. */
    fd_bls_fp_reduce_wide_batch8( &round1[0].c[0], &wide1[0].c[0] );
  }
  fd_bls_fp2_t const * yy=&round1[0], * zz=&round1[1];
  fd_bls_fp2_t const * xy=&round1[2], * yz=&round1[3];

  fd_bls_fp2_t eight_yy, b3_zz, yy_plus_b3, b9_zz, yy_minus_b9, two_xy;
  fp2_mul_small( &eight_yy, yy, 8U );            /* eight_yy  = 8Y^2.      */
  fp2_mul_3b( &b3_zz, zz );                      /* b3_zz     = 3bZ^2.     */
  fd_bls_fp2_add( &yy_plus_b3, yy, &b3_zz );     /* yy_plus_b3 = Y^2+3bZ^2. */
  fp2_mul_small( &b9_zz, &b3_zz, 3U );           /* b9ZZ     = 9bZ^2.     */
  fd_bls_fp2_sub( &yy_minus_b9, yy, &b9_zz );    /* yyMinusB9= Y^2-9bZ^2. */
  fp2_mul_small( &two_xy, xy, 2U );              /* twoXY    = 2XY.       */

  fd_bls_fp2_wide_t wide2[3];
  fp2_wide_set_mul( &wide2[0], &yy_minus_b9, &yy_plus_b3 ); /* Y3 = (Y^2-9bZ^2)(Y^2+3bZ^2) ... */
  fp2_wide_addmul( &wide2[0], &eight_yy, &b3_zz );          /* ...  + (8Y^2)(3bZ^2).            */
  fp2_wide_set_mul( &wide2[1], &yy_minus_b9, &two_xy );     /* X3 = (Y^2-9bZ^2)(2XY).            */
  fp2_wide_set_mul( &wide2[2], &eight_yy, yz );             /* Z3 = (8Y^2)(YZ).                  */
  fd_bls_fp2_t round2[3];
  fp2_reduce_batch3( round2, wide2 );
  return (fd_bls_p2_projective_t){ round2[1], round2[0], round2[2] };
}

/* Line-free complete mixed addition (add_step minus the secant
   evaluation): round 2 reduces three products instead of five. */
static fd_bls_p2_projective_t
ec_add_pa( fd_bls_p2_projective_t const * p,
           fd_bls_fp2_t const *           e2x,
           fd_bls_fp2_t const *           e2y ) {
  fd_bls_fp2_wide_t wide1[6];
  fp2_wide_set_mul( &wide1[0], e2x, &p->x ); /* xQ*X. */
  fp2_wide_set_mul( &wide1[1], e2x, &p->y ); /* xQ*Y. */
  fp2_wide_set_mul( &wide1[2], e2x, &p->z ); /* xQ*Z. */
  fp2_wide_set_mul( &wide1[3], e2y, &p->x ); /* yQ*X. */
  fp2_wide_set_mul( &wide1[4], e2y, &p->y ); /* yQ*Y. */
  fp2_wide_set_mul( &wide1[5], e2y, &p->z ); /* yQ*Z. */
  fd_bls_fp2_t round1[6];
  fp2_reduce_batch6( round1, wide1 );
  fd_bls_fp2_t const * x2x1=&round1[0], * x2y1=&round1[1], * x2z1=&round1[2];
  fd_bls_fp2_t const * y2x1=&round1[3], * y2y1=&round1[4], * y2z1=&round1[5];

  fd_bls_fp2_t x2y1_plus_y2x1, y2z1_plus_y1, x2z1_plus_x1, three_x2x1;
  fd_bls_fp2_t b3z1, y2y1_plus_b3, y2y1_minus_b3, b3_xsum;
  fd_bls_fp2_add( &x2y1_plus_y2x1, x2y1, y2x1 );  /* xysum   = xQ*Y+yQ*X. */
  fd_bls_fp2_add( &y2z1_plus_y1, y2z1, &p->y );   /* yzsum   = yQ*Z+Y.    */
  fd_bls_fp2_add( &x2z1_plus_x1, x2z1, &p->x );   /* xzsum   = xQ*Z+X.    */
  fp2_mul_small( &three_x2x1, x2x1, 3U );         /* threeXX = 3xQ*X.     */
  fp2_mul_3b( &b3z1, &p->z );                     /* b3Z     = 3bZ.       */
  fd_bls_fp2_add( &y2y1_plus_b3, y2y1, &b3z1 );   /* yp      = yQ*Y+3bZ.  */
  fd_bls_fp2_sub( &y2y1_minus_b3, y2y1, &b3z1 );  /* ym      = yQ*Y-3bZ.  */
  fp2_mul_3b( &b3_xsum, &x2z1_plus_x1 );          /* bx      = 3b*xzsum.  */

  fd_bls_fp2_wide_t wide2[3];
  fp2_wide_set_mul( &wide2[0], &x2y1_plus_y2x1, &y2y1_minus_b3 ); /* X3 = xysum*ym ...   */
  fp2_wide_submul( &wide2[0], &b3_xsum, &y2z1_plus_y1 );          /* ... - bx*yzsum.      */
  fp2_wide_set_mul( &wide2[1], &b3_xsum, &three_x2x1 );           /* Y3 = bx*threeXX ...  */
  fp2_wide_addmul( &wide2[1], &y2y1_plus_b3, &y2y1_minus_b3 );   /* ... + yp*ym.         */
  fp2_wide_set_mul( &wide2[2], &y2y1_plus_b3, &y2z1_plus_y1 );   /* Z3 = yp*yzsum ...    */
  fp2_wide_addmul( &wide2[2], &x2y1_plus_y2x1, &three_x2x1 );    /* ... + xysum*threeXX. */
  fd_bls_fp2_t round2[3];
  fp2_reduce_batch3( round2, wide2 );
  return (fd_bls_p2_projective_t){ round2[0], round2[1], round2[2] };
}

/* Complete homogeneous addition of two PROJECTIVE points (ec_add_pa
   generalized to Q = (Xq:Yq:Zq): substituting the affine xq=Xq/Zq,
   yq=Yq/Zq and clearing the Zq^2 denominator).  Costs 15 muls vs
   ec_add_pa's 11, but needs no affinization of the addend. */
static fd_bls_p2_projective_t
ec_add_pp( fd_bls_p2_projective_t const * p,
           fd_bls_p2_projective_t const * q ) {
  fd_bls_fp2_wide_t w1a[6], w1b[3];
  fp2_wide_set_mul( &w1a[0], &q->x, &p->x ); /* Xq*X. */
  fp2_wide_set_mul( &w1a[1], &q->x, &p->y ); /* Xq*Y. */
  fp2_wide_set_mul( &w1a[2], &q->x, &p->z ); /* Xq*Z. */
  fp2_wide_set_mul( &w1a[3], &q->y, &p->x ); /* Yq*X. */
  fp2_wide_set_mul( &w1a[4], &q->y, &p->y ); /* Yq*Y. */
  fp2_wide_set_mul( &w1a[5], &q->y, &p->z ); /* Yq*Z. */
  fp2_wide_set_mul( &w1b[0], &p->x, &q->z ); /* X*Zq. */
  fp2_wide_set_mul( &w1b[1], &p->y, &q->z ); /* Y*Zq. */
  fp2_wide_set_mul( &w1b[2], &p->z, &q->z ); /* Z*Zq. */
  fd_bls_fp2_t r1[6], r1b[3];
  fp2_reduce_batch6( r1, w1a );
  fp2_reduce_batch3( r1b, w1b );
  fd_bls_fp2_t const * xqx=&r1[0], * xqy=&r1[1], * xqz=&r1[2];
  fd_bls_fp2_t const * yqx=&r1[3], * yqy=&r1[4], * yqz=&r1[5];
  fd_bls_fp2_t const * xzq=&r1b[0], * yzq=&r1b[1], * zzq=&r1b[2];

  fd_bls_fp2_t xysum, ym, yp, xzsum, yzsum, three_xx, b3_zzq, bx;
  fd_bls_fp2_add( &xysum, xqy, yqx );              /* XqY+YqX.     */
  fp2_mul_3b( &b3_zzq, zzq );                      /* 3b*Z*Zq.     */
  fd_bls_fp2_sub( &ym, yqy, &b3_zzq );             /* YqY-3bZZq.   */
  fd_bls_fp2_add( &yp, yqy, &b3_zzq );             /* YqY+3bZZq.   */
  fd_bls_fp2_add( &xzsum, xqz, xzq );              /* XqZ+XZq.     */
  fd_bls_fp2_add( &yzsum, yqz, yzq );              /* YqZ+YZq.     */
  fp2_mul_small( &three_xx, xqx, 3U );            /* 3*Xq*X.      */
  fp2_mul_3b( &bx, &xzsum );                      /* 3b(XqZ+XZq). */

  fd_bls_fp2_wide_t w2[3];
  fp2_wide_set_mul( &w2[0], &xysum, &ym );          /* X3 = xysum*ym ...     */
  fp2_wide_submul( &w2[0], &bx, &yzsum );           /* ... - bx*yzsum.        */
  fp2_wide_set_mul( &w2[1], &bx, &three_xx );      /* Y3 = bx*threeXX ...    */
  fp2_wide_addmul( &w2[1], &yp, &ym );              /* ... + yp*ym.           */
  fp2_wide_set_mul( &w2[2], &yp, &yzsum );         /* Z3 = yp*yzsum ...      */
  fp2_wide_addmul( &w2[2], &xysum, &three_xx );     /* ... + xysum*threeXX.   */
  fd_bls_fp2_t r2[3];
  fp2_reduce_batch3( r2, w2 );
  return (fd_bls_p2_projective_t){ r2[0], r2[1], r2[2] };
}

/* [-z] ladder over an affine base, line-free: 2Q then the {2,3,9,32,16}
   add+double groups of -z = 0xd201000000010000. */
static fd_bls_p2_projective_t
ladder_minus_z_affine( fd_bls_fp2_t const * qx,
                       fd_bls_fp2_t const * qy ) {
  fd_bls_p2_projective_t r = { .x = *qx, .y = *qy };
  fp2_one( &r.z );
  r = ec_double( &r, 1 );
  for( int i=0; i<5; i++ ) {
    r = ec_add_pa( &r, qx, qy );
    for( uint j=0U; j<fd_bls_miller_iterations[i]; j++ )
      r = ec_double( &r, 0 );
  }
  return r;
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
    fp2_wide_set_mul( &wide1[0], &p->x, &p->x ); /* wide1[0] = X^2. */
    fp2_wide_set_mul( &wide1[1], &p->y, &p->y ); /* wide1[1] = Y^2. */
    fp2_wide_set_mul( &wide1[2], &p->x, &p->y ); /* wide1[2] = X*Y. */
    fp2_reduce_batch3( reduced, wide1 );
    round1[0]=reduced[0]; round1[1]=reduced[1]; round1[2]=p->z; /* xx=X^2, yy=Y^2, zz=1. */
    round1[3]=reduced[2]; round1[4]=p->y;                       /* xy=X*Y, yz=Y.          */
  } else {
    fd_bls_fp2_wide_t wide1[5];
    fp2_wide_set_mul( &wide1[0], &p->x, &p->x ); /* wide1[0] = X^2. */
    fp2_wide_set_mul( &wide1[1], &p->y, &p->y ); /* wide1[1] = Y^2. */
    fp2_wide_set_mul( &wide1[2], &p->z, &p->z ); /* wide1[2] = Z^2. */
    fp2_wide_set_mul( &wide1[3], &p->x, &p->y ); /* wide1[3] = X*Y. */
    fp2_wide_set_mul( &wide1[4], &p->y, &p->z ); /* wide1[4] = Y*Z. */
    fp2_reduce_batch5( round1, wide1 );
  }
  fd_bls_fp2_t const * xx=&round1[0], * yy=&round1[1], * zz=&round1[2];
  fd_bls_fp2_t const * xy=&round1[3], * yz=&round1[4];

  fd_bls_fp2_t eight_yy, b3_zz, yy_plus_b3, b9_zz;
  fd_bls_fp2_t yy_minus_b9, two_xy;
  fp2_mul_small( &eight_yy, yy, 8U );                /* eight_yy    = 8Y^2.               */
  fp2_mul_3b( &b3_zz, zz );                          /* b3_zz       = 3bZ^2.              */
  fd_bls_fp2_sub( &prepared->c, &b3_zz, yy );        /* prepared.c = ell_0=3bZ^2-Y^2.   */
  prepared->x = *xx;                                 /* prepared.x = X^2; multiply by 3xP later. */
  prepared->y = *yz;                                 /* prepared.y = YZ;  multiply by -2yP later. */
  fd_bls_fp2_add( &yy_plus_b3, yy, &b3_zz );         /* yy_plus_b3   = Y^2+3bZ^2.          */
  fp2_mul_small( &b9_zz, &b3_zz, 3U );               /* b9ZZ       = 9bZ^2.              */
  fd_bls_fp2_sub( &yy_minus_b9, yy, &b9_zz );        /* yyMinusB9  = Y^2-9bZ^2.          */
  fp2_mul_small( &two_xy, xy, 2U );                  /* twoXY      = 2XY.                 */

  fd_bls_fp2_wide_t wide2[3];
  fp2_wide_set_mul( &wide2[0], &yy_minus_b9, &yy_plus_b3 ); /* Y3 = (Y^2-9bZ^2)(Y^2+3bZ^2) ... */
  fp2_wide_addmul( &wide2[0], &eight_yy, &b3_zz );          /* ... + (8Y^2)(3bZ^2).              */
  fp2_wide_set_mul( &wide2[1], &yy_minus_b9, &two_xy );     /* X3 = (Y^2-9bZ^2)(2XY).             */
  fp2_wide_set_mul( &wide2[2], &eight_yy, yz );             /* Z3 = (8Y^2)(YZ).                    */
  fd_bls_fp2_t round2[3];
  fp2_reduce_batch3( round2, wide2 );
  return (fd_bls_p2_projective_t){ round2[1], round2[0], round2[2] };
}

static fd_bls_p2_projective_t
add_step_prepare( fd_bls_p2_projective_t const *  p,
                  fd_bls_miller_prepared_line_t * prepared,
                  fd_bls_fp2_t const *            e2x,
                  fd_bls_fp2_t const *            e2y ) {
  fd_bls_fp2_wide_t wide1[6];
  fp2_wide_set_mul( &wide1[0], e2x, &p->x ); /* wide1[0] = xQ*X. */
  fp2_wide_set_mul( &wide1[1], e2x, &p->y ); /* wide1[1] = xQ*Y. */
  fp2_wide_set_mul( &wide1[2], e2x, &p->z ); /* wide1[2] = xQ*Z. */
  fp2_wide_set_mul( &wide1[3], e2y, &p->x ); /* wide1[3] = yQ*X. */
  fp2_wide_set_mul( &wide1[4], e2y, &p->y ); /* wide1[4] = yQ*Y. */
  fp2_wide_set_mul( &wide1[5], e2y, &p->z ); /* wide1[5] = yQ*Z. */
  fd_bls_fp2_t round1[6];
  fp2_reduce_batch6( round1, wide1 );
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
  fp2_mul_small( &three_x2x1, x2x1, 3U );                  /* threeXX = 3xQ*X.     */
  fp2_mul_3b( &b3z1, &p->z );                              /* b3Z     = 3bZ.       */
  fd_bls_fp2_add( &y2y1_plus_b3, y2y1, &b3z1 );           /* yp      = yQ*Y+3bZ.  */
  fd_bls_fp2_sub( &y2y1_minus_b3, y2y1, &b3z1 );          /* ym      = yQ*Y-3bZ.  */
  fp2_mul_3b( &b3_xsum, &x2z1_plus_x1 );                  /* bx      = 3b*xzsum.   */

  fd_bls_fp2_wide_t wide2[3];
  fp2_wide_set_mul( &wide2[0], &x2y1_plus_y2x1, &y2y1_minus_b3 ); /* X3 = xysum*ym ...  */
  fp2_wide_submul( &wide2[0], &b3_xsum, &y2z1_plus_y1 );          /* ... - bx*yzsum.     */
  fp2_wide_set_mul( &wide2[1], &b3_xsum, &three_x2x1 );           /* Y3 = bx*threeXX ...  */
  fp2_wide_addmul( &wide2[1], &y2y1_plus_b3, &y2y1_minus_b3 );   /* ... + yp*ym.        */
  fp2_wide_set_mul( &wide2[2], &y2y1_plus_b3, &y2z1_plus_y1 );   /* Z3 = yp*yzsum ...    */
  fp2_wide_addmul( &wide2[2], &x2y1_plus_y2x1, &three_x2x1 );    /* ... + xysum*threeXX. */
  fd_bls_fp2_t round2[3];
  fp2_reduce_batch3( round2, wide2 );
  return (fd_bls_p2_projective_t){ round2[0], round2[1], round2[2] };
}

static inline void
prepared_line_eval( fd_bls_fp_t                           out[6],
                    fd_bls_miller_prepared_line_t const * prepared,
                    fd_bls_fp_t const *                   x,
                    fd_bls_fp_t const *                   y ) {
  fd_bls_fp2_wide_t wide[2];
  fp2_wide_set_mul_fp( &wide[0], &prepared->x, x ); /* evaluated[0] = ell_x*xP. */
  fp2_wide_set_mul_fp( &wide[1], &prepared->y, y ); /* evaluated[1] = ell_y*yP. */
  fd_bls_fp2_t evaluated[2];
  fp2_reduce_batch2( evaluated, wide );
  out[0]=prepared->c.c[0]; out[1]=prepared->c.c[1];
  out[2]=evaluated[0].c[0]; out[3]=evaluated[0].c[1];
  out[4]=evaluated[1].c[0]; out[5]=evaluated[1].c[1];
}

int
fd_bls_g2_prepare_avx512( fd_bls_g2_prepared_t * out,
                          fd_bls_g2_t const *    q ) {
  if( FD_UNLIKELY( !out || !q ) ) return -1;
  fd_bls_g2_prepared_private_t * prepared = (fd_bls_g2_prepared_private_t *)out;
  fd_bls_fp2_t e2x, e2y;
  fp2_from_normal( &e2x, q->x );
  fp2_from_normal( &e2y, q->y );
  fd_bls_p2_projective_t r = { .x=e2x, .y=e2y };
  fp2_one( &r.z );

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
fd_bls_pairing_finalverify_prepared_checked_avx512(
    fd_bls_g1_t const *          p_prepared,
    fd_bls_g2_prepared_t const * q_prepared,
    fd_bls_g1_t const *          p_checked,
    fd_bls_g2_t const *          q_checked ) {
  if( FD_UNLIKELY( !p_prepared || !q_prepared || !p_checked || !q_checked ) ) return -1;
  fd_bls_g2_prepared_private_t const * prepared = (fd_bls_g2_prepared_private_t const *)q_prepared;

  fd_bls_fp_t e1x, e1y, three_e1x, minus_two_e1y;
  miller_g1_init( &e1x, &e1y, &three_e1x, &minus_two_e1y, p_prepared );
  fd_bls_miller_state_t checked;
  miller_state_init( &checked, p_checked, q_checked );

  fd_bls_fp_t prepared_line[6], checked_line[6];
  ulong line_idx = 0UL;
  prepared_line_eval( prepared_line, prepared->line+line_idx++, &three_e1x, &minus_two_e1y ); /* lp=ell_{Qp,Qp}(Pp). */
  checked.r = double_step( &checked.r, checked_line, &checked.three_e1x,
                           &checked.minus_two_e1y, 1 ); /* Rc=2Qc; lc=ell_{Qc,Qc}(Pc). */
  fd_bls_fp12_t product;
  fp12_set_line( &product, prepared_line );                         /* product = lp.    */
  fd_bls_fp12_mul_sparse( &product, &product, checked_line );       /* product = lp*lc. */

  for( int i=0; i<5; i++ ) {
    prepared_line_eval( prepared_line, prepared->line+line_idx++, &e1x, &e1y ); /* lp=ell_{Rp,Qp}(Pp). */
    fd_bls_fp12_mul_sparse( &product, &product, prepared_line );              /* product *= lp.         */
    checked.r = add_step( &checked.r, checked_line, &checked.e1x, &checked.e1y,
                          &checked.e2x, &checked.e2y );                       /* Rc<-Rc+Qc; lc=ell_{Rc,Qc}(Pc). */
    fd_bls_fp12_mul_sparse( &product, &product, checked_line );               /* product *= lc. */
    for( uint j=0U; j<fd_bls_miller_iterations[i]; j++ ) {
      fd_bls_fp12_sqr( &product, &product );                                 /* product <- product^2. */
      prepared_line_eval( prepared_line, prepared->line+line_idx++,
                          &three_e1x, &minus_two_e1y );                       /* lp=ell_{Rp,Rp}(Pp).    */
      fd_bls_fp12_mul_sparse( &product, &product, prepared_line );           /* product *= lp.         */
      checked.r = double_step( &checked.r, checked_line, &checked.three_e1x,
                               &checked.minus_two_e1y, 0 );                   /* Rc<-2Rc; lc=ell_{Rc,Rc}(Pc). */
      fd_bls_fp12_mul_sparse( &product, &product, checked_line );            /* product *= lc. */
    }
  }
  if( FD_UNLIKELY( line_idx!=FD_BLS_MILLER_PREPARED_LINE_CNT ) ) return -1;
  if( FD_UNLIKELY( !miller_state_q_in_g2( &checked ) ) ) return 0;
  fp12_conjugate( &product ); /* product^-1 = f_{z,Qp}(Pp)*f_{z,Qc}(Pc), since z<0. */

  fd_bls_fp12_t final;
  fd_bls_final_exp( &final, &product ); /* final=product^((p^12-1)/r)=e(Pp,Qp)e(Pc,Qc). */
  return fd_bls_fp12_is_one( &final );  /* Verify that the pairing product is one.                   */
}

static int
miller_loop_n_small( fd_bls_fp12_t *     out,
                     fd_bls_g1_t const * p,
                     fd_bls_g2_t const * q,
                     ulong               cnt,
                     ulong               q_subgroup_mask ) {
  /* Accumulate product_k f_{z,Q_k}(P_k); shared squarings let the whole
     pairing product use one final exponentiation. */
  fd_bls_miller_state_t state[3];
  fd_bls_fp_t line[3][6];
  for( ulong k=0UL; k<cnt; k++ ) {
    miller_state_init( &state[k], &p[k], &q[k] );
    state[k].r = double_step( &state[k].r, line[k], &state[k].three_e1x, &state[k].minus_two_e1y, 1 ); /* Rk=2Qk; lk=ell_{Qk,Qk}(Pk). */
  }
  fp12_set_line( out, line[0] );                                               /* out = l0.             */
  for( ulong k=1UL; k<cnt; k++ ) fd_bls_fp12_mul_sparse( out, out, line[k] ); /* out = product_k lk.   */

  for( int i=0; i<5; i++ ) {
    for( ulong k=0UL; k<cnt; k++ ) {
      state[k].r = add_step( &state[k].r, line[k], &state[k].e1x, &state[k].e1y,
                            &state[k].e2x, &state[k].e2y ); /* Rk<-Rk+Qk; lk=ell_{Rk,Qk}(Pk). */
      fd_bls_fp12_mul_sparse( out, out, line[k] );         /* out *= lk.                        */
    }
    for( uint j=0U; j<fd_bls_miller_iterations[i]; j++ ) {
      fd_bls_fp12_sqr( out, out );                         /* out <- out^2 for the next scalar bit. */
      for( ulong k=0UL; k<cnt; k++ ) {
        state[k].r = double_step( &state[k].r, line[k], &state[k].three_e1x,
                                  &state[k].minus_two_e1y, 0 ); /* Rk<-2Rk; lk=ell_{Rk,Rk}(Pk). */
        fd_bls_fp12_mul_sparse( out, out, line[k] );             /* out *= lk.                         */
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
fd_bls_miller_loop_avx512( fd_bls_fp12_t *     out,
                           fd_bls_g1_t const * p,
                           fd_bls_g2_t const * q ) {
  (void)miller_loop_n_small( out, p, q, 1UL, 0UL );
}

int
fd_bls_pairing_avx512( fd_bls_fp12_t *     out,
                       fd_bls_g1_t const * p,
                       fd_bls_g2_t const * q,
                       ulong               cnt ) {
  if( FD_UNLIKELY( !out || (cnt && (!p || !q)) ) ) return -1;
  if( FD_UNLIKELY( !cnt ) ) {
    fd_bls_fp12_one( out );
    return 0;
  }

  /* Multiply Miller functions first, then apply the exponent once:
     (prod_i f_i)^((p^12-1)/r) = prod_i e(P_i,Q_i). */
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
fd_bls_pairing_finalverify_checked_avx512( fd_bls_g1_t const * p,
                                           fd_bls_g2_t const * q,
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
fd_bls_pairing_finalverify_avx512( fd_bls_g1_t const * p,
                                   fd_bls_g2_t const * q,
                                   ulong               cnt ) {
  return fd_bls_pairing_finalverify_checked_avx512( p, q, cnt, 0UL );
}

#endif
