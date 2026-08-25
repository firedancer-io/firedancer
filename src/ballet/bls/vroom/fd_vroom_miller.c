#include "fd_vroom_miller.h"
#include "fd_vroom_final.h"

#if FD_HAS_AVX512

#include "fd_vroom_constants.h"

typedef struct { fd_vroom_fp2_t x, y, z; } fd_vroom_p2_projective_t;
typedef struct { fd_vroom_fp_wide_t c[2]; } fd_vroom_fp2_wide_t;
typedef struct {
  fd_vroom_p2_projective_t r;
  fd_vroom_fp_t            e1x, e1y, three_e1x, minus_two_e1y;
  fd_vroom_fp2_t           e2x, e2y;
} fd_vroom_miller_state_t;

static uint const fd_vroom_miller_iterations[5] = { 2U, 3U, 9U, 32U, 16U };

#define FD_VROOM_MILLER_PREPARED_LINE_CNT (1UL + 5UL + 2UL + 3UL + 9UL + 32UL + 16UL)

typedef struct {
  fd_vroom_fp2_t c;
  fd_vroom_fp2_t x;
  fd_vroom_fp2_t y;
} fd_vroom_miller_prepared_line_t;

typedef struct {
  fd_vroom_miller_prepared_line_t line[ FD_VROOM_MILLER_PREPARED_LINE_CNT ];
} fd_vroom_g2_prepared_private_t;

FD_STATIC_ASSERT( sizeof(fd_vroom_g2_prepared_private_t)==FD_VROOM_G2_PREPARED_FOOTPRINT,
                  vroom_g2_prepared_footprint );
FD_STATIC_ASSERT( alignof(fd_vroom_g2_prepared_private_t)<=FD_VROOM_G2_PREPARED_ALIGN,
                  vroom_g2_prepared_alignment );

static inline void
fp2_wide_zero( fd_vroom_fp2_wide_t * out ) {
  fd_vroom_fp_wide_offset( &out->c[0] );
  fd_vroom_fp_wide_offset( &out->c[1] );
}

static inline void
fp2_wide_addmul( fd_vroom_fp2_wide_t * out,
                 fd_vroom_fp2_t const * a,
                 fd_vroom_fp2_t const * b ) {
  fd_vroom_fp_wide_addmul( &out->c[0], &a->c[0], &b->c[0] );
  fd_vroom_fp_wide_submul( &out->c[0], &a->c[1], &b->c[1] );
  fd_vroom_fp_wide_addmul( &out->c[1], &a->c[0], &b->c[1] );
  fd_vroom_fp_wide_addmul( &out->c[1], &a->c[1], &b->c[0] );
}

static inline void
fp2_wide_submul( fd_vroom_fp2_wide_t * out,
                 fd_vroom_fp2_t const * a,
                 fd_vroom_fp2_t const * b ) {
  fd_vroom_fp_wide_submul( &out->c[0], &a->c[0], &b->c[0] );
  fd_vroom_fp_wide_addmul( &out->c[0], &a->c[1], &b->c[1] );
  fd_vroom_fp_wide_submul( &out->c[1], &a->c[0], &b->c[1] );
  fd_vroom_fp_wide_submul( &out->c[1], &a->c[1], &b->c[0] );
}

static inline void
fp2_wide_addmul_fp( fd_vroom_fp2_wide_t * out,
                    fd_vroom_fp2_t const * a,
                    fd_vroom_fp_t const *  b ) {
  fd_vroom_fp_wide_addmul( &out->c[0], &a->c[0], b );
  fd_vroom_fp_wide_addmul( &out->c[1], &a->c[1], b );
}

static inline void
fp2_wide_set_mul( fd_vroom_fp2_wide_t * out,
                  fd_vroom_fp2_t const * a,
                  fd_vroom_fp2_t const * b ) {
  fp2_wide_zero( out );
  fp2_wide_addmul( out, a, b );
}

static inline void
fp2_wide_set_mul_fp( fd_vroom_fp2_wide_t * out,
                     fd_vroom_fp2_t const * a,
                     fd_vroom_fp_t const *  b ) {
  fp2_wide_zero( out );
  fp2_wide_addmul_fp( out, a, b );
}

static inline void
fp2_reduce_batch3( fd_vroom_fp2_t       out[3],
                   fd_vroom_fp2_wide_t  in [3] ) {
  fd_vroom_fp_reduce_wide_batch6( &out[0].c[0], &in[0].c[0] );
}

static inline void
fp2_reduce_batch2( fd_vroom_fp2_t       out[2],
                   fd_vroom_fp2_wide_t  in [2] ) {
  fd_vroom_fp_reduce_wide_batch4( &out[0].c[0], &in[0].c[0] );
}

static inline void
fp2_reduce_batch5( fd_vroom_fp2_t       out[5],
                   fd_vroom_fp2_wide_t  in [5] ) {
  fd_vroom_fp_reduce_wide_batch6( &out[0].c[0], &in[0].c[0] );
  fd_vroom_fp_reduce_wide_batch4( &out[3].c[0], &in[3].c[0] );
}

static inline void
fp2_reduce_batch6( fd_vroom_fp2_t       out[6],
                   fd_vroom_fp2_wide_t  in [6] ) {
  fd_vroom_fp_reduce_wide_batch6( &out[0].c[0], &in[0].c[0] );
  fd_vroom_fp_reduce_wide_batch6( &out[3].c[0], &in[3].c[0] );
}

static inline void
fp_from_normal( fd_vroom_fp_t * out,
                ulong const     in[6] ) {
  fd_vroom_fp_from_uint64( out, in );
}

static inline void
fp2_from_normal( fd_vroom_fp2_t * out,
                 ulong const      in[2][6] ) {
  fp_from_normal( &out->c[0], in[0] );
  fp_from_normal( &out->c[1], in[1] );
}

static inline void
fp_mul_small( fd_vroom_fp_t *       out,
              fd_vroom_fp_t const * a,
              uint                  n ) {
  fd_vroom_fp_t r, x = *a;
  fd_vroom_fp_zero( &r );
  while( n ) {
    if( n & 1U ) fd_vroom_fp_add( &r, &r, &x );
    n >>= 1;
    if( n ) fd_vroom_fp_add( &x, &x, &x );
  }
  *out = r;
}

static inline void
fp2_mul_small( fd_vroom_fp2_t *       out,
               fd_vroom_fp2_t const * a,
               uint                   n ) {
  fp_mul_small( &out->c[0], &a->c[0], n );
  fp_mul_small( &out->c[1], &a->c[1], n );
}

static inline void
fp2_one( fd_vroom_fp2_t * out ) {
  fd_vroom_fp_one( &out->c[0] );
  fd_vroom_fp_zero( &out->c[1] );
}

static inline fd_vroom_fp_t
fp_const_miller( ulong const m1[8],
                 ulong const m2[8] ) {
  return (fd_vroom_fp_t){
    .m1 = _mm512_load_si512( (__m512i const *)m1 ),
    .m2 = _mm512_load_si512( (__m512i const *)m2 )
  };
}

static inline int
fp2_equal( fd_vroom_fp2_t const * a,
           fd_vroom_fp2_t const * b ) {
  return fd_vroom_fp_equal( &a->c[0], &b->c[0] ) &
         fd_vroom_fp_equal( &a->c[1], &b->c[1] );
}

/* Scott's G2 subgroup relation is psi(Q)=[z]Q.  The Miller chain below
   already leaves state->r=[-z]Q, so checking the relation only needs psi
   and a projective equality instead of another 64-bit scalar multiply. */
static int
miller_state_q_in_g2( fd_vroom_miller_state_t const * state ) {
  fd_vroom_fp2_t x_conj = state->e2x;
  fd_vroom_fp2_t y_conj = state->e2y;
  fd_vroom_fp_neg( &x_conj.c[1], &x_conj.c[1] );
  fd_vroom_fp_neg( &y_conj.c[1], &y_conj.c[1] );

  fd_vroom_fp2_t frob_x, frob_y, psi_x, psi_y;
  fd_vroom_fp_zero( &frob_x.c[0] );
  frob_x.c[1] = fp_const_miller( fd_vroom_frob1_3_m1, fd_vroom_frob1_3_m2 );
  frob_y.c[0] = fp_const_miller( fd_vroom_frob3_2_m1, fd_vroom_frob3_2_m2 );
  frob_y.c[1] = fp_const_miller( fd_vroom_frob3_3_m1, fd_vroom_frob3_3_m2 );
  fd_vroom_fp2_mul( &psi_x, &x_conj, &frob_x );
  fd_vroom_fp2_mul( &psi_y, &y_conj, &frob_y );

  /* The complete Algorithm 8/9 formulas use homogeneous projective
     coordinates (x=X/Z, y=Y/Z), not Jacobian coordinates. */
  fd_vroom_fp2_t rhs_x, rhs_y;
  fd_vroom_fp2_mul( &rhs_x, &psi_x, &state->r.z );
  fd_vroom_fp2_mul( &rhs_y, &psi_y, &state->r.z );
  fd_vroom_fp2_neg( &rhs_y, &rhs_y ); /* compare against -psi(Q)=[-z]Q */
  return fp2_equal( &state->r.x, &rhs_x ) & fp2_equal( &state->r.y, &rhs_y );
}

static inline void
fp2_mul_3b( fd_vroom_fp2_t *       out,
            fd_vroom_fp2_t const * a ) {
  fd_vroom_fp2_t nonres;
  fd_vroom_fp_sub( &nonres.c[0], &a->c[0], &a->c[1] );
  fd_vroom_fp_add( &nonres.c[1], &a->c[0], &a->c[1] );
  fp2_mul_small( out, &nonres, 12U );
}

static inline void
fp12_conjugate( fd_vroom_fp12_t * out ) {
  for( int i=6; i<12; i++ ) fd_vroom_fp_neg( &out->c[i], &out->c[i] );
}

static inline void
fp12_set_line( fd_vroom_fp12_t * out,
               fd_vroom_fp_t const line[6] ) {
  for( int i=0; i<12; i++ ) fd_vroom_fp_zero( &out->c[i] );
  out->c[0]=line[0]; out->c[1]=line[1]; out->c[2]=line[2];
  out->c[3]=line[3]; out->c[8]=line[4]; out->c[9]=line[5];
}

static inline void
miller_g1_init( fd_vroom_fp_t *             e1x,
                fd_vroom_fp_t *             e1y,
                fd_vroom_fp_t *             three_e1x,
                fd_vroom_fp_t *             minus_two_e1y,
                fd_vroom_g1_affine_t const * p ) {
  if( FD_UNLIKELY( !memcmp( p->x, fd_vroom_neg_g1_x_normal, sizeof(p->x) ) &&
                           !memcmp( p->y, fd_vroom_neg_g1_y_normal, sizeof(p->y) ) ) ) {
#define LOAD_FP_CONST(dst,name) do {                                                \
    (dst).m1 = _mm512_load_si512( (__m512i const *)fd_vroom_##name##_m1 );          \
    (dst).m2 = _mm512_load_si512( (__m512i const *)fd_vroom_##name##_m2 );          \
  } while(0)
    LOAD_FP_CONST( *e1x,          neg_g1_x );
    LOAD_FP_CONST( *e1y,          neg_g1_y );
    LOAD_FP_CONST( *three_e1x,    neg_g1_3x );
    LOAD_FP_CONST( *minus_two_e1y, neg_g1_minus_2y );
#undef LOAD_FP_CONST
  } else {
    fp_from_normal( e1x, p->x );
    fp_from_normal( e1y, p->y );
    fp_mul_small( three_e1x, e1x, 3U );
    fd_vroom_fp_neg( minus_two_e1y, e1y );
    fp_mul_small( minus_two_e1y, minus_two_e1y, 2U );
  }
}

static inline void
miller_state_init( fd_vroom_miller_state_t *   state,
                   fd_vroom_g1_affine_t const * p,
                   fd_vroom_g2_affine_t const * q ) {
  miller_g1_init( &state->e1x, &state->e1y, &state->three_e1x,
                  &state->minus_two_e1y, p );
  fp2_from_normal( &state->e2x, q->x );
  fp2_from_normal( &state->e2y, q->y );
  state->r.x = state->e2x;
  state->r.y = state->e2y;
  fp2_one( &state->r.z );
}

static fd_vroom_p2_projective_t
double_step( fd_vroom_p2_projective_t const * p,
             fd_vroom_fp_t                    line[6],
             fd_vroom_fp_t const *            three_e1x,
             fd_vroom_fp_t const *            minus_two_e1y,
             int                              first ) {
  fd_vroom_fp2_t round1[5];
  if( FD_UNLIKELY( first ) ) {
    fd_vroom_fp2_wide_t wide1[3];
    fd_vroom_fp2_t reduced[3];
    fp2_wide_set_mul( &wide1[0], &p->x, &p->x );
    fp2_wide_set_mul( &wide1[1], &p->y, &p->y );
    fp2_wide_set_mul( &wide1[2], &p->x, &p->y );
    fp2_reduce_batch3( reduced, wide1 );
    round1[0]=reduced[0]; round1[1]=reduced[1]; round1[2]=p->z;
    round1[3]=reduced[2]; round1[4]=p->y;
  } else {
    fd_vroom_fp2_wide_t wide1[5];
    fp2_wide_set_mul( &wide1[0], &p->x, &p->x );
    fp2_wide_set_mul( &wide1[1], &p->y, &p->y );
    fp2_wide_set_mul( &wide1[2], &p->z, &p->z );
    fp2_wide_set_mul( &wide1[3], &p->x, &p->y );
    fp2_wide_set_mul( &wide1[4], &p->y, &p->z );
    fp2_reduce_batch5( round1, wide1 );
  }
  fd_vroom_fp2_t const * xx=&round1[0], * yy=&round1[1], * zz=&round1[2];
  fd_vroom_fp2_t const * xy=&round1[3], * yz=&round1[4];

  fd_vroom_fp2_t eight_yy, b3_zz, line_c, yy_plus_b3, b9_zz;
  fd_vroom_fp2_t yy_minus_b9, two_xy;
  fp2_mul_small( &eight_yy, yy, 8U );
  fp2_mul_3b( &b3_zz, zz );
  fd_vroom_fp2_sub( &line_c, &b3_zz, yy );
  fd_vroom_fp2_add( &yy_plus_b3, yy, &b3_zz );
  fp2_mul_small( &b9_zz, &b3_zz, 3U );
  fd_vroom_fp2_sub( &yy_minus_b9, yy, &b9_zz );
  fp2_mul_small( &two_xy, xy, 2U );

  fd_vroom_fp2_wide_t wide2[5];
  fp2_wide_set_mul_fp( &wide2[0], xx, three_e1x );
  fp2_wide_set_mul_fp( &wide2[1], yz, minus_two_e1y );
  fp2_wide_set_mul( &wide2[2], &yy_minus_b9, &yy_plus_b3 );
  fp2_wide_addmul( &wide2[2], &eight_yy, &b3_zz );
  fp2_wide_set_mul( &wide2[3], &yy_minus_b9, &two_xy );
  fp2_wide_set_mul( &wide2[4], &eight_yy, yz );
  fd_vroom_fp2_t round2[5];
  fp2_reduce_batch5( round2, wide2 );
  fd_vroom_fp2_t const * line_x=&round2[0], * line_y=&round2[1];
  fd_vroom_fp2_t const * y3=&round2[2], * x3=&round2[3], * z3=&round2[4];

  line[0]=line_c.c[0];  line[1]=line_c.c[1];
  line[2]=line_x->c[0]; line[3]=line_x->c[1];
  line[4]=line_y->c[0]; line[5]=line_y->c[1];
  return (fd_vroom_p2_projective_t){ *x3, *y3, *z3 };
}

static fd_vroom_p2_projective_t
add_step( fd_vroom_p2_projective_t const * p,
          fd_vroom_fp_t                    line[6],
          fd_vroom_fp_t const *            e1x,
          fd_vroom_fp_t const *            e1y,
          fd_vroom_fp2_t const *           e2x,
          fd_vroom_fp2_t const *           e2y ) {
  fd_vroom_fp2_wide_t wide1[6];
  fp2_wide_set_mul( &wide1[0], e2x, &p->x );
  fp2_wide_set_mul( &wide1[1], e2x, &p->y );
  fp2_wide_set_mul( &wide1[2], e2x, &p->z );
  fp2_wide_set_mul( &wide1[3], e2y, &p->x );
  fp2_wide_set_mul( &wide1[4], e2y, &p->y );
  fp2_wide_set_mul( &wide1[5], e2y, &p->z );
  fd_vroom_fp2_t round1[6];
  fp2_reduce_batch6( round1, wide1 );
  fd_vroom_fp2_t const * x2x1=&round1[0], * x2y1=&round1[1], * x2z1=&round1[2];
  fd_vroom_fp2_t const * y2x1=&round1[3], * y2y1=&round1[4], * y2z1=&round1[5];

  fd_vroom_fp2_t line_c, xq_coef, yq_coef, x2y1_plus_y2x1;
  fd_vroom_fp2_t y2z1_plus_y1, x2z1_plus_x1, three_x2x1;
  fd_vroom_fp2_t b3z1, y2y1_plus_b3, y2y1_minus_b3, b3_xsum;
  fd_vroom_fp2_sub( &line_c, x2y1, y2x1 );
  fd_vroom_fp2_sub( &xq_coef, y2z1, &p->y );
  fd_vroom_fp2_sub( &yq_coef, &p->x, x2z1 );
  fd_vroom_fp2_add( &x2y1_plus_y2x1, x2y1, y2x1 );
  fd_vroom_fp2_add( &y2z1_plus_y1, y2z1, &p->y );
  fd_vroom_fp2_add( &x2z1_plus_x1, x2z1, &p->x );
  fp2_mul_small( &three_x2x1, x2x1, 3U );
  fp2_mul_3b( &b3z1, &p->z );
  fd_vroom_fp2_add( &y2y1_plus_b3, y2y1, &b3z1 );
  fd_vroom_fp2_sub( &y2y1_minus_b3, y2y1, &b3z1 );
  fp2_mul_3b( &b3_xsum, &x2z1_plus_x1 );

  fd_vroom_fp2_wide_t wide2[5];
  fp2_wide_set_mul( &wide2[0], &x2y1_plus_y2x1, &y2y1_minus_b3 );
  fp2_wide_submul( &wide2[0], &b3_xsum, &y2z1_plus_y1 );
  fp2_wide_set_mul( &wide2[1], &b3_xsum, &three_x2x1 );
  fp2_wide_addmul( &wide2[1], &y2y1_plus_b3, &y2y1_minus_b3 );
  fp2_wide_set_mul( &wide2[2], &y2y1_plus_b3, &y2z1_plus_y1 );
  fp2_wide_addmul( &wide2[2], &x2y1_plus_y2x1, &three_x2x1 );
  fp2_wide_set_mul_fp( &wide2[3], &xq_coef, e1x );
  fp2_wide_set_mul_fp( &wide2[4], &yq_coef, e1y );
  fd_vroom_fp2_t round2[5];
  fp2_reduce_batch5( round2, wide2 );
  fd_vroom_fp2_t const * x3=&round2[0], * y3=&round2[1], * z3=&round2[2];
  fd_vroom_fp2_t const * line_x=&round2[3], * line_y=&round2[4];

  line[0]=line_c.c[0];  line[1]=line_c.c[1];
  line[2]=line_x->c[0]; line[3]=line_x->c[1];
  line[4]=line_y->c[0]; line[5]=line_y->c[1];
  return (fd_vroom_p2_projective_t){ *x3, *y3, *z3 };
}

/* The G2 state transition and the unevaluated line coefficients depend only
   on Q.  Preparing those once leaves just the two base-field evaluations at
   P for each subsequent pairing. */
static fd_vroom_p2_projective_t
double_step_prepare( fd_vroom_p2_projective_t const * p,
                     fd_vroom_miller_prepared_line_t * prepared,
                     int                                first ) {
  fd_vroom_fp2_t round1[5];
  if( FD_UNLIKELY( first ) ) {
    fd_vroom_fp2_wide_t wide1[3];
    fd_vroom_fp2_t reduced[3];
    fp2_wide_set_mul( &wide1[0], &p->x, &p->x );
    fp2_wide_set_mul( &wide1[1], &p->y, &p->y );
    fp2_wide_set_mul( &wide1[2], &p->x, &p->y );
    fp2_reduce_batch3( reduced, wide1 );
    round1[0]=reduced[0]; round1[1]=reduced[1]; round1[2]=p->z;
    round1[3]=reduced[2]; round1[4]=p->y;
  } else {
    fd_vroom_fp2_wide_t wide1[5];
    fp2_wide_set_mul( &wide1[0], &p->x, &p->x );
    fp2_wide_set_mul( &wide1[1], &p->y, &p->y );
    fp2_wide_set_mul( &wide1[2], &p->z, &p->z );
    fp2_wide_set_mul( &wide1[3], &p->x, &p->y );
    fp2_wide_set_mul( &wide1[4], &p->y, &p->z );
    fp2_reduce_batch5( round1, wide1 );
  }
  fd_vroom_fp2_t const * xx=&round1[0], * yy=&round1[1], * zz=&round1[2];
  fd_vroom_fp2_t const * xy=&round1[3], * yz=&round1[4];

  fd_vroom_fp2_t eight_yy, b3_zz, yy_plus_b3, b9_zz;
  fd_vroom_fp2_t yy_minus_b9, two_xy;
  fp2_mul_small( &eight_yy, yy, 8U );
  fp2_mul_3b( &b3_zz, zz );
  fd_vroom_fp2_sub( &prepared->c, &b3_zz, yy );
  prepared->x = *xx;
  prepared->y = *yz;
  fd_vroom_fp2_add( &yy_plus_b3, yy, &b3_zz );
  fp2_mul_small( &b9_zz, &b3_zz, 3U );
  fd_vroom_fp2_sub( &yy_minus_b9, yy, &b9_zz );
  fp2_mul_small( &two_xy, xy, 2U );

  fd_vroom_fp2_wide_t wide2[3];
  fp2_wide_set_mul( &wide2[0], &yy_minus_b9, &yy_plus_b3 );
  fp2_wide_addmul( &wide2[0], &eight_yy, &b3_zz );
  fp2_wide_set_mul( &wide2[1], &yy_minus_b9, &two_xy );
  fp2_wide_set_mul( &wide2[2], &eight_yy, yz );
  fd_vroom_fp2_t round2[3];
  fp2_reduce_batch3( round2, wide2 );
  return (fd_vroom_p2_projective_t){ round2[1], round2[0], round2[2] };
}

static fd_vroom_p2_projective_t
add_step_prepare( fd_vroom_p2_projective_t const * p,
                  fd_vroom_miller_prepared_line_t * prepared,
                  fd_vroom_fp2_t const *             e2x,
                  fd_vroom_fp2_t const *             e2y ) {
  fd_vroom_fp2_wide_t wide1[6];
  fp2_wide_set_mul( &wide1[0], e2x, &p->x );
  fp2_wide_set_mul( &wide1[1], e2x, &p->y );
  fp2_wide_set_mul( &wide1[2], e2x, &p->z );
  fp2_wide_set_mul( &wide1[3], e2y, &p->x );
  fp2_wide_set_mul( &wide1[4], e2y, &p->y );
  fp2_wide_set_mul( &wide1[5], e2y, &p->z );
  fd_vroom_fp2_t round1[6];
  fp2_reduce_batch6( round1, wide1 );
  fd_vroom_fp2_t const * x2x1=&round1[0], * x2y1=&round1[1], * x2z1=&round1[2];
  fd_vroom_fp2_t const * y2x1=&round1[3], * y2y1=&round1[4], * y2z1=&round1[5];

  fd_vroom_fp2_t x2y1_plus_y2x1, y2z1_plus_y1, x2z1_plus_x1, three_x2x1;
  fd_vroom_fp2_t b3z1, y2y1_plus_b3, y2y1_minus_b3, b3_xsum;
  fd_vroom_fp2_sub( &prepared->c, x2y1, y2x1 );
  fd_vroom_fp2_sub( &prepared->x, y2z1, &p->y );
  fd_vroom_fp2_sub( &prepared->y, &p->x, x2z1 );
  fd_vroom_fp2_add( &x2y1_plus_y2x1, x2y1, y2x1 );
  fd_vroom_fp2_add( &y2z1_plus_y1, y2z1, &p->y );
  fd_vroom_fp2_add( &x2z1_plus_x1, x2z1, &p->x );
  fp2_mul_small( &three_x2x1, x2x1, 3U );
  fp2_mul_3b( &b3z1, &p->z );
  fd_vroom_fp2_add( &y2y1_plus_b3, y2y1, &b3z1 );
  fd_vroom_fp2_sub( &y2y1_minus_b3, y2y1, &b3z1 );
  fp2_mul_3b( &b3_xsum, &x2z1_plus_x1 );

  fd_vroom_fp2_wide_t wide2[3];
  fp2_wide_set_mul( &wide2[0], &x2y1_plus_y2x1, &y2y1_minus_b3 );
  fp2_wide_submul( &wide2[0], &b3_xsum, &y2z1_plus_y1 );
  fp2_wide_set_mul( &wide2[1], &b3_xsum, &three_x2x1 );
  fp2_wide_addmul( &wide2[1], &y2y1_plus_b3, &y2y1_minus_b3 );
  fp2_wide_set_mul( &wide2[2], &y2y1_plus_b3, &y2z1_plus_y1 );
  fp2_wide_addmul( &wide2[2], &x2y1_plus_y2x1, &three_x2x1 );
  fd_vroom_fp2_t round2[3];
  fp2_reduce_batch3( round2, wide2 );
  return (fd_vroom_p2_projective_t){ round2[0], round2[1], round2[2] };
}

static inline void
prepared_line_eval( fd_vroom_fp_t                           out[6],
                    fd_vroom_miller_prepared_line_t const * prepared,
                    fd_vroom_fp_t const *                   x,
                    fd_vroom_fp_t const *                   y ) {
  fd_vroom_fp2_wide_t wide[2];
  fp2_wide_set_mul_fp( &wide[0], &prepared->x, x );
  fp2_wide_set_mul_fp( &wide[1], &prepared->y, y );
  fd_vroom_fp2_t evaluated[2];
  fp2_reduce_batch2( evaluated, wide );
  out[0]=prepared->c.c[0]; out[1]=prepared->c.c[1];
  out[2]=evaluated[0].c[0]; out[3]=evaluated[0].c[1];
  out[4]=evaluated[1].c[0]; out[5]=evaluated[1].c[1];
}

int
fd_vroom_g2_prepare_c( fd_vroom_g2_prepared_t *    out,
                       fd_vroom_g2_affine_t const * q ) {
  if( FD_UNLIKELY( !out || !q ) ) return -1;
  fd_vroom_g2_prepared_private_t * prepared = (fd_vroom_g2_prepared_private_t *)out;
  fd_vroom_fp2_t e2x, e2y;
  fp2_from_normal( &e2x, q->x );
  fp2_from_normal( &e2y, q->y );
  fd_vroom_p2_projective_t r = { .x=e2x, .y=e2y };
  fp2_one( &r.z );

  ulong line_idx = 0UL;
  r = double_step_prepare( &r, prepared->line+line_idx++, 1 );
  for( int i=0; i<5; i++ ) {
    r = add_step_prepare( &r, prepared->line+line_idx++, &e2x, &e2y );
    for( uint j=0U; j<fd_vroom_miller_iterations[i]; j++ )
      r = double_step_prepare( &r, prepared->line+line_idx++, 0 );
  }
  return line_idx==FD_VROOM_MILLER_PREPARED_LINE_CNT ? 0 : -1;
}

int
fd_vroom_pairing_finalverify_prepared_checked_c(
    fd_vroom_g1_affine_t const *   p_prepared,
    fd_vroom_g2_prepared_t const * q_prepared,
    fd_vroom_g1_affine_t const *   p_checked,
    fd_vroom_g2_affine_t const *   q_checked ) {
  if( FD_UNLIKELY( !p_prepared || !q_prepared || !p_checked || !q_checked ) ) return -1;
  fd_vroom_g2_prepared_private_t const * prepared = (fd_vroom_g2_prepared_private_t const *)q_prepared;

  fd_vroom_fp_t e1x, e1y, three_e1x, minus_two_e1y;
  miller_g1_init( &e1x, &e1y, &three_e1x, &minus_two_e1y, p_prepared );
  fd_vroom_miller_state_t checked;
  miller_state_init( &checked, p_checked, q_checked );

  fd_vroom_fp_t prepared_line[6], checked_line[6];
  ulong line_idx = 0UL;
  prepared_line_eval( prepared_line, prepared->line+line_idx++, &three_e1x, &minus_two_e1y );
  checked.r = double_step( &checked.r, checked_line, &checked.three_e1x,
                           &checked.minus_two_e1y, 1 );
  fd_vroom_fp12_t product;
  fp12_set_line( &product, prepared_line );
  fd_vroom_fp12_mul_sparse( &product, &product, checked_line );

  for( int i=0; i<5; i++ ) {
    prepared_line_eval( prepared_line, prepared->line+line_idx++, &e1x, &e1y );
    fd_vroom_fp12_mul_sparse( &product, &product, prepared_line );
    checked.r = add_step( &checked.r, checked_line, &checked.e1x, &checked.e1y,
                          &checked.e2x, &checked.e2y );
    fd_vroom_fp12_mul_sparse( &product, &product, checked_line );
    for( uint j=0U; j<fd_vroom_miller_iterations[i]; j++ ) {
      fd_vroom_fp12_sqr( &product, &product );
      prepared_line_eval( prepared_line, prepared->line+line_idx++,
                          &three_e1x, &minus_two_e1y );
      fd_vroom_fp12_mul_sparse( &product, &product, prepared_line );
      checked.r = double_step( &checked.r, checked_line, &checked.three_e1x,
                               &checked.minus_two_e1y, 0 );
      fd_vroom_fp12_mul_sparse( &product, &product, checked_line );
    }
  }
  if( FD_UNLIKELY( line_idx!=FD_VROOM_MILLER_PREPARED_LINE_CNT ) ) return -1;
  if( FD_UNLIKELY( !miller_state_q_in_g2( &checked ) ) ) return 0;
  fp12_conjugate( &product );

  fd_vroom_fp12_t final;
  fd_vroom_final_exp_c( &final, &product );
  return fd_vroom_fp12_is_one_c( &final );
}

static int
miller_loop_n_small( fd_vroom_fp12_t *      out,
                     fd_vroom_g1_affine_t const * p,
                     fd_vroom_g2_affine_t const * q,
                     ulong                  cnt,
                     ulong                  q_subgroup_mask ) {
  fd_vroom_miller_state_t state[3];
  fd_vroom_fp_t line[3][6];
  for( ulong k=0UL; k<cnt; k++ ) {
    miller_state_init( &state[k], &p[k], &q[k] );
    state[k].r = double_step( &state[k].r, line[k], &state[k].three_e1x, &state[k].minus_two_e1y, 1 );
  }
  fp12_set_line( out, line[0] );
  for( ulong k=1UL; k<cnt; k++ ) fd_vroom_fp12_mul_sparse( out, out, line[k] );

  for( int i=0; i<5; i++ ) {
    for( ulong k=0UL; k<cnt; k++ ) {
      state[k].r = add_step( &state[k].r, line[k], &state[k].e1x, &state[k].e1y,
                            &state[k].e2x, &state[k].e2y );
      fd_vroom_fp12_mul_sparse( out, out, line[k] );
    }
    for( uint j=0U; j<fd_vroom_miller_iterations[i]; j++ ) {
      fd_vroom_fp12_sqr( out, out );
      for( ulong k=0UL; k<cnt; k++ ) {
        state[k].r = double_step( &state[k].r, line[k], &state[k].three_e1x,
                                  &state[k].minus_two_e1y, 0 );
        fd_vroom_fp12_mul_sparse( out, out, line[k] );
      }
    }
  }
  for( ulong k=0UL; k<cnt; k++ )
    if( (q_subgroup_mask & (1UL<<k)) && FD_UNLIKELY( !miller_state_q_in_g2( &state[k] ) ) )
      return 0;
  fp12_conjugate( out );
  return 1;
}

void
fd_vroom_miller_loop_c( fd_vroom_fp12_t *      out,
                        fd_vroom_g1_affine_t const * p,
                        fd_vroom_g2_affine_t const * q ) {
  (void)miller_loop_n_small( out, p, q, 1UL, 0UL );
}

int
fd_vroom_pairing_finalverify_checked_c( fd_vroom_g1_affine_t const * p,
                                        fd_vroom_g2_affine_t const * q,
                                        ulong                  cnt,
                                        ulong                  q_subgroup_mask ) {
  if( FD_UNLIKELY( !p || !q || !cnt ) ) return -1;
  if( FD_UNLIKELY( cnt<8UL*sizeof(ulong) && (q_subgroup_mask>>cnt) ) ) return -1;
  fd_vroom_fp12_t product;
  if( FD_LIKELY( cnt<=3UL ) ) {
    if( FD_UNLIKELY( !miller_loop_n_small( &product, p, q, cnt, q_subgroup_mask ) ) ) return 0;
  } else {
    fd_vroom_fp12_t term;
    if( FD_UNLIKELY( !miller_loop_n_small( &product, &p[0], &q[0], 1UL, q_subgroup_mask & 1UL ) ) ) return 0;
    for( ulong i=1UL; i<cnt; i++ ) {
      ulong check = i<8UL*sizeof(ulong) ? ((q_subgroup_mask>>i)&1UL) : 0UL;
      if( FD_UNLIKELY( !miller_loop_n_small( &term, &p[i], &q[i], 1UL, check ) ) ) return 0;
      fd_vroom_fp12_mul( &product, &product, &term );
    }
  }
  fd_vroom_fp12_t final;
  fd_vroom_final_exp_c( &final, &product );
  return fd_vroom_fp12_is_one_c( &final );
}

int
fd_vroom_pairing_finalverify_c( fd_vroom_g1_affine_t const * p,
                                fd_vroom_g2_affine_t const * q,
                                ulong                  cnt ) {
  return fd_vroom_pairing_finalverify_checked_c( p, q, cnt, 0UL );
}

#endif
