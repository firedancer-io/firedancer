/* BN254 Miller loop over the VROOM engine: optimal-ate pairing with the
   6z+2 signed-digit schedule, homogeneous projective line evaluation
   (eprint 2012/408 shapes, matching the scalar fd_bn254_pairing.c), and
   the two frobenius tail lines.  The D-type twist line c + x*w + y*w*v
   occupies Fp12 slots {0,1}, {6,7}, {8,9}.  Part of the BN254 unity TU. */

#if FD_HAS_AVX512

/* gnark's signed-digit encoding of 6z+2 (fd_bn254_pairing.c s[]): the two
   implicit top digits (0, 1) are handled by the loop prologue. */
static schar const bn254_miller_digits[64] = {
   0,  0,  0,  1,  0,  1,  0, -1,
   0,  0, -1,  0,  0,  0,  1,  0,
   0, -1,  0, -1,  0,  0,  0,  1,
   0, -1,  0,  0,  0,  0, -1,  0,
   0,  1,  0, -1,  0,  0,  1,  0,
   0,  0,  0,  0, -1,  0,  0, -1,
   0,  1,  0, -1,  0,  0,  0, -1,
   0, -1,  0,  0,  0,  1,  0, -1,
};

typedef struct {
  vroom_p2_projective_t r;        /* running T */
  vroom_fp_t            e1x, e1y; /* affine P (negated y NOT folded) */
  vroom_fp2_t           e2x, e2y; /* affine Q */
} bn254_miller_state_t;

/* Doubling step with tangent evaluation, following the scalar reference
   (fd_bn254_pairing_proj_dbl, eprint 2013/722 Eq. 11):

     A = X*Y/2, B = Y^2, C = Z^2, E = 3b'*C, F = 3E, G = (B+F)/2,
     H = (Y+Z)^2 - B - C
     line = -H*yP + 3*X^2*xP * w + (E-B) * w*v
     X3 = A*(B-F), Y3 = G^2 - 3E^2, Z3 = B*H

   The division by 2 uses the encoded inv2 constant. */
static void
bn254_double_step( bn254_miller_state_t * st,
                   vroom_fp_t             line[6] ) {
  vroom_p2_projective_t const * t = &st->r;
  vroom_fp2_t inv2;
  inv2.c[0] = VROOM_FP_CONST( inv2 );
  vroom_fp_zero( &inv2.c[1] );

  vroom_fp2_wide_t w1[5];
  vroom_fp2_wide_set_mul( &w1[0], &t->x, &t->y );   /* X*Y */
  vroom_fp2_wide_set_mul( &w1[1], &t->y, &t->y );   /* B = Y^2 */
  vroom_fp2_wide_set_mul( &w1[2], &t->z, &t->z );   /* C = Z^2 */
  vroom_fp2_wide_set_mul( &w1[3], &t->x, &t->x );   /* X^2 */
  vroom_fp2_wide_set_mul( &w1[4], &t->y, &t->z );   /* (for H via 2YZ) */
  vroom_fp2_t r1[5];
  vroom_fp2_reduce_batch5( r1, w1 );
  vroom_fp2_t const * xy=&r1[0], * b=&r1[1], * c=&r1[2], * xx=&r1[3], * yz=&r1[4];

  /* H = (Y+Z)^2 - B - C = 2YZ. */
  vroom_fp2_t h;
  vroom_fp2_mul_small( &h, yz, 2U );

  vroom_fp2_t e, f, b_minus_f, g2_arg, e3;
  vroom_fp2_mul_3b( &e, c );                    /* E = 3b'*C            */
  vroom_fp2_mul_small( &f, &e, 3U );            /* F = 3E               */
  vroom_fp2_sub( &b_minus_f, b, &f );           /* B-F                  */
  vroom_fp2_add( &g2_arg, b, &f );              /* B+F (halved below)   */
  vroom_fp2_mul_small( &e3, &e, 3U );           /* for 3E^2 use (3E)*E   */

  /* A = X*Y/2 and G = (B+F)/2 via inv2. */
  vroom_fp2_wide_t w2[6];
  vroom_fp2_wide_set_mul( &w2[0], xy, &inv2 );        /* A           */
  vroom_fp2_wide_set_mul( &w2[1], &g2_arg, &inv2 );   /* G           */
  vroom_fp2_wide_set_mul_fp( &w2[2], &h, &st->e1y );  /* H*yP        */
  vroom_fp2_wide_set_mul_fp( &w2[3], xx, &st->e1x );  /* X^2*xP      */
  vroom_fp2_wide_set_mul( &w2[4], &e3, &e );          /* 3E^2        */
  vroom_fp2_wide_set_mul( &w2[5], b, &h );            /* Z3 = B*H    */
  vroom_fp2_t r2[6];
  vroom_fp2_reduce_batch6( r2, w2 );
  vroom_fp2_t const * a=&r2[0], * g=&r2[1], * h_yp=&r2[2];
  vroom_fp2_t const * xx_xp=&r2[3], * e3e=&r2[4], * z3=&r2[5];

  /* line_c = -H*yP, line_x = 3*X^2*xP, line_y = E-B (slot w*v). */
  vroom_fp2_t line_c, line_x, line_y;
  vroom_fp2_neg( &line_c, h_yp );
  vroom_fp2_mul_small( &line_x, xx_xp, 3U );
  vroom_fp2_sub( &line_y, &e, b );

  /* X3 = A*(B-F), Y3 = G^2 - 3E^2. */
  vroom_fp2_wide_t w3[2];
  vroom_fp2_wide_set_mul( &w3[0], a, &b_minus_f );
  vroom_fp2_wide_set_mul( &w3[1], g, g );
  vroom_fp2_t r3[2];
  vroom_fp2_reduce_batch2( r3, w3 );
  st->r.x = r3[0];
  vroom_fp2_sub( &st->r.y, &r3[1], e3e );
  st->r.z = *z3;

  line[0]=line_c.c[0]; line[1]=line_c.c[1];
  line[2]=line_x.c[0]; line[3]=line_x.c[1];
  line[4]=line_y.c[0]; line[5]=line_y.c[1];
}

/* Addition step with secant evaluation (fd_bn254_pairing_proj_add_sub,
   eprint 2013/722 Eq. 12/13): Q' = is_add ? Q : -Q;

     A = Y2'*Z, B = X2*Z, o = Y - A, l = X - B,
     j = o*X2, k = l*Y2'
     line = l*yP - o*xP * w + (j-k) * w*v
   and when add_point:
     C = o^2, D = l^2, E = l^3, F = Z*C, G = X*D,
     H = E + F - 2G, I = Y*E
     X3 = l*H, Y3 = o*(G-H) - I, Z3 = Z*E */
static void
bn254_add_step( bn254_miller_state_t * st,
                vroom_fp_t             line[6],
                int                    is_add,
                int                    add_point,
                vroom_fp2_t const *    qx,
                vroom_fp2_t const *    qy_in ) {
  vroom_p2_projective_t const * t = &st->r;
  vroom_fp2_t qy = *qy_in;
  if( !is_add ) { vroom_fp2_neg( &qy, &qy ); }

  vroom_fp2_wide_t w1[2];
  vroom_fp2_wide_set_mul( &w1[0], &qy, &t->z );  /* A = Y2'*Z */
  vroom_fp2_wide_set_mul( &w1[1], qx, &t->z );   /* B = X2*Z  */
  vroom_fp2_t r1[2];
  vroom_fp2_reduce_batch2( r1, w1 );

  vroom_fp2_t o, l;
  vroom_fp2_sub( &o, &t->y, &r1[0] );            /* o = Y - A */
  vroom_fp2_sub( &l, &t->x, &r1[1] );            /* l = X - B */

  vroom_fp2_wide_t w2[4];
  vroom_fp2_wide_set_mul( &w2[0], &o, qx );            /* j = o*X2  */
  vroom_fp2_wide_set_mul( &w2[1], &l, &qy );           /* k = l*Y2' */
  vroom_fp2_wide_set_mul_fp( &w2[2], &l, &st->e1y );   /* l*yP      */
  vroom_fp2_wide_set_mul_fp( &w2[3], &o, &st->e1x );   /* o*xP      */
  vroom_fp2_t r2[4];
  vroom_fp2_reduce_batch4( r2, w2 );

  vroom_fp2_t line_y;
  vroom_fp2_sub( &line_y, &r2[0], &r2[1] );      /* j-k */
  vroom_fp2_t line_x;
  vroom_fp2_neg( &line_x, &r2[3] );              /* -o*xP */

  line[0]=r2[2].c[0];  line[1]=r2[2].c[1];       /* l*yP */
  line[2]=line_x.c[0]; line[3]=line_x.c[1];
  line[4]=line_y.c[0]; line[5]=line_y.c[1];

  if( add_point ) {
    vroom_fp2_wide_t w3[2];
    vroom_fp2_wide_set_mul( &w3[0], &o, &o );    /* C = o^2 */
    vroom_fp2_wide_set_mul( &w3[1], &l, &l );    /* D = l^2 */
    vroom_fp2_t r3[2];
    vroom_fp2_reduce_batch2( r3, w3 );
    vroom_fp2_t const * cc=&r3[0], * dd=&r3[1];

    vroom_fp2_wide_t w4[4];
    vroom_fp2_wide_set_mul( &w4[0], dd, &l );    /* E = l^3 */
    vroom_fp2_wide_set_mul( &w4[1], &t->z, cc ); /* F = Z*C */
    vroom_fp2_wide_set_mul( &w4[2], &t->x, dd ); /* G = X*D */
    vroom_fp2_wide_set_mul( &w4[3], &t->y, dd ); /* (Y*D, for I=Y*E=Y*D*l) */
    vroom_fp2_t r4[4];
    vroom_fp2_reduce_batch4( r4, w4 );
    vroom_fp2_t const * e=&r4[0], * f=&r4[1], * g=&r4[2], * yd=&r4[3];

    vroom_fp2_t hh, g_minus_h;
    vroom_fp2_add( &hh, e, f );
    vroom_fp2_sub( &hh, &hh, g );
    vroom_fp2_sub( &hh, &hh, g );                /* H = E+F-2G */
    vroom_fp2_sub( &g_minus_h, g, &hh );

    vroom_fp2_wide_t w5[4];
    vroom_fp2_wide_set_mul( &w5[0], &l, &hh );        /* X3 = l*H          */
    vroom_fp2_wide_set_mul( &w5[1], &o, &g_minus_h ); /* o*(G-H)           */
    vroom_fp2_wide_set_mul( &w5[2], yd, &l );         /* I = Y*E = (Y*D)*l */
    vroom_fp2_wide_set_mul( &w5[3], &t->z, e );       /* Z3 = Z*E          */
    vroom_fp2_t r5[4];
    vroom_fp2_reduce_batch4( r5, w5 );
    st->r.x = r5[0];
    vroom_fp2_sub( &st->r.y, &r5[1], &r5[2] );
    st->r.z = r5[3];
  }
}

/* psi(Q) = pi(Q): conjugate coordinates, scale by gamma1_2 / gamma1_3
   (matches fd_bn254_g2_frob on affine input). */
static void
bn254_psi_affine( vroom_fp2_t *       ox,
                  vroom_fp2_t *       oy,
                  vroom_fp2_t const * x,
                  vroom_fp2_t const * y ) {
  vroom_fp2_t g12 = { { VROOM_FP_CONST( gamma1_2_re ), VROOM_FP_CONST( gamma1_2_im ) } };
  vroom_fp2_t g13 = { { VROOM_FP_CONST( gamma1_3_re ), VROOM_FP_CONST( gamma1_3_im ) } };
  vroom_fp2_t xc = *x, yc = *y;
  vroom_fp_neg( &xc.c[1], &xc.c[1] );  /* conj */
  vroom_fp_neg( &yc.c[1], &yc.c[1] );
  vroom_fp2_mul( ox, &xc, &g12 );
  vroom_fp2_mul( oy, &yc, &g13 );
}

/* psi^2(Q): scale by the Fp gammas gamma2_2 / gamma2_3 (no conjugation;
   matches fd_bn254_g2_frob2 on affine input). */
static void
bn254_psi2_affine( vroom_fp2_t *       ox,
                   vroom_fp2_t *       oy,
                   vroom_fp2_t const * x,
                   vroom_fp2_t const * y ) {
  vroom_fp_t g22 = VROOM_FP_CONST( gamma2_2 );
  vroom_fp_t g23 = VROOM_FP_CONST( gamma2_3 );
  vroom_fp_mul( &ox->c[0], &x->c[0], &g22 );
  vroom_fp_mul( &ox->c[1], &x->c[1], &g22 );
  vroom_fp_mul( &oy->c[0], &y->c[0], &g23 );
  vroom_fp_mul( &oy->c[1], &y->c[1], &g23 );
}

#define BN254_MILLER_BATCH_MAX (16UL)

/* f = prod_k f_{6z+2,Q_k}(P_k) including the two frobenius tail lines.
   Inputs are affine, already subgroup-checked (or checked separately).
   Matches fd_bn254_miller_loop's schedule exactly. */
static void
bn254_miller_loop_n( vroom_fp12_t *         f,
                     bn254_miller_state_t * st,
                     ulong                  cnt ) {
  vroom_fp_t line[6];

  vroom_fp12_one( f );

  /* prologue: digits s[65]=1, s[64]=0, s[63]=-1 of 6z+2 */
  for( ulong k=0UL; k<cnt; k++ ) {
    bn254_double_step( &st[k], line );
    vroom_fp12_mul_sparse( f, f, line );
  }
  vroom_fp12_sqr( f, f );
  for( ulong k=0UL; k<cnt; k++ ) {
    bn254_add_step( &st[k], line, 0, 0, &st[k].e2x, &st[k].e2y ); /* line only */
    vroom_fp12_mul_sparse( f, f, line );
    bn254_add_step( &st[k], line, 1, 1, &st[k].e2x, &st[k].e2y ); /* T = 3Q */
    vroom_fp12_mul_sparse( f, f, line );
  }

  for( int i=62; i>=0; i-- ) {
    vroom_fp12_sqr( f, f );
    for( ulong k=0UL; k<cnt; k++ ) {
      bn254_double_step( &st[k], line );
      vroom_fp12_mul_sparse( f, f, line );
    }
    if( bn254_miller_digits[i] ) {
      for( ulong k=0UL; k<cnt; k++ ) {
        bn254_add_step( &st[k], line, bn254_miller_digits[i]>0, 1,
                        &st[k].e2x, &st[k].e2y );
        vroom_fp12_mul_sparse( f, f, line );
      }
    }
  }

  /* tail: lines for pi(Q) and -pi^2(Q) */
  for( ulong k=0UL; k<cnt; k++ ) {
    vroom_fp2_t fx, fy;
    bn254_psi_affine( &fx, &fy, &st[k].e2x, &st[k].e2y );
    bn254_add_step( &st[k], line, 1, 1, &fx, &fy );
    vroom_fp12_mul_sparse( f, f, line );

    bn254_psi2_affine( &fx, &fy, &st[k].e2x, &st[k].e2y );
    vroom_fp2_neg( &fy, &fy );
    bn254_add_step( &st[k], line, 1, 0, &fx, &fy ); /* line only */
    vroom_fp12_mul_sparse( f, f, line );
  }
}

#endif /* FD_HAS_AVX512 */
