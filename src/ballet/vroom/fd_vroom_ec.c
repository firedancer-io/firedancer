/* VROOM engine: line-free complete homogeneous projective arithmetic on
   the G2 twist y^2 = x^3 + b' (a = 0; Renes-Costello-Batina complete
   formulas).  Unity-TU fragment: the curve TU must define the hook

     static inline void vroom_fp2_mul_3b( vroom_fp2_t * out,
                                          vroom_fp2_t const * a );

   computing out = 3b'*a before including this file. */

#if FD_HAS_AVX512

/* Complete doubling: (X:Y:Z) <- 2(X:Y:Z).  first selects the Z == 1
   entry shape (skips Z^2 and YZ). */
static vroom_p2_projective_t
vroom_ec_double( vroom_p2_projective_t const * p,
                 int                           first ) {
  vroom_fp2_t round1[4];
  if( FD_UNLIKELY( first ) ) {
    vroom_fp2_wide_t wide1[2];
    vroom_fp2_t reduced[2];
    vroom_fp2_wide_set_mul( &wide1[0], &p->y, &p->y ); /* Y^2. */
    vroom_fp2_wide_set_mul( &wide1[1], &p->x, &p->y ); /* X*Y. */
    vroom_fp2_reduce_batch2( reduced, wide1 );
    round1[0]=reduced[0]; round1[1]=p->z;        /* yy=Y^2, zz=Z^2=1. */
    round1[2]=reduced[1]; round1[3]=p->y;        /* xy=X*Y, yz=Y*Z=Y. */
  } else {
    vroom_fp2_wide_t wide1[4];
    vroom_fp2_wide_set_mul( &wide1[0], &p->y, &p->y ); /* Y^2. */
    vroom_fp2_wide_set_mul( &wide1[1], &p->z, &p->z ); /* Z^2. */
    vroom_fp2_wide_set_mul( &wide1[2], &p->x, &p->y ); /* X*Y. */
    vroom_fp2_wide_set_mul( &wide1[3], &p->y, &p->z ); /* Y*Z. */
    vroom_fp2_reduce_batch4( round1, wide1 );
  }
  vroom_fp2_t const * yy=&round1[0], * zz=&round1[1];
  vroom_fp2_t const * xy=&round1[2], * yz=&round1[3];

  vroom_fp2_t eight_yy, b3_zz, yy_plus_b3, b9_zz, yy_minus_b9, two_xy;
  vroom_fp2_mul_small( &eight_yy, yy, 8U );          /* eight_yy   = 8Y^2.      */
  vroom_fp2_mul_3b( &b3_zz, zz );                    /* b3_zz      = 3bZ^2.     */
  vroom_fp2_add( &yy_plus_b3, yy, &b3_zz );          /* yy_plus_b3 = Y^2+3bZ^2. */
  vroom_fp2_mul_small( &b9_zz, &b3_zz, 3U );         /* b9_zz      = 9bZ^2.     */
  vroom_fp2_sub( &yy_minus_b9, yy, &b9_zz );         /* yy_minus_b9= Y^2-9bZ^2. */
  vroom_fp2_mul_small( &two_xy, xy, 2U );            /* two_xy     = 2XY.       */

  vroom_fp2_wide_t wide2[3];
  vroom_fp2_wide_set_mul( &wide2[0], &yy_minus_b9, &yy_plus_b3 ); /* Y3 = (Y^2-9bZ^2)(Y^2+3bZ^2) ... */
  vroom_fp2_wide_addmul( &wide2[0], &eight_yy, &b3_zz );          /* ...  + (8Y^2)(3bZ^2).           */
  vroom_fp2_wide_set_mul( &wide2[1], &yy_minus_b9, &two_xy );     /* X3 = (Y^2-9bZ^2)(2XY).          */
  vroom_fp2_wide_set_mul( &wide2[2], &eight_yy, yz );             /* Z3 = (8Y^2)(YZ).                */
  vroom_fp2_t round2[3];
  vroom_fp2_reduce_batch3( round2, wide2 );
  return (vroom_p2_projective_t){ round2[1], round2[0], round2[2] };
}

/* Complete mixed addition: (X:Y:Z) <- (X:Y:Z) + (xq, yq) with Q affine. */
static vroom_p2_projective_t
vroom_ec_add_pa( vroom_p2_projective_t const * p,
                 vroom_fp2_t const *           e2x,
                 vroom_fp2_t const *           e2y ) {
  vroom_fp2_wide_t wide1[6];
  vroom_fp2_wide_set_mul( &wide1[0], e2x, &p->x ); /* xQ*X. */
  vroom_fp2_wide_set_mul( &wide1[1], e2x, &p->y ); /* xQ*Y. */
  vroom_fp2_wide_set_mul( &wide1[2], e2x, &p->z ); /* xQ*Z. */
  vroom_fp2_wide_set_mul( &wide1[3], e2y, &p->x ); /* yQ*X. */
  vroom_fp2_wide_set_mul( &wide1[4], e2y, &p->y ); /* yQ*Y. */
  vroom_fp2_wide_set_mul( &wide1[5], e2y, &p->z ); /* yQ*Z. */
  vroom_fp2_t round1[6];
  vroom_fp2_reduce_batch6( round1, wide1 );
  vroom_fp2_t const * x2x1=&round1[0], * x2y1=&round1[1], * x2z1=&round1[2];
  vroom_fp2_t const * y2x1=&round1[3], * y2y1=&round1[4], * y2z1=&round1[5];

  vroom_fp2_t x2y1_plus_y2x1, y2z1_plus_y1, x2z1_plus_x1, three_x2x1;
  vroom_fp2_t b3z1, y2y1_plus_b3, y2y1_minus_b3, b3_xsum;
  vroom_fp2_add( &x2y1_plus_y2x1, x2y1, y2x1 );  /* xysum   = xQ*Y+yQ*X. */
  vroom_fp2_add( &y2z1_plus_y1, y2z1, &p->y );   /* yzsum   = yQ*Z+Y.    */
  vroom_fp2_add( &x2z1_plus_x1, x2z1, &p->x );   /* xzsum   = xQ*Z+X.    */
  vroom_fp2_mul_small( &three_x2x1, x2x1, 3U );  /* threeXX = 3xQ*X.     */
  vroom_fp2_mul_3b( &b3z1, &p->z );              /* b3Z     = 3bZ.       */
  vroom_fp2_add( &y2y1_plus_b3, y2y1, &b3z1 );   /* yp      = yQ*Y+3bZ.  */
  vroom_fp2_sub( &y2y1_minus_b3, y2y1, &b3z1 );  /* ym      = yQ*Y-3bZ.  */
  vroom_fp2_mul_3b( &b3_xsum, &x2z1_plus_x1 );   /* bx      = 3b*xzsum.  */

  vroom_fp2_wide_t wide2[3];
  vroom_fp2_wide_set_mul( &wide2[0], &x2y1_plus_y2x1, &y2y1_minus_b3 ); /* X3 = xysum*ym ...   */
  vroom_fp2_wide_submul( &wide2[0], &b3_xsum, &y2z1_plus_y1 );          /* ... - bx*yzsum.     */
  vroom_fp2_wide_set_mul( &wide2[1], &b3_xsum, &three_x2x1 );           /* Y3 = bx*threeXX ... */
  vroom_fp2_wide_addmul( &wide2[1], &y2y1_plus_b3, &y2y1_minus_b3 );    /* ... + yp*ym.        */
  vroom_fp2_wide_set_mul( &wide2[2], &y2y1_plus_b3, &y2z1_plus_y1 );    /* Z3 = yp*yzsum ...   */
  vroom_fp2_wide_addmul( &wide2[2], &x2y1_plus_y2x1, &three_x2x1 );     /* ... + xysum*threeXX.*/
  vroom_fp2_t round2[3];
  vroom_fp2_reduce_batch3( round2, wide2 );
  return (vroom_p2_projective_t){ round2[0], round2[1], round2[2] };
}

/* Complete homogeneous addition of two PROJECTIVE points (vroom_ec_add_pa
   generalized to Q = (Xq:Yq:Zq): substituting the affine xq=Xq/Zq,
   yq=Yq/Zq and clearing the Zq^2 denominator).  Costs 15 muls vs
   vroom_ec_add_pa's 11, but needs no affinization of the addend. */
static vroom_p2_projective_t
vroom_ec_add_pp( vroom_p2_projective_t const * p,
                 vroom_p2_projective_t const * q ) {
  vroom_fp2_wide_t w1a[6], w1b[3];
  vroom_fp2_wide_set_mul( &w1a[0], &q->x, &p->x ); /* Xq*X. */
  vroom_fp2_wide_set_mul( &w1a[1], &q->x, &p->y ); /* Xq*Y. */
  vroom_fp2_wide_set_mul( &w1a[2], &q->x, &p->z ); /* Xq*Z. */
  vroom_fp2_wide_set_mul( &w1a[3], &q->y, &p->x ); /* Yq*X. */
  vroom_fp2_wide_set_mul( &w1a[4], &q->y, &p->y ); /* Yq*Y. */
  vroom_fp2_wide_set_mul( &w1a[5], &q->y, &p->z ); /* Yq*Z. */
  vroom_fp2_wide_set_mul( &w1b[0], &p->x, &q->z ); /* X*Zq. */
  vroom_fp2_wide_set_mul( &w1b[1], &p->y, &q->z ); /* Y*Zq. */
  vroom_fp2_wide_set_mul( &w1b[2], &p->z, &q->z ); /* Z*Zq. */
  vroom_fp2_t r1[6], r1b[3];
  vroom_fp2_reduce_batch6( r1, w1a );
  vroom_fp2_reduce_batch3( r1b, w1b );
  vroom_fp2_t const * xqx=&r1[0], * xqy=&r1[1], * xqz=&r1[2];
  vroom_fp2_t const * yqx=&r1[3], * yqy=&r1[4], * yqz=&r1[5];
  vroom_fp2_t const * xzq=&r1b[0], * yzq=&r1b[1], * zzq=&r1b[2];

  vroom_fp2_t xysum, ym, yp, xzsum, yzsum, three_xx, b3_zzq, bx;
  vroom_fp2_add( &xysum, xqy, yqx );              /* XqY+YqX.     */
  vroom_fp2_mul_3b( &b3_zzq, zzq );               /* 3b*Z*Zq.     */
  vroom_fp2_sub( &ym, yqy, &b3_zzq );             /* YqY-3bZZq.   */
  vroom_fp2_add( &yp, yqy, &b3_zzq );             /* YqY+3bZZq.   */
  vroom_fp2_add( &xzsum, xqz, xzq );              /* XqZ+XZq.     */
  vroom_fp2_add( &yzsum, yqz, yzq );              /* YqZ+YZq.     */
  vroom_fp2_mul_small( &three_xx, xqx, 3U );      /* 3*Xq*X.      */
  vroom_fp2_mul_3b( &bx, &xzsum );                /* 3b(XqZ+XZq). */

  vroom_fp2_wide_t w2[3];
  vroom_fp2_wide_set_mul( &w2[0], &xysum, &ym );      /* X3 = xysum*ym ...    */
  vroom_fp2_wide_submul( &w2[0], &bx, &yzsum );       /* ... - bx*yzsum.      */
  vroom_fp2_wide_set_mul( &w2[1], &bx, &three_xx );   /* Y3 = bx*threeXX ...  */
  vroom_fp2_wide_addmul( &w2[1], &yp, &ym );          /* ... + yp*ym.         */
  vroom_fp2_wide_set_mul( &w2[2], &yp, &yzsum );      /* Z3 = yp*yzsum ...    */
  vroom_fp2_wide_addmul( &w2[2], &xysum, &three_xx ); /* ... + xysum*threeXX. */
  vroom_fp2_t r2[3];
  vroom_fp2_reduce_batch3( r2, w2 );
  return (vroom_p2_projective_t){ r2[0], r2[1], r2[2] };
}


/* Miller-step variants: same complete formulas plus the evaluated line.
   The line is emitted in curve-neutral order line[0:2]=ell_c (the pure-Q
   coefficient 3bZ^2-Y^2 / xQ*Y-yQ*X), line[2:4]=ell_x (coefficient *xP),
   line[4:6]=ell_y (coefficient *yP); the curve's sparse embedding places
   them in its twist-type slots. */

static vroom_p2_projective_t
vroom_ec_double_step( vroom_p2_projective_t const * p,
             vroom_fp_t                    line[6],
             vroom_fp_t const *            three_e1x,
             vroom_fp_t const *            minus_two_e1y,
             int                            first ) {
  /* Complete homogeneous doubling plus tangent evaluation.  Independent
     products are reduced in two batches; the initial Z=1 skips Z^2 and YZ. */
  vroom_fp2_t round1[5];
  if( FD_UNLIKELY( first ) ) {
    vroom_fp2_wide_t wide1[3];
    vroom_fp2_t reduced[3];
    vroom_fp2_wide_set_mul( &wide1[0], &p->x, &p->x ); /* wide1[0] = X^2. */
    vroom_fp2_wide_set_mul( &wide1[1], &p->y, &p->y ); /* wide1[1] = Y^2. */
    vroom_fp2_wide_set_mul( &wide1[2], &p->x, &p->y ); /* wide1[2] = X*Y. */
    vroom_fp2_reduce_batch3( reduced, wide1 );
    round1[0]=reduced[0]; round1[1]=reduced[1]; round1[2]=p->z; /* xx=X^2, yy=Y^2, zz=Z^2=1. */
    round1[3]=reduced[2]; round1[4]=p->y;                       /* xy=X*Y, yz=Y*Z=Y.          */
  } else {
    vroom_fp2_wide_t wide1[5];
    vroom_fp2_wide_set_mul( &wide1[0], &p->x, &p->x ); /* wide1[0] = X^2. */
    vroom_fp2_wide_set_mul( &wide1[1], &p->y, &p->y ); /* wide1[1] = Y^2. */
    vroom_fp2_wide_set_mul( &wide1[2], &p->z, &p->z ); /* wide1[2] = Z^2. */
    vroom_fp2_wide_set_mul( &wide1[3], &p->x, &p->y ); /* wide1[3] = X*Y. */
    vroom_fp2_wide_set_mul( &wide1[4], &p->y, &p->z ); /* wide1[4] = Y*Z. */
    vroom_fp2_reduce_batch5( round1, wide1 );
  }
  vroom_fp2_t const * xx=&round1[0], * yy=&round1[1], * zz=&round1[2]; /* xx=X^2, yy=Y^2, zz=Z^2. */
  vroom_fp2_t const * xy=&round1[3], * yz=&round1[4];                 /* xy=X*Y, yz=Y*Z.          */

  vroom_fp2_t eight_yy, b3_zz, line_c, yy_plus_b3, b9_zz;
  vroom_fp2_t yy_minus_b9, two_xy;
  vroom_fp2_mul_small( &eight_yy, yy, 8U );                    /* eight_yy  = 8Y^2.                    */
  vroom_fp2_mul_3b( &b3_zz, zz );                              /* b3_zz     = 3bZ^2.                   */
  vroom_fp2_sub( &line_c, &b3_zz, yy );                 /* ell_0    = 3bZ^2-Y^2.               */
  vroom_fp2_add( &yy_plus_b3, yy, &b3_zz );             /* yy_plus_b3 = Y^2+3bZ^2.               */
  vroom_fp2_mul_small( &b9_zz, &b3_zz, 3U );                   /* b9ZZ     = 9bZ^2.                   */
  vroom_fp2_sub( &yy_minus_b9, yy, &b9_zz );            /* yyMinusB9= Y^2-9bZ^2.               */
  vroom_fp2_mul_small( &two_xy, xy, 2U );                      /* twoXY    = 2XY.                      */

  vroom_fp2_wide_t wide2[5];
  vroom_fp2_wide_set_mul_fp( &wide2[0], xx, three_e1x );        /* ell_x(P) = X^2*(3xP).                              */
  vroom_fp2_wide_set_mul_fp( &wide2[1], yz, minus_two_e1y );    /* ell_y(P) = YZ*(-2yP).                              */
  vroom_fp2_wide_set_mul( &wide2[2], &yy_minus_b9, &yy_plus_b3 ); /* Y3      = (Y^2-9bZ^2)(Y^2+3bZ^2) ...             */
  vroom_fp2_wide_addmul( &wide2[2], &eight_yy, &b3_zz );        /* ...       + (8Y^2)(3bZ^2).                         */
  vroom_fp2_wide_set_mul( &wide2[3], &yy_minus_b9, &two_xy );   /* X3        = (Y^2-9bZ^2)(2XY).                      */
  vroom_fp2_wide_set_mul( &wide2[4], &eight_yy, yz );           /* Z3        = (8Y^2)(YZ).                             */
  vroom_fp2_t round2[5];
  vroom_fp2_reduce_batch5( round2, wide2 );
  vroom_fp2_t const * line_x=&round2[0], * line_y=&round2[1];
  vroom_fp2_t const * y3=&round2[2], * x3=&round2[3], * z3=&round2[4];

  line[0]=line_c.c[0];  line[1]=line_c.c[1];  /* line[0:2] = ell_0.    */
  line[2]=line_x->c[0]; line[3]=line_x->c[1]; /* line[2:4] = ell_x(P). */
  line[4]=line_y->c[0]; line[5]=line_y->c[1]; /* line[4:6] = ell_y(P). */
  return (vroom_p2_projective_t){ *x3, *y3, *z3 }; /* (X3:Y3:Z3)=2(X:Y:Z). */
}


static vroom_p2_projective_t
vroom_ec_add_step( vroom_p2_projective_t const * p,
          vroom_fp_t                    line[6],
          vroom_fp_t const *            e1x,
          vroom_fp_t const *            e1y,
          vroom_fp2_t const *           e2x,
          vroom_fp2_t const *           e2y ) {
  /* Complete R+Q addition plus secant evaluation, using Appendix G's pattern:
     reduce each product layer, but reduce sums of products only once. */
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

  vroom_fp2_t line_c, xq_coef, yq_coef, x2y1_plus_y2x1;
  vroom_fp2_t y2z1_plus_y1, x2z1_plus_x1, three_x2x1;
  vroom_fp2_t b3z1, y2y1_plus_b3, y2y1_minus_b3, b3_xsum;
  vroom_fp2_sub( &line_c, x2y1, y2x1 );                   /* ell_0   = xQ*Y-yQ*X.               */
  vroom_fp2_sub( &xq_coef, y2z1, &p->y );                 /* ell_x   = yQ*Z-Y.                  */
  vroom_fp2_sub( &yq_coef, &p->x, x2z1 );                 /* ell_y   = X-xQ*Z.                  */
  vroom_fp2_add( &x2y1_plus_y2x1, x2y1, y2x1 );          /* xysum   = xQ*Y+yQ*X.               */
  vroom_fp2_add( &y2z1_plus_y1, y2z1, &p->y );            /* yzsum   = yQ*Z+Y.                  */
  vroom_fp2_add( &x2z1_plus_x1, x2z1, &p->x );            /* xzsum   = xQ*Z+X.                  */
  vroom_fp2_mul_small( &three_x2x1, x2x1, 3U );                  /* threeXX = 3xQ*X.                   */
  vroom_fp2_mul_3b( &b3z1, &p->z );                              /* b3Z     = 3bZ.                     */
  vroom_fp2_add( &y2y1_plus_b3, y2y1, &b3z1 );           /* yp      = yQ*Y+3bZ.                */
  vroom_fp2_sub( &y2y1_minus_b3, y2y1, &b3z1 );          /* ym      = yQ*Y-3bZ.                */
  vroom_fp2_mul_3b( &b3_xsum, &x2z1_plus_x1 );                  /* bx      = 3b(xQ*Z+X).              */

  vroom_fp2_wide_t wide2[5];
  vroom_fp2_wide_set_mul( &wide2[0], &x2y1_plus_y2x1, &y2y1_minus_b3 ); /* X3 = xysum*ym ...       */
  vroom_fp2_wide_submul( &wide2[0], &b3_xsum, &y2z1_plus_y1 );          /* ... - bx*yzsum.          */
  vroom_fp2_wide_set_mul( &wide2[1], &b3_xsum, &three_x2x1 );           /* Y3 = bx*threeXX ...       */
  vroom_fp2_wide_addmul( &wide2[1], &y2y1_plus_b3, &y2y1_minus_b3 );   /* ... + yp*ym.             */
  vroom_fp2_wide_set_mul( &wide2[2], &y2y1_plus_b3, &y2z1_plus_y1 );   /* Z3 = yp*yzsum ...         */
  vroom_fp2_wide_addmul( &wide2[2], &x2y1_plus_y2x1, &three_x2x1 );    /* ... + xysum*threeXX.      */
  vroom_fp2_wide_set_mul_fp( &wide2[3], &xq_coef, e1x );                /* ell_x(P) = (yQ*Z-Y)*xP.   */
  vroom_fp2_wide_set_mul_fp( &wide2[4], &yq_coef, e1y );                /* ell_y(P) = (X-xQ*Z)*yP.   */
  vroom_fp2_t round2[5];
  vroom_fp2_reduce_batch5( round2, wide2 );
  vroom_fp2_t const * x3=&round2[0], * y3=&round2[1], * z3=&round2[2];
  vroom_fp2_t const * line_x=&round2[3], * line_y=&round2[4];

  line[0]=line_c.c[0];  line[1]=line_c.c[1];  /* line[0:2] = ell_0.    */
  line[2]=line_x->c[0]; line[3]=line_x->c[1]; /* line[2:4] = ell_x(P). */
  line[4]=line_y->c[0]; line[5]=line_y->c[1]; /* line[4:6] = ell_y(P). */
  return (vroom_p2_projective_t){ *x3, *y3, *z3 }; /* (X3:Y3:Z3)=(X:Y:Z)+Q. */
}



/* --- base-curve (G1) complete arithmetic over Fp ------------------------
   Hook: vroom_fp_mul_3b_g1( out, a ) computing out = (3*b)*a for the
   curve y^2 = x^3 + b. */

/* Simplified mixed addition (RCB family, Q affine with Z = RNS one):
   acc <- acc + q.  acc is a valid rep, never (0,0,0). */
static void
vroom_g1_mixed_add( vroom_fp_t *       acc, /* x,y,z */
              vroom_fp_t const * q ) { /* x,y   */
  vroom_fp_wide_t w1[5], w2[6];
  vroom_fp_t t0_1, t1_2, t3_6, t5n, x3n;
  vroom_fp_t t3_4, t4_5, t4_7, y3_18, x3_19, t2_21, t3_8;
  vroom_fp_t y3_24, z3_22, t1_23, t4_13, t0_20;
  vroom_fp_t rx3[3];

  vroom_fp_add( &t3_4, &acc[0], &acc[1] );
  vroom_fp_add( &t4_5, &q[0], &q[1] );

  vroom_fp_wide_mul_raw( &w1[0], &acc[0], &q[0] );
  vroom_fp_wide_mul_raw( &w1[1], &acc[1], &q[1] );
  vroom_fp_wide_mul_raw( &w1[2], &t3_4, &t4_5 );
  vroom_fp_wide_mul_raw( &w1[3], &acc[2], &q[1] );
  vroom_fp_wide_mul_raw( &w1[4], &acc[2], &q[0] );
  vroom_fp_t r1v[5];
  vroom_fp_reduce_wide_batch10( r1v, w1 );
  t0_1=r1v[0]; t1_2=r1v[1]; t3_6=r1v[2]; t5n=r1v[3]; x3n=r1v[4];

  vroom_fp_add( &t4_7, &t0_1, &t1_2 );
  vroom_fp_add( &y3_18, &x3n, &acc[0] );
  vroom_fp_add( &x3_19, &t0_1, &t0_1 );
  vroom_fp_mul_3b_g1( &t2_21, &acc[2] );
  vroom_fp_sub( &t3_8, &t3_6, &t4_7 );
  vroom_fp_mul_3b_g1( &y3_24, &y3_18 );
  vroom_fp_add( &z3_22, &t1_2, &t2_21 );
  vroom_fp_sub( &t1_23, &t1_2, &t2_21 );
  vroom_fp_add( &t4_13, &t5n, &acc[1] );
  vroom_fp_add( &t0_20, &t0_1, &x3_19 );

  vroom_fp_t neg_y3_24;
  vroom_fp_neg( &neg_y3_24, &y3_24 );
  vroom_fp_wide_mul_raw( &w2[0], &t4_13, &neg_y3_24 );
  vroom_fp_wide_mul_raw( &w2[1], &t1_23, &t3_8 );
  vroom_fp_wide_mul_raw( &w2[2], &t0_20, &y3_24 );
  vroom_fp_wide_mul_raw( &w2[3], &t1_23, &z3_22 );
  vroom_fp_wide_mul_raw( &w2[4], &t0_20, &t3_8 );
  vroom_fp_wide_mul_raw( &w2[5], &t4_13, &z3_22 );
  /* three sums of pairs, then one batch6 reduce */
  vroom_fp_wide_t wsum[3];
  for( int i=0; i<3; i++ ) {
    wsum[i] = w2[2*i];
    vroom_fp_wide_add_raw( &wsum[i], &w2[2*i+1] );
  }
  vroom_fp_reduce_wide_batch6( rx3, wsum );

  acc[0]=rx3[0]; acc[1]=rx3[1]; acc[2]=rx3[2];
}


/* Dual-accumulator interleaved mixed addition: both chains' round-1
   products share one batch10 reduction and both chains' round-2
   products share one batch6, hiding IFMA latency.  The batch-N reduce
   has a large fixed pipeline cost, so one 6-slot batch for both chains
   beats two 3-slot batches; each element is reduced independently
   inside the batch so this is value-identical to the two-batch form. */
static void
vroom_g1_mixed_add2( vroom_fp_t *       acc0,
               vroom_fp_t *       acc1,
               vroom_fp_t const * q0,
               vroom_fp_t const * q1 ) {
  vroom_fp_wide_t w1[10], w2[6], wsum[6];
  vroom_fp_t r0[10];
  vroom_fp_t t3_4, t4_5, t4_7, y3_18, x3_19, t2_21, t3_8;
  vroom_fp_t y3_24, z3_22, t1_23, t4_13, t0_20, ny3;

  /* round 1: both chains' products in one batch10 */
  vroom_fp_add( &t3_4, &acc0[0], &acc0[1] ); vroom_fp_add( &t4_5, &q0[0], &q0[1] );
  vroom_fp_wide_mul_raw( &w1[0], &acc0[0], &q0[0] );
  vroom_fp_wide_mul_raw( &w1[1], &acc0[1], &q0[1] );
  vroom_fp_wide_mul_raw( &w1[2], &t3_4, &t4_5 );
  vroom_fp_wide_mul_raw( &w1[3], &acc0[2], &q0[1] );
  vroom_fp_wide_mul_raw( &w1[4], &acc0[2], &q0[0] );
  vroom_fp_add( &t3_4, &acc1[0], &acc1[1] ); vroom_fp_add( &t4_5, &q1[0], &q1[1] );
  vroom_fp_wide_mul_raw( &w1[5], &acc1[0], &q1[0] );
  vroom_fp_wide_mul_raw( &w1[6], &acc1[1], &q1[1] );
  vroom_fp_wide_mul_raw( &w1[7], &t3_4, &t4_5 );
  vroom_fp_wide_mul_raw( &w1[8], &acc1[2], &q1[1] );
  vroom_fp_wide_mul_raw( &w1[9], &acc1[2], &q1[0] );
  vroom_fp_reduce_wide_batch10( r0, w1 );

  /* round 2 for both chains, one shared batch6 at the end */
  #define VROOM_G1_ROUND2(acc, r, wsum, off) do {                 \
    vroom_fp_add( &t4_7, &(r)[0], &(r)[1] );            \
    vroom_fp_add( &y3_18, &(r)[4], &(acc)[0] );         \
    vroom_fp_add( &x3_19, &(r)[0], &(r)[0] );           \
    vroom_fp_mul_3b_g1( &t2_21, &(acc)[2] );                      \
    vroom_fp_sub( &t3_8, &(r)[2], &t4_7 );              \
    vroom_fp_mul_3b_g1( &y3_24, &y3_18 );                         \
    vroom_fp_add( &z3_22, &(r)[1], &t2_21 );            \
    vroom_fp_sub( &t1_23, &(r)[1], &t2_21 );            \
    vroom_fp_add( &t4_13, &(r)[3], &(acc)[1] );         \
    vroom_fp_add( &t0_20, &(r)[0], &x3_19 );            \
    vroom_fp_neg( &ny3, &y3_24 );                       \
    vroom_fp_wide_mul_raw( &w2[0], &t4_13, &ny3 );      \
    vroom_fp_wide_mul_raw( &w2[1], &t1_23, &t3_8 );     \
    vroom_fp_wide_mul_raw( &w2[2], &t0_20, &y3_24 );    \
    vroom_fp_wide_mul_raw( &w2[3], &t1_23, &z3_22 );    \
    vroom_fp_wide_mul_raw( &w2[4], &t0_20, &t3_8 );     \
    vroom_fp_wide_mul_raw( &w2[5], &t4_13, &z3_22 );    \
    for( int i=0; i<3; i++ ) {                           \
      wsum[off+i] = w2[2*i];                             \
      vroom_fp_wide_add_raw( &wsum[off+i], &w2[2*i+1] ); \
    }                                                    \
  } while(0)
  VROOM_G1_ROUND2( acc0, (r0+0), wsum, 0 );
  VROOM_G1_ROUND2( acc1, (r0+5), wsum, 3 );
  #undef VROOM_G1_ROUND2
  vroom_fp_t rx3[6];
  vroom_fp_reduce_wide_batch6( rx3, wsum );
  acc0[0]=rx3[0]; acc0[1]=rx3[1]; acc0[2]=rx3[2];
  acc1[0]=rx3[3]; acc1[1]=rx3[4]; acc1[2]=rx3[5];
}


/* Complete projective addition of the two accumulated chain values (the
   RCB shape of the twist-curve vroom_ec_add_pp in fd_bls_hash.c, specialized
   to Fp with 3b = 12).  Handles every case including doubling and the
   identity. */
static void
vroom_g1_proj_add( vroom_fp_t *       p,   /* (X1:Y1:Z1), updated in place */
             vroom_fp_t const * q ) { /* (X2:Y2:Z2) */
  vroom_fp_t xqx, xqy, xqz, yqx, yqy, yqz, xzq, yzq, zzq;
  vroom_fp_t xysum, ym, yp, xzsum, yzsum, three_xx, b3_zzq, bx;
  vroom_fp_t x3, y3, z3, t;

  vroom_fp_mul( &xqx, &q[0], &p[0] );
  vroom_fp_mul( &xqy, &q[0], &p[1] );
  vroom_fp_mul( &xqz, &q[0], &p[2] );
  vroom_fp_mul( &yqx, &q[1], &p[0] );
  vroom_fp_mul( &yqy, &q[1], &p[1] );
  vroom_fp_mul( &yqz, &q[1], &p[2] );
  vroom_fp_mul( &xzq, &p[0], &q[2] );
  vroom_fp_mul( &yzq, &p[1], &q[2] );
  vroom_fp_mul( &zzq, &p[2], &q[2] );

  vroom_fp_add( &xysum, &xqy, &yqx );
  vroom_fp_mul_3b_g1( &b3_zzq, &zzq );
  vroom_fp_sub( &ym, &yqy, &b3_zzq );
  vroom_fp_add( &yp, &yqy, &b3_zzq );
  vroom_fp_add( &xzsum, &xqz, &xzq );
  vroom_fp_add( &yzsum, &yqz, &yzq );
  vroom_fp_mul_small( &three_xx, &xqx, 3U );
  vroom_fp_mul_3b_g1( &bx, &xzsum );

  /* X3 = xysum*ym - bx*yzsum */
  vroom_fp_mul( &x3, &xysum, &ym );
  vroom_fp_mul( &t,  &bx,    &yzsum );
  vroom_fp_sub( &x3, &x3, &t );
  /* Y3 = bx*three_xx + yp*ym */
  vroom_fp_mul( &y3, &bx, &three_xx );
  vroom_fp_mul( &t,  &yp, &ym );
  vroom_fp_add( &y3, &y3, &t );
  /* Z3 = yp*yzsum + xysum*three_xx */
  vroom_fp_mul( &z3, &yp,    &yzsum );
  vroom_fp_mul( &t,  &xysum, &three_xx );
  vroom_fp_add( &z3, &z3, &t );

  p[0]=x3; p[1]=y3; p[2]=z3;
}


#endif /* FD_HAS_AVX512 */
