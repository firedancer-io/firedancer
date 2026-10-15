/* VROOM engine: tower inversion (Fp2/Fp6/Fp12) by adjugate formulas
   over one base-field inversion.  Unity-TU fragment: the curve TU must
   define, before including this file,

     static inline void vroom_fp2_mul_nonres( vroom_fp2_t * out,
                                              vroom_fp2_t const * in );
       out = xi*in for the curve's sextic nonresidue xi, and

     static void vroom_fp_inverse( vroom_fp_t * out,
                                   vroom_fp_t const * in );
       the single variable-time base-field inversion (0 -> 0). */

#if FD_HAS_AVX512

typedef struct { vroom_fp2_t c[3]; } vroom_fp6_t;

static void
vroom_fp2_inverse( vroom_fp2_t *       out,
                   vroom_fp2_t const * in ) {
  /* (a+b*u)^-1=(a-b*u)/(a^2+b^2), since u^2=-1. */
  vroom_fp_t aa, bb, norm, norm_inv;
  vroom_fp_sqr( &aa, &in->c[0] );                       /* aa      = a^2.                 */
  vroom_fp_sqr( &bb, &in->c[1] );                       /* bb      = b^2.                 */
  vroom_fp_add( &norm, &aa, &bb );                      /* norm    = a^2+b^2.             */
  vroom_fp_inverse( &norm_inv, &norm );                   /* norm_inv = 1/(a^2+b^2).         */
  vroom_fp_mul( &out->c[0], &in->c[0], &norm_inv );     /* out.re  = a/(a^2+b^2).         */
  vroom_fp_mul( &out->c[1], &in->c[1], &norm_inv );     /* out.im  = b/(a^2+b^2).         */
  vroom_fp_neg( &out->c[1], &out->c[1] );               /* out     = (a-bu)/(a^2+b^2).    */
}

static void
vroom_fp6_mul( vroom_fp6_t *       out,
               vroom_fp6_t const * a,
               vroom_fp6_t const * b ) {
  /* In Fp2[v]/(v^3-xi), xi=1+u.  First form every a_i*b_j, then fold
     v^3=xi and v^4=xi*v into the three output coefficients. */
  vroom_fp2_t a0b0, a0b1, a0b2, a1b0, a1b1, a1b2;
  vroom_fp2_t a2b0, a2b1, a2b2, t0, t1;
  vroom_fp2_mul( &a0b0, &a->c[0], &b->c[0] );       /* a0b0 = a0*b0.                                  */
  vroom_fp2_mul( &a0b1, &a->c[0], &b->c[1] );       /* a0b1 = a0*b1.                                  */
  vroom_fp2_mul( &a0b2, &a->c[0], &b->c[2] );       /* a0b2 = a0*b2.                                  */
  vroom_fp2_mul( &a1b0, &a->c[1], &b->c[0] );       /* a1b0 = a1*b0.                                  */
  vroom_fp2_mul( &a1b1, &a->c[1], &b->c[1] );       /* a1b1 = a1*b1.                                  */
  vroom_fp2_mul( &a1b2, &a->c[1], &b->c[2] );       /* a1b2 = a1*b2.                                  */
  vroom_fp2_mul( &a2b0, &a->c[2], &b->c[0] );       /* a2b0 = a2*b0.                                  */
  vroom_fp2_mul( &a2b1, &a->c[2], &b->c[1] );       /* a2b1 = a2*b1.                                  */
  vroom_fp2_mul( &a2b2, &a->c[2], &b->c[2] );       /* a2b2 = a2*b2.                                  */
  vroom_fp2_add( &t0, &a1b2, &a2b1 );              /* t0   = a1*b2+a2*b1, coefficient of v^3.        */
  vroom_fp2_mul_nonres( &t1, &t0 );                  /* t1   = xi*(a1*b2+a2*b1), because v^3=xi.       */
  vroom_fp2_add( &out->c[0], &a0b0, &t1 );         /* c0   = a0*b0+xi*(a1*b2+a2*b1).                 */
  vroom_fp2_add( &t0, &a0b1, &a1b0 );              /* t0   = a0*b1+a1*b0, coefficient of v.          */
  vroom_fp2_mul_nonres( &t1, &a2b2 );                /* t1   = xi*a2*b2, from a2*b2*v^4=xi*a2*b2*v.    */
  vroom_fp2_add( &out->c[1], &t0, &t1 );           /* c1   = a0*b1+a1*b0+xi*a2*b2.                   */
  vroom_fp2_add( &t0, &a0b2, &a1b1 );              /* t0   = a0*b2+a1*b1, coefficient of v^2.        */
  vroom_fp2_add( &out->c[2], &t0, &a2b0 );         /* c2   = a0*b2+a1*b1+a2*b0.                      */
}

static inline void
vroom_fp6_mul_v( vroom_fp6_t *       out,
                 vroom_fp6_t const * in ) {
  vroom_fp6_t r;
  vroom_fp2_mul_nonres( &r.c[0], &in->c[2] ); /* v*(c0+c1*v+c2*v^2) has c0'=xi*c2. */
  r.c[1] = in->c[0];                         /* c1'=c0.                              */
  r.c[2] = in->c[1];                         /* c2'=c1.                              */
  *out = r;                                  /* out=v*in modulo v^3-xi.              */
}

static void
vroom_fp6_inverse( vroom_fp6_t *       out,
                   vroom_fp6_t const * in ) {
  /* Adjugate inversion in Fp2[v]/(v^3-(1+u)); only its Fp2 norm is inverted. */
  vroom_fp2_t c0, c1, c2, t0, t1, tmp, tmp_inv;
  vroom_fp2_sqr( &c0, &in->c[0] );                   /* c0  = a0^2.                         */
  vroom_fp2_mul( &t0, &in->c[1], &in->c[2] );       /* t0  = a1*a2.                        */
  vroom_fp2_mul_nonres( &t1, &t0 );                   /* t1  = xi*a1*a2.                     */
  vroom_fp2_sub( &c0, &c0, &t1 );                   /* c0  = a0^2-xi*a1*a2.                */

  vroom_fp2_sqr( &t0, &in->c[2] );                  /* t0  = a2^2.                          */
  vroom_fp2_mul_nonres( &c1, &t0 );                  /* c1  = xi*a2^2.                       */
  vroom_fp2_mul( &t0, &in->c[0], &in->c[1] );       /* t0  = a0*a1.                         */
  vroom_fp2_sub( &c1, &c1, &t0 );                   /* c1  = xi*a2^2-a0*a1.                 */

  vroom_fp2_sqr( &c2, &in->c[1] );                  /* c2  = a1^2.                          */
  vroom_fp2_mul( &t0, &in->c[0], &in->c[2] );       /* t0  = a0*a2.                         */
  vroom_fp2_sub( &c2, &c2, &t0 );                   /* c2  = a1^2-a0*a2.                    */

  vroom_fp2_mul( &t0, &in->c[2], &c1 );             /* t0  = a2*c1.                         */
  vroom_fp2_mul( &t1, &in->c[1], &c2 );             /* t1  = a1*c2.                         */
  vroom_fp2_add( &tmp, &t0, &t1 );                  /* tmp = a2*c1+a1*c2.                   */
  vroom_fp2_mul_nonres( &tmp, &tmp );                 /* tmp = xi*(a2*c1+a1*c2).              */
  vroom_fp2_mul( &t0, &in->c[0], &c0 );             /* t0  = a0*c0.                         */
  vroom_fp2_add( &tmp, &tmp, &t0 );                 /* tmp = a0*c0+xi*(a2*c1+a1*c2)=Norm(a). */
  vroom_fp2_inverse( &tmp_inv, &tmp );                /* tmp_inv = 1/Norm(a).                  */
  vroom_fp2_mul( &out->c[0], &c0, &tmp_inv );       /* out0 = c0/Norm(a).                   */
  vroom_fp2_mul( &out->c[1], &c1, &tmp_inv );       /* out1 = c1/Norm(a).                   */
  vroom_fp2_mul( &out->c[2], &c2, &tmp_inv );       /* out2 = c2/Norm(a), hence out=a^-1.   */
}

VROOM_FN void
vroom_fp12_inverse( vroom_fp12_t *       out,
                     vroom_fp12_t const * in ) {
  /* (a+b*w)^-1=(a-b*w)/(a^2-v*b^2) over Fp6. */
  vroom_fp6_t a, b, aa, bb, vb, denominator, denominator_inv, r0, r1;
  for( int i=0; i<3; i++ ) {
    a.c[i].c[0] = in->c[2*i];
    a.c[i].c[1] = in->c[2*i+1];
    b.c[i].c[0] = in->c[6+2*i];
    b.c[i].c[1] = in->c[7+2*i];
  }
  vroom_fp6_mul( &aa, &a, &a );                    /* aa          = a^2.              */
  vroom_fp6_mul( &bb, &b, &b );                    /* bb          = b^2.              */
  vroom_fp6_mul_v( &vb, &bb );                     /* vb          = v*b^2.            */
  for( int i=0; i<3; i++ )
    vroom_fp2_sub( &denominator.c[i], &aa.c[i], &vb.c[i] ); /* denominator = a^2-v*b^2. */
  vroom_fp6_inverse( &denominator_inv, &denominator ); /* denominator_inv = 1/(a^2-v*b^2). */
  vroom_fp6_mul( &r0, &a, &denominator_inv );      /* r0          = a/(a^2-v*b^2).   */
  vroom_fp6_mul( &r1, &b, &denominator_inv );      /* r1          = b/(a^2-v*b^2).   */
  for( int i=0; i<3; i++ )
    vroom_fp2_neg( &r1.c[i], &r1.c[i] );          /* r1          = -b/(a^2-v*b^2).  */
  for( int i=0; i<3; i++ ) {
    out->c[2*i]   = r0.c[i].c[0];
    out->c[2*i+1] = r0.c[i].c[1];
    out->c[6+2*i] = r1.c[i].c[0];
    out->c[7+2*i] = r1.c[i].c[1];
  }
}

#endif /* FD_HAS_AVX512 */
