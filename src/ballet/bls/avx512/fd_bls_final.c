/* BLS12-381 final exponentiation, Fp12 Frobenius, and GT identity
   check.  Part of the BLS unity TU (fd_bls_backend.c). */

#if FD_HAS_AVX512

static void
fp12_conjugate_final( vroom_fp12_t *       out,
                      vroom_fp12_t const * in ) {
  /* Quadratic conjugation a+b*w -> a-b*w, equal to the p^6-Frobenius. */
  *out = *in;
  for( int i=6; i<12; i++ ) vroom_fp_neg( &out->c[i], &out->c[i] ); /* out=a-b*w=in^(p^6). */
}


static inline void
fp_mul2_final( vroom_fp_t *       out,
               vroom_fp_t const * a,
               vroom_fp_t const * ac,
               vroom_fp_t const * b,
               vroom_fp_t const * bc ) {
  vroom_fp_wide_t w;
  vroom_fp_wide_offset( &w );          /* w   = 0 mod p, represented by a positive lazy offset. */
  vroom_fp_wide_addmul( &w, a, ac );   /* w  += a*ac.                                            */
  vroom_fp_wide_addmul( &w, b, bc );   /* w  += b*bc.                                            */
  vroom_fp_reduce_wide( out, &w );     /* out = a*ac+b*bc mod p.                                 */
}

void
fd_bls_fp12_frobenius( vroom_fp12_t *       out,
                       vroom_fp12_t const * in,
                       ulong                 n ) {
  /* Apply x -> x^(p^n); conjugations and the fixed tower coefficients make
     this linear over Fp. */
  vroom_fp12_t r;
  if( n==1UL ) {
    vroom_fp_t f12=VROOM_FP_CONST(frob1_2), f13=VROOM_FP_CONST(frob1_3);
    vroom_fp_t f14=VROOM_FP_CONST(frob1_4), f15=VROOM_FP_CONST(frob1_5);
    vroom_fp_t f16=VROOM_FP_CONST(frob1_6), f17=VROOM_FP_CONST(frob1_7);
    vroom_fp_t f18=VROOM_FP_CONST(frob1_8), f19=VROOM_FP_CONST(frob1_9);
    vroom_fp_t f110=VROOM_FP_CONST(frob1_10);
    r.c[0] = in->c[0];                                                   /* c'_0  = c0.                 */
    vroom_fp_neg( &r.c[1], &in->c[1] );                                /* c'_1  = -c1.                */
    vroom_fp_mul( &r.c[2], &in->c[3], &f12 );                          /* c'_2  = f12*c3.             */
    vroom_fp_mul( &r.c[3], &in->c[2], &f12 );                          /* c'_3  = f12*c2.             */
    vroom_fp_mul( &r.c[4], &in->c[4], &f13 );                          /* c'_4  = f13*c4.             */
    vroom_fp_mul( &r.c[5], &in->c[5], &f14 );                          /* c'_5  = f14*c5.             */
    fp_mul2_final( &r.c[6],  &in->c[7],  &f16,  &in->c[6],  &f15  );   /* c'_6  = f16*c7+f15*c6.     */
    fp_mul2_final( &r.c[7],  &in->c[7],  &f16,  &in->c[6],  &f16  );   /* c'_7  = f16*c7+f16*c6.     */
    fp_mul2_final( &r.c[8],  &in->c[8],  &f17,  &in->c[9],  &f17  );   /* c'_8  = f17*c8+f17*c9.     */
    fp_mul2_final( &r.c[9],  &in->c[8],  &f17,  &in->c[9],  &f18  );   /* c'_9  = f17*c8+f18*c9.     */
    fp_mul2_final( &r.c[10], &in->c[11], &f110, &in->c[10], &f19  );   /* c'_10 = f110*c11+f19*c10.  */
    fp_mul2_final( &r.c[11], &in->c[11], &f110, &in->c[10], &f110 );   /* c'_11 = f110*c11+f110*c10. */
  } else if( n==2UL ) {
    vroom_fp_t f21=VROOM_FP_CONST(frob2_1), f22=VROOM_FP_CONST(frob2_2);
    vroom_fp_t f23=VROOM_FP_CONST(frob2_3), f25=VROOM_FP_CONST(frob2_5);
    r.c[0] = in->c[0]; r.c[1] = in->c[1];                    /* c'_{0,1}   = c_{0,1}.     */
    vroom_fp_mul( &r.c[2],  &in->c[2],  &f21 );             /* c'_2       = f21*c2.      */
    vroom_fp_mul( &r.c[3],  &in->c[3],  &f21 );             /* c'_3       = f21*c3.      */
    vroom_fp_mul( &r.c[4],  &in->c[4],  &f22 );             /* c'_4       = f22*c4.      */
    vroom_fp_mul( &r.c[5],  &in->c[5],  &f22 );             /* c'_5       = f22*c5.      */
    vroom_fp_mul( &r.c[6],  &in->c[6],  &f23 );             /* c'_6       = f23*c6.      */
    vroom_fp_mul( &r.c[7],  &in->c[7],  &f23 );             /* c'_7       = f23*c7.      */
    vroom_fp_neg( &r.c[8],  &in->c[8] );                   /* c'_8       = -c8.         */
    vroom_fp_neg( &r.c[9],  &in->c[9] );                   /* c'_9       = -c9.         */
    vroom_fp_mul( &r.c[10], &in->c[10], &f25 );            /* c'_10      = f25*c10.       */
    vroom_fp_mul( &r.c[11], &in->c[11], &f25 );            /* c'_11      = f25*c11.       */
  } else if( n==3UL ) {
    vroom_fp_t f32=VROOM_FP_CONST(frob3_2), f33=VROOM_FP_CONST(frob3_3);
    r.c[0] = in->c[0];                                                /* c'_0  = c0.               */
    vroom_fp_neg( &r.c[1], &in->c[1] );                             /* c'_1  = -c1.              */
    r.c[2] = in->c[3]; r.c[3] = in->c[2];                            /* c'_2  = c3; c'_3=c2.      */
    vroom_fp_neg( &r.c[4], &in->c[4] );                             /* c'_4  = -c4.              */
    r.c[5] = in->c[5];                                               /* c'_5  = c5.               */
    fp_mul2_final( &r.c[6],  &in->c[7],  &f33, &in->c[6],  &f32 );  /* c'_6  = f33*c7+f32*c6.   */
    fp_mul2_final( &r.c[7],  &in->c[7],  &f33, &in->c[6],  &f33 );  /* c'_7  = f33*c7+f33*c6.   */
    fp_mul2_final( &r.c[8],  &in->c[8],  &f32, &in->c[9],  &f32 );  /* c'_8  = f32*c8+f32*c9.   */
    fp_mul2_final( &r.c[9],  &in->c[8],  &f32, &in->c[9],  &f33 );  /* c'_9  = f32*c8+f33*c9.   */
    fp_mul2_final( &r.c[10], &in->c[11], &f32, &in->c[10], &f33 );  /* c'_10 = f32*c11+f33*c10. */
    fp_mul2_final( &r.c[11], &in->c[11], &f32, &in->c[10], &f32 );  /* c'_11 = f32*c11+f32*c10. */
  } else {
    r = *in;
  }
  *out = r;
}

static void
mul_n_sqr( vroom_fp12_t *       out,
           vroom_fp12_t const * a,
           vroom_fp12_t const * b,
           uint                    n ) {
  vroom_fp12_mul( out, a, b );                                      /* out = a*b.         */
  for( uint i=0U; i<n; i++ ) vroom_fp12_cyclotomic_sqr( out, out ); /* out = (a*b)^(2^n). */
}

static void
raise_to_z_div_by_2( vroom_fp12_t *       out,
                     vroom_fp12_t const * in ) {
  /* The square/add chain reaches (-z)/2; conjugation is inversion in the
     cyclotomic subgroup, so the result is in^(z/2) for negative z. */
  vroom_fp12_t r;
  vroom_fp12_cyclotomic_sqr( &r, in ); /* r   = in^2.                                             */
  mul_n_sqr( &r, &r, in, 2U );         /* r   = (in^2*in)^4       = in^12.                         */
  mul_n_sqr( &r, &r, in, 3U );         /* r   = (in^12*in)^8      = in^104.                        */
  mul_n_sqr( &r, &r, in, 9U );         /* r   = (in^104*in)^512   = in^53760.                      */
  mul_n_sqr( &r, &r, in, 32U );        /* r   = in^(53761*2^32).                                  */
  mul_n_sqr( &r, &r, in, 15U );        /* r   = in^((53761*2^32+1)*2^15) = in^((-z)/2).            */
  fp12_conjugate_final( out, &r );      /* out = r^-1 in the cyclotomic group       = in^(z/2).     */
}

static void
raise_to_z( vroom_fp12_t *       out,
            vroom_fp12_t const * in ) {
  vroom_fp12_t half;
  raise_to_z_div_by_2( &half, in );               /* half = in^(z/2). */
  vroom_fp12_cyclotomic_sqr( out, &half );       /* out  = in^z.     */
}

void
fd_bls_final_exp( vroom_fp12_t *       out,
                  vroom_fp12_t const * f ) {
  vroom_fp12_t inverse, conj, ret1, frob2_ret1, ret2, ret2_sqr;
  vroom_fp12_t y0_to_z, y0_to_z_div2, ret2_conj, y1_mul_y3;
  vroom_fp12_t y1_mul_y3_conj, y1_final, y1_to_z, y2_to_z;
  vroom_fp12_t y1_final_conj, y3_mul_y1, y1_frob3, y1_to_z_frob2;
  vroom_fp12_t y1_mul_y2, y3_to_z, y2_mul_y0, y2_mul_ret;
  vroom_fp12_t y1_mul_y2_final, y3_frob1;

  /* Easy part.  Write g=f^((p^6-1)(p^2+1)); g is cyclotomic, so conjugation
     below is inversion and Frobenius calls are cheap exponentiations by p. */
  vroom_fp12_inverse( &inverse, f );                         /* inverse   = f^-1.                              */
  fp12_conjugate_final( &conj, f );                           /* conj      = f^(p^6).                           */
  vroom_fp12_mul( &ret1, &conj, &inverse );                  /* ret1      = f^(p^6-1).                         */
  fd_bls_fp12_frobenius( &frob2_ret1, &ret1, 2UL );           /* frob2_ret1 = ret1^(p^2).                        */
  vroom_fp12_mul( &ret2, &frob2_ret1, &ret1 );               /* ret2      = f^((p^6-1)(p^2+1)) = g.           */

  /* Hard part.  The aligned exponents show the BLS12 addition chain for
     h=(p^4-p^2+1)/r.  The final product is g^h. */
  vroom_fp12_cyclotomic_sqr( &ret2_sqr, &ret2 );               /* ret2_sqr        = g^2.                      */
  raise_to_z( &y0_to_z, &ret2_sqr );                            /* y0_to_z         = g^(2z).                   */
  raise_to_z_div_by_2( &y0_to_z_div2, &y0_to_z );               /* y0_to_z_div2    = g^(z^2).                  */
  fp12_conjugate_final( &ret2_conj, &ret2 );                    /* ret2_conj       = g^-1.                     */
  vroom_fp12_mul( &y1_mul_y3, &ret2_conj, &y0_to_z );          /* y1_mul_y3       = g^(2z-1).                 */
  fp12_conjugate_final( &y1_mul_y3_conj, &y1_mul_y3 );          /* y1_mul_y3_conj  = g^(1-2z).                 */
  vroom_fp12_mul( &y1_final, &y1_mul_y3_conj, &y0_to_z_div2 ); /* y1_final        = g^(z^2-2z+1).             */
  raise_to_z( &y1_to_z, &y1_final );                            /* y1_to_z         = g^(z^3-2z^2+z).           */
  raise_to_z( &y2_to_z, &y1_to_z );                             /* y2_to_z         = g^(z^4-2z^3+z^2).         */
  fp12_conjugate_final( &y1_final_conj, &y1_final );            /* y1_final_conj   = g^(-z^2+2z-1).            */
  vroom_fp12_mul( &y3_mul_y1, &y2_to_z, &y1_final_conj );      /* y3_mul_y1       = g^(z^4-2z^3+2z-1).        */
  fd_bls_fp12_frobenius( &y1_frob3, &y1_final, 3UL );           /* y1_frob3        = g^(p^3*(z^2-2z+1)).       */
  fd_bls_fp12_frobenius( &y1_to_z_frob2, &y1_to_z, 2UL );       /* y1_to_z_frob2   = g^(p^2*(z^3-2z^2+z)).     */
  vroom_fp12_mul( &y1_mul_y2, &y1_frob3, &y1_to_z_frob2 );     /* y1_mul_y2       = y1_frob3*y1_to_z_frob2.   */
  raise_to_z( &y3_to_z, &y3_mul_y1 );                           /* y3_to_z         = y3_mul_y1^z.              */
  vroom_fp12_mul( &y2_mul_y0, &y3_to_z, &ret2_sqr );           /* y2_mul_y0       = y3_to_z*g^2.              */
  vroom_fp12_mul( &y2_mul_ret, &y2_mul_y0, &ret2 );            /* y2_mul_ret      = y3_to_z*g^3.              */
  vroom_fp12_mul( &y1_mul_y2_final, &y1_mul_y2, &y2_mul_ret ); /* y1_mul_y2_final = y1_mul_y2*y3_to_z*g^3.    */
  fd_bls_fp12_frobenius( &y3_frob1, &y3_mul_y1, 1UL );          /* y3_frob1        = y3_mul_y1^p.              */
  vroom_fp12_mul( out, &y1_mul_y2_final, &y3_frob1 );          /* out             = g^h = f^((p^12-1)/r).     */
}


#endif
