/* Final exponentiation for the AVX-512 pairing. */

#include "fd_bls_final.h"

#include "fd_bls_constants.h"

static void
fp12_conjugate_final( fd_bls_fp12_t *       out,
                      fd_bls_fp12_t const * in ) {
  /* Quadratic conjugation a+b*w -> a-b*w, equal to the p^6-Frobenius. */
  *out = *in;
  for( int i=6; i<12; i++ ) fd_bls_fp_neg( &out->c[i], &out->c[i] ); /* out=a-b*w=in^(p^6). */
}

static void
mul_n_sqr( fd_bls_fp12_t *       out,
           fd_bls_fp12_t const * a,
           fd_bls_fp12_t const * b,
           uint                    n ) {
  fd_bls_fp12_mul( out, a, b );                                      /* out = a*b.         */
  for( uint i=0U; i<n; i++ ) fd_bls_fp12_cyclotomic_sqr( out, out ); /* out = (a*b)^(2^n). */
}

static void
raise_to_z_div_by_2( fd_bls_fp12_t *       out,
                     fd_bls_fp12_t const * in ) {
  /* The square/add chain reaches (-z)/2; conjugation is inversion in the
     cyclotomic subgroup, so the result is in^(z/2) for negative z. */
  fd_bls_fp12_t r;
  fd_bls_fp12_cyclotomic_sqr( &r, in ); /* r   = in^2.                                             */
  mul_n_sqr( &r, &r, in, 2U );         /* r   = (in^2*in)^4       = in^12.                         */
  mul_n_sqr( &r, &r, in, 3U );         /* r   = (in^12*in)^8      = in^104.                        */
  mul_n_sqr( &r, &r, in, 9U );         /* r   = (in^104*in)^512   = in^53760.                      */
  mul_n_sqr( &r, &r, in, 32U );        /* r   = in^(53761*2^32).                                  */
  mul_n_sqr( &r, &r, in, 15U );        /* r   = in^((53761*2^32+1)*2^15) = in^((-z)/2).            */
  fp12_conjugate_final( out, &r );      /* out = r^-1 in the cyclotomic group       = in^(z/2).     */
}

static void
raise_to_z( fd_bls_fp12_t *       out,
            fd_bls_fp12_t const * in ) {
  fd_bls_fp12_t half;
  raise_to_z_div_by_2( &half, in );               /* half = in^(z/2). */
  fd_bls_fp12_cyclotomic_sqr( out, &half );       /* out  = in^z.     */
}

void
fd_bls_final_exp( fd_bls_fp12_t *       out,
                  fd_bls_fp12_t const * f ) {
  fd_bls_fp12_t inverse, conj, ret1, frob2_ret1, ret2, ret2_sqr;
  fd_bls_fp12_t y0_to_z, y0_to_z_div2, ret2_conj, y1_mul_y3;
  fd_bls_fp12_t y1_mul_y3_conj, y1_final, y1_to_z, y2_to_z;
  fd_bls_fp12_t y1_final_conj, y3_mul_y1, y1_frob3, y1_to_z_frob2;
  fd_bls_fp12_t y1_mul_y2, y3_to_z, y2_mul_y0, y2_mul_ret;
  fd_bls_fp12_t y1_mul_y2_final, y3_frob1;

  /* Easy part.  Write g=f^((p^6-1)(p^2+1)); g is cyclotomic, so conjugation
     below is inversion and Frobenius calls are cheap exponentiations by p. */
  fd_bls_fp12_inverse( &inverse, f );                         /* inverse   = f^-1.                              */
  fp12_conjugate_final( &conj, f );                           /* conj      = f^(p^6).                           */
  fd_bls_fp12_mul( &ret1, &conj, &inverse );                  /* ret1      = f^(p^6-1).                         */
  fd_bls_fp12_frobenius( &frob2_ret1, &ret1, 2UL );           /* frob2_ret1 = ret1^(p^2).                        */
  fd_bls_fp12_mul( &ret2, &frob2_ret1, &ret1 );               /* ret2      = f^((p^6-1)(p^2+1)) = g.           */

  /* Hard part: the blst addition chain for h=(p^4-p^2+1)/r.  It evaluates (z-1)^2(z+p)(z^2+p^2-1)+3 = 3h, so the final
     product is g^(3h) = f^(3(p^12-1)/r), the blst_final_exp (and Agave) convention; gcd(3,r)=1 keeps ==1 tests exact. */
  fd_bls_fp12_cyclotomic_sqr( &ret2_sqr, &ret2 );               /* ret2_sqr        = g^2.                      */
  raise_to_z( &y0_to_z, &ret2_sqr );                            /* y0_to_z         = g^(2z).                   */
  raise_to_z_div_by_2( &y0_to_z_div2, &y0_to_z );               /* y0_to_z_div2    = g^(z^2).                  */
  fp12_conjugate_final( &ret2_conj, &ret2 );                    /* ret2_conj       = g^-1.                     */
  fd_bls_fp12_mul( &y1_mul_y3, &ret2_conj, &y0_to_z );          /* y1_mul_y3       = g^(2z-1).                 */
  fp12_conjugate_final( &y1_mul_y3_conj, &y1_mul_y3 );          /* y1_mul_y3_conj  = g^(1-2z).                 */
  fd_bls_fp12_mul( &y1_final, &y1_mul_y3_conj, &y0_to_z_div2 ); /* y1_final        = g^(z^2-2z+1).             */
  raise_to_z( &y1_to_z, &y1_final );                            /* y1_to_z         = g^(z^3-2z^2+z).           */
  raise_to_z( &y2_to_z, &y1_to_z );                             /* y2_to_z         = g^(z^4-2z^3+z^2).         */
  fp12_conjugate_final( &y1_final_conj, &y1_final );            /* y1_final_conj   = g^(-z^2+2z-1).            */
  fd_bls_fp12_mul( &y3_mul_y1, &y2_to_z, &y1_final_conj );      /* y3_mul_y1       = g^(z^4-2z^3+2z-1).        */
  fd_bls_fp12_frobenius( &y1_frob3, &y1_final, 3UL );           /* y1_frob3        = g^(p^3*(z^2-2z+1)).       */
  fd_bls_fp12_frobenius( &y1_to_z_frob2, &y1_to_z, 2UL );       /* y1_to_z_frob2   = g^(p^2*(z^3-2z^2+z)).     */
  fd_bls_fp12_mul( &y1_mul_y2, &y1_frob3, &y1_to_z_frob2 );     /* y1_mul_y2       = y1_frob3*y1_to_z_frob2.   */
  raise_to_z( &y3_to_z, &y3_mul_y1 );                           /* y3_to_z         = y3_mul_y1^z.              */
  fd_bls_fp12_mul( &y2_mul_y0, &y3_to_z, &ret2_sqr );           /* y2_mul_y0       = y3_to_z*g^2.              */
  fd_bls_fp12_mul( &y2_mul_ret, &y2_mul_y0, &ret2 );            /* y2_mul_ret      = y3_to_z*g^3.              */
  fd_bls_fp12_mul( &y1_mul_y2_final, &y1_mul_y2, &y2_mul_ret ); /* y1_mul_y2_final = y1_mul_y2*y3_to_z*g^3.    */
  fd_bls_fp12_frobenius( &y3_frob1, &y3_mul_y1, 1UL );          /* y3_frob1        = y3_mul_y1^p.              */
  fd_bls_fp12_mul( out, &y1_mul_y2_final, &y3_frob1 );          /* out             = g^(3h) = f^(3(p^12-1)/r). */
}

int
fd_bls_fp12_is_one( fd_bls_fp12_t const * in ) {
  wwv_t mod1 = wwv_ld( fd_bls_m1 );
  wwv_t mod2 = wwv_ld( fd_bls_m2 );
  wwv_t p1   = fd_bls_field_modulus.m1;
  wwv_t p2   = fd_bls_field_modulus.m2;
  wwv_t one1 = fd_bls_one.m1;
  wwv_t one2 = fd_bls_one.m2;
  wwv_t zero = wwv_zero();

#define CANONICAL(x,m) wwv_min( (x), wwv_sub( (x), (m) ) )
  p1   = CANONICAL( p1,   mod1 );
  p2   = CANONICAL( p2,   mod2 );
  one1 = CANONICAL( one1, mod1 );
  one2 = CANONICAL( one2, mod2 );
  for( int i=0; i<12; i++ ) {
    wwv_t x1 = CANONICAL( in->c[i].m1, mod1 );
    wwv_t x2 = CANONICAL( in->c[i].m2, mod2 );
    wwv_t candidate1 = i ? zero : one1;
    wwv_t candidate2 = i ? zero : one2;
    int matched = 0;
    /* A reduced RNS element has bound one.  One unit of that bound is
       40*p, so the exact representative is value+k*p for 0<=k<=40. */
    for( int k=0; k<=40; k++ ) {
      if( wwv_eq( x1, candidate1 )==0xff &&
          wwv_eq( x2, candidate2 )==0xff ) {
        matched = 1;
        break;
      }
      candidate1 = CANONICAL( wwv_add( candidate1, p1 ), mod1 );
      candidate2 = CANONICAL( wwv_add( candidate2, p2 ), mod2 );
    }
    if( FD_UNLIKELY( !matched ) ) return 0;
  }
#undef CANONICAL
  return 1;
}
