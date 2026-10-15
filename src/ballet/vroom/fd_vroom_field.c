/* VROOM engine: tower field (Fp2/Fp12) arithmetic over the RNS base
   field.  Unity-TU fragment: the curve TU must define VROOM_FP12_KERNELS
   to its generated kernels file (gen_vroom_fp12.py) before this file. */

#include "fd_vroom_field.h"

#if FD_HAS_AVX512

#ifndef VROOM_FP12_KERNELS
#error "curve TU must define VROOM_FP12_KERNELS before fd_vroom_field.c"
#endif
#include VROOM_FP12_KERNELS

VROOM_FN void
vroom_fp2_add( vroom_fp2_t *       out,
                vroom_fp2_t const * a,
                vroom_fp2_t const * b ) {
  vroom_fp_add( &out->c[0], &a->c[0], &b->c[0] );
  vroom_fp_add( &out->c[1], &a->c[1], &b->c[1] );
}

VROOM_FN void
vroom_fp2_sub( vroom_fp2_t *       out,
                vroom_fp2_t const * a,
                vroom_fp2_t const * b ) {
  vroom_fp_sub( &out->c[0], &a->c[0], &b->c[0] );
  vroom_fp_sub( &out->c[1], &a->c[1], &b->c[1] );
}

VROOM_FN void
vroom_fp2_neg( vroom_fp2_t *       out,
                vroom_fp2_t const * a ) {
  vroom_fp_neg( &out->c[0], &a->c[0] );
  vroom_fp_neg( &out->c[1], &a->c[1] );
}

VROOM_FN void
vroom_fp2_mul( vroom_fp2_t *       out,
                vroom_fp2_t const * a,
                vroom_fp2_t const * b ) {
  /* (a0+a1*u)(b0+b1*u)=(a0b0-a1b1)+(a0b1+a1b0)u.  Each
     sum of products crosses one shared RNS reduction boundary. */
  vroom_fp_wide_t x, y;
  vroom_fp_wide_offset( &x );                         /* x      = 0 mod p.        */
  vroom_fp_wide_addmul( &x, &a->c[0], &b->c[0] );    /* x     += a0*b0.          */
  vroom_fp_wide_submul( &x, &a->c[1], &b->c[1] );    /* x     -= a1*b1.          */
  vroom_fp_wide_offset( &y );                         /* y      = 0 mod p.        */
  vroom_fp_wide_addmul( &y, &a->c[0], &b->c[1] );    /* y     += a0*b1.          */
  vroom_fp_wide_addmul( &y, &a->c[1], &b->c[0] );    /* y     += a1*b0.          */
  vroom_fp_reduce_wide( &out->c[0], &x );            /* out.re = a0b0-a1b1.      */
  vroom_fp_reduce_wide( &out->c[1], &y );            /* out.im = a0b1+a1b0.      */
}

VROOM_FN void
vroom_fp2_sqr( vroom_fp2_t *       out,
                vroom_fp2_t const * a ) {
  /* (a0+a1*u)^2=(a0^2-a1^2)+2*a0*a1*u. */
  vroom_fp_t twice_a1;
  twice_a1.m1 = wwv_add( a->c[1].m1, a->c[1].m1 ); /* twice_a1 = 2a1 in RNS base M. */
  twice_a1.m2 = wwv_add( a->c[1].m2, a->c[1].m2 ); /* twice_a1 = 2a1 in RNS base N. */

  vroom_fp_wide_t wide[2];
  vroom_fp_wide_offset( &wide[0] );                         /* wide0  = 0 mod p.   */
  vroom_fp_wide_addmul( &wide[0], &a->c[0], &a->c[0] );    /* wide0 += a0^2.     */
  vroom_fp_wide_submul( &wide[0], &a->c[1], &a->c[1] );    /* wide0 -= a1^2.     */
  vroom_fp_wide_offset( &wide[1] );                         /* wide1  = 0 mod p.   */
  vroom_fp_wide_addmul( &wide[1], &a->c[0], &twice_a1 );   /* wide1 += 2a0*a1.   */

  vroom_fp_reduce_wide_batch2( &out->c[0], &wide[0] );     /* out=(a0^2-a1^2)+(2a0a1)u. */
}

VROOM_FN void
vroom_fp12_mul( vroom_fp12_t *       out,
                 vroom_fp12_t const * a,
                 vroom_fp12_t const * b ) {
  vroom_fp12_t tmp;
  fp12_mul_generated( &tmp, a, b );
  *out = tmp;
}

VROOM_FN void
vroom_fp12_sqr( vroom_fp12_t *       out,
                 vroom_fp12_t const * a ) {
  fp12_sqr_generated( out, a );
}

VROOM_FN void
vroom_fp12_cyclotomic_sqr( vroom_fp12_t *       out,
                            vroom_fp12_t const * a ) {
  fp12_cyclotomic_sqr_generated( out, a );
}

VROOM_FN void
vroom_fp12_mul_sparse( vroom_fp12_t *       out,
                        vroom_fp12_t const * a,
                        vroom_fp_t const     line[6] ) {
  fp12_mul_sparse_generated( out, a, line );
}

VROOM_FN void
vroom_fp12_one( vroom_fp12_t * out ) {
  vroom_fp_one( &out->c[0] );
  for( int i=1; i<12; i++ ) vroom_fp_zero( &out->c[i] );
}

/* One iff in == 1 in Fp12 (each coefficient's canonical residue checked
   against the k*p ladder of the redundant RNS range). */
VROOM_FN int
vroom_fp12_is_one( vroom_fp12_t const * in ) {
  wwv_t mod1 = wwv_ld( vroom_m1 );
  wwv_t mod2 = wwv_ld( vroom_m2 );
  wwv_t p1   = wwv_ld( vroom_field_modulus_m1 );
  wwv_t p2   = wwv_ld( vroom_field_modulus_m2 );
  wwv_t one1 = wwv_ld( vroom_one_m1 );
  wwv_t one2 = wwv_ld( vroom_one_m2 );
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

#endif
