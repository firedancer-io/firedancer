#include "fd_bls_field.h"

#if FD_HAS_AVX512

#include "fd_bls_constants.h"
#include "fd_bls_fp12_generated.inc"

void
fd_bls_fp2_add( fd_bls_fp2_t *       out,
                  fd_bls_fp2_t const * a,
                  fd_bls_fp2_t const * b ) {
  fd_bls_fp_add( &out->c[0], &a->c[0], &b->c[0] );
  fd_bls_fp_add( &out->c[1], &a->c[1], &b->c[1] );
}

void
fd_bls_fp2_sub( fd_bls_fp2_t *       out,
                  fd_bls_fp2_t const * a,
                  fd_bls_fp2_t const * b ) {
  fd_bls_fp_sub( &out->c[0], &a->c[0], &b->c[0] );
  fd_bls_fp_sub( &out->c[1], &a->c[1], &b->c[1] );
}

void
fd_bls_fp2_neg( fd_bls_fp2_t *       out,
                  fd_bls_fp2_t const * a ) {
  fd_bls_fp_neg( &out->c[0], &a->c[0] );
  fd_bls_fp_neg( &out->c[1], &a->c[1] );
}

void
fd_bls_fp2_mul( fd_bls_fp2_t *       out,
                  fd_bls_fp2_t const * a,
                  fd_bls_fp2_t const * b ) {
  /* (a0+a1*u)(b0+b1*u)=(a0b0-a1b1)+(a0b1+a1b0)u.  Each
     sum of products crosses one shared RNS reduction boundary. */
  fd_bls_fp_wide_t x, y;
  fd_bls_fp_wide_offset( &x );                         /* x      = 0 mod p.        */
  fd_bls_fp_wide_addmul( &x, &a->c[0], &b->c[0] );    /* x     += a0*b0.          */
  fd_bls_fp_wide_submul( &x, &a->c[1], &b->c[1] );    /* x     -= a1*b1.          */
  fd_bls_fp_wide_offset( &y );                         /* y      = 0 mod p.        */
  fd_bls_fp_wide_addmul( &y, &a->c[0], &b->c[1] );    /* y     += a0*b1.          */
  fd_bls_fp_wide_addmul( &y, &a->c[1], &b->c[0] );    /* y     += a1*b0.          */
  fd_bls_fp_reduce_wide( &out->c[0], &x );            /* out.re = a0b0-a1b1.      */
  fd_bls_fp_reduce_wide( &out->c[1], &y );            /* out.im = a0b1+a1b0.      */
}

void
fd_bls_fp2_sqr( fd_bls_fp2_t *       out,
                  fd_bls_fp2_t const * a ) {
  /* (a0+a1*u)^2=(a0^2-a1^2)+2*a0*a1*u. */
  fd_bls_fp_t twice_a1;
  twice_a1.m1 = wwv_add( a->c[1].m1, a->c[1].m1 ); /* twiceA1 = 2a1 in RNS base M. */
  twice_a1.m2 = wwv_add( a->c[1].m2, a->c[1].m2 ); /* twiceA1 = 2a1 in RNS base N. */

  fd_bls_fp_wide_t wide[2];
  fd_bls_fp_wide_offset( &wide[0] );                         /* wide0  = 0 mod p.   */
  fd_bls_fp_wide_addmul( &wide[0], &a->c[0], &a->c[0] );    /* wide0 += a0^2.     */
  fd_bls_fp_wide_submul( &wide[0], &a->c[1], &a->c[1] );    /* wide0 -= a1^2.     */
  fd_bls_fp_wide_offset( &wide[1] );                         /* wide1  = 0 mod p.   */
  fd_bls_fp_wide_addmul( &wide[1], &a->c[0], &twice_a1 );   /* wide1 += 2a0*a1.   */

  fd_bls_fp_reduce_wide_batch2( &out->c[0], &wide[0] );     /* out=(a0^2-a1^2)+(2a0a1)u. */
}

void
fd_bls_fp12_mul( fd_bls_fp12_t *       out,
                   fd_bls_fp12_t const * a,
                   fd_bls_fp12_t const * b ) {
  fd_bls_fp12_t tmp;
  fp12_mul_generated( &tmp, a, b );
  *out = tmp;
}

void
fd_bls_fp12_sqr( fd_bls_fp12_t *       out,
                   fd_bls_fp12_t const * a ) {
  fp12_sqr_generated( out, a );
}

void
fd_bls_fp12_cyclotomic_sqr( fd_bls_fp12_t *       out,
                              fd_bls_fp12_t const * a ) {
  fp12_cyclotomic_sqr_generated( out, a );
}

void
fd_bls_fp12_mul_sparse( fd_bls_fp12_t *       out,
                          fd_bls_fp12_t const * a,
                          fd_bls_fp_t const      line[6] ) {
  fp12_mul_sparse_generated( out, a, line );
}

void
fd_bls_fp12_one( fd_bls_fp12_t * out ) {
  fd_bls_fp_one( &out->c[0] );
  for( int i=1; i<12; i++ ) fd_bls_fp_zero( &out->c[i] );
}

#endif
