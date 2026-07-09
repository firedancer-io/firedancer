#include "./fd_bn254_field_inl.h"

/* Fp12 ops used by the pairing (Miller loop and final exp). */

/* fd_bn254_fp6_mul_by_fp2 computes r = a * (b, 0, 0) in Fp6.
   Simply (a0*b, a1*b, a2*b).
   Cost: 3 Fp2_mul (vs 6 for full Fp6_mul). */
static inline fd_bn254_fp6_t *
fd_bn254_fp6_mul_by_fp2( fd_bn254_fp6_t *       r,
                         fd_bn254_fp6_t const *  a,
                         fd_bn254_fp2_t const *  b ) {
  fd_bn254_fp2_mul( &r->el[0], &a->el[0], b );
  fd_bn254_fp2_mul( &r->el[1], &a->el[1], b );
  fd_bn254_fp2_mul( &r->el[2], &a->el[2], b );
  return r;
}

/* fd_bn254_fp6_mul_by_01 computes r = a * (b0, b1, 0) in Fp6.
   Karatsuba with b2=0.
   Cost: 5 Fp2_mul (vs 6 for full Fp6_mul). */
static inline fd_bn254_fp6_t *
fd_bn254_fp6_mul_by_01( fd_bn254_fp6_t *       r,
                        fd_bn254_fp6_t const *  a,
                        fd_bn254_fp2_t const *  b0,
                        fd_bn254_fp2_t const *  b1 ) {
  fd_bn254_fp2_t const * a0 = &a->el[0];
  fd_bn254_fp2_t const * a1 = &a->el[1];
  fd_bn254_fp2_t const * a2 = &a->el[2];
  fd_bn254_fp2_t a0b0[1], a1b1[1];
  fd_bn254_fp2_t sa[1], sb[1];
  fd_bn254_fp2_t r0[1], r1[1], r2[1];

  fd_bn254_fp2_mul( a0b0, a0, b0 );
  fd_bn254_fp2_mul( a1b1, a1, b1 );

  /* r0 = a0b0 + xi * a2*b1 */
  fd_bn254_fp2_mul( r0, a2, b1 );
  fd_bn254_fp2_mul_by_xi( r0, r0 );
  fd_bn254_fp2_add( r0, r0, a0b0 );

  /* r1 = (a0+a1)*(b0+b1) - a0b0 - a1b1 */
  fd_bn254_fp2_add( sa, a0, a1 );
  fd_bn254_fp2_add( sb, b0, b1 );
  fd_bn254_fp2_mul( r1, sa, sb );
  fd_bn254_fp2_sub( r1, r1, a0b0 );
  fd_bn254_fp2_sub( r1, r1, a1b1 );

  /* r2 = (a0+a2)*b0 - a0b0 + a1b1 */
  fd_bn254_fp2_add( sa, a0, a2 );
  fd_bn254_fp2_mul( r2, sa, b0 );
  fd_bn254_fp2_sub( r2, r2, a0b0 );
  fd_bn254_fp2_add( r2, r2, a1b1 );

  fd_bn254_fp2_set( &r->el[0], r0 );
  fd_bn254_fp2_set( &r->el[1], r1 );
  fd_bn254_fp2_set( &r->el[2], r2 );
  return r;
}

/* fd_bn254_fp12_mul_sparse computes r = a * b in Fp12,
   where b has the "034" sparse pattern:
     b.el[0] = (c0, 0, 0)
     b.el[1] = (c3, c4, 0)
   This is the pattern produced by line evaluation functions.
   Cost: 13 Fp2_mul (vs 18 for full Fp12_mul). */
fd_bn254_fp12_t *
fd_bn254_fp12_mul_sparse( fd_bn254_fp12_t *       r,
                          fd_bn254_fp12_t const * a,
                          fd_bn254_fp12_t const * b ) {
  fd_bn254_fp2_t const * c0 = &b->el[0].el[0];
  fd_bn254_fp2_t const * c3 = &b->el[1].el[0];
  fd_bn254_fp2_t const * c4 = &b->el[1].el[1];
  fd_bn254_fp6_t a0b0[1], a1b1[1], sa[1];
  fd_bn254_fp2_t sc0[1];

  /* a0*b0 = a.el[0] * (c0, 0, 0) : 3 Fp2_mul */
  fd_bn254_fp6_mul_by_fp2( a0b0, &a->el[0], c0 );

  /* a1*b1 = a.el[1] * (c3, c4, 0) : 5 Fp2_mul */
  fd_bn254_fp6_mul_by_01( a1b1, &a->el[1], c3, c4 );

  /* r1 = (a0+a1) * (c0+c3, c4, 0) - a0b0 - a1b1 : 5 Fp2_mul.
     not lazy for the same reasons as fd_bn254_fp6_mul */
  fd_bn254_fp6_add( sa, &a->el[0], &a->el[1] );
  fd_bn254_fp2_add( sc0, c0, c3 );
  fd_bn254_fp6_mul_by_01( &r->el[1], sa, sc0, c4 );
  fd_bn254_fp6_sub( &r->el[1], &r->el[1], a0b0 );
  fd_bn254_fp6_sub( &r->el[1], &r->el[1], a1b1 );

  /* r0 = a0b0 + gamma * a1b1 */
  fd_bn254_fp6_mul_by_gamma( a1b1, a1b1 );
  fd_bn254_fp6_add( &r->el[0], a0b0, a1b1 );
  return r;
}

fd_bn254_fp12_t *
fd_bn254_fp12_sqr( fd_bn254_fp12_t * r,
                        fd_bn254_fp12_t const * a ) {
  /* https://eprint.iacr.org/2010/354, Alg. 22. */
  fd_bn254_fp6_t c0[1], c2[1], c3[1];
  fd_bn254_fp6_sub( c0, &a->el[0], &a->el[1] );
  fd_bn254_fp6_mul_by_gamma( c3, &a->el[1] );
  fd_bn254_fp6_sub( c3, &a->el[0], c3 );
  fd_bn254_fp6_mul( c2, &a->el[0], &a->el[1] );
  fd_bn254_fp6_mul( c0, c0, c3 );
  fd_bn254_fp6_add( c0, c0, c2 );
  fd_bn254_fp6_add( &r->el[1], c2, c2 );
  fd_bn254_fp6_mul_by_gamma( &r->el[0], c2 );
  fd_bn254_fp6_add( &r->el[0], &r->el[0], c0 );
  return r;
}
