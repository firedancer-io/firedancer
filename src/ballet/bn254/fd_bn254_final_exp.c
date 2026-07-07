#include "./fd_bn254_field_inl.h"

/* Pairing final exponentiation */

static fd_bn254_fp12_t *
fd_bn254_fp12_sqr_fast( fd_bn254_fp12_t * r,
                        fd_bn254_fp12_t const * a ) {
  /* Cyclotomic sqr, https://eprint.iacr.org/2009/565, Sec. 3.2.
     Variant of https://eprint.iacr.org/2010/354, Alg. 24.
     This works when a^(p^6+1)=1, e.g. during pairing final exp. */
  fd_bn254_fp2_t t[9];

  fd_bn254_fp2_sqr( &t[0], &a->el[1].el[1] );
  fd_bn254_fp2_sqr( &t[1], &a->el[0].el[0] );
  fd_bn254_fp2_add( &t[6], &a->el[1].el[1], &a->el[0].el[0] );
  fd_bn254_fp2_sqr( &t[6], &t[6] );
  fd_bn254_fp2_sub( &t[6], &t[6], &t[0] );
  fd_bn254_fp2_sub( &t[6], &t[6], &t[1] );

  fd_bn254_fp2_sqr( &t[2], &a->el[0].el[2] );
  fd_bn254_fp2_sqr( &t[3], &a->el[1].el[0] );
  fd_bn254_fp2_add( &t[7], &a->el[0].el[2], &a->el[1].el[0] );
  fd_bn254_fp2_sqr( &t[7], &t[7] );
  fd_bn254_fp2_sub( &t[7], &t[7], &t[2] );
  fd_bn254_fp2_sub( &t[7], &t[7], &t[3] );

  fd_bn254_fp2_sqr( &t[4], &a->el[1].el[2] );
  fd_bn254_fp2_sqr( &t[5], &a->el[0].el[1] );
  fd_bn254_fp2_add( &t[8], &a->el[1].el[2], &a->el[0].el[1] );
  fd_bn254_fp2_sqr( &t[8], &t[8] );
  fd_bn254_fp2_sub( &t[8], &t[8], &t[4] );
  fd_bn254_fp2_sub( &t[8], &t[8], &t[5] );
  fd_bn254_fp2_mul_by_xi( &t[8], &t[8] );

  fd_bn254_fp2_mul_by_xi( &t[0], &t[0] );
  fd_bn254_fp2_add( &t[0], &t[0], &t[1] );
  fd_bn254_fp2_mul_by_xi( &t[2], &t[2] );
  fd_bn254_fp2_add( &t[2], &t[2], &t[3] );
  fd_bn254_fp2_mul_by_xi( &t[4], &t[4] );
  fd_bn254_fp2_add( &t[4], &t[4], &t[5] );

  fd_bn254_fp2_sub( &r->el[0].el[0], &t[0], &a->el[0].el[0] );
  fd_bn254_fp2_add( &r->el[0].el[0], &r->el[0].el[0], &r->el[0].el[0] );
  fd_bn254_fp2_add( &r->el[0].el[0], &r->el[0].el[0], &t[0] );
  fd_bn254_fp2_sub( &r->el[0].el[1], &t[2], &a->el[0].el[1] );
  fd_bn254_fp2_add( &r->el[0].el[1], &r->el[0].el[1], &r->el[0].el[1] );
  fd_bn254_fp2_add( &r->el[0].el[1], &r->el[0].el[1], &t[2] );
  fd_bn254_fp2_sub( &r->el[0].el[2], &t[4], &a->el[0].el[2] );
  fd_bn254_fp2_add( &r->el[0].el[2], &r->el[0].el[2], &r->el[0].el[2] );
  fd_bn254_fp2_add( &r->el[0].el[2], &r->el[0].el[2], &t[4] );

  fd_bn254_fp2_add( &r->el[1].el[0], &t[8], &a->el[1].el[0] );
  fd_bn254_fp2_add( &r->el[1].el[0], &r->el[1].el[0], &r->el[1].el[0] );
  fd_bn254_fp2_add( &r->el[1].el[0], &r->el[1].el[0], &t[8] );
  fd_bn254_fp2_add( &r->el[1].el[1], &t[6], &a->el[1].el[1] );
  fd_bn254_fp2_add( &r->el[1].el[1], &r->el[1].el[1], &r->el[1].el[1] );
  fd_bn254_fp2_add( &r->el[1].el[1], &r->el[1].el[1], &t[6] );
  fd_bn254_fp2_add( &r->el[1].el[2], &t[7], &a->el[1].el[2] );
  fd_bn254_fp2_add( &r->el[1].el[2], &r->el[1].el[2], &r->el[1].el[2] );
  fd_bn254_fp2_add( &r->el[1].el[2], &r->el[1].el[2], &t[7] );
  return r;
}

fd_bn254_fp12_t *
fd_bn254_fp12_pow_x( fd_bn254_fp12_t * restrict r,
                     fd_bn254_fp12_t const *    a ) {
  /* https://github.com/Consensys/gnark-crypto/blob/v0.12.1/ecc/bn254/internal/fptower/e12_pairing.go#L16 */
  fd_bn254_fp12_t t[7];
  fd_bn254_fp12_sqr_fast( &t[3], a );
  fd_bn254_fp12_sqr_fast( &t[5], &t[3] );
  fd_bn254_fp12_sqr_fast( r,     &t[5] );
  fd_bn254_fp12_sqr_fast( &t[0], r );
  fd_bn254_fp12_mul     ( &t[2], &t[0], a );
  fd_bn254_fp12_mul     ( &t[0], &t[2], &t[3] );
  fd_bn254_fp12_mul     ( &t[1], &t[0], a );
  fd_bn254_fp12_mul     ( &t[4], &t[2], r );
  fd_bn254_fp12_sqr_fast( &t[6], &t[2] );
  fd_bn254_fp12_mul     ( &t[1], &t[1], &t[0] );
  fd_bn254_fp12_mul     ( &t[0], &t[1], &t[3] );
  for( int i=0; i<6; i++ ) fd_bn254_fp12_sqr_fast( &t[6], &t[6] );
  fd_bn254_fp12_mul     ( &t[5], &t[5], &t[6] );
  fd_bn254_fp12_mul     ( &t[5], &t[5], &t[4] );
  for( int i=0; i<7; i++ ) fd_bn254_fp12_sqr_fast( &t[5], &t[5] );
  fd_bn254_fp12_mul     ( &t[4], &t[4], &t[5] );
  for( int i=0; i<8; i++ ) fd_bn254_fp12_sqr_fast( &t[4], &t[4] );
  fd_bn254_fp12_mul     ( &t[4], &t[4], &t[0] );
  fd_bn254_fp12_mul     ( &t[3], &t[3], &t[4] );
  for( int i=0; i<6; i++ ) fd_bn254_fp12_sqr_fast( &t[3], &t[3] );
  fd_bn254_fp12_mul     ( &t[2], &t[2], &t[3] );
  for( int i=0; i<8; i++ ) fd_bn254_fp12_sqr_fast( &t[2], &t[2] );
  fd_bn254_fp12_mul     ( &t[2], &t[2], &t[0] );
  for( int i=0; i<6; i++ ) fd_bn254_fp12_sqr_fast( &t[2], &t[2] );
  fd_bn254_fp12_mul     ( &t[2], &t[2], &t[0] );
  for( int i=0; i<10; i++ ) fd_bn254_fp12_sqr_fast( &t[2], &t[2] );
  fd_bn254_fp12_mul     ( &t[1], &t[1], &t[2] );
  for( int i=0; i<6; i++ ) fd_bn254_fp12_sqr_fast( &t[1], &t[1] );
  fd_bn254_fp12_mul     ( &t[0], &t[0], &t[1] );
  fd_bn254_fp12_mul     ( r, r, &t[0] );
  return r;
}

fd_bn254_fp12_t *
fd_bn254_final_exp( fd_bn254_fp12_t *       r,
                    fd_bn254_fp12_t * const x ) {
  /* https://github.com/Consensys/gnark-crypto/blob/v0.12.1/ecc/bn254/pairing.go#L62 */
  fd_bn254_fp12_t t[5], s[1];
  fd_bn254_fp12_conj ( &t[0], x );            /* x^(p^6) */
  fd_bn254_fp12_inv  ( &t[1], x );            /* x^(-1) */
  fd_bn254_fp12_mul  ( &t[0], &t[0], &t[1] ); /* x^(p^6-1) */
  fd_bn254_fp12_frob2( &t[2], &t[0] );        /* x^(p^6-1)(p^2) */
  fd_bn254_fp12_mul  ( s, &t[0], &t[2] );     /* x^(p^6-1)(p^2+1) */
  /* Fast chain, https://eprint.iacr.org/2015/192, Alg. 10.
     Variant of https://eprint.iacr.org/2010/354, Alg. 31. */
  fd_bn254_fp12_pow_x   ( &t[0], s );
  fd_bn254_fp12_conj    ( &t[0], &t[0] );
  fd_bn254_fp12_sqr_fast( &t[0], &t[0] );
  fd_bn254_fp12_sqr_fast( &t[1], &t[0] );
  fd_bn254_fp12_mul     ( &t[1], &t[1], &t[0] );

  fd_bn254_fp12_pow_x   ( &t[2], &t[1] );
  fd_bn254_fp12_conj    ( &t[2], &t[2] );
  fd_bn254_fp12_conj    ( &t[3], &t[1] );
  fd_bn254_fp12_mul     ( &t[1], &t[2], &t[3] );

  fd_bn254_fp12_sqr_fast( &t[3], &t[2] );
  fd_bn254_fp12_pow_x   ( &t[4], &t[3] );
  fd_bn254_fp12_mul     ( &t[4], &t[1], &t[4] );
  fd_bn254_fp12_mul     ( &t[3], &t[0], &t[4] );
  fd_bn254_fp12_mul     ( &t[0], &t[2], &t[4] );
  fd_bn254_fp12_mul     ( &t[0], &t[0], s );

  fd_bn254_fp12_frob    ( &t[2], &t[3] );
  fd_bn254_fp12_mul     ( &t[0], &t[0], &t[2] );
  fd_bn254_fp12_frob2   ( &t[2], &t[4] );
  fd_bn254_fp12_mul     ( &t[0], &t[0], &t[2] );

  fd_bn254_fp12_conj    ( &t[2], s );
  fd_bn254_fp12_mul     ( &t[2], &t[2], &t[3] );
  // fd_bn254_fp12_frob3   ( &t[2], &t[2] );
  fd_bn254_fp12_frob2   ( &t[2], &t[2] );
  fd_bn254_fp12_frob    ( &t[2], &t[2] );
  fd_bn254_fp12_mul     ( r, &t[0], &t[2] );
  return r;
}
