#ifndef HEADER_fd_src_ballet_bn254_fd_bn254_g2_inl_h
#define HEADER_fd_src_ballet_bn254_fd_bn254_g2_inl_h

/* Small G2 helpers shared by fd_bn254_g2.c and fd_bn254_pairing.c. */

#include "./fd_bn254_field_inl.h"

static inline int
fd_bn254_g2_eq( fd_bn254_g2_t const * p,
                fd_bn254_g2_t const * q ) {
  if( fd_bn254_g2_is_zero( p ) ) {
    return fd_bn254_g2_is_zero( q );
  }
  if( fd_bn254_g2_is_zero( q ) ) {
    return 0;
  }

  fd_bn254_fp2_t pz2[1], qz2[1];
  fd_bn254_fp2_t l[1], r[1];

  fd_bn254_fp2_sqr( pz2, &p->Z );
  fd_bn254_fp2_sqr( qz2, &q->Z );

  fd_bn254_fp2_mul( l, &p->X, qz2 );
  fd_bn254_fp2_mul( r, &q->X, pz2 );
  if( !fd_bn254_fp2_eq( l, r ) ) {
    return 0;
  }

  fd_bn254_fp2_mul( l, &p->Y, qz2 );
  fd_bn254_fp2_mul( l, l, &q->Z );
  fd_bn254_fp2_mul( r, &q->Y, pz2 );
  fd_bn254_fp2_mul( r, r, &p->Z );
  return fd_bn254_fp2_eq( l, r );
}

static inline fd_bn254_g2_t *
fd_bn254_g2_set( fd_bn254_g2_t *       r,
                 fd_bn254_g2_t const * p ) {
  fd_bn254_fp2_set( &r->X, &p->X );
  fd_bn254_fp2_set( &r->Y, &p->Y );
  fd_bn254_fp2_set( &r->Z, &p->Z );
  return r;
}

static inline fd_bn254_g2_t *
fd_bn254_g2_neg( fd_bn254_g2_t *       r,
                 fd_bn254_g2_t const * p ) {
  fd_bn254_fp2_set( &r->X, &p->X );
  fd_bn254_fp2_neg( &r->Y, &p->Y );
  fd_bn254_fp2_set( &r->Z, &p->Z );
  return r;
}

static inline fd_bn254_g2_t *
fd_bn254_g2_set_zero( fd_bn254_g2_t * r ) {
  // fd_bn254_fp2_set_zero( &r->X );
  // fd_bn254_fp2_set_zero( &r->Y );
  fd_bn254_fp2_set_zero( &r->Z );
  return r;
}

static inline fd_bn254_g2_t *
fd_bn254_g2_frob( fd_bn254_g2_t *       r,
                  fd_bn254_g2_t const * p ) {
  fd_bn254_fp2_conj( &r->X, &p->X );
  fd_bn254_fp2_mul ( &r->X, &r->X, &fd_bn254_const_frob_gamma1_mont[1] );
  fd_bn254_fp2_conj( &r->Y, &p->Y );
  fd_bn254_fp2_mul ( &r->Y, &r->Y, &fd_bn254_const_frob_gamma1_mont[2] );
  fd_bn254_fp2_conj( &r->Z, &p->Z );
  return r;
}

static inline fd_bn254_g2_t *
fd_bn254_g2_frob2( fd_bn254_g2_t *       r,
                   fd_bn254_g2_t const * p ) {
  /* X */
  fd_bn254_fp_mul( &r->X.el[0], &p->X.el[0], &fd_bn254_const_frob_gamma2_mont[1] );
  fd_bn254_fp_mul( &r->X.el[1], &p->X.el[1], &fd_bn254_const_frob_gamma2_mont[1] );
  /* Y */
  fd_bn254_fp_mul( &r->Y.el[0], &p->Y.el[0], &fd_bn254_const_frob_gamma2_mont[2] );
  fd_bn254_fp_mul( &r->Y.el[1], &p->Y.el[1], &fd_bn254_const_frob_gamma2_mont[2] );
  /* Z=1 */
  fd_bn254_fp2_set( &r->Z, &p->Z );
  return r;
}

#endif /* HEADER_fd_src_ballet_bn254_fd_bn254_g2_inl_h */
