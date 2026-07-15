#include "./fd_bn254_g2_inl.h"
#include "./fd_bn254_glv.h"

/* G2 scalar mul and deserialization. */

/* fd_bn254_g2_scalar_mul computes r = [s]P.
   p must be in affine form (p->Z == 1).
   The result is in projective coordinates over Fp2. */
fd_bn254_g2_t *
fd_bn254_g2_scalar_mul( fd_bn254_g2_t *           r,
                        fd_bn254_g2_t const *     p,
                        fd_bn254_scalar_t const * s ) {
  if( FD_UNLIKELY( fd_uint256_is_zero( s ) || fd_bn254_g2_is_zero( p ) ) ) {
    return fd_bn254_g2_set_zero( r );
  }

  const ulong g1_const[ 3 ] = { 0x7a7bd9d4391eb18eUL, 0x4ccef014a773d2cfUL, 0x0000000000000002UL };
  ulong b1[ 3 ], b2[ 2 ];
  fd_bn254_glv_sxg3( b1, s, g1_const );
  fd_bn254_glv_sxg2( b2, s, g2_const );

  /* k1 = s - b1*N_C - b2*N_B (may be negative for G2) */
  fd_uint256_t k1_abs[1];
  int k1_neg = 0;
  {
    ulong p_nc[ 4 ];
    /* b2*nb will produce at most 3 limbs, so we want the 4th zeroed for the addition. */
    ulong p_nb[ 4 ] = {0};
    ulong    t[ 4 ];
    fd_bn254_glv_mul3x2( p_nc, b1, nc );
    fd_bn254_glv_mul2x1( p_nb, b2, nb );
    fd_bn254_glv_add4( t, p_nc, p_nb );
    ulong borrow = fd_bn254_glv_sub4( k1_abs->limbs, s->limbs, t );
    if( borrow ) {
      k1_neg = 1;
      fd_bn254_glv_negate4( k1_abs->limbs );
    }
  }

  /* k2 = b2*N_A - b1*N_B (usually negative for G2) */
  fd_uint256_t k2_abs[1];
  int k2_neg = 0;
  {
    ulong pos[ 4 ], neg[ 4 ];
    fd_bn254_glv_mul2x2( pos, b2, na );
    fd_bn254_glv_mul3x1( neg, b1, nb );
    ulong borrow = fd_bn254_glv_sub4( k2_abs->limbs, pos, neg );
    if( borrow ) {
      k2_neg = 1;
      fd_bn254_glv_negate4( k2_abs->limbs );
    }
  }

  /* pt1 = P, pt2 = phi(P) = (beta * P.x, P.y).
     If k1 < 0, negate pt1. If k2 < 0, negate pt2. */
  fd_bn254_g2_t pt1[1], pt2[1];
  fd_bn254_g2_set( pt1, p );
  fd_bn254_fp_mul( &pt2->X.el[0], &p->X.el[0], fd_bn254_const_beta_mont );
  fd_bn254_fp_mul( &pt2->X.el[1], &p->X.el[1], fd_bn254_const_beta_mont );
  fd_bn254_fp2_set( &pt2->Y, &p->Y );
  fd_bn254_fp2_set_one( &pt2->Z );
  if( k1_neg ) {
    fd_bn254_fp2_neg( &pt1->Y, &pt1->Y );
  }
  if( k2_neg ) {
    fd_bn254_fp2_neg( &pt2->Y, &pt2->Y );
  }

  fd_bn254_g2_t pt12[1];
  fd_bn254_g2_affine_add( pt12, pt1, pt2 );

  /* Shamir's trick: simultaneous double-and-add on k1, k2. */
  int i = 255;
  for( ; i>=0; i-- ) {
    int k1b = !!fd_uint256_bit( k1_abs, i );
    int k2b = !!fd_uint256_bit( k2_abs, i );
    if( k1b || k2b ) {
      fd_bn254_g2_set( r, ( k1b && k2b ) ? pt12 : ( k1b ? pt1 : pt2 ) );
      break;
    }
  }
  if( FD_UNLIKELY( i<0 ) ) {
    return fd_bn254_g2_set_zero( r );
  }
  for( i--; i >= 0; i-- ) {
    fd_bn254_g2_dbl( r, r );
    int k1b = !!fd_uint256_bit( k1_abs, i );
    int k2b = !!fd_uint256_bit( k2_abs, i );
    if( k1b && k2b ) {
      fd_bn254_g2_add_mixed( r, r, pt12 );
    } else if( k1b ) {
      fd_bn254_g2_add_mixed( r, r, pt1 );
    } else if( k2b ) {
      fd_bn254_g2_add_mixed( r, r, pt2 );
    }
  }

  return r;
}

/* fd_bn254_g2_frombytes_internal extracts (x, y) and performs basic checks.
   This is used by fd_bn254_g2_compress() and fd_bn254_g2_frombytes_check_subgroup(). */
fd_bn254_g2_t *
fd_bn254_g2_frombytes_internal( fd_bn254_g2_t * p,
                                uchar const     in[128],
                                int             big_endian ) {
  /* Special case: all zeros => point at infinity */
  const uchar zero[128] = { 0 };
  if( FD_UNLIKELY( fd_memeq( in, zero, 128 ) ) ) {
    return fd_bn254_g2_set_zero( p );
  }

  /* Check x < p */
  if( FD_UNLIKELY( !fd_bn254_fp2_frombytes_nm( &p->X, &in[0], big_endian, NULL, NULL ) ) ) {
    return NULL;
  }

  /* Check flags and y < p */
  int is_inf, is_neg;
  if( FD_UNLIKELY( !fd_bn254_fp2_frombytes_nm( &p->Y, &in[64], big_endian, &is_inf, &is_neg ) ) ) {
    return NULL;
  }

  if( FD_UNLIKELY( is_inf ) ) {
    return fd_bn254_g2_set_zero( p );
  }

  fd_bn254_fp2_set_one( &p->Z );
  return p;
}

/* fd_bn254_g2_frombytes_check_eq_only performs frombytes, checks the curve
   equation, but does NOT check subgroup membership. */
fd_bn254_g2_t *
fd_bn254_g2_frombytes_check_eq_only( fd_bn254_g2_t * p,
                                     uchar const     in[128],
                                     int             big_endian ) {
  if( FD_UNLIKELY( !fd_bn254_g2_frombytes_internal( p, in, big_endian ) ) ) {
    return NULL;
  }
  if( FD_UNLIKELY( fd_bn254_g2_is_zero( p ) ) ) {
    return p;
  }

  fd_bn254_fp2_to_mont( &p->X, &p->X );
  fd_bn254_fp2_to_mont( &p->Y, &p->Y );
  fd_bn254_fp2_set_one( &p->Z );

  /* Check that y^2 = x^3 + b */
  fd_bn254_fp2_t y2[1], x3b[1];
  fd_bn254_fp2_sqr( y2, &p->Y );
  fd_bn254_fp2_sqr( x3b, &p->X );
  fd_bn254_fp2_mul( x3b, x3b, &p->X );
  fd_bn254_fp2_add( x3b, x3b, fd_bn254_const_twist_b_mont );
  if( FD_UNLIKELY( !fd_bn254_fp2_eq( y2, x3b ) ) ) {
    return NULL;
  }
  return p;
}

/* fd_bn254_g2_frombytes_check_subgroup performs frombytes AND checks subgroup membership. */
fd_bn254_g2_t *
fd_bn254_g2_frombytes_check_subgroup( fd_bn254_g2_t * p,
                                      uchar const     in[128],
                                      int             big_endian ) {
  if( FD_UNLIKELY( fd_bn254_g2_frombytes_check_eq_only( p, in, big_endian )==NULL ) ) {
    return NULL;
  }

  /* G2 does NOT have prime order, so we have to check group membership. */

  /* We use the fast subgroup membership check, that requires a single 64-bit scalar mul.
     https://eprint.iacr.org/2022/348, Sec 3.1.
     [r]P == 0 <==> [x+1]P + ψ([x]P) + ψ²([x]P) = ψ³([2x]P)
     See also: https://github.com/Consensys/gnark-crypto/blob/v0.12.1/ecc/bn254/g2.go#L404

     For reference, the followings also work:

     1) very slow: 256-bit scalar mul

     fd_bn254_g2_t r[1];
     fd_bn254_g2_scalar_mul( r, p, fd_bn254_const_r );
     if( !fd_bn254_g2_is_zero( r ) ) return NULL;

     2) slow: 128-bit scalar mul

     fd_bn254_g2_t a[1], b[1];
     const fd_bn254_scalar_t six_x_sqr[1] = {{{ 0xf83e9682e87cfd46, 0x6f4d8248eeb859fb, 0x0, 0x0, }}};
     fd_bn254_g2_scalar_mul( a, p, six_x_sqr );
     fd_bn254_g2_frob( b, p );
     if( !fd_bn254_g2_eq( a, b ) ) return NULL; */

  fd_bn254_g2_t xp[1], l[1], psi[1], r[1];
  fd_bn254_g2_scalar_mul( xp, p, fd_bn254_const_x ); /* 64-bit */
  fd_bn254_g2_add_mixed( l, xp, p );

  /* l will not be equal to psi unless p==0 */
  fd_bn254_g2_frob( psi, xp );
  fd_bn254_g2_add( l, l, psi );

  fd_bn254_g2_frob2( psi, xp ); /* faster than frob( psi, psi ) */
  fd_bn254_g2_add( l, l, psi );

  fd_bn254_g2_frob( psi, psi );
  fd_bn254_g2_dbl( r, psi );
  if( FD_UNLIKELY( !fd_bn254_g2_eq( l, r ) ) ) {
    return NULL;
  }
  return p;
}
