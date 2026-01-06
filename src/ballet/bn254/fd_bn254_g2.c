#include "./fd_bn254.h"

/* G2 */

/* COV: unlike g1, g2 operations are not exposed to users.
   So many edge cases and checks for zero are never triggered, e.g. by syscall tests. */

static inline int
fd_bn254_g2_is_zero( fd_bn254_g2_t const * p ) {
  return fd_bn254_fp2_is_zero( &p->Z );
}

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
fd_bn254_g2_to_affine( fd_bn254_g2_t *       r,
                       fd_bn254_g2_t const * p ) {
  if( FD_UNLIKELY( fd_bn254_fp2_is_zero( &p->Z ) || fd_bn254_fp2_is_one( &p->Z ) ) ) {
    return fd_bn254_g2_set( r, p );
  }

  fd_bn254_fp2_t iz[1], iz2[1];
  fd_bn254_fp2_inv( iz, &p->Z );
  fd_bn254_fp2_sqr( iz2, iz );

  /* X / Z^2, Y / Z^3 */
  fd_bn254_fp2_mul( &r->X, &p->X, iz2 );
  fd_bn254_fp2_mul( &r->Y, &p->Y, iz2 );
  fd_bn254_fp2_mul( &r->Y, &r->Y, iz );
  fd_bn254_fp2_set_one( &r->Z );
  return r;
}

uchar *
fd_bn254_g2_tobytes( uchar                 out[128],
                     fd_bn254_g2_t const * p,
                     int                   big_endian ) {
  if( FD_UNLIKELY( fd_bn254_g2_is_zero( p ) ) ) {
    fd_memset( out, 0, 128UL );
    /* no flags */
    return out;
  }

  fd_bn254_g2_t r[1];
  fd_bn254_g2_to_affine( r, p );

  fd_bn254_fp2_from_mont( &r->X, &r->X );
  fd_bn254_fp2_from_mont( &r->Y, &r->Y );

  fd_bn254_fp2_tobytes_nm( &out[ 0], &r->X, big_endian );
  fd_bn254_fp2_tobytes_nm( &out[64], &r->Y, big_endian );
  /* no flags */
  return out;
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

/* fd_bn254_g2_dbl computes r = 2p.
   https://hyperelliptic.org/efd/g1p/auto-shortw-jacobian-0.html#doubling-dbl-2009-l */
fd_bn254_g2_t *
fd_bn254_g2_dbl( fd_bn254_g2_t *       r,
                 fd_bn254_g2_t const * p ) {
  /* p==0, return 0 */
  if( FD_UNLIKELY( fd_bn254_g2_is_zero( p ) ) ) {
    return fd_bn254_g2_set_zero( r );
  }

  fd_bn254_fp2_t a[1], b[1], c[1];
  fd_bn254_fp2_t d[1], e[1], f[1];

  /* A = X1^2 */
  fd_bn254_fp2_sqr( a, &p->X );
  /* B = Y1^2 */
  fd_bn254_fp2_sqr( b, &p->Y );
  /* C = B^2 */
  fd_bn254_fp2_sqr( c, b );
  /* D = 2*((X1+B)^2-A-C)
     (X1+B)^2 = X1^2 + 2*X1*B + B^2
     D = 2*(X1^2 + 2*X1*B + B^2 - A    - C)
     D = 2*(X1^2 + 2*X1*B + B^2 - X1^2 - B^2)
            ^               ^     ^      ^
            |---------------|-----|      |
                            |------------|
     These terms cancel each other out, and we're left with:
     D = 2*(2*X1*B) */
  fd_bn254_fp2_mul( d, &p->X, b );
  fd_bn254_fp2_add( d, d, d );
  fd_bn254_fp2_add( d, d, d );
  /* E = 3*A */
  fd_bn254_fp2_add( e, a, a );
  fd_bn254_fp2_add( e, a, e );
  /* F = E^2 */
  fd_bn254_fp2_sqr( f, e );
  /* X3 = F-2*D */
  fd_bn254_fp2_add( &r->X, d, d );
  fd_bn254_fp2_sub( &r->X, f, &r->X );
  /* Z3 = (Y1+Z1)^2-YY-ZZ
     note: compute Z3 before Y3 because it depends on p->Y,
     that might be overwritten if r==p. */
  /* Z3 = 2*Y1*Z1 */
  fd_bn254_fp2_mul( &r->Z, &p->Y, &p->Z );
  fd_bn254_fp2_add( &r->Z, &r->Z, &r->Z );
  /* Y3 = E*(D-X3)-8*C */
  fd_bn254_fp2_sub( &r->Y, d, &r->X );
  fd_bn254_fp2_mul( &r->Y, e, &r->Y );
  fd_bn254_fp2_add( c, c, c ); /* 2*c */
  fd_bn254_fp2_add( c, c, c ); /* 4*y */
  fd_bn254_fp2_add( c, c, c ); /* 8*y */
  fd_bn254_fp2_sub( &r->Y, &r->Y, c );
  return r;
}

/* fd_bn254_g2_add_mixed computes r = p + q, when q->Z==1.
   http://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#addition-madd-2007-bl */
fd_bn254_g2_t *
fd_bn254_g2_add_mixed( fd_bn254_g2_t *       r,
                       fd_bn254_g2_t const * p,
                       fd_bn254_g2_t const * q ) {
  /* p==0, return q */
  if( FD_UNLIKELY( fd_bn254_g2_is_zero( p ) ) ) {
    return fd_bn254_g2_set( r, q );
  }
  /* q==0, return p */
  if( FD_UNLIKELY( fd_bn254_g2_is_zero( q ) ) ) {
    return fd_bn254_g2_set( r, p );
  }
  fd_bn254_fp2_t zz[1], u2[1], s2[1];
  fd_bn254_fp2_t h[1], hh[1];
  fd_bn254_fp2_t i[1], j[1];
  fd_bn254_fp2_t rr[1], v[1];
  /* Z1Z1 = Z1^2 */
  fd_bn254_fp2_sqr( zz, &p->Z );
  /* U2 = X2*Z1Z1 */
  fd_bn254_fp2_mul( u2, &q->X, zz );
  /* S2 = Y2*Z1*Z1Z1 */
  fd_bn254_fp2_mul( s2, &q->Y, &p->Z );
  fd_bn254_fp2_mul( s2, s2, zz );

  /* if p==q, call fd_bn254_g2_dbl */
  if( FD_UNLIKELY( fd_bn254_fp2_eq( u2, &p->X ) && fd_bn254_fp2_eq( s2, &p->Y ) ) ) {
    return fd_bn254_g2_dbl( r, p );
  }

  /* H = U2-X1 */
  fd_bn254_fp2_sub( h, u2, &p->X );
  /* HH = H^2 */
  fd_bn254_fp2_sqr( hh, h );
  /* I = 4*HH */
  fd_bn254_fp2_add( i, hh, hh );
  fd_bn254_fp2_add( i, i, i );
  /* J = H*I */
  fd_bn254_fp2_mul( j, h, i );
  /* r = 2*(S2-Y1) */
  fd_bn254_fp2_sub( rr, s2, &p->Y );
  fd_bn254_fp2_add( rr, rr, rr );
  /* V = X1*I */
  fd_bn254_fp2_mul( v, &p->X, i );
  /* X3 = r^2-J-2*V */
  fd_bn254_fp2_sqr( &r->X, rr );
  fd_bn254_fp2_sub( &r->X, &r->X, j );
  fd_bn254_fp2_sub( &r->X, &r->X, v );
  fd_bn254_fp2_sub( &r->X, &r->X, v );
  /* Y3 = r*(V-X3)-2*Y1*J
     note: i no longer used */
  fd_bn254_fp2_mul( i, &p->Y, j ); /* i =   Y1*J */
  fd_bn254_fp2_add( i, i, i );     /* i = 2*Y1*J */
  fd_bn254_fp2_sub( &r->Y, v, &r->X );
  fd_bn254_fp2_mul( &r->Y, &r->Y, rr );
  fd_bn254_fp2_sub( &r->Y, &r->Y, i );
  /* Z3 = (Z1+H)^2-Z1Z1-HH */
  fd_bn254_fp2_add( &r->Z, &p->Z, h );
  fd_bn254_fp2_sqr( &r->Z, &r->Z );
  fd_bn254_fp2_sub( &r->Z, &r->Z, zz );
  fd_bn254_fp2_sub( &r->Z, &r->Z, hh );
  return r;
}

/* fd_bn254_g2_add computes r = p + q.
   http://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#addition-add-2007-bl */
fd_bn254_g2_t *
fd_bn254_g2_add( fd_bn254_g2_t *       r,
                 fd_bn254_g2_t const * p,
                 fd_bn254_g2_t const * q ) {
  /* p==0, return q */
  if( FD_UNLIKELY( fd_bn254_g2_is_zero( p ) ) ) {
    return fd_bn254_g2_set( r, q );
  }
  /* q==0, return p */
  if( FD_UNLIKELY( fd_bn254_g2_is_zero( q ) ) ) {
    return fd_bn254_g2_set( r, p );
  }
  fd_bn254_fp2_t zz1[1], zz2[1];
  fd_bn254_fp2_t u1[1], s1[1];
  fd_bn254_fp2_t u2[1], s2[1];
  fd_bn254_fp2_t h[1];
  fd_bn254_fp2_t i[1], j[1];
  fd_bn254_fp2_t rr[1], v[1];
  /* Z1Z1 = Z1^2 */
  fd_bn254_fp2_sqr( zz1, &p->Z );
  /* Z2Z2 = Z2^2 */
  fd_bn254_fp2_sqr( zz2, &q->Z );
  /* U1 = X1*Z2Z2 */
  fd_bn254_fp2_mul( u1, &p->X, zz2 );
  /* U2 = X2*Z1Z1 */
  fd_bn254_fp2_mul( u2, &q->X, zz1 );
  /* S1 = Y1*Z2*Z2Z2 */
  fd_bn254_fp2_mul( s1, &p->Y, &q->Z );
  fd_bn254_fp2_mul( s1, s1, zz2 );
  /* S2 = Y2*Z1*Z1Z1 */
  fd_bn254_fp2_mul( s2, &q->Y, &p->Z );
  fd_bn254_fp2_mul( s2, s2, zz1 );

  /* if p==q, call fd_bn254_g2_dbl */
  // if( FD_UNLIKELY( fd_bn254_fp2_eq( u2, &p->X ) && fd_bn254_fp2_eq( s2, &p->Y ) ) ) {
  //   return fd_bn254_g2_dbl( r, p );
  // }

  /* H = U2-U1 */
  fd_bn254_fp2_sub( h, u2, u1 );
  /* HH = (2*H)^2 */
  fd_bn254_fp2_add( i, h, h );
  fd_bn254_fp2_sqr( i, i );
  /* J = H*I */
  fd_bn254_fp2_mul( j, h, i );
  /* r = 2*(S2-S1) */
  fd_bn254_fp2_sub( rr, s2, s1 );
  fd_bn254_fp2_add( rr, rr, rr );
  /* V = U1*I */
  fd_bn254_fp2_mul( v, u1, i );
  /* X3 = r^2-J-2*V */
  fd_bn254_fp2_sqr( &r->X, rr );
  fd_bn254_fp2_sub( &r->X, &r->X, j );
  fd_bn254_fp2_sub( &r->X, &r->X, v );
  fd_bn254_fp2_sub( &r->X, &r->X, v );
  /* Y3 = r*(V-X3)-2*S1*J
     note: i no longer used */
  fd_bn254_fp2_mul( i, s1, j ); /* i =   S1*J */
  fd_bn254_fp2_add( i, i, i );  /* i = 2*S1*J */
  fd_bn254_fp2_sub( &r->Y, v, &r->X );
  fd_bn254_fp2_mul( &r->Y, &r->Y, rr );
  fd_bn254_fp2_sub( &r->Y, &r->Y, i );
  /* Z3 = ((Z1+Z2)^2-Z1Z1-Z2Z2)*H */
  fd_bn254_fp2_add( &r->Z, &p->Z, &q->Z );
  fd_bn254_fp2_sqr( &r->Z, &r->Z );
  fd_bn254_fp2_sub( &r->Z, &r->Z, zz1 );
  fd_bn254_fp2_sub( &r->Z, &r->Z, zz2 );
  fd_bn254_fp2_mul( &r->Z, &r->Z, h );
  return r;
}

/* fd_bn254_g2_scalar_mul computes r = s * p.
   This assumes that p is affine, i.e. p->Z==1. */
fd_bn254_g2_t *
fd_bn254_g2_scalar_mul( fd_bn254_g2_t *           r,
                        fd_bn254_g2_t const *     p,
                        fd_bn254_scalar_t const * s ) {
  /* TODO: wNAF, GLV */
  int i = 255;
  for( ; i>=0 && !fd_uint256_bit( s, i ); i-- ) ; /* do nothing, just i-- */
  if( FD_UNLIKELY( i<0 ) ) {
    return fd_bn254_g2_set_zero( r );
  }
  fd_bn254_g2_set( r, p );
  for( i--; i>=0; i-- ) {
    fd_bn254_g2_dbl( r, r );
    if( fd_uint256_bit( s, i ) ) {
      fd_bn254_g2_add_mixed( r, r, p );
    }
  }
  return r;
}

/* fd_bn254_g2_frombytes_internal extracts (x, y) and performs basic checks.
   This is used by fd_bn254_g2_compress() and fd_bn254_g2_frombytes_check_subgroup(). */
static inline fd_bn254_g2_t *
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

/* fd_bn254_g2_frombytes_check_subgroup performs frombytes AND checks subgroup membership. */
static inline fd_bn254_g2_t *
fd_bn254_g2_frombytes_check_subgroup( fd_bn254_g2_t * p,
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
