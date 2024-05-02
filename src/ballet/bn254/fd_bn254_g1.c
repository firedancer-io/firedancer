#include "./fd_bn254.h"

/* G1 */

static inline int
fd_bn254_g1_is_zero( fd_bn254_g1_t const * p ) {
  return fd_bn254_fp_is_zero( &p->Z );
}

static inline fd_bn254_g1_t *
fd_bn254_g1_set( fd_bn254_g1_t *       r,
                 fd_bn254_g1_t const * p ) {
  fd_bn254_fp_set( &r->X, &p->X );
  fd_bn254_fp_set( &r->Y, &p->Y );
  fd_bn254_fp_set( &r->Z, &p->Z );
  return r;
}

static inline fd_bn254_g1_t *
fd_bn254_g1_set_zero( fd_bn254_g1_t * r ) {
  // fd_bn254_fp_set_zero( &r->X );
  // fd_bn254_fp_set_zero( &r->Y );
  fd_bn254_fp_set_zero( &r->Z );
  return r;
}

static inline fd_bn254_g1_t *
fd_bn254_g1_to_affine( fd_bn254_g1_t *       r,
                       fd_bn254_g1_t const * p ) {
  if( FD_UNLIKELY( fd_bn254_fp_is_zero( &p->Z ) || fd_bn254_fp_is_one( &p->Z ) ) ) {
    return fd_bn254_g1_set( r, p );
  }

  fd_bn254_fp_t iz[1], iz2[1];
  fd_bn254_fp_inv( iz, &p->Z );
  fd_bn254_fp_sqr( iz2, iz );

  /* X / Z^2, Y / Z^3 */
  fd_bn254_fp_mul( &r->X, &p->X, iz2 );
  fd_bn254_fp_mul( &r->Y, &p->Y, iz2 );
  fd_bn254_fp_mul( &r->Y, &r->Y, iz );
  fd_bn254_fp_set_one( &r->Z );
  return r;
}

uchar *
fd_bn254_g1_tobytes( uchar                 out[64],
                     fd_bn254_g1_t const * p ) {
  if( FD_UNLIKELY( fd_bn254_g1_is_zero( p ) ) ) {
    fd_memset( out, 0, 64UL );
    /* no flags */
    return out;
  }

  fd_bn254_g1_t r[1];
  fd_bn254_g1_to_affine( r, p );

  fd_bn254_fp_from_mont( &r->X, &r->X );
  fd_bn254_fp_from_mont( &r->Y, &r->Y );

  fd_bn254_fp_tobytes_be_nm( &out[ 0], &r->X );
  fd_bn254_fp_tobytes_be_nm( &out[32], &r->Y );
  /* no flags */
  return out;
}

/* fd_bn254_g1_affine_add computes r = p + q.
   Both p, q are affine, i.e. Z==1. */
fd_bn254_g1_t *
fd_bn254_g1_affine_add( fd_bn254_g1_t *       r,
                        fd_bn254_g1_t const * p,
                        fd_bn254_g1_t const * q ) {
  /* p==0, return q */
  if( FD_UNLIKELY( fd_bn254_g1_is_zero( p ) ) ) {
    return fd_bn254_g1_set( r, q );
  }
  /* q==0, return p */
  if( FD_UNLIKELY( fd_bn254_g1_is_zero( q ) ) ) {
    return fd_bn254_g1_set( r, p );
  }

  fd_bn254_fp_t lambda[1], x[1], y[1];

  /* same X, either the points are equal or opposite */
  if( fd_bn254_fp_eq( &p->X, &q->X ) ) {
    if( fd_bn254_fp_eq( &p->Y, &q->Y ) ) {
      /* p==q => point double: lambda = 3 * x1^2 / (2 * y1) */
      fd_bn254_fp_sqr( x, &p->X ); /* x =   x1^2 */
      fd_bn254_fp_add( y, x, x );  /* y = 2 x1^2 */
      fd_bn254_fp_add( x, x, y );  /* x = 3 x1^2 */
      fd_bn254_fp_add( y, &p->Y, &p->Y );
      fd_bn254_fp_inv( lambda, y );
      fd_bn254_fp_mul( lambda, lambda, x );
    } else {
      /* p==-q => r=0 */
      return fd_bn254_g1_set_zero( r );
    }
  } else {
    /* point add: lambda = (y1 - y2) / (x1 - x2) */
    fd_bn254_fp_sub( x, &p->X, &q->X );
    fd_bn254_fp_sub( y, &p->Y, &q->Y );
    fd_bn254_fp_inv( lambda, x );
    fd_bn254_fp_mul( lambda, lambda, y );
  }

  /* x3 = lambda^2 - x1 - x2 */
  fd_bn254_fp_sqr( x, lambda );
  fd_bn254_fp_sub( x, x, &p->X );
  fd_bn254_fp_sub( x, x, &q->X );

  /* y3 = lambda * (x1 - x3) - y1 */
  fd_bn254_fp_sub( y, &p->X, x );
  fd_bn254_fp_mul( y, y, lambda );
  fd_bn254_fp_sub( y, y, &p->Y );

  fd_bn254_fp_set( &r->X, x );
  fd_bn254_fp_set( &r->Y, y );
  fd_bn254_fp_set_one( &r->Z );
  return r;
}

/* fd_bn254_g1_dbl computes r = 2p.
   https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#doubling-dbl-2007-bl */
fd_bn254_g1_t *
fd_bn254_g1_dbl( fd_bn254_g1_t *       r,
                 fd_bn254_g1_t const * p ) {
  /* p==0, return 0 */
  if( FD_UNLIKELY( fd_bn254_g1_is_zero( p ) ) ) {
    return fd_bn254_g1_set_zero( r );
  }

  fd_bn254_fp_t xx[1], yy[1], zz[1];
  fd_bn254_fp_t y4[1], s[1], m[1];
  /* XX = X1^2 */
  fd_bn254_fp_sqr( xx, &p->X );
  /* YY = Y1^2 */
  fd_bn254_fp_sqr( yy, &p->Y );
  /* YYYY = YY^2 */
  fd_bn254_fp_sqr( y4, yy );
  /* ZZ = Z1^2 */
  fd_bn254_fp_sqr( zz, &p->Z );
  /* S = 2*((X1+YY)^2-XX-YYYY) */
  fd_bn254_fp_add( s, &p->X, yy );
  fd_bn254_fp_sqr( s, s );
  fd_bn254_fp_sub( s, s, xx );
  fd_bn254_fp_sub( s, s, y4 );
  fd_bn254_fp_add( s, s, s );
  /* M = 3*XX+a*ZZ^2, a=0 */
  fd_bn254_fp_add( m, xx, xx );
  fd_bn254_fp_add( m, m, xx );
  /* T = M^2-2*S
     X3 = T */
  fd_bn254_fp_sqr( &r->X, m );
  fd_bn254_fp_sub( &r->X, &r->X, s );
  fd_bn254_fp_sub( &r->X, &r->X, s );
  /* Z3 = (Y1+Z1)^2-YY-ZZ
     note: compute Z3 before Y3 because it depends on p->Y,
     that might be overwritten if r==p. */
  fd_bn254_fp_add( &r->Z, &p->Z, &p->Y );
  fd_bn254_fp_sqr( &r->Z, &r->Z );
  fd_bn254_fp_sub( &r->Z, &r->Z, yy );
  fd_bn254_fp_sub( &r->Z, &r->Z, zz );
  /* Y3 = M*(S-T)-8*YYYY */
  fd_bn254_fp_sub( &r->Y, s, &r->X );
  fd_bn254_fp_mul( &r->Y, &r->Y, m );
  fd_bn254_fp_add( y4, y4, y4 ); /* 2 y^4 */
  fd_bn254_fp_add( y4, y4, y4 ); /* 4 y^4 */
  fd_bn254_fp_add( y4, y4, y4 ); /* 8 y^4 */
  fd_bn254_fp_sub( &r->Y, &r->Y, y4 );
  return r;
}

/* fd_bn254_g1_add_mixed computes r = p + q, when q->Z==1.
   http://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#addition-madd-2007-bl */
fd_bn254_g1_t *
fd_bn254_g1_add_mixed( fd_bn254_g1_t *       r,
                       fd_bn254_g1_t const * p,
                       fd_bn254_g1_t const * q ) {
  /* p==0, return q */
  if( FD_UNLIKELY( fd_bn254_g1_is_zero( p ) ) ) {
    return fd_bn254_g1_set( r, q );
  }
  fd_bn254_fp_t zz[1], u2[1], s2[1];
  fd_bn254_fp_t h[1], hh[1];
  fd_bn254_fp_t i[1], j[1];
  fd_bn254_fp_t rr[1], v[1];
  /* Z1Z1 = Z1^2 */
  fd_bn254_fp_sqr( zz, &p->Z );
  /* U2 = X2*Z1Z1 */
  fd_bn254_fp_mul( u2, &q->X, zz );
  /* S2 = Y2*Z1*Z1Z1 */
  fd_bn254_fp_mul( s2, &q->Y, &p->Z );
  fd_bn254_fp_mul( s2, s2, zz );

  /* if p==q, call fd_bn254_g1_dbl */
  if( FD_UNLIKELY( fd_bn254_fp_eq( u2, &p->X ) && fd_bn254_fp_eq( s2, &p->Y ) ) ) {
    return fd_bn254_g1_dbl( r, p );
  }

  /* H = U2-X1 */
  fd_bn254_fp_sub( h, u2, &p->X );
  /* HH = H^2 */
  fd_bn254_fp_sqr( hh, h );
  /* I = 4*HH */
  fd_bn254_fp_add( i, hh, hh );
  fd_bn254_fp_add( i, i, i );
  /* J = H*I */
  fd_bn254_fp_mul( j, h, i );
  /* r = 2*(S2-Y1) */
  fd_bn254_fp_sub( rr, s2, &p->Y );
  fd_bn254_fp_add( rr, rr, rr );
  /* V = X1*I */
  fd_bn254_fp_mul( v, &p->X, i );
  /* X3 = r^2-J-2*V */
  fd_bn254_fp_sqr( &r->X, rr );
  fd_bn254_fp_sub( &r->X, &r->X, j );
  fd_bn254_fp_sub( &r->X, &r->X, v );
  fd_bn254_fp_sub( &r->X, &r->X, v );
  /* Y3 = r*(V-X3)-2*Y1*J
     note: i no longer used */
  fd_bn254_fp_mul( i, &p->Y, j ); /* i =   Y1*J */
  fd_bn254_fp_add( i, i, i );     /* i = 2*Y1*J */
  fd_bn254_fp_sub( &r->Y, v, &r->X );
  fd_bn254_fp_mul( &r->Y, &r->Y, rr );
  fd_bn254_fp_sub( &r->Y, &r->Y, i );
  /* Z3 = (Z1+H)^2-Z1Z1-HH */
  fd_bn254_fp_add( &r->Z, &p->Z, h );
  fd_bn254_fp_sqr( &r->Z, &r->Z );
  fd_bn254_fp_sub( &r->Z, &r->Z, zz );
  fd_bn254_fp_sub( &r->Z, &r->Z, hh );
  return r;
}

/* fd_bn254_g1_scalar_mul computes r = s * p.
   This assumes that p is affine, i.e. p->Z==1. */
fd_bn254_g1_t *
fd_bn254_g1_scalar_mul( fd_bn254_g1_t *           r,
                        fd_bn254_g1_t const *     p,
                        fd_bn254_scalar_t const * s ) {
  /* TODO: wNAF, GLV */
  int i = 255;
  for( ; i>=0 && !fd_uint256_bit( s, i ); i-- ) ; /* do nothing, just i-- */
  if( FD_UNLIKELY( i<0 ) ) {
    return fd_bn254_g1_set_zero( r );
  }
  fd_bn254_g1_set( r, p );
  for( i--; i>=0; i-- ) {
    fd_bn254_g1_dbl( r, r );
    if( fd_uint256_bit( s, i ) ) {
      fd_bn254_g1_add_mixed( r, r, p );
    }
  }
  return r;
}

/* fd_bn254_g1_frombytes_internal extracts (x, y) and performs basic checks.
   This is used by fd_bn254_g1_compress() and fd_bn254_g1_frombytes_check_subgroup().
   https://github.com/arkworks-rs/algebra/blob/v0.4.2/ec/src/models/short_weierstrass/mod.rs#L173-L178 */
static inline fd_bn254_g1_t *
fd_bn254_g1_frombytes_internal( fd_bn254_g1_t * p,
                                uchar const     in[64] ) {
  const uchar zero[64] = { 0 };
  if( fd_memeq( in, zero, 64 ) ) return fd_bn254_g1_set_zero( p );

  /* Check x < p */
  if( FD_UNLIKELY( !fd_bn254_fp_frombytes_be_nm( &p->X, in, NULL, NULL ) ) ) {
    return NULL;
  }

  /* Check flags and y < p */
  if( FD_UNLIKELY( !fd_bn254_fp_frombytes_be_nm( &p->Y, in+32, NULL, NULL ) ) ) {
    return NULL;
  }
  //FIXME: add differential test, do we need to check flags on y?
  fd_bn254_fp_set_one( &p->Z );
  return p;
}

/* fd_bn254_g1_frombytes_check_subgroup performs frombytes AND checks subgroup membership. */
static inline fd_bn254_g1_t *
fd_bn254_g1_frombytes_check_subgroup( fd_bn254_g1_t * p,
                                      uchar const     in[64] ) {
  if( FD_UNLIKELY( !fd_bn254_g1_frombytes_internal( p, in ) ) ) return NULL;
  if( FD_UNLIKELY( fd_bn254_g1_is_zero( p ) ) ) return p;

  fd_bn254_fp_to_mont( &p->X, &p->X );
  fd_bn254_fp_to_mont( &p->Y, &p->Y );
  fd_bn254_fp_set_one( &p->Z );

  /* Check that y^2 = x^3 + b */
  fd_bn254_fp_t y2[1], x3b[1];
  fd_bn254_fp_sqr( y2, &p->Y );
  fd_bn254_fp_sqr( x3b, &p->X );
  fd_bn254_fp_mul( x3b, x3b, &p->X );
  fd_bn254_fp_add( x3b, x3b, fd_bn254_const_b_mont );
  if( !fd_bn254_fp_eq( y2, x3b ) ) return NULL;

  /* G1 has prime order, so we don't need to do any further checks. */

  return p;
}
