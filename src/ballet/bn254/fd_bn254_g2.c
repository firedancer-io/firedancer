#include "./fd_bn254_g2_inl.h"

/* G2 */

/* COV: unlike g1, g2 operations are not exposed to users.
   So many edge cases and checks for zero are never triggered, e.g. by syscall tests. */

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
   p MUST not be equal to q, unless p==0.
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

/* fd_bn254_g2_affine_add computes r = p + q.
   Both p, q are affine, i.e. Z==1. */
fd_bn254_g2_t *
fd_bn254_g2_affine_add( fd_bn254_g2_t *       r,
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

  fd_bn254_fp2_t lambda[1], x[1], y[1];

  /* same X, either the points are equal or opposite */
  if( fd_bn254_fp2_eq( &p->X, &q->X ) ) {
    if( fd_bn254_fp2_eq( &p->Y, &q->Y ) ) {
      /* p==q => point double: lambda = 3 * x1^2 / (2 * y1) */
      fd_bn254_fp2_sqr( x, &p->X ); /* x =   x1^2 */
      fd_bn254_fp2_add( y, x, x );  /* y = 2 x1^2 */
      fd_bn254_fp2_add( x, x, y );  /* x = 3 x1^2 */
      fd_bn254_fp2_add( y, &p->Y, &p->Y );
      fd_bn254_fp2_inv( lambda, y );
      fd_bn254_fp2_mul( lambda, lambda, x );
    } else {
      /* p==-q => r=0 */
      return fd_bn254_g2_set_zero( r );
    }
  } else {
    /* point add: lambda = (y1 - y2) / (x1 - x2) */
    fd_bn254_fp2_sub( x, &p->X, &q->X );
    fd_bn254_fp2_sub( y, &p->Y, &q->Y );
    fd_bn254_fp2_inv( lambda, x );
    fd_bn254_fp2_mul( lambda, lambda, y );
  }

  /* x3 = lambda^2 - x1 - x2 */
  fd_bn254_fp2_sqr( x, lambda );
  fd_bn254_fp2_sub( x, x, &p->X );
  fd_bn254_fp2_sub( x, x, &q->X );

  /* y3 = lambda * (x1 - x3) - y1 */
  fd_bn254_fp2_sub( y, &p->X, x );
  fd_bn254_fp2_mul( y, y, lambda );
  fd_bn254_fp2_sub( y, y, &p->Y );

  fd_bn254_fp2_set( &r->X, x );
  fd_bn254_fp2_set( &r->Y, y );
  fd_bn254_fp2_set_one( &r->Z );
  return r;
}
