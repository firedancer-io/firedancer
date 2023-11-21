#include "fd_ristretto255_ge.h"
#include "fd_ristretto255_ge_private.h"

fd_ed25519_ge_p3_t *
fd_ristretto255_ge_frombytes_vartime( fd_ed25519_ge_p3_t * h,
                                      uchar const          s_[ static 32 ] ) {
  fd_ed25519_fe_t s[1];
  fd_ed25519_fe_frombytes( s, s_ );

  uchar s_check[ 32 ];
  fd_ed25519_fe_tobytes( s_check, s );

  /* TODO use constant time equal */
  if( FD_UNLIKELY( ( 0==fd_memeq( s_, s_check, 32UL ) )
                 | ( fd_ed25519_fe_isnegative( s ) ) ) )
    return NULL;

  fd_ed25519_fe_t ss[1]; /* ss = s^2 */
  fd_ed25519_fe_sq( ss, s );

  fd_ed25519_fe_t u1[1]; /* u1 = 1 - ss */
  fd_ed25519_fe_t u2[1]; /* u2 = 1 + ss */
  fd_ed25519_fe_1( u1 ); fd_ed25519_fe_sub( u1, u1, ss );
  fd_ed25519_fe_1( u2 ); fd_ed25519_fe_add( u2, u2, ss );

  fd_ed25519_fe_t u2sq[1]; /* u2_sqr = u2^2 */
  fd_ed25519_fe_sq( u2sq, u2 );

  /* v = -(D * u1^2) - u2_sqr */

  fd_ed25519_fe_t v[1];
  fd_ed25519_fe_sq ( v, u1          );
  fd_ed25519_fe_mul( v, v, f25519_d );
  fd_ed25519_fe_neg( v, v           );
  fd_ed25519_fe_sub( v, v, u2sq     );

  /* (was_square, inv_sq) = SQRT_RATIO_M1(1, v * u2_sqr) */

  fd_ed25519_fe_t tmp0[1]; fd_ed25519_fe_t tmp1[1];
  fd_ed25519_fe_1  ( tmp0 );
  fd_ed25519_fe_mul( tmp1, v, u2sq );

  fd_ed25519_fe_t inv_sq[1];
  int was_square = fd_ed25519_fe_sqrt_ratio( inv_sq, tmp0, tmp1 );

  fd_ed25519_fe_t den_x[1];  /* den_x = inv_sq * u2 */
  fd_ed25519_fe_t den_y[1];  /* den_y = inv_sq * den_x * v */
  fd_ed25519_fe_mul( den_x, inv_sq, u2    );
  fd_ed25519_fe_mul( den_y, inv_sq, den_x );
  fd_ed25519_fe_mul( den_y, den_y,  v     );

  /* x = CT_ABS(2 * s * den_x) */
  fd_ed25519_fe_2  ( tmp0 );
  fd_ed25519_fe_mul( tmp0, tmp0, s     );
  fd_ed25519_fe_mul( tmp0, tmp0, den_x );
  fd_ed25519_fe_abs( h->X, tmp0        );
  /* y = u1 * den_y */
  fd_ed25519_fe_mul( h->Y, u1, den_y   );
  /* z = 1 */
  fd_ed25519_fe_1  ( h->Z             );
  /* t = x * y */
  fd_ed25519_fe_mul( h->T, h->X, h->Y  );

  if( (!was_square )
    | ( fd_ed25519_fe_isnegative( h->T ) )
    | (!fd_ed25519_fe_isnonzero ( h->Y ) ) )
    return NULL;

  return h;
}

uchar *
fd_ristretto255_ge_tobytes( uchar *                    b,
                            fd_ed25519_ge_p3_t const * h ) {

  /* u1 = (z0 + y0) * (z0 - y0) */
  fd_ed25519_fe_t tmp0 [1]; fd_ed25519_fe_add( tmp0, h->Z, h->Y );
  fd_ed25519_fe_t tmp1 [1]; fd_ed25519_fe_sub( tmp1, h->Z, h->Y );
  fd_ed25519_fe_t u1   [1]; fd_ed25519_fe_mul( u1,   tmp0, tmp1 );

  /* u2 = (x0 * y0) */
  fd_ed25519_fe_t u2   [1]; fd_ed25519_fe_mul( u2, h->X, h->Y );

  /* invsqrt = SQRT_RATIO_M1(1, u1 * u2^2) */
  fd_ed25519_fe_t u2_sq[1]; fd_ed25519_fe_sq( u2_sq, u2 );
  fd_ed25519_fe_mul( tmp1, u1, u2_sq );
  fd_ed25519_fe_t inv_sqrt[1];
  fd_ed25519_fe_inv_sqrt( inv_sqrt, tmp1 );

  /* den1 = invsqrt * u1
     den2 = invsqrt * u2 */
  fd_ed25519_fe_t den1[1]; fd_ed25519_fe_mul( den1, inv_sqrt, u1 );
  fd_ed25519_fe_t den2[1]; fd_ed25519_fe_mul( den2, inv_sqrt, u2 );

  /* z_inv = den1 * den2 * t0 */
  fd_ed25519_fe_t z_inv[1];
  fd_ed25519_fe_mul( z_inv, den1,  den2 );
  fd_ed25519_fe_mul( z_inv, z_inv, h->T );

  /* ix0 = x0 * SQRT_M1
     iy0 = y0 * SQRT_M1 */
  fd_ed25519_fe_t ix0[1]; fd_ed25519_fe_mul( ix0, h->X, f25519_sqrtm1 );
  fd_ed25519_fe_t iy0[1]; fd_ed25519_fe_mul( iy0, h->Y, f25519_sqrtm1 );

  /* enchanted_denominator = den1 * INVSQRT_A_MINUS_D */
  fd_ed25519_fe_t enchanted_denominator[1];
  fd_ed25519_fe_mul( enchanted_denominator, den1, f25519_invsqrt_a_minus_d );

  /* rotate = IS_NEGATIVE(t0 * z_inv) */
  fd_ed25519_fe_t rotate_[1]; fd_ed25519_fe_mul( rotate_, h->T, z_inv );
  int rotate = fd_ed25519_fe_isnegative( rotate_ );

  /* x = CT_SELECT(iy0 IF rotate ELSE x0)
     y = CT_SELECT(ix0 IF rotate ELSE y0) */
  fd_ed25519_fe_t x[1]; fd_ed25519_fe_if( x, rotate, iy0, h->X );
  fd_ed25519_fe_t y[1]; fd_ed25519_fe_if( y, rotate, ix0, h->Y );
  /* z = z0 */
  fd_ed25519_fe_t z[1]; fd_ed25519_fe_copy( z, h->Z );
  /* den_inv = CT_SELECT(enchanted_denominator IF rotate ELSE den2) */
  fd_ed25519_fe_t den_inv[1];
  fd_ed25519_fe_if( den_inv, rotate, enchanted_denominator, den2 );

  /* y = CT_NEG(y, IS_NEGATIVE(x * z_inv)) */
  fd_ed25519_fe_t isneg_[1]; fd_ed25519_fe_mul( isneg_, x, z_inv );
  int isneg = fd_ed25519_fe_isnegative( isneg_ );
  fd_ed25519_fe_t y_neg[1]; fd_ed25519_fe_neg( y_neg, y );
  fd_ed25519_fe_if( y, isneg, y_neg, y );

  /* s = CT_ABS(den_inv * (z - y)) */
  fd_ed25519_fe_t s[1];
  fd_ed25519_fe_sub( s, z, y       );
  fd_ed25519_fe_mul( s, s, den_inv );
  fd_ed25519_fe_abs( s, s          );

  fd_ed25519_fe_tobytes( b, s );
  return b;
}

/* Elligator2 map to ristretto group:
   https://ristretto.group/formulas/elligator.html
   This follows closely the golang implementation:
   https://github.com/gtank/ristretto255/blob/v0.1.2/ristretto255.go#L88 */
fd_ristretto255_point_t *
fd_ristretto255_map_to_curve( fd_ristretto255_point_t * h_,
                              uchar const               t[ static 32 ] ) {
  fd_ed25519_ge_p3_t * h = fd_type_pun( h_ );

  /* r = SQRT_M1 * t^2 */
  fd_ed25519_fe_t r0[1];
  fd_ed25519_fe_t r[1];
  fd_ed25519_fe_frombytes( r0, t );
  fd_ed25519_fe_mul( r, f25519_sqrtm1, fd_ed25519_fe_sq( r, r0 ) );

  /* u = (r + 1) * ONE_MINUS_D_SQ */
  fd_ed25519_fe_t u[1];
  fd_ed25519_fe_add( u, r, f25519_one );
  // fd_ed25519_fe_mul( u, u, one_minus_d_sq ); -> using mul2

  /* c = -1 */
  fd_ed25519_fe_t c[1] = {{
    { -1, 0, 0, 0, 0, 0, 0, 0, 0, 0 }
  }};
  // fd_ed25519_fe_neg( c, one );

  /* v = (c - r*D) * (r + D) */
  fd_ed25519_fe_t v[1], r_plus_d[1];
  fd_ed25519_fe_add( r_plus_d, r, f25519_d );
  // fd_ed25519_fe_mul( v, r, d ); -> using mul2
  fd_ed25519_fe_mul2( v,r,f25519_d, u,u,f25519_one_minus_d_sq );
  fd_ed25519_fe_sub( v, c, v );
  fd_ed25519_fe_mul( v, v, r_plus_d );

  /* (was_square, s) = SQRT_RATIO_M1(u, v) */
  fd_ed25519_fe_t s[1];
  int was_square = fd_ed25519_fe_sqrt_ratio( s, u, v );

  /* s_prime = -CT_ABS(s*r0) */
  fd_ed25519_fe_t s_prime[1];
  fd_ed25519_fe_neg_abs( s_prime, fd_ed25519_fe_mul( s_prime, s, r0 ) );

	/* s = CT_SELECT(s IF was_square ELSE s_prime) */
  fd_ed25519_fe_if( s, was_square, s, s_prime );
	/* c = CT_SELECT(c IF was_square ELSE r) */
  fd_ed25519_fe_if( c, was_square, c, r );

  /* N = c * (r - 1) * D_MINUS_ONE_SQ - v */
  fd_ed25519_fe_t n[1];
  fd_ed25519_fe_mul( n, c, fd_ed25519_fe_sub( n, r, f25519_one ) );
  fd_ed25519_fe_sub( n, fd_ed25519_fe_mul( n, n, f25519_d_minus_one_sq ), v );

  /* w0 = 2 * s * v
     w1 = N * SQRT_AD_MINUS_ONE
     w2 = 1 - s^2
     w3 = 1 + s^2 */
  fd_ed25519_fe_t s2[1];
  fd_ed25519_fe_sq( s2, s );
  fd_ed25519_fe_t w0[1], w1[1], w2[1], w3[1];
  fd_ed25519_fe_mul2( w0,s,v, w1,n,f25519_sqrt_ad_minus_one );
  fd_ed25519_fe_add( w0, w0, w0 );
  // fd_ed25519_fe_mul( w1, n, sqrt_ad_minus_one );
  fd_ed25519_fe_sub( w2, f25519_one, s2 );
  fd_ed25519_fe_add( w3, f25519_one, s2 );

  // fd_ed25519_fe_mul( h->X, w0, w3 );
  // fd_ed25519_fe_mul( h->Y, w2, w1 );
  // fd_ed25519_fe_mul( h->Z, w1, w3 );
  // fd_ed25519_fe_mul( h->T, w0, w2 );
  fd_ed25519_fe_mul4( h->X,w0,w3, h->Y,w2,w1, h->Z,w1,w3, h->T,w0,w2 );
  return h_;
}

fd_ristretto255_point_t *
fd_ristretto255_hash_to_curve( fd_ristretto255_point_t * h,
                               uchar const               s[ static 64 ] ) {
  fd_ristretto255_point_t p1[1];
  fd_ristretto255_point_t p2[1];

  fd_ristretto255_map_to_curve( p1, s    );
  fd_ristretto255_map_to_curve( p2, s+32 );

  return fd_ristretto255_point_add(h, p1, p2);
}

void
fd_ristretto255_map_to_curve_4( fd_ristretto255_point_t * ha_,
                                uchar const               ta[ static 32 ],
                                fd_ristretto255_point_t * hb_,
                                uchar const               tb[ static 32 ],
                                fd_ristretto255_point_t * hc_,
                                uchar const               tc[ static 32 ],
                                fd_ristretto255_point_t * hd_,
                                uchar const               td[ static 32 ] ) {
  fd_ed25519_ge_p3_t * ha = fd_type_pun( ha_ );
  fd_ed25519_ge_p3_t * hb = fd_type_pun( hb_ );
  fd_ed25519_ge_p3_t * hc = fd_type_pun( hc_ );
  fd_ed25519_ge_p3_t * hd = fd_type_pun( hd_ );

  /* r = SQRT_M1 * t^2 */
  fd_ed25519_fe_t r0a[1], r0b[1], r0c[1], r0d[1];
  fd_ed25519_fe_t ra[1], rb[1], rc[1], rd[1];
  fd_ed25519_fe_frombytes( r0a, ta );
  fd_ed25519_fe_frombytes( r0b, tb );
  fd_ed25519_fe_frombytes( r0c, tc );
  fd_ed25519_fe_frombytes( r0d, td );
  fd_ed25519_fe_sqn4( ra,r0a,1L, rb,r0b,1L, rc,r0c,1L, rd,r0d,1L );
  /* TODO(ec): this can be made more efficient */
  fd_ed25519_fe_mul4( ra,ra,f25519_sqrtm1, rb,rb,f25519_sqrtm1, rc,rc,f25519_sqrtm1, rd,rd,f25519_sqrtm1 );

  /* u = (r + 1) * ONE_MINUS_D_SQ */
  fd_ed25519_fe_t ua[1], ub[1], uc[1], ud[1];
  fd_ed25519_fe_add( ua, ra, f25519_one );
  fd_ed25519_fe_add( ub, rb, f25519_one );
  fd_ed25519_fe_add( uc, rc, f25519_one );
  fd_ed25519_fe_add( ud, rd, f25519_one );
  fd_ed25519_fe_mul4( ua,ua,f25519_one_minus_d_sq, ub,ub,f25519_one_minus_d_sq,
                      uc,uc,f25519_one_minus_d_sq, ud,ud,f25519_one_minus_d_sq );

  /* c = -1
     note that c is overwritten later, hence we need 4 */
  fd_ed25519_fe_t ca[1] = {{
    { -1, 0, 0, 0, 0, 0, 0, 0, 0, 0 }
  }};
  fd_ed25519_fe_t cb[1] = {{
    { -1, 0, 0, 0, 0, 0, 0, 0, 0, 0 }
  }};
  fd_ed25519_fe_t cc[1] = {{
    { -1, 0, 0, 0, 0, 0, 0, 0, 0, 0 }
  }};
  fd_ed25519_fe_t cd[1] = {{
    { -1, 0, 0, 0, 0, 0, 0, 0, 0, 0 }
  }};
  // fd_ed25519_fe_neg( c, one );

  /* v = (c - r*D) * (r + D) */
  fd_ed25519_fe_t va[1], vb[1], vc[1], vd[1];
  fd_ed25519_fe_t d_plus_ra[1], d_plus_rb[1], d_plus_rc[1], d_plus_rd[1];
  fd_ed25519_fe_add( d_plus_ra, ra, f25519_d );
  fd_ed25519_fe_add( d_plus_rb, rb, f25519_d );
  fd_ed25519_fe_add( d_plus_rc, rc, f25519_d );
  fd_ed25519_fe_add( d_plus_rd, rd, f25519_d );
  fd_ed25519_fe_mul4( va,ra,f25519_d, vb,rb,f25519_d, vc,rc,f25519_d, vd,rd,f25519_d );
  fd_ed25519_fe_sub( va, ca, va );
  fd_ed25519_fe_sub( vb, cb, vb );
  fd_ed25519_fe_sub( vc, cc, vc );
  fd_ed25519_fe_sub( vd, cd, vd );
  fd_ed25519_fe_mul4( va,va,d_plus_ra, vb,vb,d_plus_rb, vc,vc,d_plus_rc, vd,vd,d_plus_rd );

  /* (was_square, s) = SQRT_RATIO_M1(u, v) */
  fd_ed25519_fe_t sa[1], sb[1], sc[1], sd[1];
  // int was_square = fd_ed25519_fe_sqrt_ratio( s, u, v );
  int wsa, wsb, wsc, wsd;
  fd_ed25519_fe_sqrt_ratio_4( sa,&wsa,ua,va, sb,&wsb,ub,vb, sc,&wsc,uc,vc, sd,&wsd,ud,vd );

  /* s_prime = -CT_ABS(s*r0) */
  fd_ed25519_fe_t sa_prime[1], sb_prime[1], sc_prime[1], sd_prime[1];
  fd_ed25519_fe_mul4( sa_prime,sa,r0a, sb_prime,sb,r0b, sc_prime,sc,r0c, sd_prime,sd,r0d );
  fd_ed25519_fe_neg_abs( sa_prime, sa_prime );
  fd_ed25519_fe_neg_abs( sb_prime, sb_prime );
  fd_ed25519_fe_neg_abs( sc_prime, sc_prime );
  fd_ed25519_fe_neg_abs( sd_prime, sd_prime );

	/* s = CT_SELECT(s IF was_square ELSE s_prime) */
  fd_ed25519_fe_if( sa, wsa, sa, sa_prime );
  fd_ed25519_fe_if( sb, wsb, sb, sb_prime );
  fd_ed25519_fe_if( sc, wsc, sc, sc_prime );
  fd_ed25519_fe_if( sd, wsd, sc, sd_prime );
	/* c = CT_SELECT(c IF was_square ELSE r) */
  fd_ed25519_fe_if( ca, wsa, ca, ra );
  fd_ed25519_fe_if( cb, wsb, cb, rb );
  fd_ed25519_fe_if( cc, wsc, cc, rc );
  fd_ed25519_fe_if( cd, wsd, cd, rd );

  /* N = c * (r - 1) * D_MINUS_ONE_SQ - v */
  fd_ed25519_fe_t na[1], nb[1], nc[1], nd[1];
  fd_ed25519_fe_sub( na, ra, f25519_one );
  fd_ed25519_fe_sub( nb, rb, f25519_one );
  fd_ed25519_fe_sub( nc, rc, f25519_one );
  fd_ed25519_fe_sub( nd, rd, f25519_one );
  fd_ed25519_fe_mul4( ca,ca,f25519_d_minus_one_sq, cb,cb,f25519_d_minus_one_sq,
                      cc,cc,f25519_d_minus_one_sq, cd,cd,f25519_d_minus_one_sq );
  fd_ed25519_fe_mul4( na,na,ca, nb,nb,cb, nc,nc,cc, nd,nd,cd );
  fd_ed25519_fe_sub( na, na, va );
  fd_ed25519_fe_sub( nb, nb, vb );
  fd_ed25519_fe_sub( nc, nc, vc );
  fd_ed25519_fe_sub( nd, nd, vd );

  /* w0 = 2 * s * v
     w1 = N * SQRT_AD_MINUS_ONE
     w2 = 1 - s^2
     w3 = 1 + s^2 */
  fd_ed25519_fe_t s2a[1], s2b[1], s2c[1], s2d[1];
  fd_ed25519_fe_sqn4( s2a,sa,1L, s2b,sb,1L, s2c,sc,1L, s2d,sd,1L );
  fd_ed25519_fe_t w0a[1], w1a[1], w2a[1], w3a[1];
  fd_ed25519_fe_t w0b[1], w1b[1], w2b[1], w3b[1];
  fd_ed25519_fe_t w0c[1], w1c[1], w2c[1], w3c[1];
  fd_ed25519_fe_t w0d[1], w1d[1], w2d[1], w3d[1];
  fd_ed25519_fe_mul4( w0a,sa,va, w0b,sb,vb, w0c,sc,vc, w0d,sd,vd );
  fd_ed25519_fe_add( w0a, w0a, w0a );
  fd_ed25519_fe_add( w0b, w0b, w0b );
  fd_ed25519_fe_add( w0c, w0c, w0c );
  fd_ed25519_fe_add( w0d, w0d, w0d );
  fd_ed25519_fe_mul4( w1a,na,f25519_sqrt_ad_minus_one, w1b,nb,f25519_sqrt_ad_minus_one,
                      w1c,nc,f25519_sqrt_ad_minus_one, w1d,nd,f25519_sqrt_ad_minus_one );
  fd_ed25519_fe_sub( w2a, f25519_one, s2a );
  fd_ed25519_fe_sub( w2b, f25519_one, s2b );
  fd_ed25519_fe_sub( w2c, f25519_one, s2c );
  fd_ed25519_fe_sub( w2d, f25519_one, s2d );
  fd_ed25519_fe_add( w3a, f25519_one, s2a );
  fd_ed25519_fe_add( w3b, f25519_one, s2b );
  fd_ed25519_fe_add( w3c, f25519_one, s2c );
  fd_ed25519_fe_add( w3d, f25519_one, s2d );

  fd_ed25519_fe_mul4( ha->X,w0a,w3a, ha->Y,w2a,w1a, ha->Z,w1a,w3a, ha->T,w0a,w2a );
  fd_ed25519_fe_mul4( hb->X,w0b,w3b, hb->Y,w2b,w1b, hb->Z,w1b,w3b, hb->T,w0b,w2b );
  fd_ed25519_fe_mul4( hc->X,w0c,w3c, hc->Y,w2c,w1c, hc->Z,w1c,w3c, hc->T,w0c,w2c );
  fd_ed25519_fe_mul4( hd->X,w0d,w3d, hd->Y,w2d,w1d, hd->Z,w1d,w3d, hd->T,w0d,w2d );
}
