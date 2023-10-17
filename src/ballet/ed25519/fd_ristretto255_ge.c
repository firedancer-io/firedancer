#include "fd_ristretto255_ge.h"
#include "fd_ristretto255_ge_private.h"

fd_ed25519_ge_p3_t *
fd_ristretto255_ge_frombytes_vartime( fd_ed25519_ge_p3_t * h,
                                      uchar const          s_[ static 32 ] ) {

  static const fd_ed25519_fe_t d[1] = {{
    { -10913610, 13857413, -15372611, 6949391, 114729, -8787816, -6275908, -3247719, -18696448, -12055116 }
  }};

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
  fd_ed25519_fe_sq ( v, u1      );
  fd_ed25519_fe_mul( v, v, d    );
  fd_ed25519_fe_neg( v, v       );
  fd_ed25519_fe_sub( v, v, u2sq );

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

  static const fd_ed25519_fe_t sqrtm1[1] = {{
    { -32595792, -7943725, 9377950, 3500415, 12389472, -272473, -25146209, -2005654, 326686, 11406482 }
  }};

  static const fd_ed25519_fe_t invsqrt_a_minus_d[1] = {{
    { 6111466, 4156064, 39310137, 12243467, 41204824, 120896, 20826367, 26493656, 6093567, 31568420 }
  }};

  /* u1 = (z0 + y0) * (z0 - y0) */
  fd_ed25519_fe_t tmp0 [1]; fd_ed25519_fe_add( tmp0, h->Z, h->Y );
  fd_ed25519_fe_t tmp1 [1]; fd_ed25519_fe_sub( tmp1, h->Z, h->Y );
  fd_ed25519_fe_t u1   [1]; fd_ed25519_fe_mul( u1,   tmp0, tmp1 );

  /* u2 = (x0 * y0) */
  fd_ed25519_fe_t u2   [1]; fd_ed25519_fe_mul( u2, h->X, h->Y );

  /* invsqrt = SQRT_RATIO_M1(1, u1 * u2^2) */
  fd_ed25519_fe_t u2_sq[1]; fd_ed25519_fe_sq( u2_sq, u2 );
  fd_ed25519_fe_1  ( tmp0 );
  fd_ed25519_fe_mul( tmp1, u1, u2_sq );
  fd_ed25519_fe_t inv_sqrt[1];
  fd_ed25519_fe_sqrt_ratio( inv_sqrt, tmp0, tmp1 );

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
  fd_ed25519_fe_t ix0[1]; fd_ed25519_fe_mul( ix0, h->X, sqrtm1 );
  fd_ed25519_fe_t iy0[1]; fd_ed25519_fe_mul( iy0, h->Y, sqrtm1 );

  /* enchanted_denominator = den1 * INVSQRT_A_MINUS_D */
  fd_ed25519_fe_t enchanted_denominator[1];
  fd_ed25519_fe_mul( enchanted_denominator, den1, invsqrt_a_minus_d );

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

fd_ristretto255_point_t *
fd_ristretto255_point_decompress( fd_ristretto255_point_t * h_,
                                  uchar const               s[ static 32 ] ) {
  fd_ed25519_ge_p3_t * h = fd_type_pun( h_ );
  return fd_type_pun( fd_ristretto255_ge_frombytes_vartime( h, s ) );
}

uchar *
fd_ristretto255_point_compress( uchar                           s[ static 32 ],
                                fd_ristretto255_point_t const * f_ ) {
  fd_ed25519_ge_p3_t const * f = fd_type_pun_const( f_ );
  return fd_ristretto255_ge_tobytes( s, f );
}
