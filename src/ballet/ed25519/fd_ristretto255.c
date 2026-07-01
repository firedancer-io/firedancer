#include "fd_ristretto255.h"

#define FD_RISTRETTO255_PIPPENGER_THRESHOLD (128UL)
#define FD_RISTRETTO255_PIPPENGER_BATCH_SZ  (1024UL)
#define FD_RISTRETTO255_PIPPENGER_DIGITS    (65UL)
#define FD_RISTRETTO255_PIPPENGER_BUCKETS   (128UL)

fd_ristretto255_point_t *
fd_ristretto255_point_frombytes( fd_ristretto255_point_t * h,
                                 uchar const              buf[ 32 ] ) {
  fd_f25519_t s[1];
  fd_f25519_frombytes( s, buf );

  uchar s_check[ 32 ];
  fd_f25519_tobytes( s_check, s );

  /* we only accept canonical points */
  if( FD_UNLIKELY( ( 0==fd_memeq( buf, s_check, 32UL ) )
                 | ( buf[0] & 1 /*fd_f25519_sgn( s )*/ ) ) ) {
    return NULL;
  }

  fd_f25519_t ss[1]; /* ss = s^2 */
  fd_f25519_sqr( ss, s );

  fd_f25519_t u1[1]; /* u1 = 1 - ss */
  fd_f25519_t u2[1]; /* u2 = 1 + ss */
  fd_f25519_sub( u1, fd_f25519_one, ss );
  fd_f25519_add( u2, fd_f25519_one, ss );

  fd_f25519_t u2sq[1]; /* u2_sqr = u2^2 */
  fd_f25519_sqr( u2sq, u2 );

  /* v = -(D * u1^2) - u2_sqr */

  fd_f25519_t v[1];
  fd_f25519_sqr ( v, u1          );
  fd_f25519_mul( v, v, fd_f25519_d );
  fd_f25519_neg( v, v           );
  fd_f25519_sub( v, v, u2sq     );

  /* (was_square, inv_sq) = SQRT_RATIO_M1(1, v * u2_sqr) */

  fd_f25519_t tmp0[1];
  fd_f25519_t tmp1[1];
  fd_f25519_mul( tmp1, v, u2sq );

  fd_f25519_t inv_sq[1];
  int was_square = fd_f25519_inv_sqrt( inv_sq, tmp1 );

  fd_f25519_t den_x[1];  /* den_x = inv_sq * u2 */
  fd_f25519_t den_y[1];  /* den_y = inv_sq * den_x * v */
  fd_f25519_mul( den_x, inv_sq, u2    );
  fd_f25519_mul( den_y, inv_sq, den_x );
  fd_f25519_mul( den_y, den_y,  v     );

  /* x = CT_ABS(2 * s * den_x) */
  fd_f25519_set( tmp0, fd_f25519_two );
  fd_f25519_mul( tmp0, tmp0, s     );
  fd_f25519_mul( tmp0, tmp0, den_x );
  fd_f25519_t x[1], y[1], t[1];
  fd_f25519_abs( x, tmp0        );
  /* y = u1 * den_y */
  fd_f25519_mul( y, u1, den_y   );
  /* z = 1 */
  /* t = x * y */
  fd_f25519_mul( t, x, y  );

  if( (!was_square )
    | ( fd_f25519_sgn( t ) )
    | ( fd_f25519_is_zero( y ) ) ) {
    return NULL;
  }

  return fd_ed25519_point_from( h, x, y, fd_f25519_one, t );
}

uchar *
fd_ristretto255_point_tobytes( uchar                           buf[ 32 ],
                               fd_ristretto255_point_t const * h ) {
  fd_f25519_t x[1], y[1], z[1], t[1];
  fd_ed25519_point_to( x, y, z, t, h );

  // uchar out[32];
  /* u1 = (z0 + y0) * (z0 - y0) */
  fd_f25519_t tmp0 [1]; fd_f25519_add( tmp0, z, y );
  fd_f25519_t tmp1 [1]; fd_f25519_sub( tmp1, z, y );
  fd_f25519_t u1   [1]; fd_f25519_mul( u1,   tmp0, tmp1 );

  /* u2 = (x0 * y0) */
  fd_f25519_t u2   [1]; fd_f25519_mul( u2, x, y );

  /* invsqrt = SQRT_RATIO_M1(1, u1 * u2^2) */
  fd_f25519_t u2_sq[1]; fd_f25519_sqr( u2_sq, u2 );
  fd_f25519_mul( tmp1, u1, u2_sq );
  fd_f25519_t inv_sqrt[1];
  fd_f25519_inv_sqrt( inv_sqrt, tmp1 );

  // fd_f25519_tobytes( out, inv_sqrt );
  // FD_LOG_HEXDUMP_WARNING(( "inv_sqrt", out, 32 ));

  /* den1 = invsqrt * u1
     den2 = invsqrt * u2 */
  fd_f25519_t den1[1]; fd_f25519_mul( den1, inv_sqrt, u1 );
  fd_f25519_t den2[1]; fd_f25519_mul( den2, inv_sqrt, u2 );

  /* z_inv = den1 * den2 * t0 */
  fd_f25519_t z_inv[1];
  fd_f25519_mul( z_inv, den1,  den2 );
  fd_f25519_mul( z_inv, z_inv, t );

  /* ix0 = x0 * SQRT_M1
     iy0 = y0 * SQRT_M1 */
  fd_f25519_t ix0[1]; fd_f25519_mul( ix0, x, fd_f25519_sqrtm1 );
  fd_f25519_t iy0[1]; fd_f25519_mul( iy0, y, fd_f25519_sqrtm1 );

  /* enchanted_denominator = den1 * INVSQRT_A_MINUS_D */
  fd_f25519_t enchanted_denominator[1];
  fd_f25519_mul( enchanted_denominator, den1, fd_f25519_invsqrt_a_minus_d );

  /* rotate = IS_NEGATIVE(t0 * z_inv) */
  fd_f25519_t rotate_[1]; fd_f25519_mul( rotate_, t, z_inv );
  int rotate = fd_f25519_sgn( rotate_ );
  // FD_LOG_HEXDUMP_WARNING(( "rotate", &rotate, 1 ));

  /* x = CT_SELECT(iy0 IF rotate ELSE x0)
     y = CT_SELECT(ix0 IF rotate ELSE y0) */
  fd_f25519_if( x, rotate, iy0, x );
  fd_f25519_if( y, rotate, ix0, y );

  // fd_f25519_tobytes( out, x );
  // FD_LOG_HEXDUMP_WARNING(( "x", out, 32 ));
  // fd_f25519_tobytes( out, y );
  // FD_LOG_HEXDUMP_WARNING(( "y", out, 32 ));

  /* z = z0 */
  /* den_inv = CT_SELECT(enchanted_denominator IF rotate ELSE den2) */
  fd_f25519_t den_inv[1];
  fd_f25519_if( den_inv, rotate, enchanted_denominator, den2 );
  // fd_f25519_tobytes( out, den_inv );
  // FD_LOG_HEXDUMP_WARNING(( "den_inv", out, 32 ));

  /* y = CT_NEG(y, IS_NEGATIVE(x * z_inv)) */
  fd_f25519_t _isneg[1];
  int isneg = fd_f25519_sgn( fd_f25519_mul( _isneg, x, z_inv ) );
  fd_f25519_t y_neg[1]; fd_f25519_neg( y_neg, y );
  fd_f25519_if( y, isneg, y_neg, y ); // this is not abs (condition is not sgn(y))

  /* s = CT_ABS(den_inv * (z - y)) */
  fd_f25519_t s[1];
  fd_f25519_sub( s, z, y       );
  fd_f25519_mul( s, s, den_inv );
  fd_f25519_abs( s, s );

  fd_f25519_tobytes( buf, s );
  return buf;
}

static void
fd_ristretto255_scalar_radix_2w( schar       digits[ FD_RISTRETTO255_PIPPENGER_DIGITS ],
                                 uchar const s     [ 32 ],
                                 uint        w ) {
  for( ulong i=0UL; i<FD_RISTRETTO255_PIPPENGER_DIGITS; i++ ) digits[i] = (schar)0;

  ulong scalar[4];
  memcpy( scalar, s, 32UL );

  ulong const radix       = 1UL << w;
  ulong const window_mask = radix - 1UL;
  ulong       carry       = 0UL;
  ulong const digit_cnt   = (256UL + (ulong)w - 1UL) / (ulong)w;

  /* Signed radix-2^w: s = sum_i digits[i] 2^(wi), with digits centered near 0. */
  for( ulong i=0UL; i<digit_cnt; i++ ) {
    ulong const bit_off = i * (ulong)w;
    ulong const limb    = bit_off >> 6;
    uint  const bit_idx = (uint)(bit_off & 63UL);

    ulong buffer = scalar[limb] >> bit_idx;
    if( FD_UNLIKELY( (bit_idx + w > 64U) & (limb < 3UL) ) ) {
      buffer |= scalar[limb+1UL] << (64U - bit_idx);
    }

    ulong const coef       = carry + (buffer & window_mask);
    ulong const next_carry = (coef + (radix >> 1)) >> w;
    digits[i] = (schar)((long)coef - (long)(next_carry << w));
    carry = next_carry;
  }

  digits[digit_cnt] = (schar)carry;
}

static fd_ristretto255_point_t *
fd_ristretto255_multi_scalar_mul_pippenger( fd_ristretto255_point_t *      r,
                                            uchar const                    n[], /* sz * 32 */
                                            fd_ristretto255_point_t const  a[], /* sz */
                                            ulong                          sz ) {
  schar digits[ FD_RISTRETTO255_PIPPENGER_BATCH_SZ ][ FD_RISTRETTO255_PIPPENGER_DIGITS ];

  uint const w = (uint)( (sz<700UL) ? 6U : (sz<800UL) ? 7U : 8U );
  ulong const digit_cnt  = ((256UL + (ulong)w - 1UL) / (ulong)w) + 1UL;
  ulong const bucket_cnt = 1UL << (w-1U);

  for( ulong j=0UL; j<sz; j++ ) fd_ristretto255_scalar_radix_2w( digits[j], &n[32UL*j], w );

  fd_ristretto255_point_t buckets[ FD_RISTRETTO255_PIPPENGER_BUCKETS ];
  fd_ristretto255_point_t running[1];
  fd_ristretto255_point_t column [1];

  fd_ristretto255_point_set_zero( r );
  for( ulong fwd=0UL; fwd<digit_cnt; fwd++ ) {
    ulong const digit_idx = digit_cnt - 1UL - fwd;

    /* Horner form over radix 2^w: acc = 2^w acc + current_column. */
    if( fwd ) fd_ed25519_point_dbln( r, r, (int)w );

    for( ulong i=0UL; i<bucket_cnt; i++ ) fd_ristretto255_point_set_zero( &buckets[i] );

    /* Bucket k holds the signed sum of points whose digit has magnitude k+1. */
    for( ulong j=0UL; j<sz; j++ ) {
      int digit = (int)digits[j][digit_idx];
      if( digit>0 ) {
        ulong bucket_idx = (ulong)( digit - 1 );
        fd_ristretto255_point_add( &buckets[ bucket_idx ], &buckets[ bucket_idx ], &a[j] );
      } else if( digit<0 ) {
        ulong bucket_idx = (ulong)( -digit - 1 );
        fd_ristretto255_point_sub( &buckets[ bucket_idx ], &buckets[ bucket_idx ], &a[j] );
      }
    }

    fd_ristretto255_point_set_zero( running );
    fd_ristretto255_point_set_zero( column  );
    /* Summation by parts: sum_k (k+1)B_k from descending running sums. */
    for( ulong i=bucket_cnt; i; i-- ) {
      fd_ristretto255_point_add( running, running, &buckets[i-1UL] );
      fd_ristretto255_point_add( column,  column,  running          );
    }

    fd_ristretto255_point_add( r, r, column );
  }

  return r;
}

fd_ristretto255_point_t *
fd_ristretto255_multi_scalar_mul( fd_ristretto255_point_t *      r,
                                  uchar const                    n[], /* sz * 32 */
                                  fd_ristretto255_point_t const  a[], /* sz */
                                  ulong                          sz ) {
  if( FD_LIKELY( sz<=FD_RISTRETTO255_PIPPENGER_THRESHOLD ) ) {
    return fd_ed25519_multi_scalar_mul( r, n, a, sz );
  }

  fd_ristretto255_point_set_zero( r );
  for( ulong off=0UL; off<sz; off+=FD_RISTRETTO255_PIPPENGER_BATCH_SZ ) {
    ulong const batch_sz = fd_ulong_min( sz-off, FD_RISTRETTO255_PIPPENGER_BATCH_SZ );
    fd_ristretto255_point_t tmp[1];
    if( batch_sz<=FD_RISTRETTO255_PIPPENGER_THRESHOLD ) {
      fd_ed25519_multi_scalar_mul( tmp, &n[32UL*off], &a[off], batch_sz );
    } else {
      fd_ristretto255_multi_scalar_mul_pippenger( tmp, &n[32UL*off], &a[off], batch_sz );
    }
    fd_ristretto255_point_add( r, r, tmp );
  }

  return r;
}
