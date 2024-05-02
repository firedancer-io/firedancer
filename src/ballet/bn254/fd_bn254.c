#include "./fd_bn254_internal.h"

#include "./fd_bn254_field.c"
#include "./fd_bn254_field_ext.c"
#include "./fd_bn254_g1.c"
#include "./fd_bn254_g2.c"
#include "./fd_bn254_pairing.c"

#define FD_BN254_PAIRING_BATCH_MAX 16UL

/* Compress/Decompress */

uchar *
fd_bn254_g1_compress( uchar       out[32],
                      uchar const in [64] ) {
  fd_bn254_g1_t p[1] = {0};
  if( FD_UNLIKELY( !fd_bn254_g1_frombytes_internal( p, in ) ) ) return NULL;
  int is_inf = fd_bn254_g1_is_zero( p );
  int is_neg = fd_bn254_fp_is_neg_nm( &p->Y );

  /* Serialize compressed point:
     https://github.com/arkworks-rs/algebra/blob/v0.4.2/ec/src/models/short_weierstrass/mod.rs#L122

     1. If the infinity flags is set, return point at infinity
     2. Else, copy x and set neg_y flag */

  if( FD_UNLIKELY( is_inf ) ) {
    fd_memset( out, 0, 32 );
    out[0] = FLAG_INF;
    return out;
  }

  fd_memcpy( out, in, 32 );
  if( is_neg ) out[0] |= FLAG_NEG;
  return out;
}

uchar *
fd_bn254_g1_decompress( uchar       out[64],
                        uchar const in [32] ) {
  fd_bn254_fp_t x[1], x2[1], x3_plus_b[1], y[1];
  int is_inf, is_neg;
  if( FD_UNLIKELY( !fd_bn254_fp_frombytes_be_nm( x, in, &is_inf, &is_neg ) ) ) {
    return NULL;
  }

  /* Point at infinity.
     If the point at infinity flag is set (bit 6), return the point at
     infinity with no check on coords.
     https://github.com/arkworks-rs/algebra/blob/v0.4.2/ec/src/models/short_weierstrass/mod.rs#L156-L160
  */
  if( is_inf ) {
    fd_memset( out, 0, 64UL );
    /* no flags */
    return out;
  }

  fd_bn254_fp_to_mont( x, x );
  fd_bn254_fp_sqr( x2, x );
  fd_bn254_fp_mul( x3_plus_b, x2, x );
  fd_bn254_fp_add( x3_plus_b, x3_plus_b, fd_bn254_const_b_mont );
  if( FD_UNLIKELY( !fd_bn254_fp_sqrt( y, x3_plus_b ) ) ) {
    return NULL;
  }

  fd_bn254_fp_from_mont( y, y );
  if( is_neg != fd_bn254_fp_is_neg_nm( y ) ) {
    fd_bn254_fp_neg_nm( y, y );
  }

  fd_memcpy( out, in, 32 ); out[0] &= FLAG_MASK;
  fd_bn254_fp_tobytes_be_nm( &out[32], y );
  /* no flags */
  return out;
}

uchar *
fd_bn254_g2_compress( uchar       out[64],
                      uchar const in[128] ) {
  fd_bn254_g2_t p[1] = {0};
  if( FD_UNLIKELY( !fd_bn254_g2_frombytes_internal( p, in ) ) ) return NULL;
  int is_inf = fd_bn254_g2_is_zero( p );
  int is_neg = fd_bn254_fp2_is_neg_nm( &p->Y );

  /* Serialize compressed point */

  if( FD_UNLIKELY( is_inf ) ) {
    fd_memset( out, 0, 64 );
    out[0] = FLAG_INF;
    return out;
  }

  /* Serialize x coordinate. The flags are on the 2nd element.
     https://github.com/arkworks-rs/algebra/blob/v0.4.2/ff/src/fields/models/quadratic_extension.rs#L700-L702 */
  fd_memcpy( out, in, 64 );
  if( is_neg ) out[0] |= FLAG_NEG;
  return out;
}

uchar *
fd_bn254_g2_decompress( uchar       out[128],
                        uchar const in  [64] ) {
  fd_bn254_fp2_t x[1], x2[1], x3_plus_b[1], y[1];
  int is_inf, is_neg;
  if( FD_UNLIKELY( !fd_bn254_fp2_frombytes_be_nm( x, in, &is_inf, &is_neg ) ) ) {
    return NULL;
  }

  /* Point at infinity.
     If the point at infinity flag is set (bit 6), return the point at
     infinity with no check on coords.
     https://github.com/arkworks-rs/algebra/blob/v0.4.2/ec/src/models/short_weierstrass/mod.rs#L156-L160 */
  if( is_inf ) {
    fd_memset( out, 0, 128UL );
    /* no flags */
    return out;
  }

  fd_bn254_fp2_to_mont( x, x );
  fd_bn254_fp2_sqr( x2, x );
  fd_bn254_fp2_mul( x3_plus_b, x2, x );
  fd_bn254_fp2_add( x3_plus_b, x3_plus_b, fd_bn254_const_twist_b_mont );
  if( FD_UNLIKELY( !fd_bn254_fp2_sqrt( y, x3_plus_b ) ) ) {
    return NULL;
  }

  fd_bn254_fp2_from_mont( y, y );
  if( is_neg != fd_bn254_fp2_is_neg_nm( y ) ) {
    fd_bn254_fp2_neg_nm( y, y );
  }

  fd_memcpy( out, in, 64 ); out[0] &= FLAG_MASK;
  fd_bn254_fp2_tobytes_be_nm( &out[64], y );
  /* no flags */
  return out;
}

/* Ops */

int
fd_bn254_g1_add_syscall( uchar       out[64],
                         uchar const in[],
                         ulong       in_sz ) {
  /* Expected 128-byte input (2 points). Pad input with 0s. */
  if( FD_UNLIKELY( in_sz > 128UL ) ) return -1;
  uchar FD_ALIGNED buf[128] = { 0 };
  fd_memcpy( buf, in, in_sz );

  /* Validate inputs */
  fd_bn254_g1_t r[1], a[1], b[1];
  if( FD_UNLIKELY( !fd_bn254_g1_frombytes_check_subgroup( a, &buf[ 0] ) ) ) return -1;
  if( FD_UNLIKELY( !fd_bn254_g1_frombytes_check_subgroup( b, &buf[64] ) ) ) return -1;

  /* Compute point add and serialize result */
  fd_bn254_g1_affine_add( r, a, b );
  fd_bn254_g1_tobytes( out, r );
  return 0;
}

int
fd_bn254_g1_scalar_mul_syscall( uchar       out[64],
                                uchar const in[],
                                ulong       in_sz ) {
  /* Expected 96-byte input (1 point + 1 scalar). Pad input with 0s. */
  if( FD_UNLIKELY( in_sz > 96UL ) ) return -1;
  uchar FD_ALIGNED buf[96] = { 0 };
  fd_memcpy( buf, in, in_sz );

  /* Validate inputs */
  fd_bn254_g1_t r[1], a[1];
  fd_bn254_scalar_t s[1];
  if( FD_UNLIKELY( !fd_bn254_g1_frombytes_check_subgroup( a, &buf[ 0] ) ) ) return -1;

  /* Scalar is big endian and NOT validated
     https://github.com/anza-xyz/agave/blob/v1.18.6/sdk/program/src/alt_bn128/mod.rs#L211-L214 */
  fd_uint256_bswap( s, fd_type_pun_const( &buf[64] ) ); /* &buf[64] is always FD_ALIGNED */
  // no: if( FD_UNLIKELY( !fd_bn254_scalar_validate( s ) ) ) return -1;

  /* Compute scalar mul and serialize result */
  fd_bn254_g1_scalar_mul( r, a, s );
  fd_bn254_g1_tobytes( out, r );
  return 0;
}

int
fd_bn254_pairing_is_one_syscall( uchar       out[32],
                                 uchar const in[],
                                 ulong       in_sz ) {
  /* Expected a multiple of 192-byte input (n G1 + n G2). */
  if( FD_UNLIKELY( (in_sz%192UL)!=0 ) ) return -1;

  ulong elements_len = in_sz / 192UL;
  fd_bn254_g1_t p[FD_BN254_PAIRING_BATCH_MAX];
  fd_bn254_g2_t q[FD_BN254_PAIRING_BATCH_MAX];

  fd_bn254_fp12_t r[1];

  for( ulong i=0; i<elements_len; i+=FD_BN254_PAIRING_BATCH_MAX ) {
    ulong sz = fd_ulong_min( elements_len-i, FD_BN254_PAIRING_BATCH_MAX );
    for( ulong j=0; j<sz; j++ ) {
      if( FD_UNLIKELY( !fd_bn254_g1_frombytes_check_subgroup( &p[j], &in[(i+j)*192   ] ) ) ) return -1;
      if( FD_UNLIKELY( !fd_bn254_g2_frombytes_check_subgroup( &q[j], &in[(i+j)*192+64] ) ) ) return -1;
      //TODO skip pairs with point at infinity
    }
    if( i==0 ) {
      fd_bn254_miller_loop( r, p, q, sz );
    } else {
      fd_bn254_fp12_t tmp[1];
      fd_bn254_miller_loop( tmp, p, q, sz );
      fd_bn254_fp12_mul( r, r, tmp );
    }
  }

  fd_bn254_final_exp( r, r );

  /* Output is 0 or 1, serialized as big endian uint256. */
  fd_memset( out, 0, 32 );
  if( FD_LIKELY( fd_bn254_fp12_is_one( r ) ) ) {
    out[31] = 1;
  }
  return 0;
}
