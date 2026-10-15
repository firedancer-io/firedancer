#include "./fd_bn254_field_inl.h"
#include "./fd_bn254_backend.h"

/* Compress/Decompress */

uchar *
fd_bn254_g1_compress( uchar       out[32],
                      uchar const in [64],
                      int         big_endian ) {
  fd_bn254_g1_t p[1] = { 0 };
  if( FD_UNLIKELY( !fd_bn254_g1_frombytes_internal( p, in, big_endian ) ) ) {
    return NULL;
  }
  int is_inf   = fd_bn254_g1_is_zero( p );
  int flag_inf = in[ big_endian ? 32 : 63 ] & FLAG_INF;

  /* Serialize compressed point:
     https://github.com/arkworks-rs/algebra/blob/v0.4.2/ec/src/models/short_weierstrass/mod.rs#L122

     1. If the infinity flags is set, return point at infinity
     2. Else, copy x and set neg_y flag */

  if( FD_UNLIKELY( is_inf ) ) {
    fd_memset( out, 0, 32 );
    /* The infinity flag in the result is set iff the infinity flag is set in the Y coordinate */
    out[ big_endian ? 0 : 31 ] |= (uchar)flag_inf;
    return out;
  }

  int is_neg = fd_bn254_fp_is_neg_nm( &p->Y );
  fd_bn254_fp_tobytes_nm( out, &p->X, big_endian );
  if( is_neg ) {
    out[ big_endian ? 0 : 31 ] |= FLAG_NEG;
  }
  return out;
}

uchar *
fd_bn254_g1_decompress( uchar       out[64],
                        uchar const in [32],
                        int         big_endian ) {
  /* Special case: all zeros in => all zeros out, no flags */
  const uchar zero[32] = { 0 };
  if( fd_memeq( in, zero, 32 ) ) {
    return fd_memset( out, 0, 64UL );
  }

  fd_bn254_fp_t x_nm[1], x[1], x2[1], x3_plus_b[1], y[1];
  int is_inf, is_neg;
  if( FD_UNLIKELY( !fd_bn254_fp_frombytes_nm( x_nm, in, big_endian, &is_inf, &is_neg ) ) ) {
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

  fd_bn254_fp_to_mont( x, x_nm );
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

  fd_bn254_fp_tobytes_nm(  out,     x_nm, big_endian );
  fd_bn254_fp_tobytes_nm( &out[32], y,    big_endian );
  /* no flags */
  return out;
}

uchar *
fd_bn254_g2_compress( uchar       out[64],
                      uchar const in[128],
                      int         big_endian ) {
  fd_bn254_g2_t p[1] = { 0 };
  if( FD_UNLIKELY( !fd_bn254_g2_frombytes_internal( p, in, big_endian ) ) ) {
    return NULL;
  }
  int is_inf   = fd_bn254_g2_is_zero( p );
  int flag_inf = in[ big_endian ? 64 : 127 ] & FLAG_INF;

  /* Serialize compressed point */

  if( FD_UNLIKELY( is_inf ) ) {
    fd_memset( out, 0, 64 );
    /* The infinity flag in the result is set iff the infinity flag is set in the Y coordinate */
    out[ big_endian ? 0 : 63 ] |= (uchar)flag_inf;
    return out;
  }

  /* Serialize x coordinate. The flags are on the 2nd element.
     https://github.com/arkworks-rs/algebra/blob/v0.4.2/ff/src/fields/models/quadratic_extension.rs#L700-L702 */
  int is_neg = fd_bn254_fp2_is_neg_nm( &p->Y );
  fd_bn254_fp2_tobytes_nm( out, &p->X, big_endian );
  if( is_neg ) {
    out[ big_endian ? 0 : 63 ] |= FLAG_NEG;
  }
  return out;
}

uchar *
fd_bn254_g2_decompress( uchar       out[128],
                        uchar const in  [64],
                        int         big_endian ) {
  /* Special case: all zeros in => all zeros out, no flags */
  const uchar zero[64] = { 0 };
  if( fd_memeq( in, zero, 64 ) ) {
    return fd_memset( out, 0, 128UL );
  }

  fd_bn254_fp2_t x_nm[1], x[1], x2[1], x3_plus_b[1], y[1];
  int is_inf, is_neg;
  if( FD_UNLIKELY( !fd_bn254_fp2_frombytes_nm( x_nm, in, big_endian, &is_inf, &is_neg ) ) ) {
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

  fd_bn254_fp2_to_mont( x, x_nm );
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

  fd_bn254_fp2_tobytes_nm(  out,     x_nm, big_endian );
  fd_bn254_fp2_tobytes_nm( &out[64], y,    big_endian );
  /* no flags */
  return out;
}

/* Ops */

int
fd_bn254_g1_add_syscall( uchar       out[64],
                         uchar const in[],
                         ulong       in_sz,
                         int         big_endian ) {
  /* Expected 128-byte input (2 points). Pad input with 0s (only big endian). */
  if( FD_UNLIKELY( in_sz > 128UL ) ) {
    return -1;
  }
  if( FD_UNLIKELY( !big_endian && in_sz != 128UL ) ) {
    return -1;
  }
  uchar FD_ALIGNED buf[128] = { 0 };
  fd_memcpy( buf, in, in_sz );

  /* Validate inputs */
  fd_bn254_g1_t r[1], a[1], b[1];
  if( FD_UNLIKELY( !fd_bn254_g1_frombytes_check_subgroup( a, &buf[ 0], big_endian ) ) ) {
    return -1;
  }
  if( FD_UNLIKELY( !fd_bn254_g1_frombytes_check_subgroup( b, &buf[64], big_endian ) ) ) {
    return -1;
  }

  /* Compute point add and serialize result */
  fd_bn254_g1_affine_add( r, a, b );
  fd_bn254_g1_tobytes( out, r, big_endian );
  return 0;
}

int
fd_bn254_g2_add_syscall( uchar       out[128],
                         uchar const in[],
                         ulong       in_sz,
                         int         big_endian ) {
  /* Expected 256-byte input (2 points).
     https://github.com/anza-xyz/solana-sdk/blob/bn254%40v3.2.1/bn254/src/addition.rs#L234-L236 */
  if( FD_UNLIKELY( in_sz != 256UL ) ) {
    return -1;
  }
  uchar FD_ALIGNED buf[256] = { 0 };
  fd_memcpy( buf, in, in_sz );

  /* Validate inputs (curve eq only, no subgroup)
     https://github.com/anza-xyz/solana-sdk/blob/bn254%40v3.2.1/bn254/src/addition.rs#L238-L250 */
  fd_bn254_g2_t r[1], a[1], b[1];
  if( FD_UNLIKELY( !fd_bn254_g2_frombytes_check_eq_only( a, &buf[ 0], big_endian ) ) ) {
    return -1;
  }
  if( FD_UNLIKELY( !fd_bn254_g2_frombytes_check_eq_only( b, &buf[128], big_endian ) ) ) {
    return -1;
  }

  /* Compute point add and serialize result */
  fd_bn254_g2_affine_add( r, a, b );
  fd_bn254_g2_tobytes( out, r, big_endian );
  return 0;
}

int
fd_bn254_g1_scalar_mul_syscall( uchar       out[64],
                                uchar const in[],
                                ulong       in_sz,
                                int         big_endian ) {
  /* Expected 96-byte input (1 point + 1 scalar). Pad input with 0s (only big endian). */
  if( FD_UNLIKELY( in_sz > 96UL ) ) {
    return -1;
  }
  if( FD_UNLIKELY( !big_endian && in_sz != 96UL ) ) {
    return -1;
  }
  uchar FD_ALIGNED buf[96] = { 0 };
  fd_memcpy( buf, in, fd_ulong_min( in_sz, 96UL ) );

  /* Validate inputs */
  fd_bn254_g1_t r[1], a[1];
  fd_bn254_scalar_t s[1];
  if( FD_UNLIKELY( !fd_bn254_g1_frombytes_check_subgroup( a, &buf[ 0], big_endian ) ) ) {
    return -1;
  }

  /* Scalar is big endian and NOT validated
     https://github.com/anza-xyz/agave/blob/v1.18.6/sdk/program/src/alt_bn128/mod.rs#L211-L214 */
  if( FD_BIG_ENDIAN_LIKELY( big_endian ) ) {
    fd_uint256_bswap( s, fd_type_pun_const( &buf[64] ) ); /* &buf[64] is always FD_ALIGNED */
  } else {
    memcpy( s, &buf[64], 32 );
  }
  // no: if( FD_UNLIKELY( !fd_bn254_scalar_validate( s ) ) ) return -1;

  /* Compute scalar mul and serialize result */
  fd_bn254_backend_g1_scalar_mul( r, a, s );
  fd_bn254_g1_tobytes( out, r, big_endian );
  return 0;
}

int
fd_bn254_g2_scalar_mul_syscall( uchar       out[128],
                                uchar const in[],
                                ulong       in_sz,
                                int         big_endian ) {
  /* Expected 160-byte input (1 point + 1 scalar).
     https://github.com/anza-xyz/solana-sdk/blob/bn254%40v3.2.1/bn254/src/multiplication.rs#L248-L250 */
  if( FD_UNLIKELY( in_sz != 160UL ) ) {
    return -1;
  }
  uchar FD_ALIGNED buf[160] = { 0 };
  fd_memcpy( buf, in, 160UL );

  /* Validate point (curve equation and subgroup membership)
     https://github.com/anza-xyz/solana-sdk/blob/bn254%40v3.2.1/bn254/src/multiplication.rs#L252-L255 */
  fd_bn254_g2_t r[1], a[1];
  fd_bn254_scalar_t s[1];
  if( FD_UNLIKELY( !fd_bn254_g2_frombytes_check_eq_only( a, &buf[ 0], big_endian ) ) ) {
    return -1;
  }
  if( FD_UNLIKELY( !fd_bn254_g2_is_zero( a ) &&
                   !fd_bn254_backend_g2_in_subgroup( a ) ) ) {
    return -1;
  }

  /* Scalar is little endian and NOT validated
     https://github.com/anza-xyz/solana-sdk/blob/bn254%40v3.2.1/bn254/src/multiplication.rs#L256-L272 */
  if( FD_BIG_ENDIAN_LIKELY( big_endian ) ) {
    fd_uint256_bswap( s, fd_type_pun_const( &buf[128] ) ); /* &buf[128] is always FD_ALIGNED */
  } else {
    memcpy( s, &buf[128], 32 );
  }
  // no: if( FD_UNLIKELY( !fd_bn254_scalar_validate( s ) ) ) return -1;

  /* Compute scalar mul and serialize result */
  fd_bn254_backend_g2_scalar_mul( r, a, s );
  fd_bn254_g2_tobytes( out, r, big_endian );
  return 0;
}

int
fd_bn254_pairing_is_one_syscall( uchar       out[32],
                                 uchar const in[],
                                 ulong       in_sz,
                                 int         big_endian ) {
  /* https://github.com/anza-xyz/solana-sdk/blob/bn254%40v3.2.1/bn254/src/pairing.rs#L79 */
  if( FD_UNLIKELY( (in_sz % 192UL) != 0 ) ) {
    return -1; /* Invalid input length */
  }
  ulong elements_len = in_sz / 192UL;

  /* Validation matches agave: parse and subgroup-check each pair in
     input order, skipping infinity pairs, before any pairing work.
     FD_BN254_PAIRING_MAX bounds the one-shot backend path; the VM
     compute budget (12121 CU per pair) keeps real inputs far below it,
     and larger inputs stream through Miller-loop batches instead. */
# define FD_BN254_PAIRING_MAX (128UL)
  fd_bn254_g1_t p[FD_BN254_PAIRING_MAX];
  fd_bn254_g2_t q[FD_BN254_PAIRING_MAX];

  int stream = elements_len>FD_BN254_PAIRING_MAX;
# undef FD_BN254_PAIRING_MAX
  fd_bn254_fp12_t r[1];
  fd_bn254_fp12_set_one( r );

  ulong sz=0;
  for( ulong i=0; i<elements_len; i++ ) {
    /* G1: deserialize and check subgroup membership */
    if( FD_UNLIKELY( !fd_bn254_g1_frombytes_check_subgroup( &p[sz], &in[i*192   ], big_endian ) ) ) {
      return -1;
    }
    /* G2: deserialize and check subgroup membership (the AVX-512 backend
       runs the subgroup part natively via the dispatch) */
    if( FD_UNLIKELY( !fd_bn254_g2_frombytes_check_eq_only( &q[sz], &in[i*192+64], big_endian ) ) ) {
      return -1;
    }
    if( FD_UNLIKELY( !fd_bn254_g2_is_zero(&q[sz]) &&
                     !fd_bn254_backend_g2_in_subgroup( &q[sz] ) ) ) {
      return -1;
    }
    /* Skip any pair where either P or Q is the point at infinity */
    if( FD_UNLIKELY( fd_bn254_g1_is_zero(&p[sz]) || fd_bn254_g2_is_zero(&q[sz]) ) ) {
      continue;
    }
    ++sz;
    if( FD_UNLIKELY( stream ) && sz==FD_BN254_PAIRING_BATCH_MAX ) {
      fd_bn254_fp12_t tmp[1];
      fd_bn254_miller_loop( tmp, p, q, sz );
      fd_bn254_fp12_mul( r, r, tmp );
      sz = 0;
    }
  }

  /* Output is 0 or 1, serialized as big endian uint256.  The empty
     product is 1. */
  fd_memset( out, 0, 32 );
  if( FD_UNLIKELY( stream ) ) {
    if( sz>0 ) {
      fd_bn254_fp12_t tmp[1];
      fd_bn254_miller_loop( tmp, p, q, sz );
      fd_bn254_fp12_mul( r, r, tmp );
    }
    fd_bn254_final_exp( r, r );
    if( FD_LIKELY( fd_bn254_fp12_is_one( r ) ) ) out[ big_endian ? 31 : 0 ] = 1;
    return 0;
  }
  if( FD_LIKELY( fd_bn254_backend_pairing_is_one( p, q, sz ) ) ) {
    out[ big_endian ? 31 : 0 ] = 1;
  }
  return 0;
}

/* fd_bn254_ref_pairing_is_one: the reference pairing product over
   already-validated affine pairs (backend dispatch boundary). */
int
fd_bn254_ref_pairing_is_one( fd_bn254_g1_t const * p,
                             fd_bn254_g2_t const * q,
                             ulong                 sz ) {
  fd_bn254_fp12_t r[1], tmp[1];
  fd_bn254_fp12_set_one( r );
  ulong done = 0UL;
  while( done<sz ) {
    ulong n = fd_ulong_min( sz-done, FD_BN254_PAIRING_BATCH_MAX );
    fd_bn254_miller_loop( tmp, p+done, q+done, n );
    fd_bn254_fp12_mul( r, r, tmp );
    done += n;
  }
  fd_bn254_final_exp( r, r );
  return fd_bn254_fp12_is_one( r );
}
