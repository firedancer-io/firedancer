#include "../fd_bls.h"
#include "../../bigint/fd_uint256.h"

#include "../../../third_party/blst/bindings/blst.h"

/* Reference implementation of the byte, group, and hash-to-curve surface.
   AVX-512 builds link this fallback until those operations are ported; its
   pairing calls still dispatch through the selected fd_bls backend. */

/* Scalar */

typedef fd_uint256_t fd_bls_ref_scalar_t;

static fd_uint256_t const fd_bls_ref_scalar_modulus = { .limbs = {
  0xffffffff00000001UL,
  0x53bda402fffe5bfeUL,
  0x3339d80809a1d805UL,
  0x73eda753299d7d48UL
} };

static inline fd_bls_ref_scalar_t *
fd_bls_ref_scalar_frombytes( fd_bls_ref_scalar_t * n,
                             uchar const             in[ 32 ],
                             int                     big_endian ) {
  fd_uint256_t raw[1];
  memcpy( raw->buf, in, 32UL );
  if( big_endian ) fd_uint256_bswap( n, raw );
  else             *n = *raw;
  if( FD_UNLIKELY( fd_uint256_cmp( n, &fd_bls_ref_scalar_modulus )>=0 ) ) return NULL;
  return n;
}

/* G1 serde */

typedef blst_p1_affine fd_bls_ref_g1aff_t;
typedef blst_p1        fd_bls_ref_g1_t;

static inline void
fd_bls_ref_g1_to_fd_bls( fd_bls_g1_t *              out,
                         fd_bls_ref_g1aff_t const * in ) {
  blst_uint64_from_fp( out->x, &in->x );
  blst_uint64_from_fp( out->y, &in->y );
}

static inline void
fd_bls_ref_g1_bswap( uchar       out[ 96 ], /* out can be in */
                     uchar const in [ 96 ] ) {
  /* copy into aligned memory */
  ulong e[ 96/sizeof(ulong) ];
  memcpy( e, in, 96 );

  /* bswap X, Y independently (48 bytes each) */
  fd_ulong_n_bswap( e+0, 6 );
  fd_ulong_n_bswap( e+6, 6 );

  /* copy to out */
  memcpy( out, e, 96 );
}

static inline uchar *
fd_bls_ref_g1_tobytes( uchar                     out[ 96 ],
                       fd_bls_ref_g1_t const * a,
                       int                       big_endian ) {
  blst_p1_serialize( out, a );
  if( !big_endian ) {
    fd_bls_ref_g1_bswap( out, out );
  }
  return out;
}

static inline fd_bls_ref_g1aff_t *
fd_bls_ref_g1_frombytes_unchecked( fd_bls_ref_g1aff_t * r,
                                   uchar const            bytes[ 96 ],
                                   int                    big_endian ) {
  ulong be[ 96/sizeof(ulong) ];
  uchar const * in = bytes;
  if( !big_endian ) {
    fd_bls_ref_g1_bswap( (uchar *)be, bytes );
    in = (uchar *)be;
  }

  /* Reject the point if the compressed or parity flag is set.
     https://github.com/anza-xyz/agave/blob/v4.0.0-beta.2/bls12-381/src/encoding.rs#L57-L60 */
  if( FD_UNLIKELY( in[ 0 ] & 0xA0 ) ) {
    return NULL;
  }

  if( FD_UNLIKELY( blst_p1_deserialize( r, in )!=BLST_SUCCESS ) ) {
    return NULL;
  }
  return r;
}

static inline fd_bls_ref_g1aff_t *
fd_bls_ref_g1_frombytes( fd_bls_ref_g1aff_t * r,
                         uchar const            in[ 96 ],
                         int                    big_endian ) {
  if( FD_UNLIKELY( !fd_bls_ref_g1_frombytes_unchecked( r, in, big_endian ) ) ) {
    return NULL;
  }
  if( FD_UNLIKELY( !blst_p1_affine_in_g1( r ) ) ) {
    return NULL;
  }
  return r;
}

/* G1 operations */

int
fd_bls_g1_decompress( uchar       out[ 96 ],
                      uchar const compressed[ 48 ],
                      int         big_endian ) {
  /* blst expects input in big endian. if little endian, bswap. */
  ulong be[ 48/sizeof(ulong) ];
  uchar const * in = compressed;
  if( !big_endian ) {
    in = (uchar *)be;
    memcpy( be, compressed, 48 );
    fd_ulong_n_bswap( be, 6 );
  }

  /* decompress and serialize */
  fd_bls_ref_g1aff_t r[1];
  if( FD_UNLIKELY( blst_p1_uncompress( r, in )!=BLST_SUCCESS ) ) {
    return -1;
  }
  if( FD_UNLIKELY( !blst_p1_affine_in_g1( r ) ) ) {
    return -1;
  }
  blst_p1_affine_serialize( out, r );

  /* blst output is big endian. if we want little endian, bswap. */
  if( !big_endian ) {
    fd_bls_ref_g1_bswap( out, out );
  }
  return 0;
}

int
fd_bls_g1_validate( uchar const encoded[ 96 ],
                    int         big_endian ) {
  fd_bls_ref_g1aff_t a[1];
  return !!fd_bls_ref_g1_frombytes( a, encoded, big_endian );
}

int
fd_bls_g1_add( uchar       out[ 96 ],
               uchar const a_bytes[ 96 ],
               uchar const b_bytes[ 96 ],
               int         big_endian ) {
  /* points a, b are unchecked per SIMD-0388 */
  fd_bls_ref_g1aff_t a[1], b[1];
  if( FD_UNLIKELY( fd_bls_ref_g1_frombytes_unchecked( a, a_bytes, big_endian )==NULL ) ) {
    return -1;
  }
  if( FD_UNLIKELY( fd_bls_ref_g1_frombytes_unchecked( b, b_bytes, big_endian )==NULL ) ) {
    return -1;
  }

  fd_bls_ref_g1_t r[1], p[1];
  blst_p1_from_affine( p, a );
  blst_p1_add_or_double_affine( r, p, b );

  fd_bls_ref_g1_tobytes( out, r, big_endian );
  return 0;
}

int
fd_bls_g1_sub( uchar       out[ 96 ],
               uchar const a_bytes[ 96 ],
               uchar const b_bytes[ 96 ],
               int         big_endian ) {
  /* points a, b are unchecked per SIMD-0388 */
  fd_bls_ref_g1aff_t a[1], b[1];
  if( FD_UNLIKELY( fd_bls_ref_g1_frombytes_unchecked( a, a_bytes, big_endian )==NULL ) ) {
    return -1;
  }
  if( FD_UNLIKELY( fd_bls_ref_g1_frombytes_unchecked( b, b_bytes, big_endian )==NULL ) ) {
    return -1;
  }

  fd_bls_ref_g1_t r[1], p[1];
  blst_p1_from_affine( p, a );
  blst_fp_cneg( &b->y, &b->y, 1 ); /* -b, it works also with b=0 */
  blst_p1_add_or_double_affine( r, p, b );

  fd_bls_ref_g1_tobytes( out, r, big_endian );
  return 0;
}

int
fd_bls_g1_mul( uchar       out[ 96 ],
               uchar const scalar_bytes[ 32 ],
               uchar const a_bytes     [ 96 ],
               int         big_endian ) {
  /* point a, scalar n are validated per SIMD-0388 */
  fd_bls_ref_g1aff_t a[1];
  fd_bls_ref_scalar_t n[1];
  if( FD_UNLIKELY( fd_bls_ref_g1_frombytes( a, a_bytes, big_endian )==NULL ) ) {
    return -1;
  }
  if( FD_UNLIKELY( fd_bls_ref_scalar_frombytes( n, scalar_bytes, big_endian )==NULL ) ) {
    return -1;
  }

  fd_bls_ref_g1_t r[1], p[1];
  blst_p1_from_affine( p, a );
  /* https://github.com/filecoin-project/blstrs/blob/v0.7.1/src/g1.rs#L578-L580 */
  blst_p1_mult( r, p, n->buf, 255 );

  fd_bls_ref_g1_tobytes( out, r, big_endian );
  return 0;
}

/* G2 serde */

typedef blst_p2_affine fd_bls_ref_g2aff_t;
typedef blst_p2        fd_bls_ref_g2_t;

static inline void
fd_bls_ref_g2_to_fd_bls( fd_bls_g2_t *              out,
                         fd_bls_ref_g2aff_t const * in ) {
  blst_uint64_from_fp( out->x[0], &in->x.fp[0] );
  blst_uint64_from_fp( out->x[1], &in->x.fp[1] );
  blst_uint64_from_fp( out->y[0], &in->y.fp[0] );
  blst_uint64_from_fp( out->y[1], &in->y.fp[1] );
}

static inline void
fd_bls_ref_fp_wire_to_fd_bls( ulong       out[6],
                                uchar const in[48],
                                int         big_endian ) {
  memcpy( out, in, 48UL );
  if( big_endian ) fd_ulong_n_bswap( out, 6UL );
}

static inline void
fd_bls_ref_g1_wire_to_fd_bls( fd_bls_g1_t * out,
                                uchar const   in[96],
                                int           big_endian ) {
  fd_bls_ref_fp_wire_to_fd_bls( out->x, in,    big_endian );
  fd_bls_ref_fp_wire_to_fd_bls( out->y, in+48, big_endian );
}

static inline void
fd_bls_ref_g2_wire_to_fd_bls( fd_bls_g2_t * out,
                                uchar const   in[192],
                                int           big_endian ) {
  /* The big-endian Fp2 wire order is c1||c0; little-endian is c0||c1. */
  ulong c0 = big_endian ? 1UL : 0UL;
  ulong c1 = big_endian ? 0UL : 1UL;
  fd_bls_ref_fp_wire_to_fd_bls( out->x[0], in+48UL*c0,      big_endian );
  fd_bls_ref_fp_wire_to_fd_bls( out->x[1], in+48UL*c1,      big_endian );
  fd_bls_ref_fp_wire_to_fd_bls( out->y[0], in+96UL+48UL*c0, big_endian );
  fd_bls_ref_fp_wire_to_fd_bls( out->y[1], in+96UL+48UL*c1, big_endian );
}

static inline void
fd_bls_ref_g2_bswap( uchar       out[ 96*2 ], /* out can be in */
                       uchar const in [ 96*2 ] ) {
  /* copy into aligned memory */
  ulong e[ 96*2/sizeof(ulong) ];
  memcpy( e, in, 96*2 );

  /* bswap X, Y independently (96 bytes each) */
  fd_ulong_n_bswap( e+00, 12 );
  fd_ulong_n_bswap( e+12, 12 );

  /* copy to out */
  memcpy( out, e, 96*2 );
}

static inline uchar *
fd_bls_ref_g2_tobytes( uchar                     out[ 96*2 ],
                       fd_bls_ref_g2_t const * a,
                       int                       big_endian ) {
  blst_p2_serialize( out, a );
  if( !big_endian ) {
    fd_bls_ref_g2_bswap( out, out );
  }
  return out;
}

static inline fd_bls_ref_g2aff_t *
fd_bls_ref_g2_frombytes_unchecked( fd_bls_ref_g2aff_t * r,
                                   uchar const            bytes[ 96*2 ],
                                   int                    big_endian ) {
  ulong be[ 96*2/sizeof(ulong) ];
  uchar const * in = bytes;
  if( !big_endian ) {
    fd_bls_ref_g2_bswap( (uchar *)be, bytes );
    in = (uchar *)be;
  }

  /* Reject the point if the compressed or parity flag is set.
     https://github.com/anza-xyz/agave/blob/v4.0.0-beta.2/bls12-381/src/encoding.rs#L103-L106 */
  if( FD_UNLIKELY( in[ 0 ] & 0xA0 ) ) {
    return NULL;
  }

  if( FD_UNLIKELY( blst_p2_deserialize( r, in )!=BLST_SUCCESS ) ) {
    return NULL;
  }
  return r;
}

static inline fd_bls_ref_g2aff_t *
fd_bls_ref_g2_frombytes( fd_bls_ref_g2aff_t * r,
                         uchar const            in[ 96*2 ],
                         int                    big_endian ) {
  if( FD_UNLIKELY( !fd_bls_ref_g2_frombytes_unchecked( r, in, big_endian ) ) ) {
    return NULL;
  }
  if( FD_UNLIKELY( !blst_p2_affine_in_g2( r ) ) ) {
    return NULL;
  }
  return r;
}

/* G2 operations */

int
fd_bls_g2_decompress( uchar       out[ 96*2 ],
                      uchar const compressed[ 48*2 ],
                      int         big_endian ) {
  /* blst expects input in big endian. if little endian, bswap. */
  ulong be[ 48*2/sizeof(ulong) ];
  uchar const * in = compressed;
  if( !big_endian ) {
    in = (uchar *)be;
    memcpy( be, compressed, 48*2 );
    fd_ulong_n_bswap( be, 6*2 );
  }

  /* decompress and serialize */
  fd_bls_ref_g2aff_t r[1];
  if( FD_UNLIKELY( blst_p2_uncompress( r, in )!=BLST_SUCCESS ) ) {
    return -1;
  }
  if( FD_UNLIKELY( !blst_p2_affine_in_g2( r ) ) ) {
    return -1;
  }
  blst_p2_affine_serialize( out, r );

  /* blst output is big endian. if we want little endian, bswap. */
  if( !big_endian ) {
    fd_bls_ref_g2_bswap( out, out );
  }
  return 0;
}

int
fd_bls_g2_compress( uchar       out[  96 ],
                     uchar const in [ 192 ],
                     int         big_endian ) {
  fd_bls_ref_g2aff_t a[1];
  if( FD_UNLIKELY( !fd_bls_ref_g2_frombytes( a, in, big_endian ) ) ) return -1;

  blst_p2_affine_compress( out, a );
  if( !big_endian ) {
    ulong le[ 96/sizeof(ulong) ];
    memcpy( le, out, 96UL );
    fd_ulong_n_bswap( le, 12UL );
    memcpy( out, le, 96UL );
  }
  return 0;
}

int
fd_bls_g2_validate( uchar const encoded[ 96*2 ],
                    int         big_endian ) {
  fd_bls_ref_g2aff_t a[1];
  return !!fd_bls_ref_g2_frombytes( a, encoded, big_endian );
}

int
fd_bls_g2_add( uchar       out[ 96*2 ],
               uchar const a_bytes[ 96*2 ],
               uchar const b_bytes[ 96*2 ],
               int         big_endian ) {
  /* points a, b are unchecked per SIMD-0388 */
  fd_bls_ref_g2aff_t a[1], b[1];
  if( FD_UNLIKELY( fd_bls_ref_g2_frombytes_unchecked( a, a_bytes, big_endian )==NULL ) ) {
    return -1;
  }
  if( FD_UNLIKELY( fd_bls_ref_g2_frombytes_unchecked( b, b_bytes, big_endian )==NULL ) ) {
    return -1;
  }

  fd_bls_ref_g2_t r[1], p[1];
  blst_p2_from_affine( p, a );
  blst_p2_add_or_double_affine( r, p, b );

  fd_bls_ref_g2_tobytes( out, r, big_endian );
  return 0;
}

int
fd_bls_g2_sub( uchar       out[ 96*2 ],
               uchar const a_bytes[ 96*2 ],
               uchar const b_bytes[ 96*2 ],
               int         big_endian ) {
  /* points a, b are unchecked per SIMD-0388 */
  fd_bls_ref_g2aff_t a[1], b[1];
  if( FD_UNLIKELY( fd_bls_ref_g2_frombytes_unchecked( a, a_bytes, big_endian )==NULL ) ) {
    return -1;
  }
  if( FD_UNLIKELY( fd_bls_ref_g2_frombytes_unchecked( b, b_bytes, big_endian )==NULL ) ) {
    return -1;
  }

  fd_bls_ref_g2_t r[1], p[1];
  blst_p2_from_affine( p, a );
  blst_fp2_cneg( &b->y, &b->y, 1 ); /* -b, it works also with b=0 */
  blst_p2_add_or_double_affine( r, p, b );

  fd_bls_ref_g2_tobytes( out, r, big_endian );
  return 0;
}

int
fd_bls_g2_mul( uchar       out[ 96*2 ],
               uchar const scalar_bytes[ 32 ],
               uchar const a_bytes     [ 96*2 ],
               int         big_endian ) {
  /* point a, scalar n are validated per SIMD-0388 */
  fd_bls_ref_g2aff_t a[1];
  fd_bls_ref_scalar_t n[1];
  if( FD_UNLIKELY( fd_bls_ref_g2_frombytes( a, a_bytes, big_endian )==NULL ) ) {
    return -1;
  }
  if( FD_UNLIKELY( fd_bls_ref_scalar_frombytes( n, scalar_bytes, big_endian )==NULL ) ) {
    return -1;
  }

  fd_bls_ref_g2_t r[1], p[1];
  blst_p2_from_affine( p, a );
  /* https://github.com/filecoin-project/blstrs/blob/v0.7.1/src/g2.rs#L545-L547 */
  blst_p2_mult( r, p, n->buf, 255 );

  fd_bls_ref_g2_tobytes( out, r, big_endian );
  return 0;
}

int
fd_bls_pairing_bytes( uchar       out[ 48*12 ],
                      uchar const g1_bytes[], /* 96*cnt */
                      uchar const g2_bytes[], /* 192*cnt */
                      ulong       cnt,
                      int         big_endian ) {

  if( FD_UNLIKELY( cnt>FD_BLS_PAIR_MAX ) ) {
    return -1;
  }

  fd_bls_ref_g1aff_t a[ FD_BLS_PAIR_MAX ];
  fd_bls_ref_g2aff_t b[ FD_BLS_PAIR_MAX ];
  fd_bls_g1_t pair_a[ FD_BLS_PAIR_MAX ];
  fd_bls_g2_t pair_b[ FD_BLS_PAIR_MAX ];
  /* skip pairs where either side is the point at infinity.
     The Miller formulas assume finite affine inputs. */
  ulong m = 0UL;
  for( ulong j=0; j<cnt; j++ ) {
    fd_bls_ref_g1aff_t * aj = &a[ m ];
    fd_bls_ref_g2aff_t * bj = &b[ m ];
    if( FD_UNLIKELY( fd_bls_ref_g1_frombytes( aj, g1_bytes+96*j, big_endian )==NULL ) ) {
      return -1;
    }
    if( FD_UNLIKELY( fd_bls_ref_g2_frombytes( bj, g2_bytes+192*j, big_endian )==NULL ) ) {
      return -1;
    }
    int const a_inf = !!(g1_bytes[ 96UL*j+(big_endian ? 0UL : 47UL)] & 0x40U);
    int const b_inf = !!(g2_bytes[192UL*j+(big_endian ? 0UL : 95UL)] & 0x40U);
    if( FD_UNLIKELY( a_inf || b_inf ) ) {
      continue;
    }
    fd_bls_ref_g1_wire_to_fd_bls( pair_a+m, g1_bytes+ 96UL*j, big_endian );
    fd_bls_ref_g2_wire_to_fd_bls( pair_b+m, g2_bytes+192UL*j, big_endian );
    m++;
  }

  ulong r[12][6];
  if( FD_UNLIKELY( fd_bls_pairing( r, pair_a, pair_b, m ) ) ) return -1;

  for( ulong j=0UL; j<12UL; j++ ) {
    if( big_endian ) {
      ulong be[6];
      memcpy( be, r[j], 48UL );
      fd_ulong_n_bswap( be, 6UL );
      memcpy( out+48UL*(11UL-j), be, 48UL );
    } else {
      memcpy( out+48UL*j, r[j], 48UL );
    }
  }

  return 0;
}

/* fd_bls_verify verifies a BLS signature in the mathematical
   sense, i.e. computes a pairing to check that the signature is correct.
   This is the core computation both for "real world" signatures and proofs
   of possession. In both cases, the difference between the math paper and
   the RFC implementation is an additional domain separator that's used
   in computing the hash to G2.

   See also:
   https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-06#name-coreverify

   We use a1, a2 for points in G1, b1, b2 for points in G2.
   We have to check that e( pk, H(msg) ) == e( g1, sig ), or equivalently
   e( pk, H(msg) ) * e( -g1, sig ) == 1.

   Replacing the variables we get:
   - a1 <- public_key, input needs to be decompressed in G1
   - b1 <- msg, input needs to be hashed to G2
   - a2 <- -g1, the const generator of G1, negated
   - b2 <- signature, input needs to be decompressed in G2
   */
int
fd_bls_verify( uchar const  msg[], /* msg_sz */
               ulong        msg_sz,
               uchar const  signature[ 96 ],
               uchar const  public_key[ 48 ],
               char const * domain,
               ulong        domain_len ) {
  fd_bls_ref_g1aff_t a1[1]; /* a2 is const, we don't need a var */
  fd_bls_ref_g2aff_t b1[1], b2[1];

  /* decompress public_key into a1 and check that it's a valid point in G1 */
  if( FD_UNLIKELY( blst_p1_uncompress( a1, public_key )!=BLST_SUCCESS ) ) {
    return -1;
  }
  if( FD_UNLIKELY( !blst_p1_affine_in_g1( a1 ) ) ) {
    return -1;
  }
  /* https://github.com/anza-xyz/solana-sdk/blob/b66abfddd564aef5b4b82cf4e76381e96f2459f0/bls-signatures/src/pubkey/verify.rs#L120 */
  if( FD_UNLIKELY( blst_p1_affine_is_inf( a1 ) ) ) {
    return -1;
  }

  /* hash msg into b1. the check that it's a valid point in G2 is implicit/guaranteed */
  fd_bls_ref_g2_t hash_point[1];
  blst_hash_to_g2( hash_point, msg, msg_sz, (uchar const *)domain, domain_len, NULL, 0UL );
  blst_p2_to_affine( b1, hash_point );

  /* decompress signature into b2 and check that it's a valid point in G2 */
  if( FD_UNLIKELY( blst_p2_uncompress( b2, signature )!=BLST_SUCCESS ) ) {
    return -1;
  }
  if( FD_UNLIKELY( !blst_p2_affine_in_g2( b2 ) ) ) {
    return -1;
  }
  if( FD_UNLIKELY( blst_p2_affine_is_inf( b2 ) ) ) {
    return -1;
  }

  fd_bls_g1_t p[2];
  fd_bls_g2_t q[2];
  fd_bls_ref_g1_to_fd_bls( p,   a1                  ); /* p[0] = public_key */
  fd_bls_ref_g1_to_fd_bls( p+1, &BLS12_381_NEG_G1  ); /* p[1] = -G1        */
  fd_bls_ref_g2_to_fd_bls( q,   b1                  ); /* q[0] = H(msg)     */
  fd_bls_ref_g2_to_fd_bls( q+1, b2                  ); /* q[1] = signature  */
  return fd_bls_pairing_finalverify( p, q, 2UL )==1 ? 0 : -1; /* e(pk,H(msg)) e(-G1,sig) = 1 */
}
