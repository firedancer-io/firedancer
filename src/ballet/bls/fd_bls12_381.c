#include "fd_bls12_381.h"
#include "../bigint/fd_uint256.h"

#include <blst.h>

/* Scalar */

typedef blst_scalar fd_bls12_381_scalar_t;

static inline fd_bls12_381_scalar_t *
fd_bls12_381_scalar_frombytes( fd_bls12_381_scalar_t * n,
                               uchar const             in[ 32 ],
                               int                     big_endian ) {
  /* https://github.com/filecoin-project/blstrs/blob/v0.7.1/src/scalar.rs#L551-L569 */
  if( big_endian ) {
    blst_scalar_from_bendian( n, in );
  } else {
    blst_scalar_from_lendian( n, in );
  }
  if( FD_UNLIKELY( !blst_scalar_fr_check( n ) ) ) {
    return NULL;
  }
  return n;
}

/* G1 serde */

typedef blst_p1_affine fd_bls12_381_g1aff_t;
typedef blst_p1        fd_bls12_381_g1_t;

static inline void
fd_bls12_381_g1_bswap( uchar       out[ 96 ], /* out can be in */
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
fd_bls12_381_g1_tobytes( uchar                     out[ 96 ],
                         fd_bls12_381_g1_t const * a,
                         int                       big_endian ) {
  blst_p1_serialize( out, a );
  if( !big_endian ) {
    fd_bls12_381_g1_bswap( out, out );
  }
  return out;
}

static inline fd_bls12_381_g1aff_t *
fd_bls12_381_g1_frombytes_unchecked( fd_bls12_381_g1aff_t * r,
                                     uchar const            _in[ 96 ],
                                     int                    big_endian ) {
  ulong be[ 96/sizeof(ulong) ];
  uchar const * in = _in;
  if( !big_endian ) {
    fd_bls12_381_g1_bswap( (uchar *)be, _in );
    in = (uchar *)be;
  }
  if( FD_UNLIKELY( blst_p1_deserialize( r, in )!=BLST_SUCCESS ) ) {
    return NULL;
  }
  return r;
}

static inline fd_bls12_381_g1aff_t *
fd_bls12_381_g1_frombytes( fd_bls12_381_g1aff_t * r,
                           uchar const            in[ 96 ],
                           int                    big_endian ) {
  if( FD_UNLIKELY( !fd_bls12_381_g1_frombytes_unchecked( r, in, big_endian ) ) ) {
    return NULL;
  }
  if( FD_UNLIKELY( !blst_p1_affine_in_g1( r ) ) ) {
    return NULL;
  }
  return r;
}

/* G1 syscalls */

int
fd_bls12_381_g1_decompress_syscall( uchar       _r[ 96 ],
                                    uchar const _a[ 48 ],
                                    int         big_endian ) {
  /* blst expects input in big endian. if little endian, bswap. */
  ulong be[ 48/sizeof(ulong) ];
  uchar const * in = _a;
  if( !big_endian ) {
    in = (uchar *)be;
    memcpy( be, _a, 48 );
    fd_ulong_n_bswap( be, 6 );
  }

  /* decompress and serialize */
  fd_bls12_381_g1aff_t r[1];
  if( FD_UNLIKELY( blst_p1_uncompress( r, in )!=BLST_SUCCESS ) ) {
    return -1;
  }
  if( FD_UNLIKELY( !blst_p1_affine_in_g1( r ) ) ) {
    return -1;
  }
  blst_p1_affine_serialize( _r, r );

  /* blst output is big endian. if we want little endian, bswap. */
  if( !big_endian ) {
    fd_bls12_381_g1_bswap( _r, _r );
  }
  return 0;
}

int
fd_bls12_381_g1_validate_syscall( uchar const _a[ 96 ],
                                  int         big_endian ) {
  fd_bls12_381_g1aff_t a[1];
  return fd_bls12_381_g1_frombytes( a, _a, big_endian )!=NULL ? 0 : -1;
}

int
fd_bls12_381_g1_add_syscall( uchar       _r[ 96 ],
                             uchar const _a[ 96 ],
                             uchar const _b[ 96 ],
                             int         big_endian ) {
  /* points a, b are unchecked per SIMD-0388 */
  fd_bls12_381_g1aff_t a[1], b[1];
  if( FD_UNLIKELY( fd_bls12_381_g1_frombytes_unchecked( a, _a, big_endian )==NULL ) ) {
    return -1;
  }
  if( FD_UNLIKELY( fd_bls12_381_g1_frombytes_unchecked( b, _b, big_endian )==NULL ) ) {
    return -1;
  }

  fd_bls12_381_g1_t r[1], p[1];
  blst_p1_from_affine( p, a );
  blst_p1_add_or_double_affine( r, p, b );

  fd_bls12_381_g1_tobytes( _r, r, big_endian );
  return 0;
}

int
fd_bls12_381_g1_sub_syscall( uchar       _r[ 96 ],
                             uchar const _a[ 96 ],
                             uchar const _b[ 96 ],
                             int         big_endian ) {
  /* points a, b are unchecked per SIMD-0388 */
  fd_bls12_381_g1aff_t a[1], b[1];
  if( FD_UNLIKELY( fd_bls12_381_g1_frombytes_unchecked( a, _a, big_endian )==NULL ) ) {
    return -1;
  }
  if( FD_UNLIKELY( fd_bls12_381_g1_frombytes_unchecked( b, _b, big_endian )==NULL ) ) {
    return -1;
  }

  fd_bls12_381_g1_t r[1], p[1];
  blst_p1_from_affine( p, a );
  blst_fp_cneg( &b->y, &b->y, 1 ); /* -b, it works also with b=0 */
  blst_p1_add_or_double_affine( r, p, b );

  fd_bls12_381_g1_tobytes( _r, r, big_endian );
  return 0;
}

int
fd_bls12_381_g1_mul_syscall( uchar       _r[ 96 ],
                             uchar const _a[ 96 ],
                             uchar const _n[ 32 ],
                             int         big_endian ) {
  /* point a, scalar n are validated per SIMD-0388 */
  fd_bls12_381_g1aff_t a[1];
  fd_bls12_381_scalar_t n[1];
  if( FD_UNLIKELY( fd_bls12_381_g1_frombytes( a, _a, big_endian )==NULL ) ) {
    return -1;
  }
  if( FD_UNLIKELY( fd_bls12_381_scalar_frombytes( n, _n, big_endian )==NULL ) ) {
    return -1;
  }

  fd_bls12_381_g1_t r[1], p[1];
  blst_p1_from_affine( p, a );
  /* https://github.com/filecoin-project/blstrs/blob/v0.7.1/src/g1.rs#L578-L580 */
  blst_p1_mult( r, p, n->b, 255 );

  fd_bls12_381_g1_tobytes( _r, r, big_endian );
  return 0;
}

/* G2 serde */

typedef blst_p2_affine fd_bls12_381_g2aff_t;
typedef blst_p2        fd_bls12_381_g2_t;

static inline void
fd_bls12_381_g2_bswap( uchar       out[ 96*2 ], /* out can be in */
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
fd_bls12_381_g2_tobytes( uchar                     out[ 96*2 ],
                         fd_bls12_381_g2_t const * a,
                         int                       big_endian ) {
  blst_p2_serialize( out, a );
  if( !big_endian ) {
    fd_bls12_381_g2_bswap( out, out );
  }
  return out;
}

static inline fd_bls12_381_g2aff_t *
fd_bls12_381_g2_frombytes_unchecked( fd_bls12_381_g2aff_t * r,
                                     uchar const            _in[ 96*2 ],
                                     int                    big_endian ) {
  ulong be[ 96*2/sizeof(ulong) ];
  uchar const * in = _in;
  if( !big_endian ) {
    fd_bls12_381_g2_bswap( (uchar *)be, _in );
    in = (uchar *)be;
  }
  if( FD_UNLIKELY( blst_p2_deserialize( r, in )!=BLST_SUCCESS ) ) {
    return NULL;
  }
  return r;
}

static inline fd_bls12_381_g2aff_t *
fd_bls12_381_g2_frombytes( fd_bls12_381_g2aff_t * r,
                           uchar const            in[ 96*2 ],
                           int                    big_endian ) {
  if( FD_UNLIKELY( !fd_bls12_381_g2_frombytes_unchecked( r, in, big_endian ) ) ) {
    return NULL;
  }
  if( FD_UNLIKELY( !blst_p2_affine_in_g2( r ) ) ) {
    return NULL;
  }
  return r;
}

/* G2 syscalls */

int
fd_bls12_381_g2_decompress_syscall( uchar       _r[ 96*2 ],
                                    uchar const _a[ 48*2 ],
                                    int         big_endian ) {
  /* blst expects input in big endian. if little endian, bswap. */
  ulong be[ 48*2/sizeof(ulong) ];
  uchar const * in = _a;
  if( !big_endian ) {
    in = (uchar *)be;
    memcpy( be, _a, 48*2 );
    fd_ulong_n_bswap( be, 6*2 );
  }

  /* decompress and serialize */
  fd_bls12_381_g2aff_t r[1];
  if( FD_UNLIKELY( blst_p2_uncompress( r, in )!=BLST_SUCCESS ) ) {
    return -1;
  }
  if( FD_UNLIKELY( !blst_p2_affine_in_g2( r ) ) ) {
    return -1;
  }
  blst_p2_affine_serialize( _r, r );

  /* blst output is big endian. if we want little endian, bswap. */
  if( !big_endian ) {
    fd_bls12_381_g2_bswap( _r, _r );
  }
  return 0;
}

int
fd_bls12_381_g2_validate_syscall( uchar const _a[ 96*2 ],
                                  int         big_endian ) {
  fd_bls12_381_g2aff_t a[1];
  return fd_bls12_381_g2_frombytes( a, _a, big_endian )!=NULL ? 0 : -1;
}

int
fd_bls12_381_g2_add_syscall( uchar       _r[ 96*2 ],
                             uchar const _a[ 96*2 ],
                             uchar const _b[ 96*2 ],
                             int         big_endian ) {
  /* points a, b are unchecked per SIMD-0388 */
  fd_bls12_381_g2aff_t a[1], b[1];
  if( FD_UNLIKELY( fd_bls12_381_g2_frombytes_unchecked( a, _a, big_endian )==NULL ) ) {
    return -1;
  }
  if( FD_UNLIKELY( fd_bls12_381_g2_frombytes_unchecked( b, _b, big_endian )==NULL ) ) {
    return -1;
  }

  fd_bls12_381_g2_t r[1], p[1];
  blst_p2_from_affine( p, a );
  blst_p2_add_or_double_affine( r, p, b );

  fd_bls12_381_g2_tobytes( _r, r, big_endian );
  return 0;
}

int
fd_bls12_381_g2_sub_syscall( uchar       _r[ 96*2 ],
                             uchar const _a[ 96*2 ],
                             uchar const _b[ 96*2 ],
                             int         big_endian ) {
  /* points a, b are unchecked per SIMD-0388 */
  fd_bls12_381_g2aff_t a[1], b[1];
  if( FD_UNLIKELY( fd_bls12_381_g2_frombytes_unchecked( a, _a, big_endian )==NULL ) ) {
    return -1;
  }
  if( FD_UNLIKELY( fd_bls12_381_g2_frombytes_unchecked( b, _b, big_endian )==NULL ) ) {
    return -1;
  }

  fd_bls12_381_g2_t r[1], p[1];
  blst_p2_from_affine( p, a );
  blst_fp2_cneg( &b->y, &b->y, 1 ); /* -b, it works also with b=0 */
  blst_p2_add_or_double_affine( r, p, b );

  fd_bls12_381_g2_tobytes( _r, r, big_endian );
  return 0;
}

int
fd_bls12_381_g2_mul_syscall( uchar       _r[ 96*2 ],
                             uchar const _a[ 96*2 ],
                             uchar const _n[ 32 ],
                             int         big_endian ) {
  /* point a, scalar n are validated per SIMD-0388 */
  fd_bls12_381_g2aff_t a[1];
  fd_bls12_381_scalar_t n[1];
  if( FD_UNLIKELY( fd_bls12_381_g2_frombytes( a, _a, big_endian )==NULL ) ) {
    return -1;
  }
  if( FD_UNLIKELY( fd_bls12_381_scalar_frombytes( n, _n, big_endian )==NULL ) ) {
    return -1;
  }

  fd_bls12_381_g2_t r[1], p[1];
  blst_p2_from_affine( p, a );
  /* https://github.com/filecoin-project/blstrs/blob/v0.7.1/src/g2.rs#L545-L547 */
  blst_p2_mult( r, p, n->b, 255 );

  fd_bls12_381_g2_tobytes( _r, r, big_endian );
  return 0;
}

int
fd_bls12_381_pairing_syscall( uchar       _r[ 48*12 ],
                              uchar const _a[], /* 96*n */
                              uchar const _b[], /* 96*2*n */
                              ulong const _n,
                              int         big_endian ) {

  if( FD_UNLIKELY( _n>FD_BLS12_381_PAIRING_BATCH_SZ ) ) {
    return -1;
  }

  fd_bls12_381_g1aff_t a[ FD_BLS12_381_PAIRING_BATCH_SZ ];
  fd_bls12_381_g2aff_t b[ FD_BLS12_381_PAIRING_BATCH_SZ ];
  fd_bls12_381_g1aff_t const * aptr[ FD_BLS12_381_PAIRING_BATCH_SZ ];
  fd_bls12_381_g2aff_t const * bptr[ FD_BLS12_381_PAIRING_BATCH_SZ ];
  ulong n = 0;
  for( ulong j=0; j<_n; j++ ) {
    if( FD_UNLIKELY( fd_bls12_381_g1_frombytes( &a[ n ], _a+96*j, big_endian )==NULL ) ) {
      return -1;
    }
    if( FD_UNLIKELY( fd_bls12_381_g2_frombytes( &b[ n ], _b+96*2*j, big_endian )==NULL ) ) {
      return -1;
    }
    /* blst wants an array of pointers (not necessarily a compact array) */
    aptr[ n ] = &a[ n ];
    bptr[ n ] = &b[ n ];
    ++n;
  }

  blst_fp12 r[1];
  memcpy( r, blst_fp12_one(), sizeof(blst_fp12) );

  if( FD_LIKELY ( n>0 ) ) {
    blst_miller_loop_n( r, bptr, aptr, n );
    blst_final_exp( r, r );
  }

  if( big_endian ) {
    for( ulong j=0; j<12; j++ ) {
      blst_bendian_from_fp( _r+48*(12-1-j), &r[ 0 ].fp6[ j/6 ].fp2[ (j/2)%3 ].fp[ j%2 ] );
    }
  } else {
    for( ulong j=0; j<12; j++ ) {
      blst_lendian_from_fp( _r+48*j, &r[ 0 ].fp6[ j/6 ].fp2[ (j/2)%3 ].fp[ j%2 ] );
    }
  }

  return 0;
}
