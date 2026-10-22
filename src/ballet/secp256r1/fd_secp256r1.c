#include "fd_secp256r1_private.h"

#define PCURVE_NAME       fd_secp256r1
#define PCURVE_SCALAR_SZ  32
#define PCURVE_SCALAR_T   fd_secp256r1_scalar_t
#define PCURVE_POINT_T    fd_secp256r1_point_t
#define PCURVE_SHA_NAME   fd_sha256
#define PCURVE_SHA_T      fd_sha256_t
#define PCURVE_SHA_SZ     FD_SHA256_HASH_SZ
#define PCURVE_SUCCESS    FD_SECP256R1_SUCCESS
#define PCURVE_FAILURE    FD_SECP256R1_FAILURE

#include "../pcurves/fd_pcurve_tmpl.c"

/* Syscalls */

/* Loads a 32 byte integer, big or little endian, as plain limbs. */
static inline fd_uint256_t *
fd_secp256r1_uint256_frombytes( fd_uint256_t * r,
                                uchar const    in[ 32 ],
                                int            big_endian ) {
  memcpy( r->buf, in, 32 );
  if( big_endian ) fd_uint256_bswap( r, r );
  return r;
}

static inline uchar *
fd_secp256r1_uint256_tobytes( uchar                out[ 32 ],
                              fd_uint256_t const * a,
                              int                  big_endian ) {
  fd_uint256_t t[1];
  if( big_endian ) a = fd_uint256_bswap( t, a );
  memcpy( out, a->buf, 32 );
  return out;
}

/* Loads a scalar, NULL if not canonical (>= n). */
static inline fd_secp256r1_scalar_t *
fd_secp256r1_scalar_frombytes_syscall( fd_secp256r1_scalar_t * r,
                                       uchar const             in[ 32 ],
                                       int                     big_endian ) {
  fd_secp256r1_uint256_frombytes( r, in, big_endian );
  if( FD_LIKELY( fd_uint256_cmp( r, fd_secp256r1_const_n )<0 ) ) return r;
  return NULL;
}

/* Decodes x || y into affine-Montgomery (x, y) as 8 limbs.  64 zero
   bytes decode to (0, 0), infinity.  Returns NULL if a coordinate is
   not canonical (>= p) or the point is not on the curve. */
static ulong *
fd_secp256r1_affine_frombytes( ulong       r[ 8 ],
                               uchar const in[ 64 ],
                               int         big_endian ) {
  fd_secp256r1_fp_t x[1], y[1];
  fd_secp256r1_uint256_frombytes( x, in,    big_endian );
  fd_secp256r1_uint256_frombytes( y, in+32, big_endian );

  if( FD_UNLIKELY( fd_uint256_is_zero( x ) & fd_uint256_is_zero( y ) ) ) {
    memset( r, 0, 64 );
    return r;
  }
  if( FD_UNLIKELY( fd_uint256_cmp( x, fd_secp256r1_const_p )>=0 ) ) return NULL;
  if( FD_UNLIKELY( fd_uint256_cmp( y, fd_secp256r1_const_p )>=0 ) ) return NULL;

  fd_secp256r1_fp_tomont( x, x );
  fd_secp256r1_fp_tomont( y, y );
  if( FD_UNLIKELY( !fd_secp256r1_point_on_curve( x, y ) ) ) return NULL;

  memcpy( r,   x->limbs, 32 );
  memcpy( r+4, y->limbs, 32 );
  return r;
}

/* Encodes affine-Montgomery (x, y) as x || y.  (0, 0) encodes to 64
   zero bytes. */
static uchar *
fd_secp256r1_affine_tobytes( uchar       out[ 64 ],
                             ulong const a[ 8 ],
                             int         big_endian ) {
  fd_secp256r1_fp_t x[1], y[1];
  memcpy( x->limbs, a,   32 );
  memcpy( y->limbs, a+4, 32 );
  fd_secp256r1_fp_demont( x, x );
  fd_secp256r1_fp_demont( y, y );
  fd_secp256r1_uint256_tobytes( out,    x, big_endian );
  fd_secp256r1_uint256_tobytes( out+32, y, big_endian );
  return out;
}

static inline fd_secp256r1_point_t *
fd_secp256r1_point_from_affine( fd_secp256r1_point_t * r,
                                ulong const            a[ 8 ] ) {
  memcpy( r->x->limbs, a,   32 );
  memcpy( r->y->limbs, a+4, 32 );
  if( FD_UNLIKELY( fd_uint256_is_zero( r->x ) & fd_uint256_is_zero( r->y ) ) ) {
    fd_secp256r1_point_set_inf( r );
  } else {
    fd_secp256r1_fp_set( r->z, fd_secp256r1_const_one_mont );
  }
  return r;
}

static inline uchar *
fd_secp256r1_point_tobytes_syscall( uchar                        out[ 64 ],
                                    fd_secp256r1_point_t const * a,
                                    int                          big_endian ) {
  ulong aff[ 8 ];
  fd_secp256r1_point_toaffine_mont( aff, a );
  return fd_secp256r1_affine_tobytes( out, aff, big_endian );
}

int
fd_secp256r1_validate_syscall( uchar const _a[ 64 ],
                               int         big_endian ) {
  ulong a[ 8 ];
  return !!fd_secp256r1_affine_frombytes( a, _a, big_endian );
}

int
fd_secp256r1_decompress_syscall( uchar       _r[ 64 ],
                                 uchar const _a[ 33 ],
                                 int         big_endian ) {
  /* fd_secp256r1_point_frombytes expects big endian x */
  uchar be[ 33 ];
  if( !big_endian ) {
    be[ 0 ] = _a[ 0 ];
    for( ulong i=0UL; i<32UL; i++ ) be[ 1UL+i ] = _a[ 32UL-i ];
    _a = be;
  }

  fd_secp256r1_point_t a[1];
  if( FD_UNLIKELY( !fd_secp256r1_point_frombytes( a, _a ) ) ) {
    return -1;
  }

  fd_secp256r1_point_tobytes_syscall( _r, a, big_endian );
  return 0;
}

int
fd_secp256r1_add_syscall( uchar       _r[ 64 ],
                          uchar const _a[ 64 ],
                          uchar const _b[ 64 ],
                          int         big_endian ) {
  ulong a[ 8 ], b[ 8 ];
  if( FD_UNLIKELY( !fd_secp256r1_affine_frombytes( a, _a, big_endian ) ) ) {
    return -1;
  }
  if( FD_UNLIKELY( !fd_secp256r1_affine_frombytes( b, _b, big_endian ) ) ) {
    return -1;
  }

  fd_secp256r1_point_t r[1];
  fd_secp256r1_point_from_affine( r, a );
  fd_secp256r1_point_add_mixed( r, r, b );

  fd_secp256r1_point_tobytes_syscall( _r, r, big_endian );
  return 0;
}

int
fd_secp256r1_sub_syscall( uchar       _r[ 64 ],
                          uchar const _a[ 64 ],
                          uchar const _b[ 64 ],
                          int         big_endian ) {
  ulong a[ 8 ], b[ 8 ];
  if( FD_UNLIKELY( !fd_secp256r1_affine_frombytes( a, _a, big_endian ) ) ) {
    return -1;
  }
  if( FD_UNLIKELY( !fd_secp256r1_affine_frombytes( b, _b, big_endian ) ) ) {
    return -1;
  }

  /* -b, it works also with b=0 */
  fd_secp256r1_fp_t y[1];
  memcpy( y->limbs, b+4, 32 );
  fd_secp256r1_fp_neg( y, y );
  memcpy( b+4, y->limbs, 32 );

  fd_secp256r1_point_t r[1];
  fd_secp256r1_point_from_affine( r, a );
  fd_secp256r1_point_add_mixed( r, r, b );

  fd_secp256r1_point_tobytes_syscall( _r, r, big_endian );
  return 0;
}

int
fd_secp256r1_mul_syscall( uchar       _r[ 64 ],
                          uchar const _n[ 32 ],
                          uchar const _a[ 64 ],
                          int         big_endian ) {
  fd_secp256r1_scalar_t n[1];
  ulong a[ 8 ];
  if( FD_UNLIKELY( !fd_secp256r1_scalar_frombytes_syscall( n, _n, big_endian ) ) ) {
    return -1;
  }
  if( FD_UNLIKELY( !fd_secp256r1_affine_frombytes( a, _a, big_endian ) ) ) {
    return -1;
  }

  fd_secp256r1_point_t p[1], r[1];
  fd_secp256r1_point_from_affine( p, a );
  fd_secp256r1_point_scalarmul( r, n->limbs, p );

  fd_secp256r1_point_tobytes_syscall( _r, r, big_endian );
  return 0;
}

/* Points per MSM batch, bounds the stack: 32*16*64B = 32kB of tables. */
#define FD_SECP256R1_MSM_BATCH_SZ 32UL

/* tbl[k] = k*P for k in [0,16), affine-Montgomery, (0,0) for infinity.
   Entries are computed in Jacobian and normalized with one inversion. */
static void
fd_secp256r1_msm_table( ulong       tbl[ 16 ][ 8 ],
                        ulong const p[ 8 ] ) {
  fd_secp256r1_point_t jac[ 16 ];
  fd_secp256r1_point_from_affine( jac+1, p );
  if( FD_UNLIKELY( fd_secp256r1_point_is_inf( jac+1 ) ) ) {
    memset( tbl, 0, 16*64 );
    return;
  }
  for( ulong k=2UL; k<16UL; k++ ) {
    if( k&1UL ) fd_secp256r1_point_add_mixed( jac+k, jac+k-1, p );
    else        fd_secp256r1_point_double( jac+k, jac+(k>>1) );
  }

  /* P has prime order > 16, so no entry in [1,16) is infinity. */
  fd_secp256r1_fp_t acc[ 16 ], inv[1], zinv[1], zinv2[1], t[1];
  fd_secp256r1_fp_set( acc, fd_secp256r1_const_one_mont );
  for( ulong k=1UL; k<16UL; k++ ) fd_secp256r1_fp_mul( acc+k, acc+k-1, jac[k].z );
  fd_secp256r1_fp_inv( inv, acc+15 );
  for( ulong k=15UL; k; k-- ) {
    fd_secp256r1_fp_mul( zinv, inv, acc+k-1 );
    fd_secp256r1_fp_mul( inv, inv, jac[k].z );
    fd_secp256r1_fp_sqr( zinv2, zinv );
    fd_secp256r1_fp_mul( t, jac[k].x, zinv2 );  memcpy( tbl[k],   t->limbs, 32 );
    fd_secp256r1_fp_mul( t, zinv2, zinv );
    fd_secp256r1_fp_mul( t, t, jac[k].y );       memcpy( tbl[k]+4, t->limbs, 32 );
  }
  memset( tbl[0], 0, 64 );
}

/* Straus with 4-bit windows, variable time: inputs are public. */
int
fd_secp256r1_msm_syscall( uchar       _r[ 64 ],
                          uchar const _n[], /* 32*cnt */
                          uchar const _a[], /* 64*cnt */
                          ulong       cnt,
                          int         big_endian ) {
  fd_secp256r1_point_t r[1];
  fd_secp256r1_point_set_inf( r );

  for( ulong off=0UL; off<cnt; off+=FD_SECP256R1_MSM_BATCH_SZ ) {
    ulong bcnt = fd_ulong_min( cnt-off, FD_SECP256R1_MSM_BATCH_SZ );
    fd_secp256r1_scalar_t n[ FD_SECP256R1_MSM_BATCH_SZ ];
    ulong tbl[ FD_SECP256R1_MSM_BATCH_SZ ][ 16 ][ 8 ];

    for( ulong i=0UL; i<bcnt; i++ ) {
      ulong a[ 8 ];
      if( FD_UNLIKELY( !fd_secp256r1_scalar_frombytes_syscall( n+i, _n+32UL*(off+i), big_endian ) ) ) {
        return -1;
      }
      if( FD_UNLIKELY( !fd_secp256r1_affine_frombytes( a, _a+64UL*(off+i), big_endian ) ) ) {
        return -1;
      }
      fd_secp256r1_msm_table( tbl[i], a );
    }

    fd_secp256r1_point_t acc[1];
    fd_secp256r1_point_set_inf( acc );
    for( ulong w=64UL; w; w-- ) { /* nibbles, most significant first */
      if( FD_LIKELY( !fd_secp256r1_point_is_inf( acc ) ) ) {
        fd_secp256r1_point_double( acc, acc );
        fd_secp256r1_point_double( acc, acc );
        fd_secp256r1_point_double( acc, acc );
        fd_secp256r1_point_double( acc, acc );
      }
      for( ulong i=0UL; i<bcnt; i++ ) {
        ulong d = ( n[i].limbs[ (w-1UL)>>4 ] >> ( 4UL*((w-1UL)&15UL) ) ) & 15UL;
        if( d ) fd_secp256r1_point_add_mixed( acc, acc, tbl[i][d] );
      }
    }
    fd_secp256r1_point_add( r, r, acc );
  }

  fd_secp256r1_point_tobytes_syscall( _r, r, big_endian );
  return 0;
}
