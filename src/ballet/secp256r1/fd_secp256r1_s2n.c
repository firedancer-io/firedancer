#include <stdint.h>
#include <s2n-bignum.h>

/* On CPUs without ADX (mulx/adcx/adox), redirect the ADX-optimized
   s2n-bignum symbols to their _alt equivalents, which use only base
   x86-64 instructions and are functionally identical. */
#ifndef __ADX__
#define bignum_demont_p256     bignum_demont_p256_alt
#define bignum_mod_n256        bignum_mod_n256_alt
#define bignum_montmul_p256    bignum_montmul_p256_alt
#define bignum_montsqr_p256    bignum_montsqr_p256_alt
#define bignum_mul_4_8         bignum_mul_4_8_alt
#define bignum_tomont_p256     bignum_tomont_p256_alt
#define p256_montjadd          p256_montjadd_alt
#define p256_montjdouble       p256_montjdouble_alt
#define p256_montjmixadd       p256_montjmixadd_alt
#endif

#include "fd_secp256r1_base_table.c"

/* Scalars */

static inline int
fd_secp256r1_scalar_is_zero( fd_secp256r1_scalar_t const * a ) {
  return fd_uint256_eq( a, fd_secp256r1_const_zero );
}

static inline fd_secp256r1_scalar_t *
fd_secp256r1_scalar_frombytes( fd_secp256r1_scalar_t * r,
                               uchar const             in[ 32 ] ) {
  memcpy( r->buf, in, 32 );
  fd_uint256_bswap( r, r );
  if( FD_LIKELY( fd_uint256_cmp( r, fd_secp256r1_const_n )<0 ) ) {
    return r;
  };
  return NULL;
}

static inline fd_secp256r1_scalar_t *
fd_secp256r1_scalar_frombytes_positive( fd_secp256r1_scalar_t * r,
                                        uchar const             in[ 32 ] ) {
  memcpy( r->buf, in, 32 );
  fd_uint256_bswap( r, r );
  if( FD_LIKELY( fd_uint256_cmp( r, fd_secp256r1_const_n_m1_half )<=0 ) ) {
    return r;
  };
  return NULL;
}

static inline void
fd_secp256r1_scalar_from_digest( fd_secp256r1_scalar_t * r,
                                 uchar const             in[ 32 ] ) {
  memcpy( r->buf, in, 32 );
  fd_uint256_bswap( r, r );
  bignum_mod_n256_4( r->limbs, r->limbs );
}

static inline fd_secp256r1_scalar_t *
fd_secp256r1_scalar_mul( fd_secp256r1_scalar_t *       r,
                         fd_secp256r1_scalar_t const * a,
                         fd_secp256r1_scalar_t const * b ) {
  ulong t[ 8 ];
  bignum_mul_4_8( t, (ulong *)a->limbs, (ulong *)b->limbs );
  bignum_mod_n256( r->limbs, 8, t );
  return r;
}

static inline fd_secp256r1_scalar_t *
fd_secp256r1_scalar_inv( fd_secp256r1_scalar_t       * r,
                         fd_secp256r1_scalar_t const * a ) {
  ulong t[ 12 ];
  bignum_modinv( 4, r->limbs, (ulong *)a->limbs, (ulong *)fd_secp256r1_const_n[0].limbs, t );
  return r;
}

/* Field */

static inline fd_secp256r1_fp_t *
fd_secp256r1_fp_set( fd_secp256r1_fp_t * r,
                     fd_secp256r1_fp_t const * a ) {
  r->limbs[0] = a->limbs[0];
  r->limbs[1] = a->limbs[1];
  r->limbs[2] = a->limbs[2];
  r->limbs[3] = a->limbs[3];
  return r;
}

static inline fd_secp256r1_fp_t *
fd_secp256r1_fp_frombytes( fd_secp256r1_fp_t * r,
                           uchar const             in[ 32 ] ) {
  memcpy( r->buf, in, 32 );
  fd_uint256_bswap( r, r );
  if( FD_LIKELY( fd_uint256_cmp( r, fd_secp256r1_const_p )<0 ) ) {
    return r;
  };
  return NULL;
}

static inline fd_secp256r1_fp_t *
fd_secp256r1_fp_sqrt( fd_secp256r1_fp_t *       r,
                      fd_secp256r1_fp_t const * a ) {
  /* https://github.com/golang/go/blob/master/src/crypto/internal/fips140/nistec/p256.go#L656 */
  fd_secp256r1_fp_t _t0[1], _t1[1];
  ulong * t0 = _t0->limbs;
  ulong * t1 = _t1->limbs;
  ulong * x = (ulong *)a->limbs;

  bignum_montsqr_p256( t0, x );
  bignum_montmul_p256( t0, t0, x );
  bignum_montsqr_p256( t1, t0 ); for( int i=1; i<2; i++ ) bignum_montsqr_p256( t1, t1 );
  bignum_montmul_p256( t0, t0, t1);
  bignum_montsqr_p256( t1, t0 ); for( int i=1; i<4; i++ ) bignum_montsqr_p256( t1, t1 );
  bignum_montmul_p256( t0, t0, t1);
  bignum_montsqr_p256( t1, t0 ); for( int i=1; i<8; i++ ) bignum_montsqr_p256( t1, t1 );
  bignum_montmul_p256( t0, t0, t1);
  bignum_montsqr_p256( t1, t0 ); for( int i=1; i<16; i++ ) bignum_montsqr_p256( t1, t1 );
  bignum_montmul_p256( t0, t0, t1);
  for( int i=0; i<32; i++ ) bignum_montsqr_p256( t0, t0 );
  bignum_montmul_p256( t0, t0, x );
  for( int i=0; i<96; i++ ) bignum_montsqr_p256( t0, t0 );
  bignum_montmul_p256( t0, t0, x );
  for( int i=0; i<94; i++ ) bignum_montsqr_p256( t0, t0 );

  bignum_montsqr_p256( t1, t0 );
  if( FD_UNLIKELY( !fd_uint256_eq( _t1, a ) ) ) {
    return NULL;
  }

  return fd_secp256r1_fp_set( r, _t0 );
}

/* Points */

static inline fd_secp256r1_point_t *
fd_secp256r1_point_frombytes( fd_secp256r1_point_t * r,
                              uchar const            in[ 33 ] ) {
  fd_secp256r1_fp_t y2[1], demont_y[1];

  uchar sgn = in[0];
  if( FD_UNLIKELY( sgn!=2U && sgn!=3U ) ) {
    return FD_SECP256R1_FAILURE;
  }

  if( FD_UNLIKELY( !fd_secp256r1_fp_frombytes( r->x, in+1 ) ) ) {
    return FD_SECP256R1_FAILURE;
  }

  bignum_tomont_p256( r->x->limbs, r->x->limbs );

  /* y^2 = x^3 + ax + b */
  bignum_montsqr_p256( y2->limbs, r->x->limbs );
  bignum_add_p256    ( y2->limbs, y2->limbs, (ulong *)fd_secp256r1_const_a_mont[0].limbs );
  bignum_montmul_p256( y2->limbs, y2->limbs, r->x->limbs );
  bignum_add_p256    ( y2->limbs, y2->limbs, (ulong *)fd_secp256r1_const_b_mont[0].limbs );

  /* y = sqrt(y^2) */
  if( FD_UNLIKELY( !fd_secp256r1_fp_sqrt( r->y, y2 ) ) ) {
    return FD_SECP256R1_FAILURE;
  }

  /* choose y or -y */
  bignum_demont_p256( demont_y->limbs, r->y->limbs );
  ulong cond = (demont_y->limbs[0] % 2) != (sgn == 3U);
  bignum_optneg_p256( r->y->limbs, cond, r->y->limbs );

  fd_secp256r1_fp_set( r->z, fd_secp256r1_const_one_mont );

  return r;
}

static inline int
fd_secp256r1_point_eq_x( fd_secp256r1_point_t const *  p,
                         fd_secp256r1_scalar_t const * r ) {
  fd_secp256r1_fp_t affine_x[1];
  fd_secp256r1_scalar_t * affine_x_mod_n = affine_x;

  if( FD_UNLIKELY( fd_uint256_eq( p->z, fd_secp256r1_const_zero ) ) ) {
    return FD_SECP256R1_FAILURE;
  }

  /* x = demont(X / Z^2) mod n */
  bignum_montinv_p256( affine_x->limbs, (ulong *)p->z->limbs );
  bignum_montsqr_p256( affine_x->limbs, affine_x->limbs );
  bignum_montmul_p256( affine_x->limbs, affine_x->limbs, (ulong *)p->x->limbs );
  bignum_demont_p256( affine_x_mod_n->limbs, affine_x->limbs );
  bignum_mod_n256_4 ( affine_x_mod_n->limbs, affine_x_mod_n->limbs );

  if( FD_LIKELY( fd_uint256_eq( r, affine_x_mod_n ) ) ) {
    return FD_SECP256R1_SUCCESS;
  }
  return FD_SECP256R1_FAILURE;
}

/* Point operations in Montgomery Jacobian coordinates. */

/* r = a + b */
static inline fd_secp256r1_point_t *
fd_secp256r1_point_add( fd_secp256r1_point_t *       r,
                        fd_secp256r1_point_t const * a,
                        fd_secp256r1_point_t const * b ) {
  p256_montjadd( (ulong *)r, (ulong const *)a, (ulong const *)b );
  return r;
}

/* r = 2 * a */
static inline fd_secp256r1_point_t *
fd_secp256r1_point_dbl( fd_secp256r1_point_t *       r,
                        fd_secp256r1_point_t const * a ) {
  p256_montjdouble( (ulong *)r, (ulong const *)a );
  return r;
}

/* r = -a */
static inline fd_secp256r1_point_t *
fd_secp256r1_point_neg( fd_secp256r1_point_t *       r,
                        fd_secp256r1_point_t const * a ) {
  if( r != a ) fd_memcpy( r, a, sizeof(*r) );
  bignum_neg_p256( r->y->limbs, r->y->limbs );
  return r;
}

/* r = a - b */
static inline fd_secp256r1_point_t *
fd_secp256r1_point_sub( fd_secp256r1_point_t *       r,
                        fd_secp256r1_point_t const * a,
                        fd_secp256r1_point_t const * b ) {
  fd_secp256r1_point_t neg[1];
  fd_secp256r1_point_neg( neg, b );
  return fd_secp256r1_point_add( r, a, neg );
}

/* Given the projective point `a` and the affine point `b` (xy as 8 ulongs),
   returns 1 if they are equal and 0 otherwise.
   Assumes that `b` X and Y coordinates are in Montgomery domain. */
static inline int
fd_secp256r1_point_eq_mixed( fd_secp256r1_point_t const * a,
                             ulong                const   b[ 8 ] ) {
  if( FD_UNLIKELY( fd_uint256_eq( a->z, fd_secp256r1_const_zero ) ) ) {
    return fd_uint256_eq( (fd_uint256_t const *)b, fd_secp256r1_const_zero ) &
           fd_uint256_eq( (fd_uint256_t const *)(b+4), fd_secp256r1_const_zero );
  }
  fd_secp256r1_fp_t z1z1[1], temp[1];
  bignum_montsqr_p256( z1z1->limbs, (ulong *)a->z->limbs );
  bignum_montmul_p256( temp->limbs, (ulong *)b, z1z1->limbs );
  if( FD_UNLIKELY( fd_uint256_eq( a->x, temp ) ) ) {
    bignum_montmul_p256( temp->limbs, z1z1->limbs, (ulong *)a->z->limbs );
    bignum_montmul_p256( temp->limbs, temp->limbs, (ulong *)(b+4) );
    return fd_uint256_eq( a->y, temp );
  }
  return 0;
}

/* Mixed addition: a (Jacobian) + b (affine xy as 8 ulongs).
   Handles identity elements and the equal-point (doubling) case. */
static inline void
fd_secp256r1_point_add_mixed( fd_secp256r1_point_t *       r,
                              fd_secp256r1_point_t const * a,
                              ulong                const   b[ 8 ] ) {
  int b_is_zero = fd_uint256_eq( (fd_uint256_t const *)b, fd_secp256r1_const_zero ) &
                  fd_uint256_eq( (fd_uint256_t const *)(b+4), fd_secp256r1_const_zero );
  if( FD_UNLIKELY( b_is_zero ) ) {
    if( r != a ) fd_memcpy( r, a, sizeof(fd_secp256r1_point_t) );
    return;
  }
  if( FD_UNLIKELY( fd_secp256r1_point_eq_mixed( a, b ) ) ) {
    p256_montjdouble( (ulong *)r, (ulong const *)a );
  } else {
    p256_montjmixadd( (ulong *)r, (ulong const *)a, (ulong *)b );
  }
}

static inline void
fd_secp256r1_point_sub_mixed( fd_secp256r1_point_t *       r,
                              fd_secp256r1_point_t const * a,
                              ulong                const   b[ 8 ] ) {
  ulong neg[8];
  fd_memcpy( neg, b, 64 );
  bignum_neg_p256( neg+4, neg+4 );
  fd_secp256r1_point_add_mixed( r, a, neg );
}

/* Double base multiplication */

static inline schar *
fd_secp256r1_slide( schar       r[ 65 ],
                    uchar const s[ 32 ] ) {
  for( int i=0; i<32; i++ ) {
    r[i*2+0] = (schar)(s[i] & 0xF);
    r[i*2+1] = (schar)((s[i] >> 4) & 0xF);
  }
  /* Now, r[0..63] is between 0 and 15, r[63] is between 0 and 7 */
  schar carry = 0;
  for( int i=0; i<64; i++ ) {
    r[i] += carry;
    carry = (schar)(r[i] + 8) >> 4;
    r[i] -= (schar)(carry * 16);
    /* r[i] MUST be between [-8, 8] */
  }
  r[64] = carry;
  /* carry MUST be between [-8, 8] */
  return r;
}

static inline fd_secp256r1_point_t *
fd_secp256r1_precompute( fd_secp256r1_point_t         tbl[ 9 ],
                         fd_secp256r1_point_t const * a ) {
  fd_memset( &tbl[0], 0, sizeof(fd_secp256r1_point_t) );
  fd_memcpy( &tbl[1], a, sizeof(fd_secp256r1_point_t) );
  for( int i=2; i<=8; i++ ) {
    if( i & 1 ) {
      fd_secp256r1_point_add( &tbl[i], &tbl[i-1], a );
    } else {
      fd_secp256r1_point_dbl( &tbl[i], &tbl[i/2] );
    }
  }
  return tbl;
}

/* Computes u1*G + u2*A in Montgomery Jacobian coordinates. */
static inline void
fd_secp256r1_double_scalar_mul_base( fd_secp256r1_point_t *        r,
                                     fd_secp256r1_scalar_t const * u1,
                                     fd_secp256r1_point_t const *  a,
                                     fd_secp256r1_scalar_t const * u2 ) {
  schar e1[ 65 ];
  schar e2[ 65 ];
  fd_secp256r1_slide( e1, u1->buf );
  fd_secp256r1_slide( e2, u2->buf );

  /* Build runtime table for variable point */
  fd_secp256r1_point_t tbl[9];
  fd_secp256r1_precompute( tbl, a );

  fd_memset( r, 0, sizeof(*r) );

  for( int pos=64; ; pos-- ) {
    schar slot1 = e1[pos];
    if( slot1 > 0 ) {
      fd_secp256r1_point_add_mixed( r, r, fd_secp256r1_base_point_table[ (ulong)slot1 ].x->limbs );
    } else if( slot1 < 0 ) {
      fd_secp256r1_point_sub_mixed( r, r, fd_secp256r1_base_point_table[ (ulong)(-slot1) ].x->limbs );
    }

    schar slot2 = e2[pos];
    if( slot2 > 0 ) {
      fd_secp256r1_point_add( r, r, &tbl[ (ulong)slot2 ] );
    } else if( slot2 < 0 ) {
      fd_secp256r1_point_sub( r, r, &tbl[ (ulong)(-slot2) ] );
    }

    if( pos == 0 ) break;
    fd_secp256r1_point_dbl( r, r );
    fd_secp256r1_point_dbl( r, r );
    fd_secp256r1_point_dbl( r, r );
    fd_secp256r1_point_dbl( r, r );
  }
}

/* Converts Montgomery Jacobian (X/Z^2, Y/Z^3) to Montgomery affine. */
static inline fd_secp256r1_point_t *
fd_secp256r1_point_to_affine( fd_secp256r1_point_t *       r,
                              fd_secp256r1_point_t const * a ) {
  fd_secp256r1_fp_t z_inv[1], z_inv2[1], z_inv3[1];
  bignum_montinv_p256( z_inv->limbs, (ulong *)a->z->limbs );
  bignum_montsqr_p256( z_inv2->limbs, z_inv->limbs );
  bignum_montmul_p256( z_inv3->limbs, z_inv2->limbs, z_inv->limbs );
  bignum_montmul_p256( r->x->limbs, (ulong *)a->x->limbs, z_inv2->limbs );
  bignum_montmul_p256( r->y->limbs, (ulong *)a->y->limbs, z_inv3->limbs );
  return r;
}
