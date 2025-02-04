#include <stdint.h>
#include <s2n-bignum.h>

#include "fd_secp256r1_table.c"

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

static inline void
fd_secp256r1_double_scalar_mul_base( fd_secp256r1_point_t *        r,
                                     fd_secp256r1_scalar_t const * u1,
                                     fd_secp256r1_point_t const *  a,
                                     fd_secp256r1_scalar_t const * u2 ) {
  /* u1*G + u2*A */
  ulong rtmp[ 8 ];
  p256_scalarmulbase( rtmp, (ulong *)u1->limbs, 6, (ulong *)fd_secp256r1_base_point_table );
  bignum_tomont_p256( rtmp, rtmp );
  bignum_tomont_p256( rtmp+4, rtmp+4 );

  p256_montjscalarmul( (ulong *)r, (ulong *)u2->limbs, (ulong *)a );

  p256_montjmixadd( (ulong *)r, (ulong *)r, rtmp );
}
