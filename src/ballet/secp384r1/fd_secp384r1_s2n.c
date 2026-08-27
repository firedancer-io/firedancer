#include <stdint.h>
#include "../../third_party/s2n-bignum/include/s2n-bignum.h"

#ifndef __ADX__
#define bignum_demont_p384     bignum_demont_p384_alt
#define bignum_mod_n384        bignum_mod_n384_alt
#define bignum_montmul_p384    bignum_montmul_p384_alt
#define bignum_montsqr_p384    bignum_montsqr_p384_alt
#define bignum_mul_6_12        bignum_mul_6_12_alt
#define bignum_tomont_p384     bignum_tomont_p384_alt
#define p384_montjdouble       p384_montjdouble_alt
#define p384_montjadd          p384_montjadd_alt
#define p384_montjmixadd       p384_montjmixadd_alt
#define p384_montjscalarmul    p384_montjscalarmul_alt
#endif

/* Scalars */

static inline int
fd_secp384r1_scalar_is_zero( fd_secp384r1_scalar_t const * a ) {
  return fd_uint384_is_zero( a );
}

static inline fd_secp384r1_scalar_t *
fd_secp384r1_scalar_frombytes( fd_secp384r1_scalar_t * r,
                               uchar const             in[ 48 ] ) {
  memcpy( r->buf, in, 48 );
  fd_uint384_bswap( r, r );
  if( FD_LIKELY( fd_uint384_cmp( r, fd_secp384r1_const_n )<0 ) )
    return r;
  return NULL;
}

static inline fd_secp384r1_scalar_t *
fd_secp384r1_scalar_frombytes_positive( fd_secp384r1_scalar_t * r,
                                        uchar const             in[ 48 ] ) {
  memcpy( r->buf, in, 48 );
  fd_uint384_bswap( r, r );
  if( FD_LIKELY( fd_uint384_cmp( r, fd_secp384r1_const_n_m1_half )<=0 ) )
    return r;
  return NULL;
}

static inline void
fd_secp384r1_scalar_from_digest( fd_secp384r1_scalar_t * r,
                                 uchar const             in[ 48 ] ) {
  memcpy( r->buf, in, 48 );
  fd_uint384_bswap( r, r );
  bignum_mod_n384_6( r->limbs, r->limbs );
}

static inline fd_secp384r1_scalar_t *
fd_secp384r1_scalar_mul( fd_secp384r1_scalar_t *       r,
                         fd_secp384r1_scalar_t const * a,
                         fd_secp384r1_scalar_t const * b ) {
  ulong t[ 12 ];
  bignum_mul_6_12( t, (ulong *)a->limbs, (ulong *)b->limbs );
  bignum_mod_n384( r->limbs, 12, t );
  return r;
}

static inline fd_secp384r1_scalar_t *
fd_secp384r1_scalar_inv( fd_secp384r1_scalar_t       * r,
                         fd_secp384r1_scalar_t const * a ) {
  ulong t[ 18 ];
  bignum_modinv( 6, r->limbs, (ulong *)a->limbs, (ulong *)fd_secp384r1_const_n[0].limbs, t );
  return r;
}

/* Field */

static inline fd_secp384r1_fp_t *
fd_secp384r1_fp_set( fd_secp384r1_fp_t * r,
                     fd_secp384r1_fp_t const * a ) {
  memcpy( r->limbs, a->limbs, 48 );
  return r;
}

static inline fd_secp384r1_fp_t *
fd_secp384r1_fp_frombytes( fd_secp384r1_fp_t * r,
                           uchar const         in[ 48 ] ) {
  memcpy( r->buf, in, 48 );
  fd_uint384_bswap( r, r );
  if( FD_LIKELY( fd_uint384_cmp( r, fd_secp384r1_const_p )<0 ) )
    return r;
  return NULL;
}

/* P-384 sqrt: p ≡ 3 (mod 4), so sqrt(a) = a^((p+1)/4) mod p. */
static inline fd_secp384r1_fp_t *
fd_secp384r1_fp_sqrt( fd_secp384r1_fp_t *       r,
                      fd_secp384r1_fp_t const * a ) {
  /* (p+1)/4 bit pattern (382 bits, MSB first):
     255 ones | 0 | 31 ones | 0 | 63 ones | 1 | 30 zeros */

  fd_secp384r1_fp_t _t0[1], _t1[1];
  ulong * t0 = _t0->limbs;
  ulong * t1 = _t1->limbs;
  ulong * x  = (ulong *)a->limbs;

  /* Build x^(2^k - 1) chain */
  fd_secp384r1_fp_t e2[1], e4[1], e8[1], e16[1], e32[1], e64[1], e128[1];

  /* x^3 */
  bignum_montsqr_p384( t0, x );
  bignum_montmul_p384( t0, t0, x );
  memcpy( e2, t0, 48 );

  /* x^(2^4-1) */
  for( int i=0; i<2; i++ ) bignum_montsqr_p384( t0, t0 );
  bignum_montmul_p384( t0, t0, e2->limbs );
  memcpy( e4, t0, 48 );

  /* x^(2^8-1) */
  memcpy( t1, t0, 48 );
  for( int i=0; i<4; i++ ) bignum_montsqr_p384( t1, t1 );
  bignum_montmul_p384( t0, t1, t0 );
  memcpy( e8, t0, 48 );

  /* x^(2^16-1) */
  memcpy( t1, t0, 48 );
  for( int i=0; i<8; i++ ) bignum_montsqr_p384( t1, t1 );
  bignum_montmul_p384( t0, t1, t0 );
  memcpy( e16, t0, 48 );

  /* x^(2^32-1) */
  memcpy( t1, t0, 48 );
  for( int i=0; i<16; i++ ) bignum_montsqr_p384( t1, t1 );
  bignum_montmul_p384( t0, t1, t0 );
  memcpy( e32, t0, 48 );

  /* x^(2^64-1) */
  memcpy( t1, t0, 48 );
  for( int i=0; i<32; i++ ) bignum_montsqr_p384( t1, t1 );
  bignum_montmul_p384( t0, t1, t0 );
  memcpy( e64, t0, 48 );

  /* x^(2^128-1) */
  memcpy( t1, t0, 48 );
  for( int i=0; i<64; i++ ) bignum_montsqr_p384( t1, t1 );
  bignum_montmul_p384( t0, t1, t0 );
  memcpy( e128, t0, 48 );

  /* x^(2^255-1): build from sub-chains */

  /* x^(2^3-1) = x^7 */
  bignum_montsqr_p384( t0, e2->limbs );
  bignum_montmul_p384( t0, t0, x );

  /* x^(2^7-1) */
  memcpy( t1, e4->limbs, 48 );
  for( int i=0; i<3; i++ ) bignum_montsqr_p384( t1, t1 );
  bignum_montmul_p384( t0, t1, t0 );

  /* x^(2^15-1) */
  memcpy( t1, e8->limbs, 48 );
  for( int i=0; i<7; i++ ) bignum_montsqr_p384( t1, t1 );
  bignum_montmul_p384( t0, t1, t0 );

  /* x^(2^31-1) */
  memcpy( t1, e16->limbs, 48 );
  for( int i=0; i<15; i++ ) bignum_montsqr_p384( t1, t1 );
  bignum_montmul_p384( t0, t1, t0 );

  /* x^(2^63-1) */
  memcpy( t1, e32->limbs, 48 );
  for( int i=0; i<31; i++ ) bignum_montsqr_p384( t1, t1 );
  bignum_montmul_p384( t0, t1, t0 );

  /* x^(2^127-1) */
  memcpy( t1, e64->limbs, 48 );
  for( int i=0; i<63; i++ ) bignum_montsqr_p384( t1, t1 );
  bignum_montmul_p384( t0, t1, t0 );

  /* x^(2^255-1) */
  memcpy( t1, e128->limbs, 48 );
  for( int i=0; i<127; i++ ) bignum_montsqr_p384( t1, t1 );
  bignum_montmul_p384( t0, t1, t0 );

  /* Process remaining exponent bits:
     0 | 32 ones | 63 zeros | 1 | 30 zeros
     (bit 126 = 0, bits 125..94 = 32 ones, bits 93..31 = 63 zeros,
      bit 30 = 1, bits 29..0 = 30 zeros) */

  bignum_montsqr_p384( t0, t0 ); /* bit 126: 0 */

  for( int i=0; i<32; i++ ) { /* bits 125..94: 32 ones */
    bignum_montsqr_p384( t0, t0 );
    bignum_montmul_p384( t0, t0, x );
  }

  for( int i=0; i<63; i++ ) bignum_montsqr_p384( t0, t0 ); /* bits 93..31: 63 zeros */

  bignum_montsqr_p384( t0, t0 ); /* bit 30: 1 */
  bignum_montmul_p384( t0, t0, x );

  for( int i=0; i<30; i++ ) bignum_montsqr_p384( t0, t0 ); /* bits 29..0: 30 zeros */

  /* Verify: t0^2 == a */
  bignum_montsqr_p384( t1, t0 );
  if( FD_UNLIKELY( !fd_uint384_eq( (fd_uint384_t const *)t1, a ) ) )
    return NULL;

  return fd_secp384r1_fp_set( r, (fd_secp384r1_fp_t const *)t0 );
}

/* Points */

static inline int
fd_secp384r1_point_validate_uncompressed( uchar const in[ 97 ] ) {
  if( FD_UNLIKELY( in[ 0 ]!=0x04U ) ) return FD_SECP384R1_FAILURE;

  fd_secp384r1_fp_t x[1], y[1], lhs[1], rhs[1];
  if( FD_UNLIKELY( !fd_secp384r1_fp_frombytes( x, in+1  ) ) ) return FD_SECP384R1_FAILURE;
  if( FD_UNLIKELY( !fd_secp384r1_fp_frombytes( y, in+49 ) ) ) return FD_SECP384R1_FAILURE;

  bignum_tomont_p384( x->limbs, x->limbs );
  bignum_tomont_p384( y->limbs, y->limbs );

  /* Validate y^2 = x^3 + ax + b. */
  bignum_montsqr_p384( lhs->limbs, y->limbs );
  bignum_montsqr_p384( rhs->limbs, x->limbs );
  bignum_add_p384    ( rhs->limbs, rhs->limbs, (ulong *)fd_secp384r1_const_a_mont[0].limbs );
  bignum_montmul_p384( rhs->limbs, rhs->limbs, x->limbs );
  bignum_add_p384    ( rhs->limbs, rhs->limbs, (ulong *)fd_secp384r1_const_b_mont[0].limbs );
  return fd_uint384_eq( lhs, rhs );
}

static inline fd_secp384r1_point_t *
fd_secp384r1_point_frombytes( fd_secp384r1_point_t * r,
                              uchar const            in[ 49 ] ) {
  fd_secp384r1_fp_t y2[1], demont_y[1];

  uchar sgn = in[0];
  if( FD_UNLIKELY( sgn!=2U && sgn!=3U ) )
    return NULL;

  if( FD_UNLIKELY( !fd_secp384r1_fp_frombytes( r->x, in+1 ) ) )
    return NULL;

  bignum_tomont_p384( r->x->limbs, r->x->limbs );

  /* y^2 = x^3 + ax + b */
  bignum_montsqr_p384( y2->limbs, r->x->limbs );
  bignum_add_p384    ( y2->limbs, y2->limbs, (ulong *)fd_secp384r1_const_a_mont[0].limbs );
  bignum_montmul_p384( y2->limbs, y2->limbs, r->x->limbs );
  bignum_add_p384    ( y2->limbs, y2->limbs, (ulong *)fd_secp384r1_const_b_mont[0].limbs );

  if( FD_UNLIKELY( !fd_secp384r1_fp_sqrt( r->y, y2 ) ) )
    return NULL;

  bignum_demont_p384( demont_y->limbs, r->y->limbs );
  ulong cond = (demont_y->limbs[0] % 2) != (sgn == 3U);
  bignum_optneg_p384( r->y->limbs, cond, r->y->limbs );

  fd_secp384r1_fp_set( r->z, fd_secp384r1_const_one_mont );
  return r;
}

static inline int
fd_secp384r1_point_eq_x( fd_secp384r1_point_t const *  p,
                         fd_secp384r1_scalar_t const * r ) {
  fd_secp384r1_fp_t affine_x[1];

  if( FD_UNLIKELY( fd_uint384_is_zero( p->z ) ) )
    return FD_SECP384R1_FAILURE;

  bignum_montinv_p384( affine_x->limbs, (ulong *)p->z->limbs );
  bignum_montsqr_p384( affine_x->limbs, affine_x->limbs );
  bignum_montmul_p384( affine_x->limbs, affine_x->limbs, (ulong *)p->x->limbs );
  bignum_demont_p384( affine_x->limbs, affine_x->limbs );
  bignum_mod_n384_6 ( affine_x->limbs, affine_x->limbs );

  if( FD_LIKELY( fd_uint384_eq( r, (fd_uint384_t const *)affine_x ) ) )
    return FD_SECP384R1_SUCCESS;
  return FD_SECP384R1_FAILURE;
}

static inline void
fd_secp384r1_double_scalar_mul_base( fd_secp384r1_point_t *        r,
                                     fd_secp384r1_scalar_t const * u1,
                                     fd_secp384r1_point_t const *  a,
                                     fd_secp384r1_scalar_t const * u2 ) {
  /* No p384_scalarmulbase in s2n-bignum — use generic scalar mul with G */
  ulong u1G[18];
  p384_montjscalarmul( u1G,        (ulong *)u1->limbs, fd_secp384r1_const_g_mont );
  p384_montjscalarmul( (ulong *)r, (ulong *)u2->limbs, (ulong const *)a );
  p384_montjadd      ( (ulong *)r, (ulong *)r,         u1G );
}
