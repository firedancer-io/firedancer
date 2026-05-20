#include "fd_curve25519.h"

#define FD_ED25519_HEEA_MAX_INDEX (128)

#if FD_HAS_AVX512
#include "table/fd_curve25519_heea_table_avx512.c"
#else
#include "table/fd_curve25519_heea_table_ref.c"
#endif

static uchar const fd_ed25519_scalar_l[32] = {
  0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
  0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
};

FD_25519_INLINE int
fd_uint256_is_neg( fd_uint256_t const * x ) {
  return !!(x->limbs[3] >> 63);
}

FD_25519_INLINE fd_uint256_t *
fd_ed25519_i256_neg( fd_uint256_t *       r,
                     fd_uint256_t const * a ) {
  fd_uint256_t zero[1] = {{{ 0UL, 0UL, 0UL, 0UL }}};
  return fd_uint256_sub( r, zero, a );
}

/* Returns the sign-mag length of the signed integer. */
FD_25519_INLINE uint
fd_uint256_abs_len( fd_uint256_t const * a ) {
  fd_uint256_t x[1];
  if( fd_uint256_is_neg( a ) ) fd_ed25519_i256_neg( x, a );
  else                              *x = *a;

  for( int i=3; i>=0; i-- ) {
    if( x->limbs[i] ) return (uint)(64*i + 1 + fd_ulong_find_msb( x->limbs[i] ));
  }
  return 0U;
}

FD_25519_INLINE void
fd_uint256_abs_tobytes( uchar out[32],
                             fd_uint256_t const * a ) {
  fd_uint256_t x[1];
  if( fd_uint256_is_neg( a ) ) fd_ed25519_i256_neg( x, a );
  else                              *x = *a;
  fd_memcpy( out, x->buf, 32UL );
}

static int
fd_ed25519_heea_decompose( uchar       rho[32],
                           uchar       tau[32],
                           uchar const h  [32] ) {
  fd_uint256_t r0[1]; memcpy( r0->buf, fd_ed25519_scalar_l, 32UL );
  fd_uint256_t r1[1]; memcpy( r1->buf, h,                   32UL );
  fd_uint256_t t0[1] = {{{ 0UL, 0UL, 0UL, 0UL }}};
  fd_uint256_t t1[1] = {{{ 1UL, 0UL, 0UL, 0UL }}};

  uint bl_r0 = 253U;
  uint bl_r1 = fd_uint256_abs_len( r1 );

  while( bl_r1>127U ) {
    uint s = bl_r0 - bl_r1;
    int same_sign = fd_uint256_is_neg( r0 )==fd_uint256_is_neg( r1 );

    fd_uint256_t r1s[1], t1s[1], r[1], t[1];
    fd_uint256_shl( r1s, r1, s );
    fd_uint256_shl( t1s, t1, s );
    if( same_sign ) {
      fd_uint256_sub( r, r0, r1s );
      fd_uint256_sub( t, t0, t1s );
    } else {
      fd_uint256_add( r, r0, r1s );
      fd_uint256_add( t, t0, t1s );
    }

    uint bl_r = fd_uint256_abs_len( r );
    if( bl_r>bl_r1 ) {
      *r0 = *r;
      *t0 = *t;
      bl_r0 = bl_r;
    } else {
      *r0 = *r1;
      *r1 = *r;
      *t0 = *t1;
      *t1 = *t;
      bl_r0 = bl_r1;
      bl_r1 = bl_r;
    }
  }

  int flip_h = 0;
  if( fd_uint256_is_neg( r1 ) ) flip_h ^= 1;
  if( fd_uint256_is_neg( t1 ) ) flip_h ^= 1;
  fd_uint256_abs_tobytes( rho, r1 );
  fd_uint256_abs_tobytes( tau, t1 );
  return flip_h;
}

static fd_ed25519_point_t *
fd_ed25519_make_wnaf_table_5( fd_ed25519_point_t       table[8],
                              fd_ed25519_point_t const * a ) {
  fd_ed25519_point_t a2[1];

  fd_ed25519_point_set( &table[0], a );
  fd_ed25519_point_dbln( a2, a, 1 );
  for( int i=1; i<8; i++ ) {
    fd_ed25519_point_add( &table[i], a2, &table[i-1] );
  }
  for( int i=0; i<8; i++ ) {
    fd_curve25519_into_precomputed( &table[i] );
  }
  return table;
}

FD_25519_INLINE void
fd_ed25519_heea_add_slide( fd_ed25519_point_t *       r,
                           short                      slide,
                           fd_ed25519_point_t const * table ) {
  if(      slide>0 ) fd_ed25519_point_add_precomputed( r, r, &table[  slide  / 2] );
  else if( slide<0 ) fd_ed25519_point_sub_precomputed( r, r, &table[(-slide) / 2] );
}

FD_25519_INLINE fd_ed25519_point_t *
fd_ed25519_heea_triple_mul( fd_ed25519_point_t *       r,
                            uchar const                a1[32],
                            fd_ed25519_point_t const * A1,
                            uchar const                a2[32],
                            fd_ed25519_point_t const * A2,
                            uchar const                b [32] ) {
  uchar b_lo[32] = {0};
  uchar b_hi[32] = {0};
  fd_memcpy( b_lo, b,      16UL );
  fd_memcpy( b_hi, b+16UL, 16UL );

  short a1slide  [256]; fd_curve25519_scalar_wnaf( a1slide,   a1,   4 );
  short a2slide  [256]; fd_curve25519_scalar_wnaf( a2slide,   a2,   4 );
  short b_loslide[256]; fd_curve25519_scalar_wnaf( b_loslide, b_lo, 8 );
  short b_hislide[256]; fd_curve25519_scalar_wnaf( b_hislide, b_hi, 4 );

  fd_ed25519_point_t table_A1[8]; fd_ed25519_make_wnaf_table_5( table_A1, A1 );
  fd_ed25519_point_t table_A2[8]; fd_ed25519_make_wnaf_table_5( table_A2, A2 );

  fd_ed25519_point_set_zero( r );

  int i;
  for( i=FD_ED25519_HEEA_MAX_INDEX; i>=0; i-- ) {
    if( a1slide[i] || a2slide[i] || b_loslide[i] || b_hislide[i] ) break;
  }
  if( FD_UNLIKELY( i<0 ) ) return r;

  for( ; i>=0; i-- ) {
    fd_ed25519_point_dbl( r, r );
    fd_ed25519_heea_add_slide( r, a1slide  [i], table_A1                         );
    fd_ed25519_heea_add_slide( r, a2slide  [i], table_A2                         );
    fd_ed25519_heea_add_slide( r, b_loslide[i], fd_ed25519_base_point_wnaf_table );
    fd_ed25519_heea_add_slide( r, b_hislide[i], fd_ed25519_base_point_128_wnaf_table );
  }

  return r;
}
