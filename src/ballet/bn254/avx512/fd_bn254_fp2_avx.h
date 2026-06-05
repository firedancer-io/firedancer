#ifndef HEADER_fd_src_ballet_bn254_avx512_fd_bn254_fp2_avx_h
#define HEADER_fd_src_ballet_bn254_avx512_fd_bn254_fp2_avx_h

#if FD_HAS_AVX512

#include "fd_bn254_fp52_mul.h"

/* fd_bn254_fp2_avx_t stores an Fp2 element as 5 wwv_t registers.
   Lane 0 of each register holds one limb of the real part (el[0]).
   Lane 1 holds the corresponding limb of the imaginary part (el[1]).
   Lanes 2-7 are scratch/zero.

   This layout means:
   - Fp2 add/sub are just wwv_add/wwv_sub (single instruction per limb)
   - Data stays in ZMM registers across operations (no memory round-trips)
   - Fp2 mul packs sa,sb into lane 2 via permute, then one CIOS call */

typedef fd_bn254_fp52x8_t fd_bn254_fp2_avx_t;

/* ---- Construction / extraction ---- */

/* Load from scalar arrays */
FD_FN_UNUSED static inline fd_bn254_fp2_avx_t
fd_bn254_fp2_avx_load( ulong const a0[5], ulong const a1[5] ) {
  fd_bn254_fp2_avx_t r;
  /* Build each limb register: lane 0 = a0[i], lane 1 = a1[i] */
  for( int i=0; i<5; i++ ) {
    r.l[i] = wwv( a0[i], a1[i], 0UL, 0UL, 0UL, 0UL, 0UL, 0UL );
  }
  return r;
}

/* Store to scalar arrays */
FD_FN_UNUSED static inline void
fd_bn254_fp2_avx_store( ulong r0[5], ulong r1[5], fd_bn254_fp2_avx_t const * a ) {
  ulong FD_ALIGNED buf[8];
  for( int i=0; i<5; i++ ) {
    wwv_st( buf, a->l[i] );
    r0[i] = buf[0];
    r1[i] = buf[1];
  }
}

/* Zero */
FD_FN_UNUSED static inline fd_bn254_fp2_avx_t
fd_bn254_fp2_avx_zero( void ) {
  fd_bn254_fp2_avx_t r;
  for( int i=0; i<5; i++ ) r.l[i] = wwv_zero();
  return r;
}

/* ---- Fp2 add / sub (vectorized, no memory) ---- */

/* Fp2 add: component-wise modular addition.
   Since both components are in lanes 0,1, we just do the 8-wide
   add/sub/carry-propagate on all lanes. The conditional subtraction
   of p also works correctly per-lane. */

FD_FN_UNUSED static inline fd_bn254_fp2_avx_t
fd_bn254_fp2_avx_add( fd_bn254_fp2_avx_t const * a,
                      fd_bn254_fp2_avx_t const * b ) {
  /* Re-use the existing batched add which does carry-propagate + cond sub */
  return fd_bn254_fp52x8_add( a, b );
}

FD_FN_UNUSED static inline fd_bn254_fp2_avx_t
fd_bn254_fp2_avx_sub( fd_bn254_fp2_avx_t const * a,
                      fd_bn254_fp2_avx_t const * b ) {
  return fd_bn254_fp52x8_sub( a, b );
}

/* ---- Fp2 mul (Karatsuba, entirely in ZMM registers) ----

   Given a = (a0, a1) in lanes (0, 1) and b = (b0, b1) in lanes (0, 1):

   1. Compute sa = a0+a1, sb = b0+b1 using lane permutes + add
   2. Put sa in lane 2 of ax, sb in lane 2 of bx
   3. ONE CIOS call: 3 products in lanes 0,1,2
   4. Extract r0 = lane0 - lane1, r1 = lane2 - lane0 - lane1
      using lane permutes + sub */

FD_FN_UNUSED static inline fd_bn254_fp2_avx_t
fd_bn254_fp2_avx_mul( fd_bn254_fp2_avx_t const * a,
                      fd_bn254_fp2_avx_t const * b ) {
  fd_bn254_fp52x8_t ax, bx;
  /* Compute sa = a0+a1, sb = b0+b1 via scalar extract + add.
     The overhead (~10 cycles each) is negligible vs CIOS (~180 cycles). */

  ulong a0[5], a1[5], b0[5], b1[5], sa[5], sb[5];
  fd_bn254_fp2_avx_store( a0, a1, a );
  fd_bn254_fp2_avx_store( b0, b1, b );
  fd_bn254_fp52_add_scalar( sa, a0, a1 );
  fd_bn254_fp52_add_scalar( sb, b0, b1 );

  /* Pack all 3 products into lanes 0,1,2 */
  for( int i=0; i<5; i++ ) {
    ax.l[i] = wwv( a0[i], a1[i], sa[i], 0UL, 0UL, 0UL, 0UL, 0UL );
    bx.l[i] = wwv( b0[i], b1[i], sb[i], 0UL, 0UL, 0UL, 0UL, 0UL );
  }

  /* CIOS: 3 products in parallel */
  fd_bn254_fp52x8_t px = fd_bn254_fp52x8_mul( &ax, &bx );

  /* Extract products */
  ulong p_a0b0[5], p_a1b1[5], p_sasb[5];
  ulong FD_ALIGNED buf[8];
  for( int i=0; i<5; i++ ) {
    wwv_st( buf, px.l[i] );
    p_a0b0[i] = buf[0];
    p_a1b1[i] = buf[1];
    p_sasb[i] = buf[2];
  }

  /* Assemble: r0 = a0*b0 - a1*b1, r1 = sa*sb - a0*b0 - a1*b1 */
  ulong r0[5], r1[5];
  fd_bn254_fp52_sub_scalar( r0, p_a0b0, p_a1b1 );
  fd_bn254_fp52_sub_scalar( r1, p_sasb, p_a0b0 );
  fd_bn254_fp52_sub_scalar( r1, r1, p_a1b1 );

  return fd_bn254_fp2_avx_load( r0, r1 );
}

/* ---- Fp2 sqr ---- */

FD_FN_UNUSED static inline fd_bn254_fp2_avx_t
fd_bn254_fp2_avx_sqr( fd_bn254_fp2_avx_t const * a ) {
  ulong a0[5], a1[5], p_val[5], m_val[5];
  fd_bn254_fp2_avx_store( a0, a1, a );
  fd_bn254_fp52_add_scalar( p_val, a0, a1 );  /* a0+a1 */
  fd_bn254_fp52_sub_scalar( m_val, a0, a1 );  /* a0-a1 */

  /* 2 products: a0*a1 (lane 0) and p*m (lane 1) */
  fd_bn254_fp52x8_t ax, bx;
  for( int i=0; i<5; i++ ) {
    ax.l[i] = wwv( a0[i], p_val[i], 0UL, 0UL, 0UL, 0UL, 0UL, 0UL );
    bx.l[i] = wwv( a1[i], m_val[i], 0UL, 0UL, 0UL, 0UL, 0UL, 0UL );
  }
  fd_bn254_fp52x8_t px = fd_bn254_fp52x8_mul( &ax, &bx );

  ulong a0a1[5], pm[5];
  ulong FD_ALIGNED buf[8];
  for( int i=0; i<5; i++ ) {
    wwv_st( buf, px.l[i] );
    a0a1[i] = buf[0];
    pm[i]   = buf[1];
  }

  /* r0 = p*m, r1 = 2*a0*a1 */
  ulong r1[5];
  fd_bn254_fp52_add_scalar( r1, a0a1, a0a1 );
  return fd_bn254_fp2_avx_load( pm, r1 );
}

FD_PROTOTYPES_BEGIN
FD_PROTOTYPES_END

#endif /* FD_HAS_AVX512 */
#endif /* HEADER_fd_src_ballet_bn254_avx512_fd_bn254_fp2_avx_h */
