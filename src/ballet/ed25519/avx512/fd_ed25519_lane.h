#ifndef HEADER_fd_src_ballet_ed25519_avx512_fd_ed25519_lane_h
#define HEADER_fd_src_ballet_ed25519_avx512_fd_ed25519_lane_h

/* Private, public-input-only eight-signature arithmetic.  Each vector
   lane is one field element, never a coordinate of another signature.

   The radix-51 IFMA convolution/carry organization is adapted into C
   from Narya internal/r51x5/ifma_amd64.s and its arithmetic assurance
   notes (https://github.com/Overclock-Validator/narya-ed25519), snapshot
   c265ee9667131a556cd332c252b79de0860c7640.
   Narya, Copyright 2026 Overclock Validator.
   This product includes software developed at Overclock Validator
   (https://github.com/Overclock-Validator).
   Licensed under the Apache License, Version 2.0 (see LICENSE).
   Modifications: C SIMD primitives, unrolled per-degree chains, loose
   products, signed windows with table-form entries selected per lane
   by half-width masked loads, fixed-base table, and Firedancer point
   adapters.

   Limb classes.  "carried" is the output of fd_ed25519_lane_carry:
   limbs < 2^51+2^17.  "f52" is any limbs < 2^52, the IFMA input
   requirement.  "loose" is an uncarried product, limbs < 2^61; sums
   of loose values and offsets stay < 2^64 and any such value carries
   exactly.  Raw adds/subs of carried values are f52 only when noted.
   Operations allow exact output/input aliasing.
   No secret-key operation may use these variable-time table lookups. */

#include "../fd_curve25519.h"
#include "../../../util/simd/fd_avx512.h"

#define FD_ED25519_LANE_MASK ((1UL<<51)-1UL)

typedef struct { wwv_t limb[5]; } fd_ed25519_lane_fe_t;
typedef struct { fd_ed25519_lane_fe_t x, y, z, t; } fd_ed25519_lane_point_t;
/* Table form: y+x, y-x, 2dt, -2dt, z.  A negated entry is read with
   p,m swapped and nk in place of k, by pointer selection. */
typedef struct { fd_ed25519_lane_fe_t p, m, k, nk, z; } fd_ed25519_lane_niels_t;

/* 2p limbwise: (2^52-38, 2^52-2, ...).  2p-x is f52 for carried x.
   2^11 p exceeds any loose limb, 2^12 p exceeds the sum of two. */
#define FD_ED25519_LANE_2P0 ((1UL<<52)-38UL)
#define FD_ED25519_LANE_2P  ((1UL<<52)-2UL)
#define FD_ED25519_LANE_BIGP0(k) (((1UL<<51)-19UL)<<(k))
#define FD_ED25519_LANE_BIGP(k)  (((1UL<<51)- 1UL)<<(k))

/* Fixed-base table: entries 0..128 of (y+x, y-x, 2dxy, 2p-2dxy) for
   [e]B in canonical radix-51 limbs, 20 ulongs each. */
#define FD_ED25519_LANE_BASE_CNT  129UL
extern ulong const fd_ed25519_lane_base_table[ 20UL*FD_ED25519_LANE_BASE_CNT ] __attribute__((aligned(64)));

#define FD_LANE_LO(acc,a,b) _mm512_madd52lo_epu64( (acc), (a), (b) )
#define FD_LANE_HI(acc,a,b) _mm512_madd52hi_epu64( (acc), (a), (b) )

/* Field ops are always inlined so operands stay in registers. */
#define FD_LANE_INLINE static inline __attribute__((always_inline))

/* Any u64 limbs -> carried.  Parallel carry; for inputs < 2^63.5,
   c_i < 2^13 and limb0 < 2^51+19*2^13. */
FD_LANE_INLINE void
fd_ed25519_lane_carry( fd_ed25519_lane_fe_t * r ) {
  wwv_t const mask = wwv_bcast( FD_ED25519_LANE_MASK );
  wwv_t c0 = wwv_shr( r->limb[0], 51 ), c1 = wwv_shr( r->limb[1], 51 ), c2 = wwv_shr( r->limb[2], 51 ),
        c3 = wwv_shr( r->limb[3], 51 ), c4 = wwv_shr( r->limb[4], 51 );
  r->limb[0] = FD_LANE_LO( wwv_and( r->limb[0], mask ), c4, wwv_bcast( 19UL ) );
  r->limb[1] = wwv_add( wwv_and( r->limb[1], mask ), c0 );
  r->limb[2] = wwv_add( wwv_and( r->limb[2], mask ), c1 );
  r->limb[3] = wwv_add( wwv_and( r->limb[3], mask ), c2 );
  r->limb[4] = wwv_add( wwv_and( r->limb[4], mask ), c3 );
}

/* Raw limbwise a+b. */
FD_LANE_INLINE void
fd_ed25519_lane_add_raw( fd_ed25519_lane_fe_t *       r,
                         fd_ed25519_lane_fe_t const * a,
                         fd_ed25519_lane_fe_t const * b ) {
  for( int i=0; i<5; i++ ) r->limb[i] = wwv_add( a->limb[i], b->limb[i] );
}

/* Raw a+2p-b, b carried. */
FD_LANE_INLINE void
fd_ed25519_lane_sub_raw( fd_ed25519_lane_fe_t *       r,
                         fd_ed25519_lane_fe_t const * a,
                         fd_ed25519_lane_fe_t const * b ) {
  r->limb[0] = wwv_sub( wwv_add( a->limb[0], wwv_bcast( FD_ED25519_LANE_2P0 ) ), b->limb[0] );
  for( int i=1; i<5; i++ ) r->limb[i] = wwv_sub( wwv_add( a->limb[i], wwv_bcast( FD_ED25519_LANE_2P ) ), b->limb[i] );
}

/* 2p-a, a carried: f52 without a carry. */
FD_LANE_INLINE void
fd_ed25519_lane_neg( fd_ed25519_lane_fe_t *       r,
                     fd_ed25519_lane_fe_t const * a ) {
  r->limb[0] = wwv_sub( wwv_bcast( FD_ED25519_LANE_2P0 ), a->limb[0] );
  for( int i=1; i<5; i++ ) r->limb[i] = wwv_sub( wwv_bcast( FD_ED25519_LANE_2P ), a->limb[i] );
}

FD_LANE_INLINE void
fd_ed25519_lane_add( fd_ed25519_lane_fe_t *       r,
                     fd_ed25519_lane_fe_t const * a,
                     fd_ed25519_lane_fe_t const * b ) {
  fd_ed25519_lane_add_raw( r, a, b );
  fd_ed25519_lane_carry( r );
}

/* a-b for any f52 b: 4p prevents underflow. */
FD_LANE_INLINE void
fd_ed25519_lane_sub( fd_ed25519_lane_fe_t *       r,
                     fd_ed25519_lane_fe_t const * a,
                     fd_ed25519_lane_fe_t const * b ) {
  r->limb[0] = wwv_sub( wwv_add( a->limb[0], wwv_bcast( 2UL*FD_ED25519_LANE_2P0 ) ), b->limb[0] );
  for( int i=1; i<5; i++ ) r->limb[i] = wwv_sub( wwv_add( a->limb[i], wwv_bcast( 2UL*FD_ED25519_LANE_2P ) ), b->limb[i] );
  fd_ed25519_lane_carry( r );
}

/* Fold degrees 5..9 by 19.  The largest coefficient, r5 < 14*2^52,
   gives r0 < 267*2^52 < 2^61 (loose); carry when requested. */
FD_LANE_INLINE void
fd_ed25519_lane_fold( fd_ed25519_lane_fe_t * r,
                      wwv_t r0, wwv_t r1, wwv_t r2, wwv_t r3, wwv_t r4,
                      wwv_t r5, wwv_t r6, wwv_t r7, wwv_t r8, wwv_t r9,
                      int   carry ) {
  wwv_t const k19 = wwv_bcast( 19UL );
  r->limb[0] = wwv_add( r0, wwv_mul( r5, k19 ) );
  r->limb[1] = wwv_add( r1, wwv_mul( r6, k19 ) );
  r->limb[2] = wwv_add( r2, wwv_mul( r7, k19 ) );
  r->limb[3] = wwv_add( r3, wwv_mul( r8, k19 ) );
  r->limb[4] = wwv_add( r4, wwv_mul( r9, k19 ) );
  if( carry ) fd_ed25519_lane_carry( r );
}

/* f52 x f52 -> carried, or loose if !carry.  One chain per degree d:
   the high halves of degree d-1 (radix 2^52, so doubled once) then the
   low halves of d. */
FD_LANE_INLINE void
fd_ed25519_lane_mul_( fd_ed25519_lane_fe_t *       r,
                      fd_ed25519_lane_fe_t const * a,
                      fd_ed25519_lane_fe_t const * b,
                      int                          carry ) {
  wwv_t const z = wwv_zero();
  wwv_t a0 = a->limb[0], a1 = a->limb[1], a2 = a->limb[2], a3 = a->limb[3], a4 = a->limb[4];
  wwv_t b0 = b->limb[0], b1 = b->limb[1], b2 = b->limb[2], b3 = b->limb[3], b4 = b->limb[4];
  wwv_t r0, r1, r2, r3, r4, r5, r6, r7, r8, r9;
  r0 = FD_LANE_LO( z, a0, b0 );
  r1 = FD_LANE_HI( z, a0, b0 ); r1 = wwv_add( r1, r1 );
  r1 = FD_LANE_LO( FD_LANE_LO( r1, a0, b1 ), a1, b0 );
  r2 = FD_LANE_HI( FD_LANE_HI( z, a0, b1 ), a1, b0 ); r2 = wwv_add( r2, r2 );
  r2 = FD_LANE_LO( FD_LANE_LO( FD_LANE_LO( r2, a0, b2 ), a1, b1 ), a2, b0 );
  r3 = FD_LANE_HI( FD_LANE_HI( FD_LANE_HI( z, a0, b2 ), a1, b1 ), a2, b0 ); r3 = wwv_add( r3, r3 );
  r3 = FD_LANE_LO( FD_LANE_LO( FD_LANE_LO( FD_LANE_LO( r3, a0, b3 ), a1, b2 ), a2, b1 ), a3, b0 );
  r4 = FD_LANE_HI( FD_LANE_HI( FD_LANE_HI( FD_LANE_HI( z, a0, b3 ), a1, b2 ), a2, b1 ), a3, b0 ); r4 = wwv_add( r4, r4 );
  r4 = FD_LANE_LO( FD_LANE_LO( FD_LANE_LO( FD_LANE_LO( FD_LANE_LO( r4, a0, b4 ), a1, b3 ), a2, b2 ), a3, b1 ), a4, b0 );
  r5 = FD_LANE_HI( FD_LANE_HI( FD_LANE_HI( FD_LANE_HI( FD_LANE_HI( z, a0, b4 ), a1, b3 ), a2, b2 ), a3, b1 ), a4, b0 ); r5 = wwv_add( r5, r5 );
  r5 = FD_LANE_LO( FD_LANE_LO( FD_LANE_LO( FD_LANE_LO( r5, a1, b4 ), a2, b3 ), a3, b2 ), a4, b1 );
  r6 = FD_LANE_HI( FD_LANE_HI( FD_LANE_HI( FD_LANE_HI( z, a1, b4 ), a2, b3 ), a3, b2 ), a4, b1 ); r6 = wwv_add( r6, r6 );
  r6 = FD_LANE_LO( FD_LANE_LO( FD_LANE_LO( r6, a2, b4 ), a3, b3 ), a4, b2 );
  r7 = FD_LANE_HI( FD_LANE_HI( FD_LANE_HI( z, a2, b4 ), a3, b3 ), a4, b2 ); r7 = wwv_add( r7, r7 );
  r7 = FD_LANE_LO( FD_LANE_LO( r7, a3, b4 ), a4, b3 );
  r8 = FD_LANE_HI( FD_LANE_HI( z, a3, b4 ), a4, b3 ); r8 = wwv_add( r8, r8 );
  r8 = FD_LANE_LO( r8, a4, b4 );
  r9 = FD_LANE_HI( z, a4, b4 ); r9 = wwv_add( r9, r9 );
  fd_ed25519_lane_fold( r, r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, carry );
}
#define fd_ed25519_lane_mul(r,a,b)       fd_ed25519_lane_mul_( (r), (a), (b), 1 )
#define fd_ed25519_lane_mul_loose(r,a,b) fd_ed25519_lane_mul_( (r), (a), (b), 0 )

/* f52 -> carried, or loose if !carry.  Per degree: off-diagonal high
   halves of d-1, doubled, plus the diagonal high half, doubled again
   together with the off-diagonal low halves of d, plus the diagonal
   low half. */
FD_LANE_INLINE void
fd_ed25519_lane_sqr_( fd_ed25519_lane_fe_t *       r,
                      fd_ed25519_lane_fe_t const * a,
                      int                          carry ) {
  wwv_t const z = wwv_zero();
  wwv_t a0 = a->limb[0], a1 = a->limb[1], a2 = a->limb[2], a3 = a->limb[3], a4 = a->limb[4];
  wwv_t r0, r1, r2, r3, r4, r5, r6, r7, r8, r9;
  r0 = FD_LANE_LO( z, a0, a0 );
  r1 = FD_LANE_HI( z, a0, a0 );
  r1 = FD_LANE_LO( r1, a0, a1 ); r1 = wwv_add( r1, r1 );
  r2 = FD_LANE_HI( z, a0, a1 ); r2 = wwv_add( r2, r2 );
  r2 = FD_LANE_LO( r2, a0, a2 ); r2 = wwv_add( r2, r2 );
  r2 = FD_LANE_LO( r2, a1, a1 );
  r3 = FD_LANE_HI( z, a0, a2 ); r3 = wwv_add( r3, r3 );
  r3 = FD_LANE_HI( r3, a1, a1 );
  r3 = FD_LANE_LO( FD_LANE_LO( r3, a0, a3 ), a1, a2 ); r3 = wwv_add( r3, r3 );
  r4 = FD_LANE_HI( FD_LANE_HI( z, a0, a3 ), a1, a2 ); r4 = wwv_add( r4, r4 );
  r4 = FD_LANE_LO( FD_LANE_LO( r4, a0, a4 ), a1, a3 ); r4 = wwv_add( r4, r4 );
  r4 = FD_LANE_LO( r4, a2, a2 );
  r5 = FD_LANE_HI( FD_LANE_HI( z, a0, a4 ), a1, a3 ); r5 = wwv_add( r5, r5 );
  r5 = FD_LANE_HI( r5, a2, a2 );
  r5 = FD_LANE_LO( FD_LANE_LO( r5, a1, a4 ), a2, a3 ); r5 = wwv_add( r5, r5 );
  r6 = FD_LANE_HI( FD_LANE_HI( z, a1, a4 ), a2, a3 ); r6 = wwv_add( r6, r6 );
  r6 = FD_LANE_LO( r6, a2, a4 ); r6 = wwv_add( r6, r6 );
  r6 = FD_LANE_LO( r6, a3, a3 );
  r7 = FD_LANE_HI( z, a2, a4 ); r7 = wwv_add( r7, r7 );
  r7 = FD_LANE_HI( r7, a3, a3 );
  r7 = FD_LANE_LO( r7, a3, a4 ); r7 = wwv_add( r7, r7 );
  r8 = FD_LANE_HI( z, a3, a4 ); r8 = wwv_add( r8, r8 ); r8 = wwv_add( r8, r8 );
  r8 = FD_LANE_LO( r8, a4, a4 );
  r9 = FD_LANE_HI( z, a4, a4 ); r9 = wwv_add( r9, r9 );
  fd_ed25519_lane_fold( r, r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, carry );
}
#define fd_ed25519_lane_sqr(r,a)       fd_ed25519_lane_sqr_( (r), (a), 1 )
#define fd_ed25519_lane_sqr_loose(r,a) fd_ed25519_lane_sqr_( (r), (a), 0 )

/* Raw a + 2^k p - b for loose b (k=11) or loose a and b in
   a + 2^k p - b - c (k=12); all sums stay < 2^64. */
FD_LANE_INLINE void
fd_ed25519_lane_sub_big( fd_ed25519_lane_fe_t *       r,
                         fd_ed25519_lane_fe_t const * a,
                         fd_ed25519_lane_fe_t const * b,
                         int                          k ) {
  r->limb[0] = wwv_sub( wwv_add( a->limb[0], wwv_bcast( FD_ED25519_LANE_BIGP0( k ) ) ), b->limb[0] );
  for( int i=1; i<5; i++ ) r->limb[i] = wwv_sub( wwv_add( a->limb[i], wwv_bcast( FD_ED25519_LANE_BIGP( k ) ) ), b->limb[i] );
}

static inline void
fd_ed25519_lane_zero( fd_ed25519_lane_point_t * r ) {
  for( int i=0; i<5; i++ ) {
    r->x.limb[i] = r->t.limb[i] = wwv_zero();
    r->y.limb[i] = r->z.limb[i] = wwv_bcast( (ulong)(i==0) );
  }
}

/* Doubling (a=-1), 4S+4M: E=(X+Y)^2-A-B, G=B-A, F=G-2C, H=-A-B.
   Input x,y,z carried; t unused.  The squares stay loose; only E, F,
   G, H are carried.  T is computed only when requested. */
static inline void
fd_ed25519_lane_point_dbl( fd_ed25519_lane_point_t *       r,
                           fd_ed25519_lane_point_t const * p,
                           int                             with_t ) {
  fd_ed25519_lane_fe_t a, b, c, s, e, f, g, h;
  fd_ed25519_lane_add( &s, &p->x, &p->y );
  fd_ed25519_lane_sqr_loose( &a, &p->x );
  fd_ed25519_lane_sqr_loose( &b, &p->y );
  fd_ed25519_lane_sqr_loose( &c, &p->z );
  fd_ed25519_lane_sqr_loose( &s, &s );
  fd_ed25519_lane_sub_big( &g, &b, &a, 11 );        /* b + 2^11 p - a */
  fd_ed25519_lane_add_raw( &h, &a, &b );
  fd_ed25519_lane_sub_big( &e, &s, &h, 12 );        /* s + 2^12 p - a - b */
  for( int i=0; i<5; i++ )                          /* 2^12 p - a - b */
    h.limb[i] = wwv_sub( wwv_bcast( i ? FD_ED25519_LANE_BIGP( 12 ) : FD_ED25519_LANE_BIGP0( 12 ) ), h.limb[i] );
  fd_ed25519_lane_carry( &g );
  fd_ed25519_lane_add_raw( &c, &c, &c );
  fd_ed25519_lane_sub_big( &f, &g, &c, 11 );        /* g + 2^11 p - 2c */
  fd_ed25519_lane_carry( &e );
  fd_ed25519_lane_carry( &f );
  fd_ed25519_lane_carry( &h );
  fd_ed25519_lane_mul( &r->x, &e, &f );
  fd_ed25519_lane_mul( &r->z, &f, &g );
  fd_ed25519_lane_mul( &r->y, &g, &h );
  if( with_t ) fd_ed25519_lane_mul( &r->t, &e, &h );
}

/* Addition tail from the loose products a=(Y1-X1)(Y2-X2),
   b=(Y1+X1)(Y2+X2), c=T1*2dT2, d=Z1*Z2: E=B-A, H=B+A, F=2D-C, G=2D+C. */
FD_LANE_INLINE void
fd_ed25519_lane_point_add_fin( fd_ed25519_lane_point_t *    r,
                               fd_ed25519_lane_fe_t const * a,
                               fd_ed25519_lane_fe_t const * b,
                               fd_ed25519_lane_fe_t const * c,
                               fd_ed25519_lane_fe_t const * d,
                               int                          with_t ) {
  fd_ed25519_lane_fe_t e, f, g, h, d2;
  fd_ed25519_lane_sub_big( &e, b, a, 11 );
  fd_ed25519_lane_add_raw( &h, b, a );
  fd_ed25519_lane_add_raw( &d2, d, d );
  fd_ed25519_lane_sub_big( &f, &d2, c, 11 );
  fd_ed25519_lane_add_raw( &g, &d2, c );
  fd_ed25519_lane_carry( &e );
  fd_ed25519_lane_carry( &f );
  fd_ed25519_lane_carry( &g );
  fd_ed25519_lane_carry( &h );
  fd_ed25519_lane_mul( &r->x, &e, &f );
  fd_ed25519_lane_mul( &r->z, &f, &g );
  fd_ed25519_lane_mul( &r->y, &g, &h );
  if( with_t ) fd_ed25519_lane_mul( &r->t, &e, &h );
}

/* Complete addition r = p + q, q in table form.  affine: q->z == 1. */
static inline void
fd_ed25519_lane_point_add( fd_ed25519_lane_point_t *       r,
                           fd_ed25519_lane_point_t const * p,
                           fd_ed25519_lane_niels_t const * q,
                           int                             affine,
                           int                             with_t ) {
  fd_ed25519_lane_fe_t a, b, c, d;
  fd_ed25519_lane_sub( &a, &p->y, &p->x );
  fd_ed25519_lane_add( &b, &p->y, &p->x );
  fd_ed25519_lane_mul_loose( &a, &a, &q->m );
  fd_ed25519_lane_mul_loose( &b, &b, &q->p );
  fd_ed25519_lane_mul_loose( &c, &p->t, &q->k );
  if( affine ) d = p->z;
  else         fd_ed25519_lane_mul_loose( &d, &p->z, &q->z );
  fd_ed25519_lane_point_add_fin( r, &a, &b, &c, &d, with_t );
}

/* Extended -> table form.  k2d = 2d broadcast. */
static inline void
fd_ed25519_lane_to_niels( fd_ed25519_lane_niels_t *       r,
                          fd_ed25519_lane_point_t const * p,
                          fd_ed25519_lane_fe_t const *    k2d ) {
  fd_ed25519_lane_add( &r->p, &p->y, &p->x );
  fd_ed25519_lane_sub( &r->m, &p->y, &p->x );
  r->z = p->z;
  fd_ed25519_lane_mul( &r->k, &p->t, k2d );
  fd_ed25519_lane_neg( &r->nk, &r->k );
}

/* Per-lane select of one limb, built as two 256-bit halves: 256-bit
   masked loads and broadcasts are free next to 512-bit IFMA, one
   insert per limb is not.  rows: src[j] is lane j's qword in an
   8-lane row (lanes 0-3 and 4-7 are the row's aligned halves);
   otherwise src[j] is a per-lane scalar to broadcast. */
FD_LANE_INLINE wwv_t
fd_ed25519_lane_pick( ulong const * const src[8],
                      ulong                 off,
                      int                   rows ) {
  __m256i lo, hi;
  if( rows ) {
    lo = _mm256_load_epi64( src[0] + off );
    hi = _mm256_load_epi64( src[4] + off );
    for( int j=1; j<4; j++ ) {
      lo = _mm256_mask_load_epi64( lo, (__mmask8)(1<<j), src[j]   + off - (ulong)j );
      hi = _mm256_mask_load_epi64( hi, (__mmask8)(1<<j), src[4+j] + off - (ulong)j );
    }
  } else {
    lo = _mm256_set1_epi64x( (long)src[0][off] );
    hi = _mm256_set1_epi64x( (long)src[4][off] );
    for( int j=1; j<4; j++ ) {
      lo = _mm256_mask_set1_epi64( lo, (__mmask8)(1<<j), (long)src[j][off] );
      hi = _mm256_mask_set1_epi64( hi, (__mmask8)(1<<j), (long)src[4+j][off] );
    }
  }
  return _mm512_inserti64x4( _mm512_castsi256_si512( lo ), hi, 1 );
}

/* Complete addition r = p + q, q selected per lane just in time so
   the selection overlaps the products.  sp/sm/sk/sz[j] point at lane
   j's (y+x), (y-x), 2dt and z limb 0; negative digits are handled by
   the caller swapping sp/sm and pointing sk at -2dt.  Limbs are
   stride ulongs apart.  affine: q->z == 1 (sz unused). */
static void
fd_ed25519_lane_point_add_sel( fd_ed25519_lane_point_t *       r,
                               fd_ed25519_lane_point_t const * p,
                               ulong const * const             sp[8],
                               ulong const * const             sm[8],
                               ulong const * const             sk[8],
                               ulong const * const             sz[8],
                               ulong                           stride,
                               int                             rows,
                               int                             affine,
                               int                             with_t ) {
  fd_ed25519_lane_fe_t a, b, c, d, q;
  fd_ed25519_lane_sub( &a, &p->y, &p->x );
  fd_ed25519_lane_add( &b, &p->y, &p->x );
#define PICK(src) for( int i=0; i<5; i++ ) q.limb[i] = fd_ed25519_lane_pick( src, (ulong)i*stride, rows )
  PICK( sk );
  fd_ed25519_lane_mul_loose( &c, &p->t, &q );
  PICK( sm );
  fd_ed25519_lane_mul_loose( &a, &a, &q );
  PICK( sp );
  fd_ed25519_lane_mul_loose( &b, &b, &q );
  if( affine ) d = p->z;
  else { PICK( sz ); fd_ed25519_lane_mul_loose( &d, &p->z, &q ); }
#undef PICK
  fd_ed25519_lane_point_add_fin( r, &a, &b, &c, &d, with_t );
}

/* Conversion is only at the scalar/SIMD boundary, not in the group loop. */
static inline void
fd_ed25519_lane_pack_fe( fd_ed25519_lane_fe_t * r,
                         fd_f25519_t const     a[8] ) {
  ulong limbs[5][8];
  for( int j=0; j<8; j++ ) {
    uchar buf[32];
    fd_f25519_tobytes( buf, &a[j] );
    limbs[0][j] =  fd_ulong_load_8( buf    )       & FD_ED25519_LANE_MASK;
    limbs[1][j] = (fd_ulong_load_8( buf+ 6 )>> 3) & FD_ED25519_LANE_MASK;
    limbs[2][j] = (fd_ulong_load_8( buf+12 )>> 6) & FD_ED25519_LANE_MASK;
    limbs[3][j] = (fd_ulong_load_8( buf+19 )>> 1) & FD_ED25519_LANE_MASK;
    limbs[4][j] = (fd_ulong_load_8( buf+24 )>>12) & FD_ED25519_LANE_MASK;
  }
  for( int i=0; i<5; i++ ) r->limb[i] = wwv_ldu( limbs[i] );
}

static inline void
fd_ed25519_lane_pack( fd_ed25519_lane_point_t * r,
                      fd_ed25519_point_t const a[8] ) {
  fd_f25519_t x[8], y[8], z[8], t[8];
  for( int j=0; j<8; j++ ) fd_ed25519_point_to( &x[j], &y[j], &z[j], &t[j], &a[j] );
  fd_ed25519_lane_pack_fe( &r->x, x );
  fd_ed25519_lane_pack_fe( &r->y, y );
  fd_ed25519_lane_pack_fe( &r->z, z );
  fd_ed25519_lane_pack_fe( &r->t, t );
}

static inline fd_ed25519_lane_fe_t
fd_ed25519_lane_normalize( fd_ed25519_lane_fe_t a ) {
  /* Two sequential carry/fold passes turn loose limbs into u51 limbs.
     The only zero representatives in [0,2^255) are zero and p. */
  for( int pass=0; pass<2; pass++ ) {
    for( int i=0; i<4; i++ ) {
      a.limb[i+1] = wwv_add( a.limb[i+1], wwv_shr( a.limb[i], 51 ) );
      a.limb[i] = wwv_and( a.limb[i], wwv_bcast( FD_ED25519_LANE_MASK ) );
    }
    a.limb[0] = wwv_add( a.limb[0], wwv_mul( wwv_shr( a.limb[4], 51 ), wwv_bcast( 19UL ) ) );
    a.limb[4] = wwv_and( a.limb[4], wwv_bcast( FD_ED25519_LANE_MASK ) );
  }
  return a;
}

static inline int
fd_ed25519_lane_is_zero( fd_ed25519_lane_fe_t a ) {
  a = fd_ed25519_lane_normalize( a );
  int z = 255, p = 255;
  for( int i=0; i<5; i++ ) {
    z &= wwv_eq( a.limb[i], wwv_zero() );
    p &= wwv_eq( a.limb[i], wwv_bcast( FD_ED25519_LANE_MASK-(i==0 ? 18UL : 0UL) ) );
  }
  return z | p;
}

static inline void
fd_ed25519_lane_bcast_fe( fd_ed25519_lane_fe_t * r,
                          fd_f25519_t const *    a ) {
  fd_f25519_t values[8];
  for( int j=0; j<8; j++ ) fd_f25519_set( &values[j], a );
  fd_ed25519_lane_pack_fe( r, values );
}

static inline void
fd_ed25519_lane_sqrn( fd_ed25519_lane_fe_t *       r,
                      fd_ed25519_lane_fe_t const * a,
                      int                          n ) {
  fd_ed25519_lane_sqr( r, a );
  for( int i=1; i<n; i++ ) fd_ed25519_lane_sqr( r, r );
}

/* r = a^(2^252-3), the fd_f25519_pow22523 addition chain. */
static inline void
fd_ed25519_lane_pow22523( fd_ed25519_lane_fe_t *       r,
                          fd_ed25519_lane_fe_t const * a ) {
  fd_ed25519_lane_fe_t t0, t1, t2;
  fd_ed25519_lane_sqr ( &t0, a );
  fd_ed25519_lane_sqrn( &t1, &t0, 2 );
  fd_ed25519_lane_mul ( &t1, a, &t1 );
  fd_ed25519_lane_mul ( &t0, &t0, &t1 );
  fd_ed25519_lane_sqr ( &t0, &t0 );
  fd_ed25519_lane_mul ( &t0, &t1, &t0 );
  fd_ed25519_lane_sqrn( &t1, &t0, 5 );
  fd_ed25519_lane_mul ( &t0, &t1, &t0 );
  fd_ed25519_lane_sqrn( &t1, &t0, 10 );
  fd_ed25519_lane_mul ( &t1, &t1, &t0 );
  fd_ed25519_lane_sqrn( &t2, &t1, 20 );
  fd_ed25519_lane_mul ( &t1, &t2, &t1 );
  fd_ed25519_lane_sqrn( &t1, &t1, 10 );
  fd_ed25519_lane_mul ( &t0, &t1, &t0 );
  fd_ed25519_lane_sqrn( &t1, &t0, 50 );
  fd_ed25519_lane_mul ( &t1, &t1, &t0 );
  fd_ed25519_lane_sqrn( &t2, &t1, 100 );
  fd_ed25519_lane_mul ( &t1, &t2, &t1 );
  fd_ed25519_lane_sqrn( &t1, &t1, 50 );
  fd_ed25519_lane_mul ( &t0, &t1, &t0 );
  fd_ed25519_lane_sqrn( &t0, &t0, 2 );
  fd_ed25519_lane_mul ( r, &t0, a );
}

/* Two interleaved copies of the same chain: one squaring chain does
   not fill the IFMA pipe. */
static inline void
fd_ed25519_lane_pow22523_2( fd_ed25519_lane_fe_t *       r0,
                            fd_ed25519_lane_fe_t const * a0,
                            fd_ed25519_lane_fe_t *       r1,
                            fd_ed25519_lane_fe_t const * a1 ) {
  fd_ed25519_lane_fe_t t0[2], t1[2], t2[2];
#define SQR2(r,a)   do { fd_ed25519_lane_sqr( &(r)[0], &(a)[0] ); fd_ed25519_lane_sqr( &(r)[1], &(a)[1] ); } while(0)
#define MUL2(r,a,b) do { fd_ed25519_lane_mul( &(r)[0], &(a)[0], &(b)[0] ); fd_ed25519_lane_mul( &(r)[1], &(a)[1], &(b)[1] ); } while(0)
#define SQRN2(r,a,n) do { SQR2( r, a ); for( int _i=1; _i<(n); _i++ ) SQR2( r, r ); } while(0)
  fd_ed25519_lane_fe_t a[2] = { *a0, *a1 };
  SQR2 ( t0, a );
  SQRN2( t1, t0, 2 );
  MUL2 ( t1, a, t1 );
  MUL2 ( t0, t0, t1 );
  SQR2 ( t0, t0 );
  MUL2 ( t0, t1, t0 );
  SQRN2( t1, t0, 5 );
  MUL2 ( t0, t1, t0 );
  SQRN2( t1, t0, 10 );
  MUL2 ( t1, t1, t0 );
  SQRN2( t2, t1, 20 );
  MUL2 ( t1, t2, t1 );
  SQRN2( t1, t1, 10 );
  MUL2 ( t0, t1, t0 );
  SQRN2( t1, t0, 50 );
  MUL2 ( t1, t1, t0 );
  SQRN2( t2, t1, 100 );
  MUL2 ( t1, t2, t1 );
  SQRN2( t1, t1, 50 );
  MUL2 ( t0, t1, t0 );
  SQRN2( t0, t0, 2 );
  fd_ed25519_lane_mul( r0, &t0[0], &a[0] );
  fd_ed25519_lane_mul( r1, &t0[1], &a[1] );
#undef SQR2
#undef MUL2
#undef SQRN2
}

/* Decompress two sets of eight points, x = (u v^3)(u v^7)^((p-5)/8).
   Permissive y encoding and x=0/sign=1 are accepted, exactly like
   point_frombytes_2x.  Returns the success masks; failed lanes are
   replaced by the identity before any group operation. */
static inline void
fd_ed25519_lane_decode2( fd_ed25519_lane_point_t * r0,  uchar const * const buf0[8], int * valid0,
                         fd_ed25519_lane_point_t * r1,  uchar const * const buf1[8], int * valid1 ) {
  fd_ed25519_lane_point_t * r[2] = { r0, r1 };
  uchar const * const * buf[2] = { buf0, buf1 };
  fd_ed25519_lane_fe_t u[2], v[2], uv3[2], uv7[2], d, sqrtm1;
  int sign[2] = { 0, 0 };
  fd_ed25519_lane_bcast_fe( &d, fd_f25519_d );
  fd_ed25519_lane_bcast_fe( &sqrtm1, fd_f25519_sqrtm1 );
  for( int n=0; n<2; n++ ) {
    ulong limbs[5][8];
    for( int j=0; j<8; j++ ) {
      uchar const * b = buf[n][j];
      limbs[0][j] =  fd_ulong_load_8( b    )       & FD_ED25519_LANE_MASK;
      limbs[1][j] = (fd_ulong_load_8( b+ 6 )>> 3) & FD_ED25519_LANE_MASK;
      limbs[2][j] = (fd_ulong_load_8( b+12 )>> 6) & FD_ED25519_LANE_MASK;
      limbs[3][j] = (fd_ulong_load_8( b+19 )>> 1) & FD_ED25519_LANE_MASK;
      limbs[4][j] = (fd_ulong_load_8( b+24 )>>12) & FD_ED25519_LANE_MASK;
      sign[n] |= (int)(b[31]>>7)<<j;
    }
    fd_ed25519_lane_zero( r[n] );
    for( int i=0; i<5; i++ ) r[n]->y.limb[i] = wwv_ldu( limbs[i] );
    fd_ed25519_lane_fe_t y2, v2, v3;
    fd_ed25519_lane_sqr( &y2, &r[n]->y );
    fd_ed25519_lane_mul( &v[n], &y2, &d );
    fd_ed25519_lane_sub( &u[n], &y2, &r[n]->z );
    fd_ed25519_lane_add_raw( &v[n], &v[n], &r[n]->z );  /* carried + 1 is f52 */
    fd_ed25519_lane_sqr( &v2, &v[n] );
    fd_ed25519_lane_mul( &v3, &v2, &v[n] );
    fd_ed25519_lane_mul( &uv3[n], &u[n], &v3 );
    fd_ed25519_lane_sqr( &uv7[n], &v3 );
    fd_ed25519_lane_mul( &uv7[n], &uv7[n], &v[n] );
    fd_ed25519_lane_mul( &uv7[n], &uv7[n], &u[n] );
  }
  fd_ed25519_lane_pow22523_2( &r0->x, &uv7[0], &r1->x, &uv7[1] );
  for( int n=0; n<2; n++ ) {
    fd_ed25519_lane_fe_t check, tmp;
    fd_ed25519_lane_mul( &r[n]->x, &r[n]->x, &uv3[n] );
    fd_ed25519_lane_sqr( &check, &r[n]->x );
    fd_ed25519_lane_mul( &check, &check, &v[n] );
    fd_ed25519_lane_sub_raw( &tmp, &check, &u[n] );
    int correct = fd_ed25519_lane_is_zero( tmp );
    fd_ed25519_lane_add_raw( &tmp, &check, &u[n] );
    int flipped = fd_ed25519_lane_is_zero( tmp );
    int valid = correct | flipped;
    fd_ed25519_lane_mul( &tmp, &r[n]->x, &sqrtm1 );
    for( int i=0; i<5; i++ ) r[n]->x.limb[i] = wwv_if( flipped & ~correct, tmp.limb[i], r[n]->x.limb[i] );
    /* Canonical parity.  Normalization leaves only p..p+18 as possible
       noncanonical values.  Subtracting odd p flips parity in those lanes. */
    tmp = fd_ed25519_lane_normalize( r[n]->x );
    int ge_p = wwv_ge( tmp.limb[0], wwv_bcast( FD_ED25519_LANE_MASK-18UL ) );
    for( int i=1; i<5; i++ ) ge_p &= wwv_eq( tmp.limb[i], wwv_bcast( FD_ED25519_LANE_MASK ) );
    int parity = wwv_ne( wwv_and( tmp.limb[0], wwv_one() ), wwv_zero() ) ^ ge_p;
    fd_ed25519_lane_neg( &tmp, &r[n]->x );
    for( int i=0; i<5; i++ ) {
      r[n]->x.limb[i] = wwv_if( sign[n] ^ parity, tmp.limb[i], r[n]->x.limb[i] );
      r[n]->x.limb[i] = wwv_if( valid, r[n]->x.limb[i], wwv_zero() );
      r[n]->y.limb[i] = wwv_if( valid, r[n]->y.limb[i], wwv_bcast( (ulong)(i==0) ) );
    }
    fd_ed25519_lane_mul( &r[n]->t, &r[n]->x, &r[n]->y );
    if( n==0 ) *valid0 = valid; else *valid1 = valid;
  }
}

static inline int
fd_ed25519_lane_decode( fd_ed25519_lane_point_t * r,
                        uchar const * const       buf[8] ) {
  fd_ed25519_lane_point_t dup;
  int valid, unused;
  fd_ed25519_lane_decode2( r, buf, &valid, &dup, buf, &unused );
  return valid;
}

static inline int
fd_ed25519_lane_small_order( fd_ed25519_lane_point_t const * r ) {
  fd_ed25519_lane_fe_t y0, y1;
  fd_ed25519_lane_bcast_fe( &y0, fd_ed25519_order8_point_y0 );
  fd_ed25519_lane_bcast_fe( &y1, fd_ed25519_order8_point_y1 );
  fd_ed25519_lane_sub_raw( &y0, &r->y, &y0 );
  fd_ed25519_lane_sub_raw( &y1, &r->y, &y1 );
  return fd_ed25519_lane_is_zero( r->x ) | fd_ed25519_lane_is_zero( r->y )
       | fd_ed25519_lane_is_zero( y0 ) | fd_ed25519_lane_is_zero( y1 );
}

/* Signed digit recoding, digits in [-2^(w-1), 2^(w-1)).  Scalars are
   < 2^253, so the top digit never carries out. */
static inline void
fd_ed25519_lane_recode4( uchar const s[32], schar d[64] ) {
  int carry = 0;
  for( int w=0; w<64; w++ ) {
    int v = ((s[w>>1]>>(4*(w&1)))&15) + carry;
    carry = (v+8)>>4;
    d[w] = (schar)(v-16*carry);
  }
}

static inline void
fd_ed25519_lane_recode8( uchar const s[32], short d[32] ) {
  int carry = 0;
  for( int w=0; w<32; w++ ) {
    int v = s[w] + carry;
    carry = (v+128)>>8;
    d[w] = (short)(v-256*carry);
  }
}

/* No reduction of negative scalars modulo L: A may contain torsion.
   Caller passes -A (z=1) and the original reduced, nonnegative k and S
   (< L < 2^253).  R is affine.  Returns the mask of lanes where
   [S]B + [k](-A) == R. */
static inline int
fd_ed25519_lane_verify( fd_ed25519_lane_point_t const * a,
                        fd_ed25519_lane_point_t const * r,
                        uchar const                     k[8][32],
                        uchar const                     s[8][32] ) {
  /* Signed digits per window and lane. */
  schar kd[64][8]; short sd[32][8];
  for( int j=0; j<8; j++ ) {
    schar kj[64]; short sj[32];
    fd_ed25519_lane_recode4( k[j], kj );
    fd_ed25519_lane_recode8( s[j], sj );
    for( int w=0; w<64; w++ ) kd[w][j] = kj[w];
    for( int w=0; w<32; w++ ) sd[w][j] = sj[w];
  }

  /* Table of [e](-A), e=0..8, lane-major limbs (p, m, k, nk, z). */
  ulong ktab[9][25][8] __attribute__((aligned(64)));
  fd_ed25519_lane_fe_t k2d;
  fd_ed25519_lane_bcast_fe( &k2d, fd_f25519_k );
  {
    fd_ed25519_lane_niels_t n1, n;
    fd_ed25519_lane_point_t p2, p3, p4, p6, tmp;
#define STORE_ENTRY(e,n) do {                                                   \
      for( int i=0; i<5; i++ ) {                                                \
        wwv_st( ktab[e][i],    (n)->p.limb[i]  ); wwv_st( ktab[e][5+i],  (n)->m.limb[i] ); \
        wwv_st( ktab[e][10+i], (n)->k.limb[i]  ); wwv_st( ktab[e][15+i], (n)->nk.limb[i] ); \
        wwv_st( ktab[e][20+i], (n)->z.limb[i]  );                                \
      }                                                                         \
    } while(0)
    for( int i=0; i<5; i++ ) {
      n.k.limb[i] = wwv_zero();
      n.nk.limb[i] = wwv_bcast( i ? FD_ED25519_LANE_2P : FD_ED25519_LANE_2P0 );
      n.p.limb[i] = n.m.limb[i] = n.z.limb[i] = wwv_bcast( (ulong)(i==0) );
    }
    STORE_ENTRY( 0, &n );
    fd_ed25519_lane_to_niels( &n1, a, &k2d );                    STORE_ENTRY( 1, &n1 );
    fd_ed25519_lane_point_dbl( &p2, a, 1 );
    fd_ed25519_lane_to_niels( &n, &p2, &k2d );                   STORE_ENTRY( 2, &n );
    fd_ed25519_lane_point_add( &p3, &p2, &n1, 1, 1 );
    fd_ed25519_lane_to_niels( &n, &p3, &k2d );                   STORE_ENTRY( 3, &n );
    fd_ed25519_lane_point_dbl( &p4, &p2, 1 );
    fd_ed25519_lane_to_niels( &n, &p4, &k2d );                   STORE_ENTRY( 4, &n );
    fd_ed25519_lane_point_add( &tmp, &p4, &n1, 1, 1 );
    fd_ed25519_lane_to_niels( &n, &tmp, &k2d );                  STORE_ENTRY( 5, &n );
    fd_ed25519_lane_point_dbl( &p6, &p3, 1 );
    fd_ed25519_lane_to_niels( &n, &p6, &k2d );                   STORE_ENTRY( 6, &n );
    fd_ed25519_lane_point_add( &tmp, &p6, &n1, 1, 1 );
    fd_ed25519_lane_to_niels( &n, &tmp, &k2d );                  STORE_ENTRY( 7, &n );
    fd_ed25519_lane_point_dbl( &tmp, &p4, 1 );
    fd_ed25519_lane_to_niels( &n, &tmp, &k2d );                  STORE_ENTRY( 8, &n );
#undef STORE_ENTRY
  }

  /* Windows from the top: 4 doublings, [k] digit, and every other
     window the 8-bit [S] digit from the fixed table. */
  fd_ed25519_lane_point_t acc;
  fd_ed25519_lane_zero( &acc );
  for( int w=63; w>=0; w-- ) {
    if( w!=63 ) {
      for( int i=0; i<3; i++ ) fd_ed25519_lane_point_dbl( &acc, &acc, 0 );
      fd_ed25519_lane_point_dbl( &acc, &acc, 1 );
    }
    ulong const * sp[8], * sm[8], * sk[8], * sz[8];
    for( int j=0; j<8; j++ ) {
      int d = kd[w][j], neg = d<0;
      ulong const * e = &ktab[ neg ? -d : d ][0][j];
      sp[j] = e + (neg ? 40 : 0); sm[j] = e + (neg ? 0 : 40); sk[j] = e + (neg ? 120 : 80); sz[j] = e + 160;
    }
    fd_ed25519_lane_point_add_sel( &acc, &acc, sp, sm, sk, sz, 8UL, 1, 0, !(w&1) );
    if( !(w&1) ) {
      for( int j=0; j<8; j++ ) {
        int d = sd[w>>1][j], neg = d<0;
        ulong const * e = fd_ed25519_lane_base_table + 20UL*(ulong)(neg ? -d : d);
        sp[j] = e + (neg ? 5 : 0); sm[j] = e + (neg ? 0 : 5); sk[j] = e + (neg ? 15 : 10);
      }
      fd_ed25519_lane_point_add_sel( &acc, &acc, sp, sm, sk, sz, 1UL, 0, 1, 0 );
    }
  }
  fd_ed25519_lane_fe_t x, y;
  fd_ed25519_lane_mul( &x, &r->x, &acc.z );
  fd_ed25519_lane_mul( &y, &r->y, &acc.z );
  fd_ed25519_lane_sub_raw( &x, &x, &acc.x );
  fd_ed25519_lane_sub_raw( &y, &y, &acc.y );
  return fd_ed25519_lane_is_zero( x ) & fd_ed25519_lane_is_zero( y );
}

#endif /* HEADER_fd_src_ballet_ed25519_avx512_fd_ed25519_lane_h */
