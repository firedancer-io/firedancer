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
   Modifications: C SIMD primitives, looped convolution, separate carried
   Edwards formulas, joint radix-4 tables, and Firedancer point adapters.

   All field operands/results have unsigned limbs < 2^52.  They need
   not be canonical.  Operations allow exact output/input aliasing.
   No secret-key operation may use this variable-time table lookup. */

#include "../fd_curve25519.h"
#include "../../../util/simd/fd_avx512.h"
#include <stddef.h> /* offsetof */

#define FD_ED25519_LANE_MASK ((1UL<<51)-1UL)

typedef struct { wwv_t limb[5]; } fd_ed25519_lane_fe_t;
typedef struct { fd_ed25519_lane_fe_t x, y, z, t; } fd_ed25519_lane_point_t;

/* One simultaneous carry maps nonnegative limbs < 2^61 to limbs
   < 2^51+19*1024 < 2^52.  There are no signed/wrapped inputs. */
static inline void
fd_ed25519_lane_carry( fd_ed25519_lane_fe_t * r ) {
  wwv_t c[5];
  for( int i=0; i<5; i++ ) c[i] = wwv_shr( r->limb[i], 51 );
  for( int i=0; i<5; i++ ) r->limb[i] = wwv_and( r->limb[i], wwv_bcast( FD_ED25519_LANE_MASK ) );
  r->limb[0] = wwv_add( r->limb[0], wwv_mul( c[4], wwv_bcast( 19UL ) ) );
  for( int i=1; i<5; i++ ) r->limb[i] = wwv_add( r->limb[i], c[i-1] );
}

static inline void
fd_ed25519_lane_add( fd_ed25519_lane_fe_t *       r,
                     fd_ed25519_lane_fe_t const * a,
                     fd_ed25519_lane_fe_t const * b ) {
  for( int i=0; i<5; i++ ) r->limb[i] = wwv_add( a->limb[i], b->limb[i] );
  fd_ed25519_lane_carry( r );
}

static inline void
fd_ed25519_lane_sub( fd_ed25519_lane_fe_t *       r,
                     fd_ed25519_lane_fe_t const * a,
                     fd_ed25519_lane_fe_t const * b ) {
  /* 4p prevents underflow for u52 inputs; result < 6*2^51. */
  for( int i=0; i<5; i++ )
    r->limb[i] = wwv_sub( wwv_add( a->limb[i], wwv_bcast( 4UL*(FD_ED25519_LANE_MASK-(i==0 ? 18UL : 0UL)) ) ), b->limb[i] );
  fd_ed25519_lane_carry( r );
}

static inline void
fd_ed25519_lane_mul( fd_ed25519_lane_fe_t *       r,
                     fd_ed25519_lane_fe_t const * a,
                     fd_ed25519_lane_fe_t const * b ) {
  /* Product degree d contributes lo[d] + 2^52 hi[d].  Shift the
     high half one radix-51 degree and double it.  Each accumulator
     contains at most five u52 terms.  After folding degrees 5..9,
     coefficients are bounded by (267,213,159,105,51)*2^52 < 2^61.
     Thus all adds, shifts and the multiply by 19 are exact in u64. */
  wwv_t lo[10], hi[9];
  for( int i=0; i<10; i++ ) lo[i] = wwv_zero();
  for( int i=0; i< 9; i++ ) hi[i] = wwv_zero();
  for( int i=0; i<5; i++ ) {
    for( int j=0; j<5; j++ ) {
      lo[i+j] = _mm512_madd52lo_epu64( lo[i+j], a->limb[i], b->limb[j] );
      hi[i+j] = _mm512_madd52hi_epu64( hi[i+j], a->limb[i], b->limb[j] );
    }
  }
  for( int i=0; i<9; i++ ) lo[i+1] = wwv_add( lo[i+1], wwv_shl( hi[i], 1 ) );
  for( int i=0; i<5; i++ ) r->limb[i] = wwv_add( lo[i], wwv_mul( lo[i+5], wwv_bcast( 19UL ) ) );
  fd_ed25519_lane_carry( r );
}

static inline void
fd_ed25519_lane_sqr( fd_ed25519_lane_fe_t *       r,
                     fd_ed25519_lane_fe_t const * a ) {
  /* Same convolution as mul(a,a), but compute each off-diagonal
     product once and double its two halves.  The term matrix and
     bounds are identical to mul.  IFMA inputs are never doubled. */
  wwv_t lo[10], hi[9];
  for( int i=0; i<10; i++ ) lo[i] = wwv_zero();
  for( int i=0; i< 9; i++ ) hi[i] = wwv_zero();
  for( int i=0; i<5; i++ ) {
    for( int j=i; j<5; j++ ) {
      wwv_t l = _mm512_madd52lo_epu64( wwv_zero(), a->limb[i], a->limb[j] );
      wwv_t h = _mm512_madd52hi_epu64( wwv_zero(), a->limb[i], a->limb[j] );
      if( i!=j ) { l = wwv_add( l, l ); h = wwv_add( h, h ); }
      lo[i+j] = wwv_add( lo[i+j], l );
      hi[i+j] = wwv_add( hi[i+j], h );
    }
  }
  for( int i=0; i<9; i++ ) lo[i+1] = wwv_add( lo[i+1], wwv_shl( hi[i], 1 ) );
  for( int i=0; i<5; i++ ) r->limb[i] = wwv_add( lo[i], wwv_mul( lo[i+5], wwv_bcast( 19UL ) ) );
  fd_ed25519_lane_carry( r );
}

static inline void
fd_ed25519_lane_zero( fd_ed25519_lane_point_t * r ) {
  for( int i=0; i<5; i++ ) {
    r->x.limb[i] = r->t.limb[i] = wwv_zero();
    r->y.limb[i] = r->z.limb[i] = wwv_bcast( (ulong)(i==0) );
  }
}

/* Complete extended Edwards addition (a=-1), with k=2d. */
static inline void
fd_ed25519_lane_point_add( fd_ed25519_lane_point_t *       r,
                           fd_ed25519_lane_point_t const * p,
                           fd_ed25519_lane_point_t const * q,
                           fd_ed25519_lane_fe_t const *    k ) {
  fd_ed25519_lane_fe_t a, b, c, d, e, f, g, h;
  fd_ed25519_lane_sub( &a, &p->y, &p->x );
  fd_ed25519_lane_sub( &b, &q->y, &q->x );
  fd_ed25519_lane_mul( &a, &a, &b );
  fd_ed25519_lane_add( &b, &p->y, &p->x );
  fd_ed25519_lane_add( &c, &q->y, &q->x );
  fd_ed25519_lane_mul( &b, &b, &c );
  fd_ed25519_lane_mul( &c, &p->t, &q->t );
  fd_ed25519_lane_mul( &c, &c, k );
  fd_ed25519_lane_mul( &d, &p->z, &q->z );
  fd_ed25519_lane_add( &d, &d, &d );
  fd_ed25519_lane_sub( &e, &b, &a );
  fd_ed25519_lane_sub( &f, &d, &c );
  fd_ed25519_lane_add( &g, &d, &c );
  fd_ed25519_lane_add( &h, &b, &a );
  fd_ed25519_lane_mul( &r->x, &e, &f );
  fd_ed25519_lane_mul( &r->y, &g, &h );
  fd_ed25519_lane_mul( &r->z, &f, &g );
  fd_ed25519_lane_mul( &r->t, &e, &h );
}

static inline void
fd_ed25519_lane_point_dbl( fd_ed25519_lane_point_t *       r,
                           fd_ed25519_lane_point_t const * p ) {
  fd_ed25519_lane_fe_t a, b, c, e, f, g, h, zero;
  for( int i=0; i<5; i++ ) zero.limb[i] = wwv_zero();
  fd_ed25519_lane_sqr( &a, &p->x );
  fd_ed25519_lane_sqr( &b, &p->y );
  fd_ed25519_lane_sqr( &c, &p->z );
  fd_ed25519_lane_add( &c, &c, &c );
  fd_ed25519_lane_mul( &e, &p->x, &p->y );
  fd_ed25519_lane_add( &e, &e, &e );
  fd_ed25519_lane_sub( &g, &b, &a );
  fd_ed25519_lane_sub( &f, &g, &c );
  fd_ed25519_lane_sub( &h, &zero, &a );
  fd_ed25519_lane_sub( &h, &h, &b );
  fd_ed25519_lane_mul( &r->x, &e, &f );
  fd_ed25519_lane_mul( &r->y, &g, &h );
  fd_ed25519_lane_mul( &r->z, &f, &g );
  fd_ed25519_lane_mul( &r->t, &e, &h );
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
  /* Two sequential carry/fold passes turn u52 into u51 limbs.
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

/* The same addition chain as fd_f25519_pow22523, executed across
   signatures: r = a^(2^252-3). */
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

/* Returns a mask of successful decompressions.  Permissive y encoding
   and x=0/sign=1 are accepted, exactly like point_frombytes_2x.  Failed
   lanes are replaced by the identity before any group operation. */
static inline int
fd_ed25519_lane_decode( fd_ed25519_lane_point_t * r,
                        uchar const * const      buf[8] ) {
  ulong limbs[5][8];
  int sign = 0;
  for( int j=0; j<8; j++ ) {
    limbs[0][j] =  fd_ulong_load_8( buf[j]    )       & FD_ED25519_LANE_MASK;
    limbs[1][j] = (fd_ulong_load_8( buf[j]+ 6 )>> 3) & FD_ED25519_LANE_MASK;
    limbs[2][j] = (fd_ulong_load_8( buf[j]+12 )>> 6) & FD_ED25519_LANE_MASK;
    limbs[3][j] = (fd_ulong_load_8( buf[j]+19 )>> 1) & FD_ED25519_LANE_MASK;
    limbs[4][j] = (fd_ulong_load_8( buf[j]+24 )>>12) & FD_ED25519_LANE_MASK;
    sign |= (int)(buf[j][31]>>7)<<j;
  }
  fd_ed25519_lane_fe_t u, v, v2, v3, uv3, uv7, check, tmp, d, sqrtm1, zero;
  fd_ed25519_lane_zero( r );
  zero = r->x;
  for( int i=0; i<5; i++ ) r->y.limb[i] = wwv_ldu( limbs[i] );
  fd_ed25519_lane_bcast_fe( &d, fd_f25519_d );
  fd_ed25519_lane_bcast_fe( &sqrtm1, fd_f25519_sqrtm1 );
  fd_ed25519_lane_sqr( &u, &r->y );
  fd_ed25519_lane_mul( &v, &u, &d );
  fd_ed25519_lane_sub( &u, &u, &r->z );
  fd_ed25519_lane_add( &v, &v, &r->z );
  /* x = (u*v^3) * (u*v^7)^((p-5)/8). */
  fd_ed25519_lane_sqr( &v2, &v );
  fd_ed25519_lane_mul( &v3, &v2, &v );
  fd_ed25519_lane_mul( &uv3, &u, &v3 );
  fd_ed25519_lane_sqr( &uv7, &v3 );
  fd_ed25519_lane_mul( &uv7, &uv7, &v );
  fd_ed25519_lane_mul( &uv7, &uv7, &u );
  fd_ed25519_lane_pow22523( &r->x, &uv7 );
  fd_ed25519_lane_mul( &r->x, &r->x, &uv3 );
  fd_ed25519_lane_sqr( &check, &r->x );
  fd_ed25519_lane_mul( &check, &check, &v );
  fd_ed25519_lane_sub( &tmp, &check, &u );
  int correct = fd_ed25519_lane_is_zero( tmp );
  fd_ed25519_lane_add( &tmp, &check, &u );
  int flipped = fd_ed25519_lane_is_zero( tmp );
  int valid = correct | flipped;
  fd_ed25519_lane_mul( &tmp, &r->x, &sqrtm1 );
  for( int i=0; i<5; i++ ) r->x.limb[i] = wwv_if( flipped & ~correct, tmp.limb[i], r->x.limb[i] );
  /* Canonical parity.  Normalization leaves only p..p+18 as possible
     noncanonical values.  Subtracting odd p flips parity in those lanes. */
  tmp = fd_ed25519_lane_normalize( r->x );
  int ge_p = wwv_ge( tmp.limb[0], wwv_bcast( FD_ED25519_LANE_MASK-18UL ) );
  for( int i=1; i<5; i++ ) ge_p &= wwv_eq( tmp.limb[i], wwv_bcast( FD_ED25519_LANE_MASK ) );
  int parity = wwv_ne( wwv_and( tmp.limb[0], wwv_one() ), wwv_zero() ) ^ ge_p;
  fd_ed25519_lane_sub( &tmp, &zero, &r->x );
  for( int i=0; i<5; i++ ) {
    r->x.limb[i] = wwv_if( sign ^ parity, tmp.limb[i], r->x.limb[i] );
    r->x.limb[i] = wwv_if( valid, r->x.limb[i], wwv_zero() );
    r->y.limb[i] = wwv_if( valid, r->y.limb[i], wwv_bcast( (ulong)(i==0) ) );
  }
  fd_ed25519_lane_mul( &r->t, &r->x, &r->y );
  return valid;
}

static inline int
fd_ed25519_lane_small_order( fd_ed25519_lane_point_t const * r ) {
  fd_ed25519_lane_fe_t y0, y1;
  fd_ed25519_lane_bcast_fe( &y0, fd_ed25519_order8_point_y0 );
  fd_ed25519_lane_bcast_fe( &y1, fd_ed25519_order8_point_y1 );
  fd_ed25519_lane_sub( &y0, &r->y, &y0 );
  fd_ed25519_lane_sub( &y1, &r->y, &y1 );
  return fd_ed25519_lane_is_zero( r->x ) | fd_ed25519_lane_is_zero( r->y )
       | fd_ed25519_lane_is_zero( y0 ) | fd_ed25519_lane_is_zero( y1 );
}

/* No reduction of negative scalars modulo L: A may contain torsion.
   Caller passes -A and the original reduced, nonnegative k and S. */
static inline int
fd_ed25519_lane_verify( fd_ed25519_lane_point_t const * a,
                        fd_ed25519_lane_point_t const * r,
                        uchar const             k[8][32],
                        uchar const             s[8][32] ) {
  fd_ed25519_lane_point_t table[16], base, acc, q;
  fd_ed25519_point_t bases[8];
  fd_f25519_t ks[8];
  fd_ed25519_lane_fe_t curve_k;
  for( int j=0; j<8; j++ ) {
    fd_ed25519_point_set( &bases[j], fd_ed25519_base_point );
    fd_f25519_set( &ks[j], fd_f25519_k );
  }
  fd_ed25519_lane_pack_fe( &curve_k, ks );
  fd_ed25519_lane_pack( &base, bases );
  fd_ed25519_lane_zero( &table[0] );
  table[1] = *a;
  fd_ed25519_lane_point_dbl( &table[2], &table[1] );
  fd_ed25519_lane_point_add( &table[3], &table[2], &table[1], &curve_k );
  for( int i=4; i<16; i++ ) fd_ed25519_lane_point_add( &table[i], &table[i-4], &base, &curve_k );
  fd_ed25519_lane_zero( &acc );
  for( int bit=254; bit>=0; bit-=2 ) {
    fd_ed25519_lane_point_dbl( &acc, &acc );
    fd_ed25519_lane_point_dbl( &acc, &acc );
    ulong idx[8];
    for( int j=0; j<8; j++ )
      idx[j] = (ulong)(((k[j][bit>>3]>>(bit&7))&3) + 4*((s[j][bit>>3]>>(bit&7))&3))*sizeof(table[0]) + (ulong)j*sizeof(ulong);
    wwv_t offsets = wwv_ldu( idx );
    /* Public digits select independently, retaining each lane's offset.
       Use byte offsets rather than type-punning the point aggregate. */
    for( int i=0; i<5; i++ ) {
      q.x.limb[i] = _mm512_i64gather_epi64( offsets, (uchar const *)table + offsetof(fd_ed25519_lane_point_t,x) + (ulong)i*64UL, 1 );
      q.y.limb[i] = _mm512_i64gather_epi64( offsets, (uchar const *)table + offsetof(fd_ed25519_lane_point_t,y) + (ulong)i*64UL, 1 );
      q.z.limb[i] = _mm512_i64gather_epi64( offsets, (uchar const *)table + offsetof(fd_ed25519_lane_point_t,z) + (ulong)i*64UL, 1 );
      q.t.limb[i] = _mm512_i64gather_epi64( offsets, (uchar const *)table + offsetof(fd_ed25519_lane_point_t,t) + (ulong)i*64UL, 1 );
    }
    fd_ed25519_lane_point_add( &acc, &acc, &q, &curve_k );
  }
  q = *r; /* R is affine, just as in verify. */
  fd_ed25519_lane_mul( &q.x, &q.x, &acc.z );
  fd_ed25519_lane_mul( &q.y, &q.y, &acc.z );
  fd_ed25519_lane_sub( &q.x, &q.x, &acc.x );
  fd_ed25519_lane_sub( &q.y, &q.y, &acc.y );
  return fd_ed25519_lane_is_zero( q.x ) & fd_ed25519_lane_is_zero( q.y );
}

#endif /* HEADER_fd_src_ballet_ed25519_avx512_fd_ed25519_lane_h */
