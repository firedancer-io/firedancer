#ifndef HEADER_fd_src_ballet_ed25519_fd_f25519_h
#error "Do not include this directly; use fd_f25519.h"
#endif

#include "../../fd_ballet_base.h"
#include "fd_r52x5_inl.h"

#define FD_F25519_ALIGN 64

struct fd_f25519 {
  wwl_t el __attribute__((aligned(FD_F25519_ALIGN)));
};
typedef struct fd_f25519 fd_f25519_t;

#include "../table/fd_f25519_table_avx512.c"

FD_PROTOTYPES_BEGIN

#define FD_F25519_LIMB_MASK ((1UL << 51) - 1)

FD_FN_UNUSED FD_FN_CONST static wwl_t
fd_f25519_fold_unsigned( wwl_t x ) {
  wwl_t const mask  = wwl( FD_F25519_LIMB_MASK, FD_F25519_LIMB_MASK,
                           FD_F25519_LIMB_MASK, FD_F25519_LIMB_MASK,
                           FD_F25519_LIMB_MASK, 0L, 0L, 0L );
  wwl_t const shift = wwl( 51L, 51L, 51L, 51L, 51L, 0L, 0L, 0L );
  wwl_t const perm  = wwl(  4L,  0L,  1L,  2L,  3L, 5L, 6L, 7L );
  wwl_t const scale = wwl( 19L,  1L,  1L,  1L,  1L, 0L, 0L, 0L );

  wwl_t carry   = wwl_shru_vector( x, shift );
  wwl_t rotated = wwl_permute( perm, carry );
  return wwl_madd52lo( wwl_and( x, mask ), scale, rotated );
}

/* fd_f25519_reduce performs weak reduction: carries from each limb into
   the next, wrapping limb 4's carry by *19 because 2^255 = 19 mod p. */
FD_25519_INLINE void
fd_f25519_reduce( ulong out[5], wwl_t in ) {
  long h[8] __attribute__((aligned(FD_F25519_ALIGN)));
  wwl_st( h, fd_f25519_fold_unsigned( in ) );
  out[0] = (ulong)h[0];
  out[1] = (ulong)h[1];
  out[2] = (ulong)h[2];
  out[3] = (ulong)h[3];
  out[4] = (ulong)h[4];
}

/* fd_f25519_mul computes r = a * b. */
FD_FN_UNUSED static fd_f25519_t *
fd_f25519_mul( fd_f25519_t       * r,
               fd_f25519_t const * a,
               fd_f25519_t const * b ) {
  wwl_t const zero = wwl_zero();

  wwl_t ax = a->el;
  wwl_t x0 = wwl_permute( wwl_bcast( 0L ), ax );
  wwl_t x1 = wwl_permute( wwl_bcast( 1L ), ax );
  wwl_t x2 = wwl_permute( wwl_bcast( 2L ), ax );
  wwl_t x3 = wwl_permute( wwl_bcast( 3L ), ax );
  wwl_t x4 = wwl_permute( wwl_bcast( 4L ), ax );

  wwl_t y = b->el;
  wwl_t t0 = wwl_madd52lo( zero,                                      x0, y );
  wwl_t t1 = wwl_madd52lo( wwl_shl( wwl_madd52hi( zero, x0, y ), 1 ), x1, y );
  wwl_t t2 = wwl_madd52lo( wwl_shl( wwl_madd52hi( zero, x1, y ), 1 ), x2, y );
  wwl_t t3 = wwl_madd52lo( wwl_shl( wwl_madd52hi( zero, x2, y ), 1 ), x3, y );
  wwl_t t4 = wwl_madd52lo( wwl_shl( wwl_madd52hi( zero, x3, y ), 1 ), x4, y );
  wwl_t t5 =               wwl_shl( wwl_madd52hi( zero, x4, y ), 1 );

  wwl_t p0j =                  t0;
  wwl_t p1j = wwl_slide( zero, t1, 7 );
  wwl_t p2j = wwl_slide( zero, t2, 6 );
  wwl_t p3j = wwl_slide( zero, t3, 5 );
  wwl_t p4j = wwl_slide( zero, t4, 4 ); wwl_t q4j = wwl_slide( t4, zero, 4 );
  wwl_t p5j = wwl_slide( zero, t5, 3 ); wwl_t q5j = wwl_slide( t5, zero, 3 );

  wwl_t zl = wwl_add( wwl_add( wwl_add( p0j, p1j ), wwl_add( p2j, p3j ) ), wwl_add( p4j, p5j ) );
  wwl_t zh = wwl_add( q4j, q5j );

  wwl_t za = wwl_and( zl, wwl( -1L, -1L, -1L, -1L, -1L, 0L, 0L, 0L ) );
  wwl_t zb = wwl_slide( zl, zh, 5 );

  wwl_t z = wwl_add( wwl_add( za, zb ), wwl_add( wwl_shl( zb, 1 ), wwl_shl( zb, 4 ) ) );
  r->el = fd_f25519_fold_unsigned( z );
  return r;
}


/* fd_f25519_sqr computes r = a^2. */
FD_FN_UNUSED static fd_f25519_t *
fd_f25519_sqr( fd_f25519_t       * r,
               fd_f25519_t const * a ) {
  wwl_t const zero = wwl_zero();
  wwl_t aa = a->el;

  wwl_t x0 = wwl_permute( wwl( 0L, 0L, 0L, 0L, 0L, 2L, 3L, 3L ), aa );
  wwl_t x1 = wwl_permute( wwl( 0L, 1L, 2L, 3L, 4L, 3L, 3L, 4L ), aa );
  wwl_t x2 = wwl_permute( wwl( 4L, 5L, 1L, 1L, 1L, 1L, 2L, 5L ), aa );
  wwl_t x3 = wwl_permute( wwl( 4L, 5L, 1L, 2L, 3L, 4L, 4L, 5L ), aa );
  wwl_t x4 = wwl_permute( wwl( 5L, 5L, 5L, 5L, 2L, 5L, 5L, 5L ), aa );

  wwl_t p0l = wwl_madd52lo( zero, x0, x1 );
  wwl_t p0h = wwl_madd52hi( zero, x0, x1 );
  wwl_t p1l = wwl_madd52lo( zero, x2, x3 );
  wwl_t p1h = wwl_madd52hi( zero, x2, x3 );
  wwl_t p2l = wwl_madd52lo( zero, x4, x4 );
  wwl_t p2h = wwl_madd52hi( zero, x4, x4 );

  p0l = wwl_shl_vector( p0l, wwl( 0L, 1L, 1L, 1L, 1L, 1L, 0L, 1L ) );
  p0h = wwl_shl_vector( p0h, wwl( 1L, 2L, 2L, 2L, 2L, 2L, 1L, 2L ) );
  p1l = wwl_shl_vector( p1l, wwl( 0L, 0L, 0L, 1L, 1L, 1L, 1L, 0L ) );
  p1h = wwl_shl_vector( p1h, wwl( 1L, 0L, 1L, 2L, 2L, 2L, 2L, 0L ) );
  p2h = wwl_shl( p2h, 1 );

  wwl_t const mask1 = wwl( -1L, 0L, 0L, 0L, 0L, 0L, 0L, 0L );

  wwl_t zll = wwl_add( wwl_add( p0l, wwl_andnot( mask1, p1l ) ), p2l );
  wwl_t zlh = wwl_add( wwl_add( p0h, wwl_andnot( mask1, p1h ) ), p2h );
  wwl_t zhl = wwl_and( mask1, p1l );
  wwl_t zhh = wwl_and( mask1, p1h );

  wwl_t zl = wwl_add( zll, wwl_slide( zero, zlh, 7 ) );
  wwl_t zh = wwl_add( zhl, wwl_add( wwl_slide( zero, zhh, 7 ), wwl_slide( zlh, zero, 7 ) ) );

  wwl_t za = wwl_and( zl, wwl( -1L, -1L, -1L, -1L, -1L, 0L, 0L, 0L ) );
  wwl_t zb = wwl_slide( zl, zh, 5 );

  wwl_t z = wwl_add( wwl_add( za, zb ), wwl_add( wwl_shl( zb, 1 ), wwl_shl( zb, 4 ) ) );

  r->el = fd_f25519_fold_unsigned( z );
  return r;
}

/* fd_f25519_add computes r = a + b (with fold). */
FD_25519_INLINE fd_f25519_t *
fd_f25519_add( fd_f25519_t *       r,
               fd_f25519_t const * a,
               fd_f25519_t const * b ) {
  r->el = fd_f25519_fold_unsigned( wwl_add( a->el, b->el ) );
  return r;
}

/* fd_f25519_sub computes r = a - b (with fold).
   Adds 16*p bias to avoid underflow. */
FD_25519_INLINE fd_f25519_t *
fd_f25519_sub( fd_f25519_t *       r,
               fd_f25519_t const * a,
               fd_f25519_t const * b ) {
  wwl_t const bias = wwl( (long)0x7ffffffffffed0UL, (long)0x7ffffffffffff0UL,
                          (long)0x7ffffffffffff0UL, (long)0x7ffffffffffff0UL,
                          (long)0x7ffffffffffff0UL, 0L, 0L, 0L );
  r->el = fd_f25519_fold_unsigned( wwl_add( a->el, wwl_sub( bias, b->el ) ) );
  return r;
}

/* fd_f25519_add_nr computes r = a + b without reduction. */
FD_25519_INLINE fd_f25519_t *
fd_f25519_add_nr( fd_f25519_t *       r,
                  fd_f25519_t const * a,
                  fd_f25519_t const * b ) {
  r->el = wwl_add( a->el, b->el );
  return r;
}

/* fd_f25519_sub_nr computes r = a - b without final reduction.
   Adds 4*p to avoid underflow. */
FD_25519_INLINE fd_f25519_t *
fd_f25519_sub_nr( fd_f25519_t *       r,
                  fd_f25519_t const * a,
                  fd_f25519_t const * b ) {
  wwl_t const bias = wwl( (long)0x1fffffffffffb4UL, (long)0x1ffffffffffffcUL,
                          (long)0x1ffffffffffffcUL, (long)0x1ffffffffffffcUL,
                          (long)0x1ffffffffffffcUL, 0L, 0L, 0L );
  r->el = wwl_add( a->el, wwl_sub( bias, b->el ) );
  return r;
}

/* fd_f25519_neg computes r = -a. */
FD_25519_INLINE fd_f25519_t *
fd_f25519_neg( fd_f25519_t *       r,
               fd_f25519_t const * a ) {
  wwl_t const bias = wwl( (long)0x7ffffffffffed0UL, (long)0x7ffffffffffff0UL,
                          (long)0x7ffffffffffff0UL, (long)0x7ffffffffffff0UL,
                          (long)0x7ffffffffffff0UL, 0L, 0L, 0L );
  r->el = fd_f25519_fold_unsigned( wwl_sub( bias, a->el ) );
  return r;
}

/* fd_f25519_mul_121666 computes r = a * 121666. */
FD_25519_INLINE fd_f25519_t *
fd_f25519_mul_121666( fd_f25519_t *       r,
                      fd_f25519_t const * a ) {
  wwl_t const zero = wwl_zero();
  wwl_t const k    = wwl_bcast( 121666L );

  wwl_t lo = wwl_madd52lo( zero, k, a->el );
  wwl_t hi = wwl_shl( wwl_madd52hi( zero, k, a->el ), 1 );
  r->el = fd_f25519_fold_unsigned( wwl_add( lo, hi ) );
  return r;
}

/* fd_f25519_frombytes deserializes a 32-byte LE buffer into a field element. */
FD_25519_INLINE fd_f25519_t *
fd_f25519_frombytes( fd_f25519_t * r,
                     uchar const   buf[ 32 ] ) {
  r->el = wwl( fd_ulong_load_8_fast( buf    )        & FD_F25519_LIMB_MASK,
              (fd_ulong_load_8_fast( buf+ 6 ) >>  3) & FD_F25519_LIMB_MASK,
              (fd_ulong_load_8_fast( buf+12 ) >>  6) & FD_F25519_LIMB_MASK,
              (fd_ulong_load_8_fast( buf+19 ) >>  1) & FD_F25519_LIMB_MASK,
              (fd_ulong_load_8_fast( buf+24 ) >> 12) & FD_F25519_LIMB_MASK,
              0L,
              0L,
              0L );
  return r;
}

/* fd_f25519_canonical_limbs reduces a field element to its unique
   canonical representative in [0, p) as 5 radix-2^51 limbs. */
FD_25519_INLINE void
fd_f25519_canonical_limbs( ulong               h[5],
                           fd_f25519_t const * a ) {
  fd_f25519_reduce( h, a->el );

  ulong q = (h[0] + 19) >> 51;
  q = (h[1] + q) >> 51;
  q = (h[2] + q) >> 51;
  q = (h[3] + q) >> 51;
  q = (h[4] + q) >> 51;

  h[0] += 19 * q;

  ulong c;
  c = h[0] >> 51; h[0] &= FD_F25519_LIMB_MASK;
  h[1] += c;
  c = h[1] >> 51; h[1] &= FD_F25519_LIMB_MASK;
  h[2] += c;
  c = h[2] >> 51; h[2] &= FD_F25519_LIMB_MASK;
  h[3] += c;
  c = h[3] >> 51; h[3] &= FD_F25519_LIMB_MASK;
  h[4] += c;
  h[4] &= FD_F25519_LIMB_MASK;
}

/* fd_f25519_tobytes serializes a field element to a canonical 32-byte LE
   buffer. */
FD_25519_INLINE uchar *
fd_f25519_tobytes( uchar               out[ 32 ],
                   fd_f25519_t const * a ) {
  ulong h[5];
  fd_f25519_canonical_limbs( h, a );

  out[ 0] = (uchar)( h[0]       );
  out[ 1] = (uchar)( h[0] >>  8 );
  out[ 2] = (uchar)( h[0] >> 16 );
  out[ 3] = (uchar)( h[0] >> 24 );
  out[ 4] = (uchar)( h[0] >> 32 );
  out[ 5] = (uchar)( h[0] >> 40 );
  out[ 6] = (uchar)((h[0] >> 48) | (h[1] << 3));
  out[ 7] = (uchar)( h[1] >>  5 );
  out[ 8] = (uchar)( h[1] >> 13 );
  out[ 9] = (uchar)( h[1] >> 21 );
  out[10] = (uchar)( h[1] >> 29 );
  out[11] = (uchar)( h[1] >> 37 );
  out[12] = (uchar)((h[1] >> 45) | (h[2] << 6));
  out[13] = (uchar)( h[2] >>  2 );
  out[14] = (uchar)( h[2] >> 10 );
  out[15] = (uchar)( h[2] >> 18 );
  out[16] = (uchar)( h[2] >> 26 );
  out[17] = (uchar)( h[2] >> 34 );
  out[18] = (uchar)( h[2] >> 42 );
  out[19] = (uchar)((h[2] >> 50) | (h[3] << 1));
  out[20] = (uchar)( h[3] >>  7 );
  out[21] = (uchar)( h[3] >> 15 );
  out[22] = (uchar)( h[3] >> 23 );
  out[23] = (uchar)( h[3] >> 31 );
  out[24] = (uchar)( h[3] >> 39 );
  out[25] = (uchar)((h[3] >> 47) | (h[4] << 4));
  out[26] = (uchar)( h[4] >>  4 );
  out[27] = (uchar)( h[4] >> 12 );
  out[28] = (uchar)( h[4] >> 20 );
  out[29] = (uchar)( h[4] >> 28 );
  out[30] = (uchar)( h[4] >> 36 );
  out[31] = (uchar)( h[4] >> 44 );

  return out;
}

/* fd_f25519_if sets r = a0 if cond, else r = a1.
   Constant time. */
FD_25519_INLINE fd_f25519_t *
fd_f25519_if( fd_f25519_t *       r,
              int const           cond,
              fd_f25519_t const * a0,
              fd_f25519_t const * a1 ) {
  int mask = (-!!cond) & 0xff;
  r->el = wwl_if( mask, a0->el, a1->el );
  return r;
}

/* fd_f25519_swap_if swaps a, b if cond.
   Constant time. */
FD_25519_INLINE void
fd_f25519_swap_if( fd_f25519_t * restrict a,
                   fd_f25519_t * restrict b,
                   int const              cond ) {
  int mask = (-!!cond) & 0xff;
  wwl_t va = a->el;
  wwl_t vb = b->el;
  wwl_t t  = wwl_xor( va, vb );
  t = wwl_if( mask, t, wwl_zero() );
  a->el = wwl_xor( va, t );
  b->el = wwl_xor( vb, t );
}

/* fd_f25519_set copies r = a. */
FD_25519_INLINE fd_f25519_t *
fd_f25519_set( fd_f25519_t *       r,
               fd_f25519_t const * a ) {
  r->el = a->el;
  return r;
}

/* fd_f25519_is_zero returns 1 if a == 0 (mod p), 0 otherwise. */
FD_25519_INLINE int
fd_f25519_is_zero( fd_f25519_t const * a ) {
  ulong h[5];
  fd_f25519_canonical_limbs( h, a );
  return (h[0] | h[1] | h[2] | h[3] | h[4]) == 0;
}

/* fd_f25519_sgn returns the sign of a (bit 0 of canonical form). */
FD_25519_INLINE int
fd_f25519_sgn( fd_f25519_t const * a ) {
  ulong h[5];
  fd_f25519_canonical_limbs( h, a );
  return (int)(h[0] & 1);
}

FD_25519_INLINE void
fd_f25519_mul2( fd_f25519_t * r1, fd_f25519_t const * a1, fd_f25519_t const * b1,
                fd_f25519_t * r2, fd_f25519_t const * a2, fd_f25519_t const * b2 ) {
  fd_f25519_mul( r1, a1, b1 );
  fd_f25519_mul( r2, a2, b2 );
}

FD_PROTOTYPES_END
