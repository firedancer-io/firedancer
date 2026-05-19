#ifndef HEADER_fd_src_ballet_ed25519_fd_f25519_h
#error "Do not include this directly; use fd_f25519.h"
#endif

/* This header provides the AVX-512 field element implementation for
   GF(2^255-19).  A field element is represented as 5 radix-2^51 limbs.

    ele = el[0] + el[1]*2^51 + el[2]*2^102 + el[3]*2^153 + el[4]*2^204

   Limbs may grow up to 2^54 between reductions. */

#include "../../fd_ballet_base.h"
#include "fd_r52x5_inl.h"

#define FD_F25519_ALIGN 64

struct fd_f25519 {
  ulong el[5] __attribute__((aligned(FD_F25519_ALIGN)));
};
typedef struct fd_f25519 fd_f25519_t;

#include "../table/fd_f25519_table_avx512.c"

FD_PROTOTYPES_BEGIN

#define FD_F25519_LIMB_MASK ((1UL << 51) - 1)

/* fd_f25519_reduce performs weak reduction: carries from each limb into
   the next, wrapping limb 4's carry by *19 because 2^255 = 19 mod p. */
FD_25519_INLINE void
fd_f25519_reduce( ulong out[5], ulong const in[5] ) {
  ulong c0 = in[0] >> 51;
  ulong c1 = in[1] >> 51;
  ulong c2 = in[2] >> 51;
  ulong c3 = in[3] >> 51;
  ulong c4 = in[4] >> 51;

  out[0] = (in[0] & FD_F25519_LIMB_MASK) + c4 * 19;
  out[1] = (in[1] & FD_F25519_LIMB_MASK) + c0;
  out[2] = (in[2] & FD_F25519_LIMB_MASK) + c1;
  out[3] = (in[3] & FD_F25519_LIMB_MASK) + c2;
  out[4] = (in[4] & FD_F25519_LIMB_MASK) + c3;
}

#define FD_F25519_STORE_QUAD_LANE( r, Q, lane ) do { \
    (r)->el[0] = (ulong)wl_extract( Q##0, lane );     \
    (r)->el[1] = (ulong)wl_extract( Q##1, lane );     \
    (r)->el[2] = (ulong)wl_extract( Q##2, lane );     \
    (r)->el[3] = (ulong)wl_extract( Q##3, lane );     \
    (r)->el[4] = (ulong)wl_extract( Q##4, lane );     \
  } while(0)

/* fd_f25519_mul computes r = a * b.
   Precondition: a[i], b[i] < 2^54. */
FD_25519_INLINE fd_f25519_t *
fd_f25519_mul( fd_f25519_t       * r,
               fd_f25519_t const * a,
               fd_f25519_t const * b ) {
  ulong aa[5];
  ulong bb[5];
  fd_f25519_reduce( aa, a->el );
  fd_f25519_reduce( bb, b->el );

  FD_R52X5_QUAD_DECL( _R );
  fd_r52x5_quad_mul_fast( &_R0, &_R1, &_R2, &_R3, &_R4,
                          wl_bcast( (long)aa[0] ), wl_bcast( (long)aa[1] ),
                          wl_bcast( (long)aa[2] ), wl_bcast( (long)aa[3] ),
                          wl_bcast( (long)aa[4] ),
                          wl_bcast( (long)bb[0] ), wl_bcast( (long)bb[1] ),
                          wl_bcast( (long)bb[2] ), wl_bcast( (long)bb[3] ),
                          wl_bcast( (long)bb[4] ) );
  FD_R52X5_QUAD_REDUCE( _R, _R );
  FD_F25519_STORE_QUAD_LANE( r, _R, 0 );

  return r;
}

/* fd_f25519_sqr computes r = a^2. */
FD_25519_INLINE fd_f25519_t *
fd_f25519_sqr( fd_f25519_t *       r,
               fd_f25519_t const * a ) {
  ulong aa[5];
  fd_f25519_reduce( aa, a->el );

  FD_R52X5_QUAD_DECL( _R );
  fd_r52x5_quad_sqr_fast( &_R0, &_R1, &_R2, &_R3, &_R4,
                          wl_bcast( (long)aa[0] ), wl_bcast( (long)aa[1] ),
                          wl_bcast( (long)aa[2] ), wl_bcast( (long)aa[3] ),
                          wl_bcast( (long)aa[4] ) );
  FD_R52X5_QUAD_REDUCE( _R, _R );
  FD_F25519_STORE_QUAD_LANE( r, _R, 0 );

  return r;
}

/* fd_f25519_add computes r = a + b (with weak reduction). */
FD_25519_INLINE fd_f25519_t *
fd_f25519_add( fd_f25519_t *       r,
               fd_f25519_t const * a,
               fd_f25519_t const * b ) {
  ulong t[5];
  t[0] = a->el[0] + b->el[0];
  t[1] = a->el[1] + b->el[1];
  t[2] = a->el[2] + b->el[2];
  t[3] = a->el[3] + b->el[3];
  t[4] = a->el[4] + b->el[4];
  fd_f25519_reduce( r->el, t );
  return r;
}

/* fd_f25519_sub computes r = a - b (with weak reduction).
   Adds 16*p to avoid underflow before carry propagation. */
FD_25519_INLINE fd_f25519_t *
fd_f25519_sub( fd_f25519_t *       r,
               fd_f25519_t const * a,
               fd_f25519_t const * b ) {
  ulong t[5];
  t[0] = (a->el[0] + 0x7ffffffffffed0UL) - b->el[0];
  t[1] = (a->el[1] + 0x7ffffffffffff0UL) - b->el[1];
  t[2] = (a->el[2] + 0x7ffffffffffff0UL) - b->el[2];
  t[3] = (a->el[3] + 0x7ffffffffffff0UL) - b->el[3];
  t[4] = (a->el[4] + 0x7ffffffffffff0UL) - b->el[4];
  fd_f25519_reduce( r->el, t );
  return r;
}

/* fd_f25519_add_nr computes r = a + b without reduction.
   Caller must ensure result limbs stay < 2^54 before feeding into mul/sqr. */
FD_25519_INLINE fd_f25519_t *
fd_f25519_add_nr( fd_f25519_t *       r,
                  fd_f25519_t const * a,
                  fd_f25519_t const * b ) {
  r->el[0] = a->el[0] + b->el[0];
  r->el[1] = a->el[1] + b->el[1];
  r->el[2] = a->el[2] + b->el[2];
  r->el[3] = a->el[3] + b->el[3];
  r->el[4] = a->el[4] + b->el[4];
  return r;
}

/* fd_f25519_sub_nr computes r = a - b without final reduction.
   Adds 4*p to avoid underflow.  Result limbs stay < 2^54. */
FD_25519_INLINE fd_f25519_t *
fd_f25519_sub_nr( fd_f25519_t *       r,
                  fd_f25519_t const * a,
                  fd_f25519_t const * b ) {
  r->el[0] = (a->el[0] + 0x1fffffffffffb4UL) - b->el[0];
  r->el[1] = (a->el[1] + 0x1ffffffffffffcUL) - b->el[1];
  r->el[2] = (a->el[2] + 0x1ffffffffffffcUL) - b->el[2];
  r->el[3] = (a->el[3] + 0x1ffffffffffffcUL) - b->el[3];
  r->el[4] = (a->el[4] + 0x1ffffffffffffcUL) - b->el[4];
  return r;
}

/* fd_f25519_neg computes r = -a. */
FD_25519_INLINE fd_f25519_t *
fd_f25519_neg( fd_f25519_t *       r,
               fd_f25519_t const * a ) {
  ulong t[5];
  t[0] = 0x7ffffffffffed0UL - a->el[0];
  t[1] = 0x7ffffffffffff0UL - a->el[1];
  t[2] = 0x7ffffffffffff0UL - a->el[2];
  t[3] = 0x7ffffffffffff0UL - a->el[3];
  t[4] = 0x7ffffffffffff0UL - a->el[4];
  fd_f25519_reduce( r->el, t );
  return r;
}

/* fd_f25519_mul_121666 computes r = a * 121666. */
FD_25519_INLINE fd_f25519_t *
fd_f25519_mul_121666( fd_f25519_t *       r,
                      fd_f25519_t const * a ) {
  uint128 c0 = (uint128)a->el[0] * 121666;
  uint128 c1 = (uint128)a->el[1] * 121666;
  uint128 c2 = (uint128)a->el[2] * 121666;
  uint128 c3 = (uint128)a->el[3] * 121666;
  uint128 c4 = (uint128)a->el[4] * 121666;

  c1 += (ulong)(c0 >> 51);
  r->el[0] = (ulong)c0 & FD_F25519_LIMB_MASK;

  c2 += (ulong)(c1 >> 51);
  r->el[1] = (ulong)c1 & FD_F25519_LIMB_MASK;

  c3 += (ulong)(c2 >> 51);
  r->el[2] = (ulong)c2 & FD_F25519_LIMB_MASK;

  c4 += (ulong)(c3 >> 51);
  r->el[3] = (ulong)c3 & FD_F25519_LIMB_MASK;

  ulong carry = (ulong)(c4 >> 51);
  r->el[4] = (ulong)c4 & FD_F25519_LIMB_MASK;

  r->el[0] += carry * 19;
  r->el[1] += r->el[0] >> 51;
  r->el[0] &= FD_F25519_LIMB_MASK;

  return r;
}

/* fd_f25519_frombytes deserializes a 32-byte LE buffer into a field element.
   The five 51-bit limbs start at byte offsets 0, 6, 12, 19, and 24. */
FD_25519_INLINE fd_f25519_t *
fd_f25519_frombytes( fd_f25519_t * r,
                     uchar const   buf[ 32 ] ) {
  r->el[0] =  fd_ulong_load_8_fast( buf    )        & FD_F25519_LIMB_MASK;
  r->el[1] = (fd_ulong_load_8_fast( buf+ 6 ) >>  3) & FD_F25519_LIMB_MASK;
  r->el[2] = (fd_ulong_load_8_fast( buf+12 ) >>  6) & FD_F25519_LIMB_MASK;
  r->el[3] = (fd_ulong_load_8_fast( buf+19 ) >>  1) & FD_F25519_LIMB_MASK;
  r->el[4] = (fd_ulong_load_8_fast( buf+24 ) >> 12) & FD_F25519_LIMB_MASK;
  return r;
}

/* fd_f25519_tobytes serializes a field element to a canonical 32-byte LE
   buffer. */
FD_25519_INLINE uchar *
fd_f25519_tobytes( uchar               out[ 32 ],
                   fd_f25519_t const * a ) {
  ulong h[5];
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
  ulong mask = -(ulong)!!cond;
  r->el[0] = a1->el[0] ^ (mask & (a0->el[0] ^ a1->el[0]));
  r->el[1] = a1->el[1] ^ (mask & (a0->el[1] ^ a1->el[1]));
  r->el[2] = a1->el[2] ^ (mask & (a0->el[2] ^ a1->el[2]));
  r->el[3] = a1->el[3] ^ (mask & (a0->el[3] ^ a1->el[3]));
  r->el[4] = a1->el[4] ^ (mask & (a0->el[4] ^ a1->el[4]));
  return r;
}

/* fd_f25519_swap_if swaps a, b if cond.
   Constant time. */
FD_25519_INLINE void
fd_f25519_swap_if( fd_f25519_t * restrict a,
                   fd_f25519_t * restrict b,
                   int const              cond ) {
  ulong mask = -(ulong)!!cond;
  for( int i=0; i<5; i++ ) {
    ulong t = mask & (a->el[i] ^ b->el[i]);
    a->el[i] ^= t;
    b->el[i] ^= t;
  }
}

/* fd_f25519_set copies r = a. */
FD_25519_INLINE fd_f25519_t *
fd_f25519_set( fd_f25519_t *       r,
               fd_f25519_t const * a ) {
  r->el[0] = a->el[0];
  r->el[1] = a->el[1];
  r->el[2] = a->el[2];
  r->el[3] = a->el[3];
  r->el[4] = a->el[4];
  return r;
}

/* fd_f25519_is_zero returns 1 if a == 0 (mod p), 0 otherwise. */
FD_25519_INLINE int
fd_f25519_is_zero( fd_f25519_t const * a ) {
  uchar s[32];
  fd_f25519_tobytes( s, a );
  ulong acc = 0;
  for( int i=0; i<32; i++ ) acc |= s[i];
  return acc == 0;
}

FD_25519_INLINE void
fd_f25519_mul2( fd_f25519_t * r1, fd_f25519_t const * a1, fd_f25519_t const * b1,
                fd_f25519_t * r2, fd_f25519_t const * a2, fd_f25519_t const * b2 ) {
  ulong aa1[5]; ulong aa2[5];
  ulong bb1[5]; ulong bb2[5];
  fd_f25519_reduce( aa1, a1->el ); fd_f25519_reduce( bb1, b1->el );
  fd_f25519_reduce( aa2, a2->el ); fd_f25519_reduce( bb2, b2->el );

  FD_R52X5_QUAD_DECL( _A );
  FD_R52X5_QUAD_DECL( _B );
  _A0 = wl( (long)aa1[0], (long)aa2[0], 0L, 0L ); _B0 = wl( (long)bb1[0], (long)bb2[0], 0L, 0L );
  _A1 = wl( (long)aa1[1], (long)aa2[1], 0L, 0L ); _B1 = wl( (long)bb1[1], (long)bb2[1], 0L, 0L );
  _A2 = wl( (long)aa1[2], (long)aa2[2], 0L, 0L ); _B2 = wl( (long)bb1[2], (long)bb2[2], 0L, 0L );
  _A3 = wl( (long)aa1[3], (long)aa2[3], 0L, 0L ); _B3 = wl( (long)bb1[3], (long)bb2[3], 0L, 0L );
  _A4 = wl( (long)aa1[4], (long)aa2[4], 0L, 0L ); _B4 = wl( (long)bb1[4], (long)bb2[4], 0L, 0L );

  FD_R52X5_QUAD_DECL( _M );
  FD_R52X5_QUAD_MUL_FAST( _M, _A, _B );
  FD_R52X5_QUAD_REDUCE( _M, _M );
  FD_F25519_STORE_QUAD_LANE( r1, _M, 0 );
  FD_F25519_STORE_QUAD_LANE( r2, _M, 1 );
}

FD_25519_INLINE void
fd_f25519_mul3( fd_f25519_t * r1, fd_f25519_t const * a1, fd_f25519_t const * b1,
                fd_f25519_t * r2, fd_f25519_t const * a2, fd_f25519_t const * b2,
                fd_f25519_t * r3, fd_f25519_t const * a3, fd_f25519_t const * b3 ) {
  ulong aa1[5]; ulong aa2[5]; ulong aa3[5];
  ulong bb1[5]; ulong bb2[5]; ulong bb3[5];
  fd_f25519_reduce( aa1, a1->el ); fd_f25519_reduce( bb1, b1->el );
  fd_f25519_reduce( aa2, a2->el ); fd_f25519_reduce( bb2, b2->el );
  fd_f25519_reduce( aa3, a3->el ); fd_f25519_reduce( bb3, b3->el );

  FD_R52X5_QUAD_DECL( _A );
  FD_R52X5_QUAD_DECL( _B );
  _A0 = wl( (long)aa1[0], (long)aa2[0], (long)aa3[0], 0L ); _B0 = wl( (long)bb1[0], (long)bb2[0], (long)bb3[0], 0L );
  _A1 = wl( (long)aa1[1], (long)aa2[1], (long)aa3[1], 0L ); _B1 = wl( (long)bb1[1], (long)bb2[1], (long)bb3[1], 0L );
  _A2 = wl( (long)aa1[2], (long)aa2[2], (long)aa3[2], 0L ); _B2 = wl( (long)bb1[2], (long)bb2[2], (long)bb3[2], 0L );
  _A3 = wl( (long)aa1[3], (long)aa2[3], (long)aa3[3], 0L ); _B3 = wl( (long)bb1[3], (long)bb2[3], (long)bb3[3], 0L );
  _A4 = wl( (long)aa1[4], (long)aa2[4], (long)aa3[4], 0L ); _B4 = wl( (long)bb1[4], (long)bb2[4], (long)bb3[4], 0L );

  FD_R52X5_QUAD_DECL( _M );
  FD_R52X5_QUAD_MUL_FAST( _M, _A, _B );
  FD_R52X5_QUAD_REDUCE( _M, _M );
  FD_F25519_STORE_QUAD_LANE( r1, _M, 0 );
  FD_F25519_STORE_QUAD_LANE( r2, _M, 1 );
  FD_F25519_STORE_QUAD_LANE( r3, _M, 2 );
}

FD_25519_INLINE void
fd_f25519_mul4( fd_f25519_t * r1, fd_f25519_t const * a1, fd_f25519_t const * b1,
                fd_f25519_t * r2, fd_f25519_t const * a2, fd_f25519_t const * b2,
                fd_f25519_t * r3, fd_f25519_t const * a3, fd_f25519_t const * b3,
                fd_f25519_t * r4, fd_f25519_t const * a4, fd_f25519_t const * b4 ) {
  ulong aa1[5]; ulong aa2[5]; ulong aa3[5]; ulong aa4[5];
  ulong bb1[5]; ulong bb2[5]; ulong bb3[5]; ulong bb4[5];
  fd_f25519_reduce( aa1, a1->el ); fd_f25519_reduce( bb1, b1->el );
  fd_f25519_reduce( aa2, a2->el ); fd_f25519_reduce( bb2, b2->el );
  fd_f25519_reduce( aa3, a3->el ); fd_f25519_reduce( bb3, b3->el );
  fd_f25519_reduce( aa4, a4->el ); fd_f25519_reduce( bb4, b4->el );

  FD_R52X5_QUAD_DECL( _A );
  FD_R52X5_QUAD_DECL( _B );
  _A0 = wl( (long)aa1[0], (long)aa2[0], (long)aa3[0], (long)aa4[0] ); _B0 = wl( (long)bb1[0], (long)bb2[0], (long)bb3[0], (long)bb4[0] );
  _A1 = wl( (long)aa1[1], (long)aa2[1], (long)aa3[1], (long)aa4[1] ); _B1 = wl( (long)bb1[1], (long)bb2[1], (long)bb3[1], (long)bb4[1] );
  _A2 = wl( (long)aa1[2], (long)aa2[2], (long)aa3[2], (long)aa4[2] ); _B2 = wl( (long)bb1[2], (long)bb2[2], (long)bb3[2], (long)bb4[2] );
  _A3 = wl( (long)aa1[3], (long)aa2[3], (long)aa3[3], (long)aa4[3] ); _B3 = wl( (long)bb1[3], (long)bb2[3], (long)bb3[3], (long)bb4[3] );
  _A4 = wl( (long)aa1[4], (long)aa2[4], (long)aa3[4], (long)aa4[4] ); _B4 = wl( (long)bb1[4], (long)bb2[4], (long)bb3[4], (long)bb4[4] );

  FD_R52X5_QUAD_DECL( _M );
  FD_R52X5_QUAD_MUL_FAST( _M, _A, _B );
  FD_R52X5_QUAD_REDUCE( _M, _M );
  FD_F25519_STORE_QUAD_LANE( r1, _M, 0 );
  FD_F25519_STORE_QUAD_LANE( r2, _M, 1 );
  FD_F25519_STORE_QUAD_LANE( r3, _M, 2 );
  FD_F25519_STORE_QUAD_LANE( r4, _M, 3 );
}

FD_25519_INLINE void
fd_f25519_sqr2( fd_f25519_t * r1, fd_f25519_t const * a1,
                fd_f25519_t * r2, fd_f25519_t const * a2 ) {
  ulong aa1[5]; ulong aa2[5];
  fd_f25519_reduce( aa1, a1->el );
  fd_f25519_reduce( aa2, a2->el );

  FD_R52X5_QUAD_DECL( _A );
  _A0 = wl( (long)aa1[0], (long)aa2[0], 0L, 0L );
  _A1 = wl( (long)aa1[1], (long)aa2[1], 0L, 0L );
  _A2 = wl( (long)aa1[2], (long)aa2[2], 0L, 0L );
  _A3 = wl( (long)aa1[3], (long)aa2[3], 0L, 0L );
  _A4 = wl( (long)aa1[4], (long)aa2[4], 0L, 0L );

  FD_R52X5_QUAD_DECL( _M );
  FD_R52X5_QUAD_SQR_FAST( _M, _A );
  FD_R52X5_QUAD_REDUCE( _M, _M );
  FD_F25519_STORE_QUAD_LANE( r1, _M, 0 );
  FD_F25519_STORE_QUAD_LANE( r2, _M, 1 );
}

FD_25519_INLINE void
fd_f25519_sqr3( fd_f25519_t * r1, fd_f25519_t const * a1,
                fd_f25519_t * r2, fd_f25519_t const * a2,
                fd_f25519_t * r3, fd_f25519_t const * a3 ) {
  ulong aa1[5]; ulong aa2[5]; ulong aa3[5];
  fd_f25519_reduce( aa1, a1->el );
  fd_f25519_reduce( aa2, a2->el );
  fd_f25519_reduce( aa3, a3->el );

  FD_R52X5_QUAD_DECL( _A );
  _A0 = wl( (long)aa1[0], (long)aa2[0], (long)aa3[0], 0L );
  _A1 = wl( (long)aa1[1], (long)aa2[1], (long)aa3[1], 0L );
  _A2 = wl( (long)aa1[2], (long)aa2[2], (long)aa3[2], 0L );
  _A3 = wl( (long)aa1[3], (long)aa2[3], (long)aa3[3], 0L );
  _A4 = wl( (long)aa1[4], (long)aa2[4], (long)aa3[4], 0L );

  FD_R52X5_QUAD_DECL( _M );
  FD_R52X5_QUAD_SQR_FAST( _M, _A );
  FD_R52X5_QUAD_REDUCE( _M, _M );
  FD_F25519_STORE_QUAD_LANE( r1, _M, 0 );
  FD_F25519_STORE_QUAD_LANE( r2, _M, 1 );
  FD_F25519_STORE_QUAD_LANE( r3, _M, 2 );
}

FD_25519_INLINE void
fd_f25519_sqr4( fd_f25519_t * r1, fd_f25519_t const * a1,
                fd_f25519_t * r2, fd_f25519_t const * a2,
                fd_f25519_t * r3, fd_f25519_t const * a3,
                fd_f25519_t * r4, fd_f25519_t const * a4 ) {
  ulong aa1[5]; ulong aa2[5]; ulong aa3[5]; ulong aa4[5];
  fd_f25519_reduce( aa1, a1->el );
  fd_f25519_reduce( aa2, a2->el );
  fd_f25519_reduce( aa3, a3->el );
  fd_f25519_reduce( aa4, a4->el );

  FD_R52X5_QUAD_DECL( _A );
  _A0 = wl( (long)aa1[0], (long)aa2[0], (long)aa3[0], (long)aa4[0] );
  _A1 = wl( (long)aa1[1], (long)aa2[1], (long)aa3[1], (long)aa4[1] );
  _A2 = wl( (long)aa1[2], (long)aa2[2], (long)aa3[2], (long)aa4[2] );
  _A3 = wl( (long)aa1[3], (long)aa2[3], (long)aa3[3], (long)aa4[3] );
  _A4 = wl( (long)aa1[4], (long)aa2[4], (long)aa3[4], (long)aa4[4] );

  FD_R52X5_QUAD_DECL( _M );
  FD_R52X5_QUAD_SQR_FAST( _M, _A );
  FD_R52X5_QUAD_REDUCE( _M, _M );
  FD_F25519_STORE_QUAD_LANE( r1, _M, 0 );
  FD_F25519_STORE_QUAD_LANE( r2, _M, 1 );
  FD_F25519_STORE_QUAD_LANE( r3, _M, 2 );
  FD_F25519_STORE_QUAD_LANE( r4, _M, 3 );
}

FD_PROTOTYPES_END
