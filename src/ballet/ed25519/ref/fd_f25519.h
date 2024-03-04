#ifndef HEADER_fd_src_ballet_ed25519_fd_f25519_h
#error "Do not include this directly; use fd_f25519.h"
#endif

#include "../../fd_ballet_base.h"

#define USE_FIAT_32 0
#if USE_FIAT_32
#include "../../fiat-crypto/curve25519_32.c"
#else
#include "../../fiat-crypto/curve25519_64.c"
#endif

/* A fd_f25519_t stores a curve25519 field element in 10 uint (32 bit),
   or 5 ulong (64 bit). */
struct fd_f25519 {
#if USE_FIAT_32
  uint el[10];
#else
  ulong el[5];
#endif
};
typedef struct fd_f25519 fd_f25519_t;

#include "../table/fd_f25519_table_ref.c"

FD_PROTOTYPES_BEGIN

/*
 * Implementation of inline functions
 */

/* fd_f25519_mul computes r = a * b, and returns r. */
FD_25519_INLINE fd_f25519_t *
fd_f25519_mul( fd_f25519_t * r,
               fd_f25519_t const * a,
               fd_f25519_t const * b ) {
  fiat_25519_carry_mul( r->el, a->el, b->el );
  return r;
}

/* fd_f25519_sqr computes r = a^2, and returns r. */
FD_25519_INLINE fd_f25519_t *
fd_f25519_sqr( fd_f25519_t * r,
               fd_f25519_t const * a ) {
  fiat_25519_carry_square( r->el, a->el );
  return r;
}

/* fd_f25519_add computes r = a + b, and returns r. */
FD_25519_INLINE fd_f25519_t *
fd_f25519_add( fd_f25519_t * r,
               fd_f25519_t const * a,
               fd_f25519_t const * b ) {
  fiat_25519_add( r->el, a->el, b->el );
  fiat_25519_carry( r->el, r->el );
  return r;
}

/* fd_f25519_add computes r = a - b, and returns r. */
FD_25519_INLINE fd_f25519_t *
fd_f25519_sub( fd_f25519_t * r,
               fd_f25519_t const * a,
               fd_f25519_t const * b ) {
  fiat_25519_sub( r->el, a->el, b->el );
  fiat_25519_carry( r->el, r->el );
  return r;
}

/* fd_f25519_add computes r = a + b, and returns r.
   Note: this does NOT reduce the result mod p.
   It can be used before mul, sqr. */
FD_25519_INLINE fd_f25519_t *
fd_f25519_add_nr( fd_f25519_t * r,
                  fd_f25519_t const * a,
                  fd_f25519_t const * b ) {
  fiat_25519_add( r->el, a->el, b->el );
  return r;
}

/* fd_f25519_sub computes r = a - b, and returns r.
   Note: this does NOT reduce the result mod p.
   It can be used before mul, sqr. */
FD_25519_INLINE fd_f25519_t *
fd_f25519_sub_nr( fd_f25519_t * r,
                  fd_f25519_t const * a,
                  fd_f25519_t const * b ) {
  fiat_25519_sub( r->el, a->el, b->el );
  return r;
}

/* fd_f25519_add computes r = -a, and returns r. */
FD_25519_INLINE fd_f25519_t *
fd_f25519_neg( fd_f25519_t * r,
               fd_f25519_t const * a ) {
  fiat_25519_opp( r->el, a->el );
  return r;
}

/* fd_f25519_add computes r = a * k, k=121666, and returns r. */
FD_25519_INLINE fd_f25519_t *
fd_f25519_mul_121666( fd_f25519_t * r,
                      fd_f25519_t const * a ) {
  fiat_25519_carry_scmul_121666( r->el, a->el );
  return r;
}

/* fd_f25519_frombytes deserializes a 32-byte buffer buf into a
   fd_f25519_t element r, and returns r.
   buf is in little endian form, according to RFC 8032. */
FD_25519_INLINE fd_f25519_t *
fd_f25519_frombytes( fd_f25519_t * r,
                     uchar const   buf[ static 32 ] ) {
  fiat_25519_from_bytes( r->el, buf );
  return r;
}

/* fd_f25519_tobytes serializes a fd_f25519_t element a into
   a 32-byte buffer out, and returns out.
   out is in little endian form, according to RFC 8032. */
FD_25519_INLINE uchar *
fd_f25519_tobytes( uchar               out[ static 32 ],
                   fd_f25519_t const * a ) {
  fiat_25519_to_bytes( out, a->el );
  return out;
}

/* fd_f25519_if sets r = a0 if cond, else r = a1, equivalent to:
   r = cond ? a0 : a1.
   Note: this is constant time. */
FD_25519_INLINE fd_f25519_t *
fd_f25519_if( fd_f25519_t *       r,
              int const           cond, /* 0, 1 */
              fd_f25519_t const * a0,
              fd_f25519_t const * a1 ) {
  fiat_25519_selectznz( r->el, (uchar)cond, a1->el, a0->el );
  return r;
}

/* fd_f25519_swap_if swaps r1, r2 if cond, else leave them as is.
   Note: this is constant time. */
FD_25519_INLINE void
fd_f25519_swap_if( fd_f25519_t * restrict r1,
                   fd_f25519_t * restrict r2,
                   int const              cond /* 0, 1 */ ) {

#if USE_FIAT_32
  uint m  = (uint)-!!cond;
  uint h0 = m & (r1->el[0] ^ r2->el[0]);
  uint h1 = m & (r1->el[1] ^ r2->el[1]);
  uint h2 = m & (r1->el[2] ^ r2->el[2]);
  uint h3 = m & (r1->el[3] ^ r2->el[3]);
  uint h4 = m & (r1->el[4] ^ r2->el[4]);
  uint h5 = m & (r1->el[5] ^ r2->el[5]);
  uint h6 = m & (r1->el[6] ^ r2->el[6]);
  uint h7 = m & (r1->el[7] ^ r2->el[7]);
  uint h8 = m & (r1->el[8] ^ r2->el[8]);
  uint h9 = m & (r1->el[9] ^ r2->el[9]);

#else
  ulong m  = (ulong)-!!cond;
  ulong h0 = m & (r1->el[0] ^ r2->el[0]);
  ulong h1 = m & (r1->el[1] ^ r2->el[1]);
  ulong h2 = m & (r1->el[2] ^ r2->el[2]);
  ulong h3 = m & (r1->el[3] ^ r2->el[3]);
  ulong h4 = m & (r1->el[4] ^ r2->el[4]);
#endif

  r1->el[0] ^= h0;
  r1->el[1] ^= h1;
  r1->el[2] ^= h2;
  r1->el[3] ^= h3;
  r1->el[4] ^= h4;

  r2->el[0] ^= h0;
  r2->el[1] ^= h1;
  r2->el[2] ^= h2;
  r2->el[3] ^= h3;
  r2->el[4] ^= h4;

#if USE_FIAT_32
  r1->el[5] ^= h5;
  r1->el[6] ^= h6;
  r1->el[7] ^= h7;
  r1->el[8] ^= h8;
  r1->el[9] ^= h9;

  r2->el[5] ^= h5;
  r2->el[6] ^= h6;
  r2->el[7] ^= h7;
  r2->el[8] ^= h8;
  r2->el[9] ^= h9;
#endif
}

/* fd_f25519_set copies r = a, and returns r. */
FD_25519_INLINE fd_f25519_t *
fd_f25519_set( fd_f25519_t * r,
               fd_f25519_t const * a ) {
  r->el[0] = a->el[0];
  r->el[1] = a->el[1];
  r->el[2] = a->el[2];
  r->el[3] = a->el[3];
  r->el[4] = a->el[4];
#if USE_FIAT_32
  r->el[5] = a->el[5];
  r->el[6] = a->el[6];
  r->el[7] = a->el[7];
  r->el[8] = a->el[8];
  r->el[9] = a->el[9];
#endif
  return r;
}

/* fd_f25519_is_zero returns 1 if a == 0, 0 otherwise. */
FD_25519_INLINE int
fd_f25519_is_zero( fd_f25519_t const * a ) {
  // fiat_25519_tight_field_element x;
  // fiat_25519_carry( x, a->el );
#if USE_FIAT_32
  uint const * x = a->el;
  if(( x[0] == 0
    && x[1] == 0
    && x[2] == 0
    && x[3] == 0
    && x[4] == 0
    && x[5] == 0
    && x[6] == 0
    && x[7] == 0
    && x[8] == 0
    && x[9] == 0
  ) || (
       x[0] == 0x3ffffed
    && x[1] == 0x1ffffff
    && x[2] == 0x3ffffff
    && x[3] == 0x1ffffff
    && x[4] == 0x3ffffff
    && x[5] == 0x1ffffff
    && x[6] == 0x3ffffff
    && x[7] == 0x1ffffff
    && x[8] == 0x3ffffff
    && x[9] == 0x1ffffff
  )) {
    return 1;
  }
#else
  ulong const * x = a->el;
  if(( x[0] == 0
    && x[1] == 0
    && x[2] == 0
    && x[3] == 0
    && x[4] == 0
  ) || (
       x[0] == 0x7ffffffffffed
    && x[1] == 0x7ffffffffffff
    && x[2] == 0x7ffffffffffff
    && x[3] == 0x7ffffffffffff
    && x[4] == 0x7ffffffffffff
  )) {
    return 1;
  }
#endif
  return 0;
}

/*
 * Vectorized
 */

/* fd_f25519_muln computes r_i = a_i * b_i */
FD_25519_INLINE void
fd_f25519_mul2( fd_f25519_t * r1, fd_f25519_t const * a1, fd_f25519_t const * b1,
                fd_f25519_t * r2, fd_f25519_t const * a2, fd_f25519_t const * b2 ) {
  fd_f25519_mul( r1, a1, b1 );
  fd_f25519_mul( r2, a2, b2 );
}

FD_25519_INLINE void
fd_f25519_mul3( fd_f25519_t * r1, fd_f25519_t const * a1, fd_f25519_t const * b1,
                fd_f25519_t * r2, fd_f25519_t const * a2, fd_f25519_t const * b2,
                fd_f25519_t * r3, fd_f25519_t const * a3, fd_f25519_t const * b3 ) {
  fd_f25519_mul( r1, a1, b1 );
  fd_f25519_mul( r2, a2, b2 );
  fd_f25519_mul( r3, a3, b3 );
}

FD_25519_INLINE void
fd_f25519_mul4( fd_f25519_t * r1, fd_f25519_t const * a1, fd_f25519_t const * b1,
                fd_f25519_t * r2, fd_f25519_t const * a2, fd_f25519_t const * b2,
                fd_f25519_t * r3, fd_f25519_t const * a3, fd_f25519_t const * b3,
                fd_f25519_t * r4, fd_f25519_t const * a4, fd_f25519_t const * b4 ) {
  fd_f25519_mul( r1, a1, b1 );
  fd_f25519_mul( r2, a2, b2 );
  fd_f25519_mul( r3, a3, b3 );
  fd_f25519_mul( r4, a4, b4 );
}

/* fd_f25519_sqrn computes r_i = a_i^2 */
FD_25519_INLINE void
fd_f25519_sqr2( fd_f25519_t * r1, fd_f25519_t const * a1,
                fd_f25519_t * r2, fd_f25519_t const * a2 ) {
  fd_f25519_sqr( r1, a1 );
  fd_f25519_sqr( r2, a2 );
}

FD_25519_INLINE void
fd_f25519_sqr3( fd_f25519_t * r1, fd_f25519_t const * a1,
                fd_f25519_t * r2, fd_f25519_t const * a2,
                fd_f25519_t * r3, fd_f25519_t const * a3 ) {
  fd_f25519_sqr( r1, a1 );
  fd_f25519_sqr( r2, a2 );
  fd_f25519_sqr( r3, a3 );
}

FD_25519_INLINE void
fd_f25519_sqr4( fd_f25519_t * r1, fd_f25519_t const * a1,
                fd_f25519_t * r2, fd_f25519_t const * a2,
                fd_f25519_t * r3, fd_f25519_t const * a3,
                fd_f25519_t * r4, fd_f25519_t const * a4 ) {
  fd_f25519_sqr( r1, a1 );
  fd_f25519_sqr( r2, a2 );
  fd_f25519_sqr( r3, a3 );
  fd_f25519_sqr( r4, a4 );
}

FD_PROTOTYPES_END
