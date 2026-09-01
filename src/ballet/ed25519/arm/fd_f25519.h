#ifndef HEADER_fd_src_ballet_ed25519_fd_f25519_h
#error "Do not include this directly; use fd_f25519.h"
#endif

#include "../../fd_ballet_base.h"
#include <stdint.h>
#include "../../../third_party/s2n-bignum/include/s2n-bignum.h"

#define FD_F25519_ARM 1

/* Canonical radix-2^64 representation.  el[3] uses at most 63 bits. */
struct fd_f25519 {
  ulong el[4];
};
typedef struct fd_f25519 fd_f25519_t;

FD_STATIC_ASSERT( sizeof(ulong)==sizeof(uint64_t), arm_f25519_ulong_is_u64 );

#include "../table/fd_f25519_table_arm.c"

FD_PROTOTYPES_BEGIN

FD_25519_INLINE fd_f25519_t *
fd_f25519_mul( fd_f25519_t * r, fd_f25519_t const * a, fd_f25519_t const * b ) {
  bignum_mul_p25519_alt( r->el, a->el, b->el );
  return r;
}

FD_25519_INLINE fd_f25519_t *
fd_f25519_sqr( fd_f25519_t * r, fd_f25519_t const * a ) {
  bignum_sqr_p25519_alt( r->el, a->el );
  return r;
}

FD_25519_INLINE fd_f25519_t *
fd_f25519_add( fd_f25519_t * r, fd_f25519_t const * a, fd_f25519_t const * b ) {
  bignum_add_p25519( r->el, a->el, b->el );
  return r;
}

FD_25519_INLINE fd_f25519_t *
fd_f25519_sub( fd_f25519_t * r, fd_f25519_t const * a, fd_f25519_t const * b ) {
  bignum_sub_p25519( r->el, a->el, b->el );
  return r;
}

FD_25519_INLINE fd_f25519_t *
fd_f25519_add_nr( fd_f25519_t * r, fd_f25519_t const * a, fd_f25519_t const * b ) {
  return fd_f25519_add( r, a, b );
}

FD_25519_INLINE fd_f25519_t *
fd_f25519_sub_nr( fd_f25519_t * r, fd_f25519_t const * a, fd_f25519_t const * b ) {
  return fd_f25519_sub( r, a, b );
}

FD_25519_INLINE fd_f25519_t *
fd_f25519_neg( fd_f25519_t * r, fd_f25519_t const * a ) {
  bignum_neg_p25519( r->el, a->el );
  return r;
}

FD_25519_INLINE fd_f25519_t *
fd_f25519_mul_121666( fd_f25519_t * r, fd_f25519_t const * a ) {
  bignum_cmul_p25519( r->el, 121666UL, a->el );
  return r;
}

FD_25519_INLINE fd_f25519_t *
fd_f25519_frombytes( fd_f25519_t * r, uchar const buf[32] ) {
  ulong x[4];
  x[0] = fd_ulong_load_8_fast( buf      );
  x[1] = fd_ulong_load_8_fast( buf +  8 );
  x[2] = fd_ulong_load_8_fast( buf + 16 );
  x[3] = fd_ulong_load_8_fast( buf + 24 ) & 0x7fffffffffffffffUL;
  bignum_mod_p25519_4( r->el, x );
  return r;
}

FD_25519_INLINE uchar *
fd_f25519_tobytes( uchar out[32], fd_f25519_t const * a ) {
  memcpy( out, a->el, 32UL );
  return out;
}

FD_25519_INLINE fd_f25519_t *
fd_f25519_if( fd_f25519_t * r, int cond, fd_f25519_t const * a0, fd_f25519_t const * a1 ) {
  ulong m = (ulong)-(long)!!cond;
  r->el[0] = (a0->el[0] & m) | (a1->el[0] & ~m);
  r->el[1] = (a0->el[1] & m) | (a1->el[1] & ~m);
  r->el[2] = (a0->el[2] & m) | (a1->el[2] & ~m);
  r->el[3] = (a0->el[3] & m) | (a1->el[3] & ~m);
  return r;
}

FD_25519_INLINE void
fd_f25519_swap_if( fd_f25519_t * restrict r1, fd_f25519_t * restrict r2, int cond ) {
  ulong m = (ulong)-(long)!!cond;
  ulong h0 = m & (r1->el[0] ^ r2->el[0]);
  ulong h1 = m & (r1->el[1] ^ r2->el[1]);
  ulong h2 = m & (r1->el[2] ^ r2->el[2]);
  ulong h3 = m & (r1->el[3] ^ r2->el[3]);
  r1->el[0] ^= h0; r2->el[0] ^= h0;
  r1->el[1] ^= h1; r2->el[1] ^= h1;
  r1->el[2] ^= h2; r2->el[2] ^= h2;
  r1->el[3] ^= h3; r2->el[3] ^= h3;
}

FD_25519_INLINE fd_f25519_t *
fd_f25519_set( fd_f25519_t * r, fd_f25519_t const * a ) {
  r->el[0] = a->el[0];
  r->el[1] = a->el[1];
  r->el[2] = a->el[2];
  r->el[3] = a->el[3];
  return r;
}

FD_25519_INLINE int
fd_f25519_is_zero( fd_f25519_t const * a ) {
  return !(a->el[0] | a->el[1] | a->el[2] | a->el[3]);
}

FD_25519_INLINE void
fd_f25519_mul2( fd_f25519_t * r1, fd_f25519_t const * a1, fd_f25519_t const * b1,
                fd_f25519_t * r2, fd_f25519_t const * a2, fd_f25519_t const * b2 ) {
  fd_f25519_mul( r1, a1, b1 ); fd_f25519_mul( r2, a2, b2 );
}

FD_25519_INLINE void
fd_f25519_mul3( fd_f25519_t * r1, fd_f25519_t const * a1, fd_f25519_t const * b1,
                fd_f25519_t * r2, fd_f25519_t const * a2, fd_f25519_t const * b2,
                fd_f25519_t * r3, fd_f25519_t const * a3, fd_f25519_t const * b3 ) {
  fd_f25519_mul( r1, a1, b1 ); fd_f25519_mul( r2, a2, b2 ); fd_f25519_mul( r3, a3, b3 );
}

FD_25519_INLINE void
fd_f25519_mul4( fd_f25519_t * r1, fd_f25519_t const * a1, fd_f25519_t const * b1,
                fd_f25519_t * r2, fd_f25519_t const * a2, fd_f25519_t const * b2,
                fd_f25519_t * r3, fd_f25519_t const * a3, fd_f25519_t const * b3,
                fd_f25519_t * r4, fd_f25519_t const * a4, fd_f25519_t const * b4 ) {
  fd_f25519_mul( r1, a1, b1 ); fd_f25519_mul( r2, a2, b2 );
  fd_f25519_mul( r3, a3, b3 ); fd_f25519_mul( r4, a4, b4 );
}

FD_25519_INLINE void
fd_f25519_sqr2( fd_f25519_t * r1, fd_f25519_t const * a1,
                fd_f25519_t * r2, fd_f25519_t const * a2 ) {
  fd_f25519_sqr( r1, a1 ); fd_f25519_sqr( r2, a2 );
}

FD_25519_INLINE void
fd_f25519_sqr3( fd_f25519_t * r1, fd_f25519_t const * a1,
                fd_f25519_t * r2, fd_f25519_t const * a2,
                fd_f25519_t * r3, fd_f25519_t const * a3 ) {
  fd_f25519_sqr( r1, a1 ); fd_f25519_sqr( r2, a2 ); fd_f25519_sqr( r3, a3 );
}

FD_25519_INLINE void
fd_f25519_sqr4( fd_f25519_t * r1, fd_f25519_t const * a1,
                fd_f25519_t * r2, fd_f25519_t const * a2,
                fd_f25519_t * r3, fd_f25519_t const * a3,
                fd_f25519_t * r4, fd_f25519_t const * a4 ) {
  fd_f25519_sqr( r1, a1 ); fd_f25519_sqr( r2, a2 );
  fd_f25519_sqr( r3, a3 ); fd_f25519_sqr( r4, a4 );
}

FD_PROTOTYPES_END
