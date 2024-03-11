#ifndef HEADER_fd_src_ballet_ed25519_fd_f25519_h
#error "Do not include this directly; use fd_f25519.h"
#endif

#include "../../fd_ballet_base.h"
#include "fd_r43x6.h"

#define FD_F25519_ALIGN 64

/* A fd_f25519_t stores a curve25519 field element in 5 ulong, aligned to 64 bytes */
struct fd_f25519 {
  fd_r43x6_t el __attribute__((aligned(FD_F25519_ALIGN)));
};
typedef struct fd_f25519 fd_f25519_t;

#include "../table/fd_f25519_table_avx512.c"

FD_PROTOTYPES_BEGIN

/*
 * Implementation of inline functions
 */

/* fd_f25519_mul computes r = a * b, and returns r. */
FD_25519_INLINE fd_f25519_t *
fd_f25519_mul( fd_f25519_t * r,
               fd_f25519_t const * a,
               fd_f25519_t const * b ) {
  FD_R43X6_MUL1_INL( r->el, a->el, b->el );
  return r;
}

/* fd_f25519_sqr computes r = a^2, and returns r. */
FD_25519_INLINE fd_f25519_t *
fd_f25519_sqr( fd_f25519_t * r,
               fd_f25519_t const * a ) {
  FD_R43X6_SQR1_INL( r->el, a->el );
  return r;
}

/* fd_f25519_add computes r = a + b, and returns r. */
FD_25519_INLINE fd_f25519_t *
fd_f25519_add( fd_f25519_t * r,
               fd_f25519_t const * a,
               fd_f25519_t const * b ) {
  (r->el) = fd_r43x6_add( (a->el), (b->el) );
  return r;
}

/* fd_f25519_add computes r = a - b, and returns r. */
FD_25519_INLINE fd_f25519_t *
fd_f25519_sub( fd_f25519_t * r,
               fd_f25519_t const * a,
               fd_f25519_t const * b ) {
  (r->el) = fd_r43x6_fold_signed( fd_r43x6_sub_fast( (a->el), (b->el) ) );
  return r;
}

/* fd_f25519_add computes r = a + b, and returns r.
   Note: this does NOT reduce the result mod p.
   It can be used before mul, sqr. */
FD_25519_INLINE fd_f25519_t *
fd_f25519_add_nr( fd_f25519_t * r,
                  fd_f25519_t const * a,
                  fd_f25519_t const * b ) {
  (r->el) = fd_r43x6_add_fast( (a->el), (b->el) );
  return r;
}

/* fd_f25519_sub computes r = a - b, and returns r.
   Note: this does NOT reduce the result mod p.
   It can be used before mul, sqr. */
FD_25519_INLINE fd_f25519_t *
fd_f25519_sub_nr( fd_f25519_t * r,
                  fd_f25519_t const * a,
                  fd_f25519_t const * b ) {
  (r->el) = fd_r43x6_sub_fast( (a->el), (b->el) );
  return r;
}

/* fd_f25519_add computes r = -a, and returns r. */
FD_25519_INLINE fd_f25519_t *
fd_f25519_neg( fd_f25519_t * r,
               fd_f25519_t const * a ) {
  (r->el) = fd_r43x6_neg_fast( (a->el) );
  return r;
}

/* fd_f25519_add computes r = a * k, k=121666, and returns r. */
FD_25519_INLINE fd_f25519_t *
fd_f25519_mul_121666( fd_f25519_t * r,
                      FD_FN_UNUSED fd_f25519_t const * a ) {
  (r->el) = fd_r43x6_fold_unsigned( fd_r43x6_scale_fast( 121666L, (a->el) ) );
  return r;
}

/* fd_f25519_frombytes deserializes a 32-byte buffer buf into a
   fd_f25519_t element r, and returns r.
   buf is in little endian form, according to RFC 8032. */
FD_25519_INLINE fd_f25519_t *
fd_f25519_frombytes( fd_f25519_t * r,
                     uchar const   buf[ static 32 ] ) {
  ulong y0 = ((ulong *)buf)[0];                      /* Bits   0- 63 */
  ulong y1 = ((ulong *)buf)[1];                      /* Bits  64-127 */
  ulong y2 = ((ulong *)buf)[2];                      /* Bits 128-191 */
  ulong y3 = ((ulong *)buf)[3] & 0x7fffffffffffffff; /* Bits 192-254 */
  r->el = fd_r43x6_unpack( wv( y0, y1, y2, y3 ) );
  return r;
}

/* fd_f25519_tobytes serializes a fd_f25519_t element a into
   a 32-byte buffer out, and returns out.
   out is in little endian form, according to RFC 8032. */
FD_25519_INLINE uchar *
fd_f25519_tobytes( uchar               out[ static 32 ],
                   fd_f25519_t const * a ) {
  wv_stu( out, fd_r43x6_pack( fd_r43x6_mod( a->el ) ) );
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
  r->el = fd_r43x6_if( -!!cond, a0->el, a1->el );
  return r;
}

/* fd_f25519_swap_if swaps r1, r2 if cond, else leave them as is.
   Note: this is constant time. */
FD_25519_INLINE void
fd_f25519_swap_if( fd_f25519_t * restrict r1,
                   fd_f25519_t * restrict r2,
                   int const              cond /* 0, 1 */ ) {
  wwl_t zero = wwl_zero();
  wwl_t m = wwl_xor(r1->el, r2->el);
  m  = wwl_if( -!!cond, m, zero );
  r1->el = wwl_xor( r1->el, m );
  r2->el = wwl_xor( r2->el, m );
}

/* fd_f25519_set copies r = a, and returns r. */
FD_25519_INLINE fd_f25519_t *
fd_f25519_set( fd_f25519_t * r,
               fd_f25519_t const * a ) {
  r->el = a->el;
  return r;
}

/* fd_f25519_is_zero returns 1 if a == 0, 0 otherwise. */
FD_25519_INLINE int
fd_f25519_is_zero( fd_f25519_t const * a ) {
  return ( ( wwl_eq( a->el, fd_r43x6_zero() ) & 0xFF ) == 0xFF )
      || ( ( wwl_eq( a->el, fd_r43x6_p() )    & 0xFF ) == 0xFF );
}

/*
 * Vectorized
 */

/* fd_f25519_muln computes r_i = a_i * b_i */
FD_25519_INLINE void
fd_f25519_mul2( fd_f25519_t * r1, fd_f25519_t const * a1, fd_f25519_t const * b1,
                fd_f25519_t * r2, fd_f25519_t const * a2, fd_f25519_t const * b2 ) {
  FD_R43X6_MUL2_INL( r1->el, a1->el, b1->el,
                     r2->el, a2->el, b2->el );
}

FD_25519_INLINE void
fd_f25519_mul3( fd_f25519_t * r1, fd_f25519_t const * a1, fd_f25519_t const * b1,
                fd_f25519_t * r2, fd_f25519_t const * a2, fd_f25519_t const * b2,
                fd_f25519_t * r3, fd_f25519_t const * a3, fd_f25519_t const * b3 ) {
  FD_R43X6_MUL3_INL( r1->el, a1->el, b1->el,
                     r2->el, a2->el, b2->el,
                     r3->el, a3->el, b3->el );
}

FD_25519_INLINE void
fd_f25519_mul4( fd_f25519_t * r1, fd_f25519_t const * a1, fd_f25519_t const * b1,
                fd_f25519_t * r2, fd_f25519_t const * a2, fd_f25519_t const * b2,
                fd_f25519_t * r3, fd_f25519_t const * a3, fd_f25519_t const * b3,
                fd_f25519_t * r4, fd_f25519_t const * a4, fd_f25519_t const * b4 ) {
  FD_R43X6_MUL4_INL( r1->el, a1->el, b1->el,
                     r2->el, a2->el, b2->el,
                     r3->el, a3->el, b3->el,
                     r4->el, a4->el, b4->el );
}

/* fd_f25519_sqrn computes r_i = a_i^2 */
FD_25519_INLINE void
fd_f25519_sqr2( fd_f25519_t * r1, fd_f25519_t const * a1,
                fd_f25519_t * r2, fd_f25519_t const * a2 ) {
  FD_R43X6_SQR2_INL( r1->el, a1->el,
                     r2->el, a2->el );
}

FD_25519_INLINE void
fd_f25519_sqr3( fd_f25519_t * r1, fd_f25519_t const * a1,
                fd_f25519_t * r2, fd_f25519_t const * a2,
                fd_f25519_t * r3, fd_f25519_t const * a3 ) {
  FD_R43X6_SQR3_INL( r1->el, a1->el,
                     r2->el, a2->el,
                     r3->el, a3->el );
}

FD_25519_INLINE void
fd_f25519_sqr4( fd_f25519_t * r1, fd_f25519_t const * a1,
                fd_f25519_t * r2, fd_f25519_t const * a2,
                fd_f25519_t * r3, fd_f25519_t const * a3,
                fd_f25519_t * r4, fd_f25519_t const * a4 ) {
  FD_R43X6_SQR4_INL( r1->el, a1->el,
                     r2->el, a2->el,
                     r3->el, a3->el,
                     r4->el, a4->el );
}

FD_PROTOTYPES_END
