#ifndef HEADER_fd_src_ballet_bls_avx512_fd_bls_field_h
#define HEADER_fd_src_ballet_bls_avx512_fd_bls_field_h

#include "fd_bls_rns.h"

/* BLS12-381 tower:
     Fp2  = Fp[u]/(u^2+1),
     Fp12 = Fp2[v,w]/(v^3-(u+1), w^2-v).
   c[6*i+2*j+k] is the coefficient of w^i v^j u^k. */
typedef struct { fd_bls_fp_wide_t c[2];  } fd_bls_fp2_wide_t;
typedef struct { fd_bls_fp_t      c[12]; } fd_bls_fp12_t;

FD_PROTOTYPES_BEGIN

void fd_bls_fp2_mul( fd_bls_fp2_t * out, fd_bls_fp2_t const * a, fd_bls_fp2_t const * b );
void fd_bls_fp2_sqr( fd_bls_fp2_t * out, fd_bls_fp2_t const * a );
void fd_bls_fp2_inverse  ( fd_bls_fp2_t * out, fd_bls_fp2_t const * a );
int  fd_bls_fp2_equal    ( fd_bls_fp2_t const * a, fd_bls_fp2_t const * b );
void fd_bls_fp_from_normal      ( fd_bls_fp_t * out, ulong const in[6] );
void fd_bls_fp2_from_normal     ( fd_bls_fp2_t * out, ulong const in[2][6] );

void fd_bls_fp12_mul           ( fd_bls_fp12_t * out, fd_bls_fp12_t const * a, fd_bls_fp12_t const * b );
void fd_bls_fp12_sqr           ( fd_bls_fp12_t * out, fd_bls_fp12_t const * a );
void fd_bls_fp12_cyclotomic_sqr( fd_bls_fp12_t * out, fd_bls_fp12_t const * a );
void fd_bls_fp12_mul_sparse    ( fd_bls_fp12_t * out, fd_bls_fp12_t const * a, fd_bls_fp_t const line[6] );
void fd_bls_fp12_one           ( fd_bls_fp12_t * out );
void fd_bls_fp12_inverse       ( fd_bls_fp12_t * out, fd_bls_fp12_t const * in );
void fd_bls_fp12_frobenius     ( fd_bls_fp12_t * out, fd_bls_fp12_t const * in, ulong n );

FD_PROTOTYPES_END

/* Vector copies (avoid out-of-line memcpy calls for 256-byte Fp2 /
   768-byte point copies). */
FD_BLS_INLINE void
fd_bls_fp2_copy( fd_bls_fp2_t * out, fd_bls_fp2_t const * a ) {
  wwv_t a0 = a->c[0].m1, a1 = a->c[0].m2, a2 = a->c[1].m1, a3 = a->c[1].m2;
  out->c[0].m1 = a0; out->c[0].m2 = a1; out->c[1].m1 = a2; out->c[1].m2 = a3;
}

/* Small Fp/Fp2 helpers are header inlines: they are a handful of vector
   ops each, and out-of-line calls (with their memory round trips of the
   64-byte-aligned operands) dominated their cost. */

FD_BLS_INLINE void
fd_bls_fp2_add( fd_bls_fp2_t *       out,
                fd_bls_fp2_t const * a,
                fd_bls_fp2_t const * b ) {
  fd_bls_fp_add( &out->c[0], &a->c[0], &b->c[0] );
  fd_bls_fp_add( &out->c[1], &a->c[1], &b->c[1] );
}

FD_BLS_INLINE void
fd_bls_fp2_sub( fd_bls_fp2_t *       out,
                fd_bls_fp2_t const * a,
                fd_bls_fp2_t const * b ) {
  fd_bls_fp_sub( &out->c[0], &a->c[0], &b->c[0] );
  fd_bls_fp_sub( &out->c[1], &a->c[1], &b->c[1] );
}

FD_BLS_INLINE void
fd_bls_fp2_neg( fd_bls_fp2_t *       out,
                fd_bls_fp2_t const * a ) {
  fd_bls_fp_neg( &out->c[0], &a->c[0] );
  fd_bls_fp_neg( &out->c[1], &a->c[1] );
}

/* Double-and-add over RAW 64-bit lane sums.  Lanes are 64-bit and only
   madd52 operands must stay below 2^52, so for n<=2^8 every intermediate
   (bounded by n*2^51 < 2^60) accumulates without per-step normalization;
   one trailing fd_bls_rns_normalize restores the standard bound. */
FD_BLS_INLINE void
fd_bls_fp_mul_small( fd_bls_fp_t *       out,
                     fd_bls_fp_t const * a,
                     uint                n ) {
  wwv_t r1 = wwv_zero(), r2 = wwv_zero();
  wwv_t x1 = a->m1,      x2 = a->m2;
  while( n ) {
    if( n & 1U ) { r1 = wwv_add( r1, x1 ); r2 = wwv_add( r2, x2 ); }
    n >>= 1;
    if( n ) { x1 = wwv_add( x1, x1 ); x2 = wwv_add( x2, x2 ); }
  }
  out->m1 = fd_bls_rns_normalize( r1, wwv_ld( fd_bls_m1_t ) );
  out->m2 = fd_bls_rns_normalize( r2, wwv_ld( fd_bls_m2_t ) );
}

FD_BLS_INLINE void
fd_bls_fp2_mul_small( fd_bls_fp2_t *       out,
                      fd_bls_fp2_t const * a,
                      uint                 n ) {
  fd_bls_fp_mul_small( &out->c[0], &a->c[0], n );
  fd_bls_fp_mul_small( &out->c[1], &a->c[1], n );
}

FD_BLS_INLINE void
fd_bls_fp2_one( fd_bls_fp2_t * out ) {
  fd_bls_fp_one( &out->c[0] );
  fd_bls_fp_zero( &out->c[1] );
}

/* The twist has b=4(1+u), hence 3b*a=12(1+u)*a. */
FD_BLS_INLINE void
fd_bls_fp2_mul_3b( fd_bls_fp2_t *       out,
                   fd_bls_fp2_t const * a ) {
  fd_bls_fp2_t nonres;
  fd_bls_fp_sub( &nonres.c[0], &a->c[0], &a->c[1] );
  fd_bls_fp_add( &nonres.c[1], &a->c[0], &a->c[1] );
  fd_bls_fp2_mul_small( out, &nonres, 12U );
}

FD_BLS_INLINE void
fd_bls_fp2_wide_zero( fd_bls_fp2_wide_t * out ) {
  fd_bls_fp_wide_offset( &out->c[0] ); /* out.re = 0 mod p, with a positive lazy offset. */
  fd_bls_fp_wide_offset( &out->c[1] ); /* out.im = 0 mod p.                              */
}

FD_BLS_INLINE void
fd_bls_fp2_wide_addmul( fd_bls_fp2_wide_t *  out,
                        fd_bls_fp2_t const * a,
                        fd_bls_fp2_t const * b ) {
  fd_bls_fp_wide_addmul( &out->c[0], &a->c[0], &b->c[0] ); /* out.re += a0*b0. */
  fd_bls_fp_wide_submul( &out->c[0], &a->c[1], &b->c[1] ); /* out.re -= a1*b1. */
  fd_bls_fp_wide_addmul( &out->c[1], &a->c[0], &b->c[1] ); /* out.im += a0*b1. */
  fd_bls_fp_wide_addmul( &out->c[1], &a->c[1], &b->c[0] ); /* out.im += a1*b0. */
}

FD_BLS_INLINE void
fd_bls_fp2_wide_submul( fd_bls_fp2_wide_t *  out,
                        fd_bls_fp2_t const * a,
                        fd_bls_fp2_t const * b ) {
  fd_bls_fp_wide_submul( &out->c[0], &a->c[0], &b->c[0] ); /* out.re -= a0*b0. */
  fd_bls_fp_wide_addmul( &out->c[0], &a->c[1], &b->c[1] ); /* out.re += a1*b1. */
  fd_bls_fp_wide_submul( &out->c[1], &a->c[0], &b->c[1] ); /* out.im -= a0*b1. */
  fd_bls_fp_wide_submul( &out->c[1], &a->c[1], &b->c[0] ); /* out.im -= a1*b0. */
}

FD_BLS_INLINE void
fd_bls_fp2_wide_addmul_fp( fd_bls_fp2_wide_t *  out,
                           fd_bls_fp2_t const * a,
                           fd_bls_fp_t const *  b ) {
  fd_bls_fp_wide_addmul( &out->c[0], &a->c[0], b );
  fd_bls_fp_wide_addmul( &out->c[1], &a->c[1], b );
}

FD_BLS_INLINE void
fd_bls_fp2_wide_set_mul( fd_bls_fp2_wide_t *  out,
                         fd_bls_fp2_t const * a,
                         fd_bls_fp2_t const * b ) {
  fd_bls_fp2_wide_zero( out );
  fd_bls_fp2_wide_addmul( out, a, b );
}

/* out = a^2 = (a0+a1)(a0-a1) + (2a0)a1 u: three base products instead of
   four.  a0+a1 and 2a0 are raw lane sums (< 4m and < 2^52, valid IFMA
   digits); a0-a1 is a normalized subtraction (bounded, positive). */
FD_BLS_INLINE void
fd_bls_fp2_wide_set_sqr( fd_bls_fp2_wide_t *  out,
                         fd_bls_fp2_t const * a ) {
  fd_bls_fp_t s, d, t;
  s.m1 = wwv_add( a->c[0].m1, a->c[1].m1 ); s.m2 = wwv_add( a->c[0].m2, a->c[1].m2 );
  t.m1 = wwv_add( a->c[0].m1, a->c[0].m1 ); t.m2 = wwv_add( a->c[0].m2, a->c[0].m2 );
  fd_bls_fp_sub( &d, &a->c[0], &a->c[1] );
  fd_bls_fp_wide_offset( &out->c[0] );
  fd_bls_fp_wide_addmul( &out->c[0], &s, &d );     /* re = a0^2-a1^2. */
  fd_bls_fp_wide_offset( &out->c[1] );
  fd_bls_fp_wide_addmul( &out->c[1], &t, &a->c[1] ); /* im = 2a0a1.     */
}

FD_BLS_INLINE void
fd_bls_fp2_wide_set_mul_fp( fd_bls_fp2_wide_t *  out,
                            fd_bls_fp2_t const * a,
                            fd_bls_fp_t const *  b ) {
  fd_bls_fp2_wide_zero( out );
  fd_bls_fp2_wide_addmul_fp( out, a, b );
}

FD_BLS_INLINE void fd_bls_fp2_reduce_batch2( fd_bls_fp2_t out[2], fd_bls_fp2_wide_t in[2] ) { fd_bls_fp_reduce_wide_batch4 ( &out[0].c[0], &in[0].c[0] ); }
FD_BLS_INLINE void fd_bls_fp2_reduce_batch3( fd_bls_fp2_t out[3], fd_bls_fp2_wide_t in[3] ) { fd_bls_fp_reduce_wide_batch6 ( &out[0].c[0], &in[0].c[0] ); }
FD_BLS_INLINE void fd_bls_fp2_reduce_batch5( fd_bls_fp2_t out[5], fd_bls_fp2_wide_t in[5] ) { fd_bls_fp_reduce_wide_batch10( &out[0].c[0], &in[0].c[0] ); }
FD_BLS_INLINE void fd_bls_fp2_reduce_batch6( fd_bls_fp2_t out[6], fd_bls_fp2_wide_t in[6] ) {
  fd_bls_fp_reduce_wide_batch6( &out[0].c[0], &in[0].c[0] );
  fd_bls_fp_reduce_wide_batch6( &out[3].c[0], &in[3].c[0] );
}

#endif
