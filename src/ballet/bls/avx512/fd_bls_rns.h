#ifndef HEADER_fd_src_ballet_bls_avx512_fd_bls_rns_h
#define HEADER_fd_src_ballet_bls_avx512_fd_bls_rns_h

#include "../fd_bls.h"
#include "fd_bls_constants.h"

#define FD_BLS_INLINE static inline __attribute__((always_inline))

#define FD_BLS_MASK50      ((ulong)((1UL<<50)-1UL))
#define FD_BLS_G1_ENTRY_MAX (12)

extern ulong const fd_bls_field_modulus_limbs[6];

/* Base-field values use the public backend's redundant rotated-RNS form. */
/* An unreduced sum of products; each lane represents hi*2^52+lo. */
typedef struct __attribute__((aligned(64))) {
  wwv_t m1_hi;
  wwv_t m1_lo;
  wwv_t m2_hi;
  wwv_t m2_lo;
} fd_bls_fp_wide_t;

static __attribute__((always_inline)) inline void
fd_bls_fp_wide_mul_raw( fd_bls_fp_wide_t *  out,
                        fd_bls_fp_t const * a,
                        fd_bls_fp_t const * b ) {
  wwv_t z = wwv_zero();
  out->m1_hi = wwv_madd52hi( z, a->m1, b->m1 );
  out->m1_lo = wwv_madd52lo( z, a->m1, b->m1 );
  out->m2_hi = wwv_madd52hi( z, a->m2, b->m2 );
  out->m2_lo = wwv_madd52lo( z, a->m2, b->m2 );
}

static __attribute__((always_inline)) inline void
fd_bls_fp_wide_add_raw( fd_bls_fp_wide_t *       out,
                        fd_bls_fp_wide_t const * raw ) {
  out->m1_hi = wwv_add( out->m1_hi, raw->m1_hi );
  out->m1_lo = wwv_add( out->m1_lo, raw->m1_lo );
  out->m2_hi = wwv_add( out->m2_hi, raw->m2_hi );
  out->m2_lo = wwv_add( out->m2_lo, raw->m2_lo );
}

static __attribute__((always_inline)) inline void
fd_bls_fp_wide_sub_raw( fd_bls_fp_wide_t *       out,
                        fd_bls_fp_wide_t const * raw ) {
  out->m1_hi = wwv_sub( out->m1_hi, raw->m1_hi );
  out->m1_lo = wwv_sub( out->m1_lo, raw->m1_lo );
  out->m2_hi = wwv_sub( out->m2_hi, raw->m2_hi );
  out->m2_lo = wwv_sub( out->m2_lo, raw->m2_lo );
}

FD_PROTOTYPES_BEGIN

void fd_bls_rns_reduce_512( ulong out[6], ulong const in[8] );
wwv_t fd_bls_rns_expand_m2_to_m1( wwv_t m2 );
void  fd_bls_fp_digits50( ulong dst[8], ulong const v[6] );
void  fd_bls_fp_from_mont_core( fd_bls_fp_t * out, ulong const * d, int cnt );
void  fd_bls_fp_from_mont_batch( fd_bls_fp_t * out, ulong const * in, int cnt );

void fd_bls_fp_from_uint64( fd_bls_fp_t * out, ulong const in[6] );
/* out = in^-1 mod p for canonical in (0 maps to 0); variable time. */
void fd_bls_fp_inv_canon  ( ulong out[6], ulong const in[6] );
void fd_bls_fp_to_uint64  ( ulong out[6], fd_bls_fp_t const * in );
void fd_bls_fp_mul        ( fd_bls_fp_t * out, fd_bls_fp_t const * a, fd_bls_fp_t const * b );
void fd_bls_fp_sqr        ( fd_bls_fp_t * out, fd_bls_fp_t const * a );
int  fd_bls_fp_equal      ( fd_bls_fp_t const * a, fd_bls_fp_t const * b );

/* Reduce a positive, borrow-free wide expression modulo the BLS12-381 field.
   This is the batch-reduction boundary used by generated FP2/FP12 kernels. */
void fd_bls_fp_reduce_wide( fd_bls_fp_t * out, fd_bls_fp_wide_t const * in );
void fd_bls_fp_reduce_wide_batch2 ( fd_bls_fp_t * out, fd_bls_fp_wide_t const * in );
void fd_bls_fp_reduce_wide_batch3 ( fd_bls_fp_t * out, fd_bls_fp_wide_t const * in );
void fd_bls_fp_reduce_wide_batch4 ( fd_bls_fp_t * out, fd_bls_fp_wide_t const * in );
void fd_bls_fp_reduce_wide_batch5 ( fd_bls_fp_t * out, fd_bls_fp_wide_t const * in );
void fd_bls_fp_reduce_wide_batch6 ( fd_bls_fp_t * out, fd_bls_fp_wide_t const * in );
void fd_bls_fp_reduce_wide_batch8 ( fd_bls_fp_t * out, fd_bls_fp_wide_t const * in );
void fd_bls_fp_reduce_wide_batch9 ( fd_bls_fp_t * out, fd_bls_fp_wide_t const * in );
void fd_bls_fp_reduce_wide_batch10( fd_bls_fp_t * out, fd_bls_fp_wide_t const * in );
void fd_bls_fp_reduce_wide_scaled_batch6( fd_bls_fp_t * out, fd_bls_fp_wide_t const * in, uint scale );

FD_PROTOTYPES_END
/* For m_i=2^50-t_i, fold x=x_lo+2^50*x_hi to x_lo+t_i*x_hi (mod m_i). */
FD_BLS_INLINE wwv_t
fd_bls_rns_normalize( wwv_t x,
                      wwv_t t ) {
  wwv_t lo = wwv_and( x, wwv_bcast( (ulong)FD_BLS_MASK50 ) );
  wwv_t hi = wwv_shr( x, 50 );
  return wwv_madd52lo( lo, hi, t );
}

/* Montgomery reduction with R=2^52 and 50-bit moduli.  With
   q=lo*m^-1 (mod R), the result hi+m-floor(q*m/R) is X/R (mod m).
   The redundant two-bit headroom makes the final normalization branchless. */
FD_BLS_INLINE wwv_t
fd_bls_rns_mont_reduce_wide_raw( wwv_t hi,
                                 wwv_t lo,
                                 wwv_t moduli,
                                 wwv_t mont ) {
  hi = wwv_add( hi, wwv_shr( lo, 52 ) );             /* hi = floor(X/R), including carry from lo. */
  wwv_t q   = wwv_madd52lo( wwv_zero(), lo, mont );  /* q  = lo*m^-1 mod R.                        */
  wwv_t neg = wwv_neg( moduli );                     /* neg= -m.                                   */
  wwv_t hn  = wwv_madd52hi( neg, q, moduli );        /* hn = -m+floor(q*m/R).                      */
  return wwv_sub( hi, hn );                          /* out= hi+m-floor(q*m/R) = X/R (mod m).      */
}

FD_BLS_INLINE wwv_t
fd_bls_rns_mont_reduce_wide_normalized( wwv_t hi,
                                        wwv_t lo,
                                        wwv_t moduli,
                                        wwv_t mont,
                                        wwv_t t ) {
  return fd_bls_rns_normalize( fd_bls_rns_mont_reduce_wide_raw( hi, lo, moduli, mont ), t );
}

/* Initialize a wide accumulator with a multiple of p, making later signed
   sums borrow-free without changing their value in Fp. */
FD_BLS_INLINE void
fd_bls_fp_wide_offset( fd_bls_fp_wide_t * out ) {
  out->m1_hi = wwv_ld( fd_bls_wide_offset_m1_hi );
  out->m1_lo = wwv_ld( fd_bls_wide_offset_m1_lo );
  out->m2_hi = wwv_ld( fd_bls_wide_offset_m2_hi );
  out->m2_lo = wwv_ld( fd_bls_wide_offset_m2_lo );
}

FD_BLS_INLINE void
fd_bls_fp_wide_addmul( fd_bls_fp_wide_t *  out,
                       fd_bls_fp_t const * a,
                       fd_bls_fp_t const * b ) {
  out->m1_hi = wwv_madd52hi( out->m1_hi, a->m1, b->m1 );
  out->m1_lo = wwv_madd52lo( out->m1_lo, a->m1, b->m1 );
  out->m2_hi = wwv_madd52hi( out->m2_hi, a->m2, b->m2 );
  out->m2_lo = wwv_madd52lo( out->m2_lo, a->m2, b->m2 );
}

FD_BLS_INLINE void
fd_bls_fp_wide_submul( fd_bls_fp_wide_t *  out,
                       fd_bls_fp_t const * a,
                       fd_bls_fp_t const * b ) {
  wwv_t z = wwv_zero();
  out->m1_hi = wwv_sub( out->m1_hi, wwv_madd52hi( z, a->m1, b->m1 ) );
  out->m1_lo = wwv_sub( out->m1_lo, wwv_madd52lo( z, a->m1, b->m1 ) );
  out->m2_hi = wwv_sub( out->m2_hi, wwv_madd52hi( z, a->m2, b->m2 ) );
  out->m2_lo = wwv_sub( out->m2_lo, wwv_madd52lo( z, a->m2, b->m2 ) );
}

FD_BLS_INLINE void
fd_bls_fp_add( fd_bls_fp_t *       out,
               fd_bls_fp_t const * a,
               fd_bls_fp_t const * b ) {
  out->m1 = fd_bls_rns_normalize( wwv_add( a->m1, b->m1 ), wwv_ld( fd_bls_m1_t ) );
  out->m2 = fd_bls_rns_normalize( wwv_add( a->m2, b->m2 ), wwv_ld( fd_bls_m2_t ) );
}

/* The encoded p is zero in Fp; adding it makes p-a nonnegative per lane. */
FD_BLS_INLINE void
fd_bls_fp_neg( fd_bls_fp_t *       out,
               fd_bls_fp_t const * a ) {
  wwv_t m1 = wwv_ld( fd_bls_m1 );
  wwv_t m2 = wwv_ld( fd_bls_m2 );
  wwv_t x1 = wwv_add( wwv_sub( wwv_shl( m1, 1 ), a->m1 ), fd_bls_modulus.m1 );
  wwv_t x2 = wwv_add( wwv_sub( wwv_shl( m2, 1 ), a->m2 ), fd_bls_modulus.m2 );
  out->m1 = wwv_min( x1, wwv_sub( x1, m1 ) );
  out->m2 = wwv_min( x2, wwv_sub( x2, m2 ) );
}

FD_BLS_INLINE void
fd_bls_fp_sub( fd_bls_fp_t *       out,
               fd_bls_fp_t const * a,
               fd_bls_fp_t const * b ) {
  fd_bls_fp_t neg_b;
  fd_bls_fp_neg( &neg_b, b );
  fd_bls_fp_add( out, a, &neg_b );
}

FD_BLS_INLINE void
fd_bls_fp_one( fd_bls_fp_t * out ) {
  *out = fd_bls_one;
}

FD_BLS_INLINE void
fd_bls_fp_zero( fd_bls_fp_t * out ) {
  out->m1 = wwv_zero();
  out->m2 = wwv_zero();
}

#endif
