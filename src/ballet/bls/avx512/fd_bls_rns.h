#ifndef HEADER_fd_src_ballet_bls_avx512_fd_bls_rns_h
#define HEADER_fd_src_ballet_bls_avx512_fd_bls_rns_h

#include "../../../util/fd_util_base.h"

#if FD_HAS_AVX512
#include "../../../util/simd/fd_avx512.h"

/* A base-field value in rotated Montgomery form.  m1 and m2 hold its
   residues in two disjoint 8x50-bit RNS bases M and N.  Lanes are redundant
   in [0,2*m_i), so field equality is modulo p, not componentwise equality. */
typedef struct __attribute__((aligned(64))) {
  wwv_t m1;
  wwv_t m2;
} fd_bls_fp_t;

/* An unreduced sum of products; each lane represents hi*2^52+lo. */
typedef struct __attribute__((aligned(64))) {
  wwv_t m1_hi;
  wwv_t m1_lo;
  wwv_t m2_hi;
  wwv_t m2_lo;
} fd_bls_fp_wide_t;

static __attribute__((always_inline)) inline void
fd_bls_fp_wide_mul_raw( fd_bls_fp_wide_t * out,
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

void fd_bls_fp_from_uint64( fd_bls_fp_t * out, ulong const in[6] );
void fd_bls_fp_to_uint64  ( ulong out[6], fd_bls_fp_t const * in );
void fd_bls_fp_mul        ( fd_bls_fp_t * out, fd_bls_fp_t const * a, fd_bls_fp_t const * b );
void fd_bls_fp_sqr        ( fd_bls_fp_t * out, fd_bls_fp_t const * a );
void fd_bls_fp_add        ( fd_bls_fp_t * out, fd_bls_fp_t const * a, fd_bls_fp_t const * b );
void fd_bls_fp_sub        ( fd_bls_fp_t * out, fd_bls_fp_t const * a, fd_bls_fp_t const * b );
void fd_bls_fp_neg        ( fd_bls_fp_t * out, fd_bls_fp_t const * a );
void fd_bls_fp_one        ( fd_bls_fp_t * out );
void fd_bls_fp_zero       ( fd_bls_fp_t * out );
int  fd_bls_fp_equal      ( fd_bls_fp_t const * a, fd_bls_fp_t const * b );

/* Reduce a positive, borrow-free wide expression modulo the BLS12-381 field.
   This is the batch-reduction boundary used by generated FP2/FP12 kernels. */
void fd_bls_fp_reduce_wide( fd_bls_fp_t * out, fd_bls_fp_wide_t const * in );
/* Initialize a wide accumulator with a multiple of p, making later signed
   sums borrow-free without changing their value in Fp. */
void fd_bls_fp_wide_offset( fd_bls_fp_wide_t * out );
void fd_bls_fp_wide_addmul( fd_bls_fp_wide_t * out, fd_bls_fp_t const * a, fd_bls_fp_t const * b );
void fd_bls_fp_wide_submul( fd_bls_fp_wide_t * out, fd_bls_fp_t const * a, fd_bls_fp_t const * b );

FD_PROTOTYPES_END
#endif

#endif
