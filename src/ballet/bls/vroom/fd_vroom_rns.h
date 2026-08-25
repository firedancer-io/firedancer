#ifndef HEADER_fd_src_ballet_bls_vroom_fd_vroom_rns_h
#define HEADER_fd_src_ballet_bls_vroom_fd_vroom_rns_h

#include "../../../util/fd_util_base.h"

#if FD_HAS_AVX512
#include <immintrin.h>

/* fd_vroom_fp_t is the expanded/non-affine base-field representation used by
   the C VROOM backend.  Each zmm holds eight residues in one 8x50-bit RNS
   base.  Values are kept in [0,2*m_i), which is directly usable by IFMA. */
typedef struct __attribute__((aligned(64))) {
  __m512i m1;
  __m512i m2;
} fd_vroom_fp_t;

typedef struct __attribute__((aligned(64))) {
  __m512i m1_hi;
  __m512i m1_lo;
  __m512i m2_hi;
  __m512i m2_lo;
} fd_vroom_fp_wide_t;

static __attribute__((always_inline)) inline void
fd_vroom_fp_wide_mul_raw( fd_vroom_fp_wide_t * out,
                          fd_vroom_fp_t const * a,
                          fd_vroom_fp_t const * b ) {
  __m512i z = _mm512_setzero_si512();
  out->m1_hi = _mm512_madd52hi_epu64( z, a->m1, b->m1 );
  out->m1_lo = _mm512_madd52lo_epu64( z, a->m1, b->m1 );
  out->m2_hi = _mm512_madd52hi_epu64( z, a->m2, b->m2 );
  out->m2_lo = _mm512_madd52lo_epu64( z, a->m2, b->m2 );
}

static __attribute__((always_inline)) inline void
fd_vroom_fp_wide_add_raw( fd_vroom_fp_wide_t *       out,
                          fd_vroom_fp_wide_t const * raw ) {
  out->m1_hi = _mm512_add_epi64( out->m1_hi, raw->m1_hi );
  out->m1_lo = _mm512_add_epi64( out->m1_lo, raw->m1_lo );
  out->m2_hi = _mm512_add_epi64( out->m2_hi, raw->m2_hi );
  out->m2_lo = _mm512_add_epi64( out->m2_lo, raw->m2_lo );
}

static __attribute__((always_inline)) inline void
fd_vroom_fp_wide_sub_raw( fd_vroom_fp_wide_t *       out,
                          fd_vroom_fp_wide_t const * raw ) {
  out->m1_hi = _mm512_sub_epi64( out->m1_hi, raw->m1_hi );
  out->m1_lo = _mm512_sub_epi64( out->m1_lo, raw->m1_lo );
  out->m2_hi = _mm512_sub_epi64( out->m2_hi, raw->m2_hi );
  out->m2_lo = _mm512_sub_epi64( out->m2_lo, raw->m2_lo );
}

FD_PROTOTYPES_BEGIN

void fd_vroom_fp_from_uint64( fd_vroom_fp_t * out, ulong const in[6] );
void fd_vroom_fp_to_uint64  ( ulong out[6], fd_vroom_fp_t const * in );
void fd_vroom_fp_mul        ( fd_vroom_fp_t * out, fd_vroom_fp_t const * a, fd_vroom_fp_t const * b );
void fd_vroom_fp_sqr        ( fd_vroom_fp_t * out, fd_vroom_fp_t const * a );
void fd_vroom_fp_add        ( fd_vroom_fp_t * out, fd_vroom_fp_t const * a, fd_vroom_fp_t const * b );
void fd_vroom_fp_sub        ( fd_vroom_fp_t * out, fd_vroom_fp_t const * a, fd_vroom_fp_t const * b );
void fd_vroom_fp_neg        ( fd_vroom_fp_t * out, fd_vroom_fp_t const * a );
void fd_vroom_fp_one        ( fd_vroom_fp_t * out );
void fd_vroom_fp_zero       ( fd_vroom_fp_t * out );
int  fd_vroom_fp_equal      ( fd_vroom_fp_t const * a, fd_vroom_fp_t const * b );

/* Reduce a positive, borrow-free wide expression modulo the BLS12-381 field.
   This is the batch-reduction boundary used by generated FP2/FP12 kernels. */
void fd_vroom_fp_reduce_wide( fd_vroom_fp_t * out, fd_vroom_fp_wide_t const * in );
void fd_vroom_fp_wide_offset( fd_vroom_fp_wide_t * out );
void fd_vroom_fp_wide_addmul( fd_vroom_fp_wide_t * out, fd_vroom_fp_t const * a, fd_vroom_fp_t const * b );
void fd_vroom_fp_wide_submul( fd_vroom_fp_wide_t * out, fd_vroom_fp_t const * a, fd_vroom_fp_t const * b );

FD_PROTOTYPES_END
#endif

#endif
