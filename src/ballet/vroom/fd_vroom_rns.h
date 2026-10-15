#ifndef HEADER_fd_src_ballet_vroom_fd_vroom_rns_h
#define HEADER_fd_src_ballet_vroom_fd_vroom_rns_h

#include "../../util/fd_util_base.h"

#if FD_HAS_AVX512
#include "../../util/simd/fd_avx512.h"

/* A base-field value in rotated Montgomery form.  m1 and m2 hold its
   residues in two disjoint 8x50-bit RNS bases M and N.  Lanes are redundant
   in [0,2*m_i), so field equality is modulo p, not componentwise equality. */
typedef struct __attribute__((aligned(64))) {
  wwv_t m1;
  wwv_t m2;
} vroom_fp_t;

/* An unreduced sum of products; each lane represents hi*2^52+lo. */
typedef struct __attribute__((aligned(64))) {
  wwv_t m1_hi;
  wwv_t m1_lo;
  wwv_t m2_hi;
  wwv_t m2_lo;
} vroom_fp_wide_t;

static __attribute__((always_inline)) inline void
vroom_fp_wide_mul_raw( vroom_fp_wide_t *  out,
                        vroom_fp_t const * a,
                        vroom_fp_t const * b ) {
  wwv_t z = wwv_zero();
  out->m1_hi = wwv_madd52hi( z, a->m1, b->m1 );
  out->m1_lo = wwv_madd52lo( z, a->m1, b->m1 );
  out->m2_hi = wwv_madd52hi( z, a->m2, b->m2 );
  out->m2_lo = wwv_madd52lo( z, a->m2, b->m2 );
}

static __attribute__((always_inline)) inline void
vroom_fp_wide_add_raw( vroom_fp_wide_t *       out,
                        vroom_fp_wide_t const * raw ) {
  out->m1_hi = wwv_add( out->m1_hi, raw->m1_hi );
  out->m1_lo = wwv_add( out->m1_lo, raw->m1_lo );
  out->m2_hi = wwv_add( out->m2_hi, raw->m2_hi );
  out->m2_lo = wwv_add( out->m2_lo, raw->m2_lo );
}

static __attribute__((always_inline)) inline void
vroom_fp_wide_sub_raw( vroom_fp_wide_t *       out,
                        vroom_fp_wide_t const * raw ) {
  out->m1_hi = wwv_sub( out->m1_hi, raw->m1_hi );
  out->m1_lo = wwv_sub( out->m1_lo, raw->m1_lo );
  out->m2_hi = wwv_sub( out->m2_hi, raw->m2_hi );
  out->m2_lo = wwv_sub( out->m2_lo, raw->m2_lo );
}

/* Load a generated constant (a vroom_<name>_m1/_m2 table pair from the
   curve's generated constants header) as a vroom_fp_t. */
static inline vroom_fp_t
vroom_fp_const( ulong const m1[8],
                 ulong const m2[8] ) {
  return (vroom_fp_t){ .m1 = wwv_ld( m1 ), .m2 = wwv_ld( m2 ) };
}

#define VROOM_FP_CONST(name) vroom_fp_const( vroom_##name##_m1, vroom_##name##_m2 )

/* VROOM_FN controls the linkage of the engine's non-inline functions.
   Default is external (one curve TU may export them for its tests); a
   second curve TU in the same link must define VROOM_FN static before
   including the engine to avoid symbol collisions. */
#ifndef VROOM_FN
#define VROOM_FN
#endif

FD_PROTOTYPES_BEGIN

VROOM_FN void vroom_fp_from_uint64( vroom_fp_t * out, ulong const in[6] );
VROOM_FN void vroom_fp_to_uint64  ( ulong out[6], vroom_fp_t const * in );
VROOM_FN void vroom_fp_mul        ( vroom_fp_t * out, vroom_fp_t const * a, vroom_fp_t const * b );
VROOM_FN void vroom_fp_sqr        ( vroom_fp_t * out, vroom_fp_t const * a );
VROOM_FN void vroom_fp_add        ( vroom_fp_t * out, vroom_fp_t const * a, vroom_fp_t const * b );
VROOM_FN void vroom_fp_sub        ( vroom_fp_t * out, vroom_fp_t const * a, vroom_fp_t const * b );
VROOM_FN void vroom_fp_neg        ( vroom_fp_t * out, vroom_fp_t const * a );
VROOM_FN void vroom_fp_one        ( vroom_fp_t * out );
VROOM_FN void vroom_fp_zero       ( vroom_fp_t * out );
VROOM_FN int  vroom_fp_equal      ( vroom_fp_t const * a, vroom_fp_t const * b );
/* n*a for small n <= 2^8 via raw lane double-and-add. */
VROOM_FN void vroom_fp_mul_small  ( vroom_fp_t * out, vroom_fp_t const * a, uint n );

/* Reduce a positive, borrow-free wide expression modulo the field.
   This is the batch-reduction boundary used by generated FP2/FP12 kernels. */
VROOM_FN void vroom_fp_reduce_wide( vroom_fp_t * out, vroom_fp_wide_t const * in );
/* Initialize a wide accumulator with a multiple of p, making later signed
   sums borrow-free without changing their value in Fp. */
VROOM_FN void vroom_fp_wide_offset( vroom_fp_wide_t * out );
VROOM_FN void vroom_fp_wide_addmul( vroom_fp_wide_t * out, vroom_fp_t const * a, vroom_fp_t const * b );
VROOM_FN void vroom_fp_wide_submul( vroom_fp_wide_t * out, vroom_fp_t const * a, vroom_fp_t const * b );

FD_PROTOTYPES_END
#endif

#endif
