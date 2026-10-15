/* BLS12-381 instantiation of the VROOM AVX-512 RNS engine
   (src/ballet/vroom).  Single translation unit: keeping the
   fixed-parameter layers together lets the compiler inline through RNS,
   extension-field, and Miller operations just as it can for a
   handwritten straight-line kernel.  The object is compiled without
   semantic interposition so internal calls can be folded across layers. */

#include "../../vroom/fd_vroom_rns.h"
#include "../../vroom/fd_vroom_field.h"

#if FD_HAS_AVX512
#include "../../../third_party/blst/bindings/blst.h"

/* Curve constants (generated): RNS bases, conversion tables, and the
   BLS12-381 field constants in rotated RNS form. */
#include "fd_bls_constants.h"
#endif

/* --- engine: base field + tower --- */

#define VROOM_FP12_KERNELS "../bls/avx512/fd_bls_fp12_generated.inc"
#include "../../vroom/fd_vroom_rns.c"
#include "../../vroom/fd_vroom_field.c"
#include "../../vroom/fd_vroom_fp2w.h"

#if FD_HAS_AVX512

/* --- curve hooks --- */

/* xi*a for the BLS12-381 sextic nonresidue xi = 1+u. */
static inline void
vroom_fp2_mul_nonres( vroom_fp2_t *       out,
                      vroom_fp2_t const * in ) {
  vroom_fp_t a = in->c[0], b = in->c[1];
  vroom_fp_sub( &out->c[0], &a, &b ); /* Re((1+u)(a+bu)) = a-b, since u^2=-1. */
  vroom_fp_add( &out->c[1], &a, &b ); /* Im((1+u)(a+bu)) = a+b.               */
}

/* 3b'*a for the twist y^2 = x^3 + 4(1+u): 3b' = 12(1+u). */
static inline void
vroom_fp2_mul_3b( vroom_fp2_t *       out,
                  vroom_fp2_t const * a ) {
  vroom_fp2_t nonres;
  vroom_fp2_mul_nonres( &nonres, a );
  vroom_fp2_mul_small( out, &nonres, 12U );
}

/* (3*b)*a for the base curve y^2 = x^3 + 4: 3b = 12. */
static inline void
vroom_fp_mul_3b_g1( vroom_fp_t *       out,
                    vroom_fp_t const * a ) {
  vroom_fp_mul_small( out, a, 12U );
}

/* Variable-time base-field inversion (0 -> 0); public pairing inputs are
   not secret.  Routes the single inversion through blst (a native
   extended-GCD measured slower); RNS<->canonical conversions are the
   same helpers the export path uses. */
static void
vroom_fp_inverse( vroom_fp_t *       out,
                  vroom_fp_t const * base ) {
  ulong u[6];
  vroom_fp_to_uint64( u, base );
  if( FD_UNLIKELY( !(u[0]|u[1]|u[2]|u[3]|u[4]|u[5]) ) ) {
    vroom_fp_zero( out );
    return;
  }
  blst_fp a;
  blst_fp_from_uint64( &a, u );   /* canonical -> blst Montgomery form. */
  blst_fp_inverse( &a, &a );      /* Montgomery form of the inverse.    */
  blst_uint64_from_fp( u, &a );   /* de-Montgomery -> canonical limbs.  */
  vroom_fp_from_uint64( out, u );
}

#endif /* FD_HAS_AVX512 */

/* --- engine: tower inversion and EC formulas (use the hooks above) --- */

#include "../../vroom/fd_vroom_tower_inv.c"
#include "../../vroom/fd_vroom_ec.c"

/* --- BLS12-381 curve layer --- */

#include "../fd_bls.h"
#include "fd_bls_miller.h"
#include "fd_bls_final.h"

#include "fd_bls_final.c"
#include "fd_bls_miller.c"
#include "fd_bls_g1.c"
#include "fd_bls_hash.c"
#include "fd_bls.c"
