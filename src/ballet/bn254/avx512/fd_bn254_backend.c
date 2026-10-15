/* BN254 instantiation of the VROOM AVX-512 RNS engine
   (src/ballet/vroom).  Single translation unit, compiled with the
   dedicated clang IFMA rule; see the BLS instantiation
   (src/ballet/bls/avx512/fd_bls_backend.c) for the layout rationale.

   The engine's non-inline functions are made static here (VROOM_FN):
   the BLS TU exports them for its unit tests, and two exporting TUs
   would collide at link time. */

#define VROOM_FN static
#include "../../vroom/fd_vroom_rns.h"
#include "../../vroom/fd_vroom_field.h"

/* fd_bn254 scalar reference internals: types, Montgomery helpers, GLV
   lattice constants (the GLV scalar split is shared with the scalar
   backend; only point arithmetic runs on vroom). */
#include "../fd_bn254_field_inl.h"
#include "../fd_bn254_glv.h"
#include "../fd_bn254_backend.h"

#if FD_HAS_AVX512
/* Curve constants (generated): RNS bases, conversion tables, and the
   BN254 field constants in rotated RNS form. */
#include "fd_bn254_constants.h"
#endif

/* --- engine: base field + tower --- */

#define VROOM_FP12_KERNELS "../bn254/avx512/fd_bn254_fp12_generated.inc"
#include "../../vroom/fd_vroom_rns.c"
#include "../../vroom/fd_vroom_field.c"
#include "../../vroom/fd_vroom_fp2w.h"

#if FD_HAS_AVX512

/* --- curve hooks --- */

/* xi*a for the BN254 sextic nonresidue xi = 9+u:
   (9a - b) + (9b + a)u.  The 9x multiples go through raw double-and-add
   (vroom_fp_mul_small bound analysis). */
static inline void
vroom_fp2_mul_nonres( vroom_fp2_t *       out,
                      vroom_fp2_t const * in ) {
  vroom_fp_t a9, b9;
  vroom_fp_mul_small( &a9, &in->c[0], 9U );
  vroom_fp_mul_small( &b9, &in->c[1], 9U );
  vroom_fp_t a = in->c[0], b = in->c[1];
  vroom_fp_sub( &out->c[0], &a9, &b );
  vroom_fp_add( &out->c[1], &b9, &a );
}

/* 3b'*a for the D-type twist y^2 = x^3 + 3/(9+u): 3b' = 9/(9+u), a
   dense Fp2 constant (full constant multiply, no small form). */
static inline void
vroom_fp2_mul_3b( vroom_fp2_t *       out,
                  vroom_fp2_t const * a ) {
  vroom_fp2_t b3;
  b3.c[0] = VROOM_FP_CONST( twist_b3_re );
  b3.c[1] = VROOM_FP_CONST( twist_b3_im );
  vroom_fp2_mul( out, a, &b3 );
}

/* (3*b)*a for the base curve y^2 = x^3 + 3: 3b = 9. */
static inline void
vroom_fp_mul_3b_g1( vroom_fp_t *       out,
                    vroom_fp_t const * a ) {
  vroom_fp_mul_small( out, a, 9U );
}

/* Variable-time base-field inversion (0 -> 0); public inputs only.
   Routes through the scalar backend's inverter (s2n-bignum modinv or
   Fermat), converting at the canonical-limb boundary. */
static void
vroom_fp_inverse( vroom_fp_t *       out,
                  vroom_fp_t const * base ) {
  ulong u[6];
  vroom_fp_to_uint64( u, base );
  if( FD_UNLIKELY( !(u[0]|u[1]|u[2]|u[3]|u[4]|u[5]) ) ) {
    vroom_fp_zero( out );
    return;
  }
  fd_bn254_fp_t a, inv;
  a.limbs[0]=u[0]; a.limbs[1]=u[1]; a.limbs[2]=u[2]; a.limbs[3]=u[3];
  fd_bn254_fp_to_mont( &a, &a );     /* canonical -> Montgomery        */
  fd_bn254_fp_inv( &inv, &a );       /* Montgomery form of the inverse */
  fd_bn254_fp_from_mont( &inv, &inv ); /* -> canonical limbs           */
  u[0]=inv.limbs[0]; u[1]=inv.limbs[1]; u[2]=inv.limbs[2]; u[3]=inv.limbs[3];
  u[4]=0UL; u[5]=0UL;
  vroom_fp_from_uint64( out, u );
}

#endif /* FD_HAS_AVX512 */

/* --- engine: tower inversion and EC formulas (use the hooks above) --- */

#include "../../vroom/fd_vroom_tower_inv.c"
#include "../../vroom/fd_vroom_ec.c"

/* --- BN254 curve layer --- */

#include "fd_bn254_io.c"
#include "fd_bn254_miller.c"
#include "fd_bn254_final.c"
#include "fd_bn254_g2.c"
#include "fd_bn254_g1_mul.c"
#include "fd_bn254_avx512.c"
