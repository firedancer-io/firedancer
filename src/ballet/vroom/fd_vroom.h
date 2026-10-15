#ifndef HEADER_fd_src_ballet_vroom_fd_vroom_h
#define HEADER_fd_src_ballet_vroom_fd_vroom_h

/* VROOM: a curve-agnostic AVX-512 IFMA pairing/EC engine over a
   rotated-RNS Montgomery base field (two 8x50-bit residue bases, 2^52
   per-lane radix; after Langowski-Devadas, github.com/SimonLangowski/VROOM).

   The engine is a set of unity-TU fragments, not a library: a curve
   backend compiles ONE translation unit that includes, in order,

     1. fd_vroom_rns.h, fd_vroom_field.h    (types + prototypes)
     2. the curve's generated constants     (gen_vroom_constants.py:
        vroom_m1, vroom_r2_mat, vroom_p_limbs, VROOM_P0, ...)
     3. #define VROOM_FP12_KERNELS "<generated kernels>.inc"
        (gen_vroom_fp12.py: fp12 mul/sqr/sparse/cyclotomic for the
        curve's tower)
     4. fd_vroom_rns.c, fd_vroom_field.c, fd_vroom_fp2w.h
     5. the curve hooks (static inline/static, BEFORE step 6):
          vroom_fp2_mul_nonres( out, in )   out = xi*in
          vroom_fp2_mul_3b    ( out, in )   out = 3b'*in  (twist curve)
          vroom_fp_mul_3b_g1  ( out, in )   out = 3b*in   (base curve)
          vroom_fp_inverse    ( out, in )   base-field inverse, 0 -> 0
     6. fd_vroom_tower_inv.c, fd_vroom_ec.c
     7. the curve layer (Miller schedule, final exponentiation,
        Frobenius, subgroup checks, I/O) and its exported entry points.

   Everything in the engine is static except the vroom_fp, vroom_fp2
   and vroom_fp12 functions, whose linkage is VROOM_FN (default external
   so one TU per link may export them for tests; any additional curve
   TU defines VROOM_FN static).  Instantiations:

     src/ballet/bls/avx512/fd_bls_backend.c       BLS12-381
     src/ballet/bn254/avx512/fd_bn254_backend.c   BN254 (alt_bn128)

   The TU must be compiled with clang + AVX-512 IFMA; both Local.mk
   rules share FD_VROOM_CC / FD_VROOM_CFLAGS from this directory's
   Local.mk. */

#include "fd_vroom_rns.h"
#include "fd_vroom_field.h"

#endif
