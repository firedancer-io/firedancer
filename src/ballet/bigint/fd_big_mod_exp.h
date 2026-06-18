#ifndef HEADER_fd_src_ballet_bigint_fd_big_mod_exp_h
#define HEADER_fd_src_ballet_bigint_fd_big_mod_exp_h

/* fd_big_mod_exp.h provides big-integer modular exponentiation, the core
   computation behind the sol_big_mod_exp syscall (SIMD-0529):

     result = (base ^ exponent) mod modulus

   All operands (base, exponent, modulus) and the result are encoded as
   LITTLE-ENDIAN unsigned integers (note: this differs from EIP-198 and
   the legacy big-endian sol_big_mod_exp).  The modulus MUST be odd and
   greater than 1; this lets the computation use s2n-bignum's Montgomery
   modular exponentiation (bignum_modexp), which requires an odd modulus.

   The computation is feature-gated at the syscall layer; this module
   only provides the math primitive. */

#include "../fd_ballet_base.h"

/* The syscall caps each operand at 512 bytes. */
#define FD_BIG_MOD_EXP_MAX_BYTES (512UL)

#define FD_BIG_MOD_EXP_SUCCESS     ( 0) /* computed ok */
#define FD_BIG_MOD_EXP_ERR_MODULUS (-1) /* modulus even, zero, or one */

FD_PROTOTYPES_BEGIN

/* fd_big_mod_exp_modulus_is_valid returns 1 if the little-endian modulus
   in mod[0,mod_len) is odd and strictly greater than 1, otherwise 0.
   (SIMD-0529 requires the modulus to be odd and > 1; even, zero, and one
   moduli are rejected.) */

FD_FN_PURE int
fd_big_mod_exp_modulus_is_valid( uchar const * mod,
                                 ulong         mod_len );

/* fd_big_mod_exp computes out := (base ^ exponent) mod modulus.

   base[0,base_len), exp[0,exp_len), mod[0,mod_len) are the little-endian
   operands; out receives exactly mod_len little-endian bytes (the result,
   trailing-zero padded).  base_len, exp_len, mod_len must each be in
   [0,FD_BIG_MOD_EXP_MAX_BYTES] (mod_len must be >0 for a meaningful
   result).  out must not alias any input.

   Returns FD_BIG_MOD_EXP_SUCCESS on success.  Returns
   FD_BIG_MOD_EXP_ERR_MODULUS (without writing out) if the modulus is not
   odd and > 1.

   Requires an s2n-bignum build (FD_HAS_S2NBIGNUM). */

int
fd_big_mod_exp( uchar *       out,
                uchar const * base, ulong base_len,
                uchar const * exp,  ulong exp_len,
                uchar const * mod,  ulong mod_len );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_bigint_fd_big_mod_exp_h */
