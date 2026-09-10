/* Portable secp256r1 backend (no s2n-bignum).  Included by
   fd_secp256r1_private.h when FD_HAS_S2NBIGNUM is unset.  See
   ../pcurves/fd_pcurve_ref_tmpl.c. */

/* fiat-crypto's generated cmovznz casts a signed char mask to uint64_t */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-conversion"
#include "../../third_party/fiat-crypto/p256_64.c"
#include "../../third_party/fiat-crypto/p256_scalar_64.c"
#pragma GCC diagnostic pop

/* p-2, exponent for field inversion */
static const ulong fd_secp256r1_const_p_m2[4] = {
  0xfffffffffffffffdUL, 0x00000000ffffffffUL, 0x0000000000000000UL, 0xffffffff00000001UL,
};

/* (p+1)/4, exponent for field square root (p = 3 mod 4) */
static const ulong fd_secp256r1_const_p_p1_div4[4] = {
  0x0000000000000000UL, 0x0000000040000000UL, 0x4000000000000000UL, 0x3fffffffc0000000UL,
};

/* n-2, exponent for scalar inversion */
static const ulong fd_secp256r1_const_n_m2[4] = {
  0xf3b9cac2fc63254fUL, 0xbce6faada7179e84UL, 0xffffffffffffffffUL, 0xffffffff00000000UL,
};

#define PCURVE_REF_NAME       fd_secp256r1
#define PCURVE_REF_LIMBS      4
#define PCURVE_REF_UINT       fd_uint256
#define PCURVE_REF_FIAT_FP(x) fiat_p256_##x
#define PCURVE_REF_FIAT_SC(x) fiat_p256_scalar_##x
#define PCURVE_REF_SUCCESS    FD_SECP256R1_SUCCESS
#define PCURVE_REF_FAILURE    FD_SECP256R1_FAILURE
#include "../pcurves/fd_pcurve_ref_tmpl.c"
