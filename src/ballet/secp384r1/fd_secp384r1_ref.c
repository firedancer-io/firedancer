/* Portable secp384r1 backend (no s2n-bignum).  Included by
   fd_secp384r1_private.h when FD_HAS_S2NBIGNUM is unset.  See
   ../pcurves/fd_pcurve_ref_tmpl.c. */

/* fiat-crypto's generated cmovznz casts a signed char mask to uint64_t */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-conversion"
#include "../../third_party/fiat-crypto/p384_64.c"
#include "../../third_party/fiat-crypto/p384_scalar_64.c"
#pragma GCC diagnostic pop

/* p-2, exponent for field inversion */
static const ulong fd_secp384r1_const_p_m2[6] = {
  0x00000000fffffffdUL, 0xffffffff00000000UL, 0xfffffffffffffffeUL,
  0xffffffffffffffffUL, 0xffffffffffffffffUL, 0xffffffffffffffffUL,
};

/* (p+1)/4, exponent for field square root (p = 3 mod 4) */
static const ulong fd_secp384r1_const_p_p1_div4[6] = {
  0x0000000040000000UL, 0xbfffffffc0000000UL, 0xffffffffffffffffUL,
  0xffffffffffffffffUL, 0xffffffffffffffffUL, 0x3fffffffffffffffUL,
};

/* n-2, exponent for scalar inversion */
static const ulong fd_secp384r1_const_n_m2[6] = {
  0xecec196accc52971UL, 0x581a0db248b0a77aUL, 0xc7634d81f4372ddfUL,
  0xffffffffffffffffUL, 0xffffffffffffffffUL, 0xffffffffffffffffUL,
};

#define PCURVE_REF_NAME       fd_secp384r1
#define PCURVE_REF_LIMBS      6
#define PCURVE_REF_UINT       fd_uint384
#define PCURVE_REF_FIAT_FP(x) fiat_p384_##x
#define PCURVE_REF_FIAT_SC(x) fiat_p384_scalar_##x
#define PCURVE_REF_SUCCESS    FD_SECP384R1_SUCCESS
#define PCURVE_REF_FAILURE    FD_SECP384R1_FAILURE
#include "../pcurves/fd_pcurve_ref_tmpl.c"
