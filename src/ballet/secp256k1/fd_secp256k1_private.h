#ifndef HEADER_fd_src_ballet_secp256k1_fd_secp256k1_private_h
#define HEADER_fd_src_ballet_secp256k1_fd_secp256k1_private_h

#include "../bigint/fd_uint256.h"

FD_PROTOTYPES_BEGIN

/* Scalar Field */
typedef fd_uint256_t fd_secp256k1_scalar_t;

/* Base Field */
typedef fd_uint256_t fd_secp256k1_fp_t;

/* Secp256k1 point in Jacobian coordinates */
struct fd_secp256k1_point {
  fd_secp256k1_fp_t x[1];
  fd_secp256k1_fp_t y[1];
  fd_secp256k1_fp_t z[1];
};
typedef struct fd_secp256k1_point fd_secp256k1_point_t;

/* const 0 */
fd_secp256k1_scalar_t const fd_secp256k1_const_zero[1] = {{{
  0, 0, 0, 0,
}}};

/* const n, used to validate a scalar element. NOT Montgomery.
   0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141 */
fd_secp256k1_scalar_t const fd_secp256k1_const_n[1] = {{{
  0xbfd25e8cd0364141, 0xbaaedce6af48a03b, 0xfffffffffffffffe, 0xffffffffffffffff,
}}};

/* const p - n. NOT Montgomery.
   0x14551231950b75fc4402da1722fc9baee */
fd_secp256k1_scalar_t const fd_secp256k1_const_p_minus_n[1] = {{{
  0x402da1722fc9baeeUL, 0x4551231950b75fc4UL, 0x1UL, 0x0UL
}}};

/* const R^2 mod n, where R = 2^256. Montgomery.
   Used to convert scalars into the montgomery domain. Elements in a montgomery domain are
   a*R, where R=2^256 mod n. Montgomery multiplication does (a * b / R) mod n. We can
   move into the montgomery domain by doing montmul(x, RR), where RR is R in the montgomery domain.

   TODO: In the future s2n-bignum might provide a tomont_n256k1 API, and we should migrate to it. */
ulong const fd_secp256k1_const_scalar_rr_mont[4] = {
  0x896cf21467d7d140UL, 0x741496c20e7cf878UL, 0xe697f5e45bcd07c6UL, 0x9d671cd581c69bc5UL,
};

/* const 1 */
fd_secp256k1_fp_t const fd_secp256k1_const_one[1] = {{{
  1UL, 0UL, 0UL, 0UL
}}};

/* const b = 7 */
fd_secp256k1_fp_t const fd_secp256k1_const_b[1] = {{{
  7UL, 0UL, 0UL, 0UL
}}};

/* const n as a field element, used to bump r for recovery_id & 2.
   0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141 */
fd_secp256k1_fp_t const fd_secp256k1_const_n_fp[1] = {{{
  0xbfd25e8cd0364141UL, 0xbaaedce6af48a03bUL, 0xfffffffffffffffeUL, 0xffffffffffffffffUL
}}};

/* const p, used for field operations.
   0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f */
fd_secp256k1_fp_t const fd_secp256k1_const_p[1] = {{{
  0xfffffffefffffc2fUL, 0xffffffffffffffffUL, 0xffffffffffffffffUL, 0xffffffffffffffffUL
}}};

FD_PROTOTYPES_END

#include "fd_secp256k1_s2n.c"

#endif /* HEADER_fd_src_ballet_secp256k1_fd_secp256k1_private_h */
