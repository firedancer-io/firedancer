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

/* const 1. Montgomery. */
fd_secp256k1_fp_t const fd_secp256k1_const_one_mont[1] = {{{
  0x1000003d1UL, 0UL, 0UL, 0UL
}}};

/* const b as field element. Montgomery. */
fd_secp256k1_fp_t const fd_secp256k1_const_b_mont[1] = {{{
  0x700001ab7UL, 0UL, 0UL, 0UL
}}};

/* const n, used to bump r for recovery_id & 2. In the field curve's montgomery domain.
   0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141 */
fd_secp256k1_fp_t const fd_secp256k1_const_n_mont[1] = {{{
  0xe21120489f1d95e1UL, 0x24a1ac9eb3fde294UL, 0xfffffffebaaed80dUL, 0xffffffffffffffffUL
}}};

/* const p, used for field operations. NOT Montgomery.
   0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f */
fd_secp256k1_fp_t const fd_secp256k1_const_p[1] = {{{
  0xfffffffefffffc2fUL, 0xffffffffffffffffUL, 0xffffffffffffffffUL, 0xffffffffffffffffUL
}}};

/* basepoint x coordinate. Montgomery.
   0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798 */
fd_secp256k1_fp_t const fd_secp256k1_const_base_x_mont[1] = {{{
  0xd7362e5a487e2097UL, 0x231e295329bc66dbUL, 0x979f48c033fd129cUL, 0x9981e643e9089f48UL
}}};

/* basepoint y coordinate. Montgomery.
   0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8 */
fd_secp256k1_fp_t const fd_secp256k1_const_base_y_mont[1] = {{{
  0xb15ea6d2d3dbabe2UL, 0x8dfc5d5d1f1dc64dUL, 0x70b6b59aac19c136UL, 0xcf3f851fd4a582d6UL
}}};

FD_PROTOTYPES_END

#include "fd_secp256k1_s2n.c"

#endif /* HEADER_fd_src_ballet_secp256k1_fd_secp256k1_private_h */
