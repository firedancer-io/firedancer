#ifndef HEADER_fd_src_ballet_secp256r1_fd_secp256r1_private_h
#define HEADER_fd_src_ballet_secp256r1_fd_secp256r1_private_h

/* fd_secp256r1 provides APIs for secp256r1 signature verification. */

#include "fd_secp256r1.h"
#include "../bigint/fd_uint256.h"

FD_PROTOTYPES_BEGIN

/* Field element: uint256 */
typedef fd_uint256_t fd_secp256r1_fp_t;

/* Scalar field element: uint256 */
typedef fd_uint256_t fd_secp256r1_scalar_t;

/* Point, in Jacobian coordinates (X : Y : Z).
   These correspond to affine x=X/Z^2, y=Y/Z^3.
   Field elements are in Montgomery form. */
struct fd_secp256r1_point {
  fd_secp256r1_fp_t x[1];
  fd_secp256r1_fp_t y[1];
  fd_secp256r1_fp_t z[1];
};
typedef struct fd_secp256r1_point fd_secp256r1_point_t;

/* const 0. */
static const fd_uint256_t fd_secp256r1_const_zero[1] = {{{
  0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000,
}}};

/* const p, used to validate a field element.
   NOT Montgomery.
   0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff */
static const fd_secp256r1_fp_t fd_secp256r1_const_p[1] = {{{
  0xffffffffffffffff, 0x00000000ffffffff, 0x0000000000000000, 0xffffffff00000001,
}}};

/* const 1. Montgomery.
   0x00000000fffffffeffffffffffffffffffffffff000000000000000000000001 */
static const fd_secp256r1_fp_t fd_secp256r1_const_one_mont[1] = {{{
  0x0000000000000001, 0xffffffff00000000, 0xffffffffffffffff, 0x00000000fffffffe,
}}};

/* const a=-3, in curve equation y^2 = x^3 + ax + b. Montgomery.
   0xfffffffc00000004000000000000000000000003fffffffffffffffffffffffc */
static const fd_secp256r1_fp_t fd_secp256r1_const_a_mont[1] = {{{
  0xfffffffffffffffc, 0x00000003ffffffff, 0x0000000000000000, 0xfffffffc00000004,
}}};

/* const b, in curve equation y^2 = x^3 + ax + b. Montgomery.
   0xdc30061d04874834e5a220abf7212ed6acf005cd78843090d89cdf6229c4bddf */
static const fd_secp256r1_fp_t fd_secp256r1_const_b_mont[1] = {{{
  0xd89cdf6229c4bddf, 0xacf005cd78843090, 0xe5a220abf7212ed6, 0xdc30061d04874834
}}};

/* const n, used to validate a scalar field element.
   NOT Montgomery.
   0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551 */
static const fd_secp256r1_scalar_t fd_secp256r1_const_n[1] = {{{
  0xf3b9cac2fc632551, 0xbce6faada7179e84, 0xffffffffffffffff, 0xffffffff00000000,
}}};

/* const (n-1)/2, used to validate a signature s component.
   NOT Montgomery.
   0x7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8 */
static const fd_secp256r1_scalar_t fd_secp256r1_const_n_m1_half[1] = {{{
  0x79dce5617e3192a8, 0xde737d56d38bcf42, 0x7fffffffffffffff, 0x7fffffff80000000,
}}};

FD_PROTOTYPES_END

#include "fd_secp256r1_s2n.c"

#endif /* HEADER_fd_src_ballet_secp256r1_fd_secp256r1_private_h */
