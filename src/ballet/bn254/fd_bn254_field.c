#include "./fd_bn254_field_inl.h"

/* const 0. */
const fd_bn254_fp_t fd_bn254_const_zero[1] = {{{
  0x0UL, 0x0UL, 0x0UL, 0x0UL,
}}};

/* const 1. NOT Montgomery. mul(a, 1) = a*R^-1 = from_mont(a). */
const fd_bn254_fp_t fd_bn254_const_one[1] = {{{
  0x1UL, 0x0UL, 0x0UL, 0x0UL,
}}};

/* const R^2 mod p, R=2^256. mul(a, R^2) = a*R = to_mont(a).
   0x06d89f71cab8351f47ab1eff0a417ff6b5e71911d44501fbf32cfc5b538afa89 */
const fd_bn254_fp_t fd_bn254_const_rr[1] = {{{
  0xf32cfc5b538afa89, 0xb5e71911d44501fb, 0x47ab1eff0a417ff6, 0x06d89f71cab8351f,
}}};

/* const p, used to validate a field element. NOT Montgomery.
   0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47 */
const fd_bn254_fp_t fd_bn254_const_p[1] = {{{
  0x3c208c16d87cfd47, 0x97816a916871ca8d, 0xb85045b68181585d, 0x30644e72e131a029,
}}};

/* const 1. Montgomery.
   0x0e0a77c19a07df2f666ea36f7879462c0a78eb28f5c70b3dd35d438dc58f0d9d */
const fd_bn254_fp_t fd_bn254_const_one_mont[1] = {{{
  0xd35d438dc58f0d9d, 0x0a78eb28f5c70b3d, 0x666ea36f7879462c, 0x0e0a77c19a07df2f
}}};

/* const x, used by fd_bn254_g2_frombytes_check(). scalar (NOT Montgomery)
   0x44e992b44a6909f1 (64-bit) */
const fd_bn254_scalar_t fd_bn254_const_x[1] = {{{
  0x44e992b44a6909f1, 0x0, 0x0, 0x0,
}}};

/* const b=3, in curve equation y^2 = x^3 + b. Montgomery.
   0x2a1f6744ce179d8e334bea4e696bd2841f6ac17ae15521b97a17caa950ad28d7 */
const fd_bn254_fp_t fd_bn254_const_b_mont[1] = {{{
  0x7a17caa950ad28d7, 0x1f6ac17ae15521b9, 0x334bea4e696bd284, 0x2a1f6744ce179d8e
  // 0x3UL, 0x0UL, 0x0UL, 0x0UL,
}}};

/* const p-1, to check if sqrt exists. Montgomery.
   0x2259d6b14729c0fa51e1a247090812318d087f6872aabf4f68c3488912edefaa */
const fd_bn254_fp_t fd_bn254_const_p_minus_one_mont[1] = {{{
  0x68c3488912edefaa, 0x8d087f6872aabf4f, 0x51e1a24709081231, 0x2259d6b14729c0fa,
}}};

/* const (p-1)/2, used to check if an element is positive or negative,
   and to calculate sqrt() in Fp2. NOT Montgomery.
   0x183227397098d014dc2822db40c0ac2ecbc0b548b438e5469e10460b6c3e7ea3 */
const fd_bn254_fp_t fd_bn254_const_p_minus_one_half[1] = {{{
  0x9e10460b6c3e7ea3, 0xcbc0b548b438e546, 0xdc2822db40c0ac2e, 0x183227397098d014,
}}};

/* const (p-3)/4, used to calculate sqrt() in Fp and Fp2. bigint (NOT Montgomery)
   0x0c19139cb84c680a6e14116da060561765e05aa45a1c72a34f082305b61f3f51 */
const fd_uint256_t fd_bn254_const_sqrt_exp[1] = {{{
  0x4f082305b61f3f51, 0x65e05aa45a1c72a3, 0x6e14116da0605617, 0x0c19139cb84c680a,
}}};

/* GLV lattice constants (fd_bn254_glv.h), defined here so the G1/G2
   TUs see no literals: gcc's SLP synth_mult on a 128-bit product by a
   literal is very slow to compile. */
const ulong na[ 2 ] = { 0x8211bbeb7d4f1128UL, 0x6f4d8248eeb859fcUL };
const ulong nb[ 1 ] = { 0x89d3256894d213e3UL };
const ulong nc[ 2 ] = { 0x0be4e1541221250bUL, 0x6f4d8248eeb859fdUL };
const ulong g1_const_g1[ 3 ] = { 0x5398fd0300ff6565UL, 0x4ccef014a773d2d2UL, 0x0000000000000002UL };
const ulong g1_const_g2[ 3 ] = { 0x7a7bd9d4391eb18eUL, 0x4ccef014a773d2cfUL, 0x0000000000000002UL };
const ulong g2_const   [ 2 ] = { 0xd91d232ec7e0b3d7UL, 0x0000000000000002UL };

fd_bn254_fp_t *
fd_bn254_fp_pow( fd_bn254_fp_t * restrict r,
                 fd_bn254_fp_t const *    a,
                 fd_uint256_t  const *    b ) {
  fd_bn254_fp_set_one( r );
  if( fd_uint256_is_zero( b ) ) return r; /* x^0 = 1 */

  /* There must be a bit set, as b>0, so if we reach i==0, it must be set. */
  int i = 255;
  while( !fd_uint256_bit( b, i ) ) i--;

  for( ; i>=0; i--) {
    fd_bn254_fp_sqr( r, r );
    if( fd_uint256_bit( b, i ) ) {
      fd_bn254_fp_mul( r, r, a );
    }
  }
  return r;
}
