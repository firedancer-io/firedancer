#include "./fd_bn254_field_inl.h"

/* Extension field consts and non-inline ops. */

/* Constants */

/* const B=3/(i+9), in twist curve equation y^2 = x^3 + b'. Montgomery.
   0x2514c6324384a86d26b7edf049755260020b1b273633535d3bf938e377b802a8
   0x0141b9ce4a688d4dd749d0dd22ac00aa65f0b37d93ce0d3e38e7ecccd1dcff67 */
const fd_bn254_fp2_t fd_bn254_const_twist_b_mont[1] = {{{
  {{ 0x3bf938e377b802a8, 0x020b1b273633535d, 0x26b7edf049755260, 0x2514c6324384a86d, }},
  {{ 0x38e7ecccd1dcff67, 0x65f0b37d93ce0d3e, 0xd749d0dd22ac00aa, 0x0141b9ce4a688d4d, }},
}}};

/* fd_bn254_const_frob_gamma1_mont for frob. Montgomery.
   gamma_1,1 = 0x02f34d751a1f3a7c11bded5ef08a2087ca6b1d7387afb78aaf9ba69633144907
               0x10a75716b3899551dc2ff3a253dfc926d00f02a4565de15ba222ae234c492d72
   gamma_1,2 = 0x1956bcd8118214ec7a007127242e0991347f91c8a9aa6454b5773b104563ab30
               0x26694fbb4e82ebc3b6e713cdfae0ca3aaa1c7b6d89f891416e849f1ea0aa4757
   gamma_1,3 = 0x253570bea500f8dd31a9d1b6f9645366bb30f162e133bacbe4bbdd0c2936b629
               0x2c87200285defecc6d16bd27bb7edc6b07affd117826d1dba1d77ce45ffe77c7
   gamma_1,4 = 0x15df9cddbb9fd3ec9c941f314b3e2399a5bb2bd3273411fb7361d77f843abe92
               0x24830a9d3171f0fd37bc870a0c7dd2b962cb29a5a4445b605dddfd154bd8c949
   gamma_1,5 = 0x12aabced0ab0884132bee66b83c459e8e240342127694b0bc970692f41690fe7
               0x2f21ebb535d2925ad3b0a40b8a4910f505193418ab2fcc570d485d2340aebfa9 */
const fd_bn254_fp2_t fd_bn254_const_frob_gamma1_mont[5] = {
  {{
    {{ 0xaf9ba69633144907, 0xca6b1d7387afb78a, 0x11bded5ef08a2087, 0x02f34d751a1f3a7c, }},
    {{ 0xa222ae234c492d72, 0xd00f02a4565de15b, 0xdc2ff3a253dfc926, 0x10a75716b3899551, }},
  }},
  {{
    {{ 0xb5773b104563ab30, 0x347f91c8a9aa6454, 0x7a007127242e0991, 0x1956bcd8118214ec, }},
    {{ 0x6e849f1ea0aa4757, 0xaa1c7b6d89f89141, 0xb6e713cdfae0ca3a, 0x26694fbb4e82ebc3, }},
  }},
  {{
    {{ 0xe4bbdd0c2936b629, 0xbb30f162e133bacb, 0x31a9d1b6f9645366, 0x253570bea500f8dd, }},
    {{ 0xa1d77ce45ffe77c7, 0x07affd117826d1db, 0x6d16bd27bb7edc6b, 0x2c87200285defecc, }},
  }},
  {{
    {{ 0x7361d77f843abe92, 0xa5bb2bd3273411fb, 0x9c941f314b3e2399, 0x15df9cddbb9fd3ec, }},
    {{ 0x5dddfd154bd8c949, 0x62cb29a5a4445b60, 0x37bc870a0c7dd2b9, 0x24830a9d3171f0fd, }},
  }},
  {{
    {{ 0xc970692f41690fe7, 0xe240342127694b0b, 0x32bee66b83c459e8, 0x12aabced0ab08841, }},
    {{ 0x0d485d2340aebfa9, 0x05193418ab2fcc57, 0xd3b0a40b8a4910f5, 0x2f21ebb535d2925a, }},
  }},
};

/* fd_bn254_const_frob_gamma2_mont for frob^2. Montgomery.
   gamma_2,1 = 0x04290f65bad856e60e201271ad0d4418f0c5d61468b39769ca8d800500fa1bf2
   gamma_2,2 = 0x2682e617020217e06001b4b8b615564a7dce557cdb5e56b93350c88e13e80b9c
   gamma_2,3 = 0x2259d6b14729c0fa51e1a247090812318d087f6872aabf4f68c3488912edefaa
   gamma_2,4 = 0x2c3b3f0d26594943aa303344d4741444a6bb947cffbe332371930c11d782e155
   gamma_2,5 = 0x09e1685bdf2f8849584e90fdcb6c021319b315148d1373d408cfc388c494f1ab */
const fd_bn254_fp_t fd_bn254_const_frob_gamma2_mont[5] = {
  {{ 0xca8d800500fa1bf2, 0xf0c5d61468b39769, 0x0e201271ad0d4418, 0x04290f65bad856e6, }}, /* gamma_2,1 */
  {{ 0x3350c88e13e80b9c, 0x7dce557cdb5e56b9, 0x6001b4b8b615564a, 0x2682e617020217e0, }}, /* gamma_2,2 */
  {{ 0x68c3488912edefaa, 0x8d087f6872aabf4f, 0x51e1a24709081231, 0x2259d6b14729c0fa, }}, /* gamma_2,3 */
  {{ 0x71930c11d782e155, 0xa6bb947cffbe3323, 0xaa303344d4741444, 0x2c3b3f0d26594943, }}, /* gamma_2,4 */
  {{ 0x08cfc388c494f1ab, 0x19b315148d1373d4, 0x584e90fdcb6c0213, 0x09e1685bdf2f8849, }}, /* gamma_2,5 */
};

/* fd_bn254_fp2_pow computes r = a ^ b in Fp2. */
fd_bn254_fp2_t *
fd_bn254_fp2_pow( fd_bn254_fp2_t * restrict r,
                  fd_bn254_fp2_t const *    a,
                  fd_uint256_t   const *    b ) {
  fd_bn254_fp2_set_one( r );
  if( fd_uint256_is_zero( b ) ) return r; /* x^0 = 1 */

  /* There must be a bit set, as b>0, so if we reach i==0, it must be set. */
  int i = 255;
  while( !fd_uint256_bit( b, i ) ) i--;

  for( ; i>=0; i--) {
    fd_bn254_fp2_sqr( r, r );
    if( fd_uint256_bit( b, i ) ) {
      fd_bn254_fp2_mul( r, r, a );
    }
  }
  return r;
}

fd_bn254_fp12_t *
fd_bn254_fp12_mul( fd_bn254_fp12_t * r,
                   fd_bn254_fp12_t const * a,
                   fd_bn254_fp12_t const * b ) {
  /* https://eprint.iacr.org/2010/354, Alg. 20 */
  fd_bn254_fp6_t const * a0 = &a->el[0];
  fd_bn254_fp6_t const * a1 = &a->el[1];
  fd_bn254_fp6_t const * b0 = &b->el[0];
  fd_bn254_fp6_t const * b1 = &b->el[1];
  fd_bn254_fp6_t * r0 = &r->el[0];
  fd_bn254_fp6_t * r1 = &r->el[1];
  fd_bn254_fp6_t a0b0[1], a1b1[1], sa[1], sb[1];

  /* not lazy for the same reasons as fd_bn254_fp6_mul */
  fd_bn254_fp6_add( sa, a0, a1 );
  fd_bn254_fp6_add( sb, b0, b1 );

  fd_bn254_fp6_mul( a0b0, a0, b0 );
  fd_bn254_fp6_mul( a1b1, a1, b1 );
  fd_bn254_fp6_mul( r1, sa, sb );

  fd_bn254_fp6_sub( r1, r1, a0b0 );
  fd_bn254_fp6_sub( r1, r1, a1b1 );

  fd_bn254_fp6_mul_by_gamma( a1b1, a1b1 );
  fd_bn254_fp6_add( r0, a0b0, a1b1 );
  return r;
}

fd_bn254_fp12_t *
fd_bn254_fp12_inv( fd_bn254_fp12_t * r,
                   fd_bn254_fp12_t const * a ) {
  /* https://eprint.iacr.org/2010/354, Alg. 23 */
  fd_bn254_fp6_t t0[1], t1[1];
  fd_bn254_fp6_sqr( t0, &a->el[0] );
  fd_bn254_fp6_sqr( t1, &a->el[1] );
  fd_bn254_fp6_mul_by_gamma( t1, t1 );
  fd_bn254_fp6_sub( t0, t0, t1 );
  fd_bn254_fp6_inv( t1, t0 );
  fd_bn254_fp6_mul( &r->el[0], &a->el[0], t1 );
  fd_bn254_fp6_mul( &r->el[1], &a->el[1], t1 );
  fd_bn254_fp6_neg( &r->el[1], &r->el[1] );
  return r;
}
