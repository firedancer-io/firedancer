#include "./fd_bn254.h"

/* Extension Fields Fp2, Fp6, Fp12.

   Mostly based on https://eprint.iacr.org/2010/354, Appendix A.
   See also, as a reference implementation:
   https://github.com/Consensys/gnark-crypto/tree/v0.12.1/ecc/bn254/internal/fptower

   Elements are in Montgomery form, unless otherwise specified. */

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

/* Fp2 */

static inline fd_bn254_fp2_t *
fd_bn254_fp2_frombytes_be_nm( fd_bn254_fp2_t * r,
                              uchar const      buf[64],
                              int *            is_inf,
                              int *            is_neg ) {
  /* validate fp2.el[0] without flags */
  if( FD_UNLIKELY( !fd_bn254_fp_frombytes_be_nm( &r->el[0], &buf[32], NULL, NULL ) ) ) {
    return NULL;
  }
  /* validate fp2.el[1] with flags */
  if( FD_UNLIKELY( !fd_bn254_fp_frombytes_be_nm( &r->el[1], &buf[0], is_inf, is_neg ) ) ) {
    return NULL;
  }
  return r;
}

static inline uchar *
fd_bn254_fp2_tobytes_be_nm( uchar                  buf[64],
                            fd_bn254_fp2_t * const a ) {
  fd_bn254_fp_tobytes_be_nm( &buf[ 0], &a->el[1] );
  fd_bn254_fp_tobytes_be_nm( &buf[32], &a->el[0] );
  return buf;
}

/* fd_bn254_fp2_is_neg_nm checks wheather x < 0 in Fp2.
   Note: x is NON Montgomery.
   Returns 1 if x < 0, 0 otherwise. */
static inline int
fd_bn254_fp2_is_neg_nm( fd_bn254_fp2_t * x ) {
  return fd_bn254_fp_is_neg_nm( &x->el[1] );
}

/* fd_bn254_fp2_is_minus_one checks wheather a == -1 in Fp2.
   Returns 1 if a==-1, 0 otherwise. */
static inline int
fd_bn254_fp2_is_minus_one( fd_bn254_fp2_t const * a ) {
  return fd_uint256_eq( &a->el[0], fd_bn254_const_p_minus_one_mont )
      && fd_uint256_eq( &a->el[1], fd_bn254_const_zero );
}

/* fd_bn254_fp2_eq checks wheather a == b in Fp2.
   Returns 1 if a == b, 0 otherwise. */
static inline int
fd_bn254_fp2_eq( fd_bn254_fp2_t const * a,
                 fd_bn254_fp2_t const * b ) {
  return fd_bn254_fp_eq( &a->el[0], &b->el[0] )
      && fd_bn254_fp_eq( &a->el[1], &b->el[1] );
}

/* fd_bn254_fp2_set sets r = a. */
static inline fd_bn254_fp2_t *
fd_bn254_fp2_set( fd_bn254_fp2_t * r,
                  fd_bn254_fp2_t const * a ) {
  fd_bn254_fp_set( &r->el[0], &a->el[0] );
  fd_bn254_fp_set( &r->el[1], &a->el[1] );
  return r;
}

/* fd_bn254_fp2_from_mont sets r = a, coverting into Mongomery form. */
static inline fd_bn254_fp2_t *
fd_bn254_fp2_from_mont( fd_bn254_fp2_t * r,
                        fd_bn254_fp2_t const * a ) {
  fd_bn254_fp_from_mont( &r->el[0], &a->el[0] );
  fd_bn254_fp_from_mont( &r->el[1], &a->el[1] );
  return r;
}

/* fd_bn254_fp2_to_mont sets r = a, coverting into NON Mongomery form. */
static inline fd_bn254_fp2_t *
fd_bn254_fp2_to_mont( fd_bn254_fp2_t * r,
                      fd_bn254_fp2_t const * a ) {
  fd_bn254_fp_to_mont( &r->el[0], &a->el[0] );
  fd_bn254_fp_to_mont( &r->el[1], &a->el[1] );
  return r;
}

/* fd_bn254_fp2_neg_nm sets r = -x in Fp2.
   Note: x is NON Montgomery. */
static inline fd_bn254_fp2_t *
fd_bn254_fp2_neg_nm( fd_bn254_fp2_t * r,
                     fd_bn254_fp2_t const * x ) {
  fd_bn254_fp_neg_nm( &r->el[0], &x->el[0] );
  fd_bn254_fp_neg_nm( &r->el[1], &x->el[1] );
  return r;
}

/* fd_bn254_fp2_neg sets r = -a in Fp2. */
static inline fd_bn254_fp2_t *
fd_bn254_fp2_neg( fd_bn254_fp2_t * r,
                  fd_bn254_fp2_t const * a ) {
  fd_bn254_fp_neg( &r->el[0], &a->el[0] );
  fd_bn254_fp_neg( &r->el[1], &a->el[1] );
  return r;
}

/* fd_bn254_fp2_neg sets r = a/2 in Fp2. */
static inline fd_bn254_fp2_t *
fd_bn254_fp2_halve( fd_bn254_fp2_t * r,
                    fd_bn254_fp2_t const * a ) {
  fd_bn254_fp_halve( &r->el[0], &a->el[0] );
  fd_bn254_fp_halve( &r->el[1], &a->el[1] );
  return r;
}

/* fd_bn254_fp2_add computes r = a + b in Fp2. */
static inline fd_bn254_fp2_t *
fd_bn254_fp2_add( fd_bn254_fp2_t * r,
                  fd_bn254_fp2_t const * a,
                  fd_bn254_fp2_t const * b ) {
  fd_bn254_fp_add( &r->el[0], &a->el[0], &b->el[0] );
  fd_bn254_fp_add( &r->el[1], &a->el[1], &b->el[1] );
  return r;
}

/* fd_bn254_fp2_sub computes r = a - b in Fp2. */
static inline fd_bn254_fp2_t *
fd_bn254_fp2_sub( fd_bn254_fp2_t * r,
                  fd_bn254_fp2_t const * a,
                  fd_bn254_fp2_t const * b ) {
  fd_bn254_fp_sub( &r->el[0], &a->el[0], &b->el[0] );
  fd_bn254_fp_sub( &r->el[1], &a->el[1], &b->el[1] );
  return r;
}

/* fd_bn254_fp2_conj computes r = conj(a) in Fp2.
   If a = a0 + a1*i, conj(a) = a0 - a1*i. */
static inline fd_bn254_fp2_t *
fd_bn254_fp2_conj( fd_bn254_fp2_t * r,
                   fd_bn254_fp2_t const * a ) {
  fd_bn254_fp_set( &r->el[0], &a->el[0] );
  fd_bn254_fp_neg( &r->el[1], &a->el[1] );
  return r;
}

/* fd_bn254_fp2_mul computes r = a * b in Fp2.
   Karatsuba mul + reduction given that i^2 = -1.
   Note: this can probably be optimized, see for ideas:
   https://eprint.iacr.org/2010/354 */
static inline fd_bn254_fp2_t *
fd_bn254_fp2_mul( fd_bn254_fp2_t * r,
                  fd_bn254_fp2_t const * a,
                  fd_bn254_fp2_t const * b ) {
  fd_bn254_fp_t const * a0 = &a->el[0];
  fd_bn254_fp_t const * a1 = &a->el[1];
  fd_bn254_fp_t const * b0 = &b->el[0];
  fd_bn254_fp_t const * b1 = &b->el[1];
  fd_bn254_fp_t * r0 = &r->el[0];
  fd_bn254_fp_t * r1 = &r->el[1];
  fd_bn254_fp_t a0b0[1], a1b1[1], sa[1], sb[1];

  fd_bn254_fp_add( sa, a0, a1 );
  fd_bn254_fp_add( sb, b0, b1 );

  fd_bn254_fp_mul( a0b0, a0, b0 );
  fd_bn254_fp_mul( a1b1, a1, b1 );
  fd_bn254_fp_mul( r1, sa, sb );

  fd_bn254_fp_sub( r0, a0b0, a1b1 ); /* i^2 = -1 */
  fd_bn254_fp_sub( r1, r1, a0b0 );
  fd_bn254_fp_sub( r1, r1, a1b1 );
  return r;
}

/* fd_bn254_fp2_mul computes r = a^2 in Fp2.
   https://eprint.iacr.org/2010/354, Alg. 3.
   This is done with 2mul in Fp, instead of 2sqr+1mul. */
static inline fd_bn254_fp2_t *
fd_bn254_fp2_sqr( fd_bn254_fp2_t * r,
                  fd_bn254_fp2_t const * a ) {
  fd_bn254_fp_t p[1], m[1];
  fd_bn254_fp_add( p, &a->el[0], &a->el[1] );
  fd_bn254_fp_sub( m, &a->el[0], &a->el[1] );
  /* r1 = 2 a0*a1 */
  fd_bn254_fp_mul( &r->el[1], &a->el[0], &a->el[1] );
  fd_bn254_fp_add( &r->el[1], &r->el[1], &r->el[1] );
  /* r0 = (a0-a1)*(a0+a1) */
  fd_bn254_fp_mul( &r->el[0], p, m );
  return r;
}

/* fd_bn254_fp2_mul_by_i computes r = a * i in Fp2. */
static inline fd_bn254_fp2_t *
fd_bn254_fp2_mul_by_i( fd_bn254_fp2_t * r,
                       fd_bn254_fp2_t const * a ) {
  fd_bn254_fp_t t[1];
  fd_bn254_fp_neg( t, &a->el[1] );
  fd_bn254_fp_set( &r->el[1], &a->el[0] );
  fd_bn254_fp_set( &r->el[0], t );
  return r;
}

/* fd_bn254_fp2_inv computes r = 1 / a in Fp2.
   https://eprint.iacr.org/2010/354, Alg. 8. */
static inline fd_bn254_fp2_t *
fd_bn254_fp2_inv( fd_bn254_fp2_t * r,
                  FD_PARAM_UNUSED fd_bn254_fp2_t const * a ) {
  fd_bn254_fp_t t0[1], t1[1];
  fd_bn254_fp_sqr( t0, &a->el[0] );
  fd_bn254_fp_sqr( t1, &a->el[1] );
  fd_bn254_fp_add( t0, t0, t1 );
  fd_bn254_fp_inv( t1, t0 );
  fd_bn254_fp_mul( &r->el[0], &a->el[0], t1 );
  fd_bn254_fp_mul( &r->el[1], &a->el[1], t1 );
  fd_bn254_fp_neg( &r->el[1], &r->el[1] );
  return r;
}

/* fd_bn254_fp2_pow computes r = a ^ b in Fp2. */
fd_bn254_fp2_t *
fd_bn254_fp2_pow( fd_bn254_fp2_t * restrict r,
                  fd_bn254_fp2_t const *    a,
                  fd_uint256_t const *      b ) {
  fd_bn254_fp2_set_one( r );

  int i = 255;
  while( !fd_uint256_bit( b, i) ) i--;
  for( ; i>=0; i--) {
    fd_bn254_fp2_sqr( r, r );
    if( fd_uint256_bit( b, i ) ) fd_bn254_fp2_mul( r, r, a );
  }
  return r;
}

/* fd_bn254_fp2_sqrt computes r = sqrt(a) in Fp2.
   https://eprint.iacr.org/2012/685, Alg. 9.
   Note: r is one of the two sqrt, the other is -r. This function
   can return either the positive or negative one, no assumptions/promises.
   Returns r if a is a square (sqrt exists), or NULL otherwise. */
static inline fd_bn254_fp2_t *
fd_bn254_fp2_sqrt( fd_bn254_fp2_t * r,
                   fd_bn254_fp2_t const * a ) {
  fd_bn254_fp2_t a0[1], a1[1], alpha[1], x0[1];

  fd_bn254_fp2_pow( a1, a, fd_bn254_const_sqrt_exp );

  fd_bn254_fp2_sqr( alpha, a1 );
  fd_bn254_fp2_mul( alpha, alpha, a );

  fd_bn254_fp2_conj( a0, alpha );
  fd_bn254_fp2_mul( a0, a0, alpha );

  if( FD_UNLIKELY( fd_bn254_fp2_is_minus_one( a0 ) ) ) {
    return NULL;
  }

  fd_bn254_fp2_mul( x0, a1, a );
  if( fd_bn254_fp2_is_minus_one( alpha ) ) {
    // FD_LOG_WARNING(( "alpha == -1" ));
    fd_bn254_fp2_mul_by_i( r, x0 );
  } else {
    // FD_LOG_WARNING(( "alpha != -1" ));
    fd_bn254_fp2_set_one( a1 );
    fd_bn254_fp2_add( a0, alpha, a1 );                           /* 1 + alpha */
    fd_bn254_fp2_pow( a1, a0, fd_bn254_const_p_minus_one_half ); /* b */
    fd_bn254_fp2_mul( r, a1, x0 );
  }
  return r;
}

/* fd_bn254_fp2_mul_by_xi computes r = a * (9+i) in Fp2.
   xi = (9+i) is the const used to build Fp6.
   Note: this can probably be optimized (less reductions mod p). */
static inline fd_bn254_fp2_t *
fd_bn254_fp2_mul_by_xi( fd_bn254_fp2_t * r,
                        fd_bn254_fp2_t const * a ) {
  /* xi = 9 + i
     r = (9*a0 - a1) + (9*a1 + a0) i */
  fd_bn254_fp_t r0[1], r1[1];

  fd_bn254_fp_add( r0, &a->el[0], &a->el[0] );
  fd_bn254_fp_add( r0, r0, r0 );
  fd_bn254_fp_add( r0, r0, r0 );
  fd_bn254_fp_add( r0, r0, &a->el[0] );
  fd_bn254_fp_sub( r0, r0, &a->el[1] );

  fd_bn254_fp_add( r1, &a->el[1], &a->el[1] );
  fd_bn254_fp_add( r1, r1, r1 );
  fd_bn254_fp_add( r1, r1, r1 );
  fd_bn254_fp_add( r1, r1, &a->el[1] );
  fd_bn254_fp_add( &r->el[1], r1, &a->el[0] );

  fd_bn254_fp_set( &r->el[0], r0 );
  return r;
}

/* Fp6 */

static inline fd_bn254_fp6_t *
fd_bn254_fp6_set( fd_bn254_fp6_t * r,
                  fd_bn254_fp6_t const * a ) {
  fd_bn254_fp2_set( &r->el[0], &a->el[0] );
  fd_bn254_fp2_set( &r->el[1], &a->el[1] );
  fd_bn254_fp2_set( &r->el[2], &a->el[2] );
  return r;
}

static inline fd_bn254_fp6_t *
fd_bn254_fp6_neg( fd_bn254_fp6_t * r,
                     fd_bn254_fp6_t const * a ) {
  fd_bn254_fp2_neg( &r->el[0], &a->el[0] );
  fd_bn254_fp2_neg( &r->el[1], &a->el[1] );
  fd_bn254_fp2_neg( &r->el[2], &a->el[2] );
  return r;
}

static inline fd_bn254_fp6_t *
fd_bn254_fp6_add( fd_bn254_fp6_t * r,
                  fd_bn254_fp6_t const * a,
                  fd_bn254_fp6_t const * b ) {
  fd_bn254_fp2_add( &r->el[0], &a->el[0], &b->el[0] );
  fd_bn254_fp2_add( &r->el[1], &a->el[1], &b->el[1] );
  fd_bn254_fp2_add( &r->el[2], &a->el[2], &b->el[2] );
  return r;
}

static inline fd_bn254_fp6_t *
fd_bn254_fp6_sub( fd_bn254_fp6_t * r,
                  fd_bn254_fp6_t const * a,
                  fd_bn254_fp6_t const * b ) {
  fd_bn254_fp2_sub( &r->el[0], &a->el[0], &b->el[0] );
  fd_bn254_fp2_sub( &r->el[1], &a->el[1], &b->el[1] );
  fd_bn254_fp2_sub( &r->el[2], &a->el[2], &b->el[2] );
  return r;
}

static inline fd_bn254_fp6_t *
fd_bn254_fp6_mul_by_gamma( fd_bn254_fp6_t * r,
                           fd_bn254_fp6_t const * a ) {
  /* https://eprint.iacr.org/2010/354, Alg. 12 */
  fd_bn254_fp2_t t[1];
  fd_bn254_fp2_mul_by_xi( t, &a->el[2] );
  fd_bn254_fp2_set( &r->el[2], &a->el[1] );
  fd_bn254_fp2_set( &r->el[1], &a->el[0] );
  fd_bn254_fp2_set( &r->el[0], t );
  return r;
}

static inline fd_bn254_fp6_t *
fd_bn254_fp6_mul( fd_bn254_fp6_t * r,
                  fd_bn254_fp6_t const * a,
                  fd_bn254_fp6_t const * b ) {
  /* https://eprint.iacr.org/2010/354, Alg. 13 */
  fd_bn254_fp2_t const * a0 = &a->el[0];
  fd_bn254_fp2_t const * a1 = &a->el[1];
  fd_bn254_fp2_t const * a2 = &a->el[2];
  fd_bn254_fp2_t const * b0 = &b->el[0];
  fd_bn254_fp2_t const * b1 = &b->el[1];
  fd_bn254_fp2_t const * b2 = &b->el[2];
  fd_bn254_fp2_t a0b0[1], a1b1[1], a2b2[1];
  fd_bn254_fp2_t sa[1], sb[1];
  fd_bn254_fp2_t r0[1], r1[1], r2[1];

  fd_bn254_fp2_mul( a0b0, a0, b0 );
  fd_bn254_fp2_mul( a1b1, a1, b1 );
  fd_bn254_fp2_mul( a2b2, a2, b2 );

  fd_bn254_fp2_add( sa, a1, a2 );
  fd_bn254_fp2_add( sb, b1, b2 );
  fd_bn254_fp2_mul( r0, sa, sb );
  fd_bn254_fp2_sub( r0, r0, a1b1 );
  fd_bn254_fp2_sub( r0, r0, a2b2 );
  fd_bn254_fp2_mul_by_xi( r0, r0 );
  fd_bn254_fp2_add( r0, r0, a0b0 );

  fd_bn254_fp2_add( sa, a0, a2 );
  fd_bn254_fp2_add( sb, b0, b2 );
  fd_bn254_fp2_mul( r2, sa, sb );
  fd_bn254_fp2_sub( r2, r2, a0b0 );
  fd_bn254_fp2_sub( r2, r2, a2b2 );
  fd_bn254_fp2_add( r2, r2, a1b1 );

  fd_bn254_fp2_add( sa, a0, a1 );
  fd_bn254_fp2_add( sb, b0, b1 );
  fd_bn254_fp2_mul( r1, sa, sb );
  fd_bn254_fp2_sub( r1, r1, a0b0 );
  fd_bn254_fp2_sub( r1, r1, a1b1 );
  fd_bn254_fp2_mul_by_xi( a2b2, a2b2 );
  fd_bn254_fp2_add( r1, r1, a2b2 );

  fd_bn254_fp2_set( &r->el[0], r0 );
  fd_bn254_fp2_set( &r->el[1], r1 );
  fd_bn254_fp2_set( &r->el[2], r2 );
  return r;
}

static inline fd_bn254_fp6_t *
fd_bn254_fp6_sqr( fd_bn254_fp6_t * r,
                  fd_bn254_fp6_t const * a ) {
  /* https://eprint.iacr.org/2010/354, Alg. 16 */
  fd_bn254_fp2_t const * a0 = &a->el[0];
  fd_bn254_fp2_t const * a1 = &a->el[1];
  fd_bn254_fp2_t const * a2 = &a->el[2];
  fd_bn254_fp2_t c0[1], c1[1], c2[1];
  fd_bn254_fp2_t c3[1], c4[1], c5[1];

  fd_bn254_fp2_mul( c4, a0, a1 );
  fd_bn254_fp2_add( c4, c4, c4 );
  fd_bn254_fp2_sqr( c5, a2 );

  fd_bn254_fp2_sub( c2, c4, c5 );
  fd_bn254_fp2_mul_by_xi( c5, c5 );
  fd_bn254_fp2_add( c1, c4, c5 );

  fd_bn254_fp2_sqr( c3, a0 );
  fd_bn254_fp2_sub( c4, a0, a1 );
  fd_bn254_fp2_add( c4, c4, a2 );

  fd_bn254_fp2_mul( c5, a1, a2 );
  fd_bn254_fp2_add( c5, c5, c5 );
  fd_bn254_fp2_sqr( c4, c4 );

  fd_bn254_fp2_add( c2, c2, c4 );
  fd_bn254_fp2_add( c2, c2, c5 );
  fd_bn254_fp2_sub( c2, c2, c3 );
  fd_bn254_fp2_mul_by_xi( c5, c5 );
  fd_bn254_fp2_add( c0, c3, c5 );

  fd_bn254_fp2_set( &r->el[0], c0 );
  fd_bn254_fp2_set( &r->el[1], c1 );
  fd_bn254_fp2_set( &r->el[2], c2 );
  return r;
}

static inline fd_bn254_fp6_t *
fd_bn254_fp6_inv( fd_bn254_fp6_t * r,
                  fd_bn254_fp6_t const * a ) {
  /* https://eprint.iacr.org/2010/354, Alg. 17 */
  fd_bn254_fp2_t t[6];
  fd_bn254_fp2_sqr( &t[0], &a->el[0] );
  fd_bn254_fp2_sqr( &t[1], &a->el[1] );
  fd_bn254_fp2_sqr( &t[2], &a->el[2] );
  fd_bn254_fp2_mul( &t[3], &a->el[0], &a->el[1] );
  fd_bn254_fp2_mul( &t[4], &a->el[0], &a->el[2] );
  fd_bn254_fp2_mul( &t[5], &a->el[1], &a->el[2] );
  /* t0 := c0 = t0 - xi * t5 */
  fd_bn254_fp2_mul_by_xi( &t[5], &t[5] );
  fd_bn254_fp2_sub( &t[0], &t[0], &t[5] );
  /* t2 := c1 = xi * t2 - t3 */
  fd_bn254_fp2_mul_by_xi( &t[2], &t[2] );
  fd_bn254_fp2_sub( &t[2], &t[2], &t[3] );
  /* t1 := c2 = t1 - t4 (note: paper says t1*t4, but that's a misprint) */
  fd_bn254_fp2_sub( &t[1], &t[1], &t[4] );
  /* t3 := t6 = a0 * c0 */
  fd_bn254_fp2_mul( &t[3], &a->el[0], &t[0] );
  /* t3 := t6 = t6 + (xi * a2 * c1 =: t4) */
  fd_bn254_fp2_mul( &t[4], &a->el[2], &t[2] );
  fd_bn254_fp2_mul_by_xi( &t[4], &t[4] );
  fd_bn254_fp2_add( &t[3], &t[3], &t[4] );
  /* t3 := t6 = t6 + (xi * a2 * c1 =: t4) */
  fd_bn254_fp2_mul( &t[5], &a->el[1], &t[1] );
  fd_bn254_fp2_mul_by_xi( &t[5], &t[5] );
  fd_bn254_fp2_add( &t[3], &t[3], &t[5] );
  /* t4 := t6^-1 */
  fd_bn254_fp2_inv( &t[4], &t[3] );

  fd_bn254_fp2_mul( &r->el[0], &t[0], &t[4] );
  fd_bn254_fp2_mul( &r->el[1], &t[2], &t[4] );
  fd_bn254_fp2_mul( &r->el[2], &t[1], &t[4] );
  return r;
}

/* Fp12 */

static inline fd_bn254_fp12_t *
fd_bn254_fp12_conj( fd_bn254_fp12_t * r,
                    fd_bn254_fp12_t const * a ) {
  fd_bn254_fp6_set( &r->el[0], &a->el[0] );
  fd_bn254_fp6_neg( &r->el[1], &a->el[1] );
  return r;
}

static inline fd_bn254_fp12_t *
fd_bn254_fp12_add( fd_bn254_fp12_t * r,
                   fd_bn254_fp12_t const * a,
                   fd_bn254_fp12_t const * b ) {
  fd_bn254_fp6_add( &r->el[0], &a->el[0], &b->el[0] );
  fd_bn254_fp6_add( &r->el[1], &a->el[1], &b->el[1] );
  return r;
}

static inline fd_bn254_fp12_t *
fd_bn254_fp12_sub( fd_bn254_fp12_t * r,
                   fd_bn254_fp12_t const * a,
                   fd_bn254_fp12_t const * b ) {
  fd_bn254_fp6_sub( &r->el[0], &a->el[0], &b->el[0] );
  fd_bn254_fp6_sub( &r->el[1], &a->el[1], &b->el[1] );
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

static inline fd_bn254_fp12_t *
fd_bn254_fp12_sqr( fd_bn254_fp12_t * r,
                        fd_bn254_fp12_t const * a ) {
  /* https://eprint.iacr.org/2010/354, Alg. 22. */
  fd_bn254_fp6_t c0[1], c2[1], c3[1];
  fd_bn254_fp6_sub( c0, &a->el[0], &a->el[1] );
  fd_bn254_fp6_mul_by_gamma( c3, &a->el[1] );
  fd_bn254_fp6_sub( c3, &a->el[0], c3 );
  fd_bn254_fp6_mul( c2, &a->el[0], &a->el[1] );
  fd_bn254_fp6_mul( c0, c0, c3 );
  fd_bn254_fp6_add( c0, c0, c2 );
  fd_bn254_fp6_add( &r->el[1], c2, c2 );
  fd_bn254_fp6_mul_by_gamma( &r->el[0], c2 );
  fd_bn254_fp6_add( &r->el[0], &r->el[0], c0 );
  return r;
}

static inline fd_bn254_fp12_t *
fd_bn254_fp12_sqr_fast( fd_bn254_fp12_t * r,
                        fd_bn254_fp12_t const * a ) {
  /* Cyclotomic sqr, https://eprint.iacr.org/2009/565, Sec. 3.2.
     Variant of https://eprint.iacr.org/2010/354, Alg. 24.
     This works when a^(p^6+1)=1, e.g. during pairing final exp. */
  fd_bn254_fp2_t t[9];

  fd_bn254_fp2_sqr( &t[0], &a->el[1].el[1] );
  fd_bn254_fp2_sqr( &t[1], &a->el[0].el[0] );
  fd_bn254_fp2_add( &t[6], &a->el[1].el[1], &a->el[0].el[0] );
  fd_bn254_fp2_sqr( &t[6], &t[6] );
  fd_bn254_fp2_sub( &t[6], &t[6], &t[0] );
  fd_bn254_fp2_sub( &t[6], &t[6], &t[1] );

  fd_bn254_fp2_sqr( &t[2], &a->el[0].el[2] );
  fd_bn254_fp2_sqr( &t[3], &a->el[1].el[0] );
  fd_bn254_fp2_add( &t[7], &a->el[0].el[2], &a->el[1].el[0] );
  fd_bn254_fp2_sqr( &t[7], &t[7] );
  fd_bn254_fp2_sub( &t[7], &t[7], &t[2] );
  fd_bn254_fp2_sub( &t[7], &t[7], &t[3] );

  fd_bn254_fp2_sqr( &t[4], &a->el[1].el[2] );
  fd_bn254_fp2_sqr( &t[5], &a->el[0].el[1] );
  fd_bn254_fp2_add( &t[8], &a->el[1].el[2], &a->el[0].el[1] );
  fd_bn254_fp2_sqr( &t[8], &t[8] );
  fd_bn254_fp2_sub( &t[8], &t[8], &t[4] );
  fd_bn254_fp2_sub( &t[8], &t[8], &t[5] );
  fd_bn254_fp2_mul_by_xi( &t[8], &t[8] );

  fd_bn254_fp2_mul_by_xi( &t[0], &t[0] );
  fd_bn254_fp2_add( &t[0], &t[0], &t[1] );
  fd_bn254_fp2_mul_by_xi( &t[2], &t[2] );
  fd_bn254_fp2_add( &t[2], &t[2], &t[3] );
  fd_bn254_fp2_mul_by_xi( &t[4], &t[4] );
  fd_bn254_fp2_add( &t[4], &t[4], &t[5] );

  fd_bn254_fp2_sub( &r->el[0].el[0], &t[0], &a->el[0].el[0] );
  fd_bn254_fp2_add( &r->el[0].el[0], &r->el[0].el[0], &r->el[0].el[0] );
  fd_bn254_fp2_add( &r->el[0].el[0], &r->el[0].el[0], &t[0] );
  fd_bn254_fp2_sub( &r->el[0].el[1], &t[2], &a->el[0].el[1] );
  fd_bn254_fp2_add( &r->el[0].el[1], &r->el[0].el[1], &r->el[0].el[1] );
  fd_bn254_fp2_add( &r->el[0].el[1], &r->el[0].el[1], &t[2] );
  fd_bn254_fp2_sub( &r->el[0].el[2], &t[4], &a->el[0].el[2] );
  fd_bn254_fp2_add( &r->el[0].el[2], &r->el[0].el[2], &r->el[0].el[2] );
  fd_bn254_fp2_add( &r->el[0].el[2], &r->el[0].el[2], &t[4] );

  fd_bn254_fp2_add( &r->el[1].el[0], &t[8], &a->el[1].el[0] );
  fd_bn254_fp2_add( &r->el[1].el[0], &r->el[1].el[0], &r->el[1].el[0] );
  fd_bn254_fp2_add( &r->el[1].el[0], &r->el[1].el[0], &t[8] );
  fd_bn254_fp2_add( &r->el[1].el[1], &t[6], &a->el[1].el[1] );
  fd_bn254_fp2_add( &r->el[1].el[1], &r->el[1].el[1], &r->el[1].el[1] );
  fd_bn254_fp2_add( &r->el[1].el[1], &r->el[1].el[1], &t[6] );
  fd_bn254_fp2_add( &r->el[1].el[2], &t[7], &a->el[1].el[2] );
  fd_bn254_fp2_add( &r->el[1].el[2], &r->el[1].el[2], &r->el[1].el[2] );
  fd_bn254_fp2_add( &r->el[1].el[2], &r->el[1].el[2], &t[7] );
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

static inline fd_bn254_fp12_t *
fd_bn254_fp12_frob( fd_bn254_fp12_t * r,
                    fd_bn254_fp12_t const * a ) {
  /* https://eprint.iacr.org/2010/354, Alg. 28 */
  fd_bn254_fp2_t t[5];

  /* conj(g0) */
  fd_bn254_fp2_conj( &r->el[0].el[0], &a->el[0].el[0] );
  fd_bn254_fp2_conj( &t[0], &a->el[0].el[1] );
  fd_bn254_fp2_conj( &t[1], &a->el[0].el[2] );
  fd_bn254_fp2_conj( &t[2], &a->el[1].el[0] );
  fd_bn254_fp2_conj( &t[3], &a->el[1].el[1] );
  fd_bn254_fp2_conj( &t[4], &a->el[1].el[2] );

  /* conj(g1) * gamma_1,2 */
  fd_bn254_fp2_mul( &r->el[0].el[1], &t[0], &fd_bn254_const_frob_gamma1_mont[1] );

  /* conj(g2) * gamma_1,4 */
  fd_bn254_fp2_mul( &r->el[0].el[2], &t[1], &fd_bn254_const_frob_gamma1_mont[3] );

  /* conj(h0) * gamma_1,1 */
  fd_bn254_fp2_mul( &r->el[1].el[0], &t[2], &fd_bn254_const_frob_gamma1_mont[0] );

  /* conj(h1) * gamma_1,3 */
  fd_bn254_fp2_mul( &r->el[1].el[1], &t[3], &fd_bn254_const_frob_gamma1_mont[2] );

  /* conj(h2) * gamma_1,5 */
  fd_bn254_fp2_mul( &r->el[1].el[2], &t[4], &fd_bn254_const_frob_gamma1_mont[4] );
  return r;
}

static inline fd_bn254_fp12_t *
fd_bn254_fp12_frob2( fd_bn254_fp12_t * r,
                     fd_bn254_fp12_t const * a ) {
  /* https://eprint.iacr.org/2010/354, Alg. 29 */

  /* g0 */
  fd_bn254_fp2_set( &r->el[0].el[0], &a->el[0].el[0] );

  /* g1 * gamma_2,2 */
  fd_bn254_fp_mul( &r->el[0].el[1].el[0], &a->el[0].el[1].el[0], &fd_bn254_const_frob_gamma2_mont[1] );
  fd_bn254_fp_mul( &r->el[0].el[1].el[1], &a->el[0].el[1].el[1], &fd_bn254_const_frob_gamma2_mont[1] );

  /* g2 * gamma_2,4 */
  fd_bn254_fp_mul( &r->el[0].el[2].el[0], &a->el[0].el[2].el[0], &fd_bn254_const_frob_gamma2_mont[3] );
  fd_bn254_fp_mul( &r->el[0].el[2].el[1], &a->el[0].el[2].el[1], &fd_bn254_const_frob_gamma2_mont[3] );

  /* h0 * gamma_2,1 */
  fd_bn254_fp_mul( &r->el[1].el[0].el[0], &a->el[1].el[0].el[0], &fd_bn254_const_frob_gamma2_mont[0] );
  fd_bn254_fp_mul( &r->el[1].el[0].el[1], &a->el[1].el[0].el[1], &fd_bn254_const_frob_gamma2_mont[0] );

  /* h1 * gamma_2,3 */
  fd_bn254_fp_mul( &r->el[1].el[1].el[0], &a->el[1].el[1].el[0], &fd_bn254_const_frob_gamma2_mont[2] );
  fd_bn254_fp_mul( &r->el[1].el[1].el[1], &a->el[1].el[1].el[1], &fd_bn254_const_frob_gamma2_mont[2] );

  /* h2 * gamma_2,5 */
  fd_bn254_fp_mul( &r->el[1].el[2].el[0], &a->el[1].el[2].el[0], &fd_bn254_const_frob_gamma2_mont[4] );
  fd_bn254_fp_mul( &r->el[1].el[2].el[1], &a->el[1].el[2].el[1], &fd_bn254_const_frob_gamma2_mont[4] );
  return r;
}
