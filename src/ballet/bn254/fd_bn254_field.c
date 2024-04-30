#include "./fd_bn254.h"
#include "../fiat-crypto/bn254_64.c"

/* Fp = base field */

#define FLAG_INF  ((uchar)(1 << 6))
#define FLAG_NEG  ((uchar)(1 << 7))
#define FLAG_MASK 0x3F

/* const 0. */
const fd_bn254_fp_t fd_bn254_const_zero[1] = {{{
  0x0UL, 0x0UL, 0x0UL, 0x0UL,
}}};

/* const p, used to validate a field element. NOT Montgomery.
   0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47 */
const fd_bn254_fp_t fd_bn254_const_p[1] = {{{
  0x3c208c16d87cfd47, 0x97816a916871ca8d, 0xb85045b68181585d, 0x30644e72e131a029,
}}};

/* const 1/p for CIOS mul */
static const ulong fd_bn254_const_p_inv = 0x87D20782E4866389UL;

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

/* const (p-3)/4, used to calculate sqrt() in Fp. bigint (NOT Montgomery)
   0x0c19139cb84c680a6e14116da060561765e05aa45a1c72a34f082305b61f3f51 */
const fd_uint256_t fd_bn254_const_sqrt_exp[1] = {{{
  0x4f082305b61f3f51, 0x65e05aa45a1c72a3, 0x6e14116da0605617, 0x0c19139cb84c680a,
}}};

static inline int
fd_bn254_fp_is_neg_nm( fd_bn254_fp_t * x ) {
  return fd_uint256_cmp( x, fd_bn254_const_p_minus_one_half ) > 0;
}

static inline fd_bn254_fp_t *
fd_bn254_fp_frombytes_be_nm( fd_bn254_fp_t * r,
                             uchar const     buf[32],
                             int *           is_inf,
                             int *           is_neg ) {
  /* Flags (optional) */
  if( is_inf != NULL /* && is_neg != NULL */ ) {
    *is_inf = !!(buf[0] & FLAG_INF);
    *is_neg = !!(buf[0] & FLAG_NEG);
    /* If both flags are set (bit 6, 7), return error.
       https://github.com/arkworks-rs/algebra/blob/v0.4.2/ec/src/models/short_weierstrass/serialization_flags.rs#L75 */
    if( FD_UNLIKELY( *is_inf && *is_neg ) ) {
      return NULL;
    }
  }

  fd_memcpy( r, buf, 32 );
  fd_uint256_bswap( r, r );
  //FIXME: add differential test, I think the mask should only apply if the flags are expected
  if( is_inf != NULL ) r->buf[31] &= FLAG_MASK;

  /* Field element */
  if( FD_UNLIKELY( fd_uint256_cmp( r, fd_bn254_const_p ) >= 0 ) ) {
    return NULL;
  }
  return r;
}

static inline uchar *
fd_bn254_fp_tobytes_be_nm( uchar           buf[32],
                           fd_bn254_fp_t * a ) {
  fd_uint256_bswap( a, a );
  fd_memcpy( buf, a, 32 );
  return buf;
}

static inline int
fd_bn254_fp_eq( fd_bn254_fp_t const * r,
                fd_bn254_fp_t const * a ) {
  return fd_uint256_eq( r, a );
}

static inline fd_bn254_fp_t *
fd_bn254_fp_from_mont( fd_bn254_fp_t * r,
                       fd_bn254_fp_t const * a ) {
  fiat_bn254_from_montgomery( r->limbs, a->limbs );
  return r;
}

static inline fd_bn254_fp_t *
fd_bn254_fp_to_mont( fd_bn254_fp_t * r,
                     fd_bn254_fp_t const * a ) {
  fiat_bn254_to_montgomery( r->limbs, a->limbs );
  return r;
}

static inline fd_bn254_fp_t *
fd_bn254_fp_neg_nm( fd_bn254_fp_t * r,
                    fd_bn254_fp_t const * a ) {
  /* compute p-a */
  for( ulong i=0, cy=0; i<4; i++ ) {
    ulong p = fd_bn254_const_p->limbs[i];
    ulong b = a->limbs[i];
    b += cy;
    cy = (b < cy);
    cy += (p < b);
    r->limbs[i] = p - b;
  }
  return r;
}

static inline fd_bn254_fp_t *
fd_bn254_fp_set( fd_bn254_fp_t * r,
                 fd_bn254_fp_t const * a ) {
  r->limbs[0] = a->limbs[0];
  r->limbs[1] = a->limbs[1];
  r->limbs[2] = a->limbs[2];
  r->limbs[3] = a->limbs[3];
  return r;
}

static inline fd_bn254_fp_t *
fd_bn254_fp_add( fd_bn254_fp_t * r,
                 fd_bn254_fp_t const * a,
                 fd_bn254_fp_t const * b ) {
  fiat_bn254_add( r->limbs, a->limbs, b->limbs );
  return r;
}

static inline fd_bn254_fp_t *
fd_bn254_fp_sub( fd_bn254_fp_t * r,
                 fd_bn254_fp_t const * a,
                 fd_bn254_fp_t const * b ) {
  fiat_bn254_sub( r->limbs, a->limbs, b->limbs );
  return r;
}

static inline fd_bn254_fp_t *
fd_bn254_fp_neg( fd_bn254_fp_t * r,
                 fd_bn254_fp_t const * a ) {
  fiat_bn254_opp( r->limbs, a->limbs );
  return r;
}

static inline fd_bn254_fp_t *
fd_bn254_fp_halve( fd_bn254_fp_t * r,
                   fd_bn254_fp_t const * a ) {
  int is_odd = r->limbs[0] & 0x1;
  fd_uint256_add( r, a, is_odd ? fd_bn254_const_p : fd_bn254_const_zero );
  r->limbs[0] = (r->limbs[0] >> 1) | (r->limbs[1] << 63);
  r->limbs[1] = (r->limbs[1] >> 1) | (r->limbs[2] << 63);
  r->limbs[2] = (r->limbs[2] >> 1) | (r->limbs[3] << 63);
  r->limbs[3] = (r->limbs[3] >> 1);
  return r;
}

FD_UINT256_FP_MUL_IMPL(fd_bn254_fp, fd_bn254_const_p, fd_bn254_const_p_inv)

static inline fd_bn254_fp_t *
fd_bn254_fp_sqr( fd_bn254_fp_t * r,
                 fd_bn254_fp_t const * a ) {
  return fd_bn254_fp_mul( r, a, a );
}

fd_bn254_fp_t *
fd_bn254_fp_pow( fd_bn254_fp_t * restrict r,
                 fd_bn254_fp_t const *    a,
                 fd_uint256_t const *     b ) {
  fd_bn254_fp_set_one( r );

  int i = 255;
  while( !fd_uint256_bit( b, i) ) i--;
  for( ; i>=0; i--) {
    fd_bn254_fp_sqr( r, r );
    if( fd_uint256_bit( b, i ) ) fd_bn254_fp_mul( r, r, a );
  }
  return r;
}

static inline fd_bn254_fp_t *
fd_bn254_fp_inv( fd_bn254_fp_t * r,
                  fd_bn254_fp_t const * a ) {
  fd_uint256_t p_minus_2[1];
  fd_bn254_fp_set( p_minus_2, fd_bn254_const_p );
  p_minus_2->limbs[0] = p_minus_2->limbs[0] - 2UL;
  return fd_bn254_fp_pow( r, a, p_minus_2 );
}

static inline fd_bn254_fp_t *
fd_bn254_fp_sqrt( fd_bn254_fp_t * r,
                  fd_bn254_fp_t const * a ) {
  /* Alg. 2, https://eprint.iacr.org/2012/685 */

  fd_bn254_fp_t a0[1], a1[1];

  fd_bn254_fp_pow( a1, a, fd_bn254_const_sqrt_exp );

  fd_bn254_fp_sqr( a0, a1 );
  fd_bn254_fp_mul( a0, a0, a );
  if( FD_UNLIKELY( fd_bn254_fp_eq( a0, fd_bn254_const_p_minus_one_mont ) ) ) {
    return NULL;
  }

  fd_bn254_fp_mul( r, a1, a );
  return r;
}
