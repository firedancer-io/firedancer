#ifndef HEADER_fd_src_ballet_bigint_uint256_h
#error "Do not include this directly; use fd_uint256.h"
#endif

/* Implementation of uint256 Montgomery mul.

   TODOs:
   - efficient sqr, Alg. 5 https://eprint.iacr.org/2022/1400
   - regular CIOS (the current impl *probably* won't work for secp256k1/r1)

   This is used under the hood to implement:
   - bn254 field arithmetic
   - bn254 scalar field arithmetic
   - (TODO) ed25519 scalar field arithmetic
   - (TODO) secp256k1 field and scalar arithmetic
   - (TODO) secp256r1 field and scalar arithmetic
   - ...
 */

#define INLINE static inline __attribute__((always_inline))

#ifdef FD_USING_GCC
#define OPTIMIZE __attribute__((optimize("unroll-loops")))
#else
#define OPTIMIZE
#endif

/* Utility functions for fd_uint256_mul_mod_p.
   Implementation is based on uint128.
   The implementations WITHOUT uint128 are just for completeness, we
   should avoid using them (and, e.g., rely on fiat-crypto mul instead). */

#if FD_HAS_INT128

INLINE void
fd_ulong_vec_mul( ulong l[4], ulong h[4], ulong const a[4], ulong b ) {
  uint128 r0 = ((uint128)a[0]) * ((uint128)b);
  uint128 r1 = ((uint128)a[1]) * ((uint128)b);
  uint128 r2 = ((uint128)a[2]) * ((uint128)b);
  uint128 r3 = ((uint128)a[3]) * ((uint128)b);
  l[0] = (ulong)r0;  h[0] = (ulong)(r0 >> 64);
  l[1] = (ulong)r1;  h[1] = (ulong)(r1 >> 64);
  l[2] = (ulong)r2;  h[2] = (ulong)(r2 >> 64);
  l[3] = (ulong)r3;  h[3] = (ulong)(r3 >> 64);
}

INLINE void
fd_ulong_add_carry4( ulong *l, uchar *h, ulong a0, ulong a1, ulong a2, uchar a3 ) {
  uint128 r = ((uint128)a0) + ((uint128)a1) + ((uint128)a2) + ((uint128)a3);
  *l = (ulong)r;
  *h = (uchar)(r >> 64);
}

INLINE void
fd_ulong_sub_borrow( ulong *r, uchar *b, ulong a0, ulong a1, uchar bi ) {
  *b = (uchar)_subborrow_u64( bi, a0, a1, (unsigned long long *)r );
}

#else

INLINE void
fd_ulong_mul128( ulong * l, ulong * h, ulong const a, ulong const b ) {
    /* First calculate all of the cross products. */
    ulong lo_lo = (a & 0xFFFFFFFF) * (b & 0xFFFFFFFF);
    ulong hi_lo = (a >> 32)        * (b & 0xFFFFFFFF);
    ulong lo_hi = (a & 0xFFFFFFFF) * (b >> 32);
    ulong hi_hi = (a >> 32)        * (b >> 32);

    /* Now add the products together. These will never overflow. */
    ulong cross = (lo_lo >> 32) + (hi_lo & 0xFFFFFFFF) + lo_hi;
    ulong upper = (hi_lo >> 32) + (cross >> 32)        + hi_hi;

    *h = upper;
    *l = (cross << 32) | (lo_lo & 0xFFFFFFFF);
  }

INLINE void
fd_ulong_vec_mul( ulong l[4], ulong h[4], ulong const a[4], ulong b ) {
  fd_ulong_mul128( &l[0], &h[0], a[0], b );
  fd_ulong_mul128( &l[1], &h[1], a[1], b );
  fd_ulong_mul128( &l[2], &h[2], a[2], b );
  fd_ulong_mul128( &l[3], &h[3], a[3], b );
}

INLINE void
fd_ulong_add_carry4( ulong *l, uchar *h, ulong a0, ulong a1, ulong a2, uchar a3 ) {
  ulong r0 = a0 + a1;
  uchar c0 = r0 < a0;

  ulong r1 = a2 + a3;
  uchar c1 = r1 < a2;

  *l = r0 + r1;
  *h = (uchar)((*l < r0) + c0 + c1);
}

INLINE void
fd_ulong_sub_borrow( ulong *r, uchar *b, ulong a0, ulong a1, uchar bi ) {
  a1 += bi;
  *r = a0 - a1;
  *b = a0 < a1;
}

#endif

INLINE fd_uint256_t *
fd_uint256_add(fd_uint256_t *       r,
               fd_uint256_t const * a,
               fd_uint256_t const * b ) {
  uchar c0;
  fd_ulong_add_carry4( &r->limbs[0], &c0, a->limbs[0], b->limbs[0], 0, 0 );
  fd_ulong_add_carry4( &r->limbs[1], &c0, a->limbs[1], b->limbs[1], 0, c0 );
  fd_ulong_add_carry4( &r->limbs[2], &c0, a->limbs[2], b->limbs[2], 0, c0 );
  fd_ulong_add_carry4( &r->limbs[3], &c0, a->limbs[3], b->limbs[3], 0, c0 );
  return r;
}

/* fd_uint256_mul_mod_p computes r = a * b mod p, using the CIOS method.
   r, a, b are in Montgomery representation (p is not).

   This is an efficient implementation of CIOS that works when (circa) p < 2^255
   (precisely, p->limbs[3] < (2^64-1)/2 - 1).
   Alg. 2, https://eprint.iacr.org/2022/1400
   Code example, for bn254: https://github.com/Consensys/gnark-crypto/blob/v0.12.1/ecc/bn254/fp/element_ops_purego.go#L66

   In go lang, bits.Add64 has carry 0, 1.
   We allow the carry to be a uchar, so we can dp a single add chain after each mul.

   This function is intended to be wrapped into a fd_<field>_mul( r, a, b ).
   Experimentally we found that:
   1. We have to force inlining for this function, otherwise compilers tend to reuse
      the function, introducing overhead.
   2. In GCC, we have to force loop unrolling optimization *in the outer fd_<field>_mul()*
      function, otherwise performance degrades significantly.
      For this we added the macro FD_UINT256_FP_MUL_IMPL. */

INLINE fd_uint256_t *
fd_uint256_mul_mod_p( fd_uint256_t *       r,
                      fd_uint256_t const * a,
                      fd_uint256_t const * b,
                      fd_uint256_t const * p,
                      ulong const          p_inv ) {
  ulong FD_ALIGNED t[4] = { 0 };
  ulong FD_ALIGNED u[4];
  ulong FD_ALIGNED h[4];
  ulong FD_ALIGNED l[4];
  uchar c0, c1;
  ulong tmp;
  ulong m;

  for( int i=0; i<4; i++ ) {
    fd_ulong_vec_mul( l, u, a->limbs, b->limbs[i] );
    fd_ulong_add_carry4( &t[0], &c0, t[0], l[0], 0, 0 );
    fd_ulong_add_carry4( &t[1], &c0, t[1], l[1], u[0], c0 );
    fd_ulong_add_carry4( &t[2], &c0, t[2], l[2], u[1], c0 );
    fd_ulong_add_carry4( &t[3], &c0, t[3], l[3], u[2], c0 );

    m = t[0] * p_inv;

    fd_ulong_vec_mul( l, h, p->limbs, m );
    fd_ulong_add_carry4( &tmp,  &c1, t[0], l[0], 0, 0 );
    fd_ulong_add_carry4( &t[0], &c1, t[1], l[1], h[0], c1 );
    fd_ulong_add_carry4( &t[1], &c1, t[2], l[2], h[1], c1 );
    fd_ulong_add_carry4( &t[2], &c1, t[3], l[3], h[2], c1 );
    t[3] = u[3] + h[3] + c0 + c1;
  }

  r->limbs[0] = t[0];
  r->limbs[1] = t[1];
  r->limbs[2] = t[2];
  r->limbs[3] = t[3];

  if( fd_uint256_cmp( r, p ) >= 0 ) {
    uchar b = 0;
    fd_ulong_sub_borrow( &r->limbs[0], &b, r->limbs[0], p->limbs[0], b );
    fd_ulong_sub_borrow( &r->limbs[1], &b, r->limbs[1], p->limbs[1], b );
    fd_ulong_sub_borrow( &r->limbs[2], &b, r->limbs[2], p->limbs[2], b );
    fd_ulong_sub_borrow( &r->limbs[3], &b, r->limbs[3], p->limbs[3], b );
  }
  return r;
}

/* FD_UINT256_FP_MUL_IMPL macro to properly implement Fp mul based on
   fd_uint256_mul_mod_p().
   In GCC we need to explicitly force loop unroll. */
#define FD_UINT256_FP_MUL_IMPL(fp, p, p_inv)          \
  static inline fp ## _t * OPTIMIZE                   \
  fp ## _mul( fp ## _t * r,                           \
              fp ## _t const * a,                     \
              fp ## _t const * b ) {                  \
    return fd_uint256_mul_mod_p( r, a, b, p, p_inv ); \
  }
