#ifndef HEADER_fd_src_ballet_bigint_fd_uint256_h
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

#if FD_HAS_X86
#include <x86intrin.h>
#endif

INLINE void
fd_ulong_sub_borrow(
    ulong * r,   /* out (r=a-b) */
    int *   b,   /* out borrow flag */
    ulong   a0,
    ulong   a1,
    int     bi   /* in borrow flag */
) {
# if FD_HAS_X86
  *b = (uchar)_subborrow_u64( (uchar)bi, a0, a1, (unsigned long long *)r );
# else
  a1 += !!bi;
  *r = a0 - a1;
  *b = a0 < a1;
# endif
}

#if FD_HAS_INT128

INLINE fd_uint256_t *
fd_uint256_add(fd_uint256_t *       r,
               fd_uint256_t const * a,
               fd_uint256_t const * b ) {
  uint128 s;
  uchar   c = 0;
  s = (uint128)a->limbs[0] + b->limbs[0];      r->limbs[0] = (ulong)s; c = (uchar)(s >> 64);
  s = (uint128)a->limbs[1] + b->limbs[1] + c;  r->limbs[1] = (ulong)s; c = (uchar)(s >> 64);
  s = (uint128)a->limbs[2] + b->limbs[2] + c;  r->limbs[2] = (ulong)s; c = (uchar)(s >> 64);
  s = (uint128)a->limbs[3] + b->limbs[3] + c;  r->limbs[3] = (ulong)s;
  return r;
}

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

#else

INLINE fd_uint256_t *
fd_uint256_add(fd_uint256_t *       r,
               fd_uint256_t const * a,
               fd_uint256_t const * b ) {
  ulong s;
  uchar c = 0, c2;
  s = a->limbs[0] + b->limbs[0];     c  = (uchar)(s < a->limbs[0]);                                r->limbs[0] = s;
  s = a->limbs[1] + b->limbs[1];     c2 = (uchar)(s < a->limbs[1]); s += c; c2 |= (uchar)(s < c);  r->limbs[1] = s; c = c2;
  s = a->limbs[2] + b->limbs[2];     c2 = (uchar)(s < a->limbs[2]); s += c; c2 |= (uchar)(s < c);  r->limbs[2] = s; c = c2;
  s = a->limbs[3] + b->limbs[3] + c; r->limbs[3] = s;
  return r;
}

INLINE void
fd_ulong_mul128( ulong * l, ulong * h, ulong const a, ulong const b ) {
  ulong lo_lo = (a & 0xFFFFFFFF) * (b & 0xFFFFFFFF);
  ulong hi_lo = (a >> 32)        * (b & 0xFFFFFFFF);
  ulong lo_hi = (a & 0xFFFFFFFF) * (b >> 32);
  ulong hi_hi = (a >> 32)        * (b >> 32);
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

#endif /* FD_HAS_INT128 */

#if FD_HAS_X86

INLINE fd_uint256_t *
fd_uint256_mul_mod_p( fd_uint256_t *       r,
                      fd_uint256_t const * a,
                      fd_uint256_t const * b,
                      fd_uint256_t const * p,
                      ulong const          p_inv ) {
  ulong t0, t1, t2, t3;
  ulong hi, lo, m, c0, zero;

  t0 = 0; t1 = 0; t2 = 0; t3 = 0;
  zero = 0;

  #define CIOS_ITER(BI, T0, T1, T2, T3, NT0, NT1, NT2, NT3)                       \
    /* Step 1: t += a * b[i] */                                                   \
    "movq " BI ", %%rdx\n\t"                                                      \
    "xorl %k[zero], %k[zero]\n\t"                                                 \
                                                                                  \
    "mulx %[a0], %[lo], %[hi]\n\t"                                                \
    "adcx %[lo], " T0 "\n\t"                                                      \
                                                                                  \
    "mulx %[a1], %[lo], %[c0]\n\t"                                                \
    "adox %[hi], " T1 "\n\t"                                                      \
    "adcx %[lo], " T1 "\n\t"                                                      \
                                                                                  \
    "mulx %[a2], %[lo], %[hi]\n\t"                                                \
    "adox %[c0], " T2 "\n\t"                                                      \
    "adcx %[lo], " T2 "\n\t"                                                      \
                                                                                  \
    "mulx %[a3], %[lo], %[c0]\n\t"                                                \
    "adox %[hi], " T3 "\n\t"                                                      \
    "adcx %[lo], " T3 "\n\t"                                                      \
                                                                                  \
    "adox %[zero], %[c0]\n\t"                                                     \
    "adcx %[zero], %[c0]\n\t"                                                     \
                                                                                  \
    /* Step 2: m = t[0] * p_inv */                                                \
    "movq " T0 ", %%rdx\n\t"                                                      \
    "imulq %[pinv], %%rdx\n\t"                                                    \
                                                                                  \
    "xorl %k[zero], %k[zero]\n\t"                                                 \
                                                                                  \
    "mulx %[p0], %[lo], %[hi]\n\t"                                                \
    "adcx " T0 ", %[lo]\n\t"                  /* lo += t0 (discarded) */          \
                                                                                  \
    "mulx %[p1], %[lo], %[m]\n\t"                                                 \
    "adox %[hi], " T1 "\n\t"                                                      \
    "adcx %[lo], " T1 "\n\t"                                                      \
    /* T1 is now the new t[0] = NT0 */                                            \
                                                                                  \
    "mulx %[p2], %[lo], %[hi]\n\t"                                                \
    "adox %[m],  " T2 "\n\t"                                                      \
    "adcx %[lo], " T2 "\n\t"                                                      \
    /* T2 is now the new t[1] = NT1 */                                            \
                                                                                  \
    "mulx %[p3], %[lo], %[m]\n\t"                                                 \
    "adox %[hi], " T3 "\n\t"                                                      \
    "adcx %[lo], " T3 "\n\t"                                                      \
    /* T3 is now the new t[2] = NT2 */                                            \
                                                                                  \
    "adox %[zero], %[m]\n\t"                                                      \
    "adcx %[zero], %[m]\n\t"                                                      \
    "addq %[m], %[c0]\n\t"                                                        \
    /* c0 is now the new t[3] = NT3 */

  #define CIOS_ITER_FINAL(T0)                                                     \
    "movq %[c0], " T0 "\n\t"

  __asm__ volatile (
    CIOS_ITER("%[b0]", "%[t0]","%[t1]","%[t2]","%[t3]",  "%[t1]","%[t2]","%[t3]","%[t0]")
    CIOS_ITER_FINAL("%[t0]")

    CIOS_ITER("%[b1]", "%[t1]","%[t2]","%[t3]","%[t0]",  "%[t2]","%[t3]","%[t0]","%[t1]")
    CIOS_ITER_FINAL("%[t1]")

    CIOS_ITER("%[b2]", "%[t2]","%[t3]","%[t0]","%[t1]",  "%[t3]","%[t0]","%[t1]","%[t2]")
    CIOS_ITER_FINAL("%[t2]")

    CIOS_ITER("%[b3]", "%[t3]","%[t0]","%[t1]","%[t2]",  "%[t0]","%[t1]","%[t2]","%[t3]")
    CIOS_ITER_FINAL("%[t3]")

    : [t0] "+&r" (t0), [t1] "+&r" (t1), [t2] "+&r" (t2), [t3] "+&r" (t3),
      [hi] "=&r" (hi), [lo] "=&r" (lo), [m] "=&r" (m), [c0] "=&r" (c0),
      [zero] "+&r" (zero)
    : [a0] "m" (a->limbs[0]), [a1] "m" (a->limbs[1]),
      [a2] "m" (a->limbs[2]), [a3] "m" (a->limbs[3]),
      [b0] "m" (b->limbs[0]), [b1] "m" (b->limbs[1]),
      [b2] "m" (b->limbs[2]), [b3] "m" (b->limbs[3]),
      [p0] "m" (p->limbs[0]), [p1] "m" (p->limbs[1]),
      [p2] "m" (p->limbs[2]), [p3] "m" (p->limbs[3]),
      [pinv] "r" (p_inv)
    : "rdx", "cc"
  );

  #undef CIOS_ITER
  #undef CIOS_ITER_FINAL

  {
    ulong s0, s1, s2, s3;
    __asm__ volatile (
      "movq %[t0], %[s0]\n\t"
      "subq %[p0], %[s0]\n\t"
      "movq %[t1], %[s1]\n\t"
      "sbbq %[p1], %[s1]\n\t"
      "movq %[t2], %[s2]\n\t"
      "sbbq %[p2], %[s2]\n\t"
      "movq %[t3], %[s3]\n\t"
      "sbbq %[p3], %[s3]\n\t"
      "cmovc %[t0], %[s0]\n\t"
      "cmovc %[t1], %[s1]\n\t"
      "cmovc %[t2], %[s2]\n\t"
      "cmovc %[t3], %[s3]\n\t"
      : [s0] "=&r" (s0), [s1] "=&r" (s1), [s2] "=&r" (s2), [s3] "=&r" (s3)
      : [t0] "r" (t0), [t1] "r" (t1), [t2] "r" (t2), [t3] "r" (t3),
        [p0] "m" (p->limbs[0]), [p1] "m" (p->limbs[1]),
        [p2] "m" (p->limbs[2]), [p3] "m" (p->limbs[3])
      : "cc"
    );
    r->limbs[0] = s0;
    r->limbs[1] = s1;
    r->limbs[2] = s2;
    r->limbs[3] = s3;
  }

  return r;
}

#else 

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

  /* Branchless conditional subtraction */
  int borrow = 0;
  ulong s0, s1, s2, s3;
  fd_ulong_sub_borrow( &s0, &borrow, r->limbs[0], p->limbs[0], borrow );
  fd_ulong_sub_borrow( &s1, &borrow, r->limbs[1], p->limbs[1], borrow );
  fd_ulong_sub_borrow( &s2, &borrow, r->limbs[2], p->limbs[2], borrow );
  fd_ulong_sub_borrow( &s3, &borrow, r->limbs[3], p->limbs[3], borrow );

  ulong mask = (ulong)( -(long)borrow );
  r->limbs[0] = (r->limbs[0] & mask) | (s0 & ~mask);
  r->limbs[1] = (r->limbs[1] & mask) | (s1 & ~mask);
  r->limbs[2] = (r->limbs[2] & mask) | (s2 & ~mask);
  r->limbs[3] = (r->limbs[3] & mask) | (s3 & ~mask);

  return r;
}

#endif /* FD_HAS_X86 */

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
