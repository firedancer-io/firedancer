#ifndef HEADER_fd_src_ballet_bn254_fd_bn254_field_inl_h
#define HEADER_fd_src_ballet_bn254_fd_bn254_field_inl_h

/* Shared static-inline Fp/Fp2/Fp6/Fp12 ops for the bn254 TUs.
   Do not include outside src/ballet/bn254.
   Heavy helpers are marked noinline: they get one local copy per TU
   (same codegen as the old amalgamated build) instead of being inlined
   into every caller, which would bloat compile time and code size. */

#include "./fd_bn254_internal.h"
#include "../fiat-crypto/bn254_64.c"
#if FD_HAS_S2NBIGNUM
#include <s2n-bignum.h>
#endif
#if FD_HAS_X86
#if defined(__GNUC__) && !defined(__clang__)
#include <x86gprintrin.h> /* adc/sbb only; ~200x smaller than immintrin.h */
#else
#include <immintrin.h>
#endif
#endif

/* Fp = base field */

#define FLAG_INF  ((uchar)(1 << 6))
#define FLAG_NEG  ((uchar)(1 << 7))
#define FLAG_MASK 0x3F

/* Consts defined in fd_bn254_field.c */
extern const fd_bn254_fp_t     fd_bn254_const_zero            [1];
extern const fd_bn254_fp_t     fd_bn254_const_p               [1];
extern const fd_bn254_scalar_t fd_bn254_const_x               [1];
extern const fd_bn254_fp_t     fd_bn254_const_b_mont          [1];
extern const fd_bn254_fp_t     fd_bn254_const_p_minus_one_mont[1];
extern const fd_bn254_fp_t     fd_bn254_const_p_minus_one_half[1];
extern const fd_uint256_t      fd_bn254_const_sqrt_exp        [1];

/* Consts defined in fd_bn254_field_ext.c */
extern const fd_bn254_fp2_t fd_bn254_const_twist_b_mont    [1];
extern const fd_bn254_fp2_t fd_bn254_const_frob_gamma1_mont[5];
extern const fd_bn254_fp_t  fd_bn254_const_frob_gamma2_mont[5];

/* const 1/p for CIOS mul */
static const ulong fd_bn254_const_p_inv = 0x87D20782E4866389UL;

static inline int
fd_bn254_fp_is_neg_nm( fd_bn254_fp_t * x ) {
  return fd_uint256_cmp( x, fd_bn254_const_p_minus_one_half ) > 0;
}

static inline fd_bn254_fp_t *
fd_bn254_fp_frombytes_nm( fd_bn254_fp_t * r,
                          uchar const     buf[32],
                          int             big_endian,
                          int *           is_inf,
                          int *           is_neg ) {
  /* Flags (optional) */
  if( is_inf != NULL /* && is_neg != NULL */ ) {
    *is_inf = !!(buf[ big_endian ? 0 : 31 ] & FLAG_INF);
    *is_neg = !!(buf[ big_endian ? 0 : 31 ] & FLAG_NEG);
    /* If both flags are set (bit 6, 7), return error.
       https://github.com/arkworks-rs/algebra/blob/v0.4.2/ec/src/models/short_weierstrass/serialization_flags.rs#L75 */
    if( FD_UNLIKELY( *is_inf && *is_neg ) ) {
      return NULL;
    }
  }

  fd_memcpy( r, buf, 32 );
  if( FD_BIG_ENDIAN_LIKELY( big_endian ) ) {
    fd_uint256_bswap( r, r );
  }
  if( is_inf != NULL ) {
    r->buf[ 31 ] &= FLAG_MASK;
  }

  /* Field element */
  if( FD_UNLIKELY( fd_uint256_cmp( r, fd_bn254_const_p ) >= 0 ) ) {
    return NULL;
  }
  return r;
}

static inline uchar *
fd_bn254_fp_tobytes_nm( uchar           buf[32],
                        fd_bn254_fp_t * a,
                        int             big_endian ) {
  if( FD_BIG_ENDIAN_LIKELY( big_endian ) ) {
    fd_uint256_bswap( a, a );
  }
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
  if( FD_UNLIKELY( fd_bn254_fp_is_zero( a ) ) ) {
    return fd_bn254_fp_set_zero( r );
  }
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

/* r = a + b mod p, output in [0, p). */
INLINE fd_bn254_fp_t *
fd_bn254_fp_add( fd_bn254_fp_t * r,
                 fd_bn254_fp_t const * a,
                 fd_bn254_fp_t const * b ) {
  fiat_bn254_add( r->limbs, a->limbs, b->limbs );
  return r;
}

/* r = a + b, output in [0, 2p).
   Safe only if the result feeds into a multiplication, but should not
   be fed into fp_sub, fp_neg, fp_eq, frombytes, halve, etc. */
INLINE fd_bn254_fp_t *
fd_bn254_fp_add_lazy( fd_bn254_fp_t * r,
                      fd_bn254_fp_t const * a,
                      fd_bn254_fp_t const * b ) {
#if FD_HAS_X86
  unsigned long long t0, t1, t2, t3;
  uchar c = 0;
  c = (uchar)_addcarry_u64( c, (unsigned long long)a->limbs[0], (unsigned long long)b->limbs[0], &t0 );
  c = (uchar)_addcarry_u64( c, (unsigned long long)a->limbs[1], (unsigned long long)b->limbs[1], &t1 );
  c = (uchar)_addcarry_u64( c, (unsigned long long)a->limbs[2], (unsigned long long)b->limbs[2], &t2 );
  c = (uchar)_addcarry_u64( c, (unsigned long long)a->limbs[3], (unsigned long long)b->limbs[3], &t3 );
  (void)c; /* p < 2^254 so c is always 0 for a, b < 2p */
  r->limbs[0] = (ulong)t0;
  r->limbs[1] = (ulong)t1;
  r->limbs[2] = (ulong)t2;
  r->limbs[3] = (ulong)t3;
  return r;
#else
  /* We find no performance improvement on non-x86 targets, so we
     fallback to the original fp_add. */
  return fd_bn254_fp_add( r, a, b );
#endif
}

INLINE fd_bn254_fp_t *
fd_bn254_fp_sub( fd_bn254_fp_t * r,
                 fd_bn254_fp_t const * a,
                 fd_bn254_fp_t const * b ) {
  fiat_bn254_sub( r->limbs, a->limbs, b->limbs );
  return r;
}

INLINE fd_bn254_fp_t *
fd_bn254_fp_neg( fd_bn254_fp_t * r,
                 fd_bn254_fp_t const * a ) {
  fiat_bn254_opp( r->limbs, a->limbs );
  return r;
}

static inline fd_bn254_fp_t *
fd_bn254_fp_halve( fd_bn254_fp_t * r,
                   fd_bn254_fp_t const * a ) {
  int is_odd = a->limbs[0] & 0x1;
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

/* r = 1 / a mod p. a MUST not be 0. */
static inline fd_bn254_fp_t *
fd_bn254_fp_inv( fd_bn254_fp_t * r,
                  fd_bn254_fp_t const * a ) {
#if FD_HAS_S2NBIGNUM
  /* a is in montgomery form, giving a' = a*R mod p.
     bignum_modinv treats its inputs as canonical residues, so it computes:
      z = (a*R)^{-1} = a^{-1} * R^{-1}
     We can apply to_montgomery twice, each time multiplying by R, giving:
      r = a^{-1} * R^{-1} * R * R = a^{-1} * R = (a^{-1})' */
  ulong tmp[12];
  ulong z[4];
  bignum_modinv( 4, z, a->limbs, fd_bn254_const_p->limbs, tmp );
  fiat_bn254_to_montgomery( r->limbs, z );
  fiat_bn254_to_montgomery( r->limbs, r->limbs );
  return r;
#else
  fd_uint256_t p_minus_2[1];
  fd_bn254_fp_set( p_minus_2, fd_bn254_const_p );
  p_minus_2->limbs[0] -= 2UL;
  return fd_bn254_fp_pow( r, a, p_minus_2 );
#endif
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

/* Extension Fields Fp2, Fp6, Fp12.

   Mostly based on https://eprint.iacr.org/2010/354, Appendix A.
   See also, as a reference implementation:
   https://github.com/Consensys/gnark-crypto/tree/v0.12.1/ecc/bn254/internal/fptower

   Elements are in Montgomery form, unless otherwise specified. */

/* Fp2 */

static inline fd_bn254_fp2_t *
fd_bn254_fp2_frombytes_nm( fd_bn254_fp2_t * r,
                           uchar const      buf[64],
                           int              big_endian,
                           int *            is_inf,
                           int *            is_neg ) {
  /* validate fp2.el[0] without flags */
  if( FD_UNLIKELY( !fd_bn254_fp_frombytes_nm( &r->el[0], &buf[ big_endian ? 32 : 0 ], big_endian, NULL, NULL ) ) ) {
    return NULL;
  }
  /* validate fp2.el[1] with flags */
  if( FD_UNLIKELY( !fd_bn254_fp_frombytes_nm( &r->el[1], &buf[ big_endian ? 0 : 32 ], big_endian, is_inf, is_neg ) ) ) {
    return NULL;
  }
  return r;
}

static inline uchar *
fd_bn254_fp2_tobytes_nm( uchar                  buf[64],
                         fd_bn254_fp2_t * const a,
                         int                    big_endian ) {
  fd_bn254_fp_tobytes_nm( &buf[ 0], &a->el[ big_endian ? 1 : 0 ], big_endian );
  fd_bn254_fp_tobytes_nm( &buf[32], &a->el[ big_endian ? 0 : 1 ], big_endian );
  return buf;
}

/* fd_bn254_fp2_is_neg_nm checks whether x < 0 in Fp2.
   Note: x is NON Montgomery.
   Returns 1 if x < 0, 0 otherwise. */
static inline int
fd_bn254_fp2_is_neg_nm( fd_bn254_fp2_t * x ) {
  if( FD_UNLIKELY( fd_bn254_fp_is_zero( &x->el[1] ) ) ) {
    return fd_bn254_fp_is_neg_nm( &x->el[0] );
  }
  return fd_bn254_fp_is_neg_nm( &x->el[1] );
}

/* fd_bn254_fp2_is_minus_one checks whether a == -1 in Fp2.
   Returns 1 if a==-1, 0 otherwise. */
static inline int
fd_bn254_fp2_is_minus_one( fd_bn254_fp2_t const * a ) {
  return fd_uint256_eq( &a->el[0], fd_bn254_const_p_minus_one_mont )
      && fd_uint256_eq( &a->el[1], fd_bn254_const_zero );
}

/* fd_bn254_fp2_eq checks whether a == b in Fp2.
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

/* fd_bn254_fp2_from_mont sets r = a, coverting into NON Mongomery form. */
static inline fd_bn254_fp2_t *
fd_bn254_fp2_from_mont( fd_bn254_fp2_t * r,
                        fd_bn254_fp2_t const * a ) {
  fd_bn254_fp_from_mont( &r->el[0], &a->el[0] );
  fd_bn254_fp_from_mont( &r->el[1], &a->el[1] );
  return r;
}

/* fd_bn254_fp2_to_mont sets r = a, coverting into Mongomery form. */
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
static __attribute__((noinline,unused)) fd_bn254_fp2_t *
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
static __attribute__((noinline,unused)) fd_bn254_fp2_t *
fd_bn254_fp2_add( fd_bn254_fp2_t * r,
                  fd_bn254_fp2_t const * a,
                  fd_bn254_fp2_t const * b ) {
  fd_bn254_fp_add( &r->el[0], &a->el[0], &b->el[0] );
  fd_bn254_fp_add( &r->el[1], &a->el[1], &b->el[1] );
  return r;
}

/* fd_bn254_fp2_sub computes r = a - b in Fp2. */
static __attribute__((noinline,unused)) fd_bn254_fp2_t *
fd_bn254_fp2_sub( fd_bn254_fp2_t * r,
                  fd_bn254_fp2_t const * a,
                  fd_bn254_fp2_t const * b ) {
  fd_bn254_fp_sub( &r->el[0], &a->el[0], &b->el[0] );
  fd_bn254_fp_sub( &r->el[1], &a->el[1], &b->el[1] );
  return r;
}

/* fd_bn254_fp2_conj computes r = conj(a) in Fp2.
   If a = a0 + a1*i, conj(a) = a0 - a1*i. */
static __attribute__((noinline,unused)) fd_bn254_fp2_t *
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
static __attribute__((noinline,unused)) fd_bn254_fp2_t *
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

  /* sa, sb are lazy additions as they're only consumed by fp_mul */
  fd_bn254_fp_add_lazy( sa, a0, a1 );
  fd_bn254_fp_add_lazy( sb, b0, b1 );

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
static __attribute__((noinline,unused)) fd_bn254_fp2_t *
fd_bn254_fp2_sqr( fd_bn254_fp2_t * r,
                  fd_bn254_fp2_t const * a ) {
  fd_bn254_fp_t p[1], m[1];
  /* p is a lazy addition as it's only consumed by fp_mul */
  fd_bn254_fp_add_lazy( p, &a->el[0], &a->el[1] );
  fd_bn254_fp_sub     ( m, &a->el[0], &a->el[1] );
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
   a MUST not be 0.
   https://eprint.iacr.org/2010/354, Alg. 8. */
static __attribute__((noinline,unused)) fd_bn254_fp2_t *
fd_bn254_fp2_inv( fd_bn254_fp2_t * r,
                  fd_bn254_fp2_t const * a ) {
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

/* fd_bn254_fp2_sqrt computes r = sqrt(a) in Fp2.
   https://eprint.iacr.org/2012/685, Alg. 8.

   For bn254 the non-residue is i with i^2 = -1, so norm(c) = c0^2 + c1^2.
   This method costs us 2 fp_sqrt + 1 fp_inv + a few fp_mul/sqr.
   The method described in Alg. 9 is 2 fp2_pow, which is more expensive. */
static inline fd_bn254_fp2_t *
fd_bn254_fp2_sqrt( fd_bn254_fp2_t * r,
                   fd_bn254_fp2_t const * a ) {
  fd_bn254_fp_t const * c0 = &a->el[0];
  fd_bn254_fp_t const * c1 = &a->el[1];
  fd_bn254_fp_t norm[1], alpha[1], delta[1], tmp[1];
  fd_bn254_fp_t x[1], y[1], xinv[1];

  /* c1 == 0, sqrt reduces to Fp sqrt on c0 (or sqrt(-c0) shifted to imaginary). */
  if( FD_UNLIKELY( fd_bn254_fp_is_zero( c1 ) ) ) {
    if( fd_bn254_fp_sqrt( x, c0 ) ) {
      fd_bn254_fp_set( &r->el[0], x );
      fd_bn254_fp_set_zero( &r->el[1] );
      return r;
    }
    fd_bn254_fp_neg( y, c0 );
    if( !fd_bn254_fp_sqrt( y, y ) ) return NULL;
    fd_bn254_fp_set_zero( &r->el[0] );
    fd_bn254_fp_set( &r->el[1], y );
    return r;
  }

  /* norm = c0^2 + c1^2 */
  fd_bn254_fp_sqr( norm, c0 );
  fd_bn254_fp_sqr( tmp,  c1 );
  fd_bn254_fp_add( norm, norm, tmp );

  /* alpha = sqrt(norm); NULL means a is a non-square in Fp2. */
  if( !fd_bn254_fp_sqrt( alpha, norm ) ) return NULL;

  /* delta = (alpha + c0) / 2
     If delta is not a quadratic residue, use (c0 - alpha) / 2 instead.
     We test this by trying sqrt(delta) first. */
  fd_bn254_fp_add( delta, alpha, c0 );
  fd_bn254_fp_halve( delta, delta );

  if( !fd_bn254_fp_sqrt( x, delta ) ) {
    fd_bn254_fp_sub( delta, delta, alpha );
    if( !fd_bn254_fp_sqrt( x, delta ) ) return NULL;
  }

  /* y = c1 / (2x) = c1 * (1/x) / 2 */
  fd_bn254_fp_inv  ( xinv, x );
  fd_bn254_fp_mul  ( y, c1, xinv );
  fd_bn254_fp_halve( y, y );

  fd_bn254_fp_set( &r->el[0], x );
  fd_bn254_fp_set( &r->el[1], y );
  return r;
}

/* fd_bn254_fp2_mul_by_xi computes r = a * (9+i) in Fp2.
   xi = (9+i) is the const used to build Fp6.
   Note: this can probably be optimized (less reductions mod p). */
static __attribute__((noinline,unused)) fd_bn254_fp2_t *
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

static __attribute__((noinline,unused)) fd_bn254_fp6_t *
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

  /* fp2_mul has its own internal lazy additions, so we cannot compound
     here as it would push intermediate values past our [0, 2p) bound. */
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
  /* not lazy for the same reasons as fd_bn254_fp6_mul. */
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

/*
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
*/






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


#endif /* HEADER_fd_src_ballet_bn254_fd_bn254_field_inl_h */
