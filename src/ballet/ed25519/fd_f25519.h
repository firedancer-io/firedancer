#ifndef HEADER_fd_src_ballet_ed25519_fd_f25519_h
#define HEADER_fd_src_ballet_ed25519_fd_f25519_h

/* fd_f25519.h provides the public field API for the base field of curve25519.

   Most operations in this API should be assumed to take a variable amount
   of time depending on inputs, and thus should not be exposed to secret data.

   Constant-time operations are made explicit. */

#include "../fd_ballet_base.h"
#include "../../util/rng/fd_rng.h"

#define FD_25519_INLINE static inline

/* fd_f25519_t is the type of a field element, i.e. an integer
   mod p = 2^255 - 19.
   it's internal representation (and alignment) depends on the
   backend: ref, avx, avx512. */

#if FD_HAS_AVX512
#include "avx512/fd_f25519.h"
#else
#include "ref/fd_f25519.h"
#endif

/* field constants. these are imported from table/fd_f25519_table_{arch}.c.
   they are (re)defined here to avoid breaking compilation when the table needs
   to be rebuilt. */
static const fd_f25519_t fd_f25519_zero[1];
static const fd_f25519_t fd_f25519_one[1];
static const fd_f25519_t fd_f25519_minus_one[1];
static const fd_f25519_t fd_f25519_two[1];
static const fd_f25519_t fd_f25519_nine[1];
static const fd_f25519_t fd_f25519_k[1];
static const fd_f25519_t fd_f25519_minus_k[1];
static const fd_f25519_t fd_f25519_d[1];
static const fd_f25519_t fd_f25519_sqrtm1[1];
static const fd_f25519_t fd_f25519_invsqrt_a_minus_d[1];
static const fd_f25519_t fd_f25519_one_minus_d_sq[1];
static const fd_f25519_t fd_f25519_d_minus_one_sq[1];
static const fd_f25519_t fd_f25519_sqrt_ad_minus_one[1];

FD_PROTOTYPES_BEGIN

/* fd_f25519_mul computes r = a * b, and returns r. */
fd_f25519_t *
fd_f25519_mul( fd_f25519_t *       r,
               fd_f25519_t const * a,
               fd_f25519_t const * b );

/* fd_f25519_sqr computes r = a^2, and returns r. */
fd_f25519_t *
fd_f25519_sqr( fd_f25519_t *       r,
               fd_f25519_t const * a );

/* fd_f25519_add computes r = a + b, and returns r. */
fd_f25519_t *
fd_f25519_add( fd_f25519_t *       r,
               fd_f25519_t const * a,
               fd_f25519_t const * b );

/* fd_f25519_add computes r = a - b, and returns r. */
fd_f25519_t *
fd_f25519_sub( fd_f25519_t *       r,
               fd_f25519_t const * a,
               fd_f25519_t const * b );

/* fd_f25519_add_nr computes r = a + b, and returns r.
   Note: this does NOT reduce the result mod p.
   It can be used before mul, sqr. */
fd_f25519_t *
fd_f25519_add_nr( fd_f25519_t * r,
                  fd_f25519_t const * a,
                  fd_f25519_t const * b );

/* fd_f25519_sub_nr computes r = a - b, and returns r.
   Note: this does NOT reduce the result mod p.
   It can be used before mul, sqr. */
fd_f25519_t *
fd_f25519_sub_nr( fd_f25519_t * r,
                  fd_f25519_t const * a,
                  fd_f25519_t const * b );

/* fd_f25519_add computes r = -a, and returns r. */
fd_f25519_t *
fd_f25519_neg( fd_f25519_t *       r,
               fd_f25519_t const * a );

/* fd_f25519_mul_121666 computes r = a * k, k=121666, and returns r. */
fd_f25519_t *
fd_f25519_mul_121666( fd_f25519_t *       r,
                      fd_f25519_t const * a );

/* fd_f25519_frombytes deserializes a 32-byte buffer buf into a
   fd_f25519_t element r, and returns r.
   buf is in little endian form, according to RFC 8032. */
fd_f25519_t *
fd_f25519_frombytes( fd_f25519_t * r,
                     uchar const   buf[ 32 ] );

/* fd_f25519_tobytes serializes a fd_f25519_t element a into
   a 32-byte buffer out, and returns out.
   out is in little endian form, according to RFC 8032. */
uchar *
fd_f25519_tobytes( uchar               out[ 32 ],
                   fd_f25519_t const * a );

/* fd_f25519_set copies r = a, and returns r. */
fd_f25519_t *
fd_f25519_set( fd_f25519_t *       r,
               fd_f25519_t const * a );

/* fd_f25519_is_zero returns 1 if a == 0, 0 otherwise. */
int
fd_f25519_is_zero( fd_f25519_t const * a );

/* fd_f25519_if sets r = a0 if cond, else r = a1, equivalent to:
   r = cond ? a0 : a1.
   Note: this is constant time. */
fd_f25519_t *
fd_f25519_if( fd_f25519_t *       r,
              int const           cond, /* 0, 1 */
              fd_f25519_t const * a0,
              fd_f25519_t const * a1 );

/* fd_f25519_rng generates a random fd_f25519_t element.
   Note: insecure, for tests only. */
fd_f25519_t *
fd_f25519_rng_unsafe( fd_f25519_t * r,
                      fd_rng_t *    rng );

/*
 * Derived
 */

/* fd_f25519_eq returns 1 if a == b, 0 otherwise. */
FD_25519_INLINE int
fd_f25519_eq( fd_f25519_t const * a,
              fd_f25519_t const * b ) {
  fd_f25519_t r[1];
  fd_f25519_sub( r, a, b );
  return fd_f25519_is_zero( r );
}

/* fd_f25519_is_nonzero returns 1 (true) if a != 0, 0 if a == 0. */
FD_25519_INLINE int
fd_f25519_is_nonzero( fd_f25519_t const * a ) {
  return !fd_f25519_is_zero( a );
}

/* fd_f25519_sgn returns the sign of a (lsb). */
FD_25519_INLINE int
fd_f25519_sgn( fd_f25519_t const * a ) {
  //TODO: make it faster (unless inlining already optimizes out unnecessary code)
  uchar buf[32];
  fd_f25519_tobytes( buf, a );
  return buf[0] & 1;
}

/* fd_f25519_abs sets r = |a|. */
FD_25519_INLINE fd_f25519_t *
fd_f25519_abs( fd_f25519_t *       r,
               fd_f25519_t const * a ) {
  fd_f25519_t neg_a[1];
  fd_f25519_neg( neg_a, a );
  return fd_f25519_if( r, fd_f25519_sgn(a), neg_a, a );
}

/* fd_f25519_abs sets r = -|a|. */
FD_25519_INLINE fd_f25519_t *
fd_f25519_neg_abs( fd_f25519_t *       r,
                   fd_f25519_t const * a ) {
  fd_f25519_t neg_a[1];
  fd_f25519_neg( neg_a, a );
  return fd_f25519_if( r, fd_f25519_sgn(a), a, neg_a );
}

/*
 * Inv & Sqrt
 */

/* fd_f25519_inv computes r = 1/a, and returns r. */
fd_f25519_t *
fd_f25519_inv( fd_f25519_t *       r,
               fd_f25519_t const * a );

/* fd_f25519_pow22523 computes r = a^(2^252-3), and returns r. */
fd_f25519_t *
fd_f25519_pow22523( fd_f25519_t *       r,
                    fd_f25519_t const * a );

/* fd_f25519_sqrt_ratio computes r = (u * v^3) * (u * v^7)^((p-5)/8),
   returns 0 on success, 1 on failure. */
int
fd_f25519_sqrt_ratio( fd_f25519_t *       r,
                      fd_f25519_t const * u,
                      fd_f25519_t const * v );

/* fd_f25519_sqrt_ratio computes r = 1/sqrt(v),
   returns 0 on success, 1 on failure. */
FD_25519_INLINE int
fd_f25519_inv_sqrt( fd_f25519_t *       r,
                    fd_f25519_t const * v ) {
  return fd_f25519_sqrt_ratio( r, fd_f25519_one, v );
}

/*
 * Vectorized
 */

/* fd_f25519_muln computes r_i = a_i * b_i */
void
fd_f25519_mul2( fd_f25519_t * r1, fd_f25519_t const * a1, fd_f25519_t const * b1,
                fd_f25519_t * r2, fd_f25519_t const * a2, fd_f25519_t const * b2 );

void
fd_f25519_mul3( fd_f25519_t * r1, fd_f25519_t const * a1, fd_f25519_t const * b1,
                fd_f25519_t * r2, fd_f25519_t const * a2, fd_f25519_t const * b2,
                fd_f25519_t * r3, fd_f25519_t const * a3, fd_f25519_t const * b3 );

void
fd_f25519_mul4( fd_f25519_t * r1, fd_f25519_t const * a1, fd_f25519_t const * b1,
                fd_f25519_t * r2, fd_f25519_t const * a2, fd_f25519_t const * b2,
                fd_f25519_t * r3, fd_f25519_t const * a3, fd_f25519_t const * b3,
                fd_f25519_t * r4, fd_f25519_t const * a4, fd_f25519_t const * b4 );

/* fd_f25519_sqrn computes r_i = a_i^2 */
void
fd_f25519_sqr2( fd_f25519_t * r1, fd_f25519_t const * a1,
                fd_f25519_t * r2, fd_f25519_t const * a2 );

void
fd_f25519_sqr3( fd_f25519_t * r1, fd_f25519_t const * a1,
                fd_f25519_t * r2, fd_f25519_t const * a2,
                fd_f25519_t * r3, fd_f25519_t const * a3 );

void
fd_f25519_sqr4( fd_f25519_t * r1, fd_f25519_t const * a1,
                fd_f25519_t * r2, fd_f25519_t const * a2,
                fd_f25519_t * r3, fd_f25519_t const * a3,
                fd_f25519_t * r4, fd_f25519_t const * a4 );

/* fd_f25519_pow22523 computes r = a^(2^252-3), and returns r. */
fd_f25519_t *
fd_f25519_pow22523_2( fd_f25519_t * r1, fd_f25519_t const * a1,
                      fd_f25519_t * r2, fd_f25519_t const * a2 );

/* fd_f25519_sqrt_ratio computes r = (u * v^3) * (u * v^7)^((p-5)/8),
   returns 0 on success, 1 on failure. */
int
fd_f25519_sqrt_ratio2( fd_f25519_t * r1, fd_f25519_t const * u1, fd_f25519_t const * v1,
                       fd_f25519_t * r2, fd_f25519_t const * u2, fd_f25519_t const * v2 );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_ed25519_fd_f25519_h */
