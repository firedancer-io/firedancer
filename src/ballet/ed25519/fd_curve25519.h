#ifndef HEADER_fd_src_ballet_ed25519_fd_curve25519_h
#define HEADER_fd_src_ballet_ed25519_fd_curve25519_h

/* fd_curve25519.h provides the public Curve25519 API.

   Most operations in this API should be assumed to take a variable
   amount of time depending on inputs.  (And thus should not be exposed
   to secret data).

   Const time operations are made explicit, see fd_curve25519_secure.c */

#if FD_HAS_AVX512
#include "avx512/fd_curve25519.h"
#else
#include "ref/fd_curve25519.h"
#endif

/* curve constants. these are imported from table/fd_curve25519_table_{arch}.c.
   they are (re)defined here to avoid breaking compilation when the table needs
   to be rebuilt. */
static const fd_ed25519_point_t fd_ed25519_base_point[1];
static const fd_ed25519_point_t fd_ed25519_base_point_wnaf_table[128];
static const fd_ed25519_point_t fd_ed25519_base_point_const_time_table[32][8];

FD_PROTOTYPES_BEGIN

/* fd_ed25519_point_add computes r = a + b, and returns r.
   formulas are complete, i.e. it can be a == b.
   Cost: 9mul */
fd_ed25519_point_t *
fd_ed25519_point_add( fd_ed25519_point_t *       r,
                      fd_ed25519_point_t const * a,
                      fd_ed25519_point_t const * b );

/* fd_ed25519_point_dbln computes r = 2^n a, and returns r.
   More efficient than n fd_ed25519_point_add. */
fd_ed25519_point_t *
fd_ed25519_point_dbln( fd_ed25519_point_t *       r,
                       fd_ed25519_point_t const * a,
                       int const                  n );

/* fd_ed25519_point_sub computes r = a - b, and returns r.
   formulas are complete, i.e. it can be a == b.
   Cost: 9mul */
fd_ed25519_point_t *
fd_ed25519_point_sub( fd_ed25519_point_t *       r,
                      fd_ed25519_point_t const * a,
                      fd_ed25519_point_t const * b );

/* fd_ed25519_point_set sets r = 0 (point at infinity). */
fd_ed25519_point_t *
fd_ed25519_point_set_zero( fd_ed25519_point_t * r );

/* fd_ed25519_point_set_zero_precomputed sets r = 0 (point at infinity). */
fd_ed25519_point_t *
fd_ed25519_point_set_zero_precomputed( fd_ed25519_point_t * r );

/* fd_ed25519_point_set sets r = a. */
fd_ed25519_point_t *
fd_ed25519_point_set( fd_ed25519_point_t *       r,
                      fd_ed25519_point_t const * a );

/* fd_ed25519_point_from sets r = (x : y : z : t). */
fd_ed25519_point_t *
fd_ed25519_point_from( fd_ed25519_point_t * r,
                       fd_f25519_t const *  x,
                       fd_f25519_t const *  y,
                       fd_f25519_t const *  z,
                       fd_f25519_t const *  t );

/* fd_ed25519_point_sub sets r = -a. */
fd_ed25519_point_t *
fd_ed25519_point_neg( fd_ed25519_point_t *       r,
                      fd_ed25519_point_t const * a );

/* fd_ed25519_point_is_zero returns 1 if a == 0 (point at infinity), 0 otherwise. */
int
fd_ed25519_point_is_zero( fd_ed25519_point_t const * a );

/* fd_ed25519_point_is_small_order returns 1 if a has small order (order <= 8), 0 otherwise. */
FD_25519_INLINE int
fd_ed25519_point_is_small_order( fd_ed25519_point_t const * a ) {
  fd_ed25519_point_t r[1];
  fd_ed25519_point_dbln( r, a, 3 );
  return fd_ed25519_point_is_zero( r ); /* it should be sufficient to check r->X == 0 */
}

/* fd_ed25519_point_eq returns 1 if a == b, 0 otherwise. */
int
fd_ed25519_point_eq( fd_ed25519_point_t const * a,
                     fd_ed25519_point_t const * b );

/* fd_ed25519_point_eq returns 1 if a == b, 0 otherwise.
   b is a point with Z==1, e.g. a decompressed point. */
int
fd_ed25519_point_eq_z1( fd_ed25519_point_t const * a,
                        fd_ed25519_point_t const * b ); /* b.Z == 1, e.g. a decompressed point */

/* fd_ed25519_scalar_validate is an alias of fd_curve25519_scalar_validate
   It checks whether the given Ed25519 scalar n matches the canonical byte
   representation.  Not constant time and thus should not be exposed to secrets.
   Returns s if canonical, NULL otherwise. */

FD_25519_INLINE uchar const *
fd_ed25519_scalar_validate( uchar const n[ static 32 ] ) {
  return fd_curve25519_scalar_validate( n );
}

/* fd_ed25519_scalar_mul computes r = n * a, and returns r.
   n is a scalar. */
fd_ed25519_point_t *
fd_ed25519_scalar_mul( fd_ed25519_point_t *       r,
                       uchar const                n[ static 32 ],
                       fd_ed25519_point_t const * a );

/* fd_ed25519_scalar_mul_base_const_time computes r = n * P, and returns r.
   n is a scalar. P is the base point.
   Note: const time implementation, safe to use with n secret. */
fd_ed25519_point_t *
fd_ed25519_scalar_mul_base_const_time( fd_ed25519_point_t * r,
                                       uchar const          n[ static 32 ] ); /* can be a secret */

/* fd_ed25519_scalar_mul computes r = n1 * a + n2 * P, and returns r.
   n1, n2 are scalars. P is the base point. */
fd_ed25519_point_t *
fd_ed25519_double_scalar_mul_base( fd_ed25519_point_t *       r,
                                   uchar const                n1[ static 32 ],
                                   fd_ed25519_point_t const * a,
                                   uchar const                n2[ static 32 ] );

/* fd_ed25519_multi_scalar_mul computes r = n0 * a0 + n1 * a1 + ..., and returns r.
   n is a vector of sz scalars. a is a vector of sz points. */
fd_ed25519_point_t *
fd_ed25519_multi_scalar_mul( fd_ed25519_point_t *     r,
                             uchar const              n[], /* sz * 32 */
                             fd_ed25519_point_t const a[],  /* sz */
                             ulong const              sz );

/* fd_ed25519_multi_scalar_mul computes r = n0 * B + n1 * a1 + ..., and returns r.
   n is a vector of sz scalars. a is a vector of sz points.
   the first point is ignored, and the base point is used instead. */
fd_ed25519_point_t *
fd_ed25519_multi_scalar_mul_base( fd_ed25519_point_t *     r,
                                  uchar const              n[], /* sz * 32 */
                                  fd_ed25519_point_t const a[],  /* sz */
                                  ulong const              sz );

/* fd_ed25519_point_frombytes deserializes a 32-byte buffer buf into a
   point r, and returns r (on success, NULL on error).
   buf is in little endian form, according to RFC 8032.
   Cost: 1sqrt ~= 1inv ~= 250mul */
fd_ed25519_point_t *
fd_ed25519_point_frombytes( fd_ed25519_point_t * r,
                            uchar const          buf[ static 32 ] );

/* fd_ed25519_point_frombytes_2x deserializes 2x 32-byte buffers buf1, buf2
   resp. into points r1, r2, and returns r.
   buf1, buf2 are in little endian form, according to RFC 8032.
   It returns 0 on success, 1 or 2 on failure.
   Cost: 2sqrt (executed concurrently if possible) */
int
fd_ed25519_point_frombytes_2x( fd_ed25519_point_t * r1,
                               uchar const          buf1[ static 32 ],
                               fd_ed25519_point_t * r2,
                               uchar const          buf2[ static 32 ] );

/* fd_ed25519_point_validate checks if buf represents a valid compressed point,
   by attempting to decompress it.
   Use fd_ed25519_point_frombytes if the decompressed point is needed.
   It returns 1 if buf represents a valid point, 0 if not. */
FD_25519_INLINE int
fd_ed25519_point_validate(uchar const buf[ static 32 ] ) {
  fd_ed25519_point_t t[1];
  return !!fd_ed25519_point_frombytes( t, buf );
}

/* fd_ed25519_point_tobytes serializes a point a into
   a 32-byte buffer out, and returns out.
   out is in little endian form, according to RFC 8032. */
uchar *
fd_ed25519_point_tobytes( uchar                      out[ static 32 ],
                          fd_ed25519_point_t const * a );

/* fd_curve25519_into_precomputed transforms a point into
   precomputed table format, e.g. replaces T -> kT to save
   1mul in the dbl-and-add loop. */
void
fd_curve25519_into_precomputed( fd_ed25519_point_t * r );

/*
  Affine (only for offline building precomputation tables, can be slow)
*/
fd_ed25519_point_t *
fd_curve25519_affine_frombytes( fd_ed25519_point_t * r,
                                uchar const          x[ static 32 ],
                                uchar const          y[ static 32 ] );

fd_ed25519_point_t *
fd_curve25519_into_affine( fd_ed25519_point_t * r );

fd_ed25519_point_t *
fd_curve25519_affine_add( fd_ed25519_point_t *       r,
                          fd_ed25519_point_t const * a,
                          fd_ed25519_point_t const * b );

fd_ed25519_point_t *
fd_curve25519_affine_dbln( fd_ed25519_point_t *       r,
                           fd_ed25519_point_t const * a,
                           int const                  n );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_ballet_ed25519_fd_curve25519_h */
