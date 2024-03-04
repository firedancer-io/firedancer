#ifndef HEADER_fd_src_ballet_ed25519_fd_curve25519_h
#error "Do not include this directly; use fd_curve25519.h"
#endif

/* fd_curve25519.h provides the public Curve25519 API.

   Most operations in this API should be assumed to take a variable
   amount of time depending on inputs.  (And thus should not be exposed
   to secret data).

   Const time operations are made explicit, see fd_curve25519_secure.c */

#include "../../fd_ballet_base.h"
#include "../fd_f25519.h"
#include "../fd_curve25519_scalar.h"

/* CURVE25519_PRECOMP_XY turns on/off the precomputation of (Y-X), (Y+X)
   in precomputation tables. */
#define CURVE25519_PRECOMP_XY 1

/* struct fd_curve25519_edwards (aka fd_curve25519_edwards_t) represents
   a point in Extended Twisted Edwards Coordinates.
   https://eprint.iacr.org/2008/522 */
struct fd_curve25519_edwards {
  fd_f25519_t X[1];
  fd_f25519_t Y[1];
  fd_f25519_t T[1];
  fd_f25519_t Z[1];
};
typedef struct fd_curve25519_edwards fd_curve25519_edwards_t;

typedef fd_curve25519_edwards_t fd_ed25519_point_t;
typedef fd_curve25519_edwards_t fd_ristretto255_point_t;

#include "../table/fd_curve25519_table_ref.c"

FD_PROTOTYPES_BEGIN

/* fd_ed25519_point_set sets r = 0 (point at infinity). */
FD_25519_INLINE fd_ed25519_point_t *
fd_ed25519_point_set_zero( fd_ed25519_point_t * r ) {
  fd_f25519_set( r->X, fd_f25519_zero );
  fd_f25519_set( r->Y, fd_f25519_one );
  fd_f25519_set( r->Z, fd_f25519_one );
  fd_f25519_set( r->T, fd_f25519_zero );
  return r;
}

/* fd_ed25519_point_set_zero_precomputed sets r = 0 (point at infinity). */
FD_25519_INLINE fd_ed25519_point_t *
fd_ed25519_point_set_zero_precomputed( fd_ed25519_point_t * r ) {
#if CURVE25519_PRECOMP_XY
  fd_f25519_set( r->X, fd_f25519_one );  /* Y-X = 1-0 = 1 */
  fd_f25519_set( r->Y, fd_f25519_one );  /* Y+X = 1+0 = 1 */
  fd_f25519_set( r->Z, fd_f25519_one );  /* Z = 1 */
  fd_f25519_set( r->T, fd_f25519_zero ); /* kT = 0 */
  return r;
#else
  return fd_ed25519_point_set_zero( r );
#endif
}

/* fd_ed25519_point_set sets r = a. */
FD_25519_INLINE fd_ed25519_point_t * FD_FN_NO_ASAN
fd_ed25519_point_set( fd_ed25519_point_t *       r,
                      fd_ed25519_point_t const * a ) {
  fd_f25519_set( r->X, a->X );
  fd_f25519_set( r->Y, a->Y );
  fd_f25519_set( r->Z, a->Z );
  fd_f25519_set( r->T, a->T );
  return r;
}

/* fd_ed25519_point_from sets r = (x : y : z : t). */
FD_25519_INLINE fd_ed25519_point_t *
fd_ed25519_point_from( fd_ed25519_point_t * r,
                       fd_f25519_t const *  x,
                       fd_f25519_t const *  y,
                       fd_f25519_t const *  z,
                       fd_f25519_t const *  t ) {
  fd_f25519_set( r->X, x );
  fd_f25519_set( r->Y, y );
  fd_f25519_set( r->Z, z );
  fd_f25519_set( r->T, t );
  return r;
}

/* fd_ed25519_point_from sets (x : y : z : t) = a. */
FD_25519_INLINE void
fd_ed25519_point_to( fd_f25519_t *  x,
                     fd_f25519_t *  y,
                     fd_f25519_t *  z,
                     fd_f25519_t *  t,
                     fd_ed25519_point_t const * a ) {
  fd_f25519_set( x, a->X );
  fd_f25519_set( y, a->Y );
  fd_f25519_set( z, a->Z );
  fd_f25519_set( t, a->T );
}

/* fd_ed25519_point_sub sets r = -a. */
FD_25519_INLINE fd_ed25519_point_t *
fd_ed25519_point_neg( fd_ed25519_point_t *       r,
                      fd_ed25519_point_t const * a ) {
  fd_f25519_neg( r->X, a->X );
  fd_f25519_set( r->Y, a->Y );
  fd_f25519_set( r->Z, a->Z );
  fd_f25519_neg( r->T, a->T );
  return r;
}

/* fd_ed25519_point_is_zero returns 1 if a == 0 (point at infinity), 0 otherwise. */
FD_25519_INLINE int
fd_ed25519_point_is_zero( fd_ed25519_point_t const * a ) {
  return fd_f25519_is_zero( a->X ) & fd_f25519_eq( a->Y, a->Z );
}

/* fd_ed25519_point_eq returns 1 if a == b, 0 otherwise. */
FD_25519_INLINE int
fd_ed25519_point_eq( fd_ed25519_point_t const * a,
                     fd_ed25519_point_t const * b ) {
  fd_f25519_t x1[1], x2[1], y1[1], y2[1];
  fd_f25519_mul( x1, b->X, a->Z );
  fd_f25519_mul( x2, a->X, b->Z );
  fd_f25519_mul( y1, b->Y, a->Z );
  fd_f25519_mul( y2, a->Y, b->Z );
  return fd_f25519_eq( x1, x2 ) & fd_f25519_eq( y1, y2 );
}

/* fd_ed25519_point_eq returns 1 if a == b, 0 otherwise.
   b is a point with Z==1, e.g. a decompressed point. */
FD_25519_INLINE int
fd_ed25519_point_eq_z1( fd_ed25519_point_t const * a,
                        fd_ed25519_point_t const * b ) { /* b.Z == 1, e.g. a decompressed point */
  fd_f25519_t x1[1], y1[1];
  fd_f25519_mul( x1, b->X, a->Z );
  fd_f25519_mul( y1, b->Y, a->Z );
  return fd_f25519_eq( x1, a->X ) & fd_f25519_eq( y1, a->Y );
}

/* fd_curve25519_into_precomputed transforms a point into
   precomputed table format, e.g. replaces T -> kT to save
   1mul in the dbl-and-add loop. */
FD_25519_INLINE void
fd_curve25519_into_precomputed( fd_ed25519_point_t * r ) {
#if CURVE25519_PRECOMP_XY
  fd_f25519_t add[1], sub[1];
  fd_f25519_add_nr( add, r->Y, r->X );
  fd_f25519_sub_nr( sub, r->Y, r->X );
  fd_f25519_set( r->X, sub );
  fd_f25519_set( r->Y, add );
#endif
  fd_f25519_mul( r->T, r->T, fd_f25519_k );
}

/*
  Implementation of dbl/dbln, needed for fd_ed25519_point_is_small_order
*/
/* fd_ed25519_point_add_final_mul computes just the final mul step in point add.
   See fd_ed25519_point_add_with_opts. */
FD_25519_INLINE fd_ed25519_point_t *
fd_ed25519_point_add_final_mul( fd_ed25519_point_t * restrict r,
                                fd_ed25519_point_t const *    a ) {
  fd_f25519_t const *r1 = a->X;
  fd_f25519_t const *r2 = a->Y;
  fd_f25519_t const *r3 = a->Z;
  fd_f25519_t const *r4 = a->T;

  fd_f25519_mul4( r->X, r1, r2,
                  r->Y, r3, r4,
                  r->Z, r2, r3,
                  r->T, r1, r4 );
  return r;
}

/* fd_ed25519_point_add_final_mul_projective computes just the final mul step
   in point add, assuming the result is projective (X, Y, Z), i.e. ignoring T.
   This is useful because dbl only needs (X, Y, Z) in input, so we can save 1mul.
   See fd_ed25519_point_add_with_opts. */
FD_25519_INLINE fd_ed25519_point_t *
fd_ed25519_point_add_final_mul_projective( fd_ed25519_point_t * restrict r,
                                           fd_ed25519_point_t const *    a ) {
  fd_f25519_mul3( r->X, a->X, a->Y,
                  r->Y, a->Z, a->T,
                  r->Z, a->Y, a->Z );
  return r;
}

/* Dedicated dbl
   https://eprint.iacr.org/2008/522
   Sec 4.4.
   This uses sqr instead of mul. */
FD_25519_INLINE fd_ed25519_point_t *
fd_ed25519_partial_dbl( fd_ed25519_point_t *       r,
                        fd_ed25519_point_t const * a ) {
  fd_f25519_t r1[1], r2[1], r3[1], r4[1];
  fd_f25519_t r5[1];

  fd_f25519_add_nr( r1, a->X, a->Y );

  fd_f25519_sqr4( r2, a->X,
                  r3, a->Y,
                  r4, a->Z,
                  r5, r1 );

  /* important: reduce mod p (these values are used in add/sub) */
  fd_f25519_add( r4, r4, r4 );
  fd_f25519_add( r->T, r2, r3 );
  fd_f25519_sub( r->Z, r2, r3 );

  fd_f25519_add_nr( r->Y, r4, r->Z );
  fd_f25519_sub_nr( r->X, r->T, r5 );
  return r;
}

FD_25519_INLINE fd_ed25519_point_t * FD_FN_NO_ASAN
fd_ed25519_point_dbln( fd_ed25519_point_t *       r,
                       fd_ed25519_point_t const * a,
                       int                        n ) {
  fd_ed25519_point_t t[1];
  fd_ed25519_partial_dbl( t, a );
  for( uchar i=1; i<n; i++ ) {
    fd_ed25519_point_add_final_mul_projective( r, t );
    fd_ed25519_partial_dbl( t, r );
  }
  return fd_ed25519_point_add_final_mul( r, t );
}

FD_PROTOTYPES_END
