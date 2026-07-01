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
#include "./fd_r52x5_ge.h"

/* struct fd_curve25519_edwards (aka fd_curve25519_edwards_t) represents
   a point in Extended Twisted Edwards Coordinates.
   https://eprint.iacr.org/2008/522 */
struct fd_curve25519_edwards {
  FD_R52X5_QUAD_DECL( P ) __attribute__((aligned(FD_F25519_ALIGN)));
};
typedef struct fd_curve25519_edwards fd_curve25519_edwards_t;

typedef fd_curve25519_edwards_t fd_ed25519_point_t;
typedef fd_curve25519_edwards_t fd_ristretto255_point_t;

#include "../table/fd_curve25519_table_avx512.c"

FD_PROTOTYPES_BEGIN

/* fd_ed25519_point_set_zero sets r = 0 (point at infinity). */
FD_25519_INLINE fd_ed25519_point_t *
fd_ed25519_point_set_zero( fd_ed25519_point_t * r ) {
  FD_R52X5_GE_ZERO( r->P );
  return r;
}

/* fd_ed25519_point_set_zero_precomputed sets r to the identity in
   precomputed form:
     (Y-X, Y+X, 2*Z*121666, -2*T*121665). */
FD_25519_INLINE fd_ed25519_point_t *
fd_ed25519_point_set_zero_precomputed( fd_ed25519_point_t * r ) {
  r->P0 = wl( 121647L, 121666L, 243332L, 2251799813685229L );
  r->P1 = wl( 2251799813685248L, 0L, 0L, 2251799813685247L );
  r->P2 = wl( 2251799813685247L, 0L, 0L, 2251799813685247L );
  r->P3 = wl( 2251799813685247L, 0L, 0L, 2251799813685247L );
  r->P4 = wl( 2251799813685247L, 0L, 0L, 2251799813685247L );
  return r;
}

/* fd_ed25519_point_set sets r = a. */
FD_25519_INLINE fd_ed25519_point_t * FD_FN_NO_ASAN
fd_ed25519_point_set( fd_ed25519_point_t *       r,
                      fd_ed25519_point_t const * a ) {
  r->P0 = a->P0;
  r->P1 = a->P1;
  r->P2 = a->P2;
  r->P3 = a->P3;
  r->P4 = a->P4;
  return r;
}

/* fd_ed25519_point_from sets r = (x : y : z : t). */
FD_25519_INLINE fd_ed25519_point_t *
fd_ed25519_point_from( fd_ed25519_point_t * r,
                       fd_f25519_t const *  x,
                       fd_f25519_t const *  y,
                       fd_f25519_t const *  z,
                       fd_f25519_t const *  t ) {
  FD_R52X5_QUAD_PACK( r->P, x->el, y->el, z->el, t->el );
  return r;
}

/* fd_ed25519_point_to extracts (x : y : z : t) = a. */
FD_25519_INLINE void
fd_ed25519_point_to( fd_f25519_t *              x,
                     fd_f25519_t *              y,
                     fd_f25519_t *              z,
                     fd_f25519_t *              t,
                     fd_ed25519_point_t const * a ) {
  FD_R52X5_QUAD_UNPACK( x->el, y->el, z->el, t->el, a->P );
}

/* fd_ed25519_point_dbln computes r = 2^n a, and returns r. */
FD_25519_INLINE fd_ed25519_point_t * FD_FN_NO_ASAN
fd_ed25519_point_dbln( fd_ed25519_point_t *       r,
                       fd_ed25519_point_t const * a,
                       int                        n ) {
  FD_R52X5_GE_DBL( r->P, a->P );
  for( uchar i=1; i<n; i++ ) {
    FD_R52X5_GE_DBL( r->P, r->P );
  }
  return r;
}

/* fd_ed25519_point_neg computes r = -a.
   Given coordinates (X, Y, Z, T), the negative is (-X, Y, Z, -T). */
FD_25519_INLINE fd_ed25519_point_t *
fd_ed25519_point_neg( fd_ed25519_point_t *       r,
                      fd_ed25519_point_t const * a ) {
  FD_R52X5_QUAD_DECL( _p );
  FD_R52X5_QUAD_NEGATE_LAZY( _p, a->P );
  FD_R52X5_QUAD_REDUCE( _p, _p );
  FD_R52X5_QUAD_LANE_IF( r->P, 1,0,0,1, _p, a->P );
  return r;
}

/* fd_ed25519_point_is_zero returns 1 if a == 0 (identity), 0 otherwise. */
FD_25519_INLINE int
fd_ed25519_point_is_zero( fd_ed25519_point_t const * a ) {
  fd_ed25519_point_t zero[1];
  fd_ed25519_point_set_zero( zero );
  return FD_R52X5_GE_IS_EQ( a->P, zero->P );
}

/* fd_ed25519_point_eq returns 1 if a == b, 0 otherwise. */
FD_25519_INLINE int
fd_ed25519_point_eq( fd_ed25519_point_t const * a,
                     fd_ed25519_point_t const * b ) {
  return FD_R52X5_GE_IS_EQ( a->P, b->P );
}

/* fd_ed25519_point_affine_eq returns 1 if a == b, 0 otherwise.
   b is a point with Z==1, e.g. a decompressed point. */
FD_25519_INLINE int
fd_ed25519_point_affine_eq( fd_ed25519_point_t const * a,
                        fd_ed25519_point_t const * b ) {
  return fd_ed25519_point_eq( a, b );
}

/* fd_curve25519_into_precomputed transforms a point in-place into the
   precomputed table form. See the commend above FD_R52X5_TO_TABLE for
   more information. */
FD_25519_INLINE void
fd_curve25519_into_precomputed( fd_ed25519_point_t * r ) {
  FD_R52X5_TO_TABLE( r->P, r->P );
}

FD_PROTOTYPES_END
