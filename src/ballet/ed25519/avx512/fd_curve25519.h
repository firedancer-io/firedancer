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
#include "./fd_r43x6_ge.h"

/* struct fd_curve25519_edwards (aka fd_curve25519_edwards_t) represents
   a point in Extended Twisted Edwards Coordinates.
   https://eprint.iacr.org/2008/522 */
struct fd_curve25519_edwards {
  FD_R43X6_QUAD_DECL( P ) __attribute__((aligned(FD_F25519_ALIGN)));
};
typedef struct fd_curve25519_edwards fd_curve25519_edwards_t;

typedef fd_curve25519_edwards_t fd_ed25519_point_t;
typedef fd_curve25519_edwards_t fd_ristretto255_point_t;

#include "../table/fd_curve25519_table_avx512.c"

FD_PROTOTYPES_BEGIN

/* fd_ed25519_point_set sets r = 0 (point at infinity). */
FD_25519_INLINE fd_ed25519_point_t *
fd_ed25519_point_set_zero( fd_ed25519_point_t * r ) {
  FD_R43X6_GE_ZERO( r->P );
  return r;
}

/* fd_ed25519_point_set_zero_precomputed sets r = 0 (point at infinity). */
FD_25519_INLINE fd_ed25519_point_t *
fd_ed25519_point_set_zero_precomputed( fd_ed25519_point_t * r ) {
  r->P03 = wwl( 1L,1L,1L,0L, 0L,0L,0L,0L ); r->P14 = wwl_zero(); r->P25 = wwl_zero();
  return r;
}

/* fd_ed25519_point_set sets r = a. */
FD_25519_INLINE fd_ed25519_point_t * FD_FN_NO_ASAN
fd_ed25519_point_set( fd_ed25519_point_t *       r,
                      fd_ed25519_point_t const * a ) {
  r->P03 = a->P03;
  r->P14 = a->P14;
  r->P25 = a->P25;
  return r;
}

/* fd_ed25519_point_from sets r = (x : y : z : t). */
FD_25519_INLINE fd_ed25519_point_t *
fd_ed25519_point_from( fd_ed25519_point_t * r,
                       fd_f25519_t const *  x,
                       fd_f25519_t const *  y,
                       fd_f25519_t const *  z,
                       fd_f25519_t const *  t ) {
  FD_R43X6_QUAD_PACK( r->P, x->el, y->el, z->el, t->el );
  return r;
}

/* fd_ed25519_point_from sets (x : y : z : t) = a. */
FD_25519_INLINE void
fd_ed25519_point_to( fd_f25519_t *  x,
                     fd_f25519_t *  y,
                     fd_f25519_t *  z,
                     fd_f25519_t *  t,
                     fd_ed25519_point_t const * a ) {
  FD_R43X6_QUAD_UNPACK( x->el, y->el, z->el, t->el, a->P );
}

/* fd_ed25519_point_dbln computes r = 2^n a, and returns r.
   More efficient than n fd_ed25519_point_add. */
FD_25519_INLINE fd_ed25519_point_t * FD_FN_NO_ASAN
fd_ed25519_point_dbln( fd_ed25519_point_t *       r,
                       fd_ed25519_point_t const * a,
                       int                        n ) {
  FD_R43X6_GE_DBL( r->P, a->P );
  for( uchar i=1; i<n; i++ ) {
    FD_R43X6_GE_DBL( r->P, r->P );
  }
  return r;
}

/* fd_ed25519_point_sub sets r = -a. */
FD_25519_INLINE fd_ed25519_point_t *
fd_ed25519_point_neg( fd_ed25519_point_t *       r,
                      fd_ed25519_point_t const * a ) {
  /* use p instead of zero to avoid mod reduction */
  FD_R43X6_QUAD_DECL( _p );
  _p03 = wwl( 8796093022189L, 8796093022189L, 8796093022189L, 8796093022189L, 8796093022207L, 8796093022207L, 8796093022207L, 8796093022207L );
  _p14 = wwl( 8796093022207L, 8796093022207L, 8796093022207L, 8796093022207L, 8796093022207L, 8796093022207L, 8796093022207L, 8796093022207L );
  _p25 = wwl( 8796093022207L, 8796093022207L, 8796093022207L, 8796093022207L, 1099511627775L, 1099511627775L, 1099511627775L, 1099511627775L );
  // FD_R43X6_QUAD_LANE_SUB_FAST( r->P, a->P, 1,0,0,1, _p, a->P );
  // FD_R43X6_QUAD_FOLD_UNSIGNED( r->P, r->P );
  int _mask = 0x99; /* 1001 1001 */
  r->P03 = wwv_sub_if( _mask, _p03, a->P03, a->P03 );
  r->P14 = wwv_sub_if( _mask, _p14, a->P14, a->P14 );
  r->P25 = wwv_sub_if( _mask, _p25, a->P25, a->P25 );
  return r;
}

/* fd_ed25519_point_is_zero returns 1 if a == 0 (point at infinity), 0 otherwise. */
FD_25519_INLINE int
fd_ed25519_point_is_zero( fd_ed25519_point_t const * a ) {
  fd_ed25519_point_t zero[1];
  fd_ed25519_point_set_zero( zero );
  return FD_R43X6_GE_IS_EQ( a->P, zero->P );
}

/* fd_ed25519_point_eq returns 1 if a == b, 0 otherwise. */
FD_25519_INLINE int
fd_ed25519_point_eq( fd_ed25519_point_t const * a,
                     fd_ed25519_point_t const * b ) {
  return FD_R43X6_GE_IS_EQ( a->P, b->P );
}

/* fd_ed25519_point_eq returns 1 if a == b, 0 otherwise.
   b is a point with Z==1, e.g. a decompressed point. */
FD_25519_INLINE int
fd_ed25519_point_eq_z1( fd_ed25519_point_t const * a,
                        fd_ed25519_point_t const * b ) { /* b.Z == 1, e.g. a decompressed point */
  return fd_ed25519_point_eq( a, b );
}

FD_25519_INLINE void
fd_curve25519_into_precomputed( fd_ed25519_point_t * r ) {
  FD_R43X6_QUAD_DECL         ( _ta );
  FD_R43X6_QUAD_PERMUTE      ( _ta, 1,0,2,3, r->P );            /* _ta = (Y1,   X1,   Z1,   T1   ), s61|s61|s61|s61 */
  FD_R43X6_QUAD_LANE_SUB_FAST( _ta, _ta, 1,0,0,0, _ta, r->P );  /* _ta = (Y1-X1,X1,   Z1,   T1   ), s62|s61|s61|s61 */
  FD_R43X6_QUAD_LANE_ADD_FAST( _ta, _ta, 0,1,0,0, _ta, r->P );  /* _ta = (Y1-X1,Y1+X1,Z1,   T1   ), s62|s62|s61|s61 */
  FD_R43X6_QUAD_FOLD_UNSIGNED( r->P, _ta );                     /*   r = (Y1-X1,Y1+X1,Z1,   T1   ), u44|u44|u44|u44 */

  FD_R43X6_QUAD_DECL         ( _1112d );
  FD_R43X6_QUAD_1112d        ( _1112d );
  FD_R43X6_QUAD_MUL_FAST     ( r->P, r->P, _1112d );
  FD_R43X6_QUAD_FOLD_UNSIGNED( r->P, r->P );
}

FD_PROTOTYPES_END
