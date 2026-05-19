#include "../fd_curve25519.h"

/* fd_ed25519_point_add_with_opts computes r = a + b.

   If b_is_precomputed, b is assumed to already be in the "precomputed" form
   and is directly consumed by FD_R52X5_GE_ADD_TABLE. Otherwise b is
   performs the precomputed conversion internally. */
FD_25519_INLINE fd_ed25519_point_t *
fd_ed25519_point_add_with_opts( fd_ed25519_point_t *       r,
                                fd_ed25519_point_t const * a,
                                fd_ed25519_point_t const * b,
                                FD_PARAM_UNUSED int const b_Z_is_one,
                                int const b_is_precomputed,
                                FD_PARAM_UNUSED int const skip_last_mul ) {
  if( b_is_precomputed ) {
    fd_ed25519_point_t tmp[2];
    FD_R52X5_GE_ADD_TABLE( r->P, a->P, b->P, tmp[0].P, tmp[1].P );
  } else {
    FD_R52X5_GE_ADD( r->P, a->P, b->P );
  }
  return r;
}

fd_ed25519_point_t *
fd_ed25519_point_add( fd_ed25519_point_t *       r,
                      fd_ed25519_point_t const * a,
                      fd_ed25519_point_t const * b ) {
  return fd_ed25519_point_add_with_opts( r, a, b, 0, 0, 0 );
}

FD_25519_INLINE fd_ed25519_point_t *
fd_ed25519_point_add_final_mul( fd_ed25519_point_t * restrict r,
                                fd_ed25519_point_t const *    a ) {
  fd_ed25519_point_set( r, a );
  return r;
}

FD_25519_INLINE fd_ed25519_point_t *
fd_ed25519_point_add_final_mul_projective( fd_ed25519_point_t * restrict r,
                                           fd_ed25519_point_t const *    a ) {
  fd_ed25519_point_set( r, a );
  return r;
}

FD_25519_INLINE fd_ed25519_point_t *
fd_ed25519_point_neg_precomputed( fd_ed25519_point_t *       r,
                                  fd_ed25519_point_t const * a ) {
  FD_R52X5_QUAD_DECL( _p );
  FD_R52X5_QUAD_PERMUTE( r->P, 1,0,2,3, a->P );
  FD_R52X5_QUAD_NEGATE_LAZY( _p, a->P );
  FD_R52X5_QUAD_REDUCE( _p, _p );
  FD_R52X5_QUAD_LANE_IF( r->P, 0,0,0,1, _p, r->P );
  return r;
}

FD_25519_INLINE fd_ed25519_point_t *
fd_ed25519_point_sub_with_opts( fd_ed25519_point_t *       r,
                                fd_ed25519_point_t const * a,
                                fd_ed25519_point_t const * b,
                                int const b_Z_is_one,
                                int const b_is_precomputed,
                                int const skip_last_mul ) {
  fd_ed25519_point_t neg[1];
  if( b_is_precomputed ) {
    fd_ed25519_point_neg_precomputed( neg, b );
  } else {
    fd_ed25519_point_neg( neg, b );
  }
  return fd_ed25519_point_add_with_opts( r, a, neg, b_Z_is_one, b_is_precomputed, skip_last_mul );
}

fd_ed25519_point_t *
fd_ed25519_point_sub( fd_ed25519_point_t *       r,
                      fd_ed25519_point_t const * a,
                      fd_ed25519_point_t const * b ) {
  return fd_ed25519_point_sub_with_opts( r, a, b, 0, 0, 0 );
}

FD_25519_INLINE fd_ed25519_point_t *
fd_ed25519_partial_dbl( fd_ed25519_point_t *       r,
                        fd_ed25519_point_t const * a ) {
  FD_R52X5_GE_DBL( r->P, a->P );
  return r;
}

fd_ed25519_point_t *
fd_ed25519_point_dbl( fd_ed25519_point_t *       r,
                      fd_ed25519_point_t const * a ) {
  FD_R52X5_GE_DBL( r->P, a->P );
  return r;
}

int
fd_ed25519_point_frombytes_2x( fd_ed25519_point_t * r1,
                               uchar const          buf1[ 32 ],
                               fd_ed25519_point_t * r2,
                               uchar const          buf2[ 32 ] ) {
  return FD_R52X5_GE_DECODE2( r1->P, buf1, r2->P, buf2 );
}

fd_ed25519_point_t *
fd_curve25519_affine_frombytes( fd_ed25519_point_t * r,
                                uchar const          _x[ 32 ],
                                uchar const          _y[ 32 ] ) {
  fd_f25519_t x[1], y[1], z[1], t[1];
  fd_f25519_frombytes( x, _x );
  fd_f25519_frombytes( y, _y );
  fd_f25519_set( z, fd_f25519_one );
  fd_f25519_mul( t, x, y );
  FD_R52X5_QUAD_PACK( r->P, x->el, y->el, z->el, t->el );
  return r;
}

fd_ed25519_point_t *
fd_curve25519_into_affine( fd_ed25519_point_t * r ) {
  fd_f25519_t x[1], y[1], z[1], t[1];
  FD_R52X5_QUAD_UNPACK( x->el, y->el, z->el, t->el, r->P );
  fd_f25519_inv( z, z );
  fd_f25519_mul( x, x, z );
  fd_f25519_mul( y, y, z );
  fd_f25519_set( z, fd_f25519_one );
  fd_f25519_mul( t, x, y );
  FD_R52X5_QUAD_PACK( r->P, x->el, y->el, z->el, t->el );
  return r;
}
