#include "../fd_curve25519.h"
#include "./fd_r43x6_ge.h"

/*
 * Add
 */

/* fd_ed25519_point_add_with_opts computes r = a + b, and returns r.

   https://eprint.iacr.org/2008/522
   Sec 4.2, 4-Processor Montgomery addition and doubling.

   This implementation includes several optional optimizations
   that are used for speeding up scalar multiplication:

   - b_Z_is_one, if b->Z == 1 (affine, or decompressed), we can skip 1mul

   - b_is_precomputed, since the scalar mul loop typically accumulates
     points from a table, we can pre-compute kT into the table points and
     therefore skip 1mul in during the loop.

   - skip_last_mul, since dbl can be computed with just (X, Y, Z)
     and doesn't need T, we can skip the last 4 mul and selectively
     compute (X, Y, Z) or (X, Y, Z, T) during the scalar mul loop.
 */
FD_25519_INLINE fd_ed25519_point_t *
fd_ed25519_point_add_with_opts( fd_ed25519_point_t *       r,
                                fd_ed25519_point_t const * a,
                                fd_ed25519_point_t const * b,
                                FD_PARAM_UNUSED int const b_Z_is_one,
                                int const b_is_precomputed,
                                FD_PARAM_UNUSED int const skip_last_mul ) {

  if( b_is_precomputed ) {
    FD_R43X6_GE_ADD_TABLE_ALT( r->P, a->P, b->P );
  } else {
    FD_R43X6_GE_ADD( r->P, a->P, b->P );
  }
  return r;
}

/* fd_ed25519_point_add computes r = a + b, and returns r. */
fd_ed25519_point_t *
fd_ed25519_point_add( fd_ed25519_point_t *       r,
                      fd_ed25519_point_t const * a,
                      fd_ed25519_point_t const * b ) {
  return fd_ed25519_point_add_with_opts( r, a, b, 0, 0, 0 );
}

/* fd_ed25519_point_add_final_mul computes just the final mul step in point add.
   See fd_ed25519_point_add_with_opts. */
FD_25519_INLINE fd_ed25519_point_t *
fd_ed25519_point_add_final_mul( fd_ed25519_point_t * restrict r,
                                fd_ed25519_point_t const *    a ) {
  fd_ed25519_point_set( r, a );
  return r;
}

/* fd_ed25519_point_add_final_mul_projective computes just the final mul step
   in point add, assuming the result is projective (X, Y, Z), i.e. ignoring T.
   This is useful because dbl only needs (X, Y, Z) in input, so we can save 1mul.
   See fd_ed25519_point_add_with_opts. */
FD_25519_INLINE fd_ed25519_point_t *
fd_ed25519_point_add_final_mul_projective( fd_ed25519_point_t * restrict r,
                                           fd_ed25519_point_t const *    a ) {
  fd_ed25519_point_set( r, a );
  return r;
}

/*
 * Sub
 */

/* fd_ed25519_point_sub sets r = -a. */
FD_25519_INLINE fd_ed25519_point_t *
fd_ed25519_point_neg_precomputed( fd_ed25519_point_t *       r,
                      fd_ed25519_point_t const * a ) {
  /* use p instead of zero to avoid mod reduction */
  FD_R43X6_QUAD_DECL( _p );
  _p03 = wwl( 8796093022189L, 8796093022189L, 8796093022189L, 8796093022189L, 8796093022207L, 8796093022207L, 8796093022207L, 8796093022207L );
  _p14 = wwl( 8796093022207L, 8796093022207L, 8796093022207L, 8796093022207L, 8796093022207L, 8796093022207L, 8796093022207L, 8796093022207L );
  _p25 = wwl( 8796093022207L, 8796093022207L, 8796093022207L, 8796093022207L, 1099511627775L, 1099511627775L, 1099511627775L, 1099511627775L );
  FD_R43X6_QUAD_LANE_SUB_FAST( r->P, a->P, 0,0,0,1, _p, a->P );
  FD_R43X6_QUAD_PERMUTE      ( r->P, 1,0,2,3, r->P );
  return r;
}

/* fd_ed25519_point_sub_with_opts computes r = a - b, and returns r.
   This is like fd_ed25519_point_add_with_opts, replacing:
   - b->X => -b->X
   - b->T => -b->T
   See fd_ed25519_point_add_with_opts for details.
 */
FD_25519_INLINE fd_ed25519_point_t *
fd_ed25519_point_sub_with_opts( fd_ed25519_point_t *       r,
                                fd_ed25519_point_t const * a,
                                fd_ed25519_point_t const * b,
                                int const b_Z_is_one,
                                int const b_is_precomputed,
                                int const skip_last_mul ) {

  fd_ed25519_point_t neg[1];
  if (b_is_precomputed) {
    fd_ed25519_point_neg_precomputed( neg, b );
  } else {
    fd_ed25519_point_neg( neg, b );
  }
  return fd_ed25519_point_add_with_opts( r, a, neg, b_Z_is_one, b_is_precomputed, skip_last_mul );
}

/* fd_ed25519_point_sub computes r = a - b, and returns r. */
fd_ed25519_point_t *
fd_ed25519_point_sub( fd_ed25519_point_t *       r,
                      fd_ed25519_point_t const * a,
                      fd_ed25519_point_t const * b ) {
  return fd_ed25519_point_sub_with_opts( r, a, b, 0, 0, 0 );
}

/*
 * Dbl
 */

/* Dedicated dbl
   https://eprint.iacr.org/2008/522
   Sec 4.4.
   This uses sqr instead of mul.

   TODO: use the same iface with_opts?
  */

FD_25519_INLINE fd_ed25519_point_t *
fd_ed25519_partial_dbl( fd_ed25519_point_t *       r,
                        fd_ed25519_point_t const * a ) {
  FD_R43X6_GE_DBL( r->P, a->P );
  return r;
}

fd_ed25519_point_t *
fd_ed25519_point_dbl( fd_ed25519_point_t *       r,
                      fd_ed25519_point_t const * a ) {
  FD_R43X6_GE_DBL( r->P, a->P );
  return r;
}

/*
 * Ser/de
 */

fd_ed25519_point_t *
fd_ed25519_point_frombytes( fd_ed25519_point_t * r,
                            uchar const          buf[ static 32 ] ) {
  if ( FD_UNLIKELY( FD_R43X6_GE_DECODE( r->P, buf ) != 0 ) ) {
    return NULL;
  }
  return r;
}

int
fd_ed25519_point_frombytes_2x( fd_ed25519_point_t * r1,
                               uchar const          buf1[ static 32 ],
                               fd_ed25519_point_t * r2,
                               uchar const          buf2[ static 32 ] ) {
  return FD_R43X6_GE_DECODE2( r1->P, buf1, r2->P, buf2 );
}

uchar *
fd_ed25519_point_tobytes( uchar                      out[ static 32 ],
                          fd_ed25519_point_t const * a ) {
  FD_R43X6_GE_ENCODE( out, a->P );
  return out;
}

/*
  Affine (only for init(), can be slow)
*/
fd_ed25519_point_t *
fd_curve25519_affine_frombytes( fd_ed25519_point_t * r,
                                uchar const          _x[ static 32 ],
                                uchar const          _y[ static 32 ] ) {
  fd_f25519_t x[1], y[1], z[1], t[1];
  fd_f25519_frombytes( x, _x );
  fd_f25519_frombytes( y, _y );
  fd_f25519_set( z, fd_f25519_one );
  fd_f25519_mul( t, x, y );
  FD_R43X6_QUAD_PACK( r->P, x->el, y->el, z->el, t->el );
  return r;
}

fd_ed25519_point_t *
fd_curve25519_into_affine( fd_ed25519_point_t * r ) {
  fd_f25519_t x[1], y[1], z[1], t[1];
  FD_R43X6_QUAD_UNPACK( x->el, y->el, z->el, t->el, r->P );
  fd_f25519_inv( z, z );
  fd_f25519_mul( x, x, z );
  fd_f25519_mul( y, y, z );
  fd_f25519_set( z, fd_f25519_one );
  fd_f25519_mul( t, x, y );
  FD_R43X6_QUAD_PACK( r->P, x->el, y->el, z->el, t->el );
  return r;
}
