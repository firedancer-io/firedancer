#include "../fd_curve25519.h"

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
                                int const b_Z_is_one,
                                int const b_is_precomputed,
                                int const skip_last_mul ) {
  fd_f25519_t r1[1], r2[1], r3[1], r4[1];
  fd_f25519_t r5[1], r6[1], r7[1], r8[1];
  fd_f25519_t t[1];
  fd_f25519_t const *r2p = r2, *r4p = r4;

  fd_f25519_sub_nr( r1, a->Y, a->X );
  fd_f25519_add_nr( r3, a->Y, a->X );

#if CURVE25519_PRECOMP_XY
  if (b_is_precomputed) {
    r2p = b->X;
    r4p = b->Y;
  } else {
    fd_f25519_sub_nr( r2, b->Y, b->X );
    fd_f25519_add_nr( r4, b->Y, b->X );
  }
#else
    fd_f25519_sub_nr( r2, b->Y, b->X );
    fd_f25519_add_nr( r4, b->Y, b->X );
#endif

  /* if b->Z == 1, save 1mul */
  if( b_Z_is_one ) {
    fd_f25519_mul3( r5, r1,   r2p,
                    r6, r3,   r4p,
                    r7, a->T, b->T );
    fd_f25519_add( r8, a->Z, a->Z );
  } else {
    fd_f25519_add_nr( t, a->Z, a->Z );
    fd_f25519_mul4( r5, r1,   r2p,
                    r6, r3,   r4p,
                    r7, a->T, b->T,
                    r8, t, b->Z );
  } /* b_Z_is_one */

  /* if b->T actually contains k*b->T, save 1mul */
  if( !b_is_precomputed ) {
    fd_f25519_mul( r7, r7, fd_f25519_k );
  }

  /* skip last mul step, and use fd_ed25519_point_add_final_mul
     or fd_ed25519_point_add_final_mul_projective instead. */
  if( skip_last_mul ) {
    /* store r1, r2, r3, r4 resp. in X, Y, Z, T */
    fd_f25519_sub_nr( r->X, r6, r5 );
    fd_f25519_sub_nr( r->Y, r8, r7 );
    fd_f25519_add_nr( r->Z, r8, r7 );
    fd_f25519_add_nr( r->T, r6, r5 );
  } else {
    fd_f25519_sub_nr( r1, r6, r5 );
    fd_f25519_sub_nr( r2, r8, r7 );
    fd_f25519_add_nr( r3, r8, r7 );
    fd_f25519_add_nr( r4, r6, r5 );

    fd_f25519_mul4( r->X, r1, r2,
                    r->Y, r3, r4,
                    r->Z, r2, r3,
                    r->T, r1, r4 );
  } /* skip_last_mul */
  return r;
}

/* fd_ed25519_point_add computes r = a + b, and returns r. */
fd_ed25519_point_t *
fd_ed25519_point_add( fd_ed25519_point_t *       r,
                      fd_ed25519_point_t const * a,
                      fd_ed25519_point_t const * b ) {
  return fd_ed25519_point_add_with_opts( r, a, b, 0, 0, 0 );
}

/*
 * Sub
 */

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
  fd_f25519_t r1[1], r2[1], r3[1], r4[1];
  fd_f25519_t r5[1], r6[1], r7[1], r8[1];
  fd_f25519_t t[1];
  fd_f25519_t const *r2p = r2, *r4p = r4;

  fd_f25519_sub_nr( r1, a->Y, a->X );
  fd_f25519_add_nr( r3, a->Y, a->X );

#if CURVE25519_PRECOMP_XY
  if (b_is_precomputed) {
    r2p = b->Y;
    r4p = b->X;
  } else {
    fd_f25519_add_nr( r2, b->Y, b->X ); // _sub => _add (because of -b->X)
    fd_f25519_sub_nr( r4, b->Y, b->X ); // _add => _sub (because of -b->X)
  }
#else
    fd_f25519_add_nr( r2, b->Y, b->X ); // _sub => _add (because of -b->X)
    fd_f25519_sub_nr( r4, b->Y, b->X ); // _add => _sub (because of -b->X)
#endif

  /* if b->Z == 1, save 1mul */
  if( b_Z_is_one ) {
    fd_f25519_mul3( r5, r1,   r2p,
                    r6, r3,   r4p,
                    r7, a->T, b->T );
    fd_f25519_add( r8, a->Z, a->Z );
  } else {
    fd_f25519_add_nr( t, a->Z, a->Z );
    fd_f25519_mul4( r5, r1,   r2p,
                    r6, r3,   r4p,
                    r7, a->T, b->T,
                    r8, t, b->Z );
  } /* b_Z_is_one */

  /* if b->T actually contains k*b->T, save 1mul */
  if( !b_is_precomputed ) {
    fd_f25519_mul( r7, r7, fd_f25519_k );
  }

  /* skip last mul step, and use fd_ed25519_point_add_final_mul
     or fd_ed25519_point_add_final_mul_projective instead. */
  if( skip_last_mul ) {
    /* store r1, r2, r3, r4 resp. in X, Y, Z, T */
    fd_f25519_sub_nr( r->X, r6, r5 );
    fd_f25519_add_nr( r->Y, r8, r7 ); // _sub => _add (because of -b->T => -r7)
    fd_f25519_sub_nr( r->Z, r8, r7 ); // _add => _sub (because of -b->T => -r7)
    fd_f25519_add_nr( r->T, r6, r5 );
  } else {
    fd_f25519_sub_nr( r1, r6, r5 );
    fd_f25519_add_nr( r2, r8, r7 );   // _sub => _add (because of -b->T => -r7)
    fd_f25519_sub_nr( r3, r8, r7 );   // _add => _sub (because of -b->T => -r7)
    fd_f25519_add_nr( r4, r6, r5 );

    fd_f25519_mul4( r->X, r1, r2,
                    r->Y, r3, r4,
                    r->Z, r2, r3,
                    r->T, r1, r4 );
  } /* skip_last_mul */
  return r;
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

fd_ed25519_point_t *
fd_ed25519_point_dbl( fd_ed25519_point_t *       r,
                      fd_ed25519_point_t const * a ) {
  fd_ed25519_point_t t[1];
  /* Dedicated dbl
     https://eprint.iacr.org/2008/522
     Sec 4.4.
     This uses sqr instead of mul. */
  fd_ed25519_partial_dbl( t, a );
  return fd_ed25519_point_add_final_mul( r, t );
}

/*
 * Ser/de
 */

int
fd_ed25519_point_frombytes_2x( fd_ed25519_point_t * r1,
                               uchar const          buf1[ static 32 ],
                               fd_ed25519_point_t * r2,
                               uchar const          buf2[ static 32 ] ) {
  fd_ed25519_point_t * res = NULL;
  res = fd_ed25519_point_frombytes( r1, buf1 );
  if( res == NULL ) {
    return 1;
  }
  res = fd_ed25519_point_frombytes( r2, buf2 );
  if( res == NULL ) {
    return 2;
  }
  return 0;
}

/*
  Affine (only for init(), can be slow)
*/
fd_ed25519_point_t *
fd_curve25519_affine_frombytes( fd_ed25519_point_t * r,
                                uchar const          x[ static 32 ],
                                uchar const          y[ static 32 ] ) {
  fd_f25519_frombytes( r->X, x );
  fd_f25519_frombytes( r->Y, y );
  fd_f25519_set( r->Z, fd_f25519_one );
  fd_f25519_mul( r->T, r->X, r->Y );
  return r;
}

fd_ed25519_point_t *
fd_curve25519_into_affine( fd_ed25519_point_t * r ) {
  fd_f25519_t invz[1];
  fd_f25519_inv( invz, r->Z );
  fd_f25519_mul( r->X, r->X, invz );
  fd_f25519_mul( r->Y, r->Y, invz );
  fd_f25519_set( r->Z, fd_f25519_one );
  fd_f25519_mul( r->T, r->X, r->Y );
  return r;
}
