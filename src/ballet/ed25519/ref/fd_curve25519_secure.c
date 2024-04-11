#include "../fd_curve25519.h"

/* All the functions in this file are considered "secure", specifically:

   - Constant time in the input, i.e. the input can be a secret
   - Small and auditable code base, incl. simple types
   - No local variables = no need to clear them before exit
   - Clear registers via FD_FN_SENSITIVE
 */

/* fd_ed25519_point_add_secure computes r = a + b.

   It's equivalent to fd_ed25519_point_add_with_opts( r, a, b, 1, 1, 0 ),
   i.e. it assumes that b is from a precomputation table.

   This implementation has no temporary variables and clears registers on return.
   The intent is to avoid that an attacker can retrieve information about b,
   that was chosen in const time based on a secret value. */
FD_25519_INLINE fd_ed25519_point_t * FD_FN_SENSITIVE
fd_ed25519_point_add_secure( fd_ed25519_point_t *       restrict r,
                             fd_ed25519_point_t const * restrict a,
                             fd_ed25519_point_t const * restrict b,
                             fd_ed25519_point_t *       restrict tmp0,
                             fd_ed25519_point_t *       restrict tmp1 ) {
  fd_f25519_t * r1 = tmp0->X;
  fd_f25519_t * r2 = tmp0->Y;
  fd_f25519_t * r3 = tmp0->Z;
  fd_f25519_t * r4 = tmp0->T;
  fd_f25519_t * r5 = tmp1->X;
  fd_f25519_t * r6 = tmp1->Y;
  fd_f25519_t * r7 = tmp1->Z;
  fd_f25519_t * r8 = tmp1->T;

  fd_f25519_sub_nr( r1, a->Y, a->X );
  fd_f25519_add_nr( r3, a->Y, a->X );

#if CURVE25519_PRECOMP_XY
  fd_f25519_mul3(   r5, r1,   b->X,
                    r6, r3,   b->Y,
                    r7, a->T, b->T );
#else
  fd_f25519_sub_nr( r2, b->Y, b->X );
  fd_f25519_add_nr( r4, b->Y, b->X );
  fd_f25519_mul3(   r5, r1,   r2,
                    r6, r3,   r4,
                    r7, a->T, b->T );
#endif
  fd_f25519_add(    r8, a->Z, a->Z );

  fd_f25519_sub_nr( r1, r6, r5 );
  fd_f25519_sub_nr( r2, r8, r7 );
  fd_f25519_add_nr( r3, r8, r7 );
  fd_f25519_add_nr( r4, r6, r5 );
  fd_f25519_mul4( r->X, r1, r2,
                  r->Y, r3, r4,
                  r->Z, r2, r3,
                  r->T, r1, r4 );
  return r;
}

/* fd_ed25519_partial_dbl_secure partially computes r = 2 a.

   It's equivalent to fd_ed25519_partial_dbl( r, a ).

   This implementation has no temporary variables and clears registers on return.
   The intent is to avoid that an attacker can retrieve information about a,
   that's a partial aggregation of secretly chosen points. */
FD_25519_INLINE void FD_FN_SENSITIVE
fd_ed25519_partial_dbl_secure( fd_ed25519_point_t * restrict       r,
                               fd_ed25519_point_t const * restrict a,
                               fd_ed25519_point_t * restrict       tmp) {
  fd_f25519_t * r1 = tmp->X;
  fd_f25519_t * r2 = tmp->Y;
  fd_f25519_t * r3 = tmp->Z;
  fd_f25519_t * r4 = tmp->T;

  fd_f25519_add_nr( r1, a->X, a->Y );

  fd_f25519_sqr4( r2, a->X,
                  r3, a->Y,
                  r4, a->Z,
                  r1, r1 );

  /* important: reduce mod p (these values are used in add/sub) */
  fd_f25519_add( r4, r4, r4 );
  fd_f25519_add( r->T, r2, r3 );
  fd_f25519_sub( r->Z, r2, r3 );

  fd_f25519_add_nr( r->Y, r4, r->Z );
  fd_f25519_sub_nr( r->X, r->T, r1 );
}

/* fd_ed25519_point_dbln_secure computes r = 2^n a.

   It's equivalent to fd_ed25519_point_dbln( r, a, n ).

   This implementation has no temporary variables and clears registers on return.
   The intent is to avoid that an attacker can retrieve information about a,
   that's a partial aggregation of secretly chosen points. */
FD_25519_INLINE void FD_FN_SENSITIVE
fd_ed25519_point_dbln_secure( fd_ed25519_point_t *          r,
                              fd_ed25519_point_t const *    a,
                              int                           n,
                              fd_ed25519_point_t * restrict t,
                              fd_ed25519_point_t * restrict tmp ) {
  fd_ed25519_partial_dbl_secure( t, a, tmp );
  for( uchar i=1; i<n; i++ ) {
    // fd_ed25519_point_add_final_mul_projective( r, t );
    fd_f25519_mul3( r->X, t->X, t->Y,
                    r->Y, t->Z, t->T,
                    r->Z, t->Y, t->Z );

    fd_ed25519_partial_dbl_secure( t, r, tmp );
  }
  // fd_ed25519_point_add_final_mul( r, t );
  fd_f25519_mul4( r->X, t->X, t->Y,
                  r->Y, t->Z, t->T,
                  r->Z, t->Y, t->Z,
                  r->T, t->X, t->T );
}

/* fd_ed25519_point_if sets r = a0 if secret_cond, else r = a1.
   Equivalent to r = secret_cond ? a0 : a1.
   Note: this is const time, as the underlying fd_f25519_if is const time. */
FD_25519_INLINE void FD_FN_SENSITIVE
fd_ed25519_point_if( fd_ed25519_point_t * restrict r,
                     uchar                         secret_cond, /* 0, 1 */
                     fd_ed25519_point_t const *    a0,
                     fd_ed25519_point_t const *    a1 ) {
  fd_f25519_if( r->X, secret_cond, a0->X, a1->X );
  fd_f25519_if( r->Y, secret_cond, a0->Y, a1->Y );
  fd_f25519_if( r->T, secret_cond, a0->T, a1->T );
}

/* fd_ed25519_point_neg_if sets r = -r if secret_cond, else r = r.
   Equivalent to r = secret_cond ? -r : r.
   Note: this is const time, as the underlying fd_f25519_if is const time. */
FD_25519_INLINE void FD_FN_SENSITIVE
fd_ed25519_point_neg_if( fd_ed25519_point_t * FD_RESTRICT r,
                         fd_ed25519_point_t * const       a,
                         uchar const                      secret_cond /* 0, 1 */ ) {
  fd_f25519_neg( r->Z, a->T );
  fd_f25519_if( r->T, secret_cond, r->Z, a->T );
#if CURVE25519_PRECOMP_XY
  fd_f25519_if( r->X, secret_cond, a->Y, a->X );
  fd_f25519_if( r->Y, secret_cond, a->X, a->Y );
#else
  fd_f25519_neg( r->Z, a->X );
  fd_f25519_if( r->X, secret_cond, r->X, a->Z );
#endif
}
