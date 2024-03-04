#include "../fd_curve25519.h"

/* All the functions in this file are considered "secure", specifically:

   - Constant time in the input, i.e. the input can be a secret
   - Small and auditable code base, incl. simple types
   - Only static allocation
   - Clear local variables before exit
   - TODO: only write in secure memory passed in by the caller
   - TODO: clear the stack
   - C safety
   - Unit tests (including tests for these security properties)
 */

/* fd_ed25519_point_add_secure computes r = a + b, and returns r.

   It's equivalent to fd_ed25519_point_add_with_opts( r, a, b, 1, 1, 0 ),
   i.e. it assumes that b is from a precomputation table.

   This implementation clears all temporary variables before exit.
   The intent is to avoid that an attacker can retrieve information about b,
   that was chosen in const time based on a secret value. */
FD_25519_INLINE fd_ed25519_point_t *
fd_ed25519_point_add_secure( fd_ed25519_point_t *       restrict r,
                             fd_ed25519_point_t const * restrict a,
                             fd_ed25519_point_t const * restrict b ) {

  //TODO: add input ptr to secure memory from the caller?
  fd_f25519_t ri[8];
  fd_f25519_t * r1 = &ri[0];
  fd_f25519_t * r2 = &ri[1];
  fd_f25519_t * r3 = &ri[2];
  fd_f25519_t * r4 = &ri[3];
  fd_f25519_t * r5 = &ri[4];
  fd_f25519_t * r6 = &ri[5];
  fd_f25519_t * r7 = &ri[6];
  fd_f25519_t * r8 = &ri[7];

  fd_f25519_sub_nr( r1, a->Y, a->X );
  fd_f25519_add_nr( r3, a->Y, a->X );

#if CURVE25519_PRECOMP_XY
  fd_f25519_mul3( r5, r1,   b->X,
                  r6, r3,   b->Y,
                  r7, a->T, b->T );
#else
  fd_f25519_sub_nr( r2, b->Y, b->X );
  fd_f25519_add_nr( r4, b->Y, b->X );
  fd_f25519_mul3( r5, r1,   r2,
                  r6, r3,   r4,
                  r7, a->T, b->T );
#endif
  fd_f25519_add( r8, a->Z, a->Z );

  fd_f25519_sub_nr( r1, r6, r5 );
  fd_f25519_sub_nr( r2, r8, r7 );
  fd_f25519_add_nr( r3, r8, r7 );
  fd_f25519_add_nr( r4, r6, r5 );
  fd_f25519_mul4( r->X, r1, r2,
                  r->Y, r3, r4,
                  r->Z, r2, r3,
                  r->T, r1, r4 );
  /* Sanitize */

  fd_memset( ri, 0, 8*sizeof(fd_f25519_t) );

  return r;
}

/* fd_ed25519_point_if sets r = a0 if secret_cond, else r = a1.
   Equivalent to r = secret_cond ? a0 : a1.
   Note: this is const time, as the underlying fd_f25519_if is const time. */
FD_25519_INLINE void
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
   Note: this is const time, as the underlying wwl_if is const time. */
FD_25519_INLINE void
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
