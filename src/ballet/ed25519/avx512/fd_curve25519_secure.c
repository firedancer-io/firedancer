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

   This implementation uses only register temporaries and clears registers on return.
   The intent is to avoid that an attacker can retrieve information about b,
   that was chosen in const time based on a secret value. */
FD_25519_INLINE void FD_FN_SENSITIVE
fd_ed25519_point_add_secure( fd_ed25519_point_t *       restrict r,
                             fd_ed25519_point_t const * restrict a,
                             fd_ed25519_point_t const * restrict b,
                             fd_ed25519_point_t *       restrict tmp0,
                             fd_ed25519_point_t *       restrict tmp1 ) {
  FD_R52X5_GE_ADD_TABLE( r->P, a->P, b->P, tmp0->P, tmp1->P );
}

/* fd_ed25519_point_dbln_secure computes r = 2^n a.

   It's equivalent to fd_ed25519_point_dbln( r, a, n ).

   This implementation uses only register temporaries and clears registers on return.
   The intent is to avoid that an attacker can retrieve information about a,
   that's a partial aggregation of secretly chosen points. */
FD_25519_INLINE void FD_FN_SENSITIVE
fd_ed25519_point_dbln_secure( fd_ed25519_point_t *       r,
                              fd_ed25519_point_t const * a,
                              int                        n,
                              fd_ed25519_point_t *       restrict tmp0,
                              fd_ed25519_point_t *       restrict tmp1 ) {
  (void)tmp0;
  (void)tmp1;
  FD_R52X5_GE_DBL( r->P, a->P );
  for( uchar i=1; i<n; i++ ) {
    FD_R52X5_GE_DBL( r->P, r->P );
  }
}

/* fd_ed25519_point_if sets r = a0 if secret_cond, else r = a1.
   Equivalent to r = secret_cond ? a0 : a1.
   Note: this is const time, as the underlying wl_if is const time. */
FD_25519_INLINE void FD_FN_SENSITIVE
fd_ed25519_point_if( fd_ed25519_point_t * restrict r,
                     uchar const                   secret_cond, /* 0, 1 */
                     fd_ed25519_point_t const *    a0,
                     fd_ed25519_point_t const *    a1 ) {
  wl_t mask = wl_bcast( -secret_cond );
  r->P0 = wl_if( mask, a0->P0, a1->P0 );
  r->P1 = wl_if( mask, a0->P1, a1->P1 );
  r->P2 = wl_if( mask, a0->P2, a1->P2 );
  r->P3 = wl_if( mask, a0->P3, a1->P3 );
  r->P4 = wl_if( mask, a0->P4, a1->P4 );
}

/* fd_ed25519_point_neg_if sets r = -r if secret_cond, else r = r.
   Equivalent to r = secret_cond ? -r : r.
   Note: this is const time, as the underlying wl_if is const time. */
FD_25519_INLINE void FD_FN_SENSITIVE
fd_ed25519_point_neg_if( fd_ed25519_point_t * FD_RESTRICT r,
                         fd_ed25519_point_t * const       a,
                         uchar const                      secret_cond /* 0, 1 */ ) {
  FD_R52X5_QUAD_NEGATE_LAZY( r->P, a->P );
  FD_R52X5_QUAD_REDUCE(  r->P, r->P );
  FD_R52X5_QUAD_LANE_IF( r->P, 0,0,0,1, r->P, a->P );
  FD_R52X5_QUAD_PERMUTE( r->P, 1,0,2,3, r->P );
  wl_t cond = wl_bcast( -secret_cond );
  r->P0 = wl_if( cond, r->P0, a->P0 );
  r->P1 = wl_if( cond, r->P1, a->P1 );
  r->P2 = wl_if( cond, r->P2, a->P2 );
  r->P3 = wl_if( cond, r->P3, a->P3 );
  r->P4 = wl_if( cond, r->P4, a->P4 );
}
