#include "../fd_curve25519.h"
#include "./fd_r43x6_ge.h"

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

/* FD_R43X6_GE_ADD_TABLE_ALT is similar to FD_R43X6_GE_ADD_TABLE,
   with 2 minor differences:
   1. order of arguments: P3, P2 points in extended Edwards coordinates,
      T1 precomputed table point
   2. T1 = (Y-X : Y+X : Z==1 : kT)
*/
#define FD_R43X6_GE_ADD_TABLE_ALT( P3, P2, T1 ) do {                                                                  \
    FD_R43X6_QUAD_DECL         ( _ta );                                                                               \
    FD_R43X6_QUAD_DECL         ( _tb );                                                                               \
    FD_R43X6_QUAD_MOV          ( _ta, T1 );                     /* _ta = (Y1-X1,Y1+X1,Z1  ,T1*2d), s61|s61|s61|s61 */ \
    FD_R43X6_QUAD_PERMUTE      ( _tb, 1,0,2,3, P2 );            /* _tb = (Y2,   X2,   Z2,  T2   ), s61|s61|s61|s61 */ \
    FD_R43X6_QUAD_LANE_SUB_FAST( _tb, _tb, 1,0,0,0, _tb, P2 );  /* _tb = (Y2-X2,X2,   Z2,  T2   ), s62|s61|s61|s61 */ \
    FD_R43X6_QUAD_LANE_ADD_FAST( _tb, _tb, 0,1,1,0, _tb, P2 );  /* _tb = (Y2-X2,Y2+X2,Z2*2,T2   ), s62|s62|s61|s61 */ \
    FD_R43X6_QUAD_MUL_FAST     ( _ta, _ta, _tb );               /* _ta = (A,    B,    D,   C    ), u62|u62|u62|u62 */ \
    FD_R43X6_QUAD_FOLD_UNSIGNED( _ta, _ta );                    /* P3  = (A,    B,    D,   C    ), u44|u44|u44|u44 */ \
    FD_R43X6_QUAD_PERMUTE      ( _tb, 1,0,3,2, _ta );           /* _tb = (B,    A,    C,   D    ), u62|u62|u62|u62 */ \
    FD_R43X6_QUAD_LANE_SUB_FAST( _tb, _tb, 1,0,0,1, _tb, _ta ); /* _tb = (E,    A,    C,   F    ), s62|u62|u62|s62 */ \
    FD_R43X6_QUAD_LANE_ADD_FAST( _tb, _tb, 0,1,1,0, _tb, _ta ); /* _tb = (E,    H,    G,   F    ), s62|u63|u63|s62 */ \
    FD_R43X6_QUAD_PERMUTE      ( _ta, 0,2,2,0, _tb );           /* _ta = (E,    G,    G,   E    ), u44|u44|u44|u44 */ \
    FD_R43X6_QUAD_PERMUTE      ( _tb, 3,1,3,1, _tb );           /* _tb = (F,    H,    F,   H    ), u44|u44|u44|u44 */ \
    FD_R43X6_QUAD_MUL_FAST     ( _ta, _ta, _tb );               /* _ta = (X3,   Y3,   Z3,  T3   ), u62|u62|u62|u62 */ \
    FD_R43X6_QUAD_FOLD_UNSIGNED( P3, _ta );                     /* P3  = (X3,   Y3,   Z3,  T3   ), u44|u44|u44|u44 */ \
    FD_R43X6_GE_ZERO           ( _ta );                                                                               \
    FD_R43X6_GE_ZERO           ( _tb );                                                                               \
  } while(0)

/* fd_ed25519_point_add_secure computes r = a + b, and returns r.

   It's equivalent to fd_ed25519_point_add_with_opts( r, a, b, 1, 1, 0 ),
   i.e. it assumes that b is from a precomputation table.

   This implementation clears all temporary variables before exit.
   The intent is to avoid that an attacker can retrieve information about b,
   that was chosen in const time based on a secret value. */
FD_25519_INLINE void
fd_ed25519_point_add_secure( fd_ed25519_point_t *       restrict r,
                             fd_ed25519_point_t const * restrict a,
                             fd_ed25519_point_t const * restrict b ) {

  FD_R43X6_GE_ADD_TABLE_ALT( r->P, a->P, b->P );

  /* Sanitize */
}

/* fd_ed25519_point_if sets r = a0 if secret_cond, else r = a1.
   Equivalent to r = secret_cond ? a0 : a1.
   Note: this is const time, as the underlying wwl_if is const time. */
FD_25519_INLINE void
fd_ed25519_point_if( fd_ed25519_point_t * restrict r,
                     uchar const                   secret_cond, /* 0, 1 */
                     fd_ed25519_point_t const *    a0,
                     fd_ed25519_point_t const *    a1 ) {
  r->P03 = wwl_if( -secret_cond, a0->P03, a1->P03 );
  r->P14 = wwl_if( -secret_cond, a0->P14, a1->P14 );
  r->P25 = wwl_if( -secret_cond, a0->P25, a1->P25 );
}

/* fd_ed25519_point_neg_if sets r = -r if secret_cond, else r = r.
   Equivalent to r = secret_cond ? -r : r.
   Note: this is const time, as the underlying wwl_if is const time. */
FD_25519_INLINE void
fd_ed25519_point_neg_if( fd_ed25519_point_t * FD_RESTRICT r,
                         fd_ed25519_point_t * const       a,
                         uchar const                      secret_cond /* 0, 1 */ ) {
  FD_R43X6_QUAD_DECL( _p );
  _p03 = wwl( 8796093022189L, 8796093022189L, 8796093022189L, 8796093022189L, 8796093022207L, 8796093022207L, 8796093022207L, 8796093022207L );
  _p14 = wwl( 8796093022207L, 8796093022207L, 8796093022207L, 8796093022207L, 8796093022207L, 8796093022207L, 8796093022207L, 8796093022207L );
  _p25 = wwl( 8796093022207L, 8796093022207L, 8796093022207L, 8796093022207L, 1099511627775L, 1099511627775L, 1099511627775L, 1099511627775L );
  FD_R43X6_QUAD_LANE_SUB_FAST( r->P, a->P, 0,0,0,1, _p, a->P );
  FD_R43X6_QUAD_PERMUTE      ( r->P, 1,0,2,3, r->P );
  r->P03 = wwl_if( -secret_cond, r->P03, a->P03 );
  r->P14 = wwl_if( -secret_cond, r->P14, a->P14 );
  r->P25 = wwl_if( -secret_cond, r->P25, a->P25 );
}
