#include "../fd_curve25519.h"
#include "./fd_r43x6_ge.h"

/* All the functions in this file are considered "secure", specifically:

   - Constant time in the input, i.e. the input can be a secret
   - Small and auditable code base, incl. simple types
   - No local variables = no need to clear them before exit
   - Clear registers via FD_FN_SENSITIVE
 */

/* FD_R43X6_GE_ADD_TABLE_ALT is similar to FD_R43X6_GE_ADD_TABLE,
   with 3 minor differences:
   1. order of arguments: P3, P2 points in extended Edwards coordinates,
      T1 precomputed table point
   2. T1 = (Y-X : Y+X : Z==1 : kT)
   3. temp vars as input, so we can safely clear them in the caller
*/
#define FD_R43X6_GE_ADD_TABLE_ALT( P3, P2, T1, _ta, _tb ) do {                                                                  \
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
  } while(0)

/* fd_ed25519_point_add_secure computes r = a + b.

   It's equivalent to fd_ed25519_point_add_with_opts( r, a, b, 1, 1, 0 ),
   i.e. it assumes that b is from a precomputation table.

   This implementation has no temporary variables and clears registers on return.
   The intent is to avoid that an attacker can retrieve information about b,
   that was chosen in const time based on a secret value. */
FD_25519_INLINE void FD_FN_SENSITIVE
fd_ed25519_point_add_secure( fd_ed25519_point_t *       restrict r,
                             fd_ed25519_point_t const * restrict a,
                             fd_ed25519_point_t const * restrict b,
                             fd_ed25519_point_t *       restrict tmp0,
                             fd_ed25519_point_t *       restrict tmp1 ) {

  FD_R43X6_GE_ADD_TABLE_ALT( r->P, a->P, b->P, tmp0->P, tmp1->P );

}

/* FD_R43X6_GE_DBL_ALT is similar to FD_R43X6_GE_DBL,
   with 2 minor differences:
   1. removed _BB, by reordering instructions
   2. temp vars as input, so we can safely clear them in the caller
*/
#define FD_R43X6_GE_DBL_ALT( P3, P1, _ta, _tb ) do {                                                                              \
    FD_R43X6_QUAD_PERMUTE      ( _ta, 1,1,2,0, P1 );            /* _ta = (Y1,       Y1,Z1,  X1), u44/u44/u44/u44 */ \
    FD_R43X6_QUAD_LANE_ADD_FAST( _ta, _ta, 1,0,0,0, _ta, P1 );  /* _ta = (X1+Y1,    Y1,Z1,  X1), u45/u44/u44/u44 */ \
    FD_R43X6_QUAD_SQR_FAST     ( _ta, _ta );                    /* _ta = ((X1+Y1)^2,B, Z1^2,A ), u61/u61/u61/u61 */ \
    FD_R43X6_QUAD_FOLD_UNSIGNED( _ta, _ta );                    /* _ta = ((X1+Y1)^2,B, Z1^2,A ), u44/u44/u44/u44 */ \
    FD_R43X6_QUAD_LANE_ADD_FAST( _ta, _ta, 0,0,1,0, _ta, _ta ); /* _ta = ((X1+Y1)^2,B, C,   A ), u44/u44/u45/u44 */ \
    FD_R43X6_QUAD_PERMUTE      ( _tb, 3,3,3,3, _ta );           /* _tb = (A,        A, A,   A ), u44/u44/u44/u44 */ \
    FD_R43X6_QUAD_LANE_ADD_FAST( _tb, _tb, 0,0,1,0, _tb, _ta ); /* _tb = (A,        A, A+C, A ), u44/u44/u45/u44 */ \
    FD_R43X6_QUAD_LANE_SUB_FAST( _tb, _tb, 1,0,0,0, _tb, _ta ); /* _tb = (A-(sum)^2,A, A+C, A ), u45/u44/u45/u44 */ \
    FD_R43X6_QUAD_PERMUTE      ( _ta, 1,1,1,1, _ta );           /* _ta = (B,        B, B,   B ), u44/u44/u44/u44 */ \
    FD_R43X6_QUAD_LANE_ADD_FAST( _tb, _tb, 1,0,0,1, _tb, _ta ); /* _tb = (E,        A, A+C, H ), u46/u44/u45/u45 */ \
    FD_R43X6_QUAD_LANE_SUB_FAST( _tb, _tb, 0,1,1,0, _tb, _ta ); /* _tb = (E,        G, F,   H ), u46/u45/u46/u45 */ \
    FD_R43X6_QUAD_PERMUTE      ( _ta, 0,1,1,0, _tb );           /* _tb = (E,        G, G,   E ), u46/u45/u45/u46 */ \
    FD_R43X6_QUAD_PERMUTE      ( _tb, 2,3,2,3, _tb );           /* _tb = (F,        H, F,   H ), u46/u45/u46/u45 */ \
    FD_R43X6_QUAD_MUL_FAST     ( _ta, _ta, _tb );               /* _ta = (X3,       Y3,Z3,  T3), u62/u62/u62/u62 */ \
    FD_R43X6_QUAD_FOLD_UNSIGNED( P3, _ta );                     /* P3  = (X3,       Y3,Z3,  T3), u44/u44/u44/u44 */ \
  } while(0)

/* fd_ed25519_point_dbln_secure computes r = 2^n a.

   It's equivalent to fd_ed25519_point_dbln( r, a, n ).

   This implementation has no temporary variables and clears registers on return.
   The intent is to avoid that an attacker can retrieve information about a,
   that's a partial aggregation of secretly chosen points. */
FD_25519_INLINE void FD_FN_SENSITIVE
fd_ed25519_point_dbln_secure( fd_ed25519_point_t *       r,
                              fd_ed25519_point_t const * a,
                              int                        n,
                              fd_ed25519_point_t *       restrict tmp0,
                              fd_ed25519_point_t *       restrict tmp1 ) {
  FD_R43X6_GE_DBL_ALT( r->P, a->P, tmp0->P, tmp1->P );
  for( uchar i=1; i<n; i++ ) {
    FD_R43X6_GE_DBL_ALT( r->P, r->P, tmp0->P, tmp1->P );
  }
}

/* fd_ed25519_point_if sets r = a0 if secret_cond, else r = a1.
   Equivalent to r = secret_cond ? a0 : a1.
   Note: this is const time, as the underlying wwl_if is const time. */
FD_25519_INLINE void FD_FN_SENSITIVE
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
FD_25519_INLINE void FD_FN_SENSITIVE
fd_ed25519_point_neg_if( fd_ed25519_point_t * FD_RESTRICT r,
                         fd_ed25519_point_t * const       a,
                         uchar const                      secret_cond /* 0, 1 */ ) {
  FD_R43X6_QUAD_DECL( _p );
  _p03 = wwl( 8796093022189L, 8796093022189L, 8796093022189L, 8796093022189L, 8796093022207L, 8796093022207L, 8796093022207L, 8796093022207L );
  _p14 = wwl( 8796093022207L, 8796093022207L, 8796093022207L, 8796093022207L, 8796093022207L, 8796093022207L, 8796093022207L, 8796093022207L );
  _p25 = wwl( 8796093022207L, 8796093022207L, 8796093022207L, 8796093022207L, 1099511627775L, 1099511627775L, 1099511627775L, 1099511627775L );
  r->P03 = wwv_sub_if( 136, _p03, a->P03, a->P03 );
  r->P14 = wwv_sub_if( 136, _p14, a->P14, a->P14 );
  r->P25 = wwv_sub_if( 136, _p25, a->P25, a->P25 );
  FD_R43X6_QUAD_PERMUTE( r->P, 1,0,2,3, r->P );
  r->P03 = wwl_if( -secret_cond, r->P03, a->P03 );
  r->P14 = wwl_if( -secret_cond, r->P14, a->P14 );
  r->P25 = wwl_if( -secret_cond, r->P25, a->P25 );
}
