#include "fd_ed25519_private.h"

#if FD_ED25519_FE_IMPL == 0
#include "ref/fd_ed25519_ge.c"
#elif FD_ED25519_FE_IMPL == 1
#include "avx/fd_ed25519_ge.c"
#else
#error "Unsupported FD_ED25519_FE_IMPL"
#endif

static inline int
fd_ed25519_fe_eq( fd_ed25519_fe_t * const fe0,
                   fd_ed25519_fe_t * const fe1 ) {
  return ( fe0->limb[ 0 ] == fe1->limb[ 0 ] ) & ( fe0->limb[ 1 ] == fe1->limb[ 1 ] ) &
         ( fe0->limb[ 2 ] == fe1->limb[ 2 ] ) & ( fe0->limb[ 3 ] == fe1->limb[ 3 ] ) &
         ( fe0->limb[ 4 ] == fe1->limb[ 4 ] ) & ( fe0->limb[ 5 ] == fe1->limb[ 5 ] ) &
         ( fe0->limb[ 6 ] == fe1->limb[ 6 ] ) & ( fe0->limb[ 7 ] == fe1->limb[ 7 ] ) &
         ( fe0->limb[ 8 ] == fe1->limb[ 8 ] ) & ( fe0->limb[ 9 ] == fe1->limb[ 9 ] );
}

static inline void
fd_ed25519_ge_p3_mul_by_pow_2( fd_ed25519_ge_p3_t * ret,
                               fd_ed25519_ge_p3_t * const p,
                               uint k ) {
  /* If k is zero then return the original point p. [2^0]P = [1]P = P */
  if ( FD_UNLIKELY( k == 0 ) ) {
    *ret = *p;
    return;
  }
  fd_ed25519_ge_p1p1_t r[ 1 ];
  fd_ed25519_ge_p2_t   s[ 1 ];
  fd_ed25519_ge_p3_to_p2( s, p );
  for( uint i = 0; i < ( k - 1 ); i++ ) {
    fd_ed25519_ge_p2_dbl( r, s );
    fd_ed25519_ge_p1p1_to_p2( s, r );
  }
  fd_ed25519_ge_p2_dbl( r, s );
  fd_ed25519_ge_p1p1_to_p3( ret, r );
}

static inline int
fd_ed25519_ge_p3_is_identity( fd_ed25519_ge_p3_t * const p ) {
  fd_ed25519_ge_p3_t I[1];
  fd_ed25519_fe_0( I->X );
  fd_ed25519_fe_1( I->Y );
  fd_ed25519_fe_1( I->Z );
  fd_ed25519_fe_0( I->T );

  fd_ed25519_fe_t cmp[2];
  fd_ed25519_fe_mul( &cmp[ 0 ], p->X, I->Z );
  fd_ed25519_fe_mul( &cmp[ 1 ], I->X, p->Z );
  int x = fd_ed25519_fe_eq( &cmp[ 0 ], &cmp[ 1 ] );

  fd_ed25519_fe_mul( &cmp[ 0 ], p->Y, I->Z );
  fd_ed25519_fe_mul( &cmp[ 1 ], I->Y, p->Z );
  int y = fd_ed25519_fe_eq( &cmp[ 0 ], &cmp[ 1 ] );

  return x & y;
}

int
fd_ed25519_ge_p3_is_small_order( fd_ed25519_ge_p3_t * const p ) {
  fd_ed25519_ge_p3_t t[ 1 ];
  fd_ed25519_ge_p3_mul_by_pow_2( t, p, 3 );
  return fd_ed25519_ge_p3_is_identity( t );
}

uchar const *
fd_ed25519_scalar_validate( uchar const s[ static 32 ] ) {
  uchar r[ 32 ];
  fd_ed25519_sc_reduce( r, s );
  return (0==memcmp( r, s, 32 )) ? s : NULL;
}
