#include "fd_ed25519_private.h"

#if FD_ED25519_FE_IMPL == 0
#include "ref/fd_ed25519_ge.c"
#elif FD_ED25519_FE_IMPL == 1
#include "avx/fd_ed25519_ge.c"
#else
#error "Unsupported FD_ED25519_FE_IMPL"
#endif

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
  fd_ed25519_ge_p3_0(I);
  return fd_ed25519_ge_eq(p, I);
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
