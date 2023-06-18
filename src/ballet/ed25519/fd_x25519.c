#include "fd_x25519.h"
#include "fd_ed25519_private.h"

#ifndef FD_X25519_VECTORIZE
#if FD_ED25519_FE_IMPL==1
#define FD_X25519_VECTORIZE 1
#else
#define FD_X25519_VECTORIZE 0
#endif
#endif

/* fd_x25519_basepoint is the canonical Curve25519 base point. */

static uchar const fd_x25519_basepoint[ 32 ] = { 9 };

static void *
fd_x25519_scalar_mul( void * dst,
                      void const * scalar,
                      void const * point ) {

  uchar e[ 32UL ];
  memcpy( e, scalar, 32UL );
  e[  0 ] = (uchar)( e[  0 ] & 0xf8 );
  e[ 31 ] = (uchar)( e[ 31 ] & 0x7f );
  e[ 31 ] = (uchar)( e[ 31 ] | 0x40 );

  fd_ed25519_fe_t x1;
  fd_ed25519_fe_frombytes( &x1, point );

  fd_ed25519_fe_t x2;
  fd_ed25519_fe_1( &x2 );

  fd_ed25519_fe_t x3;
  fd_ed25519_fe_copy( &x3, &x1 );

  fd_ed25519_fe_t z2={0};
  fd_ed25519_fe_t z3;
  fd_ed25519_fe_1( &z3 );

  fd_ed25519_fe_t tmp0;
  fd_ed25519_fe_t tmp1;

  int swap = 0;
  for( long pos=254UL; pos>=0; pos-- ) {
    int b = e[ pos / 8L ] >> ( pos & 7L );
    b &= 1;
    swap ^= b;
    fd_ed25519_fe_swap_if( &x2, &x3, swap );
    fd_ed25519_fe_swap_if( &z2, &z3, swap );
    swap = b;

    fd_ed25519_fe_sub( &tmp0, &x3,   &z3   );
    fd_ed25519_fe_sub( &tmp1, &x2,   &z2   );
    fd_ed25519_fe_add( &x2,   &x2,   &z2   );
    fd_ed25519_fe_add( &z2,   &x3,   &z3   );

#   if FD_X25519_VECTORIZE /* Note that okay to use less efficient squaring because we get it for free in unused vector lanes */
    fd_ed25519_fe_mul4( &z3,   &tmp0, &x2,
                        &z2,   &z2,   &tmp1,
                        &tmp0, &tmp1, &tmp1,
                        &tmp1, &x2,   &x2   );
#   else /* Use more efficient squaring if scalar implementation */
    fd_ed25519_fe_mul( &z3,   &tmp0, &x2   );
    fd_ed25519_fe_mul( &z2,   &z2,   &tmp1 );
    fd_ed25519_fe_sq ( &tmp0, &tmp1        );
    fd_ed25519_fe_sq ( &tmp1, &x2          );
#   endif
    fd_ed25519_fe_add( &x3,   &z3,   &z2   );
    fd_ed25519_fe_sub( &z2,   &z3,   &z2   );
#   if FD_X25519_VECTORIZE /* See note above */
    fd_ed25519_fe_mul2( &x2,   &tmp1, &tmp0,
                        &z2,   &z2,   &z2   );
#   else
    fd_ed25519_fe_mul( &x2,   &tmp1, &tmp0 );
    fd_ed25519_fe_sq ( &z2,   &z2          );
#   endif
    fd_ed25519_fe_sub( &tmp1, &tmp1, &tmp0 );

    fd_ed25519_fe_mul121666( &z3, &tmp1 );
    fd_ed25519_fe_add( &tmp0, &tmp0, &z3   );
#   if FD_X25519_VECTORIZE /* See note above */
    fd_ed25519_fe_mul3( &x3,   &x3,   &x3,
                        &z3,   &x1,   &z2,
                        &z2,   &tmp1, &tmp0 );
#   else
    fd_ed25519_fe_sq ( &x3,   &x3          );
    fd_ed25519_fe_mul( &z3,   &x1,   &z2   );
    fd_ed25519_fe_mul( &z2,   &tmp1, &tmp0 );
#   endif
  }

  fd_ed25519_fe_swap_if( &x2, &x3, swap );
  fd_ed25519_fe_swap_if( &z2, &z3, swap );

  fd_ed25519_fe_invert( &z2, &z2 );
  fd_ed25519_fe_mul( &x2, &x2, &z2 );

  fd_ed25519_fe_tobytes( (uchar *)dst, &x2 );
  return dst;
}

void *
fd_x25519_public( void *       self_public_key,
                  void const * self_private_key ) {
  fd_x25519_exchange( self_public_key, self_private_key, fd_x25519_basepoint );
  return self_public_key;
}

void *
fd_x25519_exchange( void *       secret,
                    void const * self_private_key,
                    void const * peer_public_key ) {

  fd_x25519_scalar_mul( secret, self_private_key, peer_public_key );
  uchar * out = (uchar *)secret;

  /* Reject low order points */
  int is_zero = 1;
  for( ulong i=0UL; i<32UL; i++ )
    is_zero &= ( !out[ i ] );
  if( FD_UNLIKELY( is_zero ) )
    return NULL;

  return out;
}

