#include "fd_x25519.h"

#ifndef FD_X25519_IMPL
#if FD_HAS_AVX512
#define FD_X25519_IMPL 1
#else
#define FD_X25519_IMPL 0
#endif
#endif

#if FD_X25519_IMPL==0 /* Original scalar and AVX implementations */

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

#else /* AVX-512 accelerated implementation */

#include "avx512/fd_r43x6.h"

/* IETF RFC 7748 Section 5 (page 9) */

static void *
fd_x25519_scalar_mul( void *       _r,
                      void const * _k,
                      void const * _u ) {
  uchar const * k = (uchar const *)_k;

  fd_r43x6_t u = fd_r43x6_unpack( wv_ldu( _u ) ); // in u44

  FD_R43X6_QUAD_DECL( U );
  FD_R43X6_QUAD_DECL( Q );
  FD_R43X6_QUAD_PACK( U, fd_r43x6_zero(),
                         fd_r43x6_zero(),
                         fd_r43x6_zero(),
                         u );                           // x_1 = u, in u44
  FD_R43X6_QUAD_PACK( Q, fd_r43x6_one(),                // x_2 = 1, in u44
                         fd_r43x6_zero(),               // z_2 = 0, in u44
                         u,                             // x_3 = u, in u44
                         fd_r43x6_one() );              // z_3 = 1, in u44
  int swap = 0;

  for( int t=254UL; t>=0; t-- ) {                       // For t = bits-1 down to 0:

    /* At this point, Q and U in u44|u44|u44|u44 */

    int k_t = (k[t>>3] >> (t&7)) & 1;                   //   k_t = (k >> t) & 1;
    swap ^= k_t;                                        //   swap ^= k_t
    wwl_t perm = wwl_if( (-swap) & 0xff, wwl( 2L,3L,0L,1L, 6L,7L,4L,5L ), wwl( 0L,1L,2L,3L, 4L,5L,6L,7L ) );
    Q03 = wwl_permute( perm, Q03 );                     //   (x_2, x_3) = cswap(swap, x_2, x_3)
    Q14 = wwl_permute( perm, Q14 );                     //   (z_2, z_3) = cswap(swap, z_2, z_3)
    Q25 = wwl_permute( perm, Q25 );
    swap = k_t;                                         //   swap = k_t

    /* These operations are exactly from the RFC but have been reordered
       slightly to make it easier to extract ILP. */

    FD_R43X6_QUAD_DECL( P );
    fd_r43x6_t AA, E, F, G, H, GG;

    FD_R43X6_QUAD_PERMUTE      ( P, 0,0,2,2, Q );       // A = x_2 + z_2,            P  = x_2|x_2|x_3  |x_3,   in u44|u44|u44|u44
    FD_R43X6_QUAD_PERMUTE      ( Q, 1,1,3,3, Q );       // B = x_2 - z_2,            Q  = z_2|z_2|z_3  |z_3,   in u44|u44|u44|u44
    FD_R43X6_QUAD_LANE_ADD_FAST( P, P, 1,0,1,0, P, Q ); // C = x_3 + z_3,            P  = A  |x_2|C    |x_3,   in u45|u44|u45|u44
    FD_R43X6_QUAD_LANE_SUB_FAST( P, P, 0,1,0,1, P, Q ); // D = x_3 - z_3,            P  = A  |B  |C    |D,     in u45|s44|u45|s44
    FD_R43X6_QUAD_FOLD_SIGNED  ( P, P );                // AA = A^2,                 P  = A  |B  |C    |D,     in u44|u44|u44|u44
    FD_R43X6_QUAD_PERMUTE      ( Q, 0,1,1,0, P );       // BB = B^2,                 P  = A  |B  |B    |A,     in u44|u44|u44|u44
    FD_R43X6_QUAD_MUL_FAST     ( P, P, Q );             // DA = D * A,               P  = AA |BB |CB   |DA,    in u62|u62|u62|u62
    FD_R43X6_QUAD_PERMUTE      ( Q, 1,0,3,2, P );       // CB = C * B,               Q  = BB |AA |DA   |CB,    in u62|u62|u62|u62
    FD_R43X6_QUAD_LANE_SUB_FAST( P, P, 0,1,0,1, Q, P ); // E = AA-BB,                P  = AA |E  |CB   |CB-DA, in u62|s62|u62|s62
    FD_R43X6_QUAD_LANE_ADD_FAST( P, P, 0,0,1,0, P, Q ); //                           P  = AA |E  |DA+CB|CB-DA, in u62|s62|u63|s62
    FD_R43X6_QUAD_FOLD_SIGNED  ( P, P );                //                           P  = AA |E  |DA+CB|CB-DA, in u44|u44|u44|u44
    FD_R43X6_QUAD_LANE_IF      ( Q, 0,1,1,0, P, Q );    //                           Q  = BB |E  |DA+CB|CB,    in u62|u44|u44|u62
    FD_R43X6_QUAD_LANE_IF      ( Q, 0,0,0,1, U, Q );    // x_3 = (DA + CB)^2,        Q  = BB |E  |DA+CB|x_1,   in u62|u44|u44|u44
    FD_R43X6_QUAD_UNPACK       ( AA, E, F, G, P );
    H  = fd_r43x6_add_fast( AA, fd_r43x6_scale_fast( 121665L, E ) ); //              H  = AA + a24 * E,        in u60
    GG = fd_r43x6_sqr_fast( G );                        //                           GG = (DA - CB)^2,         in u61
    FD_R43X6_QUAD_PACK         ( P, AA, H, F, GG );     // z_2 = E * (AA + a24 * E), P  = AA |H  |DA+CB|GG,    in u44|u60|u44|u61
    FD_R43X6_QUAD_FOLD_UNSIGNED( P, P );                //                           P  = AA |H  |DA+CB|GG,    in u44|u44|u44|u44
    FD_R43X6_QUAD_FOLD_UNSIGNED( Q, Q );                //                           Q  = BB |AA |DA   |CB,    in u44|u44|u44|u44
    FD_R43X6_QUAD_MUL_FAST     ( P, P, Q );             // z_3 = x_1 * (DA - CB)^2,  Q  = x_2|z_2|x_3  |z_3,   in u62|u62|u62|u62
    FD_R43X6_QUAD_FOLD_UNSIGNED( Q, P    );             //                           Q  = x_2|z_2|x_3  |z_3,   in u44|u44|u44|u44
  }

  /* At this point, Q in u44|u44|u44|u44 */

  wwl_t perm = wwl_if( (-swap) & 0xff, wwl( 2L,3L,0L,1L, 6L,7L,4L,5L ), wwl( 0L,1L,2L,3L, 4L,5L,6L,7L ) );
  Q03 = wwl_permute( perm, Q03 );                       // (x_2, x_3) = cswap(swap, x_2, x_3)
  Q14 = wwl_permute( perm, Q14 );                       // (z_2, z_3) = cswap(swap, z_2, z_3)
  Q25 = wwl_permute( perm, Q25 );

  fd_r43x6_t x_2, z_2, x_3, z_3;
  FD_R43X6_QUAD_UNPACK( x_2, z_2, x_3, z_3, Q );
  (void)x_3; (void)z_3;
  wv_stu( _r, fd_r43x6_pack( fd_r43x6_mod_unreduced( fd_r43x6_mul( x_2, fd_r43x6_invert( z_2 ) ) ) ) );
  return _r;                                            // Return x_2 * (z_2^(p - 2))
}

void *
fd_x25519_exchange( void *       secret,
                    void const * self_private_key,
                    void const * peer_public_key ) {

  /* IETF RFC 7748 Section 5 (page 8) decodeScalar25519 (TODO: VECTORIZE?) */

  uchar scalar[ 32 ] __attribute__((aligned(32)));
  memcpy( scalar, self_private_key, 32UL );
  scalar[  0 ] = (uchar)( scalar[  0 ] & (uchar)248 );
  scalar[ 31 ] = (uchar)( scalar[ 31 ] & (uchar)127 );
  scalar[ 31 ] = (uchar)( scalar[ 31 ] | (uchar) 64 );

  fd_x25519_scalar_mul( secret, scalar, peer_public_key );

  return fd_ptr_if( wc_any( wv_to_wc( wv_ldu( secret ) ) ), secret, NULL ); /* Reject low order points */
}

void *
fd_x25519_public( void *       self_public_key,
                  void const * self_private_key ) {

  /* IETF RFC 7748 Section 4.1 (page 3) */

  static uchar const basepoint_u[ 32 ] __attribute__((aligned(32))) = {
    (uchar)9, (uchar)0, (uchar)0, (uchar)0, (uchar)0, (uchar)0, (uchar)0, (uchar)0,
    (uchar)0, (uchar)0, (uchar)0, (uchar)0, (uchar)0, (uchar)0, (uchar)0, (uchar)0,
    (uchar)0, (uchar)0, (uchar)0, (uchar)0, (uchar)0, (uchar)0, (uchar)0, (uchar)0,
    (uchar)0, (uchar)0, (uchar)0, (uchar)0, (uchar)0, (uchar)0, (uchar)0, (uchar)0,
  };

  return fd_x25519_exchange( self_public_key, self_private_key, basepoint_u );
}

#endif
