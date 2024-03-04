#include "fd_x25519.h"
#include "fd_f25519.h"

/* FD_X25519_VECTORIZE calls mul4 instead of sqr2+mul2, and similar.
   Only useful if the underlying ops are actually vectorized and therefore
   the cost of 4 muls is <= the cost of 2 sqr + 2 mul. */
#define FD_X25519_VECTORIZE FD_HAS_AVX512

/* FD_X25519_ALIGN aligns variables. */
#if FD_HAS_AVX
#define FD_X25519_ALIGN __attribute__((aligned(32)))
#else
#define FD_X25519_ALIGN
#endif

/*
 * Constant time primitives
 */

static inline int
fd_x25519_is_zero_const_time( uchar const point[ static 32 ] ) {
  //TODO: this is generally done by (x)or-ing the limbs, see also RFC 7748, page 13.
  int is_zero = 1;
  for( ulong i=0UL; i<32UL; i++ ) {
    is_zero &= ( !point[ i ] );
  }
  return is_zero;
}

#if !FD_HAS_AVX512

static inline void
fd_x25519_montgomery_ladder( fd_f25519_t *       x2,
                             fd_f25519_t *       z2,
                             fd_f25519_t const * x1,
                             uchar const *       secret_scalar ) {
  fd_f25519_t x3[1], z3[1];
  fd_f25519_t tmp0[1], tmp1[1];

  fd_f25519_set( x2, fd_f25519_one );
  fd_f25519_set( z2, fd_f25519_zero );

  fd_f25519_set( x3, x1 );
  fd_f25519_set( z3, fd_f25519_one );

  int swap = 0;
  int b = 0;
  for( long pos=254UL; pos>=0; pos-- ) {
    b = secret_scalar[ pos / 8L ] >> ( pos & 7L );
    b &= 1;
    swap ^= b;
    fd_f25519_swap_if( x2, x3, swap );
    fd_f25519_swap_if( z2, z3, swap );
    swap = b;

    fd_f25519_sub_nr( tmp0, x3,   z3   );
    fd_f25519_sub_nr( tmp1, x2,   z2   );
    fd_f25519_add_nr( x2,   x2,   z2   );
    fd_f25519_add_nr( z2,   x3,   z3   );

#   if FD_X25519_VECTORIZE /* Note that okay to use less efficient squaring because we get it for free in unused vector lanes */
    fd_f25519_mul4( z3,   tmp0, x2,
                    z2,   z2,   tmp1,
                    tmp0, tmp1, tmp1,
                    tmp1, x2,   x2   );
#   else /* Use more efficient squaring if scalar implementation */
    fd_f25519_mul2( z3,   tmp0, x2,
                    z2,   z2,   tmp1 );
    fd_f25519_sqr2( tmp0, tmp1,
                    tmp1, x2         );
#   endif
    fd_f25519_add_nr( x3,   z3,   z2 );
    fd_f25519_sub_nr( z2,   z3,   z2 );
#   if FD_X25519_VECTORIZE /* See note above */
    fd_f25519_mul2( x2,   tmp1, tmp0,
                    z2,   z2,   z2   );
#   else
    fd_f25519_mul(  x2,   tmp1, tmp0 );
    fd_f25519_sqr(  z2,   z2         );
#   endif
    fd_f25519_sub_nr( tmp1, tmp1, tmp0 );

    fd_f25519_mul_121666( z3, tmp1 );

    fd_f25519_add_nr( tmp0, tmp0, z3   );
#   if FD_X25519_VECTORIZE /* See note above */
    fd_f25519_mul3( x3,   x3,   x3,
                    z3,   x1,   z2,
                    z2,   tmp0, tmp1 );
#   else
    fd_f25519_sqr ( x3,   x3         );
    fd_f25519_mul2( z3,   x1,   z2,
                    z2,   tmp1, tmp0 );
#   endif
  }

  fd_f25519_swap_if( x2, x3, swap );
  fd_f25519_swap_if( z2, z3, swap );

  /* Sanitize */

  fd_f25519_set( x3,   fd_f25519_zero );
  fd_f25519_set( z3,   fd_f25519_zero );
  fd_f25519_set( tmp0, fd_f25519_zero );
  fd_f25519_set( tmp1, fd_f25519_zero );
  b = 0;
  swap = 0;
}
#else

/* This is the "transposed" version of the Montgomery ladder above.
   Experimentally, this is 15-20% faster on AVX-512. */
static inline void
fd_x25519_montgomery_ladder( fd_f25519_t *       x2,
                             fd_f25519_t *       z2,
                             fd_f25519_t const * x1,
                             uchar const *       secret_scalar ) {
  FD_R43X6_QUAD_DECL( U );
  FD_R43X6_QUAD_DECL( Q );
  FD_R43X6_QUAD_PACK( U, fd_r43x6_zero(),
                         fd_r43x6_zero(),
                         fd_r43x6_zero(),
                         x1->el );                      // x_1 = u, in u44
  FD_R43X6_QUAD_PACK( Q, fd_r43x6_one(),                // x_2 = 1, in u44
                         fd_r43x6_zero(),               // z_2 = 0, in u44
                         x1->el,                        // x_3 = u, in u44
                         fd_r43x6_one() );              // z_3 = 1, in u44
  int swap = 0;
  wwl_t perm;
  fd_r43x6_t AA, E, F, G, H, GG;

  for( int t=254UL; t>=0; t-- ) {                       // For t = bits-1 down to 0:

    /* At this point, Q and U in u44|u44|u44|u44 */

    int k_t = (secret_scalar[t>>3] >> (t&7)) & 1;       //   k_t = (k >> t) & 1;
    swap ^= k_t;                                        //   swap ^= k_t
    perm = wwl_if( (-swap) & 0xff, wwl( 2L,3L,0L,1L, 6L,7L,4L,5L ), wwl( 0L,1L,2L,3L, 4L,5L,6L,7L ) );
    Q03 = wwl_permute( perm, Q03 );                     //   (x_2, x_3) = cswap(swap, x_2, x_3)
    Q14 = wwl_permute( perm, Q14 );                     //   (z_2, z_3) = cswap(swap, z_2, z_3)
    Q25 = wwl_permute( perm, Q25 );
    swap = k_t;                                         //   swap = k_t

    /* These operations are exactly from the RFC but have been reordered
       slightly to make it easier to extract ILP. */

    FD_R43X6_QUAD_DECL( P );

    FD_R43X6_QUAD_PERMUTE      ( P, 0,0,2,2, Q );       // A = x_2 + z_2,            P  = x_2|x_2|x_3  |x_3,   in u44|u44|u44|u44
    FD_R43X6_QUAD_PERMUTE      ( Q, 1,1,3,3, Q );       // B = x_2 - z_2,            Q  = z_2|z_2|z_3  |z_3,   in u44|u44|u44|u44
    FD_R43X6_QUAD_LANE_ADD_FAST( P, P, 1,0,1,0, P, Q ); // C = x_3 + z_3,            P  = A  |x_2|C    |x_3,   in u45|u44|u45|u44
    FD_R43X6_QUAD_LANE_SUB_FAST( P, P, 0,1,0,1, P, Q ); // D = x_3 - z_3,            P  = A  |B  |C    |D,     in u45|s44|u45|s44
    FD_R43X6_QUAD_PERMUTE      ( Q, 0,1,1,0, P );       // BB = B^2,                 P  = A  |B  |B    |A,     in u44|u44|u44|u44
    FD_R43X6_QUAD_MUL_FAST     ( P, P, Q );             // DA = D * A,               P  = AA |BB |CB   |DA,    in u62|u62|u62|u62
    FD_R43X6_QUAD_FOLD_UNSIGNED( P, P );                // DA = D * A,               P  = AA |BB |CB   |DA,    in u44|u44|u44|u44
    FD_R43X6_QUAD_PERMUTE      ( Q, 1,0,3,2, P );       // CB = C * B,               Q  = BB |AA |DA   |CB,    in u62|u62|u62|u62
    FD_R43X6_QUAD_LANE_SUB_FAST( P, P, 0,1,0,1, Q, P ); // E = AA-BB,                P  = AA |E  |CB   |CB-DA, in u62|s62|u62|s62
    FD_R43X6_QUAD_LANE_ADD_FAST( P, P, 0,0,1,0, P, Q ); //                           P  = AA |E  |DA+CB|CB-DA, in u62|s62|u63|s62
    FD_R43X6_QUAD_LANE_IF      ( Q, 0,1,1,0, P, Q );    //                           Q  = BB |E  |DA+CB|CB,    in u62|u44|u44|u62
    FD_R43X6_QUAD_LANE_IF      ( Q, 0,0,0,1, U, Q );    // x_3 = (DA + CB)^2,        Q  = BB |E  |DA+CB|x_1,   in u62|u44|u44|u44
    FD_R43X6_QUAD_UNPACK       ( AA, E, F, G, P );
    H  = fd_r43x6_add_fast( AA, fd_r43x6_scale_fast( 121665L, E ) ); //              H  = AA + a24 * E,        in u60
    GG = fd_r43x6_sqr_fast( G );                        //                           GG = (DA - CB)^2,         in u61
    FD_R43X6_QUAD_PACK         ( P, AA, H, F, GG );     // z_2 = E * (AA + a24 * E), P  = AA |H  |DA+CB|GG,    in u44|u60|u44|u61
    FD_R43X6_QUAD_FOLD_UNSIGNED( P, P );                //                           P  = AA |H  |DA+CB|GG,    in u44|u44|u44|u44
    FD_R43X6_QUAD_MUL_FAST     ( P, P, Q );             // z_3 = x_1 * (DA - CB)^2,  Q  = x_2|z_2|x_3  |z_3,   in u62|u62|u62|u62
    FD_R43X6_QUAD_FOLD_UNSIGNED( Q, P    );             //                           Q  = x_2|z_2|x_3  |z_3,   in u44|u44|u44|u44
  }

  /* At this point, Q in u44|u44|u44|u44 */

  perm = wwl_if( (-swap) & 0xff, wwl( 2L,3L,0L,1L, 6L,7L,4L,5L ), wwl( 0L,1L,2L,3L, 4L,5L,6L,7L ) );
  Q03 = wwl_permute( perm, Q03 );                       // (x_2, x_3) = cswap(swap, x_2, x_3)
  Q14 = wwl_permute( perm, Q14 );                       // (z_2, z_3) = cswap(swap, z_2, z_3)
  Q25 = wwl_permute( perm, Q25 );

  FD_R43X6_QUAD_UNPACK( x2->el, z2->el, E, F, Q );

  /* Sanitize */

  AA = wwl_zero();
  E  = wwl_zero();
  F  = wwl_zero();
  G  = wwl_zero();
  H  = wwl_zero();
  GG = wwl_zero();
  perm = wwl_zero();
  swap = 0;
}
#endif

/*
 * X25519 Protocol
 */

static inline void
fd_x25519_scalar_mul_const_time( uchar               out[ static 32 ],
                                 uchar const *       secret_scalar,
                                 fd_f25519_t const * point_x ) {
  fd_f25519_t x2[1], z2[1];

  fd_x25519_montgomery_ladder( x2, z2, point_x, secret_scalar );

  fd_f25519_inv( z2, z2 );
  fd_f25519_mul( x2, x2, z2 );

  fd_f25519_tobytes( out, x2 );
}

static const uchar fd_x25519_basepoint[ 32 ] FD_X25519_ALIGN = { 9 };

uchar *
fd_x25519_public( uchar       self_public_key [ static 32 ],
                  uchar const self_private_key[ static 32 ] ) {
  /* IETF RFC 7748 Section 4.1 (page 3) */
  return fd_x25519_exchange( self_public_key, self_private_key, fd_x25519_basepoint );
}

uchar *
fd_x25519_exchange( uchar       shared_secret   [ static 32 ],
                    uchar const self_private_key[ static 32 ],
                    uchar const peer_public_key [ static 32 ] ) {

  uchar secret_scalar[ 32UL ] FD_X25519_ALIGN;
  fd_f25519_t peer_public_key_point_x[1];

  /* IETF RFC 7748 Section 5 (page 7): decodeScalar25519 */
  memcpy( secret_scalar, self_private_key, 32UL );
  secret_scalar[  0 ] = (uchar)( secret_scalar[  0 ] & 0xf8 );
  secret_scalar[ 31 ] = (uchar)( secret_scalar[ 31 ] & 0x7f );
  secret_scalar[ 31 ] = (uchar)( secret_scalar[ 31 ] | 0x40 );

  fd_f25519_frombytes( peer_public_key_point_x, peer_public_key );

  fd_x25519_scalar_mul_const_time( shared_secret, secret_scalar, peer_public_key_point_x );

  /* Sanitize */
  fd_memset( secret_scalar, 0, 32UL );

  /* Reject low order points */
  if( FD_UNLIKELY( fd_x25519_is_zero_const_time( shared_secret ) ) ) {
    return NULL;
  }

  return shared_secret;
}
