#include "fd_vinyl_bstream.h"
#if !FD_HAS_AVX512
#error "fd_hash_avx512dq requires AVX-512"
#endif

#include "../../util/simd/fd_avx512.h"
#include "../../util/simd/fd_avx.h"

/* Bases t/f just on the leading bit of c */
#define w_if( c, t, f ) _mm256_castpd_si256( _mm256_blendv_pd( _mm256_castsi256_pd( (f) ), \
                                                               _mm256_castsi256_pd( (t) ), \
                                                               _mm256_castsi256_pd( (c) ) ) )

/* Given (a0, a1, a2, a3) and (b0, b1, b2, b3), constructs
   ( c0?a0:a1, c1?b0:b1, c2?a2:a3, c3?b2:b3 ) */
#define wv_shuffle( c0,c1,c2,c3, a, b ) _mm256_castpd_si256( _mm256_shuffle_pd( _mm256_castsi256_pd( (a) ), \
                                                                                _mm256_castsi256_pd( (b) ), \
                                                                                ((!c0)<<0)|((!c1)<<1)|((!c2)<<2)|((!c3)<<3) ) )
#define wv_mul(a,b)  _mm256_mullo_epi64( (a), (b) ) /* [ a0 *b0     a1 *b1     ... a3 *b3     ] */

FD_FN_PURE void
fd_vinyl_bstream_hash_batch8( ulong                                  seed_,
                              ulong *                    FD_RESTRICT out,
                              void const * FD_RESTRICT * FD_RESTRICT buf_,
                              ulong const *              FD_RESTRICT sz_ ) {
#define C1 (11400714785074694791UL)
#define C2 (14029467366897019727UL)
#define C3 ( 1609587929392839161UL)
#define C4 ( 9650029242287828579UL)
#define C5 ( 2870177450012600261UL)

  wv_t const CC1 = wv_bcast( C1 );
  wv_t const CC2 = wv_bcast( C2 );

  wv_t const init = wv_add( wv_bcast( seed_ ), wv( C1+C2, C2, 0UL, -C1 ) );

  ulong dummy[4] = { 0UL }; /* used if sz_[i]==0 for any */

  /* Vi = ( w_i, x_i, y_i, z_i ) */
  wv_t V0 = init;    wl_t r0 = wl_bcast( (long)sz_[0]-1L );    uchar const * p0 = fd_ptr_if( !!sz_[0], buf_[0], dummy );
  wv_t V1 = init;    wl_t r1 = wl_bcast( (long)sz_[1]-1L );    uchar const * p1 = fd_ptr_if( !!sz_[1], buf_[1], dummy );
  wv_t V2 = init;    wl_t r2 = wl_bcast( (long)sz_[2]-1L );    uchar const * p2 = fd_ptr_if( !!sz_[2], buf_[2], dummy );
  wv_t V3 = init;    wl_t r3 = wl_bcast( (long)sz_[3]-1L );    uchar const * p3 = fd_ptr_if( !!sz_[3], buf_[3], dummy );
  wv_t V4 = init;    wl_t r4 = wl_bcast( (long)sz_[4]-1L );    uchar const * p4 = fd_ptr_if( !!sz_[4], buf_[4], dummy );
  wv_t V5 = init;    wl_t r5 = wl_bcast( (long)sz_[5]-1L );    uchar const * p5 = fd_ptr_if( !!sz_[5], buf_[5], dummy );
  wv_t V6 = init;    wl_t r6 = wl_bcast( (long)sz_[6]-1L );    uchar const * p6 = fd_ptr_if( !!sz_[6], buf_[6], dummy );
  wv_t V7 = init;    wl_t r7 = wl_bcast( (long)sz_[7]-1L );    uchar const * p7 = fd_ptr_if( !!sz_[7], buf_[7], dummy );


  ulong max_sz = 0UL;
  for( ulong i=0UL; i<8UL; i++ ) max_sz = fd_ulong_max( max_sz, sz_[i] );

  for( ulong j=0UL; j<max_sz; j+=32UL ) {
    wv_t v0 = wv_add( V0, wv_mul( CC2, wv_ldu( p0 ) ) );   v0 = wv_mul( wv_rol( v0, 31 ), CC1 );    V0 = w_if( r0, V0, v0 );
    wv_t v1 = wv_add( V1, wv_mul( CC2, wv_ldu( p1 ) ) );   v1 = wv_mul( wv_rol( v1, 31 ), CC1 );    V1 = w_if( r1, V1, v1 );
    wv_t v2 = wv_add( V2, wv_mul( CC2, wv_ldu( p2 ) ) );   v2 = wv_mul( wv_rol( v2, 31 ), CC1 );    V2 = w_if( r2, V2, v2 );
    wv_t v3 = wv_add( V3, wv_mul( CC2, wv_ldu( p3 ) ) );   v3 = wv_mul( wv_rol( v3, 31 ), CC1 );    V3 = w_if( r3, V3, v3 );
    wv_t v4 = wv_add( V4, wv_mul( CC2, wv_ldu( p4 ) ) );   v4 = wv_mul( wv_rol( v4, 31 ), CC1 );    V4 = w_if( r4, V4, v4 );
    wv_t v5 = wv_add( V5, wv_mul( CC2, wv_ldu( p5 ) ) );   v5 = wv_mul( wv_rol( v5, 31 ), CC1 );    V5 = w_if( r5, V5, v5 );
    wv_t v6 = wv_add( V6, wv_mul( CC2, wv_ldu( p6 ) ) );   v6 = wv_mul( wv_rol( v6, 31 ), CC1 );    V6 = w_if( r6, V6, v6 );
    wv_t v7 = wv_add( V7, wv_mul( CC2, wv_ldu( p7 ) ) );   v7 = wv_mul( wv_rol( v7, 31 ), CC1 );    V7 = w_if( r7, V7, v7 );

    wl_t sub32 = wl_bcast( -32L );
    wl_t neg1  = wl_bcast( -1L );

    /* We want to do a subtraction that clamps at -1. Shockingly wl_max
       is not a single-cycle instruction, but we can just do a blend. */
    r0 = wv_add( r0, sub32 );   r0 = w_if( r0, neg1, r0 );   p0 = fd_ptr_if( sz_[0]<j+32UL, p0, p0+32UL );
    r1 = wv_add( r1, sub32 );   r1 = w_if( r1, neg1, r1 );   p1 = fd_ptr_if( sz_[1]<j+32UL, p1, p1+32UL );
    r2 = wv_add( r2, sub32 );   r2 = w_if( r2, neg1, r2 );   p2 = fd_ptr_if( sz_[2]<j+32UL, p2, p2+32UL );
    r3 = wv_add( r3, sub32 );   r3 = w_if( r3, neg1, r3 );   p3 = fd_ptr_if( sz_[3]<j+32UL, p3, p3+32UL );
    r4 = wv_add( r4, sub32 );   r4 = w_if( r4, neg1, r4 );   p4 = fd_ptr_if( sz_[4]<j+32UL, p4, p4+32UL );
    r5 = wv_add( r5, sub32 );   r5 = w_if( r5, neg1, r5 );   p5 = fd_ptr_if( sz_[5]<j+32UL, p5, p5+32UL );
    r6 = wv_add( r6, sub32 );   r6 = w_if( r6, neg1, r6 );   p6 = fd_ptr_if( sz_[6]<j+32UL, p6, p6+32UL );
    r7 = wv_add( r7, sub32 );   r7 = w_if( r7, neg1, r7 );   p7 = fd_ptr_if( sz_[7]<j+32UL, p7, p7+32UL );
  }

  /* In preparation for the final steps, we need to transpose
     everything.  Start by renaming to make the transpose more clear. */
  wv_t w0x0y0z0 = V0;   wv_t w1x1y1z1 = V1;   wv_t w2x2y2z2 = V2;   wv_t w3x3y3z3 = V3;
  wv_t w4x4y4z4 = V4;   wv_t w5x5y5z5 = V5;   wv_t w6x6y6z6 = V6;   wv_t w7x7y7z7 = V7;

  wv_t w0w1y0y1 = wv_shuffle( 1, 1, 1, 1, w0x0y0z0, w1x1y1z1 );   wv_t w4w5y4y5 = wv_shuffle( 1, 1, 1, 1, w4x4y4z4, w5x5y5z5 );
  wv_t x0x1z0z1 = wv_shuffle( 0, 0, 0, 0, w0x0y0z0, w1x1y1z1 );   wv_t x4x5z4z5 = wv_shuffle( 0, 0, 0, 0, w4x4y4z4, w5x5y5z5 );
  wv_t w2w3y2y3 = wv_shuffle( 1, 1, 1, 1, w2x2y2z2, w3x3y3z3 );   wv_t w6w7y6y7 = wv_shuffle( 1, 1, 1, 1, w6x6y6z6, w7x7y7z7 );
  wv_t x2x3z2z3 = wv_shuffle( 0, 0, 0, 0, w2x2y2z2, w3x3y3z3 );   wv_t x6x7z6z7 = wv_shuffle( 0, 0, 0, 0, w6x6y6z6, w7x7y7z7 );

  /* On Zen 4, _mm256_inserti128_si256 is only 1 cycle. On Intel, it's
     3, and on Zen 5, it is 2. On the whole, it's still better than
     _mm256_permute2x128_si256, so we'll use it where we can. */
  wv_t w0w1w2w3 = _mm256_inserti128_si256( w0w1y0y1, _mm256_castsi256_si128( w2w3y2y3 ), 1 );
  wv_t x0x1x2x3 = _mm256_inserti128_si256( x0x1z0z1, _mm256_castsi256_si128( x2x3z2z3 ), 1 );

  wv_t y0y1y2y3 = _mm256_permute2x128_si256( w0w1y0y1, w2w3y2y3, 0x31 );
  wv_t z0z1z2z3 = _mm256_permute2x128_si256( x0x1z0z1, x2x3z2z3, 0x31 );

  wv_t w4w5w6w7 = _mm256_inserti128_si256( w4w5y4y5, _mm256_castsi256_si128( w6w7y6y7 ), 1 );
  wv_t x4x5x6x7 = _mm256_inserti128_si256( x4x5z4z5, _mm256_castsi256_si128( x6x7z6z7 ), 1 );
  wv_t y4y5y6y7 = _mm256_permute2x128_si256( w4w5y4y5, w6w7y6y7, 0x31 );
  wv_t z4z5z6z7 = _mm256_permute2x128_si256( x4x5z4z5, x6x7z6z7, 0x31 );

  wwv_t w0to7 = _mm512_inserti32x8( _mm512_castsi256_si512( w0w1w2w3 ), w4w5w6w7, 1 );
  wwv_t x0to7 = _mm512_inserti32x8( _mm512_castsi256_si512( x0x1x2x3 ), x4x5x6x7, 1 );
  wwv_t y0to7 = _mm512_inserti32x8( _mm512_castsi256_si512( y0y1y2y3 ), y4y5y6y7, 1 );
  wwv_t z0to7 = _mm512_inserti32x8( _mm512_castsi256_si512( z0z1z2z3 ), z4z5z6z7, 1 );

  wwv_t h = wwv_add(
      wwv_add( wwv_rol( w0to7,  1 ), wwv_rol( x0to7,  7 ) ),
      wwv_add( wwv_rol( y0to7, 12 ), wwv_rol( z0to7, 18 ) )
  );

  wwv_t const CCC1 = wwv_bcast( C1 );
  wwv_t const CCC2 = wwv_bcast( C2 );
  wwv_t const CCC3 = wwv_bcast( C3 );
  wwv_t const CCC4 = wwv_bcast( C4 );

  w0to7 = wwv_mul( wwv_rol( wwv_mul( w0to7, CCC2 ), 31 ), CCC1 );   h = wwv_add( wwv_mul( wwv_xor( h, w0to7 ), CCC1 ), CCC4 );
  x0to7 = wwv_mul( wwv_rol( wwv_mul( x0to7, CCC2 ), 31 ), CCC1 );   h = wwv_add( wwv_mul( wwv_xor( h, x0to7 ), CCC1 ), CCC4 );
  y0to7 = wwv_mul( wwv_rol( wwv_mul( y0to7, CCC2 ), 31 ), CCC1 );   h = wwv_add( wwv_mul( wwv_xor( h, y0to7 ), CCC1 ), CCC4 );
  z0to7 = wwv_mul( wwv_rol( wwv_mul( z0to7, CCC2 ), 31 ), CCC1 );   h = wwv_add( wwv_mul( wwv_xor( h, z0to7 ), CCC1 ), CCC4 );

  h = wwv_add( h, wwv_ldu( sz_ ) );

  /* Final avalanche */
  h = wwv_xor( h, wwv_shr( h, 33 ) );
  h = wwv_mul( h, CCC2 );
  h = wwv_xor( h, wwv_shr( h, 29 ) );
  h = wwv_mul( h, CCC3 );
  h = wwv_xor( h, wwv_shr( h, 32 ) );

  wwv_stu( out, h );
}
