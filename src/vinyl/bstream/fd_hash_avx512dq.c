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

  /* Vi = ( w_i, x_i, y_i, z_i ) */
  wv_t V0 = init;    uchar const * p0 = (uchar const *)buf_[0];
  wv_t V1 = init;    uchar const * p1 = (uchar const *)buf_[1];
  wv_t V2 = init;    uchar const * p2 = (uchar const *)buf_[2];
  wv_t V3 = init;    uchar const * p3 = (uchar const *)buf_[3];
  wv_t V4 = init;    uchar const * p4 = (uchar const *)buf_[4];
  wv_t V5 = init;    uchar const * p5 = (uchar const *)buf_[5];
  wv_t V6 = init;    uchar const * p6 = (uchar const *)buf_[6];
  wv_t V7 = init;    uchar const * p7 = (uchar const *)buf_[7];

  ulong max_sz = 0UL;
  for( ulong i=0UL; i<8UL; i++ ) max_sz = fd_ulong_max( max_sz, sz_[i] );

  wwv_t rem_sz = wwv_ldu( sz_ );
  wwv_t sub512 = wwv_bcast( 512UL );

  for( ulong j_outer=0UL; j_outer<max_sz; j_outer+=512UL ) {
    /* not_done has one bit per lane, and we need to convert it to one
       mask per lane.  We'll extract and invert the kth bit with a shift
       and mask, then add 0xFF to it, which has the effect of
       broadcasting the inverted bit: 0x00 + 0xFF = 0xFF, whereas 0x01 +
       0xFF = 0x00. */
    __mmask8 not_done = _mm512_cmpneq_epi64_mask( rem_sz, wwv_zero() );
    /* Do effectively a saturating subtract */
    rem_sz = _mm512_mask_sub_epi64( rem_sz, not_done, rem_sz, sub512 );
    __mmask8 k0 = _kadd_mask8( 0xFF, _kandn_mask8(                  not_done,      0x01 ) );
    __mmask8 k1 = _kadd_mask8( 0xFF, _kandn_mask8( _kshiftri_mask8( not_done, 1 ), 0x01 ) );
    __mmask8 k2 = _kadd_mask8( 0xFF, _kandn_mask8( _kshiftri_mask8( not_done, 2 ), 0x01 ) );
    __mmask8 k3 = _kadd_mask8( 0xFF, _kandn_mask8( _kshiftri_mask8( not_done, 3 ), 0x01 ) );
    __mmask8 k4 = _kadd_mask8( 0xFF, _kandn_mask8( _kshiftri_mask8( not_done, 4 ), 0x01 ) );
    __mmask8 k5 = _kadd_mask8( 0xFF, _kandn_mask8( _kshiftri_mask8( not_done, 5 ), 0x01 ) );
    __mmask8 k6 = _kadd_mask8( 0xFF, _kandn_mask8( _kshiftri_mask8( not_done, 6 ), 0x01 ) );
    __mmask8 k7 = _kadd_mask8( 0xFF, _kandn_mask8( _kshiftri_mask8( not_done, 7 ), 0x01 ) );


    for( ulong j=j_outer; j<j_outer+512UL; j+=32UL ) {
      V0 = _mm256_mask_mullo_epi64( V0, k0, wv_rol( wv_add( V0, wv_mul( CC2, _mm256_maskz_loadu_epi64( k0, p0+j ) ) ), 31 ), CC1 );
      V1 = _mm256_mask_mullo_epi64( V1, k1, wv_rol( wv_add( V1, wv_mul( CC2, _mm256_maskz_loadu_epi64( k1, p1+j ) ) ), 31 ), CC1 );
      V2 = _mm256_mask_mullo_epi64( V2, k2, wv_rol( wv_add( V2, wv_mul( CC2, _mm256_maskz_loadu_epi64( k2, p2+j ) ) ), 31 ), CC1 );
      V3 = _mm256_mask_mullo_epi64( V3, k3, wv_rol( wv_add( V3, wv_mul( CC2, _mm256_maskz_loadu_epi64( k3, p3+j ) ) ), 31 ), CC1 );
      V4 = _mm256_mask_mullo_epi64( V4, k4, wv_rol( wv_add( V4, wv_mul( CC2, _mm256_maskz_loadu_epi64( k4, p4+j ) ) ), 31 ), CC1 );
      V5 = _mm256_mask_mullo_epi64( V5, k5, wv_rol( wv_add( V5, wv_mul( CC2, _mm256_maskz_loadu_epi64( k5, p5+j ) ) ), 31 ), CC1 );
      V6 = _mm256_mask_mullo_epi64( V6, k6, wv_rol( wv_add( V6, wv_mul( CC2, _mm256_maskz_loadu_epi64( k6, p6+j ) ) ), 31 ), CC1 );
      V7 = _mm256_mask_mullo_epi64( V7, k7, wv_rol( wv_add( V7, wv_mul( CC2, _mm256_maskz_loadu_epi64( k7, p7+j ) ) ), 31 ), CC1 );
    }
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
  for( ulong i=0UL; i<8UL; i++ ) if( !sz_[i] ) out[i] = seed_;
}
