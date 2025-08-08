#include "fd_chacha_rng.h"
#include "../../util/simd/fd_avx512.h"
#include <assert.h>

#define wwu_rol16(a) wwb_exch_adj_pair( (a) )
#define wwu_rol12(a) wwu_rol( (a), 12 )
#define wwu_rol7(a)  wwu_rol( (a),  7 )

static inline __attribute__((always_inline)) wwu_t
wwu_rol8( wwu_t x ) {
  wwb_t const mask =
    wwb_bcast_hex( 3,0,1,2, 7,4,5,6, 11,8,9,10, 15,12,13,14 );
  return _mm512_shuffle_epi8( x, mask );
}

static void
fd_chacha_rng_refill_avx512( fd_chacha_rng_t * rng,
                             ulong             rnd2_cnt ) {

  /* This function should only be called if the buffer is empty. */
  if( FD_UNLIKELY( rng->buf_off != rng->buf_fill ) ) {
    FD_LOG_CRIT(( "refill out of sync: buf_off=%lu buf_fill=%lu", rng->buf_off, rng->buf_fill ));
  }

  wwu_t iv0  = wwu_bcast( 0x61707865U );
  wwu_t iv1  = wwu_bcast( 0x3320646eU );
  wwu_t iv2  = wwu_bcast( 0x79622d32U );
  wwu_t iv3  = wwu_bcast( 0x6b206574U );
  wwu_t zero = wwu_zero();

  /* Unpack key equivalent to:

       c4 = wwu_bcast( (uint const *)(rng->key)[0] );
       c5 = wwu_bcast( (uint const *)(rng->key)[1] );
       ...
       cB = wwu_bcast( (uint const *)(rng->key)[7] ); */

  wwu_t key_lo = _mm512_broadcast_i32x4( _mm_load_epi32( rng->key    ) );  /* [0,1,2,3,0,1,2,3] */
  wwu_t key_hi = _mm512_broadcast_i32x4( _mm_load_epi32( rng->key+16 ) );  /* [4,5,6,7,4,5,6,7] */
  wwu_t k0 = _mm512_shuffle_epi32( key_lo, 0x00 );
  wwu_t k1 = _mm512_shuffle_epi32( key_lo, 0x55 );
  wwu_t k2 = _mm512_shuffle_epi32( key_lo, 0xaa );
  wwu_t k3 = _mm512_shuffle_epi32( key_lo, 0xff );
  wwu_t k4 = _mm512_shuffle_epi32( key_hi, 0x00 );
  wwu_t k5 = _mm512_shuffle_epi32( key_hi, 0x55 );
  wwu_t k6 = _mm512_shuffle_epi32( key_hi, 0xaa );
  wwu_t k7 = _mm512_shuffle_epi32( key_hi, 0xff );

  /* Derive block index */

  ulong idx = rng->buf_fill / FD_CHACHA_BLOCK_SZ;  /* really a right shift */
  wwu_t idxs = wwu_add( wwu_bcast( idx ), wwu( 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 ) );

  /* Run through the round function */

  wwu_t c0 = iv0;   wwu_t c1 = iv1;   wwu_t c2 = iv2;   wwu_t c3 = iv3;
  wwu_t c4 = k0;    wwu_t c5 = k1;    wwu_t c6 = k2;    wwu_t c7 = k3;
  wwu_t c8 = k4;    wwu_t c9 = k5;    wwu_t cA = k6;    wwu_t cB = k7;
  wwu_t cC = idxs;  wwu_t cD = zero;  wwu_t cE = zero;  wwu_t cF = zero;

# define QUARTER_ROUND(a,b,c,d)                                   \
  do {                                                            \
    a = wwu_add( a, b ); d = wwu_xor( d, a ); d = wwu_rol16( d ); \
    c = wwu_add( c, d ); b = wwu_xor( b, c ); b = wwu_rol12( b ); \
    a = wwu_add( a, b ); d = wwu_xor( d, a ); d = wwu_rol8( d );  \
    c = wwu_add( c, d ); b = wwu_xor( b, c ); b = wwu_rol7( b );  \
  } while(0)

  for( ulong i=0UL; i<rnd2_cnt; i++ ) {
    QUARTER_ROUND( c0, c4, c8, cC );
    QUARTER_ROUND( c1, c5, c9, cD );
    QUARTER_ROUND( c2, c6, cA, cE );
    QUARTER_ROUND( c3, c7, cB, cF );
    QUARTER_ROUND( c0, c5, cA, cF );
    QUARTER_ROUND( c1, c6, cB, cC );
    QUARTER_ROUND( c2, c7, c8, cD );
    QUARTER_ROUND( c3, c4, c9, cE );
  }
# undef QUARTER_ROUND

  /* Finalize */

  c0 = wwu_add( c0, iv0  );
  c1 = wwu_add( c1, iv1  );
  c2 = wwu_add( c2, iv2  );
  c3 = wwu_add( c3, iv3  );
  c4 = wwu_add( c4, k0   );
  c5 = wwu_add( c5, k1   );
  c6 = wwu_add( c6, k2   );
  c7 = wwu_add( c7, k3   );
  c8 = wwu_add( c8, k4   );
  c9 = wwu_add( c9, k5   );
  cA = wwu_add( cA, k6   );
  cB = wwu_add( cB, k7   );
  cC = wwu_add( cC, idxs );
  //cD = wwu_add( cD, zero );
  //cE = wwu_add( cE, zero );
  //cF = wwu_add( cF, zero );

  /* Transpose matrix to get output vector */

  wwu_transpose_16x16( c0, c1, c2, c3, c4, c5, c6, c7,
                       c8, c9, cA, cB, cC, cD, cE, cF,
                       c0, c1, c2, c3, c4, c5, c6, c7,
                       c8, c9, cA, cB, cC, cD, cE, cF );

  /* Update ring buffer */

  uint * out = (uint *)rng->buf;
  wwu_st( out+0x00, c0 ); wwu_st( out+0x10, c1 );
  wwu_st( out+0x20, c2 ); wwu_st( out+0x30, c3 );
  wwu_st( out+0x40, c4 ); wwu_st( out+0x50, c5 );
  wwu_st( out+0x60, c6 ); wwu_st( out+0x70, c7 );
  wwu_st( out+0x80, c8 ); wwu_st( out+0x90, c9 );
  wwu_st( out+0xa0, cA ); wwu_st( out+0xb0, cB );
  wwu_st( out+0xc0, cC ); wwu_st( out+0xd0, cD );
  wwu_st( out+0xe0, cE ); wwu_st( out+0xf0, cF );

  /* Update ring descriptor */

  rng->buf_fill += 16*FD_CHACHA_BLOCK_SZ;
}

void
fd_chacha8_rng_refill_avx512( fd_chacha_rng_t * rng ) {
  fd_chacha_rng_refill_avx512( rng, 4UL );
}

void
fd_chacha20_rng_refill_avx512( fd_chacha_rng_t * rng ) {
  fd_chacha_rng_refill_avx512( rng, 10UL );
}
