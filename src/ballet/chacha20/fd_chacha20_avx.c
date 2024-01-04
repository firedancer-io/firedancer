#include "fd_chacha20rng.h"
#include "../../util/simd/fd_avx.h"
#include <assert.h>

#define wu_rol16(a) wb_exch_adj_pair( (a) )
#define wu_rol12(a) wu_rol( (a), 12 )
#define wu_rol7(a)  wu_rol( (a),  7 )

static inline __attribute__((always_inline)) wu_t
wu_rol8( wu_t x ) {
  wb_t const mask =
    wb( 3,0,1,2, 7,4,5,6, 11,8,9,10,  15,12,13,14,
        3,0,1,2, 7,4,5,6, 11,8,9,10,  15,12,13,14 );
  return _mm256_shuffle_epi8( x, mask );
}

void
fd_chacha20rng_refill_avx( fd_chacha20rng_t * rng ) {

  /* This function should only be called if the buffer is empty. */
  assert( rng->buf_off == rng->buf_fill );

  wu_t iv0  = wu_bcast( 0x61707865U );
  wu_t iv1  = wu_bcast( 0x3320646eU );
  wu_t iv2  = wu_bcast( 0x79622d32U );
  wu_t iv3  = wu_bcast( 0x6b206574U );
  wb_t key  = wb_ld( rng->key );
  wu_t zero = wu_zero();

  /* Unpack key equivalent to:

       c4 = wu_bcast( (uint const *)(rng->key)[0] );
       c5 = wu_bcast( (uint const *)(rng->key)[1] );
       ...
       cB = wu_bcast( (uint const *)(rng->key)[7] ); */

  wu_t key_lo = _mm256_permute2x128_si256( key, key, 0x00 );  /* [0,1,2,3,0,1,2,3] */
  wu_t key_hi = _mm256_permute2x128_si256( key, key, 0x11 );  /* [4,5,6,7,4,5,6,7] */
  wu_t k0 = _mm256_shuffle_epi32( key_lo, 0x00 );
  wu_t k1 = _mm256_shuffle_epi32( key_lo, 0x55 );
  wu_t k2 = _mm256_shuffle_epi32( key_lo, 0xaa );
  wu_t k3 = _mm256_shuffle_epi32( key_lo, 0xff );
  wu_t k4 = _mm256_shuffle_epi32( key_hi, 0x00 );
  wu_t k5 = _mm256_shuffle_epi32( key_hi, 0x55 );
  wu_t k6 = _mm256_shuffle_epi32( key_hi, 0xaa );
  wu_t k7 = _mm256_shuffle_epi32( key_hi, 0xff );

  /* Derive block index */

  ulong idx = rng->buf_fill / FD_CHACHA20_BLOCK_SZ;  /* really a right shift */
  wu_t idxs = wu_add( wu_bcast( idx ), wu( 0, 1, 2, 3, 4, 5, 6, 7 ) );

  /* Run through the round function */

  wu_t c0 = iv0;   wu_t c1 = iv1;   wu_t c2 = iv2;   wu_t c3 = iv3;
  wu_t c4 = k0;    wu_t c5 = k1;    wu_t c6 = k2;    wu_t c7 = k3;
  wu_t c8 = k4;    wu_t c9 = k5;    wu_t cA = k6;    wu_t cB = k7;
  wu_t cC = idxs;  wu_t cD = zero;  wu_t cE = zero;  wu_t cF = zero;

# define QUARTER_ROUND(a,b,c,d)                                        \
  do {                                                                 \
    a = wu_add( a, b ); d = wu_xor( d, a ); d = wu_rol16( d );         \
    c = wu_add( c, d ); b = wu_xor( b, c ); b = wu_rol12( b );         \
    a = wu_add( a, b ); d = wu_xor( d, a ); d = wu_rol8( d );          \
    c = wu_add( c, d ); b = wu_xor( b, c ); b = wu_rol7( b );          \
  } while(0)

  for( ulong i=0UL; i<10UL; i++ ) {
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

  c0 = wu_add( c0, iv0  );
  c1 = wu_add( c1, iv1  );
  c2 = wu_add( c2, iv2  );
  c3 = wu_add( c3, iv3  );
  c4 = wu_add( c4, k0   );
  c5 = wu_add( c5, k1   );
  c6 = wu_add( c6, k2   );
  c7 = wu_add( c7, k3   );
  c8 = wu_add( c8, k4   );
  c9 = wu_add( c9, k5   );
  cA = wu_add( cA, k6   );
  cB = wu_add( cB, k7   );
  cC = wu_add( cC, idxs );
  //cD = wu_add( cD, zero );
  //cE = wu_add( cE, zero );
  //cF = wu_add( cF, zero );

  /* Transpose matrix to get output vector */

  wu_transpose_8x8( c0, c1, c2, c3, c4, c5, c6, c7,
                    c0, c1, c2, c3, c4, c5, c6, c7 );
  wu_transpose_8x8( c8, c9, cA, cB, cC, cD, cE, cF,
                    c8, c9, cA, cB, cC, cD, cE, cF );

  /* Update ring buffer */

  uint * out = (uint *)rng->buf;
  wu_st( out+0x00, c0 ); wu_st( out+0x08, c8 );
  wu_st( out+0x10, c1 ); wu_st( out+0x18, c9 );
  wu_st( out+0x20, c2 ); wu_st( out+0x28, cA );
  wu_st( out+0x30, c3 ); wu_st( out+0x38, cB );
  wu_st( out+0x40, c4 ); wu_st( out+0x48, cC );
  wu_st( out+0x50, c5 ); wu_st( out+0x58, cD );
  wu_st( out+0x60, c6 ); wu_st( out+0x68, cE );
  wu_st( out+0x70, c7 ); wu_st( out+0x78, cF );

  /* Update ring descriptor */

  rng->buf_fill += 8*FD_CHACHA20_BLOCK_SZ;
}
