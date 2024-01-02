#include "fd_chacha20.h"
#include "../../util/simd/fd_sse.h"


void *
fd_chacha20_block( void *       _block,
                   void const * _key,
                   void const * _idx_nonce ) {

  uint *       block     = __builtin_assume_aligned( _block,     64UL );
  uint const * key       = __builtin_assume_aligned( _key,       32UL );
  uint const * idx_nonce = __builtin_assume_aligned( _idx_nonce, 16UL );

  /* Construct the input ChaCha20 block state as the following
     matrix of little endian uint entries:

     cccccccc  cccccccc  cccccccc  cccccccc
     kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
     kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
     bbbbbbbb  nnnnnnnn  nnnnnnnn  nnnnnnnn

     Where
       c are the constants 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
       k is the input key
       b is the block index
       n is the nonce */

  /* Remember the input state for later use */
  vu_t row0_init = vu( 0x61707865U, 0x3320646eU, 0x79622d32U, 0x6b206574U );
  vu_t row1_init = vu_ld( key       );
  vu_t row2_init = vu_ld( key+4     );
  vu_t row3_init = vu_ld( idx_nonce );

  vu_t row0 = row0_init;
  vu_t row1 = row1_init;
  vu_t row2 = row2_init;
  vu_t row3 = row3_init;

  /* These rotates are a bit faster, and they're on the critical path,
     so this makes a difference. */
#define ROTATE_LEFT_16( x ) _mm_shuffle_epi8( (x), vb( 2,3,0,1, 6,7,4,5, 10,11,8,9,  14,15,12,13 ) )
#define ROTATE_LEFT_08( x ) _mm_shuffle_epi8( (x), vb( 3,0,1,2, 7,4,5,6, 11,8,9,10,  15,12,13,14 ) )
#if FD_HAS_AVX512
# define ROTATE_LEFT_12( x ) _mm_rol_epi32( (x), 12 )
# define ROTATE_LEFT_07( x ) _mm_rol_epi32( (x),  7 )
#else
# define ROTATE_LEFT_12( x ) vu_rol( (x), 12 )
# define ROTATE_LEFT_07( x ) vu_rol( (x),  7 )
#endif

  /* Run the ChaCha round function 20 times.
     (Each iteration does a column round and a diagonal round.) */
  for( ulong i=0UL; i<10UL; i++ ) {
    /* Column round */
    row0 = vu_add( row0, row1 ); row3 = vu_xor( row3, row0 ); row3 = ROTATE_LEFT_16( row3 );
    row2 = vu_add( row2, row3 ); row1 = vu_xor( row1, row2 ); row1 = ROTATE_LEFT_12( row1 );
    row0 = vu_add( row0, row1 ); row3 = vu_xor( row3, row0 ); row3 = ROTATE_LEFT_08( row3 );
    row2 = vu_add( row2, row3 ); row1 = vu_xor( row1, row2 ); row1 = ROTATE_LEFT_07( row1 );

    row1 = _mm_shuffle_epi32( row1, _MM_SHUFFLE( 0, 3, 2, 1 ) );
    row2 = _mm_shuffle_epi32( row2, _MM_SHUFFLE( 1, 0, 3, 2 ) );
    row3 = _mm_shuffle_epi32( row3, _MM_SHUFFLE( 2, 1, 0, 3 ) );

    /* Diagonal round */
    row0 = vu_add( row0, row1 ); row3 = vu_xor( row3, row0 ); row3 = ROTATE_LEFT_16( row3 );
    row2 = vu_add( row2, row3 ); row1 = vu_xor( row1, row2 ); row1 = ROTATE_LEFT_12( row1 );
    row0 = vu_add( row0, row1 ); row3 = vu_xor( row3, row0 ); row3 = ROTATE_LEFT_08( row3 );
    row2 = vu_add( row2, row3 ); row1 = vu_xor( row1, row2 ); row1 = ROTATE_LEFT_07( row1 );

    row1 = _mm_shuffle_epi32( row1, _MM_SHUFFLE( 2, 1, 0, 3 ) );
    row2 = _mm_shuffle_epi32( row2, _MM_SHUFFLE( 1, 0, 3, 2 ) );
    row3 = _mm_shuffle_epi32( row3, _MM_SHUFFLE( 0, 3, 2, 1 ) );
  }
#undef ROTATE_LEFT_07
#undef ROTATE_LEFT_12
#undef ROTATE_LEFT_08
#undef ROTATE_LEFT_16


  /* Complete the block by adding the input state */
  row0 = vu_add( row0, row0_init );
  row1 = vu_add( row1, row1_init );
  row2 = vu_add( row2, row2_init );
  row3 = vu_add( row3, row3_init );

  vu_st( block,    row0 );
  vu_st( block+ 4, row1 );
  vu_st( block+ 8, row2 );
  vu_st( block+12, row3 );

  return _block;
}

