#include "fd_chacha20.h"

/* Reference implementation of the ChaCha20 block function.

   FIXME Not optimized for high performance.  Trivially parallelizable
         via SSE or AVX if required. */

static inline void
fd_chacha20_quarter_round( uint * a,
                           uint * b,
                           uint * c,
                           uint * d ) {
  *a += *b; *d ^= *a; *d = fd_uint_rotate_left(*d, 16);
  *c += *d; *b ^= *c; *b = fd_uint_rotate_left(*b, 12);
  *a += *b; *d ^= *a; *d = fd_uint_rotate_left(*d,  8);
  *c += *d; *b ^= *c; *b = fd_uint_rotate_left(*b,  7);
}

void *
fd_chacha20_block( void *       _block,
                   void const * _key,
                   uint         idx,
                   void const * _nonce ) {

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

  uint * block = (uint *)_block;
  block[ 0 ] = 0x61707865U;
  block[ 1 ] = 0x3320646eU;
  block[ 2 ] = 0x79622d32U;
  block[ 3 ] = 0x6b206574U;

  uint const * key = (uint const *)_key;
  memcpy( block+ 4, key, 8*sizeof(uint) );

  block[ 12 ] = idx;
  uint const * nonce = (uint const *)_nonce;
  memcpy( block+13, nonce, 3*sizeof(uint) );

  /* Remember the input state for later use */

  uint block_pre[ 16 ] __attribute__((aligned(32)));
  memcpy( block_pre, block, 64UL );

  /* Run the ChaCha round function 20 times.
     (Each iteration does a column round and a diagonal round.) */

  for( ulong i=0UL; i<10UL; i++ ) {
    fd_chacha20_quarter_round( &block[ 0 ], &block[ 4 ], &block[  8 ], &block[ 12 ] );
    fd_chacha20_quarter_round( &block[ 1 ], &block[ 5 ], &block[  9 ], &block[ 13 ] );
    fd_chacha20_quarter_round( &block[ 2 ], &block[ 6 ], &block[ 10 ], &block[ 14 ] );
    fd_chacha20_quarter_round( &block[ 3 ], &block[ 7 ], &block[ 11 ], &block[ 15 ] );
    fd_chacha20_quarter_round( &block[ 0 ], &block[ 5 ], &block[ 10 ], &block[ 15 ] );
    fd_chacha20_quarter_round( &block[ 1 ], &block[ 6 ], &block[ 11 ], &block[ 12 ] );
    fd_chacha20_quarter_round( &block[ 2 ], &block[ 7 ], &block[  8 ], &block[ 13 ] );
    fd_chacha20_quarter_round( &block[ 3 ], &block[ 4 ], &block[  9 ], &block[ 14 ] );
  }

  /* Complete the block by adding the input state */

  for( ulong i=0UL; i<16UL; i++ )
    block[ i ] += block_pre[ i ];

  return (void *)block;
}

