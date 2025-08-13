#include "fd_blake3_private.h"

static inline void
g( uint * state,
   ulong  a,
   ulong  b,
   ulong  c,
   ulong  d,
   uint   x,
   uint   y) {

  state[a] = state[a] + state[b] + x;
  state[d] = fd_uint_rotate_right( state[d] ^ state[a], 16 );
  state[c] = state[c] + state[d];
  state[b] = fd_uint_rotate_right( state[b] ^ state[c], 12 );
  state[a] = state[a] + state[b] + y;
  state[d] = fd_uint_rotate_right( state[d] ^ state[a],  8 );
  state[c] = state[c] + state[d];
  state[b] = fd_uint_rotate_right( state[b] ^ state[c],  7 );

}

static inline void
round_fn( uint         state[ static 16 ],
          uint const * msg,
          ulong        round ) {
  /* Select the message schedule based on the round */
  uchar const * schedule = FD_BLAKE3_MSG_SCHEDULE[round];

  /* Mix the columns */
  g( state,  0,  4,  8, 12, msg[ schedule[ 0] ], msg[ schedule[ 1] ] );
  g( state,  1,  5,  9, 13, msg[ schedule[ 2] ], msg[ schedule[ 3] ] );
  g( state,  2,  6, 10, 14, msg[ schedule[ 4] ], msg[ schedule[ 5] ] );
  g( state,  3,  7, 11, 15, msg[ schedule[ 6] ], msg[ schedule[ 7] ] );

  /* Mix the rows */
  g( state,  0,  5, 10, 15, msg[ schedule[ 8] ], msg[ schedule[ 9] ] );
  g( state,  1,  6, 11, 12, msg[ schedule[10] ], msg[ schedule[11] ] );
  g( state,  2,  7,  8, 13, msg[ schedule[12] ], msg[ schedule[13] ] );
  g( state,  3,  4,  9, 14, msg[ schedule[14] ], msg[ schedule[15] ] );
}

static inline void
compress_pre( uint        state[ static 16 ],
              uint const  cv   [ static  8 ],
              uchar const block[ FD_BLAKE3_BLOCK_SZ ],
              uint        block_len,
              ulong       counter,
              uint        flags ) {

  uint block_words[16];
  memcpy( block_words, block, 64 );

  uint ctr_lo = (uint)(counter&UINT_MAX);
  uint ctr_hi = (uint)(counter>>32);

  state[ 0] = cv[0];           state[ 1] = cv[1];
  state[ 2] = cv[2];           state[ 3] = cv[3];
  state[ 4] = cv[4];           state[ 5] = cv[5];
  state[ 6] = cv[6];           state[ 7] = cv[7];
  state[ 8] = FD_BLAKE3_IV[0]; state[ 9] = FD_BLAKE3_IV[1];
  state[10] = FD_BLAKE3_IV[2]; state[11] = FD_BLAKE3_IV[3];
  state[12] = ctr_lo;          state[13] = ctr_hi;
  state[14] = block_len;       state[15] = flags;

  round_fn( state, &block_words[0], 0 );
  round_fn( state, &block_words[0], 1 );
  round_fn( state, &block_words[0], 2 );
  round_fn( state, &block_words[0], 3 );
  round_fn( state, &block_words[0], 4 );
  round_fn( state, &block_words[0], 5 );
  round_fn( state, &block_words[0], 6 );
}

static inline void
compress_block( uint        cv[8],
                uchar const block[ FD_BLAKE3_BLOCK_SZ ],
                uint        block_len,
                ulong       counter,
                uint        flags ) {
  uint state[16];
  compress_pre( state, cv, block, block_len, counter, flags );
  cv[0] = state[0] ^ state[8];
  cv[1] = state[1] ^ state[9];
  cv[2] = state[2] ^ state[10];
  cv[3] = state[3] ^ state[11];
  cv[4] = state[4] ^ state[12];
  cv[5] = state[5] ^ state[13];
  cv[6] = state[6] ^ state[14];
  cv[7] = state[7] ^ state[15];
}

void
fd_blake3_ref_compress1( uchar * restrict       out,
                         uchar const * restrict msg,
                         uint                   msg_sz,
                         ulong                  counter,
                         uint                   flags ) {

  uint cv[8] = { FD_BLAKE3_IV[0], FD_BLAKE3_IV[1], FD_BLAKE3_IV[2], FD_BLAKE3_IV[3],
                 FD_BLAKE3_IV[4], FD_BLAKE3_IV[5], FD_BLAKE3_IV[6], FD_BLAKE3_IV[7] };

  uint block_flags = flags | fd_uint_if( flags&FD_BLAKE3_FLAG_PARENT, 0, FD_BLAKE3_FLAG_CHUNK_START );
  while( FD_LIKELY( msg_sz>FD_BLAKE3_BLOCK_SZ ) ) {
    compress_block( cv, msg, FD_BLAKE3_BLOCK_SZ, counter, block_flags );
    block_flags = flags;
    msg    += FD_BLAKE3_BLOCK_SZ;
    msg_sz -= (uint)FD_BLAKE3_BLOCK_SZ;
  }

  uchar block[ FD_BLAKE3_BLOCK_SZ ] = {0};
  fd_memcpy( block, msg, msg_sz );

  block_flags = flags | fd_uint_if( flags&FD_BLAKE3_FLAG_PARENT, 0, FD_BLAKE3_FLAG_CHUNK_END );
  compress_block( cv, msg, msg_sz, counter, block_flags );
  memcpy( out, cv, 32 );
}
