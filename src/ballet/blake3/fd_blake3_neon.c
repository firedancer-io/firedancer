/* BLAKE3 single-block compress using ARM NEON, ported from
   src/ballet/blake3/fd_blake3_sse41.c. */

#include "fd_blake3.h"
#include "fd_blake3_private.h"

#if FD_HAS_NEON

#include <arm_neon.h>
#include <assert.h>

static inline void
fd_blake3_g1( uint32x4_t * row0,
              uint32x4_t * row1,
              uint32x4_t * row2,
              uint32x4_t * row3,
              uint32x4_t   m ) {
  *row0 = vaddq_u32( vaddq_u32( *row0, m ), *row1 );
  *row3 = veorq_u32( *row3, *row0 );
  *row3 = vorrq_u32( vshlq_n_u32( *row3, 16 ), vshrq_n_u32( *row3, 16 ) );
  *row2 = vaddq_u32( *row2, *row3 );
  *row1 = veorq_u32( *row1, *row2 );
  *row1 = vorrq_u32( vshrq_n_u32( *row1, 12 ), vshlq_n_u32( *row1, 20 ) );
}

static inline void
fd_blake3_g2( uint32x4_t * row0,
              uint32x4_t * row1,
              uint32x4_t * row2,
              uint32x4_t * row3,
              uint32x4_t   m ) {
  *row0 = vaddq_u32( vaddq_u32( *row0, m ), *row1 );
  *row3 = veorq_u32( *row3, *row0 );
  *row3 = vreinterpretq_u32_u8( vqtbl1q_u8( vreinterpretq_u8_u32( *row3 ),
                                            (uint8x16_t){ 1,2,3,0, 5,6,7,4, 9,10,11,8, 13,14,15,12 } ) );
  *row2 = vaddq_u32( *row2, *row3 );
  *row1 = veorq_u32( *row1, *row2 );
  *row1 = vorrq_u32( vshrq_n_u32( *row1, 7 ), vshlq_n_u32( *row1, 25 ) );
}

static inline void
fd_blake3_diagonalize( uint32x4_t * row1,
                       uint32x4_t * row2,
                       uint32x4_t * row3 ) {
  *row1 = vextq_u32( *row1, *row1, 1 );
  *row2 = vextq_u32( *row2, *row2, 2 );
  *row3 = vextq_u32( *row3, *row3, 3 );
}

static inline void
fd_blake3_undiagonalize( uint32x4_t * row1,
                         uint32x4_t * row2,
                         uint32x4_t * row3 ) {
  *row1 = vextq_u32( *row1, *row1, 3 );
  *row2 = vextq_u32( *row2, *row2, 2 );
  *row3 = vextq_u32( *row3, *row3, 1 );
}

static inline uint32x4_t
fd_blake3_msg( uint const         msg[ static 16 ],
               uchar const        schedule[ static 16 ],
               int                base ) {
  uint lane[ 4 ] = {
    msg[ schedule[ base     ] ],
    msg[ schedule[ base + 2 ] ],
    msg[ schedule[ base + 4 ] ],
    msg[ schedule[ base + 6 ] ]
  };
  return vld1q_u32( lane );
}

static inline void
fd_blake3_compress_pre( uint32x4_t      rows[ static 4 ],
                        uint const       cv[ static 8 ],
                        uchar const      block[ static FD_BLAKE3_BLOCK_SZ ],
                        uint             block_len,
                        ulong            ctr,
                        uint             flags ) {
  uint msg[ 16 ];
  fd_memcpy( msg, block, FD_BLAKE3_BLOCK_SZ );

  rows[0] = vld1q_u32( cv   );
  rows[1] = vld1q_u32( cv+4 );
  rows[2] = (uint32x4_t){ FD_BLAKE3_IV[0], FD_BLAKE3_IV[1], FD_BLAKE3_IV[2], FD_BLAKE3_IV[3] };
  rows[3] = (uint32x4_t){ (uint)(ctr & UINT_MAX), (uint)(ctr >> 32), block_len, flags };

  for( ulong round=0UL; round<7UL; round++ ) {
    uchar const * sched = FD_BLAKE3_MSG_SCHEDULE[ round ];
    fd_blake3_g1( &rows[0], &rows[1], &rows[2], &rows[3], fd_blake3_msg( msg, sched, 0 ) );
    fd_blake3_g2( &rows[0], &rows[1], &rows[2], &rows[3], fd_blake3_msg( msg, sched, 1 ) );
    fd_blake3_diagonalize( &rows[1], &rows[2], &rows[3] );
    fd_blake3_g1( &rows[0], &rows[1], &rows[2], &rows[3], fd_blake3_msg( msg, sched, 8 ) );
    fd_blake3_g2( &rows[0], &rows[1], &rows[2], &rows[3], fd_blake3_msg( msg, sched, 9 ) );
    fd_blake3_undiagonalize( &rows[1], &rows[2], &rows[3] );
  }
}

void
fd_blake3_neon_compress1( uchar * restrict       out,
                          uchar const * restrict msg,
                          uint                   msg_sz,
                          ulong                  counter,
                          uint                   flags,
                          uchar * restrict       out_chain,
                          uchar const * restrict in_chain ) {
  FD_BLAKE3_TRACE(( "fd_blake3_neon_compress1(out=%p,msg=%p,sz=%u,counter=%lu,flags=%02x)",
                    (void *)out, (void *)msg, msg_sz, counter, flags ));
  assert( msg_sz<=FD_BLAKE3_CHUNK_SZ );

  uint cv[ 8 ] = {
    FD_BLAKE3_IV[0], FD_BLAKE3_IV[1], FD_BLAKE3_IV[2], FD_BLAKE3_IV[3],
    FD_BLAKE3_IV[4], FD_BLAKE3_IV[5], FD_BLAKE3_IV[6], FD_BLAKE3_IV[7]
  };
  if( FD_UNLIKELY( in_chain ) ) fd_memcpy( cv, in_chain, FD_BLAKE3_OUTCHAIN_SZ );

  uint flag_mask = ~fd_uint_if( flags&FD_BLAKE3_FLAG_PARENT,
                                FD_BLAKE3_FLAG_CHUNK_START|FD_BLAKE3_FLAG_CHUNK_END,
                                0U );

  uint block_flags = flags | (flag_mask & FD_BLAKE3_FLAG_CHUNK_START);
  if( FD_UNLIKELY( in_chain && !(flags&FD_BLAKE3_FLAG_CHUNK_START) ) ) block_flags &= ~FD_BLAKE3_FLAG_CHUNK_START;

  do {
    uint block_sz = fd_uint_min( msg_sz, FD_BLAKE3_BLOCK_SZ );
    block_flags |= FD_BLAKE3_FLAG_CHUNK_END;
    block_flags &= (flag_mask & ~fd_uint_if( msg_sz<=FD_BLAKE3_BLOCK_SZ, 0U, (FD_BLAKE3_FLAG_CHUNK_END|FD_BLAKE3_FLAG_ROOT) ) );

    uchar tail[ FD_BLAKE3_BLOCK_SZ ] __attribute__((aligned(16)));
    uchar const * block;
    if( FD_LIKELY( msg_sz>=FD_BLAKE3_BLOCK_SZ ) ) {
      block = msg;
    } else {
      fd_memset( tail, 0, sizeof(tail) );
      fd_memcpy( tail, msg, msg_sz );
      block = tail;
    }

    if( FD_UNLIKELY( out_chain && (block_flags & FD_BLAKE3_FLAG_CHUNK_END) ) ) {
      fd_memcpy( out,       block, FD_BLAKE3_BLOCK_SZ    );
      fd_memcpy( out_chain, cv,    FD_BLAKE3_OUTCHAIN_SZ );
      FD_BLAKE3_TRACE(( "fd_blake3_neon_compress1: done (XOF mode)" ));
      return;
    }

    uint32x4_t rows[ 4 ];
    fd_blake3_compress_pre( rows, cv, block, block_sz, counter, block_flags );
    if( FD_UNLIKELY( in_chain ) ) {
      vst1q_u32( (uint *)(out+32), veorq_u32( vld1q_u32( cv   ), rows[2] ) );
      vst1q_u32( (uint *)(out+48), veorq_u32( vld1q_u32( cv+4 ), rows[3] ) );
    }
    vst1q_u32( cv,   veorq_u32( rows[0], rows[2] ) );
    vst1q_u32( cv+4, veorq_u32( rows[1], rows[3] ) );
    msg    += FD_BLAKE3_BLOCK_SZ;
    msg_sz -= block_sz;
    block_flags = flags;
  } while( (int)msg_sz>0 );

  fd_memcpy( out, cv, FD_BLAKE3_OUTCHAIN_SZ );
  FD_BLAKE3_TRACE(( "fd_blake3_neon_compress1: done" ));
}

#endif /* FD_HAS_NEON */
