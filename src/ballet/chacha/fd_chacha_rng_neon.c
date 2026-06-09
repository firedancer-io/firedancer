#include "fd_chacha_rng.h"

#if FD_HAS_NEON

#include "../../util/simd/fd_neon.h"

FD_FN_CONST static inline fd_neon_u32x4_t
fd_chacha_rotl7( fd_neon_u32x4_t x ) {
  return fd_neon_u32x4_rotl( x, 7 );
}

FD_FN_CONST static inline fd_neon_u32x4_t
fd_chacha_rotl8( fd_neon_u32x4_t x ) {
  return fd_neon_u32x4_rotl( x, 8 );
}

FD_FN_CONST static inline fd_neon_u32x4_t
fd_chacha_rotl12( fd_neon_u32x4_t x ) {
  return fd_neon_u32x4_rotl( x, 12 );
}

FD_FN_CONST static inline fd_neon_u32x4_t
fd_chacha_rotl16( fd_neon_u32x4_t x ) {
  return fd_neon_u32x4_rotl( x, 16 );
}

static inline void
fd_chacha_qr( fd_neon_u32x4_t * a,
              fd_neon_u32x4_t * b,
              fd_neon_u32x4_t * c,
              fd_neon_u32x4_t * d ) {
  *a = vaddq_u32( *a, *b ); *d = veorq_u32( *d, *a ); *d = fd_chacha_rotl16( *d );
  *c = vaddq_u32( *c, *d ); *b = veorq_u32( *b, *c ); *b = fd_chacha_rotl12( *b );
  *a = vaddq_u32( *a, *b ); *d = veorq_u32( *d, *a ); *d = fd_chacha_rotl8 ( *d );
  *c = vaddq_u32( *c, *d ); *b = veorq_u32( *b, *c ); *b = fd_chacha_rotl7 ( *b );
}

static void
fd_chacha_rng_refill_neon( fd_chacha_rng_t * rng,
                           ulong             rnd2_cnt ) {
  uint const * key = (uint const *)rng->key;
  ulong idx = rng->buf_fill >> 6;
  uint  idx_lo[ 4 ] = { (uint)(idx+0UL), (uint)(idx+1UL), (uint)(idx+2UL), (uint)(idx+3UL) };
  uint  idx_hi[ 4 ] = {
    (uint)((idx+0UL)>>32), (uint)((idx+1UL)>>32), (uint)((idx+2UL)>>32), (uint)((idx+3UL)>>32)
  };

  fd_neon_u32x4_t x0  = fd_neon_u32x4_bcast( 0x61707865U );
  fd_neon_u32x4_t x1  = fd_neon_u32x4_bcast( 0x3320646eU );
  fd_neon_u32x4_t x2  = fd_neon_u32x4_bcast( 0x79622d32U );
  fd_neon_u32x4_t x3  = fd_neon_u32x4_bcast( 0x6b206574U );
  fd_neon_u32x4_t x4  = fd_neon_u32x4_bcast( key[0] );
  fd_neon_u32x4_t x5  = fd_neon_u32x4_bcast( key[1] );
  fd_neon_u32x4_t x6  = fd_neon_u32x4_bcast( key[2] );
  fd_neon_u32x4_t x7  = fd_neon_u32x4_bcast( key[3] );
  fd_neon_u32x4_t x8  = fd_neon_u32x4_bcast( key[4] );
  fd_neon_u32x4_t x9  = fd_neon_u32x4_bcast( key[5] );
  fd_neon_u32x4_t x10 = fd_neon_u32x4_bcast( key[6] );
  fd_neon_u32x4_t x11 = fd_neon_u32x4_bcast( key[7] );
  fd_neon_u32x4_t x12 = vld1q_u32( idx_lo );
  fd_neon_u32x4_t x13 = vld1q_u32( idx_hi );
  fd_neon_u32x4_t x14 = fd_neon_u32x4_bcast( 0U );
  fd_neon_u32x4_t x15 = fd_neon_u32x4_bcast( 0U );

  fd_neon_u32x4_t i0  = x0;
  fd_neon_u32x4_t i1  = x1;
  fd_neon_u32x4_t i2  = x2;
  fd_neon_u32x4_t i3  = x3;
  fd_neon_u32x4_t i4  = x4;
  fd_neon_u32x4_t i5  = x5;
  fd_neon_u32x4_t i6  = x6;
  fd_neon_u32x4_t i7  = x7;
  fd_neon_u32x4_t i8  = x8;
  fd_neon_u32x4_t i9  = x9;
  fd_neon_u32x4_t i10 = x10;
  fd_neon_u32x4_t i11 = x11;
  fd_neon_u32x4_t i12 = x12;
  fd_neon_u32x4_t i13 = x13;
  fd_neon_u32x4_t i14 = x14;
  fd_neon_u32x4_t i15 = x15;

  for( ulong i=0UL; i<rnd2_cnt; i++ ) {
    fd_chacha_qr( &x0, &x4, &x8,  &x12 );
    fd_chacha_qr( &x1, &x5, &x9,  &x13 );
    fd_chacha_qr( &x2, &x6, &x10, &x14 );
    fd_chacha_qr( &x3, &x7, &x11, &x15 );
    fd_chacha_qr( &x0, &x5, &x10, &x15 );
    fd_chacha_qr( &x1, &x6, &x11, &x12 );
    fd_chacha_qr( &x2, &x7, &x8,  &x13 );
    fd_chacha_qr( &x3, &x4, &x9,  &x14 );
  }

  x0  = vaddq_u32( x0,  i0  );
  x1  = vaddq_u32( x1,  i1  );
  x2  = vaddq_u32( x2,  i2  );
  x3  = vaddq_u32( x3,  i3  );
  x4  = vaddq_u32( x4,  i4  );
  x5  = vaddq_u32( x5,  i5  );
  x6  = vaddq_u32( x6,  i6  );
  x7  = vaddq_u32( x7,  i7  );
  x8  = vaddq_u32( x8,  i8  );
  x9  = vaddq_u32( x9,  i9  );
  x10 = vaddq_u32( x10, i10 );
  x11 = vaddq_u32( x11, i11 );
  x12 = vaddq_u32( x12, i12 );
  x13 = vaddq_u32( x13, i13 );
  x14 = vaddq_u32( x14, i14 );
  x15 = vaddq_u32( x15, i15 );

  uint lane_words[ 16 ][ 4 ] __attribute__((aligned(64)));
  vst1q_u32( lane_words[ 0], x0  );
  vst1q_u32( lane_words[ 1], x1  );
  vst1q_u32( lane_words[ 2], x2  );
  vst1q_u32( lane_words[ 3], x3  );
  vst1q_u32( lane_words[ 4], x4  );
  vst1q_u32( lane_words[ 5], x5  );
  vst1q_u32( lane_words[ 6], x6  );
  vst1q_u32( lane_words[ 7], x7  );
  vst1q_u32( lane_words[ 8], x8  );
  vst1q_u32( lane_words[ 9], x9  );
  vst1q_u32( lane_words[10], x10 );
  vst1q_u32( lane_words[11], x11 );
  vst1q_u32( lane_words[12], x12 );
  vst1q_u32( lane_words[13], x13 );
  vst1q_u32( lane_words[14], x14 );
  vst1q_u32( lane_words[15], x15 );

  for( ulong lane=0UL; lane<4UL; lane++ ) {
    uint block_words[ 16 ] __attribute__((aligned(64)));
    for( ulong word=0UL; word<16UL; word++ ) {
      block_words[ word ] = lane_words[ word ][ lane ];
    }
    ulong off = ( rng->buf_fill + lane*FD_CHACHA_BLOCK_SZ ) % FD_CHACHA_RNG_BUFSZ;
    fd_memcpy( rng->buf + off, block_words, FD_CHACHA_BLOCK_SZ );
  }
  rng->buf_fill += 4UL*FD_CHACHA_BLOCK_SZ;
}

void
fd_chacha8_rng_refill_neon( fd_chacha_rng_t * rng ) {
  fd_chacha_rng_refill_neon( rng, 4UL );
}

void
fd_chacha20_rng_refill_neon( fd_chacha_rng_t * rng ) {
  fd_chacha_rng_refill_neon( rng, 10UL );
}

#endif /* FD_HAS_NEON */
