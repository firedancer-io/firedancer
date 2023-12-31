
// Source originally from https://github.com/BLAKE3-team/BLAKE3
// From commit: c0ea395cf91d242f078c23d5f8d87eb9dd5f7b78

#include "fd_blake3.h"
#include "fd_blake3_private.h"
#include "../../util/simd/fd_sse.h"
#include <assert.h>

#define _mm_shuffle_ps2(a, b, c)                                       \
  (_mm_castps_si128(                                                   \
      _mm_shuffle_ps(_mm_castsi128_ps(a), _mm_castsi128_ps(b), (c))))

#define vu_rot16 vb_exch_adj_pair

static inline __attribute__((always_inline)) vu_t
vu_rot12( vu_t x ) {
  return vu_xor( vu_shr( x, 12 ), vu_shl( x, 32-12 ) );
}

static inline __attribute__((always_inline)) vu_t
vu_rot8( vu_t x ) {
  vb_t const mask = vb( 1,2,3,0, 5,6,7,4, 9,10,11,8, 13,14,15,12 );
  return _mm_shuffle_epi8( x, mask );
}

static inline __attribute__((always_inline)) vu_t
vu_rot7( vu_t x ) {
  return vu_xor( vu_shr( x, 7 ), vu_shl( x, 32-7 ) );
}

static inline __attribute__((always_inline)) void
g1( vu_t * row0,
    vu_t * row1,
    vu_t * row2,
    vu_t * row3,
    vu_t   m ) {
  *row0 = vu_add(vu_add(*row0, m), *row1);
  *row3 = vu_xor(*row3, *row0);
  *row3 = vu_rot16(*row3);
  *row2 = vu_add(*row2, *row3);
  *row1 = vu_xor(*row1, *row2);
  *row1 = vu_rot12(*row1);
}

static inline __attribute__((always_inline)) void
g2( vu_t * row0,
    vu_t * row1,
    vu_t * row2,
    vu_t * row3,
    vu_t   m ) {
  *row0 = vu_add(vu_add(*row0, m), *row1);
  *row3 = vu_xor(*row3, *row0);
  *row3 = vu_rot8(*row3);
  *row2 = vu_add(*row2, *row3);
  *row1 = vu_xor(*row1, *row2);
  *row1 = vu_rot7(*row1);
}

// Note the optimization here of leaving row1 as the unrotated row, rather than
// row0. All the message loads below are adjusted to compensate for this. See
// discussion at https://github.com/sneves/blake2-avx2/pull/4
static inline __attribute__((always_inline)) void
diagonalize(vu_t *row0, vu_t *row2, vu_t *row3) {
  *row0 = _mm_shuffle_epi32(*row0, _MM_SHUFFLE(2, 1, 0, 3));
  *row3 = _mm_shuffle_epi32(*row3, _MM_SHUFFLE(1, 0, 3, 2));
  *row2 = _mm_shuffle_epi32(*row2, _MM_SHUFFLE(0, 3, 2, 1));
}

static inline __attribute__((always_inline)) void
undiagonalize(vu_t *row0, vu_t *row2, vu_t *row3) {
  *row0 = _mm_shuffle_epi32(*row0, _MM_SHUFFLE(0, 3, 2, 1));
  *row3 = _mm_shuffle_epi32(*row3, _MM_SHUFFLE(1, 0, 3, 2));
  *row2 = _mm_shuffle_epi32(*row2, _MM_SHUFFLE(2, 1, 0, 3));
}

static inline __attribute__((always_inline)) void
compress_pre( vu_t        rows[4],
              uint  const cv[ static 8 ],
              uchar const block[ static FD_BLAKE3_BLOCK_SZ ],
              uint        block_len,
              ulong       ctr,
              uint        flags ) {
  rows[0] = vu_ld( cv   );
  rows[1] = vu_ld( cv+4 );
  rows[2] = vu( FD_BLAKE3_IV[0], FD_BLAKE3_IV[1], FD_BLAKE3_IV[2], FD_BLAKE3_IV[3] );
  rows[3] = vu( (uint)(ctr&UINT_MAX), (uint)(ctr>>32),
                block_len,            flags );

  vu_t m0 = vb_ldu( block    ); vu_t m1 = vb_ldu( block+16 );
  vu_t m2 = vb_ldu( block+32 ); vu_t m3 = vb_ldu( block+48 );

  vu_t t0, t1, t2, t3, tt;

  // Round 1. The first round permutes the message words from the original
  // input order, into the groups that get mixed in parallel.
  t0 = _mm_shuffle_ps2(m0, m1, _MM_SHUFFLE(2, 0, 2, 0)); //  6  4  2  0
  g1(&rows[0], &rows[1], &rows[2], &rows[3], t0);
  t1 = _mm_shuffle_ps2(m0, m1, _MM_SHUFFLE(3, 1, 3, 1)); //  7  5  3  1
  g2(&rows[0], &rows[1], &rows[2], &rows[3], t1);
  diagonalize(&rows[0], &rows[2], &rows[3]);
  t2 = _mm_shuffle_ps2(m2, m3, _MM_SHUFFLE(2, 0, 2, 0)); // 14 12 10  8
  t2 = _mm_shuffle_epi32(t2, _MM_SHUFFLE(2, 1, 0, 3));   // 12 10  8 14
  g1(&rows[0], &rows[1], &rows[2], &rows[3], t2);
  t3 = _mm_shuffle_ps2(m2, m3, _MM_SHUFFLE(3, 1, 3, 1)); // 15 13 11  9
  t3 = _mm_shuffle_epi32(t3, _MM_SHUFFLE(2, 1, 0, 3));   // 13 11  9 15
  g2(&rows[0], &rows[1], &rows[2], &rows[3], t3);
  undiagonalize(&rows[0], &rows[2], &rows[3]);
  m0 = t0;
  m1 = t1;
  m2 = t2;
  m3 = t3;

  // Round 2. This round and all following rounds apply a fixed permutation
  // to the message words from the round before.
  t0 = _mm_shuffle_ps2(m0, m1, _MM_SHUFFLE(3, 1, 1, 2));
  t0 = _mm_shuffle_epi32(t0, _MM_SHUFFLE(0, 3, 2, 1));
  g1(&rows[0], &rows[1], &rows[2], &rows[3], t0);
  t1 = _mm_shuffle_ps2(m2, m3, _MM_SHUFFLE(3, 3, 2, 2));
  tt = _mm_shuffle_epi32(m0, _MM_SHUFFLE(0, 0, 3, 3));
  t1 = _mm_blend_epi16(tt, t1, 0xCC);
  g2(&rows[0], &rows[1], &rows[2], &rows[3], t1);
  diagonalize(&rows[0], &rows[2], &rows[3]);
  t2 = _mm_unpacklo_epi64(m3, m1);
  tt = _mm_blend_epi16(t2, m2, 0xC0);
  t2 = _mm_shuffle_epi32(tt, _MM_SHUFFLE(1, 3, 2, 0));
  g1(&rows[0], &rows[1], &rows[2], &rows[3], t2);
  t3 = _mm_unpackhi_epi32(m1, m3);
  tt = _mm_unpacklo_epi32(m2, t3);
  t3 = _mm_shuffle_epi32(tt, _MM_SHUFFLE(0, 1, 3, 2));
  g2(&rows[0], &rows[1], &rows[2], &rows[3], t3);
  undiagonalize(&rows[0], &rows[2], &rows[3]);
  m0 = t0;
  m1 = t1;
  m2 = t2;
  m3 = t3;

  // Round 3
  t0 = _mm_shuffle_ps2(m0, m1, _MM_SHUFFLE(3, 1, 1, 2));
  t0 = _mm_shuffle_epi32(t0, _MM_SHUFFLE(0, 3, 2, 1));
  g1(&rows[0], &rows[1], &rows[2], &rows[3], t0);
  t1 = _mm_shuffle_ps2(m2, m3, _MM_SHUFFLE(3, 3, 2, 2));
  tt = _mm_shuffle_epi32(m0, _MM_SHUFFLE(0, 0, 3, 3));
  t1 = _mm_blend_epi16(tt, t1, 0xCC);
  g2(&rows[0], &rows[1], &rows[2], &rows[3], t1);
  diagonalize(&rows[0], &rows[2], &rows[3]);
  t2 = _mm_unpacklo_epi64(m3, m1);
  tt = _mm_blend_epi16(t2, m2, 0xC0);
  t2 = _mm_shuffle_epi32(tt, _MM_SHUFFLE(1, 3, 2, 0));
  g1(&rows[0], &rows[1], &rows[2], &rows[3], t2);
  t3 = _mm_unpackhi_epi32(m1, m3);
  tt = _mm_unpacklo_epi32(m2, t3);
  t3 = _mm_shuffle_epi32(tt, _MM_SHUFFLE(0, 1, 3, 2));
  g2(&rows[0], &rows[1], &rows[2], &rows[3], t3);
  undiagonalize(&rows[0], &rows[2], &rows[3]);
  m0 = t0;
  m1 = t1;
  m2 = t2;
  m3 = t3;

  // Round 4
  t0 = _mm_shuffle_ps2(m0, m1, _MM_SHUFFLE(3, 1, 1, 2));
  t0 = _mm_shuffle_epi32(t0, _MM_SHUFFLE(0, 3, 2, 1));
  g1(&rows[0], &rows[1], &rows[2], &rows[3], t0);
  t1 = _mm_shuffle_ps2(m2, m3, _MM_SHUFFLE(3, 3, 2, 2));
  tt = _mm_shuffle_epi32(m0, _MM_SHUFFLE(0, 0, 3, 3));
  t1 = _mm_blend_epi16(tt, t1, 0xCC);
  g2(&rows[0], &rows[1], &rows[2], &rows[3], t1);
  diagonalize(&rows[0], &rows[2], &rows[3]);
  t2 = _mm_unpacklo_epi64(m3, m1);
  tt = _mm_blend_epi16(t2, m2, 0xC0);
  t2 = _mm_shuffle_epi32(tt, _MM_SHUFFLE(1, 3, 2, 0));
  g1(&rows[0], &rows[1], &rows[2], &rows[3], t2);
  t3 = _mm_unpackhi_epi32(m1, m3);
  tt = _mm_unpacklo_epi32(m2, t3);
  t3 = _mm_shuffle_epi32(tt, _MM_SHUFFLE(0, 1, 3, 2));
  g2(&rows[0], &rows[1], &rows[2], &rows[3], t3);
  undiagonalize(&rows[0], &rows[2], &rows[3]);
  m0 = t0;
  m1 = t1;
  m2 = t2;
  m3 = t3;

  // Round 5
  t0 = _mm_shuffle_ps2(m0, m1, _MM_SHUFFLE(3, 1, 1, 2));
  t0 = _mm_shuffle_epi32(t0, _MM_SHUFFLE(0, 3, 2, 1));
  g1(&rows[0], &rows[1], &rows[2], &rows[3], t0);
  t1 = _mm_shuffle_ps2(m2, m3, _MM_SHUFFLE(3, 3, 2, 2));
  tt = _mm_shuffle_epi32(m0, _MM_SHUFFLE(0, 0, 3, 3));
  t1 = _mm_blend_epi16(tt, t1, 0xCC);
  g2(&rows[0], &rows[1], &rows[2], &rows[3], t1);
  diagonalize(&rows[0], &rows[2], &rows[3]);
  t2 = _mm_unpacklo_epi64(m3, m1);
  tt = _mm_blend_epi16(t2, m2, 0xC0);
  t2 = _mm_shuffle_epi32(tt, _MM_SHUFFLE(1, 3, 2, 0));
  g1(&rows[0], &rows[1], &rows[2], &rows[3], t2);
  t3 = _mm_unpackhi_epi32(m1, m3);
  tt = _mm_unpacklo_epi32(m2, t3);
  t3 = _mm_shuffle_epi32(tt, _MM_SHUFFLE(0, 1, 3, 2));
  g2(&rows[0], &rows[1], &rows[2], &rows[3], t3);
  undiagonalize(&rows[0], &rows[2], &rows[3]);
  m0 = t0;
  m1 = t1;
  m2 = t2;
  m3 = t3;

  // Round 6
  t0 = _mm_shuffle_ps2(m0, m1, _MM_SHUFFLE(3, 1, 1, 2));
  t0 = _mm_shuffle_epi32(t0, _MM_SHUFFLE(0, 3, 2, 1));
  g1(&rows[0], &rows[1], &rows[2], &rows[3], t0);
  t1 = _mm_shuffle_ps2(m2, m3, _MM_SHUFFLE(3, 3, 2, 2));
  tt = _mm_shuffle_epi32(m0, _MM_SHUFFLE(0, 0, 3, 3));
  t1 = _mm_blend_epi16(tt, t1, 0xCC);
  g2(&rows[0], &rows[1], &rows[2], &rows[3], t1);
  diagonalize(&rows[0], &rows[2], &rows[3]);
  t2 = _mm_unpacklo_epi64(m3, m1);
  tt = _mm_blend_epi16(t2, m2, 0xC0);
  t2 = _mm_shuffle_epi32(tt, _MM_SHUFFLE(1, 3, 2, 0));
  g1(&rows[0], &rows[1], &rows[2], &rows[3], t2);
  t3 = _mm_unpackhi_epi32(m1, m3);
  tt = _mm_unpacklo_epi32(m2, t3);
  t3 = _mm_shuffle_epi32(tt, _MM_SHUFFLE(0, 1, 3, 2));
  g2(&rows[0], &rows[1], &rows[2], &rows[3], t3);
  undiagonalize(&rows[0], &rows[2], &rows[3]);
  m0 = t0;
  m1 = t1;
  m2 = t2;
  m3 = t3;

  // Round 7
  t0 = _mm_shuffle_ps2(m0, m1, _MM_SHUFFLE(3, 1, 1, 2));
  t0 = _mm_shuffle_epi32(t0, _MM_SHUFFLE(0, 3, 2, 1));
  g1(&rows[0], &rows[1], &rows[2], &rows[3], t0);
  t1 = _mm_shuffle_ps2(m2, m3, _MM_SHUFFLE(3, 3, 2, 2));
  tt = _mm_shuffle_epi32(m0, _MM_SHUFFLE(0, 0, 3, 3));
  t1 = _mm_blend_epi16(tt, t1, 0xCC);
  g2(&rows[0], &rows[1], &rows[2], &rows[3], t1);
  diagonalize(&rows[0], &rows[2], &rows[3]);
  t2 = _mm_unpacklo_epi64(m3, m1);
  tt = _mm_blend_epi16(t2, m2, 0xC0);
  t2 = _mm_shuffle_epi32(tt, _MM_SHUFFLE(1, 3, 2, 0));
  g1(&rows[0], &rows[1], &rows[2], &rows[3], t2);
  t3 = _mm_unpackhi_epi32(m1, m3);
  tt = _mm_unpacklo_epi32(m2, t3);
  t3 = _mm_shuffle_epi32(tt, _MM_SHUFFLE(0, 1, 3, 2));
  g2(&rows[0], &rows[1], &rows[2], &rows[3], t3);
  undiagonalize(&rows[0], &rows[2], &rows[3]);
}

void
fd_blake3_sse_compress1( uchar * restrict       out,
                         uchar const * restrict msg,
                         uint                   msg_sz,
                         ulong                  counter,
                         uint                   flags ) {
  FD_BLAKE3_TRACE(( "fd_blake3_sse_compress1(out=%p,msg=%p,sz=%u,counter=%lu,flags=%02x)",
                    (void *)out, (void *)msg, msg_sz, counter, flags ));
  assert( msg_sz<=FD_BLAKE3_CHUNK_SZ );

  uint cv[8] = { FD_BLAKE3_IV[0], FD_BLAKE3_IV[1], FD_BLAKE3_IV[2], FD_BLAKE3_IV[3],
                 FD_BLAKE3_IV[4], FD_BLAKE3_IV[5], FD_BLAKE3_IV[6], FD_BLAKE3_IV[7] };
  vu_t rows[4];

  uint flag_mask = ~fd_uint_if( flags&FD_BLAKE3_FLAG_PARENT,
                                FD_BLAKE3_FLAG_CHUNK_START|FD_BLAKE3_FLAG_CHUNK_END,
                                0U );

  uint block_flags = flags | (flag_mask & FD_BLAKE3_FLAG_CHUNK_START);
  do {
    uint block_sz = fd_uint_min( msg_sz, FD_BLAKE3_BLOCK_SZ );
    block_flags |= FD_BLAKE3_FLAG_CHUNK_END;
    block_flags &= (flag_mask & ~fd_uint_if( msg_sz<=FD_BLAKE3_BLOCK_SZ, 0, (FD_BLAKE3_FLAG_CHUNK_END|FD_BLAKE3_FLAG_ROOT) ) );

    uchar tail[ FD_BLAKE3_BLOCK_SZ ] __attribute__((aligned(16)));
    uchar const * restrict block;
    if( FD_LIKELY( msg_sz>=FD_BLAKE3_BLOCK_SZ ) ) {
      block = msg;
    } else {
      vb_st( tail,    vu_zero() );
      vb_st( tail+16, vu_zero() );
      vb_st( tail+32, vu_zero() );
      vb_st( tail+48, vu_zero() );
      fd_memcpy( tail, msg, msg_sz );
      block = tail;
    }

    compress_pre( rows, cv, block, block_sz, counter, block_flags );
    vu_st( cv,   vu_xor( rows[0], rows[2] ) );
    vu_st( cv+4, vu_xor( rows[1], rows[3] ) );
    msg    += FD_BLAKE3_BLOCK_SZ;
    msg_sz -= (uint)FD_BLAKE3_BLOCK_SZ;
    block_flags = flags;
  } while( (int)msg_sz>0 );

  vu_stu( out,    vu_ld( cv   ) );
  vu_stu( out+16, vu_ld( cv+4 ) );
}
