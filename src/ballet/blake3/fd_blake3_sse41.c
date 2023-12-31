
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
              uint        flags) {
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

static inline __attribute__((always_inline)) void
round_fn4( vu_t  v[16],
           vu_t  m[16],
           ulong r ) {
  v[ 0] = vu_add(v[0], m[(ulong)FD_BLAKE3_MSG_SCHEDULE[r][0]]);
  v[ 1] = vu_add(v[1], m[(ulong)FD_BLAKE3_MSG_SCHEDULE[r][2]]);
  v[ 2] = vu_add(v[2], m[(ulong)FD_BLAKE3_MSG_SCHEDULE[r][4]]);
  v[ 3] = vu_add(v[3], m[(ulong)FD_BLAKE3_MSG_SCHEDULE[r][6]]);
  v[ 0] = vu_add(v[0], v[4]);
  v[ 1] = vu_add(v[1], v[5]);
  v[ 2] = vu_add(v[2], v[6]);
  v[ 3] = vu_add(v[3], v[7]);
  v[12] = vu_xor(v[12], v[0]);
  v[13] = vu_xor(v[13], v[1]);
  v[14] = vu_xor(v[14], v[2]);
  v[15] = vu_xor(v[15], v[3]);
  v[12] = vu_rot16(v[12]);
  v[13] = vu_rot16(v[13]);
  v[14] = vu_rot16(v[14]);
  v[15] = vu_rot16(v[15]);
  v[ 8] = vu_add(v[8], v[12]);
  v[ 9] = vu_add(v[9], v[13]);
  v[10] = vu_add(v[10], v[14]);
  v[11] = vu_add(v[11], v[15]);
  v[ 4] = vu_xor(v[4], v[8]);
  v[ 5] = vu_xor(v[5], v[9]);
  v[ 6] = vu_xor(v[6], v[10]);
  v[ 7] = vu_xor(v[7], v[11]);
  v[ 4] = vu_rot12(v[4]);
  v[ 5] = vu_rot12(v[5]);
  v[ 6] = vu_rot12(v[6]);
  v[ 7] = vu_rot12(v[7]);
  v[ 0] = vu_add(v[0], m[(ulong)FD_BLAKE3_MSG_SCHEDULE[r][1]]);
  v[ 1] = vu_add(v[1], m[(ulong)FD_BLAKE3_MSG_SCHEDULE[r][3]]);
  v[ 2] = vu_add(v[2], m[(ulong)FD_BLAKE3_MSG_SCHEDULE[r][5]]);
  v[ 3] = vu_add(v[3], m[(ulong)FD_BLAKE3_MSG_SCHEDULE[r][7]]);
  v[ 0] = vu_add(v[0], v[4]);
  v[ 1] = vu_add(v[1], v[5]);
  v[ 2] = vu_add(v[2], v[6]);
  v[ 3] = vu_add(v[3], v[7]);
  v[12] = vu_xor(v[12], v[0]);
  v[13] = vu_xor(v[13], v[1]);
  v[14] = vu_xor(v[14], v[2]);
  v[15] = vu_xor(v[15], v[3]);
  v[12] = vu_rot8(v[12]);
  v[13] = vu_rot8(v[13]);
  v[14] = vu_rot8(v[14]);
  v[15] = vu_rot8(v[15]);
  v[ 8] = vu_add(v[8], v[12]);
  v[ 9] = vu_add(v[9], v[13]);
  v[10] = vu_add(v[10], v[14]);
  v[11] = vu_add(v[11], v[15]);
  v[ 4] = vu_xor(v[4], v[8]);
  v[ 5] = vu_xor(v[5], v[9]);
  v[ 6] = vu_xor(v[6], v[10]);
  v[ 7] = vu_xor(v[7], v[11]);
  v[ 4] = vu_rot7(v[4]);
  v[ 5] = vu_rot7(v[5]);
  v[ 6] = vu_rot7(v[6]);
  v[ 7] = vu_rot7(v[7]);

  v[ 0] = vu_add(v[0], m[(ulong)FD_BLAKE3_MSG_SCHEDULE[r][8]]);
  v[ 1] = vu_add(v[1], m[(ulong)FD_BLAKE3_MSG_SCHEDULE[r][10]]);
  v[ 2] = vu_add(v[2], m[(ulong)FD_BLAKE3_MSG_SCHEDULE[r][12]]);
  v[ 3] = vu_add(v[3], m[(ulong)FD_BLAKE3_MSG_SCHEDULE[r][14]]);
  v[ 0] = vu_add(v[0], v[5]);
  v[ 1] = vu_add(v[1], v[6]);
  v[ 2] = vu_add(v[2], v[7]);
  v[ 3] = vu_add(v[3], v[4]);
  v[15] = vu_xor(v[15], v[0]);
  v[12] = vu_xor(v[12], v[1]);
  v[13] = vu_xor(v[13], v[2]);
  v[14] = vu_xor(v[14], v[3]);
  v[15] = vu_rot16(v[15]);
  v[12] = vu_rot16(v[12]);
  v[13] = vu_rot16(v[13]);
  v[14] = vu_rot16(v[14]);
  v[10] = vu_add(v[10], v[15]);
  v[11] = vu_add(v[11], v[12]);
  v[ 8] = vu_add(v[8], v[13]);
  v[ 9] = vu_add(v[9], v[14]);
  v[ 5] = vu_xor(v[5], v[10]);
  v[ 6] = vu_xor(v[6], v[11]);
  v[ 7] = vu_xor(v[7], v[8]);
  v[ 4] = vu_xor(v[4], v[9]);
  v[ 5] = vu_rot12(v[5]);
  v[ 6] = vu_rot12(v[6]);
  v[ 7] = vu_rot12(v[7]);
  v[ 4] = vu_rot12(v[4]);
  v[ 0] = vu_add(v[0], m[(ulong)FD_BLAKE3_MSG_SCHEDULE[r][9]]);
  v[ 1] = vu_add(v[1], m[(ulong)FD_BLAKE3_MSG_SCHEDULE[r][11]]);
  v[ 2] = vu_add(v[2], m[(ulong)FD_BLAKE3_MSG_SCHEDULE[r][13]]);
  v[ 3] = vu_add(v[3], m[(ulong)FD_BLAKE3_MSG_SCHEDULE[r][15]]);
  v[ 0] = vu_add(v[0], v[5]);
  v[ 1] = vu_add(v[1], v[6]);
  v[ 2] = vu_add(v[2], v[7]);
  v[ 3] = vu_add(v[3], v[4]);
  v[15] = vu_xor(v[15], v[0]);
  v[12] = vu_xor(v[12], v[1]);
  v[13] = vu_xor(v[13], v[2]);
  v[14] = vu_xor(v[14], v[3]);
  v[15] = vu_rot8(v[15]);
  v[12] = vu_rot8(v[12]);
  v[13] = vu_rot8(v[13]);
  v[14] = vu_rot8(v[14]);
  v[10] = vu_add(v[10], v[15]);
  v[11] = vu_add(v[11], v[12]);
  v[ 8] = vu_add(v[8], v[13]);
  v[ 9] = vu_add(v[9], v[14]);
  v[ 5] = vu_xor(v[5], v[10]);
  v[ 6] = vu_xor(v[6], v[11]);
  v[ 7] = vu_xor(v[7], v[8]);
  v[ 4] = vu_xor(v[4], v[9]);
  v[ 5] = vu_rot7(v[5]);
  v[ 6] = vu_rot7(v[6]);
  v[ 7] = vu_rot7(v[7]);
  v[ 4] = vu_rot7(v[4]);
}

void
fd_blake3_sse_compress1( uchar * restrict       out,
                         uchar const * restrict msg,
                         uint                   msg_sz,
                         ulong                  counter,
                         uint                   flags ) {

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

void
fd_blake3_sse_compress4_fast( uchar const * restrict msg,
                              uchar       * restrict _out,
                              ulong                  counter,
                              uchar                  flags ) {

  uchar * restrict out = __builtin_assume_aligned( _out, 16 );

  int   parent   = flags & FD_BLAKE3_FLAG_PARENT;
  int   lg_sz    = fd_int_if( parent, FD_BLAKE3_OUTCHAIN_LG_SZ+1, FD_BLAKE3_CHUNK_LG_SZ );
  ulong sz       = 1UL<<lg_sz;

  /* counters stay the same for each block.  Across chunks, they
     increment if we are hashing leaves.  Otherwise, they are zero. */

  vu_t ctr_add   = vu_and( vu_bcast( parent ? UINT_MAX : 0 ),
                           vu( 0, 1, 2, 3 ) );
  vu_t ctr_lo    = vu_add( vu_bcast( counter ), ctr_add );
  vu_t ctr_carry = vi_gt ( vu_xor( ctr_add, vu_bcast( 0x80000000 ) ),
                           vu_xor( ctr_lo,  vu_bcast( 0x80000000 ) ) );
  vu_t ctr_hi    = vu_sub( vu_bcast( counter>>32 ), ctr_carry );
  vu_t sz_vec    = vu_bcast( FD_BLAKE3_BLOCK_SZ );

  vu_t const iv0 = vu_bcast( FD_BLAKE3_IV[0] );
  vu_t const iv1 = vu_bcast( FD_BLAKE3_IV[1] );
  vu_t const iv2 = vu_bcast( FD_BLAKE3_IV[2] );
  vu_t const iv3 = vu_bcast( FD_BLAKE3_IV[3] );
  vu_t const iv4 = vu_bcast( FD_BLAKE3_IV[4] );
  vu_t const iv5 = vu_bcast( FD_BLAKE3_IV[5] );
  vu_t const iv6 = vu_bcast( FD_BLAKE3_IV[6] );
  vu_t const iv7 = vu_bcast( FD_BLAKE3_IV[7] );

  vu_t h0=iv0; vu_t h1=iv1; vu_t h2=iv2; vu_t h3=iv3;
  vu_t h4=iv4; vu_t h5=iv5; vu_t h6=iv6; vu_t h7=iv7;

  ulong off = 0UL;
  do {
    ulong const off_next = off+FD_BLAKE3_BLOCK_SZ;
    int block_start = off     ==0UL;
    int block_end   = off_next==sz;
    int chunk_flags =
        ( block_start ? FD_BLAKE3_FLAG_CHUNK_START : 0 ) |
        ( block_end   ? FD_BLAKE3_FLAG_CHUNK_END   : 0 );
    int flags_ = flags  | fd_int_if( parent, 0, chunk_flags );
        flags_ = flags_ & fd_int_if( block_end, 0xFF, (int)(~FD_BLAKE3_FLAG_ROOT) );
    vu_t flags_vec = vu_bcast( flags_ );

    vu_t m[16];
    m[ 0] = vu_ldu( msg + (0<<lg_sz) + off      );
    m[ 1] = vu_ldu( msg + (1<<lg_sz) + off      );
    m[ 2] = vu_ldu( msg + (2<<lg_sz) + off      );
    m[ 3] = vu_ldu( msg + (3<<lg_sz) + off      );
    m[ 4] = vu_ldu( msg + (0<<lg_sz) + off + 16 );
    m[ 5] = vu_ldu( msg + (1<<lg_sz) + off + 16 );
    m[ 6] = vu_ldu( msg + (2<<lg_sz) + off + 16 );
    m[ 7] = vu_ldu( msg + (3<<lg_sz) + off + 16 );
    m[ 8] = vu_ldu( msg + (0<<lg_sz) + off + 32 );
    m[ 9] = vu_ldu( msg + (1<<lg_sz) + off + 32 );
    m[10] = vu_ldu( msg + (2<<lg_sz) + off + 32 );
    m[11] = vu_ldu( msg + (3<<lg_sz) + off + 32 );
    m[12] = vu_ldu( msg + (0<<lg_sz) + off + 48 );
    m[13] = vu_ldu( msg + (1<<lg_sz) + off + 48 );
    m[14] = vu_ldu( msg + (2<<lg_sz) + off + 48 );
    m[15] = vu_ldu( msg + (3<<lg_sz) + off + 48 );

    vu_transpose_4x4( m[0x0], m[0x1], m[0x2], m[0x3],
                      m[0x0], m[0x1], m[0x2], m[0x3] );
    vu_transpose_4x4( m[0x4], m[0x5], m[0x6], m[0x7],
                      m[0x4], m[0x5], m[0x6], m[0x7] );
    vu_transpose_4x4( m[0x8], m[0x9], m[0xa], m[0xb],
                      m[0x8], m[0x9], m[0xa], m[0xb] );
    vu_transpose_4x4( m[0xc], m[0xd], m[0xe], m[0xf],
                      m[0xc], m[0xd], m[0xe], m[0xf] );

    vu_t v[16] = {
        h0,        h1,        h2,        h3,
        h4,        h5,        h6,        h7,
        iv0,       iv1,       iv2,       iv3,
        ctr_lo,    ctr_hi,    sz_vec,    flags_vec,
    };
    round_fn4( v, m, 0 );
    round_fn4( v, m, 1 );
    round_fn4( v, m, 2 );
    round_fn4( v, m, 3 );
    round_fn4( v, m, 4 );
    round_fn4( v, m, 5 );
    round_fn4( v, m, 6 );
    h0 = vu_xor( v[ 0], v[ 8] );
    h1 = vu_xor( v[ 1], v[ 9] );
    h2 = vu_xor( v[ 2], v[10] );
    h3 = vu_xor( v[ 3], v[11] );
    h4 = vu_xor( v[ 4], v[12] );
    h5 = vu_xor( v[ 5], v[13] );
    h6 = vu_xor( v[ 6], v[14] );
    h7 = vu_xor( v[ 7], v[15] );

    off = off_next;
  } while( FD_LIKELY( off!=sz ) );  /* optimize for large blocks */

  vu_transpose_4x4( h0, h1, h2, h3,
                    h0, h1, h2, h3 );
  vu_transpose_4x4( h0, h1, h2, h3,
                    h0, h1, h2, h3 );

  // The first four vecs now contain the first half of each output, and the
  // second four vecs contain the second half of each output.
  vu_st( (uint *)( out + 0*32      ), h0 );
  vu_st( (uint *)( out + 0*32 + 16 ), h4 );
  vu_st( (uint *)( out + 1*32      ), h1 );
  vu_st( (uint *)( out + 1*32 + 16 ), h5 );
  vu_st( (uint *)( out + 2*32      ), h2 );
  vu_st( (uint *)( out + 2*32 + 16 ), h6 );
  vu_st( (uint *)( out + 3*32      ), h3 );
  vu_st( (uint *)( out + 3*32 + 16 ), h7 );
}
