#include "fd_blake3_private.h"

#include <arm_sve.h>

/* Message words are added before the b term so the load is off the
   critical path. */

#define G( a, b, c, d, x, y ) do {                                     \
    (a) = svadd_u32_x( pg4, svadd_u32_x( pg4, (a), (x) ), (b) );         \
    (d) = svxar_n_u32( (d), (a), 16 );                                   \
    (c) = svadd_u32_x( pg4, (c), (d) );                                  \
    (b) = svxar_n_u32( (b), (c), 12 );                                   \
    (a) = svadd_u32_x( pg4, svadd_u32_x( pg4, (a), (y) ), (b) );         \
    (d) = svxar_n_u32( (d), (a),  8 );                                   \
    (c) = svadd_u32_x( pg4, (c), (d) );                                  \
    (b) = svxar_n_u32( (b), (c),  7 );                                   \
  } while(0)

#define ROUND( M ) do {                  \
    G( v0, v4, v8,  v12, M( 0), M( 1) ); \
    G( v1, v5, v9,  v13, M( 2), M( 3) ); \
    G( v2, v6, v10, v14, M( 4), M( 5) ); \
    G( v3, v7, v11, v15, M( 6), M( 7) ); \
    G( v0, v5, v10, v15, M( 8), M( 9) ); \
    G( v1, v6, v11, v12, M(10), M(11) ); \
    G( v2, v7, v8,  v13, M(12), M(13) ); \
    G( v3, v4, v9,  v14, M(14), M(15) ); \
  } while(0)

/* 4x4 transpose of 32-bit words (lane-major <-> word-major) */

#define T4( r0, r1, r2, r3, o0, o1, o2, o3 ) do {                                                             \
    svuint32_t _t0 = svtrn1_u32( (r0), (r1) );                                                                  \
    svuint32_t _t1 = svtrn2_u32( (r0), (r1) );                                                                  \
    svuint32_t _t2 = svtrn1_u32( (r2), (r3) );                                                                  \
    svuint32_t _t3 = svtrn2_u32( (r2), (r3) );                                                                  \
    (o0) = svreinterpret_u32_u64( svtrn1_u64( svreinterpret_u64_u32( _t0 ), svreinterpret_u64_u32( _t2 ) ) );   \
    (o1) = svreinterpret_u32_u64( svtrn1_u64( svreinterpret_u64_u32( _t1 ), svreinterpret_u64_u32( _t3 ) ) );   \
    (o2) = svreinterpret_u32_u64( svtrn2_u64( svreinterpret_u64_u32( _t0 ), svreinterpret_u64_u32( _t2 ) ) );   \
    (o3) = svreinterpret_u32_u64( svtrn2_u64( svreinterpret_u64_u32( _t1 ), svreinterpret_u64_u32( _t3 ) ) );   \
  } while(0)

/* Dead lanes read from this block */

static uint const fd_blake3_sve2_zero_block[ 16 ] __attribute__((aligned(64)));

void
fd_blake3_sve2_compress4( ulong                   batch_cnt,
                          void const   * restrict _batch_data,
                          uint const   * restrict batch_sz,
                          ulong const  * restrict ctr_vec,
                          uint const   * restrict batch_flags,
                          void * const * restrict _batch_hash,
                          uint                    out_sz,
                          void const   * restrict _batch_cv ) {
  if( FD_UNLIKELY( !batch_cnt || batch_cnt>4UL ) ) FD_LOG_ERR(( "Invalid batch_cnt %lu", batch_cnt ));
  if( FD_UNLIKELY( out_sz!=32U && out_sz!=64U ) )  FD_LOG_ERR(( "Invalid out_sz %u", out_sz ));

  void const * const * batch_data = (void const * const *)_batch_data;
  void const * const * batch_cv   = (void const * const *)_batch_cv;
  void       * const * batch_hash = (void       * const *)_batch_hash;

  svbool_t const pg4 = svwhilelt_b32_u64( 0UL, 4UL );

  uint cv_words[8][4] __attribute__((aligned(64)));
  for( ulong word=0UL; word<8UL; word++ ) {
    for( ulong lane=0UL; lane<4UL; lane++ ) cv_words[word][lane] = FD_BLAKE3_IV[word];
  }
  if( FD_UNLIKELY( batch_cv ) ) {
    for( ulong lane=0UL; lane<batch_cnt; lane++ ) {
      uchar const * cv = (uchar const *)batch_cv[lane];
      for( ulong word=0UL; word<8UL; word++ ) cv_words[word][lane] = FD_LOAD( uint, cv+4UL*word );
    }
  }

  svuint32_t h0 = svld1_u32( pg4, cv_words[0] );
  svuint32_t h1 = svld1_u32( pg4, cv_words[1] );
  svuint32_t h2 = svld1_u32( pg4, cv_words[2] );
  svuint32_t h3 = svld1_u32( pg4, cv_words[3] );
  svuint32_t h4 = svld1_u32( pg4, cv_words[4] );
  svuint32_t h5 = svld1_u32( pg4, cv_words[5] );
  svuint32_t h6 = svld1_u32( pg4, cv_words[6] );
  svuint32_t h7 = svld1_u32( pg4, cv_words[7] );

  svuint32_t hu0 = svdup_n_u32( 0U );
  svuint32_t hu1 = svdup_n_u32( 0U );
  svuint32_t hu2 = svdup_n_u32( 0U );
  svuint32_t hu3 = svdup_n_u32( 0U );
  svuint32_t hu4 = svdup_n_u32( 0U );
  svuint32_t hu5 = svdup_n_u32( 0U );
  svuint32_t hu6 = svdup_n_u32( 0U );
  svuint32_t hu7 = svdup_n_u32( 0U );

  uint ctr_lo_lane[4] __attribute__((aligned(16))) = {0U};
  uint ctr_hi_lane[4] __attribute__((aligned(16))) = {0U};
  uint block_cnt [4] = {0U};
  uint block_max = 0U;
  for( ulong lane=0UL; lane<batch_cnt; lane++ ) {
    if( FD_UNLIKELY( batch_sz[lane]>FD_BLAKE3_CHUNK_SZ ) )
      FD_LOG_ERR(( "Invalid batch_sz[%lu] %u", lane, batch_sz[lane] ));
    ctr_lo_lane[lane] = (uint)ctr_vec[lane];
    ctr_hi_lane[lane] = (uint)(ctr_vec[lane]>>32);
    block_cnt[lane]   = fd_uint_max( 1U, (batch_sz[lane]+63U)>>6 );
    block_max         = fd_uint_max( block_max, block_cnt[lane] );
  }
  svuint32_t const ctr_lo = svld1_u32( pg4, ctr_lo_lane );
  svuint32_t const ctr_hi = svld1_u32( pg4, ctr_hi_lane );

  for( uint block_idx=0U; block_idx<block_max; block_idx++ ) {
    uint const * src[4];
    uint  pad   [4][16]                 __attribute__((aligned(64)));
    uint  words [16][4]                 __attribute__((aligned(64)));
    uint  active_lane[4]                __attribute__((aligned(16))) = {0U};
    uint  block_len_lane[4]             __attribute__((aligned(16))) = {0U};
    uint  block_flag_lane[4]            __attribute__((aligned(16))) = {0U};

    for( ulong lane=0UL; lane<4UL; lane++ ) {
      src[lane] = fd_blake3_sve2_zero_block;
      if( lane>=batch_cnt || block_idx>=block_cnt[lane] ) continue;

      uint const off       = block_idx<<6;
      uint const block_len = fd_uint_min( batch_sz[lane]-off, (uint)FD_BLAKE3_BLOCK_SZ );
      uint       flags     = batch_flags[lane];
      int const  parent    = !!(flags & FD_BLAKE3_FLAG_PARENT);
      int const  last      = block_idx+1U==block_cnt[lane];

      if( !last ) flags &= ~FD_BLAKE3_FLAG_ROOT;
      if( out_sz==32U && !parent ) {
        if( !block_idx && (!batch_cv || (flags & FD_BLAKE3_FLAG_CHUNK_START)) ) flags |= FD_BLAKE3_FLAG_CHUNK_START;
        if( last ) flags |= FD_BLAKE3_FLAG_CHUNK_END;
      }

      active_lane   [lane] = UINT_MAX;
      block_len_lane[lane] = block_len;
      block_flag_lane[lane] = flags;

      /* Full blocks load straight from the input; only a short tail
         block is copied (zero padded) */
      uchar const * block = (uchar const *)batch_data[lane]+off;
      if( FD_LIKELY( block_len==FD_BLAKE3_BLOCK_SZ ) ) {
        src[lane] = (uint const *)block;
      } else {
        memset( pad[lane], 0, FD_BLAKE3_BLOCK_SZ );
        if( block_len ) fd_memcpy( pad[lane], block, block_len );
        src[lane] = pad[lane];
      }
    }

    for( ulong q=0UL; q<4UL; q++ ) {
      svuint32_t w0, w1, w2, w3;
      T4( svld1_u32( pg4, src[0]+4UL*q ), svld1_u32( pg4, src[1]+4UL*q ),
          svld1_u32( pg4, src[2]+4UL*q ), svld1_u32( pg4, src[3]+4UL*q ), w0, w1, w2, w3 );
      svst1_u32( pg4, words[4UL*q+0UL], w0 );
      svst1_u32( pg4, words[4UL*q+1UL], w1 );
      svst1_u32( pg4, words[4UL*q+2UL], w2 );
      svst1_u32( pg4, words[4UL*q+3UL], w3 );
    }

    svbool_t const active = svcmpne_n_u32( pg4, svld1_u32( pg4, active_lane ), 0U );
    svuint32_t const block_len  = svld1_u32( pg4, block_len_lane  );
    svuint32_t const block_flag = svld1_u32( pg4, block_flag_lane );

    svuint32_t v0  = h0;
    svuint32_t v1  = h1;
    svuint32_t v2  = h2;
    svuint32_t v3  = h3;
    svuint32_t v4  = h4;
    svuint32_t v5  = h5;
    svuint32_t v6  = h6;
    svuint32_t v7  = h7;
    svuint32_t v8  = svdup_n_u32( FD_BLAKE3_IV[0] );
    svuint32_t v9  = svdup_n_u32( FD_BLAKE3_IV[1] );
    svuint32_t v10 = svdup_n_u32( FD_BLAKE3_IV[2] );
    svuint32_t v11 = svdup_n_u32( FD_BLAKE3_IV[3] );
    svuint32_t v12 = ctr_lo;
    svuint32_t v13 = ctr_hi;
    svuint32_t v14 = block_len;
    svuint32_t v15 = block_flag;

#define M( idx ) svld1_u32( pg4, words[ FD_BLAKE3_MSG_SCHEDULE[ round ][ (idx) ] ] )
    _Pragma( "GCC unroll 7" )
    for( ulong round=0UL; round<7UL; round++ ) ROUND( M );
#undef M

    svuint32_t const d0 = sveor_u32_x( pg4, v0, v8  );
    svuint32_t const d1 = sveor_u32_x( pg4, v1, v9  );
    svuint32_t const d2 = sveor_u32_x( pg4, v2, v10 );
    svuint32_t const d3 = sveor_u32_x( pg4, v3, v11 );
    svuint32_t const d4 = sveor_u32_x( pg4, v4, v12 );
    svuint32_t const d5 = sveor_u32_x( pg4, v5, v13 );
    svuint32_t const d6 = sveor_u32_x( pg4, v6, v14 );
    svuint32_t const d7 = sveor_u32_x( pg4, v7, v15 );

    if( FD_UNLIKELY( out_sz==64U ) ) {
      hu0 = svsel_u32( active, sveor_u32_x( pg4, h0, v8  ), hu0 );
      hu1 = svsel_u32( active, sveor_u32_x( pg4, h1, v9  ), hu1 );
      hu2 = svsel_u32( active, sveor_u32_x( pg4, h2, v10 ), hu2 );
      hu3 = svsel_u32( active, sveor_u32_x( pg4, h3, v11 ), hu3 );
      hu4 = svsel_u32( active, sveor_u32_x( pg4, h4, v12 ), hu4 );
      hu5 = svsel_u32( active, sveor_u32_x( pg4, h5, v13 ), hu5 );
      hu6 = svsel_u32( active, sveor_u32_x( pg4, h6, v14 ), hu6 );
      hu7 = svsel_u32( active, sveor_u32_x( pg4, h7, v15 ), hu7 );
    }

    h0 = svsel_u32( active, d0, h0 );
    h1 = svsel_u32( active, d1, h1 );
    h2 = svsel_u32( active, d2, h2 );
    h3 = svsel_u32( active, d3, h3 );
    h4 = svsel_u32( active, d4, h4 );
    h5 = svsel_u32( active, d5, h5 );
    h6 = svsel_u32( active, d6, h6 );
    h7 = svsel_u32( active, d7, h7 );
  }

  /* Transpose back to lane-major and store each live lane's output */

  svuint32_t o0, o1, o2, o3;
  uint *     out[4];
  for( ulong lane=0UL; lane<4UL; lane++ ) out[lane] = lane<batch_cnt ? (uint *)batch_hash[lane] : NULL;
#define OUT4( x0, x1, x2, x3, word ) do {                          \
    T4( x0, x1, x2, x3, o0, o1, o2, o3 );                           \
    if( out[0] ) svst1_u32( pg4, out[0]+(word), o0 );               \
    if( out[1] ) svst1_u32( pg4, out[1]+(word), o1 );               \
    if( out[2] ) svst1_u32( pg4, out[2]+(word), o2 );               \
    if( out[3] ) svst1_u32( pg4, out[3]+(word), o3 );               \
  } while(0)
  OUT4( h0, h1, h2, h3, 0 );
  OUT4( h4, h5, h6, h7, 4 );
  if( FD_UNLIKELY( out_sz==64U ) ) {
    OUT4( hu0, hu1, hu2, hu3,  8 );
    OUT4( hu4, hu5, hu6, hu7, 12 );
  }
#undef OUT4
}

void
fd_blake3_sve2_compress4_fast( uchar const * restrict batch_data,
                               uchar       * restrict batch_hash,
                               ulong                  counter,
                               uchar                  flags ) {
  int const   parent = !!(flags & FD_BLAKE3_FLAG_PARENT);
  ulong const stride = parent ? 64UL : 1024UL;

  void const * data[4];
  void *       hash[4];
  uint         sz[4];
  ulong        ctr[4];
  uint         flag[4];
  for( ulong lane=0UL; lane<4UL; lane++ ) {
    data[lane] = batch_data + lane*stride;
    hash[lane] = batch_hash + lane*FD_BLAKE3_OUTCHAIN_SZ;
    sz  [lane] = (uint)stride;
    ctr [lane] = counter + (parent ? 0UL : lane);
    flag[lane] = flags;
  }
  fd_blake3_sve2_compress4( 4UL, data, sz, ctr, flag, hash, 32U, NULL );
}

void
fd_blake3_sve2_xof4( uchar const * restrict root_msg,
                     uchar const * restrict root_cv,
                     ulong                  ctr0,
                     uint                   block_sz,
                     uint                   flags,
                     uchar       * restrict out ) {
  svbool_t const pg4 = svwhilelt_b32_u64( 0UL, 4UL );

  /* All lanes share the message and chaining value, so each message
     word is a broadcast and nothing needs transposing on the way in */

  uchar block[ FD_BLAKE3_BLOCK_SZ ] __attribute__((aligned(16))) = {0};
  fd_memcpy( block, root_msg, fd_uint_min( block_sz, (uint)FD_BLAKE3_BLOCK_SZ ) );
  uint msg[16];
  for( ulong i=0UL; i<16UL; i++ ) msg[i] = FD_LOAD( uint, block+4UL*i );
  uint cv[8];
  for( ulong i=0UL; i<8UL;  i++ ) cv[i]  = FD_LOAD( uint, root_cv+4UL*i );

  /* counters ctr0..ctr0+3, split into lo/hi 32-bit words */
  svuint64_t const c01 = svindex_u64( ctr0,     1UL );
  svuint64_t const c23 = svindex_u64( ctr0+2UL, 1UL );

  svuint32_t v0  = svdup_n_u32( cv[0] );
  svuint32_t v1  = svdup_n_u32( cv[1] );
  svuint32_t v2  = svdup_n_u32( cv[2] );
  svuint32_t v3  = svdup_n_u32( cv[3] );
  svuint32_t v4  = svdup_n_u32( cv[4] );
  svuint32_t v5  = svdup_n_u32( cv[5] );
  svuint32_t v6  = svdup_n_u32( cv[6] );
  svuint32_t v7  = svdup_n_u32( cv[7] );
  svuint32_t v8  = svdup_n_u32( FD_BLAKE3_IV[0] );
  svuint32_t v9  = svdup_n_u32( FD_BLAKE3_IV[1] );
  svuint32_t v10 = svdup_n_u32( FD_BLAKE3_IV[2] );
  svuint32_t v11 = svdup_n_u32( FD_BLAKE3_IV[3] );
  svuint32_t v12 = svuzp1_u32( svreinterpret_u32_u64( c01 ), svreinterpret_u32_u64( c23 ) );
  svuint32_t v13 = svuzp2_u32( svreinterpret_u32_u64( c01 ), svreinterpret_u32_u64( c23 ) );
  svuint32_t v14 = svdup_n_u32( block_sz );
  svuint32_t v15 = svdup_n_u32( flags    );

#define M( idx ) svdup_n_u32( msg[ FD_BLAKE3_MSG_SCHEDULE[ round ][ (idx) ] ] )
  _Pragma( "GCC unroll 7" )
  for( ulong round=0UL; round<7UL; round++ ) ROUND( M );
#undef M

  /* 64 byte XOF output: words 0..7 are v[i]^v[i+8], words 8..15 are
     v[i+8]^cv[i].  Transpose to one 64 byte output block per lane. */

  svuint32_t o0, o1, o2, o3;
#define OUT4( x0, x1, x2, x3, off ) do {                    \
    T4( x0, x1, x2, x3, o0, o1, o2, o3 );                    \
    svst1_u32( pg4, (uint *)( out +   0UL + (off) ), o0 );   \
    svst1_u32( pg4, (uint *)( out +  64UL + (off) ), o1 );   \
    svst1_u32( pg4, (uint *)( out + 128UL + (off) ), o2 );   \
    svst1_u32( pg4, (uint *)( out + 192UL + (off) ), o3 );   \
  } while(0)
  OUT4( sveor_u32_x( pg4, v0, v8  ), sveor_u32_x( pg4, v1, v9  ), sveor_u32_x( pg4, v2, v10 ), sveor_u32_x( pg4, v3, v11 ),  0UL );
  OUT4( sveor_u32_x( pg4, v4, v12 ), sveor_u32_x( pg4, v5, v13 ), sveor_u32_x( pg4, v6, v14 ), sveor_u32_x( pg4, v7, v15 ), 16UL );
  OUT4( sveor_n_u32_x( pg4, v8,  cv[0] ), sveor_n_u32_x( pg4, v9,  cv[1] ), sveor_n_u32_x( pg4, v10, cv[2] ), sveor_n_u32_x( pg4, v11, cv[3] ), 32UL );
  OUT4( sveor_n_u32_x( pg4, v12, cv[4] ), sveor_n_u32_x( pg4, v13, cv[5] ), sveor_n_u32_x( pg4, v14, cv[6] ), sveor_n_u32_x( pg4, v15, cv[7] ), 48UL );
#undef OUT4
}

#undef T4
#undef ROUND
#undef G
