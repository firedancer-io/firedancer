#include "fd_blake3_private.h"

#include <arm_sve.h>

#define G( a, b, c, d, x, y ) do {       \
    (a) = svadd_u32_x( pg4, (a), (b) );  \
    (a) = svadd_u32_x( pg4, (a), (x) );  \
    (d) = svxar_n_u32( (d), (a), 16 );   \
    (c) = svadd_u32_x( pg4, (c), (d) );  \
    (b) = svxar_n_u32( (b), (c), 12 );   \
    (a) = svadd_u32_x( pg4, (a), (b) );  \
    (a) = svadd_u32_x( pg4, (a), (y) );  \
    (d) = svxar_n_u32( (d), (a),  8 );   \
    (c) = svadd_u32_x( pg4, (c), (d) );  \
    (b) = svxar_n_u32( (b), (c),  7 );   \
  } while(0)

#define M( idx ) svld1_u32( pg4, words[ FD_BLAKE3_MSG_SCHEDULE[ round ][ (idx) ] ] )

#define ROUND() do {                     \
    G( v0, v4, v8,  v12, M( 0), M( 1) ); \
    G( v1, v5, v9,  v13, M( 2), M( 3) ); \
    G( v2, v6, v10, v14, M( 4), M( 5) ); \
    G( v3, v7, v11, v15, M( 6), M( 7) ); \
    G( v0, v5, v10, v15, M( 8), M( 9) ); \
    G( v1, v6, v11, v12, M(10), M(11) ); \
    G( v2, v7, v8,  v13, M(12), M(13) ); \
    G( v3, v4, v9,  v14, M(14), M(15) ); \
  } while(0)

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
    uchar blocks[4][FD_BLAKE3_BLOCK_SZ] __attribute__((aligned(64))) = {{0}};
    uint  words [16][4]                 __attribute__((aligned(64))) = {{0}};
    uint  active_lane[4]                __attribute__((aligned(16))) = {0U};
    uint  block_len_lane[4]             __attribute__((aligned(16))) = {0U};
    uint  block_flag_lane[4]            __attribute__((aligned(16))) = {0U};

    for( ulong lane=0UL; lane<batch_cnt; lane++ ) {
      if( block_idx>=block_cnt[lane] ) continue;

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
      fd_memcpy( blocks[lane], (uchar const *)batch_data[lane]+off, block_len );
    }

    for( ulong word=0UL; word<16UL; word++ ) {
      for( ulong lane=0UL; lane<4UL; lane++ ) words[word][lane] = FD_LOAD( uint, blocks[lane]+word*sizeof(uint) );
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

    for( ulong round=0UL; round<7UL; round++ ) ROUND();

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

  uint result[16][4] __attribute__((aligned(64)));
  svst1_u32( pg4, result[ 0], h0  );
  svst1_u32( pg4, result[ 1], h1  );
  svst1_u32( pg4, result[ 2], h2  );
  svst1_u32( pg4, result[ 3], h3  );
  svst1_u32( pg4, result[ 4], h4  );
  svst1_u32( pg4, result[ 5], h5  );
  svst1_u32( pg4, result[ 6], h6  );
  svst1_u32( pg4, result[ 7], h7  );
  if( FD_UNLIKELY( out_sz==64U ) ) {
    svst1_u32( pg4, result[ 8], hu0 );
    svst1_u32( pg4, result[ 9], hu1 );
    svst1_u32( pg4, result[10], hu2 );
    svst1_u32( pg4, result[11], hu3 );
    svst1_u32( pg4, result[12], hu4 );
    svst1_u32( pg4, result[13], hu5 );
    svst1_u32( pg4, result[14], hu6 );
    svst1_u32( pg4, result[15], hu7 );
  }

  for( ulong lane=0UL; lane<batch_cnt; lane++ ) {
    uchar * out = (uchar *)batch_hash[lane];
    for( ulong word=0UL; word<(ulong)(out_sz>>2); word++ ) FD_STORE( uint, out+4UL*word, result[word][lane] );
  }
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

#undef ROUND
#undef M
#undef G
