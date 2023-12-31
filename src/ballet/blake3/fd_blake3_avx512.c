
// Source originally from https://github.com/BLAKE3-team/BLAKE3
// From commit: c0ea395cf91d242f078c23d5f8d87eb9dd5f7b78

#include "fd_blake3_private.h"
#include "../../util/simd/fd_avx512.h"

static inline __attribute__((always_inline)) void
round_fn16( wwu_t v[16],
            wwu_t m[16],
            ulong r ) {
  v[0x0] = wwu_add(v[0x0], m[(size_t)FD_BLAKE3_MSG_SCHEDULE[r][0]]);
  v[0x1] = wwu_add(v[0x1], m[(size_t)FD_BLAKE3_MSG_SCHEDULE[r][2]]);
  v[0x2] = wwu_add(v[0x2], m[(size_t)FD_BLAKE3_MSG_SCHEDULE[r][4]]);
  v[0x3] = wwu_add(v[0x3], m[(size_t)FD_BLAKE3_MSG_SCHEDULE[r][6]]);
  v[0x0] = wwu_add(v[0x0], v[0x4]);
  v[0x1] = wwu_add(v[0x1], v[0x5]);
  v[0x2] = wwu_add(v[0x2], v[0x6]);
  v[0x3] = wwu_add(v[0x3], v[0x7]);
  v[0xc] = wwu_xor(v[0xc], v[0x0]);
  v[0xd] = wwu_xor(v[0xd], v[0x1]);
  v[0xe] = wwu_xor(v[0xe], v[0x2]);
  v[0xf] = wwu_xor(v[0xf], v[0x3]);
  v[0xc] = wwu_ror(v[0xc], 16);
  v[0xd] = wwu_ror(v[0xd], 16);
  v[0xe] = wwu_ror(v[0xe], 16);
  v[0xf] = wwu_ror(v[0xf], 16);
  v[0x8] = wwu_add(v[0x8], v[0xc]);
  v[0x9] = wwu_add(v[0x9], v[0xd]);
  v[0xa] = wwu_add(v[0xa], v[0xe]);
  v[0xb] = wwu_add(v[0xb], v[0xf]);
  v[0x4] = wwu_xor(v[0x4], v[0x8]);
  v[0x5] = wwu_xor(v[0x5], v[0x9]);
  v[0x6] = wwu_xor(v[0x6], v[0xa]);
  v[0x7] = wwu_xor(v[0x7], v[0xb]);
  v[0x4] = wwu_ror(v[0x4], 12);
  v[0x5] = wwu_ror(v[0x5], 12);
  v[0x6] = wwu_ror(v[0x6], 12);
  v[0x7] = wwu_ror(v[0x7], 12);
  v[0x0] = wwu_add(v[0x0], m[(size_t)FD_BLAKE3_MSG_SCHEDULE[r][1]]);
  v[0x1] = wwu_add(v[0x1], m[(size_t)FD_BLAKE3_MSG_SCHEDULE[r][3]]);
  v[0x2] = wwu_add(v[0x2], m[(size_t)FD_BLAKE3_MSG_SCHEDULE[r][5]]);
  v[0x3] = wwu_add(v[0x3], m[(size_t)FD_BLAKE3_MSG_SCHEDULE[r][7]]);
  v[0x0] = wwu_add(v[0x0], v[0x4]);
  v[0x1] = wwu_add(v[0x1], v[0x5]);
  v[0x2] = wwu_add(v[0x2], v[0x6]);
  v[0x3] = wwu_add(v[0x3], v[0x7]);
  v[0xc] = wwu_xor(v[0xc], v[0x0]);
  v[0xd] = wwu_xor(v[0xd], v[0x1]);
  v[0xe] = wwu_xor(v[0xe], v[0x2]);
  v[0xf] = wwu_xor(v[0xf], v[0x3]);
  v[0xc] = wwu_ror(v[0xc], 8);
  v[0xd] = wwu_ror(v[0xd], 8);
  v[0xe] = wwu_ror(v[0xe], 8);
  v[0xf] = wwu_ror(v[0xf], 8);
  v[0x8] = wwu_add(v[0x8], v[0xc]);
  v[0x9] = wwu_add(v[0x9], v[0xd]);
  v[0xa] = wwu_add(v[0xa], v[0xe]);
  v[0xb] = wwu_add(v[0xb], v[0xf]);
  v[0x4] = wwu_xor(v[0x4], v[0x8]);
  v[0x5] = wwu_xor(v[0x5], v[0x9]);
  v[0x6] = wwu_xor(v[0x6], v[0xa]);
  v[0x7] = wwu_xor(v[0x7], v[0xb]);
  v[0x4] = wwu_ror(v[0x4], 7);
  v[0x5] = wwu_ror(v[0x5], 7);
  v[0x6] = wwu_ror(v[0x6], 7);
  v[0x7] = wwu_ror(v[0x7], 7);

  v[0x0] = wwu_add(v[0x0], m[(size_t)FD_BLAKE3_MSG_SCHEDULE[r][8]]);
  v[0x1] = wwu_add(v[0x1], m[(size_t)FD_BLAKE3_MSG_SCHEDULE[r][10]]);
  v[0x2] = wwu_add(v[0x2], m[(size_t)FD_BLAKE3_MSG_SCHEDULE[r][12]]);
  v[0x3] = wwu_add(v[0x3], m[(size_t)FD_BLAKE3_MSG_SCHEDULE[r][14]]);
  v[0x0] = wwu_add(v[0x0], v[0x5]);
  v[0x1] = wwu_add(v[0x1], v[0x6]);
  v[0x2] = wwu_add(v[0x2], v[0x7]);
  v[0x3] = wwu_add(v[0x3], v[0x4]);
  v[0xf] = wwu_xor(v[0xf], v[0x0]);
  v[0xc] = wwu_xor(v[0xc], v[0x1]);
  v[0xd] = wwu_xor(v[0xd], v[0x2]);
  v[0xe] = wwu_xor(v[0xe], v[0x3]);
  v[0xf] = wwu_ror(v[0xf], 16);
  v[0xc] = wwu_ror(v[0xc], 16);
  v[0xd] = wwu_ror(v[0xd], 16);
  v[0xe] = wwu_ror(v[0xe], 16);
  v[0xa] = wwu_add(v[0xa], v[0xf]);
  v[0xb] = wwu_add(v[0xb], v[0xc]);
  v[0x8] = wwu_add(v[0x8], v[0xd]);
  v[0x9] = wwu_add(v[0x9], v[0xe]);
  v[0x5] = wwu_xor(v[0x5], v[0xa]);
  v[0x6] = wwu_xor(v[0x6], v[0xb]);
  v[0x7] = wwu_xor(v[0x7], v[0x8]);
  v[0x4] = wwu_xor(v[0x4], v[0x9]);
  v[0x5] = wwu_ror(v[0x5], 12);
  v[0x6] = wwu_ror(v[0x6], 12);
  v[0x7] = wwu_ror(v[0x7], 12);
  v[0x4] = wwu_ror(v[0x4], 12);
  v[0x0] = wwu_add(v[0x0], m[(size_t)FD_BLAKE3_MSG_SCHEDULE[r][9]]);
  v[0x1] = wwu_add(v[0x1], m[(size_t)FD_BLAKE3_MSG_SCHEDULE[r][11]]);
  v[0x2] = wwu_add(v[0x2], m[(size_t)FD_BLAKE3_MSG_SCHEDULE[r][13]]);
  v[0x3] = wwu_add(v[0x3], m[(size_t)FD_BLAKE3_MSG_SCHEDULE[r][15]]);
  v[0x0] = wwu_add(v[0x0], v[0x5]);
  v[0x1] = wwu_add(v[0x1], v[0x6]);
  v[0x2] = wwu_add(v[0x2], v[0x7]);
  v[0x3] = wwu_add(v[0x3], v[0x4]);
  v[0xf] = wwu_xor(v[0xf], v[0x0]);
  v[0xc] = wwu_xor(v[0xc], v[0x1]);
  v[0xd] = wwu_xor(v[0xd], v[0x2]);
  v[0xe] = wwu_xor(v[0xe], v[0x3]);
  v[0xf] = wwu_ror(v[0xf], 8);
  v[0xc] = wwu_ror(v[0xc], 8);
  v[0xd] = wwu_ror(v[0xd], 8);
  v[0xe] = wwu_ror(v[0xe], 8);
  v[0xa] = wwu_add(v[0xa], v[0xf]);
  v[0xb] = wwu_add(v[0xb], v[0xc]);
  v[0x8] = wwu_add(v[0x8], v[0xd]);
  v[0x9] = wwu_add(v[0x9], v[0xe]);
  v[0x5] = wwu_xor(v[0x5], v[0xa]);
  v[0x6] = wwu_xor(v[0x6], v[0xb]);
  v[0x7] = wwu_xor(v[0x7], v[0x8]);
  v[0x4] = wwu_xor(v[0x4], v[0x9]);
  v[0x5] = wwu_ror(v[0x5], 7);
  v[0x6] = wwu_ror(v[0x6], 7);
  v[0x7] = wwu_ror(v[0x7], 7);
  v[0x4] = wwu_ror(v[0x4], 7);
}

// 0b10001000, or lanes a0/a2/b0/b2 in little-endian order
#define LO_IMM8 0x88

static inline wwu_t
unpack_lo_128( wwu_t a, wwu_t b ) {
  return _mm512_shuffle_i32x4(a, b, LO_IMM8);
}

// 0b11011101, or lanes a1/a3/b1/b3 in little-endian order
#define HI_IMM8 0xdd

static inline wwu_t
unpack_hi_128( wwu_t a, wwu_t b ) {
  return _mm512_shuffle_i32x4(a, b, HI_IMM8);
}

void
fd_blake3_hash16( ulong           batch_cnt,
                  void const *    _batch_data,
                  uint const      batch_sz   [ static 16 ],
                  void * const    _batch_hash[ static 16 ],
                  ulong const     ctr_vec    [ static 16 ],
                  uint const      batch_flags[ static 16 ] ) {

  /* We can only process input blocks of 64 bytes, but message data size
     is not necessarily a multiple of 64.  We compute the tail block of
     each message here.  We then process complete blocks of the original
     message in place, switching to processing to these  tail blocks in
     the same pass toward the end. */

  ulong const * batch_data = (ulong const *)_batch_data;

  ulong batch_tail_data[ 16 ] __attribute__((aligned(32)));
  ulong batch_tail_rem [ 16 ] __attribute__((aligned(32)));

  uchar scratch[ 16*FD_BLAKE3_BLOCK_SZ ] __attribute__((aligned(128)));
  do {
    ulong scratch_free = (ulong)scratch;

    wwv_t zero = wwv_zero();

    for( ulong batch_idx=0UL; batch_idx<batch_cnt; batch_idx++ ) {

      /* Allocate the tail blocks for this message */

      ulong data = batch_data[ batch_idx ];
      ulong sz   = batch_sz  [ batch_idx ];

      ulong tail_data     = scratch_free;
      ulong tail_data_sz  = sz & (FD_BLAKE3_BLOCK_SZ-1UL);
      ulong tail_data_off = fd_ulong_align_dn( sz, FD_BLAKE3_BLOCK_SZ );

      batch_tail_data[ batch_idx ] = tail_data;
      batch_tail_rem [ batch_idx ] = (!!tail_data_sz) ^ (!sz);  /* (hash 1 tail block if 0 sz) */

      scratch_free += FD_BLAKE3_BLOCK_SZ;

      /* Populate the tail blocks.  We first clear the blocks.  Then we
         copy any straggler data bytes into the tail. */

      wwv_st( (ulong *) tail_data, zero );

#     if 1
      /* See fd_sha256_private_batch_avx */
      ulong src = (ulong)data + tail_data_off;
      ulong dst = tail_data;
      ulong rem = tail_data_sz;
      while( rem>=32UL ) { wv_st( (ulong *)dst, wv_ldu( (ulong const *)src ) ); dst += 32UL; src += 32UL; rem -= 32UL; }
      while( rem>= 8UL ) { *(ulong  *)dst = FD_LOAD( ulong,  src );             dst +=  8UL; src +=  8UL; rem -=  8UL; }
      if   ( rem>= 4UL ) { *(uint   *)dst = FD_LOAD( uint,   src );             dst +=  4UL; src +=  4UL; rem -=  4UL; }
      if   ( rem>= 2UL ) { *(ushort *)dst = FD_LOAD( ushort, src );             dst +=  2UL; src +=  2UL; rem -=  2UL; }
      if   ( rem       ) { *(uchar  *)dst = FD_LOAD( uchar,  src );             dst++;                                 }
#     else
      fd_memcpy( (void *)tail_data, (void const *)(data + tail_data_off), tail_data_sz );
#     endif
    }
  } while(0);


  wwu_t const iv0 = wwu_bcast( FD_BLAKE3_IV[0] );
  wwu_t const iv1 = wwu_bcast( FD_BLAKE3_IV[1] );
  wwu_t const iv2 = wwu_bcast( FD_BLAKE3_IV[2] );
  wwu_t const iv3 = wwu_bcast( FD_BLAKE3_IV[3] );
  wwu_t const iv4 = wwu_bcast( FD_BLAKE3_IV[4] );
  wwu_t const iv5 = wwu_bcast( FD_BLAKE3_IV[5] );
  wwu_t const iv6 = wwu_bcast( FD_BLAKE3_IV[6] );
  wwu_t const iv7 = wwu_bcast( FD_BLAKE3_IV[7] );

  wwu_t h0=iv0; wwu_t h1=iv1; wwu_t h2=iv2; wwu_t h3=iv3;
  wwu_t h4=iv4; wwu_t h5=iv5; wwu_t h6=iv6; wwu_t h7=iv7;

  wwu_t ctr_lo = wwu( ctr_vec[ 0],     ctr_vec[ 1],     ctr_vec[ 2],     ctr_vec[ 3],
                      ctr_vec[ 4],     ctr_vec[ 5],     ctr_vec[ 6],     ctr_vec[ 7],
                      ctr_vec[ 8],     ctr_vec[ 9],     ctr_vec[10],     ctr_vec[11],
                      ctr_vec[12],     ctr_vec[13],     ctr_vec[14],     ctr_vec[15] );
  wwu_t ctr_hi = wwu( ctr_vec[ 0]>>32, ctr_vec[ 1]>>32, ctr_vec[ 2]>>32, ctr_vec[ 3]>>32,
                      ctr_vec[ 4]>>32, ctr_vec[ 5]>>32, ctr_vec[ 6]>>32, ctr_vec[ 7]>>32,
                      ctr_vec[ 8]>>32, ctr_vec[ 9]>>32, ctr_vec[10]>>32, ctr_vec[11]>>32,
                      ctr_vec[12]>>32, ctr_vec[13]>>32, ctr_vec[14]>>32, ctr_vec[15]>>32 );
  wwu_t flags = wwu_ldu( batch_flags );
  wwu_t off   = wwu_zero();
  wwu_t sz    = wwu_ldu( batch_sz    );


  wwv_t zero         = wwv_zero();
  wwv_t one          = wwv_one();
  wwv_t wwv_64       = wwv_bcast( FD_BLAKE3_BLOCK_SZ );
  wwv_t W_sentinel   = wwv_bcast( (ulong)scratch );
  //wwc_t batch_lane   = wc_unpack( (1<<batch_cnt)-1 );

  wwv_t tail_lo      = wwv_ld( batch_tail_data   );
  wwv_t tail_hi      = wwv_ld( batch_tail_data+4 );

  wwv_t tail_rem_lo  = wwv_ld( batch_tail_rem    );
  wwv_t tail_rem_hi  = wwv_ld( batch_tail_rem+4  );

  wwv_t W_lo         = wwv_ld( batch_data        );
  wwv_t W_hi         = wwv_ld( batch_data+8      );

  wwv_t batch_sz_lo  = _mm512_cvtepi32_epi64( _mm512_extracti32x8_epi32( sz, 0 ) );
  wwv_t batch_sz_hi  = _mm512_cvtepi32_epi64( _mm512_extracti32x8_epi32( sz, 1 ) );

  wwv_t block_rem_lo = wwv_if( ((1<<batch_cnt)-1) & 0xff,
                               wwv_add( wwv_shr( batch_sz_lo, FD_BLAKE3_BLOCK_LG_SZ ), tail_rem_lo ), zero );
  wwv_t block_rem_hi = wwv_if( ((1<<batch_cnt)-1) >> 8,
                               wwv_add( wwv_shr( batch_sz_hi, FD_BLAKE3_BLOCK_LG_SZ ), tail_rem_hi ), zero );

  for(;;) {
    int active_lane_lo = wwv_ne( block_rem_lo, zero );
    int active_lane_hi = wwv_ne( block_rem_hi, zero );
    if( FD_UNLIKELY( !(active_lane_lo | active_lane_hi) ) ) break;

    /* Switch lanes that have hit the end of their in-place bulk
       processing to their out-of-place scratch tail regions as
       necessary. */

    W_lo = wwv_if( wwv_eq( block_rem_lo, tail_rem_lo ), tail_lo, W_lo );
    W_hi = wwv_if( wwv_eq( block_rem_hi, tail_rem_hi ), tail_hi, W_hi );

    /* Derive per-block flags and block sizes */

    int block_first = wwu_eq( off, zero );
    int block_last  = wwi_lt( sz,  wwu_add( off, wwu_bcast( FD_BLAKE3_BLOCK_SZ+1 ) ) );

    /* Suppress root flag unless last block */

    wwu_t block_flags = wwu_andnot_if( block_last, zero, wwu_bcast( FD_BLAKE3_FLAG_ROOT ), flags );

    /* Suppress CHUNK_{START,END} flags unless leaf node */

    int is_parent = wwi_lt( wwu_shl( flags, 5 ), zero );  /* shift FLAG_PARENT into sign bit */
    block_flags = wwu_or_if( ((~is_parent)&block_first),              block_flags,
                             wwu_bcast( FD_BLAKE3_FLAG_CHUNK_START ), block_flags );
    block_flags = wwu_or_if( ((~is_parent)&block_last),               block_flags,
                             wwu_bcast( FD_BLAKE3_FLAG_CHUNK_END   ), block_flags );

    /* At this point, we have at least 1 block in this message segment
       pass that has not been processed.  Load the next 64 bytes of
       each unprocessed block.  Inactive lanes (e.g. message segments
       in this pass for which we've already processed all the blocks)
       will load garbage from a sentinel location (and the result of
       the state computations for the inactive lane will be ignored). */

    ulong _W0; ulong _W1; ulong _W2; ulong _W3; ulong _W4; ulong _W5; ulong _W6; ulong _W7;
    ulong _W8; ulong _W9; ulong _Wa; ulong _Wb; ulong _Wc; ulong _Wd; ulong _We; ulong _Wf;
    wwv_unpack( wwv_if( active_lane_lo, W_lo, W_sentinel ), _W0, _W1, _W2, _W3, _W4, _W5, _W6, _W7 );
    wwv_unpack( wwv_if( active_lane_hi, W_hi, W_sentinel ), _W8, _W9, _Wa, _Wb, _Wc, _Wd, _We, _Wf );
    uchar const * W0 = (uchar const *)_W0; uchar const * W1 = (uchar const *)_W1;
    uchar const * W2 = (uchar const *)_W2; uchar const * W3 = (uchar const *)_W3;
    uchar const * W4 = (uchar const *)_W4; uchar const * W5 = (uchar const *)_W5;
    uchar const * W6 = (uchar const *)_W6; uchar const * W7 = (uchar const *)_W7;
    uchar const * W8 = (uchar const *)_W8; uchar const * W9 = (uchar const *)_W9;
    uchar const * Wa = (uchar const *)_Wa; uchar const * Wb = (uchar const *)_Wb;
    uchar const * Wc = (uchar const *)_Wc; uchar const * Wd = (uchar const *)_Wd;
    uchar const * We = (uchar const *)_We; uchar const * Wf = (uchar const *)_Wf;

    wwu_t m[16];
    m[0x0] = wwu_ldu( W0 );  m[0x1] = wwu_ldu( W1 );
    m[0x2] = wwu_ldu( W2 );  m[0x3] = wwu_ldu( W3 );
    m[0x4] = wwu_ldu( W4 );  m[0x5] = wwu_ldu( W5 );
    m[0x6] = wwu_ldu( W6 );  m[0x7] = wwu_ldu( W7 );
    m[0x8] = wwu_ldu( W8 );  m[0x9] = wwu_ldu( W9 );
    m[0xa] = wwu_ldu( Wa );  m[0xb] = wwu_ldu( Wb );
    m[0xc] = wwu_ldu( Wc );  m[0xd] = wwu_ldu( Wd );
    m[0xe] = wwu_ldu( We );  m[0xf] = wwu_ldu( Wf );

    wwu_transpose_16x16( m[0x0], m[0x1], m[0x2], m[0x3], m[0x4], m[0x5], m[0x6], m[0x7], m[0x8], m[0x9], m[0xa], m[0xb], m[0xc], m[0xd], m[0xe], m[0xf],
                         m[0x0], m[0x1], m[0x2], m[0x3], m[0x4], m[0x5], m[0x6], m[0x7], m[0x8], m[0x9], m[0xa], m[0xb], m[0xc], m[0xd], m[0xe], m[0xf] );

    /* Compute the BLAKE3 compression function updates */

    wwu_t v[16] = {
        h0,     h1,     h2,     h3,
        h4,     h5,     h6,     h7,
        iv0,    iv1,    iv2,    iv3,
        ctr_lo, ctr_hi, sz,     block_flags,
    };

    round_fn16( v, m, 0 );
    round_fn16( v, m, 1 );
    round_fn16( v, m, 2 );
    round_fn16( v, m, 3 );
    round_fn16( v, m, 4 );
    round_fn16( v, m, 5 );
    round_fn16( v, m, 6 );

    /* Apply the state updates to the active lanes */

    int active_lane = active_lane_lo | (active_lane_hi<<8);

    h0 = wwu_xor_if( active_lane, v[ 0], v[ 8], h0 );
    h1 = wwu_xor_if( active_lane, v[ 1], v[ 9], h1 );
    h2 = wwu_xor_if( active_lane, v[ 2], v[10], h2 );
    h3 = wwu_xor_if( active_lane, v[ 3], v[11], h3 );
    h4 = wwu_xor_if( active_lane, v[ 4], v[12], h4 );
    h5 = wwu_xor_if( active_lane, v[ 5], v[13], h5 );
    h6 = wwu_xor_if( active_lane, v[ 6], v[14], h6 );
    h7 = wwu_xor_if( active_lane, v[ 7], v[15], h7 );

    /* Advance to the next message segment blocks.  In pseudo code,
       the below is:

         W += 64; if( block_rem ) block_rem--;

       Since we do not load anything at W(lane) above unless
       block_rem(lane) is non-zero, we can omit vector conditional
       operations for W(lane) below. */

    W_lo = wwv_add( W_lo, wwv_64 );
    W_hi = wwv_add( W_hi, wwv_64 );

    block_rem_lo = wwv_sub_if( active_lane_lo, block_rem_lo, one, block_rem_lo );
    block_rem_hi = wwv_sub_if( active_lane_hi, block_rem_hi, one, block_rem_hi );
  }

  /* Store the results */

  wwu_t o0; wwu_t o1; wwu_t o2; wwu_t o3; wwu_t o4; wwu_t o5; wwu_t o6; wwu_t o7;
  wwu_t o8; wwu_t o9; wwu_t oA; wwu_t oB; wwu_t oC; wwu_t oD; wwu_t oE; wwu_t oF;

  wwu_transpose_16x16( h0,   h1,   h2,   h3,   h4,   h5,   h6,   h7,
                       zero, zero, zero, zero, zero, zero, zero, zero,
                       o0,   o1,   o2,   o3,   o4,   o5,   o6,   o7,
                       o8,   o9,   oA,   oB,   oC,   oD,   oE,   oF );

  uint * const * batch_hash = (uint * const *)_batch_hash;
  switch( batch_cnt ) { /* application dependent prob */
  case 16UL: wu_stu( batch_hash[15], _mm512_castsi512_si256( oF ) ); __attribute__((fallthrough));
  case 15UL: wu_stu( batch_hash[14], _mm512_castsi512_si256( oE ) ); __attribute__((fallthrough));
  case 14UL: wu_stu( batch_hash[13], _mm512_castsi512_si256( oD ) ); __attribute__((fallthrough));
  case 13UL: wu_stu( batch_hash[12], _mm512_castsi512_si256( oC ) ); __attribute__((fallthrough));
  case 12UL: wu_stu( batch_hash[11], _mm512_castsi512_si256( oB ) ); __attribute__((fallthrough));
  case 11UL: wu_stu( batch_hash[10], _mm512_castsi512_si256( oA ) ); __attribute__((fallthrough));
  case 10UL: wu_stu( batch_hash[ 9], _mm512_castsi512_si256( o9 ) ); __attribute__((fallthrough));
  case  9UL: wu_stu( batch_hash[ 8], _mm512_castsi512_si256( o8 ) ); __attribute__((fallthrough));
  case  8UL: wu_stu( batch_hash[ 7], _mm512_castsi512_si256( o7 ) ); __attribute__((fallthrough));
  case  7UL: wu_stu( batch_hash[ 6], _mm512_castsi512_si256( o6 ) ); __attribute__((fallthrough));
  case  6UL: wu_stu( batch_hash[ 5], _mm512_castsi512_si256( o5 ) ); __attribute__((fallthrough));
  case  5UL: wu_stu( batch_hash[ 4], _mm512_castsi512_si256( o4 ) ); __attribute__((fallthrough));
  case  4UL: wu_stu( batch_hash[ 3], _mm512_castsi512_si256( o3 ) ); __attribute__((fallthrough));
  case  3UL: wu_stu( batch_hash[ 2], _mm512_castsi512_si256( o2 ) ); __attribute__((fallthrough));
  case  2UL: wu_stu( batch_hash[ 1], _mm512_castsi512_si256( o1 ) ); __attribute__((fallthrough));
  case  1UL: wu_stu( batch_hash[ 0], _mm512_castsi512_si256( o0 ) ); __attribute__((fallthrough));
  default: break;
  }
}

void
fd_blake3_avx512_compress16_fast( uchar const * restrict msg,
                                  uchar       * restrict out,
                                  ulong                  counter,
                                  uchar                  flags ) {

  int   parent = flags & FD_BLAKE3_FLAG_PARENT;
  int   lg_sz  = fd_int_if( parent, FD_BLAKE3_OUTCHAIN_LG_SZ+1, FD_BLAKE3_CHUNK_LG_SZ );
  ulong sz     = 1UL<<lg_sz;

  /* counters stay the same for each block.  Across chunks, they
     increment if we are hashing leaves.  Otherwise, they are zero. */

  wwu_t ctr_add   = wwu_and( wwu_bcast( parent ? 0 : UINT_MAX ),
                             wwu( 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
                                  0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf ) );
  wwu_t ctr_lo    = wwu_add( wwu_bcast( counter ), ctr_add );
  int   ctr_carry = wwi_gt ( wwu_xor( ctr_add, wwu_bcast( 0x80000000 ) ),
                             wwu_xor( ctr_lo,  wwu_bcast( 0x80000000 ) ) );
  wwu_t ctr_hi    = wwu_add_if( ctr_carry, wwu_bcast( counter>>32 ), wwu_one(), wwu_bcast( counter>>32 ) );
  wwu_t sz_vec    = wwu_bcast( FD_BLAKE3_BLOCK_SZ );

  wwu_t const iv0 = wwu_bcast( FD_BLAKE3_IV[0] );
  wwu_t const iv1 = wwu_bcast( FD_BLAKE3_IV[1] );
  wwu_t const iv2 = wwu_bcast( FD_BLAKE3_IV[2] );
  wwu_t const iv3 = wwu_bcast( FD_BLAKE3_IV[3] );
  wwu_t const iv4 = wwu_bcast( FD_BLAKE3_IV[4] );
  wwu_t const iv5 = wwu_bcast( FD_BLAKE3_IV[5] );
  wwu_t const iv6 = wwu_bcast( FD_BLAKE3_IV[6] );
  wwu_t const iv7 = wwu_bcast( FD_BLAKE3_IV[7] );

  wwu_t h0=iv0; wwu_t h1=iv1; wwu_t h2=iv2; wwu_t h3=iv3;
  wwu_t h4=iv4; wwu_t h5=iv5; wwu_t h6=iv6; wwu_t h7=iv7;

  ulong off = 0UL;
  do {
    ulong const off_next = off+FD_BLAKE3_BLOCK_SZ;
    int chunk_flags =
        ( off     ==0UL ? FD_BLAKE3_FLAG_CHUNK_START : 0 ) |
        ( off_next==sz  ? FD_BLAKE3_FLAG_CHUNK_END   : 0 );
    int flags_ = flags | fd_int_if( parent, 0, chunk_flags );
    wwu_t flags_vec = wwu_bcast( flags_ );

    wwu_t m[16];
    m[0x0] = wwu_ldu( msg + (0<<lg_sz) + off );
    m[0x1] = wwu_ldu( msg + (0<<lg_sz) + off );
    m[0x2] = wwu_ldu( msg + (0<<lg_sz) + off );
    m[0x3] = wwu_ldu( msg + (0<<lg_sz) + off );
    m[0x4] = wwu_ldu( msg + (0<<lg_sz) + off );
    m[0x5] = wwu_ldu( msg + (0<<lg_sz) + off );
    m[0x6] = wwu_ldu( msg + (0<<lg_sz) + off );
    m[0x7] = wwu_ldu( msg + (0<<lg_sz) + off );
    m[0x8] = wwu_ldu( msg + (0<<lg_sz) + off );
    m[0x9] = wwu_ldu( msg + (0<<lg_sz) + off );
    m[0xa] = wwu_ldu( msg + (0<<lg_sz) + off );
    m[0xb] = wwu_ldu( msg + (0<<lg_sz) + off );
    m[0xc] = wwu_ldu( msg + (0<<lg_sz) + off );
    m[0xd] = wwu_ldu( msg + (0<<lg_sz) + off );
    m[0xe] = wwu_ldu( msg + (0<<lg_sz) + off );
    m[0xf] = wwu_ldu( msg + (0<<lg_sz) + off );

    wwu_transpose_16x16( m[0x0], m[0x1], m[0x2], m[0x3], m[0x4], m[0x5], m[0x6], m[0x7], m[0x8], m[0x9], m[0xa], m[0xb], m[0xc], m[0xd], m[0xe], m[0xf],
                         m[0x0], m[0x1], m[0x2], m[0x3], m[0x4], m[0x5], m[0x6], m[0x7], m[0x8], m[0x9], m[0xa], m[0xb], m[0xc], m[0xd], m[0xe], m[0xf] );

    wwu_t v[16] = {
        h0,     h1,     h2,     h3,
        h4,     h5,     h6,     h7,
        iv0,    iv1,    iv2,    iv3,
        ctr_lo, ctr_hi, sz_vec, flags_vec,
    };

    round_fn16( v, m, 0 );
    round_fn16( v, m, 1 );
    round_fn16( v, m, 2 );
    round_fn16( v, m, 3 );
    round_fn16( v, m, 4 );
    round_fn16( v, m, 5 );
    round_fn16( v, m, 6 );

    h0 = wwu_xor( v[ 0], v[ 8] );
    h1 = wwu_xor( v[ 1], v[ 9] );
    h2 = wwu_xor( v[ 2], v[10] );
    h3 = wwu_xor( v[ 3], v[11] );
    h4 = wwu_xor( v[ 4], v[12] );
    h5 = wwu_xor( v[ 5], v[13] );
    h6 = wwu_xor( v[ 6], v[14] );
    h7 = wwu_xor( v[ 7], v[15] );

    off = off_next;
  } while( off!=sz );

  wwu_t o0; wwu_t o1; wwu_t o2; wwu_t o3; wwu_t o4; wwu_t o5; wwu_t o6; wwu_t o7;
  wwu_t o8; wwu_t o9; wwu_t oA; wwu_t oB; wwu_t oC; wwu_t oD; wwu_t oE; wwu_t oF;

  wwu_t zero = wwu_zero();
  wwu_transpose_16x16( h0,   h1,   h2,   h3,   h4,   h5,   h6,   h7,
                       zero, zero, zero, zero, zero, zero, zero, zero,
                       o0,   o1,   o2,   o3,   o4,   o5,   o6,   o7,
                       o8,   o9,   oA,   oB,   oC,   oD,   oE,   oF );

  wb_st( out + (0x0UL<<FD_BLAKE3_OUTCHAIN_LG_SZ), _mm512_castsi512_si256( o0 ) );
  wb_st( out + (0x1UL<<FD_BLAKE3_OUTCHAIN_LG_SZ), _mm512_castsi512_si256( o1 ) );
  wb_st( out + (0x2UL<<FD_BLAKE3_OUTCHAIN_LG_SZ), _mm512_castsi512_si256( o2 ) );
  wb_st( out + (0x3UL<<FD_BLAKE3_OUTCHAIN_LG_SZ), _mm512_castsi512_si256( o3 ) );
  wb_st( out + (0x4UL<<FD_BLAKE3_OUTCHAIN_LG_SZ), _mm512_castsi512_si256( o4 ) );
  wb_st( out + (0x5UL<<FD_BLAKE3_OUTCHAIN_LG_SZ), _mm512_castsi512_si256( o5 ) );
  wb_st( out + (0x6UL<<FD_BLAKE3_OUTCHAIN_LG_SZ), _mm512_castsi512_si256( o6 ) );
  wb_st( out + (0x7UL<<FD_BLAKE3_OUTCHAIN_LG_SZ), _mm512_castsi512_si256( o7 ) );
  wb_st( out + (0x8UL<<FD_BLAKE3_OUTCHAIN_LG_SZ), _mm512_castsi512_si256( o8 ) );
  wb_st( out + (0x9UL<<FD_BLAKE3_OUTCHAIN_LG_SZ), _mm512_castsi512_si256( o9 ) );
  wb_st( out + (0xaUL<<FD_BLAKE3_OUTCHAIN_LG_SZ), _mm512_castsi512_si256( oA ) );
  wb_st( out + (0xbUL<<FD_BLAKE3_OUTCHAIN_LG_SZ), _mm512_castsi512_si256( oB ) );
  wb_st( out + (0xcUL<<FD_BLAKE3_OUTCHAIN_LG_SZ), _mm512_castsi512_si256( oC ) );
  wb_st( out + (0xdUL<<FD_BLAKE3_OUTCHAIN_LG_SZ), _mm512_castsi512_si256( oD ) );
  wb_st( out + (0xeUL<<FD_BLAKE3_OUTCHAIN_LG_SZ), _mm512_castsi512_si256( oE ) );
  wb_st( out + (0xfUL<<FD_BLAKE3_OUTCHAIN_LG_SZ), _mm512_castsi512_si256( oF ) );
}
