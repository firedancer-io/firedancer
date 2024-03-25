
// Source originally from https://github.com/BLAKE3-team/BLAKE3
// From commit: 64747d48ffe9d1fbf4b71e94cabeb8a211461081

#include "fd_blake3.h"
#include "fd_blake3_private.h"
#include "../../util/simd/fd_avx.h"
#include <assert.h>

#define wu_rot16 wb_exch_adj_pair

static inline __attribute__((always_inline)) wu_t
wu_rot12( wu_t x ) {
  return wu_or( wu_shr( x, 12 ), wu_shl( x, 32-12 ) );
}

static inline __attribute__((always_inline)) wu_t
wu_rot8( wu_t x ) {
  wb_t const mask =
    wb( 1,2,3,0,  5,6,7,4,  9,10,11,8,  13,14,15,12,
        1,2,3,0,  5,6,7,4,  9,10,11,8,  13,14,15,12 );
  return _mm256_shuffle_epi8( x, mask );
}

static inline __attribute__((always_inline)) wu_t
wu_rot7( wu_t x ) {
  return wu_or( wu_shr( x, 7 ), wu_shl( x, 32-7 ) );
}

static inline __attribute__((always_inline)) void
round_fn8( wu_t  v[16],
           wu_t  m[16],
           ulong r ) {
  v[ 0] = wu_add(v[0], m[(ulong)FD_BLAKE3_MSG_SCHEDULE[r][0]]);
  v[ 1] = wu_add(v[1], m[(ulong)FD_BLAKE3_MSG_SCHEDULE[r][2]]);
  v[ 2] = wu_add(v[2], m[(ulong)FD_BLAKE3_MSG_SCHEDULE[r][4]]);
  v[ 3] = wu_add(v[3], m[(ulong)FD_BLAKE3_MSG_SCHEDULE[r][6]]);
  v[ 0] = wu_add(v[0], v[4]);
  v[ 1] = wu_add(v[1], v[5]);
  v[ 2] = wu_add(v[2], v[6]);
  v[ 3] = wu_add(v[3], v[7]);
  v[12] = wu_xor(v[12], v[0]);
  v[13] = wu_xor(v[13], v[1]);
  v[14] = wu_xor(v[14], v[2]);
  v[15] = wu_xor(v[15], v[3]);
  v[12] = wu_rot16(v[12]);
  v[13] = wu_rot16(v[13]);
  v[14] = wu_rot16(v[14]);
  v[15] = wu_rot16(v[15]);
  v[ 8] = wu_add(v[8], v[12]);
  v[ 9] = wu_add(v[9], v[13]);
  v[10] = wu_add(v[10], v[14]);
  v[11] = wu_add(v[11], v[15]);
  v[ 4] = wu_xor(v[4], v[8]);
  v[ 5] = wu_xor(v[5], v[9]);
  v[ 6] = wu_xor(v[6], v[10]);
  v[ 7] = wu_xor(v[7], v[11]);
  v[ 4] = wu_rot12(v[4]);
  v[ 5] = wu_rot12(v[5]);
  v[ 6] = wu_rot12(v[6]);
  v[ 7] = wu_rot12(v[7]);
  v[ 0] = wu_add(v[0], m[(ulong)FD_BLAKE3_MSG_SCHEDULE[r][1]]);
  v[ 1] = wu_add(v[1], m[(ulong)FD_BLAKE3_MSG_SCHEDULE[r][3]]);
  v[ 2] = wu_add(v[2], m[(ulong)FD_BLAKE3_MSG_SCHEDULE[r][5]]);
  v[ 3] = wu_add(v[3], m[(ulong)FD_BLAKE3_MSG_SCHEDULE[r][7]]);
  v[ 0] = wu_add(v[0], v[4]);
  v[ 1] = wu_add(v[1], v[5]);
  v[ 2] = wu_add(v[2], v[6]);
  v[ 3] = wu_add(v[3], v[7]);
  v[12] = wu_xor(v[12], v[0]);
  v[13] = wu_xor(v[13], v[1]);
  v[14] = wu_xor(v[14], v[2]);
  v[15] = wu_xor(v[15], v[3]);
  v[12] = wu_rot8(v[12]);
  v[13] = wu_rot8(v[13]);
  v[14] = wu_rot8(v[14]);
  v[15] = wu_rot8(v[15]);
  v[ 8] = wu_add(v[8], v[12]);
  v[ 9] = wu_add(v[9], v[13]);
  v[10] = wu_add(v[10], v[14]);
  v[11] = wu_add(v[11], v[15]);
  v[ 4] = wu_xor(v[4], v[8]);
  v[ 5] = wu_xor(v[5], v[9]);
  v[ 6] = wu_xor(v[6], v[10]);
  v[ 7] = wu_xor(v[7], v[11]);
  v[ 4] = wu_rot7(v[4]);
  v[ 5] = wu_rot7(v[5]);
  v[ 6] = wu_rot7(v[6]);
  v[ 7] = wu_rot7(v[7]);

  v[ 0] = wu_add(v[0], m[(ulong)FD_BLAKE3_MSG_SCHEDULE[r][8]]);
  v[ 1] = wu_add(v[1], m[(ulong)FD_BLAKE3_MSG_SCHEDULE[r][10]]);
  v[ 2] = wu_add(v[2], m[(ulong)FD_BLAKE3_MSG_SCHEDULE[r][12]]);
  v[ 3] = wu_add(v[3], m[(ulong)FD_BLAKE3_MSG_SCHEDULE[r][14]]);
  v[ 0] = wu_add(v[0], v[5]);
  v[ 1] = wu_add(v[1], v[6]);
  v[ 2] = wu_add(v[2], v[7]);
  v[ 3] = wu_add(v[3], v[4]);
  v[15] = wu_xor(v[15], v[0]);
  v[12] = wu_xor(v[12], v[1]);
  v[13] = wu_xor(v[13], v[2]);
  v[14] = wu_xor(v[14], v[3]);
  v[15] = wu_rot16(v[15]);
  v[12] = wu_rot16(v[12]);
  v[13] = wu_rot16(v[13]);
  v[14] = wu_rot16(v[14]);
  v[10] = wu_add(v[10], v[15]);
  v[11] = wu_add(v[11], v[12]);
  v[ 8] = wu_add(v[8], v[13]);
  v[ 9] = wu_add(v[9], v[14]);
  v[ 5] = wu_xor(v[5], v[10]);
  v[ 6] = wu_xor(v[6], v[11]);
  v[ 7] = wu_xor(v[7], v[8]);
  v[ 4] = wu_xor(v[4], v[9]);
  v[ 5] = wu_rot12(v[5]);
  v[ 6] = wu_rot12(v[6]);
  v[ 7] = wu_rot12(v[7]);
  v[ 4] = wu_rot12(v[4]);
  v[ 0] = wu_add(v[0], m[(ulong)FD_BLAKE3_MSG_SCHEDULE[r][9]]);
  v[ 1] = wu_add(v[1], m[(ulong)FD_BLAKE3_MSG_SCHEDULE[r][11]]);
  v[ 2] = wu_add(v[2], m[(ulong)FD_BLAKE3_MSG_SCHEDULE[r][13]]);
  v[ 3] = wu_add(v[3], m[(ulong)FD_BLAKE3_MSG_SCHEDULE[r][15]]);
  v[ 0] = wu_add(v[0], v[5]);
  v[ 1] = wu_add(v[1], v[6]);
  v[ 2] = wu_add(v[2], v[7]);
  v[ 3] = wu_add(v[3], v[4]);
  v[15] = wu_xor(v[15], v[0]);
  v[12] = wu_xor(v[12], v[1]);
  v[13] = wu_xor(v[13], v[2]);
  v[14] = wu_xor(v[14], v[3]);
  v[15] = wu_rot8(v[15]);
  v[12] = wu_rot8(v[12]);
  v[13] = wu_rot8(v[13]);
  v[14] = wu_rot8(v[14]);
  v[10] = wu_add(v[10], v[15]);
  v[11] = wu_add(v[11], v[12]);
  v[ 8] = wu_add(v[8], v[13]);
  v[ 9] = wu_add(v[9], v[14]);
  v[ 5] = wu_xor(v[5], v[10]);
  v[ 6] = wu_xor(v[6], v[11]);
  v[ 7] = wu_xor(v[7], v[8]);
  v[ 4] = wu_xor(v[4], v[9]);
  v[ 5] = wu_rot7(v[5]);
  v[ 6] = wu_rot7(v[6]);
  v[ 7] = wu_rot7(v[7]);
  v[ 4] = wu_rot7(v[4]);
}

void
fd_blake3_avx_compress8( ulong                   batch_cnt,
                         void   const * restrict _batch_data,
                         uint   const * restrict  batch_sz,
                         void * const * restrict _batch_hash,
                         ulong  const * restrict  ctr_vec,
                         uint   const * restrict  batch_flags ) {

  ulong const * batch_data = (ulong const *)_batch_data;

  if( FD_UNLIKELY( batch_cnt==1 ) ) {
    fd_blake3_sse_compress1( (uchar *)(_batch_hash[0]),
                             (uchar const *)(batch_data[0]),
                             batch_sz[0],
                             ctr_vec[0],
                             batch_flags[0] );
    return;
  }

  /* We can only process input blocks of 64 bytes, but message data size
     is not necessarily a multiple of 64.  We compute the tail block of
     each message here.  We then process complete blocks of the original
     message in place, switching to processing to these  tail blocks in
     the same pass toward the end. */

  ulong batch_tail_data[ 8 ] __attribute__((aligned(32)));
  ulong batch_tail_rem [ 8 ] __attribute__((aligned(32)));

  uchar scratch[ 8*FD_BLAKE3_BLOCK_SZ ] __attribute__((aligned(128)));
  do {
    ulong scratch_free = (ulong)scratch;

    wv_t zero = wv_zero();

    for( ulong batch_idx=0UL; batch_idx<batch_cnt; batch_idx++ ) {

      /* Allocate the tail blocks for this message */

      ulong data = batch_data[ batch_idx ];
      ulong sz   = batch_sz  [ batch_idx ];

      ulong tail_data     = scratch_free;
      ulong tail_data_sz  = sz & (FD_BLAKE3_BLOCK_SZ-1UL);
      ulong tail_data_off = fd_ulong_align_dn( sz, FD_BLAKE3_BLOCK_SZ );

      batch_tail_data[ batch_idx ] = tail_data;
      batch_tail_rem [ batch_idx ] = (ulong)( (!!tail_data_sz) ^ (!sz) );  /* (hash 1 tail block if 0 sz) */

      scratch_free += FD_BLAKE3_BLOCK_SZ;

      /* Populate the tail blocks.  We first clear the blocks.  Then we
         copy any straggler data bytes into the tail. */

      wv_st( (ulong *) tail_data,     zero );
      wv_st( (ulong *)(tail_data+32), zero );

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


  wu_t const iv0 = wu_bcast( FD_BLAKE3_IV[0] );
  wu_t const iv1 = wu_bcast( FD_BLAKE3_IV[1] );
  wu_t const iv2 = wu_bcast( FD_BLAKE3_IV[2] );
  wu_t const iv3 = wu_bcast( FD_BLAKE3_IV[3] );
  wu_t const iv4 = wu_bcast( FD_BLAKE3_IV[4] );
  wu_t const iv5 = wu_bcast( FD_BLAKE3_IV[5] );
  wu_t const iv6 = wu_bcast( FD_BLAKE3_IV[6] );
  wu_t const iv7 = wu_bcast( FD_BLAKE3_IV[7] );

  wu_t h0=iv0; wu_t h1=iv1; wu_t h2=iv2; wu_t h3=iv3;
  wu_t h4=iv4; wu_t h5=iv5; wu_t h6=iv6; wu_t h7=iv7;

  wu_t ctr_lo = wu( ctr_vec[0],     ctr_vec[1],     ctr_vec[2],     ctr_vec[3],
                    ctr_vec[4],     ctr_vec[5],     ctr_vec[6],     ctr_vec[7] );
  wu_t ctr_hi = wu( ctr_vec[0]>>32, ctr_vec[1]>>32, ctr_vec[2]>>32, ctr_vec[3]>>32,
                    ctr_vec[4]>>32, ctr_vec[5]>>32, ctr_vec[6]>>32, ctr_vec[7]>>32 );
  wu_t flags = wu_ldu( batch_flags );
  wu_t off   = wu_zero();
  wu_t sz    = wu_ldu( batch_sz    );


  wv_t wv_64        = wv_bcast( FD_BLAKE3_BLOCK_SZ );
  wv_t W_sentinel   = wv_bcast( (ulong)scratch );
  wc_t batch_lane   = wc_unpack( (1<<batch_cnt)-1 );

  wv_t tail_lo      = wv_ld( batch_tail_data   );
  wv_t tail_hi      = wv_ld( batch_tail_data+4 );

  wv_t tail_rem_lo  = wv_ld( batch_tail_rem    );
  wv_t tail_rem_hi  = wv_ld( batch_tail_rem+4  );

  wv_t W_lo         = wv_ld( batch_data        );
  wv_t W_hi         = wv_ld( batch_data+4      );

  wv_t batch_sz_lo  = _mm256_cvtepi32_epi64( _mm256_extractf128_si256( sz, 0 ) );
  wv_t batch_sz_hi  = _mm256_cvtepi32_epi64( _mm256_extractf128_si256( sz, 1 ) );

  wv_t block_rem_lo = wv_notczero( wc_expand( batch_lane, 0 ),
                        wv_add( wv_shr( batch_sz_lo, FD_BLAKE3_BLOCK_LG_SZ ), tail_rem_lo ) );
  wv_t block_rem_hi = wv_notczero( wc_expand( batch_lane, 1 ),
                        wv_add( wv_shr( batch_sz_hi, FD_BLAKE3_BLOCK_LG_SZ ), tail_rem_hi ) );

  for(;;) {
    wc_t active_lane_lo = wv_to_wc( block_rem_lo );
    wc_t active_lane_hi = wv_to_wc( block_rem_hi );
    if( FD_UNLIKELY( !wc_any( wc_or( active_lane_lo, active_lane_hi ) ) ) ) break;

    /* Switch lanes that have hit the end of their in-place bulk
       processing to their out-of-place scratch tail regions as
       necessary. */

    W_lo = wv_if( wv_eq( block_rem_lo, tail_rem_lo ), tail_lo, W_lo );
    W_hi = wv_if( wv_eq( block_rem_hi, tail_rem_hi ), tail_hi, W_hi );

    /* Derive per-block flags and block sizes */

    wc_t block_first = wu_eq( off, wu_zero() );
    wc_t block_last  = wi_lt( sz,  wu_add( off, wu_bcast( FD_BLAKE3_BLOCK_SZ+1 ) ) );

    /* Suppress root flag unless last block */

    wu_t root_mask = wu_or( block_last, wu_bcast( ~FD_BLAKE3_FLAG_ROOT ) );
    wu_t block_flags = wu_and( flags, root_mask );

    /* Suppress CHUNK_{START,END} flags unless leaf node */

    wc_t is_parent = wu_shl( flags, 5 );  /* shift FLAG_PARENT into AVX condition bit */
    wu_t chunk_flags = wu_or(
        wu_if( block_first, wu_bcast( FD_BLAKE3_FLAG_CHUNK_START ), wu_zero() ),
        wu_if( block_last,  wu_bcast( FD_BLAKE3_FLAG_CHUNK_END   ), wu_zero() ) );
    wu_t block_sz = wu_min( wu_sub( sz, off ), wu_bcast( FD_BLAKE3_BLOCK_SZ ) );
    block_flags = wu_or( block_flags, wu_if( is_parent, wu_zero(), chunk_flags ) );

    /* At this point, we have at least 1 block in this message segment
       pass that has not been processed.  Load the next 64 bytes of
       each unprocessed block.  Inactive lanes (e.g. message segments
       in this pass for which we've already processed all the blocks)
       will load garbage from a sentinel location (and the result of
       the state computations for the inactive lane will be ignored). */

    wv_t W03 = wv_if( active_lane_lo, W_lo, W_sentinel );
    uchar const * W0 = (uchar const *)wv_extract( W03, 0 );
    uchar const * W1 = (uchar const *)wv_extract( W03, 1 );
    uchar const * W2 = (uchar const *)wv_extract( W03, 2 );
    uchar const * W3 = (uchar const *)wv_extract( W03, 3 );

    wv_t W47 = wv_if( active_lane_hi, W_hi, W_sentinel );
    uchar const * W4 = (uchar const *)wv_extract( W47, 0 );
    uchar const * W5 = (uchar const *)wv_extract( W47, 1 );
    uchar const * W6 = (uchar const *)wv_extract( W47, 2 );
    uchar const * W7 = (uchar const *)wv_extract( W47, 3 );

    wu_t m[16] = { wu_ldu( W0    ), wu_ldu( W1    ), wu_ldu( W2    ), wu_ldu( W3    ),
                   wu_ldu( W4    ), wu_ldu( W5    ), wu_ldu( W6    ), wu_ldu( W7    ),
                   wu_ldu( W0+32 ), wu_ldu( W1+32 ), wu_ldu( W2+32 ), wu_ldu( W3+32 ),
                   wu_ldu( W4+32 ), wu_ldu( W5+32 ), wu_ldu( W6+32 ), wu_ldu( W7+32 ) };

    wu_transpose_8x8( m[0x0], m[0x1], m[0x2], m[0x3], m[0x4], m[0x5], m[0x6], m[0x7],
                      m[0x0], m[0x1], m[0x2], m[0x3], m[0x4], m[0x5], m[0x6], m[0x7] );
    wu_transpose_8x8( m[0x8], m[0x9], m[0xa], m[0xb], m[0xc], m[0xd], m[0xe], m[0xf],
                      m[0x8], m[0x9], m[0xa], m[0xb], m[0xc], m[0xd], m[0xe], m[0xf] );

    /* Compute the BLAKE3 compression function updates */

    wu_t v[16] = {
        h0,     h1,     h2,       h3,
        h4,     h5,     h6,       h7,
        iv0,    iv1,    iv2,      iv3,
        ctr_lo, ctr_hi, block_sz, block_flags,
    };

    round_fn8( v, m, 0 );
    round_fn8( v, m, 1 );
    round_fn8( v, m, 2 );
    round_fn8( v, m, 3 );
    round_fn8( v, m, 4 );
    round_fn8( v, m, 5 );
    round_fn8( v, m, 6 );

    /* Apply the state updates to the active lanes */

    wc_t active_lane = wc_narrow( active_lane_lo, active_lane_hi );
    h0 = wu_if( active_lane, wu_xor( v[ 0], v[ 8] ), h0 );
    h1 = wu_if( active_lane, wu_xor( v[ 1], v[ 9] ), h1 );
    h2 = wu_if( active_lane, wu_xor( v[ 2], v[10] ), h2 );
    h3 = wu_if( active_lane, wu_xor( v[ 3], v[11] ), h3 );
    h4 = wu_if( active_lane, wu_xor( v[ 4], v[12] ), h4 );
    h5 = wu_if( active_lane, wu_xor( v[ 5], v[13] ), h5 );
    h6 = wu_if( active_lane, wu_xor( v[ 6], v[14] ), h6 );
    h7 = wu_if( active_lane, wu_xor( v[ 7], v[15] ), h7 );

    /* Advance to the next message segment blocks.  In pseudo code,
       the below is:

         W += 64; if( block_rem ) block_rem--;

       Since wc_to_wv_raw(false/true) is 0UL/~0UL, we can use wv_add /
       wc_to_wv_raw instead of wv_sub / wc_to_wv to save some ops.
       (Consider conditional increment / decrement operations?)

       Also since we do not load anything at W(lane) above unless
       block_rem(lane) is non-zero, we can omit vector conditional
       operations for W(lane) below to save some additional ops. */

    W_lo = wv_add( W_lo, wv_64 );
    W_hi = wv_add( W_hi, wv_64 );
    off  = wu_add( off, wu_bcast( FD_BLAKE3_BLOCK_SZ) );

    block_rem_lo = wv_add( block_rem_lo, wc_to_wv_raw( active_lane_lo ) );
    block_rem_hi = wv_add( block_rem_hi, wc_to_wv_raw( active_lane_hi ) );
  }

  /* Store the results */

  wu_transpose_8x8( h0, h1, h2, h3, h4, h5, h6, h7,
                    h0, h1, h2, h3, h4, h5, h6, h7 );

  uint * const * batch_hash = (uint * const *)__builtin_assume_aligned( _batch_hash, 32 );
  switch( batch_cnt ) { /* application dependent prob */
  case 8UL: wu_st( batch_hash[7], h7 ); __attribute__((fallthrough));
  case 7UL: wu_st( batch_hash[6], h6 ); __attribute__((fallthrough));
  case 6UL: wu_st( batch_hash[5], h5 ); __attribute__((fallthrough));
  case 5UL: wu_st( batch_hash[4], h4 ); __attribute__((fallthrough));
  case 4UL: wu_st( batch_hash[3], h3 ); __attribute__((fallthrough));
  case 3UL: wu_st( batch_hash[2], h2 ); __attribute__((fallthrough));
  case 2UL: wu_st( batch_hash[1], h1 ); __attribute__((fallthrough));
  case 1UL: wu_st( batch_hash[0], h0 ); __attribute__((fallthrough));
  default: break;
  }
}

void
fd_blake3_avx_compress8_fast( uchar const * restrict msg,
                              uchar       * restrict _out,
                              ulong                  counter,
                              uchar                  flags ) {

  uchar * restrict out = __builtin_assume_aligned( _out, 32 );

  int   parent = flags & FD_BLAKE3_FLAG_PARENT;
  int   lg_sz  = fd_int_if( parent, FD_BLAKE3_OUTCHAIN_LG_SZ+1, FD_BLAKE3_CHUNK_LG_SZ );
  ulong sz     = 1UL<<lg_sz;

  /* counters stay the same for each block.  Across chunks, they
     increment if we are hashing leaves.  Otherwise, they are zero. */

  wu_t ctr_add   = wu_and( wu_bcast( parent ? 0 : UINT_MAX ),
                           wu( 0, 1, 2, 3, 4, 5, 6, 7 ) );
  wu_t ctr_lo    = wu_add( wu_bcast( counter ), ctr_add );
  wu_t ctr_carry = wi_gt ( wu_xor( ctr_add, wu_bcast( 0x80000000 ) ),
                           wu_xor( ctr_lo,  wu_bcast( 0x80000000 ) ) );
  wu_t ctr_hi    = wu_sub( wu_bcast( counter>>32 ), ctr_carry );
  wu_t sz_vec    = wu_bcast( FD_BLAKE3_BLOCK_SZ );

  wu_t const iv0 = wu_bcast( FD_BLAKE3_IV[0] );
  wu_t const iv1 = wu_bcast( FD_BLAKE3_IV[1] );
  wu_t const iv2 = wu_bcast( FD_BLAKE3_IV[2] );
  wu_t const iv3 = wu_bcast( FD_BLAKE3_IV[3] );
  wu_t const iv4 = wu_bcast( FD_BLAKE3_IV[4] );
  wu_t const iv5 = wu_bcast( FD_BLAKE3_IV[5] );
  wu_t const iv6 = wu_bcast( FD_BLAKE3_IV[6] );
  wu_t const iv7 = wu_bcast( FD_BLAKE3_IV[7] );

  wu_t h0=iv0; wu_t h1=iv1; wu_t h2=iv2; wu_t h3=iv3;
  wu_t h4=iv4; wu_t h5=iv5; wu_t h6=iv6; wu_t h7=iv7;

  ulong off = 0UL;
  do {
    ulong const off_next = off+FD_BLAKE3_BLOCK_SZ;
    int chunk_flags =
        ( off     ==0UL ? FD_BLAKE3_FLAG_CHUNK_START : 0 ) |
        ( off_next==sz  ? FD_BLAKE3_FLAG_CHUNK_END   : 0 );
    int flags_ = flags | fd_int_if( parent, 0, chunk_flags );
    wu_t flags_vec = wu_bcast( flags_ );

    wu_t m[16];
    m[ 0] = wu_ldu( msg + (0<<lg_sz) + off      );
    m[ 1] = wu_ldu( msg + (1<<lg_sz) + off      );
    m[ 2] = wu_ldu( msg + (2<<lg_sz) + off      );
    m[ 3] = wu_ldu( msg + (3<<lg_sz) + off      );
    m[ 4] = wu_ldu( msg + (4<<lg_sz) + off      );
    m[ 5] = wu_ldu( msg + (5<<lg_sz) + off      );
    m[ 6] = wu_ldu( msg + (6<<lg_sz) + off      );
    m[ 7] = wu_ldu( msg + (7<<lg_sz) + off      );
    m[ 8] = wu_ldu( msg + (0<<lg_sz) + off + 32 );
    m[ 9] = wu_ldu( msg + (1<<lg_sz) + off + 32 );
    m[10] = wu_ldu( msg + (2<<lg_sz) + off + 32 );
    m[11] = wu_ldu( msg + (3<<lg_sz) + off + 32 );
    m[12] = wu_ldu( msg + (4<<lg_sz) + off + 32 );
    m[13] = wu_ldu( msg + (5<<lg_sz) + off + 32 );
    m[14] = wu_ldu( msg + (6<<lg_sz) + off + 32 );
    m[15] = wu_ldu( msg + (7<<lg_sz) + off + 32 );

    wu_transpose_8x8( m[0x0], m[0x1], m[0x2], m[0x3], m[0x4], m[0x5], m[0x6], m[0x7],
                      m[0x0], m[0x1], m[0x2], m[0x3], m[0x4], m[0x5], m[0x6], m[0x7] );
    wu_transpose_8x8( m[0x8], m[0x9], m[0xa], m[0xb], m[0xc], m[0xd], m[0xe], m[0xf],
                      m[0x8], m[0x9], m[0xa], m[0xb], m[0xc], m[0xd], m[0xe], m[0xf] );

    wu_t v[16] = {
        h0,     h1,     h2,     h3,
        h4,     h5,     h6,     h7,
        iv0,    iv1,    iv2,    iv3,
        ctr_lo, ctr_hi, sz_vec, flags_vec,
    };

    round_fn8( v, m, 0 );
    round_fn8( v, m, 1 );
    round_fn8( v, m, 2 );
    round_fn8( v, m, 3 );
    round_fn8( v, m, 4 );
    round_fn8( v, m, 5 );
    round_fn8( v, m, 6 );

    h0 = wu_xor( v[ 0], v[ 8] );
    h1 = wu_xor( v[ 1], v[ 9] );
    h2 = wu_xor( v[ 2], v[10] );
    h3 = wu_xor( v[ 3], v[11] );
    h4 = wu_xor( v[ 4], v[12] );
    h5 = wu_xor( v[ 5], v[13] );
    h6 = wu_xor( v[ 6], v[14] );
    h7 = wu_xor( v[ 7], v[15] );

    off = off_next;
  } while( off!=sz );

  wu_transpose_8x8( h0, h1, h2, h3, h4, h5, h6, h7,
                    h0, h1, h2, h3, h4, h5, h6, h7 );

  wu_st( (uint *)( out + (0UL<<FD_BLAKE3_OUTCHAIN_LG_SZ) ), h0 );
  wu_st( (uint *)( out + (1UL<<FD_BLAKE3_OUTCHAIN_LG_SZ) ), h1 );
  wu_st( (uint *)( out + (2UL<<FD_BLAKE3_OUTCHAIN_LG_SZ) ), h2 );
  wu_st( (uint *)( out + (3UL<<FD_BLAKE3_OUTCHAIN_LG_SZ) ), h3 );
  wu_st( (uint *)( out + (4UL<<FD_BLAKE3_OUTCHAIN_LG_SZ) ), h4 );
  wu_st( (uint *)( out + (5UL<<FD_BLAKE3_OUTCHAIN_LG_SZ) ), h5 );
  wu_st( (uint *)( out + (6UL<<FD_BLAKE3_OUTCHAIN_LG_SZ) ), h6 );
  wu_st( (uint *)( out + (7UL<<FD_BLAKE3_OUTCHAIN_LG_SZ) ), h7 );
}
