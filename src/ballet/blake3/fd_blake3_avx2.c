
// Source originally from https://github.com/BLAKE3-team/BLAKE3
// From commit: 64747d48ffe9d1fbf4b71e94cabeb8a211461081

#include "fd_blake3.h"
#include "fd_blake3_private.h"
#include "../../util/simd/fd_avx.h"
#include <assert.h>

#define wu_rot16 wb_exch_adj_pair

static inline __attribute__((always_inline)) wu_t
wu_rot12( wu_t x ) {
  return wu_ror( x, 12 );
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
  return wu_ror( x, 7 );
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
                         uint   const * restrict batch_sz,
                         ulong  const * restrict ctr_vec,
                         uint   const * restrict batch_flags,
                         void * const * restrict _batch_hash,
                         ushort *       restrict lthash,
                         uint                    out_sz,
                         void const *   restrict batch_cv ) {
  if( FD_UNLIKELY( lthash && batch_cnt!=8 ) ) FD_LOG_ERR(( "Lane masking not supported for fd_blake3_avx_compress8 in LtHash mode" ));
  if( FD_UNLIKELY( batch_cnt==0 || batch_cnt>8 ) ) FD_LOG_ERR(( "Invalid batch_cnt %lu", batch_cnt ));

  ulong const * batch_data = (ulong const *)_batch_data;

  if( FD_UNLIKELY( batch_cnt==1 ) ) {
    fd_blake3_sse_compress1( (uchar *)(_batch_hash[0]),
                             (uchar const *)(batch_data[0]),
                             batch_sz[0],
                             ctr_vec[0],
                             batch_flags[0],
                             NULL,
                             NULL );
    return;
  }

#if FD_BLAKE3_TRACING
  /* This log_line buffer is oversized by a fair bit (due to all the
     NULL terminators) but that's fine */
  char log_line[
      sizeof( "fd_blake3_avx_compress8" )+
      sizeof( "(batch_cnt=" )+21+
      sizeof( ",sz=["       )+(8*11)+sizeof( "]" )+
      sizeof( ",counter=["  )+(8*21)+sizeof( "]" )+
      sizeof( ",flags=["    )+(8* 2)+sizeof( "]" )+
      sizeof( ",custom_cv"  )+
      sizeof( ",lthash" )+
      sizeof( ")" ) ];

  char * p = fd_cstr_init( log_line );
  p = fd_cstr_append_text( p, "fd_blake3_avx_compress8(batch_cnt=", 34UL );
  p = fd_cstr_append_ulong_as_text( p, 0, 0, batch_cnt, fd_uchar_base10_dig_cnt( (uchar)batch_cnt ) );
  p = fd_cstr_append_text( p, ",sz=[", 5UL );
  for( ulong i=0UL; i<batch_cnt; i++ ) {
    p = fd_cstr_append_uint_as_text( p, ' ', 0, batch_sz[ i ], fd_uint_base10_dig_cnt( batch_sz[ i ] ) );
    if( i+1<batch_cnt ) p = fd_cstr_append_char( p, ',' );
  }
  p = fd_cstr_append_text( p, "],counter=[", 11UL );
  for( ulong i=0UL; i<batch_cnt; i++ ) {
    p = fd_cstr_append_ulong_as_text( p, ' ', 0, ctr_vec[ i ], fd_ulong_base10_dig_cnt( ctr_vec[ i ] ) );
    if( i+1<batch_cnt ) p = fd_cstr_append_char( p, ',' );
  }
  p = fd_cstr_append_text( p, "],flags=[", 9UL );
  for( ulong i=0UL; i<batch_cnt; i++ ) {
    static char const hex_lut[ 16 ] = {
      '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'
    };
    p = fd_cstr_append_char( p, hex_lut[ batch_flags[ i ]&0xf ] );
    if( i+1<batch_cnt ) p = fd_cstr_append_char( p, ',' );
  }
  p = fd_cstr_append_char( p, ']' );
  if( batch_cv ) p = fd_cstr_append_text( p, ",custom_cv", 10UL );
  if( lthash   ) p = fd_cstr_append_text( p, ",lthash", 7UL );
  p = fd_cstr_append_char( p, ')' );
  ulong line_len = (ulong)( p-log_line );
  fd_cstr_fini( p );

  FD_BLAKE3_TRACE(( "%.*s", (int)line_len, log_line ));
#endif

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
  if( FD_UNLIKELY( batch_cv ) ) {
    /* If the input chaining value is overridden, transpose the input to
       AVX representation (8x8 transpose). */
    __m256i const ** cv_vec = (__m256i const **)batch_cv;
    wu_t cv[8];
    for( ulong i=0UL; i<8UL; i++ ) cv[i] = _mm256_loadu_si256( cv_vec[ i ] );
    wu_transpose_8x8( cv[0], cv[1], cv[2], cv[3], cv[4], cv[5], cv[6], cv[7],
                      h0,    h1,    h2,    h3,    h4,    h5,    h6,    h7 );
  }

  wu_t ctr_lo = wu( ctr_vec[0],     ctr_vec[1],     ctr_vec[2],     ctr_vec[3],
                    ctr_vec[4],     ctr_vec[5],     ctr_vec[6],     ctr_vec[7] );
  wu_t ctr_hi = wu( ctr_vec[0]>>32, ctr_vec[1]>>32, ctr_vec[2]>>32, ctr_vec[3]>>32,
                    ctr_vec[4]>>32, ctr_vec[5]>>32, ctr_vec[6]>>32, ctr_vec[7]>>32 );
  wu_t flags = wu_ldu( batch_flags );
  wu_t off   = wu_zero();
  wu_t sz    = wu_ldu( batch_sz );

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

  /* Upper half of the compression function output.
     Usually thrown away, but kept in the final compression round if
     out_sz==64. */
  wu_t hu[8] = {0};

  ulong lthash_rem    = lthash ? 32 : 0; /* Number of LtHash (XOF) blocks remaining */
  int   compress_done = 0;
  for(;;) {
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

    /* LtHash mode ends compression one early */

    wc_t active_lane_lo;
    wc_t active_lane_hi;
    if( FD_UNLIKELY( lthash ) ) {
      /* Compress until root block */
      wu_t all_root = wu_bcast( FD_BLAKE3_FLAG_ROOT );
      wu_t not_root = wu_ne( wu_and( block_flags, all_root ), all_root );
      active_lane_lo = _mm256_cvtepi32_epi64( _mm256_extractf128_si256( not_root, 0 ) );
      active_lane_hi = _mm256_cvtepi32_epi64( _mm256_extractf128_si256( not_root, 1 ) );
    } else {
      /* Complete when there is no more input data */
      active_lane_lo = wv_to_wc( block_rem_lo );
      active_lane_hi = wv_to_wc( block_rem_hi );
    }

    /* Suppress CHUNK_{START,END} flags unless leaf node */

    wc_t is_parent = wu_shl( flags, 5 );  /* shift FLAG_PARENT into AVX condition bit */
    wu_t chunk_flags = wu_if( block_last,  wu_bcast( FD_BLAKE3_FLAG_CHUNK_END   ), wu_zero() );
    if( out_sz==32 ) {
      /* Hacky: out_sz==64 is only used for post-compress XOF hashing,
         so use that as a hint when to suppress the 'CHUNK_START' flag. */
      chunk_flags = wu_or( chunk_flags, wu_if( block_first, wu_bcast( FD_BLAKE3_FLAG_CHUNK_START ), wu_zero() ) );
    }
    wu_t block_sz = wu_min( wu_sub( sz, off ), wu_bcast( FD_BLAKE3_BLOCK_SZ ) );
    block_flags = wu_or( block_flags, wu_if( is_parent, wu_zero(), chunk_flags ) );

    /* Check if we are done compressing */

    compress_done |= !wc_any( wc_or( active_lane_lo, active_lane_hi ) );
    if( FD_UNLIKELY( compress_done ) ) {
      if( FD_UNLIKELY( !lthash_rem ) ) break;
      active_lane_lo = wc_bcast( INT_MAX );
      active_lane_hi = wc_bcast( INT_MAX );
      /* Load the next message block and fall through to XOF expansion */
    }

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

compress: (void)0;
    wu_t v[16] = {
        h0,     h1,     h2,       h3,
        h4,     h5,     h6,       h7,
        iv0,    iv1,    iv2,      iv3,
        ctr_lo, ctr_hi, block_sz, block_flags,
    };

    /* Debug utility */
#define STATE_FMT         "state[%u] =\n  %08x %08x %08x %08x\n  %08x %08x %08x %08x\n  %08x %08x %08x %08x\n  %08x %08x %08x %08x"
#define STATE_FMT_ARGS(v,i) (uint)i,\
        fd_uint_bswap(wu_extract(v[0x0],i)),fd_uint_bswap(wu_extract(v[0x1],i)),fd_uint_bswap(wu_extract(v[0x2],i)),fd_uint_bswap(wu_extract(v[0x3],i)),\
        fd_uint_bswap(wu_extract(v[0x4],i)),fd_uint_bswap(wu_extract(v[0x5],i)),fd_uint_bswap(wu_extract(v[0x6],i)),fd_uint_bswap(wu_extract(v[0x7],i)),\
        fd_uint_bswap(wu_extract(v[0x8],i)),fd_uint_bswap(wu_extract(v[0x9],i)),fd_uint_bswap(wu_extract(v[0xa],i)),fd_uint_bswap(wu_extract(v[0xb],i)),\
        fd_uint_bswap(wu_extract(v[0xc],i)),fd_uint_bswap(wu_extract(v[0xd],i)),fd_uint_bswap(wu_extract(v[0xe],i)),fd_uint_bswap(wu_extract(v[0xf],i))

    // FD_LOG_NOTICE(( STATE_FMT, STATE_FMT_ARGS(v,0) ));
    round_fn8( v, m, 0 );
    round_fn8( v, m, 1 );
    round_fn8( v, m, 2 );
    round_fn8( v, m, 3 );
    round_fn8( v, m, 4 );
    round_fn8( v, m, 5 );
    round_fn8( v, m, 6 );
    // FD_LOG_NOTICE(( STATE_FMT, STATE_FMT_ARGS(v,0) ));

    wu_t d[8] = {
      wu_xor( v[ 0], v[ 8] ), wu_xor( v[ 1], v[ 9] ),
      wu_xor( v[ 2], v[10] ), wu_xor( v[ 3], v[11] ),
      wu_xor( v[ 4], v[12] ), wu_xor( v[ 5], v[13] ),
      wu_xor( v[ 6], v[14] ), wu_xor( v[ 7], v[15] )
    };

    if( FD_LIKELY( !compress_done ) ) {

      /* Apply the state updates to the active lanes */

      wc_t active_lane = wc_narrow( active_lane_lo, active_lane_hi );
      if( FD_UNLIKELY( out_sz==64 ) ) {
        /* FIXME only export in the last iteration */
        hu[0] = wu_if( active_lane, wu_xor( h0, v[ 8] ), hu[0] );
        hu[1] = wu_if( active_lane, wu_xor( h1, v[ 9] ), hu[1] );
        hu[2] = wu_if( active_lane, wu_xor( h2, v[10] ), hu[2] );
        hu[3] = wu_if( active_lane, wu_xor( h3, v[11] ), hu[3] );
        hu[4] = wu_if( active_lane, wu_xor( h4, v[12] ), hu[4] );
        hu[5] = wu_if( active_lane, wu_xor( h5, v[13] ), hu[5] );
        hu[6] = wu_if( active_lane, wu_xor( h6, v[14] ), hu[6] );
        hu[7] = wu_if( active_lane, wu_xor( h7, v[15] ), hu[7] );
      }
      h0 = wu_if( active_lane, d[0], h0 );
      h1 = wu_if( active_lane, d[1], h1 );
      h2 = wu_if( active_lane, d[2], h2 );
      h3 = wu_if( active_lane, d[3], h3 );
      h4 = wu_if( active_lane, d[4], h4 );
      h5 = wu_if( active_lane, d[5], h5 );
      h6 = wu_if( active_lane, d[6], h6 );
      h7 = wu_if( active_lane, d[7], h7 );

      /* Advance to the next message segment blocks.  In pseudo code,
         the below is:

           W += 64; if( block_rem ) block_rem--;

         Since wc_to_wv_raw(false/true) is 0UL/~0UL, we can use wv_add /
         wc_to_wv_raw instead of wv_sub / wc_to_wv to save some ops.
         (Consider conditional increment / decrement operations?)

         Also since we do not load anything at W(lane) above unless
         block_rem(lane) is non-zero, we can omit vector conditional
         operations for W(lane) below to save some additional ops. */

      W_lo = wv_add( W_lo, wv_if( active_lane_lo, wv_64, wv_zero() ) );
      W_hi = wv_add( W_hi, wv_if( active_lane_hi, wv_64, wv_zero() ) );
      off  = wu_add( off,  wu_if( active_lane, wu_bcast( FD_BLAKE3_BLOCK_SZ ), wv_zero() ) );

      block_rem_lo = wv_add( block_rem_lo, wv_if( active_lane_lo, wc_to_wv_raw( active_lane_lo ), wv_zero() ) );
      block_rem_hi = wv_add( block_rem_hi, wv_if( active_lane_hi, wc_to_wv_raw( active_lane_hi ), wv_zero() ) );

    } else { /* LtHash mode */

      /* d[i] contains output_off+(i*4) 32-bit words across output[0..8] */
      wu_t dh[ 8 ] = {
        wu_xor( h0, v[0x8] ),
        wu_xor( h1, v[0x9] ),
        wu_xor( h2, v[0xa] ),
        wu_xor( h3, v[0xb] ),
        wu_xor( h4, v[0xc] ),
        wu_xor( h5, v[0xd] ),
        wu_xor( h6, v[0xe] ),
        wu_xor( h7, v[0xf] )
      };

      /* Transpose outer 8x8 blocks */
      wu_transpose_8x8( d [0],d [1],d [2],d [3],d [4],d [5],d [6],d [7],
                        d [0],d [1],d [2],d [3],d [4],d [5],d [6],d [7] );
      wu_transpose_8x8( dh[0],dh[1],dh[2],dh[3],dh[4],dh[5],dh[6],dh[7],
                        dh[0],dh[1],dh[2],dh[3],dh[4],dh[5],dh[6],dh[7] );

      /* d[i] contains output[i]+out_off */

      /* Reduce-add into d[0] */
      d [0] = wh_add( d [0], d [1] ); /* sum(l[0 1]) */
      dh[0] = wh_add( dh[0], dh[1] ); /* sum(h[0 1]) */
      d [2] = wh_add( d [2], d [3] ); /* sum(l[2 3]) */
      dh[2] = wh_add( dh[2], dh[3] ); /* sum(h[2 3]) */
      d [4] = wh_add( d [4], d [5] ); /* sum(l[4 5])*/
      dh[4] = wh_add( dh[4], dh[5] ); /* sum(h[4 5]) */
      d [6] = wh_add( d [6], d [7] ); /* sum(l[6 7]) */
      dh[6] = wh_add( dh[6], dh[7] ); /* sum(h[6 7]) */
      d [0] = wh_add( d [0], d [2] ); /* sum(l[0 1 2 3]) */
      dh[0] = wh_add( dh[0], dh[2] ); /* sum(h[0 1 2 3]) */
      d [4] = wh_add( d [4], d [6] ); /* sum(l[4 5 6 7]) */
      dh[4] = wh_add( dh[4], dh[6] ); /* sum(h[4 5 6 7]) */
      d [0] = wh_add( d [0], d [4] ); /* sum(l[0 1 2 3 4 5 6 7]) */
      dh[0] = wh_add( dh[0], dh[4] ); /* sum(h[0 1 2 3 4 5 6 7]) */
      wh_st( lthash,    d [0] );
      wh_st( lthash+16, dh[0] );

      /* Wind up for next iteration */
      lthash += 32;
      lthash_rem--;
      wu_t ctr_add   = wu_bcast( 1 );
      /**/ ctr_lo    = wu_add( ctr_lo, ctr_add );
      wu_t ctr_carry = wi_gt ( wu_xor( ctr_add, wu_bcast( 0x80000000 ) ),
                               wu_xor( ctr_lo,  wu_bcast( 0x80000000 ) ) );
      /**/ ctr_hi    = wu_sub( ctr_hi, ctr_carry );
      if( FD_UNLIKELY( !lthash_rem ) ) {
        FD_BLAKE3_TRACE(( "fd_blake3_avx_compress8: done (lthash para)" ));
        return;
      }
      goto compress;

#   undef STATE_FMT
#   undef STATE_FMT_ARGS
    }
  }

  /* Store the results */

  wu_transpose_8x8( h0, h1, h2, h3, h4, h5, h6, h7,
                    h0, h1, h2, h3, h4, h5, h6, h7 );

  uint * const * batch_hash = (uint * const *)__builtin_assume_aligned( _batch_hash, 32 );
  if( FD_LIKELY( out_sz==32 ) ) {
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
  } else if( out_sz==64 ) {
    wu_transpose_8x8( hu[0], hu[1], hu[2], hu[3], hu[4], hu[5], hu[6], hu[7],
                      hu[0], hu[1], hu[2], hu[3], hu[4], hu[5], hu[6], hu[7] );
    switch( batch_cnt ) { /* application dependent prob */
    case 8UL: wu_st( batch_hash[7],   h7    );
              wu_st( batch_hash[7]+8, hu[7] ); __attribute__((fallthrough));
    case 7UL: wu_st( batch_hash[6],   h6    );
              wu_st( batch_hash[6]+8, hu[6] ); __attribute__((fallthrough));
    case 6UL: wu_st( batch_hash[5],   h5    );
              wu_st( batch_hash[5]+8, hu[5] ); __attribute__((fallthrough));
    case 5UL: wu_st( batch_hash[4],   h4    );
              wu_st( batch_hash[4]+8, hu[4] ); __attribute__((fallthrough));
    case 4UL: wu_st( batch_hash[3],   h3    );
              wu_st( batch_hash[3]+8, hu[3] ); __attribute__((fallthrough));
    case 3UL: wu_st( batch_hash[2],   h2    );
              wu_st( batch_hash[2]+8, hu[2] ); __attribute__((fallthrough));
    case 2UL: wu_st( batch_hash[1],   h1    );
              wu_st( batch_hash[1]+8, hu[1] ); __attribute__((fallthrough));
    case 1UL: wu_st( batch_hash[0],   h0    );
              wu_st( batch_hash[0]+8, hu[0] ); __attribute__((fallthrough));
    default: break;
    }
  } else {
    FD_LOG_ERR(( "Invalid out_sz %u", out_sz ));
  }
}

void
fd_blake3_avx_compress8_fast( uchar const * restrict msg,
                              uchar       * restrict _out,
                              ulong                  counter,
                              uchar                  flags ) {
  FD_BLAKE3_TRACE(( "fd_blake3_avx_compress8_fast(msg=%p,out=%p,counter=%lu,flags=%02x)", (void *)msg, (void *)_out, counter, flags ));

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
    uint chunk_flags =
        ( off     ==0UL ? FD_BLAKE3_FLAG_CHUNK_START : 0u ) |
        ( off_next==sz  ? FD_BLAKE3_FLAG_CHUNK_END   : 0u );
    uint flags_ = flags | fd_uint_if( parent, 0, chunk_flags );
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
