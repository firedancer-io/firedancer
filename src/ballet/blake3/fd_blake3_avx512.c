
// Source originally from https://github.com/BLAKE3-team/BLAKE3
// From commit: c0ea395cf91d242f078c23d5f8d87eb9dd5f7b78

#include "fd_blake3_private.h"
#include "../../util/simd/fd_avx512.h"
#include "../../util/simd/fd_avx.h"

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

void
fd_blake3_avx512_compress16( ulong                   batch_cnt,
                             void const   * restrict _batch_data,
                             uint const   * restrict batch_sz,
                             ulong const  * restrict ctr_vec,
                             uint const   * restrict batch_flags,
                             void * const * restrict _batch_hash,
                             ushort *       restrict lthash,
                             uint                    out_sz,
                             void const *   restrict batch_cv ) {
  if( FD_UNLIKELY( lthash && batch_cnt!=16 ) ) FD_LOG_ERR(( "Lane masking not supported for fd_blake3_avx512_compress16 in LtHash mode" ));
  if( FD_UNLIKELY( batch_cnt==0 || batch_cnt>16 ) ) FD_LOG_ERR(( "Invalid batch_cnt %lu", batch_cnt ));

  /* We can only process input blocks of 64 bytes, but message data size
     is not necessarily a multiple of 64.  We compute the tail block of
     each message here.  We then process complete blocks of the original
     message in place, switching to processing to these  tail blocks in
     the same pass toward the end. */

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
      sizeof( "fd_blake3_avx512_compress16" )+
      sizeof( "(batch_cnt=" )+21+
      sizeof( ",sz=["       )+(16*11)+sizeof( "]" )+
      sizeof( ",counter=["  )+(16*21)+sizeof( "]" )+
      sizeof( ",flags=["    )+(16* 2)+sizeof( "]" )+
      sizeof( ",custom_cv"  )+
      sizeof( ",lthash" )+
      sizeof( ")" ) ];

  char * p = fd_cstr_init( log_line );
  p = fd_cstr_append_text( p, "fd_blake3_avx512_compress16(batch_cnt=", 38UL );
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

  ulong batch_tail_data[ 16 ] __attribute__((aligned(64)));
  ulong batch_tail_rem [ 16 ] __attribute__((aligned(64)));

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
  if( FD_UNLIKELY( batch_cv ) ) {
    /* If the input chaining value is overridden, transpose the input
       to AVX512 representation.  (wwu 16x8 transpose)  FIXME There's
       probably a way to do this using AVX512 instead of AVX. */
    __m256i const ** cv_vec = (__m256i const **)batch_cv;
    wu_t cv_lo[8]; wu_t cv_hi[8];
    cv_lo[ 0 ] = _mm256_loadu_si256( cv_vec[  0 ] );
    cv_lo[ 1 ] = _mm256_loadu_si256( cv_vec[  1 ] );
    cv_lo[ 2 ] = _mm256_loadu_si256( cv_vec[  2 ] );
    cv_lo[ 3 ] = _mm256_loadu_si256( cv_vec[  3 ] );
    cv_lo[ 4 ] = _mm256_loadu_si256( cv_vec[  4 ] );
    cv_lo[ 5 ] = _mm256_loadu_si256( cv_vec[  5 ] );
    cv_lo[ 6 ] = _mm256_loadu_si256( cv_vec[  6 ] );
    cv_lo[ 7 ] = _mm256_loadu_si256( cv_vec[  7 ] );
    cv_hi[ 0 ] = _mm256_loadu_si256( cv_vec[  8 ] );
    cv_hi[ 1 ] = _mm256_loadu_si256( cv_vec[  9 ] );
    cv_hi[ 2 ] = _mm256_loadu_si256( cv_vec[ 10 ] );
    cv_hi[ 3 ] = _mm256_loadu_si256( cv_vec[ 11 ] );
    cv_hi[ 4 ] = _mm256_loadu_si256( cv_vec[ 12 ] );
    cv_hi[ 5 ] = _mm256_loadu_si256( cv_vec[ 13 ] );
    cv_hi[ 6 ] = _mm256_loadu_si256( cv_vec[ 14 ] );
    cv_hi[ 7 ] = _mm256_loadu_si256( cv_vec[ 15 ] );
    wu_transpose_8x8( cv_lo[0], cv_lo[1], cv_lo[2], cv_lo[3], cv_lo[4], cv_lo[5], cv_lo[6], cv_lo[7],
                      cv_lo[0], cv_lo[1], cv_lo[2], cv_lo[3], cv_lo[4], cv_lo[5], cv_lo[6], cv_lo[7] );
    wu_transpose_8x8( cv_hi[0], cv_hi[1], cv_hi[2], cv_hi[3], cv_hi[4], cv_hi[5], cv_hi[6], cv_hi[7],
                      cv_hi[0], cv_hi[1], cv_hi[2], cv_hi[3], cv_hi[4], cv_hi[5], cv_hi[6], cv_hi[7] );
    h0 = _mm512_inserti64x4( _mm512_castsi256_si512( cv_lo[ 0 ] ), cv_hi[ 0 ], 1 );
    h1 = _mm512_inserti64x4( _mm512_castsi256_si512( cv_lo[ 1 ] ), cv_hi[ 1 ], 1 );
    h2 = _mm512_inserti64x4( _mm512_castsi256_si512( cv_lo[ 2 ] ), cv_hi[ 2 ], 1 );
    h3 = _mm512_inserti64x4( _mm512_castsi256_si512( cv_lo[ 3 ] ), cv_hi[ 3 ], 1 );
    h4 = _mm512_inserti64x4( _mm512_castsi256_si512( cv_lo[ 4 ] ), cv_hi[ 4 ], 1 );
    h5 = _mm512_inserti64x4( _mm512_castsi256_si512( cv_lo[ 5 ] ), cv_hi[ 5 ], 1 );
    h6 = _mm512_inserti64x4( _mm512_castsi256_si512( cv_lo[ 6 ] ), cv_hi[ 6 ], 1 );
    h7 = _mm512_inserti64x4( _mm512_castsi256_si512( cv_lo[ 7 ] ), cv_hi[ 7 ], 1 );
  }

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
  wwu_t wwu_64       = wwu_bcast( FD_BLAKE3_BLOCK_SZ );
  wwv_t wwv_64       = wwv_bcast( FD_BLAKE3_BLOCK_SZ );
  wwv_t W_sentinel   = wwv_bcast( (ulong)scratch );
  //wwc_t batch_lane   = wc_unpack( (1<<batch_cnt)-1 );

  wwv_t tail_lo      = wwv_ld( batch_tail_data   );
  wwv_t tail_hi      = wwv_ld( batch_tail_data+8 );

  wwv_t tail_rem_lo  = wwv_ld( batch_tail_rem    );
  wwv_t tail_rem_hi  = wwv_ld( batch_tail_rem+8  );

  wwv_t W_lo         = wwv_ld( batch_data        );
  wwv_t W_hi         = wwv_ld( batch_data+8      );

  wwv_t batch_sz_lo  = _mm512_cvtepi32_epi64( _mm512_extracti32x8_epi32( sz, 0 ) );
  wwv_t batch_sz_hi  = _mm512_cvtepi32_epi64( _mm512_extracti32x8_epi32( sz, 1 ) );

  wwv_t block_rem_lo = wwv_if( ((1<<batch_cnt)-1) & 0xff,
                               wwv_add( wwv_shr( batch_sz_lo, FD_BLAKE3_BLOCK_LG_SZ ), tail_rem_lo ), zero );
  wwv_t block_rem_hi = wwv_if( ((1<<batch_cnt)-1) >> 8,
                               wwv_add( wwv_shr( batch_sz_hi, FD_BLAKE3_BLOCK_LG_SZ ), tail_rem_hi ), zero );

  /* Upper half of the compression function output.
     Usually thrown away, but kept in the final compression round if
     out_sz==64. */
  wwu_t hu[8] = {0};

  ulong lthash_rem    = lthash ? 32 : 0; /* Number of LtHash (XOF) blocks remaining */
  int   compress_done = 0;
  for(;;) {
    /* Switch lanes that have hit the end of their in-place bulk
       processing to their out-of-place scratch tail regions as
       necessary. */

    W_lo = wwv_if( wwv_eq( block_rem_lo, tail_rem_lo ), tail_lo, W_lo );
    W_hi = wwv_if( wwv_eq( block_rem_hi, tail_rem_hi ), tail_hi, W_hi );

    /* Derive per-block flags and block sizes */

    int block_first = wwu_eq( off, wwu_zero() );
    int block_last  = wwi_le( sz, wwu_add( off, wwu_bcast( FD_BLAKE3_BLOCK_SZ ) ) );

    /* Suppress root flag unless last block */

    wwu_t root_mask   = wwu_if( block_last, wwu_bcast( UINT_MAX ), wwu_bcast( ~FD_BLAKE3_FLAG_ROOT ) );
    wwu_t block_flags = wwu_and( flags, root_mask );

    /* Mask lanes that completed */

    int active_lane_lo;
    int active_lane_hi;
    if( FD_UNLIKELY( lthash ) ) {
      /* Compress until root block */
      wwu_t all_root = wwu_bcast( FD_BLAKE3_FLAG_ROOT );
      int   not_root = wwu_ne( wwu_and( block_flags, all_root ), all_root );
      active_lane_lo = (int)(__mmask8)not_root;
      active_lane_hi = (int)(__mmask8)(not_root>>8);
    } else {
      /* Complete when there is no more input data */
      active_lane_lo = wwv_ne( block_rem_lo, zero );
      active_lane_hi = wwv_ne( block_rem_hi, zero );
    }

    /* Suppress CHUNK_{START,END} flags unless leaf node */

    int is_parent = wwu_ne( wwu_and( flags, wwu_bcast( FD_BLAKE3_FLAG_PARENT ) ), wwu_zero() );
    wwu_t chunk_flags = wwu_if( block_last, wwu_bcast( FD_BLAKE3_FLAG_CHUNK_END ), wwu_zero() );
    if( out_sz==32 ) {
      /* Hacky: out_sz==64 is only used for post-compress XOF hashing,
         so use that as a hint when to suppress the 'CHUNK_START' flag. */
      chunk_flags = wwu_or( chunk_flags, wwu_if( block_first, wwu_bcast( FD_BLAKE3_FLAG_CHUNK_START ), wwu_zero() ) );
    }
    wwu_t block_sz = wwu_min( wwu_sub( sz, off ), wwu_64 );
    block_flags = wwu_or( block_flags, wwu_if( is_parent, wwu_zero(), chunk_flags ) );

    /* Check if we are done compressing */

    compress_done |= !(active_lane_lo | active_lane_hi);
    if( FD_UNLIKELY( compress_done ) ) {
      if( FD_UNLIKELY( !lthash_rem ) ) break;
      active_lane_lo = 0xff;
      active_lane_hi = 0xff;
      /* Load the next message block and fall through to XOF expansion */
    }

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

    wwu_transpose_16x16( m[0x0], m[0x1], m[0x2], m[0x3], m[0x4], m[0x5], m[0x6], m[0x7],
                         m[0x8], m[0x9], m[0xa], m[0xb], m[0xc], m[0xd], m[0xe], m[0xf],
                         m[0x0], m[0x1], m[0x2], m[0x3], m[0x4], m[0x5], m[0x6], m[0x7],
                         m[0x8], m[0x9], m[0xa], m[0xb], m[0xc], m[0xd], m[0xe], m[0xf] );

    /* Compute the BLAKE3 compression function updates */

compress: (void)0;
    wwu_t v[16] = {
        h0,     h1,     h2,       h3,
        h4,     h5,     h6,       h7,
        iv0,    iv1,    iv2,      iv3,
        ctr_lo, ctr_hi, block_sz, block_flags,
    };

    /* Debug utility */
#define STATE_FMT         "[%u] =\n  %08x %08x %08x %08x\n  %08x %08x %08x %08x\n  %08x %08x %08x %08x\n  %08x %08x %08x %08x"
#define STATE_FMT_ARGS(v,i) (uint)i,\
        fd_uint_bswap(wwu_extract(v[0x0],i)),fd_uint_bswap(wwu_extract(v[0x1],i)),fd_uint_bswap(wwu_extract(v[0x2],i)),fd_uint_bswap(wwu_extract(v[0x3],i)),\
        fd_uint_bswap(wwu_extract(v[0x4],i)),fd_uint_bswap(wwu_extract(v[0x5],i)),fd_uint_bswap(wwu_extract(v[0x6],i)),fd_uint_bswap(wwu_extract(v[0x7],i)),\
        fd_uint_bswap(wwu_extract(v[0x8],i)),fd_uint_bswap(wwu_extract(v[0x9],i)),fd_uint_bswap(wwu_extract(v[0xa],i)),fd_uint_bswap(wwu_extract(v[0xb],i)),\
        fd_uint_bswap(wwu_extract(v[0xc],i)),fd_uint_bswap(wwu_extract(v[0xd],i)),fd_uint_bswap(wwu_extract(v[0xe],i)),fd_uint_bswap(wwu_extract(v[0xf],i))

    // FD_LOG_NOTICE(( "pre " STATE_FMT, STATE_FMT_ARGS(v,0) ));
    round_fn16( v, m, 0 );
    round_fn16( v, m, 1 );
    round_fn16( v, m, 2 );
    round_fn16( v, m, 3 );
    round_fn16( v, m, 4 );
    round_fn16( v, m, 5 );
    round_fn16( v, m, 6 );
    // FD_LOG_NOTICE(( "post" STATE_FMT, STATE_FMT_ARGS(v,0) ));

    if( FD_LIKELY( !compress_done ) ) {

      /* Apply the state updates to the active lanes */

      int active_lane = active_lane_lo | (active_lane_hi<<8);
      FD_BLAKE3_TRACE(( "fd_blake3_avx512_compress16: compress lanes %02x%02x", active_lane_hi, active_lane_lo ));

      if( FD_UNLIKELY( out_sz==64 ) ) {
        /* FIXME only export in the last iteration */
        hu[0] = wwu_xor_if( active_lane, h0, v[ 8], hu[0] );
        hu[1] = wwu_xor_if( active_lane, h1, v[ 9], hu[1] );
        hu[2] = wwu_xor_if( active_lane, h2, v[10], hu[2] );
        hu[3] = wwu_xor_if( active_lane, h3, v[11], hu[3] );
        hu[4] = wwu_xor_if( active_lane, h4, v[12], hu[4] );
        hu[5] = wwu_xor_if( active_lane, h5, v[13], hu[5] );
        hu[6] = wwu_xor_if( active_lane, h6, v[14], hu[6] );
        hu[7] = wwu_xor_if( active_lane, h7, v[15], hu[7] );
      }
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

      W_lo = wwv_add_if( active_lane_lo, W_lo, wwv_64, W_lo );
      W_hi = wwv_add_if( active_lane_hi, W_hi, wwv_64, W_hi );
      off  = wwu_add_if( active_lane,    off,  wwu_64, off  );

      block_rem_lo = wwv_sub_if( active_lane_lo, block_rem_lo, one, block_rem_lo );
      block_rem_hi = wwv_sub_if( active_lane_hi, block_rem_hi, one, block_rem_hi );

    } else { /* LtHash mode */

      /* d[i] contains output_off+(i*4) 32-bit words across output[0..8] */
      FD_BLAKE3_TRACE(( "fd_blake3_avx512_compress16: expand lanes" ));
      wwu_t d[ 16 ] = {
        wwu_xor( v[0x0], v[0x8] ),
        wwu_xor( v[0x1], v[0x9] ),
        wwu_xor( v[0x2], v[0xa] ),
        wwu_xor( v[0x3], v[0xb] ),
        wwu_xor( v[0x4], v[0xc] ),
        wwu_xor( v[0x5], v[0xd] ),
        wwu_xor( v[0x6], v[0xe] ),
        wwu_xor( v[0x7], v[0xf] ),
        wwu_xor( h0,     v[0x8] ),
        wwu_xor( h1,     v[0x9] ),
        wwu_xor( h2,     v[0xa] ),
        wwu_xor( h3,     v[0xb] ),
        wwu_xor( h4,     v[0xc] ),
        wwu_xor( h5,     v[0xd] ),
        wwu_xor( h6,     v[0xe] ),
        wwu_xor( h7,     v[0xf] )
      };

      /* Transpose each 8x8 block */
      wwu_transpose_16x16( d[0x0], d[0x1], d[0x2], d[0x3], d[0x4], d[0x5], d[0x6], d[0x7],
                           d[0x8], d[0x9], d[0xa], d[0xb], d[0xc], d[0xd], d[0xe], d[0xf],
                           d[0x0], d[0x1], d[0x2], d[0x3], d[0x4], d[0x5], d[0x6], d[0x7],
                           d[0x8], d[0x9], d[0xa], d[0xb], d[0xc], d[0xd], d[0xe], d[0xf] );

      /* Reduce-add into d[0] */
      d[0x0] = wwh_add( d[0x0], d[0x1] ); /* sum(l[0 1]) */
      d[0x2] = wwh_add( d[0x2], d[0x3] ); /* sum(l[2 3]) */
      d[0x4] = wwh_add( d[0x4], d[0x5] ); /* sum(l[4 5]) */
      d[0x6] = wwh_add( d[0x6], d[0x7] ); /* sum(l[6 7]) */
      d[0x8] = wwh_add( d[0x8], d[0x9] ); /* sum(l[8 9]) */
      d[0xa] = wwh_add( d[0xa], d[0xb] ); /* sum(l[a b]) */
      d[0xc] = wwh_add( d[0xc], d[0xd] ); /* sum(l[c d]) */
      d[0xe] = wwh_add( d[0xe], d[0xf] ); /* sum(l[e f]) */
      d[0x0] = wwh_add( d[0x0], d[0x2] ); /* sum(l[0 1 2 3]) */
      d[0x4] = wwh_add( d[0x4], d[0x6] ); /* sum(l[4 5 6 7]) */
      d[0x8] = wwh_add( d[0x8], d[0xa] ); /* sum(l[8 9 a b]) */
      d[0xc] = wwh_add( d[0xc], d[0xe] ); /* sum(l[c d e f]) */
      d[0x0] = wwh_add( d[0x0], d[0x4] ); /* sum(l[0 1 2 3 4 5 6 7]) */
      d[0x8] = wwh_add( d[0x8], d[0xc] ); /* sum(l[8 9 a b c d e f]) */
      d[0x0] = wwh_add( d[0x0], d[0x8] ); /* sum(l[0 1 2 3 4 5 6 7 8 9 a b c d e f]) */
      wwh_st( lthash, d[0x0] );

      /* Wind up for next iteration */
      lthash += 32; /* 64 byte stride */
      lthash_rem--;
      wwu_t ctr_add   = wwu_bcast( 1 );
      /**/  ctr_lo    = wwu_add( ctr_lo, ctr_add );
      int   ctr_carry = wwi_gt ( wwu_xor( ctr_add, wwu_bcast( 0x80000000 ) ),
                                 wwu_xor( ctr_lo,  wwu_bcast( 0x80000000 ) ) );
      /**/  ctr_hi    = wwu_add_if( ctr_carry, ctr_hi, wwu_one(), ctr_hi );
      if( FD_UNLIKELY( !lthash_rem ) ) {
        FD_BLAKE3_TRACE(( "fd_blake3_avx512_compress16: done (lthash para)" ));
        return;
      }
      goto compress;

#   undef STATE_FMT
#   undef STATE_FMT_ARGS
    }
  }

  /* Store the results */

  wwu_t o0; wwu_t o1; wwu_t o2; wwu_t o3; wwu_t o4; wwu_t o5; wwu_t o6; wwu_t o7;
  wwu_t o8; wwu_t o9; wwu_t oA; wwu_t oB; wwu_t oC; wwu_t oD; wwu_t oE; wwu_t oF;

  wwu_transpose_16x16( h0,   h1,   h2,   h3,   h4,   h5,   h6,   h7,
                       hu[0],hu[1],hu[2],hu[3],hu[4],hu[5],hu[6],hu[7],
                       o0,   o1,   o2,   o3,   o4,   o5,   o6,   o7,
                       o8,   o9,   oA,   oB,   oC,   oD,   oE,   oF );

  uint * const * batch_hash = (uint * const *)_batch_hash;
  if( FD_LIKELY( out_sz==32 ) ) {
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
    FD_BLAKE3_TRACE(( "fd_blake3_avx512_compress16: done" ));
  } else if( out_sz==64 ) {
    switch( batch_cnt ) { /* application dependent prob */
    case 16UL: wwu_stu( batch_hash[15], oF ); __attribute__((fallthrough));
    case 15UL: wwu_stu( batch_hash[14], oE ); __attribute__((fallthrough));
    case 14UL: wwu_stu( batch_hash[13], oD ); __attribute__((fallthrough));
    case 13UL: wwu_stu( batch_hash[12], oC ); __attribute__((fallthrough));
    case 12UL: wwu_stu( batch_hash[11], oB ); __attribute__((fallthrough));
    case 11UL: wwu_stu( batch_hash[10], oA ); __attribute__((fallthrough));
    case 10UL: wwu_stu( batch_hash[ 9], o9 ); __attribute__((fallthrough));
    case  9UL: wwu_stu( batch_hash[ 8], o8 ); __attribute__((fallthrough));
    case  8UL: wwu_stu( batch_hash[ 7], o7 ); __attribute__((fallthrough));
    case  7UL: wwu_stu( batch_hash[ 6], o6 ); __attribute__((fallthrough));
    case  6UL: wwu_stu( batch_hash[ 5], o5 ); __attribute__((fallthrough));
    case  5UL: wwu_stu( batch_hash[ 4], o4 ); __attribute__((fallthrough));
    case  4UL: wwu_stu( batch_hash[ 3], o3 ); __attribute__((fallthrough));
    case  3UL: wwu_stu( batch_hash[ 2], o2 ); __attribute__((fallthrough));
    case  2UL: wwu_stu( batch_hash[ 1], o1 ); __attribute__((fallthrough));
    case  1UL: wwu_stu( batch_hash[ 0], o0 ); __attribute__((fallthrough));
    default: break;
    }
    FD_BLAKE3_TRACE(( "fd_blake3_avx512_compress16: done (out_sz=64)" ));
  } else {
    FD_LOG_ERR(( "Invalid out_sz %u", out_sz ));
  }
}

void
fd_blake3_avx512_compress16_fast( uchar const * restrict msg,
                                  uchar       * restrict out,
                                  ulong                  counter,
                                  uchar                  flags ) {
  FD_BLAKE3_TRACE(( "fd_blake3_avx512_compress16_fast(msg=%p,out=%p,counter=%lu,flags=%02x)", (void *)msg, (void *)out, counter, flags ));

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
    m[0x0] = wwu_ldu( msg + (0x0<<lg_sz) + off );
    m[0x1] = wwu_ldu( msg + (0x1<<lg_sz) + off );
    m[0x2] = wwu_ldu( msg + (0x2<<lg_sz) + off );
    m[0x3] = wwu_ldu( msg + (0x3<<lg_sz) + off );
    m[0x4] = wwu_ldu( msg + (0x4<<lg_sz) + off );
    m[0x5] = wwu_ldu( msg + (0x5<<lg_sz) + off );
    m[0x6] = wwu_ldu( msg + (0x6<<lg_sz) + off );
    m[0x7] = wwu_ldu( msg + (0x7<<lg_sz) + off );
    m[0x8] = wwu_ldu( msg + (0x8<<lg_sz) + off );
    m[0x9] = wwu_ldu( msg + (0x9<<lg_sz) + off );
    m[0xa] = wwu_ldu( msg + (0xa<<lg_sz) + off );
    m[0xb] = wwu_ldu( msg + (0xb<<lg_sz) + off );
    m[0xc] = wwu_ldu( msg + (0xc<<lg_sz) + off );
    m[0xd] = wwu_ldu( msg + (0xd<<lg_sz) + off );
    m[0xe] = wwu_ldu( msg + (0xe<<lg_sz) + off );
    m[0xf] = wwu_ldu( msg + (0xf<<lg_sz) + off );

    wwu_transpose_16x16( m[0x0], m[0x1], m[0x2], m[0x3], m[0x4], m[0x5], m[0x6], m[0x7],
                         m[0x8], m[0x9], m[0xa], m[0xb], m[0xc], m[0xd], m[0xe], m[0xf],
                         m[0x0], m[0x1], m[0x2], m[0x3], m[0x4], m[0x5], m[0x6], m[0x7],
                         m[0x8], m[0x9], m[0xa], m[0xb], m[0xc], m[0xd], m[0xe], m[0xf] );

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
