#define FD_SHA256_BATCH_IMPL 2

#include "fd_sha256.h"
#include "../../util/simd/fd_avx512.h"
#include "../../util/simd/fd_avx.h"

FD_STATIC_ASSERT( FD_SHA256_BATCH_MAX==16UL, compat );

void
fd_sha256_private_batch_avx( ulong          batch_cnt,
                             void const *   batch_data,
                             ulong const *  batch_sz,
                             void * const * batch_hash );

void
fd_sha256_private_batch_avx512( ulong          batch_cnt,
                                void const *   _batch_data,
                                ulong const *  batch_sz,
                                void * const * _batch_hash ) {

  /* If the batch is small enough, it is more efficient to use the
     narrow batched implementations.  The threshold for fallback depends
     on whether that itself narrower batched implementation is using
     SHA-NI acceleration for really small batches. */

# if FD_HAS_SHANI
# define MIN_BATCH_CNT (5UL)
# else
# define MIN_BATCH_CNT (2UL)
# endif

  if( FD_UNLIKELY( batch_cnt<MIN_BATCH_CNT ) ) {
    fd_sha256_private_batch_avx( batch_cnt, _batch_data, batch_sz, _batch_hash );
    return;
  }

# undef MIN_BATCH_CNT

  /* SHA appends to the end of each message 9 bytes of additional data
     (a messaging terminator byte and the big endian ulong with the
     message size in bits) and enough zero padding to make the message
     an integer number of blocks long.  We compute the 1 or 2 tail
     blocks of each message here.  We then process complete blocks of
     the original messages in place, switching to processing these tail
     blocks in the same pass toward the end.  TODO: This code could
     probably be SIMD optimized slightly more (this is where all the
     really performance suboptimally designed parts of SHA live so it is
     just inherently gross).  The main optimization would probably be to
     allow tail reading to use a faster memcpy and then maybe some
     vectorization of the bswap. */

  ulong const * batch_data = (ulong const *)_batch_data;

  ulong batch_tail_data[ FD_SHA256_BATCH_MAX ] __attribute__((aligned(64)));
  ulong batch_tail_rem [ FD_SHA256_BATCH_MAX ] __attribute__((aligned(64)));

  uchar scratch[ FD_SHA256_BATCH_MAX*2UL*FD_SHA256_PRIVATE_BUF_MAX ] __attribute__((aligned(128)));
  do {
    ulong scratch_free = (ulong)scratch;

    wwv_t zero = wwv_zero();

    for( ulong batch_idx=0UL; batch_idx<batch_cnt; batch_idx++ ) {

      /* Allocate the tail blocks for this message */

      ulong data = batch_data[ batch_idx ];
      ulong sz   = batch_sz  [ batch_idx ];

      ulong tail_data     = scratch_free;
      ulong tail_data_sz  = sz & (FD_SHA256_PRIVATE_BUF_MAX-1UL);
      ulong tail_data_off = fd_ulong_align_dn( sz,               FD_SHA256_PRIVATE_BUF_MAX );
      ulong tail_sz       = fd_ulong_align_up( tail_data_sz+9UL, FD_SHA256_PRIVATE_BUF_MAX );

      batch_tail_data[ batch_idx ] = tail_data;
      batch_tail_rem [ batch_idx ] = tail_sz >> FD_SHA256_PRIVATE_LG_BUF_MAX;

      scratch_free += tail_sz;

      /* Populate the tail blocks.  We first clear the blocks (note that
         it is okay to clobber bytes 64:127 if tail_sz only 64, saving a
         nasty branch).  Then we copy any straggler data bytes into the
         tail, terminate the message, and finally record the size of the
         message in bits at the end as a big endian ulong.  */

      wwv_st( (ulong *) tail_data,     zero );
      wwv_st( (ulong *)(tail_data+64), zero );

#     if 1
      /* Quick experiments found that, once again, straight memcpy is
         much slower than a fd_memcpy is slightly slower than a
         site-optimized handrolled memcpy (fd_memcpy would be less L1I
         cache footprint though).  They also found that doing the below
         in a branchless way is slightly worse and an ILP optimized
         version of the conditional calculation is about the same.  They
         also found that vectorizing the overall loop and/or Duffing the
         vectorized loop did not provide noticeable performance
         improvements under various styles of memcpy. */
      ulong src = data + tail_data_off;
      ulong dst = tail_data;
      ulong rem = tail_data_sz;
      while( rem>=64UL ) { wwv_st( (ulong *)dst, wwv_ldu( (ulong const *)src ) ); dst += 64UL; src += 64UL; rem -= 64UL; }
      while( rem>= 8UL ) { *(ulong  *)dst = FD_LOAD( ulong,  src );               dst +=  8UL; src +=  8UL; rem -=  8UL; }
      if   ( rem>= 4UL ) { *(uint   *)dst = FD_LOAD( uint,   src );               dst +=  4UL; src +=  4UL; rem -=  4UL; }
      if   ( rem>= 2UL ) { *(ushort *)dst = FD_LOAD( ushort, src );               dst +=  2UL; src +=  2UL; rem -=  2UL; }
      if   ( rem       ) { *(uchar  *)dst = FD_LOAD( uchar,  src );               dst++;                                 }
      *(uchar *)dst = (uchar)0x80;
#     else
      fd_memcpy( (void *)tail_data, (void const *)(data + tail_data_off), tail_data_sz );
      *((uchar *)(tail_data+tail_data_sz)) = (uchar)0x80;
#     endif

      *((ulong *)(tail_data+tail_sz-8UL )) = fd_ulong_bswap( sz<<3 );
    }
  } while(0);

  wwu_t s0 = wwu_bcast( 0x6a09e667U );
  wwu_t s1 = wwu_bcast( 0xbb67ae85U );
  wwu_t s2 = wwu_bcast( 0x3c6ef372U );
  wwu_t s3 = wwu_bcast( 0xa54ff53aU );
  wwu_t s4 = wwu_bcast( 0x510e527fU );
  wwu_t s5 = wwu_bcast( 0x9b05688cU );
  wwu_t s6 = wwu_bcast( 0x1f83d9abU );
  wwu_t s7 = wwu_bcast( 0x5be0cd19U );

  wwv_t zero       = wwv_zero();
  wwv_t one        = wwv_one();
  wwv_t wwv_64     = wwv_bcast( FD_SHA256_PRIVATE_BUF_MAX );
  wwv_t W_sentinel = wwv_bcast( (ulong)scratch );

  wwv_t tail_lo      = wwv_ld( batch_tail_data   ); wwv_t tail_hi      = wwv_ld( batch_tail_data+8 );
  wwv_t tail_rem_lo  = wwv_ld( batch_tail_rem    ); wwv_t tail_rem_hi  = wwv_ld( batch_tail_rem +8 );
  wwv_t W_lo         = wwv_ld( batch_data        ); wwv_t W_hi         = wwv_ld( batch_data     +8 );

  wwv_t block_rem_lo = wwv_if( ((1<<batch_cnt)-1) & 0xff,
                               wwv_add( wwv_shr( wwv_ld( batch_sz   ), FD_SHA256_PRIVATE_LG_BUF_MAX ), tail_rem_lo ), zero );
  wwv_t block_rem_hi = wwv_if( ((1<<batch_cnt)-1) >> 8,
                               wwv_add( wwv_shr( wwv_ld( batch_sz+8 ), FD_SHA256_PRIVATE_LG_BUF_MAX ), tail_rem_hi ), zero );

  for(;;) {
    int active_lane_lo = wwv_ne( block_rem_lo, zero );
    int active_lane_hi = wwv_ne( block_rem_hi, zero );
    if( FD_UNLIKELY( !(active_lane_lo | active_lane_hi) ) ) break;

    /* Switch lanes that have hit the end of their in-place bulk
       processing to their out-of-place scratch tail regions as
       necessary. */

    W_lo = wwv_if( wwv_eq( block_rem_lo, tail_rem_lo ), tail_lo, W_lo );
    W_hi = wwv_if( wwv_eq( block_rem_hi, tail_rem_hi ), tail_hi, W_hi );

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

    wwu_t x0; wwu_t x1; wwu_t x2; wwu_t x3; wwu_t x4; wwu_t x5; wwu_t x6; wwu_t x7;
    wwu_t x8; wwu_t x9; wwu_t xa; wwu_t xb; wwu_t xc; wwu_t xd; wwu_t xe; wwu_t xf;
    wwu_transpose_16x16( wwu_bswap( wwu_ldu( W0 ) ), wwu_bswap( wwu_ldu( W1 ) ),
                         wwu_bswap( wwu_ldu( W2 ) ), wwu_bswap( wwu_ldu( W3 ) ),
                         wwu_bswap( wwu_ldu( W4 ) ), wwu_bswap( wwu_ldu( W5 ) ),
                         wwu_bswap( wwu_ldu( W6 ) ), wwu_bswap( wwu_ldu( W7 ) ),
                         wwu_bswap( wwu_ldu( W8 ) ), wwu_bswap( wwu_ldu( W9 ) ),
                         wwu_bswap( wwu_ldu( Wa ) ), wwu_bswap( wwu_ldu( Wb ) ),
                         wwu_bswap( wwu_ldu( Wc ) ), wwu_bswap( wwu_ldu( Wd ) ),
                         wwu_bswap( wwu_ldu( We ) ), wwu_bswap( wwu_ldu( Wf ) ),
                         x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, xa, xb, xc, xd, xe, xf );

    /* Compute the SHA-256 state updates */

    wwu_t a = s0; wwu_t b = s1; wwu_t c = s2; wwu_t d = s3; wwu_t e = s4; wwu_t f = s5; wwu_t g = s6; wwu_t h = s7;

    static uint const K[64] = { /* FIXME: Reuse with other functions */
      0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
      0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U, 0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
      0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU, 0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
      0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U, 0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
      0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U, 0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
      0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U, 0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
      0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
      0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U, 0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U,
    };

#   define Sigma0(x)  wwu_xor( wwu_rol(x,30), wwu_xor( wwu_rol(x,19), wwu_rol(x,10) ) )
#   define Sigma1(x)  wwu_xor( wwu_rol(x,26), wwu_xor( wwu_rol(x,21), wwu_rol(x, 7) ) )
#   define sigma0(x)  wwu_xor( wwu_rol(x,25), wwu_xor( wwu_rol(x,14), wwu_shr(x, 3) ) )
#   define sigma1(x)  wwu_xor( wwu_rol(x,15), wwu_xor( wwu_rol(x,13), wwu_shr(x,10) ) )
#   define Ch(x,y,z)  wwu_xor( wwu_and(x,y), wwu_andnot(x,z) )
#   define Maj(x,y,z) wwu_xor( wwu_and(x,y), wwu_xor( wwu_and(x,z), wwu_and(y,z) ) )
#   define SHA_CORE(xi,ki)                                                           \
    T1 = wwu_add( wwu_add(xi,ki), wwu_add( wwu_add( h, Sigma1(e) ), Ch(e, f, g) ) ); \
    T2 = wwu_add( Sigma0(a), Maj(a, b, c) );                                         \
    h = g;                                                                           \
    g = f;                                                                           \
    f = e;                                                                           \
    e = wwu_add( d, T1 );                                                            \
    d = c;                                                                           \
    c = b;                                                                           \
    b = a;                                                                           \
    a = wwu_add( T1, T2 )

    wwu_t T1;
    wwu_t T2;

    SHA_CORE( x0, wwu_bcast( K[ 0] ) );
    SHA_CORE( x1, wwu_bcast( K[ 1] ) );
    SHA_CORE( x2, wwu_bcast( K[ 2] ) );
    SHA_CORE( x3, wwu_bcast( K[ 3] ) );
    SHA_CORE( x4, wwu_bcast( K[ 4] ) );
    SHA_CORE( x5, wwu_bcast( K[ 5] ) );
    SHA_CORE( x6, wwu_bcast( K[ 6] ) );
    SHA_CORE( x7, wwu_bcast( K[ 7] ) );
    SHA_CORE( x8, wwu_bcast( K[ 8] ) );
    SHA_CORE( x9, wwu_bcast( K[ 9] ) );
    SHA_CORE( xa, wwu_bcast( K[10] ) );
    SHA_CORE( xb, wwu_bcast( K[11] ) );
    SHA_CORE( xc, wwu_bcast( K[12] ) );
    SHA_CORE( xd, wwu_bcast( K[13] ) );
    SHA_CORE( xe, wwu_bcast( K[14] ) );
    SHA_CORE( xf, wwu_bcast( K[15] ) );
    for( ulong i=16UL; i<64UL; i+=16UL ) {
      x0 = wwu_add( wwu_add( x0, sigma0(x1) ), wwu_add( sigma1(xe), x9 ) ); SHA_CORE( x0, wwu_bcast( K[i     ] ) );
      x1 = wwu_add( wwu_add( x1, sigma0(x2) ), wwu_add( sigma1(xf), xa ) ); SHA_CORE( x1, wwu_bcast( K[i+ 1UL] ) );
      x2 = wwu_add( wwu_add( x2, sigma0(x3) ), wwu_add( sigma1(x0), xb ) ); SHA_CORE( x2, wwu_bcast( K[i+ 2UL] ) );
      x3 = wwu_add( wwu_add( x3, sigma0(x4) ), wwu_add( sigma1(x1), xc ) ); SHA_CORE( x3, wwu_bcast( K[i+ 3UL] ) );
      x4 = wwu_add( wwu_add( x4, sigma0(x5) ), wwu_add( sigma1(x2), xd ) ); SHA_CORE( x4, wwu_bcast( K[i+ 4UL] ) );
      x5 = wwu_add( wwu_add( x5, sigma0(x6) ), wwu_add( sigma1(x3), xe ) ); SHA_CORE( x5, wwu_bcast( K[i+ 5UL] ) );
      x6 = wwu_add( wwu_add( x6, sigma0(x7) ), wwu_add( sigma1(x4), xf ) ); SHA_CORE( x6, wwu_bcast( K[i+ 6UL] ) );
      x7 = wwu_add( wwu_add( x7, sigma0(x8) ), wwu_add( sigma1(x5), x0 ) ); SHA_CORE( x7, wwu_bcast( K[i+ 7UL] ) );
      x8 = wwu_add( wwu_add( x8, sigma0(x9) ), wwu_add( sigma1(x6), x1 ) ); SHA_CORE( x8, wwu_bcast( K[i+ 8UL] ) );
      x9 = wwu_add( wwu_add( x9, sigma0(xa) ), wwu_add( sigma1(x7), x2 ) ); SHA_CORE( x9, wwu_bcast( K[i+ 9UL] ) );
      xa = wwu_add( wwu_add( xa, sigma0(xb) ), wwu_add( sigma1(x8), x3 ) ); SHA_CORE( xa, wwu_bcast( K[i+10UL] ) );
      xb = wwu_add( wwu_add( xb, sigma0(xc) ), wwu_add( sigma1(x9), x4 ) ); SHA_CORE( xb, wwu_bcast( K[i+11UL] ) );
      xc = wwu_add( wwu_add( xc, sigma0(xd) ), wwu_add( sigma1(xa), x5 ) ); SHA_CORE( xc, wwu_bcast( K[i+12UL] ) );
      xd = wwu_add( wwu_add( xd, sigma0(xe) ), wwu_add( sigma1(xb), x6 ) ); SHA_CORE( xd, wwu_bcast( K[i+13UL] ) );
      xe = wwu_add( wwu_add( xe, sigma0(xf) ), wwu_add( sigma1(xc), x7 ) ); SHA_CORE( xe, wwu_bcast( K[i+14UL] ) );
      xf = wwu_add( wwu_add( xf, sigma0(x0) ), wwu_add( sigma1(xd), x8 ) ); SHA_CORE( xf, wwu_bcast( K[i+15UL] ) );
    }

#   undef SHA_CORE
#   undef Sigma0
#   undef Sigma1
#   undef sigma0
#   undef sigma1
#   undef Ch
#   undef Maj

    /* Apply the state updates to the active lanes */

    int active_lane = active_lane_lo | (active_lane_hi<<8);

    s0 = wwu_add_if( active_lane, s0, a, s0 );
    s1 = wwu_add_if( active_lane, s1, b, s1 );
    s2 = wwu_add_if( active_lane, s2, c, s2 );
    s3 = wwu_add_if( active_lane, s3, d, s3 );
    s4 = wwu_add_if( active_lane, s4, e, s4 );
    s5 = wwu_add_if( active_lane, s5, f, s5 );
    s6 = wwu_add_if( active_lane, s6, g, s6 );
    s7 = wwu_add_if( active_lane, s7, h, s7 );

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

  /* Store the results.  FIXME: Probably could optimize the transpose
     further by taking into account needed stores (and then maybe go
     direct into memory ... would need a family of such transposed
     stores). */

  wwu_transpose_2x8x8( wwu_bswap(s0), wwu_bswap(s1), wwu_bswap(s2), wwu_bswap(s3),
                       wwu_bswap(s4), wwu_bswap(s5), wwu_bswap(s6), wwu_bswap(s7), s0,s1,s2,s3,s4,s5,s6,s7 );

  uint * const * batch_hash = (uint * const *)_batch_hash;
  switch( batch_cnt ) { /* application dependent prob */
  case 16UL: wu_stu( batch_hash[15], _mm512_extracti32x8_epi32( s7, 1 ) ); __attribute__((fallthrough));
  case 15UL: wu_stu( batch_hash[14], _mm512_extracti32x8_epi32( s6, 1 ) ); __attribute__((fallthrough));
  case 14UL: wu_stu( batch_hash[13], _mm512_extracti32x8_epi32( s5, 1 ) ); __attribute__((fallthrough));
  case 13UL: wu_stu( batch_hash[12], _mm512_extracti32x8_epi32( s4, 1 ) ); __attribute__((fallthrough));
  case 12UL: wu_stu( batch_hash[11], _mm512_extracti32x8_epi32( s3, 1 ) ); __attribute__((fallthrough));
  case 11UL: wu_stu( batch_hash[10], _mm512_extracti32x8_epi32( s2, 1 ) ); __attribute__((fallthrough));
  case 10UL: wu_stu( batch_hash[ 9], _mm512_extracti32x8_epi32( s1, 1 ) ); __attribute__((fallthrough));
  case  9UL: wu_stu( batch_hash[ 8], _mm512_extracti32x8_epi32( s0, 1 ) ); __attribute__((fallthrough));
  case  8UL: wu_stu( batch_hash[ 7], _mm512_extracti32x8_epi32( s7, 0 ) ); __attribute__((fallthrough));
  case  7UL: wu_stu( batch_hash[ 6], _mm512_extracti32x8_epi32( s6, 0 ) ); __attribute__((fallthrough));
  case  6UL: wu_stu( batch_hash[ 5], _mm512_extracti32x8_epi32( s5, 0 ) ); __attribute__((fallthrough));
  case  5UL: wu_stu( batch_hash[ 4], _mm512_extracti32x8_epi32( s4, 0 ) ); __attribute__((fallthrough));
  case  4UL: wu_stu( batch_hash[ 3], _mm512_extracti32x8_epi32( s3, 0 ) ); __attribute__((fallthrough));
  case  3UL: wu_stu( batch_hash[ 2], _mm512_extracti32x8_epi32( s2, 0 ) ); __attribute__((fallthrough));
  case  2UL: wu_stu( batch_hash[ 1], _mm512_extracti32x8_epi32( s1, 0 ) ); __attribute__((fallthrough));
  case  1UL: wu_stu( batch_hash[ 0], _mm512_extracti32x8_epi32( s0, 0 ) ); __attribute__((fallthrough));
  default: break;
  }
}
