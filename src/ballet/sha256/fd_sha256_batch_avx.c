#define FD_SHA256_BATCH_IMPL 1

#include "fd_sha256.h"
#include "../../util/simd/fd_avx.h"

FD_STATIC_ASSERT( FD_SHA256_BATCH_MAX==8UL, compat );

void
fd_sha256_private_batch_avx( ulong          batch_cnt,
                             void const *   _batch_data,
                             ulong const *  batch_sz,
                             void * const * _batch_hash ) {

  /* If the batch is too small, it's faster to run each part of the
     batch sequentially.  When we have SHA-NI instructions, the
     sequential implementation is faster, so we need a larger batch size
     to justify using the batched implementation. */

# if FD_HAS_SHANI
# define MIN_BATCH_CNT (6UL)
# else
# define MIN_BATCH_CNT (2UL)
# endif

  if( FD_UNLIKELY( batch_cnt<MIN_BATCH_CNT ) ) {
    void const * const * batch_data = (void const * const *)_batch_data;
    for( ulong batch_idx=0UL; batch_idx<batch_cnt; batch_idx++ )
      fd_sha256_hash( batch_data[ batch_idx ], batch_sz[ batch_idx ], _batch_hash[ batch_idx ] );
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

  ulong batch_tail_data[ FD_SHA256_BATCH_MAX ] __attribute__((aligned(32)));
  ulong batch_tail_rem [ FD_SHA256_BATCH_MAX ] __attribute__((aligned(32)));

  uchar scratch[ FD_SHA256_BATCH_MAX*2UL*FD_SHA256_PRIVATE_BUF_MAX ] __attribute__((aligned(128)));
  do {
    ulong scratch_free = (ulong)scratch;

    wv_t zero = wv_zero();

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

      wv_st( (ulong *) tail_data,     zero );
      wv_st( (ulong *)(tail_data+32), zero );
      wv_st( (ulong *)(tail_data+64), zero );
      wv_st( (ulong *)(tail_data+96), zero );

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
      while( rem>=32UL ) { wv_st( (ulong *)dst, wv_ldu( (ulong const *)src ) ); dst += 32UL; src += 32UL; rem -= 32UL; }
      while( rem>= 8UL ) { *(ulong  *)dst = FD_LOAD( ulong,  src );             dst +=  8UL; src +=  8UL; rem -=  8UL; }
      if   ( rem>= 4UL ) { *(uint   *)dst = FD_LOAD( uint,   src );             dst +=  4UL; src +=  4UL; rem -=  4UL; }
      if   ( rem>= 2UL ) { *(ushort *)dst = FD_LOAD( ushort, src );             dst +=  2UL; src +=  2UL; rem -=  2UL; }
      if   ( rem       ) { *(uchar  *)dst = FD_LOAD( uchar,  src );             dst++;                                 }
      *(uchar *)dst = (uchar)0x80;
#     else
      fd_memcpy( (void *)tail_data, (void const *)(data + tail_data_off), tail_data_sz );
      *((uchar *)(tail_data+tail_data_sz)) = (uchar)0x80;
#     endif

      *((ulong *)(tail_data+tail_sz-8UL )) = fd_ulong_bswap( sz<<3 );
    }
  } while(0);

  wu_t s0 = wu_bcast( 0x6a09e667U );
  wu_t s1 = wu_bcast( 0xbb67ae85U );
  wu_t s2 = wu_bcast( 0x3c6ef372U );
  wu_t s3 = wu_bcast( 0xa54ff53aU );
  wu_t s4 = wu_bcast( 0x510e527fU );
  wu_t s5 = wu_bcast( 0x9b05688cU );
  wu_t s6 = wu_bcast( 0x1f83d9abU );
  wu_t s7 = wu_bcast( 0x5be0cd19U );

  wv_t wv_64        = wv_bcast( FD_SHA256_PRIVATE_BUF_MAX );
  wv_t W_sentinel   = wv_bcast( (ulong)scratch );
  wc_t batch_lane   = wc_unpack( (1<<batch_cnt)-1 );

  wv_t tail_lo      = wv_ld( batch_tail_data   );
  wv_t tail_hi      = wv_ld( batch_tail_data+4 );

  wv_t tail_rem_lo  = wv_ld( batch_tail_rem    );
  wv_t tail_rem_hi  = wv_ld( batch_tail_rem+4  );

  wv_t W_lo         = wv_ld( batch_data        );
  wv_t W_hi         = wv_ld( batch_data+4      );

  wv_t block_rem_lo = wv_notczero( wc_expand( batch_lane, 0 ),
                        wv_add( wv_shr( wv_ld( batch_sz   ), FD_SHA256_PRIVATE_LG_BUF_MAX ), tail_rem_lo ) );
  wv_t block_rem_hi = wv_notczero( wc_expand( batch_lane, 1 ),
                        wv_add( wv_shr( wv_ld( batch_sz+4 ), FD_SHA256_PRIVATE_LG_BUF_MAX ), tail_rem_hi ) );
  for(;;) {
    wc_t active_lane_lo = wv_to_wc( block_rem_lo );
    wc_t active_lane_hi = wv_to_wc( block_rem_hi );
    if( FD_UNLIKELY( !wc_any( wc_or( active_lane_lo, active_lane_hi ) ) ) ) break;

    /* Switch lanes that have hit the end of their in-place bulk
       processing to their out-of-place scratch tail regions as
       necessary. */

    W_lo = wv_if( wv_eq( block_rem_lo, tail_rem_lo ), tail_lo, W_lo );
    W_hi = wv_if( wv_eq( block_rem_hi, tail_rem_hi ), tail_hi, W_hi );

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

    wu_t x0; wu_t x1; wu_t x2; wu_t x3; wu_t x4; wu_t x5; wu_t x6; wu_t x7;
    wu_transpose_8x8( wu_bswap( wu_ldu(W0   ) ), wu_bswap( wu_ldu(W1   ) ), wu_bswap( wu_ldu(W2   ) ), wu_bswap( wu_ldu(W3   ) ),
                      wu_bswap( wu_ldu(W4   ) ), wu_bswap( wu_ldu(W5   ) ), wu_bswap( wu_ldu(W6   ) ), wu_bswap( wu_ldu(W7   ) ),
                      x0, x1, x2, x3, x4, x5, x6, x7 );

    wu_t x8; wu_t x9; wu_t xa; wu_t xb; wu_t xc; wu_t xd; wu_t xe; wu_t xf;
    wu_transpose_8x8( wu_bswap( wu_ldu(W0+32) ), wu_bswap( wu_ldu(W1+32) ), wu_bswap( wu_ldu(W2+32) ), wu_bswap( wu_ldu(W3+32) ),
                      wu_bswap( wu_ldu(W4+32) ), wu_bswap( wu_ldu(W5+32) ), wu_bswap( wu_ldu(W6+32) ), wu_bswap( wu_ldu(W7+32) ),
                      x8, x9, xa, xb, xc, xd, xe, xf );

    /* Compute the SHA-256 state updates */

    wu_t a = s0; wu_t b = s1; wu_t c = s2; wu_t d = s3; wu_t e = s4; wu_t f = s5; wu_t g = s6; wu_t h = s7;

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

#   define Sigma0(x)  wu_xor( wu_rol(x,30), wu_xor( wu_rol(x,19), wu_rol(x,10) ) )
#   define Sigma1(x)  wu_xor( wu_rol(x,26), wu_xor( wu_rol(x,21), wu_rol(x, 7) ) )
#   define sigma0(x)  wu_xor( wu_rol(x,25), wu_xor( wu_rol(x,14), wu_shr(x, 3) ) )
#   define sigma1(x)  wu_xor( wu_rol(x,15), wu_xor( wu_rol(x,13), wu_shr(x,10) ) )
#   define Ch(x,y,z)  wu_xor( wu_and(x,y), wu_andnot(x,z) )
#   define Maj(x,y,z) wu_xor( wu_and(x,y), wu_xor( wu_and(x,z), wu_and(y,z) ) )
#   define SHA_CORE(xi,ki)                                                       \
    T1 = wu_add( wu_add(xi,ki), wu_add( wu_add( h, Sigma1(e) ), Ch(e, f, g) ) ); \
    T2 = wu_add( Sigma0(a), Maj(a, b, c) );                                      \
    h = g;                                                                       \
    g = f;                                                                       \
    f = e;                                                                       \
    e = wu_add( d, T1 );                                                         \
    d = c;                                                                       \
    c = b;                                                                       \
    b = a;                                                                       \
    a = wu_add( T1, T2 )

    wu_t T1;
    wu_t T2;

    SHA_CORE( x0, wu_bcast( K[ 0] ) );
    SHA_CORE( x1, wu_bcast( K[ 1] ) );
    SHA_CORE( x2, wu_bcast( K[ 2] ) );
    SHA_CORE( x3, wu_bcast( K[ 3] ) );
    SHA_CORE( x4, wu_bcast( K[ 4] ) );
    SHA_CORE( x5, wu_bcast( K[ 5] ) );
    SHA_CORE( x6, wu_bcast( K[ 6] ) );
    SHA_CORE( x7, wu_bcast( K[ 7] ) );
    SHA_CORE( x8, wu_bcast( K[ 8] ) );
    SHA_CORE( x9, wu_bcast( K[ 9] ) );
    SHA_CORE( xa, wu_bcast( K[10] ) );
    SHA_CORE( xb, wu_bcast( K[11] ) );
    SHA_CORE( xc, wu_bcast( K[12] ) );
    SHA_CORE( xd, wu_bcast( K[13] ) );
    SHA_CORE( xe, wu_bcast( K[14] ) );
    SHA_CORE( xf, wu_bcast( K[15] ) );
    for( ulong i=16UL; i<64UL; i+=16UL ) {
      x0 = wu_add( wu_add( x0, sigma0(x1) ), wu_add( sigma1(xe), x9 ) ); SHA_CORE( x0, wu_bcast( K[i     ] ) );
      x1 = wu_add( wu_add( x1, sigma0(x2) ), wu_add( sigma1(xf), xa ) ); SHA_CORE( x1, wu_bcast( K[i+ 1UL] ) );
      x2 = wu_add( wu_add( x2, sigma0(x3) ), wu_add( sigma1(x0), xb ) ); SHA_CORE( x2, wu_bcast( K[i+ 2UL] ) );
      x3 = wu_add( wu_add( x3, sigma0(x4) ), wu_add( sigma1(x1), xc ) ); SHA_CORE( x3, wu_bcast( K[i+ 3UL] ) );
      x4 = wu_add( wu_add( x4, sigma0(x5) ), wu_add( sigma1(x2), xd ) ); SHA_CORE( x4, wu_bcast( K[i+ 4UL] ) );
      x5 = wu_add( wu_add( x5, sigma0(x6) ), wu_add( sigma1(x3), xe ) ); SHA_CORE( x5, wu_bcast( K[i+ 5UL] ) );
      x6 = wu_add( wu_add( x6, sigma0(x7) ), wu_add( sigma1(x4), xf ) ); SHA_CORE( x6, wu_bcast( K[i+ 6UL] ) );
      x7 = wu_add( wu_add( x7, sigma0(x8) ), wu_add( sigma1(x5), x0 ) ); SHA_CORE( x7, wu_bcast( K[i+ 7UL] ) );
      x8 = wu_add( wu_add( x8, sigma0(x9) ), wu_add( sigma1(x6), x1 ) ); SHA_CORE( x8, wu_bcast( K[i+ 8UL] ) );
      x9 = wu_add( wu_add( x9, sigma0(xa) ), wu_add( sigma1(x7), x2 ) ); SHA_CORE( x9, wu_bcast( K[i+ 9UL] ) );
      xa = wu_add( wu_add( xa, sigma0(xb) ), wu_add( sigma1(x8), x3 ) ); SHA_CORE( xa, wu_bcast( K[i+10UL] ) );
      xb = wu_add( wu_add( xb, sigma0(xc) ), wu_add( sigma1(x9), x4 ) ); SHA_CORE( xb, wu_bcast( K[i+11UL] ) );
      xc = wu_add( wu_add( xc, sigma0(xd) ), wu_add( sigma1(xa), x5 ) ); SHA_CORE( xc, wu_bcast( K[i+12UL] ) );
      xd = wu_add( wu_add( xd, sigma0(xe) ), wu_add( sigma1(xb), x6 ) ); SHA_CORE( xd, wu_bcast( K[i+13UL] ) );
      xe = wu_add( wu_add( xe, sigma0(xf) ), wu_add( sigma1(xc), x7 ) ); SHA_CORE( xe, wu_bcast( K[i+14UL] ) );
      xf = wu_add( wu_add( xf, sigma0(x0) ), wu_add( sigma1(xd), x8 ) ); SHA_CORE( xf, wu_bcast( K[i+15UL] ) );
    }

#   undef SHA_CORE
#   undef Sigma0
#   undef Sigma1
#   undef sigma0
#   undef sigma1
#   undef Ch
#   undef Maj

    /* Apply the state updates to the active lanes */

    wc_t active_lane = wc_narrow( active_lane_lo, active_lane_hi );
    s0 = wu_add( s0, wu_notczero( active_lane, a ) );
    s1 = wu_add( s1, wu_notczero( active_lane, b ) );
    s2 = wu_add( s2, wu_notczero( active_lane, c ) );
    s3 = wu_add( s3, wu_notczero( active_lane, d ) );
    s4 = wu_add( s4, wu_notczero( active_lane, e ) );
    s5 = wu_add( s5, wu_notczero( active_lane, f ) );
    s6 = wu_add( s6, wu_notczero( active_lane, g ) );
    s7 = wu_add( s7, wu_notczero( active_lane, h ) );

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

    block_rem_lo = wv_add( block_rem_lo, wc_to_wv_raw( active_lane_lo ) );
    block_rem_hi = wv_add( block_rem_hi, wc_to_wv_raw( active_lane_hi ) );
  }

  /* Store the results.  FIXME: Probably could optimize the transpose
     further by taking into account needed stores (and then maybe go
     direct into memory ... would need a family of such transposed
     stores). */

  wu_transpose_8x8( s0,s1,s2,s3,s4,s5,s6,s7, s0,s1,s2,s3,s4,s5,s6,s7 );

  uint * const * batch_hash = (uint * const *)_batch_hash;
  switch( batch_cnt ) { /* application dependent prob */
  case 8UL: wu_stu( batch_hash[7], wu_bswap( s7 ) ); __attribute__((fallthrough));
  case 7UL: wu_stu( batch_hash[6], wu_bswap( s6 ) ); __attribute__((fallthrough));
  case 6UL: wu_stu( batch_hash[5], wu_bswap( s5 ) ); __attribute__((fallthrough));
  case 5UL: wu_stu( batch_hash[4], wu_bswap( s4 ) ); __attribute__((fallthrough));
  case 4UL: wu_stu( batch_hash[3], wu_bswap( s3 ) ); __attribute__((fallthrough));
  case 3UL: wu_stu( batch_hash[2], wu_bswap( s2 ) ); __attribute__((fallthrough));
  case 2UL: wu_stu( batch_hash[1], wu_bswap( s1 ) ); __attribute__((fallthrough));
  case 1UL: wu_stu( batch_hash[0], wu_bswap( s0 ) ); __attribute__((fallthrough));
  default: break;
  }
}
