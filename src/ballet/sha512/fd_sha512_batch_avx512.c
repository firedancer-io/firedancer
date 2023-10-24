#define FD_SHA512_BATCH_IMPL 2

#include "fd_sha512.h"
#include "../../util/simd/fd_avx512.h"

FD_STATIC_ASSERT( FD_SHA512_BATCH_MAX==8UL, compat );

void
fd_sha512_private_batch_avx( ulong          batch_cnt,
                             void const *   batch_data,
                             ulong const *  batch_sz,
                             void * const * batch_hash );

void
fd_sha512_private_batch_avx512( ulong          batch_cnt,
                                void const *   _batch_data,
                                ulong const *  batch_sz,
                                void * const * _batch_hash ) {

  if( FD_UNLIKELY( batch_cnt<5UL ) ) {
    fd_sha512_private_batch_avx( batch_cnt, _batch_data, batch_sz, _batch_hash );
    return;
  }

  /* SHA appends to the end of each message 17 bytes of additional data
     (a messaging terminator byte and the big endian uint128 with the
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

  ulong batch_tail_data[ FD_SHA512_BATCH_MAX ] __attribute__((aligned(64)));
  ulong batch_tail_rem [ FD_SHA512_BATCH_MAX ] __attribute__((aligned(64)));

  uchar scratch[ FD_SHA512_BATCH_MAX*2UL*FD_SHA512_PRIVATE_BUF_MAX ] __attribute__((aligned(128)));
  do {
    ulong scratch_free = (ulong)scratch;

    wwv_t zero = wwv_zero();

    for( ulong batch_idx=0UL; batch_idx<batch_cnt; batch_idx++ ) {

      /* Allocate the tail blocks for this message */

      ulong data = batch_data[ batch_idx ];
      ulong sz   = batch_sz  [ batch_idx ];

      ulong tail_data     = scratch_free;
      ulong tail_data_sz  = sz & (FD_SHA512_PRIVATE_BUF_MAX-1UL);
      ulong tail_data_off = fd_ulong_align_dn( sz,                FD_SHA512_PRIVATE_BUF_MAX );
      ulong tail_sz       = fd_ulong_align_up( tail_data_sz+17UL, FD_SHA512_PRIVATE_BUF_MAX );

      batch_tail_data[ batch_idx ] = tail_data;
      batch_tail_rem [ batch_idx ] = tail_sz >> FD_SHA512_PRIVATE_LG_BUF_MAX;

      scratch_free += tail_sz;

      /* Populate the tail blocks.  We first clear the blocks (note that
         it is okay to clobber bytes 128:255 if tail_sz only 128, saving
         a nasty branch).  Then we copy any straggler data bytes into
         the tail, terminate the message, and finally record the size of
         the message in bits at the end as a big endian ulong.  */

      wwv_st( (ulong *) tail_data,        zero );
      wwv_st( (ulong *)(tail_data+ 64UL), zero );
      wwv_st( (ulong *)(tail_data+128UL), zero );
      wwv_st( (ulong *)(tail_data+192UL), zero );

#     if 1 /* See notes in fd_sha256_batch_avx.c for more details here */
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

      *((ulong *)(tail_data+tail_sz-16UL )) = fd_ulong_bswap( sz>>61 );
      *((ulong *)(tail_data+tail_sz- 8UL )) = fd_ulong_bswap( sz<< 3 );
    }
  } while(0);

  wwv_t s0 = wwv_bcast( 0x6a09e667f3bcc908UL );
  wwv_t s1 = wwv_bcast( 0xbb67ae8584caa73bUL );
  wwv_t s2 = wwv_bcast( 0x3c6ef372fe94f82bUL );
  wwv_t s3 = wwv_bcast( 0xa54ff53a5f1d36f1UL );
  wwv_t s4 = wwv_bcast( 0x510e527fade682d1UL );
  wwv_t s5 = wwv_bcast( 0x9b05688c2b3e6c1fUL );
  wwv_t s6 = wwv_bcast( 0x1f83d9abfb41bd6bUL );
  wwv_t s7 = wwv_bcast( 0x5be0cd19137e2179UL );

  wwv_t zero       = wwv_zero();
  wwv_t one        = wwv_one();
  wwv_t wwv_128    = wwv_bcast( FD_SHA512_PRIVATE_BUF_MAX );
  wwv_t W_sentinel = wwv_bcast( (ulong)scratch );

  wwv_t tail       = wwv_ld( batch_tail_data );
  wwv_t tail_rem   = wwv_ld( batch_tail_rem  );
  wwv_t W          = wwv_ld( batch_data      );
  wwv_t block_rem  = wwv_if( (1<<batch_cnt)-1,
                             wwv_add( wwv_shr( wwv_ld( batch_sz ), FD_SHA512_PRIVATE_LG_BUF_MAX ), tail_rem ), zero );
  for(;;) {
    int active_lane = wwv_ne( block_rem, zero );
    if( FD_UNLIKELY( !active_lane ) ) break;

    /* Switch lanes that have hit the end of their in-place bulk
       processing to their out-of-place scratch tail regions as
       necessary. */

    W = wwv_if( wwv_eq( block_rem, tail_rem ), tail, W );

    /* At this point, we have at least 1 block in this message segment
       pass that has not been processed.  Load the next 128 bytes of
       each unprocessed block.  Inactive lanes (e.g. message segments
       in this pass for which we've already processed all the blocks)
       will load garbage from a sentinel location (and the result of
       the state computations for the inactive lane will be ignored). */

    ulong _W0; ulong _W1; ulong _W2; ulong _W3; ulong _W4; ulong _W5; ulong _W6; ulong _W7;
    wwv_unpack( wwv_if( active_lane, W, W_sentinel ), _W0,_W1,_W2,_W3,_W4,_W5,_W6,_W7 );
    uchar const * W0 = (uchar const *)_W0; uchar const * W1 = (uchar const *)_W1;
    uchar const * W2 = (uchar const *)_W2; uchar const * W3 = (uchar const *)_W3;
    uchar const * W4 = (uchar const *)_W4; uchar const * W5 = (uchar const *)_W5;
    uchar const * W6 = (uchar const *)_W6; uchar const * W7 = (uchar const *)_W7;

    wwv_t x0; wwv_t x1; wwv_t x2; wwv_t x3; wwv_t x4; wwv_t x5; wwv_t x6; wwv_t x7;
    wwv_transpose_8x8( wwv_bswap( wwv_ldu( W0   ) ), wwv_bswap( wwv_ldu( W1   ) ),
                       wwv_bswap( wwv_ldu( W2   ) ), wwv_bswap( wwv_ldu( W3   ) ),
                       wwv_bswap( wwv_ldu( W4   ) ), wwv_bswap( wwv_ldu( W5   ) ),
                       wwv_bswap( wwv_ldu( W6   ) ), wwv_bswap( wwv_ldu( W7   ) ), x0, x1, x2, x3, x4, x5, x6, x7 );

    wwv_t x8; wwv_t x9; wwv_t xa; wwv_t xb; wwv_t xc; wwv_t xd; wwv_t xe; wwv_t xf;
    wwv_transpose_8x8( wwv_bswap( wwv_ldu( W0+64 ) ), wwv_bswap( wwv_ldu( W1+64 ) ),
                       wwv_bswap( wwv_ldu( W2+64 ) ), wwv_bswap( wwv_ldu( W3+64 ) ),
                       wwv_bswap( wwv_ldu( W4+64 ) ), wwv_bswap( wwv_ldu( W5+64 ) ),
                       wwv_bswap( wwv_ldu( W6+64 ) ), wwv_bswap( wwv_ldu( W7+64 ) ), x8, x9, xa, xb, xc, xd, xe, xf );

    /* Compute the SHA-512 state updates */

    wwv_t a = s0; wwv_t b = s1; wwv_t c = s2; wwv_t d = s3; wwv_t e = s4; wwv_t f = s5; wwv_t g = s6; wwv_t h = s7;

    static ulong const K[80] = { /* FIXME: Reuse with other functions */
      0x428a2f98d728ae22UL, 0x7137449123ef65cdUL, 0xb5c0fbcfec4d3b2fUL, 0xe9b5dba58189dbbcUL,
      0x3956c25bf348b538UL, 0x59f111f1b605d019UL, 0x923f82a4af194f9bUL, 0xab1c5ed5da6d8118UL,
      0xd807aa98a3030242UL, 0x12835b0145706fbeUL, 0x243185be4ee4b28cUL, 0x550c7dc3d5ffb4e2UL,
      0x72be5d74f27b896fUL, 0x80deb1fe3b1696b1UL, 0x9bdc06a725c71235UL, 0xc19bf174cf692694UL,
      0xe49b69c19ef14ad2UL, 0xefbe4786384f25e3UL, 0x0fc19dc68b8cd5b5UL, 0x240ca1cc77ac9c65UL,
      0x2de92c6f592b0275UL, 0x4a7484aa6ea6e483UL, 0x5cb0a9dcbd41fbd4UL, 0x76f988da831153b5UL,
      0x983e5152ee66dfabUL, 0xa831c66d2db43210UL, 0xb00327c898fb213fUL, 0xbf597fc7beef0ee4UL,
      0xc6e00bf33da88fc2UL, 0xd5a79147930aa725UL, 0x06ca6351e003826fUL, 0x142929670a0e6e70UL,
      0x27b70a8546d22ffcUL, 0x2e1b21385c26c926UL, 0x4d2c6dfc5ac42aedUL, 0x53380d139d95b3dfUL,
      0x650a73548baf63deUL, 0x766a0abb3c77b2a8UL, 0x81c2c92e47edaee6UL, 0x92722c851482353bUL,
      0xa2bfe8a14cf10364UL, 0xa81a664bbc423001UL, 0xc24b8b70d0f89791UL, 0xc76c51a30654be30UL,
      0xd192e819d6ef5218UL, 0xd69906245565a910UL, 0xf40e35855771202aUL, 0x106aa07032bbd1b8UL,
      0x19a4c116b8d2d0c8UL, 0x1e376c085141ab53UL, 0x2748774cdf8eeb99UL, 0x34b0bcb5e19b48a8UL,
      0x391c0cb3c5c95a63UL, 0x4ed8aa4ae3418acbUL, 0x5b9cca4f7763e373UL, 0x682e6ff3d6b2b8a3UL,
      0x748f82ee5defb2fcUL, 0x78a5636f43172f60UL, 0x84c87814a1f0ab72UL, 0x8cc702081a6439ecUL,
      0x90befffa23631e28UL, 0xa4506cebde82bde9UL, 0xbef9a3f7b2c67915UL, 0xc67178f2e372532bUL,
      0xca273eceea26619cUL, 0xd186b8c721c0c207UL, 0xeada7dd6cde0eb1eUL, 0xf57d4f7fee6ed178UL,
      0x06f067aa72176fbaUL, 0x0a637dc5a2c898a6UL, 0x113f9804bef90daeUL, 0x1b710b35131c471bUL,
      0x28db77f523047d84UL, 0x32caab7b40c72493UL, 0x3c9ebe0a15c9bebcUL, 0x431d67c49c100d4cUL,
      0x4cc5d4becb3e42b6UL, 0x597f299cfc657e2aUL, 0x5fcb6fab3ad6faecUL, 0x6c44198c4a475817UL
    };

#   define Sigma0(x)  wwv_xor( wwv_ror(x,28), wwv_xor( wwv_ror(x,34), wwv_ror(x,39) ) )
#   define Sigma1(x)  wwv_xor( wwv_ror(x,14), wwv_xor( wwv_ror(x,18), wwv_ror(x,41) ) )
#   define sigma0(x)  wwv_xor( wwv_ror(x, 1), wwv_xor( wwv_ror(x, 8), wwv_shr(x, 7) ) )
#   define sigma1(x)  wwv_xor( wwv_ror(x,19), wwv_xor( wwv_ror(x,61), wwv_shr(x, 6) ) )
#   define Ch(x,y,z)  wwv_xor( wwv_and(x,y), wwv_andnot(x,z) )
#   define Maj(x,y,z) wwv_xor( wwv_and(x,y), wwv_xor( wwv_and(x,z), wwv_and(y,z) ) )
#   define SHA_CORE(xi,ki)                                                           \
    T1 = wwv_add( wwv_add(xi,ki), wwv_add( wwv_add( h, Sigma1(e) ), Ch(e, f, g) ) ); \
    T2 = wwv_add( Sigma0(a), Maj(a, b, c) );                                         \
    h = g;                                                                           \
    g = f;                                                                           \
    f = e;                                                                           \
    e = wwv_add( d, T1 );                                                            \
    d = c;                                                                           \
    c = b;                                                                           \
    b = a;                                                                           \
    a = wwv_add( T1, T2 )

    wwv_t T1;
    wwv_t T2;

    SHA_CORE( x0, wwv_bcast( K[ 0] ) );
    SHA_CORE( x1, wwv_bcast( K[ 1] ) );
    SHA_CORE( x2, wwv_bcast( K[ 2] ) );
    SHA_CORE( x3, wwv_bcast( K[ 3] ) );
    SHA_CORE( x4, wwv_bcast( K[ 4] ) );
    SHA_CORE( x5, wwv_bcast( K[ 5] ) );
    SHA_CORE( x6, wwv_bcast( K[ 6] ) );
    SHA_CORE( x7, wwv_bcast( K[ 7] ) );
    SHA_CORE( x8, wwv_bcast( K[ 8] ) );
    SHA_CORE( x9, wwv_bcast( K[ 9] ) );
    SHA_CORE( xa, wwv_bcast( K[10] ) );
    SHA_CORE( xb, wwv_bcast( K[11] ) );
    SHA_CORE( xc, wwv_bcast( K[12] ) );
    SHA_CORE( xd, wwv_bcast( K[13] ) );
    SHA_CORE( xe, wwv_bcast( K[14] ) );
    SHA_CORE( xf, wwv_bcast( K[15] ) );
    for( ulong i=16UL; i<80UL; i+=16UL ) {
      x0 = wwv_add( wwv_add( x0, sigma0(x1) ), wwv_add( sigma1(xe), x9 ) ); SHA_CORE( x0, wwv_bcast( K[i     ] ) );
      x1 = wwv_add( wwv_add( x1, sigma0(x2) ), wwv_add( sigma1(xf), xa ) ); SHA_CORE( x1, wwv_bcast( K[i+ 1UL] ) );
      x2 = wwv_add( wwv_add( x2, sigma0(x3) ), wwv_add( sigma1(x0), xb ) ); SHA_CORE( x2, wwv_bcast( K[i+ 2UL] ) );
      x3 = wwv_add( wwv_add( x3, sigma0(x4) ), wwv_add( sigma1(x1), xc ) ); SHA_CORE( x3, wwv_bcast( K[i+ 3UL] ) );
      x4 = wwv_add( wwv_add( x4, sigma0(x5) ), wwv_add( sigma1(x2), xd ) ); SHA_CORE( x4, wwv_bcast( K[i+ 4UL] ) );
      x5 = wwv_add( wwv_add( x5, sigma0(x6) ), wwv_add( sigma1(x3), xe ) ); SHA_CORE( x5, wwv_bcast( K[i+ 5UL] ) );
      x6 = wwv_add( wwv_add( x6, sigma0(x7) ), wwv_add( sigma1(x4), xf ) ); SHA_CORE( x6, wwv_bcast( K[i+ 6UL] ) );
      x7 = wwv_add( wwv_add( x7, sigma0(x8) ), wwv_add( sigma1(x5), x0 ) ); SHA_CORE( x7, wwv_bcast( K[i+ 7UL] ) );
      x8 = wwv_add( wwv_add( x8, sigma0(x9) ), wwv_add( sigma1(x6), x1 ) ); SHA_CORE( x8, wwv_bcast( K[i+ 8UL] ) );
      x9 = wwv_add( wwv_add( x9, sigma0(xa) ), wwv_add( sigma1(x7), x2 ) ); SHA_CORE( x9, wwv_bcast( K[i+ 9UL] ) );
      xa = wwv_add( wwv_add( xa, sigma0(xb) ), wwv_add( sigma1(x8), x3 ) ); SHA_CORE( xa, wwv_bcast( K[i+10UL] ) );
      xb = wwv_add( wwv_add( xb, sigma0(xc) ), wwv_add( sigma1(x9), x4 ) ); SHA_CORE( xb, wwv_bcast( K[i+11UL] ) );
      xc = wwv_add( wwv_add( xc, sigma0(xd) ), wwv_add( sigma1(xa), x5 ) ); SHA_CORE( xc, wwv_bcast( K[i+12UL] ) );
      xd = wwv_add( wwv_add( xd, sigma0(xe) ), wwv_add( sigma1(xb), x6 ) ); SHA_CORE( xd, wwv_bcast( K[i+13UL] ) );
      xe = wwv_add( wwv_add( xe, sigma0(xf) ), wwv_add( sigma1(xc), x7 ) ); SHA_CORE( xe, wwv_bcast( K[i+14UL] ) );
      xf = wwv_add( wwv_add( xf, sigma0(x0) ), wwv_add( sigma1(xd), x8 ) ); SHA_CORE( xf, wwv_bcast( K[i+15UL] ) );
    }

    /* Apply the state updates to the active lanes */

    s0 = wwv_add_if( active_lane, s0, a, s0 );
    s1 = wwv_add_if( active_lane, s1, b, s1 );
    s2 = wwv_add_if( active_lane, s2, c, s2 );
    s3 = wwv_add_if( active_lane, s3, d, s3 );
    s4 = wwv_add_if( active_lane, s4, e, s4 );
    s5 = wwv_add_if( active_lane, s5, f, s5 );
    s6 = wwv_add_if( active_lane, s6, g, s6 );
    s7 = wwv_add_if( active_lane, s7, h, s7 );

    /* Advance to the next message segment blocks.  In pseudo code,
       the below is:

         W += 128; if( block_rem ) block_rem--;

       Since we do not load anything at W(lane) above unless
       block_rem(lane) is non-zero, we can omit vector conditional
       operations for W(lane) below. */

    W = wwv_add( W, wwv_128 );
    block_rem = wwv_sub_if( active_lane, block_rem, one, block_rem );

#   undef SHA_CORE
#   undef Sigma0
#   undef Sigma1
#   undef sigma0
#   undef sigma1
#   undef Ch
#   undef Maj

  }

  wwv_transpose_8x8( s0,s1,s2,s3,s4,s5,s6,s7, s0,s1,s2,s3,s4,s5,s6,s7 );

  ulong * const * batch_hash = (ulong * const *)_batch_hash;
  switch( batch_cnt ) { /* application dependent prob */
  case 8UL: wwv_stu( batch_hash[7], wwv_bswap( s7 ) ); __attribute__((fallthrough));
  case 7UL: wwv_stu( batch_hash[6], wwv_bswap( s6 ) ); __attribute__((fallthrough));
  case 6UL: wwv_stu( batch_hash[5], wwv_bswap( s5 ) ); __attribute__((fallthrough));
  case 5UL: wwv_stu( batch_hash[4], wwv_bswap( s4 ) ); __attribute__((fallthrough));
  case 4UL: wwv_stu( batch_hash[3], wwv_bswap( s3 ) ); __attribute__((fallthrough));
  case 3UL: wwv_stu( batch_hash[2], wwv_bswap( s2 ) ); __attribute__((fallthrough));
  case 2UL: wwv_stu( batch_hash[1], wwv_bswap( s1 ) ); __attribute__((fallthrough));
  case 1UL: wwv_stu( batch_hash[0], wwv_bswap( s0 ) ); __attribute__((fallthrough));
  default: break;
  }
}
