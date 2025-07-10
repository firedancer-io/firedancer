#include "fd_sha256.h"
#include "fd_sha256_constants.h"

#if FD_HAS_SHANI
/* For the optimized repeated hash */
#include "../../util/simd/fd_sse.h"
#endif

ulong
fd_sha256_align( void ) {
  return FD_SHA256_ALIGN;
}

ulong
fd_sha256_footprint( void ) {
  return FD_SHA256_FOOTPRINT;
}

void *
fd_sha256_new( void * shmem ) {
  fd_sha256_t * sha = (fd_sha256_t *)shmem;

  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_sha256_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  ulong footprint = fd_sha256_footprint();

  fd_memset( sha, 0, footprint );

  FD_COMPILER_MFENCE();
  FD_VOLATILE( sha->magic ) = FD_SHA256_MAGIC;
  FD_COMPILER_MFENCE();

  return (void *)sha;
}

fd_sha256_t *
fd_sha256_join( void * shsha ) {

  if( FD_UNLIKELY( !shsha ) ) {
    FD_LOG_WARNING(( "NULL shsha" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shsha, fd_sha256_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shsha" ));
    return NULL;
  }

  fd_sha256_t * sha = (fd_sha256_t *)shsha;

  if( FD_UNLIKELY( sha->magic!=FD_SHA256_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return sha;
}

void *
fd_sha256_leave( fd_sha256_t * sha ) {

  if( FD_UNLIKELY( !sha ) ) {
    FD_LOG_WARNING(( "NULL sha" ));
    return NULL;
  }

  return (void *)sha;
}

void *
fd_sha256_delete( void * shsha ) {

  if( FD_UNLIKELY( !shsha ) ) {
    FD_LOG_WARNING(( "NULL shsha" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shsha, fd_sha256_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shsha" ));
    return NULL;
  }

  fd_sha256_t * sha = (fd_sha256_t *)shsha;

  if( FD_UNLIKELY( sha->magic!=FD_SHA256_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  FD_COMPILER_MFENCE();
  FD_VOLATILE( sha->magic ) = 0UL;
  FD_COMPILER_MFENCE();

  return (void *)sha;
}

#ifndef FD_SHA256_CORE_IMPL
#if FD_HAS_SHANI
#define FD_SHA256_CORE_IMPL 1
#else
#define FD_SHA256_CORE_IMPL 0
#endif
#endif

#if FD_SHA256_CORE_IMPL==0

/* The implementation below was derived from OpenSSL's SHA-256
   implementation (Apache-2.0 licensed).  See in particular:

    https://github.com/openssl/openssl/blob/master/crypto/sha/sha256.c

   (link valid circa 2022-Dec).  It has been made more strict with more
   extensive implementation documentation, has been simplified and has
   been streamlined specifically for use inside Firedancer base machine
   model (no machine specific capabilities required).

   In particular, fd_sha256_core_ref is based on OpenSSL's
   OPENSSL_SMALL_FOOTPRINT SHA-256 implementation (Apache licensed).
   This should work anywhere but it is not the highest performance
   implementation possible.

   It is also straightforward to replace these implementations with HPC
   implementations that target specific machine capabilities without
   requiring any changes to caller code. */

static void
fd_sha256_core_ref( uint *        state,
                    uchar const * block,
                    ulong         block_cnt ) {


# define ROTATE     fd_uint_rotate_left
# define Sigma0(x)  (ROTATE((x),30) ^ ROTATE((x),19) ^ ROTATE((x),10))
# define Sigma1(x)  (ROTATE((x),26) ^ ROTATE((x),21) ^ ROTATE((x),7))
# define sigma0(x)  (ROTATE((x),25) ^ ROTATE((x),14) ^ ((x)>>3))
# define sigma1(x)  (ROTATE((x),15) ^ ROTATE((x),13) ^ ((x)>>10))
# define Ch(x,y,z)  (((x) & (y)) ^ ((~(x)) & (z)))
# define Maj(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

  uint const * W = (uint const *)block;
  do {
    uint a = state[0];
    uint b = state[1];
    uint c = state[2];
    uint d = state[3];
    uint e = state[4];
    uint f = state[5];
    uint g = state[6];
    uint h = state[7];

    uint X[16];

    ulong i;
    for( i=0UL; i<16UL; i++ ) {
      X[i] = fd_uint_bswap( W[i] );
      uint T1 = X[i] + h + Sigma1(e) + Ch(e, f, g) + fd_sha256_K[i];
      uint T2 = Sigma0(a) + Maj(a, b, c);
      h = g;
      g = f;
      f = e;
      e = d + T1;
      d = c;
      c = b;
      b = a;
      a = T1 + T2;
    }
    for( ; i<64UL; i++ ) {
      uint s0 = X[(i +  1UL) & 0x0fUL];
      uint s1 = X[(i + 14UL) & 0x0fUL];
      s0 = sigma0(s0);
      s1 = sigma1(s1);
      X[i & 0xfUL] += s0 + s1 + X[(i + 9UL) & 0xfUL];
      uint T1 = X[i & 0xfUL ] + h + Sigma1(e) + Ch(e, f, g) + fd_sha256_K[i];
      uint T2 = Sigma0(a) + Maj(a, b, c);
      h = g;
      g = f;
      f = e;
      e = d + T1;
      d = c;
      c = b;
      b = a;
      a = T1 + T2;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;

    W += 16UL;
  } while( --block_cnt );

# undef ROTATE
# undef Sigma0
# undef Sigma1
# undef sigma0
# undef sigma1
# undef Ch
# undef Maj

}

#define fd_sha256_core fd_sha256_core_ref

#elif FD_SHA256_CORE_IMPL==1

/* _mm_sha256rnds2_epu32 does two rounds, one from the first uint in
   wk and one from the second.  Since wk stores four rounds worth of
   message schedule values, it makes sense for the macro to do four
   rounds at a time.  We need to permute wk in between so that the
   second call to the intrinsic will use the other values. */
#define FOUR_ROUNDS( wk ) do {                                                               \
      vu_t __wk = (wk);                                                                      \
      vu_t temp_state = stateFEBA;                                                           \
      stateFEBA = _mm_sha256rnds2_epu32( stateHGDC, stateFEBA, __wk );                       \
      stateHGDC = temp_state;                                                                \
                                                                                             \
      temp_state = stateFEBA;                                                                \
      stateFEBA = _mm_sha256rnds2_epu32( stateHGDC, stateFEBA, vu_permute( __wk, 2,3,0,1 ) );\
      stateHGDC = temp_state;                                                                \
    } while( 0 )


/* For completeness, here's the documentation for _mm_sha256msg1_epu32
   and _mm_sha256msg2_epu32 in a slightly reformatted way, where all
   values are uints, and "-" indicates a don't-care value:

       _mm_sha256msg1_epu32( (w[j  ], w[j+1], w[j+1], w[j+3]),
                             (w[j+4], -,      -,      -     ) )
         = ( w[j  ]+s0( w[j+1] ),  w[j+1]+s0( w[j+2] ),
             w[j+2]+s0( w[j+3] ),  w[j+3]+s0( w[j+4] ) ).


       _mm_sha256msg2_epu32( (v[j  ], v[j+1], v[j+1], v[j+3]),
                             (-,      -,      w[j-2], w[j-1]) )
         sets w[j  ] = v[j  ] + s1( w[j-2] ) and
              w[j+1] = v[j+1] + s1( w[j-1] ), and then returns

           ( v[j  ]+s1( w[j-2] ), v[j+1]+s1( w[j-1] ),
             v[j+2]+s1( w[j  ] ), v[j+3]+s1( w[j+1] ) )   */


/* w[i] for i>= 16 is w[i-16] + s0(w[i-15]) + w[i-7] + s1(w[i-2])
   Since our vector size is 4 uints, it's only s1 that is a little
   problematic, because it references items in the same vector.
   Thankfully, the msg2 intrinsic takes care of the complexity, but we
   need to execute it last.

   We get w[i-16] and s0(s[i-15]) using the msg1 intrinsic, setting j =
   i-16.  For example, to compute w1013, we pass in w0003 and w0407.
   Then we can get w[i-7] by using the alignr instruction on
   (w[i-8], w[i-7], w[i-6], w[i-5]) and (w[i-4], w[i-3], w[i-2], w[i-1])
   to concatenate them and shift by one uint.  Continuing with the
   example of w1013, we need w080b and w0c0f.  We then put
             v[i] = w[i-16] + s0(w[i-15]) + w[i-7],
   and invoke the msg2 intrinsic with j=i, which gives w[i], as desired.
   Each invocation of NEXT_W computes 4 values of w. */

#define NEXT_W( w_minus_16, w_minus_12, w_minus_8, w_minus_4 ) (__extension__({      \
    vu_t __w_i_16_s0_i_15 = _mm_sha256msg1_epu32( w_minus_16, w_minus_12 );          \
    vu_t __w_i_7          = _mm_alignr_epi8( w_minus_4, w_minus_8, 4 );              \
    _mm_sha256msg2_epu32( vu_add( __w_i_7, __w_i_16_s0_i_15 ), w_minus_4 );          \
    }))

void
fd_sha256_core_shaext( uint *        state,       /* 64-byte aligned, 8 entries */
                       uchar const * block,       /* ideally 128-byte aligned (but not required), 64*block_cnt in size */
                       ulong         block_cnt ) {/* positive */
  vu_t stateABCD = vu_ld( state     );
  vu_t stateEFGH = vu_ld( state+4UL );

  vu_t baseFEBA = vu_permute2( stateEFGH, stateABCD, 1, 0, 1, 0 );
  vu_t baseHGDC = vu_permute2( stateEFGH, stateABCD, 3, 2, 3, 2 );

  for( ulong b=0UL; b<block_cnt; b++ ) {
    vu_t stateFEBA = baseFEBA;
    vu_t stateHGDC = baseHGDC;

    vu_t w0003 = vu_bswap( vu_ldu( block+64UL*b      ) );
    vu_t w0407 = vu_bswap( vu_ldu( block+64UL*b+16UL ) );
    vu_t w080b = vu_bswap( vu_ldu( block+64UL*b+32UL ) );
    vu_t w0c0f = vu_bswap( vu_ldu( block+64UL*b+48UL ) );

    /*                                              */ FOUR_ROUNDS( vu_add( w0003, vu_ld( fd_sha256_K+ 0UL ) ) );
    /*                                              */ FOUR_ROUNDS( vu_add( w0407, vu_ld( fd_sha256_K+ 4UL ) ) );
    /*                                              */ FOUR_ROUNDS( vu_add( w080b, vu_ld( fd_sha256_K+ 8UL ) ) );
    /*                                              */ FOUR_ROUNDS( vu_add( w0c0f, vu_ld( fd_sha256_K+12UL ) ) );
    vu_t w1013 = NEXT_W( w0003, w0407, w080b, w0c0f ); FOUR_ROUNDS( vu_add( w1013, vu_ld( fd_sha256_K+16UL ) ) );
    vu_t w1417 = NEXT_W( w0407, w080b, w0c0f, w1013 ); FOUR_ROUNDS( vu_add( w1417, vu_ld( fd_sha256_K+20UL ) ) );
    vu_t w181b = NEXT_W( w080b, w0c0f, w1013, w1417 ); FOUR_ROUNDS( vu_add( w181b, vu_ld( fd_sha256_K+24UL ) ) );
    vu_t w1c1f = NEXT_W( w0c0f, w1013, w1417, w181b ); FOUR_ROUNDS( vu_add( w1c1f, vu_ld( fd_sha256_K+28UL ) ) );
    vu_t w2023 = NEXT_W( w1013, w1417, w181b, w1c1f ); FOUR_ROUNDS( vu_add( w2023, vu_ld( fd_sha256_K+32UL ) ) );
    vu_t w2427 = NEXT_W( w1417, w181b, w1c1f, w2023 ); FOUR_ROUNDS( vu_add( w2427, vu_ld( fd_sha256_K+36UL ) ) );
    vu_t w282b = NEXT_W( w181b, w1c1f, w2023, w2427 ); FOUR_ROUNDS( vu_add( w282b, vu_ld( fd_sha256_K+40UL ) ) );
    vu_t w2c2f = NEXT_W( w1c1f, w2023, w2427, w282b ); FOUR_ROUNDS( vu_add( w2c2f, vu_ld( fd_sha256_K+44UL ) ) );
    vu_t w3033 = NEXT_W( w2023, w2427, w282b, w2c2f ); FOUR_ROUNDS( vu_add( w3033, vu_ld( fd_sha256_K+48UL ) ) );
    vu_t w3437 = NEXT_W( w2427, w282b, w2c2f, w3033 ); FOUR_ROUNDS( vu_add( w3437, vu_ld( fd_sha256_K+52UL ) ) );
    vu_t w383b = NEXT_W( w282b, w2c2f, w3033, w3437 ); FOUR_ROUNDS( vu_add( w383b, vu_ld( fd_sha256_K+56UL ) ) );
    vu_t w3c3f = NEXT_W( w2c2f, w3033, w3437, w383b ); FOUR_ROUNDS( vu_add( w3c3f, vu_ld( fd_sha256_K+60UL ) ) );

    baseFEBA = vu_add( baseFEBA, stateFEBA );
    baseHGDC = vu_add( baseHGDC, stateHGDC );

  }

  stateABCD = vu_permute2( baseFEBA, baseHGDC, 3, 2, 3, 2 );
  stateEFGH = vu_permute2( baseFEBA, baseHGDC, 1, 0, 1, 0 );
  vu_st( state,     stateABCD );
  vu_st( state+4UL, stateEFGH );
}

#define fd_sha256_core fd_sha256_core_shaext

#else
#error "Unsupported FD_SHA256_CORE_IMPL"
#endif

fd_sha256_t *
fd_sha256_init( fd_sha256_t * sha ) {
  sha->state[0] = FD_SHA256_INITIAL_A;
  sha->state[1] = FD_SHA256_INITIAL_B;
  sha->state[2] = FD_SHA256_INITIAL_C;
  sha->state[3] = FD_SHA256_INITIAL_D;
  sha->state[4] = FD_SHA256_INITIAL_E;
  sha->state[5] = FD_SHA256_INITIAL_F;
  sha->state[6] = FD_SHA256_INITIAL_G;
  sha->state[7] = FD_SHA256_INITIAL_H;
  sha->buf_used = 0UL;
  sha->bit_cnt  = 0UL;
  return sha;
}

fd_sha256_t *
fd_sha256_append( fd_sha256_t * sha,
                  void const *  _data,
                  ulong         sz ) {

  /* If no data to append, we are done */

  if( FD_UNLIKELY( !sz ) ) return sha; /* optimize for non-trivial append */

  /* Unpack inputs */

  uint *  state    = sha->state;
  uchar * buf      = sha->buf;
  ulong   buf_used = sha->buf_used;
  ulong   bit_cnt  = sha->bit_cnt;

  uchar const * data = (uchar const *)_data;

  /* Update bit_cnt */
  /* FIXME: could accumulate bytes here and do bit conversion in append */
  /* FIXME: Overflow handling if more than 2^64 bits (unlikely) */

  sha->bit_cnt = bit_cnt + (sz<<3);

  /* Handle buffered bytes from previous appends */

  if( FD_UNLIKELY( buf_used ) ) { /* optimized for well aligned use of append */

    /* If the append isn't large enough to complete the current block,
       buffer these bytes too and return */

    ulong buf_rem = FD_SHA256_PRIVATE_BUF_MAX - buf_used; /* In (0,FD_SHA256_PRIVATE_BUF_MAX) */
    if( FD_UNLIKELY( sz < buf_rem ) ) { /* optimize for large append */
      fd_memcpy( buf + buf_used, data, sz );
      sha->buf_used = buf_used + sz;
      return sha;
    }

    /* Otherwise, buffer enough leading bytes of data to complete the
       block, update the hash and then continue processing any remaining
       bytes of data. */

    fd_memcpy( buf + buf_used, data, buf_rem );
    data += buf_rem;
    sz   -= buf_rem;

    fd_sha256_core( state, buf, 1UL );
    sha->buf_used = 0UL;
  }

  /* Append the bulk of the data */

  ulong block_cnt = sz >> FD_SHA256_PRIVATE_LG_BUF_MAX;
  if( FD_LIKELY( block_cnt ) ) fd_sha256_core( state, data, block_cnt ); /* optimized for large append */

  /* Buffer any leftover bytes */

  buf_used = sz & (FD_SHA256_PRIVATE_BUF_MAX-1UL); /* In [0,FD_SHA256_PRIVATE_BUF_MAX) */
  if( FD_UNLIKELY( buf_used ) ) { /* optimized for well aligned use of append */
    fd_memcpy( buf, data + (block_cnt << FD_SHA256_PRIVATE_LG_BUF_MAX), buf_used );
    sha->buf_used = buf_used; /* In (0,FD_SHA256_PRIVATE_BUF_MAX) */
  }

  return sha;
}

void *
fd_sha256_fini( fd_sha256_t * sha,
                void *        _hash ) {

  /* Unpack inputs */

  uint *  state    = sha->state;
  uchar * buf      = sha->buf;
  ulong   buf_used = sha->buf_used; /* In [0,FD_SHA256_PRIVATE_BUF_MAX) */
  ulong   bit_cnt  = sha->bit_cnt;

  /* Append the terminating message byte */

  buf[ buf_used ] = (uchar)0x80;
  buf_used++;

  /* If there isn't enough room to save the message length in bits at
     the end of the in progress block, clear the rest of the in progress
     block, update the hash and start a new block. */

  if( FD_UNLIKELY( buf_used > (FD_SHA256_PRIVATE_BUF_MAX-8UL) ) ) { /* optimize for well aligned use of append */
    fd_memset( buf + buf_used, 0, FD_SHA256_PRIVATE_BUF_MAX-buf_used );
    fd_sha256_core( state, buf, 1UL );
    buf_used = 0UL;
  }

  /* Clear in progress block up to last 64-bits, append the message
     size in bytes in the last 64-bits of the in progress block and
     update the hash to finalize it. */

  fd_memset( buf + buf_used, 0, FD_SHA256_PRIVATE_BUF_MAX-8UL-buf_used );
  FD_STORE( ulong, buf+FD_SHA256_PRIVATE_BUF_MAX-8UL, fd_ulong_bswap( bit_cnt ) );
  fd_sha256_core( state, buf, 1UL );

  /* Unpack the result into md (annoying bswaps here) */

  state[0] = fd_uint_bswap( state[0] );
  state[1] = fd_uint_bswap( state[1] );
  state[2] = fd_uint_bswap( state[2] );
  state[3] = fd_uint_bswap( state[3] );
  state[4] = fd_uint_bswap( state[4] );
  state[5] = fd_uint_bswap( state[5] );
  state[6] = fd_uint_bswap( state[6] );
  state[7] = fd_uint_bswap( state[7] );
  return memcpy( _hash, state, 32 );
}

void *
fd_sha256_hash( void const * _data,
                ulong        sz,
                void *       _hash ) {
  uchar const * data = (uchar const *)_data;

  /* This is just the above streamlined to eliminate all the overheads
     to support incremental hashing. */

  uchar buf[ FD_SHA256_PRIVATE_BUF_MAX ] __attribute__((aligned(128)));
  uint  state[8] __attribute__((aligned(32)));

  state[0] = FD_SHA256_INITIAL_A;
  state[1] = FD_SHA256_INITIAL_B;
  state[2] = FD_SHA256_INITIAL_C;
  state[3] = FD_SHA256_INITIAL_D;
  state[4] = FD_SHA256_INITIAL_E;
  state[5] = FD_SHA256_INITIAL_F;
  state[6] = FD_SHA256_INITIAL_G;
  state[7] = FD_SHA256_INITIAL_H;

  ulong block_cnt = sz >> FD_SHA256_PRIVATE_LG_BUF_MAX;
  if( FD_LIKELY( block_cnt ) ) fd_sha256_core( state, data, block_cnt );

  ulong buf_used = sz & (FD_SHA256_PRIVATE_BUF_MAX-1UL);
  if( FD_UNLIKELY( buf_used ) ) fd_memcpy( buf, data + (block_cnt << FD_SHA256_PRIVATE_LG_BUF_MAX), buf_used );
  buf[ buf_used ] = (uchar)0x80;
  buf_used++;

  if( FD_UNLIKELY( buf_used > (FD_SHA256_PRIVATE_BUF_MAX-8UL) ) ) {
    fd_memset( buf + buf_used, 0, FD_SHA256_PRIVATE_BUF_MAX-buf_used );
    fd_sha256_core( state, buf, 1UL );
    buf_used = 0UL;
  }

  ulong bit_cnt = sz << 3;
  fd_memset( buf + buf_used, 0, FD_SHA256_PRIVATE_BUF_MAX-8UL-buf_used );
  FD_STORE( ulong, buf+FD_SHA256_PRIVATE_BUF_MAX-8UL, fd_ulong_bswap( bit_cnt ) );
  fd_sha256_core( state, buf, 1UL );

  state[0] = fd_uint_bswap( state[0] );
  state[1] = fd_uint_bswap( state[1] );
  state[2] = fd_uint_bswap( state[2] );
  state[3] = fd_uint_bswap( state[3] );
  state[4] = fd_uint_bswap( state[4] );
  state[5] = fd_uint_bswap( state[5] );
  state[6] = fd_uint_bswap( state[6] );
  state[7] = fd_uint_bswap( state[7] );
  return memcpy( _hash, state, 32 );
}



void *
fd_sha256_hash_32_repeated( void const * _data,
                            void *       _hash,
                            ulong        cnt ) {
  uchar const * data = (uchar const *)_data;
  uchar       * hash = (uchar       *)_hash;
#if FD_HAS_SHANI
  vu_t       w0003 = vu_bswap( vu_ldu( data      ) );
  vu_t       w0407 = vu_bswap( vu_ldu( data+16UL ) );
  vb_t const w080b = vb( 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00,
                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 );
  vb_t const w0c0f = vb( 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                         0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00 ); /* 32 bytes */

  vu_t const initialFEBA = vu( FD_SHA256_INITIAL_F, FD_SHA256_INITIAL_E, FD_SHA256_INITIAL_B, FD_SHA256_INITIAL_A );
  vu_t const initialHGDC = vu( FD_SHA256_INITIAL_H, FD_SHA256_INITIAL_G, FD_SHA256_INITIAL_D, FD_SHA256_INITIAL_C );

  for( ulong iter=0UL; iter<cnt; iter++ ) {
    vu_t stateFEBA = initialFEBA;
    vu_t stateHGDC = initialHGDC;



    /*                                              */ FOUR_ROUNDS( vu_add( w0003, vu_ld( fd_sha256_K+ 0UL ) ) );
    /*                                              */ FOUR_ROUNDS( vu_add( w0407, vu_ld( fd_sha256_K+ 4UL ) ) );
    /*                                              */ FOUR_ROUNDS( vu_add( w080b, vu_ld( fd_sha256_K+ 8UL ) ) );
    /*                                              */ FOUR_ROUNDS( vu_add( w0c0f, vu_ld( fd_sha256_K+12UL ) ) );
    vu_t w1013 = NEXT_W( w0003, w0407, w080b, w0c0f ); FOUR_ROUNDS( vu_add( w1013, vu_ld( fd_sha256_K+16UL ) ) );
    vu_t w1417 = NEXT_W( w0407, w080b, w0c0f, w1013 ); FOUR_ROUNDS( vu_add( w1417, vu_ld( fd_sha256_K+20UL ) ) );
    vu_t w181b = NEXT_W( w080b, w0c0f, w1013, w1417 ); FOUR_ROUNDS( vu_add( w181b, vu_ld( fd_sha256_K+24UL ) ) );
    vu_t w1c1f = NEXT_W( w0c0f, w1013, w1417, w181b ); FOUR_ROUNDS( vu_add( w1c1f, vu_ld( fd_sha256_K+28UL ) ) );
    vu_t w2023 = NEXT_W( w1013, w1417, w181b, w1c1f ); FOUR_ROUNDS( vu_add( w2023, vu_ld( fd_sha256_K+32UL ) ) );
    vu_t w2427 = NEXT_W( w1417, w181b, w1c1f, w2023 ); FOUR_ROUNDS( vu_add( w2427, vu_ld( fd_sha256_K+36UL ) ) );
    vu_t w282b = NEXT_W( w181b, w1c1f, w2023, w2427 ); FOUR_ROUNDS( vu_add( w282b, vu_ld( fd_sha256_K+40UL ) ) );
    vu_t w2c2f = NEXT_W( w1c1f, w2023, w2427, w282b ); FOUR_ROUNDS( vu_add( w2c2f, vu_ld( fd_sha256_K+44UL ) ) );
    vu_t w3033 = NEXT_W( w2023, w2427, w282b, w2c2f ); FOUR_ROUNDS( vu_add( w3033, vu_ld( fd_sha256_K+48UL ) ) );
    vu_t w3437 = NEXT_W( w2427, w282b, w2c2f, w3033 ); FOUR_ROUNDS( vu_add( w3437, vu_ld( fd_sha256_K+52UL ) ) );
    vu_t w383b = NEXT_W( w282b, w2c2f, w3033, w3437 ); FOUR_ROUNDS( vu_add( w383b, vu_ld( fd_sha256_K+56UL ) ) );
    vu_t w3c3f = NEXT_W( w2c2f, w3033, w3437, w383b ); FOUR_ROUNDS( vu_add( w3c3f, vu_ld( fd_sha256_K+60UL ) ) );

    stateFEBA = vu_add( stateFEBA, initialFEBA );
    stateHGDC = vu_add( stateHGDC, initialHGDC );

    vu_t stateABCD = vu_permute2( stateFEBA, stateHGDC, 3, 2, 3, 2 );
    vu_t stateEFGH = vu_permute2( stateFEBA, stateHGDC, 1, 0, 1, 0 );

    w0003 = stateABCD;
    w0407 = stateEFGH;
  }
  vu_stu( hash,      vu_bswap( w0003 ) );
  vu_stu( hash+16UL, vu_bswap( w0407 ) );
#undef FOUND_ROUNDS
#undef NEXT_W

#else

  uchar buf[ FD_SHA256_PRIVATE_BUF_MAX ] __attribute__((aligned(128)));

  /* Prepare padding once */
  ulong buf_used = 32UL;
  memcpy( buf, data, 32UL );
  buf[ buf_used ] = (uchar)0x80;
  buf_used++;

  ulong bit_cnt = 32UL << 3;
  memset( buf + buf_used, 0, FD_SHA256_PRIVATE_BUF_MAX-8UL-buf_used );
  FD_STORE( ulong, buf+FD_SHA256_PRIVATE_BUF_MAX-8UL, fd_ulong_bswap( bit_cnt ) );

  /* This is just the above streamlined to eliminate all the overheads
     to support incremental hashing. */
  for( ulong iter=0UL; iter<cnt; iter++ ) {

    uint  state[8] __attribute__((aligned(32)));

    state[0] = FD_SHA256_INITIAL_A;
    state[1] = FD_SHA256_INITIAL_B;
    state[2] = FD_SHA256_INITIAL_C;
    state[3] = FD_SHA256_INITIAL_D;
    state[4] = FD_SHA256_INITIAL_E;
    state[5] = FD_SHA256_INITIAL_F;
    state[6] = FD_SHA256_INITIAL_G;
    state[7] = FD_SHA256_INITIAL_H;

    fd_sha256_core( state, buf, 1UL );

    state[0] = fd_uint_bswap( state[0] );
    state[1] = fd_uint_bswap( state[1] );
    state[2] = fd_uint_bswap( state[2] );
    state[3] = fd_uint_bswap( state[3] );
    state[4] = fd_uint_bswap( state[4] );
    state[5] = fd_uint_bswap( state[5] );
    state[6] = fd_uint_bswap( state[6] );
    state[7] = fd_uint_bswap( state[7] );
    memcpy( buf, state, 32UL );
  }
  memcpy( hash, buf, 32UL );
#endif
  return _hash;
}

#undef fd_sha256_core
