#include "fd_sha512.h"

ulong
fd_sha512_align( void ) {
  return FD_SHA512_ALIGN;
}

ulong
fd_sha512_footprint( void ) {
  return FD_SHA512_FOOTPRINT;
}

void *
fd_sha512_new( void * shmem ) {
  fd_sha512_t * sha = (fd_sha512_t *)shmem;

  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_sha512_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  ulong footprint = fd_sha512_footprint();

  fd_memset( sha, 0, footprint );

  FD_COMPILER_MFENCE();
  FD_VOLATILE( sha->magic ) = FD_SHA512_MAGIC;
  FD_COMPILER_MFENCE();

  return (void *)sha;
}

fd_sha512_t *
fd_sha512_join( void * shsha ) {

  if( FD_UNLIKELY( !shsha ) ) {
    FD_LOG_WARNING(( "NULL shsha" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shsha, fd_sha512_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shsha" ));
    return NULL;
  }

  fd_sha512_t * sha = (fd_sha512_t *)shsha;

  if( FD_UNLIKELY( sha->magic!=FD_SHA512_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return sha;
}

void *
fd_sha512_leave( fd_sha512_t * sha ) {

  if( FD_UNLIKELY( !sha ) ) {
    FD_LOG_WARNING(( "NULL sha" ));
    return NULL;
  }

  return (void *)sha;
}

void *
fd_sha512_delete( void * shsha ) {

  if( FD_UNLIKELY( !shsha ) ) {
    FD_LOG_WARNING(( "NULL shsha" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shsha, fd_sha512_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shsha" ));
    return NULL;
  }

  fd_sha512_t * sha = (fd_sha512_t *)shsha;

  if( FD_UNLIKELY( sha->magic!=FD_SHA512_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  FD_COMPILER_MFENCE();
  FD_VOLATILE( sha->magic ) = 0UL;
  FD_COMPILER_MFENCE();

  return (void *)sha;
}

#ifndef FD_SHA512_CORE_IMPL
#if FD_HAS_AVX
#define FD_SHA512_CORE_IMPL 1
#else
#define FD_SHA512_CORE_IMPL 0
#endif
#endif

#if FD_SHA512_CORE_IMPL==0

/* The implementation below was derived from OpenSSL's sha512
   implementation (Apache 2 licensed).  See in particular:

     https://github.com/openssl/openssl/blob/master/crypto/sha/sha512.c

   (link valid circa 2022-Oct).  It has been made more strict with more
   extensive implementation documentation, has been simplified and has
   been streamlined specifically for use inside Firedancer base machine
   model (no machine specific capabilities required).

   In particular, fd_sha512_core_ref is based on OpenSSL's
   OPENSSL_SMALL_FOOTPRINT SHA-512 implementation (Apache licensed).
   This should work anywhere but it is not the highest performance
   implementation possible.

   It is also straightforward to replace these implementations with HPC
   implementations that target specific machine capabilities without
   requiring any changes to caller code. */

static void
fd_sha512_core_ref( ulong *       state,        /* 64-byte aligned, 8 entries */
                    uchar const * block,        /* ideally 128-byte aligned (but not required), 128*block_cnt in size */
                    ulong         block_cnt ) { /* positive */

  static ulong const K[80] = {
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

# define ROTR       fd_ulong_rotate_right
# define Sigma0(x)  (ROTR((x),28) ^ ROTR((x),34) ^ ROTR((x),39))
# define Sigma1(x)  (ROTR((x),14) ^ ROTR((x),18) ^ ROTR((x),41))
# define sigma0(x)  (ROTR((x), 1) ^ ROTR((x), 8) ^ ((x)>>7))
# define sigma1(x)  (ROTR((x),19) ^ ROTR((x),61) ^ ((x)>>6))
# define Ch(x,y,z)  (((x) & (y)) ^ ((~(x)) & (z)))
# define Maj(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

  ulong const * W = (ulong const *)block;
  do {
    ulong a = state[0];
    ulong b = state[1];
    ulong c = state[2];
    ulong d = state[3];
    ulong e = state[4];
    ulong f = state[5];
    ulong g = state[6];
    ulong h = state[7];

    ulong X[16];

    ulong i;
    for( i=0UL; i<16UL; i++ ) {
      X[i] = fd_ulong_bswap( W[i] );
      ulong T1 = X[i] + h + Sigma1(e) + Ch(e, f, g) + K[i];
      ulong T2 = Sigma0(a) + Maj(a, b, c);
      h = g;
      g = f;
      f = e;
      e = d + T1;
      d = c;
      c = b;
      b = a;
      a = T1 + T2;
    }
    for( ; i<80UL; i++ ) {
      ulong s0 = X[(i +  1UL) & 0x0fUL];
      ulong s1 = X[(i + 14UL) & 0x0fUL];
      s0 = sigma0(s0);
      s1 = sigma1(s1);
      X[i & 0xfUL] += s0 + s1 + X[(i + 9UL) & 0xfUL];
      ulong T1 = X[i & 0xfUL ] + h + Sigma1(e) + Ch(e, f, g) + K[i];
      ulong T2 = Sigma0(a) + Maj(a, b, c);
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

# undef ROTR
# undef Sigma0
# undef Sigma1
# undef sigma0
# undef sigma1
# undef Ch
# undef Maj

}

#define fd_sha512_core fd_sha512_core_ref

#elif FD_SHA512_CORE_IMPL==1

__attribute__((sysv_abi))
void
fd_sha512_core_avx2( ulong *       state,       /* 64-byte aligned, 8 entries */
                     uchar const * block,       /* ideally 128-byte aligned (but not required), 128*block_cnt in size */
                     ulong         block_cnt ); /* positive */

#define fd_sha512_core fd_sha512_core_avx2

#else
#error "Unsupported FD_SHA512_CORE_IMPL"
#endif

fd_sha512_t *
fd_sha384_init( fd_sha512_t * sha ) {
  /* sha->buf d/c */
  sha->state[0]   = 0xcbbb9d5dc1059ed8UL;
  sha->state[1]   = 0x629a292a367cd507UL;
  sha->state[2]   = 0x9159015a3070dd17UL;
  sha->state[3]   = 0x152fecd8f70e5939UL;
  sha->state[4]   = 0x67332667ffc00b31UL;
  sha->state[5]   = 0x8eb44a8768581511UL;
  sha->state[6]   = 0xdb0c2e0d64f98fa7UL;
  sha->state[7]   = 0x47b5481dbefa4fa4UL;
  sha->buf_used   = 0U;
  sha->bit_cnt_lo = 0UL;
  sha->bit_cnt_hi = 0UL;
  return sha;
}

fd_sha512_t *
fd_sha512_init( fd_sha512_t * sha ) {
  /* sha->buf d/c */
  sha->state[0]   = 0x6a09e667f3bcc908UL;
  sha->state[1]   = 0xbb67ae8584caa73bUL;
  sha->state[2]   = 0x3c6ef372fe94f82bUL;
  sha->state[3]   = 0xa54ff53a5f1d36f1UL;
  sha->state[4]   = 0x510e527fade682d1UL;
  sha->state[5]   = 0x9b05688c2b3e6c1fUL;
  sha->state[6]   = 0x1f83d9abfb41bd6bUL;
  sha->state[7]   = 0x5be0cd19137e2179UL;
  sha->buf_used   = 0U;
  sha->bit_cnt_lo = 0UL;
  sha->bit_cnt_hi = 0UL;
  return sha;
}

fd_sha512_t *
fd_sha512_append( fd_sha512_t * sha,
                  void const *  _data,
                  ulong         sz ) {

  /* If no data to append, we are done */

  if( FD_UNLIKELY( !sz ) ) return sha; /* optimize for non-trivial append */

  /* Unpack inputs */

  ulong * state      = sha->state;
  uchar * buf        = sha->buf;
  ulong   buf_used   = sha->buf_used;
  ulong   bit_cnt_lo = sha->bit_cnt_lo;
  ulong   bit_cnt_hi = sha->bit_cnt_hi;

  uchar const * data = (uchar const *)_data;

  /* Update bit_cnt */
  /* FIXME: could accumulate bytes here and do bit conversion in append */

  ulong new_bit_cnt_lo = bit_cnt_lo + (sz<< 3);
  ulong new_bit_cnt_hi = bit_cnt_hi + (sz>>61) + (ulong)(new_bit_cnt_lo<bit_cnt_lo);

  sha->bit_cnt_lo = new_bit_cnt_lo;
  sha->bit_cnt_hi = new_bit_cnt_hi;

  /* Handle buffered bytes from previous appends */

  if( FD_UNLIKELY( buf_used ) ) { /* optimized for well aligned use of append */

    /* If the append isn't large enough to complete the current block,
       buffer these bytes too and return */

    ulong buf_rem = FD_SHA512_PRIVATE_BUF_MAX - buf_used; /* In (0,FD_SHA512_PRIVATE_BUF_MAX) */
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

    fd_sha512_core( state, buf, 1UL );
    sha->buf_used = 0UL;
  }

  /* Append the bulk of the data */

  ulong block_cnt = sz >> FD_SHA512_PRIVATE_LG_BUF_MAX;
  if( FD_LIKELY( block_cnt ) ) fd_sha512_core( state, data, block_cnt ); /* optimized for large append */

  /* Buffer any leftover bytes */

  buf_used = sz & (FD_SHA512_PRIVATE_BUF_MAX-1UL); /* In [0,FD_SHA512_PRIVATE_BUF_MAX) */
  if( FD_UNLIKELY( buf_used ) ) { /* optimized for well aligned use of append */
    fd_memcpy( buf, data + (block_cnt << FD_SHA512_PRIVATE_LG_BUF_MAX), buf_used );
    sha->buf_used = buf_used; /* In (0,FD_SHA512_PRIVATE_BUF_MAX) */
  }

  return sha;
}

void *
fd_sha512_fini( fd_sha512_t * sha,
                void *        _hash ) {

  /* Unpack inputs */

  ulong * state      = sha->state;
  uchar * buf        = sha->buf;
  ulong   buf_used   = sha->buf_used; /* In [0,FD_SHA512_PRIVATE_BUF_MAX) */
  ulong   bit_cnt_lo = sha->bit_cnt_lo;
  ulong   bit_cnt_hi = sha->bit_cnt_hi;

  /* Append the terminating message byte */

  buf[ buf_used ] = (uchar)0x80;
  buf_used++;

  /* If there isn't enough room to save the message length in bits at
     the end of the in progress block, clear the rest of the in progress
     block, update the hash and start a new block. */

  if( FD_UNLIKELY( buf_used > FD_SHA512_PRIVATE_BUF_MAX-16UL ) ) { /* optimize for well aligned use of append */
    fd_memset( buf + buf_used, 0, FD_SHA512_PRIVATE_BUF_MAX-buf_used );
    fd_sha512_core( state, buf, 1UL );
    buf_used = 0UL;
  }

  /* Clear in progress block up to last 128-bits, append the message
     size in bytes in the last 128-bits of the in progress block and
     update the hash to finalize it. */

  fd_memset( buf + buf_used, 0, FD_SHA512_PRIVATE_BUF_MAX-16UL-buf_used );
  *((ulong *)(buf+FD_SHA512_PRIVATE_BUF_MAX-16UL)) = fd_ulong_bswap( bit_cnt_hi );
  *((ulong *)(buf+FD_SHA512_PRIVATE_BUF_MAX- 8UL)) = fd_ulong_bswap( bit_cnt_lo );
  fd_sha512_core( state, buf, 1UL );

  /* Unpack the result into md (annoying bswaps here) */

  ulong * hash = (ulong *)_hash;
  hash[0] = fd_ulong_bswap( state[0] );
  hash[1] = fd_ulong_bswap( state[1] );
  hash[2] = fd_ulong_bswap( state[2] );
  hash[3] = fd_ulong_bswap( state[3] );
  hash[4] = fd_ulong_bswap( state[4] );
  hash[5] = fd_ulong_bswap( state[5] );
  hash[6] = fd_ulong_bswap( state[6] );
  hash[7] = fd_ulong_bswap( state[7] );
  return _hash;
}

void *
fd_sha384_fini( fd_sha512_t * sha,
                void *        _hash ) {
  uchar hash[ FD_SHA512_HASH_SZ ] __attribute__((aligned(64)));
  fd_sha512_fini( sha, hash );
  memcpy( _hash, hash, FD_SHA384_HASH_SZ );
  return _hash;
}

void *
fd_sha512_hash( void const * _data,
                ulong        sz,
                void *       _hash ) {
  uchar const * data = (uchar const *)_data;

  /* This is just the above streamlined to eliminate all the overheads
     to support incremental hashing. */

  uchar buf[ FD_SHA512_PRIVATE_BUF_MAX ] __attribute__((aligned(128)));
  ulong state[8] __attribute__((aligned(64)));

  state[0] = 0x6a09e667f3bcc908UL;
  state[1] = 0xbb67ae8584caa73bUL;
  state[2] = 0x3c6ef372fe94f82bUL;
  state[3] = 0xa54ff53a5f1d36f1UL;
  state[4] = 0x510e527fade682d1UL;
  state[5] = 0x9b05688c2b3e6c1fUL;
  state[6] = 0x1f83d9abfb41bd6bUL;
  state[7] = 0x5be0cd19137e2179UL;

  ulong block_cnt = sz >> FD_SHA512_PRIVATE_LG_BUF_MAX;
  if( FD_LIKELY( block_cnt ) ) fd_sha512_core( state, data, block_cnt );

  ulong buf_used = sz & (FD_SHA512_PRIVATE_BUF_MAX-1UL);
  if( FD_UNLIKELY( buf_used ) ) fd_memcpy( buf, data + (block_cnt << FD_SHA512_PRIVATE_LG_BUF_MAX), buf_used );
  buf[ buf_used ] = (uchar)0x80;
  buf_used++;

  if( FD_UNLIKELY( buf_used > (FD_SHA512_PRIVATE_BUF_MAX-16UL) ) ) {
    fd_memset( buf + buf_used, 0, FD_SHA512_PRIVATE_BUF_MAX-buf_used );
    fd_sha512_core( state, buf, 1UL );
    buf_used = 0UL;
  }

  ulong bit_cnt_lo = sz<< 3;
  ulong bit_cnt_hi = sz>>61;
  fd_memset( buf + buf_used, 0, FD_SHA512_PRIVATE_BUF_MAX-16UL-buf_used );
  *((ulong *)(buf+FD_SHA512_PRIVATE_BUF_MAX-16UL)) = fd_ulong_bswap( bit_cnt_hi );
  *((ulong *)(buf+FD_SHA512_PRIVATE_BUF_MAX- 8UL)) = fd_ulong_bswap( bit_cnt_lo );
  fd_sha512_core( state, buf, 1UL );

  ulong * hash = (ulong *)_hash;
  hash[0] = fd_ulong_bswap( state[0] );
  hash[1] = fd_ulong_bswap( state[1] );
  hash[2] = fd_ulong_bswap( state[2] );
  hash[3] = fd_ulong_bswap( state[3] );
  hash[4] = fd_ulong_bswap( state[4] );
  hash[5] = fd_ulong_bswap( state[5] );
  hash[6] = fd_ulong_bswap( state[6] );
  hash[7] = fd_ulong_bswap( state[7] );
  return _hash;
}

void *
fd_sha384_hash( void const * _data,
                ulong        sz,
                void *       _hash ) {
  uchar const * data = (uchar const *)_data;

  /* This is just the above streamlined to eliminate all the overheads
     to support incremental hashing. */

  uchar buf[ FD_SHA512_PRIVATE_BUF_MAX ] __attribute__((aligned(128)));
  ulong state[8] __attribute__((aligned(64)));

  state[0] = 0xcbbb9d5dc1059ed8UL;
  state[1] = 0x629a292a367cd507UL;
  state[2] = 0x9159015a3070dd17UL;
  state[3] = 0x152fecd8f70e5939UL;
  state[4] = 0x67332667ffc00b31UL;
  state[5] = 0x8eb44a8768581511UL;
  state[6] = 0xdb0c2e0d64f98fa7UL;
  state[7] = 0x47b5481dbefa4fa4UL;

  ulong block_cnt = sz >> FD_SHA512_PRIVATE_LG_BUF_MAX;
  if( FD_LIKELY( block_cnt ) ) fd_sha512_core( state, data, block_cnt );

  ulong buf_used = sz & (FD_SHA512_PRIVATE_BUF_MAX-1UL);
  if( FD_UNLIKELY( buf_used ) ) fd_memcpy( buf, data + (block_cnt << FD_SHA512_PRIVATE_LG_BUF_MAX), buf_used );
  buf[ buf_used ] = (uchar)0x80;
  buf_used++;

  if( FD_UNLIKELY( buf_used > (FD_SHA512_PRIVATE_BUF_MAX-16UL) ) ) {
    fd_memset( buf + buf_used, 0, FD_SHA512_PRIVATE_BUF_MAX-buf_used );
    fd_sha512_core( state, buf, 1UL );
    buf_used = 0UL;
  }

  ulong bit_cnt_lo = sz<< 3;
  ulong bit_cnt_hi = sz>>61;
  fd_memset( buf + buf_used, 0, FD_SHA512_PRIVATE_BUF_MAX-16UL-buf_used );
  *((ulong *)(buf+FD_SHA512_PRIVATE_BUF_MAX-16UL)) = fd_ulong_bswap( bit_cnt_hi );
  *((ulong *)(buf+FD_SHA512_PRIVATE_BUF_MAX- 8UL)) = fd_ulong_bswap( bit_cnt_lo );
  fd_sha512_core( state, buf, 1UL );

  ulong * hash = (ulong *)_hash;
  hash[0] = fd_ulong_bswap( state[0] );
  hash[1] = fd_ulong_bswap( state[1] );
  hash[2] = fd_ulong_bswap( state[2] );
  hash[3] = fd_ulong_bswap( state[3] );
  hash[4] = fd_ulong_bswap( state[4] );
  hash[5] = fd_ulong_bswap( state[5] );
  return _hash;
}

#undef fd_sha512_core

