#include "fd_sha256.h"

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

/* The implementation below was derived from OpenSSL's SHA-256
   implementation (Apache-2.0 licensed).  See in particular:

    https://github.com/openssl/openssl/blob/openssl-3.0.7/crypto/sha/sha256.c */

static void
fd_sha256_core_ref( uint *        state,
                    uchar const * block,
                    ulong         block_cnt ) {

  static uint const K[64] = {
    0x428a2f98UL, 0x71374491UL, 0xb5c0fbcfUL, 0xe9b5dba5UL,
    0x3956c25bUL, 0x59f111f1UL, 0x923f82a4UL, 0xab1c5ed5UL,
    0xd807aa98UL, 0x12835b01UL, 0x243185beUL, 0x550c7dc3UL,
    0x72be5d74UL, 0x80deb1feUL, 0x9bdc06a7UL, 0xc19bf174UL,
    0xe49b69c1UL, 0xefbe4786UL, 0x0fc19dc6UL, 0x240ca1ccUL,
    0x2de92c6fUL, 0x4a7484aaUL, 0x5cb0a9dcUL, 0x76f988daUL,
    0x983e5152UL, 0xa831c66dUL, 0xb00327c8UL, 0xbf597fc7UL,
    0xc6e00bf3UL, 0xd5a79147UL, 0x06ca6351UL, 0x14292967UL,
    0x27b70a85UL, 0x2e1b2138UL, 0x4d2c6dfcUL, 0x53380d13UL,
    0x650a7354UL, 0x766a0abbUL, 0x81c2c92eUL, 0x92722c85UL,
    0xa2bfe8a1UL, 0xa81a664bUL, 0xc24b8b70UL, 0xc76c51a3UL,
    0xd192e819UL, 0xd6990624UL, 0xf40e3585UL, 0x106aa070UL,
    0x19a4c116UL, 0x1e376c08UL, 0x2748774cUL, 0x34b0bcb5UL,
    0x391c0cb3UL, 0x4ed8aa4aUL, 0x5b9cca4fUL, 0x682e6ff3UL,
    0x748f82eeUL, 0x78a5636fUL, 0x84c87814UL, 0x8cc70208UL,
    0x90befffaUL, 0xa4506cebUL, 0xbef9a3f7UL, 0xc67178f2UL
  };

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
      uint T1 = X[i] + h + Sigma1(e) + Ch(e, f, g) + K[i];
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
      uint T1 = X[i & 0xfUL ] + h + Sigma1(e) + Ch(e, f, g) + K[i];
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

fd_sha256_t *
fd_sha256_init( fd_sha256_t * sha ) {
  sha->state[0]   = 0x6a09e667UL;
  sha->state[1]   = 0xbb67ae85UL;
  sha->state[2]   = 0x3c6ef372UL;
  sha->state[3]   = 0xa54ff53aUL;
  sha->state[4]   = 0x510e527fUL;
  sha->state[5]   = 0x9b05688cUL;
  sha->state[6]   = 0x1f83d9abUL;
  sha->state[7]   = 0x5be0cd19UL;
  sha->buf_used   = 0U;
  sha->bit_cnt    = 0UL;
  return sha;
}

fd_sha256_t *
fd_sha256_append( fd_sha256_t * sha,
                  void const *  _data,
                  ulong         sz ) {

  /* If no data to append, we are done */

  if( FD_UNLIKELY( !sz ) ) return sha; /* optimize for non-trivial append */

  /* Unpack inputs */

  uint * state       = sha->state;
  uchar * buf        = sha->buf;
  ulong   buf_used   = sha->buf_used;
  ulong   bit_cnt    = sha->bit_cnt;

  uchar const * data = (uchar const *)_data;

  /* Update bit_cnt */
  /* FIXME: could accumulate bytes here and do bit conversion in append */

  ulong new_bit_cnt = bit_cnt + (sz<<3);
  sha->bit_cnt = new_bit_cnt;

  /* Handle buffered bytes from previous appends */

  if( FD_UNLIKELY( buf_used ) ) { /* optimized for well aligned use of append */

    /* If the append isn't large enough to complete the current block,
       buffer these bytes too and return */

    ulong buf_rem = FD_SHA256_BUF_MAX - buf_used; /* In (0,64) */
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

  ulong block_cnt = sz / FD_SHA256_BUF_MAX;
  if( FD_LIKELY( block_cnt ) ) fd_sha256_core( state, data, block_cnt ); /* optimized for large append */

  /* Buffer any leftover bytes */

  buf_used = sz & (FD_SHA256_BUF_MAX-1); /* In [0,64) */
  if( FD_UNLIKELY( buf_used ) ) { /* optimized for well aligned use of append */
    fd_memcpy( buf, data + (block_cnt*FD_SHA256_BUF_MAX), buf_used );
    sha->buf_used = buf_used; /* In (0,64) */
  }

  return sha;
}

void *
fd_sha256_fini( fd_sha256_t * sha,
                void *        _hash ) {

  /* Unpack inputs */

  uint * state       = sha->state;
  uchar * buf        = sha->buf;
  ulong   buf_used   = sha->buf_used; /* In [0,64) */
  ulong   bit_cnt    = sha->bit_cnt;

  /* Append the terminating message byte */

  buf[ buf_used ] = (uchar)0x80;
  buf_used++;

  /* If there isn't enough room to save the message length in bits at
     the end of the in progress block, clear the rest of the in progress
     block, update the hash and start a new block. */

  if( FD_UNLIKELY( buf_used > (FD_SHA256_BUF_MAX-8) ) ) { /* optimize for well aligned use of append */
    fd_memset( buf + buf_used, 0, FD_SHA256_BUF_MAX-buf_used );
    fd_sha256_core( state, buf, 1UL );
    buf_used = 0UL;
  }

  /* Clear in progress block up to last 64-bits, append the message
     size in bytes in the last 64-bits of the in progress block and
     update the hash to finalize it. */

  uint bit_cnt_lo = (uint)(bit_cnt);
  uint bit_cnt_hi = (uint)(bit_cnt>>32);

  fd_memset( buf + buf_used, 0, FD_SHA256_BUF_MAX-8-buf_used );
  *((uint *)(buf+FD_SHA256_BUF_MAX-8)) = fd_uint_bswap( bit_cnt_hi );
  *((uint *)(buf+FD_SHA256_BUF_MAX-4)) = fd_uint_bswap( bit_cnt_lo );
  fd_sha256_core( state, buf, 1UL );

  /* Unpack the result into md (annoying bswaps here) */

  uint * hash = (uint *)_hash;
  hash[0] = fd_uint_bswap( state[0] );
  hash[1] = fd_uint_bswap( state[1] );
  hash[2] = fd_uint_bswap( state[2] );
  hash[3] = fd_uint_bswap( state[3] );
  hash[4] = fd_uint_bswap( state[4] );
  hash[5] = fd_uint_bswap( state[5] );
  hash[6] = fd_uint_bswap( state[6] );
  hash[7] = fd_uint_bswap( state[7] );
  return _hash;
}
