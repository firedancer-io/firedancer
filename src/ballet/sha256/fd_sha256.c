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

  static uint const K[64] = {
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
    0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U, 0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
    0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU, 0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
    0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U, 0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
    0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U, 0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
    0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U, 0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
    0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
    0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U, 0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U,
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

#elif FD_SHA256_CORE_IMPL==1

__attribute__((sysv_abi))
void
fd_sha256_core_shaext( uint *        state,       /* 64-byte aligned, 8 entries */
                       uchar const * block,       /* ideally 128-byte aligned (but not required), 128*block_cnt in size */
                       ulong         block_cnt ); /* positive */

#define fd_sha256_core fd_sha256_core_shaext

#else
#error "Unsupported FD_SHA256_CORE_IMPL"
#endif

fd_sha256_t *
fd_sha256_init( fd_sha256_t * sha ) {
  sha->state[0] = 0x6a09e667U;
  sha->state[1] = 0xbb67ae85U;
  sha->state[2] = 0x3c6ef372U;
  sha->state[3] = 0xa54ff53aU;
  sha->state[4] = 0x510e527fU;
  sha->state[5] = 0x9b05688cU;
  sha->state[6] = 0x1f83d9abU;
  sha->state[7] = 0x5be0cd19U;
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

void *
fd_sha256_hash( void const * _data,
                ulong        sz,
                void *       _hash ) {
  uchar const * data = (uchar const *)_data;

  /* This is just the above streamlined to eliminate all the overheads
     to support incremental hashing. */

  uchar buf[ FD_SHA256_PRIVATE_BUF_MAX ] __attribute__((aligned(128)));
  uint  state[8] __attribute__((aligned(32)));

  state[0] = 0x6a09e667U;
  state[1] = 0xbb67ae85U;
  state[2] = 0x3c6ef372U;
  state[3] = 0xa54ff53aU;
  state[4] = 0x510e527fU;
  state[5] = 0x9b05688cU;
  state[6] = 0x1f83d9abU;
  state[7] = 0x5be0cd19U;

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

#undef fd_sha256_core
