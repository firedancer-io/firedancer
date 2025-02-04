#include "fd_keccak256.h"
#include "fd_keccak256_private.h"

ulong
fd_keccak256_align( void ) {
  return FD_KECCAK256_ALIGN;
}

ulong
fd_keccak256_footprint( void ) {
  return FD_KECCAK256_FOOTPRINT;
}

void *
fd_keccak256_new( void * shmem ) {
  fd_keccak256_t * sha = (fd_keccak256_t *)shmem;

  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_keccak256_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  ulong footprint = fd_keccak256_footprint();

  fd_memset( sha, 0, footprint );

  FD_COMPILER_MFENCE();
  FD_VOLATILE( sha->magic ) = FD_KECCAK256_MAGIC;
  FD_COMPILER_MFENCE();

  return (void *)sha;
}

fd_keccak256_t *
fd_keccak256_join( void * shsha ) {

  if( FD_UNLIKELY( !shsha ) ) {
    FD_LOG_WARNING(( "NULL shsha" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shsha, fd_keccak256_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shsha" ));
    return NULL;
  }

  fd_keccak256_t * sha = (fd_keccak256_t *)shsha;

  if( FD_UNLIKELY( sha->magic!=FD_KECCAK256_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return sha;
}

void *
fd_keccak256_leave( fd_keccak256_t * sha ) {

  if( FD_UNLIKELY( !sha ) ) {
    FD_LOG_WARNING(( "NULL sha" ));
    return NULL;
  }

  return (void *)sha;
}

void *
fd_keccak256_delete( void * shsha ) {

  if( FD_UNLIKELY( !shsha ) ) {
    FD_LOG_WARNING(( "NULL shsha" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shsha, fd_keccak256_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shsha" ));
    return NULL;
  }

  fd_keccak256_t * sha = (fd_keccak256_t *)shsha;

  if( FD_UNLIKELY( sha->magic!=FD_KECCAK256_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  FD_COMPILER_MFENCE();
  FD_VOLATILE( sha->magic ) = 0UL;
  FD_COMPILER_MFENCE();

  return (void *)sha;
}

fd_keccak256_t *
fd_keccak256_init( fd_keccak256_t * sha ) {
  fd_memset( sha->state, 0, sizeof( sha->state ) );

  sha->padding_start = 0;

  return sha;
}

fd_keccak256_t *
fd_keccak256_append( fd_keccak256_t * sha,
                     void const *     _data,
                     ulong            sz ) {

  /* If no data to append, we are done */

  if( FD_UNLIKELY( !sz ) ) return sha; /* optimize for non-trivial append */

  /* Unpack inputs */

  ulong * state         = sha->state;
  uchar * state_bytes   = (uchar*) sha->state;
  ulong   padding_start = sha->padding_start;

  uchar const * data = (uchar const *)_data;

  ulong state_idx = padding_start;
  for( ulong i = 0; i < sz; i++ ) {
    state_bytes[state_idx] ^= data[i];
    state_idx++;
    if( state_idx >= FD_KECCAK256_RATE ) {
      fd_keccak256_core(state);
      state_idx = 0;
    }
  }

  sha->padding_start = state_idx;

  return sha;
}

void *
fd_keccak256_fini( fd_keccak256_t * sha,
                   void *           hash ) {

  /* Unpack inputs */

  ulong * state         = sha->state;
  uchar * state_bytes   = (uchar*) sha->state;
  ulong   padding_start = sha->padding_start;


  /* Append the terminating message byte */

  state_bytes[padding_start] ^= (uchar)0x01;
  state_bytes[FD_KECCAK256_RATE-1] ^= (uchar)0x80;
  fd_keccak256_core(state);

  /* Copy the result into hash */

  fd_memcpy(hash, state, FD_KECCAK256_OUT_SZ);
  return hash;
}

void *
fd_keccak256_hash( void const * _data,
                ulong        sz,
                void *       _hash ) {
  fd_keccak256_t sha;
  fd_keccak256_init( &sha );
  fd_keccak256_append( &sha, _data, sz );
  fd_keccak256_fini( &sha, _hash );


  return _hash;
}

#undef fd_keccak256_core
