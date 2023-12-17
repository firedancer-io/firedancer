#include "fd_blake3.h"
#include "blake3_impl.h"
#include "blake3_dispatch.c"
#include "blake3.c"

ulong
fd_blake3_align( void ) {
  return FD_BLAKE3_ALIGN;
}

ulong
fd_blake3_footprint( void ) {
  return FD_BLAKE3_FOOTPRINT;
}

void *
fd_blake3_new( void * shmem ) {
  fd_blake3_t * sha = (fd_blake3_t *)shmem;

  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_blake3_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  ulong footprint = fd_blake3_footprint();

  fd_memset( sha, 0, footprint );

  FD_COMPILER_MFENCE();
  FD_VOLATILE( sha->magic ) = FD_BLAKE3_MAGIC;
  FD_COMPILER_MFENCE();

  return (void *)sha;
}

fd_blake3_t *
fd_blake3_join( void * shsha ) {

  if( FD_UNLIKELY( !shsha ) ) {
    FD_LOG_WARNING(( "NULL shsha" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shsha, fd_blake3_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shsha" ));
    return NULL;
  }

  fd_blake3_t * sha = (fd_blake3_t *)shsha;

  if( FD_UNLIKELY( sha->magic!=FD_BLAKE3_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return sha;
}

void *
fd_blake3_leave( fd_blake3_t * sha ) {

  if( FD_UNLIKELY( !sha ) ) {
    FD_LOG_WARNING(( "NULL sha" ));
    return NULL;
  }

  return (void *)sha;
}

void *
fd_blake3_delete( void * shsha ) {

  if( FD_UNLIKELY( !shsha ) ) {
    FD_LOG_WARNING(( "NULL shsha" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shsha, fd_blake3_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shsha" ));
    return NULL;
  }

  fd_blake3_t * sha = (fd_blake3_t *)shsha;

  if( FD_UNLIKELY( sha->magic!=FD_BLAKE3_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  FD_COMPILER_MFENCE();
  FD_VOLATILE( sha->magic ) = 0UL;
  FD_COMPILER_MFENCE();

  return (void *)sha;
}

/* The implementation below is a wrapper around the BLAKE3 reference
   implementation (CC0-1.0 and Apache-2.0 licensed).  See in particular:

   https://github.com/BLAKE3-team/BLAKE3/tree/master/c

   We bring in the portable implementation of BLAKE3 and the AVX2
   implementation.  There is room for improvement in these implementations In
   particular:

    - Using fd_memset, fd_memcpy where reference implementation uses memset, memcpy
    - Reduction in the number of memset(s) and memcpy(s)
    - Better AVX2 routines

   It is also straightforward to replace or improve these implementations with
   HPC implementations that target specific machine capabilities without
   requiring any changes to caller code. */

fd_blake3_t *
fd_blake3_init( fd_blake3_t * sha ) {
  blake3_hasher_init( &sha->hasher );
  return sha;
}

fd_blake3_t *
fd_blake3_append( fd_blake3_t * sha,
                  void const *  data,
                  ulong         sz ) {
  blake3_hasher_update( &sha->hasher, data, sz);
  return sha;
}

void *
fd_blake3_fini( fd_blake3_t * sha,
                void *        hash ) {
  blake3_hasher_finalize( &sha->hasher, (uchar *) hash, 32 );
  return hash;
}

