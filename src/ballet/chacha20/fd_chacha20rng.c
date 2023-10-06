#include "fd_chacha20rng.h"

FD_FN_CONST ulong
fd_chacha20rng_align( void ) {
  return alignof(fd_chacha20rng_t);
}

FD_FN_CONST ulong
fd_chacha20rng_footprint( void ) {
  return sizeof(fd_chacha20rng_t);
}

void *
fd_chacha20rng_new( void * shmem, int mode ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, alignof(fd_chacha20rng_t) ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }
  memset( shmem, 0, sizeof(fd_chacha20rng_t) );
  if( FD_UNLIKELY( (mode!=FD_CHACHA20RNG_MODE_MOD) & (mode!=FD_CHACHA20RNG_MODE_SHIFT) ) ) {
    FD_LOG_WARNING(( "invalid mode" ));
    return NULL;
  }
  ((fd_chacha20rng_t *)shmem)->mode = mode;

  return shmem;
}

fd_chacha20rng_t *
fd_chacha20rng_join( void * shrng ) {
  if( FD_UNLIKELY( !shrng ) ) {
    FD_LOG_WARNING(( "NULL shrng" ));
    return NULL;
  }
  return (fd_chacha20rng_t *)shrng;
}

void *
fd_chacha20rng_leave( fd_chacha20rng_t * rng ) {
  if( FD_UNLIKELY( !rng ) ) {
    FD_LOG_WARNING(( "NULL rng" ));
    return NULL;
  }
  return (void *)rng;
}

void *
fd_chacha20rng_delete( void * shrng ) {
  if( FD_UNLIKELY( !shrng ) ) {
    FD_LOG_WARNING(( "NULL shrng" ));
    return NULL;
  }
  memset( shrng, 0, sizeof(fd_chacha20rng_t) );
  return shrng;
}

fd_chacha20rng_t *
fd_chacha20rng_init( fd_chacha20rng_t * rng,
                     void const *       key ) {
  memcpy( rng->key, key, FD_CHACHA20_KEY_SZ );
  rng->buf_off  = 0UL;
  rng->buf_fill = 0UL;
  rng->idx      = 0U ;
  fd_chacha20rng_private_refill( rng );
  return rng;
}

void
fd_chacha20rng_private_refill( fd_chacha20rng_t * rng ) {
  ulong fill_target = FD_CHACHA20RNG_BUFSZ - FD_CHACHA20_BLOCK_SZ;
  uint nonce[ 3 ]={0};

  ulong buf_avail;
  while( (buf_avail=(rng->buf_fill - rng->buf_off))<fill_target ) {
    fd_chacha20_block( rng->buf + (rng->buf_fill % FD_CHACHA20RNG_BUFSZ),
                       rng->key,
                       rng->idx++,
                       &nonce );
    rng->buf_fill += (uint)FD_CHACHA20_BLOCK_SZ;
  }
}

