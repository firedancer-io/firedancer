#include "fd_chacha_rng.h"

FD_FN_CONST ulong
fd_chacha_rng_align( void ) {
  return alignof(fd_chacha_rng_t);
}

FD_FN_CONST ulong
fd_chacha_rng_footprint( void ) {
  return sizeof(fd_chacha_rng_t);
}

void *
fd_chacha_rng_new( void * shmem, int mode ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, alignof(fd_chacha_rng_t) ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }
  memset( shmem, 0, sizeof(fd_chacha_rng_t) );
  if( FD_UNLIKELY( (mode!=FD_CHACHA_RNG_MODE_MOD) & (mode!=FD_CHACHA_RNG_MODE_SHIFT) ) ) {
    FD_LOG_WARNING(( "invalid mode" ));
    return NULL;
  }
  ((fd_chacha_rng_t *)shmem)->mode = mode;
  ((fd_chacha_rng_t *)shmem)->algo = FD_CHACHA_RNG_ALGO_CHACHA20;
  return shmem;
}

fd_chacha_rng_t *
fd_chacha_rng_join( void * shrng ) {
  if( FD_UNLIKELY( !shrng ) ) {
    FD_LOG_WARNING(( "NULL shrng" ));
    return NULL;
  }
  return (fd_chacha_rng_t *)shrng;
}

void *
fd_chacha_rng_leave( fd_chacha_rng_t * rng ) {
  if( FD_UNLIKELY( !rng ) ) {
    FD_LOG_WARNING(( "NULL rng" ));
    return NULL;
  }
  return (void *)rng;
}

void *
fd_chacha_rng_delete( void * shrng ) {
  if( FD_UNLIKELY( !shrng ) ) {
    FD_LOG_WARNING(( "NULL shrng" ));
    return NULL;
  }
  memset( shrng, 0, sizeof(fd_chacha_rng_t) );
  return shrng;
}

fd_chacha_rng_t *
fd_chacha_rng_init( fd_chacha_rng_t * rng,
                    void const *      key,
                    int               algo ) {
  memcpy( rng->key, key, FD_CHACHA_KEY_SZ );
  rng->buf_off  = 0UL;
  rng->buf_fill = 0UL;

  /* invalid algo defaults to chacha20 */
  rng->algo = algo;
  if( algo==FD_CHACHA_RNG_ALGO_CHACHA8 ) {
    fd_chacha8_rng_private_refill( rng );
  } else {
    fd_chacha20_rng_private_refill( rng );
  }

  return rng;
}

static void
fd_chacha_rng_refill_seq( fd_chacha_rng_t * rng,
                          void * (* block_fn)( void *, void const *, void const * ) ) {
  ulong fill_target = FD_CHACHA_RNG_BUFSZ - FD_CHACHA_BLOCK_SZ;

  ulong buf_avail;
  while( (buf_avail=(rng->buf_fill - rng->buf_off))<fill_target ) {
    ulong idx = rng->buf_fill >> 6;
    uint idx_nonce[4] __attribute__((aligned(16))) =
      { (uint)idx, 0U, 0U, 0U };
    block_fn( rng->buf + (rng->buf_fill % FD_CHACHA_RNG_BUFSZ),
              rng->key,
              idx_nonce );
    rng->buf_fill += (uint)FD_CHACHA_BLOCK_SZ;
  }
}

void
fd_chacha8_rng_refill_seq( fd_chacha_rng_t * rng ) {
  fd_chacha_rng_refill_seq( rng, fd_chacha8_block );
}

void
fd_chacha20_rng_refill_seq( fd_chacha_rng_t * rng ) {
  fd_chacha_rng_refill_seq( rng, fd_chacha20_block );
}
