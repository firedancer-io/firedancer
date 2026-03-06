#include "fd_rserve.h"
#include "fd_repair.h"
#include "../../ballet/sha256/fd_sha256.h"

ulong
fd_rserve_footprint( ulong ping_cache_entries ) {
  if( FD_UNLIKELY( !ping_cache_entries ) ) return 0UL;

  ulong ping_max = fd_ulong_pow2_up( ping_cache_entries );

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_rserve_t), sizeof(fd_rserve_t) );
  l = FD_LAYOUT_APPEND( l, ping_pool_align(),     ping_pool_footprint( ping_max ) );
  l = FD_LAYOUT_APPEND( l, ping_map_align(),      ping_map_footprint( ping_map_chain_cnt_est( ping_max ) ) );
  l = FD_LAYOUT_APPEND( l, ping_dlist_align(),    ping_dlist_footprint() );
  return FD_LAYOUT_FINI( l, fd_rserve_align() );
}

void *
fd_rserve_new( void * shmem,
               ulong  ping_cache_entries,
               ulong  seed ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_rserve_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  ulong footprint = fd_rserve_footprint( ping_cache_entries );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING(( "bad ping cache size (%lu)", ping_cache_entries ));
    return NULL;
  }

  ulong ping_max = fd_ulong_pow2_up( ping_cache_entries );

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  void * rserve_mem     = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_rserve_t), sizeof(fd_rserve_t) );
  void * ping_pool_mem  = FD_SCRATCH_ALLOC_APPEND( l, ping_pool_align(),    ping_pool_footprint( ping_max ) );
  void * ping_map_mem   = FD_SCRATCH_ALLOC_APPEND( l, ping_map_align(),     ping_map_footprint( ping_map_chain_cnt_est( ping_max ) ) );
  void * ping_dlist_mem = FD_SCRATCH_ALLOC_APPEND( l, ping_dlist_align(),   ping_dlist_footprint() );

  fd_rserve_t * rserve = (fd_rserve_t *)rserve_mem;
  ping_pool_new( ping_pool_mem, ping_max );
  rserve->ping_pool  = fd_type_pun( ping_pool_mem );
  rserve->ping_map   = ping_map_join  ( ping_map_new  ( ping_map_mem,   ping_map_chain_cnt_est( ping_max ), seed ) );
  rserve->ping_dlist = ping_dlist_join( ping_dlist_new( ping_dlist_mem ) );

  /* Initialize rotating tokens. */
  rserve->seed      = seed;
  rserve->token_idx = 0UL;
  rserve->last_rotate_ts = 0UL;
  fd_rserve_derive_token( rserve->token_cur,  seed, 0UL );
  fd_rserve_derive_token( rserve->token_prev, seed, 0UL );

  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, fd_rserve_align() )==(ulong)shmem + footprint );

  return shmem;
}

fd_rserve_t *
fd_rserve_join( void * shrserve ) {
  if( FD_UNLIKELY( !shrserve ) ) {
    FD_LOG_WARNING(( "NULL rserve" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shrserve, fd_rserve_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned rserve" ));
    return NULL;
  }

  fd_rserve_t * rserve = (fd_rserve_t *)shrserve;
  rserve->ping_pool  = ping_pool_join ( rserve->ping_pool  );
  rserve->ping_map   = ping_map_join  ( rserve->ping_map   );
  rserve->ping_dlist = ping_dlist_join( rserve->ping_dlist );

  return (fd_rserve_t *)rserve;
}

void *
fd_rserve_leave( fd_rserve_t const * rserve ) {
  if( FD_UNLIKELY( !rserve ) ) {
    FD_LOG_WARNING(( "NULL rserve" ));
    return NULL;
  }

  return (void *)rserve;
}

void *
fd_rserve_delete( void * rserve ) {
  if( FD_UNLIKELY( !rserve ) ) {
    FD_LOG_WARNING(( "NULL rserve" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)rserve, fd_rserve_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned rserve" ));
    return NULL;
  }

  return rserve;
}

int
fd_rserve_pong_token_verify( fd_rserve_t const * rserve,
                             uchar const       * pong_hash ) {
  /* The pong hash is SHA-256( "SOLANA_PING_PONG" || token ).
     Compute the expected hash for both current and previous tokens
     and check if either matches. */

  uchar preimage[ FD_REPAIR_PONG_PREIMAGE_SZ ];
  uchar expected[ 32 ];

  /* Check current token. */
  preimage_pong( (fd_hash_t const *)rserve->token_cur, preimage, sizeof(preimage) );
  fd_sha256_hash( preimage, FD_REPAIR_PONG_PREIMAGE_SZ, expected );
  if( FD_LIKELY( !memcmp( expected, pong_hash, 32UL ) ) ) return 1;

  /* Check previous token. */
  preimage_pong( (fd_hash_t const *)rserve->token_prev, preimage, sizeof(preimage) );
  fd_sha256_hash( preimage, FD_REPAIR_PONG_PREIMAGE_SZ, expected );
  if( FD_LIKELY( !memcmp( expected, pong_hash, 32UL ) ) ) return 1;

  return 0;
}

