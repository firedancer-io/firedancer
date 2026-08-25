#include "fd_rserve.h"
#include "fd_repair.h"
#include "../../ballet/sha256/fd_sha256.h"

static void
fd_rserve_rotation_secret( uchar       out[ 32 ],
                           uchar const master[ 32 ],
                           ulong       idx ) {
  uchar buf[ 40 ];
  memcpy( buf, master, 32UL );
  FD_STORE( ulong, buf+32UL, idx );
  fd_sha256_hash( buf, sizeof(buf), out );
}

static void
fd_rserve_token_compute( uchar               token[ 32 ],
                         uchar const         secret[ 32 ],
                         fd_pubkey_t const * from,
                         uint                ip4,
                         ushort              port ) {
  memcpy( token, "SOLANA_PING_PONG", 16UL );

  uchar buf[ 32UL + 32UL + 4UL + 2UL ];
  memcpy( buf,       secret,   32UL );
  memcpy( buf+32UL,  from->uc, 32UL );
  FD_STORE( uint,   buf+64UL, ip4  );
  FD_STORE( ushort, buf+68UL, port );

  uchar mac[ 32 ];
  fd_sha256_hash( buf, sizeof(buf), mac );
  memcpy( token+16UL, mac, 16UL );
}

ulong
fd_rserve_footprint( ulong ping_cache_entries ) {
  if( FD_UNLIKELY( !ping_cache_entries ) ) return 0UL;

  ulong ping_max = fd_ulong_pow2_up( ping_cache_entries );

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_rserve_t), sizeof(fd_rserve_t) );
  l = FD_LAYOUT_APPEND( l, ping_pool_align(),    ping_pool_footprint( ping_max ) );
  l = FD_LAYOUT_APPEND( l, ping_map_align(),     ping_map_footprint( ping_map_chain_cnt_est( ping_max ) ) );
  l = FD_LAYOUT_APPEND( l, ping_dlist_align(),   ping_dlist_footprint() );
  return FD_LAYOUT_FINI( l, fd_rserve_align() );
}

void *
fd_rserve_new( void * shmem,
               ulong  ping_cache_entries,
               ulong  seed,
               uchar const secret[ 32 ] ) {
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

  /* Initialize rotating token secrets. */
  rserve->seed           = seed;
  rserve->token_idx      = 0UL;
  rserve->last_rotate_ts = 0UL;
  memcpy( rserve->secret_master, secret, 32UL );
  fd_rserve_rotation_secret( rserve->secret_cur, rserve->secret_master, 0UL );
  memcpy( rserve->secret_prev, rserve->secret_cur, 32UL );

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

void
fd_rserve_ping_token( fd_rserve_t const * rserve,
                      uchar               token[ 32 ],
                      fd_pubkey_t const * from,
                      uint                ip4,
                      ushort              port ) {
  fd_rserve_token_compute( token, rserve->secret_cur, from, ip4, port );
}

static int
fd_rserve_secret_pong_verify( uchar const         secret[ 32 ],
                              uchar const       * pong_hash,
                              fd_pubkey_t const * from,
                              uint                ip4,
                              ushort              port ) {
  uchar token   [ 32 ];
  uchar preimage[ FD_REPAIR_PONG_PREIMAGE_SZ ];
  uchar expected[ 32 ];

  fd_rserve_token_compute( token, secret, from, ip4, port );
  preimage_pong( (fd_hash_t const *)token, preimage );
  fd_sha256_hash( preimage, FD_REPAIR_PONG_PREIMAGE_SZ, expected );
  return !memcmp( expected, pong_hash, 32UL );
}

int
fd_rserve_pong_token_verify( fd_rserve_t const * rserve,
                             uchar const       * pong_hash,
                             fd_pubkey_t const * from,
                             uint                ip4,
                             ushort              port ) {
  if( FD_LIKELY( fd_rserve_secret_pong_verify( rserve->secret_cur,  pong_hash, from, ip4, port ) ) ) return 1;
  if( FD_LIKELY( fd_rserve_secret_pong_verify( rserve->secret_prev, pong_hash, from, ip4, port ) ) ) return 1;
  return 0;
}

void
fd_rserve_maybe_rotate( fd_rserve_t * rserve,
                        ulong         now_ns ) {
  if( FD_UNLIKELY( now_ns-rserve->last_rotate_ts > FD_RSERVE_TOKEN_ROTATE_NS ) ) {
    rserve->last_rotate_ts = now_ns;
    rserve->token_idx++;
    memcpy( rserve->secret_prev, rserve->secret_cur, 32UL );
    fd_rserve_rotation_secret( rserve->secret_cur, rserve->secret_master, rserve->token_idx );
  }
}

