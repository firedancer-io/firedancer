#include "fd_footer_cache.h"

#define ENTRY_CNT (64UL)

struct __attribute__((aligned(FD_FOOTER_CACHE_ALIGN))) fd_footer_cache {
  ulong magic; /* ==FD_FOOTER_CACHE_MAGIC */
  ulong next;

  struct {
    ulong sz; /* 0 if empty */
    uchar msg[ FD_FOOTER_CACHE_MSG_MAX ];
    blst_p2_affine h;
  } e[ ENTRY_CNT ];
};

ulong
fd_footer_cache_align( void ) {
  return FD_FOOTER_CACHE_ALIGN;
}

ulong
fd_footer_cache_footprint( void ) {
  return sizeof(fd_footer_cache_t);
}

void *
fd_footer_cache_new( void * shmem ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_footer_cache_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  fd_footer_cache_t * cache = (fd_footer_cache_t *)shmem;
  fd_memset( cache, 0, sizeof(fd_footer_cache_t) );

  FD_COMPILER_MFENCE();
  FD_VOLATILE( cache->magic ) = FD_FOOTER_CACHE_MAGIC;
  FD_COMPILER_MFENCE();

  return shmem;
}

fd_footer_cache_t *
fd_footer_cache_join( void * shcache ) {
  if( FD_UNLIKELY( !shcache ) ) {
    FD_LOG_WARNING(( "NULL shcache" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shcache, fd_footer_cache_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shcache" ));
    return NULL;
  }

  fd_footer_cache_t * cache = (fd_footer_cache_t *)shcache;

  if( FD_UNLIKELY( cache->magic!=FD_FOOTER_CACHE_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return cache;
}

void
fd_footer_cache_hash_msg( fd_footer_cache_t * cache,
                          uchar const *       msg,
                          ulong               msg_sz,
                          blst_p2_affine *    h ) {
  FD_TEST( msg_sz && msg_sz<=FD_FOOTER_CACHE_MSG_MAX );
  for( ulong i=0UL; i<ENTRY_CNT; i++ ) {
    if( cache->e[ i ].sz==msg_sz && !memcmp( cache->e[ i ].msg, msg, msg_sz ) ) { *h = cache->e[ i ].h; return; }
  }
  fd_bls_hash_msg( msg, msg_sz, h );
  ulong i = cache->next++ % ENTRY_CNT;
  cache->e[ i ].sz = msg_sz;
  memcpy( cache->e[ i ].msg, msg, msg_sz );
  cache->e[ i ].h  = *h;
}
