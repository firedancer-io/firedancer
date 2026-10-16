#include "fd_footer_cache.h"

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
  blst_p2_affine const * hit = fd_footer_cache_hash_query( cache, msg, msg_sz );
  if( hit ) { *h = *hit; return; }
  fd_bls_hash_msg( msg, msg_sz, h );
  fd_footer_cache_hash_insert( cache, msg, msg_sz, h );
}

void
fd_footer_cache_hash_insert( fd_footer_cache_t *    cache,
                             uchar const *          msg,
                             ulong                  msg_sz,
                             blst_p2_affine const * h ) {
  FD_TEST( msg_sz && msg_sz<=FD_FOOTER_CACHE_MSG_MAX );
  ulong i = cache->next++ % FD_FOOTER_CACHE_MSG_CNT;
  cache->e[ i ].sz = msg_sz;
  memcpy( cache->e[ i ].msg, msg, msg_sz );
  cache->e[ i ].h  = *h;
}

fd_lthash_value_t const *
fd_footer_cache_memo_query( fd_footer_cache_memo_t const * memo,
                            uchar const                    pubkey[ static FD_HASH_FOOTPRINT ],
                            uchar const                    owner[ static FD_HASH_FOOTPRINT ],
                            ulong                          lamports,
                            int                            executable,
                            uchar const *                  data,
                            ulong                          data_len ) {
  int hit = lamports && memo->lamports==lamports && memo->data_len==data_len && memo->executable==!!executable &&
            fd_memeq( memo->pubkey, pubkey, 32UL ) && fd_memeq( memo->owner, owner, 32UL ) &&
            fd_memeq( memo->data, data, data_len );
  return hit ? &memo->lthash : NULL;
}

int
fd_footer_cache_memo_insert( fd_footer_cache_memo_t * memo,
                             uchar const              pubkey[ static FD_HASH_FOOTPRINT ],
                             uchar const              owner[ static FD_HASH_FOOTPRINT ],
                             ulong                    lamports,
                             int                      executable,
                             uchar const *            data,
                             ulong                    data_len ) {
  if( FD_UNLIKELY( !lamports || data_len>FD_FOOTER_CACHE_MEMO_DATA_MAX ) ) {
    memo->lamports = 0UL;
    return 0;
  }
  fd_memcpy( memo->pubkey, pubkey, 32UL );
  fd_memcpy( memo->owner,  owner,  32UL );
  memo->lamports   = lamports;
  memo->data_len   = data_len;
  memo->executable = !!executable;
  fd_memcpy( memo->data, data, data_len );
  return 1;
}

blst_p2_affine const *
fd_footer_cache_hash_query( fd_footer_cache_t const * cache,
                            uchar const *             msg,
                            ulong                     msg_sz ) {
  FD_TEST( msg_sz && msg_sz<=FD_FOOTER_CACHE_MSG_MAX );
  for( ulong i=0UL; i<FD_FOOTER_CACHE_MSG_CNT; i++ ) {
    if( cache->e[ i ].sz==msg_sz && !memcmp( cache->e[ i ].msg, msg, msg_sz ) ) return &cache->e[ i ].h;
  }
  return NULL;
}
