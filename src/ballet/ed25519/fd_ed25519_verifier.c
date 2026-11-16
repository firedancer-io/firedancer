#include "fd_ed25519_verifier.h"

#define FD_ED25519_VERIFIER_MAGIC (0xfd3d25519e71f1e0UL) /* fd ed25519 verifier ver 0 */

#define FD_ED25519_VERIFIER_CACHE_DEFAULT_ENT_CNT (2048UL)

/* verify_sigs takes the signatures in groups of at most
   FD_ED25519_VERIFIER_BATCH.  A group of at least BATCH_MIN goes
   through fd_ed25519_verify_batch8, a smaller one through
   fd_ed25519_verify_cached (fd_ed25519_verify without a cache) one
   signature at a time.  BATCH_MIN is the group size from which the
   fd_ed25519_verify_batch8 of the build beats the one-at-a-time path;
   a fd_ed25519_verify_batch8 that itself verifies one signature at a
   time never does, as a cache hit is always the cheaper path. */

#if FD_ED25519_CRC && defined(FD_ED25519_CRC_IMPL_AVX512)
#define BATCH_MIN (3UL)
#else
#define BATCH_MIN (ULONG_MAX)
#endif

/* cache_ent_cnt_resolve maps a FD_ED25519_VERIFIER_CACHE_* value or a
   cache entry count to the entry count to allocate, 0 for no cache
   and ULONG_MAX for an invalid value. */

static ulong
cache_ent_cnt_resolve( ulong cache_ent_cnt ) {
  if( cache_ent_cnt==FD_ED25519_VERIFIER_CACHE_DEFAULT ) return FD_ED25519_VERIFIER_CACHE_DEFAULT_ENT_CNT;
  if( cache_ent_cnt==FD_ED25519_VERIFIER_CACHE_OFF     ) return 0UL;
  if( FD_UNLIKELY( !fd_ed25519_cache_footprint( cache_ent_cnt ) ) ) return ULONG_MAX;
  return cache_ent_cnt;
}

struct __attribute__((aligned(FD_ED25519_VERIFIER_ALIGN))) fd_ed25519_verifier {
  ulong                magic;
  ulong                cache_ent_cnt; /* 0 without a cache */
  fd_ed25519_cache_t * cache;         /* NULL without a cache, else the join of the region after sha */
  fd_sha512_t *        sha_ptr[ FD_ED25519_VERIFIER_BATCH ]; /* scratch of one fd_ed25519_verify_batch8 call */
  fd_sha512_t          sha    [ FD_ED25519_VERIFIER_BATCH ];
};

FD_STATIC_ASSERT( FD_ED25519_CACHE_ALIGN<=FD_ED25519_VERIFIER_ALIGN, verifier_align );
FD_STATIC_ASSERT( FD_SHA512_ALIGN       <=FD_ED25519_VERIFIER_ALIGN, verifier_align );

ulong
fd_ed25519_verifier_align( void ) {
  return FD_ED25519_VERIFIER_ALIGN;
}

ulong
fd_ed25519_verifier_footprint( ulong cache_ent_cnt ) {
  ulong ent_cnt = cache_ent_cnt_resolve( cache_ent_cnt );
  if( FD_UNLIKELY( ent_cnt==ULONG_MAX ) ) return 0UL;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_ed25519_verifier_t), sizeof(fd_ed25519_verifier_t) );
  if( ent_cnt ) l = FD_LAYOUT_APPEND( l, fd_ed25519_cache_align(), fd_ed25519_cache_footprint( ent_cnt ) );
  return FD_LAYOUT_FINI( l, FD_ED25519_VERIFIER_ALIGN );
}

void *
fd_ed25519_verifier_new( void * mem,
                         ulong  cache_ent_cnt,
                         ulong  seed ) {
  if( FD_UNLIKELY( !mem ) ) { FD_LOG_WARNING(( "NULL mem" )); return NULL; }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, FD_ED25519_VERIFIER_ALIGN ) ) ) { FD_LOG_WARNING(( "misaligned mem" )); return NULL; }
  ulong ent_cnt = cache_ent_cnt_resolve( cache_ent_cnt );
  if( FD_UNLIKELY( ent_cnt==ULONG_MAX ) ) { FD_LOG_WARNING(( "bad cache_ent_cnt" )); return NULL; }

  fd_ed25519_verifier_t * verifier = (fd_ed25519_verifier_t *)mem;
  verifier->cache_ent_cnt = ent_cnt;
  verifier->cache         = NULL;
  for( ulong j=0UL; j<FD_ED25519_VERIFIER_BATCH; j++ ) {
    if( FD_UNLIKELY( !fd_sha512_new( verifier->sha+j ) ) ) { FD_LOG_WARNING(( "fd_sha512_new failed" )); return NULL; }
  }
  if( ent_cnt ) {
    if( FD_UNLIKELY( !fd_ed25519_cache_new( verifier+1, ent_cnt, seed ) ) ) { FD_LOG_WARNING(( "fd_ed25519_cache_new failed" )); return NULL; }
  }

  FD_COMPILER_MFENCE();
  verifier->magic = FD_ED25519_VERIFIER_MAGIC;
  FD_COMPILER_MFENCE();
  return mem;
}

fd_ed25519_verifier_t *
fd_ed25519_verifier_join( void * shverifier ) {
  fd_ed25519_verifier_t * verifier = (fd_ed25519_verifier_t *)shverifier;
  if( FD_UNLIKELY( !verifier ) ) { FD_LOG_WARNING(( "NULL shverifier" )); return NULL; }
  if( FD_UNLIKELY( verifier->magic!=FD_ED25519_VERIFIER_MAGIC ) ) { FD_LOG_WARNING(( "bad magic" )); return NULL; }
  for( ulong j=0UL; j<FD_ED25519_VERIFIER_BATCH; j++ ) {
    verifier->sha_ptr[ j ] = fd_sha512_join( verifier->sha+j );
    if( FD_UNLIKELY( !verifier->sha_ptr[ j ] ) ) { FD_LOG_WARNING(( "fd_sha512_join failed" )); return NULL; }
  }
  if( verifier->cache_ent_cnt ) {
    verifier->cache = fd_ed25519_cache_join( verifier+1 );
    if( FD_UNLIKELY( !verifier->cache ) ) { FD_LOG_WARNING(( "fd_ed25519_cache_join failed" )); return NULL; }
  }
  return verifier;
}

void *
fd_ed25519_verifier_leave( fd_ed25519_verifier_t * verifier ) {
  if( FD_UNLIKELY( !verifier ) ) { FD_LOG_WARNING(( "NULL verifier" )); return NULL; }
  if( verifier->cache ) fd_ed25519_cache_leave( verifier->cache );
  for( ulong j=0UL; j<FD_ED25519_VERIFIER_BATCH; j++ ) fd_sha512_leave( verifier->sha_ptr[ j ] );
  return (void *)verifier;
}

void *
fd_ed25519_verifier_delete( void * shverifier ) {
  fd_ed25519_verifier_t * verifier = (fd_ed25519_verifier_t *)shverifier;
  if( FD_UNLIKELY( !verifier ) ) { FD_LOG_WARNING(( "NULL shverifier" )); return NULL; }
  if( FD_UNLIKELY( verifier->magic!=FD_ED25519_VERIFIER_MAGIC ) ) { FD_LOG_WARNING(( "bad magic" )); return NULL; }
  if( verifier->cache_ent_cnt ) fd_ed25519_cache_delete( verifier+1 );
  for( ulong j=0UL; j<FD_ED25519_VERIFIER_BATCH; j++ ) fd_sha512_delete( verifier->sha+j );
  FD_COMPILER_MFENCE();
  verifier->magic = 0UL;
  FD_COMPILER_MFENCE();
  return shverifier;
}

int
fd_ed25519_verifier_verify( fd_ed25519_verifier_t * verifier,
                            uchar const             msg[],
                            ulong                   msg_sz,
                            uchar const             sig[ 64 ],
                            uchar const             public_key[ 32 ] ) {
  if( verifier->cache ) return fd_ed25519_verify_cached( msg, msg_sz, sig, public_key, verifier->sha_ptr[ 0 ], verifier->cache );
  return fd_ed25519_verify( msg, msg_sz, sig, public_key, verifier->sha_ptr[ 0 ] );
}

void
fd_ed25519_verifier_verify_sigs( fd_ed25519_verifier_t * verifier,
                                 uchar const * const     msgs[],
                                 ulong const             msg_szs[],
                                 uchar const * const     sigs[],
                                 uchar const * const     public_keys[],
                                 int                     results[],
                                 ulong                   sig_cnt ) {
  FD_TEST( 0UL<sig_cnt && sig_cnt<=FD_ED25519_VERIFIER_SIG_MAX );

  for( ulong j=0UL; j<sig_cnt; j+=FD_ED25519_VERIFIER_BATCH ) {
    ulong n = fd_ulong_min( sig_cnt-j, FD_ED25519_VERIFIER_BATCH );
    if( n>=BATCH_MIN ) {
      fd_ed25519_verify_batch8( msgs+j, msg_szs+j, sigs+j, public_keys+j, verifier->sha_ptr, results+j, n );
      continue;
    }
    for( ulong i=j; i<j+n; i++ ) {
      results[i] = fd_ed25519_verifier_verify( verifier, msgs[i], msg_szs[i], sigs[i], public_keys[i] );
    }
  }
}

ulong fd_ed25519_verifier_hit_cnt   ( fd_ed25519_verifier_t const * verifier ) { return verifier->cache ? fd_ed25519_cache_hit_cnt   ( verifier->cache ) : 0UL; }
ulong fd_ed25519_verifier_miss_cnt  ( fd_ed25519_verifier_t const * verifier ) { return verifier->cache ? fd_ed25519_cache_miss_cnt  ( verifier->cache ) : 0UL; }
ulong fd_ed25519_verifier_insert_cnt( fd_ed25519_verifier_t const * verifier ) { return verifier->cache ? fd_ed25519_cache_insert_cnt( verifier->cache ) : 0UL; }
