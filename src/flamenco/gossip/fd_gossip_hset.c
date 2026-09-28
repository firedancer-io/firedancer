#include "fd_gossip_hset.h"
#include "../../util/log/fd_log.h"

#include <string.h>

#define HSET_NULL (UINT_MAX)

static ulong
hset_lg_bucket_cnt( ulong ele_max ) {
  /* ~128 elements per bucket when full, so a pull request mask range
     (mask_bits<=12 on mainnet sized tables) covers whole buckets and
     the partially filled head chunks waste few lanes. */
  return fd_ulong_min( fd_ulong_max( (ulong)fd_ulong_find_msb( ele_max ), 8UL )-7UL, 16UL );
}

static ulong
hset_chunk_max( ulong ele_max ) {
  /* Every bucket has at most one non-full chunk. */
  return ele_max/8UL + (1UL<<hset_lg_bucket_cnt( ele_max ));
}

FD_FN_CONST ulong
fd_gossip_hset_align( void ) {
  return FD_GOSSIP_HSET_ALIGN;
}

FD_FN_CONST ulong
fd_gossip_hset_footprint( ulong ele_max ) {
  if( FD_UNLIKELY( !ele_max || !fd_ulong_is_pow2( ele_max ) || ele_max>(1UL<<31) ) ) return 0UL;
  ulong chunk_max = hset_chunk_max( ele_max );
  ulong l;
  l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, FD_GOSSIP_HSET_ALIGN, sizeof(fd_gossip_hset_t)                         );
  l = FD_LAYOUT_APPEND( l, alignof(uint),        sizeof(uint)*(1UL<<hset_lg_bucket_cnt( ele_max )) );
  l = FD_LAYOUT_APPEND( l, 64UL,                 sizeof(fd_gossip_hset_chunk_t)*chunk_max          );
  l = FD_LAYOUT_APPEND( l, 64UL,                 256UL*chunk_max                                    );
  l = FD_LAYOUT_APPEND( l, alignof(uint),        sizeof(uint)*8UL*chunk_max                         );
  l = FD_LAYOUT_APPEND( l, alignof(uint),        sizeof(uint)*ele_max                               );
  return FD_LAYOUT_FINI( l, FD_GOSSIP_HSET_ALIGN );
}

void *
fd_gossip_hset_new( void * shmem,
                    ulong  ele_max ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_gossip_hset_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_gossip_hset_footprint( ele_max ) ) ) {
    FD_LOG_WARNING(( "bad ele_max" ));
    return NULL;
  }

  ulong lg_bucket_cnt = hset_lg_bucket_cnt( ele_max );
  ulong chunk_max     = hset_chunk_max( ele_max );

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_gossip_hset_t * hset = FD_SCRATCH_ALLOC_APPEND( l, FD_GOSSIP_HSET_ALIGN, sizeof(fd_gossip_hset_t)                  );
  void * _bucket_head     = FD_SCRATCH_ALLOC_APPEND( l, alignof(uint),        sizeof(uint)*(1UL<<lg_bucket_cnt)         );
  void * _chunk           = FD_SCRATCH_ALLOC_APPEND( l, 64UL,                 sizeof(fd_gossip_hset_chunk_t)*chunk_max  );
  void * _hash            = FD_SCRATCH_ALLOC_APPEND( l, 64UL,                 256UL*chunk_max                           );
  void * _owner           = FD_SCRATCH_ALLOC_APPEND( l, alignof(uint),        sizeof(uint)*8UL*chunk_max                );
  void * _slot            = FD_SCRATCH_ALLOC_APPEND( l, alignof(uint),        sizeof(uint)*ele_max                      );
  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, FD_GOSSIP_HSET_ALIGN )==(ulong)shmem+fd_gossip_hset_footprint( ele_max ) );

  hset->ele_max       = ele_max;
  hset->chunk_max     = chunk_max;
  hset->lg_bucket_cnt = lg_bucket_cnt;
  hset->bucket_head   = (uint *)_bucket_head;
  hset->chunk         = (fd_gossip_hset_chunk_t *)_chunk;
  hset->hash          = (uchar (*)[ 32 ])_hash;
  hset->owner         = (uint *)_owner;
  hset->slot          = (uint *)_slot;

  for( ulong b=0UL; b<(1UL<<lg_bucket_cnt); b++ ) hset->bucket_head[ b ] = HSET_NULL;
  for( ulong c=0UL; c<chunk_max; c++ ) {
    hset->chunk[ c ].next = c+1UL<chunk_max ? (uint)(c+1UL) : HSET_NULL;
    hset->chunk[ c ].cnt  = 0U;
  }
  hset->chunk_free = 0U;
  /* Lanes past a chunk's cnt are read (and ignored) by bloom inserts */
  memset( _hash, 0, 256UL*chunk_max );
  for( ulong i=0UL; i<ele_max; i++ ) hset->slot[ i ] = HSET_NULL;

  FD_COMPILER_MFENCE();
  FD_VOLATILE( hset->magic ) = FD_GOSSIP_HSET_MAGIC;
  FD_COMPILER_MFENCE();

  return (void *)hset;
}

fd_gossip_hset_t *
fd_gossip_hset_join( void * shhset ) {
  if( FD_UNLIKELY( !shhset ) ) {
    FD_LOG_WARNING(( "NULL shhset" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shhset, fd_gossip_hset_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shhset" ));
    return NULL;
  }

  fd_gossip_hset_t * hset = (fd_gossip_hset_t *)shhset;

  if( FD_UNLIKELY( hset->magic!=FD_GOSSIP_HSET_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return hset;
}

static inline ulong
hset_bucket( fd_gossip_hset_t const * hset,
             uchar const *            hash ) {
  return fd_ulong_load_8( hash )>>(64UL-hset->lg_bucket_cnt);
}

void
fd_gossip_hset_insert( fd_gossip_hset_t * hset,
                       ulong              ele_idx,
                       uchar const *      hash ) {
  ulong b    = hset_bucket( hset, hash );
  ulong head = hset->bucket_head[ b ];
  if( FD_UNLIKELY( head==HSET_NULL || hset->chunk[ head ].cnt==8U ) ) {
    ulong c = hset->chunk_free;
    FD_TEST( c!=HSET_NULL ); /* impossible, see hset_chunk_max */
    hset->chunk_free       = hset->chunk[ c ].next;
    hset->chunk[ c ].next  = (uint)head;
    hset->chunk[ c ].cnt   = 0U;
    hset->bucket_head[ b ] = (uint)c;
    head = c;
  }
  ulong s = 8UL*head + hset->chunk[ head ].cnt++;
  memcpy( hset->hash[ s ], hash, 32UL );
  hset->owner[ s ]       = (uint)ele_idx;
  hset->slot[ ele_idx ]  = (uint)s;
}

void
fd_gossip_hset_remove( fd_gossip_hset_t * hset,
                       ulong              ele_idx ) {
  ulong s    = hset->slot[ ele_idx ];
  ulong b    = hset_bucket( hset, hset->hash[ s ] );
  ulong head = hset->bucket_head[ b ];
  ulong last = 8UL*head + hset->chunk[ head ].cnt - 1UL;
  if( FD_LIKELY( s!=last ) ) {
    /* Fill the hole with the head chunk's last hash */
    memcpy( hset->hash[ s ], hset->hash[ last ], 32UL );
    ulong moved = hset->owner[ last ];
    hset->owner[ s ]     = (uint)moved;
    hset->slot[ moved ]  = (uint)s;
  }
  hset->slot[ ele_idx ] = HSET_NULL;
  if( FD_UNLIKELY( !--hset->chunk[ head ].cnt ) ) {
    hset->bucket_head[ b ] = hset->chunk[ head ].next;
    hset->chunk[ head ].next = hset->chunk_free;
    hset->chunk_free = (uint)head;
  }
}

/* hset_seek sets it->chunk to the head of the first non-empty bucket
   in [it->bucket,it->bucket_end]. */

static inline void
hset_seek( fd_gossip_hset_iter_t *  it,
           fd_gossip_hset_t const * hset ) {
  ulong c = HSET_NULL;
  for( ulong b=it->bucket; b<=it->bucket_end; b++ ) {
    c = hset->bucket_head[ b ];
    if( FD_LIKELY( c!=HSET_NULL ) ) { it->bucket = b; break; }
  }
  it->chunk = c;
}

static inline void
hset_prefetch( fd_gossip_hset_t const * hset,
               ulong                    c ) {
  if( FD_UNLIKELY( c==HSET_NULL ) ) return;
  uchar const * h = hset->hash[ 8UL*c ];
  __builtin_prefetch( h     ); __builtin_prefetch( h+ 64UL );
  __builtin_prefetch( h+128 ); __builtin_prefetch( h+192UL );
  __builtin_prefetch( hset->chunk+c );
}

void
fd_gossip_hset_iter_init( fd_gossip_hset_iter_t *  it,
                          fd_gossip_hset_t const * hset,
                          ulong                    start_hash,
                          ulong                    end_hash ) {
  ulong shift = 64UL-hset->lg_bucket_cnt;
  ulong low   = (1UL<<shift)-1UL;
  it->start      = start_hash;
  it->end        = end_hash;
  it->filter     = (start_hash&low)!=0UL || (end_hash&low)!=low;
  it->bucket     = start_hash>>shift;
  it->bucket_end = end_hash>>shift;
  hset_seek( it, hset );
  if( FD_LIKELY( it->chunk!=HSET_NULL ) ) {
    hset_prefetch( hset, it->chunk );
    hset_prefetch( hset, hset->chunk[ it->chunk ].next );
  }
}

void
fd_gossip_hset_iter_next( fd_gossip_hset_iter_t *  it,
                          fd_gossip_hset_t const * hset ) {
  ulong c = hset->chunk[ it->chunk ].next;
  if( FD_UNLIKELY( c==HSET_NULL ) ) {
    it->bucket++;
    hset_seek( it, hset );
    c = it->chunk;
    if( FD_UNLIKELY( c==HSET_NULL ) ) return;
  }
  it->chunk = c;
  /* The chunk after c is usually full and random in memory; start its
     loads now so they overlap hashing c. */
  ulong n = hset->chunk[ c ].next;
  if( FD_UNLIKELY( n==HSET_NULL && it->bucket<it->bucket_end ) ) n = hset->bucket_head[ it->bucket+1UL ];
  hset_prefetch( hset, n );
}
