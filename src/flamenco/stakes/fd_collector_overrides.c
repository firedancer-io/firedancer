#include "fd_collector_overrides.h"
#include "../fd_rwlock.h"
#include "../../util/fd_hash32.h"

#include <errno.h>
#include <unistd.h>

#define FD_COLLECTOR_OVERRIDES_FORK_CNT      (FD_COLLECTOR_OVERRIDES_MAX_FORK_WIDTH+1UL)
#define FD_COLLECTOR_OVERRIDES_MASK_WORD_CNT ((FD_COLLECTOR_OVERRIDES_FORK_CNT+63UL)/64UL)

struct override_ele {
  fd_pubkey_t pubkey;
  ulong       epoch;
  fd_pubkey_t inflation; /* valid iff has_inflation */
  fd_pubkey_t block;     /* valid iff has_block */
  uint        next;      /* pool / map chain */
  uint        prev_multi;
  uint        next_multi;
  uchar       has_inflation;
  uchar       has_block;
};
typedef struct override_ele override_ele_t;

#define POOL_NAME  override_pool
#define POOL_T     override_ele_t
#define POOL_NEXT  next
#define POOL_IDX_T uint
#define POOL_LAZY  1
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME                           override_map
#define MAP_MULTI                          1
#define MAP_OPTIMIZE_RANDOM_ACCESS_REMOVAL 1
#define MAP_KEY_T                          fd_pubkey_t
#define MAP_ELE_T                          override_ele_t
#define MAP_KEY                            pubkey
#define MAP_KEY_EQ(k0,k1)                  (!memcmp( k0, k1, sizeof(fd_pubkey_t) ))
#define MAP_KEY_HASH(key,seed)             (fd_hash32( key->uc, seed ))
#define MAP_PREV                           prev_multi
#define MAP_NEXT                           next_multi
#define MAP_IDX_T                          uint
#include "../../util/tmpl/fd_map_chain.c"

#define FD_COLLECTOR_OVERRIDES_MAGIC (0xF17EDA2CC011EC70UL) /* FIREDANCER COLLECTOR V0 */

struct fd_collector_overrides {
  ulong magic;
  ulong set_sz;
  ulong pool_off;
  ulong map_off;
  ulong cache_off;
  ulong clock;
  ulong cache_age[ FD_COLLECTOR_OVERRIDES_CACHE_CNT ];
  ushort cache_fork[ FD_COLLECTOR_OVERRIDES_CACHE_CNT ];
  uchar cache_dirty[ FD_COLLECTOR_OVERRIDES_CACHE_CNT ];
  ulong forks_used[ FD_COLLECTOR_OVERRIDES_MASK_WORD_CNT ];
  ulong ele_cnt[ FD_COLLECTOR_OVERRIDES_FORK_CNT ];
  uchar disk_valid[ FD_COLLECTOR_OVERRIDES_FORK_CNT ];
  ushort root_idx;
  fd_rwlock_t lock;
};

static ulong
set_footprint( ulong max_overrides ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, override_pool_align(), override_pool_footprint( max_overrides ) );
  l = FD_LAYOUT_APPEND( l, override_map_align(), override_map_footprint( override_map_chain_cnt_est( max_overrides ) ) );
  return FD_LAYOUT_FINI( l, FD_COLLECTOR_OVERRIDES_ALIGN );
}

static inline override_ele_t *
get_pool( fd_collector_overrides_t const * co,
          void *                           set ) {
  return fd_type_pun( (uchar *)set + co->pool_off );
}

static inline override_map_t *
get_map( fd_collector_overrides_t const * co,
         void *                           set ) {
  return fd_type_pun( (uchar *)set + co->map_off );
}

/* Sets contain only relative pool/map links and can be copied verbatim.
   All cache accesses hold the write lock, including query misses. */
static void
spill_io( void * buf,
          ulong  sz,
          ulong  off,
          int    writing ) {
  ulong done = 0UL;
  while( done<sz ) {
    long n = writing ? pwrite( FD_COLLECTOR_OVERRIDES_FD, (uchar *)buf+done, sz-done, (long)(off+done) )
                     : pread ( FD_COLLECTOR_OVERRIDES_FD, (uchar *)buf+done, sz-done, (long)(off+done) );
    if( FD_UNLIKELY( n<0L && errno==EINTR ) ) continue;
    if( FD_UNLIKELY( n<=0L ) )
      FD_LOG_CRIT(( "collector overrides spill %s failed (offset=%lu, result=%ld, errno=%i)",
                    writing ? "write" : "read", off+done, n, errno ));
    done += (ulong)n;
  }
}

static void *
get_set( fd_collector_overrides_t * co,
         ushort                     fork_idx ) {
  FD_TEST( fork_idx<FD_COLLECTOR_OVERRIDES_FORK_CNT );
  ulong victim = 0UL;
  for( ulong i=0UL; i<FD_COLLECTOR_OVERRIDES_CACHE_CNT; i++ ) {
    if( co->cache_fork[i]==fork_idx ) {
      co->cache_age[i] = ++co->clock;
      return (uchar *)co + co->cache_off + i*co->set_sz;
    }
    if( co->cache_age[i]<co->cache_age[victim] ) victim = i;
  }
  void * set = (uchar *)co + co->cache_off + victim*co->set_sz;
  ushort old = co->cache_fork[victim];
  if( old!=USHORT_MAX && co->cache_dirty[victim] ) {
    spill_io( set, co->set_sz, (ulong)old*co->set_sz, 1 );
    co->disk_valid[old] = 1U;
  }
  if( co->disk_valid[fork_idx] ) spill_io( set, co->set_sz, (ulong)fork_idx*co->set_sz, 0 );
  else {
    override_pool_reset( get_pool( co, set ) );
    override_map_reset( get_map( co, set ) );
  }
  co->cache_fork[victim]  = fork_idx;
  co->cache_dirty[victim] = 0U;
  co->cache_age[victim]   = ++co->clock;
  return set;
}

static void
mark_dirty( fd_collector_overrides_t * co,
            ushort                     fork_idx ) {
  for( ulong i=0UL; i<FD_COLLECTOR_OVERRIDES_CACHE_CNT; i++ )
    if( co->cache_fork[i]==fork_idx ) co->cache_dirty[i] = 1U;
}

static inline int
mask_test( ulong const mask[ FD_COLLECTOR_OVERRIDES_MASK_WORD_CNT ],
           ushort     idx ) {
  return !!( mask[ idx>>6 ] & (1UL<<(idx&63UL)) );
}

static inline void
mask_set( ulong  mask[ FD_COLLECTOR_OVERRIDES_MASK_WORD_CNT ],
          ushort idx ) {
  mask[ idx>>6 ] |= (1UL<<(idx&63UL));
}

static inline void
mask_clear( ulong  mask[ FD_COLLECTOR_OVERRIDES_MASK_WORD_CNT ],
            ushort idx ) {
  mask[ idx>>6 ] &= ~(1UL<<(idx&63UL));
}

ulong
fd_collector_overrides_align( void ) {
  return FD_COLLECTOR_OVERRIDES_ALIGN;
}

ulong
fd_collector_overrides_footprint( ulong max_overrides ) {
  if( FD_UNLIKELY( !max_overrides || max_overrides>UINT_MAX ) ) return 0UL;
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, fd_collector_overrides_align(), sizeof(fd_collector_overrides_t) );
  l = FD_LAYOUT_APPEND( l, FD_COLLECTOR_OVERRIDES_ALIGN, FD_COLLECTOR_OVERRIDES_CACHE_CNT*set_footprint( max_overrides ) );
  return FD_LAYOUT_FINI( l, fd_collector_overrides_align() );
}

void *
fd_collector_overrides_new( void * shmem,
                            ulong  max_overrides,
                            ulong  seed ) {
  if( FD_UNLIKELY( !shmem || !fd_ulong_is_aligned( (ulong)shmem, fd_collector_overrides_align() ) ||
                    !fd_collector_overrides_footprint( max_overrides ) ) ) return NULL;
  fd_collector_overrides_t * co = shmem;
  fd_memset( co, 0, sizeof(*co) );
  co->set_sz = set_footprint( max_overrides );
  co->cache_off = fd_ulong_align_up( sizeof(*co), FD_COLLECTOR_OVERRIDES_ALIGN );
  for( ulong i=0UL; i<FD_COLLECTOR_OVERRIDES_CACHE_CNT; i++ ) {
    void * set = (uchar *)co + co->cache_off + i*co->set_sz;
    /* Initialize unused entries too: complete images are written to disk. */
    fd_memset( set, 0, co->set_sz );
    FD_SCRATCH_ALLOC_INIT( l, set );
    void * pool_mem = FD_SCRATCH_ALLOC_APPEND( l, override_pool_align(), override_pool_footprint( max_overrides ) );
    void * map_mem = FD_SCRATCH_ALLOC_APPEND( l, override_map_align(), override_map_footprint( override_map_chain_cnt_est( max_overrides ) ) );
    override_ele_t * pool = override_pool_join( override_pool_new( pool_mem, max_overrides ) );
    override_map_t * map = override_map_join( override_map_new( map_mem, override_map_chain_cnt_est( max_overrides ), seed ) );
    FD_TEST( pool && map );
    co->pool_off = (ulong)pool - (ulong)set;
    co->map_off = (ulong)map - (ulong)set;
    co->cache_fork[i] = USHORT_MAX;
  }
  co->forks_used[0] = 1UL;
  fd_rwlock_new( &co->lock );
  FD_COMPILER_MFENCE();
  FD_VOLATILE( co->magic ) = FD_COLLECTOR_OVERRIDES_MAGIC;
  FD_COMPILER_MFENCE();
  return co;
}

fd_collector_overrides_t *
fd_collector_overrides_join( void * shmem ) {
  fd_collector_overrides_t * co = (fd_collector_overrides_t *)shmem;

  if( FD_UNLIKELY( !co ) ) {
    FD_LOG_WARNING(( "NULL collector overrides" ));
    return NULL;
  }

  if( FD_UNLIKELY( co->magic!=FD_COLLECTOR_OVERRIDES_MAGIC ) ) {
    FD_LOG_WARNING(( "Invalid collector overrides magic" ));
    return NULL;
  }

  return co;
}

ushort
fd_collector_overrides_new_child( fd_collector_overrides_t * co ) {
  fd_rwlock_write( &co->lock );

  ushort idx = USHORT_MAX;
  for( ulong word_idx=0UL; word_idx<FD_COLLECTOR_OVERRIDES_MASK_WORD_CNT; word_idx++ ) {
    ulong free = ~co->forks_used[ word_idx ];
    if( FD_UNLIKELY( !free ) ) continue;
    ulong candidate = (word_idx<<6) + (ulong)fd_ulong_find_lsb( free );
    if( FD_UNLIKELY( candidate>FD_COLLECTOR_OVERRIDES_MAX_FORK_WIDTH ) ) break;
    idx = (ushort)candidate;
    break;
  }
  if( FD_UNLIKELY( idx==USHORT_MAX ) ) FD_LOG_CRIT(( "no free collector override forks" ));
  mask_set( co->forks_used, idx );

  fd_rwlock_unwrite( &co->lock );
  return idx;
}

void
fd_collector_overrides_inherit( fd_collector_overrides_t * co,
                                ushort                     parent_idx,
                                ushort                     child_idx,
                                ulong                      min_epoch ) {
  fd_rwlock_write( &co->lock );

  FD_TEST( parent_idx!=child_idx );
  FD_TEST( parent_idx<FD_COLLECTOR_OVERRIDES_FORK_CNT && child_idx<FD_COLLECTOR_OVERRIDES_FORK_CNT );
  FD_TEST( mask_test( co->forks_used, parent_idx ) && mask_test( co->forks_used, child_idx ) );
  /* Loading the parent makes it MRU. Loading the child therefore cannot
     evict the parent from the two-entry cache while we copy it. */
  void * parent_set = get_set( co, parent_idx );
  void * child_set = get_set( co, child_idx );
  override_ele_t * parent_pool = get_pool( co, parent_set );
  override_map_t * parent_map = get_map( co, parent_set );
  override_ele_t * pool = get_pool( co, child_set );
  override_map_t * map = get_map( co, child_set );
  FD_TEST( !co->ele_cnt[child_idx] );
  for( override_map_iter_t iter = override_map_iter_init( parent_map, parent_pool );
       !override_map_iter_done( iter, parent_map, parent_pool );
       iter = override_map_iter_next( iter, parent_map, parent_pool ) ) {
    override_ele_t const * src = override_map_iter_ele( iter, parent_map, parent_pool );
    if( src->epoch<min_epoch ) continue;
    FD_TEST( override_pool_free( pool ) );
    override_ele_t * dst = override_pool_ele_acquire( pool );
    *dst = *src;
    FD_TEST( override_map_ele_insert( map, dst, pool ) );
    co->ele_cnt[child_idx]++;
  }
  mark_dirty( co, child_idx );
  fd_rwlock_unwrite( &co->lock );
}

/* Discard resident and spilled state without loading a purged fork. */
static void
release_fork( fd_collector_overrides_t * co,
              ushort                     fork_idx ) {
  FD_TEST( fork_idx<FD_COLLECTOR_OVERRIDES_FORK_CNT );
  for( ulong i=0UL; i<FD_COLLECTOR_OVERRIDES_CACHE_CNT; i++ ) {
    if( co->cache_fork[i]!=fork_idx ) continue;
    co->cache_fork[i] = USHORT_MAX;
    co->cache_age[i] = 0UL;
    co->cache_dirty[i] = 0U;
  }
  co->disk_valid[fork_idx] = 0U;
  co->ele_cnt[fork_idx] = 0UL;
  mask_clear( co->forks_used, fork_idx );
}

void
fd_collector_overrides_advance_root( fd_collector_overrides_t * co,
                                     ushort                     root_idx ) {
  fd_rwlock_write( &co->lock );

  FD_TEST( root_idx<FD_COLLECTOR_OVERRIDES_FORK_CNT && mask_test( co->forks_used, root_idx ) );
  if( FD_LIKELY( root_idx==co->root_idx ) ) {
    fd_rwlock_unwrite( &co->lock );
    return;
  }

  for( ulong i=0UL; i<=FD_COLLECTOR_OVERRIDES_MAX_FORK_WIDTH; i++ ) {
    if( i!=(ulong)root_idx && mask_test( co->forks_used, (ushort)i ) ) release_fork( co, (ushort)i );
  }
  co->root_idx = root_idx;

  fd_rwlock_unwrite( &co->lock );
}

void
fd_collector_overrides_purge_child( fd_collector_overrides_t * co,
                                    ushort                     fork_idx ) {
  fd_rwlock_write( &co->lock );

  if( FD_UNLIKELY( fork_idx==co->root_idx ) ) {
    fd_rwlock_unwrite( &co->lock );
    return;
  }

  release_fork( co, fork_idx );

  fd_rwlock_unwrite( &co->lock );
}

void
fd_collector_overrides_reset( fd_collector_overrides_t * co ) {
  fd_rwlock_write( &co->lock );

  for( ulong i=0UL; i<FD_COLLECTOR_OVERRIDES_CACHE_CNT; i++ ) {
    co->cache_fork[i] = USHORT_MAX;
    co->cache_age[i] = 0UL;
    co->cache_dirty[i] = 0U;
  }
  co->clock = 0UL;
  fd_memset( co->disk_valid, 0, sizeof(co->disk_valid) );
  fd_memset( co->ele_cnt, 0, sizeof(co->ele_cnt) );
  fd_memset( co->forks_used, 0, sizeof(co->forks_used) );
  co->forks_used[0] = 1UL;
  co->root_idx      = 0;

  fd_rwlock_unwrite( &co->lock );
}

ushort
fd_collector_overrides_get_root_idx( fd_collector_overrides_t * co ) {
  fd_rwlock_read( &co->lock );
  ushort idx = co->root_idx;
  fd_rwlock_unread( &co->lock );
  return idx;
}

void
fd_collector_overrides_upsert( fd_collector_overrides_t * co,
                               ushort                     fork_idx,
                               ulong                      epoch,
                               fd_pubkey_t const *        pubkey,
                               int                        has_inflation,
                               fd_pubkey_t const *        inflation,
                               int                        has_block,
                               fd_pubkey_t const *        block ) {
  FD_TEST( has_inflation || has_block );

  fd_rwlock_write( &co->lock );

  void * set = get_set( co, fork_idx );
  override_ele_t * pool = get_pool( co, set );
  override_map_t * map  = get_map( co, set );

  /* Identical captures within a fork are idempotent. */
  for( uint idx = (uint)override_map_idx_query_const( map, pubkey, UINT_MAX, pool );
       idx!=UINT_MAX;
       idx = (uint)override_map_idx_next_const( idx, UINT_MAX, pool ) ) {
    override_ele_t * ele = override_pool_ele( pool, idx );
    if( ele->epoch!=epoch ) continue;
    if( ele->has_inflation!=(uchar)!!has_inflation ) continue;
    if( ele->has_block!=(uchar)!!has_block ) continue;
    if( has_inflation && !fd_pubkey_eq( &ele->inflation, inflation ) ) continue;
    if( has_block && !fd_pubkey_eq( &ele->block, block ) ) continue;
    fd_rwlock_unwrite( &co->lock );
    return;
  }

  if( FD_UNLIKELY( !override_pool_free( pool ) ) ) {
    FD_LOG_CRIT(( "collector overrides pool is full" ));
  }

  override_ele_t * ele = override_pool_ele_acquire( pool );
  ele->pubkey        = *pubkey;
  ele->epoch         = epoch;
  ele->has_inflation = (uchar)!!has_inflation;
  ele->has_block     = (uchar)!!has_block;
  ele->inflation     = has_inflation ? *inflation : (fd_pubkey_t){0};
  ele->block         = has_block ? *block : (fd_pubkey_t){0};
  FD_TEST( override_map_ele_insert( map, ele, pool ) );
  co->ele_cnt[fork_idx]++;
  mark_dirty( co, fork_idx );

  fd_rwlock_unwrite( &co->lock );
}

int
fd_collector_overrides_query( fd_collector_overrides_t * co,
                              ushort                     fork_idx,
                              ulong                      epoch,
                              fd_pubkey_t const *        pubkey,
                              fd_pubkey_t *              inflation_out_opt,
                              fd_pubkey_t *              block_out_opt ) {
  fd_rwlock_write( &co->lock );

  void * set = get_set( co, fork_idx );
  override_ele_t * pool = get_pool( co, set );
  override_map_t * map  = get_map( co, set );

  int flags = 0;
  for( uint idx = (uint)override_map_idx_query_const( map, pubkey, UINT_MAX, pool );
       idx!=UINT_MAX;
       idx = (uint)override_map_idx_next_const( idx, UINT_MAX, pool ) ) {
    override_ele_t const * ele = override_pool_ele_const( pool, idx );
    if( ele->epoch!=epoch ) continue;
    if( ele->has_inflation ) {
      flags |= FD_COLLECTOR_OVERRIDE_INFLATION;
      if( inflation_out_opt ) *inflation_out_opt = ele->inflation;
    }
    if( ele->has_block ) {
      flags |= FD_COLLECTOR_OVERRIDE_BLOCK;
      if( block_out_opt ) *block_out_opt = ele->block;
    }
    break;
  }

  fd_rwlock_unwrite( &co->lock );
  return flags;
}

ulong
fd_collector_overrides_ele_cnt( fd_collector_overrides_t * co ) {
  fd_rwlock_read( &co->lock );
  ulong cnt = 0UL;
  for( ulong i=0UL; i<FD_COLLECTOR_OVERRIDES_FORK_CNT; i++ ) cnt += co->ele_cnt[i];
  fd_rwlock_unread( &co->lock );
  return cnt;
}
