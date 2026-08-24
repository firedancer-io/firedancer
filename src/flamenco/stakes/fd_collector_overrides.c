#include "fd_collector_overrides.h"
#include "../fd_rwlock.h"
#include "../../util/fd_hash32.h"

struct override_ele {
  fd_pubkey_t pubkey;
  ulong       epoch;
  fd_pubkey_t inflation; /* valid iff has_inflation */
  fd_pubkey_t block;     /* valid iff has_block */
  ulong       mask[2];   /* fork membership bits */
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
  ulong pool_off;
  ulong map_off;

  ulong  forks_used[2]; /* allocated fork id bits */
  ushort root_idx;

  fd_rwlock_t lock;
};
typedef struct fd_collector_overrides fd_collector_overrides_t;

static inline override_ele_t *
get_pool( fd_collector_overrides_t const * co ) {
  return fd_type_pun( (uchar *)co + co->pool_off );
}

static inline override_map_t *
get_map( fd_collector_overrides_t const * co ) {
  return fd_type_pun( (uchar *)co + co->map_off );
}

static inline int
mask_test( ulong const mask[2], ushort idx ) {
  return !!( mask[ idx>>6 ] & (1UL<<(idx&63UL)) );
}

static inline void
mask_set( ulong mask[2], ushort idx ) {
  mask[ idx>>6 ] |= (1UL<<(idx&63UL));
}

static inline void
mask_clear( ulong mask[2], ushort idx ) {
  mask[ idx>>6 ] &= ~(1UL<<(idx&63UL));
}

ulong
fd_collector_overrides_align( void ) {
  return FD_COLLECTOR_OVERRIDES_ALIGN;
}

ulong
fd_collector_overrides_footprint( ulong max_overrides ) {
  ulong chain_cnt = override_map_chain_cnt_est( max_overrides );

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, fd_collector_overrides_align(), sizeof(fd_collector_overrides_t) );
  l = FD_LAYOUT_APPEND( l, override_pool_align(),          override_pool_footprint( max_overrides ) );
  l = FD_LAYOUT_APPEND( l, override_map_align(),           override_map_footprint( chain_cnt ) );
  return FD_LAYOUT_FINI( l, fd_collector_overrides_align() );
}

void *
fd_collector_overrides_new( void * shmem,
                            ulong  max_overrides,
                            ulong  seed ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_collector_overrides_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  ulong chain_cnt = override_map_chain_cnt_est( max_overrides );

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_collector_overrides_t * co       = FD_SCRATCH_ALLOC_APPEND( l, fd_collector_overrides_align(), sizeof(fd_collector_overrides_t) );
  void *                     pool_mem = FD_SCRATCH_ALLOC_APPEND( l, override_pool_align(),          override_pool_footprint( max_overrides ) );
  void *                     map_mem  = FD_SCRATCH_ALLOC_APPEND( l, override_map_align(),           override_map_footprint( chain_cnt ) );

  override_ele_t * pool = override_pool_join( override_pool_new( pool_mem, max_overrides ) );
  if( FD_UNLIKELY( !pool ) ) {
    FD_LOG_WARNING(( "Failed to create collector overrides pool" ));
    return NULL;
  }

  override_map_t * map = override_map_join( override_map_new( map_mem, chain_cnt, seed ) );
  if( FD_UNLIKELY( !map ) ) {
    FD_LOG_WARNING(( "Failed to create collector overrides map" ));
    return NULL;
  }

  co->pool_off      = (ulong)pool - (ulong)shmem;
  co->map_off       = (ulong)map - (ulong)shmem;
  co->forks_used[0] = 1UL; /* root */
  co->forks_used[1] = 0UL;
  co->root_idx      = 0;

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

  ulong free0 = ~co->forks_used[0];
  ulong free1 = ~co->forks_used[1];
  ushort idx;
  if( FD_LIKELY( free0 ) )      idx = (ushort)fd_ulong_find_lsb( free0 );
  else if( FD_LIKELY( free1 ) ) idx = (ushort)( 64UL+(ulong)fd_ulong_find_lsb( free1 ) );
  else                          FD_LOG_CRIT(( "no free collector override forks" ));
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

  override_ele_t * pool = get_pool( co );
  override_map_t * map  = get_map( co );

  for( override_map_iter_t iter = override_map_iter_init( map, pool );
       !override_map_iter_done( iter, map, pool );
       iter = override_map_iter_next( iter, map, pool ) ) {
    override_ele_t * ele = override_map_iter_ele( iter, map, pool );
    if( mask_test( ele->mask, parent_idx ) && ele->epoch>=min_epoch ) {
      mask_set( ele->mask, child_idx );
    }
  }

  fd_rwlock_unwrite( &co->lock );
}

/* Removes fork_idx from every entry, freeing entries with no
   remaining fork.  Assumes the write lock is held. */

static void
release_fork( fd_collector_overrides_t * co,
              ushort                     fork_idx ) {
  override_ele_t * pool = get_pool( co );
  override_map_t * map  = get_map( co );

  for( override_map_iter_t iter = override_map_iter_init( map, pool );
       !override_map_iter_done( iter, map, pool ); ) {
    override_ele_t * ele = override_map_iter_ele( iter, map, pool );
    iter = override_map_iter_next( iter, map, pool );
    if( !mask_test( ele->mask, fork_idx ) ) continue;
    mask_clear( ele->mask, fork_idx );
    if( FD_UNLIKELY( !ele->mask[0] && !ele->mask[1] ) ) {
      FD_TEST( override_map_ele_remove_fast( map, ele, pool ) );
      override_pool_ele_release( pool, ele );
    }
  }

  mask_clear( co->forks_used, fork_idx );
}

void
fd_collector_overrides_advance_root( fd_collector_overrides_t * co,
                                     ushort                     root_idx ) {
  fd_rwlock_write( &co->lock );

  if( FD_LIKELY( root_idx==co->root_idx ) ) {
    fd_rwlock_unwrite( &co->lock );
    return;
  }

  for( ushort i=0; i<=(ushort)FD_COLLECTOR_OVERRIDES_MAX_FORK_WIDTH; i++ ) {
    if( i!=root_idx && mask_test( co->forks_used, i ) ) release_fork( co, i );
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

  override_map_reset( get_map( co ) );
  override_pool_reset( get_pool( co ) );
  co->forks_used[0] = 1UL;
  co->forks_used[1] = 0UL;
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

  override_ele_t * pool = get_pool( co );
  override_map_t * map  = get_map( co );

  /* Join an existing identical entry (captured by a sibling fork) if
     one exists. */
  for( uint idx = (uint)override_map_idx_query_const( map, pubkey, UINT_MAX, pool );
       idx!=UINT_MAX;
       idx = (uint)override_map_idx_next_const( idx, UINT_MAX, pool ) ) {
    override_ele_t * ele = override_pool_ele( pool, idx );
    if( ele->epoch!=epoch ) continue;
    if( ele->has_inflation!=(uchar)!!has_inflation ) continue;
    if( ele->has_block!=(uchar)!!has_block ) continue;
    if( has_inflation && !fd_pubkey_eq( &ele->inflation, inflation ) ) continue;
    if( has_block && !fd_pubkey_eq( &ele->block, block ) ) continue;
    mask_set( ele->mask, fork_idx );
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
  ele->mask[0]       = 0UL;
  ele->mask[1]       = 0UL;
  mask_set( ele->mask, fork_idx );
  FD_TEST( override_map_ele_insert( map, ele, pool ) );

  fd_rwlock_unwrite( &co->lock );
}

int
fd_collector_overrides_query( fd_collector_overrides_t * co,
                              ushort                     fork_idx,
                              ulong                      epoch,
                              fd_pubkey_t const *        pubkey,
                              fd_pubkey_t *              inflation_out_opt,
                              fd_pubkey_t *              block_out_opt ) {
  fd_rwlock_read( &co->lock );

  override_ele_t * pool = get_pool( co );
  override_map_t * map  = get_map( co );

  int flags = 0;
  for( uint idx = (uint)override_map_idx_query_const( map, pubkey, UINT_MAX, pool );
       idx!=UINT_MAX;
       idx = (uint)override_map_idx_next_const( idx, UINT_MAX, pool ) ) {
    override_ele_t const * ele = override_pool_ele_const( pool, idx );
    if( ele->epoch!=epoch ) continue;
    if( !mask_test( ele->mask, fork_idx ) ) continue;
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

  fd_rwlock_unread( &co->lock );
  return flags;
}

ulong
fd_collector_overrides_ele_cnt( fd_collector_overrides_t * co ) {
  fd_rwlock_read( &co->lock );
  ulong cnt = override_pool_used( get_pool( co ) );
  fd_rwlock_unread( &co->lock );
  return cnt;
}
