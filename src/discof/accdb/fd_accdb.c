#define _GNU_SOURCE
#include "fd_accdb.h"
#include "fd_accdb_shmem.h"
#define FD_ACCDB_NO_FORK_ID
#include "fd_accdb_private.h"
#undef FD_ACCDB_NO_FORK_ID

#include "../../flamenco/fd_rwlock.h"
#include "../../ballet/txn/fd_txn.h"

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/uio.h>

static inline void
spin_lock_acquire( int * lock ) {
# if FD_HAS_THREADS
  for(;;) {
    if( FD_LIKELY( !FD_ATOMIC_CAS( lock, 0, 1 ) ) ) break;
    FD_SPIN_PAUSE();
  }
# else
  *lock = 1;
# endif
  FD_COMPILER_MFENCE();
}

static inline void
spin_lock_release( int * lock ) {
  FD_COMPILER_MFENCE();
# if FD_HAS_THREADS
  FD_VOLATILE( *lock ) = 0;
# else
  *lock = 0;
# endif
}

struct fd_accdb_fork {
  fd_accdb_fork_shmem_t * shmem;
  descends_set_t * descends;
};

typedef struct fd_accdb_fork fd_accdb_fork_t;

struct fd_accdb_metrics {
  ulong accounts_acquired;
  ulong accounts_acquired_cache_hit;

  ulong accounts_released;
  ulong accounts_released_dirty;
};

struct __attribute__((aligned(FD_ACCDB_ALIGN))) fd_accdb_private {
  int fd;

  fd_accdb_shmem_t * shmem;

  fd_accdb_fork_t * fork_pool;
  fd_accdb_fork_shmem_t * fork_shmem_pool;

  fd_accdb_acc_t * acc_pool;
  uint * acc_map;

  fd_accdb_cache_map_t * cache_map;
  fd_accdb_cache_line_t * cache [ FD_ACCDB_CACHE_CLASS_CNT ];

  cache_dlist_t * cache_lru[ FD_ACCDB_CACHE_CLASS_CNT ];

  fd_accdb_partition_t * partition_pool;
  compaction_dlist_t * compaction_dlist[ FD_ACCDB_COMPACTION_LAYER_CNT ];
  deferred_free_dlist_t * deferred_free_dlist;

  fd_accdb_txn_t * txn_pool;

  long credit[ FD_ACCDB_CACHE_CLASS_CNT ];

  /* Pointer into shmem->joiner_epochs[ my_slot ].  Set to the current
     global epoch on rwlock-read entry, and ULONG_MAX on exit.  Used by
     compaction to determine when deferred partition frees are safe. */
  ulong * my_epoch_slot;
};

FD_FN_CONST ulong
fd_accdb_align( void ) {
  return FD_ACCDB_ALIGN;
}

FD_FN_CONST ulong
fd_accdb_footprint( ulong max_live_slots ) {
  ulong l;
  l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, FD_ACCDB_ALIGN,           sizeof(fd_accdb_t)                     );
  l = FD_LAYOUT_APPEND( l, alignof(fd_accdb_fork_t), max_live_slots*sizeof(fd_accdb_fork_t) );
  return FD_LAYOUT_FINI( l, FD_ACCDB_ALIGN );
}

void *
fd_accdb_new( void *             ljoin,
              fd_accdb_shmem_t * shmem,
              int                fd ) {
  if( FD_UNLIKELY( !ljoin ) ) {
    FD_LOG_WARNING(( "NULL ljoin" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)ljoin, fd_accdb_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned ljoin" ));
    return NULL;
  }

  if( FD_UNLIKELY( fd<0 ) ) {
    FD_LOG_WARNING(( "fd must be a valid file descriptor" ));
    return NULL;
  }

  ulong max_live_slots = shmem->max_live_slots;
  ulong max_accounts = shmem->max_accounts;
  ulong max_account_writes_per_slot = shmem->max_account_writes_per_slot;
  ulong partition_cnt = shmem->partition_cnt;

  ulong chain_cnt = fd_ulong_pow2_up( (max_accounts>>1) + (max_accounts&1UL) );
  ulong txn_max = max_live_slots * max_account_writes_per_slot;

  ulong total_cache_slots = 0UL;
  for( ulong c=0UL; c<FD_ACCDB_CACHE_CLASS_CNT; c++ ) total_cache_slots += shmem->cache_class_max[ c ];

  FD_SCRATCH_ALLOC_INIT( l, shmem );
                             FD_SCRATCH_ALLOC_APPEND( l, FD_ACCDB_SHMEM_ALIGN,     sizeof(fd_accdb_shmem_t)                                );
  void * _fork_pool        = FD_SCRATCH_ALLOC_APPEND( l, fork_pool_align(),        fork_pool_footprint( max_live_slots )                   );
  void * _descends_sets    = FD_SCRATCH_ALLOC_APPEND( l, descends_set_align(),     max_live_slots*descends_set_footprint( max_live_slots ) );
  void * _cache_map        = FD_SCRATCH_ALLOC_APPEND( l, cache_map_align(),        cache_map_footprint( total_cache_slots )                );
  void * _acc_map          = FD_SCRATCH_ALLOC_APPEND( l, alignof(uint),            chain_cnt*sizeof(uint)                                  );
  void * _acc_pool         = FD_SCRATCH_ALLOC_APPEND( l, acc_pool_align(),         acc_pool_footprint( max_accounts )                      );
  void * _txn_pool         = FD_SCRATCH_ALLOC_APPEND( l, txn_pool_align(),         txn_pool_footprint( txn_max )                           );
  void * _partition_pool   = FD_SCRATCH_ALLOC_APPEND( l, partition_pool_align(),   partition_pool_footprint( partition_cnt )               );
  void * _compaction_dlists[ FD_ACCDB_COMPACTION_LAYER_CNT ];
  for( ulong k=0UL; k<FD_ACCDB_COMPACTION_LAYER_CNT; k++ ) {
    _compaction_dlists[ k ] = FD_SCRATCH_ALLOC_APPEND( l, compaction_dlist_align(), compaction_dlist_footprint()                           );
  }
  void * _deferred_free_dlist = FD_SCRATCH_ALLOC_APPEND( l, deferred_free_dlist_align(), deferred_free_dlist_footprint()                   );

  FD_SCRATCH_ALLOC_INIT( l2, ljoin );
  fd_accdb_t * accdb      = FD_SCRATCH_ALLOC_APPEND( l2, fd_accdb_align(),         sizeof(fd_accdb_t)                     );
  void * _local_fork_pool = FD_SCRATCH_ALLOC_APPEND( l2, alignof(fd_accdb_fork_t), max_live_slots*sizeof(fd_accdb_fork_t) );

  accdb->fd = fd;

  accdb->shmem = (fd_accdb_shmem_t *)shmem;
  accdb->acc_pool = acc_pool_join( _acc_pool );
  FD_TEST( accdb->acc_pool );
  accdb->acc_map = _acc_map;
  accdb->txn_pool = txn_pool_join( _txn_pool );
  FD_TEST( accdb->txn_pool );
  accdb->cache_map = cache_map_join( _cache_map );
  FD_TEST( accdb->cache_map );
  accdb->partition_pool = partition_pool_join( _partition_pool );
  FD_TEST( accdb->partition_pool );
  for( ulong k=0UL; k<FD_ACCDB_COMPACTION_LAYER_CNT; k++ ) {
    accdb->compaction_dlist[ k ] = compaction_dlist_join( _compaction_dlists[ k ] );
    FD_TEST( accdb->compaction_dlist[ k ] );
  }
  accdb->deferred_free_dlist = deferred_free_dlist_join( _deferred_free_dlist );
  FD_TEST( accdb->deferred_free_dlist );

  accdb->fork_shmem_pool = fork_pool_join( _fork_pool );
  FD_TEST( accdb->fork_shmem_pool );
  accdb->fork_pool = _local_fork_pool;
  for( ulong i=0UL; i<max_live_slots; i++ ) {
    fd_accdb_fork_t * fork = &accdb->fork_pool[ i ];
    fork->shmem = &accdb->fork_shmem_pool[ i ];
    fork->descends = descends_set_join( (uchar *)_descends_sets + i*descends_set_footprint( max_live_slots ) );
    FD_TEST( fork->shmem );
    FD_TEST( fork->descends );
  }

  memset( accdb->credit, 0, sizeof( accdb->credit ) );

  ulong epoch_idx = FD_ATOMIC_FETCH_AND_ADD( &shmem->joiner_cnt, 1UL );
  FD_TEST( epoch_idx<FD_ACCDB_MAX_JOINERS );
  accdb->my_epoch_slot = &shmem->joiner_epochs[ epoch_idx ];

  return accdb;
}

fd_accdb_t *
fd_accdb_join( void * shaccdb ) {
  if( FD_UNLIKELY( !shaccdb ) ) {
    FD_LOG_WARNING(( "NULL shaccdb" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shaccdb, fd_accdb_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shaccdb" ));
    return NULL;
  }

  return (fd_accdb_t*)shaccdb;
}

fd_accdb_fork_id_t
fd_accdb_attach_child( fd_accdb_t *       accdb,
                       fd_accdb_fork_id_t parent_fork_id ) {
  fd_rwlock_write( accdb->shmem->lock );

  FD_TEST( fork_pool_free( accdb->fork_shmem_pool ) );
  ulong idx = fork_pool_idx_acquire( accdb->fork_shmem_pool );

  fd_accdb_fork_t * fork = &accdb->fork_pool[ idx ];
  fd_accdb_fork_id_t fork_id = { .val = (ushort)idx };

  fork->shmem->child_id = (fd_accdb_fork_id_t){ .val = USHORT_MAX };

  if( FD_LIKELY( parent_fork_id.val==USHORT_MAX ) ) {
    FD_TEST( fork_pool_free( accdb->fork_shmem_pool )==fork_pool_max( accdb->fork_shmem_pool )-1UL );
    fork->shmem->parent_id  = (fd_accdb_fork_id_t){ .val = USHORT_MAX };
    fork->shmem->sibling_id = (fd_accdb_fork_id_t){ .val = USHORT_MAX };

    descends_set_null( fork->descends );
    accdb->shmem->root_fork_id = fork_id;
  } else {
    fd_accdb_fork_t * parent = &accdb->fork_pool[ parent_fork_id.val ];
    fork->shmem->sibling_id = parent->shmem->child_id;
    fork->shmem->parent_id  = parent_fork_id;
    parent->shmem->child_id = fork_id;

    descends_set_copy( fork->descends, parent->descends );
    descends_set_insert( fork->descends, parent_fork_id.val );
  }

  fork->shmem->generation = accdb->shmem->generation++;
  fork->shmem->txn_head = UINT_MAX;

  fd_rwlock_unwrite( accdb->shmem->lock );
  return fork_id;
}

static inline fd_accdb_cache_line_t *
cache_query( fd_accdb_t *  accdb,
             uchar const * pubkey,
             ulong         generation ) {
  ulong hash = generation ^ fd_funk_rec_key_hash1( pubkey, accdb->cache_map->seed );
  uint * chains = fd_accdb_cm_chains( accdb->cache_map );
  fd_accdb_cache_entry_t * entries = fd_accdb_cm_entries( accdb->cache_map );

  uint idx = chains[ hash & (accdb->cache_map->chain_cnt-1UL) ];
  while( idx!=UINT_MAX ) {
    fd_accdb_cache_entry_t * e = &entries[ idx ];
    fd_accdb_acc_t const * acc = &accdb->acc_pool[ e->acc_idx ];
    if( FD_LIKELY( acc->generation==generation && !memcmp( acc->pubkey, pubkey, 32UL ) ) ) {
      return &accdb->cache[ FD_ACCDB_CACHE_PACK_CLASS( e->cache_idx ) ][ FD_ACCDB_CACHE_PACK_IDX( e->cache_idx ) ];
    }
    idx = e->next;
  }
  return NULL;
}

static inline void
cache_remove( fd_accdb_t *            accdb,
              fd_accdb_cache_line_t * line ) {
  uint * chains = fd_accdb_cm_chains( accdb->cache_map );
  fd_accdb_cache_entry_t * entries = fd_accdb_cm_entries( accdb->cache_map );
  fd_accdb_cache_entry_t * e = &entries[ line->cache_idx ];

  if( FD_LIKELY( e->prev!=UINT_MAX ) ) {
    entries[ e->prev ].next = e->next;
  } else {
    fd_accdb_acc_t const * acc = &accdb->acc_pool[ e->acc_idx ];
    ulong hash = acc->generation ^ fd_funk_rec_key_hash1( acc->pubkey, accdb->cache_map->seed );
    chains[ hash & (accdb->cache_map->chain_cnt-1UL) ] = e->next;
  }

  if( FD_LIKELY( e->next!=UINT_MAX ) ) entries[ e->next ].prev = e->prev;

  e->next = accdb->cache_map->free_head;
  accdb->cache_map->free_head = line->cache_idx;
  line->key.generation = ULONG_MAX;
}

static inline void
cache_insert( fd_accdb_t *            accdb,
              fd_accdb_cache_line_t * line,
              uint                    acc_idx,
              ulong                   size_class ) {
  fd_accdb_acc_t const * key_acc = &accdb->acc_pool[ acc_idx ];

  ulong hash = key_acc->generation ^ fd_funk_rec_key_hash1( key_acc->pubkey, accdb->cache_map->seed );
  uint * chains = fd_accdb_cm_chains( accdb->cache_map );
  fd_accdb_cache_entry_t * entries = fd_accdb_cm_entries( accdb->cache_map );
  ulong chain_idx = hash & (accdb->cache_map->chain_cnt-1UL);

  FD_TEST( accdb->cache_map->free_head!=UINT_MAX );
  uint entry_idx = accdb->cache_map->free_head;
  fd_accdb_cache_entry_t * e = &entries[ entry_idx ];
  accdb->cache_map->free_head = e->next;

  e->acc_idx   = acc_idx;
  e->cache_idx = FD_ACCDB_CACHE_PACK( size_class, (ulong)( line - accdb->cache[ size_class ] ) );
  e->prev      = UINT_MAX;
  e->next      = chains[ chain_idx ];
  if( FD_LIKELY( e->next!=UINT_MAX ) ) entries[ e->next ].prev = entry_idx;
  chains[ chain_idx ] = entry_idx;

  line->cache_idx = entry_idx;
}

static void
purge_inner( fd_accdb_t *       accdb,
                fd_accdb_fork_id_t fork_id ) {
  fd_accdb_fork_t * fork = &accdb->fork_pool[ fork_id.val ];

  fd_accdb_fork_id_t child = fork->shmem->child_id;
  while( child.val!=USHORT_MAX ) {
    fd_accdb_fork_id_t next = accdb->fork_pool[ child.val ].shmem->sibling_id;
    purge_inner( accdb, child );
    child = next;
  }

  uint txn = fork->shmem->txn_head;
  while( txn!=UINT_MAX ) {
    fd_accdb_txn_t * txne = txn_pool_ele( accdb->txn_pool, txn );

    fd_accdb_acc_t * acc = &accdb->acc_pool[ txne->acc_pool_idx ];

    if( FD_LIKELY( acc->offset!=ULONG_MAX ) ) {
      fd_accdb_shmem_bytes_freed( accdb->shmem, acc->offset, (ulong)acc->size+sizeof(fd_accdb_disk_meta_t) );
      accdb->shmem->metrics->disk_used_bytes -= (ulong)acc->size+sizeof(fd_accdb_disk_meta_t);
    }
    accdb->shmem->metrics->accounts_total--;

    uint prev = UINT_MAX;
    uint cur = accdb->acc_map[ txne->acc_map_idx ];
    while( cur!=(uint)(acc-accdb->acc_pool) ) {
      prev = cur;
      cur = accdb->acc_pool[ cur ].map.next;
    }

    if( FD_LIKELY( prev==UINT_MAX ) ) accdb->acc_map[ txne->acc_map_idx ] = acc->map.next;
    else                              accdb->acc_pool[ prev ].map.next = acc->map.next;

    /* If the freed acc is still referenced by a cache line, remove it
       so the eviction path does not try to write back stale data from a
       recycled pool slot. */
    fd_accdb_cache_line_t * stale = cache_query( accdb, acc->pubkey, acc->generation );
    if( FD_UNLIKELY( stale ) ) {
      cache_remove( accdb, stale );
      stale->persisted = 1;
    }

    acc_pool_idx_release( accdb->acc_pool, (uint)(acc-accdb->acc_pool) );

    txn = txne->fork.next;
    txn_pool_ele_release( accdb->txn_pool, txne );
  }

  for( ulong i=0UL; i<accdb->shmem->max_live_slots; i++ ) descends_set_remove( accdb->fork_pool[ i ].descends, fork_id.val );

  fork_pool_idx_release( accdb->fork_shmem_pool, fork_id.val );
}

static inline void
remove_children( fd_accdb_t *      accdb,
                 fd_accdb_fork_t * fork,
                 fd_accdb_fork_t * except ) {
  fd_accdb_fork_id_t sibling_idx = fork->shmem->child_id;
  while( sibling_idx.val!=USHORT_MAX ) {
    fd_accdb_fork_t * sibling = &accdb->fork_pool[ sibling_idx.val ];
    fd_accdb_fork_id_t cur_idx = sibling_idx;

    sibling_idx = sibling->shmem->sibling_id;
    if( FD_UNLIKELY( sibling==except ) ) continue;

    purge_inner( accdb, cur_idx );
  }
}

void
fd_accdb_advance_root( fd_accdb_t *       accdb,
                       fd_accdb_fork_id_t fork_id ) {
  fd_rwlock_write( accdb->shmem->lock );

  /* The caller guarantees that rooting is sequential: each call
     advances the root by exactly one slot (the immediate child of the
     current root).  Skipping levels is not supported. */
  fd_accdb_fork_t * fork = &accdb->fork_pool[ fork_id.val ];
  FD_TEST( fork->shmem->parent_id.val==accdb->shmem->root_fork_id.val );
  FD_TEST( fork->shmem->parent_id.val!=USHORT_MAX );

  fd_accdb_fork_t * parent_fork = &accdb->fork_pool[ fork->shmem->parent_id.val ];

  /* When a fork is rooted, any competing forks can be immediately
     removed as they will not be needed again.  This includes child
     forks of the pruned siblings as well. */
  remove_children( accdb, parent_fork, fork );

  /* And for any accounts which were updated in the newly rooted slot,
     we will now never need to access any older version, so we can
     discard any slots earlier than the one we are rooting. */
  uint txn = fork->shmem->txn_head;
  while( txn!=UINT_MAX ) {
    fd_accdb_txn_t * txne = txn_pool_ele( accdb->txn_pool, txn );

    fd_accdb_acc_t const * new_acc = &accdb->acc_pool[ txne->acc_pool_idx ];

    uint prev = UINT_MAX;
    uint acc = accdb->acc_map[ txne->acc_map_idx ];
    FD_TEST( acc!=UINT_MAX );
    while( acc!=UINT_MAX ) {
      fd_accdb_acc_t const * cur_acc = &accdb->acc_pool[ acc ];
      if( FD_LIKELY( cur_acc->map.next!=UINT_MAX ) ) __builtin_prefetch( &accdb->acc_pool[ cur_acc->map.next ], 0, 0 );

      if( FD_LIKELY( acc==txne->acc_pool_idx ) ) {
        prev = acc;
        acc = cur_acc->map.next;
        continue;
      }

      if( FD_LIKELY( (cur_acc->generation<=parent_fork->shmem->generation || descends_set_test( fork->descends, cur_acc->fork_id ) ) && !memcmp( new_acc->pubkey, cur_acc->pubkey, 32UL ) ) ) {
        if( FD_LIKELY( cur_acc->offset!=ULONG_MAX ) ) {
          fd_accdb_shmem_bytes_freed( accdb->shmem, cur_acc->offset, (ulong)cur_acc->size+sizeof(fd_accdb_disk_meta_t) );
          accdb->shmem->metrics->disk_used_bytes -= (ulong)cur_acc->size+sizeof(fd_accdb_disk_meta_t);
        }
        accdb->shmem->metrics->accounts_total--;

        uint next = cur_acc->map.next;

        if( FD_LIKELY( prev==UINT_MAX ) ) accdb->acc_map[ txne->acc_map_idx ] = next;
        else                              accdb->acc_pool[ prev ].map.next = next;

        /* If the freed acc is still referenced by a cache line, remove
           it so the eviction path does not try to write back stale data
           from a recycled pool slot. */
        fd_accdb_cache_line_t * stale = cache_query( accdb, cur_acc->pubkey, cur_acc->generation );
        if( FD_UNLIKELY( stale ) ) {
          cache_remove( accdb, stale );
          stale->persisted = 1;
        }

        acc_pool_idx_release( accdb->acc_pool, acc );
        acc = next;
      } else {
        prev = acc;
        acc = cur_acc->map.next;
      }
    }

    txn = txne->fork.next;
    txn_pool_ele_release( accdb->txn_pool, txne );
  }

  uint parent_txn = parent_fork->shmem->txn_head;
  while( parent_txn!=UINT_MAX ) {
    fd_accdb_txn_t * t = txn_pool_ele( accdb->txn_pool, parent_txn );
    parent_txn = t->fork.next;
    txn_pool_ele_release( accdb->txn_pool, t );
  }

  /* Remove the parent from all descends_sets before freeing its slot,
     so that when the slot is recycled to a new fork, existing forks do
     not incorrectly treat the new fork as an ancestor.  Entries from
     the freed parent are still visible via the generation <=
     root_generation fast path in reads. */
  for( ulong i=0UL; i<accdb->shmem->max_live_slots; i++ ) descends_set_remove( accdb->fork_pool[ i ].descends, fork->shmem->parent_id.val );

  fork_pool_idx_release( accdb->fork_shmem_pool, fork->shmem->parent_id.val );
  fork->shmem->parent_id  = (fd_accdb_fork_id_t){ .val = USHORT_MAX };
  fork->shmem->sibling_id = (fd_accdb_fork_id_t){ .val = USHORT_MAX };
  fork->shmem->txn_head   = UINT_MAX;
  descends_set_null( fork->descends );
  accdb->shmem->root_fork_id = fork_id;

  fd_rwlock_unwrite( accdb->shmem->lock );
}

void
fd_accdb_purge( fd_accdb_t *       accdb,
                fd_accdb_fork_id_t fork_id ) {
  FD_TEST( fork_id.val!=accdb->shmem->root_fork_id.val );

  fd_rwlock_write( accdb->shmem->lock );

  /* Unlink fork_id from its parent's child list before freeing, so the
     parent does not retain a dangling reference to the recycled slot. */
  fd_accdb_fork_t * fork = &accdb->fork_pool[ fork_id.val ];
  fd_accdb_fork_id_t parent_id = fork->shmem->parent_id;
  if( FD_LIKELY( parent_id.val!=USHORT_MAX ) ) {
    fd_accdb_fork_t * parent = &accdb->fork_pool[ parent_id.val ];
    if( FD_UNLIKELY( parent->shmem->child_id.val==fork_id.val ) ) {
      parent->shmem->child_id = fork->shmem->sibling_id;
    } else {
      fd_accdb_fork_id_t prev_id = parent->shmem->child_id;
      while( prev_id.val!=USHORT_MAX ) {
        fd_accdb_fork_t * prev = &accdb->fork_pool[ prev_id.val ];
        if( prev->shmem->sibling_id.val==fork_id.val ) {
          prev->shmem->sibling_id = fork->shmem->sibling_id;
          break;
        }
        prev_id = prev->shmem->sibling_id;
      }
    }
  }

  purge_inner( accdb, fork_id );
  fd_rwlock_unwrite( accdb->shmem->lock );
}

static inline fd_accdb_cache_line_t *
acquire_cache_line( fd_accdb_t * accdb,
                    ulong        size_class,
                    uint *       out_evicted_acc_idx ) {
  if( FD_LIKELY( accdb->shmem->cache_class_init[ size_class ]<accdb->shmem->cache_class_max[ size_class ] ) ) {
    fd_accdb_cache_line_t * result = &accdb->cache[ size_class ][ accdb->shmem->cache_class_init[ size_class ] ];
    accdb->shmem->cache_class_init[ size_class ]++;
    result->refcnt = 0;
    result->persisted = 1;
    result->acc_idx = UINT_MAX;
    result->key.generation = ULONG_MAX;
    *out_evicted_acc_idx = UINT_MAX;
    return result;
  } else {
    FD_TEST( !cache_dlist_is_empty( accdb->cache_lru[ size_class ], accdb->cache[ size_class ] ) );
    fd_accdb_cache_line_t * result = cache_dlist_ele_pop_tail( accdb->cache_lru[ size_class ], accdb->cache[ size_class ] );
    FD_TEST( !result->refcnt );
    if( FD_LIKELY( result->key.generation!=ULONG_MAX ) ) cache_remove( accdb, result );
    *out_evicted_acc_idx = result->persisted ? UINT_MAX : result->acc_idx;
    result->acc_idx = UINT_MAX;
    result->key.generation = ULONG_MAX;
    return result;
  }
}

#define FD_ACCDB_PARTITION_OFF_BITS 52UL

static FD_FN_CONST inline accdb_offset_t
accdb_offset( ulong partition_idx,
              ulong partition_offset ) {
  return (accdb_offset_t){ .val = (partition_idx<<FD_ACCDB_PARTITION_OFF_BITS) | partition_offset };
}

static FD_FN_CONST inline ulong
packed_partition_idx( accdb_offset_t offset ) {
  return offset.val>>FD_ACCDB_PARTITION_OFF_BITS;
}

static FD_FN_CONST inline ulong
packed_partition_offset( accdb_offset_t offset ) {
  return offset.val & ((1UL<<FD_ACCDB_PARTITION_OFF_BITS)-1UL);
}

static FD_FN_CONST inline ulong
packed_partition_file_offset( accdb_offset_t offset,
                              ulong          partition_sz ) {
   return (packed_partition_idx( offset )*partition_sz + packed_partition_offset( offset ));
}

static inline void
change_partition( fd_accdb_t *     accdb,
                  accdb_offset_t   offset_before,
                  accdb_offset_t * out_offset,
                  int *            has_partition,
                  uchar            layer ) {
  /* New data will not fit in the current partition, so we need to
     move to the next one.  */
  ulong partition_idx_before = packed_partition_idx( offset_before );
  ulong partition_offset_before = packed_partition_offset( offset_before );
  if( FD_LIKELY( *has_partition ) ) {
    fd_accdb_partition_t * before = partition_pool_ele( accdb->partition_pool, partition_idx_before );
    before->write_offset = partition_offset_before;
  }

  ulong free_offset = packed_partition_file_offset( offset_before, accdb->shmem->partition_sz );
  ulong free_size = accdb->shmem->partition_sz - partition_offset_before;
  if( FD_LIKELY( *has_partition ) ) fd_accdb_shmem_bytes_freed( accdb->shmem, free_offset, free_size );

  if( FD_UNLIKELY( !partition_pool_free( accdb->partition_pool ) ) ) FD_LOG_ERR(( "accounts database file is at capacity" ));
  fd_accdb_partition_t * partition = partition_pool_ele_acquire( accdb->partition_pool );
  partition->bytes_freed       = 0UL;
  partition->marked_compaction = 0;
  partition->layer             = layer;

  ulong new_partition_idx = partition_pool_idx( accdb->partition_pool, partition );
  *out_offset   = accdb_offset( new_partition_idx, 0UL );
  *has_partition = 1;

  if( FD_UNLIKELY( new_partition_idx>=accdb->shmem->partition_max ) ) {
    FD_LOG_NOTICE(( "growing accounts database from %lu MiB to %lu MiB", accdb->shmem->partition_max*accdb->shmem->partition_sz/(1UL<<20UL), (new_partition_idx+1UL)*accdb->shmem->partition_sz/(1UL<<20UL) ));

    int result = fallocate( accdb->fd, 0, (long)(new_partition_idx*accdb->shmem->partition_sz), (long)accdb->shmem->partition_sz );
    if( FD_UNLIKELY( -1==result ) ) {
      if( FD_LIKELY( errno==ENOSPC ) ) FD_LOG_ERR(( "fallocate() failed (%d-%s). The accounts database filled "
                                                    "the disk it is on, trying to grow from %lu MiB to %lu MiB. Please "
                                                    "free up disk space and restart the validator.",
                                                    errno, fd_io_strerror( errno ), accdb->shmem->partition_max*accdb->shmem->partition_sz/(1UL<<20UL), (new_partition_idx+1UL)*accdb->shmem->partition_sz/(1UL<<20UL) ));
      else FD_LOG_ERR(( "fallocate() failed (%d-%s)", errno, fd_io_strerror( errno ) ));
    }

    /* CAS loop: the compaction tile may also be growing the file
       concurrently, so neither path may clobber the other. */
    for(;;) {
      ulong cur = accdb->shmem->partition_max;
      if( FD_LIKELY( new_partition_idx+1UL<=cur ) ) break;
      if( FD_LIKELY( FD_ATOMIC_CAS( &accdb->shmem->partition_max, cur, new_partition_idx+1UL )==cur ) ) break;
    }
    accdb->shmem->metrics->disk_allocated_bytes = accdb->shmem->partition_max*accdb->shmem->partition_sz;
  }
}

static inline ulong
allocate_next_write( fd_accdb_t * accdb,
                     ulong        sz ) {
  for(;;) {
    accdb_offset_t offset = { .val = FD_ATOMIC_FETCH_AND_ADD( &accdb->shmem->whead[ 0 ].val, sz ) };
    if( FD_LIKELY( packed_partition_offset( offset )+sz<=accdb->shmem->partition_sz ) ) return packed_partition_file_offset( offset, accdb->shmem->partition_sz );

    if( FD_UNLIKELY( packed_partition_offset( offset )>accdb->shmem->partition_sz ) ) {
      /* This can happen if another thread also raced to allocate the
         next write and won.  Wait for the partition switch to finish
         before retrying, so we do not keep doing fetch-and-adds that
         advance the offset further past the boundary. */
      while( FD_VOLATILE_CONST( accdb->shmem->partition_lock ) ) FD_SPIN_PAUSE();
      continue;
    }

    spin_lock_acquire( &accdb->shmem->partition_lock );
    change_partition( accdb, offset, &accdb->shmem->whead[ 0 ], &accdb->shmem->has_partition[ 0 ], 0 );
    spin_lock_release( &accdb->shmem->partition_lock );
  }
}

/* Compaction write allocation.  Single-threaded: only the compaction
   tile calls these, so the compaction write heads do not need atomic
   fetch-and-add.  dest_layer is the target layer (1..N-1). */

static inline ulong
allocate_next_compaction_write( fd_accdb_t * accdb,
                                ulong        sz,
                                ulong        dest_layer ) {
  accdb_offset_t offset = accdb->shmem->whead[ dest_layer ];
  if( FD_UNLIKELY( packed_partition_offset( offset )+sz>accdb->shmem->partition_sz ) ) {
    spin_lock_acquire( &accdb->shmem->partition_lock );
    change_partition( accdb, offset, &accdb->shmem->whead[ dest_layer ], &accdb->shmem->has_partition[ dest_layer ], (uchar)dest_layer );
    spin_lock_release( &accdb->shmem->partition_lock );
    offset = accdb->shmem->whead[ dest_layer ];
  }
  accdb->shmem->whead[ dest_layer ].val += sz;
  return packed_partition_file_offset( offset, accdb->shmem->partition_sz );
}

/* fd_accdb_compact relocates one record from the oldest partition
   queued for compaction at src_layer into the write head for the
   next colder tier, or the same tier for the deepest layer.  It is
   designed to be called repeatedly from a dedicated compaction tile.
   If there is work to do, *charge_busy is set to 1; otherwise 0 is
   left unchanged and the call returns immediately.

   src_layer must be in 0..FD_ACCDB_COMPACTION_LAYER_CNT-1. */

void
fd_accdb_compact( fd_accdb_t * accdb,
                  ulong        src_layer,
                  int *        charge_busy ) {
  fd_rwlock_read( accdb->shmem->lock );
  FD_COMPILER_MFENCE();
  FD_VOLATILE( *accdb->my_epoch_slot ) = FD_VOLATILE_CONST( accdb->shmem->epoch );
  FD_COMPILER_MFENCE();

  /* Reclaim any deferred-free partitions whose epoch has been observed
     by all joiners (i.e. no rwlock-read holder could still be
     referencing data in them). */
  ulong min_epoch = ULONG_MAX;
  ulong joiner_cnt = FD_VOLATILE_CONST( accdb->shmem->joiner_cnt );
  for( ulong t=0UL; t<joiner_cnt; t++ ) {
    ulong e = FD_VOLATILE_CONST( accdb->shmem->joiner_epochs[ t ] );
    if( FD_LIKELY( e<min_epoch ) ) min_epoch = e;
  }
  for(;;) {
    fd_accdb_partition_t * p = deferred_free_dlist_ele_peek_head( accdb->deferred_free_dlist, accdb->partition_pool );
    if( FD_LIKELY( !p || p->epoch_tag>=min_epoch ) ) break;

    spin_lock_acquire( &accdb->shmem->partition_lock );
    deferred_free_dlist_ele_pop_head( accdb->deferred_free_dlist, accdb->partition_pool );
    partition_pool_ele_release( accdb->partition_pool, p );
    spin_lock_release( &accdb->shmem->partition_lock );
  }

  fd_accdb_partition_t * compact = compaction_dlist_ele_peek_head( accdb->compaction_dlist[ src_layer ], accdb->partition_pool );
  if( FD_LIKELY( !compact ) ) {
    FD_COMPILER_MFENCE();
    FD_VOLATILE( *accdb->my_epoch_slot ) = ULONG_MAX;
    fd_rwlock_unread( accdb->shmem->lock );
    return;
  }

  *charge_busy = 1;

  fd_accdb_disk_meta_t meta[1];

  ulong compact_base = partition_pool_idx( accdb->partition_pool, compact )*accdb->shmem->partition_sz;

  /* Read the on-disk metadata header at the current compaction
     cursor within the partition being compacted. */
  ulong bytes_read = 0UL;
  while( FD_UNLIKELY( bytes_read<sizeof(fd_accdb_disk_meta_t) ) ) {
    long result = pread( accdb->fd, ((uchar *)meta)+bytes_read, sizeof(fd_accdb_disk_meta_t)-bytes_read, (long)(compact_base+compact->compaction_offset+bytes_read) );
    if( FD_UNLIKELY( -1==result && (errno==EINTR || errno==EAGAIN || errno==EWOULDBLOCK ) ) ) continue;
    else if( FD_UNLIKELY( -1==result ) ) FD_LOG_ERR(( "pread() failed (%d-%s)", errno, fd_io_strerror( errno ) ));
    else if( FD_UNLIKELY( !result ) ) FD_LOG_ERR(( "accounts database is corrupt, data expected at offset %lu with size %lu exceeded file extents",
                                                   compact_base+compact->compaction_offset+bytes_read, sizeof(fd_accdb_disk_meta_t) ));
    bytes_read += (ulong)result;
  }

  /* Walk the hash chain to find a live index entry whose on-disk
     offset matches the record we are compacting. */
  fd_accdb_acc_t * acc = NULL;
  uint acc_idx = accdb->acc_map[ fd_funk_rec_key_hash1( meta->pubkey, accdb->shmem->seed )&(accdb->shmem->chain_cnt-1UL) ];
  while( acc_idx!=UINT_MAX ) {
    fd_accdb_acc_t * candidate = &accdb->acc_pool[ acc_idx ];
    if( FD_LIKELY( candidate->map.next!=UINT_MAX ) ) __builtin_prefetch( &accdb->acc_pool[ candidate->map.next ], 0, 0 );
    if( FD_LIKELY( candidate->offset==compact_base+compact->compaction_offset ) ) {
      acc = candidate;
      break;
    }
    acc_idx = candidate->map.next;
  }

  ulong record_sz  = sizeof(fd_accdb_disk_meta_t) + (ulong)meta->size;
  ulong bytes_copied = 0UL;
  if( FD_UNLIKELY( !acc ) ) {
    /* Dead record — the index entry was already removed, so this
       on-disk extent is garbage.  Nothing to relocate. */
  } else {
    ulong dest_layer  = fd_ulong_min( src_layer+1UL, FD_ACCDB_COMPACTION_LAYER_CNT-1UL );
    ulong dest_offset = allocate_next_compaction_write( accdb, record_sz, dest_layer );

    while( FD_UNLIKELY( bytes_copied<record_sz ) ) {
      long in_off  = (long)(compact_base + compact->compaction_offset + bytes_copied);
      long out_off = (long)(dest_offset + bytes_copied);

      long result = copy_file_range( accdb->fd, &in_off, accdb->fd, &out_off, record_sz-bytes_copied, 0 );
      if( FD_UNLIKELY( -1==result && (errno==EINTR || errno==EAGAIN || errno==EWOULDBLOCK ) ) ) continue;
      else if( FD_UNLIKELY( -1==result ) ) FD_LOG_ERR(( "copy_file_range() failed (%d-%s)", errno, fd_io_strerror( errno ) ));
      else if( FD_UNLIKELY( !result ) ) FD_LOG_ERR(( "accounts database is corrupt, data expected at offset %lu with size %lu exceeded file extents",
                                                      compact_base+compact->compaction_offset+bytes_copied, record_sz ));
      bytes_copied += (ulong)result;
    }

    accdb->shmem->metrics->accounts_relocated++;
    accdb->shmem->metrics->accounts_relocated_bytes += bytes_copied;

    /* Ensure the data is on disk before publishing the new offset,
       so concurrent acquire threads do not preadv2 from a location
       that hasn't been written yet. */
    FD_COMPILER_MFENCE();

    /* CAS the offset from old to new.  If a concurrent release
       overwrote acc->offset to ULONG_MAX (dirty sentinel for a new
       commit), the CAS fails and we treat the record as superseded —
       the new data is in cache only and our relocated copy is stale. */
    ulong old_offset = compact_base + compact->compaction_offset;
    if( FD_UNLIKELY( FD_ATOMIC_CAS( &acc->offset, old_offset, dest_offset )!=old_offset ) ) {
      /* Record was superseded by a concurrent overwrite commit.
         The disk space we just wrote is dead on arrival — account
         it as freed so compaction can reclaim it later. */
      fd_accdb_shmem_bytes_freed( accdb->shmem, dest_offset, record_sz );
      bytes_copied = 0UL;
    }
  }

  compact->compaction_offset += record_sz;

  if( FD_UNLIKELY( compact->compaction_offset>=compact->write_offset ) ) {
    FD_LOG_NOTICE(( "compaction of partition %lu completed", partition_pool_idx( accdb->partition_pool, compact ) ));

    /* Ensure the new acc->offset stores above are visible to other
       cores before the source partition is moved to the deferred-free
       list.  On x86 (TSO) hardware store ordering already guarantees
       this, but the compiler fence prevents the compiler from sinking
       the offset store past the inlined pool/dlist mutations below. */
    FD_COMPILER_MFENCE();

    /* Bump the global epoch and tag this partition so the reclamation
       scan knows when all rwlock-read holders that could reference
       data in this partition have exited. */
    ulong tag = FD_ATOMIC_FETCH_AND_ADD( &accdb->shmem->epoch, 1UL );
    compact->epoch_tag = tag;

    /* partition_lock serializes these dlist/pool mutations with
       concurrent push_tail in fd_accdb_shmem_bytes_freed and
       partition_pool_ele_acquire in change_partition.  Neither fd_dlist
       nor fd_pool are thread-safe, so all mutations must be under the
       same lock. */
    spin_lock_acquire( &accdb->shmem->partition_lock );

    accdb->shmem->metrics->partitions_freed++;
    compaction_dlist_ele_pop_head( accdb->compaction_dlist[ src_layer ], accdb->partition_pool );
    deferred_free_dlist_ele_push_tail( accdb->deferred_free_dlist, compact, accdb->partition_pool );

    accdb->shmem->metrics->compactions_completed++;
    if( FD_LIKELY( compaction_dlist_is_empty( accdb->compaction_dlist[ src_layer ], accdb->partition_pool ) ) ) {
      accdb->shmem->metrics->in_compaction = 0;
    } else {
      fd_accdb_partition_t * next = compaction_dlist_ele_peek_head( accdb->compaction_dlist[ src_layer ], accdb->partition_pool );
      FD_LOG_NOTICE(( "compaction of layer %lu partition %lu started", src_layer, partition_pool_idx( accdb->partition_pool, next ) ));
    }

    spin_lock_release( &accdb->shmem->partition_lock );
  }

  accdb->shmem->metrics->bytes_read += bytes_read + bytes_copied;
  accdb->shmem->metrics->bytes_written += bytes_copied;

  FD_COMPILER_MFENCE();
  FD_VOLATILE( *accdb->my_epoch_slot ) = ULONG_MAX;
  fd_rwlock_unread( accdb->shmem->lock );
}

void
fd_accdb_acquire( fd_accdb_t *          accdb,
                  fd_accdb_fork_id_t    fork_id,
                  ulong                 pubkeys_cnt,
                  uchar const * const * pubkeys,
                  int *                 writable,
                  fd_accdb_entry_t *    out_entries ) {
  FD_TEST( pubkeys_cnt<=5UL*(2UL+MAX_TX_ACCOUNT_LOCKS) );
  fd_rwlock_read( accdb->shmem->lock );
  FD_COMPILER_MFENCE();
  FD_VOLATILE( *accdb->my_epoch_slot ) = FD_VOLATILE_CONST( accdb->shmem->epoch );
  FD_COMPILER_MFENCE();

  // STEP 1.
  //   Locate each account in the fork and index structure, to determine
  //   if it already exists, its size and other metadata, and which
  //   specific slot (generation) it was last written in.

  fd_accdb_fork_t * fork = &accdb->fork_pool[ fork_id.val ];
  ulong root_generation = accdb->fork_pool[ accdb->shmem->root_fork_id.val ].shmem->generation;

  fd_accdb_acc_t * accs[ 5UL*(2UL+MAX_TX_ACCOUNT_LOCKS) ];
  ulong acc_map_idxs[ 5UL*(2UL+MAX_TX_ACCOUNT_LOCKS) ];

  /* Walk the hash chain for each pubkey and take the first visible
     match.  Correctness relies on newer entries always being prepended
     to the chain head, which is guaranteed because replay processes
     writes in slot order and release always inserts at the head.

     CONCURRENCY: This chain walk runs under rwlock-read without the
     cache spin lock.  A concurrent fd_accdb_release may prepend a new
     node to the same chain while we walk it.  This is safe on x86-64
     (TSO): the releasing thread stores all acc fields (pubkey,
     generation, map.next, ...) before publishing the new head via
     acc_map[idx], and TSO guarantees a reading core that observes the
     new head also observes all prior stores to the node.  A reader that
     does not yet see the new head simply sees an older (still valid)
     version of the chain.  On weakly-ordered architectures an explicit
     acquire fence would be needed before the chain walk and a release
     fence in fd_accdb_release before the head-pointer store.  Multiple
     concurrent releases are serialized by the cache spin lock, so at
     most one writer mutates a given chain head at a time. */
  for( ulong i=0UL; i<pubkeys_cnt; i++ ) {
    acc_map_idxs[ i ] = fd_funk_rec_key_hash1( pubkeys[ i ], accdb->shmem->seed )&(accdb->shmem->chain_cnt-1UL);
    uint acc = accdb->acc_map[ acc_map_idxs[ i ] ];
    while( acc!=UINT_MAX ) {
      fd_accdb_acc_t const * candidate_acc = &accdb->acc_pool[ acc ];
      if( FD_LIKELY( candidate_acc->map.next!=UINT_MAX ) ) __builtin_prefetch( &accdb->acc_pool[ candidate_acc->map.next ], 0, 0 );

      if( FD_UNLIKELY( (candidate_acc->generation>root_generation && candidate_acc->fork_id!=fork_id.val && !descends_set_test( fork->descends, candidate_acc->fork_id )) ) || memcmp( pubkeys[ i ], candidate_acc->pubkey, 32UL ) ) {
        acc = candidate_acc->map.next;
        continue;
      }

      break;
    }
    
    if( FD_UNLIKELY( acc==UINT_MAX ) ) accs[ i ] = NULL;
    else                               accs[ i ] = &accdb->acc_pool[ acc ];
  }

  // STEP 2.
  //   We are potentially going to need to read the account data off of
  //   disk into the cache, if the account(s) are not in the cache so
  //   reserve the necessary cache space.  This is done with an "atomic
  //   subtract" spin loop on the cache class counters, which is
  //   actually faster than doing a real CAS on a packed ulong.
  //
  //   For reads, we only need space to copy the account data into a
  //   single right-sized cache line, but for writes ... we need to
  //   reserve one of every size class.  The reason is we are going to
  //   need a 10MiB staging buffer for the executor to write to (it may
  //   grow the account, so needs the max size class).  Even if the
  //   account is already in the 10MiB cache class, we need another one
  //   because a transaction can fail half way, so we need scratch space
  //   to be able to unwind.
  //
  //   So we acquire one of each size class.  Then when the transaction
  //   finishes, if it succeeded, we will copy the data back to the
  //   whichever size-class is now right-sized post execution.

  ulong requested_buckets[ FD_ACCDB_CACHE_CLASS_CNT ] = {0};
  for( ulong i=0UL; i<pubkeys_cnt; i++ ) {
    if( FD_UNLIKELY( !accs[ i ] && !writable[ i ] ) ) continue;

    if( FD_LIKELY( accs[ i ] ) ) requested_buckets[ fd_accdb_cache_class( accs[ i ]->size ) ]++;
    if( FD_UNLIKELY( writable[ i ] ) ) {
      for( ulong j=0UL; j<FD_ACCDB_CACHE_CLASS_CNT; j++ ) requested_buckets[ j ]++;
    }
  }

  /* TODO: This over-reserves cache slots for writable accounts that
     already exist.  For each such account we reserve one line in the
     account's size class (for the read into cache) AND one line in
     every size class (for the write destination buffers). But if the
     account is already resident in cache (which is the common case for
     hot accounts), the read-into-cache line is unnecessary — we will
     get a cache hit in step 3 and never use it.  The fix is to probe
     the cache map here (locklessly, via cache_query) and skip the
     per-account size class reservation when a hit is found. This would
     reduce peak reservation by up to one line per writable account per
     acquire batch, lowering contention on the cache class counters and
     allowing smaller cache provisioning. */

  /* Reserve cache slots using thread-local credits.  Each thread keeps
     a local credit[i] for each size class.  On the fast path (common
     case), the reservation is satisfied entirely from local credits
     with no atomics and no shared cache line bounces.

     When a class's local credit goes negative, the deficit is claimed
     from the shared cache_class_pool via an atomic subtract (medium
     path).  Credits naturally accumulate locally because release
     returns them to the local array, so after the initial warm-up most
     acquires are fully local. */
  for(;;) {
    for( ulong i=0UL; i<FD_ACCDB_CACHE_CLASS_CNT; i++ ) accdb->credit[ i ] -= (long)requested_buckets[ i ];

    int need_pool = 0;
    for( ulong i=0UL; i<FD_ACCDB_CACHE_CLASS_CNT; i++ ) {
      if( FD_UNLIKELY( accdb->credit[ i ]<0L ) ) { need_pool = 1; break; }
    }
    if( FD_LIKELY( !need_pool ) ) break;

    int acquire_failed = 0;
    ulong grabbed[ FD_ACCDB_CACHE_CLASS_CNT ] = {0};
    for( ulong i=0UL; i<FD_ACCDB_CACHE_CLASS_CNT; i++ ) {
      if( FD_LIKELY( accdb->credit[ i ]>=0L ) ) continue;

      ulong deficit = (ulong)( -accdb->credit[ i ] );
      for(;;) {
        ulong cur = FD_VOLATILE_CONST( accdb->shmem->cache_class_pool[ i ] );
        if( FD_UNLIKELY( cur<deficit ) ) {
          acquire_failed = 1;
          break;
        }
        if( FD_LIKELY( FD_ATOMIC_CAS( &accdb->shmem->cache_class_pool[ i ], cur, cur-deficit )==cur ) ) {
          grabbed[ i ] = deficit;
          accdb->credit[ i ] = 0L;
          break;
        }
        FD_SPIN_PAUSE();
      }
      if( FD_UNLIKELY( acquire_failed ) ) {
        for( ulong j=0UL; j<i; j++ ) {
          if( grabbed[ j ] ) FD_ATOMIC_FETCH_AND_ADD( &accdb->shmem->cache_class_pool[ j ], grabbed[ j ] );
          accdb->credit[ j ] -= (long)grabbed[ j ];
        }
        for( ulong k=0UL; k<FD_ACCDB_CACHE_CLASS_CNT; k++ ) accdb->credit[ k ] += (long)requested_buckets[ k ];

        /* Slow path: return all positive local credits to the global
           pool so other threads (or our own retry) can use them.
           Without this, credits hoarded by idle threads would make
           the pool appear permanently exhausted. */
        for( ulong k=0UL; k<FD_ACCDB_CACHE_CLASS_CNT; k++ ) {
          if( accdb->credit[ k ]>0L ) {
            FD_ATOMIC_FETCH_AND_ADD( &accdb->shmem->cache_class_pool[ k ], (ulong)accdb->credit[ k ] );
            accdb->credit[ k ] = 0L;
          }
        }

        FD_SPIN_PAUSE();
        break;
      }
    }
    if( FD_LIKELY( !acquire_failed ) ) break;
  }

  // STEP 3.
  //   For any accounts that are not in cache, we now need to actually
  //   retrieve the cache pointers from our structures.  Space has been
  //   reserved already, so this step is guaranteed to succeed, and is
  //   just pulling the cache lines out of the free lists and marking
  //   them as in-use.
  //
  //   Manipulating the free LRU lists is difficult to do lockless (they
  //   are doubly linked), so we just take a simple spin lock for this
  //   step.  The duty cycle is effectively zero due to everything else
  //   happening outside the lock, so this will rarely be contended.

  int exists_in_cache[ 5UL*(2UL+MAX_TX_ACCOUNT_LOCKS) ] = {0};
  fd_accdb_cache_line_t * original_cache_line[ 5UL*(2UL+MAX_TX_ACCOUNT_LOCKS) ] = { NULL };
  fd_accdb_cache_line_t * destination_cache_lines[ 5UL*(2UL+MAX_TX_ACCOUNT_LOCKS) ][ FD_ACCDB_CACHE_CLASS_CNT ] = { NULL };

  /* Saved acc_pool indices of evicted dirty cache lines.  These are
     captured before clearing acc_idx to UINT_MAX on the line struct, so
     that the sentinel protocol (step 13) works correctly while the
     evicted account metadata is still available for writeback in steps
     4 and 6. */
  uint evicted_dest_acc[ 5UL*(2UL+MAX_TX_ACCOUNT_LOCKS) ][ FD_ACCDB_CACHE_CLASS_CNT ];
  uint evicted_orig_acc[ 5UL*(2UL+MAX_TX_ACCOUNT_LOCKS) ];

  spin_lock_acquire( &accdb->shmem->cache_lock );

  for( ulong i=0UL; i<pubkeys_cnt; i++ ) {
    if( FD_UNLIKELY( !accs[ i ] && !writable[ i ] ) ) continue;

    original_cache_line[ i ] = accs[ i ] ? cache_query( accdb, pubkeys[ i ], accs[ i ]->generation ) : NULL;
    exists_in_cache[ i ] = original_cache_line[ i ]!=NULL;
    if( FD_LIKELY( original_cache_line[ i ] ) ) {
      /* Each transaction can reference the account at most once, and
         there will be at most execrp+execld threads concurrently
         referencing the account at once, which is safe to assume fits
         in a UCHAR. */
      FD_TEST( original_cache_line[ i ]->refcnt<UCHAR_MAX-1 );
      original_cache_line[ i ]->refcnt++;
      ulong size_class = fd_accdb_cache_class( accs[ i ]->size );
      if( FD_LIKELY( original_cache_line[ i ]->refcnt==1UL ) ) cache_dlist_ele_remove( accdb->cache_lru[ size_class ], original_cache_line[ i ], accdb->cache[ size_class ] );
    }

    if( FD_UNLIKELY( writable[ i ] ) ) {
      for( ulong j=0UL; j<FD_ACCDB_CACHE_CLASS_CNT; j++ ) destination_cache_lines[ i ][ j ] = acquire_cache_line( accdb, j, &evicted_dest_acc[ i ][ j ] );
      if( FD_LIKELY( accs[ i ] ) && FD_UNLIKELY( !original_cache_line[ i ] ) ) {
        ulong size_class = fd_accdb_cache_class( accs[ i ]->size );
        original_cache_line[ i ] = acquire_cache_line( accdb, size_class, &evicted_orig_acc[ i ] ); /* TODO: Optimize. Sometimes not needed if same generation overwrite? */
        original_cache_line[ i ]->refcnt = 1;
        fd_memcpy( original_cache_line[ i ]->key.pubkey, accs[ i ]->pubkey, 32UL );
        original_cache_line[ i ]->key.generation = accs[ i ]->generation;
        cache_insert( accdb, original_cache_line[ i ], (uint)( accs[ i ] - accdb->acc_pool ), size_class );
      }
    } else {
      if( FD_UNLIKELY( !original_cache_line[ i ] ) ) {
        ulong size_class = fd_accdb_cache_class( accs[ i ]->size );
        original_cache_line[ i ] = acquire_cache_line( accdb, size_class, &evicted_orig_acc[ i ] );
        original_cache_line[ i ]->refcnt = 1;
        fd_memcpy( original_cache_line[ i ]->key.pubkey, accs[ i ]->pubkey, 32UL );
        original_cache_line[ i ]->key.generation = accs[ i ]->generation;
        cache_insert( accdb, original_cache_line[ i ], (uint)( accs[ i ] - accdb->acc_pool ), size_class );
      }
    }
  }

  spin_lock_release( &accdb->shmem->cache_lock );

  // STEP 4.
  //   For any cache lines we have retrieved, which we might potentially
  //   be about to trash (by writing stuff in there), we need to write
  //   them back to disk first if they are dirty.  This is the proces of
  //   "persisting" (a/k/a evicting) whatever was previously in the
  //   cache line we are about to use.
  //
  //   This step does not actually persist the data to disk, it just
  //   constructs a series of iovecs (write instructions) which will be
  //   used later to do the actual write.  The reason is that we want to
  //   batch all the writes together into a single writev call, to
  //   minimize overhead, and also keep the actual writes at the end of
  //   the function and independent of the specific control flow, so
  //   that they could be offloaded to another thread of made
  //   asynchronous (e.g. with io_uring) in the future without needing
  //   to change the rest of the logic.

  int write_ops_cnt = 0;
  int write_meta_cnt = 0;
  ulong total_write_sz = 0UL;
  fd_accdb_disk_meta_t write_metas[ (FD_ACCDB_CACHE_CLASS_CNT+1UL)*5UL*(2UL+MAX_TX_ACCOUNT_LOCKS) ];
  struct iovec write_ops[ 2UL*(FD_ACCDB_CACHE_CLASS_CNT+1UL)*5UL*(2UL+MAX_TX_ACCOUNT_LOCKS) ];

  for( ulong i=0UL; i<pubkeys_cnt; i++ ) {
    if( FD_UNLIKELY( !accs[ i ] && !writable[ i ] ) ) continue;

    if( FD_UNLIKELY( writable[ i ] ) ) {
      for( ulong j=0UL; j<FD_ACCDB_CACHE_CLASS_CNT; j++ ) {
        if( FD_LIKELY( evicted_dest_acc[ i ][ j ]==UINT_MAX ) ) continue;

        fd_accdb_acc_t const * evicted = &accdb->acc_pool[ evicted_dest_acc[ i ][ j ] ];
        total_write_sz += sizeof(fd_accdb_disk_meta_t) + evicted->size;
        fd_memcpy( write_metas[ write_meta_cnt ].pubkey, evicted->pubkey, 32UL );
        write_metas[ write_meta_cnt ].size = evicted->size;
        write_ops[ write_ops_cnt++ ] = (struct iovec){ .iov_base = &write_metas[ write_meta_cnt ], .iov_len = sizeof(fd_accdb_disk_meta_t) };
        write_meta_cnt++;
        write_ops[ write_ops_cnt++ ] = (struct iovec){ .iov_base = destination_cache_lines[ i ][ j ]+1UL, .iov_len = evicted->size };
      }
      if( FD_UNLIKELY( accs[ i ] && !exists_in_cache[ i ] && evicted_orig_acc[ i ]!=UINT_MAX ) ) {
        fd_accdb_acc_t const * evicted = &accdb->acc_pool[ evicted_orig_acc[ i ] ];
        total_write_sz += sizeof(fd_accdb_disk_meta_t) + evicted->size;
        fd_memcpy( write_metas[ write_meta_cnt ].pubkey, evicted->pubkey, 32UL );
        write_metas[ write_meta_cnt ].size = evicted->size;
        write_ops[ write_ops_cnt++ ] = (struct iovec){ .iov_base = &write_metas[ write_meta_cnt ], .iov_len = sizeof(fd_accdb_disk_meta_t) };
        write_meta_cnt++;
        write_ops[ write_ops_cnt++ ] = (struct iovec){ .iov_base = original_cache_line[ i ]+1UL, .iov_len = evicted->size };
      }
    } else {
      if( FD_LIKELY( exists_in_cache[ i ] || evicted_orig_acc[ i ]==UINT_MAX ) ) continue;

      fd_accdb_acc_t const * evicted = &accdb->acc_pool[ evicted_orig_acc[ i ] ];
      total_write_sz += sizeof(fd_accdb_disk_meta_t) + evicted->size;
      fd_memcpy( write_metas[ write_meta_cnt ].pubkey, evicted->pubkey, 32UL );
      write_metas[ write_meta_cnt ].size = evicted->size;
      write_ops[ write_ops_cnt++ ] = (struct iovec){ .iov_base = &write_metas[ write_meta_cnt ], .iov_len = sizeof(fd_accdb_disk_meta_t) };
      write_meta_cnt++;
      write_ops[ write_ops_cnt++ ] = (struct iovec){ .iov_base = original_cache_line[ i ]+1UL, .iov_len = evicted->size };
    }
  }

  // STEP 5.
  //   Compute the file offset for the writes we are about to do.  This
  //   is basically a single fetch-add on the file offset, so we
  //   pre-reserve space we are going to write into, and then write it,
  //   although we do actually take a lock in here in rare cases when
  //   crossing a partition boundary and we need to make broader
  //   metadata updates.
  ulong file_offset = total_write_sz ? allocate_next_write( accdb, total_write_sz ) : 0UL;

  // STEP 6.
  //   The index structure keeps the offset on disk of every account, so
  //   now that we are writing cache lines back to disk, we need to
  //   update the index to point to the new locations.
  //
  //   The actual stores to evicted->offset and line->persisted are
  //   deferred until after pwritev2 completes (after Step 9), so
  //   a concurrent acquire spinning on offset==ULONG_MAX does not
  //   proceed to preadv2 from a location that hasn't been written.
  int                     pending_cnt = 0;
  fd_accdb_acc_t *        pending_accs [ (FD_ACCDB_CACHE_CLASS_CNT+1UL)*5UL*(2UL+MAX_TX_ACCOUNT_LOCKS) ];
  ulong                   pending_offs [ (FD_ACCDB_CACHE_CLASS_CNT+1UL)*5UL*(2UL+MAX_TX_ACCOUNT_LOCKS) ];
  fd_accdb_cache_line_t * pending_lines[ (FD_ACCDB_CACHE_CLASS_CNT+1UL)*5UL*(2UL+MAX_TX_ACCOUNT_LOCKS) ];

  ulong cumulative_offset = 0UL;
  for( ulong i=0UL; i<pubkeys_cnt; i++ ) {
    if( FD_UNLIKELY( !accs[ i ] && !writable[ i ] ) ) continue;

    if( FD_UNLIKELY( writable[ i ] ) ) {
      for( ulong j=0UL; j<FD_ACCDB_CACHE_CLASS_CNT; j++ ) {
        if( FD_LIKELY( evicted_dest_acc[ i ][ j ]==UINT_MAX ) ) continue;

        fd_accdb_acc_t * evicted = &accdb->acc_pool[ evicted_dest_acc[ i ][ j ] ];
        if( FD_LIKELY( evicted->offset!=ULONG_MAX ) ) {
          fd_accdb_shmem_bytes_freed( accdb->shmem, evicted->offset, (ulong)evicted->size+sizeof(fd_accdb_disk_meta_t) );
          FD_ATOMIC_FETCH_AND_SUB( &accdb->shmem->metrics->disk_used_bytes, (ulong)evicted->size+sizeof(fd_accdb_disk_meta_t) );
        }
        pending_accs [ pending_cnt ] = evicted;
        pending_offs [ pending_cnt ] = file_offset + cumulative_offset;
        pending_lines[ pending_cnt ] = destination_cache_lines[ i ][ j ];
        pending_cnt++;
        cumulative_offset += sizeof(fd_accdb_disk_meta_t) + evicted->size;
        FD_ATOMIC_FETCH_AND_ADD( &accdb->shmem->metrics->disk_used_bytes, (ulong)evicted->size+sizeof(fd_accdb_disk_meta_t) );
      }
      if( FD_UNLIKELY( accs[ i ] && !exists_in_cache[ i ] && evicted_orig_acc[ i ]!=UINT_MAX ) ) {
        fd_accdb_acc_t * evicted = &accdb->acc_pool[ evicted_orig_acc[ i ] ];
        if( FD_LIKELY( evicted->offset!=ULONG_MAX ) ) {
          fd_accdb_shmem_bytes_freed( accdb->shmem, evicted->offset, (ulong)evicted->size+sizeof(fd_accdb_disk_meta_t) );
          FD_ATOMIC_FETCH_AND_SUB( &accdb->shmem->metrics->disk_used_bytes, (ulong)evicted->size+sizeof(fd_accdb_disk_meta_t) );
        }
        pending_accs [ pending_cnt ] = evicted;
        pending_offs [ pending_cnt ] = file_offset + cumulative_offset;
        pending_lines[ pending_cnt ] = original_cache_line[ i ];
        pending_cnt++;
        cumulative_offset += sizeof(fd_accdb_disk_meta_t) + evicted->size;
        FD_ATOMIC_FETCH_AND_ADD( &accdb->shmem->metrics->disk_used_bytes, (ulong)evicted->size+sizeof(fd_accdb_disk_meta_t) );
      }
    } else {
      if( FD_LIKELY( exists_in_cache[ i ] || evicted_orig_acc[ i ]==UINT_MAX ) ) continue;

      fd_accdb_acc_t * evicted = &accdb->acc_pool[ evicted_orig_acc[ i ] ];
      if( FD_LIKELY( evicted->offset!=ULONG_MAX ) ) {
        fd_accdb_shmem_bytes_freed( accdb->shmem, evicted->offset, (ulong)evicted->size+sizeof(fd_accdb_disk_meta_t) );
        FD_ATOMIC_FETCH_AND_SUB( &accdb->shmem->metrics->disk_used_bytes, (ulong)evicted->size+sizeof(fd_accdb_disk_meta_t) );
      }
      pending_accs [ pending_cnt ] = evicted;
      pending_offs [ pending_cnt ] = file_offset + cumulative_offset;
      pending_lines[ pending_cnt ] = original_cache_line[ i ];
      pending_cnt++;
      cumulative_offset += sizeof(fd_accdb_disk_meta_t) + evicted->size;
      FD_ATOMIC_FETCH_AND_ADD( &accdb->shmem->metrics->disk_used_bytes, (ulong)evicted->size+sizeof(fd_accdb_disk_meta_t) );
    }
  }

  // STEP 7.
  //   Fill the output entries with cache pointers and metadata based on
  //   the accounts we have located and the cache lines we have
  //   reserved.

  for( ulong i=0UL; i<pubkeys_cnt; i++ ) {
    if( FD_UNLIKELY( !accs[ i ] && !writable[ i ] ) ) {
      out_entries[ i ].data = NULL;
      out_entries[ i ].data_len = 0UL;
      out_entries[ i ].lamports = 0UL;
      out_entries[ i ].commit = 0;
      out_entries[ i ]._writable = 0;
      out_entries[ i ]._original_size_class = ULONG_MAX;
      out_entries[ i ]._original_cache_idx = ULONG_MAX;
      continue;
    }

    if( FD_LIKELY( !writable[ i ] ) ) out_entries[ i ].data = (uchar *)(original_cache_line[ i ]+1UL);
    else                              out_entries[ i ].data = (uchar *)(destination_cache_lines[ i ][ 7UL ]+1UL);
    out_entries[ i ].data_len = accs[ i ] ? accs[ i ]->size : 0UL;
    out_entries[ i ].lamports = accs[ i ] ? accs[ i ]->lamports : 0UL;
    if( FD_UNLIKELY( !accs[ i ] ) ) memset( out_entries[ i ].owner, 0, 32UL );
    else                            fd_memcpy( out_entries[ i ].owner, accs[ i ]->owner, 32UL );
    out_entries[ i ].commit = 0;
    out_entries[ i ]._writable = writable[ i ];
    if( FD_UNLIKELY( writable[ i ] && accs[ i ] ) ) out_entries[ i ]._overwrite = accdb->fork_pool[ fork_id.val ].shmem->generation==accs[ i ]->generation;
    else                                            out_entries[ i ]._overwrite = 0;

    if( FD_UNLIKELY( writable[ i ] ) ) {
      out_entries[ i ]._fork_id = fork_id.val;
      out_entries[ i ]._generation = fork->shmem->generation;
      out_entries[ i ]._acc_map_idx = acc_map_idxs[ i ];
      fd_memcpy( out_entries[ i ]._pubkey, pubkeys[ i ], 32UL );
    }

    if( FD_UNLIKELY( !accs[ i ] ) ) {
      out_entries[ i ]._original_size_class = ULONG_MAX;
      out_entries[ i ]._original_cache_idx = ULONG_MAX;
    } else {
      out_entries[ i ]._original_size_class = fd_accdb_cache_class( accs[ i ]->size );
      out_entries[ i ]._original_cache_idx = (ulong)( original_cache_line[ i ] - accdb->cache[ out_entries[ i ]._original_size_class ] );
    }

    if( FD_UNLIKELY( writable[ i ] ) ) {
      for( ulong j=0UL; j<FD_ACCDB_CACHE_CLASS_CNT; j++ ) {
        out_entries[ i ]._write.destination_cache_idx[ j ] = (ulong)( destination_cache_lines[ i ][ j ] - accdb->cache[ j ] );
      }
    }
  }

  // STEP 8.
  //   As with writes, we also need to construct iovecs for any reads we
  //   need to do of accounts into the cache.  For reading accounts, we
  //   read them directly into the sole cache line we took (and maybe
  //   just evicted).  For writing accounts, we read them into the right
  //   sized cache line, and later it will be copied to the staging
  //   buffer.  This is to prevent repeatedly reading the same account
  //   of disk into cache, if it is being written cold multiple times
  //   and every write fails.

  ulong read_ops_cnt = 0UL;
  ulong read_offsets[ FD_ACCDB_CACHE_CLASS_CNT*5UL*(2UL+MAX_TX_ACCOUNT_LOCKS) ];
  uchar * read_bases[ FD_ACCDB_CACHE_CLASS_CNT*5UL*(2UL+MAX_TX_ACCOUNT_LOCKS) ];
  ulong read_sizes[ FD_ACCDB_CACHE_CLASS_CNT*5UL*(2UL+MAX_TX_ACCOUNT_LOCKS) ];
  struct iovec read_ops[ FD_ACCDB_CACHE_CLASS_CNT*5UL*(2UL+MAX_TX_ACCOUNT_LOCKS) ];

  for( ulong i=0UL; i<pubkeys_cnt; i++ ) {
    if( FD_UNLIKELY( !accs[ i ] || exists_in_cache[ i ] ) ) continue;

    /* We are guaranteed that if an account is in the cache, the bytes
       are available (all cache operations happen with the cache_lock),
       but we are not guaranteed that if something is _not_ in the cache
       that it has been written back to disk yet.  In paticular, if we
       are trying to read an account that another thread is in the
       process of evicting, we know they removed it from the cache, but
       we don't know exactly when they will have written it back fully
       to disk, so we may need to wait for that here.

       Compaction may concurrently relocate this record, but
       epoch-based safe reclamation guarantees the source partition
       is not freed until all rwlock-read holders that could have
       snapshotted the old offset have exited.  So the data at the
       snapshotted offset remains stable for the duration of our
       read and no post-read validation is needed. */
    while( accs[ i ]->offset==ULONG_MAX ) FD_SPIN_PAUSE();

    read_offsets[ read_ops_cnt ] = accs[ i ]->offset + sizeof(fd_accdb_disk_meta_t);
    read_bases[ read_ops_cnt ]   = (uchar *)( original_cache_line[ i ]+1UL );
    read_sizes[ read_ops_cnt ]   = accs[ i ]->size;
    read_ops[ read_ops_cnt++ ]   = (struct iovec){ .iov_base = original_cache_line[ i ]+1UL, .iov_len = accs[ i ]->size };
  }

  // STEP 9.
  //   Now we are finally ready to do the actual writes of the cache
  //   lines back to disk.  This is just a simple loop over the iovecs
  //   we constructed, and we use pwritev2 with RWF_HIPRI to minimize
  //   latency.
  ulong bytes_written = 0UL;
  struct iovec * write_ptr = write_ops;
  while( FD_LIKELY( bytes_written<total_write_sz ) ) {
    long result = pwritev2( accdb->fd, write_ptr, fd_int_min( write_ops_cnt, IOV_MAX ), (long)(file_offset+bytes_written), RWF_HIPRI );
    if( FD_UNLIKELY( -1==result && (errno==EINTR || errno==EAGAIN || errno==EWOULDBLOCK ) ) ) continue;
    else if( FD_UNLIKELY( -1==result ) ) FD_LOG_ERR(( "pwritev2() failed (%d-%s)", errno, fd_io_strerror( errno ) ));
    else if( FD_UNLIKELY( !result ) ) FD_LOG_ERR(( "accounts database is corrupt, pwritev2() returned 0 at offset %lu with %lu bytes remaining",
                                                   file_offset+bytes_written, total_write_sz-bytes_written ));
    bytes_written += (ulong)result;

    while( write_ops_cnt && (ulong)result>=(ulong)write_ptr[ 0 ].iov_len ) {
      result -= (long)write_ptr[ 0 ].iov_len;
      write_ptr++;
      write_ops_cnt--;
    }
    if( FD_LIKELY( write_ops_cnt ) ) {
      write_ptr[ 0 ].iov_base = (uchar *)write_ptr[ 0 ].iov_base + result;
      write_ptr[ 0 ].iov_len -= (ulong)result;
    }
  }

  // STEP 10.
  //   Now that the data is on disk, publish the evicted account offsets
  //   so concurrent acquire threads spinning on offset==ULONG_MAX can
  //   proceed.  The fence ensures pwritev2 data is globally visible
  //   before the offset stores.
  FD_COMPILER_MFENCE();
  for( int k=0; k<pending_cnt; k++ ) {
    pending_accs[ k ]->offset = pending_offs[ k ];
    pending_lines[ k ]->persisted = 1;
  }

  // STEP 11.
  //   Almost done... now do the actual reads of accounts into cache,
  //   using the iovecs we constructed.  This is basically the same loop
  //   as the writes, but with preadv2 instead of pwritev2, and that the
  //   reads are not necessarily all contiguous, but occur at random
  //   offsets.
  //
  //   CONCURRENCY: The compaction tile may concurrently relocate a
  //   record we are about to read (both hold rwlock-read).  Epoch-based
  //   safe reclamation guarantees the source partition is not freed
  //   until all rwlock-read holders that could have snapshotted the
  //   old offset have exited, so the data at the snapshotted offset
  //   remains stable for the duration of this read — no post-read
  //   validation or retry is needed.
  for( ulong i=0UL; i<read_ops_cnt; i++ ) {
    ulong bytes_read = 0UL;
    while( FD_LIKELY( bytes_read<read_sizes[ i ] ) ) {
      long result = preadv2( accdb->fd, &read_ops[ i ], 1, (long)(read_offsets[ i ]+bytes_read), RWF_HIPRI );
      if( FD_UNLIKELY( -1==result && (errno==EINTR || errno==EAGAIN || errno==EWOULDBLOCK ) ) ) continue;
      else if( FD_UNLIKELY( -1==result ) ) FD_LOG_ERR(( "preadv2() failed (%d-%s)", errno, fd_io_strerror( errno ) ));
      else if( FD_UNLIKELY( !result ) ) FD_LOG_ERR(( "accounts database is corrupt, data expected at offset %lu with size %lu exceeded file extents",
                                                     read_offsets[ i ]+bytes_read, read_sizes[ i ] ));
      bytes_read += (ulong)result;

      read_ops[ i ].iov_base = read_bases[ i ] + bytes_read;
      read_ops[ i ].iov_len  = read_sizes[ i ] - bytes_read;
    }
  }

  // STEP 12.
  //   Publish the real acc index for any cache lines we just loaded
  //   from disk, so concurrent threads spinning on acc_idx==UINT_MAX
  //   can proceed.  The fence ensures all preadv2 data is visible
  //   before the sentinel is cleared.
  FD_COMPILER_MFENCE();
  for( ulong i=0UL; i<pubkeys_cnt; i++ ) {
    if( FD_UNLIKELY( !accs[ i ] || exists_in_cache[ i ] ) ) continue;
    FD_VOLATILE( original_cache_line[ i ]->acc_idx ) = (uint)( accs[ i ] - accdb->acc_pool );
  }

  // STEP 13.
  //   Spin-wait for any cache lines found via cache_query that are
  //   still being loaded by another thread's preadv2.  The loading
  //   thread sets acc_idx to UINT_MAX before inserting into the cache
  //   map and publishes the real acc index after its read completes.
  //   This step is placed as late as possible to give the loading
  //   thread maximum time to finish before we need to spin.
  for( ulong i=0UL; i<pubkeys_cnt; i++ ) {
    if( FD_UNLIKELY( !original_cache_line[ i ] ) ) continue;
    while( FD_UNLIKELY( FD_VOLATILE_CONST( original_cache_line[ i ]->acc_idx )==UINT_MAX ) ) FD_SPIN_PAUSE();
  }

  // STEP 14.
  //   Finally, copy any accounts we are writing into the staging
  //   buffers, so they occupy a 10MiB cache line for the execution
  //   system.
  for( ulong i=0UL; i<pubkeys_cnt; i++ ) {
    if( FD_UNLIKELY( !accs[ i ] || !writable[ i ] ) ) continue;

    fd_memcpy( destination_cache_lines[ i ][ 7UL ]+1UL, original_cache_line[ i ]+1UL, accs[ i ]->size );
  }

  FD_COMPILER_MFENCE();
  FD_VOLATILE( *accdb->my_epoch_slot ) = ULONG_MAX;
  fd_rwlock_unread( accdb->shmem->lock );
}

void
fd_accdb_release( fd_accdb_t *       accdb,
                  ulong              entries_cnt,
                  fd_accdb_entry_t * entries ) {
  fd_rwlock_read( accdb->shmem->lock );
  FD_COMPILER_MFENCE();
  FD_VOLATILE( *accdb->my_epoch_slot ) = FD_VOLATILE_CONST( accdb->shmem->epoch );
  FD_COMPILER_MFENCE();

  // STEP 1.
  //   For each cache line which was written to in the 10MiB staging
  //   buffer, we may need to copy to the data out to a right sized
  //   cache line.  Figuring out the target cache line is non-obvious,
  //   but follows the more complete logic below this, we just pull the
  //   memcpy out so they are not done inside the cache lock.

  for( ulong i=0UL; i<entries_cnt; i++ ) {
    if( FD_UNLIKELY( entries[ i ]._original_size_class==ULONG_MAX && !entries[ i ]._writable ) ) continue;

    if( FD_LIKELY( entries[ i ]._original_size_class!=ULONG_MAX ) ) {
      FD_TEST( entries[ i ]._original_cache_idx<accdb->shmem->cache_class_max[ entries[ i ]._original_size_class ] );
    }
    if( FD_UNLIKELY( entries[ i ].commit ) ) FD_TEST( entries[ i ]._writable );

    if( FD_LIKELY( !entries[ i ]._writable || !entries[ i ].commit ) ) continue;
    if( FD_UNLIKELY( entries[ i ]._overwrite ) ) {
      FD_TEST( entries[ i ]._writable );
      FD_TEST( entries[ i ]._original_cache_idx!=ULONG_MAX );
      FD_TEST( entries[ i ]._original_size_class!=ULONG_MAX );
    }

    ulong original_size_class = entries[ i ]._original_size_class;
    ulong new_size_class = fd_accdb_cache_class( entries[ i ].data_len );
    if( FD_UNLIKELY( new_size_class==7UL ) ) continue;

    fd_accdb_cache_line_t * target_cache_line;
    if( FD_LIKELY( original_size_class==new_size_class && entries[ i ]._overwrite ) ) target_cache_line = &accdb->cache[ original_size_class ][ entries[ i ]._original_cache_idx ];
    else                                                                              target_cache_line = &accdb->cache[ new_size_class ][ entries[ i ]._write.destination_cache_idx[ new_size_class ] ];

    fd_memcpy( target_cache_line+1UL, &accdb->cache[ 7UL ][ entries[ i ]._write.destination_cache_idx[ 7UL ] ]+1UL, entries[ i ].data_len );
  }

  // STEP 2.
  //   Now update the metadata structures and free lists to reflect the
  //   fact that we are done with these cache lines, this must happen
  //   with the cache lock as the dlist updates are not atomic.

  spin_lock_acquire( &accdb->shmem->cache_lock );

  for( ulong i=0UL; i<entries_cnt; i++ ) {
    if( FD_UNLIKELY( entries[ i ]._original_size_class==ULONG_MAX && !entries[ i ]._writable ) ) continue;

    ulong original_size_class = entries[ i ]._original_size_class;
    fd_accdb_cache_line_t * original_cache_line = entries[ i ]._original_cache_idx==ULONG_MAX ? NULL : &accdb->cache[ original_size_class ][ entries[ i ]._original_cache_idx ];
    if( FD_LIKELY( original_cache_line ) ) {
      FD_TEST( original_cache_line->refcnt>0UL );
      original_cache_line->refcnt--;
    }

    if( FD_LIKELY( !entries[ i ]._writable ) ) {
      /* For readonly accounts, just bump it to the head of the LRU
         since it was just accessed. */
      FD_TEST( original_cache_line );
      if( FD_LIKELY( !original_cache_line->refcnt ) ) cache_dlist_ele_push_head( accdb->cache_lru[ original_size_class ], original_cache_line, accdb->cache[ original_size_class ] );
      continue;
    }

    fd_accdb_cache_line_t * destination_cache_lines[ FD_ACCDB_CACHE_CLASS_CNT ];
    for( ulong j=0UL; j<FD_ACCDB_CACHE_CLASS_CNT; j++ ) destination_cache_lines[ j ] = &accdb->cache[ j ][ entries[ i ]._write.destination_cache_idx[ j ] ];
    int destination_cache_lru[ FD_ACCDB_CACHE_CLASS_CNT ] = {0};

    if( FD_LIKELY( !entries[ i ].commit ) ) {
      /* If it's writable but it didn't commit, all of the destination
         cache lines (including the staging buffer which is trashed) are
         unused and can be added to the tail of the LRU for immediate
         reuse.  Whatever buffer it was accessing also bumps to the
         head of the LRU since it was just accessed. */
      if( FD_LIKELY( original_cache_line && !original_cache_line->refcnt ) ) cache_dlist_ele_push_head( accdb->cache_lru[ original_size_class ], original_cache_line, accdb->cache[ original_size_class ] );
      for( ulong j=0UL; j<FD_ACCDB_CACHE_CLASS_CNT; j++ ) cache_dlist_ele_push_tail( accdb->cache_lru[ j ], destination_cache_lines[ j ], accdb->cache[ j ] );
      continue;
    }

    ulong new_size_class = fd_accdb_cache_class( entries[ i ].data_len );
    fd_accdb_cache_line_t * committed_line;
    if( FD_UNLIKELY( new_size_class==7UL ) ) {
      /* The account belongs in the largest size class, and we already
         have it resident in a 10MiB buffer anyway, so no need to copy
         back.  If we are "overwriting" (same generation as the account
         came from), then the original can be discarded to the tail
         of the LRU and removed from the cache. */
      destination_cache_lines[ 7UL ]->persisted = 0;
      destination_cache_lru[ 7UL ] = 1;
      if( FD_LIKELY( entries[ i ]._overwrite ) ) {
        original_cache_line->persisted = 1;
        cache_dlist_ele_push_tail( accdb->cache_lru[ original_size_class ], original_cache_line, accdb->cache[ original_size_class ] );
        cache_remove( accdb, original_cache_line );
      }
      committed_line = destination_cache_lines[ 7UL ];
    } else {
      /* The account started in some arbitrary size class, transited
         through a 10MiB staging buffer, and is now being written back
         to some arbitrary (non-10MiB) size class, so we need to copy it
         there.  The staging buffer is discarded, and can go to the
         tail of the LRU.  If we are going to a different size class,
         and we are "overwriting" (same generation), then the original
         can also be discarded to the tail of the LRU, but if we are
         staying in the same size class, we can reuse the cache line
         in place and push it to the head of the LRU since it now
         holds valid new data.

         As a small optimization, if we are staying in the same size
         class, we can just copy the new data over the old cache line,
         and then move it to the head of the LRU. */
      fd_accdb_cache_line_t * target_cache_line;
      if( FD_LIKELY( original_size_class==new_size_class ) ) {
        if( FD_LIKELY( entries[ i ]._overwrite ) ) {
          cache_remove( accdb, original_cache_line );
          target_cache_line = original_cache_line;
        } else {
          target_cache_line = destination_cache_lines[ new_size_class ];
          destination_cache_lru[ new_size_class ] = 1;
        }
      } else {
        if( FD_LIKELY( entries[ i ]._overwrite ) ) {
          original_cache_line->persisted = 1;
          cache_dlist_ele_push_tail( accdb->cache_lru[ original_size_class ], original_cache_line, accdb->cache[ original_size_class ] );
          cache_remove( accdb, original_cache_line );
        }

        destination_cache_lru[ new_size_class ] = 1;
        target_cache_line = destination_cache_lines[ new_size_class ];
      }

      target_cache_line->persisted = 0;
      /* If target is the original cache line (overwrite, same size
         class), push to head directly since the cleanup loop only
         handles destination lines. */
      if( FD_LIKELY( !destination_cache_lru[ new_size_class ] ) ) cache_dlist_ele_push_head( accdb->cache_lru[ new_size_class ], target_cache_line, accdb->cache[ new_size_class ] );
      committed_line = target_cache_line;
    }

    /* For non-overwrite commits, the original cache line (if any) still
       holds valid ancestor data but is no longer pinned. Return it to
       the LRU so it can be reused. */
    if( FD_UNLIKELY( !entries[ i ]._overwrite && original_cache_line && !original_cache_line->refcnt ) ) {
      cache_dlist_ele_push_head( accdb->cache_lru[ original_size_class ], original_cache_line, accdb->cache[ original_size_class ] );
    }

    /* Push every destination cache line into the LRU.  This is the
       sole insertion point for destination lines, no double insertion
       can occur because: when destination_cache_lru[j]==1 (the line
       is committed_line or otherwise used), we skip the push and
       defer to this loop; when destination_cache_lru[j]==0, we may push
       target_cache_line which is original_cache_line (a different
       object), not destination_cache_lines[j]. */
    for( ulong j=0UL; j<FD_ACCDB_CACHE_CLASS_CNT; j++ ) {
      if( destination_cache_lru[ j ] ) cache_dlist_ele_push_head( accdb->cache_lru[ j ], destination_cache_lines[ j ], accdb->cache[ j ] );
      else                             cache_dlist_ele_push_tail( accdb->cache_lru[ j ], destination_cache_lines[ j ], accdb->cache[ j ] );
    }

    /* Update the accounts index for this committed write.  For an
       overwrite (same fork+generation), update the existing acc
       entry in place.  Otherwise allocate a new acc, prepend it
       to the hash chain, and record the write in a txn linked to
       the fork so advance_root can clean up old versions. */
    if( FD_LIKELY( entries[ i ]._overwrite ) ) {
      committed_line->acc_idx = original_cache_line->acc_idx;

      fd_accdb_acc_t * acc = &accdb->acc_pool[ original_cache_line->acc_idx ];
      /* Free old disk space before updating metadata, since the
         old size on disk may differ from the new size. */
      if( FD_LIKELY( acc->offset!=ULONG_MAX ) ) {
        fd_accdb_shmem_bytes_freed( accdb->shmem, acc->offset, (ulong)acc->size+sizeof(fd_accdb_disk_meta_t) );
        FD_ATOMIC_FETCH_AND_SUB( &accdb->shmem->metrics->disk_used_bytes, (ulong)acc->size+sizeof(fd_accdb_disk_meta_t) );
      }
      acc->offset   = ULONG_MAX;
      acc->size     = (uint)entries[ i ].data_len;
      acc->lamports = entries[ i ].lamports;
      fd_memcpy( acc->owner, entries[ i ].owner, 32UL );

      committed_line->key.generation = acc->generation;
      cache_insert( accdb, committed_line, committed_line->acc_idx, new_size_class );
    } else {
      ulong acc_idx = acc_pool_idx_acquire( accdb->acc_pool );
      fd_accdb_acc_t * acc = &accdb->acc_pool[ acc_idx ];
      fd_memcpy( acc->pubkey, entries[ i ]._pubkey, 32UL );
      fd_memcpy( acc->owner, entries[ i ].owner, 32UL );
      acc->lamports   = entries[ i ].lamports;
      acc->size       = (uint)entries[ i ].data_len;
      acc->generation = entries[ i ]._generation;
      acc->fork_id    = entries[ i ]._fork_id;
      acc->offset     = ULONG_MAX;

      acc->map.next = accdb->acc_map[ entries[ i ]._acc_map_idx ];
      FD_COMPILER_MFENCE();
      accdb->acc_map[ entries[ i ]._acc_map_idx ] = (uint)acc_idx;

      /* CONCURRENCY: This prepend is visible to concurrent
         fd_accdb_acquire readers who walk acc_map chains under only
         rwlock-read (no cache_lock).  This is safe:

         (1) Multiple releases are serialized by cache_lock, so only one
             thread mutates a given chain at a time. There is no
             lost-update race on the head pointer.

         (2) The FD_COMPILER_MFENCE above ensures stores to the acc
             node fields (pubkey, owner, lamports, size, generation,
             fork_id, offset, map.next) are ordered before the store
             to acc_map[idx] that publishes the new head.  On x86-64
             (TSO), hardware also guarantees this, but the compiler
             fence is needed to prevent the compiler from reordering
             the stores.  A reader that observes the new head is
             guaranteed to see a fully initialized node.  A reader
             that has not yet seen the new head simply traverses the
             previous (still valid) chain. */

      committed_line->acc_idx = (uint)acc_idx;

      committed_line->key.generation = acc->generation;
      cache_insert( accdb, committed_line, (uint)acc_idx, new_size_class );

      ulong txn_idx = txn_pool_idx_acquire( accdb->txn_pool );
      fd_accdb_txn_t * txn = &accdb->txn_pool[ txn_idx ];
      txn->acc_map_idx  = (uint)entries[ i ]._acc_map_idx;
      txn->acc_pool_idx = (uint)acc_idx;
      txn->fork.next = accdb->fork_pool[ entries[ i ]._fork_id ].shmem->txn_head;
      accdb->fork_pool[ entries[ i ]._fork_id ].shmem->txn_head = (uint)txn_idx;

      accdb->shmem->metrics->accounts_total++;
    }
  }

  spin_lock_release( &accdb->shmem->cache_lock );

  // STEP 3.
  //   Finally, we release the cache class reservations we took at the
  //   beginning when we acquired these cache lines.  Credits return to
  //   the thread-local credit array with no atomics.  Other threads
  //   that need credits will grab from the global pool, not from our
  //   local credits.

  for( ulong i=0UL; i<entries_cnt; i++ ) {
    if( FD_LIKELY( entries[ i ]._original_size_class!=ULONG_MAX ) ) accdb->credit[ entries[ i ]._original_size_class ] += 1L;
    if( FD_UNLIKELY( entries[ i ]._writable ) ) {
      for( ulong j=0UL; j<FD_ACCDB_CACHE_CLASS_CNT; j++ ) accdb->credit[ j ] += 1L;
    }
  }

  FD_COMPILER_MFENCE();
  FD_VOLATILE( *accdb->my_epoch_slot ) = ULONG_MAX;
  fd_rwlock_unread( accdb->shmem->lock );
}
