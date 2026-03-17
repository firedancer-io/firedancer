#include "fd_accdb.h"
#include "fd_accdb_shmem.h"
#define FD_ACCDB_NO_FORK_ID
#include "fd_accdb_private.h"
#undef FD_ACCDB_NO_FORK_ID

#include "../../flamenco/fd_rwlock.h"
#include "../../ballet/txn/fd_txn.h"
#include "../../tango/mcache/fd_mcache.h"
#include "../../tango/dcache/fd_dcache.h"

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
  fd_accdb_shmem_t * shmem;

  fd_accdb_fork_t * fork_pool;
  fd_accdb_fork_shmem_t * fork_shmem_pool;

  fd_accdb_acc_t * acc_pool;
  uint * acc_map;

  cache_entry_t * cache_map;

  fd_accdb_txn_t * txn_pool;

  fd_frag_meta_t * request;
  ulong            request_seq;
  ulong            request_depth;
  fd_wksp_t *      request_mem;
  ulong            request_chunk;
  ulong            request_chunk0;
  ulong            request_wmark;
  ulong            request_mtu;

  fd_frag_meta_t * response;
  ulong            response_seq;
  ulong            response_depth;
  fd_wksp_t *      response_mem;
  ulong            response_chunk0;
  ulong            response_wmark;
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
fd_accdb_cache_new( void *             ljoin,
                    fd_accdb_shmem_t * shmem,
                    fd_frag_meta_t *   request_mcache,
                    uchar *            request_dcache,
                    fd_frag_meta_t *   response_mcache,
                    uchar *            response_dcache,
                    ulong              request_mtu ) {
  if( FD_UNLIKELY( !ljoin ) ) {
    FD_LOG_WARNING(( "NULL ljoin" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)ljoin, fd_accdb_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned ljoin" ));
    return NULL;
  }

  ulong max_live_slots = shmem->max_live_slots;
  ulong max_accounts = shmem->max_accounts;
  ulong max_account_writes_per_slot = shmem->max_account_writes_per_slot;
  ulong partition_cnt = shmem->partition_cnt;

  ulong chain_cnt = fd_ulong_pow2_up( (max_accounts>>1) + (max_accounts&1UL) );
  ulong txn_max = max_live_slots * max_account_writes_per_slot;

  FD_SCRATCH_ALLOC_INIT( l, shmem );
                             FD_SCRATCH_ALLOC_APPEND( l, FD_ACCDB_SHMEM_ALIGN,     sizeof(fd_accdb_shmem_t)                                );
  void * _fork_pool        = FD_SCRATCH_ALLOC_APPEND( l, fork_pool_align(),        fork_pool_footprint( max_live_slots )                   );
  void * _descends_sets    = FD_SCRATCH_ALLOC_APPEND( l, descends_set_align(),     max_live_slots*descends_set_footprint( max_live_slots ) );
  void * _cache_map        = FD_SCRATCH_ALLOC_APPEND( l, cache_map_align(),        cache_map_footprint( shmem->cache_map_lg_slot_count )   );
  void * _acc_map          = FD_SCRATCH_ALLOC_APPEND( l, alignof(uint),            chain_cnt*sizeof(uint)                                  );
  void * _acc_pool         = FD_SCRATCH_ALLOC_APPEND( l, acc_pool_align(),         acc_pool_footprint( max_accounts )                      );
  void * _txn_pool         = FD_SCRATCH_ALLOC_APPEND( l, txn_pool_align(),         txn_pool_footprint( txn_max )                           );
  void * _partition_pool   = FD_SCRATCH_ALLOC_APPEND( l, partition_pool_align(),   partition_pool_footprint( partition_cnt )               );
  void * _compaction_dlist = FD_SCRATCH_ALLOC_APPEND( l, compaction_dlist_align(), compaction_dlist_footprint()                            );
  (void)_partition_pool; (void)_compaction_dlist;

  FD_SCRATCH_ALLOC_INIT( l2, ljoin );
  fd_accdb_t * accdb      = FD_SCRATCH_ALLOC_APPEND( l2, fd_accdb_align(),         sizeof(fd_accdb_t)                     );
  void * _local_fork_pool = FD_SCRATCH_ALLOC_APPEND( l2, alignof(fd_accdb_fork_t), max_live_slots*sizeof(fd_accdb_fork_t) );

  accdb->shmem = (fd_accdb_shmem_t *)shmem;
  accdb->acc_pool = acc_pool_join( _acc_pool );
  accdb->acc_map = _acc_map;
  accdb->txn_pool = txn_pool_join( _txn_pool );
  accdb->cache_map = cache_map_join( _cache_map );

  accdb->fork_shmem_pool = fork_pool_join( _fork_pool );
  accdb->fork_pool = _local_fork_pool;
  for( ulong i=0UL; i<max_live_slots; i++ ) {
    fd_accdb_fork_t * fork = &accdb->fork_pool[ i ];
    fork->shmem = (fd_accdb_fork_shmem_t*)( (uchar *)_fork_pool + i*fork_pool_footprint( max_live_slots ) );
    fork->descends = descends_set_join( (uchar *)_descends_sets + i*descends_set_footprint( max_live_slots ) );
    FD_TEST( fork->shmem );
    FD_TEST( fork->descends );
  }

  accdb->request        = request_mcache;
  accdb->request_depth  = fd_mcache_depth( request_mcache );
  accdb->request_seq    = 0UL;
  accdb->request_mem    = fd_wksp_containing( request_dcache );
  accdb->request_chunk0 = fd_dcache_compact_chunk0( accdb->request_mem, request_dcache );
  accdb->request_wmark  = fd_dcache_compact_wmark( accdb->request_mem, request_dcache, request_mtu );
  accdb->request_chunk  = accdb->request_chunk0;
  accdb->request_mtu    = request_mtu;

  accdb->response        = response_mcache;
  accdb->response_depth  = fd_mcache_depth( response_mcache );
  accdb->response_seq    = 0UL;
  accdb->response_mem    = fd_wksp_containing( response_dcache );
  accdb->response_chunk0 = fd_dcache_compact_chunk0( accdb->response_mem, response_dcache );
  accdb->response_wmark  = fd_dcache_compact_wmark( accdb->response_mem, response_dcache, 64UL );

  return shmem;
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

    fd_accdb_purge( accdb, cur_idx );
  }
}

void
fd_accdb_advance_root( fd_accdb_t *       accdb,
                       fd_accdb_fork_id_t fork_id ) {
  fd_rwlock_write( accdb->shmem->lock );

  /* The caller guarantees that rooting is sequential: each call
     advances the root by exactly one slot (the immediate child of
     the current root).  Skipping levels is not supported. */
  fd_accdb_fork_t * fork = &accdb->fork_pool[ fork_id.val ];
  FD_TEST( fork->shmem->parent_id.val==accdb->shmem->root_fork_id.val );
  if( FD_UNLIKELY( fork->shmem->parent_id.val==USHORT_MAX ) ) {
    accdb->shmem->root_fork_id = fork_id;
    fd_rwlock_unwrite( accdb->shmem->lock );
    return;
  }

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
        fd_accdb_shmem_bytes_freed( accdb->shmem, cur_acc->offset, (ulong)cur_acc->size+sizeof(fd_accdb_disk_meta_t) );
        accdb->shmem->metrics->disk_used_bytes -= (ulong)cur_acc->size+sizeof(fd_accdb_disk_meta_t);
        accdb->shmem->metrics->accounts_total--;

        uint next = cur_acc->map.next;

        if( FD_LIKELY( prev==UINT_MAX ) ) accdb->acc_map[ txne->acc_map_idx ] = next;
        else                              accdb->acc_pool[ prev ].map.next = next;

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

  /* Remove the parent from all descends_sets before freeing its
     slot, so that when the slot is recycled to a new fork, existing
     forks do not incorrectly treat the new fork as an ancestor.
     Entries from the freed parent are still visible via the
     generation <= root_generation fast path in reads. */
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
  fd_rwlock_write( accdb->shmem->lock );

  fd_accdb_fork_t * fork = &accdb->fork_pool[ fork_id.val ];

  fd_accdb_fork_id_t child = fork->shmem->child_id;
  while( child.val!=USHORT_MAX ) {
    fd_accdb_fork_id_t next = accdb->fork_pool[ child.val ].shmem->sibling_id;
    fd_accdb_purge( accdb, child );
    child = next;
  }

  uint txn = fork->shmem->txn_head;
  while( txn!=UINT_MAX ) {
    fd_accdb_txn_t * txne = txn_pool_ele( accdb->txn_pool, txn );

    fd_accdb_acc_t * acc = &accdb->acc_pool[ txne->acc_pool_idx ];

    fd_accdb_shmem_bytes_freed( accdb->shmem, acc->offset, (ulong)acc->size+sizeof(fd_accdb_disk_meta_t) );
    accdb->shmem->metrics->disk_used_bytes -= (ulong)acc->size+sizeof(fd_accdb_disk_meta_t);
    accdb->shmem->metrics->accounts_total--;

    uint prev = UINT_MAX;
    uint cur = accdb->acc_map[ txne->acc_map_idx ];
    while( cur!=(uint)(acc-accdb->acc_pool) ) {
      prev = cur;
      cur = accdb->acc_pool[ cur ].map.next;
    }

    if( FD_LIKELY( prev==UINT_MAX ) ) accdb->acc_map[ txne->acc_map_idx ] = acc->map.next;
    else                              accdb->acc_pool[ prev ].map.next = acc->map.next;

    acc_pool_idx_release( accdb->acc_pool, (uint)(acc-accdb->acc_pool) );

    txn = txne->fork.next;
    txn_pool_ele_release( accdb->txn_pool, txne );
  }

  for( ulong i=0UL; i<accdb->shmem->max_live_slots; i++ ) descends_set_remove( accdb->fork_pool[ i ].descends, fork_id.val );

  fork_pool_idx_release( accdb->fork_shmem_pool, fork_id.val );

  fd_rwlock_unwrite( accdb->shmem->lock );
}

static void
release( fd_accdb_t * accdb,
         ulong        cache_idx ) {
  /* TODO */
}

static int
index_lookup( fd_accdb_t *       accdb,
              fd_accdb_fork_id_t fork_idx,
              uchar const *      pubkey,
              fd_accdb_entry_t * out_entry ) {
  /* TODO */
  return 0;
}

static cache_entry_t *
cache_reserve( fd_accdb_t * accdb,
               ulong        size,
               int          writable ) {
  /* TODO */
  return NULL;
}

int
fd_accdb_acquire( fd_accdb_t *          accdb,
                  fd_accdb_fork_id_t    fork_id,
                  ulong                 pubkeys_cnt,
                  uchar const * const * pubkeys,
                  int *                 writable,
                  fd_accdb_entry_t *    out_entries ) {
  fd_rwlock_read( accdb->shmem->lock );

  fd_accdb_fork_t * fork = &accdb->fork_pool[ fork_id.val ];
  ulong root_generation = accdb->fork_pool[ accdb->shmem->root_fork_id.val ].shmem->generation;

  ulong accs[ MAX_TX_ACCOUNT_LOCKS ];

  for( ulong i=0UL; i<pubkeys_cnt; i++ ) {
    accs[ i ] = accdb->acc_map[ fd_funk_rec_key_hash1( pubkeys[ i ], accdb->shmem->seed )%accdb->shmem->chain_cnt ];
    while( accs[ i ]!=UINT_MAX ) {
      fd_accdb_acc_t const * candidate_acc = &accdb->acc_pool[ accs[ i ] ];
      if( FD_LIKELY( candidate_acc->map.next!=UINT_MAX ) ) __builtin_prefetch( &accdb->acc_pool[ candidate_acc->map.next ], 0, 0 );

      if( FD_UNLIKELY( (candidate_acc->generation>root_generation && candidate_acc->fork_id!=fork_id.val && !descends_set_test( fork->descends, candidate_acc->fork_id )) ) || memcmp( pubkey, candidate_acc->pubkey, 32UL ) ) {
        accs[ i ] = candidate_acc->map.next;
        continue;
      }
      
      break;
    }
    
    if( FD_UNLIKELY( accs[ i ]==UINT_MAX ) ) return -1;
  }

      /* Account is not in the database at all on this fork, so fail the
         entire acquire call.  We have already addref'd some prior
         accounts so release them before returning. */
      for( ulong j=0UL; j<i; j++ ) release( accdb, out_entries[ j ]._cache_idx );
      fd_rwlock_unwrite( accdb->shmem->lock );
      return -1;
    }

    fd_accdb_acc_t const * account = &accdb->acc_pool[ acc ];

    cache_entry_key_t key = {
      .generation = account->generation
    };
    fd_memcpy( key.pubkey, pubkeys[ i ], 32UL );

    int operation;
    cache_entry_t * entry = cache_map_query( accdb->cache_map, key, NULL );
    if( FD_UNLIKELY( !entry ) ) {
      entry = cache_reserve( accdb, account->size, writable[ i ] );


      operations[ operation_cnt++ ] = 
    }

    int in_cache = cache_lookup( accdb, pubkeys[ i ], &out_entries[ i ] );

    /* Now we found a valid account, enter it into the cache so that
       it's live for the lifetime of the caller. */
    ulong cache_idx = ensure_cached( accdb, acc );
    out_entries[ i ] = (fd_accdb_entry_t){
      .pubkey   = acc->pubkey,
      .owner    = acc->owner,
      .lamports = acc->lamports,
      .data_len = acc->data_len,
      .data     = accdb->data_buffers[ cache_idx ],
      .dirty    = 0,
    };

    if( FD_UNLIKELY( writable[ i ]==2 && !is_10mib_already( accdb, cache_idx ) ) ) {
      /* If the caller is acquiring for full write, and the buffer is
         not 10MiB but needs to be, as it might be resized.  We need to
         pass an additional staging buffer of 10MiB for them to write to.

         TODO: Is this always necessary? */
      out_entries[ i ].sidecar = ensure_sidecar( accdb, cache_idx );
    } else {
      out_entries[ i ].sidecar = NULL;
    }

    addref( accdb, elem );
  }

  fd_rwlock_unwrite( accdb->lock );
  return 0;
}

void
fd_accdb_cache_release( fd_accdb_cache_t *       cache,
                        ulong                    entries_cnt,
                        fd_accdb_cache_entry_t * entries ) {
  fd_rwlock_write( cache->lock );

  for( ulong i=0UL; i<entries_cnt; i++ ) {
    cache->elem[ entries[ i ].cache_idx ].dirty |= entries[ i ].dirty;
    cache->elem[ entries[ i ].cache_idx ].refcnt -= 1;
    if( FD_LIKELY( !cache->elem[ entries[ i ].cache_idx ].refcnt ) ) {
      lru_for_size_class.push_back( elem );
    }
  }

  fd_rwlock_unwrite( cache->lock );
}
