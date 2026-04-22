#define _GNU_SOURCE
#include "fd_accdb.h"
#include "fd_accdb_shmem.h"
#define FD_ACCDB_NO_FORK_ID
#include "fd_accdb_private.h"
#undef FD_ACCDB_NO_FORK_ID

#include "../../ballet/txn/fd_txn.h"

FD_STATIC_ASSERT( sizeof(fd_accdb_cache_line_t)==FD_ACCDB_CACHE_META_SZ, cache_meta_sz );

#include <stddef.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/uio.h>

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
  fork_pool_t fork_shmem_pool[1];

  fd_accdb_acc_t * acc_pool;
  acc_pool_t acc_pool_join[1];
  uint * acc_map;

  uchar * cache [ FD_ACCDB_CACHE_CLASS_CNT ];

  fd_accdb_partition_t * partition_pool;
  compaction_dlist_t * compaction_dlist[ FD_ACCDB_COMPACTION_LAYER_CNT ];
  deferred_free_dlist_t * deferred_free_dlist;

  txn_pool_t txn_pool[1];

  /* Pointer into shmem->joiner_epochs[ my_slot ].val.  Set to the
     current global epoch on entry to an epoch-protected operation,
     and ULONG_MAX on exit.  Used to determine when deferred frees
     are safe. */
  ulong * my_epoch_slot;

  /* At most one batch of acc pool elements that have been CAS-unlinked
     from their hash chains but cannot be released back to acc_pool yet,
     because concurrent readers (acquire / compact) may still be
     traversing the removed nodes via map.next.  The batch is released
     once all joiner_epochs exceed deferred_acc_epoch. */
  fd_accdb_acc_t * deferred_acc_head;
  fd_accdb_acc_t * deferred_acc_tail;
  ulong            deferred_acc_epoch;

  /* Chain of fork pool slots whose IDs are still potentially
     referenced by concurrent readers (via descends_set_test or
     root_fork_id snapshot).  The chain is released back to fork_pool
     once all joiner_epochs exceed deferred_fork_epoch.  NULL head
     means no deferred forks. */
  fd_accdb_fork_shmem_t * deferred_fork_head;
  fd_accdb_fork_shmem_t * deferred_fork_tail;
  ulong                   deferred_fork_epoch;
};

static inline fd_accdb_cache_line_t *
cache_line( fd_accdb_t * accdb,
            ulong        cls,
            ulong        idx ) {
  return (fd_accdb_cache_line_t *)( accdb->cache[ cls ] + idx * fd_accdb_cache_slot_sz[ cls ] );
}

static inline ulong
cache_line_idx( fd_accdb_t *                  accdb,
                ulong                         cls,
                fd_accdb_cache_line_t const * line ) {
  return (ulong)( (uchar const *)line - accdb->cache[ cls ] ) / fd_accdb_cache_slot_sz[ cls ];
}

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

  // if( FD_UNLIKELY( fd<0 ) ) {
  //   FD_LOG_WARNING(( "fd must be a valid file descriptor" ));
  //   return NULL;
  // }

  ulong max_live_slots = shmem->max_live_slots;
  ulong max_accounts = shmem->max_accounts;
  ulong max_account_writes_per_slot = shmem->max_account_writes_per_slot;
  ulong partition_cnt = shmem->partition_cnt;

  ulong chain_cnt = fd_ulong_pow2_up( (max_accounts>>1) + (max_accounts&1UL) );
  ulong txn_max = max_live_slots * max_account_writes_per_slot;

  FD_SCRATCH_ALLOC_INIT( l, shmem );
                             FD_SCRATCH_ALLOC_APPEND( l, FD_ACCDB_SHMEM_ALIGN,           sizeof(fd_accdb_shmem_t)                                );
  void * _fork_pool_shmem  = FD_SCRATCH_ALLOC_APPEND( l, fork_pool_align(),              fork_pool_footprint()                                   );
  void * _fork_pool_ele    = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_accdb_fork_shmem_t), max_live_slots*sizeof(fd_accdb_fork_shmem_t)            );
  void * _descends_sets    = FD_SCRATCH_ALLOC_APPEND( l, descends_set_align(),           max_live_slots*descends_set_footprint( max_live_slots ) );
  void * _acc_map          = FD_SCRATCH_ALLOC_APPEND( l, alignof(uint),                  chain_cnt*sizeof(uint)                                  );
  void * _acc_pool_shmem   = FD_SCRATCH_ALLOC_APPEND( l, acc_pool_align(),               acc_pool_footprint()                                    );
  void * _acc_pool_ele     = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_accdb_acc_t),        max_accounts*sizeof(fd_accdb_acc_t)                     );
  void * _txn_pool_shmem   = FD_SCRATCH_ALLOC_APPEND( l, txn_pool_align(),               txn_pool_footprint()                                    );
  void * _txn_pool_ele     = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_accdb_txn_t),        txn_max*sizeof(fd_accdb_txn_t)                          );
  void * _partition_pool   = FD_SCRATCH_ALLOC_APPEND( l, partition_pool_align(),         partition_pool_footprint( partition_cnt )               );
  void * _compaction_dlists[ FD_ACCDB_COMPACTION_LAYER_CNT ];
  for( ulong k=0UL; k<FD_ACCDB_COMPACTION_LAYER_CNT; k++ ) {
    _compaction_dlists[ k ] = FD_SCRATCH_ALLOC_APPEND( l, compaction_dlist_align(), compaction_dlist_footprint()                                 );
  }
  void * _deferred_free_dlist = FD_SCRATCH_ALLOC_APPEND( l, deferred_free_dlist_align(), deferred_free_dlist_footprint()                         );

  FD_SCRATCH_ALLOC_INIT( l2, ljoin );
  fd_accdb_t * accdb      = FD_SCRATCH_ALLOC_APPEND( l2, fd_accdb_align(),         sizeof(fd_accdb_t)                     );
  void * _local_fork_pool = FD_SCRATCH_ALLOC_APPEND( l2, alignof(fd_accdb_fork_t), max_live_slots*sizeof(fd_accdb_fork_t) );

  accdb->fd = fd;

  accdb->shmem = (fd_accdb_shmem_t *)shmem;
  FD_TEST( acc_pool_join( accdb->acc_pool_join, _acc_pool_shmem, _acc_pool_ele, max_accounts ) );
  accdb->acc_pool = accdb->acc_pool_join->ele;
  accdb->acc_map = _acc_map;
  FD_TEST( txn_pool_join( accdb->txn_pool, _txn_pool_shmem, _txn_pool_ele, txn_max ) );
  for( ulong c=0UL; c<FD_ACCDB_CACHE_CLASS_CNT; c++ ) accdb->cache[ c ] = (uchar *)shmem + shmem->cache_region_off[ c ];
  accdb->partition_pool = partition_pool_join( _partition_pool );
  FD_TEST( accdb->partition_pool );
  for( ulong k=0UL; k<FD_ACCDB_COMPACTION_LAYER_CNT; k++ ) {
    accdb->compaction_dlist[ k ] = compaction_dlist_join( _compaction_dlists[ k ] );
    FD_TEST( accdb->compaction_dlist[ k ] );
  }
  accdb->deferred_free_dlist = deferred_free_dlist_join( _deferred_free_dlist );
  FD_TEST( accdb->deferred_free_dlist );

  FD_TEST( fork_pool_join( accdb->fork_shmem_pool, _fork_pool_shmem, _fork_pool_ele, max_live_slots ) );
  accdb->fork_pool = _local_fork_pool;
  for( ulong i=0UL; i<max_live_slots; i++ ) {
    fd_accdb_fork_t * fork = &accdb->fork_pool[ i ];
    fork->shmem = fork_pool_ele( accdb->fork_shmem_pool, i );
    fork->descends = descends_set_join( (uchar *)_descends_sets + i*descends_set_footprint( max_live_slots ) );
    FD_TEST( fork->shmem );
    FD_TEST( fork->descends );
  }

  ulong epoch_idx = FD_ATOMIC_FETCH_AND_ADD( &shmem->joiner_cnt, 1UL );
  FD_TEST( epoch_idx<shmem->joiner_cnt_max );
  accdb->my_epoch_slot = &shmem->joiner_epochs[ epoch_idx ].val;

  accdb->deferred_acc_head  = NULL;
  accdb->deferred_acc_tail  = NULL;
  accdb->deferred_acc_epoch = 0UL;

  accdb->deferred_fork_head  = NULL;
  accdb->deferred_fork_tail  = NULL;
  accdb->deferred_fork_epoch = 0UL;

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

/* wait_cmd blocks until any previously submitted T1 -> T2 command has
   been completed by T2.  If no command is in flight (cmd_op is idle),
   returns immediately.  Must be called from T1 before submitting a new
   command or performing inline fork operations. */

static inline void
wait_cmd( fd_accdb_t * accdb ) {
  fd_accdb_shmem_t * shmem = accdb->shmem;
  if( FD_LIKELY( FD_VOLATILE_CONST( shmem->cmd_op )==FD_ACCDB_CMD_IDLE ) ) return;
  for(;;) {
    if( FD_LIKELY( FD_VOLATILE_CONST( shmem->cmd_done ) ) ) break;
    FD_SPIN_PAUSE();
  }
  FD_COMPILER_MFENCE();
  FD_VOLATILE( shmem->cmd_done ) = 0;
  FD_VOLATILE( shmem->cmd_op )   = FD_ACCDB_CMD_IDLE;
  FD_COMPILER_MFENCE();
}

static inline void
submit_cmd( fd_accdb_t * accdb,
            uint         op,
            ushort       fork_id ) {
  fd_accdb_shmem_t * shmem = accdb->shmem;
  FD_VOLATILE( shmem->cmd_fork_id ) = fork_id;
  FD_COMPILER_MFENCE();
  FD_VOLATILE( shmem->cmd_op ) = op;
}

fd_accdb_fork_id_t
fd_accdb_attach_child( fd_accdb_t *       accdb,
                       fd_accdb_fork_id_t parent_fork_id ) {
  wait_cmd( accdb );

  fd_accdb_fork_shmem_t * acquired = fork_pool_acquire( accdb->fork_shmem_pool );
  ulong idx = fork_pool_idx( accdb->fork_shmem_pool, acquired );

  fd_accdb_fork_t * fork = &accdb->fork_pool[ idx ];
  fd_accdb_fork_id_t fork_id = { .val = (ushort)idx };

  fork->shmem->child_id = (fd_accdb_fork_id_t){ .val = USHORT_MAX };

  if( FD_LIKELY( parent_fork_id.val==USHORT_MAX ) ) {
    fork->shmem->parent_id  = (fd_accdb_fork_id_t){ .val = USHORT_MAX };
    fork->shmem->sibling_id = (fd_accdb_fork_id_t){ .val = USHORT_MAX };

    descends_set_null( fork->descends );
    accdb->shmem->root_fork_id = fork_id;
  } else {
    fd_accdb_fork_t * parent = &accdb->fork_pool[ parent_fork_id.val ];
    fork->shmem->parent_id  = parent_fork_id;

    descends_set_copy( fork->descends, parent->descends );
    descends_set_insert( fork->descends, parent_fork_id.val );

    /* Atomically prepend to parent's child list.  T2 (background_purge)
       may concurrently unlink a different child from the same list, so
       we must CAS here. */
    FD_COMPILER_MFENCE();
    for(;;) {
      ushort old_head = FD_VOLATILE_CONST( parent->shmem->child_id.val );
      fork->shmem->sibling_id = (fd_accdb_fork_id_t){ .val = old_head };
      FD_COMPILER_MFENCE();
      if( FD_LIKELY( FD_ATOMIC_CAS( &parent->shmem->child_id.val, old_head, fork_id.val )==old_head ) ) break;
      FD_SPIN_PAUSE();
    }
  }

  fork->shmem->generation = accdb->shmem->generation++;
  fork->shmem->txn_head = UINT_MAX;

  return fork_id;
}

/* cache_free_push pushes a fully-freed cache line onto the per-class
   CAS free list (Treiber stack).  The caller must have already
   invalidated the line (key.generation==UINT_MAX) and set persisted=1
   before pushing. */

static inline void
cache_free_push( fd_accdb_t * accdb,
                 ulong        size_class,
                 fd_accdb_cache_line_t * line ) {
  ulong line_idx = cache_line_idx( accdb, size_class, line );
  for(;;) {
    ulong old_vt  = FD_VOLATILE_CONST( accdb->shmem->cache_free[ size_class ].ver_top );
    uint  old_top = (uint)( old_vt & (ulong)UINT_MAX );
    uint  old_ver = (uint)( old_vt >> 32 );
    line->next = old_top;
    FD_COMPILER_MFENCE();
    ulong new_vt = ((ulong)(uint)( old_ver+1U ) << 32) | (ulong)(uint)line_idx;
    if( FD_LIKELY( FD_ATOMIC_CAS( &accdb->shmem->cache_free[ size_class ].ver_top, old_vt, new_vt )==old_vt ) ) {
      FD_ATOMIC_FETCH_AND_ADD( &accdb->shmem->cache_free_cnt[ size_class ].val, 1UL );
      return;
    }
    FD_SPIN_PAUSE();
  }
}

/* cache_free_pop pops a line from the per-class CAS free list.  Returns
   NULL if the list is empty. */

static inline fd_accdb_cache_line_t *
cache_free_pop( fd_accdb_t * accdb,
                ulong        size_class ) {
  for(;;) {
    ulong old_vt  = FD_VOLATILE_CONST( accdb->shmem->cache_free[ size_class ].ver_top );
    uint  old_top = (uint)( old_vt & (ulong)UINT_MAX );
    if( FD_UNLIKELY( old_top==UINT_MAX ) ) return NULL;
    uint  old_ver = (uint)( old_vt >> 32 );
    fd_accdb_cache_line_t * top = cache_line( accdb, size_class, (ulong)old_top );
    uint next = FD_VOLATILE_CONST( top->next );
    ulong new_vt = ((ulong)(uint)( old_ver+1U ) << 32) | (ulong)next;
    if( FD_LIKELY( FD_ATOMIC_CAS( &accdb->shmem->cache_free[ size_class ].ver_top, old_vt, new_vt )==old_vt ) ) {
      FD_ATOMIC_FETCH_AND_SUB( &accdb->shmem->cache_free_cnt[ size_class ].val, 1UL );
      return top;
    }
    FD_SPIN_PAUSE();
  }
}

/* cache_try_pin attempts a lock-free pin of a cache-hit line.  Returns
   the line if successfully pinned, or NULL if the line is being evicted
   or was recycled (ABA). */

static inline fd_accdb_cache_line_t *
cache_try_pin( fd_accdb_cache_line_t * line,
               uchar const             pubkey[ 32 ],
               uint                    generation ) {
  for(;;) {
    uint old_rc = FD_VOLATILE_CONST( line->refcnt );
    if( FD_UNLIKELY( old_rc==FD_ACCDB_EVICT_SENTINEL ) ) return NULL;
    /* No saturation guard needed: refcnt is a uint and at most
       FD_ACCDB_MAX_JOINERS (256) threads can pin concurrently,
       so old_rc+1 can never reach FD_ACCDB_EVICT_SENTINEL
       (UINT_MAX) or wrap. */
    if( FD_LIKELY( FD_ATOMIC_CAS( &line->refcnt, old_rc, old_rc+1U )==old_rc ) ) {
      /* Pinned.  ABA check: verify the key hasn't changed under us. */
      FD_COMPILER_MFENCE();
      if( FD_UNLIKELY( line->key.generation!=generation ||
                       memcmp( line->key.pubkey, pubkey, 32UL ) ) ) {
        FD_ATOMIC_FETCH_AND_SUB( &line->refcnt, 1U );
        return NULL;
      }
      line->referenced = 1;
      return line;
    }
    FD_SPIN_PAUSE();
  }
}

/* wait_for_epoch_drain spins until every joiner's published epoch
   exceeds tag, meaning all readers that were active at epoch=tag have
   since exited their critical sections. */

static void
wait_for_epoch_drain( fd_accdb_t * accdb,
                      ulong        tag ) {
  for(;;) {
    ulong min_epoch = ULONG_MAX;
    ulong joiner_cnt = FD_VOLATILE_CONST( accdb->shmem->joiner_cnt );
    for( ulong t=0UL; t<joiner_cnt; t++ ) {
      ulong e = FD_VOLATILE_CONST( accdb->shmem->joiner_epochs[ t ].val );
      if( FD_LIKELY( e<min_epoch ) ) min_epoch = e;
    }
    if( FD_LIKELY( tag<min_epoch ) ) break;
    FD_SPIN_PAUSE();
  }
}

/* drain_deferred_frees releases back to their respective pools any acc
   batch and/or fork slots that were unlinked in a prior advance_root /
   purge call.  The resources cannot be released immediately because
   concurrent readers may still reference them. We wait until every
   joiner's published epoch exceeds the tag stamped when each resource
   was unlinked.

   Must be called before creating new deferred batches (there is at most
   one of each outstanding at a time). */

static void
drain_deferred_frees( fd_accdb_t * accdb ) {
  if( FD_UNLIKELY( accdb->deferred_fork_head ) ) {
    wait_for_epoch_drain( accdb, accdb->deferred_fork_epoch );
    fork_pool_release_chain( accdb->fork_shmem_pool, accdb->deferred_fork_head, accdb->deferred_fork_tail );
    accdb->deferred_fork_head = NULL;
    accdb->deferred_fork_tail = NULL;
  }

  if( FD_LIKELY( !accdb->deferred_acc_head ) ) return;
  wait_for_epoch_drain( accdb, accdb->deferred_acc_epoch );
  acc_pool_release_chain( accdb->acc_pool_join, accdb->deferred_acc_head, accdb->deferred_acc_tail );
  accdb->deferred_acc_head = NULL;
  accdb->deferred_acc_tail = NULL;
}

/* acc_unlink unlinks an account from its hash map chain, frees any
   associated disk bytes, and invalidates a stale cache reference.  Does
   NOT release the acc pool slot — the caller is responsible for that
   (or for batching releases).

   prev is the previous element in the map chain (UINT_MAX if acc_idx is
   the head).

   CONCURRENCY: The chain link being removed is swapped out with a CAS
   so that a concurrent fd_accdb_release prepending to the same chain
   cannot lose its update.  If a head-removal CAS fails (a new node was
   prepended since we loaded the head), we re-walk from the new head to
   find the target as an interior node.  Interior CAS cannot fail from
   inserts (inserts only touch the head) and only one remover exists at
   a time (advance_root / purge are serialized). */

static inline void
acc_unlink( fd_accdb_t * accdb,
            uint         map_idx,
            uint         prev,
            uint         acc_idx ) {
  fd_accdb_acc_t * acc = &accdb->acc_pool[ acc_idx ];

  if( FD_LIKELY( fd_accdb_acc_offset(acc)!=FD_ACCDB_OFF_INVAL ) ) {
    fd_accdb_shmem_bytes_freed( accdb->shmem, fd_accdb_acc_offset(acc), (ulong)FD_ACCDB_SIZE_DATA(acc->executable_size)+sizeof(fd_accdb_disk_meta_t) );
    FD_ATOMIC_FETCH_AND_SUB( &accdb->shmem->metrics->disk_used_bytes, (ulong)FD_ACCDB_SIZE_DATA(acc->executable_size)+sizeof(fd_accdb_disk_meta_t) );
  }
  FD_ATOMIC_FETCH_AND_SUB( &accdb->shmem->metrics->accounts_total, 1UL );

  if( FD_LIKELY( prev==UINT_MAX ) ) {
    /* Head removal — CAS may fail if a concurrent insert prepended a
       new node.  On failure the target is now interior. */
    for(;;) {
      uint old_head = FD_VOLATILE_CONST( accdb->acc_map[ map_idx ] );
      if( FD_LIKELY( old_head==acc_idx ) ) {
        if( FD_LIKELY( FD_ATOMIC_CAS( &accdb->acc_map[ map_idx ], acc_idx, acc->map.next )==acc_idx ) ) break;
        FD_SPIN_PAUSE();
        continue;
      }
      /* Head changed — walk from new head to find prev for interior
         removal.  The target must still be in the chain because only
         this thread removes elements. */
      prev = old_head;
      while( FD_VOLATILE_CONST( accdb->acc_pool[ prev ].map.next )!=acc_idx ) prev = FD_VOLATILE_CONST( accdb->acc_pool[ prev ].map.next );
      FD_ATOMIC_CAS( &accdb->acc_pool[ prev ].map.next, acc_idx, acc->map.next );
      break;
    }
  } else {
    FD_ATOMIC_CAS( &accdb->acc_pool[ prev ].map.next, acc_idx, acc->map.next );
  }

  /* If the freed acc still has a cached location, invalidate it and
     try to reclaim the cache line so the eviction path does not try
     to write back stale data from a recycled pool slot.  Lock-free:
     CAS the refcnt 0 -> EVICT_SENTINEL to claim it exclusively, then
     push to the CAS free list.  If the line is pinned (refcnt>0),
     skip, the pinner's release will handle it. */
  uint cidx = acc->cache_idx;
  if( FD_UNLIKELY( FD_ACCDB_SIZE_CACHE_VALID( acc->executable_size ) ) ) {
    acc->cache_idx = FD_ACCDB_ACC_CIDX_INVAL;
    acc->executable_size &= ~FD_ACCDB_SIZE_CACHE_VALID_BIT;
    fd_accdb_cache_line_t * stale = cache_line( accdb, FD_ACCDB_ACC_CIDX_CLASS( cidx ), FD_ACCDB_ACC_CIDX_IDX( cidx ) );
    uint old_rc = FD_ATOMIC_CAS( &stale->refcnt, 0U, FD_ACCDB_EVICT_SENTINEL );
    if( FD_LIKELY( !old_rc ) ) {
      /* Claimed.  Validate key (ABA, slot could have been recycled
         between our read of cache_idx and the CAS). */
      if( FD_LIKELY( stale->key.generation==acc->key.generation &&
                     !memcmp( stale->key.pubkey, acc->key.pubkey, 32UL ) ) ) {
        ulong sc = fd_accdb_cache_class( FD_ACCDB_SIZE_DATA( acc->executable_size ) );
        stale->key.generation = UINT_MAX;
        stale->persisted = 1;
        stale->acc_idx   = UINT_MAX;
        stale->refcnt    = 0;
        cache_free_push( accdb, sc, stale );
      } else {
        /* Wrong line (ABA).  Release claim. */
        FD_VOLATILE( stale->refcnt ) = 0;
      }
    }
    /* If old_rc>0 the line is pinned by an active transaction.  Since
       acc_unlink only runs during advance_root/purge, pinned lines
       can't reference the fork being purged — safe to skip. */
  }
}

/* fork_slot_defer removes fork_id from every descends_set and chains
   the fork pool slot onto the deferred fork chain for later release.
   The slot must not be released immediately because concurrent readers
   may still reference the fork ID via descends_set or stale chain
   walks.

   The eager descends_set_remove here is safe despite being a
   non-atomic RMW that races with concurrent descends_set_test in
   fd_accdb_acquire, for two reasons:

   (a) Rooted parent forks: after advance_root publishes the new
       root_fork_id, any acquire loads root_generation >=
       parent->generation.  Every account from the old parent has
       generation <= parent->generation, so the
       "generation > root_generation" gate in the chain walk is
       never satisfied and the parent's bit is never tested.

   (b) Purged / pruned sibling forks: a purged fork is by
       definition not an ancestor of any live fork, so its bit
       was never set in any live fork's descends_set.  Clearing
       it is a literal no-op.

   Fork-id ABA after slot reuse is also safe: the fork pool slot
   is not released until drain_deferred_frees, which waits until
   all epoch-protected readers have exited.  On x86 (TSO), the
   synchronization chain (T2: bit clear -> epoch FAA; reader:
   epoch load -> epoch_slot store -> mfence -> bit read) guarantees
   that any reader entering a new epoch section after the drain
   will observe the cleared bit before the slot is recycled by
   attach_child. */

static inline void
fork_slot_defer( fd_accdb_t *              accdb,
                 fd_accdb_fork_id_t         fork_id,
                 fd_accdb_fork_shmem_t **   fork_head,
                 fd_accdb_fork_shmem_t **   fork_tail ) {
  for( ulong i=0UL; i<accdb->shmem->max_live_slots; i++ ) descends_set_remove( accdb->fork_pool[ i ].descends, fork_id.val );
  fd_accdb_fork_shmem_t * shmem = fork_pool_ele( accdb->fork_shmem_pool, (ulong)fork_id.val );
  if( *fork_tail ) (*fork_tail)->pool.next = fork_pool_private_cidx( (ulong)fork_id.val );
  else             *fork_head = shmem;
  *fork_tail = shmem;
}

static void
purge_inner( fd_accdb_t *              accdb,
             fd_accdb_fork_id_t         fork_id,
             fd_accdb_acc_t   **        acc_head,
             fd_accdb_acc_t   **        acc_tail,
             fd_accdb_fork_shmem_t **   fork_head,
             fd_accdb_fork_shmem_t **   fork_tail ) {
  fd_accdb_fork_t * fork = &accdb->fork_pool[ fork_id.val ];

  fd_accdb_fork_id_t child = fork->shmem->child_id;
  while( child.val!=USHORT_MAX ) {
    fd_accdb_fork_id_t next = accdb->fork_pool[ child.val ].shmem->sibling_id;
    purge_inner( accdb, child, acc_head, acc_tail, fork_head, fork_tail );
    child = next;
  }

  uint txn = fork->shmem->txn_head;
  if( txn!=UINT_MAX ) {
    fd_accdb_txn_t * txn_head = txn_pool_ele( accdb->txn_pool, (ulong)txn );
    fd_accdb_txn_t * txn_tail = NULL;
    while( txn!=UINT_MAX ) {
      fd_accdb_txn_t * txne = txn_pool_ele( accdb->txn_pool, (ulong)txn );

      uint acc_idx = txne->acc_pool_idx;

      uint prev = UINT_MAX;
      uint cur = FD_VOLATILE_CONST( accdb->acc_map[ txne->acc_map_idx ] );
      while( cur!=acc_idx ) {
        prev = cur;
        cur = FD_VOLATILE_CONST( accdb->acc_pool[ cur ].map.next );
      }

      acc_unlink( accdb, txne->acc_map_idx, prev, acc_idx );

      fd_accdb_acc_t * freed = &accdb->acc_pool[ acc_idx ];
      if( *acc_tail ) (*acc_tail)->pool.next = acc_pool_private_cidx( (ulong)acc_idx );
      else            *acc_head = freed;
      *acc_tail = freed;

      txn_tail = txne;
      txn = txne->fork.next;
    }
    txn_pool_release_chain( accdb->txn_pool, txn_head, txn_tail );
  }

  fork_slot_defer( accdb, fork_id, fork_head, fork_tail );
}

static inline void
remove_children( fd_accdb_t *              accdb,
                 fd_accdb_fork_t *          fork,
                 fd_accdb_fork_t *          except,
                 fd_accdb_acc_t   **        acc_head,
                 fd_accdb_acc_t   **        acc_tail,
                 fd_accdb_fork_shmem_t **   fork_head,
                 fd_accdb_fork_shmem_t **   fork_tail ) {
  fd_accdb_fork_id_t sibling_idx = fork->shmem->child_id;
  while( sibling_idx.val!=USHORT_MAX ) {
    fd_accdb_fork_t * sibling = &accdb->fork_pool[ sibling_idx.val ];
    fd_accdb_fork_id_t cur_idx = sibling_idx;

    sibling_idx = sibling->shmem->sibling_id;
    if( FD_UNLIKELY( sibling==except ) ) continue;

    purge_inner( accdb, cur_idx, acc_head, acc_tail, fork_head, fork_tail );
  }
}

static void
background_advance_root( fd_accdb_t *       accdb,
                         fd_accdb_fork_id_t fork_id ) {
  drain_deferred_frees( accdb );

  /* The caller guarantees that rooting is sequential: each call
     advances the root by exactly one slot (the immediate child of the
     current root).  Skipping levels is not supported. */
  fd_accdb_fork_t * fork = &accdb->fork_pool[ fork_id.val ];
  FD_LOG_WARNING(( "Advancing root from %hu to %hu", accdb->shmem->root_fork_id.val, fork_id.val ));
  FD_TEST( fork->shmem->parent_id.val==accdb->shmem->root_fork_id.val );
  FD_TEST( fork->shmem->parent_id.val!=USHORT_MAX );

  fd_accdb_fork_t * parent_fork = &accdb->fork_pool[ fork->shmem->parent_id.val ];

  /* Accumulate all freed acc pool elements and fork pool slots across
     remove_children and the old-version cleanup below into chains that
     will be deferred-released after the epoch bump. */
  fd_accdb_acc_t * acc_head = NULL;
  fd_accdb_acc_t * acc_tail = NULL;
  fd_accdb_fork_shmem_t * fork_head = NULL;
  fd_accdb_fork_shmem_t * fork_tail = NULL;

  /* When a fork is rooted, any competing forks can be immediately
     removed as they will not be needed again.  This includes child
     forks of the pruned siblings as well. */
  remove_children( accdb, parent_fork, fork, &acc_head, &acc_tail, &fork_head, &fork_tail );

  /* And for any accounts which were updated in the newly rooted slot,
     we will now never need to access any older version, so we can
     discard any slots earlier than the one we are rooting. */
  uint txn = fork->shmem->txn_head;
  if( txn!=UINT_MAX ) {
    fd_accdb_txn_t * txn_head = txn_pool_ele( accdb->txn_pool, (ulong)txn );
    fd_accdb_txn_t * txn_tail = NULL;
    while( txn!=UINT_MAX ) {
      fd_accdb_txn_t * txne = txn_pool_ele( accdb->txn_pool, (ulong)txn );

      fd_accdb_acc_t const * new_acc = &accdb->acc_pool[ txne->acc_pool_idx ];

      uint prev = UINT_MAX;
      uint acc = FD_VOLATILE_CONST( accdb->acc_map[ txne->acc_map_idx ] );
      FD_TEST( acc!=UINT_MAX );
      while( acc!=UINT_MAX ) {
        fd_accdb_acc_t const * cur_acc = &accdb->acc_pool[ acc ];
        uint cur_next = FD_VOLATILE_CONST( cur_acc->map.next );

        if( FD_LIKELY( acc==txne->acc_pool_idx ) ) {
          prev = acc;
          acc = cur_next;
          continue;
        }

        if( FD_LIKELY( (cur_acc->key.generation<=parent_fork->shmem->generation || descends_set_test( fork->descends, fd_accdb_acc_fork_id(cur_acc) ) ) && !memcmp( new_acc->key.pubkey, cur_acc->key.pubkey, 32UL ) ) ) {
          uint next = cur_next;
          acc_unlink( accdb, txne->acc_map_idx, prev, acc );

          fd_accdb_acc_t * freed = &accdb->acc_pool[ acc ];
          if( FD_LIKELY( acc_tail ) ) acc_tail->pool.next = acc_pool_private_cidx( (ulong)acc );
          else                        acc_head = freed;
          acc_tail = freed;

          acc = next;
        } else {
          prev = acc;
          acc = cur_next;
        }
      }

      txn_tail = txne;
      txn = txne->fork.next;
    }
    txn_pool_release_chain( accdb->txn_pool, txn_head, txn_tail );
  }

  uint parent_txn = parent_fork->shmem->txn_head;
  if( parent_txn!=UINT_MAX ) {
    fd_accdb_txn_t * parent_head = txn_pool_ele( accdb->txn_pool, (ulong)parent_txn );
    fd_accdb_txn_t * parent_tail = NULL;
    while( parent_txn!=UINT_MAX ) {
      fd_accdb_txn_t * t = txn_pool_ele( accdb->txn_pool, (ulong)parent_txn );
      parent_tail = t;
      parent_txn = t->fork.next;
    }
    txn_pool_release_chain( accdb->txn_pool, parent_head, parent_tail );
  }

  /* Remove the parent from all descends_sets and chain it for deferred
     release, so that when the slot is eventually recycled to a new
     fork, no concurrent reader can mistake the new fork for the old
     ancestor.  Entries from the freed parent are still visible via the
     generation <= root_generation fast path in reads. */
  fd_accdb_fork_id_t old_parent_id = fork->shmem->parent_id;
  fork_slot_defer( accdb, old_parent_id, &fork_head, &fork_tail );

  fork->shmem->parent_id  = (fd_accdb_fork_id_t){ .val = USHORT_MAX };
  fork->shmem->sibling_id = (fd_accdb_fork_id_t){ .val = USHORT_MAX };
  fork->shmem->txn_head   = UINT_MAX;
  descends_set_null( fork->descends );

  /* Publish the new root_fork_id BEFORE bumping the epoch and deferring
     the parent slot.  On x86-64 (TSO) a concurrent reader that still
     loads the old root_fork_id is guaranteed to see the parent shmem in
     its original (not-yet-recycled) state because the slot has not been
     released yet.  A reader that loads the new root_fork_id uses the
     new fork. */
  accdb->shmem->root_fork_id = fork_id;
  FD_COMPILER_MFENCE();

  /* Bump epoch and defer both the acc batch and parent fork slot. They
     will be released at the next drain_deferred_frees call once all
     concurrent readers have exited. */
  ulong tag = FD_ATOMIC_FETCH_AND_ADD( &accdb->shmem->epoch, 1UL );
  if( FD_LIKELY( acc_head ) ) {
    accdb->deferred_acc_head  = acc_head;
    accdb->deferred_acc_tail  = acc_tail;
    accdb->deferred_acc_epoch = tag;
  }
  if( FD_LIKELY( fork_head ) ) {
    accdb->deferred_fork_head  = fork_head;
    accdb->deferred_fork_tail  = fork_tail;
    accdb->deferred_fork_epoch = tag;
  }
}

void
fd_accdb_advance_root( fd_accdb_t *       accdb,
                       fd_accdb_fork_id_t fork_id ) {
  wait_cmd( accdb );
  FD_LOG_WARNING(( "Submitted advance_root for fork_id %hu, current %hu", fork_id.val, accdb->shmem->root_fork_id.val ));
  submit_cmd( accdb, FD_ACCDB_CMD_ADVANCE_ROOT, fork_id.val );
}

/* background_purge does the heavy lifting of purge on T2: unlink the
   fork from the parent's child list, drain deferred frees, recursively
   purge the fork subtree, and defer-release the freed acc pool
   elements.  The sibling-list unlink is done here (not on T1) because
   advance_root / remove_children also mutate sibling lists on T2, and
   T2 is single-threaded so plain stores are safe. */

static void
background_purge( fd_accdb_t *       accdb,
                  fd_accdb_fork_id_t fork_id ) {
  /* Unlink fork_id from its parent's child list.  This runs on T2
     which is the sole mutator of sibling lists (advance_root and
     remove_children also run on T2), so plain stores are safe. */
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

  drain_deferred_frees( accdb );

  fd_accdb_acc_t * acc_head = NULL;
  fd_accdb_acc_t * acc_tail = NULL;
  fd_accdb_fork_shmem_t * fork_head = NULL;
  fd_accdb_fork_shmem_t * fork_tail = NULL;
  purge_inner( accdb, fork_id, &acc_head, &acc_tail, &fork_head, &fork_tail );

  ulong tag = FD_ATOMIC_FETCH_AND_ADD( &accdb->shmem->epoch, 1UL );
  if( FD_LIKELY( acc_head ) ) {
    accdb->deferred_acc_head  = acc_head;
    accdb->deferred_acc_tail  = acc_tail;
    accdb->deferred_acc_epoch = tag;
  }
  if( FD_LIKELY( fork_head ) ) {
    accdb->deferred_fork_head  = fork_head;
    accdb->deferred_fork_tail  = fork_tail;
    accdb->deferred_fork_epoch = tag;
  }
}

void
fd_accdb_purge( fd_accdb_t *       accdb,
                fd_accdb_fork_id_t fork_id ) {
  FD_TEST( fork_id.val!=accdb->shmem->root_fork_id.val );

  wait_cmd( accdb );
  submit_cmd( accdb, FD_ACCDB_CMD_PURGE, fork_id.val );
}

static inline fd_accdb_cache_line_t *
acquire_cache_line( fd_accdb_t * accdb,
                    ulong        size_class,
                    uint *       out_evicted_acc_idx ) {
  /* Priority 1: CAS free list — already invalidated,
     persisted==1, generation==UINT_MAX.  Cheapest path. */
  fd_accdb_cache_line_t * result = cache_free_pop( accdb, size_class );
  if( FD_LIKELY( result ) ) {
    result->refcnt     = 1;
    result->referenced = 0;
    *out_evicted_acc_idx = UINT_MAX;
    return result;
  }

  /* Priority 2: Lazy initial allocation — atomic FAA with undo on
     overflow.  Safe for concurrent callers. */
  ulong old_init = FD_ATOMIC_FETCH_AND_ADD( &accdb->shmem->cache_class_init[ size_class ].val, 1UL );
  if( FD_LIKELY( old_init<accdb->shmem->cache_class_max[ size_class ] ) ) {
    result = cache_line( accdb, size_class, old_init );
    result->refcnt         = 1;
    result->persisted      = 1;
    result->referenced     = 0;
    result->acc_idx        = UINT_MAX;
    result->key.generation = UINT_MAX;
    *out_evicted_acc_idx   = UINT_MAX;
    return result;
  }
  FD_ATOMIC_FETCH_AND_SUB( &accdb->shmem->cache_class_init[ size_class ].val, 1UL );

  /* Priority 3: CLOCK sweep ... scan forward giving second chances. */
  for(;;) {
    ulong hand = FD_ATOMIC_FETCH_AND_ADD( &accdb->shmem->clock_hand[ size_class ].val, 1UL ) % accdb->shmem->cache_class_max[ size_class ];
    fd_accdb_cache_line_t * line = cache_line( accdb, size_class, hand );

    if( FD_UNLIKELY( line->key.generation==UINT_MAX && line->acc_idx==UINT_MAX ) ) continue;

    uint rc = FD_VOLATILE_CONST( line->refcnt );
    if( FD_UNLIKELY( rc!=0U ) ) continue; /* Pinned or being evicted */

    if( FD_UNLIKELY( line->referenced ) ) {
      line->referenced = 0;
      continue; /* Second chance */
    }

    if( FD_UNLIKELY( FD_ATOMIC_CAS( &line->refcnt, 0U, FD_ACCDB_EVICT_SENTINEL )!=0U ) ) continue;

    if( FD_LIKELY( line->acc_idx!=UINT_MAX ) ) {
      FD_VOLATILE( accdb->acc_pool[ line->acc_idx ].cache_idx ) = FD_ACCDB_ACC_CIDX_INVAL;
      FD_VOLATILE( accdb->acc_pool[ line->acc_idx ].executable_size ) &= ~FD_ACCDB_SIZE_CACHE_VALID_BIT;
    }
    *out_evicted_acc_idx    = line->persisted ? UINT_MAX : line->acc_idx;
    line->key.generation    = UINT_MAX;
    line->refcnt            = 1;
    line->referenced        = 0;
    return line;
  }

  FD_TEST( 0 );
  return NULL;
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

  ulong free_size = accdb->shmem->partition_sz - partition_offset_before;
  if( FD_LIKELY( *has_partition ) ) {
    fd_accdb_partition_t * old = partition_pool_ele( accdb->partition_pool, partition_idx_before );
    FD_ATOMIC_FETCH_AND_ADD( &old->bytes_freed, free_size );
  }

  if( FD_UNLIKELY( !partition_pool_free( accdb->partition_pool ) ) ) FD_LOG_ERR(( "accounts database file is at capacity" ));
  fd_accdb_partition_t * partition = partition_pool_ele_acquire( accdb->partition_pool );
  partition->bytes_freed       = 0UL;
  partition->marked_compaction = 0;
  partition->layer             = layer;

  ulong new_partition_idx = partition_pool_idx( accdb->partition_pool, partition );
  int had_partition = *has_partition;
  *out_offset   = accdb_offset( new_partition_idx, 0UL );
  *has_partition = 1;

  /* Now that the write head has been rotated away from the old
     partition, check if it should be enqueued for compaction.  We call
     try_enqueue directly because the caller already holds
     partition_lock (calling fd_accdb_shmem_bytes_freed here would
     deadlock on the non-reentrant lock).  Skip when
     has_partition was 0, because the sentinel partition_idx is
     not a valid pool element. */
  if( FD_LIKELY( had_partition && partition_idx_before!=new_partition_idx ) ) {
    fd_accdb_shmem_try_enqueue_compaction( accdb->shmem, partition_idx_before );
  }

  if( FD_UNLIKELY( new_partition_idx>=accdb->shmem->partition_max ) ) {
    FD_LOG_NOTICE(( "growing accounts database from %lu GiB to %lu GiB", accdb->shmem->partition_max*accdb->shmem->partition_sz/(1UL<<30UL), (new_partition_idx+1UL)*accdb->shmem->partition_sz/(1UL<<30UL) ));

    int result = fallocate( accdb->fd, 0, (long)(new_partition_idx*accdb->shmem->partition_sz), (long)accdb->shmem->partition_sz );
    if( FD_UNLIKELY( -1==result ) ) {
      if( FD_LIKELY( errno==ENOSPC ) ) FD_LOG_ERR(( "fallocate() failed (%d-%s). The accounts database filled "
                                                    "the disk it is on, trying to grow from %lu GiB to %lu GiB. Please "
                                                    "free up disk space and restart the validator.",
                                                    errno, fd_io_strerror( errno ), accdb->shmem->partition_max*accdb->shmem->partition_sz/(1UL<<30UL), (new_partition_idx+1UL)*accdb->shmem->partition_sz/(1UL<<30UL) ));
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
      ulong stale_partition = packed_partition_idx( offset );
      while( packed_partition_idx( (accdb_offset_t){ .val = FD_VOLATILE_CONST( accdb->shmem->whead[ 0 ].val ) } )==stale_partition ) FD_SPIN_PAUSE();
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

static void
background_compact( fd_accdb_t * accdb,
                    ulong        src_layer,
                    int *        charge_busy ) {
  FD_COMPILER_MFENCE();
  FD_VOLATILE( *accdb->my_epoch_slot ) = FD_VOLATILE_CONST( accdb->shmem->epoch );
  FD_HW_MFENCE(); /* StoreLoad: epoch store must be globally visible
                     before any subsequent loads so the deferred
                     reclamation scan does not miss us. */

  /* Reclaim any deferred-free partitions whose epoch has been observed
     by all joiners (i.e. no epoch-publishing joiner could still be
     referencing data in them). */
  ulong min_epoch = ULONG_MAX;
  ulong joiner_cnt = FD_VOLATILE_CONST( accdb->shmem->joiner_cnt );
  for( ulong t=0UL; t<joiner_cnt; t++ ) {
    ulong e = FD_VOLATILE_CONST( accdb->shmem->joiner_epochs[ t ].val );
    if( FD_LIKELY( e<min_epoch ) ) min_epoch = e;
  }
  for(;;) {
    if( FD_LIKELY( deferred_free_dlist_is_empty( accdb->deferred_free_dlist, accdb->partition_pool ) ) ) break;
    fd_accdb_partition_t * p = deferred_free_dlist_ele_peek_head( accdb->deferred_free_dlist, accdb->partition_pool );
    if( FD_LIKELY( p->epoch_tag>=min_epoch ) ) break;

    spin_lock_acquire( &accdb->shmem->partition_lock );
    deferred_free_dlist_ele_pop_head( accdb->deferred_free_dlist, accdb->partition_pool );
    partition_pool_ele_release( accdb->partition_pool, p );
    spin_lock_release( &accdb->shmem->partition_lock );
  }

  if( FD_LIKELY( compaction_dlist_is_empty( accdb->compaction_dlist[ src_layer ], accdb->partition_pool ) ) ) {
    FD_COMPILER_MFENCE();
    FD_VOLATILE( *accdb->my_epoch_slot ) = ULONG_MAX;
    return;
  }
  fd_accdb_partition_t * compact = compaction_dlist_ele_peek_head( accdb->compaction_dlist[ src_layer ], accdb->partition_pool );
  if( FD_UNLIKELY( !compact ) ) {
    FD_COMPILER_MFENCE();
    FD_VOLATILE( *accdb->my_epoch_slot ) = ULONG_MAX;
    return;
  }

  /* Wait until all epoch-publishing joiners that were active when this
     partition was enqueued for compaction have exited, ensuring any
     in-flight pwritev2 to this partition has completed before we start
     reading from it. */
  if( FD_UNLIKELY( compact->compaction_ready_epoch>=min_epoch ) ) {
    FD_COMPILER_MFENCE();
    FD_VOLATILE( *accdb->my_epoch_slot ) = ULONG_MAX;
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
  uint acc_idx = FD_VOLATILE_CONST( accdb->acc_map[ fd_accdb_hash( meta->pubkey, accdb->shmem->seed )&(accdb->shmem->chain_cnt-1UL) ] );
  while( acc_idx!=UINT_MAX ) {
    fd_accdb_acc_t * candidate = &accdb->acc_pool[ acc_idx ];
    uint next_idx = FD_VOLATILE_CONST( candidate->map.next );
    if( FD_LIKELY( fd_accdb_acc_offset(candidate)==compact_base+compact->compaction_offset ) ) {
      acc = candidate;
      break;
    }
    acc_idx = next_idx;
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
       overwrote the offset to FD_ACCDB_OFF_INVAL (dirty sentinel for
       a new commit), the CAS fails and we treat the record as
       superseded — the new data is in cache only and our relocated
       copy is stale.  We CAS the full packed offset_fork so the
       12-bit fork_id is preserved. */
    ulong old_packed = FD_VOLATILE_CONST( acc->offset_fork );
    ulong new_packed = ( old_packed & ~FD_ACCDB_OFF_MASK ) | ( dest_offset & FD_ACCDB_OFF_MASK );
    if( FD_UNLIKELY( FD_ATOMIC_CAS( &acc->offset_fork, old_packed, new_packed )!=old_packed ) ) {
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

    /* Ensure the new acc->offset_fork stores above are visible to other
       cores before the source partition is moved to the deferred-free
       list.  On x86 (TSO) hardware store ordering already guarantees
       this, but the compiler fence prevents the compiler from sinking
       the offset store past the inlined pool/dlist mutations below. */
    FD_COMPILER_MFENCE();

    /* Bump the global epoch and tag this partition so the reclamation
       scan knows when all epoch-publishing joiners that could reference
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
}

#define RESERVATION_TYPE_SIMPLE            (0)
#define RESERVATION_TYPE_MAYBE_PROGRAMDATA (1)
#define RESERVATION_TYPE_ALREADY_RESERVED  (2)

static void
fd_accdb_acquire_inner( fd_accdb_t *          accdb,
                        fd_accdb_fork_id_t    fork_id,
                        int                   reservation_type,
                        ulong                 pubkeys_cnt,
                        uchar const * const * pubkeys,
                        int *                 writable,
                        fd_accdb_entry_t *    out_entries ) {
  FD_TEST( pubkeys_cnt<=5UL*(2UL+MAX_TX_ACCOUNT_LOCKS) );
  FD_COMPILER_MFENCE();
  FD_VOLATILE( *accdb->my_epoch_slot ) = FD_VOLATILE_CONST( accdb->shmem->epoch );
  FD_HW_MFENCE(); /* StoreLoad: epoch store must be globally visible
                     before any subsequent loads so the deferred
                     reclamation scan does not miss us */

  // STEP 1.
  //   Locate each account in the fork and index structure, to determine
  //   if it already exists, its size and other metadata, and which
  //   specific slot (generation) it was last written in.

  fd_accdb_fork_t * fork = &accdb->fork_pool[ fork_id.val ];
  uint root_generation = accdb->fork_pool[ accdb->shmem->root_fork_id.val ].shmem->generation;

  fd_accdb_acc_t * accs[ 5UL*(2UL+MAX_TX_ACCOUNT_LOCKS) ];
  ulong acc_map_idxs[ 5UL*(2UL+MAX_TX_ACCOUNT_LOCKS) ];

  /* Walk the hash chain for each pubkey and take the first visible
     match.  Correctness relies on newer entries always being prepended
     to the chain head, which is guaranteed because replay processes
     writes in slot order and release always inserts at the head.

     CONCURRENCY: This chain walk runs epoch-protected.  A concurrent
     fd_accdb_release may prepend a new node to the same chain while
     we walk it.  This is safe on x86-64 (TSO): the releasing thread
     stores all acc fields (pubkey, generation, map.next, ...) before
     publishing the new head via a CAS on acc_map[idx], and TSO
     guarantees a reading core that observes the new head also observes
     all prior stores to the node.  A reader that does not yet see the
     new head simply sees an older (still valid) version of the chain.
     On weakly-ordered architectures an explicit acquire fence would be
     needed before the chain walk and a release fence in
     fd_accdb_release before the head-pointer store.  Multiple
     concurrent releases serialize on the CAS of the chain head. */
  for( ulong i=0UL; i<pubkeys_cnt; i++ ) {
    acc_map_idxs[ i ] = fd_accdb_hash( pubkeys[ i ], accdb->shmem->seed )&(accdb->shmem->chain_cnt-1UL);
    uint acc = FD_VOLATILE_CONST( accdb->acc_map[ acc_map_idxs[ i ] ] );
    while( acc!=UINT_MAX ) {
      fd_accdb_acc_t const * candidate_acc = &accdb->acc_pool[ acc ];
      uint next_acc = FD_VOLATILE_CONST( candidate_acc->map.next );

      if( FD_UNLIKELY( (candidate_acc->key.generation>root_generation &&
                        fd_accdb_acc_fork_id(candidate_acc)!=fork_id.val &&
                        !descends_set_test( fork->descends, fd_accdb_acc_fork_id(candidate_acc) )) ) ||
                        memcmp( pubkeys[ i ], candidate_acc->key.pubkey, 32UL ) ) {
        acc = next_acc;
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
  //   grow the account, so needs the max size class).  Even if theI thi
  //   account is already in the 10MiB cache class, we need another one
  //   because a transaction can fail half way, so we need scratch space
  //   to be able to unwind.
  //
  //   So we acquire one of each size class.  Then when the transaction
  //   finishes, if it succeeded, we will copy the data back to the
  //   whichever size-class is now right-sized post execution.
  if( FD_LIKELY( reservation_type==RESERVATION_TYPE_SIMPLE || reservation_type==RESERVATION_TYPE_MAYBE_PROGRAMDATA ) ) {
    ulong requested_buckets[ FD_ACCDB_CACHE_CLASS_CNT ] = {0};
    for( ulong i=0UL; i<pubkeys_cnt; i++ ) {
      if( FD_UNLIKELY( !accs[ i ] && !writable[ i ] ) ) continue;

      if( FD_LIKELY( accs[ i ] ) ) {
        if( FD_UNLIKELY( accdb->shmem->cache_class_used[ fd_accdb_cache_class( FD_ACCDB_SIZE_DATA( accs[ i ]->executable_size ) ) ].val!=ULONG_MAX ) ) {
          requested_buckets[ fd_accdb_cache_class( FD_ACCDB_SIZE_DATA( accs[ i ]->executable_size ) ) ]++;
        }
      }
      if( FD_UNLIKELY( writable[ i ] ) ) {
        for( ulong j=0UL; j<FD_ACCDB_CACHE_CLASS_CNT; j++ ) {
          if( FD_UNLIKELY( accdb->shmem->cache_class_used[ j ].val!=ULONG_MAX ) ) {
            requested_buckets[ j ]++;
          }
        }
      }

      if( FD_LIKELY( reservation_type==RESERVATION_TYPE_MAYBE_PROGRAMDATA ) ) {
        /* Any account could also have an implied reference to a
          programdata account, which we don't know yet ... so we need to
          reserve worst case space if they all went to the same size
          class. */
        for( ulong j=0UL; j<FD_ACCDB_CACHE_CLASS_CNT; j++ ) {
          if( FD_UNLIKELY( accdb->shmem->cache_class_used[ j ].val!=ULONG_MAX ) ) {
            requested_buckets[ j ]++;
          }
        }
      }
    }

    /* TODO: This over-reserves cache slots for writable accounts that
      already exist.  For each such account we reserve one line in the
      account's size class (for the read into cache) AND one line in
      every size class (for the write destination buffers). But if the
      account is already resident in cache (which is the common case for
      hot accounts), the read-into-cache line is unnecessary — we will
      get a cache hit in step 3 and never use it.  The fix is to probe
      acc->cache_idx here and skip the per-account size class reservation
      per-account size class reservation when a hit is found. This would
      reduce peak reservation by up to one line per writable account per
      acquire batch, lowering contention on the cache class counters and
      allowing smaller cache provisioning. */

    /* Reserve cache slots by atomically incrementing the shared used
      counters.  If any class exceeds its max, the reservation
      overflowed — subtract back partial grabs and retry. */
    for(;;) {
      int acquire_failed = 0;
      ulong grabbed[ FD_ACCDB_CACHE_CLASS_CNT ] = {0};
      for( ulong i=0UL; i<FD_ACCDB_CACHE_CLASS_CNT; i++ ) {
        if( FD_LIKELY( !requested_buckets[ i ] ) ) continue;
        ulong new_used = FD_ATOMIC_ADD_AND_FETCH( &accdb->shmem->cache_class_used[ i ].val, requested_buckets[ i ] );
        if( FD_UNLIKELY( new_used>accdb->shmem->cache_class_max[ i ] ) ) {
          FD_ATOMIC_FETCH_AND_SUB( &accdb->shmem->cache_class_used[ i ].val, requested_buckets[ i ] );
          acquire_failed = 1;
        } else {
          grabbed[ i ] = requested_buckets[ i ];
        }
        if( FD_UNLIKELY( acquire_failed ) ) {
          for( ulong j=0UL; j<i; j++ ) {
            if( grabbed[ j ] ) FD_ATOMIC_FETCH_AND_SUB( &accdb->shmem->cache_class_used[ j ].val, grabbed[ j ] );
          }
          FD_SPIN_PAUSE();
          break;
        }
      }
      if( FD_LIKELY( !acquire_failed ) ) break;
    }
  }

  // STEP 3.
  //   For any accounts that are not in cache, we now need to actually
  //   retrieve the cache pointers from our structures.  Space has been
  //   reserved already, so this step is guaranteed to succeed, and is
  //   just pulling the cache lines out of the free lists and marking
  //   them as in-use.
  //
  //   This step is fully lock-free.  Cache hits are pinned with an
  //   atomic CAS on refcnt (cache_try_pin).  Eviction uses the CLOCK
  //   algorithm.  The CAS free list provides immediate recycling of
  //   fully-freed lines.

  int exists_in_cache[ 5UL*(2UL+MAX_TX_ACCOUNT_LOCKS) ];
  fd_accdb_cache_line_t * original_cache_line[ 5UL*(2UL+MAX_TX_ACCOUNT_LOCKS) ];
  fd_accdb_cache_line_t * destination_cache_lines[ 5UL*(2UL+MAX_TX_ACCOUNT_LOCKS) ][ FD_ACCDB_CACHE_CLASS_CNT ];

  /* Saved acc_pool indices of evicted dirty cache lines.  These are
     captured before clearing acc_idx to UINT_MAX on the line struct, so
     that the sentinel protocol (step 13) works correctly while the
     evicted account metadata is still available for writeback in steps
     4 and 6. */
  uint evicted_dest_acc[ 5UL*(2UL+MAX_TX_ACCOUNT_LOCKS) ][ FD_ACCDB_CACHE_CLASS_CNT ];
  uint evicted_orig_acc[ 5UL*(2UL+MAX_TX_ACCOUNT_LOCKS) ];

  for( ulong i=0UL; i<pubkeys_cnt; i++ ) {
    if( FD_UNLIKELY( !accs[ i ] && !writable[ i ] ) ) continue;

    original_cache_line[ i ] = NULL;
    if( FD_LIKELY( accs[ i ] ) ) {
      if( FD_LIKELY( FD_ACCDB_SIZE_CACHE_VALID( accs[ i ]->executable_size ) ) ) {
        uint cidx = accs[ i ]->cache_idx;
        fd_accdb_cache_line_t * hit = cache_line( accdb, FD_ACCDB_ACC_CIDX_CLASS( cidx ), FD_ACCDB_ACC_CIDX_IDX( cidx ) );
        original_cache_line[ i ] = cache_try_pin( hit, pubkeys[ i ], accs[ i ]->key.generation );
      }
    }
    exists_in_cache[ i ] = original_cache_line[ i ]!=NULL;

    if( FD_UNLIKELY( writable[ i ] ) ) {
      for( ulong j=0UL; j<FD_ACCDB_CACHE_CLASS_CNT; j++ ) destination_cache_lines[ i ][ j ] = acquire_cache_line( accdb, j, &evicted_dest_acc[ i ][ j ] );
      if( FD_LIKELY( accs[ i ] ) && FD_UNLIKELY( !original_cache_line[ i ] ) ) {
        ulong size_class = fd_accdb_cache_class( FD_ACCDB_SIZE_DATA( accs[ i ]->executable_size ) );
        original_cache_line[ i ] = acquire_cache_line( accdb, size_class, &evicted_orig_acc[ i ] ); /* TODO: Optimize. Sometimes not needed if same generation overwrite? */
        fd_memcpy( original_cache_line[ i ]->key.pubkey, accs[ i ]->key.pubkey, 32UL );
        original_cache_line[ i ]->key.generation = accs[ i ]->key.generation;
        original_cache_line[ i ]->acc_idx = (uint)( accs[ i ] - accdb->acc_pool );
        FD_VOLATILE( accs[ i ]->cache_idx ) = FD_ACCDB_ACC_CIDX_PACK( (uint)size_class, (uint)cache_line_idx( accdb, size_class, original_cache_line[ i ] ) );
        FD_VOLATILE( accs[ i ]->executable_size ) |= FD_ACCDB_SIZE_CACHE_VALID_BIT;
      }
    } else {
      if( FD_UNLIKELY( !original_cache_line[ i ] ) ) {
        ulong size_class = fd_accdb_cache_class( FD_ACCDB_SIZE_DATA( accs[ i ]->executable_size ) );
        original_cache_line[ i ] = acquire_cache_line( accdb, size_class, &evicted_orig_acc[ i ] );
        fd_memcpy( original_cache_line[ i ]->key.pubkey, accs[ i ]->key.pubkey, 32UL );
        original_cache_line[ i ]->key.generation = accs[ i ]->key.generation;
        original_cache_line[ i ]->acc_idx = (uint)( accs[ i ] - accdb->acc_pool );
        FD_VOLATILE( accs[ i ]->cache_idx ) = FD_ACCDB_ACC_CIDX_PACK( (uint)size_class, (uint)cache_line_idx( accdb, size_class, original_cache_line[ i ] ) );
        FD_VOLATILE( accs[ i ]->executable_size ) |= FD_ACCDB_SIZE_CACHE_VALID_BIT;
      }
    }
  }

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
        total_write_sz += sizeof(fd_accdb_disk_meta_t) + FD_ACCDB_SIZE_DATA( evicted->executable_size );
        fd_memcpy( write_metas[ write_meta_cnt ].pubkey, evicted->key.pubkey, 32UL );
        write_metas[ write_meta_cnt ].size = FD_ACCDB_SIZE_DATA( evicted->executable_size );
        fd_memcpy( write_metas[ write_meta_cnt ].owner, destination_cache_lines[ i ][ j ]->owner, 32UL );
        write_ops[ write_ops_cnt++ ] = (struct iovec){ .iov_base = &write_metas[ write_meta_cnt ], .iov_len = sizeof(fd_accdb_disk_meta_t) };
        write_meta_cnt++;
        write_ops[ write_ops_cnt++ ] = (struct iovec){ .iov_base = destination_cache_lines[ i ][ j ]+1UL, .iov_len = FD_ACCDB_SIZE_DATA( evicted->executable_size ) };
      }
      if( FD_UNLIKELY( accs[ i ] && !exists_in_cache[ i ] && evicted_orig_acc[ i ]!=UINT_MAX ) ) {
        fd_accdb_acc_t const * evicted = &accdb->acc_pool[ evicted_orig_acc[ i ] ];
        total_write_sz += sizeof(fd_accdb_disk_meta_t) + FD_ACCDB_SIZE_DATA( evicted->executable_size );
        fd_memcpy( write_metas[ write_meta_cnt ].pubkey, evicted->key.pubkey, 32UL );
        write_metas[ write_meta_cnt ].size = FD_ACCDB_SIZE_DATA( evicted->executable_size );
        fd_memcpy( write_metas[ write_meta_cnt ].owner, original_cache_line[ i ]->owner, 32UL );
        write_ops[ write_ops_cnt++ ] = (struct iovec){ .iov_base = &write_metas[ write_meta_cnt ], .iov_len = sizeof(fd_accdb_disk_meta_t) };
        write_meta_cnt++;
        write_ops[ write_ops_cnt++ ] = (struct iovec){ .iov_base = original_cache_line[ i ]+1UL, .iov_len = FD_ACCDB_SIZE_DATA( evicted->executable_size ) };
      }
    } else {
      if( FD_LIKELY( exists_in_cache[ i ] || evicted_orig_acc[ i ]==UINT_MAX ) ) continue;

      fd_accdb_acc_t const * evicted = &accdb->acc_pool[ evicted_orig_acc[ i ] ];
      total_write_sz += sizeof(fd_accdb_disk_meta_t) + FD_ACCDB_SIZE_DATA( evicted->executable_size );
      fd_memcpy( write_metas[ write_meta_cnt ].pubkey, evicted->key.pubkey, 32UL );
      write_metas[ write_meta_cnt ].size = FD_ACCDB_SIZE_DATA( evicted->executable_size );
      fd_memcpy( write_metas[ write_meta_cnt ].owner, original_cache_line[ i ]->owner, 32UL );
      write_ops[ write_ops_cnt++ ] = (struct iovec){ .iov_base = &write_metas[ write_meta_cnt ], .iov_len = sizeof(fd_accdb_disk_meta_t) };
      write_meta_cnt++;
      write_ops[ write_ops_cnt++ ] = (struct iovec){ .iov_base = original_cache_line[ i ]+1UL, .iov_len = FD_ACCDB_SIZE_DATA( evicted->executable_size ) };
    }
  }

  // STEP 5-6.
  //   Compute the file offset for the writes we are about to do and
  //   build the pending offset table.  The common case is a single
  //   atomic fetch-add on the write head, reserving a contiguous
  //   region.  If the total eviction batch is too large to fit in one
  //   partition (extremely unlikely — requires many dirty 10MiB
  //   evictions), fall back to per-entry allocation so that each
  //   individual write fits in a single partition.
  //
  //   The actual stores to evicted->offset_fork and line->persisted
  //   are deferred until after pwritev2 completes (Step 8-9), so
  //   a concurrent acquire spinning on offset==FD_ACCDB_OFF_INVAL
  //   does not proceed to preadv2 from a location that hasn't been
  //   written.
  int                     pending_cnt = 0;
  fd_accdb_acc_t *        pending_accs [ (FD_ACCDB_CACHE_CLASS_CNT+1UL)*5UL*(2UL+MAX_TX_ACCOUNT_LOCKS) ];
  ulong                   pending_offs [ (FD_ACCDB_CACHE_CLASS_CNT+1UL)*5UL*(2UL+MAX_TX_ACCOUNT_LOCKS) ];
  fd_accdb_cache_line_t * pending_lines[ (FD_ACCDB_CACHE_CLASS_CNT+1UL)*5UL*(2UL+MAX_TX_ACCOUNT_LOCKS) ];

  ulong file_offset;
  int   batch_contiguous;
  if( FD_LIKELY( total_write_sz && total_write_sz<=accdb->shmem->partition_sz ) ) {
    file_offset      = allocate_next_write( accdb, total_write_sz );
    batch_contiguous = 1;
  } else {
    file_offset      = 0UL;
    batch_contiguous = 0;
  }

  ulong cumulative_offset = 0UL;
  for( ulong i=0UL; i<pubkeys_cnt; i++ ) {
    if( FD_UNLIKELY( !accs[ i ] && !writable[ i ] ) ) continue;

    if( FD_UNLIKELY( writable[ i ] ) ) {
      for( ulong j=0UL; j<FD_ACCDB_CACHE_CLASS_CNT; j++ ) {
        if( FD_LIKELY( evicted_dest_acc[ i ][ j ]==UINT_MAX ) ) continue;

        fd_accdb_acc_t * evicted = &accdb->acc_pool[ evicted_dest_acc[ i ][ j ] ];
        ulong entry_sz = sizeof(fd_accdb_disk_meta_t) + (ulong)FD_ACCDB_SIZE_DATA( evicted->executable_size );
        if( FD_LIKELY( fd_accdb_acc_offset(evicted)!=FD_ACCDB_OFF_INVAL ) ) {
          fd_accdb_shmem_bytes_freed( accdb->shmem, fd_accdb_acc_offset(evicted), entry_sz );
          FD_ATOMIC_FETCH_AND_SUB( &accdb->shmem->metrics->disk_used_bytes, entry_sz );
        }
        pending_accs [ pending_cnt ] = evicted;
        if( FD_LIKELY( batch_contiguous ) ) pending_offs[ pending_cnt ] = file_offset + cumulative_offset;
        else                                pending_offs[ pending_cnt ] = allocate_next_write( accdb, entry_sz );
        pending_lines[ pending_cnt ] = destination_cache_lines[ i ][ j ];
        pending_cnt++;
        cumulative_offset += entry_sz;
        FD_ATOMIC_FETCH_AND_ADD( &accdb->shmem->metrics->disk_used_bytes, entry_sz );
      }
      if( FD_UNLIKELY( accs[ i ] && !exists_in_cache[ i ] && evicted_orig_acc[ i ]!=UINT_MAX ) ) {
        fd_accdb_acc_t * evicted = &accdb->acc_pool[ evicted_orig_acc[ i ] ];
        ulong entry_sz = sizeof(fd_accdb_disk_meta_t) + (ulong)FD_ACCDB_SIZE_DATA( evicted->executable_size );
        if( FD_LIKELY( fd_accdb_acc_offset(evicted)!=FD_ACCDB_OFF_INVAL ) ) {
          fd_accdb_shmem_bytes_freed( accdb->shmem, fd_accdb_acc_offset(evicted), entry_sz );
          FD_ATOMIC_FETCH_AND_SUB( &accdb->shmem->metrics->disk_used_bytes, entry_sz );
        }
        pending_accs [ pending_cnt ] = evicted;
        if( FD_LIKELY( batch_contiguous ) ) pending_offs[ pending_cnt ] = file_offset + cumulative_offset;
        else                                pending_offs[ pending_cnt ] = allocate_next_write( accdb, entry_sz );
        pending_lines[ pending_cnt ] = original_cache_line[ i ];
        pending_cnt++;
        cumulative_offset += entry_sz;
        FD_ATOMIC_FETCH_AND_ADD( &accdb->shmem->metrics->disk_used_bytes, entry_sz );
      }
    } else {
      if( FD_LIKELY( exists_in_cache[ i ] || evicted_orig_acc[ i ]==UINT_MAX ) ) continue;

      fd_accdb_acc_t * evicted = &accdb->acc_pool[ evicted_orig_acc[ i ] ];
      ulong entry_sz = sizeof(fd_accdb_disk_meta_t) + (ulong)FD_ACCDB_SIZE_DATA( evicted->executable_size );
      if( FD_LIKELY( fd_accdb_acc_offset(evicted)!=FD_ACCDB_OFF_INVAL ) ) {
        fd_accdb_shmem_bytes_freed( accdb->shmem, fd_accdb_acc_offset(evicted), entry_sz );
        FD_ATOMIC_FETCH_AND_SUB( &accdb->shmem->metrics->disk_used_bytes, entry_sz );
      }
      pending_accs [ pending_cnt ] = evicted;
      if( FD_LIKELY( batch_contiguous ) ) pending_offs[ pending_cnt ] = file_offset + cumulative_offset;
      else                                pending_offs[ pending_cnt ] = allocate_next_write( accdb, entry_sz );
      pending_lines[ pending_cnt ] = original_cache_line[ i ];
      pending_cnt++;
      cumulative_offset += entry_sz;
      FD_ATOMIC_FETCH_AND_ADD( &accdb->shmem->metrics->disk_used_bytes, entry_sz );
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
      out_entries[ i ].executable = 0;
      out_entries[ i ].prior_lamports = 0UL;
      out_entries[ i ].prior_data_len = 0UL;
      out_entries[ i ].prior_executable = 0;
      memset( out_entries[ i ].prior_owner, 0, 32UL );
      out_entries[ i ].prior_data = NULL;
      out_entries[ i ].commit = 0;
      out_entries[ i ]._writable = 0;
      out_entries[ i ]._original_size_class = ULONG_MAX;
      out_entries[ i ]._original_cache_idx = ULONG_MAX;
      continue;
    }

    if( FD_LIKELY( !writable[ i ] ) ) out_entries[ i ].data = (uchar *)(original_cache_line[ i ]+1UL);
    else                              out_entries[ i ].data = (uchar *)(destination_cache_lines[ i ][ 7UL ]+1UL);
    out_entries[ i ].data_len = accs[ i ] ? FD_ACCDB_SIZE_DATA( accs[ i ]->executable_size ) : 0UL;
    out_entries[ i ].executable = accs[ i ] ? FD_ACCDB_SIZE_EXEC( accs[ i ]->executable_size ) : 0;
    out_entries[ i ].lamports = accs[ i ] ? accs[ i ]->lamports : 0UL;
    if( FD_UNLIKELY( !accs[ i ] ) ) memset( out_entries[ i ].owner, 0, 32UL );
    /* For accs[i] != NULL, the owner is copied from the cache line
       below in step 14, after step 11 has populated it from disk for
       cold loads. */

    out_entries[ i ].prior_lamports   = out_entries[ i ].lamports;
    out_entries[ i ].prior_data_len   = out_entries[ i ].data_len;
    out_entries[ i ].prior_executable = out_entries[ i ].executable;
    out_entries[ i ].prior_data       = (uchar *)(original_cache_line[ i ] ? (original_cache_line[ i ]+1UL) : NULL);

    out_entries[ i ].commit = 0;
    out_entries[ i ]._writable = writable[ i ];
    if( FD_UNLIKELY( writable[ i ] && accs[ i ] ) ) out_entries[ i ]._overwrite = accdb->fork_pool[ fork_id.val ].shmem->generation==accs[ i ]->key.generation;
    else                                            out_entries[ i ]._overwrite = 0;

    if( FD_UNLIKELY( writable[ i ] ) ) {
      out_entries[ i ]._fork_id = fork_id.val;
      out_entries[ i ]._generation = fork->shmem->generation;
      out_entries[ i ]._acc_map_idx = acc_map_idxs[ i ];
    }
    fd_memcpy( out_entries[ i ].pubkey, pubkeys[ i ], 32UL );

    if( FD_UNLIKELY( !accs[ i ] ) ) {
      out_entries[ i ]._original_size_class = ULONG_MAX;
      out_entries[ i ]._original_cache_idx = ULONG_MAX;
    } else {
      out_entries[ i ]._original_size_class = fd_accdb_cache_class( FD_ACCDB_SIZE_DATA( accs[ i ]->executable_size ) );
      out_entries[ i ]._original_cache_idx = cache_line_idx( accdb, out_entries[ i ]._original_size_class, original_cache_line[ i ] );
    }

    if( FD_UNLIKELY( writable[ i ] ) ) {
      for( ulong j=0UL; j<FD_ACCDB_CACHE_CLASS_CNT; j++ ) {
        out_entries[ i ]._write.destination_cache_idx[ j ] = cache_line_idx( accdb, j, destination_cache_lines[ i ][ j ] );
      }
    }
  }

  // STEP 8.
  //   Write the dirty eviction data to disk and publish the new offsets
  //   BEFORE constructing read iovecs.  This is critical: step 3 may
  //   have evicted a dirty cache line belonging to another account in
  //   the same batch whose acc->offset is still FD_ACCDB_OFF_INVAL.
  //   The read-iovec loop below spin-waits on
  //   offset!=FD_ACCDB_OFF_INVAL, so publishing evicted offsets first
  //   prevents an intra-batch deadlock where the thread waits on an
  //   offset that only it can resolve.
  if( FD_LIKELY( batch_contiguous ) ) {
    /* Fast path: all evictions fit in one contiguous region.  Use the
       pre-built iovec array for a single batched pwritev2 call. */
    ulong bytes_written = 0UL;
    struct iovec * write_ptr = write_ops;
    while( FD_LIKELY( bytes_written<total_write_sz ) ) {
      long result = pwritev2( accdb->fd, write_ptr, fd_int_min( write_ops_cnt, IOV_MAX ), (long)(file_offset+bytes_written), 0 ); /* TODO: RWF_HIPRI with O_DIRECT */
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
  } else {
    /* Slow path: total eviction batch exceeds a single partition.
       Write each entry individually using its own allocated offset.
       This path is only taken in extreme edge cases (many concurrent
       dirty 10 MiB evictions). */
    struct iovec * wp = write_ops;
    for( int k=0; k<pending_cnt; k++ ) {
      ulong entry_sz = sizeof(fd_accdb_disk_meta_t) + (ulong)FD_ACCDB_SIZE_DATA( pending_accs[ k ]->executable_size );
      ulong entry_off = pending_offs[ k ];
      struct iovec entry_iovs[2] = { wp[0], wp[1] };
      wp += 2;

      ulong written = 0UL;
      while( FD_LIKELY( written<entry_sz ) ) {
        long result = pwritev2( accdb->fd, entry_iovs, 2, (long)(entry_off+written), 0 ); /* TODO: RWF_HIPRI with O_DIRECT */
        if( FD_UNLIKELY( -1==result && (errno==EINTR || errno==EAGAIN || errno==EWOULDBLOCK ) ) ) continue;
        else if( FD_UNLIKELY( -1==result ) ) FD_LOG_ERR(( "pwritev2() failed (%d-%s)", errno, fd_io_strerror( errno ) ));
        else if( FD_UNLIKELY( !result ) ) FD_LOG_ERR(( "accounts database is corrupt, pwritev2() returned 0 at offset %lu with %lu bytes remaining", entry_off+written, entry_sz-written ));
        written += (ulong)result;

        for( int v=0; v<2; v++ ) {
          if( (ulong)result>=(ulong)entry_iovs[ v ].iov_len ) {
            result -= (long)entry_iovs[ v ].iov_len;
            entry_iovs[ v ].iov_len = 0UL;
          } else {
            entry_iovs[ v ].iov_base = (uchar *)entry_iovs[ v ].iov_base + result;
            entry_iovs[ v ].iov_len -= (ulong)result;
            break;
          }
        }
      }
    }
  }

  // STEP 9.
  //   Now that the data is on disk, publish the evicted account offsets
  //   so concurrent acquire threads spinning on
  //   offset==FD_ACCDB_OFF_INVAL can proceed.  The fence ensures
  //   pwritev2 data is globally visible before the offset stores.
  FD_COMPILER_MFENCE();
  for( int k=0; k<pending_cnt; k++ ) {
    pending_accs[ k ]->offset_fork = fd_accdb_acc_pack_offset_fork( pending_offs[ k ], fd_accdb_acc_fork_id(pending_accs[ k ]) );
    pending_lines[ k ]->persisted = 1;
  }

  // STEP 10.
  //   Now construct iovecs for any reads we need to do of accounts into
  //   the cache.  For reading accounts, we read them directly into the
  //   sole cache line we took (and maybe just evicted).  For writing
  //   accounts, we read them into the right sized cache line, and later
  //   it will be copied to the staging buffer.  This is to prevent
  //   repeatedly reading the same account off disk into cache, if it is
  //   being written cold multiple times and every write fails.

  ulong read_ops_cnt = 0UL;
  ulong read_offsets[ FD_ACCDB_CACHE_CLASS_CNT*5UL*(2UL+MAX_TX_ACCOUNT_LOCKS) ];
  uchar * read_bases[ FD_ACCDB_CACHE_CLASS_CNT*5UL*(2UL+MAX_TX_ACCOUNT_LOCKS) ];
  ulong read_sizes[ FD_ACCDB_CACHE_CLASS_CNT*5UL*(2UL+MAX_TX_ACCOUNT_LOCKS) ];
  struct iovec read_ops[ FD_ACCDB_CACHE_CLASS_CNT*5UL*(2UL+MAX_TX_ACCOUNT_LOCKS) ];

  for( ulong i=0UL; i<pubkeys_cnt; i++ ) {
    if( FD_UNLIKELY( !accs[ i ] || exists_in_cache[ i ] ) ) continue;

    /* We are guaranteed that if an account is in the cache, the bytes
       are available (all cache operations are atomic via refcnt CAS),
       but we are not guaranteed that if something is _not_ in the cache
       that it has been written back to disk yet.  In paticular, if we
       are trying to read an account that another thread is in the
       process of evicting, we know they removed it from the cache, but
       we don't know exactly when they will have written it back fully
       to disk, so we may need to wait for that here.

       Compaction may concurrently relocate this record, but
       epoch-based safe reclamation guarantees the source partition
       is not freed until all epoch-protected operations that could
       have snapshotted the old offset have exited.  So the data at the
       snapshotted offset remains stable for the duration of our
       read and no post-read validation is needed. */
    while( FD_UNLIKELY( (FD_VOLATILE_CONST( accs[ i ]->offset_fork ) & FD_ACCDB_OFF_MASK)==FD_ACCDB_OFF_INVAL ) ) FD_SPIN_PAUSE();

    read_offsets[ read_ops_cnt ] = fd_accdb_acc_offset(accs[ i ]) + offsetof(fd_accdb_disk_meta_t, owner);
    read_bases[ read_ops_cnt ]   = original_cache_line[ i ]->owner;
    read_sizes[ read_ops_cnt ]   = 32UL + FD_ACCDB_SIZE_DATA( accs[ i ]->executable_size );
    read_ops[ read_ops_cnt++ ]   = (struct iovec){ .iov_base = original_cache_line[ i ]->owner, .iov_len = 32UL + FD_ACCDB_SIZE_DATA( accs[ i ]->executable_size ) };
  }

  // STEP 11.
  //   Almost done... now do the actual reads of accounts into cache,
  //   using the iovecs we constructed.  This is basically the same loop
  //   as the writes, but with preadv2 instead of pwritev2, and that the
  //   reads are not necessarily all contiguous, but occur at random
  //   offsets.
  //
  //   CONCURRENCY: The compaction tile may concurrently relocate a
  //   record we are about to read (both are epoch-protected).  Epoch-
  //   based safe reclamation guarantees the source partition is not
  //   freed until all epoch-protected operations that could have
  //   snapshotted the old offset have exited, so the data at the
  //   remains stable for the duration of this read — no post-read
  //   validation or retry is needed.
  for( ulong i=0UL; i<read_ops_cnt; i++ ) {
    ulong bytes_read = 0UL;
    while( FD_LIKELY( bytes_read<read_sizes[ i ] ) ) {
      long result = preadv2( accdb->fd, &read_ops[ i ], 1, (long)(read_offsets[ i ]+bytes_read), 0 ); /* TODO: RWF_HIPRI with O_DIRECT */
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
  //   Spin-wait for any cache lines found via acc->cache_idx that are
  //   still being loaded by another thread's preadv2.  The loading
  //   thread sets acc_idx to UINT_MAX before publishing cache_idx
  //   and publishes the real acc index after its read completes.
  //   This step is placed as late as possible to give the loading
  //   thread maximum time to finish before we need to spin.
  for( ulong i=0UL; i<pubkeys_cnt; i++ ) {
    if( FD_UNLIKELY( !accs[ i ] && !writable[ i ] ) ) continue;

    if( FD_UNLIKELY( !original_cache_line[ i ] ) ) continue;
    while( FD_UNLIKELY( FD_VOLATILE_CONST( original_cache_line[ i ]->acc_idx )==UINT_MAX ) ) FD_SPIN_PAUSE();
  }

  // STEP 14.
  //   Now that all reads from disk into original_cache_line have
  //   completed (and any concurrent loaders have published their
  //   acc_idx in step 13), copy the owner into the output entries.
  //   This must happen here rather than in step 7 because the cache
  //   line owner is only valid post-read for cold loads.
  for( ulong i=0UL; i<pubkeys_cnt; i++ ) {
    if( FD_UNLIKELY( !accs[ i ] ) ) continue;
    fd_memcpy( out_entries[ i ].owner,       original_cache_line[ i ]->owner, 32UL );
    fd_memcpy( out_entries[ i ].prior_owner, original_cache_line[ i ]->owner, 32UL );
  }

  // STEP 15.
  //   Finally, copy any accounts we are writing into the staging
  //   buffers, so they occupy a 10MiB cache line for the execution
  //   system.
  for( ulong i=0UL; i<pubkeys_cnt; i++ ) {
    if( FD_UNLIKELY( !accs[ i ] || !writable[ i ] ) ) continue;

    fd_memcpy( destination_cache_lines[ i ][ 7UL ]+1UL, original_cache_line[ i ]+1UL, FD_ACCDB_SIZE_DATA( accs[ i ]->executable_size ) );
  }

  FD_COMPILER_MFENCE();
  FD_VOLATILE( *accdb->my_epoch_slot ) = ULONG_MAX;
}

void
fd_accdb_acquire( fd_accdb_t *          accdb,
                  fd_accdb_fork_id_t    fork_id,
                  ulong                 pubkeys_cnt,
                  uchar const * const * pubkeys,
                  int *                 writable,
                  fd_accdb_entry_t *    out_entries ) {
  fd_accdb_acquire_inner( accdb, fork_id, RESERVATION_TYPE_SIMPLE, pubkeys_cnt, pubkeys, writable, out_entries );
}

void
fd_accdb_acquire_a( fd_accdb_t *             accdb,
                       fd_accdb_fork_id_t    fork_id,
                       ulong                 pubkeys_cnt,
                       uchar const * const * pubkeys,
                       int *                 writable,
                       fd_accdb_entry_t *    out_entries ) {
  fd_accdb_acquire_inner( accdb, fork_id, RESERVATION_TYPE_MAYBE_PROGRAMDATA, pubkeys_cnt, pubkeys, writable, out_entries );
}

void
fd_accdb_acquire_b( fd_accdb_t *          accdb,
                    fd_accdb_fork_id_t    fork_id,
                    ulong                 reserved_cnt,
                    ulong                 pubkeys_cnt,
                    uchar const * const * pubkeys,
                    int *                 writable,
                    fd_accdb_entry_t *    out_entries ) {
  ulong refund[ FD_ACCDB_CACHE_CLASS_CNT ] = {0};
  for( ulong i=0UL; i<reserved_cnt; i++ ) {
    for( ulong j=0UL; j<FD_ACCDB_CACHE_CLASS_CNT; j++ ) {
      if( FD_UNLIKELY( accdb->shmem->cache_class_used[ j ].val!=ULONG_MAX ) ) {
        refund[ j ]++;
      }
    }
  }

  for( ulong k=0UL; k<FD_ACCDB_CACHE_CLASS_CNT; k++ ) {
    if( FD_UNLIKELY( refund[ k ] ) ) FD_ATOMIC_FETCH_AND_SUB( &accdb->shmem->cache_class_used[ k ].val, refund[ k ] );
  }

  fd_accdb_acquire_inner( accdb, fork_id, RESERVATION_TYPE_ALREADY_RESERVED, pubkeys_cnt, pubkeys, writable, out_entries );
}

void
fd_accdb_release( fd_accdb_t *       accdb,
                  ulong              entries_cnt,
                  fd_accdb_entry_t * entries ) {
  FD_COMPILER_MFENCE();
  FD_VOLATILE( *accdb->my_epoch_slot ) = FD_VOLATILE_CONST( accdb->shmem->epoch );
  FD_HW_MFENCE(); /* StoreLoad: epoch store must be globally visible
                     before any subsequent loads so the deferred
                     reclamation scan does not miss us. */

  // STEP 1.
  //   For each cache line which was written to in the 10MiB staging
  //   buffer, we may need to copy to the data out to a right sized
  //   cache line.  Figuring out the target cache line is non-obvious,
  //   but follows the more complete logic below this, we just pull the
  //   memcpy out so they are not done inside the cache lock.

  for( ulong i=0UL; i<entries_cnt; i++ ) {
    if( FD_UNLIKELY( entries[ i ]._original_size_class==ULONG_MAX && !entries[ i ]._writable ) ) continue;

#if FD_TMPL_USE_HANDHOLDING
    if( FD_LIKELY( entries[ i ]._original_size_class!=ULONG_MAX ) ) {
      FD_TEST( entries[ i ]._original_cache_idx<accdb->shmem->cache_class_max[ entries[ i ]._original_size_class ] );
    }
    if( FD_UNLIKELY( entries[ i ].commit ) ) FD_TEST( entries[ i ]._writable );
#endif

    if( FD_LIKELY( !entries[ i ]._writable || !entries[ i ].commit ) ) continue;
#if FD_TMPL_USE_HANDHOLDING
    if( FD_UNLIKELY( entries[ i ]._overwrite ) ) {
      FD_TEST( entries[ i ]._writable );
      FD_TEST( entries[ i ]._original_cache_idx!=ULONG_MAX );
      FD_TEST( entries[ i ]._original_size_class!=ULONG_MAX );
    }
#endif

    ulong original_size_class = entries[ i ]._original_size_class;
    ulong new_size_class = fd_accdb_cache_class( entries[ i ].data_len );
    if( FD_UNLIKELY( new_size_class==7UL ) ) continue;

    fd_accdb_cache_line_t * target_cache_line;
    if( FD_LIKELY( original_size_class==new_size_class && entries[ i ]._overwrite ) ) target_cache_line = cache_line( accdb, original_size_class, entries[ i ]._original_cache_idx );
    else                                                                              target_cache_line = cache_line( accdb, new_size_class, entries[ i ]._write.destination_cache_idx[ new_size_class ] );

    fd_accdb_cache_line_t * staging_line = cache_line( accdb, 7UL, entries[ i ]._write.destination_cache_idx[ 7UL ] );
    fd_memcpy( target_cache_line->owner, entries[ i ].owner, 32UL );
    fd_memcpy( target_cache_line+1UL, staging_line+1UL, entries[ i ].data_len );
  }

  // STEP 2.
  //   Now update the metadata structures and free lists to reflect the
  //   fact that we are done with these cache lines.  This is fully
  //   atomic with CLOCK.

  for( ulong i=0UL; i<entries_cnt; i++ ) {
    if( FD_UNLIKELY( entries[ i ]._original_size_class==ULONG_MAX && !entries[ i ]._writable ) ) continue;

    ulong original_size_class = entries[ i ]._original_size_class;
    fd_accdb_cache_line_t * original_cache_line = entries[ i ]._original_cache_idx==ULONG_MAX ? NULL : cache_line( accdb, original_size_class, entries[ i ]._original_cache_idx );
    /* For overwrite commits, defer the refcnt decrement on
       original_cache_line until after invalidation completes.  If
       we dropped refcnt to 0 here, a concurrent CLOCK sweep could
       CAS(refcnt, 0, EVICT_SENTINEL) and steal the line before we
       get to invalidate it, causing data corruption.
       Non-overwrite and non-commit paths unpin
       immediately because they never invalidate the original line. */
    if( FD_LIKELY( original_cache_line ) ) {
#if FD_TMPL_USE_HANDHOLDING
      FD_TEST( original_cache_line->refcnt>0U );
#endif
      if( FD_LIKELY( !entries[ i ]._writable || !entries[ i ].commit || !entries[ i ]._overwrite ) ) {
        FD_ATOMIC_FETCH_AND_SUB( &original_cache_line->refcnt, 1U );
      }
    }

    if( FD_LIKELY( !entries[ i ]._writable ) ) {
      /* For readonly accounts, mark as recently used so the CLOCK
         algorithm gives it a second chance before eviction. */
#if FD_TMPL_USE_HANDHOLDING
      FD_TEST( original_cache_line );
#endif
      original_cache_line->referenced = 1;
      continue;
    }

    fd_accdb_cache_line_t * destination_cache_lines[ FD_ACCDB_CACHE_CLASS_CNT ];
    for( ulong j=0UL; j<FD_ACCDB_CACHE_CLASS_CNT; j++ ) destination_cache_lines[ j ] = cache_line( accdb, j, entries[ i ]._write.destination_cache_idx[ j ] );
    int destination_committed[ FD_ACCDB_CACHE_CLASS_CNT ] = {0};

    if( FD_LIKELY( !entries[ i ].commit ) ) {
      /* If it's writable but it didn't commit, all of the destination
         cache lines (including the staging buffer which is trashed) are
         unused and can be pushed to the CAS free list for immediate
         reuse.  Whatever buffer it was accessing also gets marked as
         recently used. */
      if( FD_LIKELY( original_cache_line ) ) original_cache_line->referenced = 1;
      for( ulong j=0UL; j<FD_ACCDB_CACHE_CLASS_CNT; j++ ) {
        destination_cache_lines[ j ]->refcnt    = 0;
        destination_cache_lines[ j ]->persisted = 1;
        cache_free_push( accdb, j, destination_cache_lines[ j ] );
      }
      continue;
    }

    ulong new_size_class = fd_accdb_cache_class( entries[ i ].data_len );
    uint original_acc_idx = original_cache_line ? original_cache_line->acc_idx : UINT_MAX;
    fd_accdb_cache_line_t * committed_line;

    /* For overwrites, invalidate the on-disk offset BEFORE removing
       the cache entry.  This ensures a concurrent acquire that misses
       the cache will see offset==FD_ACCDB_OFF_INVAL and spin-wait,
       rather than reading stale on-disk bytes from the old location.
       The CAS-loop exchange also serializes with a concurrent
       compaction CAS (old_offset -> dest_offset). */
    ulong old_offset = FD_ACCDB_OFF_INVAL;
    if( FD_LIKELY( entries[ i ]._overwrite ) ) {
      fd_accdb_acc_t * ow_acc = &accdb->acc_pool[ original_acc_idx ];
      old_offset = fd_accdb_acc_xchg_offset( ow_acc, FD_ACCDB_OFF_INVAL );
      if( FD_LIKELY( old_offset!=FD_ACCDB_OFF_INVAL ) ) {
        fd_accdb_shmem_bytes_freed( accdb->shmem, old_offset, (ulong)FD_ACCDB_SIZE_DATA(ow_acc->executable_size)+sizeof(fd_accdb_disk_meta_t) );
        FD_ATOMIC_FETCH_AND_SUB( &accdb->shmem->metrics->disk_used_bytes, (ulong)FD_ACCDB_SIZE_DATA(ow_acc->executable_size)+sizeof(fd_accdb_disk_meta_t) );
      }
    }

    if( FD_UNLIKELY( new_size_class==7UL ) ) {
      /* The account belongs in the largest size class, and we already
         have it resident in a 10MiB buffer anyway, so no need to copy
         back.  If we are "overwriting" (same generation as the account
         came from), then the original can be discarded (pushed to
         the CAS free list) and removed from the cache. */
      destination_cache_lines[ 7UL ]->persisted = 0;
      destination_committed[ 7UL ] = 1;
      if( FD_LIKELY( entries[ i ]._overwrite ) ) {
        original_cache_line->persisted = 1;
        original_cache_line->acc_idx   = UINT_MAX;
        original_cache_line->key.generation = UINT_MAX;
        /* Now safe to unpin and free — line is invalidated. */
        FD_ATOMIC_FETCH_AND_SUB( &original_cache_line->refcnt, 1U );
        cache_free_push( accdb, original_size_class, original_cache_line );
      }
      committed_line = destination_cache_lines[ 7UL ];
    } else {
      /* The account started in some arbitrary size class, transited
         through a 10MiB staging buffer, and is now being written back
         to some arbitrary (non-10MiB) size class, so we need to copy it
         there.  The staging buffer is discarded.  If we are going to
         a different size class, and we are "overwriting" (same
         generation), then the original can also be discarded, but if
         we are staying in the same size class, we can reuse the cache
         line in place. */
      fd_accdb_cache_line_t * target_cache_line;
      if( FD_LIKELY( original_size_class==new_size_class ) ) {
        if( FD_LIKELY( entries[ i ]._overwrite ) ) {
          original_cache_line->key.generation = UINT_MAX;
          /* Keep refcnt>=1 through the reuse window so CLOCK cannot
             steal the line between invalidation and re-publish. The
             pin is released in the destination cleanup loop after
             acc->cache_idx has been republished. */
          original_cache_line->acc_idx = UINT_MAX;
          target_cache_line = original_cache_line;
        } else {
          target_cache_line = destination_cache_lines[ new_size_class ];
          destination_committed[ new_size_class ] = 1;
        }
      } else {
        if( FD_LIKELY( entries[ i ]._overwrite ) ) {
          original_cache_line->persisted = 1;
          original_cache_line->acc_idx   = UINT_MAX;
          original_cache_line->key.generation = UINT_MAX;
          /* Now safe to unpin and free — line is invalidated. */
          FD_ATOMIC_FETCH_AND_SUB( &original_cache_line->refcnt, 1U );
          cache_free_push( accdb, original_size_class, original_cache_line );
        }

        destination_committed[ new_size_class ] = 1;
        target_cache_line = destination_cache_lines[ new_size_class ];
      }

      target_cache_line->persisted = 0;
      /* If target is the original cache line (overwrite, same size
         class), mark as referenced directly since the cleanup loop
         only handles destination lines. */
      if( FD_LIKELY( !destination_committed[ new_size_class ] ) ) target_cache_line->referenced = 1;
      committed_line = target_cache_line;
    }

    /* For non-overwrite commits, the original cache line (if any) still
       holds valid ancestor data but is no longer pinned.  Mark it as
       recently used so the CLOCK algorithm retains it. */
    if( FD_UNLIKELY( !entries[ i ]._overwrite && original_cache_line ) ) {
      original_cache_line->referenced = 1;
    }

    /* Handle every destination cache line: committed ones keep
       refcnt>=1 until acc->cache_idx is published (the deferred
       unpin happens after the publish below), uncommitted ones are
       fully freed to the CAS free list. */
    for( ulong j=0UL; j<FD_ACCDB_CACHE_CLASS_CNT; j++ ) {
      if( destination_committed[ j ] ) {
        destination_cache_lines[ j ]->referenced = 1;
      } else {
        destination_cache_lines[ j ]->refcnt    = 0;
        destination_cache_lines[ j ]->persisted = 1;
        cache_free_push( accdb, j, destination_cache_lines[ j ] );
      }
    }

    /* Update the accounts index for this committed write.  For an
       overwrite (same fork+generation), update the existing acc
       entry in place.  Otherwise allocate a new acc, prepend it
       to the hash chain, and record the write in a txn linked to
       the fork so advance_root can clean up old versions. */
    if( FD_LIKELY( entries[ i ]._overwrite ) ) {
      committed_line->acc_idx = original_acc_idx;

      fd_accdb_acc_t * acc = &accdb->acc_pool[ original_acc_idx ];
      /* The offset was already atomically swapped to FD_ACCDB_OFF_INVAL
         and bytes freed above, so just update the metadata and
         re-publish the cache location. */
      acc->executable_size     = FD_ACCDB_SIZE_PACK( (uint)entries[ i ].data_len, entries[ i ].executable );
      acc->lamports = entries[ i ].lamports;

      fd_memcpy( committed_line->owner, entries[ i ].owner, 32UL );
      fd_memcpy( committed_line->key.pubkey, acc->key.pubkey, 32UL );
      committed_line->key.generation = acc->key.generation;
      committed_line->acc_idx = original_acc_idx;
      FD_VOLATILE( acc->cache_idx ) = FD_ACCDB_ACC_CIDX_PACK( (uint)new_size_class, (uint)cache_line_idx( accdb, new_size_class, committed_line ) );
      FD_VOLATILE( acc->executable_size ) |= FD_ACCDB_SIZE_CACHE_VALID_BIT;

      /* Now that acc->cache_idx is published, unpin so
         CLOCK can eventually evict it.  For same-size overwrites,
         committed_line IS the reused original_cache_line.  For
         cross-size overwrites, committed_line is a destination line
         whose refcnt decrement was deferred from the cleanup loop. */
      FD_ATOMIC_FETCH_AND_SUB( &committed_line->refcnt, 1U );
      committed_line->referenced = 1;
    } else {
      fd_accdb_acc_t * acc = acc_pool_acquire( accdb->acc_pool_join );
      FD_TEST( acc );
      ulong acc_idx = acc_pool_idx( accdb->acc_pool_join, acc );
      fd_memcpy( acc->key.pubkey, entries[ i ].pubkey, 32UL );
      acc->lamports       = entries[ i ].lamports;
      acc->executable_size           = FD_ACCDB_SIZE_PACK( (uint)entries[ i ].data_len, entries[ i ].executable );
      acc->key.generation = entries[ i ]._generation;
      acc->offset_fork    = fd_accdb_acc_pack_offset_fork( FD_ACCDB_OFF_INVAL, entries[ i ]._fork_id );

      /* Publish in the cache BEFORE the acc_map head so that a
         concurrent acquire that finds this acc in the hash chain will
         also find a cache hit, rather than inserting a conflicting
         placeholder cache entry. */
      committed_line->acc_idx = (uint)acc_idx;
      fd_memcpy( committed_line->owner, entries[ i ].owner, 32UL );
      fd_memcpy( committed_line->key.pubkey, acc->key.pubkey, 32UL );
      committed_line->key.generation = acc->key.generation;
      FD_VOLATILE( acc->cache_idx ) = FD_ACCDB_ACC_CIDX_PACK( (uint)new_size_class, (uint)cache_line_idx( accdb, new_size_class, committed_line ) );
      FD_VOLATILE( acc->executable_size ) |= FD_ACCDB_SIZE_CACHE_VALID_BIT;

      /* Now that acc->cache_idx is published, unpin it so
         CLOCK can eventually evict it. */
      FD_ATOMIC_FETCH_AND_SUB( &committed_line->refcnt, 1U );
      committed_line->referenced = 1;

      /* CAS loop to prepend to the hash chain.  Succeeds on the first
         try in most cases, but a concurrent acc_unlink CAS removing
         the old head can change acc_map[idx] between our load and
         CAS.  Multiple concurrent releases may also race on the head
         pointer — the CAS retry handles this. */
      for(;;) {
        uint old_head = FD_VOLATILE_CONST( accdb->acc_map[ entries[ i ]._acc_map_idx ] );
        acc->map.next = old_head;
        FD_COMPILER_MFENCE();
        if( FD_LIKELY( FD_ATOMIC_CAS( &accdb->acc_map[ entries[ i ]._acc_map_idx ], old_head, (uint)acc_idx )==old_head ) ) break;
        FD_SPIN_PAUSE();
      }

      /* CONCURRENCY: The cache entry is published before the acc_map
         head so that a concurrent fd_accdb_acquire reader that
         observes the new head also finds a cache hit, preventing
         duplicate cache insertion.

         (1) The CAS on acc_map[idx] serializes head-pointer mutations
             from concurrent releases onto the same chain without any
             external lock.

         (2) The FD_COMPILER_MFENCE above ensures stores to the acc node
             fields (pubkey, lamports, size, generation, fork_id,
             offset, map.next) are ordered before the CAS that publishes
             the new head.  On x86-64 (TSO), hardware also guarantees
             this, but the compiler fence is needed to prevent the
             compiler from reordering the stores.  A reader that
             observes the new head is guaranteed to see a fully
             initialized node.  A reader that has not yet seen the new
             head simply traverses the previous (still valid) chain.

         (3) A concurrent acc_unlink (advance_root / purge) may CAS the
             head away between our load and CAS here.  The CAS retry
             loop handles this. */

      fd_accdb_txn_t * txn = txn_pool_acquire( accdb->txn_pool );
      FD_TEST( txn ); /* Sized so it always succeeds */
      txn->acc_map_idx  = (uint)entries[ i ]._acc_map_idx;
      txn->acc_pool_idx = (uint)acc_idx;
      uint txn_idx = (uint)txn_pool_idx( accdb->txn_pool, txn );
      for(;;) {
        uint old_head = FD_VOLATILE_CONST( accdb->fork_pool[ entries[ i ]._fork_id ].shmem->txn_head );
        txn->fork.next = old_head;
        if( FD_LIKELY( FD_ATOMIC_CAS( &accdb->fork_pool[ entries[ i ]._fork_id ].shmem->txn_head, old_head, txn_idx )==old_head ) ) break;
        FD_SPIN_PAUSE();
      }

      FD_ATOMIC_FETCH_AND_ADD( &accdb->shmem->metrics->accounts_total, 1UL );
    }

    FD_ATOMIC_FETCH_AND_ADD( &accdb->shmem->metrics->accounts_written, 1UL );
  }

  // STEP 3.
  //   Finally, we release the cache class reservations we took at the
  //   beginning when we acquired these cache lines.  Credits return
  //   directly to the shared pool so other threads can use them
  //   immediately.

  ulong refund[ FD_ACCDB_CACHE_CLASS_CNT ] = {0};
  for( ulong i=0UL; i<entries_cnt; i++ ) {
    if( FD_LIKELY( entries[ i ]._original_size_class!=ULONG_MAX ) ) {
      if( FD_UNLIKELY( accdb->shmem->cache_class_used[ entries[ i ]._original_size_class ].val!=ULONG_MAX ) ) {
        refund[ entries[ i ]._original_size_class ]++;
      }
    }
    if( FD_UNLIKELY( entries[ i ]._writable ) ) {
      for( ulong j=0UL; j<FD_ACCDB_CACHE_CLASS_CNT; j++ ) {
        if( FD_UNLIKELY( accdb->shmem->cache_class_used[ j ].val!=ULONG_MAX ) ) {
          refund[ j ]++;
        }
      }
    }
  }
  for( ulong k=0UL; k<FD_ACCDB_CACHE_CLASS_CNT; k++ ) {
    if( FD_UNLIKELY( refund[ k ] ) ) FD_ATOMIC_FETCH_AND_SUB( &accdb->shmem->cache_class_used[ k ].val, refund[ k ] );
  }

  FD_COMPILER_MFENCE();
  FD_VOLATILE( *accdb->my_epoch_slot ) = ULONG_MAX;
}

fd_accdb_entry_t
fd_accdb_read_one( fd_accdb_t *       accdb,
                   fd_accdb_fork_id_t fork_id,
                   uchar const *      pubkey ) {
  fd_accdb_entry_t entry;
  fd_accdb_acquire( accdb, fork_id, 1UL, &pubkey, (int[]){0}, &entry );
  return entry;
}

void
fd_accdb_unread_one( fd_accdb_t *       accdb,
                     fd_accdb_entry_t * entry ) {
  fd_accdb_release( accdb, 1UL, entry );
}

fd_accdb_entry_t
fd_accdb_write_one( fd_accdb_t *       accdb,
                    fd_accdb_fork_id_t fork_id,
                    uchar const *      pubkey,
                    int                create,
                    int                truncate ) {
  fd_accdb_entry_t entry;
  fd_accdb_acquire( accdb, fork_id, 1UL, &pubkey, (int[]){1}, &entry );
  return entry;
  (void)create; (void)truncate; // TODO: handle these flags
}

void
fd_accdb_unwrite_one( fd_accdb_t *       accdb,
                      fd_accdb_entry_t * entry ) {
  fd_accdb_release( accdb, 1UL, entry );
}

int
fd_accdb_exists( fd_accdb_t *       accdb,
                 fd_accdb_fork_id_t fork_id,
                 uchar const *      pubkey ) {
  uint root_generation = accdb->fork_pool[ accdb->shmem->root_fork_id.val ].shmem->generation;
  fd_accdb_fork_t * fork = &accdb->fork_pool[ fork_id.val ];
  ulong hash = fd_accdb_hash( pubkey, accdb->shmem->seed )&(accdb->shmem->chain_cnt-1UL);
  uint acc = FD_VOLATILE_CONST( accdb->acc_map[ hash ] );
  while( acc!=UINT_MAX ) {
    fd_accdb_acc_t const * candidate_acc = &accdb->acc_pool[ acc ];
    uint next_acc = FD_VOLATILE_CONST( candidate_acc->map.next );

    if( FD_UNLIKELY( (candidate_acc->key.generation>root_generation && fd_accdb_acc_fork_id(candidate_acc)!=fork_id.val && !descends_set_test( fork->descends, fd_accdb_acc_fork_id(candidate_acc) )) ) || memcmp( pubkey, candidate_acc->key.pubkey, 32UL ) ) {
      acc = next_acc;
      continue;
    }

    break;
  }

  if( FD_UNLIKELY( acc==UINT_MAX ) ) return 0;
  else                               return !!accdb->acc_pool[ acc ].lamports;
}

ulong
fd_accdb_lamports( fd_accdb_t *       accdb,
                   fd_accdb_fork_id_t fork_id,
                   uchar const *      pubkey ) {
 uint root_generation = accdb->fork_pool[ accdb->shmem->root_fork_id.val ].shmem->generation;
  fd_accdb_fork_t * fork = &accdb->fork_pool[ fork_id.val ];
  ulong hash = fd_accdb_hash( pubkey, accdb->shmem->seed )&(accdb->shmem->chain_cnt-1UL);
  uint acc = FD_VOLATILE_CONST( accdb->acc_map[ hash ] );
  while( acc!=UINT_MAX ) {
    fd_accdb_acc_t const * candidate_acc = &accdb->acc_pool[ acc ];
    uint next_acc = FD_VOLATILE_CONST( candidate_acc->map.next );

    if( FD_UNLIKELY( (candidate_acc->key.generation>root_generation && fd_accdb_acc_fork_id(candidate_acc)!=fork_id.val && !descends_set_test( fork->descends, fd_accdb_acc_fork_id(candidate_acc) )) ) || memcmp( pubkey, candidate_acc->key.pubkey, 32UL ) ) {
      acc = next_acc;
      continue;
    }

    break;
  }

  if( FD_UNLIKELY( acc==UINT_MAX ) ) return ULONG_MAX;
  else                               return accdb->acc_pool[ acc ].lamports;
}

/* cache_bg_evict pre-evicts cache lines in the background to keep the
   per-class CAS free lists populated ahead of demand.  For each class
   whose free-list depth has dropped below low_water, a bounded CLOCK
   sweep claims lines, writes dirty ones to disk, and pushes them onto
   the free list until the depth reaches target.

   Budget: at most 256 CLOCK ticks per class per invocation to keep the
   background loop responsive.  The function is called every tick of
   fd_accdb_background, so large refills happen across several ticks
   rather than blocking.

   The min-reserved floor prevents eviction from classes that are
   already at capacity: if used >= max - min_reserved, no pre-eviction
   is performed (those slots are reserved for execution). */

static void
background_preevict( fd_accdb_t * accdb,
                     int *        charge_busy ) {
  fd_accdb_shmem_t * shmem = accdb->shmem;

  for( ulong c=0UL; c<FD_ACCDB_CACHE_CLASS_CNT; c++ ) {
    ulong depth = FD_VOLATILE_CONST( shmem->cache_free_cnt[ c ].val );
    if( FD_LIKELY( depth>=shmem->cache_free_low_water[ c ] ) ) continue;

    ulong target = shmem->cache_free_target[ c ];
    ulong max_c  = shmem->cache_class_max[ c ];

    ulong budget  = 256UL;
    ulong evicted = 0UL;

    for( ulong tick=0UL; tick<budget && depth+evicted<target; tick++ ) {
      ulong used = FD_VOLATILE_CONST( shmem->cache_class_used[ c ].val );
      if( FD_UNLIKELY( used+FD_ACCDB_CACHE_MIN_RESERVED>=max_c ) ) break;

      ulong hand = FD_ATOMIC_FETCH_AND_ADD( &shmem->clock_hand[ c ].val, 1UL ) % max_c;
      fd_accdb_cache_line_t * line = cache_line( accdb, c, hand );

      if( FD_UNLIKELY( line->key.generation==UINT_MAX && line->acc_idx==UINT_MAX ) ) continue;

      uint rc = FD_VOLATILE_CONST( line->refcnt );
      if( FD_UNLIKELY( rc ) ) continue;

      if( FD_UNLIKELY( line->referenced ) ) {
        line->referenced = 0;
        continue;
      }

      if( FD_UNLIKELY( FD_ATOMIC_CAS( &line->refcnt, 0U, FD_ACCDB_EVICT_SENTINEL )!=0U ) ) continue;

      uint acc_idx = line->acc_idx;
      if( FD_LIKELY( acc_idx!=UINT_MAX ) ) {
        FD_VOLATILE( accdb->acc_pool[ acc_idx ].cache_idx ) = FD_ACCDB_ACC_CIDX_INVAL;
        FD_VOLATILE( accdb->acc_pool[ acc_idx ].executable_size ) &= ~FD_ACCDB_SIZE_CACHE_VALID_BIT;
      }
      line->key.generation = UINT_MAX;
      if( FD_UNLIKELY( !line->persisted && acc_idx!=UINT_MAX ) ) {
        fd_accdb_acc_t * acc = &accdb->acc_pool[ acc_idx ];
        ulong entry_sz = sizeof(fd_accdb_disk_meta_t)+(ulong)FD_ACCDB_SIZE_DATA( acc->executable_size );

        /* Atomically swap the old offset to FD_ACCDB_OFF_INVAL so that
           a concurrent compaction CAS (old_offset -> dest_offset)
           cannot succeed between our read and our later store of
           the new file_off.  Without the exchange, compaction could
           relocate the record, then our plain store would overwrite
           the relocated offset, leaving the compaction destination
           as unreachable dead space whose bytes are never freed. */
        ulong old_offset = fd_accdb_acc_xchg_offset( acc, FD_ACCDB_OFF_INVAL );
        if( FD_LIKELY( old_offset!=FD_ACCDB_OFF_INVAL ) ) {
          fd_accdb_shmem_bytes_freed( shmem, old_offset, entry_sz );
          FD_ATOMIC_FETCH_AND_SUB( &shmem->metrics->disk_used_bytes, entry_sz );
        }

        fd_accdb_disk_meta_t meta;
        fd_memcpy( meta.pubkey, acc->key.pubkey, 32UL );
        meta.size = FD_ACCDB_SIZE_DATA( acc->executable_size );
        fd_memcpy( meta.owner, line->owner, 32UL );

        struct iovec iovs[ 2UL ] = {
          { .iov_base = &meta,              .iov_len = sizeof(fd_accdb_disk_meta_t) },
          { .iov_base = (void *)(line+1UL), .iov_len = FD_ACCDB_SIZE_DATA( acc->executable_size ) }
        };

        ulong file_off = allocate_next_write( accdb, entry_sz );
        ulong written = 0UL;
        while( written<entry_sz ) {
          long result = pwritev2( accdb->fd, iovs, 2, (long)(file_off+written), 0 );
          if( FD_UNLIKELY( result==-1 && errno==EINTR ) ) continue;
          else if( FD_UNLIKELY( result<=0 ) ) FD_LOG_ERR(( "pwritev2() failed (%d-%s)", errno, fd_io_strerror( errno ) ));
          written += (ulong)result;
          for( int v=0; v<2; v++ ) {
            if( (ulong)result>=iovs[ v ].iov_len ) {
              result -= (long)iovs[ v ].iov_len;
              iovs[ v ].iov_len = 0UL;
            } else {
              iovs[ v ].iov_base = (uchar *)iovs[ v ].iov_base + result;
              iovs[ v ].iov_len -= (ulong)result;
              break;
            }
          }
        }

        FD_COMPILER_MFENCE();
        acc->offset_fork = fd_accdb_acc_pack_offset_fork( file_off, fd_accdb_acc_fork_id(acc) );
        FD_ATOMIC_FETCH_AND_ADD( &shmem->metrics->disk_used_bytes, entry_sz );
      }

      line->persisted      = 1;
      line->acc_idx        = UINT_MAX;
      line->key.generation = UINT_MAX;
      line->refcnt         = 0;
      cache_free_push( accdb, c, line );
      evicted++;
    }

    if( FD_UNLIKELY( evicted ) ) *charge_busy = 1;
  }
}

static inline ulong
snapshot_allocate_next_write( fd_accdb_t * accdb,
                              ulong        sz ) {
  if( FD_UNLIKELY( packed_partition_offset( accdb->shmem->whead[ 0 ] )==accdb->shmem->partition_sz ) ) accdb->shmem->whead[ 0 ].val = 0UL;

  if( FD_LIKELY( accdb->shmem->whead[ 0 ].val+sz<=accdb->shmem->partition_sz ) ) {
    accdb->shmem->whead[ 0 ].val += sz;
    return accdb->shmem->whead[ 0 ].val - sz;
  } else {
    ulong remaining_in_partition = accdb->shmem->partition_sz - (accdb->shmem->whead[ 0 ].val % accdb->shmem->partition_sz);
    ulong next = accdb->shmem->whead[ 0 ].val + remaining_in_partition;
    accdb->shmem->whead[ 0 ].val = next + sz;
    return next;
  }
}

int
fd_accdb_snapshot_write_one( fd_accdb_t *  accdb,
                             uchar const * pubkey,
                             ulong         slot,
                             ulong         lamports,
                             ulong         data_len,
                             int           executable ) {
  ulong hash = fd_accdb_hash( pubkey, accdb->shmem->seed )&(accdb->shmem->chain_cnt-1UL);

  fd_accdb_acc_t * acc = NULL;

  ulong next_acc = accdb->acc_map[ hash ];
  while( next_acc!=UINT_MAX ) {
    fd_accdb_acc_t * candidate_acc = &accdb->acc_pool[ next_acc ];
    if( FD_UNLIKELY( !memcmp( pubkey, candidate_acc->key.pubkey, 32UL ) ) ) {
      if( FD_LIKELY( candidate_acc->cache_idx>slot ) ) {
        /* Still advance the write head so snapwr and snapin stay in
           sync — snapwr unconditionally writes every account to disk.
           Mark the space as immediately freed since it is dead on
           arrival. */
        ulong dead_sz  = sizeof(fd_accdb_disk_meta_t)+data_len;
        ulong dead_off = snapshot_allocate_next_write( accdb, dead_sz );
        ulong pidx     = dead_off / accdb->shmem->partition_sz;
        partition_pool_ele( accdb->partition_pool, pidx )->bytes_freed += dead_sz;
        return -1;
      } else {
        acc = candidate_acc;
        break;
      }
    }
    next_acc = candidate_acc->map.next;
  }

  int replace = !!acc;

  if( FD_UNLIKELY( !acc ) ) {
    acc = acc_pool_acquire( accdb->acc_pool_join );
    if( FD_UNLIKELY( !acc ) ) FD_LOG_ERR(( "accounts database ran out of space during snapshot loading, increase [accounts.max_accounts], current value is %lu", acc_pool_ele_max( accdb->acc_pool_join ) ));

    fd_memcpy( acc->key.pubkey, pubkey, 32UL );
    acc->key.generation = accdb->shmem->generation;
    acc->map.next = accdb->acc_map[ hash ];
    accdb->acc_map[ hash ] = (uint)acc_pool_idx( accdb->acc_pool_join, acc );
  }

  if( FD_UNLIKELY( replace ) ) {
    /* The old version's disk space is now dead. */
    ulong old_sz   = sizeof(fd_accdb_disk_meta_t) + FD_ACCDB_SIZE_DATA( acc->executable_size );
    ulong old_off  = acc->offset_fork;
    ulong old_pidx = old_off / accdb->shmem->partition_sz;
    partition_pool_ele( accdb->partition_pool, old_pidx )->bytes_freed += old_sz;
  }

  acc->cache_idx = (uint)slot;
  acc->lamports = lamports;
  acc->executable_size = FD_ACCDB_SIZE_PACK( (uint)data_len, executable );
  acc->offset_fork = snapshot_allocate_next_write( accdb, sizeof(fd_accdb_disk_meta_t)+data_len );

  return replace ? 2 : 1;
}

int
fd_accdb_snapshot_write_batch( fd_accdb_t *        accdb,
                               ulong               cnt,
                               uchar const * const pubkeys[],
                               ulong const         slots[],
                               ulong  const        lamports[],
                               ulong  const        data_lens[],
                               int    const        executables[],
                               ulong *             accounts_ignored,
                               ulong *             accounts_replaced,
                               ulong *             accounts_loaded ) {
  ulong seed      = accdb->shmem->seed;
  ulong chain_msk = accdb->shmem->chain_cnt - 1UL;
  uint  gen       = accdb->shmem->generation;

  ulong ignored  = 0UL;
  ulong replaced = 0UL;
  ulong loaded   = 0UL;

  /* Phase 1: compute hashes and prefetch chain heads. */

  ulong            hashes[ 8 ];
  fd_accdb_acc_t * existing[ 8 ];
  int              skip[ 8 ];

  for( ulong i=0UL; i<cnt; i++ ) {
    hashes[ i ]   = fd_accdb_hash( pubkeys[ i ], seed ) & chain_msk;
    existing[ i ] = NULL;
    skip[ i ]     = 0;

    /* Prefetch the chain head and first pool element on the chain */
    __builtin_prefetch( &accdb->acc_map[ hashes[ i ] ], 1, 1 );
  }

  /* Phase 2: walk chains looking for duplicates.  By now the chain
     heads prefetched above should be warm in L1/L2.  If the existing
     entry has a higher slot, mark skip.  Otherwise, save the existing
     entry pointer for in-place update (matching write_one semantics). */

  for( ulong i=0UL; i<cnt; i++ ) {
    ulong next_acc = accdb->acc_map[ hashes[ i ] ];

    if( FD_LIKELY( next_acc!=UINT_MAX ) ) {
      __builtin_prefetch( &accdb->acc_pool[ next_acc ], 0, 1 );
    }

    while( next_acc!=UINT_MAX ) {
      fd_accdb_acc_t * candidate = &accdb->acc_pool[ next_acc ];

      if( FD_LIKELY( candidate->map.next!=UINT_MAX ) ) {
        __builtin_prefetch( &accdb->acc_pool[ candidate->map.next ], 0, 1 );
      }

      if( FD_UNLIKELY( !memcmp( pubkeys[ i ], candidate->key.pubkey, 32UL ) ) ) {
        if( FD_LIKELY( candidate->cache_idx>(uint)slots[ i ] ) ) {
          skip[ i ] = 1;
        } else {
          existing[ i ] = candidate;
        }
        break;
      }
      next_acc = candidate->map.next;
    }
  }

  /* Phase 3: commit.  For each account either update the existing
     entry in-place (replace), allocate and insert at the chain head
     (new), or skip entirely (ignore).  This matches the
     insert/replace/ignore semantics of write_one. */

  for( ulong i=0UL; i<cnt; i++ ) {
    if( FD_UNLIKELY( skip[ i ] ) ) {
      /* Still advance the write head so snapwr and snapin stay in
         sync — snapwr unconditionally writes every account to disk.
         Mark the space as immediately freed since it is dead on
         arrival. */
      ulong dead_sz  = sizeof(fd_accdb_disk_meta_t)+data_lens[ i ];
      ulong dead_off = snapshot_allocate_next_write( accdb, dead_sz );
      ulong pidx     = dead_off / accdb->shmem->partition_sz;
      partition_pool_ele( accdb->partition_pool, pidx )->bytes_freed += dead_sz;
      ignored++;
      continue;
    }

    fd_accdb_acc_t * acc;

    if( FD_UNLIKELY( existing[ i ] ) ) {
      acc = existing[ i ];
      /* The old version's disk space is now dead. */
      ulong old_sz   = sizeof(fd_accdb_disk_meta_t) + FD_ACCDB_SIZE_DATA( acc->executable_size );
      ulong old_off  = acc->offset_fork;
      ulong old_pidx = old_off / accdb->shmem->partition_sz;
      partition_pool_ele( accdb->partition_pool, old_pidx )->bytes_freed += old_sz;
      replaced++;
    } else {
      acc = acc_pool_acquire( accdb->acc_pool_join );
      if( FD_UNLIKELY( !acc ) ) FD_LOG_ERR(( "accounts database ran out of space during snapshot loading" ));
      fd_memcpy( acc->key.pubkey, pubkeys[ i ], 32UL );
      acc->key.generation = gen;
      acc->map.next = accdb->acc_map[ hashes[ i ] ];
      accdb->acc_map[ hashes[ i ] ] = (uint)acc_pool_idx( accdb->acc_pool_join, acc );
      loaded++;
    }

    acc->cache_idx       = (uint)slots[ i ];
    acc->lamports        = lamports[ i ];
    acc->executable_size = FD_ACCDB_SIZE_PACK( (uint)data_lens[ i ], executables[ i ] );
    acc->offset_fork     = snapshot_allocate_next_write( accdb, sizeof(fd_accdb_disk_meta_t)+data_lens[ i ] );
  }

  *accounts_ignored  = ignored;
  *accounts_replaced = replaced;
  *accounts_loaded   = loaded;

  return 0;
}

void
fd_accdb_background( fd_accdb_t * accdb,
                     int *        charge_busy ) {
  fd_accdb_shmem_t * shmem = accdb->shmem;
  uint op = FD_VOLATILE_CONST( shmem->cmd_op );
  if( FD_UNLIKELY( op!=FD_ACCDB_CMD_IDLE ) ) {
    fd_accdb_fork_id_t fork_id = { .val = FD_VOLATILE_CONST( shmem->cmd_fork_id ) };

    switch( op ) {
      case FD_ACCDB_CMD_ADVANCE_ROOT:
        background_advance_root( accdb, fork_id );
        break;
      case FD_ACCDB_CMD_PURGE:
        background_purge( accdb, fork_id );
        break;
      default:
        FD_LOG_ERR(( "unexpected accdb cmd_op %u", op ));
    }

    FD_COMPILER_MFENCE();
    FD_VOLATILE( shmem->cmd_done ) = 1;
    *charge_busy = 1;
    return;
  }

  if( 0 ) background_preevict( accdb, charge_busy );

  for( ulong k=0UL; k<FD_ACCDB_COMPACTION_LAYER_CNT; k++ ) {
    background_compact( accdb, k, charge_busy );
  }
}

fd_accdb_shmem_metrics_t const *
fd_accdb_metrics( fd_accdb_t * accdb ) {
  return accdb->shmem->metrics;
}
