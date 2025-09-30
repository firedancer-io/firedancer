#include "fd_txncache.h"
#include "fd_txncache_private.h"
#include "../../util/log/fd_log.h"

struct blockcache {
  fd_txncache_blockcache_shmem_t * shmem;

  uint * heads;          /* The hash table for the blockhash.  Each entry is a pointer to the head of a linked list of
                            transactions that reference this blockhash.  As we add transactions to the bucket, the head
                            pointer is updated to the new item, and the new item is pointed to the previous head. */
  uint * pages;          /* A list of the txnpages containing the transactions for this blockcache. */

  uchar * descends;      /* Each fork can descend from other forks in the txncache, and this array contains one value
                            for each fork in the txncache.  If this fork descends from the fork at position id,
                            then descends[ id ] will be 1, otherwise 1. */
};

typedef struct blockcache blockcache_t;

struct fd_txncache_private {
  fd_txncache_shmem_t * shmem;

  fd_txncache_blockcache_shmem_t * blockcache_shmem_pool;
  blockcache_t * blockcache_pool;
  blockhash_map_t * blockhash_map;

  ushort * txnpages_free;           /* The index in the txnpages array that is free, for each of the free pages. */

  fd_txncache_txnpage_t * txnpages; /* The actual storage for the transactions.  The blockcache points to these
                                       pages when storing transactions.  Transaction are grouped into pages of
                                       size 16384 to make certain allocation and deallocation operations faster
                                       (just the pages are acquired/released, rather than each txn). */
};

FD_FN_CONST ulong
fd_txncache_align( void ) {
  return FD_TXNCACHE_ALIGN;
}

FD_FN_CONST ulong
fd_txncache_footprint( ulong max_live_slots ) {
  ulong max_active_slots = FD_TXNCACHE_MAX_BLOCKHASH_DISTANCE+max_live_slots;

  ulong l;
  l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, FD_TXNCACHE_SHMEM_ALIGN, sizeof(fd_txncache_t) );
  l = FD_LAYOUT_APPEND( l, alignof(blockcache_t),   max_active_slots*sizeof(blockcache_t) );
  return FD_LAYOUT_FINI( l, FD_TXNCACHE_ALIGN );
}

void *
fd_txncache_new( void *                ljoin,
                 fd_txncache_shmem_t * shmem ) {
  if( FD_UNLIKELY( !ljoin ) ) {
    FD_LOG_WARNING(( "NULL ljoin" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)ljoin, fd_txncache_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned ljoin" ));
    return NULL;
  }

  ulong max_active_slots = shmem->active_slots_max;
  ulong blockhash_map_chains = fd_ulong_pow2_up( 2UL*shmem->active_slots_max );

  ushort _max_txnpages               = fd_txncache_max_txnpages( max_active_slots, shmem->txn_per_slot_max );
  ushort _max_txnpages_per_blockhash = fd_txncache_max_txnpages_per_blockhash( max_active_slots, shmem->txn_per_slot_max );

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_txncache_shmem_t * tc    = FD_SCRATCH_ALLOC_APPEND( l, FD_TXNCACHE_SHMEM_ALIGN,         sizeof(fd_txncache_shmem_t)                               );
  void * _blockhash_map       = FD_SCRATCH_ALLOC_APPEND( l, blockhash_map_align(),           blockhash_map_footprint( blockhash_map_chains )           );
  void * _blockcache_pool     = FD_SCRATCH_ALLOC_APPEND( l, blockcache_pool_align(),         blockcache_pool_footprint( max_active_slots )             );
  void * _blockcache_pages    = FD_SCRATCH_ALLOC_APPEND( l, alignof(uint),                   max_active_slots*_max_txnpages_per_blockhash*sizeof(uint) );
  void * _blockcache_heads    = FD_SCRATCH_ALLOC_APPEND( l, alignof(uint),                   max_active_slots*shmem->txn_per_slot_max*sizeof(uint)     );
  void * _blockcache_descends = FD_SCRATCH_ALLOC_APPEND( l, alignof(uchar),                  max_active_slots*max_active_slots*sizeof(uchar)           );
  void * _txnpages_free       = FD_SCRATCH_ALLOC_APPEND( l, alignof(ushort),                 _max_txnpages*sizeof(ushort)                              );
  void * _txnpages            = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_txncache_txnpage_t),  _max_txnpages*sizeof(fd_txncache_txnpage_t)               );

  FD_SCRATCH_ALLOC_INIT( l2, ljoin );
  fd_txncache_t * ltc           = FD_SCRATCH_ALLOC_APPEND( l2, FD_TXNCACHE_ALIGN,     sizeof(fd_txncache_t)                 );
  void * _local_blockcache_pool = FD_SCRATCH_ALLOC_APPEND( l2, alignof(blockcache_t), max_active_slots*sizeof(blockcache_t) );

  ltc->shmem = tc;

  ltc->blockcache_pool = (blockcache_t*)_local_blockcache_pool;
  ltc->blockcache_shmem_pool = blockcache_pool_join( _blockcache_pool );

  for( ulong i=0UL; i<shmem->active_slots_max; i++ ) {
    ltc->blockcache_pool[ i ].pages = (uint *)_blockcache_pages + i*_max_txnpages_per_blockhash;
    ltc->blockcache_pool[ i ].heads = (uint *)_blockcache_heads + i*shmem->txn_per_slot_max;
    ltc->blockcache_pool[ i ].descends = (uchar *)_blockcache_descends + i*max_active_slots;
    ltc->blockcache_pool[ i ].shmem = ltc->blockcache_shmem_pool + i;
  }

  FD_TEST( ltc->blockcache_shmem_pool );

  ltc->blockhash_map = blockhash_map_join( _blockhash_map );
  FD_TEST( ltc->blockhash_map );

  ltc->txnpages_free = (ushort *)_txnpages_free;
  ltc->txnpages      = (fd_txncache_txnpage_t *)_txnpages;

  return (void *)ltc;
}

fd_txncache_t *
fd_txncache_join( void * ljoin ) {
  if( FD_UNLIKELY( !ljoin ) ) {
    FD_LOG_WARNING(( "NULL ljoin" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)ljoin, fd_txncache_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned ljoin" ));
    return NULL;
  }

  fd_txncache_t * tc = (fd_txncache_t *)ljoin;

  return tc;
}

void
fd_txncache_reset( fd_txncache_t * tc ) {
  fd_rwlock_write( tc->shmem->lock );

  tc->shmem->root_cnt = 0UL;
  root_slist_remove_all( tc->shmem->root_ll, tc->blockcache_shmem_pool );

  tc->shmem->txnpages_free_cnt = tc->shmem->max_txnpages;
  for( ushort i=0; i<tc->shmem->max_txnpages; i++ ) tc->txnpages_free[ i ] = i;

  blockcache_pool_reset( tc->blockcache_shmem_pool );
  blockhash_map_reset( tc->blockhash_map );

  fd_rwlock_unwrite( tc->shmem->lock );
}

static fd_txncache_txnpage_t *
fd_txncache_ensure_txnpage( fd_txncache_t * tc,
                            blockcache_t *  blockcache ) {
  ushort page_cnt = blockcache->shmem->pages_cnt;
  if( FD_UNLIKELY( page_cnt>tc->shmem->txnpages_per_blockhash_max ) ) return NULL;

  if( FD_LIKELY( page_cnt ) ) {
    uint txnpage_idx = blockcache->pages[ page_cnt-1 ];
    ushort txnpage_free = tc->txnpages[ txnpage_idx ].free;
    if( FD_LIKELY( txnpage_free ) ) return &tc->txnpages[ txnpage_idx ];
  }

  if( FD_UNLIKELY( page_cnt==tc->shmem->txnpages_per_blockhash_max ) ) return NULL;
  if( FD_LIKELY( FD_ATOMIC_CAS( &blockcache->pages[ page_cnt ], UINT_MAX, UINT_MAX-1UL )==UINT_MAX ) ) {
    ulong txnpages_free_cnt = tc->shmem->txnpages_free_cnt;
    for(;;) {
      if( FD_UNLIKELY( !txnpages_free_cnt ) ) return NULL;
      ulong old_txnpages_free_cnt = FD_ATOMIC_CAS( &tc->shmem->txnpages_free_cnt, (ushort)txnpages_free_cnt, (ushort)(txnpages_free_cnt-1UL) );
      if( FD_LIKELY( old_txnpages_free_cnt==txnpages_free_cnt ) ) break;
      txnpages_free_cnt = old_txnpages_free_cnt;
      FD_SPIN_PAUSE();
    }

    ushort txnpage_idx = tc->txnpages_free[ txnpages_free_cnt-1UL ];
    fd_txncache_txnpage_t * txnpage = &tc->txnpages[ txnpage_idx ];
    txnpage->free = FD_TXNCACHE_TXNS_PER_PAGE;
    FD_COMPILER_MFENCE();
    blockcache->pages[ page_cnt ] = txnpage_idx;
    FD_COMPILER_MFENCE();
    blockcache->shmem->pages_cnt = (ushort)(page_cnt+1);
    return txnpage;
  } else {
    uint txnpage_idx = blockcache->pages[ page_cnt ];
    while( FD_UNLIKELY( txnpage_idx>=UINT_MAX-1UL ) ) {
      txnpage_idx = blockcache->pages[ page_cnt ];
      FD_SPIN_PAUSE();
    }
    return &tc->txnpages[ txnpage_idx ];
  }
}

static int
fd_txncache_insert_txn( fd_txncache_t *         tc,
                        blockcache_t *          blockcache,
                        fd_txncache_txnpage_t * txnpage,
                        fd_txncache_fork_id_t   fork_id,
                        uchar const *           txnhash ) {
  ulong txnpage_idx = (ulong)(txnpage - tc->txnpages);

  for(;;) {
    ushort txnpage_free = txnpage->free;
    if( FD_UNLIKELY( !txnpage_free ) ) return 0;
    if( FD_UNLIKELY( FD_ATOMIC_CAS( &txnpage->free, txnpage_free, txnpage_free-1UL )!=txnpage_free ) ) {
      FD_SPIN_PAUSE();
      continue;
    }

    ulong txn_idx = FD_TXNCACHE_TXNS_PER_PAGE-txnpage_free;
    ulong txnhash_offset = blockcache->shmem->txnhash_offset;
    memcpy( txnpage->txns[ txn_idx ]->txnhash, txnhash+txnhash_offset, 20UL );
    txnpage->txns[ txn_idx ]->fork_id = fork_id;
    FD_COMPILER_MFENCE();

    ulong txn_bucket = FD_LOAD( ulong, txnhash+txnhash_offset )%tc->shmem->txn_per_slot_max;
    for(;;) {
      uint head = blockcache->heads[ txn_bucket ];
      txnpage->txns[ txn_idx ]->blockcache_next = head;
      FD_COMPILER_MFENCE();
      if( FD_LIKELY( FD_ATOMIC_CAS( &blockcache->heads[ txn_bucket ], head, (uint)(FD_TXNCACHE_TXNS_PER_PAGE*txnpage_idx+txn_idx) )==head ) ) break;
      FD_SPIN_PAUSE();
    }

    return 1;
  }
}

fd_txncache_fork_id_t
fd_txncache_attach_child( fd_txncache_t *       tc,
                          fd_txncache_fork_id_t parent_fork_id ) {
  fd_rwlock_write( tc->shmem->lock );

  FD_TEST( blockcache_pool_free( tc->blockcache_shmem_pool ) );
  ulong idx = blockcache_pool_idx_acquire( tc->blockcache_shmem_pool );

  blockcache_t * fork = &tc->blockcache_pool[ idx ];
  fd_txncache_fork_id_t fork_id = { .val = (ushort)idx };

  fork->shmem->child_id = (fd_txncache_fork_id_t){ .val = USHORT_MAX };

  if( FD_LIKELY( parent_fork_id.val==USHORT_MAX ) ) {
    FD_TEST( blockcache_pool_free( tc->blockcache_shmem_pool )==blockcache_pool_max( tc->blockcache_shmem_pool )-1UL );
    fork->shmem->parent_id  = (fd_txncache_fork_id_t){ .val = USHORT_MAX };
    fork->shmem->sibling_id = (fd_txncache_fork_id_t){ .val = USHORT_MAX };

    fd_memset( fork->descends, 0, tc->shmem->active_slots_max*sizeof(uchar) );
    root_slist_ele_push_tail( tc->shmem->root_ll, fork->shmem, tc->blockcache_shmem_pool );
  } else {
    blockcache_t * parent = &tc->blockcache_pool[ parent_fork_id.val ];
    FD_TEST( parent );
    /* We might be tempted to freeze the parent here, and it's valid to
       do this ordinarily, but not when loading from a snapshot, when
       we need to load many transactions into a root parent chain at
       once. */
    fork->shmem->sibling_id = parent->shmem->child_id;
    fork->shmem->parent_id  = parent_fork_id;
    parent->shmem->child_id = fork_id;

    fd_memcpy( fork->descends, parent->descends, tc->shmem->active_slots_max*sizeof(uchar) );
    fork->descends[ parent_fork_id.val ] = 1;
  }

  fork->shmem->txnhash_offset = 0UL;
  fork->shmem->frozen = 0;
  memset( fork->heads, 0xFF, tc->shmem->txn_per_slot_max*sizeof(uint) );
  fork->shmem->pages_cnt = 0;
  memset( fork->pages, 0xFF, tc->shmem->txnpages_per_blockhash_max*sizeof(uint) );

  fd_rwlock_unwrite( tc->shmem->lock );
  return fork_id;
}

void
fd_txncache_attach_blockhash( fd_txncache_t *       tc,
                              fd_txncache_fork_id_t fork_id,
                              uchar const *         blockhash ) {
  fd_rwlock_write( tc->shmem->lock );

  blockcache_t * fork = &tc->blockcache_pool[ fork_id.val ];
  FD_TEST( !fork->shmem->frozen );
  fork->shmem->frozen = 1;

  memcpy( fork->shmem->blockhash.uc, blockhash, 32UL );

  blockhash_map_ele_insert( tc->blockhash_map, fork->shmem, tc->blockcache_shmem_pool );

  fd_rwlock_unwrite( tc->shmem->lock );
}

void
fd_txncache_finalize_fork( fd_txncache_t *       tc,
                           fd_txncache_fork_id_t fork_id,
                           ulong                 txnhash_offset,
                           uchar const *         blockhash ) {
  fd_rwlock_write( tc->shmem->lock );

  blockcache_t * fork = &tc->blockcache_pool[ fork_id.val ];
  FD_TEST( fork->shmem->frozen<=1 );
  fork->shmem->txnhash_offset = txnhash_offset;

  memcpy( fork->shmem->blockhash.uc, blockhash, 32UL );

  if( FD_LIKELY( !fork->shmem->frozen ) ) blockhash_map_ele_insert( tc->blockhash_map, fork->shmem, tc->blockcache_shmem_pool );
  fork->shmem->frozen = 2;

  fd_rwlock_unwrite( tc->shmem->lock );
}

static inline void
remove_blockcache( fd_txncache_t * tc,
                   blockcache_t *  blockcache ) {
  memcpy( tc->txnpages_free+tc->shmem->txnpages_free_cnt, blockcache->pages, blockcache->shmem->pages_cnt*sizeof(ushort) );
  tc->shmem->txnpages_free_cnt = (ushort)(tc->shmem->txnpages_free_cnt+blockcache->shmem->pages_cnt);

  ulong idx = blockcache_pool_idx( tc->blockcache_shmem_pool, blockcache->shmem );
  for( ulong i=0UL; i<tc->shmem->active_slots_max; i++ ) tc->blockcache_pool[ i ].descends[ idx ] = 0;

  blockhash_map_ele_remove_fast( tc->blockhash_map, blockcache->shmem, tc->blockcache_shmem_pool );
  blockcache_pool_ele_release( tc->blockcache_shmem_pool, blockcache->shmem );
}

static inline void
remove_children( fd_txncache_t *      tc,
                 blockcache_t const * fork,
                 blockcache_t const * except ) {
  fd_txncache_fork_id_t sibling_idx = fork->shmem->child_id;
  while( sibling_idx.val!=USHORT_MAX ) {
    blockcache_t * sibling = &tc->blockcache_pool[ sibling_idx.val ];
    FD_TEST( sibling );

    sibling_idx = sibling->shmem->sibling_id;
    if( FD_UNLIKELY( sibling==except ) ) continue;

    remove_children( tc, sibling, except );
    remove_blockcache( tc, sibling );
  }
}

void
fd_txncache_advance_root( fd_txncache_t *       tc,
                          fd_txncache_fork_id_t fork_id ) {
  fd_rwlock_write( tc->shmem->lock );

  blockcache_t * fork = &tc->blockcache_pool[ fork_id.val ];
  FD_TEST( fork );

  blockcache_t * parent_fork = &tc->blockcache_pool[ fork->shmem->parent_id.val ];
  if( FD_UNLIKELY( root_slist_ele_peek_tail( tc->shmem->root_ll, tc->blockcache_shmem_pool )!=parent_fork->shmem ) ) {
    FD_LOG_CRIT(( "advancing root from %s to %s but that is not valid, last root is %s",
                  FD_BASE58_ENC_32_ALLOCA( parent_fork->shmem->blockhash.uc ),
                  FD_BASE58_ENC_32_ALLOCA( fork->shmem->blockhash.uc ),
                  FD_BASE58_ENC_32_ALLOCA( root_slist_ele_peek_tail( tc->shmem->root_ll, tc->blockcache_shmem_pool )->blockhash.uc ) ));
  }

  FD_LOG_DEBUG(( "advancing root from %s to %s",
                 FD_BASE58_ENC_32_ALLOCA( parent_fork->shmem->blockhash.uc ),
                 FD_BASE58_ENC_32_ALLOCA( fork->shmem->blockhash.uc ) ));

  /* When a fork is rooted, any competing forks can be immediately
     removed as they will not be needed again.  This includes child
     forks of the pruned siblings as well. */
  remove_children( tc, parent_fork, fork );

  /* Now, the earliest known rooted fork can likely be removed since its
     blockhashes cannot be referenced anymore (they are older than 151
     blockhashes away). */
  tc->shmem->root_cnt++;
  root_slist_ele_push_tail( tc->shmem->root_ll, fork->shmem, tc->blockcache_shmem_pool );
  if( FD_LIKELY( tc->shmem->root_cnt>FD_TXNCACHE_MAX_BLOCKHASH_DISTANCE ) ) {
    fd_txncache_blockcache_shmem_t * old_root_shmem = root_slist_ele_pop_head( tc->shmem->root_ll, tc->blockcache_shmem_pool );
    FD_TEST( old_root_shmem );
    blockcache_t * old_root = &tc->blockcache_pool[ blockcache_pool_idx( tc->blockcache_shmem_pool, old_root_shmem ) ];

    root_slist_ele_peek_head( tc->shmem->root_ll, tc->blockcache_shmem_pool )->parent_id.val = USHORT_MAX;

    remove_blockcache( tc, old_root );
    tc->shmem->root_cnt--;
  }

  fd_rwlock_unwrite( tc->shmem->lock );
}

static inline blockcache_t *
blockhash_on_fork( fd_txncache_t *      tc,
                   blockcache_t const * fork,
                   uchar const *        blockhash ) {
  fd_txncache_blockcache_shmem_t const * candidate = blockhash_map_ele_query_const( tc->blockhash_map, fd_type_pun_const( blockhash ), NULL, tc->blockcache_shmem_pool );
  if( FD_UNLIKELY( !candidate ) ) FD_LOG_CRIT(( "transaction refers to blockhash %s which does not exist", FD_BASE58_ENC_32_ALLOCA( blockhash ) ));

  while( candidate ) {
    ulong candidate_idx = blockcache_pool_idx( tc->blockcache_shmem_pool, candidate );
    if( FD_LIKELY( fork->descends[ candidate_idx ] ) ) return &tc->blockcache_pool[ candidate_idx ];
    candidate = blockhash_map_ele_next_const( candidate, NULL, tc->blockcache_shmem_pool );
  }
  return NULL;
}

void
fd_txncache_insert( fd_txncache_t *       tc,
                    fd_txncache_fork_id_t fork_id,
                    uchar const *         blockhash,
                    uchar const *         txnhash ) {
  fd_rwlock_read( tc->shmem->lock );

  blockcache_t const * fork = &tc->blockcache_pool[ fork_id.val ];
  FD_TEST( fork->shmem->frozen<=1 );
  blockcache_t * blockcache = blockhash_on_fork( tc, fork, blockhash );
  FD_TEST( blockcache );

  for(;;) {
    fd_txncache_txnpage_t * txnpage = fd_txncache_ensure_txnpage( tc, blockcache );
    FD_TEST( txnpage );

    int success = fd_txncache_insert_txn( tc, blockcache, txnpage, fork_id, txnhash );
    if( FD_LIKELY( success ) ) break;

    FD_SPIN_PAUSE();
  }

  fd_rwlock_unread( tc->shmem->lock );
}

int
fd_txncache_query( fd_txncache_t *       tc,
                   fd_txncache_fork_id_t fork_id,
                   uchar const *         blockhash,
                   uchar const *         txnhash ) {
  fd_rwlock_read( tc->shmem->lock );

  blockcache_t const * fork = &tc->blockcache_pool[ fork_id.val ];
  blockcache_t const * blockcache = blockhash_on_fork( tc, fork, blockhash );
  if( FD_UNLIKELY( !blockcache ) ) FD_LOG_CRIT(( "transaction refers to blockhash %s which is not in ancestors", FD_BASE58_ENC_32_ALLOCA( blockhash ) ));

  int found = 0;

  ulong txnhash_offset = blockcache->shmem->txnhash_offset;
  ulong head_hash = FD_LOAD( ulong, txnhash+txnhash_offset ) % tc->shmem->txn_per_slot_max;
  for( uint head=blockcache->heads[ head_hash ]; head!=UINT_MAX; head=tc->txnpages[ head/FD_TXNCACHE_TXNS_PER_PAGE ].txns[ head%FD_TXNCACHE_TXNS_PER_PAGE ]->blockcache_next ) {
    fd_txncache_single_txn_t * txn = tc->txnpages[ head/FD_TXNCACHE_TXNS_PER_PAGE ].txns[ head%FD_TXNCACHE_TXNS_PER_PAGE ];

    int descends = txn->fork_id.val==fork_id.val || fork->descends[ txn->fork_id.val ];
    if( FD_LIKELY( descends && !memcmp( txnhash+txnhash_offset, txn->txnhash, 20UL ) ) ) {
      found = 1;
      break;
    }
  }

  fd_rwlock_unread( tc->shmem->lock );
  return found;
}
