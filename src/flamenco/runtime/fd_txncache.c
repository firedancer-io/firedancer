#include "fd_txncache.h"
#include "fd_txncache_private.h"
#include "../../util/log/fd_log.h"

struct blockcache {
  fd_txncache_blockcache_shmem_t * shmem;

  uint * heads;          /* The hash table for the blockhash.  Each entry is a pointer to the head of a linked list of
                            transactions that reference this blockhash.  As we add transactions to the bucket, the head
                            pointer is updated to the new item, and the new item is pointed to the previous head. */
  ushort * pages;        /* A list of the txnpages containing the transactions for this blockcache. */

  descends_set_t * descends; /* Each fork can descend from other forks in the txncache, and this bit vector contains one
                                value for each fork in the txncache.  If this fork descends from some other fork F, then
                                the bit at index F in descends[] is set. */
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

  ulong _descends_footprint = descends_set_footprint( max_active_slots );
  if( FD_UNLIKELY( !_descends_footprint ) ) {
    FD_LOG_WARNING(( "invalid max_active_slots" ));
    return NULL;
  }

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_txncache_shmem_t * tc    = FD_SCRATCH_ALLOC_APPEND( l, FD_TXNCACHE_SHMEM_ALIGN,         sizeof(fd_txncache_shmem_t)                                 );
  void * _blockhash_map       = FD_SCRATCH_ALLOC_APPEND( l, blockhash_map_align(),           blockhash_map_footprint( blockhash_map_chains )             );
  void * _blockcache_pool     = FD_SCRATCH_ALLOC_APPEND( l, blockcache_pool_align(),         blockcache_pool_footprint( max_active_slots )               );
  void * _blockcache_pages    = FD_SCRATCH_ALLOC_APPEND( l, alignof(ushort),                 max_active_slots*_max_txnpages_per_blockhash*sizeof(ushort) );
  void * _blockcache_heads    = FD_SCRATCH_ALLOC_APPEND( l, alignof(uint),                   max_active_slots*shmem->txn_per_slot_max*sizeof(uint)       );
  void * _blockcache_descends = FD_SCRATCH_ALLOC_APPEND( l, descends_set_align(),            max_active_slots*_descends_footprint                        );
  void * _txnpages_free       = FD_SCRATCH_ALLOC_APPEND( l, alignof(ushort),                 _max_txnpages*sizeof(ushort)                                );
  void * _txnpages            = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_txncache_txnpage_t),  _max_txnpages*sizeof(fd_txncache_txnpage_t)                 );

  FD_SCRATCH_ALLOC_INIT( l2, ljoin );
  fd_txncache_t * ltc           = FD_SCRATCH_ALLOC_APPEND( l2, FD_TXNCACHE_ALIGN,     sizeof(fd_txncache_t)                 );
  void * _local_blockcache_pool = FD_SCRATCH_ALLOC_APPEND( l2, alignof(blockcache_t), max_active_slots*sizeof(blockcache_t) );

  ltc->shmem = tc;

  ltc->blockcache_pool = (blockcache_t*)_local_blockcache_pool;
  ltc->blockcache_shmem_pool = blockcache_pool_join( _blockcache_pool );

  for( ulong i=0UL; i<shmem->active_slots_max; i++ ) {
    ltc->blockcache_pool[ i ].pages    = (ushort *)_blockcache_pages + i*_max_txnpages_per_blockhash;
    ltc->blockcache_pool[ i ].heads    = (uint *)_blockcache_heads + i*shmem->txn_per_slot_max;
    ltc->blockcache_pool[ i ].descends = descends_set_join( (uchar *)_blockcache_descends + i*_descends_footprint );
    ltc->blockcache_pool[ i ].shmem    = ltc->blockcache_shmem_pool + i;
    FD_TEST( ltc->blockcache_pool[ i ].shmem );
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
    ushort txnpage_idx = blockcache->pages[ page_cnt-1 ];
    ushort txnpage_free = tc->txnpages[ txnpage_idx ].free;
    if( FD_LIKELY( txnpage_free ) ) return &tc->txnpages[ txnpage_idx ];
  }

  if( FD_UNLIKELY( page_cnt==tc->shmem->txnpages_per_blockhash_max ) ) return NULL;
  if( FD_LIKELY( FD_ATOMIC_CAS( &blockcache->pages[ page_cnt ], (ushort)USHORT_MAX, (ushort)(USHORT_MAX-1UL) )==(ushort)USHORT_MAX ) ) {
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
    ushort txnpage_idx = blockcache->pages[ page_cnt ];
    while( FD_UNLIKELY( txnpage_idx>=USHORT_MAX-1UL ) ) {
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
    ulong txn_bucket = FD_LOAD( ulong, txnhash+txnhash_offset )%tc->shmem->txn_per_slot_max;
    FD_TEST( txn_bucket<UINT_MAX );
    fd_txncache_single_txn_t * txn = txnpage->txns[ txn_idx ];
    memcpy( txn->txnhash, txnhash+txnhash_offset, 20UL );
    txn->owner_fork_id.val = (ushort)blockcache_pool_idx( tc->blockcache_shmem_pool, blockcache->shmem );
    txn->fork_id = fork_id;
    txn->blockcache_prev_is_head = 1;
    txn->blockcache_prev = (uint)txn_bucket;
    if( FD_UNLIKELY( txn->owner_fork_id.val==txn->fork_id.val ) ) FD_LOG_CRIT(( "self-referencing txn fork_id %u", txn->fork_id.val ));
    FD_COMPILER_MFENCE();

    uint txn_gidx = (uint)(FD_TXNCACHE_TXNS_PER_PAGE*txnpage_idx+txn_idx);
    for(;;) {
      uint head = blockcache->heads[ txn_bucket ];
      txn->blockcache_next = head;
      FD_COMPILER_MFENCE();
      if( FD_LIKELY( FD_ATOMIC_CAS( &blockcache->heads[ txn_bucket ], head, txn_gidx )==head ) ) {
        if( FD_UNLIKELY( head!=UINT_MAX ) ) {
          fd_txncache_single_txn_t * old_head_txn = tc->txnpages[ head/FD_TXNCACHE_TXNS_PER_PAGE ].txns[ head%FD_TXNCACHE_TXNS_PER_PAGE ];
          FD_TEST( old_head_txn->blockcache_prev_is_head );
          old_head_txn->blockcache_prev_is_head = 0;
          old_head_txn->blockcache_prev = txn_gidx;
        }
        break;
      }
      FD_SPIN_PAUSE();
    }
    for(;;) {
      fd_txncache_blockcache_shmem_t * fork_shmem = tc->blockcache_pool[ fork_id.val ].shmem;
      uint head = fork_shmem->txn_head;
      txn->fork_next = head;
      txn->fork_prev_is_head = 1;
      txn->fork_prev = fork_id.val;
      FD_COMPILER_MFENCE();
      if( FD_LIKELY( FD_ATOMIC_CAS( &(fork_shmem->txn_head), head, txn_gidx )==head ) ) {
        if( FD_LIKELY( head!=UINT_MAX ) ) {
          fd_txncache_single_txn_t * old_head_txn = tc->txnpages[ head/FD_TXNCACHE_TXNS_PER_PAGE ].txns[ head%FD_TXNCACHE_TXNS_PER_PAGE ];
          FD_TEST( old_head_txn->fork_prev_is_head );
          FD_TEST( old_head_txn->fork_prev==fork_id.val );
          old_head_txn->fork_prev_is_head = 0;
          old_head_txn->fork_prev = txn_gidx;
        }
        break;
      }
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

    descends_set_null( fork->descends );
    root_slist_ele_push_tail( tc->shmem->root_ll, fork->shmem, tc->blockcache_shmem_pool );
    FD_LOG_DEBUG(( "attached root fork_id %u", fork_id.val ));
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

    descends_set_copy( fork->descends, parent->descends );
    descends_set_insert( fork->descends, parent_fork_id.val );
    FD_LOG_DEBUG(( "attached fork_id %u to parent fork_id %u", fork_id.val, parent_fork_id.val ));
  }

  fork->shmem->txnhash_offset = 0UL;
  fork->shmem->frozen = 0;
  memset( fork->heads, 0xFF, tc->shmem->txn_per_slot_max*sizeof(uint) );
  fork->shmem->txn_head = UINT_MAX;
  fork->shmem->pages_cnt = 0;
  memset( fork->pages, 0xFF, tc->shmem->txnpages_per_blockhash_max*sizeof(fork->pages[ 0 ]) );

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
                   blockcache_t *  blockcache,
                   int             is_minority ) {
  fd_txncache_fork_id_t fork_id = (fd_txncache_fork_id_t){ .val = (ushort)blockcache_pool_idx( tc->blockcache_shmem_pool, blockcache->shmem ) };
  FD_LOG_DEBUG(( "removing fork_id %u is_minority %d", fork_id.val, is_minority ));

  if( FD_UNLIKELY( is_minority ) ) {
    long start_tick = fd_tickcount();
    /* If this fork is a minority fork, we need to remove all of its
       transactions from whatever blockcache these transactions are
       residing in.  We do this so in the event that this
       soon-to-be-removed fork_id is reused in the near future, these
       transactions don't show up in queries.  This operation is
       somewhat expensive.  Fortunately, forks are rare. */
    ulong cnt1 = 0UL;
    ulong move_cnt = 0UL;
    uint * headp = &(blockcache->shmem->txn_head);
    for( uint head=blockcache->shmem->txn_head; head!=UINT_MAX; headp=&(tc->txnpages[ head/FD_TXNCACHE_TXNS_PER_PAGE ].txns[ head%FD_TXNCACHE_TXNS_PER_PAGE ]->fork_next), head=*headp ) {
      cnt1++;
      fd_txncache_single_txn_t * txn = tc->txnpages[ head/FD_TXNCACHE_TXNS_PER_PAGE ].txns[ head%FD_TXNCACHE_TXNS_PER_PAGE ];
      blockcache_t * owner_blockcache = tc->blockcache_pool+txn->owner_fork_id.val;

      if( FD_UNLIKELY( txn->fork_id.val!=fork_id.val ) ) FD_LOG_CRIT(( "txn->fork_id %u != fork_id %u cnt1 %lu", txn->fork_id.val, fork_id.val, cnt1 ));

      /* Remove from hash chain. */
      if( txn->blockcache_next!=UINT_MAX ) {
        fd_txncache_single_txn_t * next_txn = tc->txnpages[ txn->blockcache_next/FD_TXNCACHE_TXNS_PER_PAGE ].txns[ txn->blockcache_next%FD_TXNCACHE_TXNS_PER_PAGE ];
        FD_TEST( !next_txn->blockcache_prev_is_head );
        FD_TEST( next_txn->blockcache_prev==head );
        next_txn->blockcache_prev = txn->blockcache_prev;
        next_txn->blockcache_prev_is_head = txn->blockcache_prev_is_head;
      }
      FD_TEST( txn->blockcache_prev!=UINT_MAX );
      if( txn->blockcache_prev_is_head ) {
        FD_TEST( owner_blockcache->heads[ txn->blockcache_prev ]==head );
        owner_blockcache->heads[ txn->blockcache_prev ] = txn->blockcache_next;
      } else {
        fd_txncache_single_txn_t * prev_txn = tc->txnpages[ txn->blockcache_prev/FD_TXNCACHE_TXNS_PER_PAGE ].txns[ txn->blockcache_prev%FD_TXNCACHE_TXNS_PER_PAGE ];
        FD_TEST( prev_txn->blockcache_next==head );
        prev_txn->blockcache_next = txn->blockcache_next;
      }

      /* Remove from txnpages.

         This frees up txnpages such that sizing invariants aren't
         violated.  The most obvious violation is on the max number of
         txnpages per blockcache.  Allowing pruned transactions to
         linger around could potentially cause a blockcache to grab more
         txnpages than expected.  While this is easy to overcome by just
         expanding the size of the per blockcache txnpages array,
         failing to remove pruned transactions could still degrade the
         txncache's capacity to handle future forks.  This is likely the
         most expensive part of this whole exercise, and fortunately,
         forks are rare.

         The property we want for removal from txnpages is that all the
         unremoved transactions are tightly packed at the front of the
         txnpages array within each blockcache.  In other words, we're
         compacting txnpages.  Any fully free txnpages resulting from
         this exercise will be returned to the free txnpages pool.

         The way we do this in O(n) memcpy is as follows:

         Suppose every txnpage holds 4 transactions.  C is the current
         transaction we would like to prune.  P stands for transactions
         that are already pruned or about to be pruned, i.e. other nodes
         in the linked list we are iterating over.  U stands for
         unremoved transactions that should be packed tightly.

         UUUU UCUU
                 ^ move this into C's spot

         We start scanning from the tail end (right hand side).  The
         first U transaction is swapped with C.  So the end result for
         the above is

         UUUU UUUC
               ^ ^ these were swapped

         If there is a P in the scan, it's skipped over.  So for example

         UUUC UUPP
                ^^ these stay put
               ^ this moves

         becomes

         UUUU UCPP
                ^^ these stayed put
            ^  ^ these were swapped

         If there is no U to the right hand side of C, then nothing
         moves.  For example

         UUUU CPPP  nothing moves here

         The intended invariant here is that at the end of every
         iteration, there will be nothing but P to the right of C.
         Which implies that by the end of the whole loop, all the pruned
         transactions will be at the end of txnpages, while all the
         unremoved transactions will be compacted at the front. */

      /* First step is finding an unremoved transaction to bubble up
         from the tail end of txnpages. */
      fd_txncache_single_txn_t * move_txn = NULL;
      uint move_txn_gidx = UINT_MAX;
      int done = 0;
      for( ulong j=0UL; j<owner_blockcache->shmem->pages_cnt; j++ ) {
        ushort curr_txnpage_gidx = owner_blockcache->pages[ owner_blockcache->shmem->pages_cnt-j-1UL ];
        ulong curr_txn_cnt = FD_TXNCACHE_TXNS_PER_PAGE-tc->txnpages[ curr_txnpage_gidx ].free;
        for( ulong k=0UL; k<curr_txn_cnt; k++ ) {
          fd_txncache_single_txn_t * curr_txn = tc->txnpages[ curr_txnpage_gidx ].txns[ curr_txn_cnt-k-1UL ];
          if( curr_txn==txn ) {
            /* We've reached the pruned transaction.  There's nothing to
               move.  Yay. */
            done = 1;
            break;
          }
          if( curr_txn->fork_id.val==fork_id.val ) continue; /* No point in moving another pruned transaction. */

          /* This unremoved transaction needs to move into the pruned
             transaction's spot. */
          done = 1;
          move_txn = curr_txn;
          move_txn_gidx = (uint)(FD_TXNCACHE_TXNS_PER_PAGE*curr_txnpage_gidx+curr_txn_cnt-k-1UL);
          break;
        }
        if( done ) break;
      }

      /* Bubble up the unremoved transaction. */
      if( move_txn ) {
        FD_TEST( txn->owner_fork_id.val==move_txn->owner_fork_id.val );
        move_cnt++;
        uint saved_fork_next = txn->fork_next;
        fd_txncache_fork_id_t saved_fork_id = txn->fork_id;
        *txn = *move_txn;

        /* Stitch up the hash chain for the unremoved transaction. */
        if( txn->blockcache_next!=UINT_MAX ) {
          fd_txncache_single_txn_t * next_txn = tc->txnpages[ txn->blockcache_next/FD_TXNCACHE_TXNS_PER_PAGE ].txns[ txn->blockcache_next%FD_TXNCACHE_TXNS_PER_PAGE ];
          FD_TEST( !next_txn->blockcache_prev_is_head );
          FD_TEST( next_txn->blockcache_prev==move_txn_gidx );
          next_txn->blockcache_prev = head;
        }
        FD_TEST( txn->blockcache_prev!=UINT_MAX );
        if( txn->blockcache_prev_is_head ) {
          FD_TEST( owner_blockcache->heads[ txn->blockcache_prev ]==move_txn_gidx );
          owner_blockcache->heads[ txn->blockcache_prev ] = head;
        } else {
          fd_txncache_single_txn_t * prev_txn = tc->txnpages[ txn->blockcache_prev/FD_TXNCACHE_TXNS_PER_PAGE ].txns[ txn->blockcache_prev%FD_TXNCACHE_TXNS_PER_PAGE ];
          FD_TEST( prev_txn->blockcache_next==move_txn_gidx );
          prev_txn->blockcache_next = head;
        }

        /* Stitch up the fork linked list for the unremoved transaction. */
        if( txn->fork_next!=UINT_MAX ) {
          fd_txncache_single_txn_t * next_txn = tc->txnpages[ txn->fork_next/FD_TXNCACHE_TXNS_PER_PAGE ].txns[ txn->fork_next%FD_TXNCACHE_TXNS_PER_PAGE ];
          FD_TEST( !next_txn->fork_prev_is_head );
          FD_TEST( next_txn->fork_prev==move_txn_gidx );
          next_txn->fork_prev = head;
        }
        FD_TEST( txn->fork_prev!=UINT_MAX );
        if( txn->fork_prev_is_head ) {
          FD_TEST( txn->fork_prev==txn->fork_id.val );
          blockcache_t * move_txn_blockcache = tc->blockcache_pool+txn->fork_id.val;
          move_txn_blockcache->shmem->txn_head = head;
        } else {
          fd_txncache_single_txn_t * prev_txn = tc->txnpages[ txn->fork_prev/FD_TXNCACHE_TXNS_PER_PAGE ].txns[ txn->fork_prev%FD_TXNCACHE_TXNS_PER_PAGE ];
          FD_TEST( prev_txn->fork_next==move_txn_gidx );
          prev_txn->fork_next = head;
        }

        /* Stitch up the linked list we are iterating over.  We don't
           care about updating fork_prev here because we won't need it
           for the second iteration and this transaction is about to be
           purged for good. */
        *headp = move_txn_gidx;
        move_txn->fork_next = saved_fork_next;
        head = move_txn_gidx;

        /* We need to swap this field, lest a future scan visits this
           transaction again and decides to move it once again. */
        move_txn->fork_id = saved_fork_id;

        /* No need to swap owner fork_id because they are the same. */
      }

      /* We couldn't decrement the txnpage free count right here.  The
         order in which transactions are inserted into the linked list
         in the blockcache in which they land, and the order in which
         transactions appear in the txnpages in the blockcache in which
         they reside, might not be the same.  This is because txnpage
         acquisition and list insertion are not an atomic group of
         operations.  So if we were to decrement the free count here, we
         could break invariants in how we visit and bubble up
         transactions. */
    }

    /* Now a second iteration to update all the txnpage free counts.
       This is the final step in txnpage compaction.  At this point,
       only the linked list next pointer and the owner fork_id are valid
       fields to read.  Any other field within a transaction may have
       been overwritten when we moved unremoved transactions. */
    ulong cnt2 = 0UL;
    for( uint head=blockcache->shmem->txn_head; head!=UINT_MAX; head=tc->txnpages[ head/FD_TXNCACHE_TXNS_PER_PAGE ].txns[ head%FD_TXNCACHE_TXNS_PER_PAGE ]->fork_next ) {
      cnt2++;
      fd_txncache_single_txn_t * txn = tc->txnpages[ head/FD_TXNCACHE_TXNS_PER_PAGE ].txns[ head%FD_TXNCACHE_TXNS_PER_PAGE ];
      blockcache_t * owner_blockcache = tc->blockcache_pool+txn->owner_fork_id.val;
      ushort curr_txnpage_gidx = owner_blockcache->pages[ owner_blockcache->shmem->pages_cnt-1UL ];
      ulong last_txn_idx = FD_TXNCACHE_TXNS_PER_PAGE-tc->txnpages[ curr_txnpage_gidx ].free-1UL;
      fd_txncache_single_txn_t * last_txn = tc->txnpages[ curr_txnpage_gidx ].txns[ last_txn_idx ];

      /* Invariant: all pruned transactions should be at the tail end of
         txnpages after compaction.  The specific tail transaction we
         are looking at here may not be the same transaction that we are
         visiting over the linked list, but this at least checks that
         the number of pruned transactions at the tail end matches our
         expectation. */
      FD_TEST( last_txn->fork_id.val==fork_id.val );

      tc->txnpages[ curr_txnpage_gidx ].free++;
      if( FD_UNLIKELY( tc->txnpages[ curr_txnpage_gidx ].free==FD_TXNCACHE_TXNS_PER_PAGE ) ) {
        owner_blockcache->shmem->pages_cnt--;
        tc->txnpages_free[ tc->shmem->txnpages_free_cnt ] = curr_txnpage_gidx;
        tc->shmem->txnpages_free_cnt++;
        FD_LOG_DEBUG(( "compacted away txnpage %u", curr_txnpage_gidx ));
      }
    }
    FD_TEST( cnt1==cnt2 );
    long end_tick = fd_tickcount();
    FD_LOG_DEBUG(( "pruned %lu minority fork (fork_id %u) transactions in %ld ticks with %lu moves", cnt1, fork_id.val, end_tick-start_tick, move_cnt ));
  }

  memcpy( tc->txnpages_free+tc->shmem->txnpages_free_cnt, blockcache->pages, blockcache->shmem->pages_cnt*sizeof(tc->txnpages_free[ 0 ]) );
  tc->shmem->txnpages_free_cnt = (ushort)(tc->shmem->txnpages_free_cnt+blockcache->shmem->pages_cnt);

  for( ulong i=0UL; i<tc->shmem->active_slots_max; i++ ) descends_set_remove( tc->blockcache_pool[ i ].descends, fork_id.val );

  if( FD_LIKELY( blockcache->shmem->frozen ) ) blockhash_map_ele_remove_fast( tc->blockhash_map, blockcache->shmem, tc->blockcache_shmem_pool );
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
    if( FD_LIKELY( sibling==except ) ) continue; /* Optimize for no forking. */

    remove_children( tc, sibling, except );
    remove_blockcache( tc, sibling, 1 );
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

    remove_blockcache( tc, old_root, 0 );
    tc->shmem->root_cnt--;
  }

  fd_rwlock_unwrite( tc->shmem->lock );
}

static inline blockcache_t *
blockhash_on_fork( fd_txncache_t *      tc,
                   blockcache_t const * fork,
                   uchar const *        blockhash ) {
  fd_txncache_blockcache_shmem_t const * candidate = blockhash_map_ele_query_const( tc->blockhash_map, fd_type_pun_const( blockhash ), NULL, tc->blockcache_shmem_pool );
  if( FD_UNLIKELY( !candidate ) ) return NULL;

  while( candidate ) {
    ulong candidate_idx = blockcache_pool_idx( tc->blockcache_shmem_pool, candidate );
    if( FD_LIKELY( descends_set_test( fork->descends, candidate_idx ) ) ) return &tc->blockcache_pool[ candidate_idx ];
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

  /* TODO: We can't print the full txnhash here typically because we
     might only be able to see 20 bytes, but we need to print it for
     diagnostic purposes. Remove once bug is identified. */
  if( FD_UNLIKELY( !blockcache ) ) FD_LOG_CRIT(( "transaction %s refers to blockhash %s which does not exist on fork", FD_BASE58_ENC_32_ALLOCA( txnhash ), FD_BASE58_ENC_32_ALLOCA( blockhash ) ));

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

  /* TODO: We can't print the full txnhash here typically because we
     might only be able to see 20 bytes, but we need to print it for
     diagnostic purposes. Remove once bug is identified. */
  if( FD_UNLIKELY( !blockcache ) ) FD_LOG_CRIT(( "transaction %s refers to blockhash %s which does not exist on fork", FD_BASE58_ENC_32_ALLOCA( txnhash ), FD_BASE58_ENC_32_ALLOCA( blockhash ) ));

  int found = 0;

  ulong txnhash_offset = blockcache->shmem->txnhash_offset;
  ulong head_hash = FD_LOAD( ulong, txnhash+txnhash_offset ) % tc->shmem->txn_per_slot_max;
  for( uint head=blockcache->heads[ head_hash ]; head!=UINT_MAX; head=tc->txnpages[ head/FD_TXNCACHE_TXNS_PER_PAGE ].txns[ head%FD_TXNCACHE_TXNS_PER_PAGE ]->blockcache_next ) {
    fd_txncache_single_txn_t * txn = tc->txnpages[ head/FD_TXNCACHE_TXNS_PER_PAGE ].txns[ head%FD_TXNCACHE_TXNS_PER_PAGE ];

    int descends = txn->fork_id.val==fork_id.val || descends_set_test( fork->descends, txn->fork_id.val );
    if( FD_LIKELY( descends && !memcmp( txnhash+txnhash_offset, txn->txnhash, 20UL ) ) ) {
      found = 1;
      break;
    }
  }

  fd_rwlock_unread( tc->shmem->lock );
  return found;
}
