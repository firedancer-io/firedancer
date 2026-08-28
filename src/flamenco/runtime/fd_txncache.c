#include "fd_txncache.h"
#include "fd_txncache_private.h"
#include "../../util/log/fd_log.h"

#include <errno.h>
#include <unistd.h>

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

  ushort * scratch_pages;
  uint * scratch_heads;
  fd_txncache_txnpage_t * scratch_txnpage;

  /* Disk tier.  Page indices in [ram_txnpages,max_txnpages) live in a
     file at slot (idx-ram_txnpages), accessed with explicit
     pread/pwrite through fd.  All fields below are only used when
     shmem->disk_txnpages is nonzero. */
  ushort * disk_free;                    /* Free disk slot stack (global page indices). */
  fd_txncache_txnpage_t * scratch_rdpage; /* Scratchpad txnpage for disk reads during compaction. */
  ushort * scratch_remap;                /* Scratchpad RAM page idx -> disk page idx map for spills. */
  int fd;
};

static void
spill_ram( fd_txncache_t * tc,
           ulong           target_free );

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
                 fd_txncache_shmem_t * shmem,
                 int                   fd ) {
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
  ulong bucket_cnt = shmem->bucket_cnt;

  /* Page counts come from the shmem header rather than being
     re-derived, so the layout walk below cannot desync from the one in
     fd_txncache_shmem_new. */
  ushort _ram_txnpages              = shmem->ram_txnpages;
  ushort _disk_txnpages             = shmem->disk_txnpages;
  ushort _max_txnpages_per_blockhash = shmem->txnpages_per_blockhash_max;

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
  void * _blockcache_heads    = FD_SCRATCH_ALLOC_APPEND( l, alignof(uint),                   max_active_slots*bucket_cnt*sizeof(uint)                    );
  void * _blockcache_descends = FD_SCRATCH_ALLOC_APPEND( l, descends_set_align(),            max_active_slots*_descends_footprint                        );
  void * _txnpages_free       = FD_SCRATCH_ALLOC_APPEND( l, alignof(ushort),                 _ram_txnpages*sizeof(ushort)                                );
  void * _txnpages            = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_txncache_txnpage_t),  _ram_txnpages*sizeof(fd_txncache_txnpage_t)                 );
  void * _scratch_pages       = FD_SCRATCH_ALLOC_APPEND( l, alignof(ushort),                 _max_txnpages_per_blockhash*sizeof(ushort)                  );
  void * _scratch_heads       = FD_SCRATCH_ALLOC_APPEND( l, alignof(uint),                   bucket_cnt*sizeof(uint)                                     );
  void * _scratch_txnpage     = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_txncache_txnpage_t),  sizeof(fd_txncache_txnpage_t)                               );
  void * _disk_free           = FD_SCRATCH_ALLOC_APPEND( l, alignof(ushort),                 _disk_txnpages*sizeof(ushort)                               );
  void * _scratch_rdpage      = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_txncache_txnpage_t),  _disk_txnpages ? sizeof(fd_txncache_txnpage_t) : 0UL        );
  void * _scratch_remap       = FD_SCRATCH_ALLOC_APPEND( l, alignof(ushort),                 _disk_txnpages ? _ram_txnpages*sizeof(ushort) : 0UL         );

  FD_SCRATCH_ALLOC_INIT( l2, ljoin );
  fd_txncache_t * ltc           = FD_SCRATCH_ALLOC_APPEND( l2, FD_TXNCACHE_ALIGN,     sizeof(fd_txncache_t)                 );
  void * _local_blockcache_pool = FD_SCRATCH_ALLOC_APPEND( l2, alignof(blockcache_t), max_active_slots*sizeof(blockcache_t) );

  ltc->shmem = tc;

  ltc->blockcache_pool = (blockcache_t*)_local_blockcache_pool;
  ltc->blockcache_shmem_pool = blockcache_pool_join( _blockcache_pool );

  for( ulong i=0UL; i<shmem->active_slots_max; i++ ) {
    ltc->blockcache_pool[ i ].pages    = (ushort *)_blockcache_pages + i*_max_txnpages_per_blockhash;
    ltc->blockcache_pool[ i ].heads    = (uint *)_blockcache_heads + i*bucket_cnt;
    ltc->blockcache_pool[ i ].descends = descends_set_join( (uchar *)_blockcache_descends + i*_descends_footprint );
    ltc->blockcache_pool[ i ].shmem    = ltc->blockcache_shmem_pool + i;
    FD_TEST( ltc->blockcache_pool[ i ].shmem );
  }

  FD_TEST( ltc->blockcache_shmem_pool );

  ltc->blockhash_map = blockhash_map_join( _blockhash_map );
  FD_TEST( ltc->blockhash_map );

  ltc->txnpages_free = (ushort *)_txnpages_free;
  ltc->txnpages      = (fd_txncache_txnpage_t *)_txnpages;

  ltc->scratch_pages   = _scratch_pages;
  ltc->scratch_heads   = _scratch_heads;
  ltc->scratch_txnpage = _scratch_txnpage;

  ltc->disk_free      = (ushort *)_disk_free;
  ltc->scratch_rdpage = (fd_txncache_txnpage_t *)_scratch_rdpage;
  ltc->scratch_remap  = (ushort *)_scratch_remap;
  ltc->fd             = fd;

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

  tc->shmem->txnpages_free_cnt = tc->shmem->ram_txnpages;
  for( ushort i=0; i<tc->shmem->ram_txnpages; i++ ) tc->txnpages_free[ i ] = i;

  tc->shmem->disk_free_cnt = tc->shmem->disk_txnpages;
  for( ulong i=0UL; i<tc->shmem->disk_txnpages; i++ ) tc->disk_free[ i ] = (ushort)(tc->shmem->ram_txnpages+i);

  blockcache_pool_reset( tc->blockcache_shmem_pool );
  blockhash_map_reset( tc->blockhash_map );

  fd_rwlock_unwrite( tc->shmem->lock );
}

FD_FN_PURE static inline ulong
fd_txncache_bucket( fd_txncache_t const * tc,
                    uchar const *         txnhash ) {
  return fd_ulong_hash( FD_LOAD( ulong, txnhash )^tc->shmem->seed )%tc->shmem->bucket_cnt;
}

/* Disk tier I/O.  Global page indices >=ram_txnpages live in the tier
   file at slot (idx-ram_txnpages).  Pages are written only under the
   write lock; reads happen under the read lock, and never race a
   writer because a disk page's contents are immutable while any chain
   references it. */

static inline ulong
fd_txncache_disk_off( fd_txncache_t const * tc,
                      ulong                 page_idx ) {
  return (page_idx-tc->shmem->ram_txnpages)*sizeof(fd_txncache_txnpage_t);
}

static void
fd_txncache_disk_rd( fd_txncache_t const * tc,
                     void *                dst,
                     ulong                 sz,
                     ulong                 off ) {
  uchar * p = (uchar *)dst;
  while( sz ) {
    long res = pread( tc->fd, p, sz, (off_t)off );
    if( FD_UNLIKELY( res<=0L ) ) {
      if( FD_UNLIKELY( res<0L && errno==EINTR ) ) continue;
      FD_LOG_ERR(( "txncache disk tier pread(%lu,%lu) failed (%i-%s)", sz, off, errno, fd_io_strerror( errno ) ));
    }
    p += res; sz -= (ulong)res; off += (ulong)res;
  }
}

static void
fd_txncache_disk_wr( fd_txncache_t const * tc,
                     void const *          src,
                     ulong                 sz,
                     ulong                 off ) {
  uchar const * p = (uchar const *)src;
  while( sz ) {
    long res = pwrite( tc->fd, p, sz, (off_t)off );
    if( FD_UNLIKELY( res<=0L ) ) {
      if( FD_UNLIKELY( res<0L && errno==EINTR ) ) continue;
      FD_LOG_ERR(( "txncache disk tier pwrite(%lu,%lu) failed (%i-%s)", sz, off, errno, fd_io_strerror( errno ) ));
    }
    p += res; sz -= (ulong)res; off += (ulong)res;
  }
}

/* fd_txncache_txn_at loads the chain entry with global index gidx,
   either directly from a RAM page or with a 30 byte pread from the
   disk tier into *out. */

static inline fd_txncache_single_txn_t const *
fd_txncache_txn_at( fd_txncache_t const *      tc,
                    uint                       gidx,
                    fd_txncache_single_txn_t * out ) {
  ulong page_idx = gidx/FD_TXNCACHE_TXNS_PER_PAGE;
  ulong txn_idx  = gidx%FD_TXNCACHE_TXNS_PER_PAGE;
  if( FD_LIKELY( page_idx<tc->shmem->ram_txnpages ) ) return tc->txnpages[ page_idx ].txns[ txn_idx ];
  fd_txncache_disk_rd( tc, out, sizeof(fd_txncache_single_txn_t),
                       fd_txncache_disk_off( tc, page_idx )+offsetof(fd_txncache_txnpage_t, txns)+txn_idx*sizeof(fd_txncache_single_txn_t) );
  return out;
}

/* fd_txncache_ram_suffix returns the index into blockcache->pages of
   the first RAM resident page.  Pages before it are disk tier pages:
   spills always migrate the entire RAM suffix, so disk pages always
   form a prefix of the page list. */

static inline ulong
fd_txncache_ram_suffix( fd_txncache_t const * tc,
                        blockcache_t const *  blockcache ) {
  ulong suffix0 = blockcache->shmem->pages_cnt;
  while( suffix0>0UL && blockcache->pages[ suffix0-1UL ]<tc->shmem->ram_txnpages ) suffix0--;
  return suffix0;
}

static fd_txncache_txnpage_t *
fd_txncache_ensure_txnpage( fd_txncache_t * tc,
                            blockcache_t *  blockcache ) {
  ushort page_cnt = blockcache->shmem->pages_cnt;
  if( FD_UNLIKELY( page_cnt>tc->shmem->txnpages_per_blockhash_max ) ) return NULL;

  if( FD_LIKELY( page_cnt ) ) {
    ushort txnpage_idx = blockcache->pages[ page_cnt-1 ];
    /* A disk tier tail page is never inserted into, a fresh RAM page
       is allocated instead. */
    if( FD_LIKELY( txnpage_idx<tc->shmem->ram_txnpages ) ) {
      ushort txnpage_free = tc->txnpages[ txnpage_idx ].free;
      if( FD_LIKELY( txnpage_free ) ) return &tc->txnpages[ txnpage_idx ];
    }
  }

  if( FD_UNLIKELY( page_cnt==tc->shmem->txnpages_per_blockhash_max ) ) return NULL;
  if( FD_LIKELY( FD_ATOMIC_CAS( &blockcache->pages[ page_cnt ], (ushort)USHORT_MAX, (ushort)(USHORT_MAX-1UL) )==(ushort)USHORT_MAX ) ) {
    ulong txnpages_free_cnt = tc->shmem->txnpages_free_cnt;
    for(;;) {
      if( FD_UNLIKELY( !txnpages_free_cnt ) ) {
        blockcache->pages[ page_cnt ] = (ushort)USHORT_MAX;
        FD_COMPILER_MFENCE();
        return NULL;
      }
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
    while( FD_UNLIKELY( txnpage_idx==(ushort)(USHORT_MAX-1UL) ) ) {
      txnpage_idx = blockcache->pages[ page_cnt ];
      FD_SPIN_PAUSE();
    }
    if( FD_UNLIKELY( txnpage_idx==(ushort)USHORT_MAX ) ) return NULL;
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
    txnpage->txns[ txn_idx ]->generation = tc->blockcache_pool[ fork_id.val ].shmem->generation;
    FD_COMPILER_MFENCE();

    ulong txn_bucket = fd_txncache_bucket( tc, txnhash+txnhash_offset );
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

  fork->shmem->generation = tc->shmem->blockcache_generation++;
  fork->shmem->child_id = (fd_txncache_fork_id_t){ .val = USHORT_MAX };

  if( FD_LIKELY( parent_fork_id.val==USHORT_MAX ) ) {
    FD_TEST( blockcache_pool_free( tc->blockcache_shmem_pool )==blockcache_pool_max( tc->blockcache_shmem_pool )-1UL );
    fork->shmem->parent_id  = (fd_txncache_fork_id_t){ .val = USHORT_MAX };
    fork->shmem->sibling_id = (fd_txncache_fork_id_t){ .val = USHORT_MAX };

    descends_set_null( fork->descends );
    root_slist_ele_push_tail( tc->shmem->root_ll, fork->shmem, tc->blockcache_shmem_pool );
  } else {
    blockcache_t * parent = &tc->blockcache_pool[ parent_fork_id.val ];
    /* We might be tempted to freeze the parent here, and it's valid to
       do this ordinarily, but not when loading from a snapshot, when
       we need to load many transactions into a root parent chain at
       once. */
    fork->shmem->sibling_id = parent->shmem->child_id;
    fork->shmem->parent_id  = parent_fork_id;
    parent->shmem->child_id = fork_id;

    descends_set_copy( fork->descends, parent->descends );
    descends_set_insert( fork->descends, parent_fork_id.val );
  }

  fork->shmem->txnhash_offset = 0UL;
  fork->shmem->frozen = 0;
  memset( fork->heads, 0xFF, tc->shmem->bucket_cnt*sizeof(uint) );
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
  FD_TEST( fork->shmem->frozen>=0 );
  fork->shmem->txnhash_offset = txnhash_offset;

  memcpy( fork->shmem->blockhash.uc, blockhash, 32UL );

  if( FD_LIKELY( !fork->shmem->frozen ) ) blockhash_map_ele_insert( tc->blockhash_map, fork->shmem, tc->blockcache_shmem_pool );
  fork->shmem->frozen = 2;

  fd_rwlock_unwrite( tc->shmem->lock );
}

static inline void
remove_blockcache( fd_txncache_t * tc,
                   blockcache_t *  blockcache ) {
  FD_TEST( blockcache->shmem->frozen>=0 );
  ulong ram_suffix0 = fd_txncache_ram_suffix( tc, blockcache );
  for( ulong i=0UL; i<blockcache->shmem->pages_cnt; i++ ) {
    ushort page = blockcache->pages[ i ];
    if( FD_LIKELY( i>=ram_suffix0 ) ) tc->txnpages_free[ tc->shmem->txnpages_free_cnt++ ] = page;
    else                              tc->disk_free[ tc->shmem->disk_free_cnt++ ] = page;
  }

  ulong idx = blockcache_pool_idx( tc->blockcache_shmem_pool, blockcache->shmem );
  for( ulong i=0UL; i<tc->shmem->active_slots_max; i++ ) descends_set_remove( tc->blockcache_pool[ i ].descends, idx );

  if( FD_LIKELY( blockcache->shmem->frozen ) ) blockhash_map_ele_remove_fast( tc->blockhash_map, blockcache->shmem, tc->blockcache_shmem_pool );
  blockcache->shmem->frozen = -1;
  blockcache_pool_ele_release( tc->blockcache_shmem_pool, blockcache->shmem );
}

static inline void
remove_children( fd_txncache_t *      tc,
                 blockcache_t const * fork,
                 blockcache_t const * except ) {
  fd_txncache_fork_id_t sibling_idx = fork->shmem->child_id;
  while( sibling_idx.val!=USHORT_MAX ) {
    blockcache_t * sibling = &tc->blockcache_pool[ sibling_idx.val ];

    sibling_idx = sibling->shmem->sibling_id;
    if( FD_UNLIKELY( sibling==except ) ) continue;

    remove_children( tc, sibling, except );
    remove_blockcache( tc, sibling );
  }
}

void
fd_txncache_cancel_fork( fd_txncache_t *       tc,
                         fd_txncache_fork_id_t fork_id ) {
  fd_rwlock_write( tc->shmem->lock );
  blockcache_t * fork = &tc->blockcache_pool[ fork_id.val ];
  FD_TEST( fork->shmem->parent_id.val!=USHORT_MAX );

  /* The soon-to-be-pruned subtree must be unrooted. */
  fd_txncache_blockcache_shmem_t const * latest_root = root_slist_ele_peek_tail_const( tc->shmem->root_ll, tc->blockcache_shmem_pool );
  FD_TEST( latest_root );
  FD_TEST( descends_set_test( fork->descends, blockcache_pool_idx( tc->blockcache_shmem_pool, latest_root ) ) );

  remove_children( tc, fork, NULL );
  remove_blockcache( tc, fork );
  ushort * fork_id_p = &(tc->blockcache_pool[ fork->shmem->parent_id.val ].shmem->child_id.val);
  while( *fork_id_p!=fork_id.val ) {
    fork_id_p = &(tc->blockcache_pool[ *fork_id_p ].shmem->sibling_id.val);
  }
  *fork_id_p = fork->shmem->sibling_id.val;
  fd_rwlock_unwrite( tc->shmem->lock );
}

void
fd_txncache_advance_root( fd_txncache_t *       tc,
                          fd_txncache_fork_id_t fork_id ) {
  fd_rwlock_write( tc->shmem->lock );

  blockcache_t * fork = &tc->blockcache_pool[ fork_id.val ];
  FD_TEST( fork->shmem->parent_id.val!=USHORT_MAX );

  blockcache_t * parent_fork = &tc->blockcache_pool[ fork->shmem->parent_id.val ];
  if( FD_UNLIKELY( root_slist_ele_peek_tail( tc->shmem->root_ll, tc->blockcache_shmem_pool )!=parent_fork->shmem ) ) {
    FD_BASE58_ENCODE_32_BYTES( parent_fork->shmem->blockhash.uc, parent_blockhash_b58 );
    FD_BASE58_ENCODE_32_BYTES( fork->shmem->blockhash.uc, fork_blockhash_b58 );
    FD_BASE58_ENCODE_32_BYTES( root_slist_ele_peek_tail( tc->shmem->root_ll, tc->blockcache_shmem_pool )->blockhash.uc, root_blockhash_b58 );
    FD_LOG_CRIT(( "advancing root from %s to %s but that is not valid, last root is %s",
                  parent_blockhash_b58,
                  fork_blockhash_b58,
                  root_blockhash_b58 ));
  }

  FD_BASE58_ENCODE_32_BYTES( parent_fork->shmem->blockhash.uc, parent_blockhash_b58 );
  FD_BASE58_ENCODE_32_BYTES( fork->shmem->blockhash.uc, fork_blockhash_b58 );
  FD_LOG_DEBUG(( "advancing root from %s to %s",
                 parent_blockhash_b58,
                 fork_blockhash_b58 ));

  /* When a fork is rooted, any competing forks can be immediately
     removed as they will not be needed again.  This includes child
     forks of the pruned siblings as well. */
  remove_children( tc, parent_fork, fork );
  parent_fork->shmem->child_id = fork_id;
  fork->shmem->sibling_id = (fd_txncache_fork_id_t){ .val = USHORT_MAX };

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

  /* Migrate cold blockcaches to the disk tier here rather than only on
     insert exhaustion, amortizing spill I/O into root advancement.  At
     mainnet load the pool never drops this low and this never runs. */
  if( FD_UNLIKELY( tc->shmem->disk_txnpages && tc->shmem->txnpages_free_cnt<tc->shmem->ram_txnpages/4 ) )
    spill_ram( tc, tc->shmem->ram_txnpages/2UL );

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

static void
purge_stale_on_blockcache( fd_txncache_t * tc,
                           blockcache_t *  blockcache ) {
  FD_TEST( blockcache->shmem->frozen>=0 );
  /* Blockcaches with disk tier pages are compacted by sweep_disk
     instead (rebuilding heads here would sever the disk chains). */
  if( FD_UNLIKELY( blockcache->shmem->pages_cnt && blockcache->pages[ 0 ]>=tc->shmem->ram_txnpages ) ) return;
  memset( tc->scratch_heads, 0xFF, tc->shmem->bucket_cnt*sizeof(tc->scratch_heads[ 0 ]) );
  memset( tc->scratch_pages, 0xFF, tc->shmem->txnpages_per_blockhash_max*sizeof(tc->scratch_pages[ 0 ]) );
  ushort scratch_pages_cnt = 0;
  ushort scratch_txnpage_idx = USHORT_MAX;
  tc->scratch_txnpage->free = 0;
  for( ulong i=0UL; i<blockcache->shmem->pages_cnt; i++ ) {
    ushort curr_txnpage_idx = blockcache->pages[ blockcache->shmem->pages_cnt-i-1UL ];
    ulong curr_txn_cnt = FD_TXNCACHE_TXNS_PER_PAGE-tc->txnpages[ curr_txnpage_idx ].free;
    for( ulong j=0UL; j<curr_txn_cnt; j++ ) {
      fd_txncache_single_txn_t * curr_txn = tc->txnpages[ curr_txnpage_idx ].txns[ curr_txn_cnt-j-1UL ];
      blockcache_t const * txn_fork = &tc->blockcache_pool[ curr_txn->fork_id.val ];
      if( FD_LIKELY( txn_fork->shmem->frozen>=0 && txn_fork->shmem->generation==curr_txn->generation ) ) {
        /* Valid transaction.  Keep. */
        if( FD_UNLIKELY( !tc->scratch_txnpage->free ) ) {
          FD_TEST( scratch_txnpage_idx!=curr_txnpage_idx );
          if( FD_LIKELY( scratch_txnpage_idx!=USHORT_MAX ) ) {
            fd_txncache_txnpage_t * txnpage = &tc->txnpages[ scratch_txnpage_idx ];
            memcpy( txnpage, tc->scratch_txnpage, sizeof(*txnpage) );
          }
          scratch_txnpage_idx = curr_txnpage_idx;
          tc->scratch_txnpage->free = FD_TXNCACHE_TXNS_PER_PAGE;
          tc->scratch_pages[ scratch_pages_cnt ] = scratch_txnpage_idx;
          scratch_pages_cnt++;
        }
        ulong txn_idx = FD_TXNCACHE_TXNS_PER_PAGE-tc->scratch_txnpage->free;
        memcpy( tc->scratch_txnpage->txns[ txn_idx ], curr_txn, sizeof(*curr_txn) );
        ulong txn_bucket = fd_txncache_bucket( tc, curr_txn->txnhash );
        uint head = tc->scratch_heads[ txn_bucket ];
        tc->scratch_txnpage->txns[ txn_idx ]->blockcache_next = head;
        ulong txn_gidx = FD_TXNCACHE_TXNS_PER_PAGE*scratch_txnpage_idx+txn_idx;
        FD_TEST( txn_gidx<UINT_MAX );
        tc->scratch_heads[ txn_bucket ] = (uint)txn_gidx;
        tc->scratch_txnpage->free--;
      } else {
        /* Stale transaction.  Drop. */
        continue;
      }
    }
    if( FD_UNLIKELY( curr_txnpage_idx!=scratch_txnpage_idx ) ) {
      /* The txnpage is not being used for compaction, free it up. */
      tc->txnpages_free[ tc->shmem->txnpages_free_cnt ] = curr_txnpage_idx;
      tc->shmem->txnpages_free_cnt++;
    }
  }
  if( FD_LIKELY( scratch_txnpage_idx!=USHORT_MAX ) ) {
    fd_txncache_txnpage_t * txnpage = &tc->txnpages[ scratch_txnpage_idx ];
    memcpy( txnpage, tc->scratch_txnpage, sizeof(*txnpage) );
  }
  blockcache->shmem->pages_cnt = scratch_pages_cnt;
  memcpy( blockcache->pages, tc->scratch_pages, tc->shmem->txnpages_per_blockhash_max*sizeof(blockcache->pages[0]) );
  memcpy( blockcache->heads, tc->scratch_heads, tc->shmem->bucket_cnt*sizeof(blockcache->heads[0]) );
}

static void
purge_stale_on_fork( fd_txncache_t * tc,
                     blockcache_t *  fork ) {
  purge_stale_on_blockcache( tc, fork );

  fd_txncache_fork_id_t sibling_idx = fork->shmem->child_id;
  while( sibling_idx.val!=USHORT_MAX ) {
    blockcache_t * sibling = &tc->blockcache_pool[ sibling_idx.val ];
    purge_stale_on_fork( tc, sibling );
    sibling_idx = sibling->shmem->sibling_id;
  }
}

static void
purge_stale( fd_txncache_t * tc ) {
  fd_txncache_blockcache_shmem_t * root_shmem = root_slist_ele_peek_head( tc->shmem->root_ll, tc->blockcache_shmem_pool );
  FD_TEST( root_shmem );
  blockcache_t * root = &tc->blockcache_pool[ blockcache_pool_idx( tc->blockcache_shmem_pool, root_shmem ) ];
  ushort free_before = tc->shmem->txnpages_free_cnt;
  /* One might think that an optimization here is to stop the descent on
     the latest rooted blockcache.  There could be no pruned minority
     forks from that point on.  As a result, there could be no stale
     transactions in any blockcache descending from that.
     Unfortunately, frontier eviction means that any blockcache in the
     fork tree can have stale transactions. */
  purge_stale_on_fork( tc, root );
  FD_LOG_WARNING(( "purge_stale: txnpages_free %hu -> %hu", free_before, tc->shmem->txnpages_free_cnt ));
}

/* spill_append migrates the RAM page suffix of a blockcache to the
   disk tier wholesale.  Chains never leave a blockcache and entries
   only point at older entries, so moving the entire suffix means no
   pointer into RAM survives and already written disk pages stay
   immutable: only the page component of chain links needs remapping.
   Caller must hold the write lock and preflight disk_free_cnt. */

static void
spill_append( fd_txncache_t * tc,
              blockcache_t *  blockcache ) {
  ulong ram_txnpages = tc->shmem->ram_txnpages;
  ulong pages_cnt    = blockcache->shmem->pages_cnt;
  ulong suffix0      = fd_txncache_ram_suffix( tc, blockcache );
  if( FD_UNLIKELY( suffix0==pages_cnt ) ) return;

  FD_TEST( tc->shmem->disk_free_cnt>=pages_cnt-suffix0 );
  for( ulong i=suffix0; i<pages_cnt; i++ ) tc->scratch_remap[ blockcache->pages[ i ] ] = tc->disk_free[ --tc->shmem->disk_free_cnt ];

  for( ulong i=suffix0; i<pages_cnt; i++ ) {
    ushort src = blockcache->pages[ i ];
    ushort dst = tc->scratch_remap[ src ];
    fd_txncache_txnpage_t * stage = tc->scratch_txnpage;
    memcpy( stage, &tc->txnpages[ src ], sizeof(fd_txncache_txnpage_t) );
    ulong used = FD_TXNCACHE_TXNS_PER_PAGE-stage->free;
    for( ulong j=0UL; j<used; j++ ) {
      uint next = stage->txns[ j ]->blockcache_next;
      if( next==UINT_MAX ) continue;
      ulong next_page = next/FD_TXNCACHE_TXNS_PER_PAGE;
      if( next_page<ram_txnpages ) stage->txns[ j ]->blockcache_next = (uint)(FD_TXNCACHE_TXNS_PER_PAGE*tc->scratch_remap[ next_page ]+next%FD_TXNCACHE_TXNS_PER_PAGE);
    }
    fd_txncache_disk_wr( tc, stage, sizeof(fd_txncache_txnpage_t), fd_txncache_disk_off( tc, dst ) );
    tc->txnpages_free[ tc->shmem->txnpages_free_cnt++ ] = src;
    blockcache->pages[ i ] = dst;
  }

  for( ulong b=0UL; b<tc->shmem->bucket_cnt; b++ ) {
    uint head = blockcache->heads[ b ];
    if( head==UINT_MAX ) continue;
    ulong head_page = head/FD_TXNCACHE_TXNS_PER_PAGE;
    if( head_page<ram_txnpages ) blockcache->heads[ b ] = (uint)(FD_TXNCACHE_TXNS_PER_PAGE*tc->scratch_remap[ head_page ]+head%FD_TXNCACHE_TXNS_PER_PAGE);
  }
}

/* compact_disk rewrites the disk pages of a blockcache, dropping
   entries whose inserting fork is gone (the disk analogue of
   purge_stale) and repacking partial pages.  RAM entries stay in
   place, stale ones are just unlinked, and all chains are rebuilt so
   disk entries still never point at RAM.  Never allocates disk slots:
   the compacted stream reuses the blockcache's own slots in list
   order, and since kept entries never exceed entries read, the write
   cursor cannot pass the read cursor (the page being read is fully
   buffered first).  Caller must hold the write lock. */

static void
compact_disk( fd_txncache_t * tc,
              blockcache_t *  blockcache ) {
  if( FD_UNLIKELY( blockcache->shmem->frozen<0 ) ) return;
  ulong pages_cnt = blockcache->shmem->pages_cnt;
  ulong suffix0   = fd_txncache_ram_suffix( tc, blockcache );
  if( FD_UNLIKELY( !suffix0 ) ) return; /* no disk pages */

  memset( tc->scratch_heads, 0xFF, tc->shmem->bucket_cnt*sizeof(uint) );

  fd_txncache_txnpage_t * stage = tc->scratch_txnpage;
  stage->free = FD_TXNCACHE_TXNS_PER_PAGE;
  ulong out_cnt = 0UL;

  for( ulong i=0UL; i<suffix0; i++ ) {
    fd_txncache_disk_rd( tc, tc->scratch_rdpage, sizeof(fd_txncache_txnpage_t), fd_txncache_disk_off( tc, blockcache->pages[ i ] ) );
    ulong used = FD_TXNCACHE_TXNS_PER_PAGE-tc->scratch_rdpage->free;
    for( ulong j=0UL; j<used; j++ ) {
      fd_txncache_single_txn_t * txn = tc->scratch_rdpage->txns[ j ];
      blockcache_t const * txn_fork = &tc->blockcache_pool[ txn->fork_id.val ];
      if( FD_UNLIKELY( txn_fork->shmem->frozen<0 || txn_fork->shmem->generation!=txn->generation ) ) continue;
      if( FD_UNLIKELY( !stage->free ) ) {
        ushort dst = blockcache->pages[ out_cnt ];
        fd_txncache_disk_wr( tc, stage, sizeof(fd_txncache_txnpage_t), fd_txncache_disk_off( tc, dst ) );
        tc->scratch_pages[ out_cnt++ ] = dst;
        stage->free = FD_TXNCACHE_TXNS_PER_PAGE;
      }
      ulong txn_idx = FD_TXNCACHE_TXNS_PER_PAGE-stage->free;
      memcpy( stage->txns[ txn_idx ], txn, sizeof(fd_txncache_single_txn_t) );
      ulong txn_bucket = fd_txncache_bucket( tc, txn->txnhash );
      stage->txns[ txn_idx ]->blockcache_next = tc->scratch_heads[ txn_bucket ];
      tc->scratch_heads[ txn_bucket ] = (uint)(FD_TXNCACHE_TXNS_PER_PAGE*blockcache->pages[ out_cnt ]+txn_idx);
      stage->free--;
    }
  }
  if( FD_LIKELY( stage->free<FD_TXNCACHE_TXNS_PER_PAGE ) ) {
    ushort dst = blockcache->pages[ out_cnt ];
    fd_txncache_disk_wr( tc, stage, sizeof(fd_txncache_txnpage_t), fd_txncache_disk_off( tc, dst ) );
    tc->scratch_pages[ out_cnt++ ] = dst;
  }

  for( ulong i=out_cnt; i<suffix0; i++ ) tc->disk_free[ tc->shmem->disk_free_cnt++ ] = blockcache->pages[ i ];

  /* RAM entries are newer than all disk entries and pushed after, so
     rebuilt disk chains never point at RAM. */
  for( ulong i=suffix0; i<pages_cnt; i++ ) {
    fd_txncache_txnpage_t * page = &tc->txnpages[ blockcache->pages[ i ] ];
    ulong used = FD_TXNCACHE_TXNS_PER_PAGE-page->free;
    for( ulong j=0UL; j<used; j++ ) {
      fd_txncache_single_txn_t * txn = page->txns[ j ];
      blockcache_t const * txn_fork = &tc->blockcache_pool[ txn->fork_id.val ];
      if( FD_UNLIKELY( txn_fork->shmem->frozen<0 || txn_fork->shmem->generation!=txn->generation ) ) continue;
      ulong txn_bucket = fd_txncache_bucket( tc, txn->txnhash );
      txn->blockcache_next = tc->scratch_heads[ txn_bucket ];
      tc->scratch_heads[ txn_bucket ] = (uint)(FD_TXNCACHE_TXNS_PER_PAGE*blockcache->pages[ i ]+j);
    }
  }

  ulong new_cnt = out_cnt+(pages_cnt-suffix0);
  for( ulong i=suffix0; i<pages_cnt; i++ ) tc->scratch_pages[ out_cnt+(i-suffix0) ] = blockcache->pages[ i ];
  memcpy( blockcache->pages, tc->scratch_pages, new_cnt*sizeof(ushort) );
  for( ulong i=new_cnt; i<pages_cnt; i++ ) blockcache->pages[ i ] = USHORT_MAX;
  blockcache->shmem->pages_cnt = (ushort)new_cnt;
  memcpy( blockcache->heads, tc->scratch_heads, tc->shmem->bucket_cnt*sizeof(uint) );
}

static void
sweep_disk( fd_txncache_t * tc ) {
  for( ulong i=0UL; i<tc->shmem->active_slots_max; i++ ) {
    blockcache_t * blockcache = &tc->blockcache_pool[ i ];
    if( FD_UNLIKELY( blockcache->shmem->frozen<0 ) ) continue;
    compact_disk( tc, blockcache );
  }
}

/* spill_ram frees RAM pages by migrating the coldest blockcaches
   (lowest generation: oldest roots, then oldest unrooted forks) to the
   disk tier until target_free RAM pages are free, sweeping stale
   entries out of the disk tier if slots run short.  At mainnet load
   the RAM pool never runs low and none of this executes; catchup with
   a deep unrooted backlog and adversarial max-fill regimes spill,
   preserving full capacity.  Caller must hold the write lock. */

static void
spill_ram( fd_txncache_t * tc,
           ulong           target_free ) {
  if( FD_LIKELY( !tc->shmem->disk_txnpages ) ) return;
  if( FD_UNLIKELY( tc->fd<0 ) ) FD_LOG_ERR(( "txncache RAM pages exhausted and no disk tier file" ));

  int swept = 0;
  while( tc->shmem->txnpages_free_cnt<target_free ) {
    blockcache_t * victim = NULL;
    for( ulong i=0UL; i<tc->shmem->active_slots_max; i++ ) {
      blockcache_t * blockcache = &tc->blockcache_pool[ i ];
      if( FD_UNLIKELY( blockcache->shmem->frozen<0 ) ) continue;
      ulong pages_cnt = blockcache->shmem->pages_cnt;
      if( !pages_cnt || blockcache->pages[ pages_cnt-1UL ]>=tc->shmem->ram_txnpages ) continue; /* no RAM pages */
      if( !victim || (int)(blockcache->shmem->generation-victim->shmem->generation)<0 ) victim = blockcache;
    }
    if( FD_UNLIKELY( !victim ) ) break;
    ulong need = victim->shmem->pages_cnt-fd_txncache_ram_suffix( tc, victim );
    if( FD_UNLIKELY( tc->shmem->disk_free_cnt<need ) ) {
      if( FD_LIKELY( !swept ) ) { sweep_disk( tc ); swept = 1; continue; }
      break;
    }
    spill_append( tc, victim );
  }
}

void
fd_txncache_insert( fd_txncache_t *       tc,
                    fd_txncache_fork_id_t fork_id,
                    uchar const *         blockhash,
                    uchar const *         txnhash ) {
  fd_rwlock_read( tc->shmem->lock );

  blockcache_t const * fork = &tc->blockcache_pool[ fork_id.val ];
  FD_TEST( fork->shmem->frozen<=1 );
  FD_TEST( fork->shmem->frozen>=0 );
  blockcache_t * blockcache = blockhash_on_fork( tc, fork, blockhash );
  FD_TEST( blockcache );

  for(;;) {
    fd_txncache_txnpage_t * txnpage = fd_txncache_ensure_txnpage( tc, blockcache );
    if( FD_UNLIKELY( !txnpage ) ) {
      /* Because of sizing invariants when creating the structure, it is
         not typically possible to fill it, unless there are stale
         transactions from minority forks that were purged floating
         around, in which case we can purge them here and try again. */
      fd_rwlock_unread( tc->shmem->lock );
      fd_rwlock_write( tc->shmem->lock );
      if( FD_LIKELY( !fd_txncache_ensure_txnpage( tc, blockcache ) ) ) {
        spill_ram( tc, tc->shmem->ram_txnpages/2UL );
        if( FD_UNLIKELY( !fd_txncache_ensure_txnpage( tc, blockcache ) ) ) {
          /* Not out of RAM pages, but out of stale entries or at the
             per-blockhash page limit. */
          compact_disk( tc, blockcache );
          purge_stale( tc );
        }
      }
      fd_rwlock_unwrite( tc->shmem->lock );
      fd_rwlock_read( tc->shmem->lock );
      continue;
    }

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
  FD_TEST( fork->shmem->frozen>=0 );
  blockcache_t const * blockcache = blockhash_on_fork( tc, fork, blockhash );
  FD_TEST( blockcache );
  FD_TEST( blockcache->shmem->frozen==2 );

  int found = 0;

  ulong txnhash_offset = blockcache->shmem->txnhash_offset;
  ulong head_hash = fd_txncache_bucket( tc, txnhash+txnhash_offset );
  fd_txncache_single_txn_t disk_txn[1];
  for( uint head=blockcache->heads[ head_hash ]; head!=UINT_MAX; ) {
    fd_txncache_single_txn_t const * txn = fd_txncache_txn_at( tc, head, disk_txn );

    blockcache_t const * txn_fork = &tc->blockcache_pool[ txn->fork_id.val ];
    int descends = (txn->fork_id.val==fork_id.val || descends_set_test( fork->descends, txn->fork_id.val )) && txn_fork->shmem->frozen>=0 && txn_fork->shmem->generation==txn->generation;
    if( FD_LIKELY( descends && !memcmp( txnhash+txnhash_offset, txn->txnhash, 20UL ) ) ) {
      found = 1;
      break;
    }

    head = txn->blockcache_next;
  }

  fd_rwlock_unread( tc->shmem->lock );
  return found;
}
