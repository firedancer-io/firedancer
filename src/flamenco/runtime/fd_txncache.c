#include "fd_txncache.h"
#include "../fd_rwlock.h"
#include "../types/fd_types_custom.h"
#include "../../util/log/fd_log.h"

/* The number of transactions in each page.  This needs to be high
   enough to amoritze the cost of caller code reserving pages from,
   and returning pages to the pool, but not so high that the memory
   wasted from blockhashes with only one transaction is significant. */

#define FD_TXNCACHE_TXNS_PER_PAGE (16384UL)

/* The maximum distance a transaction blockhash reference can be
   (inclusive).  For example, if no slots were skipped, and the value is
   151, slot 300 is allowed to reference blockhashes from slots
   [149, 300). */
#define MAX_BLOCKHASH_DISTANCE (151UL)

struct single_txn {
  uint  blockcache_next; /* Pointer to the next element in the blockcache hash chain containing this entry from the pool. */

  fd_txncache_fork_id_t fork_id; /* Fork that the transaction was executed on.  A transaction might be in the cache
                                    multiple times if it was executed on multiple forks. */
  uchar txnhash[ 20UL ]; /* The transaction message hash, truncated to 20 bytes.  The hash is not always the first 20
                            bytes, but is 20 bytes starting at some arbitrary offset given by the txnhash_offset value
                            of the containing blockcache entry. */
};

typedef struct single_txn single_txn_t;

struct txnpage {
  ushort       free; /* The number of free txn entries in this page. */
  single_txn_t txns[ FD_TXNCACHE_TXNS_PER_PAGE][ 1 ]; /* The transactions in the page. */
};

typedef struct txnpage txnpage_t;

struct blockcache {
  fd_txncache_fork_id_t parent_id;
  fd_txncache_fork_id_t child_id;
  fd_txncache_fork_id_t sibling_id;

  int frozen;            /* If non-zero, the blockcache is frozen and should not be modified.  This is used to enforce
                            invariants on the caller of the txncache. */

  fd_hash_t blockhash;   /* The blockhash that this entry is for. */
  ulong txnhash_offset;  /* To save memory, the Agave validator decided to truncate the hash of transactions stored in
                            this memory to 20 bytes rather than 32 bytes.  The bytes used are not the first 20 as you
                            might expect, but instead the first 20 starting at some random offset into the transaction
                            hash (starting between 0 and len(hash)-20, a/k/a 44 for signatures, and 12 for hashes).

                            In an unfortunate turn, the offset is also propogated to peers via. snapshot responses,
                            which only communicate the offset and the respective 20 bytes.  To make sure we are
                            deduplicating incoming transactions correctly, we must replicate this system even though
                            it would be easier to just always take the first 20 bytes.  For transactions that we
                            insert into the cache ourselves, we do just always use a key_offset of zero, so this is
                            only nonzero when constructed form a peer snapshot. */

  uint * heads;          /* The hash table for the blockhash.  Each entry is a pointer to the head of a linked list of
                            transactions that reference this blockhash.  As we add transactions to the bucket, the head
                            pointer is updated to the new item, and the new item is pointed to the previous head. */

  ushort pages_cnt;      /* The number of txnpages currently in use to store the transactions in this blockcache. */
  uint * pages;          /* A list of the txnpages containing the transactions for this blockcache. */

  uchar * descends;      /* Each fork can descend from other forks in the txncache, and this array contains one value
                            for each fork in the txncache.  If this fork descends from the fork at position id,
                            then descends[ id ] will be 1, otherwise 1. */

  struct {
    ulong next;
  } pool;

  struct {
    ulong next;
  } slist;

  struct {
    ulong next;
    ulong prev;
  } blockhash_map;

  struct {
    ulong next;
    ulong prev;
  } fork_map;
};

typedef struct blockcache blockcache_t;

#define POOL_NAME  blockcache_pool
#define POOL_T     blockcache_t
#define POOL_IDX_T ulong
#define POOL_NEXT  pool.next
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME               blockhash_map
#define MAP_KEY                blockhash
#define MAP_ELE_T              blockcache_t
#define MAP_KEY_T              fd_hash_t
#define MAP_PREV               blockhash_map.prev
#define MAP_NEXT               blockhash_map.next
#define MAP_KEY_EQ(k0,k1)      fd_hash_eq( k0, k1 )
#define MAP_KEY_HASH(key,seed) (__extension__({ (void)(seed); fd_ulong_load_8_fast( (key)->uc ); }))
#define MAP_OPTIMIZE_RANDOM_ACCESS_REMOVAL 1
#define MAP_MULTI              1
#include "../../util/tmpl/fd_map_chain.c"

#define SLIST_NAME  root_slist
#define SLIST_ELE_T blockcache_t
#define SLIST_IDX_T ulong
#define SLIST_NEXT  slist.next
#include "../../util/tmpl/fd_slist.c"

struct __attribute__((aligned(FD_TXNCACHE_ALIGN))) fd_txncache_private {
  /* The txncache is a concurrent structure and will be accessed by multiple threads
     concurrently.  Insertion and querying only take a read lock as they can be done
     lockless but all other operations will take a write lock internally.

     The lock needs to be aligned to 128 bytes to avoid false sharing with other
     data that might be on the same cache line. */
  fd_rwlock_t lock[ 1 ] __attribute__((aligned(128UL)));

  ulong  txn_per_slot_max;
  ulong  active_slots_max;
  ushort txnpages_per_blockhash_max;

  blockcache_t * blockcache_pool;
  blockhash_map_t * blockhash_map;

  ulong root_cnt;
  root_slist_t root_ll[1]; /* A singly linked list of the forks that are roots of fork chains.  The tail is the
                              most recently added root, the head is the oldest root.  This is used to identify
                              which forks can be pruned when a new root is added. */

  ushort   max_txnpages;
  ushort   txnpages_free_cnt; /* The number of pages in the txnpages that are not currently in use. */
  ushort * txnpages_free;     /* The index in the txnpages array that is free, for each of the free pages. */
  txnpage_t * txnpages;       /* The actual storage for the transactions.  The blockcache points to these
                                 pages when storing transactions.  Transaction are grouped into pages of
                                 size 16384 to make certain allocation and deallocation operations faster
                                 (just the pages are acquired/released, rather than each txn). */

  ulong magic; /* ==FD_TXNCACHE_MAGIC */
};

FD_FN_CONST static ushort
fd_txncache_max_txnpages_per_blockhash( ulong max_active_slots,
                                        ulong max_txn_per_slot ) {
  /* The maximum number of transaction pages we might need to store all
     the transactions that could be seen in a blockhash.

     In the worst case, every transaction in every live bank refers to
     the same blockhash. */

  ulong result = 1UL+(max_txn_per_slot*max_active_slots)/FD_TXNCACHE_TXNS_PER_PAGE;
  if( FD_UNLIKELY( result>USHORT_MAX ) ) return 0;
  return (ushort)result;
}

FD_FN_CONST static ushort
fd_txncache_max_txnpages( ulong max_active_slots,
                          ulong max_txn_per_slot ) {
  /* We need to be able to store potentially every slot that is live
     being completely full of transactions.  This would be

       max_active_slots*max_txn_per_slot

     transactions, except that we are counting pages here, not
     transactions.  It's not enough to divide by the page size, because
     pages might be wasted.  The maximum page wastage occurs when all
     the blockhashes except one have one transaction in them, and the
     remaining blockhash has all other transactions.  In that case, the
     full blockhash needs

       (max_active_slots*max_txn_per_slot)/FD_TXNCACHE_TXNS_PER_PAGE

     pages, and the other blockhashes need 1 page each. */

  ulong result = max_active_slots-1UL+max_active_slots*(1UL+(max_txn_per_slot-1UL)/FD_TXNCACHE_TXNS_PER_PAGE);
  if( FD_UNLIKELY( result>USHORT_MAX ) ) return 0;
  return (ushort)result;
}

FD_FN_CONST ulong
fd_txncache_align( void ) {
  return FD_TXNCACHE_ALIGN;
}

FD_FN_CONST ulong
fd_txncache_footprint( ulong max_live_slots,
                       ulong max_txn_per_slot ) {
  if( FD_UNLIKELY( max_live_slots<1UL ) ) return 0UL;
  if( FD_UNLIKELY( max_txn_per_slot<1UL ) ) return 0UL;

  ulong max_active_slots = MAX_BLOCKHASH_DISTANCE+max_live_slots;
  ulong blockhash_map_chains = fd_ulong_pow2_up( 2UL*max_active_slots );

  /* To save memory, txnpages are referenced as ushort which is enough
     to support mainnet parameters without overflow. */
  ushort max_txnpages = fd_txncache_max_txnpages( max_active_slots, max_txn_per_slot );
  if( FD_UNLIKELY( !max_txnpages ) ) return 0UL;

  ulong max_txnpages_per_blockhash = fd_txncache_max_txnpages_per_blockhash( max_active_slots, max_txn_per_slot );
  if( FD_UNLIKELY( !max_txnpages_per_blockhash ) ) return 0UL;

  ulong l;
  l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, FD_TXNCACHE_ALIGN,       sizeof(fd_txncache_t)                                    );
  l = FD_LAYOUT_APPEND( l, blockhash_map_align(),   blockhash_map_footprint( blockhash_map_chains )          );
  l = FD_LAYOUT_APPEND( l, blockcache_pool_align(), blockcache_pool_footprint( max_active_slots )            );
  l = FD_LAYOUT_APPEND( l, alignof(uint),           max_active_slots*max_txnpages_per_blockhash*sizeof(uint) ); /* blockcache->pages */
  l = FD_LAYOUT_APPEND( l, alignof(uint),           max_active_slots*max_txn_per_slot*sizeof(uint)           ); /* blockcache->heads */
  l = FD_LAYOUT_APPEND( l, alignof(uchar),          max_active_slots*max_active_slots*sizeof(uchar)          ); /* blockcache->descends */
  l = FD_LAYOUT_APPEND( l, alignof(ushort),         max_txnpages*sizeof(ushort)                              ); /* txnpages_free */
  l = FD_LAYOUT_APPEND( l, alignof(txnpage_t),      max_txnpages*sizeof(txnpage_t)                           ); /* txnpages */
  return FD_LAYOUT_FINI( l, FD_TXNCACHE_ALIGN );
}

void *
fd_txncache_new( void * shmem,
                 ulong  max_live_slots,
                 ulong  max_txn_per_slot ) {
  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_txncache_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !max_live_slots ) ) return NULL;
  if( FD_UNLIKELY( !max_txn_per_slot ) ) return NULL;

  ulong max_active_slots = MAX_BLOCKHASH_DISTANCE+max_live_slots;
  ulong blockhash_map_chains = fd_ulong_pow2_up( 2UL*max_active_slots );

  ushort max_txnpages               = fd_txncache_max_txnpages( max_active_slots, max_txn_per_slot );
  ushort max_txnpages_per_blockhash = fd_txncache_max_txnpages_per_blockhash( max_active_slots, max_txn_per_slot );

  if( FD_UNLIKELY( !max_txnpages ) ) return NULL;
  if( FD_UNLIKELY( !max_txnpages_per_blockhash ) ) return NULL;

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_txncache_t * tc          = FD_SCRATCH_ALLOC_APPEND( l, FD_TXNCACHE_ALIGN,       sizeof(fd_txncache_t)                                    );
  void * _blockhash_map       = FD_SCRATCH_ALLOC_APPEND( l, blockhash_map_align(),   blockhash_map_footprint( blockhash_map_chains )          );
  void * _blockhash_pool      = FD_SCRATCH_ALLOC_APPEND( l, blockcache_pool_align(), blockcache_pool_footprint( max_active_slots )            );
  void * _blockcache_pages    = FD_SCRATCH_ALLOC_APPEND( l, alignof(uint),           max_active_slots*max_txnpages_per_blockhash*sizeof(uint) );
  void * _blockcache_heads    = FD_SCRATCH_ALLOC_APPEND( l, alignof(uint),           max_active_slots*max_txn_per_slot*sizeof(uint)           );
  void * _blockcache_descends = FD_SCRATCH_ALLOC_APPEND( l, alignof(uchar),          max_active_slots*max_active_slots*sizeof(uchar)          );
  void * _txnpages_free       = FD_SCRATCH_ALLOC_APPEND( l, alignof(ushort),         max_txnpages*sizeof(ushort)                              );
  void * _txnpages            = FD_SCRATCH_ALLOC_APPEND( l, alignof(txnpage_t),      max_txnpages*sizeof(txnpage_t)                           );

  tc->blockcache_pool = blockcache_pool_join( blockcache_pool_new( _blockhash_pool, max_active_slots ) );
  FD_TEST( tc->blockcache_pool );

  tc->blockhash_map = blockhash_map_join( blockhash_map_new( _blockhash_map, blockhash_map_chains, 0UL /* seed not used */ ) );
  FD_TEST( tc->blockhash_map );

  tc->root_cnt = 0UL;
  FD_TEST( root_slist_join( root_slist_new( tc->root_ll ) ) );

  tc->txnpages_free = _txnpages_free;
  tc->txnpages      = _txnpages;

  tc->lock->value = 0;

  tc->txn_per_slot_max           = max_txn_per_slot;
  tc->active_slots_max           = max_active_slots;
  tc->txnpages_per_blockhash_max = max_txnpages_per_blockhash;

  for( ulong i=0UL; i<max_active_slots; i++ ) {
    tc->blockcache_pool[ i ].pages = (uint *)_blockcache_pages + i*max_txnpages_per_blockhash;
    tc->blockcache_pool[ i ].heads = (uint *)_blockcache_heads + i*max_txn_per_slot;
    tc->blockcache_pool[ i ].descends = (uchar *)_blockcache_descends + i*max_active_slots;
  }

  tc->max_txnpages = max_txnpages;
  tc->txnpages_free_cnt = max_txnpages;
  for( ushort i=0; i<max_txnpages; i++ ) tc->txnpages_free[ i ] = i;

  FD_COMPILER_MFENCE();
  FD_VOLATILE( tc->magic ) = FD_TXNCACHE_MAGIC;
  FD_COMPILER_MFENCE();

  return (void *)tc;
}

fd_txncache_t *
fd_txncache_join( void * shtc ) {
  if( FD_UNLIKELY( !shtc ) ) {
    FD_LOG_WARNING(( "NULL shtc" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shtc, fd_txncache_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shtc" ));
    return NULL;
  }

  fd_txncache_t * tc = (fd_txncache_t *)shtc;

  if( FD_UNLIKELY( tc->magic!=FD_TXNCACHE_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  return tc;
}

static txnpage_t *
fd_txncache_ensure_txnpage( fd_txncache_t * tc,
                            blockcache_t *  blockcache ) {
  ushort page_cnt = blockcache->pages_cnt;
  if( FD_UNLIKELY( page_cnt>tc->txnpages_per_blockhash_max ) ) return NULL;

  if( FD_LIKELY( page_cnt ) ) {
    uint txnpage_idx = blockcache->pages[ page_cnt-1 ];
    ushort txnpage_free = tc->txnpages[ txnpage_idx ].free;
    if( FD_LIKELY( txnpage_free ) ) return &tc->txnpages[ txnpage_idx ];
  }

  if( FD_UNLIKELY( page_cnt==tc->txnpages_per_blockhash_max ) ) return NULL;
  if( FD_LIKELY( FD_ATOMIC_CAS( &blockcache->pages[ page_cnt ], UINT_MAX, UINT_MAX-1UL )==UINT_MAX ) ) {
    ulong txnpages_free_cnt = tc->txnpages_free_cnt;
    for(;;) {
      if( FD_UNLIKELY( !txnpages_free_cnt ) ) return NULL;
      ulong old_txnpages_free_cnt = FD_ATOMIC_CAS( &tc->txnpages_free_cnt, (ushort)txnpages_free_cnt, (ushort)(txnpages_free_cnt-1UL) );
      if( FD_LIKELY( old_txnpages_free_cnt==txnpages_free_cnt ) ) break;
      txnpages_free_cnt = old_txnpages_free_cnt;
      FD_SPIN_PAUSE();
    }

    ushort txnpage_idx = tc->txnpages_free[ txnpages_free_cnt-1UL ];
    // FD_TEST( txnpage_idx<tc->max_txnpages );
    txnpage_t * txnpage = &tc->txnpages[ txnpage_idx ];
    txnpage->free = FD_TXNCACHE_TXNS_PER_PAGE;
    FD_COMPILER_MFENCE();
    blockcache->pages[ page_cnt ] = txnpage_idx;
    FD_COMPILER_MFENCE();
    blockcache->pages_cnt = (ushort)(page_cnt+1);
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
fd_txncache_insert_txn( fd_txncache_t *       tc,
                        blockcache_t *        blockcache,
                        txnpage_t *           txnpage,
                        fd_txncache_fork_id_t fork_id,
                        uchar const *         txnhash ) {
  ulong txnpage_idx = (ulong)(txnpage - tc->txnpages);

  for(;;) {
    ushort txnpage_free = txnpage->free;
    if( FD_UNLIKELY( !txnpage_free ) ) return 0;
    if( FD_UNLIKELY( FD_ATOMIC_CAS( &txnpage->free, txnpage_free, txnpage_free-1UL )!=txnpage_free ) ) {
      FD_SPIN_PAUSE();
      continue;
    }

    ulong txn_idx = FD_TXNCACHE_TXNS_PER_PAGE-txnpage_free;
    ulong txnhash_offset = blockcache->txnhash_offset;
    memcpy( txnpage->txns[ txn_idx ]->txnhash, txnhash+txnhash_offset, 20UL );
    txnpage->txns[ txn_idx ]->fork_id = fork_id;
    FD_COMPILER_MFENCE();

    ulong txn_bucket = FD_LOAD( ulong, txnhash+txnhash_offset )%tc->txn_per_slot_max;
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
                          fd_txncache_fork_id_t parent_fork_id,
                          ulong                 txnhash_offset,
                          uchar const *         blockhash ) {
  fd_rwlock_write( tc->lock );

  FD_TEST( blockcache_pool_free( tc->blockcache_pool ) );
  blockcache_t * fork = blockcache_pool_ele_acquire( tc->blockcache_pool );

  ulong idx = blockcache_pool_idx( tc->blockcache_pool, fork );
  fd_txncache_fork_id_t fork_id = { .val = (ushort)idx };

  fork->child_id = (fd_txncache_fork_id_t){ .val = USHORT_MAX };

  if( FD_LIKELY( parent_fork_id.val==USHORT_MAX ) ) {
    FD_TEST( blockcache_pool_free( tc->blockcache_pool )==blockcache_pool_max( tc->blockcache_pool )-1UL );
    fork->parent_id  = (fd_txncache_fork_id_t){ .val = USHORT_MAX };
    fork->sibling_id = (fd_txncache_fork_id_t){ .val = USHORT_MAX };

    fd_memset( fork->descends, 0, tc->active_slots_max*sizeof(uchar) );
    root_slist_ele_push_tail( tc->root_ll, fork, tc->blockcache_pool );
  } else {
    blockcache_t * parent = blockcache_pool_ele( tc->blockcache_pool, parent_fork_id.val );
    FD_TEST( parent );
    parent->frozen = 1;
    fork->sibling_id = parent->child_id;
    fork->parent_id  = parent_fork_id;
    parent->child_id = fork_id;

    fd_memcpy( fork->descends, parent->descends, tc->active_slots_max*sizeof(uchar) );
    fork->descends[ parent_fork_id.val ] = 1;
  }

  fork->frozen = 0;
  memcpy( fork->blockhash.uc, blockhash, 32UL );
  memset( fork->heads, 0xFF, tc->txn_per_slot_max*sizeof(uint) );
  fork->pages_cnt      = 0;
  fork->txnhash_offset = txnhash_offset;
  memset( fork->pages, 0xFF, tc->txnpages_per_blockhash_max*sizeof(uint) );

  blockhash_map_ele_insert( tc->blockhash_map, fork, tc->blockcache_pool );

  fd_rwlock_unwrite( tc->lock );
  return fork_id;
}

static inline void
remove_blockcache( fd_txncache_t * tc,
                   blockcache_t *  blockcache ) {
  memcpy( tc->txnpages_free+tc->txnpages_free_cnt, blockcache->pages, blockcache->pages_cnt*sizeof(ushort) );
  tc->txnpages_free_cnt = (ushort)(tc->txnpages_free_cnt+blockcache->pages_cnt);

  ulong idx = blockcache_pool_idx( tc->blockcache_pool, blockcache );
  for( ulong i=0UL; i<tc->active_slots_max; i++ ) blockcache_pool_ele( tc->blockcache_pool, i )->descends[ idx ] = 0;

  blockhash_map_ele_remove_fast( tc->blockhash_map, blockcache, tc->blockcache_pool );
  blockcache_pool_ele_release( tc->blockcache_pool, (blockcache_t *)blockcache );
}

static inline void
remove_children( fd_txncache_t *      tc,
                 blockcache_t const * fork,
                 blockcache_t const * except ) {
  fd_txncache_fork_id_t sibling_idx = fork->child_id;
  while( sibling_idx.val!=USHORT_MAX ) {
    blockcache_t * sibling = blockcache_pool_ele( tc->blockcache_pool, sibling_idx.val );
    FD_TEST( sibling );

    sibling_idx = sibling->sibling_id;
    if( FD_UNLIKELY( sibling==except ) ) continue;

    remove_children( tc, sibling, except );
    remove_blockcache( tc, sibling );
  }
}

void
fd_txncache_advance_root( fd_txncache_t *       tc,
                          fd_txncache_fork_id_t fork_id ) {
  fd_rwlock_write( tc->lock );

  blockcache_t * fork = blockcache_pool_ele( tc->blockcache_pool, fork_id.val );
  FD_TEST( fork );

  blockcache_t * parent_fork = blockcache_pool_ele( tc->blockcache_pool, fork->parent_id.val );
  FD_TEST( root_slist_ele_peek_tail( tc->root_ll, tc->blockcache_pool )==parent_fork );

  /* When a fork is rooted, any competing forks can be immediately
     removed as they will not be needed again.  This includes child
     forks of the pruned siblings as well. */
  remove_children( tc, parent_fork, fork );

  /* Now, the earliest known rooted fork can likely be removed since its
     blockhashes cannot be referenced anymore (they are older than 151
     blockhashes away). */
  tc->root_cnt++;
  root_slist_ele_push_tail( tc->root_ll, fork, tc->blockcache_pool );
  if( FD_LIKELY( tc->root_cnt>MAX_BLOCKHASH_DISTANCE ) ) {
    blockcache_t * old_root = root_slist_ele_pop_head( tc->root_ll, tc->blockcache_pool );
    FD_TEST( old_root );

    root_slist_ele_peek_head( tc->root_ll, tc->blockcache_pool )->parent_id.val = USHORT_MAX;

    remove_blockcache( tc, old_root );
    tc->root_cnt--;
  }

  fd_rwlock_unwrite( tc->lock );
}

static inline blockcache_t *
blockhash_on_fork( fd_txncache_t *      tc,
                   blockcache_t const * fork,
                   uchar const *        blockhash ) {
  blockcache_t const * candidate = blockhash_map_ele_query( tc->blockhash_map, fd_type_pun_const( blockhash ), NULL, tc->blockcache_pool );
  FD_TEST( candidate );

  while( candidate ) {
    ulong candidate_idx = blockcache_pool_idx( tc->blockcache_pool, candidate );
    if( FD_LIKELY( fork->descends[ candidate_idx ] ) ) return (blockcache_t*)candidate;
    candidate = blockhash_map_ele_next_const( candidate, NULL, tc->blockcache_pool );
  }
  return NULL;
}

void
fd_txncache_insert( fd_txncache_t *       tc,
                    fd_txncache_fork_id_t fork_id,
                    uchar const *         blockhash,
                    uchar const *         txnhash ) {
  fd_rwlock_read( tc->lock );

  blockcache_t const * fork = blockcache_pool_ele( tc->blockcache_pool, fork_id.val );
  FD_TEST( !fork->frozen );
  blockcache_t * blockcache = blockhash_on_fork( tc, fork, blockhash );
  FD_TEST( blockcache );

  for(;;) {
    txnpage_t * txnpage = fd_txncache_ensure_txnpage( tc, blockcache );
    FD_TEST( txnpage );

    int success = fd_txncache_insert_txn( tc, blockcache, txnpage, fork_id, txnhash );
    if( FD_LIKELY( success ) ) break;

    FD_SPIN_PAUSE();
  }

  fd_rwlock_unread( tc->lock );
}

int
fd_txncache_query( fd_txncache_t *       tc,
                   fd_txncache_fork_id_t fork_id,
                   uchar const *         blockhash,
                   uchar const *         txnhash ) {
  fd_rwlock_read( tc->lock );

  blockcache_t const * fork = blockcache_pool_ele( tc->blockcache_pool, fork_id.val );
  blockcache_t const * blockcache = blockhash_on_fork( tc, fork, blockhash );
  FD_TEST( blockcache );

  int found = 0;

  ulong txnhash_offset = blockcache->txnhash_offset;
  ulong head_hash = FD_LOAD( ulong, txnhash+txnhash_offset ) % tc->txn_per_slot_max;
  for( uint head=blockcache->heads[ head_hash ]; head!=UINT_MAX; head=tc->txnpages[ head/FD_TXNCACHE_TXNS_PER_PAGE ].txns[ head%FD_TXNCACHE_TXNS_PER_PAGE ]->blockcache_next ) {
    single_txn_t * txn = tc->txnpages[ head/FD_TXNCACHE_TXNS_PER_PAGE ].txns[ head%FD_TXNCACHE_TXNS_PER_PAGE ];

    int descends = txn->fork_id.val==fork_id.val || fork->descends[ txn->fork_id.val ];
    if( FD_LIKELY( descends && !memcmp( txnhash+txnhash_offset, txn->txnhash, 20UL ) ) ) {
      found = 1;
      break;
    }
  }

  fd_rwlock_unread( tc->lock );
  return found;
}
