#include "fd_txncache.h"


#define SORT_NAME        sort_slot_ascend
#define SORT_KEY_T       ulong
#define SORT_BEFORE(a,b) (a)<(b)
#include "../../util/tmpl/fd_sort.c"

/* The number of transactions in each page.  This needs to be high
   enough to amoritze the cost of caller code reserving pages from,
   and returning pages to the pool, but not so high that the memory
   wasted from blockhashes with only one transaction is significant. */

#define FD_TXNCACHE_TXNS_PER_PAGE (16384UL)

/* The number of unique entries in the hash lookup table for each
   blockhash.  A higher value here uses more memory but enables faster
   lookups. */

#define FD_TXNCACHE_BLOCKCACHE_MAP_CNT (524288UL)

/* The number of unique entries in the hash lookup table for each
   (slot, blockhash).  This prevents all the entries needing to be in
   one slotcache list, so insertions can happen concurrently. */

#define FD_TXNCACHE_SLOTCACHE_MAP_CNT (1024UL)

/* Value for an empty blockcache `max_slot` or empty slotcache
  `slot` entry. When the entries are set to this value, we can insert
  to the entry, but stop iterating while running queries. */

#define FD_TXNCACHE_EMPTY_ENTRY (ULONG_MAX)

/* Value for a deleted cache entry. We can insert to such entries,
   and keep iterating while running queries. */

#define FD_TXNCACHE_TOMBSTONE_ENTRY (ULONG_MAX-1UL)

/* Placeholder value used for critical sections. */
#define FD_TXNCACHE_TEMP_ENTRY (ULONG_MAX-2UL)

struct fd_txncache_private_txn {
  uint  blockcache_next; /* Pointer to the next element in the blockcache hash chain containing this entry from the pool. */
  uint  slotblockcache_next;  /* Pointer to the next element in the slotcache hash chain containing this entry from the pool. */

  ulong slot;            /* Slot that the transaction was executed.  A transaction might be in the cache
                            multiple times if it was executed in a different slot on different forks.  The
                            same slot will not appear multiple times however. */
  uchar txnhash[ 20 ];   /* The transaction hash, truncated to 20 bytes.  The hash is not always the first 20
                            bytes, but is 20 bytes starting at some arbitrary offset given by the key_offset value
                            of the containing by_blockhash entry. */
  uchar result;          /* The result of executing the transaction. This is the discriminant of the transaction
                            result type. 0 means success. */
};

typedef struct fd_txncache_private_txn fd_txncache_private_txn_t;

struct fd_txncache_private_txnpage {
  ushort                    free; /* The number of free txn entries in this page. */
  fd_txncache_private_txn_t txns[ FD_TXNCACHE_TXNS_PER_PAGE][ 1 ]; /* The transactions in the page. */
};

typedef struct fd_txncache_private_txnpage fd_txncache_private_txnpage_t;

struct fd_txncache_private_blockcache {
  uchar blockhash[ 32 ]; /* The actual blockhash of these transactions. */
  ulong max_slot;     /* The lowest slot we have seen that contains a transaction referencing this blockhash.
                            The blockhash entry will not be purged until the lowest rooted slot is at least 150
                            slots higher than this. */
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

  uint  heads[ FD_TXNCACHE_BLOCKCACHE_MAP_CNT ]; /* The hash table for the blockhash.  Each entry is a pointer to the head of a
                                                    linked list of transactions that reference this blockhash.  As we add
                                                    transactions to the bucket, the head pointer is updated to the new item, and
                                                    the new item is pointed to the previous head. */

  ushort pages_cnt;      /* The number of txnpages currently in use to store the transactions in this blockcache. */
  uint * pages;          /* A list of the txnpages containing the transactions for this blockcache. */
};

typedef struct fd_txncache_private_blockcache fd_txncache_private_blockcache_t;

struct fd_txncache_private_slotblockcache {
  uchar blockhash[ 32 ]; /* The actual blockhash of these transactions. */
  ulong txnhash_offset;  /* As described above. */
  uint  heads[ FD_TXNCACHE_SLOTCACHE_MAP_CNT ]; /* A map of the head of a linked list of tansactions in this slot and blockhash */
};

typedef struct fd_txncache_private_slotblockcache fd_txncache_private_slotblockcache_t;

struct fd_txncache_private_slotcache {
  ulong                                slot; /* The slot that this slotcache is for. */
  fd_txncache_private_slotblockcache_t blockcache[ 300UL ];
};

typedef struct fd_txncache_private_slotcache fd_txncache_private_slotcache_t;

struct __attribute__((aligned(FD_TXNCACHE_ALIGN))) fd_txncache_private {
  fd_rwlock_t lock[ 1 ]; /* The txncache is a concurrent structure and will be accessed by multiple threads
                            concurrently.  Insertion and querying only take a read lock as they can be done
                            lockless but all other operations will take a write lock internally. */

  ulong  root_slots_max;
  ulong  live_slots_max;
  ushort txnpages_per_blockhash_max;
  uint   txnpages_max;

  ulong   root_slots_cnt; /* The number of root slots being tracked in the below array. */
  ulong   root_slots_off; /* The highest N slots that have been rooted.  These slots are
                             used to determine which transactions should be kept around to
                             be queried and served to snapshot requests.  The actual
                             footprint for this data (and other data below) are declared
                             immediately following the struct.  I.e. these pointers point to
                             memory not far after the struct. */

  ulong blockcache_off; /* The actual cache of transactions.  This is a linear probed hash
                           table that maps blockhashes to the transactions that reference them.
                           The depth of the hash table is live_slots_max, since this is the
                           maximum number of blockhashes that can be alive.  The loading factor
                           if they were all alive would be 1.0, but this is rare because we
                           will almost never fork repeatedly to hit this limit.  These
                           blockcaches are just pointers to pages from the txnpages below, so
                           they don't take up much memory. */

  ulong slotcache_off; /* The cache of transactions by slot instead of by blockhash, so we
                          can quickly serialize the slot deltas for the root slots which are
                          served to peers in snapshots.  Similar to the above, it uses the
                          same underlying transaction storage, but different lookup tables. */

  uint     txnpages_free_cnt; /* The number of pages in the txnpages that are not currently in use. */
  ulong    txnpages_free_off; /* The index in the txnpages array that is free, for each of the free pages. */

  ulong    txnpages_off; /* The actual storage for the transactions.  The blockcache points to these
                            pages when storing transactions.  Transaction are grouped into pages of
                            size 16384 to make certain allocation and deallocation operations faster
                            (just the pages are acquired/released, rather than each txn). */

  ulong blockcache_pages_off;
  ulong magic; /* ==FD_TXNCACHE_MAGIC */
};

FD_FN_PURE static ulong *
fd_txncache_get_root_slots( fd_txncache_t * tc ) {
  return (ulong *)( (uchar *)tc + tc->root_slots_off );
}

FD_FN_PURE static fd_txncache_private_blockcache_t *
fd_txncache_get_blockcache( fd_txncache_t * tc ) {
  return (fd_txncache_private_blockcache_t *)( (uchar *)tc + tc->blockcache_off );
}

FD_FN_PURE static fd_txncache_private_blockcache_t *
fd_txncache_get_blockcache_const( fd_txncache_t const * tc ) {
  return (fd_txncache_private_blockcache_t *)( (uchar const *)tc + tc->blockcache_off );
}

FD_FN_PURE static fd_txncache_private_slotcache_t *
fd_txncache_get_slotcache( fd_txncache_t * tc ) {
  return (fd_txncache_private_slotcache_t *)( (uchar *)tc + tc->slotcache_off );
}

FD_FN_PURE static fd_txncache_private_slotcache_t *
fd_txncache_get_slotcache_const( fd_txncache_t const * tc ) {
  return (fd_txncache_private_slotcache_t *)( (uchar const *)tc + tc->slotcache_off );
}

FD_FN_PURE static uint *
fd_txncache_get_txnpages_free( fd_txncache_t * tc ) {
  return (uint *)( (uchar *)tc + tc->txnpages_free_off );
}

FD_FN_PURE static fd_txncache_private_txnpage_t *
fd_txncache_get_txnpages( fd_txncache_t * tc ) {
  return (fd_txncache_private_txnpage_t *)( (uchar *)tc + tc->txnpages_off );
}

FD_FN_CONST static ushort
fd_txncache_max_txnpages_per_blockhash( ulong max_txn_per_slot ) {
  /* The maximum number of transaction pages we might need to store all
     the transactions that could be seen in a blockhash.

     In the worst case, every transaction in every slot refers to
     the same blockhash for as long as it is possible (150 slots
     following the slot where the blockhash is produced).  So there
     could be up to

        524,288 * 150 = 78,643,200

     Note that the blockcaches store txns for forks, and the same txn
     might appear multiple times in one block, but if there's a fork,
     the fork has to have skipped slots (had 0 txns in them), so it
     cannot cause this limit to go higher.

     Transactions referenced by a particular blockhash.
     Transactions are stored in pages of 16,384, so we might need up
     to 4,800 of these pages to store all the transactions in a
     slot. */

  ulong result = 1UL+(max_txn_per_slot*150UL-1UL)/FD_TXNCACHE_TXNS_PER_PAGE;
  if( FD_UNLIKELY( result>USHORT_MAX ) ) return 0;
  return (ushort)result;
}

FD_FN_CONST static uint
fd_txncache_max_txnpages( ulong max_live_slots,
                          ulong max_txn_per_slot ) {
  /* We need to be able to store potentially every slot that is live
     being completely full of transactions.  This would be

       max_live_slots*max_txn_per_slot

     transactions, except that we are counting pages here, not
     transactions.  It's not enough to divide by the page size, because
     pages might be wasted.  The maximum page wastage occurs when all
     the blockhashes except one have one transaction in them, and the
     remaining blockhash has all other transactions.  In that case, the
     full blockhash needs

       (max_live_slots*max_txn_per_slot)/FD_TXNCACHE_TXNS_PER_PAGE

     pages, and the other blockhashes need 1 page each. */

  ulong result = max_live_slots-1UL+max_live_slots*(1UL+(max_txn_per_slot-1UL)/FD_TXNCACHE_TXNS_PER_PAGE);
  if( FD_UNLIKELY( result>UINT_MAX ) ) return 0;
  return (uint)result;
}

FD_FN_CONST ulong
fd_txncache_align( void ) {
  return FD_TXNCACHE_ALIGN;
}

FD_FN_CONST ulong
fd_txncache_footprint( ulong max_rooted_slots,
                       ulong max_live_slots,
                       ulong max_txn_per_slot ) {
  if( FD_UNLIKELY( max_rooted_slots<1UL || max_live_slots<1UL ) ) return 0UL;
  if( FD_UNLIKELY( max_live_slots<max_rooted_slots ) ) return 0UL;
  if( FD_UNLIKELY( max_txn_per_slot<1UL ) ) return 0UL;
  if( FD_UNLIKELY( !fd_ulong_is_pow2( max_live_slots ) || !fd_ulong_is_pow2( max_txn_per_slot ) ) ) return 0UL;

  /* To save memory, txnpages are referenced as uint which is enough
     to support mainnet parameters without overflow. */
  uint max_txnpages = fd_txncache_max_txnpages( max_live_slots, max_txn_per_slot );
  if( FD_UNLIKELY( !max_txnpages ) ) return 0UL;

  ulong max_txnpages_per_blockhash = fd_txncache_max_txnpages_per_blockhash( max_txn_per_slot );
  if( FD_UNLIKELY( !max_txnpages_per_blockhash ) ) return 0UL;

  ulong l;
  l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, FD_TXNCACHE_ALIGN,                         sizeof(fd_txncache_t)                                   );
  l = FD_LAYOUT_APPEND( l, alignof(ulong),                            max_rooted_slots*sizeof(ulong)                          ); /* root_slots */
  l = FD_LAYOUT_APPEND( l, alignof(fd_txncache_private_blockcache_t), max_live_slots*sizeof(fd_txncache_private_blockcache_t) ); /* blockcache */
  l = FD_LAYOUT_APPEND( l, alignof(uint),                             max_live_slots*max_txnpages_per_blockhash*sizeof(uint)  ); /* blockcache->pages */
  l = FD_LAYOUT_APPEND( l, alignof(fd_txncache_private_slotcache_t),  max_live_slots*sizeof(fd_txncache_private_slotcache_t ) ); /* slotcache */
  l = FD_LAYOUT_APPEND( l, alignof(uint),                             max_txnpages                                            ); /* txnpages_free */
  l = FD_LAYOUT_APPEND( l, alignof(fd_txncache_private_txnpage_t),    max_txnpages*sizeof(fd_txncache_private_txnpage_t)      ); /* txnpages */
  return FD_LAYOUT_FINI( l, FD_TXNCACHE_ALIGN );
}

void *
fd_txncache_new( void * shmem,
                 ulong  max_rooted_slots,
                 ulong  max_live_slots,
                 ulong  max_txn_per_slot ) {
  fd_txncache_t * tc = (fd_txncache_t *)shmem;

  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_txncache_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned shmem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !max_rooted_slots ) ) return NULL;
  if( FD_UNLIKELY( !max_live_slots ) ) return NULL;
  if( FD_UNLIKELY( max_live_slots<max_rooted_slots ) ) return NULL;
  if( FD_UNLIKELY( !max_txn_per_slot ) ) return NULL;
  if( FD_UNLIKELY( !fd_ulong_is_pow2( max_live_slots ) || !fd_ulong_is_pow2( max_txn_per_slot ) ) ) return NULL;

  uint max_txnpages                 = fd_txncache_max_txnpages( max_live_slots, max_txn_per_slot );
  ushort max_txnpages_per_blockhash = fd_txncache_max_txnpages_per_blockhash( max_txn_per_slot );

  if( FD_UNLIKELY( !max_txnpages ) ) return NULL;
  if( FD_UNLIKELY( !max_txnpages_per_blockhash ) ) return NULL;

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_txncache_t * txncache = FD_SCRATCH_ALLOC_APPEND( l,  FD_TXNCACHE_ALIGN,                        sizeof(fd_txncache_t)                                   );
  void * _root_slots       = FD_SCRATCH_ALLOC_APPEND( l, alignof(ulong),                            max_rooted_slots*sizeof(ulong)                          );
  void * _blockcache       = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_txncache_private_blockcache_t), max_live_slots*sizeof(fd_txncache_private_blockcache_t) );
  void * _blockcache_pages = FD_SCRATCH_ALLOC_APPEND( l, alignof(uint),                             max_live_slots*max_txnpages_per_blockhash*sizeof(uint)  );
  void * _slotcache        = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_txncache_private_slotcache_t),  max_live_slots*sizeof(fd_txncache_private_slotcache_t ) );
  void * _txnpages_free    = FD_SCRATCH_ALLOC_APPEND( l, alignof(uint),                             max_txnpages                                            );
  void * _txnpages         = FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_txncache_private_txnpage_t),    max_txnpages*sizeof(fd_txncache_private_txnpage_t)      );

  /* We calculate and store the offsets for these allocations. */
  txncache->root_slots_off       = (ulong)_root_slots - (ulong)txncache;
  txncache->blockcache_off       = (ulong)_blockcache - (ulong)txncache;
  txncache->slotcache_off        = (ulong)_slotcache - (ulong)txncache;
  txncache->txnpages_free_off    = (ulong)_txnpages_free - (ulong)txncache;
  txncache->txnpages_off         = (ulong)_txnpages - (ulong)txncache;
  txncache->blockcache_pages_off = (ulong)_blockcache_pages - (ulong)txncache;

  tc->lock->value = 0;
  tc->root_slots_cnt = 0UL;

  tc->root_slots_max             = max_rooted_slots;
  tc->live_slots_max             = max_live_slots;
  tc->txnpages_per_blockhash_max = max_txnpages_per_blockhash;
  tc->txnpages_max               = max_txnpages;

  ulong * root_slots = (ulong *)_root_slots;
  memset( root_slots, 0xFF, max_rooted_slots*sizeof(ulong) );

  fd_txncache_private_blockcache_t * blockcache = (fd_txncache_private_blockcache_t *)_blockcache;
  fd_txncache_private_slotcache_t  * slotcache  = (fd_txncache_private_slotcache_t *)_slotcache;
  for( ulong i=0UL; i<max_live_slots; i++ ) {
    blockcache[ i ].lowest_slot = FD_TXNCACHE_EMPTY_ENTRY;
    slotcache[ i ].slot         = FD_TXNCACHE_EMPTY_ENTRY;
  }

  tc->txnpages_free_cnt = max_txnpages;
  uint * txnpages_free  = _txnpages_free;
  for( uint i=0; i<max_txnpages; i++ ) txnpages_free[ i ] = i;

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

  uchar * base = (uchar *)tc;
  fd_txncache_private_blockcache_t * blockcache = (fd_txncache_private_blockcache_t *)( base + tc->blockcache_off );

  void * _blockcache_pages = base + tc->blockcache_pages_off;
  for( ulong i=0UL; i<tc->live_slots_max; i++ ) {
    blockcache[ i ].pages       = (uint *)_blockcache_pages + i*tc->txnpages_per_blockhash_max;
  }
  return tc;
}

void *
fd_txncache_leave( fd_txncache_t * tc ) {
  if( FD_UNLIKELY( !tc ) ) {
    FD_LOG_WARNING(( "NULL tc" ));
    return NULL;  }

  return (void *)tc;
}

void *
fd_txncache_delete( void * shtc ) {
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

  FD_COMPILER_MFENCE();
  FD_VOLATILE( tc->magic ) = 0UL;
  FD_COMPILER_MFENCE();

  return (void *)tc;
}

static void
fd_txncache_remove_blockcache_idx( fd_txncache_t * tc,
                                   ulong idx ) {
  fd_txncache_private_blockcache_t * blockcache = fd_txncache_get_blockcache( tc );
  uint * txnpages_free = fd_txncache_get_txnpages_free( tc );
  blockcache[ idx ].lowest_slot = FD_TXNCACHE_TOMBSTONE_ENTRY;
  memcpy( txnpages_free+tc->txnpages_free_cnt, blockcache[ idx ].pages, blockcache[ idx ].pages_cnt*sizeof(ushort) );
  tc->txnpages_free_cnt += blockcache[ idx ].pages_cnt;
}

static void
fd_txncache_remove_slotcache_idx( fd_txncache_t * tc,
                                  ulong idx ) {
  fd_txncache_private_slotcache_t * slotcache = fd_txncache_get_slotcache( tc );
  slotcache[ idx ].slot = FD_TXNCACHE_TOMBSTONE_ENTRY;
}

static void
fd_txncache_purge_slot( fd_txncache_t * tc,
                        ulong           slot ) {
  fd_txncache_private_blockcache_t * blockcache = fd_txncache_get_blockcache( tc );
  for( ulong i=0UL; i<tc->live_slots_max; i++ ) {
    if( FD_LIKELY( blockcache[ i ].lowest_slot==FD_TXNCACHE_EMPTY_ENTRY || blockcache[ i ].lowest_slot==FD_TXNCACHE_TOMBSTONE_ENTRY || (blockcache[ i ].lowest_slot+150UL)>slot ) ) continue;
    fd_txncache_remove_blockcache_idx( tc, i );
  }

  fd_txncache_private_slotcache_t * slotcache = fd_txncache_get_slotcache( tc );
  for( ulong i=0UL; i<tc->live_slots_max; i++ ) {
    if( FD_LIKELY( slotcache[ i ].slot==FD_TXNCACHE_EMPTY_ENTRY || slotcache[ i ].slot==FD_TXNCACHE_TOMBSTONE_ENTRY || slotcache[ i ].slot>slot ) ) continue;
    fd_txncache_remove_slotcache_idx( tc, i );
  }
}

void
fd_txncache_register_root_slot( fd_txncache_t * tc,
                                ulong           slot ) {
  fd_rwlock_write( tc->lock );

  ulong * root_slots = fd_txncache_get_root_slots( tc );
  ulong idx;
  for( idx=0UL; idx<tc->root_slots_cnt; idx++ ) {
    if( FD_UNLIKELY( root_slots[ idx ]==slot ) ) goto unlock;
    if( FD_UNLIKELY( root_slots[ idx ]>slot ) ) break;
  }

  if( FD_UNLIKELY( tc->root_slots_cnt>=tc->root_slots_max ) ) {
    if( FD_LIKELY( idx ) ) {
      fd_txncache_purge_slot( tc, root_slots[ 0 ] );
      memmove( root_slots, root_slots+1UL, (idx-1UL)*sizeof(ulong) );
      root_slots[ (idx-1UL) ] = slot;
    } else {
      fd_txncache_purge_slot( tc, slot );
    }
  } else {
    if( FD_UNLIKELY( idx<tc->root_slots_cnt ) ) {
      memmove( root_slots+idx+1UL, root_slots+idx, (tc->root_slots_cnt-idx)*sizeof(ulong) );
    }
    root_slots[ idx ] = slot;
    tc->root_slots_cnt++;
  }

unlock:
  fd_rwlock_unwrite( tc->lock );
}

void
fd_txncache_root_slots( fd_txncache_t * tc,
                        ulong *         out_slots ) {
  fd_rwlock_write( tc->lock );
  ulong * root_slots = fd_txncache_get_root_slots( tc );
  memcpy( out_slots, root_slots, tc->root_slots_max*sizeof(ulong) );
  fd_rwlock_unwrite( tc->lock );
}

#define FD_TXNCACHE_FIND_FOUND      (0)
#define FD_TXNCACHE_FIND_FOUNDEMPTY (1)
#define FD_TXNCACHE_FIND_FULL       (2)

static int
fd_txncache_find_blockhash( fd_txncache_t const *               tc,
                            uchar const                         blockhash[ static 32 ],
                            uint                                is_insert,
                            fd_txncache_private_blockcache_t ** out_blockcache ) {
  ulong hash = FD_LOAD( ulong, blockhash );
  fd_txncache_private_blockcache_t * tc_blockcache = fd_txncache_get_blockcache_const( tc );
  for( ulong i=0UL; i<tc->live_slots_max; i++ ) {
    ulong blockcache_idx = (hash+i)%tc->live_slots_max;
    fd_txncache_private_blockcache_t * blockcache = &tc_blockcache[ blockcache_idx ];
    if( FD_UNLIKELY( blockcache->lowest_slot==FD_TXNCACHE_EMPTY_ENTRY ) ) {
      *out_blockcache = blockcache;
      return FD_TXNCACHE_FIND_FOUNDEMPTY;
    } else if ( blockcache->max_slot==FD_TXNCACHE_TOMBSTONE_ENTRY) {
      if( is_insert ) {
        *out_blockcache = blockcache;
        return FD_TXNCACHE_FIND_FOUNDEMPTY;
      }
      continue;
    }
    while( FD_UNLIKELY( blockcache->max_slot==FD_TXNCACHE_TEMP_ENTRY ) ) {
      FD_SPIN_PAUSE();
    }
    FD_COMPILER_MFENCE(); /* Prevent reordering of the blockhash read to before the atomic lock
                             (highest_slot) has been fully released by the writer. */
    if( FD_LIKELY( !memcmp( blockcache->blockhash, blockhash, 32UL ) ) ) {
      *out_blockcache = blockcache;
      return FD_TXNCACHE_FIND_FOUND;
    }
  }
  return FD_TXNCACHE_FIND_FULL;
}

static int
fd_txncache_find_slot( fd_txncache_t const *              tc,
                       ulong                              slot,
                       uint                               is_insert,
                       fd_txncache_private_slotcache_t ** out_slotcache ) {
  fd_txncache_private_slotcache_t * tc_slotcache = fd_txncache_get_slotcache_const( tc );
  for( ulong i=0UL; i<tc->live_slots_max; i++ ) {
    ulong slotcache_idx = (slot+i)%tc->live_slots_max;
    fd_txncache_private_slotcache_t * slotcache = &tc_slotcache[ slotcache_idx ];
    if( FD_UNLIKELY( slotcache->slot==FD_TXNCACHE_EMPTY_ENTRY ) ) {
      *out_slotcache = slotcache;
      return FD_TXNCACHE_FIND_FOUNDEMPTY;
    } else if( FD_UNLIKELY( slotcache->slot==FD_TXNCACHE_TOMBSTONE_ENTRY ) ) {
      if( is_insert ) {
        *out_slotcache = slotcache;
        return FD_TXNCACHE_FIND_FOUNDEMPTY;
      }
      continue;
    }
    while( FD_UNLIKELY( slotcache->slot==FD_TXNCACHE_TEMP_ENTRY ) ) {
      FD_SPIN_PAUSE();
    }
    FD_COMPILER_MFENCE(); /* Prevent reordering of the slot read to before the atomic lock
                             (slot) has been fully released by the writer. */
    if( FD_LIKELY( slotcache->slot==slot ) ) {
      *out_slotcache = slotcache;
      return FD_TXNCACHE_FIND_FOUND;
    }
  }
  return FD_TXNCACHE_FIND_FULL;
}

static int
fd_txncache_find_slot_blockhash( fd_txncache_private_slotcache_t *       slotcache,
                                 uchar const                             blockhash[ static 32 ],
                                 fd_txncache_private_slotblockcache_t ** out_slotblockcache ) {
  ulong hash = FD_LOAD( ulong, blockhash );
  for( ulong i=0UL; i<300UL; i++ ) {
    ulong slotblockcache_idx = (hash+i)%300UL;
    fd_txncache_private_slotblockcache_t * slotblockcache = &slotcache->blockcache[ slotblockcache_idx ];
    if( FD_UNLIKELY( slotblockcache->txnhash_offset==ULONG_MAX ) ) {
      *out_slotblockcache = slotblockcache;
      return FD_TXNCACHE_FIND_FOUNDEMPTY;
    }
    while( FD_UNLIKELY( slotblockcache->txnhash_offset==ULONG_MAX-1UL ) ) {
      FD_SPIN_PAUSE();
    }
    FD_COMPILER_MFENCE(); /* Prevent reordering of the blockhash read to before the atomic lock
                             (txnhash_offset) has been fully released by the writer. */
    if( FD_LIKELY( !memcmp( slotblockcache->blockhash, blockhash, 32UL ) ) ) {
      *out_slotblockcache = slotblockcache;
      return FD_TXNCACHE_FIND_FOUND;
    }
  }
  return FD_TXNCACHE_FIND_FULL;
}

static int
fd_txncache_ensure_blockcache( fd_txncache_t *                     tc,
                               uchar const                         blockhash[ static 32 ],
                               fd_txncache_private_blockcache_t ** out_blockcache ) {
  for(;;) {
    int blockcache_find = fd_txncache_find_blockhash( tc, blockhash, 1, out_blockcache );
    if( FD_LIKELY( blockcache_find==FD_TXNCACHE_FIND_FOUND ) ) return 1;
    else if( FD_UNLIKELY( blockcache_find==FD_TXNCACHE_FIND_FULL ) ) return 0;

    if( FD_LIKELY( FD_ATOMIC_CAS( &(*out_blockcache)->max_slot, FD_TXNCACHE_EMPTY_ENTRY, FD_TXNCACHE_TEMP_ENTRY ) ||
        FD_ATOMIC_CAS( &(*out_blockcache)->max_slot, FD_TXNCACHE_TOMBSTONE_ENTRY, FD_TXNCACHE_TEMP_ENTRY ) ) ) {
      memcpy( (*out_blockcache)->blockhash, blockhash, 32UL );
      memset( (*out_blockcache)->heads, 0xFF, FD_TXNCACHE_BLOCKCACHE_MAP_CNT*sizeof(uint) );
      (*out_blockcache)->pages_cnt      = 0;
      (*out_blockcache)->txnhash_offset = 0UL;
      memset( (*out_blockcache)->pages, 0xFF, tc->txnpages_per_blockhash_max*sizeof(uint) );
      FD_COMPILER_MFENCE();
      /* Set it to max unreserved value possible */
      (*out_blockcache)->max_slot    = ULONG_MAX-3UL;
      return 1;
    }
    FD_SPIN_PAUSE();
  }
}

static int
fd_txncache_ensure_slotcache( fd_txncache_t *                    tc,
                              ulong                              slot,
                              fd_txncache_private_slotcache_t ** out_slotcache ) {
  for(;;) {
    int slotcache_find = fd_txncache_find_slot( tc, slot, 1, out_slotcache );
    if( FD_LIKELY( slotcache_find==FD_TXNCACHE_FIND_FOUND ) ) return 1;
    else if( FD_UNLIKELY( slotcache_find==FD_TXNCACHE_FIND_FULL ) ) return 0;

    if( FD_LIKELY( FD_ATOMIC_CAS( &(*out_slotcache)->slot, FD_TXNCACHE_EMPTY_ENTRY, FD_TXNCACHE_TEMP_ENTRY ) ||
        FD_ATOMIC_CAS( &(*out_slotcache)->slot, FD_TXNCACHE_TOMBSTONE_ENTRY, FD_TXNCACHE_TEMP_ENTRY ) ) ) {
      for( ulong i=0UL; i<300UL; i++ ) {
        (*out_slotcache)->blockcache[ i ].txnhash_offset = ULONG_MAX;
      }
      FD_COMPILER_MFENCE();
      (*out_slotcache)->slot = slot;
      return 1;
    }
    FD_SPIN_PAUSE();
  }
}

static int
fd_txncache_ensure_slotblockcache( fd_txncache_private_slotcache_t *       slotcache,
                                   uchar const                             blockhash[ static 32 ],
                                   fd_txncache_private_slotblockcache_t ** out_slotblockcache ) {
  for(;;) {
    int slotblockcache_find = fd_txncache_find_slot_blockhash( slotcache, blockhash, out_slotblockcache );
    if( FD_LIKELY( slotblockcache_find==FD_TXNCACHE_FIND_FOUND ) ) return 1;
    else if( FD_UNLIKELY( slotblockcache_find==FD_TXNCACHE_FIND_FULL ) ) return 0;

    if( FD_LIKELY( FD_ATOMIC_CAS( &(*out_slotblockcache)->txnhash_offset, ULONG_MAX, ULONG_MAX-1UL ) ) ) {
      memcpy( (*out_slotblockcache)->blockhash, blockhash, 32UL );
      memset( (*out_slotblockcache)->heads, 0xFF, FD_TXNCACHE_SLOTCACHE_MAP_CNT*sizeof(uint) );
      FD_COMPILER_MFENCE();
      (*out_slotblockcache)->txnhash_offset = 0UL;
      return 1;
    }
    FD_SPIN_PAUSE();
  }
}

static fd_txncache_private_txnpage_t *
fd_txncache_ensure_txnpage( fd_txncache_t *                    tc,
                            fd_txncache_private_blockcache_t * blockcache ) {
  ushort page_cnt = blockcache->pages_cnt;
  if( FD_UNLIKELY( page_cnt>tc->txnpages_per_blockhash_max ) ) return NULL;
  fd_txncache_private_txnpage_t * txnpages = fd_txncache_get_txnpages( tc );

  if( FD_LIKELY( page_cnt ) ) {
    uint txnpage_idx = blockcache->pages[ page_cnt-1 ];
    ushort txnpage_free = txnpages[ txnpage_idx ].free;
    if( FD_LIKELY( txnpage_free ) ) return &txnpages[ txnpage_idx ];
  }

  if( FD_UNLIKELY( page_cnt==tc->txnpages_per_blockhash_max ) ) return NULL;
  if( FD_LIKELY( FD_ATOMIC_CAS( &blockcache->pages[ page_cnt ], UINT_MAX, UINT_MAX-1UL )==UINT_MAX ) ) {
    ulong txnpages_free_cnt = tc->txnpages_free_cnt;
    for(;;) {
      if( FD_UNLIKELY( !txnpages_free_cnt ) ) return NULL;
      ulong old_txnpages_free_cnt = FD_ATOMIC_CAS( &tc->txnpages_free_cnt, (uint)txnpages_free_cnt, (uint)(txnpages_free_cnt-1UL) );
      if( FD_LIKELY( old_txnpages_free_cnt==txnpages_free_cnt ) ) break;
      txnpages_free_cnt = old_txnpages_free_cnt;
      FD_SPIN_PAUSE();
    }
    uint * txnpages_free = fd_txncache_get_txnpages_free( tc );

    uint txnpage_idx = txnpages_free[ txnpages_free_cnt-1UL ];
    fd_txncache_private_txnpage_t * txnpage = &txnpages[ txnpage_idx ];
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
    return &txnpages[ txnpage_idx ];
  }
}

static int
fd_txncache_insert_txn( fd_txncache_t *                        tc,
                        fd_txncache_private_blockcache_t *     blockcache,
                        fd_txncache_private_slotblockcache_t * slotblockcache,
                        fd_txncache_private_txnpage_t *        txnpage,
                        fd_txncache_insert_t const *           txn ) {
  fd_txncache_private_txnpage_t * txnpages = fd_txncache_get_txnpages( tc );
  ulong txnpage_idx = (ulong)(txnpage - txnpages);

  for(;;) {
    ushort txnpage_free = txnpage->free;
    if( FD_UNLIKELY( !txnpage_free ) ) return 0;
    if( FD_UNLIKELY( FD_ATOMIC_CAS( &txnpage->free, txnpage_free, txnpage_free-1UL )!=txnpage_free ) ) continue;
  
    ulong txn_idx = FD_TXNCACHE_TXNS_PER_PAGE-txnpage_free;
    ulong txnhash_offset = blockcache->txnhash_offset;
    ulong txnhash = FD_LOAD( ulong, txn->txnhash+txnhash_offset );
    memcpy( txnpage->txns[ txn_idx ]->txnhash, txn->txnhash+txnhash_offset, 20UL );
    txnpage->txns[ txn_idx ]->result = *txn->result;
    txnpage->txns[ txn_idx ]->slot   = txn->slot;
    FD_COMPILER_MFENCE();

    for(;;) {
      ulong txn_bucket = txnhash%FD_TXNCACHE_BLOCKCACHE_MAP_CNT;
      uint head = blockcache->heads[ txn_bucket ];
      txnpage->txns[ txn_idx ]->blockcache_next = head;
      FD_COMPILER_MFENCE();
      if( FD_LIKELY( FD_ATOMIC_CAS( &blockcache->heads[ txn_bucket ], head, (uint)(FD_TXNCACHE_TXNS_PER_PAGE*txnpage_idx+txn_idx) )==head ) ) break;
      FD_SPIN_PAUSE();
    }

    for(;;) {
      ulong txn_bucket = txnhash%FD_TXNCACHE_SLOTCACHE_MAP_CNT;
      uint head = slotblockcache->heads[ txn_bucket ];
      txnpage->txns[ txn_idx ]->slotblockcache_next = head;
      FD_COMPILER_MFENCE();
      if( FD_LIKELY( FD_ATOMIC_CAS( &slotblockcache->heads[ txn_bucket ], head, (uint)(FD_TXNCACHE_TXNS_PER_PAGE*txnpage_idx+txn_idx) )==head ) ) break;
      FD_SPIN_PAUSE();
    }

    for(;;) {
      ulong max_slot = blockcache->max_slot;

      if( FD_UNLIKELY( txn->slot<=max_slot && max_slot != ULONG_MAX-3UL) ) break;
      if( FD_LIKELY( FD_ATOMIC_CAS( &blockcache->max_slot, max_slot, txn->slot )==max_slot ) ) break;
      FD_SPIN_PAUSE();
    }
    return 1;
  }
}

int
fd_txncache_insert_batch( fd_txncache_t *              tc,
                          fd_txncache_insert_t const * txns,
                          ulong                        txns_cnt ) {
  fd_rwlock_read( tc->lock );

  for( ulong i=0UL; i<txns_cnt; i++ ) {
    fd_txncache_private_blockcache_t * blockcache;
    if( FD_UNLIKELY( !fd_txncache_ensure_blockcache( tc, txns[ i ].blockhash, &blockcache ) ) ) goto unlock_fail;

    // TODO: should this be enabled? Ledger tests fail immediately
    // if( FD_UNLIKELY( blockcache->max_slot!=ULONG_MAX-2 && txns[ i ].slot>=blockcache->max_slot+150UL ) ) {
    //   FD_LOG_WARNING(("Lowest slot %lu for slot %lu", blockcache->max_slot, txns[i].slot ));
    //   goto unlock_fail;
    // }

    fd_txncache_private_slotcache_t * slotcache;
    if( FD_UNLIKELY( !fd_txncache_ensure_slotcache( tc, txns[ i ].slot, &slotcache ) ) ) goto unlock_fail;

    fd_txncache_private_slotblockcache_t * slotblockcache;
    if( FD_UNLIKELY( !fd_txncache_ensure_slotblockcache( slotcache, txns[ i ].blockhash, &slotblockcache ) ) ) goto unlock_fail;

    for(;;) {
      fd_txncache_private_txnpage_t * txnpage = fd_txncache_ensure_txnpage( tc, blockcache );
      if( FD_UNLIKELY( !txnpage ) ) goto unlock_fail;

      int success = fd_txncache_insert_txn( tc, blockcache, slotblockcache, txnpage, &txns[ i ] );
      if( FD_LIKELY( success ) ) break;
      FD_SPIN_PAUSE();
    }
  }

  fd_rwlock_unread( tc->lock );
  return 1;

unlock_fail:
  fd_rwlock_unread( tc->lock );
  return 0;
}

void
fd_txncache_query_batch( fd_txncache_t *             tc,
                         fd_txncache_query_t const * queries,
                         ulong                       queries_cnt,
                         void *                      query_func_ctx,
                         int ( * query_func )( ulong slot, void * ctx ),
                         int *                       out_results ) {
  fd_rwlock_read( tc->lock );
  fd_txncache_private_txnpage_t * txnpages = fd_txncache_get_txnpages( tc );
  for( ulong i=0UL; i<queries_cnt; i++ ) {
    out_results[ i ] = 0;

    fd_txncache_query_t const * query = &queries[ i ];
    fd_txncache_private_blockcache_t * blockcache;
    int result = fd_txncache_find_blockhash( tc, query->blockhash, 0, &blockcache );
    if( FD_UNLIKELY( result!=FD_TXNCACHE_FIND_FOUND ) ) {
      continue;
    }

    ulong txnhash_offset = blockcache->txnhash_offset;
    ulong head_hash = FD_LOAD( ulong, query->txnhash+txnhash_offset ) % FD_TXNCACHE_BLOCKCACHE_MAP_CNT;
    for( uint head=blockcache->heads[ head_hash ]; head!=UINT_MAX; head=txnpages[ head/FD_TXNCACHE_TXNS_PER_PAGE ].txns[ head%FD_TXNCACHE_TXNS_PER_PAGE ]->blockcache_next ) {
      fd_txncache_private_txn_t * txn = txnpages[ head/FD_TXNCACHE_TXNS_PER_PAGE ].txns[ head%FD_TXNCACHE_TXNS_PER_PAGE ];
      if( FD_LIKELY( !memcmp( query->txnhash+txnhash_offset, txn->txnhash, 20UL ) ) ) {
        if( FD_LIKELY( !query_func || query_func( txn->slot, query_func_ctx ) ) ) {
          out_results[ i ] = 1;
          break;
        }
      }
    }
  }

  fd_rwlock_unread( tc->lock );
}

int
fd_txncache_snapshot( fd_txncache_t * tc,
                      void *          ctx,
                      int ( * write )( uchar const * data, ulong data_sz, void * ctx ) ) {
  if( !write ) {
    FD_LOG_WARNING(("No write method provided to snapshotter"));
    return 1;
  }
  fd_rwlock_read( tc->lock );

  fd_txncache_private_txnpage_t * txnpages = fd_txncache_get_txnpages( tc );
  ulong * root_slots = fd_txncache_get_root_slots( tc );
  for( ulong i=0UL; i<tc->root_slots_cnt; i++ ) {
    ulong slot = root_slots[ i ];

    fd_txncache_private_slotcache_t * slotcache;
    if( FD_UNLIKELY( FD_TXNCACHE_FIND_FOUND!=fd_txncache_find_slot( tc, slot, 0, &slotcache ) ) ) continue;

    for( ulong j=0UL; j<300UL; j++ ) {
      fd_txncache_private_slotblockcache_t * slotblockcache = &slotcache->blockcache[ j ];
      if( FD_UNLIKELY( slotblockcache->txnhash_offset>=ULONG_MAX-1UL ) ) continue;

      for( ulong k=0UL; k<FD_TXNCACHE_SLOTCACHE_MAP_CNT; k++ ) {
        uint head = slotblockcache->heads[ k ];
        for( ; head!=UINT_MAX; head=txnpages[ head/FD_TXNCACHE_TXNS_PER_PAGE ].txns[ head%FD_TXNCACHE_TXNS_PER_PAGE ]->slotblockcache_next ) {
          fd_txncache_private_txn_t * txn = txnpages[ head/FD_TXNCACHE_TXNS_PER_PAGE ].txns[ head%FD_TXNCACHE_TXNS_PER_PAGE ];

          fd_txncache_snapshot_entry_t entry = {
            .slot      = slot,
            .txn_idx   = slotblockcache->txnhash_offset,
            .result    = txn->result
          };
          fd_memcpy( entry.blockhash, slotblockcache->blockhash, 32 );
          fd_memcpy( entry.txnhash, txn->txnhash, 20 );
          int err = write( (uchar*)&entry, sizeof(fd_txncache_snapshot_entry_t), ctx );
          if( err ) {
            fd_rwlock_unread( tc->lock );
            return err;
          }
        }
      }
    }
  }

  fd_rwlock_unread( tc->lock );
  return 0;
}

int
fd_txncache_set_txnhash_offset( fd_txncache_t * tc,
                                ulong slot,
                                uchar blockhash[ 32 ],
                                ulong txnhash_offset ) {
  fd_rwlock_read( tc->lock );
  fd_txncache_private_blockcache_t * blockcache;
  if( FD_UNLIKELY( !fd_txncache_ensure_blockcache( tc, blockhash, &blockcache ) ) ) goto unlock_fail;

  blockcache->txnhash_offset = txnhash_offset;
  fd_txncache_private_slotcache_t * slotcache;
  if( FD_UNLIKELY( !fd_txncache_ensure_slotcache( tc, slot, &slotcache ) ) ) goto unlock_fail;

  fd_txncache_private_slotblockcache_t * slotblockcache;
  if( FD_UNLIKELY( !fd_txncache_ensure_slotblockcache( slotcache, blockhash, &slotblockcache ) ) ) goto unlock_fail;
  slotblockcache->txnhash_offset = txnhash_offset;

  fd_rwlock_unread( tc->lock );
  return 0;

unlock_fail:
  fd_rwlock_unread( tc->lock );
  return 1;
}

int
fd_txncache_is_rooted_slot( fd_txncache_t * tc,
                            ulong slot ) {
  fd_rwlock_read( tc->lock );

  ulong * root_slots = fd_txncache_get_root_slots( tc );
  for( ulong idx=0UL; idx<tc->root_slots_cnt; idx++ ) {
    if( FD_UNLIKELY( root_slots[ idx ]==slot ) ) {
      fd_rwlock_unread( tc->lock );
      return 1;
    }
    if( FD_UNLIKELY( root_slots[ idx ]>slot ) ) break;
  }

  fd_rwlock_unread( tc->lock );
  return 0;
}

ulong
fd_txncache_blockhash_cnt( fd_txncache_t * tc ) {
  fd_rwlock_read( tc->lock );

  ulong blockhash_cnt = 0UL;
  for( ulong i=0UL; i<tc->live_slots_max; i++ ) {
    fd_txncache_private_blockcache_t * blockcache = &tc->blockcache[ i ];
    if( FD_UNLIKELY( blockcache->max_slot==FD_TXNCACHE_EMPTY_ENTRY ) ) {
      blockhash_cnt++;
    } else if ( blockcache->max_slot==FD_TXNCACHE_TOMBSTONE_ENTRY ) {
      blockhash_cnt++;
    } else if( FD_UNLIKELY( blockcache->max_slot==FD_TXNCACHE_TEMP_ENTRY ) ) {
      blockhash_cnt++;
    }
  }

  fd_rwlock_unread( tc->lock );
  return blockhash_cnt;
}

ulong
fd_txncache_slot_cnt( fd_txncache_t * tc ) {
  fd_rwlock_read( tc->lock );

  ulong slot_cnt = 0UL;
  for( ulong i=0UL; i<tc->live_slots_max; i++ ) {
    fd_txncache_private_slotcache_t * slotcache = &tc->slotcache[ i ];
    if( FD_UNLIKELY( slotcache->slot==FD_TXNCACHE_EMPTY_ENTRY ) ) {
      slot_cnt++;
    } else if( FD_UNLIKELY( slotcache->slot==FD_TXNCACHE_TOMBSTONE_ENTRY ) ) {
      slot_cnt++;
    } else if( FD_UNLIKELY( slotcache->slot==FD_TXNCACHE_TEMP_ENTRY ) ) {
      slot_cnt++;
    }
  }

  fd_rwlock_unread( tc->lock );
  return slot_cnt;
}