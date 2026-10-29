#ifndef HEADER_fd_src_flamenco_runtime_fd_txncache_private_h
#define HEADER_fd_src_flamenco_runtime_fd_txncache_private_h

#include "fd_txncache.h"
#include "../fd_flamenco_base.h"
#include "../fd_rwlock.h"

/* The number of transactions in each page.  This needs to be high
   enough to amortize the cost of caller code reserving pages from,
   and returning pages to the pool, but not so high that the memory
   wasted from blockhashes with only one transaction is significant. */

#define FD_TXNCACHE_TXNS_PER_PAGE (8192UL)
#define FD_TXNCACHE_TXNPAGE_ALIGN (4096UL)

/* The maximum distance a transaction blockhash reference can be
   (inclusive).  For example, if no slots were skipped, and the value is
   151, slot 300 is allowed to reference blockhashes from slots
   [149, 300). */
#define FD_TXNCACHE_MAX_BLOCKHASH_DISTANCE (151UL)

/* The most roots the txncache holds.  root_cnt does not count the
   initial root. */
#define FD_TXNCACHE_MAX_ROOTS (FD_TXNCACHE_MAX_BLOCKHASH_DISTANCE+1UL)

/* The global txn index (page*FD_TXNCACHE_TXNS_PER_PAGE+txn) is a uint
   with UINT_MAX as the null link, which bounds the txnpage pool. */

#define FD_TXNCACHE_MAX_TXNPAGES (UINT_MAX/FD_TXNCACHE_TXNS_PER_PAGE)

/* The most pages a read-locked operation loads without the lock before
   it retries under the write lock.  The fallback guarantees progress
   when the pages an operation needs do not fit in the frames at
   once. */

#define FD_TXNCACHE_FETCH_MAX (4UL)

struct __attribute__((packed)) fd_txncache_single_txn {
  uint  blockcache_next; /* Global txn index of the next element in this blockcache hash chain, or UINT_MAX. */
  uint  generation;      /* The generation of the fork when this transaction was inserted.  Used to
                            determine if the transaction is still valid for a fork that might have
                            advanced since insertion. */

  fd_txncache_fork_id_t fork_id; /* Fork that the transaction was executed on.  A transaction might be in the cache
                                    multiple times if it was executed on multiple forks. */
  uchar txnhash[ 20UL ]; /* The transaction message hash, truncated to 20 bytes.  The hash is not always the first 20
                            bytes, but is 20 bytes starting at some arbitrary offset given by the txnhash_offset value
                            of the containing blockcache entry. */
};
typedef struct fd_txncache_single_txn fd_txncache_single_txn_t;

FD_STATIC_ASSERT( sizeof(fd_txncache_single_txn_t)==30UL, fd_txncache_single_txn );

struct __attribute__((aligned(FD_TXNCACHE_TXNPAGE_ALIGN))) fd_txncache_txnpage {
  ushort                   free; /* The number of free txn entries in this page. */
  fd_txncache_single_txn_t txns[ FD_TXNCACHE_TXNS_PER_PAGE][ 1 ]; /* The transactions in the page. */
};
typedef struct fd_txncache_txnpage fd_txncache_txnpage_t;

struct fd_txncache_page_meta {
  uint frame;      /* UINT_MAX if not resident. */
  uint dirty;      /* Resident contents changed since the last writeback. */
  int  disk_valid; /* A complete page has been written to its disk slot. */
  uint next;       /* Next older txnpage of the owning blockcache, or UINT_MAX. */
  uint ref;        /* Resident and accessed since the eviction sweep last passed its frame. */
  uint io;         /* A fetch is loading or writing back the page without the lock. */
};
typedef struct fd_txncache_page_meta fd_txncache_page_meta_t;

struct fd_txncache_blockcache_shmem {
  fd_txncache_fork_id_t parent_id;
  fd_txncache_fork_id_t child_id;
  fd_txncache_fork_id_t sibling_id;

  int frozen;            /* This is used to enforce invariants on the caller of the txncache.
                            -1: invalid
                             0: active
                             1: semi frozen, only happens during snapshot load
                             2: frozen, should not be modified */

  uint generation;

  fd_hash_t blockhash;   /* The blockhash that this entry is for. */
  ulong txnhash_offset;  /* To save memory, the Agave validator decided to truncate the hash of transactions stored in
                            this memory to 20 bytes rather than 32 bytes.  The bytes used are not the first 20 as you
                            might expect, but instead the first 20 starting at some random offset into the transaction
                            hash (starting between 0 and len(hash)-20, a/k/a 44 for signatures, and 12 for hashes).

                            In an unfortunate turn, the offset is also propagated to peers via. snapshot responses,
                            which only communicate the offset and the respective 20 bytes.  To make sure we are
                            deduplicating incoming transactions correctly, we must replicate this system even though
                            it would be easier to just always take the first 20 bytes.  For transactions that we
                            insert into the cache ourselves, we do just always use a txnhash_offset of zero, so this is
                            only nonzero when constructed from a peer snapshot. */

  ulong pages_cnt;       /* The number of txnpages currently in use to store the transactions in this blockcache. */
  uint  page_head;       /* Newest logical page, or UINT_MAX.  Older pages follow page_meta[ page ].next. */

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
};

typedef struct fd_txncache_blockcache_shmem fd_txncache_blockcache_shmem_t;

#define POOL_NAME       blockcache_pool
#define POOL_T          fd_txncache_blockcache_shmem_t
#define POOL_IDX_T      ulong
#define POOL_NEXT       pool.next
#define POOL_IMPL_STYLE 1
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME               blockhash_map
#define MAP_KEY                blockhash
#define MAP_ELE_T              fd_txncache_blockcache_shmem_t
#define MAP_KEY_T              fd_hash_t
#define MAP_PREV               blockhash_map.prev
#define MAP_NEXT               blockhash_map.next
#define MAP_KEY_EQ(k0,k1)      fd_hash_eq( k0, k1 )
#define MAP_KEY_HASH(key,seed) (__extension__({ (void)(seed); fd_ulong_load_8_fast( (key)->uc ); }))
#define MAP_OPTIMIZE_RANDOM_ACCESS_REMOVAL 1
#define MAP_MULTI              1
#define MAP_IMPL_STYLE         1
#include "../../util/tmpl/fd_map_chain.c"

#define SLIST_NAME       root_slist
#define SLIST_ELE_T      fd_txncache_blockcache_shmem_t
#define SLIST_IDX_T      ulong
#define SLIST_NEXT       slist.next
#define SLIST_IMPL_STYLE 1
#include "../../util/tmpl/fd_slist.c"

#define SET_NAME descends_set
#include "../../util/tmpl/fd_set_dynamic.c"

struct __attribute__((aligned(FD_TXNCACHE_SHMEM_ALIGN))) fd_txncache_shmem_private {
  /* The txncache is a concurrent structure and will be accessed by
     multiple threads concurrently.  Resident queries and inserts take
     a read lock.  Structural operations take a write lock.  A cache
     miss takes the write lock only to reserve a frame and does its
     spill I/O without the lock, marking the pages it moves busy (see
     page_meta io) until it publishes them.  The lock prevents eviction
     while a reader uses a frame.

     The lock needs to be aligned to 128 bytes to avoid false sharing
     with other data that might be on the same cache line. */
  fd_rwlock_t lock[ 1 ] __attribute__((aligned(128UL)));

  ulong txn_per_slot_max;
  ulong active_slots_max;
  ulong bucket_cnt; /* Hash buckets per blockcache, txn_per_slot_max/32 (load factor 16, as live forks hold at most txn_per_slot_max/2). */
  ulong txnpages_per_blockhash_max;
  ulong txnpages_max;
  ulong frames_max;

  uint  blockcache_generation; /* Incremented for every blockcache. */
  ulong txnpages_free_cnt;     /* Number of unallocated logical pages. */
  ulong frames_free_cnt;       /* Free in-memory resident frames. */
  ulong evict_next;            /* CLOCK hand: next frame the eviction sweep checks. */
  ulong release_seq;           /* Incremented whenever a logical page is released, under the write lock. */
  fd_rwlock_t alloc_lock[ 1 ]; /* Lock for allocating new logical page + frame. */

  /* Metrics.  page_miss_cnt, lock_read_wait_ticks and the spill
     counters are updated atomically, the rest under the write lock. */
  ulong page_miss_cnt;         /* Read-locked lookups that found their page not resident. */
  ulong page_spilled_cnt;      /* Dirty pages written to the spill file. */
  ulong page_spill_read_cnt;   /* Pages read back from the spill file. */
  ulong frame_evicted_cnt;     /* Frames evicted to load another page. */
  ulong spill_ticks;           /* Ticks spent in spill file I/O. */
  ulong lock_read_wait_ticks;  /* Ticks spent waiting to take the read lock. */
  ulong lock_write_wait_ticks; /* Ticks spent waiting to take the write lock. */

  ulong root_cnt;
  root_slist_t root_ll[1]; /* A singly linked list of the forks that are roots of fork chains.  The tail is the
                              most recently added root, the head is the oldest root.  This is used to identify
                              which forks can be pruned when a new root is added. */

  ulong seed;
  ulong magic; /* ==FD_TXNCACHE_SHMEM_MAGIC */
};

struct blockcache {
  fd_txncache_blockcache_shmem_t * shmem;

  uint * heads;          /* The hash table for the blockhash.  Each entry is the global txn index of the head of a linked list of
                            transactions that reference this blockhash.  As we add transactions to the bucket, the head
                            pointer is updated to the new item, and the new item is pointed to the previous head. */

  descends_set_t * descends; /* Each fork can descend from other forks in the txncache, and this bit vector contains one
                                value for each fork in the txncache.  If this fork descends from some other fork F, then
                                the bit at index F in descends[] is set. */
};

typedef struct blockcache blockcache_t;

struct fd_txncache_private {
  fd_txncache_shmem_t * shmem;

  fd_txncache_blockcache_shmem_t * blockcache_shmem_pool;
  blockcache_t *                   blockcache_pool;
  blockhash_map_t *                blockhash_map;

  int spill_fd;

  fd_txncache_page_meta_t * page_meta;     /* Metadata for each logical page */
  uint *                    txnpages_free; /* Stack of free logical pages */
  uint *                    frame_page;    /* Array mapping frame to logical page */
  uint *                    frames_free;   /* Stack of unused frame indices. */

  fd_txncache_txnpage_t * txnpages; /* Aligned resident frames, indexed through page_meta. */

  /* Scratch space used for cleaning up stale entries for compaction. */
  uint *                  scratch_heads;
  fd_txncache_txnpage_t * scratch_txnpage;
  fd_txncache_txnpage_t * scratch_input;

  fd_txncache_join_metrics_t metrics[1];
};

FD_PROTOTYPES_BEGIN

/* fd_txncache_max_txnpages{,_per_blockhash} return the txnpage pool
   size and the per blockcache page cap for the given parameters.  The
   result is not bounded; callers compare against
   FD_TXNCACHE_MAX_TXNPAGES. */

FD_FN_CONST ulong
fd_txncache_max_txnpages_per_blockhash( ulong max_active_slots,
                                        ulong max_txn_per_slot );

FD_FN_CONST ulong
fd_txncache_max_txnpages( ulong max_active_slots,
                          ulong max_txn_per_slot );

FD_FN_CONST static inline ulong
fd_txncache_bucket_cnt( ulong max_txn_per_slot ) {
  return fd_ulong_max( 1UL, (max_txn_per_slot+31UL)/32UL );
}

/* Snapshot support.  These let the snapshot writer read the rooted part
   of the txncache without knowing its locking or paging. */

struct fd_txncache_root {
  ulong blockcache_idx;
  ulong txnhash_offset;
  uint  generation;
  uchar blockhash[ 32UL ];
};

typedef struct fd_txncache_root fd_txncache_root_t;

/* fd_txncache_snapshot_roots copies every root, oldest first, to out
   and returns the count.  out must have room for
   FD_TXNCACHE_MAX_ROOTS roots.  The caller must keep the
   root from advancing, so the newest root is the snapshot root. */

ulong
fd_txncache_snapshot_roots( fd_txncache_t *      tc,
                            fd_txncache_root_t * out );

/* fd_txncache_blockcache_iter_t iterates the transactions of a
   blockcache.  It visits one hash chain at a time and holds the
   txncache lock for that chain, so the chain cannot be compacted,
   freed, or evicted underneath it.  Concurrent inserts only prepend to
   a chain, so the entries reachable from the head loaded when the chain
   is opened do not change while it is held.  The lock is released
   between chains.

   For each chain, the iterator holds the read lock if every page of the
   chain is resident.  Otherwise it holds the write lock, under which it
   loads pages on demand.

   fd_txncache_blockcache_iter_init locks tc and positions iter at the
   first transaction of blockcache blockcache_idx.  Returns iter.  init
   must be paired with fd_txncache_blockcache_iter_fini.  The caller
   must not call into the txncache between init and fini.

   fd_txncache_blockcache_iter_ele returns the current transaction,
   valid until the next call to fd_txncache_blockcache_iter_next or
   fd_txncache_blockcache_iter_fini.

   Typical usage:

     fd_txncache_blockcache_iter_t iter[1];
     for( fd_txncache_blockcache_iter_init( iter, tc, blockcache_idx );
          !fd_txncache_blockcache_iter_done( iter );
          fd_txncache_blockcache_iter_next( iter ) ) {
       fd_txncache_single_txn_t const * txn = fd_txncache_blockcache_iter_ele( iter );
       ...
     }
     fd_txncache_blockcache_iter_fini( iter ); */

struct fd_txncache_blockcache_iter {
  fd_txncache_t *                  tc;
  fd_txncache_single_txn_t const * txn; /* NULL once done */
  ulong                            blockcache_idx;
  ulong                            bucket;
  int                              write_lock;
};

typedef struct fd_txncache_blockcache_iter fd_txncache_blockcache_iter_t;

fd_txncache_blockcache_iter_t *
fd_txncache_blockcache_iter_init( fd_txncache_blockcache_iter_t * iter,
                                  fd_txncache_t *                 tc,
                                  ulong                           blockcache_idx );

void
fd_txncache_blockcache_iter_next( fd_txncache_blockcache_iter_t * iter );

void
fd_txncache_blockcache_iter_fini( fd_txncache_blockcache_iter_t * iter );

FD_FN_PURE static inline int
fd_txncache_blockcache_iter_done( fd_txncache_blockcache_iter_t const * iter ) {
  return !iter->txn;
}

FD_FN_PURE static inline fd_txncache_single_txn_t const *
fd_txncache_blockcache_iter_ele( fd_txncache_blockcache_iter_t const * iter ) {
  return iter->txn;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_txncache_private_h */
