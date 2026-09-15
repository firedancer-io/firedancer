#ifndef HEADER_fd_src_flamenco_runtime_fd_txncache_private_h
#define HEADER_fd_src_flamenco_runtime_fd_txncache_private_h

#include "fd_txncache_shmem.h"
#include "../fd_flamenco_base.h"
#include "../fd_rwlock.h"

/* The number of transactions in each page.  This needs to be high
   enough to amoritze the cost of caller code reserving pages from,
   and returning pages to the pool, but not so high that the memory
   wasted from blockhashes with only one transaction is significant. */

#define FD_TXNCACHE_TXNS_PER_PAGE (8192UL)

/* The maximum distance a transaction blockhash reference can be
   (inclusive).  For example, if no slots were skipped, and the value is
   151, slot 300 is allowed to reference blockhashes from slots
   [149, 300). */
#define FD_TXNCACHE_MAX_BLOCKHASH_DISTANCE (151UL)

/* The global txn index (page*FD_TXNCACHE_TXNS_PER_PAGE+txn) is a uint
   with UINT_MAX as the null link, which bounds the txnpage pool. */

#define FD_TXNCACHE_MAX_TXNPAGES (UINT_MAX/FD_TXNCACHE_TXNS_PER_PAGE)

struct __attribute__((packed)) fd_txncache_single_txn {
  uint  blockcache_next; /* Pointer to the next element in the blockcache hash chain containing this entry from the pool. */
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

struct fd_txncache_txnpage {
  ushort                   free; /* The number of free txn entries in this page. */
  fd_txncache_single_txn_t txns[ FD_TXNCACHE_TXNS_PER_PAGE][ 1 ]; /* The transactions in the page. */
};

typedef struct fd_txncache_txnpage fd_txncache_txnpage_t;

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
                            insert into the cache ourselves, we do just always use a key_offset of zero, so this is
                            only nonzero when constructed form a peer snapshot. */

  ulong pages_cnt;       /* The number of txnpages currently in use to store the transactions in this blockcache. */

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
  /* The txncache is a concurrent structure and will be accessed by multiple threads
     concurrently.  Insertion and querying only take a read lock as they can be done
     lockless but all other operations will take a write lock internally.

     The lock needs to be aligned to 128 bytes to avoid false sharing with other
     data that might be on the same cache line. */
  fd_rwlock_t lock[ 1 ] __attribute__((aligned(128UL)));

  ulong  txn_per_slot_max;
  ulong  active_slots_max;
  ulong  bucket_cnt;      /* Hash buckets per blockcache.  Decoupled from txn_per_slot_max (load
                             factor 8) to reduce the heads arrays' memory footprint. */
  ulong  txnpages_per_blockhash_max;
  ulong  max_txnpages;
  ulong  txnpage_idx_sz;  /* Element size of every txnpage index array (blockcache->pages,
                             txnpages_free, scratch_pages), see fd_txncache_txnpage_idx_sz. */

  uint  blockcache_generation; /* Incremented for every blockcache. */
  ulong txnpages_free_cnt; /* The number of pages in the txnpages that are not currently in use. */

  /* Helps the snapshot producer walk the txncache lock-free and detect
     relevant changes to the txncache.  mutation_gen covers transaction
     storage, and root_gen covers the root history.  mutation_gen is odd
     when the storage is being modified in ways that could affect the
     snapshot, such as during reset, root advancement, and compaction,
     and bumped once the mutation is done.  root_gen increments on root
     advancement and reset.

     For the snapshot producer, fd_txncache_writer, mutation_gen changes
     trigger retry in the writer, and root_gen changes are treated as
     fatal invariant violation because the replay tile is expected to
     pause root history changes while a snapshot is in progress.

     Note that attach/cancel of the unrooted frontier does not bump
     mutation_gen.  Suppose an unrooted child executed transaction T
     referencing an old rooted blockhash.  Before cancellation, T is
     unrooted, so the writer skips it.  After cancellation, T is stale,
     so the writer still skips it.  So the desired snapshot did not
     change.

     A note on concurrency ... Accesses to the two generation numbers
     are race free under C11.  Every store after initialization is
     atomic and pairs with an atomic load in the snapshot producer tile.
     The loads in the write locked mutators need no atomicity because
     every store is made under the write lock so said loads are already
     ordered properly with respect to the writes.  In contrast, the
     transaction entries the snapshot walker loads and the txncache
     stores are plain on both sides, and the blockcache bucket heads are
     stored plainly by compaction while the walker loads them with an
     acquire load.  Both are data races under C11.  The walker is
     nevertheless correct, given that the compiler emits the plain entry
     accesses as ordinary loads and stores.  FD_HW_MFENCE_ST in
     fd_txncache_mutation_begin orders the odd store before the entry
     stores and FD_HW_MFENCE_LD in the walker orders the entry loads
     before the generation re-check, so an entry load that observed a
     store made inside a mutation section is followed by a re-check that
     fails, and whatever was read, torn or otherwise, is discarded. */
  ulong mutation_gen;
  ulong root_gen;

  ulong root_cnt;
  root_slist_t root_ll[1]; /* A singly linked list of the forks that are roots of fork chains.  The tail is the
                              most recently added root, the head is the oldest root.  This is used to identify
                              which forks can be pruned when a new root is added. */

  ulong seed;
  ulong magic; /* ==FD_TXNCACHE_SHMEM_MAGIC */
};

struct blockcache {
  fd_txncache_blockcache_shmem_t * shmem;

  uint * heads;          /* The hash table for the blockhash.  Each entry is a pointer to the head of a linked list of
                            transactions that reference this blockhash.  As we add transactions to the bucket, the head
                            pointer is updated to the new item, and the new item is pointed to the previous head. */
  void * pages;          /* A list of the txnpages containing the transactions for this blockcache, elements of
                            shmem->txnpage_idx_sz bytes (see fd_txncache_txnpage_idx_ld). */

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

  void * txnpages_free;             /* The index in the txnpages array that is free, for each of the free pages.
                                       Elements are shmem->txnpage_idx_sz bytes, as are scratch_pages below. */

  fd_txncache_txnpage_t * txnpages; /* The actual storage for the transactions.  The blockcache points to these
                                       pages when storing transactions.  Transaction are grouped into pages of
                                       size 16384 to make certain allocation and deallocation operations faster
                                       (just the pages are acquired/released, rather than each txn). */

  void * scratch_pages;
  uint * scratch_heads;
  fd_txncache_txnpage_t * scratch_txnpage;
};

FD_PROTOTYPES_BEGIN

/* Use these to bracket a write locked change that is visible to the
   lock-free snapshot chain walker (fd_txncache_writer).  mutation_gen
   is odd while a change is in progress.  The walker uses an acquire
   load of the generation before starting its chain reads and a LoadLoad
   barrier before each re-check. */

static inline void
fd_txncache_mutation_begin( fd_txncache_shmem_t * shmem ) {
  /* Plain load is fine because the write lock holder is the only writer. */
  ulong gen = shmem->mutation_gen;
  FD_TEST_CRIT( !(gen&1UL) );
  __atomic_store_n( &shmem->mutation_gen, gen+1UL, __ATOMIC_RELAXED );

  /* The walker does not write/publish any shared state visible to the
     txncache.  So no need for a StoreLoad barrier here.  Just
     StoreStore. */
  FD_HW_MFENCE_ST();
}

static inline void
fd_txncache_mutation_end( fd_txncache_shmem_t * shmem ) {
  /* Plain load is fine because the write lock holder is the only writer. */
  ulong gen = shmem->mutation_gen;
  FD_TEST_CRIT( gen&1UL );
  __atomic_store_n( &shmem->mutation_gen, gen+1UL, __ATOMIC_RELEASE );
}

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
  return fd_ulong_max( 1UL, (max_txn_per_slot+7UL)/8UL );
}

/* Txnpage indices are stored as ushort, which covers production
   parameters, and widen to uint only when the pool exceeds the ushort
   range (development.bench sizing), keeping the production footprint
   unchanged.  The all-ones value of the width is the null index and
   all-ones minus one is the allocation-in-progress flag, so memset 0xFF
   nulls an array of either width.  ld/st access an index array of the
   given element size. */

FD_FN_CONST static inline ulong
fd_txncache_txnpage_idx_sz( ulong max_txnpages ) {
  return max_txnpages>USHORT_MAX-2UL ? sizeof(uint) : sizeof(ushort);
}

static inline ulong
fd_txncache_txnpage_idx_ld( ulong        idx_sz,
                            void const * idx,
                            ulong        i ) {
  return idx_sz==sizeof(uint) ? (ulong)((uint const *)idx)[ i ] : (ulong)((ushort const *)idx)[ i ];
}

static inline void
fd_txncache_txnpage_idx_st( ulong  idx_sz,
                            void * idx,
                            ulong  i,
                            ulong  val ) {
  if( idx_sz==sizeof(uint) ) ((uint *)idx)[ i ] = (uint)val;
  else                       ((ushort *)idx)[ i ] = (ushort)val;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_txncache_private_h */
