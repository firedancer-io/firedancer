#ifndef HEADER_fd_src_flamenco_runtime_fd_txncache_private_h
#define HEADER_fd_src_flamenco_runtime_fd_txncache_private_h

#include "fd_txncache_shmem.h"
#include "../types/fd_types_custom.h"
#include "../fd_rwlock.h"

/* The number of transactions in each page.  This needs to be high
   enough to amoritze the cost of caller code reserving pages from,
   and returning pages to the pool, but not so high that the memory
   wasted from blockhashes with only one transaction is significant. */

#define FD_TXNCACHE_TXNS_PER_PAGE (16384UL)

/* The maximum distance a transaction blockhash reference can be
   (inclusive).  For example, if no slots were skipped, and the value is
   151, slot 300 is allowed to reference blockhashes from slots
   [149, 300). */
#define FD_TXNCACHE_MAX_BLOCKHASH_DISTANCE (151UL)

struct fd_txncache_single_txn {
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

struct fd_txncache_txnpage {
  ushort                   free; /* The number of free txn entries in this page. */
  fd_txncache_single_txn_t txns[ FD_TXNCACHE_TXNS_PER_PAGE][ 1 ]; /* The transactions in the page. */
};

typedef struct fd_txncache_txnpage fd_txncache_txnpage_t;

struct fd_txncache_blockcache_shmem {
  fd_txncache_fork_id_t parent_id;
  fd_txncache_fork_id_t child_id;
  fd_txncache_fork_id_t sibling_id;

  int frozen;            /* If non-zero, the blockcache is frozen and should not be modified.  This is used to enforce
                            invariants on the caller of the txncache. */

  uint generation;

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

  ushort pages_cnt;      /* The number of txnpages currently in use to store the transactions in this blockcache. */

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
  ushort txnpages_per_blockhash_max;
  ushort max_txnpages;

  uint blockcache_generation; /* Incremented for every blockcache. */
  ushort txnpages_free_cnt; /* The number of pages in the txnpages that are not currently in use. */

  ulong root_cnt;
  root_slist_t root_ll[1]; /* A singly linked list of the forks that are roots of fork chains.  The tail is the
                              most recently added root, the head is the oldest root.  This is used to identify
                              which forks can be pruned when a new root is added. */

  ulong magic; /* ==FD_TXNCACHE_MAGIC */
};

FD_PROTOTYPES_BEGIN

FD_FN_CONST ushort
fd_txncache_max_txnpages_per_blockhash( ulong max_active_slots,
                                        ulong max_txn_per_slot );

FD_FN_CONST ushort
fd_txncache_max_txnpages( ulong max_active_slots,
                          ulong max_txn_per_slot );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_txncache_private_h */
