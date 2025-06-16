#ifndef HEADER_fd_src_flamenco_runtime_txncache_h
#define HEADER_fd_src_flamenco_runtime_txncache_h

#include "../fd_flamenco_base.h"
#include "../types/fd_types.h"
#include <math.h>

#include "../../disco/pack/fd_pack.h"
#include "../../disco/pack/fd_pack_cost.h"

/* A txn cache is a concurrent map for saving the result (status) of
   transactions that have executed, and for fast concurrent queries of
   transaction results.

   The txn cache is designed to do two operations fast,

     (a) Insertion.  Insertion is done by both the leader pipeline and
         the replay stage, with an insertion for every transaction that
         is executed, potentially over 1M per second.

     (b) Query.  The leader pipeline queries the status of transactions
         before executing them to ensure that it does not execute
         anything twice.

   Both of these operations are concurrent and lockless, assuming there
   are no other (non-insert/query) operations occuring on the txn cache.
   Most other operations, such as purging transactions from the
   structure, lock the entire structure and will prevent both insertion
   and query from proceeding.

   The txn cache is both CPU and memory sensitive.  A transaction result
   is 1 byte, and the stored transaction hashes are 20 bytes, so
   without any overhead just storing 150 slots of transactions in a flat
   array would require

      524,288 * 150 * 21 ~ 1.5GiB

   Of memory.  But, we can't query, insert, and remove quickly from a
   flat array.  We make a few trade-offs to achieve good performance
   without bloating memory completely.  In particular:

     - The transactions to be queried are stored in a structure that
       looks like a

         hash_map<blockhash, hash_map<txnhash, list<(slot, txn_result)>>>

       The top level hash_map is a probed hash map, and the txnhash map
       is a chained hash map, where the items come from a pool of pages
       of transactions.  We use pages of transactions to support fast
       removal of a blockhash from the top level map, we need to return
       at most 4,800 pages back to the pool rather than 78,643,200
       individual transactions.

       This adds additional memory overhead, a blockhash with only one
       transaction in it will still consume a full page (16,384) of
       transactions of memory.  Allocating a new transaction page to a
       chained map is rare (once every 16,384 inserts) so the cost
       amortizes to zero.  Creating a blockhash happens once per
       blockhash, so also amortizes to zero, the only operation we care
       about is then the simple insert case with an unfull transaction
       page into an existing blockhash.  This can be done with two
       compare-and-swaps,

         // 1. Find the blockhash in the probed hash map.

            let by_blockhash = hash_map[ blockhash ];

         // 2. Request space for the transaction from the current page

            let page = by_blockhash.pages.back();
            let idx = page.used.compare_and_swap( current, current+1 );

         // 3. Write the transaction into the page and the map

            page.txns[ idx ] = txn;
            page.txns[ idx ].next = by_blockhash.txns[ txnhash ].head;
            by_blockhash.txns[ txnhash ].head.compare_and_swap( head, idx );

       Removal of a blockhash from this structure is simple because it
       does not need to be concurrent (the caller will only remove
       between executing slots, so there's no contention and it can take
       a full write lock).  We take a write lock, restore the pages in
       the blockhash to the pool, and then mark the space in the
       hash_map as empty.  This is fast since there are at most 4,800
       pages to restore and restoration is a simple memcpy.

     - Another set of structures are required to support nonce
       transactions.  In the worst case, every single nonce transaction
       could reference a unique blockhash.  If we were to provision the
       by_blockhash map to support this, it would be impractically
       large, and the vast majority of the chained maps would be
       unoccupied.  This is extremely wasteful.  So instead, we organize
       nonce transactions into the following structures:

         hash_map<txnhash, slot>
         hash_map<slot, list<idx>>

       Both top level hash_maps are linearly probed hash maps.  The
       second hash_map essentially takes you from a slot number to a
       list which links together entries in the first hash_map that
       belong to said slot.  The second hash_map is there to support
       fast purging.  On purge of a slot, we can quickly iterate over
       only the nonce transactions in that slot, without having to
       iterate over the entirety of the first hash_map.  Similar to the
       by_blockhash map, removal of a slot does not need to be
       concurrent, as the caller will only remove at the end of a slot,
       and takes a full write lock while doing so.

       Creating a new entry in the by_slot hash map happens once per
       slot, so the cost amortizes to zero.  Inserting a transaction
       into this pair of structures can be done with two
       compare-and-swaps:

         // 1. Find an entry for the txnhash in the first probed hash map.

            let by_txnhash = hash_map[ txnhash ];

         // 2. Install the new slot number.

            by_txnhash.slot.compare_and_swap( empty, slot );

         // 3. Find the entry for the slot in the second probed hash map.

            let by_slot = hash_map[ slot ];

         // 4. Link the txn into the list.

            by_txnhash.next = by_slot.head;
            by_slot.head.compare_and_swap( head, by_txnhash.idx );

       More details can be found in the implementation. */

#define FD_TXNCACHE_ALIGN (128UL)

#define FD_TXNCACHE_MAGIC (0xF17EDA2CE5CAC4E0) /* FIREDANCE SCACHE V0 */

#define FD_TXNCACHE_MAX_ROOTED_SLOTS_LOWER_BOUND (151UL)

/* The Solana consensus protocol has an implied restriction on the
   number of transactions in a slot.  At the time of writing, a slot
   might have 50,000,000 CUs, but a transaction requires at least around
   1020 CUs, so there could be at most ~50K transactions in a slot.

   For Firedancer, we use this limit when running in production, but the
   number of transactions per slot is configurable for development and
   preformance tuning. */

#define FD_TXNCACHE_MAX_TRANSACTIONS_PER_SLOT_LOWER_BOUND (FD_PACK_MAX_COST_PER_BLOCK_UPPER_BOUND/FD_PACK_MIN_TXN_COST)

/* Keys are truncated to 20 bytes when inserting into the txn cache.
   Typically, keys are transaction message hashes, which are 32 bytes.
   They could also be transaction signatures, which are 64 bytes.
   This cannot be changed willy-nilly, because keys get serialized out
   and loaded from snapshots, and more importantly this affects the
   key index flooring logic. */

#define FD_TXNCACHE_KEY_SIZE (20UL)

/* Result codes stored in the txn cache.  Currently only an indication
   of whether the transaction execution returned success or not.

   There's enough bits to store richer information if needed in the
   future, such as the actual error code returned by the executor.  We
   don't do that because all we care about when querying the txn cache
   is whether the transaction executed or not.  The mere presence of a
   transaction in the txn cache tells us that it executed, or landed on
   chain, regardless of whether the execution was entirely successful or
   not, because only executed/committed transactions are inserted into
   the txn cache. */
#define FD_TXNCACHE_RESULT_OK  (0)
#define FD_TXNCACHE_RESULT_ERR (1)

/* Bit-or flags for specifying insert/query mode. */
#define FD_TXNCACHE_FLAG_REGULAR_TXN (1UL)    /* This is a regular non-nonce transaction. */
#define FD_TXNCACHE_FLAG_NONCE_TXN   (1UL<<1) /* This is a nonce transaction. */
#define FD_TXNCACHE_FLAG_SNAPSHOT    (1UL<<2) /* This is a snapshot transaction. */

/* Results from querying the txn cache. */
#define FD_TXNCACHE_QUERY_ABSENT  (0)
#define FD_TXNCACHE_QUERY_PRESENT (1)

struct fd_txncache_insert {
  uchar const * blockhash;
  uchar const * txnhash;
  ulong         key_sz;
  ulong         slot;
  uchar const * result;
  ulong         flags;
};

typedef struct fd_txncache_insert fd_txncache_insert_t;

struct fd_txncache_query {
  uchar const * blockhash;
  uchar const * txnhash;
  ulong         key_sz;
  ulong         flags;
};

typedef struct fd_txncache_query fd_txncache_query_t;

/* Forward declare opaque handle */
struct fd_txncache_private;
typedef struct fd_txncache_private fd_txncache_t;

FD_PROTOTYPES_BEGIN

/* fd_txncache_{align,footprint} give the needed alignment and
   footprint of a memory region suitable to hold a txn cache.
   fd_txncache_{align,footprint} return the same value as
   FD_TXNCACHE_{ALIGN,FOOTPRINT}.

   fd_txncache_new formats memory region with suitable alignment and
   footprint suitable for holding a txn cache.  Assumes shmem points
   on the caller to the first byte of the memory region owned by the
   caller to use.  Returns shmem on success and NULL on failure (logs
   details).  The memory region will be owned by the state on successful
   return.  The caller is not joined on return.

   fd_txncache_join joins the caller to a txn cache. Assumes shtc points
   to the first byte of the memory region holding the state.  Returns a
   local handle to the join on success (this is not necessarily a simple
   cast of the address) and NULL on failure (logs details).

   fd_txncache_leave leaves the caller's current local join to a txn
   cache.  Returns a pointer to the memory region holding the state on
   success (this is not necessarily a simple cast of the address) and
   NULL on failure (logs details).  The caller is not joined on
   successful return.

   fd_txncache_delete unformats a memory region that holds a txn cache.
   Assumes shtc points on the caller to the first byte of the memory
   region holding the state and that nobody is joined.  Returns a
   pointer to the memory region on success and NULL on failure (logs
   details).  The caller has ownership of the memory region on
   successful return. */

FD_FN_CONST ulong
fd_txncache_align( void );

FD_FN_CONST ulong
fd_txncache_footprint( ulong max_rooted_slots,
                       ulong max_live_slots,
                       ulong max_txn_per_slot );

void *
fd_txncache_new( void * shmem,
                 ulong  max_rooted_slots,
                 ulong  max_live_slots,
                 ulong  max_txn_per_slot );

fd_txncache_t *
fd_txncache_join( void * shtc );

void *
fd_txncache_leave( fd_txncache_t * tc );

void *
fd_txncache_delete( void * shtc );

/* fd_txncache_register_root registers a root slot in a txn cache.  Only
   the provided limit of roots (typically 300) can exist in the txn
   cache at once, after which the oldest roots will be purged.

   Purging a root means it cannot be served in a snapshot response,
   although transactions in the root may or may not still be present.
   Transaction status is removed once all roots referencing the
   blockhash of the transaction are removed from the txn cache.

   This is neither cheap or expensive, it will pause all insertion and
   query operations but only momentarily until any old slots can be
   purged from the cache. */

void
fd_txncache_register_root_slot( fd_txncache_t * tc,
                                ulong           slot );

/* fd_txncache_root_slots returns the list of live slots currently
   tracked by the txn cache.  There will be at most max_root_slots
   slots, which will be written into the provided out_slots.  It is
   assumed tc points to a txn cache and out_slots has space for at least
   max_root_slots results.  If there are less than max_root_slots slots
   in the cache, the front part of out_slots will be filled in, and all
   the remaining slots will be set to ULONG_MAX.

   This is a fast operation, but it will lock the whole structure and
   cause a temporary pause in insert and query operations. */

void
fd_txncache_root_slots( fd_txncache_t * tc,
                        ulong *         out_slots );

/* fd_txncache_insert_batch inserts a batch of transaction results into
   a txn cache.  Assumes tc points to a txn cache, txns is a list of
   transaction results to be inserted, and txns_cnt is the count of the
   results list.  The insert copies data from the results and does not
   have any lifetime interest in the results memory provided once this
   call returns.

   Returns 1 on success and 0 on failure.  The only reasons insertion
   can fail are because (1) the txn cache is full or (2) duplicate
   transactions are concurrently inserted.  Neither should ever happen
   in production if the caller sizes the bounds correctly and the caller
   doesn't dispatch conflicting transactions on the same fork.
   Duplicate transactions necessarily reference the same fee payer
   account, and therefore should be serialized due to conflicts on the
   writeable fee payer account.  The return code is mostly here to
   support testing and fuzzing.

   This is a cheap, high performance, concurrent operation and can occur
   at the same time as queries and arbitrary other insertions. */

int
fd_txncache_insert_batch( fd_txncache_t *              tc,
                          fd_txncache_insert_t const * txns,
                          ulong                        txns_cnt );

/* fd_txncache_query_batch queries a batch of transactions to determine
   if they exist in the txn cache or not.  The queries have an ambiguous
   slot, but must match both the blockhash and txnhash.  In addition, if
   the query_func is not NULL, the query_func will be called with the
   slot of the txn and the query_func_ctx that was provided, and the
   transaction will be considered present only if the query_func also
   returns 1.

   Assumes tc points to a txn cache, queries is a list of queries to be
   executed, and queries_cnt is the count of the queries list.
   out_results must be at least as large as queries_cnt and will be
   filled with 0 or 1 if the transaction is not present or present
   respectively, at some point during the query.

   This is a cheap, high performance, concurrent operation and can occur
   at the same time as queries and arbitrary other insertions.
   Crucially, callers of this function should not expect guaranteed
   presence of concurrently inserted transactions.
   Visibility of inserted transactions in subsequent queries need to be
   ensured via external synchronizations, if desired.
 */

void
fd_txncache_query_batch( fd_txncache_t *             tc,
                         fd_txncache_query_t const * queries,
                         ulong                       queries_cnt,
                         void *                      query_func_ctx,
                         int ( * query_func )( ulong slot, void * ctx ),
                         int *                       out_results );

/* fd_txncache_set_nonce_txnhash_offset sets the txnhash offset in the
   nonce txn slotcache.  This is used solely for snapshot restore since
   in Firedancer we always use an offset of 0 after snapshot restore.
   Return an error if the cache entry isn't found.

   Returns 1 on success and 0 on failure.

   THIS IS NOT THREAD SAFE and should only be called during snapshot
   restore. */
int
fd_txncache_set_nonce_txnhash_offset( fd_txncache_t * tc,
                                      uchar           blockhash[ 32 ],
                                      ulong           txnhash_offset );

/* fd_txncache_is_rooted_slot returns 1 is `slot` is rooted, 0 otherwise.
   Acquires a read lock.
 */
int
fd_txncache_is_rooted_slot( fd_txncache_t * tc,
                            ulong           slot );

/* fd_txncache_is_rooted_slot_locked returns 1 is `slot` is rooted, 0 otherwise.
   Assumes a read lock has been acquired.
 */
int
fd_txncache_is_rooted_slot_locked( fd_txncache_t * tc,
                                   ulong           slot );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_txncache_h */
