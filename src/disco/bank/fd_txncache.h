#ifndef HEADER_fd_src_disco_bank_txncache_h
#define HEADER_fd_src_disco_bank_txncache_h

/* A txn cache is a concurrent map for saving the result (status) of
   transactions that have executed.  In addition to supporting fast
   concurrent insertion and query of transaction results, the txn
   cache supports serialization of its state into a standard bincode
   format for serving the state to other nodes via. snapshot responses,
   and then restoring snapshots produced by other nodes.

   The txn cache is designed to do two operations fast,

     (a) Insertion.  Insertion is done by both the leader pipeline and
         the replay stage, with an insertion for every transaction that
         is executed, potentially over 1M per second.

     (b) Query.  The leader pipeline queries the status of transactions
         before executing them to ensure that it does not execute
         anything twice.

   Both of these operations are concurrent and lockless, assuming there
   are no other (non-insert/query) operations occuring on the txn cache.
   Most other operations lock the entire structure and will prevent both
   insertion and query from proceeding.

   The txn cache is both CPU and memory sensitive.  A transaction result
   is 40 bytes, and the stored transaction hashes are 20 bytes, so
   without any overhead just storing 150 slots of transactions in a flat
   array would require

      524,288 * 150 * 60 ~ 5GiB

   Of memory.  But, we can't query, insert, and remove quickly from a
   flat array.  We make a few trade-offs to achieve good performance
   without bloating memory completely.  In particular:

     - The transactions to be queried are stored in a structure that
       looks like a
       
         hash_map<blockhash, hash_map<txnhash, vec<(slot, status)>>>

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
            page.txns[ idx ].next = by_blockhash.txns[ txnhash ].idx;
            by_blockhash.txns[ txnhash ].head.compare_and_swap( current, idx );

       Removal of a blockhash from this structure is simple because it
       does not need to be concurrent (the caller will only remove
       between executing slots, so there's no contention and it can take
       a full write lock).  We take a write lock, restore the pages in
       the blockhash to the pool, and then mark the space in the
       hash_map as empty.  This is fast since there are at most 4,800
       pages to restore and restoration is a simple memcpy.
      
     - Another structure is required to support serialization of
       snapshots from the cache.  Serialization must produce a binary
       structure that encodes essentially:

         hash_map<slot, hash_map<blockhash, vec<(txnhash, txn_result)>>>

       For each slot that is rooted.  Observe that we can't reuse the
       structure used for queries, since it's not grouped by slot, we
       would have to iterate all of the transactions to do this grouping
       which is not feasible.

       We can't add the slot to that index, since then query would not
       be fast.  Queries are just against (blockhash, txnhash) pairs,
       they don't know which slot might have included it.

       So we need a second index for this information.  The index is
       going to line up with what we described above, the root hash map
       will be probed, and the nested hash map will be chained.  The
       vector of results will also use a pool of pages.

       In this case the page pool is for a different reason: we know a
       sensible upper bound for the number of transactions that could be
       alive in the entire cache at any point in time, but we don't know
       quite how to bound it for a single slot or blockhash.  Well, we
       do: the bound is 524,288 per (slot, blockhash) pair but we would
       need to allocate all that memory up front.  Instead, we bound the
       total number of slots and transactions per slot, assume the
       transactions must be distributed somehow within the blockhashes,
       and then give some overhead for unoccupied page entries.

       The insertion process for this structure is similar to the one
       above, except the vector is not a chained map but just a regular
       vector.

         // 1. Find the (slot, blockhash) in the probed hash map.

            let by_slot_blockhash = hash_map[ slot ][ blockhash ];

         // 2. Request space for the transaction from the current page

            let page = by_slot_blockhash.pages.back();
            let idx = page.used.fetch_add( 1 );

         // 3. Write the transaction into the page and the map

            page.txns[ idx ] = txn;
            by_slot_blockhash.txn_count += 1;

       The final increment is OK even with concurrent inserts because
       no reader will try to observe the txn_count until the slot is
       rooted, at which point nothing could be being inserted into it
       and the txn_count will be finalized. */

#include "fd_rwlock.h"
#include "../fd_disco_base.h"

#define FD_TXNCACHE_ALIGN (128UL)

#define FD_TXNCACHE_MAGIC (0xF17EDA2CE5CAC4E0) /* FIREDANCE SCACHE V0 */

/* The duration of history to keep around in the txn cache before aging
   it out.  This must be at least 150, otherwise we could forget about
   transactions for blockhashes that are still valid to use, and let
   duplicate transactions make it into a produced block.
   
   Beyond 150, any value is valid.  The value used here, 300 comes from
   Agave, and corresponds to roughly 2 minutes of history assuming there
   are no forks, with an extra 12.8 seconds of history for slots that
   are in progress but have not rooted yet.  On a production validator
   without RPC support, the value should probably be configurable and
   always set to strictly 150. */

#define FD_TXNCACHE_DEFAULT_MAX_ROOTED_SLOTS (300UL)

/* A note on live slots ...

   The maximum number of live slots is the sum of the rooted and
   unrooted slots.  The rooted slots are explicitly capped at 300 for
   this structure (implying we keep around 2 minutes of history
   around for queries and snapshots).

   For the unrooted slots, we must root at least one slot in an epoch
   for an epoch transition to occur successfully to the next one, so
   assuming every slot is unconfirmed for some reason, and the prior
   epoch was rooted at the first slot in the epoch, and the next epoch
   is rooted at the last slot, there could be 

      432,000 + 432,000 - 31 = 863,969

   Live slots on the validator.  This is clearly impractical as each
   bank consumes a lof of memory to store slot state, so the
   validator would crash long before this.

   For now we just pick a number: 2048, and hope for the best.  This
   would represent the network failing to root a new slot for almost
   five minutes.

   TODO: Hmm... need to figure out what's reasonable here. */

#define FD_TXNCACHE_DEFAULT_MAX_LIVE_SLOTS (2048UL)

/* The Solana consensus protocol has an implied restriction on the number
   transactions in a slot.  A slot might have at most 48,000,000 CUs,
   but a transaction requires at least around 1500 CUs, so there could
   be at most 32,000 transactions in a slot.

   For Firedancer, we respect this limit when running in production, but
   for development and preformance tuning this limit is removed, and
   instead we will produce and accept at most 524,288 transactions per
   slot.  This is chosen arbitrarily and works out to around ~1.3M TPS,
   however such a value does not exist in the consensus protocol. */

#define FD_TXNCACHE_DEFAULT_MAX_TRANSACTIONS_PER_SLOT (524288UL)

struct fd_txncache_insert {
  uchar const * blockhash;
  uchar const * txnhash;
  ulong         slot;
  uchar const * result;
};

typedef struct fd_txncache_insert fd_txncache_insert_t;

struct fd_txncache_query {
  uchar const * blockhash;
  uchar const * txnhash;
};

typedef struct fd_txncache_query fd_txncache_query_t;

struct fd_txncache_snapshot_entry {
   ulong slot;
   uchar blockhash[ 32 ];
   uchar txnhash[ 20 ];
   ulong txn_idx;
   uchar result;
};

typedef struct fd_txncache_snapshot_entry fd_txncache_snapshot_entry_t;

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

/* fd_txncache_snapshot writes the current state of a txn cache into a
   binary format suitable for serving to other nodes via snapshot
   responses.  The write function is called in a streaming fashion with
   the binary data, the size of the data, and the ctx pointer provided
   to this function.  The write function should return 0 on success and
   -1 on failure, this function will propgate a failure to write back to
   the caller immediately, so this function also returns 0 on success
   and -1 on failure.

   IMPORTANT!  THIS ASSUMES THERE ARE NO CONCURRENT INSERTS OCCURING ON
   THE TXN CACHE AT THE ROOT SLOTS DURING SNAPSHOTTING.  OTHERWISE THE
   SNAPSHOT MIGHT BE NOT CONTAIN ALL OF THE DATA, ALTHOUGH IT WILL NOT
   CAUSE CORRUPTION.  THIS IS ASSUMED OK BECAUSE YOU CANNOT MODIFY A
   ROOTED SLOT.

   This is a cheap operation and will not cause any pause in insertion
   or query operations. */

int
fd_txncache_snapshot( fd_txncache_t * tc,
                      void *          ctx,
                      int ( * write )( uchar const * data, ulong data_sz, void * ctx ) );

/* fd_txncache_insert_batch inserts a batch of transaction results into
   a txn cache.  Assumes tc points to a txn cache, txns is a list of
   transaction results to be inserted, and txns_cnt is the count of the
   results list.  The insert copies data from the results and does not
   have any lifetime interest in the results memory provided once this
   call returns.

   Returns 1 on success and 0 on failure.  The only reason insertion can
   fail is because the txn cache is full, which should never happen in
   practice if the caller sizes the bounds correctly.  This is mostly
   here to support testing and fuzzing.

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
   respectively.

   This is a cheap, high performance, concurrent operation and can occur
   at the same time as queries and arbitrary other insertions. */

void
fd_txncache_query_batch( fd_txncache_t *             tc,
                         fd_txncache_query_t const * queries,
                         ulong                       queries_cnt,
                         void *                      query_func_ctx,
                         int ( * query_func )( ulong slot, void * ctx ),
                         int *                       out_results );

/* fd_txncache_set_txnhash_offset sets the correct offset value for the
   txn hash "key slice" in the blockcache and slotblockcache. This is used
   primarily for snapshot restore since in firedancer we always use the
   offset of 0. Return an error if the cache entry isn't found. */
int
fd_txncache_set_txnhash_offset( fd_txncache_t * tc,
                                ulong slot,
                                uchar blockhash[ 32 ],
                                ulong txnhash_offset );
FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_bank_txncache_h */
