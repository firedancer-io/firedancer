#ifndef HEADER_fd_src_flamenco_runtime_fd_txncache_h
#define HEADER_fd_src_flamenco_runtime_fd_txncache_h

/* A txn cache is a concurrent set storing the message hashes of
   transactions which have already executed.  Note the structure is
   keyed by message hash, not signature, otherwiwe a double spend might
   be possible due to signature malleability.

   The txn cache is designed to do two operations fast,

     (a) Insertion.  Insertion is done by both the leader pipeline and
         the replay stage, with an insertion for every transaction that
         is executed, potentially over 1M per second.

     (b) Query.  The leader pipeline queries the status of transactions
         before executing them to ensure that it does not execute
         anything twice.  The replay stage queries to make sure that
         blocks do not contain duplicate transactions.

   Both of these operations are concurrent and lockless, assuming there
   are no other (non-insert/query) operations occuring on the txn cache.
   Most other operations lock the entire structure and will prevent both
   insertion and query from proceeding, but are rare (once per slot) so
   it's OK.

   The txn cache is somewhat CPU and memory sensitive.  To store message
   hashes requires 20 bytes (only the first 20 of the 32 bytes of the
   hash are used, since this is sufficient to avoid collisions).
   Without any other overhead, and 31 unrooted blocks with 41,019
   transactions each (the current maximum), the txn cache would need to
   store

     31 * 41,019 * 20 = 0.025 GB

   Of memory.  But, we can't query, insert, and remove quickly from a
   flat array.  We make a few trade-offs to achieve good performance
   without bloating memory completely.  In particular the transactions
   to be queried are stored in a structure that looks like a

     multi_map<blockhash, hash_map<txnhash, vec<fork_idx>>>

   Note that there can be multiple duplicate blockhashes in the map, so
   it is a multimap.  This is to handle the extremely rare degenerate
   case where a leader equivocates a block, but keeps the transactions
   the same and just fiddles with the shred data or padding a little
   bit.  This keeps blockhash the same, but creates a new block ID
   (fork).  We cannot stick both forks in the same blockhash entry
   because later, when one fork is rooted, we need to be able to purge
   all transactions in the non-rooted equivocation, otherwise we would
   violate our own invariants around the max active banks.  (Rooting one
   equivocation should fully evict transactions belonging to the other
   equivocations, which would be impossible if they were under one
   blockhash).

   Both hash maps are chained hash maps, and for the txnhash map items
   come from a pool of pages of transactions.  We use pages of
   transactions to support fast removal of a blockhash from the top
   level map.

   This adds additional memory overhead, a blockhash with only one
   transaction in it will still consume a full page (16,384) of
   transactions of memory.  Allocating a new transaction page to a
   chained map is rare (once every 16,384 inserts) so the cost amortizes
   to zero.  Creating a blockhash happens once per blockhash, so also
   amortizes to zero, the only operation we care about is then the
   simple insert case with an unfull transaction page into an existing
   blockhash.  This can be done with two compare-and-swaps,

      // 1. Find the blockhash in the probed hash map.

         let by_blockhash = multi_map[ blockhash ];

      // 2. Request space for the transaction from the current page

         let page = by_blockhash.pages.back();
         let idx = page.used.compare_and_swap( current, current+1 );

      // 3. Write the transaction into the page and the map

         page.txns[ idx ] = txn;
         page.txns[ idx ].next = by_blockhash.txns[ txnhash ].idx;
         by_blockhash.txns[ txnhash ].head.compare_and_swap( current, idx );

   Step 1 is fast assuming equivocation is rare, since there will only
   ever be one matching blockhash in the multi map.

   Removal of a blockhash from this structure is simple because it does
   not need to be concurrent (it is once per slot).  We take a write
   lock, restore the pages in the blockhash to the pool, and then mark
   the space in the hash_map as empty.  Page restoration is a simple
   memcpy.

   All of this would be complicated by nonce transactions, which can
   reference any blockhash, and so a transaction could appear in the
   txn cache under any blockhash.  But when dealing with these we make
   a simple observation: double spend is already cryptographically
   prevented by the nonce mechanism itself, so we do not need to store
   or check them.  Agave does store them for RPC related reasons (they
   want to be able to query the status of nonce transactions that have
   already executed).  It is therefore an error to insert any nonce
   transactions into the txn cache, and the caller is responsible for
   ensuring this does not happen.

   There is one minor complication with this, which is that Agave
   snapshots serve out the status cache with nonce transactions already
   in it.  This structure assumes these will not get inserted, so it is
   up to the snapshot loading code to filter out all blockhashes which
   are nonce blockhashes (not in the recent blockhashes sysvar). */

#include "fd_txncache_shmem.h"

#define FD_TXNCACHE_ALIGN (128UL)

#define FD_TXNCACHE_MAGIC (0xF17EDA2CE5CAC4E0) /* FIREDANCE SCACHE V0 */

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

   Max live slots is global value for the validator, indicating the
   maximum number of forks which can be active at any one time.  It
   should be the same as "max active banks" in the replay system.  This
   number counts any unrooted banks, plus one for the most recent root
   bank.

   Max transactions per slot should be some consensus derived upper
   bound on the number of transactions that can appear in a slot.  This
   value must be valid else it is a security issue, where an attacker
   can cause the txn cache to run out of space and abort the program.

   fd_txncache_join joins the caller to a txn cache. Assumes shtc points
   to the first byte of the memory region holding the state.  Returns a
   local handle to the join on success (this is not necessarily a simple
   cast of the address) and NULL on failure (logs details). */

FD_FN_CONST ulong
fd_txncache_align( void );

FD_FN_CONST ulong
fd_txncache_footprint( ulong max_live_slots );

void *
fd_txncache_new( void *                ljoin,
                 fd_txncache_shmem_t * shmem );

fd_txncache_t *
fd_txncache_join( void * ljoin );

void
fd_txncache_reset( fd_txncache_t * tc );

/* fd_txncache_attach_child notifies the txncache that a new child bank
   has been created, off some parent.  This must be called before any
   transaction executed on this child fork is inserted.  The parent fork
   id must be a fork ID previously returned from attach child, which
   must be still valid (the current root bank or a child of it).

   It is assumed that there are less than max_live_slots number of
   unrooted (or the active root) banks active prior to calling,
   otherwise it is an error.

   Attaching a child takes a write lock on the entire structure, which
   is an expensive stall for any other concurrent operations, but it is
   OK because the operation is otherwise cheap and it is called rarely
   (once every 400ms or so). */

fd_txncache_fork_id_t
fd_txncache_attach_child( fd_txncache_t *       tc,
                          fd_txncache_fork_id_t parent_fork_id );

void
fd_txncache_attach_blockhash( fd_txncache_t *       tc,
                              fd_txncache_fork_id_t fork_id,
                              uchar const *         blockhash );

void
fd_txncache_finalize_fork( fd_txncache_t *       tc,
                           fd_txncache_fork_id_t fork_id,
                           ulong                 txnhash_offset,
                           uchar const *         blockhash );

/* fd_txncache_advance_root is called when the root slot of the chain
   has advanced, in which case old message hashes (referncing
   blockhashes that could no longer be valid) can be removed from the
   cache.

   Advancing the root takes a write lock on the structure, which is an
   expensive stall for any other concurrent operations, but it is OK
   because the operation is otherwise cheap and it is called rarely
   (once every 400ms or so). */

void
fd_txncache_advance_root( fd_txncache_t *       tc,
                          fd_txncache_fork_id_t fork_id );

/* fd_txncache_insert inserts a transaction hash into the txn cache on
   the provided fork.  The insert copies data from the hashes and does
   not have any lifetime interest in the hashes memory provided once
   this call returns.

   Insertion cannot fail, as it is assume the caller is respecting the
   invariants of the structure.  If there is no space internally to
   insert another transaction, the program is aborted with an error.

   This is a cheap, high performance, concurrent operation and can occur
   at the same time as queries and arbitrary other insertions. */

void
fd_txncache_insert( fd_txncache_t *       tc,
                    fd_txncache_fork_id_t fork_id,
                    uchar const *         blockhash,
                    uchar const *         txnhash );

/* fd_txncache_query queries the txncache to determine if the given
   txnhash (referencing the given blockhash) exists on the provided fork
   or not.

   Returns 1 if the transaction exists on the provided fork and 0 if it
   does not.

   This is a cheap, high performance, concurrent operation and can occur
   at the same time as queries and arbitrary other insertions. */

int
fd_txncache_query( fd_txncache_t *       tc,
                   fd_txncache_fork_id_t fork_id,
                   uchar const *         blockhash,
                   uchar const *         txnhash );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_txncache_h */
