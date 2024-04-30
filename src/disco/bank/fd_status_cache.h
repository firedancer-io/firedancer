#ifndef HEADER_fd_src_disco_bank_status_cache_h
#define HEADER_fd_src_disco_bank_status_cache_h

#include "../fd_disco_base.h"

/* A status cache is a concurrent map for saving the result (status) of
   transactions that have executed.  In addition supporting fast concurrent
   insertion and query of transaction results, the status cache supports
   serialization of its state into a standard bincode format for serving
   the state to other nodes via. snapshot responses, and then restoring
   snapshots produced by other nodes.

   The status cache is designed to do two operations fast,

     (a) Insertion.  Insertion is done by both the leader pipeline and
         the replay stage, with an insertion for every transaction that
         is executed, potentially over 1M per second.

     (b) Query.  The leader pipeline queries the status of transactions
         before executing them to ensure that it does not execute
         anything twice.

   Both of these operations are concurrent and lockless, assuming there
   are no other operations occuring on the status cache.  Most other
   operations lock the entire structure and will prevent both insertion
   and query from proceeding. */

#define FD_STATUS_CACHE_ALIGN     (128UL)
#define FD_STATUS_CACHE_FOOTPRINT (???)

struct fd_txn_result_t {
   uchar * blockhash;
   uchar * txhash;
   ulong   slot;
   uchar   status;
};

typedef struct fd_txn_result_t fd_txn_result_t;

struct fd_txn_status_t {
   ulong slot;
   uchar status;
};

typedef struct fd_txn_status_t fd_txn_status_t;

struct fd_status_cache_private {
   fd_rwlock_t lock;

   ulong root_slots[ 300 ];
   ulong root_slots_cnt;

   /* A note on forks ...

      The maximum number of live slots is the sum of the rooted and
      unrooted slots.  The rooted slots are explicitly capped at 300 for
      this structure (implying we keep around 2 minutes of history
      around for queries and snapshots).

      For the unrooted slots, we must root at least one slot in an epoch
      for an epoch transition to occur successfully to the next one, so
      assuming every slot is forked (there is no exponential forking,
      since a leader is assumed not to equivocate and produce more than
      one block per slot), and the prior epoch was rooted at the first
      slot in the epoch, and the next epoch is rooted at the last slot,
      there could be 

         432,000 + 432,000 - 31 = 863,969

      Live slots on the validator.  This is clearly impractical as each
      bank consumes a lof of memory to store fork state, so the
      validator would crash long before this.

      Assume that in a completely dysfunctional network, the probability
      of a fork at any given slot is 99.5%, a/k/a the network forks
      almost every single slot.  The probability that we have more than
      3796 live forks at any moment is then 0.005^3796 ~ 200,000,000
      (one in 200 million).

      TODO: This probably isn't right, we could fork, then not fork,
      then fork again, and what matters is when we root.  What bounds
      the rooting duration? */
   struct {
      uchar blockhash[ 32 ];

      /* The highest slot we have seen that contains a transaction
         referencing this blockhash.  The blockhash entry will not
         be purged until the slot is rooted and there are 300
         rooted slots higher than this. */

      ulong highest_slot;

      /* To save memory, the Agave validator decided to truncate
         the hash of transactions stored in this memory to 20 bytes
         rather than 32 bytes.  The bytes used are not the first 20 as
         you might expect, but instead the first 20 starting at some
         random offset into the transaction hash (starting between 0
         and len(hash)-20, a/k/a 44 for signatures, and 12 for hashes).
         
         In an unfortunate turn, the offset is also propogated to peers
         via. snapshot responses, which only communicate the offset and
         the respective 20 bytes.  To make sure we are deduplicating
         incoming transactions correctly, we must replicate this system
         even though it would be easier to just always take the first
         20 bytes.  For transactions that we insert into the cache
         ourselves, we do just always use a key_offset of zero, so this
         is only nonzero when constructed form a peer snapshot. */

      ulong key_offset;

      /* Now... assume the validator can process 2^19 = 524,288
         transactions per slot.  This is strictly true due to consensus
         limits which bound the transactions per slot to around 32k.  We
         use 2^19 though assuming a full Firedancer would have a
         consensus limit of 2^19 transactions per slot instead. */

      uint buckets[ 524288UL ];
   } by_blockhash[ 4096UL ];

   struct {
      ulong slot;
      uchar hash[ 20 ];
      uchar result[ 40 ];

      uint next_by_blockhash;
      uint next_by_slot_blockhash;
   } by_blockhash_pool[ 524288UL*(300UL+32UL) ];

   struct {
      ulong slot;

      /* Each slot can have two forks, assuming no equivocated slots,
         which is a fork where it wasn't produced, and a fork where it
         was.  The blockhash can be used for up to 150 slots after it
         exists, creating a bound of 300 blockhashes per slot. */

      struct {
         uchar blockhash[ 32 ];
         
         ulong key_offset;
         uint  head;
      } by_slot_blockhash[ 300 ];
   } by_slot[ 4096 ];
};

typedef struct fd_status_cache_private fd_status_cache_t;

FD_PROTOTYPES_BEGIN

/* fd_status_cache_{align,footprint} give the needed alignment and
   footprint of a memory region suitable to hold a status cache.
   fd_status_cache_{align,footprint} return the same value as
   FD_STATUS_CACHE_{ALIGN,FOOTPRINT}.

   fd_status_cache_new formats memory region with suitable alignment and
   footprint suitable for holding a status cache.  Assumes shmem points
   on the caller to the first byte of the memory region owned by the
   caller to use.  Returns shmem on success and NULL on failure (logs
   details).  The memory region will be owned by the state on successful
   return.  The caller is not joined on return.

   fd_status_cache_join joins the caller to a status cache. Assumes shsc
   points to the first byte of the memory region holding the state.
   Returns a local handle to the join on success (this is not
   necessarily a simple cast of the address) and NULL on failure (logs
   details).

   fd_status_cache_leave leaves the caller's current local join to a
   status cache.  Returns a pointer to the memory region holding the
   state on success (this is not necessarily a simple cast of the
   address) and NULL on failure (logs details).  The caller is not
   joined on successful return.

   fd_status_cache_delete unformats a memory region that holds a status
   cache.  Assumes shsc points on the caller to the first byte of the
   memory region holding the state and that nobody is joined.  Returns a
   pointer to the memory region on success and NULL on failure (logs
   details).  The caller has ownership of the memory region on
   successful return. */

FD_FN_CONST ulong
fd_status_cache_align( void );

FD_FN_CONST ulong
fd_status_cache_footprint( void );

void *
fd_status_cache_new( void * shmem );

fd_status_cache_t *
fd_status_cache_join( void * shsc );

void *
fd_status_cache_leave( fd_status_cache_t * sc );

void *
fd_status_cache_delete( void * shsc );

/* fd_status_cache_register_root registers a root slot in a status
   cache.  Only 300 roots can exist in the status cache at once, after
   which the oldest roots will be purged.

   Purging a root means it cannot be served in a snapshot response,
   although transactions in the root may or may not still be present.
   Transaction status is definitely removed once all roots referencing
   the blockhash of the transaction are removed from the status cache.
   
   This is neither cheap or expensive, it will pause all insertion and
   query operations but only momentarily until any old slots can be
   purged from the cache. */

void
fd_status_cache_register_root_slot( fd_status_cache_t * sc,
                                    ulong               slot );

/* fd_status_cache_root_slots returns the list of live slots currently
   tracked by the status cache.  There will be at most 300 slots, which
   will be written into the provided out_slots.  It is assumed sc points
   to a status cache and out_slots has space for at least 300 slots.
   
   This is a cheap operation and will not cause any pause in insertion
   or query operations. */

void
fd_status_cache_root_slots( fd_status_cache_t * sc,
                            ulong *             out_slots[ static 300 ] );

/* fd_status_cache_restore restores the state of the status cache from a
   list produced by fd_status_cache_snapshot.  The list is merged into
   the status cache, and updates it in-place.  If restoring entries
   causes new root slots to be registered, old ones may be purged as
   described in fd_status_cache_register_root_slot.

   This operation stalls the status cache for the duration of the
   restore and no insertions or queries will be serviced. */

void
fd_status_cache_restore( fd_status_cache_t *               sc,
                         fd_status_cache_restore_t const * restores,
                         ulong                             restores_cnt );

/* fd_status_cache_snapshot */

void
fd_status_cache_snapshot( fd_status_cache_t * sc );

/* fd_status_cache_insert_batch inserts a batch of transaction results
   into a status cache.  Assumes sc points to a status cache, txns is a
   list of transaction results to be inserted, and txns_cnt is the count
   of the results list.  The insert copies data from the results and
   does not have any lifetime interest in the results memory provided
   once this call returns.
   
   This is a cheap, high performance, concurrent operation and can occur
   at the same time as queries and arbitrary other insertions. */

void
fd_status_cache_insert_batch( fd_status_cache_t *              sc,
                              fd_status_cache_insert_t const * txns,
                              ulong                            txns_cnt );

/* fd_status_cache_query_batch queries a batch of transactions to
   determine if they exist in the status cache or not.  The queries have
   an ambiguous slot, but must match both the blockhash and txnhash.

   Assumes sc points to a status cache, queries is a list of queries to
   be executed, and queries_cnt is the count of the queries list.
   out_results must be at least as large as queries_cnt and will be
   filled with 0 or 1 if the transaction is not present or present
   respectively.

   This is a cheap, high performance, concurrent operation and can occur
   at the same time as queries and arbitrary other insertions. */

void
fd_status_cache_query_batch( fd_status_cache_t *             sc,
                             fd_status_cache_query_t const * queries,
                             ulong                           queries_cnt,
                             int *                           out_results );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_bank_status_cache_h */
