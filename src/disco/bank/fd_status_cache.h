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

      /* Assume the validator can process 2^21 = 2,097,152 TPS.  This is
         less than 2^20 transactions per slot.  In the worst case, every
         transaction sent to the validator is for the same blockhash,
         so we could have 150 * 2^20 = 157,286,400 transactions in the
         blockhash.

         Each chunk can contain results for up to 2^16 = 65,536
         transactions so we potentially will need 2,400 chunks to store
         all the transactions in each blockhash.
         
         This is an estimate for Firedancer, but is very strictly
         bounded for the existing Solana consensus, which is limited
         by the compute unit limit in each slot to around 32k. */
      ulong chunk_cnt;
      ulong chunks[ 2400 ];
   } by_blockhash[ 450 ];

   /* The maximum number of live slots is the sum of the rooted and
      unrooted slots.  The rooted slots are explicitly capped at 300 for
      this structure (implying we keep around 2 minutes of history
      around for queries and snapshots).

      At least one slot must be rooted in an epoch, so the maximum
      number of unrooted slots is 432000, assuming 
      The max number of unrooted slots happens when the network forks at
      every slot.  
   
   Assume at some slot the network forks, so there are two different
      blockhashes live for this slot, which we could choose between.

      Assume both of those forks then fork again, so now there are four
      different blockhashes live for this slot.  This can theoretically
      continue forever, and the number of live forks, and number of
      forks at any particular slot is unbounded.

      At some point we need to bound it rather than letting the system
      run out memory and crash, so this status cache assumes there will
      be at most 4096 unrooted slots alive at any one time.  This could
      handle a case where the network forks 12 times consecutively,
      which seems unlikely based on the convergence of the consensus
      model, although is definitely possible (if the network also
      stopped voting at the same time the leaders started forking).  It
      is reasonable to assume in scenarios like this that the network is
      borked and it is ok to crash (some other component likely already
      has).

      In the typical case of very few unrooted slots, this makes the
      hashmap lookups fast because we do not have to probe more than
      once. */

   struct {

   } by_slot[ 300+432000 ];



   /* It is tricky to bound the number of transactions we might need
      to store... there's a maximum number of rooted slots, but there
      might be many unrooted slots.  TODO ??? */  Map<Slot, Map<BlockHash, Map<Txn, Result>>>
   struct {
      ushort len;
      struct {
         uchar written;
         uchar txhash[ 20 ];
         uchar result[ 40 ];
      } txns[ 65536 ];
   } chunks[ 4800 ];
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
