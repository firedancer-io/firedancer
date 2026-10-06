#ifndef HEADER_fd_src_flamenco_runtime_fd_blockhashes_h
#define HEADER_fd_src_flamenco_runtime_fd_blockhashes_h

#include "../fd_flamenco_base.h"
#include "../../util/fd_hash32.h"

/* fd_blockhashes.h provides a "blockhash queue" API.  The blockhash
   queue is a consensus-relevant data structure that is part of the slot
   bank.

   See solana_accounts_db::blockhash_queue::BlockhashQueue. */

/* FD_BLOCKHASHES_MAX is the most live entries Agave's BlockhashQueue
   ever holds: the purge keeps ages 0..300 inclusive.

   Every entry carries the hash_index it was registered at, and ages are
   computed from hash_index (see fd_blockhashes_check_age), as in Agave.
   Indices are usually consecutive, but a snapshot may skip some: a
   blockhash registered more than once (agave-ledger-tool create-snapshot
   synthesizing slots with 0 hashes per tick, during a restart on an
   Alpenglow cluster) keeps only its newest hash_index, so the older
   index is simply absent.  The queue holds only the entries that exist,
   so a skipped index costs no space and needs no special handling.

   FD_BLOCKHASHES_DEQ_MAX is the deque capacity: the power of two that
   holds FD_BLOCKHASHES_MAX entries.  The runtime evicts by count when
   it is full; entries beyond age 300 that this retains are never valid,
   since every lookup bounds the age. */

#define FD_BLOCKHASHES_MAX     (301UL)
#define FD_BLOCKHASHES_DEQ_MAX (512UL)
FD_STATIC_ASSERT( !( FD_BLOCKHASHES_DEQ_MAX & (FD_BLOCKHASHES_DEQ_MAX-1UL) ), blockhashes_deq_max_pow2 );
FD_STATIC_ASSERT( FD_BLOCKHASHES_DEQ_MAX>=FD_BLOCKHASHES_MAX, blockhashes_deq_max_fits );

/* See solana_accounts_db::blockhash_queue::HashInfo. */

struct fd_blockhash_info {
  fd_hash_t hash;
  ulong     lamports_per_signature;
  ulong     hash_index; /* sequence number this blockhash was registered at */
  ushort    next;
};

typedef struct fd_blockhash_info fd_blockhash_info_t;

/* Declare a static size deque for the blockhash queue. */

#define DEQUE_NAME fd_blockhash_deq
#define DEQUE_T    fd_blockhash_info_t
#define DEQUE_MAX  FD_BLOCKHASHES_DEQ_MAX /* must be a power of 2 */
#include "../../util/tmpl/fd_deque.c"

/* Declare a separately chained hash map over the blockhash queue. */

#define FD_BLOCKHASH_MAP_CHAIN_MAX  (512UL)
#define FD_BLOCKHASH_MAP_FOOTPRINT (1048UL)

#define MAP_NAME          fd_blockhash_map
#define MAP_ELE_T         fd_blockhash_info_t
#define MAP_KEY_T         fd_hash_t
#define MAP_KEY           hash
#define MAP_IDX_T         ushort
#define MAP_NEXT          next
#define MAP_KEY_EQ(k0,k1) fd_hash_eq( (k0), (k1) )
#define MAP_KEY_HASH(k,s) fd_hash32( (k->uc), (s) )
#include "../../util/tmpl/fd_map_chain.c"

/* fd_blockhashes_t is the class representing a blockhash queue.

   It is a static size container housing sub-structures as plain old
   struct members.  Safe to declare as a local variable assuming the
   stack is sufficiently sized.  Entirely self-contained and position-
   independent (safe to clone via fd_memcpy and safe to map into another
   address space).

   Under the hood it is an array-backed double-ended queue, and a
   separately-chained hash index on top.  New entries are inserted to
   the **tail** of the queue.  Entries are kept in ascending hash_index
   order, so the tail is the newest entry and its hash_index is the last
   registered one; consecutive entries may differ by more than one (see
   above). */

struct fd_blockhashes {

  union {
    fd_blockhash_map_t map[1];
    uchar map_mem[ FD_BLOCKHASH_MAP_FOOTPRINT ];
  };

  fd_blockhash_deq_private_t d;

};

typedef struct fd_blockhashes fd_blockhashes_t;

FD_PROTOTYPES_BEGIN

fd_blockhashes_t *
fd_blockhashes_init( fd_blockhashes_t * mem,
                     ulong              seed );

/* fd_blockhashes_push_new adds a new slot to the blockhash queue. The
   caller fills the returned pointer with blockhash queue info
   (currently only lamports_per_signature).  Called as part of regular
   runtime processing.  The new entry's hash_index is one past the
   newest entry's (0 on an empty queue, like Agave's genesis hash).
   Evicts the oldest entry if the queue is full (practically always the
   case except for the first few blocks after genesis).  Aborts if hash
   is already present.  Always returns a valid pointer. */

fd_blockhash_info_t *
fd_blockhashes_push_new( fd_blockhashes_t * blockhashes,
                         fd_hash_t const *  hash );

/* fd_blockhashes_push_old behaves like the above, but adding a new
   oldest entry instead, with hash_index one below the oldest entry's.
   Returns NULL if there is no more space or no lower hash_index.
   Aborts if hash is already present.  Useful for testing. */

fd_blockhash_info_t *
fd_blockhashes_push_old( fd_blockhashes_t * blockhashes,
                         fd_hash_t const *  hash );

/* fd_blockhashes_pop_new removes the newest blockhash queue entry. */

void
fd_blockhashes_pop_new( fd_blockhashes_t * blockhashes );

/* fd_blockhashes_age returns the age of info, an entry of blockhashes:
   how many hash indices it is behind the newest entry.  Assumes the
   queue is not empty. */

FD_FN_PURE static inline ulong
fd_blockhashes_age( fd_blockhashes_t const *    blockhashes,
                    fd_blockhash_info_t const * info ) {
  return fd_blockhash_deq_peek_tail_const( blockhashes->d.deque )->hash_index - info->hash_index;
}

/* fd_blockhashes_check_age returns 1 if blockhash is in the queue with
   an age of at most max_age, and 0 otherwise. */

FD_FN_PURE int
fd_blockhashes_check_age( fd_blockhashes_t const * blockhashes,
                          fd_hash_t const *        blockhash,
                          ulong                    max_age );

FD_FN_PURE static inline fd_hash_t const *
fd_blockhashes_peek_last_hash( fd_blockhashes_t const * blockhashes ) {
  if( FD_UNLIKELY( fd_blockhash_deq_empty( blockhashes->d.deque ) ) ) return NULL;
  return &fd_blockhash_deq_peek_tail_const( blockhashes->d.deque )->hash;
}


FD_FN_PURE static inline fd_blockhash_info_t const *
fd_blockhashes_peek_last( fd_blockhashes_t const * blockhashes ) {
  if( FD_UNLIKELY( fd_blockhash_deq_empty( blockhashes->d.deque ) ) ) return NULL;
  return fd_blockhash_deq_peek_tail_const( blockhashes->d.deque );
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_blockhashes_h */
