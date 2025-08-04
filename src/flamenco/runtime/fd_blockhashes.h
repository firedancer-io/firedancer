#ifndef HEADER_fd_src_flamenco_runtime_fd_blockhashes_h
#define HEADER_fd_src_flamenco_runtime_fd_blockhashes_h

#include "../types/fd_types.h"
#include "../../funk/fd_funk_base.h" /* fd_funk_rec_key_hash1 */

/* fd_blockhashes.h provides a "blockhash queue" API.  The blockhash
   queue is a consensus-relevant data structure that is part of the slot
   bank.

   See solana_accounts_db::blockhash_queue::BlockhashQueue. */

#define FD_BLOCKHASHES_MAX 301

/* See solana_accounts_db::blockhash_queue::HashInfo. */

struct fd_blockhash_info {
  fd_hash_t           hash;
  fd_fee_calculator_t fee_calculator;
  ushort              next;
  ushort              exists : 1;
};

typedef struct fd_blockhash_info fd_blockhash_info_t;

/* Declare a static size deque for the blockhash queue. */

#define DEQUE_NAME fd_blockhash_deq
#define DEQUE_T    fd_blockhash_info_t
#define DEQUE_MAX  512 /* must be a power of 2 */
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
#define MAP_KEY_HASH(k,s) fd_funk_rec_key_hash1( (k->uc), 0, (s) )
#include "../../util/tmpl/fd_map_chain.c"

/* fd_blockhashes_t is the class representing a blockhash queue.

   It is a static size container housing sub-structures as plain old
   struct members.  Safe to declare as a local variable assuming the
   stack is sufficiently sized.  Entirely self-contained and position-
   independent (safe to clone via fd_memcpy and safe to map into another
   address space).

   Under the hood it is an array-backed double-ended queue, and a
   separately-chained hash index on top.  New entries are inserted to
   the **tail** of the queue. */

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

/* fd_blockhashes_push_new adds a new slot to the blockhash queue.
   The caller fills the returned pointer with blockhash queue info
   (currently only lamports_per_signature).  Called as part of regular
   runtime processing.  Evicts the oldest entry if the queue is full
   (practically always the case except for the first few blocks after
   genesis).  Always returns a valid pointer. */

fd_blockhash_info_t *
fd_blockhashes_push_new( fd_blockhashes_t * blockhashes,
                         fd_hash_t const *  hash );

/* fd_blockhashes_push_old behaves like the above, but adding a new
   oldest entry instead.  Returns NULL if there is no more space.
   Useful for testing. */

fd_blockhash_info_t *
fd_blockhashes_push_old( fd_blockhashes_t * blockhashes,
                         fd_hash_t const *  hash );

/* fd_blockhashes_pop_new removes the newest blockhash queue entry. */

void
fd_blockhashes_pop_new( fd_blockhashes_t * blockhashes );

FD_FN_PURE int
fd_blockhashes_check_age( fd_blockhashes_t const * blockhashes,
                          fd_hash_t const *        blockhash,
                          ulong                    max_age );

FD_FN_PURE static inline fd_hash_t const *
fd_blockhashes_peek_last( fd_blockhashes_t const * blockhashes ) {
  if( FD_UNLIKELY( fd_blockhash_deq_empty( blockhashes->d.deque ) ) ) return 0;
  return &fd_blockhash_deq_peek_tail_const( blockhashes->d.deque )->hash;
}

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_runtime_fd_blockhashes_h */
