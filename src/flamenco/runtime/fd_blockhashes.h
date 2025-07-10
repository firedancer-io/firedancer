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
};

typedef struct fd_blockhash_info fd_blockhash_info_t;

/* Declare a static size deque for the blockhash queue. */

#define DEQUE_NAME fd_blockhash_deq
#define DEQUE_T    fd_blockhash_info_t
#define DEQUE_MAX  FD_BLOCKHASHES_MAX
#include "../../util/tmpl/fd_deque.c"

/* Declare a separately chained hash map over the blockhash queue. */

#define FD_BLOCKHASH_MAP_CHAIN_MAX (512UL)
#define FD_BLOCKHASH_MAP_FOOTPRINT (300UL) /* TODO */

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
   address space). */

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
fd_blockhashes_recover( fd_blockhashes_t *                 blockhashes,
                        fd_block_hash_vec_global_t const * src );

fd_blockhash_info_t *
fd_blockhashes_push( fd_blockhashes_t * blockhashes,
                     fd_hash_t const *  hash );

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
