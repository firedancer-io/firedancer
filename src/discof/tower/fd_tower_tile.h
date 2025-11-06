#ifndef HEADER_fd_src_discof_tower_fd_tower_tile_h
#define HEADER_fd_src_discof_tower_fd_tower_tile_h

#include "../../disco/topo/fd_topo.h"

#define FD_TOWER_SIG_SLOT_DONE      (0)
#define FD_TOWER_SIG_SLOT_CONFIRMED (1)

/* In response to finishing replay of a slot, the tower tile will
   produce both a block to vote for and block to reset to, and
   potentially advance the root. */

struct fd_tower_slot_done {

  /* The slot being voted on.  There is not always a vote slot (locked
     out, failed switch threshhold, etc.) and will be set to ULONG_MAX
     when there is no slot to vote on.  When set, the vote slot is used
     by the vote sending tile to do some internal book-keeping related
     to leader targeting. */

  ulong vote_slot;

  /* The slot to reset leader pipeline to.  Unlike vote slot, the reset
     slot is always set and represents the consensus fork to build on.
     It may be unchanged since the last slot done.  reset_block_id is
     a unique identifier in case there are multiple blocks for the reset
     slot due to equivocation. */

  ulong     reset_slot;
  fd_hash_t reset_block_id;

  /* This always contains a vote transaction with our current tower,
     regardless of whether there is a new vote slot or not (ie. vote
     slot can be ULONG_MAX and vote_txn will contain a txn of our
     current tower).  The vote is not yet signed.  This is necessary to
     support refreshing our last vote, ie. we retransmit our vote even
     when we are locked out / can't switch vote forks.

     TODO: Need to implement "refresh last vote" logic. */

  ulong vote_txn_sz;
  uchar vote_txn[ FD_TPU_MTU ];
};
typedef struct fd_tower_slot_done fd_tower_slot_done_t;

/* fd_tower_slot_confirmed provides confirmed notifications of different
   Solana confirmation levels.  The levels are:

   - duplicate: a block is duplicate confirmed if it has received votes
     from at least 52% of stake in the cluster.

   - optimistic: a block is optimistically confirmed if it has received
     votes from at least 2/3 of stake in the cluster and we have already
     replayed it (bank is available).

   - cluster: same as optimistic, but may not have replayed / can be
     delivered out of order.

   - rooted: a block is rooted if it or any of its descendants reach max
     lockout per TowerBFT rules.

   For optimistic and rooted confirmations, the tower tile guarantees
   that we have already replayed the block.  This is not the case for
   duplicate and cluster confirmations (a block can get duplicate or
   cluster confirmed before it has been replayed).  Optimistic and
   rooted confirmations are also guaranteed to be delivered in-order
   with no gaps from tower.  That is, if we receive a rooted frag for
   slot N, we will have already received rooted frags for any ancestor
   slots N - 1, N - 2, ... (if they are not skipped / on a different
   fork) and likewise for optimistic.

   Note even if tower never actually voted on a slot (and therefore the
   slot never became a tower root), tower will still send a rooted
   confirmation for that slot if a descendant is voted on and eventually
   rooted.

   The reason both optimistic and cluster confirmed exist is "cluster"
   is intended to be consumed by the Solana RPC protocol, whereas
   optimistic is intended for Firedancer-specific APIs (hence in-order
   and no gap guarantees) */

#define FD_TOWER_SLOT_CONFIRMED_DUPLICATE  0
#define FD_TOWER_SLOT_CONFIRMED_OPTIMISTIC 1
#define FD_TOWER_SLOT_CONFIRMED_CLUSTER    2
#define FD_TOWER_SLOT_CONFIRMED_ROOTED     3

struct fd_tower_slot_confirmed {
  ulong     slot;
  fd_hash_t block_id;
  int       kind;
};
typedef struct fd_tower_slot_confirmed fd_tower_slot_confirmed_t;

union fd_tower_msg {
  fd_tower_slot_done_t      slot_done;
  fd_tower_slot_confirmed_t slot_confirmed;
};
typedef union fd_tower_msg fd_tower_msg_t;

extern fd_topo_run_tile_t fd_tile_tower;

#endif /* HEADER_fd_src_discof_tower_fd_tower_tile_h */
