#ifndef HEADER_fd_src_discof_tower_fd_tower_tile_h
#define HEADER_fd_src_discof_tower_fd_tower_tile_h

#include "../../disco/topo/fd_topo.h"

/* In response to finishing replay of a slot, the tower tile will
   generate an update to the vote state, and potentially advance
   the root. */

struct fd_tower_slot_done {

  /* The slot being voted on.  There is not always a vote slot (locked
     out, failed switch threshhold, etc.) and will be set to ULONG_MAX
     when there is no slot to vote on.  When set, the vote slot is used
     by the vote sending tile to do some internal book-keeping related
     to leader targeting. */

  ulong     vote_slot;

  /* Sometimes, finshing replay of a slot may cause a new slot to be
     rooted.  If this happens, new root will be 1 and both root_slot and
     root_block_id will be set to the new root values accordingly.
     Otherwise, `new_root` will be 0 and root_slot will be ULONG_MAX and
     root_block_id will be all 32-bytes of all 0s (Base58 111...). */

  ulong     root_slot;
  fd_hash_t root_block_id;
  int       new_root;

  /* This always contains a vote transaction with our current tower,
     regardless of whether there is a new vote slot or not (ie. vote
     slot can be ULONG_MAX and vote_txn will contain a txn of our
     current tower).  The vote is not yet signed.  This is necessary to
     support refreshing our last vote, ie. we retransmit our vote even
     when we are locked out / can't switch vote forks.

     TODO: Need to implement "refresh last vote" logic. */

  ulong vote_txn_sz;
  uchar vote_txn[ FD_TPU_MTU ];

  /* The slot to reset leader pipeline to.  Unlike vote slot, the reset
     slot is always set and represents the consensus fork to build on.
     It may be unchanged since the last slot done. */

  ulong     reset_slot;
  fd_hash_t reset_block_id;

  /* The closet ancestor of reset_slot such that its vote stake is
     greater than 2/3 total epoch stake.  Might be ULONG_MAX at startup
     when tower's history is tiny. */
  ulong opt_confirmed_slot;
};

typedef struct fd_tower_slot_done fd_tower_slot_done_t;

extern fd_topo_run_tile_t fd_tile_tower;

#endif /* HEADER_fd_src_discof_tower_fd_tower_tile_h */
