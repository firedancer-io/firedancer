#ifndef HEADER_fd_src_discof_tower_fd_tower_tile_h
#define HEADER_fd_src_discof_tower_fd_tower_tile_h

#include "../../disco/topo/fd_topo.h"

#define FD_TOWER_SIG_SLOT_DONE           (0)
#define FD_TOWER_SIG_DUPLICATE_CONFIRMED (1)

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
     It may be unchanged since the last slot done. */

  ulong     reset_slot;
  fd_hash_t reset_block_id;

  /* Sometimes, finishing replay of a slot may cause a new slot to be
     rooted.  If this happens, new root will be 1 and both root_slot and
     root_block_id will be set to the new root values accordingly.
     Otherwise, new_root will be 0 and root_slot and root_block_id will
     be undefined.  Note it is possible tower emits a new root slot but
     the new root slot's block_id is unavailable (eg. it is an old tower
     vote that precedes the snapshot slot).  In this case new_root will
     _not_ be set to 1. */

  ulong     root_slot;
  fd_hash_t root_block_id;

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

struct fd_tower_duplicate_confirmed {
  ulong     slot;
  fd_hash_t block_id;
};
typedef struct fd_tower_duplicate_confirmed fd_tower_duplicate_confirmed_t;

union fd_tower_msg {
  fd_tower_slot_done_t           slot_done;
  fd_tower_duplicate_confirmed_t duplicate_confirmed;
};
typedef union fd_tower_msg fd_tower_msg_t;

extern fd_topo_run_tile_t fd_tile_tower;

#endif /* HEADER_fd_src_discof_tower_fd_tower_tile_h */
