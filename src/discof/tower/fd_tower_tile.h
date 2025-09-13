#ifndef HEADER_fd_src_discof_tower_fd_tower_tile_h
#define HEADER_fd_src_discof_tower_fd_tower_tile_h

#include "../../disco/topo/fd_topo.h"

/* In response to finishing replay of a slot, the tower tile will
   generate an update to the vote state, and potentially advance
   the root. */

struct fd_tower_slot_done {
   /* The reset slot is always set and represents the current fork to
      build on, it may be unchanged since the last slot done. */
  ulong reset_slot;

  /* The slot being voted on.  Currently every slot completion triggers
     a vote to be cast.  This is used by the vote sending tile to
     do some internal book-keeping related to leader targeting. */
  ulong vote_slot;

  /* Sometimes, finshing replay of a slot may cause a new slot to be
     rooted.  If this happens, new root will be 1 and both root_slot and
     root_block_id will be set to the new root values accordingly.
     Otherwise, `new_root` will be 0 and root_slot, root_block_id have
     undefined values. */
  int       new_root;
  ulong     root_slot;
  fd_hash_t root_block_id;

  /* TODO: This is not currently used but probably should be? */
  fd_hash_t block_id;

  /* It currently appears to be the case that every slot completion
     triggers a vote to be sent, so this contains the vote transaction
     payload and size.  The vote is not yet signed.

     TODO: Need to implement "refresh last vote" logic. */
  ulong vote_txn_sz;
  uchar vote_txn[ FD_TPU_MTU ];
};

typedef struct fd_tower_slot_done fd_tower_slot_done_t;

extern fd_topo_run_tile_t fd_tile_tower;

#endif /* HEADER_fd_src_discof_tower_fd_tower_tile_h */
