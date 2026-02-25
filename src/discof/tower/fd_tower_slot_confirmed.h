#ifndef HEADER_fd_src_discof_tower_fd_tower_slot_confirmed_h
#define HEADER_fd_src_discof_tower_fd_tower_slot_confirmed_h

/* This belongs most cleanly in fd_tower_tile.h, but the shred tile
   needs this type, and the shred tile is in disco, not discof.  Nothing
   in this header requires discof, so we factor it out so that the shred
   tile can just include this one. */

/* #define FD_TOWER_SIG_SLOT_DONE      (0) */
#define FD_TOWER_SIG_SLOT_CONFIRMED (1)
/* #define FD_TOWER_SIG_SLOT_IGNORED   (2)
   #define FD_TOWER_SIG_SLOT_DUPLICATE (3) */

/* fd_tower_slot_confirmed provides confirmed notifications of different
   Solana confirmation levels.  The levels are:

   - duplicate: a block is duplicate confirmed if it has received votes
     from at least 52% of stake in the cluster.

   - optimistic: a block is optimistically confirmed if it has received
     votes from at least 2/3 of stake in the cluster and we have already
     replayed it (bank is available).

   - cluster: same as optimistic, but may not have replayed / can be
     delivered out of order.

   - super: same as optimistic, but the stake threshold is 4/5
     of stake.

   - rooted: a block is rooted if it or any of its descendants reach max
     lockout per TowerBFT rules.

   For optimistic, super, and rooted confirmations, the tower tile
   guarantees that we have already replayed the block.  This is not the
   case for duplicate and cluster confirmations (a block can get
   duplicate or cluster confirmed before it has been replayed).
   Optimistic, super, and rooted confirmations are also
   guaranteed to be delivered in-order with no gaps from tower.  That
   is, if we receive a rooted frag for slot N, we will have already
   received rooted frags for any ancestor slots N - 1, N - 2, ... (if
   they are not skipped / on a different fork) and likewise for
   optimistic.

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
#define FD_TOWER_SLOT_CONFIRMED_SUPER      3
#define FD_TOWER_SLOT_CONFIRMED_ROOTED     4

struct fd_tower_slot_confirmed {
  ulong     slot;
  fd_hash_t block_id;
  ulong     bank_idx; /* only valid for OPTIMISTIC or ROOTED kind (otherwise ULONG_MAX) */
  int       kind;
};
typedef struct fd_tower_slot_confirmed fd_tower_slot_confirmed_t;

#endif /* HEADER_fd_src_discof_tower_fd_tower_slot_confirmed_h */
