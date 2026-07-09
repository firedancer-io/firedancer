#ifndef HEADER_fd_src_discof_tower_fd_tower_slot_rooted_h
#define HEADER_fd_src_discof_tower_fd_tower_slot_rooted_h

#include "../../disco/fd_disco_base.h"

/* This belongs most cleanly in fd_tower_tile.h, but the shred tile
   needs this type, and the shred tile is in disco, not discof.  Nothing
   in this header requires discof, so we factor it out so that the shred
   tile can just include this one. */

// #define FD_TOWER_SIG_SLOT_CONFIRMED (0)
// #define FD_TOWER_SIG_SLOT_DONE      (1)
// #define FD_TOWER_SIG_SLOT_DUPLICATE (2)
// #define FD_TOWER_SIG_SLOT_IGNORED   (3)
#define FD_TOWER_SIG_SLOT_ROOTED (4)

/* fd_tower_slot_rooted describes a Tower frag that notifies a new root.
   A block is rooted if it or any of its descendants reach max lockout
   per TowerBFT rules.  Once a block is rooted, it can never be rolled
   back (whereas technically, any of the above confirmation levels can
   be rolled back, but it is extremely unlikely and would only happen
   with a large percentage of malicious stake in the network).  This is
   the most important confirmation level for Firedancer's internal
   structures, since it is the only one that guarantees a block will
   never be rolled back, many structures "publish" a new root which
   prunes forks that do not descend from that root.

   Note even if tower never actually voted on a slot (and therefore the
   slot never became a tower root), tower will still send a root
   confirmation for that slot if a descendant is voted on and eventually
   rooted. */

struct fd_tower_slot_rooted {
  ulong     slot;
  fd_hash_t block_id;
};
typedef struct fd_tower_slot_rooted fd_tower_slot_rooted_t;

#endif /* HEADER_fd_src_discof_tower_fd_tower_slot_rooted_h */
