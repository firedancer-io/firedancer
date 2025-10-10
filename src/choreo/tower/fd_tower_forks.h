#ifndef HEADER_fd_src_choreo_tower_fd_tower_forks_h
#define HEADER_fd_src_choreo_tower_fd_tower_forks_h

#include "../fd_choreo_base.h"

/* fd_tower_forks maintains fork information for specifically tower,
   such as which slots are on the same or different forks.  Importantly,
   fork tracking is done with slot numbers, so in cases of equivocation
   (duplicate blocks), tower will still consider something an ancestor
   or descendant even if the blocks technically do not strictly build
   off each other (this can be detected by block_ids that do not chain).
   This is different from fd_ghost and fd_notar, which both track forks
   using block_id keys.

   Instead, fd_tower_forks maintains two block_id fields on every slot.
   The first is the block_id that was voted on for that slot.  In case
   of duplicates, this is the first version of the block we replayed and
   voted on.  The second is the block_id that was duplicate confirmed
   (voted on by >=52% of stake).  This may or may not equal the block_id
   we voted on.  It also may or may not be populated.  It is possible
   but highly unlikely for confirmed_block_id to never be populated
   before the slot is pruned during rooting.

   This behavior intentionally mirrors the Agave logic implemented in
   `make_check_switch_threshold_decision`.  Essentially, tower is unable
   to distinguish duplicates because the vote account format (in which
   towers are stored) only stores slot numbers and not block_ids. */

struct fd_tower_forks {
  ulong     slot;
  ulong     parent_slot;
  fd_hash_t voted_block_id;          /* the block_id we voted on for this slot */
  fd_hash_t reset_block_id;          /* the block_id we reset to as leader for this slot */
  fd_hash_t first_replayed_block_id; /* the block_id we replayed for this slot */
  fd_hash_t confirmed_block_id;      /* the block_id that was duplicate confirmed */
};
typedef struct fd_tower_forks fd_tower_forks_t;

#define MAP_NAME    fd_tower_forks
#define MAP_T       fd_tower_forks_t
#define MAP_KEY     slot
#define MAP_MEMOIZE 0
#include "../../util/tmpl/fd_map_dynamic.c"

FD_PROTOTYPES_BEGIN

int
fd_tower_forks_is_ancestor( fd_tower_forks_t * forks,
                            ulong              descendant_slot,
                            ulong              ancestor_slot );

int
fd_tower_forks_is_descendant( fd_tower_forks_t * forks,
                              ulong              ancestor_slot,
                              ulong              descendant_slot );

/* fd_tower_forks_same returns the lowest common ancestor of slot1 and
   slot 2.  There is always an LCA in a valid tower_forks (the root). */

ulong
fd_tower_forks_lowest_common_ancestor( fd_tower_forks_t * forks,
                                       ulong              slot1,
                                       ulong              slot2 );

ulong
fd_tower_forks_publish( fd_tower_forks_t * forks,
                        ulong              old_root,
                        ulong              new_root );

#endif /* HEADER_fd_src_choreo_tower_fd_tower_forks_h */
