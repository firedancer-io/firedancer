#ifndef HEADER_fd_src_choreo_tower_fd_tower_forks_h
#define HEADER_fd_src_choreo_tower_fd_tower_forks_h

#include "../fd_choreo_base.h"

/* fd_tower_forks maintains fork information for tower, such as whether
   slots are on the same or different forks.  Importantly, parentage is
   based purely on slot numbers as opposed to block ids, so in cases of
   equivocation (duplicate blocks), tower will consider something an
   ancestor or descendant even if the block ids do not chain. This is
   different from fd_ghost and fd_notar, which both track block ids.

   Instead, fd_tower_forks maintains two block_id fields on every slot.
   The first is the block_id that we voted on for that slot.  In case of
   duplicates, this is the first version of the block we replayed and
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
  ulong     slot;               /* map key */
  ulong     parent_slot;        /* parent slot */
  int       confirmed;          /* whether this slot has been duplicate confirmed */
  fd_hash_t confirmed_block_id; /* the block_id that was duplicate confirmed */
  int       voted;              /* whether we voted for this slot yet */
  fd_hash_t voted_block_id;     /* the block_id we voted on for this slot */
  int       replayed;           /* whether we replayed this slot yet */
  fd_hash_t replayed_block_id;  /* the block_id we _first_ replayed for this slot */
};
typedef struct fd_tower_forks fd_tower_forks_t;

#define MAP_NAME    fd_tower_forks
#define MAP_T       fd_tower_forks_t
#define MAP_KEY     slot
#define MAP_MEMOIZE 0
#include "../../util/tmpl/fd_map_dynamic.c"

FD_PROTOTYPES_BEGIN

int
fd_tower_forks_is_slot_ancestor( fd_tower_forks_t * forks,
                                 ulong              descendant_slot,
                                 ulong              ancestor_slot );

int
fd_tower_forks_is_slot_descendant( fd_tower_forks_t * forks,
                                   ulong              ancestor_slot,
                                   ulong              descendant_slot );

/* fd_tower_forks_lowest_common_ancestor returns the lowest common
   ancestor of slot1 and slot 2.  There is always an LCA in a valid
   tower_forks tree (the root). */

ulong
fd_tower_forks_lowest_common_ancestor( fd_tower_forks_t * forks,
                                       ulong              slot1,
                                       ulong              slot2 );

/* fd_tower_forks_canonical_block_id returns what we think to be the
   correct block id for a given slot, based on what we've observed.

   We prioritize in-order:
   1. the confirmed block id
   2. our voted block id
   3. replayed block id

   This is the canonical order because it reflects what we think is the
   "true" block id given the information we have.

   Agave behaves similarly, except they "purge" their replay bank hash
   so they're always comparing the confirmed block id */

fd_hash_t const *
fd_tower_forks_canonical_block_id( fd_tower_forks_t * forks,
                                   ulong              slot );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_choreo_tower_fd_tower_forks_h */
