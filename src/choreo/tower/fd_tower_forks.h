#ifndef HEADER_fd_src_choreo_tower_fd_tower_forks_h
#define HEADER_fd_src_choreo_tower_fd_tower_forks_h

#include "../fd_choreo_base.h"
#include "fd_tower_accts.h"

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
  fd_hash_t replayed_block_id;  /* the block_id we _first_ replayed for this slot */
  ulong     bank_idx;           /* pool idx of the bank as of this replayed block */
};
typedef struct fd_tower_forks fd_tower_forks_t;

#define MAP_NAME           fd_tower_forks
#define MAP_T              fd_tower_forks_t
#define MAP_KEY            slot
#define MAP_KEY_NULL       ULONG_MAX
#define MAP_KEY_INVAL(key) ((key)==ULONG_MAX)
#define MAP_MEMOIZE        0
#include "../../util/tmpl/fd_map_dynamic.c"

/* using map chain for ease of threading a linkedlist through the leaves
   for fast iteration. (needed for switch check) */
struct fd_tower_leaf {
   ulong     slot;               /* map key */
   ulong     hash;               /* reserved for fd_map_chain and fd_pool */
   ulong     next;               /* next leaf in the linked list */
   ulong     prev;               /* prev leaf in the linked list */
};
typedef struct fd_tower_leaf fd_tower_leaf_t;

#define MAP_NAME    fd_tower_leaves_map
#define MAP_ELE_T   fd_tower_leaf_t
#define MAP_KEY     slot
#define MAP_NEXT    hash
#include "../../util/tmpl/fd_map_chain.c"

#define POOL_NAME fd_tower_leaves_pool
#define POOL_T    fd_tower_leaf_t
#define POOL_NEXT hash
#include "../../util/tmpl/fd_pool.c"

#define DLIST_NAME  fd_tower_leaves_dlist
#define DLIST_ELE_T fd_tower_leaf_t
#include "../../util/tmpl/fd_dlist.c"

/* tower_forks also tracks a map of lockout intervals.
   We need to track a list of lockout intervals per validator per slot.
   Ex.
   After executing slot 33, validator A votes for slot 32, has a tower
       vote  | confirmation count | lockout interval
       ----- | -------------------|------------------
       32    |  1                 | [32, 33]
       2     |  3                 | [2,  6]
       1     |  4                 | [1,  9]

   Thw lockout interval is the interval of slots that the validator is
   locked out from voting for if they want to switch off that vote. For
   example if validator A wants to switch off fork 1, they have to wait
   until slot 9.

   Agave tracks a similar structure.

   key: for an interval [vote, vote+lockout] for validator A,
   it is stored like:
   vote+lockout -> (vote, validator A) -> (2, validator B) -> (any other vote, any other validator)

   Since a validator can have up to 31 entries in the tower, and we have
   a max_vote_accounts, we can pool the interval objects to be
   31*max_vote_accounts entries PER bank / executed slot. We can also
   string all the intervals of the same bank together as a linkedlist.
*/

struct fd_lockout_intervals {
  ulong     key; /* fork_slot << 32 | end_interval */
  ulong     next; /* reserved for fd_map_chain and fd_pool */
  fd_hash_t vote_account_pubkey;
  ulong     interval_start; /* start of interval, also vote slot */
};
typedef struct fd_lockout_intervals fd_lockout_intervals_t;

#define MAP_NAME    fd_lockout_intervals_map
#define MAP_ELE_T   fd_lockout_intervals_t
#define MAP_MULTI   1
#define MAP_KEY     key
#define MAP_NEXT    next
#include "../../util/tmpl/fd_map_chain.c"

#define POOL_NAME fd_lockout_intervals_pool
#define POOL_T    fd_lockout_intervals_t
#define POOL_NEXT next
#include "../../util/tmpl/fd_pool.c"

struct fd_lockout_slots {
  ulong   fork_slot;
  ulong   next;      /* reserved for fd_map_chain and fd_pool */
  ulong   interval_end;
};
typedef struct fd_lockout_slots fd_lockout_slots_t;

#define MAP_NAME    fd_lockout_slots_map
#define MAP_ELE_T   fd_lockout_slots_t
#define MAP_MULTI   1
#define MAP_KEY     fork_slot
#define MAP_NEXT    next
#include "../../util/tmpl/fd_map_chain.c"

#define POOL_NAME fd_lockout_slots_pool
#define POOL_T    fd_lockout_slots_t
#define POOL_NEXT next
#include "../../util/tmpl/fd_pool.c"

static inline ulong
fd_lockout_interval_key( ulong fork_slot, ulong end_interval ) {
  return (fork_slot << 32) | end_interval;
}
struct __attribute__((aligned(128UL))) fd_forks {
  fd_tower_forks_t        * tower_forks;
  fd_tower_leaves_map_t   * tower_leaves_map;
  fd_tower_leaves_dlist_t * tower_leaves_dlist;
  fd_tower_leaf_t         * tower_leaves_pool;

  fd_lockout_slots_map_t * lockout_slots_map;
  fd_lockout_slots_t     * lockout_slots_pool;

  fd_lockout_intervals_map_t * lockout_intervals_map;
  fd_lockout_intervals_t     * lockout_intervals_pool;
};
typedef struct fd_forks fd_forks_t;

FD_PROTOTYPES_BEGIN

#define FD_LOCKOUT_ENTRY_MAX (31UL) /* should be same as FD_TOWER_VOTE_MAX */

FD_FN_CONST static inline ulong
fd_forks_align( void ) {
  return alignof(fd_forks_t);
}

FD_FN_CONST static inline ulong
fd_forks_footprint( ulong slot_max, ulong voter_max ) {
  ulong interval_max = fd_ulong_pow2_up( FD_LOCKOUT_ENTRY_MAX*slot_max*voter_max );
  int   lg_slot_max  = fd_ulong_find_msb( fd_ulong_pow2_up( slot_max ) ) + 1;
  return FD_LAYOUT_FINI(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_INIT,
      alignof(fd_forks_t),               sizeof(fd_forks_t)                              ),
      /* Fork structures */
      fd_tower_forks_align(),            fd_tower_forks_footprint        ( lg_slot_max ) ),
      fd_tower_leaves_map_align(),       fd_tower_leaves_map_footprint      ( slot_max ) ),
      fd_tower_leaves_dlist_align(),     fd_tower_leaves_dlist_footprint    (          ) ),
      fd_tower_leaves_pool_align(),      fd_tower_leaves_pool_footprint     ( slot_max ) ),
      /* Lockout interval structures */
      fd_lockout_slots_map_align(),      fd_lockout_slots_map_footprint     ( slot_max ) ),
      fd_lockout_slots_pool_align(),     fd_lockout_slots_pool_footprint    ( interval_max ) ),
      fd_lockout_intervals_map_align(),  fd_lockout_intervals_map_footprint ( interval_max ) ),
      fd_lockout_intervals_pool_align(), fd_lockout_intervals_pool_footprint( interval_max ) ),
    fd_forks_align() );
}

void *
fd_forks_new( void * shmem, ulong slot_max, ulong voter_max );

fd_forks_t *
fd_forks_join( void * shforks );

int
fd_forks_is_slot_ancestor( fd_forks_t * forks,
                           ulong        descendant_slot,
                           ulong        ancestor_slot );

int
fd_forks_is_slot_descendant( fd_forks_t * forks,
                             ulong        ancestor_slot,
                             ulong        descendant_slot );

/* fd_forks_lowest_common_ancestor returns the lowest common
   ancestor of slot1 and slot 2.  There is always an LCA in a valid
   tower_forks tree (the root). */

ulong
fd_forks_lowest_common_ancestor( fd_forks_t * forks,
                                 ulong        slot1,
                                 ulong        slot2 );

/* fd_forks_canonical_block_id returns what we think to be the
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
fd_forks_canonical_block_id( fd_forks_t * forks,
                             ulong        slot );

fd_tower_forks_t *
fd_forks_insert( fd_forks_t * forks,
                 ulong        slot,
                 ulong        parent_slot );

fd_tower_forks_t *
fd_forks_confirmed( fd_tower_forks_t * fork,
                    fd_hash_t const  * block_id );

fd_tower_forks_t *
fd_forks_replayed( fd_forks_t *       forks,
                   fd_tower_forks_t * fork,
                   ulong              bank_idx,
                   fd_hash_t const  * block_id );

fd_tower_forks_t *
fd_forks_voted( fd_tower_forks_t * fork,
                fd_hash_t const  * block_id );

fd_tower_forks_t *
fd_forks_query( fd_forks_t * forks, ulong slot );

int
fd_forks_remove( fd_forks_t * forks, ulong slot );

void
fd_forks_lockouts_add( fd_forks_t * forks,
                       ulong fork_slot,
                       fd_hash_t const * vote_account_pubkey,
                       fd_tower_accts_t * acct );

void
fd_forks_lockouts_clear( fd_forks_t * forks, ulong fork_slot );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_choreo_tower_fd_tower_forks_h */
