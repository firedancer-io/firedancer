#ifndef HEADER_fd_src_choreo_tower_fd_tower_blocks_h
#define HEADER_fd_src_choreo_tower_fd_tower_blocks_h

#include "../fd_choreo_base.h"
#include "fd_tower_voters.h"

/* fd_tower_blocks maintains tower-specific metadata about every block,
   such as what block_id we first replayed, what block_id we voted for,
   and what block_id was ultimately "duplicate confirmed".

   This is used by tower to make voting decisions, such as whether or
   not we can switch "forks".  In this context, a fork is a branch of a
   tree that extends from the root to a leaf.  For example:

           /-- 3-- 4 (A)
   1-- 2 \-- 5        (B)

   Here, A and B are two different forks.  A is [1, 2, 3, 4] and B is
   [1, 2, 5], two branches that each extend from the root to a leaf.

   Note that even though fd_tower_blocks is block_id-aware, it does not
   use them for determining parentage.  Instead, parentage is based on
   slot numbers, so in cases of equivocation (duplicate blocks), tower
   will consider something an ancestor or descendant even if the block
   ids do not chain.

   This behavior intentionally mirrors the Agave logic implemented in
   `make_check_switch_threshold_decision`.  Essentially, tower is unable
   to distinguish duplicates because the vote account format (in which
   towers are stored) only stores slot numbers and not block_ids. */

struct fd_tower_blk {
  ulong     slot;               /* map key */
  ulong     epoch;              /* epoch of this slot */
  ulong     parent_slot;        /* parent slot */
  int       replayed;           /* whether we've replayed this slot yet */
  fd_hash_t replayed_block_id;  /* the block_id we _first_ replayed for this slot */
  int       voted;              /* whether we voted for this slot yet */
  fd_hash_t voted_block_id;     /* the block_id we voted on for this slot */
  int       confirmed;          /* whether this slot has been duplicate confirmed */
  fd_hash_t confirmed_block_id; /* the block_id that was duplicate confirmed */
  ulong     bank_idx;           /* pool idx of the bank as of this replayed block */
};
typedef struct fd_tower_blk fd_tower_blk_t;

#define MAP_NAME           fd_tower_blk
#define MAP_T              fd_tower_blk_t
#define MAP_KEY            slot
#define MAP_KEY_NULL       ULONG_MAX
#define MAP_KEY_INVAL(key) ((key)==ULONG_MAX)
#define MAP_MEMOIZE        0
#include "../../util/tmpl/fd_map_dynamic.c"

/* fd_tower_leaf threads a linkedlist through the leaves for fast
   iteration (needed for switch check). */

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

/* fd_lockout_intervals tracks a map of lockout intervals.

   We need to track a list of lockout intervals per validator per slot.
   Example:

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
   string all the intervals of the same bank together as a linkedlist. */

struct fd_lockout_intervals {
  ulong     key; /* vote_slot (32 bits) | expiration_slot (32 bits) ie. vote_slot + (1 << confirmation count) */
  ulong     next; /* reserved for fd_map_chain and fd_pool */
  fd_hash_t addr; /* vote account address */
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
struct __attribute__((aligned(128UL))) fd_tower_blocks {
  fd_tower_blk_t        * blk_map;
  fd_tower_leaves_map_t   * tower_leaves_map;
  fd_tower_leaves_dlist_t * tower_leaves_dlist;
  fd_tower_leaf_t         * tower_leaves_pool;

  fd_lockout_slots_map_t * lockout_slots_map;
  fd_lockout_slots_t     * lockout_slots_pool;

  fd_lockout_intervals_map_t * lockout_intervals_map;
  fd_lockout_intervals_t     * lockout_intervals_pool;
};
typedef struct fd_tower_blocks fd_tower_blocks_t;

FD_PROTOTYPES_BEGIN

#define FD_LOCKOUT_ENTRY_MAX (31UL) /* should be same as FD_TOWER_VOTE_MAX */

FD_FN_CONST static inline ulong
fd_tower_blocks_align( void ) {
  return alignof(fd_tower_blocks_t);
}

FD_FN_CONST static inline ulong
fd_tower_blocks_footprint( ulong slot_max, ulong voter_max ) {
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
      alignof(fd_tower_blocks_t),               sizeof(fd_tower_blocks_t)                              ),
      /* Fork structures */
      fd_tower_blk_align(),            fd_tower_blk_footprint        ( lg_slot_max ) ),
      fd_tower_leaves_map_align(),       fd_tower_leaves_map_footprint      ( slot_max ) ),
      fd_tower_leaves_dlist_align(),     fd_tower_leaves_dlist_footprint    (          ) ),
      fd_tower_leaves_pool_align(),      fd_tower_leaves_pool_footprint     ( slot_max ) ),
      /* Lockout interval structures */
      fd_lockout_slots_map_align(),      fd_lockout_slots_map_footprint     ( slot_max ) ),
      fd_lockout_slots_pool_align(),     fd_lockout_slots_pool_footprint    ( interval_max ) ),
      fd_lockout_intervals_map_align(),  fd_lockout_intervals_map_footprint ( interval_max ) ),
      fd_lockout_intervals_pool_align(), fd_lockout_intervals_pool_footprint( interval_max ) ),
    fd_tower_blocks_align() );
}

void *
fd_tower_blocks_new( void * shmem, ulong slot_max, ulong voter_max );

fd_tower_blocks_t *
fd_tower_blocks_join( void * shforks );

int
fd_tower_blocks_is_slot_ancestor( fd_tower_blocks_t * forks,
                           ulong        descendant_slot,
                           ulong        ancestor_slot );

int
fd_tower_blocks_is_slot_descendant( fd_tower_blocks_t * forks,
                             ulong        ancestor_slot,
                             ulong        descendant_slot );

/* fd_tower_blocks_lowest_common_ancestor returns the lowest common
   ancestor of slot1 and slot 2.  There is always an LCA in a valid
   tower_forks tree (the root). */

ulong
fd_tower_blocks_lowest_common_ancestor( fd_tower_blocks_t * forks,
                                 ulong        slot1,
                                 ulong        slot2 );

/* fd_tower_blocks_canonical_block_id returns what we think to be the
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
fd_tower_blocks_canonical_block_id( fd_tower_blocks_t * forks,
                             ulong        slot );

fd_tower_blk_t *
fd_tower_blocks_insert( fd_tower_blocks_t * forks,
                 ulong        slot,
                 ulong        parent_slot );

fd_tower_blk_t *
fd_tower_blocks_replayed( fd_tower_blocks_t *       forks,
                   fd_tower_blk_t * fork,
                   ulong              bank_idx,
                   fd_hash_t const  * block_id );

fd_tower_blk_t *
fd_tower_blocks_voted( fd_tower_blk_t * fork,
                fd_hash_t const  * block_id );

fd_tower_blk_t *
fd_tower_blocks_query( fd_tower_blocks_t * forks, ulong slot );

int
fd_tower_blocks_remove( fd_tower_blocks_t * forks, ulong slot );

void
fd_tower_blocks_lockouts_add( fd_tower_blocks_t * forks,
                       ulong fork_slot,
                       fd_hash_t const * vote_account_pubkey,
                       fd_tower_voters_t * acct );

void
fd_tower_blocks_lockouts_clear( fd_tower_blocks_t * forks, ulong fork_slot );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_choreo_tower_fd_tower_blocks_h */
