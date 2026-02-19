#ifndef HEADER_fd_src_choreo_tower_fd_tower_stakes_h
#define HEADER_fd_src_choreo_tower_fd_tower_stakes_h

/* fd_tower_stakes_t tracks stakes of the top k voters in a slot (as of
   SIMD-0357, k=2000).  While the stakes are usually the same for every
   slot in a given epoch, it is not guaranteed.  Specifically, if there
   is a fork across an epoch boundary, the set of voters and their
   stakes may be different across slots in the same epoch because the
   slots are on different forks that calculated the stakes differently.
   If we have not rooted a slot in the new epoch yet, this could be
   different from other forks, but if we have rooted an epoch slot, the
   stakes for each voter are the same for all forks that descend from
   that root (forks that do not descend will have been pruned).

   This is currently exclusively used for the switch check, which
   requires the stakes of each voter on the HEAVIEST fork in the epoch.
   We need to do all this tracking because tower cannot query the vote
   states from any bank at will.  Replay determines which banks can be
   queried, and won't know beforehand which banks will be the heaviest.

   fd_tower_stakes_t is backed by two hash maps:
   1. fd_tower_stakes_vtr_map: this maps a vote account to a voter stake
   2. fd_tower_stakes_blk_map: this maps a slot to a voter stake index

   The voter_stake_map has a compound key {vote_account, slot}, so that
   the map can be queries O(1) by slot and vote account. As we populate
   the map, we also thread a linkedlist through all the entries for the
   same slot. This is possible because the vote stake map is populated/
   updated all at once when a slot arrives from the bank, so we can
   sequentially link the current entry to the previous entry. Then the
   last entry in the linkedlist (last voter we process for a slot) will
   have its key {vote_account, slot} put in the slot_stakes_map. This
   way on publish, we have a way to query all the stakes / voters for a
   slot without doing a full scan of the voter_stake_map.

*/

#include "../fd_choreo_base.h"

struct fd_vote_acc_stake_key {
    fd_hash_t addr; /* vote account address */
    ulong     slot;
};
typedef struct fd_vote_acc_stake_key fd_vote_acc_stake_key_t;

static const fd_vote_acc_stake_key_t fd_vote_acc_stake_key_null = { .addr = {{ 0 }}, .slot = 0UL };

struct fd_tower_stakes_vtr {
  fd_vote_acc_stake_key_t key;
  ulong                next;
  ulong                stake;
  ulong                prev;
};
typedef struct fd_tower_stakes_vtr fd_tower_stakes_vtr_t;

#define MAP_NAME                fd_tower_stakes_vtr_map
#define MAP_ELE_T               fd_tower_stakes_vtr_t
#define MAP_KEY_T               fd_vote_acc_stake_key_t
#define MAP_KEY_EQ(k0,k1)       (!memcmp( k0, k1, sizeof(fd_vote_acc_stake_key_t) ))
#define MAP_KEY_HASH(key, seed) fd_ulong_hash( ((key)->slot) ^ ((key)->addr.ul[0]) ^ (seed) )
#include "../../util/tmpl/fd_map_chain.c"

#define POOL_NAME fd_tower_stakes_vtr_pool
#define POOL_T    fd_tower_stakes_vtr_t
#include "../../util/tmpl/fd_pool.c"

/* Some really terrible witchcraft to track used vote accounts for
   whatever reason. For example, switch check needs to make sure it's
   not repeating usage of the same vote account. We can flip a bit on
   the vote stake pool index if its been used. Caller should ensure that
   the set is cleared before and after each use. The size of the set
   will be the number of elements in the vote stake pool. */

#define SET_NAME    fd_used_acc_scratch
#include "../../util/tmpl/fd_set_dynamic.c"

struct fd_tower_stakes_blk {
  ulong slot;
  ulong head; /* pool idx of the head of a linked list of voters in this slot */
};
typedef struct fd_tower_stakes_blk fd_tower_stakes_blk_t;

#define MAP_NAME           fd_tower_stakes_blk
#define MAP_T              fd_tower_stakes_blk_t
#define MAP_KEY            slot
#define MAP_KEY_NULL       ULONG_MAX
#define MAP_KEY_INVAL(key) ((key)==ULONG_MAX)
#define MAP_MEMOIZE        0
#include "../../util/tmpl/fd_map_dynamic.c"

struct __attribute__((aligned(128UL))) fd_tower_stakes {
  fd_tower_stakes_vtr_map_t * voter_stake_map;
  fd_tower_stakes_vtr_t *     voter_stake_pool;
  fd_tower_stakes_blk_t *     slot_stakes_map;
  fd_used_acc_scratch_t *     used_acc_scratch;
};
typedef struct fd_tower_stakes fd_tower_stakes_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST static inline ulong
fd_tower_stakes_align( void ) {
  return alignof(fd_tower_stakes_t);
}

FD_FN_CONST static inline ulong
fd_tower_stakes_footprint( ulong slot_max ) {
  int lg_slot_cnt = fd_ulong_find_msb( fd_ulong_pow2_up( slot_max ) ) + 1;
  return FD_LAYOUT_FINI(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_INIT,
      alignof(fd_tower_stakes_t),       sizeof(fd_tower_stakes_t)                                     ),
      fd_tower_stakes_vtr_map_align(),  fd_tower_stakes_vtr_map_footprint ( FD_VOTER_MAX * slot_max ) ),
      fd_tower_stakes_vtr_pool_align(), fd_tower_stakes_vtr_pool_footprint( FD_VOTER_MAX * slot_max ) ),
      fd_tower_stakes_blk_align(),      fd_tower_stakes_blk_footprint( lg_slot_cnt )                  ),
      fd_used_acc_scratch_align(),      fd_used_acc_scratch_footprint( FD_VOTER_MAX * slot_max )      ),
    fd_tower_stakes_align() );
}

void *
fd_tower_stakes_new( void * shmem,
                     ulong  slot_max );

fd_tower_stakes_t *
fd_tower_stakes_join( void * shtower_stakes );

/* fd_tower_stakes_vtr_insert adds a new stake for a voter to the epoch
   stakes for a specific slot, and returns the index of the new voter
   stake in the pool. prev_voter_idx is the index of the previous voter
   stake in the pool. If this is the first voter inserted for this slot,
   prev_voter_idx should be ULONG_MAX. Example usage:

   prev_voter_idx = ULONG_MAX;
   for( v : voters ) {
     voter_idx = fd_tower_stakes_vtr_insert( tower_stakes, slot, v.vote_account, v.stake, prev_voter_idx );
     prev_voter_idx = voter_idx;
   } */

ulong
fd_tower_stakes_vtr_insert( fd_tower_stakes_t * tower_stakes,
                            ulong               slot,
                            fd_hash_t const *   vote_account,
                            ulong               stake,
                            ulong               prev_voter_idx );

void
fd_tower_stakes_blk_prune( fd_tower_stakes_t     * tower_stakes,
                            fd_tower_stakes_blk_t * blk );

#endif /* HEADER_fd_src_choreo_tower_fd_tower_stakes_h */
