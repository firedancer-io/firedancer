#include <stdio.h>
#include <string.h>

#include "fd_tower.h"
#include "../../flamenco/txn/fd_txn_generate.h"
#include "../../flamenco/runtime/fd_system_ids.h"
#include "../../flamenco/runtime/program/vote/fd_vote_state_versioned.h"

/* Pool and map_chain for fd_tower_blk_t. */

#define POOL_NAME blk_pool
#define POOL_T    fd_tower_blk_t
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME                           blk_map
#define MAP_ELE_T                          fd_tower_blk_t
#define MAP_KEY_T                          ulong
#define MAP_KEY                            slot
#define MAP_KEY_EQ(k0,k1)                  (*(k0)==*(k1))
#define MAP_KEY_HASH(key,seed)             ((*(key))^(seed))
#define MAP_OPTIMIZE_RANDOM_ACCESS_REMOVAL 1
#include "../../util/tmpl/fd_map_chain.c"

/* lockout_interval tracks a map of lockout intervals.

   We need to track a list of lockout intervals per validator per slot.
   Intervals are inclusive.  Example:

   After executing slot 33, validator A votes for slot 32, has a tower

     vote  | confirmation count | lockout interval
     ----- | -------------------|------------------
     32    |  1                 | [32, 33]
     2     |  3                 | [2,  6]
     1     |  4                 | [1,  9]

   The lockout interval is the interval of slots that the validator is
   locked out from voting for if they want to switch off that vote.  For
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

struct lockout_interval {
  ulong     key;   /* vote_slot (32 bits) | expiration_slot (32 bits) ie. vote_slot + (1 << confirmation count) */
  ulong     next;  /* reserved for fd_map_chain and fd_pool */
  fd_hash_t addr;  /* vote account address */
  ulong     start; /* For normal entries: start of interval (vote slot).
                      For sentinel entries (key has expiration_slot==0):
                      the interval_end value this sentinel indexes.
                      Multiple sentinels can exist per slot (one per
                      unique interval_end), all sharing key (slot, 0)
                      via MAP_MULTI. */
};
typedef struct lockout_interval lockout_interval_t;

#define MAP_NAME    lockout_interval_map
#define MAP_ELE_T   lockout_interval_t
#define MAP_MULTI   1
#define MAP_KEY     key
#define MAP_NEXT    next
#include "../../util/tmpl/fd_map_chain.c"

#define POOL_NAME lockout_interval_pool
#define POOL_T    lockout_interval_t
#define POOL_NEXT next
#include "../../util/tmpl/fd_pool.c"

FD_FN_PURE static inline ulong
lockout_interval_key( ulong fork_slot, ulong end_interval ) {
  return (fork_slot << 32) | end_interval;
}

#define THRESHOLD_DEPTH (8)
#define THRESHOLD_RATIO (2.0 / 3.0)
#define SWITCH_RATIO    (0.38)

ulong
fd_tower_align( void ) {
  return 128UL;
}

ulong
fd_tower_footprint( ulong blk_max,
                    ulong vtr_max ) {
  ulong lck_interval_max = fd_ulong_pow2_up( FD_TOWER_LOCKOS_MAX*blk_max*vtr_max );
  ulong lck_pool_max     = fd_ulong_pow2_up( 2UL * lck_interval_max );

  ulong stk_vtr_chain_cnt = fd_tower_stakes_vtr_map_chain_cnt_est( vtr_max * blk_max );
  int   stk_lg_slot_cnt   = fd_ulong_find_msb( fd_ulong_pow2_up( blk_max ) ) + 1;

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, 128UL,                              sizeof(fd_tower_t)                                          );
  l = FD_LAYOUT_APPEND( l, fd_tower_vote_align(),              fd_tower_vote_footprint()                                   );
  l = FD_LAYOUT_APPEND( l, blk_pool_align(),                   blk_pool_footprint     ( blk_max )                          );
  l = FD_LAYOUT_APPEND( l, blk_map_align(),                    blk_map_footprint      ( blk_map_chain_cnt_est( blk_max ) ) );
  l = FD_LAYOUT_APPEND( l, fd_tower_vtr_align(),               fd_tower_vtr_footprint ( vtr_max )                          );
  for( ulong i = 0; i < vtr_max; i++ ) {
    l = FD_LAYOUT_APPEND( l, fd_tower_vote_align(),            fd_tower_vote_footprint()                                   );
  }
  /* lockos */
  l = FD_LAYOUT_APPEND( l, lockout_interval_pool_align(),      lockout_interval_pool_footprint( lck_pool_max )              );
  l = FD_LAYOUT_APPEND( l, lockout_interval_map_align(),       lockout_interval_map_footprint ( lck_pool_max )              );
  /* stakes */
  l = FD_LAYOUT_APPEND( l, fd_tower_stakes_vtr_map_align(),   fd_tower_stakes_vtr_map_footprint ( stk_vtr_chain_cnt )      );
  l = FD_LAYOUT_APPEND( l, fd_tower_stakes_vtr_pool_align(),  fd_tower_stakes_vtr_pool_footprint( vtr_max * blk_max )      );
  l = FD_LAYOUT_APPEND( l, fd_tower_stakes_slot_align(),      fd_tower_stakes_slot_footprint( stk_lg_slot_cnt )            );
  l = FD_LAYOUT_APPEND( l, fd_used_acc_scratch_align(),       fd_used_acc_scratch_footprint( vtr_max * blk_max )           );
  return FD_LAYOUT_FINI( l, fd_tower_align() );
}

void *
fd_tower_new( void * shmem,
              ulong  blk_max,
              ulong  vtr_max,
              ulong  seed ) {

  if( FD_UNLIKELY( !shmem ) ) {
    FD_LOG_WARNING(( "NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shmem, fd_tower_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned mem" ));
    return NULL;
  }

  ulong footprint = fd_tower_footprint( blk_max, vtr_max );
  if( FD_UNLIKELY( !footprint ) ) {
    FD_LOG_WARNING(( "bad blk_max (%lu) or vtr_max (%lu)", blk_max, vtr_max ));
    return NULL;
  }

  fd_memset( shmem, 0, footprint );

  ulong lck_interval_max = fd_ulong_pow2_up( FD_TOWER_LOCKOS_MAX*blk_max*vtr_max );
  ulong lck_pool_max     = fd_ulong_pow2_up( 2UL * lck_interval_max );

  ulong stk_vtr_chain_cnt = fd_tower_stakes_vtr_map_chain_cnt_est( vtr_max * blk_max );
  int   stk_lg_slot_cnt   = fd_ulong_find_msb( fd_ulong_pow2_up( blk_max ) ) + 1;

  FD_SCRATCH_ALLOC_INIT( l, shmem );
  fd_tower_t * tower          = FD_SCRATCH_ALLOC_APPEND( l, 128UL,                             sizeof(fd_tower_t)                                          );
  void *       votes          = FD_SCRATCH_ALLOC_APPEND( l, fd_tower_vote_align(),             fd_tower_vote_footprint()                                   );
  void *       blk_pool       = FD_SCRATCH_ALLOC_APPEND( l, blk_pool_align(),                  blk_pool_footprint     ( blk_max )                          );
  void *       blk_map        = FD_SCRATCH_ALLOC_APPEND( l, blk_map_align(),                   blk_map_footprint      ( blk_map_chain_cnt_est( blk_max ) ) );
  void *       vtrs           = FD_SCRATCH_ALLOC_APPEND( l, fd_tower_vtr_align(),              fd_tower_vtr_footprint ( vtr_max )                          );
  void *       towers[ vtr_max ];
  for( ulong i = 0; i < vtr_max; i++ ) {
    towers[i] = FD_SCRATCH_ALLOC_APPEND( l, fd_tower_vote_align(),            fd_tower_vote_footprint()                                   );
  }
  void *       lck_pool_mem   = FD_SCRATCH_ALLOC_APPEND( l, lockout_interval_pool_align(),     lockout_interval_pool_footprint( lck_pool_max )              );
  void *       lck_map_mem    = FD_SCRATCH_ALLOC_APPEND( l, lockout_interval_map_align(),      lockout_interval_map_footprint ( lck_pool_max )              );
  void *       stk_vtr_map    = FD_SCRATCH_ALLOC_APPEND( l, fd_tower_stakes_vtr_map_align(),  fd_tower_stakes_vtr_map_footprint ( stk_vtr_chain_cnt )      );
  void *       stk_vtr_pool   = FD_SCRATCH_ALLOC_APPEND( l, fd_tower_stakes_vtr_pool_align(), fd_tower_stakes_vtr_pool_footprint( vtr_max * blk_max )      );
  void *       stk_slot_map   = FD_SCRATCH_ALLOC_APPEND( l, fd_tower_stakes_slot_align(),     fd_tower_stakes_slot_footprint( stk_lg_slot_cnt )            );
  void *       stk_used_acc   = FD_SCRATCH_ALLOC_APPEND( l, fd_used_acc_scratch_align(),      fd_used_acc_scratch_footprint( vtr_max * blk_max )           );
  FD_TEST( FD_SCRATCH_ALLOC_FINI( l, fd_tower_align() ) == (ulong)shmem + footprint );

  tower->root     = ULONG_MAX;
  tower->blk_max  = blk_max;
  tower->vtr_max  = vtr_max;
  tower->votes    = fd_tower_vote_new( votes );
  tower->blk_pool = blk_pool_new( blk_pool, blk_max );
  tower->blk_map  = blk_map_new( blk_map, blk_map_chain_cnt_est( blk_max ), seed );
  tower->vtrs     = fd_tower_vtr_new( vtrs, vtr_max );
  for( ulong i = 0; i < vtr_max; i++ ) {
    fd_tower_vtr_join( tower->vtrs )[i].votes = fd_tower_vote_new( towers[i] );
  }

  tower->lck_pool     = lockout_interval_pool_new( lck_pool_mem, lck_pool_max       );
  tower->lck_map      = lockout_interval_map_new ( lck_map_mem,  lck_pool_max, seed );
  tower->stk_vtr_map  = fd_tower_stakes_vtr_map_new ( stk_vtr_map,  stk_vtr_chain_cnt, seed );
  tower->stk_vtr_pool = fd_tower_stakes_vtr_pool_new( stk_vtr_pool, vtr_max * blk_max       );
  tower->stk_slot_map = fd_tower_stakes_slot_new    ( stk_slot_map, stk_lg_slot_cnt,   seed  );
  tower->stk_used_acc = fd_used_acc_scratch_new     ( stk_used_acc, vtr_max * blk_max        );

  return shmem;
}

fd_tower_t *
fd_tower_join( void * shtower ) {
  fd_tower_t * tower = (fd_tower_t *)shtower;

  if( FD_UNLIKELY( !tower ) ) {
    FD_LOG_WARNING(( "NULL tower" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)tower, fd_tower_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned tower" ));
    return NULL;
  }

  tower->votes        = fd_tower_vote_join( tower->votes    );
  tower->blk_pool     = blk_pool_join     ( tower->blk_pool );
  tower->blk_map      = blk_map_join      ( tower->blk_map  );
  tower->vtrs         = fd_tower_vtr_join ( tower->vtrs     );
  for( ulong i = 0; i < tower->vtr_max; i++ ) {
    tower->vtrs[i].votes = fd_tower_vote_join( tower->vtrs[i].votes );
  }
  tower->lck_pool     = lockout_interval_pool_join( tower->lck_pool );
  tower->lck_map      = lockout_interval_map_join ( tower->lck_map  );
  tower->stk_vtr_map  = fd_tower_stakes_vtr_map_join ( tower->stk_vtr_map  );
  tower->stk_vtr_pool = fd_tower_stakes_vtr_pool_join( tower->stk_vtr_pool );
  tower->stk_slot_map = fd_tower_stakes_slot_join    ( tower->stk_slot_map );
  tower->stk_used_acc = fd_used_acc_scratch_join     ( tower->stk_used_acc );

  return tower;
}

void *
fd_tower_leave( fd_tower_t const * tower ) {

  if( FD_UNLIKELY( !tower ) ) {
    FD_LOG_WARNING(( "NULL tower" ));
    return NULL;
  }

  return (void *)tower;
}

void *
fd_tower_delete( void * shtower ) {

  if( FD_UNLIKELY( !shtower ) ) {
    FD_LOG_WARNING(( "NULL tower" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)shtower, fd_tower_align() ) ) ) {
    FD_LOG_WARNING(( "misaligned tower" ));
    return NULL;
  }

  return shtower;
}

static fd_vote_acc_vote_t const *
v4_off( fd_vote_acc_t const * voter ) {
  return (fd_vote_acc_vote_t const *)( voter->v4.bls_pubkey_compressed + voter->v4.has_bls_pubkey_compressed * sizeof(voter->v4.bls_pubkey_compressed) + sizeof(ulong) );
}

/* expiration calculates the expiration slot of vote given a slot and
   confirmation count. */

static inline ulong
expiration_slot( fd_tower_vote_t const * vote ) {
  ulong lockout = 1UL << vote->conf;
  return vote->slot + lockout;
}

/* simulate_vote simulates voting for slot, popping all votes from the
   top that would be consecutively expired by voting for slot. */

static ulong
simulate_vote( fd_tower_vote_t const * votes,
               ulong                   slot ) {
  ulong cnt = fd_tower_vote_cnt( votes );
  while( cnt ) {
    fd_tower_vote_t const * top_vote = fd_tower_vote_peek_index_const( votes, cnt - 1 );
    if( FD_LIKELY( expiration_slot( top_vote ) >= slot ) ) break; /* expire only if consecutive */
    cnt--;
  }
  return cnt;
}

/* push_vote pushes a new vote for slot onto the tower.  Pops and
   returns the new root (bottom of the tower) if it reaches max lockout
   as a result of the new vote.  Otherwise, returns ULONG_MAX.

   Max lockout is equivalent to 1 << FD_TOWER_VOTE_MAX + 1 (which
   implies confirmation count is FD_TOWER_VOTE_MAX + 1).  As a result,
   fd_tower_vote also maintains the invariant that the tower contains at
   most FD_TOWER_VOTE_MAX votes, because (in addition to vote expiry)
   there will always be a pop before reaching FD_TOWER_VOTE_MAX + 1. */

static ulong
push_vote( fd_tower_t * tower,
           ulong        slot ) {

  /* Sanity check: slot should always be greater than previous vote slot in tower. */

  fd_tower_vote_t const * vote = fd_tower_vote_peek_tail_const( tower->votes );
  if( FD_UNLIKELY( vote && slot <= vote->slot ) ) FD_LOG_CRIT(( "[%s] slot %lu <= vote->slot %lu", __func__, slot, vote->slot ));

  /* Use simulate_vote to determine how many expired votes to pop. */

  ulong cnt = simulate_vote( tower->votes, slot );

  /* Pop everything that got expired. */

  while( FD_LIKELY( fd_tower_vote_cnt( tower->votes ) > cnt ) ) {
    fd_tower_vote_pop_tail( tower->votes );
  }

  /* If the tower is still full after expiring, then pop and return the
     bottom vote slot as the new root because this vote has incremented
     it to max lockout.  Otherwise this is a no-op and there is no new
     root (ULONG_MAX). */

  ulong root = ULONG_MAX;
  if( FD_LIKELY( fd_tower_vote_full( tower->votes ) ) ) { /* optimize for full tower */
    root = fd_tower_vote_pop_head( tower->votes ).slot;
  }

  /* Increment confirmations (double lockouts) for consecutive
     confirmations in prior votes. */

  ulong prev_conf = 0;
  for( fd_tower_vote_iter_t iter = fd_tower_vote_iter_init_rev( tower->votes       );
                             !fd_tower_vote_iter_done_rev( tower->votes, iter );
                       iter = fd_tower_vote_iter_prev    ( tower->votes, iter ) ) {
    fd_tower_vote_t * vote = fd_tower_vote_iter_ele( tower->votes, iter );
    if( FD_UNLIKELY( vote->conf != ++prev_conf ) ) break;
    vote->conf++;
  }

  /* Add the new vote to the tower. */

  fd_tower_vote_push_tail( tower->votes, (fd_tower_vote_t){ .slot = slot, .conf = 1 } );

  /* Return the new root (FD_SLOT_NULL if there is none). */

  return root;
}

/* lockout_check checks if we are locked out from voting for slot.
   Returns 1 if we can vote for slot without violating lockout, 0
   otherwise.

   After voting for a slot n, we are locked out for 2^k slots, where k
   is the confirmation count of that vote.  Once locked out, we cannot
   vote for a different fork until that previously-voted fork expires at
   slot n+2^k.  This implies the earliest slot in which we can switch
   from the previously-voted fork is (n+2^k)+1.  We use `ghost` to
   determine whether `slot` is on the same or different fork as previous
   vote slots.

   In the case of the tower, every vote has its own expiration slot
   depending on confirmations. The confirmation count is the max number
   of consecutive votes that have been pushed on top of the vote, and
   not necessarily its current height in the tower.

   For example, the following is a diagram of a tower pushing and
   popping with each vote:


   slot | confirmation count
   -----|-------------------
   4    |  1 <- vote
   3    |  2
   2    |  3
   1    |  4


   slot | confirmation count
   -----|-------------------
   9    |  1 <- vote
   2    |  3
   1    |  4


   slot | confirmation count
   -----|-------------------
   10   |  1 <- vote
   9    |  2
   2    |  3
   1    |  4


   slot | confirmation count
   -----|-------------------
   11   |  1 <- vote
   10   |  2
   9    |  3
   2    |  4
   1    |  5


   slot | confirmation count
   -----|-------------------
   18   |  1 <- vote
   2    |  4
   1    |  5


   In the final tower, note the gap in confirmation counts between slot
   18 and slot 2, even though slot 18 is directly above slot 2. */

static int
lockout_check( fd_tower_t * tower,
               ulong        slot ) {

  if( FD_UNLIKELY( fd_tower_vote_empty( tower->votes )                         ) ) return 1; /* always not locked out if we haven't voted. */
  if( FD_UNLIKELY( slot <= fd_tower_vote_peek_tail_const( tower->votes )->slot ) ) return 0; /* always locked out from voting for slot <= last vote slot */

  /* Simulate a vote to pop off all the votes that would be expired by
     voting for slot.  Then check if the newly top-of-tower vote is on
     the same fork as slot (if so this implies we can vote for it). */

  ulong cnt = simulate_vote( tower->votes, slot ); /* pop off votes that would be expired */
  if( FD_UNLIKELY( !cnt ) ) return 1;              /* tower is empty after popping expired votes */

  fd_tower_vote_t const * vote    = fd_tower_vote_peek_index_const( tower->votes, cnt - 1 );       /* newly top-of-tower */
  int                     lockout = fd_tower_blocks_is_slot_descendant( tower, vote->slot, slot ); /* check if on same fork */
  return lockout;
}

/* switch_check checks if we can switch to the fork of `slot`.  Returns
   1 if we can switch, 0 otherwise.  Assumes tower is non-empty.

   There are two forks of interest: our last vote fork ("vote fork") and
   the fork we want to switch to ("switch fork").  The switch fork is on
   the fork of `slot`.

   In order to switch, SWITCH_RATIO of stake must have voted for
   a slot that satisfies the following conditions: the
   GCA(slot, last_vote) is an ancestor of the switch_slot

   Recall from the lockout check a validator is locked out from voting
   for our last vote slot when their last vote slot is on a different
   fork, and that vote's expiration slot > our last vote slot.

   The following pseudocode describes the algorithm:

   ```
   for every fork f in the fork tree, take the most recently executed
   slot `s` (the leaf of the fork).

   Take the greatest common ancestor of the `s` and the our last vote
   slot. If the switch_slot is a descendant of this GCA, then votes for
   `s` can count towards the switch threshold.

     query banks(`s`) for vote accounts in `s`
       for all vote accounts v in `s`
          if v's  locked out[1] from voting for our latest vote slot
             add v's stake to switch stake

   return switch stake >= total_stake * SWITCH_RATIO
   ```

   The switch check is used to safeguard optimistic confirmation.
   Specifically: optimistic confirmation pct + SWITCH_RATIO >= 1. */

static int
is_purged( fd_tower_t * tower,
           fd_ghost_blk_t * blk ) {
  fd_tower_blk_t * tower_blk = fd_tower_blocks_query( tower, blk->slot );
  return tower_blk->confirmed && memcmp( &tower_blk->confirmed_block_id, &blk->id, sizeof(fd_hash_t) );
}

static int
switch_check( fd_tower_t * tower,
              fd_ghost_t * ghost,
              ulong        total_stake,
              ulong        switch_slot ) {

  lockout_interval_map_t * lck_map  = tower->lck_map;
  lockout_interval_t *     lck_pool = tower->lck_pool;

  ulong switch_stake = 0;
  ulong vote_slot    = fd_tower_vote_peek_tail_const( tower->votes )->slot;
  ulong root_slot    = fd_tower_vote_peek_head_const( tower->votes )->slot;

  ulong            null = fd_ghost_blk_idx_null( ghost );
  fd_ghost_blk_t * head = fd_ghost_blk_map_remove( ghost, fd_ghost_root( ghost ) );
  fd_ghost_blk_t * tail = head;
  head->next = null;

  while( FD_LIKELY( head ) ) {
    fd_ghost_blk_t * blk = head; /* guaranteed to not be purged */

    /* Because agave has particular behavior where if they replay a
       equivocating version of a slot and then the correct version, the
       original version and all of it's children get purged from all
       structures.  None of the nodes on this subtree can be considered
       for the switch proof.  Note that this means as we BFS, a node
       can be considered a "valid leaf" if either it has no children,
       or if all of it's children are purged/superseded slots.  We
       detect this by comparing against tower_blocks confirmed. */

    int is_valid_leaf = 1;
    fd_ghost_blk_t * child = fd_ghost_blk_child( ghost, head );
    while( FD_LIKELY( child ) ) {
      if( FD_LIKELY( !is_purged( tower, child ) ) ) {
        fd_ghost_blk_map_remove( ghost, child );
        tail->next    = fd_ghost_blk_idx( ghost, child );
        tail          = child;
        tail->next    = null;
        is_valid_leaf = 0;
      }
      child = fd_ghost_blk_sibling( ghost, child );
    }

    head = fd_ghost_blk_next( ghost, blk );  /* pop queue head */
    fd_ghost_blk_map_insert( ghost, blk );   /* re-insert into map */

    if( FD_UNLIKELY( !is_valid_leaf ) ) continue;  /* not a real candidate */

    ulong candidate_slot = blk->slot;
    ulong lca = fd_tower_blocks_lowest_common_ancestor( tower, candidate_slot, vote_slot );
    if( FD_UNLIKELY( candidate_slot == vote_slot ) ) continue;
    if( FD_UNLIKELY( lca==ULONG_MAX ) ) continue;       /* unlikely but this leaf is an already pruned minority fork */

    if( FD_UNLIKELY( fd_tower_blocks_is_slot_descendant( tower, lca, switch_slot ) ) ) {

      /* This candidate slot may be considered for the switch proof, if
         it passes the following conditions:

         https://github.com/anza-xyz/agave/blob/c7b97bc77addacf03b229c51b47c18650d909576/core/src/consensus.rs#L1117

         Now for this candidate slot, look at the lockouts that were
         created at the time that we processed the bank for this
         candidate slot. */

      ulong sentinel_key = lockout_interval_key( candidate_slot, 0 );
      for( lockout_interval_t const * sentinel = lockout_interval_map_ele_query_const( lck_map, &sentinel_key, NULL, lck_pool );
                                      sentinel;
                                      sentinel = lockout_interval_map_ele_next_const( sentinel, NULL, lck_pool ) ) {
        ulong interval_end = sentinel->start;
        ulong key = lockout_interval_key( candidate_slot, interval_end );

        /* Intervals are keyed by the end of the interval. If the end of
           the interval is < the last vote slot, then these vote
           accounts with this particular lockout are NOT locked out from
           voting for the last vote slot, which means we can skip this
           set of intervals. */

        if( FD_LIKELY( interval_end < vote_slot ) ) continue;

        /* At this point we can actually query for the intervals by
           end interval to get the vote accounts. */

        for( lockout_interval_t const * interval = lockout_interval_map_ele_query_const( lck_map, &key, NULL, lck_pool );
                                        interval;
                                        interval = lockout_interval_map_ele_next_const( interval, NULL, lck_pool ) ) {
          ulong interval_slot        =  interval->start;
          fd_hash_t const * vote_acc = &interval->addr;

          if( FD_UNLIKELY( !fd_tower_blocks_is_slot_descendant( tower, interval_slot, vote_slot ) && interval_slot > root_slot ) ) {
            fd_tower_stakes_vtr_xid_t     key         = { .addr = *vote_acc, .slot = switch_slot };
            fd_tower_stakes_vtr_t const * voter_stake = fd_tower_stakes_vtr_map_ele_query_const( tower->stk_vtr_map, &key, NULL, tower->stk_vtr_pool );
            if( FD_UNLIKELY( !voter_stake ) ) {
              FD_BASE58_ENCODE_32_BYTES( vote_acc->key, vote_acc_b58 );
              FD_LOG_CRIT(( "missing voter stake for vote account %s on slot %lu. Is this an error?", vote_acc_b58, switch_slot ));
            }
            ulong voter_idx = fd_tower_stakes_vtr_pool_idx( tower->stk_vtr_pool, voter_stake );
            if( FD_UNLIKELY( fd_used_acc_scratch_test( tower->stk_used_acc, voter_idx ) ) ) continue; /* exclude already counted voters */
            fd_used_acc_scratch_insert( tower->stk_used_acc, voter_idx );
            switch_stake += voter_stake->stake;
            if( FD_LIKELY( (double)switch_stake / (double)total_stake > SWITCH_RATIO ) ) {
              fd_used_acc_scratch_null( tower->stk_used_acc );
              FD_LOG_DEBUG(( "[%s] vote_slot: %lu. switch_slot: %lu. pct: %.0lf%%", __func__, vote_slot, switch_slot, (double)switch_stake / (double)total_stake * 100.0 ));
              while( FD_LIKELY( head ) ) { /* cleanup: re-insert remaining BFS queue into map */
                fd_ghost_blk_t * next = fd_ghost_blk_next( ghost, head );
                fd_ghost_blk_map_insert( ghost, head );
                head = next;
              }
              return 1;
            }
          }
        }
      }
    }
  }
  fd_used_acc_scratch_null( tower->stk_used_acc );
  FD_LOG_DEBUG(( "[%s] vote_slot: %lu. switch_slot: %lu. pct: %.0lf%%", __func__, vote_slot, switch_slot, (double)switch_stake / (double)total_stake * 100.0 ));
  return 0;
}

/* threshold_check checks if we pass the threshold required to vote for
   `slot`.  Returns 1 if we pass the threshold check, 0 otherwise.

   The following psuedocode describes the algorithm:

   ```
   simulate that we have voted for `slot`

   for all vote accounts in the current epoch

      simulate that the vote account has voted for `slot`

      pop all votes expired by that simulated vote

      if the validator's latest tower vote after expiry >= our threshold
      slot ie. our vote from THRESHOLD_DEPTH back also after simulating,
      then add validator's stake to threshold_stake.

   return threshold_stake >= FD_TOWER_THRESHOLD_RATIO
   ```

   The threshold check simulates voting for the current slot to expire
   stale votes.  This is to prevent validators that haven't voted in a
   long time from counting towards the threshold stake. */

static int
threshold_check( fd_tower_t const *     tower,
                 fd_tower_vtr_t const * accts,
                 ulong                  total_stake,
                 ulong                  slot ) {

  /* First, simulate a vote on our tower, popping off everything that
     would be expired by voting for slot. */

  ulong cnt = simulate_vote( tower->votes, slot );

  /* We can always vote if our tower is not at least THRESHOLD_DEPTH
     deep after simulating. */

  if( FD_UNLIKELY( cnt < THRESHOLD_DEPTH ) ) return 1;

  /* Get the vote slot from THRESHOLD_DEPTH back. Note THRESHOLD_DEPTH
     is the 8th index back _including_ the simulated vote at index 0. */

  ulong threshold_slot  = fd_tower_vote_peek_index_const( tower->votes, cnt - THRESHOLD_DEPTH )->slot;
  ulong threshold_stake = 0;
  for( fd_tower_vtr_iter_t iter = fd_tower_vtr_iter_init( accts       );
                                 !fd_tower_vtr_iter_done( accts, iter );
                           iter = fd_tower_vtr_iter_next( accts, iter ) ) {
    fd_tower_vtr_t const * acct = fd_tower_vtr_iter_ele_const( accts, iter );

    ulong cnt = simulate_vote( acct->votes, slot ); /* expire votes */
    if( FD_UNLIKELY( !cnt ) ) continue;              /* no votes left after expiry */

    /* Count their stake towards the threshold check if their prev vote
       slot >= our threshold slot.

       We know their prev vote slot is definitely on the same fork as
       our threshold slot, because these towers are sourced from vote
       _accounts_, not vote _transactions_ and the Vote Program
       validates that all slots in the vote account's tower exist on the
       current fork.

       Therefore, if their prev vote slot >= our threshold slot, we know
       that vote must be for the threshold slot itself or one of
       threshold slot's descendants. */

    ulong vote_slot = fd_tower_vote_peek_index_const( acct->votes, cnt - 1 )->slot;
    if( FD_LIKELY( vote_slot >= threshold_slot ) ) threshold_stake += acct->stake;
  }

  double threshold_pct = (double)threshold_stake / (double)total_stake;
  int    threshold     = threshold_pct > THRESHOLD_RATIO;
  if( FD_UNLIKELY( !threshold ) ) FD_LOG_DEBUG(( "[%s] vote_slot: %lu. threshold_slot: %lu. pct: %.0lf%%.", __func__, fd_tower_vote_peek_tail_const( tower->votes )->slot, threshold_slot, threshold_pct * 100.0 ));
  return threshold;
}

static int
propagated_check( fd_tower_t * tower,
                  ulong        slot ) {

  fd_tower_blk_t * blk = fd_tower_blocks_query( tower, slot );
  FD_TEST( blk );

  if( FD_LIKELY( blk->leader                        ) ) return 1; /* can always vote for slot in which we're leader */
  if( FD_LIKELY( blk->prev_leader_slot==ULONG_MAX   ) ) return 1; /* haven't been leader yet */

  fd_tower_blk_t * prev_leader_blk = fd_tower_blocks_query( tower, blk->prev_leader_slot );
  if( FD_LIKELY( !prev_leader_blk ) ) return 1; /* already pruned / rooted */

  return prev_leader_blk->propagated;
}

uchar
fd_tower_vote_and_reset( fd_tower_t * tower,
                         fd_ghost_t * ghost,
                         fd_votes_t * votes FD_PARAM_UNUSED,
                         ulong *      reset_slot,
                         fd_hash_t *  reset_block_id,
                         ulong *      vote_slot,
                         fd_hash_t *  vote_block_id,
                         ulong *      root_slot,
                         fd_hash_t *  root_block_id ) {

  uchar                  flags     = 0;
  fd_ghost_blk_t const * best_blk  = fd_ghost_best( ghost, fd_ghost_root( ghost ) );
  fd_ghost_blk_t const * reset_blk = NULL;
  fd_ghost_blk_t const * vote_blk  = NULL;

  /* Case 0: if we haven't voted yet then we can always vote and reset
     to ghost_best.

     https://github.com/anza-xyz/agave/blob/v2.3.7/core/src/consensus.rs#L933-L935 */

  if( FD_UNLIKELY( fd_tower_vote_empty( tower->votes ) ) ) {
    FD_BASE58_ENCODE_32_BYTES( best_blk->id.uc, best_blk_id );
    FD_LOG_DEBUG(( "[%s] case 0: empty tower. reset_blk: (%lu, %s). vote_blk: (%lu, %s)", __func__, best_blk->slot, best_blk_id, best_blk->slot, best_blk_id ));
    fd_tower_blk_t * fork = fd_tower_blocks_query( tower, best_blk->slot );
    fork->voted           = 1;
    fork->voted_block_id  = best_blk->id;
    *reset_slot     = best_blk->slot;
    *reset_block_id = best_blk->id;
    *vote_slot      = best_blk->slot;
    *vote_block_id  = best_blk->id;
    *root_slot      = push_vote( tower, best_blk->slot );
    *root_block_id  = (fd_hash_t){0};
    return flags;
  }

  ulong            prev_vote_slot = fd_tower_vote_peek_tail_const( tower->votes )->slot;
  fd_tower_blk_t * prev_vote_fork = fd_tower_blocks_query( tower, prev_vote_slot ); /* must exist */

  fd_hash_t      * prev_vote_block_id = &prev_vote_fork->voted_block_id;
  fd_ghost_blk_t * prev_vote_blk      = fd_ghost_query( ghost, prev_vote_block_id );

  /* Case 1: if any ancestor of our prev vote (including prev vote
     itself) is an unconfirmed duplicate, then our prev vote was on a
     duplicate fork.

     There are three subcases to check. */

  int invalid_ancestor = !!fd_ghost_invalid_ancestor( ghost, prev_vote_blk );

  /* Case 1a: ghost_best is an ancestor of prev vote.  This means
     ghost_best is rolling back to an ancestor that precedes the
     duplicate ancestor on the same fork as our prev vote.  In this
     case, we can't vote on our ancestor, but we do reset to that
     ancestor.

     https://github.com/anza-xyz/agave/blob/v2.3.7/core/src/consensus.rs#L1016-L1019 */

  int ancestor_rollback = prev_vote_blk != best_blk && !!fd_ghost_ancestor( ghost, prev_vote_blk, &best_blk->id );

  /* Case 1b: ghost_best is not an ancestor, but prev_vote is a
     duplicate and we've confirmed its duplicate sibling.  In this
     case, we allow switching to ghost_best without a switch proof.

     Example: slot 5 is a duplicate.  We first receive, replay and
     vote for block 5, so that is our prev vote.  We later receive
     block 5' and observe that it is duplicate confirmed.  ghost_best
     now returns block 5' and we both vote and reset to block 5'
     regardless of the switch check.

     https://github.com/anza-xyz/agave/blob/v2.3.7/core/src/consensus.rs#L1021-L1024 */

  int sibling_confirmed = prev_vote_fork->confirmed && 0!=memcmp( &prev_vote_fork->voted_block_id, &prev_vote_fork->confirmed_block_id, sizeof(fd_hash_t) );

  if( FD_UNLIKELY( invalid_ancestor && ancestor_rollback ) ) {
    flags     = fd_uchar_set_bit( flags, FD_TOWER_FLAG_ANCESTOR_ROLLBACK );
    reset_blk = best_blk;
    FD_BASE58_ENCODE_32_BYTES( reset_blk->id.uc, reset_blk_id );
    FD_LOG_DEBUG(( "[%s] case 1a: ancestor rollback. prev_vote_slot: %lu. reset_blk: (%lu, %s). vote_blk: (NULL)", __func__, prev_vote_slot, reset_blk->slot, reset_blk_id ));

  } else if( FD_UNLIKELY( invalid_ancestor && sibling_confirmed ) ) {
    flags     = fd_uchar_set_bit( flags, FD_TOWER_FLAG_SIBLING_CONFIRMED );
    reset_blk = best_blk;
    vote_blk  = best_blk;
    FD_BASE58_ENCODE_32_BYTES( reset_blk->id.uc, reset_blk_id );
    FD_BASE58_ENCODE_32_BYTES( vote_blk->id.uc,  vote_blk_id  );
    FD_LOG_DEBUG(( "[%s] case 1b: sibling confirmed. prev_vote_slot: %lu. reset_blk: (%lu, %s). vote_blk: (%lu, %s)", __func__, prev_vote_slot, reset_blk->slot, reset_blk_id, vote_blk->slot, vote_blk_id ));
  }

  /* Case 2: if our prev vote slot is an ancestor of the best slot, then
     they are on the same fork and we can both reset to it.  We can also
     vote for it if we pass the can_vote checks.

     https://github.com/anza-xyz/agave/blob/v2.3.7/core/src/consensus.rs#L1057 */

  else if( FD_LIKELY( best_blk->slot == prev_vote_slot || fd_tower_blocks_is_slot_ancestor( tower, best_blk->slot, prev_vote_slot ) ) ) {
    flags     = fd_uchar_set_bit( flags, FD_TOWER_FLAG_SAME_FORK );
    reset_blk = best_blk;
    vote_blk  = best_blk;
    FD_BASE58_ENCODE_32_BYTES( reset_blk->id.uc, reset_blk_id );
    FD_BASE58_ENCODE_32_BYTES( vote_blk->id.uc,  vote_blk_id  );
    FD_LOG_DEBUG(( "[%s] case 2: same fork. prev_vote_slot: %lu. reset_blk: (%lu, %s). vote_blk: (%lu, %s)", __func__, prev_vote_slot, reset_blk->slot, reset_blk_id, vote_blk->slot, vote_blk_id ));
  }

  /* Case 3: if our prev vote is not an ancestor of the best block, then
     it is on a different fork.  If we pass the switch check, we can
     reset to it.  If we additionally pass the lockout check, we can
     also vote for it.

     https://github.com/anza-xyz/agave/blob/v2.3.7/core/src/consensus.rs#L1208-L1215

     Note also Agave uses the best blk's total stake for checking the
     threshold.

     https://github.com/anza-xyz/agave/blob/v2.3.7/core/src/consensus/fork_choice.rs#L443-L445 */

  else if( FD_LIKELY( switch_check( tower, ghost, best_blk->total_stake, best_blk->slot ) ) ) {
    flags     = fd_uchar_set_bit( flags, FD_TOWER_FLAG_SWITCH_PASS );
    reset_blk = best_blk;
    vote_blk  = best_blk;
    FD_BASE58_ENCODE_32_BYTES( reset_blk->id.uc, reset_blk_id );
    FD_BASE58_ENCODE_32_BYTES( vote_blk->id.uc,  vote_blk_id  );
    FD_LOG_DEBUG(( "[%s] case 3: switch pass. prev_vote_slot: %lu. reset_blk: (%lu, %s). vote_blk: (%lu, %s)", __func__, prev_vote_slot, reset_blk->slot, reset_blk_id, vote_blk->slot, vote_blk_id ));
  }

  /* Case 4: same as case 3 but we didn't pass the switch check.  In
     this case we reset to either ghost_best or ghost_deepest beginning
     from our prev vote blk.

     We must reset to a block beginning from our prev vote fork to
     ensure votes get a chance to propagate.  Because in order for votes
     to land, someone needs to build a block on that fork.

     We reset to ghost_best or ghost_deepest depending on whether our
     prev vote is valid.  When it's invalid we use ghost_deepest instead
     of ghost_best, because ghost_best won't be able to return a valid
     block beginning from our prev_vote because by definition the entire
     subtree will be invalid.

     When our prev vote fork is not a duplicate, we want to propagate
     votes that might allow others to switch to our fork.  In addition,
     if our prev vote fork is a duplicate, we want to propagate votes
     that might "duplicate confirm" that block (reach 52% of stake).

     See top-level documentation in fd_tower.h for more details on vote
     propagation. */

  else {

    /* Case 4a: failed switch check and last vote slot has an invalid
       ancestor.

      https://github.com/anza-xyz/agave/blob/v2.3.7/core/src/consensus/heaviest_subtree_fork_choice.rs#L1187 */

    if( FD_UNLIKELY( invalid_ancestor ) ) {
      flags     = fd_uchar_set_bit( flags, FD_TOWER_FLAG_SWITCH_FAIL );
      reset_blk = fd_ghost_deepest( ghost, prev_vote_blk );
      FD_BASE58_ENCODE_32_BYTES( reset_blk->id.uc, reset_blk_id );
      FD_LOG_DEBUG(( "[%s] case 4a: switch fail, invalid ancestor. prev_vote_slot: %lu. reset_blk: (%lu, %s). vote_blk: (NULL)", __func__, prev_vote_slot, reset_blk->slot, reset_blk_id ));
    }

    /* Case 4b: failed switch check (no invalid ancestor).

      https://github.com/anza-xyz/agave/blob/v2.3.7/core/src/consensus/fork_choice.rs#L200 */

    else {
      flags     = fd_uchar_set_bit( flags, FD_TOWER_FLAG_SWITCH_FAIL );
      reset_blk = fd_ghost_best( ghost, prev_vote_blk );
      FD_BASE58_ENCODE_32_BYTES( reset_blk->id.uc, reset_blk_id );
      FD_LOG_DEBUG(( "[%s] case 4b: switch fail, no invalid ancestor. prev_vote_slot: %lu. reset_blk: (%lu, %s). vote_blk: (NULL)", __func__, prev_vote_slot, reset_blk->slot, reset_blk_id ));
    }
  }

  /* If there is a block to vote for, there are a few additional checks
     to make sure we can actually vote for it.

     Specifically, we need to make sure we're not locked out, pass the
     threshold check and that our previous leader block has propagated
     (reached the prop threshold according to fd_votes).

     https://github.com/firedancer-io/agave/blob/master/core/src/consensus/fork_choice.rs#L382-L385

     Agave uses the total stake on the fork being threshold checked
     (vote_blk) for determining whether it meets the stake threshold. */

  if( FD_LIKELY( vote_blk ) ) {
    if     ( FD_UNLIKELY( !lockout_check( tower, vote_blk->slot ) ) ) {
      FD_BASE58_ENCODE_32_BYTES( vote_blk->id.uc, vote_blk_id );
      FD_LOG_DEBUG(( "[%s] lockout check failed. prev_vote_slot: %lu. vote_blk: (%lu, %s)", __func__, prev_vote_slot, vote_blk->slot, vote_blk_id ));
      flags    = fd_uchar_set_bit( flags, FD_TOWER_FLAG_LOCKOUT_FAIL );
      vote_blk = NULL;
    }
    else if( FD_UNLIKELY( !threshold_check( tower, tower->vtrs, vote_blk->total_stake, vote_blk->slot ) ) ) {
      FD_BASE58_ENCODE_32_BYTES( vote_blk->id.uc, vote_blk_id );
      FD_LOG_DEBUG(( "[%s] threshold check failed. prev_vote_slot: %lu. vote_blk: (%lu, %s)", __func__, prev_vote_slot, vote_blk->slot, vote_blk_id ));
      flags    = fd_uchar_set_bit( flags, FD_TOWER_FLAG_THRESHOLD_FAIL );
      vote_blk = NULL;
    }
    else if( FD_UNLIKELY( !propagated_check( tower, vote_blk->slot ) ) ) {
      FD_BASE58_ENCODE_32_BYTES( vote_blk->id.uc, vote_blk_id );
      FD_LOG_DEBUG(( "[%s] propagated check failed. prev_vote_slot: %lu. vote_blk: (%lu, %s)", __func__, prev_vote_slot, vote_blk->slot, vote_blk_id ));
      flags    = fd_uchar_set_bit( flags, FD_TOWER_FLAG_PROPAGATED_FAIL );
      vote_blk = NULL;
    }
  }

  FD_TEST( reset_blk ); /* always a reset_blk */
  *reset_slot     = reset_blk->slot;
  *reset_block_id = reset_blk->id;
  *vote_slot      = ULONG_MAX;
  *vote_block_id  = (fd_hash_t){0};
  *root_slot      = ULONG_MAX;
  *root_block_id  = (fd_hash_t){0};

  /* Finally, if our vote passed all the checks, we actually push the
     vote onto the tower. */

  if( FD_LIKELY( vote_blk ) ) {
    *vote_slot     = vote_blk->slot;
    *vote_block_id = vote_blk->id;
    *root_slot     = push_vote( tower, vote_blk->slot );

    /* Query our tower fork for this slot we're voting for.  Note this
       can never be NULL because we record tower forks as we replay, and
       we should never be voting on something we haven't replayed. */

    fd_tower_blk_t * fork = fd_tower_blocks_query( tower, vote_blk->slot );
    fork->voted           = 1;
    fork->voted_block_id  = vote_blk->id;

    /* Query the root slot's block id from tower forks.  This block id
       may not necessarily be confirmed, because confirmation requires
       votes on the block itself (vs. block and its descendants).

       So if we have a confirmed block id, we return that.  Otherwise
       we return our own vote block id for that slot, which we assume
       is the cluster converged on by the time we're rooting it.

       The only way it is possible for us to root the wrong version of
       a block (ie. not the one the cluster confirmed) is if there is
       mass equivocation (>2/3 of threshold check stake has voted for
       two versions of a block).  This exceeds the equivocation safety
       threshold and we would eventually detect this via a bank hash
       mismatch and error out. */

    if( FD_LIKELY( *root_slot!=ULONG_MAX ) ) {
      fd_tower_blk_t * root_fork = fd_tower_blocks_query( tower, *root_slot );
      *root_block_id         = *fd_ptr_if( root_fork->confirmed, &root_fork->confirmed_block_id, &root_fork->voted_block_id );
    }
  }

  FD_BASE58_ENCODE_32_BYTES( reset_block_id->uc, reset_block_id_b58 );
  FD_BASE58_ENCODE_32_BYTES( vote_block_id->uc,  vote_block_id_b58  );
  FD_BASE58_ENCODE_32_BYTES( root_block_id->uc,  root_block_id_b58  );
  FD_LOG_DEBUG(( "[%s] flags: %d. reset_slot: %lu (%s). vote_slot: %lu (%s). root_slot: %lu (%s).", __func__, flags, *reset_slot, reset_block_id_b58, *vote_slot, vote_block_id_b58, *root_slot, root_block_id_b58 ));
  return flags;
}

/* fd_tower_reconcile reconciles our local tower with our on-chain tower
   (stored inside our vote account).  This function is important in two
   contexts:

   ON BOOT

   When Firedancer boots up its local tower contains no votes, only a
   root slot set to the snapshot slot.  It needs to restore its "latest"
   tower votes and root as of its previous run.  This information is
   stored on-chain itself, in a vote account, and Firedancer updates
   vote account states during catchup by replaying blocks since the
   snapshot.  Firedancer reconciles its local tower with the on-chain
   one every time it replays a block, and will by definition have its
   "latest" tower once it has caught up.

   Note that it is possible Firedancer had voted for a minority fork in
   the previous run.  In this case, its true "latest" tower contains
   votes for slots that were pruned by the time of this boot.  In theory
   TowerBFT stipulates that lockout can be up to 2^32 slots, but in
   practice slots are pruned once they fall out of the slot hash history
   limit, because they can no longer be canonically verified on-chain.
   Therefore, Firedancer can safely ignore slots that are pruned and
   restore its latest tower on the majority fork as of boot time.

   HIGH-AVAILABILITY SETUP

   A typical validator setup involves two nodes, a primary and a backup.
   The primary is a valid fee payer, and the one landing votes recording
   the latest state of its tower on-chain.  The two nodes' towers will
   usually be identical but occassionally diverge when one node votes
   for slots that the other one doesn't.  This usually happens when
   there are multiple forks.

   This becomes a problem, because the primary's tower may contain votes
   the backup doesn't have and/or vice versa.  The primary's tower is
   the canonical one, since it's the one recorded on-chain, so reconcile
   is a no-op on the primary.

   On the backup, reconcile is more involved.  Because what's on-chain
   is the primary's tower, there may be slots the backup never actually
   voted for.  When the backup node reads back the on-chain tower, some
   metadata, namely `voted` and `voted_block_id`, will be missing from
   its fd_tower instance.

   fd_tower_reconcile assumes that if a tower has been recorded on-chain
   then it is safe to assume the vote account registered with the
   currently running Firedancer has in fact at some point voted for the
   slots in that tower.

   In case the instance is the backup, it updates the local tower votes,
   root, and metadata structures accordingly with this assumption namely
   by inserting voted_block_id for votes that the backup didn't actually
   vote for but can safely assume the primary did.

   This affects the Tower voting rules (see fd_tower_vote_and_reset) in
   that the voted_block_id is used for certain vote and reset decisions.

   There are some corner cases to consider related to equivocation:

      2
     / \
    3   3' (confirmed)

   Assume 3 and 3' are alternate blocks for the same slot (3) and have
   different block ids.  3' is the block that eventually gets confirmed.
   Let's consider a scenario in which the primary votes for "3" and the
   backup misses the vote for "3".  fd_tower_reconcile needs to backfill
   the voted_block_id for "3" on the backup.  However, it's unclear
   whether that vote is for 3 (unconfirmed) or 3' (confirmed), because
   all the on-chain tower contains is the slot "3" (with no block_id).
   How does the backup figure out the voted_block_id?

   It turns out it doesn't really matter either way, the backup can just
   backfill with whichever block_id it happened to replay (we know the
   backup has to have replayed either 3 or 3' in order to observe an
   on-chain tower containing 3 in the first place):

   If the primary voted for 3 and the backup backfills with 3', we know
   the primary will eventually switch to the DC block (3') via repair.
   So backfilling with 3' is ok because the primary will converge to it.

   If the primary voted for 3' and the backup backfills with 3, then the
   backup will similarly eventually switch to the DC block via repair.
   Indeed, it will "freebie" switch in fd_tower_vote_and_reset ie. case
   1b: "sibling confirmed".  Thus, the backup will converge to 3'. */

void
fd_tower_reconcile( fd_tower_t      * tower,
                    fd_tower_vote_t * onchain_votes,
                    ulong             onchain_root ) {

  fd_tower_vote_t * local_votes = tower->votes;
  ulong             local_root  = tower->root;

  ulong local_vote   = fd_tower_vote_empty( local_votes   ) ? ULONG_MAX : fd_tower_vote_peek_tail_const( local_votes   )->slot;
  ulong onchain_vote = fd_tower_vote_empty( onchain_votes ) ? ULONG_MAX : fd_tower_vote_peek_tail_const( onchain_votes )->slot;

  /* Cases:

     Agave checks Option<onchain_vote> <= Option<local_vote>.  Breakdown of Ord<Option<Slot>>:

     None, None => True
     None, Some => True
     Some, None => False
     Some, Some => onchain_vote <= local_vote */

  if( FD_LIKELY( onchain_vote==ULONG_MAX ||                            /* None, None or None, Some */
               ( local_vote  !=ULONG_MAX && onchain_vote<=local_vote ) /* Some, Some               */ ) ) return;

  /* On-chain tower is newer, so sync our local tower to the on-chain tower. */

  char local_cstr[FD_TOWER_CSTR_MIN];
  FD_LOG_NOTICE(( "[%s] overwriting local tower:\n\n%s\nwith onchain tower (root=%lu, vote_cnt=%lu, tip=%lu)", __func__, fd_tower_to_cstr( tower, local_cstr ), onchain_root, fd_tower_vote_cnt( onchain_votes ), onchain_vote ));

  FD_TEST( local_root!=ULONG_MAX ); /* local root should always be set before fd_tower_reconcile */
  if( FD_LIKELY( onchain_root==ULONG_MAX || local_root > onchain_root ) ) {

    /* Local root is larger than on-chain root. Overwrite on-chain root
       with local root (this is just a copy, not writing to accdb). */

    FD_LOG_NOTICE(( "[%s] local_root %lu > onchain_root %lu", __func__, local_root, onchain_root ));
    onchain_root = local_root;

    /* Drop on-chain votes <= local root. */

    while( FD_LIKELY( !fd_tower_vote_empty( onchain_votes ) ) ) {
      fd_tower_vote_t const * vote = fd_tower_vote_peek_head_const( onchain_votes );
      if( FD_LIKELY( vote->slot > local_root ) ) break;
      FD_LOG_NOTICE(( "[%s] dropping on-chain vote for slot %lu since it's <= local root %lu", __func__, vote->slot, local_root ));
      fd_tower_vote_pop_head( onchain_votes );
    }

    /* TODO add sanity-check that onchain_root is an ancestor of the
       first vote's ancestor at this point. */
  }

  for( fd_tower_vote_iter_t iter = fd_tower_vote_iter_init( tower->votes );
                                  !fd_tower_vote_iter_done( tower->votes, iter );
                            iter = fd_tower_vote_iter_next( tower->votes, iter ) ) {
    fd_tower_vote_t const * vote = fd_tower_vote_iter_ele_const( tower->votes, iter );
    fd_tower_blk_t * tower_blk = fd_tower_blocks_query( tower, vote->slot );
    FD_TEST( tower_blk ); /* must exist if it's in our tower */
    tower_blk->voted = 0;
  }

  /* Need to overwrite tower->root with onchain_root, so first clear out
     any intermediate slots between them. */

  for( ulong slot = tower->root; slot < onchain_root; slot++ ) {
    fd_tower_blocks_remove( tower, slot );
    fd_tower_lockos_remove( tower, slot );
    fd_tower_stakes_remove( tower, slot );
  }

  /* Overwrite the root.  No-op if local_root > onchain_root. */

  tower->root = onchain_root;

  /* Clear out all local_votes. */

  fd_tower_vote_remove_all( tower->votes );

  /* Replace them with onchain_votes. */

  for( fd_tower_vote_iter_t iter = fd_tower_vote_iter_init( onchain_votes );
                                  !fd_tower_vote_iter_done( onchain_votes, iter );
                            iter = fd_tower_vote_iter_next( onchain_votes, iter ) ) {
    fd_tower_vote_t const * vote = fd_tower_vote_iter_ele_const( onchain_votes, iter );
    fd_tower_vote_push_tail( tower->votes, *vote );

    /* Additionally, backfill voted_block_id for the slots we didn't
       actually vote for.  This is intentionally always using the latest
       replayed_block_id if we overwrote it with a second replay.  */

    fd_tower_blk_t * tower_blk = fd_tower_blocks_query( tower, vote->slot );
    FD_TEST( tower_blk ); /* must exist because
                             1. all on-chain votes >  root slot
                             2. all on-chain votes <= replay slot  */
    if( FD_UNLIKELY( !tower_blk->voted ) ) {
      tower_blk->voted          = 1;
      tower_blk->voted_block_id = tower_blk->replayed_block_id;
    }
  }
}

void
fd_tower_from_vote_acc( fd_tower_vote_t * votes,
                        ulong           * root,
                        uchar  const    * vote_acc ) {
  fd_vote_acc_t const * voter = (fd_vote_acc_t const *)fd_type_pun_const( vote_acc );
  uint               kind  = fd_uint_load_4_fast( vote_acc ); /* skip node_pubkey */
  for( ulong i=0; i<fd_vote_acc_vote_cnt( vote_acc ); i++ ) {
    switch( kind ) {
    case FD_VOTE_ACC_V4: fd_tower_vote_push_tail( votes, (fd_tower_vote_t){ .slot = v4_off( voter )[i].slot, .conf = v4_off( voter )[i].conf } ); break;
    case FD_VOTE_ACC_V3: fd_tower_vote_push_tail( votes, (fd_tower_vote_t){ .slot = voter->v3.votes[i].slot, .conf = voter->v3.votes[i].conf } ); break;
    case FD_VOTE_ACC_V2: fd_tower_vote_push_tail( votes, (fd_tower_vote_t){ .slot = voter->v2.votes[i].slot, .conf = voter->v2.votes[i].conf } ); break;
    default:          FD_LOG_ERR(( "unsupported voter account version: %u", kind ));
    }
  }
  *root = fd_vote_acc_root_slot( vote_acc );
}

ulong
fd_tower_with_lat_from_vote_acc( fd_vote_acc_vote_t tower[ static FD_TOWER_VOTE_MAX ],
                                 uchar const *      vote_acc ) {
  fd_vote_acc_t const * voter = (fd_vote_acc_t const *)fd_type_pun_const( vote_acc );
  uint               kind  = fd_uint_load_4_fast( vote_acc ); /* skip node_pubkey */
  for( ulong i=0; i<fd_vote_acc_vote_cnt( vote_acc ); i++ ) {
    switch( kind ) {
    case FD_VOTE_ACC_V4: tower[ i ] = (fd_vote_acc_vote_t){ .latency = v4_off( voter )[i].latency, .slot = v4_off( voter )[i].slot, .conf = v4_off( voter )[i].conf }; break;
    case FD_VOTE_ACC_V3: tower[ i ] = (fd_vote_acc_vote_t){ .latency = voter->v3.votes[i].latency, .slot = voter->v3.votes[i].slot, .conf = voter->v3.votes[i].conf }; break;
    case FD_VOTE_ACC_V2: tower[ i ] = (fd_vote_acc_vote_t){ .latency = UCHAR_MAX,                  .slot = voter->v2.votes[i].slot, .conf = voter->v2.votes[i].conf }; break;
    default:          FD_LOG_ERR(( "unsupported voter account version: %u", kind ));
    }
  }

  return fd_vote_acc_vote_cnt( vote_acc );
}

void
fd_tower_to_vote_txn( fd_tower_t const *    tower,
                      fd_hash_t const *     bank_hash,
                      fd_hash_t const *     block_id,
                      fd_hash_t const *     recent_blockhash,
                      fd_pubkey_t const *   validator_identity,
                      fd_pubkey_t const *   vote_authority,
                      fd_pubkey_t const *   vote_acc,
                      fd_txn_p_t *          vote_txn ) {

  FD_TEST( fd_tower_vote_cnt( tower->votes )<=FD_TOWER_VOTE_MAX );
  fd_compact_tower_sync_serde_t tower_sync_serde = {
    .root             = fd_ulong_if( tower->root == ULONG_MAX, 0UL, tower->root ),
    .lockouts_cnt     = (ushort)fd_tower_vote_cnt( tower->votes ),
    /* .lockouts populated below */
    .hash             = *bank_hash,
    .timestamp_option = 1,
    .timestamp        = fd_log_wallclock() / (long)1e9, /* seconds */
    .block_id         = *block_id
  };

  ulong i = 0UL;
  ulong prev = tower_sync_serde.root;
  for( fd_tower_vote_iter_t iter = fd_tower_vote_iter_init( tower->votes       );
                             !fd_tower_vote_iter_done( tower->votes, iter );
                       iter = fd_tower_vote_iter_next( tower->votes, iter ) ) {
    fd_tower_vote_t const * vote                         = fd_tower_vote_iter_ele_const( tower->votes, iter );
    tower_sync_serde.lockouts[i].offset             = vote->slot - prev;
    tower_sync_serde.lockouts[i].confirmation_count = (uchar)vote->conf;
    prev                                            = vote->slot;
    i++;
  }

  uchar * txn_out = vote_txn->payload;
  uchar * txn_meta_out = vote_txn->_;

  int same_addr = !memcmp( validator_identity, vote_authority, sizeof(fd_pubkey_t) );
  if( FD_LIKELY( same_addr ) ) {

    /* 0: validator identity
       1: vote account address
       2: vote program */

    fd_txn_accounts_t votes;
    votes.signature_cnt         = 1;
    votes.readonly_signed_cnt   = 0;
    votes.readonly_unsigned_cnt = 1;
    votes.acct_cnt              = 3;
    votes.signers_w             = validator_identity;
    votes.signers_r             = NULL;
    votes.non_signers_w         = vote_acc;
    votes.non_signers_r         = &fd_solana_vote_program_id;
    FD_TEST( fd_txn_base_generate( txn_meta_out, txn_out, votes.signature_cnt, &votes, recent_blockhash->uc ) );

  } else {

    /* 0: validator identity
       1: vote authority
       2: vote account address
       3: vote program */

    fd_txn_accounts_t votes;
    votes.signature_cnt         = 2;
    votes.readonly_signed_cnt   = 1;
    votes.readonly_unsigned_cnt = 1;
    votes.acct_cnt              = 4;
    votes.signers_w             = validator_identity;
    votes.signers_r             = vote_authority;
    votes.non_signers_w         = vote_acc;
    votes.non_signers_r         = &fd_solana_vote_program_id;
    FD_TEST( fd_txn_base_generate( txn_meta_out, txn_out, votes.signature_cnt, &votes, recent_blockhash->uc ) );
  }

  /* Add the vote instruction to the transaction. */

  uchar  vote_ix_buf[FD_TXN_MTU];
  ulong  vote_ix_sz = 0;
  FD_STORE( uint, vote_ix_buf, FD_VOTE_IX_KIND_TOWER_SYNC );
  FD_TEST( 0==fd_compact_tower_sync_ser( &tower_sync_serde, vote_ix_buf + sizeof(uint), FD_TXN_MTU - sizeof(uint), &vote_ix_sz ) ); // cannot fail if fd_tower_vote_cnt( tower->votes ) <= FD_TOWER_VOTE_MAX
  vote_ix_sz += sizeof(uint);
  uchar program_id;
  uchar ix_accs[2];
  if( FD_LIKELY( same_addr ) ) {
    ix_accs[0] = 1; /* vote account address */
    ix_accs[1] = 0; /* vote authority */
    program_id = 2; /* vote program */
  } else {
    ix_accs[0] = 2; /* vote account address */
    ix_accs[1] = 1; /* vote authority */
    program_id = 3; /* vote program */
  }
  vote_txn->payload_sz = fd_txn_add_instr( txn_meta_out, txn_out, program_id, ix_accs, 2, vote_ix_buf, vote_ix_sz );
}

int
fd_tower_verify( fd_tower_t const * tower ) {
  if( FD_UNLIKELY( fd_tower_vote_cnt( tower->votes )>=FD_TOWER_VOTE_MAX ) ) {
    FD_LOG_WARNING(( "[%s] invariant violation: cnt %lu >= FD_TOWER_VOTE_MAX %lu", __func__, fd_tower_vote_cnt( tower->votes ), (ulong)FD_TOWER_VOTE_MAX ));
    return -1;
  }

  fd_tower_vote_t const * prev = NULL;
  for( fd_tower_vote_iter_t iter = fd_tower_vote_iter_init( tower->votes       );
                                   !fd_tower_vote_iter_done( tower->votes, iter );
                             iter = fd_tower_vote_iter_next( tower->votes, iter ) ) {
    fd_tower_vote_t const * vote = fd_tower_vote_iter_ele_const( tower->votes, iter );
    if( FD_UNLIKELY( prev && ( vote->slot < prev->slot || vote->conf < prev->conf ) ) ) {
      FD_LOG_WARNING(( "[%s] invariant violation: vote (slot:%lu conf:%lu) prev (slot:%lu conf:%lu)", __func__, vote->slot, vote->conf, prev->slot, prev->conf ));
      return -1;
    }
    prev = vote;
  }
  return 0;
}

static void
to_cstr( fd_tower_t const * tower, char * s, ulong len ) {
  ulong root = tower->root;
  ulong off = 0;
  int   n;

  n = snprintf( s + off, len - off, "[Tower]\n\n" );
  if( FD_UNLIKELY( n < 0 )) FD_LOG_CRIT(( "snprintf: %d", n ));
  off += (ulong)n;

  if( FD_UNLIKELY( fd_tower_vote_empty( tower->votes ) ) ) return;

  ulong max_slot = 0;

  /* Determine spacing. */

  for( fd_tower_vote_iter_t iter = fd_tower_vote_iter_init_rev( tower->votes       );
                             !fd_tower_vote_iter_done_rev( tower->votes, iter );
                       iter = fd_tower_vote_iter_prev    ( tower->votes, iter ) ) {
    max_slot = fd_ulong_max( max_slot, fd_tower_vote_iter_ele_const( tower->votes, iter )->slot );
  }

  /* Calculate the number of digits in the maximum slot value. */


  int digit_cnt = (int)fd_ulong_base10_dig_cnt( max_slot );

  /* Print the column headers. */

  if( off < len ) {
    n = snprintf( s + off, len - off, "slot%*s | %s\n", digit_cnt - (int)strlen("slot"), "", "confirmation count" );
    if( FD_UNLIKELY( n < 0 )) FD_LOG_CRIT(( "snprintf: %d", n ));
    off += (ulong)n;
  }

  /* Print the divider line. */

  for( int i = 0; i < digit_cnt && off < len; i++ ) {
    s[off++] = '-';
  }
  if( off < len ) {
    n = snprintf( s + off, len - off, " | " );
    if( FD_UNLIKELY( n < 0 )) FD_LOG_CRIT(( "snprintf: %d", n ));
    off += (ulong)n;
  }
  for( ulong i = 0; i < strlen( "confirmation count" ) && off < len; i++ ) {
    s[off++] = '-';
  }
  if( off < len ) {
    s[off++] = '\n';
  }

  /* Print each vote as a table. */

  for( fd_tower_vote_iter_t iter = fd_tower_vote_iter_init_rev( tower->votes       );
                             !fd_tower_vote_iter_done_rev( tower->votes, iter );
                       iter = fd_tower_vote_iter_prev    ( tower->votes, iter ) ) {
    fd_tower_vote_t const * vote = fd_tower_vote_iter_ele_const( tower->votes, iter );
    if( off < len ) {
      n = snprintf( s + off, len - off, "%*lu | %lu\n", digit_cnt, vote->slot, vote->conf );
      if( FD_UNLIKELY( n < 0 )) FD_LOG_CRIT(( "snprintf: %d", n ));
      off += (ulong)n;
    }
  }

  if( FD_UNLIKELY( root == ULONG_MAX ) ) {
    if( off < len ) {
      n = snprintf( s + off, len - off, "%*s | root\n", digit_cnt, "NULL" );
      if( FD_UNLIKELY( n < 0 )) FD_LOG_CRIT(( "snprintf: %d", n ));
      off += (ulong)n;
    }
  } else {
    if( off < len ) {
      n = snprintf( s + off, len - off, "%*lu | root\n", digit_cnt, root );
      if( FD_UNLIKELY( n < 0 )) FD_LOG_CRIT(( "snprintf: %d", n ));
      off += (ulong)n;
    }
  }

  /* Ensure null termination */
  if( off < len ) {
    s[off] = '\0';
  } else {
    s[len - 1] = '\0';
  }
}

char *
fd_tower_to_cstr( fd_tower_t const * tower,
                  char *             cstr ) {
  to_cstr( tower, cstr, FD_TOWER_CSTR_MIN );
  return cstr;
}

void
fd_tower_count_vote( fd_tower_t *        tower,
                     fd_pubkey_t const * vote_acc,
                     ulong               stake,
                     uchar const         data[static FD_VOTE_STATE_DATA_MAX] ) {
  fd_tower_vtr_t * vtr = fd_tower_vtr_push_tail_nocopy( tower->vtrs );
  vtr->vote_acc        = *vote_acc;
  vtr->stake           = stake;
  fd_tower_vote_remove_all( vtr->votes );
  fd_tower_from_vote_acc( vtr->votes, &vtr->root, data );
}

/* Block functions ********************************************************/

static int
is_ancestor( fd_tower_t * tower,
             ulong        slot,
             ulong        ancestor_slot ) {
  fd_tower_blk_t * anc = blk_map_ele_query( tower->blk_map, &slot, NULL, tower->blk_pool );
  while( FD_LIKELY( anc ) ) {
    if( FD_LIKELY( anc->parent_slot == ancestor_slot ) ) return 1;
    anc = anc->parent_slot == ULONG_MAX ? NULL : blk_map_ele_query( tower->blk_map, &anc->parent_slot, NULL, tower->blk_pool );
  }
  return 0;
}

int
fd_tower_blocks_is_slot_ancestor( fd_tower_t * tower,
                                  ulong        descendant_slot,
                                  ulong        ancestor_slot ) {
  return is_ancestor( tower, descendant_slot, ancestor_slot );
}

int
fd_tower_blocks_is_slot_descendant( fd_tower_t * tower,
                                    ulong        ancestor_slot,
                                    ulong        descendant_slot ) {
  return is_ancestor( tower, descendant_slot, ancestor_slot );
}

ulong
fd_tower_blocks_lowest_common_ancestor( fd_tower_t * tower,
                                        ulong        slot1,
                                        ulong        slot2 ) {

  fd_tower_blk_t * fork1 = blk_map_ele_query( tower->blk_map, &slot1, NULL, tower->blk_pool );
  fd_tower_blk_t * fork2 = blk_map_ele_query( tower->blk_map, &slot2, NULL, tower->blk_pool );

  if( FD_UNLIKELY( !fork1 )) FD_LOG_CRIT(( "slot1 %lu not found", slot1 ));
  if( FD_UNLIKELY( !fork2 )) FD_LOG_CRIT(( "slot2 %lu not found", slot2 ));

  while( FD_LIKELY( fork1 && fork2 ) ) {
    if( FD_UNLIKELY( fork1->slot == fork2->slot ) ) return fork1->slot;
    if( fork1->slot > fork2->slot                 ) fork1 = blk_map_ele_query( tower->blk_map, &fork1->parent_slot, NULL, tower->blk_pool );
    else                                            fork2 = blk_map_ele_query( tower->blk_map, &fork2->parent_slot, NULL, tower->blk_pool );
  }

  return ULONG_MAX;
}

fd_hash_t const *
fd_tower_blocks_canonical_block_id( fd_tower_t * tower,
                                    ulong        slot ) {
  fd_tower_blk_t * blk = blk_map_ele_query( tower->blk_map, &slot, NULL, tower->blk_pool );
  if( FD_UNLIKELY( !blk ) ) return NULL;
  if     ( FD_LIKELY( blk->confirmed ) ) return &blk->confirmed_block_id;
  else if( FD_LIKELY( blk->voted     ) ) return &blk->voted_block_id;
  else                                   return &blk->replayed_block_id;
}

fd_tower_blk_t *
fd_tower_blocks_query( fd_tower_t * tower, ulong slot ) {
  return blk_map_ele_query( tower->blk_map, &slot, NULL, tower->blk_pool );
}

fd_tower_blk_t *
fd_tower_blocks_insert( fd_tower_t * tower,
                        ulong        slot,
                        ulong        parent_slot ) {
  fd_tower_blk_t * blk = blk_pool_ele_acquire( tower->blk_pool );
  if( FD_UNLIKELY( !blk ) ) return NULL;

  memset( blk, 0, sizeof(fd_tower_blk_t) );
  blk->parent_slot      = parent_slot;
  blk->slot             = slot;
  blk->prev_leader_slot = ULONG_MAX;
  blk_map_ele_insert( tower->blk_map, blk, tower->blk_pool );
  return blk;
}

void
fd_tower_blocks_remove( fd_tower_t * tower,
                        ulong        slot ) {
  fd_tower_blk_t * blk = blk_map_ele_query( tower->blk_map, &slot, NULL, tower->blk_pool );
  if( FD_LIKELY( blk ) ) {
    blk_map_ele_remove_fast( tower->blk_map, blk, tower->blk_pool );
    blk_pool_ele_release( tower->blk_pool, blk );
  }
}

/* Lockos implementation */

void
fd_tower_lockos_insert( fd_tower_t *      tower,
                        ulong             slot,
                        fd_hash_t const * addr,
                        fd_tower_vote_t * votes ) {

  lockout_interval_map_t * lck_map  = tower->lck_map;
  lockout_interval_t *     lck_pool = tower->lck_pool;

  for( fd_tower_vote_iter_t iter = fd_tower_vote_iter_init( votes );
                                  !fd_tower_vote_iter_done( votes, iter );
                            iter = fd_tower_vote_iter_next( votes, iter ) ) {
    fd_tower_vote_t const * vote = fd_tower_vote_iter_ele_const( votes, iter );
    ulong        interval_start = vote->slot;
    ulong        interval_end   = vote->slot + ( 1UL << vote->conf );
    ulong        key            = lockout_interval_key( slot, interval_end );

    if( !lockout_interval_map_ele_query( lck_map, &key, NULL, lck_pool ) ) {
      /* Insert sentinel for pruning.  key = fork_slot | 0, start = interval_end. */
      ulong sentinel_key = lockout_interval_key( slot, 0 );
      FD_TEST( lockout_interval_pool_free( lck_pool ) );
      lockout_interval_t * sentinel = lockout_interval_pool_ele_acquire( lck_pool );
      sentinel->key   = sentinel_key;
      sentinel->start = interval_end;
      lockout_interval_map_ele_insert( lck_map, sentinel, lck_pool );
    }

    FD_TEST( lockout_interval_pool_free( lck_pool ) );
    lockout_interval_t * interval = lockout_interval_pool_ele_acquire( lck_pool );
    interval->key                         = key;
    interval->addr                        = *addr;
    interval->start                       = interval_start;
    FD_TEST( lockout_interval_map_ele_insert( lck_map, interval, lck_pool ) );
  }
}

void
fd_tower_lockos_remove( fd_tower_t * tower,
                        ulong        slot ) {

  lockout_interval_map_t * lck_map  = tower->lck_map;
  lockout_interval_t *     lck_pool = tower->lck_pool;

  ulong sentinel_key = lockout_interval_key( slot, 0 );
  for( lockout_interval_t * sentinel = lockout_interval_map_ele_remove( lck_map, &sentinel_key, NULL, lck_pool );
                            sentinel;
                            sentinel = lockout_interval_map_ele_remove( lck_map, &sentinel_key, NULL, lck_pool ) ) {
    ulong interval_end = sentinel->start;
    lockout_interval_pool_ele_release( lck_pool, sentinel );

    ulong key = lockout_interval_key( slot, interval_end );
    for( lockout_interval_t * itrvl = lockout_interval_map_ele_remove( lck_map, &key, NULL, lck_pool );
                                      itrvl;
                                      itrvl = lockout_interval_map_ele_remove( lck_map, &key, NULL, lck_pool ) ) {
      lockout_interval_pool_ele_release( lck_pool, itrvl );
    }
  }
}
