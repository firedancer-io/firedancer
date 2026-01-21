#include <limits.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#include "fd_tower.h"
#include "../voter/fd_voter.h"
#include "../voter/fd_voter_private.h"
#include "fd_tower_forks.h"
#include "fd_tower_serde.h"
#include "../../flamenco/txn/fd_txn_generate.h"
#include "../../flamenco/runtime/fd_system_ids.h"

#define LOGGING 0

#define THRESHOLD_DEPTH (8)
#define THRESHOLD_RATIO (2.0 / 3.0)
#define SWITCH_RATIO    (0.38)

/* expiration calculates the expiration slot of vote given a slot and
   confirmation count. */

static inline ulong
expiration_slot( fd_tower_t const * vote ) {
  ulong lockout = 1UL << vote->conf;
  return vote->slot + lockout;
}

/* simulate_vote simulates voting for slot, popping all votes from the
   top that would be consecutively expired by voting for slot. */

ulong
simulate_vote( fd_tower_t const * tower,
               ulong              slot ) {
  ulong cnt = fd_tower_cnt( tower );
  while( cnt ) {
    fd_tower_t const * top_vote = fd_tower_peek_index_const( tower, cnt - 1 );
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

ulong
push_vote( fd_tower_t * tower,
           ulong        slot ) {

# if FD_TOWER_PARANOID
  fd_tower_t const * vote = fd_tower_peek_tail_const( tower );
  if( FD_UNLIKELY( vote && slot <= vote->slot ) ) FD_LOG_ERR(( "[%s] slot %lu <= vote->slot %lu", __func__, slot, vote->slot )); /* caller error*/
# endif

  /* Use simulate_vote to determine how many expired votes to pop. */

  ulong cnt = simulate_vote( tower, slot );

  /* Pop everything that got expired. */

  while( FD_LIKELY( fd_tower_cnt( tower ) > cnt ) ) {
    fd_tower_pop_tail( tower );
  }

  /* If the tower is still full after expiring, then pop and return the
     bottom vote slot as the new root because this vote has incremented
     it to max lockout.  Otherwise this is a no-op and there is no new
     root (FD_SLOT_NULL). */

  ulong root = FD_SLOT_NULL;
  if( FD_LIKELY( fd_tower_full( tower ) ) ) { /* optimize for full tower */
    root = fd_tower_pop_head( tower ).slot;
  }

  /* Increment confirmations (double lockouts) for consecutive
     confirmations in prior votes. */

  ulong prev_conf = 0;
  for( fd_tower_iter_t iter = fd_tower_iter_init_rev( tower       );
                             !fd_tower_iter_done_rev( tower, iter );
                       iter = fd_tower_iter_prev    ( tower, iter ) ) {
    fd_tower_t * vote = fd_tower_iter_ele( tower, iter );
    if( FD_UNLIKELY( vote->conf != ++prev_conf ) ) break;
    vote->conf++;
  }

  /* Add the new vote to the tower. */

  fd_tower_push_tail( tower, (fd_tower_t){ .slot = slot, .conf = 1 } );

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

int
lockout_check( fd_tower_t const * tower,
               fd_forks_t       * forks,
               ulong              slot ) {

  if( FD_UNLIKELY( fd_tower_empty( tower )                         ) ) return 1; /* always not locked out if we haven't voted. */
  if( FD_UNLIKELY( slot <= fd_tower_peek_tail_const( tower )->slot ) ) return 0; /* always locked out from voting for slot <= last vote slot */

  /* Simulate a vote to pop off all the votes that would be expired by
     voting for slot.  Then check if the newly top-of-tower vote is on
     the same fork as slot (if so this implies we can vote for it). */

  ulong cnt = simulate_vote( tower, slot ); /* pop off votes that would be expired */
  if( FD_UNLIKELY( !cnt ) ) return 1;       /* tower is empty after popping expired votes */

  fd_tower_t const * vote    = fd_tower_peek_index_const( tower, cnt - 1 );            /* newly top-of-tower */
  int                lockout = fd_forks_is_slot_descendant( forks, vote->slot, slot ); /* check if on same fork */
  FD_LOG_INFO(( "[%s] lockout? %d. last_vote_slot: %lu. slot: %lu", __func__, lockout, vote->slot, slot ));
  return lockout;
}

/* switch_check checks if we can switch to the fork of `slot`.  Returns
   1 if we can switch, 0 otherwise.  Assumes tower is non-empty.

   There are two forks of interest: our last vote fork ("vote fork") and
   the fork we want to switch to ("switch fork").  The switch fork is on
   the fork of `slot`.

   In order to switch, FD_TOWER_SWITCH_PCT of stake must have voted for
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

   return switch stake >= FD_TOWER_SWITCH_PCT
   ```

   The switch check is used to safeguard optimistic confirmation.
   Specifically: FD_TOWER_OPT_CONF_PCT + FD_TOWER_SWITCH_PCT >= 1. */

int
switch_check( fd_tower_t const  * tower,
              fd_forks_t        * forks,
              fd_epoch_stakes_t * epoch_stakes,
              ulong               total_stake,
              ulong               switch_slot ) {
  ulong switch_stake   = 0;
  ulong last_vote_slot = fd_tower_peek_tail_const( tower )->slot;
  ulong root_slot      = fd_tower_peek_head_const( tower )->slot;
  for ( fd_tower_leaves_dlist_iter_t iter = fd_tower_leaves_dlist_iter_fwd_init( forks->tower_leaves_dlist, forks->tower_leaves_pool );
                                           !fd_tower_leaves_dlist_iter_done( iter, forks->tower_leaves_dlist, forks->tower_leaves_pool );
                                     iter = fd_tower_leaves_dlist_iter_fwd_next( iter, forks->tower_leaves_dlist, forks->tower_leaves_pool ) ) {

    /* Iterate over all the leaves of all forks */
    fd_tower_leaf_t  * leaf = fd_tower_leaves_dlist_iter_ele( iter, forks->tower_leaves_dlist, forks->tower_leaves_pool );
    ulong candidate_slot = leaf->slot;
    ulong lca = fd_forks_lowest_common_ancestor( forks, candidate_slot, last_vote_slot );

    if( lca != ULONG_MAX && fd_forks_is_slot_descendant( forks, lca, switch_slot ) ) {

      /* This candidate slot may be considered for the switch proof, if
         it passes the following conditions:

         https://github.com/anza-xyz/agave/blob/c7b97bc77addacf03b229c51b47c18650d909576/core/src/consensus.rs#L1117

         Now for this candidate slot, look at the lockouts that were created at
         the time that we processed the bank for this candidate slot. */

      for( fd_lockout_slots_t const * slot = fd_lockout_slots_map_ele_query_const( forks->lockout_slots_map, &candidate_slot, NULL, forks->lockout_slots_pool );
                                      slot;
                                      slot = fd_lockout_slots_map_ele_next_const ( slot, NULL, forks->lockout_slots_pool ) ) {
        ulong interval_end = slot->interval_end;
        ulong key = fd_lockout_interval_key( candidate_slot, interval_end );

        /* Intervals are keyed by the end of the interval. If the end of
           the interval is < the last vote slot, then these vote
           accounts with this particular lockout are NOT locked out from
           voting for the last vote slot, which means we can skip this
           set of intervals. */

        if( interval_end < last_vote_slot ) continue;

        /* At this point we can actually query for the intervals by
           end interval to get the vote accounts. */

        for( fd_lockout_intervals_t const * interval = fd_lockout_intervals_map_ele_query_const( forks->lockout_intervals_map, &key, NULL, forks->lockout_intervals_pool );
                                            interval;
                                            interval = fd_lockout_intervals_map_ele_next_const( interval, NULL, forks->lockout_intervals_pool ) ) {
          ulong vote_slot            =  interval->interval_start;
          fd_hash_t const * vote_acc = &interval->vote_account_pubkey;

          if( FD_UNLIKELY( !fd_forks_is_slot_descendant( forks, vote_slot, last_vote_slot ) &&
                            vote_slot > root_slot ) ) {
            fd_voter_stake_key_t key = { .vote_account = *vote_acc, .slot = switch_slot };
            fd_voter_stake_t const * voter_stake = fd_voter_stake_map_ele_query_const( epoch_stakes->voter_stake_map, &key, NULL, epoch_stakes->voter_stake_pool );
            if( FD_UNLIKELY( !voter_stake ) ) {
              FD_BASE58_ENCODE_32_BYTES( vote_acc->key, vote_acc_b58 );
              FD_LOG_CRIT(( "missing voter stake for vote account %s on slot %lu. Is this an error?", vote_acc_b58, switch_slot ));
            }
            ulong voter_idx = fd_voter_stake_pool_idx( epoch_stakes->voter_stake_pool, voter_stake );

            /* Don't count this vote account towards the switch cqheck if it has already been used. */
            if( FD_UNLIKELY( fd_used_acc_scratch_test( epoch_stakes->used_acc_scratch, voter_idx ) ) ) continue;

            fd_used_acc_scratch_insert( epoch_stakes->used_acc_scratch, voter_idx );
            switch_stake += voter_stake->stake;
            if( FD_LIKELY( (double)switch_stake >= (double)total_stake * SWITCH_RATIO ) ) {
              fd_used_acc_scratch_null( epoch_stakes->used_acc_scratch );
              FD_LOG_INFO(( "[%s] switch? 1. last_vote_slot: %lu. switch_slot: %lu. pct: %.0lf%%", __func__, last_vote_slot, switch_slot, (double)switch_stake / (double)total_stake * 100.0 ));
              return 1;
            }
          }
        }
      }
    }
  }
  fd_used_acc_scratch_null( epoch_stakes->used_acc_scratch );
  FD_LOG_INFO(( "[%s] switch? 0. last_vote_slot: %lu. switch_slot: %lu. pct: %.0lf%%", __func__, last_vote_slot, switch_slot, (double)switch_stake / (double)total_stake * 100.0 ));
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

int
threshold_check( fd_tower_t       const * tower,
                 fd_tower_accts_t const * accts,
                 ulong                    total_stake,
                 ulong                    slot ) {

  uchar __attribute__((aligned(FD_TOWER_ALIGN))) scratch[ FD_TOWER_FOOTPRINT ];
  fd_tower_t * scratch_tower = fd_tower_join( fd_tower_new( scratch ) );

  /* First, simulate a vote on our tower, popping off everything that
     would be expired by voting for slot. */

  ulong cnt = simulate_vote( tower, slot );

  /* We can always vote if our tower is not at least THRESHOLD_DEPTH
     deep after simulating. */

  if( FD_UNLIKELY( cnt < THRESHOLD_DEPTH ) ) return 1;

  /* Get the vote slot from THRESHOLD_DEPTH back. Note THRESHOLD_DEPTH
     is the 8th index back _including_ the simulated vote at index 0. */

  ulong threshold_slot  = fd_tower_peek_index_const( tower, cnt - THRESHOLD_DEPTH )->slot;
  ulong threshold_stake = 0;
  for( fd_tower_accts_iter_t iter = fd_tower_accts_iter_init( accts       );
                                   !fd_tower_accts_iter_done( accts, iter );
                             iter = fd_tower_accts_iter_next( accts, iter ) ) {
    fd_tower_accts_t const * acct = fd_tower_accts_iter_ele_const( accts, iter );
    fd_tower_remove_all( scratch_tower );
    fd_tower_from_vote_acc( scratch_tower, acct->data );

    ulong cnt = simulate_vote( scratch_tower, slot ); /* expire votes */
    if( FD_UNLIKELY( !cnt ) ) continue;               /* no votes left after expiry */

    /* Count their stake towards the threshold check if their last vote
       slot >= our threshold slot.

       We know these votes are for our own fork because towers are
       sourced from vote _accounts_, not vote _transactions_.

       Because we are iterating vote accounts on the same fork that we
       we want to vote for, we know these slots must all occur along the
       same fork ancestry.

       Therefore, if their latest vote slot >= our threshold slot, we
       know that vote must be for the threshold slot itself or one of
       threshold slot's descendants. */

    ulong last_vote = fd_tower_peek_index_const( scratch_tower, cnt - 1 )->slot;
    if( FD_LIKELY( last_vote >= threshold_slot ) ) threshold_stake += acct->stake;
  }

  double threshold_pct = (double)threshold_stake / (double)total_stake;
  int    threshold     = threshold_pct > THRESHOLD_RATIO;
  FD_LOG_INFO(( "[%s] threshold? %d. top: %lu. threshold: %lu. pct: %.0lf%%.", __func__, threshold, fd_tower_peek_tail_const( tower )->slot, threshold_slot, threshold_pct * 100.0 ));
  return threshold;
}

int
propagated_check( fd_notar_t * notar,
                  ulong        slot ) {

  fd_notar_slot_t * notar_slot = fd_notar_slot_query( notar->slot_map, slot, NULL );
  if( FD_UNLIKELY( !notar_slot ) ) return 1;

  if( FD_LIKELY( notar_slot->is_leader                   ) ) return 1; /* can always vote for slot in which we're leader */
  if( FD_LIKELY( notar_slot->prev_leader_slot==ULONG_MAX ) ) return 1; /* haven't been leader yet */

  fd_notar_slot_t * prev_leader_notar_slot = fd_notar_slot_query( notar->slot_map, notar_slot->prev_leader_slot, NULL );
  if( FD_LIKELY( !prev_leader_notar_slot ) ) return 1; /* already pruned rooted */

  return prev_leader_notar_slot->is_propagated;
}

fd_tower_out_t
fd_tower_vote_and_reset( fd_tower_t        * tower,
                         fd_tower_accts_t  * accts,
                         fd_epoch_stakes_t * epoch_stakes,
                         fd_forks_t        * forks,
                         fd_ghost_t        * ghost,
                         fd_notar_t        * notar ) {

  uchar                  flags     = 0;
  fd_ghost_blk_t const * best_blk  = fd_ghost_best( ghost, fd_ghost_root( ghost ) );
  fd_ghost_blk_t const * reset_blk = NULL;
  fd_ghost_blk_t const * vote_blk  = NULL;

  /* Case 0: if we haven't voted yet then we can always vote and reset
     to ghost_best.

     https://github.com/anza-xyz/agave/blob/v2.3.7/core/src/consensus.rs#L933-L935 */

  if( FD_UNLIKELY( fd_tower_empty( tower ) ) ) {
    fd_tower_forks_t * fork = fd_forks_query( forks, best_blk->slot );
    fork->voted             = 1;
    fork->voted_block_id    = best_blk->id;
    return (fd_tower_out_t){
      .flags          = flags,
      .reset_slot     = best_blk->slot,
      .reset_block_id = best_blk->id,
      .vote_slot      = best_blk->slot,
      .vote_block_id  = best_blk->id,
      .root_slot      = push_vote( tower, best_blk->slot )
    };
  }

  ulong              prev_vote_slot     = fd_tower_peek_tail_const( tower )->slot;
  fd_tower_forks_t * prev_vote_fork     = fd_forks_query( forks, prev_vote_slot );
  fd_hash_t        * prev_vote_block_id = &prev_vote_fork->voted_block_id;
  fd_ghost_blk_t   * prev_vote_blk      = fd_ghost_query( ghost, prev_vote_block_id );

  /* Case 1: if an ancestor of our prev vote (including prev vote
     itself) is an unconfirmed duplicate, then our prev vote was on a
     duplicate fork.

     There are two subcases to check. */

  int invalid_ancestor = !!fd_ghost_invalid_ancestor( ghost, prev_vote_blk );
  if( FD_UNLIKELY( invalid_ancestor ) ) { /* do we have an invalid ancestor? */

    /* Case 1a: ghost_best is an ancestor of prev vote.  This means
       ghost_best is rolling back to an ancestor that precedes the
       duplicate ancestor on the same fork as our prev vote.  In this
       case, we can't vote on our ancestor, but we do reset to that
       ancestor.

       https://github.com/anza-xyz/agave/blob/v2.3.7/core/src/consensus.rs#L1016-L1019 */

    int ancestor_rollback = prev_vote_blk != best_blk && !!fd_ghost_ancestor( ghost, prev_vote_blk, &best_blk->id );
    if( FD_LIKELY( ancestor_rollback ) ) {
      flags     = fd_uchar_set_bit( flags, FD_TOWER_FLAG_ANCESTOR_ROLLBACK );
      reset_blk = best_blk;
    }

    /* Case 1b: ghost_best is not an ancestor, but prev_vote is a
       duplicate and we've confirmed its duplicate sibling.  In this
       case, we allow switching to ghost_best without a switch proof.

       Example: slot 5 is a duplicate.  We first receive, replay and
       vote for block 5, so that is our prev vote.  We later receive
       block 5' and observe that it is duplicate confirmed.  ghost_best
       now returns block 5' and we both vote and reset to block 5'
       regardless of the switch check.

       https://github.com/anza-xyz/agave/blob/v2.3.7/core/src/consensus.rs#L1021-L1024 */

    int sibling_confirmed = 0!=memcmp( &prev_vote_fork->voted_block_id, &prev_vote_fork->confirmed_block_id, sizeof(fd_hash_t) );
    if( FD_LIKELY( sibling_confirmed ) ) {
      flags     = fd_uchar_set_bit( flags, FD_TOWER_FLAG_SIBLING_CONFIRMED );
      reset_blk = best_blk;
      vote_blk  = best_blk;
    }

    /* At this point our prev vote was on a duplicate fork but didn't
       match either of the above subcases.

       In this case, we have to pass the switch check to reset to a
       different fork from prev vote (same as non-duplicate case). */
  }

  /* Case 2: if our prev vote slot is an ancestor of the best slot, then
     they are on the same fork and we can both reset to it.  We can also
     vote for it if we pass the can_vote checks.

     https://github.com/anza-xyz/agave/blob/v2.3.7/core/src/consensus.rs#L1057 */

  else if( FD_LIKELY( best_blk->slot == prev_vote_slot || fd_forks_is_slot_ancestor( forks, best_blk->slot, prev_vote_slot ) ) ) {
    flags     = fd_uchar_set_bit( flags, FD_TOWER_FLAG_SAME_FORK );
    reset_blk = best_blk;
    vote_blk  = best_blk;
  }

  /* Case 3: if our prev vote is not an ancestor of the best block, then
     it is on a different fork.  If we pass the switch check, we can
     reset to it.  If we additionally pass the lockout check, we can
     also vote for it.

     https://github.com/anza-xyz/agave/blob/v2.3.7/core/src/consensus.rs#L1208-L1215

     Note also Agave uses the best blk's total stake for checking the
     threshold.

     https://github.com/anza-xyz/agave/blob/v2.3.7/core/src/consensus/fork_choice.rs#L443-L445 */

  else if( FD_LIKELY( switch_check( tower, forks, epoch_stakes, best_blk->total_stake, best_blk->slot ) ) ) {
    flags     = fd_uchar_set_bit( flags, FD_TOWER_FLAG_SWITCH_PASS );
    reset_blk = best_blk;
    vote_blk  = best_blk;
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

    /* Case 4a: failed switch check and last vote's fork is invalid.

      https://github.com/anza-xyz/agave/blob/v2.3.7/core/src/consensus/heaviest_subtree_fork_choice.rs#L1187 */

    if( FD_UNLIKELY( invalid_ancestor ) ) {
      flags     = fd_uchar_set_bit( flags, FD_TOWER_FLAG_SWITCH_FAIL );
      reset_blk = fd_ghost_deepest( ghost, prev_vote_blk );
    }

    /* Case 4b: failed switch check and last vote's fork is valid.

      https://github.com/anza-xyz/agave/blob/v2.3.7/core/src/consensus/fork_choice.rs#L200 */

    else {
      flags     = fd_uchar_set_bit( flags, FD_TOWER_FLAG_SWITCH_FAIL );
      reset_blk = fd_ghost_best( ghost, prev_vote_blk );
    }
  }

  /* If there is a block to vote for, there are a few additional checks
     to make sure we can actually vote for it.

     Specifically, we need to make sure we're not locked out, pass the
     threshold check and that our previous leader block has propagated
     (reached the prop threshold according to fd_notar).

     https://github.com/firedancer-io/agave/blob/master/core/src/consensus/fork_choice.rs#L382-L385

     Agave uses the total stake on the fork being threshold checked
     (vote_blk) for determining whether it meets the stake threshold. */

  if( FD_LIKELY( vote_blk ) ) {
    if     ( FD_UNLIKELY( !lockout_check( tower, forks, vote_blk->slot ) ) ) {
      flags    = fd_uchar_set_bit( flags, FD_TOWER_FLAG_LOCKOUT_FAIL );
      vote_blk = NULL;
    }
    else if( FD_UNLIKELY( !threshold_check( tower, accts, vote_blk->total_stake, vote_blk->slot ) ) ) {
      flags    = fd_uchar_set_bit( flags, FD_TOWER_FLAG_THRESHOLD_FAIL );
      vote_blk = NULL;
    }
    else if( FD_UNLIKELY( !propagated_check( notar, vote_blk->slot ) ) ) {
      flags    = fd_uchar_set_bit( flags, FD_TOWER_FLAG_PROPAGATED_FAIL );
      vote_blk = NULL;
    }
  }

  FD_TEST( reset_blk ); /* always a reset_blk */
  fd_tower_out_t out = {
    .flags          = flags,
    .reset_slot     = reset_blk->slot,
    .reset_block_id = reset_blk->id,
    .vote_slot      = ULONG_MAX,
    .root_slot      = ULONG_MAX
  };

  /* Finally, if our vote passed all the checks, we actually push the
     vote onto the tower. */

  if( FD_LIKELY( vote_blk ) ) {
    out.vote_slot     = vote_blk->slot;
    out.vote_block_id = vote_blk->id;
    out.root_slot     = push_vote( tower, vote_blk->slot );

    /* Query our tower fork for this slot we're voting for.  Note this
       can never be NULL because we record tower forks as we replay, and
       we should never be voting on something we haven't replayed. */

    fd_tower_forks_t * fork = fd_forks_query( forks, vote_blk->slot );
    fork->voted             = 1;
    fork->voted_block_id    = vote_blk->id;

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

    if( FD_LIKELY( out.root_slot!=ULONG_MAX ) ) {
      fd_tower_forks_t * root_fork = fd_forks_query( forks, out.root_slot );
      out.root_block_id            = *fd_ptr_if( root_fork->confirmed, &root_fork->confirmed_block_id, &root_fork->voted_block_id );
    }
  }

  FD_BASE58_ENCODE_32_BYTES( out.reset_block_id.uc, reset_block_id );
  FD_BASE58_ENCODE_32_BYTES( out.vote_block_id.uc,  vote_block_id  );
  FD_BASE58_ENCODE_32_BYTES( out.root_block_id.uc,  root_block_id  );
  FD_LOG_INFO(( "[%s] flags: %d. reset_slot: %lu (%s). vote_slot: %lu (%s). root_slot: %lu (%s).", __func__, out.flags, out.reset_slot, reset_block_id, out.vote_slot, vote_block_id, out.root_slot, root_block_id ));
  return out;
}

void
fd_tower_reconcile( fd_tower_t  * tower,
                    ulong         root,
                    uchar const * vote_account_data ) {
  ulong on_chain_vote = fd_voter_vote_slot( vote_account_data );
  ulong on_chain_root = fd_voter_root_slot( vote_account_data );

  fd_tower_vote_t const * last_vote      = fd_tower_peek_tail_const( tower );
  ulong                   last_vote_slot = last_vote ? last_vote->slot : ULONG_MAX;

  if( FD_UNLIKELY( ( on_chain_vote==ULONG_MAX && last_vote_slot==ULONG_MAX ) ) ) return;
  if( FD_LIKELY  ( ( on_chain_vote!=ULONG_MAX && last_vote_slot!=ULONG_MAX
                     && on_chain_vote <= last_vote_slot                    ) ) ) return;

  /* At this point our local tower is too old, and we need to replace it
     with our on-chain tower.  However, it's possible our local root is
     newer than the on-chain root (even though the tower is older).  The
     most likely reason this happens is because we just booted from a
     snapshot and the snapshot slot > on-chain root.

     So we need to filter out the stale votes < snapshot slot.  This
     mirrors the Agave logic:
     https://github.com/firedancer-io/agave/blob/master/core/src/replay_stage.rs#L3690-L3719 */

  if( FD_LIKELY( on_chain_root == ULONG_MAX || root > on_chain_root ) ) {
    fd_tower_remove_all( tower );
    fd_voter_t const * voter = (fd_voter_t const *)fd_type_pun_const( vote_account_data );
    uint               kind  = fd_uint_load_4_fast( vote_account_data ); /* skip node_pubkey */
    for( ulong i=0; i<fd_voter_votes_cnt( vote_account_data ); i++ ) {
      switch( kind ) {
      case FD_VOTER_V4: fd_tower_push_tail( tower, (fd_tower_vote_t){ .slot = v4_off( voter )[i].slot, .conf = v4_off( voter )[i].conf } ); break;
      case FD_VOTER_V3: fd_tower_push_tail( tower, (fd_tower_vote_t){ .slot = voter->v3.votes[i].slot, .conf = voter->v3.votes[i].conf } ); break;
      case FD_VOTER_V2: fd_tower_push_tail( tower, (fd_tower_vote_t){ .slot = voter->v2.votes[i].slot, .conf = voter->v2.votes[i].conf } ); break;
      default:          FD_LOG_ERR(( "unsupported voter account version: %u", kind ));
      }
    }

    /* Fast forward our tower to tower_root by retaining only votes >
       local tower root. */

    while( FD_LIKELY( !fd_tower_empty( tower ) ) ) {
      fd_tower_t const * vote = fd_tower_peek_head_const( tower );
      if( FD_LIKELY( vote->slot > root ) ) break;
      fd_tower_pop_head( tower );
    }
  }
}

void
fd_tower_from_vote_acc( fd_tower_t   * tower,
                        uchar  const * vote_acc ) {
  fd_voter_t const * voter = (fd_voter_t const *)fd_type_pun_const( vote_acc );
  uint               kind  = fd_uint_load_4_fast( vote_acc ); /* skip node_pubkey */
  for( ulong i=0; i<fd_voter_votes_cnt( vote_acc ); i++ ) {
    switch( kind ) {
    case FD_VOTER_V4: fd_tower_push_tail( tower, (fd_tower_vote_t){ .slot = v4_off( voter )[i].slot, .conf = v4_off( voter )[i].conf } ); break;
    case FD_VOTER_V3: fd_tower_push_tail( tower, (fd_tower_vote_t){ .slot = voter->v3.votes[i].slot, .conf = voter->v3.votes[i].conf } ); break;
    case FD_VOTER_V2: fd_tower_push_tail( tower, (fd_tower_vote_t){ .slot = voter->v2.votes[i].slot, .conf = voter->v2.votes[i].conf } ); break;
    default:          FD_LOG_ERR(( "unsupported voter account version: %u", kind ));
    }
  }
}

ulong
fd_tower_with_lat_from_vote_acc( fd_voter_vote_t tower[ static FD_TOWER_VOTE_MAX ],
                                 uchar const *      vote_acc ) {
  fd_voter_t const * voter = (fd_voter_t const *)fd_type_pun_const( vote_acc );
  uint               kind  = fd_uint_load_4_fast( vote_acc ); /* skip node_pubkey */
  for( ulong i=0; i<fd_voter_votes_cnt( vote_acc ); i++ ) {
    switch( kind ) {
    case FD_VOTER_V4: tower[ i ] = (fd_voter_vote_t){ .latency = v4_off( voter )[i].latency, .slot = v4_off( voter )[i].slot, .conf = v4_off( voter )[i].conf }; break;
    case FD_VOTER_V3: tower[ i ] = (fd_voter_vote_t){ .latency = voter->v3.votes[i].latency, .slot = voter->v3.votes[i].slot, .conf = voter->v3.votes[i].conf }; break;
    case FD_VOTER_V2: tower[ i ] = (fd_voter_vote_t){ .latency = UCHAR_MAX,                  .slot = voter->v2.votes[i].slot, .conf = voter->v2.votes[i].conf }; break;
    default:          FD_LOG_ERR(( "unsupported voter account version: %u", kind ));
    }
  }

  return fd_voter_votes_cnt( vote_acc );
}

void
fd_tower_to_vote_txn( fd_tower_t const *    tower,
                      ulong                 root,
                      fd_hash_t const *     bank_hash,
                      fd_hash_t const *     block_id,
                      fd_hash_t const *     recent_blockhash,
                      fd_pubkey_t const *   validator_identity,
                      fd_pubkey_t const *   vote_authority,
                      fd_pubkey_t const *   vote_acc,
                      fd_txn_p_t *          vote_txn ) {

  FD_TEST( fd_tower_cnt( tower )<=FD_TOWER_VOTE_MAX );
  fd_compact_tower_sync_serde_t tower_sync_serde = {
    .root             = fd_ulong_if( root == ULONG_MAX, 0UL, root ),
    .lockouts_cnt     = (ushort)fd_tower_cnt( tower ),
    /* .lockouts populated below */
    .hash             = *bank_hash,
    .timestamp_option = 1,
    .timestamp        = fd_log_wallclock() / (long)1e9, /* seconds */
    .block_id         = *block_id
  };

  ulong i = 0UL;
  ulong prev = tower_sync_serde.root;
  for( fd_tower_iter_t iter = fd_tower_iter_init( tower       );
                             !fd_tower_iter_done( tower, iter );
                       iter = fd_tower_iter_next( tower, iter ) ) {
    fd_tower_t const * vote                         = fd_tower_iter_ele_const( tower, iter );
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
  FD_TEST( 0==fd_compact_tower_sync_serialize( &tower_sync_serde, vote_ix_buf + sizeof(uint), FD_TXN_MTU - sizeof(uint), &vote_ix_sz ) ); // cannot fail if fd_tower_cnt( tower ) <= FD_TOWER_VOTE_MAX
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
  if( FD_UNLIKELY( fd_tower_cnt( tower )>=FD_TOWER_VOTE_MAX ) ) {
    FD_LOG_WARNING(( "[%s] invariant violation: cnt %lu >= FD_TOWER_VOTE_MAX %lu", __func__, fd_tower_cnt( tower ), (ulong)FD_TOWER_VOTE_MAX ));
    return -1;
  }

  fd_tower_t const * prev = NULL;
  for( fd_tower_iter_t iter = fd_tower_iter_init( tower       );
                                   !fd_tower_iter_done( tower, iter );
                             iter = fd_tower_iter_next( tower, iter ) ) {
    fd_tower_t const * vote = fd_tower_iter_ele_const( tower, iter );
    if( FD_UNLIKELY( prev && ( vote->slot < prev->slot || vote->conf < prev->conf ) ) ) {
      FD_LOG_WARNING(( "[%s] invariant violation: vote (slot:%lu conf:%lu) prev (slot:%lu conf:%lu)", __func__, vote->slot, vote->conf, prev->slot, prev->conf ));
      return -1;
    }
    prev = vote;
  }
  return 0;
}

#include <stdio.h>

#define PRINT( fmt, ... ) do { if( FD_LIKELY( ostream_opt ) ) { snprintf( buf, sizeof(buf), fmt, ##__VA_ARGS__ ); fd_io_buffered_ostream_write( ostream_opt, buf, strlen(buf) ); } else { printf( fmt, ##__VA_ARGS__ ); } } while(0)
#define PRINT_STR( str )  do { if( FD_LIKELY( ostream_opt ) ) { fd_io_buffered_ostream_write( ostream_opt, str, strlen(str) ); } else { printf( str ); } } while(0)
void
fd_tower_print( fd_tower_t const * tower, ulong root, fd_io_buffered_ostream_t * ostream_opt ) {
  if( FD_LIKELY( ostream_opt ) ) PRINT_STR( "\n\n[Tower]\n" );
  else                           FD_LOG_NOTICE( ( "\n\n[Tower]" ) );

  if( FD_UNLIKELY( fd_tower_empty( tower ) ) ) return;

  ulong max_slot = 0;

  /* Determine spacing. */

  for( fd_tower_iter_t iter = fd_tower_iter_init_rev( tower       );
                             !fd_tower_iter_done_rev( tower, iter );
                       iter = fd_tower_iter_prev    ( tower, iter ) ) {

    max_slot = fd_ulong_max( max_slot, fd_tower_iter_ele_const( tower, iter )->slot );
  }

  /* Calculate the number of digits in the maximum slot value. */

  int           digit_cnt = (int)fd_ulong_base10_dig_cnt(max_slot);

  /* Print the column headers. */

  char buf[1024];
  PRINT( "slot%*s | %s\n", digit_cnt - (int)strlen("slot"), "", "confirmation count" );

  /* Print the divider line. */

  for( int i = 0; i < digit_cnt; i++ ) {
    PRINT_STR( "-" );
  }
  PRINT_STR( " | " );
  for( ulong i = 0; i < strlen( "confirmation count" ); i++ ) {
    PRINT_STR( "-" );
  }
  PRINT_STR( "\n" );

  /* Print each vote as a table. */

  for( fd_tower_iter_t iter = fd_tower_iter_init_rev( tower       );
                             !fd_tower_iter_done_rev( tower, iter );
                       iter = fd_tower_iter_prev    ( tower, iter ) ) {

    fd_tower_t const * vote = fd_tower_iter_ele_const( tower, iter );
    PRINT( "%*lu | %lu\n", digit_cnt, vote->slot, vote->conf );
    max_slot = fd_ulong_max( max_slot, fd_tower_iter_ele_const( tower, iter )->slot );
  }
  if( FD_UNLIKELY( root==ULONG_MAX ) ) {
    PRINT( "%*s | root\n", digit_cnt, "NULL" );
  } else {
    PRINT( "%*lu | root\n", digit_cnt, root );
  }
  PRINT_STR( "\n" );
}
#undef PRINT
#undef PRINT_STR
