#ifndef HEADER_fd_src_choreo_tower_fd_tower_h
#define HEADER_fd_src_choreo_tower_fd_tower_h

/* fd_tower presents an API for Solana's TowerBFT algorithm.

   What is TowerBFT? TowerBFT is an algorithm for converging a
   supermajority of stake in the validator cluster on the same fork.

        /-- 3-- 4 (A)
   1-- 2
        \-- 5     (B)

   Above is a diagram of a fork. The leader for slot 5 decided to build
   off slot 2, rather than slot 4. This can happen for various reasons,
   for example network propagation delay. We now have two possible forks
   labeled A and B. The consensus algorithm has to pick one of them.

   So, how does the consensus algorithm pick? As detailed in fd_ghost.h,
   we pick the fork based on the most stake from votes, called the
   "heaviest". Validators vote for blocks during replay, and
   simultaneously use other validator’s votes to determine which block
   to vote for. This encourages convergence, because as one fork gathers
   more votes, more and more votes pile-on, solidifying its position as
   the heaviest fork.

         /-- 3-- 4 (10%)
   1-- 2
         \-- 5     (9%)

   However, network propagation delay of votes can lead us to think one
   fork is heaviest, before observing new votes that indicate another
   fork is heavier. So our consensus algorithm also needs to support
   switching.

         /-- 3-- 4 (10%)
   1-- 2
         \-- 5     (15%)

   At the same time we don’t want excessive switching. The more often
   validators switch, the more difficult it will be to achieve that
   pile-on effect I just described.

   Note that to switch forks, you need to rollback a given slot and its
   descendants on that fork. In the example above, to switch to 1, 2, 5,
   we need to rollback 3 and 4. The consensus algorithm makes it more
   costly the further you want to rollback a fork. Here, I’ve added a
   column lockout, which doubles for every additional slot you want to
   rollback.

   Eventually you have traversed far enough down a fork, that the
   lockout is so great it is infeasible to imagine it ever rolling back
   in practice. So you can make that fork permanent or “commit” it. Once
   all validators do this, the blockchain now just has a single fork.

   Armed with some intuition, let’s now begin defining some terminology.
   Here is a diagram of a validator's "vote tower":

   slot | confirmation count (conf)
   --------------------------------
   4    | 1
   3    | 2
   2    | 3
   1    | 4

   It is a stack structure in which each element is a vote. The vote
   slot column indicates which slots the validator has voted for,
   ordered from most to least recent.

   The confirmation count column indicates how many consecutive votes on
   the same fork have been pushed on top of that vote. You are
   confirming your own votes for a fork every time you vote on top of
   the same fork.

   Two related concepts to confirmation count are lockout and expiration
   slot. Lockout equals 2 to the power of confirmation count. Every time
   we “confirm” a vote by voting on top of it, we double the lockout.
   The expiration slot is the sum of vote slot and lockout, so it also
   increases when lockouts double. It represents which slot the vote
   will expire. When a vote expires, it is popped from the top of the
   tower. An important Tower rule is that a validator cannot vote for a
   different fork from a given vote slot, until reaching the expiration
   slot for that vote slot. To summarize, the further a validator wants
   to rollback their fork (or vote slots) the longer the validator needs
   to wait without voting (in slot time).

   Here is the same tower, fully-expanded to include all the fields:

   slot | conf | lockout | expiration
   ----------------------------------
   4    | 1    | 2       | 6
   3    | 2    | 4       | 7
   2    | 3    | 8       | 10
   1    | 4    | 16      | 17

   Based on this tower, the validator is locked out from voting for any
   slot <= 6 that is on a different fork than slot 4. I’d like to
   emphasize that the expiration is with respect to the vote slot, and
   is _not_ related to the Proof-of-History slot or what the
   quote-unquote current slot is. So even if the current slot is now 7,
   the validator can’t go back and vote for slot 5, if slot 5 were on a
   different fork than 4. The earliest valid vote slot this validator
   could submit for a different fork from 4 would be slot 7 or later.

   Next let’s look at how the tower makes state transitions. Here we
   have the previous example tower, with a before-and-after view with
   respect to a vote for slot 9:

   (before)  slot | conf
            -----------
             4    | 1
             3    | 2
             2    | 3
             1    | 4

   (after)  slot | conf
            -----------
            9    | 1
            2    | 3
            1    | 4

   As you can see, we added a vote for slot 9 to the top of the tower.
   But we also removed the votes for slot 4 and slot 3. What happened?
   This is an example of vote expiry in action. When we voted for slot
   9, this exceeded the expirations of vote slots 4 and 3, which were 6
   and 7 respectively. This action of voting triggered the popping of
   the expired votes from the top of the tower.

   Next, we add a vote for slot 10:

   (before)  slot | conf
            -----------
             9    | 1
             2    | 3
             1    | 4

   (after)  slot | conf
            -----------
             10   | 1
             9    | 2
             2    | 3
             1    | 4

   The next vote for slot 10 doesn’t involve expirations, so we just add
   it to the top of the tower. Also, here is an important property of
   lockouts. Note that the lockout for vote slot 9 doubled (ie. the
   confirmation count increased by 1) but the lockouts of vote slots 2
   and 1 remained unchanged.

   The reason for this is confirmation counts only increase when they
   are consecutive in the vote tower. Because 4 and 3 were expired
   previously by the vote for 9, that consecutive property was broken.
   In this case, the vote for slot 10 is only consecutive with slot 9,
   but not 2 and 1. Specifically, there is a gap in the before-tower at
   confirmation count 2.

   In the after-tower, all the votes are again consecutive (confirmation
   counts 1, 2, 3, 4 are all accounted for), so the next vote will
   result in all lockouts doubling as long as it doesn’t result in more
   expirations.

   One other thing I’d like to point out about this vote for slot 10.
   Even though 10 >= the expiration slot of vote slot 2, which is
   10, voting for 11 did not expire the vote for 2. This is because
   expiration happens top-down and contiguously. Because vote slot 9 was
   not expired, we do not proceed with expiring 2.

   In the Tower rules, once a vote reaches a conf count of 32, it is
   considered rooted and it is popped from the bottom of the tower. Here
   is an example where 1 got rooted and therefore popped from the bottom:

   (before)  slot | conf
            -----------
             50   | 1
             ...  | ... (29 votes elided)
             1    | 31

   (after)  slot | conf
            -----------
             53   | 1
             ...  | ... (29 votes elided)
             2    | 31

   So the tower is really a double-ended queue rather than a stack.

   Rooting has implications beyond the Tower. It's what we use to prune
   our state. Every time tower makes a new root slot, we prune any old
   state that does not originate from that new root slot. Our blockstore
   will discard blocks below that root, our forks structure will discard
   stale banks, funk (which is our accounts database) will discard stale
   transactions (which in turn track modifications to accounts), and
   ghost (which is our fork select tree) will discard stale nodes
   tracking stake percentages. We call this operation publishing.

   Note that the vote slots are not necessarily consecutive. Here I
   elided the votes sandwiched between the newest and oldest votes for
   brevity.

   Next, let’s go over three additional tower checks. These three checks
   further reinforce the consensus algorithm we established with
   intuition, in this case getting a supermajority (ie. 2/3) of stake to
   converge on a fork.

   The first is the threshold check. The threshold check makes sure at
   least 2/3 of stake has voted for the same fork as the vote at depth 8
   in our tower. Essentially, this guards our tower from getting too out
   of sync with the rest of the cluster. If we get too out of sync we
   can’t vote for a long time, because we had to rollback a vote we had
   already confirmed many times and had a large lockout. This might
   otherwise happen as the result of a network partition where we can
   only communicate with a subset of stake.

   Next is the lockout check. We went in detail on this earlier when
   going through the lockout and expiration slot, and as before, the
   rule is we can only vote on a slot for a different fork from a
   previous vote, after that vote’s expiration slot.

   Given this fork and tower from earlier:

        /-- 3-- 4
   1-- 2
        \-- 5

   slot | conf
   -----------
   4    | 1
   3    | 2
   2    | 3
   1    | 4

  You’re locked out from voting for 5 because it’s on a different fork
  from 4 and the expiration slot of your previous vote for 4 is 6.

  However, if we introduce a new slot 9:

        /-- 3-- 4
  1-- 2
        \-- 5-- 9

  slot | conf
  -----------
  9    | 1
  2    | 3
  1    | 4

  Here the new Slot 9 descends from 5, and exceeds vote slot 4’s
  expiration slot of 6 unlike 5.

  After your lockout expires, the tower rules allow you to vote for
  descendants of the fork slot you wanted to switch to in the first
  place (here, 9 descending from 5). So we eventually switch to the fork
  we wanted, by voting for 9 and expiring 3 and 4.

  Importantly, notice that the fork slots and vote slots are not exactly
  1-to-1. While conceptually our tower is voting for the fork 1, 2, 5,
  9, the vote for 5 is only implied. Our tower votes themselves still
  can’t include 5 due to lockout.

  Finally, the switch check. The switch check is used to safeguard
  optimistic confirmation. Optimistic confirmation is when a slot gets
  2/3 of stake-weighted votes. This is then treated as a signal that the
  slot will eventually get rooted. However, to actually guarantee this
  we need a rule that prevents validators from arbitrarily switching
  forks (even when their vote lockout has expired). This rule is the
  switch check.

  The switch check is additional to the lockout check. Before switching
  forks, we need to make sure at least 38% of stake has voted for a
  different fork than our own. Different fork is defined by finding the
  greatest common ancestor of our last voted fork slot and the slot we
  want to switch to. Any forks descending from the greatest common
  ancestor (which I will subsequently call the GCA) that are not our
  own fork are counted towards the switch check stake.

  Here we visualize the switch check:

             /-- 7
        /-- 3-- 4
  1-- 2  -- 6
        \-- 5-- 9

  First, we find the GCA of 4 and 9 which is 2. Then we look at all the
  descendants of the GCA that do not share a fork with us, and make sure
  their stake sums to more than 38%.

  I’d like to highlight that 7 here is not counted towards the switch
  proof, even though it is on a different fork from 4. This is because
  it’s on the same fork relative to the GCA.

  So that covers the checks. Next, there are two additional important
  concepts: "reset slot" and "vote slot". The reset slot is the slot you
  reset PoH to when it's your turn to be leader. Because you are
  responsible for producing a block, you need to decide which fork to
  build your block on. For example, if there are two competing slots 3
  and 4, you would decide whether to build 3 <- 5 or 4 <- 5. In general
  the reset slot is the same fork as the vote slot, but not always.
  There is an important reason for this. Recall this fork graph from
  earlier:

        /-- 3-- 4 (10%)
   1-- 2
        \-- 5-- 6 (9%)

  In this diagram, 4 is the winner of fork choice. All future leaders
  now want to reset to slot 4. Naively, this makes sense because you
  maximize the chance of your block finalizing (and earning the rewards)
  if you greedily (in the algorithmic, and perhaps also literal sense)
  pick what's currently the heaviest.

  However, say most validators actually voted fork 5, even though we
  currently observe 3 as the heavier. For whatever reason, those votes
  for 5 just didn't land (the leader for 6 missed the votes, network
  blip, etc.)

  All these validators that voted for 5 are now constrained by the
  switch check (38% of stake), and none of them can actually switch
  their vote to 4 (which only has 10%). But they're all continuing to
  build blocks on top of fork 4, which importantly implies that votes
  for 5 will not be able to propagate. This is because the validators
  that can't switch continue to refresh their votes for 5, but those
  votes never "land" because no one is building blocks on top of fork
  5 anymore (everyone is building on 4 because that's currently the
  heaviest).

  Therefore, it is important to reset to the same fork as your last vote
  slot, which is usually also the heaviest fork, but not always.

  Note that with both the vote slot and reset slot, the tower uses ghost
  to determine the last vote slot's ancestry. So what happens if the
  last vote slot isn't in the ghost? There are two separate cases in
  which this can happen that tower needs to handle:

  1. Our last vote slot > ghost root slot, but is not a descendant of
     the ghost root. This can happen if we get stuck on a minority fork
     with a long lockout. In the worst case, lockout duration is
     2^{threshold_check_depth} ie. 2^8 = 256 slots. In other words, we
     voted for and confirmed a minority fork 8 times in a row. We assume
     we won't vote past 8 times for the minority fork, because the
     threshold check would have stopped us (recall the threshold check
     requires 2/3 of stake to be on the same fork at depth 8 before we
     can keep voting for that fork).

     While waiting for those 256 slots of lockout to expire, it is
     possible that in the meantime a supermajority (ie. >2/3) of the
     cluster actually roots another fork that is not ours. During
     regular execution, we would not publish ghost until we have an
     updated tower root. So as long as the validator stays running while
     it is locked out from the supermajority fork, it keeps track of its
     vote slot's ancestry.

     If the validator were to stop running while locked out though (eg.
     operator needed to restart the box), the validator attempts to
     repair the ancestry of its last vote slot.

     In the worst case, if we cannot repair that ancestry, then we do
     not vote until replay reaches the expiration slot of that last vote
     slot. We can assume the votes > depth 8 in the tower do not violate
     lockout, because again the threshold check would have guarded it.

     TODO CURRENTLY THIS IS UNHANDLED. WHAT THE VALIDATOR DOES IF IT
     HAS LOST THE GHOST ANCESTRY IS IT WILL ERROR OUT.

  2. Our last vote slot < ghost root slot.  In this case we simply
     cannot determine whether our last vote slot is on the same fork as
     our ghost root slot because we no longer have ancestry information
     before the ghost root slot. This can happen if the validator is not
     running for a long time, then started up again. It will have to use
     the snapshot slot for the beginning of the ghost ancestry, which
     could be well past the last vote slot in the tower.

     In this case, before the validator votes again, it makes sure that
     the last vote's confirmation count >= THRESHOLD_CHECK_DEPTH (stated
     differently, it makes sure the next time it votes it will expire at
     least the first THRESHOLD_CHECK_DEPTH votes in the tower), and then
     it assumes that the last vote slot is on the same fork as the ghost
     root slot.

     TODO VERIFY AGAVE BEHAVIOR IS THE SAME.

  Now let’s switch gears from theory back to practice. What does it mean
  to send a vote?

  As a validator, you aren’t sending individual tower votes. Rather, you
  are sending your entire updated tower to the cluster every time.
  Essentially, the validator is continuously syncing their local tower
  with the cluster. That tower state is then stored inside a vote
  account, like any other state on Solana.

  On the flip side, we also must stay in sync the other way from cluster
  to local. If we have previously voted, we need to make sure our tower
  matches up with what the cluster has last seen. We know the most
  recent tower is in the last vote we sent, so we durably store every
  tower (by checkpointing it to disk) whenever we send a vote. In case
  this tower is out-of-date Conveniently Funk, our accounts database,
  stores all the vote accounts including our own, so on bootstrap we
  simply load in our vote account state itself to to initialize our own
  local view of the tower.

  Finally, a note on the difference between the Vote Program and
  TowerBFT. The Vote Program runs during transaction (block) execution.
  It checks that certain invariants about the tower inside a vote
  transaction are upheld (recall a validator sends their entire tower as
  part of a "vote"): otherwise, it fails the transaction. For example,
  it checks that every vote contains a tower in which the vote slots are
  strictly monotonically increasing. As a consequence, only valid towers
  are committed to the ledger. Another important detail of the Vote
  Program is that it only has a view of the current fork on which it is
  executing. Specifically, it can't observe what state is on other
  forks, like what a validator's tower looks like on fork A vs. fork B.

  The TowerBFT rules, on the other hand, run after transaction
  execution. Also unlike the Vote Program, the TowerBFT rules do not
  take the vote transactions as inputs: rather the inputs are the towers
  that have already been written to the ledger by the Vote Program. As
  described above, the Vote Program validates every tower, and in this
  way, the TowerBFT rules leverage the validation already done by the
  Vote Program to (mostly) assume each tower is valid. Every validator
  runs TowerBFT to update their own tower with votes based on the
  algorithm documented above. Importantly, TowerBFT has a view of all
  forks, and the validator makes a voting decision based on all forks.
*/

#include "../fd_choreo_base.h"
#include "../epoch/fd_epoch.h"
#include "../ghost/fd_ghost.h"
#include "../../disco/pack/fd_microblock.h"

/* FD_TOWER_USE_HANDHOLDING:  Define this to non-zero at compile time
   to turn on additional runtime checks and logging. */

#ifndef FD_TOWER_USE_HANDHOLDING
#define FD_TOWER_USE_HANDHOLDING 1
#endif

#define FD_TOWER_VOTE_MAX (31UL)

struct fd_tower_vote {
  ulong slot; /* vote slot */
  ulong conf; /* confirmation count */
};
typedef struct fd_tower_vote fd_tower_vote_t;

#define DEQUE_NAME fd_tower_votes
#define DEQUE_T    fd_tower_vote_t
#define DEQUE_MAX  FD_TOWER_VOTE_MAX
#include "../../util/tmpl/fd_deque.c"

/* fd_tower is a representation of a validator's "vote tower" (described
   in detail in the preamble at the top of this file).  The votes in the
   tower are stored in an fd_deque ordered from lowest to highest vote
   slot (highest to lowest confirmation count) relative to the head and
   tail .  There can be at most 31 votes in the tower.  This invariant
   is upheld with every call to `fd_tower_vote`.

   The definition of `fd_tower_t` is a simple typedef alias for
   `fd_tower_vote_t` and is a transparent wrapper around the vote deque.
   Relatedly, the tower API takes a local pointer to the first vote in
   the deque (the result of `fd_deque_join`) as a parameter in all its
   function signatures. */

typedef fd_tower_vote_t fd_tower_t;

/* FD_TOWER_{ALIGN,FOOTPRINT} specify the alignment and footprint needed
   for tower.  ALIGN is double x86 cache line to mitigate various kinds
   of false sharing (eg. ACLPF adjacent cache line prefetch).  FOOTPRINT
   is the size of fd_deque including the private header's start and end
   and an exact multiple of ALIGN.  These are provided to facilitate
   compile time tower declarations. */

#define FD_TOWER_ALIGN     (128UL)
#define FD_TOWER_FOOTPRINT (512UL)
FD_STATIC_ASSERT( FD_TOWER_FOOTPRINT==sizeof(fd_tower_votes_private_t), FD_TOWER_FOOTPRINT );

/* fd_tower_{align,footprint} return the required alignment and
   footprint of a memory region suitable for use as a tower.  align
   returns FD_TOWER_ALIGN.  footprint returns FD_TOWER_FOOTPRINT. */

FD_FN_CONST static inline ulong
fd_tower_align( void ) {
   return FD_TOWER_ALIGN;
}

FD_FN_CONST static inline ulong
fd_tower_footprint( void ) {
   return FD_TOWER_FOOTPRINT;
}

/* fd_tower_new formats an unused memory region for use as a tower.  mem
   is a non-NULL pointer to this region in the local address space with
   the required footprint and alignment. */

void *
fd_tower_new( void * mem );

/* fd_tower_join joins the caller to the tower.  tower points to the
   first byte of the memory region backing the tower in the caller's
   address space.

   Returns a pointer in the local address space to tower on success. */

fd_tower_t *
fd_tower_join( void * tower );

/* fd_tower_leave leaves a current local join.  Returns a pointer to the
   underlying shared memory region on success and NULL on failure (logs
   details).  Reasons for failure include tower is NULL. */

void *
fd_tower_leave( fd_tower_t * tower );

/* fd_tower_delete unformats a memory region used as a tower.  Assumes
   only the local process is joined to the region.  Returns a pointer to
   the underlying shared memory region or NULL if used obviously in
   error (e.g. tower is obviously not a tower ...  logs details).  The
   ownership of the memory region is transferred to the caller. */

void *
fd_tower_delete( void * tower );

/* fd_tower_lockout_check checks if we are locked out from voting for
   `slot`.  Returns 1 if we can vote for `slot` without violating
   lockout, 0 otherwise.  Assumes tower is non-empty.

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
fd_tower_lockout_check( fd_tower_t const * tower,
                        fd_ghost_t const * ghost,
                        ulong              slot,
                        fd_hash_t const *  hash_id );

/* fd_tower_switch_check checks if we can switch to the fork of `slot`.
   Returns 1 if we can switch, 0 otherwise.  Assumes tower is non-empty.

   There are two forks of interest: our last vote fork ("vote fork") and
   the fork we want to switch to ("switch fork"). The switch fork is the
   fork of `slot`.

   In order to switch, FD_TOWER_SWITCH_PCT of stake must have voted for
   a different descendant of the GCA of vote_fork and switch_fork, and
   also must be locked out from our last vote slot.

   Recall from the lockout check a validator is locked out from voting
   for our last vote slot when their last vote slot is on a different
   fork, and that vote's expiration slot > our last vote slot.

   The following pseudocode describes the algorithm:

   ```
   find the greatest common ancestor (gca) of vote_fork and switch_fork
   for all validators v
      if v's  locked out[1] from voting for our latest vote slot
         add v's stake to switch stake
   return switch stake >= FD_TOWER_SWITCH_PCT
   ```

   The switch check is used to safeguard optimistic confirmation.
   Specifically: FD_TOWER_OPT_CONF_PCT + FD_TOWER_SWITCH_PCT >= 1. */

int
fd_tower_switch_check( fd_tower_t const * tower,
                       fd_epoch_t const * epoch,
                       fd_ghost_t const * ghost,
                       ulong              slot,
                       fd_hash_t const *  hash_id );

/* fd_tower_threshold_check checks if we pass the threshold required to
   vote for `slot`.  This is only relevant after voting for (and
   confirming) the same fork ie. the tower is FD_TOWER_THRESHOLD_DEPTH
   deep.  Returns 1 if we pass the threshold check, 0 otherwise.

   The following psuedocode describes the algorithm:

   ```
   for all vote accounts in the current epoch

      simulate that the validator has voted for `slot`

      pop all votes expired by that simulated vote

      if the validator's latest tower vote after expiry >= our threshold
      slot ie. our vote from FD_TOWER_THRESHOLD_DEPTH back (after
      simulating a vote on our own tower the same way), then add
      validator's stake to threshold_stake.

   return threshold_stake >= FD_TOWER_THRESHOLD_PCT
   ```

   The threshold check simulates voting for the current slot to expire
   stale votes.  This is to prevent validators that haven't voted in a
   long time from counting towards the threshold stake. */

int
fd_tower_threshold_check( fd_tower_t const *    tower,
                          fd_epoch_t const *    epoch,
                          fd_funk_t *           funk,
                          fd_funk_txn_t const * txn,
                          ulong                 slot,
                          fd_tower_t *          scratch );

/* fd_tower_reset_slot returns the slot to reset PoH to when building
   the next leader block.  Assumes tower and ghost are both valid local
   joins and in-sync ie. every vote slot in tower corresponds to a node
   in ghost.  Returns FD_SLOT_NULL if this is not true.

   In general our reset slot is the fork head of our last vote slot, but
   there are 3 cases in which that doesn't apply:

   1. If we haven't voted before, we reset to the ghost head.

   2. If our last vote slot is older than the ghost root, we know we
      don't have ancestry information about our last vote slot anymore,
      so we also reset to the ghost head.

   2. If our last vote slot is newer than the ghost root, but we are
      locked out on a minority fork that does not chain back to the
      ghost root, we know that we should definitely not reset to a slot
      on this fork to build a block, given a supermajority of the
      cluster has already rooted a different fork.  So build off the
      best fork instead.

   See the top-level documentation in fd_tower.h for more context. */

ulong
fd_tower_reset_slot( fd_tower_t const * tower,
                     fd_ghost_t const * ghost );

/* fd_tower_vote_slot returns the correct vote slot to pick given the
   ghost tree.  Returns FD_SLOT_NULL if we cannot vote, because we are
   locked out, do not meet switch threshold, or fail the threshold
   check.

   Specifically, these are the two scenarios in which we can vote:

   1. the ghost head is on the same fork as our last vote slot, and
      we pass the threshold check.
   2. the ghost head is on a different fork than our last vote slot,
      but we pass both the lockout and switch checks so we can
      switch to the ghost head's fork. */

ulong
fd_tower_vote_slot( fd_tower_t *          tower,
                    fd_epoch_t const *    epoch,
                    fd_funk_t *           funk,
                    fd_funk_txn_t const * txn,
                    fd_ghost_t const *    ghost,
                    fd_tower_t *          scratch );

/* fd_tower_simulate_vote simulates a vote on the vote tower for slot,
   returning the new height (cnt) for all the votes that would have been
   popped.  Assumes tower is non-empty. */

ulong
fd_tower_simulate_vote( fd_tower_t const * tower, ulong slot );

/* Operations */

/* fd_tower_vote votes for slot.  Assumes caller has already performed
   the relevant tower checks (lockout_check, etc.) to ensure it is valid
   to vote for `slot`.  Returns a new root if this vote results in the
   lowest vote slot in the tower reaching max lockout.  The lowest vote
   will also be popped from the tower.

   Max lockout is equivalent to 1 << FD_TOWER_VOTE_MAX + 1 (which
   implies confirmation count is FD_TOWER_VOTE_MAX + 1).  As a result,
   fd_tower_vote also maintains the invariant that the tower contains at
   most FD_TOWER_VOTE_MAX votes, because (in addition to vote expiry)
   there will always be a pop before reaching FD_TOWER_VOTE_MAX + 1. */

ulong
fd_tower_vote( fd_tower_t * tower, ulong slot );

/* Misc */

/* fd_tower_from_vote_acc reads into tower the vote account saved in
   funk at the provided txn and vote_acc address.  Returns 0 on success,
   -1 on failure (account not found or failed to parse).  Assumes tower
   is a valid local join and currently empty. */

int
fd_tower_from_vote_acc( fd_tower_t *              tower,
                        fd_funk_t *               funk,
                        fd_funk_txn_t const *     txn,
                        fd_funk_rec_key_t const * vote_acc );

/* fd_tower_to_vote_txn writes tower into a fd_tower_sync_t vote
   instruction and serializes it into a Solana transaction.  Assumes
   tower is a valid local join. */

void
fd_tower_to_vote_txn( fd_tower_t const *    tower,
                      ulong                 root,
                      fd_lockout_offset_t * lockouts_scratch,
                      fd_hash_t const *     bank_hash,
                      fd_hash_t const *     recent_blockhash,
                      fd_pubkey_t const *   validator_identity,
                      fd_pubkey_t const *   vote_authority,
                      fd_pubkey_t const *   vote_acc,
                      fd_txn_p_t *          vote_txn );

/* fd_tower_verify checks tower is in a valid state. Valid iff:
   - cnt < FD_TOWER_VOTE_MAX
   - vote slots and confirmation counts in the tower are monotonically
     increasing */

int
fd_tower_verify( fd_tower_t const * tower );

/* fd_tower_on_duplicate checks if the tower is on the same fork with an
   invalid ancestor. */

int
fd_tower_on_duplicate( fd_tower_t const * tower, fd_ghost_t const * ghost );

/* fd_tower_print pretty-prints tower as a formatted table.

   Sample output:

        slot | confirmation count
   --------- | ------------------
   279803918 | 1
   279803917 | 2
   279803916 | 3
   279803915 | 4
   279803914 | 5
   279803913 | 6
   279803912 | 7
*/

void
fd_tower_print( fd_tower_t const * tower, ulong root );

#endif /* HEADER_fd_src_choreo_tower_fd_tower_h */
