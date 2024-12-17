#ifndef HEADER_fd_src_choreo_tower_fd_tower_h
#define HEADER_fd_src_choreo_tower_fd_tower_h

/* fd_tower presents an API for Solana's TowerBFT algorithm.

   What is TowerBFT? TowerBFT is an algorithm for converging a
   supermajority of stake in the validator cluster on the same fork.

        /-- 3-- 4 (A)
   1-- 2
        \-- 5     (B)

   Here, is a diagram of a fork. The leader for slot 5 decided to build
   off slot 2, rather than slot 4. This can happen for various reasons,
   for example network propagation delay. We now have two possible forks
   labeled A and B. The consensus algorithm has to pick one of them.

   So, how does the consensus algorithm pick? As detailed in fd_ghost.h,
   we pick the fork based on the most stake from votes, called the
   “heaviest”. Validators vote for blocks during replay, and
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

   Armed with some intuition, now let’s begin defining some terminology.
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

             slot | conf
   (before)  -----------
             4    | 1
             3    | 2
             2    | 3
             1    | 4

            slot | conf
   (after)  -----------
            9    | 1
            2    | 3
            1    | 4

   As you can see, we added a vote for slot 9 to the top of the tower.
   But we also removed the votes for slot 4 and slot 3. What happened?
   This is an example of vote expiry in action. When we voted for slot
   9, this exceeded the expirations of vote slots 4 and 3, which were 6
   and 7 respectively. This action of voting triggered the popping of
   the expired votes from the top of the tower.

   Next, we add a vote for slot 11:

             slot | conf
   (before)  -----------
             9    | 1
             2    | 3
             1    | 4

             slot | conf
   (after)   -----------
             11   | 1
             9    | 2
             2    | 3
             1    | 4

   The next vote for slot 11 doesn’t involve expirations, so we just add
   it to the top of the tower. Also, here is an important property of
   lockouts. Note that the lockout for vote slot 9 doubled (ie. the
   confirmation count increased by 1) but the lockouts of vote slots 2
   and 1 remained unchanged.

   The reason for this is confirmation counts only increase when they
   are consecutive in the vote tower. Because 4 and 3 were expired
   previously by the vote for 9, that consecutive property was broken.
   In this case, the vote for slot 11 is only consecutive with slot 9,
   but not 2 and 1. Specifically, there is a gap in the before-tower at
   confirmation count 2.

   In the after-tower, all the votes are again consecutive (confirmation
   counts 1, 2, 3, 4 are all accounted for), so the next vote will
   result in all lockouts doubling as long as it doesn’t result in more
   expirations.

   One other thing I’d like to point out about this vote for slot 11.
   Even though 11 exceeds the expiration slot of vote slot 2, which is
   10, voting for 11 did not expire the vote for 2. This is because
   expiration happens top-down and contiguously. Because vote slot 9 was
   not expired, we do not proceed with expiring 2.

   In the Tower rules, once a vote reaches a max lockout of 32, it is
   considered rooted and it is popped from the bottom of the tower. Here
   is an example:

             slot | conf
   (before)  -----------
             50   | 1
             ...  | ... (29 votes elided)
             1    | 4

             slot | conf
   (after)  -----------
             53   | 1
             ...  | ... (29 votes elided)
             1    | 4

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

  Here the new Slot 9 descends from 5, and exceeds vote slot 2’s
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
   optimistic confirmation. I won’t go into detail on optimistic
   confirmation, but in a nutshell it enables a fast-fork compared to
   rooting for a client to have high confidence a slot will eventually
   get rooted.

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
   descendants of the GCA that do not share a fork with us, and make
   sure their stake sums to more than 38%.

   I’d like to highlight that 7 here is not counted towards the switch
   proof, even though it is on a different fork from 4. This is because
   it’s on the same fork relative to the GCA.

   Now let’s switch gears from theory back to practice. What does it
   mean to send a vote?

   As a validator, you aren’t sending individual tower votes. Rather,
   you are sending your entire updated tower to the cluster every time.
   Essentially, the validator is continuously syncing their local tower
   with the cluster. That tower state is then stored inside a vote
   account, like any other state on Solana.

   On the flip side, we also must sync the other way: from cluster to
   local. If we have previously voted, we need to make sure we’re
   starting from where the cluster thinks we last left off. Conveniently
   Funk, our accounts database, stores all the vote accounts including
   our own, so on bootstrap we simply load in our vote account state
   itself to to initialize our own local view of the tower.

   *Additional Considerations*

   What's the difference between TowerBFT and the Vote Program?

   - TowerBFT runs on the sending side against our own tower ("local"
     view). It updates the tower with votes based on the algorithm
     detailed above. Importantly, TowerBFT has a view of all forks, and
     the validator makes a voting decision based on all forks.

   - The Vote Program runs on the receiving side against others' towers
     ("cluster" view). It checks that invariants about TowerBFT are
     maintained on votes received from the cluster. These checks are
     comparatively superficial to all the rules in tower. Furthermore,
     given it is a native program, the Vote Program only has access to
     the limited state programs are subject to. Specifically, it only
     has a view of the current fork it is executing on. It can't
     determine things like how much stake is allocated to other forks.

   What happens if our tower is out of sync with the cluster
   supermajority root (SMR)?

   - We detect this by seeing that our latest vote no longer descends
     from the SMR. Consider 2 cases:

     1. We are stuck on a minority fork.  In this case, we will observe
        that our latest vote slot > SMR, but its ancestry does not
        connect back to the SMR.  This can happen if we get locked out
        for a long time by voting for (and confirming) a minority fork.

        when we don't vote for a while (e.g. this validator was not
        running or we were stuck waiting for lockouts.) */

#include "../../flamenco/runtime/fd_blockstore.h"
#include "../fd_choreo_base.h"
#include "../forks/fd_forks.h"
#include "../ghost/fd_ghost.h"

#define FD_TOWER_EQV_SAFE ( 0.52 )
#define FD_TOWER_OPT_CONF ( 2.0 / 3.0 )
#define FD_TOWER_VOTE_MAX ( 32UL )

/* FD_TOWER_USE_HANDHOLDING:  Define this to non-zero at compile time
   to turn on additional runtime checks and logging. */

#ifndef FD_TOWER_USE_HANDHOLDING
#define FD_TOWER_USE_HANDHOLDING 1
#endif

struct fd_tower_vote {
  ulong slot; /* vote slot */
  ulong conf; /* confirmation count */
};
typedef struct fd_tower_vote fd_tower_vote_t;

#define DEQUE_NAME fd_tower_votes
#define DEQUE_T    fd_tower_vote_t
#define DEQUE_MAX  FD_TOWER_VOTE_MAX
#include "../../util/tmpl/fd_deque.c"

struct fd_tower_vote_acc {
  fd_pubkey_t const * addr;
  ulong               stake;
};
typedef struct fd_tower_vote_acc fd_tower_vote_acc_t;

#define DEQUE_NAME fd_tower_vote_accs
#define DEQUE_T    fd_tower_vote_acc_t
#define DEQUE_MAX  FD_VOTER_MAX
#include "../../util/tmpl/fd_deque.c"

/* fd_tower implements the TowerBFT algorithm and related consensus
   rules. */

/* clang-format off */
struct __attribute__((aligned(128UL))) fd_tower {

  /* The votes currently in the tower, ordered from latest to earliest
     vote slot (lowest to highest confirmation count). */

  fd_tower_vote_t * votes;

  /* The root is the most recent vote in the tower to reach max lockout
     (ie. confirmation count 32).  It is no longer present in the tower
     votes themselves. */

  ulong root; /* FIXME wire with fseq */

  /* Vote accounts in the current epoch.

     Lifetimes of the vote account addresses (pubkeys) are valid for the
     epoch (the pubkey memory is owned by the epoch bank.) */

  fd_tower_vote_acc_t * vote_accs;

  /* Total amount of stake in the current epoch. */

  ulong total_stake;

  /* smr is a non-NULL pointer to an fseq that always contains the
     highest observed smr.  This value is initialized by replay tile.

     Do not read or modify outside the fseq API. */

  ulong * smr;
};
typedef struct fd_tower fd_tower_t;

/* fd_tower_{align,footprint} return the required alignment and
   footprint of a memory region suitable for use as tower.  align is
   double cache line to mitigate false sharing. */

FD_FN_CONST static inline ulong
fd_tower_align( void ) {
  return alignof(fd_tower_t);
}

FD_FN_CONST static inline ulong
fd_tower_footprint( void ) {
  return FD_LAYOUT_FINI(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_APPEND(
    FD_LAYOUT_INIT,
      alignof(fd_tower_t),        sizeof(fd_tower_t)             ),
      fd_tower_votes_align(),     fd_tower_votes_footprint()     ),
      fd_tower_vote_accs_align(), fd_tower_vote_accs_footprint() ),
    alignof(fd_tower_t) );
}
/* clang-format on */

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
fd_tower_leave( fd_tower_t const * tower );

/* fd_tower_delete unformats a memory region used as a tower.  Assumes
   only the local process is joined to the region.  Returns a pointer to
   the underlying shared memory region or NULL if used obviously in
   error (e.g. tower is obviously not a tower ...  logs details).  The
   ownership of the memory region is transferred to the caller. */

void *
fd_tower_delete( void * tower );

/* fd_tower_init initializes a tower.  Assumes tower is a valid local
   join and no other processes are joined.  root is the initial root
   that tower will use.  This is the snapshot slot if booting from a
   snapshot, genesis slot otherwise.

   In general, this should be called by the same process that formatted
   tower's memory, ie. the caller of fd_tower_new. */
void
fd_tower_init( fd_tower_t *                tower,
               fd_pubkey_t const *         vote_acc_addr,
               fd_acc_mgr_t *              acc_mgr,
               fd_exec_epoch_ctx_t const * epoch_ctx,
               fd_fork_t const *           fork,
               ulong *                     smr );

/* fd_tower_lockout_check checks if we are locked out from voting for
   fork.  Returns 1 if we can vote for fork without violating lockout, 0
   otherwise.

   After voting for a slot n, we are locked out for 2^k slots, where k
   is the confirmation count of that vote.  Once locked out, we cannot
   vote for a different fork until that previously-voted fork expires at
   slot n+2^k.  This implies the earliest slot in which we can switch
   from the previously-voted fork is (n+2^k)+1.

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
                        fd_fork_t const *  fork,
                        fd_ghost_t const * ghost );

/* fd_tower_switch_check checks if we can switch to fork.  Returns 1 if
   we can switch, 0 otherwise.

   The switch rule is based on the percentage of validators whose: 1.
   last vote slot is for fork and 2. lockout prevents them from voting
   for our last vote slot.

   A validator is locked out from voting for our last vote slot when
   their last vote slot is on a different fork, and that vote's
   expiration slot > our last vote slot.

   The following pseudocode describes the algorithm:

   ```
   find the greatest common ancestor (gca) of our fork and fork
   for all validators v
      if v's latest vote is for fork
         add v's stake to switch stake


   for all validators v
      if v's  locked out[1] from voting for our latest vote slot
         add v's stake to switch stake
   return switch stake >= FD_TOWER_SWITCH_PCT
   ```


   The switch check is used to safeguard optimistic confirmation.
   Invariant: FD_TOWER_OPT_CONF_PCT + FD_TOWER_SWITCH_PCT >= 1. */

int
fd_tower_switch_check( fd_tower_t const * tower, fd_fork_t const * fork, fd_ghost_t const * ghost );

/* fd_tower_threshold_check checks if we pass the threshold required to
   continue voting along the same fork as our last vote.  Returns 1 if
   we pass the threshold check, 0 otherwise.

   The following psuedocode describes the algorithm:

   ```
   for all vote accounts on the current fork

      simulate that the validator has voted on the current slot (the
      fork head)

      pop all votes expired by that simulated vote

      if validator's latest tower vote after expiry >= our threshold
      slot ie. our vote from FD_TOWER_THRESHOLD_DEPTH back (after
      simulating a vote on our own tower the same way)

         add validator's stake to threshold_stake.

   return threshold_stake >= FD_TOWER_THRESHOLD_PCT
   ```

   The threshold check simulates voting for the current slot to expire
   stale votes.  This is to prevent validators that haven't voted in a
   long time from counting towards the threshold stake. */

int
fd_tower_threshold_check( fd_tower_t const * tower,
                          fd_fork_t const *  fork,
                          fd_acc_mgr_t *     acc_mgr );

/* fd_tower_best_fork picks the best fork, where best is defined as the
   fork head containing the highest stake-weight in its ancestry.
   Returns a non-NULL fork.  Assumes forks->frontier is non-empty.  Note
   this is not necessarily the same fork as the one we vote on, as we
   might be locked out on a different fork.

   Does not modify tower. */

fd_fork_t const *
fd_tower_best_fork( fd_tower_t const * tower, fd_forks_t const * forks, fd_ghost_t const * ghost );

/* fd_tower_reset_fork picks which fork to reset PoH to for our next
   leader slot.  Returns a non-NULL fork.  Note this is not necessarily
   the same fork as the one we vote on, as we do not always vote for the
   fork we reset to.

   Does not modify tower. */

fd_fork_t const *
fd_tower_reset_fork( fd_tower_t const * tower, fd_forks_t const * forks, fd_ghost_t const * ghost );

/* fd_tower_vote_fork picks which frontier fork to vote on. Returns NULL
   if we cannot vote because we are locked out, do not meet switch
   threshold, or fail the threshold check.

   Modifies the tower to record the vote slot of the fork we select. */

fd_fork_t const *
fd_tower_vote_fork( fd_tower_t *       tower,
                    fd_forks_t const * forks,
                    fd_acc_mgr_t *     acc_mgr,
                    fd_ghost_t const * ghost );

/* fd_tower_epoch_update updates the tower after with a new epoch ctx.
   This should only be called on startup and when crossing an epoch
   boundary. */

void
fd_tower_epoch_update( fd_tower_t * tower, fd_exec_epoch_ctx_t const * epoch_ctx );

/* fd_tower_fork_update updates ghost with the latest state of the vote
   accounts after executing the fork head (fork->slot).

   IMPORTANT SAFETY TIP!  This should be called _after_ execution of
   fork->slot, not before. */

void
fd_tower_fork_update( fd_tower_t const * tower,
                      fd_fork_t const *  fork,
                      fd_acc_mgr_t *     acc_mgr,
                      fd_blockstore_t *  blockstore,
                      fd_ghost_t *       ghost );

/* fd_tower_simulate_vote simulates a vote on the vote tower for slot,
   returning the new height (cnt) for all the votes that would have been
   popped. */

ulong
fd_tower_simulate_vote( fd_tower_t const * tower, ulong slot );

/* fd_tower_vote votes for slot.  Assumes caller has already performed
   all the tower checks to ensure this is a valid vote. */

void
fd_tower_vote( fd_tower_t const * tower, ulong slot );

/* fd_tower_is_max_lockout returns 1 if the bottom vote of the tower has
   reached max lockout, 0 otherwise.  Max lockout is equivalent to 1 <<
   FD_TOWER_VOTE_MAX (equivalently, confirmation count is
   FD_TOWER_VOTE_MAX).  So if the tower is at height FD_TOWER_VOTE_MAX,
   then the bottom vote has reached max lockout. */

static inline int
fd_tower_is_max_lockout( fd_tower_t const * tower ) {
  return fd_tower_votes_cnt( tower->votes ) == FD_TOWER_VOTE_MAX;
}

/* fd_tower_publish publishes the tower.  Returns the new root.  Assumes
   caller has already checked that tower has reached max lockout (see
   fd_tower_is_max_lockout). */

static inline ulong
fd_tower_publish( fd_tower_t * tower ) {
#if FD_TOWER_USE_HANDHOLDING
  FD_TEST( fd_tower_is_max_lockout( tower ) );
#endif

  ulong root = fd_tower_votes_pop_head( tower->votes ).slot;
  FD_LOG_NOTICE( ( "[%s] root %lu", __func__, tower->root ) );
  tower->root = root;
  return root;
}

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
fd_tower_print( fd_tower_t const * tower );

/* Vote state API */

/* fd_tower_vote_state_cmp compares tower with vote_state.  Conceptually
   this is comparing our local view of our tower with the cluster's view
   (which may be out of sync).  Returns -1 if the vote_state is
   newer, 0 if they're in sync and 1 if the local view is newer.
   Assumes both tower and vote_state are valid ie. there is a root and
   there is at least one vote (verifies this with handholding enabled).

   If tower is newer than vote_state, then the cluster has a stale view
   of our local tower.  This normally just means our last vote hasn't
   landed yet and our vote state will eventually updated once that vote
   or a later one does land.

   If vote_state is newer than tower, then we already voted for
   fork->slot.  This means we are not caught up yet or more
   problematically there is potentially another process running that is
   voting using our private key.

   IMPORTANT SAFETY TIP!  Even though these towers may be out of sync,
   they should never be incompatible.  For example, tower should never
   contain a state that could only be reached from vote_state by
   violating lockouts. */

int
fd_tower_vote_state_cmp( fd_tower_t const * tower, fd_vote_state_t * vote_state );

/* fd_tower_vote_state_query queries for vote_acc_addr's vote state
   which is effectively the cluster view of the tower as of fork->slot.
   Returns a pointer to vote_state on success, NULL on failure.  The
   vote_state is allocated using the provided valloc. */

fd_vote_state_t *
fd_tower_vote_state_query( fd_tower_t const *          tower,
                           fd_pubkey_t const *         vote_acc_addr,
                           fd_acc_mgr_t *              acc_mgr,
                           fd_fork_t const *           fork,
                           fd_valloc_t                 valloc,
                           fd_vote_state_versioned_t * versioned );

/* fd_tower_from_vote_state replaces the votes and root of tower with
   those from the vote state. */

void
fd_tower_from_vote_state( fd_tower_t * tower, fd_vote_state_t * vote_state );

/* fd_tower_to_tower_sync converts an fd_tower_t into a fd_tower_sync_t
   to be sent out as a vote program ix inside a txn. */

void
fd_tower_to_tower_sync( fd_tower_t const *               tower,
                        fd_hash_t const *                bank_hash,
                        fd_compact_vote_state_update_t * tower_sync );

#endif /* HEADER_fd_src_choreo_tower_fd_tower_h */
