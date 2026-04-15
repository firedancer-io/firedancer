#ifndef HEADER_fd_src_choreo_tower_fd_tower_h
#define HEADER_fd_src_choreo_tower_fd_tower_h

/* fd_tower presents an API for Solana's TowerBFT algorithm.

   What is TowerBFT?  TowerBFT is an algorithm for converging a
   supermajority of stake in the validator cluster on the same fork.

        /-- 3-- 4 (A)
   1-- 2
        \-- 5     (B)

   Above is a diagram of a fork.  The leader for slot 5 decided to build
   off slot 2, rather than slot 4.  This can happen for various reasons,
   for example network propagation delay.  We now have two possible forks
   labeled A and B.  The consensus algorithm has to pick one of them.

   So, how does the consensus algorithm pick?  As detailed in
   fd_ghost.h, we pick the fork based on the most stake from votes,
   called the "heaviest".  Validators vote for blocks during replay, and
   simultaneously use other validator’s votes to determine which block
   to vote for.  This encourages convergence, because as one fork gathers
   more votes, more and more votes pile-on, solidifying its position as
   the heaviest fork.

         /-- 3-- 4 (10%)
   1-- 2
         \-- 5     (9%)

   However, network propagation delay of votes can lead us to think one
   fork is heaviest, before observing new votes that indicate another
   fork is heavier.  So our consensus algorithm also needs to support
   switching.

         /-- 3-- 4 (10%)
   1-- 2
         \-- 5     (15%)

   At the same time we don’t want excessive switching.  The more often
   validators switch, the more difficult it will be to achieve that
   pile-on effect I just described.

   Note that to switch forks, you need to rollback a given slot and its
   descendants on that fork.  In the example above, to switch to 1, 2, 5,
   we need to rollback 3 and 4.  The consensus algorithm makes it more
   costly the further you want to rollback a fork.  Here, I’ve added a
   column lockout, which doubles for every additional slot you want to
   rollback.

   Eventually you have traversed far enough down a fork, that the
   lockout is so great it is infeasible to imagine it ever rolling back
   in practice.  So you can make that fork permanent or “commit” it.
   Once all validators do this, the blockchain now just has a single
   fork.

   Armed with some intuition, let’s now begin defining some terminology.
   Here is a diagram of a validator's "vote tower":

   slot | confirmation count (conf)
   --------------------------------
   4    | 1
   3    | 2
   2    | 3
   1    | 4

   It is a stack structure in which each element is a vote.  The vote
   slot column indicates which slots the validator has voted for,
   ordered from most to least recent.

   The confirmation count column indicates how many consecutive votes on
   the same fork have been pushed on top of that vote.  You are
   confirming your own votes for a fork every time you vote on top of
   the same fork.

   Two related concepts to confirmation count are lockout and expiration
   slot.  Lockout equals 2 to the power of confirmation count.  Every
   time we “confirm” a vote by voting on top of it, we double the
   lockout. The expiration slot is the sum of vote slot and lockout, so
   it also increases when lockouts double.  It represents which slot the
   vote will expire.  When a vote expires, it is popped from the top of
   the tower.  An important Tower rule is that a validator cannot vote
   for a different fork from a given vote slot, until reaching the
   expiration slot for that vote slot.  To summarize, the further a
   validator wants to rollback their fork (or vote slots) the longer the
   validator needs to wait without voting (in slot time).

   Here is the same tower, fully-expanded to include all the fields:

   slot | conf | lockout | expiration
   ----------------------------------
   4    | 1    | 2       | 6
   3    | 2    | 4       | 7
   2    | 3    | 8       | 10
   1    | 4    | 16      | 17

   Based on this tower, the validator is locked out from voting for any
   slot <= 6 that is on a different fork than slot 4.  I’d like to
   emphasize that the expiration is with respect to the vote slot, and
   is _not_ related to the Proof-of-History slot or what the "current
   slot" is.  So even if the current slot is now 7, the validator can’t
   go back and vote for slot 5, if slot 5 were on a different fork than
   4.  The earliest valid vote slot this validator could submit for a
   different fork from 4 would be slot 7 or later.

   Next let’s look at how the tower makes state transitions.  Here we
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
   But we also removed the votes for slot 4 and slot 3.  What happened?
   This is an example of vote expiry in action.  When we voted for slot
   9, this exceeded the expirations of vote slots 4 and 3, which were 6
   and 7 respectively.  This action of voting triggered the popping of
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
   it to the top of the tower.  Also, here is an important property of
   lockouts.  Note that the lockout for vote slot 9 doubled (ie. the
   confirmation count increased by 1) but the lockouts of vote slots 2
   and 1 remained unchanged.

   The reason for this is confirmation counts only increase when they
   are consecutive in the vote tower.  Because 4 and 3 were expired
   previously by the vote for 9, that consecutive property was broken.
   In this case, the vote for slot 10 is only consecutive with slot 9,
   but not 2 and 1.  Specifically, there is a gap in the before-tower at
   confirmation count 2.

   In the after-tower, all the votes are again consecutive (confirmation
   counts 1, 2, 3, 4 are all accounted for), so the next vote will
   result in all lockouts doubling as long as it doesn’t result in more
   expirations.

   One other thing I’d like to point out about this vote for slot 10.
   Even though 10 >= the expiration slot of vote slot 2, which is 10,
   voting for 11 did not expire the vote for 2.  This is because
   expiration happens top-down and contiguously.  Because vote slot 9
   was not expired, we do not proceed with expiring 2.

   In the Tower rules, once a vote reaches a conf count of 32, it is
   considered rooted and it is popped from the bottom of the tower.
   Here is an example where 1 got rooted and popped from the bottom:

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

   Rooting has implications beyond the Tower.  It's what we use to prune
   our state.  Every time tower makes a new root slot, we prune any old
   state that does not originate from that new root slot.  Our
   blockstore will discard blocks below that root, our forks structure
   will discard stale banks, funk (which is our accounts database) will
   discard stale transactions (which in turn track modifications to
   accounts), and ghost (which is our fork select tree) will discard
   stale nodes tracking stake percentages.  We call this operation
   publishing.

   Note that the vote slots are not necessarily consecutive.  Here I
   elided the votes sandwiched between the newest and oldest votes for
   brevity.

   Next, let’s go over three additional tower checks.  These three
   checks further reinforce the consensus algorithm we established with
   intuition, in this case getting a supermajority (ie. 2/3) of stake to
   converge on a fork.

   The first is the threshold check.  The threshold check makes sure at
   least 2/3 of stake has voted for the same fork as the vote at depth 8
   in our tower.  Essentially, this guards our tower from getting too
   out of sync with the rest of the cluster.  If we get too out of sync
   we can’t vote for a long time, because we had to rollback a vote we
   had already confirmed many times and had a large lockout.  This might
   otherwise happen as the result of a network partition where we can
   only communicate with a subset of stake.

   Next is the lockout check.  We went in detail on this earlier when
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

  Here the new Slot 9 descends from 5 and exceeds vote slot 4’s
  expiration slot of 6 unlike 5.

  After your lockout expires, the tower rules allow you to vote for
  descendants of the fork slot you wanted to switch to in the first
  place (here, 9 descending from 5).  So we eventually switch to the
  fork we wanted, by voting for 9 and expiring 3 and 4.

  Importantly, notice that the fork slots and vote slots are not exactly
  1-to-1.  While conceptually our tower is voting for the fork 1, 2, 5,
  9, the vote for 5 is only implied.  Our tower votes themselves still
  can’t include 5 due to lockout.

  Finally, the switch check.  The switch check is used to safeguard
  optimistic confirmation.  Optimistic confirmation is when a slot gets
  2/3 of stake-weighted votes.  This is then treated as a signal that the
  slot will eventually get rooted.  However, to actually guarantee this
  we need a rule that prevents validators from arbitrarily switching
  forks (even when their vote lockout has expired).  This rule is the
  switch check.

  The switch check is additional to the lockout check.  Before switching
  forks, we need to make sure at least 38% of stake has voted for a
  different fork than our own.  Different fork is defined by finding the
  greatest common ancestor of our last voted fork slot and the slot we
  want to switch to.  Any forks descending from the greatest common
  ancestor (which I will subsequently call the GCA) that are not our
  own fork are counted towards the switch check stake.

  Here we visualize the switch check:

             /-- 7
        /-- 3-- 4
  1-- 2  -- 6
        \-- 5-- 9

  First, we find the GCA of 4 and 9 which is 2.  Then we look at all the
  descendants of the GCA that do not share a fork with us, and make sure
  their stake sums to more than 38%.

  I’d like to highlight that 7 here is not counted towards the switch
  proof, even though it is on a different fork from 4. This is because
  it’s on the same fork relative to the GCA.

  So that covers the checks.  Next, there are two additional important
  concepts: "reset slot" and "vote slot".  The reset slot is the slot you
  reset PoH to when it's your turn to be leader.  Because you are
  responsible for producing a block, you need to decide which fork to
  build your block on.  For example, if there are two competing slots 3
  and 4, you would decide whether to build 3 <- 5 or 4 <- 5.  In general
  the reset slot is the same fork as the vote slot, but not always.
  There is an important reason for this.  Recall this fork graph from
  earlier:

        /-- 3-- 4 (10%)
   1-- 2
        \-- 5-- 6 (9%)

  In this diagram, 4 is the winner of fork choice.  All future leaders
  now want to reset to slot 4.  Naively, this makes sense because you
  maximize the chance of your block finalizing (and earning the rewards)
  if you greedily (in the algorithmic, and perhaps also literal sense)
  pick what's currently the heaviest.

  However, say most validators actually voted fork 5, even though we
  currently observe 3 as the heavier. For whatever reason, those votes
  for 5 just didn't land (the leader for 6 missed the votes, network
  blip, etc.)

  All these validators that voted for 5 are now constrained by the
  switch check (38% of stake), and none of them can actually switch
  their vote to 4 (which only has 10%).  But they're all continuing to
  build blocks on top of fork 4, which importantly implies that votes
  for 5 will not be able to propagate.  This is because the validators
  that can't switch continue to refresh their votes for 5, but those
  votes never "land" because no one is building blocks on top of fork
  5 anymore (everyone is building on 4 because that's currently the
  heaviest).

  Therefore, it is important to reset to the same fork as your last vote
  slot, which is usually also the heaviest fork, but not always.

  Now let’s switch gears from theory back to practice.  How does the
  literal mechanism of voting actually work?

  Validators don't send individual votes.  Rather, they send their
  entire updated tower to the cluster every time. Essentially, the
  validator is continuously syncing their local tower with the cluster.
  That tower state is then stored inside a vote account, like any other
  state on Solana.

  On the flip side, validators also must stay in sync the other way from
  cluster to local.  If a validator has previously voted, then they have
  an on-chain vote account containing the cluster's latest view of the
  tower (as of a given replay slot).  If this on-chain tower is
  incompatible with the local one, they must be reconciled
  (fd_tower_reconcile - also note the etymology for the "TowerSync" vote
  instruction).

  Finally, a note on the difference between the Vote Program and
  TowerBFT.  The Vote Program runs during transaction (block) execution.
  It checks that certain invariants about the tower inside a vote
  transaction are upheld (recall a validator sends their entire tower as
  part of a "vote"): otherwise, it fails the transaction. For example,
  it checks that every vote contains a tower in which the vote slots are
  strictly monotonically increasing.  As a consequence, only valid
  towers are committed to the ledger.  Another important detail of the
  Vote Program is that it only has a view of the current fork on which
  it is executing.  Specifically, it can't observe what state is on
  other forks, like what a validator's tower looks like on fork A vs.
  fork B.

  The TowerBFT rules, on the other hand, run after transaction
  execution.  Also unlike the Vote Program, the TowerBFT rules do not
  take the vote transactions as inputs: rather the inputs are the towers
  that have already been written to the ledger by the Vote Program.  As
  described above, the Vote Program validates every tower, and in this
  way, the TowerBFT rules leverage the validation already done by the
  Vote Program to (mostly) assume each tower is valid.  Every validator
  runs TowerBFT to update their own tower with votes based on the
  algorithm documented above.  Importantly, TowerBFT has a view of all
  forks, and the validator makes a voting decision based on all forks.
*/

#include "../fd_choreo_base.h"
#include "fd_tower_serdes.h"

#define FD_TOWER_LOCKOS_MAX 31UL
#include "fd_tower_stakes.h"
#include "../ghost/fd_ghost.h"
#include "../votes/fd_votes.h"
#include "../../disco/pack/fd_microblock.h"

#define FD_TOWER_VOTE_MAX (FD_TOWER_LOCKOS_MAX)

/* fd_tower is a representation of a validator's "vote tower" (described
   in detail in the preamble at the top of this file).  The votes in the
   tower are stored in an fd_deque.c ordered from lowest to highest vote
   slot (highest to lowest confirmation count) relative to the head and
   tail.  There can be at most FD_TOWER_VOTE_MAX votes in the tower. */

struct fd_tower_vote {
  ulong slot; /* vote slot */
  ulong conf; /* confirmation count */
};
typedef struct fd_tower_vote fd_tower_vote_t;

#define DEQUE_NAME fd_tower_vote
#define DEQUE_T    fd_tower_vote_t
#define DEQUE_MAX  FD_TOWER_VOTE_MAX
#include "../../util/tmpl/fd_deque.c"

/* FD_TOWER_VOTE_{ALIGN,FOOTPRINT} provided for static declarations. */

#define FD_TOWER_VOTE_ALIGN     (alignof(fd_tower_vote_private_t))
#define FD_TOWER_VOTE_FOOTPRINT (sizeof (fd_tower_vote_private_t))
FD_STATIC_ASSERT( alignof(fd_tower_vote_private_t)==8UL,   FD_TOWER_VOTE_ALIGN     );
FD_STATIC_ASSERT( sizeof (fd_tower_vote_private_t)==512UL, FD_TOWER_VOTE_FOOTPRINT );

/* fd_tower_blk_t maintains tower-specific metadata about every block,
   such as what block_id we last replayed, what block_id we voted for,
   and what block_id was ultimately "duplicate confirmed".

   This is used by tower to make voting decisions, such as whether or
   not we can switch "forks".  In this context, a fork is a branch of a
   tree that extends from the root to a leaf.  For example:

        /-- 3-- 4  (A)
   1-- 2
        \-- 5      (B)

   Here, A and B are two different forks.  A is [1, 2, 3, 4] and B is
   [1, 2, 5], two branches that each extend from the root to a leaf.

   Note that even though fd_tower_blk_t is block_id-aware, it does not
   use them for determining parentage.  Instead, parentage is based on
   slot numbers, so in cases of equivocation (duplicate blocks), tower
   will consider something an ancestor or descendant even if the block
   ids do not chain.

   This behavior intentionally mirrors the Agave logic implemented in
   `make_check_switch_threshold_decision`.  Essentially, tower is unable
   to distinguish duplicates because the vote account format (in which
   towers are stored) only stores slot numbers and not block_ids. */

struct fd_tower_blk {
  ulong     slot;               /* pool next / map key */
  ulong     next;               /* pool next / map next */
  ulong     prev;               /* map prev */
  ulong     parent_slot;        /* parent slot */
  ulong     epoch;              /* epoch of this slot */
  int       replayed;           /* whether we've replayed this slot yet */
  fd_hash_t replayed_block_id;  /* the block_id we _last_ replayed for this slot */
  int       voted;              /* whether we voted for this slot yet */
  fd_hash_t voted_block_id;     /* the block_id we voted on for this slot */
  int       confirmed;          /* whether this slot has been duplicate confirmed */
  fd_hash_t confirmed_block_id; /* the block_id that was duplicate confirmed */
  int       leader;             /* whether this slot was our own leader slot */
  int       propagated;         /* whether this slot has been propagation confirmed (1/3 stake) */
  ulong     prev_leader_slot;   /* previous slot in which we were leader as of this slot (inclusive) */
};
typedef struct fd_tower_blk fd_tower_blk_t;

/* fd_tower_vtr_t describes a single vote account that feeds into
   TowerBFT rules: vote account address, stake, and deserialized tower
   votes + root.  The votes pointer points into pre-allocated storage
   managed by the tower and is joined once during init. */

struct fd_tower_vtr {
  fd_pubkey_t       vote_acc; /* vote account address */
  ulong             stake;    /* vote account stake */
  fd_tower_vote_t * votes;    /* deserialized vote deque (pre-allocated, owned by tower) */
  ulong             root;     /* tower root slot (ULONG_MAX if none) */
};
typedef struct fd_tower_vtr fd_tower_vtr_t;

#define DEQUE_NAME fd_tower_vtr
#define DEQUE_T    fd_tower_vtr_t
#include "../../util/tmpl/fd_deque_dynamic.c"

/* fd_tower_t wraps the vote deque, root slot, block metadata, and
   voter entries.  Sub-structures are allocated inline after the struct.
   Use fd_tower_{new,join,leave,delete,align,footprint} to manage. */

struct fd_tower {
  fd_tower_vote_t * votes; /* our local tower's vote deque */
  ulong             root;  /* our local tower's root slot (ULONG_MAX if none) */

  ulong              blk_max;   /* max number of blocks */
  ulong              vtr_max;   /* max number of voters */
  fd_tower_blk_t *   blk_pool;  /* pool of blk_t elements (NULL if blk_max==0) */
  void *             blk_map;   /* map chain of blk_t elements (NULL if blk_max==0) */
  fd_tower_vtr_t *   vtrs;      /* deque of voter entries (NULL if vtr_max==0) */

  void * lck_pool; /* lockout interval pool */
  void * lck_map;  /* lockout interval map chain */

  fd_tower_stakes_vtr_map_t * stk_vtr_map;
  fd_tower_stakes_vtr_t *     stk_vtr_pool;
  fd_tower_stakes_slot_t *    stk_slot_map;
  fd_used_acc_scratch_t *     stk_used_acc;
};
typedef struct fd_tower fd_tower_t;

/* fd_tower_{align,footprint} return the required alignment and
   footprint of a memory region suitable for use as a tower.
   blk_max==0 creates a votes-only tower (for voter towers). */

FD_FN_CONST ulong
fd_tower_align( void );

ulong
fd_tower_footprint( ulong blk_max,
                    ulong vtr_max );

/* fd_tower_new formats an unused memory region for use as a tower.  mem
   is a non-NULL pointer to this region in the local address space with
   the required footprint and alignment.  seed is for the block map
   hash. */

void *
fd_tower_new( void * mem,
              ulong  blk_max,
              ulong  vtr_max,
              ulong  seed );

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

#define FD_TOWER_FLAG_ANCESTOR_ROLLBACK 0 /* rollback to an ancestor of our prev vote */
#define FD_TOWER_FLAG_SIBLING_CONFIRMED 1 /* our prev vote was a duplicate and its sibling got confirmed */
#define FD_TOWER_FLAG_SAME_FORK         2 /* prev vote is on the same fork */
#define FD_TOWER_FLAG_SWITCH_PASS       3 /* successfully switched to a different fork */
#define FD_TOWER_FLAG_SWITCH_FAIL       4 /* failed to switch to a different fork */
#define FD_TOWER_FLAG_LOCKOUT_FAIL      5 /* failed lockout check */
#define FD_TOWER_FLAG_THRESHOLD_FAIL    6 /* failed threshold check */
#define FD_TOWER_FLAG_PROPAGATED_FAIL   7 /* failed propagated check */

struct fd_tower_out {
  uchar     flags;          /* one of FD_TOWER_{EMPTY,...} */
  ulong     reset_slot;     /* slot to reset PoH to */
  fd_hash_t reset_block_id; /* block ID to reset PoH to */
  ulong     vote_slot;      /* slot to vote for (ULONG_MAX if no vote) */
  fd_hash_t vote_block_id;  /* block ID to vote for */
  ulong     root_slot;      /* new tower root slot (ULONG_MAX if no new root) */
  fd_hash_t root_block_id;  /* new tower root block ID */
};
typedef struct fd_tower_out fd_tower_out_t;

#define FD_TOWER_CSTR_MIN (917UL) /* worst-case tower with 31 entries and 20-digit (the max width of a `ulong`) slots */

void
fd_tower_count_vote( fd_tower_t *        tower,
                     fd_pubkey_t const * vote_acc,
                     ulong               stake,
                     uchar const         data[static FD_VOTE_STATE_DATA_MAX] );

/* fd_tower_vote_and_reset selects both a block to vote for and block to
   reset to.  Returns flags (FD_TOWER_FLAG_{...}) and writes results to
   out-pointers for {reset,vote,root}_{slot,block_id}.

   We can't always vote, so vote_slot may be ULONG_MAX which indicates
   no vote should be cast and caller should ignore vote_block_id.  New
   roots result from votes, so the same applies for root_slot (there is
   not always a new root).  However there is always a reset block, so
   reset_slot and reset_block_id will always be populated on return. The
   implementation contains detailed documentation of the tower rules. */

uchar
fd_tower_vote_and_reset( fd_tower_t * tower,
                         fd_ghost_t * ghost,
                         fd_votes_t * votes,
                         ulong *      reset_slot,
                         fd_hash_t *  reset_block_id,
                         ulong *      vote_slot,
                         fd_hash_t *  vote_block_id,
                         ulong *      root_slot,
                         fd_hash_t *  root_block_id );

/* Misc */

/* fd_tower_reconcile reconciles our local tower with the on-chain tower
   inside our vote account.  Mirrors what Agave does.  Also updates
   block vote metadata to match the updated tower. */

void
fd_tower_reconcile( fd_tower_t  * tower,
                    uchar const * vote_acc );

/* fd_tower_blocks_{query,insert,remove} provide convenient wrappers for
   {querying,inserting,removing} blocks into the tower's block map. */

fd_tower_blk_t *
fd_tower_blocks_query( fd_tower_t * tower,
                       ulong        slot );

fd_tower_blk_t *
fd_tower_blocks_insert( fd_tower_t * tower,
                        ulong        slot,
                        ulong        parent_slot );

void
fd_tower_blocks_remove( fd_tower_t * tower,
                        ulong        slot );

int
fd_tower_blocks_is_slot_ancestor( fd_tower_t * tower,
                                  ulong        descendant_slot,
                                  ulong        ancestor_slot );

int
fd_tower_blocks_is_slot_descendant( fd_tower_t * tower,
                                    ulong        ancestor_slot,
                                    ulong        descendant_slot );

ulong
fd_tower_blocks_lowest_common_ancestor( fd_tower_t * tower,
                                        ulong        slot1,
                                        ulong        slot2 );

fd_hash_t const *
fd_tower_blocks_canonical_block_id( fd_tower_t * tower,
                                    ulong        slot );

/* fd_tower_from_vote_acc deserializes the vote account into a votes
   deque and extracts the root.  Assumes votes is a valid joined deque
   and currently empty.  On return *root is the tower root slot, or
   ULONG_MAX if the vote account has no root. */

void
fd_tower_from_vote_acc( fd_tower_vote_t * votes,
                        ulong           * root,
                        uchar const     * vote_acc );

/* fd_tower_with_lat_from_vote_acc deserializes the vote account into
   tower, including slot latency (when available) for tower votes.
   Assumes tower points to a static array of length FD_TOWER_VOTE_MAX.

   Returns the number of copied elements. */

ulong
fd_tower_with_lat_from_vote_acc( fd_vote_acc_vote_t tower[ static FD_TOWER_VOTE_MAX ],
                                 uchar const *      vote_acc );

/* fd_tower_to_vote_txn writes tower into a fd_tower_sync_t vote
   instruction and serializes it into a Solana transaction.  Assumes
   tower is a valid local join. */

void
fd_tower_to_vote_txn( fd_tower_t    const * tower,
                      fd_hash_t     const * bank_hash,
                      fd_hash_t     const * block_id,
                      fd_hash_t     const * recent_blockhash,
                      fd_pubkey_t   const * validator_identity,
                      fd_pubkey_t   const * vote_authority,
                      fd_pubkey_t   const * vote_account,
                      fd_txn_p_t          * vote_txn );

/* fd_tower_verify checks tower is in a valid state. Valid iff:
   - cnt < FD_TOWER_VOTE_MAX
   - vote slots and confirmation counts in the tower are monotonically
     increasing */

int
fd_tower_verify( fd_tower_t const * tower );

/* fd_tower_to_cstr pretty-prints tower as a formatted table to the
   buffer cstr.  Assumes cstr is a buffer of at least FD_TOWER_CSTR_MIN
   capacity.

   Sample output:

        slot | confirmation count
   --------- | ------------------
   279803931 | 1
   279803930 | 2
   ...
   279803901 | 31
   279803900 | root
*/

char *
fd_tower_to_cstr( fd_tower_t const * tower,
                  char *             cstr );

/* fd_tower_lockos API.  Lockout intervals are stored inline in the
   tower (lck_pool and lck_map). */

void
fd_tower_lockos_insert( fd_tower_t *      tower,
                        ulong             slot,
                        fd_hash_t const * vote_acc,
                        fd_tower_vote_t * votes );

void
fd_tower_lockos_remove( fd_tower_t * tower,
                        ulong        slot );

#endif /* HEADER_fd_src_choreo_tower_fd_tower_h */
