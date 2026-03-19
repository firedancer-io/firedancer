#ifndef HEADER_fd_src_choreo_votes_fd_votes_h
#define HEADER_fd_src_choreo_votes_fd_votes_h

/* fd_votes handles votes, specifically vote transactions, from all
   sources including gossip, TPU and replay.

   Solana has two notions of a vote: vote _transactions_ and vote
   _accounts_.  Vote transactions are updates to vote accounts.  Vote
   transactions are "across forks": a vote transaction observed via
   gossip or TPU is not tied to any particular fork and can be counted
   globally.  Vote transactions are also sourced from replay: when a
   vote txn packed in a block is successfully executed, votes processes
   it.  In this case, the vote txn is sourced from the specific fork the
   block is on, but this is not inherently significant to vote txns
   generally or fd_votes.  Vote accounts, on the other hand, are "per
   fork": each fork has its own copy of the vote account state, which is
   the last successfully executed vote transaction on that fork (in
   addition to other metadata).

   Solana reaches consensus via replay, but can "forward confirm" slots
   ahead of the replay tip by listening to vote txns from gossip or TPU.
   The larger max_live_slots (specified in configuration toml), the
   further ahead slots can be cluster confirmed before they are
   replayed.

   What's the difference between fd_ghost and fd_votes?

   The reason both fd_ghost and fd_votes exist even though they appear
   to do the same thing ie. counting votes is because of the
   aforementioned distinction between the two kinds of votes (vote txns
   vs. vote accs).

   At a high-level, fd_ghost "counts" vote accounts vs. fd_votes
   "counts" vote transactions.  Everything in fd_ghost is dependent on
   the vote account's state after vote transactions have been
   successfully executed.  So ghost can only count a vote for a block
   after a _descendant_ of that block has been replayed (meaning the
   vote txns packed into that block have been executed).

   On the other hand, fd_votes counts vote transactions even if the
   block they are packed in has not been replayed yet.  Specifically,
   txns that come from gossip and TPU do not have the same requirement
   that the block has been replayed.  This is important, because block
   transmission is unreliable, and votes provides a fallback mechanism
   for detecting votes for blocks we don't have. fd_votes still ingests
   replay votes as well, so it is guaranteed to be a superset of the
   votes tracked by fd_ghost, though note this assumption is contingent
   on feature "Deprecate legacy vote instructions" because votes only
   counts TowerSync ixs and ignores any other deprecated vote
   instructions.

   There are also differences in how votes are counted between the two.
   In fd_ghost, we use the GHOST rule to recursively sum the stake of
   the subtree (a slot and all its descendants).  The LMD rule counts a
   validator's stake to at most one fork.  When the validator switches
   forks, their stake is subtracted from the old fork and added to the
   new fork.  The tree is then traversed as part of fork choice to find
   the best leaf ("head").  ghost bases fork choice purely on replay
   votes, but marks forks valid or invalid with gossip votes.

   In fd_votes, we count votes towards only the block itself, and not
   its ancestors.  Also a validator's stake can be counted towards
   multiple forks at the same time if they vote on a fork then switch to
   a different one, unlike ghost.  votes uses both replay and gossip
   votes when counting stake.

   What's the difference between fd_hfork and fd_votes?

   Both operate on vote transactions (not vote accounts), but have very
   different purposes and accounting methods.

   fd_hfork detects hard forks that result from runtime execution
   differences.  These manifest as different bank hashes for a given
   block id, meaning validators agreed on which block to process but
   arrived at different ledger states after executing it.  This
   indicates a consensus bug (e.g. Firedancer and Agave disagree on the
   result of executing transactions in a block).

   fd_votes detects different block ids for a given slot, which
   indicates equivocation by a leader: the leader produced multiple
   different blocks for the same slot.  This is a different problem
   entirely- it is about leader misbehavior rather than execution
   divergence.

   A note on slots and block ids: vote transactions only contain the
   block_id of the last vote slot (and do not specify what block_ids
   previous vote slots correspond to.  Agave assumes if the hash of the
   last vote slot matches, all the previous slots in the tower match as
   well.  Agave uses bank hashes instead of block_ids (the relevant code
   predates block_ids) and maps slots to bank hashes during replay.

   As a result, there can be multiple block ids for a given slot.  votes
   tracks the block_id for each slot using fd_tower_block, and also
   "duplicate confirmation".  If votes observes a duplicate confirmation
   for a different block_id than the one it has for a given slot, it
   updates the block_id for that slot to the duplicate confirmed one. */

/* FD_VOTES_PARANOID:  Define this to non-zero at compile time to turn
   on additional runtime integrity checks. */

#include "../fd_choreo_base.h"
#include "../tower/fd_tower_voters.h"
#include "../tower/fd_tower_stakes.h"

#ifndef FD_VOTES_PARANOID
#define FD_VOTES_PARANOID 1
#endif

#define SET_NAME slot_vtrs
#include "../../util/tmpl/fd_set_dynamic.c"

struct fd_votes_blk {
  fd_hash_t block_id; /* blk_map key */
  ulong     next;     /* pool next */
  struct {
    ulong prev;
    ulong next;
  } map;
  struct {
    ulong prev;
    ulong next;
  } dlist;
  ulong slot;
  ulong stake;
  uchar flags;
};
typedef struct fd_votes_blk fd_votes_blk_t;

struct fd_votes;
typedef struct fd_votes fd_votes_t;

FD_PROTOTYPES_BEGIN

/* fd_votes_{align,footprint} return the required alignment and
   footprint of a memory region suitable for use as a votes.  align
   returns fd_votes_ALIGN.  footprint returns fd_votes_FOOTPRINT. */

FD_FN_CONST ulong
fd_votes_align( void );

ulong
fd_votes_footprint( ulong slot_max,
                    ulong vtr_max );

/* fd_votes_new formats an unused memory region for use as a votes.  mem
   is a non-NULL pointer to this region in the local address space with
   the required footprint and alignment. */

void *
fd_votes_new( void * shmem,
              ulong  slot_max,
              ulong  vtr_max,
              ulong  seed );

/* fd_votes_join joins the caller to the votes.  votes points to the
   first byte of the memory region backing the votes in the caller's
   address space.

   Returns a pointer in the local address space to votes on success. */

fd_votes_t *
fd_votes_join( void * votes );

/* fd_votes_leave leaves a current local join.  Returns a pointer to the
   underlying shared memory region on success and NULL on failure (logs
   details).  Reasons for failure include votes is NULL. */

void *
fd_votes_leave( fd_votes_t const * votes );

/* fd_votes_delete unformats a memory region used as a votes.  Assumes
   only the local process is joined to the region.  Returns a pointer to
   the underlying shared memory region or NULL if used obviously in
   error (e.g. votes is obviously not a votes ...  logs details).  The
   ownership of the memory region is transferred to the caller. */

void *
fd_votes_delete( void * votes );

/* fd_votes_query returns a pointer to the votes block entry for the
   given block_id, or NULL if not found. */

fd_votes_blk_t *
fd_votes_query( fd_votes_t *      votes,
                fd_hash_t const * block_id );

/* fd_votes_count_vote counts id's stake towards the voted slot.
   Returns a pointer to the votes block entry after counting, or NULL
   if the vote was not counted.  The caller may inspect blk->stake and
   blk->flags directly.  Flag management is the caller's responsibility
   (use fd_uchar_extract_bit / fd_uchar_set_bit on blk->flags). */

fd_votes_blk_t *
fd_votes_count_vote( fd_votes_t *        votes,
                     fd_pubkey_t const * vote_acc,
                     ulong               slot,
                     fd_hash_t const *   block_id );

/* fd_votes_update_voters updates the set of voters tracked by votes.
   Should be called on each epoch boundary when the stake-weighted voter
   set changes.  Voters not in tower_voters are removed.  New voters are
   added and assigned bit positions in the per-slot vtrs bitset.
   Existing voters keep their old bit positions.  All existing slot vtrs
   are intersected with the kept set to clear removed voters' bits.
   Stake is set from tower_stakes for each voter.  We intentionally do
   NOT update stakes on existing vote counts to match Agave behavior. */

void
fd_votes_update_voters( fd_votes_t *              votes,
                        fd_tower_voters_t const * tower_voters,
                        fd_tower_stakes_t *       tower_stakes,
                        ulong                     root_slot );

/* fd_votes_publish publishes root as the new votes root slot, removing
   all blocks with slot numbers < the new votes root slot.  Some slots
   on minority forks that were pruned but >= the new root may remain but
   they will eventually be pruned as well as the root advances. */

void
fd_votes_publish( fd_votes_t * votes,
                  ulong        root );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_choreo_votes_fd_votes_h */
