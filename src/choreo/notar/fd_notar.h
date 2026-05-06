#ifndef HEADER_fd_src_choreo_notar_fd_notar_h
#define HEADER_fd_src_choreo_notar_fd_notar_h

/* fd_notar handles votes, specifically vote transactions, from all
   sources including gossip, TPU and replay.

   Solana has two notions of a vote: vote _transactions_ and vote
   _accounts_.  Vote transactions are updates to vote accounts.  Vote
   transactions are "across forks": a vote transaction observed via
   gossip or TPU is not tied to any particular fork and can be counted
   globally.  Vote transactions are also sourced from replay: when a
   vote txn packed in a block is successfully executed, notar processes
   it.  In this case, the vote txn is sourced from the specific fork the
   block is on, but this is not inherently significant to vote txns
   generally or fd_notar.  Vote accounts, on the other hand, are "per
   fork": each fork has its own copy of the vote account state, which is
   the last successfully executed vote transaction on that fork (in
   addition to other metadata).

   Solana reaches consensus via replay, but can "forward confirm" slots
   ahead of the replay tip by listening to vote txns from gossip or TPU.
   The larger max_live_slots (specified in configuration toml), the
   further ahead slots can be cluster confirmed before they are
   replayed.

   What's the difference between fd_ghost and fd_notar?

   The reason both fd_ghost and fd_notar exist even though they appear
   to do the same thing ie. counting votes is because of the
   aforementioned distinction between the two kinds of votes (vote txns
   vs. vote accs).

   At a high-level, fd_ghost "counts" vote accounts vs. fd_notar
   "counts" vote transactions.  Everything in fd_ghost is dependent on
   the vote account's state after vote transactions have been
   successfully executed.  So ghost can only count a vote for a block
   after a _descendant_ of that block has been replayed (meaning the
   vote txns packed into that block have been executed).

   On the other hand, fd_notar counts vote transactions even if the
   block they are packed in has not been replayed yet.  Specifically,
   txns that come from gossip and TPU do not have the same requirement
   that the block has been replayed.  This is important, because block
   transmission is unreliable, and notar provides a fallback mechanism
   for detecting votes for blocks we don't have. fd_notar still ingests
   replay votes as well, so it is guaranteed to be a superset of the
   votes tracked by fd_ghost, though note this assumption is contingent
   on feature "Deprecate legacy vote instructions" because notar only
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

   In fd_notar, we count votes towards only the block itself, and not
   its ancestors.  Also a validator's stake can be counted towards
   multiple forks at the same time if they vote on a fork then switch to
   a different one, unlike ghost.  notar uses both replay and gossip
   votes when counting stake.

   What's the difference between fd_hfork and fd_notar?

   Both operate on vote transactions (not vote accounts), but have very
   different purposes and accounting methods.

   fd_hfork detects hard forks that result from runtime execution
   differences.  These manifest as different bank hashes for a given
   block id, meaning validators agreed on which block to process but
   arrived at different ledger states after executing it.  This
   indicates a consensus bug (e.g. Firedancer and Agave disagree on the
   result of executing transactions in a block).

   fd_notar detects different block ids for a given slot, which
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

   As a result, there can be multiple block ids for a given slot.  notar
   tracks the block_id for each slot using fd_tower_block, and also
   "duplicate confirmation".  If notar observes a duplicate confirmation
   for a different block_id than the one it has for a given slot, it
   updates the block_id for that slot to the duplicate confirmed one. */

/* FD_NOTAR_PARANOID:  Define this to non-zero at compile time to turn
   on additional runtime integrity checks. */

#include "../fd_choreo_base.h"

#ifndef FD_NOTAR_PARANOID
#define FD_NOTAR_PARANOID 1
#endif

#define SET_NAME slot_vtrs
#include "../../util/tmpl/fd_set_dynamic.c"

struct fd_notar_blk_key {
  ulong     slot;
  fd_hash_t block_id;
};
typedef struct fd_notar_blk_key fd_notar_blk_key_t;

struct fd_notar_blk {
  fd_notar_blk_key_t key;  /* blk_map key: (slot, block_id) */
  ulong              next; /* pool next */
  struct {
    ulong prev;
    ulong next;
  } map;
  struct {
    ulong prev;
    ulong next;
  } dlist;
  ulong stake;
  uchar flags; /* first 4 bits: confirmation levels, last 4 bits: forward confirmation levels */
};
typedef struct fd_notar_blk fd_notar_blk_t;

struct fd_notar;
typedef struct fd_notar fd_notar_t;

FD_PROTOTYPES_BEGIN

/* fd_notar_{align,footprint} return the required alignment and
   footprint of a memory region suitable for use as a notar.  align
   returns fd_notar_ALIGN.  footprint returns fd_notar_FOOTPRINT. */

FD_FN_CONST ulong
fd_notar_align( void );

ulong
fd_notar_footprint( ulong slot_max,
                    ulong vtr_max );

/* fd_notar_new formats an unused memory region for use as a notar.  mem
   is a non-NULL pointer to this region in the local address space with
   the required footprint and alignment. */

void *
fd_notar_new( void * shmem,
              ulong  slot_max,
              ulong  vtr_max,
              ulong  seed );

/* fd_notar_join joins the caller to the notar.  notar points to the
   first byte of the memory region backing the notar in the caller's
   address space.

   Returns a pointer in the local address space to notar on success. */

fd_notar_t *
fd_notar_join( void * notar );

/* fd_notar_leave leaves a current local join.  Returns a pointer to the
   underlying shared memory region on success and NULL on failure (logs
   details).  Reasons for failure include notar is NULL. */

void *
fd_notar_leave( fd_notar_t const * notar );

/* fd_notar_delete unformats a memory region used as a notar.  Assumes
   only the local process is joined to the region.  Returns a pointer to
   the underlying shared memory region or NULL if used obviously in
   error (e.g. notar is obviously not a notar ...  logs details).  The
   ownership of the memory region is transferred to the caller. */

void *
fd_notar_delete( void * notar );

/* fd_notar_query returns a pointer to the notar block entry for the
   given (slot, block_id), or NULL if not found.

   If block_id is NULL, searches all block_ids for the slot and returns
   the one with the highest forward confirmation level (upper nibble of
   flags), or NULL if no forward-confirmed entry exists. */

fd_notar_blk_t *
fd_notar_query( fd_notar_t *      notar,
                ulong             slot,
                fd_hash_t const * block_id );

/* fd_notar_count_vote return codes. */

#define FD_NOTAR_SUCCESS           ( 0) /* vote counted successfully */
#define FD_NOTAR_ERR_VOTE_TOO_NEW  (-1) /* vote_slot >= root + slot_max */
#define FD_NOTAR_ERR_UNKNOWN_VTR   (-2) /* voter not in vtr_map */
#define FD_NOTAR_ERR_ALREADY_VOTED (-3) /* voter already voted for this slot */

/* fd_notar_count_vote counts vote_acc's stake towards the voted
   (slot, block_id).  Assumes the notar root has already been
   initialized via fd_notar_publish.  Returns FD_NOTAR_SUCCESS on
   success, or a negative FD_NOTAR_ERR_* code if the vote was not
   counted. */

int
fd_notar_count_vote( fd_notar_t *        notar,
                     fd_pubkey_t const * vote_acc,
                     ulong               slot,
                     fd_hash_t const *   block_id );

/* fd_notar_update_voters updates the set of voters tracked by notar.
   Should be called on each epoch boundary when the stake-weighted voter
   set changes.  Voters not in vote_accs[0..cnt) are removed.  New
   voters are added and assigned bit positions in the per-slot vtrs
   bitset.  Existing voters keep their old bit positions.  All existing
   slot vtrs are intersected with the kept set to clear removed voters'
   bits.  vote_accs and stakes are parallel arrays of length cnt, where
   vote_accs[i] is the vote account address and stakes[i] is the stake
   for that voter. */

void
fd_notar_update_voters( fd_notar_t *        notar,
                        fd_pubkey_t const * vote_accs,
                        ulong const *       stakes,
                        ulong               cnt );

/* fd_notar_publish publishes root as the new notar root slot, removing
   all blocks with slot numbers < the new notar root slot.  Some slots
   on minority forks that were pruned but >= the new root may remain but
   they will eventually be pruned as well as the root advances. */

void
fd_notar_publish( fd_notar_t * notar,
                  ulong        root );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_choreo_notar_fd_notar_h */
