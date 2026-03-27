#ifndef HEADER_fd_src_discof_tower_fd_hfork_h
#define HEADER_fd_src_discof_tower_fd_hfork_h

/* fd_hfork presents an API for detecting hard forks by monitoring
   votes from validators and comparing their bank hashes against ours.

   The Solana chain occasionally forks for what we will call soft and
   hard reasons.

     - Soft forks occur due to network latency and the distributed
       nature of the network.  Different validators may see different
       blocks at different times, and so may disagree on ledger state
       temporarily until the network converges.  This is expected and
       normal.

     - Hard forks occur when validators have a disagreement about the
       rules of the protocol and come to different conclusions about the
       permanent state of the ledger.  This is not expected or normal.

   For Firedancer, it is useful to be able to detect when any hard fork
   has occurred, because it means there was likely some consensus bug
   that caused us to diverge from Agave.  What we check is actually
   broader: it is possible that we disagreed about the result of some
   block, but did not diverge from Agave as the block we disagreed on
   did not become canonical.  We still want to detect this case, as it
   indicates a consensus bug even if we did not ultimately diverge.

   We detect hard forked blocks by monitoring votes from validators, the
   specific criteria is:

    - 52% of stake has voted on a block_id and agreed on a bank_hash
      which is different than the bank_hash we have for that block_id.

    - 52% of stake has voted on a block_id and agreed on a bank_hash
      when we marked the block dead because it failed to execute.

   Interestingly we do not need to handle the case where we thought a
   block succeeded, but the rest of the cluster failed it, because this
   does not cause a hard fork.  We simply switch to the canonical fork
   the rest of the cluster will converge on.  It is not really possible
   to detect this case, because other nodes do not report that the block
   failed, they simply vote somewhere else.

   We are essentially receiving a

     Stream<Either<(VoteAccountPubkey, BlockId, BankHash), EpochStakes>>

   The first variant is a vote from some validator for a certain
   block_id and block_hash.  This could come from either any replayed
   block, or gossip.  It does not matter where it comes from, or even if
   the source is valid (e.g. it could come from a block which gets
   marked dead because it did not validate), all the matters is that the
   vote is validly signed by the vote account.

   Internally, we maintain a Map<BlockId, Map<BankHash, StakeWeight>>.
   Any time we receive a vote, if it causes an entry in this map to
   exceed 52% of the total stake weight, or it is from our own validator
   identity, we check if our vote is different, and potentially raise a
   warning or error.

   The last max_live_slots votes for each vote account are kept in a
   ring buffer and replaced as new votes come in, to prevent unbounded
   memory usage.  This makes the structure somewhat heuristic: it might
   be that if some nodes are very far ahead, and some behind, we might
   evict old votes for those ahead and never see a fork exceed 52% in
   our window.  This is unlikely to happen in practice, and even if it
   does, it only means we might miss detecting a hard fork, which is not
   catastrophic.  The default behavior anyway should be to continue
   running on the forked chain. */

#include "../fd_choreo_base.h"

struct fd_hfork;
typedef struct fd_hfork fd_hfork_t;

FD_PROTOTYPES_BEGIN

/* fd_hfork_{align,footprint} return the required alignment and
   footprint of a memory region suitable for use as a hfork.  align
   returns fd_hfork_ALIGN.  footprint returns fd_hfork_FOOTPRINT. */

FD_FN_CONST ulong
fd_hfork_align( void );

FD_FN_CONST ulong
fd_hfork_footprint( ulong per_vtr_max,
                    ulong vtr_max );

/* fd_hfork_new formats an unused memory region for use as a hfork.  mem
   is a non-NULL pointer to this region in the local address space with
   the required footprint and alignment. */

void *
fd_hfork_new( void * mem,
              ulong  per_vtr_max,
              ulong  vtr_max,
              ulong  seed );

/* fd_hfork_join joins the caller to the hfork.  hfork points to the
   first byte of the memory region backing the hfork in the caller's
   address space.

   Returns a pointer in the local address space to hfork on success. */

fd_hfork_t *
fd_hfork_join( void * hfork );

/* fd_hfork_leave leaves a current local join.  Returns a pointer to the
   underlying shared memory region on success and NULL on failure (logs
   details).  Reasons for failure include hfork is NULL. */

void *
fd_hfork_leave( fd_hfork_t const * hfork );

/* fd_hfork_delete unformats a memory region used as a hfork.  Assumes
   only the local process is joined to the region.  Returns a pointer to
   the underlying shared memory region or NULL if used obviously in
   error (e.g. hfork is obviously not a hfork ...  logs details).  The
   ownership of the memory region is transferred to the caller. */

void *
fd_hfork_delete( void * hfork );

/* fd_hfork_count_vote return codes. */

#define FD_HFORK_SUCCESS_MATCHED   ( 1) /* vote counted, bank hash matches ours */
#define FD_HFORK_SUCCESS           ( 0) /* vote counted successfully */
#define FD_HFORK_ERR_MISMATCHED    (-1) /* vote counted, bank hash does not match ours */
#define FD_HFORK_ERR_UNKNOWN_VTR   (-2) /* voter not in vtr_map */
#define FD_HFORK_ERR_ALREADY_VOTED (-3) /* voter already voted for this block_id */
#define FD_HFORK_ERR_VOTE_TOO_OLD  (-4) /* vote slot not newer than previous */

/* fd_hfork_count_vote updates the hard fork detector with a newly
   observed vote.  Returns FD_HFORK_SUCCESS_MATCHED if the bank hash
   matches ours, FD_HFORK_SUCCESS if counted but not yet compared,
   FD_HFORK_ERR_MISMATCHED if the bank hash does not match ours, or a
   negative FD_HFORK_ERR_* code if the vote was not counted. */

int
fd_hfork_count_vote( fd_hfork_t *        hfork,
                     fd_pubkey_t const * vote_acc,
                     fd_hash_t const *   block_id,
                     fd_hash_t const *   bank_hash,
                     ulong               slot,
                     ulong               stake,
                     ulong               total_stake );

/* fd_hfork_record_our_bank_hash updates the hard fork detector with our
   bank hash (computed on replay) for a given block ID.  If bank_hash is
   NULL, this indicates the block was marked dead during replay and we
   did not think it was valid.  Returns a flag indicating the outcome:
   1 (match), -1 (mismatch), or 0 (not yet compared). */

int
fd_hfork_record_our_bank_hash( fd_hfork_t *      hfork,
                               fd_hash_t const * block_id,
                               fd_hash_t const * bank_hash,
                               ulong             total_stake );

/* fd_hfork_update_voters updates the set of voters tracked by the hard
   fork detector.  Voters not in vote_accs[0..cnt) are removed along
   with all their vote entries.  New voters are added.  This should be
   called on each epoch boundary when the stake-weighted voter set
   changes.  vote_accs is an array of vote account addresses of length
   cnt. */

void
fd_hfork_update_voters( fd_hfork_t *        hfork,
                        fd_pubkey_t const * vote_accs,
                        ulong               cnt );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_tower_fd_hfork_h */
