#ifndef HEADER_fd_src_discof_tower_fd_hard_fork_detector_h
#define HEADER_fd_src_discof_tower_fd_hard_fork_detector_h

#include "../../flamenco/leaders/fd_leaders_base.h"

/* The Solana chain occasionally forks for what we will call soft and
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
   exceed 52% of the total stake weight, or it is from our own
   validator identity, we check if our vote is different, and
   potentially raise a warning or error.

   The last 4096 votes for each vote account are kept in a ring buffer
   and replaced as new votes come in, to prevent unbounded memory usage.
   This makes the structure somewhat heuristic: it might be that if some
   nodes are very far ahead, and some behind, we might evict old votes
   for those ahead and never see a fork exceed 52% in our window.  This
   is unlikely to happen in practice, and even if it does, it only
   means we might miss detecting a hard fork, which is not catastrophic.
   The default behavior anyway should be to continue running on the
   forked chain. */

#define FD_HARD_FORK_DETECTOR_ALIGN (128UL)

#define FD_HARD_FORK_DETECTOR_MAGIC (0xF17EDA2CE58F0C80) /* FIREDANCE HFORK V0 */

struct fd_hard_fork_detector_private;
typedef struct fd_hard_fork_detector_private fd_hard_fork_detector_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong
fd_hard_fork_detector_align( void );

FD_FN_CONST ulong
fd_hard_fork_detector_footprint( ulong max_live_slots,
                                 ulong max_vote_accounts );

void *
fd_hard_fork_detector_new( void *        shmem,
                           ulong         max_live_slots,
                           ulong         max_vote_accounts,
                           int           fatal,
                           ulong         seed );

fd_hard_fork_detector_t *
fd_hard_fork_detector_join( void * shtc );

/* Update the stake weights used by the fork detector.  Technically,
   there can be many sets of stake weights active at once, around the
   epoch boundary.  For simplicity, we ignore this and just always use
   the latest provided stake weights when registering votes.  This may
   have minor discrepancies around epoch boundaries, but is unlikely to
   cause problems in practice.  There is not really any way to solve
   this: we don't know stake weights for banks we haven't replayed, and
   if there's a hard fork at the boundary, we are not replaying the side
   we need to, to determine what 52% would be. */

void
fd_hard_fork_detector_stakes( fd_hard_fork_detector_t *     detector,
                              fd_stake_weight_msg_t const * epoch_stakes );

/* Update the block detector with a newly observed vote.  A vote is for
   a block hash, with a block ID, from a certain vote account.  Updates
   are a time ordered stream, containing votes from both gossip and
   replayed blocks.  Any vote which has a valid signature is valid, and
   should be provided to the update time series, even if, for example,
   it's from a block which was not valid or got skipped, or the vote
   otherwise looks malformed.

   If incorporating the vote would cause a hard fork to be detected, and
   if the hard fork detector was created with fatal=0, this simply logs
   a warning and returns, and the validator will continue running now on
   the forked chain.  This is the preferred mode for production, as it
   makes sense from a consensus perspective to continue running in case
   the other nodes switch to our fork.

   Otherwise, if the hard fork detector was created with fatal!=0, this
   will log a critical error and abort the process.  This mode is useful
   for development, testing, and debugging purposes to make sure we can
   isolate the failure to the specific time it occurs. */

void
fd_hard_fork_detector_vote( fd_hard_fork_detector_t * detector,
                            uchar const *             vote_account,
                            uchar const *             block_id,
                            uchar const *             block_hash );

/* Update the block detector, telling it that this validator produced
   a result for a given block ID.  The slot is not used for any logical
   or consensus purpose, but is included in the log messages to help
   debugging.

   If the block_hash is NULL, this indicates the block was marked dead
   during replay and we did not think it was valid. */

void
fd_hard_fork_detector_block( fd_hard_fork_detector_t * detector,
                             ulong                     slot,
                             uchar const *             block_id,
                             uchar const *             block_hash );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_tower_fd_hard_fork_detector_h */
