#ifndef HEADER_fd_src_flamenco_stakes_fd_epoch_stakes_digest_h
#define HEADER_fd_src_flamenco_stakes_fd_epoch_stakes_digest_h

/* fd_epoch_stakes_digest.h computes a canonical digest over one epoch
   stakes set.

   Epoch stakes are the one piece of consensus critical snapshot state
   that cannot be rederived from the accounts a snapshot carries: they
   are a snapshot of what existed at a past epoch boundary.  Committing
   this digest to the bank hash is what lets a loading validator verify
   them (see fd_hashes_apply_epoch_stakes).

   The serialization is:

     sha256(
       LE64 epoch
       LE64 entry_cnt
       for each entry, ascending by vote pubkey:
         vote_pubkey     [32]
         identity_pubkey [32]
         LE64 stake
     )

   The set's total stake is deliberately not bound.  It is by
   construction the sum of the stakes already hashed here -- the runtime
   defines it that way (fd_refresh_vote_accounts accumulates
   total_epoch_stake over the admitted set) and the snapshot load path
   trusts the manifest's field to equal that sum -- so hashing it would
   add nothing while giving the two sides a way to disagree if a
   producer ever computed it over a wider set than the admitted one.

   Only the fields that the leader schedule and stake weighted
   consensus consume are covered.  Commission, BLS keys, epoch credits
   and last vote timestamps are deliberately excluded: the last of
   those is mutated throughout the epoch (fd_vote_stakes_update_state),
   so a digest including it could not be computed once at the boundary
   and then held fixed.

   Entries are sorted by vote pubkey because that is the only total
   order available.  The fd_vote_stakes tiers are hash maps seeded from
   fd_rng_secure at topology setup, so their iteration order differs
   between validator boots on identical data. */

#include "fd_stake_weight.h"
#include "fd_vote_stakes.h"

FD_PROTOTYPES_BEGIN

/* fd_epoch_stakes_digest hashes entry_cnt entries into hash_out.

   entries is sorted in place into canonical order, so the caller may
   gather it in any order.  Duplicate vote pubkeys are a caller bug;
   the digest does not detect them.

   entry_cnt of 0 is valid and produces the digest of the empty set for
   epoch (which is not the zero hash). */

void
fd_epoch_stakes_digest( fd_vote_stake_weight_t * entries,
                        ulong                    entry_cnt,
                        ulong                    epoch,
                        fd_hash_t *              hash_out );

/* fd_epoch_stakes_digest_tier gathers one fd_vote_stakes tier and
   digests it.

   iter_kind is one of FD_VOTE_STAKES_ITER_T_{1,2,3}.  epoch is the
   epoch the tier represents, and is hashed as-is rather than derived,
   so that the caller states which of the three sets this is.

   scratch must hold at least FD_RUNTIME_MAX_VAT_VOTE_ACCOUNTS entries
   and is clobbered.  A tier that is not resident (t-3 at epoch 0)
   digests as the empty set. */

void
fd_epoch_stakes_digest_tier( fd_vote_stakes_t const * vote_stakes,
                             ulong                    fork_id,
                             int                      iter_kind,
                             ulong                    epoch,
                             fd_vote_stake_weight_t * scratch,
                             fd_hash_t *              hash_out );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_flamenco_stakes_fd_epoch_stakes_digest_h */
