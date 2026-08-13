#ifndef HEADER_fd_src_alpenglow_consensus_ag_epoch_info_h
#define HEADER_fd_src_alpenglow_consensus_ag_epoch_info_h

#include "../ag_alpenglow_base.h"
#include "../crypto/ag_aggsig.h"
#include "../../flamenco/stakes/fd_stake_weight.h" /* fd_vote_stake_weight_t */

struct ag_validator_info {
  ulong          id;
  ulong          stake;
  fd_pubkey_t    pubkey;
  ag_aggsig_pk_t voting_pubkey;
};
typedef struct ag_validator_info ag_validator_info_t;

/* ag_epoch_info is the epoch's validator set, identical across all
   validators: a flat array of ag_validator_info_t indexed by rank
   (validators[i].id==i), plus the stake total derived from it.  The array
   is sized for the protocol cap, so the footprint is the same for every
   epoch and only the leading validator_cnt entries are live. */

struct ag_epoch_info {
  ulong               validator_cnt;
  ulong               total_stake;
  ag_validator_info_t validators[ AG_VAT_MAX ]; /* indexed by rank; validator_cnt live */
};
typedef struct ag_epoch_info ag_epoch_info_t;

FD_PROTOTYPES_BEGIN

/* ag_epoch_info_init fills self in place from a rank-ordered validator
   array (validators[i].id==i must hold) and derives total_stake from it.

   There is no align / footprint / new / join lifecycle: ag_epoch_info_t
   is a plain value of fixed size, so a caller declares one, embeds one,
   or carves sizeof(ag_epoch_info_t) out of its own scratch, and hands
   the pointer here.  Nothing about it is shared across processes, so
   there is nothing for a join to translate. */

void
ag_epoch_info_init( ag_epoch_info_t *           self,
                    ag_validator_info_t const * validators,
                    ulong                       validator_cnt );

/* ag_epoch_info_rank: canonical Alpenglow validator ranking from staked
   voters: drop zero-stake / missing / undecodable compressed BLS voting
   pubkeys, order by stake desc, tie-break by compressed BLS pubkey asc;
   rank == position.  Distinct from the leader-schedule stake sort.
   TODO: also drop duplicate BLS / node pubkeys and check proof of
   possession.  bls_pubkeys: 48-byte compressed keys indexed 1:1 with
   stakes.  Writes up to out_max validators into out, returns count. */

ulong
ag_epoch_info_rank( ag_validator_info_t *          out,
                    ulong                          out_max,
                    fd_vote_stake_weight_t const * stakes,
                    ulong                          stake_cnt,
                    uchar const *                  bls_pubkeys );


FD_FN_CONST static inline ag_validator_info_t const *
ag_epoch_info_validators( ag_epoch_info_t const * self ) {
  return self->validators;
}

FD_FN_PURE static inline ag_validator_info_t const *
ag_epoch_info_validator( ag_epoch_info_t const * self,
                         ulong                   id ) {
  FD_TEST( id<self->validator_cnt );
  return ag_epoch_info_validators( self ) + id;
}

FD_FN_PURE static inline ag_validator_info_t const *
ag_epoch_info_leader( ag_epoch_info_t const * self,
                      ulong                   slot ) {
  ulong window    = slot / AG_SLOTS_PER_WINDOW;
  ulong leader_id = window % self->validator_cnt;
  return ag_epoch_info_validator( self, leader_id );
}

FD_FN_PURE static inline ulong
ag_epoch_info_total_stake( ag_epoch_info_t const * self ) { return self->total_stake; }

/* The quorum predicates: is stake at least AG_*_QUORUM_THRESHOLD_NUMER /
   AG_QUORUM_THRESHOLD_DENOM of the epoch's total stake -- 20% / 40% /
   60% / 80%. */

FD_FN_PURE int ag_epoch_info_is_weakest_quorum( ag_epoch_info_t const * self, ulong stake );
FD_FN_PURE int ag_epoch_info_is_weak_quorum   ( ag_epoch_info_t const * self, ulong stake );
FD_FN_PURE int ag_epoch_info_is_quorum        ( ag_epoch_info_t const * self, ulong stake );
FD_FN_PURE int ag_epoch_info_is_strong_quorum ( ag_epoch_info_t const * self, ulong stake );

FD_PROTOTYPES_END

#endif
