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

struct ag_epoch_info {
  ulong validator_cnt;
  ulong total_stake;

};
typedef struct ag_epoch_info ag_epoch_info_t;

struct ag_validator_epoch_info {
  ulong                   own_id;
  ag_epoch_info_t const * epoch;
};
typedef struct ag_validator_epoch_info ag_validator_epoch_info_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong ag_epoch_info_align( void );

FD_FN_CONST ulong ag_epoch_info_footprint( ulong validator_cnt );

void * ag_epoch_info_new( void *                      mem,
                          ag_validator_info_t const * validators,
                          ulong                       validator_cnt );

ag_epoch_info_t * ag_epoch_info_join( void * mem );

/* ag_epoch_info_rank: canonical Alpenglow validator ranking from staked
   voters: drop zero-stake / missing / undecodable compressed BLS voting
   pubkeys, order by stake desc, tie-break by compressed BLS pubkey asc;
   rank == position.  Distinct from the leader-schedule stake sort.
   TODO: Agave also drops duplicate BLS / node pubkeys and checks proof
   of possession.  bls_pubkeys: 48-byte compressed keys indexed 1:1 with
   stakes.  Writes up to out_max validators into out, returns count. */

ulong
ag_epoch_info_rank( ag_validator_info_t *          out,
                    ulong                          out_max,
                    fd_vote_stake_weight_t const * stakes,
                    ulong                          stake_cnt,
                    uchar const *                  bls_pubkeys );


FD_FN_PURE static inline ag_validator_info_t const *
ag_epoch_info_validators( ag_epoch_info_t const * self ) {
  return (ag_validator_info_t const *)(self+1);
}

FD_FN_PURE static inline ag_validator_info_t const *
ag_epoch_info_validator( ag_epoch_info_t const * ei,
                         ulong                   id ) {
  FD_TEST( id<ei->validator_cnt );
  return ag_epoch_info_validators( ei ) + id;
}

FD_FN_PURE static inline ag_aggsig_pk_t const *
ag_epoch_info_voting_pubkeys( ag_epoch_info_t const * ei ) {
  return (ag_aggsig_pk_t const *)( ag_epoch_info_validators( ei ) + ei->validator_cnt );
}

FD_FN_PURE static inline ag_validator_info_t const *
ag_epoch_info_leader( ag_epoch_info_t const * ei,
                      ulong                   slot ) {
  ulong window    = slot / AG_SLOTS_PER_WINDOW;
  ulong leader_id = window % ei->validator_cnt;
  return ag_epoch_info_validator( ei, leader_id );
}

FD_FN_PURE static inline ulong
ag_epoch_info_total_stake( ag_epoch_info_t const * ei ) { return ei->total_stake; }

/* EpochInfo::is_*_quorum -- THRESHOLD.is_met( stake, self.total_stake() )
   with the thresholds from consensus.rs (AG_ALPENGLOW_*_QUORUM_NUMER).
   20% / 40% / 60% / 80%. */

FD_FN_PURE static inline int
ag_epoch_info_is_weakest_quorum( ag_epoch_info_t const * ei,
                                 ulong                   stake ) {
  return ag_alpenglow_fraction_is_met( stake, ei->total_stake, AG_ALPENGLOW_WEAKEST_QUORUM_NUMER, AG_ALPENGLOW_QUORUM_DENOM );
}
FD_FN_PURE static inline int
ag_epoch_info_is_weak_quorum( ag_epoch_info_t const * ei,
                              ulong                   stake ) {
  return ag_alpenglow_fraction_is_met( stake, ei->total_stake, AG_ALPENGLOW_WEAK_QUORUM_NUMER, AG_ALPENGLOW_QUORUM_DENOM );
}
FD_FN_PURE static inline int
ag_epoch_info_is_quorum( ag_epoch_info_t const * ei,
                         ulong                   stake ) {
  return ag_alpenglow_fraction_is_met( stake, ei->total_stake, AG_ALPENGLOW_QUORUM_NUMER, AG_ALPENGLOW_QUORUM_DENOM );
}
FD_FN_PURE static inline int
ag_epoch_info_is_strong_quorum( ag_epoch_info_t const * ei,
                                ulong                   stake ) {
  return ag_alpenglow_fraction_is_met( stake, ei->total_stake, AG_ALPENGLOW_STRONG_QUORUM_NUMER, AG_ALPENGLOW_QUORUM_DENOM );
}

FD_PROTOTYPES_END

#endif
