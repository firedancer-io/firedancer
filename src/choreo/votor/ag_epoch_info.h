#ifndef HEADER_fd_src_choreo_votor_ag_epoch_info_h
#define HEADER_fd_src_choreo_votor_ag_epoch_info_h

#include "ag_votor_base.h"
#include "ag_bls.h"
#include "../../flamenco/stakes/fd_stake_weight.h"

struct ag_validator_info {
  ulong        id;
  ulong        stake;
  fd_pubkey_t  pubkey;
  ag_bls_pub_t voting_pubkey;
};
typedef struct ag_validator_info ag_validator_info_t;

struct ag_epoch_info {
  ulong               validator_cnt;
  ulong               total_stake;
  ag_validator_info_t validators[ AG_VAT_MAX ]; /* indexed by rank; validator_cnt live */
  ag_bls_pub_t        pubkeys   [ AG_VAT_MAX ]; /* same validators list, pubkeys continguous for easy cert verification. TODO keep/remove? */
};
typedef struct ag_epoch_info ag_epoch_info_t;

FD_PROTOTYPES_BEGIN

void
ag_epoch_info( ag_epoch_info_t *           self,
               ag_validator_info_t const * validators,
               ulong                       validator_cnt );

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

FD_FN_PURE int ag_epoch_info_is_weakest_quorum( ag_epoch_info_t const * self, ulong stake );
FD_FN_PURE int ag_epoch_info_is_weak_quorum   ( ag_epoch_info_t const * self, ulong stake );
FD_FN_PURE int ag_epoch_info_is_quorum        ( ag_epoch_info_t const * self, ulong stake );
FD_FN_PURE int ag_epoch_info_is_strong_quorum ( ag_epoch_info_t const * self, ulong stake );

/* ag_epoch_info_init formats mem as an ag_epoch_info_t holding the
   canonical Alpenglow validator ranking derived from the epoch info
   msg's staked VAT voters.  init drops entries with a missing or
   undecodable compressed BLS voting pubkey, drop ALL copies of a
   duplicated BLS key or identity pubkey, then order survivors by stake,
   tie-broken by compressed BLS pubkey asc.

   See Agave BLSPubkeyToRankMap https://github.com/anza-xyz/agave/blob/19e021d626df202b0ec11b4b39c76c3cfe9b90e4/runtime/src/epoch_stakes.rs#L87

   Zero-stake, vote account balance, and top-2000 VAT admission are
   already enforced by the producer (fd_stakes_activate_epoch) and are
   not re-checked here.

   Returns mem on success.  Returns NULL, leaving mem untouched, if mem
   is no validator survives the filters. */

ag_epoch_info_t *
ag_epoch_info_init( ag_epoch_info_t              * ei_mem,
                    fd_vote_stake_weight_t const * stakes,
                    ulong                          stake_cnt );

FD_PROTOTYPES_END

#endif
