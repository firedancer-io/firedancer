#ifndef HEADER_fd_src_choreo_votor_ag_epoch_info_h
#define HEADER_fd_src_choreo_votor_ag_epoch_info_h

#include "ag_votor_base.h"
#include "ag_bls.h"
#include "../../flamenco/stakes/fd_stake_weight.h"

struct ag_validator_info {
  ulong         id;
  ulong         stake;
  ag_id_key_t   id_key;
  ag_vote_key_t vote_key;
  ag_bls_pub_t  bls_key;
};
typedef struct ag_validator_info ag_validator_info_t;

struct ag_epoch_info {
  ulong               validator_cnt;
  ulong               total_stake;
  ag_validator_info_t validators[ AG_VAT_MAX ]; /* indexed by rank; validator_cnt live */
  ag_bls_pub_native_t pubkeys[ AG_VAT_MAX ]; /* validated host-native keys, indexed by rank */
  ag_bls_pub_cache_t  pubkey_cache; /* native block and total sums; derived once per epoch */
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
                         ulong                   rank ) {
  FD_TEST( rank<self->validator_cnt );
  return ag_epoch_info_validators( self ) + rank;
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

ag_epoch_info_t *
ag_epoch_info_rank( ag_epoch_info_t              * epoch_info_mem,
                    fd_vote_stake_weight_t const * stakes,
                    ulong                          stake_cnt );

FD_PROTOTYPES_END

#endif
