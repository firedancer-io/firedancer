#ifndef HEADER_fd_src_choreo_votor_ag_epoch_info_h
#define HEADER_fd_src_choreo_votor_ag_epoch_info_h

#include "ag_votor_base.h"
#include "ag_aggsig.h"

struct ag_validator_info {
  ulong          id;
  ulong          stake;
  fd_pubkey_t    pubkey;
  ag_aggsig_pk_t voting_pubkey;
};
typedef struct ag_validator_info ag_validator_info_t;

struct ag_epoch_info {
  ulong               validator_cnt;
  ulong               total_stake;
  ag_validator_info_t validators[ AG_VAT_MAX ]; /* indexed by rank; validator_cnt live */
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

FD_PROTOTYPES_END

#endif
