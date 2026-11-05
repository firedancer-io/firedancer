#ifndef HEADER_fd_src_choreo_votor_fd_epoch_info_h
#define HEADER_fd_src_choreo_votor_fd_epoch_info_h

#include "fd_votor_base.h"
#include "../../ballet/bls/fd_bls.h"

FD_STATIC_ASSERT( FD_BLS_SET_MAX==FD_VOTOR_VAT_MAX, fd_bls_set_max );

struct fd_validator_info {
  ulong id;
  ulong stake;
  uchar id_key  [ 32 ];                       /* identity public key */
  uchar vote_key[ 32 ];                       /* vote account address */
  uchar bls_key [ FD_BLS_PUB_COMPRESSED_SZ ]; /* compressed BLS public key */
};
typedef struct fd_validator_info fd_validator_info_t;

struct fd_epoch_info {
  ulong               validator_cnt;
  ulong               total_stake;
  fd_validator_info_t validators[ FD_VOTOR_VAT_MAX ]; /* indexed by rank; validator_cnt live */
  fd_bls_pub_t        pubkeys   [ FD_VOTOR_VAT_MAX ]; /* validated keys, indexed by rank */
};
typedef struct fd_epoch_info fd_epoch_info_t;

FD_PROTOTYPES_BEGIN

/* EpochInfo::validators */

FD_FN_CONST static inline fd_validator_info_t const *
fd_epoch_info_validators( fd_epoch_info_t const * self ) {
  return self->validators;
}

/* EpochInfo::validator */

FD_FN_PURE static inline fd_validator_info_t const *
fd_epoch_info_validator( fd_epoch_info_t const * self,
                         ulong                   rank ) {
  FD_TEST( rank<self->validator_cnt );
  return fd_epoch_info_validators( self ) + rank;
}

/* Deserialized fd_epoch_info_validator( self, rank )->bls_key */

FD_FN_PURE static inline fd_bls_pub_t const *
fd_epoch_info_pubkey( fd_epoch_info_t const * self,
                      ulong                   rank ) {
  FD_TEST( rank<self->validator_cnt );
  return self->pubkeys + rank;
}

/* EpochInfo::leader */

FD_FN_PURE static inline fd_validator_info_t const *
fd_epoch_info_leader( fd_epoch_info_t const * self,
                      ulong                   slot ) {
  ulong window    = slot / FD_VOTOR_SLOTS_PER_WINDOW;
  ulong leader_id = window % self->validator_cnt;
  return fd_epoch_info_validator( self, leader_id );
}

/* EpochInfo::total_stake */

FD_FN_PURE static inline ulong
fd_epoch_info_total_stake( fd_epoch_info_t const * self ) { return self->total_stake; }

/* Definition 13. EpochInfo::is_weakest_quorum, is_weak_quorum, is_quorum, is_strong_quorum */

FD_FN_PURE int fd_epoch_info_is_weakest_quorum( fd_epoch_info_t const * self, ulong stake );
FD_FN_PURE int fd_epoch_info_is_weak_quorum   ( fd_epoch_info_t const * self, ulong stake );
FD_FN_PURE int fd_epoch_info_is_quorum        ( fd_epoch_info_t const * self, ulong stake );
FD_FN_PURE int fd_epoch_info_is_strong_quorum ( fd_epoch_info_t const * self, ulong stake );

FD_PROTOTYPES_END

#endif
