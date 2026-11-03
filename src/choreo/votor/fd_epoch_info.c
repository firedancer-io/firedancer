#include "fd_epoch_info.h"

FD_FN_CONST static int
fraction_is_met( ulong stake,
                 ulong total,
                 ulong numer,
                 ulong denom ) {
  return (uint128)stake*(uint128)denom >= (uint128)total*(uint128)numer;
}

FD_FN_PURE int
fd_epoch_info_is_weakest_quorum( fd_epoch_info_t const * self, ulong stake ) {
  return fraction_is_met( stake, self->total_stake, FD_VOTOR_WEAKEST_QUORUM_THRESHOLD_NUMER, FD_VOTOR_QUORUM_THRESHOLD_DENOM );
}

FD_FN_PURE int
fd_epoch_info_is_weak_quorum( fd_epoch_info_t const * self, ulong stake ) {
  return fraction_is_met( stake, self->total_stake, FD_VOTOR_WEAK_QUORUM_THRESHOLD_NUMER, FD_VOTOR_QUORUM_THRESHOLD_DENOM );
}

FD_FN_PURE int
fd_epoch_info_is_quorum( fd_epoch_info_t const * self, ulong stake ) {
  return fraction_is_met( stake, self->total_stake, FD_VOTOR_QUORUM_THRESHOLD_NUMER, FD_VOTOR_QUORUM_THRESHOLD_DENOM );
}

FD_FN_PURE int
fd_epoch_info_is_strong_quorum( fd_epoch_info_t const * self, ulong stake ) {
  return fraction_is_met( stake, self->total_stake, FD_VOTOR_STRONG_QUORUM_THRESHOLD_NUMER, FD_VOTOR_QUORUM_THRESHOLD_DENOM );
}
