#ifndef HEADER_fd_src_flamenco_leaders_fd_leaders_base_h
#define HEADER_fd_src_flamenco_leaders_fd_leaders_base_h

#include "../types/fd_types_custom.h"
#include "../features/fd_features.h"

#define MAX_SLOTS_PER_EPOCH   432000UL
#define MAX_PUB_CNT           50000UL
#define MAX_STAKED_LEADERS    40200UL

/* Follows message structure in fd_stake_ci_stake_msg_init.
   Frankendancer only */
struct fd_stake_weight_msg_t {
  ulong                  epoch;          /* Epoch for which the stake weights are valid */
  ulong                  staked_cnt;     /* Number of staked nodes */
  ulong                  start_slot;     /* Start slot of the epoch */
  ulong                  slot_cnt;       /* Number of slots in the epoch */
  ulong                  excluded_stake; /* Total stake that is excluded from leader selection */
  fd_vote_stake_weight_t weights[]; /* Stake weights for each staked node */
};
typedef struct fd_stake_weight_msg_t fd_stake_weight_msg_t;

#define FD_STAKE_CI_STAKE_MSG_HEADER_SZ (sizeof(fd_stake_weight_msg_t))
#define FD_STAKE_CI_STAKE_MSG_RECORD_SZ (sizeof(fd_vote_stake_weight_t))
#define FD_STAKE_CI_STAKE_MSG_SZ (FD_STAKE_CI_STAKE_MSG_HEADER_SZ + MAX_STAKED_LEADERS * FD_STAKE_CI_STAKE_MSG_RECORD_SZ)

#define FD_STAKE_OUT_MTU FD_STAKE_CI_STAKE_MSG_SZ

static inline ulong fd_stake_weight_msg_sz( ulong cnt ) {
  return FD_STAKE_CI_STAKE_MSG_HEADER_SZ + cnt * FD_STAKE_CI_STAKE_MSG_RECORD_SZ;
}

/* Firedancer only */
struct fd_epoch_info_msg_t {
  ulong                  epoch;             /* Epoch for which the info is valid */
  ulong                  staked_cnt;        /* Number of staked nodes */
  ulong                  start_slot;        /* Start slot of the epoch */
  ulong                  slot_cnt;          /* Number of slots in the epoch */
  ulong                  excluded_stake;    /* Total stake that is excluded from leader selection */
  fd_features_t          features;          /* Feature activation slots */
  fd_vote_stake_weight_t weights[];         /* Flexible array member (must be last) */
};
typedef struct fd_epoch_info_msg_t fd_epoch_info_msg_t;

#define FD_EPOCH_INFO_MSG_HEADER_SZ (sizeof(fd_epoch_info_msg_t))
#define FD_EPOCH_INFO_MAX_MSG_SZ    (FD_EPOCH_INFO_MSG_HEADER_SZ + MAX_STAKED_LEADERS * sizeof(fd_vote_stake_weight_t))
#define FD_EPOCH_OUT_MTU            FD_EPOCH_INFO_MAX_MSG_SZ

static inline ulong fd_epoch_info_msg_sz( ulong cnt ) {
  return FD_EPOCH_INFO_MSG_HEADER_SZ + ( cnt * sizeof(fd_vote_stake_weight_t) );
}

#endif /* HEADER_fd_src_flamenco_leaders_fd_leaders_base_h */
