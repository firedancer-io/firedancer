#ifndef HEADER_fd_src_flamenco_leaders_fd_leaders_base_h
#define HEADER_fd_src_flamenco_leaders_fd_leaders_base_h

#include "../fd_flamenco_base.h"
#include "../types/fd_types.h"

#define MAX_SLOTS_PER_EPOCH   432000UL
#define MAX_PUB_CNT           50000UL
#define MAX_STAKED_LEADERS    40200UL

/* Follows message structure in fd_stake_ci_stake_msg_init */
struct fd_stake_weight_msg_t {
  ulong             epoch;          /* Epoch for which the stake weights are valid */
  ulong             staked_cnt;     /* Number of staked nodes */
  ulong             start_slot;     /* Start slot of the epoch */
  ulong             slot_cnt;       /* Number of slots in the epoch */
  ulong             excluded_stake; /* Total stake that is excluded from leader selection */
  fd_stake_weight_t weights[];      /* Stake weights for each staked node */
};
typedef struct fd_stake_weight_msg_t fd_stake_weight_msg_t;

#endif /* HEADER_fd_src_flamenco_leaders_fd_leaders_base_h */
