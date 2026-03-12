#ifndef HEADER_fd_src_flamenco_leaders_fd_leaders_base_h
#define HEADER_fd_src_flamenco_leaders_fd_leaders_base_h

#include "../types/fd_types_custom.h"
#include "../features/fd_features.h"

#define MAX_SLOTS_PER_EPOCH          432000UL
#define MAX_STAKED_LEADERS           108000UL
#define MAX_COMPRESSED_STAKE_WEIGHTS (MAX_STAKED_LEADERS*2UL)

/* Follows message structure in fd_stake_ci_stake_msg_init.
   Frankendancer only */
struct fd_stake_weight_msg_t {
  ulong             epoch;          /* Epoch for which the stake weights are valid */
  ulong             staked_cnt;     /* Number of staked nodes */
  ulong             start_slot;     /* Start slot of the epoch */
  ulong             slot_cnt;       /* Number of slots in the epoch */
  ulong             excluded_stake; /* Total stake that is excluded from leader selection */
  ulong             vote_keyed_lsched; /* 1=use vote-keyed leader schedule, 0=use old leader schedule */
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
  ulong                  vote_keyed_lsched; /* Whether vote account keyed leader schedule is active */
  fd_epoch_schedule_t    epoch_schedule;    /* Epoch schedule */
  fd_features_t          features;          /* Feature activation slots */
  fd_vote_stake_weight_t weights[];         /* Flexible array member (must be last) */
};
typedef struct fd_epoch_info_msg_t fd_epoch_info_msg_t;

/* There can be up to 432000/4 leaders per epoch, but there can be up to
   ~40,000,000 staked vote accounts.  In order to find a tighter bound
   on the number of stake weights, we can compress the effective set of
   stake weights into a smaller set: all of the accounts that are not
   chosen to be leaders can be compressed into buckets of dummy leaders.
   Each of these buckets will aggregate all adjacent non-chosen accounts
   (see fd_leaders and fd_wsample).  This means that to generate an
   equivalent, valid leader schedule, we need to store all of the
   accounts that are chosen in addition to all of the dummy buckets.  In
   the worst case we will have MAX_LEADERS_IN_EPOCH dummy bucket.
   TODO: Make this explanation more clear. */

#define FD_EPOCH_INFO_MSG_HEADER_SZ (sizeof(fd_epoch_info_msg_t))
#define FD_EPOCH_INFO_MAX_MSG_SZ    (FD_EPOCH_INFO_MSG_HEADER_SZ + MAX_COMPRESSED_STAKE_WEIGHTS * sizeof(fd_vote_stake_weight_t))
#define FD_EPOCH_OUT_MTU            FD_EPOCH_INFO_MAX_MSG_SZ

static inline ulong fd_epoch_info_msg_sz( ulong cnt ) {
  return FD_EPOCH_INFO_MSG_HEADER_SZ + ( cnt * sizeof(fd_vote_stake_weight_t) );
}

#endif /* HEADER_fd_src_flamenco_leaders_fd_leaders_base_h */
