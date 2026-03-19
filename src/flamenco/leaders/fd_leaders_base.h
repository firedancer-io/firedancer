#ifndef HEADER_fd_src_flamenco_leaders_fd_leaders_base_h
#define HEADER_fd_src_flamenco_leaders_fd_leaders_base_h

#include "../types/fd_types_custom.h"
#include "../features/fd_features.h"

#define MAX_SLOTS_PER_EPOCH          432000UL
#define MAX_STAKED_LEADERS           108000UL
#define MAX_COMPRESSED_STAKE_WEIGHTS (MAX_STAKED_LEADERS*2UL+1UL)

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
  ulong                  staked_cnt;        /* Number of compressed stake weight entries (leaders + dummies) */
  ulong                  start_slot;        /* Start slot of the epoch */
  ulong                  slot_cnt;          /* Number of slots in the epoch */
  ulong                  excluded_stake;    /* Total stake that is excluded from leader selection */
  ulong                  vote_keyed_lsched; /* Whether vote account keyed leader schedule is active */
  ulong                  id_staked_cnt;     /* Number of identity-deduped stake entries for turbine */
  fd_epoch_schedule_t    epoch_schedule;    /* Epoch schedule */
  fd_features_t          features;          /* Feature activation slots */
  fd_vote_stake_weight_t weights[];         /* Flexible array member: first staked_cnt compressed entries,
                                               then id_staked_cnt fd_stake_weight_t entries (accessed via
                                               fd_epoch_info_msg_id_stakes) */
};
typedef struct fd_epoch_info_msg_t fd_epoch_info_msg_t;

/* Leader schedule calculation is done based on a weighted sample of
   a sorted list of stake weights (see fd_leaders and fd_wsample).
   Because there are many consumers of the stake weights from the Replay
   tile, a naive approach will make the link size very large:
   (72 bytes per weight * 40M vote accounts) = ~2.9GB.

   In order to do something more clever consider some protocol/message
   invariants:
   1. the set of stake weights that is passed around is sorted based on
      stake and then tiebroken on lexicographic order of the vote key.
   2. There are 108,000 leaders per epoch in the worst case (432000
      slots per epoch / 4 leaders per slot).
   3. Stake weighted sample is done to select leaders.

   From this we know that there can be up to 108k leaders from a much
   larger set of stake weights.  All other pubkeys can be ignored since
   we know that they won't be selected.  In the worst case there are
   40M - 108,000 vote accounts that won't be selected.  In the weighted
   sample, two adjacent, non-selected pubkeys can be combined into one
   aggregated stake weight.  If we take this idea to its limit we can
   combine all adjacent non-selected pubkeys into aggregated weights.
   The worst case number of these non-selected pubkeys is 108001 (if
   the non-selected keys are perfectly interleaved with the selected
   keys with the first and last key also being non-selected).  In
   practice, this bound is probably tighter because the higher staked
   nodes are almost guaranteed to be selected.

   Regardless, this allows us to compress the set of stake weights into
   a much smaller, bounded set.  The worst case number of compressed
   stake weights is 108000 + 108001 = 216001 keys.  The aggregated
   weights will be stored as FD_DUMMY_ACCOUNT.  The consumer is
   responsible for post-processing the aggregated weights to make sure
   they aren't inserted into any downstream data structures. */

#define FD_EPOCH_INFO_MSG_HEADER_SZ (sizeof(fd_epoch_info_msg_t))
#define FD_EPOCH_INFO_MAX_MSG_SZ    (FD_EPOCH_INFO_MSG_HEADER_SZ + MAX_COMPRESSED_STAKE_WEIGHTS * sizeof(fd_vote_stake_weight_t) + MAX_STAKED_LEADERS * sizeof(fd_stake_weight_t))
#define FD_EPOCH_OUT_MTU            FD_EPOCH_INFO_MAX_MSG_SZ

static inline ulong fd_epoch_info_msg_sz( ulong vote_cnt, ulong id_cnt ) {
  return FD_EPOCH_INFO_MSG_HEADER_SZ + vote_cnt * sizeof(fd_vote_stake_weight_t) + id_cnt * sizeof(fd_stake_weight_t);
}

/* Returns a pointer to the identity-deduped stakes that are serialized
   after the compressed vote stake weights in the epoch info message. */
static inline fd_stake_weight_t *
fd_epoch_info_msg_id_stakes( fd_epoch_info_msg_t * msg ) {
  return (fd_stake_weight_t *)( msg->weights + msg->staked_cnt );
}

static inline fd_stake_weight_t const *
fd_epoch_info_msg_id_stakes_const( fd_epoch_info_msg_t const * msg ) {
  return (fd_stake_weight_t const *)( msg->weights + msg->staked_cnt );
}

#endif /* HEADER_fd_src_flamenco_leaders_fd_leaders_base_h */
