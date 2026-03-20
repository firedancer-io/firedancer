#ifndef HEADER_fd_src_flamenco_leaders_fd_leaders_base_h
#define HEADER_fd_src_flamenco_leaders_fd_leaders_base_h

#include "../types/fd_types_custom.h"
#include "../features/fd_features.h"

#define MAX_SHRED_DESTS              40200UL /* 200 * 201 - 1 (exclude self) */
#define MAX_SLOTS_PER_EPOCH          432000UL
#define MAX_STAKED_LEADERS           108000UL
#define MAX_COMPRESSED_STAKE_WEIGHTS (MAX_STAKED_LEADERS*2UL+1UL)

/* Follows message structure in fd_stake_ci_stake_msg_init.
   Frankendancer only */
struct fd_stake_weight_msg_t {
  ulong             epoch;             /* Epoch for which the stake weights are valid */
  ulong             staked_vote_cnt;   /* Number of staked nodes */
  ulong             staked_id_cnt;     /* Number of staked nodes */
  ulong             start_slot;        /* Start slot of the epoch */
  ulong             slot_cnt;          /* Number of slots in the epoch */
  ulong             excluded_id_stake; /* Total stake that is excluded for shred dests */
  ulong             vote_keyed_lsched; /* 1=use vote-keyed leader schedule, 0=use old leader schedule */
};
typedef struct fd_stake_weight_msg_t fd_stake_weight_msg_t;

#define FD_STAKE_CI_STAKE_MSG_HEADER_SZ (sizeof(fd_stake_weight_msg_t))
#define FD_STAKE_CI_STAKE_MSG_RECORD_SZ (sizeof(fd_vote_stake_weight_t))
#define FD_STAKE_CI_ID_WEIGHT_RECORD_SZ (sizeof(fd_stake_weight_t))
#define FD_STAKE_CI_STAKE_MSG_SZ (FD_STAKE_CI_STAKE_MSG_HEADER_SZ + MAX_COMPRESSED_STAKE_WEIGHTS * FD_STAKE_CI_STAKE_MSG_RECORD_SZ + MAX_SHRED_DESTS * sizeof(fd_stake_weight_t))

#define FD_STAKE_OUT_MTU FD_STAKE_CI_STAKE_MSG_SZ

static inline ulong fd_stake_weight_msg_sz( ulong staked_vote_cnt,
                                            ulong staked_id_cnt ) {
  return FD_STAKE_CI_STAKE_MSG_HEADER_SZ + staked_vote_cnt * FD_STAKE_CI_STAKE_MSG_RECORD_SZ + staked_id_cnt * FD_STAKE_CI_ID_WEIGHT_RECORD_SZ;
}

static inline fd_vote_stake_weight_t *
fd_stake_weight_msg_stake_weights( fd_stake_weight_msg_t const * stake_weight_msg ) {
  return (fd_vote_stake_weight_t *)fd_type_pun( (uchar *)stake_weight_msg + FD_STAKE_CI_STAKE_MSG_HEADER_SZ );
}

static inline fd_stake_weight_t *
fd_stake_weight_msg_id_weights( fd_stake_weight_msg_t const * stake_weight_msg ) {
  return (fd_stake_weight_t *)fd_type_pun( (uchar *)stake_weight_msg + FD_STAKE_CI_STAKE_MSG_HEADER_SZ + stake_weight_msg->staked_vote_cnt * sizeof(fd_vote_stake_weight_t) );
}

/* Firedancer only */
struct fd_epoch_info_msg_t {
  ulong                  epoch;             /* Epoch for which the info is valid */
  ulong                  staked_vote_cnt;   /* Number of staked nodes */
  ulong                  staked_id_cnt;     /* Number of staked nodes */
  ulong                  start_slot;        /* Start slot of the epoch */
  ulong                  slot_cnt;          /* Number of slots in the epoch */
  ulong                  excluded_id_stake; /* Total stake that is excluded for shred dests */
  ulong                  vote_keyed_lsched; /* Whether vote account keyed leader schedule is active */
  fd_epoch_schedule_t    epoch_schedule;    /* Epoch schedule */
  fd_features_t          features;          /* Feature activation slots */
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
#define FD_EPOCH_INFO_MAX_MSG_SZ    (FD_EPOCH_INFO_MSG_HEADER_SZ + MAX_COMPRESSED_STAKE_WEIGHTS * sizeof(fd_vote_stake_weight_t) + MAX_SHRED_DESTS * sizeof(fd_stake_weight_t))
#define FD_EPOCH_OUT_MTU            FD_EPOCH_INFO_MAX_MSG_SZ

static inline ulong fd_epoch_info_msg_sz( ulong vote_cnt,
                                          ulong id_weight_cnt ) {
  return FD_EPOCH_INFO_MSG_HEADER_SZ +
         (vote_cnt * sizeof(fd_vote_stake_weight_t)) +
         (id_weight_cnt * sizeof(fd_stake_weight_t));
}

static inline fd_vote_stake_weight_t *
fd_epoch_info_msg_stake_weights( fd_epoch_info_msg_t const * epoch_info_msg ) {
  return (fd_vote_stake_weight_t *)fd_type_pun( (uchar *)epoch_info_msg + FD_EPOCH_INFO_MSG_HEADER_SZ );
}

static inline fd_stake_weight_t *
fd_epoch_info_msg_id_weights( fd_epoch_info_msg_t const * epoch_info_msg ) {
  return (fd_stake_weight_t *)fd_type_pun( (uchar *)epoch_info_msg + FD_EPOCH_INFO_MSG_HEADER_SZ + epoch_info_msg->staked_vote_cnt * sizeof(fd_vote_stake_weight_t) );
}

/* compute_id_weights_from_vote_weights() translates vote-based
   stake weights into (older) identity-based stake weights.

   Before SIMD-0180, the leader schedule was generated starting from
   a list [(id, stake)] where `id` is the validator identity and
   `stake` its aggregated stake, and the same list was used to build
   the Turbine tree.

   After SIMD-0180, the leader schedule is generated by vote
   accounts, i.e. starting from a list [(vote, id, stake)] instead.
   This makes it easier to send rewards to the expected vote account.
   Notably, turbine tree doesn't change with SIMD-0180, so the old
   list [(id, stake)] is still necessary.

   Realistically, there should be a 1:1 relationship between id and
   vote, but unfortunately the on chain state allows for a 1:N
   relationship (1 id could be associated to N vote accounts).
   At the time of writing, testnet has one such example.
   id: DtSguGSHVrXdqZU1mKWKocsAjrXMhaC7YJic5xxN1Uom
   votes:
   - https://solscan.io/account/BbtyLT1ntMFbbXtsJRCZnYjpe7d7TUtyZeGKzod3eNsN?cluster=testnet
   - https://solscan.io/account/FFr8Gyjy3Wjeqv6oD4RjbwqD1mVfKycAFxQdASYAfR75?cluster=testnet

   Even when there is a 1:1 relationship, the order of the 2 lists
   can be different because validators with the same stake could
   be ordered differently by vote vs id.

   Last consideration, this operation is done only once per epoch, twice
   at startup.

   The current implementation uses sort in place to avoid extra memory
   for a map or tree. */
   ulong
   compute_id_weights_from_vote_weights( fd_stake_weight_t *            stake_weight,
                                         fd_vote_stake_weight_t const * vote_stake_weight,
                                         ulong                          staked_cnt );

#endif /* HEADER_fd_src_flamenco_leaders_fd_leaders_base_h */
