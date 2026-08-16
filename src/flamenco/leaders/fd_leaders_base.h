#ifndef HEADER_fd_src_flamenco_leaders_fd_leaders_base_h
#define HEADER_fd_src_flamenco_leaders_fd_leaders_base_h

#include "../stakes/fd_stake_weight.h"
#include "../runtime/sysvar/fd_sysvar_base.h"
#include "../features/fd_features.h"

#define MAX_SHRED_DESTS     40200UL /* 200 * 201 - 1 (exclude self) */
#define MAX_SLOTS_PER_EPOCH 432000UL
#define MAX_STAKE_WEIGHTS   2000UL  /* validator_admission_ticket limit */

/* Follows message structure in fd_stake_ci_stake_msg_init.
   Frankendancer only */
struct fd_stake_weight_msg_t {
  ulong             epoch;             /* Epoch for which the stake weights are valid */
  ulong             staked_vote_cnt;   /* Number of staked nodes */
  ulong             staked_id_cnt;     /* Number of staked nodes */
  ulong             start_slot;        /* Start slot of the epoch */
  ulong             slot_cnt;          /* Number of slots in the epoch */
  ulong             ns_per_slot;       /* Slot time duration */
};
typedef struct fd_stake_weight_msg_t fd_stake_weight_msg_t;

#define FD_STAKE_CI_STAKE_MSG_HEADER_SZ (sizeof(fd_stake_weight_msg_t))
#define FD_STAKE_CI_STAKE_MSG_RECORD_SZ (sizeof(fd_vote_stake_weight_t))
#define FD_STAKE_CI_ID_WEIGHT_RECORD_SZ (sizeof(fd_stake_weight_t))
#define FD_STAKE_CI_STAKE_MSG_SZ (FD_STAKE_CI_STAKE_MSG_HEADER_SZ + MAX_STAKE_WEIGHTS * (FD_STAKE_CI_STAKE_MSG_RECORD_SZ + FD_STAKE_CI_ID_WEIGHT_RECORD_SZ))

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
  return (fd_stake_weight_t *)fd_type_pun( (uchar *)stake_weight_msg + FD_STAKE_CI_STAKE_MSG_HEADER_SZ + stake_weight_msg->staked_vote_cnt * FD_STAKE_CI_STAKE_MSG_RECORD_SZ );
}

/* Firedancer only */
struct fd_epoch_info_msg_t {
  ulong               epoch;             /* Epoch for which the info is valid */
  ulong               staked_vote_cnt;   /* Number of staked nodes */
  ulong               staked_id_cnt;     /* Number of staked nodes */
  ulong               start_slot;        /* Start slot of the epoch */
  ulong               slot_cnt;          /* Number of slots in the epoch */
  ulong               ns_per_slot;       /* Slot time duration */
  fd_epoch_schedule_t epoch_schedule;    /* Epoch schedule */
  fd_features_t       features;          /* Feature activation slots */
};
typedef struct fd_epoch_info_msg_t fd_epoch_info_msg_t;

/* The epoch info message also carries one compressed BLS voting pubkey
   per staked voter, appended after the id weights and indexed 1:1 with
   the vote stake weights (fd_epoch_info_msg_stake_weights).  The votor
   tile consumes these for vote-signature aggregation; other consumers
   ignore the trailing array.  MAX_STAKE_WEIGHTS is already the
   validator_admission_ticket voter cap, so it bounds this too. */
#define FD_EPOCH_INFO_MAX_VOTERS    MAX_STAKE_WEIGHTS
#define FD_EPOCH_INFO_BLS_PUBKEY_SZ (48UL)

#define FD_EPOCH_INFO_MSG_HEADER_SZ (sizeof(fd_epoch_info_msg_t))
#define FD_EPOCH_INFO_MAX_MSG_SZ    (FD_EPOCH_INFO_MSG_HEADER_SZ + MAX_STAKE_WEIGHTS * (sizeof(fd_vote_stake_weight_t) + sizeof(fd_stake_weight_t) + FD_EPOCH_INFO_BLS_PUBKEY_SZ))
#define FD_EPOCH_OUT_MTU            FD_EPOCH_INFO_MAX_MSG_SZ

static inline ulong fd_epoch_info_msg_sz( ulong vote_cnt,
                                          ulong id_weight_cnt ) {
  return FD_EPOCH_INFO_MSG_HEADER_SZ +
         (vote_cnt * sizeof(fd_vote_stake_weight_t)) +
         (id_weight_cnt * sizeof(fd_stake_weight_t)) +
         (vote_cnt * FD_EPOCH_INFO_BLS_PUBKEY_SZ);
}

static inline fd_vote_stake_weight_t *
fd_epoch_info_msg_stake_weights( fd_epoch_info_msg_t const * epoch_info_msg ) {
  return (fd_vote_stake_weight_t *)fd_type_pun( (uchar *)epoch_info_msg + FD_EPOCH_INFO_MSG_HEADER_SZ );
}

static inline fd_stake_weight_t *
fd_epoch_info_msg_id_weights( fd_epoch_info_msg_t const * epoch_info_msg ) {
  return (fd_stake_weight_t *)fd_type_pun( (uchar *)epoch_info_msg + FD_EPOCH_INFO_MSG_HEADER_SZ + epoch_info_msg->staked_vote_cnt * sizeof(fd_vote_stake_weight_t) );
}

/* fd_epoch_info_msg_bls_pubkeys returns the array of per-voter
   compressed BLS voting pubkeys (FD_EPOCH_INFO_BLS_PUBKEY_SZ bytes
   each), appended after the id weights and indexed 1:1 with
   fd_epoch_info_msg_stake_weights (so entry i is the BLS key of voter
   i). */
static inline uchar *
fd_epoch_info_msg_bls_pubkeys( fd_epoch_info_msg_t const * epoch_info_msg ) {
  return (uchar *)fd_type_pun( (uchar *)epoch_info_msg + FD_EPOCH_INFO_MSG_HEADER_SZ +
                               epoch_info_msg->staked_vote_cnt * sizeof(fd_vote_stake_weight_t) +
                               epoch_info_msg->staked_id_cnt   * sizeof(fd_stake_weight_t) );
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
