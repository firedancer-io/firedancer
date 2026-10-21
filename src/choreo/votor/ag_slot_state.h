#ifndef HEADER_fd_src_choreo_votor_ag_slot_state_h
#define HEADER_fd_src_choreo_votor_ag_slot_state_h

#include "ag_votor_base.h"
#include "ag_cert.h"
#include "ag_epoch_info.h"
#include "ag_vote.h"

#define AG_PARENT_STATUS_KNOWN     (1)
#define AG_PARENT_STATUS_CERTIFIED (2)

#define AG_SLASHABLE_NONE                        (0)
#define AG_SLASHABLE_NOTAR_DIFFERENT_HASH        (1)
#define AG_SLASHABLE_SKIP_AND_NOTARIZE           (2)
#define AG_SLASHABLE_SKIP_AND_FINALIZE           (3)
#define AG_SLASHABLE_NOTAR_FALLBACK_AND_FINALIZE (4)
#define AG_SLASHABLE_NOTAR_FALLBACK_OVER_THREE   (5)

#define AG_SLOT_STATE_OUT_CERT_MAX   (3UL)
#define AG_SLOT_STATE_OUT_EVENT_MAX  (3UL)
#define AG_SLOT_STATE_OUT_REPAIR_MAX (3UL)

#define AG_NOTAR_FALLBACK_HASH_MAX (AG_VAT_MAX*AG_NOTAR_FALLBACK_VOTE_MAX)
#define AG_REWARD_CAND_MAX         (8UL) /* duplicate notar certs kept per slot for reward certs */

struct ag_vote_stake_ele {
  ag_block_id_t block_id;
  ulong         stake;
  ulong         next;
  ulong         prev;
};
typedef struct ag_vote_stake_ele ag_vote_stake_ele_t;
FD_STATIC_ASSERT( sizeof(ag_vote_stake_ele_t)==64UL, ag_vote_stake_ele );

#define POOL_NAME ag_vote_stake_pool
#define POOL_T    ag_vote_stake_ele_t
#define POOL_NEXT next
#define POOL_LAZY 1
#include "../../util/tmpl/fd_pool.c"

#define MAP_NAME               ag_vote_stake_map
#define MAP_ELE_T              ag_vote_stake_ele_t
#define MAP_KEY                block_id
#define MAP_KEY_T              ag_block_id_t
#define MAP_NEXT               next
#define MAP_KEY_EQ(k0,k1)      (ag_block_id_eq( (k0), (k1) ))
#define MAP_KEY_HASH(key,seed) (fd_hash( (seed), (key), sizeof(ag_block_id_t) ))
#include "../../util/tmpl/fd_map_chain.c"

struct ag_parent_status {
  ag_block_hash_t hash;
  int             kind;
};
typedef struct ag_parent_status ag_parent_status_t;

struct ag_block_hash_set {
  ag_block_hash_t hash[ AG_EQVOC_BLOCK_HASH_MAX ];
  ulong           cnt;
};
typedef struct ag_block_hash_set ag_block_hash_set_t;

struct fd_bls_sig_ele {
  fd_bls_sig_t sig;
  ulong        next;
};
typedef struct fd_bls_sig_ele fd_bls_sig_ele_t;

#define POOL_NAME fd_bls_sig_pool
#define POOL_T    fd_bls_sig_ele_t
#include "../../util/tmpl/fd_pool.c"

struct ag_slot_votes {
  fd_bls_set_t    notar_set                    [ fd_bls_set_word_cnt ];
  uint            notar_sig_idx                [ AG_VAT_MAX ];
  uint            notar_hash_stake_idx         [ AG_VAT_MAX ];
  ulong           notar_hash_stake_head;
  ulong           notar_hash_stake_cnt;
  uint            notar_fallback_sig_idx       [ AG_VAT_MAX ][ AG_NOTAR_FALLBACK_VOTE_MAX ];
  uint            notar_fallback_hash_stake_idx[ AG_VAT_MAX ][ AG_NOTAR_FALLBACK_VOTE_MAX ];
  ulong           notar_fallback_hash_stake_head;
  ulong           notar_fallback_hash_stake_cnt;
  uchar           notar_fallback_sig_cnt       [ AG_VAT_MAX ];
  ulong           skip_stake;
  uint            skip_sig_idx                 [ AG_VAT_MAX ];
  fd_bls_agg_t    skip_agg;
  ulong           skip_fallback_stake;
  uint            skip_fallback_sig_idx        [ AG_VAT_MAX ];
  fd_bls_agg_t    skip_fallback_agg;
  ulong           finalize_stake;
  uint            finalize_sig_idx             [ AG_VAT_MAX ];
  fd_bls_agg_t    finalize_agg;
  ulong           notar_or_skip_stake;
  ulong           top_notar_stake;
  ag_block_hash_t top_notar_hash;
};
typedef struct ag_slot_votes ag_slot_votes_t;

/* A notar or fast finalize cert that arrived after the slot had one,
   kept unverified because it names signers the others do not: reward
   certs can include them. */

struct ag_reward_cand {
  uint            kind; /* AG_CERT_KIND_{NOTAR,FAST_FINAL,SKIP} */
  ag_block_hash_t block_hash;
  fd_bls_agg_t    agg;
  int             bad;  /* failed verification, skip */
  int             ok;   /* verified, do not again */
};
typedef struct ag_reward_cand ag_reward_cand_t;

struct ag_slot_certs {
  ag_cert_notar_t          notar;
  ag_cert_notar_fallback_t notar_fallback[ AG_NOTAR_FALLBACK_CERT_MAX ];
  ulong                    notar_fallback_cnt;
  ag_cert_skip_t           skip;
  ag_cert_fast_final_t     fast_finalize;
  ag_cert_final_t          finalize;
  ag_reward_cand_t         reward_cand[ AG_REWARD_CAND_MAX ];
  ulong                    reward_cand_cnt;
};
typedef struct ag_slot_certs ag_slot_certs_t;

struct ag_slot_state {
  ag_slot_votes_t votes;
  ag_slot_certs_t certs;

  ag_parent_status_t parents[ AG_EQVOC_BLOCK_HASH_MAX ];
  ulong              parents_cnt;

  ag_block_hash_set_t pending_safe_to_notar;
  ag_block_hash_set_t sent_safe_to_notar;
  int                 sent_safe_to_skip;

  ulong  slot;
  ulong  own_rank;
  ushort shred_version;
};
typedef struct ag_slot_state ag_slot_state_t;

struct ag_slot_states {
  fd_bls_sig_ele_t *      bls_sig_pool;
  ag_vote_stake_ele_t *   notar_hash_stake_pool;
  ag_vote_stake_map_t *   notar_hash_stake_map;
  ag_vote_stake_ele_t *   notar_fallback_hash_stake_pool;
  ag_vote_stake_map_t *   notar_fallback_hash_stake_map;
  ag_epoch_info_t const * prev_epoch_info;
  ulong                   prev_epoch_rank;
  ulong                   prev_epoch_slot;
  ag_epoch_info_t const * curr_epoch_info;
  ulong                   curr_epoch_rank;
  ulong                   curr_epoch_slot;
  ag_epoch_info_t const * next_epoch_info;
  ulong                   next_epoch_rank;
  ulong                   next_epoch_slot;
  ulong                   bls_verify_cnt;
};
typedef struct ag_slot_states ag_slot_states_t;

FD_PROTOTYPES_BEGIN

/* Resets self to an empty slot state.  self must be zeroed memory or a
   slot state. */

void
ag_slot_state_null( ag_slot_state_t *  self,
                    ag_slot_states_t * states );

/* Replaces our rank own_rank (USHORT_MAX if unstaked). */

void
ag_slot_state_set_own_rank( ag_slot_state_t * self,
                            ulong             own_rank );

/* Definition 13. SlotState::add_cert */

void
ag_slot_state_add_cert( ag_slot_state_t * self,
                        ag_cert_t const * cert );

/* Definition 12. SlotState::add_vote */

int
ag_slot_state_add_vote( ag_slot_state_t *  self,
                        ag_slot_states_t * states,
                        ag_vote_t const *  vote,
                        ulong              stake,
                        ag_cert_t *        out_cert_events,
                        ulong *            out_cert_event_cnt,
                        ag_block_id_t *    out_safe_to_notar,
                        ulong *            out_safe_to_notar_cnt,
                        ulong *            out_safe_to_skip,
                        ulong *            out_safe_to_skip_cnt,
                        ag_block_id_t *    out_repair_events,
                        ulong *            out_repair_event_cnt,
                        fd_bls_set_t *     bad );

/* Definition 16. SlotState::notify_parent_known */

void
ag_slot_state_notify_parent_known( ag_slot_state_t *     self,
                                   ag_block_hash_t const block_hash );

/* Definition 16. SlotState::notify_parent_certified */

int
ag_slot_state_notify_parent_certified( ag_slot_state_t *     self,
                                       ag_slot_states_t *    states,
                                       ag_block_hash_t const block_hash,
                                       fd_bls_set_t *        bad );

/* SlotState::check_slashable_offence */

FD_FN_PURE int
ag_slot_state_check_slashable_offence( ag_slot_state_t const *  self,
                                       ag_slot_states_t const * states,
                                       ag_vote_t const *        vote );

/* Definition 12. SlotState::should_ignore_vote */

FD_FN_PURE int
ag_slot_state_should_ignore_vote( ag_slot_state_t const *  self,
                                  ag_slot_states_t const * states,
                                  ag_vote_t const *        vote );

/* Definition 13. SlotState::is_notar_fallback */

FD_FN_PURE int
ag_slot_state_is_notar_fallback( ag_slot_state_t const * self,
                                 ag_block_hash_t const   block_hash );

/* Definition 13. SlotState::is_notar_fallback_or_stronger */

FD_FN_PURE int
ag_slot_state_is_notar_fallback_or_stronger( ag_slot_state_t const * self,
                                             ag_block_hash_t const   block_hash );

/* Accessors for reward certs */

void
ag_slot_state_add_reward_cand( ag_slot_state_t * self,
                               ag_cert_t const * cert );

fd_bls_agg_t *
ag_slot_state_notar_reward_agg( ag_slot_state_t *        self,
                                ag_slot_states_t *       states,
                                fd_bls_agg_t *           out,
                                fd_bls_agg_t *           out_base );

fd_bls_agg_t *
ag_slot_state_skip_reward_agg( ag_slot_state_t *  self,
                               ag_slot_states_t * states,
                               fd_bls_agg_t *     out,
                               fd_bls_agg_t *     out_base );

/* Copies the kind vote sigs of the ranks in set into out[ rank ].
   block_hash selects the sig for notar fallback; for notar the caller
   filters set by hash. */

fd_bls_sig_t *
ag_slot_state_sigs( ag_slot_state_t const *  self,
                    ag_slot_states_t const * states,
                    uint                     kind,
                    ag_block_hash_t const    block_hash,
                    fd_bls_set_t const *     set,
                    fd_bls_sig_t *           out );

FD_PROTOTYPES_END

#endif
