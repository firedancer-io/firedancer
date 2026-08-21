#ifndef HEADER_fd_src_choreo_votor_ag_slot_state_h
#define HEADER_fd_src_choreo_votor_ag_slot_state_h

#include "ag_votor_base.h"
#include "ag_cert.h"
#include "ag_epoch_info.h"
#include "ag_event.h"
#include "ag_vote.h"

#define AG_PARENT_STATUS_KNOWN     (1)
#define AG_PARENT_STATUS_CERTIFIED (2)

#define AG_SLASHABLE_NONE                        (0)
#define AG_SLASHABLE_NOTAR_DIFFERENT_HASH        (1)
#define AG_SLASHABLE_SKIP_AND_NOTARIZE           (2)
#define AG_SLASHABLE_SKIP_AND_FINALIZE           (3)
#define AG_SLASHABLE_NOTAR_FALLBACK_AND_FINALIZE (4)

#define AG_SLOT_STATE_OUT_CERT_MAX   (3UL)
#define AG_SLOT_STATE_OUT_EVENT_MAX  (3UL)
#define AG_SLOT_STATE_OUT_REPAIR_MAX (3UL)

struct ag_slot_state_outputs {
  ag_cert_t       certs        [ AG_SLOT_STATE_OUT_CERT_MAX   ]; ulong certs_cnt;
  ag_event_pool_t pool_events  [ AG_SLOT_STATE_OUT_EVENT_MAX  ]; ulong pool_events_cnt;
  ag_block_id_t   block_repairs[ AG_SLOT_STATE_OUT_REPAIR_MAX ]; ulong block_repairs_cnt;
};
typedef struct ag_slot_state_outputs ag_slot_state_outputs_t;

#define AG_NOTAR_STAKE_MAX          (AG_VAT_MAX)
#define AG_NOTAR_FALLBACK_STAKE_MAX (AG_VAT_MAX*AG_NOTAR_FALLBACK_VOTE_MAX)

struct ag_hashstake {
  ag_block_hash_t hash;
  ulong           stake;
};
typedef struct ag_hashstake ag_hashstake_t;

struct ag_parent_status {
  ag_block_hash_t hash;
  int             kind;
};
typedef struct ag_parent_status ag_parent_status_t;

struct ag_hash_set {
  ulong           cnt;
  ag_block_hash_t hash[ AG_EQVOC_BLOCK_HASH_MAX ];
};
typedef struct ag_hash_set ag_hash_set_t;

struct ag_slot_votes {
  ag_notar_vote_t          notar             [AG_VAT_MAX];
  ag_notar_fallback_vote_t notar_fallback    [AG_VAT_MAX][AG_NOTAR_FALLBACK_VOTE_MAX];
  uchar                    notar_fallback_cnt[AG_VAT_MAX];
  ag_skip_vote_t           skip              [AG_VAT_MAX];
  ag_skip_fallback_vote_t  skip_fallback     [AG_VAT_MAX];
  ag_final_vote_t          finalize          [AG_VAT_MAX];
};
typedef struct ag_slot_votes ag_slot_votes_t;

struct ag_slot_voted_stake {
  ag_hashstake_t notar             [ AG_NOTAR_STAKE_MAX          ]; ulong notar_cnt;
  ag_hashstake_t notar_fallback    [ AG_NOTAR_FALLBACK_STAKE_MAX ]; ulong notar_fallback_cnt;
  ulong          skip;
  ulong          skip_fallback;
  ulong          finalize;
  ulong          notar_or_skip;
};
typedef struct ag_slot_voted_stake ag_slot_voted_stake_t;

struct ag_slot_certificates {
  ag_notar_cert_t          notar;
  ag_notar_fallback_cert_t notar_fallback[ AG_NOTAR_FALLBACK_CERT_MAX ];
  ulong                    notar_fallback_cnt;
  ag_skip_cert_t           skip;
  ag_fast_final_cert_t     fast_finalize;
  ag_final_cert_t          finalize;
};
typedef struct ag_slot_certificates ag_slot_certificates_t;

struct __attribute__((aligned(128UL))) ag_slot_state {
  ag_slot_votes_t        votes;
  ag_slot_voted_stake_t  voted_stakes;
  ag_slot_certificates_t certificates;

  ag_parent_status_t parents[ AG_EQVOC_BLOCK_HASH_MAX ];
  ulong              parents_cnt;

  ag_hash_set_t pending_safe_to_notar;
  ag_hash_set_t sent_safe_to_notar;
  int           sent_safe_to_skip;
  uint          own_agg_logged;

  ulong slot;
  ulong own_rank;

  ag_epoch_info_t const * epoch_info;
};
typedef struct ag_slot_state ag_slot_state_t;

FD_PROTOTYPES_BEGIN

void
ag_slot_state_init( ag_slot_state_t *       self,
                    ulong                   slot,
                    ag_epoch_info_t const * epoch_info,
                    ulong                   own_rank );

FD_FN_PURE int
ag_slot_state_vote_fits( ag_slot_state_t const * self,
                         ag_vote_t const *       vote );

FD_FN_PURE int
ag_slot_state_cert_fits( ag_slot_state_t const * self,
                         ag_cert_t const *       cert );

void
ag_slot_state_add_cert( ag_slot_state_t * self,
                        ag_cert_t const * cert );

ag_slot_state_outputs_t
ag_slot_state_add_vote( ag_slot_state_t * self,
                        ag_vote_t const * vote,
                        ulong             voter_stake );

void
ag_slot_state_notify_parent_known( ag_slot_state_t *     self,
                                   ag_block_hash_t const hash );

int
ag_slot_state_notify_parent_certified( ag_slot_state_t *     self,
                                       ag_block_hash_t const hash );

FD_FN_PURE int
ag_slot_state_check_slashable_offence( ag_slot_state_t const * self,
                                       ag_vote_t const *       vote );

FD_FN_PURE int
ag_slot_state_should_ignore_vote( ag_slot_state_t const * self,
                                  ag_vote_t const *       vote );

FD_FN_PURE ulong
ag_slot_state_stake( ag_hashstake_t const * ele,
                     ulong                  cnt,
                     ag_block_hash_t const  hash );

FD_FN_PURE int
ag_slot_state_is_notar_fallback( ag_slot_state_t const * self,
                                 ag_block_hash_t const   block_hash );

FD_FN_PURE int
ag_slot_state_is_notar_fallback_or_stronger( ag_slot_state_t const * self,
                                             ag_block_hash_t const   block_hash );

FD_FN_PURE ulong ag_slot_state_cert_voted_stake( ag_slot_state_t const * self, ag_cert_t const * cert );

FD_PROTOTYPES_END

#endif
