#ifndef HEADER_fd_src_choreo_votor_ag_slot_state_h
#define HEADER_fd_src_choreo_votor_ag_slot_state_h

#include "ag_votor_base.h"
#include "ag_cert.h"
#include "ag_epoch_info.h"
#include "ag_event.h"
#include "ag_vote.h"
#include "../../util/fd_hash32.h"

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

#define AG_NOTAR_MAP_LG_SLOT_CNT          (11)
#define AG_NOTAR_MAP_SLOT_CNT             (1UL<<AG_NOTAR_MAP_LG_SLOT_CNT)
#define AG_NOTAR_FALLBACK_MAP_LG_SLOT_CNT (13)
#define AG_NOTAR_FALLBACK_MAP_SLOT_CNT    (1UL<<AG_NOTAR_FALLBACK_MAP_LG_SLOT_CNT)
FD_STATIC_ASSERT( AG_NOTAR_MAP_SLOT_CNT         >AG_VAT_MAX,                            notar_map          );
FD_STATIC_ASSERT( AG_NOTAR_FALLBACK_MAP_SLOT_CNT>AG_VAT_MAX*AG_NOTAR_FALLBACK_VOTE_MAX, notar_fallback_map );

struct ag_slot_voted_stake_hash {
  ag_block_hash_key_t hash;
  ulong               stake;
  fd_bls_agg_t        agg;
};
typedef struct ag_slot_voted_stake_hash ag_slot_voted_stake_hash_t;

#define MAP_NAME              notar_map
#define MAP_T                 ag_slot_voted_stake_hash_t
#define MAP_LG_SLOT_CNT       AG_NOTAR_MAP_LG_SLOT_CNT
#define MAP_KEY               hash
#define MAP_KEY_T             ag_block_hash_key_t
#define MAP_KEY_NULL          ag_block_hash_key_null
#define MAP_KEY_INVAL(k)      MAP_KEY_EQUAL(k,ag_block_hash_key_null)
#define MAP_KEY_EQUAL(k0,k1)  (!memcmp((k0).block_hash,(k1).block_hash,sizeof(ag_block_hash_key_t)))
#define MAP_KEY_EQUAL_IS_SLOW 1
#define MAP_KEY_HASH(key)     ((uint)fd_hash32( (key).block_hash, 42UL ))
#define MAP_MEMOIZE           0
#include "../../util/tmpl/fd_map.c"

#define MAP_NAME              notar_fallback_map
#define MAP_T                 ag_slot_voted_stake_hash_t
#define MAP_LG_SLOT_CNT       AG_NOTAR_FALLBACK_MAP_LG_SLOT_CNT
#define MAP_KEY               hash
#define MAP_KEY_T             ag_block_hash_key_t
#define MAP_KEY_NULL          ag_block_hash_key_null
#define MAP_KEY_INVAL(k)      MAP_KEY_EQUAL(k,ag_block_hash_key_null)
#define MAP_KEY_EQUAL(k0,k1)  (!memcmp((k0).block_hash,(k1).block_hash,sizeof(ag_block_hash_key_t)))
#define MAP_KEY_EQUAL_IS_SLOW 1
#define MAP_KEY_HASH(key)     ((uint)fd_hash32( (key).block_hash, 42UL ))
#define MAP_MEMOIZE           0
#include "../../util/tmpl/fd_map.c"


struct ag_parent_status {
  ag_block_hash_t hash;
  int             kind;
};
typedef struct ag_parent_status ag_parent_status_t;

struct ag_block_hash_set {
  ulong           cnt;
  ag_block_hash_t hash[ AG_EQVOC_BLOCK_HASH_MAX ];
};
typedef struct ag_block_hash_set ag_block_hash_set_t;

struct ag_slot_voted_stake {
  ag_slot_voted_stake_hash_t notar[ AG_NOTAR_MAP_SLOT_CNT ];
  fd_bls_sig_t               notar_sig[ AG_VAT_MAX ];
  ag_slot_voted_stake_hash_t notar_fallback[ AG_NOTAR_FALLBACK_MAP_SLOT_CNT ];
  fd_bls_sig_t               notar_fallback_sig[ AG_VAT_MAX ][ AG_NOTAR_FALLBACK_VOTE_MAX ];
  ag_block_hash_t            notar_fallback_sig_hash[ AG_VAT_MAX ][ AG_NOTAR_FALLBACK_VOTE_MAX ];
  uchar                      notar_fallback_sig_cnt[ AG_VAT_MAX ];
  ulong                      skip;
  fd_bls_sig_t               skip_sig[ AG_VAT_MAX ];
  fd_bls_agg_t               skip_agg;
  ulong                      skip_fallback;
  fd_bls_sig_t               skip_fallback_sig[ AG_VAT_MAX ];
  fd_bls_agg_t               skip_fallback_agg;
  ulong                      finalize;
  fd_bls_sig_t               finalize_sig[ AG_VAT_MAX ];
  fd_bls_agg_t               finalize_agg;
  ulong                      notar_or_skip;
  ulong                      top_notar;
  ag_block_hash_t            top_notar_hash;
};
typedef struct ag_slot_voted_stake ag_slot_voted_stake_t;

struct ag_slot_certs {
  ag_cert_notar_t          notar;
  ag_cert_notar_fallback_t notar_fallback[ AG_NOTAR_FALLBACK_CERT_MAX ];
  ulong                    notar_fallback_cnt;
  ag_cert_skip_t           skip;
  ag_cert_fast_final_t     fast_finalize;
  ag_cert_final_t          finalize;
};
typedef struct ag_slot_certs ag_slot_certs_t;

struct __attribute__((aligned(128UL))) ag_slot_state {
  ag_slot_voted_stake_t votes; /* the reference's votes and voted_stakes combined */
  ag_slot_certs_t       certs;

  ag_parent_status_t parents[ AG_EQVOC_BLOCK_HASH_MAX ];
  ulong              parents_cnt;

  ag_block_hash_set_t pending_safe_to_notar;
  ag_block_hash_set_t sent_safe_to_notar;
  int                 sent_safe_to_skip;

  ulong  slot;
  ulong  own_rank;
  ushort shred_version;

  ag_epoch_info_t const * epoch_info;
};
typedef struct ag_slot_state ag_slot_state_t;

FD_PROTOTYPES_BEGIN

void
ag_slot_state_null( ag_slot_state_t * self );

/* Definition 13. SlotState::add_cert */

void
ag_slot_state_add_cert( ag_slot_state_t * self,
                        ag_cert_t const * cert );

/* Definition 12. SlotState::add_vote */

int
ag_slot_state_add_vote( ag_slot_state_t *   self,
                        ag_vote_t const *   vote,
                        ulong               stake,
                        ag_event_cert_t *   out_cert_events,
                        ulong *             out_cert_event_cnt,
                        ag_event_pool_t *   out_pool_events,
                        ulong *             out_pool_event_cnt,
                        ag_event_repair_t * out_repair_events,
                        ulong *             out_repair_event_cnt,
                        fd_bls_set_t *      bad );

/* Definition 16. SlotState::notify_parent_known */

void
ag_slot_state_notify_parent_known( ag_slot_state_t *     self,
                                   ag_block_hash_t const block_hash );

/* Definition 16. SlotState::notify_parent_certified */

int
ag_slot_state_notify_parent_certified( ag_slot_state_t *     self,
                                       ag_block_hash_t const block_hash,
                                       fd_bls_set_t *        bad );

/* SlotState::check_slashable_offence */

FD_FN_PURE int
ag_slot_state_check_slashable_offence( ag_slot_state_t const * self,
                                       ag_vote_t const *       vote );

/* Definition 12. SlotState::should_ignore_vote */

FD_FN_PURE int
ag_slot_state_should_ignore_vote( ag_slot_state_t const * self,
                                  ag_vote_t const *       vote );

/* Definition 13. SlotState::is_notar_fallback */

FD_FN_PURE int
ag_slot_state_is_notar_fallback( ag_slot_state_t const * self,
                                 ag_block_hash_t const   block_hash );

/* Definition 13. SlotState::is_notar_fallback_or_stronger */

FD_FN_PURE int
ag_slot_state_is_notar_fallback_or_stronger( ag_slot_state_t const * self,
                                             ag_block_hash_t const   block_hash );

FD_PROTOTYPES_END

#endif
