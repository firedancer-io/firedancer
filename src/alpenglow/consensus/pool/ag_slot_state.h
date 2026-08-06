#ifndef HEADER_fd_src_alpenglow_consensus_pool_ag_slot_state_h
#define HEADER_fd_src_alpenglow_consensus_pool_ag_slot_state_h

#include "../../ag_alpenglow_base.h"
#include "../ag_vote.h"
#include "../ag_cert.h"
#include "../ag_epoch_info.h"
#include "../ag_pool_event.h"        /* ag_pool_event_t */

#define AG_PARENT_STATUS_KNOWN     (1)
#define AG_PARENT_STATUS_CERTIFIED (2)

#define AG_SAFE_TO_NOTAR_STATUS_SAFE_TO_NOTAR  (0)
#define AG_SAFE_TO_NOTAR_STATUS_MISSING_BLOCK  (1)
#define AG_SAFE_TO_NOTAR_STATUS_AWAITING_VOTES (2)

#define AG_SLASHABLE_NONE                        (0)
#define AG_SLASHABLE_NOTAR_DIFFERENT_HASH        (1)
#define AG_SLASHABLE_SKIP_AND_NOTARIZE           (2)
#define AG_SLASHABLE_SKIP_AND_FINALIZE           (3)
#define AG_SLASHABLE_NOTAR_FALLBACK_AND_FINALIZE (4)

#define AG_SLOT_STATE_OUT_CERT_MAX   (3UL)
#define AG_SLOT_STATE_OUT_EVENT_MAX  (3UL)
#define AG_SLOT_STATE_OUT_REPAIR_MAX (3UL)
#define AG_SLOT_STATE_NF_CERT_MAX    (32UL)

struct ag_slot_state_outputs {
  ag_cert_t       certs        [ AG_SLOT_STATE_OUT_CERT_MAX   ]; ulong certs_cnt;
  ag_pool_event_t pool_events  [ AG_SLOT_STATE_OUT_EVENT_MAX  ]; ulong pool_events_cnt;
  ag_block_id_t   block_repairs[ AG_SLOT_STATE_OUT_REPAIR_MAX ]; ulong block_repairs_cnt;
};
typedef struct ag_slot_state_outputs ag_slot_state_outputs_t;

typedef struct ag_slot_state ag_slot_state_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong ag_slot_state_align( void );

FD_FN_CONST ulong ag_slot_state_footprint( ulong validator_max );

void *
ag_slot_state_new( void *                  mem,
                   ulong                   slot,
                   ulong                   own_id,
                   ulong                   validator_max,
                   ulong                   seed,
                   ag_epoch_info_t const * epoch_info );

ag_slot_state_t * ag_slot_state_join  ( void *                  mem );
void *            ag_slot_state_leave ( ag_slot_state_t const * slot_state );
void *            ag_slot_state_delete( void *                  mem );

void
ag_slot_state_add_cert( ag_slot_state_t * self,
                        ag_cert_t const * cert );

ag_slot_state_outputs_t
ag_slot_state_add_vote( ag_slot_state_t * self,
                        ag_vote_t const * vote,
                        ulong             voter_stake );

void
ag_slot_state_notify_parent_known( ag_slot_state_t * self,
                                   fd_hash_t const * hash );

/* Returns the block's AG_SAFE_TO_NOTAR_STATUS_* (AWAITING_VOTES when
   safe-to-notar was already sent); the caller emits the safe-to-notar
   event / repair itself. */

int
ag_slot_state_notify_parent_certified( ag_slot_state_t * self,
                                       fd_hash_t const * hash );

FD_FN_PURE int
ag_slot_state_check_slashable_offence( ag_slot_state_t const * self,
                                       ag_vote_t const *       vote );

FD_FN_PURE int
ag_slot_state_should_ignore_vote( ag_slot_state_t const * self,
                                  ag_vote_t const *       vote );

FD_FN_PURE int
ag_slot_state_is_notar_fallback( ag_slot_state_t const * self,
                                 fd_hash_t const *       block_hash );

FD_FN_PURE ulong
ag_slot_state_slot( ag_slot_state_t const * self );

FD_FN_PURE ulong
ag_slot_state_notar_stake( ag_slot_state_t const * self,
                           fd_hash_t const *       block_hash );
FD_FN_PURE ulong
ag_slot_state_notar_fallback_stake( ag_slot_state_t const * self,
                                    fd_hash_t const *       block_hash );

FD_FN_PURE int
ag_slot_state_has_notar_vote( ag_slot_state_t const * self,
                              ulong                   v );

FD_FN_PURE int ag_slot_state_has_notar_cert        ( ag_slot_state_t const * self );
FD_FN_PURE int ag_slot_state_has_skip_cert         ( ag_slot_state_t const * self );
FD_FN_PURE int ag_slot_state_has_fast_finalize_cert( ag_slot_state_t const * self );
FD_FN_PURE int ag_slot_state_has_finalize_cert     ( ag_slot_state_t const * self );

FD_FN_PURE ag_final_cert_t      const * ag_slot_state_finalize_cert     ( ag_slot_state_t const * self );
FD_FN_PURE ag_fast_final_cert_t const * ag_slot_state_fast_finalize_cert( ag_slot_state_t const * self );
FD_FN_PURE ag_notar_cert_t      const * ag_slot_state_notar_cert        ( ag_slot_state_t const * self );
FD_FN_PURE ag_skip_cert_t       const * ag_slot_state_skip_cert         ( ag_slot_state_t const * self );

/* ag_slot_state_cert_voted_stake returns the stake accumulated from
   individual votes toward building cert's aggregate: notar
   [+ notar-fallback] stake for the cert's block hash, skip +
   skip-fallback, or finalize. */

FD_FN_PURE ulong ag_slot_state_cert_voted_stake( ag_slot_state_t const * self, ag_cert_t const * cert );

FD_FN_PURE ulong ag_slot_state_notar_fallback_cert_cnt( ag_slot_state_t const * self );

FD_FN_PURE ag_notar_fallback_cert_t const *
ag_slot_state_notar_fallback_cert( ag_slot_state_t const * self,
                                   ulong                   i );

FD_FN_PURE ag_final_vote_t         const * ag_slot_state_own_finalize_vote     ( ag_slot_state_t const * self );
FD_FN_PURE ag_notar_vote_t         const * ag_slot_state_own_notar_vote        ( ag_slot_state_t const * self );
FD_FN_PURE ag_skip_vote_t          const * ag_slot_state_own_skip_vote         ( ag_slot_state_t const * self );
FD_FN_PURE ag_skip_fallback_vote_t const * ag_slot_state_own_skip_fallback_vote( ag_slot_state_t const * self );

ulong
ag_slot_state_own_notar_fallback_votes( ag_slot_state_t const *    self,
                                        ag_notar_fallback_vote_t * out,
                                        ulong                      out_max );

FD_PROTOTYPES_END

#endif
