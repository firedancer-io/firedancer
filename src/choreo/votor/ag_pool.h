#ifndef HEADER_fd_src_choreo_votor_ag_pool_h
#define HEADER_fd_src_choreo_votor_ag_pool_h

#include "ag_votor_base.h"
#include "ag_cert.h"
#include "ag_epoch_info.h"
#include "ag_parent_ready_tracker.h" /* ag_parent_ready_t */
#include "ag_vote.h"

#define AG_POOL_SUCCESS                ( 0)
#define AG_POOL_ERR_SLOT_TOO_OLD       (-1)
#define AG_POOL_ERR_SLOT_TOO_NEW       (-2)
#define AG_POOL_ERR_DUPLICATE          (-3)
#define AG_POOL_ERR_SLASHABLE          (-4)
#define AG_POOL_ERR_CERT_VERIFY        (-5)
#define AG_POOL_ERR_DUPLICATE_KEPT     (-6) /* a duplicate kept as a reward cert candidate */

#define AG_POOL_QUORUM_REACHED_FINAL          (AG_CERT_KIND_FINAL)
#define AG_POOL_QUORUM_REACHED_FAST_FINAL     (AG_CERT_KIND_FAST_FINAL)
#define AG_POOL_QUORUM_REACHED_NOTAR          (AG_CERT_KIND_NOTAR)
#define AG_POOL_QUORUM_REACHED_NOTAR_FALLBACK (AG_CERT_KIND_NOTAR_FALLBACK)
#define AG_POOL_QUORUM_REACHED_SKIP           (AG_CERT_KIND_SKIP)
#define AG_POOL_QUORUM_REACHED_SAFE_TO_NOTAR  (5)
#define AG_POOL_QUORUM_REACHED_SAFE_TO_SKIP   (6)

#define AG_POOL_EVENT_PARENT_READY  (0) /* Definition 15. PoolEvent::ParentReady */
#define AG_POOL_EVENT_SAFE_TO_NOTAR (1) /* Definition 16. PoolEvent::SafeToNotar */
#define AG_POOL_EVENT_SAFE_TO_SKIP  (2) /* Definition 16. PoolEvent::SafeToSkip  */
#define AG_POOL_EVENT_CERT_CREATED  (3) /* Definition 13. PoolEvent::CertCreated */
#define AG_POOL_EVENT_STANDSTILL    (4) /* Section 4.1.   PoolEvent::Standstill  */

#define AG_POOL_EVENT_IMPLICITLY_SKIPPED   (5) /* Firedancer only: for other tiles, never routed to ag_votor */
#define AG_POOL_EVENT_IMPLICITLY_FINALIZED (6) /* Firedancer only: for other tiles, never routed to ag_votor */

typedef struct ag_pool ag_pool_t;

typedef struct ag_slot_state  ag_slot_state_t;
typedef struct ag_slot_states ag_slot_states_t;

struct ag_pool_event {
  int kind;
  union {
    ag_parent_ready_t parent_ready;
    ag_block_id_t     safe_to_notar;
    ulong             safe_to_skip;
    ag_cert_t         cert_created;
    ag_standstill_t   standstill;
    ulong             implicitly_skipped;
    ag_block_id_t     implicitly_finalized;
  };
};
typedef struct ag_pool_event ag_pool_event_t;

struct ag_pool_metrics {
  ulong slot_state_pool_used;
  ulong slot_state_pool_free;
  ulong finalized_slot;
  ulong pool_events_cnt;
  ulong bls_verify_cnt;
};
typedef struct ag_pool_metrics ag_pool_metrics_t;

struct ag_pool_standstill_iter {
  ulong finalized;
  ulong slot; /* ULONG_MAX when done */
  ulong idx;
  int   is_vote;
  union {
    ag_cert_t cert;
    ag_vote_t vote;
  };
};
typedef struct ag_pool_standstill_iter ag_pool_standstill_iter_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong
ag_pool_align( void );

FD_FN_CONST ulong
ag_pool_footprint( ulong slot_max,
                   ulong burst );

void *
ag_pool_new( void * mem,
             ulong  slot_max,
             ulong  burst,
             ulong  seed );

ag_pool_t *
ag_pool_join( void * mem );

void *
ag_pool_leave( ag_pool_t const * pool );

void *
ag_pool_delete( void * mem );

/* ag_pool_from_snapshot starts the pool at root, a finalized block
   that is treated as notarized (Section 2.9). */

void
ag_pool_from_snapshot( ag_pool_t *           self,
                       ag_block_id_t const * root );

/* ag_pool_from_genesis starts the pool at the genesis block.  Like
   ag_pool_from_snapshot, but also makes genesis+1 ParentReady (see
   ag_parent_ready_tracker_mark_root). */

void
ag_pool_from_genesis( ag_pool_t *           self,
                      ag_block_id_t const * genesis );

void
ag_pool_fini( ag_pool_t * self );

FD_FN_PURE ag_pool_metrics_t
ag_pool_metrics( ag_pool_t const * self );

void
ag_pool_advance_epoch( ag_pool_t *             self,
                       ag_epoch_info_t const * epoch_info,
                       ulong                   epoch_rank,
                       ulong                   epoch_slot );

/* Replaces our rank in the epoch starting at epoch_slot, for when our
   identity changes after the epoch advanced.  The epoch's live slot
   states then treat the new rank's votes as ours.  USHORT_MAX if we
   are not ranked in that epoch. */

void
ag_pool_set_rank( ag_pool_t * self,
                  ulong       epoch_slot,
                  ulong       epoch_rank );

/* Definition 13. Pool::add_cert

   verified is non-zero for a cert whose signature and stake were already
   verified, e.g. by replay.  The bounds, duplicate and safety checks
   still run.  relayer is the rank of the peer that sent it, banned if a
   kept duplicate later fails verification, or USHORT_MAX. */

int
ag_pool_add_cert( ag_pool_t *       self,
                  ag_cert_t const * cert,
                  int               verified,
                  ushort            relayer,
                  fd_bls_set_t *    bad );

/* Definition 12. Pool::add_vote

   verified is non-zero for a vote whose signature is trusted, e.g. our
   own, and skips the G2 subgroup check. */

int
ag_pool_add_vote( ag_pool_t *       self,
                  ag_vote_t const * vote,
                  int               verified,
                  fd_bls_set_t *    bad,
                  uchar *           quorum_reached );

/* Definition 16. Pool::add_block */

int
ag_pool_add_block( ag_pool_t *           self,
                   ag_block_id_t const * block_id,
                   ag_block_id_t const * parent_id,
                   fd_bls_set_t *        bad );

/* See ag_slot_state_{skip,notar}_reward_agg.  NULL if the slot has no
   state or nothing to reward. */

fd_bls_agg_t *
ag_pool_skip_reward_agg( ag_pool_t *    self,
                         ulong          slot,
                         fd_bls_agg_t * out,
                         fd_bls_agg_t * out_base,
                         fd_bls_set_t * bad,
                         fd_bls_set_t * bad_relayer );

fd_bls_agg_t *
ag_pool_notar_reward_agg( ag_pool_t *    self,
                          ulong          slot,
                          fd_bls_agg_t * out,
                          fd_bls_agg_t * out_base,
                          uchar *        out_hash,
                          fd_bls_set_t * bad,
                          fd_bls_set_t * bad_relayer );

/* PoolImpl::slot_state, read-only */

ag_slot_state_t const *
ag_pool_slot_state( ag_pool_t const * self,
                    ulong             slot );

ag_slot_states_t const *
ag_pool_slot_states( ag_pool_t const * self );

/* Section 4.1. Pool::recover_from_standstill */

ag_pool_standstill_iter_t *
ag_pool_standstill_iter_init( ag_pool_standstill_iter_t * iter,
                              ag_pool_t const *           self );

ag_pool_standstill_iter_t *
ag_pool_standstill_iter_next( ag_pool_standstill_iter_t * iter,
                              ag_pool_t const *           self );

FD_FN_PURE int
ag_pool_standstill_iter_done( ag_pool_standstill_iter_t const * iter );

/* Definition 14. Pool::finalized_slot */

FD_FN_PURE ulong
ag_pool_finalized_slot( ag_pool_t const * self );

FD_FN_PURE uchar const *
ag_pool_finalized_block_hash( ag_pool_t const * self );

FD_FN_PURE ulong
ag_pool_highest_parent_ready( ag_pool_t const * self );

/* Definition 15. Pool::parents_ready. */

ulong
ag_pool_parents_ready( ag_pool_t const * self,
                       ulong             slot,
                       ag_block_id_t *   out,
                       ulong             out_max );

/* Definition 15. Pool::wait_for_parent_ready. */

ag_block_id_t
ag_pool_wait_for_parent_ready( ag_pool_t * self,
                               ulong       slot );

int
ag_pool_poll_pool_event( ag_pool_t *       self,
                         ag_pool_event_t * event );

int
ag_pool_poll_repair_event( ag_pool_t *     self,
                           ag_block_id_t * block );

FD_PROTOTYPES_END

#endif
