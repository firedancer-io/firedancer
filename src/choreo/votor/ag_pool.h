#ifndef HEADER_fd_src_choreo_votor_ag_pool_h
#define HEADER_fd_src_choreo_votor_ag_pool_h

#include "ag_votor_base.h"
#include "ag_cert.h"
#include "ag_epoch_info.h"
#include "ag_event.h"
#include "ag_slot_state.h"
#include "ag_vote.h"

#define AG_POOL_SUCCESS                ( 0)
#define AG_POOL_ERR_SLOT_OUT_OF_BOUNDS (-1)
#define AG_POOL_ERR_DUPLICATE          (-2)
#define AG_POOL_ERR_SLASHABLE          (-3)
#define AG_POOL_ERR_CERT_VERIFY        (-4)

#define AG_POOL_QUORUM_REACHED_FINAL          (AG_CERT_KIND_FINAL)
#define AG_POOL_QUORUM_REACHED_FAST_FINAL     (AG_CERT_KIND_FAST_FINAL)
#define AG_POOL_QUORUM_REACHED_NOTAR          (AG_CERT_KIND_NOTAR)
#define AG_POOL_QUORUM_REACHED_NOTAR_FALLBACK (AG_CERT_KIND_NOTAR_FALLBACK)
#define AG_POOL_QUORUM_REACHED_SKIP           (AG_CERT_KIND_SKIP)
#define AG_POOL_QUORUM_REACHED_SAFE_TO_NOTAR  (5)
#define AG_POOL_QUORUM_REACHED_SAFE_TO_SKIP   (6)

typedef struct ag_pool ag_pool_t;

struct ag_pool_metrics {
  ulong slot_state_pool_used;
  ulong slot_state_pool_free;
  ulong finalized_slot;
  ulong pool_events_cnt;
};
typedef struct ag_pool_metrics ag_pool_metrics_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong
ag_pool_align( void );

FD_FN_CONST ulong
ag_pool_footprint( ulong slot_max );

void *
ag_pool_new( void * mem,
             ulong  slot_max,
             ulong  seed );

ag_pool_t *
ag_pool_join( void * mem );

void *
ag_pool_leave( ag_pool_t const * pool );

void *
ag_pool_delete( void * mem );

/* ag_pool_init starts the pool at root, a finalized block that is
   treated as notarized (Section 2.9). */

void
ag_pool_init( ag_pool_t *           self,
              ag_block_id_t const * root );

void
ag_pool_fini( ag_pool_t * self );

FD_FN_CONST char const *
ag_pool_strerror( int err );

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

/* Definition 13. Pool::add_cert */

int
ag_pool_add_cert( ag_pool_t *       self,
                  ag_cert_t const * cert,
                  fd_bls_set_t *    bad );

/* ag_pool_add_verified_cert is ag_pool_add_cert for a cert whose
   signature and stake were already verified, e.g. by replay.  The
   bounds, duplicate and safety checks still run. */

int
ag_pool_add_verified_cert( ag_pool_t *       self,
                           ag_cert_t const * cert,
                           fd_bls_set_t *    bad );

/* Definition 12. Pool::add_vote */

int
ag_pool_add_vote( ag_pool_t *       self,
                  ag_vote_t const * vote,
                  fd_bls_set_t *    bad,
                  uchar *           quorum_reached );

/* Definition 16. Pool::add_block */

int
ag_pool_add_block( ag_pool_t *           self,
                   ag_block_id_t const * block_id,
                   ag_block_id_t const * parent_id,
                   fd_bls_set_t *        bad );

/* PoolImpl::slot_state, read-only */

ag_slot_state_t const *
ag_pool_slot_state( ag_pool_t const * self,
                    ulong             slot );

/* Section 4.1. Pool::recover_from_standstill */

void
ag_pool_recover_from_standstill( ag_pool_t * self );

/* Definition 14. Pool::finalized_slot */

FD_FN_PURE ulong
ag_pool_finalized_slot( ag_pool_t const * self );

FD_FN_PURE uchar const *
ag_pool_finalized_block_hash( ag_pool_t const * self );

/* Definition 15. Pool::parents_ready.  Writes up to out_max ready
   parents of slot to out and returns how many are ready. */

ulong
ag_pool_parents_ready( ag_pool_t const * self,
                       ulong             slot,
                       ag_block_id_t *   out,
                       ulong             out_max );

/* Definition 15. Pool::wait_for_parent_ready; slot ULONG_MAX is the pending receiver */

ag_block_id_t
ag_pool_wait_for_parent_ready( ag_pool_t * self,
                               ulong       slot );

int
ag_pool_poll_pool_event( ag_pool_t *       self,
                         ag_event_pool_t * event );

int
ag_pool_poll_repair_event( ag_pool_t *         self,
                           ag_event_repair_t * event );

FD_PROTOTYPES_END

#endif
