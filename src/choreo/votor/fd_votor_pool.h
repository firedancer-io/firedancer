#ifndef HEADER_fd_src_choreo_votor_fd_votor_pool_h
#define HEADER_fd_src_choreo_votor_fd_votor_pool_h

#include "fd_votor_base.h"
#include "fd_cert.h"
#include "fd_epoch_info.h"
#include "fd_parent_ready_tracker.h" /* fd_parent_ready_t */
#include "fd_vote.h"

#define FD_VOTOR_POOL_SUCCESS                ( 0)
#define FD_VOTOR_POOL_ERR_SLOT_TOO_OLD       (-1)
#define FD_VOTOR_POOL_ERR_SLOT_TOO_NEW       (-2)
#define FD_VOTOR_POOL_ERR_DUPLICATE          (-3)
#define FD_VOTOR_POOL_ERR_SLASHABLE          (-4)
#define FD_VOTOR_POOL_ERR_CERT_VERIFY        (-5)
#define FD_VOTOR_POOL_ERR_VOTE_VERIFY        (-6)

#define FD_VOTOR_POOL_QUORUM_REACHED_FINAL          (FD_CERT_KIND_FINAL)
#define FD_VOTOR_POOL_QUORUM_REACHED_FAST_FINAL     (FD_CERT_KIND_FAST_FINAL)
#define FD_VOTOR_POOL_QUORUM_REACHED_NOTAR          (FD_CERT_KIND_NOTAR)
#define FD_VOTOR_POOL_QUORUM_REACHED_NOTAR_FALLBACK (FD_CERT_KIND_NOTAR_FALLBACK)
#define FD_VOTOR_POOL_QUORUM_REACHED_SKIP           (FD_CERT_KIND_SKIP)
#define FD_VOTOR_POOL_QUORUM_REACHED_SAFE_TO_NOTAR  (5)
#define FD_VOTOR_POOL_QUORUM_REACHED_SAFE_TO_SKIP   (6)

#define FD_VOTOR_POOL_EVENT_PARENT_READY  (0) /* Definition 15, ParentReady. PoolEvent::ParentReady */
#define FD_VOTOR_POOL_EVENT_SAFE_TO_NOTAR (1) /* Definition 16, SafeToNotar. PoolEvent::SafeToNotar */
#define FD_VOTOR_POOL_EVENT_SAFE_TO_SKIP  (2) /* Definition 16, SafeToSkip. PoolEvent::SafeToSkip   */
#define FD_VOTOR_POOL_EVENT_CERT_CREATED  (3) /* Definition 13. PoolEvent::CertCreated */
#define FD_VOTOR_POOL_EVENT_STANDSTILL    (4) /* Section 4.1.   PoolEvent::Standstill  */

#define FD_VOTOR_POOL_EVENT_IMPLICITLY_SKIPPED   (5) /* Firedancer only: for other tiles, never routed to fd_votor_loop */
#define FD_VOTOR_POOL_EVENT_IMPLICITLY_FINALIZED (6) /* Firedancer only: for other tiles, never routed to fd_votor_loop */

/* Spill file for a slot's block hash stakes past the inline ones,
   opened at boot.  123450-123461 are other fixed fds, 123462+ XDP. */

#define FD_VOTOR_SPILL_FD (123449)

typedef struct fd_votor_pool fd_votor_pool_t;

struct fd_votor_pool_event {
  int kind;
  union {
    fd_parent_ready_t parent_ready;
    fd_block_id_t     safe_to_notar;
    ulong             safe_to_skip;
    fd_cert_t         cert_created;
    fd_standstill_t   standstill;
    ulong             implicitly_skipped;
    fd_block_id_t     implicitly_finalized;
  };
};
typedef struct fd_votor_pool_event fd_votor_pool_event_t;

struct fd_votor_pool_standstill_iter {
  ulong finalized;
  ulong slot; /* ULONG_MAX when done */
  ulong idx;
  int   is_vote;
  union {
    fd_cert_t cert;
    fd_vote_t vote;
  };
};
typedef struct fd_votor_pool_standstill_iter fd_votor_pool_standstill_iter_t;

struct fd_votor_pool_metrics {
  ulong slot_state_pool_used;
  ulong slot_state_pool_free;
  ulong finalized_slot;
  ulong pool_events_cnt;
  ulong bls_verify_cnt;
};
typedef struct fd_votor_pool_metrics fd_votor_pool_metrics_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong
fd_votor_pool_align( void );

FD_FN_CONST ulong
fd_votor_pool_footprint( ulong slot_max,
                         ulong burst );

/* spill_fd is read/written with pread/pwrite at offsets below
   slot_max*SLOT_STATE_SPILL_SZ, only when a slot sees more than
   HASH_STAKE_INLINE_MAX distinct notar or notar fallback hashes. */

void *
fd_votor_pool_new( void * mem,
                   ulong  slot_max,
                   ulong  burst,
                   ulong  seed,
                   int    spill_fd );

fd_votor_pool_t *
fd_votor_pool_join( void * mem );

void *
fd_votor_pool_leave( fd_votor_pool_t const * self );

void *
fd_votor_pool_delete( void * mem );

FD_FN_PURE fd_votor_pool_metrics_t
fd_votor_pool_metrics( fd_votor_pool_t const * self );

void
fd_votor_pool_from_snapshot( fd_votor_pool_t *     self,
                             fd_block_id_t const * root );

void
fd_votor_pool_from_genesis( fd_votor_pool_t *     self,
                            fd_block_id_t const * genesis );

void
fd_votor_pool_advance_epoch( fd_votor_pool_t *       self,
                             fd_epoch_info_t const * epoch_info,
                             ulong                   epoch_rank,
                             ulong                   epoch_slot );

void
fd_votor_pool_update_own_rank( fd_votor_pool_t * self,
                               ulong             epoch_slot,
                               ulong             epoch_rank );

/* Definition 16, SafeToNotar. Pool::add_block */

int
fd_votor_pool_add_block( fd_votor_pool_t *     self,
                         fd_block_id_t const * block_id,
                         fd_block_id_t const * parent_id,
                         fd_bls_set_t *        bad );

/* Definition 13. Pool::add_cert */

int
fd_votor_pool_add_cert( fd_votor_pool_t * self,
                        fd_cert_t const * cert,
                        int               verified,
                        fd_bls_set_t *    bad );

/* Definition 12. Pool::add_vote */

int
fd_votor_pool_add_vote( fd_votor_pool_t * self,
                        fd_vote_t const * vote,
                        int               verified,
                        fd_bls_set_t *    bad,
                        uchar *           quorum_reached );

fd_block_hash_t const *
fd_votor_pool_agg_rewards( fd_votor_pool_t * self,
                           ulong             slot,
                           fd_bls_agg_t *    notar,
                           fd_bls_agg_t *    skip,
                           fd_bls_set_t *    bad );

fd_cert_final_t *
fd_votor_pool_final_cert( fd_votor_pool_t const * self,
                          ulong                   slot,
                          fd_cert_final_t *       out );

fd_cert_notar_t *
fd_votor_pool_notar_cert( fd_votor_pool_t const * self,
                          ulong                   slot,
                          fd_cert_notar_t *       out );

/* Section 4.1. Pool::recover_from_standstill */

fd_votor_pool_standstill_iter_t *
fd_votor_pool_standstill_iter_init( fd_votor_pool_standstill_iter_t * iter,
                                    fd_votor_pool_t const *           self );

fd_votor_pool_standstill_iter_t *
fd_votor_pool_standstill_iter_next( fd_votor_pool_standstill_iter_t * iter,
                                    fd_votor_pool_t const *           self );

FD_FN_PURE int
fd_votor_pool_standstill_iter_done( fd_votor_pool_standstill_iter_t const * iter );

/* Definition 14. Pool::finalized_slot */

FD_FN_PURE ulong
fd_votor_pool_finalized_slot( fd_votor_pool_t const * self );

FD_FN_PURE fd_block_hash_t const *
fd_votor_pool_finalized_block_hash( fd_votor_pool_t const * self );

FD_FN_PURE ulong
fd_votor_pool_highest_parent_ready( fd_votor_pool_t const * self );

/* Definition 15, ParentReady. Pool::parents_ready. */

ulong
fd_votor_pool_parents_ready( fd_votor_pool_t const * self,
                             ulong                   slot,
                             fd_block_id_t *         out,
                             ulong                   out_max );

/* Definition 15, ParentReady. Pool::wait_for_parent_ready. */

FD_FN_PURE fd_block_id_t
fd_votor_pool_wait_for_parent_ready( fd_votor_pool_t const * self,
                                     ulong                   slot );

int
fd_votor_pool_poll_pool_event( fd_votor_pool_t *       self,
                               fd_votor_pool_event_t * event );

int
fd_votor_pool_poll_repair_event( fd_votor_pool_t * self,
                                 fd_block_id_t *   block );

FD_PROTOTYPES_END

#endif
