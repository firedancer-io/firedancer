#ifndef HEADER_fd_src_alpenglow_consensus_ag_pool_h
#define HEADER_fd_src_alpenglow_consensus_ag_pool_h

#include "../ag_alpenglow_base.h"
#include "ag_vote.h"
#include "ag_cert.h"
#include "ag_epoch_info.h"
#include "pool/ag_slot_state.h"

#define AG_POOL_SUCCESS                    ( 0)

/* AddVoteError (pool.rs). */

#define AG_ADD_VOTE_ERR_SLOT_OUT_OF_BOUNDS (-1)
#define AG_ADD_VOTE_ERR_UNKNOWN_SIGNER     (-2)
#define AG_ADD_VOTE_ERR_INVALID_SIGNATURE  (-3)
#define AG_ADD_VOTE_ERR_DUPLICATE          (-4)
#define AG_ADD_VOTE_ERR_SLASHABLE          (-5)

/* AddCertError (pool.rs).  Disjoint from AG_ADD_VOTE_ERR_* so
   ag_pool_strerror can map either. */

#define AG_ADD_CERT_ERR_SLOT_OUT_OF_BOUNDS (-6)
#define AG_ADD_CERT_ERR_THRESHOLD_NOT_MET  (-7)
#define AG_ADD_CERT_ERR_INVALID_SIGNATURE  (-8)
#define AG_ADD_CERT_ERR_DUPLICATE          (-9)

/* ag_pool_event_t (Rust PoolEvent). */

#define AG_POOL_VOTOR_EVENT_MAX (256UL)
#define AG_POOL_REPAIR_MAX      (256UL)

/* Caller-buffer caps for ag_pool_recover_from_standstill's recovery
   bundle.  Only slots above the finalized one are unpruned and the loop
   re-runs every DELTA_STANDSTILL, so these are headroom rather than a
   functional limit; a bundle that hits them is truncated and logged. */

#define AG_POOL_STANDSTILL_CERT_MAX (4096UL)
#define AG_POOL_STANDSTILL_VOTE_MAX (4096UL)

typedef struct ag_pool ag_pool_t;

FD_PROTOTYPES_BEGIN

/* ag_pool_strerror converts an AG_POOL_SUCCESS / AG_ADD_VOTE_ERR_* /
   AG_ADD_CERT_ERR_* code into a cstr (the Rust #[error] strings). */

FD_FN_CONST char const *
ag_pool_strerror( int err );

FD_FN_CONST ulong
ag_pool_align( void );

FD_FN_CONST ulong
ag_pool_footprint( ulong slot_max,
                   ulong validator_max,
                   ulong blockid_max );

void *
ag_pool_new( void *                      mem,
             ulong                       slot_max,
             ulong                       validator_max,
             ulong                       blockid_max,
             ulong                       own_id,
             ag_validator_info_t const * validators,
             ulong                       validator_cnt,
             ushort                      shred_version,
             ulong                       seed,
             ulong                       root_slot,
             fd_hash_t const *           root_block_hash );

ag_pool_t * ag_pool_join  ( void *            mem );
void *      ag_pool_leave ( ag_pool_t const * pool );
void *      ag_pool_delete( void *            mem );

int
ag_pool_add_cert( ag_pool_t *       self,
                  ag_cert_t const * cert );

int
ag_pool_add_vote( ag_pool_t *       self,
                  ag_vote_t const * vote );

void
ag_pool_add_block( ag_pool_t *           self,
                   ag_block_id_t const * block_id,
                   ag_block_id_t const * parent_id );

void
ag_pool_recover_from_standstill( ag_pool_t * self,
                                 ag_cert_t * certs,
                                 ulong *     certs_cnt,
                                 ulong       certs_max,
                                 ag_vote_t * votes,
                                 ulong *     votes_cnt,
                                 ulong       votes_max );

FD_FN_CONST ag_pool_event_t const * ag_pool_votor_event_channel( ag_pool_t const * self );
FD_FN_PURE  ulong                   ag_pool_votor_event_cnt    ( ag_pool_t const * self );
FD_FN_CONST ag_block_id_t const *   ag_pool_repair_channel     ( ag_pool_t const * self );
FD_FN_PURE  ulong                   ag_pool_repair_cnt         ( ag_pool_t const * self );

void ag_pool_drain_channels( ag_pool_t * self );

FD_FN_PURE ulong
ag_pool_finalized_slot( ag_pool_t const * self );

FD_FN_PURE ulong
ag_pool_first_unpruned_slot( ag_pool_t const * self );

/* ag_pool_prune_to_root (C-only): shed all per-slot state below the
   certified-final consensus root; see ag_finality_tracker_prune_to. */

void
ag_pool_prune_to_root( ag_pool_t *       self,
                       ulong             root_slot,
                       fd_hash_t const * root_hash );

ag_block_id_t const *
ag_pool_parents_ready( ag_pool_t * self,
                       ulong       slot,
                       ulong *     cnt );

/* ag_pool_wait_for_parent_ready mirrors Pool::wait_for_parent_ready's
   ready-now query (the Rust oneshot half is votor-side plumbing). */

int
ag_pool_wait_for_parent_ready( ag_pool_t *     self,
                               ulong           slot,
                               ag_block_id_t * out_id );

int
ag_pool_is_parent_ready( ag_pool_t *           self,
                         ulong                 slot,
                         ag_block_id_t const * parent );

FD_FN_PURE int
ag_pool_has_notar_or_fallback_cert( ag_pool_t const * self,
                                    ulong             slot );

int
ag_pool_get_notarized_block( ag_pool_t const * self,
                             ulong             slot,
                             fd_hash_t *       out_hash );

/* ag_pool_notar_voted_stake returns the stake accumulated from
   individual notar votes for slot's notarized block, or 0 if the slot
   has no state / notar cert. */

ulong
ag_pool_notar_voted_stake( ag_pool_t const * self,
                           ulong             slot );

/* ag_pool_get_finalized_block returns the certified block hash of slot
   from its notar or fast-final cert (a slow Final cert carries no hash).
   Returns 0 if neither cert is in the pool. */

int
ag_pool_get_finalized_block( ag_pool_t const * self,
                             ulong             slot,
                             fd_hash_t *       out_hash );

FD_FN_PURE int
ag_pool_has_final_cert( ag_pool_t const * self,
                        ulong             slot );
FD_FN_PURE int
ag_pool_has_notar_cert( ag_pool_t const * self,
                        ulong             slot );
FD_FN_PURE int
ag_pool_has_skip_cert( ag_pool_t const * self,
                       ulong             slot );

FD_FN_PURE int
ag_pool_contains_slot( ag_pool_t const * self,
                       ulong             slot );

FD_PROTOTYPES_END

#endif
