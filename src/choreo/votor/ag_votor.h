#ifndef HEADER_fd_src_choreo_votor_ag_votor_h
#define HEADER_fd_src_choreo_votor_ag_votor_h

#include "ag_votor_base.h"
#include "../../ballet/bls/fd_bls.h"
#include "ag_event.h"

#define AG_VOTOR_REASON_BLOCK_REPLAYED         (0)
#define AG_VOTOR_REASON_BLOCK_DEAD             (1)
#define AG_VOTOR_REASON_PARENT_READY           (2)
#define AG_VOTOR_REASON_BLOCK_NOTARIZED        (3)
#define AG_VOTOR_REASON_TIMEOUT                (4)
#define AG_VOTOR_REASON_TIMEOUT_CRASHED_LEADER (5)
#define AG_VOTOR_REASON_SAFE_TO_NOTAR          (6)
#define AG_VOTOR_REASON_SAFE_TO_SKIP           (7)

typedef struct ag_votor ag_votor_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong
ag_votor_align( void );

FD_FN_CONST ulong
ag_votor_footprint( ulong slot_max );

void *
ag_votor_new( void * mem,
              ulong  slot_max,
              ulong  seed );

ag_votor_t *
ag_votor_join( void * mem );

void *
ag_votor_leave( ag_votor_t const * votor );

void *
ag_votor_delete( void * mem );

void
ag_votor_init( ag_votor_t *   self,
               ulong          slot,
               long           now,
               long           ns_per_slot,
               ushort         shred_version,
               fd_bls_sign_fn sign_fn,
               void *         sign_ctx );

void
ag_votor_fini( ag_votor_t * self );

/* Advances the epoch and copies its compressed BLS public key selector.
   A NULL bls_pubkey disables voting in that epoch. */

void
ag_votor_advance_epoch( ag_votor_t *  self,
                        long          ns_per_slot,
                        ulong         epoch_rank,
                        ulong         epoch_slot,
                        uchar const * bls_pubkey );

/* Algorithm 1, lines 9-25. Votor::handle_pool_event */

void
ag_votor_handle_pool_event( ag_votor_t *            self,
                            ag_event_pool_t const * event,
                            long                    now );

/* Votor::handle_blockstore_event, FirstShred and InvalidBlock */

void
ag_votor_handle_block_event( ag_votor_t *             self,
                             ag_event_block_t const * event );

/* Algorithm 1, lines 1-5. Votor::handle_blockstore_event, Block */

void
ag_votor_handle_replay_event( ag_votor_t *              self,
                              ag_event_replay_t const * event );

/* Algorithm 1, lines 6-8. Votor::handle_timeout_event */

void
ag_votor_handle_timeout_event( ag_votor_t *               self,
                               ag_event_timeout_t const * event );

int
ag_votor_poll_timeout_event( ag_votor_t *         self,
                             long                 now,
                             ag_event_timeout_t * event );

int
ag_votor_poll_vote_event( ag_votor_t *      self,
                          ag_event_vote_t * event );

int
ag_votor_poll_cert_event( ag_votor_t *      self,
                          ag_event_cert_t * event );

FD_PROTOTYPES_END

#endif
