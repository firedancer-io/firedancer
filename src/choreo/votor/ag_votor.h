#ifndef HEADER_fd_src_choreo_votor_ag_votor_h
#define HEADER_fd_src_choreo_votor_ag_votor_h

#include "ag_votor_base.h"
#include "../../ballet/bls/fd_bls.h"
#include "ag_event.h"

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

void
ag_votor_advance_epoch( ag_votor_t * self,
                        long         ns_per_slot,
                        ulong        epoch_rank,
                        ulong        epoch_slot );

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

FD_FN_PURE ulong ag_votor_slot_state_used( ag_votor_t const * self );
FD_FN_PURE ulong ag_votor_slot_state_max ( ag_votor_t const * self );
FD_FN_PURE ulong ag_votor_finalized_slot ( ag_votor_t const * self );

FD_PROTOTYPES_END

#endif
