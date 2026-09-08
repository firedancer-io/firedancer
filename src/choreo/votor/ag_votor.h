#ifndef HEADER_fd_src_choreo_votor_ag_votor_h
#define HEADER_fd_src_choreo_votor_ag_votor_h

#include "ag_votor_base.h"
#include "ag_bls.h"
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

void
ag_votor_advance_epoch( ag_votor_t * self,
                        ulong        epoch_rank,
                        ulong        epoch_slot );

/* Sets the signing key for the most recently advanced epoch.  If this
   is not called after advancing an epoch, the votor does not vote in
   that epoch.  The caller retains ownership of bls_key and must keep it
   valid for the lifetime of the votor. */

void
ag_votor_set_bls_key( ag_votor_t *       self,
                      ag_bls_sec_t const bls_key );

void
ag_votor_set_shred_version( ag_votor_t * self,
                            ushort       shred_version );

/* init before any event is handled or polled; genesis is slot 0 */

void
ag_votor_init( ag_votor_t * self,
               ulong        slot,
               long         now );

void
ag_votor_fini( ag_votor_t * self );

ag_votor_t *
ag_votor_join( void * mem );

void *
ag_votor_leave( ag_votor_t const * votor );

void *
ag_votor_delete( void * mem );

void
ag_votor_handle_pool_event( ag_votor_t *            self,
                            ag_event_pool_t const * event,
                            long                    now );

void
ag_votor_handle_block_event( ag_votor_t *             self,
                             ag_event_block_t const * event );

void
ag_votor_handle_replay_event( ag_votor_t *              self,
                              ag_event_replay_t const * event );

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
