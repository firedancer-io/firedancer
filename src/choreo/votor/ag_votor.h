#ifndef HEADER_fd_src_choreo_votor_ag_votor_h
#define HEADER_fd_src_choreo_votor_ag_votor_h

#include "ag_votor_base.h"
#include "../../ballet/bls/fd_bls.h"
#include "ag_event.h"
#include "ag_hist.h"

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

/* ag_votor_set_ranks replaces our rank in the three epochs the votor
   tracks, for an identity switch.  USHORT_MAX is unranked. */

void
ag_votor_set_ranks( ag_votor_t * self,
                    ulong        prev_epoch_rank,
                    ulong        curr_epoch_rank,
                    ulong        next_epoch_rank );

/* ag_votor_highest_final_cert_slot is the finality anchor, ULONG_MAX
   before init.  ag_votor_first_unpruned_slot is the lowest slot the
   votor still tracks.  ag_votor_has_voted says whether we cast any vote
   on slot. */

FD_FN_PURE ulong
ag_votor_highest_final_cert_slot( ag_votor_t const * self );

FD_FN_PURE ulong
ag_votor_first_unpruned_slot( ag_votor_t const * self );

FD_FN_PURE int
ag_votor_has_voted( ag_votor_t const * self,
                    ulong              slot );

/* ag_votor_mark_unsent records that a vote we built never left the
   machine.  The slot stays voted and gets the bad window flag, so no
   final vote follows.  A dropped notar also loses its notar mark, so it
   cannot become the parent of a later notar nobody saw. */

void
ag_votor_mark_unsent( ag_votor_t *      self,
                      ag_vote_t const * vote );

/* ag_votor_advance_root moves the finality anchor to slot and prunes
   below it, for a node that learns finality from replay rather than
   from certs.  Nothing happens if slot is not past the anchor. */

void
ag_votor_advance_root( ag_votor_t * self,
                       ulong        slot );

/* ag_votor_hist_export writes our own votes since the anchor into out,
   with last_leader_slot as given.  If more than AG_HIST_MAX slots were
   voted it drops whole windows from the bottom and lifts the anchor so
   the frame stays complete relative to it, and returns 1.  Returns 0
   otherwise. */

int
ag_votor_hist_export( ag_votor_t * self,
                      ulong        last_leader_slot,
                      ag_hist_t *  out );

/* ag_votor_hist_adopt moves the anchor to the history's and ORs its
   records into our slot states, so we never vote against what the
   exporter already sent as this identity.  Our own marks are kept.
   Returns how many notar hashes disagreed with our own, theirs win. */

ulong
ag_votor_hist_adopt( ag_votor_t *      self,
                     ag_hist_t const * hist );

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
