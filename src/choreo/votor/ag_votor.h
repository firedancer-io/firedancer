#ifndef HEADER_fd_src_choreo_votor_ag_votor_h
#define HEADER_fd_src_choreo_votor_ag_votor_h

#include "ag_votor_base.h"
#include "../../ballet/bls/fd_bls.h"
#include "ag_event.h"
#include "ag_hist.h"

#define AG_VOTOR_REASON_BLOCK_REPLAYED  (0)
#define AG_VOTOR_REASON_PARENT_READY    (1)
#define AG_VOTOR_REASON_BLOCK_NOTARIZED (2)
#define AG_VOTOR_REASON_TIMEOUT         (3)
#define AG_VOTOR_REASON_SAFE_TO_NOTAR   (4)
#define AG_VOTOR_REASON_SAFE_TO_SKIP    (5)

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

/* ag_votor_set_keys replaces our rank and BLS key in the three epochs
   the votor tracks, for an identity switch.  USHORT_MAX is unranked,
   and a NULL bls_pubkey disables voting in that epoch. */

void
ag_votor_set_keys( ag_votor_t *  self,
                   ulong         prev_epoch_rank,
                   uchar const * prev_bls_pubkey,
                   ulong         curr_epoch_rank,
                   uchar const * curr_bls_pubkey,
                   ulong         next_epoch_rank,
                   uchar const * next_bls_pubkey );

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

/* ag_votor_set_vote_bound stops us casting any vote, notar, skip,
   fallback or final, on a slot at or below bound.  An empty adopted
   history sets it, and an adopted history raises it to the exporter's.
   The bound only moves up and must not be ULONG_MAX.
   ag_votor_vote_bound returns it, ULONG_MAX when none is set. */

void
ag_votor_set_vote_bound( ag_votor_t * self,
                         ulong        bound );

FD_FN_PURE ulong
ag_votor_vote_bound( ag_votor_t const * self );

/* ag_votor_mark_unsent records that a vote we built never left the
   machine.  The slot stays voted and gets the bad window flag, so no
   final vote follows.  A dropped notar also loses its notar mark, so it
   cannot become the parent of a later notar nobody saw.  A dropped
   notar on a slot whose notar mark was adopted changes nothing. */

void
ag_votor_mark_unsent( ag_votor_t *      self,
                      ag_vote_t const * vote );

/* ag_votor_hist_export writes our own votes since the anchor into out,
   with last_leader_slot as given and our vote bound.  If more than
   AG_HIST_MAX slots were voted it drops whole windows from the bottom
   and lifts the anchor so the frame stays complete relative to it, and
   returns 1.  Returns 0 otherwise. */

int
ag_votor_hist_export( ag_votor_t * self,
                      ulong        last_leader_slot,
                      ag_hist_t *  out );

/* ag_votor_hist_adopt moves the anchor to the history's, raises our
   vote bound to the history's and ORs its records into our slot states,
   so we never vote against what the exporter already sent as this
   identity.  Our own marks are kept.  Returns how many notar hashes
   disagreed with our own, theirs win. */

ulong
ag_votor_hist_adopt( ag_votor_t *      self,
                     ag_hist_t const * hist );

/* Algorithm 1, lines 9-25. Votor::handle_pool_event */

void
ag_votor_handle_pool_event( ag_votor_t *            self,
                            ag_event_pool_t const * event,
                            long                    now );

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
