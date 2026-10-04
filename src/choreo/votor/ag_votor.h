#ifndef HEADER_fd_src_choreo_votor_ag_votor_h
#define HEADER_fd_src_choreo_votor_ag_votor_h

#include "ag_votor_base.h"
#include "../../ballet/bls/fd_bls.h"
#include "ag_pool.h"

#define AG_VOTOR_REASON_BLOCK_REPLAYED  (0)
#define AG_VOTOR_REASON_PARENT_READY    (1)
#define AG_VOTOR_REASON_BLOCK_NOTARIZED (2)
#define AG_VOTOR_REASON_TIMEOUT         (3)
#define AG_VOTOR_REASON_SAFE_TO_NOTAR   (4)
#define AG_VOTOR_REASON_SAFE_TO_SKIP    (5)

typedef struct ag_votor ag_votor_t;

struct ag_votor_metrics {
  ulong slot_state_pool_used;
  ulong slot_state_pool_free;
  ulong highest_final_cert_slot;
  ulong vote_events_cnt;
};
typedef struct ag_votor_metrics ag_votor_metrics_t;

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

/* ag_votor_init starts votor at root, a finalized block that is
   treated as notarized (Section 2.9). */

void
ag_votor_init( ag_votor_t *          self,
               ag_block_id_t const * root,
               long                  now,
               long                  ns_per_slot,
               ushort                shred_version,
               fd_bls_sign_fn        sign_fn,
               void *                sign_ctx );

void
ag_votor_fini( ag_votor_t * self );

FD_FN_PURE ag_votor_metrics_t
ag_votor_metrics( ag_votor_t const * self );

/* ag_votor_advance_epoch is called at boot and the epoch boundary and
   updates the rank and BLS key that is used for voting.  A NULL bls
   pubkey will disable voting for the epoch corresponding to the
   epoch_slot. */

void
ag_votor_advance_epoch( ag_votor_t *       self,
                        long               ns_per_slot,
                        ulong              epoch_rank,
                        ulong              epoch_slot,
                        ag_bls_key_t const bls_key );

/* ag_votor_set_bls_key updates the BLS key that is used for voting,
   or stops voting if the BLS key is NULL.  It should be called when
   authorized voters change.  Votes made while there was no key are
   never sent. */

void
ag_votor_set_bls_key( ag_votor_t *       self,
                      ulong              epoch_slot,
                      ag_bls_key_t const bls_key );

/* Replaces our rank in the epoch starting at epoch_slot, for when our
   identity changes after the epoch advanced. */

void
ag_votor_set_rank( ag_votor_t * self,
                   ulong        epoch_slot,
                   ulong        epoch_rank );

/* ag_votor_wait_to_vote is called when our identity changes.  Votor
   signs no more votes up to the end of the window of the highest slot
   it voted notar or skip in, since the new identity may have voted in
   that window on another machine.  Like Agave's --wait-to-vote-slot. */

void
ag_votor_wait_to_vote( ag_votor_t * self );

/* Algorithm 1, lines 9-25. Votor::handle_pool_event */

void
ag_votor_handle_pool_event( ag_votor_t *            self,
                            ag_pool_event_t const * event,
                            long                    now );

/* Algorithm 1, lines 1-5. Votor::handle_blockstore_event, Block */

void
ag_votor_process_replay( ag_votor_t *            self,
                         ulong                   slot,
                         ag_block_info_t const * block_info );

/* Algorithm 1, lines 6-8. Votor::handle_timeout_event */

void
ag_votor_handle_skip_timeout( ag_votor_t * self,
                              ulong        slot );

int
ag_votor_poll_skip_timeout( ag_votor_t * self,
                            long         now,
                            ulong *      slot );

FD_FN_PURE long
ag_votor_next_skip_timeout( ag_votor_t const * self );

int
ag_votor_poll_vote( ag_votor_t * self,
                    ag_vote_t *  vote,
                    uchar *      reason );

int
ag_votor_poll_cert( ag_votor_t * self,
                    ag_cert_t *  cert );

FD_PROTOTYPES_END

#endif
