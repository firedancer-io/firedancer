#ifndef HEADER_fd_src_choreo_votor_fd_votor_loop_h
#define HEADER_fd_src_choreo_votor_fd_votor_loop_h

/* fd_votor_loop describes the API for the Votor event loop.  It applies
   the voting rules of the Alpenglow White Paper v1.2, Section 2.6,
   Algorithms 1 and 2.  The loop is driven by replayed blocks, pool
   events and skip timeouts, and queues the signed votes they produce
   for the caller to broadcast. */

#include "fd_votor_base.h"
#include "../../ballet/bls/fd_bls.h"
#include "fd_votor_pool.h"
#include "fd_votor_hist.h"

typedef struct fd_votor_loop fd_votor_loop_t;

struct fd_votor_loop_metrics {
  ulong slot_state_pool_used;
  ulong slot_state_pool_free;
  ulong highest_final_slot;
  ulong vote_events_cnt;
};
typedef struct fd_votor_loop_metrics fd_votor_loop_metrics_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong
fd_votor_loop_align( void );

FD_FN_CONST ulong
fd_votor_loop_footprint( ulong slot_max );

void *
fd_votor_loop_new( void * mem,
                   ulong  slot_max,
                   ulong  seed );

fd_votor_loop_t *
fd_votor_loop_join( void * mem );

void *
fd_votor_loop_leave( fd_votor_loop_t const * self );

void *
fd_votor_loop_delete( void * mem );

/* fd_votor_loop_init starts votor at root, a finalized block that is
   treated as notarized (Section 2.9).  It does not arm the root
   window's skip timeouts; call fd_votor_loop_arm_skip_timeouts for
   that. */

void
fd_votor_loop_init( fd_votor_loop_t *     self,
                    fd_block_id_t const * root,
                    long                  now,
                    long                  ns_per_slot,
                    ushort                shred_version,
                    fd_bls_sign_fn        sign_fn,
                    void *                sign_ctx );

void
fd_votor_loop_fini( fd_votor_loop_t * self );

FD_FN_PURE fd_votor_loop_metrics_t
fd_votor_loop_metrics( fd_votor_loop_t const * self );

void
fd_votor_loop_advance_epoch( fd_votor_loop_t * self,
                             long              ns_per_slot,
                             ulong             epoch_rank,
                             ulong             epoch_slot,
                             uchar const       bls_key[ FD_BLS_PUB_COMPRESSED_SZ ] );

/* fd_votor_loop_arm_skip_timeouts arms the root window's skip timeouts at
   now.  Split from init so a wait-for-supermajority can arm them at
   the restart instant: set_timeout only lowers a live deadline, so
   timeouts armed at boot cannot be moved out afterwards.  Call once. */

void
fd_votor_loop_arm_skip_timeouts( fd_votor_loop_t * self,
                                 long              now );

void
fd_votor_loop_set_bls_key( fd_votor_loop_t * self,
                           ulong             epoch_slot,
                           uchar const       bls_key[ FD_BLS_PUB_COMPRESSED_SZ ] );

void
fd_votor_loop_update_own_rank( fd_votor_loop_t * self,
                               ulong             epoch_slot,
                               ulong             epoch_rank );

/* Algorithm 1, lines 9-25. Votor::handle_pool_event */

fd_cert_t const *
fd_votor_loop_handle_pool_event( fd_votor_loop_t *             self,
                                 fd_votor_pool_event_t const * event,
                                 long                          now );

/* Algorithm 1, lines 1-5. Votor::handle_blockstore_event, Block */

void
fd_votor_loop_process_replay( fd_votor_loop_t *       self,
                              ulong                   slot,
                              fd_block_info_t const * block_info );

/* fd_votor_loop_advance_cert_wmark raises the first slot worth a vote
   while catching up, from a verified cert at cert_slot past the pool
   window: slot_max behind it, or for a final cert the first slot whose
   reward block follows it.  Below it, state still advances, but votes
   are not signed and certs not broadcast.  Returns the first slot worth
   a vote. */

ulong
fd_votor_loop_advance_cert_wmark( fd_votor_loop_t * self,
                                  ulong             cert_slot,
                                  int               final );

/* Algorithm 1, lines 6-8. Votor::handle_timeout_event */

void
fd_votor_loop_handle_skip_timeout( fd_votor_loop_t * self,
                                   ulong             slot );

int
fd_votor_loop_poll_skip_timeout( fd_votor_loop_t * self,
                                 long              now,
                                 ulong *           slot );

FD_FN_PURE long
fd_votor_loop_next_skip_timeout( fd_votor_loop_t const * self );

int
fd_votor_loop_poll_vote( fd_votor_loop_t * self,
                         fd_vote_t *       vote,
                         uchar *           reason );

/* fd_votor_loop_failover_set_vote_bound stops us voting at or below
   bound, which only moves up.  fd_votor_loop_failover_get_vote_bound
   returns it, ULONG_MAX when none is set. */

void
fd_votor_loop_failover_set_vote_bound( fd_votor_loop_t * self,
                                       ulong             bound );

FD_FN_PURE ulong
fd_votor_loop_failover_get_vote_bound( fd_votor_loop_t const * self );

/* fd_votor_loop_failover_hist_export writes our own votes since the
   anchor into out.  Returns 1 if it had to drop old windows to fit. */

int
fd_votor_loop_failover_hist_export( fd_votor_loop_t * self,
                                    ulong             last_leader_slot,
                                    fd_votor_hist_t * out );

/* fd_votor_loop_failover_hist_adopt merges a valid history into
   initialized slot states.  Returns how many notar hashes disagreed
   with ours, or ULONG_MAX if the retained local and imported slots
   exceed capacity.  Failure leaves consensus state unchanged. */

ulong
fd_votor_loop_failover_hist_adopt( fd_votor_loop_t *       self,
                                   fd_votor_hist_t const * hist );

FD_PROTOTYPES_END

#endif
