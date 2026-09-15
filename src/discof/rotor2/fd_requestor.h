#ifndef HEADER_fd_src_discof_rotor2_fd_requestor_h
#define HEADER_fd_src_discof_rotor2_fd_requestor_h

/* fd_requestor turns a check of one slot version into repair requests.
   It consumes schedulor events (CHECK_SLOT), reads the chainer, and
   fills an internal queue with every request the version needs, all
   at once.  The tile then drains that queue one request per
   after_credit through poll_request_event.  Once the queue is empty
   the requestor reports an outcome the schedulor uses to decide when
   to check the version again.

   The requestor works one version at a time.  The tile learns it is
   idle from the polls themselves: poll_request_event returning 0 means
   the queue is drained, and poll_requestor_event returning 0 after that
   means no outcome is pending, so a new CHECK_SLOT may be handed over.

   The request priority is as follows:

     0. The version is gone (no slotv, at or below the root, or
        abandoned): DONE, no requests.

     1. Metadata.  One request, then REQUESTED_PARENT:
          parent unknown        verified: ParentAndFecSetCount
                                turbine:  Shred idx 0 (its header names the parent)
          parent known, absent  Orphan (asks peers for the ancestry)
          complete_idx unknown  verified: ParentAndFecSetCount
                                turbine:  HighestShred

     2. Fill.  Every missing shred past the buffered prefix, then
        REQUESTED if anything was queued or DONE if nothing was missing:
          has_block_id, no entry at the set   one FecSetRoot for the set
          has_block_id, shred missing         ShredForBlockId
          turbine,      shred missing         Shred

   Legacy requests (Shred, HighestShred, Orphan) are suppressed when
   block_id_only is set; that is a development flag for exercising
   block-id repair in isolation.

   Because a full block's requests take many after_credits to drain,
   the chainer keeps moving while they wait.  poll_request_event skips
   any queued request that fd_requestor_stale says is no longer needed,
   and the outcome is only reported after the last request leaves. */

#include "fd_rotor_event.h"
#include "../chainer/fd_chainer.h"

typedef struct fd_requestor fd_requestor_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong
fd_requestor_align( void );

/* fd_requestor_footprint returns the footprint for a request queue of
   request_max entries.  One check queues at most one request per
   missing shred, so max_shreds_per_block is the right bound for a
   single version.  Returns 0 if request_max is 0 or too large. */

FD_FN_CONST ulong
fd_requestor_footprint( ulong request_max );

void *
fd_requestor_new( void * mem,
                  ulong  request_max );

fd_requestor_t *
fd_requestor_join( void * mem );

void *
fd_requestor_leave( fd_requestor_t const * requestor );

void *
fd_requestor_delete( void * mem );

/* fd_requestor_set_block_id_only suppresses legacy request kinds
   (development only). */

void
fd_requestor_set_block_id_only( fd_requestor_t * self,
                                int              block_id_only );

/* fd_requestor_queued_cnt returns the number of requests waiting to be
   polled. */

ulong
fd_requestor_queued_cnt( fd_requestor_t const * self );

/* fd_requestor_handle_schedulor_event runs a full check of the version
   named by a CHECK_SLOT against chainer: every request the version
   needs is queued and the outcome recorded.  Fatal if the requestor is
   busy.  now stamps the queued requests. */

void
fd_requestor_handle_schedulor_event( fd_requestor_t *             self,
                                     fd_chainer_t *               chainer,
                                     fd_event_schedulor_t const * event,
                                     long                         now );

/* fd_requestor_handle_chainer_event drops the queued requests and
   reports DONE when the chainer retires the version being worked
   (SLOT_RETIRED for that key).  Maybe consume SLOT_COMPLETE as well.  */

void
fd_requestor_handle_chainer_event( fd_requestor_t *           self,
                                   fd_event_chainer_t const * event );

/* fd_requestor_stale returns 1 if request no longer needs to be sent
   given the chainer's current state: the version is gone, or the
   shred / FEC root / metadata it asks for has arrived since it was
   queued.  Returns 0 if it should still go out. */

int
fd_requestor_stale( fd_chainer_t *             chainer,
                    fd_event_request_t const * request );

/* fd_requestor_poll_request_event pops the next queued request that is
   not stale into *event and returns 1.  Returns 0 once the queue is
   empty, in which case poll_requestor_event has the outcome.  now
   stamps the event. */

int
fd_requestor_poll_request_event( fd_requestor_t *     self,
                                 fd_chainer_t *       chainer,
                                 long                 now,
                                 fd_event_request_t * event );

/* fd_requestor_poll_requestor_event fills *event with the outcome of
   the finished check once its queue has drained, releases the version
   and returns 1.  Returns 0 while requests are still queued or nothing
   is pending. */

int
fd_requestor_poll_requestor_event( fd_requestor_t *       self,
                                   long                   now,
                                   fd_event_requestor_t * event );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_rotor2_fd_requestor_h */
