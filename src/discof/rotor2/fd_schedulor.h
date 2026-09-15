#ifndef HEADER_fd_src_discof_rotor2_fd_schedulor_h
#define HEADER_fd_src_discof_rotor2_fd_schedulor_h

/* fd_schedulor is the repair scheduler.  It consumes chainer events and
   requestor events and emits scheduler events (see fd_rotor_event.h).
   It keeps at most one pending check per slot of interest, orders the
   checks by timeout, and decides how long a slotv sleeps from what the
   requestor reports it did.

   When a queued task becomes due it is popped, handed to the requestor
   as SCHEDULOR_CHECK_SLOT, and forgotten: the requestor owns everything
   about the check from then on.

     CHAINER_SLOT_ADDED    queue the unique slot's task due now
     CHAINER_FEC_EVICTED   queue due now, or pull an existing timeout
                           to now
     CHAINER_SLOT_RETIRED  drop the task if queued

     poll_schedulor_event  pop the earliest due task as CHECK_SLOT

     REQUESTOR_REQUESTED_PARENT  queue after the parent timeout
     REQUESTOR_REQUESTED         queue after the request timeout
     REQUESTOR_DONE              nothing: the slotv needs nothing now

   Because the schedulor forgets a popped task, a chainer event for a
   slotv the requestor is currently working on just queues it again,
   due now.  That is the intended behaviour: new work landed, so the
   slotv is rechecked as soon as the requestor is free.

   Timeouts are floored to FD_SCHEDULOR_QUANTUM_NS so tasks due in the
   same quantum are served lowest slot first, which keeps repair
   root-first among whatever is currently due. */

#include "fd_rotor_event.h"

#define FD_SCHEDULOR_QUANTUM_NS         ( 10000000L) /* 10 ms: timeout granularity, ties served lowest slot first        */
#define FD_SCHEDULOR_PARENT_TIMEOUT_NS  ( 50000000L) /* 50 ms: recheck after a parent was requested                       */
#define FD_SCHEDULOR_REQUEST_TIMEOUT_NS ( 80000000L) /* 80 ms: recheck after a fill pass, matches the legacy dedup window */

typedef struct fd_schedulor fd_schedulor_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong
fd_schedulor_align( void );

/* fd_schedulor_footprint returns the footprint for slotv_max tasks,
   which must equal the chainer's slotv pool max.  Returns 0 if
   slotv_max is 0 or too large. */

FD_FN_CONST ulong
fd_schedulor_footprint( ulong slotv_max );

void *
fd_schedulor_new( void * mem,
                  ulong  slotv_max,
                  ulong  seed );

fd_schedulor_t *
fd_schedulor_join( void * mem );

void *
fd_schedulor_leave( fd_schedulor_t const * schedulor );

void *
fd_schedulor_delete( void * mem );

void
fd_schedulor_handle_chainer_event( fd_schedulor_t *           self,
                                   fd_event_chainer_t const * event );

void
fd_schedulor_handle_requestor_event( fd_schedulor_t *             self,
                                     fd_event_requestor_t const * event,
                                     long                         now );

/* fd_schedulor_poll_schedulor_event pops the earliest task due at or
   before now and returns 1.  Returns 0 if nothing is due. The caller
   must not poll while the requestor is busy. */

int
fd_schedulor_poll_schedulor_event( fd_schedulor_t *       self,
                                   long                   now,
                                   fd_event_schedulor_t * event );

/* Introspection, for tests and metrics. */

ulong
fd_schedulor_queued_cnt( fd_schedulor_t const * self );

long
fd_schedulor_next_timeout( fd_schedulor_t const * self );

int
fd_schedulor_verify( fd_schedulor_t const * self );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_discof_rotor2_fd_schedulor_h */
