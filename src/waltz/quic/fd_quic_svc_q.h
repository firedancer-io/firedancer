#ifndef HEADER_fd_src_waltz_quic_fd_quic_svc_q_h
#define HEADER_fd_src_waltz_quic_fd_quic_svc_q_h

#include "fd_quic_common.h"

/* sentinel index */
#define FD_QUIC_SVC_IDX_INVAL  (~0UL)

struct fd_quic_svc_timers_conn_meta {
  ulong idx;           /* points to idx in heap, caller should not modify */
  ulong next_timeout;  /* next timeout for this connection */
};
typedef struct fd_quic_svc_timers_conn_meta fd_quic_svc_timers_conn_meta_t;

/* Event structure stored in timers */
struct __attribute__((packed)) fd_quic_svc_event {
  ulong timeout;
  fd_quic_conn_t * conn;
};
typedef struct fd_quic_svc_event fd_quic_svc_event_t;

/* the timers state
   Because it's only prq* rn, we avoid an extra pointer deref
   by just aliasing. If adding new fields, switch back to struct
   and make sure to update footprint, align, and init functions.
   struct fd_quic_svc_timers {
      fd_quic_svc_event_t * prq;
   };
   typedef struct fd_quic_svc_timers fd_quic_svc_timers_t;
*/
typedef fd_quic_svc_event_t fd_quic_svc_timers_t;

/* Setup functions ****************************************************/

/* fd_quic_svc_timers_footprint returns the footprint of the timers */
ulong
fd_quic_svc_timers_footprint( ulong max_conn );

/* fd_quic_svc_timers_align returns the alignment of the timers */
ulong
fd_quic_svc_timers_align( void );

/* fd_quic_svc_timers_init initializes the timers
   mem is a pointer to ALIGNED memory to initialize
   max_conn is the maximum number of connections to support
   NOT JUST A SIMPLE POINTER CAST FROM mem */
fd_quic_svc_timers_t *
fd_quic_svc_timers_init( void * mem,
                         ulong  max_conn );

/* fd_quic_svc_timers_init_conn initializes the conn_meta in this conn */
void
fd_quic_svc_timers_init_conn( fd_quic_conn_t * conn );

/* Public functions ***************************************************/

/* fd_quic_svc_schedule schedules a connection timer.
   Uses conn->svc_meta.next_timeout as the expiry time.
   If already scheduled, keeps the earlier time. */
void
fd_quic_svc_schedule( fd_quic_svc_timers_t * timers,
                      fd_quic_conn_t       * conn );

/* fd_quic_svc_timers_validate checks that events and
    connections point to each other
   returns 1 if valid, 0 otherwise */
int
fd_quic_svc_timers_validate( fd_quic_svc_timers_t * timers,
                             fd_quic_t            * quic );

/* fd_quic_svc_cancel removes a connection from the service queue */
void
fd_quic_svc_cancel( fd_quic_svc_timers_t * timers,
                    fd_quic_conn_t       * conn );

/* fd_quic_svc_timers_next returns next event. If 'pop' is true,
   the event (if in past) is popped from the queue. If next event
   is in the future with pop=true, will return none!
   If pop is false, event will remain enqueued and may be in the future.
   Returns NULL conn if queue empty. */
fd_quic_svc_event_t
fd_quic_svc_timers_next( fd_quic_svc_timers_t * timers,
                         ulong                  now,
                         int                    pop );


/* fd_quic_svc_get_event returns pointer to event for a given conn
   returns NULL if not found */
fd_quic_svc_event_t*
fd_quic_svc_get_event( fd_quic_svc_timers_t * timers,
                       fd_quic_conn_t       * conn );

#endif /* HEADER_fd_src_waltz_quic_fd_quic_svc_q_h */
