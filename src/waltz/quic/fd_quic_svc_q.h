#ifndef HEADER_fd_src_waltz_quic_fd_quic_svc_q_h
#define HEADER_fd_src_waltz_quic_fd_quic_svc_q_h

#include "fd_quic_common.h"

/* service queue types */
#define FD_QUIC_SVC_INSTANT (0U)  /* as soon as possible */
#define FD_QUIC_SVC_TIMEOUT (1U)  /* timeout - never serviced, a graveyard */
#define FD_QUIC_SVC_DYNAMIC (2U)  /* some dynamic amount of time */
#define FD_QUIC_SVC_CNT     (3U)  /* number of FD_QUIC_SVC_{...} levels */

/* sentinel index */
#define FD_QUIC_SVC_PRQ_IDX_INVAL   (~0UL)
#define FD_QUIC_SVC_DLIST_IDX_INVAL (~0U)

/* fd_quic_svc_queue_t is a dlist. */
struct fd_quic_svc_queue {
   uint cnt;
   uint head;
   uint tail;
 };

typedef struct fd_quic_svc_queue fd_quic_svc_queue_t;

struct fd_quic_svc_timers_conn_meta {
  ulong next_timeout;  /* next timeout for this connection */
  struct {
    union {
      ulong prq_idx;         /* only non-IDX_INVALID when in prq*/
      struct {
        uint  next;          /* next connection in dlist */
        uint  prev;          /* prev connection in dlist */
      } dlist; /* only used for dlist */
    };
    uint  svc_type;      /* FD_QUIC_SVC_* */
  } private;
};
typedef struct fd_quic_svc_timers_conn_meta fd_quic_svc_timers_conn_meta_t;

/* Event structure stored in timers */
struct __attribute__((packed)) fd_quic_svc_event {
  ulong            timeout;
  fd_quic_conn_t * conn;
};
typedef struct fd_quic_svc_event fd_quic_svc_event_t;

/* the timers struct */
struct fd_quic_svc_timers {
  fd_quic_svc_event_t * prq;         /* priority queue for DYNAMIC timers */
  fd_quic_svc_queue_t   queues[2];  /* INSTANT and TIMEOUT queue (dlist) */
  fd_quic_state_t     * state;       /* state pointer */
};
typedef struct fd_quic_svc_timers fd_quic_svc_timers_t;

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
   NOT JUST A SIMPLE POINTER CAST FROM mem
   Retains a read interest in state throughout lifetime */
fd_quic_svc_timers_t *
fd_quic_svc_timers_init( void            * mem,
                         ulong             max_conn,
                         fd_quic_state_t * state );

/* fd_quic_svc_timers_init_conn initializes the conn_meta in this conn */
void
fd_quic_svc_timers_init_conn( fd_quic_conn_t * conn );

/* Public functions ***************************************************/

/* fd_quic_svc_schedule schedules a connection timer.
   Uses conn->svc_meta.next_timeout as the expiry time.
   If next_timeout==ULONG_MAX, conn will never be serviced. */
void
fd_quic_svc_schedule( fd_quic_svc_timers_t * timers,
                      fd_quic_conn_t       * conn,
                      ulong                  now );

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
   the event (if in past) is popped from the queue, and next_timeout
   is reset to ULONG_MAX. If next event is in the future with pop=true,
   will return none! If pop is false, event will remain enqueued and
   may be in the future. Returns NULL conn if queue empty. */
fd_quic_svc_event_t
fd_quic_svc_timers_next( fd_quic_svc_timers_t * timers,
                         ulong                  now,
                         int                    pop );

/* fd_quic_svc_get_event returns event for a given conn
   returns event with conn==NULL if not found */
fd_quic_svc_event_t
fd_quic_svc_get_event( fd_quic_svc_timers_t * timers,
                       fd_quic_conn_t       * conn,
                       ulong                  now );


/* fd_quic_svc_cnt_events returns the number of conns with active timers
   Primarily used for testing/validation. */
ulong
fd_quic_svc_cnt_events( fd_quic_svc_timers_t * timers );

/* fd_quic_svc_timeout_pop removes and returns next connection from timeout queue
   Returns NULL if timeout queue is empty */
fd_quic_conn_t *
fd_quic_svc_timeout_pop( fd_quic_svc_timers_t * timers );

/* fd_quic_svc_timeout_empty returns 1 if timeout queue is empty, 0 otherwise */
int
fd_quic_svc_timeout_empty( fd_quic_svc_timers_t * timers );

#endif /* HEADER_fd_src_waltz_quic_fd_quic_svc_q_h */
