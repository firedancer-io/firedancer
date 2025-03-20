#ifndef HEADER_fd_src_waltz_quic_fd_quic_svc_q_h
#define HEADER_fd_src_waltz_quic_fd_quic_svc_q_h

#include "fd_quic_common.h"
/* FD_QUIC_SVC_{...} specify connection timer types. */

/* Larger constant --> higher priority for tie-breaking */
#define FD_QUIC_SVC_IDLE       (0U)  /* idle timeout */
#define FD_QUIC_SVC_RTT_SAMPLE (1U)  /* RTT timeout */
#define FD_QUIC_SVC_RETX       (2U)  /* retransmission timeout */
#define FD_QUIC_SVC_ACK_TX     (3U)  /* within local max_ack_delay (ACK TX coalesce) */
#define FD_QUIC_SVC_INSTANT    (4U)  /* as soon as possible */
#define FD_QUIC_SVC_CNT        (5U)  /* number of FD_QUIC_SVC_{...} levels */

/* sentinel index */
#define FD_QUIC_SVC_IDX_INVAL  (~0UL)

struct fd_quic_svc_timers_conn_meta {
  /* idx into prq for prq-type,
     into backing pool for dlist-type */
  ulong idx[FD_QUIC_SVC_CNT]; /* unsafe to modify directly in live conn */
};
typedef struct fd_quic_svc_timers_conn_meta fd_quic_svc_timers_conn_meta_t;

/* the public state of the timers */
struct fd_quic_svc_timers {
  ulong default_timeouts[ FD_QUIC_SVC_CNT ]; /* set by user, default duration */
};
typedef struct fd_quic_svc_timers fd_quic_svc_timers_t;

/* Event structure stored in timers */
struct __attribute__((packed)) fd_quic_svc_event {
  ulong timeout;
  fd_quic_conn_t * conn;
  uint svc_type;

  /* linked list garbage */
  uint prev;
  uint next;
  uint _;
};
typedef struct fd_quic_svc_event fd_quic_svc_event_t;

/* Setup functions ****************************************************/

/* fd_quic_svc_timers_footprint returns the footprint of the timers */
ulong
fd_quic_svc_timers_footprint( ulong max_conn );

/* fd_quic_svc_timers_align returns the alignment of the timers */
ulong
fd_quic_svc_timers_align( void );

/* fd_quic_svc_timers_init initializes the timers
   mem is a pointer to ALIGNED memory to initialize
   max_conn is the maximum number of connections to support */
fd_quic_svc_timers_t*
fd_quic_svc_timers_init( void* mem,
                         ulong max_conn );

/* fd_quic_svc_timers_init_conn initializes the conn_meta in this conn */
void
fd_quic_svc_timers_init_conn( fd_quic_conn_t * conn );


/* Public functions ***************************************************/

/* fd_quic_svc_schedule installs a connection timer.  svc_type is in
   [0,FD_QUIC_SVC_CNT), and expiry is the TIME of timeout.
   Lower timers override higher ones. Higher timers get no-oped.
   Service types are independent */

void
fd_quic_svc_schedule( fd_quic_svc_timers_t * timers,
                      fd_quic_conn_t       * conn,
                      uint                   svc_type,
                      ulong                  expiry     );


/* fd_quic_svc_schedule_later is like fd_quic_svc_schedule, but keeps
   the later timer instead of earlier one. */

void
fd_quic_svc_schedule_later( fd_quic_svc_timers_t * timers,
                            fd_quic_conn_t       * conn,
                            uint                   svc_type,
                            ulong                  expiry     );

/* fd_quic_svc_schedule_default is like fd_quic_svc_schedule, but uses
   the default timeout for the given svc_type. */

static inline void
fd_quic_svc_schedule_default( fd_quic_svc_timers_t * timers,
                               fd_quic_conn_t      * conn,
                               uint                  svc_type,
                               ulong                 now       ) {
  fd_quic_svc_schedule( timers, conn, svc_type, now + timers->default_timeouts[ svc_type ] );
}

/* fd_quic_svc_schedule_later_default is like
   fd_quic_svc_schedule_later, but uses the default timeout for the
   given svc_type. */

static inline void
fd_quic_svc_schedule_later_default( fd_quic_svc_timers_t * timers,
                                     fd_quic_conn_t      * conn,
                                     uint                  svc_type,
                                     ulong                 now       ) {
  fd_quic_svc_schedule_later( timers, conn, svc_type, now + timers->default_timeouts[ svc_type ] );
}

/* fd_quic_svc_timers_validate checks the following:
   - event and its connection point to each other
   - dlists are ordered by expiry
   returns 1 if valid, 0 otherwise */
int
fd_quic_svc_timers_validate( fd_quic_svc_timers_t * timers );

/* fd_quic_svc_cancel removes a connection from the given service queue. */
void
fd_quic_svc_cancel( fd_quic_svc_timers_t * timers,
                    fd_quic_conn_t       * conn,
                    uint                   svc_type );

/* fd_quic_svc_cancel removes a connection from all service queues */
static inline void
fd_quic_svc_cancel_all( fd_quic_svc_timers_t * timers,
                        fd_quic_conn_t       * conn ) {
  for( uint i = 0; i < FD_QUIC_SVC_CNT; i++ ) {
    fd_quic_svc_cancel( timers, conn, i );
  }
}

/* fd_quic_svc_timers_next returns next event. If 'pop' is true,
   the event is popped from the queue. It will be in the past!
   If pop is false, event won't be popped and may be in the future.
   Returns .svc_type==FD_QUIC_SVC_CNT if queue empty.
   Returns lowest timestamp across all event types
   If timestamp same, larger svc_type is returned */
fd_quic_svc_event_t
fd_quic_svc_timers_next( fd_quic_svc_timers_t * timers,
                         ulong                  now,
                         int                    pop );


#endif /* HEADER_fd_src_waltz_quic_fd_quic_svc_q_h */
