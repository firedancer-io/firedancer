#include "fd_quic_svc_q.h"
#include "fd_quic_private.h"
#include "fd_quic_conn.h"

/* PRIVATE ************************************************/

#define PRQ_NAME fd_quic_svc_queue_prq
#define PRQ_T    fd_quic_svc_event_t
#define PRQ_TMP_ST(p,t) do { \
                         (p)[0] = (t); \
                         t.conn->svc_meta.idx = (ulong)((p)-heap); \
                       } while( 0 )
#define PRQ_TIMEOUT_T ulong
#include "../../util/tmpl/fd_prq.c"
typedef fd_quic_svc_event_t fd_quic_svc_queue_prq_t;


/* SETUP FUNCTIONS *************************************************/

ulong
fd_quic_svc_timers_footprint( ulong max_conn ) {
  ulong offset = 0UL;
  offset       = fd_ulong_align_up( offset, fd_quic_svc_queue_prq_align() );
  offset      += fd_quic_svc_queue_prq_footprint( max_conn );
  return offset;
}

ulong
fd_quic_svc_timers_align( void ) {
  return fd_ulong_max( alignof( fd_quic_svc_timers_t ),
                      fd_quic_svc_queue_prq_align() );
}

fd_quic_svc_timers_t *
fd_quic_svc_timers_init( void * mem,
                         ulong  max_conn ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_ERR(( "fd_quic_svc_timers_init called with NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_quic_svc_timers_align() ) ) ) {
    FD_LOG_ERR(( "fd_quic_svc_timers_init called with misaligned mem" ));
    return NULL;
  }

  fd_quic_svc_event_t* prq =  fd_quic_svc_queue_prq_join(
                                fd_quic_svc_queue_prq_new( (uchar *)mem, max_conn )
                              );
  if( FD_UNLIKELY( !prq ) ) {
    FD_LOG_ERR(( "fd_quic_svc_timers_init failed to join prq" ));
  }

  return prq;
}

void
fd_quic_svc_timers_init_conn( fd_quic_conn_t * conn ) {
  conn->svc_meta.idx          = FD_QUIC_SVC_IDX_INVAL;
  conn->svc_meta.next_timeout = ULONG_MAX;
}

/* END SETUP FUNCTIONS *********************************************/

/* TASK FUNCTIONS *************************************************/

void
fd_quic_svc_cancel( fd_quic_svc_timers_t * timers,
                    fd_quic_conn_t       * conn ) {
  if( FD_UNLIKELY( conn->svc_meta.idx == FD_QUIC_SVC_IDX_INVAL ) ) {
    return;
  }

  fd_quic_svc_queue_prq_remove( timers, conn->svc_meta.idx );
  conn->svc_meta.idx = FD_QUIC_SVC_IDX_INVAL;
}

void
fd_quic_svc_schedule( fd_quic_svc_timers_t * timers,
                      fd_quic_conn_t       * conn ) {
  ulong idx    = conn->svc_meta.idx;
  ulong expiry = conn->svc_meta.next_timeout;

  if( FD_UNLIKELY( idx != FD_QUIC_SVC_IDX_INVAL ) ) {
    /* find current expiry */
    fd_quic_svc_event_t * event      = timers + idx;
    ulong                 cur_expiry = event->timeout;

    if( FD_LIKELY( cur_expiry == expiry ) ) {
      return;
    } else if( cur_expiry < expiry ) {
      return;
    } else {
      fd_quic_svc_queue_prq_remove( timers, idx );
      conn->svc_meta.idx = FD_QUIC_SVC_IDX_INVAL;
    }
  }

  /* insert new element */
  fd_quic_svc_event_t e = {
    .conn    = conn,
    .timeout = expiry
  };
  fd_quic_svc_queue_prq_insert( timers, &e );
}

int
fd_quic_svc_timers_validate( fd_quic_svc_timers_t * timers,
                             fd_quic_t            * quic ) {
  fd_quic_state_t * state = fd_quic_get_state( quic );
  ulong             cnt   = fd_quic_svc_queue_prq_cnt( timers );

  for( ulong i = 0; i < cnt; i++ ) {
    fd_quic_svc_event_t * event = timers + i;

    /* conn and idx match */
    if( FD_UNLIKELY( event->conn->svc_meta.idx != i ) ) return 0;

    /* conn in prq at most once */
    if( FD_UNLIKELY( event->conn->visited ) ) return 0;
    event->conn->visited = 1U;
  }

  /* connections not in prq have INVALID idx */
  for( ulong i = 0; i < quic->limits.conn_cnt; i++ ) {
    fd_quic_conn_t * conn = fd_quic_conn_at_idx( state, i );
    if( !conn->visited && conn->svc_meta.idx != FD_QUIC_SVC_IDX_INVAL ) return 0;
  }

  return 1;
}

fd_quic_svc_event_t
fd_quic_svc_timers_next( fd_quic_svc_timers_t * timers,
                         ulong                  now,
                         int                    pop ) {
  fd_quic_svc_event_t next = { .timeout = ULONG_MAX, .conn = NULL };

  if( FD_UNLIKELY( fd_quic_svc_queue_prq_cnt( timers ) == 0 )) {
    return next;
  }

  if( FD_LIKELY( pop ) ) {
    if( FD_UNLIKELY( now < timers[0].timeout ) ) {
      return next;
    }
    next                    = timers[0];
    next.conn->svc_meta.idx = FD_QUIC_SVC_IDX_INVAL;
    fd_quic_svc_queue_prq_remove_min( timers );
  } else {
    next = timers[0];
  }

  return next;
}

fd_quic_svc_event_t*
fd_quic_svc_get_event( fd_quic_svc_timers_t * timers,
                       fd_quic_conn_t       * conn ) {
  ulong idx = conn->svc_meta.idx;
  if( idx == FD_QUIC_SVC_IDX_INVAL ) return NULL;
  return timers + idx;
}
