#include "fd_quic_svc_q.h"
#include "fd_quic_private.h"
#include "fd_quic_conn.h"

/* PRIVATE ************************************************/

#define PRQ_NAME fd_quic_svc_queue_prq
#define PRQ_T    fd_quic_svc_event_t
#define PRQ_TMP_ST(p,t) do { \
                         (p)[0] = (t); \
                         t.conn->svc_meta.private.prq_idx = (ulong)((p)-heap); \
                       } while( 0 )
#define PRQ_TIMEOUT_T ulong
#include "../../util/tmpl/fd_prq.c"
typedef fd_quic_svc_event_t fd_quic_svc_queue_prq_t;


/* SETUP FUNCTIONS *************************************************/

ulong
fd_quic_svc_timers_footprint( ulong max_conn ) {

  return FD_LAYOUT_FINI( FD_LAYOUT_APPEND( FD_LAYOUT_APPEND( FD_LAYOUT_INIT,
            sizeof(fd_quic_svc_timers_t), alignof(fd_quic_svc_timers_t) ),
            fd_quic_svc_queue_prq_align(), fd_quic_svc_queue_prq_footprint( max_conn ) ),
         fd_quic_svc_timers_align() );
}

ulong
fd_quic_svc_timers_align( void ) {
  return fd_ulong_max( alignof( fd_quic_svc_timers_t ),
                      fd_quic_svc_queue_prq_align() );
}

fd_quic_svc_timers_t *
fd_quic_svc_timers_init( void            * mem,
                         ulong             max_conn,
                         fd_quic_state_t * state ) {
  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_ERR(( "fd_quic_svc_timers_init called with NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_quic_svc_timers_align() ) ) ) {
    FD_LOG_ERR(( "fd_quic_svc_timers_init called with misaligned mem" ));
    return NULL;
  }

  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_quic_svc_timers_t * timers  = FD_SCRATCH_ALLOC_APPEND( l,
                                                            alignof(fd_quic_svc_timers_t),
                                                            sizeof(fd_quic_svc_timers_t) );
  uchar                * prq_mem = FD_SCRATCH_ALLOC_APPEND( l,
                                                            fd_quic_svc_queue_prq_align(),
                                                            fd_quic_svc_queue_prq_footprint( max_conn ) );


  timers->prq = fd_quic_svc_queue_prq_join( fd_quic_svc_queue_prq_new( prq_mem, max_conn ) );
  if( FD_UNLIKELY( !timers->prq ) ) {
    FD_LOG_ERR(( "fd_quic_svc_timers_init failed to join prq" ));
    return NULL;
  }

  for( uint i = 0; i < 2; i++ ) {
    timers->queues[i].cnt  = 0U;
    timers->queues[i].head = FD_QUIC_SVC_DLIST_IDX_INVAL;
    timers->queues[i].tail = FD_QUIC_SVC_DLIST_IDX_INVAL;
  }
  timers->state = state;

  return timers;
}

void
fd_quic_svc_timers_init_conn( fd_quic_conn_t * conn ) {
  conn->svc_meta.next_timeout = ULONG_MAX;

  conn->svc_meta.private.prq_idx    = FD_QUIC_SVC_PRQ_IDX_INVAL;
  conn->svc_meta.private.svc_type   = FD_QUIC_SVC_CNT;
}

/* END SETUP FUNCTIONS *********************************************/

/* DLIST HELPER FUNCTIONS *******************************************/

static inline void
fd_quic_svc_dlist_insert_tail( fd_quic_svc_queue_t * queue,
                               fd_quic_state_t     * state,
                               fd_quic_conn_t      * conn ) {

  uint             conn_idx  = conn->conn_idx;
  fd_quic_conn_t * tail_conn = fd_quic_conn_at_idx( state, queue->tail );

  *fd_ptr_if( !!queue->cnt, &tail_conn->svc_meta.private.dlist.next , &queue->head) = conn_idx ;
  conn->svc_meta.private.dlist.prev = queue->tail;
  conn->svc_meta.private.dlist.next = FD_QUIC_SVC_DLIST_IDX_INVAL;
  queue->tail         = conn_idx;
  queue->cnt++;
}

static inline void
fd_quic_svc_dlist_remove( fd_quic_svc_queue_t * queue,
                          fd_quic_state_t     * state,
                          fd_quic_conn_t      * conn ) {
  uint conn_idx = conn->conn_idx;
  uint qhead    = queue->head;
  uint qtail    = queue->tail;

  fd_quic_conn_t * prev_conn = fd_quic_conn_at_idx( state, conn->svc_meta.private.dlist.prev );
  fd_quic_conn_t * next_conn = fd_quic_conn_at_idx( state, conn->svc_meta.private.dlist.next );

  *fd_ptr_if( conn_idx == qhead, &queue->head , &prev_conn->svc_meta.private.dlist.next) = conn->svc_meta.private.dlist.next;
  *fd_ptr_if( conn_idx == qtail, &queue->tail , &next_conn->svc_meta.private.dlist.prev) = conn->svc_meta.private.dlist.prev;

  conn->svc_meta.private.dlist.next = FD_QUIC_SVC_DLIST_IDX_INVAL;
  conn->svc_meta.private.dlist.prev = FD_QUIC_SVC_DLIST_IDX_INVAL;
  queue->cnt--;
}

/* TASK FUNCTIONS *************************************************/

void
fd_quic_svc_cancel( fd_quic_svc_timers_t * timers,
                    fd_quic_conn_t       * conn ) {

  uint              svc_type = conn->svc_meta.private.svc_type;
  fd_quic_state_t * state    = timers->state;

  if( svc_type == FD_QUIC_SVC_INSTANT || svc_type == FD_QUIC_SVC_TIMEOUT ) {
    fd_quic_svc_dlist_remove( &timers->queues[svc_type], state, conn );
  } else if ( svc_type == FD_QUIC_SVC_DYNAMIC ) {
    fd_quic_svc_queue_prq_remove( timers->prq, conn->svc_meta.private.prq_idx );
  }
  conn->svc_meta.private.prq_idx  = FD_QUIC_SVC_PRQ_IDX_INVAL;
  conn->svc_meta.private.svc_type = FD_QUIC_SVC_CNT;
}

void
fd_quic_svc_schedule( fd_quic_svc_timers_t * timers,
                      fd_quic_conn_t       * conn,
                      ulong                  now ) {

  /* if conn null or invalid, do not schedule */
  if( FD_UNLIKELY( !conn || conn->state == FD_QUIC_CONN_STATE_INVALID ) ) {
    /* cleaner/safer to check in here for now. If function call overhead
       becomes a constraint, move check to caller */
    return;
  }

  fd_quic_state_t * state        = timers->state;
  ulong             expiry       = conn->svc_meta.next_timeout;
  uint              old_svc_type = conn->svc_meta.private.svc_type;
  uint              new_svc_type;

  /* Determine new svc queue */
  if( expiry == now ) {
    new_svc_type = FD_QUIC_SVC_INSTANT;
  } else if( expiry == ULONG_MAX ) {
    new_svc_type = FD_QUIC_SVC_TIMEOUT;
  } else {
    new_svc_type = FD_QUIC_SVC_DYNAMIC;
  }

  /* no-op if svc_type hasn't changed. But for dynamic, also make sure the new time is later */
  int noop = 0;
  noop |= !!(old_svc_type == new_svc_type);
  if( noop && new_svc_type == FD_QUIC_SVC_DYNAMIC ) {
    /* if both dynamic, compare existing timer with current timer */
    ulong old_idx = conn->svc_meta.private.prq_idx;
    ulong old_expiry = timers->prq[old_idx].timeout;
    noop &= !!( old_expiry <= expiry );
  }
  if( noop ) return;

  /* if previously scheduled, remove from old queue */
  if( old_svc_type == FD_QUIC_SVC_DYNAMIC ) {
    fd_quic_svc_queue_prq_remove( timers->prq, conn->svc_meta.private.prq_idx );
  } else if( old_svc_type!=FD_QUIC_SVC_CNT ) {
    fd_quic_svc_dlist_remove( &timers->queues[old_svc_type], state, conn );
  }

  /* Schedule in appropriate queue */
  conn->svc_meta.private.svc_type = new_svc_type;

  if( (new_svc_type==FD_QUIC_SVC_INSTANT) | (new_svc_type==FD_QUIC_SVC_TIMEOUT) ) {
    fd_quic_svc_dlist_insert_tail( &timers->queues[new_svc_type], state, conn );
  } else {
    /* FD_QUIC_SVC_DYNAMIC - use heap */
    fd_quic_svc_event_t e = {
      .conn    = conn,
      .timeout = expiry
    };
    fd_quic_svc_queue_prq_insert( timers->prq, &e );
  }

  conn->svc_meta.next_timeout = ULONG_MAX; /* reset */
}

int
fd_quic_svc_timers_validate( fd_quic_svc_timers_t * timers,
                             fd_quic_t            * quic ) {
  fd_quic_state_t * state = fd_quic_get_state( quic );

  /* Validate DYNAMIC queue (heap) */
  ulong prq_cnt = fd_quic_svc_queue_prq_cnt( timers->prq );
  for( ulong i = 0; i < prq_cnt; i++ ) {
    fd_quic_svc_event_t * event = timers->prq + i;
    fd_quic_conn_t      * conn  = event->conn;

    /* conn and idx match for dynamic queue */
    if( FD_UNLIKELY( conn->svc_meta.private.prq_idx != i ) ) return 0;
    if( FD_UNLIKELY( conn->svc_meta.private.svc_type != FD_QUIC_SVC_DYNAMIC ) ) return 0;

    /* conn in prq at most once */
    if( FD_UNLIKELY( conn->visited ) ) return 0;
    conn->visited = 1U;
  }

  /* Validate dlists  */
  ulong cnts[2] = { 0U, 0U };
  for( uint i = 0; i < 2; i++ ) {
    uint curr = timers->queues[i].head;
    while( curr != FD_QUIC_SVC_DLIST_IDX_INVAL ) {
      fd_quic_conn_t * conn = fd_quic_conn_at_idx( state, curr );
      if( FD_UNLIKELY( conn->svc_meta.private.svc_type != i ) ) return 0;
      if( FD_UNLIKELY( conn->visited ) ) return 0;
      conn->visited = 1U;
      curr = conn->svc_meta.private.dlist.next;
      cnts[i]++;
    }
    if( cnts[i] != timers->queues[i].cnt ) return 0;
  }

  /* connections not in any queue should have INVALID idx */
  for( ulong i = 0; i < quic->limits.conn_cnt; i++ ) {
    fd_quic_conn_t * conn = fd_quic_conn_at_idx( state, i );
    if( !conn->visited && conn->svc_meta.private.prq_idx != FD_QUIC_SVC_PRQ_IDX_INVAL ) return 0;
  }

  return 1;
}

fd_quic_svc_event_t
fd_quic_svc_timers_next( fd_quic_svc_timers_t * timers,
                         ulong                  now,
                         int                    pop ) {
  fd_quic_svc_event_t next = { .timeout = ULONG_MAX, .conn = NULL };

  /* Priority: INSTANT > DYNAMIC, never TIMEOUT */

  /* Check INSTANT queue first */
  fd_quic_svc_queue_t * instant_queue = &timers->queues[FD_QUIC_SVC_INSTANT];
  if( instant_queue->cnt ) {
    uint             conn_idx = instant_queue->head;
    fd_quic_conn_t * conn     = fd_quic_conn_at_idx( timers->state, conn_idx );

    next.timeout = fd_ulong_min( now, conn->svc_meta.next_timeout );
    next.conn    = conn;

    if( pop ) {
      fd_quic_svc_dlist_remove( instant_queue, timers->state, conn );
      conn->svc_meta.next_timeout      = ULONG_MAX;
      conn->svc_meta.private.svc_type  = FD_QUIC_SVC_CNT;
      conn->svc_meta.private.prq_idx   = FD_QUIC_SVC_PRQ_IDX_INVAL;
    }

    return next;
  }

  /* Check DYNAMIC queue (heap) */
  if( fd_quic_svc_queue_prq_cnt( timers->prq ) ) {
    if( FD_LIKELY( pop ) ) {
      if( FD_UNLIKELY( now < timers->prq[0].timeout ) ) {
        return next;
      }
      next                                  = timers->prq[0];
      next.conn->svc_meta.private.prq_idx   = FD_QUIC_SVC_PRQ_IDX_INVAL;
      next.conn->svc_meta.private.svc_type  = FD_QUIC_SVC_CNT;
      next.conn->svc_meta.next_timeout      = ULONG_MAX;
      fd_quic_svc_queue_prq_remove_min( timers->prq );
    } else {
      next = timers->prq[0];
    }
    return next;
  }

  return next;
}

fd_quic_svc_event_t
fd_quic_svc_get_event( fd_quic_svc_timers_t * timers,
                       fd_quic_conn_t       * conn,
                       ulong                  now ) {
  uint svc_type = conn->svc_meta.private.svc_type;

  if( svc_type == FD_QUIC_SVC_INSTANT ) {
    return (fd_quic_svc_event_t){ .timeout = now, .conn = conn };
  } else if ( svc_type == FD_QUIC_SVC_TIMEOUT ) {
    return (fd_quic_svc_event_t){ .timeout = ULONG_MAX, .conn = conn };
  } else if (svc_type == FD_QUIC_SVC_DYNAMIC) {
    ulong idx = conn->svc_meta.private.prq_idx;
    return *(timers->prq + idx);
  }
  return (fd_quic_svc_event_t){ .timeout = ULONG_MAX, .conn = NULL };
}

ulong
fd_quic_svc_cnt_events( fd_quic_svc_timers_t * timers ) {
  return timers->queues[FD_QUIC_SVC_INSTANT].cnt +
         timers->queues[FD_QUIC_SVC_TIMEOUT].cnt +
         fd_quic_svc_queue_prq_cnt( timers->prq );
}

fd_quic_conn_t *
fd_quic_svc_timeout_pop( fd_quic_svc_timers_t * timers ) {
  fd_quic_svc_queue_t * queue = &timers->queues[FD_QUIC_SVC_TIMEOUT];
  if( queue->head == FD_QUIC_SVC_DLIST_IDX_INVAL ) return NULL;

  fd_quic_conn_t * conn = fd_quic_conn_at_idx( timers->state, queue->head );
  fd_quic_svc_dlist_remove( queue, timers->state, conn );
  conn->svc_meta.private.prq_idx = FD_QUIC_SVC_PRQ_IDX_INVAL;
  conn->svc_meta.private.svc_type = FD_QUIC_SVC_CNT;
  return conn;
}

int
fd_quic_svc_timeout_empty( fd_quic_svc_timers_t * timers ) {
  return timers->queues[FD_QUIC_SVC_TIMEOUT].cnt == 0;
}
