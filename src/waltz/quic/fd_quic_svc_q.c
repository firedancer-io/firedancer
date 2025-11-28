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
#define PRQ_TIMEOUT_T long
#include "../../util/tmpl/fd_prq.c"
typedef fd_quic_svc_event_t fd_quic_svc_queue_prq_t;


/* SETUP FUNCTIONS *************************************************/

ulong
fd_quic_svc_timers_footprint( ulong max_conn ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, alignof(fd_quic_svc_timers_t), sizeof(fd_quic_svc_timers_t) );
  l = FD_LAYOUT_APPEND( l, fd_quic_svc_queue_prq_align(), fd_quic_svc_queue_prq_footprint( max_conn ) );
  l = FD_LAYOUT_FINI(   l, fd_quic_svc_timers_align() );
  return l;
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
  if( FD_UNLIKELY( !timers->prq ) ) FD_LOG_ERR(( "fd_quic_svc_timers_init failed to join prq" ));

  timers->instant.cnt  = 0U;
  timers->instant.head = FD_QUIC_SVC_DLIST_IDX_INVAL;
  timers->instant.tail = FD_QUIC_SVC_DLIST_IDX_INVAL;

  timers->state = state;

  return timers;
}

void
fd_quic_svc_timers_init_conn( fd_quic_conn_t * conn ) {
  conn->svc_meta.next_timeout       = LONG_MAX;
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
fd_quic_svc_timers_cancel( fd_quic_svc_timers_t * timers,
                           fd_quic_conn_t       * conn ) {

  uint              svc_type = conn->svc_meta.private.svc_type;
  fd_quic_state_t * state    = timers->state;

  if( svc_type == FD_QUIC_SVC_INSTANT ) {
    fd_quic_svc_dlist_remove( &timers->instant, state, conn );
  } else if( svc_type == FD_QUIC_SVC_DYNAMIC ) {
    fd_quic_svc_queue_prq_remove( timers->prq, conn->svc_meta.private.prq_idx );
  }
  fd_quic_svc_timers_init_conn( conn );
}

void
fd_quic_svc_timers_schedule( fd_quic_svc_timers_t * timers,
                             fd_quic_conn_t       * conn,
                             long                   now ) {

  /* if conn null or invalid, do not schedule */
  if( FD_UNLIKELY( !conn || conn->state == FD_QUIC_CONN_STATE_INVALID ) ) {
    /* cleaner/safer to check in here for now. If function call overhead
       becomes a constraint, move check to caller */
    return;
  }

  fd_quic_state_t * state         = timers->state;
  long     const    expiry        = conn->svc_meta.next_timeout;
  uint     const    old_svc_type  = conn->svc_meta.private.svc_type;

  uint     const    new_svc_type  = expiry == now ? FD_QUIC_SVC_INSTANT : FD_QUIC_SVC_DYNAMIC;
  int      const    old_dynamic   = old_svc_type==FD_QUIC_SVC_DYNAMIC;
  int      const    both_dynamic  = old_dynamic & (new_svc_type==FD_QUIC_SVC_DYNAMIC);

  /* Speculative is_increase is invalid when !both_dynamic, but safe bc prq_idx==0 */
  ulong const prq_idx     = fd_ulong_if( both_dynamic, conn->svc_meta.private.prq_idx, 0 );
  int   const is_increase = timers->prq[prq_idx].timeout <= expiry;

  /* No-op if already INSTANT, or if trying to increase/preserve DYNAMIC expiry */
  int noop = (old_svc_type==FD_QUIC_SVC_INSTANT) | (both_dynamic & is_increase);
  if( noop ) return;

  /* Cancel existing DYNAMIC timer if it exists */
  if( old_dynamic ) {
    fd_quic_svc_queue_prq_remove( timers->prq, conn->svc_meta.private.prq_idx );
  }

  /* Schedule in appropriate queue */
  conn->svc_meta.private.svc_type = new_svc_type;

  if( new_svc_type==FD_QUIC_SVC_INSTANT ) {
    fd_quic_svc_dlist_insert_tail( &timers->instant, state, conn );
  } else {
    /* FD_QUIC_SVC_DYNAMIC - use heap */
    fd_quic_svc_event_t e = {
      .conn    = conn,
      .timeout = expiry
    };
    fd_quic_svc_queue_prq_insert( timers->prq, &e );
  }
}

int
fd_quic_svc_timers_validate( fd_quic_svc_timers_t * timers,
                             fd_quic_t            * quic ) {
  fd_quic_state_t * state = fd_quic_get_state( quic );

  /* Validate DYNAMIC queue (heap) */
  ulong prq_cnt = fd_quic_svc_queue_prq_cnt( timers->prq );
  for( ulong i=0; i<prq_cnt; i++ ) {
    fd_quic_svc_event_t * event = timers->prq + i;
    fd_quic_conn_t      * conn  = event->conn;

    /* conn and idx match for dynamic queue */
    if( FD_UNLIKELY( conn->svc_meta.private.prq_idx != i ) ) return 0;
    if( FD_UNLIKELY( conn->svc_meta.private.svc_type != FD_QUIC_SVC_DYNAMIC ) ) return 0;

    /* conn in prq at most once */
    if( FD_UNLIKELY( conn->visited ) ) return 0;
    conn->visited = 1U;
  }

  /* Validate dlist */
  ulong instant_cnt = 0U;
  uint  curr        = timers->instant.head;
  while( curr != FD_QUIC_SVC_DLIST_IDX_INVAL ) {
    fd_quic_conn_t * conn = fd_quic_conn_at_idx( state, curr );
    if( FD_UNLIKELY( conn->svc_meta.private.svc_type != FD_QUIC_SVC_INSTANT ) ) return 0;
    if( FD_UNLIKELY( conn->visited ) ) return 0;
    conn->visited = 1U;
    curr = conn->svc_meta.private.dlist.next;
    instant_cnt++;
  }
  if( instant_cnt != timers->instant.cnt ) return 0;

  /* connections not in any queue should have INVALID idx */
  ulong const conn_cnt = quic->limits.conn_cnt;
  for( ulong i=0; i<conn_cnt; i++ ) {
    fd_quic_conn_t * conn = fd_quic_conn_at_idx( state, i );
    if( !conn->visited && conn->svc_meta.private.prq_idx != FD_QUIC_SVC_PRQ_IDX_INVAL ) return 0;
  }

  return 1;
}

fd_quic_svc_event_t
fd_quic_svc_timers_next( fd_quic_svc_timers_t * timers,
                         long                   now,
                         int                    pop ) {
  fd_quic_svc_event_t next = { .timeout = LONG_MAX, .conn = NULL };

  /* Priority: INSTANT > DYNAMIC */

  /* Check INSTANT queue first */
  if( FD_LIKELY( timers->instant.cnt ) ) {
    fd_quic_conn_t * conn = fd_quic_conn_at_idx( timers->state, timers->instant.head );
    next = (fd_quic_svc_event_t){.conn = conn, .timeout = fd_long_min( now, conn->svc_meta.next_timeout )};

    if( FD_LIKELY( pop ) ) {
      fd_quic_svc_dlist_remove( &timers->instant, timers->state, conn );
      fd_quic_svc_timers_init_conn( conn );
    }

    return next;
  }

  /* Check DYNAMIC queue (heap) */
  if( !fd_quic_svc_queue_prq_cnt( timers->prq ) ) return next;
  else if( pop && now < timers->prq[0].timeout ) return next;
  else {
    next = timers->prq[0];
    if( FD_LIKELY( pop ) ) {
      fd_quic_svc_queue_prq_remove_min( timers->prq );
      fd_quic_svc_timers_init_conn( next.conn );
    }
    return next;
  }
}

fd_quic_svc_event_t
fd_quic_svc_timers_get_event( fd_quic_svc_timers_t * timers,
                              fd_quic_conn_t       * conn,
                              long                   now ) {
  uint svc_type = conn->svc_meta.private.svc_type;

  if( svc_type == FD_QUIC_SVC_INSTANT ) {
    return (fd_quic_svc_event_t){ .timeout = now, .conn = conn };
  } else if (svc_type == FD_QUIC_SVC_DYNAMIC) {
    ulong idx = conn->svc_meta.private.prq_idx;
    return *(timers->prq + idx);
  }
  return (fd_quic_svc_event_t){ .timeout = LONG_MAX, .conn = NULL };
}

ulong
fd_quic_svc_timers_cnt_events( fd_quic_svc_timers_t * timers ) {
  return timers->instant.cnt +
         fd_quic_svc_queue_prq_cnt( timers->prq );
}
