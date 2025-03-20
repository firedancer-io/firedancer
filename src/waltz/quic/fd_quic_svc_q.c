#include "fd_quic_svc_q.h"
#include "fd_quic_private.h"
#include "fd_quic_conn.h"

/* CONSTANTS ************************************************/
/* bitmap of the svc types that use a dlist.
   Everything else goes into prq */
#define FD_QUIC_SVC_USE_DLIST      \
   ((0x1<<FD_QUIC_SVC_IDLE)       | \
    (0x1<<FD_QUIC_SVC_RTT_SAMPLE) | \
    (0x1<<FD_QUIC_SVC_INSTANT))

/* number of dlist-based event queues */
#define FD_QUIC_SVC_DLIST_COUNT \
   (ulong)fd_ulong_popcnt( FD_QUIC_SVC_USE_DLIST )

/* number of prq-based event queues */
#define FD_QUIC_SVC_PRQ_COUNT \
   (FD_QUIC_SVC_CNT - FD_QUIC_SVC_DLIST_COUNT)

/* macro to check if svc type is dlist-based */
#define FD_QUIC_SVC_IS_DLIST(svc_type) \
   (fd_ulong_extract_bit( FD_QUIC_SVC_USE_DLIST, (int)svc_type ))


/* PRIVATE ************************************************/

#define POOL_NAME fd_quic_svc_event_pool
#define POOL_T    fd_quic_svc_event_t
#define POOL_IDX_T uint
#include "../../util/tmpl/fd_pool.c"

#define DLIST_NAME fd_quic_svc_queue_dlist
#define DLIST_ELE_T fd_quic_svc_event_t
#define DLIST_IDX_T uint
#include "../../util/tmpl/fd_dlist.c"

#define PRQ_NAME fd_quic_svc_queue_prq
#define PRQ_T    fd_quic_svc_event_t
#define PRQ_TMP_ST(p,t) do { \
                         (p)[0] = (t); \
                         t.conn->svc_meta.idx[ t.svc_type ] = (ulong)((p)-heap); \
                       } while( 0 )
#define PRQ_TIMEOUT_T ulong
#include "../../util/tmpl/fd_prq.c"
typedef fd_quic_svc_event_t fd_quic_svc_queue_prq_t;

/* fd_quic_svc_queue represents a logical service queue
   for some fixed svc_type*/
union fd_quic_svc_queue {
  fd_quic_svc_queue_dlist_t * dlist; /* dlist join */
  fd_quic_svc_event_t* prq; /* prq join */
};
typedef union fd_quic_svc_queue fd_quic_svc_queue_t;


/* fd_quic_svc_timers_priv holds timer private state */
struct __attribute__((aligned(64))) fd_quic_svc_timers_priv {
  fd_quic_svc_queue_t svc_queue[ FD_QUIC_SVC_CNT ];
  fd_quic_svc_event_t* pool; /* used by dlists */
};
typedef struct fd_quic_svc_timers_priv fd_quic_svc_timers_priv_t;


/* HELPER FUNCTIONS *************************************************/
#define FD_QUIC_SVC_PRIV_OFFSET fd_ulong_align_up( sizeof( fd_quic_svc_timers_t ), alignof( fd_quic_svc_timers_priv_t ) )

static inline fd_quic_svc_timers_priv_t *
fd_quic_svc_timers_get_priv( fd_quic_svc_timers_t * timers) {
  return (fd_quic_svc_timers_priv_t *)( (ulong)timers + FD_QUIC_SVC_PRIV_OFFSET );
}

/* fd_quic_svc_cancel_helper cancels a timer event
   idx_ptr points to pool/prq idx to be cancelled */
static inline void
fd_quic_svc_cancel_helper( fd_quic_svc_queue_t * queue,
                           fd_quic_svc_event_t * pool,
                           ulong               * idx_ptr,
                           int                   use_dlist ) {
  if( use_dlist ) {
    fd_quic_svc_queue_dlist_idx_remove( queue->dlist, *idx_ptr, pool );
    fd_quic_svc_event_pool_idx_release( pool, *idx_ptr );
  } else {
    fd_quic_svc_queue_prq_remove( queue->prq, *idx_ptr );
  }
  *idx_ptr = FD_QUIC_SVC_IDX_INVAL;
}

/* fd_quic_svc_schedule_helper schedules a service event for a particular conn
   it schedules an event of type svc_type at time expiry
   If there's already an event of this type for this conn,
     keep_earlier==1 -> keep earlier events, 0 -> keep later events */
static void
fd_quic_svc_schedule_helper( fd_quic_svc_timers_t * timers,
                             fd_quic_conn_t *       conn,
                             uint                   svc_type,
                             ulong                  expiry,
                             int                    keep_earlier ) {
  if( FD_UNLIKELY( svc_type >= FD_QUIC_SVC_CNT ) ) {
    FD_LOG_ERR(( "fd_quic_svc_schedule called with invalid svc_type (%u)", svc_type ));
  }

  fd_quic_svc_timers_priv_t * priv      = fd_quic_svc_timers_get_priv( timers );
  fd_quic_svc_queue_t *       queue     = &priv->svc_queue[ svc_type ];
  ulong                       idx       = conn->svc_meta.idx[ svc_type ];
  int                         use_dlist = FD_QUIC_SVC_IS_DLIST( svc_type );

  if( idx != FD_QUIC_SVC_IDX_INVAL ) {
    /* find current expiry */
    fd_quic_svc_event_t * event = (fd_quic_svc_event_t *)fd_ulong_if(
      use_dlist,
      (ulong)(priv->pool+idx),
      (ulong)(queue->prq+idx) );
    ulong cur_expiry = event->timeout;

    /* INSTANT always with 0 */
    if( FD_LIKELY( cur_expiry == expiry ) ) {
      return;
    } else if( (cur_expiry > expiry) != keep_earlier ) {
      return;
    } else {
      fd_quic_svc_cancel_helper( queue, priv->pool, conn->svc_meta.idx+svc_type, use_dlist );
    }
  }

  /* if we got to here, insert new element */
  if( FD_LIKELY( use_dlist ) ) {
    idx                            = fd_quic_svc_event_pool_idx_acquire( priv->pool );
    fd_quic_svc_event_t * e        = priv->pool + idx;
    e->conn                        = conn;
    e->timeout                     = expiry;
    e->svc_type                    = svc_type;
    conn->svc_meta.idx[ svc_type ] = idx;
    fd_quic_svc_queue_dlist_idx_push_tail( queue->dlist, idx, priv->pool );
  } else {
    fd_quic_svc_event_t e = {
      .conn = conn,
      .timeout = expiry,
      .svc_type = svc_type
    };
    fd_quic_svc_queue_prq_insert( queue->prq, &e );
    /* conn->svc_meta.idx[ svc_type ] = idx; */ /* already set by insert */
  }
}

/* fd_quic_svc_dlist_validate checks that a particular dlist is valid
   Checks for monotonic expiries and conn and event pointing to each other
   returns 1 if valid, else 0*/
static inline int
fd_quic_svc_dlist_validate( fd_quic_svc_queue_dlist_t * dlist,
                            fd_quic_svc_event_t       * pool  ) {
  fd_quic_svc_event_t * prev = NULL;
  for( fd_quic_svc_queue_dlist_iter_t iter = fd_quic_svc_queue_dlist_iter_fwd_init( dlist, pool );
       !fd_quic_svc_queue_dlist_iter_done( iter, dlist, pool );
       iter = fd_quic_svc_queue_dlist_iter_fwd_next( iter, dlist, pool ) ) {
    ulong idx = fd_quic_svc_queue_dlist_iter_idx( iter, dlist, pool );
    fd_quic_svc_event_t* curr = pool + idx;

    if( FD_UNLIKELY( curr->conn->svc_meta.idx[curr->svc_type] != idx ) ) {
      return 0;
    }
    if( FD_LIKELY( prev ) ) {
      if( FD_UNLIKELY( prev->timeout > curr->timeout ) ) {
        return 0;
      }
    }
    prev = curr;
  }
  return 1;
}

/* fd_quic_svc_prq_validate validates that a particular prq is valid
   There can be multiple svc_types sharing that prq
   In particular, just that conn and event point to each other
   returns 1 if valid, else 0 */
static inline int
fd_quic_svc_prq_validate( fd_quic_svc_event_t * prq ) {
  ulong cnt = fd_quic_svc_queue_prq_cnt( prq );
  for( ulong i = 0; i < cnt; i++ ) {
    fd_quic_svc_event_t * event = prq+i;
    if( FD_UNLIKELY( event->conn->svc_meta.idx[event->svc_type] != i ) ) return 0;
  }
  return 1;
}

/* END HELPER FUNCTIONS *********************************************/


/* SETUP FUNCTIONS *************************************************/

ulong
fd_quic_svc_timers_footprint( ulong max_conn ) {

  ulong offset = FD_QUIC_SVC_PRIV_OFFSET + sizeof( fd_quic_svc_timers_priv_t );

  offset = fd_ulong_align_up( offset, fd_quic_svc_queue_dlist_align() );
  offset += FD_QUIC_SVC_DLIST_COUNT*fd_quic_svc_queue_dlist_footprint();

  offset = fd_ulong_align_up( offset, fd_quic_svc_event_pool_align() );
  offset += fd_quic_svc_event_pool_footprint( max_conn*FD_QUIC_SVC_DLIST_COUNT );

  offset = fd_ulong_align_up( offset, fd_quic_svc_queue_prq_align() );
  offset += fd_quic_svc_queue_prq_footprint( max_conn*FD_QUIC_SVC_PRQ_COUNT );

  return offset;
}

ulong
fd_quic_svc_timers_align( void ) {
  ulong option = alignof( fd_quic_svc_timers_priv_t );
  option = fd_ulong_max( option, fd_quic_svc_queue_dlist_align() );
  option = fd_ulong_max( option, fd_quic_svc_queue_prq_align() );
  option = fd_ulong_max( option, fd_quic_svc_event_pool_align() );
  return option;
}

fd_quic_svc_timers_t*
fd_quic_svc_timers_init( void* mem,
                         ulong max_conn ) {

  if( FD_UNLIKELY( !mem ) ) {
    FD_LOG_ERR(( "fd_quic_svc_timers_init called with NULL mem" ));
    return NULL;
  }

  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_quic_svc_timers_align() ) ) ) {
    FD_LOG_ERR(( "fd_quic_svc_timers_init called with misaligned mem" ));
    return NULL;
  }

  fd_quic_svc_timers_t      * timers = (fd_quic_svc_timers_t *)mem;
  fd_quic_svc_timers_priv_t * priv   = fd_quic_svc_timers_get_priv( timers );

  ulong offset = FD_QUIC_SVC_PRIV_OFFSET + sizeof( fd_quic_svc_timers_priv_t );

  /* setup dlists */
  offset = fd_ulong_align_up( offset, fd_quic_svc_queue_dlist_align() );
  for( uchar i = 0; i < FD_QUIC_SVC_CNT; i++ ) {
    if( !FD_QUIC_SVC_IS_DLIST( i ) ) continue;

    priv->svc_queue[i].dlist = fd_quic_svc_queue_dlist_join(
                                fd_quic_svc_queue_dlist_new( (uchar*)mem+offset )
                              );
    if( FD_UNLIKELY( !priv->svc_queue[i].dlist ) ) {
      FD_LOG_ERR(( "fd_quic_svc_timers_init failed to join dlist" ));
    }
    offset += fd_quic_svc_queue_dlist_footprint();
  }

  /* setup event pool */
  offset               = fd_ulong_align_up( offset, fd_quic_svc_event_pool_align() );
  const ulong pool_max = max_conn * FD_QUIC_SVC_DLIST_COUNT;
  priv->pool           = fd_quic_svc_event_pool_join(
                          fd_quic_svc_event_pool_new( (uchar*)mem+offset, pool_max )
                        );
  if( FD_UNLIKELY( !priv->pool ) ) FD_LOG_ERR(( "fd_quic_svc_timers_init failed to join pool" ));
  offset += fd_quic_svc_event_pool_footprint( pool_max );

  /* setup prqs */
  offset                     = fd_ulong_align_up( offset, fd_quic_svc_queue_prq_align() );
  fd_quic_svc_event_t * heap = fd_quic_svc_queue_prq_join(
                                fd_quic_svc_queue_prq_new( (uchar*)mem+offset, max_conn*FD_QUIC_SVC_PRQ_COUNT )
                              );
  if( FD_UNLIKELY( !heap ) ) FD_LOG_ERR(( "fd_quic_svc_timers_init failed to join prq" ));
  for( uchar i = 0; i < FD_QUIC_SVC_CNT; i++ ) {
    if( !FD_QUIC_SVC_IS_DLIST( i ) ) {
      priv->svc_queue[ i ].prq = heap;
    }
  }
  offset += fd_quic_svc_queue_prq_footprint( max_conn*FD_QUIC_SVC_PRQ_COUNT );

  return timers;
}

void
fd_quic_svc_timers_init_conn( fd_quic_conn_t * conn ) {
  for( uchar i=0; i<FD_QUIC_SVC_CNT; i++ ) {
    conn->svc_meta.idx[i] = FD_QUIC_SVC_IDX_INVAL;
  }
}

/* END SETUP FUNCTIONS *********************************************/

/* TASK FUNCTIONS *************************************************/

void
fd_quic_svc_cancel( fd_quic_svc_timers_t * timers,
                    fd_quic_conn_t       * conn,
                    uint                   svc_type ) {

  fd_quic_svc_timers_priv_t * priv      = fd_quic_svc_timers_get_priv( timers );
  fd_quic_svc_queue_t       * queue     = &priv->svc_queue[ svc_type ];
  int                         use_dlist = FD_QUIC_SVC_IS_DLIST( svc_type );
  ulong                     * idx_ptr   = conn->svc_meta.idx + svc_type;

  if( FD_UNLIKELY( *idx_ptr == FD_QUIC_SVC_IDX_INVAL ) ) {
    return;
  }

  fd_quic_svc_cancel_helper( queue, priv->pool, idx_ptr, use_dlist );
}

void
fd_quic_svc_schedule( fd_quic_svc_timers_t * timers,
                      fd_quic_conn_t       * conn,
                      uint                   svc_type,
                      ulong                  expiry ) {
  fd_quic_svc_schedule_helper( timers, conn, svc_type, expiry, 1 );
}

void
fd_quic_svc_schedule_later( fd_quic_svc_timers_t * timers,
                            fd_quic_conn_t       * conn,
                            uint                   svc_type,
                            ulong                  expiry ) {
  fd_quic_svc_schedule_helper( timers, conn, svc_type, expiry, 0 );
}

int
fd_quic_svc_timers_validate( fd_quic_svc_timers_t * timers ) {
  fd_quic_svc_timers_priv_t * priv = fd_quic_svc_timers_get_priv( timers );
  fd_quic_svc_event_t * pool = priv->pool;

  for( uint svc_type = 0; svc_type<FD_QUIC_SVC_CNT; svc_type++) {
    if( FD_QUIC_SVC_IS_DLIST( svc_type ) ) {
      if( !fd_quic_svc_dlist_validate( priv->svc_queue[ svc_type ].dlist, pool ) ) {
        return 0;
      }
    } else {
      /* we'll end up revalidating the prq for each svc_type in it
        but for testing anyway, it's fine! */
      if( !fd_quic_svc_prq_validate( priv->svc_queue[ svc_type ].prq ) ) {
        return 0;
      }
    }
  }
  return 1;
}

fd_quic_svc_event_t
fd_quic_svc_timers_next( fd_quic_svc_timers_t * timers,
                         ulong                  now,
                         int                    pop ) {
  fd_quic_svc_timers_priv_t * priv = fd_quic_svc_timers_get_priv( timers );
  fd_quic_svc_event_t       * pool = priv->pool;
  fd_quic_svc_event_t         next = { .svc_type = FD_QUIC_SVC_CNT };
  next.timeout /* init earliest */ = fd_ulong_if( pop, now, ULONG_MAX );

  for( ushort svc_type = 0; svc_type < FD_QUIC_SVC_CNT; svc_type++ ) {
    int                   use_dlist = FD_QUIC_SVC_IS_DLIST( svc_type );
    fd_quic_svc_queue_t * queue     = &priv->svc_queue[ svc_type ];
    int                   non_empty = fd_int_if( use_dlist,
                                        !fd_quic_svc_queue_dlist_is_empty( queue->dlist, pool ),
                                        (int)fd_quic_svc_queue_prq_cnt( queue->prq ) );
    fd_quic_svc_event_t * event     = (fd_quic_svc_event_t *)fd_ulong_if( use_dlist,
                                        (ulong)(priv->pool + fd_quic_svc_queue_dlist_idx_peek_head( queue->dlist, pool )),
                                        (ulong)queue->prq );
    /* careful! deref event must be guarded by non_empty now */

    if( non_empty && event->timeout <= next.timeout ) {
      next = *event;
    }
  }

  if( next.svc_type == FD_QUIC_SVC_CNT ) {
    return next;
  }

  if( pop ) {
    next.conn->svc_meta.idx[ next.svc_type ] = FD_QUIC_SVC_IDX_INVAL;
    if( FD_QUIC_SVC_IS_DLIST( next.svc_type ) ) {
      ulong release_idx = fd_quic_svc_queue_dlist_idx_pop_head( priv->svc_queue[ next.svc_type ].dlist, pool );
      fd_quic_svc_event_pool_idx_release( pool, release_idx );
    } else {
      fd_quic_svc_queue_prq_remove_min( priv->svc_queue[ next.svc_type ].prq );
    }
  }

  return next;
}
