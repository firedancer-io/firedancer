#include "fd_quic_svc_q.h"
#include "fd_quic_private.h"
#include "fd_quic_conn.h"

/* PRIVATE ************************************************/

#define POOL_NAME fd_quic_svc_event_pool
#define POOL_T    fd_quic_svc_event_t
#include "../../util/tmpl/fd_pool.c"

#define DLIST_NAME fd_quic_svc_queue_dlist
#define DLIST_ELE_T fd_quic_svc_event_t
#include "../../util/tmpl/fd_dlist.c"

#define PRQ_NAME fd_quic_svc_queue_prq
#define PRQ_T    fd_quic_svc_event_t
#define PRQ_TMP_ST(p,t) do { \
                         (p)[0] = (t); \
                         t.conn->svc_meta.idx[ FD_QUIC_SVC_RETX ] = (ulong)((p)-heap); \
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
                           int                   use_prq ) {
  if( use_prq ) {
    fd_quic_svc_queue_prq_remove( queue->prq, *idx_ptr );
  } else {
    fd_quic_svc_queue_dlist_idx_remove( queue->dlist, *idx_ptr, pool );
    fd_quic_svc_event_pool_idx_release( pool, *idx_ptr );
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

  fd_quic_svc_timers_priv_t * priv    = fd_quic_svc_timers_get_priv( timers );
  fd_quic_svc_queue_t *       queue   = &priv->svc_queue[ svc_type ];
  ulong                       idx     = conn->svc_meta.idx[ svc_type ];
  int                         use_prq = svc_type == FD_QUIC_SVC_RETX;

  if( idx != FD_QUIC_SVC_IDX_INVAL ) {
    /* find current expiry */
    fd_quic_svc_event_t * event = (fd_quic_svc_event_t *)fd_ulong_if(
      use_prq,
      (ulong)(queue->prq+idx),
      (ulong)(priv->pool+idx) );
    ulong cur_expiry = event->timeout;

    /* INSTANT always with 0 */
    if( FD_LIKELY( cur_expiry == expiry ) ) {
      return;
    } else if( (cur_expiry > expiry) != keep_earlier ) {
      return;
    } else {
      fd_quic_svc_cancel_helper( queue, priv->pool, conn->svc_meta.idx+svc_type, use_prq );
    }
  }

  /* if we got to here, insert new element */
  if( FD_LIKELY( use_prq ) ) {
    fd_quic_svc_event_t e = {
      .conn = conn,
      .timeout = expiry
    };
    fd_quic_svc_queue_prq_insert( queue->prq, &e );
    /* conn->svc_meta.idx[ svc_type ] = idx; */ /* already set by insert */
  } else {
    idx                            = fd_quic_svc_event_pool_idx_acquire( priv->pool );
    fd_quic_svc_event_t * e        = priv->pool + idx;
    e->conn                        = conn;
    e->timeout                     = expiry;
    conn->svc_meta.idx[ svc_type ] = idx;
    fd_quic_svc_queue_dlist_idx_push_tail( queue->dlist, idx, priv->pool );
  }
}

/* fd_quic_svc_dlist_validate checks that a particular dlist is valid
   Checks for monotonic expiries and conn and event pointing to each other
   returns 1 if valid, else 0*/
static inline int
fd_quic_svc_dlist_validate( fd_quic_svc_queue_dlist_t * dlist,
                            fd_quic_svc_event_t       * pool,
                            uint                        svc_type ) {
  fd_quic_svc_event_t * prev = NULL;
  for( fd_quic_svc_queue_dlist_iter_t iter = fd_quic_svc_queue_dlist_iter_fwd_init( dlist, pool );
       !fd_quic_svc_queue_dlist_iter_done( iter, dlist, pool );
       iter = fd_quic_svc_queue_dlist_iter_fwd_next( iter, dlist, pool ) ) {
    ulong idx = fd_quic_svc_queue_dlist_iter_idx( iter, dlist, pool );
    fd_quic_svc_event_t* curr = pool + idx;

    if( FD_UNLIKELY( curr->conn->svc_meta.idx[svc_type] != idx ) ) {
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
   In particular, just that conn and event point to each other
   returns 1 if valid, else 0 */
static inline int
fd_quic_svc_prq_validate( fd_quic_svc_event_t * prq,
                          uint                  svc_type ) {
  ulong cnt = fd_quic_svc_queue_prq_cnt( prq );
  for( ulong i = 0; i < cnt; i++ ) {
    fd_quic_svc_event_t * event = prq+i;
    if( FD_UNLIKELY( event->conn->svc_meta.idx[svc_type] != i ) ) return 0;
  }
  return 1;
}

/* END HELPER FUNCTIONS *********************************************/


/* SETUP FUNCTIONS *************************************************/

ulong
fd_quic_svc_timers_footprint( ulong max_conn ) {
  static const ulong pool_based = FD_QUIC_SVC_CNT-1;

  ulong offset = FD_QUIC_SVC_PRIV_OFFSET + sizeof( fd_quic_svc_timers_priv_t );

  offset = fd_ulong_align_up( offset, fd_quic_svc_queue_dlist_align() );
  offset += pool_based*fd_quic_svc_queue_dlist_footprint();

  offset = fd_ulong_align_up( offset, fd_quic_svc_event_pool_align() );
  offset += fd_quic_svc_event_pool_footprint( max_conn*pool_based );

  offset = fd_ulong_align_up( offset, fd_quic_svc_queue_prq_align() );
  offset += fd_quic_svc_queue_prq_footprint( max_conn );

  return offset;
}

inline ulong
fd_quic_svc_timers_align() {
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
  ulong dl_cnt = 0;

  /* setup dlists */
  offset = fd_ulong_align_up( offset, fd_quic_svc_queue_dlist_align() );
  for( uint i = 0; i < FD_QUIC_SVC_CNT; i++ ) {
    /* Ugly but cleaner than hardcoding all 4 dlist types(?)
       Skip any types in this loop that aren't dlists
       Modify the assert once you've confirmed desired behavior */
    FD_STATIC_ASSERT( FD_QUIC_SVC_CNT == 5, "Check continue logic" );
    if( FD_UNLIKELY( i == FD_QUIC_SVC_RETX ) ) continue;

    priv->svc_queue[i].dlist = fd_quic_svc_queue_dlist_join(
                                fd_quic_svc_queue_dlist_new( (uchar*)mem+offset )
                              );
    if( FD_UNLIKELY( !priv->svc_queue[i].dlist ) ) {
      FD_LOG_ERR(( "fd_quic_svc_timers_init failed to join dlist" ));
    }
    offset += fd_quic_svc_queue_dlist_footprint();
    dl_cnt++;
  }

  /* setup event pool */
  offset               = fd_ulong_align_up( offset, fd_quic_svc_event_pool_align() );
  const ulong pool_max = max_conn * dl_cnt;
  priv->pool           = fd_quic_svc_event_pool_join(
                          fd_quic_svc_event_pool_new( (uchar*)mem+offset, pool_max )
                        );
  if( FD_UNLIKELY( !priv->pool ) ) FD_LOG_ERR(( "fd_quic_svc_timers_init failed to join pool" ));
  offset += fd_quic_svc_event_pool_footprint( pool_max );

  /* setup prq */
  offset                     = fd_ulong_align_up( offset, fd_quic_svc_queue_prq_align() );
  fd_quic_svc_event_t * heap = fd_quic_svc_queue_prq_join(
                                 fd_quic_svc_queue_prq_new( (uchar*)mem+offset, max_conn )
                               );
  if( FD_UNLIKELY( !heap ) ) FD_LOG_ERR(( "fd_quic_svc_timers_init failed to join prq" ));
  priv->svc_queue[ FD_QUIC_SVC_RETX ].prq = heap;
  offset += fd_quic_svc_queue_prq_footprint( max_conn );

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

inline void
fd_quic_svc_cancel( fd_quic_svc_timers_t * timers,
                    fd_quic_conn_t       * conn,
                    uint                   svc_type ) {

  fd_quic_svc_timers_priv_t * priv     = fd_quic_svc_timers_get_priv( timers );
  fd_quic_svc_queue_t       * queue    = &priv->svc_queue[ svc_type ];
  int                         use_prq  = svc_type == FD_QUIC_SVC_RETX;
  ulong                     * idx_ptr  = conn->svc_meta.idx + svc_type;

  if( FD_UNLIKELY( *idx_ptr == FD_QUIC_SVC_IDX_INVAL ) ) {
    return;
  }

  fd_quic_svc_cancel_helper( queue, priv->pool, idx_ptr, use_prq );
}

inline void
fd_quic_svc_schedule( fd_quic_svc_timers_t * timers,
                      fd_quic_conn_t       * conn,
                      uint                   svc_type,
                      ulong                  expiry ) {
  fd_quic_svc_schedule_helper( timers, conn, svc_type, expiry, 1 );
}

inline void
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
    if( svc_type == FD_QUIC_SVC_RETX ) {
      if( !fd_quic_svc_prq_validate( priv->svc_queue[ svc_type ].prq, svc_type ) ) {
        return 0;
      }
    } else {
      if( !fd_quic_svc_dlist_validate( priv->svc_queue[ svc_type ].dlist, pool, svc_type ) ) {
        return 0;
      }
    }
  }
  return 1;
}

fd_quic_svc_event_and_type_t
fd_quic_svc_timers_next( fd_quic_svc_timers_t * timers,
                         ulong                  now,
                         int                    pop ) {
  fd_quic_svc_timers_priv_t *  priv        = fd_quic_svc_timers_get_priv( timers );
  fd_quic_svc_event_t       *  pool        = priv->pool;
  fd_quic_svc_event_and_type_t next        = { .svc_type = FD_QUIC_SVC_CNT };
  next.event.timeout                       = now; /* starting earliest time */

  for( ushort svc_type = 0; svc_type < FD_QUIC_SVC_CNT; svc_type++ ) {
    int                   use_prq   = svc_type == FD_QUIC_SVC_RETX;
    fd_quic_svc_queue_t * queue     = &priv->svc_queue[ svc_type ];
    int                   non_empty = use_prq ?
                                      (int)fd_quic_svc_queue_prq_cnt( queue->prq ) :
                                      !fd_quic_svc_queue_dlist_is_empty( queue->dlist, pool );
    fd_quic_svc_event_t * event     = use_prq ?
                                      queue->prq :
                                      priv->pool + fd_quic_svc_queue_dlist_idx_peek_head( queue->dlist, pool );
    /* careful! deref event must be guarded by non_empty now */

    if( non_empty && event->timeout <= next.event.timeout ) {
      next.svc_type = svc_type;
      next.event    = *event;
    }
  }

  if( next.svc_type == FD_QUIC_SVC_CNT ) {
    return next;
  }

  if( pop ) {
    next.event.conn->svc_meta.idx[ next.svc_type ] = FD_QUIC_SVC_IDX_INVAL;
    if( next.svc_type == FD_QUIC_SVC_RETX ) {
      fd_quic_svc_queue_prq_remove_min( priv->svc_queue[ next.svc_type ].prq );
    } else {
      ulong release_idx = fd_quic_svc_queue_dlist_idx_pop_head( priv->svc_queue[ next.svc_type ].dlist, pool );
      fd_quic_svc_event_pool_idx_release( pool, release_idx );
    }
  }

  return next;
}
