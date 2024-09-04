#include "fd_qos.h"

#include "fd_qos_map.h"
#include "../../util/rng/fd_rng.h"

#if 0
#define FD_DEBUG(...) __VA_ARGS__
#else
#define FD_DEBUG(...)
#endif

/* special value used to cap linked list to inform clients not to append */
#define CAP (~0UL)

struct qos_node_key {
  int               active;   /* indicates at least one conn references the IP address */
  fd_qos_key_t      key;      /* the IP address */
};
typedef struct qos_node_key qos_node_key_t;


struct qos_node {
  qos_node_key_t node_key; /* for sequencing the nodes */

  /* required for treap impl */
  ulong parent;
  ulong left;
  ulong right;
  ulong prio;

  /* required for pool */
  ulong next;
};
typedef struct qos_node qos_node_t;


static int
qos_priset_cmp_impl( qos_node_key_t const * lhs, qos_node_key_t const * rhs ) {
  /* -1 indicates lhs is lower priority, and occurs leftmost in the map */
  int   cmp_active   = rhs->active - lhs->active;

  /* uint subtraction ensures well defined two's compliment subtraction */
  /* converting to long allows for optimized conversion to {-1,0,+1} */
  /* for some reason, doing this in an int instead adds a branch */
  long  delta_key    = (long)(int)( (uint)rhs->key - (uint)lhs->key );
  int   cmp_key      = delta_key  < 0L ? -1 :
                       delta_key == 0L ?  0 : 1;

  return cmp_active != 0 ? cmp_active : cmp_key;
}


/* pool for treap over something */
#define POOL_T        qos_node_t
#define POOL_NAME     qos_pool
#include "../../util/tmpl/fd_pool.c"

#define TREAP_T        qos_node_t
#define TREAP_QUERY_T  qos_node_key_t *
#define TREAP_NAME     qos_priset
#define TREAP_CMP(u,v) qos_priset_cmp_impl( (u), &(v)->node_key )
#define TREAP_LT(u,v)  ( qos_priset_cmp_impl( &(u)->node_key, &(v)->node_key ) < 0 )
#include "../../util/tmpl/fd_treap.c"


struct fd_qos {
  ulong  magic;

  ulong  global_map_mem;   /* memory of global_map relative to fd_qos */
  ulong  global_map;       /* a hashmap of ip-address -> fd_qos_entry relative to fd_qos */

  /* mutex is locked when global is inserting or removing and when
   * global entry is being updated */

  /* linked list of updates?
   *   the delta is stored in a region in the workspace unique
   *   to the tile. Each tile can have up to one such update in flight.
   *   Each tile checks local region first. If local delta is in use, it
   *   simply kicks the ball down the road and moves on.
   *   If the local is not in use, it sets the value to the required key
   *   and delta, next to NULL, and then lastly it atomically updates the
   *   end of the linked list to point to the new delta.
   *   The tile is producer, qos is the consumer. Only producer allowed to
   *   set the "ready" bit, and only the consumer allowed to clear it.
   *   The producer inserts into the list. The consumer removes from the list.
   *   The ready bit is always cleared AFTER removal from the linked list.
   */

  /* this is the sentinel before the head of the linked list
   * of deltas to apply */
  fd_qos_entry_t deltas_sentinel[1];

  /* value for calculating emas */
  float          ema_decay;

  ulong          entry_cnt;

  ulong          pool_mem;       /* relative to fd_qos */
  ulong          qos_priset_mem; /* relative to fd_qos */
  ulong          rng_mem;        /* relative to fd_qos */

  ulong          pool;           /* relative to fd_qos */
  ulong          qos_priset;     /* relative to fd_qos */
  ulong          rng;            /* relative to fd_qos */
};

/* get local pointer from fd_qos */
#define QOS_PTR( qos, type, name ) ((type*)((ulong)(qos) + (qos)->name))

/* get local pointer to the global_map */
#define GLOBAL_MAP( qos )          QOS_PTR( qos, fd_qos_map_t, global_map )

/* get local pointer to the pool */
#define POOL( qos )                QOS_PTR( qos, qos_node_t,   pool )

/* get local pointer to the qos_priset */
#define QOS_PRISET( qos )          QOS_PTR( qos, qos_priset_t, qos_priset )

/* get local pointer to the rng */
#define RNG( qos )                 QOS_PTR( qos, fd_rng_t,     rng )

/* fd_qos_{align,footprint} return the required alignment and footprint
 * for the memory region in order to create a new fd_qos */

FD_FN_CONST ulong
fd_qos_align( void ) {
  return FD_QOS_ALIGN;
}

FD_FN_CONST ulong
fd_qos_footprint( ulong entry_cnt ) {

  ulong lg_entry_cnt = 10UL;
  while( ( 1UL << lg_entry_cnt ) < entry_cnt ) lg_entry_cnt++;

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, FD_QOS_ALIGN,       sizeof( fd_qos_t )                        );
  l = FD_LAYOUT_APPEND( l, fd_qos_map_align(), fd_qos_map_footprint( (int)lg_entry_cnt ) );
  l = FD_LAYOUT_APPEND( l, qos_pool_align(),   qos_pool_footprint( entry_cnt+1 )         );
  l = FD_LAYOUT_APPEND( l, qos_priset_align(), qos_priset_footprint( entry_cnt )         );
  l = FD_LAYOUT_APPEND( l, fd_rng_align(),     fd_rng_footprint()                        );

  return FD_LAYOUT_FINI( l, FD_QOS_ALIGN );
}

/* fd_new_qos creates a new fd_qos with the capacity for the given number
 * of entries and tiles. Period is the amount of time in nanoseconds between
 * updates to the global map.
 * A local cache of data is maintained by the producing tiles to keep
 * the work cheap and fast
 * Periodically the
 * Returns the memory to be used by join. */
void *
fd_qos_new( void * mem, ulong entry_cnt ) {
  /* sanity checks */
  if( FD_UNLIKELY( !mem ) )                              return NULL;
  if( !fd_ulong_is_aligned( (ulong)mem, FD_QOS_ALIGN ) ) return NULL;

  ulong lg_entry_cnt = 10UL;
  while( ( 1UL << lg_entry_cnt ) < entry_cnt ) lg_entry_cnt++;

  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_qos_t * qos            = FD_SCRATCH_ALLOC_APPEND( l, FD_QOS_ALIGN,       sizeof( fd_qos_t )                        );
  void *     global_map_mem = FD_SCRATCH_ALLOC_APPEND( l, fd_qos_map_align(), fd_qos_map_footprint( (int)lg_entry_cnt ) );
  void *     pool           = FD_SCRATCH_ALLOC_APPEND( l, qos_pool_align(),   qos_pool_footprint( entry_cnt )           );
  void *     qos_priset     = FD_SCRATCH_ALLOC_APPEND( l, qos_priset_align(), qos_priset_footprint( entry_cnt )         );
  void *     rng            = FD_SCRATCH_ALLOC_APPEND( l, fd_rng_align(),     fd_rng_footprint()                        );

  FD_SCRATCH_ALLOC_FINI( l, FD_QOS_ALIGN );

  qos->global_map = 0;
  qos->pool       = 0;
  qos->qos_priset = 0;
  qos->rng        = 0;

  /* new map */
  qos->global_map_mem = (ulong)fd_qos_map_new( global_map_mem, (int)lg_entry_cnt ) - (ulong)qos;
  qos->pool_mem       = (ulong)qos_pool_new(   pool,       entry_cnt+1 )           - (ulong)qos;
  qos->qos_priset_mem = (ulong)qos_priset_new( qos_priset, entry_cnt )             - (ulong)qos;
  /* later call to fd_qos_set_rng_seed sets seq amd idx, so just use constants here */
  qos->rng            = (ulong)fd_rng_new(     rng, 42, 42 )                       - (ulong)qos;

  qos->entry_cnt      = entry_cnt;

  /* set decay value */
  qos->ema_decay = FD_QOS_EMA_DECAY;

  /* set magic, after ensuring all prior values written */
  FD_COMPILER_MFENCE();
  qos->magic = FD_QOS_MAGIC;
  FD_COMPILER_MFENCE();

  return qos;
}


fd_qos_t *
fd_qos_join( void * mem ) {
  fd_qos_t * qos = (fd_qos_t*)mem;

  if( FD_UNLIKELY( qos->magic != FD_QOS_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  /* join map */
  qos->global_map = (ulong)fd_qos_map_join( QOS_PTR( qos, void*, global_map_mem ) ) - (ulong)qos;
  qos->pool       = (ulong)qos_pool_join(   QOS_PTR( qos, void*, pool_mem       ) ) - (ulong)qos;
  qos->qos_priset = (ulong)qos_priset_join( QOS_PTR( qos, void*, qos_priset_mem ) ) - (ulong)qos;
  qos->rng        = (ulong)fd_rng_join(     QOS_PTR( qos, void*, rng_mem        ) ) - (ulong)qos;

  return qos;
}

void *
fd_qos_leave( fd_qos_t * qos ) {
  if( FD_UNLIKELY( qos->magic != FD_QOS_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  fd_qos_map_leave( GLOBAL_MAP( qos ) );
  qos_priset_leave( QOS_PRISET( qos ) );

  return (void*)qos;
}

void *
fd_qos_delete( void * mem ) {
  fd_qos_t * qos = (fd_qos_t*)mem;

  if( FD_UNLIKELY( !qos ) ) return NULL;

  if( FD_UNLIKELY( qos->magic != FD_QOS_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  qos->magic = 0;

  return mem;
}


void
fd_qos_set_rng_seed( fd_qos_t * qos, uint seq, ulong idx ) {
  fd_rng_t * rng = RNG( qos );
  fd_rng_seq_set( rng, seq );
  fd_rng_idx_set( rng, idx );
}

/* inserts key into map, initialized value to all zeros */
fd_qos_entry_t *
fd_qos_insert( fd_qos_map_t * map, fd_qos_key_t key ) {

  FD_DEBUG( FD_LOG_WARNING(( "fd_qos_insert - %x", (uint)key )); )
  fd_qos_entry_t * entry = fd_qos_map_insert( map, key );
  if( FD_LIKELY( entry ) ) {
    FD_DEBUG( FD_LOG_WARNING(( "fd_qos_insert - %x success", (uint)key )); )
    memset( &entry->value, 0, sizeof( entry->value ) );
  }
  return entry;
}

/* find an entry by key */
fd_qos_entry_t *
fd_qos_query( fd_qos_map_t * map, fd_qos_key_t key ) {
  return fd_qos_map_query( map, key, NULL );
}

/* find an entry by key in global map, if none create one and if none */
/* available, evict one, and complete the process */
/* there should be at least as many entries as allowed connections */
fd_qos_entry_t *
fd_qos_query_forced( fd_qos_t * qos, fd_qos_key_t key ) {
  fd_qos_map_t *   global_map = GLOBAL_MAP( qos );
  qos_priset_t *   priset     = QOS_PRISET( qos );
  qos_node_t *     pool       = POOL( qos );
  fd_qos_entry_t * entry      = fd_qos_map_query( global_map, key, NULL );
  FD_DEBUG( FD_LOG_WARNING(( "fd_qos_query_forced - %x", (uint)key )); )

  if( FD_LIKELY( entry ) ) {
    FD_DEBUG( FD_LOG_WARNING(( "fd_qos_query_forced - %x  conn_cnt: %lu", (uint)key, (ulong)entry->value.conn_cnt )); )
    return entry;
  }

  /* attempt insert into global map */
  /* initialized upon success */
  entry = fd_qos_insert( global_map, key );
  if( FD_UNLIKELY( entry ) ) return entry;

  /* if this fails, we'll obtain an entry by eliminating an old one */

  /* find lowest priority node in qos_priset */

  qos_priset_fwd_iter_t iter = qos_priset_fwd_iter_init( priset, pool );
  FD_TEST( !qos_priset_fwd_iter_done( iter ) );

  /* extract the element */
  qos_node_t * node = qos_priset_fwd_iter_ele( iter, pool );

  /* inactive nodes come first, and there should be one because: */
  /*   ip address entries >= connection capacity */
  /*   ip address not found in global_map */
  FD_TEST( node && !node->node_key.active );

  /* remove the old IP address `node->node_key.key` from the global map */
  /* to make room for the new key */
  fd_qos_remove_key( global_map, node->node_key.key );

  /* insert new key */
  entry = fd_qos_insert( global_map, key );
  FD_TEST( entry );

  /* fd_qos_insert initialized entry, so just return it */

  return entry;
}

/* removes entry from map
 *
 * entry must be return value of fd_qos_query */
void
fd_qos_remove( fd_qos_map_t * map, fd_qos_entry_t * entry ) {
  fd_qos_map_remove( map, entry );
}

/* removes entry from map by key */
void
fd_qos_remove_key( fd_qos_map_t * map, fd_qos_key_t key ) {
  fd_qos_entry_t * entry = fd_qos_query( map, key );
  if( FD_UNLIKELY( !entry ) ) return;

  fd_qos_remove( map, entry );
}

/* obtain global map */
fd_qos_map_t *
fd_qos_global_get_map( fd_qos_t * qos ) {
  return GLOBAL_MAP( qos );
}


void
fd_qos_enqueue_delta( fd_qos_t * qos, fd_qos_entry_t * delta ) {
  if( FD_UNLIKELY( delta->value.state != FD_QOS_STATE_ASSIGNED ) ) return;

  /* next delta must point to zero */
  delta->value.rel_next = 0UL;

  /* keep trying until operation succeeds */
  while(1) {
    fd_qos_entry_t * cur = qos->deltas_sentinel;

    ulong cnt = 0UL;

    /* find end of list */
    while(1) {
      /* prevented by state transitions */
      /* however, if it occurs it's harmful, but returning is */
      /* harmless */
      if( FD_UNLIKELY( cur == delta ) ) return;

      cnt++;

      /* list at max size */
      /* will try again later */
      if( FD_UNLIKELY( cnt >= FD_QOS_MAX_QUEUED ) ) return;

      if( FD_UNLIKELY( cur->value.rel_next == CAP ) ) {
        /* start over */
        cur = qos->deltas_sentinel;
        cnt = 0;
        continue;
      }

      /* if no more, break */
      if( FD_UNLIKELY( !cur->value.rel_next ) ) break;

      cur = FD_QOS_ENTRY_NEXT_GET( cur->value.rel_next );
    }

    /* attempt atomic CAS the new delta */
    ulong            new_value      = FD_QOS_ENTRY_NEXT_SET( cur->value.rel_next, delta );
    ulong            expected_value = 0UL;
    ulong            replaced_value = FD_ATOMIC_CAS( (ulong*)&cur->value.rel_next, expected_value, new_value );

    /* if the replaced value was 0, we are done */
    if( FD_LIKELY( replaced_value == 0UL ) ) break;

    /* next pointer changed, so try again */
  }

  /* success, so update state */
  FD_VOLATILE( delta->value.state ) = FD_QOS_STATE_QUEUED;
}

/* process deltas in linked list, updating global map with each */
void
fd_qos_process_deltas( fd_qos_t * qos ) {
  fd_qos_map_t * global_map = GLOBAL_MAP( qos );

  /* for convenience */
  fd_qos_entry_t * deltas_sentinel = qos->deltas_sentinel;

  /* list empty, we're done */
  if( FD_UNLIKELY( !deltas_sentinel->value.rel_next ) ) return;

  /* fetch list */
  fd_qos_entry_t * cut = FD_QOS_ENTRY_NEXT_GET( deltas_sentinel->value.rel_next );

  /* cut list at the head */
  /* inserts only occur at the tail, so this is safe */
  FD_VOLATILE( deltas_sentinel->value.rel_next ) = 0UL;

  /* find the end, cap it
   * the cap prevents other threads/processes from enqueuing
   * but since we already cut it, there is a new end they can
   * use to append to
   */

  fd_qos_entry_t * end = cut;

  /* keep trying until successful
   * another thread could already have a reference into the list
   * and append to the end
   * this will be detected, so keep trying */
  while(1) {
    /* end is always non-zero */
    while( end->value.rel_next ) end = FD_QOS_ENTRY_NEXT_GET( end->value.rel_next );

    /* try to cap it, but fail if rel_next is non-zero, indicating a race */
    ulong old = FD_ATOMIC_CAS( &end->value.rel_next, 0UL, CAP );

    /* if the old value was 0UL, we were successful */
    if( FD_LIKELY( old == 0UL ) ) break;

    /* something went wrong - shouldn't occur */
    /* but the safe thing to do is continue */
    if( FD_UNLIKELY( old == CAP ) ) break;

    /* if there was a concurrent update, move the pointer up
     * and try again */
  }

  /* at this point, a new list ends in zero, and the old cut list is
   * capped and owned by us
   * no other thread/process can add to a capped list */

  /* start at the head of the cut */
  fd_qos_entry_t * cur = cut;

  /* process each until cap */
  while( 1 ) {
    /* sanity check */
    if( FD_UNLIKELY( !cur ) ) {
      FD_LOG_ERR(( "QOS cur pointer NULL" ));
    }

    /* transition state */
    FD_VOLATILE( cur->value.state ) = FD_QOS_STATE_PROCESSING;

    /* initialize last state to FD_QOS_STATE_ASSIGNED */
    uint dest_state = FD_QOS_STATE_ASSIGNED;

    /* find matching entry in global map */
    fd_qos_entry_t * gbl_entry = fd_qos_map_query( global_map, cur->key, NULL );

    /* if entry exists, update */
    if( FD_LIKELY( gbl_entry ) ) {
      /* this removes qty from cur and adds it to gbl_entry */
      fd_qos_delta_apply( gbl_entry, cur, qos->ema_decay );
    } else {
      /* no gbl_entry means local copies should unassign this gbl_entry */
      dest_state = FD_QOS_STATE_UNASSIGNED;

      /* set entry to zero */
      fd_qos_entry_clear( cur );
    }

    /* is rel_next the cap? */
    int next_cap = cur->value.rel_next == CAP;

    /* fetch next */
    fd_qos_entry_t * next = FD_QOS_ENTRY_NEXT_GET( cur->value.rel_next );

    /* set next to NULL */
    FD_VOLATILE( cur->value.rel_next ) = 0UL;

    /* transition state again */
    FD_VOLATILE( cur->value.state ) = dest_state;

    if( FD_UNLIKELY( next_cap ) ) break;

    /* move cur to next in list */
    cur = next;
  }

}


/* set priority based on QoS stats */
void
fd_qos_set_priority( fd_qos_priority_t * prio, fd_qos_stats_t * stats ) {
  /* This is the following, but optimized to avoid division and
     branches:
        priset_key->sgn_fail_over = (uchar)(
            stats->sgn_total                       > FD_QOS_SGN_MIN_TOTAL &&
            stats->sgn_fail / qos_entry->sgn_total > FD_QOS_SGN_RATIO_THRESH );
            */
  float txn_total            = stats->txn_success + stats->txn_fail;
  float scaled_txn_total     = FD_QOS_TXN_RATIO_THRESH * txn_total;
  float scaled_txn_min_total = FD_QOS_TXN_RATIO_THRESH * FD_QOS_TXN_MIN_TOTAL;
  prio->txn_fail_over        = (uchar)( ( stats->txn_fail  > scaled_txn_total     ) &
                                        ( scaled_txn_total > scaled_txn_min_total ) );

  float sgn_total            = stats->sgn_success + stats->sgn_fail;
  float scaled_sgn_total     = FD_QOS_SGN_RATIO_THRESH * sgn_total;
  float scaled_sgn_min_total = FD_QOS_SGN_RATIO_THRESH * FD_QOS_SGN_MIN_TOTAL;
  prio->sgn_fail_over        = (uchar)( ( stats->sgn_fail  > scaled_sgn_total     ) &
                                        ( scaled_sgn_total > scaled_sgn_min_total ) );

  prio->profit               = stats->profit;
}

/* update connection count */
void
fd_qos_update_conn_cnt( fd_qos_t * qos, fd_qos_entry_t * entry, ulong new_conn_cnt ) {
  int  old_active = ( entry->value.conn_cnt == 0 );
  int  new_active = ( new_conn_cnt          == 0 );
  uint key        = entry->key;

  /* nothing to do? */
  if( FD_UNLIKELY( old_active == new_active ) ) {
    entry->value.conn_cnt = new_conn_cnt;
    return;
  }

  qos_priset_t * qos_priset = QOS_PRISET( qos );
  qos_node_t *   pool       = POOL( qos );

  /* look up key by old_active */
  qos_node_key_t node_key = { .key = key, .active = old_active };
  qos_node_t *   node = qos_priset_ele_query( qos_priset, &node_key, pool );

  if( FD_LIKELY( node ) ) {
    /* remove */
    qos_priset_ele_remove( qos_priset, node, pool );

    /* node is still valid, so fall thru */
  } else {
    /* want to insert into priset, even if `active` is zero */
    node = qos_pool_ele_acquire( pool );
    FD_TEST( node );
  }

  /* update key */
  node->node_key.active = new_active;
  node->node_key.key    = key;

  /* update entry */
  entry->value.conn_cnt = new_conn_cnt;

  /* each insert should use a new prio */
  node->prio = fd_rng_ulong( RNG( qos ) );

  /* insert */
  qos_priset_ele_insert( qos_priset, node, pool );
}

int
fd_qos_test_query( fd_qos_t * qos, int active, uint key ) {
  qos_node_key_t node_key   = { .key = key, .active = active };
  qos_node_t *   node       = qos_priset_ele_query( QOS_PRISET( qos ), &node_key, POOL( qos ) );
  return !!node;
}
