#include "fd_qos.h"

#include "fd_qos_map.h"


struct fd_qos_local {
  ulong  magic;
  void * local_map_mem;
  void * local_map;
};


/* fd_qos_local_{align,footprint} return the required alignment and footprint
 * for the memory region in order to create a new fd_qos */

FD_FN_CONST ulong
fd_qos_local_align( void ) {
  return FD_QOS_ALIGN;
}

FD_FN_CONST ulong
fd_qos_local_footprint( ulong entry_cnt ) {
  ulong lg_entry_cnt = 10UL;
  while( ( 1UL << lg_entry_cnt ) < entry_cnt ) lg_entry_cnt++;

  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, FD_QOS_ALIGN, sizeof( fd_qos_local_t ) );
  l = FD_LAYOUT_APPEND( l, fd_qos_map_align(), fd_qos_map_footprint( (int)lg_entry_cnt ) );

  return FD_LAYOUT_FINI( l, FD_QOS_ALIGN );
}

/* fd_qos_local_new creates a new fd_qos_local with the capacity for the given number
 * of entries and tiles.
 * This represents a local cache ofqos data that is periodically forwarded to the
 * global qos map for processing */
void *
fd_qos_local_new( void * mem, ulong entry_cnt ) {
  /* sanity checks */
  if( FD_UNLIKELY( !mem ) )                              return NULL;
  if( !fd_ulong_is_aligned( (ulong)mem, FD_QOS_ALIGN ) ) return NULL;

  ulong lg_entry_cnt = 10UL;
  while( ( 1UL << lg_entry_cnt ) < entry_cnt ) lg_entry_cnt++;

  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_qos_local_t * qos_local = FD_SCRATCH_ALLOC_APPEND( l, FD_QOS_ALIGN, sizeof( fd_qos_local_t ) );
  void *           local_map = FD_SCRATCH_ALLOC_APPEND( l, fd_qos_map_align(), fd_qos_map_footprint( (int)lg_entry_cnt ) );

  FD_SCRATCH_ALLOC_FINI( l, FD_QOS_ALIGN );

  memset( qos_local, 0, sizeof( *qos_local ) );

  /* new map */
  qos_local->local_map_mem = fd_qos_map_new( local_map, (int)lg_entry_cnt );

  /* set magic, after ensuring all prior values written */
  FD_COMPILER_MFENCE();
  qos_local->magic = FD_QOS_MAGIC;
  FD_COMPILER_MFENCE();

  return qos_local;
}


fd_qos_local_t *
fd_qos_local_join( void * mem ) {
  fd_qos_local_t * qos_local = (fd_qos_local_t*)mem;

  if( FD_UNLIKELY( qos_local->magic != FD_QOS_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  /* join map */
  qos_local->local_map = fd_qos_map_join( qos_local->local_map_mem );

  return qos_local;
}

void *
fd_qos_local_leave( fd_qos_local_t * qos_local ) {
  if( FD_UNLIKELY( qos_local->magic != FD_QOS_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  fd_qos_map_leave( qos_local->local_map );
  return (void*)qos_local;
}

void *
fd_qos_local_delete( void * mem ) {
  fd_qos_local_t * qos_local = (fd_qos_local_t*)mem;

  if( FD_UNLIKELY( !qos_local ) ) return NULL;

  if( FD_UNLIKELY( qos_local->magic != FD_QOS_MAGIC ) ) {
    FD_LOG_WARNING(( "bad magic" ));
    return NULL;
  }

  qos_local->magic = 0;

  return mem;
}

/* get map for the local tile */
fd_qos_map_t *
fd_qos_local_get_map( fd_qos_local_t * qos_local ) {
  return (fd_qos_map_t*)qos_local->local_map;
}

fd_qos_entry_t *
fd_qos_local_query_forced( fd_qos_local_t * qos_local, fd_qos_key_t key ) {
  fd_qos_map_t *   local_map  = qos_local->local_map;
  fd_qos_entry_t * entry      = fd_qos_map_query( local_map, key, NULL );
  FD_DEBUG( FD_LOG_WARNING(( "fd_qos_local_query_forced - %x", (uint)key )); )

  if( FD_LIKELY( entry ) ) {
    FD_DEBUG( FD_LOG_WARNING(( "fd_qos_local_query_forced - %x  conn_cnt: %lu", (uint)key, (ulong)entry->value.conn_cnt )); )

    /* FD_QOS_STATE_UNASSIGNED indicates we should remove the entry */
    if( FD_UNLIKELY( entry->value.state == FD_QOS_STATE_UNASSIGNED ) ) {
      entry->value.state = FD_QOS_STATE_IDLE;
      fd_qos_map_remove( qos_local->local_map, entry );
      return NULL;
    }

    return entry;
  }

  /* attempt insert into global map */
  /* initialized upon success */
  entry = fd_qos_insert( local_map, key );
  if( FD_LIKELY( entry ) ) {
    /* local entry should be in assigned state */
    /* TODO consider having separate state for local entries */
    entry->value.state = FD_QOS_STATE_ASSIGNED;
  }

  return entry; /* could be NULL - caller will try again */
}

void
fd_qos_local_update( fd_qos_local_t * qos_local,
                     fd_qos_t *       qos,
                     long             now,
                     int              type,
                     fd_qos_key_t     key,
                     float            delta ) {

  fd_qos_entry_t * entry = fd_qos_local_query_forced( qos_local, key );
  if( FD_UNLIKELY( !entry ) ) return;

  if( FD_UNLIKELY( entry->value.state == FD_QOS_STATE_UNASSIGNED ) ) {
    entry->value.state = FD_QOS_STATE_IDLE;

    /* IP address is being removed - so remove from local map */
    fd_qos_map_remove( qos_local->local_map, entry );
    return;
  }

  long prior_time = (long)entry->value.last_update;

  long decay_time = now - prior_time;

  float decay = FD_QOS_EMA_DECAY;

  switch( type ) {
    case FD_QOS_TYPE_PROFIT:
      entry->value.stats.profit += delta;
      break;

    case FD_QOS_TYPE_TXN_FAIL:
      fd_qos_delta_update( &entry->value.stats.txn_fail, decay, delta, decay_time );
      break;

    case FD_QOS_TYPE_TXN_SUCCESS:
      fd_qos_delta_update( &entry->value.stats.txn_success, decay, delta, decay_time );
      break;

    case FD_QOS_TYPE_SGN_FAIL:
      fd_qos_delta_update( &entry->value.stats.sgn_fail, decay, delta, decay_time );
      break;

    case FD_QOS_TYPE_SGN_SUCCESS:
      fd_qos_delta_update( &entry->value.stats.sgn_success, decay, delta, decay_time );
      break;

    default:
      return;
  }

  entry->value.last_update = (ulong)now;

  if( FD_UNLIKELY( (ulong)now > entry->value.next_queue_time ) ) {
    entry->value.next_queue_time = (ulong)now + FD_QOS_UPDATE_PERIOD;
    fd_qos_enqueue_delta( qos, entry );
  }
}

