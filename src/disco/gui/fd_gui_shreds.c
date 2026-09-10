#include "fd_gui_shreds.h"
#include "fd_gui.h"

static inline ulong
fd_gui_shred_event_timestamp_delta_load( uchar const delta[ 3 ] ) {
  return (ulong)delta[ 0 ] | ((ulong)delta[ 1 ]<<8) | ((ulong)delta[ 2 ]<<16);
}

static inline void
fd_gui_shred_event_timestamp_delta_store( uchar delta[ 3 ],
                                          ulong value ) {
  delta[ 0 ] = (uchar) value;
  delta[ 1 ] = (uchar)(value>>8);
  delta[ 2 ] = (uchar)(value>>16);
}

fd_gui_shred_event_iter_t *
fd_gui_shred_event_iter_begin( fd_gui_t *                  gui,
                               fd_gui_shred_event_iter_t * iter,
                               long                        after_ns,
                               long                        before_ns ) {
  fd_memset( iter, 0, sizeof(fd_gui_shred_event_iter_t) );
  iter->_gui         = gui;
  iter->_after_ns    = after_ns;
  iter->_before_ns   = before_ns;
  iter->_pending_idx = USHORT_MAX;

  if( FD_LIKELY( gui->db && gui->hist ) ) {
    if( FD_LIKELY( !fd_gui_hist_range_begin( gui, &iter->_hist_iter, FD_GUI_HIST_SHRED_EVENTS, after_ns, before_ns, NULL, NULL ) ) ) {
      iter->_hist_active = 1;
    }
  }

  if( FD_LIKELY( gui->shreds.shred_event_pool && gui->shreds.shred_event_list &&
                 !fd_gui_shred_event_dlist_is_empty( gui->shreds.shred_event_list, gui->shreds.shred_event_pool ) ) ) {
    iter->_pending_idx = fd_gui_shred_event_dlist_idx_peek_head( gui->shreds.shred_event_list, gui->shreds.shred_event_pool );
  }
  return iter;
}

int
fd_gui_shred_event_iter_next( fd_gui_shred_event_iter_t * iter ) {
  while( iter->_hist_active ) {
    if( FD_LIKELY( iter->_batch && iter->_batch_idx<fd_ulong_min( iter->_batch->event_cnt, FD_GUI_SHRED_EVENT_BATCH_MAX ) ) ) {
      fd_gui_shred_batch_event_t const * src = &iter->_batch->events[ iter->_batch_idx++ ];
      iter->event.timestamp = iter->_batch->base_timestamp + (long)fd_gui_shred_event_timestamp_delta_load( src->timestamp_delta );
      iter->event.slot      = (uint)iter->_batch->slot;
      iter->event.idx       = fd_ushort_if( src->event==FD_GUI_SLOT_SHRED_SHRED_SLOT_COMPLETE,
                                           USHORT_MAX,
                                           (ushort)(iter->_batch->base_idx+(ushort)src->idx_delta) );
      iter->event.event     = src->event;
      if( FD_LIKELY( iter->event.timestamp>=iter->_after_ns && iter->event.timestamp<=iter->_before_ns ) ) return 1;
      continue;
    }

    iter->_batch = NULL;
    if( FD_LIKELY( fd_gui_hist_range_next( &iter->_hist_iter ) ) ) {
      iter->_batch     = (fd_gui_shred_batch_t const *)iter->_hist_iter.rec;
      iter->_batch_idx = 0UL;
      continue;
    }
    fd_gui_hist_range_end( &iter->_hist_iter );
    iter->_hist_active = 0;
  }

  while( iter->_pending_idx!=USHORT_MAX ) {
    fd_gui_shred_event_staged_t const * src = &iter->_gui->shreds.shred_event_pool[ iter->_pending_idx ];
    iter->_pending_idx = src->dlist_next;
    iter->event.timestamp = src->timestamp;
    iter->event.slot      = src->slot;
    iter->event.idx       = src->idx;
    iter->event.event     = src->event;
    if( FD_LIKELY( iter->event.timestamp>=iter->_after_ns && iter->event.timestamp<=iter->_before_ns ) ) return 1;
  }
  return 0;
}

void
fd_gui_shred_event_iter_end( fd_gui_shred_event_iter_t * iter ) {
  if( FD_LIKELY( iter->_hist_active ) ) fd_gui_hist_range_end( &iter->_hist_iter );
  iter->_hist_active = 0;
}

void
fd_gui_shred_event_append( fd_gui_t * gui,
                           ulong      slot,
                           ulong      idx,
                           uchar      event,
                           long       timestamp ) {
  if( FD_UNLIKELY( idx>=USHORT_MAX ) ) {
    gui->shreds.dropped_event_cnt++;
    return;
  }
  if( FD_UNLIKELY( slot>UINT_MAX ) ) {
    gui->shreds.dropped_event_cnt++;
    return;
  }

  if( FD_LIKELY( gui->db && gui->hist ) ) {
    fd_gui_slot_t const * slot_meta = fd_gui_slot_get_any( gui, slot );
    if( FD_UNLIKELY( slot_meta && slot_meta->completed_time!=LONG_MAX ) ) {
      gui->shreds.dropped_event_cnt++;
      return;
    }
  }

  fd_gui_shred_event_staged_t * pool = gui->shreds.shred_event_pool;
  fd_gui_shred_event_dlist_t *  list = gui->shreds.shred_event_list;
  if( FD_UNLIKELY( !pool || !list || !fd_gui_shred_event_pool_free( pool ) ) ) {
    gui->shreds.dropped_event_cnt++;
    return;
  }

  fd_gui_shred_event_staged_t * staged = fd_gui_shred_event_pool_ele_acquire( pool );
  staged->timestamp = timestamp;
  staged->slot      = (uint)slot;
  staged->idx       = (ushort)idx;
  staged->event     = event;
  fd_gui_shred_event_dlist_ele_push_tail( list, staged, pool );
}

void
fd_gui_shred_event_reclaim_before( fd_gui_t * gui,
                                   ulong      root_slot ) {
  fd_gui_shred_event_staged_t * pool = gui->shreds.shred_event_pool;
  fd_gui_shred_event_dlist_t *  list = gui->shreds.shred_event_list;
  if( FD_UNLIKELY( !pool || !list ) ) return;

  for( fd_gui_shred_event_dlist_iter_t iter = fd_gui_shred_event_dlist_iter_fwd_init( list, pool );
       !fd_gui_shred_event_dlist_iter_done( iter, list, pool ); ) {
    ulong idx      = fd_gui_shred_event_dlist_iter_idx( iter, list, pool );
    ulong next_idx = fd_gui_shred_event_dlist_iter_fwd_next( iter, list, pool );
    if( FD_UNLIKELY( (ulong)pool[ idx ].slot<root_slot ) ) {
      fd_gui_shred_event_dlist_idx_remove( list, idx, pool );
      fd_gui_shred_event_pool_idx_release( pool, idx );
    }
    iter = next_idx;
  }
}

struct fd_gui_shred_batch_builder {
  fd_gui_shred_batch_t batch;
  long                 max_timestamp;
  ushort               max_idx;
};

typedef struct fd_gui_shred_batch_builder fd_gui_shred_batch_builder_t;

static inline long
fd_gui_shred_event_timestamp_clamp( long timestamp,
                                    long now ) {
  return fd_long_max( now-FD_GUI_HIST_TS_SKEW_NS, fd_long_min( timestamp, now+FD_GUI_HIST_TS_SKEW_NS ) );
}

static inline ulong
fd_gui_shred_event_window( long timestamp ) {
  return timestamp<=0L ? 0UL : (ulong)(timestamp / FD_GUI_HIST_RES_1S_NS);
}

static int
fd_gui_shred_batch_try_add( fd_gui_shred_batch_builder_t * builder,
                            ulong                          slot,
                            long                           timestamp,
                            ushort                         idx,
                            uchar                          event ) {
  fd_gui_shred_batch_t * batch = &builder->batch;
  int const is_complete = event==FD_GUI_SLOT_SHRED_SHRED_SLOT_COMPLETE;

  if( FD_UNLIKELY( !batch->event_cnt ) ) {
    batch->slot           = slot;
    batch->base_timestamp = timestamp;
    batch->base_idx       = fd_ushort_if( is_complete, 0U, idx );
    builder->max_timestamp = timestamp;
    builder->max_idx       = batch->base_idx;
  } else {
    if( FD_UNLIKELY( batch->event_cnt>=FD_GUI_SHRED_EVENT_BATCH_MAX ||
                     batch->slot!=slot ||
                     fd_gui_shred_event_window( batch->base_timestamp )!=fd_gui_shred_event_window( timestamp ) ) ) return 0;

    if( FD_UNLIKELY( timestamp<batch->base_timestamp ) ) {
      ulong shift = (ulong)(batch->base_timestamp-timestamp);
      ulong span  = (ulong)(builder->max_timestamp-batch->base_timestamp);
      if( FD_UNLIKELY( shift>FD_GUI_SHRED_EVENT_TS_MAX-span ) ) return 0;
      for( ulong i=0UL; i<batch->event_cnt; i++ ) {
        ulong delta = fd_gui_shred_event_timestamp_delta_load( batch->events[ i ].timestamp_delta );
        fd_gui_shred_event_timestamp_delta_store( batch->events[ i ].timestamp_delta, delta+shift );
      }
      batch->base_timestamp = timestamp;
    } else if( FD_UNLIKELY( (ulong)(timestamp-batch->base_timestamp)>FD_GUI_SHRED_EVENT_TS_MAX ) ) {
      return 0;
    }
    builder->max_timestamp = fd_long_max( builder->max_timestamp, timestamp );

    if( FD_LIKELY( !is_complete ) ) {
      if( FD_UNLIKELY( idx<batch->base_idx ) ) {
        ulong shift = (ulong)(batch->base_idx-idx);
        ulong span  = (ulong)(builder->max_idx-batch->base_idx);
        if( FD_UNLIKELY( shift>UCHAR_MAX-span ) ) return 0;
        for( ulong i=0UL; i<batch->event_cnt; i++ ) batch->events[ i ].idx_delta = (uchar)(batch->events[ i ].idx_delta+shift);
        batch->base_idx = idx;
      } else if( FD_UNLIKELY( (ulong)(idx-batch->base_idx)>UCHAR_MAX ) ) {
        return 0;
      }
      builder->max_idx = fd_ushort_max( builder->max_idx, idx );
    }
  }

  fd_gui_shred_batch_event_t * dst = &batch->events[ batch->event_cnt++ ];
  fd_gui_shred_event_timestamp_delta_store( dst->timestamp_delta, (ulong)(timestamp-batch->base_timestamp) );
  dst->event     = event;
  dst->idx_delta = is_complete ? 0U : (uchar)(idx-batch->base_idx);
  return 1;
}

static void
fd_gui_shred_batch_flush( fd_gui_t *                     gui,
                          fd_gui_shred_batch_builder_t * builder,
                          long                           now ) {
  if( FD_UNLIKELY( !builder->batch.event_cnt ) ) return;
  fd_gui_hist_ts_append( gui, FD_GUI_HIST_SHRED_EVENTS, now, builder->batch.base_timestamp, &builder->batch );
  fd_memset( builder, 0, sizeof(fd_gui_shred_batch_builder_t) );
}

void
fd_gui_shred_event_slot_complete( fd_gui_t * gui,
                                  ulong      slot,
                                  long       timestamp,
                                  long       now ) {
  fd_gui_shred_event_staged_t * pool = gui->shreds.shred_event_pool;
  fd_gui_shred_event_dlist_t *  list = gui->shreds.shred_event_list;
  if( FD_UNLIKELY( !pool || !list ) ) return;

  fd_gui_shred_batch_builder_t builder[ 1 ];
  fd_memset( builder, 0, sizeof(fd_gui_shred_batch_builder_t) );

  for( fd_gui_shred_event_dlist_iter_t iter = fd_gui_shred_event_dlist_iter_fwd_init( list, pool );
       !fd_gui_shred_event_dlist_iter_done( iter, list, pool ); ) {
    ulong idx      = fd_gui_shred_event_dlist_iter_idx( iter, list, pool );
    ulong next_idx = fd_gui_shred_event_dlist_iter_fwd_next( iter, list, pool );
    fd_gui_shred_event_staged_t * staged = &pool[ idx ];
    if( FD_LIKELY( staged->slot==slot ) ) {
      long event_timestamp = fd_gui_shred_event_timestamp_clamp( staged->timestamp, now );
      if( FD_UNLIKELY( !fd_gui_shred_batch_try_add( builder, slot, event_timestamp, staged->idx, staged->event ) ) ) {
        fd_gui_shred_batch_flush( gui, builder, now );
        FD_TEST( fd_gui_shred_batch_try_add( builder, slot, event_timestamp, staged->idx, staged->event ) );
      }
      fd_gui_shred_event_dlist_idx_remove( list, idx, pool );
      fd_gui_shred_event_pool_idx_release( pool, idx );
    }
    iter = next_idx;
  }

  long completion_timestamp = fd_gui_shred_event_timestamp_clamp( timestamp, now );
  if( FD_UNLIKELY( !fd_gui_shred_batch_try_add( builder, slot, completion_timestamp, USHORT_MAX,
                                                FD_GUI_SLOT_SHRED_SHRED_SLOT_COMPLETE ) ) ) {
    fd_gui_shred_batch_flush( gui, builder, now );
    FD_TEST( fd_gui_shred_batch_try_add( builder, slot, completion_timestamp, USHORT_MAX,
                                        FD_GUI_SLOT_SHRED_SHRED_SLOT_COMPLETE ) );
  }
  fd_gui_shred_batch_flush( gui, builder, now );
}
