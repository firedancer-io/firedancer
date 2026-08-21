#include "fd_gui_shred.h"
#include "fd_gui.h"

fd_gui_shred_event_iter_t *
fd_gui_shred_event_hist_iter_begin( fd_gui_t *                  gui,
                                    fd_gui_shred_event_iter_t * iter,
                                    int                         dbi,
                                    long                        after_ns,
                                    long                        before_ns ) {
  fd_memset( iter, 0, sizeof(fd_gui_shred_event_iter_t) );
  iter->_gui         = gui;
  iter->_after_ns    = after_ns;
  iter->_before_ns   = before_ns;
  iter->_pending_idx = USHORT_MAX;

  /* We widen the scan by +-1 second. The assumption here is that
     event-ordering approximately equals insert-ordering, and in rare
     cases where there is more than a second of skew in the system we
     can tolerate missing data.  */
  if( FD_LIKELY( gui->db && gui->hist ) ) {
    long lo_ns = after_ns <LONG_MIN+1L+FD_GUI_HIST_RES_1S_NS ? LONG_MIN+1L : after_ns -FD_GUI_HIST_RES_1S_NS;
    long hi_ns = before_ns>LONG_MAX-1L-FD_GUI_HIST_RES_1S_NS ? LONG_MAX-1L : before_ns+FD_GUI_HIST_RES_1S_NS;
    if( FD_LIKELY( !fd_gui_hist_range_begin( gui, &iter->_hist_iter, dbi, lo_ns, hi_ns, NULL, NULL ) ) ) {
      iter->_hist_active = 1;
    }
  }

  return iter;
}

fd_gui_shred_event_iter_t *
fd_gui_shred_event_iter_begin( fd_gui_t * gui, fd_gui_shred_event_iter_t * iter, long after_ns, long before_ns ) {
  fd_gui_shred_event_hist_iter_begin( gui, iter, FD_GUI_HIST_SHRED_EVENTS, after_ns, before_ns );
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
      iter->event.timestamp = iter->_batch->base_timestamp + (long)src->timestamp_delta;
      iter->event.slot      = (uint)iter->_batch->slot;
      iter->event.idx       = fd_ushort_if( src->event==FD_GUI_SLOT_SHRED_SHRED_SLOT_COMPLETE, USHORT_MAX, (ushort)(iter->_batch->base_idx+(ushort)src->idx_delta) );
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
    fd_gui_shred_event_staged_t const * pool = iter->_gui->shreds.shred_event_pool;
    fd_gui_shred_event_staged_t const * src = &pool[ iter->_pending_idx ];
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

static int
fd_gui_event_slot_closed( fd_gui_t * gui, ulong slot ) {
  if( gui->shreds.closed_full || slot<gui->shreds.closed_before_slot ) return 1;
  ulong lo=0UL, hi=gui->shreds.closed_slot_cnt;
  while( lo<hi ) {
    ulong mid = lo+(hi-lo)/2UL;
    if( gui->shreds.closed_slots[ mid ]<slot ) lo=mid+1UL;
    else hi=mid;
  }
  if( lo<gui->shreds.closed_slot_cnt && gui->shreds.closed_slots[ lo ]==slot ) return 1;
  fd_gui_slot_t const * meta = fd_gui_slot_get_any( gui, slot );
  return meta && meta->completed_time!=LONG_MAX;
}

static void
fd_gui_event_slot_close( fd_gui_t * gui, ulong slot ) {
  if( gui->shreds.closed_full ) {
    gui->shreds.closed_overflow_max=fd_ulong_max( gui->shreds.closed_overflow_max, slot );
    return;
  }
  if( slot<gui->shreds.closed_before_slot ) return;
  ulong lo=0UL, hi=gui->shreds.closed_slot_cnt;
  while( lo<hi ) {
    ulong mid = lo+(hi-lo)/2UL;
    if( gui->shreds.closed_slots[ mid ]<slot ) lo=mid+1UL;
    else hi=mid;
  }
  if( lo<gui->shreds.closed_slot_cnt && gui->shreds.closed_slots[ lo ]==slot ) return;
  if( gui->shreds.closed_slot_cnt==FD_GUI_SHRED_EVENT_POOL_MAX ) {
    gui->shreds.closed_full=1;
    gui->shreds.closed_overflow_max=fd_ulong_max( gui->shreds.closed_overflow_max, slot );
    return;
  }
  memmove( &gui->shreds.closed_slots[ lo+1UL ], &gui->shreds.closed_slots[ lo ],
           (gui->shreds.closed_slot_cnt-lo)*sizeof(ulong) );
  gui->shreds.closed_slots[ lo ]=slot;
  gui->shreds.closed_slot_cnt++;
}

void
fd_gui_fec_event_iter_begin( fd_gui_t * gui, fd_gui_shred_event_iter_t * iter, long after_ns, long before_ns ) {
  fd_gui_shred_event_hist_iter_begin( gui, iter, FD_GUI_HIST_FEC_EVENTS, after_ns, before_ns );
}

void
fd_gui_fec_event_staged_append( fd_gui_t * gui, ulong slot, ulong idx, uchar event, long timestamp ) {
  fd_gui_shred_event_staged_t * pool = gui->shreds.fec_event_pool;
  fd_gui_shred_event_dlist_t * list = gui->shreds.fec_event_list;
  fd_gui_fec_event_map_t * map = gui->shreds.fec_event_map;
  if( !gui->db || !gui->hist || !pool || !list || !map || slot>UINT_MAX || idx>=USHORT_MAX ||
      timestamp<0L || timestamp==LONG_MAX || event>6U || event==4U || event==5U || fd_gui_event_slot_closed( gui, slot ) ) {
    gui->shreds.dropped_fec_event_cnt++;
    return;
  }
  fd_gui_fec_event_key_t key = { .slot=(uint)slot, .idx=(ushort)idx, .event=event };
  fd_gui_shred_event_staged_t * dst = fd_gui_fec_event_map_ele_query( map, &key, NULL, pool );
  if( dst ) {
    dst->timestamp = fd_long_min( dst->timestamp, timestamp );
    return;
  }
  if( !fd_gui_shred_event_pool_free( pool ) ) { gui->shreds.dropped_fec_event_cnt++; return; }
  dst = fd_gui_shred_event_pool_ele_acquire( pool );
  dst->key=key;
  dst->timestamp=timestamp;
  fd_gui_fec_event_map_ele_insert( map, dst, pool );
  fd_gui_shred_event_dlist_ele_push_tail( list, dst, pool );
}

void
fd_gui_shred_event_staged_append( fd_gui_t * gui,
                                  ulong      slot,
                                  ulong      idx,
                                  uchar      event,
                                  long       timestamp ) {
  if( FD_UNLIKELY( !gui->db || !gui->hist || idx>=USHORT_MAX || timestamp<0L || timestamp==LONG_MAX ||
                   event>6U || event==4U || event==5U || fd_gui_event_slot_closed( gui, slot ) ) ) {
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
fd_gui_shred_event_staged_prune( fd_gui_t * gui,
                                 ulong      root_slot ) {
  fd_gui_shred_event_staged_advance( gui, root_slot, fd_log_wallclock() );
}

struct fd_gui_shred_batch_builder {
  fd_gui_shred_batch_t batch;
  long                 max_timestamp;
  ushort               max_idx;
};

typedef struct fd_gui_shred_batch_builder fd_gui_shred_batch_builder_t;

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
    batch->slot            = slot;
    batch->base_timestamp  = timestamp;
    batch->base_idx        = fd_ushort_if( is_complete, 0U, idx );
    builder->max_timestamp = timestamp;
    builder->max_idx       = batch->base_idx;
  } else {
    if( FD_UNLIKELY( batch->event_cnt>=FD_GUI_SHRED_EVENT_BATCH_MAX
                  || batch->slot!=slot
                  || fd_gui_shred_event_window( batch->base_timestamp )!=fd_gui_shred_event_window( timestamp ) ) ) return 0;

    if( FD_UNLIKELY( timestamp<batch->base_timestamp ) ) {
      ulong shift = (ulong)batch->base_timestamp-(ulong)timestamp;
      ulong span  = (ulong)builder->max_timestamp-(ulong)batch->base_timestamp;
      if( FD_UNLIKELY( shift>FD_GUI_SHRED_EVENT_TS_MAX-span ) ) return 0;
      for( ulong i=0UL; i<batch->event_cnt; i++ )
        batch->events[ i ].timestamp_delta = (uint)((batch->events[ i ].timestamp_delta+shift) & FD_GUI_SHRED_EVENT_TS_MAX);
      batch->base_timestamp = timestamp;
    } else if( FD_UNLIKELY( ((ulong)timestamp-(ulong)batch->base_timestamp)>FD_GUI_SHRED_EVENT_TS_MAX ) ) {
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
  dst->timestamp_delta = (uint)(((ulong)timestamp-(ulong)batch->base_timestamp) & FD_GUI_SHRED_EVENT_TS_MAX);
  dst->event           = event;
  dst->idx_delta       = is_complete ? 0U : (uchar)(idx-batch->base_idx);
  return 1;
}

static void
fd_gui_shred_batch_flush( fd_gui_t *                     gui,
                          fd_gui_shred_batch_builder_t * builder,
                          long                           now,
                          int                            dbi ) {
  if( FD_UNLIKELY( !builder->batch.event_cnt ) ) return;
  builder->batch.insert_time_ns = now;
  if( gui->db && gui->hist ) fd_gui_hist_ts_append( gui, dbi, &builder->batch );
  fd_memset( builder, 0, sizeof(fd_gui_shred_batch_builder_t) );
}

static void
fd_gui_event_slot_flush( fd_gui_t * gui, ulong slot, long timestamp, long now, int fec, int marker ) {
  fd_gui_shred_event_staged_t * pool = fec ? gui->shreds.fec_event_pool : gui->shreds.shred_event_pool;
  fd_gui_shred_event_dlist_t *  list = fec ? gui->shreds.fec_event_list : gui->shreds.shred_event_list;
  int dbi = fec ? FD_GUI_HIST_FEC_EVENTS : FD_GUI_HIST_SHRED_EVENTS;
  if( FD_UNLIKELY( !pool || !list ) ) return;

  fd_gui_shred_batch_builder_t builder[ 1 ];
  fd_memset( builder, 0, sizeof(fd_gui_shred_batch_builder_t) );

  fd_gui_shred_event_dlist_iter_t iter = fd_gui_shred_event_dlist_iter_fwd_init( list, pool );
  while( !fd_gui_shred_event_dlist_iter_done( iter, list, pool ) ) {
    ulong idx      = fd_gui_shred_event_dlist_iter_idx( iter, list, pool );
    ulong next_idx = fd_gui_shred_event_dlist_iter_fwd_next( iter, list, pool );
    fd_gui_shred_event_staged_t * staged = &pool[ idx ];
    if( FD_LIKELY( staged->slot==slot ) ) {
      if( FD_UNLIKELY( !fd_gui_shred_batch_try_add( builder, slot, staged->timestamp, staged->idx, staged->event ) ) ) {
        fd_gui_shred_batch_flush( gui, builder, now, dbi );
        FD_TEST( fd_gui_shred_batch_try_add( builder, slot, staged->timestamp, staged->idx, staged->event ) );
      }
      fd_gui_shred_event_dlist_idx_remove( list, idx, pool );
      if( fec ) fd_gui_fec_event_map_idx_remove( gui->shreds.fec_event_map, &staged->key, USHORT_MAX, pool );
      fd_gui_shred_event_pool_idx_release( pool, idx );
    }
    iter = next_idx;
  }

  if( marker && FD_UNLIKELY( !fd_gui_shred_batch_try_add( builder, slot, timestamp, USHORT_MAX,
                                                          FD_GUI_SLOT_SHRED_SHRED_SLOT_COMPLETE ) ) ) {
    fd_gui_shred_batch_flush( gui, builder, now, dbi );
    FD_TEST( fd_gui_shred_batch_try_add( builder, slot, timestamp, USHORT_MAX,
                                        FD_GUI_SLOT_SHRED_SHRED_SLOT_COMPLETE ) );
  }
  fd_gui_shred_batch_flush( gui, builder, now, dbi );
}

void
fd_gui_fec_completion_iter_begin( fd_gui_t * gui, fd_gui_fec_completion_iter_t * it, long after_ns, long before_ns ) {
  memset( it, 0, sizeof(*it) );
  it->after_ns=after_ns;
  it->before_ns=before_ns;
  if( gui->db && gui->hist ) {
    long lo=fd_long_max( LONG_MIN+1L, fd_long_sat_sub( after_ns, FD_GUI_HIST_RES_1S_NS ) );
    long hi=fd_long_min( LONG_MAX-1L, fd_long_sat_add( before_ns, FD_GUI_HIST_RES_1S_NS ) );
    it->hist_active=!fd_gui_hist_range_begin( gui, &it->hist_iter, FD_GUI_HIST_FEC_COMPLETIONS, lo, hi, NULL, NULL );
  }
}

int
fd_gui_fec_completion_iter_next( fd_gui_fec_completion_iter_t * it ) {
  while( it->hist_active ) {
    if( it->batch && it->batch_idx<fd_ulong_min( it->batch->event_cnt, FD_GUI_FEC_COMPLETION_BATCH_MAX ) ) {
      it->event=it->batch->events[ it->batch_idx++ ];
      it->slot=it->batch->slot;
      if( it->event.timestamp>=it->after_ns && it->event.timestamp<=it->before_ns ) return 1;
      continue;
    }
    it->batch=NULL;
    if( fd_gui_hist_range_next( &it->hist_iter ) ) {
      it->batch=it->hist_iter.rec;
      it->batch_idx=0UL;
      continue;
    }
    fd_gui_hist_range_end( &it->hist_iter );
    it->hist_active=0;
  }
  return 0;
}

void
fd_gui_fec_completion_iter_end( fd_gui_fec_completion_iter_t * it ) {
  if( it->hist_active ) fd_gui_hist_range_end( &it->hist_iter );
  it->hist_active=0;
}

int
fd_gui_fec_completion_staged_append( fd_gui_t * gui, ulong slot, long timestamp,
                                     ulong turbine, ulong repair, ulong reconstructed, int leader ) {
  fd_gui_fec_completion_staged_t * pool=gui->shreds.completion_pool;
  fd_gui_fec_completion_dlist_t * list=gui->shreds.completion_list;
  if( !gui->db || !gui->hist || slot>UINT_MAX || timestamp<0L || timestamp==LONG_MAX ||
      turbine>64UL || repair>64UL || reconstructed>64UL || fd_gui_event_slot_closed( gui, slot ) ) {
    gui->shreds.dropped_completion_cnt++;
    return 0;
  }
  /* Collection still checks staged completions for duplicates. */
  if( pool && list ) for( ulong i=fd_gui_fec_completion_dlist_idx_peek_head( list, pool ); i!=USHORT_MAX; i=pool[i].dlist_next ) {
    fd_gui_fec_completion_staged_t const * src=&pool[i];
    if( src->slot==slot && src->event.timestamp==timestamp && src->event.turbine==turbine &&
        src->event.repair==repair && src->event.reconstructed==reconstructed && src->event.leader==!!leader ) return 0;
  }
  fd_gui_fec_completion_iter_t it;
  fd_gui_fec_completion_iter_begin( gui, &it, timestamp, timestamp );
  while( fd_gui_fec_completion_iter_next( &it ) ) {
    if( it.slot==slot && it.event.timestamp==timestamp && it.event.turbine==turbine &&
        it.event.repair==repair && it.event.reconstructed==reconstructed && it.event.leader==!!leader ) {
      fd_gui_fec_completion_iter_end( &it );
      return 0;
    }
  }
  fd_gui_fec_completion_iter_end( &it );
  if( !pool || !list || !fd_gui_fec_completion_pool_free( pool ) ) { gui->shreds.dropped_completion_cnt++; return -1; }
  fd_gui_fec_completion_staged_t * dst=fd_gui_fec_completion_pool_ele_acquire( pool );
  dst->slot=(uint)slot;
  dst->event=(fd_gui_fec_completion_t){ .timestamp=timestamp, .turbine=(uchar)turbine,
    .repair=(uchar)repair, .reconstructed=(uchar)reconstructed, .leader=(uchar)!!leader };
  fd_gui_fec_completion_dlist_ele_push_tail( list, dst, pool );
  return 1;
}

static void
fd_gui_completion_slot_flush( fd_gui_t * gui, ulong slot, long now ) {
  fd_gui_fec_completion_staged_t * pool=gui->shreds.completion_pool;
  fd_gui_fec_completion_dlist_t * list=gui->shreds.completion_list;
  if( !pool || !list ) return;
  fd_gui_fec_completion_batch_t batch={ .slot=slot, .insert_time_ns=now };
  for( ulong i=fd_gui_fec_completion_dlist_idx_peek_head( list, pool ); i!=USHORT_MAX; ) {
    ulong next=pool[i].dlist_next;
    if( pool[i].slot==slot ) {
      batch.events[ batch.event_cnt++ ]=pool[i].event;
      fd_gui_fec_completion_dlist_idx_remove( list, i, pool );
      fd_gui_fec_completion_pool_idx_release( pool, i );
      if( batch.event_cnt==FD_GUI_FEC_COMPLETION_BATCH_MAX ) {
        if( gui->db && gui->hist ) fd_gui_hist_ts_append( gui, FD_GUI_HIST_FEC_COMPLETIONS, &batch );
        batch.event_cnt=0U;
      }
    }
    i=next;
  }
  if( batch.event_cnt && gui->db && gui->hist ) fd_gui_hist_ts_append( gui, FD_GUI_HIST_FEC_COMPLETIONS, &batch );
}

void
fd_gui_shred_event_slot_complete( fd_gui_t * gui, ulong slot, long timestamp, long now ) {
  if( FD_UNLIKELY( slot>UINT_MAX ) ) return;
  fd_gui_event_slot_close( gui, slot );
  fd_gui_event_slot_flush( gui, slot, timestamp, now, 0, 1 );
  fd_gui_event_slot_flush( gui, slot, timestamp, now, 1, 1 );
  fd_gui_completion_slot_flush( gui, slot, now );
}

void
fd_gui_shred_event_staged_advance( fd_gui_t * gui, ulong cutoff, long now ) {
  if( cutoff==ULONG_MAX || cutoff<=gui->shreds.closed_before_slot ) return;
  gui->shreds.closed_before_slot=cutoff;
  ulong n=0UL;
  for( ulong i=0UL; i<gui->shreds.closed_slot_cnt; i++ )
    if( gui->shreds.closed_slots[i]>=cutoff ) gui->shreds.closed_slots[n++]=gui->shreds.closed_slots[i];
  gui->shreds.closed_slot_cnt=n;
  if( gui->shreds.closed_full && n<FD_GUI_SHRED_EVENT_POOL_MAX && cutoff>gui->shreds.closed_overflow_max )
    gui->shreds.closed_full=0;
  for( int fec=0; fec<2; fec++ ) {
    fd_gui_shred_event_staged_t * pool=fec ? gui->shreds.fec_event_pool : gui->shreds.shred_event_pool;
    fd_gui_shred_event_dlist_t * list=fec ? gui->shreds.fec_event_list : gui->shreds.shred_event_list;
    if( !pool || !list ) continue;
    for(;;) {
      ulong slot=ULONG_MAX;
      for( ulong i=fd_gui_shred_event_dlist_idx_peek_head( list, pool ); i!=USHORT_MAX; i=pool[i].dlist_next )
        if( pool[i].slot<cutoff ) { slot=pool[i].slot; break; }
      if( slot==ULONG_MAX ) break;
      fd_gui_event_slot_flush( gui, slot, 0L, now, fec, 0 );
    }
  }
  fd_gui_fec_completion_staged_t * pool=gui->shreds.completion_pool;
  fd_gui_fec_completion_dlist_t * list=gui->shreds.completion_list;
  if( !pool || !list ) return;
  for(;;) {
    ulong slot=ULONG_MAX;
    for( ulong i=fd_gui_fec_completion_dlist_idx_peek_head( list, pool ); i!=USHORT_MAX; i=pool[i].dlist_next )
      if( pool[i].slot<cutoff ) { slot=pool[i].slot; break; }
    if( slot==ULONG_MAX ) break;
    fd_gui_completion_slot_flush( gui, slot, now );
  }
}

int
fd_gui_event_bounds( fd_gui_t * gui, int dbi, long * lo, long * hi ) {
  long first, last;
  int have=gui->db && fd_gui_store_ts_live_timestamp_bounds( gui->db, (ulong)dbi, &first, &last );
  *lo=have ? fd_long_max( 0L, fd_long_sat_sub( first, FD_GUI_HIST_RES_1S_NS ) ) : LONG_MAX;
  *hi=have ? fd_long_min( LONG_MAX-1L, fd_long_sat_add( last, FD_GUI_HIST_RES_1S_NS+1L ) ) : LONG_MIN;
  return have;
}

int
fd_gui_shred_window_is_empty( fd_gui_t * gui,
                              long       after_ns,
                              long       before_ns ) {
  fd_gui_shred_event_iter_t it[ 1 ];
  fd_gui_shred_event_iter_begin( gui, it, after_ns, before_ns );
  if( FD_LIKELY( fd_gui_shred_event_iter_next( it ) ) ) {
    fd_gui_shred_event_iter_end( it );
    return 0;
  }
  fd_gui_shred_event_iter_end( it );
  return 1;
}
