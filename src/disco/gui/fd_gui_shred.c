#include "fd_gui_shred.h"
#include "fd_gui.h"

#define FD_GUI_SHRED_LITERAL     (0U)
#define FD_GUI_SHRED_DELTA       (1U)
#define FD_GUI_SHRED_TS_NEG      (2U)
#define FD_GUI_SHRED_IDX_NEG     (4U)
#define FD_GUI_SHRED_EVENT_SHIFT (3U)

struct __attribute__((packed)) fd_gui_shred_delta {
  uint  insert_delta;
  uint  timestamp_delta : 24;
  uchar idx_delta;
};
typedef struct fd_gui_shred_delta fd_gui_shred_delta_t;

FD_STATIC_ASSERT( sizeof(fd_gui_shred_delta_t)==8UL, shred_delta_sz );
FD_STATIC_ASSERT( sizeof(fd_gui_shred_batch_t)==FD_GUI_SHRED_BATCH_SZ, shred_batch_sz );

static ulong
shred_window( long ns ) {
  return ns<=0L ? 0UL : (ulong)(ns/FD_GUI_HIST_RES_1S_NS);
}

static int
batch_append( fd_gui_shred_builder_t *      builder,
              fd_gui_shred_event_t const * event ) {
  fd_gui_shred_batch_t * batch = &builder->batch;
  fd_gui_shred_event_t const * prev = &builder->prev;
  ulong ts_delta = event->event_time_ns>=prev->event_time_ns
      ? (ulong)event->event_time_ns-(ulong)prev->event_time_ns
      : (ulong)prev->event_time_ns-(ulong)event->event_time_ns;
  ulong idx_delta = event->idx>=prev->idx ? (ulong)(event->idx-prev->idx) : (ulong)(prev->idx-event->idx);
  int delta = batch->event_cnt && event->slot==prev->slot && ts_delta<=FD_GUI_SHRED_EVENT_TS_MAX && idx_delta<=UCHAR_MAX &&
              event->event<=(UCHAR_MAX>>FD_GUI_SHRED_EVENT_SHIFT);
  ulong sz = 1UL + (delta ? sizeof(fd_gui_shred_delta_t) : sizeof(fd_gui_shred_event_t));
  if( FD_UNLIKELY( sz>sizeof(batch->data)-batch->data_sz ) ) return 0;

  uchar * dst = batch->data+batch->data_sz;
  if( FD_LIKELY( delta ) ) {
    *dst++ = (uchar)(FD_GUI_SHRED_DELTA |
                    (event->event_time_ns<prev->event_time_ns ? FD_GUI_SHRED_TS_NEG  : 0U) |
                    (event->idx<prev->idx ? FD_GUI_SHRED_IDX_NEG : 0U) |
                    ((uint)event->event<<FD_GUI_SHRED_EVENT_SHIFT));
    fd_gui_shred_delta_t d = {
      .insert_delta    = (uint)(event->insert_time_ns-prev->insert_time_ns),
      .timestamp_delta = (uint)(ts_delta & FD_GUI_SHRED_EVENT_TS_MAX),
      .idx_delta       = (uchar)idx_delta
    };
    fd_memcpy( dst, &d, sizeof(d) );
  } else {
    *dst++ = FD_GUI_SHRED_LITERAL;
    fd_memcpy( dst, event, sizeof(*event) );
  }
  batch->data_sz += (uint)sz;
  batch->event_cnt++;
  builder->prev = *event;
  return 1;
}

static void
batch_next( fd_gui_shred_event_iter_t * iter ) {
  uchar const * src = iter->_batch->data+iter->_data_off;
  uchar tag = *src++;
  if( FD_LIKELY( tag & FD_GUI_SHRED_DELTA ) ) {
    fd_gui_shred_delta_t d;
    fd_memcpy( &d, src, sizeof(d) );
    iter->event.insert_time_ns += (long)d.insert_delta;
    iter->event.event_time_ns += (tag & FD_GUI_SHRED_TS_NEG) ? -(long)d.timestamp_delta : (long)d.timestamp_delta;
    iter->event.idx = (ushort)((tag & FD_GUI_SHRED_IDX_NEG) ? iter->event.idx-d.idx_delta : iter->event.idx+d.idx_delta);
    iter->event.event = (uchar)(tag>>FD_GUI_SHRED_EVENT_SHIFT);
    iter->_data_off += 1UL+sizeof(d);
  } else {
    fd_memcpy( &iter->event, src, sizeof(iter->event) );
    iter->_data_off += 1UL+sizeof(iter->event);
  }
  iter->_batch_idx++;
}

static fd_gui_shred_event_iter_t *
shred_iter_begin( fd_gui_t *                  gui,
                  fd_gui_shred_event_iter_t * iter,
                  int                         event_time,
                  long                        after_ns,
                  long                        before_ns ) {
  fd_memset( iter, 0, sizeof(*iter) );
  iter->_gui        = gui;
  iter->_after_ns   = after_ns;
  iter->_before_ns  = before_ns;
  iter->_event_time = event_time;

  /* Event-time queries widen the scan by +-1 second. The assumption is that
     event-ordering approximately equals insert-ordering, and in rare
     cases where there is more than a second of skew in the system we
     can tolerate missing data.  */
  if( FD_LIKELY( gui->db && gui->hist && after_ns<=before_ns ) ) {
    long margin = event_time ? FD_GUI_HIST_RES_1S_NS : 0L;
    long lo_ns = fd_long_max( 0L, fd_long_sat_sub( after_ns, margin ) );
    long hi_ns = fd_long_min( LONG_MAX-1L, fd_long_sat_add( before_ns, margin ) );
    iter->_hist_active = !fd_gui_hist_range_begin( gui, &iter->_hist_iter, FD_GUI_HIST_SHRED_EVENTS, lo_ns, hi_ns, NULL, NULL );
    iter->_builder_pending = 1;
  }
  return iter;
}

fd_gui_shred_event_iter_t *
fd_gui_shred_event_hist_iter_begin( fd_gui_t *                  gui,
                                    fd_gui_shred_event_iter_t * iter,
                                    long                        after_ns,
                                    long                        before_ns ) {
  return shred_iter_begin( gui, iter, 1, after_ns, before_ns );
}

fd_gui_shred_event_iter_t *
fd_gui_shred_event_iter_begin( fd_gui_t *                  gui,
                               fd_gui_shred_event_iter_t * iter,
                               long                        after_ns,
                               long                        before_ns ) {
  return shred_iter_begin( gui, iter, 0, fd_long_max( after_ns, 0L ), fd_long_min( before_ns, LONG_MAX-1L ) );
}

int
fd_gui_shred_event_iter_next( fd_gui_shred_event_iter_t * iter ) {
  while( iter->_batch || iter->_hist_active || iter->_builder_pending ) {
    if( iter->_batch && iter->_batch_idx<iter->_batch->event_cnt ) {
      batch_next( iter );
      long ts = iter->_event_time ? iter->event.event_time_ns : iter->event.insert_time_ns;
      if( ts>=iter->_after_ns && (iter->_event_time ? ts<iter->_before_ns : ts<=iter->_before_ns) ) return 1;
      continue;
    }
    iter->_batch = NULL;
    iter->_batch_idx = 0UL;
    iter->_data_off  = 0UL;
    if( iter->_hist_active && fd_gui_hist_range_next( &iter->_hist_iter ) ) {
      iter->_batch = iter->_hist_iter.rec;
      continue;
    }
    if( iter->_hist_active ) fd_gui_hist_range_end( &iter->_hist_iter );
    iter->_hist_active = 0;
    if( iter->_builder_pending ) {
      iter->_builder_pending = 0;
      iter->_batch = &iter->_gui->shreds.builder.batch;
    }
  }

  /* Only fd_gui_fec_event_iter_begin activates this alternate backend. */
  while( fd_gui_store_kv_scan_next( &iter->_fec_iter ) ) {
    fd_gui_fec_event_t const * src = iter->_fec_iter.rec;
    if( src->event_time_ns<iter->_after_ns || src->event_time_ns>iter->_before_ns ) continue;
    iter->event = (fd_gui_shred_event_t){
      .insert_time_ns = src->insert_time_ns,
      .event_time_ns  = src->event_time_ns,
      .slot           = src->key.slot,
      .idx            = src->key.idx,
      .event          = src->key.event
    };
    return 1;
  }
  return 0;
}

void
fd_gui_shred_event_iter_end( fd_gui_shred_event_iter_t * iter ) {
  if( iter->_hist_active ) fd_gui_hist_range_end( &iter->_hist_iter );
  iter->_hist_active = 0;
  iter->_builder_pending = 0;
  iter->_batch = NULL;
  iter->_fec_iter.db = NULL;
}

static void
batch_flush( fd_gui_t * gui ) {
  fd_gui_shred_batch_t * batch = &gui->shreds.builder.batch;
  if( !batch->event_cnt ) return;
  if( FD_UNLIKELY( fd_gui_hist_ts_append( gui, FD_GUI_HIST_SHRED_EVENTS, batch ) ) ) {
    gui->shreds.dropped_event_cnt += batch->event_cnt;
  }
  batch->event_cnt = 0U;
  batch->data_sz   = 0U;
}

static int
fd_gui_event_slot_closed( fd_gui_t * gui,
                          ulong      slot );

void
fd_gui_shred_event_append( fd_gui_t * gui,
                           ulong      slot,
                           ulong      idx,
                           uchar      event,
                           long       timestamp,
                           long       now ) {
  fd_gui_shred_builder_t * builder = &gui->shreds.builder;
  int marker = event==FD_GUI_SLOT_SHRED_SHRED_SLOT_COMPLETE;
  if( FD_UNLIKELY( !gui->db || !gui->hist || slot>UINT_MAX || idx>USHORT_MAX ||
                  (marker ? idx!=USHORT_MAX : idx==USHORT_MAX) ||
                  (event>FD_GUI_SLOT_SHRED_SHRED_SLOT_COMPLETE && event!=FD_GUI_SLOT_SHRED_SHRED_PUBLISHED) ||
                  (!marker && (timestamp<0L || timestamp==LONG_MAX || fd_gui_event_slot_closed( gui, slot ))) ||
                  now<0L || now==LONG_MAX || now<builder->prev.insert_time_ns ) ) {
    gui->shreds.dropped_event_cnt++;
    return;
  }
  if( (marker && timestamp>=0L && timestamp!=LONG_MAX) ||
      event==FD_GUI_SLOT_SHRED_SHRED_RECEIVED_TURBINE || event==FD_GUI_SLOT_SHRED_SHRED_RECEIVED_REPAIR ||
      event==FD_GUI_SLOT_SHRED_SHRED_PUBLISHED ) {
    /* Retain arrival/completion independently of detailed event and fork
       eviction.  Producer timestamps need not arrive in timestamp order. */
    fd_gui_epoch_t * epoch = fd_gui_get_epoch_by_slot( gui, slot );
    if( epoch && slot>=epoch->start_slot && slot-epoch->start_slot<epoch->slot_cnt && slot-epoch->start_slot<MAX_SLOTS_PER_EPOCH ) {
      ulong idx = slot-epoch->start_slot;
      uchar state = epoch->timeline_slot_state[ idx ];
      if( marker ) {
        /* A landed slot uses its classified fork's completion.  Skipped
           slots use the earliest recorded completion across replays,
           including completions received after skip classification. */
        if( !(state & FD_GUI_TIMELINE_SLOT_STATE_VALID) || (state & FD_GUI_TIMELINE_SLOT_STATE_SKIPPED) ) {
          epoch->timeline_slot_end_ns[ idx ] = (state & FD_GUI_TIMELINE_SLOT_STATE_COMPLETED)
            ? fd_long_min( epoch->timeline_slot_end_ns[ idx ], timestamp ) : timestamp;
          epoch->timeline_slot_start_ns[ idx ] = (state & FD_GUI_TIMELINE_SLOT_STATE_STARTED)
            ? epoch->timeline_slot_first_shred_ns[ idx ] : LONG_MAX;
          epoch->timeline_slot_state[ idx ] = (uchar)(state | FD_GUI_TIMELINE_SLOT_STATE_COMPLETED);
        }
      } else if( !(state & FD_GUI_TIMELINE_SLOT_STATE_VALID) ) {
        epoch->timeline_slot_first_shred_ns[ idx ] = (state & FD_GUI_TIMELINE_SLOT_STATE_STARTED)
          ? fd_long_min( epoch->timeline_slot_first_shred_ns[ idx ], timestamp ) : timestamp;
        epoch->timeline_slot_state[ idx ] = (uchar)(state | FD_GUI_TIMELINE_SLOT_STATE_STARTED);
      }
    }
  }
  fd_gui_shred_batch_t * batch = &builder->batch;
  long window_ns = (long)shred_window( now )*FD_GUI_HIST_RES_1S_NS;
  if( batch->event_cnt && batch->insert_time_ns!=window_ns ) batch_flush( gui );
  batch->insert_time_ns = window_ns;
  fd_gui_shred_event_t rec = { .insert_time_ns=now, .event_time_ns=timestamp, .slot=(uint)slot, .idx=(ushort)idx, .event=event };
  if( FD_UNLIKELY( !batch_append( builder, &rec ) ) ) {
    batch_flush( gui );
    FD_TEST( batch_append( builder, &rec ) );
  }
}

int
fd_gui_shred_flush( fd_gui_t * gui,
                    long       now ) {
  if( FD_UNLIKELY( !gui->db || !gui->hist ) ) return 0;
  fd_gui_shred_batch_t const * batch = &gui->shreds.builder.batch;
  if( !batch->event_cnt || shred_window( batch->insert_time_ns )>=shred_window( now ) ) return 0;
  batch_flush( gui );
  return 1;
}

int
fd_gui_event_slot_permanently_closed( fd_gui_t const * gui,
                                      ulong            slot ) {
  if( slot<gui->shreds.closed_before_slot ) return 1;
  ulong lo = 0UL;
  ulong hi = gui->shreds.closed_slot_cnt;
  while( lo<hi ) {
    ulong mid = lo+(hi-lo)/2UL;
    if( gui->shreds.closed_slots[ mid ]<slot ) lo = mid + 1UL;
    else hi = mid;
  }
  return lo<gui->shreds.closed_slot_cnt && gui->shreds.closed_slots[ lo ]==slot;
}

static int
fd_gui_event_slot_closed( fd_gui_t * gui,
                          ulong      slot ) {
  if( gui->shreds.closed_full || fd_gui_event_slot_permanently_closed( gui, slot ) ) return 1;
  fd_gui_slot_t const * meta = fd_gui_slot_get_any( gui, slot );
  return meta && meta->completed_time!=LONG_MAX;
}

static void
fd_gui_event_slot_close( fd_gui_t * gui,
                         ulong      slot ) {
  if( gui->shreds.closed_full ) {
    gui->shreds.closed_overflow_max = fd_ulong_max( gui->shreds.closed_overflow_max, slot );
    return;
  }
  if( slot<gui->shreds.closed_before_slot ) return;
  ulong lo = 0UL;
  ulong hi = gui->shreds.closed_slot_cnt;
  while( lo<hi ) {
    ulong mid = lo+(hi-lo)/2UL;
    if( gui->shreds.closed_slots[ mid ]<slot ) lo = mid + 1UL;
    else hi = mid;
  }
  if( lo<gui->shreds.closed_slot_cnt && gui->shreds.closed_slots[ lo ]==slot ) return;
  if( gui->shreds.closed_slot_cnt==FD_GUI_CLOSED_SLOT_MAX ) {
    gui->shreds.closed_full         = 1;
    gui->shreds.closed_overflow_max = fd_ulong_max( gui->shreds.closed_overflow_max, slot );
    return;
  }
  memmove( &gui->shreds.closed_slots[ lo+1UL ], &gui->shreds.closed_slots[ lo ],
           (gui->shreds.closed_slot_cnt-lo)*sizeof(ulong) );
  gui->shreds.closed_slots[ lo ] = slot;
  gui->shreds.closed_slot_cnt++;
}

void
fd_gui_fec_event_iter_begin( fd_gui_t *                  gui,
                             fd_gui_shred_event_iter_t * iter,
                             long                        after_ns,
                             long                        before_ns ) {
  memset( iter, 0, sizeof(*iter) );
  iter->_after_ns  = after_ns;
  iter->_before_ns = before_ns;
  if( gui->db && gui->hist && after_ns<=before_ns ) fd_gui_store_kv_scan_begin( gui->db, &iter->_fec_iter, FD_GUI_HIST_FEC_EVENTS );
}

void
fd_gui_fec_event_append( fd_gui_t * gui,
                         ulong      slot,
                         ulong      idx,
                         uchar      event,
                         long       timestamp,
                         long       now ) {
  int marker = event==FD_GUI_SLOT_SHRED_SHRED_SLOT_COMPLETE;
  if( FD_UNLIKELY( !gui->db || !gui->hist || slot>UINT_MAX || idx>USHORT_MAX ||
                  (marker ? idx!=USHORT_MAX : idx==USHORT_MAX) || timestamp<0L || timestamp==LONG_MAX ||
                  now<0L || now==LONG_MAX ||
                  (event>FD_GUI_SLOT_SHRED_SHRED_SLOT_COMPLETE && event!=FD_GUI_SLOT_SHRED_SHRED_PUBLISHED) ||
                  (!marker && fd_gui_event_slot_closed( gui, slot )) ||
                  (marker && gui->shreds.fec_marker_sequence==ULONG_MAX) ) ) {
    gui->shreds.dropped_fec_event_cnt++;
    return;
  }
  fd_gui_fec_event_key_t key = {
    .slot            = (uint)slot,
    .idx             = (ushort)idx,
    .event           = event,
    .marker_sequence = marker ? ++gui->shreds.fec_marker_sequence : 0UL
  };
  fd_gui_fec_event_t * dst = fd_gui_hist_kv_get( gui, FD_GUI_HIST_FEC_EVENTS, &key );
  if( dst ) {
    dst->event_time_ns = fd_long_min( dst->event_time_ns, timestamp );
    return;
  }
  dst = fd_gui_hist_kv_get_or_create( gui, FD_GUI_HIST_FEC_EVENTS, &key );
  if( FD_UNLIKELY( !dst ) ) {
    gui->shreds.dropped_fec_event_cnt++;
    return;
  }
  now = fd_long_max( now, gui->shreds.fec_insert_time_ns[ 0 ] );
  *dst = (fd_gui_fec_event_t){ .key=key, .insert_time_ns=now, .event_time_ns=timestamp };
  gui->shreds.fec_insert_time_ns[ 0 ] = now;
}

void
fd_gui_fec_completion_iter_begin( fd_gui_t *                     gui,
                                  fd_gui_fec_completion_iter_t * it,
                                  long                           after_ns,
                                  long                           before_ns ) {
  memset( it, 0, sizeof(*it) );
  it->after_ns  = after_ns;
  it->before_ns = before_ns;
  if( gui->db && gui->hist && after_ns<=before_ns ) fd_gui_store_kv_scan_begin( gui->db, &it->iter, FD_GUI_HIST_FEC_COMPLETIONS );
}

int
fd_gui_fec_completion_iter_next( fd_gui_fec_completion_iter_t * it ) {
  while( fd_gui_store_kv_scan_next( &it->iter ) ) {
    fd_gui_fec_completion_record_t const * src = it->iter.rec;
    if( src->key.timestamp<it->after_ns || src->key.timestamp>it->before_ns ) continue;
    uint counts = src->key.counts;
    it->event = (fd_gui_fec_completion_t){
      .timestamp     = src->key.timestamp,
      .turbine       = (uchar)(counts & 127U),
      .repair        = (uchar)((counts>>7) & 127U),
      .reconstructed = (uchar)((counts>>14) & 127U),
      .leader        = (uchar)(counts>>21)
    };
    it->slot = src->key.slot;
    return 1;
  }
  return 0;
}

void
fd_gui_fec_completion_iter_end( fd_gui_fec_completion_iter_t * it ) {
  it->iter.db = NULL;
}

int
fd_gui_fec_completion_append( fd_gui_t * gui,
                              ulong      slot,
                              long       timestamp,
                              ulong      turbine,
                              ulong      repair,
                              ulong      reconstructed,
                              int        leader,
                              long       now ) {
  if( FD_UNLIKELY( !gui->db || !gui->hist || slot>UINT_MAX || timestamp<0L || timestamp==LONG_MAX || now<0L || now==LONG_MAX ||
                  turbine>FD_GUI_FEC_PUBLISHED_SHRED_CNT || repair>FD_GUI_FEC_PUBLISHED_SHRED_CNT ||
                  reconstructed>FD_GUI_FEC_PUBLISHED_SHRED_CNT || fd_gui_event_slot_closed( gui, slot ) ) ) {
    gui->shreds.dropped_completion_cnt++;
    return 0;
  }
  fd_gui_fec_completion_key_t key = {
    .timestamp = timestamp,
    .slot      = (uint)slot,
    .counts    = (uint)turbine | ((uint)repair<<7) | ((uint)reconstructed<<14) | ((uint)!!leader<<21)
  };
  if( fd_gui_hist_kv_get( gui, FD_GUI_HIST_FEC_COMPLETIONS, &key ) ) return 0;
  fd_gui_fec_completion_record_t * dst = fd_gui_hist_kv_get_or_create( gui, FD_GUI_HIST_FEC_COMPLETIONS, &key );
  if( FD_UNLIKELY( !dst ) ) {
    gui->shreds.dropped_completion_cnt++;
    return 0;
  }
  now = fd_long_max( now, gui->shreds.fec_insert_time_ns[ 1 ] );
  *dst = (fd_gui_fec_completion_record_t){ .key=key, .insert_time_ns=now };
  gui->shreds.fec_insert_time_ns[ 1 ] = now;
  return 1;
}

void
fd_gui_shred_event_slot_complete( fd_gui_t * gui,
                                  ulong      slot,
                                  long       timestamp,
                                  long       now ) {
  if( FD_UNLIKELY( slot>UINT_MAX ) ) return;
  fd_gui_event_slot_close( gui, slot );
  fd_gui_shred_event_append( gui, slot, USHORT_MAX, FD_GUI_SLOT_SHRED_SHRED_SLOT_COMPLETE, timestamp, now );
  fd_gui_fec_event_append( gui, slot, USHORT_MAX, FD_GUI_SLOT_SHRED_SHRED_SLOT_COMPLETE, timestamp, now );
}

void
fd_gui_event_slots_close_before( fd_gui_t * gui,
                                 ulong      cutoff ) {
  if( FD_UNLIKELY( cutoff==ULONG_MAX || cutoff<=gui->shreds.closed_before_slot ) ) return;
  gui->shreds.closed_before_slot = cutoff;
  ulong n = 0UL;
  for( ulong i=0UL; i<gui->shreds.closed_slot_cnt; i++ ) {
    if( gui->shreds.closed_slots[ i ]>=cutoff ) gui->shreds.closed_slots[ n++ ] = gui->shreds.closed_slots[ i ];
  }
  gui->shreds.closed_slot_cnt = n;
  if( gui->shreds.closed_full && n<FD_GUI_CLOSED_SLOT_MAX && cutoff>gui->shreds.closed_overflow_max ) {
    gui->shreds.closed_full = 0;
  }
}

int
fd_gui_event_bounds( fd_gui_t * gui,
                     int        dbi,
                     long *     lo,
                     long *     hi ) {
  if( dbi==FD_GUI_HIST_FEC_EVENTS || dbi==FD_GUI_HIST_FEC_COMPLETIONS ) {
    *lo = LONG_MAX;
    *hi = LONG_MIN;
    fd_gui_store_kv_scan_t it;
    fd_gui_store_kv_scan_begin( gui->db, &it, (ulong)dbi );
    while( fd_gui_store_kv_scan_next( &it ) ) {
      long ts = dbi==FD_GUI_HIST_FEC_EVENTS ? ((fd_gui_fec_event_t const *)it.rec)->event_time_ns
                                           : ((fd_gui_fec_completion_record_t const *)it.rec)->key.timestamp;
      *lo = fd_long_min( *lo, ts );
      *hi = fd_long_max( *hi, ts+1L );
    }
    return *lo!=LONG_MAX;
  }
  long first;
  long last;
  int have = gui->db && fd_gui_store_ts_live_timestamp_bounds( gui->db, (ulong)dbi, &first, &last );
  if( dbi==FD_GUI_HIST_SHRED_EVENTS && gui->shreds.builder.batch.event_cnt ) {
    long active = gui->shreds.builder.batch.insert_time_ns;
    first = have ? fd_long_min( first, active ) : active;
    last  = have ? fd_long_max( last, active ) : active;
    have  = 1;
  }
  *lo = have ? fd_long_max( 0L, fd_long_sat_sub( first, FD_GUI_HIST_RES_1S_NS ) ) : LONG_MAX;
  *hi = have ? fd_long_min( LONG_MAX-1L, fd_long_sat_add( last, FD_GUI_HIST_RES_1S_NS+1L ) ) : LONG_MIN;
  return have;
}

int
fd_gui_shred_window_is_empty( fd_gui_t * gui,
                              long       after_ns,
                              long       before_ns ) {
  fd_gui_shred_event_iter_t it[ 1 ];
  fd_gui_shred_event_iter_begin( gui, it, after_ns, before_ns );
  int empty = !fd_gui_shred_event_iter_next( it );
  fd_gui_shred_event_iter_end( it );
  return empty;
}
