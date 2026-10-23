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

static ulong
shred_window( long ns ) {
  return ns<=0L ? 0UL : (ulong)(ns/FD_GUI_HIST_RES_1S_NS);
}

static inline fd_gui_shred_event_t
fec_shred_event( fd_gui_fec_event_t const * src ) {
  return (fd_gui_shred_event_t){ .insert_time_ns=src->insert_time_ns, .event_time_ns=src->event_time_ns,
                                 .slot=src->key.slot, .idx=src->key.idx, .event=src->key.event };
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

ulong
fd_gui_fec_archive( fd_gui_t * gui,
                    ulong      budget ) {
  if( !gui->db || !gui->hist ) return 0UL;
  ulong total = 0UL;
  while( budget ) {
    fd_gui_store_kv_scan_t scan;
    fd_gui_store_kv_scan_begin( gui->db, &scan, FD_GUI_HIST_FEC_EVENTS );
    fd_gui_shred_builder_t builder = {0};
    fd_gui_fec_event_batch_t events = { .min_ns=LONG_MAX, .max_ns=LONG_MIN };
    ulong count = 0UL;
    while( count<budget && fd_gui_store_kv_scan_next( &scan ) ) {
      fd_gui_fec_event_t const * src = scan.rec;
      if( src->key.slot>=fd_gui_event_closed_slot_wmark( gui ) ) break;
      /* Bound the batch's admission span so event-time queries can find
         it (see FD_GUI_FEC_BATCH_SPAN_NS).  This also keeps the codec's
         32-bit admission deltas in range. */
      if( count && src->insert_time_ns-events.insert_time_ns>FD_GUI_FEC_BATCH_SPAN_NS ) break;
      fd_gui_shred_event_t event = fec_shred_event( src );
      if( !count ) events.insert_time_ns = builder.batch.insert_time_ns = src->insert_time_ns;
      if( !batch_append( &builder, &event ) ) break;
      events.min_ns = fd_long_min( events.min_ns, src->event_time_ns );
      events.max_ns = fd_long_max( events.max_ns, src->event_time_ns );
      count++;
    }
    if( !count ) break; /* An open prefix pins all later admissions. */
    events.batch = builder.batch;
    /* Keep staging intact on archive admission failure. */
    if( fd_gui_hist_ts_append( gui, FD_GUI_HIST_FEC_EVENT_ARCHIVE, &events ) ) break;
    FD_TEST( fd_gui_store_kv_reclaim_prefix( gui->db, FD_GUI_HIST_FEC_EVENTS, count, NULL, NULL )==count );
    budget -= count;
    total  += count;
  }
  return total;
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
                  int                         fec,
                  long                        after_ns,
                  long                        before_ns ) {
  fd_memset( iter, 0, sizeof(*iter) );
  iter->_gui         = gui;
  iter->_after_ns    = after_ns;
  iter->_before_ns   = before_ns;
  iter->_event_time  = event_time;
  iter->_fec_archive = fec;

  /* Event-time shred queries widen the scan by +-1 second. The
     assumption is that event-ordering approximately equals
     insert-ordering, and in rare cases where there is more than a second
     of skew in the system we can tolerate missing data.  Stored FEC event
     times are within FD_GUI_FEC_EVENT_LAG_MAX_NS of admission and
     batches span at most FD_GUI_FEC_BATCH_SPAN_NS of admission. */
  if( FD_LIKELY( gui->db && gui->hist && after_ns<=before_ns ) ) {
    long lo_margin = fec ? FD_GUI_FEC_EVENT_LAG_MAX_NS+FD_GUI_FEC_BATCH_SPAN_NS : event_time ? FD_GUI_HIST_RES_1S_NS : 0L;
    long hi_margin = fec ? FD_GUI_FEC_EVENT_LAG_MAX_NS                          : event_time ? FD_GUI_HIST_RES_1S_NS : 0L;
    long lo_ns = fd_long_max( 0L, fd_long_sat_sub( after_ns, lo_margin ) );
    long hi_ns = fd_long_min( LONG_MAX-1L, fd_long_sat_add( before_ns, hi_margin ) );
    int  dbi   = fec ? FD_GUI_HIST_FEC_EVENT_ARCHIVE : FD_GUI_HIST_SHRED_EVENTS;
    iter->_hist_active = !fd_gui_hist_range_begin( gui, &iter->_hist_iter, dbi, lo_ns, hi_ns, NULL, NULL );
    if( fec ) fd_gui_store_kv_scan_begin( gui->db, &iter->_fec_iter, FD_GUI_HIST_FEC_EVENTS );
    else      iter->_builder_pending = 1;
  }
  return iter;
}

fd_gui_shred_event_iter_t *
fd_gui_shred_event_hist_iter_begin( fd_gui_t *                  gui,
                                    fd_gui_shred_event_iter_t * iter,
                                    long                        after_ns,
                                    long                        before_ns ) {
  return shred_iter_begin( gui, iter, 1, 0, after_ns, before_ns );
}

fd_gui_shred_event_iter_t *
fd_gui_shred_event_iter_begin( fd_gui_t *                  gui,
                               fd_gui_shred_event_iter_t * iter,
                               long                        after_ns,
                               long                        before_ns ) {
  return shred_iter_begin( gui, iter, 0, 0, fd_long_max( after_ns, 0L ), fd_long_min( before_ns, LONG_MAX-1L ) );
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
      if( iter->_fec_archive ) {
        fd_gui_fec_event_batch_t const * b = iter->_hist_iter.rec;
        if( b->max_ns<iter->_after_ns || b->min_ns>=iter->_before_ns ) continue;
        iter->_batch = &b->batch;
      } else iter->_batch = iter->_hist_iter.rec;
      continue;
    }
    if( iter->_hist_active ) fd_gui_hist_range_end( &iter->_hist_iter );
    iter->_hist_active = 0;
    if( iter->_builder_pending ) {
      iter->_builder_pending = 0;
      iter->_batch = &iter->_gui->shreds.builder.batch;
    }
  }

  /* Staged FEC events, only set up by fd_gui_fec_event_iter_begin. */
  while( fd_gui_store_kv_scan_next( &iter->_fec_iter ) ) {
    fd_gui_fec_event_t const * src = iter->_fec_iter.rec;
    if( src->event_time_ns<iter->_after_ns || src->event_time_ns>=iter->_before_ns ) continue;
    iter->event = fec_shred_event( src );
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

void
fd_gui_shred_event_append( fd_gui_t * gui,
                           ulong      slot,
                           ulong      idx,
                           uchar      event,
                           long       timestamp,
                           long       now ) {
  fd_gui_shred_builder_t * builder = &gui->shreds.builder;
  if( FD_UNLIKELY( !gui->db || !gui->hist || slot>UINT_MAX || idx>USHORT_MAX ||
                  (idx==USHORT_MAX && event!=FD_GUI_SLOT_SHRED_SHRED_SLOT_COMPLETE) ||
                  now<builder->prev.insert_time_ns ) ) {
    gui->shreds.dropped_event_cnt++;
    return;
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

ulong
fd_gui_event_closed_slot_wmark( fd_gui_t const * gui ) {
  return gui->shreds.closed_slot_wmark;
}

/* fec_slot_hi_wmark returns the FEC staging high watermark: slots at or
   above it are not staged. */

static inline ulong
fec_slot_hi_wmark( fd_gui_t const * gui ) {
  return fd_ulong_sat_add( gui->shreds.closed_slot_wmark, FD_GUI_FEC_SLOT_WMARK_CNT );
}

void
fd_gui_fec_event_iter_begin( fd_gui_t *                  gui,
                             fd_gui_shred_event_iter_t * iter,
                             long                        after_ns,
                             long                        before_ns ) {
  shred_iter_begin( gui, iter, 1, 1, after_ns, before_ns );
}

/* fec_event_skewed tests whether timestamp is more than
   FD_GUI_FEC_EVENT_LAG_MAX_NS from the admission time insert_ns.
   Skewed events are not stored, so event-time queries can find every
   stored event from its admission time. */

static int
fec_event_skewed( long insert_ns,
                  long timestamp ) {
  return timestamp<fd_long_sat_sub( insert_ns, FD_GUI_FEC_EVENT_LAG_MAX_NS ) ||
         timestamp>fd_long_sat_add( insert_ns, FD_GUI_FEC_EVENT_LAG_MAX_NS );
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
                  (!marker && slot<fd_gui_event_closed_slot_wmark( gui )) || slot>=fec_slot_hi_wmark( gui ) ||
                  (marker && gui->shreds.fec_marker_sequence==ULONG_MAX) ) ) {
    gui->shreds.dropped_fec_event_cnt++;
    return;
  }
  /* Staging admission order must be monotone in admission time, since
     it becomes the archive order. */
  now = fd_long_max( now, gui->shreds.fec_insert_time_ns );
  fd_gui_fec_event_key_t key = { .slot=(uint)slot, .idx=(ushort)idx, .event=event };
  fd_gui_fec_event_t * dst = marker ? NULL : fd_gui_hist_kv_get( gui, FD_GUI_HIST_FEC_EVENTS, &key );
  if( dst && timestamp>=dst->event_time_ns ) return;
  if( FD_UNLIKELY( fec_event_skewed( dst ? dst->insert_time_ns : now, timestamp ) ) ) {
    gui->shreds.clamped_fec_event_cnt++;
    return;
  }
  if( dst ) {
    dst->event_time_ns = timestamp;
    return;
  }
  if( marker ) key.marker_sequence = ++gui->shreds.fec_marker_sequence;
  dst = fd_gui_hist_kv_get_or_create( gui, FD_GUI_HIST_FEC_EVENTS, &key );
  if( FD_UNLIKELY( !dst ) ) {
    gui->shreds.dropped_fec_event_cnt++;
    return;
  }
  *dst = (fd_gui_fec_event_t){ .key=key, .insert_time_ns=now, .event_time_ns=timestamp };
  gui->shreds.fec_insert_time_ns = now;
}

void
fd_gui_shred_event_slot_complete( fd_gui_t * gui,
                                  ulong      slot,
                                  long       timestamp,
                                  long       now ) {
  fd_gui_shred_event_append( gui, slot, USHORT_MAX, FD_GUI_SLOT_SHRED_SHRED_SLOT_COMPLETE, timestamp, now );
  fd_gui_fec_event_append( gui, slot, USHORT_MAX, FD_GUI_SLOT_SHRED_SHRED_SLOT_COMPLETE, timestamp, now );
}

void
fd_gui_event_closed_slot_wmark_advance( fd_gui_t * gui,
                                        ulong      wmark ) {
  if( FD_UNLIKELY( wmark==ULONG_MAX || wmark<=gui->shreds.closed_slot_wmark ) ) return;
  gui->shreds.closed_slot_wmark = wmark;
}

int
fd_gui_event_bounds( fd_gui_t * gui,
                     int        dbi,
                     long *     lo,
                     long *     hi ) {
  if( dbi==FD_GUI_HIST_FEC_EVENTS ) {
    /* Bound by admission time, widened by the lag bound and batch span
       rather than scanning event times. */
    long first = LONG_MAX;
    long last  = LONG_MIN;
    long a_first, a_last;
    if( gui->db && fd_gui_store_ts_live_timestamp_bounds( gui->db, FD_GUI_HIST_FEC_EVENT_ARCHIVE, &a_first, &a_last ) ) {
      first = a_first;
      last  = fd_long_sat_add( a_last, FD_GUI_FEC_BATCH_SPAN_NS );
    }
    if( gui->db ) {
      fd_gui_store_kv_scan_t it;
      fd_gui_store_kv_scan_begin( gui->db, &it, FD_GUI_HIST_FEC_EVENTS );
      if( fd_gui_store_kv_scan_next( &it ) ) {
        first = fd_long_min( first, ((fd_gui_fec_event_t const *)it.rec)->insert_time_ns );
        last  = fd_long_max( last, gui->shreds.fec_insert_time_ns );
      }
    }
    int have = first!=LONG_MAX;
    *lo = have ? fd_long_max( 0L, fd_long_sat_sub( first, FD_GUI_FEC_EVENT_LAG_MAX_NS ) ) : LONG_MAX;
    *hi = have ? fd_long_min( LONG_MAX-1L, fd_long_sat_add( last, FD_GUI_FEC_EVENT_LAG_MAX_NS+1L ) ) : LONG_MIN;
    return have;
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

  if( have && dbi==FD_GUI_HIST_SHRED_EVENTS ) last = fd_long_sat_add( last, FD_GUI_HIST_RES_1S_NS-1L );
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
