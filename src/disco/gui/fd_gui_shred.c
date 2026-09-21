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

fd_gui_shred_event_iter_t *
fd_gui_shred_event_iter_begin( fd_gui_t *                  gui,
                               fd_gui_shred_event_iter_t * iter,
                               long                        after_ns,
                               long                        before_ns ) {
  fd_memset( iter, 0, sizeof(*iter) );
  iter->_gui          = gui;
  iter->_after_ns     = fd_long_max( after_ns, 0L );
  iter->_before_ns    = fd_long_min( before_ns, LONG_MAX-1L );
  if( FD_UNLIKELY( !gui->db || !gui->hist || iter->_after_ns>iter->_before_ns ) ) {
    iter->_phase = 2;
    return iter;
  }
  fd_gui_hist_range_begin( gui, &iter->_hist_iter, FD_GUI_HIST_SHRED_EVENTS,
                          iter->_after_ns, iter->_before_ns, NULL, NULL );
  return iter;
}

int
fd_gui_shred_event_iter_next( fd_gui_shred_event_iter_t * iter ) {
  while( iter->_phase<2 ) {
    if( iter->_batch && iter->_batch_idx<iter->_batch->event_cnt ) {
      batch_next( iter );
      if( iter->event.insert_time_ns>=iter->_after_ns && iter->event.insert_time_ns<=iter->_before_ns ) return 1;
      continue;
    }
    iter->_batch = NULL;
    iter->_batch_idx = 0UL;
    iter->_data_off  = 0UL;
    if( iter->_phase==1 ) {
      iter->_phase = 2;
      break;
    }
    if( fd_gui_hist_range_next( &iter->_hist_iter ) ) {
      iter->_batch = iter->_hist_iter.rec;
      continue;
    }
    fd_gui_hist_range_end( &iter->_hist_iter );
    fd_memset( &iter->_hist_iter, 0, sizeof(iter->_hist_iter) );
    iter->_phase = 1;
    iter->_batch = &iter->_gui->shreds.builder.batch;
  }
  return 0;
}

void
fd_gui_shred_event_iter_end( fd_gui_shred_event_iter_t * iter ) {
  fd_gui_hist_range_end( &iter->_hist_iter );
  iter->_phase = 2;
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
