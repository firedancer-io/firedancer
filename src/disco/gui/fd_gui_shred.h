#ifndef HEADER_fd_src_disco_gui_fd_gui_shred_h
#define HEADER_fd_src_disco_gui_fd_gui_shred_h

#include "fd_gui_hist.h"
#include "../shred/fd_fec_set.h"

struct fd_gui;
typedef struct fd_gui fd_gui_t;

#define FD_GUI_SHRED_BATCH_SZ       (4096UL)
#define FD_GUI_SHRED_EVENT_TS_MAX   (0xFFFFFFUL)

/* FEC staging holds at most FD_GUI_FEC_RECORD_MAX records, and only
   admits slots below a high watermark FD_GUI_FEC_SLOT_WMARK_CNT slots
   past the closed slot watermark. */
#define FD_GUI_FEC_RECORD_MAX     (1UL<<20)
#define FD_GUI_FEC_SLOT_WMARK_CNT (1024UL)

/* The FEC archive is an ordinary time-series ring ordered by admission
   time, while queries select by event time.  Events skewed further than
   LAG_MAX are excluded from query responses and counted in
   clamped_fec_event_cnt. */
#define FD_GUI_FEC_EVENT_LAG_MAX_NS (10L*1000L*1000L*1000L)
#define FD_GUI_FEC_BATCH_SPAN_NS    (1000L*1000L*1000L)

#define FD_GUI_SLOT_SHRED_REPAIR_REQUEST         (0UL)
#define FD_GUI_SLOT_SHRED_SHRED_RECEIVED_TURBINE (1UL)
#define FD_GUI_SLOT_SHRED_SHRED_RECEIVED_REPAIR  (2UL)
#define FD_GUI_SLOT_SHRED_SHRED_REPLAY_EXEC_DONE (3UL)
#define FD_GUI_SLOT_SHRED_SHRED_SLOT_COMPLETE    (4UL)
#define FD_GUI_SLOT_SHRED_SHRED_PUBLISHED        (6UL)

struct __attribute__((packed)) fd_gui_shred_event {
  long   insert_time_ns;
  long   event_time_ns;
  uint   slot;
  ushort idx;
  uchar  event;
};
typedef struct fd_gui_shred_event fd_gui_shred_event_t;

struct fd_gui_shred_scratch {
  long   event_time_ns;
  uint   slot;
  ushort idx;
  uchar  event;
};
typedef struct fd_gui_shred_scratch fd_gui_shred_scratch_t;

#define FD_GUI_SHRED_SCRATCH_MAX (262144UL)

/* Each block belongs to one insertion-time second.  The index timestamp
   is that second's start; individual insertion times remain in data.
   Entries are a one-byte tag followed by either a literal event or a
   delta from the preceding event (same slot).  Deltas store the event
   type and delta signs in the tag, then four insertion-time bytes, three
   event-time bytes, and one index byte.  Slot changes and larger deltas
   use literals. */
struct fd_gui_shred_batch {
  long   insert_time_ns;
  uint   event_cnt;
  uint   data_sz;
  uchar  data[ FD_GUI_SHRED_BATCH_SZ-16UL ];
};
typedef struct fd_gui_shred_batch fd_gui_shred_batch_t;

/* Encode the open insertion second directly.  Full batches and closed
   seconds move to the history ring.  History retention only applies to
   sealed batches in the store; the active batch remains queryable. */
struct fd_gui_shred_builder {
  fd_gui_shred_batch_t batch;
  fd_gui_shred_event_t prev;
};
typedef struct fd_gui_shred_builder fd_gui_shred_builder_t;

struct fd_gui_fec_event_key {
  uint   slot;
  ushort idx;
  uchar  event;
  uchar  reserved;
  ulong  marker_sequence;
};
typedef struct fd_gui_fec_event_key fd_gui_fec_event_key_t;

struct fd_gui_fec_event {
  fd_gui_fec_event_key_t key;
  long                   insert_time_ns;
  long                   event_time_ns;
};
typedef struct fd_gui_fec_event fd_gui_fec_event_t;

struct fd_gui_fec_event_batch {
  long                 insert_time_ns;
  long                 min_ns;
  long                 max_ns;
  fd_gui_shred_batch_t batch;
};
typedef struct fd_gui_fec_event_batch fd_gui_fec_event_batch_t;

FD_STATIC_ASSERT( sizeof(fd_gui_shred_batch_t)==FD_GUI_SHRED_BATCH_SZ, shred_batch_size );
FD_STATIC_ASSERT( sizeof(fd_gui_fec_event_key_t)==16UL, fec_event_key_size );
FD_STATIC_ASSERT( sizeof(fd_gui_fec_event_t)<=32UL, fec_event_size );
FD_STATIC_ASSERT( FD_GUI_STORE_REGION_SZ/32UL>=FD_GUI_FEC_RECORD_MAX, fec_region_capacity );
/* The batch codec stores admission deltas in 32 bits. */
FD_STATIC_ASSERT( FD_GUI_FEC_BATCH_SPAN_NS<=(long)UINT_MAX, fec_batch_span );

struct fd_gui_shred_event_iter {
  fd_gui_shred_event_t event;
  fd_gui_t * _gui;
  long _after_ns;
  long _before_ns;
  fd_gui_hist_iter_t _hist_iter;
  fd_gui_shred_batch_t const * _batch;
  ulong _batch_idx;
  ulong _data_off;
  int   _event_time;
  int   _fec_archive;
  int   _builder_pending;
  int   _hist_active;
  long  _fec_insert_hi;
  fd_gui_store_kv_scan_t _fec_iter;
};
typedef struct fd_gui_shred_event_iter fd_gui_shred_event_iter_t;

FD_PROTOTYPES_BEGIN

/* Iterate by original insertion time, inclusive at both ends.  Event
   timestamps are preserved verbatim and need not be ordered. */
fd_gui_shred_event_iter_t *
fd_gui_shred_event_iter_begin( fd_gui_t *                  gui,
                               fd_gui_shred_event_iter_t * iter,
                               long                        after_ns,
                               long                        before_ns );

/* fd_gui_shred_event_hist_iter_begin selects event time in
   [after_ns,before_ns).  Event times are only approximately ordered
   with insertion, so the scan is widened by one second on each side. */
fd_gui_shred_event_iter_t *
fd_gui_shred_event_hist_iter_begin( fd_gui_t *                  gui,
                                    fd_gui_shred_event_iter_t * iter,
                                    long                        after_ns,
                                    long                        before_ns );

int
fd_gui_shred_event_iter_next( fd_gui_shred_event_iter_t * iter );

void
fd_gui_shred_event_iter_end( fd_gui_shred_event_iter_t * iter );

/* Append immediately.  now is the GUI insertion time and must be
   nondecreasing across all channels; timestamp is the source event time. */
void
fd_gui_shred_event_append( fd_gui_t * gui,
                           ulong      slot,
                           ulong      idx,
                           uchar      event,
                           long       timestamp,
                           long       now );

/* Seal the active batch once its insertion second has closed.
   Returns 1 when a batch was flushed. */
int
fd_gui_shred_flush( fd_gui_t * gui,
                    long       now );

/* fd_gui_shred_event_slot_complete records a slot complete marker at
   timestamp in both the shred and FEC event histories.  now is the
   insertion time. */

void
fd_gui_shred_event_slot_complete( fd_gui_t * gui,
                                  ulong      slot,
                                  long       timestamp,
                                  long       now );

/* fd_gui_fec_event_append records a FEC event, keeping the earliest
   timestamp for each (slot, idx, event) identity.  idx is the FEC set
   index, or USHORT_MAX for slot complete markers.  now is the GUI
   insertion time. */

void
fd_gui_fec_event_append( fd_gui_t * gui,
                         ulong      slot,
                         ulong      idx,
                         uchar      event,
                         long       timestamp,
                         long       now );

/* fd_gui_fec_archive moves at most budget staged FEC events, in
   admission order, to the archive.  A staged event is only removed once
   its archive append succeeds. Returns the number of events archived. */

ulong
fd_gui_fec_archive( fd_gui_t * gui,
                    ulong      budget );

/* fd_gui_fec_event_iter_begin selects archived and staged FEC events
   by event time in [after_ns,before_ns). */

void
fd_gui_fec_event_iter_begin( fd_gui_t *                  gui,
                             fd_gui_shred_event_iter_t * iter,
                             long                        after_ns,
                             long                        before_ns );

/* fd_gui_event_closed_slot_wmark returns the closed slot watermark.
   Slots below it are permanently closed. */

ulong
fd_gui_event_closed_slot_wmark( fd_gui_t const * gui );

/* fd_gui_event_closed_slot_wmark_advance permanently closes slots
   below wmark (one slot behind the rooted slot). */

void
fd_gui_event_closed_slot_wmark_advance( fd_gui_t * gui,
                                        ulong      wmark );

int
fd_gui_shred_window_is_empty( fd_gui_t * gui,
                              long       after_ns,
                              long       before_ns );

/* fd_gui_event_bounds returns whether dbi has lookup bounds, writing
   half-open [lo,hi) bounds that include the active shred batch. */

int
fd_gui_event_bounds( fd_gui_t * gui,
                     int        dbi,
                     long *     lo,
                     long *     hi );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_gui_fd_gui_shred_h */
