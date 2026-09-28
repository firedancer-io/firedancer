#ifndef HEADER_fd_src_disco_gui_fd_gui_shred_h
#define HEADER_fd_src_disco_gui_fd_gui_shred_h

#include "fd_gui_hist.h"
#include "../shred/fd_fec_set.h"

struct fd_gui;
typedef struct fd_gui fd_gui_t;

#define FD_GUI_SHRED_BATCH_SZ       (4096UL)
#define FD_GUI_SHRED_EVENT_TS_MAX   (0xFFFFFFUL)
#define FD_GUI_FEC_RECORD_MAX          (1UL<<20)
/* FEC staging only admits slots less than FD_GUI_FEC_SLOT_HORIZON past
   the closing cutoff.  At a few hundred staged records per slot, the
   horizon fits well within FD_GUI_FEC_RECORD_MAX. */
#define FD_GUI_FEC_SLOT_HORIZON        (1024UL)
#define FD_GUI_FEC_PUBLISHED_SHRED_CNT (2UL*FD_FEC_SHRED_CNT)

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
  long                  insert_time_ns;
  long                  event_time_ns;
};
typedef struct fd_gui_fec_event fd_gui_fec_event_t;

struct fd_gui_fec_completion_key {
  long timestamp;
  uint slot;
  uint counts;
};
typedef struct fd_gui_fec_completion_key fd_gui_fec_completion_key_t;

struct fd_gui_fec_completion_record {
  fd_gui_fec_completion_key_t key;
  long                        insert_time_ns;
};
typedef struct fd_gui_fec_completion_record fd_gui_fec_completion_record_t;

FD_STATIC_ASSERT( sizeof(fd_gui_shred_batch_t)==FD_GUI_SHRED_BATCH_SZ, shred_batch_size );
FD_STATIC_ASSERT( sizeof(fd_gui_fec_event_key_t)==16UL, fec_event_key_size );
FD_STATIC_ASSERT( sizeof(fd_gui_fec_completion_key_t)==16UL, fec_completion_key_size );
FD_STATIC_ASSERT( sizeof(fd_gui_fec_event_t)<=32UL, fec_event_size );
FD_STATIC_ASSERT( sizeof(fd_gui_fec_completion_record_t)<=32UL, fec_completion_size );
FD_STATIC_ASSERT( FD_GUI_STORE_REGION_SZ/32UL>=FD_GUI_FEC_RECORD_MAX, fec_region_capacity );

/* Archives are ordered by admission time, not event time.  Per-batch
   bounds permit event-time filtering even for arbitrarily late updates. */
struct fd_gui_fec_event_batch {
  long insert_time_ns;
  long min_ns;
  long max_ns;
  fd_gui_shred_batch_t batch;
};
typedef struct fd_gui_fec_event_batch fd_gui_fec_event_batch_t;

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
  fd_gui_store_kv_scan_t _fec_iter;
};
typedef struct fd_gui_shred_event_iter fd_gui_shred_event_iter_t;

FD_PROTOTYPES_BEGIN

/* Move at most budget closed-prefix FEC events to immutable TS batches
   and drop at most budget closed-prefix completions.  Never remove an
   event record before its archive append succeeds. */
ulong
fd_gui_fec_archive( fd_gui_t * gui, ulong budget );

/* Admission pressure must not drain unrelated channels. */
ulong
fd_gui_fec_archive_channel( fd_gui_t * gui, int dbi, ulong budget );

/* fd_gui_fec_event_iter_begin selects persisted FEC events by event time
   in [after_ns,before_ns].  Use fd_gui_shred_event_iter_next/end to read
   and finish this alternate backend of the shared event iterator. */

void
fd_gui_fec_event_iter_begin( fd_gui_t *                  gui,
                             fd_gui_shred_event_iter_t * iter,
                             long                        after_ns,
                             long                        before_ns );

/* fd_gui_fec_event_append retains the earliest timestamp for each FEC
   event identity.  Slot-complete markers remain distinct admissions. */

void
fd_gui_fec_event_append( fd_gui_t * gui,
                         ulong      slot,
                         ulong      idx,
                         uchar      event,
                         long       timestamp,
                         long       now );

/* fd_gui_fec_completion_append returns 1 for a newly admitted completion,
   or 0 for a duplicate or rejected record. */

int
fd_gui_fec_completion_append( fd_gui_t * gui,
                              ulong      slot,
                              long       timestamp,
                              ulong      turbine,
                              ulong      repair,
                              ulong      reconstructed,
                              int        leader,
                              long       now );

/* fd_gui_event_slot_permanently_closed tests whether slot is below the
   closing cutoff, so its staged FEC records can be reclaimed without
   allowing ordinary events to be readmitted. */

int
fd_gui_event_slot_permanently_closed( fd_gui_t const * gui,
                                      ulong            slot );

/* fd_gui_event_slots_close_before permanently closes slots below
   cutoff, the optimistically confirmed slot (or the root on Alpenglow).
   Ordinary events for closed slots are rejected and their staged FEC
   records become eligible for archival. */

void
fd_gui_event_slots_close_before( fd_gui_t * gui,
                                 ulong      cutoff );

/* fd_gui_event_bounds returns whether dbi has lookup bounds, writing
   half-open [lo,hi) bounds that include the active shred batch. */

int
fd_gui_event_bounds( fd_gui_t * gui,
                     int        dbi,
                     long *     lo,
                     long *     hi );

/* fd_gui_shred_event_hist_iter_begin selects event time in
   [after_ns,before_ns), scanning history with a +/-1s insertion-time
   margin and the active batch.  Use fd_gui_shred_event_iter_next/end. */

fd_gui_shred_event_iter_t *
fd_gui_shred_event_hist_iter_begin( fd_gui_t *                  gui,
                                    fd_gui_shred_event_iter_t * iter,
                                    long                        after_ns,
                                    long                        before_ns );

/* fd_gui_shred_event_iter_{begin|next|end} iterate over shred event
   history, then the active batch, by insertion time in [after_ns,before_ns]. */

fd_gui_shred_event_iter_t *
fd_gui_shred_event_iter_begin( fd_gui_t *                  gui,
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

/* fd_gui_shred_event_slot_complete closes the slot to ordinary events
   and adds a completion event at timestamp.  now is the history
   insertion time; both times are in nanoseconds. */

void
fd_gui_shred_event_slot_complete( fd_gui_t * gui,
                                  ulong      slot,
                                  long       timestamp,
                                  long       now );

/* fd_gui_shred_window_is_empty returns 1 if there are no recorded shred
   events in [after_ns,before_ns], 0 otherwise. */

int
fd_gui_shred_window_is_empty( fd_gui_t * gui,
                              long       after_ns,
                              long       before_ns );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_gui_fd_gui_shred_h */
