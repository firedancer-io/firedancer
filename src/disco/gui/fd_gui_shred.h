#ifndef HEADER_fd_src_disco_gui_fd_gui_shred_h
#define HEADER_fd_src_disco_gui_fd_gui_shred_h

#include "fd_gui_hist.h"

struct fd_gui;
typedef struct fd_gui fd_gui_t;

#define FD_GUI_SHRED_BATCH_SZ       (4096UL)
#define FD_GUI_SHRED_EVENT_TS_MAX   (0xFFFFFFUL)

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

struct fd_gui_shred_event_iter {
  fd_gui_shred_event_t event;
  fd_gui_t * _gui;
  long _after_ns;
  long _before_ns;
  fd_gui_hist_iter_t _hist_iter;
  fd_gui_shred_batch_t const * _batch;
  ulong _batch_idx;
  ulong _data_off;
  int _phase; /* 0 shred batches, 1 active events, 2 done */
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

int
fd_gui_shred_window_is_empty( fd_gui_t * gui,
                              long       after_ns,
                              long       before_ns );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_gui_fd_gui_shred_h */
