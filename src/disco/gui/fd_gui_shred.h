#ifndef HEADER_fd_src_disco_gui_fd_gui_shred_h
#define HEADER_fd_src_disco_gui_fd_gui_shred_h

#include "fd_gui_hist.h"

struct fd_gui;
typedef struct fd_gui fd_gui_t;

#define FD_GUI_SHRED_EVENT_POOL_MAX  ((ulong)USHORT_MAX)
#define FD_GUI_SHRED_EVENT_BATCH_MAX (128UL)
#define FD_GUI_SHRED_EVENT_TS_MAX    (0xFFFFFFUL)
#define FD_GUI_FEC_COMPLETION_BATCH_MAX (128UL)

#define FD_GUI_SLOT_SHRED_REPAIR_REQUEST         (0UL)
#define FD_GUI_SLOT_SHRED_SHRED_RECEIVED_TURBINE (1UL)
#define FD_GUI_SLOT_SHRED_SHRED_RECEIVED_REPAIR  (2UL)
#define FD_GUI_SLOT_SHRED_SHRED_REPLAY_EXEC_DONE (3UL)
#define FD_GUI_SLOT_SHRED_SHRED_SLOT_COMPLETE    (4UL)
#define FD_GUI_SLOT_SHRED_SHRED_PUBLISHED        (6UL)

struct __attribute__((packed)) fd_gui_shred_event {
  long   timestamp;
  uint   slot;
  ushort idx;
  uchar  event;
};

typedef struct fd_gui_shred_event fd_gui_shred_event_t;

struct __attribute__((packed)) fd_gui_shred_batch_event {
  uint  timestamp_delta : 24; /* ~16.7ms */
  uchar event;
  uchar idx_delta;
};

typedef struct fd_gui_shred_batch_event fd_gui_shred_batch_event_t;

struct fd_gui_shred_batch {
  ulong  slot;
  long   insert_time_ns;
  long   base_timestamp;
  ushort base_idx;
  uchar  event_cnt;
  fd_gui_shred_batch_event_t events[ FD_GUI_SHRED_EVENT_BATCH_MAX ];
};

typedef struct fd_gui_shred_batch fd_gui_shred_batch_t;

struct fd_gui_fec_event_key {
  uint   slot;
  ushort idx;
  uchar  event;
};

typedef struct fd_gui_fec_event_key fd_gui_fec_event_key_t;

struct fd_gui_shred_event_staged {
  long   timestamp;
  union {
    fd_gui_fec_event_key_t key;
    struct {
      uint   slot;
      ushort idx;
      uchar  event;
    };
  };
  union {
    ushort pool_next;
    ushort dlist_next;
  };
  ushort dlist_prev;
  ushort map_next;
};

typedef struct fd_gui_shred_event_staged fd_gui_shred_event_staged_t;

#define POOL_NAME  fd_gui_shred_event_pool
#define POOL_T     fd_gui_shred_event_staged_t
#define POOL_NEXT  pool_next
#define POOL_IDX_T ushort
#define POOL_LAZY  1
#include "../../util/tmpl/fd_pool.c"

#define DLIST_NAME  fd_gui_shred_event_dlist
#define DLIST_ELE_T fd_gui_shred_event_staged_t
#define DLIST_IDX_T ushort
#define DLIST_NEXT  dlist_next
#define DLIST_PREV  dlist_prev
#include "../../util/tmpl/fd_dlist.c"

/* Index only FEC events.  Hash the fields explicitly to ignore padding. */
#define MAP_NAME             fd_gui_fec_event_map
#define MAP_ELE_T            fd_gui_shred_event_staged_t
#define MAP_KEY_T            fd_gui_fec_event_key_t
#define MAP_KEY              key
#define MAP_IDX_T            ushort
#define MAP_NEXT             map_next
#define MAP_KEY_EQ(a,b)      ((a)->slot==(b)->slot && (a)->idx==(b)->idx && (a)->event==(b)->event)
#define MAP_KEY_HASH(k,seed)  fd_ulong_hash( (seed) ^ ((ulong)(k)->slot | ((ulong)(k)->idx<<32) | ((ulong)(k)->event<<48)) )
#include "../../util/tmpl/fd_map_chain.c"

struct fd_gui_fec_completion {
  long  timestamp;
  uchar turbine;
  uchar repair;
  uchar reconstructed;
  uchar leader;
};
typedef struct fd_gui_fec_completion fd_gui_fec_completion_t;

struct fd_gui_fec_completion_batch {
  ulong slot;
  long  insert_time_ns;
  uchar event_cnt;
  fd_gui_fec_completion_t events[ FD_GUI_FEC_COMPLETION_BATCH_MAX ];
};
typedef struct fd_gui_fec_completion_batch fd_gui_fec_completion_batch_t;

struct fd_gui_fec_completion_staged {
  fd_gui_fec_completion_t event;
  uint slot;
  union { ushort pool_next; ushort dlist_next; };
  ushort dlist_prev;
};
typedef struct fd_gui_fec_completion_staged fd_gui_fec_completion_staged_t;

#define POOL_NAME  fd_gui_fec_completion_pool
#define POOL_T     fd_gui_fec_completion_staged_t
#define POOL_NEXT  pool_next
#define POOL_IDX_T ushort
#define POOL_LAZY  1
#include "../../util/tmpl/fd_pool.c"

#define DLIST_NAME  fd_gui_fec_completion_dlist
#define DLIST_ELE_T fd_gui_fec_completion_staged_t
#define DLIST_IDX_T ushort
#define DLIST_NEXT  dlist_next
#define DLIST_PREV  dlist_prev
#include "../../util/tmpl/fd_dlist.c"

FD_STATIC_ASSERT( sizeof(fd_gui_shred_batch_event_t)==5UL, shred_entry_size );
FD_STATIC_ASSERT( sizeof(fd_gui_shred_batch_t)==672UL, shred_batch_size );
FD_STATIC_ASSERT( sizeof(fd_gui_fec_completion_t)==16UL, completion_entry_size );
FD_STATIC_ASSERT( sizeof(fd_gui_fec_completion_batch_t)==2072UL, completion_batch_size );

struct fd_gui_shred_event_iter {
  fd_gui_shred_event_t event;

  fd_gui_t * _gui;
  long _after_ns;
  long _before_ns;
  fd_gui_hist_iter_t _hist_iter;
  fd_gui_shred_batch_t const * _batch;
  ulong _batch_idx;
  ulong _pending_idx;
  int   _hist_active;
};

typedef struct fd_gui_shred_event_iter fd_gui_shred_event_iter_t;

struct fd_gui_fec_completion_iter {
  fd_gui_fec_completion_t event;
  ulong slot;
  long after_ns;
  long before_ns;
  fd_gui_hist_iter_t hist_iter;
  fd_gui_fec_completion_batch_t const * batch;
  ulong batch_idx;
  int hist_active;
};
typedef struct fd_gui_fec_completion_iter fd_gui_fec_completion_iter_t;

FD_PROTOTYPES_BEGIN

/* FEC event and completion iterators read persisted history only. */

void
fd_gui_fec_event_iter_begin( fd_gui_t * gui, fd_gui_shred_event_iter_t * iter, long after_ns, long before_ns );

void
fd_gui_fec_event_staged_append( fd_gui_t * gui, ulong slot, ulong idx, uchar event, long timestamp );

int
fd_gui_fec_completion_staged_append( fd_gui_t * gui, ulong slot, long timestamp,
                                     ulong turbine, ulong repair, ulong reconstructed, int leader );

void
fd_gui_fec_completion_iter_begin( fd_gui_t * gui, fd_gui_fec_completion_iter_t * iter,
                                  long after_ns, long before_ns );
int
fd_gui_fec_completion_iter_next( fd_gui_fec_completion_iter_t * iter );
void
fd_gui_fec_completion_iter_end( fd_gui_fec_completion_iter_t * iter );

void
fd_gui_shred_event_staged_advance( fd_gui_t * gui, ulong cutoff, long now );

/* Lookup bounds are half-open [lo,hi) and exclude staged events and
   completions. */

int
fd_gui_event_bounds( fd_gui_t * gui, int dbi, long * lo, long * hi );

/* Historical queries read persisted records only.  The live shred iterator
   below additionally includes staged events.  Both use the same next/end. */

fd_gui_shred_event_iter_t *
fd_gui_shred_event_hist_iter_begin( fd_gui_t * gui, fd_gui_shred_event_iter_t * iter,
                                    int dbi, long after_ns, long before_ns );

/* fd_gui_shred_event_iter_{begin|next|end} iterate over shred event
   history, then staged events, in [after_ns,before_ns]. */

fd_gui_shred_event_iter_t *
fd_gui_shred_event_iter_begin( fd_gui_t *                  gui,
                               fd_gui_shred_event_iter_t * iter,
                               long                        after_ns,
                               long                        before_ns );

int
fd_gui_shred_event_iter_next( fd_gui_shred_event_iter_t * iter );

void
fd_gui_shred_event_iter_end( fd_gui_shred_event_iter_t * iter );

/* fd_gui_shred_event_staged_append adds a new shred event to the
   staging buffer. Drops the event if staging is unavailable or full, or
   the slot was already completed. */

void
fd_gui_shred_event_staged_append( fd_gui_t * gui,
                                  ulong      slot,
                                  ulong      idx,
                                  uchar      event,
                                  long       timestamp );

void
fd_gui_shred_event_staged_prune( fd_gui_t * gui,
                                 ulong      root_slot );

/* fd_gui_shred_event_slot_complete moves the slot's staged events to
   history and adds a completion event at timestamp.  now is the history
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

#endif /* HEADER_fd_src_disco_gui_fd_gui_shreds_h */
