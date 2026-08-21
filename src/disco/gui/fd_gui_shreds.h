#ifndef HEADER_fd_src_disco_gui_fd_gui_shreds_h
#define HEADER_fd_src_disco_gui_fd_gui_shreds_h

#include "fd_gui_hist.h"

struct fd_gui;
typedef struct fd_gui fd_gui_t;

#define FD_GUI_SHRED_EVENT_POOL_MAX  ((ulong)USHORT_MAX)
#define FD_GUI_SHRED_EVENT_BATCH_MAX (128UL)
#define FD_GUI_SHRED_EVENT_TS_MAX    (0xFFFFFFUL)

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
  uchar timestamp_delta[ 3 ];
  uchar event;
  uchar idx_delta;
};

typedef struct fd_gui_shred_batch_event fd_gui_shred_batch_event_t;

struct fd_gui_shred_batch {
  ulong  slot;
  long   base_timestamp;
  ushort base_idx;
  uchar  event_cnt;
  fd_gui_shred_batch_event_t events[ FD_GUI_SHRED_EVENT_BATCH_MAX ];
};

typedef struct fd_gui_shred_batch fd_gui_shred_batch_t;

struct fd_gui_shred_event_staged {
  long   timestamp;
  uint   slot;
  ushort idx;
  uchar  event;
  union {
    ushort pool_next;
    ushort dlist_next;
  };
  ushort dlist_prev;
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

FD_PROTOTYPES_BEGIN

fd_gui_shred_event_iter_t *
fd_gui_shred_event_iter_begin( fd_gui_t *                  gui,
                               fd_gui_shred_event_iter_t * iter,
                               long                        after_ns,
                               long                        before_ns );

int
fd_gui_shred_event_iter_next( fd_gui_shred_event_iter_t * iter );

void
fd_gui_shred_event_iter_end( fd_gui_shred_event_iter_t * iter );

void
fd_gui_shred_event_append( fd_gui_t * gui,
                           ulong      slot,
                           ulong      idx,
                           uchar      event,
                           long       timestamp );

void
fd_gui_shred_event_reclaim_before( fd_gui_t * gui,
                                   ulong      root_slot );

void
fd_gui_shred_event_slot_complete( fd_gui_t * gui,
                                  ulong      slot,
                                  long       timestamp,
                                  long       now );

FD_PROTOTYPES_END

#endif
