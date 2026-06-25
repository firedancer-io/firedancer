#ifndef HEADER_fd_src_disco_gui_fd_gui_hist_h
#define HEADER_fd_src_disco_gui_fd_gui_hist_h

/* fd_gui_hist is the GUI's historical event store semantics layer.  It
   sits on top of fd_gui_store and owns everything GUI-specific about
   the monitoring history: the named DBs (FD_GUI_HIST_* below), their
   key/value structs, fixed record sizes, the eviction policy, and the
   query API.

   There are two kinds of DB:

     - TIME-SERIES (TS) DBs are append-only streams tagged by a
       wallclock window. Written by fd_gui_hist_ts_append, read by
       time-window range scan.
     - KEY-VALUE (KV) DBs hold one record per key.  Written/read by
       point key (fd_gui_hist_kv_get_or_create / _get / _get_any).
*/

#include "../../util/fd_util_base.h"
#include "fd_gui_store.h"

struct fd_gui;
typedef struct fd_gui fd_gui_t;

#define FD_GUI_HIST_MAGIC (0xf17e6d09147802UL)

/* FD_GUI_HIST_TS_SKEW_NS bounds how far a TS record's timestamp may
   deviate from the trusted wallclock `now` at append time (in either
   direction).  fd_gui_hist_ts_append clamps ts_ns into [now-skew, now+skew]
   before flooring it to a window.  This bounds the out-of-orderness of
   the append stream which ensures the underlying ring buffer can efficiently evict old entries. */

#define FD_GUI_HIST_TS_SKEW_NS (10L*FD_GUI_HIST_RES_1S_NS) /* +/- 10 s */
#define FD_GUI_HIST_RES_1S_NS (1000000000L)

/* FD_GUI_HIST_MIN_EPOCHS is the minimum number of epochs the store must
   hold, plus one more which can be evicted under space pressure. */

#define FD_GUI_HIST_MIN_EPOCHS (3UL)

#define FD_GUI_HIST_SCHEDULER_COUNTS (0)  /* (ts, type)            */
#define FD_GUI_HIST_TILE_TIMERS      (1)  /* (ts, type)            */
#define FD_GUI_HIST_SHRED_EVENTS     (2)  /* (ts, type, slot)      */
#define FD_GUI_HIST_TXN_START        (3)  /* (ts, type, bank, txn) */
#define FD_GUI_HIST_TXN_END          (4)  /* (ts, type, bank, txn) */
#define FD_GUI_HIST_TOWER            (5)  /* (ts, type)            */
#define FD_GUI_HIST_SLOT             (6)  /* (slot, bank_seq)      */
#define FD_GUI_HIST_LEADER_SLOT      (7)  /* (slot, bank_seq)      */
#define FD_GUI_HIST_EPOCH            (8)  /* (epoch)               */
#define FD_GUI_HIST_TILE_STATS       (9)  /* (ts, type)            */
#define FD_GUI_HIST_TXN_WATERFALL    (10) /* (ts, type)            */
#define FD_GUI_HIST_CNT              (11)

struct fd_gui_hist_metrics {
  /* Writes that hit MAP_FULL and were dropped. */
  ulong map_full[ FD_GUI_HIST_CNT ];
  /* Writes that evicted records before succeeding. */
  ulong reserves [ FD_GUI_HIST_CNT ];
};
typedef struct fd_gui_hist_metrics fd_gui_hist_metrics_t;

struct fd_gui_hist_slot_key        { ulong slot; ulong bank_seq; };
struct fd_gui_hist_leader_slot_key { ulong slot; ulong bank_seq; };
struct fd_gui_hist_epoch_key       { ulong epoch; };

typedef struct fd_gui_hist_slot_key        fd_gui_hist_slot_key_t;
typedef struct fd_gui_hist_leader_slot_key fd_gui_hist_leader_slot_key_t;
typedef struct fd_gui_hist_epoch_key       fd_gui_hist_epoch_key_t;

struct fd_gui_hist_private;
typedef struct fd_gui_hist_private fd_gui_hist_t;

/* fd_gui_hist_kv_slot_iter_t iterates every record for `slot` (every
   fork's block) in a slot-keyed KV DB.  Used to enumerate the
   equivocating forks of a slot. */
struct fd_gui_hist_kv_slot_iter {
  void const *            rec;       /* current record; NULL when done */
  ulong                   bank_seq;  /* current record's bank_seq      */
  fd_gui_store_kv_iter_t _it;
};
typedef struct fd_gui_hist_kv_slot_iter fd_gui_hist_kv_slot_iter_t;

/* fd_gui_hist_range_filter_fn is an optional per-record predicate
   evaluated during a range scan: called with a pointer to the DB's
   record and the caller's `ctx`, it returns non-zero to emit the record
   or zero to skip it.  A NULL filter emits every record in the window
   range. */

typedef int (*fd_gui_hist_range_filter_fn)( void const * rec, void * ctx );

/* fd_gui_hist_iter_t iterates the records produced by a time-window
   range query.

   Records are emitted oldest-window-first, but the backend does not
   strictly order records within a window.
*/
struct fd_gui_hist_iter {
  void const * rec;
  ulong        rec_sz;

  int                         _dbi;
  int                         _emitted;
  fd_gui_hist_range_filter_fn _filter;
  void *                      _filter_ctx;
  fd_gui_store_ts_iter_t      _it;
};

typedef struct fd_gui_hist_iter fd_gui_hist_iter_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong
fd_gui_hist_align( void );

FD_FN_CONST ulong
fd_gui_hist_footprint( void );

/* fd_gui_hist_new formats the workspace region `mem`
   (>= fd_gui_hist_footprint bytes, fd_gui_hist_align aligned) as the
   history semantics layer over the store `db`. Returns `mem` on success
   or NULL on failure (logged). */

void *
fd_gui_hist_new( void *                 mem,
                 fd_gui_store_t const * db );

/* fd_gui_hist_join joins a region formatted by fd_gui_hist_new,
   returning a usable handle (mem may be NULL -> NULL). */

fd_gui_hist_t *
fd_gui_hist_join( void * mem );

void *
fd_gui_hist_leave( fd_gui_hist_t * hist );

void *
fd_gui_hist_delete( void * mem );

/* fd_gui_hist_db_descs returns a pointer to a static array to be passed
   to fd_gui_store_new. */

fd_gui_store_desc_t const *
fd_gui_hist_db_descs( ulong store_bytes );

FD_FN_CONST static inline ulong
fd_gui_hist_db_cnt( void ) { return FD_GUI_HIST_CNT; }

fd_gui_hist_metrics_t const *
fd_gui_hist_metrics( fd_gui_t const * gui );

/* ---- TS read/write -------------------------------------------------- */

/* fd_gui_hist_ts_append appends one record `val` into time-series
   database `dbi`, tagged with wallclock timestamp `ts_ns`.  `now` is
   the current wallclock at append time.

   Will evict old entries to make room if necessary.  Returns 0 on
   success, -1 on failure (e.g. a misconfigured DB size). */

int
fd_gui_hist_ts_append( fd_gui_t *   gui,
                       int          dbi,
                       long         now,
                       long         ts_ns,
                       void const * val );

int
fd_gui_hist_range_begin( fd_gui_t *                   gui,
                         fd_gui_hist_iter_t *         iter,
                         int                          dbi,
                         long                         lo_ns,
                         long                         hi_ns,
                         fd_gui_hist_range_filter_fn  filter,
                         void *                       filter_ctx );

int
fd_gui_hist_range_next( fd_gui_hist_iter_t * iter );

void
fd_gui_hist_range_end( fd_gui_hist_iter_t * iter );


/* ---- KV read/write -------------------------------------------------- */

/* fd_gui_hist_kv_get_or_create reserves (creating if absent) the record
   for `*key` in a KV DB and returns a mutable pointer to the record's
   value, or NULL on failure.

   Will evict old entries to make room if necessary.  Returns the value
   pointer on success, or NULL on error. */

void *
fd_gui_hist_kv_get_or_create( fd_gui_t *   gui,
                              int          dbi,
                              void const * key );

/* fd_gui_hist_kv_get is like fd_gui_hist_kv_get_or_create, but returns
   NULL when the record is not found instead of creating one. */

void *
fd_gui_hist_kv_get( fd_gui_t *   gui,
                    int          dbi,
                    void const * key );

/* fd_gui_hist_kv_get_slot_any looks up the slot record for the first
   key matching (slot, *) and returns a pointer to its value. */

void *
fd_gui_hist_kv_get_slot_any( fd_gui_t * gui,
                             int        dbi,
                             ulong      slot );

fd_gui_hist_kv_slot_iter_t *
fd_gui_hist_kv_iter_begin( fd_gui_t *                   gui,
                           fd_gui_hist_kv_slot_iter_t * iter,
                           int                          dbi,
                           ulong                        slot );

int
fd_gui_hist_kv_iter_next( fd_gui_hist_kv_slot_iter_t * iter );

/* ---- Eviction ------------------------------------------------------- */

/* fd_gui_hist_evict_step does at most one bounded unit of eviction
   work.

   The store is bounded by its configured map size.  When it grows near
   full, the oldest epoch is evicted whole: its EPOCH record, every KV
   row for the epoch's slots, and every time-series row in the wallclock
   window the epoch spanned.  An epoch can hold a lot of data, so the
   work is spread across many bounded batches.

   If the store is below the high-water threshold and no eviction
   is in progress, it does nothing and returns 0.  Otherwise it advances
   the current epoch's cascade by one batch (or starts a new cascade on
   the oldest epoch), returning 1.  No-op (returns 0) if the store is
   unavailable. */

int
fd_gui_hist_evict_step( fd_gui_t * gui );

/* fd_gui_hist_evict_oldest evicts the single oldest epoch in its
   entirety, synchronously and unconditionally.

   It is the slow-path used when a write hits map-full.  Returns 1 if an
   epoch was evicted, 0 if there was nothing to evict or the store is
   unavailable. */

int
fd_gui_hist_evict_oldest( fd_gui_t * gui );

/* fd_gui_hist_evict_ts_oldest sheds time-series data oldest-first.

   It is the slow-path used when a write hits map-full. Returns 1 if it
   evicted a window's worth of records, 0 if every time-series DB is
   already empty or the store is unavailable. */

int
fd_gui_hist_evict_ts_oldest( fd_gui_t * gui );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_gui_fd_gui_hist_h */
