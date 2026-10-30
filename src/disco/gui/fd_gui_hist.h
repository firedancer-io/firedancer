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
#include "../../flamenco/leaders/fd_leaders_base.h"   /* MAX_SLOTS_PER_EPOCH */
#include "../../flamenco/runtime/fd_slot_params.h"    /* FD_SLOT_PARAMS_200MS */

struct fd_gui;
typedef struct fd_gui fd_gui_t;

#define FD_GUI_HIST_MAGIC (0xf17e6d09147802UL)

#define FD_GUI_HIST_RES_1S_NS (1000000000L)

#define FD_GUI_HIST_MAX_LEADER_SLOTS_PER_EPOCH (43200UL) /* 10% capacity should be enough for mainnet/testnet */

#define FD_GUI_HIST_MAX_EPOCHS (64UL) /* Comfortably above typical time between restarts */

/* Minimum number of epochs of slot, leader slot and epoch records the
   store always retains, regardless of pressure from other DBs. */
#define FD_GUI_HIST_MIN_EPOCHS (3UL)

/* Bounds the per-tile CPU day records retained (per tile).  Two months
   of calendar days, about the span of FD_GUI_HIST_MAX_EPOCHS epochs. */
#define FD_GUI_HIST_MAX_TIMELINE_DAYS (64UL)

#define FD_GUI_HIST_SCHEDULER_COUNTS  (0)  /* (ts, type)            */
#define FD_GUI_HIST_TILE_TIMERS       (1)  /* (ts, type)            */
#define FD_GUI_HIST_SHRED_EVENTS      (2)
#define FD_GUI_HIST_TXN_START         (3)  /* (ts, type, bank, txn) */
#define FD_GUI_HIST_TXN_END           (4)  /* (ts, type, bank, txn) */
#define FD_GUI_HIST_SLOT              (5)  /* (slot, bank_seq)      */
#define FD_GUI_HIST_LEADER_SLOT       (6)  /* (slot, bank_seq)      */
#define FD_GUI_HIST_EPOCH             (7)  /* (epoch)               */
#define FD_GUI_HIST_TILE_STATS        (8)  /* (ts, type)            */
#define FD_GUI_HIST_TXN_WATERFALL     (9)  /* (ts, type)            */
#define FD_GUI_HIST_TIMELINE_DAY      (10)
#define FD_GUI_HIST_REPLAY_TXN        (11)
#define FD_GUI_HIST_TIMELINE_TILE_DAY (12) /* (day_idx, tile_idx)  */
#define FD_GUI_HIST_FEC_EVENTS        (13) /* (FEC event key)      */
#define FD_GUI_HIST_FEC_EVENT_ARCHIVE (14) /* (ts, ...)            */
#define FD_GUI_HIST_CNT               (15)

struct fd_gui_hist_metrics {
  /* Writes dropped after exhausting region or KV index capacity. */
  ulong map_full[ FD_GUI_HIST_CNT ];
  /* Writes that evicted records before succeeding. */
  ulong reserves [ FD_GUI_HIST_CNT ];
};
typedef struct fd_gui_hist_metrics fd_gui_hist_metrics_t;

struct fd_gui_hist_slot_key        { ulong slot; ulong bank_seq; };
struct fd_gui_hist_leader_slot_key { ulong slot; ulong bank_seq; };
struct fd_gui_hist_epoch_key       { ulong epoch; };
struct fd_gui_hist_tile_day_key    { ulong day_idx; ulong tile_idx; };
typedef struct fd_gui_hist_slot_key        fd_gui_hist_slot_key_t;
typedef struct fd_gui_hist_leader_slot_key fd_gui_hist_leader_slot_key_t;
typedef struct fd_gui_hist_epoch_key       fd_gui_hist_epoch_key_t;
typedef struct fd_gui_hist_tile_day_key    fd_gui_hist_tile_day_key_t;

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

/* fd_gui_hist_db_descs fills descs with the FD_GUI_HIST_CNT DB
   descriptors for a store of store_bytes, and returns descs. */

fd_gui_store_desc_t *
fd_gui_hist_db_descs( fd_gui_store_desc_t descs[ static FD_GUI_HIST_CNT ],
                      ulong               store_bytes );

FD_FN_CONST static inline ulong
fd_gui_hist_db_cnt( void ) { return FD_GUI_HIST_CNT; }

/* fd_gui_hist_store_footprint returns the footprint of a store of
   store_bytes holding the history DBs, or 0 if store_bytes is too
   small. */

ulong
fd_gui_hist_store_footprint( ulong store_bytes );

/* fd_gui_hist_store_new formats mem as a store of store_bytes backed
   by path, holding the history DBs.  The result is ready to join and
   pass to fd_gui_hist_new.  Returns mem on success or NULL on failure
   (logged, see fd_gui_store_new). */

void *
fd_gui_hist_store_new( void *       mem,
                       char const * path,
                       ulong        store_bytes,
                       ulong        seed );

fd_gui_hist_metrics_t const *
fd_gui_hist_metrics( fd_gui_t const * gui );

/* ---- TS read/write -------------------------------------------------- */

/* fd_gui_hist_ts_append copies the record at val into time-series DB
   dbi, preserving its contents.  The timestamp at the DB's configured
   offset must be >= the timestamp of the last successful append.

   Returns 0 on success, -1 for an invalid DB, a decreasing timestamp,
   or a store append failure. */

int
fd_gui_hist_ts_append( fd_gui_t *   gui,
                       int          dbi,
                       void const * val );

/* fd_gui_hist_ts_emplace is fd_gui_hist_ts_append without the copy: it
   appends a record whose timestamp field is stored_ts and returns a
   pointer to it in the store, or NULL on the same failures. */

void *
fd_gui_hist_ts_emplace( fd_gui_t * gui,
                        int        dbi,
                        long       stored_ts );

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

/* fd_gui_hist_evict_step reclaims at most FD_GUI_HIST_EVICT_BATCH
   records from an oldest excess region once at most one shared region
   remains free.  Every DB's newest base_regions regions are protected
   (see fd_gui_hist_db_descs).  FEC staging is never evicted; it only
   drains through fd_gui_fec_archive.  Returns 1 for actual progress, 0
   when idle or all candidates pinned.  Writes retry on pressure, then
   recycle only their own eligible history if no excess candidate
   remains. */

int
fd_gui_hist_evict_step( fd_gui_t * gui );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_gui_fd_gui_hist_h */
