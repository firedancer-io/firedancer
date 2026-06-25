#ifndef HEADER_fd_src_disco_gui_fd_gui_store_h
#define HEADER_fd_src_disco_gui_fd_gui_store_h

/* fd_gui_store is the GUI's historical event *backend*: a single mmap'd
   file carved into fixed-size regions that the rings claim and release
   on demand (so each ring grows and shrinks dynamically), plus
   in-memory indices.

   The store hosts a fixed set of named rings.  Each ring is one of two
   *kinds*:

     - KEY-VALUE (KV) rings are a generic point store: a record is
       uniquely identified by a caller-supplied key and there is exactly
       one record per key.

     - TIME-SERIES (TS) rings are an append-only stream of fixed-size
       records.  Each record carries its own timestamp.  The store
       derives the record's `window` (an integer time bucket) from it.
       Readers query records by a time range scan. The scan order is
       insertion order.

   ---- ring-buffer backend --------------------------------------------

   fd_gui_store is one mmap'd file plus in-memory indices.  The file is
   a superblock page followed by a pool of uniform REGION_SZ regions;
   regions are claimed/released on demand from a shared LIFO free list
   (so a given ring has composite regions that are generally
   discontiguous) and the file is ftruncate'd up to the highest claimed
   region as needed, never exceeding size_bytes.  Region ownership, the
   free list and the TS window index are in-memory; only the superblock
   persists.

     file offset 0                data_off
     +----------------------------+--------+--------+--------+-  -+--------+
     |        superblock          | region | region | region |... | region |
     | magic,size,ring[MAX_RINGS] |   0    |   1    |   2    |    | cnt-1  |
     +----------------------------+--------+--------+--------+-  -+--------+
     |<-- data_off (page 0..N) -->|<---------- REGION_SZ each ------------>|
     (ftruncate'd to highest claimed region)

   ---- rings ----------------------------------------------------------

   Both storage shapes are ring buffers addressed by generation cursors
   (monotonically increasing).  Cursors stay contiguous per ring even
   though the regions backing them are physically scattered: cursor
   `cur` lives in the (cur/region_capacity)-th region the ring owns, at
   slot (cur%region_capacity).

   Each ring keeps an ordered region_ids ring mapping region_idx to
   region_id.

     cursor:           0   1   2 | 3   4   5 | 6   7   8
     +---+---+---+---+---+---+---+---+---+
     slot in region: | 0 | 1 | 2 | 0 | 1 | 2 | 0 | 1 | 2 |  (cur % region_capacity)
     +---+---+---+---+---+---+---+---+---+
     logical ord:     \___ 0 __/ \___ 1 __/ \___ 2 __/      (cur / region_capacity)
     |           |           |
     region_ids[ord]:  phys 5      phys 2      phys 9       (physically scattered)

   ---- cursor watermarks ----------------------------------------------

   Three monotonic watermarks (tail_cur <= evict_cur <= head_cur) divide
   a ring's cursor line.  tail_cur is a physical watermark used by the
   eviction policy to free space in the ring. evict_cur is a logical
   watermark used by readers to skip entries marked for eviction.

     cursor --->  (older, smaller)                       (newer, larger)
     .................|===============|########################|- - - - - -
     reclaimed slots | evicted slots |      live records      |  unwritten
     (regions freed) | (below wmark) |  (>= evict_cur, alive) |  (future)
     ^               ^                        ^
     tail_cur        evict_cur                head_cur

   KV records do not store the key separately: the key is a
   caller-declared sub-field of the value (val + key_off, key_sz bytes),
   so a lookup reads and compares it in place via the ring's
   key_cmp/key_hash callbacks. */

#include "../../util/fd_util_base.h"

struct fd_gui_store_private;
typedef struct fd_gui_store_private fd_gui_store_t;

#define FD_GUI_STORE_SUCCESS  ( 0)
#define FD_GUI_STORE_ERR      (-1)
#define FD_GUI_STORE_MAP_FULL ( 1)

#define FD_GUI_STORE_KIND_KV (0)
#define FD_GUI_STORE_KIND_TS (1)

/* FD_GUI_STORE_REGION_SZ is the fixed size of every region in the pool.
   No ring's record stride may exceed it (fd_gui_store_new fails fast
   otherwise).  The store prepends no per-record header (both kinds embed
   their metadata in the value), so FD_GUI_STORE_MAX_REC_SZ is the whole
   region size.  Callers that know their record types at compile time
   should static-assert sizeof(their largest record) <=
   FD_GUI_STORE_MAX_REC_SZ. */
#define FD_GUI_STORE_REGION_SZ  (36UL<<20)
#define FD_GUI_STORE_MAX_REC_SZ (FD_GUI_STORE_REGION_SZ)

/* FD_GUI_STORE_MAX_RINGS is the maximum number of named rings a store
   can host.  It bounds the per-ring metrics arrays below. */
#define FD_GUI_STORE_MAX_RINGS (64UL)

struct fd_gui_store_desc {
  char const * name;    /* the name of the ring.  Must be non-NULL and unique within the store */
  int          kind;    /* FD_GUI_STORE_KIND_KV or FD_GUI_STORE_KIND_TS */
  ulong        key_off; /* byte offset, within the value, of the record's key (pass 0 for TS) */
  ulong        key_sz;  /* key size in bytes */
  ulong      ( * key_hash )( void const * key ); /* hashes a key to a ulong (pass NULL for TS) */
  int        ( * key_cmp  )( void const * a, void const * b ); /* full-key total order; may treat sentinels as wildcards for get_any/iter (pass NULL for TS) */
  ulong        val_sz;      /* record size in bytes */
  ulong        val_align;   /* record alignment (power of two, >=1; pass 1 for none) */
  ulong        ts_off;      /* byte offset, within the value, of the record's `long` timestamp (TS only; pass 0 for KV) */
  ulong        granularity; /* TS window divisor: window = (ulong)(*(long*)(val+ts_off)) / granularity (pass 0 for KV) */
  ulong        max_records; /* The maximum number of distinct live records this ring can ever hold (pass 0 for TS) */
};

typedef struct fd_gui_store_desc fd_gui_store_desc_t;

FD_PROTOTYPES_BEGIN

FD_FN_CONST ulong
fd_gui_store_align( void );

FD_FN_CONST ulong
fd_gui_store_footprint( ulong                       size_bytes,
                        ulong                       ring_cnt,
                        fd_gui_store_desc_t const * descs );

/* fd_gui_store_new formats the workspace region `mem` and opens the
   backing store whose data file is `path`, with a size ceiling of
   `size_bytes`.  The parent directory of `path` must already exist.
   `ring_cnt` named rings are created, one per entry of `descs`.  The
   store is wiped on open.

   Returns `mem` on success, or NULL on failure (logged at WARNING). */

void *
fd_gui_store_new( void *                      mem,
                  char const *                path,
                  ulong                       size_bytes,
                  ulong                       ring_cnt,
                  fd_gui_store_desc_t const * descs );

fd_gui_store_t *
fd_gui_store_join( void * mem );

void *
fd_gui_store_leave( fd_gui_store_t * db );

void *
fd_gui_store_delete( void * mem );

/* fd_gui_store_cnt returns the number of named rings in the store. */

ulong
fd_gui_store_cnt( fd_gui_store_t const * db );

/* ---- space accounting ------------------------------------------------- */

ulong
fd_gui_store_used_bytes( fd_gui_store_t * db );

ulong
fd_gui_store_live_bytes( fd_gui_store_t * db );

ulong
fd_gui_store_size( fd_gui_store_t const * db );

/* fd_gui_store_free_region_cnt returns the number of regions currently
   unclaimed on disk. */

ulong
fd_gui_store_free_region_cnt( fd_gui_store_t const * db );

int
fd_gui_store_fd( fd_gui_store_t const * db );

/* fd_gui_store_min_overhead_bytes returns the fixed byte overhead a
   store adds on top of usable record space: the superblock page plus
   one region.  A store whose size_bytes ceiling is at least this large
   plus the caller's desired usable capacity is guaranteed to lay out
   with at least one region. */

FD_FN_CONST ulong
fd_gui_store_min_overhead_bytes( void );

struct fd_gui_store_metrics {
  ulong kv_lookups   [ FD_GUI_STORE_MAX_RINGS ]; /* KV lookup calls (per call)         */
  ulong ts_appends   [ FD_GUI_STORE_MAX_RINGS ]; /* TS records appended (per rec)      */
  ulong ts_reads     [ FD_GUI_STORE_MAX_RINGS ]; /* TS scan calls (per call)           */
  ulong ts_read_records[ FD_GUI_STORE_MAX_RINGS ]; /* TS records returned (per rec)    */
  ulong evict_records[ FD_GUI_STORE_MAX_RINGS ]; /* records physically evicted         */
  ulong evicts       [ FD_GUI_STORE_MAX_RINGS ]; /* kv_evict + ts_evict calls          */
  ulong region_grows [ FD_GUI_STORE_MAX_RINGS ]; /* regions claimed from the free list */
  ulong region_reclaims[ FD_GUI_STORE_MAX_RINGS ]; /* regions returned to the free list */
  ulong map_full     [ FD_GUI_STORE_MAX_RINGS ]; /* low-level MAP_FULL returns before higher-layer recovery */
};

typedef struct fd_gui_store_metrics fd_gui_store_metrics_t;

fd_gui_store_metrics_t const *
fd_gui_store_metrics( fd_gui_store_t const * db );

/* fd_gui_store_ring_stats computes on-demand space accounting for ring
   `ring_idx`. */
void
fd_gui_store_ring_stats( fd_gui_store_t * db,
                         ulong            ring_idx,
                         ulong *          used_bytes,
                         ulong *          cap_bytes,
                         ulong *          free_bytes,
                         ulong *          used_slots,
                         ulong *          cap_slots,
                         ulong *          free_slots );

/* ---- KV ring -------------------------------------------------------- */

/* fd_gui_store_kv_get_or_create reserves (creating if absent) the
   record for `key` and, on success, hands back a mutable pointer to the
   record's value region. */

int
fd_gui_store_kv_get_or_create( fd_gui_store_t * db,
                               ulong            ring_idx,
                               void const *     key,
                               void **          val_out );

/* fd_gui_store_kv_get looks up the record for `key` in KV ring
   `ring_idx` and returns a mutable pointer to the record's value
   region, or NULL if the record is not found. */

void *
fd_gui_store_kv_get( fd_gui_store_t * db,
                     ulong            ring_idx,
                     void const *     key );

/* fd_gui_store_kv_get_any looks up the lowest record whose key matches
   `key` (per the ring's key_cmp, which may treat sentinel fields in `key`
   as wildcards) and returns a mutable pointer to its value region, or
   NULL if none.  Pass key==NULL to match the lowest record in the ring. */

void *
fd_gui_store_kv_get_any( fd_gui_store_t * db,
                         ulong            ring_idx,
                         void const *     key );

struct fd_gui_store_kv_iter {
  void const *  rec;        /* current record value (into the store map); NULL when done */
  void const *  key;        /* current record full key (into rec, at key_off); NULL when done */
  ulong         val_sz;     /* current record value size                                  */
  ulong         key_sz;     /* current record full key size                               */
  /* opaque state */
  void *        _db;        /* backend handle (fd_gui_store_t *) */
  ulong         _ring_idx;
  int           _valid;
  int           _have_prev; /* 1 once at least one record has been emitted */
  uchar         _key[ 16 ]; /* query key (may hold wildcards); FD_GUI_STORE_KV_KEY_MAX */
  uchar         _prev_key[ 16 ]; /* last emitted full key (selection cursor) */
};

typedef struct fd_gui_store_kv_iter fd_gui_store_kv_iter_t;

fd_gui_store_kv_iter_t *
fd_gui_store_kv_iter_begin( fd_gui_store_t *         db,
                            fd_gui_store_kv_iter_t * iter,
                            ulong                    ring_idx,
                            void const *             key );

FD_FN_PURE static inline int
fd_gui_store_kv_iter_done( fd_gui_store_kv_iter_t const * iter ) {
  return !iter->_valid;
}

int
fd_gui_store_kv_iter_next( fd_gui_store_kv_iter_t * iter );


/* ---- KV ring: eviction ---------------------------------------------- */

/* fd_gui_store_kv_evict reclaims drained records (up to budget records)
   from the `ring_idx` ring, stopping at the hi_key watermark. */

int
fd_gui_store_kv_evict( fd_gui_store_t * db,
                       ulong            ring_idx,
                       void const *     hi_key,
                       ulong *          budget,
                       int *            drained );

/* ---- TS ring: append-only stream ------------------------------------ */

/* fd_gui_store_ts_append appends one fixed-size record to ring
   `ring_idx`. Returns FD_GUI_STORE_SUCCESS, FD_GUI_STORE_MAP_FULL,
   or FD_GUI_STORE_ERR. */

int
fd_gui_store_ts_append( fd_gui_store_t * db,
                        ulong            ring_idx,
                        void const *     val );

/* fd_gui_store_ts_filter_fn is an optional per-record predicate
   evaluated during a scan: it returns non-zero to emit the record or
   zero to skip it. A NULL filter accepts every record. */

typedef int (*fd_gui_store_ts_filter_fn)( void const * rec, void * ctx );

struct fd_gui_store_ts_iter {
  void const *           rec;       /* current record (into the store map); NULL when done */
  ulong                  window;    /* current record's window                   */
  /* opaque state */
  void *                 _db;       /* backend handle (fd_gui_store_t *) */
  void *                 _cur;      /* next ring cursor to examine (value, not ptr) */
  int                    _valid;
  ulong                  _rec_sz;   /* ring_idx+1 (0 means uninitialised) */
  ulong                  _window_lo;
  ulong                  _window_hi;
  ulong                  _cur_hi;   /* ring cursor to stop at (exclusive; from the window index) */
  fd_gui_store_ts_filter_fn _filter;
  void *                 _filter_ctx;
};

typedef struct fd_gui_store_ts_iter fd_gui_store_ts_iter_t;

fd_gui_store_ts_iter_t *
fd_gui_store_ts_scan_begin( fd_gui_store_t *          db,
                            fd_gui_store_ts_iter_t *  iter,
                            ulong                     ring_idx,
                            ulong                     window_lo,
                            ulong                     window_hi,
                            fd_gui_store_ts_filter_fn filter,
                            void *                    filter_ctx );

FD_FN_PURE static inline int
fd_gui_store_ts_scan_done( fd_gui_store_ts_iter_t const * iter ) {
  return !iter->_valid;
}

int
fd_gui_store_ts_scan_next( fd_gui_store_ts_iter_t * iter );

void
fd_gui_store_ts_scan_end( fd_gui_store_ts_iter_t * iter );

/* fd_gui_store_ts_oldest_window returns, in *out_window, the time
   window for the oldest record in TS ring `ring_idx`.  Returns 1 if the
   ring holds any record, 0 if it is empty or not a TS ring. */

int
fd_gui_store_ts_oldest_window( fd_gui_store_t * db,
                               ulong            ring_idx,
                               ulong *          out_window );

/* ---- TS ring: eviction ---------------------------------------------- */

/* fd_gui_store_ts_evict reclaims drained records (up to budget records)
   from the `ring_idx` ring, stopping at the hi_key watermark. */

int
fd_gui_store_ts_evict( fd_gui_store_t * db,
                       ulong            ring_idx,
                       ulong            hi_window,
                       ulong *          budget,
                       int *            drained );

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_gui_fd_gui_store_h */
