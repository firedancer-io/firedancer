#include "fd_gui_hist.h"
#include "fd_gui_store.h"
#include "fd_gui.h" /* fd_gui_t, record types */

#include <stddef.h> /* offsetof */

/* Every record type must fit in one store region (header + record). */
FD_STATIC_ASSERT( sizeof(fd_gui_slot_history_shred_event_t)<=FD_GUI_STORE_MAX_REC_SZ, rec_fits );
FD_STATIC_ASSERT( sizeof(fd_gui_tile_timers_hist_t        )<=FD_GUI_STORE_MAX_REC_SZ, rec_fits );
FD_STATIC_ASSERT( sizeof(fd_gui_scheduler_counts_t        )<=FD_GUI_STORE_MAX_REC_SZ, rec_fits );
FD_STATIC_ASSERT( sizeof(fd_gui_tile_stats_t              )<=FD_GUI_STORE_MAX_REC_SZ, rec_fits );
FD_STATIC_ASSERT( sizeof(fd_gui_txn_waterfall_t           )<=FD_GUI_STORE_MAX_REC_SZ, rec_fits );
FD_STATIC_ASSERT( sizeof(fd_gui_store_txn_start_t         )<=FD_GUI_STORE_MAX_REC_SZ, rec_fits );
FD_STATIC_ASSERT( sizeof(fd_gui_store_txn_end_t           )<=FD_GUI_STORE_MAX_REC_SZ, rec_fits );
FD_STATIC_ASSERT( sizeof(fd_gui_slot_t                    )<=FD_GUI_STORE_MAX_REC_SZ, rec_fits );
FD_STATIC_ASSERT( sizeof(fd_gui_leader_slot_t             )<=FD_GUI_STORE_MAX_REC_SZ, rec_fits );
FD_STATIC_ASSERT( sizeof(fd_gui_epoch_t                   )<=FD_GUI_STORE_MAX_REC_SZ, rec_fits );

/* fd_gui_hist_ts_append copies each TS record through a fixed stack buffer
   so it can rewrite the clamped timestamp; every TS record type must fit. */
#define FD_GUI_HIST_TS_SZ_MAX (512UL)
FD_STATIC_ASSERT( sizeof(fd_gui_slot_history_shred_event_t)<=FD_GUI_HIST_TS_SZ_MAX, ts_rec_fits );
FD_STATIC_ASSERT( sizeof(fd_gui_tile_timers_hist_t        )<=FD_GUI_HIST_TS_SZ_MAX, ts_rec_fits );
FD_STATIC_ASSERT( sizeof(fd_gui_scheduler_counts_t        )<=FD_GUI_HIST_TS_SZ_MAX, ts_rec_fits );
FD_STATIC_ASSERT( sizeof(fd_gui_tile_stats_t              )<=FD_GUI_HIST_TS_SZ_MAX, ts_rec_fits );
FD_STATIC_ASSERT( sizeof(fd_gui_txn_waterfall_t           )<=FD_GUI_HIST_TS_SZ_MAX, ts_rec_fits );
FD_STATIC_ASSERT( sizeof(fd_gui_store_txn_start_t         )<=FD_GUI_HIST_TS_SZ_MAX, ts_rec_fits );
FD_STATIC_ASSERT( sizeof(fd_gui_store_txn_end_t           )<=FD_GUI_HIST_TS_SZ_MAX, ts_rec_fits );

/* Each key type must alias the matching record field exactly. */
FD_STATIC_ASSERT( offsetof( fd_gui_hist_slot_key_t,        slot     )==offsetof( fd_gui_slot_t,        slot     ), key_layout );
FD_STATIC_ASSERT( offsetof( fd_gui_hist_slot_key_t,        bank_seq )==offsetof( fd_gui_slot_t,        bank_seq ), key_layout );
FD_STATIC_ASSERT( offsetof( fd_gui_hist_leader_slot_key_t, slot     )==offsetof( fd_gui_leader_slot_t, slot     ), key_layout );
FD_STATIC_ASSERT( offsetof( fd_gui_hist_leader_slot_key_t, bank_seq )==offsetof( fd_gui_leader_slot_t, bank_seq ), key_layout );
FD_STATIC_ASSERT( offsetof( fd_gui_hist_epoch_key_t,       epoch    )==offsetof( fd_gui_epoch_t,       epoch    ), key_layout );

#define FD_GUI_HIST_KEYSHAPE_TIMESERIES (0) /* (ts, ...)        */
#define FD_GUI_HIST_KEYSHAPE_SLOT_BANK  (1) /* (slot, bank_seq) */
#define FD_GUI_HIST_KEYSHAPE_EPOCH      (2) /* (epoch)          */

static inline long
fd_gui_hist_dbi_res_ns( int dbi FD_PARAM_UNUSED ) {
  return FD_GUI_HIST_RES_1S_NS; /* all TS DBs use the 1s resolution */
}

static inline ulong
fd_gui_hist_dbi_ts_off( int dbi ) {
  switch( dbi ) {
    case FD_GUI_HIST_SHRED_EVENTS:     return offsetof( fd_gui_slot_history_shred_event_t, timestamp           );
    case FD_GUI_HIST_TILE_TIMERS:      return offsetof( fd_gui_tile_timers_hist_t,         sample_time_nanos   );
    case FD_GUI_HIST_SCHEDULER_COUNTS: return offsetof( fd_gui_scheduler_counts_t,         sample_time_ns      );
    case FD_GUI_HIST_TILE_STATS:       return offsetof( fd_gui_tile_stats_t,               sample_time_nanos   );
    case FD_GUI_HIST_TXN_WATERFALL:    return offsetof( fd_gui_txn_waterfall_t,            sample_time_nanos   );
    case FD_GUI_HIST_TXN_START:        return offsetof( fd_gui_store_txn_start_t,          microblock_start_ns );
    case FD_GUI_HIST_TXN_END:          return offsetof( fd_gui_store_txn_end_t,            microblock_end_ns   );
    default:                           return 0UL;
  }
}

static inline ulong
fd_gui_hist_window( long ts_ns, long res_ns ) {
  return (ulong)( ts_ns / res_ns );
}

static int
fd_gui_hist_keyshape( int dbi ) {
  switch( dbi ) {
    case FD_GUI_HIST_SCHEDULER_COUNTS:
    case FD_GUI_HIST_TILE_TIMERS:
    case FD_GUI_HIST_TILE_STATS:
    case FD_GUI_HIST_TXN_WATERFALL:
    case FD_GUI_HIST_TOWER:
    case FD_GUI_HIST_SHRED_EVENTS:
    case FD_GUI_HIST_TXN_START:
    case FD_GUI_HIST_TXN_END:          return FD_GUI_HIST_KEYSHAPE_TIMESERIES;
    case FD_GUI_HIST_SLOT:
    case FD_GUI_HIST_LEADER_SLOT:      return FD_GUI_HIST_KEYSHAPE_SLOT_BANK;
    case FD_GUI_HIST_EPOCH:            return FD_GUI_HIST_KEYSHAPE_EPOCH;
    default: FD_LOG_ERR(( "invalid dbi %d", dbi )); return -1;
  }
}

static inline int
fd_gui_hist_is_timeseries( int dbi ) {
  return fd_gui_hist_keyshape( dbi )==FD_GUI_HIST_KEYSHAPE_TIMESERIES;
}

static ulong
fd_gui_hist_slot_key_hash( void const * key ) {
  fd_gui_hist_slot_key_t const * k = key;
  return fd_ulong_hash( k->slot );
}

static int
fd_gui_hist_slot_key_cmp( void const * a, void const * b ) {
  fd_gui_hist_slot_key_t const * ka = a;
  fd_gui_hist_slot_key_t const * kb = b;
  if( ka->slot<kb->slot ) return -1;
  if( ka->slot>kb->slot ) return  1;
  if( ka->bank_seq==ULONG_MAX || kb->bank_seq==ULONG_MAX ) return 0;
  if( ka->bank_seq<kb->bank_seq ) return -1;
  if( ka->bank_seq>kb->bank_seq ) return  1;
  return 0;
}

static ulong
fd_gui_hist_leader_slot_key_hash( void const * key ) {
  fd_gui_hist_leader_slot_key_t const * k = key;
  return fd_ulong_hash( k->slot );
}

static int
fd_gui_hist_leader_slot_key_cmp( void const * a, void const * b ) {
  fd_gui_hist_leader_slot_key_t const * ka = a;
  fd_gui_hist_leader_slot_key_t const * kb = b;
  if( ka->slot<kb->slot ) return -1;
  if( ka->slot>kb->slot ) return  1;
  if( ka->bank_seq==ULONG_MAX || kb->bank_seq==ULONG_MAX ) return 0;
  if( ka->bank_seq<kb->bank_seq ) return -1;
  if( ka->bank_seq>kb->bank_seq ) return  1;
  return 0;
}

static ulong
fd_gui_hist_epoch_key_hash( void const * key ) {
  fd_gui_hist_epoch_key_t const * k = key;
  return fd_ulong_hash( k->epoch );
}

static int
fd_gui_hist_epoch_key_cmp( void const * a, void const * b ) {
  fd_gui_hist_epoch_key_t const * ka = a;
  fd_gui_hist_epoch_key_t const * kb = b;
  if( ka->epoch<kb->epoch ) return -1;
  if( ka->epoch>kb->epoch ) return  1;
  return 0;
}

static inline ulong
fd_gui_hist_rec_sz( int dbi ) {
  switch( dbi ) {
    case FD_GUI_HIST_SHRED_EVENTS:     return sizeof(fd_gui_slot_history_shred_event_t);
    case FD_GUI_HIST_TILE_TIMERS:      return sizeof(fd_gui_tile_timers_hist_t);
    case FD_GUI_HIST_SCHEDULER_COUNTS: return sizeof(fd_gui_scheduler_counts_t);
    case FD_GUI_HIST_TILE_STATS:       return sizeof(fd_gui_tile_stats_t);
    case FD_GUI_HIST_TXN_WATERFALL:    return sizeof(fd_gui_txn_waterfall_t);
    case FD_GUI_HIST_TXN_START:        return sizeof(fd_gui_store_txn_start_t);
    case FD_GUI_HIST_TXN_END:          return sizeof(fd_gui_store_txn_end_t);
    case FD_GUI_HIST_SLOT:             return sizeof(fd_gui_slot_t);
    case FD_GUI_HIST_LEADER_SLOT:      return sizeof(fd_gui_leader_slot_t);
    case FD_GUI_HIST_EPOCH:            return sizeof(fd_gui_epoch_t);
    /* FD_GUI_HIST_TOWER is declared but not yet written (no record type). */
    default:                           return 0UL;
  }
}

/* fd_gui_hist_key_sz returns the KV key width for `dbi`: 16 bytes
   (slot, bank_seq) for slot-keyed DBs, 8 bytes (epoch) for EPOCH, 0 for TS. */
static inline ulong
fd_gui_hist_key_sz( int dbi ) {
  switch( dbi ) {
    case FD_GUI_HIST_SLOT:        return sizeof(fd_gui_hist_slot_key_t);
    case FD_GUI_HIST_LEADER_SLOT: return sizeof(fd_gui_hist_leader_slot_key_t);
    case FD_GUI_HIST_EPOCH:       return sizeof(fd_gui_hist_epoch_key_t);
    default:                      return 0UL; /* TS DBs have no key */
  }
}

/* fd_gui_hist_key_hash / fd_gui_hist_key_cmp return the per-DB KV key
   callbacks for `dbi` (NULL for TS DBs). */

static inline ulong
( * fd_gui_hist_key_hash( int dbi ) )( void const * key ) {
  switch( dbi ) {
    case FD_GUI_HIST_SLOT:        return fd_gui_hist_slot_key_hash;
    case FD_GUI_HIST_LEADER_SLOT: return fd_gui_hist_leader_slot_key_hash;
    case FD_GUI_HIST_EPOCH:       return fd_gui_hist_epoch_key_hash;
    default:                      return NULL;
  }
}

static inline int
( * fd_gui_hist_key_cmp( int dbi ) )( void const * a, void const * b ) {
  switch( dbi ) {
    case FD_GUI_HIST_SLOT:        return fd_gui_hist_slot_key_cmp;
    case FD_GUI_HIST_LEADER_SLOT: return fd_gui_hist_leader_slot_key_cmp;
    case FD_GUI_HIST_EPOCH:       return fd_gui_hist_epoch_key_cmp;
    default:                      return NULL;
  }
}

/* fd_gui_hist_kv_stride approximates fd_gui_store's per-record ring stride
   for KV DB `dbi`.  The store adds no header (the key and link live inside
   the value), so the stride is just the align-padded record. */
static inline ulong
fd_gui_hist_kv_stride( int dbi ) {
  return fd_ulong_align_up( fd_gui_hist_rec_sz( dbi ), 8UL );
}

static inline ulong
fd_gui_hist_bytes_per_epoch( void ) {
  return fd_gui_hist_kv_stride( FD_GUI_HIST_EPOCH )
       + MAX_SLOTS_PER_EPOCH * ( fd_gui_hist_kv_stride( FD_GUI_HIST_SLOT ) + fd_gui_hist_kv_stride( FD_GUI_HIST_LEADER_SLOT ) );
}

fd_gui_store_desc_t const *
fd_gui_hist_db_descs( ulong store_bytes ) {
  static char const * const names[ FD_GUI_HIST_CNT ] = {
    "scheduler_counts", "tile_timers", "shred_events", "txn_start",
    "txn_end", "tower", "slot", "leader_slot",
    "epoch", "tile_stats", "txn_waterfall"
  };
  static fd_gui_store_desc_t descs[ FD_GUI_HIST_CNT ];
  static ulong built_for = 0UL; /* store_bytes the table was built for (0 = unbuilt) */

  if( FD_UNLIKELY( built_for && built_for!=store_bytes ) )
    FD_LOG_ERR(( "fd_gui_hist_db_descs: called with %lu after %lu", store_bytes, built_for ));

  if( FD_UNLIKELY( !built_for ) ) {
    ulong per_epoch_bytes = fd_gui_hist_bytes_per_epoch();
    ulong epoch_n = fd_ulong_max( FD_GUI_HIST_MIN_EPOCHS, store_bytes / fd_ulong_max( per_epoch_bytes, 1UL ) );

    for( int i=0; i<FD_GUI_HIST_CNT; i++ ) {
      int   ts     = fd_gui_hist_is_timeseries( i );
      ulong rec_sz = fd_gui_hist_rec_sz( i );
      ulong key_sz = ts ? 0UL : fd_gui_hist_key_sz( i ); /* TS DBs have no key (0) */
      ulong val_sz = ts ? fd_ulong_max( rec_sz, 1UL ) : rec_sz;
      ulong max_records = 0UL;
      if( !ts ) {
        max_records = ( fd_gui_hist_keyshape( i )==FD_GUI_HIST_KEYSHAPE_EPOCH ) ? epoch_n : epoch_n * MAX_SLOTS_PER_EPOCH;
      }

      descs[ i ].name        = names[ i ];
      descs[ i ].kind        = ts ? FD_GUI_STORE_KIND_TS : FD_GUI_STORE_KIND_KV;
      descs[ i ].key_off     = 0UL; /* the key is the leading field(s) of the value */
      descs[ i ].key_sz      = key_sz;
      descs[ i ].key_hash    = ts ? NULL : fd_gui_hist_key_hash( i );
      descs[ i ].key_cmp     = ts ? NULL : fd_gui_hist_key_cmp( i );
      descs[ i ].val_sz      = val_sz;
      descs[ i ].val_align   = 8UL;
      descs[ i ].ts_off      = ts ? fd_gui_hist_dbi_ts_off( i ) : 0UL;
      descs[ i ].granularity = ts ? (ulong)fd_gui_hist_dbi_res_ns( i ) : 0UL;
      descs[ i ].max_records = max_records;
    }
    FD_COMPILER_MFENCE();
    built_for = store_bytes;
  }
  return descs;
}

/* ---- space-pressure eviction -----------------------------------------

   Eviction is a small resumable state machine, advanced in small batches
   at an infrequent cadence.  It evicts the oldest epoch as a whole, in
   phases:

     IDLE       -> nothing in progress (the common case)
     SLOT       -> deleting the epoch's (slot,bank_seq) KV rows
     TIMESERIES -> deleting the epoch's TS rows (by wallclock window)
     EPOCH      -> deleting the EPOCH record itself, then -> IDLE

   The trigger is space, not age: eviction happens eagely as utilization
   crosses hysteresis thresholds. */

#define FD_GUI_HIST_EVICT_IDLE       (0)
#define FD_GUI_HIST_EVICT_SLOT       (1)
#define FD_GUI_HIST_EVICT_TIMESERIES (2)
#define FD_GUI_HIST_EVICT_EPOCH      (3)

/* High/low water marks as a fraction (in 1/100ths) of the configured map
   size. */
#define FD_GUI_HIST_EVICT_HIGH_PCT (99UL)
#define FD_GUI_HIST_EVICT_LOW_PCT  (95UL)

/* Maximum number of records deleted per evition iteration. */
#define FD_GUI_HIST_EVICT_BATCH (512UL)

struct fd_gui_hist_private {
  ulong magic;          /* ==FD_GUI_HIST_MAGIC after fd_gui_hist_new */

  struct {
    int   armed;        /* 1 once over the high-water mark, until under low  */
    int   phase;        /* FD_GUI_HIST_EVICT_*                               */
    ulong epoch;        /* epoch being evicted                              */
    ulong start_slot;   /* first slot of the epoch (inclusive)              */
    ulong end_slot;     /* last slot of the epoch (inclusive)               */
    ulong window_hi;    /* last TS window of the epoch (inclusive)  */
    int   have_ts;      /* 1 if the epoch has any TS to evict       */
    int   cur_dbi;      /* DB the current phase is mid-scan on              */
  } evict;

  fd_gui_hist_metrics_t metrics;
};

FD_FN_CONST ulong
fd_gui_hist_align( void ) {
  return 128UL;
}

FD_FN_CONST ulong
fd_gui_hist_footprint( void ) {
  ulong l = FD_LAYOUT_INIT;
  l = FD_LAYOUT_APPEND( l, fd_gui_hist_align(), sizeof(fd_gui_hist_t) );
  return FD_LAYOUT_FINI( l, fd_gui_hist_align() );
}

void *
fd_gui_hist_new( void *                 mem,
                 fd_gui_store_t const * db ) {
  if( FD_UNLIKELY( !mem ) ) { FD_LOG_WARNING(( "fd_gui_hist_new: null mem" )); return NULL; }
  if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)mem, fd_gui_hist_align() ) ) ) { FD_LOG_WARNING(( "fd_gui_hist_new: misaligned mem" )); return NULL; }
  if( FD_UNLIKELY( !db ) ) { FD_LOG_WARNING(( "fd_gui_hist_new: null db" )); return NULL; }

  ulong store_bytes = fd_gui_store_size( db );
  ulong min_bytes   = FD_GUI_HIST_MIN_EPOCHS * fd_gui_hist_bytes_per_epoch() + fd_gui_store_min_overhead_bytes();
  if( FD_UNLIKELY( store_bytes<min_bytes ) ) {
    FD_LOG_WARNING(( "fd_gui_hist_new: store size %lu bytes too small; must be >= %lu bytes", store_bytes, min_bytes ));
    return NULL;
  }

  fd_memset( mem, 0, sizeof(fd_gui_hist_t) );
  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_gui_hist_t * hist = FD_SCRATCH_ALLOC_APPEND( l, fd_gui_hist_align(), sizeof(fd_gui_hist_t) );
  hist->evict.phase = FD_GUI_HIST_EVICT_IDLE;
  FD_SCRATCH_ALLOC_FINI( l, fd_gui_hist_align() );

  FD_COMPILER_MFENCE();
  hist->magic = FD_GUI_HIST_MAGIC;
  FD_COMPILER_MFENCE();
  return mem;
}

fd_gui_hist_t *
fd_gui_hist_join( void * mem ) {
  if( FD_UNLIKELY( !mem ) ) return NULL;
  fd_gui_hist_t * hist = (fd_gui_hist_t *)mem;
  if( FD_UNLIKELY( hist->magic!=FD_GUI_HIST_MAGIC ) ) { FD_LOG_WARNING(( "fd_gui_hist_join: bad magic" )); return NULL; }
  return hist;
}

void *
fd_gui_hist_leave( fd_gui_hist_t * hist ) {
  return (void *)hist;
}

void *
fd_gui_hist_delete( void * mem ) {
  if( FD_UNLIKELY( !mem ) ) return NULL;
  ((fd_gui_hist_t *)mem)->magic = 0UL;
  return mem;
}

static inline fd_gui_hist_t *
fd_gui_hist( fd_gui_t * gui ) {
  return (fd_gui_hist_t *)gui->hist;
}

static inline fd_gui_store_t *
fd_gui_hist_db( fd_gui_t * gui ) {
  return (fd_gui_store_t *)gui->db;
}

static int
fd_gui_hist_reserve_evict_step( fd_gui_t * gui ) {
  if( FD_LIKELY( fd_gui_hist_evict_oldest( gui ) ) ) return 1;
  return fd_gui_hist_evict_ts_oldest( gui );
}

static int
fd_gui_hist_reserve( fd_gui_t * gui, int dbi ) {
  fd_gui_store_t * db = fd_gui_hist_db( gui );
  (void)dbi;
  if( FD_LIKELY( fd_gui_store_free_region_cnt( db )>0UL ) ) return 0; /* fast path: room already */

  int evicted = 0;
  while( fd_gui_store_free_region_cnt( db )==0UL ) {
    if( FD_UNLIKELY( !fd_gui_hist_reserve_evict_step( gui ) ) ) break; /* genuinely full */
    evicted = 1;
  }
  return evicted;
}

static int
fd_gui_hist_map_full_evict_step( fd_gui_t * gui ) {
  return fd_gui_hist_reserve_evict_step( gui );
}

fd_gui_hist_metrics_t const *
fd_gui_hist_metrics( fd_gui_t const * gui ) {
  if( FD_UNLIKELY( !gui->hist ) ) return NULL;
  return &((fd_gui_hist_t const *)gui->hist)->metrics;
}

void *
fd_gui_hist_kv_get_or_create( fd_gui_t *   gui,
                              int          dbi,
                              void const * key ) {
  if( FD_UNLIKELY( fd_gui_hist_is_timeseries( dbi ) ) ) { FD_LOG_WARNING(( "fd_gui_hist_kv_get_or_create: dbi %d is time-series", dbi )); return NULL; }

  int forced_eviction = fd_gui_hist_reserve( gui, dbi );
  void * val = NULL;
  int rc;
  for(;;) {
    rc = fd_gui_store_kv_get_or_create( fd_gui_hist_db( gui ), (ulong)dbi, key, &val );
    if( FD_LIKELY( rc==FD_GUI_STORE_SUCCESS ) ) {
      if( FD_UNLIKELY( forced_eviction ) ) fd_gui_hist( gui )->metrics.reserves[ dbi ]++;
      return val;
    }
    if( FD_LIKELY( rc!=FD_GUI_STORE_MAP_FULL ) ) break;
    if( FD_UNLIKELY( !fd_gui_hist_map_full_evict_step( gui ) ) ) break;
    forced_eviction = 1;
  }
  if( FD_UNLIKELY( rc==FD_GUI_STORE_MAP_FULL ) ) {
    fd_gui_hist( gui )->metrics.map_full[ dbi ]++;
    FD_LOG_WARNING(( "fd_gui_hist_kv_get_or_create: dropping a record for dbi %d; store full and nothing left to evict", dbi ));
  }
  return NULL;
}

int
fd_gui_hist_ts_append( fd_gui_t *   gui,
                       int          dbi,
                       long         now,
                       long         ts_ns,
                       void const * val ) {
  if( FD_UNLIKELY( dbi<0 || dbi>=FD_GUI_HIST_CNT ) ) { FD_LOG_WARNING(( "fd_gui_hist_ts_append: bad dbi %d", dbi )); return -1; }
  if( FD_UNLIKELY( !fd_gui_hist_is_timeseries( dbi ) ) ) { FD_LOG_WARNING(( "fd_gui_hist_ts_append: dbi %d is not time-series", dbi )); return -1; }
  fd_gui_store_t * db = fd_gui_hist_db( gui );

  ulong rec_sz = fd_gui_hist_rec_sz( dbi );
  if( FD_UNLIKELY( !rec_sz ) ) { FD_LOG_WARNING(( "fd_gui_hist_ts_append: dbi %d has no record type", dbi )); return -1; }

  /* Clamp the record's timestamp to a bounded skew around `now` and
     write the clamped value back into the record. */
  long clamped_ts = fd_long_max( now-FD_GUI_HIST_TS_SKEW_NS, fd_long_min( ts_ns, now+FD_GUI_HIST_TS_SKEW_NS ) );

  uchar buf[ FD_GUI_HIST_TS_SZ_MAX ];
  if( FD_UNLIKELY( rec_sz>sizeof(buf) ) ) { FD_LOG_WARNING(( "fd_gui_hist_ts_append: dbi %d record too large (%lu)", dbi, rec_sz )); return -1; }
  fd_memcpy( buf, val, rec_sz );
  *(long *)( buf + fd_gui_hist_dbi_ts_off( dbi ) ) = clamped_ts;

  /* Reserve space ahead of the append. */
  int forced_eviction = fd_gui_hist_reserve( gui, dbi );
  int rc;
  for(;;) {
    rc = fd_gui_store_ts_append( db, (ulong)dbi, buf );
    if( FD_LIKELY( rc==FD_GUI_STORE_SUCCESS ) ) {
      if( FD_UNLIKELY( forced_eviction ) ) fd_gui_hist( gui )->metrics.reserves[ dbi ]++;
      return 0;
    }
    if( FD_LIKELY( rc!=FD_GUI_STORE_MAP_FULL ) ) break;
    if( FD_UNLIKELY( !fd_gui_hist_map_full_evict_step( gui ) ) ) break;
    forced_eviction = 1;
  }
  if( FD_UNLIKELY( rc==FD_GUI_STORE_MAP_FULL ) ) {
    fd_gui_hist( gui )->metrics.map_full[ dbi ]++;
    FD_LOG_WARNING(( "fd_gui_hist_ts_append: dropping a record for dbi %d; store full and nothing left to evict", dbi ));
  }
  return -1;
}


static void
fd_gui_hist_iter_load( fd_gui_hist_iter_t * iter ) {
  for(;;) {
    if( fd_gui_store_ts_scan_done( &iter->_it ) ) { iter->rec = NULL; return; }
    void const * rec = iter->_it.rec; /* the gui record verbatim; self-describing */
    if( !iter->_filter || iter->_filter( rec, iter->_filter_ctx ) ) {
      iter->rec = rec;
      return;
    }
    fd_gui_store_ts_scan_next( &iter->_it );
  }
}

int
fd_gui_hist_range_begin( fd_gui_t *                   gui,
                         fd_gui_hist_iter_t *         iter,
                         int                          dbi,
                         long                         lo_ns,
                         long                         hi_ns,
                         fd_gui_hist_range_filter_fn  filter,
                         void *                       filter_ctx ) {
  fd_gui_store_t * db = fd_gui_hist_db( gui );
  memset( iter, 0, sizeof(fd_gui_hist_iter_t) );

  if( FD_UNLIKELY( !fd_gui_hist_is_timeseries( dbi ) ) ) { FD_LOG_WARNING(( "fd_gui_hist_range_begin: dbi %d is not time-series", dbi )); return -1; }

  FD_TEST( lo_ns!=LONG_MIN && hi_ns!=LONG_MAX ); /* open-ended queries not supported */

  long res_ns = fd_gui_hist_dbi_res_ns( dbi );
  ulong window_lo = (lo_ns<=0L) ? 0UL : fd_gui_hist_window( lo_ns, res_ns );
  ulong window_hi = fd_gui_hist_window( hi_ns, res_ns );

  iter->_dbi        = dbi;
  iter->rec_sz      = fd_gui_hist_rec_sz( dbi );
  iter->_filter     = filter;
  iter->_filter_ctx = filter_ctx;

  fd_gui_store_ts_scan_begin( db, &iter->_it, (ulong)dbi, window_lo, window_hi, NULL, NULL );
  fd_gui_hist_iter_load( iter );
  return 0;
}

int
fd_gui_hist_range_next( fd_gui_hist_iter_t * iter ) {
  if( FD_UNLIKELY( !iter->rec ) ) return 0;
  if( iter->_emitted ) {
    fd_gui_store_ts_scan_next( &iter->_it );
    fd_gui_hist_iter_load( iter );
    if( !iter->rec ) return 0;
  }
  iter->_emitted = 1;
  return 1;
}

void
fd_gui_hist_range_end( fd_gui_hist_iter_t * iter ) {
  fd_gui_store_ts_scan_end( &iter->_it );
}

void *
fd_gui_hist_kv_get( fd_gui_t *   gui,
                    int          dbi,
                    void const * key ) {
  if( FD_UNLIKELY( fd_gui_hist_is_timeseries( dbi ) ) ) { FD_LOG_WARNING(( "fd_gui_hist_meta_get: dbi %d is time-series", dbi )); return NULL; }
  return fd_gui_store_kv_get( fd_gui_hist_db( gui ), (ulong)dbi, key );
}

void *
fd_gui_hist_kv_get_slot_any( fd_gui_t * gui,
                             int        dbi,
                             ulong      slot ) {
  if( FD_UNLIKELY( fd_gui_hist_keyshape( dbi )!=FD_GUI_HIST_KEYSHAPE_SLOT_BANK ) ) {
    FD_LOG_WARNING(( "fd_gui_hist_kv_get_slot_any: dbi %d is not slot/bank-keyed", dbi ));
    return NULL;
  }

  fd_gui_hist_slot_key_t key = { .slot=slot, .bank_seq=ULONG_MAX };
  return fd_gui_store_kv_get_any( fd_gui_hist_db( gui ), (ulong)dbi, &key );
}

/* fd_gui_hist_ts_iter_load reads the iterator's current backend record into
   the typed iterator fields (or marks it done). */
static void
fd_gui_hist_ts_iter_load( fd_gui_hist_kv_slot_iter_t * iter ) {
  if( FD_UNLIKELY( fd_gui_store_kv_iter_done( &iter->_it ) ) ) {
    iter->rec      = NULL;
    iter->bank_seq = ULONG_MAX;
    return;
  }
  iter->rec      = iter->_it.rec;
  iter->bank_seq = ( iter->_it.key_sz>=2UL*sizeof(ulong) )
                 ? ((ulong const *)iter->_it.key)[ 1 ]
                 : ULONG_MAX;
}

fd_gui_hist_kv_slot_iter_t *
fd_gui_hist_kv_iter_begin( fd_gui_t *                   gui,
                           fd_gui_hist_kv_slot_iter_t * iter,
                           int                          dbi,
                           ulong                        slot ) {
  iter->rec      = NULL;
  iter->bank_seq = ULONG_MAX;
  if( FD_UNLIKELY( fd_gui_hist_keyshape( dbi )!=FD_GUI_HIST_KEYSHAPE_SLOT_BANK ) ) {
    FD_LOG_WARNING(( "fd_gui_hist_kv_iter_begin: dbi %d is not slot/bank-keyed", dbi ));
    fd_gui_hist_slot_key_t none = { .slot=ULONG_MAX, .bank_seq=ULONG_MAX };
    fd_gui_store_kv_iter_begin( fd_gui_hist_db( gui ), &iter->_it, (ulong)dbi, &none );
    return iter;
  }
  fd_gui_hist_slot_key_t key = { .slot=slot, .bank_seq=ULONG_MAX };
  fd_gui_store_kv_iter_begin( fd_gui_hist_db( gui ), &iter->_it, (ulong)dbi, &key );
  fd_gui_hist_ts_iter_load( iter );
  return iter;
}

int
fd_gui_hist_kv_iter_next( fd_gui_hist_kv_slot_iter_t * iter ) {
  if( FD_UNLIKELY( !iter->rec ) ) return 0;
  fd_gui_store_kv_iter_next( &iter->_it );
  fd_gui_hist_ts_iter_load( iter );
  return iter->rec!=NULL;
}

/* fd_gui_hist_evict_used_pct returns the store's high-water-mark fill level
   as a percentage (0..100) of its configured map size. */

static ulong
fd_gui_hist_evict_used_pct( fd_gui_t * gui ) {
  fd_gui_store_t * db = fd_gui_hist_db( gui );
  ulong size = fd_gui_store_size( db );
  if( FD_UNLIKELY( !size ) ) return 0UL;
  return ( fd_gui_store_used_bytes( db ) * 100UL ) / size;
}

/* fd_gui_hist_evict_slot_completed_window returns, in *out_window, the
   wallclock window (floored completion time) of the lowest-bank_seq
   SLOT record for `slot`, or 0 if there is no such record (or it
   has no completion time).  Used to bound the TS eviction window.
   Returns 1 on success. */

static int
fd_gui_hist_evict_slot_completed_window( fd_gui_t * gui,
                                         ulong      slot,
                                         ulong *    out_window ) {
  fd_gui_slot_t const * rmeta = fd_gui_hist_kv_get_slot_any( gui, FD_GUI_HIST_SLOT, slot );
  if( FD_UNLIKELY( !rmeta ) ) return 0;
  if( FD_UNLIKELY( rmeta->completed_time==LONG_MAX ) ) return 0;
  *out_window = fd_gui_hist_window( rmeta->completed_time, FD_GUI_HIST_RES_1S_NS );
  return 1;
}

/* fd_gui_hist_evict_begin sets up an eviction cascade for the oldest epoch.
   Returns 1 if a cascade was armed (state populated, phase advanced past
   IDLE), 0 if there is nothing to evict. */

static int
fd_gui_hist_evict_begin( fd_gui_t * gui ) {
  fd_gui_hist_t * hist = fd_gui_hist( gui );

  /* Make sure we always keep the current/next epoch. */
  if( FD_UNLIKELY( gui->epoch.stored_epoch_cnt<FD_GUI_HIST_MIN_EPOCHS ) ) return 0;

  fd_gui_epoch_t const * meta = fd_gui_store_kv_get_any( fd_gui_hist_db( gui ), (ulong)FD_GUI_HIST_EPOCH, NULL );
  if( FD_UNLIKELY( !meta ) ) return 0;
  ulong epoch      = meta->epoch;
  ulong meta_start = meta->start_slot;
  ulong meta_cnt   = meta->slot_cnt;
  ulong start_slot = meta_start;
  ulong end_slot   = meta_start + meta_cnt - 1UL;
  ulong next_start = meta_start + meta_cnt; /* next epoch's first slot; always valid (>= FD_GUI_HIST_MIN_EPOCHS resident) */

  ulong window_hi = 0UL;
  int   have_ts   = 0;
  ulong next_window;
  if( FD_LIKELY( fd_gui_hist_evict_slot_completed_window( gui, next_start, &next_window ) ) ) {
    window_hi = ( next_window>0UL ) ? ( next_window-1UL ) : 0UL;
    have_ts   = next_window>0UL;
  }

  hist->evict.epoch      = epoch;
  hist->evict.start_slot = start_slot;
  hist->evict.end_slot   = end_slot;
  hist->evict.window_hi  = window_hi;
  hist->evict.have_ts    = have_ts;
  hist->evict.phase      = FD_GUI_HIST_EVICT_SLOT;
  hist->evict.cur_dbi    = FD_GUI_HIST_SLOT;
  return 1;
}

/* fd_gui_hist_evict_slot_batch advances KV DB `dbi`'s watermark to
   evict the (slot,bank_seq) rows with slot <= end_slot, decrementing
   *budget per reclaimed row.  Returns 1 if the DB's range is fully
   drained, 0 if it stopped because the budget ran out. */

static int
fd_gui_hist_evict_slot_batch( fd_gui_t * gui,
                              int        dbi,
                              ulong      end_slot,
                              ulong *    budget ) {
  fd_gui_hist_slot_key_t hi = { .slot=end_slot+1UL, .bank_seq=0UL };
  int drained = 1;
  fd_gui_store_kv_evict( fd_gui_hist_db( gui ), (ulong)dbi, &hi, budget, &drained );
  return drained;
}

/* fd_gui_hist_evict_ts_batch advances TS DB `dbi`'s watermark to evict
   rows with window <= window_hi, decrementing *budget per reclaimed row.
   Returns 1 if drained, 0 if it stopped on the budget. */

static int
fd_gui_hist_evict_ts_batch( fd_gui_t * gui,
                            int        dbi,
                            ulong      window_hi,
                            ulong *    budget ) {
  int drained = 1;
  fd_gui_store_ts_evict( fd_gui_hist_db( gui ), (ulong)dbi, window_hi+1UL, budget, &drained );
  return drained;
}

/* fd_gui_hist_evict_one advances an in-progress cascade by one bounded batch.
   Returns 1 (it always does work, or
   resolves the cascade, when not IDLE). */

static int
fd_gui_hist_evict_one( fd_gui_t * gui ) {
  fd_gui_hist_t * hist   = fd_gui_hist( gui );
  ulong           budget = FD_GUI_HIST_EVICT_BATCH;

  switch( hist->evict.phase ) {

  case FD_GUI_HIST_EVICT_SLOT: {
    int drained = fd_gui_hist_evict_slot_batch( gui, hist->evict.cur_dbi, hist->evict.end_slot, &budget );
    if( !drained ) return 1; /* budget spent on this DB; resume next step */
    /* advance to the next slot-keyed KV DB, or to the TS phase */
    if( hist->evict.cur_dbi==FD_GUI_HIST_SLOT ) {
      hist->evict.cur_dbi = FD_GUI_HIST_LEADER_SLOT;
    } else {
      hist->evict.phase   = FD_GUI_HIST_EVICT_TIMESERIES;
      hist->evict.cur_dbi = 0; /* fd_gui_hist_evict_one finds the first TS DB below */
    }
    return 1;
  }

  case FD_GUI_HIST_EVICT_TIMESERIES: {
    /* skip non-TS DBs (the KV DBs interleave by index) */
    while( hist->evict.cur_dbi<FD_GUI_HIST_CNT && !fd_gui_hist_is_timeseries( hist->evict.cur_dbi ) ) hist->evict.cur_dbi++;
    if( hist->evict.cur_dbi>=FD_GUI_HIST_CNT || !hist->evict.have_ts ) {
      hist->evict.phase = FD_GUI_HIST_EVICT_EPOCH;
      return 1;
    }
    int drained = fd_gui_hist_evict_ts_batch( gui, hist->evict.cur_dbi, hist->evict.window_hi, &budget );
    if( !drained ) return 1;
    hist->evict.cur_dbi++; /* next step picks up the next TS DB (or the EPOCH phase) */
    return 1;
  }

  case FD_GUI_HIST_EVICT_EPOCH: {
    fd_gui_hist_epoch_key_t hi = { .epoch=hist->evict.epoch+1UL };

    fd_gui_store_t * db      = fd_gui_hist_db( gui );
    int           drained = 1;
    fd_gui_store_kv_evict( db, (ulong)FD_GUI_HIST_EPOCH, &hi, &budget, &drained );
    if( !drained ) return 1; /* budget spent; resume this phase next step */
    if( FD_LIKELY( gui->epoch.stored_epoch_cnt ) ) gui->epoch.stored_epoch_cnt--;

    hist->evict.phase = FD_GUI_HIST_EVICT_IDLE; /* cascade complete */
    return 1;
  }

  default:
    hist->evict.phase = FD_GUI_HIST_EVICT_IDLE;
    return 0;
  }
}

int
fd_gui_hist_evict_step( fd_gui_t * gui ) {
  if( FD_UNLIKELY( !gui->db || !gui->hist ) ) return 0;
  fd_gui_hist_t * hist = fd_gui_hist( gui );

  if( hist->evict.phase==FD_GUI_HIST_EVICT_IDLE ) {
    ulong used_pct = fd_gui_hist_evict_used_pct( gui );
    if( used_pct>=FD_GUI_HIST_EVICT_HIGH_PCT ) hist->evict.armed = 1;
    else if( used_pct<FD_GUI_HIST_EVICT_LOW_PCT ) hist->evict.armed = 0;
    if( !hist->evict.armed ) return 0;
    if( FD_UNLIKELY( !fd_gui_hist_evict_begin( gui ) ) ) { hist->evict.armed = 0; return 0; } /* nothing to evict */
    return 1;
  }

  return fd_gui_hist_evict_one( gui );
}

int
fd_gui_hist_evict_oldest( fd_gui_t * gui ) {
  fd_gui_hist_t * hist = fd_gui_hist( gui );
  if( FD_UNLIKELY( !gui->db || !gui->hist ) ) return 0;
  if( hist->evict.phase==FD_GUI_HIST_EVICT_IDLE && FD_UNLIKELY( !fd_gui_hist_evict_begin( gui ) ) ) return 0;
  while( hist->evict.phase!=FD_GUI_HIST_EVICT_IDLE ) fd_gui_hist_evict_one( gui );
  return 1;
}

/* fd_gui_hist_ts_oldest_window finds the oldest live window across all
   TS DBs (the global minimum of each DB's oldest live record's window).
   Stores it in *out_window and returns 1 if any TS record exists, 0 if
   every TS DB is empty.  O(1) per DB: no scan. */

static int
fd_gui_hist_ts_oldest_window( fd_gui_t * gui,
                              ulong *    out_window ) {
  fd_gui_store_t * db     = fd_gui_hist_db( gui );
  ulong            oldest = ULONG_MAX;
  int              found  = 0;
  for( int dbi=0; dbi<FD_GUI_HIST_CNT; dbi++ ) {
    if( !fd_gui_hist_is_timeseries( dbi ) ) continue;
    ulong window;
    if( fd_gui_store_ts_oldest_window( db, (ulong)dbi, &window ) ) {
      found  = 1;
      oldest = fd_ulong_min( oldest, window );
    }
  }
  if( FD_UNLIKELY( !found ) ) return 0;
  *out_window = oldest;
  return 1;
}

int
fd_gui_hist_evict_ts_oldest( fd_gui_t * gui ) {
  if( FD_UNLIKELY( !gui->db || !gui->hist ) ) return 0;

  ulong oldest;
  if( FD_UNLIKELY( !fd_gui_hist_ts_oldest_window( gui, &oldest ) ) ) return 0; /* no TS data left */

  for( int dbi=0; dbi<FD_GUI_HIST_CNT; dbi++ ) {
    if( !fd_gui_hist_is_timeseries( dbi ) ) continue;
    ulong budget  = ULONG_MAX;
    int   drained = 1;
    fd_gui_store_ts_evict( fd_gui_hist_db( gui ), (ulong)dbi, oldest+1UL, &budget, &drained );
  }
  return 1;
}
