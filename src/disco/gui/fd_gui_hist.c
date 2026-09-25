#include "fd_gui_hist.h"
#include "fd_gui_store.h"
#include "fd_gui_shred.h"
#include "fd_gui.h" /* fd_gui_t, record types */

#include <stddef.h> /* offsetof */

/* Every record type must fit in one store region (header + record). */
FD_STATIC_ASSERT( sizeof(fd_gui_shred_batch_t     )<=FD_GUI_STORE_MAX_REC_SZ, rec_fits );
FD_STATIC_ASSERT( sizeof(fd_gui_fec_completion_record_t  )<=FD_GUI_STORE_MAX_REC_SZ, rec_fits );
FD_STATIC_ASSERT( sizeof(fd_gui_fec_event_t              )<=FD_GUI_STORE_MAX_REC_SZ, rec_fits );
FD_STATIC_ASSERT( sizeof(fd_gui_store_replay_txn_batch_t  )<=FD_GUI_STORE_MAX_REC_SZ, rec_fits );
FD_STATIC_ASSERT( sizeof(fd_gui_tile_timers_hist_t)<=FD_GUI_STORE_MAX_REC_SZ, rec_fits );
FD_STATIC_ASSERT( sizeof(fd_gui_scheduler_counts_t)<=FD_GUI_STORE_MAX_REC_SZ, rec_fits );
FD_STATIC_ASSERT( sizeof(fd_gui_tile_stats_t      )<=FD_GUI_STORE_MAX_REC_SZ, rec_fits );
FD_STATIC_ASSERT( sizeof(fd_gui_txn_waterfall_t   )<=FD_GUI_STORE_MAX_REC_SZ, rec_fits );
FD_STATIC_ASSERT( sizeof(fd_gui_store_txn_start_t )<=FD_GUI_STORE_MAX_REC_SZ, rec_fits );
FD_STATIC_ASSERT( sizeof(fd_gui_store_txn_end_t   )<=FD_GUI_STORE_MAX_REC_SZ, rec_fits );
FD_STATIC_ASSERT( sizeof(fd_gui_store_replay_txn_t)<=FD_GUI_STORE_MAX_REC_SZ, rec_fits );
FD_STATIC_ASSERT( sizeof(fd_gui_slot_t            )<=FD_GUI_STORE_MAX_REC_SZ, rec_fits );
FD_STATIC_ASSERT( sizeof(fd_gui_leader_slot_t     )<=FD_GUI_STORE_MAX_REC_SZ, rec_fits );
FD_STATIC_ASSERT( sizeof(fd_gui_epoch_t           )<=FD_GUI_STORE_MAX_REC_SZ, rec_fits );
FD_STATIC_ASSERT( sizeof(fd_gui_timeline_day_t    )<=FD_GUI_STORE_MAX_REC_SZ, rec_fits );
FD_STATIC_ASSERT( sizeof(fd_gui_store_slot_duration_t)<=FD_GUI_STORE_MAX_REC_SZ, rec_fits );
FD_STATIC_ASSERT( sizeof(fd_gui_store_slot_duration_t)==32UL, slot_duration_size );

/* Each key type must alias the matching record field exactly. */
FD_STATIC_ASSERT( offsetof( fd_gui_hist_slot_key_t,        slot     )==offsetof( fd_gui_slot_t,        slot     ), key_layout );
FD_STATIC_ASSERT( offsetof( fd_gui_hist_slot_key_t,        bank_seq )==offsetof( fd_gui_slot_t,        bank_seq ), key_layout );
FD_STATIC_ASSERT( offsetof( fd_gui_hist_leader_slot_key_t, slot     )==offsetof( fd_gui_leader_slot_t, slot     ), key_layout );
FD_STATIC_ASSERT( offsetof( fd_gui_hist_leader_slot_key_t, bank_seq )==offsetof( fd_gui_leader_slot_t, bank_seq ), key_layout );
FD_STATIC_ASSERT( offsetof( fd_gui_hist_epoch_key_t,       epoch    )==offsetof( fd_gui_epoch_t,       epoch    ), key_layout );

#define FD_GUI_HIST_KEYSHAPE_TIMESERIES (0) /* (ts, ...)        */
#define FD_GUI_HIST_KEYSHAPE_SLOT_BANK  (1) /* (slot, bank_seq) */
#define FD_GUI_HIST_KEYSHAPE_EPOCH      (2) /* (epoch)          */
#define FD_GUI_HIST_KEYSHAPE_FEC        (3) /* (16-byte FEC key) */

static inline long
fd_gui_hist_dbi_res_ns( int dbi FD_PARAM_UNUSED ) {
  return FD_GUI_HIST_RES_1S_NS; /* all TS DBs use the 1s resolution */
}

static inline ulong
fd_gui_hist_dbi_ts_off( int dbi ) {
  switch( dbi ) {
    case FD_GUI_HIST_SHRED_EVENTS:     return offsetof( fd_gui_shred_batch_t,      insert_time_ns    );
    case FD_GUI_HIST_TILE_TIMERS:      return offsetof( fd_gui_tile_timers_hist_t, sample_time_nanos );
    case FD_GUI_HIST_SCHEDULER_COUNTS: return offsetof( fd_gui_scheduler_counts_t, sample_time_ns    );
    case FD_GUI_HIST_TILE_STATS:       return offsetof( fd_gui_tile_stats_t,       sample_time_nanos );
    case FD_GUI_HIST_TXN_WATERFALL:    return offsetof( fd_gui_txn_waterfall_t,    sample_time_nanos );
    case FD_GUI_HIST_TXN_START:        return offsetof( fd_gui_store_txn_start_t,  insert_time_ns    );
    case FD_GUI_HIST_TXN_END:          return offsetof( fd_gui_store_txn_end_t,    insert_time_ns    );
    case FD_GUI_HIST_REPLAY_TXN:       return offsetof( fd_gui_store_replay_txn_t, insert_time_ns    );
    case FD_GUI_HIST_REPLAY_TXN_BATCH:  return offsetof( fd_gui_store_replay_txn_batch_t, insert_time_ns );
    case FD_GUI_HIST_TIMELINE_DAY:     return offsetof( fd_gui_timeline_day_t,     end_time_ns       );
    case FD_GUI_HIST_SLOT_DURATION:    return offsetof( fd_gui_store_slot_duration_t, insert_time_ns );
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
    case FD_GUI_HIST_REPLAY_TXN:
    case FD_GUI_HIST_REPLAY_TXN_BATCH:
    case FD_GUI_HIST_SLOT_DURATION:
    case FD_GUI_HIST_TIMELINE_DAY:     return FD_GUI_HIST_KEYSHAPE_TIMESERIES;
    case FD_GUI_HIST_SLOT:
    case FD_GUI_HIST_LEADER_SLOT:      return FD_GUI_HIST_KEYSHAPE_SLOT_BANK;
    case FD_GUI_HIST_EPOCH:            return FD_GUI_HIST_KEYSHAPE_EPOCH;
    case FD_GUI_HIST_FEC_EVENTS:
    case FD_GUI_HIST_FEC_COMPLETIONS:  return FD_GUI_HIST_KEYSHAPE_FEC;
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

static ulong
fd_gui_hist_fec_key_hash( void const * key ) {
  ulong words[ 2 ];
  memcpy( words, key, sizeof(words) );
  return fd_ulong_hash( words[ 0 ] ) ^ fd_ulong_hash( words[ 1 ] );
}

static int
fd_gui_hist_fec_key_cmp( void const * a,
                         void const * b ) {
  return memcmp( a, b, sizeof(fd_gui_fec_event_key_t) );
}

static inline ulong
fd_gui_hist_rec_sz( int dbi ) {
  switch( dbi ) {
    case FD_GUI_HIST_SHRED_EVENTS:     return sizeof(fd_gui_shred_batch_t);
    case FD_GUI_HIST_TILE_TIMERS:      return sizeof(fd_gui_tile_timers_hist_t);
    case FD_GUI_HIST_SCHEDULER_COUNTS: return sizeof(fd_gui_scheduler_counts_t);
    case FD_GUI_HIST_TILE_STATS:       return sizeof(fd_gui_tile_stats_t);
    case FD_GUI_HIST_TXN_WATERFALL:    return sizeof(fd_gui_txn_waterfall_t);
    case FD_GUI_HIST_TXN_START:        return sizeof(fd_gui_store_txn_start_t);
    case FD_GUI_HIST_TXN_END:          return sizeof(fd_gui_store_txn_end_t);
    case FD_GUI_HIST_REPLAY_TXN:       return sizeof(fd_gui_store_replay_txn_t);
    case FD_GUI_HIST_REPLAY_TXN_BATCH:  return sizeof(fd_gui_store_replay_txn_batch_t);
    case FD_GUI_HIST_FEC_EVENTS:       return sizeof(fd_gui_fec_event_t);
    case FD_GUI_HIST_FEC_COMPLETIONS:  return sizeof(fd_gui_fec_completion_record_t);
    case FD_GUI_HIST_SLOT:             return sizeof(fd_gui_slot_t);
    case FD_GUI_HIST_LEADER_SLOT:      return sizeof(fd_gui_leader_slot_t);
    case FD_GUI_HIST_EPOCH:            return sizeof(fd_gui_epoch_t);
    case FD_GUI_HIST_TIMELINE_DAY:     return sizeof(fd_gui_timeline_day_t);
    case FD_GUI_HIST_SLOT_DURATION:    return sizeof(fd_gui_store_slot_duration_t);
    /* FD_GUI_HIST_TOWER is declared but not yet written (no record type). */
    default:                           return 0UL;
  }
}

/* fd_gui_hist_key_sz returns the KV key width for `dbi`: 16 bytes
   (slot, bank_seq) for slot-keyed DBs, 8 bytes for EPOCH, 0 for TS. */
static inline ulong
fd_gui_hist_key_sz( int dbi ) {
  switch( dbi ) {
    case FD_GUI_HIST_SLOT:        return sizeof(fd_gui_hist_slot_key_t);
    case FD_GUI_HIST_LEADER_SLOT: return sizeof(fd_gui_hist_leader_slot_key_t);
    case FD_GUI_HIST_EPOCH:       return sizeof(fd_gui_hist_epoch_key_t);
    case FD_GUI_HIST_FEC_EVENTS:
    case FD_GUI_HIST_FEC_COMPLETIONS: return sizeof(fd_gui_fec_event_key_t);
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
    case FD_GUI_HIST_FEC_EVENTS:
    case FD_GUI_HIST_FEC_COMPLETIONS: return fd_gui_hist_fec_key_hash;
    default:                      return NULL;
  }
}

static inline int
( * fd_gui_hist_key_cmp( int dbi ) )( void const * a, void const * b ) {
  switch( dbi ) {
    case FD_GUI_HIST_SLOT:        return fd_gui_hist_slot_key_cmp;
    case FD_GUI_HIST_LEADER_SLOT: return fd_gui_hist_leader_slot_key_cmp;
    case FD_GUI_HIST_EPOCH:       return fd_gui_hist_epoch_key_cmp;
    case FD_GUI_HIST_FEC_EVENTS:
    case FD_GUI_HIST_FEC_COMPLETIONS: return fd_gui_hist_fec_key_cmp;
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

fd_gui_store_desc_t const *
fd_gui_hist_db_descs( ulong store_bytes ) {
  static char const * const names[ FD_GUI_HIST_CNT ] = {
    "scheduler_counts", "tile_timers", "shred_events", "txn_start",
    "txn_end", "tower", "slot", "leader_slot", "epoch", "tile_stats",
    "txn_waterfall", "timeline_day", "replay_txn", "replay_txn_batch", "fec_events", "fec_completions", "slot_duration"
  };
  static fd_gui_store_desc_t descs[ FD_GUI_HIST_CNT ];
  static ulong built_for = 0UL; /* store_bytes the table was built for (0 = unbuilt) */

  if( FD_UNLIKELY( built_for && built_for!=store_bytes ) )
    FD_LOG_ERR(( "fd_gui_hist_db_descs: called with %lu after %lu", store_bytes, built_for ));

  if( FD_UNLIKELY( !built_for ) ) {
    ulong shared = fd_ulong_sat_sub( store_bytes, fd_gui_store_min_size( FD_GUI_HIST_CNT ) ) / FD_GUI_STORE_REGION_SZ;

    for( int i=0; i<FD_GUI_HIST_CNT; i++ ) {
      int   ts     = fd_gui_hist_is_timeseries( i );
      ulong rec_sz = fd_gui_hist_rec_sz( i );
      ulong key_sz = ts ? 0UL : fd_gui_hist_key_sz( i ); /* TS DBs have no key (0) */
      ulong val_sz = ts ? fd_ulong_max( rec_sz, 1UL ) : rec_sz;
      ulong max_records = 0UL;
      if( !ts ) {
        int shape = fd_gui_hist_keyshape( i );
        if(      shape==FD_GUI_HIST_KEYSHAPE_FEC   ) max_records = FD_GUI_FEC_RECORD_MAX;
        else {
          ulong cap   = FD_GUI_STORE_REGION_SZ / fd_gui_hist_kv_stride( i );
          ulong base  = FD_GUI_STORE_BASE_REGIONS*cap;
          ulong limit = shape==FD_GUI_HIST_KEYSHAPE_EPOCH ? FD_GUI_HIST_MAX_EPOCHS
                      : FD_GUI_HIST_MAX_EPOCHS*(i==FD_GUI_HIST_LEADER_SLOT ? FD_GUI_HIST_MAX_LEADER_SLOTS_PER_EPOCH : MAX_SLOTS_PER_EPOCH);
          max_records = fd_ulong_max( base, fd_ulong_min( (FD_GUI_STORE_BASE_REGIONS+shared)*cap, limit ) );
        }
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

/* Maximum number of records deleted per eviction iteration. */
#define FD_GUI_HIST_EVICT_BATCH (512UL)

struct fd_gui_hist_private {
  ulong magic;          /* ==FD_GUI_HIST_MAGIC after fd_gui_hist_new */
  long  last_ts[ FD_GUI_HIST_CNT ];
  int   has_last_ts[ FD_GUI_HIST_CNT ];

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
  ulong min_bytes   = fd_gui_store_min_size( FD_GUI_HIST_CNT );
  if( FD_UNLIKELY( store_bytes<min_bytes ) ) {
    FD_LOG_WARNING(( "fd_gui_hist_new: store size %lu bytes too small; must be >= %lu bytes", store_bytes, min_bytes ));
    return NULL;
  }

  fd_memset( mem, 0, sizeof(fd_gui_hist_t) );
  FD_SCRATCH_ALLOC_INIT( l, mem );
  fd_gui_hist_t * hist = FD_SCRATCH_ALLOC_APPEND( l, fd_gui_hist_align(), sizeof(fd_gui_hist_t) );
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

fd_gui_hist_metrics_t const *
fd_gui_hist_metrics( fd_gui_t const * gui ) {
  if( FD_UNLIKELY( !gui->hist ) ) return NULL;
  return &((fd_gui_hist_t const *)gui->hist)->metrics;
}

static int
fd_gui_hist_reclaim_eligible( ulong        dbi,
                              void const * rec,
                              void *       ctx ) {
  if( dbi==FD_GUI_HIST_FEC_EVENTS )
    return fd_gui_event_slot_permanently_closed( ctx, ((fd_gui_fec_event_t const *)rec)->key.slot );
  if( dbi==FD_GUI_HIST_FEC_COMPLETIONS )
    return fd_gui_event_slot_permanently_closed( ctx, ((fd_gui_fec_completion_record_t const *)rec)->key.slot );
  return 1;
}

static int
fd_gui_hist_make_room( fd_gui_t * gui,
                       int        dbi,
                       int        rc ) {
  if( rc!=FD_GUI_STORE_MAP_FULL && rc!=FD_GUI_STORE_RING_FULL ) return 0;
  if( rc==FD_GUI_STORE_MAP_FULL && fd_gui_store_reclaim( gui->db, ULONG_MAX, FD_GUI_HIST_EVICT_BATCH, fd_gui_hist_reclaim_eligible, gui ) ) return 1;
  return !!fd_gui_store_reclaim( gui->db, (ulong)dbi, FD_GUI_HIST_EVICT_BATCH, fd_gui_hist_reclaim_eligible, gui );
}

void *
fd_gui_hist_kv_get_or_create( fd_gui_t *   gui,
                              int          dbi,
                              void const * key ) {
  if( FD_UNLIKELY( fd_gui_hist_is_timeseries( dbi ) ) ) { FD_LOG_WARNING(( "fd_gui_hist_kv_get_or_create: dbi %d is time-series", dbi )); return NULL; }

  int forced_eviction = 0;
  void * val = NULL;
  int rc;
  for(;;) {
    rc = fd_gui_store_kv_get_or_create( fd_gui_hist_db( gui ), (ulong)dbi, key, &val );
    if( FD_LIKELY( rc==FD_GUI_STORE_SUCCESS ) ) {
      if( FD_UNLIKELY( forced_eviction ) ) fd_gui_hist( gui )->metrics.reserves[ dbi ]++;
      return val;
    }
    if( FD_UNLIKELY( !fd_gui_hist_make_room( gui, dbi, rc ) ) ) break;
    forced_eviction = 1;
  }
  if( FD_UNLIKELY( rc==FD_GUI_STORE_MAP_FULL || rc==FD_GUI_STORE_RING_FULL ) ) {
    fd_gui_hist( gui )->metrics.map_full[ dbi ]++;
  }
  return NULL;
}

void *
fd_gui_hist_ts_emplace( fd_gui_t * gui,
                        int        dbi,
                        long       stored_ts ) {
  if( FD_UNLIKELY( dbi<0 || dbi>=FD_GUI_HIST_CNT ) ) { FD_LOG_WARNING(( "fd_gui_hist_ts_append: bad dbi %d", dbi )); return NULL; }
  if( FD_UNLIKELY( !fd_gui_hist_is_timeseries( dbi ) ) ) { FD_LOG_WARNING(( "fd_gui_hist_ts_append: dbi %d is not time-series", dbi )); return NULL; }
  fd_gui_store_t * db = fd_gui_hist_db( gui );

  ulong rec_sz = fd_gui_hist_rec_sz( dbi );
  if( FD_UNLIKELY( !rec_sz ) ) { FD_LOG_WARNING(( "fd_gui_hist_ts_append: dbi %d has no record type", dbi )); return NULL; }

  fd_gui_hist_t * hist = fd_gui_hist( gui );
  if( FD_UNLIKELY( hist->has_last_ts[ dbi ] && stored_ts<hist->last_ts[ dbi ] ) ) {
    FD_LOG_WARNING(( "fd_gui_hist_ts_append: dbi %d insertion timestamp decreased from %ld to %ld", dbi, hist->last_ts[ dbi ], stored_ts ));
    return NULL;
  }

  int forced_eviction = 0;
  void * val = NULL;
  int rc;
  for(;;) {
    rc = fd_gui_store_ts_emplace( db, (ulong)dbi, stored_ts, &val );
    if( FD_LIKELY( rc==FD_GUI_STORE_SUCCESS ) ) {
      hist->last_ts[ dbi ]     = stored_ts;
      hist->has_last_ts[ dbi ] = 1;
      if( FD_UNLIKELY( forced_eviction ) ) hist->metrics.reserves[ dbi ]++;
      return val;
    }
    if( FD_UNLIKELY( !fd_gui_hist_make_room( gui, dbi, rc ) ) ) break;
    forced_eviction = 1;
  }
  if( FD_UNLIKELY( rc==FD_GUI_STORE_MAP_FULL ) ) {
    fd_gui_hist( gui )->metrics.map_full[ dbi ]++;
    FD_LOG_WARNING(( "fd_gui_hist_ts_append: dropping a record for dbi %d; store full and nothing left to evict", dbi ));
  }
  return NULL;
}

int
fd_gui_hist_ts_append( fd_gui_t *   gui,
                       int          dbi,
                       void const * val ) {
  if( FD_UNLIKELY( dbi<0 || dbi>=FD_GUI_HIST_CNT ) ) { FD_LOG_WARNING(( "fd_gui_hist_ts_append: bad dbi %d", dbi )); return -1; }
  long stored_ts;
  fd_memcpy( &stored_ts, (uchar const *)val + fd_gui_hist_dbi_ts_off( dbi ), sizeof(stored_ts) );
  void * dst = fd_gui_hist_ts_emplace( gui, dbi, stored_ts );
  if( FD_UNLIKELY( !dst ) ) return -1;
  fd_memcpy( dst, val, fd_gui_hist_rec_sz( dbi ) );
  return 0;
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

  /* Clamp the request time range to the index bounds. */
  long first_ts;
  long last_ts;
  if( FD_UNLIKELY( !fd_gui_store_ts_live_timestamp_bounds( db, (ulong)dbi, &first_ts, &last_ts ) ) ) return 0; /* empty ring */

  ulong first_window = fd_gui_hist_window( fd_long_max( first_ts, 0L ), res_ns );
  ulong last_window  = fd_gui_hist_window( fd_long_max( last_ts,  0L ), res_ns );
  window_lo = fd_ulong_max( window_lo, first_window );
  window_hi = fd_ulong_min( window_hi, last_window );
  if( FD_UNLIKELY( window_lo>window_hi ) ) return 0; /* request does not overlap the ring */

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

int
fd_gui_hist_evict_step( fd_gui_t * gui ) {
  if( FD_UNLIKELY( !gui->db || !gui->hist ) ) return 0;
  if( fd_gui_store_shared_free_region_cnt( gui->db ) ) return 0;
  return !!fd_gui_store_reclaim( gui->db, ULONG_MAX, FD_GUI_HIST_EVICT_BATCH, fd_gui_hist_reclaim_eligible, gui );
}
