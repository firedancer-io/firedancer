/* Protected per-DB bases, shared pressure, owner rollover and history
   queries.  Fixtures wire a bare GUI to the two store layers. */

#include "../../util/fd_util.h"
#include "fd_gui.h"
#include "fd_gui_store.h"
#include "fd_gui_hist.h"
#include "fd_gui_printf.h"
#include "../fd_txn_m.h"
#include "../metrics/fd_metrics.h"
#include "../../ballet/json/fd_jtok.h"
#include "../../waltz/http/fd_http_server_private.h"
#include "../pack/fd_pack_cost.h"
#include "../../choreo/votor/fd_vote.h"
#include "../../flamenco/runtime/fd_system_ids.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define EPOCH_A      (10UL)
#define EPOCH_B      (11UL)
#define EPOCH_C      (12UL)
#define A_START_SLOT (1000UL)
#define B_START_SLOT (1010UL)
#define C_START_SLOT (1020UL)
#define SLOT_CNT     (10UL)
#define A_END_SLOT   (A_START_SLOT+SLOT_CNT-1UL) /* 1009 */
#define B_END_SLOT   (B_START_SLOT+SLOT_CNT-1UL) /* 1019 */
#define C_END_SLOT   (C_START_SLOT+SLOT_CNT-1UL) /* 1029 */
#define BANK_SEQ     (0UL)

#define TEST_STORE_BYTES (10UL<<30) /* the [tiles.gui.db_size_gib] minimum */
#define TEST_TILE_CNT    (44UL)

/* test_descs returns the DB descriptors for a TEST_STORE_BYTES store. */

static fd_gui_store_desc_t const *
test_descs( void ) {
  static fd_gui_store_desc_t descs[ FD_GUI_HIST_CNT ];
  return fd_gui_hist_db_descs( descs, TEST_STORE_BYTES, TEST_TILE_CNT );
}

/* test_http_open joins gui to a fresh single-connection HTTP server
   with outgoing buffer buf_sz and returns its memory, to be released
   by test_http_close. */

static void *
test_http_open( fd_gui_t * gui,
                ulong      buf_sz ) {
  fd_http_server_params_t params = {
    .max_connection_cnt    = 1UL,
    .max_ws_connection_cnt = 1UL,
    .max_request_len       = 1024UL,
    .max_ws_recv_frame_len = 1024UL,
    .max_ws_send_frame_cnt = 4UL,
    .outgoing_buffer_sz    = buf_sz
  };
  void * mem = aligned_alloc( fd_http_server_align(), fd_http_server_footprint( params ) );
  FD_TEST( mem );
  gui->http = fd_http_server_join( fd_http_server_new( mem, params, (fd_http_server_callbacks_t){0}, NULL ) );
  FD_TEST( gui->http );
  return mem;
}

static void
test_http_close( fd_gui_t * gui,
                 void *     mem ) {
  FD_TEST( fd_http_server_delete( fd_http_server_leave( gui->http ) )==mem );
  free( mem );
  gui->http = NULL;
}

/* slot -> completion wallclock ns.  slot 1000 -> 10s, 1001 -> 11s, ... so the
   window (floored second) equals (slot-990). */
static long
slot_complete_ns( ulong slot ) {
  ulong sec = slot - 990UL; /* 1000->10s ... 1019->29s */
  return (long)( sec * 1000000000UL );
}
static long
sec_ns( ulong sec ) { return (long)( sec*1000000000UL ); }

static long
timeline_day_end_ns( ulong day ) {
  FD_TEST( day<(ulong)LONG_MAX/(ulong)FD_GUI_TIMELINE_DAY_NS );
  return (long)(day+1UL)*FD_GUI_TIMELINE_DAY_NS;
}

/* Put epoch A immediately before a UTC-day boundary and epochs B/C after it. */
static long
epoch_slot_complete_ns( ulong slot ) {
  return sec_ns( 86390UL+(slot-A_START_SLOT) );
}

static void
rm_tmpdir( char const * path ) {
  char cmd[ 256 ];
  /* MDB_NOSUBDIR: data file at `path`, lock file at `path-lock`. */
  fd_cstr_printf_check( cmd, sizeof(cmd), NULL, "rm -rf %s %s-lock", path, path );
  if( FD_UNLIKELY( system( cmd ) ) ) FD_LOG_WARNING(( "failed to clean up %s", path ));
}

/* ---- write helpers ---------------------------------------------------- */

/* epoch_reblk rebuilds epoch's block hulls from its slot intervals, for
   tests that write the intervals directly. */

static void
epoch_reblk( fd_gui_epoch_t * epoch ) {
  fd_gui_epoch_timeline_blk_init( epoch );
  for( ulong i=0UL; i<fd_ulong_min( epoch->slot_cnt, MAX_SLOTS_PER_EPOCH ); i++ ) {
    long rs = epoch->timeline_slot_start_ns[ i ];
    long re = epoch->timeline_slot_end_ns[ i ];
    if( rs<0L || re<=rs ) continue;
    ulong blk = i/FD_GUI_TIMELINE_SLOT_BLK_SZ;
    epoch->timeline_blk_min_start_ns[ blk ] = fd_long_min( epoch->timeline_blk_min_start_ns[ blk ], rs );
    epoch->timeline_blk_max_end_ns  [ blk ] = fd_long_max( epoch->timeline_blk_max_end_ns  [ blk ], re );
  }
}

static void
put_epoch( fd_gui_t * gui, ulong epoch, ulong start_slot, ulong slot_cnt ) {
  fd_gui_hist_epoch_key_t key[ 1 ];
  key->epoch = epoch;

  fd_gui_epoch_t * rec = fd_gui_hist_kv_get_or_create( gui, FD_GUI_HIST_EPOCH, key );
  FD_TEST( rec );
  memset( rec, 0, sizeof(fd_gui_epoch_t) );
  rec->epoch      = epoch;
  rec->start_slot = start_slot;
  rec->slot_cnt   = slot_cnt;
  rec->timeline_slot_min_start_ns = LONG_MAX;
  rec->timeline_slot_max_end_ns   = LONG_MIN;
  rec->timeline_slot_lo_idx       = ULONG_MAX;
  rec->timeline_slot_hi_idx       = ULONG_MAX;
  fd_gui_epoch_timeline_blk_init( rec );
  memset( rec->vote_count, 0xFF, sizeof(rec->vote_count) );
  memset( rec->timeline_slot_shred_cnt, 0xFF, sizeof(rec->timeline_slot_shred_cnt) );

}

static void
put_slot( fd_gui_t * gui, ulong slot, long completed_time ) {
  fd_gui_hist_slot_key_t key[ 1 ];
  key->slot = slot; key->bank_seq = BANK_SEQ;

  fd_gui_slot_t * rec = fd_gui_hist_kv_get_or_create( gui, FD_GUI_HIST_SLOT, key );
  FD_TEST( rec );
  memset( rec, 0, sizeof(*rec) );
  rec->slot           = slot;
  rec->bank_seq       = BANK_SEQ;
  rec->completed_time = completed_time;
}

static void
put_leader_slot( fd_gui_t * gui, ulong slot, long start_time ) {
  fd_gui_hist_leader_slot_key_t key[ 1 ];
  key->slot = slot; key->bank_seq = BANK_SEQ;

  fd_gui_leader_slot_t * rec = fd_gui_hist_kv_get_or_create( gui, FD_GUI_HIST_LEADER_SLOT, key );
  FD_TEST( rec );
  memset( rec, 0, sizeof(*rec) );
  rec->slot              = slot;
  rec->bank_seq          = BANK_SEQ;
  rec->leader_start_time = start_time;
}

/* SCHEDULER_COUNTS is window-only (no slot). */
static void
append_sched_counts( fd_gui_t * gui, long ts_ns ) {
  fd_gui_scheduler_counts_t rec[ 1 ];
  memset( rec, 0, sizeof(*rec) );
  rec->sample_time_ns = ts_ns;

  FD_TEST( !fd_gui_hist_ts_append( gui, FD_GUI_HIST_SCHEDULER_COUNTS, rec ) );
}

static void
append_shred( fd_gui_t * gui,
               long       insert_time_ns,
               long       ts_ns,
               ulong      slot ) {
  /* Storage fixtures include already-completed slots and arbitrary event
     times.  Seed a literal batch directly, without producer admission. */
  fd_gui_shred_event_t event = { insert_time_ns, ts_ns, (uint)slot, 0U, FD_GUI_SLOT_SHRED_REPAIR_REQUEST };
  fd_gui_shred_batch_t batch = { .insert_time_ns=insert_time_ns, .event_cnt=1U, .data_sz=1U+sizeof(event) };
  fd_memcpy( batch.data+1UL, &event, sizeof(event) );
  FD_TEST( !fd_gui_hist_ts_append( gui, FD_GUI_HIST_SHRED_EVENTS, &batch ) );
}

static void
append_replay_txn( fd_gui_t * gui,
                   long       now_ns,
                   long       ts_ns,
                   ulong      slot ) {
  fd_gui_store_replay_txn_t rec[ 1 ];
  memset( rec, 0, sizeof(*rec) );
  rec->insert_time_ns      = now_ns;
  rec->completion_time_ns  = ts_ns;
  rec->commit_end_ns       = ts_ns;
  rec->slot                = slot;
  rec->txn_start_shred_idx = UINT_MAX;
  rec->txn_end_shred_idx   = UINT_MAX;

  FD_TEST( !fd_gui_hist_ts_append( gui, FD_GUI_HIST_REPLAY_TXN, rec ) );
}

static void
append_replay_txn_batch( fd_gui_t * gui,
                         long       now_ns,
                         long       ts_ns,
                         ulong      slot ) {
  fd_gui_store_replay_txn_batch_t rec[ 1 ];
  memset( rec, 0, sizeof(*rec) );
  rec->insert_time_ns      = now_ns;
  rec->completion_time_ns  = ts_ns;
  rec->slot                = slot;

  FD_TEST( !fd_gui_hist_ts_append( gui, FD_GUI_HIST_REPLAY_TXN_BATCH, rec ) );
}

static void
put_timeline_day( fd_gui_t * gui,
                  ulong      day ) {
  fd_gui_timeline_day_t * rec = aligned_alloc( alignof(fd_gui_timeline_day_t), sizeof(fd_gui_timeline_day_t) );
  FD_TEST( rec );
  memset( rec, 0xFF, sizeof(fd_gui_timeline_day_t) );
  rec->end_time_ns    = timeline_day_end_ns( day );
  rec->insert_time_ns = rec->end_time_ns+sec_ns( 100UL );
  FD_TEST( !fd_gui_hist_ts_append( gui, FD_GUI_HIST_TIMELINE_DAY, rec ) );
  free( rec );
}

/* ---- read helpers (presence checks) ----------------------------------- */

static int
epoch_present( fd_gui_t * gui, ulong epoch ) {
  fd_gui_hist_epoch_key_t key[ 1 ];
  key->epoch = epoch;
  return fd_gui_hist_kv_get( gui, FD_GUI_HIST_EPOCH, key )!=NULL;
}

static int
slot_meta_present( fd_gui_t * gui, int dbi, ulong slot ) {
  return fd_gui_hist_kv_get_slot_any( gui, dbi, slot )!=NULL;
}

/* Count decoded shred events, or records for the other time-series DBs. */
static ulong
count_ts( fd_gui_t * gui, int dbi, ulong slot ) {
  ulong cnt = 0UL;
  if( dbi==FD_GUI_HIST_SHRED_EVENTS || dbi==FD_GUI_HIST_FEC_EVENTS ) {
    fd_gui_shred_event_iter_t it[ 1 ];
    if( dbi==FD_GUI_HIST_FEC_EVENTS ) fd_gui_fec_event_iter_begin( gui, it, 0L, LONG_MAX );
    else                              fd_gui_shred_event_iter_begin( gui, it, LONG_MIN, LONG_MAX );
    while( fd_gui_shred_event_iter_next( it ) ) cnt += slot==ULONG_MAX || it->event.slot==slot;
    fd_gui_shred_event_iter_end( it );
    return cnt;
  }

  fd_gui_hist_iter_t it[ 1 ];
  FD_TEST( !fd_gui_hist_range_begin( gui, it, dbi, LONG_MIN+1, LONG_MAX-1L, NULL, NULL ) );
  while( fd_gui_hist_range_next( it ) ) cnt++;
  fd_gui_hist_range_end( it );
  return cnt;
}

static int
timeline_day_present( fd_gui_t * gui,
                      ulong      day ) {
  long end_time_ns = timeline_day_end_ns( day );
  fd_gui_hist_iter_t it[ 1 ];
  FD_TEST( !fd_gui_hist_range_begin( gui, it, FD_GUI_HIST_TIMELINE_DAY, end_time_ns, end_time_ns, NULL, NULL ) );
  int found = 0;
  while( fd_gui_hist_range_next( it ) ) found |= ((fd_gui_timeline_day_t const *)it->rec)->end_time_ns==end_time_ns;
  fd_gui_hist_range_end( it );
  return found;
}

/* ---- the test --------------------------------------------------------- */

static void
test_base_history_protected( fd_gui_t * gui ) {
  /* --- populate three epochs ----------------------------------------- */
  put_epoch( gui, EPOCH_A, A_START_SLOT, SLOT_CNT );
  put_epoch( gui, EPOCH_B, B_START_SLOT, SLOT_CNT );
  put_epoch( gui, EPOCH_C, C_START_SLOT, SLOT_CNT );

  for( ulong s=A_START_SLOT; s<=C_END_SLOT; s++ ) {
    put_slot( gui, s, epoch_slot_complete_ns( s ) );
    put_leader_slot( gui, s, epoch_slot_complete_ns( s ) );
  }

  /* time-series: one scheduler-counts sample per second across all epochs'
     windows [86390,86419], straddling midnight at the A/B boundary. */
  for( ulong sec=86390UL; sec<=86419UL; sec++ ) append_sched_counts( gui, sec_ns( sec ) );

  /* event streams: one record per slot at the slot's own completion second */
  for( ulong s=A_START_SLOT; s<=C_END_SLOT; s++ ) {
    long ts_ns = epoch_slot_complete_ns( s );
    append_shred( gui, ts_ns, ts_ns, s );
    append_replay_txn( gui, ts_ns, ts_ns, s );
    append_replay_txn_batch( gui, ts_ns, ts_ns, s );
  }

  append_shred( gui, sec_ns( 86420UL ), sec_ns( 86399UL ), B_START_SLOT );

  put_timeline_day( gui, 0UL );
  put_timeline_day( gui, 1UL );
  FD_TEST( timeline_day_present( gui, 0UL ) );
  FD_TEST( timeline_day_present( gui, 1UL ) );

  /* flush time-series so the writes are visible to range reads */
  /* (range_begin flushes internally, but count_ts below relies on that) */

  /* --- baseline assertions ------------------------------------------- */
  FD_TEST( epoch_present( gui, EPOCH_A ) );
  FD_TEST( epoch_present( gui, EPOCH_B ) );
  FD_TEST( epoch_present( gui, EPOCH_C ) );
  FD_TEST( slot_meta_present( gui, FD_GUI_HIST_SLOT, A_START_SLOT ) );
  FD_TEST( slot_meta_present( gui, FD_GUI_HIST_SLOT, B_START_SLOT ) );
  FD_TEST( slot_meta_present( gui, FD_GUI_HIST_LEADER_SLOT, A_END_SLOT ) );
  FD_TEST( slot_meta_present( gui, FD_GUI_HIST_LEADER_SLOT, B_END_SLOT ) );
  FD_TEST( count_ts( gui, FD_GUI_HIST_SCHEDULER_COUNTS, ULONG_MAX )==30UL ); /* secs 86390..86419 */
  FD_TEST( count_ts( gui, FD_GUI_HIST_SHRED_EVENTS,     ULONG_MAX )==31UL ); /* 30 slots + 1 boundary */
  FD_TEST( count_ts( gui, FD_GUI_HIST_SHRED_EVENTS,     B_START_SLOT )==2UL ); /* slot 1010: its own + boundary */
  FD_TEST( count_ts( gui, FD_GUI_HIST_REPLAY_TXN,       ULONG_MAX )==30UL );
  FD_TEST( count_ts( gui, FD_GUI_HIST_REPLAY_TXN_BATCH, ULONG_MAX )==30UL );

  /* Exhaust shared capacity with a different writer, including repeated
     reclamation.  None of the base records may be removed. */
  ulong cap = FD_GUI_STORE_REGION_SZ / fd_ulong_align_up( sizeof(fd_gui_tile_stats_t), 8UL );
  for( ulong i=0UL; i<16UL*cap; i++ ) {
    FD_TEST( fd_gui_hist_ts_emplace( gui, FD_GUI_HIST_TILE_STATS, (long)i ) );
    fd_gui_hist_evict_step( gui );
  }
  FD_TEST( epoch_present( gui, EPOCH_A ) );
  FD_TEST(  epoch_present( gui, EPOCH_B ) );
  FD_TEST(  epoch_present( gui, EPOCH_C ) );
  FD_TEST(  timeline_day_present( gui, 0UL ) );
  FD_TEST(  timeline_day_present( gui, 1UL ) );

  for( ulong s=A_START_SLOT; s<=A_END_SLOT; s++ ) {
    FD_TEST( slot_meta_present( gui, FD_GUI_HIST_SLOT, s ) );
    FD_TEST( slot_meta_present( gui, FD_GUI_HIST_LEADER_SLOT, s ) );
  }
  for( ulong s=B_START_SLOT; s<=C_END_SLOT; s++ ) {
    FD_TEST( slot_meta_present( gui, FD_GUI_HIST_SLOT, s ) );
    FD_TEST( slot_meta_present( gui, FD_GUI_HIST_LEADER_SLOT, s ) );
  }

  FD_TEST( count_ts( gui, FD_GUI_HIST_SCHEDULER_COUNTS, ULONG_MAX )==30UL );
  FD_TEST( count_ts( gui, FD_GUI_HIST_REPLAY_TXN,       ULONG_MAX )==30UL );
  FD_TEST( count_ts( gui, FD_GUI_HIST_REPLAY_TXN_BATCH, ULONG_MAX )==30UL );
  FD_TEST( count_ts( gui, FD_GUI_HIST_SHRED_EVENTS, ULONG_MAX )==31UL );
  FD_TEST( count_ts( gui, FD_GUI_HIST_SHRED_EVENTS, B_START_SLOT )==2UL );
  FD_TEST( count_ts( gui, FD_GUI_HIST_SHRED_EVENTS, A_START_SLOT )==1UL );
  FD_LOG_NOTICE(( "test_base_history_protected: ok" ));
}

static void
test_evict_large_batch( fd_gui_t * gui ) {
  /* Fill one TS ring, bypassing history retry.  A background step must
     stop at 512 records, even within a single timestamp window. */
  ulong count = 0UL;
  void * rec;
  while( fd_gui_store_ts_emplace( gui->db, FD_GUI_HIST_SHRED_EVENTS, 1L, &rec )==FD_GUI_STORE_SUCCESS ) count++;
  ulong cap = FD_GUI_STORE_REGION_SZ / fd_ulong_align_up( sizeof(fd_gui_shred_batch_t), 8UL );
  FD_TEST( cap>512UL && count>3UL*cap );
  FD_TEST( fd_gui_hist_evict_step( gui ) );
  FD_TEST( fd_gui_store_metrics( gui->db )->evict_records[ FD_GUI_HIST_SHRED_EVENTS ]==512UL );
  ulong steps = 1UL;
  while( fd_gui_hist_evict_step( gui ) ) {
    steps++;
    FD_TEST( steps<cap );
  }
  /* Background eviction keeps one spare shared region, so it stops
     once two regions are free. */
  FD_TEST( steps==2UL*((cap+511UL)/512UL) );
  FD_TEST( fd_gui_store_metrics( gui->db )->evict_records[ FD_GUI_HIST_SHRED_EVENTS ]==2UL*cap );
  FD_TEST( fd_gui_store_shared_free_region_cnt( gui->db )==2UL );
  long first, last;
  FD_TEST( fd_gui_store_ts_live_timestamp_bounds( gui->db, FD_GUI_HIST_SHRED_EVENTS, &first, &last ) );
  FD_TEST( first==1L && last==1L );
  FD_LOG_NOTICE(( "test_evict_large_batch: ok" ));
}

/* test_current_epoch_protected is the direct regression for the blank-nav-bar
   bug: at startup the validator publishes epoch info for the current
   (in-progress) epoch and the next epoch, so exactly two epochs are resident.
   Eviction must preserve their records under another writer's pressure. */

#define CP_CUR_EPOCH  (60UL)
#define CP_CUR_START  (10000UL)
#define CP_NEXT_EPOCH (61UL)
#define CP_NEXT_START (11000UL)
#define CP_SLOT_CNT   (5UL)

static void
test_current_epoch_protected( fd_gui_t * gui ) {
  /* current (in-progress) + next epoch, mirroring the startup publish. */
  put_epoch( gui, CP_CUR_EPOCH,  CP_CUR_START,  CP_SLOT_CNT );
  put_epoch( gui, CP_NEXT_EPOCH, CP_NEXT_START, CP_SLOT_CNT );
  put_slot( gui, CP_CUR_START,  slot_complete_ns( 1000UL ) );
  put_slot( gui, CP_NEXT_START, slot_complete_ns( 2000UL ) );

  ulong cap = FD_GUI_STORE_REGION_SZ / sizeof(fd_gui_shred_batch_t);
  for( ulong i=0UL; i<16UL*cap; i++ ) {
    FD_TEST( fd_gui_hist_ts_emplace( gui, FD_GUI_HIST_SHRED_EVENTS, (long)i ) );
    fd_gui_hist_evict_step( gui );
  }
  FD_TEST( epoch_present( gui, CP_CUR_EPOCH ) );
  FD_TEST( epoch_present( gui, CP_NEXT_EPOCH ) );

  FD_LOG_NOTICE(( "test_current_epoch_protected: ok" ));
}

static void
test_timeline_rollover( fd_gui_t * gui ) {
  fd_gui_timeline_day_t * rec = aligned_alloc( alignof(fd_gui_timeline_day_t), sizeof(fd_gui_timeline_day_t) );
  FD_TEST( rec );
  memset( rec, 0xFF, sizeof(fd_gui_timeline_day_t) );
  ulong day_cnt = 0UL;
  ulong cap = FD_GUI_STORE_REGION_SZ / sizeof(fd_gui_timeline_day_t);
  ulong capacity = (fd_gui_store_shared_free_region_cnt( gui->db )+test_descs()[ FD_GUI_HIST_TIMELINE_DAY ].base_regions)*cap;
  FD_TEST( capacity<30UL ); /* day windows wrap the 30-day time index beyond this */
  while( day_cnt<capacity ) {
    rec->insert_time_ns = sec_ns( day_cnt+1UL );
    rec->end_time_ns    = timeline_day_end_ns( day_cnt++ );
    FD_TEST( !fd_gui_hist_ts_append( gui, FD_GUI_HIST_TIMELINE_DAY, rec ) );
  }
  FD_TEST( day_cnt>1UL );
  FD_TEST( fd_gui_timeline_day_get( gui, 0UL ) );
  ulong evicted_before = fd_gui_store_metrics( gui->db )->evict_records[ FD_GUI_HIST_TIMELINE_DAY ];
  ulong reserves_before = fd_gui_hist_metrics( gui )->reserves[ FD_GUI_HIST_TIMELINE_DAY ];
  fd_gui_store_metrics_t store_before = *fd_gui_store_metrics( gui->db );
  fd_gui_hist_metrics_t hist_before = *fd_gui_hist_metrics( gui );
  fd_gui_timeline_day_t * regression = aligned_alloc( alignof(fd_gui_timeline_day_t), sizeof(fd_gui_timeline_day_t) );
  FD_TEST( regression );
  memset( regression, 0, sizeof(fd_gui_timeline_day_t) );
  regression->insert_time_ns = sec_ns( day_cnt+1UL );
  regression->end_time_ns = timeline_day_end_ns( day_cnt-1UL )-1L;
  FD_TEST( fd_gui_hist_ts_append( gui, FD_GUI_HIST_TIMELINE_DAY, regression )==-1 );
  FD_TEST( !fd_gui_store_shared_free_region_cnt( gui->db ) );
  FD_TEST( !memcmp( &store_before, fd_gui_store_metrics( gui->db ), sizeof(store_before) ) );
  FD_TEST( !memcmp( &hist_before, fd_gui_hist_metrics( gui ), sizeof(hist_before) ) );
  free( regression );
  rec->insert_time_ns = 0L;
  rec->end_time_ns    = timeline_day_end_ns( day_cnt );
  FD_TEST( !fd_gui_hist_ts_append( gui, FD_GUI_HIST_TIMELINE_DAY, rec ) );
  free( rec );

  FD_TEST( fd_gui_store_metrics( gui->db )->evict_records[ FD_GUI_HIST_TIMELINE_DAY ]==evicted_before+cap );
  FD_TEST( fd_gui_hist_metrics( gui )->reserves[ FD_GUI_HIST_TIMELINE_DAY ]==reserves_before+1UL );
  FD_TEST( !fd_gui_timeline_day_get( gui, 0UL ) );
  for( ulong day=0UL; day<cap; day++ ) FD_TEST( !fd_gui_timeline_day_get( gui, day ) );
  for( ulong day=cap; day<=day_cnt; day++ ) FD_TEST( fd_gui_timeline_day_get( gui, day ) );

  FD_LOG_NOTICE(( "test_timeline_rollover: ok" ));
}

/* test_resident_meta_mutation_survives_evict checks the in-place mutation
   model the GUI now relies on: per-epoch mutable bookkeeping lives in the DB
   EPOCH record and is written through the stable map pointer returned by
   fd_gui_hist_kv_get.  Mutating a resident (newer) epoch's record in place
   must be durable, and evicting an OLDER epoch must not disturb the newer
   epoch's record or its mutated fields. */

#define RM_OLD_EPOCH  (40UL)
#define RM_OLD_START  (5000UL)
#define RM_NEW_EPOCH  (41UL)
#define RM_NEW_START  (6000UL)
#define RM_NEW2_EPOCH (42UL)
#define RM_NEW2_START (7000UL)
#define RM_SLOT_CNT   (5UL)

static void
test_resident_meta_mutation_survives_evict( fd_gui_t * gui ) {
  /* Fill the ring to its record limit, after which further inserts
     recycle the ring's own oldest region. */
  put_epoch( gui, RM_OLD_EPOCH, RM_OLD_START, RM_SLOT_CNT );
  put_epoch( gui, RM_NEW_EPOCH, RM_NEW_START, RM_SLOT_CNT );
  put_epoch( gui, RM_NEW2_EPOCH, RM_NEW2_START, RM_SLOT_CNT );
  /* Slot history remains independent of epoch reclamation. */
  put_slot( gui, RM_OLD_START, slot_complete_ns( 1000UL ) );
  put_slot( gui, RM_NEW_START, slot_complete_ns( 2000UL ) );
  put_slot( gui, RM_NEW2_START, slot_complete_ns( 3000UL ) );

  /* Resolve the newer (resident) epoch's record pointer and mutate the
     per-epoch bookkeeping fields in place. */
  ulong cap = FD_GUI_STORE_REGION_SZ / fd_ulong_align_up( sizeof(fd_gui_epoch_t), 8UL );
  ulong max_cnt = test_descs()[ FD_GUI_HIST_EPOCH ].max_records;
  for( ulong i=3UL; i<max_cnt; i++ ) put_epoch( gui, RM_OLD_EPOCH+i, RM_OLD_START+i*RM_SLOT_CNT, RM_SLOT_CNT );
  FD_TEST( !fd_gui_store_metrics( gui->db )->evict_records[ FD_GUI_HIST_EPOCH ] );
  fd_gui_hist_epoch_key_t key[ 1 ]; key->epoch = RM_OLD_EPOCH+max_cnt-1UL;
  fd_gui_epoch_t * rec = (fd_gui_epoch_t *)fd_gui_hist_kv_get( gui, FD_GUI_HIST_EPOCH, key );
  FD_TEST( rec );
  rec->my_total_slots          = 7UL;
  rec->my_skipped_slots        = 3UL;
  rec->is_voter[ 0 ]           = FD_GUI_IS_VOTER_YES;
  rec->rankings->largest_tips[ 0 ].slot  = RM_NEW_START + 4UL;
  rec->rankings->largest_tips[ 0 ].value = 12345UL;

  /* A fresh get must observe the in-place writes (no put/round-trip). */
  fd_gui_epoch_t * rec2 = (fd_gui_epoch_t *)fd_gui_hist_kv_get( gui, FD_GUI_HIST_EPOCH, key );
  FD_TEST( rec2==rec ); /* stable map pointer */
  FD_TEST( rec2->my_total_slots==7UL );
  FD_TEST( rec2->my_skipped_slots==3UL );

  /* Writing another region's worth of epochs recycles the ring's own
     oldest region; the newer epoch's record and its mutated fields must
     be untouched, and its map pointer must remain valid. */
  ulong evicted_before = fd_gui_store_metrics( gui->db )->evict_records[ FD_GUI_HIST_EPOCH ];
  for( ulong i=max_cnt; i<max_cnt+cap; i++ ) put_epoch( gui, RM_OLD_EPOCH+i, RM_OLD_START+i*RM_SLOT_CNT, RM_SLOT_CNT );
  FD_TEST( fd_gui_store_metrics( gui->db )->evict_records[ FD_GUI_HIST_EPOCH ]==evicted_before+cap );
  FD_TEST( !epoch_present( gui, RM_OLD_EPOCH ) );
  FD_TEST( epoch_present( gui, RM_OLD_EPOCH+cap ) );

  fd_gui_epoch_t * rec3 = (fd_gui_epoch_t *)fd_gui_hist_kv_get( gui, FD_GUI_HIST_EPOCH, key );
  FD_TEST( rec3==rec );
  FD_TEST( rec3->epoch==key->epoch );
  FD_TEST( rec3->my_total_slots==7UL );
  FD_TEST( rec3->my_skipped_slots==3UL );
  FD_TEST( rec3->is_voter[ 0 ]==FD_GUI_IS_VOTER_YES );
  FD_TEST( rec3->rankings->largest_tips[ 0 ].slot==RM_NEW_START + 4UL );
  FD_TEST( rec3->rankings->largest_tips[ 0 ].value==12345UL );

  FD_LOG_NOTICE(( "test_resident_meta_mutation_survives_evict: ok" ));
}

/* Epoch rollover keeps current/next throughout many base rotations. */

#define RR_A_EPOCH (50UL)
#define RR_A_START (7000UL)
#define RR_SLOT_CNT (5UL)

static void
test_epoch_region_reclaimed( fd_gui_t * gui ) {
  ulong const epoch_region_capacity =
      FD_GUI_STORE_REGION_SZ / fd_ulong_align_up( sizeof(fd_gui_epoch_t), 8UL );
  FD_TEST( epoch_region_capacity>0UL );

  /* Enough epochs to rotate through the base many times. */
  ulong const epoch_cnt = 30UL*epoch_region_capacity;
  for( ulong ordinal=0UL; ordinal<epoch_cnt; ordinal++ ) {
    ulong epoch = RR_A_EPOCH + ordinal;
    ulong start = RR_A_START + ordinal*RR_SLOT_CNT;
    put_epoch( gui, epoch, start, RR_SLOT_CNT );
    FD_TEST( epoch_present( gui, epoch ) );
    if( ordinal ) FD_TEST( epoch_present( gui, epoch-1UL ) );
    if( ordinal>=3UL*epoch_region_capacity ) FD_TEST( !epoch_present( gui, epoch-3UL*epoch_region_capacity ) );
    FD_TEST( !fd_gui_hist_evict_step( gui ) );
  }
  FD_TEST( fd_gui_store_metrics( gui->db )->region_reclaims[ FD_GUI_HIST_EPOCH ]>20UL );
  FD_LOG_NOTICE(( "test_epoch_region_reclaimed: ok" ));
}

/* ---- store lifecycle (bare fd_gui_t + the two store layers) ----------- */

struct test_store {
  fd_gui_t * gui;
  void *     db_mem;
  void *     hist_mem;
  char       path[ 128 ];
};
typedef struct test_store test_store_t;

static void
store_open( test_store_t * s, ulong map_bytes, int instance ) {
  fd_cstr_printf_check( s->path, sizeof(s->path), NULL, "/tmp/fd_gui_hist_evict_test.%i.%i", (int)getpid(), instance );

  s->gui = aligned_alloc( fd_gui_align(), fd_gui_footprint( 1UL, 1UL, 1UL ) );
  FD_TEST( s->gui );
  memset( s->gui, 0, fd_gui_footprint( 1UL, 1UL, 1UL ) );
  s->gui->slot_txn_scratch.max = 1UL;
  static fd_gui_ag_slot_t ag_slot[ 1 ] = {{ .slot = ULONG_MAX, .bank_seq = ULONG_MAX }};
  s->gui->ag.slot     = ag_slot;
  s->gui->ag.slot_cnt = 1UL;
  s->gui->max_consecutive_skips = 1024UL;
  s->gui->tile_cnt = TEST_TILE_CNT;
  s->gui->cpu_util.last_slot = ULONG_MAX;
  for( ulong i=0UL; i<FD_GUI_BOOT_PROGRESS_SNAPSHOT_CNT; i++ ) s->gui->summary.boot_progress.loading_snapshot[ i ].slot = ULONG_MAX; /* as fd_gui_new */
  s->gui->day_prep.day  = ULONG_MAX;
  s->gui->day_prep.done = ULONG_MAX;
  s->gui->day_prep.sync = 1; /* day records on first use, as before paced preparation */
  for( ulong i=0UL; i<FD_GUI_VOTE_SLOT_CNT; i++ ) s->gui->votes.slot[ i ].slot = ULONG_MAX;

  s->db_mem = aligned_alloc( fd_gui_store_align(),
                             fd_ulong_align_up( fd_gui_hist_store_footprint( map_bytes, TEST_TILE_CNT ), fd_gui_store_align() ) );
  FD_TEST( s->db_mem );
  s->gui->db = fd_gui_store_join( fd_gui_hist_store_new( s->db_mem, s->path, map_bytes, TEST_TILE_CNT, 0x0123456789abcdefUL ) );
  FD_TEST( s->gui->db );

  s->hist_mem = aligned_alloc( fd_gui_hist_align(),
                               fd_ulong_align_up( fd_gui_hist_footprint(), fd_gui_hist_align() ) );
  FD_TEST( s->hist_mem );
  s->gui->hist = fd_gui_hist_join( fd_gui_hist_new( s->hist_mem, s->gui->db ) );
  FD_TEST( s->gui->hist );

}

static void
store_close( test_store_t * s ) {
  fd_gui_store_delete( fd_gui_store_leave( s->gui->db ) );
  free( s->hist_mem );
  free( s->db_mem );
  free( s->gui );
  rm_tmpdir( s->path );
}

static void
test_timeline_db( fd_gui_t * gui ) {
  fd_gui_store_desc_t const * descs = test_descs();
  FD_TEST( FD_GUI_HIST_TIMELINE_DAY==10 );
  FD_TEST( FD_GUI_HIST_REPLAY_TXN==11 );
  FD_TEST( FD_GUI_HIST_REPLAY_TXN_BATCH==12 );
  FD_TEST( FD_GUI_HIST_FEC_EVENTS==13 );
  FD_TEST( FD_GUI_HIST_TIMELINE_TILE_DAY==14 );
  FD_TEST( FD_GUI_HIST_FEC_EVENT_ARCHIVE==15 );
  FD_TEST( FD_GUI_HIST_REPLAY_SLOT_STATE==16 );
  FD_TEST( FD_GUI_HIST_TIMELINE_TILE_STATE_DAY==17 );
  FD_TEST( FD_GUI_HIST_VOTES==18 );
  FD_TEST( FD_GUI_HIST_VOTE_EVENTS==19 );
  FD_TEST( FD_GUI_HIST_REPLAY_LTHASH==20 );
  FD_TEST( FD_GUI_HIST_REPLAY_LTHASH_BATCH==21 );
  FD_TEST( FD_GUI_HIST_VOTE_BATCH==22 );
  FD_TEST( FD_GUI_HIST_CNT==23 );
  FD_TEST( !strcmp( descs[ FD_GUI_HIST_VOTE_BATCH ].name, "vote_batch" ) );
  FD_TEST( descs[ FD_GUI_HIST_VOTE_BATCH ].kind==FD_GUI_STORE_KIND_TS );
  FD_TEST( descs[ FD_GUI_HIST_VOTE_BATCH ].ts_off==offsetof(fd_gui_store_vote_t,insert_time_ns) );
  FD_TEST( !strcmp( descs[ FD_GUI_HIST_REPLAY_LTHASH_BATCH ].name, "replay_lthash_batch" ) );
  FD_TEST( descs[ FD_GUI_HIST_REPLAY_LTHASH_BATCH ].kind==FD_GUI_STORE_KIND_TS );
  FD_TEST( descs[ FD_GUI_HIST_REPLAY_LTHASH_BATCH ].ts_off==offsetof(fd_gui_store_replay_lthash_batch_t,insert_time_ns) );
  FD_TEST( !strcmp( descs[ FD_GUI_HIST_REPLAY_LTHASH ].name, "replay_lthash" ) );
  FD_TEST( descs[ FD_GUI_HIST_REPLAY_LTHASH ].kind==FD_GUI_STORE_KIND_TS );
  FD_TEST( descs[ FD_GUI_HIST_REPLAY_LTHASH ].ts_off==offsetof(fd_gui_store_replay_lthash_t,insert_time_ns) );
  FD_TEST( !strcmp( descs[ FD_GUI_HIST_REPLAY_SLOT_STATE ].name, "replay_slot_state" ) );
  FD_TEST( descs[ FD_GUI_HIST_REPLAY_SLOT_STATE ].kind==FD_GUI_STORE_KIND_TS );
  FD_TEST( descs[ FD_GUI_HIST_REPLAY_SLOT_STATE ].ts_off==offsetof(fd_gui_store_replay_slot_state_t,insert_time_ns) );
  FD_TEST( !strcmp( descs[ FD_GUI_HIST_TIMELINE_TILE_STATE_DAY ].name, "timeline_tile_state_day" ) );
  FD_TEST( descs[ FD_GUI_HIST_TIMELINE_TILE_STATE_DAY ].kind==FD_GUI_STORE_KIND_KV );
  FD_TEST( descs[ FD_GUI_HIST_TIMELINE_TILE_STATE_DAY ].key_sz==sizeof(fd_gui_hist_tile_day_key_t) );
  /* Yesterday, today and tomorrow (prepared ahead) for every tile
     state position. */
  FD_TEST( (descs[ FD_GUI_HIST_TIMELINE_TILE_STATE_DAY ].base_regions-1UL)*(FD_GUI_STORE_REGION_SZ/fd_ulong_align_up( sizeof(fd_gui_timeline_tile_state_day_t), 8UL ))>=
           FD_GUI_HIST_PREPARED_DAYS*fd_ulong_min( TEST_TILE_CNT, FD_GUI_TILE_STATE_POS_CNT ) );
  FD_TEST( !strcmp( descs[ FD_GUI_HIST_FEC_EVENTS        ].name, "fec_events"        ) );
  FD_TEST( !strcmp( descs[ FD_GUI_HIST_FEC_EVENT_ARCHIVE ].name, "fec_event_archive" ) );
  FD_TEST( descs[ FD_GUI_HIST_FEC_EVENTS ].kind==FD_GUI_STORE_KIND_KV );
  FD_TEST( descs[ FD_GUI_HIST_FEC_EVENTS ].key_sz==sizeof(fd_gui_fec_event_key_t) );
  FD_TEST( descs[ FD_GUI_HIST_FEC_EVENTS ].val_sz==sizeof(fd_gui_fec_event_t) );
  FD_TEST( descs[ FD_GUI_HIST_FEC_EVENTS ].max_records==FD_GUI_FEC_RECORD_MAX );
  FD_TEST( fd_ulong_align_up( descs[ FD_GUI_HIST_FEC_EVENTS ].val_sz, descs[ FD_GUI_HIST_FEC_EVENTS ].val_align )<=32UL );
  FD_TEST( descs[ FD_GUI_HIST_FEC_EVENT_ARCHIVE ].kind==FD_GUI_STORE_KIND_TS );
  FD_TEST( descs[ FD_GUI_HIST_FEC_EVENT_ARCHIVE ].val_sz==sizeof(fd_gui_fec_event_batch_t) );
  FD_TEST( descs[ FD_GUI_HIST_FEC_EVENT_ARCHIVE ].ts_off==offsetof(fd_gui_fec_event_batch_t,insert_time_ns) );
  FD_TEST( !strcmp( descs[ FD_GUI_HIST_TIMELINE_DAY     ].name, "timeline_day"     ) );
  FD_TEST( !strcmp( descs[ FD_GUI_HIST_REPLAY_TXN       ].name, "replay_txn"       ) );
  FD_TEST( !strcmp( descs[ FD_GUI_HIST_REPLAY_TXN_BATCH ].name, "replay_txn_batch" ) );
  FD_TEST( descs[ FD_GUI_HIST_SHRED_EVENTS     ].val_sz==sizeof(fd_gui_shred_batch_t) );
  FD_TEST( descs[ FD_GUI_HIST_TIMELINE_DAY     ].val_sz==sizeof(fd_gui_timeline_day_t) );
  FD_TEST( sizeof(fd_gui_timeline_day_t)<=FD_GUI_STORE_MAX_REC_SZ );
  FD_TEST( !strcmp( descs[ FD_GUI_HIST_TIMELINE_TILE_DAY ].name, "timeline_tile_day" ) );
  FD_TEST( descs[ FD_GUI_HIST_TIMELINE_TILE_DAY ].val_sz==sizeof(fd_gui_timeline_tile_day_t) );
  FD_TEST( descs[ FD_GUI_HIST_TIMELINE_TILE_DAY ].kind==FD_GUI_STORE_KIND_KV );
  FD_TEST( descs[ FD_GUI_HIST_TIMELINE_TILE_DAY ].key_sz==sizeof(fd_gui_hist_tile_day_key_t) );
  /* Retention floors: yesterday, today and tomorrow for every tile, and
     FD_GUI_HIST_MIN_EPOCHS epochs of slot/leader/epoch records, survive
     with a full head region. */
  FD_TEST( (descs[ FD_GUI_HIST_TIMELINE_TILE_DAY ].base_regions-1UL)*(FD_GUI_STORE_REGION_SZ/sizeof(fd_gui_timeline_tile_day_t))>=FD_GUI_HIST_PREPARED_DAYS*TEST_TILE_CNT );
  FD_TEST( (descs[ FD_GUI_HIST_SLOT        ].base_regions-1UL)*(FD_GUI_STORE_REGION_SZ/fd_ulong_align_up( descs[ FD_GUI_HIST_SLOT        ].val_sz, 8UL ))>=FD_GUI_HIST_MIN_EPOCHS*MAX_SLOTS_PER_EPOCH );
  FD_TEST( (descs[ FD_GUI_HIST_LEADER_SLOT ].base_regions-1UL)*(FD_GUI_STORE_REGION_SZ/fd_ulong_align_up( descs[ FD_GUI_HIST_LEADER_SLOT ].val_sz, 8UL ))>=FD_GUI_HIST_MIN_EPOCHS*FD_GUI_HIST_MAX_LEADER_SLOTS_PER_EPOCH );
  FD_TEST( (descs[ FD_GUI_HIST_EPOCH       ].base_regions-1UL)*(FD_GUI_STORE_REGION_SZ/fd_ulong_align_up( descs[ FD_GUI_HIST_EPOCH       ].val_sz, 8UL ))>=FD_GUI_HIST_MIN_EPOCHS );
  FD_TEST( descs[ FD_GUI_HIST_TIMELINE_DAY ].base_regions>=FD_GUI_HIST_PREPARED_DAYS );
  FD_TEST( offsetof(fd_gui_timeline_tile_day_t,day_idx )==offsetof(fd_gui_hist_tile_day_key_t,day_idx ) );
  FD_TEST( offsetof(fd_gui_timeline_tile_day_t,tile_idx)==offsetof(fd_gui_hist_tile_day_key_t,tile_idx) );
  FD_TEST( descs[ FD_GUI_HIST_REPLAY_TXN_BATCH ].val_sz==sizeof(fd_gui_store_replay_txn_batch_t) );
  FD_TEST( descs[ FD_GUI_HIST_TIMELINE_DAY ].kind==FD_GUI_STORE_KIND_TS );
  FD_TEST( descs[ FD_GUI_HIST_TIMELINE_DAY     ].ts_off==offsetof(fd_gui_timeline_day_t,end_time_ns) );
  FD_TEST( descs[ FD_GUI_HIST_SHRED_EVENTS     ].ts_off==offsetof(fd_gui_shred_batch_t,insert_time_ns) );
  FD_TEST( descs[ FD_GUI_HIST_TXN_START        ].ts_off==offsetof(fd_gui_store_txn_start_t,insert_time_ns) );
  FD_TEST( descs[ FD_GUI_HIST_TXN_END          ].ts_off==offsetof(fd_gui_store_txn_end_t,insert_time_ns) );
  FD_TEST( descs[ FD_GUI_HIST_REPLAY_TXN       ].ts_off==offsetof(fd_gui_store_replay_txn_t,insert_time_ns) );
  FD_TEST( descs[ FD_GUI_HIST_REPLAY_TXN_BATCH ].ts_off==offsetof(fd_gui_store_replay_txn_batch_t,insert_time_ns) );
  FD_TEST( descs[ FD_GUI_HIST_SCHEDULER_COUNTS ].ts_off==offsetof(fd_gui_scheduler_counts_t,sample_time_ns) );
  FD_TEST( descs[ FD_GUI_HIST_TILE_TIMERS      ].ts_off==offsetof(fd_gui_tile_timers_hist_t,sample_time_nanos) );
  FD_TEST( descs[ FD_GUI_HIST_TILE_STATS       ].ts_off==offsetof(fd_gui_tile_stats_t,sample_time_nanos) );
  FD_TEST( descs[ FD_GUI_HIST_TXN_WATERFALL    ].ts_off==offsetof(fd_gui_txn_waterfall_t,sample_time_nanos) );

  fd_gui_timeline_day_t * day = aligned_alloc( alignof(fd_gui_timeline_day_t), sizeof(fd_gui_timeline_day_t) );
  FD_TEST( day );
  memset( day, 0xFF, sizeof(*day) );
  FD_TEST( fd_gui_timeline_field_get( day, FD_GUI_TIMELINE_GRANULARITY_250MS, FD_GUI_TIMELINE_FIELD_SKIPPED, 0UL )==ULONG_MAX );
  fd_gui_timeline_field_set( day, FD_GUI_TIMELINE_GRANULARITY_250MS, FD_GUI_TIMELINE_FIELD_SKIPPED, 0UL, (ulong)USHORT_MAX );
  FD_TEST( fd_gui_timeline_field_get( day, FD_GUI_TIMELINE_GRANULARITY_250MS, FD_GUI_TIMELINE_FIELD_SKIPPED, 0UL )==(ulong)USHORT_MAX-1UL );
  fd_gui_timeline_field_set( day, FD_GUI_TIMELINE_GRANULARITY_15M, FD_GUI_TIMELINE_FIELD_PUBLISHED, 0UL, (ulong)UINT_MAX );
  FD_TEST( fd_gui_timeline_field_get( day, FD_GUI_TIMELINE_GRANULARITY_15M, FD_GUI_TIMELINE_FIELD_PUBLISHED, 0UL )==(ulong)UINT_MAX-1UL );
  fd_gui_timeline_field_set( day, FD_GUI_TIMELINE_GRANULARITY_250MS, FD_GUI_TIMELINE_FIELD_TIPS, 0UL, 10UL*(ulong)UINT_MAX );
  FD_TEST( fd_gui_timeline_field_get( day, FD_GUI_TIMELINE_GRANULARITY_250MS, FD_GUI_TIMELINE_FIELD_TIPS, 0UL )==10UL*(ulong)UINT_MAX );
  free( day );

  long const source_ns = sec_ns( 2000UL );
  long const now_ns    = source_ns+sec_ns( 100UL );
  long const stored_ns = now_ns;

  fd_gui_store_metrics_t const * metrics = fd_gui_store_metrics( gui->db );
  ulong reads_before   = metrics->ts_reads       [ FD_GUI_HIST_REPLAY_TXN ];
  ulong records_before = metrics->ts_read_records[ FD_GUI_HIST_REPLAY_TXN ];
  append_replay_txn( gui, now_ns, source_ns, 2UL );
  FD_TEST( metrics->ts_reads       [ FD_GUI_HIST_REPLAY_TXN ]==reads_before   );
  FD_TEST( metrics->ts_read_records[ FD_GUI_HIST_REPLAY_TXN ]==records_before );

  fd_gui_hist_iter_t it[ 1 ];
  long const shred_ns = sec_ns( 3000UL );
  append_shred( gui, shred_ns, shred_ns, 3UL );
  reads_before   = metrics->ts_reads       [ FD_GUI_HIST_SHRED_EVENTS ];
  records_before = metrics->ts_read_records[ FD_GUI_HIST_SHRED_EVENTS ];
  FD_TEST( !fd_gui_hist_range_begin( gui, it, FD_GUI_HIST_SHRED_EVENTS, shred_ns, shred_ns+1L, NULL, NULL ) );
  FD_TEST( fd_gui_hist_range_next( it ) );
  FD_TEST( ((fd_gui_shred_batch_t const *)it->rec)->event_cnt==1U );
  FD_TEST( ((fd_gui_shred_batch_t const *)it->rec)->insert_time_ns==shred_ns );
  fd_gui_hist_range_end( it );
  FD_TEST( metrics->ts_reads       [ FD_GUI_HIST_SHRED_EVENTS ]==reads_before+1UL   );
  FD_TEST( metrics->ts_read_records[ FD_GUI_HIST_SHRED_EVENTS ]==records_before+1UL );

  FD_TEST( !fd_gui_hist_range_begin( gui, it, FD_GUI_HIST_REPLAY_TXN,
                                     stored_ns, stored_ns+1L, NULL, NULL ) );
  ulong found = 0UL;
  while( fd_gui_hist_range_next( it ) ) {
    fd_gui_store_replay_txn_t const * rec = it->rec;
    FD_TEST( rec->completion_time_ns==source_ns );
    FD_TEST( rec->insert_time_ns==stored_ns );
    FD_TEST( rec->slot==2UL );
    found++;
  }
  fd_gui_hist_range_end( it );
  FD_TEST( found==1UL );

  /* Monotonic timestamps are rejected before reserve can evict data. */
  fd_gui_scheduler_counts_t sched[ 1 ] = {{0}};
  sched->sample_time_ns = sec_ns( 3000UL );
  FD_TEST( !fd_gui_hist_ts_append( gui, FD_GUI_HIST_SCHEDULER_COUNTS, sched ) );
  ulong appends_before = fd_gui_store_metrics( gui->db )->ts_appends[ FD_GUI_HIST_SCHEDULER_COUNTS ];
  sched->sample_time_ns--;
  FD_TEST( fd_gui_hist_ts_append( gui, FD_GUI_HIST_SCHEDULER_COUNTS, sched )==-1 );
  FD_TEST( fd_gui_store_metrics( gui->db )->ts_appends[ FD_GUI_HIST_SCHEDULER_COUNTS ]==appends_before );
  sched->sample_time_ns++;
  FD_TEST( !fd_gui_hist_ts_append( gui, FD_GUI_HIST_SCHEDULER_COUNTS, sched ) );
  FD_TEST( fd_gui_store_metrics( gui->db )->ts_appends[ FD_GUI_HIST_SCHEDULER_COUNTS ]==appends_before+1UL );

  FD_LOG_NOTICE(( "test_timeline_foundation: ok" ));
}

static void
test_range_live_timestamp_bounds( fd_gui_t * gui ) {
  append_shred( gui, 0L, -sec_ns( 2UL ), 1UL );

  fd_gui_shred_event_iter_t shred_it[ 1 ];
  fd_gui_shred_event_iter_begin( gui, shred_it, 0L, 0L );
  FD_TEST( fd_gui_shred_event_iter_next( shred_it ) );
  fd_gui_shred_event_iter_end( shred_it );
  fd_gui_shred_event_iter_begin( gui, shred_it, -sec_ns( 2UL ), 0L );
  FD_TEST( fd_gui_shred_event_iter_next( shred_it ) );
  fd_gui_shred_event_t const * shred = &shred_it->event;
  FD_TEST( shred->event_time_ns==-sec_ns( 2UL ) && shred->insert_time_ns==0L && shred->slot==1UL );
  FD_TEST( !fd_gui_shred_event_iter_next( shred_it ) );
  fd_gui_shred_event_iter_end( shred_it );

  fd_gui_hist_iter_t it[ 1 ];
  append_replay_txn( gui, sec_ns( 100UL ), sec_ns( 100UL ), 2UL );
  append_replay_txn( gui, sec_ns( 101UL ), sec_ns( 10UL ), 3UL );

  FD_TEST( !fd_gui_hist_range_begin( gui, it, FD_GUI_HIST_REPLAY_TXN,
                                     sec_ns( 100UL ), sec_ns( 101UL ), NULL, NULL ) );
  ulong found = 0UL;
  while( fd_gui_hist_range_next( it ) ) {
    fd_gui_store_replay_txn_t const * rec = it->rec;
    if( rec->slot==2UL ) { FD_TEST( rec->completion_time_ns==sec_ns( 100UL ) ); FD_TEST( rec->insert_time_ns==sec_ns( 100UL ) ); found |= 1UL; }
    if( rec->slot==3UL ) { FD_TEST( rec->completion_time_ns==sec_ns( 10UL ) ); FD_TEST( rec->insert_time_ns==sec_ns( 101UL ) ); found |= 2UL; }
  }
  fd_gui_hist_range_end( it );
  FD_TEST( found==3UL );

  append_replay_txn( gui, sec_ns( 101UL ), LONG_MIN, 4UL );
  fd_gui_store_metrics_t metrics_before = *fd_gui_store_metrics( gui->db );
  ulong free_before = fd_gui_store_free_region_cnt( gui->db );
  fd_gui_store_replay_txn_t regression = { .completion_time_ns=LONG_MAX, .insert_time_ns=sec_ns( 100UL ), .slot=5UL };
  fd_gui_store_replay_txn_t unchanged;
  memcpy( &unchanged, &regression, sizeof(unchanged) );
  FD_TEST( fd_gui_hist_ts_append( gui, FD_GUI_HIST_REPLAY_TXN, &regression )==-1 );
  FD_TEST( !memcmp( &regression, &unchanged, sizeof(regression) ) );
  FD_TEST( !memcmp( &metrics_before, fd_gui_store_metrics( gui->db ), sizeof(metrics_before) ) );
  FD_TEST( fd_gui_store_free_region_cnt( gui->db )==free_before );
  append_replay_txn( gui, sec_ns( 101UL ), LONG_MAX, 6UL );

  FD_TEST( !fd_gui_hist_range_begin( gui, it, FD_GUI_HIST_REPLAY_TXN, sec_ns( 101UL ), sec_ns( 101UL ), NULL, NULL ) );
  long const source_times[] = { sec_ns( 10UL ), LONG_MIN, LONG_MAX };
  for( ulong i=0UL; i<3UL; i++ ) {
    FD_TEST( fd_gui_hist_range_next( it ) );
    fd_gui_store_replay_txn_t const * rec = it->rec;
    FD_TEST( rec->insert_time_ns==sec_ns( 101UL ) );
    FD_TEST( rec->completion_time_ns==source_times[ i ] );
  }
  FD_TEST( !fd_gui_hist_range_next( it ) );
  fd_gui_hist_range_end( it );

  ulong reads_before   = fd_gui_store_metrics( gui->db )->ts_reads       [ FD_GUI_HIST_REPLAY_TXN ];
  ulong records_before = fd_gui_store_metrics( gui->db )->ts_read_records[ FD_GUI_HIST_REPLAY_TXN ];
  FD_TEST( !fd_gui_hist_range_begin( gui, it, FD_GUI_HIST_REPLAY_TXN,
                                     sec_ns( 102UL ), sec_ns( 102UL ), NULL, NULL ) );
  FD_TEST( !fd_gui_hist_range_next( it ) );
  fd_gui_hist_range_end( it );
  FD_TEST( fd_gui_store_metrics( gui->db )->ts_reads[ FD_GUI_HIST_REPLAY_TXN ]==reads_before );
  FD_TEST( fd_gui_store_metrics( gui->db )->ts_read_records[ FD_GUI_HIST_REPLAY_TXN ]==records_before );

  FD_LOG_NOTICE(( "test_range_live_timestamp_bounds: ok" ));
}

static void
test_txn_insert_bounds( fd_gui_t * gui ) {
  fd_txn_e_t txn[ 1 ] = {0};
  txn->txnp->payload[ 0 ]  = 1U;
  txn->txnp->payload[ 65 ] = 1U;
  txn->txnp->payload[ 68 ] = 1U;
  txn->txnp->payload_sz = 134UL;
  txn->txnp->source_tpu = FD_TXN_M_TPU_SOURCE_UDP;
  FD_TEST( fd_txn_parse( txn->txnp->payload, txn->txnp->payload_sz, TXN( txn->txnp ), NULL ) );

  ulong const slot_num = 500UL;
  ulong const bank_seq = 7UL;
  fd_gui_leader_slot_t * lslot = fd_gui_slot_leader_get_or_create( gui, slot_num, bank_seq );
  FD_TEST( lslot );
  FD_TEST( lslot->txn_insert_time_min_ns==LONG_MAX && lslot->txn_insert_time_max_ns==LONG_MIN );
  fd_txn_ns_dt_t dt = {0};
  for( ulong i=0UL; i<2UL; i++ ) {
    long start_ns = sec_ns( 11UL-i );
    fd_gui_microblock_execution_begin( gui, start_ns, slot_num, txn, 1UL, (uint)i, i, bank_seq, sec_ns( 100UL+i ) );
    fd_gui_microblock_execution_end( gui, start_ns+100L, i, slot_num, 1UL, txn->txnp, i, dt, LONG_MAX, 0UL, bank_seq, sec_ns( 102UL+i ) );
  }
  lslot = fd_gui_slot_leader_get( gui, slot_num, bank_seq );
  FD_TEST( lslot && lslot->begin_microblocks==2U && lslot->end_microblocks==2U );
  FD_TEST( lslot->txn_insert_time_min_ns==sec_ns( 100UL ) );
  FD_TEST( lslot->txn_insert_time_max_ns==sec_ns( 103UL ) );
  lslot->leader_start_time       = sec_ns( 10UL );
  lslot->leader_end_time         = sec_ns( 12UL );
  lslot->microblocks_upper_bound = 2U;
  lslot->unbecame_leader         = 1U;
  fd_done_packing_t scheduler_stats;
  fd_memcpy( &scheduler_stats, lslot->scheduler_stats, sizeof(scheduler_stats) );
  scheduler_stats.end_slot_reason = FD_PACK_END_SLOT_REASON_TIME;
  fd_memcpy( lslot->scheduler_stats, &scheduler_stats, sizeof(scheduler_stats) );

  fd_gui_leader_slot_t * other = fd_gui_slot_leader_get_or_create( gui, slot_num, bank_seq-1UL );
  FD_TEST( other );
  fd_gui_microblock_execution_begin( gui, sec_ns( 50UL ), slot_num, txn, 1UL, 0U, 0UL, bank_seq-1UL, sec_ns( 101UL ) );
  fd_gui_microblock_execution_end( gui, sec_ns( 50UL )+1L, 0UL, slot_num, 1UL, txn->txnp, 0UL, dt, LONG_MAX, 0UL, bank_seq-1UL, sec_ns( 103UL ) );

  fd_gui_slot_t slot = { .slot=slot_num, .bank_seq=bank_seq, .parent_slot=ULONG_MAX,
                         .completed_time=LONG_MAX, .level=FD_GUI_SLOT_LEVEL_COMPLETED,
                         .skip=FD_GUI_SKIP_STATUS_NOT_SKIPPED, .vote_slot=ULONG_MAX };
  fd_gui_store_txn_start_t starts[ 2 ];
  fd_gui_store_txn_end_t   ends[ 2 ];
  fd_gui_slot_txn_join_t   joined[ 2 ];
  gui->slot_txn_scratch.starts = starts;
  gui->slot_txn_scratch.ends   = ends;
  gui->slot_txn_scratch.joined = joined;
  gui->slot_txn_scratch.max    = 2UL;

  void * http_mem = test_http_open( gui, 1UL<<20 );
  fd_gui_printf_slot_transactions_request( gui, slot_num, 1UL, &slot );
  FD_TEST( !gui->http->stage_err );
  ulong len = fd_http_server_stage_len( gui->http );
  FD_TEST( len && gui->http->stage_off%gui->http->oring_sz+len<=gui->http->oring_sz );
  fd_jtok_t j[1];
  fd_jtok_init( j, (char const *)gui->http->oring+gui->http->stage_off%gui->http->oring_sz, len );
  fd_jtok_str_t key;
  int has_start_times = 0;
  int has_end_times   = 0;
  fd_jtok_obj_enter( j );
  while( fd_jtok_obj_next( j, &key ) ) {
    if( !fd_jtok_str_eq( &key, "value" ) ) continue;
    fd_jtok_obj_enter( j );
    while( fd_jtok_obj_next( j, &key ) ) {
      if( !fd_jtok_str_eq( &key, "transactions" ) ) continue;
      fd_jtok_obj_enter( j );
      while( fd_jtok_obj_next( j, &key ) ) {
        int is_start = fd_jtok_str_eq( &key, "txn_mb_start_timestamps_nanos" );
        int is_end   = fd_jtok_str_eq( &key, "txn_mb_end_timestamps_nanos" );
        if( !is_start && !is_end ) continue;
        char const * expected[ 2 ] = { is_start ? "11000000000" : "11000000100",
                                      is_start ? "10000000000" : "10000000100" };
        ulong cnt = 0UL;
        fd_jtok_arr_enter( j );
        while( fd_jtok_arr_next( j ) ) {
          fd_jtok_str_t timestamp;
          fd_jtok_str( j, &timestamp );
          FD_TEST( !fd_jtok_err( j ) && cnt<2UL );
          FD_TEST( fd_jtok_str_eq( &timestamp, expected[ cnt++ ] ) );
        }
        FD_TEST( cnt==2UL );
        has_start_times |= is_start;
        has_end_times   |= is_end;
      }
    }
  }
  FD_TEST( !fd_jtok_fini( j ) && has_start_times && has_end_times );

  fd_gui_store_metrics_t const * metrics = fd_gui_store_metrics( gui->db );
  ulong start_appends = metrics->ts_appends[ FD_GUI_HIST_TXN_START ];
  ulong end_appends   = metrics->ts_appends[ FD_GUI_HIST_TXN_END ];
  fd_gui_microblock_execution_begin( gui, sec_ns( 20UL ), slot_num, txn, 1UL, 2U, 2UL, bank_seq, sec_ns( 99UL ) );
  fd_gui_microblock_execution_end( gui, sec_ns( 20UL )+1L, 0UL, slot_num, 1UL, txn->txnp, 2UL, dt, LONG_MAX, 0UL, bank_seq, sec_ns( 99UL ) );
  FD_TEST( metrics->ts_appends[ FD_GUI_HIST_TXN_START ]==start_appends );
  FD_TEST( metrics->ts_appends[ FD_GUI_HIST_TXN_END   ]==end_appends );
  lslot = fd_gui_slot_leader_get( gui, slot_num, bank_seq );
  FD_TEST( lslot->txn_insert_time_min_ns==sec_ns( 100UL ) );
  FD_TEST( lslot->txn_insert_time_max_ns==sec_ns( 103UL ) );

  fd_gui_microblock_execution_begin( gui, sec_ns( 20UL ), slot_num, txn, 1UL, 2U, 2UL, bank_seq+1UL, sec_ns( 99UL ) );
  fd_gui_microblock_execution_end( gui, sec_ns( 20UL )+1L, 0UL, slot_num, 1UL, txn->txnp, 2UL, dt, LONG_MAX, 0UL, bank_seq+1UL, sec_ns( 99UL ) );
  other = fd_gui_slot_leader_get( gui, slot_num, bank_seq+1UL );
  FD_TEST( other && other->txn_insert_time_min_ns==LONG_MAX && other->txn_insert_time_max_ns==LONG_MIN );

  test_http_close( gui, http_mem );
  memset( &gui->slot_txn_scratch, 0, sizeof(gui->slot_txn_scratch) );
  FD_LOG_NOTICE(( "test_txn_insert_bounds: ok" ));
}

static void
test_waterfall_snapshots( fd_gui_t * gui ) {
  fd_topo_t * topo = calloc( 1UL, sizeof(fd_topo_t) );
  FD_TEST( topo );
  gui->topo = topo;
  gui->leader_slot_pending     = ULONG_MAX;
  gui->leader_bank_seq_pending = ULONG_MAX;
  memset( gui->summary.txn_waterfall_reference, 0, sizeof(gui->summary.txn_waterfall_reference) );

  fd_done_packing_t done_packing = { .microblocks_in_slot = 7UL };
  fd_gui_txn_waterfall_t zero = {0};

  fd_gui_leader_slot_t * first = fd_gui_slot_leader_get_or_create( gui, 100UL, 11UL );
  FD_TEST( first );
  fd_gui_unbecame_leader( gui, 100UL, &done_packing );
  FD_TEST( !first->has_waterfall );
  FD_TEST( gui->leader_slot_pending==100UL && gui->leader_bank_seq_pending==11UL );
  fd_gui_done_draining( gui, 123L );
  FD_TEST( first->has_waterfall );
  FD_TEST( !memcmp( first->waterfall_reference, &zero, sizeof(zero) ) );
  FD_TEST( !memcmp( first->waterfall,       &(long){ 123L }, sizeof(long)         ) );
  FD_TEST( !memcmp( first->scheduler_stats, &done_packing,   sizeof(done_packing) ) );
  FD_TEST( !memcmp( gui->summary.txn_waterfall_reference, first->waterfall, sizeof(fd_gui_txn_waterfall_t) ) );
  FD_TEST( fd_gui_slot_leader_get( gui, 100UL, 11UL )==first );
  FD_TEST( !fd_gui_slot_leader_get( gui, 100UL, 12UL ) );

  fd_gui_leader_slot_t * second = fd_gui_slot_leader_get_or_create( gui, 104UL, 22UL );
  FD_TEST( second );
  fd_gui_unbecame_leader( gui, 104UL, &done_packing );
  FD_TEST( !second->has_waterfall );
  fd_gui_done_draining( gui, 456L );
  FD_TEST( second->has_waterfall );
  FD_TEST( !memcmp( second->waterfall_reference, first->waterfall, sizeof(fd_gui_txn_waterfall_t) ) );
  FD_TEST( !memcmp( second->waterfall, &(long){ 456L }, sizeof(long) ) );
  FD_TEST( !memcmp( gui->summary.txn_waterfall_reference, second->waterfall, sizeof(fd_gui_txn_waterfall_t) ) );

  fd_gui_unbecame_leader( gui, 104UL, &done_packing );
  fd_gui_done_draining( gui, 789L );
  FD_TEST( !memcmp( second->waterfall_reference, first->waterfall, sizeof(fd_gui_txn_waterfall_t) ) );
  FD_TEST( !memcmp( second->waterfall, &(long){ 456L }, sizeof(long) ) );

  free( topo );
  FD_LOG_NOTICE(( "test_waterfall_snapshots: ok" ));
}

static void
assert_shreds( fd_gui_t *                   gui,
               fd_gui_shred_event_t const * events,
               ulong                        cnt,
               long                         lo,
               long                         hi ) {
  fd_gui_shred_event_iter_t it[ 1 ];
  fd_gui_shred_event_iter_begin( gui, it, lo, hi );
  for( ulong i=0UL; i<cnt; i++ ) {
    FD_TEST( fd_gui_shred_event_iter_next( it ) );
    FD_TEST( !memcmp( &it->event, events+i, sizeof(*events) ) );
  }
  FD_TEST( !fd_gui_shred_event_iter_next( it ) );
  fd_gui_shred_event_iter_end( it );
}

static void
test_shred_closure_codec( fd_gui_t * gui ) {
  ulong const cnt = 2048UL;
  long const ts  = sec_ns( 100UL );
  long const now = ts + 500000000L;
  fd_gui_shred_event_t * events = malloc( cnt*sizeof(fd_gui_shred_event_t) );
  FD_TEST( events );
  for( ulong i=0UL; i<cnt; i++ ) {
    events[ i ] = (fd_gui_shred_event_t){ .insert_time_ns=now, .event_time_ns=ts+(long)(i%17UL),
      .slot=700U, .idx=(ushort)(i%512UL), .event=FD_GUI_SLOT_SHRED_SHRED_RECEIVED_TURBINE };
    fd_gui_shred_event_append( gui, events[ i ].slot, events[ i ].idx, events[ i ].event, events[ i ].event_time_ns, now );
  }
  fd_gui_shred_event_append( gui, 701UL, 0UL, FD_GUI_SLOT_SHRED_REPAIR_REQUEST, ts+20L, now );
  FD_TEST( count_ts( gui, FD_GUI_HIST_SHRED_EVENTS, ULONG_MAX )==cnt+1UL );
  FD_TEST( fd_gui_store_metrics( gui->db )->ts_appends[ FD_GUI_HIST_SHRED_EVENTS ]>1UL );

  fd_gui_shred_event_iter_t it[ 1 ];
  fd_gui_shred_event_hist_iter_begin( gui, it, ts, ts+30L );
  FD_TEST( fd_gui_shred_event_iter_next( it ) );
  fd_gui_shred_event_iter_end( it );
  fd_gui_shred_event_iter_begin( gui, it, now, now );
  ulong live = 0UL;
  while( fd_gui_shred_event_iter_next( it ) ) {
    FD_TEST( it->event.insert_time_ns==now );
    live++;
  }
  fd_gui_shred_event_iter_end( it );
  FD_TEST( live==cnt+1UL );

  fd_gui_shred_event_slot_complete( gui, 700UL, ts+30L, now );
  FD_TEST( count_ts( gui, FD_GUI_HIST_SHRED_EVENTS, ULONG_MAX )==cnt+2UL );
  FD_TEST( fd_gui_store_metrics( gui->db )->ts_appends[ FD_GUI_HIST_SHRED_EVENTS ]>1UL );
  fd_gui_shred_event_hist_iter_begin( gui, it, ts, ts+31L );
  for( ulong i=0UL; i<cnt; i++ ) {
    FD_TEST( fd_gui_shred_event_iter_next( it ) );
    FD_TEST( !memcmp( &it->event, events+i, sizeof(*events) ) );
  }
  FD_TEST( fd_gui_shred_event_iter_next( it ) );
  FD_TEST( it->event.slot==701U && it->event.event_time_ns==ts+20L );
  FD_TEST( fd_gui_shred_event_iter_next( it ) );
  FD_TEST( it->event.slot==700U && it->event.idx==USHORT_MAX &&
           it->event.event==FD_GUI_SLOT_SHRED_SHRED_SLOT_COMPLETE &&
           it->event.event_time_ns==ts+30L && it->event.insert_time_ns==now );
  FD_TEST( !fd_gui_shred_event_iter_next( it ) );
  fd_gui_shred_event_iter_end( it );

  fd_gui_hist_iter_t hi[ 1 ];
  FD_TEST( !fd_gui_hist_range_begin( gui, hi, FD_GUI_HIST_SHRED_EVENTS, now, now, NULL, NULL ) );
  ulong sealed = 0UL;
  while( fd_gui_hist_range_next( hi ) ) {
    fd_gui_shred_batch_t const * batch = hi->rec;
    FD_TEST( hi->rec_sz==FD_GUI_SHRED_BATCH_SZ && batch->insert_time_ns==ts );
    FD_TEST( batch->event_cnt && batch->data_sz<=sizeof(batch->data) );
    sealed += batch->event_cnt;
  }
  fd_gui_hist_range_end( hi );
  FD_TEST( sealed+gui->shreds.builder.batch.event_cnt==cnt+2UL );

  fd_gui_shred_event_hist_iter_begin( gui, it, ts, ts+1L );
  ulong at_start = 0UL;
  while( fd_gui_shred_event_iter_next( it ) ) {
    FD_TEST( it->event.event_time_ns==ts );
    at_start++;
  }
  fd_gui_shred_event_iter_end( it );
  FD_TEST( at_start==(cnt+16UL)/17UL );
  fd_gui_shred_event_hist_iter_begin( gui, it, ts+17L, ts+20L );
  FD_TEST( !fd_gui_shred_event_iter_next( it ) );
  fd_gui_shred_event_iter_end( it );

  /* Replay completion does not close the slot: an event the GUI reads
     after the completion (on another link) is still recorded. */
  fd_gui_shred_event_append( gui, 700UL, 1UL, FD_GUI_SLOT_SHRED_REPAIR_REQUEST, ts+31L, now );
  FD_TEST( !gui->shreds.dropped_event_cnt );
  fd_gui_shred_event_slot_complete( gui, 700UL, ts+32L, now+1L );
  fd_gui_shred_event_hist_iter_begin( gui, it, ts+30L, ts+33L );
  FD_TEST( fd_gui_shred_event_iter_next( it ) );
  FD_TEST( it->event.event==FD_GUI_SLOT_SHRED_SHRED_SLOT_COMPLETE && it->event.event_time_ns==ts+30L );
  FD_TEST( fd_gui_shred_event_iter_next( it ) );
  FD_TEST( it->event.slot==700U && it->event.event==FD_GUI_SLOT_SHRED_REPAIR_REQUEST && it->event.event_time_ns==ts+31L );
  FD_TEST( fd_gui_shred_event_iter_next( it ) );
  FD_TEST( it->event.event==FD_GUI_SLOT_SHRED_SHRED_SLOT_COMPLETE && it->event.event_time_ns==ts+32L );
  FD_TEST( !fd_gui_shred_event_iter_next( it ) );
  fd_gui_shred_event_iter_end( it );

  ulong active = gui->shreds.builder.batch.event_cnt;
  fd_gui_event_closed_slot_wmark_advance( gui, 702UL );
  FD_TEST( gui->shreds.builder.batch.event_cnt==active );
  fd_gui_shred_event_append( gui, 700UL, 2UL, FD_GUI_SLOT_SHRED_REPAIR_REQUEST, ts+34L, now+2L );
  FD_TEST( gui->shreds.dropped_event_cnt==1UL );
  fd_gui_shred_event_hist_iter_begin( gui, it, ts+20L, ts+21L );
  FD_TEST( fd_gui_shred_event_iter_next( it ) );
  FD_TEST( it->event.slot==701U && it->event.event==FD_GUI_SLOT_SHRED_REPAIR_REQUEST &&
           it->event.event_time_ns==ts+20L && it->event.insert_time_ns==now );
  FD_TEST( !fd_gui_shred_event_iter_next( it ) );
  fd_gui_shred_event_iter_end( it );
  fd_gui_shred_event_append( gui, 701UL, 1UL, FD_GUI_SLOT_SHRED_REPAIR_REQUEST, ts+33L, now+2L );
  FD_TEST( gui->shreds.dropped_event_cnt==2UL );
  free( events );
  FD_LOG_NOTICE(( "test_shred_closure_codec: ok" ));
}

static void
test_shred_encoding( fd_gui_t * gui ) {
  long const base = sec_ns( 100UL );
  fd_gui_shred_event_t events[] = {
    { base+1L, 1L,        700U, 1U,         FD_GUI_SLOT_SHRED_REPAIR_REQUEST },
    { base+1L, 1L,        700U, 1U,         FD_GUI_SLOT_SHRED_REPAIR_REQUEST },
    { base+2L, 4L,        700U, 255U,       FD_GUI_SLOT_SHRED_SHRED_RECEIVED_TURBINE },
    { base+3L, 2L,        700U, 0U,         FD_GUI_SLOT_SHRED_SHRED_RECEIVED_REPAIR },
    { base+4L, LONG_MAX-1L,701U, 65000U,    FD_GUI_SLOT_SHRED_SHRED_PUBLISHED },
    { base+5L, LONG_MAX,  701U, USHORT_MAX, FD_GUI_SLOT_SHRED_SHRED_SLOT_COMPLETE },
    { base+6L, 0L,        701U, 65000U,     FD_GUI_SLOT_SHRED_SHRED_REPLAY_EXEC_DONE },
    { base+7L, 0L,        701U, 0U,         FD_GUI_SLOT_SHRED_REPAIR_REQUEST },
    { base+8L, 0xFFFFFFL, 701U, 255U,       FD_GUI_SLOT_SHRED_REPAIR_REQUEST },
    { base+9L, 0x1FFFFFFL,701U, 511U,       FD_GUI_SLOT_SHRED_REPAIR_REQUEST },
    { base+10L,0xFFFFFFL, 701U, 256U,       FD_GUI_SLOT_SHRED_REPAIR_REQUEST },
    { base+sec_ns( 1UL ), 100L, 702U, 10U,    FD_GUI_SLOT_SHRED_SHRED_RECEIVED_TURBINE }
  };
  ulong cnt = sizeof(events)/sizeof(events[0]);
  for( ulong i=0UL; i<cnt; i++ ) {
    fd_gui_shred_event_t const * e = events+i;
    fd_gui_shred_event_append( gui, e->slot, e->idx, e->event, e->event_time_ns, e->insert_time_ns );
  }
  FD_TEST( fd_gui_store_metrics( gui->db )->ts_appends[ FD_GUI_HIST_SHRED_EVENTS ]==1UL );
  FD_TEST( gui->shreds.builder.batch.event_cnt==1U );
  FD_TEST( fd_gui_shred_window_is_empty( gui, 0L, 10L ) );
  assert_shreds( gui, events, cnt, LONG_MIN, LONG_MAX );


  fd_gui_shred_flush( gui, base+sec_ns( 1UL )+1L );
  FD_TEST( gui->shreds.builder.batch.event_cnt==1U );
  fd_gui_shred_flush( gui, base+sec_ns( 2UL ) );
  FD_TEST( !gui->shreds.builder.batch.event_cnt );
  assert_shreds( gui, events, cnt, LONG_MIN, LONG_MAX );
  FD_TEST( !gui->shreds.dropped_event_cnt );
  FD_LOG_NOTICE(( "test_shred_encoding: ok" ));
}

static void
test_shred_event_batches( fd_gui_t * gui ) {
  long split_base = sec_ns( 30UL );
  fd_gui_shred_event_iter_t it[ 1 ];
  ulong dropped_event_cnt = gui->shreds.dropped_event_cnt;
  fd_gui_shred_event_append( gui, (ulong)UINT_MAX+1UL, 0UL, FD_GUI_SLOT_SHRED_SHRED_RECEIVED_TURBINE, split_base, split_base );
  fd_gui_shred_event_append( gui, 704UL, USHORT_MAX, FD_GUI_SLOT_SHRED_SHRED_RECEIVED_TURBINE, split_base, split_base );
  FD_TEST( gui->shreds.dropped_event_cnt==dropped_event_cnt+2UL );

  fd_gui_shred_event_append( gui, 705UL, 0UL, FD_GUI_SLOT_SHRED_SHRED_RECEIVED_TURBINE, sec_ns( 30UL )-1L, split_base );
  fd_gui_shred_event_slot_complete( gui, 705UL, sec_ns( 30UL )+1L, sec_ns( 30UL )+500000000L );
  fd_gui_shred_event_hist_iter_begin( gui, it, sec_ns( 30UL )-1L, sec_ns( 30UL ) );
  FD_TEST( fd_gui_shred_event_iter_next( it ) );
  FD_TEST( it->event.event_time_ns==sec_ns( 30UL )-1L );
  FD_TEST( !fd_gui_shred_event_iter_next( it ) );
  fd_gui_shred_event_iter_end( it );
  fd_gui_shred_event_hist_iter_begin( gui, it, sec_ns( 30UL )+1L, sec_ns( 30UL )+2L );
  FD_TEST( fd_gui_shred_event_iter_next( it ) );
  FD_TEST( it->event.event_time_ns==sec_ns( 30UL )+1L );
  FD_TEST( !fd_gui_shred_event_iter_next( it ) );
  fd_gui_shred_event_iter_end( it );

  fd_gui_shred_event_append( gui, 706UL, 0UL, FD_GUI_SLOT_SHRED_SHRED_RECEIVED_TURBINE, sec_ns( 32UL ), sec_ns( 31UL )+999999999L );
  fd_gui_shred_event_slot_complete( gui, 706UL, sec_ns( 32UL )+1L, sec_ns( 31UL )+999999999L );
  fd_gui_shred_event_hist_iter_begin( gui, it, sec_ns( 32UL ), sec_ns( 32UL )+1L );
  FD_TEST( fd_gui_shred_event_iter_next( it ) );
  FD_TEST( it->event.slot==706UL && it->event.event_time_ns==sec_ns( 32UL ) );
  FD_TEST( !fd_gui_shred_event_iter_next( it ) );
  fd_gui_shred_event_iter_end( it );

  fd_gui_shred_event_append( gui, 704UL, 1UL, FD_GUI_SLOT_SHRED_SHRED_RECEIVED_TURBINE, 0L, sec_ns( 40UL ) );
  fd_gui_shred_event_slot_complete( gui, 704UL, 0L, sec_ns( 40UL ) );
  fd_gui_shred_event_iter_begin( gui, it, 0L, 0L );
  FD_TEST( !fd_gui_shred_event_iter_next( it ) );
  fd_gui_shred_event_iter_end( it );
  fd_gui_shred_event_iter_begin( gui, it, 0L, sec_ns( 40UL ) );
  ulong found_704 = 0UL;
  while( fd_gui_shred_event_iter_next( it ) ) {
    if( it->event.slot!=704UL ) continue;
    FD_TEST( it->event.event_time_ns==0L );
    FD_TEST( it->event.idx==fd_ushort_if( found_704==0UL, 1U, USHORT_MAX ) );
    found_704++;
  }
  FD_TEST( found_704==2UL );
  fd_gui_shred_event_iter_end( it );

  fd_gui_hist_iter_t range_it[ 1 ];
  fd_gui_shred_flush( gui, sec_ns( 41UL ) );
  FD_TEST( !fd_gui_hist_range_begin( gui, range_it, FD_GUI_HIST_SHRED_EVENTS, sec_ns( 40UL ), sec_ns( 40UL ), NULL, NULL ) );
  FD_TEST( fd_gui_hist_range_next( range_it ) );
  fd_gui_shred_batch_t const * batch = range_it->rec;
  FD_TEST( batch->insert_time_ns==sec_ns( 40UL ) && batch->event_cnt==2U );
  FD_TEST( !fd_gui_hist_range_next( range_it ) );
  fd_gui_hist_range_end( range_it );

  fd_gui_shred_event_iter_begin( gui, it, LONG_MIN+1L, LONG_MIN+1L );
  FD_TEST( !fd_gui_shred_event_iter_next( it ) );
  fd_gui_shred_event_iter_end( it );
  fd_gui_shred_event_iter_begin( gui, it, LONG_MAX-1L, LONG_MAX-1L );
  FD_TEST( !fd_gui_shred_event_iter_next( it ) );
  fd_gui_shred_event_iter_end( it );
  fd_gui_shred_event_iter_begin( gui, it, LONG_MIN+1L, LONG_MAX-1L );
  FD_TEST( fd_gui_shred_event_iter_next( it ) );
  fd_gui_shred_event_iter_end( it );

  long const extreme_timestamps[] = { LONG_MIN, 0L, LONG_MIN+1L, LONG_MAX };
  for( ulong i=0UL; i<4UL; i++ ) {
    fd_gui_shred_event_append( gui, 707UL, i, FD_GUI_SLOT_SHRED_SHRED_RECEIVED_TURBINE, extreme_timestamps[ i ], sec_ns( 41UL ) );
  }
  fd_gui_shred_event_slot_complete( gui, 707UL, LONG_MAX, sec_ns( 41UL ) );
  fd_gui_shred_flush( gui, sec_ns( 42UL ) );
  FD_TEST( !fd_gui_hist_range_begin( gui, range_it, FD_GUI_HIST_SHRED_EVENTS, sec_ns( 41UL ), sec_ns( 41UL ), NULL, NULL ) );
  FD_TEST( fd_gui_hist_range_next( range_it ) );
  batch = range_it->rec;
  FD_TEST( batch->insert_time_ns==sec_ns( 41UL ) && batch->event_cnt==2U );
  FD_TEST( !fd_gui_hist_range_next( range_it ) );
  fd_gui_hist_range_end( range_it );
  fd_gui_shred_event_iter_begin( gui, it, LONG_MIN, LONG_MAX );
  ulong extreme_cnt = 0UL;
  while( fd_gui_shred_event_iter_next( it ) ) {
    if( it->event.slot!=707UL ) continue;
    FD_TEST( extreme_cnt<2UL );
    FD_TEST( it->event.event_time_ns==(extreme_cnt ? LONG_MAX : 0L) );
    extreme_cnt++;
  }
  FD_TEST( extreme_cnt==2UL );
  fd_gui_shred_event_iter_end( it );

  FD_LOG_NOTICE(( "test_shred_event_batches: ok" ));
}

static void
test_shred_event_root_reclaim( fd_gui_t * gui ) {
  fd_http_server_params_t params = {
    .max_connection_cnt    = 1UL,
    .max_ws_connection_cnt = 1UL,
    .max_request_len       = 1024UL,
    .max_ws_recv_frame_len = 1024UL,
    .max_ws_send_frame_cnt = 4UL,
    .outgoing_buffer_sz    = 1UL<<20
  };
  ulong http_footprint = fd_http_server_footprint( params );
  void * http_mem = aligned_alloc( fd_http_server_align(), http_footprint );
  FD_TEST( http_mem );
  gui->http = fd_http_server_join( fd_http_server_new( http_mem, params, (fd_http_server_callbacks_t){0}, NULL ) );
  FD_TEST( gui->http );
  gui->summary.slot_rooted = ULONG_MAX;

  fd_gui_shred_event_append( gui, 899UL, 1UL, FD_GUI_SLOT_SHRED_SHRED_RECEIVED_TURBINE, 1L, 1L );
  fd_gui_shred_event_append( gui, 900UL, 2UL, FD_GUI_SLOT_SHRED_SHRED_RECEIVED_REPAIR,  2L, 2L );
  fd_gui_shred_event_append( gui, 901UL, 3UL, FD_GUI_SLOT_SHRED_SHRED_PUBLISHED,        3L, 3L );
  fd_gui_shred_event_append( gui, 898UL, 4UL, FD_GUI_SLOT_SHRED_SHRED_REPLAY_EXEC_DONE, 4L, 4L );
  fd_gui_shred_event_append( gui, 902UL, 5UL, FD_GUI_SLOT_SHRED_REPAIR_REQUEST,          5L, 5L );

  /* Rooting a slot closes the slots below its parent. */
  put_slot( gui, 901UL, 6L );
  fd_gui_slot_get( gui, 901UL, BANK_SEQ )->parent_slot = ULONG_MAX;
  fd_gui_handle_root_advanced( gui, 901UL, BANK_SEQ, 6L );

  FD_TEST( gui->shreds.closed_slot_wmark==900UL );
  FD_TEST( gui->shreds.builder.batch.event_cnt==5UL );
  FD_TEST( count_ts( gui, FD_GUI_HIST_SHRED_EVENTS, 898UL )==1UL );
  FD_TEST( count_ts( gui, FD_GUI_HIST_SHRED_EVENTS, 899UL )==1UL );

  fd_gui_shred_event_append( gui, 899UL, 6UL, FD_GUI_SLOT_SHRED_SHRED_RECEIVED_TURBINE, 7L, 7L );
  FD_TEST( gui->shreds.dropped_event_cnt==1UL );
  FD_TEST( gui->shreds.builder.batch.event_cnt==5UL );

  put_slot( gui, 900UL, 8L );
  fd_gui_slot_get( gui, 900UL, BANK_SEQ )->parent_slot = ULONG_MAX;
  fd_gui_handle_root_advanced( gui, 901UL, BANK_SEQ, 8L );
  FD_TEST( gui->shreds.closed_slot_wmark==900UL );
  fd_gui_handle_root_advanced( gui, 900UL, BANK_SEQ, 8L );
  FD_TEST( gui->shreds.closed_slot_wmark==900UL );

  put_slot( gui, 902UL, 9L );
  fd_gui_slot_get( gui, 902UL, BANK_SEQ )->parent_slot = ULONG_MAX;
  fd_gui_handle_root_advanced( gui, 902UL, BANK_SEQ, 9L );

  FD_TEST( gui->shreds.closed_slot_wmark==901UL );
  FD_TEST( gui->shreds.builder.batch.event_cnt==5UL );
  FD_TEST( count_ts( gui, FD_GUI_HIST_SHRED_EVENTS, 899UL )==1UL );
  FD_TEST( count_ts( gui, FD_GUI_HIST_SHRED_EVENTS, 900UL )==1UL );
  fd_gui_shred_event_iter_t it;
  fd_gui_shred_event_iter_begin( gui, &it, 0L, 9L );
  ulong flushed = 0UL;
  while( fd_gui_shred_event_iter_next( &it ) ) {
    FD_TEST( it.event.event!=FD_GUI_SLOT_SHRED_SHRED_SLOT_COMPLETE );
    flushed += it.event.slot<901UL;
  }
  fd_gui_shred_event_iter_end( &it );
  FD_TEST( flushed==3UL );

  /* Completion alone closes nothing; only the root cutoff does. */
  fd_gui_shred_event_slot_complete( gui, 901UL, 10L, 10L );
  FD_TEST( (901UL>=fd_gui_event_closed_slot_wmark( gui )) );
  FD_TEST( count_ts( gui, FD_GUI_HIST_SHRED_EVENTS, 901UL )==2UL );
  fd_gui_shred_event_append( gui, 901UL, 7UL, FD_GUI_SLOT_SHRED_SHRED_RECEIVED_TURBINE, 11L, 11L );
  FD_TEST( gui->shreds.dropped_event_cnt==1UL );
  FD_TEST( count_ts( gui, FD_GUI_HIST_SHRED_EVENTS, 901UL )==3UL );

  put_slot( gui, 903UL, 12L );
  fd_gui_slot_get( gui, 903UL, BANK_SEQ )->parent_slot = ULONG_MAX;
  fd_gui_handle_root_advanced( gui, 903UL, BANK_SEQ, 12L );
  FD_TEST( (901UL<fd_gui_event_closed_slot_wmark( gui )) );
  FD_TEST( (902UL>=fd_gui_event_closed_slot_wmark( gui )) );
  FD_TEST( gui->shreds.builder.batch.event_cnt==7UL );

  FD_TEST( fd_http_server_delete( fd_http_server_leave( gui->http ) )==http_mem );
  free( http_mem );
  gui->http = NULL;

  FD_LOG_NOTICE(( "test_shred_event_root_reclaim: ok" ));
}

static void
test_shred_storage( fd_gui_t * gui ) {
  ulong const cnt = 70000UL;
  long const base = sec_ns( 200UL );
  fd_gui_shred_event_t * events = malloc( cnt*sizeof(fd_gui_shred_event_t) );
  FD_TEST( events );
  for( ulong i=0UL; i<cnt; i++ ) {
    events[ i ] = (fd_gui_shred_event_t){ base+(long)(i/2UL), base+(long)i, (uint)(800UL+i/10000UL),
                                         (ushort)(i%10000UL), FD_GUI_SLOT_SHRED_SHRED_RECEIVED_TURBINE };
    fd_gui_shred_event_t const * e = events+i;
    fd_gui_shred_event_append( gui, e->slot, e->idx, e->event, e->event_time_ns, e->insert_time_ns );
  }
  ulong sealed = fd_gui_store_metrics( gui->db )->ts_appends[ FD_GUI_HIST_SHRED_EVENTS ];
  FD_TEST( sealed>1UL && gui->shreds.builder.batch.event_cnt );
  assert_shreds( gui, events, cnt, base, base+(long)cnt );
  assert_shreds( gui, events+800UL, 400UL, base+400L, base+599L );
  fd_gui_shred_flush( gui, base+sec_ns( 1UL ) );
  ulong bytes = fd_gui_store_metrics( gui->db )->ts_appends[ FD_GUI_HIST_SHRED_EVENTS ]*sizeof(fd_gui_shred_batch_t);
  FD_TEST( bytes<cnt*10UL ); /* nine-byte common encoding plus block overhead */
  FD_TEST( !gui->shreds.builder.batch.event_cnt );
  assert_shreds( gui, events, cnt, base, base+(long)cnt );
  free( events );

  /* Sparse seconds pay for one block each and are sealed by the next event. */
  sealed = fd_gui_store_metrics( gui->db )->ts_appends[ FD_GUI_HIST_SHRED_EVENTS ];
  fd_gui_shred_event_t sparse[ 8 ];
  for( ulong i=0UL; i<8UL; i++ ) {
    sparse[ i ] = (fd_gui_shred_event_t){ base+sec_ns( 2UL+i ), base+sec_ns( 2UL+i ), 808U, 0U, FD_GUI_SLOT_SHRED_REPAIR_REQUEST };
    fd_gui_shred_event_append( gui, sparse[i].slot, sparse[i].idx, sparse[i].event, sparse[i].event_time_ns, sparse[i].insert_time_ns );
  }
  FD_TEST( fd_gui_store_metrics( gui->db )->ts_appends[ FD_GUI_HIST_SHRED_EVENTS ]==sealed+7UL );
  assert_shreds( gui, sparse, 8UL, sparse[ 0 ].event_time_ns, sparse[ 7 ].event_time_ns );
  fd_gui_shred_flush( gui, base+sec_ns( 10UL ) );
  FD_TEST( fd_gui_store_metrics( gui->db )->ts_appends[ FD_GUI_HIST_SHRED_EVENTS ]==sealed+8UL );
  FD_TEST( !gui->shreds.dropped_event_cnt );
  FD_LOG_NOTICE(( "test_shred_storage: %lu events in %lu bytes; ok", cnt, bytes ));
}

static void
test_shred_flush_full( fd_gui_t * gui,
                       int        tail_oldest ) {
  long const base = sec_ns( 300UL );
  fd_gui_shred_event_t event = { base+sec_ns( 2UL ), base, 900U, 0U, FD_GUI_SLOT_SHRED_REPAIR_REQUEST };
  fd_gui_shred_event_append( gui, event.slot, event.idx, event.event, event.event_time_ns, event.insert_time_ns );
  /* Fill another ring without invoking history's pressure eviction. */
  fd_gui_scheduler_counts_t counts = { .sample_time_ns=base+(tail_oldest ? sec_ns( 1UL ) : -sec_ns( 1UL )) };
  while( fd_gui_store_ts_append( gui->db, FD_GUI_HIST_SCHEDULER_COUNTS, &counts )==FD_GUI_STORE_SUCCESS ) {}
  FD_TEST( !fd_gui_store_shared_free_region_cnt( gui->db ) );
  if( tail_oldest==2 ) {
    /* Unrelated history writes only evict stored records. */
    append_sched_counts( gui, counts.sample_time_ns );
    FD_TEST( gui->shreds.builder.batch.event_cnt==1UL );
    FD_TEST( !fd_gui_shred_window_is_empty( gui, event.insert_time_ns, event.insert_time_ns ) );
  }
  fd_gui_shred_flush( gui, base+sec_ns( 3UL ) );
  FD_TEST( !gui->shreds.builder.batch.event_cnt );
  FD_TEST( fd_gui_store_metrics( gui->db )->ts_appends[ FD_GUI_HIST_SHRED_EVENTS ]==1UL );
  FD_TEST( !gui->shreds.dropped_event_cnt );
  assert_shreds( gui, &event, 1UL, base, base+sec_ns( 2UL ) );
  fd_gui_shred_flush( gui, base+sec_ns( 3UL ) );
  assert_shreds( gui, &event, 1UL, base, base+sec_ns( 2UL ) );
  FD_LOG_NOTICE(( "test_shred_flush_full: tail_oldest=%i; ok", tail_oldest ));
}

static void
test_shred_retention( fd_gui_t * gui ) {
  long const base = sec_ns( 400UL );
  /* An active-only second is outside store retention. */
  fd_gui_shred_event_append( gui, 900UL, 0UL, FD_GUI_SLOT_SHRED_REPAIR_REQUEST, base, base );
  FD_TEST( !fd_gui_store_metrics( gui->db )->ts_appends[ FD_GUI_HIST_SHRED_EVENTS ] );
  FD_TEST( !fd_gui_hist_evict_step( gui ) );
  FD_TEST( !fd_gui_shred_window_is_empty( gui, base, base ) );
  FD_TEST( gui->shreds.builder.batch.event_cnt==1UL );
  fd_gui_shred_flush( gui, base+sec_ns( 1UL ) );
  FD_TEST( !fd_gui_hist_evict_step( gui ) ); /* base survives background pressure */
  FD_TEST( fd_gui_store_reclaim( gui->db, FD_GUI_HIST_SHRED_EVENTS, ULONG_MAX, NULL, NULL ) );
  FD_TEST( fd_gui_shred_window_is_empty( gui, base, base ) );
  FD_TEST( !fd_gui_hist_evict_step( gui ) );

  for( ulong i=0UL; i<1000UL; i++ )
    fd_gui_shred_event_append( gui, 901UL, i, FD_GUI_SLOT_SHRED_REPAIR_REQUEST, base+sec_ns( 2UL )+(long)i, base+sec_ns( 2UL )+(long)i );
  fd_gui_shred_event_append( gui, 902UL, 0UL, FD_GUI_SLOT_SHRED_REPAIR_REQUEST, base+sec_ns( 3UL ), base+sec_ns( 3UL ) );
  FD_TEST( count_ts( gui, FD_GUI_HIST_SHRED_EVENTS, ULONG_MAX )==1001UL );
  FD_TEST( fd_gui_store_reclaim( gui->db, FD_GUI_HIST_SHRED_EVENTS, ULONG_MAX, NULL, NULL ) );
  FD_TEST( gui->shreds.builder.batch.event_cnt==1UL );
  FD_TEST( count_ts( gui, FD_GUI_HIST_SHRED_EVENTS, ULONG_MAX )==1UL );
  FD_TEST( !fd_gui_hist_evict_step( gui ) );
  fd_gui_shred_flush( gui, base+sec_ns( 4UL ) );
  FD_TEST( count_ts( gui, FD_GUI_HIST_SHRED_EVENTS, ULONG_MAX )==1UL );
  FD_TEST( fd_gui_store_reclaim( gui->db, FD_GUI_HIST_SHRED_EVENTS, ULONG_MAX, NULL, NULL ) );
  FD_TEST( fd_gui_shred_window_is_empty( gui, base, LONG_MAX ) );
  FD_TEST( !fd_gui_hist_evict_step( gui ) );
  FD_LOG_NOTICE(( "test_shred_retention: ok" ));
}

static void
test_shred_epoch_retention( fd_gui_t * gui,
                            ulong      cnt ) {
  put_epoch( gui, EPOCH_A, A_START_SLOT, SLOT_CNT );
  put_epoch( gui, EPOCH_B, B_START_SLOT, SLOT_CNT );
  put_epoch( gui, EPOCH_C, C_START_SLOT, SLOT_CNT );
  for( ulong i=0UL; i<cnt; i++ ) {
    fd_gui_shred_event_append( gui, A_START_SLOT, i, FD_GUI_SLOT_SHRED_REPAIR_REQUEST, (long)i, sec_ns( 19UL ) );
  }
  put_slot( gui, A_START_SLOT, sec_ns( 10UL ) );
  put_slot( gui, B_START_SLOT, sec_ns( 20UL ) );
  put_slot( gui, C_START_SLOT, sec_ns( 30UL ) );
  FD_TEST( gui->shreds.builder.batch.event_cnt );
  ulong tail_cnt = gui->shreds.builder.batch.event_cnt;
  FD_TEST( count_ts( gui, FD_GUI_HIST_SHRED_EVENTS, ULONG_MAX )==cnt );
  FD_TEST( !fd_gui_hist_evict_step( gui ) );
  FD_TEST( gui->shreds.builder.batch.event_cnt==tail_cnt );
  FD_TEST( count_ts( gui, FD_GUI_HIST_SHRED_EVENTS, ULONG_MAX )==cnt );
  fd_gui_shred_flush( gui, sec_ns( 20UL ) );
  FD_TEST( !gui->shreds.builder.batch.event_cnt );
  FD_TEST( count_ts( gui, FD_GUI_HIST_SHRED_EVENTS, ULONG_MAX )==cnt );
  FD_TEST( fd_gui_store_reclaim( gui->db, FD_GUI_HIST_SHRED_EVENTS, ULONG_MAX, NULL, NULL ) );
  FD_TEST( count_ts( gui, FD_GUI_HIST_SHRED_EVENTS, ULONG_MAX )==0UL );

  /* Background pressure leaves active and stored base history intact. */
  put_epoch( gui, EPOCH_C+1UL, C_START_SLOT+SLOT_CNT, SLOT_CNT );
  put_slot( gui, C_START_SLOT+SLOT_CNT, sec_ns( 40UL ) );
  fd_gui_shred_event_t next = { sec_ns( 30UL ), 1L, C_START_SLOT+1UL, 0U, FD_GUI_SLOT_SHRED_REPAIR_REQUEST };
  fd_gui_shred_event_append( gui, next.slot, next.idx, next.event, next.event_time_ns, next.insert_time_ns );
  FD_TEST( !fd_gui_hist_evict_step( gui ) );
  FD_TEST( !fd_gui_shred_window_is_empty( gui, 0L, LONG_MAX ) );
  FD_TEST( gui->shreds.builder.batch.event_cnt==1U );
  fd_gui_shred_flush( gui, sec_ns( 31UL ) );
  assert_shreds( gui, &next, 1UL, 0L, LONG_MAX );
  FD_LOG_NOTICE(( "test_shred_epoch_retention: %lu events; ok", cnt ));
}

/* ---- timeline queries ---------------------------------------------- */

static void *
timeline_http_open( fd_gui_t * gui ) {
  fd_http_server_params_t params = {
    .max_connection_cnt    = 1UL,
    .max_ws_connection_cnt = 1UL,
    .max_request_len       = 1024UL,
    .max_ws_recv_frame_len = 1024UL,
    .max_ws_send_frame_cnt = 4UL,
    .outgoing_buffer_sz    = FD_GUI_HTTP_MIN_SEND_BUFFER_SZ
  };
  void * mem = aligned_alloc( fd_http_server_align(), fd_http_server_footprint( params ) );
  FD_TEST( mem );
  gui->http = fd_http_server_join( fd_http_server_new( mem, params, (fd_http_server_callbacks_t){0}, NULL ) );
  FD_TEST( gui->http );
  return mem;
}

/* Response slices borrow the HTTP staging buffer until the next write. */
typedef struct {
  char const * ptr;
  ulong        sz;
} test_json_t;

static test_json_t
test_json_field( test_json_t  json,
                 char const * field ) {
  fd_jtok_t j[ 1 ];
  fd_jtok_init( j, json.ptr, json.sz );
  fd_jtok_str_t key;
  test_json_t result = {0};
  fd_jtok_obj_enter( j );
  while( fd_jtok_obj_next( j, &key ) ) {
    if( fd_jtok_str_eq( &key, field ) ) fd_jtok_raw( j, &result.ptr, &result.sz );
  }
  FD_TEST( !fd_jtok_fini( j ) );
  return result;
}

static test_json_t
test_json_index( test_json_t json,
                 int         index ) {
  fd_jtok_t j[ 1 ];
  fd_jtok_init( j, json.ptr, json.sz );
  test_json_t result = {0};
  int i = 0;
  fd_jtok_arr_enter( j );
  while( fd_jtok_arr_next( j ) ) {
    if( i++==index ) fd_jtok_raw( j, &result.ptr, &result.sz );
    if( result.ptr ) return result;
  }
  FD_TEST( !fd_jtok_fini( j ) && result.ptr );
  return result;
}

static int
test_json_count( test_json_t json ) {
  fd_jtok_t j[ 1 ];
  fd_jtok_init( j, json.ptr, json.sz );
  int count = 0;
  fd_jtok_arr_enter( j );
  while( fd_jtok_arr_next( j ) ) count++;
  FD_TEST( !fd_jtok_fini( j ) );
  return count;
}

static int
test_json_kind( test_json_t json ) {
  fd_jtok_t j[ 1 ];
  fd_jtok_init( j, json.ptr, json.sz );
  return fd_jtok_peek( j );
}

static ulong
test_json_ulong( test_json_t json ) {
  fd_jtok_t j[ 1 ];
  fd_jtok_init( j, json.ptr, json.sz );
  ulong value = 0UL;
  fd_jtok_ulong( j, &value );
  FD_TEST( !fd_jtok_fini( j ) );
  return value;
}

static int
test_json_string_eq( test_json_t  json,
                     char const * expected ) {
  fd_jtok_t j[ 1 ];
  fd_jtok_init( j, json.ptr, json.sz );
  fd_jtok_str_t value;
  fd_jtok_str( j, &value );
  FD_TEST( !fd_jtok_fini( j ) );
  return fd_jtok_str_eq( &value, expected );
}

static test_json_t
timeline_response( fd_gui_t * gui ) {
  FD_TEST( !gui->http->stage_err );
  ulong len = fd_http_server_stage_len( gui->http );
  FD_TEST( len && gui->http->stage_off%gui->http->oring_sz+len<=gui->http->oring_sz );
  test_json_t json = { (char const *)gui->http->oring+gui->http->stage_off%gui->http->oring_sz, len };
  fd_jtok_t j[ 1 ];
  fd_jtok_init( j, json.ptr, json.sz );
  FD_TEST( !fd_jtok_fini( j ) );
  fd_http_server_stage_trunc( gui->http, 0UL );
  return json;
}

static test_json_t
timeline_value( test_json_t  json,
                char const * field ) {
  return test_json_field( test_json_field( json, "value" ), field );
}

static void
test_fec_event_index( fd_gui_t * gui ) {
  long const ts = sec_ns( 10UL );
  ulong const cnt = FD_GUI_FEC_RECORD_MAX;
  /* The earliest event time a record admitted at ts+30 can hold.  Late
     dedup updates before it are skewed and rejected
     (FD_GUI_FEC_EVENT_LAG_MAX_NS). */
  long const early = ts+30L-FD_GUI_FEC_EVENT_LAG_MAX_NS;
  ulong const clamped0 = gui->shreds.clamped_fec_event_cnt;
  for( ulong i=0UL; i<cnt; i++ ) {
    fd_gui_fec_event_append( gui, 100UL+i/65535UL, i%65535UL, FD_GUI_SLOT_SHRED_REPAIR_REQUEST, ts+20L, ts+30L );
  }
  FD_TEST( !gui->shreds.dropped_fec_event_cnt );
  fd_gui_store_kv_scan_t scan;
  fd_gui_store_kv_scan_begin( gui->db, &scan, FD_GUI_HIST_FEC_EVENTS );
  FD_TEST( scan.end-scan.cur==cnt );
  fd_gui_fec_event_key_t key = { .slot=100U, .idx=0U, .event=FD_GUI_SLOT_SHRED_REPAIR_REQUEST };
  fd_gui_fec_event_t * first = fd_gui_hist_kv_get( gui, FD_GUI_HIST_FEC_EVENTS, &key );
  FD_TEST( first && first->insert_time_ns==ts+30L );
  fd_gui_fec_event_append( gui, 100UL, 0UL, key.event, early-1L, ts+sec_ns( 5UL ) );
  FD_TEST( first->event_time_ns==ts+20L );
  fd_gui_fec_event_append( gui, 100UL, 0UL, key.event, early, ts+sec_ns( 5UL ) );
  fd_gui_fec_event_append( gui, 100UL, 0UL, key.event, ts+40L, ts+sec_ns( 6UL ) );
  FD_TEST( first->event_time_ns==early && first->insert_time_ns==ts+30L );
  FD_TEST( gui->shreds.clamped_fec_event_cnt==clamped0+1UL );
  /* A full open event head drops new admissions. */
  fd_gui_event_closed_slot_wmark_advance( gui, 51UL );
  fd_gui_fec_event_append( gui, 999UL, 0UL, key.event, ts, ts );
  FD_TEST( gui->shreds.dropped_fec_event_cnt==1UL );
  FD_TEST( !fd_gui_hist_evict_step( gui ) );
  fd_gui_shred_event_iter_t it;
  fd_gui_fec_event_iter_begin( gui, &it, early, early+1L );
  FD_TEST( fd_gui_shred_event_iter_next( &it ) && it.event.event_time_ns==early && it.event.slot==100U );
  FD_TEST( !fd_gui_shred_event_iter_next( &it ) );
  fd_gui_shred_event_iter_end( &it );

  long start = fd_log_wallclock();
  for( ulong round=0UL; round<8UL; round++ ) {
    fd_gui_fec_event_iter_begin( gui, &it, 0L, LONG_MAX );
    for( ulong i=0UL; i<cnt; i++ ) {
      FD_TEST( fd_gui_shred_event_iter_next( &it ) );
      FD_TEST( it.event.slot==100UL+i/65535UL && it.event.idx==i%65535UL );
      FD_TEST( it.event.event_time_ns==(i ? ts+20L : early) );
    }
    FD_TEST( !fd_gui_shred_event_iter_next( &it ) );
    fd_gui_shred_event_iter_end( &it );
  }
  FD_LOG_NOTICE(( "FEC scan: %lu records, %.3f ms/scan", cnt, (double)(fd_log_wallclock()-start)/8e6 ));
  void * http_mem = timeline_http_open( gui );
  start = fd_log_wallclock();
  FD_TEST( !fd_gui_printf_timeline_query_fec_events( gui, early, early+1L, 7UL ) );
  long elapsed = fd_log_wallclock() - start;
  test_json_t json = timeline_response( gui );
  FD_TEST( test_json_count( timeline_value( json, "idx" ) )==1 );
  FD_LOG_NOTICE(( "FEC narrow query including availability: %lu retained records, %.3f ms", cnt, (double)elapsed/1e6 ));
  FD_TEST( fd_http_server_delete( fd_http_server_leave( gui->http ) )==http_mem );
  free( http_mem );
  gui->http = NULL;

  fd_gui_event_closed_slot_wmark_advance( gui, 101UL );
  for( ulong i=0UL; i<65535UL; i++ ) {
    fd_gui_fec_event_append( gui, 1000UL, i, key.event, ts+50L, ts+50L );
  }
  FD_TEST( gui->shreds.dropped_fec_event_cnt==1UL );
  FD_TEST( !fd_gui_hist_kv_get( gui, FD_GUI_HIST_FEC_EVENTS, &key ) );
  fd_gui_fec_event_append( gui, 100UL, 0UL, key.event, 0L, ts+60L );
  FD_TEST( gui->shreds.dropped_fec_event_cnt==2UL );
  fd_gui_store_kv_scan_begin( gui->db, &scan, FD_GUI_HIST_FEC_EVENTS );
  FD_TEST( scan.end-scan.cur<=cnt );
  FD_TEST( fd_gui_store_kv_scan_next( &scan ) );
  FD_TEST( ((fd_gui_fec_event_t const *)scan.rec)->key.slot==101U );
  FD_TEST( !fd_gui_hist_evict_step( gui ) );
  key.slot = 101U;
  fd_gui_fec_event_append( gui, key.slot, key.idx, key.event, early+1L, ts+70L );
  FD_TEST( ((fd_gui_fec_event_t *)fd_gui_hist_kv_get( gui, FD_GUI_HIST_FEC_EVENTS, &key ))->event_time_ns==early+1L );
  FD_TEST( gui->shreds.dropped_fec_event_cnt==2UL );

  fd_gui_event_closed_slot_wmark_advance( gui, 1001UL );
  FD_TEST( !fd_gui_hist_evict_step( gui ) ); /* closed base retained until owner writes */
  for( ulong i=0UL; i<cnt; i++ ) {
    fd_gui_fec_event_append( gui, 1100UL+i/65535UL, i%65535UL, key.event, ts+90L, ts+90L );
  }
  ulong used;
  ulong cap;
  ulong free_bytes;
  ulong used_slots;
  ulong cap_slots;
  ulong free_slots;
  fd_gui_store_ring_stats( gui->db, FD_GUI_HIST_FEC_EVENTS, &used, &cap, &free_bytes, &used_slots, &cap_slots, &free_slots );
  FD_TEST( used_slots<=cnt && used_slots>cnt-512UL && cap<=2UL*FD_GUI_STORE_REGION_SZ );
  FD_TEST( cap_slots==cap/32UL );
  /* Cycling staging must not destroy history.  This exceeds the old hard
     retention ceiling and includes the timestamp updated into the past. */
  FD_TEST( count_ts( gui, FD_GUI_HIST_FEC_EVENTS, ULONG_MAX )==2UL*cnt+65535UL );
  fd_gui_fec_event_iter_begin( gui, &it, early, early+1L );
  FD_TEST( fd_gui_shred_event_iter_next( &it ) && it.event.slot==100U );
  FD_TEST( !fd_gui_shred_event_iter_next( &it ) );
  fd_gui_shred_event_iter_end( &it );
  FD_LOG_NOTICE(( "test_fec_event_index: quota %lu, stride %lu, regions %lu; ok", cnt, used/used_slots, cap/FD_GUI_STORE_REGION_SZ ));
}

/* A slot that never closes can only pin staging for slots within the
   admission horizon of the cutoff.  Slots past it are dropped instead,
   so an early future-leader slot or the tip during catch up cannot
   stall archival of everything behind it. */
static void
test_fec_slot_horizon( fd_gui_t * gui ) {
  long const ts = sec_ns( 10UL );
  uchar const event = FD_GUI_SLOT_SHRED_SHRED_RECEIVED_TURBINE;
  /* Before the first cutoff, nothing real is staged. */
  fd_gui_fec_event_append( gui, 1000000UL, 0UL, event, ts, ts );
  fd_gui_fec_event_append( gui, 1000000UL, USHORT_MAX, FD_GUI_SLOT_SHRED_SHRED_SLOT_COMPLETE, ts, ts );
  FD_TEST( gui->shreds.dropped_fec_event_cnt==2UL );

  ulong const cutoff = 1000000UL;
  fd_gui_event_closed_slot_wmark_advance( gui, cutoff );
  ulong const far = cutoff+FD_GUI_FEC_SLOT_WMARK_CNT;
  fd_gui_fec_event_append( gui, far, 0UL, event, ts, ts );
  FD_TEST( gui->shreds.dropped_fec_event_cnt==3UL );
  fd_gui_fec_event_append( gui, far-1UL, 0UL, event, ts, ts );
  FD_TEST( gui->shreds.dropped_fec_event_cnt==3UL );

  /* far-1 stays open and pins later admissions until the cutoff moves
     past it, which happens within the horizon of slots. */
  for( ulong slot=cutoff; slot<cutoff+16UL; slot++ ) {
    fd_gui_fec_event_append( gui, slot, 0UL, event, ts, ts );
  }
  fd_gui_event_closed_slot_wmark_advance( gui, cutoff+16UL );
  FD_TEST( !fd_gui_fec_archive( gui, 512UL ) );
  fd_gui_event_closed_slot_wmark_advance( gui, far );
  FD_TEST( fd_gui_fec_archive( gui, 512UL )==17UL );
  fd_gui_fec_event_append( gui, far+FD_GUI_FEC_SLOT_WMARK_CNT-1UL, 0UL, event, ts, ts );
  FD_TEST( gui->shreds.dropped_fec_event_cnt==3UL );
  FD_LOG_NOTICE(( "test_fec_slot_horizon: ok" ));
}

static void
test_fec_archive( fd_gui_t * gui ) {
  long ts = sec_ns( 100UL );
  ulong clamped0 = gui->shreds.clamped_fec_event_cnt;
  fd_gui_fec_event_append( gui, 100UL, 0UL, FD_GUI_SLOT_SHRED_REPAIR_REQUEST, ts, ts );
  fd_gui_fec_event_append( gui, 100UL, 0UL, FD_GUI_SLOT_SHRED_REPAIR_REQUEST, 1L, ts+1L );
  fd_gui_fec_event_append( gui, 101UL, 0UL, FD_GUI_SLOT_SHRED_REPAIR_REQUEST, ts+2L, ts+2L );
  fd_gui_shred_event_slot_complete( gui, 101UL, ts+3L, ts+3L );
  FD_TEST( !fd_gui_fec_archive( gui, 512UL ) ); /* completion closes nothing */
  fd_gui_event_closed_slot_wmark_advance( gui, 101UL );
  /* One event moves to the archive. */
  FD_TEST( fd_gui_fec_archive( gui, 1UL )==1UL );
  FD_TEST( count_ts( gui, FD_GUI_HIST_FEC_EVENTS, ULONG_MAX )==3UL );
  FD_TEST( !fd_gui_fec_archive( gui, 512UL ) ); /* open 101 pins its marker */
  fd_gui_event_closed_slot_wmark_advance( gui, 102UL );
  FD_TEST( fd_gui_fec_archive( gui, 512UL )==2UL );
  FD_TEST( !fd_gui_fec_archive( gui, 512UL ) );
  fd_gui_fec_event_key_t key = { .slot=100U, .idx=0U, .event=FD_GUI_SLOT_SHRED_REPAIR_REQUEST };
  FD_TEST( !fd_gui_hist_kv_get( gui, FD_GUI_HIST_FEC_EVENTS, &key ) );
  fd_gui_fec_event_append( gui, 100UL, 0UL, key.event, 0L, ts+4L );
  FD_TEST( gui->shreds.dropped_fec_event_cnt==1UL );
  /* Late completion markers are distinct, even after the first marker has
     already left staging and the slot has closed, and arrive more than 30
     days later.  The late dedup update above (timestamp 1) was skewed
     past the lag bound of its admission time and rejected. */
  long const lag  = FD_GUI_FEC_EVENT_LAG_MAX_NS;
  long const late = ts+sec_ns( 30UL*24UL*60UL*60UL+10UL );
  FD_TEST( gui->shreds.clamped_fec_event_cnt==clamped0+1UL );
  fd_gui_shred_event_slot_complete( gui, 101UL, late-2L, late );
  FD_TEST( fd_gui_fec_archive( gui, 512UL )==1UL );
  FD_TEST( count_ts( gui, FD_GUI_HIST_FEC_EVENTS, ULONG_MAX )==4UL );
  long lo, hi;
  FD_TEST( fd_gui_event_bounds( gui, FD_GUI_HIST_FEC_EVENTS, &lo, &hi ) );
  FD_TEST( lo==ts-lag && hi==late+FD_GUI_FEC_BATCH_SPAN_NS+lag+1L );
  fd_gui_shred_event_iter_t it;
  fd_gui_fec_event_iter_begin( gui, &it, ts-lag, ts+1L );
  FD_TEST( fd_gui_shred_event_iter_next( &it ) && it.event.event_time_ns==ts );
  FD_TEST( !fd_gui_shred_event_iter_next( &it ) );
  fd_gui_shred_event_iter_end( &it );
  fd_gui_fec_event_iter_begin( gui, &it, late-2L, late-1L );
  FD_TEST( fd_gui_shred_event_iter_next( &it ) && it.event.event_time_ns==late-2L && it.event.insert_time_ns==late );
  FD_TEST( !fd_gui_shred_event_iter_next( &it ) );
  fd_gui_shred_event_iter_end( &it );

  /* An admission gap too large for the delta codec must remain exact. */
  fd_gui_fec_event_append( gui, 102UL, 0UL, key.event, late+1L, late+1L );
  fd_gui_fec_event_append( gui, 102UL, 1UL, key.event, late+(long)UINT_MAX+2L, late+(long)UINT_MAX+2L );
  fd_gui_event_closed_slot_wmark_advance( gui, 103UL );
  FD_TEST( fd_gui_fec_archive( gui, 512UL )==2UL );
  fd_gui_fec_event_iter_begin( gui, &it, late+1L, late+(long)UINT_MAX+3L );
  FD_TEST( fd_gui_shred_event_iter_next( &it ) && it.event.insert_time_ns==late+1L );
  FD_TEST( fd_gui_shred_event_iter_next( &it ) && it.event.insert_time_ns==late+(long)UINT_MAX+2L );
  FD_TEST( !fd_gui_shred_event_iter_next( &it ) );
  fd_gui_shred_event_iter_end( &it );
  FD_LOG_NOTICE(( "test_fec_archive: closed-prefix handoff, late timestamps/markers: ok" ));
}

static void
test_fec_footprint( ulong bytes ) {
  fd_gui_store_desc_t descs[ FD_GUI_HIST_CNT ];
  fd_gui_hist_db_descs( descs, bytes, TEST_TILE_CNT );
  /* The floor itself is checked by test_min_footprint. */
  ulong current = fd_gui_store_footprint( bytes, FD_GUI_HIST_CNT, descs );
  descs[ FD_GUI_HIST_FEC_EVENTS ].kind        = FD_GUI_STORE_KIND_TS;
  descs[ FD_GUI_HIST_FEC_EVENTS ].key_sz      = 0UL;
  descs[ FD_GUI_HIST_FEC_EVENTS ].key_hash    = NULL;
  descs[ FD_GUI_HIST_FEC_EVENTS ].key_cmp     = NULL;
  descs[ FD_GUI_HIST_FEC_EVENTS ].max_records = 0UL;
  ulong old = fd_gui_store_footprint( bytes, FD_GUI_HIST_CNT, descs );
  FD_TEST( current>old );
  FD_TEST( current-old<73UL*1024UL*1024UL );
  FD_TEST( sizeof(((fd_gui_timeline_scratch_t *)0)->events)<sizeof(fd_gui_timeline_scratch_t) );
  FD_LOG_NOTICE(( "FEC RAM: store %lu, TS baseline %lu, added KV index %lu bytes",
                   current, old, current-old ));
  FD_LOG_NOTICE(( "GUI RAM: footprint %lu, query scratch %lu, event rows %lu; day %lu, epoch %lu bytes",
    fd_gui_footprint( 1UL, 1UL, 1UL ), sizeof(fd_gui_timeline_scratch_t), sizeof(((fd_gui_timeline_scratch_t *)0)->events),
    sizeof(fd_gui_timeline_day_t), sizeof(fd_gui_epoch_t) ));
}

static void
test_fec_base_admission( fd_gui_t * gui ) {
  long ts = sec_ns( 10UL );
  fd_gui_fec_event_append( gui, 100UL, 0UL, FD_GUI_SLOT_SHRED_REPAIR_REQUEST, ts, ts );
  FD_TEST( !gui->shreds.dropped_fec_event_cnt );
  fd_gui_scheduler_counts_t counts = { .sample_time_ns=ts };
  while( fd_gui_store_ts_append( gui->db, FD_GUI_HIST_SCHEDULER_COUNTS, &counts )==FD_GUI_STORE_SUCCESS ) {}
  FD_TEST( !fd_gui_store_shared_free_region_cnt( gui->db ) );
  fd_gui_timeline_handle_fec( gui, 100UL, 1, ts, 32UL, 16UL, 8UL, ts );
  FD_TEST( fd_gui_timeline_day_get( gui, 0UL ) );
  ulong evicts = fd_gui_store_metrics( gui->db )->evict_records[ FD_GUI_HIST_SCHEDULER_COUNTS ];
  fd_gui_fec_event_append( gui, 100UL, 0UL, FD_GUI_SLOT_SHRED_REPAIR_REQUEST, 1L, ts+sec_ns( 9UL ) );
  fd_gui_fec_event_append( gui, 101UL, 0UL, FD_GUI_SLOT_SHRED_REPAIR_REQUEST, 2L, ts );
  fd_gui_timeline_handle_fec( gui, 100UL, 1, ts, 32UL, 16UL, 8UL, ts );
  FD_TEST( !gui->shreds.dropped_fec_event_cnt );
  FD_TEST( fd_gui_store_metrics( gui->db )->evict_records[ FD_GUI_HIST_SCHEDULER_COUNTS ]==evicts );
  FD_TEST( count_ts( gui, FD_GUI_HIST_FEC_EVENTS, ULONG_MAX )==2UL );
  for( ulong i=0UL; i<3UL*(FD_GUI_STORE_REGION_SZ/sizeof(counts)); i++ ) append_sched_counts( gui, ts );
  FD_TEST( count_ts( gui, FD_GUI_HIST_FEC_EVENTS, ULONG_MAX )==2UL );
  FD_LOG_NOTICE(( "test_fec_base_admission: late FEC admission and retention under sustained pressure: ok" ));
}

static void
test_fec_minimum_store( fd_gui_t * gui ) {
  ulong free_before = fd_gui_store_free_region_cnt( gui->db );
  fd_gui_store_desc_t const * descs = test_descs();
  ulong base_cnt = 0UL;
  for( ulong i=0UL; i<FD_GUI_HIST_CNT; i++ ) base_cnt += descs[ i ].base_regions;
  FD_TEST( free_before==base_cnt );
  fd_gui_fec_event_append( gui, 100UL, 0UL, FD_GUI_SLOT_SHRED_REPAIR_REQUEST, 1L, 1L );
  FD_TEST( !gui->shreds.dropped_fec_event_cnt );
  FD_TEST( fd_gui_store_free_region_cnt( gui->db )==free_before-1UL );
  append_sched_counts( gui, 1L );
  FD_TEST( count_ts( gui, FD_GUI_HIST_SCHEDULER_COUNTS, ULONG_MAX )==1UL );
  FD_TEST( !fd_gui_hist_evict_step( gui ) );
  FD_LOG_NOTICE(( "test_fec_minimum_store: all bases fit: ok" ));
}

/* Explicit owner deletion for closure/query fixtures.  Production quota
   pressure and the pinned-head retry are exercised by test_fec_event_index. */
static int
closed_fec( ulong dbi, void const * rec, void * gui ) {
  (void)dbi;
  return ((fd_gui_fec_event_t const *)rec)->key.slot<fd_gui_event_closed_slot_wmark( gui );
}

static ulong
reclaim_closed_fec( fd_gui_t * gui ) {
  return fd_gui_store_reclaim( gui->db, FD_GUI_HIST_FEC_EVENTS, ULONG_MAX, closed_fec, gui );
}

static void
test_fec_prefix_guards( fd_gui_t * gui ) {
  long ts = sec_ns( 10UL );
  fd_gui_fec_event_append( gui, 100UL, 0UL, FD_GUI_SLOT_SHRED_REPAIR_REQUEST, ts, ts );
  fd_gui_fec_event_append( gui, 101UL, 0UL, FD_GUI_SLOT_SHRED_REPAIR_REQUEST, ts, ts );
  /* Replay completion and a completed slot record do not close a slot,
     so its records are neither reclaimed nor locked out. */
  fd_gui_shred_event_slot_complete( gui, 101UL, ts, ts );
  fd_gui_shred_flush( gui, ts+sec_ns( 1UL ) );
  FD_TEST( !fd_gui_hist_evict_step( gui ) );
  FD_TEST( !reclaim_closed_fec( gui ) );
  FD_TEST( count_ts( gui, FD_GUI_HIST_FEC_EVENTS, ULONG_MAX )==3UL );
  put_slot( gui, 100UL, ts );
  FD_TEST( (100UL>=fd_gui_event_closed_slot_wmark( gui )) );
  fd_gui_shred_event_append( gui, 100UL, 1UL, FD_GUI_SLOT_SHRED_REPAIR_REQUEST, ts, ts );
  FD_TEST( !gui->shreds.dropped_event_cnt );
  FD_TEST( gui->shreds.builder.batch.event_cnt==1UL );
  FD_TEST( !reclaim_closed_fec( gui ) );
  fd_gui_event_closed_slot_wmark_advance( gui, 102UL );
  FD_TEST( (100UL<fd_gui_event_closed_slot_wmark( gui )) && (101UL<fd_gui_event_closed_slot_wmark( gui )) );
  FD_TEST( reclaim_closed_fec( gui ) );
  FD_TEST( !count_ts( gui, FD_GUI_HIST_FEC_EVENTS, ULONG_MAX ) );
  fd_gui_fec_event_append( gui, 100UL, 0UL, FD_GUI_SLOT_SHRED_REPAIR_REQUEST, 1L, ts );
  FD_TEST( gui->shreds.dropped_fec_event_cnt==1UL );
  FD_LOG_NOTICE(( "test_fec_prefix_guards: no selective eviction, permanent vs transient closure: ok" ));
}

static void
test_timeline_live_events( test_store_t * s ) {
  fd_gui_t * gui = s->gui;
  long const ts = sec_ns( 10UL );
  void * http_mem = timeline_http_open( gui );

  fd_gui_fec_event_append( gui, 100UL, 1UL, FD_GUI_SLOT_SHRED_REPAIR_REQUEST, ts+20L, ts );
  fd_gui_fec_event_append( gui, 101UL, 2UL, FD_GUI_SLOT_SHRED_SHRED_RECEIVED_TURBINE, ts+30L, ts );
  fd_gui_fec_event_append( gui, 100UL, 1UL, FD_GUI_SLOT_SHRED_REPAIR_REQUEST, ts+10L, ts );
  FD_TEST( !gui->shreds.dropped_fec_event_cnt );
  fd_gui_shred_event_append( gui, 100UL, 32UL, FD_GUI_SLOT_SHRED_REPAIR_REQUEST, ts+10L, ts+10L );
  FD_TEST( gui->shreds.builder.batch.event_cnt==1UL );

  FD_TEST( !fd_gui_printf_timeline_query_fec_events( gui, ts+10L, ts+30L, 7UL ) );
  test_json_t json = timeline_response( gui );
  FD_TEST( test_json_count( timeline_value( json, "idx" ) )==1 );
  /* FEC bounds are admission times (all ts here) widened by the lag
     clamp, so they are conservative. */
  FD_TEST( test_json_string_eq( timeline_value( json, "available_start_ns" ), "9000000000" ) ); /* ts-FD_GUI_FEC_EVENT_LAG_MAX_NS */
  FD_TEST( test_json_string_eq( timeline_value( json, "available_end_ns" ), "11000000001" ) );
  FD_TEST( !test_json_field( test_json_field( json, "value" ), "shred_idx" ).ptr );

  FD_TEST( !fd_gui_printf_timeline_query_fec_events( gui, ts+11L, ts+30L, 7UL ) );
  json = timeline_response( gui );
  FD_TEST( !test_json_count( timeline_value( json, "idx" ) ) );


  FD_TEST( !fd_gui_printf_timeline_query_shreds( gui, ts, ts+30L, 7UL ) );
  json = timeline_response( gui );
  FD_TEST( test_json_count( timeline_value( json, "idx" ) )==1 );
  FD_TEST( test_json_kind( timeline_value( json, "available_start_ns" ) )==FD_JTOK_STR );
  FD_TEST( test_json_string_eq( timeline_value( json, "available_end_ns" ), "12000000000" ) );
  FD_TEST( !fd_gui_shred_window_is_empty( gui, ts, ts+30L ) );
  fd_gui_printf_shred_updates( gui, ts, ts+9L );
  json = timeline_response( gui );
  FD_TEST( !test_json_count( timeline_value( json, "shred_idx" ) ) );
  fd_gui_printf_shred_updates( gui, ts, ts+10L );
  json = timeline_response( gui );
  FD_TEST( test_json_string_eq( test_json_field( json, "key" ), "live_shreds" ) );
  FD_TEST( test_json_count( timeline_value( json, "shred_idx" ) )==1 );
  FD_TEST( test_json_ulong( test_json_index( timeline_value( json, "shred_idx" ), 0 ) )==32UL );
  FD_TEST( test_json_string_eq( timeline_value( json, "reference_ts" ), "10000000010" ) );
  FD_TEST( test_json_string_eq( test_json_index( timeline_value( json, "event_ts_delta" ), 0 ), "0" ) );
  fd_gui_printf_shred_updates( gui, ts+11L, ts+30L );
  json = timeline_response( gui );
  FD_TEST( !test_json_count( timeline_value( json, "shred_idx" ) ) );

  fd_gui_timeline_handle_fec( gui, 100UL, 1, ts+10L, 32UL, 16UL, 16UL, ts+40L );
  fd_gui_timeline_handle_fec( gui, 100UL, 1, ts+10L, 32UL, 16UL, 16UL, ts+40L );
  fd_gui_timeline_handle_fec( gui, 100UL, 1, ts+11L, 32UL, 16UL, 16UL, ts+40L );
  fd_gui_timeline_day_t const * day = fd_gui_timeline_day_get( gui, 0UL );
  FD_TEST( day );
  FD_TEST( fd_gui_timeline_field_get( day, FD_GUI_TIMELINE_GRANULARITY_250MS, FD_GUI_TIMELINE_FIELD_PUBLISHED, 40UL )==192UL );
  FD_TEST( fd_gui_timeline_field_get( day, FD_GUI_TIMELINE_GRANULARITY_250MS, FD_GUI_TIMELINE_FIELD_TURBINE, 40UL )==96UL );

  FD_TEST( !fd_gui_printf_timeline_query_agg( gui, "query_agg_shreds", "250ms", 3UL, ts, 1UL, 7UL ) );
  json = timeline_response( gui );
  FD_TEST( test_json_ulong( test_json_index( timeline_value( json, "published" ), 0 ) )==192UL );
  FD_TEST( test_json_ulong( test_json_index( timeline_value( json, "repair" ), 0 ) )==48UL );
  FD_TEST( test_json_string_eq( timeline_value( json, "available_start_ns" ), "0" ) );
  FD_TEST( test_json_string_eq( timeline_value( json, "available_end_ns" ), "86400000000000" ) );

  /* Slot aggregates come from the same day record as the shreds. */
  FD_TEST( !fd_gui_printf_timeline_query_agg( gui, "query_agg_slots", "250ms", 3UL, ts, 1UL, 7UL ) );
  json = timeline_response( gui );
  FD_TEST( test_json_string_eq( timeline_value( json, "available_start_ns" ), "0" ) );
  FD_TEST( test_json_ulong( test_json_index( timeline_value( json, "start_slot" ), 0 ) )==100UL );
  FD_TEST( test_json_ulong( test_json_index( timeline_value( json, "end_slot" ), 0 ) )==100UL );

  fd_gui_event_closed_slot_wmark_advance( gui, 101UL );
  /* One event is archived; queries now merge archive + open KV. */
  FD_TEST( fd_gui_fec_archive( gui, 512UL )==1UL );
  FD_TEST( !fd_gui_printf_timeline_query_agg( gui, "query_agg_shreds", "250ms", 3UL, ts, 1UL, 7UL ) );
  json = timeline_response( gui );
  FD_TEST( test_json_ulong( test_json_index( timeline_value( json, "published" ), 0 ) )==192UL );
  FD_TEST( test_json_ulong( test_json_index( timeline_value( json, "repair" ), 0 ) )==48UL );
  FD_TEST( test_json_kind( timeline_value( json, "available_start_ns" ) )==FD_JTOK_STR );

  FD_TEST( !fd_gui_printf_timeline_query_shreds( gui, ts, ts+30L, 7UL ) );
  json = timeline_response( gui );
  FD_TEST( test_json_count( timeline_value( json, "idx" ) )==1 );
  fd_gui_printf_shred_rebroadcast( gui, ts, ts+10L );
  json = timeline_response( gui );
  FD_TEST( test_json_count( timeline_value( json, "shred_idx" ) )==1 );
  FD_TEST( test_json_ulong( test_json_index( timeline_value( json, "shred_idx" ), 0 ) )==32UL );
  FD_TEST( test_json_string_eq( timeline_value( json, "reference_ts" ), "10000000010" ) );
  fd_gui_printf_shred_updates( gui, ts+11L, ts+50L );
  json = timeline_response( gui );
  FD_TEST( !test_json_count( timeline_value( json, "shred_idx" ) ) );
  FD_TEST( !fd_gui_printf_timeline_query_fec_events( gui, ts, ts+100L, 7UL ) );
  json = timeline_response( gui );
  FD_TEST( test_json_count( timeline_value( json, "idx" ) )==2 );
  FD_TEST( test_json_ulong( test_json_index( timeline_value( json, "idx" ), 0 ) )==1UL );
  FD_TEST( test_json_string_eq( timeline_value( json, "reference_ts" ), "10000000010" ) );

  /* Slot aggregates are served from the day record whatever the
     detailed transaction history holds. */
  append_replay_txn( gui, sec_ns( 1UL ), sec_ns( 1UL ), 99UL );
  FD_TEST( !fd_gui_printf_timeline_query_agg( gui, "query_agg_slots", "250ms", 3UL, ts, 1UL, 7UL ) );
  json = timeline_response( gui );
  FD_TEST( (test_json_kind( timeline_value( json, "available_start_ns" ) )==FD_JTOK_STR) );
  FD_TEST( (test_json_kind( timeline_value( json, "available_end_ns" ) )==FD_JTOK_STR) );
  FD_TEST( test_json_ulong( test_json_index( timeline_value( json, "start_slot" ), 0 ) )==100UL );


  fd_gui_event_closed_slot_wmark_advance( gui, 101UL );
  FD_TEST( gui->shreds.builder.batch.event_cnt==1UL );
  FD_TEST( count_ts( gui, FD_GUI_HIST_FEC_EVENTS, ULONG_MAX )==2UL );
  fd_gui_shred_event_iter_t ei;
  fd_gui_fec_event_iter_begin( gui, &ei, ts, ts+100L );
  FD_TEST( fd_gui_shred_event_iter_next( &ei ) && ei.event.slot==100UL && ei.event.idx==1U );
  FD_TEST( fd_gui_shred_event_iter_next( &ei ) && ei.event.slot==101UL && ei.event.idx==2U );
  FD_TEST( !fd_gui_shred_event_iter_next( &ei ) );
  fd_gui_shred_event_iter_end( &ei );
  fd_gui_event_closed_slot_wmark_advance( gui, 99UL );
  fd_gui_shred_event_append( gui, 100UL, 33UL, FD_GUI_SLOT_SHRED_REPAIR_REQUEST, ts+60L, ts+60L );
  FD_TEST( gui->shreds.closed_slot_wmark==101UL && gui->shreds.dropped_event_cnt==1UL );

  fd_gui_shred_event_slot_complete( gui, 101UL, ts+70L, ts+70L );
  fd_gui_shred_event_slot_complete( gui, 101UL, ts+80L, ts+80L );
  fd_gui_fec_event_iter_begin( gui, &ei, ts+70L, ts+81L );
  for( ulong i=0UL; i<2UL; i++ ) {
    FD_TEST( fd_gui_shred_event_iter_next( &ei ) );
    FD_TEST( ei.event.idx==USHORT_MAX && ei.event.event==FD_GUI_SLOT_SHRED_SHRED_SLOT_COMPLETE );
    FD_TEST( ei.event.event_time_ns==ts+70L+10L*(long)i );
  }
  FD_TEST( !fd_gui_shred_event_iter_next( &ei ) );
  fd_gui_shred_event_iter_end( &ei );
  for( int earlier=0; earlier<2; earlier++ ) {
    if( earlier ) fd_gui_shred_event_slot_complete( gui, 101UL, ts+60L, ts+90L );
    FD_TEST( !fd_gui_printf_timeline_query_fec_events( gui, ts+60L, ts+81L, 7UL ) );
    json = timeline_response( gui );
    FD_TEST( test_json_count( timeline_value( json, "idx" ) )==2+earlier );
    FD_TEST( (test_json_kind( test_json_index( timeline_value( json, "idx" ), 0 ) )==FD_JTOK_NULL) );
    FD_TEST( test_json_string_eq( timeline_value( json, "reference_ts" ), earlier ? "10000000060" : "10000000070" ) );

    FD_TEST( !fd_gui_printf_timeline_query_fec_events( gui, ts+71L, ts+81L, 7UL ) );
    json = timeline_response( gui );
    FD_TEST( test_json_count( timeline_value( json, "idx" ) )==1 );

    FD_TEST( !fd_gui_printf_timeline_query_shreds( gui, ts+60L, ts+81L, 7UL ) );
    json = timeline_response( gui );
    FD_TEST( test_json_count( timeline_value( json, "idx" ) )==2+earlier );

  }
  /* A completed but unconfirmed slot still admits late events. */
  put_slot( gui, 101UL, ts+80L );
  fd_gui_fec_event_append( gui, 101UL, 3UL, FD_GUI_SLOT_SHRED_REPAIR_REQUEST, ts+90L, ts );
  FD_TEST( !gui->shreds.dropped_fec_event_cnt );
  FD_TEST( count_ts( gui, FD_GUI_HIST_FEC_EVENTS, ULONG_MAX )==6UL );
  fd_gui_event_closed_slot_wmark_advance( gui, 102UL );
  fd_gui_fec_event_append( gui, 101UL, 4UL, FD_GUI_SLOT_SHRED_REPAIR_REQUEST, ts+90L, ts );
  FD_TEST( gui->shreds.dropped_fec_event_cnt==1UL );
  FD_TEST( count_ts( gui, FD_GUI_HIST_FEC_EVENTS, ULONG_MAX )==6UL );
  day = fd_gui_timeline_day_get( gui, 0UL );
  FD_TEST( day && fd_gui_timeline_field_get( day, FD_GUI_TIMELINE_GRANULARITY_250MS, FD_GUI_TIMELINE_FIELD_PUBLISHED, 40UL )==192UL );

  FD_TEST( fd_http_server_delete( fd_http_server_leave( gui->http ) )==http_mem );
  free( http_mem );
  gui->http = NULL;
  FD_LOG_NOTICE(( "test_timeline_live_events: ok" ));
}

static void
test_timeline_closure_cutoff( fd_gui_t * gui ) {
  long ts = sec_ns( 10UL );
  /* Any number of replay completions closes nothing. */
  for( ulong slot=1UL; slot<=70000UL; slot++ ) fd_gui_shred_event_slot_complete( gui, slot, ts, ts );
  ulong invalid[] = { (ulong)UINT_MAX+1UL, (ulong)LONG_MAX, ULONG_MAX };
  ulong appends = fd_gui_store_metrics( gui->db )->ts_appends[ FD_GUI_HIST_SHRED_EVENTS ];
  for( ulong i=0UL; i<3UL; i++ ) fd_gui_shred_event_slot_complete( gui, invalid[ i ], ts, ts );
  FD_TEST( fd_gui_store_metrics( gui->db )->ts_appends[ FD_GUI_HIST_SHRED_EVENTS ]==appends );
  FD_TEST( !gui->shreds.closed_slot_wmark );
  ulong dropped = gui->shreds.dropped_event_cnt;
  fd_gui_shred_event_append( gui, 1UL, 32UL, FD_GUI_SLOT_SHRED_REPAIR_REQUEST, ts, ts );
  FD_TEST( gui->shreds.dropped_event_cnt==dropped );

  /* The cutoff only moves forward and ignores ULONG_MAX. */
  ulong cutoffs[] = { 70001UL, 60000UL, ULONG_MAX, 70002UL };
  ulong expect[]  = { 70001UL, 70001UL, 70001UL, 70002UL };
  for( ulong i=0UL; i<4UL; i++ ) {
    fd_gui_event_closed_slot_wmark_advance( gui, cutoffs[ i ] );
    FD_TEST( gui->shreds.closed_slot_wmark==expect[ i ] );
  }
  FD_TEST( (70001UL<fd_gui_event_closed_slot_wmark( gui )) );
  FD_TEST( (70002UL>=fd_gui_event_closed_slot_wmark( gui )) );
  ulong slots[] = { 1UL, 70001UL, 70002UL };
  ulong fec_dropped = gui->shreds.dropped_fec_event_cnt;
  for( ulong j=0UL; j<3UL; j++ ) {
    fd_gui_shred_event_append( gui, slots[ j ], 32UL, FD_GUI_SLOT_SHRED_REPAIR_REQUEST, ts, ts );
    fd_gui_fec_event_append( gui, slots[ j ], 1UL, FD_GUI_SLOT_SHRED_REPAIR_REQUEST, ts, ts );
  }
  FD_TEST( gui->shreds.dropped_event_cnt==dropped+2UL );
  FD_TEST( gui->shreds.dropped_fec_event_cnt==fec_dropped+2UL );
  FD_LOG_NOTICE(( "test_timeline_closure_cutoff: replay completions do not close, monotone cutoff: ok" ));
}

/* batch_txn records a replayed transaction on execrp tiles exec
   (execution) and sig (sigverify, ULONG_MAX for none) and feeds it to
   the streaming batcher, as fd_gui_record_replay_txn does. */
static void
batch_txn( fd_gui_t * gui,
           ulong      slot,
           ulong      txn_idx,
           ulong      exec,
           ulong      sig,
           long       start,
           long       dur,
           uint       err ) {
  fd_gui_store_replay_txn_t txn = {
    .insert_time_ns=start+dur, .completion_time_ns=start+dur, .slot=slot, .txn_idx=txn_idx,
    .txn_exec_idx=exec, .txn_sigverify_exec_idx=sig, .error_code=err,
    .txn_start_shred_idx=UINT_MAX, .txn_end_shred_idx=UINT_MAX,
    .sigverify_start_ns=sig==ULONG_MAX ? LONG_MAX : start-dur, .sigverify_end_ns=sig==ULONG_MAX ? LONG_MAX : start,
    .load_start_ns=start, .check_start_ns=start+dur/4L, .exec_start_ns=start+dur/2L,
    .commit_start_ns=start+3L*dur/4L, .commit_end_ns=start+dur, .block_compute_unit_limit=ULONG_MAX
  };
  FD_TEST( !fd_gui_hist_ts_append( gui, FD_GUI_HIST_REPLAY_TXN, &txn ) );
  fd_gui_txn_batch_add( gui, &txn );
}

/* Batches stream: a transaction joins its lane's open batch while it
   starts within FD_GUI_TXN_BATCH_GAP_NS of the batch's end and the
   batch has room, whatever its slot; otherwise the open batch is
   written at once.  Idle batches are written by the flush. */
static void
test_timeline_batch_stream( fd_gui_t * gui ) {
  long  ts   = sec_ns( 11UL );
  ulong base = count_ts( gui, FD_GUI_HIST_REPLAY_TXN_BATCH, ULONG_MAX );

  /* Three back to back members on execrp 2, sigverified on execrp 1:
     nothing is written until the flush, which writes one execution and
     one sigverify row. */
  for( ulong i=0UL; i<3UL; i++ ) batch_txn( gui, 101UL, i, 2UL, 1UL, ts+(long)i*1000L, 400L, i==1UL ? 7U : 0U );
  long last     = ts+2000L+400L; /* execution lane end */
  long sig_last = ts+2000L;      /* sigverify lane end */
  FD_TEST( count_ts( gui, FD_GUI_HIST_REPLAY_TXN_BATCH, ULONG_MAX )==base );
  /* Flushes before the earliest due batch skip the scan. */
  FD_TEST( gui->tile_state.txn_flush_ns<=sig_last+FD_GUI_TXN_BATCH_IDLE_NS );
  fd_gui_txn_batch_flush( gui, sig_last+FD_GUI_TXN_BATCH_IDLE_NS-1L );
  FD_TEST( gui->tile_state.txn_flush_ns==sig_last+FD_GUI_TXN_BATCH_IDLE_NS );
  FD_TEST( count_ts( gui, FD_GUI_HIST_REPLAY_TXN_BATCH, ULONG_MAX )==base );
  fd_gui_txn_batch_flush( gui, sig_last+FD_GUI_TXN_BATCH_IDLE_NS );
  FD_TEST( count_ts( gui, FD_GUI_HIST_REPLAY_TXN_BATCH, ULONG_MAX )==base+1UL ); /* each lane flushes on its own idle */
  FD_TEST( gui->tile_state.txn_flush_ns==last+FD_GUI_TXN_BATCH_IDLE_NS );
  fd_gui_txn_batch_flush( gui, last+FD_GUI_TXN_BATCH_IDLE_NS-1L );
  FD_TEST( count_ts( gui, FD_GUI_HIST_REPLAY_TXN_BATCH, ULONG_MAX )==base+1UL );
  fd_gui_txn_batch_flush( gui, last+FD_GUI_TXN_BATCH_IDLE_NS );
  FD_TEST( count_ts( gui, FD_GUI_HIST_REPLAY_TXN_BATCH, ULONG_MAX )==base+2UL );
  FD_TEST( gui->tile_state.txn_flush_ns==LONG_MAX );
  fd_gui_hist_iter_t it;
  FD_TEST( !fd_gui_hist_range_begin( gui, &it, FD_GUI_HIST_REPLAY_TXN_BATCH, sig_last+FD_GUI_TXN_BATCH_IDLE_NS, last+FD_GUI_TXN_BATCH_IDLE_NS, NULL, NULL ) );
  ulong seen = 0UL;
  while( fd_gui_hist_range_next( &it ) ) {
    fd_gui_store_replay_txn_batch_t const * b = it.rec;
    FD_TEST( b->slot==101UL && !b->is_leader && b->txn_idx==0UL );
    if( b->exec_txn_cnt ) {
      /* The execution lane: three members of 400 ns end at last, so it
         lasts 1200 ns, split 1/4 each into the four stages. */
      FD_TEST( b->exec_txn_cnt==3U && !b->sigverify_txn_cnt );
      FD_TEST( b->txn_exec_idx==2UL && b->txn_sigverify_exec_idx==ULONG_MAX );
      FD_TEST( b->completion_time_ns==last && b->commit_end_ns==last && b->load_start_ns==last-1200L );
      FD_TEST( b->check_start_ns==last-900L && b->exec_start_ns==last-600L && b->commit_start_ns==last-300L );
      FD_TEST( b->error_code==0U ); /* two of three succeeded */
      seen |= 1UL;
    } else {
      /* The sigverify lane needs no execution metadata. */
      FD_TEST( b->sigverify_txn_cnt==3U && b->txn_sigverify_exec_idx==1UL && b->txn_exec_idx==ULONG_MAX );
      FD_TEST( b->sigverify_txn_idx==0UL && b->sigverify_end_ns==ts+2000L && b->sigverify_start_ns==ts+2000L-1200L );
      FD_TEST( b->completion_time_ns==b->sigverify_end_ns && b->load_start_ns==LONG_MAX && b->commit_end_ns==LONG_MAX );
      seen |= 2UL;
    }
  }
  fd_gui_hist_range_end( &it );
  FD_TEST( seen==3UL );

  /* A gap past FD_GUI_TXN_BATCH_GAP_NS writes the open batch as soon as
     the next member arrives.  Another slot within the gap joins, and
     the batch takes the slot of the member that ended last. */
  ts   = sec_ns( 12UL );
  base = count_ts( gui, FD_GUI_HIST_REPLAY_TXN_BATCH, ULONG_MAX );
  batch_txn( gui, 102UL, 0UL, 3UL, ULONG_MAX, ts, 100L, 0U );
  batch_txn( gui, 102UL, 1UL, 3UL, ULONG_MAX, ts+100L+FD_GUI_TXN_BATCH_GAP_NS+1L, 100L, 0U );
  FD_TEST( count_ts( gui, FD_GUI_HIST_REPLAY_TXN_BATCH, ULONG_MAX )==base+1UL );
  ts += FD_GUI_TXN_BATCH_GAP_NS+1L+200L+FD_GUI_TXN_BATCH_GAP_NS;
  batch_txn( gui, 103UL, 0UL, 3UL, ULONG_MAX, ts, 100L, 0U );
  FD_TEST( count_ts( gui, FD_GUI_HIST_REPLAY_TXN_BATCH, ULONG_MAX )==base+1UL );
  /* Leader transactions (no sigverify) batch on their own lane. */
  fd_gui_txn_batch_flush( gui, ts+100L+FD_GUI_TXN_BATCH_IDLE_NS );
  FD_TEST( count_ts( gui, FD_GUI_HIST_REPLAY_TXN_BATCH, ULONG_MAX )==base+2UL );
  FD_TEST( !fd_gui_hist_range_begin( gui, &it, FD_GUI_HIST_REPLAY_TXN_BATCH, sec_ns( 12UL ), sec_ns( 13UL ), NULL, NULL ) );
  ulong rows = 0UL;
  while( fd_gui_hist_range_next( &it ) ) {
    fd_gui_store_replay_txn_batch_t const * b = it.rec;
    FD_TEST( b->is_leader && b->txn_exec_idx==3UL );
    FD_TEST( rows ? ( b->exec_txn_cnt==2U && b->slot==103UL ) : ( b->exec_txn_cnt==1U && b->slot==102UL ) );
    rows++;
  }
  fd_gui_hist_range_end( &it );
  FD_TEST( rows==2UL );

  /* A full batch is written and the next member starts a new one. */
  ts   = sec_ns( 13UL );
  base = count_ts( gui, FD_GUI_HIST_REPLAY_TXN_BATCH, ULONG_MAX );
  for( ulong i=0UL; i<FD_GUI_TXN_BATCH_MAX_TXN+1UL; i++ ) batch_txn( gui, 104UL, i, 4UL, 5UL, ts+(long)i*100L, 100L, 0U );
  FD_TEST( count_ts( gui, FD_GUI_HIST_REPLAY_TXN_BATCH, ULONG_MAX )==base+2UL ); /* both lanes' first batch */
  fd_gui_txn_batch_flush( gui, ts+sec_ns( 1UL ) );
  FD_TEST( count_ts( gui, FD_GUI_HIST_REPLAY_TXN_BATCH, ULONG_MAX )==base+4UL );
  FD_LOG_NOTICE(( "test_timeline_batch_stream: ok" ));
}

static void
test_timeline_batches( fd_gui_t * gui ) {
  void * http_mem = timeline_http_open( gui );
  long const ts = sec_ns( 10UL );
  ulong const max = FD_GUI_TXN_BATCH_MAX_TXN;
  for( ulong i=0UL; i<2UL*max+1UL; i++ ) {
    /* The first batch mixes error codes: 5 is the most frequent
       (half the members), ahead of 3 and success (a quarter each), so it
       wins despite the representative succeeding.  Neither the codes nor
       success/failure split the batch. */
    uint err = i>=max ? 0U : (i&1UL) ? 5U : (i&2UL) ? 3U : 0U;
    fd_gui_store_replay_txn_t txn = {
      .insert_time_ns=ts, .completion_time_ns=ts+(long)i*1000L+800L, .slot=100UL, .txn_idx=i,
      .error_code=err, .txn_sigverify_exec_idx=1UL,
      .sigverify_start_ns=ts+(long)i*1000L, .sigverify_end_ns=ts+(long)i*1000L+800L,
      .load_start_ns=ts+(long)i*1000L+100L, .check_start_ns=ts+(long)i*1000L+200L,
      .exec_start_ns=ts+(long)i*1000L+300L, .commit_start_ns=ts+(long)i*1000L+600L,
      .commit_end_ns=ts+(long)i*1000L+700L, .block_compute_unit_limit=ULONG_MAX
    };
    FD_TEST( !fd_gui_hist_ts_append( gui, FD_GUI_HIST_REPLAY_TXN, &txn ) );
    fd_gui_txn_batch_add( gui, &txn );
  }
  /* Leader transactions of the same slot, overlapping in time on the
     same tile, batch on their own lane. */
  for( ulong i=0UL; i<4UL; i++ ) {
    fd_gui_store_replay_txn_t txn = {
      .insert_time_ns=ts, .completion_time_ns=ts+(long)i*1000L+900L, .slot=100UL, .bank_seq=1UL, .txn_idx=i,
      .sigverify_start_ns=LONG_MAX, .sigverify_end_ns=LONG_MAX, .txn_sigverify_exec_idx=ULONG_MAX,
      .load_start_ns=ts+(long)i*1000L+150L, .check_start_ns=LONG_MAX, .exec_start_ns=LONG_MAX,
      .commit_start_ns=LONG_MAX, .commit_end_ns=ts+(long)i*1000L+750L, .block_compute_unit_limit=ULONG_MAX
    };
    FD_TEST( !fd_gui_hist_ts_append( gui, FD_GUI_HIST_REPLAY_TXN, &txn ) );
    fd_gui_txn_batch_add( gui, &txn );
  }
  fd_gui_txn_batch_flush( gui, ts+1000000L+FD_GUI_TXN_BATCH_IDLE_NS );
  /* Execution and sigverify lanes: two full batches and a singleton
     each, plus one leader batch. */
  FD_TEST( count_ts( gui, FD_GUI_HIST_REPLAY_TXN_BATCH, ULONG_MAX )==7UL );
  fd_gui_hist_iter_t it;
  FD_TEST( !fd_gui_hist_range_begin( gui, &it, FD_GUI_HIST_REPLAY_TXN_BATCH, ts, ts+1000000L, NULL, NULL ) );
  ulong exec_seen = 0UL, sig_seen = 0UL, leader_seen = 0UL;
  while( fd_gui_hist_range_next( &it ) ) {
    fd_gui_store_replay_txn_batch_t const * b = it.rec;
    if( b->is_leader ) {
      FD_TEST( b->exec_txn_cnt==4U && !b->sigverify_txn_cnt );
      leader_seen++;
    } else if( b->exec_txn_cnt ) {
      ulong i   = b->txn_idx/max;
      ulong cnt = i<2UL ? max : 1UL;
      FD_TEST( !b->sigverify_txn_cnt && b->exec_txn_cnt==(uint)cnt && b->txn_idx==i*max );
      FD_TEST( b->error_code==(i ? 0U : 5U) );
      FD_TEST( b->completion_time_ns==ts+(long)(i*max+cnt-1UL)*1000L+700L );
      FD_TEST( b->load_start_ns<=b->check_start_ns && b->check_start_ns<=b->exec_start_ns );
      FD_TEST( b->exec_start_ns<=b->commit_start_ns && b->commit_start_ns<=b->commit_end_ns );
      exec_seen++;
    } else {
      ulong i   = b->sigverify_txn_idx/max;
      ulong cnt = i<2UL ? max : 1UL;
      FD_TEST( b->sigverify_txn_cnt==(uint)cnt && b->sigverify_txn_idx==i*max );
      FD_TEST( b->completion_time_ns==ts+(long)(i*max+cnt-1UL)*1000L+800L );
      sig_seen++;
    }
  }
  fd_gui_hist_range_end( &it );
  FD_TEST( exec_seen==3UL && sig_seen==3UL && leader_seen==1UL );
  /* Two execrp tiles: both batches execute on tile 0 and sigverify on
     tile 1, with Idle around them. */
  gui->tile_state.exec_cnt = 2UL;
  gui->tile_state.pos_cnt  = 2UL;
  FD_TEST( !fd_gui_printf_timeline_query_tile_states( gui, ts, ts+1000000L, 1, 7UL ) );
  test_json_t json = timeline_response( gui );
  FD_TEST( test_json_string_eq( timeline_value( json, "granularity" ), "txn_batch" ) );
  FD_TEST( test_json_count( timeline_value( json, "state_cnt" ) )==2 );
  FD_TEST( !test_json_count( timeline_value( json, "txn_idx" ) ) && !test_json_count( timeline_value( json, "txn_slot_delta" ) ) );
  FD_TEST( test_json_ulong( timeline_value( json, "reference_slot" ) )==100UL );
  int n = test_json_count( timeline_value( json, "state" ) );
  /* Every non-idle batch state is covered by exactly one slot segment,
     Idle by none, and runs of states between Idles are one segment. */
  {
    int seg_n = test_json_count( timeline_value( json, "slot_state_lo" ) );
    FD_TEST( seg_n>0 && seg_n==test_json_count( timeline_value( json, "slot_state_cnt" ) ) && seg_n==test_json_count( timeline_value( json, "slot_delta" ) ) );
    static uchar covered[ 4096 ];
    FD_TEST( n<=4096 );
    memset( covered, 0, sizeof(covered) );
    for( int g=0; g<seg_n; g++ ) {
      ulong glo  = test_json_ulong( test_json_index( timeline_value( json, "slot_state_lo"  ), g ) );
      ulong gcnt = test_json_ulong( test_json_index( timeline_value( json, "slot_state_cnt" ), g ) );
      FD_TEST( test_json_ulong( test_json_index( timeline_value( json, "slot_delta" ), g ) )==0UL );
      FD_TEST( gcnt && glo+gcnt<=(ulong)n );
      for( ulong i=glo; i<glo+gcnt; i++ ) { FD_TEST( !covered[ i ] ); covered[ i ] = 1; }
    }
    ulong runs = 0UL;
    for( int i=0; i<n; i++ ) {
      int idle = test_json_ulong( test_json_index( timeline_value( json, "state" ), i ) )==FD_GUI_TILE_STATE_IDLE;
      FD_TEST( covered[ i ]==!idle );
      if( !idle && ( !i || !covered[ i-1 ] ) ) runs++;
    }
    /* runs also split at tile boundaries */
    FD_TEST( runs<=(ulong)seg_n );
  }
  FD_TEST( n==test_json_count( timeline_value( json, "dur" ) ) );
  ulong total = 0UL; ulong sig_batch = 0UL;
  ulong stage_cnt[ 4 ] = {0}; ulong stage_dur[ 4 ] = {0};
  for( int i=0; i<n; i++ ) {
    ulong state = test_json_ulong( test_json_index( timeline_value( json, "state" ), i ) );
    ulong dur   = test_json_ulong( test_json_index( timeline_value( json, "dur" ), i ) );
    FD_TEST( state==FD_GUI_TILE_STATE_IDLE || state==FD_GUI_TILE_STATE_SIGVERIFY_BATCH ||
             ( state>=FD_GUI_TILE_STATE_LOAD_BATCH && state<=FD_GUI_TILE_STATE_POST_EXEC_BATCH ) );
    sig_batch += state==FD_GUI_TILE_STATE_SIGVERIFY_BATCH;
    if( state>=FD_GUI_TILE_STATE_LOAD_BATCH && state<=FD_GUI_TILE_STATE_POST_EXEC_BATCH ) {
      stage_cnt[ state-FD_GUI_TILE_STATE_LOAD_BATCH ]++;
      stage_dur[ state-FD_GUI_TILE_STATE_LOAD_BATCH ] += dur;
    }
    total += dur;
  }
  /* Each tile spans its first state's start to its last state's end,
     with Idle only between states. */
  FD_TEST( sig_batch==3UL );
  ulong span = 0UL;
  FD_TEST( !fd_gui_hist_range_begin( gui, &it, FD_GUI_HIST_REPLAY_TXN_BATCH, ts, ts+1000000L, NULL, NULL ) );
  long lo[ 2 ] = { LONG_MAX, LONG_MAX }, hi[ 2 ] = { LONG_MIN, LONG_MIN };
  while( fd_gui_hist_range_next( &it ) ) {
    fd_gui_store_replay_txn_batch_t const * b = it.rec;
    if( b->is_leader ) continue;
    if( b->exec_txn_cnt ) { lo[ 0 ] = fd_long_min( lo[ 0 ], b->load_start_ns );      hi[ 0 ] = fd_long_max( hi[ 0 ], b->commit_end_ns );   }
    else                  { lo[ 1 ] = fd_long_min( lo[ 1 ], b->sigverify_start_ns ); hi[ 1 ] = fd_long_max( hi[ 1 ], b->sigverify_end_ns ); }
  }
  fd_gui_hist_range_end( &it );
  span = (ulong)(hi[ 0 ]-lo[ 0 ]) + (ulong)(hi[ 1 ]-lo[ 1 ]);
  FD_TEST( total==span );
  /* Each batch's stages are the batch record's proportional split. */
  ulong want_dur[ 4 ] = {0};
  FD_TEST( !fd_gui_hist_range_begin( gui, &it, FD_GUI_HIST_REPLAY_TXN_BATCH, ts, ts+1000000L, NULL, NULL ) );
  while( fd_gui_hist_range_next( &it ) ) {
    fd_gui_store_replay_txn_batch_t const * b = it.rec;
    if( b->is_leader || !b->exec_txn_cnt ) continue;
    uchar st[ 4 ]; long sts[ 5 ];
    ulong sn = fd_gui_txn_exec_states( b->load_start_ns, b->check_start_ns, b->exec_start_ns, b->commit_start_ns, b->commit_end_ns, st, sts );
    for( ulong i=0UL; i<sn; i++ ) want_dur[ st[ i ]-FD_GUI_TILE_STATE_LOADING ] += (ulong)(sts[ i+1UL ]-sts[ i ]);
  }
  fd_gui_hist_range_end( &it );
  for( ulong s=0UL; s<4UL; s++ ) {
    FD_TEST( stage_cnt[ s ]==3UL ); /* every member reached every stage */
    FD_TEST( stage_dur[ s ]==want_dur[ s ] && stage_dur[ s ] );
  }
  /* Members spend 100/100/300/100 ns per stage, so Exec is 3x the rest
     (up to rounding of the batch boundaries). */
  for( ulong s=0UL; s<4UL; s++ ) {
    ulong want = (s==2UL ? 3UL : 1UL)*stage_dur[ 0 ];
    FD_TEST( stage_dur[ s ]+4UL>=want && stage_dur[ s ]<=want+4UL );
  }

  /* A batch is inserted shortly after it ends.  A narrow window around
     the batch still finds it, up to the scan margin. */
  long const late = ts+sec_ns( 100UL );
  for( ulong i=0UL; i<2UL; i++ ) {
    fd_gui_store_replay_txn_batch_t b = {
      .insert_time_ns=late+(i ? FD_GUI_TIMELINE_SCAN_MARGIN_NS+sec_ns( 2UL ) : FD_GUI_TIMELINE_SCAN_MARGIN_NS-1L),
      .completion_time_ns=late+(long)i, .slot=200UL+i, .txn_exec_idx=0UL, .txn_sigverify_exec_idx=ULONG_MAX,
      .sigverify_start_ns=LONG_MAX, .sigverify_end_ns=LONG_MAX, .load_start_ns=late-10L+(long)i,
      .check_start_ns=LONG_MAX, .exec_start_ns=LONG_MAX, .commit_start_ns=LONG_MAX,
      .commit_end_ns=late+(long)i, .exec_txn_cnt=1U, .sigverify_txn_idx=ULONG_MAX
    };
    FD_TEST( !fd_gui_hist_ts_append( gui, FD_GUI_HIST_REPLAY_TXN_BATCH, &b ) );
  }
  FD_TEST( !fd_gui_printf_timeline_query_tile_states( gui, late, late+2L, 1, 7UL ) );
  json = timeline_response( gui );
  /* Only the first batch was inserted within the margin. */
  FD_TEST( test_json_count( timeline_value( json, "state" ) )==1 );
  FD_TEST( test_json_ulong( test_json_index( timeline_value( json, "state" ), 0 ) )==FD_GUI_TILE_STATE_LOAD_BATCH );
  gui->tile_state.exec_cnt = 0UL;
  gui->tile_state.pos_cnt  = 0UL;
  FD_TEST( fd_http_server_delete( fd_http_server_leave( gui->http ) )==http_mem );
  free( http_mem );
  gui->http = NULL;
  FD_LOG_NOTICE(( "test_timeline_batches: ok" ));
}

/* The replayed (non-leader) completion path counts a locally produced
   slot once however often it completes. */
static void
test_timeline_replay_batches( fd_gui_t * gui ) {
  void * http_mem = timeline_http_open( gui );
  long const  ts   = sec_ns( 10UL );
  ulong const slot = 600UL;
  gui->slot_txn_scratch.max                   = 8UL;
  gui->summary.slot_caught_up                = ULONG_MAX;
  for( ulong i=0UL; i<FD_GUI_TURBINE_SLOT_HISTORY_SZ; i++ ) gui->summary.slots_max_turbine[ i ].slot = ULONG_MAX;
  fd_replay_slot_completed_t completed = { .slot=slot, .bank_seq=3UL, .parent_slot=ULONG_MAX, .parent_bank_seq=ULONG_MAX,
    .first_transaction_scheduled_nanos=ts+50L, .completion_time_nanos=ts+300L,
    .nonvote_success=3UL, .identity_balance=ULONG_MAX };
  fd_gui_handle_replay_update( gui, &completed, ts+300L );
  fd_http_server_stage_trunc( gui->http, 0UL );

  /* A locally produced slot adds to MINE once, even when it completes
     again. */
  fd_gui_slot_t * meta = fd_gui_slot_get( gui, slot, 3UL );
  FD_TEST( meta && !meta->timeline_mine_accounted );
  ulong idx = (ulong)(ts+300L)/fd_gui_timeline_stored_granularity_ns[ FD_GUI_TIMELINE_GRANULARITY_250MS ];
  ulong slot2 = slot+1UL;
  completed.slot = slot2;
  completed.first_transaction_scheduled_nanos = 0L;
  fd_gui_slot_t * mine = fd_gui_slot_get_or_create( gui, slot2, ULONG_MAX, 3UL, ULONG_MAX );
  FD_TEST( mine );
  mine->mine = 1;
  for( ulong i=0UL; i<2UL; i++ ) {
    fd_gui_handle_replay_update( gui, &completed, ts+300L );
    fd_http_server_stage_trunc( gui->http, 0UL );
  }
  FD_TEST( fd_gui_slot_get( gui, slot2, 3UL )->timeline_mine_accounted );
  fd_gui_timeline_day_t const * day = fd_gui_timeline_day_get( gui, 0UL );
  FD_TEST( day && fd_gui_timeline_field_get( day, FD_GUI_TIMELINE_GRANULARITY_250MS, FD_GUI_TIMELINE_FIELD_MINE, idx )==1UL );

  FD_TEST( fd_http_server_delete( fd_http_server_leave( gui->http ) )==http_mem );
  free( http_mem );
  gui->http = NULL;
  FD_LOG_NOTICE(( "test_timeline_replay_batches: mine counted once: ok" ));
}

static void
test_timeline_marker_order( fd_gui_t * gui ) {
  void * http_mem = timeline_http_open( gui );
  long ts = sec_ns( 10UL );
  fd_gui_shred_event_t input[] = {
    { .slot=103U, .idx=USHORT_MAX, .event=FD_GUI_SLOT_SHRED_SHRED_SLOT_COMPLETE, .event_time_ns=ts+80L },
    { .slot=100U, .idx=1U, .event=FD_GUI_SLOT_SHRED_REPAIR_REQUEST, .event_time_ns=ts+70L },
    { .slot=105U, .idx=USHORT_MAX, .event=FD_GUI_SLOT_SHRED_SHRED_SLOT_COMPLETE, .event_time_ns=ts+75L },
    { .slot=101U, .idx=2U, .event=FD_GUI_SLOT_SHRED_SHRED_RECEIVED_TURBINE, .event_time_ns=ts+90L },
    { .slot=103U, .idx=USHORT_MAX, .event=FD_GUI_SLOT_SHRED_SHRED_SLOT_COMPLETE, .event_time_ns=ts+60L },
    { .slot=104U, .idx=USHORT_MAX, .event=FD_GUI_SLOT_SHRED_SHRED_SLOT_COMPLETE, .event_time_ns=ts+85L },
    { .slot=102U, .idx=3U, .event=FD_GUI_SLOT_SHRED_SHRED_REPLAY_EXEC_DONE, .event_time_ns=ts+65L },
    { .slot=105U, .idx=USHORT_MAX, .event=FD_GUI_SLOT_SHRED_SHRED_SLOT_COMPLETE, .event_time_ns=ts+40L },
    { .slot=104U, .idx=USHORT_MAX, .event=FD_GUI_SLOT_SHRED_SHRED_SLOT_COMPLETE, .event_time_ns=ts+45L },
    { .slot=103U, .idx=USHORT_MAX, .event=FD_GUI_SLOT_SHRED_SHRED_SLOT_COMPLETE, .event_time_ns=ts+100L }
  };
  ulong appended = 0UL;
  for( ulong fixture=0UL; fixture<2UL; fixture++ ) {
    ulong count = fixture ? sizeof(input)/sizeof(input[ 0 ]) : 2UL;
    for( ; appended<count; appended++ ) {
      fd_gui_shred_event_t const * e = &input[ appended ];
      if( e->event==FD_GUI_SLOT_SHRED_SHRED_SLOT_COMPLETE ) fd_gui_shred_event_slot_complete( gui, e->slot, e->event_time_ns, ts );
      else fd_gui_fec_event_append( gui, e->slot, e->idx, e->event, e->event_time_ns, ts );
    }
    for( ulong query=0UL; query<(fixture ? 4UL : 1UL); query++ ) {
      long starts[] = { ts+30L, ts+50L, ts+61L, ts+50L };
      long start = starts[ query ];
      long end   = query==3UL ? ts+76L : ts+101L;
      fd_gui_shred_event_t oracle[ 10 ];
      ulong n       = 0UL;
      ulong refslot = ULONG_MAX;
      long  refts   = LONG_MAX;
      for( ulong i=0UL; i<count; i++ ) {
        fd_gui_shred_event_t const * e = &input[ i ];
        if( e->event_time_ns<start || e->event_time_ns>=end ) continue;
        oracle[ n++ ] = *e;
        refslot = fd_ulong_min( refslot, e->slot );
        refts   = fd_long_min( refts, e->event_time_ns );
      }
      ulong expected[] = { 10UL, 8UL, 7UL, 4UL };
      FD_TEST( n==(fixture ? expected[ query ] : 2UL) );
      if( !fixture ) FD_TEST( oracle[ 0 ].slot==103U && oracle[ 1 ].slot==100U );
      FD_TEST( !fd_gui_printf_timeline_query_fec_events( gui, start, end, 7UL ) );
      test_json_t json = timeline_response( gui );
      FD_TEST( !test_json_field( json, "error" ).ptr );
      FD_TEST( test_json_count( timeline_value( json, "idx" ) )==(int)n );
      FD_TEST( test_json_ulong( timeline_value( json, "reference_slot" ) )==refslot );
      char expected_ts[ 32 ];
      fd_cstr_printf_check( expected_ts, sizeof(expected_ts), NULL, "%ld", refts );
      FD_TEST( test_json_string_eq( timeline_value( json, "reference_ts" ), expected_ts ) );
      for( ulong i=0UL; i<n; i++ ) {
        FD_TEST( test_json_ulong( test_json_index( timeline_value( json, "slot_delta" ), (int)i ) )==oracle[ i ].slot-refslot );
        FD_TEST( test_json_ulong( test_json_index( timeline_value( json, "event" ), (int)i ) )==oracle[ i ].event );
        test_json_t idx = test_json_index( timeline_value( json, "idx" ), (int)i );
        FD_TEST( oracle[ i ].idx==USHORT_MAX ? (test_json_kind( idx )==FD_JTOK_NULL)
                  : (test_json_kind( idx )==FD_JTOK_INT) && test_json_ulong( idx )==oracle[ i ].idx );
        fd_cstr_printf_check( expected_ts, sizeof(expected_ts), NULL, "%ld", oracle[ i ].event_time_ns-refts );
        FD_TEST( test_json_string_eq( test_json_index( timeline_value( json, "event_ts_delta" ), (int)i ), expected_ts ) );
      }

    }
  }
  FD_TEST( fd_http_server_delete( fd_http_server_leave( gui->http ) )==http_mem );
  free( http_mem );
  gui->http = NULL;
  FD_LOG_NOTICE(( "test_timeline_marker_order: duplicate completions preserved, requested-window filtering: ok" ));
}

static void
test_timeline_marker_limits( fd_gui_t * gui ) {
  void * http_mem = timeline_http_open( gui );
  long ts = sec_ns( 10UL );
  for( ulong i=0UL; i<FD_GUI_TIMELINE_QUERY_SHRED_MAX; i++ ) {
    /* Advance the cutoff with the slots so every marker stays within
       the admission horizon. */
    if( !(i%FD_GUI_FEC_SLOT_WMARK_CNT) ) fd_gui_event_closed_slot_wmark_advance( gui, i );
    fd_gui_fec_event_append( gui, i, USHORT_MAX, FD_GUI_SLOT_SHRED_SHRED_SLOT_COMPLETE, ts+1L, ts );
  }
  FD_TEST( !gui->shreds.dropped_fec_event_cnt );
  FD_TEST( !fd_gui_printf_timeline_query_fec_events( gui, ts+1L, ts+2L, 7UL ) );
  test_json_t json = timeline_response( gui );
  FD_TEST( test_json_count( timeline_value( json, "idx" ) )==(int)FD_GUI_TIMELINE_QUERY_SHRED_MAX );

  /* A duplicate counts toward the same result limit as any other row. */
  fd_gui_fec_event_append( gui, 0UL, USHORT_MAX, FD_GUI_SLOT_SHRED_SHRED_SLOT_COMPLETE, ts+1L, ts );
  FD_TEST( !fd_gui_printf_timeline_query_fec_events( gui, ts+1L, ts+2L, 7UL ) );
  json = timeline_response( gui );
  FD_TEST( test_json_string_eq( test_json_field( test_json_field( json, "error" ), "code" ), "result_limit_exceeded" ) );

  /* Earlier markers do not count toward the requested window's limit. */
  FD_TEST( !fd_gui_printf_timeline_query_fec_events( gui, ts+2L, ts+3L, 7UL ) );
  json = timeline_response( gui );
  FD_TEST( !test_json_field( json, "error" ).ptr );
  FD_TEST( !test_json_count( timeline_value( json, "idx" ) ) );
  FD_TEST( fd_http_server_delete( fd_http_server_leave( gui->http ) )==http_mem );
  free( http_mem );
  gui->http = NULL;
  FD_LOG_NOTICE(( "test_timeline_marker_limits: result limit includes duplicates and excludes earlier markers: ok" ));
}

static void
test_timeline_limits( fd_gui_t * gui ) {
  void * http_mem = timeline_http_open( gui );
  long const ts = sec_ns( 10UL );
  for( ulong i=0UL; i<FD_GUI_TIMELINE_QUERY_SHRED_MAX; i++ ) {
    ulong slot = 100UL + i/65535UL;
    fd_gui_shred_event_append( gui, slot, i%65535UL, FD_GUI_SLOT_SHRED_REPAIR_REQUEST, ts, ts );
    fd_gui_fec_event_append( gui, slot, i%65535UL, FD_GUI_SLOT_SHRED_REPAIR_REQUEST, ts, ts );
    if( i%65535UL==65534UL ) fd_gui_event_closed_slot_wmark_advance( gui, slot+1UL );
  }
  fd_gui_event_closed_slot_wmark_advance( gui, 109UL );
  FD_TEST( !gui->shreds.dropped_event_cnt && !gui->shreds.dropped_fec_event_cnt );
  for( int fec=0; fec<2; fec++ ) {
    FD_TEST( !(fec ? fd_gui_printf_timeline_query_fec_events( gui, ts, ts+1L, 7UL )
                  : fd_gui_printf_timeline_query_shreds( gui, ts, ts+1L, 7UL )) );
    FD_TEST( fd_http_server_stage_len( gui->http )<(32UL<<20) );
    test_json_t json = timeline_response( gui );
    FD_TEST( test_json_count( timeline_value( json, "idx" ) )==(int)FD_GUI_TIMELINE_QUERY_SHRED_MAX );

  }
  fd_gui_shred_event_append( gui, 109UL, 0UL, FD_GUI_SLOT_SHRED_REPAIR_REQUEST, ts, ts );
  fd_gui_fec_event_append( gui, 109UL, 0UL, FD_GUI_SLOT_SHRED_REPAIR_REQUEST, ts, ts );
  fd_gui_event_closed_slot_wmark_advance( gui, 110UL );
  for( int fec=0; fec<2; fec++ ) {
    FD_TEST( !(fec ? fd_gui_printf_timeline_query_fec_events( gui, ts, ts+1L, 7UL )
                  : fd_gui_printf_timeline_query_shreds( gui, ts, ts+1L, 7UL )) );
    test_json_t json = timeline_response( gui );
    FD_TEST( test_json_string_eq( test_json_field( test_json_field( json, "error" ), "code" ), "result_limit_exceeded" ) );

  }

  fd_gui_store_replay_txn_t txn = { .insert_time_ns=ts, .completion_time_ns=ts, .slot=100UL, .block_compute_unit_limit=ULONG_MAX,
    .txn_start_shred_idx=UINT_MAX-1U, .txn_end_shred_idx=UINT_MAX-1U,
    .load_start_ns=ts-1L, .check_start_ns=ts-1L, .exec_start_ns=ts-1L, .commit_start_ns=ts-1L, .commit_end_ns=ts };
  fd_gui_store_replay_txn_batch_t tb = { .insert_time_ns=ts, .completion_time_ns=ts, .slot=100UL, .sigverify_txn_cnt=1U,
    .load_start_ns=ts-1L, .commit_end_ns=ts };
  gui->tile_state.exec_cnt = 1UL;
  gui->tile_state.pos_cnt  = 1UL;
  for( ulong i=0UL; i<FD_GUI_TIMELINE_QUERY_TXN_MAX; i++ ) {
    txn.txn_idx = i;
    tb.batch_idx = i;
    FD_TEST( !fd_gui_hist_ts_append( gui, FD_GUI_HIST_REPLAY_TXN, &txn ) );
    FD_TEST( !fd_gui_hist_ts_append( gui, FD_GUI_HIST_REPLAY_TXN_BATCH, &tb ) );
  }
  for( int kind=0; kind<3; kind++ ) {
    FD_TEST( !(kind==1 ? fd_gui_printf_timeline_query_txn_meta( gui, ts, ts+1L, 7UL )
                       : fd_gui_printf_timeline_query_tile_states( gui, ts, ts+1L, kind==2, 7UL )) );
    FD_TEST( fd_http_server_stage_len( gui->http )<(32UL<<20) );
    test_json_t json = timeline_response( gui );
    /* The identical txn rows overlap on one tile, so only the first
       is laid out; batch granularity reports states only. */
    FD_TEST( test_json_count( timeline_value( json, "txn_idx" ) )==(kind==1 ? (int)FD_GUI_TIMELINE_QUERY_TXN_MAX : kind==0) );
    if( kind==1 ) {
      FD_TEST( test_json_count( timeline_value( json, "txn_start_shred_idx" ) )==(int)FD_GUI_TIMELINE_QUERY_TXN_MAX );
      FD_TEST( test_json_count( timeline_value( json, "txn_end_shred_idx" ) )==(int)FD_GUI_TIMELINE_QUERY_TXN_MAX );
    } else {
      FD_TEST( !timeline_value( json, "txn_start_shred_idx" ).ptr && !timeline_value( json, "txn_end_shred_idx" ).ptr );
    }

  }
  FD_TEST( !fd_gui_hist_ts_append( gui, FD_GUI_HIST_REPLAY_TXN, &txn ) );
  FD_TEST( !fd_gui_hist_ts_append( gui, FD_GUI_HIST_REPLAY_TXN_BATCH, &tb ) );
  for( int kind=0; kind<3; kind++ ) {
    FD_TEST( !(kind==1 ? fd_gui_printf_timeline_query_txn_meta( gui, ts, ts+1L, 7UL )
                       : fd_gui_printf_timeline_query_tile_states( gui, ts, ts+1L, kind==2, 7UL )) );
    test_json_t json = timeline_response( gui );
    FD_TEST( test_json_string_eq( test_json_field( test_json_field( json, "error" ), "code" ), "result_limit_exceeded" ) );

  }
  gui->tile_state.exec_cnt = 0UL;
  gui->tile_state.pos_cnt  = 0UL;
  put_epoch( gui, 0UL, 0UL, FD_GUI_TIMELINE_QUERY_SLOT_MAX+1UL );
  gui->epoch.current_epoch = 0UL;
  fd_gui_epoch_t * epoch = fd_gui_epoch( gui, 0UL );
  epoch->timeline_slot_lo_idx = 0UL;
  epoch->timeline_slot_hi_idx = FD_GUI_TIMELINE_QUERY_SLOT_MAX-1UL;
  for( ulong i=0UL; i<=FD_GUI_TIMELINE_QUERY_SLOT_MAX; i++ ) {
    epoch->timeline_slot_start_ns[ i ] = ts;
    epoch->timeline_slot_end_ns[ i ]   = ts + 1L;
    epoch->timeline_slot_state[ i ]    = FD_GUI_TIMELINE_SLOT_STATE_VALID;
  }
  epoch->timeline_slot_min_start_ns = ts;
  epoch->timeline_slot_max_end_ns   = ts + 1L;
  epoch_reblk( epoch );
  FD_TEST( !fd_gui_printf_timeline_query_slots( gui, ts, ts+1L, 7UL ) );
  test_json_t json = timeline_response( gui );
  FD_TEST( test_json_count( timeline_value( json, "slot_delta" ) )==(int)FD_GUI_TIMELINE_QUERY_SLOT_MAX );

  epoch->timeline_slot_hi_idx++;
  FD_TEST( !fd_gui_printf_timeline_query_slots( gui, ts, ts+1L, 7UL ) );
  json = timeline_response( gui );
  FD_TEST( test_json_string_eq( test_json_field( test_json_field( json, "error" ), "code" ), "result_limit_exceeded" ) );

  FD_TEST( !fd_gui_printf_timeline_query_agg( gui, "query_agg_compute", "100ms", 2UL, ts, FD_GUI_TIMELINE_QUERY_MAX_BUCKETS, 7UL ) );
  json = timeline_response( gui );
  FD_TEST( test_json_count( timeline_value( json, "compute_units" ) )==(int)FD_GUI_TIMELINE_QUERY_MAX_BUCKETS );

  /* Slot order need not match timestamp order.  The reference timestamp
     must come from the earliest returned interval, not the first row. */
  epoch->timeline_slot_lo_idx         = 10UL;
  epoch->timeline_slot_hi_idx         = 12UL;
  epoch->timeline_slot_start_ns[ 10 ] = 30L;
  epoch->timeline_slot_end_ns[ 10 ]   = 40L;
  epoch->timeline_slot_start_ns[ 11 ] = 10L;
  epoch->timeline_slot_end_ns[ 11 ]   = 20L;
  epoch->timeline_slot_start_ns[ 12 ] = 20L;
  epoch->timeline_slot_end_ns[ 12 ]   = 30L;
  epoch->timeline_slot_min_start_ns   = 10L;
  epoch->timeline_slot_max_end_ns     = 40L;
  epoch_reblk( epoch );
  FD_TEST( !fd_gui_printf_timeline_query_slots( gui, 0L, 50L, 7UL ) );
  json = timeline_response( gui );
  FD_TEST( test_json_ulong( timeline_value( json, "reference_slot" ) )==10UL );
  FD_TEST( test_json_string_eq( timeline_value( json, "reference_ts" ), "10" ) );
  FD_TEST( test_json_string_eq( timeline_value( json, "available_start_ns" ), "10" ) );
  FD_TEST( test_json_string_eq( timeline_value( json, "available_end_ns" ), "40" ) );
  char const * starts[] = { "20", "0", "10" };
  char const * ends[]   = { "30", "10", "20" };
  for( int i=0; i<3; i++ ) {
    FD_TEST( test_json_ulong( test_json_index( timeline_value( json, "slot_delta" ), i ) )==(ulong)i );
    FD_TEST( test_json_string_eq( test_json_index( timeline_value( json, "start_ts_delta" ), i ), starts[ i ] ) );
    FD_TEST( test_json_string_eq( test_json_index( timeline_value( json, "end_ts_delta" ), i ), ends[ i ] ) );
  }
  /* Revenue columns come from the canonical block record: null without
     one, and for skipped slots even with one. */
  for( int i=0; i<3; i++ ) {
    FD_TEST( test_json_kind( test_json_index( timeline_value( json, "txn_fees" ), i ) )==FD_JTOK_NULL );
    FD_TEST( test_json_kind( test_json_index( timeline_value( json, "tips" ), i ) )==FD_JTOK_NULL );
  }
  ulong const rooted = gui->summary.slot_rooted;
  gui->summary.slot_rooted = 100UL;
  for( ulong s=10UL; s<=12UL; s++ ) {
    put_slot( gui, s, 0L );
    fd_gui_slot_t * rec = fd_gui_slot_get( gui, s, BANK_SEQ );
    rec->skip            = FD_GUI_SKIP_STATUS_NOT_SKIPPED;
    rec->transaction_fee = 5000UL*s;
    rec->priority_fee    = s==11UL ? ULONG_MAX : 100UL*s;
    rec->tips            = s;
  }
  epoch->timeline_slot_state[ 12 ] |= FD_GUI_TIMELINE_SLOT_STATE_SKIPPED;
  FD_TEST( !fd_gui_printf_timeline_query_slots( gui, 0L, 50L, 7UL ) );
  json = timeline_response( gui );
  FD_TEST( test_json_string_eq( test_json_index( timeline_value( json, "txn_fees" ), 0 ), "50000" ) );
  FD_TEST( test_json_string_eq( test_json_index( timeline_value( json, "prio_fees" ), 0 ), "1000" ) );
  FD_TEST( test_json_string_eq( test_json_index( timeline_value( json, "tips" ), 0 ), "10" ) );
  FD_TEST( test_json_string_eq( test_json_index( timeline_value( json, "txn_fees" ), 1 ), "55000" ) );
  FD_TEST( test_json_kind( test_json_index( timeline_value( json, "prio_fees" ), 1 ) )==FD_JTOK_NULL );
  FD_TEST( test_json_kind( test_json_index( timeline_value( json, "txn_fees" ), 2 ) )==FD_JTOK_NULL );
  FD_TEST( test_json_kind( test_json_index( timeline_value( json, "tips" ), 2 ) )==FD_JTOK_NULL );
  epoch->timeline_slot_state[ 12 ] &= (uchar)~FD_GUI_TIMELINE_SLOT_STATE_SKIPPED;
  gui->summary.slot_rooted = rooted;
  FD_TEST( !fd_gui_printf_timeline_query_slots( gui, 20L, 40L, 7UL ) );
  json = timeline_response( gui );
  FD_TEST( test_json_string_eq( timeline_value( json, "reference_ts" ), "20" ) );
  FD_TEST( !fd_gui_printf_timeline_query_slots( gui, 40L, 50L, 7UL ) );
  json = timeline_response( gui );
  FD_TEST( test_json_kind( timeline_value( json, "reference_slot" ) )==FD_JTOK_NULL );
  FD_TEST( test_json_kind( timeline_value( json, "reference_ts" ) )==FD_JTOK_NULL );
  /* Epochs whose interval hull misses the window are not scanned, and
     the availability bounds come from the hull alone. */
  ulong rows = 0UL;
  FD_TEST( !fd_gui_timeline_slots_collect( gui, 0L, 50L, gui->timeline_scratch.slots, 3UL, &rows ) && rows==3UL );
  /* Blocks whose hull misses the window are skipped whole: slot 200
     (block 3) is found alone, and the others still without it. */
  epoch->timeline_slot_start_ns[ 200 ] = 41L;
  epoch->timeline_slot_end_ns[ 200 ]   = 45L;
  epoch->timeline_slot_state[ 200 ]    = FD_GUI_TIMELINE_SLOT_STATE_VALID;
  epoch->timeline_slot_hi_idx          = 200UL;
  epoch->timeline_slot_max_end_ns      = 45L;
  epoch_reblk( epoch );
  FD_TEST( epoch->timeline_blk_min_start_ns[ 3 ]==41L );
  FD_TEST( !fd_gui_timeline_slots_collect( gui, 40L, 50L, gui->timeline_scratch.slots, 3UL, &rows ) && rows==1UL &&
           gui->timeline_scratch.slots[ 0 ].slot==200UL );
  FD_TEST( !fd_gui_timeline_slots_collect( gui, 0L, 40L, gui->timeline_scratch.slots, 3UL, &rows ) && rows==3UL );
  epoch->timeline_slot_state[ 200 ] = 0;
  epoch->timeline_slot_hi_idx       = 12UL;
  epoch->timeline_slot_max_end_ns   = 40L;
  epoch->timeline_slot_min_start_ns = 100L;
  epoch->timeline_slot_max_end_ns   = 200L;
  FD_TEST( !fd_gui_timeline_slots_collect( gui, 0L, 50L, gui->timeline_scratch.slots, 3UL, &rows ) && !rows );
  FD_TEST( !fd_gui_printf_timeline_query_slots( gui, 0L, 50L, 7UL ) );
  json = timeline_response( gui );
  FD_TEST( test_json_string_eq( timeline_value( json, "available_start_ns" ), "100" ) );
  FD_TEST( test_json_string_eq( timeline_value( json, "available_end_ns" ), "200" ) );

  /* query_events: leader_skip is a skipped slot scheduled to us, at
     its interval midpoint.  Rotation 0 (slots 0-3) is ours, rotation 1
     (slots 4-7) belongs to someone else. */
  memset( gui->summary.identity_key->uc, 0xAB, 32UL );
  memset( epoch->pub[ 0 ].uc, 0xAB, 32UL );
  memset( epoch->pub[ 1 ].uc, 0xCD, 32UL );
  epoch->pub_cnt = 2UL;
  for( ulong i=0UL; i<=FD_GUI_TIMELINE_QUERY_EVENT_MAX; i++ ) {
    epoch->timeline_slot_start_ns[ i ] = ts;
    epoch->timeline_slot_end_ns[ i ]   = ts + 2L;
    epoch->timeline_slot_state[ i ]    = FD_GUI_TIMELINE_SLOT_STATE_VALID | FD_GUI_TIMELINE_SLOT_STATE_SKIPPED;
  }
  epoch->timeline_slot_lo_idx       = 0UL;
  epoch->timeline_slot_hi_idx       = FD_GUI_TIMELINE_QUERY_EVENT_MAX-1UL;
  epoch->timeline_slot_min_start_ns = ts;
  epoch->timeline_slot_max_end_ns   = ts + 2L;
  epoch_reblk( epoch );
  FD_TEST( !fd_gui_printf_timeline_query_events( gui, ts, ts+2L, 7UL ) );
  json = timeline_response( gui );
  FD_TEST( test_json_count( timeline_value( json, "slot" ) )==(int)FD_GUI_TIMELINE_QUERY_EVENT_MAX );
  epoch->timeline_slot_hi_idx++;
  FD_TEST( !fd_gui_printf_timeline_query_events( gui, ts, ts+2L, 7UL ) );
  json = timeline_response( gui );
  FD_TEST( test_json_string_eq( test_json_field( test_json_field( json, "error" ), "code" ), "result_limit_exceeded" ) );

  epoch->sched[ 1 ] = 1U;
  epoch->timeline_slot_lo_idx = 0UL;
  epoch->timeline_slot_hi_idx = 7UL;
  for( ulong i=0UL; i<8UL; i++ ) {
    epoch->timeline_slot_start_ns[ i ] = 10L*(long)i;
    epoch->timeline_slot_end_ns[ i ]   = 10L*(long)i + 10L;
  }
  epoch->timeline_slot_state[ 1 ]   = FD_GUI_TIMELINE_SLOT_STATE_VALID;                                    /* landed */
  epoch->timeline_slot_state[ 3 ]   = FD_GUI_TIMELINE_SLOT_STATE_SKIPPED;                                  /* unclassified */
  epoch->timeline_slot_end_ns[ 2 ]  = 31L;                                                                 /* midpoint 25 */
  epoch->timeline_slot_min_start_ns = 0L;
  epoch->timeline_slot_max_end_ns   = 80L;
  epoch_reblk( epoch );
  FD_TEST( !fd_gui_printf_timeline_query_events( gui, 0L, 100L, 7UL ) );
  json = timeline_response( gui );
  FD_TEST( test_json_string_eq( timeline_value( json, "available_start_ns" ), "0" ) );
  FD_TEST( test_json_string_eq( timeline_value( json, "available_end_ns" ), "80" ) );
  FD_TEST( test_json_count( timeline_value( json, "event" ) )==2 );
  FD_TEST( test_json_count( timeline_value( json, "ts" ) )==2 );
  FD_TEST( test_json_ulong( test_json_index( timeline_value( json, "event" ), 0 ) )==FD_GUI_TIMELINE_EVENT_LEADER_SKIP );
  FD_TEST( test_json_ulong( test_json_index( timeline_value( json, "slot" ), 0 ) )==0UL );
  FD_TEST( test_json_ulong( test_json_index( timeline_value( json, "slot" ), 1 ) )==2UL );
  FD_TEST( test_json_string_eq( test_json_index( timeline_value( json, "ts" ), 0 ), "5" ) );
  FD_TEST( test_json_string_eq( test_json_index( timeline_value( json, "ts" ), 1 ), "25" ) );
  /* Half-open on the midpoint. */
  FD_TEST( !fd_gui_printf_timeline_query_events( gui, 5L, 25L, 7UL ) );
  json = timeline_response( gui );
  FD_TEST( test_json_count( timeline_value( json, "slot" ) )==1 );
  FD_TEST( test_json_ulong( test_json_index( timeline_value( json, "slot" ), 0 ) )==0UL );
  FD_TEST( !fd_gui_printf_timeline_query_events( gui, 6L, 25L, 7UL ) );
  json = timeline_response( gui );
  FD_TEST( test_json_count( timeline_value( json, "event" ) )==0 );
  FD_TEST( test_json_count( timeline_value( json, "slot" ) )==0 );
  FD_TEST( test_json_count( timeline_value( json, "ts" ) )==0 );

  FD_TEST( fd_http_server_delete( fd_http_server_leave( gui->http ) )==http_mem );
  free( http_mem );
  gui->http = NULL;
  FD_LOG_NOTICE(( "test_timeline_limits: ok" ));
}

static void
test_live_shred_receive_time( fd_gui_t * gui ) {
  void * http_mem = timeline_http_open( gui );
  long watermark = sec_ns( 10UL );
  long now       = watermark + 100L;
  fd_gui_shred_event_t event = { .insert_time_ns=now-1L, .event_time_ns=watermark-1000L,
    .slot=100U, .idx=7U, .event=FD_GUI_SLOT_SHRED_REPAIR_REQUEST };
  fd_gui_handle_repair_request( gui, event.slot, event.idx, event.event_time_ns, event.insert_time_ns );
  FD_TEST( gui->shreds.builder.batch.event_cnt==1U );
  FD_TEST( !fd_gui_store_metrics( gui->db )->ts_appends[ FD_GUI_HIST_SHRED_EVENTS ] );
  for( int sealed=0; sealed<2; sealed++ ) {
    assert_shreds( gui, &event, 1UL, watermark, now-1L );
    FD_TEST( fd_gui_shred_window_is_empty( gui, watermark, now-2L ) );
    FD_TEST( fd_gui_shred_window_is_empty( gui, now, now+1L ) );
    fd_gui_printf_shred_updates( gui, watermark, now-1L );
    test_json_t json = timeline_response( gui );
    FD_TEST( test_json_count( timeline_value( json, "shred_idx" ) )==1 );
    FD_TEST( test_json_ulong( test_json_index( timeline_value( json, "shred_idx" ), 0 ) )==7UL );
    FD_TEST( test_json_string_eq( timeline_value( json, "reference_ts" ), "9999999000" ) );
    FD_TEST( !fd_gui_printf_timeline_query_shreds( gui, event.event_time_ns, event.event_time_ns+1L, 7UL ) );
    json = timeline_response( gui );
    FD_TEST( test_json_count( timeline_value( json, "idx" ) )==1 );
    FD_TEST( !fd_gui_printf_timeline_query_shreds( gui, event.event_time_ns-1L, event.event_time_ns, 7UL ) );
    json = timeline_response( gui );
    FD_TEST( !test_json_count( timeline_value( json, "idx" ) ) );
    fd_gui_shred_flush( gui, watermark+sec_ns( 1UL ) );
  }
  FD_TEST( fd_http_server_delete( fd_http_server_leave( gui->http ) )==http_mem );
  free( http_mem );
  gui->http = NULL;
  FD_LOG_NOTICE(( "test_live_shred_receive_time: late producer timestamps, inclusive receive bounds, active history: ok" ));
}

static void
test_timeline_leader_txns( fd_gui_t * gui ) {
  void * http_mem = timeline_http_open( gui );
  long const  ts       = sec_ns( 10UL );
  long const  now      = ts + 500000000L;
  ulong const slot     = 500UL;
  ulong const bank_seq = 7UL;
  /* Make the local tick sample difference sub-nanosecond so absolute
     timestamps are deterministic, independently of test execution speed. */
  gui->tick_per_ns                           = 1e30;
  gui->slot_txn_scratch.max                   = 8UL;
  gui->summary.slot_caught_up                = ULONG_MAX;
  for( ulong i=0UL; i<FD_GUI_TURBINE_SLOT_HISTORY_SZ; i++ ) gui->summary.slots_max_turbine[ i ].slot = ULONG_MAX;
  fd_gui_became_leader( gui, slot, ts, ts+sec_ns( 1UL ), 60000000UL, 8UL, bank_seq );
  FD_TEST( fd_gui_slot_leader_get( gui, slot, bank_seq )->max_compute_units==60000000UL );
  FD_TEST( fd_gui_slot_leader_get_or_create( gui, slot+1UL, bank_seq )->max_compute_units==ULONG_MAX );

  /* A parsed packet with a CU limit, a CU price and two precompile
     signatures.  Execution results below are supplied by the mock trailer. */
  fd_txn_p_t txn = {0};
  txn.payload[ 0 ]  = 1U;
  txn.payload[ 65 ] = 1U;
  txn.payload[ 67 ] = 2U;
  txn.payload[ 68 ] = 3U;
  fd_memcpy( txn.payload+101UL, &fd_solana_compute_budget_program_id, 32UL );
  fd_memcpy( txn.payload+133UL, &fd_solana_ed25519_sig_verify_program_id, 32UL );
  txn.payload[ 197 ] = 3U;
  uchar instrs[] = { 1U,0U,5U,2U,0xE8U,3U,0U,0U, /* CU limit 1000 */
                   1U,0U,9U,3U,0x40U,0x42U,0x0FU,0U,0U,0U,0U,0U, /* price 1e6 */
                   2U,0U,30U,2U,0U };
  fd_memcpy( txn.payload+198UL, instrs, sizeof(instrs) );
  txn.payload_sz = (ushort)(198UL+sizeof(instrs)+28UL);
  FD_TEST( fd_txn_parse( txn.payload, txn.payload_sz, TXN( &txn ), NULL ) );
  ulong priority   = 0UL;
  ulong precompile = 0UL;
  ulong requested  = fd_pack_compute_cost( TXN( &txn ), txn.payload, NULL, &priority, &precompile, NULL, NULL );
  FD_TEST( requested && priority==1000UL && precompile==2UL );
  fd_txn_ns_dt_t dt = { .load_start=10.4f, .check_start=20.6f, .exec_start=30.4f, .commit_start=60.6f, .commit_end=100.4f };
  txn.pack_alloc = 0x12345678U; /* Not shred indices, despite sharing their union. */
  for( ulong i=0UL; i<2UL; i++ ) {
    txn.flags = FD_TXN_P_FLAGS_EXECUTE_SUCCESS;
    if( i ) txn.flags |= FD_TXN_P_FLAGS_FEES_ONLY | (200U<<24);
    txn.execle_cu.actual_consumed_cus = 42U;
    memset( txn.payload+1UL, (int)(i+1UL), FD_TXN_SIGNATURE_SZ );
    fd_gui_microblock_execution_end( gui, now+1000L, 3UL, slot, 1UL, &txn, 17UL+i*3UL, dt, fd_tickcount(), 7UL, bank_seq, now );
  }
  /* Neither a non-landed transaction nor a missing commit tick produces a row. */
  txn.flags = 0U;
  fd_gui_microblock_execution_end( gui, now, 3UL, slot, 1UL, &txn, 21UL, dt, fd_tickcount(), 7UL, bank_seq, now );
  txn.flags = FD_TXN_P_FLAGS_EXECUTE_SUCCESS;
  fd_gui_microblock_execution_end( gui, now, 3UL, slot, 1UL, &txn, 22UL, dt, LONG_MAX, 7UL, bank_seq, now );
  FD_TEST( count_ts( gui, FD_GUI_HIST_REPLAY_TXN, ULONG_MAX )==2UL );
  fd_gui_hist_iter_t it;
  FD_TEST( !fd_gui_hist_range_begin( gui, &it, FD_GUI_HIST_REPLAY_TXN, now, now, NULL, NULL ) );
  for( ulong i=0UL; i<2UL; i++ ) {
    FD_TEST( fd_gui_hist_range_next( &it ) );
    fd_gui_store_replay_txn_t const * rec = it.rec;
    FD_TEST( rec->slot==slot && rec->txn_idx==17UL+i*3UL && rec->txn_exec_idx==3UL );
    FD_TEST( rec->txn_sigverify_exec_idx==ULONG_MAX && rec->sigverify_start_ns==LONG_MAX && rec->sigverify_end_ns==LONG_MAX );
    FD_TEST( rec->txn_start_shred_idx==UINT_MAX && rec->txn_end_shred_idx==UINT_MAX );
    FD_TEST( rec->insert_time_ns==now && rec->completion_time_ns==now && rec->commit_end_ns==now );
    FD_TEST( rec->load_start_ns==now-90L && rec->check_start_ns==now-79L && rec->exec_start_ns==now-70L && rec->commit_start_ns==now-39L );
    FD_TEST( rec->block_compute_unit_limit==60000000UL && rec->compute_units_requested==requested && rec->compute_units_consumed==42U );
    FD_TEST( rec->transaction_fee==15000UL && rec->priority_fee==1000UL && rec->tips==7UL );
    FD_TEST( rec->is_committable && rec->is_fees_only==i && rec->error_code==i*200UL );
    for( ulong j=0UL; j<FD_TXN_SIGNATURE_SZ; j++ ) FD_TEST( rec->signature[ j ]==i+1UL );
  }
  FD_TEST( !fd_gui_hist_range_next( &it ) );
  fd_gui_hist_range_end( &it );

  /* Leader rows index execle tiles and have no sigverify lane, so
     query_tile_states skips them. */
  gui->tile_state.exec_cnt = 4UL;
  gui->tile_state.pos_cnt  = 4UL;
  FD_TEST( !fd_gui_printf_timeline_query_tile_states( gui, now-100L, now+1L, 0, 7UL ) );
  {
    test_json_t json = timeline_response( gui );
    FD_TEST( !test_json_count( timeline_value( json, "txn_idx" ) ) );
    FD_TEST( !test_json_count( timeline_value( json, "state" ) ) ); /* tiles without states are empty */
  }
  for( int meta=1; meta<2; meta++ ) {
    FD_TEST( !fd_gui_printf_timeline_query_txn_meta( gui, now, now+1L, 7UL ) );
    test_json_t json = timeline_response( gui );
    FD_TEST( test_json_count( timeline_value( json, "txn_idx" ) )==2 );
    if( meta ) {
      FD_TEST( test_json_count( timeline_value( json, "txn_start_shred_idx" ) )==2 );
      FD_TEST( test_json_count( timeline_value( json, "txn_end_shred_idx" ) )==2 );
    } else {
      FD_TEST( !timeline_value( json, "txn_start_shred_idx" ).ptr && !timeline_value( json, "txn_end_shred_idx" ).ptr );
    }
    FD_TEST( test_json_string_eq( timeline_value( json, "reference_ts" ), "10499999910" ) );
    for( int i=0; i<2; i++ ) {
      FD_TEST( test_json_ulong( test_json_index( timeline_value( json, "txn_idx" ), i ) )==17UL+3UL*(ulong)i );
      FD_TEST( test_json_ulong( test_json_index( timeline_value( json, "txn_exec_idx" ), i ) )==3UL );
      FD_TEST( test_json_kind( test_json_index( timeline_value( json, "txn_sigverify_exec_idx" ), i ) )==FD_JTOK_NULL );
      if( !meta ) {
        FD_TEST( test_json_kind( test_json_index( timeline_value( json, "txn_sigverify_start_ts_delta" ), i ) )==FD_JTOK_NULL );
        FD_TEST( test_json_kind( test_json_index( timeline_value( json, "txn_sigverify_end_ts_delta" ), i ) )==FD_JTOK_NULL );
        FD_TEST( test_json_string_eq( test_json_index( timeline_value( json, "txn_commit_end_ts_delta" ), i ), "90" ) );
      } else {
        FD_TEST( test_json_string_eq( test_json_index( timeline_value( json, "txn_transaction_fee" ), i ), "15000" ) );
        FD_TEST( test_json_string_eq( test_json_index( timeline_value( json, "txn_priority_fee" ), i ), "1000" ) );
        FD_TEST( test_json_ulong( test_json_index( timeline_value( json, "txn_compute_units_requested" ), i ) )==requested );
        FD_TEST( test_json_kind( test_json_index( timeline_value( json, "txn_start_shred_idx" ), i ) )==FD_JTOK_NULL );
        FD_TEST( test_json_kind( test_json_index( timeline_value( json, "txn_end_shred_idx" ), i ) )==FD_JTOK_NULL );
      }
    }
  }
  /* Exercise the actual completion path with no replay scheduling times. */
  fd_replay_slot_completed_t completed = { .slot=slot, .bank_seq=bank_seq, .parent_slot=ULONG_MAX, .parent_bank_seq=ULONG_MAX,
    .completion_time_nanos=now+1L, .is_leader=1, .nonvote_success=1UL, .vote_failed=1UL, .identity_balance=ULONG_MAX };
  fd_gui_handle_replay_update( gui, &completed, now+1L );
  fd_http_server_stage_trunc( gui->http, 0UL );
  fd_gui_txn_batch_flush( gui, now+FD_GUI_TXN_BATCH_IDLE_NS );
  /* The success and the error-200 failure share a tile and overlap, so
     they merge into one batch; the 1-1 error-code tie picks success. */
  FD_TEST( count_ts( gui, FD_GUI_HIST_REPLAY_TXN_BATCH, ULONG_MAX )==1UL );
  FD_TEST( !fd_gui_hist_range_begin( gui, &it, FD_GUI_HIST_REPLAY_TXN_BATCH, now, now+1L, NULL, NULL ) );
  while( fd_gui_hist_range_next( &it ) ) {
    fd_gui_store_replay_txn_batch_t const * rec = it.rec;
    FD_TEST( rec->sigverify_txn_cnt==0U && rec->exec_txn_cnt==2U && rec->error_code==0U );
    FD_TEST( rec->sigverify_txn_idx==ULONG_MAX );
    FD_TEST( rec->txn_sigverify_exec_idx==ULONG_MAX && rec->sigverify_start_ns==LONG_MAX && rec->sigverify_end_ns==LONG_MAX );
    FD_TEST( rec->completion_time_ns==now );
  }
  fd_gui_hist_range_end( &it );
  FD_TEST( !fd_gui_printf_timeline_query_tile_states( gui, now-100L, now+1L, 1, 7UL ) );
  test_json_t json = timeline_response( gui );
  FD_TEST( !test_json_count( timeline_value( json, "state" ) ) ); /* leader batch skipped */
  gui->tile_state.exec_cnt = 0UL;
  gui->tile_state.pos_cnt  = 0UL;

  for( ulong g=0UL; g<FD_GUI_TIMELINE_GRANULARITY_CNT; g++ ) {
    ulong ns = fd_gui_timeline_granularity_ns( g );
    long ref = (long)((ulong)now/ns*ns);
    char const * gran = fd_gui_timeline_granularities[ g ].name;
    int stored; ulong merge_cnt;
    if( fd_gui_timeline_tier( "query_agg_txn", g, &stored, &merge_cnt ) ) {
      /* Below the minimum; compute and revenue also serve 100ms. */
      FD_TEST( fd_gui_printf_timeline_query_agg( gui, "query_agg_txn", gran, g, ref, 1UL, 7UL )==-1 );
      if( fd_gui_timeline_tier( "query_agg_revenue", g, &stored, &merge_cnt ) ) {
        FD_TEST( fd_gui_printf_timeline_query_agg( gui, "query_agg_revenue", gran, g, ref, 1UL, 7UL )==-1 );
        FD_TEST( fd_gui_printf_timeline_query_agg( gui, "query_agg_compute", gran, g, ref, 1UL, 7UL )==-1 );
        continue;
      }
    } else {
      FD_TEST( !fd_gui_printf_timeline_query_agg( gui, "query_agg_txn", gran, g, ref, 1UL, 7UL ) );
      json = timeline_response( gui );
      FD_TEST( test_json_ulong( test_json_index( timeline_value( json, "success_nonvote_transactions" ), 0 ) )==1UL );
      FD_TEST( test_json_ulong( test_json_index( timeline_value( json, "failed_nonvote_transactions" ), 0 ) )==1UL );
      FD_TEST( !test_json_ulong( test_json_index( timeline_value( json, "failed_vote_transactions" ), 0 ) ) );
    }
    FD_TEST( !fd_gui_printf_timeline_query_agg( gui, "query_agg_revenue", gran, g, ref, 1UL, 7UL ) );
    json = timeline_response( gui );
    FD_TEST( test_json_string_eq( test_json_index( timeline_value( json, "txn_fees" ), 0 ), "30000" ) );
    FD_TEST( test_json_string_eq( test_json_index( timeline_value( json, "prio_fees" ), 0 ), "2000" ) );
    /* Only the successful transaction pays its tip (7); the error-200
       failure still pays fees but no tip.  The 100ms tier must agree
       with the other stored day tiers. */
    FD_TEST( test_json_string_eq( test_json_index( timeline_value( json, "tips" ), 0 ), "7" ) );
    FD_TEST( !fd_gui_printf_timeline_query_agg( gui, "query_agg_compute", gran, g, ref, 1UL, 7UL ) );
    json = timeline_response( gui );
    FD_TEST( test_json_ulong( test_json_index( timeline_value( json, "compute_units" ), 0 ) )==84UL );
    FD_TEST( test_json_ulong( timeline_value( json, "max_compute_units" ) )==60000000UL );
  }
  /* Also exercise a nonzero tick-to-nanosecond offset and a leader whose
     becoming-leader notification (and block CU limit) was not received. */
  gui->tick_per_ns = 1.0;
  long later       = sec_ns( 20UL );
  long tick_before = fd_tickcount();
  long commit_tick = tick_before - 1000000L;
  fd_gui_microblock_execution_end( gui, later, 4UL, slot+1UL, 1UL, &txn, 30UL, dt, commit_tick, 0UL, bank_seq, later );
  long tick_after = fd_tickcount();
  FD_TEST( !fd_gui_hist_range_begin( gui, &it, FD_GUI_HIST_REPLAY_TXN, later, later, NULL, NULL ) );
  FD_TEST( fd_gui_hist_range_next( &it ) );
  fd_gui_store_replay_txn_t const * rec = it.rec;
  FD_TEST( rec->slot==slot+1UL && rec->txn_exec_idx==4UL && rec->block_compute_unit_limit==ULONG_MAX );
  FD_TEST( rec->commit_end_ns>=later+commit_tick-tick_after && rec->commit_end_ns<=later+commit_tick-tick_before );
  FD_TEST( rec->completion_time_ns==rec->commit_end_ns && rec->load_start_ns==rec->commit_end_ns-90L );
  FD_TEST( !fd_gui_hist_range_next( &it ) );
  fd_gui_hist_range_end( &it );
  FD_TEST( fd_http_server_delete( fd_http_server_leave( gui->http ) )==http_mem );
  free( http_mem );
  gui->http = NULL;
  FD_LOG_NOTICE(( "test_timeline_leader_txns: rows, nullable sigverify and shred indices, batches, all aggregate resolutions: ok" ));
}

static void
test_timeline_queries( fd_gui_t * gui ) {
  void * http_mem = timeline_http_open( gui );
  void * db = gui->db;
  void * hist = gui->hist;
  gui->db = NULL;
  gui->hist = NULL;
  char const * keys[] = { "query_agg_slots", "query_agg_shreds", "query_agg_compute", "query_agg_revenue", "query_agg_txn" };
  for( ulong i=0UL; i<5UL; i++ ) {
    FD_TEST( !fd_gui_printf_timeline_query_agg( gui, keys[ i ], "250ms", 3UL, 0L, 1UL, 7UL ) );
    test_json_t json = timeline_response( gui );
    FD_TEST( (test_json_kind( timeline_value( json, "available_start_ns" ) )==FD_JTOK_NULL) );
  }
  gui->db = db;
  gui->hist = hist;
  char const * invalid[] = {
    "{\"start_ns\":\"01\",\"end_ns\":\"2\",\"granularity\":\"shred\"}",
    "{\"start_ns\":\"0\",\"end_ns\":\"9223372036854775807\",\"granularity\":\"shred\"}",
    "{\"start_ns\":\"0\",\"end_ns\":\"9223372036854775808\",\"granularity\":\"shred\"}",
    "{\"start_ns\":\"-1\",\"end_ns\":\"2\",\"granularity\":\"shred\"}",
    "{\"start_ns\":0,\"end_ns\":\"2\",\"granularity\":\"shred\"}",
    "{\"start_ns\":\"2\",\"end_ns\":\"2\",\"granularity\":\"shred\"}",
    "{\"start_ns\":\"0\",\"end_ns\":\"2\"}",
    "{\"start_ns\":\"0\",\"end_ns\":\"2\",\"granularity\":\"txn\"}"
  };
  for( ulong i=0UL; i<sizeof(invalid)/sizeof(invalid[ 0 ]); i++ ) {
    char request[ 512 ];
    fd_cstr_printf_check( request, sizeof(request), NULL, "{\"id\":7,\"topic\":\"timeline\",\"key\":\"query_shreds\",\"params\":%s}", invalid[ i ] );
    FD_TEST( fd_gui_ws_message( gui, 0UL, (uchar const *)request, strlen(request) )==FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST );
  }
  char const * valid = "{\"id\":7,\"topic\":\"timeline\",\"key\":\"query_shreds\","
                      "\"params\":{\"start_ns\":\"0\",\"end_ns\":\"1\",\"granularity\":\"fec\"}}";
  FD_TEST( !fd_gui_ws_message( gui, 0UL, (uchar const *)valid, strlen(valid) ) );
  char const * events_ok  = "{\"id\":7,\"topic\":\"timeline\",\"key\":\"query_events\",\"params\":{\"start_ns\":\"0\",\"end_ns\":\"1\"}}";
  char const * events_bad = "{\"id\":7,\"topic\":\"timeline\",\"key\":\"query_events\",\"params\":{\"start_ns\":\"1\",\"end_ns\":\"1\"}}";
  FD_TEST( !fd_gui_ws_message( gui, 0UL, (uchar const *)events_ok, strlen(events_ok) ) );
  FD_TEST( fd_gui_ws_message( gui, 0UL, (uchar const *)events_bad, strlen(events_bad) )==FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST );
  FD_TEST( fd_gui_printf_timeline_query_agg( gui, "query_agg_compute", "100ms", 2UL, 0L, FD_GUI_TIMELINE_QUERY_MAX_BUCKETS+1UL, 7UL )==-1 );
  FD_TEST( fd_gui_printf_timeline_query_agg( gui, "query_agg_compute", "100ms", 2UL, LONG_MAX-1L, 1UL, 7UL )==-1 );

  /* Granularities below each method's minimum, and names no longer
     supported, are rejected on the request path. */
  {
    struct { char const * key; char const * gran; int ok; } const cases[] = {
      { "query_agg_compute", "50ms",  0 }, { "query_agg_compute", "100ms", 1 },
      { "query_agg_revenue", "50ms",  0 }, { "query_agg_revenue", "100ms", 1 },
      { "query_agg_shreds",  "100ms", 0 }, { "query_agg_shreds",  "250ms", 1 },
      { "query_agg_slots",   "100ms", 0 }, { "query_agg_slots",   "250ms", 1 },
      { "query_agg_txn",     "100ms", 0 }, { "query_agg_txn",     "250ms", 1 },
      { "query_agg_shreds",  "1ms",   0 }, { "query_agg_compute", "1ms",   0 },
      { "query_agg_txn",     "10ms",  0 }, { "query_agg_cpu",     "1ms",   0 },
      { "query_agg_tile_states", "100ms", 0 }
    }; /* accepted CPU queries need reported tiles, see test_timeline_cpu */
    for( ulong i=0UL; i<sizeof(cases)/sizeof(cases[ 0 ]); i++ ) {
      char request[ 512 ];
      fd_cstr_printf_check( request, sizeof(request), NULL,
        "{\"id\":7,\"topic\":\"timeline\",\"key\":\"%s\",\"params\":{\"start_ns\":\"0\",\"end_ns\":\"1000000000\","
        "\"granularity\":\"%s\",\"tiles\":[0]}}", cases[ i ].key, cases[ i ].gran );
      int rc = fd_gui_ws_message( gui, 0UL, (uchar const *)request, strlen(request) );
      if( FD_UNLIKELY( rc!=(cases[ i ].ok ? 0 : FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST) ) ) {
        FD_LOG_ERR(( "FAIL: %s %s returned %d", cases[ i ].key, cases[ i ].gran, rc ));
      }
      fd_http_server_stage_trunc( gui->http, 0UL );
    }
    int stored; ulong merge_cnt;
    FD_TEST( fd_gui_timeline_tier( "query_agg_compute", 1UL, &stored, &merge_cnt )==-1 ); /* 50ms */
    FD_TEST( !fd_gui_timeline_tier( "query_agg_compute", 2UL, &stored, &merge_cnt ) && stored==FD_GUI_TIMELINE_GRANULARITY_100MS && merge_cnt==1UL );
    FD_TEST( !fd_gui_timeline_tier( "query_agg_compute", 4UL, &stored, &merge_cnt ) && stored==FD_GUI_TIMELINE_GRANULARITY_250MS && merge_cnt==2UL );
    FD_TEST( !fd_gui_timeline_tier( "query_agg_compute", 5UL, &stored, &merge_cnt ) && stored==FD_GUI_TIMELINE_GRANULARITY_250MS && merge_cnt==4UL );
    FD_TEST( fd_gui_timeline_tier( "query_agg_txn", 2UL, &stored, &merge_cnt )==-1 ); /* 100ms */
    FD_TEST( !fd_gui_timeline_tier( "query_agg_cpu", 1UL, &stored, &merge_cnt ) && stored==FD_GUI_TIMELINE_GRANULARITY_25MS && merge_cnt==2UL );
    FD_TEST( !fd_gui_timeline_tier( "query_agg_cpu", 5UL, &stored, &merge_cnt ) && stored==FD_GUI_TIMELINE_GRANULARITY_250MS && merge_cnt==4UL );
    FD_TEST( !fd_gui_timeline_tier( "query_agg_cpu", 7UL, &stored, &merge_cnt ) && stored==FD_GUI_TIMELINE_GRANULARITY_2S && merge_cnt==2UL );
    FD_TEST( !fd_gui_timeline_tier( "query_agg_txn", 22UL, &stored, &merge_cnt ) && stored==FD_GUI_TIMELINE_GRANULARITY_12H && merge_cnt==2UL );
    FD_TEST( fd_gui_timeline_tier( "query_agg_tile_states", 2UL, &stored, &merge_cnt )==-1 ); /* 100ms */
    FD_TEST( !fd_gui_timeline_tier( "query_agg_tile_states", 5UL, &stored, &merge_cnt ) && stored==FD_GUI_TIMELINE_GRANULARITY_250MS && merge_cnt==4UL );
    FD_TEST( !fd_gui_timeline_tier( "query_agg_tile_states", 7UL, &stored, &merge_cnt ) && stored==FD_GUI_TIMELINE_GRANULARITY_2S && merge_cnt==2UL );
    FD_TEST( fd_gui_timeline_tier( "query_bogus", 22UL, &stored, &merge_cnt )==-1 );
    FD_TEST( fd_gui_timeline_tier( "query_agg_txn", FD_GUI_TIMELINE_GRANULARITY_CNT, &stored, &merge_cnt )==-1 );
  }

  fd_gui_store_replay_txn_t txn = {
    .insert_time_ns=sec_ns( 10UL ), .completion_time_ns=sec_ns( 10UL )+20L,
    .slot=100UL, .txn_idx=3UL, .txn_exec_idx=1UL, .txn_sigverify_exec_idx=2UL,
    .txn_start_shred_idx=UINT_MAX, .txn_end_shred_idx=UINT_MAX,
    .sigverify_start_ns=sec_ns( 10UL ), .sigverify_end_ns=sec_ns( 10UL )+20L,
    .load_start_ns=sec_ns( 10UL )+1L, .check_start_ns=LONG_MAX, .exec_start_ns=LONG_MAX,
    .commit_start_ns=LONG_MAX, .commit_end_ns=sec_ns( 10UL )+10L,
    .compute_units_requested=123U, .compute_units_consumed=42U, .block_compute_unit_limit=60000000UL,
    .transaction_fee=5000UL, .priority_fee=1UL, .tips=2UL, .is_committable=1U
  };
  FD_TEST( !fd_gui_hist_ts_append( gui, FD_GUI_HIST_REPLAY_TXN, &txn ) );
  fd_gui_timeline_handle_txn( gui, txn.slot, txn.commit_end_ns, txn.compute_units_consumed, txn.block_compute_unit_limit,
    txn.transaction_fee, txn.priority_fee, txn.tips, 1, txn.insert_time_ns );
  for( ulong g=0UL; g<FD_GUI_TIMELINE_GRANULARITY_CNT; g++ ) {
    ulong ns = fd_gui_timeline_granularity_ns( g );
    long ref = (long)((ulong)txn.commit_end_ns/ns*ns);
    if( ns<100000000UL ) {
      FD_TEST( fd_gui_printf_timeline_query_agg( gui, "query_agg_compute", fd_gui_timeline_granularities[ g ].name, g, ref, 1UL, 7UL )==-1 );
      continue;
    }
    FD_TEST( !fd_gui_printf_timeline_query_agg( gui, "query_agg_compute", fd_gui_timeline_granularities[ g ].name, g, ref, 1UL, 7UL ) );
    test_json_t json = timeline_response( gui );
    FD_TEST( test_json_ulong( timeline_value( json, "max_compute_units" ) )==60000000UL );
    FD_TEST( test_json_ulong( test_json_index( timeline_value( json, "compute_units" ), 0 ) )==42UL );
  }

  /* 100ms compute and revenue come from the 100ms tier: neighboring
     100ms buckets of the same 250ms bucket stay separate. */
  {
    long base = sec_ns( 15UL );
    fd_gui_timeline_handle_txn( gui, txn.slot, base+50000000L,  10U, 60000000UL, 100UL, 10UL, 1UL, 1, base+sec_ns( 1UL ) );
    fd_gui_timeline_handle_txn( gui, txn.slot, base+150000000L, 20U, 50000000UL, 200UL, 20UL, 2UL, 1, base+sec_ns( 1UL ) );
    fd_gui_timeline_day_t const * day = fd_gui_timeline_day_get( gui, 0UL );
    FD_TEST( day );
    ulong idx = (ulong)base/100000000UL;
    FD_TEST( fd_gui_timeline_field_get( day, FD_GUI_TIMELINE_GRANULARITY_100MS, FD_GUI_TIMELINE_FIELD_COMPUTE_UNITS, idx     )==10UL );
    FD_TEST( fd_gui_timeline_field_get( day, FD_GUI_TIMELINE_GRANULARITY_100MS, FD_GUI_TIMELINE_FIELD_COMPUTE_UNITS, idx+1UL )==20UL );
    FD_TEST( fd_gui_timeline_field_get( day, FD_GUI_TIMELINE_GRANULARITY_100MS, FD_GUI_TIMELINE_FIELD_COMPUTE_UNITS, idx+2UL )==ULONG_MAX );
    FD_TEST( fd_gui_timeline_tier_has_field( FD_GUI_TIMELINE_GRANULARITY_100MS, FD_GUI_TIMELINE_FIELD_TIPS ) );
    FD_TEST( !fd_gui_timeline_tier_has_field( FD_GUI_TIMELINE_GRANULARITY_100MS, FD_GUI_TIMELINE_FIELD_TURBINE ) );
    FD_TEST( !fd_gui_printf_timeline_query_agg( gui, "query_agg_compute", "100ms", 2UL, base, 3UL, 7UL ) );
    test_json_t cj = timeline_response( gui );
    test_json_t cu = timeline_value( cj, "compute_units" );
    FD_TEST( test_json_count( cu )==3 );
    FD_TEST( test_json_ulong( test_json_index( cu, 0 ) )==10UL );
    FD_TEST( test_json_ulong( test_json_index( cu, 1 ) )==20UL );
    FD_TEST( test_json_kind( test_json_index( cu, 2 ) )==FD_JTOK_NULL );
    FD_TEST( test_json_ulong( timeline_value( cj, "max_compute_units" ) )==60000000UL );
    FD_TEST( test_json_string_eq( timeline_value( cj, "available_start_ns" ), "0" ) );
    FD_TEST( !fd_gui_printf_timeline_query_agg( gui, "query_agg_revenue", "100ms", 2UL, base, 3UL, 7UL ) );
    cj = timeline_response( gui );
    FD_TEST( test_json_string_eq( test_json_index( timeline_value( cj, "txn_fees" ), 0 ), "100" ) );
    FD_TEST( test_json_string_eq( test_json_index( timeline_value( cj, "txn_fees" ), 1 ), "200" ) );
    FD_TEST( test_json_string_eq( test_json_index( timeline_value( cj, "prio_fees" ), 1 ), "20" ) );
    FD_TEST( test_json_string_eq( test_json_index( timeline_value( cj, "tips" ), 0 ), "1" ) );
    FD_TEST( test_json_kind( test_json_index( timeline_value( cj, "tips" ), 2 ) )==FD_JTOK_NULL );
    /* The 250ms tier holds both. */
    FD_TEST( !fd_gui_printf_timeline_query_agg( gui, "query_agg_compute", "250ms", 3UL, base, 1UL, 7UL ) );
    cj = timeline_response( gui );
    FD_TEST( test_json_ulong( test_json_index( timeline_value( cj, "compute_units" ), 0 ) )==30UL );
  }
  /* Three execrp tiles: txn 3 loads on tile 1 over [1,10) and
     sigverifies on tile 2 over [0,20), relative to the window start.
     The window must include the sigverify end to own it. */
  gui->tile_state.exec_cnt = 3UL;
  gui->tile_state.pos_cnt  = 3UL;
  FD_TEST( !fd_gui_printf_timeline_query_tile_states( gui, txn.sigverify_start_ns, txn.completion_time_ns+1L, 0, 7UL ) );
  test_json_t json = timeline_response( gui );
  {
    FD_TEST( test_json_string_eq( timeline_value( json, "start_ts" ), "10000000000" ) );
    FD_TEST( test_json_ulong( timeline_value( json, "reference_slot" ) )==100UL );
    ulong const state_cnt[] = { 0UL, 1UL, 1UL };
    ulong const state[]     = { FD_GUI_TILE_STATE_LOADING, FD_GUI_TILE_STATE_SIGVERIFY };
    ulong const dur[]       = { 9UL, 20UL };
    FD_TEST( test_json_count( timeline_value( json, "state_cnt" ) )==3 && test_json_count( timeline_value( json, "state" ) )==2 );
    FD_TEST( test_json_string_eq( test_json_index( timeline_value( json, "tile_start_ts_delta" ), 1 ), "1" ) );
    for( int i=0; i<3; i++ ) FD_TEST( test_json_ulong( test_json_index( timeline_value( json, "state_cnt" ), i ) )==state_cnt[ i ] );
    for( int i=0; i<2; i++ ) {
      FD_TEST( test_json_ulong( test_json_index( timeline_value( json, "state" ), i ) )==state[ i ] );
      FD_TEST( test_json_ulong( test_json_index( timeline_value( json, "dur" ),   i ) )==dur[ i ] );
    }
    /* One exec and one sigverify segment for the same txn. */
    FD_TEST( test_json_count( timeline_value( json, "txn_idx" ) )==2 );
    FD_TEST( test_json_ulong( test_json_index( timeline_value( json, "txn_state_lo" ), 0 ) )==0UL );
    FD_TEST( test_json_ulong( test_json_index( timeline_value( json, "txn_state_lo" ), 1 ) )==1UL );
    FD_TEST( test_json_ulong( test_json_index( timeline_value( json, "txn_state_cnt" ), 0 ) )==1UL );
    FD_TEST( test_json_ulong( test_json_index( timeline_value( json, "txn_idx" ), 1 ) )==3UL );
    FD_TEST( test_json_ulong( test_json_index( timeline_value( json, "txn_slot_delta" ), 0 ) )==0UL );
    FD_TEST( test_json_ulong( test_json_index( timeline_value( json, "txn_error_code" ), 0 ) )==0UL );
    FD_TEST( test_json_kind( test_json_index( timeline_value( json, "txn_error_code" ), 1 ) )==FD_JTOK_NULL );
    FD_TEST( !test_json_count( timeline_value( json, "slot_state_lo" ) ) );
  }
  /* A window after the txn's last state ended has no states. */
  FD_TEST( !fd_gui_printf_timeline_query_tile_states( gui, txn.completion_time_ns+1L, txn.completion_time_ns+2L, 0, 7UL ) );
  json = timeline_response( gui );
  FD_TEST( !test_json_count( timeline_value( json, "txn_idx" ) ) && !test_json_count( timeline_value( json, "state" ) ) );
  gui->tile_state.exec_cnt = 0UL;
  gui->tile_state.pos_cnt  = 0UL;

  FD_TEST( !fd_gui_printf_timeline_query_txn_meta( gui, txn.completion_time_ns, txn.completion_time_ns+1L, 7UL ) );
  json = timeline_response( gui );
  FD_TEST( test_json_ulong( test_json_index( timeline_value( json, "txn_compute_units_requested" ), 0 ) )==123UL );
  FD_TEST( (test_json_kind( test_json_index( timeline_value( json, "txn_transaction_fee" ), 0 ) )==FD_JTOK_STR) );

  /* Commit belongs to the preceding bucket even when sigverify completes
     exactly at the next boundary.  Check each granularity up to one
     second, with separate query windows. */
  txn.insert_time_ns     = sec_ns( 20UL );
  txn.completion_time_ns = sec_ns( 20UL );
  txn.sigverify_start_ns = sec_ns( 20UL ) - 2L;
  txn.sigverify_end_ns   = sec_ns( 20UL );
  txn.load_start_ns      = sec_ns( 20UL ) - 2L;
  txn.commit_end_ns      = sec_ns( 20UL ) - 1L;
  FD_TEST( !fd_gui_hist_ts_append( gui, FD_GUI_HIST_REPLAY_TXN, &txn ) );
  fd_gui_timeline_handle_txn( gui, txn.slot, txn.commit_end_ns, txn.compute_units_consumed, txn.block_compute_unit_limit,
    txn.transaction_fee, txn.priority_fee, txn.tips, 1, txn.insert_time_ns );
  for( ulong g=0UL; g<FD_GUI_TIMELINE_GRANULARITY_CNT; g++ ) {
    ulong ns = fd_gui_timeline_granularity_ns( g );
    if( ns>(ulong)FD_GUI_HIST_RES_1S_NS ) break;
    if( ns<100000000UL ) continue; /* below the compute minimum */
    long ref = (long)((ulong)txn.commit_end_ns/ns*ns);
    FD_TEST( !fd_gui_printf_timeline_query_agg( gui, "query_agg_compute", fd_gui_timeline_granularities[ g ].name, g, ref, 1UL, 7UL ) );
    json = timeline_response( gui );
    FD_TEST( test_json_ulong( test_json_index( timeline_value( json, "compute_units" ), 0 ) )==42UL );
    FD_TEST( !fd_gui_printf_timeline_query_agg( gui, "query_agg_compute", fd_gui_timeline_granularities[ g ].name, g, ref+(long)ns, 1UL, 7UL ) );
    json = timeline_response( gui );
    FD_TEST( test_json_kind( test_json_index( timeline_value( json, "compute_units" ), 0 ) )==FD_JTOK_NULL );
  }

  /* Replay's message carries the scheduler's shred indices verbatim,
     including a saturated USHORT_MAX end rather than an unknown sentinel. */
  long const replay_now = sec_ns( 30UL );
  long const tick       = fd_tickcount();
  gui->tick_per_ns = 1e30; /* Deterministic timestamps, as in the leader test. */
  fd_replay_txn_executed_t executed = {
    .slot=101UL, .exec_tile_idx=3UL, .sigverify_exec_tile_idx=4UL,
    .tick_sigverify_disp=tick, .tick_sigverify_done=tick, .tick_load_start=tick,
    .tick_check_start=LONG_MAX, .tick_exec_start=LONG_MAX, .tick_commit_start=LONG_MAX, .tick_commit_end=tick,
    .is_committable=1, .max_compute_units=60000000UL
  };
  /* Minimal parsed legacy transaction: one signature, one account, no instructions. */
  executed.txn->payload[ 0 ]  = 1U;
  executed.txn->payload[ 65 ] = 1U;
  executed.txn->payload[ 68 ] = 1U;
  executed.txn->payload_sz    = 134U;
  FD_TEST( fd_txn_parse( executed.txn->payload, executed.txn->payload_sz, TXN( executed.txn ), NULL ) );
  ushort const starts[ 2 ] = { 0U, USHORT_MAX-1U };
  ushort const ends[ 2 ]   = { 42U, USHORT_MAX };
  for( ulong i=0UL; i<2UL; i++ ) {
    executed.index_in_slot       = 5UL+i;
    executed.txn->start_shred_idx = starts[ i ];
    executed.txn->end_shred_idx   = ends[ i ];
    fd_gui_handle_replay_txn( gui, &executed, replay_now );
  }
  {
    FD_TEST( !fd_gui_printf_timeline_query_txn_meta( gui, replay_now, replay_now+1L, 7UL ) );
    json = timeline_response( gui );
    test_json_t start_indices = timeline_value( json, "txn_start_shred_idx" );
    test_json_t end_indices   = timeline_value( json, "txn_end_shred_idx" );
    FD_TEST( test_json_count( timeline_value( json, "txn_idx" ) )==2 );
    FD_TEST( test_json_count( start_indices )==2 && test_json_count( end_indices )==2 );
    FD_TEST( timeline_value( json, "txn_sigverify_exec_idx" ).ptr<start_indices.ptr && start_indices.ptr<end_indices.ptr );
    for( int i=0; i<2; i++ ) {
      FD_TEST( test_json_ulong( test_json_index( timeline_value( json, "txn_idx" ), i ) )==5UL+(ulong)i );
      FD_TEST( test_json_kind( test_json_index( start_indices, i ) )==FD_JTOK_INT );
      FD_TEST( test_json_kind( test_json_index( end_indices, i ) )==FD_JTOK_INT );
      FD_TEST( test_json_ulong( test_json_index( start_indices, i ) )==starts[ i ] );
      FD_TEST( test_json_ulong( test_json_index( end_indices, i ) )==ends[ i ] );
    }
  }

  FD_TEST( fd_http_server_delete( fd_http_server_leave( gui->http ) )==http_mem );
  free( http_mem );
  gui->http = NULL;
  FD_LOG_NOTICE(( "test_timeline_queries: ok" ));
}


/* check_response compares the staged websocket response to expected
   exactly, and discards it. */

static void
check_response( fd_gui_t *   gui,
                char const * expected ) {
  FD_TEST( !gui->http->stage_err );
  ulong len = fd_http_server_stage_len( gui->http );
  ulong off = gui->http->stage_off%gui->http->oring_sz;
  FD_TEST( len && off+len<=gui->http->oring_sz );
  if( FD_UNLIKELY( len!=strlen( expected ) || memcmp( gui->http->oring+off, expected, len ) ) ) {
    FD_LOG_WARNING(( "expected: %s", expected ));
    FD_LOG_ERR(( "     got: %.*s", (int)len, (char const *)gui->http->oring+off ));
  }
  fd_http_server_stage_trunc( gui->http, 0UL );
}

/* Leadership follows what pack produced, not the schedule: active while
   the highest became_leader slot is above the highest unbecame_leader
   slot, in either arrival order. */

static void
test_leader_active_slot( fd_gui_t * gui ) {
  long now = 1000L*1000L*1000L;
  fd_done_packing_t done_packing = {0};
  gui->leader_begin_slot       = 0UL;
  gui->leader_end_slot         = 0UL;
  gui->leader_slot_pending     = ULONG_MAX;
  gui->leader_bank_seq_pending = ULONG_MAX;
  fd_gui_became_leader( gui, 600UL, now, now+sec_ns( 1UL ), 60000000UL, 8UL, 9UL );
  FD_TEST( gui->leader_begin_slot>gui->leader_end_slot );
  fd_gui_unbecame_leader( gui, 600UL, &done_packing );
  FD_TEST( gui->leader_begin_slot<=gui->leader_end_slot );

  /* The next slot begins before the previous one's completion lands. */
  fd_gui_became_leader( gui, 601UL, now, now+sec_ns( 1UL ), 60000000UL, 8UL, 10UL );
  fd_gui_became_leader( gui, 602UL, now, now+sec_ns( 1UL ), 60000000UL, 8UL, 11UL );
  fd_gui_unbecame_leader( gui, 601UL, &done_packing );
  FD_TEST( gui->leader_begin_slot>gui->leader_end_slot );
  fd_gui_unbecame_leader( gui, 602UL, &done_packing );
  FD_TEST( gui->leader_begin_slot<=gui->leader_end_slot );

  /* A completion processed before its start leaves the GUI idle. */
  fd_gui_unbecame_leader( gui, 603UL, &done_packing );
  fd_gui_became_leader( gui, 603UL, now, now+sec_ns( 1UL ), 60000000UL, 8UL, 12UL );
  FD_TEST( gui->leader_begin_slot<=gui->leader_end_slot );
}

static void
test_timeline_shreds( fd_gui_t * gui ) {
  void * http_mem = test_http_open( gui, FD_GUI_HTTP_MIN_SEND_BUFFER_SZ );

  /* Positive event-time skew within one second must fit the advertised
     bounds, including insertion at the last nanosecond of a batch.
     Events are appended before the slots complete, since shred events
     for completed slots are dropped. */
  long const now = sec_ns( 101UL )-1L;
  long const event_ns = now+sec_ns( 1UL );
  ulong const event_slots[] = { 101UL, 102UL, 113UL, 101UL };
  for( ulong i=0UL; i<sizeof(event_slots)/sizeof(event_slots[ 0 ]); i++ )
    fd_gui_shred_event_append( gui, event_slots[ i ], 0UL, FD_GUI_SLOT_SHRED_REPAIR_REQUEST, event_ns, now );

  /* Canonical lineage 100 -> 102 -> 110 -> 112 proves 101 was skipped,
     even though no slot record exists for it. */
  ulong const slots[] = { 100UL, 102UL, 110UL, 112UL };
  for( ulong i=0UL; i<sizeof(slots)/sizeof(slots[ 0 ]); i++ ) {
    put_slot( gui, slots[ i ], sec_ns( 100UL ) );
    fd_gui_slot_t * slot = fd_gui_slot_get( gui, slots[ i ], BANK_SEQ );
    slot->parent_slot     = i ? slots[ i-1UL ] : ULONG_MAX;
    slot->parent_bank_seq = BANK_SEQ;
    slot->skip            = FD_GUI_SKIP_STATUS_NOT_SKIPPED;
  }
  gui->summary.slot_tower          = 112UL;
  gui->summary.slot_tower_bank_seq = BANK_SEQ;

  for( int flushed=0; flushed<2; flushed++ ) {
    long lo, hi;
    FD_TEST( fd_gui_event_bounds( gui, FD_GUI_HIST_SHRED_EVENTS, &lo, &hi ) );
    FD_TEST( lo<=event_ns && event_ns<hi );
    /* 101 is only marked once the root advances past it; the landed
       slot 102 and unresolved slot 113 must not be marked. */
    ulong        const roots  [] = { 100UL, 110UL };
    char const * const skipped[] = { "[]", "[0]" };
    for( ulong i=0UL; i<sizeof(roots)/sizeof(roots[ 0 ]); i++ ) {
      gui->summary.slot_rooted = roots[ i ];
      FD_TEST( !fd_gui_printf_timeline_query_shreds( gui, lo, hi, 7UL ) );
      char expected[ 512 ];
      fd_cstr_printf_check( expected, sizeof(expected), NULL,
                            "{\"topic\":\"timeline\",\"key\":\"query_shreds\",\"id\":7,\"value\":{\"granularity\":\"shred\","
                            "\"available_start_ns\":\"99000000000\",\"available_end_ns\":\"102000000000\","
                            "\"reference_slot\":101,\"reference_ts\":\"101999999999\",\"slot_delta\":[0,1,12,0],\"idx\":[0,0,0,0],"
                            "\"event\":[0,0,0,0],\"event_ts_delta\":[\"0\",\"0\",\"0\",\"0\"],\"skipped\":%s}}", skipped[ i ] );
      check_response( gui, expected );
    }
    if( !flushed ) FD_TEST( fd_gui_shred_flush( gui, sec_ns( 101UL ) ) );
  }

  test_http_close( gui, http_mem );
  FD_LOG_NOTICE(( "test_timeline_shreds: availability bounds and historical skips: ok" ));
}

static void
test_timeline_agg( fd_gui_t * gui ) {
  void * http_mem = test_http_open( gui, FD_GUI_HTTP_MIN_SEND_BUFFER_SZ );

  /* Empty history: every bucket is unknown and no bounds are available. */
  FD_TEST( !fd_gui_printf_timeline_query_agg( gui, "query_agg_revenue", "250ms", 3UL, 0L, 2UL, 7UL ) );
  check_response( gui, "{\"topic\":\"timeline\",\"key\":\"query_agg_revenue\",\"id\":7,\"value\":{\"granularity\":\"250ms\",\"reference_ts_ns\":\"0\","
                       "\"available_start_ns\": null,\"available_end_ns\": null,\"txn_fees\":[null,null],\"prio_fees\":[null,null],\"tips\":[null,null]}}" );
  FD_TEST( !fd_gui_printf_timeline_query_agg( gui, "query_agg_compute", "250ms", 3UL, 0L, 2UL, 7UL ) );
  check_response( gui, "{\"topic\":\"timeline\",\"key\":\"query_agg_compute\",\"id\":7,\"value\":{\"granularity\":\"250ms\",\"reference_ts_ns\":\"0\","
                       "\"available_start_ns\": null,\"available_end_ns\": null,\"compute_units\":[null,null],\"max_compute_units\": null}}" );
  FD_TEST( !fd_gui_printf_timeline_query_agg( gui, "query_agg_txn", "250ms", 3UL, 0L, 2UL, 7UL ) );
  check_response( gui, "{\"topic\":\"timeline\",\"key\":\"query_agg_txn\",\"id\":7,\"value\":{\"granularity\":\"250ms\",\"reference_ts_ns\":\"0\","
                       "\"available_start_ns\": null,\"available_end_ns\": null,\"success_nonvote_transactions\":[null,null],\"failed_nonvote_transactions\":[null,null],"
                       "\"success_vote_transactions\":[null,null],\"failed_vote_transactions\":[null,null]}}" );

  /* Malformed requests: missing or unknown granularity, empty range, too many buckets. */
  char const * invalid[] = {
    "{\"start_ns\":\"0\",\"end_ns\":\"2\"}",
    "{\"start_ns\":\"0\",\"end_ns\":\"2\",\"granularity\":\"bogus\"}",
    "{\"start_ns\":\"2\",\"end_ns\":\"2\",\"granularity\":\"250ms\"}",
    "{\"start_ns\":\"0\",\"end_ns\":\"1024000000001\",\"granularity\":\"250ms\"}"
  };
  char const * keys[] = { "query_agg_compute", "query_agg_revenue", "query_agg_txn" };
  for( ulong k=0UL; k<sizeof(keys)/sizeof(keys[ 0 ]); k++ ) {
    for( ulong i=0UL; i<sizeof(invalid)/sizeof(invalid[ 0 ]); i++ ) {
      char request[ 512 ];
      fd_cstr_printf_check( request, sizeof(request), NULL, "{\"id\":7,\"topic\":\"timeline\",\"key\":\"%s\",\"params\":%s}", keys[ k ], invalid[ i ] );
      FD_TEST( fd_gui_ws_message( gui, 0UL, (uchar const *)request, strlen( request ) )==FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST );
      FD_TEST( !fd_http_server_stage_len( gui->http ) );
    }
    char valid[ 512 ];
    fd_cstr_printf_check( valid, sizeof(valid), NULL, "{\"id\":7,\"topic\":\"timeline\",\"key\":\"%s\","
                          "\"params\":{\"start_ns\":\"0\",\"end_ns\":\"1024000000000\",\"granularity\":\"250ms\"}}", keys[ k ] );
    FD_TEST( !fd_gui_ws_message( gui, 0UL, (uchar const *)valid, strlen( valid ) ) );
    fd_http_server_stage_trunc( gui->http, 0UL );
  }

  /* Replay producer: fees and tips are recorded at commit time. */
  long const now  = sec_ns( 10UL ) + 500000000L;
  long const tick = fd_tickcount();
  gui->tick_per_ns = 1e30; /* deterministic sub-nanosecond tick offsets */
  fd_replay_txn_executed_t executed = {
    .slot=101UL, .exec_tile_idx=3UL, .sigverify_exec_tile_idx=4UL, .index_in_slot=5UL,
    .tick_sigverify_disp=tick, .tick_sigverify_done=tick, .tick_load_start=tick,
    .tick_check_start=LONG_MAX, .tick_exec_start=LONG_MAX, .tick_commit_start=LONG_MAX, .tick_commit_end=tick,
    .is_committable=1, .max_compute_units=60000000UL, .transaction_fee=5000UL, .priority_fee=11UL, .tips=13UL
  };
  executed.txn->payload[ 0 ]  = 1U;
  executed.txn->payload[ 65 ] = 1U;
  executed.txn->payload[ 68 ] = 1U;
  executed.txn->payload_sz    = 134U;
  FD_TEST( fd_txn_parse( executed.txn->payload, executed.txn->payload_sz, TXN( executed.txn ), NULL ) );
  fd_gui_handle_replay_txn( gui, &executed, now );
  executed.tick_commit_end = LONG_MAX; /* incomplete transactions are not recorded */
  fd_gui_handle_replay_txn( gui, &executed, now );

  /* Leader producer: execle rows use pack fees, including precompile
     signatures, and the tips supplied by the trailer. */
  fd_gui_became_leader( gui, 500UL, now, now+sec_ns( 1UL ), 60000000UL, 8UL, 7UL );
  FD_TEST( fd_gui_slot_leader_get( gui, 500UL, 7UL )->max_compute_units==60000000UL );
  fd_txn_p_t txn = {0};
  txn.payload[ 0 ]  = 1U;
  txn.payload[ 65 ] = 1U;
  txn.payload[ 67 ] = 2U;
  txn.payload[ 68 ] = 3U;
  fd_memcpy( txn.payload+101UL, &fd_solana_compute_budget_program_id, 32UL );
  fd_memcpy( txn.payload+133UL, &fd_solana_ed25519_sig_verify_program_id, 32UL );
  txn.payload[ 197 ] = 3U;
  uchar instrs[] = { 1U,0U,5U,2U,0xE8U,3U,0U,0U, /* CU limit 1000 */
                     1U,0U,9U,3U,0x40U,0x42U,0x0FU,0U,0U,0U,0U,0U, /* price 1e6 */
                     2U,0U,30U,2U,0U };
  fd_memcpy( txn.payload+198UL, instrs, sizeof(instrs) );
  txn.payload_sz = (ushort)(198UL+sizeof(instrs)+28UL);
  FD_TEST( fd_txn_parse( txn.payload, txn.payload_sz, TXN( &txn ), NULL ) );
  fd_txn_ns_dt_t dt = { .load_start=10.4f, .check_start=20.6f, .exec_start=30.4f, .commit_start=60.6f, .commit_end=100.4f };
  txn.flags = FD_TXN_P_FLAGS_EXECUTE_SUCCESS | (200U<<24);
  txn.execle_cu.actual_consumed_cus = 42U;
  fd_gui_microblock_execution_end( gui, now, 3UL, 500UL, 1UL, &txn, 17UL, dt, fd_tickcount(), 7UL, 7UL, now );
  txn.flags = 0U; /* a non-landed transaction is not recorded */
  fd_gui_microblock_execution_end( gui, now, 3UL, 500UL, 1UL, &txn, 18UL, dt, fd_tickcount(), 7UL, 7UL, now );
  FD_TEST( count_ts( gui, FD_GUI_HIST_REPLAY_TXN, ULONG_MAX )==2UL );

  /* Error code, unknown shred indices and commit time come from the
     leader row; fees and tips are checked through the query below. */
  fd_gui_hist_iter_t it;
  FD_TEST( !fd_gui_hist_range_begin( gui, &it, FD_GUI_HIST_REPLAY_TXN, now, now, NULL, NULL ) );
  FD_TEST( fd_gui_hist_range_next( &it ) && fd_gui_hist_range_next( &it ) );
  fd_gui_store_replay_txn_t const * rec = it.rec;
  FD_TEST( rec->slot==500UL && rec->commit_end_ns==now && rec->error_code==200U );
  FD_TEST( rec->txn_start_shred_idx==UINT_MAX && rec->txn_end_shred_idx==UINT_MAX );
  fd_gui_hist_range_end( &it );

  /* Transactions with an invalid fee payer (errors 5 and 6) pay no fees
     or tips, and failed transactions pay no tips, so the aggregates
     below are unaffected by these rows. */
  executed.tick_commit_end = tick;
  executed.transaction_fee = 7000UL;
  executed.priority_fee    = 17UL;
  executed.tips            = 19UL;
  executed.txn_err         = -5;
  fd_gui_handle_replay_txn( gui, &executed, now );
  executed.txn_err         = -6;
  fd_gui_handle_replay_txn( gui, &executed, now );

  /* A non-committable transaction (which kills its block) keeps its
     replay row but adds nothing to the aggregates. */
  executed.txn_err         = -9;
  executed.is_committable  = 0;
  fd_gui_handle_replay_txn( gui, &executed, now );

  /* Both producers land in one bucket at the 250ms, 1s (4x250ms) and
     1d (2x12h) granularities.  The next bucket is unknown; for 1d it
     is a day with no record at all. */
  ulong const gs[] = { 3UL, 5UL, 22UL };
  for( ulong i=0UL; i<sizeof(gs)/sizeof(gs[ 0 ]); i++ ) {
    ulong g   = gs[ i ];
    ulong ns  = fd_gui_timeline_granularity_ns( g );
    long  ref = (long)((ulong)now/ns*ns);
    char expected[ 768 ];
    fd_cstr_printf_check( expected, sizeof(expected), NULL,
                          "{\"topic\":\"timeline\",\"key\":\"query_agg_revenue\",\"id\":7,\"value\":{\"granularity\":\"%s\",\"reference_ts_ns\":\"%ld\","
                          "\"available_start_ns\":\"0\",\"available_end_ns\":\"86400000000000\","
                          "\"txn_fees\":[\"20000\",null],\"prio_fees\":[\"1011\",null],\"tips\":[\"13\",null]}}",
                          fd_gui_timeline_granularities[ g ].name, ref );
    FD_TEST( !fd_gui_printf_timeline_query_agg( gui, "query_agg_revenue", fd_gui_timeline_granularities[ g ].name, g, ref, 2UL, 7UL ) );
    check_response( gui, expected );

    /* The replay rows add no compute units and the leader row adds 42,
       all against a 60M block limit.  Of the four landed rows, only the
       first replay row succeeded. */
    fd_cstr_printf_check( expected, sizeof(expected), NULL,
                          "{\"topic\":\"timeline\",\"key\":\"query_agg_compute\",\"id\":7,\"value\":{\"granularity\":\"%s\",\"reference_ts_ns\":\"%ld\","
                          "\"available_start_ns\":\"0\",\"available_end_ns\":\"86400000000000\","
                          "\"compute_units\":[42,null],\"max_compute_units\":60000000}}",
                          fd_gui_timeline_granularities[ g ].name, ref );
    FD_TEST( !fd_gui_printf_timeline_query_agg( gui, "query_agg_compute", fd_gui_timeline_granularities[ g ].name, g, ref, 2UL, 7UL ) );
    check_response( gui, expected );

    fd_cstr_printf_check( expected, sizeof(expected), NULL,
                          "{\"topic\":\"timeline\",\"key\":\"query_agg_txn\",\"id\":7,\"value\":{\"granularity\":\"%s\",\"reference_ts_ns\":\"%ld\","
                          "\"available_start_ns\":\"0\",\"available_end_ns\":\"86400000000000\","
                          "\"success_nonvote_transactions\":[1,null],\"failed_nonvote_transactions\":[3,null],"
                          "\"success_vote_transactions\":[0,null],\"failed_vote_transactions\":[0,null]}}",
                          fd_gui_timeline_granularities[ g ].name, ref );
    FD_TEST( !fd_gui_printf_timeline_query_agg( gui, "query_agg_txn", fd_gui_timeline_granularities[ g ].name, g, ref, 2UL, 7UL ) );
    check_response( gui, expected );
  }

  test_http_close( gui, http_mem );
  FD_LOG_NOTICE(( "test_timeline_agg: requests, replay and leader producers, granularities: ok" ));
}

/* test_min_footprint checks the store's minimum size: the per-DB base
   regions, sized for the largest topology, fit the documented 10 GiB
   floor of [tiles.gui.db_size_gib] (src/app/shared/fd_config.c). */

static void
test_min_footprint( void ) {
  fd_gui_store_desc_t const * descs = test_descs();
  ulong min_size = fd_gui_store_min_size( FD_GUI_HIST_CNT, descs );
  FD_LOG_NOTICE(( "GUI DB minimum: %lu MiB", min_size>>20 ));
  FD_TEST( min_size<=TEST_STORE_BYTES );
  FD_TEST( !fd_gui_store_footprint( min_size-1UL, FD_GUI_HIST_CNT, descs ) );
  FD_TEST( fd_gui_store_footprint( min_size, FD_GUI_HIST_CNT, descs ) );
  FD_TEST( fd_gui_hist_store_footprint( TEST_STORE_BYTES, TEST_TILE_CNT )==fd_gui_store_footprint( TEST_STORE_BYTES, FD_GUI_HIST_CNT, descs ) );
  FD_TEST( !fd_gui_hist_store_footprint( min_size-1UL, TEST_TILE_CNT ) );
}

/* In a minimum-size store with every other DB's base full, day rollover
   for FD_TOPO_MAX_TILES tiles only evicts records of earlier days:
   today's and yesterday's records for every tile always survive. */
static void
test_tile_day_minimum_store( fd_gui_t * gui ) {
  fd_gui_scheduler_counts_t counts = { .sample_time_ns=1L };
  while( fd_gui_store_ts_append( gui->db, FD_GUI_HIST_SCHEDULER_COUNTS, &counts )==FD_GUI_STORE_SUCCESS ) {}
  FD_TEST( !fd_gui_store_shared_free_region_cnt( gui->db ) );
  for( ulong day=0UL; day<5UL; day++ ) {
    for( ulong t=0UL; t<FD_TOPO_MAX_TILES; t++ ) {
      fd_gui_hist_tile_day_key_t key = { .day_idx=day, .tile_idx=t };
      fd_gui_timeline_tile_day_t * rec = fd_gui_hist_kv_get_or_create( gui, FD_GUI_HIST_TIMELINE_TILE_DAY, &key );
      FD_TEST( rec );
      rec->insert_time_ns = (long)day;
      for( ulong d=day ? day-1UL : 0UL; d<=day; d++ )
        for( ulong u=0UL; u<(d==day ? t+1UL : FD_TOPO_MAX_TILES); u++ )
          FD_TEST( fd_gui_timeline_tile_day_get( gui, d, u ) );
    }
  }
  FD_TEST( fd_gui_store_metrics( gui->db )->evict_records[ FD_GUI_HIST_TIMELINE_TILE_DAY ] );
  FD_LOG_NOTICE(( "test_tile_day_minimum_store: today and yesterday survive rollover: ok" ));
}

/* test_timeline_cpu drives the CPU sampler from fake tile metrics and
   checks the per-tile day records: 25ms sample merges, the 2s and
   longer sum/count tiers, the tile whitelist, unknown samples, a
   missing tile record and the availability bounds.  Tile 0 is fully
   busy for two seconds then idle for two; tile 1 is fully busy for two
   seconds then stops publishing; tile 2 has no metrics. */

/* Day records are prepared from fd_gui_poll in budgeted steps and are
   invisible until complete; the frag path never creates them. */

static void
test_day_prepare( fd_gui_t * gui ) {
  gui->day_prep.sync = 0;
  fd_topo_t * topo = calloc( 1UL, sizeof(fd_topo_t) );
  FD_TEST( topo );
  topo->tile_cnt = TEST_TILE_CNT;
  static ulong metrics[ 2 ][ 1UL+FD_METRICS_TOTAL_SZ/sizeof(ulong) ];
  memset( metrics, 0, sizeof(metrics) );
  topo->tiles[ 0 ].metrics = metrics[ 0 ];
  topo->tiles[ 1 ].metrics = metrics[ 1 ];
  gui->topo = topo;
  gui->tile_state.exec_cnt    = 1UL;
  gui->tile_state.pos_cnt     = 2UL;
  gui->tile_state.topo_idx[0] = 0UL;
  gui->tile_state.topo_idx[1] = 1UL;

  long  const day = FD_GUI_TIMELINE_DAY_NS;
  long        now = 5L*day + sec_ns( 10UL );

  /* Nothing is created on use. */
  volatile ulong * busy0 = fd_metrics_tile( metrics[ 0 ] ) + MIDX( COUNTER, TILE, REGIME_DURATION_NANOS ) + FD_METRICS_ENUM_TILE_REGIME_V_PROCESSING_PREFRAG_IDX;
  *busy0 = 1UL;
  fd_gui_cpu_util_snap( gui, now );
  *busy0 += 25000000UL;
  fd_gui_cpu_util_snap( gui, now+FD_GUI_CPU_UTIL_SAMPLE_NS );
  FD_TEST( !fd_gui_timeline_tile_day_get( gui, 5UL, 0UL ) );
  FD_TEST( gui->day_prep.missing_cnt==1UL );

  /* Today is prepared in steps of at most the budget, and no record is
     visible before it is complete. */
  ulong const budget = 16UL<<20;
  ulong       polls  = 0UL;
  /* Each record becomes visible once its own initialization is
     complete. */
  while( gui->day_prep.done!=5UL ) {
    fd_gui_timeline_days_prepare( gui, now, budget );
    polls++;
    FD_TEST( polls<64UL );
    if( gui->day_prep.done==5UL ) break;
    ulong step = gui->day_prep.step;
    FD_TEST( !fd_gui_timeline_day_get( gui, 5UL )==!step );
    if( step>=1UL && step<=2UL ) FD_TEST( !fd_gui_timeline_tile_day_get( gui, 5UL, step-1UL ) );
  }
  ulong const total = sizeof(fd_gui_timeline_day_t) + 2UL*sizeof(fd_gui_timeline_tile_day_t) + 2UL*sizeof(fd_gui_timeline_tile_state_day_t);
  FD_TEST( polls>=total/budget );
  fd_gui_timeline_day_t const * d5 = fd_gui_timeline_day_get( gui, 5UL );
  FD_TEST( d5 && d5->insert_time_ns==now && d5->end_time_ns==6L*day );
  FD_TEST( d5->bucket_12h.skipped[ 0 ]==UINT_MAX );
  FD_TEST( fd_gui_timeline_tile_day_get( gui, 5UL, 0UL ) && fd_gui_timeline_tile_day_get( gui, 5UL, 1UL ) );
  FD_TEST( !fd_gui_timeline_tile_day_get( gui, 5UL, 2UL ) ); /* no metrics */
  fd_gui_timeline_tile_state_day_t const * ts = fd_gui_timeline_tile_state_day_get( gui, 5UL, 1UL );
  FD_TEST( ts && ts->first_ns==LONG_MAX && !ts->last_ns && ts->insert_time_ns==now );

  /* Samples now land. */
  ulong missing = gui->day_prep.missing_cnt;
  *busy0 += 25000000UL;
  fd_gui_cpu_util_snap( gui, now+2L*FD_GUI_CPU_UTIL_SAMPLE_NS );
  FD_TEST( gui->day_prep.missing_cnt==missing );

  /* Tomorrow is not prepared before the last hour of the day, then is
     prepared without becoming available. */
  fd_gui_timeline_days_prepare( gui, 6L*day-FD_GUI_TIMELINE_PREPARE_AHEAD_NS-1L, ULONG_MAX );
  FD_TEST( gui->day_prep.done==5UL && !fd_gui_timeline_day_get( gui, 6UL ) );
  now = 6L*day-FD_GUI_TIMELINE_PREPARE_AHEAD_NS;
  gui->chunk.now = now;
  fd_gui_timeline_days_prepare( gui, now, ULONG_MAX );
  FD_TEST( gui->day_prep.done==6UL && fd_gui_timeline_day_get( gui, 6UL ) );
  FD_TEST( fd_gui_timeline_tile_state_day_get( gui, 6UL, 0UL ) );
  ulong lo_day, hi_day;
  FD_TEST( fd_gui_timeline_tile_day_bounds( gui, &lo_day, &hi_day ) && lo_day==5UL && hi_day==5UL );
  FD_TEST( fd_gui_timeline_tile_state_day_bounds( gui, &lo_day, &hi_day ) && hi_day==5UL );
  gui->chunk.now = 6L*day+1L;
  FD_TEST( fd_gui_timeline_tile_day_bounds( gui, &lo_day, &hi_day ) && hi_day==6UL );
  gui->chunk.now = 0L;

  gui->topo = NULL;
  free( topo );
  gui->day_prep.sync = 1;
  FD_LOG_NOTICE(( "test_day_prepare: %lu polls of %lu MiB for %lu MiB: ok", polls, budget>>20, total>>20 ));
}

static void
test_timeline_cpu( fd_gui_t * gui ) {
  void * http_mem = test_http_open( gui, FD_GUI_HTTP_MIN_SEND_BUFFER_SZ );

  fd_topo_t * topo = calloc( 1UL, sizeof(fd_topo_t) );
  FD_TEST( topo );
  topo->tile_cnt = TEST_TILE_CNT;
  static ulong metrics[ 2 ][ 1UL+FD_METRICS_TOTAL_SZ/sizeof(ulong) ];
  memset( metrics, 0, sizeof(metrics) );
  topo->tiles[ 0 ].metrics = metrics[ 0 ];
  topo->tiles[ 1 ].metrics = metrics[ 1 ];
  gui->topo = topo;
  gui->summary.tile_cnt = TEST_TILE_CNT;
  for( ulong i=0UL; i<TEST_TILE_CNT; i++ ) gui->summary.tile[ i ] = i;

  volatile ulong * busy0 = fd_metrics_tile( metrics[ 0 ] ) + MIDX( COUNTER, TILE, REGIME_DURATION_NANOS ) + FD_METRICS_ENUM_TILE_REGIME_V_PROCESSING_PREFRAG_IDX;
  volatile ulong * idle0 = fd_metrics_tile( metrics[ 0 ] ) + MIDX( COUNTER, TILE, REGIME_DURATION_NANOS ) + FD_METRICS_ENUM_TILE_REGIME_V_CAUGHT_UP_SLEEPING_IDX;
  volatile ulong * busy1 = fd_metrics_tile( metrics[ 1 ] ) + MIDX( COUNTER, TILE, REGIME_DURATION_NANOS ) + FD_METRICS_ENUM_TILE_REGIME_V_PROCESSING_PREFRAG_IDX;

  /* Tiles have published timers before the first sample, which only
     sets their references. */
  *idle0 = 1UL;
  *busy1 = 1UL;
  long const t0 = sec_ns( 10UL );
  for( ulong k=0UL; k<=160UL; k++ ) {
    if( k ) {
      if( k<=80UL ) { *busy0 += 25000000UL; *busy1 += 25000000UL; }
      else            *idle0 += 25000000UL;
    }
    fd_gui_cpu_util_snap( gui, t0 + (long)k*FD_GUI_CPU_UTIL_SAMPLE_NS + 1L );
  }

  /* One record per publishing tile for day 0.  Samples cover [10s,14s);
     tile 1's last two seconds are unknown. */
  fd_gui_timeline_tile_day_t const * rec0 = fd_gui_timeline_tile_day_get( gui, 0UL, 0UL );
  fd_gui_timeline_tile_day_t const * rec1 = fd_gui_timeline_tile_day_get( gui, 0UL, 1UL );
  FD_TEST( rec0 && rec1 && !fd_gui_timeline_tile_day_get( gui, 0UL, 2UL ) );
  FD_TEST( rec0->day_idx==0UL && rec0->tile_idx==0UL && rec1->tile_idx==1UL );
  ulong i0 = (ulong)t0/(ulong)FD_GUI_CPU_UTIL_SAMPLE_NS;
  FD_TEST( rec0->util_25ms[ i0-1UL ]==FD_GUI_CPU_UTIL_UNKNOWN );
  FD_TEST( rec0->util_25ms[ i0     ]==FD_GUI_CPU_UTIL_MAX );
  FD_TEST( rec0->util_25ms[ i0+80UL ]==0 );
  FD_TEST( rec0->util_25ms[ i0+160UL ]==FD_GUI_CPU_UTIL_UNKNOWN );
  FD_TEST( rec1->util_25ms[ i0+79UL ]==FD_GUI_CPU_UTIL_MAX );
  FD_TEST( rec1->util_25ms[ i0+80UL ]==FD_GUI_CPU_UTIL_UNKNOWN );
  ulong lo_day, hi_day;
  FD_TEST( fd_gui_timeline_tile_day_bounds( gui, &lo_day, &hi_day ) && !lo_day && !hi_day );

#define CPU_RESPONSE( gran, ref, util ) \
  "{\"topic\":\"timeline\",\"key\":\"query_agg_cpu\",\"id\":7,\"value\":{\"granularity\":\"" gran "\",\"reference_ts_ns\":\"" ref "\"," \
  "\"available_start_ns\":\"0\",\"available_end_ns\":\"86400000000000\",\"utilization\":" util "}}"

  /* 1s buckets average the 25ms samples; unknown samples are skipped,
     and a tile without a record is null. */
  ulong tiles[ 3 ] = { 0UL, 1UL, 2UL };
  FD_TEST( !fd_gui_printf_timeline_query_agg_cpu( gui, "1s", 5UL, t0, 4UL, tiles, 3UL, 7UL ) );
  check_response( gui, CPU_RESPONSE( "1s", "10000000000", "[[250,250,0,0],[250,250,null,null],[null,null,null,null]]" ) );
  /* The window must be aligned to the requested granularity, so no
     bucket crosses into the next day's record. */
  FD_TEST( fd_gui_printf_timeline_query_agg_cpu( gui, "1s", 5UL, t0+sec_ns( 1UL )+sec_ns( 1UL )/2L, 1UL, tiles, 2UL, 7UL )==-1 );
  FD_TEST( fd_gui_printf_timeline_query_agg_cpu( gui, "1s", 5UL, FD_GUI_TIMELINE_DAY_NS-250000000L, 1UL, tiles, 1UL, 7UL )==-1 );
  FD_TEST( fd_gui_printf_timeline_query_agg_cpu( gui, "1d", 22UL, FD_GUI_TIMELINE_DAY_NS-sec_ns( 2UL ), 1UL, tiles, 1UL, 7UL )==-1 );

  /* The whitelist selects and orders tiles. */
  ulong tile1[ 1 ] = { 1UL };
  FD_TEST( !fd_gui_printf_timeline_query_agg_cpu( gui, "25ms", 0UL, t0+sec_ns( 2UL )-FD_GUI_CPU_UTIL_SAMPLE_NS, 2UL, tile1, 1UL, 7UL ) );
  check_response( gui, CPU_RESPONSE( "25ms", "11975000000", "[[250,null]]" ) );
  ulong tile10[ 2 ] = { 1UL, 0UL };
  FD_TEST( !fd_gui_printf_timeline_query_agg_cpu( gui, "50ms", 1UL, t0+sec_ns( 2UL )-50000000L, 2UL, tile10, 2UL, 7UL ) );
  check_response( gui, CPU_RESPONSE( "50ms", "11950000000", "[[250,null],[250,0]]" ) );
  FD_TEST( !fd_gui_printf_timeline_query_agg_cpu( gui, "100ms", 2UL, t0+sec_ns( 2UL )-100000000L, 2UL, tiles, 1UL, 7UL ) );
  check_response( gui, CPU_RESPONSE( "100ms", "11900000000", "[[250,0]]" ) );
  FD_TEST( !fd_gui_printf_timeline_query_agg_cpu( gui, "250ms", 3UL, t0+sec_ns( 2UL )-250000000L, 2UL, tiles, 2UL, 7UL ) );
  check_response( gui, CPU_RESPONSE( "250ms", "11750000000", "[[250,0],[250,null]]" ) );
  FD_TEST( fd_gui_printf_timeline_query_agg_cpu( gui, "250ms", 3UL, t0+sec_ns( 2UL )-125000000L, 1UL, tiles, 2UL, 7UL )==-1 ); /* unaligned */

  /* 2s and longer merge exact sums and counts: tile 1 only counts its
     known samples. */
  FD_TEST( !fd_gui_printf_timeline_query_agg_cpu( gui, "2s", 6UL, t0, 2UL, tiles, 2UL, 7UL ) );
  check_response( gui, CPU_RESPONSE( "2s", "10000000000", "[[250,0],[250,null]]" ) );
  FD_TEST( !fd_gui_printf_timeline_query_agg_cpu( gui, "8s", 8UL, sec_ns( 8UL ), 1UL, tiles, 2UL, 7UL ) );
  check_response( gui, CPU_RESPONSE( "8s", "8000000000", "[[125],[250]]" ) );
#undef CPU_RESPONSE

  /* Only tile 0 publishes into day 1.  Preparing day 1 created tile
     1's record too, but its buckets stay null while tile 0's are not. */
  *busy0 += 1000UL;
  *idle0 += 1000UL;
  fd_gui_cpu_util_snap( gui, FD_GUI_TIMELINE_DAY_NS + sec_ns( 1UL ) + 1L );
  FD_TEST( fd_gui_timeline_tile_day_get( gui, 1UL, 0UL ) && fd_gui_timeline_tile_day_get( gui, 1UL, 1UL ) );
  FD_TEST( fd_gui_timeline_tile_day_bounds( gui, &lo_day, &hi_day ) && lo_day==0UL && hi_day==1UL );
  FD_TEST( !fd_gui_printf_timeline_query_agg_cpu( gui, "1s", 5UL, FD_GUI_TIMELINE_DAY_NS, 1UL, tiles, 2UL, 7UL ) );
  check_response( gui, "{\"topic\":\"timeline\",\"key\":\"query_agg_cpu\",\"id\":7,\"value\":{\"granularity\":\"1s\",\"reference_ts_ns\":\"86400000000000\","
                       "\"available_start_ns\":\"0\",\"available_end_ns\":\"172800000000000\",\"utilization\":[[125],[null]]}}" );
  FD_TEST( !fd_gui_printf_timeline_query_agg_cpu( gui, "1d", 22UL, 0L, 2UL, tiles, 2UL, 7UL ) );
  check_response( gui, "{\"topic\":\"timeline\",\"key\":\"query_agg_cpu\",\"id\":7,\"value\":{\"granularity\":\"1d\",\"reference_ts_ns\":\"0\","
                       "\"available_start_ns\":\"0\",\"available_end_ns\":\"172800000000000\",\"utilization\":[[125,125],[250,null]]}}" );

  ulong bad[ 1 ] = { TEST_TILE_CNT };
  FD_TEST( fd_gui_printf_timeline_query_agg_cpu( gui, "1s", 5UL, t0, 1UL, bad, 1UL, 7UL )==-1 );
  FD_TEST( fd_gui_printf_timeline_query_agg_cpu( gui, "1s", 5UL, t0, 1UL, tiles, 0UL, 7UL )==-1 );
  ulong dup[ 2 ] = { 1UL, 1UL };
  FD_TEST( fd_gui_printf_timeline_query_agg_cpu( gui, "1s", 5UL, t0, 1UL, dup, 2UL, 7UL )==-1 );

  /* Every granularity merges at most 4 stored buckets, so the maximum
     tile count over the full bucket count is served at every
     granularity. */
  for( ulong g=0UL; g<FD_GUI_TIMELINE_GRANULARITY_CNT; g++ ) {
    int   stored;
    ulong merge_cnt;
    FD_TEST( !fd_gui_timeline_tier( "query_agg_cpu", g, &stored, &merge_cnt ) && merge_cnt<=4UL );
  }
  static ulong all[ FD_TOPO_MAX_TILES ];
  for( ulong i=0UL; i<FD_TOPO_MAX_TILES; i++ ) all[ i ] = i;
  gui->summary.tile_cnt = FD_TOPO_MAX_TILES;
  for( ulong i=0UL; i<FD_TOPO_MAX_TILES; i++ ) gui->summary.tile[ i ] = i;
  FD_TEST( !fd_gui_printf_timeline_query_agg_cpu( gui, "1s", 5UL, 0L, FD_GUI_TIMELINE_QUERY_MAX_BUCKETS, all, FD_TOPO_MAX_TILES, 7UL ) );
  fd_http_server_stage_trunc( gui->http, 0UL );
  gui->summary.tile_cnt = TEST_TILE_CNT;

  /* The request path accepts a tile list, rejects a repeated tile, and
     enforces the tile count limit before resolving any tile. */
  char const * ok = "{\"id\":7,\"topic\":\"timeline\",\"key\":\"query_agg_cpu\",\"params\":"
                    "{\"start_ns\":\"10000000000\",\"end_ns\":\"12000000000\",\"granularity\":\"1s\",\"tiles\":[1,0]}}";
  FD_TEST( !fd_gui_ws_message( gui, 0UL, (uchar const *)ok, strlen( ok ) ) );
  char const * rep = "{\"id\":7,\"topic\":\"timeline\",\"key\":\"query_agg_cpu\",\"params\":"
                     "{\"start_ns\":\"10000000000\",\"end_ns\":\"12000000000\",\"granularity\":\"1s\",\"tiles\":[1,1]}}";
  FD_TEST( fd_gui_ws_message( gui, 0UL, (uchar const *)rep, strlen( rep ) )==FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST );
  char * big = malloc( 8192UL );
  FD_TEST( big );
  ulong off = 0UL;
  fd_cstr_printf_check( big, 8192UL, &off, "{\"id\":7,\"topic\":\"timeline\",\"key\":\"query_agg_cpu\",\"params\":"
                        "{\"start_ns\":\"0\",\"end_ns\":\"1000000000\",\"granularity\":\"1s\",\"tiles\":[" );
  for( ulong i=0UL; i<=FD_TOPO_MAX_TILES; i++ ) {
    ulong n;
    fd_cstr_printf_check( big+off, 8192UL-off, &n, "%s0", i ? "," : "" );
    off += n;
  }
  fd_cstr_printf_check( big+off, 8192UL-off, NULL, "]}}" );
  FD_TEST( fd_gui_ws_message( gui, 0UL, (uchar const *)big, strlen( big ) )==FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST );
  free( big );

  /* Replay slot states land on the replay tile (topo tile 1, after
     the single execrp tile 0): stored as rows for query_tile_states and
     aggregated for query_agg_tile_states.  Ticks are converted against
     the current tickcount, so allow a little slack. */
  {
    double tick_per_ns = gui->tick_per_ns;
    gui->tick_per_ns = 1.0;
    gui->tile_state.exec_cnt    = 1UL;
    gui->tile_state.pos_cnt     = 2UL;
    gui->tile_state.topo_idx[0] = 0UL;
    gui->tile_state.topo_idx[1] = 1UL;
    long now = 3L*FD_GUI_TIMELINE_DAY_NS + sec_ns( 10UL );
    fd_replay_slot_states_t msg = { .cnt = 1UL };
    long tick = fd_tickcount();
    msg.states[ 0 ] = (fd_sched_slot_state_t){ .slot=42UL, .start_tick=tick-3000000000L, .end_tick=tick-1000000000L, .state=FD_SCHED_SLOT_STATE_BLOCKED_NETWORK };
    fd_gui_handle_replay_slot_states( gui, &msg, now );
    long slack = 10000000L; /* 10ms */

    long  ref = 3L*FD_GUI_TIMELINE_DAY_NS + sec_ns( 6UL );
    FD_TEST( !fd_gui_printf_timeline_query_agg_tile_states( gui, "2s", 6UL, ref, 2UL, 7UL ) );
    test_json_t json = timeline_response( gui );
    test_json_t ts   = timeline_value( json, "tile_states" );
    FD_TEST( test_json_count( timeline_value( json, "tiles" ) )==2 );
    FD_TEST( test_json_ulong( test_json_index( timeline_value( json, "tiles" ), 0 ) )==0UL );
    FD_TEST( test_json_ulong( test_json_index( timeline_value( json, "tiles" ), 1 ) )==1UL );
    FD_TEST( test_json_count( ts )==2 );
    FD_TEST( test_json_kind( test_json_index( test_json_index( test_json_index( ts, 0 ), 0 ), 0 ) )==FD_JTOK_NULL ); /* no execrp record */
    test_json_t replay = test_json_index( ts, 1 );
    FD_TEST( test_json_count( replay )==(int)FD_GUI_TILE_STATE_CNT );
    for( int b=0; b<2; b++ ) {
      ulong net  = test_json_ulong( test_json_index( test_json_index( replay, FD_GUI_TILE_STATE_BLOCKED_ON_NETWORK ), b ) );
      ulong idle = test_json_ulong( test_json_index( test_json_index( replay, FD_GUI_TILE_STATE_IDLE ), b ) );
      ulong tile = test_json_ulong( test_json_index( test_json_index( replay, FD_GUI_TILE_STATE_BLOCKED_ON_TILES ), b ) );
      FD_TEST( net+(ulong)(slack/1000L)>=1000000UL && net<=1000000UL+(ulong)(slack/1000L) ); /* 1s of each 2s bucket, in us */
      FD_TEST( !tile && idle<=(ulong)(slack/1000L) ); /* outside the recorded span is unknown, not Idle */
    }
    /* The 250ms tier is exact ns too: the network state covers
       [ref+1s,ref+3s), so of the 250ms buckets from ref+0.25s the first
       three are empty and the next eight full, and 1s buckets sum them. */
    FD_TEST( !fd_gui_printf_timeline_query_agg_tile_states( gui, "250ms", 3UL, ref+250000000L, 12UL, 7UL ) );
    json   = timeline_response( gui );
    replay = test_json_index( timeline_value( json, "tile_states" ), 1 );
    for( int b=0; b<12; b++ ) {
      test_json_t v    = test_json_index( test_json_index( replay, FD_GUI_TILE_STATE_BLOCKED_ON_NETWORK ), b );
      ulong       want = ( b>=3 && b<11 ) ? 250000UL : 0UL;
      if( test_json_kind( v )==FD_JTOK_NULL ) { FD_TEST( !want ); continue; } /* outside the recorded span */
      ulong       net  = test_json_ulong( v );
      FD_TEST( net+(ulong)(slack/1000L)>=want && net<=want+(ulong)(slack/1000L) );
    }
    FD_TEST( !fd_gui_printf_timeline_query_agg_tile_states( gui, "1s", 5UL, ref, 4UL, 7UL ) );
    json   = timeline_response( gui );
    replay = test_json_index( timeline_value( json, "tile_states" ), 1 );
    for( int b=0; b<4; b++ ) {
      test_json_t v    = test_json_index( test_json_index( replay, FD_GUI_TILE_STATE_BLOCKED_ON_NETWORK ), b );
      ulong       want = ( b==1 || b==2 ) ? 1000000UL : 0UL;
      if( test_json_kind( v )==FD_JTOK_NULL ) { FD_TEST( !want ); continue; }
      ulong       net  = test_json_ulong( v );
      FD_TEST( net+(ulong)(slack/1000L)>=want && net<=want+(ulong)(slack/1000L) );
    }
    FD_TEST( fd_gui_printf_timeline_query_agg_tile_states( gui, "100ms", 2UL, ref, 2UL, 7UL )==-1 ); /* 250ms minimum */

    FD_TEST( !fd_gui_printf_timeline_query_tile_states( gui, ref, ref+sec_ns( 4UL ), 0, 7UL ) );
    json = timeline_response( gui );
    FD_TEST( test_json_ulong( timeline_value( json, "reference_slot" ) )==42UL );
    FD_TEST( test_json_count( timeline_value( json, "tile" ) )==2 );
    FD_TEST( test_json_ulong( test_json_index( timeline_value( json, "tile" ), 1 ) )==1UL );
    FD_TEST( test_json_ulong( test_json_index( timeline_value( json, "state_cnt" ), 0 ) )==0UL );
    FD_TEST( test_json_ulong( test_json_index( timeline_value( json, "state_cnt" ), 1 ) )==1UL ); /* network only, no Idle padding */
    FD_TEST( test_json_kind( test_json_index( timeline_value( json, "tile_start_ts_delta" ), 0 ) )==FD_JTOK_NULL );
    FD_TEST( test_json_ulong( test_json_index( timeline_value( json, "state" ), 0 ) )==FD_GUI_TILE_STATE_BLOCKED_ON_NETWORK );
    long dur = (long)test_json_ulong( test_json_index( timeline_value( json, "dur" ), 0 ) );
    FD_TEST( dur>=sec_ns( 2UL )-slack && dur<=sec_ns( 2UL )+slack );
    FD_TEST( test_json_count( timeline_value( json, "slot_state_lo" ) )==1 );
    FD_TEST( test_json_ulong( test_json_index( timeline_value( json, "slot_state_lo" ), 0 ) )==0UL );
    FD_TEST( test_json_ulong( test_json_index( timeline_value( json, "slot_state_cnt" ), 0 ) )==1UL );
    FD_TEST( test_json_ulong( test_json_index( timeline_value( json, "slot_delta" ), 0 ) )==0UL );
    FD_TEST( !test_json_count( timeline_value( json, "txn_idx" ) ) );

    /* txn_batch maps slot states to slots the same way. */
    FD_TEST( !fd_gui_printf_timeline_query_tile_states( gui, ref, ref+sec_ns( 4UL ), 1, 7UL ) );
    json = timeline_response( gui );
    FD_TEST( test_json_ulong( timeline_value( json, "reference_slot" ) )==42UL );
    FD_TEST( test_json_ulong( test_json_index( timeline_value( json, "state" ), 0 ) )==FD_GUI_TILE_STATE_BLOCKED_ON_NETWORK );
    FD_TEST( test_json_count( timeline_value( json, "slot_state_lo" ) )==1 );
    FD_TEST( test_json_ulong( test_json_index( timeline_value( json, "slot_state_lo" ), 0 ) )==0UL );
    FD_TEST( test_json_ulong( test_json_index( timeline_value( json, "slot_state_cnt" ), 0 ) )==1UL );
    FD_TEST( test_json_ulong( test_json_index( timeline_value( json, "slot_delta" ), 0 ) )==0UL );
    FD_TEST( !test_json_count( timeline_value( json, "txn_slot_delta" ) ) && !test_json_count( timeline_value( json, "lthash_slot_delta" ) ) );

    gui->tile_state.exec_cnt = 0UL;
    gui->tile_state.pos_cnt  = 0UL;
    gui->tick_per_ns = tick_per_ns;
  }

  gui->topo = NULL;
  free( topo );
  test_http_close( gui, http_mem );
  FD_LOG_NOTICE(( "test_timeline_cpu: ok" ));
}

/* test_fec_events covers FEC staging (admission checks, earliest-time
   dedup, skewed event exclusion, monotone admission, distinct slot complete
   markers), archival of the closed admission prefix with bounded batch
   spans, and event-time lookup across archive and staging through the
   regular time-series range query. */

static void
test_fec_events( fd_gui_t * gui ) {
  long  const ts  = sec_ns( 100UL );
  long  const lag = FD_GUI_FEC_EVENT_LAG_MAX_NS;
  uchar const ev  = FD_GUI_SLOT_SHRED_REPAIR_REQUEST;

  /* Before the closed slot watermark first advances, slots at or above
     the high watermark are dropped. */
  fd_gui_fec_event_append( gui, FD_GUI_FEC_SLOT_WMARK_CNT, 0UL, ev, ts, ts );
  FD_TEST( gui->shreds.dropped_fec_event_cnt==1UL );
  fd_gui_event_closed_slot_wmark_advance( gui, 100UL );
  fd_gui_event_closed_slot_wmark_advance( gui, 50UL ); /* only advances */
  FD_TEST( fd_gui_event_closed_slot_wmark( gui )==100UL );

  fd_gui_fec_event_append( gui, 99UL,  0UL, ev, ts, ts );                                     /* closed */
  fd_gui_fec_event_append( gui, 100UL+FD_GUI_FEC_SLOT_WMARK_CNT, 0UL, ev, ts, ts );           /* wmark */
  fd_gui_fec_event_append( gui, 100UL, USHORT_MAX, ev, ts, ts );                              /* marker idx */
  fd_gui_fec_event_append( gui, 100UL, 0UL, FD_GUI_SLOT_SHRED_SHRED_SLOT_COMPLETE, ts, ts );  /* marker idx */
  fd_gui_fec_event_append( gui, 100UL, 0UL, (uchar)5, ts, ts );                               /* bad event */
  fd_gui_fec_event_append( gui, 100UL, 0UL, ev, -1L, ts );                                    /* bad time */
  FD_TEST( gui->shreds.dropped_fec_event_cnt==7UL );
  FD_TEST( !count_ts( gui, FD_GUI_HIST_FEC_EVENTS, ULONG_MAX ) );
  long lo, hi;
  FD_TEST( !fd_gui_event_bounds( gui, FD_GUI_HIST_FEC_EVENTS, &lo, &hi ) );

  /* Dedup keeps the earliest event time and the first admission time. */
  fd_gui_fec_event_append( gui, 100UL, 0UL, ev, ts-10L, ts    );
  fd_gui_fec_event_append( gui, 100UL, 0UL, ev, ts-20L, ts+5L );
  fd_gui_fec_event_append( gui, 100UL, 0UL, ev, ts,     ts+6L );
  fd_gui_fec_event_key_t key = { .slot=100U, .idx=0U, .event=ev };
  fd_gui_fec_event_t const * rec = fd_gui_hist_kv_get( gui, FD_GUI_HIST_FEC_EVENTS, &key );
  FD_TEST( rec && rec->insert_time_ns==ts && rec->event_time_ns==ts-20L );
  FD_TEST( !gui->shreds.clamped_fec_event_cnt );

  /* Events beyond the lag bound of admission are excluded, on updates
     and on first admission.  Events at the bound are kept. */
  fd_gui_fec_event_append( gui, 100UL, 0UL, ev, ts-lag-1L, ts+7L );
  FD_TEST( rec->event_time_ns==ts-20L && gui->shreds.clamped_fec_event_cnt==1UL );
  fd_gui_fec_event_append( gui, 100UL, 0UL, ev, ts-lag, ts+7L );
  FD_TEST( rec->event_time_ns==ts-lag && gui->shreds.clamped_fec_event_cnt==1UL );
  fd_gui_fec_event_append( gui, 100UL, 1UL, ev, ts+sec_ns( 60UL ), ts+8L );
  key.idx = 1U;
  FD_TEST( !fd_gui_hist_kv_get( gui, FD_GUI_HIST_FEC_EVENTS, &key ) && gui->shreds.clamped_fec_event_cnt==2UL );
  fd_gui_fec_event_append( gui, 100UL, 1UL, ev, ts+8L+lag, ts+8L );
  rec = fd_gui_hist_kv_get( gui, FD_GUI_HIST_FEC_EVENTS, &key );
  FD_TEST( rec && rec->event_time_ns==ts+8L+lag && gui->shreds.clamped_fec_event_cnt==2UL );

  /* Admission time never decreases across staged records. */
  fd_gui_fec_event_append( gui, 101UL, 0UL, ev, ts, ts-1000L );
  key = (fd_gui_fec_event_key_t){ .slot=101U, .idx=0U, .event=ev };
  rec = fd_gui_hist_kv_get( gui, FD_GUI_HIST_FEC_EVENTS, &key );
  FD_TEST( rec && rec->insert_time_ns==ts+8L );

  /* Slot complete markers are distinct admissions. */
  fd_gui_shred_event_slot_complete( gui, 100UL, ts+9L, ts+9L );
  fd_gui_shred_event_slot_complete( gui, 100UL, ts+9L, ts+9L );
  fd_gui_shred_event_slot_complete( gui, 100UL, ts+9L+lag+1L, ts+9L ); /* skewed */
  FD_TEST( gui->shreds.fec_marker_sequence==2UL && gui->shreds.clamped_fec_event_cnt==3UL );
  FD_TEST( count_ts( gui, FD_GUI_HIST_FEC_EVENTS, ULONG_MAX )==5UL );
  FD_TEST( gui->shreds.dropped_fec_event_cnt==7UL );

  /* Only the closed admission prefix moves to the archive, and an open
     slot pins everything admitted after it. */
  FD_TEST( !fd_gui_fec_archive( gui, 512UL ) );
  fd_gui_event_closed_slot_wmark_advance( gui, 101UL );
  FD_TEST( fd_gui_fec_archive( gui, 1UL )==1UL );
  FD_TEST( fd_gui_fec_archive( gui, 512UL )==1UL );
  FD_TEST( !fd_gui_fec_archive( gui, 512UL ) );
  fd_gui_fec_event_append( gui, 100UL, 2UL, ev, ts+10L, ts+10L ); /* closed */
  FD_TEST( gui->shreds.dropped_fec_event_cnt==8UL );
  fd_gui_event_closed_slot_wmark_advance( gui, 102UL );
  FD_TEST( fd_gui_fec_archive( gui, 512UL )==3UL );
  FD_TEST( count_ts( gui, FD_GUI_HIST_FEC_EVENT_ARCHIVE, ULONG_MAX )==3UL );
  FD_TEST( count_ts( gui, FD_GUI_HIST_FEC_EVENTS, ULONG_MAX )==5UL );

  /* Archived batches span at most FD_GUI_FEC_BATCH_SPAN_NS of
     admission.  An event at the latest event time allowed at the end of
     a batch is still found from its batch's admission time. */
  long const t = ts+sec_ns( 20UL );
  long const span = FD_GUI_FEC_BATCH_SPAN_NS;
  fd_gui_fec_event_append( gui, 102UL, 0UL, ev, t,             t           );
  fd_gui_fec_event_append( gui, 102UL, 1UL, ev, t+span+lag,    t+span      );
  fd_gui_fec_event_append( gui, 102UL, 2UL, ev, t+span+1L,     t+span+1L   );
  fd_gui_fec_event_append( gui, 102UL, 3UL, ev, t+(long)UINT_MAX+span, t+(long)UINT_MAX+span );
  /* One staged event remains queryable before archival. */
  fd_gui_fec_event_append( gui, 103UL, 0UL, ev, t+sec_ns( 30UL ), t+sec_ns( 30UL ) );
  FD_TEST( gui->shreds.clamped_fec_event_cnt==3UL );
  fd_gui_event_closed_slot_wmark_advance( gui, 103UL );
  FD_TEST( fd_gui_fec_archive( gui, 512UL )==4UL );
  FD_TEST( count_ts( gui, FD_GUI_HIST_FEC_EVENT_ARCHIVE, ULONG_MAX )==6UL );

  struct { long a; long b; ulong cnt; } const q[] = {
    { ts-lag,      ts-lag,      1UL }, /* at the lag bound in the past */
    { ts+8L+lag,   ts+8L+lag,   1UL }, /* at the lag bound in the future */
    { 0L,          ts-lag-1L,   0UL }, /* skewed events are excluded */
    { ts,          ts+9L,       3UL }, /* 101/0 and both markers */
    { t+span+lag,  t+span+lag,  1UL }, /* latest time at a batch end */
    { t,           t+span+1L,   2UL },
    { t+(long)UINT_MAX+span, t+(long)UINT_MAX+span, 1UL }, /* admitted after a gap */
    { t+sec_ns( 30UL ), t+sec_ns( 30UL ), 1UL }, /* still staged */
    { 0L,          LONG_MAX-1L, 10UL },
  };
  for( ulong i=0UL; i<sizeof(q)/sizeof(q[ 0 ]); i++ ) {
    fd_gui_shred_event_iter_t it;
    fd_gui_fec_event_iter_begin( gui, &it, q[ i ].a, q[ i ].b+1L );
    ulong cnt = 0UL;
    while( fd_gui_shred_event_iter_next( &it ) ) {
      FD_TEST( it.event.event_time_ns>=q[ i ].a && it.event.event_time_ns<=q[ i ].b );
      cnt++;
    }
    fd_gui_shred_event_iter_end( &it );
    if( FD_UNLIKELY( cnt!=q[ i ].cnt ) ) FD_LOG_ERR(( "query %lu: got %lu events, expected %lu", i, cnt, q[ i ].cnt ));
  }

  /* Bounds cover every event, conservatively. */
  FD_TEST( fd_gui_event_bounds( gui, FD_GUI_HIST_FEC_EVENTS, &lo, &hi ) );
  FD_TEST( lo==ts-lag && hi>t+sec_ns( 30UL ) );

  void * http_mem = test_http_open( gui, FD_GUI_HTTP_MIN_SEND_BUFFER_SZ );
  FD_TEST( !fd_gui_printf_timeline_query_fec_events( gui, ts, ts+10L, 7UL ) );
  char expected[ 512 ];
  fd_cstr_printf_check( expected, sizeof(expected), NULL,
                        "{\"topic\":\"timeline\",\"key\":\"query_shreds\",\"id\":7,\"value\":{\"granularity\":\"fec\","
                        "\"available_start_ns\":\"%ld\",\"available_end_ns\":\"%ld\","
                        "\"reference_slot\":100,\"reference_ts\":\"%ld\",\"slot_delta\":[1,0,0],\"idx\":[0,null,null],"
                        "\"event\":[0,4,4],\"event_ts_delta\":[\"0\",\"9\",\"9\"],\"skipped\":[]}}", lo, hi, ts );
  check_response( gui, expected );
  test_http_close( gui, http_mem );
  FD_LOG_NOTICE(( "test_fec_events: staging, skew, archival and event-time lookup: ok" ));
}

/* test_fec_staging_pressure fills FEC staging to its quota.  With an
   open head nothing can be archived and new events are dropped.  Once
   the head closes, staging pressure archives the closed prefix instead
   of evicting it, so no events are lost. */

static void
test_fec_staging_pressure( fd_gui_t * gui ) {
  long  const ts  = sec_ns( 100UL );
  uchar const ev  = FD_GUI_SLOT_SHRED_SHRED_RECEIVED_TURBINE;
  ulong const cnt = FD_GUI_FEC_RECORD_MAX;
  fd_gui_event_closed_slot_wmark_advance( gui, 100UL );
  for( ulong i=0UL; i<cnt; i++ ) fd_gui_fec_event_append( gui, 100UL+i/65535UL, i%65535UL, ev, ts+(long)i, ts+(long)i );
  FD_TEST( !gui->shreds.dropped_fec_event_cnt );
  fd_gui_fec_event_append( gui, 200UL, 0UL, ev, ts+(long)cnt, ts+(long)cnt );
  FD_TEST( gui->shreds.dropped_fec_event_cnt==1UL );
  FD_TEST( !fd_gui_hist_evict_step( gui ) ); /* staging is never evicted */

  FD_TEST( count_ts( gui, FD_GUI_HIST_FEC_EVENTS, ULONG_MAX )==cnt );

  fd_gui_event_closed_slot_wmark_advance( gui, 200UL );
  for( ulong i=0UL; i<1024UL; i++ ) fd_gui_fec_event_append( gui, 200UL, i, ev, ts+(long)(cnt+i), ts+(long)(cnt+i) );
  FD_TEST( gui->shreds.dropped_fec_event_cnt==1UL );
  FD_TEST( count_ts( gui, FD_GUI_HIST_FEC_EVENT_ARCHIVE, ULONG_MAX ) );

  while( fd_gui_fec_archive( gui, 512UL ) ) {}
  FD_TEST( count_ts( gui, FD_GUI_HIST_FEC_EVENTS, ULONG_MAX )==cnt+1024UL );

  /* A narrow query reads only the batches admitted near its window. */
  long const a = ts+(long)(cnt/2UL);
  fd_gui_shred_event_iter_t it;
  fd_gui_fec_event_iter_begin( gui, &it, a, a+1L );
  FD_TEST( fd_gui_shred_event_iter_next( &it ) && it.event.event_time_ns==a );
  FD_TEST( !fd_gui_shred_event_iter_next( &it ) );
  fd_gui_shred_event_iter_end( &it );

  /* Staged queries only read admissions within the lag bound of their
     window.  Admissions at the bound are still found. */
  long const lag = FD_GUI_FEC_EVENT_LAG_MAX_NS;
  long const u   = ts+sec_ns( 100UL );
  fd_gui_fec_event_append( gui, 300UL, 0UL, ev, u-lag,  u    );
  fd_gui_fec_event_append( gui, 300UL, 1UL, ev, u+1L,   u+1L );
  fd_gui_fec_event_append( gui, 300UL, 2UL, ev, u+2L+lag, u+2L );
  fd_gui_fec_event_iter_begin( gui, &it, u-lag, u-lag+1L );
  FD_TEST( it._fec_iter.cur==it._fec_iter.end-3UL );
  FD_TEST( fd_gui_shred_event_iter_next( &it ) && it.event.idx==0U );
  FD_TEST( !fd_gui_shred_event_iter_next( &it ) );
  fd_gui_shred_event_iter_end( &it );
  fd_gui_fec_event_iter_begin( gui, &it, u+2L+lag, u+3L+lag );
  FD_TEST( it._fec_iter.cur==it._fec_iter.end-1UL );
  FD_TEST( fd_gui_shred_event_iter_next( &it ) && it.event.idx==2U );
  FD_TEST( !fd_gui_shred_event_iter_next( &it ) );
  fd_gui_shred_event_iter_end( &it );

  /* Windows disjoint from staged admissions skip staging. */
  fd_gui_fec_event_iter_begin( gui, &it, u+3L+2L*lag, LONG_MAX-1L );
  FD_TEST( it._fec_iter.cur==it._fec_iter.end );
  FD_TEST( !fd_gui_shred_event_iter_next( &it ) );
  fd_gui_shred_event_iter_end( &it );
  fd_gui_fec_event_iter_begin( gui, &it, 0L, ts-lag );
  FD_TEST( !fd_gui_shred_event_iter_next( &it ) );
  FD_TEST( !it._fec_iter.db );
  fd_gui_shred_event_iter_end( &it );
  FD_LOG_NOTICE(( "test_fec_staging_pressure: ok" ));
}

/* check_shreds runs a query_agg_shreds query and checks that the
   response ends with expected. */

static void
check_suffix( fd_gui_t *   gui,
              char const * expected );

static void
check_shreds( fd_gui_t *   gui,
              ulong        g,
              long         reference,
              ulong        cnt,
              char const * expected ) {
  FD_TEST( !fd_gui_printf_timeline_query_agg( gui, "query_agg_shreds", fd_gui_timeline_granularities[ g ].name, g, reference, cnt, 7UL ) );
  check_suffix( gui, expected );
}

static void
check_suffix( fd_gui_t *   gui,
              char const * expected ) {
  FD_TEST( !gui->http->stage_err );
  ulong len = fd_http_server_stage_len( gui->http );
  ulong off = gui->http->stage_off%gui->http->oring_sz;
  ulong n   = strlen( expected );
  FD_TEST( len>=n && off+len<=gui->http->oring_sz );
  if( FD_UNLIKELY( memcmp( gui->http->oring+off+len-n, expected, n ) ) ) {
    FD_LOG_WARNING(( "expected suffix: %s", expected ));
    FD_LOG_ERR(( "            got: %.*s", (int)len, (char const *)gui->http->oring+off ));
  }
  fd_http_server_stage_trunc( gui->http, 0UL );
}

static void
replay_duration( fd_gui_t * gui,
                 ulong      slot,
                 ulong      parent_slot,
                 ulong      bank_seq,
                 long       parent_ns,
                 long       completed_ns ) {
  if( parent_slot!=ULONG_MAX ) {
    fd_gui_slot_t * parent = fd_gui_slot_get_or_create( gui, parent_slot, ULONG_MAX, BANK_SEQ, ULONG_MAX );
    FD_TEST( parent );
    parent->completed_time = parent_ns;
  }
  fd_replay_slot_completed_t completed = { .slot=slot, .bank_seq=bank_seq, .parent_slot=parent_slot, .parent_bank_seq=BANK_SEQ,
    .completion_time_nanos=completed_ns, .identity_balance=ULONG_MAX };
  fd_gui_handle_replay_update( gui, &completed, fd_long_max( completed_ns, 0L )+sec_ns( 1UL ) );
  fd_http_server_stage_trunc( gui->http, 0UL );
}

/* test_timeline_agg_shreds tests query_agg_shreds: the FEC completion
   counts and the slot duration. */

static void
test_timeline_agg_shreds( fd_gui_t * gui ) {
  void * http_mem = test_http_open( gui, FD_GUI_HTTP_MIN_SEND_BUFFER_SZ );
  gui->summary.slot_caught_up = ULONG_MAX;
  /* Keep canonical lookups on the rooted path.  If not, the invalid
     ancestry cases below (parent_slot>=slot) cause an infinite loop in
     the fork walk. */
  gui->summary.slot_rooted    = 1000000UL;
  for( ulong i=0UL; i<FD_GUI_TURBINE_SLOT_HISTORY_SZ; i++ ) gui->summary.slots_max_turbine[ i ].slot = ULONG_MAX;

  /* The FEC handler ignores invalid slots, times and counts, and creates
     no day for them.  Each valid completion counts, also two
     completions with identical fields. */
  long  ts  = sec_ns( 50UL );
  ulong max = 2UL*FD_FEC_SHRED_CNT;
  fd_gui_timeline_handle_fec( gui, ULONG_MAX, 0, ts,       32UL,    0UL,     0UL,     ts );
  fd_gui_timeline_handle_fec( gui, 100UL,     0, -1L,      32UL,    0UL,     0UL,     ts );
  fd_gui_timeline_handle_fec( gui, 100UL,     0, LONG_MAX, 32UL,    0UL,     0UL,     ts );
  fd_gui_timeline_handle_fec( gui, 100UL,     0, ts,       max+1UL, 0UL,     0UL,     ts );
  fd_gui_timeline_handle_fec( gui, 100UL,     0, ts,       0UL,     max+1UL, 0UL,     ts );
  fd_gui_timeline_handle_fec( gui, 100UL,     0, ts,       0UL,     0UL,     max+1UL, ts );
  FD_TEST( !fd_gui_timeline_day_get( gui, 0UL ) );
  fd_gui_timeline_handle_fec( gui, 100UL, 1, ts,                  32UL, 16UL, 8UL, ts );
  fd_gui_timeline_handle_fec( gui, 100UL, 1, ts,                  32UL, 16UL, 8UL, ts );
  fd_gui_timeline_handle_fec( gui, 101UL, 0, ts+1L,               20UL,  4UL, 2UL, ts );
  fd_gui_timeline_handle_fec( gui, 102UL, 0, ts+sec_ns( 1UL )/3L,  7UL,  1UL, 1UL, ts );
  check_shreds( gui, 3UL, ts, 3UL, "\"turbine\":[84,7,null],\"repair\":[36,1,null],\"reconstructed\":[18,1,null],"
                                   "\"published\":[128,0,null],\"slot_duration\":[null,null,null]}}" );

  /* A block advances four slots in 1.6s, so each bucket it overlaps
     shows 400ms for each slot, at each granularity.  An exact duplicate
     and a different fork also count.  Buckets before the parent
     completion and after the block completion stay null. */
  ts = sec_ns( 100UL );
  replay_duration( gui, 104UL, 100UL, BANK_SEQ,     ts, ts+1600000000L );
  replay_duration( gui, 104UL, 100UL, BANK_SEQ,     ts, ts+1600000000L );
  replay_duration( gui, 104UL, 100UL, BANK_SEQ+1UL, ts, ts+1600000000L );
  check_shreds( gui, 3UL, ts-250000000L, 9UL, "\"slot_duration\":[null,400000000,400000000,400000000,400000000,400000000,400000000,400000000,null]}}" );
  for( ulong g=0UL; g<FD_GUI_TIMELINE_GRANULARITY_CNT; g++ ) {
    int stored; ulong merge_cnt;
    if( fd_gui_timeline_tier( "query_agg_shreds", g, &stored, &merge_cnt ) ) continue; /* less than the minimum granularity */
    ulong ns = fd_gui_timeline_granularity_ns( g );
    check_shreds( gui, g, (long)((ulong)ts/ns*ns), 1UL, "\"slot_duration\":[400000000]}}" );
  }

  /* These cases must not credit a bucket: a missing or invalid parent
     time, a missing or invalid completion time, a gap that is not
     positive, and invalid ancestry. */
  ts = sec_ns( 1000UL );
  long end = ts+sec_ns( 2UL );
  replay_duration( gui, 1008UL, ULONG_MAX, BANK_SEQ, LONG_MAX, end );
  replay_duration( gui, 1008UL, 1007UL,    BANK_SEQ, LONG_MAX, end );
  replay_duration( gui, 1008UL, 1007UL,    BANK_SEQ, -1L,      end );
  replay_duration( gui, 1008UL, 1007UL,    BANK_SEQ, ts,       LONG_MAX );
  replay_duration( gui, 1008UL, 1007UL,    BANK_SEQ, ts,       -1L );
  replay_duration( gui, 1008UL, 1007UL,    BANK_SEQ, ts,       ts );
  replay_duration( gui, 1008UL, 1007UL,    BANK_SEQ, ts,       ts-1L );
  replay_duration( gui, 1008UL, 1008UL,    BANK_SEQ, ts,       end );
  replay_duration( gui, 1008UL, 1009UL,    BANK_SEQ, ts,       end );
  check_shreds( gui, 3UL, ts, 8UL, "\"slot_duration\":[null,null,null,null,null,null,null,null]}}" );

  /* A run of skipped slots shows the time for each slot, with no gaps.
     A block that advances more than gui->max_consecutive_skips slots
     gets credit for only gui->max_consecutive_skips slots.  Both
     cases also use the 64-bit overflow shift. */
  ts = sec_ns( 1760UL );
  replay_duration( gui, 300UL, 200UL, BANK_SEQ, ts, ts+sec_ns( 40UL ) );
  check_shreds( gui, 8UL, ts, 5UL, "\"slot_duration\":[400000000,400000000,400000000,400000000,400000000]}}" );
  ts = sec_ns( 10000UL );
  replay_duration( gui, 5000UL, 5000UL-2UL*gui->max_consecutive_skips, BANK_SEQ, ts, ts+sec_ns( gui->max_consecutive_skips ) );
  check_shreds( gui, 6UL, ts, 2UL, "\"slot_duration\":[1000000000,1000000000]}}" );

  /* Overlapping intervals combine by slots advanced.  The result is a
     ratio of sums, not a time-weighted mean.  This is also true across
     merged stored buckets. */
  ts = sec_ns( 6000UL );
  replay_duration( gui, 401UL, 400UL, BANK_SEQ, ts,              ts+125000000L );
  replay_duration( gui, 402UL, 401UL, BANK_SEQ, ts+125000000L,   ts+1125000000L );
  check_shreds( gui, 3UL, ts, 6UL, "\"slot_duration\":[222222222,1000000000,1000000000,1000000000,1000000000,null]}}" );
  check_shreds( gui, 4UL, ts, 3UL, "\"slot_duration\":[363636364,1000000000,1000000000]}}" );

  /* The code splits an interval that crosses midnight across the two
     day records. */
  ts = FD_GUI_TIMELINE_DAY_NS;
  replay_duration( gui, 601UL, 600UL, BANK_SEQ, ts-200000000L, ts+200000000L );
  FD_TEST( fd_gui_timeline_day_get( gui, 0UL ) && fd_gui_timeline_day_get( gui, 1UL ) );
  check_shreds( gui, 3UL,  ts-250000000L, 2UL, "\"slot_duration\":[400000000,400000000]}}" );
  check_shreds( gui, 22UL, ts,            1UL, "\"slot_duration\":[400000000]}}" );

  test_http_close( gui, http_mem );
  FD_LOG_NOTICE(( "test_timeline_agg_shreds: ok" ));
}

/* test_votes covers the Votes track: votes reach the raw ring, our
   casts / acks and votor_out certs / ParentReady become markers (first
   per slot), malformed and stale records are counted, query_votes
   merges both by time, and a newly missed vote lands in
   query_agg_votes. */

static void
timeline_setup( fd_gui_t * gui,
                ulong      epoch_cnt ) {
  FD_TEST( fd_epoch_schedule_derive( &gui->epoch.epoch_schedule, 1024UL, 1024UL, 0 ) );
  gui->epoch.has_epoch_schedule = 1;
  gui->epoch.current_epoch      = epoch_cnt-1UL;
  gui->summary.slot_rooted      = ULONG_MAX;
  for( ulong e=0UL; e<epoch_cnt; e++ ) put_epoch( gui, e, e*1024UL, 1024UL );
}

/* put_block creates a replayed block of slot on top of parent
   (ULONG_MAX for none, or a slot with no record). */

static fd_gui_slot_t *
put_block( fd_gui_t * gui,
           ulong      slot,
           ulong      parent,
           long       completed ) {
  fd_gui_slot_t const * p = parent==ULONG_MAX ? NULL : fd_gui_slot_get( gui, parent, BANK_SEQ );
  long parent_completed = p ? p->completed_time : LONG_MAX;
  put_slot( gui, slot, completed );
  fd_gui_slot_t * c = fd_gui_slot_get( gui, slot, BANK_SEQ );
  c->parent_slot           = parent;
  c->parent_bank_seq       = parent==ULONG_MAX ? ULONG_MAX : BANK_SEQ;
  c->parent_completed_time = parent_completed;
  return c;
}

/* Boot, catch-up and epoch-start events. */

static void
test_timeline_lifecycle_events( fd_gui_t * gui ) {
  void * http_mem = test_http_open( gui, FD_GUI_HTTP_MIN_SEND_BUFFER_SZ );
  long const ts = sec_ns( 10UL );
  timeline_setup( gui, 2UL ); /* epochs 0 [0,1024) and 1 [1024,2048) */
  gui->summary.startup_time_nanos = ts-sec_ns( 5UL );
  fd_gui_timeline_query_event_t events[ 8 ];
  ulong cnt;

  /* Nothing before a snapshot is known or anything is rooted. */
  for( ulong i=0UL; i<FD_GUI_BOOT_PROGRESS_SNAPSHOT_CNT; i++ ) gui->summary.boot_progress.loading_snapshot[ i ].slot = ULONG_MAX;
  FD_TEST( !fd_gui_timeline_events_collect( gui, 0L, LONG_MAX-1L, events, 8UL, &cnt ) && !cnt );

  /* Boot is at the snapshot slot, at process start, as soon as the
     snapshot is known; the incremental wins over the full. */
  gui->summary.boot_progress.loading_snapshot[ FD_GUI_BOOT_PROGRESS_FULL_SNAPSHOT_IDX ].slot = 900UL;
  FD_TEST( !fd_gui_timeline_events_collect( gui, 0L, LONG_MAX-1L, events, 8UL, &cnt ) && cnt==1UL );
  FD_TEST( events[ 0 ].event==FD_GUI_TIMELINE_EVENT_BOOT && events[ 0 ].slot==900UL && events[ 0 ].ts==ts-sec_ns( 5UL ) );
  gui->summary.boot_progress.loading_snapshot[ FD_GUI_BOOT_PROGRESS_INCREMENTAL_SNAPSHOT_IDX ].slot = 1020UL;
  FD_TEST( !fd_gui_timeline_events_collect( gui, 0L, LONG_MAX-1L, events, 8UL, &cnt ) && cnt==1UL && events[ 0 ].slot==1020UL );

  /* Root 1020 -> 1023 -> 1026.  1021 and 1022 are skipped and split the
     1020 -> 1023 gap, so catch-up (1021) is at the gap start.  1024,
     the first slot of epoch 1, gets the first third of 1023 -> 1026. */
  put_block( gui, 1020UL, ULONG_MAX, ts );
  put_block( gui, 1023UL, 1020UL, ts+300L );
  fd_gui_handle_root_advanced( gui, 1023UL, BANK_SEQ, ts+300L );
  FD_TEST( !fd_gui_timeline_events_collect( gui, 0L, LONG_MAX-1L, events, 8UL, &cnt ) && cnt==2UL );
  FD_TEST( events[ 0 ].event==FD_GUI_TIMELINE_EVENT_BOOT );
  FD_TEST( events[ 1 ].event==FD_GUI_TIMELINE_EVENT_CATCH_UP && events[ 1 ].slot==1021UL && events[ 1 ].ts==ts );
  put_block( gui, 1026UL, 1023UL, ts+600L );
  fd_gui_handle_root_advanced( gui, 1026UL, BANK_SEQ, ts+600L );
  FD_TEST( !fd_gui_timeline_events_collect( gui, 0L, LONG_MAX-1L, events, 8UL, &cnt ) && cnt==3UL );
  FD_TEST( events[ 2 ].event==FD_GUI_TIMELINE_EVENT_EPOCH_START && events[ 2 ].slot==1024UL && events[ 2 ].ts==ts+300L );
  /* Epoch 0 started before the snapshot, so it has no event. */

  /* Events are owned by the window containing their timestamp. */
  FD_TEST( !fd_gui_timeline_events_collect( gui, ts, ts+300L, events, 8UL, &cnt ) && cnt==1UL && events[ 0 ].event==FD_GUI_TIMELINE_EVENT_CATCH_UP );
  FD_TEST( !fd_gui_timeline_events_collect( gui, ts+300L, ts+301L, events, 8UL, &cnt ) && cnt==1UL && events[ 0 ].event==FD_GUI_TIMELINE_EVENT_EPOCH_START );
  FD_TEST( fd_gui_timeline_events_collect( gui, 0L, LONG_MAX-1L, events, 2UL, &cnt )==1 );

  FD_TEST( !fd_gui_printf_timeline_query_events( gui, 0L, LONG_MAX-1L, 3UL ) );
  char want[ 256 ];
  FD_TEST( fd_cstr_printf_check( want, sizeof(want), NULL,
           "\"event\":[6,7,5],\"slot\":[1020,1021,1024],\"ts\":[\"%ld\",\"%ld\",\"%ld\"],"
           "\"identity_result\":[],\"identity_from\":[],\"identity_to\":[],\"identity_notes\":[]}}",
           ts-sec_ns( 5UL ), ts, ts+300L ) );
  check_suffix( gui, want );

  test_http_close( gui, http_mem );
  FD_LOG_NOTICE(( "test_timeline_lifecycle_events: boot, catch-up and epoch-start events: ok" ));
}

static void
test_timeline_root( fd_gui_t * gui ) {
  void * http_mem = test_http_open( gui, FD_GUI_HTTP_MIN_SEND_BUFFER_SZ );
  long const ts = sec_ns( 10UL );
  timeline_setup( gui, 1UL );

  /* Rooting 100 -> 103 records 103's observed interval, and splits the
     gap evenly between 101 and 102, which never replayed. */
  put_block( gui, 100UL, ULONG_MAX, ts );
  fd_gui_shred_event_append( gui, 103UL, 0UL, FD_GUI_SLOT_SHRED_SHRED_PUBLISHED, ts+200L, ts );
  put_block( gui, 103UL, 100UL, ts+300L )->mine = 1;
  fd_gui_handle_root_advanced( gui, 103UL, BANK_SEQ, ts+300L );
  fd_gui_timeline_query_slot_t rows[ 4 ];
  ulong cnt;
  FD_TEST( !fd_gui_timeline_slots_collect( gui, ts, ts+300L, rows, 4UL, &cnt ) && cnt==3UL );
  for( ulong i=0UL; i<3UL; i++ ) {
    FD_TEST( rows[ i ].slot==101UL+i && rows[ i ].start_ns==ts+100L*(long)i && rows[ i ].end_ns==ts+100L*(long)(i+1UL) );
    FD_TEST( rows[ i ].skipped==(i<2UL) && rows[ i ].mine==(i==2UL) );
  }
  FD_TEST( fd_gui_timeline_slots_collect( gui, ts, ts+300L, rows, 2UL, &cnt )==1 );
  /* The next root counts only its own skips (104, 105).  A bucket
     with a day record but no skips reads 0; one without reads null. */
  put_block( gui, 106UL, 103UL, ts+sec_ns( 1UL )+300L );
  fd_gui_handle_root_advanced( gui, 106UL, BANK_SEQ, ts+sec_ns( 1UL ) );
  FD_TEST( !fd_gui_printf_timeline_query_agg( gui, "query_agg_slots", "250ms", 3UL, ts, 4UL, 7UL ) );
  check_suffix( gui, "\"skipped\":[3,0,1,0],\"mine\":[0,0,0,0],\"mine_skipped\":[0,0,0,0]}}" );
  FD_TEST( !fd_gui_printf_timeline_query_agg( gui, "query_agg_slots", "1d", 22UL, FD_GUI_TIMELINE_DAY_NS, 1UL, 7UL ) );
  check_suffix( gui, "\"skipped\":[null],\"mine\":[null],\"mine_skipped\":[null]}}" );

  /* Our block for 107 replays twice but counts once in mine.  Rooting
     108 on 106 skips it, so it also counts in mine_skipped at its
     completion, at both a stored and a rolled-up granularity. */
  fd_gui_epoch( gui, 0UL )->pub_cnt = 1UL; /* every slot is scheduled to our (zero) identity */
  gui->summary.slot_caught_up = ULONG_MAX;
  for( ulong i=0UL; i<FD_GUI_TURBINE_SLOT_HISTORY_SZ; i++ ) gui->summary.slots_max_turbine[ i ].slot = ULONG_MAX;
  replay_duration( gui, 107UL, 106UL, BANK_SEQ+1UL, ts+sec_ns( 1UL )+300L, ts+sec_ns( 2UL ) );
  replay_duration( gui, 107UL, 106UL, BANK_SEQ+1UL, ts+sec_ns( 1UL )+300L, ts+sec_ns( 2UL ) );
  put_block( gui, 108UL, 106UL, ts+sec_ns( 3UL ) );
  fd_gui_handle_root_advanced( gui, 108UL, BANK_SEQ, ts+sec_ns( 3UL ) );
  FD_TEST( !fd_gui_printf_timeline_query_agg( gui, "query_agg_slots", "250ms", 3UL, ts+sec_ns( 2UL ), 1UL, 7UL ) );
  check_suffix( gui, "\"mine\":[1],\"mine_skipped\":[1]}}" );
  FD_TEST( !fd_gui_printf_timeline_query_agg( gui, "query_agg_slots", "1s", 5UL, ts+sec_ns( 2UL ), 1UL, 7UL ) );
  check_suffix( gui, "\"mine\":[1],\"mine_skipped\":[1]}}" );

  test_http_close( gui, http_mem );
  FD_LOG_NOTICE(( "test_timeline_root: ok" ));
}

static void
test_timeline_slot_intervals( fd_gui_t * gui ) {
  void * http_mem = test_http_open( gui, FD_GUI_HTTP_MIN_SEND_BUFFER_SZ );
  long ts  = sec_ns( 10UL );
  long now = ts+1000L;
  timeline_setup( gui, 2UL );

  /* A repair request is not receipt.  Index zero need not arrive first,
     and the earlier producer timestamp can reach the GUI later. */
  fd_gui_handle_repair_request( gui, 1022UL, 0UL, ts+1L, now );
  fd_gui_handle_shred( gui, 1022UL, 7UL, 0UL, 1, ts+60L, now );
  fd_gui_handle_shred( gui, 1022UL, 9UL, 0UL, 0, ts+50L, now );
  fd_gui_handle_shred( gui, 1022UL, 0UL, 0UL, 1, ts+70L, now );
  fd_gui_handle_shred( gui, 1023UL, 3UL, 0UL, 0, ts+20L, now );
  fd_gui_handle_leader_fec( gui, 1024UL, 32UL, 0, ts+250L, now );
  fd_gui_handle_leader_fec( gui, 1024UL, 32UL, 1, ts+280L, now );
  fd_gui_handle_repair_request( gui, 1025UL, 0UL, ts+2L, now );
  fd_gui_handle_shred( gui, 1026UL, 0UL, 0UL, 1, ts+700L, now ); /* start after completion */
  fd_gui_handle_shred( gui, 1028UL, 0UL, 0UL, 1, ts+610L, now );

  ulong slots[]   = { 1021UL, 1022UL, 1023UL, 1024UL, 1025UL, 1026UL, 1028UL, 1029UL };
  long complete[] = { 10L, 200L, 300L, 400L, 500L, 600L, 800L, 900L };
  for( ulong i=0UL; i<8UL; i++ ) {
    fd_gui_slot_t * slot = put_block( gui, slots[ i ], i ? slots[ i-1UL ] : ULONG_MAX, ts+complete[ i ] );
    slot->mine           = slots[ i ]==1024UL;
    slot->shred_cnt      = (uint)(32UL*(i+1UL));
  }
  /* A closed slot cannot have its start revised by late traffic. */
  fd_gui_event_closed_slot_wmark_advance( gui, 1023UL );
  fd_gui_handle_shred( gui, 1022UL, 10UL, 0UL, 1, ts+5L, now );

  /* Arrival timestamps survive raw event eviction before classification. */
  fd_gui_shred_flush( gui, ts+sec_ns( 1UL ) );
  ulong budget = ULONG_MAX;
  int drained;
  FD_TEST( !fd_gui_store_ts_evict( gui->db, FD_GUI_HIST_SHRED_EVENTS, ULONG_MAX, &budget, &drained ) );
  fd_gui_handle_root_advanced( gui, 1029UL, BANK_SEQ, now );

  FD_TEST( !fd_gui_printf_timeline_query_slots( gui, ts+100L, ts+150L, 7UL ) );
  check_suffix( gui, "{\"available_start_ns\":\"10000000020\",\"available_end_ns\":\"10000000800\",\"reference_slot\":1022,"
                     "\"reference_ts\":\"10000000020\",\"slot_delta\":[0,1],\"start_ts_delta\":[\"30\",\"0\"],"
                     "\"end_ts_delta\":[\"180\",\"280\"],\"shred_cnt\":[64,96],\"skipped\":[],\"mine\":[],"
                     "\"txn_fees\":[\"0\",\"0\"],\"prio_fees\":[\"0\",\"0\"],\"tips\":[\"0\",\"0\"]}}" );

  fd_gui_timeline_query_slot_t rows[ 8 ];
  ulong cnt;
  FD_TEST( !fd_gui_timeline_slots_collect( gui, ts, now, rows, 8UL, &cnt ) && cnt==5UL );
  FD_TEST( rows[ 2 ].slot==1024UL && rows[ 2 ].mine && rows[ 2 ].start_ns==ts+250L && rows[ 2 ].end_ns==ts+400L );
  FD_TEST( rows[ 3 ].slot==1027UL && rows[ 3 ].skipped && rows[ 3 ].start_ns==ts+600L && rows[ 3 ].end_ns==ts+700L );
  FD_TEST( rows[ 4 ].slot==1028UL && !rows[ 4 ].skipped && rows[ 4 ].start_ns==ts+610L && rows[ 4 ].end_ns==ts+800L );
  FD_TEST( rows[ 2 ].shred_cnt==128U && rows[ 3 ].shred_cnt==UINT_MAX && rows[ 4 ].shred_cnt==224U );
  FD_TEST( !fd_gui_timeline_slots_collect( gui, ts+200L, ts+250L, rows, 8UL, &cnt ) && cnt==1UL && rows[ 0 ].slot==1023UL );
  FD_TEST( !fd_gui_timeline_slots_collect( gui, ts+400L, ts+600L, rows, 8UL, &cnt ) && !cnt );

  test_http_close( gui, http_mem );
  FD_LOG_NOTICE(( "test_timeline_slot_intervals: overlapping arrivals, leader publication, skipped slots, missing starts, eviction: ok" ));
}

static void
test_timeline_replayed_skips( fd_gui_t * gui ) {
  void * http_mem = test_http_open( gui, FD_GUI_HTTP_MIN_SEND_BUFFER_SZ );
  long ts  = sec_ns( 10UL );
  long now = ts+1000L;
  timeline_setup( gui, 1UL );
  fd_gui_epoch_t * epoch = fd_gui_epoch( gui, 0UL );
  epoch->pub_cnt = 1UL; /* every slot is scheduled to our (zero) identity */

  /* Root 100 -> 105.  101 replayed on two losing forks; 102 replayed
     but never completed; 103 and 104 never replayed. */
  fd_gui_handle_shred( gui, 101UL, 0UL, 0UL, 1, ts+150L, now );
  put_slot( gui, 101UL, ts+450L );
  fd_gui_slot_get( gui, 101UL, BANK_SEQ )->shred_cnt = 64U;
  fd_gui_hist_slot_key_t key = { .slot=101UL, .bank_seq=BANK_SEQ+1UL };
  fd_gui_slot_t * fork = fd_gui_hist_kv_get_or_create( gui, FD_GUI_HIST_SLOT, &key );
  memset( fork, 0, sizeof(*fork) );
  fork->slot           = 101UL;
  fork->bank_seq       = BANK_SEQ+1UL;
  fork->completed_time = ts+400L;
  fork->shred_cnt      = 96U;
  put_slot( gui, 102UL, LONG_MAX );
  fd_gui_handle_shred( gui, 105UL, 0UL, 0UL, 1, ts+500L, now );
  put_block( gui, 100UL, ULONG_MAX, ts+100L );
  put_block( gui, 105UL, 100UL, ts+600L )->shred_cnt = 128U;
  fd_gui_handle_root_advanced( gui, 105UL, BANK_SEQ, now );

  /* 101 uses its earliest fork completion and that fork's shred count.
     The rest of the skips share the gap; 105 landed. */
  fd_gui_timeline_query_slot_t rows[ 8 ];
  ulong cnt;
  FD_TEST( !fd_gui_timeline_slots_collect( gui, ts, now, rows, 8UL, &cnt ) && cnt==5UL );
  FD_TEST( rows[ 0 ].slot==101UL && rows[ 0 ].skipped && rows[ 0 ].mine && rows[ 0 ].start_ns==ts+150L && rows[ 0 ].end_ns==ts+400L && rows[ 0 ].shred_cnt==96U );
  for( ulong i=1UL; i<4UL; i++ ) {
    FD_TEST( rows[ i ].slot==101UL+i && rows[ i ].skipped && !rows[ i ].mine && rows[ i ].shred_cnt==UINT_MAX );
    FD_TEST( rows[ i ].start_ns==ts+100L+100L*(long)i && rows[ i ].end_ns==ts+200L+100L*(long)i );
  }
  FD_TEST( rows[ 4 ].slot==105UL && !rows[ 4 ].skipped && rows[ 4 ].start_ns==ts+500L && rows[ 4 ].end_ns==ts+600L && rows[ 4 ].shred_cnt==128U );

  /* Only our completed skipped block counts in mine_skipped.  Each
     skipped slot is a leader_skip event at its midpoint. */
  fd_gui_timeline_day_t const * day = fd_gui_timeline_day_get( gui, 0UL );
  FD_TEST( fd_gui_timeline_field_get( day, FD_GUI_TIMELINE_GRANULARITY_250MS, FD_GUI_TIMELINE_FIELD_MINE_SKIPPED, 40UL )==1UL );
  fd_gui_timeline_query_event_t events[ 8 ];
  FD_TEST( !fd_gui_timeline_events_collect( gui, ts, now, events, 8UL, &cnt ) && cnt==4UL );
  FD_TEST( events[ 0 ].slot==101UL && events[ 0 ].ts==ts+275L && events[ 0 ].event==FD_GUI_TIMELINE_EVENT_LEADER_SKIP );
  FD_TEST( fd_gui_timeline_events_collect( gui, ts, now, events, 3UL, &cnt )==1 );

  /* Rooted slots are final: a completion after rooting changes nothing. */
  put_slot( gui, 103UL, ts+50L );
  FD_TEST( !fd_gui_timeline_slots_collect( gui, ts, now, rows, 8UL, &cnt ) && cnt==5UL && rows[ 2 ].end_ns==ts+400L );

  /* Identity commands are events too, by slot then time among the
     skips, at the replay frontier.  One before the first replayed slot
     is at the first slot after the snapshot. */
  fd_admin_gui_event_t ev = { .kind=FD_ADMIN_GUI_EVENT_IDENTITY_TAKEOVER };
  fd_memset( ev.from, 0x01, 32UL );
  fd_memset( ev.to,   0x02, 32UL );
  strcpy( ev.result, "holder_live" );
  strcpy( ev.notes,  "This was the first attempt of a takeover: the promoted node asked the demoted node to hand over the staked identity." );
  ev.ts_ns = ts+700L;
  gui->summary.slot_estimated = 102UL;
  fd_gui_handle_identity_event( gui, &ev );
  fd_admin_gui_event_t ev2 = { .kind=FD_ADMIN_GUI_EVENT_IDENTITY_SET, .ts_ns=ts+800L };
  strcpy( ev2.result, "success" );
  ev2.notes[ 0 ] = '\0'; /* a plain success: just the stake change */
  fd_memset( ev2.to, 0x03, 32UL );
  fd_gui_epoch_t * stake_epoch = fd_gui_current_epoch( gui );
  FD_TEST( stake_epoch );
  ulong stakes_cnt0 = stake_epoch->stakes_cnt;
  stake_epoch->stakes_cnt = 2UL;
  fd_memset( stake_epoch->stakes[ 0 ].id_key.uc, 0x00, 32UL ); stake_epoch->stakes[ 0 ].stake = 1000000000000000UL;
  fd_memset( stake_epoch->stakes[ 1 ].id_key.uc, 0x00, 32UL ); stake_epoch->stakes[ 1 ].stake =  300000000000000UL;
  gui->summary.slot_estimated = ULONG_MAX;
  fd_gui_handle_identity_event( gui, &ev2 );
  FD_TEST( !strcmp( gui->identity_events.event[ 1 ].notes, "1.3M Sol Stake -> 0 Sol Stake" ) );
  /* A forced success keeps its notes, followed by the stake change.
     Notes too long to fit are cut, the stake change never is.  A
     failure keeps its notes unchanged (event 0). */
  {
    fd_admin_gui_event_t fe = ev2;
    strcpy( fe.notes, "It went ahead only because of --force: the demoted node still looked alive." );
    fd_gui_handle_identity_event( gui, &fe );
    FD_TEST( !strcmp( gui->identity_events.event[ 2 ].notes,
                      "It went ahead only because of --force: the demoted node still looked alive. 1.3M Sol Stake -> 0 Sol Stake" ) );
    fd_memset( fe.notes, 'x', FD_ADMIN_GUI_NOTES_MAX-1UL ); fe.notes[ FD_ADMIN_GUI_NOTES_MAX-1UL ] = '\0';
    fd_gui_handle_identity_event( gui, &fe );
    char const * n = gui->identity_events.event[ 3 ].notes;
    ulong nl = strlen( n );
    char const * tail = " 1.3M Sol Stake -> 0 Sol Stake";
    FD_TEST( nl==FD_ADMIN_GUI_NOTES_MAX-1UL && !strcmp( n+nl-strlen( tail ), tail ) && n[ 0 ]=='x' );
    gui->identity_events.cnt = 2UL;
  }
  stake_epoch->stakes_cnt = stakes_cnt0;
  FD_TEST( !strcmp( gui->identity_events.event[ 0 ].notes, "This was the first attempt of a takeover: the promoted node asked the demoted node to hand over the staked identity." ) );
  fd_admin_gui_event_t bad = { .kind=FD_GUI_TIMELINE_EVENT_CNT, .ts_ns=ts+900L };
  fd_gui_handle_identity_event( gui, &bad );
  FD_TEST( gui->identity_events.cnt==2UL );
  gui->summary.boot_progress.loading_snapshot[ FD_GUI_BOOT_PROGRESS_FULL_SNAPSHOT_IDX        ].slot = ULONG_MAX;
  gui->summary.boot_progress.loading_snapshot[ FD_GUI_BOOT_PROGRESS_INCREMENTAL_SNAPSHOT_IDX ].slot = ULONG_MAX;
  FD_TEST( !fd_gui_timeline_events_collect( gui, ts, now, events, 8UL, &cnt ) && cnt==6UL );
  FD_TEST( events[ 0 ].slot==0UL && events[ 0 ].event==FD_GUI_TIMELINE_EVENT_IDENTITY_SET ); /* no snapshot known yet */
  gui->summary.boot_progress.loading_snapshot[ FD_GUI_BOOT_PROGRESS_FULL_SNAPSHOT_IDX        ].slot = 90UL;
  FD_TEST( !fd_gui_timeline_events_collect( gui, ts, now, events, 8UL, &cnt ) && cnt==6UL );
  FD_TEST( events[ 0 ].slot==91UL && events[ 0 ].event==FD_GUI_TIMELINE_EVENT_IDENTITY_SET ); /* after the full snapshot */
  /* After the incremental snapshot at 104, rooted 105 is also the
     catch-up slot, stamped at its start.  Boot is at process start,
     outside this window. */
  gui->summary.boot_progress.loading_snapshot[ FD_GUI_BOOT_PROGRESS_INCREMENTAL_SNAPSHOT_IDX ].slot = 104UL;
  FD_TEST( !fd_gui_timeline_events_collect( gui, ts, now, events, 8UL, &cnt ) && cnt==7UL );
  FD_TEST( events[ 1 ].slot==102UL && events[ 1 ].event==FD_GUI_TIMELINE_EVENT_LEADER_SKIP );
  FD_TEST( events[ 2 ].slot==102UL && events[ 2 ].ts==ts+700L && events[ 2 ].event==FD_GUI_TIMELINE_EVENT_IDENTITY_TAKEOVER && events[ 2 ].identity==0UL );
  FD_TEST( events[ 5 ].slot==105UL && events[ 5 ].ts==ts+500L && events[ 5 ].event==FD_GUI_TIMELINE_EVENT_CATCH_UP );
  FD_TEST( events[ 6 ].slot==105UL && events[ 6 ].event==FD_GUI_TIMELINE_EVENT_IDENTITY_SET );
  FD_TEST( fd_gui_timeline_events_collect( gui, ts, now, events, 5UL, &cnt )==1 );
  FD_TEST( !fd_gui_timeline_events_collect( gui, ts+750L, now, events, 8UL, &cnt ) && cnt==1UL && events[ 0 ].event==FD_GUI_TIMELINE_EVENT_IDENTITY_SET );

  FD_TEST( !fd_gui_printf_timeline_query_events( gui, ts+650L, now, 3UL ) );
  char from[ FD_BASE58_ENCODED_32_SZ ]; fd_base58_encode_32( ev.from, NULL, from );
  char to  [ FD_BASE58_ENCODED_32_SZ ]; fd_base58_encode_32( ev.to,   NULL, to   );
  char to2 [ FD_BASE58_ENCODED_32_SZ ]; fd_base58_encode_32( ev2.to,  NULL, to2  );
  char want[ 512 ];
  FD_TEST( fd_cstr_printf_check( want, sizeof(want), NULL,
           "\"event\":[3,1],\"slot\":[102,105],\"ts\":[\"%ld\",\"%ld\"],"
           "\"identity_result\":[\"holder_live\",\"success\"],\"identity_from\":[\"%s\",\"%s\"],\"identity_to\":[\"%s\",\"%s\"],"
           "\"identity_notes\":[\"This was the first attempt of a takeover: the promoted node asked the demoted node to hand over the staked identity.\",\"1.3M Sol Stake -> 0 Sol Stake\"]}}",
           ts+700L, ts+800L, from, "11111111111111111111111111111111", to, to2 ) );
  ulong len = fd_http_server_stage_len( gui->http );
  char const * got = (char const *)gui->http->oring+gui->http->stage_off%gui->http->oring_sz;
  ulong want_len = strlen( want );
  if( FD_UNLIKELY( len<want_len || memcmp( got+len-want_len, want, want_len ) ) ) FD_LOG_ERR(( "got: %.*s", (int)len, got ));
  fd_http_server_stage_trunc( gui->http, 0UL );

  /* The ring keeps the last FD_GUI_IDENTITY_EVENT_MAX. */
  for( ulong i=0UL; i<FD_GUI_IDENTITY_EVENT_MAX; i++ ) { ev2.ts_ns = ts+1000L+(long)i; fd_gui_handle_identity_event( gui, &ev2 ); }
  FD_TEST( !fd_gui_timeline_events_collect( gui, ts+650L, ts+1000L, events, 8UL, &cnt ) && cnt==0UL );
  gui->identity_events.cnt = 0UL;

  test_http_close( gui, http_mem );
  FD_LOG_NOTICE(( "test_timeline_replayed_skips: ok" ));
}

static fd_votor_gui_rec_t
vote_rec( uchar kind, uchar sub, ulong slot, long ts, ulong stake ) {
  return (fd_votor_gui_rec_t){ .slot=slot, .ts_ns=ts, .stake=stake, .total_stake=10000UL, .rank=7, .kind=kind, .sub=sub };
}

static void
test_votes( fd_gui_t * gui ) {
  long base = 3L*FD_GUI_TIMELINE_DAY_NS;
  long now  = base + 500000000L; /* within FD_GUI_TIMELINE_SCAN_MARGIN_NS of the votes */
  fd_votor_gui_rec_t recs[ 16 ];
  ulong n = 0UL;
  /* slot 100: three notar votes (the third arriving out of order), a
     skip vote, our cast (twice) and ack.  Malformed records are
     dropped. */
  recs[ n++ ] = vote_rec( FD_VOTOR_GUI_REC_KIND_VOTE, FD_VOTE_KIND_NOTAR, 100UL, base+1L, 10UL );
  recs[ n++ ] = vote_rec( FD_VOTOR_GUI_REC_KIND_VOTE, FD_VOTE_KIND_NOTAR, 100UL, base+20L, 30UL );
  recs[ n++ ] = vote_rec( FD_VOTOR_GUI_REC_KIND_VOTE, FD_VOTE_KIND_NOTAR, 100UL, base, 30UL );
  recs[ n++ ] = vote_rec( FD_VOTOR_GUI_REC_KIND_VOTE, FD_VOTE_KIND_SKIP,  100UL, base+10L, 20UL );
  recs[ n++ ] = vote_rec( FD_VOTOR_GUI_REC_KIND_VOTE_CAST, FD_VOTE_KIND_NOTAR, 100UL, base+6L, 100UL );
  recs[ n++ ] = vote_rec( FD_VOTOR_GUI_REC_KIND_VOTE_CAST, FD_VOTE_KIND_NOTAR, 100UL, base+7L, 100UL );
  recs[ n++ ] = vote_rec( FD_VOTOR_GUI_REC_KIND_VOTE_ACK,  FD_VOTE_KIND_NOTAR, 100UL, base+8L, 100UL );
  recs[ n++ ] = vote_rec( 3, 0, 100UL, base+1L, 0UL );
  recs[ n++ ] = vote_rec( FD_VOTOR_GUI_REC_KIND_VOTE, 5, 100UL, base+1L, 0UL );
  recs[ n++ ] = vote_rec( FD_VOTOR_GUI_REC_KIND_VOTE, FD_VOTE_KIND_NOTAR, 100UL, -1L, 0UL );
  fd_gui_handle_votor_gui( gui, recs, n, now );
  /* votor_out markers: notar cert (created then accepted), finalize
     cert, ParentReady for 104, a malformed one. */
  fd_gui_handle_vote_event( gui, 100UL, FD_GUI_VOTE_EVENT_CERT+FD_CERT_KIND_NOTAR, base+7L, now );
  fd_gui_handle_vote_event( gui, 100UL, FD_GUI_VOTE_EVENT_CERT+FD_CERT_KIND_NOTAR, base+9L, now );
  fd_gui_handle_vote_event( gui, 100UL, FD_GUI_VOTE_EVENT_CERT+FD_CERT_KIND_FINAL, base+30L, now );
  fd_gui_handle_vote_event( gui, 104UL, FD_GUI_VOTE_EVENT_PARENT_READY, base+9L, now );
  fd_gui_handle_vote_event( gui, 100UL, FD_GUI_VOTE_EVENT_BATCH, base+9L, now );
  FD_TEST( gui->votes.dropped_cnt==4UL );
  FD_TEST( count_ts( gui, FD_GUI_HIST_VOTES,       ULONG_MAX )==4UL );
  FD_TEST( count_ts( gui, FD_GUI_HIST_VOTE_EVENTS, ULONG_MAX )==5UL ); /* cast, ack, 2 certs, parent ready */

  /* Markers for a slot older than the one tracked in its entry are
     dropped; a newer slot takes the entry over. */
  fd_gui_handle_vote_event( gui, 100UL+FD_GUI_VOTE_SLOT_CNT, FD_GUI_VOTE_EVENT_CERT+FD_CERT_KIND_SKIP, base+40L, now );
  fd_gui_handle_vote_event( gui, 100UL, FD_GUI_VOTE_EVENT_CERT+FD_CERT_KIND_SKIP, base+40L, now );
  FD_TEST( gui->votes.dropped_cnt==5UL );
  FD_TEST( count_ts( gui, FD_GUI_HIST_VOTE_EVENTS, ULONG_MAX )==6UL );

  /* query_votes: votes and markers by time, stakes null for markers. */
  void * http_mem = timeline_http_open( gui );
  FD_TEST( !fd_gui_printf_timeline_query_votes( gui, base, base+30L, 0, 7UL ) );
  test_json_t json = timeline_response( gui );
  FD_TEST( test_json_ulong( timeline_value( json, "reference_slot" ) )==100UL );
  FD_TEST( test_json_string_eq( timeline_value( json, "reference_ts" ), "259200000000000" ) );
  test_json_t ev    = timeline_value( json, "event" );
  test_json_t stake = timeline_value( json, "stake" );
  ulong const expect_ev[ 8 ] = {
    FD_GUI_VOTE_EVENT_VOTE+FD_VOTE_KIND_NOTAR, FD_GUI_VOTE_EVENT_VOTE+FD_VOTE_KIND_NOTAR,
    FD_GUI_VOTE_EVENT_CAST+FD_VOTE_KIND_NOTAR, FD_GUI_VOTE_EVENT_CERT+FD_CERT_KIND_NOTAR,
    FD_GUI_VOTE_EVENT_ACK +FD_VOTE_KIND_NOTAR, FD_GUI_VOTE_EVENT_PARENT_READY,
    FD_GUI_VOTE_EVENT_VOTE+FD_VOTE_KIND_SKIP,  FD_GUI_VOTE_EVENT_VOTE+FD_VOTE_KIND_NOTAR };
  FD_TEST( test_json_count( ev )==8 ); /* finalize cert at base+30 is outside [base, base+30) */
  for( int i=0; i<8; i++ ) FD_TEST( test_json_ulong( test_json_index( ev, i ) )==expect_ev[ i ] );
  FD_TEST( test_json_string_eq( test_json_index( stake, 0 ), "30" ) );
  FD_TEST( test_json_string_eq( test_json_index( stake, 1 ), "10" ) );
  FD_TEST( test_json_kind( test_json_index( stake, 2 ) )==FD_JTOK_NULL );
  FD_TEST( test_json_string_eq( timeline_value( json, "total_stake" ), "10000" ) );
  FD_TEST( test_json_kind( timeline_value( json, "next_epoch_start_slot" ) )==FD_JTOK_NULL );
  FD_TEST( test_json_kind( timeline_value( json, "next_total_stake" ) )==FD_JTOK_NULL );
  FD_TEST( test_json_ulong( test_json_index( timeline_value( json, "slot_delta" ), 5 ) )==4UL );
  FD_TEST( test_json_string_eq( test_json_index( timeline_value( json, "event_ts_delta" ), 2 ), "6" ) );
  FD_TEST( test_json_kind( timeline_value( json, "available_start_ns" ) )!=FD_JTOK_NULL );
  FD_TEST( test_json_string_eq( timeline_value( json, "granularity" ), "vote" ) );

  /* A window before anything happened, and bad arguments. */
  FD_TEST( !fd_gui_printf_timeline_query_votes( gui, base-sec_ns( 2UL ), base-sec_ns( 1UL ), 0, 7UL ) );
  json = timeline_response( gui );
  FD_TEST( !test_json_count( timeline_value( json, "event" ) ) );
  FD_TEST( test_json_kind( timeline_value( json, "reference_slot" ) )==FD_JTOK_NULL );
  FD_TEST( test_json_kind( timeline_value( json, "total_stake" ) )==FD_JTOK_NULL );
  FD_TEST( fd_gui_printf_timeline_query_votes( gui, base, base, 0, 7UL )==-1 );

  /* A newly missed vote counts in query_agg_votes at the time it
     becomes known. */
  long mt = base+sec_ns( 20UL );
  FD_TEST( fd_epoch_schedule_derive( &gui->epoch.epoch_schedule, 1024UL, 1024UL, 0 ) );
  gui->epoch.has_epoch_schedule = 1;
  gui->epoch.current_epoch      = 0UL;
  put_epoch( gui, 0UL, 0UL, 1024UL );
  fd_replay_slot_completed_t completed = { .slot=500UL+FD_NUM_SLOTS_FOR_REWARD, .bank_seq=BANK_SEQ, .parent_slot=ULONG_MAX, .parent_bank_seq=ULONG_MAX,
    .completion_time_nanos=mt, .identity_balance=ULONG_MAX, .vote_balance=ULONG_MAX, .vote_commission=USHORT_MAX, .voted=0, .voted_rank=3 };
  gui->summary.slot_caught_up = ULONG_MAX; /* no repair sampling (needs the topology) */
  fd_gui_handle_replay_update( gui, &completed, mt );
  fd_http_server_stage_trunc( gui->http, 0UL );
  FD_TEST( !fd_gui_printf_timeline_query_agg( gui, "query_agg_votes", "250ms", 3UL, mt-sec_ns( 1UL ), 8UL, 7UL ) );
  json = timeline_response( gui );
  test_json_t missed = timeline_value( json, "missed_votes" );
  FD_TEST( test_json_count( missed )==8 );
  for( int i=0; i<8; i++ ) FD_TEST( test_json_ulong( test_json_index( missed, i ) )==(i==4 ? 1UL : 0UL) );

  /* A window crossing an epoch boundary (1024-slot epochs above)
     reports the next epoch's total stake from its start slot on; old
     epoch votes arriving late still use total_stake. */
  n = 0UL;
  recs[ n++ ] = vote_rec( FD_VOTOR_GUI_REC_KIND_VOTE, FD_VOTE_KIND_NOTAR, 1023UL, mt+100L, 10UL );
  recs[ n++ ] = vote_rec( FD_VOTOR_GUI_REC_KIND_VOTE, FD_VOTE_KIND_NOTAR, 1024UL, mt+101L, 10UL );
  recs[ n++ ] = vote_rec( FD_VOTOR_GUI_REC_KIND_VOTE, FD_VOTE_KIND_NOTAR, 1022UL, mt+102L, 10UL );
  recs[ 1 ].total_stake = 20000UL;
  fd_gui_handle_votor_gui( gui, recs, n, mt );
  FD_TEST( !fd_gui_printf_timeline_query_votes( gui, mt+100L, mt+103L, 0, 7UL ) );
  json = timeline_response( gui );
  FD_TEST( test_json_string_eq( timeline_value( json, "total_stake" ), "10000" ) );
  FD_TEST( test_json_ulong( timeline_value( json, "next_epoch_start_slot" ) )==1024UL );
  FD_TEST( test_json_string_eq( timeline_value( json, "next_total_stake" ), "20000" ) );
  FD_TEST( !fd_gui_printf_timeline_query_votes( gui, mt+101L, mt+102L, 0, 7UL ) );
  json = timeline_response( gui );
  FD_TEST( test_json_string_eq( timeline_value( json, "total_stake" ), "20000" ) );
  FD_TEST( test_json_kind( timeline_value( json, "next_total_stake" ) )==FD_JTOK_NULL );

  /* Websocket dispatch */
  char const * ok  = "{\"id\":7,\"topic\":\"timeline\",\"key\":\"query_votes\",\"params\":"
                     "{\"start_ns\":\"0\",\"end_ns\":\"1000000000\",\"granularity\":\"vote\"}}";
  char const * nog = "{\"id\":7,\"topic\":\"timeline\",\"key\":\"query_votes\",\"params\":"
                     "{\"start_ns\":\"0\",\"end_ns\":\"1000000000\"}}";
  char const * agg = "{\"id\":7,\"topic\":\"timeline\",\"key\":\"query_agg_votes\",\"params\":"
                     "{\"start_ns\":\"0\",\"end_ns\":\"1000000000\",\"granularity\":\"1s\"}}";
  FD_TEST( !fd_gui_ws_message( gui, 0UL, (uchar const *)ok,  strlen( ok  ) ) );
  FD_TEST( fd_gui_ws_message( gui, 0UL, (uchar const *)nog, strlen( nog ) )==FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST );
  FD_TEST( !fd_gui_ws_message( gui, 0UL, (uchar const *)agg, strlen( agg ) ) );

  fd_http_server_delete( fd_http_server_leave( gui->http ) );
  gui->http = NULL;
  free( http_mem );
  FD_LOG_NOTICE(( "test_votes: ok" ));
}

/* test_vote_latency covers the query_agg_votes latency lines: slot
   starts anchored at the window's ParentReady plus the slot's offset
   times the target slot duration, independent lines, Final before
   Notar, dedup, missing anchors, null gaps, tier rollup and sum
   saturation. */

static void
vote_latency_values( test_json_t json,
                     char const * name,
                     ulong        n,
                     ulong const * expect ) { /* ULONG_MAX for null */
  test_json_t arr = timeline_value( json, name );
  FD_TEST( test_json_count( arr )==(int)n );
  for( ulong i=0UL; i<n; i++ ) {
    test_json_t v = test_json_index( arr, (int)i );
    if( expect[ i ]==ULONG_MAX ) FD_TEST( test_json_kind( v )==FD_JTOK_NULL );
    else                         FD_TEST( test_json_ulong( v )==expect[ i ] );
  }
}

static void
test_vote_latency( fd_gui_t * gui ) {
  long base = 5L*FD_GUI_TIMELINE_DAY_NS;
  long ms   = 1000000L;
  long t0   = base + sec_ns( 1UL ); /* ParentReady of window 200..203 */
  FD_TEST( fd_epoch_schedule_derive( &gui->epoch.epoch_schedule, 1024UL, 1024UL, 0 ) );
  gui->epoch.has_epoch_schedule = 1;
  gui->epoch.current_epoch      = 0UL;
  put_epoch( gui, 0UL, 0UL, 1024UL );
  fd_gui_epoch( gui, 0UL )->target_slot_duration_ns = 400L*ms;

  long now = t0;
  fd_gui_handle_vote_event( gui, 200UL, FD_GUI_VOTE_EVENT_PARENT_READY, t0, now );
  fd_gui_handle_vote_event( gui, 204UL, FD_GUI_VOTE_EVENT_PARENT_READY, t0+2000L*ms, now );
  /* slot 200 (starts t0): notar 300ms, fast final 350ms, slow final
     500ms (both finalization lines are recorded). */
  fd_gui_handle_vote_event( gui, 200UL, FD_GUI_VOTE_EVENT_CERT+FD_CERT_KIND_NOTAR,      t0+300L*ms, now );
  fd_gui_handle_vote_event( gui, 200UL, FD_GUI_VOTE_EVENT_CERT+FD_CERT_KIND_FAST_FINAL, t0+350L*ms, now );
  fd_gui_handle_vote_event( gui, 200UL, FD_GUI_VOTE_EVENT_CERT+FD_CERT_KIND_FINAL,      t0+500L*ms, now );
  fd_gui_handle_vote_event( gui, 200UL, FD_GUI_VOTE_EVENT_CERT+FD_CERT_KIND_FINAL,      t0+600L*ms, now ); /* duplicate */
  /* slot 201 (starts t0+400ms): Final before Notar, so the slow line
     waits for the notarization at 800ms (latency 400ms). */
  fd_gui_handle_vote_event( gui, 201UL, FD_GUI_VOTE_EVENT_CERT+FD_CERT_KIND_FINAL,      t0+700L*ms, now );
  fd_gui_handle_vote_event( gui, 201UL, FD_GUI_VOTE_EVENT_CERT+FD_CERT_KIND_NOTAR,      t0+800L*ms, now );
  /* slot 202 (starts t0+800ms): notar fallback 300ms, skip 400ms. */
  fd_gui_handle_vote_event( gui, 202UL, FD_GUI_VOTE_EVENT_CERT+FD_CERT_KIND_NOTAR_FALLBACK, t0+1100L*ms, now );
  fd_gui_handle_vote_event( gui, 202UL, FD_GUI_VOTE_EVENT_CERT+FD_CERT_KIND_SKIP,           t0+1200L*ms, now );
  /* slot 203 (starts t0+1200ms): fast final notarizes too, 50ms. */
  fd_gui_handle_vote_event( gui, 203UL, FD_GUI_VOTE_EVENT_CERT+FD_CERT_KIND_FAST_FINAL, t0+1250L*ms, now );
  fd_gui_handle_vote_event( gui, 203UL, FD_GUI_VOTE_EVENT_CERT+FD_CERT_KIND_NOTAR,      t0+1260L*ms, now ); /* already notarized */
  /* Not sampled: no ParentReady for window 300..303, and slot 207
     (starts t0+3200ms) certified before its start. */
  FD_TEST( gui->votes.lat_missing_cnt==0UL );
  fd_gui_handle_vote_event( gui, 300UL, FD_GUI_VOTE_EVENT_CERT+FD_CERT_KIND_NOTAR,      t0+1300L*ms, now );
  fd_gui_handle_vote_event( gui, 207UL, FD_GUI_VOTE_EVENT_CERT+FD_CERT_KIND_NOTAR,      t0+2500L*ms, now );
  FD_TEST( gui->votes.lat_missing_cnt==2UL );

  void * http_mem = timeline_http_open( gui );
  /* 1s buckets from t0: [t0,t0+1s) [t0+1s,t0+2s) [t0+2s,t0+3s) */
  FD_TEST( !fd_gui_printf_timeline_query_agg( gui, "query_agg_votes", "1s", 5UL, t0, 3UL, 7UL ) );
  test_json_t json = timeline_response( gui );
  ulong const U = ULONG_MAX;
  vote_latency_values( json, "notarized_latency_ns",      3UL, (ulong[]){ 350000000UL, 50000000UL, U } );
  vote_latency_values( json, "notarized_cnt",             3UL, (ulong[]){ 2UL, 1UL, 0UL } );
  vote_latency_values( json, "finalized_fast_latency_ns", 3UL, (ulong[]){ 350000000UL, 50000000UL, U } );
  vote_latency_values( json, "finalized_fast_cnt",        3UL, (ulong[]){ 1UL, 1UL, 0UL } );
  vote_latency_values( json, "finalized_slow_latency_ns", 3UL, (ulong[]){ 450000000UL, U, U } );
  vote_latency_values( json, "finalized_slow_cnt",        3UL, (ulong[]){ 2UL, 0UL, 0UL } );
  vote_latency_values( json, "skipped_latency_ns",        3UL, (ulong[]){ U, 400000000UL, U } );
  vote_latency_values( json, "skipped_cnt",               3UL, (ulong[]){ 0UL, 1UL, 0UL } );
  vote_latency_values( json, "notar_fallback_latency_ns", 3UL, (ulong[]){ U, 300000000UL, U } );
  vote_latency_values( json, "notar_fallback_cnt",        3UL, (ulong[]){ 0UL, 1UL, 0UL } );
  vote_latency_values( json, "missed_votes",              3UL, (ulong[]){ 0UL, 0UL, 0UL } );

  /* The 2m tier rolls the same samples up: notarized (300+400+50)/3. */
  FD_TEST( !fd_gui_printf_timeline_query_agg( gui, "query_agg_votes", "2m", 12UL, base, 1UL, 7UL ) );
  json = timeline_response( gui );
  vote_latency_values( json, "notarized_latency_ns", 1UL, (ulong[]){ 250000000UL } );
  vote_latency_values( json, "notarized_cnt",        1UL, (ulong[]){ 3UL } );

  /* Buckets before the first day record are null too. */
  FD_TEST( !fd_gui_printf_timeline_query_agg( gui, "query_agg_votes", "1s", 5UL, base-sec_ns( 2UL ), 1UL, 7UL ) );
  json = timeline_response( gui );
  vote_latency_values( json, "notarized_latency_ns", 1UL, (ulong[]){ U } );
  vote_latency_values( json, "notarized_cnt",        1UL, (ulong[]){ 0UL } );
  fd_http_server_delete( fd_http_server_leave( gui->http ) );
  gui->http = NULL;
  free( http_mem );

  /* Sums saturate rather than wrap; unset counts read as empty. */
  fd_gui_timeline_day_t * day = aligned_alloc( alignof(fd_gui_timeline_day_t), sizeof(fd_gui_timeline_day_t) );
  FD_TEST( day );
  memset( day->vote_lat, 0xFF, sizeof(day->vote_lat) );
  ulong sum, cnt;
  fd_gui_timeline_vote_lat_get( day, FD_GUI_VOTE_LAT_SKIP, FD_GUI_TIMELINE_GRANULARITY_250MS, 0UL, &sum, &cnt );
  FD_TEST( !sum && !cnt );
  memset( day->vote_lat, 0, sizeof(day->vote_lat) );
  fd_gui_timeline_vote_lat_add( day, FD_GUI_VOTE_LAT_SKIP, 0UL, 4000000000UL );
  fd_gui_timeline_vote_lat_add( day, FD_GUI_VOTE_LAT_SKIP, 0UL, 4000000000UL );
  fd_gui_timeline_vote_lat_get( day, FD_GUI_VOTE_LAT_SKIP, FD_GUI_TIMELINE_GRANULARITY_250MS, 0UL, &sum, &cnt );
  FD_TEST( sum==UINT_MAX && cnt==2UL );
  fd_gui_timeline_vote_lat_get( day, FD_GUI_VOTE_LAT_SKIP, FD_GUI_TIMELINE_GRANULARITY_15S, 0UL, &sum, &cnt );
  FD_TEST( sum==8000000000UL && cnt==2UL );
  free( day );
  FD_LOG_NOTICE(( "test_vote_latency: ok" ));
}

/* test_vote_batch covers vote batches: each (slot, kind) cumulative
   stake curve is flushed as Douglas-Peucker breakpoints whose stakes
   sum to the votes they replace, open slots are simplified at query
   time, late votes are recorded alone, and query_votes "vote_batch"
   returns batches and markers but no raw votes. */

static ulong
batch_stake_sum( fd_gui_t * gui, ulong slot, uint event, ulong * cnt ) {
  fd_gui_hist_iter_t it[ 1 ];
  FD_TEST( !fd_gui_hist_range_begin( gui, it, FD_GUI_HIST_VOTE_BATCH, LONG_MIN+1, LONG_MAX-1L, NULL, NULL ) );
  ulong sum = 0UL;
  *cnt = 0UL;
  while( fd_gui_hist_range_next( it ) ) {
    fd_gui_store_vote_t const * v = (fd_gui_store_vote_t const *)it->rec;
    if( v->slot!=slot || v->event!=event ) continue;
    sum += v->stake;
    (*cnt)++;
  }
  fd_gui_hist_range_end( it );
  return sum;
}

static ulong
batch_cum_max( fd_gui_t * gui, ulong slot, uint event ) {
  fd_gui_hist_iter_t it[ 1 ];
  FD_TEST( !fd_gui_hist_range_begin( gui, it, FD_GUI_HIST_VOTE_BATCH, LONG_MIN+1, LONG_MAX-1L, NULL, NULL ) );
  ulong max = 0UL;
  while( fd_gui_hist_range_next( it ) ) {
    fd_gui_store_vote_t const * v = (fd_gui_store_vote_t const *)it->rec;
    if( v->slot!=slot || v->event!=event ) continue;
    FD_TEST( v->cum_stake!=FD_GUI_VOTE_CUM_UNKNOWN );
    max = fd_ulong_max( max, v->cum_stake );
  }
  fd_gui_hist_range_end( it );
  return max;
}

/* query_cum_max queries votes (vote batches if batch) of [start,end)
   and returns the largest cumulative_stake of slot's rows of event,
   checking that no row's exceeds limit and that the stake of each row
   is at most its cumulative_stake.  *stake_sum is the sum of their
   stake. */

static ulong
query_cum_max( fd_gui_t * gui,
               long       start,
               long       end,
               int        batch,
               ulong      slot,
               ulong      event,
               ulong      limit,
               ulong *    stake_sum ) {
  fd_http_server_stage_trunc( gui->http, 0UL );
  FD_TEST( !fd_gui_printf_timeline_query_votes( gui, start, end, batch, 7UL ) );
  test_json_t json  = timeline_response( gui );
  test_json_t ev    = timeline_value( json, "event" );
  test_json_t sd    = timeline_value( json, "slot_delta" );
  test_json_t stake = timeline_value( json, "stake" );
  test_json_t cum   = timeline_value( json, "cumulative_stake" );
  int         cnt   = test_json_count( ev );
  FD_TEST( test_json_count( cum )==cnt );
  ulong ref = cnt ? test_json_ulong( timeline_value( json, "reference_slot" ) ) : 0UL;
  ulong max = 0UL;
  *stake_sum = 0UL;
  for( int i=0; i<cnt; i++ ) {
    ulong e = test_json_ulong( test_json_index( ev, i ) );
    test_json_t cj = test_json_index( cum, i );
    if( !fd_gui_vote_event_has_stake( (uchar)e ) ) { FD_TEST( test_json_kind( cj )==FD_JTOK_NULL ); continue; }
    if( e!=event || ref+test_json_ulong( test_json_index( sd, i ) )!=slot ) continue;
    test_json_t sj = test_json_index( stake, i );
    FD_TEST( cj.sz>2UL && cj.ptr[ 0 ]=='"' && sj.sz>2UL && sj.ptr[ 0 ]=='"' );
    ulong c = strtoul( cj.ptr+1, NULL, 10 );
    ulong s = strtoul( sj.ptr+1, NULL, 10 );
    FD_TEST( c<=limit && s<=c );
    max = fd_ulong_max( max, c );
    *stake_sum += s;
  }
  return max;
}

static void
test_vote_batch( fd_gui_t * gui ) {
  long  base = 5L*FD_GUI_TIMELINE_DAY_NS;
  long  ms   = 1000L*1000L;
  fd_votor_gui_rec_t recs[ 512 ];

  /* slot 200: 400 notar votes of 10 stake, 1 ms apart: a straight line
     collapses to its two ends.  Then 100 skip votes on a curve with a
     knee: the knee survives. */
  ulong n = 0UL;
  for( ulong i=0UL; i<400UL; i++ ) recs[ n++ ] = vote_rec( FD_VOTOR_GUI_REC_KIND_VOTE, FD_VOTE_KIND_NOTAR, 200UL, base+(long)i*ms, 10UL );
  for( ulong i=0UL; i<100UL; i++ ) recs[ n++ ] = vote_rec( FD_VOTOR_GUI_REC_KIND_VOTE, FD_VOTE_KIND_SKIP, 200UL, base+(long)i*ms, i<50UL ? 40UL : 1UL );
  fd_gui_handle_votor_gui( gui, recs, n, base );
  FD_TEST( count_ts( gui, FD_GUI_HIST_VOTES, 200UL )==500UL );
  FD_TEST( gui->votes.batch[ 200UL%FD_GUI_VOTE_SLOT_CNT ].pt_cnt==500UL );

  /* Open slots are visible to vote_batch queries before any flush. */
  void * http_mem = timeline_http_open( gui );
  FD_TEST( !fd_gui_printf_timeline_query_votes( gui, base, base+sec_ns( 1UL ), 1, 7UL ) );
  test_json_t json = timeline_response( gui );
  test_json_t ev    = timeline_value( json, "event" );
  test_json_t stake = timeline_value( json, "stake" );
  ulong notar_cnt = 0UL, notar_sum = 0UL, skip_cnt = 0UL, skip_sum = 0UL;
  for( int i=0; i<test_json_count( ev ); i++ ) {
    ulong e = test_json_ulong( test_json_index( ev, i ) );
    test_json_t sj = test_json_index( stake, i );
    FD_TEST( sj.sz>2UL && sj.ptr[ 0 ]=='"' );
    ulong s = strtoul( sj.ptr+1, NULL, 10 );
    if( e==FD_GUI_VOTE_EVENT_BATCH+FD_VOTE_KIND_NOTAR ) { notar_cnt++; notar_sum += s; }
    else if( e==FD_GUI_VOTE_EVENT_BATCH+FD_VOTE_KIND_SKIP ) { skip_cnt++; skip_sum += s; }
    else FD_TEST( 0 );
  }
  FD_TEST( notar_cnt==2UL && notar_sum==4000UL );
  FD_TEST( skip_cnt>=3UL && skip_cnt<10UL && skip_sum==2050UL );
  FD_TEST( test_json_string_eq( timeline_value( json, "total_stake" ), "10000" ) );
  FD_TEST( test_json_string_eq( timeline_value( json, "granularity" ), "vote_batch" ) );
  ulong c;
  FD_TEST( !batch_stake_sum( gui, 200UL, FD_GUI_VOTE_EVENT_BATCH+FD_VOTE_KIND_NOTAR, &c ) && !c );

  /* Not yet idle or old: nothing flushed, and the next due time is
     the idle deadline. */
  fd_gui_vote_batch_flush( gui, base+FD_GUI_VOTE_BATCH_IDLE_NS-1L, 0 );
  FD_TEST( !count_ts( gui, FD_GUI_HIST_VOTE_BATCH, 200UL ) );
  FD_TEST( gui->votes.batch_flush_ns==base+FD_GUI_VOTE_BATCH_IDLE_NS );
  /* Idle: flushed, with the same rows the open query produced. */
  fd_gui_vote_batch_flush( gui, base+FD_GUI_VOTE_BATCH_IDLE_NS, 0 );
  FD_TEST( batch_stake_sum( gui, 200UL, FD_GUI_VOTE_EVENT_BATCH+FD_VOTE_KIND_NOTAR, &c )==4000UL && c==2UL );
  FD_TEST( batch_stake_sum( gui, 200UL, FD_GUI_VOTE_EVENT_BATCH+FD_VOTE_KIND_SKIP,  &c )==2050UL && c==skip_cnt );
  FD_TEST( !gui->votes.batch[ 200UL%FD_GUI_VOTE_SLOT_CNT ].pt_cnt );

  /* A slot that keeps getting votes flushes once its oldest buffered
     vote is FD_GUI_VOTE_BATCH_AGE_NS old. */
  long t = base+sec_ns( 10UL );
  long const step = FD_GUI_VOTE_BATCH_IDLE_NS/2L; /* never idle */
  ulong votes = 0UL;
  for( long k=0L; k*step<=FD_GUI_VOTE_BATCH_AGE_NS; k++ ) {
    fd_votor_gui_rec_t r = vote_rec( FD_VOTOR_GUI_REC_KIND_VOTE, FD_VOTE_KIND_FINAL, 201UL, t+k*step, 1UL );
    fd_gui_handle_votor_gui( gui, &r, 1UL, t+k*step );
    fd_gui_vote_batch_flush( gui, t+k*step, 0 );
    votes++;
  }
  FD_TEST( batch_stake_sum( gui, 201UL, FD_GUI_VOTE_EVENT_BATCH+FD_VOTE_KIND_FINAL, &c )==votes );

  /* A newer slot taking the entry over flushes the old one; a vote for
     the older slot after that is recorded alone. */
  long t2 = base+sec_ns( 40UL );
  fd_votor_gui_rec_t r = vote_rec( FD_VOTOR_GUI_REC_KIND_VOTE, FD_VOTE_KIND_NOTAR, 202UL, t2, 5UL );
  fd_gui_handle_votor_gui( gui, &r, 1UL, t2 );
  r = vote_rec( FD_VOTOR_GUI_REC_KIND_VOTE, FD_VOTE_KIND_NOTAR, 202UL+FD_GUI_VOTE_SLOT_CNT, t2+1L, 5UL );
  fd_gui_handle_votor_gui( gui, &r, 1UL, t2+1L );
  FD_TEST( batch_stake_sum( gui, 202UL, FD_GUI_VOTE_EVENT_BATCH+FD_VOTE_KIND_NOTAR, &c )==5UL && c==1UL );
  FD_TEST( batch_cum_max( gui, 202UL, FD_GUI_VOTE_EVENT_BATCH+FD_VOTE_KIND_NOTAR )==5UL );
  ulong late = gui->votes.batch_late_cnt;
  r = vote_rec( FD_VOTOR_GUI_REC_KIND_VOTE, FD_VOTE_KIND_SKIP_FALLBACK, 202UL, t2+2L, 7UL );
  fd_gui_handle_votor_gui( gui, &r, 1UL, t2+2L );
  FD_TEST( gui->votes.batch_late_cnt==late+1UL );
  FD_TEST( batch_stake_sum( gui, 202UL, FD_GUI_VOTE_EVENT_BATCH+FD_VOTE_KIND_SKIP_FALLBACK, &c )==7UL && c==1UL );
  FD_TEST( batch_cum_max( gui, 202UL, FD_GUI_VOTE_EVENT_BATCH+FD_VOTE_KIND_SKIP_FALLBACK )==7UL );

  /* A full buffer flushes. */
  long t3 = base+sec_ns( 60UL );
  for( ulong done=0UL; done<FD_GUI_VOTE_BATCH_PTS_MAX+1UL; done+=n ) {
    n = fd_ulong_min( 512UL, FD_GUI_VOTE_BATCH_PTS_MAX+1UL-done );
    for( ulong i=0UL; i<n; i++ ) recs[ i ] = vote_rec( FD_VOTOR_GUI_REC_KIND_VOTE, FD_VOTE_KIND_NOTAR, 300UL, t3+(long)(done+i), 1UL );
    fd_gui_handle_votor_gui( gui, recs, n, t3 );
  }
  FD_TEST( batch_stake_sum( gui, 300UL, FD_GUI_VOTE_EVENT_BATCH+FD_VOTE_KIND_NOTAR, &c )==FD_GUI_VOTE_BATCH_PTS_MAX );
  FD_TEST( gui->votes.batch[ 300UL%FD_GUI_VOTE_SLOT_CNT ].pt_cnt==1UL );
  fd_gui_vote_batch_flush( gui, t3, 1 );
  FD_TEST( batch_stake_sum( gui, 300UL, FD_GUI_VOTE_EVENT_BATCH+FD_VOTE_KIND_NOTAR, &c )==FD_GUI_VOTE_BATCH_PTS_MAX+1UL );
  /* The second flush continues the running total of the first. */
  FD_TEST( batch_cum_max( gui, 300UL, FD_GUI_VOTE_EVENT_BATCH+FD_VOTE_KIND_NOTAR )==FD_GUI_VOTE_BATCH_PTS_MAX+1UL );
  FD_TEST( batch_cum_max( gui, 200UL, FD_GUI_VOTE_EVENT_BATCH+FD_VOTE_KIND_NOTAR )==4000UL );
  FD_TEST( batch_cum_max( gui, 200UL, FD_GUI_VOTE_EVENT_BATCH+FD_VOTE_KIND_SKIP  )==2050UL );

  /* A slot split across two requests, polled live: the first request
     sees half the votes, whose curve ends at its 50th vote.  The rest
     extend the line, so the open slot simplifies to its two ends and
     the second request's last breakpoint carries the stake of all but
     the first vote, already counted by the first request.  Summing
     stake gives 149%, but the largest cumulative_stake is the total,
     with votes or vote batches, open or flushed. */
  long  t4 = base+sec_ns( 80UL );
  ulong const sl = 400UL;
  ulong const ek = FD_GUI_VOTE_EVENT_BATCH+FD_VOTE_KIND_NOTAR;
  ulong const ev_vote = FD_GUI_VOTE_EVENT_VOTE+FD_VOTE_KIND_NOTAR;
  for( ulong i=0UL; i<100UL; i++ ) recs[ i ] = vote_rec( FD_VOTOR_GUI_REC_KIND_VOTE, FD_VOTE_KIND_NOTAR, sl, t4+(long)i*ms, 100UL );
  long  mid = t4+50L*ms;
  long  end = t4+sec_ns( 1UL );
  ulong s0, s1;
  fd_gui_handle_votor_gui( gui, recs, 50UL, t4 );
  ulong c0 = query_cum_max( gui, t4, mid, 1, sl, ek, 10000UL, &s0 );
  FD_TEST( c0==5000UL && s0==5000UL );
  fd_gui_handle_votor_gui( gui, recs+50UL, 50UL, t4 );
  ulong c1 = query_cum_max( gui, mid, end, 1, sl, ek, 10000UL, &s1 );
  FD_TEST( s0+s1==14900UL ); /* the issue cumulative_stake fixes */
  FD_TEST( fd_ulong_max( c0, c1 )==10000UL );
  for( int flushed=0; flushed<2; flushed++ ) {
    c0 = query_cum_max( gui, t4,  mid, 1, sl, ek, 10000UL, &s0 );
    c1 = query_cum_max( gui, mid, end, 1, sl, ek, 10000UL, &s1 );
    FD_TEST( fd_ulong_max( c0, c1 )==10000UL );
    FD_TEST( query_cum_max( gui, t4, end, 1, sl, ek, 10000UL, &s0 )==10000UL && s0==10000UL );
    /* Raw votes: the running total at the window edge, then the total. */
    FD_TEST( query_cum_max( gui, t4,  mid, 0, sl, ev_vote, 10000UL, &s0 )==5000UL && s0==5000UL );
    FD_TEST( query_cum_max( gui, mid, end, 0, sl, ev_vote, 10000UL, &s1 )==10000UL && s1==5000UL );
    fd_gui_vote_batch_flush( gui, t4, 1 );
  }
  FD_TEST( batch_cum_max( gui, sl, (uint)ek )==10000UL );

  /* vote_batch queries return batches and markers, never raw votes;
     vote queries the reverse. */
  fd_gui_handle_vote_event( gui, 200UL, FD_GUI_VOTE_EVENT_CERT+FD_CERT_KIND_NOTAR, base+5L*ms, base+sec_ns( 1UL ) );
  fd_http_server_stage_trunc( gui->http, 0UL );
  FD_TEST( !fd_gui_printf_timeline_query_votes( gui, base, base+sec_ns( 1UL ), 1, 7UL ) );
  json = timeline_response( gui );
  ev    = timeline_value( json, "event" );
  stake = timeline_value( json, "stake" );
  int saw_marker = 0;
  for( int i=0; i<test_json_count( ev ); i++ ) {
    ulong e = test_json_ulong( test_json_index( ev, i ) );
    FD_TEST( e>=FD_GUI_VOTE_EVENT_CERT );
    if( e<FD_GUI_VOTE_EVENT_BATCH ) { saw_marker = 1; FD_TEST( test_json_kind( test_json_index( stake, i ) )==FD_JTOK_NULL ); }
  }
  FD_TEST( saw_marker );
  fd_http_server_stage_trunc( gui->http, 0UL );
  FD_TEST( !fd_gui_printf_timeline_query_votes( gui, base, base+sec_ns( 1UL ), 0, 7UL ) );
  json = timeline_response( gui );
  ev = timeline_value( json, "event" );
  FD_TEST( test_json_count( ev )==501 );
  for( int i=0; i<test_json_count( ev ); i++ ) FD_TEST( test_json_ulong( test_json_index( ev, i ) )<FD_GUI_VOTE_EVENT_BATCH );

  /* Websocket dispatch */
  char const * batch = "{\"id\":7,\"topic\":\"timeline\",\"key\":\"query_votes\",\"params\":"
                       "{\"start_ns\":\"0\",\"end_ns\":\"1000000000\",\"granularity\":\"vote_batch\"}}";
  char const * vote  = "{\"id\":7,\"topic\":\"timeline\",\"key\":\"query_votes\",\"params\":"
                       "{\"start_ns\":\"0\",\"end_ns\":\"1000000000\",\"granularity\":\"vote\"}}";
  char const * bad   = "{\"id\":7,\"topic\":\"timeline\",\"key\":\"query_votes\",\"params\":"
                       "{\"start_ns\":\"0\",\"end_ns\":\"1000000000\",\"granularity\":\"1s\"}}";
  FD_TEST( !fd_gui_ws_message( gui, 0UL, (uchar const *)batch, strlen( batch ) ) );
  FD_TEST( !fd_gui_ws_message( gui, 0UL, (uchar const *)vote,  strlen( vote  ) ) );
  FD_TEST( fd_gui_ws_message( gui, 0UL, (uchar const *)bad, strlen( bad ) )==FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST );

  fd_http_server_delete( fd_http_server_leave( gui->http ) );
  gui->http = NULL;
  free( http_mem );
  FD_LOG_NOTICE(( "test_vote_batch: ok" ));
}

/* test_votes_raw_grow covers the raw vote ring growing past its base
   regions into shared space rather than being capped. */

static void
test_votes_raw_grow( fd_gui_t * gui ) {
  ulong per_region = FD_GUI_STORE_REGION_SZ/sizeof(fd_gui_store_vote_t);
  long  base       = 4L*FD_GUI_TIMELINE_DAY_NS; /* after test_votes */
  fd_votor_gui_rec_t recs[ FD_VOTOR_GUI_REC_MAX ];
  for( ulong i=0UL; i<FD_VOTOR_GUI_REC_MAX; i++ ) recs[ i ] = vote_rec( FD_VOTOR_GUI_REC_KIND_VOTE, FD_VOTE_KIND_NOTAR, 7UL, base, 1UL );
  ulong total = 0UL;
  for( ulong done=0UL; done<3UL*per_region; done+=FD_VOTOR_GUI_REC_MAX ) {
    fd_gui_handle_votor_gui( gui, recs, FD_VOTOR_GUI_REC_MAX, base+(long)done );
    total += FD_VOTOR_GUI_REC_MAX;
  }
  ulong used_bytes, cap_bytes, free_bytes, used_slots, cap_slots, free_slots;
  fd_gui_store_ring_stats( gui->db, FD_GUI_HIST_VOTES, &used_bytes, &cap_bytes, &free_bytes, &used_slots, &cap_slots, &free_slots );
  FD_TEST( cap_bytes>=3UL*FD_GUI_STORE_REGION_SZ );
  FD_TEST( used_slots>=total ); /* nothing evicted: the store has room */
  FD_LOG_NOTICE(( "test_votes_raw_grow: ok" ));
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  /* Tests that fill most of a store peak at 0.7-1.2 GiB of disk each
     (the rest stay under 300 MiB), so they only run with --run-all. */
  int run_all = fd_env_strip_cmdline_contains( &argc, &argv, "--run-all" );

  if( argc>1 && !strcmp( argv[1], "--shreds" ) ) {
    test_store_t s[1];
    store_open( s, TEST_STORE_BYTES, 20 ); test_shred_encoding( s->gui ); store_close( s );
    store_open( s, TEST_STORE_BYTES, 21 ); test_shred_storage( s->gui ); store_close( s );
    store_open( s, TEST_STORE_BYTES, 22 ); test_shred_flush_full( s->gui, 0 ); store_close( s );
    store_open( s, TEST_STORE_BYTES, 23 ); test_shred_retention( s->gui ); store_close( s );
    store_open( s, TEST_STORE_BYTES, 24 ); test_shred_epoch_retention( s->gui, 1UL ); store_close( s );
    store_open( s, TEST_STORE_BYTES, 25 ); test_shred_epoch_retention( s->gui, 1000UL ); store_close( s );
    store_open( s, TEST_STORE_BYTES, 26 ); test_shred_flush_full( s->gui, 1 ); store_close( s );
    store_open( s, TEST_STORE_BYTES, 27 ); test_shred_flush_full( s->gui, 2 ); store_close( s );
    FD_LOG_NOTICE(( "pass" ));
    fd_halt();
    return 0;
  }

  /* Each test gets its own store. */
  ulong min_bytes = fd_gui_store_min_size( FD_GUI_HIST_CNT, test_descs() );
  test_store_t s4_[ 1 ];
  test_min_footprint();
  if( argc>1 && !strcmp( argv[ 1 ], "--footprint" ) ) {
    test_fec_footprint( 100UL<<30 );
    fd_halt();
    return 0;
  }
  test_fec_footprint( TEST_STORE_BYTES );
  test_store_t fec[ 1 ];
  store_open( fec, TEST_STORE_BYTES, 28 );
  test_live_shred_receive_time( fec->gui );
  store_close( fec );
  store_open( fec, TEST_STORE_BYTES, 28 );
  test_timeline_leader_txns( fec->gui );
  store_close( fec );
  if( run_all ) {
    store_open( fec, TEST_STORE_BYTES, 29 );
    test_fec_base_admission( fec->gui );
    store_close( fec );
  }
  store_open( fec, TEST_STORE_BYTES, 30 );
  test_fec_prefix_guards( fec->gui );
  store_close( fec );
  store_open( fec, TEST_STORE_BYTES, 32 );
  test_fec_archive( fec->gui );
  store_close( fec );
  store_open( fec, min_bytes, 31 );
  test_fec_minimum_store( fec->gui );
  store_close( fec );
  test_store_t closure[ 1 ];
  store_open( closure, TEST_STORE_BYTES, 28 );
  test_shred_closure_codec( closure->gui );
  store_close( closure );

  if( run_all ) {
    test_store_t s0[ 1 ];
    store_open( s0, TEST_STORE_BYTES, 0 );
    test_base_history_protected( s0->gui );
    store_close( s0 );

    test_store_t s1[ 1 ];
    store_open( s1, TEST_STORE_BYTES, 2 );
    test_evict_large_batch( s1->gui );
    store_close( s1 );

    test_store_t sp[ 1 ];
    store_open( sp, TEST_STORE_BYTES, 6 );
    test_current_epoch_protected( sp->gui );
    store_close( sp );

    test_store_t st[ 1 ];
    store_open( st, min_bytes + 16UL*FD_GUI_STORE_REGION_SZ, 9 );
    test_timeline_rollover( st->gui );
    store_close( st );

    store_open( s4_, min_bytes, 33 );
    test_tile_day_minimum_store( s4_->gui );
    store_close( s4_ );
  }

  test_store_t s3[ 1 ];
  store_open( s3, TEST_STORE_BYTES, 4 );
  test_resident_meta_mutation_survives_evict( s3->gui );
  store_close( s3 );

  test_store_t s4[ 1 ];
  store_open( s4, min_bytes, 5 );
  test_epoch_region_reclaimed( s4->gui );
  store_close( s4 );

  test_store_t s5[ 1 ];
  store_open( s5, TEST_STORE_BYTES, 7 );
  test_waterfall_snapshots( s5->gui );
  store_close( s5 );

  test_store_t s6[ 1 ];
  store_open( s6, TEST_STORE_BYTES, 8 );
  test_timeline_db( s6->gui );
  store_close( s6 );

  test_store_t sr[ 1 ];
  store_open( sr, TEST_STORE_BYTES, 13 );
  test_range_live_timestamp_bounds( sr->gui );
  store_close( sr );

  test_store_t tx[ 1 ];
  store_open( tx, TEST_STORE_BYTES, 14 );
  test_txn_insert_bounds( tx->gui );
  store_close( tx );

  test_store_t rv[ 1 ];
  store_open( rv, TEST_STORE_BYTES, 28 );
  test_timeline_agg( rv->gui );
  store_close( rv );

  store_open( rv, TEST_STORE_BYTES, 29 );
  test_timeline_shreds( rv->gui );
  store_close( rv );

  test_store_t la[ 1 ];
  store_open( la, TEST_STORE_BYTES, 30 );
  test_leader_active_slot( la->gui );
  store_close( la );

  store_open( rv, TEST_STORE_BYTES, 32 );
  test_timeline_cpu( rv->gui );
  store_close( rv );

  store_open( rv, TEST_STORE_BYTES, 32 );
  test_day_prepare( rv->gui );
  store_close( rv );

  store_open( rv, TEST_STORE_BYTES, 34 );
  test_fec_events( rv->gui );
  store_close( rv );

  store_open( rv, TEST_STORE_BYTES, 35 );
  test_fec_staging_pressure( rv->gui );
  store_close( rv );

  store_open( rv, TEST_STORE_BYTES, 36 );
  test_timeline_agg_shreds( rv->gui );
  store_close( rv );

  test_store_t s7[ 1 ];
  store_open( s7, TEST_STORE_BYTES, 10 );
  test_shred_encoding( s7->gui );
  store_close( s7 );

  test_store_t s8[ 1 ];
  store_open( s8, TEST_STORE_BYTES, 11 );
  test_shred_storage( s8->gui );
  store_close( s8 );

  test_store_t s9[ 1 ];
  if( run_all ) {
    store_open( s9, TEST_STORE_BYTES, 12 );
    test_shred_flush_full( s9->gui, 0 );
    store_close( s9 );
  }

  test_store_t s10[ 1 ];
  store_open( s10, TEST_STORE_BYTES, 15 );
  test_shred_retention( s10->gui );
  store_close( s10 );

  store_open( s10, TEST_STORE_BYTES, 16 );
  test_shred_epoch_retention( s10->gui, 1UL );
  store_close( s10 );

  store_open( s10, TEST_STORE_BYTES, 17 );
  test_shred_epoch_retention( s10->gui, 1000UL );
  store_close( s10 );

  if( run_all ) {
    store_open( s10, TEST_STORE_BYTES, 18 );
    test_shred_flush_full( s10->gui, 1 );
    store_close( s10 );

    store_open( s10, TEST_STORE_BYTES, 19 );
    test_shred_flush_full( s10->gui, 2 );
    store_close( s10 );
  }
  store_open( s7, TEST_STORE_BYTES, 10 );
  test_shred_event_batches( s7->gui );
  store_close( s7 );

  store_open( s9, TEST_STORE_BYTES, 12 );
  test_shred_event_root_reclaim( s9->gui );
  store_close( s9 );

  store_open( s10, TEST_STORE_BYTES, 15 );
  test_fec_event_index( s10->gui );
  store_close( s10 );

  store_open( s10, TEST_STORE_BYTES, 15 );
  test_fec_slot_horizon( s10->gui );
  store_close( s10 );

  store_open( s10, TEST_STORE_BYTES, 15 );
  test_timeline_live_events( s10 );
  store_close( s10 );

  test_store_t s11[ 1 ];
  store_open( s11, TEST_STORE_BYTES, 16 );
  test_timeline_queries( s11->gui );
  store_close( s11 );

  test_store_t s12[ 1 ];
  store_open( s12, TEST_STORE_BYTES, 17 );
  test_timeline_slot_intervals( s12->gui );
  store_close( s12 );

  store_open( s12, TEST_STORE_BYTES, 17 );
  test_timeline_replayed_skips( s12->gui );
  store_close( s12 );

  store_open( s12, TEST_STORE_BYTES, 17 );
  test_timeline_root( s12->gui );
  store_close( s12 );

  store_open( s12, TEST_STORE_BYTES, 17 );
  test_timeline_lifecycle_events( s12->gui );
  store_close( s12 );

  test_store_t s13[ 1 ];
  store_open( s13, TEST_STORE_BYTES, 18 );
  test_timeline_batches( s13->gui );
  store_close( s13 );

  store_open( s13, TEST_STORE_BYTES, 18 );
  test_timeline_replay_batches( s13->gui );
  store_close( s13 );

  test_store_t s14[ 1 ];
  store_open( s14, TEST_STORE_BYTES, 19 );
  test_timeline_limits( s14->gui );
  store_close( s14 );

  test_store_t s17[ 1 ];
  store_open( s17, TEST_STORE_BYTES, 22 );
  test_timeline_batch_stream( s17->gui );
  store_close( s17 );

  test_store_t s18[ 1 ];
  store_open( s18, TEST_STORE_BYTES, 23 );
  test_timeline_closure_cutoff( s18->gui );
  store_close( s18 );

  test_store_t s20[ 1 ];
  store_open( s20, TEST_STORE_BYTES, 25 );
  test_timeline_marker_limits( s20->gui );
  store_close( s20 );

  test_store_t s21[ 1 ];
  store_open( s21, TEST_STORE_BYTES, 26 );
  test_timeline_marker_order( s21->gui );
  store_close( s21 );

  test_store_t sv[ 1 ];
  store_open( sv, TEST_STORE_BYTES, 40 );
  test_votes( sv->gui );
  test_votes_raw_grow( sv->gui );
  store_close( sv );

  test_store_t sl[ 1 ];
  store_open( sl, TEST_STORE_BYTES, 41 );
  test_vote_latency( sl->gui );
  store_close( sl );

  test_store_t sb[ 1 ];
  store_open( sb, TEST_STORE_BYTES, 42 );
  test_vote_batch( sb->gui );
  store_close( sb );

  if( !run_all ) FD_LOG_NOTICE(( "skipped 8 expensive tests; pass --run-all to run them" ));
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
