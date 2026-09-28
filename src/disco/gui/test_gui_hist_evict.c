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

#define TEST_STORE_BYTES (5UL<<30)
#define TEST_TILE_CNT    (44UL)

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
  memset( rec->vote_count, 0xFF, sizeof(rec->vote_count) );

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
  if( dbi==FD_GUI_HIST_FEC_COMPLETIONS ) {
    fd_gui_store_kv_scan_t it;
    fd_gui_store_kv_scan_begin( gui->db, &it, FD_GUI_HIST_FEC_COMPLETIONS );
    while( fd_gui_store_kv_scan_next( &it ) ) cnt += slot==ULONG_MAX || ((fd_gui_fec_completion_record_t const *)it.rec)->key.slot==slot;
    return cnt;
  }
  if( dbi==FD_GUI_HIST_SHRED_EVENTS || dbi==FD_GUI_HIST_FEC_EVENTS ) {
    fd_gui_shred_event_iter_t it[ 1 ];
    if( dbi==FD_GUI_HIST_FEC_EVENTS ) fd_gui_fec_event_iter_begin( gui, it, 0L, LONG_MAX );
    else fd_gui_shred_event_iter_begin( gui, it, LONG_MIN, LONG_MAX );
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
    fd_gui_store_slot_duration_t duration = { .insert_time_ns=ts_ns, .midpoint_ns=ts_ns, .slot=s, .duration_ns=400000000UL };
    FD_TEST( !fd_gui_hist_ts_append( gui, FD_GUI_HIST_SLOT_DURATION, &duration ) );
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
  FD_TEST( count_ts( gui, FD_GUI_HIST_SLOT_DURATION,    ULONG_MAX )==30UL );

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
  FD_TEST( count_ts( gui, FD_GUI_HIST_SLOT_DURATION,    ULONG_MAX )==30UL );
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
  ulong capacity = (fd_gui_store_shared_free_region_cnt( gui->db )+fd_gui_hist_db_descs( TEST_STORE_BYTES, TEST_TILE_CNT )[ FD_GUI_HIST_TIMELINE_DAY ].base_regions)*cap;
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
  ulong max_cnt = fd_gui_hist_db_descs( TEST_STORE_BYTES, TEST_TILE_CNT )[ FD_GUI_HIST_EPOCH ].max_records;
  FD_TEST( max_cnt>=fd_gui_hist_db_descs( TEST_STORE_BYTES, TEST_TILE_CNT )[ FD_GUI_HIST_EPOCH ].base_regions*cap );
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
  s->gui->timeline_skipped_slot_watermark = ULONG_MAX;
  s->gui->timeline_skipped_bank_seq_watermark = ULONG_MAX;
  s->gui->timeline_skipped_coverage_start_ns = LONG_MAX;
  s->gui->timeline_skipped_coverage_end_ns = LONG_MAX;
  s->gui->slot_txn_scratch.max = 1UL;
  static fd_gui_ag_slot_t ag_slot[ 1 ] = {{ .slot = ULONG_MAX, .bank_seq = ULONG_MAX }};
  s->gui->ag.slot     = ag_slot;
  s->gui->ag.slot_cnt = 1UL;
  s->gui->tile_cnt = TEST_TILE_CNT;
  s->gui->cpu_util.last_slot = ULONG_MAX;
  s->gui->cpu_util.cur_day   = ULONG_MAX;

  s->db_mem = aligned_alloc( fd_gui_store_align(),
                             fd_ulong_align_up( fd_gui_store_footprint( map_bytes, fd_gui_hist_db_cnt(), fd_gui_hist_db_descs( TEST_STORE_BYTES, TEST_TILE_CNT ) ), fd_gui_store_align() ) );
  FD_TEST( s->db_mem );
  s->gui->db = fd_gui_store_join( fd_gui_store_new( s->db_mem, s->path, map_bytes, fd_gui_hist_db_cnt(), 0x0123456789abcdefUL, fd_gui_hist_db_descs( TEST_STORE_BYTES, TEST_TILE_CNT ) ) );
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
  fd_gui_store_desc_t const * descs = fd_gui_hist_db_descs( TEST_STORE_BYTES, TEST_TILE_CNT );
  FD_TEST( FD_GUI_HIST_TIMELINE_DAY==10 );
  FD_TEST( FD_GUI_HIST_REPLAY_TXN==11 );
  FD_TEST( FD_GUI_HIST_REPLAY_TXN_BATCH==12 );
  FD_TEST( FD_GUI_HIST_FEC_EVENTS==13 );
  FD_TEST( FD_GUI_HIST_FEC_COMPLETIONS==14 );
  FD_TEST( FD_GUI_HIST_SLOT_DURATION==15 );
  FD_TEST( FD_GUI_HIST_TIMELINE_TILE_DAY==16 );
  FD_TEST( FD_GUI_HIST_REPLAY_SLOT_STATE==18 );
  FD_TEST( FD_GUI_HIST_TIMELINE_TILE_STATE_DAY==19 );
  FD_TEST( FD_GUI_HIST_CNT==20 );
  FD_TEST( !strcmp( descs[ FD_GUI_HIST_REPLAY_SLOT_STATE ].name, "replay_slot_state" ) );
  FD_TEST( descs[ FD_GUI_HIST_REPLAY_SLOT_STATE ].kind==FD_GUI_STORE_KIND_TS );
  FD_TEST( descs[ FD_GUI_HIST_REPLAY_SLOT_STATE ].ts_off==offsetof(fd_gui_store_replay_slot_state_t,insert_time_ns) );
  FD_TEST( !strcmp( descs[ FD_GUI_HIST_TIMELINE_TILE_STATE_DAY ].name, "timeline_tile_state_day" ) );
  FD_TEST( descs[ FD_GUI_HIST_TIMELINE_TILE_STATE_DAY ].kind==FD_GUI_STORE_KIND_KV );
  FD_TEST( descs[ FD_GUI_HIST_TIMELINE_TILE_STATE_DAY ].key_sz==sizeof(fd_gui_hist_tile_day_key_t) );
  /* Today and yesterday for every execrp and replay tile. */
  FD_TEST( (descs[ FD_GUI_HIST_TIMELINE_TILE_STATE_DAY ].base_regions-1UL)*(FD_GUI_STORE_REGION_SZ/fd_ulong_align_up( sizeof(fd_gui_timeline_tile_state_day_t), 8UL ))>=
           2UL*fd_ulong_min( TEST_TILE_CNT, FD_GUI_TILE_STATE_POS_CNT ) );
  FD_TEST( descs[ FD_GUI_HIST_FEC_EVENT_ARCHIVE ].kind==FD_GUI_STORE_KIND_TS );
  FD_TEST( !strcmp( descs[ FD_GUI_HIST_SLOT_DURATION ].name, "slot_duration" ) );
  FD_TEST( descs[ FD_GUI_HIST_SLOT_DURATION ].val_sz==sizeof(fd_gui_store_slot_duration_t) );
  FD_TEST( descs[ FD_GUI_HIST_SLOT_DURATION ].val_sz==32UL );
  FD_TEST( descs[ FD_GUI_HIST_SLOT_DURATION ].kind==FD_GUI_STORE_KIND_TS );
  FD_TEST( descs[ FD_GUI_HIST_SLOT_DURATION ].key_sz==0UL );
  FD_TEST( descs[ FD_GUI_HIST_SLOT_DURATION ].ts_off==offsetof(fd_gui_store_slot_duration_t,insert_time_ns) );
  FD_TEST( descs[ FD_GUI_HIST_FEC_EVENTS ].val_sz==sizeof(fd_gui_fec_event_t) );
  FD_TEST( descs[ FD_GUI_HIST_FEC_COMPLETIONS ].val_sz==sizeof(fd_gui_fec_completion_record_t) );
  for( int dbi=FD_GUI_HIST_FEC_EVENTS; dbi<=FD_GUI_HIST_FEC_COMPLETIONS; dbi++ ) {
    FD_TEST( descs[ dbi ].kind==FD_GUI_STORE_KIND_KV && descs[ dbi ].key_sz==16UL );
    FD_TEST( descs[ dbi ].max_records==FD_GUI_FEC_RECORD_MAX );
    FD_TEST( fd_ulong_align_up( descs[ dbi ].val_sz, descs[ dbi ].val_align )<=32UL );
  }
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
  FD_TEST( descs[ FD_GUI_HIST_TIMELINE_TILE_DAY ].max_records>=descs[ FD_GUI_HIST_TIMELINE_TILE_DAY ].base_regions*(FD_GUI_STORE_REGION_SZ/sizeof(fd_gui_timeline_tile_day_t)) );
  /* Retention floors: today and yesterday for every tile, and
     FD_GUI_HIST_MIN_EPOCHS epochs of slot/leader/epoch records, survive
     with a full head region. */
  FD_TEST( (descs[ FD_GUI_HIST_TIMELINE_TILE_DAY ].base_regions-1UL)*(FD_GUI_STORE_REGION_SZ/sizeof(fd_gui_timeline_tile_day_t))>=2UL*TEST_TILE_CNT );
  FD_TEST( (descs[ FD_GUI_HIST_SLOT        ].base_regions-1UL)*(FD_GUI_STORE_REGION_SZ/fd_ulong_align_up( descs[ FD_GUI_HIST_SLOT        ].val_sz, 8UL ))>=FD_GUI_HIST_MIN_EPOCHS*MAX_SLOTS_PER_EPOCH );
  FD_TEST( (descs[ FD_GUI_HIST_LEADER_SLOT ].base_regions-1UL)*(FD_GUI_STORE_REGION_SZ/fd_ulong_align_up( descs[ FD_GUI_HIST_LEADER_SLOT ].val_sz, 8UL ))>=FD_GUI_HIST_MIN_EPOCHS*FD_GUI_HIST_MAX_LEADER_SLOTS_PER_EPOCH );
  FD_TEST( (descs[ FD_GUI_HIST_EPOCH       ].base_regions-1UL)*(FD_GUI_STORE_REGION_SZ/fd_ulong_align_up( descs[ FD_GUI_HIST_EPOCH       ].val_sz, 8UL ))>=FD_GUI_HIST_MIN_EPOCHS );
  FD_TEST( descs[ FD_GUI_HIST_TIMELINE_DAY ].base_regions>=2UL );
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

  fd_http_server_params_t params = {
    .max_connection_cnt    = 1UL,
    .max_ws_connection_cnt = 1UL,
    .max_request_len       = 1024UL,
    .max_ws_recv_frame_len = 1024UL,
    .max_ws_send_frame_cnt = 4UL,
    .outgoing_buffer_sz    = 1UL<<20
  };
  void * http_mem = aligned_alloc( fd_http_server_align(), fd_http_server_footprint( params ) );
  FD_TEST( http_mem );
  gui->http = fd_http_server_join( fd_http_server_new( http_mem, params, (fd_http_server_callbacks_t){0}, NULL ) );
  FD_TEST( gui->http );
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

  FD_TEST( fd_http_server_delete( fd_http_server_leave( gui->http ) )==http_mem );
  free( http_mem );
  gui->http = NULL;
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
  fd_gui_event_slots_close_before( gui, 702UL );
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
  gui->timeline_skipped_slot_watermark = ULONG_MAX;
  gui->timeline_skipped_coverage_start_ns = LONG_MAX;
  gui->timeline_skipped_coverage_end_ns = LONG_MAX;

  fd_gui_shred_event_append( gui, 899UL, 1UL, FD_GUI_SLOT_SHRED_SHRED_RECEIVED_TURBINE, 1L, 1L );
  fd_gui_shred_event_append( gui, 900UL, 2UL, FD_GUI_SLOT_SHRED_SHRED_RECEIVED_REPAIR,  2L, 2L );
  fd_gui_shred_event_append( gui, 901UL, 3UL, FD_GUI_SLOT_SHRED_SHRED_PUBLISHED,        3L, 3L );
  fd_gui_shred_event_append( gui, 898UL, 4UL, FD_GUI_SLOT_SHRED_SHRED_REPLAY_EXEC_DONE, 4L, 4L );
  fd_gui_shred_event_append( gui, 902UL, 5UL, FD_GUI_SLOT_SHRED_REPAIR_REQUEST,          5L, 5L );

  put_slot( gui, 900UL, 6L );
  fd_gui_slot_get( gui, 900UL, BANK_SEQ )->parent_slot = ULONG_MAX;
  fd_gui_handle_root_advanced( gui, 900UL, BANK_SEQ, 6L );

  FD_TEST( gui->shreds.closed_before_slot==900UL );
  FD_TEST( gui->shreds.builder.batch.event_cnt==5UL );
  FD_TEST( count_ts( gui, FD_GUI_HIST_SHRED_EVENTS, 898UL )==1UL );
  FD_TEST( count_ts( gui, FD_GUI_HIST_SHRED_EVENTS, 899UL )==1UL );

  fd_gui_shred_event_append( gui, 899UL, 6UL, FD_GUI_SLOT_SHRED_SHRED_RECEIVED_TURBINE, 7L, 7L );
  FD_TEST( gui->shreds.dropped_event_cnt==1UL );
  FD_TEST( gui->shreds.builder.batch.event_cnt==5UL );

  put_slot( gui, 899UL, 8L );
  fd_gui_slot_get( gui, 899UL, BANK_SEQ )->parent_slot = ULONG_MAX;
  fd_gui_handle_root_advanced( gui, 900UL, BANK_SEQ, 8L );
  FD_TEST( gui->shreds.closed_before_slot==900UL );
  fd_gui_handle_root_advanced( gui, 899UL, BANK_SEQ, 8L );
  FD_TEST( gui->shreds.closed_before_slot==900UL );

  put_slot( gui, 901UL, 9L );
  fd_gui_slot_get( gui, 901UL, BANK_SEQ )->parent_slot = ULONG_MAX;
  fd_gui_handle_root_advanced( gui, 901UL, BANK_SEQ, 9L );

  FD_TEST( gui->shreds.closed_before_slot==901UL );
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
  FD_TEST( !fd_gui_event_slot_permanently_closed( gui, 901UL ) );
  FD_TEST( count_ts( gui, FD_GUI_HIST_SHRED_EVENTS, 901UL )==2UL );
  fd_gui_shred_event_append( gui, 901UL, 7UL, FD_GUI_SLOT_SHRED_SHRED_RECEIVED_TURBINE, 11L, 11L );
  FD_TEST( gui->shreds.dropped_event_cnt==1UL );
  FD_TEST( count_ts( gui, FD_GUI_HIST_SHRED_EVENTS, 901UL )==3UL );

  put_slot( gui, 902UL, 12L );
  fd_gui_slot_get( gui, 902UL, BANK_SEQ )->parent_slot = ULONG_MAX;
  fd_gui_handle_root_advanced( gui, 902UL, BANK_SEQ, 12L );
  FD_TEST( fd_gui_event_slot_permanently_closed( gui, 901UL ) );
  FD_TEST( !fd_gui_event_slot_permanently_closed( gui, 902UL ) );
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
  fd_gui_fec_event_append( gui, 100UL, 0UL, key.event, 1L, ts+sec_ns( 5UL ) );
  fd_gui_fec_event_append( gui, 100UL, 0UL, key.event, ts+40L, ts+sec_ns( 6UL ) );
  FD_TEST( first->event_time_ns==1L && first->insert_time_ns==ts+30L );
  /* A full open event head must not synchronously drain a closed
     completion backlog on the unrelated channel. */
  for( ulong i=0UL; i<2048UL; i++ )
    FD_TEST( fd_gui_fec_completion_append( gui, 50UL, ts+(long)i, 1UL, 0UL, 0UL, 0, ts ) );
  fd_gui_event_slots_close_before( gui, 51UL );
  fd_gui_fec_event_append( gui, 999UL, 0UL, key.event, ts, ts );
  FD_TEST( gui->shreds.dropped_fec_event_cnt==1UL );
  fd_gui_store_kv_scan_t completions;
  fd_gui_store_kv_scan_begin( gui->db, &completions, FD_GUI_HIST_FEC_COMPLETIONS );
  FD_TEST( completions.end-completions.cur==2048UL );
  long archive_start = fd_log_wallclock();
  FD_TEST( fd_gui_fec_archive_channel( gui, FD_GUI_HIST_FEC_COMPLETIONS, 2048UL )==2048UL );
  FD_LOG_NOTICE(( "FEC archive: 2048 completions %.3f ms (includes first file growth)", (double)(fd_log_wallclock()-archive_start)/1e6 ));
  FD_TEST( !fd_gui_hist_evict_step( gui ) );
  fd_gui_shred_event_iter_t it;
  fd_gui_fec_event_iter_begin( gui, &it, 1L, 1L );
  FD_TEST( fd_gui_shred_event_iter_next( &it ) && it.event.event_time_ns==1L && it.event.slot==100U );
  FD_TEST( !fd_gui_shred_event_iter_next( &it ) );
  fd_gui_shred_event_iter_end( &it );

  long start = fd_log_wallclock();
  for( ulong round=0UL; round<8UL; round++ ) {
    fd_gui_fec_event_iter_begin( gui, &it, 0L, LONG_MAX );
    for( ulong i=0UL; i<cnt; i++ ) {
      FD_TEST( fd_gui_shred_event_iter_next( &it ) );
      FD_TEST( it.event.slot==100UL+i/65535UL && it.event.idx==i%65535UL );
      FD_TEST( it.event.event_time_ns==(i ? ts+20L : 1L) );
    }
    FD_TEST( !fd_gui_shred_event_iter_next( &it ) );
    fd_gui_shred_event_iter_end( &it );
  }
  FD_LOG_NOTICE(( "FEC scan: %lu records, %.3f ms/scan", cnt, (double)(fd_log_wallclock()-start)/8e6 ));
  void * http_mem = timeline_http_open( gui );
  start = fd_log_wallclock();
  FD_TEST( !fd_gui_printf_timeline_query_fec_events( gui, 1L, 2L, 7UL ) );
  long elapsed = fd_log_wallclock() - start;
  test_json_t json = timeline_response( gui );
  FD_TEST( test_json_count( timeline_value( json, "idx" ) )==1 );
  FD_LOG_NOTICE(( "FEC narrow query including availability: %lu retained records, %.3f ms", cnt, (double)elapsed/1e6 ));
  FD_TEST( fd_http_server_delete( fd_http_server_leave( gui->http ) )==http_mem );
  free( http_mem );
  gui->http = NULL;

  fd_gui_event_slots_close_before( gui, 101UL );
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
  fd_gui_fec_event_append( gui, key.slot, key.idx, key.event, 2L, ts+70L );
  FD_TEST( ((fd_gui_fec_event_t *)fd_gui_hist_kv_get( gui, FD_GUI_HIST_FEC_EVENTS, &key ))->event_time_ns==2L );
  FD_TEST( gui->shreds.dropped_fec_event_cnt==2UL );

  fd_gui_event_slots_close_before( gui, 1001UL );
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
     retention ceiling and includes the timestamp updated far into the past. */
  FD_TEST( count_ts( gui, FD_GUI_HIST_FEC_EVENTS, ULONG_MAX )==2UL*cnt+65535UL );
  fd_gui_fec_event_iter_begin( gui, &it, 1L, 1L );
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
  FD_TEST( !fd_gui_fec_completion_append( gui, 1000000UL, ts, 32UL, 0UL, 0UL, 0, ts ) );
  FD_TEST( gui->shreds.dropped_fec_event_cnt==2UL && gui->shreds.dropped_completion_cnt==1UL );

  ulong const cutoff = 1000000UL;
  fd_gui_event_slots_close_before( gui, cutoff );
  ulong const far = cutoff+FD_GUI_FEC_SLOT_HORIZON;
  fd_gui_fec_event_append( gui, far, 0UL, event, ts, ts );
  FD_TEST( !fd_gui_fec_completion_append( gui, far, ts, 32UL, 0UL, 0UL, 0, ts ) );
  FD_TEST( gui->shreds.dropped_fec_event_cnt==3UL && gui->shreds.dropped_completion_cnt==2UL );
  fd_gui_fec_event_append( gui, far-1UL, 0UL, event, ts, ts );
  FD_TEST( fd_gui_fec_completion_append( gui, far-1UL, ts, 32UL, 0UL, 0UL, 0, ts )==1 );
  FD_TEST( gui->shreds.dropped_fec_event_cnt==3UL && gui->shreds.dropped_completion_cnt==2UL );

  /* far-1 stays open and pins later admissions until the cutoff moves
     past it, which happens within the horizon of slots. */
  for( ulong slot=cutoff; slot<cutoff+16UL; slot++ ) {
    fd_gui_fec_event_append( gui, slot, 0UL, event, ts, ts );
    FD_TEST( fd_gui_fec_completion_append( gui, slot, ts, 32UL, 0UL, 0UL, 0, ts )==1 );
  }
  fd_gui_event_slots_close_before( gui, cutoff+16UL );
  FD_TEST( !fd_gui_fec_archive( gui, 512UL ) );
  fd_gui_event_slots_close_before( gui, far );
  FD_TEST( fd_gui_fec_archive( gui, 512UL )==34UL );
  FD_TEST( !count_ts( gui, FD_GUI_HIST_FEC_COMPLETIONS, ULONG_MAX ) );
  fd_gui_fec_event_append( gui, far+FD_GUI_FEC_SLOT_HORIZON-1UL, 0UL, event, ts, ts );
  FD_TEST( gui->shreds.dropped_fec_event_cnt==3UL );
  FD_LOG_NOTICE(( "test_fec_slot_horizon: ok" ));
}

static void
test_fec_archive( fd_gui_t * gui ) {
  long ts = sec_ns( 10UL );
  fd_gui_fec_event_append( gui, 100UL, 0UL, FD_GUI_SLOT_SHRED_REPAIR_REQUEST, ts, ts );
  fd_gui_fec_event_append( gui, 100UL, 0UL, FD_GUI_SLOT_SHRED_REPAIR_REQUEST, 1L, ts+1L );
  fd_gui_fec_event_append( gui, 101UL, 0UL, FD_GUI_SLOT_SHRED_REPAIR_REQUEST, ts+2L, ts+2L );
  FD_TEST( fd_gui_fec_completion_append( gui, 100UL, ts, 32UL, 16UL, 8UL, 1, ts ) );
  FD_TEST( !fd_gui_fec_completion_append( gui, 100UL, ts, 32UL, 16UL, 8UL, 1, ts ) );
  fd_gui_shred_event_slot_complete( gui, 101UL, ts+3L, ts+3L );
  FD_TEST( !fd_gui_fec_archive( gui, 512UL ) ); /* completion closes nothing */
  fd_gui_event_slots_close_before( gui, 101UL );
  /* One event moves to the archive and the closed completion is
     dropped from staging, not archived. */
  FD_TEST( fd_gui_fec_archive( gui, 1UL )==2UL );
  FD_TEST( count_ts( gui, FD_GUI_HIST_FEC_EVENTS, ULONG_MAX )==3UL );
  FD_TEST( !count_ts( gui, FD_GUI_HIST_FEC_COMPLETIONS, ULONG_MAX ) );
  FD_TEST( !fd_gui_fec_archive( gui, 512UL ) ); /* open 101 pins its marker */
  fd_gui_event_slots_close_before( gui, 102UL );
  FD_TEST( fd_gui_fec_archive( gui, 512UL )==2UL );
  FD_TEST( !fd_gui_fec_archive( gui, 512UL ) );
  fd_gui_fec_event_key_t key = { .slot=100U, .idx=0U, .event=FD_GUI_SLOT_SHRED_REPAIR_REQUEST };
  FD_TEST( !fd_gui_hist_kv_get( gui, FD_GUI_HIST_FEC_EVENTS, &key ) );
  fd_gui_fec_event_append( gui, 100UL, 0UL, key.event, 0L, ts+4L );
  FD_TEST( gui->shreds.dropped_fec_event_cnt==1UL );
  FD_TEST( !fd_gui_fec_completion_append( gui, 100UL, ts, 32UL, 16UL, 8UL, 1, ts+4L ) );
  /* Late completion markers are distinct, even after the first marker has
     already left staging and the slot has closed, and arrive more than 30
     days later. */
  long late = ts+sec_ns( 30UL*24UL*60UL*60UL+10UL );
  fd_gui_shred_event_slot_complete( gui, 101UL, 2L, late );
  FD_TEST( fd_gui_fec_archive( gui, 512UL )==1UL );
  FD_TEST( count_ts( gui, FD_GUI_HIST_FEC_EVENTS, ULONG_MAX )==4UL );
  long lo, hi;
  FD_TEST( fd_gui_event_bounds( gui, FD_GUI_HIST_FEC_EVENTS, &lo, &hi ) );
  FD_TEST( lo==1L && hi==ts+4L );
  fd_gui_shred_event_iter_t it;
  fd_gui_fec_event_iter_begin( gui, &it, 1L, 2L );
  FD_TEST( fd_gui_shred_event_iter_next( &it ) && it.event.event_time_ns==1L );
  FD_TEST( fd_gui_shred_event_iter_next( &it ) && it.event.event_time_ns==2L && it.event.insert_time_ns==late );
  FD_TEST( !fd_gui_shred_event_iter_next( &it ) );
  fd_gui_shred_event_iter_end( &it );

  /* An admission gap too large for the delta codec must remain exact. */
  fd_gui_fec_event_append( gui, 102UL, 0UL, key.event, 3L, late+1L );
  fd_gui_fec_event_append( gui, 102UL, 1UL, key.event, 4L, late+(long)UINT_MAX+2L );
  fd_gui_event_slots_close_before( gui, 103UL );
  FD_TEST( fd_gui_fec_archive( gui, 512UL )==2UL );
  fd_gui_fec_event_iter_begin( gui, &it, 3L, 4L );
  FD_TEST( fd_gui_shred_event_iter_next( &it ) && it.event.insert_time_ns==late+1L );
  FD_TEST( fd_gui_shred_event_iter_next( &it ) && it.event.insert_time_ns==late+(long)UINT_MAX+2L );
  FD_TEST( !fd_gui_shred_event_iter_next( &it ) );
  fd_gui_shred_event_iter_end( &it );

  /* Completion staging only drains behind the cutoff, so it stays within
     its quota while slots keep closing, without archiving anything. */
  long reclaim_total = 0L;
  long reclaim_max = 0L;
  for( ulong i=0UL; i<FD_GUI_FEC_RECORD_MAX+1UL; i++ ) {
    ulong slot = 200UL+i/1024UL;
    FD_TEST( fd_gui_fec_completion_append( gui, slot, late+(long)i, 32UL, 16UL, 8UL, 1, late+(long)i ) );
    if( i%1024UL==1023UL ) {
      fd_gui_event_slots_close_before( gui, slot+1UL );
      long start = fd_log_wallclock();
      FD_TEST( fd_gui_fec_archive( gui, 1024UL )==1024UL );
      long elapsed = fd_log_wallclock()-start;
      reclaim_total += elapsed;
      reclaim_max = fd_long_max( reclaim_max, elapsed );
    }
  }
  FD_TEST( count_ts( gui, FD_GUI_HIST_FEC_COMPLETIONS, ULONG_MAX )==1UL );
  FD_LOG_NOTICE(( "FEC completion reclaim: 1024 passes, mean %.3f ms, max %.3f ms", (double)reclaim_total/1024e6, (double)reclaim_max/1e6 ));
  FD_LOG_NOTICE(( "test_fec_archive: closed-prefix handoff, late timestamps/markers, completion quota: ok" ));
}

static void
test_fec_footprint( ulong bytes ) {
  fd_gui_store_desc_t descs[ FD_GUI_HIST_CNT ];
  memcpy( descs, fd_gui_hist_db_descs( bytes, TEST_TILE_CNT ), sizeof(descs) );
  /* Per-DB base regions for TEST_TILE_CNT tiles fit the configured
     5 GiB floor, as does the largest topology. */
  ulong min_size = fd_gui_store_min_size( FD_GUI_HIST_CNT, descs );
  FD_TEST( min_size>FD_GUI_HIST_CNT*2UL*FD_GUI_STORE_REGION_SZ && min_size<=(5UL<<30) );
  /* Only the tile-day base depends on the tile count; the largest
     topology must also fit the configured 5 GiB floor
     (src/app/shared/fd_config.c). */
  ulong tile_day_cap = FD_GUI_STORE_REGION_SZ/fd_ulong_align_up( sizeof(fd_gui_timeline_tile_day_t), 8UL );
  ulong max_tile_base = (2UL*FD_TOPO_MAX_TILES+tile_day_cap-1UL)/tile_day_cap + 1UL;
  ulong max_min_size  = min_size + (max_tile_base-descs[ FD_GUI_HIST_TIMELINE_TILE_DAY ].base_regions)*FD_GUI_STORE_REGION_SZ;
  FD_TEST( max_min_size<=(5UL<<30) );
  FD_LOG_NOTICE(( "GUI DB minimum: %lu MiB for %lu tiles, %lu MiB for %lu tiles", min_size>>20, TEST_TILE_CNT,
                  max_min_size>>20, (ulong)FD_TOPO_MAX_TILES ));
  FD_TEST( !fd_gui_store_footprint( min_size-1UL, FD_GUI_HIST_CNT, descs ) );
  FD_TEST( fd_gui_store_footprint( min_size, FD_GUI_HIST_CNT, descs ) );
  FD_TEST( fd_gui_store_footprint( 5UL<<30, FD_GUI_HIST_CNT, descs ) );
  ulong current = fd_gui_store_footprint( bytes, FD_GUI_HIST_CNT, descs );
  for( int dbi=FD_GUI_HIST_FEC_EVENTS; dbi<=FD_GUI_HIST_FEC_COMPLETIONS; dbi++ ) {
    descs[ dbi ].kind        = FD_GUI_STORE_KIND_TS;
    descs[ dbi ].key_sz      = 0UL;
    descs[ dbi ].key_hash    = NULL;
    descs[ dbi ].key_cmp     = NULL;
    descs[ dbi ].max_records = 0UL;
  }
  ulong old = fd_gui_store_footprint( bytes, FD_GUI_HIST_CNT, descs );
  FD_TEST( current>old );
  FD_TEST( current-old<73UL*1024UL*1024UL );
  FD_TEST( sizeof(((fd_gui_timeline_scratch_t *)0)->events)<sizeof(fd_gui_timeline_scratch_t) );
  FD_LOG_NOTICE(( "FEC RAM: store %lu, two-TS baseline %lu, added KV indices %lu bytes",
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
  FD_TEST( !gui->shreds.dropped_completion_cnt );
  FD_TEST( count_ts( gui, FD_GUI_HIST_FEC_COMPLETIONS, ULONG_MAX )==1UL );
  FD_TEST( fd_gui_timeline_day_get( gui, 0UL ) );
  ulong evicts = fd_gui_store_metrics( gui->db )->evict_records[ FD_GUI_HIST_SCHEDULER_COUNTS ];
  fd_gui_fec_event_append( gui, 100UL, 0UL, FD_GUI_SLOT_SHRED_REPAIR_REQUEST, 1L, ts+sec_ns( 9UL ) );
  fd_gui_fec_event_append( gui, 101UL, 0UL, FD_GUI_SLOT_SHRED_REPAIR_REQUEST, 2L, ts );
  fd_gui_timeline_handle_fec( gui, 100UL, 1, ts, 32UL, 16UL, 8UL, ts );
  FD_TEST( !gui->shreds.dropped_completion_cnt && !gui->shreds.dropped_fec_event_cnt );
  FD_TEST( fd_gui_store_metrics( gui->db )->evict_records[ FD_GUI_HIST_SCHEDULER_COUNTS ]==evicts );
  FD_TEST( count_ts( gui, FD_GUI_HIST_FEC_EVENTS, ULONG_MAX )==2UL );
  for( ulong i=0UL; i<3UL*(FD_GUI_STORE_REGION_SZ/sizeof(counts)); i++ ) append_sched_counts( gui, ts );
  FD_TEST( count_ts( gui, FD_GUI_HIST_FEC_EVENTS, ULONG_MAX )==2UL );
  FD_TEST( count_ts( gui, FD_GUI_HIST_FEC_COMPLETIONS, ULONG_MAX )==1UL );
  FD_LOG_NOTICE(( "test_fec_base_admission: late FEC admission and retention under sustained pressure: ok" ));
}

/* In a minimum-size store with every other DB's base full, day rollover
   for TEST_TILE_CNT tiles only evicts records of earlier days: today's
   and yesterday's records for every tile always survive. */
static void
test_tile_day_minimum_store( fd_gui_t * gui ) {
  fd_gui_scheduler_counts_t counts = { .sample_time_ns=1L };
  while( fd_gui_store_ts_append( gui->db, FD_GUI_HIST_SCHEDULER_COUNTS, &counts )==FD_GUI_STORE_SUCCESS ) {}
  FD_TEST( !fd_gui_store_shared_free_region_cnt( gui->db ) );
  for( ulong day=0UL; day<5UL; day++ ) {
    for( ulong t=0UL; t<TEST_TILE_CNT; t++ ) {
      fd_gui_hist_tile_day_key_t key = { .day_idx=day, .tile_idx=t };
      fd_gui_timeline_tile_day_t * rec = fd_gui_hist_kv_get_or_create( gui, FD_GUI_HIST_TIMELINE_TILE_DAY, &key );
      FD_TEST( rec );
      rec->insert_time_ns = (long)day;
      for( ulong d=day ? day-1UL : 0UL; d<=day; d++ )
        for( ulong u=0UL; u<(d==day ? t+1UL : TEST_TILE_CNT); u++ )
          FD_TEST( fd_gui_timeline_tile_day_get( gui, d, u ) );
    }
  }
  FD_TEST( fd_gui_store_metrics( gui->db )->evict_records[ FD_GUI_HIST_TIMELINE_TILE_DAY ] );
  FD_LOG_NOTICE(( "test_tile_day_minimum_store: today and yesterday survive rollover: ok" ));
}

static void
test_fec_minimum_store( fd_gui_t * gui ) {
  ulong free_before = fd_gui_store_free_region_cnt( gui->db );
  fd_gui_store_desc_t const * descs = fd_gui_hist_db_descs( TEST_STORE_BYTES, TEST_TILE_CNT );
  ulong base_cnt = 0UL;
  for( ulong i=0UL; i<FD_GUI_HIST_CNT; i++ ) base_cnt += descs[ i ].base_regions;
  FD_TEST( free_before==base_cnt );
  fd_gui_fec_event_append( gui, 100UL, 0UL, FD_GUI_SLOT_SHRED_REPAIR_REQUEST, 1L, 1L );
  FD_TEST( fd_gui_fec_completion_append( gui, 100UL, 1L, 32UL, 16UL, 8UL, 1, 1L ) );
  FD_TEST( !gui->shreds.dropped_fec_event_cnt && !gui->shreds.dropped_completion_cnt );
  FD_TEST( fd_gui_store_free_region_cnt( gui->db )==free_before-2UL );
  append_sched_counts( gui, 1L );
  FD_TEST( count_ts( gui, FD_GUI_HIST_SCHEDULER_COUNTS, ULONG_MAX )==1UL );
  FD_TEST( !fd_gui_hist_evict_step( gui ) );
  FD_LOG_NOTICE(( "test_fec_minimum_store: all bases fit: ok" ));
}

/* Explicit owner deletion for closure/query fixtures.  Production quota
   pressure and the pinned-head retry are exercised by test_fec_event_index. */
static int
closed_fec( ulong dbi, void const * rec, void * gui ) {
  ulong slot = dbi==FD_GUI_HIST_FEC_EVENTS ? ((fd_gui_fec_event_t const *)rec)->key.slot
                                         : ((fd_gui_fec_completion_record_t const *)rec)->key.slot;
  return fd_gui_event_slot_permanently_closed( gui, slot );
}

static ulong
reclaim_closed_fec( fd_gui_t * gui ) {
  return fd_gui_store_reclaim( gui->db, FD_GUI_HIST_FEC_EVENTS, ULONG_MAX, closed_fec, gui )
       + fd_gui_store_reclaim( gui->db, FD_GUI_HIST_FEC_COMPLETIONS, ULONG_MAX, closed_fec, gui );
}

static void
test_fec_prefix_guards( fd_gui_t * gui ) {
  long ts = sec_ns( 10UL );
  fd_gui_fec_event_append( gui, 100UL, 0UL, FD_GUI_SLOT_SHRED_REPAIR_REQUEST, ts, ts );
  fd_gui_fec_event_append( gui, 101UL, 0UL, FD_GUI_SLOT_SHRED_REPAIR_REQUEST, ts, ts );
  FD_TEST( fd_gui_fec_completion_append( gui, 100UL, ts, 32UL, 16UL, 8UL, 1, ts )==1 );
  FD_TEST( fd_gui_fec_completion_append( gui, 101UL, ts, 32UL, 16UL, 8UL, 1, ts )==1 );
  /* Replay completion and a completed slot record do not close a slot,
     so its records are neither reclaimed nor locked out. */
  fd_gui_shred_event_slot_complete( gui, 101UL, ts, ts );
  fd_gui_shred_flush( gui, ts+sec_ns( 1UL ) );
  FD_TEST( !fd_gui_hist_evict_step( gui ) );
  FD_TEST( !reclaim_closed_fec( gui ) );
  FD_TEST( count_ts( gui, FD_GUI_HIST_FEC_EVENTS, ULONG_MAX )==3UL );
  FD_TEST( count_ts( gui, FD_GUI_HIST_FEC_COMPLETIONS, ULONG_MAX )==2UL );
  put_slot( gui, 100UL, ts );
  FD_TEST( !fd_gui_event_slot_permanently_closed( gui, 100UL ) );
  fd_gui_shred_event_append( gui, 100UL, 1UL, FD_GUI_SLOT_SHRED_REPAIR_REQUEST, ts, ts );
  FD_TEST( !gui->shreds.dropped_event_cnt );
  FD_TEST( gui->shreds.builder.batch.event_cnt==1UL );
  FD_TEST( !reclaim_closed_fec( gui ) );
  fd_gui_event_slots_close_before( gui, 102UL );
  FD_TEST( fd_gui_event_slot_permanently_closed( gui, 100UL ) && fd_gui_event_slot_permanently_closed( gui, 101UL ) );
  FD_TEST( reclaim_closed_fec( gui ) );
  FD_TEST( !count_ts( gui, FD_GUI_HIST_FEC_EVENTS, ULONG_MAX ) );
  FD_TEST( !count_ts( gui, FD_GUI_HIST_FEC_COMPLETIONS, ULONG_MAX ) );
  fd_gui_fec_event_append( gui, 100UL, 0UL, FD_GUI_SLOT_SHRED_REPAIR_REQUEST, 1L, ts );
  FD_TEST( !fd_gui_fec_completion_append( gui, 101UL, ts, 32UL, 16UL, 8UL, 1, ts ) );
  FD_TEST( gui->shreds.dropped_fec_event_cnt==1UL && gui->shreds.dropped_completion_cnt==1UL );
  FD_TEST( fd_gui_fec_completion_append( gui, 102UL, ts, 32UL, 16UL, 8UL, 1, ts )==1 );
  FD_TEST( !fd_gui_fec_completion_append( gui, 102UL, ts, 32UL, 16UL, 8UL, 7, ts+sec_ns( 9UL ) ) );
  FD_TEST( fd_gui_fec_completion_append( gui, 102UL, ts, 31UL, 16UL, 8UL, 1, ts )==1 );
  FD_TEST( fd_gui_fec_completion_append( gui, 102UL, ts, 32UL, 15UL, 8UL, 1, ts )==1 );
  FD_TEST( fd_gui_fec_completion_append( gui, 102UL, ts, 32UL, 16UL, 7UL, 1, ts )==1 );
  FD_TEST( fd_gui_fec_completion_append( gui, 102UL, ts, 32UL, 16UL, 8UL, 0, ts )==1 );
  FD_TEST( count_ts( gui, FD_GUI_HIST_FEC_COMPLETIONS, ULONG_MAX )==5UL );
  FD_TEST( gui->shreds.dropped_completion_cnt==1UL );
  FD_LOG_NOTICE(( "test_fec_prefix_guards: no selective eviction, permanent vs transient closure, complete identity: ok" ));
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
  FD_TEST( test_json_string_eq( timeline_value( json, "available_start_ns" ), "10000000010" ) );
  FD_TEST( test_json_string_eq( timeline_value( json, "available_end_ns" ), "10000000031" ) );
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
  FD_TEST( count_ts( gui, FD_GUI_HIST_FEC_COMPLETIONS, 100UL )==2UL );
  FD_TEST( !gui->shreds.dropped_completion_cnt );
  fd_gui_timeline_day_t const * day = fd_gui_timeline_day_get( gui, 0UL );
  FD_TEST( day );
  FD_TEST( fd_gui_timeline_field_get( day, FD_GUI_TIMELINE_GRANULARITY_250MS, FD_GUI_TIMELINE_FIELD_PUBLISHED, 40UL )==128UL );
  FD_TEST( fd_gui_timeline_field_get( day, FD_GUI_TIMELINE_GRANULARITY_250MS, FD_GUI_TIMELINE_FIELD_TURBINE, 40UL )==64UL );
  FD_TEST( !fd_gui_fec_completion_append( gui, 100UL, ts+12L, 65UL, 0UL, 0UL, 0, ts ) );
  FD_TEST( !fd_gui_fec_completion_append( gui, 100UL, ts+12L, 0UL, 65UL, 0UL, 0, ts ) );
  FD_TEST( !fd_gui_fec_completion_append( gui, 100UL, ts+12L, 0UL, 0UL, 65UL, 0, ts ) );
  FD_TEST( gui->shreds.dropped_completion_cnt==3UL );
  FD_TEST( count_ts( gui, FD_GUI_HIST_FEC_COMPLETIONS, ULONG_MAX )==2UL );

  FD_TEST( !fd_gui_printf_timeline_query_agg( gui, "query_agg_shreds", "250ms", 3UL, ts, 1UL, 7UL ) );
  json = timeline_response( gui );
  FD_TEST( test_json_ulong( test_json_index( timeline_value( json, "published" ), 0 ) )==128UL );
  FD_TEST( test_json_ulong( test_json_index( timeline_value( json, "repair" ), 0 ) )==32UL );
  FD_TEST( test_json_string_eq( timeline_value( json, "available_start_ns" ), "0" ) );
  FD_TEST( test_json_string_eq( timeline_value( json, "available_end_ns" ), "86400000000000" ) );

  /* Slot aggregates come from the same day record as the shreds. */
  FD_TEST( !fd_gui_printf_timeline_query_agg( gui, "query_agg_slots", "250ms", 3UL, ts, 1UL, 7UL ) );
  json = timeline_response( gui );
  FD_TEST( test_json_string_eq( timeline_value( json, "available_start_ns" ), "0" ) );
  FD_TEST( test_json_ulong( test_json_index( timeline_value( json, "start_slot" ), 0 ) )==100UL );
  FD_TEST( test_json_ulong( test_json_index( timeline_value( json, "end_slot" ), 0 ) )==100UL );

  fd_gui_event_slots_close_before( gui, 101UL );
  /* One event is archived and two completions are dropped; queries now
     merge archive + open KV. */
  FD_TEST( fd_gui_fec_archive( gui, 512UL )==3UL );
  FD_TEST( !fd_gui_printf_timeline_query_agg( gui, "query_agg_shreds", "250ms", 3UL, ts, 1UL, 7UL ) );
  json = timeline_response( gui );
  FD_TEST( test_json_ulong( test_json_index( timeline_value( json, "published" ), 0 ) )==128UL );
  FD_TEST( test_json_ulong( test_json_index( timeline_value( json, "repair" ), 0 ) )==32UL );
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


  fd_gui_event_slots_close_before( gui, 101UL );
  FD_TEST( gui->shreds.builder.batch.event_cnt==1UL );
  FD_TEST( count_ts( gui, FD_GUI_HIST_FEC_EVENTS, ULONG_MAX )==2UL );
  FD_TEST( !count_ts( gui, FD_GUI_HIST_FEC_COMPLETIONS, ULONG_MAX ) );
  fd_gui_shred_event_iter_t ei;
  fd_gui_fec_event_iter_begin( gui, &ei, ts, ts+100L );
  FD_TEST( fd_gui_shred_event_iter_next( &ei ) && ei.event.slot==100UL && ei.event.idx==1U );
  FD_TEST( fd_gui_shred_event_iter_next( &ei ) && ei.event.slot==101UL && ei.event.idx==2U );
  FD_TEST( !fd_gui_shred_event_iter_next( &ei ) );
  fd_gui_shred_event_iter_end( &ei );
  fd_gui_event_slots_close_before( gui, 99UL );
  fd_gui_shred_event_append( gui, 100UL, 33UL, FD_GUI_SLOT_SHRED_REPAIR_REQUEST, ts+60L, ts+60L );
  FD_TEST( gui->shreds.closed_before_slot==101UL && gui->shreds.dropped_event_cnt==1UL );

  fd_gui_shred_event_slot_complete( gui, 101UL, ts+70L, ts+70L );
  fd_gui_shred_event_slot_complete( gui, 101UL, ts+80L, ts+80L );
  fd_gui_fec_event_iter_begin( gui, &ei, ts+70L, ts+80L );
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
  fd_gui_event_slots_close_before( gui, 102UL );
  fd_gui_fec_event_append( gui, 101UL, 4UL, FD_GUI_SLOT_SHRED_REPAIR_REQUEST, ts+90L, ts );
  FD_TEST( gui->shreds.dropped_fec_event_cnt==1UL );
  FD_TEST( count_ts( gui, FD_GUI_HIST_FEC_EVENTS, ULONG_MAX )==6UL );
  day = fd_gui_timeline_day_get( gui, 0UL );
  FD_TEST( day && fd_gui_timeline_field_get( day, FD_GUI_TIMELINE_GRANULARITY_250MS, FD_GUI_TIMELINE_FIELD_PUBLISHED, 40UL )==128UL );

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
  FD_TEST( !gui->shreds.closed_before_slot );
  ulong dropped = gui->shreds.dropped_event_cnt;
  fd_gui_shred_event_append( gui, 1UL, 32UL, FD_GUI_SLOT_SHRED_REPAIR_REQUEST, ts, ts );
  FD_TEST( gui->shreds.dropped_event_cnt==dropped );

  /* The cutoff only moves forward and ignores ULONG_MAX. */
  ulong cutoffs[] = { 70001UL, 60000UL, ULONG_MAX, 70002UL };
  ulong expect[]  = { 70001UL, 70001UL, 70001UL, 70002UL };
  for( ulong i=0UL; i<4UL; i++ ) {
    fd_gui_event_slots_close_before( gui, cutoffs[ i ] );
    FD_TEST( gui->shreds.closed_before_slot==expect[ i ] );
  }
  FD_TEST( fd_gui_event_slot_permanently_closed( gui, 70001UL ) );
  FD_TEST( !fd_gui_event_slot_permanently_closed( gui, 70002UL ) );
  ulong slots[] = { 1UL, 70001UL, 70002UL };
  for( ulong j=0UL; j<3UL; j++ ) {
    fd_gui_shred_event_append( gui, slots[ j ], 32UL, FD_GUI_SLOT_SHRED_REPAIR_REQUEST, ts, ts );
    fd_gui_fec_event_append( gui, slots[ j ], 1UL, FD_GUI_SLOT_SHRED_REPAIR_REQUEST, ts, ts );
    FD_TEST( fd_gui_fec_completion_append( gui, slots[ j ], ts, 32UL, 16UL, 8UL, 1, ts )==(j==2UL) );
  }
  FD_TEST( gui->shreds.dropped_event_cnt==dropped+2UL );
  FD_TEST( count_ts( gui, FD_GUI_HIST_FEC_COMPLETIONS, ULONG_MAX )==1UL );
  FD_LOG_NOTICE(( "test_timeline_closure_cutoff: completions do not close, monotone cutoff: ok" ));
}

static void
test_timeline_completion_overflow( test_store_t * s ) {
  fd_gui_t * gui = s->gui;
  long ts = sec_ns( 10UL );
  fd_gui_timeline_handle_fec( gui, 100UL, 1, ts+1L, 32UL, 16UL, 8UL, ts );
  fd_gui_timeline_handle_fec( gui, 100UL, 1, ts+2L, 32UL, 16UL, 8UL, ts );
  for( ulong i=2UL; i<FD_GUI_FEC_RECORD_MAX; i++ ) {
    FD_TEST( fd_gui_fec_completion_append( gui, 100UL, ts+1L+(long)i, 32UL, 16UL, 8UL, 1, ts )==1 );
  }
  FD_TEST( count_ts( gui, FD_GUI_HIST_FEC_COMPLETIONS, 100UL )==FD_GUI_FEC_RECORD_MAX );
  ulong used = fd_gui_store_used_bytes( gui->db );
  for( ulong i=0UL; i<3UL; i++ ) {
    fd_gui_timeline_handle_fec( gui, 100UL, 7, ts+1L, 32UL, 16UL, 8UL, ts+sec_ns( 10UL ) );
    fd_gui_timeline_handle_fec( gui, 100UL, 1, ts+(long)FD_GUI_FEC_RECORD_MAX+1L, 32UL, 16UL, 8UL, ts );
  }
  FD_TEST( gui->shreds.dropped_completion_cnt==3UL );
  FD_TEST( fd_gui_store_used_bytes( gui->db )==used );
  fd_gui_timeline_day_t const * day = fd_gui_timeline_day_get( gui, 0UL );
  FD_TEST( day );
  for( int g=FD_GUI_TIMELINE_GRANULARITY_250MS; g<(int)FD_GUI_TIMELINE_STORED_GRANULARITY_CNT; g++ ) {
    ulong idx = (ulong)ts / fd_gui_timeline_stored_granularity_ns[ g ];
    FD_TEST( fd_gui_timeline_field_get( day, g, FD_GUI_TIMELINE_FIELD_TURBINE, idx )==64UL );
    FD_TEST( fd_gui_timeline_field_get( day, g, FD_GUI_TIMELINE_FIELD_REPAIR, idx )==32UL );
    FD_TEST( fd_gui_timeline_field_get( day, g, FD_GUI_TIMELINE_FIELD_RECONSTRUCTED, idx )==16UL );
    FD_TEST( fd_gui_timeline_field_get( day, g, FD_GUI_TIMELINE_FIELD_PUBLISHED, idx )==128UL );
  }
  fd_gui_event_slots_close_before( gui, 101UL );
  fd_gui_timeline_handle_fec( gui, 101UL, 1, ts+4L, 32UL, 16UL, 8UL, ts );
  FD_TEST( gui->shreds.dropped_completion_cnt==3UL );
  fd_gui_timeline_handle_fec( gui, 100UL, 1, ts+1L, 32UL, 16UL, 8UL, ts );
  FD_TEST( gui->shreds.dropped_completion_cnt==4UL );
  FD_TEST( fd_gui_timeline_field_get( fd_gui_timeline_day_get( gui, 0UL ), FD_GUI_TIMELINE_GRANULARITY_250MS, FD_GUI_TIMELINE_FIELD_PUBLISHED, 40UL )==192UL );
  FD_LOG_NOTICE(( "test_timeline_completion_overflow: drop detail and day totals, normalized duplicates, closed prefix recovery: ok" ));
}

static void
test_timeline_ancestry( fd_gui_t * gui ) {
  void * http_mem = timeline_http_open( gui );
  long const ts = sec_ns( 10UL );
  /* Slot aggregates count skipped slots only in buckets that the
     skipped coverage window fully contains. */
  append_replay_txn( gui, ts, ts, 100UL );
  FD_TEST( fd_gui_fec_completion_append( gui, 100UL, ts, 0UL, 0UL, 0UL, 0, ts )==1 );
  FD_TEST( fd_epoch_schedule_derive( &gui->epoch.epoch_schedule, 1024UL, 1024UL, 0 ) );
  gui->epoch.has_epoch_schedule = 1;
  gui->epoch.current_epoch = 0UL;
  put_epoch( gui, 0UL, 0UL, 1024UL );
  fd_gui_epoch_t * epoch = fd_gui_epoch( gui, 0UL );
  epoch->timeline_slot_lo_idx = ULONG_MAX;
  epoch->timeline_slot_hi_idx = ULONG_MAX;
  put_slot( gui, 100UL, ts );
  fd_gui_slot_t * slot = fd_gui_slot_get( gui, 100UL, BANK_SEQ );
  slot->parent_slot = ULONG_MAX;
  slot->parent_bank_seq = ULONG_MAX;
  fd_gui_shred_event_append( gui, 103UL, 0UL, FD_GUI_SLOT_SHRED_SHRED_PUBLISHED, ts+6666667L, ts );
  put_slot( gui, 103UL, ts+10000001L );
  slot = fd_gui_slot_get( gui, 103UL, BANK_SEQ );
  slot->parent_slot = 100UL;
  slot->parent_bank_seq = BANK_SEQ;
  slot->mine = 1;
  FD_TEST( gui->timeline_skipped_slot_watermark==ULONG_MAX );
  fd_gui_timeline_skipped_update( gui, slot, ts+10000001L );
  FD_TEST( gui->timeline_skipped_slot_watermark==103UL );
  FD_TEST( gui->timeline_skipped_bank_seq_watermark==BANK_SEQ );
  FD_TEST( gui->timeline_skipped_coverage_start_ns==ts );
  FD_TEST( gui->timeline_skipped_coverage_end_ns==ts+10000001L );
  fd_gui_timeline_slot_row_t rows[ 4 ];
  ulong cnt;
  FD_TEST( !fd_gui_timeline_slots_collect( gui, ts, ts+10000001L, rows, 4UL, &cnt ) );
  FD_TEST( cnt==3UL );
  for( ulong i=0UL; i<3UL; i++ ) {
    FD_TEST( rows[ i ].slot==101UL+i );
    FD_TEST( rows[ i ].start_ns==ts+(long)(((uint128)i*10000001UL)/3UL) );
    FD_TEST( rows[ i ].end_ns==ts+(long)(((uint128)(i+1UL)*10000001UL)/3UL) );
    FD_TEST( rows[ i ].skipped==(i<2UL) && rows[ i ].mine==(i==2UL) );
  }
  FD_TEST( fd_gui_timeline_slots_collect( gui, ts, ts+10000001L, rows, 2UL, &cnt )==1 );
  FD_TEST( !fd_gui_timeline_slots_collect( gui, ts+3333333L, ts+6666667L, rows, 4UL, &cnt ) );
  FD_TEST( cnt==1UL && rows[ 0 ].slot==102UL );
  fd_gui_timeline_day_t const * day = fd_gui_timeline_day_get( gui, 0UL );
  FD_TEST( day && fd_gui_timeline_field_get( day, FD_GUI_TIMELINE_GRANULARITY_250MS, FD_GUI_TIMELINE_FIELD_SKIPPED, 40UL )==2UL );
  fd_gui_timeline_skipped_update( gui, fd_gui_slot_get( gui, 103UL, BANK_SEQ ), ts+10000001L );
  FD_TEST( fd_gui_timeline_field_get( day, FD_GUI_TIMELINE_GRANULARITY_250MS, FD_GUI_TIMELINE_FIELD_SKIPPED, 40UL )==2UL );
  /* The 250ms bucket extends past the coverage window. */
  FD_TEST( !fd_gui_printf_timeline_query_agg( gui, "query_agg_slots", "250ms", 3UL, ts, 1UL, 7UL ) );
  test_json_t json = timeline_response( gui );
  FD_TEST( (test_json_kind( test_json_index( timeline_value( json, "skipped" ), 0 ) )==FD_JTOK_NULL) );

  put_slot( gui, 106UL, ts+20000000L );
  slot = fd_gui_slot_get( gui, 106UL, BANK_SEQ );
  slot->parent_slot = 103UL;
  slot->parent_bank_seq = 1UL;
  fd_gui_timeline_skipped_update( gui, slot, ts+20000000L );
  FD_TEST( gui->timeline_skipped_slot_watermark==103UL );
  slot->parent_bank_seq = BANK_SEQ;
  gui->epoch.has_epoch_schedule = 0;
  fd_gui_timeline_skipped_update( gui, slot, ts+20000000L );
  FD_TEST( gui->timeline_skipped_slot_watermark==103UL );
  gui->epoch.has_epoch_schedule = 1;
  fd_gui_timeline_skipped_update( gui, slot, ts+20000000L );
  FD_TEST( gui->timeline_skipped_slot_watermark==106UL );
  FD_TEST( fd_gui_timeline_field_get( day, FD_GUI_TIMELINE_GRANULARITY_250MS, FD_GUI_TIMELINE_FIELD_SKIPPED, 40UL )==4UL );

  fd_gui_hist_slot_key_t key = { .slot=104UL, .bank_seq=ULONG_MAX };
  ulong budget = ULONG_MAX;
  int drained;
  FD_TEST( !fd_gui_store_kv_evict( gui->db, FD_GUI_HIST_SLOT, &key, &budget, &drained ) );
  FD_TEST( !fd_gui_slot_get( gui, 103UL, BANK_SEQ ) );
  FD_TEST( !fd_gui_printf_timeline_query_agg( gui, "query_agg_slots", "250ms", 3UL, ts, 1UL, 7UL ) );
  json = timeline_response( gui );
  FD_TEST( (test_json_kind( test_json_index( timeline_value( json, "skipped" ), 0 ) )==FD_JTOK_NULL) );

  key.slot = 107UL;
  FD_TEST( !fd_gui_store_kv_evict( gui->db, FD_GUI_HIST_SLOT, &key, &budget, &drained ) );
  FD_TEST( !fd_gui_slot_get( gui, 106UL, BANK_SEQ ) );
  put_slot( gui, 109UL, ts+sec_ns( 1UL ) );
  slot = fd_gui_slot_get( gui, 109UL, BANK_SEQ );
  slot->parent_slot     = 106UL;
  slot->parent_bank_seq = BANK_SEQ;
  fd_gui_shred_event_append( gui, 112UL, 0UL, FD_GUI_SLOT_SHRED_SHRED_RECEIVED_TURBINE, ts+sec_ns( 1UL )+666666666L, ts+sec_ns( 2UL ) );
  put_slot( gui, 112UL, ts+sec_ns( 2UL ) );
  slot = fd_gui_slot_get( gui, 112UL, BANK_SEQ );
  slot->parent_slot     = 109UL;
  slot->parent_bank_seq = 1UL;
  fd_gui_timeline_skipped_update( gui, slot, ts+sec_ns( 2UL ) );
  FD_TEST( gui->timeline_skipped_slot_watermark==106UL );
  slot->parent_bank_seq = BANK_SEQ;
  gui->summary.slot_rooted = 106UL;
  fd_gui_handle_root_advanced( gui, 112UL, BANK_SEQ, ts+sec_ns( 2UL ) );
  FD_TEST( gui->timeline_skipped_slot_watermark==112UL && gui->summary.slot_rooted==112UL );
  FD_TEST( gui->timeline_skipped_coverage_start_ns==ts+sec_ns( 1UL ) );
  FD_TEST( gui->timeline_skipped_coverage_end_ns==ts+sec_ns( 2UL ) );
  FD_TEST( fd_gui_timeline_field_get( fd_gui_timeline_day_get( gui, 0UL ), FD_GUI_TIMELINE_GRANULARITY_250MS, FD_GUI_TIMELINE_FIELD_SKIPPED, 40UL )==4UL );
  FD_TEST( !fd_gui_timeline_slots_collect( gui, ts, ts+10000001L, rows, 4UL, &cnt ) && cnt==3UL );
  FD_TEST( !fd_gui_timeline_slots_collect( gui, ts+20000000L, ts+sec_ns( 1UL ), rows, 4UL, &cnt ) && !cnt );
  FD_TEST( !fd_gui_timeline_slots_collect( gui, ts+sec_ns( 1UL ), ts+sec_ns( 2UL ), rows, 4UL, &cnt ) && cnt==3UL );
  FD_TEST( rows[ 0 ].slot==110UL && rows[ 0 ].skipped && rows[ 2 ].slot==112UL && !rows[ 2 ].skipped );
  FD_TEST( !fd_gui_printf_timeline_query_agg( gui, "query_agg_slots", "250ms", 3UL, ts, 4UL, 7UL ) );
  json = timeline_response( gui );
  for( int i=0; i<4; i++ ) FD_TEST( (test_json_kind( test_json_index( timeline_value( json, "skipped" ), i ) )==FD_JTOK_NULL) );
  /* Buckets inside the new coverage window count their skipped slots. */
  FD_TEST( !fd_gui_printf_timeline_query_agg( gui, "query_agg_slots", "250ms", 3UL, ts+sec_ns( 1UL ), 4UL, 7UL ) );
  json = timeline_response( gui );
  ulong skipped_sum = 0UL;
  for( int i=0; i<4; i++ ) {
    test_json_t v = test_json_index( timeline_value( json, "skipped" ), i );
    FD_TEST( test_json_kind( v )==FD_JTOK_INT );
    skipped_sum += test_json_ulong( v );
  }
  FD_TEST( skipped_sum==2UL );

  long prior = ts + sec_ns( 1UL );
  fd_gui_timeline_handle_txn( gui, 112UL, prior, 1UL, 60000000UL, 5000UL, 2UL, 3UL, 1, ts+sec_ns( 2UL ) );
  FD_TEST( !fd_gui_printf_timeline_query_agg( gui, "query_agg_slots", "250ms", 3UL, prior, 1UL, 7UL ) );
  json = timeline_response( gui );
  FD_TEST( test_json_ulong( test_json_index( timeline_value( json, "skipped" ), 0 ) )==1UL );

  FD_TEST( !fd_gui_printf_timeline_query_agg( gui, "query_agg_revenue", "250ms", 3UL, prior, 1UL, 7UL ) );
  json = timeline_response( gui );
  FD_TEST( test_json_string_eq( test_json_index( timeline_value( json, "txn_fees" ), 0 ), "5000" ) );

  FD_TEST( !fd_gui_store_ts_evict( gui->db, FD_GUI_HIST_TIMELINE_DAY, ULONG_MAX, &budget, &drained ) );
  FD_TEST( !fd_gui_timeline_day_get( gui, 0UL ) );
  FD_TEST( !count_ts( gui, FD_GUI_HIST_TIMELINE_DAY, ULONG_MAX ) );

  /* With no record left the index has no current day, so the next event
     starts a fresh record that holds only that event. */

  fd_gui_timeline_handle_txn( gui, 112UL, prior+250000000L, 1UL, 60000000UL, 7UL, 8UL, 9UL, 1, ts+sec_ns( 2UL ) );
  FD_TEST( count_ts( gui, FD_GUI_HIST_TIMELINE_DAY, ULONG_MAX )==1UL );
  FD_TEST( !fd_gui_printf_timeline_query_agg( gui, "query_agg_revenue", "250ms", 3UL, prior, 2UL, 7UL ) );
  json = timeline_response( gui );
  FD_TEST( (test_json_kind( test_json_index( timeline_value( json, "txn_fees" ), 0 ) )==FD_JTOK_NULL) );
  FD_TEST( test_json_string_eq( test_json_index( timeline_value( json, "txn_fees" ), 1 ), "7" ) );
  fd_gui_timeline_handle_txn( gui, 113UL, FD_GUI_TIMELINE_DAY_NS, 1UL, 60000000UL, 7UL, 8UL, 9UL, 1, FD_GUI_TIMELINE_DAY_NS );
  FD_TEST( fd_gui_timeline_day_get( gui, 1UL ) && fd_gui_timeline_day_get( gui, 0UL ) );
  FD_TEST( fd_http_server_delete( fd_http_server_leave( gui->http ) )==http_mem );
  free( http_mem );
  gui->http = NULL;
  FD_LOG_NOTICE(( "test_timeline_ancestry: recovery, regression and restart after lost day: ok" ));
}

static void
test_timeline_day_recovery( fd_gui_t * gui ) {
  void * http_mem = timeline_http_open( gui );
  FD_TEST( fd_epoch_schedule_derive( &gui->epoch.epoch_schedule, 1024UL, 1024UL, 0 ) );
  gui->epoch.has_epoch_schedule = 1;
  gui->epoch.current_epoch      = 0UL;
  gui->summary.slot_rooted      = ULONG_MAX;
  put_epoch( gui, 0UL, 0UL, 1024UL );
  fd_gui_epoch_t * epoch = fd_gui_epoch( gui, 0UL );
  epoch->timeline_slot_lo_idx = ULONG_MAX;
  epoch->timeline_slot_hi_idx = ULONG_MAX;
  long ts = sec_ns( 10UL );
  put_slot( gui, 100UL, ts );
  fd_gui_slot_t * slot = fd_gui_slot_get( gui, 100UL, BANK_SEQ );
  slot->parent_slot     = ULONG_MAX;
  slot->parent_bank_seq = ULONG_MAX;
  fd_gui_shred_event_append( gui, 103UL, 0UL, FD_GUI_SLOT_SHRED_SHRED_RECEIVED_TURBINE, ts+666666666L, ts );
  put_slot( gui, 103UL, ts+sec_ns( 1UL ) );
  slot = fd_gui_slot_get( gui, 103UL, BANK_SEQ );
  slot->parent_slot     = 100UL;
  slot->parent_bank_seq = BANK_SEQ;
  fd_gui_handle_root_advanced( gui, 103UL, BANK_SEQ, ts+sec_ns( 1UL ) );
  FD_TEST( gui->timeline_skipped_slot_watermark==103UL );
  FD_TEST( fd_gui_timeline_field_get( fd_gui_timeline_day_get( gui, 0UL ), 8, FD_GUI_TIMELINE_FIELD_SKIPPED, 0UL )==2UL );
  /* Day 1 becomes the current day before day 0 is lost, so the index
     still knows where the history ends. */
  fd_gui_timeline_handle_txn( gui, 103UL, FD_GUI_TIMELINE_DAY_NS, 1UL, 60000000UL, 1UL, 0UL, 0UL, 1, FD_GUI_TIMELINE_DAY_NS );
  FD_TEST( fd_gui_timeline_day_get( gui, 0UL ) && fd_gui_timeline_day_get( gui, 1UL ) );
  ulong budget = 1UL;
  int drained;
  FD_TEST( !fd_gui_store_ts_evict( gui->db, FD_GUI_HIST_TIMELINE_DAY, ULONG_MAX, &budget, &drained ) );
  FD_TEST( fd_gui_slot_get( gui, 100UL, BANK_SEQ ) && fd_gui_slot_get( gui, 103UL, BANK_SEQ ) );
  ulong slots[]   = { 106UL, 109UL, 110UL };
  ulong parents[] = { 103UL, 106UL, 109UL };
  for( ulong i=0UL; i<3UL; i++ ) {
    long now = FD_GUI_TIMELINE_DAY_NS + sec_ns( i+1UL );
    fd_gui_shred_event_append( gui, slots[ i ], 0UL, FD_GUI_SLOT_SHRED_SHRED_RECEIVED_TURBINE,
                              now-(i==2UL ? sec_ns( 1UL ) : 333333334L), now );
    put_slot( gui, slots[ i ], now );
    slot = fd_gui_slot_get( gui, slots[ i ], BANK_SEQ );
    slot->parent_slot     = parents[ i ];
    slot->parent_bank_seq = BANK_SEQ;
    fd_gui_handle_root_advanced( gui, slots[ i ], BANK_SEQ, now );
    FD_TEST( gui->timeline_skipped_slot_watermark==slots[ i ] );
    FD_TEST( gui->timeline_skipped_coverage_start_ns==FD_GUI_TIMELINE_DAY_NS+sec_ns( 1UL ) );
    FD_TEST( !fd_gui_timeline_day_get( gui, 0UL ) && fd_gui_timeline_day_get( gui, 1UL ) );
  }
  FD_TEST( fd_gui_timeline_field_get( fd_gui_timeline_day_get( gui, 1UL ), 8, FD_GUI_TIMELINE_FIELD_SKIPPED, 0UL )==2UL );
  fd_gui_timeline_slot_row_t rows[ 8 ];
  ulong cnt;
  FD_TEST( !fd_gui_timeline_slots_collect( gui, ts, ts+sec_ns( 1UL ), rows, 8UL, &cnt ) && cnt==3UL );
  FD_TEST( rows[ 0 ].skipped && !rows[ 2 ].skipped );
  FD_TEST( !fd_gui_timeline_slots_collect( gui, ts+sec_ns( 1UL ), FD_GUI_TIMELINE_DAY_NS+sec_ns( 1UL ), rows, 8UL, &cnt ) && !cnt );
  FD_TEST( !fd_gui_timeline_slots_collect( gui, FD_GUI_TIMELINE_DAY_NS+sec_ns( 1UL ),
                                          FD_GUI_TIMELINE_DAY_NS+sec_ns( 3UL ), rows, 8UL, &cnt ) && cnt==4UL );
  FD_TEST( rows[ 0 ].slot==107UL && rows[ 0 ].skipped && rows[ 3 ].slot==110UL && !rows[ 3 ].skipped );
  {
    FD_TEST( !fd_gui_printf_timeline_query_agg( gui, "query_agg_slots", "250ms", 3UL, FD_GUI_TIMELINE_DAY_NS, 4UL, 7UL ) );
    test_json_t json    = timeline_response( gui );
    test_json_t skipped = timeline_value( json, "skipped" );
    FD_TEST( test_json_count( skipped )==4 );
    for( int row=0; row<test_json_count( skipped ); row++ ) FD_TEST( (test_json_kind( test_json_index( skipped, row ) )==FD_JTOK_NULL) );
  }
  FD_TEST( !fd_gui_printf_timeline_query_agg( gui, "query_agg_slots", "250ms", 3UL, FD_GUI_TIMELINE_DAY_NS+sec_ns( 1UL ), 8UL, 7UL ) );
  test_json_t json = timeline_response( gui );
  FD_TEST( test_json_ulong( test_json_index( timeline_value( json, "skipped" ), 0 ) )==1UL );
  FD_TEST( test_json_ulong( test_json_index( timeline_value( json, "skipped" ), 2 ) )==1UL );
  FD_TEST( (test_json_kind( test_json_index( timeline_value( json, "skipped" ), 7 ) )==FD_JTOK_INT) );

  FD_TEST( fd_http_server_delete( fd_http_server_leave( gui->http ) )==http_mem );
  free( http_mem );
  gui->http = NULL;
  FD_LOG_NOTICE(( "test_timeline_day_recovery: day-only eviction, intact ancestry, consecutive day-1 roots: ok" ));
}

static void
test_timeline_batch_parity( fd_gui_t * gui ) {
  long ts = sec_ns( 11UL );
  fd_gui_store_replay_txn_t txns[ 128 ];
  fd_gui_txn_batch_work_t oracle[ 128 ];
  ulong appended = 0UL;
  for( ulong fixture=0UL; fixture<4UL; fixture++ ) {
    ulong target = fixture==0UL ? 17UL : fixture==1UL ? 5UL : 33UL;
    ulong count  = 128UL/FD_GUI_TXN_BATCH_MAX_TXN;
    long  start  = ts;
    for( ulong i=0UL; i<128UL; i++ ) {
      start += fixture==3UL ? 1000L+(long)(i*17UL%23UL)*100L : 1000L;
      txns[ i ] = (fd_gui_store_replay_txn_t){
        .insert_time_ns=ts, .completion_time_ns=start+800L, .slot=101UL+fixture, .txn_idx=i,
        .txn_exec_idx=i%target, .sigverify_start_ns=start, .sigverify_end_ns=start+800L,
        .txn_start_shred_idx=(uint)(127UL-i), .txn_end_shred_idx=(uint)(1000UL+i),
        .load_start_ns=start+100L, .check_start_ns=start+200L, .exec_start_ns=start+300L,
        .commit_start_ns=start+600L, .commit_end_ns=start+700L, .block_compute_unit_limit=ULONG_MAX
      };
      FD_TEST( !fd_gui_hist_ts_append( gui, FD_GUI_HIST_REPLAY_TXN, &txns[ i ] ) );
    }
    ulong const max = FD_GUI_TXN_BATCH_MAX_TXN;
    for( ulong i=0UL; i<count; i++ ) {
      oracle[ i ] = (fd_gui_txn_batch_work_t){
        .first=max*i, .cnt=max, .representative_txn_idx=max*i,
        .start_ns=txns[ max*i ].sigverify_start_ns, .end_ns=txns[ max*i+max-1UL ].sigverify_end_ns
      };
    }
    while( count<target ) {
      ulong best = ULONG_MAX;
      for( ulong i=0UL; i<count; i++ ) {
        if( oracle[ i ].cnt<=1UL ) continue;
        long span = fd_long_sat_sub( oracle[ i ].end_ns, oracle[ i ].start_ns );
        long old  = best==ULONG_MAX ? LONG_MIN : fd_long_sat_sub( oracle[ best ].end_ns, oracle[ best ].start_ns );
        if( best==ULONG_MAX || span>old || (span==old && (oracle[ i ].cnt>oracle[ best ].cnt ||
            (oracle[ i ].cnt==oracle[ best ].cnt && oracle[ i ].representative_txn_idx<oracle[ best ].representative_txn_idx))) ) {
          best = i;
        }
      }
      FD_TEST( best!=ULONG_MAX );
      ulong off = 1UL;
      long  gap = LONG_MIN;
      for( ulong k=1UL; k<oracle[ best ].cnt; k++ ) {
        long next = fd_long_sat_sub( txns[ oracle[ best ].first+k ].sigverify_start_ns,
                                     txns[ oracle[ best ].first+k-1UL ].sigverify_end_ns );
        ulong dist    = fd_long_abs( (long)(2UL*k)-(long)oracle[ best ].cnt );
        ulong olddist = fd_long_abs( (long)(2UL*off)-(long)oracle[ best ].cnt );
        if( next>gap || (next==gap && dist<olddist) ) {
          gap = next;
          off = k;
        }
      }
      oracle[ count ] = oracle[ best ];
      oracle[ count ].first += off;
      oracle[ count ].cnt   -= off;
      oracle[ best ].cnt     = off;
      oracle[ best ].end_ns  = txns[ oracle[ best ].first+off-1UL ].sigverify_end_ns;
      oracle[ count ].start_ns               = txns[ oracle[ count ].first ].sigverify_start_ns;
      oracle[ count ].representative_txn_idx = oracle[ count ].first;
      count++;
    }
    gui->slot_txn_scratch.max = 128UL;
    FD_TEST( !fd_gui_materialize_replay_txn_batches( gui, 101UL+fixture, 0UL, ts, ts+sec_ns( 1UL ), 128UL, ts ) );
    appended += target;
    FD_TEST( count_ts( gui, FD_GUI_HIST_REPLAY_TXN_BATCH, ULONG_MAX )==appended );
    for( ulong i=0UL; i<count; i++ ) {
      fd_gui_store_replay_txn_batch_t const * rec = &gui->timeline_scratch.materialize.records[ i ];
      FD_TEST( rec->batch_idx==i && rec->txn_idx==i );
      if( i ) FD_TEST( gui->timeline_scratch.materialize.records[ i-1UL ].sigverify_txn_idx<rec->sigverify_txn_idx );
      ulong j = 0UL;
      while( j<count && oracle[ j ].first!=rec->sigverify_txn_idx ) j++;
      FD_TEST( j<count && rec->sigverify_txn_cnt==oracle[ j ].cnt );
      FD_TEST( rec->sigverify_start_ns==oracle[ j ].start_ns && rec->sigverify_end_ns==oracle[ j ].end_ns );
    }
  }
  ulong n = FD_MAX_TXN_PER_SLOT;
  ts = sec_ns( 12UL );
  /* Execution gaps exceed the merge gap, so every EXEC batch is a singleton. */
  long const exec_step = FD_GUI_TXN_BATCH_GAP_NS+1000L;
  for( ulong i=0UL; i<n; i++ ) {
    fd_gui_store_replay_txn_t txn = { .insert_time_ns=ts, .slot=105UL, .txn_idx=i,
      .txn_start_shred_idx=UINT_MAX, .txn_end_shred_idx=UINT_MAX,
      .sigverify_start_ns=ts+(long)i*1000L, .sigverify_end_ns=ts+(long)i*1000L+800L,
      .load_start_ns=ts+(long)i*exec_step, .check_start_ns=LONG_MAX, .exec_start_ns=LONG_MAX,
      .commit_start_ns=LONG_MAX, .commit_end_ns=ts+(long)i*exec_step+700L,
      .completion_time_ns=ts+(long)i*exec_step+800L, .block_compute_unit_limit=ULONG_MAX };
    FD_TEST( !fd_gui_hist_ts_append( gui, FD_GUI_HIST_REPLAY_TXN, &txn ) );
  }
  gui->slot_txn_scratch.max = n;
  FD_TEST( !fd_gui_materialize_replay_txn_batches( gui, 105UL, 0UL, ts, ts+(long)n*exec_step, n, ts ) );
  ulong work = gui->timeline_scratch.materialize.normalize_work;
  FD_TEST( work && work<n*128UL );
  for( ulong i=0UL; i<n; i++ ) {
    fd_gui_store_replay_txn_batch_t const * rec = &gui->timeline_scratch.materialize.records[ i ];
    FD_TEST( rec->exec_txn_cnt==1U && rec->sigverify_txn_cnt==1U );
    FD_TEST( rec->txn_idx==i && rec->sigverify_txn_idx==i );
  }
  FD_LOG_NOTICE(( "test_timeline_batch_parity: tie fixtures and %lu singleton EXEC / %lu-member SIG: %lu normalization work; ok",
                  n, FD_GUI_TXN_BATCH_MAX_TXN, work ));
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
  }
  gui->slot_txn_scratch.max = max+1UL;
  /* A replay of the same slot on another fork, overlapping in time, is
     not mixed into this fork's batches. */
  for( ulong i=0UL; i<4UL; i++ ) {
    fd_gui_store_replay_txn_t txn = {
      .insert_time_ns=ts, .completion_time_ns=ts+(long)i*1000L+900L, .slot=100UL, .bank_seq=1UL, .txn_idx=i,
      .sigverify_start_ns=LONG_MAX, .sigverify_end_ns=LONG_MAX, .txn_sigverify_exec_idx=ULONG_MAX,
      .load_start_ns=ts+(long)i*1000L+150L, .check_start_ns=LONG_MAX, .exec_start_ns=LONG_MAX,
      .commit_start_ns=LONG_MAX, .commit_end_ns=ts+(long)i*1000L+750L, .block_compute_unit_limit=ULONG_MAX
    };
    FD_TEST( !fd_gui_hist_ts_append( gui, FD_GUI_HIST_REPLAY_TXN, &txn ) );
  }
  FD_TEST( !fd_gui_materialize_replay_txn_batches( gui, 100UL, 0UL, ts, ts+1000000L, 2UL*max+1UL, ts+1000000L ) );
  FD_TEST( count_ts( gui, FD_GUI_HIST_REPLAY_TXN_BATCH, ULONG_MAX )==2UL );
  fd_gui_hist_iter_t it;
  FD_TEST( !fd_gui_hist_range_begin( gui, &it, FD_GUI_HIST_REPLAY_TXN_BATCH, ts, ts+1000000L, NULL, NULL ) );
  for( ulong i=0UL; i<2UL; i++ ) {
    FD_TEST( fd_gui_hist_range_next( &it ) );
    fd_gui_store_replay_txn_batch_t const * b = it.rec;
    FD_TEST( b->batch_idx==i && b->exec_txn_cnt==(i ? 1U : (uint)max) && b->sigverify_txn_cnt==b->exec_txn_cnt );
    FD_TEST( b->txn_idx==i*max && b->sigverify_txn_idx==i*max );
    FD_TEST( b->error_code==(i ? 0U : 5U) );
    FD_TEST( b->completion_time_ns==ts+(long)(i ? max : max-1UL)*1000L+800L );
    FD_TEST( b->load_start_ns<=b->check_start_ns && b->check_start_ns<=b->exec_start_ns );
    FD_TEST( b->exec_start_ns<=b->commit_start_ns && b->commit_start_ns<=b->commit_end_ns );
  }
  FD_TEST( !fd_gui_hist_range_next( &it ) );
  fd_gui_hist_range_end( &it );
  /* Two execrp tiles: both batches execute on tile 0 and sigverify on
     tile 1, with Idle around them. */
  gui->tile_state.exec_cnt = 2UL;
  gui->tile_state.pos_cnt  = 2UL;
  FD_TEST( !fd_gui_printf_timeline_query_tile_states( gui, ts, ts+1000000L, 1, 7UL ) );
  test_json_t json = timeline_response( gui );
  FD_TEST( test_json_string_eq( timeline_value( json, "granularity" ), "txn_batch" ) );
  FD_TEST( test_json_count( timeline_value( json, "state_cnt" ) )==2 );
  FD_TEST( !test_json_count( timeline_value( json, "txn_idx" ) ) && !test_json_count( timeline_value( json, "slot_state_lo" ) ) );
  int n = test_json_count( timeline_value( json, "state" ) );
  FD_TEST( n==test_json_count( timeline_value( json, "dur" ) ) );
  ulong total = 0UL; ulong exec_batch = 0UL; ulong sig_batch = 0UL;
  for( int i=0; i<n; i++ ) {
    ulong state = test_json_ulong( test_json_index( timeline_value( json, "state" ), i ) );
    FD_TEST( state==FD_GUI_TILE_STATE_IDLE || state==FD_GUI_TILE_STATE_EXEC_BATCH || state==FD_GUI_TILE_STATE_SIGVERIFY_BATCH );
    exec_batch += state==FD_GUI_TILE_STATE_EXEC_BATCH;
    sig_batch  += state==FD_GUI_TILE_STATE_SIGVERIFY_BATCH;
    total += test_json_ulong( test_json_index( timeline_value( json, "dur" ), i ) );
  }
  FD_TEST( exec_batch==2UL && sig_batch==2UL && total==2UL*1000000UL ); /* each tile covers the window */

  /* A batch is inserted when its slot completes, which can be seconds
     after the batch itself.  A narrow window around the batch still
     finds it, up to the query margin. */
  long const late = ts+sec_ns( 100UL );
  append_replay_txn_batch( gui, late+FD_GUI_TXN_BATCH_QUERY_MARGIN_NS-sec_ns( 1UL ), late, 200UL );
  append_replay_txn_batch( gui, late+FD_GUI_TXN_BATCH_QUERY_MARGIN_NS+sec_ns( 2UL ), late+1L, 201UL );
  FD_TEST( !fd_gui_printf_timeline_query_tile_states( gui, late, late+2L, 1, 7UL ) );
  json = timeline_response( gui );
  /* Batches without a sigverify lane are leader batches and skipped. */
  FD_TEST( test_json_kind( timeline_value( json, "reference_slot" ) )==FD_JTOK_NULL );
  gui->tile_state.exec_cnt = 0UL;
  gui->tile_state.pos_cnt  = 0UL;
  FD_TEST( fd_http_server_delete( fd_http_server_leave( gui->http ) )==http_mem );
  free( http_mem );
  gui->http = NULL;
  FD_LOG_NOTICE(( "test_timeline_batches: ok" ));
}

/* The replayed (non-leader) completion path bounds its scan by the
   replay schedule, only rolls up the completed fork's transactions, and
   counts a locally produced slot once however often it completes. */
static void
test_timeline_replay_batches( fd_gui_t * gui ) {
  void * http_mem = timeline_http_open( gui );
  long const  ts   = sec_ns( 10UL );
  ulong const slot = 600UL;
  gui->slot_txn_scratch.max                   = 8UL;
  gui->summary.slot_caught_up                = ULONG_MAX;
  for( ulong i=0UL; i<FD_GUI_TURBINE_SLOT_HISTORY_SZ; i++ ) gui->summary.slots_max_turbine[ i ].slot = ULONG_MAX;
  /* Two transactions on fork 3, one on fork 4 at the same time, and one
     on fork 3 past the scan margin. */
  ulong forks[] = { 3UL, 3UL, 4UL, 3UL };
  long  ends[]  = { ts+100L, ts+200L, ts+150L, ts+FD_GUI_TXN_BATCH_SCAN_MARGIN_NS+1000L };
  for( ulong i=0UL; i<4UL; i++ ) {
    fd_gui_store_replay_txn_t txn = {
      .insert_time_ns=ts, .completion_time_ns=ends[ i ], .slot=slot, .bank_seq=forks[ i ], .txn_idx=i, .txn_exec_idx=i,
      .txn_sigverify_exec_idx=ULONG_MAX, .sigverify_start_ns=LONG_MAX, .sigverify_end_ns=LONG_MAX,
      .load_start_ns=ends[ i ]-50L, .check_start_ns=LONG_MAX, .exec_start_ns=LONG_MAX, .commit_start_ns=LONG_MAX,
      .commit_end_ns=ends[ i ], .block_compute_unit_limit=ULONG_MAX
    };
    FD_TEST( !fd_gui_hist_ts_append( gui, FD_GUI_HIST_REPLAY_TXN, &txn ) );
  }
  fd_replay_slot_completed_t completed = { .slot=slot, .bank_seq=3UL, .parent_slot=ULONG_MAX, .parent_bank_seq=ULONG_MAX,
    .first_transaction_scheduled_nanos=ts+50L, .completion_time_nanos=ts+300L,
    .nonvote_success=3UL, .identity_balance=ULONG_MAX };
  fd_gui_handle_replay_update( gui, &completed, ts+300L );
  fd_http_server_stage_trunc( gui->http, 0UL );
  FD_TEST( count_ts( gui, FD_GUI_HIST_REPLAY_TXN_BATCH, ULONG_MAX )==2UL );
  fd_gui_hist_iter_t it;
  FD_TEST( !fd_gui_hist_range_begin( gui, &it, FD_GUI_HIST_REPLAY_TXN_BATCH, ts, ts+sec_ns( 1UL ), NULL, NULL ) );
  for( ulong i=0UL; i<2UL; i++ ) {
    FD_TEST( fd_gui_hist_range_next( &it ) );
    fd_gui_store_replay_txn_batch_t const * b = it.rec;
    FD_TEST( b->slot==slot && b->exec_txn_cnt==1U && b->txn_idx==i );
  }
  FD_TEST( !fd_gui_hist_range_next( &it ) );
  fd_gui_hist_range_end( &it );

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
  FD_LOG_NOTICE(( "test_timeline_replay_batches: fork filter, scan margin, mine counted once: ok" ));
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
    if( !(i%FD_GUI_FEC_SLOT_HORIZON) ) fd_gui_event_slots_close_before( gui, i );
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
    if( i%65535UL==65534UL ) fd_gui_event_slots_close_before( gui, slot+1UL );
  }
  fd_gui_event_slots_close_before( gui, 109UL );
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
  fd_gui_event_slots_close_before( gui, 110UL );
  for( int fec=0; fec<2; fec++ ) {
    FD_TEST( !(fec ? fd_gui_printf_timeline_query_fec_events( gui, ts, ts+1L, 7UL )
                  : fd_gui_printf_timeline_query_shreds( gui, ts, ts+1L, 7UL )) );
    test_json_t json = timeline_response( gui );
    FD_TEST( test_json_string_eq( test_json_field( test_json_field( json, "error" ), "code" ), "result_limit_exceeded" ) );

  }

  fd_gui_store_replay_txn_t txn = { .insert_time_ns=ts, .completion_time_ns=ts, .slot=100UL, .block_compute_unit_limit=ULONG_MAX,
    .txn_start_shred_idx=UINT_MAX-1U, .txn_end_shred_idx=UINT_MAX-1U,
    .load_start_ns=ts, .check_start_ns=ts, .exec_start_ns=ts, .commit_start_ns=ts, .commit_end_ns=ts+1L };
  fd_gui_store_replay_txn_batch_t tb = { .insert_time_ns=ts, .completion_time_ns=ts, .slot=100UL, .sigverify_txn_cnt=1U,
    .load_start_ns=ts, .commit_end_ns=ts+1L };
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
  FD_TEST( !fd_gui_timeline_slots_collect( gui, 0L, 50L, gui->timeline_scratch.slot_rows, 3UL, &rows ) && rows==3UL );
  epoch->timeline_slot_min_start_ns = 100L;
  epoch->timeline_slot_max_end_ns   = 200L;
  FD_TEST( !fd_gui_timeline_slots_collect( gui, 0L, 50L, gui->timeline_scratch.slot_rows, 3UL, &rows ) && !rows );
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
test_timeline_slot_intervals( fd_gui_t * gui ) {
  void * http_mem = timeline_http_open( gui );
  long ts  = sec_ns( 10UL );
  long now = ts+1000L;
  FD_TEST( fd_epoch_schedule_derive( &gui->epoch.epoch_schedule, 1024UL, 1024UL, 0 ) );
  gui->epoch.has_epoch_schedule = 1;
  gui->epoch.current_epoch = 1UL;
  for( ulong e=0UL; e<2UL; e++ ) {
    put_epoch( gui, e, e*1024UL, 1024UL );
    fd_gui_epoch_t * epoch = fd_gui_epoch( gui, e );
    epoch->timeline_slot_lo_idx = ULONG_MAX;
    epoch->timeline_slot_hi_idx = ULONG_MAX;
  }

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
    put_slot( gui, slots[ i ], ts+complete[ i ] );
    fd_gui_slot_t * slot = fd_gui_slot_get( gui, slots[ i ], BANK_SEQ );
    slot->parent_slot     = i ? slots[ i-1UL ] : ULONG_MAX;
    slot->parent_bank_seq = i ? BANK_SEQ : ULONG_MAX;
    slot->mine           = slots[ i ]==1024UL;
    fd_gui_shred_event_slot_complete( gui, slots[ i ], ts+complete[ i ], now );
  }
  /* A closed slot cannot have its start revised by late traffic. */
  fd_gui_event_slots_close_before( gui, 1023UL );
  fd_gui_handle_shred( gui, 1022UL, 10UL, 0UL, 1, ts+5L, now );

  /* Arrival timestamps survive raw event eviction before classification. */
  fd_gui_shred_flush( gui, ts+sec_ns( 1UL ) );
  ulong budget = ULONG_MAX;
  int drained;
  FD_TEST( !fd_gui_store_ts_evict( gui->db, FD_GUI_HIST_SHRED_EVENTS, ULONG_MAX, &budget, &drained ) );
  fd_gui_timeline_skipped_update( gui, fd_gui_slot_get( gui, 1029UL, BANK_SEQ ), now );

  FD_TEST( !fd_gui_printf_timeline_query_slots( gui, ts+100L, ts+150L, 7UL ) );
  test_json_t json = timeline_response( gui );
  FD_TEST( test_json_count( timeline_value( json, "slot_delta" ) )==2 );
  FD_TEST( test_json_ulong( timeline_value( json, "reference_slot" ) )==1022UL );
  FD_TEST( test_json_string_eq( timeline_value( json, "reference_ts" ), "10000000020" ) );
  FD_TEST( test_json_string_eq( test_json_index( timeline_value( json, "start_ts_delta" ), 0 ), "30" ) );
  FD_TEST( test_json_string_eq( test_json_index( timeline_value( json, "start_ts_delta" ), 1 ), "0" ) );
  FD_TEST( test_json_string_eq( test_json_index( timeline_value( json, "end_ts_delta" ), 0 ), "180" ) );
  FD_TEST( test_json_string_eq( test_json_index( timeline_value( json, "end_ts_delta" ), 1 ), "280" ) );
  FD_TEST( test_json_string_eq( timeline_value( json, "available_start_ns" ), "10000000020" ) );
  FD_TEST( test_json_string_eq( timeline_value( json, "available_end_ns" ), "10000000800" ) );

  fd_gui_timeline_slot_row_t rows[ 8 ];
  ulong cnt;
  FD_TEST( !fd_gui_timeline_slots_collect( gui, ts, now, rows, 8UL, &cnt ) && cnt==5UL );
  FD_TEST( rows[ 2 ].slot==1024UL && rows[ 2 ].mine && rows[ 2 ].start_ns==ts+250L && rows[ 2 ].end_ns==ts+400L );
  FD_TEST( rows[ 3 ].slot==1027UL && rows[ 3 ].skipped && rows[ 3 ].start_ns==ts+600L && rows[ 3 ].end_ns==ts+700L );
  FD_TEST( rows[ 4 ].slot==1028UL && !rows[ 4 ].skipped && rows[ 4 ].start_ns==ts+610L && rows[ 4 ].end_ns==ts+800L );
  FD_TEST( !fd_gui_timeline_slots_collect( gui, ts+200L, ts+250L, rows, 8UL, &cnt ) && cnt==1UL && rows[ 0 ].slot==1023UL );
  FD_TEST( !fd_gui_timeline_slots_collect( gui, ts+400L, ts+600L, rows, 8UL, &cnt ) && !cnt );

  FD_TEST( fd_http_server_delete( fd_http_server_leave( gui->http ) )==http_mem );
  free( http_mem );
  gui->http = NULL;
  FD_LOG_NOTICE(( "test_timeline_slot_intervals: overlapping arrivals, leader publication, skipped slots, missing starts, eviction: ok" ));
}

static void
test_timeline_replayed_skips( fd_gui_t * gui ) {
  void * http_mem = timeline_http_open( gui );
  long ts  = sec_ns( 10UL );
  long now = ts+1000L;
  FD_TEST( fd_epoch_schedule_derive( &gui->epoch.epoch_schedule, 1024UL, 1024UL, 0 ) );
  gui->epoch.has_epoch_schedule = 1;
  gui->epoch.current_epoch = 0UL;
  put_epoch( gui, 0UL, 0UL, 1024UL );
  fd_gui_epoch_t * epoch = fd_gui_epoch( gui, 0UL );
  epoch->timeline_slot_lo_idx = ULONG_MAX;
  epoch->timeline_slot_hi_idx = ULONG_MAX;

  /* A completed abandoned fork can disappear before classification. */
  fd_gui_handle_shred( gui, 102UL, 7UL, 0UL, 0, ts+150L, now );
  fd_gui_shred_event_slot_complete( gui, 102UL, ts+450L, now );
  fd_gui_shred_event_slot_complete( gui, 102UL, ts+475L, now );
  put_slot( gui, 102UL, ts+475L );
  fd_gui_hist_slot_key_t key = { .slot=103UL, .bank_seq=0UL };
  ulong budget = ULONG_MAX;
  int drained;
  FD_TEST( !fd_gui_store_kv_evict( gui->db, FD_GUI_HIST_SLOT, &key, &budget, &drained ) );
  FD_TEST( !fd_gui_slot_get_any( gui, 102UL ) );

  fd_gui_handle_leader_fec( gui, 101UL, 32UL, 1, ts+50L, now );
  put_slot( gui, 101UL, ts+350L );
  fd_gui_slot_get( gui, 101UL, BANK_SEQ )->mine = 1;
  fd_gui_shred_event_slot_complete( gui, 101UL, ts+350L, now );
  fd_gui_handle_shred( gui, 103UL, 0UL, 0UL, 1, ts+250L, now );
  fd_gui_handle_shred( gui, 104UL, 0UL, 0UL, 1, ts+300L, now );
  fd_gui_shred_event_slot_complete( gui, 105UL, ts+650L, now ); /* missing arrival */
  put_slot( gui, 107UL, LONG_MAX ); /* replay started but never completed */
  fd_gui_handle_shred( gui, 108UL, 0UL, 0UL, 1, ts+500L, now );
  put_slot( gui, 100UL, ts+100L );
  fd_gui_slot_t * slot = fd_gui_slot_get( gui, 100UL, BANK_SEQ );
  slot->parent_slot = ULONG_MAX;
  slot->parent_bank_seq = ULONG_MAX;
  put_slot( gui, 108UL, ts+900L );
  slot = fd_gui_slot_get( gui, 108UL, BANK_SEQ );
  slot->parent_slot = 100UL;
  slot->parent_bank_seq = BANK_SEQ;
  fd_gui_shred_event_slot_complete( gui, 108UL, ts+900L, now );
  fd_gui_shred_flush( gui, ts+sec_ns( 1UL ) );
  FD_TEST( !fd_gui_store_ts_evict( gui->db, FD_GUI_HIST_SHRED_EVENTS, ULONG_MAX, &budget, &drained ) );
  fd_gui_timeline_skipped_update( gui, slot, now );

  FD_TEST( !fd_gui_printf_timeline_query_slots( gui, ts+200L, ts+225L, 7UL ) );
  test_json_t json = timeline_response( gui );
  FD_TEST( test_json_count( timeline_value( json, "slot_delta" ) )==2 );
  FD_TEST( test_json_ulong( timeline_value( json, "reference_slot" ) )==101UL );
  FD_TEST( test_json_string_eq( timeline_value( json, "reference_ts" ), "10000000050" ) );
  FD_TEST( test_json_string_eq( test_json_index( timeline_value( json, "start_ts_delta" ), 0 ), "0" ) );
  FD_TEST( test_json_string_eq( test_json_index( timeline_value( json, "start_ts_delta" ), 1 ), "100" ) );
  FD_TEST( test_json_string_eq( test_json_index( timeline_value( json, "end_ts_delta" ), 0 ), "300" ) );
  FD_TEST( test_json_string_eq( test_json_index( timeline_value( json, "end_ts_delta" ), 1 ), "400" ) );
  FD_TEST( test_json_count( timeline_value( json, "skipped" ) )==2 );
  FD_TEST( test_json_ulong( test_json_index( timeline_value( json, "skipped" ), 0 ) )==0UL );
  FD_TEST( test_json_ulong( test_json_index( timeline_value( json, "skipped" ), 1 ) )==1UL );
  FD_TEST( test_json_count( timeline_value( json, "mine" ) )==1 );
  FD_TEST( test_json_ulong( test_json_index( timeline_value( json, "mine" ), 0 ) )==0UL );

  /* A late completion replaces interpolation, retaining the true start.
     Duplicate replays deterministically retain the earliest completion. */
  FD_TEST( epoch->timeline_slot_start_ns[ 103 ]==ts+300L && epoch->timeline_slot_end_ns[ 103 ]==ts+400L );
  fd_gui_shred_event_slot_complete( gui, 103UL, ts+550L, now );
  fd_gui_shred_event_slot_complete( gui, 103UL, ts+575L, now );
  fd_gui_shred_event_slot_complete( gui, 103UL, ts+525L, now );
  fd_gui_timeline_slot_row_t rows[ 8 ];
  ulong cnt;
  FD_TEST( !fd_gui_timeline_slots_collect( gui, ts, now, rows, 8UL, &cnt ) && cnt==7UL );
  FD_TEST( rows[ 2 ].slot==103UL && rows[ 2 ].skipped && rows[ 2 ].start_ns==ts+250L && rows[ 2 ].end_ns==ts+525L );
  FD_TEST( rows[ 3 ].slot==104UL && rows[ 3 ].skipped && rows[ 3 ].start_ns==ts+400L && rows[ 3 ].end_ns==ts+500L );
  FD_TEST( rows[ 4 ].slot==106UL && rows[ 4 ].skipped && rows[ 4 ].start_ns==ts+600L && rows[ 4 ].end_ns==ts+700L );
  FD_TEST( rows[ 5 ].slot==107UL && rows[ 5 ].skipped && rows[ 5 ].start_ns==ts+700L && rows[ 5 ].end_ns==ts+800L );
  FD_TEST( rows[ 6 ].slot==108UL && !rows[ 6 ].skipped && rows[ 6 ].start_ns==ts+500L && rows[ 6 ].end_ns==ts+900L );
  fd_gui_shred_event_slot_complete( gui, 106UL, ts+750L, now ); /* late completion without arrival */
  FD_TEST( !fd_gui_timeline_slots_collect( gui, ts, now, rows, 8UL, &cnt ) && cnt==6UL );
  FD_TEST( rows[ 4 ].slot==107UL );

  FD_TEST( fd_http_server_delete( fd_http_server_leave( gui->http ) )==http_mem );
  free( http_mem );
  gui->http = NULL;
  FD_LOG_NOTICE(( "test_timeline_replayed_skips: observed intervals, eviction, late/duplicate completions, unreplayed interpolation: ok" ));
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
  uint  flags      = 0U;
  ulong priority   = 0UL;
  ulong precompile = 0UL;
  ulong requested  = fd_pack_compute_cost( TXN( &txn ), txn.payload, &flags, NULL, &priority, &precompile, NULL, NULL );
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
    FD_TEST( test_json_count( timeline_value( json, "state" ) )==4 ); /* one Idle per tile */
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
  /* The success and the error-200 failure share a tile and overlap, so
     they merge into one batch; the 1-1 error-code tie picks success. */
  FD_TEST( count_ts( gui, FD_GUI_HIST_REPLAY_TXN_BATCH, ULONG_MAX )==1UL );
  FD_TEST( !gui->timeline_scratch.materialize.normalize_work );
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
  FD_TEST( test_json_count( timeline_value( json, "state" ) )==4 ); /* leader batch skipped */
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
replay_duration( fd_gui_t * gui,
                  ulong      slot,
                  ulong      parent_slot,
                  ulong      bank_seq,
                  long       parent_ns,
                  long       completed_ns,
                  long       now ) {
  if( parent_slot!=ULONG_MAX ) {
    fd_gui_slot_t * parent = fd_gui_slot_get_or_create( gui, parent_slot, ULONG_MAX, BANK_SEQ, ULONG_MAX );
    FD_TEST( parent );
    parent->completed_time = parent_ns;
  }
  fd_replay_slot_completed_t completed = { .slot=slot, .bank_seq=bank_seq, .parent_slot=parent_slot, .parent_bank_seq=BANK_SEQ,
    .completion_time_nanos=completed_ns, .identity_balance=ULONG_MAX };
  fd_gui_handle_replay_update( gui, &completed, now );
  fd_http_server_stage_trunc( gui->http, 0UL );
}

static void
assert_duration_query( fd_gui_t *    gui,
                        ulong         g,
                        long          reference,
                        ulong const * expected,
                        ulong         cnt ) {
  FD_TEST( !fd_gui_printf_timeline_query_agg( gui, "query_agg_shreds", fd_gui_timeline_granularities[ g ].name, g, reference, cnt, 7UL ) );
  test_json_t values = timeline_value( timeline_response( gui ), "slot_duration" );
  FD_TEST( test_json_count( values )==(int)cnt );
  for( ulong i=0UL; i<cnt; i++ ) {
    test_json_t value = test_json_index( values, (int)i );
    if( expected[ i ]==ULONG_MAX ) FD_TEST( test_json_kind( value )==FD_JTOK_NULL );
    else FD_TEST( test_json_kind( value )==FD_JTOK_INT && test_json_ulong( value )==expected[ i ] );
  }
}

static void
test_timeline_slot_duration( fd_gui_t * gui ) {
  void * http_mem = timeline_http_open( gui );
  gui->summary.slot_caught_up                = ULONG_MAX;
  for( ulong i=0UL; i<FD_GUI_TURBINE_SLOT_HISTORY_SZ; i++ ) gui->summary.slots_max_turbine[ i ].slot = ULONG_MAX;
  long ts  = sec_ns( 100UL );
  long mid = ts+800000000L;
  long now = ts+sec_ns( 2UL );
  /* Four numeric slots spanned; an exact duplicate and a different fork
     all count, even with no canonical ancestry. */
  replay_duration( gui, 104UL, 100UL, BANK_SEQ, ts, ts+1600000000L, now );
  replay_duration( gui, 104UL, 100UL, BANK_SEQ, ts, ts+1600000000L, now );
  replay_duration( gui, 104UL, 100UL, BANK_SEQ+1UL, ts, ts+1600000000L, now );
  FD_TEST( count_ts( gui, FD_GUI_HIST_SLOT_DURATION, ULONG_MAX )==3UL );
  fd_gui_hist_iter_t it;
  FD_TEST( !fd_gui_hist_range_begin( gui, &it, FD_GUI_HIST_SLOT_DURATION, now, now, NULL, NULL ) );
  while( fd_gui_hist_range_next( &it ) ) {
    fd_gui_store_slot_duration_t const * rec = it.rec;
    FD_TEST( rec->insert_time_ns==now && rec->midpoint_ns==mid && rec->slot==104UL && rec->duration_ns==400000000UL );
  }
  fd_gui_hist_range_end( &it );
  fd_gui_timeline_day_t * day = fd_gui_timeline_day_get( gui, 0UL );
  FD_TEST( day );
  for( int g=FD_GUI_TIMELINE_GRANULARITY_250MS; g<(int)FD_GUI_TIMELINE_STORED_GRANULARITY_CNT; g++ ) {
    ulong idx = (ulong)mid/fd_gui_timeline_stored_granularity_ns[ g ];
    FD_TEST( fd_gui_timeline_field_get( day, g, FD_GUI_TIMELINE_FIELD_DURATION_SUM, idx )==1200000000UL );
    FD_TEST( fd_gui_timeline_field_get( day, g, FD_GUI_TIMELINE_FIELD_DURATION_CNT, idx )==3UL );
  }
  for( ulong g=0UL; g<FD_GUI_TIMELINE_GRANULARITY_CNT; g++ ) {
    int stored; ulong merge_cnt;
    if( fd_gui_timeline_tier( "query_agg_shreds", g, &stored, &merge_cnt ) ) continue; /* below the minimum */
    ulong ns = fd_gui_timeline_granularity_ns( g );
    assert_duration_query( gui, g, (long)((ulong)mid/ns*ns), (ulong[]){400000000UL}, 1UL );
  }
  /* Missing/invalid parent and completion times, non-positive gaps, and
     invalid ancestry must not append anything. */
  replay_duration( gui, 108UL, ULONG_MAX, BANK_SEQ, LONG_MAX, now, now );
  replay_duration( gui, 108UL, 107UL, BANK_SEQ, LONG_MAX, now, now );
  replay_duration( gui, 108UL, 107UL, BANK_SEQ, -1L, now, now );
  replay_duration( gui, 108UL, 107UL, BANK_SEQ, ts, LONG_MAX, now );
  replay_duration( gui, 108UL, 107UL, BANK_SEQ, ts, -1L, now );
  replay_duration( gui, 108UL, 107UL, BANK_SEQ, ts, ts, now );
  replay_duration( gui, 108UL, 107UL, BANK_SEQ, ts, ts-1L, now );
  replay_duration( gui, 108UL, 108UL, BANK_SEQ, ts, now, now );
  replay_duration( gui, 108UL, 109UL, BANK_SEQ, ts, now, now );
  FD_TEST( count_ts( gui, FD_GUI_HIST_SLOT_DURATION, ULONG_MAX )==3UL );

  /* Midpoints out of insert order, half-up mean, contained samples take
     precedence over NN, and equidistant neighbors choose the earlier. */
  ts  = sec_ns( 200UL );
  now = ts+sec_ns( 9UL );
  replay_duration( gui, 201UL, 200UL, BANK_SEQ, ts+625000000L-15L, ts+625000000L+15L, now );
  replay_duration( gui, 203UL, 202UL, BANK_SEQ, ts+125000000L-5L, ts+125000000L+5L, now );
  replay_duration( gui, 205UL, 204UL, BANK_SEQ, ts+125000000L-5L, ts+125000000L+6L, now );
  replay_duration( gui, 207UL, 206UL, BANK_SEQ, ts+1125000000L-25L, ts+1125000000L+25L, now );
  fd_gui_store_metrics_t const * metrics = fd_gui_store_metrics( gui->db );
  ulong reads   = metrics->ts_reads[ FD_GUI_HIST_SLOT_DURATION ];
  ulong records = metrics->ts_read_records[ FD_GUI_HIST_SLOT_DURATION ];
  assert_duration_query( gui, 3UL, ts, (ulong[]){11UL,10UL,30UL,30UL,50UL,50UL}, 6UL );
  FD_TEST( metrics->ts_reads[ FD_GUI_HIST_SLOT_DURATION ]==reads+1UL );
  FD_TEST( metrics->ts_read_records[ FD_GUI_HIST_SLOT_DURATION ]==records+4UL );
  assert_duration_query( gui, 3UL, ts+11000000000L, (ulong[]){50UL}, 1UL ); /* exactly cap */
  assert_duration_query( gui, 3UL, ts+11000000001L, (ulong[]){ULONG_MAX}, 1UL );
  assert_duration_query( gui, 3UL, ts-250000000L, (ulong[]){10UL}, 1UL ); /* neighbor after window */
  /* A future neighbor at the cap, inserted another nine seconds later,
     needs both the cap widening and the insert-time margin. */
  assert_duration_query( gui, 3UL, ts-sec_ns( 10UL ), (ulong[]){10UL}, 1UL );
  assert_duration_query( gui, 3UL, ts-sec_ns( 10UL )-1L, (ulong[]){ULONG_MAX}, 1UL );

  /* Availability is the retained day range, not the raw durations. */
  FD_TEST( !fd_gui_printf_timeline_query_agg( gui, "query_agg_shreds", "250ms", 3UL, ts, 1UL, 7UL ) );
  test_json_t json = timeline_response( gui );
  FD_TEST( test_json_string_eq( timeline_value( json, "available_start_ns" ), "0" ) );
  FD_TEST( test_json_string_eq( timeline_value( json, "available_end_ns" ), "86400000000000" ) );

  /* Merged 500ms buckets weight counts, not sub-bucket averages.  Nearby
     empty runs share one scan and tie to the earlier raw sample. */
  ts  = sec_ns( 300UL );
  now = ts+sec_ns( 2UL );
  replay_duration( gui, 301UL, 300UL, BANK_SEQ, ts+125000000L-50L, ts+125000000L+50L, now );
  replay_duration( gui, 301UL, 300UL, BANK_SEQ, ts+125000000L-50L, ts+125000000L+50L, now );
  replay_duration( gui, 303UL, 302UL, BANK_SEQ, ts+375000000L-200L, ts+375000000L+201L, now );
  replay_duration( gui, 305UL, 304UL, BANK_SEQ, ts+1125000000L-450L, ts+1125000000L+450L, now );
  reads = metrics->ts_reads[ FD_GUI_HIST_SLOT_DURATION ];
  assert_duration_query( gui, 4UL, ts, (ulong[]){200UL,401UL,900UL,900UL}, 4UL );
  FD_TEST( metrics->ts_reads[ FD_GUI_HIST_SLOT_DURATION ]==reads+1UL );
  reads = metrics->ts_reads[ FD_GUI_HIST_SLOT_DURATION ];
  assert_duration_query( gui, 4UL, ts, (ulong[]){200UL}, 1UL );
  for( ulong g=10UL; g<FD_GUI_TIMELINE_GRANULARITY_CNT; g++ ) { /* 30s and up: no NN scan */
    ulong ns = fd_gui_timeline_granularity_ns( g );
    assert_duration_query( gui, g, (long)(fd_ulong_max( 600000000000UL, 2UL*ns )/ns*ns), (ulong[]){ULONG_MAX}, 1UL );
  }
  FD_TEST( metrics->ts_reads[ FD_GUI_HIST_SLOT_DURATION ]==reads );

  /* Sticky sum/count overflow cannot turn into a bogus average, including
     when one stored bucket poisons a merged bucket. */
  ts  = sec_ns( 500UL );
  mid = ts+125000000L;
  now = ts+sec_ns( 1UL );
  ulong idx = (ulong)mid/250000000UL;
  fd_gui_timeline_field_set( day, 2, FD_GUI_TIMELINE_FIELD_DURATION_SUM, idx, ULONG_MAX-1UL );
  replay_duration( gui, 501UL, 500UL, BANK_SEQ, mid-50L, mid+50L, now );
  replay_duration( gui, 501UL, 500UL, BANK_SEQ, mid-50L, mid+50L, now );
  FD_TEST( fd_gui_timeline_field_get( day, FD_GUI_TIMELINE_GRANULARITY_250MS, FD_GUI_TIMELINE_FIELD_DURATION_SUM, idx )==ULONG_MAX );
  FD_TEST( fd_gui_timeline_field_get( day, FD_GUI_TIMELINE_GRANULARITY_250MS, FD_GUI_TIMELINE_FIELD_DURATION_CNT, idx )==ULONG_MAX );
  fd_gui_timeline_field_set( day, 3, FD_GUI_TIMELINE_FIELD_DURATION_CNT, (ulong)mid/2000000000UL, UINT_MAX-1UL );
  replay_duration( gui, 501UL, 500UL, BANK_SEQ, mid-50L, mid+50L, now );
  FD_TEST( fd_gui_timeline_field_get( day, 3, FD_GUI_TIMELINE_FIELD_DURATION_SUM, (ulong)mid/2000000000UL )==ULONG_MAX );
  assert_duration_query( gui, 4UL, ts, (ulong[]){100UL}, 1UL ); /* unknown aggregate uses NN */
  ulong sum = ULONG_MAX-2UL;
  ulong cnt = 1UL;
  fd_gui_timeline_duration_merge( &sum, &cnt, 3UL, 1UL );
  FD_TEST( sum==ULONG_MAX && cnt==ULONG_MAX );

  /* Removing raw history removes the nearest-neighbor fill, but does
     not remove valid stored averages. */
  ulong budget = ULONG_MAX;
  int drained;
  FD_TEST( !fd_gui_store_ts_evict( gui->db, FD_GUI_HIST_SLOT_DURATION, ULONG_MAX, &budget, &drained ) );
  assert_duration_query( gui, 3UL, sec_ns( 200UL ), (ulong[]){11UL,ULONG_MAX}, 2UL );
  assert_duration_query( gui, 4UL, sec_ns( 300UL ), (ulong[]){200UL,ULONG_MAX,900UL,ULONG_MAX}, 4UL );
  assert_duration_query( gui, 4UL, ts, (ulong[]){ULONG_MAX}, 1UL );

  /* Empty runs farther apart than twice the widened scan window scan
     separately, so work stays bounded around the gaps. */
  {
    long  far_ts  = sec_ns( 3000UL ); /* after the raw drain above; clear of other windows */
    ulong far_cnt = 200UL; /* 100 seconds of 500ms buckets */
    for( ulong i=1UL; i<far_cnt-1UL; i++ ) {
      long m = far_ts+(long)(i*500000000UL)+250000000L;
      replay_duration( gui, 1000UL+i, 999UL+i, BANK_SEQ, m-50L, m+50L, m+sec_ns( 1UL ) );
    }
    ulong far_expected[ 200 ];
    for( ulong i=0UL; i<far_cnt; i++ ) far_expected[ i ] = 100UL;
    reads = metrics->ts_reads[ FD_GUI_HIST_SLOT_DURATION ];
    assert_duration_query( gui, 4UL, far_ts, far_expected, far_cnt );
    FD_TEST( metrics->ts_reads[ FD_GUI_HIST_SLOT_DURATION ]==reads+2UL );
  }

  /* Attribution follows the midpoint's day, not insertion/completion day. */
  ts = FD_GUI_TIMELINE_DAY_NS;
  replay_duration( gui, 601UL, 600UL, BANK_SEQ, ts-300L, ts+100L, ts+200L );
  day = fd_gui_timeline_day_get( gui, 0UL );
  FD_TEST( fd_gui_timeline_field_get( day, FD_GUI_TIMELINE_GRANULARITY_250MS, FD_GUI_TIMELINE_FIELD_DURATION_SUM, FD_GUI_TIMELINE_250MS_CNT-1UL )==400UL );
  assert_duration_query( gui, 3UL, ts-250000000L, (ulong[]){400UL}, 1UL );

  FD_TEST( fd_http_server_delete( fd_http_server_leave( gui->http ) )==http_mem );
  free( http_mem );
  gui->http = NULL;
  FD_LOG_NOTICE(( "test_timeline_slot_duration: all granularities, replay samples, bounded NN, overflow, eviction: ok" ));
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
      { "query_agg_tile_states", "1s", 0 }
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
    FD_TEST( !fd_gui_timeline_tier( "query_agg_cpu", 5UL, &stored, &merge_cnt ) && stored==FD_GUI_TIMELINE_GRANULARITY_25MS && merge_cnt==40UL );
    FD_TEST( !fd_gui_timeline_tier( "query_agg_cpu", 7UL, &stored, &merge_cnt ) && stored==FD_GUI_TIMELINE_GRANULARITY_2S && merge_cnt==2UL );
    FD_TEST( !fd_gui_timeline_tier( "query_agg_txn", 22UL, &stored, &merge_cnt ) && stored==FD_GUI_TIMELINE_GRANULARITY_12H && merge_cnt==2UL );
    FD_TEST( fd_gui_timeline_tier( "query_agg_tile_states", 5UL, &stored, &merge_cnt )==-1 ); /* 1s */
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
     sigverifies on tile 2 over [0,20), relative to the window start. */
  gui->tile_state.exec_cnt = 3UL;
  gui->tile_state.pos_cnt  = 3UL;
  FD_TEST( !fd_gui_printf_timeline_query_tile_states( gui, txn.sigverify_start_ns, txn.completion_time_ns, 0, 7UL ) );
  test_json_t json = timeline_response( gui );
  {
    FD_TEST( test_json_string_eq( timeline_value( json, "start_ts" ), "10000000000" ) );
    FD_TEST( test_json_ulong( timeline_value( json, "reference_slot" ) )==100UL );
    ulong const state_cnt[] = { 1UL, 3UL, 1UL };
    ulong const state[]     = { FD_GUI_TILE_STATE_IDLE, FD_GUI_TILE_STATE_IDLE, FD_GUI_TILE_STATE_LOADING, FD_GUI_TILE_STATE_IDLE, FD_GUI_TILE_STATE_SIGVERIFY };
    ulong const dur[]       = { 20UL, 1UL, 9UL, 10UL, 20UL };
    FD_TEST( test_json_count( timeline_value( json, "state_cnt" ) )==3 && test_json_count( timeline_value( json, "state" ) )==5 );
    for( int i=0; i<3; i++ ) FD_TEST( test_json_ulong( test_json_index( timeline_value( json, "state_cnt" ), i ) )==state_cnt[ i ] );
    for( int i=0; i<5; i++ ) {
      FD_TEST( test_json_ulong( test_json_index( timeline_value( json, "state" ), i ) )==state[ i ] );
      FD_TEST( test_json_ulong( test_json_index( timeline_value( json, "dur" ),   i ) )==dur[ i ] );
    }
    /* One exec and one sigverify segment for the same txn. */
    FD_TEST( test_json_count( timeline_value( json, "txn_idx" ) )==2 );
    FD_TEST( test_json_ulong( test_json_index( timeline_value( json, "txn_state_lo" ), 0 ) )==2UL );
    FD_TEST( test_json_ulong( test_json_index( timeline_value( json, "txn_state_lo" ), 1 ) )==4UL );
    FD_TEST( test_json_ulong( test_json_index( timeline_value( json, "txn_state_cnt" ), 0 ) )==1UL );
    FD_TEST( test_json_ulong( test_json_index( timeline_value( json, "txn_idx" ), 1 ) )==3UL );
    FD_TEST( test_json_ulong( test_json_index( timeline_value( json, "txn_slot_delta" ), 0 ) )==0UL );
    FD_TEST( test_json_ulong( test_json_index( timeline_value( json, "txn_error_code" ), 0 ) )==0UL );
    FD_TEST( test_json_kind( test_json_index( timeline_value( json, "txn_error_code" ), 1 ) )==FD_JTOK_NULL );
    FD_TEST( !test_json_count( timeline_value( json, "slot_state_lo" ) ) );
  }
  /* A window after the txn finished has only Idle. */
  FD_TEST( !fd_gui_printf_timeline_query_tile_states( gui, txn.completion_time_ns, txn.completion_time_ns+1L, 0, 7UL ) );
  json = timeline_response( gui );
  FD_TEST( !test_json_count( timeline_value( json, "txn_idx" ) ) && test_json_count( timeline_value( json, "state" ) )==3 );
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
  fd_http_server_params_t params = {
    .max_connection_cnt    = 1UL,
    .max_ws_connection_cnt = 1UL,
    .max_request_len       = 1024UL,
    .max_ws_recv_frame_len = 1024UL,
    .max_ws_send_frame_cnt = 4UL,
    .outgoing_buffer_sz    = FD_GUI_HTTP_MIN_SEND_BUFFER_SZ
  };
  void * http_mem = aligned_alloc( fd_http_server_align(), fd_http_server_footprint( params ) );
  FD_TEST( http_mem );
  gui->http = fd_http_server_join( fd_http_server_new( http_mem, params, (fd_http_server_callbacks_t){0}, NULL ) );
  FD_TEST( gui->http );

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

  FD_TEST( fd_http_server_delete( fd_http_server_leave( gui->http ) )==http_mem );
  free( http_mem );
  gui->http = NULL;
  FD_LOG_NOTICE(( "test_timeline_shreds: availability bounds and historical skips: ok" ));
}

static void
test_timeline_agg( fd_gui_t * gui ) {
  fd_http_server_params_t params = {
    .max_connection_cnt    = 1UL,
    .max_ws_connection_cnt = 1UL,
    .max_request_len       = 1024UL,
    .max_ws_recv_frame_len = 1024UL,
    .max_ws_send_frame_cnt = 4UL,
    .outgoing_buffer_sz    = FD_GUI_HTTP_MIN_SEND_BUFFER_SZ
  };
  void * http_mem = aligned_alloc( fd_http_server_align(), fd_http_server_footprint( params ) );
  FD_TEST( http_mem );
  gui->http = fd_http_server_join( fd_http_server_new( http_mem, params, (fd_http_server_callbacks_t){0}, NULL ) );
  FD_TEST( gui->http );

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

  FD_TEST( fd_http_server_delete( fd_http_server_leave( gui->http ) )==http_mem );
  free( http_mem );
  gui->http = NULL;
  FD_LOG_NOTICE(( "test_timeline_agg: requests, replay and leader producers, granularities: ok" ));
}

/* test_timeline_cpu drives the CPU sampler from fake tile metrics and
   checks the per-tile day records: 25ms sample merges, the 2s and
   longer sum/count tiers, the tile whitelist, unknown samples, a
   missing tile record and the availability bounds.  Tile 0 is fully
   busy for two seconds then idle for two; tile 1 is fully busy for two
   seconds then stops publishing; tile 2 has no metrics. */

static void
test_timeline_cpu( fd_gui_t * gui ) {
  fd_http_server_params_t params = {
    .max_connection_cnt    = 1UL,
    .max_ws_connection_cnt = 1UL,
    .max_request_len       = 1024UL,
    .max_ws_recv_frame_len = 1024UL,
    .max_ws_send_frame_cnt = 4UL,
    .outgoing_buffer_sz    = FD_GUI_HTTP_MIN_SEND_BUFFER_SZ
  };
  void * http_mem = aligned_alloc( fd_http_server_align(), fd_http_server_footprint( params ) );
  FD_TEST( http_mem );
  gui->http = fd_http_server_join( fd_http_server_new( http_mem, params, (fd_http_server_callbacks_t){0}, NULL ) );
  FD_TEST( gui->http );

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
  FD_TEST( fd_gui_timeline_tile_day_bounds( gui, FD_GUI_HIST_TIMELINE_TILE_DAY, &lo_day, &hi_day ) && !lo_day && !hi_day );

#define CPU_RESPONSE( gran, ref, util ) \
  "{\"topic\":\"timeline\",\"key\":\"query_agg_cpu\",\"id\":7,\"value\":{\"granularity\":\"" gran "\",\"reference_ts_ns\":\"" ref "\"," \
  "\"available_start_ns\":\"0\",\"available_end_ns\":\"86400000000000\",\"utilization\":" util "}}"

  /* 1s buckets average the 25ms samples; unknown samples are skipped,
     and a tile without a record is null. */
  ulong tiles[ 3 ] = { 0UL, 1UL, 2UL };
  FD_TEST( !fd_gui_printf_timeline_query_agg_cpu( gui, "1s", 5UL, t0, 4UL, tiles, 3UL, 7UL ) );
  check_response( gui, CPU_RESPONSE( "1s", "10000000000", "[[250,250,0,0],[250,250,null,null],[null,null,null,null]]" ) );
  FD_TEST( !fd_gui_printf_timeline_query_agg_cpu( gui, "1s", 5UL, t0+sec_ns( 1UL )+sec_ns( 1UL )/2L, 1UL, tiles, 2UL, 7UL ) );
  check_response( gui, CPU_RESPONSE( "1s", "11500000000", "[[125],[250]]" ) );

  /* The whitelist selects and orders tiles. */
  ulong tile1[ 1 ] = { 1UL };
  FD_TEST( !fd_gui_printf_timeline_query_agg_cpu( gui, "25ms", 0UL, t0+sec_ns( 2UL )-FD_GUI_CPU_UTIL_SAMPLE_NS, 2UL, tile1, 1UL, 7UL ) );
  check_response( gui, CPU_RESPONSE( "25ms", "11975000000", "[[250,null]]" ) );
  ulong tile10[ 2 ] = { 1UL, 0UL };
  FD_TEST( !fd_gui_printf_timeline_query_agg_cpu( gui, "50ms", 1UL, t0+sec_ns( 2UL )-50000000L, 2UL, tile10, 2UL, 7UL ) );
  check_response( gui, CPU_RESPONSE( "50ms", "11950000000", "[[250,null],[250,0]]" ) );
  FD_TEST( !fd_gui_printf_timeline_query_agg_cpu( gui, "100ms", 2UL, t0+sec_ns( 2UL )-100000000L, 2UL, tiles, 1UL, 7UL ) );
  check_response( gui, CPU_RESPONSE( "100ms", "11900000000", "[[250,0]]" ) );
  FD_TEST( !fd_gui_printf_timeline_query_agg_cpu( gui, "250ms", 3UL, t0+sec_ns( 2UL )-125000000L, 1UL, tiles, 2UL, 7UL ) );
  check_response( gui, CPU_RESPONSE( "250ms", "11875000000", "[[125],[250]]" ) );

  /* 2s and longer merge exact sums and counts: tile 1 only counts its
     known samples. */
  FD_TEST( !fd_gui_printf_timeline_query_agg_cpu( gui, "2s", 6UL, t0, 2UL, tiles, 2UL, 7UL ) );
  check_response( gui, CPU_RESPONSE( "2s", "10000000000", "[[250,0],[250,null]]" ) );
  FD_TEST( !fd_gui_printf_timeline_query_agg_cpu( gui, "8s", 8UL, sec_ns( 8UL ), 1UL, tiles, 2UL, 7UL ) );
  check_response( gui, CPU_RESPONSE( "8s", "8000000000", "[[125],[250]]" ) );
#undef CPU_RESPONSE

  /* Only tile 0 publishes into day 1, so tile 1 has no record there:
     its day 1 buckets are null while tile 0's are not. */
  *busy0 += 1000UL;
  *idle0 += 1000UL;
  fd_gui_cpu_util_snap( gui, FD_GUI_TIMELINE_DAY_NS + sec_ns( 1UL ) + 1L );
  FD_TEST( fd_gui_timeline_tile_day_get( gui, 1UL, 0UL ) && !fd_gui_timeline_tile_day_get( gui, 1UL, 1UL ) );
  FD_TEST( fd_gui_timeline_tile_day_bounds( gui, FD_GUI_HIST_TIMELINE_TILE_DAY, &lo_day, &hi_day ) && lo_day==0UL && hi_day==1UL );
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

  /* Work is bounded by tiles x buckets x merged samples.  Every test
     tile at 1s over the full bucket count fits; the maximum tile count
     only fits at 2s and longer. */
  static ulong all[ FD_TOPO_MAX_TILES ];
  for( ulong i=0UL; i<FD_TOPO_MAX_TILES; i++ ) all[ i ] = i;
  FD_TEST( TEST_TILE_CNT*FD_GUI_TIMELINE_QUERY_MAX_BUCKETS*40UL<=FD_GUI_TIMELINE_CPU_QUERY_WORK_MAX );
  FD_TEST( !fd_gui_printf_timeline_query_agg_cpu( gui, "1s", 5UL, 0L, FD_GUI_TIMELINE_QUERY_MAX_BUCKETS, all, TEST_TILE_CNT, 7UL ) );
  fd_http_server_stage_trunc( gui->http, 0UL );
  gui->summary.tile_cnt = FD_TOPO_MAX_TILES;
  for( ulong i=0UL; i<FD_TOPO_MAX_TILES; i++ ) gui->summary.tile[ i ] = i;
  FD_TEST( FD_TOPO_MAX_TILES*FD_GUI_TIMELINE_QUERY_MAX_BUCKETS*40UL>FD_GUI_TIMELINE_CPU_QUERY_WORK_MAX );
  FD_TEST( fd_gui_printf_timeline_query_agg_cpu( gui, "1s", 5UL, 0L, FD_GUI_TIMELINE_QUERY_MAX_BUCKETS, all, FD_TOPO_MAX_TILES, 7UL )==-1 );
  FD_TEST( !fd_gui_printf_timeline_query_agg_cpu( gui, "2s", 6UL, 0L, FD_GUI_TIMELINE_QUERY_MAX_BUCKETS, all, FD_TOPO_MAX_TILES, 7UL ) );
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
    gui->tile_state.cur_day     = ULONG_MAX;
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
    FD_TEST( fd_gui_printf_timeline_query_agg_tile_states( gui, "1s", 5UL, ref, 2UL, 7UL )==-1 ); /* 2s minimum */

    FD_TEST( !fd_gui_printf_timeline_query_tile_states( gui, ref, ref+sec_ns( 4UL ), 0, 7UL ) );
    json = timeline_response( gui );
    FD_TEST( test_json_ulong( timeline_value( json, "reference_slot" ) )==42UL );
    FD_TEST( test_json_count( timeline_value( json, "tile" ) )==2 );
    FD_TEST( test_json_ulong( test_json_index( timeline_value( json, "tile" ), 1 ) )==1UL );
    FD_TEST( test_json_ulong( test_json_index( timeline_value( json, "state_cnt" ), 1 ) )==3UL ); /* Idle, network, Idle */
    FD_TEST( test_json_ulong( test_json_index( timeline_value( json, "state" ), 2 ) )==FD_GUI_TILE_STATE_BLOCKED_ON_NETWORK );
    long dur = (long)test_json_ulong( test_json_index( timeline_value( json, "dur" ), 2 ) );
    FD_TEST( dur>=sec_ns( 2UL )-slack && dur<=sec_ns( 2UL )+slack );
    FD_TEST( test_json_count( timeline_value( json, "slot_state_lo" ) )==1 );
    FD_TEST( test_json_ulong( test_json_index( timeline_value( json, "slot_state_lo" ), 0 ) )==2UL );
    FD_TEST( test_json_ulong( test_json_index( timeline_value( json, "slot_state_cnt" ), 0 ) )==1UL );
    FD_TEST( test_json_ulong( test_json_index( timeline_value( json, "slot_delta" ), 0 ) )==0UL );
    FD_TEST( !test_json_count( timeline_value( json, "txn_idx" ) ) );

    gui->tile_state.exec_cnt = 0UL;
    gui->tile_state.pos_cnt  = 0UL;
    gui->tick_per_ns = tick_per_ns;
  }

  gui->topo = NULL;
  free( topo );
  FD_TEST( fd_http_server_delete( fd_http_server_leave( gui->http ) )==http_mem );
  free( http_mem );
  gui->http = NULL;
  FD_LOG_NOTICE(( "test_timeline_cpu: ok" ));
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
  ulong min_bytes = fd_gui_store_min_size( FD_GUI_HIST_CNT, fd_gui_hist_db_descs( TEST_STORE_BYTES, TEST_TILE_CNT ) );
  store_open( fec, min_bytes, 31 );
  test_fec_minimum_store( fec->gui );
  store_close( fec );
  store_open( fec, min_bytes, 33 );
  test_tile_day_minimum_store( fec->gui );
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

  store_open( s11, TEST_STORE_BYTES, 16 );
  test_timeline_slot_duration( s11->gui );
  store_close( s11 );

  test_store_t s12[ 1 ];
  store_open( s12, TEST_STORE_BYTES, 17 );
  test_timeline_slot_intervals( s12->gui );
  store_close( s12 );

  store_open( s12, TEST_STORE_BYTES, 17 );
  test_timeline_replayed_skips( s12->gui );
  store_close( s12 );

  store_open( s12, TEST_STORE_BYTES, 17 );
  test_timeline_ancestry( s12->gui );
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

  test_store_t s15[ 1 ];
  store_open( s15, TEST_STORE_BYTES, 20 );
  test_timeline_completion_overflow( s15 );
  store_close( s15 );

  test_store_t s17[ 1 ];
  store_open( s17, TEST_STORE_BYTES, 22 );
  test_timeline_batch_parity( s17->gui );
  store_close( s17 );

  test_store_t s18[ 1 ];
  store_open( s18, TEST_STORE_BYTES, 23 );
  test_timeline_closure_cutoff( s18->gui );
  store_close( s18 );

  test_store_t s19[ 1 ];
  store_open( s19, TEST_STORE_BYTES, 24 );
  test_timeline_day_recovery( s19->gui );
  store_close( s19 );

  test_store_t s20[ 1 ];
  store_open( s20, TEST_STORE_BYTES, 25 );
  test_timeline_marker_limits( s20->gui );
  store_close( s20 );

  test_store_t s21[ 1 ];
  store_open( s21, TEST_STORE_BYTES, 26 );
  test_timeline_marker_order( s21->gui );
  store_close( s21 );

  if( !run_all ) FD_LOG_NOTICE(( "skipped 8 expensive tests; pass --run-all to run them" ));
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
