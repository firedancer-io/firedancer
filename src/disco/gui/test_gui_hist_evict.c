/* test_gui_hist_evict exercises the space-pressure epoch-cascade eviction in
   fd_gui_hist: fd_gui_hist_evict_oldest (the synchronous drain used by the
   map-full fallback and driven one batch at a time by
   fd_gui_hist_evict_step).  It builds multiple epochs' worth of records -- the
   EPOCH records, the per-slot (slot,bank_seq) entity rows, and the
   time-bucketed time-series rows -- then evicts the oldest epoch and asserts
   that exactly that epoch's rows are gone while the newer epochs survive,
   including the SHRED_EVENTS boundary case (a slot of the NEXT epoch whose
   event landed in a wallclock second shared with the oldest epoch's tail).

   The eviction path only touches gui->db / gui->hist, so the test allocates a
   bare fd_gui_t (like test_gui_consensus) and wires up the two store layers
   by hand -- no http server / topology / fd_gui_new. */

#include "../../util/fd_util.h"
#include "fd_gui.h"
#include "fd_gui_store.h"
#include "fd_gui_hist.h"
#include "fd_gui_printf.h"
#include "../fd_txn_m.h"
#include "../../ballet/json/fd_jtok.h"
#include "../../waltz/http/fd_http_server_private.h"

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

/* Put epoch A immediately before a UTC-day boundary and epochs B/C after it.
   This lets the cascade test verify that timeline-day eviction retains the
   day shared by the first surviving epoch while reclaiming older days. */
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
  memset( rec->vote_count, 0xFF, sizeof(rec->vote_count) );

  gui->epoch.stored_epoch_cnt++; /* mirror fd_gui_handle_epoch_info; the >= FD_GUI_HIST_MIN_EPOCHS guard reads this */
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

/* put_leader_slot_seq writes a leader-slot-meta row at (slot,bank_seq).
   Used by the trigger test to pad the store with many distinct, committed
   keys (so used-bytes grows immediately, no flush needed) that still belong
   to an evictable epoch's slot.  (The trigger test batches these inline for
   speed; this single-row form documents the shape.) */
FD_FN_UNUSED static void
put_leader_slot_seq( fd_gui_t * gui, ulong slot, ulong bank_seq ) {
  fd_gui_hist_leader_slot_key_t key[ 1 ];
  key->slot = slot; key->bank_seq = bank_seq;

  fd_gui_leader_slot_t * rec = fd_gui_hist_kv_get_or_create( gui, FD_GUI_HIST_LEADER_SLOT, key );
  FD_TEST( rec );
  memset( rec, 0, sizeof(*rec) );
  rec->slot     = slot;
  rec->bank_seq = bank_seq;
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
  fd_gui_shred_event_append( gui, slot, 0UL, FD_GUI_SLOT_SHRED_REPAIR_REQUEST, ts_ns, insert_time_ns );
  fd_gui_shred_flush( gui, insert_time_ns+sec_ns( 1UL ) );
}

static void
append_replay_txn( fd_gui_t * gui,
                   long       now_ns,
                   long       ts_ns,
                   ulong      slot ) {
  fd_gui_store_replay_txn_t rec[ 1 ];
  memset( rec, 0, sizeof(*rec) );
  rec->insert_time_ns     = now_ns;
  rec->completion_time_ns = ts_ns;
  rec->slot               = slot;

  FD_TEST( !fd_gui_hist_ts_append( gui, FD_GUI_HIST_REPLAY_TXN, rec ) );
}

static void
put_timeline_day( fd_gui_t * gui,
                  ulong      day ) {
  fd_gui_timeline_day_t * rec = aligned_alloc( alignof(fd_gui_timeline_day_t), sizeof(fd_gui_timeline_day_t) );
  FD_TEST( rec );
  memset( rec, 0xFF, sizeof(*rec) );
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
  if( dbi==FD_GUI_HIST_SHRED_EVENTS ) {
    fd_gui_shred_event_iter_t it[ 1 ];
    fd_gui_shred_event_iter_begin( gui, it, 0L, LONG_MAX );
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
test_evict_oldest_epoch( fd_gui_t * gui ) {
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

  /* --- evict the oldest epoch (A); B and C stay resident (the current +
     next epochs the floor protects) --------------------------------- */
  FD_TEST( fd_gui_hist_evict_oldest( gui )==1 );

  /* epoch A entirely gone; epochs B and C intact */
  FD_TEST( !epoch_present( gui, EPOCH_A ) );
  FD_TEST(  epoch_present( gui, EPOCH_B ) );
  FD_TEST(  epoch_present( gui, EPOCH_C ) );
  FD_TEST(  timeline_day_present( gui, 0UL ) );
  FD_TEST(  timeline_day_present( gui, 1UL ) );

  for( ulong s=A_START_SLOT; s<=A_END_SLOT; s++ ) {
    FD_TEST( !slot_meta_present( gui, FD_GUI_HIST_SLOT, s ) );
    FD_TEST( !slot_meta_present( gui, FD_GUI_HIST_LEADER_SLOT, s ) );
  }
  for( ulong s=B_START_SLOT; s<=C_END_SLOT; s++ ) {
    FD_TEST( slot_meta_present( gui, FD_GUI_HIST_SLOT, s ) );
    FD_TEST( slot_meta_present( gui, FD_GUI_HIST_LEADER_SLOT, s ) );
  }

  /* time-series: epoch A windows [86390,86399] gone, epochs B+C windows
     [86400,86419] kept.  scheduler_counts had 10 in epoch A, 20 across B+C. */
  FD_TEST( count_ts( gui, FD_GUI_HIST_SCHEDULER_COUNTS, ULONG_MAX )==20UL );
  FD_TEST( count_ts( gui, FD_GUI_HIST_REPLAY_TXN,       ULONG_MAX )==20UL );

  FD_TEST( count_ts( gui, FD_GUI_HIST_SHRED_EVENTS, ULONG_MAX )==21UL );
  FD_TEST( count_ts( gui, FD_GUI_HIST_SHRED_EVENTS, B_START_SLOT )==2UL );
  /* an evicted epoch-A slot has no shred rows left */
  FD_TEST( count_ts( gui, FD_GUI_HIST_SHRED_EVENTS, A_START_SLOT )==0UL );

  /* --- guard: only epochs B and C remain (== FD_GUI_HIST_MIN_EPOCHS-1) so
     eviction refuses.  The current in-progress epoch and the next epoch must
     always stay resident, so fd_gui_hist_evict_oldest is a no-op here. */
  FD_TEST( fd_gui_hist_evict_oldest( gui )==0 );
  FD_TEST( epoch_present( gui, EPOCH_B ) );
  FD_TEST( epoch_present( gui, EPOCH_C ) );
  FD_TEST( count_ts( gui, FD_GUI_HIST_SCHEDULER_COUNTS, ULONG_MAX )==20UL );
  FD_TEST( count_ts( gui, FD_GUI_HIST_SHRED_EVENTS,     ULONG_MAX )==21UL );
  FD_TEST( count_ts( gui, FD_GUI_HIST_REPLAY_TXN,       ULONG_MAX )==20UL );

  FD_LOG_NOTICE(( "test_evict_oldest_epoch: ok" ));
}

/* test_evict_large_batch checks the resumable batching: an epoch with more
   than FD_GUI_HIST_EVICT_BATCH (512) distinct time-series keys must still be
   fully drained by fd_gui_hist_evict_oldest (which loops the bounded
   per-batch fd_gui_hist_evict_one until the cascade completes). */

#define BIG_EPOCH       (20UL)
#define BIG_START_SLOT  (2000UL)
#define BIG_SLOT_CNT    (1000UL) /* > 512, forces multiple delete batches */
#define BIG_KEEP_EPOCH  (21UL)   /* a newer epoch so BIG is the oldest + survivors remain */
#define BIG_KEEP_START  (3000UL)
#define BIG_KEEP2_EPOCH (22UL)   /* second keeper so we stay above FD_GUI_HIST_MIN_EPOCHS */
#define BIG_KEEP2_START (4000UL)

static void
test_evict_large_batch( fd_gui_t * gui ) {
  put_epoch( gui, BIG_EPOCH, BIG_START_SLOT, BIG_SLOT_CNT );

  /* one shred-event key per slot; distinct slots -> distinct keys.  Pack the
     timestamps into a compact window range. */
  ulong end_slot = BIG_START_SLOT + BIG_SLOT_CNT - 1UL;
  for( ulong s=BIG_START_SLOT; s<=end_slot; s++ ) {
    put_slot( gui, s, slot_complete_ns( 1000UL + (s-BIG_START_SLOT) ) );
    append_shred( gui, slot_complete_ns( 1000UL + (s-BIG_START_SLOT) ), slot_complete_ns( 1000UL + (s-BIG_START_SLOT) ), s );
  }
  /* newer epochs (so BIG is the oldest, and the >= FD_GUI_HIST_MIN_EPOCHS guard
     is satisfied); the immediately-following epoch's first slot replay meta
     bounds BIG's time-series eviction window. */
  put_epoch( gui, BIG_KEEP_EPOCH, BIG_KEEP_START, BIG_SLOT_CNT );
  put_slot( gui, BIG_KEEP_START, slot_complete_ns( 1000UL + BIG_SLOT_CNT ) );
  put_epoch( gui, BIG_KEEP2_EPOCH, BIG_KEEP2_START, BIG_SLOT_CNT );
  put_slot( gui, BIG_KEEP2_START, slot_complete_ns( 1000UL + 2UL*BIG_SLOT_CNT ) );

  FD_TEST( count_ts( gui, FD_GUI_HIST_SHRED_EVENTS, ULONG_MAX )==BIG_SLOT_CNT );
  FD_TEST( epoch_present( gui, BIG_EPOCH ) );

  /* single synchronous drain must clear all 1000 keys (crossing the 512
     per-batch budget several times) */
  FD_TEST( fd_gui_hist_evict_oldest( gui )==1 );
  FD_TEST( !epoch_present( gui, BIG_EPOCH ) );
  FD_TEST(  epoch_present( gui, BIG_KEEP_EPOCH ) );
  FD_TEST(  epoch_present( gui, BIG_KEEP2_EPOCH ) );
  FD_TEST( count_ts( gui, FD_GUI_HIST_SHRED_EVENTS, ULONG_MAX )==0UL );
  for( ulong s=BIG_START_SLOT; s<=end_slot; s++ ) {
    FD_TEST( !slot_meta_present( gui, FD_GUI_HIST_SLOT, s ) );
  }

  FD_LOG_NOTICE(( "test_evict_large_batch: ok" ));
}

/* test_current_epoch_protected is the direct regression for the blank-nav-bar
   bug: at startup the validator publishes epoch info for the current
   (in-progress) epoch and the next epoch, so exactly two epochs are resident.
   Whole-epoch eviction must NEVER shed the current epoch in that state --
   doing so strips the leader schedule for "now" and the GUI nav bar goes
   blank.  The floor keeps at least FD_GUI_HIST_MIN_EPOCHS resident, so with
   only current + next present eviction must refuse. */

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

  FD_TEST( gui->epoch.stored_epoch_cnt==2UL );

  /* Two epochs resident (== FD_GUI_HIST_MIN_EPOCHS-1): eviction must refuse so
     the current epoch's schedule stays available to the GUI. */
  FD_TEST( fd_gui_hist_evict_oldest( gui )==0 );
  FD_TEST( epoch_present( gui, CP_CUR_EPOCH ) );
  FD_TEST( epoch_present( gui, CP_NEXT_EPOCH ) );
  FD_TEST( gui->epoch.stored_epoch_cnt==2UL );

  FD_LOG_NOTICE(( "test_current_epoch_protected: ok" ));
}

/* test_evict_ts_oldest_fallback covers fd_gui_hist_evict_ts_oldest, the
   last-resort reclaimer used when whole-epoch eviction is guard-blocked
   (fewer than FD_GUI_HIST_MIN_EPOCHS resident) yet space is still needed.  It
   must shed time-series data one oldest window at a time WITHOUT touching
   epoch/slot metadata. */

#define TS_EPOCH      (30UL)
#define TS_START_SLOT (4000UL)
#define TS_SLOT_CNT   (5UL)

static void
test_evict_ts_oldest_fallback( fd_gui_t * gui ) {
  /* A single epoch (below FD_GUI_HIST_MIN_EPOCHS, so the whole-epoch guard
     blocks eviction) with time-series data spread over 5 distinct windows
     [50,54]. */
  put_epoch( gui, TS_EPOCH, TS_START_SLOT, TS_SLOT_CNT );
  put_slot( gui, TS_START_SLOT, slot_complete_ns( 990UL+50UL ) );
  for( ulong sec=50UL; sec<=54UL; sec++ ) {
    append_sched_counts( gui, sec_ns( sec ) );
    append_shred( gui, sec_ns( sec ), sec_ns( sec ), TS_START_SLOT + (sec-50UL) );
  }

  FD_TEST(  epoch_present( gui, TS_EPOCH ) );
  FD_TEST( count_ts( gui, FD_GUI_HIST_SCHEDULER_COUNTS, ULONG_MAX )==5UL );
  FD_TEST( count_ts( gui, FD_GUI_HIST_SHRED_EVENTS,     ULONG_MAX )==5UL );

  /* Whole-epoch eviction refuses (below FD_GUI_HIST_MIN_EPOCHS resident). */
  FD_TEST( fd_gui_hist_evict_oldest( gui )==0 );
  FD_TEST( gui->epoch.stored_epoch_cnt==1UL );

  /* The TS fallback sheds the oldest live window (50) across all TS DBs in one
     step: one scheduler-counts row and one shred row drop, the epoch and its
     slot metadata are untouched. */
  FD_TEST( fd_gui_hist_evict_ts_oldest( gui )==1 );
  FD_TEST(  epoch_present( gui, TS_EPOCH ) );
  FD_TEST(  slot_meta_present( gui, FD_GUI_HIST_SLOT, TS_START_SLOT ) );
  FD_TEST( count_ts( gui, FD_GUI_HIST_SCHEDULER_COUNTS, ULONG_MAX )==4UL );
  FD_TEST( count_ts( gui, FD_GUI_HIST_SHRED_EVENTS,     ULONG_MAX )==4UL );

  /* Drive it to exhaustion: each call sheds the next-oldest window until the
     TS DBs are empty, at which point it reports 0 (nothing left). */
  for( int i=0; i<4; i++ ) FD_TEST( fd_gui_hist_evict_ts_oldest( gui )==1 );
  FD_TEST( count_ts( gui, FD_GUI_HIST_SCHEDULER_COUNTS, ULONG_MAX )==0UL );
  FD_TEST( count_ts( gui, FD_GUI_HIST_SHRED_EVENTS,     ULONG_MAX )==0UL );
  FD_TEST( fd_gui_hist_evict_ts_oldest( gui )==0 ); /* genuinely nothing left */
  /* Epoch metadata survived the entire TS drain. */
  FD_TEST(  epoch_present( gui, TS_EPOCH ) );

  FD_LOG_NOTICE(( "test_evict_ts_oldest_fallback: ok" ));
}


static void
test_evict_timeline_ts_fallback( fd_gui_t * gui ) {
  ulong day_cnt = 0UL;
  while( fd_gui_store_free_region_cnt( gui->db ) ) {
    put_timeline_day( gui, day_cnt++ );
  }
  FD_TEST( day_cnt>1UL );
  FD_TEST( timeline_day_present( gui, 0UL ) );
  FD_TEST( !fd_gui_hist_evict_oldest( gui ) );
  ulong evicted_before = fd_gui_store_metrics( gui->db )->evict_records[ FD_GUI_HIST_TIMELINE_DAY ];
  ulong reserves_before = fd_gui_hist_metrics( gui )->reserves[ FD_GUI_HIST_TIMELINE_DAY ];
  fd_gui_store_metrics_t store_before = *fd_gui_store_metrics( gui->db );
  fd_gui_hist_metrics_t hist_before = *fd_gui_hist_metrics( gui );
  fd_gui_timeline_day_t * regression = aligned_alloc( alignof(fd_gui_timeline_day_t), sizeof(fd_gui_timeline_day_t) );
  FD_TEST( regression );
  memset( regression, 0, sizeof(*regression) );
  regression->insert_time_ns = timeline_day_end_ns( day_cnt-1UL )+sec_ns( 100UL )-1L;
  FD_TEST( fd_gui_hist_ts_append( gui, FD_GUI_HIST_TIMELINE_DAY, regression )==-1 );
  FD_TEST( !fd_gui_store_free_region_cnt( gui->db ) );
  FD_TEST( !memcmp( &store_before, fd_gui_store_metrics( gui->db ), sizeof(store_before) ) );
  FD_TEST( !memcmp( &hist_before, fd_gui_hist_metrics( gui ), sizeof(hist_before) ) );
  free( regression );
  put_timeline_day( gui, day_cnt );

  FD_TEST( fd_gui_store_metrics( gui->db )->evict_records[ FD_GUI_HIST_TIMELINE_DAY ]==evicted_before+1UL );
  FD_TEST( fd_gui_hist_metrics( gui )->reserves[ FD_GUI_HIST_TIMELINE_DAY ]==reserves_before+1UL );
  FD_TEST( !timeline_day_present( gui, 0UL ) );
  for( ulong day=1UL; day<=day_cnt; day++ ) FD_TEST( timeline_day_present( gui, day ) );

  FD_LOG_NOTICE(( "test_evict_timeline_ts_fallback: ok" ));
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
  /* Three epochs durable (satisfies the >= FD_GUI_HIST_MIN_EPOCHS eviction
     guard so the oldest can be evicted while two keepers remain). */
  put_epoch( gui, RM_OLD_EPOCH, RM_OLD_START, RM_SLOT_CNT );
  put_epoch( gui, RM_NEW_EPOCH, RM_NEW_START, RM_SLOT_CNT );
  put_epoch( gui, RM_NEW2_EPOCH, RM_NEW2_START, RM_SLOT_CNT );
  /* the older epoch's time-series window is bounded by the next epoch's first
     completed slot, so give each a replay meta. */
  put_slot( gui, RM_OLD_START, slot_complete_ns( 1000UL ) );
  put_slot( gui, RM_NEW_START, slot_complete_ns( 2000UL ) );
  put_slot( gui, RM_NEW2_START, slot_complete_ns( 3000UL ) );

  /* Resolve the newer (resident) epoch's record pointer and mutate the
     per-epoch bookkeeping fields in place. */
  fd_gui_hist_epoch_key_t key[ 1 ]; key->epoch = RM_NEW_EPOCH;
  fd_gui_epoch_t * rec = (fd_gui_epoch_t *)fd_gui_hist_kv_get( gui, FD_GUI_HIST_EPOCH, key );
  FD_TEST( rec );
  rec->my_total_slots          = 7UL;
  rec->my_skipped_slots        = 3UL;
  rec->latency_exact[ 0 ]      = 2;
  rec->rankings->largest_tips[ 0 ].slot  = RM_NEW_START + 4UL;
  rec->rankings->largest_tips[ 0 ].value = 12345UL;

  /* A fresh get must observe the in-place writes (no put/round-trip). */
  fd_gui_epoch_t * rec2 = (fd_gui_epoch_t *)fd_gui_hist_kv_get( gui, FD_GUI_HIST_EPOCH, key );
  FD_TEST( rec2==rec ); /* stable map pointer */
  FD_TEST( rec2->my_total_slots==7UL );
  FD_TEST( rec2->my_skipped_slots==3UL );

  /* Evict the older epoch; the newer epoch's record and its mutated fields
     must be untouched, and its map pointer must remain valid. */
  FD_TEST( fd_gui_hist_evict_oldest( gui )==1 );
  FD_TEST( !epoch_present( gui, RM_OLD_EPOCH ) );
  FD_TEST(  epoch_present( gui, RM_NEW_EPOCH ) );
  FD_TEST(  epoch_present( gui, RM_NEW2_EPOCH ) );

  fd_gui_epoch_t * rec3 = (fd_gui_epoch_t *)fd_gui_hist_kv_get( gui, FD_GUI_HIST_EPOCH, key );
  FD_TEST( rec3==rec );
  FD_TEST( rec3->epoch==RM_NEW_EPOCH );
  FD_TEST( rec3->my_total_slots==7UL );
  FD_TEST( rec3->my_skipped_slots==3UL );
  FD_TEST( rec3->latency_exact[ 0 ]==2 );
  FD_TEST( rec3->rankings->largest_tips[ 0 ].slot==RM_NEW_START + 4UL );
  FD_TEST( rec3->rankings->largest_tips[ 0 ].value==12345UL );

  FD_LOG_NOTICE(( "test_resident_meta_mutation_survives_evict: ok" ));
}

/* test_epoch_region_reclaimed tests epoch eviction shrinking the
   DB's committed footprint. */

#define RR_A_EPOCH (50UL)
#define RR_A_START (7000UL)
#define RR_SLOT_CNT (5UL)

static void
test_epoch_region_reclaimed( fd_gui_t * gui ) {
  ulong const epoch_region_capacity =
      FD_GUI_STORE_REGION_SZ / fd_ulong_align_up( sizeof(fd_gui_epoch_t), 8UL );
  FD_TEST( epoch_region_capacity>0UL );

  /* Keep three epochs durable so the oldest remains evictable while two
     keepers survive. */
  for( ulong ordinal=0UL; ordinal<3UL; ordinal++ ) {
    ulong epoch = RR_A_EPOCH + ordinal;
    ulong start = RR_A_START + ordinal*RR_SLOT_CNT;
    put_epoch( gui, epoch, start, RR_SLOT_CNT );
    put_slot( gui, start, slot_complete_ns( 1000UL + ordinal ) );
  }

  /* Rotate until the oldest live record is the final slot in its region.
     This is a no-op when each epoch record already occupies a whole region. */
  for( ulong ordinal=3UL; ordinal<epoch_region_capacity+2UL; ordinal++ ) {
    FD_TEST( fd_gui_hist_evict_oldest( gui )==1 );
    ulong epoch = RR_A_EPOCH + ordinal;
    ulong start = RR_A_START + ordinal*RR_SLOT_CNT;
    put_epoch( gui, epoch, start, RR_SLOT_CNT );
    put_slot( gui, start, slot_complete_ns( 1000UL + ordinal ) );
  }

  ulong oldest = RR_A_EPOCH + epoch_region_capacity - 1UL;
  FD_TEST( epoch_present( gui, oldest      ) );
  FD_TEST( epoch_present( gui, oldest+1UL ) );
  FD_TEST( epoch_present( gui, oldest+2UL ) );

  /* The next eviction advances the EPOCH watermark across a region boundary. */
  ulong used_before = fd_gui_store_used_bytes( gui->db );
  FD_TEST( used_before>0UL );

  FD_TEST( fd_gui_hist_evict_oldest( gui )==1 );
  FD_TEST( !epoch_present( gui, oldest      ) );
  FD_TEST(  epoch_present( gui, oldest+1UL ) );
  FD_TEST(  epoch_present( gui, oldest+2UL ) );

  ulong used_after = fd_gui_store_used_bytes( gui->db );
  FD_TEST( used_after<used_before );

  FD_LOG_NOTICE(( "test_epoch_region_reclaimed: used %lu -> %lu bytes; ok",
                  used_before, used_after ));
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

  s->db_mem = aligned_alloc( fd_gui_store_align(),
                             fd_ulong_align_up( fd_gui_store_footprint( map_bytes, fd_gui_hist_db_cnt(), fd_gui_hist_db_descs( map_bytes ) ), fd_gui_store_align() ) );
  FD_TEST( s->db_mem );
  s->gui->db = fd_gui_store_join( fd_gui_store_new( s->db_mem, s->path, map_bytes, fd_gui_hist_db_cnt(), 0x0123456789abcdefUL, fd_gui_hist_db_descs( map_bytes ) ) );
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
  fd_gui_store_desc_t const * descs = fd_gui_hist_db_descs( 1UL<<30 );
  FD_TEST( FD_GUI_HIST_TIMELINE_DAY==11 );
  FD_TEST( FD_GUI_HIST_REPLAY_TXN==12 );
  FD_TEST( FD_GUI_HIST_CNT==13 );
  FD_TEST( !strcmp( descs[ FD_GUI_HIST_TIMELINE_DAY     ].name, "timeline_day"     ) );
  FD_TEST( !strcmp( descs[ FD_GUI_HIST_REPLAY_TXN       ].name, "replay_txn"       ) );
  FD_TEST( descs[ FD_GUI_HIST_SHRED_EVENTS     ].val_sz==sizeof(fd_gui_shred_batch_t) );
  FD_TEST( descs[ FD_GUI_HIST_TIMELINE_DAY     ].val_sz==sizeof(fd_gui_timeline_day_t) );
  FD_TEST( descs[ FD_GUI_HIST_TIMELINE_DAY ].kind==FD_GUI_STORE_KIND_TS );
  FD_TEST( descs[ FD_GUI_HIST_TIMELINE_DAY     ].ts_off==offsetof(fd_gui_timeline_day_t,end_time_ns) );
  FD_TEST( descs[ FD_GUI_HIST_SHRED_EVENTS     ].ts_off==offsetof(fd_gui_shred_batch_t,insert_time_ns) );
  FD_TEST( descs[ FD_GUI_HIST_TXN_START        ].ts_off==offsetof(fd_gui_store_txn_start_t,insert_time_ns) );
  FD_TEST( descs[ FD_GUI_HIST_TXN_END          ].ts_off==offsetof(fd_gui_store_txn_end_t,insert_time_ns) );
  FD_TEST( descs[ FD_GUI_HIST_REPLAY_TXN       ].ts_off==offsetof(fd_gui_store_replay_txn_t,insert_time_ns) );
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
  FD_TEST( sizeof(day->bucket_250ms.skipped[0])==sizeof(ushort) );
  FD_TEST( sizeof(day->bucket_2h.skipped[0])==sizeof(ushort) );
  FD_TEST( sizeof(day->bucket_12h.skipped[0])==sizeof(uint) );
  FD_TEST( sizeof(day->bucket_15s.compute_units[0])==sizeof(ulong) );
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
  lslot->scheduler_stats->end_slot_reason = FD_PACK_END_SLOT_REASON_TIME;

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
test_shred_encoding( fd_gui_t * gui ) {
  long const base = sec_ns( 100UL );
  fd_gui_shred_event_t events[] = {
    { base+1L, 1L,        700U, 1U,         FD_GUI_SLOT_SHRED_REPAIR_REQUEST },
    { base+1L, 1L,        700U, 1U,         FD_GUI_SLOT_SHRED_REPAIR_REQUEST },
    { base+2L, 4L,        700U, 255U,       FD_GUI_SLOT_SHRED_SHRED_RECEIVED_TURBINE },
    { base+3L, 2L,        700U, 0U,         FD_GUI_SLOT_SHRED_SHRED_RECEIVED_REPAIR },
    { base+4L, LONG_MIN,  701U, 65000U,     FD_GUI_SLOT_SHRED_SHRED_PUBLISHED },
    { base+5L, LONG_MAX,  701U, USHORT_MAX, FD_GUI_SLOT_SHRED_SHRED_SLOT_COMPLETE },
    { base+6L, 0L,        701U, 65000U,     FD_GUI_SLOT_SHRED_SHRED_REPLAY_EXEC_DONE },
    { base+7L, 0L,        701U, 0U,         FD_GUI_SLOT_SHRED_REPAIR_REQUEST },
    { base+8L, 0xFFFFFFL, 701U, 255U,       FD_GUI_SLOT_SHRED_REPAIR_REQUEST },
    { base+9L, 0x1FFFFFFL,701U, 511U,       FD_GUI_SLOT_SHRED_REPAIR_REQUEST },
    { base+10L,0xFFFFFFL, 701U, 256U,       FD_GUI_SLOT_SHRED_REPAIR_REQUEST },
    { base+sec_ns(1UL), -100L, 702U, 10U,   FD_GUI_SLOT_SHRED_SHRED_RECEIVED_TURBINE }
  };
  ulong cnt = sizeof(events)/sizeof(events[0]);
  /* Replay/root metadata must not suppress late arrivals. */
  put_slot( gui, 701UL, 10L );
  gui->summary.slot_rooted = 702UL;
  for( ulong i=0UL; i<cnt; i++ ) {
    fd_gui_shred_event_t const * e = events+i;
    if( e->event==FD_GUI_SLOT_SHRED_REPAIR_REQUEST ) {
      fd_gui_handle_repair_request( gui, e->slot, e->idx, e->event_time_ns, e->insert_time_ns );
    } else {
      fd_gui_shred_event_append( gui, e->slot, e->idx, e->event, e->event_time_ns, e->insert_time_ns );
    }
    assert_shreds( gui, events, i+1UL, base, e->insert_time_ns );
  }
  FD_TEST( fd_gui_store_metrics( gui->db )->ts_appends[ FD_GUI_HIST_SHRED_EVENTS ]==1UL );
  FD_TEST( gui->shreds.builder.batch.event_cnt==1U );
  FD_TEST( fd_gui_shred_window_is_empty( gui, 0L, 10L ) ); /* insertion, not event time */
  assert_shreds( gui, events, 2UL, base+1L, base+1L );
  assert_shreds( gui, events+cnt-1UL, 1UL, base+sec_ns(1UL), base+sec_ns(1UL) );
  FD_TEST( fd_gui_shred_window_is_empty( gui, base+11L, base+sec_ns(1UL)-1L ) );

  /* Polls leave this second's partial block available to queries. */
  fd_gui_shred_flush( gui, base+sec_ns(1UL)+1L );
  FD_TEST( gui->shreds.builder.batch.event_cnt==1U );
  fd_gui_shred_flush( gui, base+sec_ns(2UL) );
  FD_TEST( !gui->shreds.builder.batch.event_cnt );
  assert_shreds( gui, events, cnt, base, base+sec_ns(1UL) );

  fd_gui_shred_event_t later[] = {
    { base+sec_ns(3UL), 4L, 703U, 0U, FD_GUI_SLOT_SHRED_REPAIR_REQUEST },
    { base+sec_ns(5UL), 2L, 703U, 0U, FD_GUI_SLOT_SHRED_REPAIR_REQUEST }
  };
  for( ulong i=0UL; i<2UL; i++ ) {
    fd_gui_handle_repair_request( gui, later[i].slot, later[i].idx, later[i].event_time_ns, later[i].insert_time_ns );
  }
  fd_gui_shred_flush( gui, base+sec_ns(6UL) );
  assert_shreds( gui, later, 2UL, base+sec_ns(3UL), base+sec_ns(6UL) );
  FD_TEST( !gui->shreds.dropped_event_cnt );
  FD_LOG_NOTICE(( "test_shred_encoding: ok" ));
}

static void
test_shred_storage( fd_gui_t * gui ) {
  ulong const cnt = 70000UL;
  long const base = sec_ns( 200UL );
  fd_gui_shred_event_t * events = malloc( cnt*sizeof(fd_gui_shred_event_t) );
  FD_TEST( events );
  for( ulong i=0UL; i<cnt; i++ ) {
    events[i] = (fd_gui_shred_event_t){ base+(long)(i/2UL), (long)i, (uint)(800UL+i/10000UL), (ushort)(i%10000UL), FD_GUI_SLOT_SHRED_SHRED_RECEIVED_TURBINE };
    fd_gui_shred_event_t const * e = events+i;
    fd_gui_shred_event_append( gui, e->slot, e->idx, e->event, e->event_time_ns, e->insert_time_ns );
  }
  ulong sealed = fd_gui_store_metrics( gui->db )->ts_appends[ FD_GUI_HIST_SHRED_EVENTS ];
  FD_TEST( sealed>1UL && gui->shreds.builder.batch.event_cnt );
  assert_shreds( gui, events, cnt, base, base+(long)cnt );
  assert_shreds( gui, events+400UL, 200UL, base+200L, base+299L );
  fd_gui_shred_flush( gui, base+sec_ns(1UL) );
  ulong bytes = fd_gui_store_metrics( gui->db )->ts_appends[ FD_GUI_HIST_SHRED_EVENTS ]*sizeof(fd_gui_shred_batch_t);
  FD_TEST( bytes<cnt*10UL ); /* nine-byte common encoding plus block overhead */
  FD_TEST( !gui->shreds.builder.batch.event_cnt );
  assert_shreds( gui, events, cnt, base, base+(long)cnt );
  free( events );

  /* Sparse seconds pay for one block each and are sealed by the next event. */
  sealed = fd_gui_store_metrics( gui->db )->ts_appends[ FD_GUI_HIST_SHRED_EVENTS ];
  fd_gui_shred_event_t sparse[ 8 ];
  for( ulong i=0UL; i<8UL; i++ ) {
    sparse[i] = (fd_gui_shred_event_t){ base+sec_ns( 2UL+i ), (long)i, 808U, 0U, FD_GUI_SLOT_SHRED_REPAIR_REQUEST };
    fd_gui_shred_event_append( gui, sparse[i].slot, sparse[i].idx, sparse[i].event, sparse[i].event_time_ns, sparse[i].insert_time_ns );
  }
  FD_TEST( fd_gui_store_metrics( gui->db )->ts_appends[ FD_GUI_HIST_SHRED_EVENTS ]==sealed+7UL );
  assert_shreds( gui, sparse, 8UL, sparse[0].insert_time_ns, sparse[7].insert_time_ns );
  fd_gui_shred_flush( gui, base+sec_ns( 10UL ) );
  FD_TEST( fd_gui_store_metrics( gui->db )->ts_appends[ FD_GUI_HIST_SHRED_EVENTS ]==sealed+8UL );
  FD_TEST( !gui->shreds.dropped_event_cnt );
  FD_LOG_NOTICE(( "test_shred_storage: %lu events in %lu bytes; ok", cnt, bytes ));
}

static void
test_shred_flush_full( fd_gui_t * gui,
                       int        tail_oldest ) {
  long const base = sec_ns( 300UL );
  fd_gui_shred_event_t event = { base, 1L, 900U, 0U, FD_GUI_SLOT_SHRED_REPAIR_REQUEST };
  fd_gui_shred_event_append( gui, event.slot, event.idx, event.event, event.event_time_ns, base );
  /* Fill another ring without invoking history's pressure eviction. */
  fd_gui_scheduler_counts_t counts = { .sample_time_ns=base+(tail_oldest ? sec_ns(1UL) : -sec_ns(1UL)) };
  while( fd_gui_store_ts_append( gui->db, FD_GUI_HIST_SCHEDULER_COUNTS, &counts )==FD_GUI_STORE_SUCCESS ) {}
  FD_TEST( !fd_gui_store_free_region_cnt( gui->db ) );
  if( tail_oldest==2 ) {
    /* Unrelated history writes only evict stored records. */
    append_sched_counts( gui, counts.sample_time_ns );
    FD_TEST( gui->shreds.builder.batch.event_cnt==1U );
    assert_shreds( gui, &event, 1UL, base, base );
  }
  fd_gui_shred_flush( gui, base+sec_ns(2UL) );
  FD_TEST( !gui->shreds.builder.batch.event_cnt );
  FD_TEST( fd_gui_store_metrics( gui->db )->ts_appends[ FD_GUI_HIST_SHRED_EVENTS ]==1UL );
  FD_TEST( !gui->shreds.dropped_event_cnt );
  assert_shreds( gui, &event, 1UL, base, base );
  fd_gui_shred_flush( gui, base+sec_ns(3UL) );
  assert_shreds( gui, &event, 1UL, base, base );
  FD_LOG_NOTICE(( "test_shred_flush_full: tail_oldest=%i; ok", tail_oldest ));
}

static void
test_shred_retention( fd_gui_t * gui ) {
  long const base = sec_ns( 400UL );
  /* An active-only second is outside store retention. */
  fd_gui_shred_event_append( gui, 900UL, 0UL, FD_GUI_SLOT_SHRED_REPAIR_REQUEST, 1L, base );
  FD_TEST( !fd_gui_store_metrics( gui->db )->ts_appends[ FD_GUI_HIST_SHRED_EVENTS ] );
  FD_TEST( fd_gui_hist_evict_ts_oldest( gui )==0 );
  FD_TEST( !fd_gui_shred_window_is_empty( gui, base, base ) );
  FD_TEST( gui->shreds.builder.batch.event_cnt==1U );
  fd_gui_shred_flush( gui, base+sec_ns(1UL) );
  FD_TEST( fd_gui_hist_evict_ts_oldest( gui )==1 );
  FD_TEST( fd_gui_shred_window_is_empty( gui, base, base ) );
  FD_TEST( fd_gui_hist_evict_ts_oldest( gui )==0 );

  /* A capacity split gives one second both stored blocks and an active tail. */
  for( ulong i=0UL; i<1000UL; i++ ) {
    fd_gui_shred_event_append( gui, 901UL, i, FD_GUI_SLOT_SHRED_REPAIR_REQUEST, (long)i, base+sec_ns(2UL) );
  }
  FD_TEST( fd_gui_store_metrics( gui->db )->ts_appends[ FD_GUI_HIST_SHRED_EVENTS ] );
  FD_TEST( gui->shreds.builder.batch.event_cnt );
  FD_TEST( count_ts( gui, FD_GUI_HIST_SHRED_EVENTS, ULONG_MAX )==1000UL );
  ulong tail_cnt = gui->shreds.builder.batch.event_cnt;
  FD_TEST( fd_gui_hist_evict_ts_oldest( gui )==1 );
  FD_TEST( gui->shreds.builder.batch.event_cnt==tail_cnt );
  FD_TEST( count_ts( gui, FD_GUI_HIST_SHRED_EVENTS, ULONG_MAX )==tail_cnt );
  FD_TEST( fd_gui_hist_evict_ts_oldest( gui )==0 );
  fd_gui_shred_flush( gui, base+sec_ns(3UL) );
  FD_TEST( count_ts( gui, FD_GUI_HIST_SHRED_EVENTS, ULONG_MAX )==tail_cnt );
  FD_TEST( fd_gui_hist_evict_ts_oldest( gui )==1 );
  FD_TEST( fd_gui_shred_window_is_empty( gui, base, LONG_MAX ) );
  FD_TEST( fd_gui_hist_evict_ts_oldest( gui )==0 );

  fd_gui_shred_event_t next = { base+sec_ns(4UL), LONG_MIN, 902U, 0U, FD_GUI_SLOT_SHRED_REPAIR_REQUEST };
  fd_gui_shred_event_append( gui, next.slot, next.idx, next.event, next.event_time_ns, next.insert_time_ns );
  assert_shreds( gui, &next, 1UL, base, LONG_MAX );
  FD_LOG_NOTICE(( "test_shred_retention: ok" ));
}

static void
test_shred_epoch_retention( fd_gui_t * gui,
                            ulong      cnt ) {
  put_epoch( gui, EPOCH_A, A_START_SLOT, SLOT_CNT );
  put_epoch( gui, EPOCH_B, B_START_SLOT, SLOT_CNT );
  put_epoch( gui, EPOCH_C, C_START_SLOT, SLOT_CNT );
  put_slot( gui, A_START_SLOT, sec_ns( 10UL ) );
  put_slot( gui, B_START_SLOT, sec_ns( 20UL ) );
  put_slot( gui, C_START_SLOT, sec_ns( 30UL ) );
  for( ulong i=0UL; i<cnt; i++ ) {
    fd_gui_shred_event_append( gui, A_START_SLOT, i, FD_GUI_SLOT_SHRED_REPAIR_REQUEST, (long)i, sec_ns( 19UL ) );
  }
  FD_TEST( gui->shreds.builder.batch.event_cnt );
  FD_TEST( count_ts( gui, FD_GUI_HIST_SHRED_EVENTS, ULONG_MAX )==cnt );
  ulong tail_cnt = gui->shreds.builder.batch.event_cnt;
  FD_TEST( fd_gui_hist_evict_oldest( gui )==1 );
  FD_TEST( gui->shreds.builder.batch.event_cnt==tail_cnt );
  FD_TEST( count_ts( gui, FD_GUI_HIST_SHRED_EVENTS, ULONG_MAX )==tail_cnt );
  fd_gui_shred_flush( gui, sec_ns( 20UL ) );
  FD_TEST( !gui->shreds.builder.batch.event_cnt );
  FD_TEST( count_ts( gui, FD_GUI_HIST_SHRED_EVENTS, ULONG_MAX )==tail_cnt );
  FD_TEST( fd_gui_hist_evict_ts_oldest( gui )==1 );
  FD_TEST( count_ts( gui, FD_GUI_HIST_SHRED_EVENTS, ULONG_MAX )==0UL );

  /* A surviving epoch's active second is outside the next cascade cutoff. */
  put_epoch( gui, EPOCH_C+1UL, C_START_SLOT+SLOT_CNT, SLOT_CNT );
  put_slot( gui, C_START_SLOT+SLOT_CNT, sec_ns( 40UL ) );
  fd_gui_shred_event_t next = { sec_ns( 30UL ), 1L, C_START_SLOT, 0U, FD_GUI_SLOT_SHRED_REPAIR_REQUEST };
  fd_gui_shred_event_append( gui, next.slot, next.idx, next.event, next.event_time_ns, next.insert_time_ns );
  FD_TEST( fd_gui_hist_evict_oldest( gui )==1 );
  assert_shreds( gui, &next, 1UL, 0L, LONG_MAX );
  FD_TEST( gui->shreds.builder.batch.event_cnt==1U );
  FD_LOG_NOTICE(( "test_shred_epoch_retention: %lu events; ok", cnt ));
}

/* ---- space-pressure trigger ------------------------------------------

   The space-pressure *trigger* (high-water threshold via
   fd_gui_hist_evict_step) is intentionally not covered here: it depends on
   the backend partition sizing, which is a deliberate MVP placeholder slated
   for rework.  The eviction *mechanics* it drives are exercised above via
   fd_gui_hist_evict_oldest. */
int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

  if( argc>1 && !strcmp( argv[1], "--shreds" ) ) {
    test_store_t s[1];
    store_open( s, 1UL<<30, 20 ); test_shred_encoding( s->gui ); store_close( s );
    store_open( s, 1UL<<30, 21 ); test_shred_storage( s->gui ); store_close( s );
    store_open( s, 1UL<<30, 22 ); test_shred_flush_full( s->gui, 0 ); store_close( s );
    store_open( s, 1UL<<30, 23 ); test_shred_retention( s->gui ); store_close( s );
    store_open( s, 1UL<<30, 24 ); test_shred_epoch_retention( s->gui, 1UL ); store_close( s );
    store_open( s, 1UL<<30, 25 ); test_shred_epoch_retention( s->gui, 1000UL ); store_close( s );
    store_open( s, 1UL<<30, 26 ); test_shred_flush_full( s->gui, 1 ); store_close( s );
    store_open( s, 1UL<<30, 27 ); test_shred_flush_full( s->gui, 2 ); store_close( s );
    FD_LOG_NOTICE(( "pass" ));
    fd_halt();
    return 0;
  }

  /* cascade mechanics: a generous (1 GiB) map so writes never hit map-full;
     eviction is driven directly via fd_gui_hist_evict_oldest.  Each test gets
     its own store so leftover epochs don't perturb the next (eviction now
     keeps the last epoch, so stores do not empty between tests). */
  test_store_t s0[ 1 ];
  store_open( s0, 1UL<<30, 0 );
  test_evict_oldest_epoch( s0->gui );
  store_close( s0 );

  test_store_t s1[ 1 ];
  store_open( s1, 1UL<<30, 2 );
  test_evict_large_batch( s1->gui );
  store_close( s1 );

  test_store_t sp[ 1 ];
  store_open( sp, 1UL<<30, 6 );
  test_current_epoch_protected( sp->gui );
  store_close( sp );

  test_store_t s2[ 1 ];
  store_open( s2, 1UL<<30, 3 );
  test_evict_ts_oldest_fallback( s2->gui );
  store_close( s2 );

  test_store_t st[ 1 ];
  store_open( st, 1UL<<30, 9 );
  test_evict_timeline_ts_fallback( st->gui );
  store_close( st );

  test_store_t s3[ 1 ];
  store_open( s3, 1UL<<30, 4 );
  test_resident_meta_mutation_survives_evict( s3->gui );
  store_close( s3 );

  test_store_t s4[ 1 ];
  store_open( s4, 1UL<<30, 5 );
  test_epoch_region_reclaimed( s4->gui );
  store_close( s4 );

  test_store_t s5[ 1 ];
  store_open( s5, 1UL<<30, 7 );
  test_waterfall_snapshots( s5->gui );
  store_close( s5 );

  test_store_t s6[ 1 ];
  store_open( s6, 1UL<<30, 8 );
  test_timeline_db( s6->gui );
  store_close( s6 );

  test_store_t sr[ 1 ];
  store_open( sr, 1UL<<30, 13 );
  test_range_live_timestamp_bounds( sr->gui );
  store_close( sr );

  test_store_t tx[ 1 ];
  store_open( tx, 1UL<<30, 14 );
  test_txn_insert_bounds( tx->gui );
  store_close( tx );

  test_store_t s7[ 1 ];
  store_open( s7, 1UL<<30, 10 );
  test_shred_encoding( s7->gui );
  store_close( s7 );

  test_store_t s8[ 1 ];
  store_open( s8, 1UL<<30, 11 );
  test_shred_storage( s8->gui );
  store_close( s8 );

  test_store_t s9[ 1 ];
  store_open( s9, 1UL<<30, 12 );
  test_shred_flush_full( s9->gui, 0 );
  store_close( s9 );

  test_store_t s10[ 1 ];
  store_open( s10, 1UL<<30, 15 );
  test_shred_retention( s10->gui );
  store_close( s10 );

  store_open( s10, 1UL<<30, 16 );
  test_shred_epoch_retention( s10->gui, 1UL );
  store_close( s10 );

  store_open( s10, 1UL<<30, 17 );
  test_shred_epoch_retention( s10->gui, 1000UL );
  store_close( s10 );

  store_open( s10, 1UL<<30, 18 );
  test_shred_flush_full( s10->gui, 1 );
  store_close( s10 );

  store_open( s10, 1UL<<30, 19 );
  test_shred_flush_full( s10->gui, 2 );
  store_close( s10 );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
