/* test_gui_hist_evict exercises the space-pressure epoch-cascade eviction in
   fd_gui_hist: fd_gui_hist_evict_oldest (the synchronous drain used by the
   map-full fallback and driven one batch at a time by
   fd_gui_hist_evict_step).  It builds multiple epochs' worth of records -- the
   EPOCH records, the per-slot (slot,bank_seq) entity rows, and the
   time-bucketed time-series rows -- then evicts the oldest epoch and asserts
   that exactly that epoch's rows are gone while the newer epochs survive,
   including the SHRED_EVENTS/FEC_EVENTS boundary case (a slot of the NEXT
   epoch whose event landed in a wallclock second shared with the oldest
   epoch's tail).

   The eviction path only touches gui->db / gui->hist, so the test allocates a
   bare fd_gui_t (like test_gui_consensus) and wires up the two store layers
   by hand -- no http server / topology / fd_gui_new. */

#include "../../util/fd_util.h"
#include "fd_gui.h"
#include "fd_gui_store.h"
#include "fd_gui_hist.h"

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

  FD_TEST( !fd_gui_hist_ts_append( gui, FD_GUI_HIST_SCHEDULER_COUNTS, ts_ns, ts_ns, rec ) );
}

/* SHRED_EVENTS carries its slot in the record. */
static void
append_shred( fd_gui_t * gui, long ts_ns, ulong slot ) {
  fd_gui_slot_history_tvu_event_t rec[ 1 ];
  memset( rec, 0, sizeof(*rec) );
  rec->slot      = (uint)slot;
  rec->timestamp = ts_ns;

  FD_TEST( !fd_gui_hist_ts_append( gui, FD_GUI_HIST_SHRED_EVENTS, ts_ns, ts_ns, rec ) );
}

static void
append_fec_event( fd_gui_t * gui,
                  long       ts_ns,
                  ulong      slot ) {
  fd_gui_fec_event_record_t rec[ 1 ];
  memset( rec, 0, sizeof(*rec) );
  rec->slot      = (uint)slot;
  rec->timestamp = ts_ns;

  FD_TEST( !fd_gui_hist_ts_append( gui, FD_GUI_HIST_FEC_EVENTS, ts_ns, ts_ns, rec ) );
}

static void
append_replay_txn( fd_gui_t * gui,
                   long       now_ns,
                   long       ts_ns,
                   ulong      slot ) {
  fd_gui_store_replay_txn_t rec[ 1 ];
  memset( rec, 0, sizeof(*rec) );
  rec->completion_time_ns = ts_ns;
  rec->slot               = slot;

  FD_TEST( !fd_gui_hist_ts_append( gui, FD_GUI_HIST_REPLAY_TXN, now_ns, ts_ns, rec ) );
}

static void
append_replay_txn_batch( fd_gui_t * gui,
                         long       now_ns,
                         long       ts_ns,
                         ulong      slot ) {
  fd_gui_store_replay_txn_batch_t rec[ 1 ];
  memset( rec, 0, sizeof(*rec) );
  rec->completion_time_ns = ts_ns;
  rec->slot               = slot;

  FD_TEST( !fd_gui_hist_ts_append( gui, FD_GUI_HIST_REPLAY_TXN_BATCH, now_ns, ts_ns, rec ) );
}

static void
put_timeline_day( fd_gui_t * gui,
                  ulong      day ) {
  fd_gui_hist_timeline_day_key_t key = { .day=day };
  fd_gui_timeline_day_t * rec = fd_gui_hist_kv_get_or_create( gui, FD_GUI_HIST_TIMELINE_DAY, &key );
  FD_TEST( rec );
  memset( rec, 0, sizeof(*rec) );
  rec->day = day;
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

/* count_ts counts time-series records in DB `dbi` over the whole timeline,
   optionally restricted to a single slot (slot==ULONG_MAX -> all).  The
   per-slot restriction reads the slot from the SHRED_EVENTS record (the only
   DB this is used with a specific slot), the same way the real query call
   sites filter. */
static ulong
count_ts( fd_gui_t * gui, int dbi, ulong slot ) {
  fd_gui_hist_iter_t it[ 1 ];
  FD_TEST( !fd_gui_hist_range_begin( gui, it, dbi, LONG_MIN+1, LONG_MAX-1L, NULL, NULL ) );
  ulong cnt = 0UL;
  while( fd_gui_hist_range_next( it ) ) {
    if( slot!=ULONG_MAX ) {
      fd_gui_slot_history_tvu_event_t const * e = (fd_gui_slot_history_tvu_event_t const *)it->rec;
      if( e->slot!=slot ) continue;
    }
    cnt++;
  }
  fd_gui_hist_range_end( it );
  return cnt;
}

static int
timeline_day_present( fd_gui_t * gui,
                      ulong      day ) {
  fd_gui_hist_timeline_day_key_t key = { .day=day };
  return fd_gui_hist_kv_get( gui, FD_GUI_HIST_TIMELINE_DAY, &key )!=NULL;
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
    append_shred( gui, ts_ns, s );
    append_fec_event( gui, ts_ns, s );
    append_replay_txn( gui, ts_ns, ts_ns, s );
    append_replay_txn_batch( gui, ts_ns, ts_ns, s );
  }

  /* boundary case: a shred for epoch B's first slot (1010) that landed in
     window 86399 -- the same second as epoch A's last slot (1009).  Eviction
     of epoch A bounds the window there, but the slot watermark
     (1010 > 1009) must keep this row. */
  append_shred( gui, sec_ns( 86399UL ), B_START_SLOT );
  append_fec_event( gui, sec_ns( 86399UL ), B_START_SLOT );

  /* Day zero belongs exclusively to epoch A.  Day one belongs to epoch B
     and must survive eviction of epoch A. */
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
  FD_TEST( count_ts( gui, FD_GUI_HIST_FEC_EVENTS,       ULONG_MAX )==31UL );
  FD_TEST( count_ts( gui, FD_GUI_HIST_FEC_EVENTS,       B_START_SLOT )==2UL );
  FD_TEST( count_ts( gui, FD_GUI_HIST_REPLAY_TXN,       ULONG_MAX )==30UL );
  FD_TEST( count_ts( gui, FD_GUI_HIST_REPLAY_TXN_BATCH, ULONG_MAX )==30UL );

  /* --- evict the oldest epoch (A); B and C stay resident (the current +
     next epochs the floor protects) --------------------------------- */
  FD_TEST( fd_gui_hist_evict_oldest( gui )==1 );

  /* epoch A entirely gone; epochs B and C intact */
  FD_TEST( !epoch_present( gui, EPOCH_A ) );
  FD_TEST(  epoch_present( gui, EPOCH_B ) );
  FD_TEST(  epoch_present( gui, EPOCH_C ) );
  FD_TEST( !timeline_day_present( gui, 0UL ) );
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
  FD_TEST( count_ts( gui, FD_GUI_HIST_REPLAY_TXN_BATCH, ULONG_MAX )==20UL );

  /* shred events: TS eviction is an approximate watermark advance (a
     monotonic prefix bump on the partition's evict_cur), not a precise
     by-window delete.  Records are stored in arrival order, which is only
     approximately window-ordered: the boundary row (slot 1010, epoch B) was
     appended LAST but carries window 19, so it sits in the ring *past* the
     watermark and survives eviction even though its window is in epoch A's
     range.  This is intentional -- readers re-filter on the record's own
     timestamp/slot, and the watermark never touches records below it.  So
     epoch A's 10 in-order slot rows (windows 86390..86399) are evicted,
     epochs B+C's 20 rows (windows 86400..86419) are kept, and the straggler
     boundary row survives: 21 live rows, with slot 1010 keeping its own row
     plus the boundary row. */
  FD_TEST( count_ts( gui, FD_GUI_HIST_SHRED_EVENTS, ULONG_MAX )==21UL );
  FD_TEST( count_ts( gui, FD_GUI_HIST_SHRED_EVENTS, B_START_SLOT )==2UL );
  FD_TEST( count_ts( gui, FD_GUI_HIST_FEC_EVENTS,   ULONG_MAX )==21UL );
  FD_TEST( count_ts( gui, FD_GUI_HIST_FEC_EVENTS,   B_START_SLOT )==2UL );
  /* an evicted epoch-A slot has no shred rows left */
  FD_TEST( count_ts( gui, FD_GUI_HIST_SHRED_EVENTS, A_START_SLOT )==0UL );
  FD_TEST( count_ts( gui, FD_GUI_HIST_FEC_EVENTS,   A_START_SLOT )==0UL );

  /* --- guard: only epochs B and C remain (== FD_GUI_HIST_MIN_EPOCHS-1) so
     eviction refuses.  The current in-progress epoch and the next epoch must
     always stay resident, so fd_gui_hist_evict_oldest is a no-op here. */
  FD_TEST( fd_gui_hist_evict_oldest( gui )==0 );
  FD_TEST( epoch_present( gui, EPOCH_B ) );
  FD_TEST( epoch_present( gui, EPOCH_C ) );
  FD_TEST( count_ts( gui, FD_GUI_HIST_SCHEDULER_COUNTS, ULONG_MAX )==20UL );
  FD_TEST( count_ts( gui, FD_GUI_HIST_SHRED_EVENTS,     ULONG_MAX )==21UL );
  FD_TEST( count_ts( gui, FD_GUI_HIST_FEC_EVENTS,       ULONG_MAX )==21UL );
  FD_TEST( count_ts( gui, FD_GUI_HIST_REPLAY_TXN,       ULONG_MAX )==20UL );
  FD_TEST( count_ts( gui, FD_GUI_HIST_REPLAY_TXN_BATCH, ULONG_MAX )==20UL );

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
    append_shred( gui, slot_complete_ns( 1000UL + (s-BIG_START_SLOT) ), s );
    append_fec_event( gui, slot_complete_ns( 1000UL + (s-BIG_START_SLOT) ), s );
  }
  /* newer epochs (so BIG is the oldest, and the >= FD_GUI_HIST_MIN_EPOCHS guard
     is satisfied); the immediately-following epoch's first slot replay meta
     bounds BIG's time-series eviction window. */
  put_epoch( gui, BIG_KEEP_EPOCH, BIG_KEEP_START, BIG_SLOT_CNT );
  put_slot( gui, BIG_KEEP_START, slot_complete_ns( 1000UL + BIG_SLOT_CNT ) );
  put_epoch( gui, BIG_KEEP2_EPOCH, BIG_KEEP2_START, BIG_SLOT_CNT );
  put_slot( gui, BIG_KEEP2_START, slot_complete_ns( 1000UL + 2UL*BIG_SLOT_CNT ) );

  FD_TEST( count_ts( gui, FD_GUI_HIST_SHRED_EVENTS, ULONG_MAX )==BIG_SLOT_CNT );
  FD_TEST( count_ts( gui, FD_GUI_HIST_FEC_EVENTS,   ULONG_MAX )==BIG_SLOT_CNT );
  FD_TEST( epoch_present( gui, BIG_EPOCH ) );

  /* single synchronous drain must clear all 1000 keys (crossing the 512
     per-batch budget several times) */
  FD_TEST( fd_gui_hist_evict_oldest( gui )==1 );
  FD_TEST( !epoch_present( gui, BIG_EPOCH ) );
  FD_TEST(  epoch_present( gui, BIG_KEEP_EPOCH ) );
  FD_TEST(  epoch_present( gui, BIG_KEEP2_EPOCH ) );
  FD_TEST( count_ts( gui, FD_GUI_HIST_SHRED_EVENTS, ULONG_MAX )==0UL );
  FD_TEST( count_ts( gui, FD_GUI_HIST_FEC_EVENTS,   ULONG_MAX )==0UL );
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
    append_shred( gui, sec_ns( sec ), TS_START_SLOT + (sec-50UL) );
    append_fec_event( gui, sec_ns( sec ), TS_START_SLOT + (sec-50UL) );
    append_replay_txn_batch( gui, sec_ns( sec ), sec_ns( sec ), TS_START_SLOT + (sec-50UL) );
  }

  FD_TEST(  epoch_present( gui, TS_EPOCH ) );
  FD_TEST( count_ts( gui, FD_GUI_HIST_SCHEDULER_COUNTS, ULONG_MAX )==5UL );
  FD_TEST( count_ts( gui, FD_GUI_HIST_SHRED_EVENTS,     ULONG_MAX )==5UL );
  FD_TEST( count_ts( gui, FD_GUI_HIST_FEC_EVENTS,       ULONG_MAX )==5UL );
  FD_TEST( count_ts( gui, FD_GUI_HIST_REPLAY_TXN_BATCH, ULONG_MAX )==5UL );

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
  FD_TEST( count_ts( gui, FD_GUI_HIST_FEC_EVENTS,       ULONG_MAX )==4UL );
  FD_TEST( count_ts( gui, FD_GUI_HIST_REPLAY_TXN_BATCH, ULONG_MAX )==4UL );

  /* Drive it to exhaustion: each call sheds the next-oldest window until the
     TS DBs are empty, at which point it reports 0 (nothing left). */
  for( int i=0; i<4; i++ ) FD_TEST( fd_gui_hist_evict_ts_oldest( gui )==1 );
  FD_TEST( count_ts( gui, FD_GUI_HIST_SCHEDULER_COUNTS, ULONG_MAX )==0UL );
  FD_TEST( count_ts( gui, FD_GUI_HIST_SHRED_EVENTS,     ULONG_MAX )==0UL );
  FD_TEST( count_ts( gui, FD_GUI_HIST_FEC_EVENTS,       ULONG_MAX )==0UL );
  FD_TEST( count_ts( gui, FD_GUI_HIST_REPLAY_TXN_BATCH, ULONG_MAX )==0UL );
  FD_TEST( fd_gui_hist_evict_ts_oldest( gui )==0 ); /* genuinely nothing left */
  /* Epoch metadata survived the entire TS drain. */
  FD_TEST(  epoch_present( gui, TS_EPOCH ) );

  FD_LOG_NOTICE(( "test_evict_ts_oldest_fallback: ok" ));
}


static void
test_evict_timeline_oldest_fallback( fd_gui_t * gui ) {
  ulong day_cnt = 0UL;
  while( fd_gui_store_free_region_cnt( gui->db ) ) {
    fd_gui_hist_timeline_day_key_t key = { .day=day_cnt++ };
    FD_TEST( fd_gui_hist_kv_get_or_create( gui, FD_GUI_HIST_TIMELINE_DAY, &key ) );
  }
  FD_TEST( day_cnt>1UL );
  FD_TEST( timeline_day_present( gui, 0UL ) );
  FD_TEST( !fd_gui_hist_evict_oldest( gui ) );
  FD_TEST( !fd_gui_hist_evict_ts_oldest( gui ) );

  ulong evicted_before = fd_gui_store_metrics( gui->db )->evict_records[ FD_GUI_HIST_TIMELINE_DAY ];
  ulong reserves_before = fd_gui_hist_metrics( gui )->reserves[ FD_GUI_HIST_TIMELINE_DAY ];
  fd_gui_hist_timeline_day_key_t key = { .day=day_cnt };
  FD_TEST( fd_gui_hist_kv_get_or_create( gui, FD_GUI_HIST_TIMELINE_DAY, &key ) );

  FD_TEST( fd_gui_store_metrics( gui->db )->evict_records[ FD_GUI_HIST_TIMELINE_DAY ]==evicted_before+1UL );
  FD_TEST( fd_gui_hist_metrics( gui )->reserves[ FD_GUI_HIST_TIMELINE_DAY ]==reserves_before+1UL );
  FD_TEST( !timeline_day_present( gui, 0UL ) );
  for( ulong day=1UL; day<=day_cnt; day++ ) FD_TEST( timeline_day_present( gui, day ) );

  FD_LOG_NOTICE(( "test_evict_timeline_oldest_fallback: ok" ));
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

  s->gui = aligned_alloc( fd_gui_align(), fd_gui_footprint( 1UL, 1UL ) );
  FD_TEST( s->gui );
  memset( s->gui, 0, fd_gui_footprint( 1UL, 1UL ) );

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
  FD_TEST( FD_GUI_HIST_FEC_EVENTS==13 );
  FD_TEST( FD_GUI_HIST_REPLAY_TXN_BATCH==14 );
  FD_TEST( !strcmp( descs[ FD_GUI_HIST_TIMELINE_DAY     ].name, "timeline_day"     ) );
  FD_TEST( !strcmp( descs[ FD_GUI_HIST_REPLAY_TXN       ].name, "replay_txn"       ) );
  FD_TEST( !strcmp( descs[ FD_GUI_HIST_FEC_EVENTS       ].name, "fec_events"       ) );
  FD_TEST( descs[ FD_GUI_HIST_FEC_EVENTS ].val_sz==sizeof(fd_gui_fec_event_record_t) );
  FD_TEST( !strcmp( descs[ FD_GUI_HIST_REPLAY_TXN_BATCH ].name, "replay_txn_batch" ) );
  FD_TEST( descs[ FD_GUI_HIST_TIMELINE_DAY ].val_sz==sizeof(fd_gui_timeline_day_t) );
  char const * fine_names[] = { "1ms", "2ms", "5ms", "10ms", "25ms", "50ms", "100ms" };
  ulong const fine_ns[] = { 1000000UL, 2000000UL, 5000000UL, 10000000UL, 25000000UL, 50000000UL, 100000000UL };
  for( ulong i=0UL; i<FD_GUI_TIMELINE_FINE_GRANULARITY_CNT; i++ ) {
    FD_TEST( !strcmp( fd_gui_timeline_granularities[i].name, fine_names[i] ) );
    FD_TEST( fd_gui_timeline_granularities[i].duration_ns==fine_ns[i] );
    FD_TEST( fd_gui_timeline_granularities[i].stored_idx==ULONG_MAX );
  }

  /* Replay transactions use the same bounded-skew timestamp handling as all
     other time-series records. */
  long const source_ns = sec_ns( 2000UL );
  long const now_ns    = source_ns+sec_ns( 100UL );
  long const stored_ns = now_ns-FD_GUI_HIST_TS_SKEW_NS;
  append_replay_txn( gui, now_ns, source_ns, 2UL );

  fd_gui_hist_iter_t it[ 1 ];
  FD_TEST( !fd_gui_hist_range_begin( gui, it, FD_GUI_HIST_REPLAY_TXN,
                                     stored_ns, stored_ns+1L, NULL, NULL ) );
  ulong found = 0UL;
  while( fd_gui_hist_range_next( it ) ) {
    fd_gui_store_replay_txn_t const * rec = it->rec;
    if( rec->completion_time_ns==stored_ns ) {
      FD_TEST( rec->slot==2UL );
      found++;
    }
  }
  fd_gui_hist_range_end( it );
  FD_TEST( found==1UL );

  FD_LOG_NOTICE(( "test_timeline_foundation: ok" ));
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

/* ---- space-pressure trigger ------------------------------------------

   The space-pressure *trigger* (high-water threshold via
   fd_gui_hist_evict_step) is intentionally not covered here: it depends on
   the backend partition sizing, which is a deliberate MVP placeholder slated
   for rework.  The eviction *mechanics* it drives are exercised above via
   fd_gui_hist_evict_oldest. */

/* fd_gui_slot_is_skipped must answer for slots at or below `root` from
   the durable rooted-fork epoch cache.  The fork walk cannot: it returns
   0 the moment it reaches root, which every descent from the tower tip
   does before it could straddle an older slot.  Since root trails the
   tip by only a handful of slots, a regression here reports essentially
   every historical slot as not-skipped, which the timeline shred and FEC
   queries surface directly in their `skipped` array. */

static void
test_slot_is_skipped_below_root( fd_gui_t * gui ) {
  FD_TEST( fd_epoch_schedule_derive( &gui->epoch.epoch_schedule, 432000UL, 432000UL, 0 ) );
  gui->epoch.has_epoch_schedule = 1;

  /* Let the schedule tell us where the slot lands rather than assuming. */
  ulong const probe_slot = 5000000UL;
  ulong offset;
  ulong epoch = fd_slot_to_epoch( &gui->epoch.epoch_schedule, probe_slot, &offset );
  ulong start_slot = probe_slot - offset;
  put_epoch( gui, epoch, start_slot, gui->epoch.epoch_schedule.slots_per_epoch );

  fd_gui_hist_epoch_key_t key[ 1 ]; key->epoch = epoch;
  fd_gui_epoch_t * rec = (fd_gui_epoch_t *)fd_gui_hist_kv_get( gui, FD_GUI_HIST_EPOCH, key );
  FD_TEST( rec );

  ulong const skipped_slot = probe_slot;
  ulong const kept_slot    = probe_slot + 1UL;
  FD_TEST( fd_slot_to_epoch( &gui->epoch.epoch_schedule, kept_slot, NULL )==epoch );
  rec->skipped[ skipped_slot-start_slot ] = 1;
  rec->skipped[ kept_slot   -start_slot ] = 0;

  /* Both slots sit well below root, so only the epoch cache can answer.
     The fork tip is deliberately unpopulated: the walk has nothing to
     find, which is exactly the situation for a historical query. */
  ulong const root = probe_slot + 1000UL;

  FD_TEST(  fd_gui_slot_is_skipped( gui, root, root, BANK_SEQ, skipped_slot ) );
  FD_TEST( !fd_gui_slot_is_skipped( gui, root, root, BANK_SEQ, kept_slot    ) );

  /* root itself is on the fork by definition, and an unknown epoch or a
     slot outside the record's range must not be reported as skipped. */
  FD_TEST( !fd_gui_slot_is_skipped( gui, root, root, BANK_SEQ, root ) );
  FD_TEST( !fd_gui_slot_is_skipped( gui, root, root, BANK_SEQ, start_slot-1UL ) );

  /* Without an epoch schedule there is nothing to consult, so the answer
     must be "unknown" rather than a wrong "skipped". */
  gui->epoch.has_epoch_schedule = 0;
  FD_TEST( !fd_gui_slot_is_skipped( gui, root, root, BANK_SEQ, skipped_slot ) );
  gui->epoch.has_epoch_schedule = 1;

  FD_LOG_NOTICE(( "test_slot_is_skipped_below_root: ok" ));
}

int
main( int     argc,
      char ** argv ) {
  fd_boot( &argc, &argv );

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
  test_evict_timeline_oldest_fallback( st->gui );
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

  test_store_t s7[ 1 ];
  store_open( s7, 1UL<<30, 10 );
  test_slot_is_skipped_below_root( s7->gui );
  store_close( s7 );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
