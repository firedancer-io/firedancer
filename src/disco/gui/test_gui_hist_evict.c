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
  fd_gui_shred_batch_t rec[ 1 ];
  memset( rec, 0, sizeof(*rec) );
  rec->slot           = slot;
  rec->base_timestamp = ts_ns;
  rec->insert_time_ns  = insert_time_ns;
  rec->event_cnt      = 1U;

  FD_TEST( !fd_gui_hist_ts_append( gui, FD_GUI_HIST_SHRED_EVENTS, rec ) );
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
  rec->commit_end_ns      = ts_ns;
  rec->slot               = slot;

  FD_TEST( !fd_gui_hist_ts_append( gui, FD_GUI_HIST_REPLAY_TXN, rec ) );
}

static void
append_replay_txn_batch( fd_gui_t * gui,
                         long       now_ns,
                         long       ts_ns,
                         ulong      slot ) {
  fd_gui_store_replay_txn_batch_t rec[ 1 ];
  memset( rec, 0, sizeof(*rec) );
  rec->insert_time_ns     = now_ns;
  rec->completion_time_ns = ts_ns;
  rec->slot               = slot;

  FD_TEST( !fd_gui_hist_ts_append( gui, FD_GUI_HIST_REPLAY_TXN_BATCH, rec ) );
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
      ulong rec_slot = ((fd_gui_shred_batch_t const *)it->rec)->slot;
      if( rec_slot!=slot ) continue;
    }
    cnt++;
  }
  fd_gui_hist_range_end( it );
  return cnt;
}

static int
timeline_day_present( fd_gui_t * gui,
                      ulong      day ) {
  long end_time_ns = timeline_day_end_ns( day );
  fd_gui_hist_iter_t it[ 1 ];
  long insert_time_ns = end_time_ns+sec_ns( 100UL );
  FD_TEST( !fd_gui_hist_range_begin( gui, it, FD_GUI_HIST_TIMELINE_DAY, insert_time_ns, insert_time_ns, NULL, NULL ) );
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
  FD_TEST( count_ts( gui, FD_GUI_HIST_REPLAY_TXN_BATCH, ULONG_MAX )==20UL );

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
    append_replay_txn_batch( gui, sec_ns( sec ), sec_ns( sec ), TS_START_SLOT + (sec-50UL) );
  }

  FD_TEST(  epoch_present( gui, TS_EPOCH ) );
  FD_TEST( count_ts( gui, FD_GUI_HIST_SCHEDULER_COUNTS, ULONG_MAX )==5UL );
  FD_TEST( count_ts( gui, FD_GUI_HIST_SHRED_EVENTS,     ULONG_MAX )==5UL );
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
  FD_TEST( count_ts( gui, FD_GUI_HIST_REPLAY_TXN_BATCH, ULONG_MAX )==4UL );

  /* Drive it to exhaustion: each call sheds the next-oldest window until the
     TS DBs are empty, at which point it reports 0 (nothing left). */
  for( int i=0; i<4; i++ ) FD_TEST( fd_gui_hist_evict_ts_oldest( gui )==1 );
  FD_TEST( count_ts( gui, FD_GUI_HIST_SCHEDULER_COUNTS, ULONG_MAX )==0UL );
  FD_TEST( count_ts( gui, FD_GUI_HIST_SHRED_EVENTS,     ULONG_MAX )==0UL );
  FD_TEST( count_ts( gui, FD_GUI_HIST_REPLAY_TXN_BATCH, ULONG_MAX )==0UL );
  FD_TEST( fd_gui_hist_evict_ts_oldest( gui )==0 ); /* genuinely nothing left */
  /* Epoch metadata survived the entire TS drain. */
  FD_TEST(  epoch_present( gui, TS_EPOCH ) );

  FD_LOG_NOTICE(( "test_evict_ts_oldest_fallback: ok" ));
}


static void
test_evict_timeline_ts_fallback( fd_gui_t * gui ) {
  fd_gui_timeline_day_t * rec=aligned_alloc( alignof(fd_gui_timeline_day_t), sizeof(fd_gui_timeline_day_t) );
  FD_TEST( rec );
  memset( rec, 0xFF, sizeof(*rec) );
  ulong day_cnt = 0UL;
  while( fd_gui_store_free_region_cnt( gui->db ) ) {
    rec->insert_time_ns=sec_ns( day_cnt+1UL );
    rec->end_time_ns=timeline_day_end_ns( day_cnt++ );
    FD_TEST( !fd_gui_hist_ts_append( gui, FD_GUI_HIST_TIMELINE_DAY, rec ) );
  }
  FD_TEST( day_cnt>1UL );
  FD_TEST( fd_gui_timeline_day_get( gui, 0UL ) );
  FD_TEST( !fd_gui_hist_evict_oldest( gui ) );
  ulong evicted_before = fd_gui_store_metrics( gui->db )->evict_records[ FD_GUI_HIST_TIMELINE_DAY ];
  ulong reserves_before = fd_gui_hist_metrics( gui )->reserves[ FD_GUI_HIST_TIMELINE_DAY ];
  fd_gui_store_metrics_t store_before = *fd_gui_store_metrics( gui->db );
  fd_gui_hist_metrics_t hist_before = *fd_gui_hist_metrics( gui );
  fd_gui_timeline_day_t * regression = aligned_alloc( alignof(fd_gui_timeline_day_t), sizeof(fd_gui_timeline_day_t) );
  FD_TEST( regression );
  memset( regression, 0, sizeof(*regression) );
  regression->insert_time_ns = sec_ns( day_cnt )-1L;
  FD_TEST( fd_gui_hist_ts_append( gui, FD_GUI_HIST_TIMELINE_DAY, regression )==-1 );
  FD_TEST( !fd_gui_store_free_region_cnt( gui->db ) );
  FD_TEST( !memcmp( &store_before, fd_gui_store_metrics( gui->db ), sizeof(store_before) ) );
  FD_TEST( !memcmp( &hist_before, fd_gui_hist_metrics( gui ), sizeof(hist_before) ) );
  free( regression );
  rec->insert_time_ns=sec_ns( day_cnt+1UL );
  rec->end_time_ns=timeline_day_end_ns( day_cnt );
  FD_TEST( !fd_gui_hist_ts_append( gui, FD_GUI_HIST_TIMELINE_DAY, rec ) );
  free( rec );

  FD_TEST( fd_gui_store_metrics( gui->db )->evict_records[ FD_GUI_HIST_TIMELINE_DAY ]==evicted_before+1UL );
  FD_TEST( fd_gui_hist_metrics( gui )->reserves[ FD_GUI_HIST_TIMELINE_DAY ]==reserves_before+1UL );
  FD_TEST( !fd_gui_timeline_day_get( gui, 0UL ) );
  for( ulong day=1UL; day<=day_cnt; day++ ) FD_TEST( fd_gui_timeline_day_get( gui, day ) );

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
  void *     shred_pool_mem;
  void *     shred_list_mem;
  void *     fec_pool_mem;
  void *     fec_list_mem;
  void *     fec_map_mem;
  void *     completion_pool_mem;
  void *     completion_list_mem;
  char       path[ 128 ];
};
typedef struct test_store test_store_t;

static void
store_open( test_store_t * s, ulong map_bytes, int instance ) {
  fd_cstr_printf_check( s->path, sizeof(s->path), NULL, "/tmp/fd_gui_hist_evict_test.%i.%i", (int)getpid(), instance );

  s->gui = aligned_alloc( fd_gui_align(), fd_gui_footprint( 1UL, 1UL, 1UL ) );
  FD_TEST( s->gui );
  memset( s->gui, 0, fd_gui_footprint( 1UL, 1UL, 1UL ) );
  s->gui->timeline_day_max = ULONG_MAX;
  s->gui->timeline_skipped_slot_watermark = ULONG_MAX;
  s->gui->timeline_skipped_bank_seq_watermark = ULONG_MAX;
  s->gui->timeline_skipped_coverage_start_ns = LONG_MAX;
  s->gui->timeline_skipped_coverage_end_ns = LONG_MAX;
  s->gui->slot_txn_scratch.max = 1UL;

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

  s->shred_pool_mem = aligned_alloc( fd_gui_shred_event_pool_align(),
                                     fd_gui_shred_event_pool_footprint( FD_GUI_SHRED_EVENT_POOL_MAX ) );
  FD_TEST( s->shred_pool_mem );
  s->gui->shreds.shred_event_pool = fd_gui_shred_event_pool_join(
      fd_gui_shred_event_pool_new( s->shred_pool_mem, FD_GUI_SHRED_EVENT_POOL_MAX ) );
  FD_TEST( s->gui->shreds.shred_event_pool );

  s->shred_list_mem = aligned_alloc( fd_gui_shred_event_dlist_align(), fd_gui_shred_event_dlist_footprint() );
  FD_TEST( s->shred_list_mem );
  s->gui->shreds.shred_event_list = fd_gui_shred_event_dlist_join(
      fd_gui_shred_event_dlist_new( s->shred_list_mem ) );
  FD_TEST( s->gui->shreds.shred_event_list );

  s->fec_pool_mem = aligned_alloc( fd_gui_shred_event_pool_align(), fd_gui_shred_event_pool_footprint( FD_GUI_SHRED_EVENT_POOL_MAX ) );
  s->fec_list_mem = aligned_alloc( fd_gui_shred_event_dlist_align(), fd_gui_shred_event_dlist_footprint() );
  ulong fec_chain_cnt = fd_gui_fec_event_map_chain_cnt_est( FD_GUI_SHRED_EVENT_POOL_MAX );
  s->fec_map_mem = aligned_alloc( fd_gui_fec_event_map_align(), fd_gui_fec_event_map_footprint( fec_chain_cnt ) );
  FD_TEST( s->fec_pool_mem && s->fec_list_mem && s->fec_map_mem );
  s->gui->shreds.fec_event_pool = fd_gui_shred_event_pool_join( fd_gui_shred_event_pool_new( s->fec_pool_mem, FD_GUI_SHRED_EVENT_POOL_MAX ) );
  s->gui->shreds.fec_event_list = fd_gui_shred_event_dlist_join( fd_gui_shred_event_dlist_new( s->fec_list_mem ) );
  s->gui->shreds.fec_event_map = fd_gui_fec_event_map_join( fd_gui_fec_event_map_new( s->fec_map_mem, fec_chain_cnt, 0UL ) );
  FD_TEST( s->gui->shreds.fec_event_pool && s->gui->shreds.fec_event_list && s->gui->shreds.fec_event_map );

  s->completion_pool_mem = aligned_alloc( fd_gui_fec_completion_pool_align(), fd_gui_fec_completion_pool_footprint( FD_GUI_SHRED_EVENT_POOL_MAX ) );
  s->completion_list_mem = aligned_alloc( fd_gui_fec_completion_dlist_align(), fd_gui_fec_completion_dlist_footprint() );
  FD_TEST( s->completion_pool_mem && s->completion_list_mem );
  s->gui->shreds.completion_pool = fd_gui_fec_completion_pool_join( fd_gui_fec_completion_pool_new( s->completion_pool_mem, FD_GUI_SHRED_EVENT_POOL_MAX ) );
  s->gui->shreds.completion_list = fd_gui_fec_completion_dlist_join( fd_gui_fec_completion_dlist_new( s->completion_list_mem ) );
  FD_TEST( s->gui->shreds.completion_pool && s->gui->shreds.completion_list );
}

static void
store_close( test_store_t * s ) {
  fd_gui_shred_event_dlist_delete( fd_gui_shred_event_dlist_leave( s->gui->shreds.shred_event_list ) );
  fd_gui_shred_event_pool_delete( fd_gui_shred_event_pool_leave( s->gui->shreds.shred_event_pool ) );
  fd_gui_shred_event_dlist_delete( fd_gui_shred_event_dlist_leave( s->gui->shreds.fec_event_list ) );
  fd_gui_fec_event_map_delete( fd_gui_fec_event_map_leave( s->gui->shreds.fec_event_map ) );
  fd_gui_shred_event_pool_delete( fd_gui_shred_event_pool_leave( s->gui->shreds.fec_event_pool ) );
  fd_gui_fec_completion_dlist_delete( fd_gui_fec_completion_dlist_leave( s->gui->shreds.completion_list ) );
  fd_gui_fec_completion_pool_delete( fd_gui_fec_completion_pool_leave( s->gui->shreds.completion_pool ) );
  fd_gui_store_delete( fd_gui_store_leave( s->gui->db ) );
  free( s->fec_pool_mem );
  free( s->fec_list_mem );
  free( s->fec_map_mem );
  free( s->completion_pool_mem );
  free( s->completion_list_mem );
  free( s->shred_list_mem );
  free( s->shred_pool_mem );
  free( s->hist_mem );
  free( s->db_mem );
  free( s->gui );
  rm_tmpdir( s->path );
}

static void
test_timeline_db( fd_gui_t * gui ) {
  fd_gui_store_desc_t const * descs = fd_gui_hist_db_descs( 2UL<<30 );
  FD_TEST( FD_GUI_HIST_TIMELINE_DAY==11 );
  FD_TEST( FD_GUI_HIST_REPLAY_TXN==12 );
  FD_TEST( FD_GUI_HIST_REPLAY_TXN_BATCH==13 );
  FD_TEST( FD_GUI_HIST_FEC_EVENTS==14 );
  FD_TEST( FD_GUI_HIST_FEC_COMPLETIONS==15 );
  FD_TEST( FD_GUI_HIST_CNT==16 );
  FD_TEST( descs[ FD_GUI_HIST_FEC_EVENTS ].val_sz==sizeof(fd_gui_shred_batch_t) );
  FD_TEST( descs[ FD_GUI_HIST_FEC_COMPLETIONS ].val_sz==sizeof(fd_gui_fec_completion_batch_t) );
  FD_TEST( descs[ FD_GUI_HIST_FEC_EVENTS ].ts_off==offsetof(fd_gui_shred_batch_t,insert_time_ns) );
  FD_TEST( descs[ FD_GUI_HIST_FEC_COMPLETIONS ].ts_off==offsetof(fd_gui_fec_completion_batch_t,insert_time_ns) );
  FD_TEST( !strcmp( descs[ FD_GUI_HIST_TIMELINE_DAY     ].name, "timeline_day"     ) );
  FD_TEST( !strcmp( descs[ FD_GUI_HIST_REPLAY_TXN       ].name, "replay_txn"       ) );
  FD_TEST( !strcmp( descs[ FD_GUI_HIST_REPLAY_TXN_BATCH ].name, "replay_txn_batch" ) );
  FD_TEST( descs[ FD_GUI_HIST_SHRED_EVENTS     ].val_sz==sizeof(fd_gui_shred_batch_t) );
  FD_TEST( descs[ FD_GUI_HIST_TIMELINE_DAY     ].val_sz==sizeof(fd_gui_timeline_day_t) );
  FD_TEST( descs[ FD_GUI_HIST_REPLAY_TXN_BATCH ].val_sz==sizeof(fd_gui_store_replay_txn_batch_t) );
  FD_TEST( descs[ FD_GUI_HIST_TIMELINE_DAY ].kind==FD_GUI_STORE_KIND_TS );
  FD_TEST( descs[ FD_GUI_HIST_TIMELINE_DAY     ].ts_off==offsetof(fd_gui_timeline_day_t,insert_time_ns) );
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
  FD_TEST( ((fd_gui_shred_batch_t const *)it->rec)->base_timestamp==shred_ns );
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

  fd_gui_hist_iter_t it[ 1 ];
  FD_TEST( !fd_gui_hist_range_begin( gui, it, FD_GUI_HIST_SHRED_EVENTS, 0L, 0L, NULL, NULL ) );
  FD_TEST( fd_gui_hist_range_next( it ) );
  fd_gui_shred_batch_t const * shred = it->rec;
  FD_TEST( shred->base_timestamp==-sec_ns( 2UL ) && shred->insert_time_ns==0L && shred->slot==1UL );
  FD_TEST( !fd_gui_hist_range_next( it ) );
  fd_gui_hist_range_end( it );

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
    fd_gui_microblock_execution_end( gui, start_ns+100L, i, slot_num, 1UL, txn->txnp, i, dt, 0UL, bank_seq, sec_ns( 102UL+i ) );
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
  fd_gui_microblock_execution_end( gui, sec_ns( 50UL )+1L, 0UL, slot_num, 1UL, txn->txnp, 0UL, dt, 0UL, bank_seq-1UL, sec_ns( 103UL ) );

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
  fd_gui_microblock_execution_end( gui, sec_ns( 20UL )+1L, 0UL, slot_num, 1UL, txn->txnp, 2UL, dt, 0UL, bank_seq, sec_ns( 99UL ) );
  FD_TEST( metrics->ts_appends[ FD_GUI_HIST_TXN_START ]==start_appends );
  FD_TEST( metrics->ts_appends[ FD_GUI_HIST_TXN_END   ]==end_appends );
  lslot = fd_gui_slot_leader_get( gui, slot_num, bank_seq );
  FD_TEST( lslot->txn_insert_time_min_ns==sec_ns( 100UL ) );
  FD_TEST( lslot->txn_insert_time_max_ns==sec_ns( 103UL ) );

  fd_gui_microblock_execution_begin( gui, sec_ns( 20UL ), slot_num, txn, 1UL, 2U, 2UL, bank_seq+1UL, sec_ns( 99UL ) );
  fd_gui_microblock_execution_end( gui, sec_ns( 20UL )+1L, 0UL, slot_num, 1UL, txn->txnp, 2UL, dt, 0UL, bank_seq+1UL, sec_ns( 99UL ) );
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
test_shred_event_batches( fd_gui_t * gui ) {
  long const base = 10000000000L;

  for( ulong i=0UL; i<128UL; i++ )
    fd_gui_shred_event_staged_append( gui, 700UL, i, FD_GUI_SLOT_SHRED_SHRED_RECEIVED_TURBINE, base+(long)i );

  fd_gui_shred_event_staged_append( gui, 701UL, 9UL, FD_GUI_SLOT_SHRED_REPAIR_REQUEST, base+50L );
  fd_gui_shred_event_staged_append( gui, 700UL, 128UL, FD_GUI_SLOT_SHRED_SHRED_REPLAY_EXEC_DONE, base+128L );

  FD_TEST( fd_gui_shred_event_pool_used( gui->shreds.shred_event_pool )==130UL );

  fd_gui_shred_event_iter_t it[ 1 ];
  fd_gui_shred_event_iter_begin( gui, it, base+10L, base+60L );
  for( ulong i=10UL; i<=60UL; i++ ) {
    FD_TEST( fd_gui_shred_event_iter_next( it ) );
    FD_TEST( it->event.slot==700UL );
    FD_TEST( it->event.idx==(ushort)i );
    FD_TEST( it->event.timestamp==base+(long)i );
  }
  FD_TEST( fd_gui_shred_event_iter_next( it ) );
  FD_TEST( it->event.slot==701UL && it->event.idx==9U && it->event.timestamp==base+50L );
  FD_TEST( !fd_gui_shred_event_iter_next( it ) );
  fd_gui_shred_event_iter_end( it );

  fd_gui_shred_event_slot_complete( gui, 700UL, base+129L, base+129L );
  FD_TEST( fd_gui_shred_event_pool_used( gui->shreds.shred_event_pool )==1UL );
  FD_TEST( count_ts( gui, FD_GUI_HIST_SHRED_EVENTS, ULONG_MAX )==2UL );

  fd_gui_shred_event_iter_begin( gui, it, base, base+1000L );
  for( ulong i=0UL; i<128UL; i++ ) {
    FD_TEST( fd_gui_shred_event_iter_next( it ) );
    FD_TEST( it->event.slot==700UL );
    FD_TEST( it->event.idx==(ushort)i );
    FD_TEST( it->event.timestamp==base+(long)i );
  }
  FD_TEST( fd_gui_shred_event_iter_next( it ) );
  FD_TEST( it->event.slot==700UL && it->event.idx==128U && it->event.event==FD_GUI_SLOT_SHRED_SHRED_REPLAY_EXEC_DONE );
  FD_TEST( fd_gui_shred_event_iter_next( it ) );
  FD_TEST( it->event.slot==700UL && it->event.idx==USHORT_MAX && it->event.event==FD_GUI_SLOT_SHRED_SHRED_SLOT_COMPLETE );
  FD_TEST( fd_gui_shred_event_iter_next( it ) );
  FD_TEST( it->event.slot==701UL && it->event.idx==9U );
  FD_TEST( !fd_gui_shred_event_iter_next( it ) );
  fd_gui_shred_event_iter_end( it );

  fd_gui_shred_event_slot_complete( gui, 701UL, base+130L, base+130L );
  FD_TEST( fd_gui_shred_event_pool_free( gui->shreds.shred_event_pool )==FD_GUI_SHRED_EVENT_POOL_MAX );
  FD_TEST( fd_gui_shred_event_dlist_is_empty( gui->shreds.shred_event_list, gui->shreds.shred_event_pool ) );
  FD_TEST( count_ts( gui, FD_GUI_HIST_SHRED_EVENTS, ULONG_MAX )==3UL );

  put_slot( gui, 700UL, base+129L );
  fd_gui_shred_event_staged_append( gui, 700UL, 129UL, FD_GUI_SLOT_SHRED_SHRED_RECEIVED_REPAIR, base+131L );
  FD_TEST( gui->shreds.dropped_event_cnt==1UL );
  FD_TEST( fd_gui_shred_event_pool_free( gui->shreds.shred_event_pool )==FD_GUI_SHRED_EVENT_POOL_MAX );

  long const split_base = 20000000000L;
  fd_gui_shred_event_staged_append( gui, 702UL, 500UL, FD_GUI_SLOT_SHRED_SHRED_RECEIVED_TURBINE, split_base+100L );
  fd_gui_shred_event_staged_append( gui, 702UL, 400UL, FD_GUI_SLOT_SHRED_SHRED_RECEIVED_REPAIR,  split_base      );
  fd_gui_shred_event_staged_append( gui, 702UL, 655UL, FD_GUI_SLOT_SHRED_SHRED_PUBLISHED,        split_base+(long)FD_GUI_SHRED_EVENT_TS_MAX );
  fd_gui_shred_event_staged_append( gui, 702UL, 400UL, FD_GUI_SLOT_SHRED_SHRED_REPLAY_EXEC_DONE, split_base+(long)FD_GUI_SHRED_EVENT_TS_MAX+1L );
  fd_gui_shred_event_staged_append( gui, 702UL, 401UL, FD_GUI_SLOT_SHRED_REPAIR_REQUEST,          split_base+FD_GUI_HIST_RES_1S_NS );
  fd_gui_shred_event_slot_complete( gui, 702UL, split_base+FD_GUI_HIST_RES_1S_NS+1L,
                                    split_base+FD_GUI_HIST_RES_1S_NS+1L );
  FD_TEST( count_ts( gui, FD_GUI_HIST_SHRED_EVENTS, 702UL )==3UL );

  ushort const expected_idx[] = { 500U, 400U, 655U, 400U, 401U, USHORT_MAX };
  long const expected_ts[] = {
    split_base+100L,
    split_base,
    split_base+(long)FD_GUI_SHRED_EVENT_TS_MAX,
    split_base+(long)FD_GUI_SHRED_EVENT_TS_MAX+1L,
    split_base+FD_GUI_HIST_RES_1S_NS,
    split_base+FD_GUI_HIST_RES_1S_NS+1L
  };
  fd_gui_shred_event_iter_begin( gui, it, split_base, split_base+FD_GUI_HIST_RES_1S_NS+1L );
  for( ulong i=0UL; i<6UL; i++ ) {
    FD_TEST( fd_gui_shred_event_iter_next( it ) );
    FD_TEST( it->event.slot==702UL );
    FD_TEST( it->event.idx==expected_idx[ i ] );
    FD_TEST( it->event.timestamp==expected_ts[ i ] );
  }
  FD_TEST( !fd_gui_shred_event_iter_next( it ) );
  fd_gui_shred_event_iter_end( it );

  fd_gui_shred_event_staged_append( gui, 703UL,   0UL, FD_GUI_SLOT_SHRED_SHRED_RECEIVED_TURBINE, split_base );
  fd_gui_shred_event_staged_append( gui, 703UL, 255UL, FD_GUI_SLOT_SHRED_SHRED_RECEIVED_TURBINE, split_base );
  fd_gui_shred_event_staged_append( gui, 703UL, 256UL, FD_GUI_SLOT_SHRED_SHRED_RECEIVED_TURBINE, split_base );
  fd_gui_shred_event_slot_complete( gui, 703UL, split_base+1L, split_base+FD_GUI_HIST_RES_1S_NS+2L );
  FD_TEST( count_ts( gui, FD_GUI_HIST_SHRED_EVENTS, 703UL )==2UL );

  ulong dropped_event_cnt = gui->shreds.dropped_event_cnt;
  fd_gui_shred_event_staged_append( gui, (ulong)UINT_MAX+1UL, 0UL, FD_GUI_SLOT_SHRED_SHRED_RECEIVED_TURBINE, split_base );
  fd_gui_shred_event_staged_append( gui, 704UL, USHORT_MAX, FD_GUI_SLOT_SHRED_SHRED_RECEIVED_TURBINE, split_base );
  FD_TEST( gui->shreds.dropped_event_cnt==dropped_event_cnt+2UL );

  fd_gui_shred_event_staged_append( gui, 705UL, 0UL, FD_GUI_SLOT_SHRED_SHRED_RECEIVED_TURBINE, sec_ns( 30UL )-1L );
  fd_gui_shred_event_slot_complete( gui, 705UL, sec_ns( 30UL )+1L, sec_ns( 30UL )+500000000L );
  fd_gui_shred_event_iter_begin( gui, it, sec_ns( 30UL )-1L, sec_ns( 30UL )-1L );
  FD_TEST( fd_gui_shred_event_iter_next( it ) );
  FD_TEST( it->event.timestamp==sec_ns( 30UL )-1L );
  FD_TEST( !fd_gui_shred_event_iter_next( it ) );
  fd_gui_shred_event_iter_end( it );
  fd_gui_shred_event_iter_begin( gui, it, sec_ns( 30UL )+1L, sec_ns( 30UL )+1L );
  FD_TEST( fd_gui_shred_event_iter_next( it ) );
  FD_TEST( it->event.timestamp==sec_ns( 30UL )+1L );
  FD_TEST( !fd_gui_shred_event_iter_next( it ) );
  fd_gui_shred_event_iter_end( it );

  fd_gui_shred_event_staged_append( gui, 706UL, 0UL, FD_GUI_SLOT_SHRED_SHRED_RECEIVED_TURBINE, sec_ns( 32UL ) );
  fd_gui_shred_event_slot_complete( gui, 706UL, sec_ns( 32UL )+1L, sec_ns( 31UL )+999999999L );
  fd_gui_shred_event_iter_begin( gui, it, sec_ns( 32UL ), sec_ns( 32UL ) );
  FD_TEST( fd_gui_shred_event_iter_next( it ) );
  FD_TEST( it->event.slot==706UL && it->event.timestamp==sec_ns( 32UL ) );
  FD_TEST( !fd_gui_shred_event_iter_next( it ) );
  fd_gui_shred_event_iter_end( it );

  fd_gui_shred_event_staged_append( gui, 704UL, 1UL, FD_GUI_SLOT_SHRED_SHRED_RECEIVED_TURBINE, 0L );
  fd_gui_shred_event_slot_complete( gui, 704UL, 0L, sec_ns( 40UL ) );
  fd_gui_shred_event_iter_begin( gui, it, 0L, 0L );
  FD_TEST( !fd_gui_shred_event_iter_next( it ) );
  fd_gui_shred_event_iter_end( it );
  fd_gui_shred_event_iter_begin( gui, it, 0L, sec_ns( 40UL ) );
  ulong found_704 = 0UL;
  while( fd_gui_shred_event_iter_next( it ) ) {
    if( it->event.slot!=704UL ) continue;
    FD_TEST( it->event.timestamp==0L );
    FD_TEST( it->event.idx==fd_ushort_if( found_704==0UL, 1U, USHORT_MAX ) );
    found_704++;
  }
  FD_TEST( found_704==2UL );
  fd_gui_shred_event_iter_end( it );

  fd_gui_hist_iter_t range_it[ 1 ];
  FD_TEST( !fd_gui_hist_range_begin( gui, range_it, FD_GUI_HIST_SHRED_EVENTS, sec_ns( 40UL ), sec_ns( 40UL ), NULL, NULL ) );
  FD_TEST( fd_gui_hist_range_next( range_it ) );
  fd_gui_shred_batch_t const * batch = range_it->rec;
  FD_TEST( batch->slot==704UL && batch->insert_time_ns==sec_ns( 40UL ) && batch->base_timestamp==0L );
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
  for( ulong i=0UL; i<4UL; i++ )
    fd_gui_shred_event_staged_append( gui, 707UL, i, FD_GUI_SLOT_SHRED_SHRED_RECEIVED_TURBINE, extreme_timestamps[ i ] );
  fd_gui_shred_event_slot_complete( gui, 707UL, LONG_MAX, sec_ns( 41UL ) );
  FD_TEST( !fd_gui_hist_range_begin( gui, range_it, FD_GUI_HIST_SHRED_EVENTS, sec_ns( 41UL ), sec_ns( 41UL ), NULL, NULL ) );
  for( ulong i=0UL; i<2UL; i++ ) {
    FD_TEST( fd_gui_hist_range_next( range_it ) );
    batch = range_it->rec;
    FD_TEST( batch->slot==707UL && batch->insert_time_ns==sec_ns( 41UL ) );
    FD_TEST( batch->base_timestamp==(i ? LONG_MAX : 0L) );
    FD_TEST( batch->event_cnt==1U );
  }
  FD_TEST( !fd_gui_hist_range_next( range_it ) );
  fd_gui_hist_range_end( range_it );
  fd_gui_shred_event_iter_begin( gui, it, LONG_MIN, LONG_MAX );
  ulong extreme_cnt = 0UL;
  while( fd_gui_shred_event_iter_next( it ) ) {
    if( it->event.slot!=707UL ) continue;
    FD_TEST( extreme_cnt<2UL );
    FD_TEST( it->event.timestamp==(extreme_cnt ? LONG_MAX : 0L) );
    extreme_cnt++;
  }
  FD_TEST( extreme_cnt==2UL );
  fd_gui_shred_event_iter_end( it );

  FD_LOG_NOTICE(( "test_shred_event_batches: ok" ));
}

static void
assert_staged_events( fd_gui_t *         gui,
                      ulong const *      slots,
                      ushort const *     idxs,
                      ulong              event_cnt ) {
  fd_gui_shred_event_staged_t * pool = gui->shreds.shred_event_pool;
  fd_gui_shred_event_dlist_t *  list = gui->shreds.shred_event_list;
  ulong i = 0UL;
  for( fd_gui_shred_event_dlist_iter_t iter = fd_gui_shred_event_dlist_iter_fwd_init( list, pool );
       !fd_gui_shred_event_dlist_iter_done( iter, list, pool );
       iter = fd_gui_shred_event_dlist_iter_fwd_next( iter, list, pool ) ) {
    FD_TEST( i<event_cnt );
    fd_gui_shred_event_staged_t const * staged = fd_gui_shred_event_dlist_iter_ele_const( iter, list, pool );
    FD_TEST( staged->slot==slots[ i ] );
    FD_TEST( staged->idx ==idxs [ i ] );
    i++;
  }
  FD_TEST( i==event_cnt );
  FD_TEST( fd_gui_shred_event_pool_used( pool )==event_cnt );
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
  gui->summary.is_alpenglow = 1;
  gui->timeline_skipped_slot_watermark = ULONG_MAX;
  gui->timeline_skipped_coverage_start_ns = LONG_MAX;
  gui->timeline_skipped_coverage_end_ns = LONG_MAX;
  gui->timeline_day_max = ULONG_MAX;

  fd_gui_shred_event_staged_append( gui, 899UL, 1UL, FD_GUI_SLOT_SHRED_SHRED_RECEIVED_TURBINE, 1L );
  fd_gui_shred_event_staged_append( gui, 900UL, 2UL, FD_GUI_SLOT_SHRED_SHRED_RECEIVED_REPAIR,  2L );
  fd_gui_shred_event_staged_append( gui, 901UL, 3UL, FD_GUI_SLOT_SHRED_SHRED_PUBLISHED,        3L );
  fd_gui_shred_event_staged_append( gui, 898UL, 4UL, FD_GUI_SLOT_SHRED_SHRED_REPLAY_EXEC_DONE, 4L );
  fd_gui_shred_event_staged_append( gui, 902UL, 5UL, FD_GUI_SLOT_SHRED_REPAIR_REQUEST,          5L );

  put_slot( gui, 900UL, 6L );
  fd_gui_slot_get( gui, 900UL, BANK_SEQ )->parent_slot = ULONG_MAX;
  fd_gui_handle_root_advanced( gui, 900UL, BANK_SEQ, 6L );

  ulong const  slots_after_first[] = { 900UL, 901UL, 902UL };
  ushort const idxs_after_first [] = { 2U,    3U,    5U    };
  assert_staged_events( gui, slots_after_first, idxs_after_first, 3UL );
  FD_TEST( count_ts( gui, FD_GUI_HIST_SHRED_EVENTS, 898UL )==1UL );
  FD_TEST( count_ts( gui, FD_GUI_HIST_SHRED_EVENTS, 899UL )==1UL );

  fd_gui_shred_event_staged_append( gui, 899UL, 6UL, FD_GUI_SLOT_SHRED_SHRED_RECEIVED_TURBINE, 7L );
  FD_TEST( gui->shreds.dropped_event_cnt==1UL );
  assert_staged_events( gui, slots_after_first, idxs_after_first, 3UL );

  put_slot( gui, 899UL, 8L );
  fd_gui_slot_get( gui, 899UL, BANK_SEQ )->parent_slot = ULONG_MAX;
  fd_gui_handle_root_advanced( gui, 900UL, BANK_SEQ, 8L );
  assert_staged_events( gui, slots_after_first, idxs_after_first, 3UL );
  fd_gui_handle_root_advanced( gui, 899UL, BANK_SEQ, 8L );
  assert_staged_events( gui, slots_after_first, idxs_after_first, 3UL );

  put_slot( gui, 901UL, 9L );
  fd_gui_slot_get( gui, 901UL, BANK_SEQ )->parent_slot = ULONG_MAX;
  fd_gui_handle_root_advanced( gui, 901UL, BANK_SEQ, 9L );

  ulong const  slots_after_advance[] = { 901UL, 902UL };
  ushort const idxs_after_advance [] = { 3U,    5U    };
  assert_staged_events( gui, slots_after_advance, idxs_after_advance, 2UL );
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

  fd_gui_shred_event_slot_complete( gui, 901UL, 10L, 10L );
  ulong const  slots_after_complete[] = { 902UL };
  ushort const idxs_after_complete [] = { 5U    };
  assert_staged_events( gui, slots_after_complete, idxs_after_complete, 1UL );
  FD_TEST( count_ts( gui, FD_GUI_HIST_SHRED_EVENTS, 901UL )==1UL );

  fd_gui_shred_event_slot_complete( gui, 902UL, 11L, 11L );
  FD_TEST( fd_gui_shred_event_dlist_is_empty( gui->shreds.shred_event_list, gui->shreds.shred_event_pool ) );
  FD_TEST( !fd_gui_shred_event_pool_used( gui->shreds.shred_event_pool ) );

  FD_TEST( fd_http_server_delete( fd_http_server_leave( gui->http ) )==http_mem );
  free( http_mem );
  gui->http = NULL;

  FD_LOG_NOTICE(( "test_shred_event_root_reclaim: ok" ));
}

static void
test_shred_event_pool_exhaustion( fd_gui_t * gui ) {
  long const timestamp = 30000000000L;
  for( ulong i=0UL; i<FD_GUI_SHRED_EVENT_POOL_MAX; i++ )
    fd_gui_shred_event_staged_append( gui, 800UL, i & 255UL, FD_GUI_SLOT_SHRED_SHRED_RECEIVED_TURBINE, timestamp );

  FD_TEST( !fd_gui_shred_event_pool_free( gui->shreds.shred_event_pool ) );
  FD_TEST( !gui->shreds.dropped_event_cnt );
  fd_gui_shred_event_staged_append( gui, 801UL, 0UL, FD_GUI_SLOT_SHRED_SHRED_RECEIVED_TURBINE, timestamp );
  FD_TEST( gui->shreds.dropped_event_cnt==1UL );

  fd_gui_shred_event_slot_complete( gui, 800UL, timestamp+1L, timestamp+1L );
  FD_TEST( fd_gui_shred_event_pool_free( gui->shreds.shred_event_pool )==FD_GUI_SHRED_EVENT_POOL_MAX );
  FD_TEST( fd_gui_shred_event_dlist_is_empty( gui->shreds.shred_event_list, gui->shreds.shred_event_pool ) );
  FD_TEST( count_ts( gui, FD_GUI_HIST_SHRED_EVENTS, 800UL)==(FD_GUI_SHRED_EVENT_POOL_MAX/FD_GUI_SHRED_EVENT_BATCH_MAX)+1UL );

  FD_LOG_NOTICE(( "test_shred_event_pool_exhaustion: ok" ));
}

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
test_json_field( test_json_t json, char const * field ) {
  fd_jtok_t j[1]; fd_jtok_init( j, json.ptr, json.sz );
  fd_jtok_str_t key;
  test_json_t result = {0};
  fd_jtok_obj_enter( j );
  while( fd_jtok_obj_next( j, &key ) )
    if( fd_jtok_str_eq( &key, field ) ) fd_jtok_raw( j, &result.ptr, &result.sz );
  FD_TEST( !fd_jtok_fini( j ) );
  return result;
}

static test_json_t
test_json_index( test_json_t json, int index ) {
  fd_jtok_t j[1]; fd_jtok_init( j, json.ptr, json.sz );
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
  fd_jtok_t j[1]; fd_jtok_init( j, json.ptr, json.sz );
  int count = 0;
  fd_jtok_arr_enter( j );
  while( fd_jtok_arr_next( j ) ) count++;
  FD_TEST( !fd_jtok_fini( j ) );
  return count;
}

static int
test_json_kind( test_json_t json ) {
  fd_jtok_t j[1]; fd_jtok_init( j, json.ptr, json.sz );
  return fd_jtok_peek( j );
}

static ulong
test_json_ulong( test_json_t json ) {
  fd_jtok_t j[1]; fd_jtok_init( j, json.ptr, json.sz );
  ulong value = 0UL;
  fd_jtok_ulong( j, &value );
  FD_TEST( !fd_jtok_fini( j ) );
  return value;
}

static int
test_json_string_eq( test_json_t json, char const * expected ) {
  fd_jtok_t j[1]; fd_jtok_init( j, json.ptr, json.sz );
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
  fd_jtok_t j[1]; fd_jtok_init( j, json.ptr, json.sz );
  FD_TEST( !fd_jtok_fini( j ) );
  fd_http_server_stage_trunc( gui->http, 0UL );
  return json;
}

static test_json_t
timeline_value( test_json_t json, char const * field ) {
  return test_json_field( test_json_field( json, "value" ), field );
}

static void
test_fec_event_index( fd_gui_t * gui ) {
  long const ts = sec_ns( 10UL );
  fd_gui_shred_event_staged_t * pool = gui->shreds.fec_event_pool;
  fd_gui_fec_event_map_t * map = gui->shreds.fec_event_map;

  /* Exercise every pool index, including duplicates when full. */
  for( ulong i=0UL; i<FD_GUI_SHRED_EVENT_POOL_MAX; i++ )
    fd_gui_fec_event_staged_append( gui, 100UL, i, FD_GUI_SLOT_SHRED_REPAIR_REQUEST, ts+20L );
  FD_TEST( !fd_gui_shred_event_pool_free( pool ) );
  fd_gui_fec_event_staged_append( gui, 100UL, 0UL, FD_GUI_SLOT_SHRED_REPAIR_REQUEST, ts+10L );
  fd_gui_fec_event_staged_append( gui, 100UL, 0UL, FD_GUI_SLOT_SHRED_REPAIR_REQUEST, ts+30L );
  fd_gui_fec_event_staged_append( gui, 100UL, USHORT_MAX-1UL, FD_GUI_SLOT_SHRED_REPAIR_REQUEST, ts+10L );
  FD_TEST( !gui->shreds.dropped_fec_event_cnt );
  fd_gui_fec_event_staged_append( gui, 101UL, 0UL, FD_GUI_SLOT_SHRED_REPAIR_REQUEST, ts );
  fd_gui_fec_event_staged_append( gui, 100UL, 0UL, FD_GUI_SLOT_SHRED_SHRED_RECEIVED_TURBINE, ts );
  FD_TEST( gui->shreds.dropped_fec_event_cnt==2UL );
  FD_TEST( !fd_gui_fec_event_map_verify( map, FD_GUI_SHRED_EVENT_POOL_MAX, pool ) );

  fd_gui_shred_event_staged_advance( gui, 101UL, ts+40L );
  FD_TEST( !fd_gui_shred_event_pool_used( pool ) );
  FD_TEST( fd_gui_shred_event_dlist_is_empty( gui->shreds.fec_event_list, pool ) );
  FD_TEST( !fd_gui_fec_event_map_verify( map, FD_GUI_SHRED_EVENT_POOL_MAX, pool ) );

  /* Cutoff flushing retains insertion order and the minimum timestamps,
     and removes all mappings before their pool nodes can be reused. */
  fd_gui_shred_event_iter_t it;
  fd_gui_fec_event_iter_begin( gui, &it, ts, ts+40L );
  for( ulong i=0UL; i<FD_GUI_SHRED_EVENT_POOL_MAX; i++ ) {
    fd_gui_fec_event_key_t key = { .slot=100U, .idx=(ushort)i, .event=FD_GUI_SLOT_SHRED_REPAIR_REQUEST };
    FD_TEST( !fd_gui_fec_event_map_ele_query( map, &key, NULL, pool ) );
    FD_TEST( fd_gui_shred_event_iter_next( &it ) );
    FD_TEST( it.event.slot==100U && it.event.idx==i && it.event.event==FD_GUI_SLOT_SHRED_REPAIR_REQUEST );
    FD_TEST( it.event.timestamp==ts+((!i || i==USHORT_MAX-1UL) ? 10L : 20L) );
  }
  FD_TEST( !fd_gui_shred_event_iter_next( &it ) );
  fd_gui_shred_event_iter_end( &it );

  /* Each component of the key distinguishes events.  Reuse freed nodes
     and flush one slot while another remains live. */
  fd_gui_fec_event_key_t keys[] = {
    { .slot=101U, .idx=7U, .event=FD_GUI_SLOT_SHRED_REPAIR_REQUEST },
    { .slot=102U, .idx=7U, .event=FD_GUI_SLOT_SHRED_REPAIR_REQUEST },
    { .slot=101U, .idx=8U, .event=FD_GUI_SLOT_SHRED_REPAIR_REQUEST },
    { .slot=101U, .idx=7U, .event=FD_GUI_SLOT_SHRED_SHRED_RECEIVED_TURBINE },
  };
  for( ulong i=0UL; i<4UL; i++ ) {
    fd_gui_fec_event_key_t const * key = &keys[i];
    fd_gui_fec_event_staged_append( gui, key->slot, key->idx, key->event, ts+50L+(long)i );
    fd_gui_fec_event_staged_append( gui, key->slot, key->idx, key->event, ts+60L );
    fd_gui_shred_event_staged_t * ele = fd_gui_fec_event_map_ele_query( map, key, NULL, pool );
    FD_TEST( ele && ele->timestamp==ts+50L+(long)i );
  }
  FD_TEST( fd_gui_shred_event_pool_used( pool )==4UL );
  fd_gui_shred_event_slot_complete( gui, 101UL, ts+70L, ts+70L );
  FD_TEST( fd_gui_shred_event_pool_used( pool )==1UL );
  for( ulong i=0UL; i<4UL; i++ )
    FD_TEST( !!fd_gui_fec_event_map_ele_query( map, &keys[i], NULL, pool )==(i==1UL) );
  fd_gui_fec_event_staged_append( gui, 102UL, 7UL, FD_GUI_SLOT_SHRED_REPAIR_REQUEST, ts+45L );
  FD_TEST( fd_gui_fec_event_map_ele_query( map, &keys[1], NULL, pool )->timestamp==ts+45L );
  fd_gui_shred_event_slot_complete( gui, 102UL, ts+80L, ts+80L );
  FD_TEST( !fd_gui_shred_event_pool_used( pool ) );
  for( ulong i=0UL; i<4UL; i++ )
    FD_TEST( !fd_gui_fec_event_map_ele_query( map, &keys[i], NULL, pool ) );
  FD_TEST( !fd_gui_fec_event_map_verify( map, FD_GUI_SHRED_EVENT_POOL_MAX, pool ) );
  FD_LOG_NOTICE(( "test_fec_event_index: ok" ));
}

static void
test_timeline_staging( test_store_t * s ) {
  fd_gui_t * gui = s->gui;
  long const ts = sec_ns( 10UL );
  gui->shreds.fec_event_pool = fd_gui_shred_event_pool_join( fd_gui_shred_event_pool_new( s->fec_pool_mem, 2UL ) );
  gui->shreds.completion_pool = fd_gui_fec_completion_pool_join( fd_gui_fec_completion_pool_new( s->completion_pool_mem, 2UL ) );
  gui->summary.is_alpenglow = 1;
  void * http_mem = timeline_http_open( gui );

  fd_gui_fec_event_staged_append( gui, 100UL, 1UL, FD_GUI_SLOT_SHRED_REPAIR_REQUEST, ts+20L );
  fd_gui_fec_event_staged_append( gui, 101UL, 2UL, FD_GUI_SLOT_SHRED_SHRED_RECEIVED_TURBINE, ts+30L );
  FD_TEST( !fd_gui_shred_event_pool_free( gui->shreds.fec_event_pool ) );
  fd_gui_fec_event_staged_append( gui, 100UL, 1UL, FD_GUI_SLOT_SHRED_REPAIR_REQUEST, ts+10L );
  FD_TEST( !gui->shreds.dropped_fec_event_cnt );
  fd_gui_fec_event_staged_append( gui, 102UL, 3UL, FD_GUI_SLOT_SHRED_REPAIR_REQUEST, ts+40L );
  FD_TEST( gui->shreds.dropped_fec_event_cnt==1UL );
  fd_gui_shred_event_staged_append( gui, 100UL, 32UL, FD_GUI_SLOT_SHRED_REPAIR_REQUEST, ts+10L );
  FD_TEST( fd_gui_shred_event_pool_used( gui->shreds.shred_event_pool )==1UL );

  FD_TEST( !fd_gui_printf_timeline_query_fec_events( gui, "timeline", ts+10L, ts+30L, 7UL ) );
  test_json_t json = timeline_response( gui );
  FD_TEST( !test_json_count( timeline_value( json, "idx" ) ) );
  FD_TEST( test_json_kind( timeline_value( json, "available_start_ns" ) )==FD_JTOK_NULL );
  FD_TEST( test_json_kind( timeline_value( json, "available_end_ns" ) )==FD_JTOK_NULL );
  FD_TEST( !test_json_field( test_json_field( json, "value" ), "shred_idx" ).ptr );

  FD_TEST( !fd_gui_printf_timeline_query_fec_events( gui, "timeline", ts+11L, ts+30L, 7UL ) );
  json = timeline_response( gui );
  FD_TEST( !test_json_count( timeline_value( json, "idx" ) ) );


  FD_TEST( !fd_gui_printf_timeline_query_shreds( gui, "timeline", ts, ts+30L, 7UL ) );
  json = timeline_response( gui );
  FD_TEST( !test_json_count( timeline_value( json, "idx" ) ) );
  FD_TEST( test_json_kind( timeline_value( json, "available_start_ns" ) )==FD_JTOK_NULL );
  FD_TEST( !fd_gui_shred_window_is_empty( gui, ts, ts+30L ) ); /* live display still sees staging */

  fd_gui_timeline_handle_fec( gui, 100UL, 1, ts+10L, 32UL, 16UL, 16UL, ts+40L );
  fd_gui_timeline_handle_fec( gui, 100UL, 1, ts+10L, 32UL, 16UL, 16UL, ts+40L );
  fd_gui_timeline_handle_fec( gui, 100UL, 1, ts+11L, 32UL, 16UL, 16UL, ts+40L );
  FD_TEST( fd_gui_fec_completion_pool_used( gui->shreds.completion_pool )==2UL );
  FD_TEST( !gui->shreds.dropped_completion_cnt );
  fd_gui_timeline_day_t const * day = fd_gui_timeline_day_get( gui, 0UL );
  FD_TEST( day );
  FD_TEST( fd_gui_timeline_field_get( day, 0, FD_GUI_TIMELINE_FIELD_PUBLISHED, 40UL )==128UL );
  FD_TEST( fd_gui_timeline_field_get( day, 0, FD_GUI_TIMELINE_FIELD_TURBINE, 40UL )==64UL );
  FD_TEST( !fd_gui_fec_completion_staged_append( gui, 100UL, ts+12L, 65UL, 0UL, 0UL, 0 ) );
  FD_TEST( !fd_gui_fec_completion_staged_append( gui, 100UL, ts+12L, 0UL, 65UL, 0UL, 0 ) );
  FD_TEST( !fd_gui_fec_completion_staged_append( gui, 100UL, ts+12L, 0UL, 0UL, 65UL, 0 ) );
  FD_TEST( gui->shreds.dropped_completion_cnt==3UL );
  FD_TEST( !count_ts( gui, FD_GUI_HIST_FEC_COMPLETIONS, ULONG_MAX ) );

  FD_TEST( !fd_gui_printf_timeline_query_agg( gui, "query_agg_shreds", "1ms", 0UL, ts, 1UL, 7UL ) );
  json = timeline_response( gui );
  FD_TEST( test_json_kind( test_json_index( timeline_value( json, "published" ), 0 ) )==FD_JTOK_NULL );
  FD_TEST( test_json_kind( test_json_index( timeline_value( json, "repair" ), 0 ) )==FD_JTOK_NULL );
  FD_TEST( test_json_kind( timeline_value( json, "available_start_ns" ) )==FD_JTOK_NULL );
  FD_TEST( test_json_kind( timeline_value( json, "available_end_ns" ) )==FD_JTOK_NULL );

  FD_TEST( !fd_gui_printf_timeline_query_agg( gui, "query_agg_slots", "1ms", 0UL, ts, 1UL, 7UL ) );
  json = timeline_response( gui );
  FD_TEST( (test_json_kind( timeline_value( json, "available_start_ns" ) )==FD_JTOK_NULL) );
  FD_TEST( (test_json_kind( timeline_value( json, "available_end_ns" ) )==FD_JTOK_NULL) );
  char const * slot_fields[] = { "start_slot", "end_slot", "skipped", "mine", "mine_skipped" };
  for( ulong i=0UL; i<5UL; i++ ) FD_TEST( !test_json_count( timeline_value( json, slot_fields[i] ) ) );

  fd_gui_shred_event_staged_advance( gui, 101UL, ts+50L );
  FD_TEST( !fd_gui_printf_timeline_query_agg( gui, "query_agg_shreds", "1ms", 0UL, ts, 1UL, 7UL ) );
  json = timeline_response( gui );
  FD_TEST( test_json_ulong( test_json_index( timeline_value( json, "published" ), 0 ) )==128UL );
  FD_TEST( test_json_ulong( test_json_index( timeline_value( json, "repair" ), 0 ) )==32UL );
  FD_TEST( test_json_kind( timeline_value( json, "available_start_ns" ) )==FD_JTOK_STR );

  FD_TEST( !fd_gui_printf_timeline_query_shreds( gui, "timeline", ts, ts+30L, 7UL ) );
  json = timeline_response( gui );
  FD_TEST( test_json_count( timeline_value( json, "idx" ) )==1 );
  FD_TEST( !fd_gui_printf_timeline_query_fec_events( gui, "timeline", ts, ts+100L, 7UL ) );
  json = timeline_response( gui );
  FD_TEST( test_json_count( timeline_value( json, "idx" ) )==1 );
  FD_TEST( test_json_ulong( test_json_index( timeline_value( json, "idx" ), 0 ) )==1UL );
  FD_TEST( test_json_string_eq( timeline_value( json, "reference_ts" ), "10000000010" ) );

  /* Both histories exist, but their lookup bounds do not overlap. */
  append_replay_txn( gui, sec_ns( 1UL ), sec_ns( 1UL ), 99UL );
  FD_TEST( !fd_gui_printf_timeline_query_agg( gui, "query_agg_slots", "1ms", 0UL, ts, 1UL, 7UL ) );
  json = timeline_response( gui );
  FD_TEST( (test_json_kind( timeline_value( json, "available_start_ns" ) )==FD_JTOK_NULL) );
  FD_TEST( (test_json_kind( timeline_value( json, "available_end_ns" ) )==FD_JTOK_NULL) );
  for( ulong i=0UL; i<5UL; i++ ) FD_TEST( !test_json_count( timeline_value( json, slot_fields[i] ) ) );

  /* Overlapping histories still return the slot data. */
  append_replay_txn( gui, ts, ts, 100UL );
  FD_TEST( !fd_gui_printf_timeline_query_agg( gui, "query_agg_slots", "1ms", 0UL, ts, 1UL, 7UL ) );
  json = timeline_response( gui );
  FD_TEST( (test_json_kind( timeline_value( json, "available_start_ns" ) )==FD_JTOK_STR) );
  FD_TEST( (test_json_kind( timeline_value( json, "available_end_ns" ) )==FD_JTOK_STR) );
  FD_TEST( test_json_ulong( test_json_index( timeline_value( json, "start_slot" ), 0 ) )==100UL );


  fd_gui_shred_event_staged_advance( gui, 101UL, ts+50L );
  FD_TEST( !fd_gui_shred_event_pool_used( gui->shreds.shred_event_pool ) );
  FD_TEST( fd_gui_shred_event_pool_used( gui->shreds.fec_event_pool )==1UL );
  FD_TEST( !fd_gui_fec_completion_pool_used( gui->shreds.completion_pool ) );
  FD_TEST( count_ts( gui, FD_GUI_HIST_FEC_COMPLETIONS, 100UL )==1UL );
  fd_gui_fec_completion_iter_t ci;
  fd_gui_fec_completion_iter_begin( gui, &ci, ts+10L, ts+11L );
  FD_TEST( fd_gui_fec_completion_iter_next( &ci ) && ci.event.timestamp==ts+10L );
  FD_TEST( fd_gui_fec_completion_iter_next( &ci ) && ci.event.timestamp==ts+11L );
  FD_TEST( !fd_gui_fec_completion_iter_next( &ci ) );
  fd_gui_fec_completion_iter_end( &ci );
  fd_gui_shred_event_iter_t ei;
  fd_gui_fec_event_iter_begin( gui, &ei, ts, ts+100L );
  FD_TEST( fd_gui_shred_event_iter_next( &ei ) && ei.event.slot==100UL && ei.event.idx==1U );
  FD_TEST( !fd_gui_shred_event_iter_next( &ei ) );
  fd_gui_shred_event_iter_end( &ei );
  fd_gui_shred_event_staged_advance( gui, 99UL, ts+60L );
  fd_gui_shred_event_staged_append( gui, 100UL, 33UL, FD_GUI_SLOT_SHRED_REPAIR_REQUEST, ts+60L );
  FD_TEST( gui->shreds.closed_before_slot==101UL && gui->shreds.dropped_event_cnt==1UL );

  fd_gui_shred_event_slot_complete( gui, 101UL, ts+70L, ts+70L );
  fd_gui_shred_event_slot_complete( gui, 101UL, ts+80L, ts+80L );
  fd_gui_fec_event_iter_begin( gui, &ei, ts+70L, ts+80L );
  for( ulong i=0UL; i<2UL; i++ ) {
    FD_TEST( fd_gui_shred_event_iter_next( &ei ) );
    FD_TEST( ei.event.idx==USHORT_MAX && ei.event.event==FD_GUI_SLOT_SHRED_SHRED_SLOT_COMPLETE );
    FD_TEST( ei.event.timestamp==ts+70L+10L*(long)i );
  }
  FD_TEST( !fd_gui_shred_event_iter_next( &ei ) );
  fd_gui_shred_event_iter_end( &ei );
  for( int earlier=0; earlier<2; earlier++ ) {
    if( earlier ) fd_gui_shred_event_slot_complete( gui, 101UL, ts+60L, ts+90L );
    FD_TEST( !fd_gui_printf_timeline_query_fec_events( gui, "timeline", ts+60L, ts+81L, 7UL ) );
    json=timeline_response( gui );
    FD_TEST( test_json_count( timeline_value( json, "idx" ) )==2+earlier );
    FD_TEST( (test_json_kind( test_json_index( timeline_value( json, "idx" ), 0 ) )==FD_JTOK_NULL) );
    FD_TEST( test_json_string_eq( timeline_value( json, "reference_ts" ), earlier ? "10000000060" : "10000000070" ) );

    FD_TEST( !fd_gui_printf_timeline_query_fec_events( gui, "timeline", ts+71L, ts+81L, 7UL ) );
    json=timeline_response( gui );
    FD_TEST( test_json_count( timeline_value( json, "idx" ) )==1 );

    FD_TEST( !fd_gui_printf_timeline_query_shreds( gui, "timeline", ts+60L, ts+81L, 7UL ) );
    json=timeline_response( gui );
    FD_TEST( test_json_count( timeline_value( json, "idx" ) )==2+earlier );

  }
  put_slot( gui, 101UL, ts+80L );
  fd_gui_hist_slot_key_t key = { .slot=102UL, .bank_seq=ULONG_MAX };
  ulong budget = ULONG_MAX;
  int drained;
  FD_TEST( !fd_gui_store_kv_evict( gui->db, FD_GUI_HIST_SLOT, &key, &budget, &drained ) );
  FD_TEST( !fd_gui_slot_get_any( gui, 101UL ) );
  fd_gui_fec_event_staged_append( gui, 101UL, 2UL, FD_GUI_SLOT_SHRED_REPAIR_REQUEST, ts+90L );
  FD_TEST( gui->shreds.dropped_fec_event_cnt==2UL );
  FD_TEST( !fd_gui_shred_event_pool_used( gui->shreds.fec_event_pool ) );
  day = fd_gui_timeline_day_get( gui, 0UL );
  FD_TEST( day && fd_gui_timeline_field_get( day, 0, FD_GUI_TIMELINE_FIELD_PUBLISHED, 40UL )==128UL );

  FD_TEST( fd_http_server_delete( fd_http_server_leave( gui->http ) )==http_mem );
  free( http_mem );
  gui->http = NULL;
  FD_LOG_NOTICE(( "test_timeline_staging: ok" ));
}

static void
test_timeline_closure_overflow( fd_gui_t * gui ) {
  long ts=sec_ns( 10UL );
  for( ulong slot=1UL; slot<=FD_GUI_SHRED_EVENT_POOL_MAX; slot++ )
    fd_gui_shred_event_slot_complete( gui, slot, ts, ts );
  FD_TEST( gui->shreds.closed_slot_cnt==FD_GUI_SHRED_EVENT_POOL_MAX && !gui->shreds.closed_full );
  fd_gui_shred_event_slot_complete( gui, 70000UL, ts, ts );
  FD_TEST( gui->shreds.closed_full && gui->shreds.closed_overflow_max==70000UL );
  ulong invalid[]={ (ulong)UINT_MAX+1UL, (ulong)LONG_MAX, ULONG_MAX };
  ulong appends=fd_gui_store_metrics( gui->db )->ts_appends[FD_GUI_HIST_SHRED_EVENTS];
  for( ulong i=0UL; i<3UL; i++ ) fd_gui_shred_event_slot_complete( gui, invalid[i], ts, ts );
  FD_TEST( gui->shreds.closed_overflow_max==70000UL );
  FD_TEST( fd_gui_store_metrics( gui->db )->ts_appends[FD_GUI_HIST_SHRED_EVENTS]==appends );
  fd_gui_shred_event_slot_complete( gui, 80000UL, ts, ts );
  fd_gui_shred_event_staged_advance( gui, 65536UL, ts );
  FD_TEST( !gui->shreds.closed_slot_cnt && gui->shreds.closed_full && gui->shreds.closed_overflow_max==80000UL );
  fd_gui_shred_event_slot_complete( gui, 90000UL, ts, ts );
  put_slot( gui, 70000UL, ts );
  put_slot( gui, 80000UL, ts );
  put_slot( gui, 90000UL, ts );
  fd_gui_hist_slot_key_t key={ .slot=90001UL, .bank_seq=ULONG_MAX };
  ulong budget=ULONG_MAX;
  int drained;
  FD_TEST( !fd_gui_store_kv_evict( gui->db, FD_GUI_HIST_SLOT, &key, &budget, &drained ) );
  FD_TEST( !fd_gui_slot_get_any( gui, 90000UL ) );
  ulong cutoffs[]={ 70001UL, 80001UL, 90000UL, 90001UL, 60000UL };
  for( ulong i=0UL; i<5UL; i++ ) {
    fd_gui_shred_event_staged_advance( gui, cutoffs[i], ts );
    FD_TEST( gui->shreds.closed_full==(i<3UL) );
    FD_TEST( gui->shreds.closed_overflow_max==90000UL );
    ulong slots[]={ 1UL, 70000UL, 80000UL, 90000UL, 100000UL+i };
    for( ulong j=0UL; j<5UL; j++ ) {
      fd_gui_shred_event_staged_append( gui, slots[j], 32UL, FD_GUI_SLOT_SHRED_REPAIR_REQUEST, ts );
      fd_gui_fec_event_staged_append( gui, slots[j], 1UL, FD_GUI_SLOT_SHRED_REPAIR_REQUEST, ts );
      int rc=fd_gui_fec_completion_staged_append( gui, slots[j], ts, 32UL, 16UL, 8UL, 1 );
      FD_TEST( rc==(i>=3UL && j==4UL) );
    }
    ulong used=i<3UL ? 0UL : i-2UL;
    FD_TEST( fd_gui_shred_event_pool_used( gui->shreds.shred_event_pool )==used );
    FD_TEST( fd_gui_shred_event_pool_used( gui->shreds.fec_event_pool )==used );
    FD_TEST( fd_gui_fec_completion_pool_used( gui->shreds.completion_pool )==used );
  }
  FD_TEST( gui->shreds.closed_before_slot==90001UL );
  FD_LOG_NOTICE(( "test_timeline_closure_overflow: 65535 keys, partial cleanup, overflow high-water recovery: ok" ));
}

static void
test_timeline_completion_overflow( test_store_t * s ) {
  fd_gui_t * gui=s->gui;
  long ts=sec_ns( 10UL );
  gui->shreds.completion_pool=fd_gui_fec_completion_pool_join( fd_gui_fec_completion_pool_new( s->completion_pool_mem, 2UL ) );
  fd_gui_timeline_handle_fec( gui, 100UL, 1, ts+1L, 32UL, 16UL, 8UL, ts );
  fd_gui_timeline_handle_fec( gui, 100UL, 1, ts+2L, 32UL, 16UL, 8UL, ts );
  FD_TEST( fd_gui_fec_completion_pool_used( gui->shreds.completion_pool )==2UL );
  for( ulong n=2UL; n<=4UL; n++ ) {
    fd_gui_timeline_handle_fec( gui, 100UL, 7, ts+1L, 32UL, 16UL, 8UL, ts );
    fd_gui_timeline_day_t const * day=fd_gui_timeline_day_get( gui, 0UL );
    FD_TEST( day );
    for( int g=0; g<7; g++ ) {
      ulong idx=(ulong)ts/fd_gui_timeline_stored_granularity_ns[g];
      FD_TEST( fd_gui_timeline_field_get( day, g, FD_GUI_TIMELINE_FIELD_TURBINE, idx )==32UL*n );
      FD_TEST( fd_gui_timeline_field_get( day, g, FD_GUI_TIMELINE_FIELD_REPAIR, idx )==16UL*n );
      FD_TEST( fd_gui_timeline_field_get( day, g, FD_GUI_TIMELINE_FIELD_RECONSTRUCTED, idx )==8UL*n );
      FD_TEST( fd_gui_timeline_field_get( day, g, FD_GUI_TIMELINE_FIELD_PUBLISHED, idx )==64UL*n );
    }
    if( n<4UL ) fd_gui_timeline_handle_fec( gui, 100UL, 1, ts+3L, 32UL, 16UL, 8UL, ts );
  }
  FD_TEST( gui->shreds.dropped_completion_cnt==2UL );
  FD_TEST( fd_gui_fec_completion_staged_append( gui, 100UL, ts+3L, 32UL, 16UL, 8UL, 1 )==-1 );
  fd_gui_shred_event_staged_advance( gui, 101UL, ts );
  FD_TEST( count_ts( gui, FD_GUI_HIST_FEC_COMPLETIONS, 100UL )==1UL );
  fd_gui_fec_completion_iter_t it;
  fd_gui_fec_completion_iter_begin( gui, &it, ts, ts+10L );
  for( long i=1L; i<=2L; i++ ) FD_TEST( fd_gui_fec_completion_iter_next( &it ) && it.event.timestamp==ts+i );
  FD_TEST( !fd_gui_fec_completion_iter_next( &it ) );
  fd_gui_fec_completion_iter_end( &it );
  fd_gui_timeline_handle_fec( gui, 100UL, 1, ts+4L, 32UL, 16UL, 8UL, ts );
  fd_gui_timeline_handle_fec( gui, 101UL, 1, ts+4L, 65UL, 16UL, 8UL, ts );
  FD_TEST( fd_gui_timeline_field_get( fd_gui_timeline_day_get( gui, 0UL ), 0, FD_GUI_TIMELINE_FIELD_PUBLISHED, 40UL )==256UL );
  fd_gui_fec_completion_staged_t * pool=gui->shreds.completion_pool;
  fd_gui_fec_completion_dlist_t * list=gui->shreds.completion_list;
  gui->shreds.completion_pool=NULL;
  FD_TEST( fd_gui_fec_completion_staged_append( gui, 101UL, ts+4L, 32UL, 16UL, 8UL, 1 )==-1 );
  fd_gui_timeline_handle_fec( gui, 101UL, 1, ts+4L, 32UL, 16UL, 8UL, ts );
  gui->shreds.completion_pool=pool;
  gui->shreds.completion_list=NULL;
  FD_TEST( fd_gui_fec_completion_staged_append( gui, 101UL, ts+5L, 32UL, 16UL, 8UL, 1 )==-1 );
  fd_gui_timeline_handle_fec( gui, 101UL, 1, ts+5L, 32UL, 16UL, 8UL, ts );
  gui->shreds.completion_list=list;
  void * db=gui->db;
  void * hist=gui->hist;
  gui->db=NULL;
  FD_TEST( !fd_gui_fec_completion_staged_append( gui, 101UL, ts+6L, 32UL, 16UL, 8UL, 1 ) );
  fd_gui_timeline_handle_fec( gui, 101UL, 1, ts+6L, 32UL, 16UL, 8UL, ts );
  gui->db=db;
  gui->hist=NULL;
  FD_TEST( !fd_gui_fec_completion_staged_append( gui, 101UL, ts+6L, 32UL, 16UL, 8UL, 1 ) );
  fd_gui_timeline_handle_fec( gui, 101UL, 1, ts+6L, 32UL, 16UL, 8UL, ts );
  gui->hist=hist;
  FD_TEST( !fd_gui_fec_completion_pool_used( pool ) );
  FD_TEST( fd_gui_timeline_field_get( fd_gui_timeline_day_get( gui, 0UL ), 0, FD_GUI_TIMELINE_FIELD_PUBLISHED, 40UL )==384UL );
  FD_LOG_NOTICE(( "test_timeline_completion_overflow: ok" ));
}

static void
test_timeline_ancestry( fd_gui_t * gui ) {
  void * http_mem = timeline_http_open( gui );
  long const ts = sec_ns( 10UL );
  /* Fine slot aggregates require overlapping transaction and FEC history. */
  append_replay_txn( gui, ts, ts, 100UL );
  fd_gui_fec_completion_batch_t completion = {
    .slot=100UL, .insert_time_ns=ts, .event_cnt=1U, .events={{ .timestamp=ts }}
  };
  FD_TEST( !fd_gui_hist_ts_append( gui, FD_GUI_HIST_FEC_COMPLETIONS, &completion ) );
  FD_TEST( fd_epoch_schedule_derive( &gui->epoch.epoch_schedule, 1024UL, 1024UL, 0 ) );
  gui->epoch.has_epoch_schedule = 1;
  gui->epoch.current_epoch = 0UL;
  gui->summary.is_alpenglow = 1;
  put_epoch( gui, 0UL, 0UL, 1024UL );
  fd_gui_epoch_t * epoch = fd_gui_epoch( gui, 0UL );
  epoch->timeline_slot_lo_idx = ULONG_MAX;
  epoch->timeline_slot_hi_idx = ULONG_MAX;
  put_slot( gui, 100UL, ts );
  fd_gui_slot_t * slot = fd_gui_slot_get( gui, 100UL, BANK_SEQ );
  slot->parent_slot = ULONG_MAX;
  slot->parent_bank_seq = ULONG_MAX;
  put_slot( gui, 103UL, ts+10000001L );
  slot = fd_gui_slot_get( gui, 103UL, BANK_SEQ );
  slot->parent_slot = 100UL;
  slot->parent_bank_seq = BANK_SEQ;
  slot->mine = 1;
  fd_gui_handle_oc_advanced( gui, 103UL, BANK_SEQ, ts+10000001L );
  FD_TEST( gui->timeline_skipped_slot_watermark==ULONG_MAX );
  fd_gui_timeline_skipped_update( gui, slot, ts+10000001L );
  FD_TEST( gui->timeline_skipped_slot_watermark==103UL );
  FD_TEST( gui->timeline_skipped_bank_seq_watermark==BANK_SEQ );
  FD_TEST( gui->timeline_skipped_coverage_start_ns==ts );
  FD_TEST( gui->timeline_skipped_coverage_end_ns==ts+10000001L );
  fd_gui_timeline_slot_row_t rows[4];
  ulong cnt;
  FD_TEST( !fd_gui_timeline_slots_collect( gui, ts, ts+10000001L, rows, 4UL, &cnt ) );
  FD_TEST( cnt==3UL );
  for( ulong i=0UL; i<3UL; i++ ) {
    FD_TEST( rows[i].slot==101UL+i );
    FD_TEST( rows[i].start_ns==ts+(long)(((uint128)i*10000001UL)/3UL) );
    FD_TEST( rows[i].end_ns==ts+(long)(((uint128)(i+1UL)*10000001UL)/3UL) );
    FD_TEST( rows[i].skipped==(i<2UL) && rows[i].mine==(i==2UL) );
  }
  FD_TEST( fd_gui_timeline_slots_collect( gui, ts, ts+10000001L, rows, 2UL, &cnt )==1 );
  FD_TEST( !fd_gui_timeline_slots_collect( gui, ts+3333333L, ts+6666667L, rows, 4UL, &cnt ) );
  FD_TEST( cnt==1UL && rows[0].slot==102UL );
  fd_gui_timeline_day_t const * day = fd_gui_timeline_day_get( gui, 0UL );
  FD_TEST( day && fd_gui_timeline_field_get( day, 0, FD_GUI_TIMELINE_FIELD_SKIPPED, 40UL )==2UL );
  fd_gui_timeline_skipped_update( gui, fd_gui_slot_get( gui, 103UL, BANK_SEQ ), ts+10000001L );
  FD_TEST( fd_gui_timeline_field_get( day, 0, FD_GUI_TIMELINE_FIELD_SKIPPED, 40UL )==2UL );
  FD_TEST( !fd_gui_printf_timeline_query_agg( gui, "query_agg_slots", "1ms", 0UL, ts, 10UL, 7UL ) );
  test_json_t json = timeline_response( gui );
  FD_TEST( test_json_ulong( test_json_index( timeline_value( json, "skipped" ), 1 ) )==1UL );
  FD_TEST( test_json_ulong( test_json_index( timeline_value( json, "skipped" ), 5 ) )==1UL );
  FD_TEST( (test_json_kind( test_json_index( timeline_value( json, "skipped" ), 0 ) )==FD_JTOK_INT) );


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
  FD_TEST( fd_gui_timeline_field_get( day, 0, FD_GUI_TIMELINE_FIELD_SKIPPED, 40UL )==4UL );

  fd_gui_hist_slot_key_t key = { .slot=104UL, .bank_seq=ULONG_MAX };
  ulong budget = ULONG_MAX;
  int drained;
  FD_TEST( !fd_gui_store_kv_evict( gui->db, FD_GUI_HIST_SLOT, &key, &budget, &drained ) );
  FD_TEST( !fd_gui_slot_get( gui, 103UL, BANK_SEQ ) );
  FD_TEST( !fd_gui_printf_timeline_query_agg( gui, "query_agg_slots", "1ms", 0UL, ts, 10UL, 7UL ) );
  json = timeline_response( gui );
  for( int i=0; i<10; i++ ) FD_TEST( (test_json_kind( test_json_index( timeline_value( json, "skipped" ), i ) )==FD_JTOK_NULL) );

  key.slot=107UL;
  FD_TEST( !fd_gui_store_kv_evict( gui->db, FD_GUI_HIST_SLOT, &key, &budget, &drained ) );
  FD_TEST( !fd_gui_slot_get( gui, 106UL, BANK_SEQ ) );
  put_slot( gui, 109UL, ts+sec_ns( 1UL ) );
  slot=fd_gui_slot_get( gui, 109UL, BANK_SEQ );
  slot->parent_slot=106UL;
  slot->parent_bank_seq=BANK_SEQ;
  put_slot( gui, 112UL, ts+sec_ns( 2UL ) );
  slot=fd_gui_slot_get( gui, 112UL, BANK_SEQ );
  slot->parent_slot=109UL;
  slot->parent_bank_seq=1UL;
  fd_gui_timeline_skipped_update( gui, slot, ts+sec_ns( 2UL ) );
  FD_TEST( gui->timeline_skipped_slot_watermark==106UL );
  slot->parent_bank_seq=BANK_SEQ;
  gui->summary.slot_rooted=106UL;
  fd_gui_handle_root_advanced( gui, 112UL, BANK_SEQ, ts+sec_ns( 2UL ) );
  FD_TEST( gui->timeline_skipped_slot_watermark==112UL && gui->summary.slot_rooted==112UL );
  FD_TEST( gui->timeline_skipped_coverage_start_ns==ts+sec_ns( 1UL ) );
  FD_TEST( gui->timeline_skipped_coverage_end_ns==ts+sec_ns( 2UL ) );
  FD_TEST( fd_gui_timeline_field_get( fd_gui_timeline_day_get( gui, 0UL ), 0, FD_GUI_TIMELINE_FIELD_SKIPPED, 40UL )==4UL );
  FD_TEST( !fd_gui_timeline_slots_collect( gui, ts, ts+10000001L, rows, 4UL, &cnt ) && cnt==3UL );
  FD_TEST( !fd_gui_timeline_slots_collect( gui, ts+20000000L, ts+sec_ns( 1UL ), rows, 4UL, &cnt ) && !cnt );
  FD_TEST( !fd_gui_timeline_slots_collect( gui, ts+sec_ns( 1UL ), ts+sec_ns( 2UL ), rows, 4UL, &cnt ) && cnt==3UL );
  FD_TEST( rows[0].slot==110UL && rows[0].skipped && rows[2].slot==112UL && !rows[2].skipped );
  FD_TEST( !fd_gui_printf_timeline_query_agg( gui, "query_agg_slots", "1ms", 0UL, ts+20000000L, 10UL, 7UL ) );
  json=timeline_response( gui );
  for( int i=0; i<10; i++ ) FD_TEST( (test_json_kind( test_json_index( timeline_value( json, "skipped" ), i ) )==FD_JTOK_NULL) );

  gui->summary.is_alpenglow=0;
  put_slot( gui, 110UL, ts+sec_ns( 1UL )+333333333L );
  slot=fd_gui_slot_get( gui, 110UL, BANK_SEQ );
  slot->parent_slot=109UL;
  slot->parent_bank_seq=BANK_SEQ;
  gui->summary.slot_rooted=ULONG_MAX;
  gui->summary.slot_tower=110UL;
  gui->summary.slot_tower_bank_seq=BANK_SEQ;
  gui->summary.slot_optimistically_confirmed=112UL;
  FD_TEST( fd_gui_slot_get_canon( gui, 110UL )==slot );
  fd_gui_handle_oc_advanced( gui, 110UL, BANK_SEQ, ts+sec_ns( 2UL ) );
  FD_TEST( gui->timeline_skipped_slot_watermark==112UL );
  FD_TEST( !fd_gui_timeline_slots_collect( gui, ts+sec_ns( 1UL ), ts+sec_ns( 2UL ), rows, 4UL, &cnt ) && cnt==3UL );
  FD_TEST( rows[0].skipped && !rows[2].skipped );

  long prior=ts+sec_ns( 1UL );
  fd_gui_timeline_handle_txn( gui, 112UL, prior, 1UL, 60000000UL, 5000UL, 2UL, 3UL, 0, 1, ts+sec_ns( 2UL ) );
  FD_TEST( !fd_gui_printf_timeline_query_agg( gui, "query_agg_slots", "250ms", 7UL, prior, 1UL, 7UL ) );
  json=timeline_response( gui );
  FD_TEST( test_json_ulong( test_json_index( timeline_value( json, "skipped" ), 0 ) )==1UL );

  FD_TEST( !fd_gui_printf_timeline_query_agg( gui, "query_agg_revenue", "250ms", 7UL, prior, 1UL, 7UL ) );
  json=timeline_response( gui );
  FD_TEST( test_json_string_eq( test_json_index( timeline_value( json, "txn_fees" ), 0 ), "5000" ) );

  FD_TEST( !fd_gui_store_ts_evict( gui->db, FD_GUI_HIST_TIMELINE_DAY, ULONG_MAX, &budget, &drained ) );
  FD_TEST( !fd_gui_timeline_day_get( gui, 0UL ) && gui->timeline_day_max==0UL );
  fd_gui_timeline_handle_txn( gui, 112UL, prior+250000000L, 1UL, 60000000UL, 7UL, 8UL, 9UL, 0, 1, ts+sec_ns( 2UL ) );
  FD_TEST( !fd_gui_timeline_day_get( gui, 0UL ) );
  FD_TEST( !count_ts( gui, FD_GUI_HIST_TIMELINE_DAY, ULONG_MAX ) );
  for( int i=0; i<2; i++ ) {
    FD_TEST( !fd_gui_printf_timeline_query_agg( gui, i ? "query_agg_slots" : "query_agg_revenue", "250ms", 7UL, prior, 2UL, 7UL ) );
    json=timeline_response( gui );
    for( int j=0; j<2; j++ ) FD_TEST( (test_json_kind( test_json_index( timeline_value( json, i ? "skipped" : "txn_fees" ), j ) )==FD_JTOK_NULL) );

  }
  fd_gui_timeline_handle_txn( gui, 113UL, FD_GUI_TIMELINE_DAY_NS, 1UL, 60000000UL, 7UL, 8UL, 9UL, 0, 1, FD_GUI_TIMELINE_DAY_NS );
  FD_TEST( fd_gui_timeline_day_get( gui, 1UL ) && !fd_gui_timeline_day_get( gui, 0UL ) );
  FD_TEST( fd_http_server_delete( fd_http_server_leave( gui->http ) )==http_mem );
  free( http_mem );
  gui->http = NULL;
  FD_LOG_NOTICE(( "test_timeline_ancestry: recovery, regression and lost-current-day: ok" ));
}

static void
test_timeline_day_recovery( fd_gui_t * gui ) {
  void * http_mem=timeline_http_open( gui );
  FD_TEST( fd_epoch_schedule_derive( &gui->epoch.epoch_schedule, 1024UL, 1024UL, 0 ) );
  gui->epoch.has_epoch_schedule=1;
  gui->epoch.current_epoch=0UL;
  gui->summary.is_alpenglow=1;
  gui->summary.slot_rooted=ULONG_MAX;
  put_epoch( gui, 0UL, 0UL, 1024UL );
  fd_gui_epoch_t * epoch=fd_gui_epoch( gui, 0UL );
  epoch->timeline_slot_lo_idx=ULONG_MAX;
  epoch->timeline_slot_hi_idx=ULONG_MAX;
  long ts=sec_ns( 10UL );
  put_slot( gui, 100UL, ts );
  fd_gui_slot_t * slot=fd_gui_slot_get( gui, 100UL, BANK_SEQ );
  slot->parent_slot=ULONG_MAX;
  slot->parent_bank_seq=ULONG_MAX;
  put_slot( gui, 103UL, ts+sec_ns( 1UL ) );
  slot=fd_gui_slot_get( gui, 103UL, BANK_SEQ );
  slot->parent_slot=100UL;
  slot->parent_bank_seq=BANK_SEQ;
  fd_gui_handle_root_advanced( gui, 103UL, BANK_SEQ, ts+sec_ns( 1UL ) );
  FD_TEST( gui->timeline_skipped_slot_watermark==103UL );
  FD_TEST( fd_gui_timeline_field_get( fd_gui_timeline_day_get( gui, 0UL ), 6, FD_GUI_TIMELINE_FIELD_SKIPPED, 0UL )==2UL );
  ulong budget=ULONG_MAX;
  int drained;
  FD_TEST( !fd_gui_store_ts_evict( gui->db, FD_GUI_HIST_TIMELINE_DAY, ULONG_MAX, &budget, &drained ) );
  FD_TEST( fd_gui_slot_get( gui, 100UL, BANK_SEQ ) && fd_gui_slot_get( gui, 103UL, BANK_SEQ ) );
  ulong slots[]={106UL,109UL,110UL};
  ulong parents[]={103UL,106UL,109UL};
  for( ulong i=0UL; i<3UL; i++ ) {
    long now=FD_GUI_TIMELINE_DAY_NS+sec_ns( i+1UL );
    put_slot( gui, slots[i], now );
    slot=fd_gui_slot_get( gui, slots[i], BANK_SEQ );
    slot->parent_slot=parents[i];
    slot->parent_bank_seq=BANK_SEQ;
    fd_gui_handle_root_advanced( gui, slots[i], BANK_SEQ, now );
    FD_TEST( gui->timeline_skipped_slot_watermark==slots[i] );
    FD_TEST( gui->timeline_skipped_coverage_start_ns==FD_GUI_TIMELINE_DAY_NS+sec_ns( 1UL ) );
    FD_TEST( !fd_gui_timeline_day_get( gui, 0UL ) && fd_gui_timeline_day_get( gui, 1UL ) );
  }
  FD_TEST( fd_gui_timeline_field_get( fd_gui_timeline_day_get( gui, 1UL ), 6, FD_GUI_TIMELINE_FIELD_SKIPPED, 0UL )==2UL );
  fd_gui_timeline_slot_row_t rows[8];
  ulong cnt;
  FD_TEST( !fd_gui_timeline_slots_collect( gui, ts, ts+sec_ns( 1UL ), rows, 8UL, &cnt ) && cnt==3UL );
  FD_TEST( rows[0].skipped && !rows[2].skipped );
  FD_TEST( !fd_gui_timeline_slots_collect( gui, ts+sec_ns( 1UL ), FD_GUI_TIMELINE_DAY_NS+sec_ns( 1UL ), rows, 8UL, &cnt ) && !cnt );
  FD_TEST( !fd_gui_timeline_slots_collect( gui, FD_GUI_TIMELINE_DAY_NS+sec_ns( 1UL ), FD_GUI_TIMELINE_DAY_NS+sec_ns( 3UL ), rows, 8UL, &cnt ) && cnt==4UL );
  FD_TEST( rows[0].slot==107UL && rows[0].skipped && rows[3].slot==110UL && !rows[3].skipped );
  for( int fine=0; fine<2; fine++ ) {
    FD_TEST( !fd_gui_printf_timeline_query_agg( gui, "query_agg_slots", fine ? "1ms" : "250ms", fine ? 0UL : 7UL,
      FD_GUI_TIMELINE_DAY_NS, fine ? 1000UL : 4UL, 7UL ) );
    test_json_t json=timeline_response( gui );
    test_json_t skipped=timeline_value( json, "skipped" );
    for( int row=0; row<test_json_count( skipped ); row++ ) FD_TEST( (test_json_kind( test_json_index( skipped, row ) )==FD_JTOK_NULL) );

  }
  FD_TEST( !fd_gui_printf_timeline_query_agg( gui, "query_agg_slots", "250ms", 7UL, FD_GUI_TIMELINE_DAY_NS+sec_ns( 1UL ), 8UL, 7UL ) );
  test_json_t json=timeline_response( gui );
  FD_TEST( test_json_ulong( test_json_index( timeline_value( json, "skipped" ), 0 ) )==1UL );
  FD_TEST( test_json_ulong( test_json_index( timeline_value( json, "skipped" ), 2 ) )==1UL );
  FD_TEST( (test_json_kind( test_json_index( timeline_value( json, "skipped" ), 7 ) )==FD_JTOK_INT) );

  FD_TEST( fd_http_server_delete( fd_http_server_leave( gui->http ) )==http_mem );
  free( http_mem );
  gui->http=NULL;
  FD_LOG_NOTICE(( "test_timeline_day_recovery: day-only eviction, intact ancestry, consecutive day-1 roots: ok" ));
}

static void
test_timeline_day_cache( fd_gui_t * gui ) {
  void * http_mem=timeline_http_open( gui );
  ulong capacity=FD_GUI_STORE_REGION_SZ/fd_ulong_align_up( sizeof(fd_gui_timeline_day_t), 8UL );
  FD_TEST( capacity==1UL );
  FD_TEST( (2UL<<30)>=fd_gui_store_min_overhead_bytes()+40UL*FD_GUI_STORE_REGION_SZ );
  long now=39L*FD_GUI_TIMELINE_DAY_NS;
  for( ulong d=0UL; d<40UL; d++ )
    fd_gui_timeline_handle_txn( gui, 100UL+d, (long)d*FD_GUI_TIMELINE_DAY_NS, 1UL, 60000000UL, d+1UL, 0UL, 0UL, 0, 1, now+sec_ns( d ) );
  FD_TEST( count_ts( gui, FD_GUI_HIST_TIMELINE_DAY, ULONG_MAX )==40UL );
  memset( &gui->timeline_day_cache, 0, sizeof(gui->timeline_day_cache) );
  fd_gui_store_metrics_t const * metrics=fd_gui_store_metrics( gui->db );
  ulong reads=metrics->ts_reads[FD_GUI_HIST_TIMELINE_DAY];
  ulong records=metrics->ts_read_records[FD_GUI_HIST_TIMELINE_DAY];
  for( ulong i=0UL; i<10000UL; i++ ) {
    fd_gui_timeline_day_t const * day=fd_gui_timeline_day_get( gui, 39UL );
    FD_TEST( day && day->insert_time_ns==now+sec_ns( 39UL ) && day->end_time_ns==40L*FD_GUI_TIMELINE_DAY_NS );
    FD_TEST( fd_gui_timeline_field_get( day, 0, FD_GUI_TIMELINE_FIELD_TXN_FEES, 0UL )==40UL );
  }
  FD_TEST( metrics->ts_reads[FD_GUI_HIST_TIMELINE_DAY]-reads==1UL );
  FD_TEST( metrics->ts_read_records[FD_GUI_HIST_TIMELINE_DAY]-records==40UL );
  gui->timeline_skipped_coverage_start_ns=0L;
  gui->timeline_skipped_coverage_end_ns=40L*FD_GUI_TIMELINE_DAY_NS;
  for( int query=0; query<3; query++ ) {
    memset( &gui->timeline_day_cache, 0, sizeof(gui->timeline_day_cache) );
    ulong before_reads=metrics->ts_reads[FD_GUI_HIST_TIMELINE_DAY];
    ulong before_records=metrics->ts_read_records[FD_GUI_HIST_TIMELINE_DAY];
    char const * key=query==0 ? "query_agg_compute" : query==1 ? "query_agg_slots" : "query_agg_revenue";
    FD_TEST( !fd_gui_printf_timeline_query_agg( gui, key, query ? "1d" : "250ms", query ? 26UL : 7UL, 0L, 10000UL, 7UL ) );
    test_json_t json=timeline_response( gui );
    test_json_t values=timeline_value( json, query==0 ? "compute_units" : query==1 ? "start_slot" : "txn_fees" );
    FD_TEST( test_json_count( values )==10000 );
    for( int d=0; d<(query ? 40 : 1); d++ ) {
      test_json_t value=test_json_index( values, d );
      if( query==2 ) {
        char expected[32];
        fd_cstr_printf_check( expected, sizeof(expected), NULL, "%d", d+1 );
        FD_TEST( test_json_string_eq( value, expected ) );
      } else FD_TEST( (test_json_kind( value )==FD_JTOK_INT) && test_json_ulong( value )==(query ? 100UL+(ulong)d : 1UL) );
    }
    FD_TEST( (test_json_kind( test_json_index( values, 40 ) )==FD_JTOK_NULL) );
    FD_TEST( test_json_string_eq( timeline_value( json, "available_start_ns" ), "0" ) );
    FD_TEST( test_json_string_eq( timeline_value( json, "available_end_ns" ), "3456000000000000" ) );
    if( query==1 ) FD_TEST( (test_json_kind( test_json_index( timeline_value( json, "skipped" ), 0 ) )==FD_JTOK_INT) );

    FD_TEST( metrics->ts_reads[FD_GUI_HIST_TIMELINE_DAY]-before_reads==1UL );
    FD_TEST( metrics->ts_read_records[FD_GUI_HIST_TIMELINE_DAY]-before_records==40UL );
  }
  ulong scans=metrics->ts_reads[FD_GUI_HIST_TIMELINE_DAY]-reads;
  ulong scanned=metrics->ts_read_records[FD_GUI_HIST_TIMELINE_DAY]-records;
  FD_TEST( fd_gui_timeline_day_get( gui, 0UL ) && fd_gui_timeline_day_get( gui, 39UL ) );
  ulong budget=1UL;
  int drained;
  FD_TEST( !fd_gui_store_ts_evict( gui->db, FD_GUI_HIST_TIMELINE_DAY, ULONG_MAX, &budget, &drained ) );
  FD_TEST( !fd_gui_timeline_day_get( gui, 0UL ) && fd_gui_timeline_day_get( gui, 39UL ) );
  fd_gui_timeline_handle_txn( gui, 140UL, 40L*FD_GUI_TIMELINE_DAY_NS, 1UL, 60000000UL, 41UL, 0UL, 0UL, 0, 1, 40L*FD_GUI_TIMELINE_DAY_NS );
  FD_TEST( !fd_gui_timeline_day_get( gui, 0UL ) && fd_gui_timeline_day_get( gui, 40UL ) );
  FD_TEST( count_ts( gui, FD_GUI_HIST_TIMELINE_DAY, ULONG_MAX )==40UL );
  FD_TEST( fd_http_server_delete( fd_http_server_leave( gui->http ) )==http_mem );
  free( http_mem );
  gui->http=NULL;
  FD_LOG_NOTICE(( "test_timeline_day_cache: %lu-byte days, %lu per region, 40 retained; 10000 hot lookups and three cold 10000-bucket queries: %lu scans, %lu records; ok",
                  sizeof(fd_gui_timeline_day_t), capacity, scans, scanned ));
}

static void
test_timeline_batch_parity( fd_gui_t * gui ) {
  long ts=sec_ns( 11UL );
  fd_gui_store_replay_txn_t txns[128];
  fd_gui_txn_batch_work_t oracle[128];
  ulong appended=0UL;
  for( ulong fixture=0UL; fixture<4UL; fixture++ ) {
    ulong target=fixture==0UL ? 17UL : fixture==1UL ? 5UL : 33UL;
    ulong count=4UL;
    long start=ts;
    for( ulong i=0UL; i<128UL; i++ ) {
      start+=fixture==3UL ? 1000L+(long)(i*17UL%23UL)*100L : 1000L;
      txns[i]=(fd_gui_store_replay_txn_t){
        .insert_time_ns=ts, .completion_time_ns=start+800L, .slot=101UL+fixture, .txn_idx=i,
        .txn_exec_idx=i%target, .sigverify_start_ns=start, .sigverify_end_ns=start+800L,
        .load_start_ns=start+100L, .check_start_ns=start+200L, .exec_start_ns=start+300L,
        .commit_start_ns=start+600L, .commit_end_ns=start+700L, .block_compute_unit_limit=ULONG_MAX
      };
      FD_TEST( !fd_gui_hist_ts_append( gui, FD_GUI_HIST_REPLAY_TXN, &txns[i] ) );
    }
    for( ulong i=0UL; i<4UL; i++ ) oracle[i]=(fd_gui_txn_batch_work_t){
      .first=32UL*i, .cnt=32UL, .representative_txn_idx=32UL*i,
      .start_ns=txns[32UL*i].sigverify_start_ns, .end_ns=txns[32UL*i+31UL].sigverify_end_ns
    };
    while( count<target ) {
      ulong best=ULONG_MAX;
      for( ulong i=0UL; i<count; i++ ) {
        if( oracle[i].cnt<=1UL ) continue;
        long span=fd_long_sat_sub( oracle[i].end_ns, oracle[i].start_ns );
        long old=best==ULONG_MAX ? LONG_MIN : fd_long_sat_sub( oracle[best].end_ns, oracle[best].start_ns );
        if( best==ULONG_MAX || span>old || (span==old && (oracle[i].cnt>oracle[best].cnt ||
            (oracle[i].cnt==oracle[best].cnt && oracle[i].representative_txn_idx<oracle[best].representative_txn_idx))) ) best=i;
      }
      FD_TEST( best!=ULONG_MAX );
      ulong off=1UL;
      long gap=LONG_MIN;
      for( ulong k=1UL; k<oracle[best].cnt; k++ ) {
        long next=fd_long_sat_sub( txns[oracle[best].first+k].sigverify_start_ns, txns[oracle[best].first+k-1UL].sigverify_end_ns );
        ulong dist=fd_long_abs( (long)(2UL*k)-(long)oracle[best].cnt );
        ulong olddist=fd_long_abs( (long)(2UL*off)-(long)oracle[best].cnt );
        if( next>gap || (next==gap && dist<olddist) ) { gap=next; off=k; }
      }
      oracle[count]=oracle[best];
      oracle[count].first+=off;
      oracle[count].cnt-=off;
      oracle[best].cnt=off;
      oracle[best].end_ns=txns[oracle[best].first+off-1UL].sigverify_end_ns;
      oracle[count].start_ns=txns[oracle[count].first].sigverify_start_ns;
      oracle[count].representative_txn_idx=oracle[count].first;
      count++;
    }
    gui->slot_txn_scratch.max=128UL;
    FD_TEST( !fd_gui_materialize_replay_txn_batches( gui, 101UL+fixture, ts, ts+sec_ns( 1UL ), 128UL, ts ) );
    appended+=target;
    FD_TEST( count_ts( gui, FD_GUI_HIST_REPLAY_TXN_BATCH, ULONG_MAX )==appended );
    for( ulong i=0UL; i<count; i++ ) {
      fd_gui_store_replay_txn_batch_t const * rec=&gui->timeline_scratch.materialize.records[i];
      FD_TEST( rec->batch_idx==i && rec->txn_idx==i );
      if( i ) FD_TEST( gui->timeline_scratch.materialize.records[i-1UL].sigverify_txn_idx[0]<rec->sigverify_txn_idx[0] );
      ulong j=0UL;
      while( j<count && oracle[j].first!=rec->sigverify_txn_idx[0] ) j++;
      FD_TEST( j<count && rec->sigverify_txn_cnt==oracle[j].cnt );
      FD_TEST( rec->sigverify_start_ns==oracle[j].start_ns && rec->sigverify_end_ns==oracle[j].end_ns );
      for( ulong k=0UL; k<oracle[j].cnt; k++ ) FD_TEST( rec->sigverify_txn_idx[k]==oracle[j].first+k );
    }
  }
  ulong n=FD_MAX_TXN_PER_SLOT;
  ts=sec_ns( 12UL );
  for( ulong i=0UL; i<n; i++ ) {
    fd_gui_store_replay_txn_t txn={ .insert_time_ns=ts, .slot=105UL, .txn_idx=i,
      .sigverify_start_ns=ts+(long)i*1000L, .sigverify_end_ns=ts+(long)i*1000L+800L,
      .load_start_ns=ts+(long)i*200000L, .check_start_ns=LONG_MAX, .exec_start_ns=LONG_MAX,
      .commit_start_ns=LONG_MAX, .commit_end_ns=ts+(long)i*200000L+700L,
      .completion_time_ns=ts+(long)i*200000L+800L, .block_compute_unit_limit=ULONG_MAX };
    FD_TEST( !fd_gui_hist_ts_append( gui, FD_GUI_HIST_REPLAY_TXN, &txn ) );
  }
  gui->slot_txn_scratch.max=n;
  FD_TEST( !fd_gui_materialize_replay_txn_batches( gui, 105UL, ts, ts+(long)n*200000L, n, ts ) );
  ulong work=gui->timeline_scratch.materialize.normalize_work;
  FD_TEST( work && work<n*128UL );
  for( ulong i=0UL; i<n; i++ ) {
    fd_gui_store_replay_txn_batch_t const * rec=&gui->timeline_scratch.materialize.records[i];
    FD_TEST( rec->exec_txn_cnt==1U && rec->sigverify_txn_cnt==1U );
    FD_TEST( rec->exec_txn_idx[0]==i && rec->sigverify_txn_idx[0]==i );
  }
  FD_TEST( !gui->timeline_scratch_in_use );
  FD_LOG_NOTICE(( "test_timeline_batch_parity: tie fixtures and %lu singleton EXEC / 32-member SIG: %lu normalization work; ok", n, work ));
}

static void
test_timeline_batches( fd_gui_t * gui ) {
  long const ts = sec_ns( 10UL );
  for( ulong i=0UL; i<65UL; i++ ) {
    fd_gui_store_replay_txn_t txn = {
      .insert_time_ns=ts, .completion_time_ns=ts+(long)i*1000L+800L, .slot=100UL, .txn_idx=i,
      .sigverify_start_ns=ts+(long)i*1000L, .sigverify_end_ns=ts+(long)i*1000L+800L,
      .load_start_ns=ts+(long)i*1000L+100L, .check_start_ns=ts+(long)i*1000L+200L,
      .exec_start_ns=ts+(long)i*1000L+300L, .commit_start_ns=ts+(long)i*1000L+600L,
      .commit_end_ns=ts+(long)i*1000L+700L, .block_compute_unit_limit=ULONG_MAX
    };
    FD_TEST( !fd_gui_hist_ts_append( gui, FD_GUI_HIST_REPLAY_TXN, &txn ) );
  }
  gui->slot_txn_scratch.max = 33UL;
  FD_TEST( !fd_gui_materialize_replay_txn_batches( gui, 100UL, ts, ts+1000000L, 65UL, ts+1000000L ) );
  FD_TEST( count_ts( gui, FD_GUI_HIST_REPLAY_TXN_BATCH, ULONG_MAX )==2UL );
  fd_gui_hist_iter_t it;
  FD_TEST( !fd_gui_hist_range_begin( gui, &it, FD_GUI_HIST_REPLAY_TXN_BATCH, ts, ts+1000000L, NULL, NULL ) );
  for( ulong i=0UL; i<2UL; i++ ) {
    FD_TEST( fd_gui_hist_range_next( &it ) );
    fd_gui_store_replay_txn_batch_t const * b = it.rec;
    FD_TEST( b->batch_idx==i && b->exec_txn_cnt==(i ? 1U : 32U) && b->sigverify_txn_cnt==b->exec_txn_cnt );
    FD_TEST( b->txn_idx==i*32UL && b->exec_txn_idx[0]==i*32UL && b->sigverify_txn_idx[0]==i*32UL );
    FD_TEST( b->completion_time_ns==ts+(long)(i ? 32UL : 31UL)*1000L+800L );
    FD_TEST( b->load_start_ns<=b->check_start_ns && b->check_start_ns<=b->exec_start_ns );
    FD_TEST( b->exec_start_ns<=b->commit_start_ns && b->commit_start_ns<=b->commit_end_ns );
  }
  FD_TEST( !fd_gui_hist_range_next( &it ) );
  fd_gui_hist_range_end( &it );
  FD_TEST( !gui->timeline_scratch_in_use );
  FD_LOG_NOTICE(( "test_timeline_batches: ok" ));
}

static void
test_timeline_marker_order( fd_gui_t * gui ) {
  void * http_mem=timeline_http_open( gui );
  gui->summary.is_alpenglow=1;
  long ts=sec_ns( 10UL );
  fd_gui_shred_event_t input[]={
    { .slot=103U, .idx=USHORT_MAX, .event=FD_GUI_SLOT_SHRED_SHRED_SLOT_COMPLETE, .timestamp=ts+80L },
    { .slot=100U, .idx=1U, .event=FD_GUI_SLOT_SHRED_REPAIR_REQUEST, .timestamp=ts+70L },
    { .slot=105U, .idx=USHORT_MAX, .event=FD_GUI_SLOT_SHRED_SHRED_SLOT_COMPLETE, .timestamp=ts+75L },
    { .slot=101U, .idx=2U, .event=FD_GUI_SLOT_SHRED_SHRED_RECEIVED_TURBINE, .timestamp=ts+90L },
    { .slot=103U, .idx=USHORT_MAX, .event=FD_GUI_SLOT_SHRED_SHRED_SLOT_COMPLETE, .timestamp=ts+60L },
    { .slot=104U, .idx=USHORT_MAX, .event=FD_GUI_SLOT_SHRED_SHRED_SLOT_COMPLETE, .timestamp=ts+85L },
    { .slot=102U, .idx=3U, .event=FD_GUI_SLOT_SHRED_SHRED_REPLAY_EXEC_DONE, .timestamp=ts+65L },
    { .slot=105U, .idx=USHORT_MAX, .event=FD_GUI_SLOT_SHRED_SHRED_SLOT_COMPLETE, .timestamp=ts+40L },
    { .slot=104U, .idx=USHORT_MAX, .event=FD_GUI_SLOT_SHRED_SHRED_SLOT_COMPLETE, .timestamp=ts+45L },
    { .slot=103U, .idx=USHORT_MAX, .event=FD_GUI_SLOT_SHRED_SHRED_SLOT_COMPLETE, .timestamp=ts+100L }
  };
  ulong appended=0UL;
  for( ulong fixture=0UL; fixture<2UL; fixture++ ) {
    ulong count=fixture ? sizeof(input)/sizeof(input[0]) : 2UL;
    for( ; appended<count; appended++ ) {
      fd_gui_shred_event_t const * e=&input[appended];
      if( e->event==FD_GUI_SLOT_SHRED_SHRED_SLOT_COMPLETE ) fd_gui_shred_event_slot_complete( gui, e->slot, e->timestamp, ts );
      else {
        fd_gui_shred_batch_t batch={ .slot=e->slot, .insert_time_ns=ts, .base_timestamp=e->timestamp,
          .base_idx=e->idx, .event_cnt=1U };
        batch.events[0].event=e->event;
        FD_TEST( !fd_gui_hist_ts_append( gui, FD_GUI_HIST_FEC_EVENTS, &batch ) );
      }
    }
    for( ulong query=0UL; query<(fixture ? 4UL : 1UL); query++ ) {
      long starts[]={ts+30L,ts+50L,ts+61L,ts+50L};
      long start=starts[query], end=query==3UL ? ts+76L : ts+101L;
      fd_gui_shred_event_t oracle[10];
      ulong n=0UL;
      ulong refslot=ULONG_MAX;
      long refts=LONG_MAX;
      for( ulong i=0UL; i<count; i++ ) {
        fd_gui_shred_event_t const * e=&input[i];
        if( e->timestamp<start || e->timestamp>=end ) continue;
        oracle[n++]=*e;
        refslot=fd_ulong_min( refslot, e->slot );
        refts=fd_long_min( refts, e->timestamp );
      }
      ulong expected[]={10UL,8UL,7UL,4UL};
      FD_TEST( n==(fixture ? expected[query] : 2UL) );
      if( !fixture ) FD_TEST( oracle[0].slot==103U && oracle[1].slot==100U );
      FD_TEST( !fd_gui_printf_timeline_query_fec_events( gui, "timeline", start, end, 7UL ) );
      test_json_t json=timeline_response( gui );
      FD_TEST( !test_json_field( json, "error" ).ptr );
      FD_TEST( test_json_count( timeline_value( json, "idx" ) )==(int)n );
      FD_TEST( test_json_ulong( timeline_value( json, "reference_slot" ) )==refslot );
      char expected_ts[32];
      fd_cstr_printf_check( expected_ts, sizeof(expected_ts), NULL, "%ld", refts );
      FD_TEST( test_json_string_eq( timeline_value( json, "reference_ts" ), expected_ts ) );
      for( ulong i=0UL; i<n; i++ ) {
        FD_TEST( test_json_ulong( test_json_index( timeline_value( json, "slot_delta" ), (int)i ) )==oracle[i].slot-refslot );
        FD_TEST( test_json_ulong( test_json_index( timeline_value( json, "event" ), (int)i ) )==oracle[i].event );
        test_json_t idx=test_json_index( timeline_value( json, "idx" ), (int)i );
        FD_TEST( oracle[i].idx==USHORT_MAX ? (test_json_kind( idx )==FD_JTOK_NULL) : (test_json_kind( idx )==FD_JTOK_INT) && test_json_ulong( idx )==oracle[i].idx );
        fd_cstr_printf_check( expected_ts, sizeof(expected_ts), NULL, "%ld", oracle[i].timestamp-refts );
        FD_TEST( test_json_string_eq( test_json_index( timeline_value( json, "event_ts_delta" ), (int)i ), expected_ts ) );
      }

    }
  }
  FD_TEST( !gui->timeline_scratch_in_use );
  FD_TEST( fd_http_server_delete( fd_http_server_leave( gui->http ) )==http_mem );
  free( http_mem );
  gui->http=NULL;
  FD_LOG_NOTICE(( "test_timeline_marker_order: duplicate completions preserved, requested-window filtering: ok" ));
}

static void
test_timeline_marker_limits( fd_gui_t * gui ) {
  void * http_mem=timeline_http_open( gui );
  gui->summary.is_alpenglow=1;
  long ts=sec_ns( 10UL );
  fd_gui_shred_batch_t batch={ .insert_time_ns=ts, .base_timestamp=ts+1L, .event_cnt=1U };
  batch.events[0].event=FD_GUI_SLOT_SHRED_SHRED_SLOT_COMPLETE;
  for( ulong i=0UL; i<FD_GUI_TIMELINE_QUERY_SHRED_MAX; i++ ) {
    batch.slot=i;
    FD_TEST( !fd_gui_hist_ts_append( gui, FD_GUI_HIST_FEC_EVENTS, &batch ) );
  }
  FD_TEST( !fd_gui_printf_timeline_query_fec_events( gui, "timeline", ts+1L, ts+2L, 7UL ) );
  test_json_t json=timeline_response( gui );
  FD_TEST( test_json_count( timeline_value( json, "idx" ) )==(int)FD_GUI_TIMELINE_QUERY_SHRED_MAX );

  /* A duplicate counts toward the same result limit as any other row. */
  batch.slot=0UL;
  FD_TEST( !fd_gui_hist_ts_append( gui, FD_GUI_HIST_FEC_EVENTS, &batch ) );
  FD_TEST( !fd_gui_printf_timeline_query_fec_events( gui, "timeline", ts+1L, ts+2L, 7UL ) );
  json=timeline_response( gui );
  FD_TEST( test_json_string_eq( test_json_field( test_json_field( json, "error" ), "code" ), "result_limit_exceeded" ) );

  /* Earlier markers do not count toward the requested window's limit. */
  FD_TEST( !fd_gui_printf_timeline_query_fec_events( gui, "timeline", ts+2L, ts+3L, 7UL ) );
  json=timeline_response( gui );
  FD_TEST( !test_json_field( json, "error" ).ptr );
  FD_TEST( !test_json_count( timeline_value( json, "idx" ) ) );
  FD_TEST( !gui->timeline_scratch_in_use );
  FD_TEST( fd_http_server_delete( fd_http_server_leave( gui->http ) )==http_mem );
  free( http_mem );
  gui->http=NULL;
  FD_LOG_NOTICE(( "test_timeline_marker_limits: result limit includes duplicates and excludes earlier markers: ok" ));
}

static void
test_timeline_limits( fd_gui_t * gui ) {
  void * http_mem = timeline_http_open( gui );
  gui->summary.is_alpenglow = 1;
  long const ts = sec_ns( 10UL );
  fd_gui_shred_batch_t batch = { .slot=100UL, .insert_time_ns=ts, .base_timestamp=ts, .event_cnt=128U };
  for( ulong i=0UL; i<FD_GUI_TIMELINE_QUERY_SHRED_MAX/128UL; i++ ) {
    FD_TEST( !fd_gui_hist_ts_append( gui, FD_GUI_HIST_SHRED_EVENTS, &batch ) );
    FD_TEST( !fd_gui_hist_ts_append( gui, FD_GUI_HIST_FEC_EVENTS, &batch ) );
  }
  for( int fec=0; fec<2; fec++ ) {
    FD_TEST( !(fec ? fd_gui_printf_timeline_query_fec_events( gui, "timeline", ts, ts+1L, 7UL )
                  : fd_gui_printf_timeline_query_shreds( gui, "timeline", ts, ts+1L, 7UL )) );
    FD_TEST( fd_http_server_stage_len( gui->http )<(32UL<<20) );
    test_json_t json = timeline_response( gui );
    FD_TEST( test_json_count( timeline_value( json, "idx" ) )==(int)FD_GUI_TIMELINE_QUERY_SHRED_MAX );

  }
  batch.event_cnt = 1U;
  FD_TEST( !fd_gui_hist_ts_append( gui, FD_GUI_HIST_SHRED_EVENTS, &batch ) );
  FD_TEST( !fd_gui_hist_ts_append( gui, FD_GUI_HIST_FEC_EVENTS, &batch ) );
  for( int fec=0; fec<2; fec++ ) {
    FD_TEST( !(fec ? fd_gui_printf_timeline_query_fec_events( gui, "timeline", ts, ts+1L, 7UL )
                  : fd_gui_printf_timeline_query_shreds( gui, "timeline", ts, ts+1L, 7UL )) );
    test_json_t json = timeline_response( gui );
    FD_TEST( test_json_string_eq( test_json_field( test_json_field( json, "error" ), "code" ), "result_limit_exceeded" ) );

  }

  fd_gui_store_replay_txn_t txn = { .insert_time_ns=ts, .completion_time_ns=ts, .slot=100UL, .block_compute_unit_limit=ULONG_MAX };
  fd_gui_store_replay_txn_batch_t tb = { .insert_time_ns=ts, .completion_time_ns=ts, .slot=100UL };
  for( ulong i=0UL; i<FD_GUI_TIMELINE_QUERY_TXN_META_MAX; i++ ) {
    txn.txn_idx = i;
    tb.batch_idx = i;
    FD_TEST( !fd_gui_hist_ts_append( gui, FD_GUI_HIST_REPLAY_TXN, &txn ) );
    FD_TEST( !fd_gui_hist_ts_append( gui, FD_GUI_HIST_REPLAY_TXN_BATCH, &tb ) );
  }
  for( int kind=0; kind<3; kind++ ) {
    FD_TEST( !(kind==2 ? fd_gui_printf_timeline_query_txn_batches( gui, "timeline", "query_txn_timestamps", ts, ts+1L, 7UL )
                      : fd_gui_printf_timeline_query_txns( gui, "timeline", kind ? "query_txn_meta" : "query_txn_timestamps", ts, ts+1L, 7UL )) );
    FD_TEST( fd_http_server_stage_len( gui->http )<(32UL<<20) );
    test_json_t json = timeline_response( gui );
    FD_TEST( test_json_count( timeline_value( json, "txn_idx" ) )==(int)FD_GUI_TIMELINE_QUERY_TXN_META_MAX );

  }
  FD_TEST( !fd_gui_hist_ts_append( gui, FD_GUI_HIST_REPLAY_TXN, &txn ) );
  FD_TEST( !fd_gui_hist_ts_append( gui, FD_GUI_HIST_REPLAY_TXN_BATCH, &tb ) );
  for( int kind=0; kind<3; kind++ ) {
    FD_TEST( !(kind==2 ? fd_gui_printf_timeline_query_txn_batches( gui, "timeline", "query_txn_timestamps", ts, ts+1L, 7UL )
                      : fd_gui_printf_timeline_query_txns( gui, "timeline", kind ? "query_txn_meta" : "query_txn_timestamps", ts, ts+1L, 7UL )) );
    test_json_t json = timeline_response( gui );
    FD_TEST( test_json_string_eq( test_json_field( test_json_field( json, "error" ), "code" ), "result_limit_exceeded" ) );

  }
  put_epoch( gui, 0UL, 0UL, FD_GUI_TIMELINE_QUERY_SLOT_MAX+1UL );
  gui->epoch.current_epoch = 0UL;
  fd_gui_epoch_t * epoch = fd_gui_epoch( gui, 0UL );
  epoch->timeline_slot_lo_idx = 0UL;
  epoch->timeline_slot_hi_idx = FD_GUI_TIMELINE_QUERY_SLOT_MAX-1UL;
  for( ulong i=0UL; i<=FD_GUI_TIMELINE_QUERY_SLOT_MAX; i++ ) {
    epoch->timeline_slot_start_ns[i] = ts;
    epoch->timeline_slot_end_ns[i] = ts+1L;
    epoch->timeline_slot_state[i] = FD_GUI_TIMELINE_SLOT_STATE_VALID;
  }
  FD_TEST( !fd_gui_printf_timeline_query_slots( gui, ts, ts+1L, 7UL ) );
  test_json_t json = timeline_response( gui );
  FD_TEST( test_json_count( timeline_value( json, "slot_delta" ) )==(int)FD_GUI_TIMELINE_QUERY_SLOT_MAX );

  epoch->timeline_slot_hi_idx++;
  FD_TEST( !fd_gui_printf_timeline_query_slots( gui, ts, ts+1L, 7UL ) );
  json = timeline_response( gui );
  FD_TEST( test_json_string_eq( test_json_field( test_json_field( json, "error" ), "code" ), "result_limit_exceeded" ) );

  FD_TEST( !fd_gui_printf_timeline_query_agg( gui, "query_agg_compute", "1ms", 0UL, ts, 10000UL, 7UL ) );
  json = timeline_response( gui );
  FD_TEST( test_json_count( timeline_value( json, "compute_units" ) )==10000 );

  /* Slot order need not match timestamp order.  The reference timestamp
     must come from the earliest returned interval, not the first row. */
  epoch->timeline_slot_lo_idx=10UL;
  epoch->timeline_slot_hi_idx=12UL;
  epoch->timeline_slot_start_ns[10]=30L;
  epoch->timeline_slot_end_ns[10]=40L;
  epoch->timeline_slot_start_ns[11]=10L;
  epoch->timeline_slot_end_ns[11]=20L;
  epoch->timeline_slot_start_ns[12]=20L;
  epoch->timeline_slot_end_ns[12]=30L;
  FD_TEST( !fd_gui_printf_timeline_query_slots( gui, 0L, 50L, 7UL ) );
  json=timeline_response( gui );
  FD_TEST( test_json_ulong( timeline_value( json, "reference_slot" ) )==10UL );
  FD_TEST( test_json_string_eq( timeline_value( json, "reference_ts" ), "10" ) );
  char const * starts[]={ "20", "0", "10" };
  char const * ends[]={ "30", "10", "20" };
  for( int i=0; i<3; i++ ) {
    FD_TEST( test_json_ulong( test_json_index( timeline_value( json, "slot_delta" ), i ) )==(ulong)i );
    FD_TEST( test_json_string_eq( test_json_index( timeline_value( json, "start_ts_delta" ), i ), starts[i] ) );
    FD_TEST( test_json_string_eq( test_json_index( timeline_value( json, "end_ts_delta" ), i ), ends[i] ) );
  }
  FD_TEST( !fd_gui_printf_timeline_query_slots( gui, 20L, 40L, 7UL ) );
  json=timeline_response( gui );
  FD_TEST( test_json_string_eq( timeline_value( json, "reference_ts" ), "20" ) );
  FD_TEST( !fd_gui_printf_timeline_query_slots( gui, 40L, 50L, 7UL ) );
  json=timeline_response( gui );
  FD_TEST( test_json_kind( timeline_value( json, "reference_slot" ) )==FD_JTOK_NULL );
  FD_TEST( test_json_kind( timeline_value( json, "reference_ts" ) )==FD_JTOK_NULL );

  FD_TEST( !gui->timeline_scratch_in_use );
  FD_TEST( fd_http_server_delete( fd_http_server_leave( gui->http ) )==http_mem );
  free( http_mem );
  gui->http = NULL;
  FD_LOG_NOTICE(( "test_timeline_limits: ok" ));
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
    FD_TEST( !fd_gui_printf_timeline_query_agg( gui, keys[i], "1ms", 0UL, 0L, 1UL, 7UL ) );
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
  for( ulong i=0UL; i<sizeof(invalid)/sizeof(invalid[0]); i++ ) {
    char request[512];
    fd_cstr_printf_check( request, sizeof(request), NULL, "{\"id\":7,\"topic\":\"timeline\",\"key\":\"query_shreds\",\"params\":%s}", invalid[i] );
    FD_TEST( fd_gui_ws_message( gui, 0UL, (uchar const *)request, strlen(request) )==FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST );
  }
  char const * valid = "{\"id\":7,\"topic\":\"timeline\",\"key\":\"query_shreds\",\"params\":{\"start_ns\":\"0\",\"end_ns\":\"1\",\"granularity\":\"fec\"}}";
  FD_TEST( !fd_gui_ws_message( gui, 0UL, (uchar const *)valid, strlen(valid) ) );
  FD_TEST( fd_gui_printf_timeline_query_agg( gui, "query_agg_compute", "1ms", 0UL, 0L, 10001UL, 7UL )==-1 );
  FD_TEST( fd_gui_printf_timeline_query_agg( gui, "query_agg_compute", "1d", 26UL, LONG_MAX-1L, 1UL, 7UL )==-1 );

  fd_gui_store_replay_txn_t txn = {
    .insert_time_ns=sec_ns( 10UL ), .completion_time_ns=sec_ns( 10UL )+20L,
    .slot=100UL, .txn_idx=3UL, .txn_exec_idx=1UL, .txn_sigverify_exec_idx=2UL,
    .sigverify_start_ns=sec_ns( 10UL ), .sigverify_end_ns=sec_ns( 10UL )+20L,
    .load_start_ns=sec_ns( 10UL )+1L, .check_start_ns=LONG_MAX, .exec_start_ns=LONG_MAX,
    .commit_start_ns=LONG_MAX, .commit_end_ns=sec_ns( 10UL )+10L,
    .compute_units_requested=123U, .compute_units_consumed=42U, .block_compute_unit_limit=60000000UL,
    .transaction_fee=5000UL, .priority_fee=1UL, .tips=2UL, .is_committable=1U
  };
  FD_TEST( !fd_gui_hist_ts_append( gui, FD_GUI_HIST_REPLAY_TXN, &txn ) );
  fd_gui_timeline_handle_txn( gui, txn.slot, txn.commit_end_ns, txn.compute_units_consumed, txn.block_compute_unit_limit,
    txn.transaction_fee, txn.priority_fee, txn.tips, 0, 1, txn.insert_time_ns );
  for( ulong g=0UL; g<FD_GUI_TIMELINE_GRANULARITY_CNT; g++ ) {
    ulong ns = fd_gui_timeline_granularities[g].duration_ns;
    long ref = (long)((ulong)txn.commit_end_ns/ns*ns);
    FD_TEST( !fd_gui_printf_timeline_query_agg( gui, "query_agg_compute", fd_gui_timeline_granularities[g].name, g, ref, 1UL, 7UL ) );
    test_json_t json = timeline_response( gui );
    FD_TEST( test_json_ulong( timeline_value( json, "max_compute_units" ) )==60000000UL );
    FD_TEST( test_json_ulong( test_json_index( timeline_value( json, "compute_units" ), 0 ) )==42UL );

  }
  FD_TEST( !fd_gui_printf_timeline_query_txns( gui, "timeline", "query_txn_timestamps", txn.completion_time_ns-1L, txn.completion_time_ns, 7UL ) );
  test_json_t json = timeline_response( gui );
  FD_TEST( !test_json_count( timeline_value( json, "txn_idx" ) ) );

  FD_TEST( !fd_gui_printf_timeline_query_txns( gui, "timeline", "query_txn_timestamps", txn.completion_time_ns, txn.completion_time_ns+1L, 7UL ) );
  json = timeline_response( gui );
  FD_TEST( test_json_count( timeline_value( json, "txn_idx" ) )==1 );
  FD_TEST( test_json_string_eq( timeline_value( json, "reference_ts" ), "10000000000" ) );
  FD_TEST( (test_json_kind( test_json_index( timeline_value( json, "txn_check_start_ts_delta" ), 0 ) )==FD_JTOK_NULL) );

  FD_TEST( !fd_gui_printf_timeline_query_txns( gui, "timeline", "query_txn_meta", txn.completion_time_ns, txn.completion_time_ns+1L, 7UL ) );
  json = timeline_response( gui );
  FD_TEST( test_json_ulong( test_json_index( timeline_value( json, "txn_compute_units_requested" ), 0 ) )==123UL );
  FD_TEST( (test_json_kind( test_json_index( timeline_value( json, "txn_transaction_fee" ), 0 ) )==FD_JTOK_STR) );

  /* Commit belongs to the preceding bucket even when sigverify completes
     exactly at the next boundary.  Check each fine granularity and the
     coarse granularities up to one second, with separate query windows. */
  txn.insert_time_ns=sec_ns( 20UL );
  txn.completion_time_ns=sec_ns( 20UL );
  txn.sigverify_start_ns=sec_ns( 20UL )-2L;
  txn.sigverify_end_ns=sec_ns( 20UL );
  txn.load_start_ns=sec_ns( 20UL )-2L;
  txn.commit_end_ns=sec_ns( 20UL )-1L;
  FD_TEST( !fd_gui_hist_ts_append( gui, FD_GUI_HIST_REPLAY_TXN, &txn ) );
  fd_gui_timeline_handle_txn( gui, txn.slot, txn.commit_end_ns, txn.compute_units_consumed, txn.block_compute_unit_limit,
    txn.transaction_fee, txn.priority_fee, txn.tips, 0, 1, txn.insert_time_ns );
  for( ulong g=0UL; g<FD_GUI_TIMELINE_GRANULARITY_CNT; g++ ) {
    ulong ns=fd_gui_timeline_granularities[g].duration_ns;
    if( ns>(ulong)FD_GUI_HIST_RES_1S_NS ) break;
    long ref=(long)((ulong)txn.commit_end_ns/ns*ns);
    FD_TEST( !fd_gui_printf_timeline_query_agg( gui, "query_agg_compute", fd_gui_timeline_granularities[g].name, g, ref, 1UL, 7UL ) );
    json=timeline_response( gui );
    FD_TEST( test_json_ulong( test_json_index( timeline_value( json, "compute_units" ), 0 ) )==42UL );
    FD_TEST( !fd_gui_printf_timeline_query_agg( gui, "query_agg_compute", fd_gui_timeline_granularities[g].name, g, ref+(long)ns, 1UL, 7UL ) );
    json=timeline_response( gui );
    FD_TEST( test_json_kind( test_json_index( timeline_value( json, "compute_units" ), 0 ) )==FD_JTOK_NULL );
  }

  FD_TEST( fd_http_server_delete( fd_http_server_leave( gui->http ) )==http_mem );
  free( http_mem );
  gui->http = NULL;
  FD_LOG_NOTICE(( "test_timeline_queries: ok" ));
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

  test_store_t s0[ 1 ];
  store_open( s0, 2UL<<30, 0 );
  test_evict_oldest_epoch( s0->gui );
  store_close( s0 );

  test_store_t s1[ 1 ];
  store_open( s1, 2UL<<30, 2 );
  test_evict_large_batch( s1->gui );
  store_close( s1 );

  test_store_t sp[ 1 ];
  store_open( sp, 2UL<<30, 6 );
  test_current_epoch_protected( sp->gui );
  store_close( sp );

  test_store_t s2[ 1 ];
  store_open( s2, 2UL<<30, 3 );
  test_evict_ts_oldest_fallback( s2->gui );
  store_close( s2 );

  test_store_t st[ 1 ];
  store_open( st, 2UL<<30, 9 );
  test_evict_timeline_ts_fallback( st->gui );
  store_close( st );

  test_store_t s3[ 1 ];
  store_open( s3, 2UL<<30, 4 );
  test_resident_meta_mutation_survives_evict( s3->gui );
  store_close( s3 );

  test_store_t s4[ 1 ];
  store_open( s4, 2UL<<30, 5 );
  test_epoch_region_reclaimed( s4->gui );
  store_close( s4 );

  test_store_t s5[ 1 ];
  store_open( s5, 2UL<<30, 7 );
  test_waterfall_snapshots( s5->gui );
  store_close( s5 );

  test_store_t s6[ 1 ];
  store_open( s6, 2UL<<30, 8 );
  test_timeline_db( s6->gui );
  store_close( s6 );

  test_store_t sr[ 1 ];
  store_open( sr, 2UL<<30, 13 );
  test_range_live_timestamp_bounds( sr->gui );
  store_close( sr );

  test_store_t tx[ 1 ];
  store_open( tx, 2UL<<30, 14 );
  test_txn_insert_bounds( tx->gui );
  store_close( tx );

  test_store_t s7[ 1 ];
  store_open( s7, 2UL<<30, 10 );
  test_shred_event_batches( s7->gui );
  store_close( s7 );

  test_store_t s8[ 1 ];
  store_open( s8, 2UL<<30, 11 );
  test_shred_event_pool_exhaustion( s8->gui );
  store_close( s8 );

  test_store_t s9[ 1 ];
  store_open( s9, 2UL<<30, 12 );
  test_shred_event_root_reclaim( s9->gui );
  store_close( s9 );

  test_store_t s10[ 1 ];
  store_open( s10, 2UL<<30, 15 );
  test_fec_event_index( s10->gui );
  store_close( s10 );

  store_open( s10, 2UL<<30, 15 );
  test_timeline_staging( s10 );
  store_close( s10 );

  test_store_t s11[ 1 ];
  store_open( s11, 2UL<<30, 16 );
  test_timeline_queries( s11->gui );
  store_close( s11 );

  test_store_t s12[ 1 ];
  store_open( s12, 2UL<<30, 17 );
  test_timeline_ancestry( s12->gui );
  store_close( s12 );

  test_store_t s13[ 1 ];
  store_open( s13, 2UL<<30, 18 );
  test_timeline_batches( s13->gui );
  store_close( s13 );

  test_store_t s14[ 1 ];
  store_open( s14, 2UL<<30, 19 );
  test_timeline_limits( s14->gui );
  store_close( s14 );

  test_store_t s15[ 1 ];
  store_open( s15, 2UL<<30, 20 );
  test_timeline_completion_overflow( s15 );
  store_close( s15 );

  test_store_t s16[ 1 ];
  store_open( s16, 2UL<<30, 21 );
  test_timeline_day_cache( s16->gui );
  store_close( s16 );

  test_store_t s17[ 1 ];
  store_open( s17, 2UL<<30, 22 );
  test_timeline_batch_parity( s17->gui );
  store_close( s17 );

  test_store_t s18[ 1 ];
  store_open( s18, 2UL<<30, 23 );
  test_timeline_closure_overflow( s18->gui );
  store_close( s18 );

  test_store_t s19[ 1 ];
  store_open( s19, 2UL<<30, 24 );
  test_timeline_day_recovery( s19->gui );
  store_close( s19 );

  test_store_t s20[ 1 ];
  store_open( s20, 2UL<<30, 25 );
  test_timeline_marker_limits( s20->gui );
  store_close( s20 );

  test_store_t s21[ 1 ];
  store_open( s21, 2UL<<30, 26 );
  test_timeline_marker_order( s21->gui );
  store_close( s21 );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
