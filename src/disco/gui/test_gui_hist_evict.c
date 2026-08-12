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
#include "fd_gui_printf.h"
#include "fd_gui_store.h"
#include "fd_gui_hist.h"
#include "../shred/fd_shred_tile.h"
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

static fd_gui_slot_t *
put_oc_slot( fd_gui_t * gui,
             ulong      slot,
             ulong      parent_slot,
             long       completed_time,
             long       parent_completed_time ) {
  ulong parent_bank_seq = parent_slot==ULONG_MAX ? ULONG_MAX : BANK_SEQ;
  fd_gui_slot_t * rec = fd_gui_slot_get_or_create( gui, slot, parent_slot, BANK_SEQ, parent_bank_seq );
  FD_TEST( rec );
  rec->completed_time        = completed_time;
  rec->parent_completed_time = parent_completed_time;
  rec->skip                  = FD_GUI_SKIP_STATUS_NOT_SKIPPED;
  rec->level                 = FD_GUI_SLOT_LEVEL_COMPLETED;
  return rec;
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
  fd_gui_slot_history_event_t rec[ 1 ];
  memset( rec, 0, sizeof(*rec) );
  rec->slot      = (uint)slot;
  rec->timestamp = ts_ns;

  FD_TEST( !fd_gui_hist_ts_append( gui, FD_GUI_HIST_SHRED_EVENTS, ts_ns, ts_ns, rec ) );
}

static void
append_fec_event( fd_gui_t * gui,
                  long       ts_ns,
                  ulong      slot,
                  ulong      idx,
                  ulong      event ) {
  fd_gui_slot_history_event_t rec = {
    .timestamp = ts_ns,
    .slot      = (uint)slot,
    .idx       = (ushort)idx,
    .event     = (uchar)event
  };
  FD_TEST( !fd_gui_hist_ts_append( gui, FD_GUI_HIST_FEC_EVENTS, ts_ns, ts_ns, &rec ) );
}

static ulong
test_fec_cache_idx( ulong slot,
                    ulong idx,
                    ulong event ) {
  ulong key = ((ulong)(uint)slot<<24) | ((ulong)(ushort)idx<<8) | (ulong)(uchar)event;
  return fd_ulong_hash( key ) & (FD_GUI_FEC_EVENT_CACHE_CNT-1UL);
}

static void
append_replay_txn( fd_gui_t * gui, long ts_ns, ulong slot ) {
  fd_gui_store_replay_txn_t rec[ 1 ];
  memset( rec, 0, sizeof(*rec) );
  rec->completion_time_ns = ts_ns;
  rec->slot               = slot;

  FD_TEST( !fd_gui_hist_ts_append( gui, FD_GUI_HIST_REPLAY_TXN, ts_ns, ts_ns, rec ) );
}

static void
append_replay_txn_timing( fd_gui_t * gui,
                          ulong      slot,
                          ulong      txn_idx,
                          ulong      exec_tile_idx,
                          ulong      sigverify_tile_idx,
                          uint       error_code,
                          long       sigverify_start_ns,
                          long       sigverify_end_ns,
                          long       load_start_ns,
                          long       check_start_ns,
                          long       exec_start_ns,
                          long       commit_start_ns,
                          long       commit_end_ns ) {
  fd_gui_store_replay_txn_t rec = {
    .completion_time_ns      = fd_long_max( sigverify_end_ns, commit_end_ns ),
    .slot                    = slot,
    .txn_idx                 = txn_idx,
    .txn_exec_idx            = exec_tile_idx,
    .txn_sigverify_exec_idx  = sigverify_tile_idx,
    .sigverify_start_ns      = sigverify_start_ns,
    .sigverify_end_ns        = sigverify_end_ns,
    .load_start_ns           = load_start_ns,
    .check_start_ns          = check_start_ns,
    .exec_start_ns           = exec_start_ns,
    .commit_start_ns         = commit_start_ns,
    .commit_end_ns           = commit_end_ns,
    .error_code              = error_code
  };
  FD_TEST( !fd_gui_hist_ts_append( gui, FD_GUI_HIST_REPLAY_TXN,
                                   rec.completion_time_ns, rec.completion_time_ns, &rec ) );
}

static void
append_replay_txn_batch( fd_gui_t * gui,
                         long       ts_ns,
                         ulong      slot,
                         ulong      batch_idx ) {
  fd_gui_store_replay_txn_batch_t rec[ 1 ];
  memset( rec, 0, sizeof(*rec) );
  rec->completion_time_ns = ts_ns;
  rec->slot               = slot;
  rec->batch_idx          = batch_idx;
  rec->sigverify_start_ns = ts_ns;
  rec->sigverify_end_ns   = ts_ns;
  rec->load_start_ns      = ts_ns;
  rec->check_start_ns     = ts_ns;
  rec->exec_start_ns      = ts_ns;
  rec->commit_start_ns    = ts_ns;
  rec->commit_end_ns      = ts_ns;

  FD_TEST( !fd_gui_hist_ts_append( gui, FD_GUI_HIST_REPLAY_TXN_BATCH, ts_ns, ts_ns, rec ) );
}

static ulong
collect_replay_txn_batches( fd_gui_t *                       gui,
                            ulong                            slot,
                            fd_gui_store_replay_txn_batch_t * out,
                            ulong                            out_cap ) {
  fd_gui_hist_iter_t it[ 1 ];
  FD_TEST( !fd_gui_hist_range_begin( gui, it, FD_GUI_HIST_REPLAY_TXN_BATCH,
                                     LONG_MIN+1L, LONG_MAX-1L, NULL, NULL ) );
  ulong cnt = 0UL;
  while( fd_gui_hist_range_next( it ) ) {
    fd_gui_store_replay_txn_batch_t const * rec = it->rec;
    if( rec->slot!=slot ) continue;
    FD_TEST( cnt<out_cap );
    out[ cnt++ ] = *rec;
  }
  fd_gui_hist_range_end( it );
  return cnt;
}

static void
complete_replay_txn_batch_slot( fd_gui_t * gui,
                                ulong      slot,
                                ulong      txn_cnt,
                                long       first_transaction_ns,
                                long       completion_ns ) {
  gui->summary.slot_storage                   = ULONG_MAX;
  gui->summary.identity_account_balance       = ULONG_MAX;
  gui->summary.slot_rooted                    = ULONG_MAX;
  gui->summary.slot_tower                     = ULONG_MAX;
  gui->summary.slot_tower_bank_seq            = ULONG_MAX;
  gui->summary.slot_optimistically_confirmed  = ULONG_MAX;
  gui->summary.slot_caught_up                 = ULONG_MAX;
  for( ulong i=0UL; i<FD_GUI_TURBINE_SLOT_HISTORY_SZ; i++ ) gui->summary.slots_max_turbine[ i ].slot = ULONG_MAX;

  fd_replay_slot_completed_t completed;
  memset( &completed, 0xFF, sizeof(completed) );
  completed.slot                              = slot;
  completed.parent_slot                       = slot-1UL;
  completed.storage_slot                      = ULONG_MAX;
  completed.bank_seq                          = 1UL;
  completed.parent_bank_seq                   = 1UL;
  completed.first_transaction_scheduled_nanos = first_transaction_ns;
  completed.last_transaction_finished_nanos   = completion_ns;
  completed.completion_time_nanos              = completion_ns;
  completed.is_leader                          = 0;
  completed.identity_balance                   = ULONG_MAX;
  completed.vote_success                       = txn_cnt;
  completed.vote_failed                        = 0UL;
  completed.nonvote_success                    = 0UL;
  completed.nonvote_failed                     = 0UL;
  completed.transaction_fee                    = 0UL;
  completed.priority_fee                       = 0UL;
  completed.tips                               = 0UL;
  completed.shred_cnt                          = 0UL;

  fd_gui_handle_replay_update( gui, &completed, ULONG_MAX, completion_ns );
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
      fd_gui_slot_history_event_t const * e = (fd_gui_slot_history_event_t const *)it->rec;
      if( e->slot!=slot ) continue;
    }
    cnt++;
  }
  fd_gui_hist_range_end( it );
  return cnt;
}

static int
timeline_day_present( fd_gui_t * gui, ulong day ) {
  fd_gui_hist_timeline_day_key_t key = { .day=day };
  return fd_gui_hist_kv_get( gui, FD_GUI_HIST_TIMELINE_DAY, &key )!=NULL;
}

static fd_http_server_t *
test_http_new( void ** mem ) {
  fd_http_server_params_t params = {
    .max_connection_cnt    = 1UL,
    .max_ws_connection_cnt = 1UL,
    .max_request_len       = 4096UL,
    .max_ws_recv_frame_len = 4096UL,
    .max_ws_send_frame_cnt = 1UL,
    .outgoing_buffer_sz    = 1UL<<20,
    .compress_websocket    = 0,
  };
  ulong footprint = fd_http_server_footprint( params );
  *mem = aligned_alloc( fd_http_server_align(), fd_ulong_align_up( footprint, fd_http_server_align() ) );
  FD_TEST( *mem );
  fd_http_server_callbacks_t callbacks = {0};
  fd_http_server_t * http = fd_http_server_join( fd_http_server_new( *mem, params, callbacks, NULL ) );
  FD_TEST( http );
  return http;
}

static void
test_http_expect( fd_http_server_t * http,
                  char const *       expected ) {
  ulong len = strlen( expected );
  FD_TEST( http->stage_len==len );
  FD_TEST( !memcmp( http->oring+(http->stage_off%http->oring_sz), expected, len ) );
  fd_http_server_unstage( http );
}

static ulong
test_json_array_cnt( char const * json,
                     char const * field ) {
  char needle[ 128 ];
  fd_cstr_printf_check( needle, sizeof(needle), NULL, "\"%s\":[", field );
  char const * cur = strstr( json, needle );
  FD_TEST( cur );
  cur += strlen( needle );
  if( *cur==']' ) return 0UL;
  ulong cnt = 1UL;
  while( *cur && *cur!=']' ) cnt += (ulong)(*cur++==',');
  FD_TEST( *cur==']' );
  return cnt;
}

static void
test_timeline_agg_queries( fd_gui_t * gui ) {
  void * http_mem = NULL;
  fd_http_server_t * http = test_http_new( &http_mem );
  gui->http = http;

  fd_wksp_t * wksp = fd_wksp_new_anonymous( FD_SHMEM_NORMAL_PAGE_SZ, 4096UL, 0UL, "gui_agg_query", 0UL );
  FD_TEST( wksp );
  void * alloc_mem = fd_wksp_alloc_laddr( wksp, fd_alloc_align(), fd_alloc_footprint(), 1UL );
  FD_TEST( alloc_mem );
  gui->alloc = fd_alloc_join( fd_alloc_new( alloc_mem, 1UL ), 0UL );
  FD_TEST( gui->alloc );

  ulong const fec_shred_cnt = 2UL*FD_FEC_SHRED_CNT;
  long const day2           = 2L*FD_GUI_TIMELINE_DAY_NS;
  long const t0             = day2+10100000000L;
  long const t1             = day2+11100000000L;

  /* Completed FECs from all replay candidates accumulate immediately.  A
     single slot can complete FECs in more than one bucket, and all shred
     source counts use the corresponding FEC completion timestamp. */
  fd_gui_timeline_handle_shred( gui, 7000UL, SHRED_SIG_SRC_TURBINE );
  fd_gui_timeline_handle_fec  ( gui, 7000UL, 0, t0, 24U, 8U, 32U );
  fd_gui_timeline_handle_txn  ( gui, 7000UL, t0, 100UL, 1000UL, 10UL, 1UL, 0UL, 0, 1 );

  fd_gui_timeline_handle_shred( gui, 7001UL, SHRED_SIG_SRC_REPAIR );
  fd_gui_timeline_handle_txn  ( gui, 7001UL, t0, 200UL, 2000UL, 20UL, 2UL, 3UL, 0, 0 );

  fd_gui_timeline_handle_shred( gui, 7000UL, SHRED_SIG_SRC_RECONSTRUCTED );
  fd_gui_timeline_handle_fec  ( gui, 7000UL, 0, t1, 16U, 16U, 32U );
  fd_gui_timeline_handle_txn  ( gui, 7001UL, t1, 300UL, 1500UL, 30UL, 3UL, 4UL, 1, 1 );
  fd_gui_timeline_handle_txn  ( gui, 7001UL, t1, ULONG_MAX, ULONG_MAX,
                                ULONG_MAX, ULONG_MAX, ULONG_MAX, 1, 0 );

  char expected[ 2048 ];
  fd_cstr_printf_check(
      expected, sizeof(expected), NULL,
      "{\"topic\":\"timeline\",\"key\":\"query_agg_shreds\",\"id\":33,"
      "\"value\":{\"granularity\":\"1s\",\"reference_ts_ns\":\"%ld\","
      "\"turbine\":[null,24,16],\"repair\":[null,8,16],"
      "\"reconstructed\":[null,32,32],\"published\":[null,0,0]}}",
      day2+9000000000L );
  FD_TEST( !fd_gui_printf_timeline_query_agg( gui, "query_agg_shreds", "1s", FD_GUI_TIMELINE_GRANULARITY_1S,
                                              day2+9000000000L, 3UL, 33UL ) );
  test_http_expect( http, expected );

  FD_TEST( !fd_gui_printf_timeline_query_agg( gui, "query_agg_txn", "1s", FD_GUI_TIMELINE_GRANULARITY_1S,
                                              day2+9000000000L, 3UL, 136UL ) );
  fd_cstr_printf_check(
      expected, sizeof(expected), NULL,
      "{\"topic\":\"timeline\",\"key\":\"query_agg_txn\",\"id\":136,"
      "\"value\":{\"granularity\":\"1s\",\"reference_ts_ns\":\"%ld\","
      "\"success_nonvote_transactions\":[null,1,0],"
      "\"failed_nonvote_transactions\":[null,1,0],"
      "\"success_vote_transactions\":[null,0,1],"
      "\"failed_vote_transactions\":[null,0,1]}}",
      day2+9000000000L );
  test_http_expect( http, expected );

  FD_TEST( !fd_gui_printf_timeline_query_agg( gui, "query_agg_slots", "1s", FD_GUI_TIMELINE_GRANULARITY_1S,
                                              day2+9000000000L, 3UL, 34UL ) );
  fd_cstr_printf_check(
      expected, sizeof(expected), NULL,
      "{\"topic\":\"timeline\",\"key\":\"query_agg_slots\",\"id\":34,"
      "\"value\":{\"granularity\":\"1s\",\"reference_ts_ns\":\"%ld\","
      "\"start_slot\":[null,7000,7000],\"end_slot\":[null,7001,7001],"
      "\"skipped\":[null,null,null]}}",
      day2+9000000000L );
  test_http_expect( http, expected );

  FD_TEST( !fd_gui_printf_timeline_query_agg( gui, "query_agg_compute", "1s", FD_GUI_TIMELINE_GRANULARITY_1S,
                                              day2+9000000000L, 3UL, 35UL ) );
  fd_cstr_printf_check(
      expected, sizeof(expected), NULL,
      "{\"topic\":\"timeline\",\"key\":\"query_agg_compute\",\"id\":35,"
      "\"value\":{\"granularity\":\"1s\",\"reference_ts_ns\":\"%ld\","
      "\"compute_units\":[null,300,300],\"max_compute_units\":2000}}",
      day2+9000000000L );
  test_http_expect( http, expected );

  FD_TEST( !fd_gui_printf_timeline_query_agg( gui, "query_agg_revenue", "1s", FD_GUI_TIMELINE_GRANULARITY_1S,
                                              day2+9000000000L, 3UL, 36UL ) );
  fd_cstr_printf_check(
      expected, sizeof(expected), NULL,
      "{\"topic\":\"timeline\",\"key\":\"query_agg_revenue\",\"id\":36,"
      "\"value\":{\"granularity\":\"1s\",\"reference_ts_ns\":\"%ld\","
      "\"txn_fees\":[null,\"30\",\"30\"],"
      "\"prio_fees\":[null,\"3\",\"3\"],"
      "\"tips\":[null,\"3\",\"4\"]}}",
      day2+9000000000L );
  test_http_expect( http, expected );

  /* Root and tower changes do not subtract or move already recorded work. */
  gui->summary.slot_rooted         = 9999UL;
  gui->summary.slot_tower          = 10001UL;
  gui->summary.slot_tower_bank_seq = 77UL;
  FD_TEST( !fd_gui_printf_timeline_query_agg( gui, "query_agg_shreds", "1s", FD_GUI_TIMELINE_GRANULARITY_1S,
                                              day2+9000000000L, 3UL, 37UL ) );
  fd_cstr_printf_check(
      expected, sizeof(expected), NULL,
      "{\"topic\":\"timeline\",\"key\":\"query_agg_shreds\",\"id\":37,"
      "\"value\":{\"granularity\":\"1s\",\"reference_ts_ns\":\"%ld\","
      "\"turbine\":[null,24,16],\"repair\":[null,8,16],"
      "\"reconstructed\":[null,32,32],\"published\":[null,0,0]}}",
      day2+9000000000L );
  test_http_expect( http, expected );

  FD_TEST( !fd_gui_printf_timeline_query_agg( gui, "query_agg_txn", "1s", FD_GUI_TIMELINE_GRANULARITY_1S,
                                              day2+9000000000L, 3UL, 137UL ) );
  fd_cstr_printf_check(
      expected, sizeof(expected), NULL,
      "{\"topic\":\"timeline\",\"key\":\"query_agg_txn\",\"id\":137,"
      "\"value\":{\"granularity\":\"1s\",\"reference_ts_ns\":\"%ld\","
      "\"success_nonvote_transactions\":[null,1,0],"
      "\"failed_nonvote_transactions\":[null,1,0],"
      "\"success_vote_transactions\":[null,0,1],"
      "\"failed_vote_transactions\":[null,0,1]}}",
      day2+9000000000L );
  test_http_expect( http, expected );

  /* Crossing midnight creates the new day while retaining the preceding
     one.  A subsequently delivered event can still update that retained
     older day. */
  long const before_midnight = 3L*FD_GUI_TIMELINE_DAY_NS-500000000L;
  long const after_midnight  = 3L*FD_GUI_TIMELINE_DAY_NS+500000000L;
  fd_gui_timeline_handle_fec( gui, 8000UL, 0, before_midnight, 20U, 12U, 32U );
  fd_gui_timeline_handle_fec( gui, 8001UL, 1, after_midnight,   0U,  0U,  0U );
  FD_TEST( timeline_day_present( gui, 2UL ) );
  FD_TEST( timeline_day_present( gui, 3UL ) );

  FD_TEST( !fd_gui_printf_timeline_query_agg( gui, "query_agg_shreds", "1s", FD_GUI_TIMELINE_GRANULARITY_1S,
                                              3L*FD_GUI_TIMELINE_DAY_NS-1000000000L,
                                              2UL, 38UL ) );
  fd_cstr_printf_check(
      expected, sizeof(expected), NULL,
      "{\"topic\":\"timeline\",\"key\":\"query_agg_shreds\",\"id\":38,"
      "\"value\":{\"granularity\":\"1s\",\"reference_ts_ns\":\"%ld\","
      "\"turbine\":[20,0],\"repair\":[12,0],"
      "\"reconstructed\":[32,0],\"published\":[0,%lu]}}",
      3L*FD_GUI_TIMELINE_DAY_NS-1000000000L, fec_shred_cnt );
  test_http_expect( http, expected );

  /* Known zero is distinct from unknown. */
  long const zero_ts = 3L*FD_GUI_TIMELINE_DAY_NS+2100000000L;
  fd_gui_timeline_handle_txn( gui, 8100UL, zero_ts, 0UL, ULONG_MAX, 0UL, 0UL, 0UL, 0, 1 );
  FD_TEST( !fd_gui_printf_timeline_query_agg( gui, "query_agg_compute", "1s", FD_GUI_TIMELINE_GRANULARITY_1S,
                                              3L*FD_GUI_TIMELINE_DAY_NS+2000000000L,
                                              1UL, 39UL ) );
  fd_cstr_printf_check(
      expected, sizeof(expected), NULL,
      "{\"topic\":\"timeline\",\"key\":\"query_agg_compute\",\"id\":39,"
      "\"value\":{\"granularity\":\"1s\",\"reference_ts_ns\":\"%ld\","
      "\"compute_units\":[0],\"max_compute_units\": null}}",
      3L*FD_GUI_TIMELINE_DAY_NS+2000000000L );
  test_http_expect( http, expected );

  FD_TEST( !fd_gui_printf_timeline_query_agg( gui, "query_agg_txn", "1s", FD_GUI_TIMELINE_GRANULARITY_1S,
                                              3L*FD_GUI_TIMELINE_DAY_NS+2000000000L,
                                              1UL, 140UL ) );
  fd_cstr_printf_check(
      expected, sizeof(expected), NULL,
      "{\"topic\":\"timeline\",\"key\":\"query_agg_txn\",\"id\":140,"
      "\"value\":{\"granularity\":\"1s\",\"reference_ts_ns\":\"%ld\","
      "\"success_nonvote_transactions\":[1],\"failed_nonvote_transactions\":[0],"
      "\"success_vote_transactions\":[0],\"failed_vote_transactions\":[0]}}",
      3L*FD_GUI_TIMELINE_DAY_NS+2000000000L );
  test_http_expect( http, expected );

  FD_TEST( !fd_gui_printf_timeline_query_agg( gui, "query_agg_revenue", "1s", FD_GUI_TIMELINE_GRANULARITY_1S,
                                              3L*FD_GUI_TIMELINE_DAY_NS+2000000000L,
                                              1UL, 40UL ) );
  fd_cstr_printf_check(
      expected, sizeof(expected), NULL,
      "{\"topic\":\"timeline\",\"key\":\"query_agg_revenue\",\"id\":40,"
      "\"value\":{\"granularity\":\"1s\",\"reference_ts_ns\":\"%ld\","
      "\"txn_fees\":[\"0\"],\"prio_fees\":[\"0\"],\"tips\":[\"0\"]}}",
      3L*FD_GUI_TIMELINE_DAY_NS+2000000000L );
  test_http_expect( http, expected );

  /* Sums saturate below the unknown sentinel and max-compute takes the
     largest known limit. */
  long const saturated_ts = 3L*FD_GUI_TIMELINE_DAY_NS+3100000000L;
  fd_gui_timeline_handle_txn( gui, 8200UL, saturated_ts,
                              ULONG_MAX-2UL, 5000UL, ULONG_MAX-2UL, ULONG_MAX, ULONG_MAX-2UL, 0, 1 );
  fd_gui_timeline_handle_txn( gui, 8201UL, saturated_ts+250000000L,
                              10UL, 6000UL, 10UL, 5UL, 10UL, 0, 1 );
  fd_gui_hist_timeline_day_key_t day3_key = { .day=3UL };
  fd_gui_timeline_day_t * day3 = fd_gui_hist_kv_get( gui, FD_GUI_HIST_TIMELINE_DAY, &day3_key );
  FD_TEST( day3 );
  ulong saturated_idx0 = FD_GUI_TIMELINE_250MS_OFF+12UL;
  ulong saturated_idx1 = FD_GUI_TIMELINE_250MS_OFF+13UL;
  FD_TEST( day3->compute_units[ saturated_idx0 ]==ULONG_MAX-2UL );
  FD_TEST( day3->compute_units[ saturated_idx1 ]==10UL );
  day3->nonvote_success[ saturated_idx0 ] = ULONG_MAX-2UL;
  day3->nonvote_success[ saturated_idx1 ] = 10UL;

  FD_TEST( !fd_gui_printf_timeline_query_agg( gui, "query_agg_slots", "1s", FD_GUI_TIMELINE_GRANULARITY_1S,
                                              3L*FD_GUI_TIMELINE_DAY_NS+3000000000L, 1UL, 41UL ) );
  fd_cstr_printf_check(
      expected, sizeof(expected), NULL,
      "{\"topic\":\"timeline\",\"key\":\"query_agg_slots\",\"id\":41,"
      "\"value\":{\"granularity\":\"1s\",\"reference_ts_ns\":\"%ld\","
      "\"start_slot\":[8200],\"end_slot\":[8201],\"skipped\":[null]}}",
      3L*FD_GUI_TIMELINE_DAY_NS+3000000000L );
  test_http_expect( http, expected );

  FD_TEST( !fd_gui_printf_timeline_query_agg( gui, "query_agg_compute", "1s", FD_GUI_TIMELINE_GRANULARITY_1S,
                                              3L*FD_GUI_TIMELINE_DAY_NS+3000000000L, 1UL, 42UL ) );
  fd_cstr_printf_check(
      expected, sizeof(expected), NULL,
      "{\"topic\":\"timeline\",\"key\":\"query_agg_compute\",\"id\":42,"
      "\"value\":{\"granularity\":\"1s\",\"reference_ts_ns\":\"%ld\","
      "\"compute_units\":[%lu],\"max_compute_units\":6000}}",
      3L*FD_GUI_TIMELINE_DAY_NS+3000000000L, ULONG_MAX-1UL );
  test_http_expect( http, expected );

  FD_TEST( !fd_gui_printf_timeline_query_agg( gui, "query_agg_revenue", "1s", FD_GUI_TIMELINE_GRANULARITY_1S,
                                              3L*FD_GUI_TIMELINE_DAY_NS+3000000000L, 1UL, 43UL ) );
  fd_cstr_printf_check(
      expected, sizeof(expected), NULL,
      "{\"topic\":\"timeline\",\"key\":\"query_agg_revenue\",\"id\":43,"
      "\"value\":{\"granularity\":\"1s\",\"reference_ts_ns\":\"%ld\","
      "\"txn_fees\":[\"%lu\"],\"prio_fees\":[\"5\"],\"tips\":[\"%lu\"]}}",
      3L*FD_GUI_TIMELINE_DAY_NS+3000000000L, ULONG_MAX-1UL, ULONG_MAX-1UL );
  test_http_expect( http, expected );

  FD_TEST( !fd_gui_printf_timeline_query_agg( gui, "query_agg_txn", "1s", FD_GUI_TIMELINE_GRANULARITY_1S,
                                              3L*FD_GUI_TIMELINE_DAY_NS+3000000000L, 1UL, 143UL ) );
  fd_cstr_printf_check(
      expected, sizeof(expected), NULL,
      "{\"topic\":\"timeline\",\"key\":\"query_agg_txn\",\"id\":143,"
      "\"value\":{\"granularity\":\"1s\",\"reference_ts_ns\":\"%ld\","
      "\"success_nonvote_transactions\":[%lu],\"failed_nonvote_transactions\":[0],"
      "\"success_vote_transactions\":[0],\"failed_vote_transactions\":[0]}}",
      3L*FD_GUI_TIMELINE_DAY_NS+3000000000L, ULONG_MAX-1UL );
  test_http_expect( http, expected );

  /* Transaction classification is known even when compute and revenue fields
     are not, so the event still creates slot bounds and transaction counts. */
  long const unknown_ts = 3L*FD_GUI_TIMELINE_DAY_NS+4100000000L;
  fd_gui_timeline_handle_txn( gui, 8300UL, unknown_ts,
                              ULONG_MAX, ULONG_MAX, ULONG_MAX, ULONG_MAX, ULONG_MAX, 1, 0 );
  FD_TEST( !fd_gui_printf_timeline_query_agg( gui, "query_agg_slots", "1s", FD_GUI_TIMELINE_GRANULARITY_1S,
                                              3L*FD_GUI_TIMELINE_DAY_NS+4000000000L,
                                              1UL, 41UL ) );
  fd_cstr_printf_check(
      expected, sizeof(expected), NULL,
      "{\"topic\":\"timeline\",\"key\":\"query_agg_slots\",\"id\":41,"
      "\"value\":{\"granularity\":\"1s\",\"reference_ts_ns\":\"%ld\","
      "\"start_slot\":[8300],\"end_slot\":[8300],\"skipped\":[null]}}",
      3L*FD_GUI_TIMELINE_DAY_NS+4000000000L );
  test_http_expect( http, expected );

  FD_TEST( !fd_gui_printf_timeline_query_agg( gui, "query_agg_compute", "1s", FD_GUI_TIMELINE_GRANULARITY_1S,
                                              3L*FD_GUI_TIMELINE_DAY_NS+4000000000L,
                                              1UL, 144UL ) );
  fd_cstr_printf_check(
      expected, sizeof(expected), NULL,
      "{\"topic\":\"timeline\",\"key\":\"query_agg_compute\",\"id\":144,"
      "\"value\":{\"granularity\":\"1s\",\"reference_ts_ns\":\"%ld\","
      "\"compute_units\":[null],\"max_compute_units\": null}}",
      3L*FD_GUI_TIMELINE_DAY_NS+4000000000L );
  test_http_expect( http, expected );

  FD_TEST( !fd_gui_printf_timeline_query_agg( gui, "query_agg_revenue", "1s", FD_GUI_TIMELINE_GRANULARITY_1S,
                                              3L*FD_GUI_TIMELINE_DAY_NS+4000000000L,
                                              1UL, 145UL ) );
  fd_cstr_printf_check(
      expected, sizeof(expected), NULL,
      "{\"topic\":\"timeline\",\"key\":\"query_agg_revenue\",\"id\":145,"
      "\"value\":{\"granularity\":\"1s\",\"reference_ts_ns\":\"%ld\","
      "\"txn_fees\":[null],\"prio_fees\":[null],\"tips\":[null]}}",
      3L*FD_GUI_TIMELINE_DAY_NS+4000000000L );
  test_http_expect( http, expected );

  FD_TEST( !fd_gui_printf_timeline_query_agg( gui, "query_agg_txn", "1s", FD_GUI_TIMELINE_GRANULARITY_1S,
                                              3L*FD_GUI_TIMELINE_DAY_NS+4000000000L,
                                              1UL, 146UL ) );
  fd_cstr_printf_check(
      expected, sizeof(expected), NULL,
      "{\"topic\":\"timeline\",\"key\":\"query_agg_txn\",\"id\":146,"
      "\"value\":{\"granularity\":\"1s\",\"reference_ts_ns\":\"%ld\","
      "\"success_nonvote_transactions\":[0],\"failed_nonvote_transactions\":[0],"
      "\"success_vote_transactions\":[0],\"failed_vote_transactions\":[1]}}",
      3L*FD_GUI_TIMELINE_DAY_NS+4000000000L );
  test_http_expect( http, expected );

  /* A derived 500 ms bucket merges adjacent 250 ms stored buckets. */
  long const merge_ts0 = 3L*FD_GUI_TIMELINE_DAY_NS+5100000000L;
  long const merge_ts1 = 3L*FD_GUI_TIMELINE_DAY_NS+5300000000L;
  fd_gui_timeline_handle_fec( gui, 8401UL, 0, merge_ts0, 20U, 12U, 32U );
  fd_gui_timeline_handle_fec( gui, 8399UL, 1, merge_ts1,  0U,  0U,  0U );
  fd_gui_timeline_handle_txn( gui, 8401UL, merge_ts0, 10UL, 100UL, 1UL, 2UL, 3UL, 0, 1 );
  fd_gui_timeline_handle_txn( gui, 8399UL, merge_ts1, 20UL, 200UL, 4UL, 5UL, 6UL, 1, 0 );

  FD_TEST( !fd_gui_printf_timeline_query_agg( gui, "query_agg_shreds", "500ms", FD_GUI_TIMELINE_GRANULARITY_500MS,
                                              3L*FD_GUI_TIMELINE_DAY_NS+5000000000L, 1UL, 44UL ) );
  fd_cstr_printf_check(
      expected, sizeof(expected), NULL,
      "{\"topic\":\"timeline\",\"key\":\"query_agg_shreds\",\"id\":44,"
      "\"value\":{\"granularity\":\"500ms\",\"reference_ts_ns\":\"%ld\","
      "\"turbine\":[20],\"repair\":[12],\"reconstructed\":[32],\"published\":[%lu]}}",
      3L*FD_GUI_TIMELINE_DAY_NS+5000000000L, fec_shred_cnt );
  test_http_expect( http, expected );

  FD_TEST( !fd_gui_printf_timeline_query_agg( gui, "query_agg_txn", "500ms", FD_GUI_TIMELINE_GRANULARITY_500MS,
                                              3L*FD_GUI_TIMELINE_DAY_NS+5000000000L, 1UL, 147UL ) );
  fd_cstr_printf_check(
      expected, sizeof(expected), NULL,
      "{\"topic\":\"timeline\",\"key\":\"query_agg_txn\",\"id\":147,"
      "\"value\":{\"granularity\":\"500ms\",\"reference_ts_ns\":\"%ld\","
      "\"success_nonvote_transactions\":[1],\"failed_nonvote_transactions\":[0],"
      "\"success_vote_transactions\":[0],\"failed_vote_transactions\":[1]}}",
      3L*FD_GUI_TIMELINE_DAY_NS+5000000000L );
  test_http_expect( http, expected );

  FD_TEST( !fd_gui_printf_timeline_query_agg( gui, "query_agg_slots", "500ms", FD_GUI_TIMELINE_GRANULARITY_500MS,
                                              3L*FD_GUI_TIMELINE_DAY_NS+5000000000L, 1UL, 45UL ) );
  fd_cstr_printf_check(
      expected, sizeof(expected), NULL,
      "{\"topic\":\"timeline\",\"key\":\"query_agg_slots\",\"id\":45,"
      "\"value\":{\"granularity\":\"500ms\",\"reference_ts_ns\":\"%ld\","
      "\"start_slot\":[8399],\"end_slot\":[8401],\"skipped\":[null]}}",
      3L*FD_GUI_TIMELINE_DAY_NS+5000000000L );
  test_http_expect( http, expected );

  FD_TEST( !fd_gui_printf_timeline_query_agg( gui, "query_agg_compute", "500ms", FD_GUI_TIMELINE_GRANULARITY_500MS,
                                              3L*FD_GUI_TIMELINE_DAY_NS+5000000000L, 1UL, 46UL ) );
  fd_cstr_printf_check(
      expected, sizeof(expected), NULL,
      "{\"topic\":\"timeline\",\"key\":\"query_agg_compute\",\"id\":46,"
      "\"value\":{\"granularity\":\"500ms\",\"reference_ts_ns\":\"%ld\","
      "\"compute_units\":[30],\"max_compute_units\":200}}",
      3L*FD_GUI_TIMELINE_DAY_NS+5000000000L );
  test_http_expect( http, expected );

  FD_TEST( !fd_gui_printf_timeline_query_agg( gui, "query_agg_revenue", "500ms", FD_GUI_TIMELINE_GRANULARITY_500MS,
                                              3L*FD_GUI_TIMELINE_DAY_NS+5000000000L, 1UL, 47UL ) );
  fd_cstr_printf_check(
      expected, sizeof(expected), NULL,
      "{\"topic\":\"timeline\",\"key\":\"query_agg_revenue\",\"id\":47,"
      "\"value\":{\"granularity\":\"500ms\",\"reference_ts_ns\":\"%ld\","
      "\"txn_fees\":[\"5\"],\"prio_fees\":[\"7\"],\"tips\":[\"9\"]}}",
      3L*FD_GUI_TIMELINE_DAY_NS+5000000000L );
  test_http_expect( http, expected );

  /* Exercise every public-to-stored mapping with one contribution in each
     source bucket.  This also verifies that no query examines more than the
     descriptor's bounded merge count. */
  long const day4_ts = 4L*FD_GUI_TIMELINE_DAY_NS;
  fd_gui_timeline_handle_txn( gui, 9000UL, day4_ts, 0UL, 0UL, 0UL, 0UL, 0UL, 0, 1 );
  gui->timeline_skipped_coverage_start_ns = day4_ts;
  gui->timeline_skipped_coverage_end_ns   = day4_ts+FD_GUI_TIMELINE_DAY_NS;
  fd_gui_hist_timeline_day_key_t day4_key = { .day=4UL };
  fd_gui_timeline_day_t * day4 = fd_gui_hist_kv_get( gui, FD_GUI_HIST_TIMELINE_DAY, &day4_key );
  FD_TEST( day4 );
  for( ulong g=0UL; g<FD_GUI_TIMELINE_GRANULARITY_CNT; g++ ) {
    fd_gui_timeline_granularity_t const * granularity = &fd_gui_timeline_granularities[ g ];
    ulong stored_ns = fd_gui_timeline_stored_granularity_ns[ granularity->stored_idx ];
    memset( day4, 0xFF, sizeof(*day4) );
    day4->day = 4UL;
    for( ulong j=0UL; j<granularity->merge_cnt; j++ ) {
      ulong value = j+1UL;
      fd_gui_timeline_handle_txn( gui, 9000UL+j, day4_ts+(long)(j*stored_ns)+1L,
                                  value, 100UL+j, value, value, value, 0, 1 );
      ulong idx = fd_gui_timeline_stored_granularity_off[ granularity->stored_idx ]+j;
      day4->skipped[ idx ] = (uint)value;
    }
    ulong sum = granularity->merge_cnt*(granularity->merge_cnt+1UL)/2UL;

    FD_TEST( !fd_gui_printf_timeline_query_agg( gui, "query_agg_slots", granularity->name, g,
                                                day4_ts, 1UL, 100UL+g ) );
    fd_cstr_printf_check(
        expected, sizeof(expected), NULL,
        "{\"topic\":\"timeline\",\"key\":\"query_agg_slots\",\"id\":%lu,"
        "\"value\":{\"granularity\":\"%s\",\"reference_ts_ns\":\"%ld\","
        "\"start_slot\":[9000],\"end_slot\":[%lu],\"skipped\":[%lu]}}",
        100UL+g, granularity->name, day4_ts, 8999UL+granularity->merge_cnt, sum );
    test_http_expect( http, expected );

    FD_TEST( !fd_gui_printf_timeline_query_agg( gui, "query_agg_revenue", granularity->name, g,
                                                day4_ts, 1UL, 200UL+g ) );
    fd_cstr_printf_check(
        expected, sizeof(expected), NULL,
        "{\"topic\":\"timeline\",\"key\":\"query_agg_revenue\",\"id\":%lu,"
        "\"value\":{\"granularity\":\"%s\",\"reference_ts_ns\":\"%ld\","
        "\"txn_fees\":[\"%lu\"],\"prio_fees\":[\"%lu\"],\"tips\":[\"%lu\"]}}",
        200UL+g, granularity->name, day4_ts, sum, sum, sum );
    test_http_expect( http, expected );

    FD_TEST( !fd_gui_printf_timeline_query_agg( gui, "query_agg_txn", granularity->name, g,
                                                day4_ts, 1UL, 300UL+g ) );
    fd_cstr_printf_check(
        expected, sizeof(expected), NULL,
        "{\"topic\":\"timeline\",\"key\":\"query_agg_txn\",\"id\":%lu,"
        "\"value\":{\"granularity\":\"%s\",\"reference_ts_ns\":\"%ld\","
        "\"success_nonvote_transactions\":[%lu],\"failed_nonvote_transactions\":[0],"
        "\"success_vote_transactions\":[0],\"failed_vote_transactions\":[0]}}",
        300UL+g, granularity->name, day4_ts, granularity->merge_cnt );
    test_http_expect( http, expected );
  }

  /* The first optimistic-confirmation event backfills retained ancestry.
     Each skipped numeric slot is placed at the midpoint of its logical-slot
     segment, and later OC events only append beyond the exact watermark. */
  long const day5_ts = 5L*FD_GUI_TIMELINE_DAY_NS;
  put_oc_slot( gui, 10000UL, ULONG_MAX, day5_ts, LONG_MAX );
  put_oc_slot( gui, 10003UL, 10000UL, day5_ts+750000000L, day5_ts );

  gui->timeline_skipped_slot_watermark     = ULONG_MAX;
  gui->timeline_skipped_bank_seq_watermark = ULONG_MAX;
  gui->timeline_skipped_coverage_start_ns  = LONG_MAX;
  gui->timeline_skipped_coverage_end_ns    = LONG_MAX;
  gui->summary.slot_rooted                 = 9999UL;
  gui->summary.slot_tower                  = 10003UL;
  gui->summary.slot_tower_bank_seq         = BANK_SEQ;
  gui->summary.slot_optimistically_confirmed = ULONG_MAX;

  fd_gui_handle_oc_advanced( gui, 10003UL, BANK_SEQ, day5_ts+750000000L );
  FD_TEST( gui->timeline_skipped_slot_watermark==10003UL );
  FD_TEST( gui->timeline_skipped_coverage_start_ns==day5_ts );
  FD_TEST( gui->timeline_skipped_coverage_end_ns==day5_ts+750000000L );

  FD_TEST( !fd_gui_printf_timeline_query_agg( gui, "query_agg_slots", "250ms", FD_GUI_TIMELINE_GRANULARITY_250MS,
                                              day5_ts, 4UL, 48UL ) );
  fd_cstr_printf_check(
      expected, sizeof(expected), NULL,
      "{\"topic\":\"timeline\",\"key\":\"query_agg_slots\",\"id\":48,"
      "\"value\":{\"granularity\":\"250ms\",\"reference_ts_ns\":\"%ld\","
      "\"start_slot\":[null,null,null,null],\"end_slot\":[null,null,null,null],"
      "\"skipped\":[1,1,0,null]}}",
      day5_ts );
  test_http_expect( http, expected );

  put_oc_slot( gui, 10006UL, 10003UL, day5_ts+1500000000L, day5_ts+750000000L );
  gui->summary.slot_tower = 10006UL;
  fd_gui_handle_oc_advanced( gui, 10006UL, BANK_SEQ, day5_ts+1500000000L );
  fd_gui_handle_oc_advanced( gui, 10006UL, BANK_SEQ, day5_ts+1500000000L ); /* deduplicated */

  FD_TEST( !fd_gui_printf_timeline_query_agg( gui, "query_agg_slots", "250ms", FD_GUI_TIMELINE_GRANULARITY_250MS,
                                              day5_ts, 6UL, 49UL ) );
  fd_cstr_printf_check(
      expected, sizeof(expected), NULL,
      "{\"topic\":\"timeline\",\"key\":\"query_agg_slots\",\"id\":49,"
      "\"value\":{\"granularity\":\"250ms\",\"reference_ts_ns\":\"%ld\","
      "\"start_slot\":[null,null,null,null,null,null],"
      "\"end_slot\":[null,null,null,null,null,null],\"skipped\":[1,1,0,1,1,0]}}",
      day5_ts );
  test_http_expect( http, expected );

  FD_TEST( !fd_gui_printf_timeline_query_agg( gui, "query_agg_slots", "500ms", FD_GUI_TIMELINE_GRANULARITY_500MS,
                                              day5_ts, 3UL, 50UL ) );
  fd_cstr_printf_check(
      expected, sizeof(expected), NULL,
      "{\"topic\":\"timeline\",\"key\":\"query_agg_slots\",\"id\":50,"
      "\"value\":{\"granularity\":\"500ms\",\"reference_ts_ns\":\"%ld\","
      "\"start_slot\":[null,null,null],\"end_slot\":[null,null,null],\"skipped\":[2,1,1]}}",
      day5_ts );
  test_http_expect( http, expected );

  /* Interpolation and coverage remain coherent across UTC midnight. */
  long const day6_ts = 6L*FD_GUI_TIMELINE_DAY_NS;
  put_oc_slot( gui, 20000UL, ULONG_MAX, day6_ts-250000000L, LONG_MAX );
  put_oc_slot( gui, 20003UL, 20000UL, day6_ts+500000000L, day6_ts-250000000L );
  gui->timeline_skipped_slot_watermark       = ULONG_MAX;
  gui->timeline_skipped_bank_seq_watermark   = ULONG_MAX;
  gui->timeline_skipped_coverage_start_ns    = LONG_MAX;
  gui->timeline_skipped_coverage_end_ns      = LONG_MAX;
  gui->summary.slot_rooted                   = 19999UL;
  gui->summary.slot_tower                    = 20003UL;
  gui->summary.slot_tower_bank_seq           = BANK_SEQ;
  gui->summary.slot_optimistically_confirmed = ULONG_MAX;
  fd_gui_handle_oc_advanced( gui, 20003UL, BANK_SEQ, day6_ts+500000000L );

  FD_TEST( !fd_gui_printf_timeline_query_agg( gui, "query_agg_slots", "250ms", FD_GUI_TIMELINE_GRANULARITY_250MS,
                                              day6_ts-250000000L, 3UL, 51UL ) );
  fd_cstr_printf_check(
      expected, sizeof(expected), NULL,
      "{\"topic\":\"timeline\",\"key\":\"query_agg_slots\",\"id\":51,"
      "\"value\":{\"granularity\":\"250ms\",\"reference_ts_ns\":\"%ld\","
      "\"start_slot\":[null,null,null],\"end_slot\":[null,null,null],\"skipped\":[1,1,0]}}",
      day6_ts-250000000L );
  test_http_expect( http, expected );

  /* Derived skipped counts saturate below the uint unknown sentinel. */
  long const day7_ts = 7L*FD_GUI_TIMELINE_DAY_NS;
  fd_gui_timeline_handle_txn( gui, 30000UL, day7_ts, 0UL, 0UL, 0UL, 0UL, 0UL, 0, 1 );
  fd_gui_hist_timeline_day_key_t day7_key = { .day=7UL };
  fd_gui_timeline_day_t * day7 = fd_gui_hist_kv_get( gui, FD_GUI_HIST_TIMELINE_DAY, &day7_key );
  FD_TEST( day7 );
  day7->skipped[ FD_GUI_TIMELINE_250MS_OFF     ] = UINT_MAX-2U;
  day7->skipped[ FD_GUI_TIMELINE_250MS_OFF+1UL ] = 10U;
  gui->timeline_skipped_coverage_start_ns = day7_ts;
  gui->timeline_skipped_coverage_end_ns   = day7_ts+500000000L;
  FD_TEST( !fd_gui_printf_timeline_query_agg( gui, "query_agg_slots", "500ms", FD_GUI_TIMELINE_GRANULARITY_500MS,
                                              day7_ts, 1UL, 52UL ) );
  fd_cstr_printf_check(
      expected, sizeof(expected), NULL,
      "{\"topic\":\"timeline\",\"key\":\"query_agg_slots\",\"id\":52,"
      "\"value\":{\"granularity\":\"500ms\",\"reference_ts_ns\":\"%ld\","
      "\"start_slot\":[30000],\"end_slot\":[30000],\"skipped\":[%u]}}",
      day7_ts, UINT_MAX-1U );
  test_http_expect( http, expected );

  /* A midpoint exactly on a bucket boundary belongs to the bucket beginning
     at that timestamp, matching the half-open query convention. */
  long const day8_ts = 8L*FD_GUI_TIMELINE_DAY_NS;
  put_oc_slot( gui, 40000UL, ULONG_MAX, day8_ts, LONG_MAX );
  put_oc_slot( gui, 40003UL, 40000UL, day8_ts+1500000000L, day8_ts );
  gui->timeline_skipped_slot_watermark       = ULONG_MAX;
  gui->timeline_skipped_bank_seq_watermark   = ULONG_MAX;
  gui->timeline_skipped_coverage_start_ns    = LONG_MAX;
  gui->timeline_skipped_coverage_end_ns      = LONG_MAX;
  gui->summary.slot_rooted                   = 39999UL;
  gui->summary.slot_tower                    = 40003UL;
  gui->summary.slot_tower_bank_seq           = BANK_SEQ;
  gui->summary.slot_optimistically_confirmed = ULONG_MAX;
  fd_gui_handle_oc_advanced( gui, 40003UL, BANK_SEQ, day8_ts+1500000000L );

  FD_TEST( !fd_gui_printf_timeline_query_agg( gui, "query_agg_slots", "250ms", FD_GUI_TIMELINE_GRANULARITY_250MS,
                                              day8_ts, 6UL, 53UL ) );
  fd_cstr_printf_check(
      expected, sizeof(expected), NULL,
      "{\"topic\":\"timeline\",\"key\":\"query_agg_slots\",\"id\":53,"
      "\"value\":{\"granularity\":\"250ms\",\"reference_ts_ns\":\"%ld\","
      "\"start_slot\":[null,null,null,null,null,null],"
      "\"end_slot\":[null,null,null,null,null,null],\"skipped\":[0,1,0,1,0,0]}}",
      day8_ts );
  test_http_expect( http, expected );

  /* The result begins exactly at the requested bucket and contains exactly
     the requested number of dense buckets, even when the left edge is empty. */
  long const dense_start = day2-100L*1000000000L;
  FD_TEST( !fd_gui_printf_timeline_query_agg( gui, "query_agg_slots", "1s", FD_GUI_TIMELINE_GRANULARITY_1S,
                                              dense_start, FD_GUI_TIMELINE_QUERY_MAX_BUCKETS, 42UL ) );
  char * json = malloc( http->stage_len+1UL );
  FD_TEST( json );
  fd_memcpy( json, http->oring+(http->stage_off%http->oring_sz), http->stage_len );
  json[ http->stage_len ] = '\0';
  char reference[ 96 ];
  fd_cstr_printf_check( reference, sizeof(reference), NULL, "\"reference_ts_ns\":\"%ld\"", dense_start );
  FD_TEST( strstr( json, reference ) );
  FD_TEST( test_json_array_cnt( json, "start_slot" )==FD_GUI_TIMELINE_QUERY_MAX_BUCKETS );
  FD_TEST( test_json_array_cnt( json, "end_slot"   )==FD_GUI_TIMELINE_QUERY_MAX_BUCKETS );
  FD_TEST( test_json_array_cnt( json, "skipped"    )==FD_GUI_TIMELINE_QUERY_MAX_BUCKETS );
  FD_TEST( !strstr( json, "mutable_bucket_ts_ns" ) );
  free( json );
  fd_http_server_unstage( http );

  /* Full websocket dispatch retains strict parsing and the half-open
     150-bucket limit. */
#define WS_REQ(json_text,expect) do {                                             \
    char const * _json = (json_text);                                             \
    FD_TEST( fd_gui_ws_message( gui, 0UL, (uchar const *)_json, strlen( _json ) )==(expect) ); \
  } while(0)
  for( ulong i=0UL; i<FD_GUI_TIMELINE_GRANULARITY_CNT; i++ ) {
    char request[ 256 ];
    fd_cstr_printf_check( request, sizeof(request), NULL,
                          "{\"topic\":\"timeline\",\"key\":\"query_agg_revenue\",\"id\":1,"
                          "\"params\":{\"start_ns\":\"0\",\"end_ns\":\"1\",\"granularity\":\"%s\"}}",
                          fd_gui_timeline_granularities[ i ].name );
    WS_REQ( request, 0 );
  }
  static char const * const aggregate_keys[] = {
    "query_agg_slots", "query_agg_shreds", "query_agg_compute", "query_agg_txn", "query_agg_revenue"
  };
  for( ulong i=0UL; i<sizeof(aggregate_keys)/sizeof(aggregate_keys[ 0 ]); i++ ) {
    char request[ 256 ];
    fd_cstr_printf_check( request, sizeof(request), NULL,
                          "{\"topic\":\"timeline\",\"key\":\"%s\",\"id\":1,"
                          "\"params\":{\"start_ns\":\"0\",\"end_ns\":\"1\",\"granularity\":\"250ms\"}}",
                          aggregate_keys[ i ] );
    WS_REQ( request, 0 );
    fd_cstr_printf_check( request, sizeof(request), NULL,
                          "{\"topic\":\"timeline\",\"key\":\"%s\",\"id\":1,"
                          "\"params\":{\"start_ns\":\"0\",\"end_ns\":\"1\",\"granularity\":\"500ms\"}}",
                          aggregate_keys[ i ] );
    WS_REQ( request, 0 );
  }
  WS_REQ( "{\"topic\":\"timeline\",\"key\":\"query_agg_slots\",\"id\":1,"
          "\"params\":{\"start_ns\":\"0\",\"end_ns\":\"37500000000\","
          "\"granularity\":\"250ms\"}}", 0 );
  WS_REQ( "{\"topic\":\"timeline\",\"key\":\"query_agg_slots\",\"id\":1,"
          "\"params\":{\"start_ns\":\"0\",\"end_ns\":\"37500000001\","
          "\"granularity\":\"250ms\"}}", FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST );
  WS_REQ( "{\"topic\":\"timeline\",\"key\":\"query_agg_slots\",\"id\":1,"
          "\"params\":{\"start_ns\":\"0\",\"end_ns\":\"75000000000\","
          "\"granularity\":\"500ms\"}}", 0 );
  WS_REQ( "{\"topic\":\"timeline\",\"key\":\"query_agg_slots\",\"id\":1,"
          "\"params\":{\"start_ns\":\"0\",\"end_ns\":\"75000000001\","
          "\"granularity\":\"500ms\"}}", FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST );
  WS_REQ( "{\"topic\":\"timeline\",\"key\":\"query_agg_slots\",\"id\":1,"
          "\"params\":{\"start_ns\":\"0\",\"end_ns\":\"150000000000\","
          "\"granularity\":\"1s\"}}", 0 );
  WS_REQ( "{\"topic\":\"timeline\",\"key\":\"query_agg_revenue\",\"id\":1,"
          "\"params\":{\"start_ns\":\"0\",\"end_ns\":\"150000000001\","
          "\"granularity\":\"1s\"}}", FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST );
  WS_REQ( "{\"topic\":\"timeline\",\"key\":\"query_agg_revenue\",\"id\":1,"
          "\"params\":{\"start_ns\":0,\"end_ns\":\"1\",\"granularity\":\"1s\"}}",
          FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST );
  WS_REQ( "{\"topic\":\"timeline\",\"key\":\"query_agg_revenue\",\"id\":1,"
          "\"params\":{\"start_ns\":\"0\",\"end_ns\":\"0\",\"granularity\":\"1s\"}}",
          FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST );
  WS_REQ( "{\"topic\":\"timeline\",\"key\":\"query_agg_revenue\",\"id\":1,"
          "\"params\":{\"start_ns\":\"0\",\"end_ns\":\"1\",\"granularity\":\"5s\"}}",
          FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST );
#undef WS_REQ

  FD_TEST( fd_alloc_delete( fd_alloc_leave( gui->alloc ) )==alloc_mem );
  fd_wksp_free_laddr( alloc_mem );
  fd_wksp_delete_anonymous( wksp );
  gui->alloc = NULL;
  gui->http = NULL;
  free( fd_http_server_delete( fd_http_server_leave( http ) ) );
  FD_LOG_NOTICE(( "test_timeline_agg_queries: ok" ));
}

static void
test_timeline_day_order( fd_gui_t * gui ) {
  long const day10_ts = 10L*FD_GUI_TIMELINE_DAY_NS+1000000000L;

  /* The first event pre-creates its preceding day, keeping initial insertion
     monotonic and making the common previous-day late-arrival case writable. */
  fd_gui_timeline_handle_fec( gui, 100UL, 0, day10_ts, 20U, 12U, 32U );
  FD_TEST( timeline_day_present( gui, 9UL  ) );
  FD_TEST( timeline_day_present( gui, 10UL ) );

  fd_gui_hist_timeline_day_key_t hi = { .day=10UL };
  ulong budget = ULONG_MAX;
  int drained = 0;
  FD_TEST( fd_gui_store_kv_evict( gui->db, FD_GUI_HIST_TIMELINE_DAY, &hi, &budget, &drained )==FD_GUI_STORE_SUCCESS );
  FD_TEST( drained );
  FD_TEST( !timeline_day_present( gui, 9UL  ) );
  FD_TEST(  timeline_day_present( gui, 10UL ) );

  /* A late FEC completion for an evicted day is dropped instead of reordering
     the KV ring.  Advancing across a gap creates only the immediately
     preceding day and the event day, oldest first. */
  fd_gui_timeline_handle_fec( gui, 99UL, 0,
                              9L*FD_GUI_TIMELINE_DAY_NS+2000000000L,
                              20U, 12U, 32U );
  FD_TEST( !timeline_day_present( gui, 9UL ) );

  fd_gui_timeline_handle_fec( gui, 102UL, 0,
                              12L*FD_GUI_TIMELINE_DAY_NS+1000000000L,
                              20U, 12U, 32U );
  FD_TEST( timeline_day_present( gui, 11UL ) );
  FD_TEST( timeline_day_present( gui, 12UL ) );

  FD_LOG_NOTICE(( "test_timeline_day_order: ok" ));
}

static void
test_timeline_aggregates( fd_gui_t * gui ) {
  ulong expected_off = 0UL;
  for( ulong g=0UL; g<FD_GUI_TIMELINE_STORED_GRANULARITY_CNT; g++ ) {
    ulong stored_ns = fd_gui_timeline_stored_granularity_ns[ g ];
    FD_TEST( stored_ns && !((ulong)FD_GUI_TIMELINE_DAY_NS%stored_ns) );
    FD_TEST( fd_gui_timeline_stored_granularity_off[ g ]==expected_off );
    expected_off += (ulong)FD_GUI_TIMELINE_DAY_NS/stored_ns;
  }
  FD_TEST( expected_off==FD_GUI_TIMELINE_BUCKET_CNT );
  for( ulong g=0UL; g<FD_GUI_TIMELINE_GRANULARITY_CNT; g++ ) {
    fd_gui_timeline_granularity_t const * granularity = &fd_gui_timeline_granularities[ g ];
    FD_TEST( granularity->name && granularity->name[ 0 ] );
    FD_TEST( granularity->stored_idx<FD_GUI_TIMELINE_STORED_GRANULARITY_CNT );
    FD_TEST( granularity->merge_cnt && granularity->merge_cnt<=FD_GUI_TIMELINE_MAX_MERGE_CNT );
    FD_TEST( granularity->duration_ns==
             granularity->merge_cnt*fd_gui_timeline_stored_granularity_ns[ granularity->stored_idx ] );
    FD_TEST( !((ulong)FD_GUI_TIMELINE_DAY_NS%granularity->duration_ns) );
  }

  fd_gui_slot_t completed[ 1 ];
  memset( completed, 0xFF, sizeof(completed) );

  ulong const slot = 5000UL;
  long const t1    = 1100000000L;
  fd_gui_timeline_handle_shred( gui, slot, SHRED_SIG_SRC_TURBINE       );
  fd_gui_timeline_handle_shred( gui, slot, SHRED_SIG_SRC_TURBINE       );
  fd_gui_timeline_handle_shred( gui, slot, SHRED_SIG_SRC_REPAIR        );
  fd_gui_timeline_handle_shred( gui, slot, SHRED_SIG_SRC_RECONSTRUCTED );
  fd_gui_timeline_handle_fec  ( gui, slot, 0, t1, 20U, 12U, 32U );
  fd_gui_timeline_complete_slot( gui, slot, completed );
  FD_TEST( completed->block_shred_cnt==2U*FD_FEC_SHRED_CNT );
  FD_TEST( completed->turbine_shred_cnt==2U );
  FD_TEST( completed->repair_shred_cnt==1U );
  FD_TEST( completed->reconstructed_shred_cnt==1U );
  FD_TEST( completed->published_shred_cnt==UINT_MAX );

  fd_gui_hist_timeline_day_key_t key = { .day=0UL };
  fd_gui_timeline_day_t const * day = fd_gui_hist_kv_get( gui, FD_GUI_HIST_TIMELINE_DAY, &key );
  FD_TEST( day );
  for( ulong g=0UL; g<FD_GUI_TIMELINE_STORED_GRANULARITY_CNT; g++ ) {
    ulong idx = fd_gui_timeline_stored_granularity_off[ g ]+
                (ulong)t1/fd_gui_timeline_stored_granularity_ns[ g ];
    FD_TEST( day->start_slot   [ idx ]==slot );
    FD_TEST( day->end_slot     [ idx ]==slot );
    FD_TEST( day->turbine      [ idx ]==20UL );
    FD_TEST( day->repair       [ idx ]==12UL );
    FD_TEST( day->reconstructed[ idx ]==32UL );
    FD_TEST( day->published    [ idx ]==0UL );
  }

  /* Raw shred observations only feed per-slot detail.  They do not create an
     aggregate contribution until an FEC completes.  A newer alias replaces
     an older direct-mapped accumulator entry, and a subsequent old repair
     observation cannot evict the newer slot. */
  ulong const newer = slot+FD_GUI_TIMELINE_SHRED_BUF_CNT;
  fd_gui_timeline_handle_shred( gui, newer, SHRED_SIG_SRC_TURBINE );
  fd_gui_timeline_handle_shred( gui, slot,  SHRED_SIG_SRC_REPAIR  );
  memset( completed, 0xFF, sizeof(completed) );
  fd_gui_timeline_complete_slot( gui, newer, completed );
  FD_TEST( completed->turbine_shred_cnt==1U );
  FD_TEST( completed->repair_shred_cnt==0U );
  FD_TEST( day->turbine      [ FD_GUI_TIMELINE_250MS_OFF+8UL  ]==ULONG_MAX );
  FD_TEST( day->repair       [ FD_GUI_TIMELINE_250MS_OFF+12UL ]==ULONG_MAX );
  FD_TEST( day->reconstructed[ FD_GUI_TIMELINE_250MS_OFF+12UL ]==ULONG_MAX );
  FD_TEST( day->published    [ FD_GUI_TIMELINE_250MS_OFF+12UL ]==ULONG_MAX );
  FD_TEST( day->start_slot   [ FD_GUI_TIMELINE_250MS_OFF+12UL ]==ULONG_MAX );
  FD_TEST( day->end_slot     [ FD_GUI_TIMELINE_250MS_OFF+12UL ]==ULONG_MAX );

  /* A completion drains transient state even if slot persistence could not
     supply a destination record. */
  fd_gui_timeline_handle_shred( gui, newer+1UL, SHRED_SIG_SRC_REPAIR );
  fd_gui_timeline_complete_slot( gui, newer+1UL, NULL );
  memset( completed, 0xFF, sizeof(completed) );
  fd_gui_timeline_complete_slot( gui, newer+1UL, completed );
  FD_TEST( completed->repair_shred_cnt==UINT_MAX );

  /* Transaction metrics use commit/cancel completion time, and the same slot
     can contribute to multiple buckets. */
  fd_gui_timeline_handle_txn( gui, slot, 5100000000L, 1234UL, 48000000UL, 11UL, 12UL, 13UL, 0, 1 );
  fd_gui_timeline_handle_txn( gui, slot, 6100000000L, 7UL,    47000000UL,  1UL,  2UL,  3UL, 1, 0 );
  ulong idx5 = FD_GUI_TIMELINE_250MS_OFF+20UL;
  ulong idx6 = FD_GUI_TIMELINE_250MS_OFF+24UL;
  FD_TEST( day->start_slot   [ idx5 ]==slot && day->end_slot[ idx5 ]==slot );
  FD_TEST( day->start_slot   [ idx6 ]==slot && day->end_slot[ idx6 ]==slot );
  FD_TEST( day->compute_units[ idx5 ]==1234UL );
  FD_TEST( day->compute_units[ idx6 ]==7UL );
  FD_TEST( day->max_compute  [ idx5 ]==48000000UL );
  FD_TEST( day->max_compute  [ idx6 ]==47000000UL );
  FD_TEST( day->txn_fees     [ idx5 ]==11UL );
  FD_TEST( day->prio_fees    [ idx5 ]==12UL );
  FD_TEST( day->tips         [ idx5 ]==13UL );
  FD_TEST( day->nonvote_success[ idx5 ]==1UL );
  FD_TEST( day->nonvote_failed [ idx5 ]==0UL );
  FD_TEST( day->vote_success   [ idx5 ]==0UL );
  FD_TEST( day->vote_failed    [ idx5 ]==0UL );
  FD_TEST( day->nonvote_success[ idx6 ]==0UL );
  FD_TEST( day->nonvote_failed [ idx6 ]==0UL );
  FD_TEST( day->vote_success   [ idx6 ]==0UL );
  FD_TEST( day->vote_failed    [ idx6 ]==1UL );

  FD_TEST( FD_GUI_TIMELINE_BUCKET_CNT==395390UL );
  FD_TEST( sizeof(fd_gui_timeline_day_t)==49028368UL );
  FD_TEST( FD_GUI_STORE_REGION_SZ/sizeof(fd_gui_timeline_day_t)==1UL );
  FD_LOG_NOTICE(( "test_timeline_aggregates: ok" ));
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

  /* shred events: one per slot at the slot's own completion second */
  for( ulong s=A_START_SLOT; s<=C_END_SLOT; s++ ) {
    append_shred( gui, epoch_slot_complete_ns( s ), s );
    append_fec_event( gui, epoch_slot_complete_ns( s ), s, 0UL, FD_GUI_SLOT_SHRED_REPAIR_REQUEST );
    append_replay_txn( gui, epoch_slot_complete_ns( s ), s );
    append_replay_txn_batch( gui, epoch_slot_complete_ns( s ), s, 0UL );
  }

  /* boundary case: a shred for epoch B's first slot (1010) that landed in
     window 86399 -- the same second as epoch A's last slot (1009).  Eviction
     of epoch A bounds the window there, but the slot watermark
     (1010 > 1009) must keep this row. */
  append_shred( gui, sec_ns( 86399UL ), B_START_SLOT );
  append_fec_event( gui, sec_ns( 86399UL ), B_START_SLOT, 0UL, FD_GUI_SLOT_SHRED_REPAIR_REQUEST );

  /* Day zero is owned exclusively by epoch A.  Day one belongs to epoch B
     and must survive eviction of epoch A. */
  fd_gui_timeline_handle_fec( gui, A_END_SLOT,   0, sec_ns( 86399UL ), 20U, 12U, 32U );
  fd_gui_timeline_handle_fec( gui, B_START_SLOT, 0, sec_ns( 86400UL ), 20U, 12U, 32U );
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
  FD_TEST( count_ts( gui, FD_GUI_HIST_SCHEDULER_COUNTS, ULONG_MAX )==30UL ); /* secs 10..39 */
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

  /* time-series: epoch A's ten windows are gone and epochs B+C stay. */
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
     epoch A's 10 in-order slot rows (windows 10..19) are evicted, epochs B+C's
     20 rows (windows 20..39) are kept, and the straggler boundary row
     survives: 21 live rows, with slot 1010 keeping its own row plus the
     boundary row. */
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
    append_fec_event( gui, slot_complete_ns( 1000UL + (s-BIG_START_SLOT) ), s, 0UL, FD_GUI_SLOT_SHRED_REPAIR_REQUEST );
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
    append_fec_event( gui, sec_ns( sec ), TS_START_SLOT + (sec-50UL), 0UL, FD_GUI_SLOT_SHRED_REPAIR_REQUEST );
    append_replay_txn_batch( gui, sec_ns( sec ), TS_START_SLOT + (sec-50UL), 0UL );
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

  s->gui = aligned_alloc( fd_gui_align(), fd_gui_footprint( 1UL ) );
  FD_TEST( s->gui );
  memset( s->gui, 0, fd_gui_footprint( 1UL ) );
  s->gui->timeline_day_max = ULONG_MAX;
  s->gui->timeline_skipped_slot_watermark     = ULONG_MAX;
  s->gui->timeline_skipped_bank_seq_watermark = ULONG_MAX;
  s->gui->timeline_skipped_coverage_start_ns  = LONG_MAX;
  s->gui->timeline_skipped_coverage_end_ns    = LONG_MAX;
  for( ulong i=0UL; i<FD_GUI_TIMELINE_SHRED_BUF_CNT; i++ ) s->gui->timeline_shreds[ i ].slot = ULONG_MAX;

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
test_waterfall_snapshots( fd_gui_t * gui ) {
  fd_topo_t * topo = calloc( 1UL, sizeof(fd_topo_t) );
  FD_TEST( topo );
  gui->topo = topo;
  gui->leader_slot_pending     = ULONG_MAX;
  gui->leader_bank_seq_pending = ULONG_MAX;
  memset( gui->summary.txn_waterfall_reference, 0, sizeof(gui->summary.txn_waterfall_reference) );

  fd_done_packing_t done_packing = {0};
  fd_gui_txn_waterfall_t zero = {0};

  fd_gui_leader_slot_t * first = fd_gui_slot_leader_get_or_create( gui, 100UL, 11UL );
  FD_TEST( first );
  fd_gui_unbecame_leader( gui, 100UL, &done_packing );
  FD_TEST( !first->has_waterfall );
  FD_TEST( gui->leader_slot_pending==100UL && gui->leader_bank_seq_pending==11UL );
  fd_gui_done_draining( gui, 123L );
  FD_TEST( first->has_waterfall );
  FD_TEST( !memcmp( first->waterfall_reference, &zero, sizeof(zero) ) );
  FD_TEST( first->waterfall->sample_time_nanos==123L );
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
  FD_TEST( second->waterfall->sample_time_nanos==456L );
  FD_TEST( !memcmp( gui->summary.txn_waterfall_reference, second->waterfall, sizeof(fd_gui_txn_waterfall_t) ) );

  fd_gui_unbecame_leader( gui, 104UL, &done_packing );
  fd_gui_done_draining( gui, 789L );
  FD_TEST( !memcmp( second->waterfall_reference, first->waterfall, sizeof(fd_gui_txn_waterfall_t) ) );
  FD_TEST( second->waterfall->sample_time_nanos==456L );

  free( topo );
  FD_LOG_NOTICE(( "test_waterfall_snapshots: ok" ));
}

static void
test_timeline_queries( fd_gui_t * gui ) {
  long const start_ns = 10000000000L;
  long const end_ns   = start_ns + 1000L;

  fd_gui_hist_slot_key_t canonical_keys[ 3 ] = {
    { .slot=9UL,  .bank_seq=1UL },
    { .slot=10UL, .bank_seq=1UL },
    { .slot=11UL, .bank_seq=1UL },
  };
  long const canonical_completed_time[ 3 ] = {
    start_ns-20L,
    start_ns+50L,
    end_ns,
  };
  for( ulong i=0UL; i<3UL; i++ ) {
    fd_gui_slot_t * slot = fd_gui_hist_kv_get_or_create( gui, FD_GUI_HIST_SLOT, &canonical_keys[ i ] );
    FD_TEST( slot );
    memset( slot, 0xFF, sizeof(*slot) );
    slot->slot            = canonical_keys[ i ].slot;
    slot->bank_seq        = canonical_keys[ i ].bank_seq;
    slot->parent_slot     = canonical_keys[ i ].slot-1UL;
    slot->parent_bank_seq = canonical_keys[ i ].bank_seq;
    slot->completed_time  = canonical_completed_time[ i ];
    slot->skip            = FD_GUI_SKIP_STATUS_NOT_SKIPPED;
    slot->level           = FD_GUI_SLOT_LEVEL_ROOTED;
  }
  gui->summary.slot_rooted         = 13UL;
  gui->summary.slot_tower          = 13UL;
  gui->summary.slot_tower_bank_seq = 1UL;

  fd_gui_store_replay_txn_t a = {
    .completion_time_ns      = start_ns,
    .slot                    = 11UL,
    .txn_idx                 = 2UL,
    .txn_exec_idx            = 1UL,
    .txn_sigverify_exec_idx  = 3UL,
    .sigverify_start_ns      = start_ns-5L,
    .sigverify_end_ns        = start_ns,
    .load_start_ns           = start_ns-3L,
    .check_start_ns          = start_ns-2L,
    .exec_start_ns           = LONG_MAX,
    .commit_start_ns         = LONG_MAX,
    .commit_end_ns           = start_ns-1L,
    .transaction_fee         = 5000UL,
    .priority_fee            = 1200UL,
    .tips                    = 7UL,
    .compute_units_requested = 3428U,
    .compute_units_consumed  = 3000U,
    .error_code              = 9U,
    .is_committable          = 1U,
    .is_fees_only            = 0U,
    .is_simple_vote          = 1U
  };
  fd_gui_store_replay_txn_t b = {
    .completion_time_ns      = end_ns,
    .slot                    = 10UL,
    .txn_idx                 = 5UL,
    .txn_exec_idx            = 0UL,
    .txn_sigverify_exec_idx  = 2UL,
    .sigverify_start_ns      = start_ns-10L,
    .sigverify_end_ns        = end_ns-1L,
    .load_start_ns           = start_ns-8L,
    .check_start_ns          = LONG_MAX,
    .exec_start_ns           = start_ns-7L,
    .commit_start_ns         = start_ns-6L,
    .commit_end_ns           = end_ns,
    .transaction_fee         = 0UL,
    .priority_fee            = 0UL,
    .tips                    = 0UL,
    .compute_units_requested = 0U,
    .compute_units_consumed  = 0U,
    .error_code              = 3U,
    .is_committable          = 0U,
    .is_fees_only            = 0U,
    .is_simple_vote          = 0U
  };
  fd_gui_store_replay_txn_t outside = b;
  outside.completion_time_ns = end_ns+1L;
  outside.slot               = 12UL;
  outside.txn_idx            = 99UL;

  FD_TEST( !fd_gui_hist_ts_append( gui, FD_GUI_HIST_REPLAY_TXN, a.completion_time_ns,       a.completion_time_ns,       &a       ) );
  FD_TEST( !fd_gui_hist_ts_append( gui, FD_GUI_HIST_REPLAY_TXN, b.completion_time_ns,       b.completion_time_ns,       &b       ) );
  FD_TEST( !fd_gui_hist_ts_append( gui, FD_GUI_HIST_REPLAY_TXN, outside.completion_time_ns, outside.completion_time_ns, &outside ) );

  fd_http_server_params_t params = {
    .max_connection_cnt    = 1UL,
    .max_ws_connection_cnt = 1UL,
    .max_request_len       = 1024UL,
    .max_ws_recv_frame_len = 1024UL,
    .max_ws_send_frame_cnt = 1UL,
    .outgoing_buffer_sz    = FD_GUI_HTTP_MIN_SEND_BUFFER_SZ
  };
  fd_http_server_callbacks_t callbacks = {0};
  ulong http_footprint = fd_http_server_footprint( params );
  void * http_mem = aligned_alloc( fd_http_server_align(), fd_ulong_align_up( http_footprint, fd_http_server_align() ) );
  FD_TEST( http_mem );
  gui->http = fd_http_server_join( fd_http_server_new( http_mem, params, callbacks, NULL ) );
  FD_TEST( gui->http );

  fd_wksp_t * wksp = fd_wksp_new_anonymous( FD_SHMEM_NORMAL_PAGE_SZ, 4096UL, 0UL, "gui_query", 0UL );
  FD_TEST( wksp );
  void * alloc_mem = fd_wksp_alloc_laddr( wksp, fd_alloc_align(), fd_alloc_footprint(), 1UL );
  FD_TEST( alloc_mem );
  gui->alloc = fd_alloc_join( fd_alloc_new( alloc_mem, 1UL ), 0UL );
  FD_TEST( gui->alloc );

  append_shred( gui, start_ns+100L, 11UL );
  append_shred( gui, start_ns+200L, 11UL );
  FD_TEST( !fd_gui_printf_timeline_query_shreds( gui, "timeline", start_ns+100L, start_ns+200L, 33UL ) );
  char * json = malloc( gui->http->stage_len+1UL );
  FD_TEST( json );
  fd_memcpy( json, gui->http->oring+(gui->http->stage_off%gui->http->oring_sz), gui->http->stage_len );
  json[ gui->http->stage_len ] = '\0';
  FD_TEST( strstr( json, "\"granularity\":\"shred\"" ) );
  FD_TEST( strstr( json, "\"reference_slot\":11,\"reference_ts\":\"10000000100\"" ) );
  FD_TEST( strstr( json, "\"slot_delta\":[0]" ) );
  FD_TEST( strstr( json, "\"idx\":[0]" ) );
  FD_TEST( !strstr( json, "\"shred_idx\"" ) );
  FD_TEST( strstr( json, "\"event_ts_delta\":[\"0\"]" ) );
  FD_TEST( strstr( json, "\"skipped\":[]" ) );
  free( json );
  fd_http_server_unstage( gui->http );

  FD_TEST( !fd_gui_printf_timeline_query_shreds( gui, "timeline", start_ns+100L, start_ns+201L, 33UL ) );
  json = malloc( gui->http->stage_len+1UL );
  FD_TEST( json );
  fd_memcpy( json, gui->http->oring+(gui->http->stage_off%gui->http->oring_sz), gui->http->stage_len );
  json[ gui->http->stage_len ] = '\0';
  FD_TEST( strstr( json, "\"slot_delta\":[0,0]" ) );
  FD_TEST( strstr( json, "\"event_ts_delta\":[\"0\",\"100\"]" ) );
  FD_TEST( strstr( json, "\"skipped\":[]" ) );
  free( json );
  fd_http_server_unstage( gui->http );

  fd_gui_printf_shred_updates( gui, start_ns+100L, start_ns+200L );
  json = malloc( gui->http->stage_len+1UL );
  FD_TEST( json );
  fd_memcpy( json, gui->http->oring+(gui->http->stage_off%gui->http->oring_sz), gui->http->stage_len );
  json[ gui->http->stage_len ] = '\0';
  FD_TEST( strstr( json, "\"topic\":\"slot\",\"key\":\"live_shreds\"" ) );
  FD_TEST( strstr( json, "\"shred_idx\":[" ) );
  FD_TEST( !strstr( json, "\"skipped\"" ) );
  free( json );
  fd_http_server_unstage( gui->http );

  FD_TEST( !fd_gui_printf_timeline_query_shreds( gui, "timeline", start_ns+250L, start_ns+251L, 33UL ) );
  json = malloc( gui->http->stage_len+1UL );
  FD_TEST( json );
  fd_memcpy( json, gui->http->oring+(gui->http->stage_off%gui->http->oring_sz), gui->http->stage_len );
  json[ gui->http->stage_len ] = '\0';
  FD_TEST( strstr( json, "\"reference_slot\": null,\"reference_ts\": null" ) );
  FD_TEST( strstr( json, "\"skipped\":[]" ) );
  free( json );
  fd_http_server_unstage( gui->http );

  append_shred( gui, start_ns+300L, 0UL );
  FD_TEST( !fd_gui_printf_timeline_query_shreds( gui, "timeline", start_ns+300L, start_ns+301L, 33UL ) );
  json = malloc( gui->http->stage_len+1UL );
  FD_TEST( json );
  fd_memcpy( json, gui->http->oring+(gui->http->stage_off%gui->http->oring_sz), gui->http->stage_len );
  json[ gui->http->stage_len ] = '\0';
  FD_TEST( strstr( json, "\"reference_slot\":0,\"reference_ts\":\"10000000300\",\"slot_delta\":[0]" ) );
  FD_TEST( strstr( json, "\"event_ts_delta\":[\"0\"]" ) );
  FD_TEST( strstr( json, "\"skipped\":[]" ) );
  free( json );
  fd_http_server_unstage( gui->http );

  gui->epoch.has_epoch_schedule = 1;
  gui->epoch.epoch_schedule = (fd_epoch_schedule_t) {
    .slots_per_epoch             = 32UL,
    .leader_schedule_slot_offset = 32UL,
    .warmup                      = 0,
    .first_normal_epoch          = 0UL,
    .first_normal_slot           = 0UL
  };
  put_epoch( gui, 0UL, 0UL, 32UL );
  fd_gui_epoch_t * epoch0 = fd_gui_epoch( gui, 0UL );
  FD_TEST( epoch0 );
  epoch0->skipped[ 8UL ] = 1;
  FD_TEST(  fd_gui_slot_is_skipped( gui, 10UL, ULONG_MAX, ULONG_MAX,  8UL ) );
  FD_TEST( !fd_gui_slot_is_skipped( gui, 10UL, ULONG_MAX, ULONG_MAX,  9UL ) );
  FD_TEST( !fd_gui_slot_is_skipped( gui, 10UL, ULONG_MAX, ULONG_MAX, 10UL ) );

  fd_gui_hist_slot_key_t live_keys[ 2 ] = {
    { .slot=12UL, .bank_seq=1UL },
    { .slot=14UL, .bank_seq=1UL },
  };
  ulong live_parents[ 2 ] = { 10UL, 12UL };
  for( ulong i=0UL; i<2UL; i++ ) {
    fd_gui_slot_t * slot = fd_gui_hist_kv_get_or_create( gui, FD_GUI_HIST_SLOT, &live_keys[ i ] );
    FD_TEST( slot );
    memset( slot, 0xFF, sizeof(*slot) );
    slot->slot            = live_keys[ i ].slot;
    slot->bank_seq        = live_keys[ i ].bank_seq;
    slot->parent_slot     = live_parents[ i ];
    slot->parent_bank_seq = live_keys[ i ].bank_seq;
    slot->skip            = FD_GUI_SKIP_STATUS_NOT_SKIPPED;
    slot->level           = FD_GUI_SLOT_LEVEL_COMPLETED;
  }
  gui->summary.slot_rooted         = 10UL;
  gui->summary.slot_tower          = 14UL;
  gui->summary.slot_tower_bank_seq = 1UL;

  append_shred( gui, start_ns+310L, 13UL );
  append_shred( gui, start_ns+311L,  8UL );
  append_shred( gui, start_ns+312L, 12UL );
  append_shred( gui, start_ns+313L, 13UL );
  append_shred( gui, start_ns+314L, 11UL );
  append_shred( gui, start_ns+315L, 14UL );
  append_shred( gui, start_ns+316L,  9UL );
  append_shred( gui, start_ns+317L, 10UL );
  append_shred( gui, start_ns+318L, 15UL );
  FD_TEST( !fd_gui_printf_timeline_query_shreds( gui, "timeline", start_ns+310L, start_ns+319L, 33UL ) );
  json = malloc( gui->http->stage_len+1UL );
  FD_TEST( json );
  fd_memcpy( json, gui->http->oring+(gui->http->stage_off%gui->http->oring_sz), gui->http->stage_len );
  json[ gui->http->stage_len ] = '\0';
  FD_TEST( strstr( json, "\"reference_slot\":8,\"reference_ts\":\"10000000310\"" ) );
  FD_TEST( strstr( json, "\"slot_delta\":[5,0,4,5,3,6,1,2,7]" ) );
  FD_TEST( strstr( json, "\"skipped\":[0,3,5]" ) );
  free( json );
  fd_http_server_unstage( gui->http );

  fd_gui_hist_slot_key_t bounded_anchor_key = { .slot=1000UL, .bank_seq=1UL };
  fd_gui_slot_t * bounded_anchor = fd_gui_hist_kv_get_or_create( gui, FD_GUI_HIST_SLOT, &bounded_anchor_key );
  FD_TEST( bounded_anchor );
  memset( bounded_anchor, 0xFF, sizeof(*bounded_anchor) );
  bounded_anchor->slot            = bounded_anchor_key.slot;
  bounded_anchor->bank_seq        = bounded_anchor_key.bank_seq;
  bounded_anchor->parent_slot     = bounded_anchor_key.slot-1UL;
  bounded_anchor->parent_bank_seq = bounded_anchor_key.bank_seq;
  bounded_anchor->completed_time  = start_ns+350L;
  bounded_anchor->skip            = FD_GUI_SKIP_STATUS_NOT_SKIPPED;
  bounded_anchor->level           = FD_GUI_SLOT_LEVEL_ROOTED;
  gui->summary.slot_rooted         = 2024UL;
  gui->summary.slot_tower          = 2024UL;
  gui->summary.slot_tower_bank_seq = 1UL;

  append_shred( gui, start_ns+400L, 2023UL );
  FD_TEST( !fd_gui_printf_timeline_query_shreds( gui, "timeline", start_ns+400L, start_ns+401L, 33UL ) );
  json = malloc( gui->http->stage_len+1UL );
  FD_TEST( json );
  fd_memcpy( json, gui->http->oring+(gui->http->stage_off%gui->http->oring_sz), gui->http->stage_len );
  json[ gui->http->stage_len ] = '\0';
  FD_TEST( strstr( json, "\"reference_slot\":2023,\"reference_ts\":\"10000000400\"" ) );
  FD_TEST( strstr( json, "\"slot_delta\":[0]" ) );
  FD_TEST( strstr( json, "\"event_ts_delta\":[\"0\"]" ) );
  free( json );
  fd_http_server_unstage( gui->http );

  append_shred( gui, start_ns+500L, 2024UL );
  FD_TEST( !fd_gui_printf_timeline_query_shreds( gui, "timeline", start_ns+500L, start_ns+501L, 33UL ) );
  json = malloc( gui->http->stage_len+1UL );
  FD_TEST( json );
  fd_memcpy( json, gui->http->oring+(gui->http->stage_off%gui->http->oring_sz), gui->http->stage_len );
  json[ gui->http->stage_len ] = '\0';
  FD_TEST( strstr( json, "\"reference_slot\":2024,\"reference_ts\":\"10000000500\",\"slot_delta\":[0]" ) );
  free( json );
  fd_http_server_unstage( gui->http );

  char shred_request[ 256 ];
  fd_cstr_printf_check( shred_request, sizeof(shred_request), NULL,
                        "{\"topic\":\"timeline\",\"key\":\"query_shreds\",\"id\":33,"
                        "\"params\":{\"start_ns\":\"%ld\",\"end_ns\":\"%ld\",\"granularity\":\"shred\"}}",
                        start_ns+500L, start_ns+501L );
  FD_TEST( !fd_gui_ws_message( gui, 0UL, (uchar const *)shred_request, strlen( shred_request ) ) );

  ulong txn_reads = fd_gui_store_metrics( gui->db )->ts_reads[ FD_GUI_HIST_REPLAY_TXN ];
  FD_TEST( !fd_gui_printf_timeline_query_txns( gui, "timeline", "query_txn_timestamps", start_ns, end_ns+1L, 34UL ) );
  FD_TEST( fd_gui_store_metrics( gui->db )->ts_reads[ FD_GUI_HIST_REPLAY_TXN ]==txn_reads+1UL );
  FD_TEST( !gui->http->stage_err );
  json = malloc( gui->http->stage_len+1UL );
  FD_TEST( json );
  fd_memcpy( json, gui->http->oring+(gui->http->stage_off%gui->http->oring_sz), gui->http->stage_len );
  json[ gui->http->stage_len ] = '\0';

  FD_TEST( strstr( json, "\"topic\":\"timeline\",\"key\":\"query_txn_timestamps\",\"id\":34" ) );
  FD_TEST( strstr( json, "\"granularity\":\"txn\"" ) );
  FD_TEST( strstr( json, "\"reference_slot\":10,\"reference_ts\":\"9999999990\"" ) );
  FD_TEST( strstr( json, "\"slot_delta\":[0,1]" ) );
  FD_TEST( strstr( json, "\"txn_idx\":[5,2]" ) );
  FD_TEST( strstr( json, "\"txn_exec_idx\":[0,1]" ) );
  FD_TEST( strstr( json, "\"txn_sigverify_exec_idx\":[2,3]" ) );
  FD_TEST( strstr( json, "\"txn_sigverify_start_ts_delta\":[\"0\",\"5\"]" ) );
  FD_TEST( strstr( json, "\"txn_check_start_ts_delta\":[null,\"8\"]" ) );
  FD_TEST( strstr( json, "\"txn_exec_start_ts_delta\":[\"3\",null]" ) );
  FD_TEST( strstr( json, "\"txn_commit_start_ts_delta\":[\"4\",null]" ) );
  FD_TEST( strstr( json, "\"txn_commit_end_ts_delta\":[\"1010\",\"9\"]" ) );
  FD_TEST( strstr( json, "\"txn_error_code\":[3,9]" ) );
  FD_TEST( !strstr( json, "\"txn_signature\"" ) );
  FD_TEST( !strstr( json, "\"txn_compute_units_requested\"" ) );
  FD_TEST( !strstr( json, "\"txn_microblock_id\"" ) );
  FD_TEST( !strstr( json, "\"txn_exec_tile_idx\"" ) );
  free( json );

  fd_http_server_unstage( gui->http );
  txn_reads = fd_gui_store_metrics( gui->db )->ts_reads[ FD_GUI_HIST_REPLAY_TXN ];
  FD_TEST( !fd_gui_printf_timeline_query_txns( gui, "timeline", "query_txn_meta", start_ns, end_ns+1L, 35UL ) );
  FD_TEST( fd_gui_store_metrics( gui->db )->ts_reads[ FD_GUI_HIST_REPLAY_TXN ]==txn_reads+1UL );
  FD_TEST( !gui->http->stage_err );
  json = malloc( gui->http->stage_len+1UL );
  FD_TEST( json );
  fd_memcpy( json, gui->http->oring+(gui->http->stage_off%gui->http->oring_sz), gui->http->stage_len );
  json[ gui->http->stage_len ] = '\0';

  FD_TEST( strstr( json, "\"topic\":\"timeline\",\"key\":\"query_txn_meta\",\"id\":35" ) );
  FD_TEST( !strstr( json, "\"granularity\"" ) );
  FD_TEST( strstr( json, "\"reference_slot\":10,\"reference_ts\":\"9999999990\"" ) );
  FD_TEST( strstr( json, "\"slot_delta\":[0,1]" ) );
  FD_TEST( strstr( json, "\"txn_idx\":[5,2]" ) );
  FD_TEST( strstr( json, "\"txn_exec_idx\":[0,1]" ) );
  FD_TEST( strstr( json, "\"txn_sigverify_exec_idx\":[2,3]" ) );
  FD_TEST( strstr( json, "\"txn_compute_units_requested\":[null,3428]" ) );
  FD_TEST( strstr( json, "\"txn_transaction_fee\":[\"0\",\"5000\"]" ) );
  FD_TEST( strstr( json, "\"txn_is_committable\":[false,true]" ) );
  FD_TEST( strstr( json, "\"txn_load_start_ts_delta\":[\"2\",\"7\"]" ) );
  FD_TEST( strstr( json, "\"txn_commit_end_ts_delta\":[\"1010\",\"9\"]" ) );
  FD_TEST( strstr( json, "\"txn_error_code\":[3,9]" ) );
  FD_TEST( !strstr( json, "\"txn_sigverify_start_ts_delta\"" ) );
  FD_TEST( !strstr( json, "\"txn_microblock_id\"" ) );
  FD_TEST( !strstr( json, "\"txn_exec_tile_idx\"" ) );
  free( json );

  fd_http_server_unstage( gui->http );
  FD_TEST( !fd_gui_printf_timeline_query_txns( gui, "timeline", "query_txn_meta", end_ns+2L, end_ns+3L, 36UL ) );
  FD_TEST( !gui->http->stage_err );
  json = malloc( gui->http->stage_len+1UL );
  FD_TEST( json );
  fd_memcpy( json, gui->http->oring+(gui->http->stage_off%gui->http->oring_sz), gui->http->stage_len );
  json[ gui->http->stage_len ] = '\0';
  FD_TEST( strstr( json, "\"reference_slot\": null,\"reference_ts\": null,\"slot_delta\":[]" ) );
  free( json );

  /* Multiple replay candidates can produce indistinguishable public IDs.
     Both rows remain in the response. */
  fd_http_server_unstage( gui->http );
  long const duplicate_ts = end_ns+10L;
  fd_gui_store_replay_txn_t duplicate_a = a;
  duplicate_a.completion_time_ns = duplicate_ts;
  duplicate_a.slot               = 15UL;
  duplicate_a.txn_idx            = 4UL;
  duplicate_a.txn_exec_idx       = 1UL;
  duplicate_a.sigverify_start_ns = duplicate_ts;
  duplicate_a.sigverify_end_ns   = duplicate_ts;
  duplicate_a.load_start_ns      = duplicate_ts;
  duplicate_a.check_start_ns     = LONG_MAX;
  duplicate_a.exec_start_ns      = LONG_MAX;
  duplicate_a.commit_start_ns    = LONG_MAX;
  duplicate_a.commit_end_ns      = duplicate_ts;
  fd_gui_store_replay_txn_t duplicate_b = duplicate_a;
  duplicate_b.txn_exec_idx = 2UL;
  FD_TEST( !fd_gui_hist_ts_append( gui, FD_GUI_HIST_REPLAY_TXN, duplicate_ts, duplicate_ts, &duplicate_a ) );
  FD_TEST( !fd_gui_hist_ts_append( gui, FD_GUI_HIST_REPLAY_TXN, duplicate_ts, duplicate_ts, &duplicate_b ) );
  FD_TEST( !fd_gui_printf_timeline_query_txns( gui, "timeline", "query_txn_meta",
                                               duplicate_ts, duplicate_ts+1L, 45UL ) );
  json = malloc( gui->http->stage_len+1UL );
  FD_TEST( json );
  fd_memcpy( json, gui->http->oring+(gui->http->stage_off%gui->http->oring_sz), gui->http->stage_len );
  json[ gui->http->stage_len ] = '\0';
  FD_TEST( strstr( json, "\"reference_slot\":15,\"reference_ts\":\"10000001010\"" ) );
  FD_TEST( strstr( json, "\"slot_delta\":[0,0]" ) );
  FD_TEST( strstr( json, "\"txn_idx\":[4,4]" ) );
  free( json );

  /* Replay transaction timestamps come from the local monotonic clock and
     remain exact even if the GUI consumes the notification much later. */
  fd_http_server_unstage( gui->http );
  long const lagged_ts = 2000000000000L;
  fd_gui_hist_slot_key_t lagged_anchor_key = { .slot=12UL, .bank_seq=1UL };
  fd_gui_slot_t * lagged_anchor = fd_gui_hist_kv_get_or_create( gui, FD_GUI_HIST_SLOT, &lagged_anchor_key );
  FD_TEST( lagged_anchor );
  memset( lagged_anchor, 0xFF, sizeof(*lagged_anchor) );
  lagged_anchor->slot            = lagged_anchor_key.slot;
  lagged_anchor->bank_seq        = lagged_anchor_key.bank_seq;
  lagged_anchor->parent_slot     = 11UL;
  lagged_anchor->parent_bank_seq = 1UL;
  lagged_anchor->completed_time  = lagged_ts-20L;
  lagged_anchor->skip            = FD_GUI_SKIP_STATUS_NOT_SKIPPED;
  lagged_anchor->level           = FD_GUI_SLOT_LEVEL_ROOTED;

  fd_gui_store_replay_txn_t lagged = b;
  lagged.completion_time_ns = lagged_ts;
  lagged.slot               = 13UL;
  lagged.txn_idx            = 7UL;
  lagged.sigverify_start_ns = lagged_ts-10L;
  lagged.sigverify_end_ns   = lagged_ts-1L;
  lagged.load_start_ns      = lagged_ts-8L;
  lagged.check_start_ns     = LONG_MAX;
  lagged.exec_start_ns      = lagged_ts-7L;
  lagged.commit_start_ns    = lagged_ts-6L;
  lagged.commit_end_ns      = lagged_ts;
  FD_TEST( !fd_gui_hist_ts_append( gui, FD_GUI_HIST_REPLAY_TXN,
                                   lagged_ts+100000000000L, lagged_ts, &lagged ) );

  /* Make the exact timestamp an append-order interior extreme.  Endpoint
     bounds alone would miss it; conservative observed extrema must not. */
  fd_gui_store_replay_txn_t lagged_tail = lagged;
  lagged_tail.completion_time_ns = 1000000000000L;
  FD_TEST( !fd_gui_hist_ts_append( gui, FD_GUI_HIST_REPLAY_TXN,
                                   lagged_tail.completion_time_ns,
                                   lagged_tail.completion_time_ns,
                                   &lagged_tail ) );
  FD_TEST( !fd_gui_printf_timeline_query_txns( gui, "timeline", "query_txn_timestamps", lagged_ts, lagged_ts+1L, 36UL ) );
  json = malloc( gui->http->stage_len+1UL );
  FD_TEST( json );
  fd_memcpy( json, gui->http->oring+(gui->http->stage_off%gui->http->oring_sz), gui->http->stage_len );
  json[ gui->http->stage_len ] = '\0';
  FD_TEST( strstr( json, "\"txn_idx\":[7]" ) );
  free( json );

  fd_http_server_unstage( gui->http );
  char const request_wide[] =
    "{\"topic\":\"timeline\",\"key\":\"query_txn_timestamps\",\"id\":36,"
    "\"params\":{\"start_ns\":\"10000000000\",\"end_ns\":\"26000000000\",\"granularity\":\"txn\"}}";
  FD_TEST( !fd_gui_ws_message( gui, 0UL, (uchar const *)request_wide, sizeof(request_wide)-1UL ) );

  char const request_wider[] =
    "{\"topic\":\"timeline\",\"key\":\"query_txn_meta\",\"id\":37,"
    "\"params\":{\"start_ns\":\"10000000000\",\"end_ns\":\"26000000001\"}}";
  FD_TEST( !fd_gui_ws_message( gui, 0UL, (uchar const *)request_wider, sizeof(request_wider)-1UL ) );

  char const request_removed[] =
    "{\"topic\":\"timeline\",\"key\":\"query_transactions\",\"id\":38,"
    "\"params\":{\"start_ns\":\"10000000000\",\"end_ns\":\"26000000001\"}}";
  FD_TEST( fd_gui_ws_message( gui, 0UL, (uchar const *)request_removed, sizeof(request_removed)-1UL )==
           FD_HTTP_SERVER_CONNECTION_CLOSE_UNKNOWN_METHOD );

  char const request_removed_batch[] =
    "{\"topic\":\"timeline\",\"key\":\"query_txn_batch_timestamps\",\"id\":38,"
    "\"params\":{\"start_ns\":\"10000000000\",\"end_ns\":\"26000000001\"}}";
  FD_TEST( fd_gui_ws_message( gui, 0UL, (uchar const *)request_removed_batch, sizeof(request_removed_batch)-1UL )==
           FD_HTTP_SERVER_CONNECTION_CLOSE_UNKNOWN_METHOD );

  char const * invalid_requests[] = {
    "{\"topic\":\"timeline\",\"key\":\"query_txn_timestamps\",\"id\":38,\"params\":{\"start_ns\":1,\"end_ns\":\"2\",\"granularity\":\"txn\"}}",
    "{\"topic\":\"timeline\",\"key\":\"query_txn_meta\",\"id\":38,\"params\":{\"start_ns\":\"\",\"end_ns\":\"2\"}}",
    "{\"topic\":\"timeline\",\"key\":\"query_txn_timestamps\",\"id\":38,\"params\":{\"start_ns\":\"-1\",\"end_ns\":\"2\",\"granularity\":\"txn\"}}",
    "{\"topic\":\"timeline\",\"key\":\"query_txn_meta\",\"id\":38,\"params\":{\"start_ns\":\"1x\",\"end_ns\":\"2\"}}",
    "{\"topic\":\"timeline\",\"key\":\"query_txn_timestamps\",\"id\":38,\"params\":{\"start_ns\":\"1\\u0000junk\",\"end_ns\":\"2\",\"granularity\":\"txn\"}}",
    "{\"topic\":\"timeline\",\"key\":\"query_txn_meta\",\"id\":38,\"params\":{\"start_ns\":\"9223372036854775807\",\"end_ns\":\"9223372036854775807\"}}",
    "{\"topic\":\"timeline\",\"key\":\"query_txn_meta\",\"id\":38,\"params\":{\"start_ns\":\"2\",\"end_ns\":\"2\"}}",
    "{\"topic\":\"timeline\",\"key\":\"query_txn_timestamps\",\"id\":38,\"params\":{\"start_ns\":\"2\",\"end_ns\":\"1\",\"granularity\":\"txn\"}}",
    "{\"topic\":\"timeline\",\"key\":\"query_txn_timestamps\",\"id\":38,\"params\":{\"start_ns\":\"1\",\"end_ns\":\"2\"}}",
    "{\"topic\":\"timeline\",\"key\":\"query_txn_timestamps\",\"id\":38,\"params\":{\"start_ns\":\"1\",\"end_ns\":\"2\",\"granularity\":1}}",
    "{\"topic\":\"timeline\",\"key\":\"query_txn_timestamps\",\"id\":38,\"params\":{\"start_ns\":\"1\",\"end_ns\":\"2\",\"granularity\":\"batch\"}}"
  };
  for( ulong i=0UL; i<sizeof(invalid_requests)/sizeof(invalid_requests[ 0 ]); i++ )
    FD_TEST( fd_gui_ws_message( gui, 0UL, (uchar const *)invalid_requests[ i ], strlen( invalid_requests[ i ] ) )==
             FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST );

  static uchar const request_literal_nul[] =
    "{\"topic\":\"timeline\",\"key\":\"query_txn_meta\",\"id\":38,"
    "\"params\":{\"start_ns\":\"1\0junk\",\"end_ns\":\"2\"}}";
  FD_TEST( fd_gui_ws_message( gui, 0UL, request_literal_nul, sizeof(request_literal_nul)-1UL )==
           FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST );

  /* A wide range entirely outside retained history is rejected by the live
     bounds without opening a store scan. */
  long future_start = LONG_MAX-10000000000000000L;
  long future_end   = LONG_MAX-1L;
  txn_reads = fd_gui_store_metrics( gui->db )->ts_reads[ FD_GUI_HIST_REPLAY_TXN ];
  FD_TEST( !fd_gui_printf_timeline_query_txns( gui, "timeline", "query_txn_meta", future_start, future_end, 39UL ) );
  FD_TEST( fd_gui_store_metrics( gui->db )->ts_reads[ FD_GUI_HIST_REPLAY_TXN ]==txn_reads );
  fd_http_server_unstage( gui->http );

  /* Exactly the transaction limit succeeds in one scan; limit+1 produces a
     small error envelope with no partial value. */
  long const txn_limit_ts = 100000000000L;
  for( ulong i=0UL; i<FD_GUI_TIMELINE_QUERY_TXN_TIMESTAMPS_MAX; i++ ) append_replay_txn( gui, txn_limit_ts, i );
  append_replay_txn( gui, txn_limit_ts+1L, FD_GUI_TIMELINE_QUERY_TXN_TIMESTAMPS_MAX );

  txn_reads = fd_gui_store_metrics( gui->db )->ts_reads[ FD_GUI_HIST_REPLAY_TXN ];
  ulong txn_read_records = fd_gui_store_metrics( gui->db )->ts_read_records[ FD_GUI_HIST_REPLAY_TXN ];
  FD_TEST( !fd_gui_printf_timeline_query_txns( gui, "timeline", "query_txn_timestamps", txn_limit_ts, txn_limit_ts+1L, 40UL ) );
  FD_TEST( fd_gui_store_metrics( gui->db )->ts_reads[ FD_GUI_HIST_REPLAY_TXN ]==txn_reads+1UL );
  FD_TEST( fd_gui_store_metrics( gui->db )->ts_read_records[ FD_GUI_HIST_REPLAY_TXN ]==txn_read_records+FD_GUI_TIMELINE_QUERY_TXN_TIMESTAMPS_MAX+1UL );
  FD_TEST( !gui->http->stage_err && gui->http->stage_len<FD_GUI_HTTP_MIN_SEND_BUFFER_SZ );
  gui->http->ws_conns[ 0 ].compress_websocket = 1;
  FD_TEST( !fd_http_server_ws_send( gui->http, 0UL ) );
  FD_TEST( !gui->http->stage_err && !gui->http->stage_len && !gui->http->stage_comp_len );

  long const txn_meta_limit_ts = 150000000000L;
  for( ulong i=0UL; i<FD_GUI_TIMELINE_QUERY_TXN_META_MAX; i++ ) append_replay_txn( gui, txn_meta_limit_ts, i );
  append_replay_txn( gui, txn_meta_limit_ts+1L, FD_GUI_TIMELINE_QUERY_TXN_META_MAX );

  txn_reads        = fd_gui_store_metrics( gui->db )->ts_reads[ FD_GUI_HIST_REPLAY_TXN ];
  txn_read_records = fd_gui_store_metrics( gui->db )->ts_read_records[ FD_GUI_HIST_REPLAY_TXN ];
  FD_TEST( !fd_gui_printf_timeline_query_txns( gui, "timeline", "query_txn_meta", txn_meta_limit_ts, txn_meta_limit_ts+2L, 41UL ) );
  FD_TEST( fd_gui_store_metrics( gui->db )->ts_reads[ FD_GUI_HIST_REPLAY_TXN ]==txn_reads+1UL );
  FD_TEST( fd_gui_store_metrics( gui->db )->ts_read_records[ FD_GUI_HIST_REPLAY_TXN ]==txn_read_records+FD_GUI_TIMELINE_QUERY_TXN_META_MAX+1UL );
  json = malloc( gui->http->stage_len+1UL );
  FD_TEST( json );
  fd_memcpy( json, gui->http->oring+(gui->http->stage_off%gui->http->oring_sz), gui->http->stage_len );
  json[ gui->http->stage_len ] = '\0';
  FD_TEST( strstr( json, "\"error\":{\"code\":\"result_limit_exceeded\"}" ) );
  FD_TEST( !strstr( json, "\"max_records\"" ) );
  FD_TEST( strstr( json, "\"topic\":\"timeline\",\"key\":\"query_txn_meta\",\"id\":41" ) );
  FD_TEST( !strstr( json, "\"value\"" ) );
  free( json );
  fd_http_server_unstage( gui->http );

  /* Apply the same one-scan and exact-limit behavior to shred rows. */
  long const shred_limit_ts = 200000000000L;
  for( ulong i=0UL; i<FD_GUI_TIMELINE_QUERY_SHRED_MAX; i++ ) append_shred( gui, shred_limit_ts, 1UL );
  append_shred( gui, shred_limit_ts+1L, 1UL );

  ulong shred_reads        = fd_gui_store_metrics( gui->db )->ts_reads[ FD_GUI_HIST_SHRED_EVENTS ];
  ulong shred_read_records = fd_gui_store_metrics( gui->db )->ts_read_records[ FD_GUI_HIST_SHRED_EVENTS ];
  FD_TEST( !fd_gui_printf_timeline_query_shreds( gui, "timeline", shred_limit_ts, shred_limit_ts+1L, 42UL ) );
  FD_TEST( fd_gui_store_metrics( gui->db )->ts_reads[ FD_GUI_HIST_SHRED_EVENTS ]==shred_reads+1UL );
  FD_TEST( fd_gui_store_metrics( gui->db )->ts_read_records[ FD_GUI_HIST_SHRED_EVENTS ]==shred_read_records+FD_GUI_TIMELINE_QUERY_SHRED_MAX+1UL );
  FD_TEST( !gui->http->stage_err && gui->http->stage_len<FD_GUI_HTTP_MIN_SEND_BUFFER_SZ );
  FD_TEST( !fd_http_server_ws_send( gui->http, 0UL ) );
  FD_TEST( !gui->http->stage_err && !gui->http->stage_len && !gui->http->stage_comp_len );

  shred_reads        = fd_gui_store_metrics( gui->db )->ts_reads[ FD_GUI_HIST_SHRED_EVENTS ];
  shred_read_records = fd_gui_store_metrics( gui->db )->ts_read_records[ FD_GUI_HIST_SHRED_EVENTS ];
  FD_TEST( !fd_gui_printf_timeline_query_shreds( gui, "timeline", shred_limit_ts, shred_limit_ts+2L, 43UL ) );
  FD_TEST( fd_gui_store_metrics( gui->db )->ts_reads[ FD_GUI_HIST_SHRED_EVENTS ]==shred_reads+1UL );
  FD_TEST( fd_gui_store_metrics( gui->db )->ts_read_records[ FD_GUI_HIST_SHRED_EVENTS ]==shred_read_records+FD_GUI_TIMELINE_QUERY_SHRED_MAX+1UL );
  json = malloc( gui->http->stage_len+1UL );
  FD_TEST( json );
  fd_memcpy( json, gui->http->oring+(gui->http->stage_off%gui->http->oring_sz), gui->http->stage_len );
  json[ gui->http->stage_len ] = '\0';
  FD_TEST( strstr( json, "\"error\":{\"code\":\"result_limit_exceeded\"}" ) );
  FD_TEST( !strstr( json, "\"max_records\"" ) );
  FD_TEST( !strstr( json, "\"value\"" ) );
  free( json );
  fd_http_server_unstage( gui->http );

  /* If staging unexpectedly fails, the request reports a connection-local
     close reason instead of terminating the tile. */
  fd_http_server_t * normal_http = gui->http;
  fd_http_server_params_t tiny_params = params;
  tiny_params.outgoing_buffer_sz = 32UL;
  ulong tiny_http_footprint = fd_http_server_footprint( tiny_params );
  void * tiny_http_mem = aligned_alloc( fd_http_server_align(), fd_ulong_align_up( tiny_http_footprint, fd_http_server_align() ) );
  FD_TEST( tiny_http_mem );
  gui->http = fd_http_server_join( fd_http_server_new( tiny_http_mem, tiny_params, callbacks, NULL ) );
  FD_TEST( gui->http );
  char const tiny_request[] =
    "{\"topic\":\"timeline\",\"key\":\"query_txn_meta\",\"id\":44,"
    "\"params\":{\"start_ns\":\"300000000000\",\"end_ns\":\"300000000001\"}}";
  FD_TEST( fd_gui_ws_message( gui, 0UL, (uchar const *)tiny_request, sizeof(tiny_request)-1UL )==
           FD_HTTP_SERVER_CONNECTION_CLOSE_EVICTED );
  FD_TEST( !gui->http->stage_err && !gui->http->stage_len );
  fd_http_server_delete( fd_http_server_leave( gui->http ) );
  free( tiny_http_mem );
  gui->http = normal_http;

  FD_TEST( fd_alloc_delete( fd_alloc_leave( gui->alloc ) )==alloc_mem );
  fd_wksp_free_laddr( alloc_mem );
  fd_wksp_delete_anonymous( wksp );
  fd_http_server_delete( fd_http_server_leave( gui->http ) );
  free( http_mem );
  gui->alloc = NULL;
  gui->http  = NULL;

  FD_LOG_NOTICE(( "test_timeline_queries: ok" ));
}

static void
test_txn_batch_timeline_queries( fd_gui_t * gui ) {
  fd_http_server_params_t params = {
    .max_connection_cnt    = 1UL,
    .max_ws_connection_cnt = 1UL,
    .max_request_len       = 4096UL,
    .max_ws_recv_frame_len = 4096UL,
    .max_ws_send_frame_cnt = 1UL,
    .outgoing_buffer_sz    = FD_GUI_HTTP_MIN_SEND_BUFFER_SZ
  };
  fd_http_server_callbacks_t callbacks = {0};
  ulong http_footprint = fd_http_server_footprint( params );
  void * http_mem = aligned_alloc( fd_http_server_align(), fd_ulong_align_up( http_footprint, fd_http_server_align() ) );
  FD_TEST( http_mem );
  gui->http = fd_http_server_join( fd_http_server_new( http_mem, params, callbacks, NULL ) );
  FD_TEST( gui->http );

  fd_wksp_t * wksp = fd_wksp_new_anonymous( FD_SHMEM_NORMAL_PAGE_SZ, 4096UL, 0UL, "gui_txn_batch_query", 0UL );
  FD_TEST( wksp );
  void * alloc_mem = fd_wksp_alloc_laddr( wksp, fd_alloc_align(), fd_alloc_footprint(), 1UL );
  FD_TEST( alloc_mem );
  gui->alloc = fd_alloc_join( fd_alloc_new( alloc_mem, 1UL ), 0UL );
  FD_TEST( gui->alloc );

  /* The execution lane splits at 32 members, on a success transition, just
     above the inclusive 100 us boundary, and on a tile transition. */
  ulong const capped_slot = 100UL;
  long const  capped_base = 300000000000L;
  long prev_exec_end = 0L;
  for( ulong i=0UL; i<37UL; i++ ) {
    long load_start;
    if(      !i      ) load_start = capped_base+1000L;
    else if( i==34UL ) load_start = prev_exec_end+FD_GUI_TXN_BATCH_GAP_NS;
    else if( i==35UL ) load_start = prev_exec_end+FD_GUI_TXN_BATCH_GAP_NS+1L;
    else                load_start = prev_exec_end+1L;
    long commit_end = load_start+10L;
    prev_exec_end = commit_end;

    ulong exec_tile = i==36UL ? 1UL : 0UL;
    ulong sig_tile  = i<=32UL ? 0UL : (i<=34UL ? 1UL : i-33UL);
    uint  error     = i<33UL ? 0U : 7U;
    long  sig_start = capped_base+100L+(long)(20UL*i);
    append_replay_txn_timing( gui, capped_slot, i, exec_tile, sig_tile, error,
                              sig_start, sig_start+10L,
                              load_start, load_start+1L, load_start+2L,
                              load_start+5L, commit_end );
  }
  complete_replay_txn_batch_slot( gui, capped_slot, 37UL, capped_base, prev_exec_end+100L );

  fd_gui_store_replay_txn_batch_t batches[ 8 ];
  ulong batch_cnt = collect_replay_txn_batches( gui, capped_slot, batches, 8UL );
  FD_TEST( batch_cnt==5UL );
  ulong const capped_counts[ 5 ] = { 32UL, 1UL, 2UL, 1UL, 1UL };
  ulong const capped_first [ 5 ] = {  0UL,32UL,33UL,35UL,36UL };
  for( ulong i=0UL; i<5UL; i++ ) {
    FD_TEST( batches[ i ].batch_idx==i );
    FD_TEST( batches[ i ].exec_txn_cnt==capped_counts[ i ] );
    FD_TEST( batches[ i ].sigverify_txn_cnt==capped_counts[ i ] );
    FD_TEST( batches[ i ].exec_txn_idx[ 0 ]==capped_first[ i ] );
    FD_TEST( batches[ i ].sigverify_txn_idx[ 0 ]==capped_first[ i ] );
  }
  FD_TEST( batches[ 0 ].exec_txn_idx[ 31 ]==31U );
  FD_TEST( batches[ 2 ].exec_txn_idx[ 1 ]==34U );
  FD_TEST( batches[ 2 ].error_code==7U );
  FD_TEST( batches[ 4 ].txn_exec_idx==1UL );

  /* Three sigverify batches collapse to one execution batch by discarding
     the two shortest spans. */
  ulong const excess_slot = 101UL;
  long const  excess_base = 310000000000L;
  for( ulong i=0UL; i<3UL; i++ ) {
    long sig_start = excess_base+100L+(long)(100UL*i);
    long sig_end   = sig_start+(long)(10UL*(i+1UL));
    long load      = excess_base+1000L+(long)(20UL*i);
    append_replay_txn_timing( gui, excess_slot, i, 0UL, i, 0U,
                              sig_start, sig_end, load, LONG_MAX,
                              load+2L, load+5L, load+10L );
  }
  complete_replay_txn_batch_slot( gui, excess_slot, 3UL, excess_base, excess_base+2000L );
  batch_cnt = collect_replay_txn_batches( gui, excess_slot, batches, 8UL );
  FD_TEST( batch_cnt==1UL );
  FD_TEST( batches[ 0 ].exec_txn_cnt==3U );
  FD_TEST( batches[ 0 ].sigverify_txn_cnt==1U );
  FD_TEST( batches[ 0 ].sigverify_txn_idx[ 0 ]==2U );
  FD_TEST( batches[ 0 ].txn_sigverify_exec_idx==2UL );
  FD_TEST( batches[ 0 ].sigverify_start_ns==excess_base+300L );
  FD_TEST( batches[ 0 ].sigverify_end_ns  ==excess_base+330L );

  /* One sigverify batch is split first at its largest gap and then the
     widest remaining batch is split at its largest gap. */
  ulong const short_slot = 102UL;
  long const  short_base = 320000000000L;
  long const sig_start[ 5 ] = {
    short_base+100L, short_base+120L, short_base+200L,
    short_base+220L, short_base+500L
  };
  for( ulong i=0UL; i<5UL; i++ ) {
    ulong exec_tile = i<2UL ? 0UL : (i<4UL ? 1UL : 2UL);
    long load = short_base+1000L+(long)(20UL*i);
    append_replay_txn_timing( gui, short_slot, i, exec_tile, 0UL, 0U,
                              sig_start[ i ], sig_start[ i ]+10L,
                              load, i==2UL ? load+1L : LONG_MAX,
                              load+2L, load+5L, load+10L );
  }
  complete_replay_txn_batch_slot( gui, short_slot, 5UL, short_base, short_base+2000L );
  batch_cnt = collect_replay_txn_batches( gui, short_slot, batches, 8UL );
  FD_TEST( batch_cnt==3UL );
  ulong const short_counts[ 3 ] = { 2UL, 2UL, 1UL };
  ulong const short_first [ 3 ] = { 0UL, 2UL, 4UL };
  for( ulong i=0UL; i<3UL; i++ ) {
    FD_TEST( batches[ i ].batch_idx==i );
    FD_TEST( batches[ i ].exec_txn_cnt==short_counts[ i ] );
    FD_TEST( batches[ i ].sigverify_txn_cnt==short_counts[ i ] );
    FD_TEST( batches[ i ].exec_txn_idx[ 0 ]==short_first[ i ] );
    FD_TEST( batches[ i ].sigverify_txn_idx[ 0 ]==short_first[ i ] );
  }
  FD_TEST( batches[ 0 ].sigverify_txn_idx[ 1 ]==1U );
  FD_TEST( batches[ 1 ].sigverify_txn_idx[ 1 ]==3U );
  /* Execution stage durations are summed across members and projected onto
     each batch's load-to-commit envelope.  Batch 0 totals 4 ns load, 6 ns
     execute, and 10 ns commit over a 30 ns envelope.  Batch 1 additionally
     has 1 ns of check contribution. */
  FD_TEST( batches[ 0 ].check_start_ns==LONG_MAX );
  FD_TEST( batches[ 0 ].exec_start_ns  ==short_base+1006L );
  FD_TEST( batches[ 0 ].commit_start_ns==short_base+1015L );
  FD_TEST( batches[ 1 ].check_start_ns ==short_base+1044L );
  FD_TEST( batches[ 1 ].exec_start_ns  ==short_base+1046L );
  FD_TEST( batches[ 1 ].commit_start_ns==short_base+1055L );

  /* Exercise the maximum repeated-split case: 32 execution batches versus
     one 32-member sigverify batch whose largest gap stays at the right edge.
     This drives all 31 heap-selected splits. */
  ulong const split_stress_slot = 103UL;
  long const  split_stress_base = 330000000000L;
  long prev_sig_end = 0L;
  long split_stress_completion = 0L;
  for( ulong i=0UL; i<FD_GUI_TXN_BATCH_MAX_TXN; i++ ) {
    long split_sig_start = i ? prev_sig_end+(long)i : split_stress_base+100L;
    prev_sig_end = split_sig_start+10L;
    long load = split_stress_base+1000L+(long)(20UL*i);
    split_stress_completion = load+10L;
    append_replay_txn_timing( gui, split_stress_slot, i, i, 0UL, 0U,
                              split_sig_start, prev_sig_end,
                              load, LONG_MAX, load+2L, load+5L, load+10L );
  }
  complete_replay_txn_batch_slot( gui, split_stress_slot, FD_GUI_TXN_BATCH_MAX_TXN,
                                  split_stress_base, split_stress_completion+100L );
  fd_gui_store_replay_txn_batch_t split_stress_batches[ FD_GUI_TXN_BATCH_MAX_TXN ];
  batch_cnt = collect_replay_txn_batches( gui, split_stress_slot, split_stress_batches,
                                          FD_GUI_TXN_BATCH_MAX_TXN );
  FD_TEST( batch_cnt==FD_GUI_TXN_BATCH_MAX_TXN );
  for( ulong i=0UL; i<batch_cnt; i++ ) {
    FD_TEST( split_stress_batches[ i ].batch_idx==i );
    FD_TEST( split_stress_batches[ i ].exec_txn_cnt==1U );
    FD_TEST( split_stress_batches[ i ].sigverify_txn_cnt==1U );
    FD_TEST( split_stress_batches[ i ].exec_txn_idx[ 0 ]==i );
    FD_TEST( split_stress_batches[ i ].sigverify_txn_idx[ 0 ]==i );
  }

  ulong batch_reads = fd_gui_store_metrics( gui->db )->ts_reads[ FD_GUI_HIST_REPLAY_TXN_BATCH ];
  FD_TEST( !fd_gui_printf_timeline_query_txn_batches( gui, "timeline", "query_txn_timestamps",
                                                       short_base, short_base+2000L, 70UL ) );
  FD_TEST( fd_gui_store_metrics( gui->db )->ts_reads[ FD_GUI_HIST_REPLAY_TXN_BATCH ]==batch_reads+1UL );
  char * json = malloc( gui->http->stage_len+1UL );
  FD_TEST( json );
  fd_memcpy( json, gui->http->oring+(gui->http->stage_off%gui->http->oring_sz), gui->http->stage_len );
  json[ gui->http->stage_len ] = '\0';
  FD_TEST( strstr( json, "\"topic\":\"timeline\",\"key\":\"query_txn_timestamps\",\"id\":70" ) );
  FD_TEST( strstr( json, "\"granularity\":\"txn_batch\"" ) );
  FD_TEST( strstr( json, "\"reference_slot\":102,\"reference_ts\":\"320000000100\"" ) );
  FD_TEST( strstr( json, "\"slot_delta\":[0,0,0]" ) );
  FD_TEST( strstr( json, "\"txn_idx\":[0,1,2]" ) );
  FD_TEST( strstr( json, "\"txn_exec_idx\":[0,1,2]" ) );
  FD_TEST( strstr( json, "\"txn_sigverify_exec_idx\":[0,0,0]" ) );
  FD_TEST( strstr( json, "\"txn_sigverify_start_ts_delta\":[\"0\",\"100\",\"400\"]" ) );
  FD_TEST( strstr( json, "\"txn_sigverify_end_ts_delta\":[\"30\",\"130\",\"410\"]" ) );
  FD_TEST( strstr( json, "\"txn_load_start_ts_delta\":[\"900\",\"940\",\"980\"]" ) );
  FD_TEST( strstr( json, "\"txn_check_start_ts_delta\":[null,\"944\",null]" ) );
  FD_TEST( strstr( json, "\"txn_exec_start_ts_delta\":[\"906\",\"946\",\"982\"]" ) );
  FD_TEST( strstr( json, "\"txn_commit_start_ts_delta\":[\"915\",\"955\",\"985\"]" ) );
  FD_TEST( strstr( json, "\"txn_commit_end_ts_delta\":[\"930\",\"970\",\"990\"]" ) );
  FD_TEST( strstr( json, "\"txn_error_code\":[0,0,0]" ) );
  free( json );
  fd_http_server_unstage( gui->http );

  FD_TEST( !fd_gui_printf_timeline_query_txn_batches( gui, "timeline", "query_txn_timestamps",
                                                       short_base+3000L, short_base+3001L, 71UL ) );
  json = malloc( gui->http->stage_len+1UL );
  FD_TEST( json );
  fd_memcpy( json, gui->http->oring+(gui->http->stage_off%gui->http->oring_sz), gui->http->stage_len );
  json[ gui->http->stage_len ] = '\0';
  FD_TEST( strstr( json, "\"reference_slot\": null,\"reference_ts\": null,\"slot_delta\":[]" ) );
  free( json );
  fd_http_server_unstage( gui->http );

  char request[ 256 ];
  fd_cstr_printf_check( request, sizeof(request), NULL,
                        "{\"topic\":\"timeline\",\"key\":\"query_txn_timestamps\",\"id\":72,"
                        "\"params\":{\"start_ns\":\"%ld\",\"end_ns\":\"%ld\",\"granularity\":\"txn_batch\"}}",
                        short_base, short_base+2000L );
  FD_TEST( !fd_gui_ws_message( gui, 0UL, (uchar const *)request, strlen( request ) ) );

  /* The txn_batch granularity applies the same exact 65,536-row bound as
     the txn granularity. */
  long const batch_limit_ts = 400000000000L;
  for( ulong i=0UL; i<FD_GUI_TIMELINE_QUERY_TXN_BATCH_TIMESTAMPS_MAX; i++ )
    append_replay_txn_batch( gui, batch_limit_ts, 1000UL+i, 0UL );
  append_replay_txn_batch( gui, batch_limit_ts+1L,
                           1000UL+FD_GUI_TIMELINE_QUERY_TXN_BATCH_TIMESTAMPS_MAX, 0UL );

  batch_reads = fd_gui_store_metrics( gui->db )->ts_reads[ FD_GUI_HIST_REPLAY_TXN_BATCH ];
  ulong batch_read_records = fd_gui_store_metrics( gui->db )->ts_read_records[ FD_GUI_HIST_REPLAY_TXN_BATCH ];
  FD_TEST( !fd_gui_printf_timeline_query_txn_batches( gui, "timeline", "query_txn_timestamps",
                                                       batch_limit_ts, batch_limit_ts+1L, 73UL ) );
  FD_TEST( fd_gui_store_metrics( gui->db )->ts_reads[ FD_GUI_HIST_REPLAY_TXN_BATCH ]==batch_reads+1UL );
  FD_TEST( fd_gui_store_metrics( gui->db )->ts_read_records[ FD_GUI_HIST_REPLAY_TXN_BATCH ]==
           batch_read_records+FD_GUI_TIMELINE_QUERY_TXN_BATCH_TIMESTAMPS_MAX+1UL );
  FD_TEST( !gui->http->stage_err && gui->http->stage_len<FD_GUI_HTTP_MIN_SEND_BUFFER_SZ );
  fd_http_server_unstage( gui->http );

  batch_reads        = fd_gui_store_metrics( gui->db )->ts_reads[ FD_GUI_HIST_REPLAY_TXN_BATCH ];
  batch_read_records = fd_gui_store_metrics( gui->db )->ts_read_records[ FD_GUI_HIST_REPLAY_TXN_BATCH ];
  FD_TEST( !fd_gui_printf_timeline_query_txn_batches( gui, "timeline", "query_txn_timestamps",
                                                       batch_limit_ts, batch_limit_ts+2L, 74UL ) );
  FD_TEST( fd_gui_store_metrics( gui->db )->ts_reads[ FD_GUI_HIST_REPLAY_TXN_BATCH ]==batch_reads+1UL );
  FD_TEST( fd_gui_store_metrics( gui->db )->ts_read_records[ FD_GUI_HIST_REPLAY_TXN_BATCH ]==
           batch_read_records+FD_GUI_TIMELINE_QUERY_TXN_BATCH_TIMESTAMPS_MAX+1UL );
  json = malloc( gui->http->stage_len+1UL );
  FD_TEST( json );
  fd_memcpy( json, gui->http->oring+(gui->http->stage_off%gui->http->oring_sz), gui->http->stage_len );
  json[ gui->http->stage_len ] = '\0';
  FD_TEST( strstr( json, "\"topic\":\"timeline\",\"key\":\"query_txn_timestamps\",\"id\":74" ) );
  FD_TEST( strstr( json, "\"error\":{\"code\":\"result_limit_exceeded\"}" ) );
  FD_TEST( !strstr( json, "\"value\"" ) );
  free( json );
  fd_http_server_unstage( gui->http );

  FD_TEST( fd_alloc_delete( fd_alloc_leave( gui->alloc ) )==alloc_mem );
  fd_wksp_free_laddr( alloc_mem );
  fd_wksp_delete_anonymous( wksp );
  fd_http_server_delete( fd_http_server_leave( gui->http ) );
  free( http_mem );
  gui->alloc = NULL;
  gui->http  = NULL;

  FD_LOG_NOTICE(( "test_txn_batch_timeline_queries: ok" ));
}

static void
test_fec_timeline_queries( fd_gui_t * gui ) {
  long const base_ns = 500000000000L;

  fd_http_server_params_t params = {
    .max_connection_cnt    = 1UL,
    .max_ws_connection_cnt = 1UL,
    .max_request_len       = 1024UL,
    .max_ws_recv_frame_len = 1024UL,
    .max_ws_send_frame_cnt = 1UL,
    .outgoing_buffer_sz    = FD_GUI_HTTP_MIN_SEND_BUFFER_SZ
  };
  fd_http_server_callbacks_t callbacks = {0};
  ulong http_footprint = fd_http_server_footprint( params );
  void * http_mem = aligned_alloc( fd_http_server_align(), fd_ulong_align_up( http_footprint, fd_http_server_align() ) );
  FD_TEST( http_mem );
  gui->http = fd_http_server_join( fd_http_server_new( http_mem, params, callbacks, NULL ) );
  FD_TEST( gui->http );

  fd_wksp_t * wksp = fd_wksp_new_anonymous( FD_SHMEM_NORMAL_PAGE_SZ, 16384UL, 0UL, "gui_fec_query", 0UL );
  FD_TEST( wksp );
  void * alloc_mem = fd_wksp_alloc_laddr( wksp, fd_alloc_align(), fd_alloc_footprint(), 1UL );
  FD_TEST( alloc_mem );
  gui->alloc = fd_alloc_join( fd_alloc_new( alloc_mem, 1UL ), 0UL );
  FD_TEST( gui->alloc );

  gui->summary.slot_caught_up = 0UL;
  gui->summary.slot_turbine   = 100UL;
  gui->summary.slot_rooted    = 101UL;
  gui->summary.slot_tower     = ULONG_MAX;
  gui->summary.slot_tower_bank_seq = ULONG_MAX;
  gui->epoch.has_epoch_schedule = 1;
  gui->epoch.epoch_schedule = (fd_epoch_schedule_t) {
    .slots_per_epoch             = 128UL,
    .leader_schedule_slot_offset = 128UL,
    .warmup                      = 0,
    .first_normal_epoch          = 0UL,
    .first_normal_slot           = 0UL
  };
  put_epoch( gui, 0UL, 0UL, 128UL );
  fd_gui_epoch_t * epoch = fd_gui_epoch( gui, 0UL );
  FD_TEST( epoch );
  epoch->skipped[ 100UL ] = 1U;

  /* FEC ordinals are fec_set_idx/32.  Each event kind takes the minimum
     timestamp across all shreds touching that set. */
  fd_gui_handle_repair_request( gui, 100UL, 31UL, base_ns+100L );
  fd_gui_handle_repair_request( gui, 100UL,  0UL, base_ns+200L ); /* same key, later: suppressed */
  fd_gui_handle_repair_request( gui, 100UL, 32UL, base_ns+110L );

  fd_gui_handle_shred( gui, 100UL, 7UL, 0UL, 0, base_ns+300L, base_ns+300L );
  fd_gui_handle_shred( gui, 100UL, 8UL, 0UL, 0, base_ns+250L, base_ns+400L ); /* lower correction */
  fd_gui_handle_shred( gui, 100UL, 33UL, 32UL, 1, base_ns+350L, base_ns+350L );

  fd_gui_handle_exec_txn_done( gui, 100UL, 30UL, 34UL, base_ns+390L, base_ns+400L, base_ns+400L );
  fd_gui_handle_leader_fec( gui, 100UL, FD_FEC_SHRED_CNT, 0, base_ns+450L, base_ns+450L );
  fd_gui_handle_leader_fec( gui, 100UL, FD_FEC_SHRED_CNT, 0, base_ns+460L, base_ns+460L );
  append_fec_event( gui, base_ns+500L, 100UL, USHORT_MAX, FD_GUI_SLOT_SHRED_SHRED_SLOT_COMPLETE );

  FD_TEST( count_ts( gui, FD_GUI_HIST_FEC_EVENTS, ULONG_MAX )==10UL );

  ulong raw_reads = fd_gui_store_metrics( gui->db )->ts_reads[ FD_GUI_HIST_SHRED_EVENTS ];
  FD_TEST( !fd_gui_printf_timeline_query_fec_events( gui, "timeline", base_ns, base_ns+1000L, 50UL ) );
  FD_TEST( fd_gui_store_metrics( gui->db )->ts_reads[ FD_GUI_HIST_SHRED_EVENTS ]==raw_reads );
  char * json = malloc( gui->http->stage_len+1UL );
  FD_TEST( json );
  fd_memcpy( json, gui->http->oring+(gui->http->stage_off%gui->http->oring_sz), gui->http->stage_len );
  json[ gui->http->stage_len ] = '\0';
  FD_TEST( strstr( json, "\"topic\":\"timeline\",\"key\":\"query_shreds\",\"id\":50" ) );
  FD_TEST( strstr( json, "\"granularity\":\"fec\"" ) );
  FD_TEST( strstr( json, "\"reference_slot\":100,\"reference_ts\":\"500000000100\"" ) );
  FD_TEST( strstr( json, "\"slot_delta\":[0,0,0,0,0,0,0,0,0]" ) );
  FD_TEST( strstr( json, "\"idx\":[0,1,0,1,0,1,0,1,null]" ) );
  FD_TEST( !strstr( json, "\"shred_idx\"" ) );
  FD_TEST( strstr( json, "\"event\":[0,0,2,1,3,3,6,6,4]" ) );
  FD_TEST( strstr( json, "\"event_ts_delta\":[\"0\",\"10\",\"150\",\"250\",\"300\",\"300\",\"350\",\"360\",\"400\"]" ) );
  FD_TEST( strstr( json, "\"skipped\":[0]" ) );
  free( json );
  fd_http_server_unstage( gui->http );

  FD_TEST( !fd_gui_printf_timeline_query_fec_events( gui, "timeline", base_ns+1000L, base_ns+1001L, 51UL ) );
  json = malloc( gui->http->stage_len+1UL );
  FD_TEST( json );
  fd_memcpy( json, gui->http->oring+(gui->http->stage_off%gui->http->oring_sz), gui->http->stage_len );
  json[ gui->http->stage_len ] = '\0';
  FD_TEST( strstr( json, "\"reference_slot\": null,\"reference_ts\": null,\"slot_delta\":[],\"idx\":[]" ) );
  free( json );
  fd_http_server_unstage( gui->http );

  /* Direct-map pressure may leave multiple retained candidates for a key;
     query reduction remains authoritative. */
  ulong collision_a = 200UL;
  ulong collision_b = collision_a+1UL;
  ulong collision_idx = test_fec_cache_idx( collision_a, 0UL, FD_GUI_SLOT_SHRED_REPAIR_REQUEST );
  while( test_fec_cache_idx( collision_b, 0UL, FD_GUI_SLOT_SHRED_REPAIR_REQUEST )!=collision_idx ) collision_b++;
  fd_gui_handle_repair_request( gui, collision_a, 0UL, base_ns+2000000100L );
  fd_gui_handle_repair_request( gui, collision_b, 0UL, base_ns+2000000110L );
  fd_gui_handle_repair_request( gui, collision_a, 1UL, base_ns+2000000120L );
  FD_TEST( !fd_gui_printf_timeline_query_fec_events( gui, "timeline", base_ns+2000000000L, base_ns+2000001000L, 52UL ) );
  json = malloc( gui->http->stage_len+1UL );
  FD_TEST( json );
  fd_memcpy( json, gui->http->oring+(gui->http->stage_off%gui->http->oring_sz), gui->http->stage_len );
  json[ gui->http->stage_len ] = '\0';
  FD_TEST( test_json_array_cnt( json, "idx" )==2UL );
  FD_TEST( test_json_array_cnt( json, "event" )==2UL );
  free( json );
  fd_http_server_unstage( gui->http );

  /* A lower correction can sit before the requested window.  The 2*skew
     guard must remove the stale in-window candidate. */
  fd_gui_handle_shred( gui, 101UL, 0UL, 0UL, 0, base_ns+15000000000L, base_ns+15000000000L );
  fd_gui_handle_shred( gui, 101UL, 1UL, 0UL, 0, base_ns-1000000000L,  base_ns+19000000000L );
  FD_TEST( !fd_gui_printf_timeline_query_fec_events( gui, "timeline", base_ns+12000000000L, base_ns+16000000000L, 53UL ) );
  json = malloc( gui->http->stage_len+1UL );
  FD_TEST( json );
  fd_memcpy( json, gui->http->oring+(gui->http->stage_off%gui->http->oring_sz), gui->http->stage_len );
  json[ gui->http->stage_len ] = '\0';
  FD_TEST( strstr( json, "\"reference_slot\": null,\"reference_ts\": null" ) );
  free( json );
  fd_http_server_unstage( gui->http );

  FD_TEST( !fd_gui_printf_timeline_query_fec_events( gui, "timeline", base_ns+9000000000L, base_ns+10000000000L, 54UL ) );
  json = malloc( gui->http->stage_len+1UL );
  FD_TEST( json );
  fd_memcpy( json, gui->http->oring+(gui->http->stage_off%gui->http->oring_sz), gui->http->stage_len );
  json[ gui->http->stage_len ] = '\0';
  FD_TEST( strstr( json, "\"reference_slot\":101,\"reference_ts\":\"509000000000\"" ) );
  FD_TEST( strstr( json, "\"idx\":[0],\"event\":[2]" ) );
  free( json );
  fd_http_server_unstage( gui->http );

  char request[ 256 ];
  fd_cstr_printf_check( request, sizeof(request), NULL,
                        "{\"topic\":\"timeline\",\"key\":\"query_shreds\",\"id\":55,"
                        "\"params\":{\"start_ns\":\"%ld\",\"end_ns\":\"%ld\",\"granularity\":\"fec\"}}",
                        base_ns, base_ns+1000L );
  FD_TEST( !fd_gui_ws_message( gui, 0UL, (uchar const *)request, strlen( request ) ) );
  char const removed_request[] =
    "{\"topic\":\"timeline\",\"key\":\"query_fecs\",\"id\":56,"
    "\"params\":{\"start_ns\":\"1\",\"end_ns\":\"2\"}}";
  FD_TEST( fd_gui_ws_message( gui, 0UL, (uchar const *)removed_request, sizeof(removed_request)-1UL )==
           FD_HTTP_SERVER_CONNECTION_CLOSE_UNKNOWN_METHOD );

  char const * invalid_requests[] = {
    "{\"topic\":\"timeline\",\"key\":\"query_shreds\",\"id\":56,\"params\":{\"start_ns\":1,\"end_ns\":\"2\",\"granularity\":\"fec\"}}",
    "{\"topic\":\"timeline\",\"key\":\"query_shreds\",\"id\":56,\"params\":{\"start_ns\":\"1\",\"end_ns\":\"2\"}}",
    "{\"topic\":\"timeline\",\"key\":\"query_shreds\",\"id\":56,\"params\":{\"start_ns\":\"1\",\"end_ns\":\"2\",\"granularity\":1}}",
    "{\"topic\":\"timeline\",\"key\":\"query_shreds\",\"id\":56,\"params\":{\"start_ns\":\"1\",\"end_ns\":\"2\",\"granularity\":\"set\"}}"
  };
  for( ulong j=0UL; j<sizeof(invalid_requests)/sizeof(invalid_requests[ 0 ]); j++ )
    FD_TEST( fd_gui_ws_message( gui, 0UL, (uchar const *)invalid_requests[ j ], strlen( invalid_requests[ j ] ) )==
             FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST );

  /* The result limit applies after candidate reduction.  One duplicate over
     the stored-row limit still succeeds; one additional logical key fails. */
  long const limit_ts = base_ns+100000000000L;
  for( ulong i=0UL; i<FD_GUI_TIMELINE_QUERY_SHRED_MAX; i++ )
    append_fec_event( gui, limit_ts, 1000UL+i/(ulong)USHORT_MAX, i%(ulong)USHORT_MAX,
                      FD_GUI_SLOT_SHRED_SHRED_RECEIVED_TURBINE );
  append_fec_event( gui, limit_ts, 1000UL, 0UL, FD_GUI_SLOT_SHRED_SHRED_RECEIVED_TURBINE );

  raw_reads = fd_gui_store_metrics( gui->db )->ts_reads[ FD_GUI_HIST_SHRED_EVENTS ];
  FD_TEST( !fd_gui_printf_timeline_query_fec_events( gui, "timeline", limit_ts, limit_ts+1L, 57UL ) );
  FD_TEST( fd_gui_store_metrics( gui->db )->ts_reads[ FD_GUI_HIST_SHRED_EVENTS ]==raw_reads );
  FD_TEST( !gui->http->stage_err && gui->http->stage_len<FD_GUI_HTTP_MIN_SEND_BUFFER_SZ );
  FD_TEST( !fd_http_server_ws_send( gui->http, 0UL ) );
  FD_TEST( !gui->http->stage_err && !gui->http->stage_len && !gui->http->stage_comp_len );

  ulong i = FD_GUI_TIMELINE_QUERY_SHRED_MAX;
  append_fec_event( gui, limit_ts+1L, 1000UL+i/(ulong)USHORT_MAX, i%(ulong)USHORT_MAX,
                    FD_GUI_SLOT_SHRED_SHRED_RECEIVED_TURBINE );
  FD_TEST( !fd_gui_printf_timeline_query_fec_events( gui, "timeline", limit_ts, limit_ts+2L, 58UL ) );
  json = malloc( gui->http->stage_len+1UL );
  FD_TEST( json );
  fd_memcpy( json, gui->http->oring+(gui->http->stage_off%gui->http->oring_sz), gui->http->stage_len );
  json[ gui->http->stage_len ] = '\0';
  FD_TEST( strstr( json, "\"topic\":\"timeline\",\"key\":\"query_shreds\",\"id\":58" ) );
  FD_TEST( strstr( json, "\"error\":{\"code\":\"result_limit_exceeded\"}" ) );
  FD_TEST( !strstr( json, "\"value\"" ) );
  free( json );
  fd_http_server_unstage( gui->http );

  FD_TEST( fd_alloc_delete( fd_alloc_leave( gui->alloc ) )==alloc_mem );
  fd_wksp_free_laddr( alloc_mem );
  fd_wksp_delete_anonymous( wksp );
  fd_http_server_delete( fd_http_server_leave( gui->http ) );
  free( http_mem );
  gui->alloc = NULL;
  gui->http  = NULL;

  FD_LOG_NOTICE(( "test_fec_timeline_queries: ok" ));
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

  /* cascade mechanics: a generous (2 GiB) map so writes never hit map-full;
     eviction is driven directly via fd_gui_hist_evict_oldest.  Each test gets
     its own store so leftover epochs don't perturb the next (eviction now
     keeps the last epoch, so stores do not empty between tests). */
  ulong const map_bytes = 2UL<<30;
  test_store_t sa[ 1 ];
  store_open( sa, map_bytes, 0 );
  test_timeline_aggregates( sa->gui );
  store_close( sa );

  test_store_t sq[ 1 ];
  store_open( sq, map_bytes, 0 );
  test_timeline_agg_queries( sq->gui );
  store_close( sq );

  test_store_t s0[ 1 ];
  store_open( s0, map_bytes, 0 );
  test_evict_oldest_epoch( s0->gui );
  store_close( s0 );

  test_store_t s1[ 1 ];
  store_open( s1, map_bytes, 2 );
  test_evict_large_batch( s1->gui );
  store_close( s1 );

  test_store_t so[ 1 ];
  store_open( so, map_bytes, 7 );
  test_timeline_day_order( so->gui );
  store_close( so );

  test_store_t sp[ 1 ];
  store_open( sp, map_bytes, 6 );
  test_current_epoch_protected( sp->gui );
  store_close( sp );

  test_store_t s2[ 1 ];
  store_open( s2, map_bytes, 3 );
  test_evict_ts_oldest_fallback( s2->gui );
  store_close( s2 );

  test_store_t s3[ 1 ];
  store_open( s3, map_bytes, 4 );
  test_resident_meta_mutation_survives_evict( s3->gui );
  store_close( s3 );

  test_store_t s4[ 1 ];
  store_open( s4, map_bytes, 5 );
  test_epoch_region_reclaimed( s4->gui );
  store_close( s4 );

  test_store_t s5[ 1 ];
  store_open( s5, map_bytes, 7 );
  test_waterfall_snapshots( s5->gui );

  test_store_t s6[ 1 ];
  store_open( s6, map_bytes, 8 );
  test_timeline_queries( s6->gui );
  store_close( s6 );

  test_store_t s8[ 1 ];
  store_open( s8, map_bytes, 10 );
  test_txn_batch_timeline_queries( s8->gui );
  store_close( s8 );

  test_store_t s7[ 1 ];
  store_open( s7, map_bytes, 9 );
  test_fec_timeline_queries( s7->gui );
  store_close( s7 );

  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
