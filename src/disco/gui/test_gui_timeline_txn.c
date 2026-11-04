#include "fd_gui.h"
#include "fd_gui_printf.h"
#include "../../ballet/json/fd_jtok.h"
#include "../../waltz/http/fd_http_server_private.h"
#include <stdlib.h>
#include <unistd.h>

/* Exercise the public producer and query paths against a real history
   store and HTTP staging buffer, without starting validator tiles. */

typedef struct {
  char const * ptr;
  ulong        sz;
} json_t;

static json_t
field( json_t       json,
       char const * name ) {
  fd_jtok_t j[1]; fd_jtok_init( j, json.ptr, json.sz );
  fd_jtok_str_t key;
  json_t result = {0};
  fd_jtok_obj_enter( j );
  while( fd_jtok_obj_next( j, &key ) ) {
    if( fd_jtok_str_eq( &key, name ) ) fd_jtok_raw( j, &result.ptr, &result.sz );
  }
  FD_TEST( !fd_jtok_fini( j ) );
  return result;
}

static json_t
element( json_t json,
         ulong  index ) {
  fd_jtok_t j[1]; fd_jtok_init( j, json.ptr, json.sz );
  json_t result = {0};
  ulong i = 0UL;
  fd_jtok_arr_enter( j );
  while( fd_jtok_arr_next( j ) ) {
    if( i++==index ) { fd_jtok_raw( j, &result.ptr, &result.sz ); return result; }
  }
  FD_TEST( 0 );
  return result;
}

static ulong
count( json_t json ) {
  fd_jtok_t j[1]; fd_jtok_init( j, json.ptr, json.sz );
  ulong n = 0UL;
  fd_jtok_arr_enter( j );
  while( fd_jtok_arr_next( j ) ) n++;
  FD_TEST( !fd_jtok_fini( j ) );
  return n;
}

static int
is_null( json_t json ) {
  fd_jtok_t j[1]; fd_jtok_init( j, json.ptr, json.sz );
  return fd_jtok_peek( j )==FD_JTOK_NULL;
}

static ulong
number( json_t json ) {
  fd_jtok_t j[1]; fd_jtok_init( j, json.ptr, json.sz );
  ulong value = 0UL;
  fd_jtok_ulong( j, &value );
  FD_TEST( !fd_jtok_fini( j ) );
  return value;
}

static int
string_eq( json_t       json,
           char const * expected ) {
  fd_jtok_t j[1]; fd_jtok_init( j, json.ptr, json.sz );
  fd_jtok_str_t value;
  fd_jtok_str( j, &value );
  FD_TEST( !fd_jtok_fini( j ) );
  return fd_jtok_str_eq( &value, expected );
}

/* Response slices remain valid until the next HTTP staging write. */
static json_t
query_batch( fd_gui_t *   gui,
             char const * key,
             long         start,
             long         end,
             int          batch ) {
  int rc;
  if(      !strcmp( key, "query_tile_states" ) ) rc = fd_gui_printf_timeline_query_tile_states( gui, start, end, batch, 7UL );
  else if( !strcmp( key, "query_revenue"     ) ) rc = fd_gui_printf_timeline_query_revenue( gui, start, end, batch, 7UL );
  else                                           rc = fd_gui_printf_timeline_query_txn_meta( gui, start, end, 7UL );
  FD_TEST( !rc );
  FD_TEST( !gui->http->stage_err );
  ulong len = fd_http_server_stage_len( gui->http );
  FD_TEST( len && len<(40UL<<20) && gui->http->stage_off%gui->http->oring_sz+len<=gui->http->oring_sz );
  json_t json = { (char const *)gui->http->oring+gui->http->stage_off%gui->http->oring_sz, len };
  FD_TEST( string_eq( field( json, "topic" ), "timeline" ) );
  FD_TEST( string_eq( field( json, "key" ), key ) );
  FD_TEST( number( field( json, "id" ) )==7UL );
  fd_http_server_stage_trunc( gui->http, 0UL );
  return json;
}

static json_t
query( fd_gui_t *   gui,
       char const * key,
       long         start,
       long         end ) {
  return query_batch( gui, key, start, end, 0 );
}

static void
test_requests( fd_gui_t * gui ) {
  char const * invalid[] = {
    "{}",
    "{\"start_ns\":\"0\",\"end_ns\":\"1\"}",
    "{\"start_ns\":\"01\",\"end_ns\":\"2\",\"granularity\":\"txn\"}",
    "{\"start_ns\":\"-1\",\"end_ns\":\"2\",\"granularity\":\"txn\"}",
    "{\"start_ns\":0,\"end_ns\":\"2\",\"granularity\":\"txn\"}",
    "{\"start_ns\":\"0\",\"end_ns\":\"9223372036854775807\",\"granularity\":\"txn\"}",
    "{\"start_ns\":\"0\",\"end_ns\":\"9223372036854775808\",\"granularity\":\"txn\"}",
    "{\"start_ns\":\"2\",\"end_ns\":\"2\",\"granularity\":\"txn\"}",
    "{\"start_ns\":\"3\",\"end_ns\":\"2\",\"granularity\":\"txn\"}",
    "{\"start_ns\":\"0\",\"end_ns\":\"1\",\"granularity\":\"shred\"}",
    "{\"start_ns\":\"0\",\"end_ns\":\"1\",\"granularity\":1}"
  };
  for( ulong i=0UL; i<sizeof(invalid)/sizeof(invalid[0]); i++ ) {
    char request[512];
    fd_cstr_printf_check( request, sizeof(request), NULL,
      "{\"id\":7,\"topic\":\"timeline\",\"key\":\"query_tile_states\",\"params\":%s}", invalid[i] );
    FD_TEST( fd_gui_ws_message( gui, 0UL, (uchar const *)request, strlen(request) )==FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST );
    FD_TEST( !fd_http_server_stage_len( gui->http ) );
  }
  char const * valid[] = {
    "{\"id\":7,\"topic\":\"timeline\",\"key\":\"query_tile_states\",\"params\":{\"start_ns\":\"0\",\"end_ns\":\"1\",\"granularity\":\"txn\"}}",
    "{\"id\":7,\"topic\":\"timeline\",\"key\":\"query_tile_states\",\"params\":{\"start_ns\":\"0\",\"end_ns\":\"1\",\"granularity\":\"txn_batch\"}}",
    "{\"id\":7,\"topic\":\"timeline\",\"key\":\"query_txn_meta\",\"params\":{\"start_ns\":\"0\",\"end_ns\":\"1\"}}",
    "{\"id\":7,\"topic\":\"timeline\",\"key\":\"query_slots\",\"params\":{\"start_ns\":\"0\",\"end_ns\":\"1\"}}",
    "{\"id\":7,\"topic\":\"timeline\",\"key\":\"query_revenue\",\"params\":{\"start_ns\":\"0\",\"end_ns\":\"1\",\"granularity\":\"txn\"}}",
    "{\"id\":7,\"topic\":\"timeline\",\"key\":\"query_revenue\",\"params\":{\"start_ns\":\"0\",\"end_ns\":\"1\",\"granularity\":\"txn_batch\"}}"
  };
  for( ulong i=0UL; i<sizeof(valid)/sizeof(valid[0]); i++ ) {
    FD_TEST( !fd_gui_ws_message( gui, 0UL, (uchar const *)valid[i], strlen(valid[i]) ) );
  }
  /* query_txn_meta and query_slots validate their window like the rest. */
  char const * bad[] = {
    "{\"id\":7,\"topic\":\"timeline\",\"key\":\"query_txn_meta\",\"params\":{\"start_ns\":\"2\",\"end_ns\":\"2\"}}",
    "{\"id\":7,\"topic\":\"timeline\",\"key\":\"query_slots\",\"params\":{\"start_ns\":\"0\",\"end_ns\":\"9223372036854775807\"}}",
    /* query_revenue requires a txn or txn_batch granularity. */
    "{\"id\":7,\"topic\":\"timeline\",\"key\":\"query_revenue\",\"params\":{\"start_ns\":\"0\",\"end_ns\":\"1\"}}",
    "{\"id\":7,\"topic\":\"timeline\",\"key\":\"query_revenue\",\"params\":{\"start_ns\":\"0\",\"end_ns\":\"1\",\"granularity\":\"1s\"}}"
  };
  for( ulong i=0UL; i<sizeof(bad)/sizeof(bad[0]); i++ ) {
    FD_TEST( fd_gui_ws_message( gui, 0UL, (uchar const *)bad[i], strlen(bad[i]) )==FD_HTTP_SERVER_CONNECTION_CLOSE_BAD_REQUEST );
  }
  /* query_txn_timestamps was renamed to query_tile_states. */
  char const * old = "{\"id\":7,\"topic\":\"timeline\",\"key\":\"query_txn_timestamps\",\"params\":{\"start_ns\":\"0\",\"end_ns\":\"1\",\"granularity\":\"txn\"}}";
  FD_TEST( fd_gui_ws_message( gui, 0UL, (uchar const *)old, strlen(old) )==FD_HTTP_SERVER_CONNECTION_CLOSE_UNKNOWN_METHOD );
}

static void
test_timestamps( fd_gui_t * gui ) {
  json_t value = field( query( gui, "query_txn_meta", 0L, 1L ), "value" );
  FD_TEST( !count( field( value, "txn_idx" ) ) );
  FD_TEST( is_null( field( value, "reference_slot" ) ) && is_null( field( value, "reference_ts" ) ) );
  FD_TEST( is_null( field( value, "available_start_ns" ) ) && is_null( field( value, "available_end_ns" ) ) );

  /* A later sigverify completion selects the row, even when commit has
     already finished.  The insertion index needs its one-second margin. */
  long const ts = 10000000000L;
  fd_gui_store_replay_txn_t rec = {
    .insert_time_ns=ts+500000000L, .completion_time_ns=ts+20L, .slot=100UL, .txn_idx=3UL,
    .txn_exec_idx=1UL, .txn_sigverify_exec_idx=2UL,
    .sigverify_start_ns=ts, .sigverify_end_ns=ts+20L, .load_start_ns=ts+1L,
    .check_start_ns=LONG_MAX, .exec_start_ns=LONG_MAX, .commit_start_ns=LONG_MAX, .commit_end_ns=ts+10L,
    .error_code=9U
  };
  FD_TEST( !fd_gui_hist_ts_append( gui, FD_GUI_HIST_REPLAY_TXN, &rec ) );
  value = field( query( gui, "query_txn_meta", ts+19L, ts+20L ), "value" );
  FD_TEST( !count( field( value, "txn_idx" ) ) );
  value = field( query( gui, "query_txn_meta", ts+20L, ts+21L ), "value" );
  FD_TEST( count( field( value, "txn_idx" ) )==1UL );
  FD_TEST( string_eq( field( value, "reference_ts" ), "10000000000" ) );
  FD_TEST( string_eq( field( value, "available_start_ns" ), "9500000000" ) );
  FD_TEST( string_eq( field( value, "available_end_ns" ), "11500000001" ) );
  FD_TEST( string_eq( element( field( value, "txn_load_start_ts_delta" ), 0UL ), "1" ) );
  FD_TEST( string_eq( element( field( value, "txn_commit_end_ts_delta" ), 0UL ), "10" ) );
  FD_TEST( number( element( field( value, "txn_error_code" ), 0UL ) )==9UL );

  /* The same row as states: tile 1 loads over [1,10), tile 2
     sigverifies over [0,20), within a [0,21) window. */
  gui->tile_state.exec_cnt = 3UL;
  gui->tile_state.pos_cnt  = 3UL;
  value = field( query( gui, "query_tile_states", ts, ts+21L ), "value" );
  FD_TEST( string_eq( field( value, "granularity" ), "txn" ) );
  FD_TEST( string_eq( field( value, "start_ts" ), "10000000000" ) );
  ulong const states[] = { FD_GUI_TILE_STATE_IDLE, FD_GUI_TILE_STATE_IDLE, FD_GUI_TILE_STATE_LOADING, FD_GUI_TILE_STATE_IDLE,
                           FD_GUI_TILE_STATE_SIGVERIFY, FD_GUI_TILE_STATE_IDLE };
  ulong const durs[]   = { 21UL, 1UL, 9UL, 11UL, 20UL, 1UL };
  FD_TEST( count( field( value, "state" ) )==6UL );
  for( ulong i=0UL; i<6UL; i++ ) {
    FD_TEST( number( element( field( value, "state" ), i ) )==states[ i ] );
    FD_TEST( number( element( field( value, "dur" ), i ) )==durs[ i ] );
  }
  FD_TEST( number( element( field( value, "txn_error_code" ), 0UL ) )==9UL );
  FD_TEST( is_null( element( field( value, "txn_error_code" ), 1UL ) ) );
  gui->tile_state.exec_cnt = 0UL;
  gui->tile_state.pos_cnt  = 0UL;

  rec.slot = 99UL; rec.txn_idx = 8UL;
  FD_TEST( !fd_gui_hist_ts_append( gui, FD_GUI_HIST_REPLAY_TXN, &rec ) );
  rec.slot = 100UL; rec.txn_idx = 1UL;
  FD_TEST( !fd_gui_hist_ts_append( gui, FD_GUI_HIST_REPLAY_TXN, &rec ) );
  value = field( query( gui, "query_txn_meta", ts+20L, ts+21L ), "value" );
  FD_TEST( number( field( value, "reference_slot" ) )==99UL );
  ulong expected[] = {8UL, 1UL, 3UL};
  for( ulong i=0UL; i<3UL; i++ ) {
    FD_TEST( number( element( field( value, "txn_idx" ), i ) )==expected[i] );
    FD_TEST( number( element( field( value, "slot_delta" ), i ) )==!!i );
  }

  /* Replay producer: stages that were never reached remain null. */
  long const now  = 20000000000L;
  long const tick = fd_tickcount();
  gui->tick_per_ns = 1e30; /* deterministic sub-nanosecond tick offsets */
  fd_replay_txn_executed_t executed = {
    .slot=101UL, .exec_tile_idx=3UL, .sigverify_exec_tile_idx=4UL, .index_in_slot=5UL,
    .tick_sigverify_disp=tick, .tick_sigverify_done=tick, .tick_load_start=tick,
    .tick_check_start=LONG_MAX, .tick_exec_start=LONG_MAX, .tick_commit_start=LONG_MAX, .tick_commit_end=tick,
    .txn_err=-9
  };
  /* Minimal parsed legacy transaction: one signature, one account. */
  executed.txn->payload[0] = 1U; executed.txn->payload[65] = 1U; executed.txn->payload[68] = 1U;
  executed.txn->payload_sz = 134U;
  FD_TEST( fd_txn_parse( executed.txn->payload, executed.txn->payload_sz, TXN( executed.txn ), NULL ) );
  fd_gui_handle_replay_txn( gui, &executed, now );
  executed.tick_commit_end = LONG_MAX;
  fd_gui_handle_replay_txn( gui, &executed, now );
  value = field( query( gui, "query_txn_meta", now, now+1L ), "value" );
  FD_TEST( count( field( value, "txn_idx" ) )==1UL );
  FD_TEST( number( element( field( value, "txn_exec_idx" ), 0UL ) )==3UL );
  FD_TEST( number( element( field( value, "txn_sigverify_exec_idx" ), 0UL ) )==4UL );
  FD_TEST( number( element( field( value, "txn_error_code" ), 0UL ) )==9UL );

  /* Leader rows come from execle, use pack indices and have no sigverify. */
  fd_txn_p_t txn = *executed.txn;
  txn.flags = FD_TXN_P_FLAGS_EXECUTE_SUCCESS | (200U<<24);
  fd_txn_ns_dt_t dt = { .load_start=10.4f, .check_start=20.6f, .exec_start=30.4f, .commit_start=60.6f, .commit_end=100.4f };
  long const leader_now = 30000000000L;
  fd_gui_microblock_execution_end( gui, leader_now, 3UL, 500UL, 1UL, &txn, 17UL, dt, tick, 0UL, 7UL, leader_now );
  txn.flags = 0U;
  fd_gui_microblock_execution_end( gui, leader_now, 3UL, 500UL, 1UL, &txn, 18UL, dt, tick, 0UL, 7UL, leader_now );
  txn.flags = FD_TXN_P_FLAGS_EXECUTE_SUCCESS;
  fd_gui_microblock_execution_end( gui, leader_now, 3UL, 500UL, 1UL, &txn, 19UL, dt, LONG_MAX, 0UL, 7UL, leader_now );
  value = field( query( gui, "query_txn_meta", leader_now, leader_now+1L ), "value" );
  FD_TEST( count( field( value, "txn_idx" ) )==1UL );
  FD_TEST( number( element( field( value, "txn_idx" ), 0UL ) )==17UL );
  FD_TEST( number( element( field( value, "txn_error_code" ), 0UL ) )==200UL );
  FD_TEST( is_null( element( field( value, "txn_sigverify_exec_idx" ), 0UL ) ) );
  FD_TEST( string_eq( field( value, "reference_ts" ), "29999999910" ) );
  FD_TEST( string_eq( element( field( value, "txn_commit_end_ts_delta" ), 0UL ), "90" ) );
  /* query_tile_states skips leader rows. */
  value = field( query( gui, "query_tile_states", leader_now-100L, leader_now+1L ), "value" );
  FD_TEST( !count( field( value, "txn_idx" ) ) && is_null( field( value, "reference_slot" ) ) );
}

/* Lthash tasks are a fourth query_tile_states lane on execrp tiles,
   clamped where they overlap txn states. */
static void
test_lthash( fd_gui_t * gui ) {
  long const ts = 50000000000L;
  gui->tile_state.exec_cnt = 2UL;
  gui->tile_state.pos_cnt  = 2UL;
  fd_gui_store_replay_txn_t txn = {
    .insert_time_ns=ts+30L, .completion_time_ns=ts+10L, .slot=200UL, .txn_idx=4UL,
    .txn_exec_idx=0UL, .txn_sigverify_exec_idx=ULONG_MAX-1UL,
    .sigverify_start_ns=LONG_MAX, .sigverify_end_ns=LONG_MAX, .load_start_ns=ts,
    .check_start_ns=LONG_MAX, .exec_start_ns=LONG_MAX, .commit_start_ns=LONG_MAX, .commit_end_ns=ts+10L
  };
  FD_TEST( !fd_gui_hist_ts_append( gui, FD_GUI_HIST_REPLAY_TXN, &txn ) );
  /* Tile 0: an add overlapping the txn's end.  Tile 1: a sub, and an
     out of range tile that is ignored. */
  fd_gui_store_replay_lthash_t l[ 3 ] = {
    { .insert_time_ns=ts+30L, .start_ns=ts+5L,  .end_ns=ts+15L, .slot=201UL, .exec_idx=0, .kind=FD_GUI_LTHASH_KIND_ADD, .cnt=32 },
    { .insert_time_ns=ts+30L, .start_ns=ts+2L,  .end_ns=ts+6L,  .slot=200UL, .exec_idx=1, .kind=FD_GUI_LTHASH_KIND_SUB, .cnt=8  },
    { .insert_time_ns=ts+30L, .start_ns=ts+2L,  .end_ns=ts+6L,  .slot=200UL, .exec_idx=5, .kind=FD_GUI_LTHASH_KIND_SUB, .cnt=8  },
  };
  for( ulong i=0UL; i<3UL; i++ ) FD_TEST( !fd_gui_hist_ts_append( gui, FD_GUI_HIST_REPLAY_LTHASH, l+i ) );

  json_t value = field( query( gui, "query_tile_states", ts, ts+20L ), "value" );
  FD_TEST( number( field( value, "reference_slot" ) )==200UL );
  ulong const states[] = { FD_GUI_TILE_STATE_LOADING, FD_GUI_TILE_STATE_LTHASH, FD_GUI_TILE_STATE_IDLE,
                           FD_GUI_TILE_STATE_IDLE, FD_GUI_TILE_STATE_LTHASH, FD_GUI_TILE_STATE_IDLE };
  ulong const durs[]   = { 10UL, 5UL, 5UL, 2UL, 4UL, 14UL };
  FD_TEST( count( field( value, "state" ) )==6UL );
  for( ulong i=0UL; i<6UL; i++ ) {
    FD_TEST( number( element( field( value, "state" ), i ) )==states[ i ] );
    FD_TEST( number( element( field( value, "dur" ), i ) )==durs[ i ] );
  }
  FD_TEST( number( element( field( value, "state_cnt" ), 0UL ) )==3UL );
  FD_TEST( number( element( field( value, "state_cnt" ), 1UL ) )==3UL );
  FD_TEST( count( field( value, "txn_state_lo" ) )==1UL );
  FD_TEST( count( field( value, "lthash_state_lo" ) )==2UL );
  ulong const lo[] = { 1UL, 4UL }, delta[] = { 1UL, 0UL }, kind[] = { 1UL, 0UL }, acct[] = { 32UL, 8UL };
  for( ulong i=0UL; i<2UL; i++ ) {
    FD_TEST( number( element( field( value, "lthash_state_lo"   ), i ) )==lo[ i ] );
    FD_TEST( number( element( field( value, "lthash_slot_delta" ), i ) )==delta[ i ] );
    FD_TEST( number( element( field( value, "lthash_kind"       ), i ) )==kind[ i ] );
    FD_TEST( number( element( field( value, "lthash_acct_cnt"   ), i ) )==acct[ i ] );
  }

  /* Producer: a done frag is recorded as a row, and bad ones are not. */
  long const now  = 60000000000L;
  long const tick = fd_tickcount();
  gui->tick_per_ns = 1e30;
  fd_gui_handle_lthash_done( gui, 1UL, FD_GUI_LTHASH_KIND_ADD, 300UL, 17UL, tick, tick, now );
  fd_gui_handle_lthash_done( gui, 2UL, FD_GUI_LTHASH_KIND_ADD, 300UL, 17UL, tick, tick, now ); /* no such tile */
  fd_gui_handle_lthash_done( gui, 1UL, FD_GUI_LTHASH_KIND_ADD, 300UL, 0UL,  tick, tick, now ); /* empty */
  fd_gui_handle_lthash_done( gui, 1UL, FD_GUI_LTHASH_KIND_ADD, 300UL, 17UL, tick, tick-1L, now ); /* reversed */
  fd_gui_hist_iter_t it;
  FD_TEST( !fd_gui_hist_range_begin( gui, &it, FD_GUI_HIST_REPLAY_LTHASH, now, now, NULL, NULL ) );
  ulong rows = 0UL;
  while( fd_gui_hist_range_next( &it ) ) {
    fd_gui_store_replay_lthash_t const * r = it.rec;
    FD_TEST( r->slot==300UL && r->exec_idx==1 && r->kind==FD_GUI_LTHASH_KIND_ADD && r->cnt==17 );
    FD_TEST( r->start_ns==now && r->end_ns==now && r->insert_time_ns==now );
    rows++;
  }
  fd_gui_hist_range_end( &it );
  FD_TEST( rows==1UL );
  fd_gui_lthash_batch_flush( gui, now+FD_GUI_LTHASH_BATCH_IDLE_NS ); /* close the producer's batch */

  gui->tile_state.exec_cnt = 0UL;
  gui->tile_state.pos_cnt  = 0UL;
}

/* Tasks are batched per tile with the txn rule: same slot, within
   FD_GUI_TXN_BATCH_GAP_NS of the previous task, at most
   FD_GUI_TXN_BATCH_MAX_TXN tasks.  txn_batch reports a batch as one
   LthashBatch state. */

static void
test_lthash_batch( fd_gui_t * gui ) {
  long const base = 70000000000L;
  long const gap  = FD_GUI_TXN_BATCH_GAP_NS;
  gui->tile_state.exec_cnt = 2UL;
  gui->tile_state.pos_cnt  = 2UL;
  long const now = base+3L*gap+51L; /* just after the last task */
  /* Tile 0: three tasks within the gap, then one after a longer gap.
     Tile 1: two tasks within the gap but for different slots. */
  fd_gui_lthash_record( gui, 0UL, FD_GUI_LTHASH_KIND_SUB, 500UL, 8UL,  base,            base+100L,        now );
  fd_gui_lthash_record( gui, 0UL, FD_GUI_LTHASH_KIND_SUB, 500UL, 16UL, base+200L,       base+300L,        now );
  fd_gui_lthash_record( gui, 0UL, FD_GUI_LTHASH_KIND_ADD, 500UL, 32UL, base+300L+gap,   base+400L+gap,    now );
  fd_gui_lthash_record( gui, 0UL, FD_GUI_LTHASH_KIND_ADD, 500UL, 4UL,  base+3L*gap,     base+3L*gap+50L,  now );
  fd_gui_lthash_record( gui, 1UL, FD_GUI_LTHASH_KIND_ADD, 500UL, 2UL,  base,            base+10L,         now );
  fd_gui_lthash_record( gui, 1UL, FD_GUI_LTHASH_KIND_ADD, 501UL, 3UL,  base+20L,        base+30L,         now );
  /* Tile 0's last batch is not idle long enough yet.  The rest were
     closed by a later task or are idle. */
  fd_gui_lthash_batch_flush( gui, now );
  fd_gui_hist_iter_t it;
  ulong cnt = 0UL;
  FD_TEST( !fd_gui_hist_range_begin( gui, &it, FD_GUI_HIST_REPLAY_LTHASH_BATCH, base, LONG_MAX-1L, NULL, NULL ) );
  while( fd_gui_hist_range_next( &it ) ) cnt++;
  fd_gui_hist_range_end( &it );
  FD_TEST( cnt==3UL );
  long const flush = now+FD_GUI_LTHASH_BATCH_IDLE_NS;
  fd_gui_lthash_batch_flush( gui, flush );
  struct { long start, end; ulong slot; uint acct; ushort pos; uchar tasks; } const want[] = {
    { base,          base+400L+gap,   500UL, 56U, 0, 3 },
    { base,          base+10L,        500UL, 2U,  1, 1 },
    { base+20L,      base+30L,        501UL, 3U,  1, 1 },
    { base+3L*gap,   base+3L*gap+50L, 500UL, 4U,  0, 1 },
  };
  cnt = 0UL;
  FD_TEST( !fd_gui_hist_range_begin( gui, &it, FD_GUI_HIST_REPLAY_LTHASH_BATCH, base, LONG_MAX-1L, NULL, NULL ) );
  while( fd_gui_hist_range_next( &it ) ) {
    fd_gui_store_replay_lthash_batch_t const * b = it.rec;
    FD_TEST( cnt<4UL );
    FD_TEST( b->start_ns==want[ cnt ].start && b->end_ns==want[ cnt ].end && b->slot==want[ cnt ].slot );
    FD_TEST( b->acct_cnt==want[ cnt ].acct && b->exec_idx==want[ cnt ].pos && b->task_cnt==want[ cnt ].tasks );
    FD_TEST( b->insert_time_ns==( cnt<3UL ? now : flush ) );
    cnt++;
  }
  fd_gui_hist_range_end( &it );
  FD_TEST( cnt==4UL );
  for( ulong i=0UL; i<2UL; i++ ) FD_TEST( !gui->tile_state.lthash_open[ i ].task_cnt );

  /* txn_batch: one LthashBatch per batch.  txn: one Lthash per task. */
  json_t value = field( query_batch( gui, "query_tile_states", base, base+4L*gap, 1 ), "value" );
  ulong const bstates[] = { FD_GUI_TILE_STATE_LTHASH_BATCH, FD_GUI_TILE_STATE_IDLE, FD_GUI_TILE_STATE_LTHASH_BATCH, FD_GUI_TILE_STATE_IDLE,
                            FD_GUI_TILE_STATE_LTHASH_BATCH, FD_GUI_TILE_STATE_IDLE, FD_GUI_TILE_STATE_LTHASH_BATCH, FD_GUI_TILE_STATE_IDLE };
  ulong const bdurs[]   = { (ulong)(400L+gap), (ulong)(2L*gap-400L), 50UL, (ulong)(gap-50L),
                            10UL, 10UL, 10UL, (ulong)(4L*gap-30L) };
  FD_TEST( count( field( value, "state" ) )==8UL );
  for( ulong i=0UL; i<8UL; i++ ) {
    FD_TEST( number( element( field( value, "state" ), i ) )==bstates[ i ] );
    FD_TEST( number( element( field( value, "dur" ), i ) )==bdurs[ i ] );
  }
  FD_TEST( !count( field( value, "lthash_state_lo" ) ) );
  value = field( query( gui, "query_tile_states", base, base+4L*gap ), "value" );
  ulong lthash_states = 0UL;
  for( ulong i=0UL; i<count( field( value, "state" ) ); i++ ) {
    lthash_states += number( element( field( value, "state" ), i ) )==FD_GUI_TILE_STATE_LTHASH;
  }
  FD_TEST( lthash_states==6UL );
  FD_TEST( count( field( value, "lthash_state_lo" ) )==6UL );

  /* At most FD_GUI_TXN_BATCH_MAX_TXN tasks per batch. */
  long const t0 = base+10L*gap;
  long const now2 = t0+2000L;
  for( ulong i=0UL; i<FD_GUI_TXN_BATCH_MAX_TXN+1UL; i++ ) {
    long t = t0+(long)i*10L;
    fd_gui_lthash_record( gui, 0UL, FD_GUI_LTHASH_KIND_ADD, 600UL, 1UL, t, t+5L, now2 );
  }
  fd_gui_lthash_batch_flush( gui, now2+FD_GUI_LTHASH_BATCH_IDLE_NS );
  cnt = 0UL;
  FD_TEST( !fd_gui_hist_range_begin( gui, &it, FD_GUI_HIST_REPLAY_LTHASH_BATCH, now2, LONG_MAX-1L, NULL, NULL ) );
  ulong tasks[ 2 ] = { 0UL, 0UL };
  while( fd_gui_hist_range_next( &it ) ) {
    fd_gui_store_replay_lthash_batch_t const * b = it.rec;
    if( b->slot!=600UL ) continue;
    FD_TEST( cnt<2UL );
    tasks[ cnt++ ] = b->task_cnt;
  }
  fd_gui_hist_range_end( &it );
  FD_TEST( cnt==2UL && tasks[ 0 ]==FD_GUI_TXN_BATCH_MAX_TXN && tasks[ 1 ]==1UL );

  gui->tile_state.exec_cnt = 0UL;
  gui->tile_state.pos_cnt  = 0UL;
}

/* query_revenue returns the rows completing in the window that paid
   anything, with fees per fd_gui_store_replay_txn_revenue, and batch
   rows whose sums match their members. */
static void
test_revenue( fd_gui_t * gui ) {
  long const ts = 80000000000L;
  struct { ulong fee, prio, tips; uint err; uchar committable; long load, end; } const in[ 6 ] = {
    { 5000UL, 100UL, 7UL,  0U, 1, 0L,    100L  }, /* paid */
    { 0UL,    0UL,   0UL,  0U, 1, 200L,  300L  }, /* paid nothing */
    { 5000UL, 100UL, 7UL,  5U, 1, 400L,  500L  }, /* invalid fee payer pays nothing */
    { 5000UL, 200UL, 50UL, 1U, 1, 1000L, 1100L }, /* failed: fees but no tips */
    { 5000UL, 100UL, 7UL,  0U, 1, 2000L, 2000L }, /* no positive span */
    { 5000UL, 100UL, 7UL,  0U, 0, 2100L, 2200L }  /* did not land */
  };
  for( ulong i=0UL; i<6UL; i++ ) {
    fd_gui_store_replay_txn_t rec = {
      .insert_time_ns=ts+in[ i ].end, .completion_time_ns=ts+in[ i ].end, .slot=300UL, .txn_idx=i,
      .txn_exec_idx=2UL, .txn_sigverify_exec_idx=ULONG_MAX,
      .sigverify_start_ns=LONG_MAX, .sigverify_end_ns=LONG_MAX, .load_start_ns=ts+in[ i ].load,
      .check_start_ns=LONG_MAX, .exec_start_ns=LONG_MAX, .commit_start_ns=LONG_MAX, .commit_end_ns=ts+in[ i ].end,
      .transaction_fee=in[ i ].fee, .priority_fee=in[ i ].prio, .tips=in[ i ].tips,
      .error_code=in[ i ].err, .is_committable=in[ i ].committable
    };
    FD_TEST( !fd_gui_hist_ts_append( gui, FD_GUI_HIST_REPLAY_TXN, &rec ) );
  }
  json_t value = field( query( gui, "query_revenue", ts, ts+3000L ), "value" );
  FD_TEST( string_eq( field( value, "granularity" ), "txn" ) );
  FD_TEST( number( field( value, "reference_slot" ) )==300UL );
  FD_TEST( string_eq( field( value, "reference_ts" ), "80000000000" ) );
  FD_TEST( count( field( value, "slot_delta" ) )==2UL );
  char const * starts[ 2 ] = { "0", "1000" };
  char const * ends  [ 2 ] = { "100", "1100" };
  char const * fees  [ 2 ][ 3 ] = { { "5000", "100", "7" }, { "5000", "200", "0" } };
  for( ulong i=0UL; i<2UL; i++ ) {
    FD_TEST( !number( element( field( value, "slot_delta" ), i ) ) );
    FD_TEST( number( element( field( value, "exec_idx" ), i ) )==2UL );
    FD_TEST( string_eq( element( field( value, "start_ts_delta" ), i ), starts[ i ] ) );
    FD_TEST( string_eq( element( field( value, "end_ts_delta" ), i ), ends[ i ] ) );
    FD_TEST( string_eq( element( field( value, "txn_fees" ), i ), fees[ i ][ 0 ] ) );
    FD_TEST( string_eq( element( field( value, "prio_fees" ), i ), fees[ i ][ 1 ] ) );
    FD_TEST( string_eq( element( field( value, "tips" ), i ), fees[ i ][ 2 ] ) );
    FD_TEST( number( element( field( value, "txn_cnt" ), i ) )==1UL );
  }
  /* A row belongs to the window holding its end, so adjacent windows
     split the rows without repeating any. */
  value = field( query( gui, "query_revenue", ts, ts+1100L ), "value" );
  FD_TEST( count( field( value, "slot_delta" ) )==1UL );
  FD_TEST( string_eq( element( field( value, "end_ts_delta" ), 0UL ), "100" ) );
  value = field( query( gui, "query_revenue", ts+1100L, ts+3000L ), "value" );
  FD_TEST( count( field( value, "slot_delta" ) )==1UL );
  FD_TEST( string_eq( field( value, "reference_ts" ), "80000001000" ) );
  value = field( query( gui, "query_revenue", ts+101L, ts+1100L ), "value" );
  FD_TEST( !count( field( value, "slot_delta" ) ) && is_null( field( value, "reference_ts" ) ) );

  /* All six execute within the batch gap on one tile, so they form one
     batch.  Its sums count what every member paid, including the
     zero-span one the txn granularity omits. */
  gui->slot_txn_scratch.max = 6UL;
  FD_TEST( !fd_gui_materialize_replay_txn_batches( gui, 300UL, 0UL, ts, ts+3000L, 6UL, ts+3000L ) );
  value = field( query_batch( gui, "query_revenue", ts, ts+3000L, 1 ), "value" );
  FD_TEST( string_eq( field( value, "granularity" ), "txn_batch" ) );
  FD_TEST( count( field( value, "slot_delta" ) )==1UL );
  FD_TEST( string_eq( element( field( value, "start_ts_delta" ), 0UL ), "0" ) );
  FD_TEST( string_eq( element( field( value, "end_ts_delta" ), 0UL ), "2200" ) );
  FD_TEST( string_eq( element( field( value, "txn_fees" ), 0UL ), "15000" ) );
  FD_TEST( string_eq( element( field( value, "prio_fees" ), 0UL ), "400" ) );
  FD_TEST( string_eq( element( field( value, "tips" ), 0UL ), "14" ) );
  FD_TEST( number( element( field( value, "txn_cnt" ), 0UL ) )==6UL );
  value = field( query_batch( gui, "query_revenue", ts, ts+2200L, 1 ), "value" );
  FD_TEST( !count( field( value, "slot_delta" ) ) );
}

static void
test_limit( fd_gui_t * gui ) {
  long const ts = 40000000000L;
  fd_gui_store_replay_txn_t txn = { .insert_time_ns=ts, .completion_time_ns=ts, .slot=100UL, .load_start_ns=ts, .commit_end_ns=ts };
  for( ulong i=0UL; i<FD_GUI_TIMELINE_QUERY_TXN_MAX; i++ ) {
    txn.txn_idx = i;
    FD_TEST( !fd_gui_hist_ts_append( gui, FD_GUI_HIST_REPLAY_TXN, &txn ) );
  }
  json_t json = query( gui, "query_txn_meta", ts, ts+1L );
  FD_TEST( count( field( field( json, "value" ), "txn_idx" ) )==FD_GUI_TIMELINE_QUERY_TXN_MAX );
  FD_TEST( !fd_gui_hist_ts_append( gui, FD_GUI_HIST_REPLAY_TXN, &txn ) );
  for( int states=0; states<2; states++ ) {
    json = query( gui, states ? "query_tile_states" : "query_txn_meta", ts, ts+1L );
    FD_TEST( !field( json, "value" ).ptr );
    FD_TEST( string_eq( field( field( json, "error" ), "code" ), "result_limit_exceeded" ) );
  }
  /* The rows paid nothing, so query_revenue omits them; paying rows
     count against the limit. */
  json = query( gui, "query_revenue", ts, ts+1L );
  FD_TEST( !count( field( field( json, "value" ), "slot_delta" ) ) );
  txn.load_start_ns = ts-1L; txn.is_committable = 1; txn.transaction_fee = 5000UL;
  for( ulong i=0UL; i<=FD_GUI_TIMELINE_QUERY_TXN_MAX; i++ ) {
    txn.txn_idx = i;
    FD_TEST( !fd_gui_hist_ts_append( gui, FD_GUI_HIST_REPLAY_TXN, &txn ) );
  }
  json = query( gui, "query_revenue", ts, ts+1L );
  FD_TEST( !field( json, "value" ).ptr );
  FD_TEST( string_eq( field( field( json, "error" ), "code" ), "result_limit_exceeded" ) );
}

int
main( int argc, char ** argv ) {
  fd_boot( &argc, &argv );
  fd_gui_t * gui = aligned_alloc( fd_gui_align(), fd_gui_footprint( 1UL, 1UL, 1UL ) );
  FD_TEST( gui );
  memset( gui, 0, fd_gui_footprint( 1UL, 1UL, 1UL ) );
  char path[128];
  fd_cstr_printf_check( path, sizeof(path), NULL, "/tmp/fd_gui_timeline_txn.%i", (int)getpid() );
  ulong bytes = 6UL<<30;
  void * db_mem = aligned_alloc( fd_gui_store_align(), fd_ulong_align_up( fd_gui_hist_store_footprint( bytes ), fd_gui_store_align() ) );
  FD_TEST( db_mem );
  gui->db = fd_gui_store_join( fd_gui_hist_store_new( db_mem, path, bytes, 0UL ) );
  FD_TEST( gui->db );
  void * hist_mem = aligned_alloc( fd_gui_hist_align(), fd_ulong_align_up( fd_gui_hist_footprint(), fd_gui_hist_align() ) );
  FD_TEST( hist_mem );
  gui->hist = fd_gui_hist_join( fd_gui_hist_new( hist_mem, gui->db ) );
  FD_TEST( gui->hist );
  fd_http_server_params_t params = {
    .max_connection_cnt=1UL, .max_ws_connection_cnt=1UL, .max_request_len=1024UL,
    .max_ws_recv_frame_len=1024UL, .max_ws_send_frame_cnt=4UL, .outgoing_buffer_sz=FD_GUI_HTTP_MIN_SEND_BUFFER_SZ
  };
  void * http_mem = aligned_alloc( fd_http_server_align(), fd_http_server_footprint( params ) );
  FD_TEST( http_mem );
  gui->http = fd_http_server_join( fd_http_server_new( http_mem, params, (fd_http_server_callbacks_t){0}, NULL ) );
  FD_TEST( gui->http );
  test_requests( gui );
  test_timestamps( gui );
  test_limit( gui );
  test_lthash( gui ); /* after test_limit: time-series appends are in time order */
  test_lthash_batch( gui );
  test_revenue( gui );
  fd_http_server_delete( fd_http_server_leave( gui->http ) );
  fd_gui_hist_delete( fd_gui_hist_leave( gui->hist ) );
  fd_gui_store_delete( fd_gui_store_leave( gui->db ) );
  FD_TEST( !unlink( path ) );
  free( http_mem ); free( hist_mem ); free( db_mem ); free( gui );
  FD_LOG_NOTICE(( "pass" ));
  fd_halt();
  return 0;
}
